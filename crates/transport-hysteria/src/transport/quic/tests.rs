//! End-to-end tests for the hysteria v1 `quinn` session over a real loopback UDP socket.
//!
//! Only the client half of hysteria v1 is implemented, so the server half is assembled here from
//! the crate's own `core::protocol` helpers on a plain `quinn` endpoint.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use murmur_component_ca::keypair::{new_random_tls_key_pair, x509_key_pair, KeyPairType};
use murmur_component_tls::utls;
use murmur_quic::congestion::ByteCount;
use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};

use crate::congestion::brutal::new_brutal_sender;
use crate::core::client::{Client, CongestionFactory};
use crate::core::protocol::{self, ServerHello, ServerResponse, UdpMessage};
use crate::transport::client::ClientTransport;
use crate::transport::quic::{new_transport_factory, Config, TlsConfig};
use crate::utils::misc::{self, PacketDialer};

const ALPN: &str = "hysteria";
const AUTH: &[u8] = b"test-auth";
const AUTH_FAILURE: &str = "authentication failure";
const SERVER_NAME: &str = "example.com";
const SEND_BPS: u64 = 12_500_000;
const RECV_BPS: u64 = 24_000_000;
const UDP_SESSION_ID: u32 = 0x5eed;
/// Generous enough that a loaded box does not turn a slow-but-correct handshake into a failure,
/// and short enough that a genuinely dead session still fails the test.
const TIMEOUT: Duration = Duration::from_secs(20);

/// The server half of the hysteria v1 handshake over `quinn`.
struct TestServer {
    addr: SocketAddr,
    /// Control streams whose `ClientHello` was readable, and how many of those the auth check
    /// rejected. The ALPN test asserts the first stays zero: TLS rejects the handshake before any
    /// hysteria stream exists.
    client_hellos: Arc<AtomicUsize>,
    auth_rejections: Arc<AtomicUsize>,
    /// Held so the endpoint outlives the test body.
    _endpoint: quinn::Endpoint,
}

fn spawn_server(auth: &[u8], alpn: &str) -> TestServer {
    let (cert_pem, key_pem, _) = new_random_tls_key_pair(KeyPairType::P256).expect("generate a server key pair");
    let certificate = x509_key_pair(cert_pem.as_bytes(), key_pem.as_bytes()).expect("parse the server key pair");
    let tls = utls::Config {
        certificates: vec![certificate],
        next_protos: vec![alpn.to_owned()],
        min_version: utls::VERSION_TLS13,
        ..utls::Config::default()
    };
    let rustls_config = utls::server_rustls_config(&tls).expect("build the server rustls config");
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config).expect("quinn accepts the rustls config");

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    server_config.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().expect("loopback address"))
        .expect("bind the server endpoint");
    let addr = endpoint.local_addr().expect("the endpoint has a local address");

    let client_hellos = Arc::new(AtomicUsize::new(0));
    let auth_rejections = Arc::new(AtomicUsize::new(0));
    let accept_endpoint = endpoint.clone();
    let accept_hellos = Arc::clone(&client_hellos);
    let accept_rejections = Arc::clone(&auth_rejections);
    let auth = auth.to_vec();
    tokio::spawn(async move {
        while let Some(incoming) = accept_endpoint.accept().await {
            let auth = auth.clone();
            let client_hellos = Arc::clone(&accept_hellos);
            let auth_rejections = Arc::clone(&accept_rejections);
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                serve_connection(conn, auth, client_hellos, auth_rejections).await;
            });
        }
    });

    TestServer { addr, client_hellos, auth_rejections, _endpoint: endpoint }
}

async fn serve_connection(
    conn: quinn::Connection,
    auth: Vec<u8>,
    client_hellos: Arc<AtomicUsize>,
    auth_rejections: Arc<AtomicUsize>,
) {
    let Ok((mut send, mut recv)) = conn.accept_bi().await else { return };
    let Ok(hello) = protocol::read_client_hello(&mut recv).await else { return };
    client_hellos.fetch_add(1, Ordering::SeqCst);
    if hello.auth != auth {
        auth_rejections.fetch_add(1, Ordering::SeqCst);
        let response = ServerHello { ok: false, send_bps: 0, recv_bps: 0, message: AUTH_FAILURE.to_owned() };
        let _ = protocol::write_server_hello(&mut send, &response).await;
        // Hold the session until the client tears it down, so the error the client reports is the
        // hysteria rejection and not whatever a connection closed underneath it says.
        let _ = conn.closed().await;
        return;
    }
    let response = ServerHello { ok: true, send_bps: SEND_BPS, recv_bps: RECV_BPS, message: String::new() };
    if protocol::write_server_hello(&mut send, &response).await.is_err() {
        return;
    }

    let datagram_conn = conn.clone();
    tokio::spawn(async move {
        while let Ok(data) = datagram_conn.read_datagram().await {
            let Ok(message) = UdpMessage::unpack(&data) else { continue };
            if datagram_conn.send_datagram(Bytes::from(message.pack())).is_err() {
                break;
            }
        }
    });

    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        tokio::spawn(async move {
            let Ok(request) = protocol::read_client_request(&mut recv).await else { return };
            let response = if request.udp {
                ServerResponse { ok: true, udp_session_id: UDP_SESSION_ID, message: String::new() }
            } else {
                ServerResponse { ok: true, udp_session_id: 0, message: String::new() }
            };
            if protocol::write_server_response(&mut send, &response).await.is_err() {
                return;
            }
            if request.udp {
                // The stream is the session's lifetime; the datagram relay above answers it.
                let mut buf = [0u8; 64];
                while matches!(recv.read(&mut buf).await, Ok(Some(n)) if n > 0) {}
                return;
            }
            let mut buf = vec![0u8; 4096];
            while let Ok(Some(n)) = recv.read(&mut buf).await {
                if send.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = send.finish();
        });
    }
}

/// A dialer reduced to loopback: every address these tests use is `127.0.0.1`.
struct LoopbackDialer {
    ctx: CancellationToken,
}

#[async_trait]
impl PacketDialer for LoopbackDialer {
    async fn listen_packet(&self, _r_addr: &dyn Addr) -> anyhow::Result<Box<dyn PacketConn>> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        Ok(Box::new(socket))
    }

    fn context(&self) -> CancellationToken {
        self.ctx.clone()
    }

    async fn remote_addr(&self, host: &str) -> anyhow::Result<Box<dyn Addr>> {
        let (host, port) = misc::split_host_port(host)?;
        let ip: IpAddr = host.parse()?;
        Ok(Box::new(UdpAddr::new(ip, port)))
    }
}

/// The TLS config the QUIC session reads, in its `rustls` form. The certificate is self-signed,
/// so this trusts it the way `skip-cert-verify: true` does in a config file; hysteria's own
/// authentication is the control stream's, and it is what the tests exercise.
struct TestTls {
    config: utls::Config,
}

impl TestTls {
    fn new(alpn: &str) -> Self {
        Self {
            config: utls::Config {
                server_name: SERVER_NAME.to_owned(),
                next_protos: vec![alpn.to_owned()],
                insecure_skip_verify: true,
                min_version: utls::VERSION_TLS13,
                ..utls::Config::default()
            },
        }
    }
}

impl TlsConfig for TestTls {
    fn rustls_client_config(&self) -> anyhow::Result<rustls::ClientConfig> {
        utls::client_rustls_config(&self.config)
    }

    fn server_name(&self) -> &str {
        &self.config.server_name
    }
}

/// The QUIC config the hysteria outbound builds: `enable_datagrams` is what carries UDP sessions,
/// and the receive windows are the client's defaults.
fn quic_config() -> Config {
    Config {
        initial_stream_receive_window: 1_572_864,
        max_stream_receive_window: 15_728_640,
        initial_connection_receive_window: 6_710_886,
        max_connection_receive_window: 67_108_864,
        keep_alive_period: Duration::from_secs(10),
        disable_path_mtu_discovery: false,
        enable_datagrams: true,
    }
}

fn connect(addr: SocketAddr, auth: &[u8], alpn: &str) -> Arc<Client> {
    let congestion: CongestionFactory = Arc::new(|ref_bps: u64| Box::new(new_brutal_sender(ref_bps as ByteCount)));
    Client::new_client(
        addr.to_string(),
        String::new(),
        "udp".to_owned(),
        auth.to_vec(),
        Arc::new(TestTls::new(alpn)),
        quic_config(),
        Arc::new(ClientTransport::new(new_transport_factory())),
        SEND_BPS,
        RECV_BPS,
        Some(congestion),
        None,
        Duration::from_secs(10),
        false,
    )
    .expect("build the hysteria client")
}

fn dialer() -> Arc<dyn PacketDialer> {
    Arc::new(LoopbackDialer { ctx: CancellationToken::new() })
}

/// The handshake, the auth check, the stream relay and the UDP relay all complete against a real
/// server. A key or a framing mistake anywhere in the session fails here, not in a mock.
#[tokio::test]
async fn hysteria_session_completes_handshake_and_carries_traffic() {
    let server = spawn_server(AUTH, ALPN);
    let client = connect(server.addr, AUTH, ALPN);

    let conn = tokio::time::timeout(TIMEOUT, client.dial_tcp("example.com", 80, dialer()))
        .await
        .expect("the hysteria handshake completes in time")
        .expect("the hysteria handshake succeeds");
    let mut conn = murmur_common_net::io::OldConnAsStream(conn);
    conn.write_all(b"hysteria").await.expect("write the stream payload");
    conn.flush().await.expect("flush the stream payload");
    let mut buf = vec![0u8; b"hysteria".len()];
    tokio::time::timeout(TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("the stream echo arrives in time")
        .expect("read the stream echo");
    assert_eq!(buf, b"hysteria", "the stream round-trips through the QUIC session");
    assert_eq!(server.client_hellos.load(Ordering::SeqCst), 1, "one control stream reached the auth check");

    let udp = tokio::time::timeout(TIMEOUT, client.dial_udp(dialer()))
        .await
        .expect("the UDP session opens in time")
        .expect("the UDP session opens");
    udp.write_to(b"ping", "example.com:53").await.expect("send a datagram");
    let (data, from) = tokio::time::timeout(TIMEOUT, udp.read_from())
        .await
        .expect("the datagram echo arrives in time")
        .expect("receive the datagram echo");
    assert_eq!(data, b"ping", "the datagram round-trips through the UDP relay");
    assert_eq!(from, "example.com:53", "the relayed address is preserved");

    // Larger than one datagram, so the send path fragments and the receive path reassembles.
    let large: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    udp.write_to(&large, "example.com:53").await.expect("send a fragmented datagram");
    let (echoed, _) = tokio::time::timeout(TIMEOUT, udp.read_from())
        .await
        .expect("the fragmented echo arrives in time")
        .expect("receive the fragmented echo");
    assert_eq!(echoed, large, "a fragmented datagram is reassembled");

    let _ = client.close().await;
}

/// A client presenting the wrong auth is rejected by the control stream, and never reaches the
/// server's request handlers.
#[tokio::test]
async fn wrong_auth_fails_closed() {
    let server = spawn_server(AUTH, ALPN);
    let client = connect(server.addr, b"wrong-auth", ALPN);

    let result = tokio::time::timeout(TIMEOUT, client.dial_tcp("example.com", 80, dialer()))
        .await
        .expect("the rejected handshake fails rather than hanging");
    let err = result.err().expect("a client with the wrong auth must not establish a session");
    assert!(err.to_string().contains(AUTH_FAILURE), "the client reports the server's rejection: {err}");
    assert_eq!(server.client_hellos.load(Ordering::SeqCst), 1, "the client's hello reached the auth check");
    assert_eq!(server.auth_rejections.load(Ordering::SeqCst), 1, "the auth check rejected the credentials");
}

/// A client that does not offer the server's ALPN never reaches the hysteria auth check at all:
/// the same code path succeeds in `hysteria_session_completes_handshake_and_carries_traffic`.
#[tokio::test]
async fn wrong_alpn_fails_closed() {
    let server = spawn_server(AUTH, ALPN);
    let client = connect(server.addr, AUTH, "not-hysteria");

    let result = tokio::time::timeout(TIMEOUT, client.dial_tcp("example.com", 80, dialer()))
        .await
        .expect("the rejected handshake fails rather than hanging");
    assert!(result.is_err(), "a client without the server's ALPN must not establish a session");
    assert_eq!(server.client_hellos.load(Ordering::SeqCst), 0, "TLS rejects the handshake before any stream is opened");
    assert_eq!(server.auth_rejections.load(Ordering::SeqCst), 0, "the auth check never runs");
}

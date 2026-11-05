#![cfg(feature = "extra-protocols")]
//! Drives the hysteria v1 outbound's `dial_context`/`listen_packet_context` end to end: option
//! decode, the TLS seam, the hysteria handshake and auth, a stream payload and a datagram round
//! trip, against a server assembled in-process from the transport crate's own public protocol
//! helpers over a real loopback QUIC endpoint.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::pedantic,
    clippy::nursery
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use murmur_adapter_outbound::hysteria::Hysteria;
use murmur_component_ca::keypair::{new_random_tls_key_pair, x509_key_pair, KeyPairType};
use murmur_component_tls::utls;
use murmur_constant::adapters::ProxyAdapter as CProxyAdapter;
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_std_compat::net::UdpAddr;
use murmur_testsupport_probe::ensure_test_crypto_provider;
use murmur_transport_hysteria::core::protocol::{self, ServerHello, ServerResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const ALPN: &str = "hysteria";
const AUTH_STRING: &str = "test-auth";
const AUTH_FAILURE: &str = "authentication failure";
const SNI: &str = "example.com";
const SEND_BPS: u64 = 12_500_000;
const RECV_BPS: u64 = 24_000_000;
const UDP_SESSION_ID: u32 = 0x5eed;
const PAYLOAD: &[u8] = b"hysteria-adapter-e2e";
const TIMEOUT: Duration = Duration::from_secs(20);

/// The server half of the hysteria v1 handshake over a real `quinn` endpoint.
struct TestServer {
    addr: SocketAddr,
    client_hellos: Arc<AtomicUsize>,
    auth_rejections: Arc<AtomicUsize>,
    _endpoint: quinn::Endpoint,
}

async fn spawn_server(auth: &[u8], alpn: &str) -> TestServer {
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
            if datagram_conn.send_datagram(data).is_err() {
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

fn outbound(server: SocketAddr, auth_string: &str, alpn: Option<&str>) -> Arc<Hysteria> {
    let mut yaml = format!(
        "name: hysteria-e2e\n\
         server: {}\n\
         port: {}\n\
         sni: {SNI}\n\
         skip-cert-verify: true\n\
         up: 100 Mbps\n\
         down: 200 Mbps\n\
         auth-str: {auth_string}\n",
        server.ip(),
        server.port(),
    );
    if let Some(alpn) = alpn {
        yaml.push_str(&format!("alpn: [\"{alpn}\"]\n"));
    }
    Hysteria::new(yaml_serde::from_str(&yaml).expect("hysteria option")).expect("hysteria outbound")
}

fn tcp_metadata() -> Metadata {
    Metadata { network: NetWork::TCP, host: "example.com".to_owned(), dst_port: 80, ..Default::default() }
}

fn udp_metadata() -> Metadata {
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    Metadata {
        network: NetWork::UDP,
        host: "127.0.0.1".to_owned(),
        dst_ip: Some(ip),
        dst_port: 5300,
        ..Default::default()
    }
}

/// The outbound's whole TCP dial path: the YAML option, the TLS seam, the QUIC handshake, the
/// control stream's auth check and a payload that the peer echoes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hysteria_outbound_dials_a_stream_payload() {
    ensure_test_crypto_provider();
    let server = spawn_server(AUTH_STRING.as_bytes(), ALPN).await;
    let outbound = outbound(server.addr, AUTH_STRING, None);

    let ctx = CancellationToken::new();
    let mut metadata = tcp_metadata();
    let mut conn =
        tokio::time::timeout(TIMEOUT, <Hysteria as CProxyAdapter>::dial_context(&*outbound, &ctx, &mut metadata))
            .await
            .expect("the adapter never finished dialing")
            .expect("dial through the hysteria session");

    conn.write_all(PAYLOAD).await.expect("write the stream payload");
    conn.flush().await.expect("flush the stream payload");
    let mut echoed = vec![0u8; PAYLOAD.len()];
    tokio::time::timeout(TIMEOUT, conn.read_exact(&mut echoed))
        .await
        .expect("the echo never came back")
        .expect("read the echo");

    assert_eq!(echoed, PAYLOAD, "the peer must see exactly what the adapter sent");
    assert_eq!(server.client_hellos.load(Ordering::SeqCst), 1, "one control stream reached the auth check");
    outbound.close().expect("close the outbound");
}

/// The UDP half of the same outbound: `listen_packet_context` opens a datagram session, and a
/// payload written through the adapter's packet conn is echoed back with its relayed address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hysteria_outbound_carries_a_datagram_round_trip() {
    ensure_test_crypto_provider();
    let server = spawn_server(AUTH_STRING.as_bytes(), ALPN).await;
    let outbound = outbound(server.addr, AUTH_STRING, None);

    let ctx = CancellationToken::new();
    let mut metadata = udp_metadata();
    let pc = tokio::time::timeout(
        TIMEOUT,
        <Hysteria as CProxyAdapter>::listen_packet_context(&*outbound, &ctx, &mut metadata),
    )
    .await
    .expect("the adapter never finished opening the UDP session")
    .expect("open the hysteria UDP session");

    let dest = UdpAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5300);
    pc.write_to(PAYLOAD, &dest).await.expect("send a datagram through the adapter");
    let mut buf = vec![0u8; 256];
    let (n, from) = tokio::time::timeout(TIMEOUT, pc.read_from(&mut buf))
        .await
        .expect("the datagram echo never came back")
        .expect("receive the datagram echo");

    assert_eq!(&buf[..n], PAYLOAD, "the datagram round-trips through the adapter");
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5300);
    let relayed =
        murmur_common_net::io::old_addr_to_socket_addr(from.as_ref()).expect("relayed address is socket-backed");
    assert_eq!(relayed, loopback, "the relayed address is preserved");
    outbound.close().expect("close the outbound");
}

/// A client presenting the wrong auth is rejected by the control stream and never gets a session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hysteria_outbound_rejects_a_wrong_password() {
    ensure_test_crypto_provider();
    let server = spawn_server(AUTH_STRING.as_bytes(), ALPN).await;
    let outbound = outbound(server.addr, "wrong-auth", None);

    let ctx = CancellationToken::new();
    let mut metadata = tcp_metadata();
    let result =
        tokio::time::timeout(TIMEOUT, <Hysteria as CProxyAdapter>::dial_context(&*outbound, &ctx, &mut metadata))
            .await
            .expect("the rejected handshake must fail rather than hang");

    let err = result.err().expect("a client with the wrong auth must not establish a session");
    assert!(err.to_string().contains(AUTH_FAILURE), "the outbound reports the server's rejection: {err}");
    assert_eq!(server.client_hellos.load(Ordering::SeqCst), 1, "the client's hello reached the auth check");
    assert_eq!(server.auth_rejections.load(Ordering::SeqCst), 1, "the auth check rejected the credentials");
}

/// A client that does not offer the server's ALPN never reaches the hysteria auth check, because
/// the TLS handshake fails first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hysteria_outbound_rejects_a_wrong_alpn() {
    ensure_test_crypto_provider();
    let server = spawn_server(AUTH_STRING.as_bytes(), ALPN).await;
    let outbound = outbound(server.addr, AUTH_STRING, Some("not-hysteria"));

    let ctx = CancellationToken::new();
    let mut metadata = tcp_metadata();
    let result =
        tokio::time::timeout(TIMEOUT, <Hysteria as CProxyAdapter>::dial_context(&*outbound, &ctx, &mut metadata))
            .await
            .expect("the rejected handshake must fail rather than hang");

    assert!(result.is_err(), "a client without the server's ALPN must not establish a session");
    assert_eq!(server.client_hellos.load(Ordering::SeqCst), 0, "TLS rejects the handshake before any stream is opened");
    assert_eq!(server.auth_rejections.load(Ordering::SeqCst), 0, "the auth check never runs");
}

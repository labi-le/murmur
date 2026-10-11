//! End-to-end tests for the JLS-over-`quinn` session: a real client and server complete a
//! handshake over a real loopback UDP socket, and then carry stream and datagram traffic.
//!
//! The JLS handshake's own wire format is covered by `murmur_jls_tls`'s `quic_tests`; what
//! these tests pin down is the layer above it — that `JlsSession` hands `quinn` keys at the right
//! encryption levels and in an order it can install, and that the `PacketConn` bridge actually
//! moves datagrams in both directions. The server side goes through `listen_early`, so the
//! `EarlyListener` path the shadowquic server drives is exercised too.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use murmur_component_ca::keypair::{new_random_tls_key_pair, KeyPairType};
use murmur_jls_tls::{JlsUser, ServerConfig as JlsServerConfig};
use murmur_quic::jls::{Conn, TransportFactory};
use murmur_quic::{Config, JlsStatus, TlsConfig, Version, VERSION2};
use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey as _;
use quinn::{ConnectionError, VarInt};
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::conn::QuinnTransportFactory;
use super::crypto::{JlsQuicClientConfig, JlsQuicServerConfig};
use super::socket::PacketConnSocket;
use super::{listen_early, CongestionOption};

const SERVER_NAME: &str = "example.com";
const ALPN: [&str; 1] = ["shadowquic"];
/// Generous enough that a loaded CI box does not turn a slow-but-correct handshake into a
/// failure, and short enough that a genuinely dead handshake still fails the test.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

fn user() -> JlsUser {
    JlsUser { username: "alice".to_owned(), password: "s3cret".to_owned() }
}

fn server_credentials() -> Arc<JlsServerConfig> {
    let (certificate_pem, private_key_pem, _) =
        new_random_tls_key_pair(KeyPairType::P256).expect("generate a camouflage key pair");
    Arc::new(JlsServerConfig {
        users: vec![user()],
        server_name: SERVER_NAME.to_owned(),
        alpn: ALPN.iter().map(|alpn| (*alpn).to_owned()).collect(),
        cert_der: pem_to_der(&certificate_pem, "CERTIFICATE"),
        key: SigningKey::from_pkcs8_der(&pem_to_der(&private_key_pem, "PRIVATE KEY"))
            .expect("the generated key is a valid PKCS#8 P-256 key"),
    })
}

fn pem_to_der(pem: &str, label: &str) -> Vec<u8> {
    use base64::Engine as _;

    let body = pem
        .split_once(&format!("-----BEGIN {label}-----"))
        .and_then(|(_, rest)| rest.split_once(&format!("-----END {label}-----")))
        .map(|(body, _)| body)
        .unwrap_or_else(|| panic!("no {label} block in PEM"));
    let unwrapped: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(unwrapped).expect("the PEM body is base64")
}

fn client_crypto(user: JlsUser) -> Arc<JlsQuicClientConfig> {
    Arc::new(JlsQuicClientConfig::new(
        ALPN.iter().map(|alpn| (*alpn).to_owned()).collect(),
        user,
        Arc::new(RootCertStore::empty()),
        None,
    ))
}

fn quic_config() -> Config {
    quic_config_with(Vec::new())
}

/// An empty set keeps quinn's defaults, as leaving `versions` unset does; a non-empty one is
/// advertised by `endpoint_config` and picked for the dial by `connect`.
fn quic_config_with(versions: Vec<Version>) -> Config {
    Config { versions, enable_datagrams: true, max_datagram_frame_size: 1400, ..Config::default() }
}

fn congestion() -> CongestionOption {
    CongestionOption { name: "bbr".to_owned(), cwnd: 32 }
}

/// A `PacketConn` over a `tokio::net::UdpSocket`, standing in for the dialer's proxy-aware conn.
struct SocketPacketConn {
    socket: tokio::net::UdpSocket,
    closed: CancellationToken,
}

impl SocketPacketConn {
    async fn bind() -> io::Result<(Self, SocketAddr)> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        Ok((Self { socket, closed: CancellationToken::new() }, addr))
    }
}

#[async_trait::async_trait]
impl PacketConn for SocketPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let (n, addr) = tokio::select! {
            () = self.closed.cancelled() => return Err(io::Error::new(io::ErrorKind::NotConnected, "closed")),
            result = self.socket.recv_from(buf) => result?,
        };
        Ok((n, Box::new(UdpAddr::from(addr))))
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.socket.send_to(buf, murmur_common_net::io::old_addr_to_socket_addr(addr)?).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(UdpAddr::from(self.socket.local_addr()?)))
    }

    fn close(&self) -> io::Result<()> {
        self.closed.cancel();
        Ok(())
    }
}

/// A server on loopback speaking the default versions.
async fn spawn_server() -> SocketAddr {
    spawn_server_with(quic_config()).await
}

/// Binds a JLS server on loopback and echoes every datagram and stream back, which is what the
/// client's assertions read. `config` is the server's `Config`, so its `versions` reach
/// `endpoint_config`'s `supported_versions`.
async fn spawn_server_with(config: Config) -> SocketAddr {
    let (packet_conn, addr) = SocketPacketConn::bind().await.expect("bind the server's loopback UDP socket");
    let listener =
        listen_early(Box::new(packet_conn), server_credentials(), config, congestion()).expect("bind the JLS listener");
    tokio::spawn(async move {
        while let Ok(conn) = listener.accept(&CancellationToken::new()).await {
            tokio::spawn(echo_connection(conn));
        }
    });
    addr
}

async fn echo_connection(conn: Arc<dyn Conn>) {
    let datagrams = Arc::clone(&conn);
    tokio::spawn(async move {
        while let Ok(datagram) = datagrams.receive_datagram(&CancellationToken::new()).await {
            if datagrams.send_datagram(datagram).is_err() {
                break;
            }
        }
    });
    while let Ok(stream) = conn.accept_stream(&CancellationToken::new()).await {
        tokio::spawn(async move {
            let (mut read_half, mut write_half) = stream.split();
            let mut buf = vec![0u8; 2048];
            while let Ok(n) = read_half.read(&mut buf).await {
                if n == 0 || write_half.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = write_half.close();
        });
    }
}

async fn dial(addr: SocketAddr, user: JlsUser) -> anyhow::Result<Arc<dyn Conn>> {
    dial_with(addr, user, quic_config()).await
}

async fn dial_with(addr: SocketAddr, user: JlsUser, config: Config) -> anyhow::Result<Arc<dyn Conn>> {
    let (packet_conn, _) = SocketPacketConn::bind().await?;
    let factory = QuinnTransportFactory::new(client_crypto(user), SERVER_NAME.to_owned(), congestion());
    let transport = factory.new_transport(Arc::new(packet_conn), 0);
    transport.set_created_conn(true);
    transport.set_single_use(true);
    transport.dial(&CancellationToken::new(), &UdpAddr::from(addr), &MarkerTls, &config).await
}

/// The dial's TLS-config argument: the transport reads its JLS credentials from the factory
/// it was built with, so the marker only has to satisfy the trait.
struct MarkerTls;

impl TlsConfig for MarkerTls {}

/// Dials `addr` with `config` and asserts the JLS session authenticated as `user`.
async fn dial_authenticated(addr: SocketAddr, user: JlsUser, config: Config) -> Arc<dyn Conn> {
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, dial_with(addr, user.clone(), config))
        .await
        .expect("the JLS handshake completes in time")
        .expect("the JLS handshake succeeds");
    let state = conn.connection_state();
    assert_eq!(state.tls.jls.status, JlsStatus::Authenticated, "the JLS credentials are accepted");
    assert_eq!(state.tls.jls.user, user.username, "the server reports the authenticated user");
    conn
}

/// Both directions of 1-RTT traffic: a stream and a datagram have to survive the installed keys.
async fn assert_session_carries_traffic(conn: &Arc<dyn Conn>) {
    let mut stream = conn.open_stream_sync(&CancellationToken::new()).await.expect("open a stream");
    stream.write_all(b"shadowquic").await.expect("write to the stream");
    stream.flush().await.expect("flush the stream");
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read(&mut buf))
        .await
        .expect("the echo arrives in time")
        .expect("read the echo");
    assert_eq!(&buf[..n], b"shadowquic", "the stream round-trips through 1-RTT keys");

    conn.send_datagram(b"ping".to_vec()).expect("send a datagram");
    let echoed = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.receive_datagram(&CancellationToken::new()))
        .await
        .expect("the datagram arrives in time")
        .expect("receive the datagram");
    assert_eq!(echoed, b"ping", "the datagram round-trips through 1-RTT keys");
}

/// The whole point of the session: both directions of the JLS handshake complete, the JLS
/// credentials are accepted, and traffic flows afterwards. A key installed at the wrong encryption
/// level fails here, not at the wire-format level `murmur_jls_tls`'s tests already cover.
#[tokio::test]
async fn jls_session_completes_handshake_and_carries_traffic() {
    let addr = spawn_server().await;
    let conn = dial_authenticated(addr, user(), quic_config()).await;
    assert_session_carries_traffic(&conn).await;
}

/// The same round trip with v2 on both ends, the version RFC 9369 changes the Initial salt and the
/// key labels for. Pins the `ClientConfig` version selection: left at quinn's v1 default a v2 dial
/// dies as `ConnectError::UnsupportedVersion` before a packet is sent.
#[tokio::test]
async fn v2_session_completes_handshake_and_carries_traffic() {
    let addr = spawn_server_with(quic_config_with(vec![VERSION2])).await;
    let conn = dial_authenticated(addr, user(), quic_config_with(vec![VERSION2])).await;
    assert_session_carries_traffic(&conn).await;
}

/// A v2-only client against a v1 listener must fail closed: the listener answers the Initial with a
/// Version Negotiation packet that does not list v2, and the dial ends as
/// `ConnectionError::VersionMismatch` rather than re-dialing on v1.
#[tokio::test]
async fn client_version_the_listener_does_not_speak_fails_closed() {
    let addr = spawn_server().await;
    let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, dial_with(addr, user(), quic_config_with(vec![VERSION2])))
        .await
        .expect("the dial fails rather than hanging");
    let Err(err) = result else { panic!("a v2-only client must not establish a session against a v1 listener") };
    assert!(
        matches!(err.downcast_ref::<ConnectionError>(), Some(ConnectionError::VersionMismatch)),
        "an unsupported version must fail as a version mismatch, not {err:?}"
    );
}

/// A client presenting the wrong password is rejected by the handshake, and never reaches the
/// server's stream handlers — the property `QuinnListener::accept` relies on when it drops a
/// failed handshake and loops.
#[tokio::test]
async fn wrong_jls_password_fails_the_handshake() {
    let addr = spawn_server().await;
    let wrong = JlsUser { username: user().username, password: "wrong".to_owned() };
    let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, dial(addr, wrong))
        .await
        .expect("the handshake fails rather than hanging");
    assert!(result.is_err(), "a client with the wrong password must not establish a session");
}

/// An unknown username fails the same way, which shows the rejection is the JLS check itself and
/// not some other transport problem: the identical code path succeeds for the right credentials
/// in `jls_session_completes_handshake_and_carries_traffic`.
#[tokio::test]
async fn unknown_jls_user_fails_the_handshake() {
    let addr = spawn_server().await;
    let unknown = JlsUser { username: "mallory".to_owned(), password: user().password };
    let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, dial(addr, unknown))
        .await
        .expect("the handshake fails rather than hanging");
    assert!(result.is_err(), "a client with an unknown username must not establish a session");
}

/// A JLS client session with no stored ticket has no early secret, so quinn's
/// `Connecting::into_0rtt` fails instead of attempting a 0-RTT flight nothing advertised.
/// (Replaces the earlier `jls_client_never_exposes_early_data_keys`, which pinned the same two
/// `None`s as evidence that the engine had no resumption at all; the ticket path now exists, so
/// what the test pins is the ticketless case.)
#[test]
fn a_jls_client_without_a_ticket_exposes_no_early_data_keys() {
    use quinn::crypto::ClientConfig as _;
    use quinn_proto::transport_parameters::TransportParameters;

    let config =
        Arc::new(JlsQuicClientConfig::new(vec![ALPN[0].to_owned()], user(), Arc::new(RootCertStore::empty()), None));
    let mut empty = &[][..];
    let params =
        TransportParameters::read(quinn::Side::Client, &mut empty).expect("an empty parameter list is all defaults");
    let session = config.start_session(1, SERVER_NAME, &params).expect("the JLS client session starts");
    assert!(session.early_crypto().is_none(), "a client with no ticket has no 0-RTT keys");
    assert!(session.early_data_accepted().is_none(), "0-RTT was never offered, so it cannot be accepted");
}

/// A quinn endpoint over the loopback `PacketConn` the tests bind.
async fn raw_endpoint(server: Option<quinn::ServerConfig>) -> (quinn::Endpoint, SocketAddr) {
    let (packet_conn, addr) = SocketPacketConn::bind().await.expect("bind a loopback UDP socket");
    let packet_conn: Arc<dyn PacketConn> = Arc::new(packet_conn);
    let socket = PacketConnSocket::new(packet_conn).expect("adapter");
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        server,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .expect("bind the endpoint");
    (endpoint, addr)
}

/// A quinn server whose connections report the first bytes of every stream they accept.
async fn spawn_raw_server(
    credentials: Arc<JlsServerConfig>,
    allow_0rtt: bool,
) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
    let server = quinn::ServerConfig::with_crypto(Arc::new(JlsQuicServerConfig::new(credentials, allow_0rtt)));
    let (endpoint, addr) = raw_endpoint(Some(server)).await;
    let (payloads, received) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Ok(connecting) = incoming.accept() else { continue };
            let Ok(connection) = connecting.await else { continue };
            let payloads = payloads.clone();
            tokio::spawn(async move {
                while let Ok((_send, mut recv)) = connection.accept_bi().await {
                    let mut buf = vec![0u8; 64];
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) if n > 0 => {
                            if payloads.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            });
        }
    });
    (addr, received)
}

async fn start_connect(addr: SocketAddr, crypto: Arc<JlsQuicClientConfig>) -> (quinn::Endpoint, quinn::Connecting) {
    let (endpoint, _) = raw_endpoint(None).await;
    let crypto: Arc<dyn quinn::crypto::ClientConfig> = crypto;
    let mut client = quinn::ClientConfig::new(crypto);
    client.transport_config(Arc::new(quinn::TransportConfig::default()));
    let connecting = endpoint.connect_with(client, addr, SERVER_NAME).expect("dial the JLS server");
    (endpoint, connecting)
}

/// The ticket the JLS client config keeps once a handshake has delivered one.
async fn wait_for_stored_session(crypto: &JlsQuicClientConfig) -> murmur_jls_tls::ClientSessionTicket {
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        if let Some(ticket) = crypto.stored_session() {
            return ticket;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the server's session ticket never reached the client");
}

/// The whole point of the resumption work: after one connection stores a ticket, the next
/// connection can send its first stream under 0-RTT keys, the server takes the early flight, and
/// the payload arrives.
#[tokio::test]
async fn a_resumed_client_rides_the_zero_rtt_flight() {
    let (addr, mut payloads) = spawn_raw_server(server_credentials(), true).await;
    let crypto = client_crypto(user());

    let (_endpoint, connecting) = tokio::time::timeout(HANDSHAKE_TIMEOUT, start_connect(addr, Arc::clone(&crypto)))
        .await
        .expect("the first handshake completes in time");
    let first = connecting.await.expect("the first JLS handshake succeeds");
    let ticket = wait_for_stored_session(&crypto).await;
    assert_eq!(ticket.max_early_data, u32::MAX, "RFC 9001 §4.6.1: a QUIC ticket that allows 0-RTT says so");
    assert_eq!(ticket.username, user().username, "the ticket is bound to the JLS identity that earned it");
    assert_eq!(ticket.alpn.as_deref(), Some(ALPN[0]), "RFC 8446 §4.2.10: the ticket records the ALPN to resume under");
    first.close(VarInt::from_u32(0), b"done");

    let (_endpoint, connecting) = start_connect(addr, crypto).await;
    let (connection, accepted) = connecting.into_0rtt().expect("a stored ticket yields 0-RTT keys");
    let (mut send, _echo) = connection.open_bi().await.expect("open the early stream");
    send.write_all(b"zero-rtt").await.expect("write the early payload");
    send.finish().expect("finish the early stream");

    assert!(
        tokio::time::timeout(HANDSHAKE_TIMEOUT, accepted).await.expect("the handshake completes in time"),
        "the server accepted the early flight"
    );
    let payload = tokio::time::timeout(HANDSHAKE_TIMEOUT, payloads.recv())
        .await
        .expect("the early payload arrives in time")
        .expect("the server read the early payload");
    assert_eq!(payload, b"zero-rtt", "the server read the payload the client wrote before the handshake");
}

/// The negative control: with an empty client session cache there is nothing to resume, so quinn
/// must refuse to start an early flight rather than send one the server never advertised.
#[tokio::test]
async fn a_client_without_a_ticket_never_attempts_zero_rtt() {
    let (addr, _payloads) = spawn_raw_server(server_credentials(), true).await;
    let (_endpoint, connecting) = start_connect(addr, client_crypto(user())).await;
    assert!(connecting.into_0rtt().is_err(), "a client with no stored ticket must not be able to send 0-RTT data");
}

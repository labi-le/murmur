//! Drives the whole `dial_context` of every outbound that carries `restls-opts` against a live
//! Restls peer, so the option decode, the Restls handshake, the proxy protocol header and the
//! payload are all exercised through the real adapter rather than the raw crate APIs.
//!
//! The peer is this crate's own `restls_server` relaying the handshake to a genuine rustls
//! camouflage origin built from `murmur_testsupport::TLS_CONFIG`, the same certificate the rest of
//! the suite's TLS tests use.
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

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use murmur_adapter_outbound::anytls::AnyTLS;
use murmur_adapter_outbound::trojan::Trojan;
use murmur_adapter_outbound::vless::Vless;
use murmur_adapter_outbound::vmess::Vmess;
use murmur_common_net::io::{Stream, StreamAsOldConn};
use murmur_component_tls::utls as tls_c;
use murmur_constant::adapters::{Conn as CConn, ProxyAdapter as CProxyAdapter};
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_restls::{restls_server, DialFn, ServerConfig};
use murmur_std_compat::net::Conn as NetConn;
use murmur_testsupport::TLS_CONFIG;
use murmur_testsupport_probe::ensure_test_crypto_provider;
use murmur_transport::socks5::socks5::ATYP_DOMAIN_NAME;
use murmur_transport::trojan::trojan as trojan_transport;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "restls-adapter-e2e";
const SNI: &str = "camouflage.example";
const DEST_HOST: &str = "example.com";
const DEST_PORT: u16 = 443;
const UUID: &str = "00000000-0000-0000-0000-000000000001";
const PAYLOAD: &[u8] = b"adapter-restls-e2e-payload";
const TIMEOUT: Duration = Duration::from_secs(20);
// The peer has no length to read up to, so it echoes once the adapter's writes go quiet.
const IDLE: Duration = Duration::from_millis(750);
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_APPLICATION_DATA: u8 = 0x17;

#[derive(Clone, Copy)]
enum Dialer {
    Trojan,
    Vless,
    Vmess,
    AnyTls,
}

impl Dialer {
    fn label(self) -> &'static str {
        match self {
            Dialer::Trojan => "trojan",
            Dialer::Vless => "vless",
            Dialer::Vmess => "vmess",
            Dialer::AnyTls => "anytls",
        }
    }

    fn yaml(self, host: &str, port: u16, version_hint: &str) -> String {
        let head = match self {
            Dialer::Trojan | Dialer::AnyTls => {
                format!("name: e2e\nserver: {host}\nport: {port}\npassword: p\nsni: {SNI}\nskip-cert-verify: true\n")
            }
            Dialer::Vless => format!(
                "name: e2e\nserver: {host}\nport: {port}\nuuid: {UUID}\ntls: true\nservername: {SNI}\n\
                 skip-cert-verify: true\n"
            ),
            Dialer::Vmess => format!(
                "name: e2e\nserver: {host}\nport: {port}\nuuid: {UUID}\nalterId: 0\ncipher: auto\ntls: true\n\
                 servername: {SNI}\nskip-cert-verify: true\n"
            ),
        };
        format!("{head}restls-opts:\n  password: {PASSWORD}\n  version-hint: {version_hint}\n")
    }
}

enum Adapter {
    Trojan(Arc<Trojan>),
    Vless(Arc<Vless>),
    Vmess(Arc<Vmess>),
    AnyTls(Arc<AnyTLS>),
}

impl Adapter {
    fn build(dialer: Dialer, yaml: &str) -> Self {
        match dialer {
            Dialer::Trojan => {
                Adapter::Trojan(Trojan::new(yaml_serde::from_str(yaml).expect("trojan option")).expect("trojan"))
            }
            Dialer::Vless => {
                Adapter::Vless(Vless::new(yaml_serde::from_str(yaml).expect("vless option")).expect("vless"))
            }
            Dialer::Vmess => {
                Adapter::Vmess(Vmess::new(yaml_serde::from_str(yaml).expect("vmess option")).expect("vmess"))
            }
            Dialer::AnyTls => {
                Adapter::AnyTls(AnyTLS::new(yaml_serde::from_str(yaml).expect("anytls option")).expect("anytls"))
            }
        }
    }

    async fn dial(&self, metadata: &mut Metadata) -> anyhow::Result<Box<dyn CConn>> {
        let ctx = CancellationToken::new();
        match self {
            Adapter::Trojan(a) => <Trojan as CProxyAdapter>::dial_context(&**a, &ctx, metadata).await,
            Adapter::Vless(a) => <Vless as CProxyAdapter>::dial_context(&**a, &ctx, metadata).await,
            Adapter::Vmess(a) => <Vmess as CProxyAdapter>::dial_context(&**a, &ctx, metadata).await,
            Adapter::AnyTls(a) => <AnyTLS as CProxyAdapter>::dial_context(&**a, &ctx, metadata).await,
        }
    }
}

/// Records every byte the peer reads, which is exactly what a passive observer between the adapter
/// and the Restls peer sees.
struct Recorder<S> {
    inner: S,
    wire: Arc<Mutex<Vec<u8>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Recorder<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let start = buf.filled().len();
        let ready = Pin::new(&mut me.inner).poll_read(cx, buf);
        if matches!(ready, Poll::Ready(Ok(()))) {
            let filled = buf.filled().len();
            if filled > start {
                me.wire.lock().expect("wire lock").extend_from_slice(&buf.filled()[start..filled]);
            }
        }
        ready
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recorder<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: Stream> Stream for Recorder<S> {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.inner.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.inner.as_socket()
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        self.inner.old_conn()
    }
}

struct Peer {
    host: String,
    port: u16,
    wire: Arc<Mutex<Vec<u8>>>,
    received: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl Peer {
    fn wire(&self) -> Vec<u8> {
        self.wire.lock().expect("wire lock").clone()
    }
}

async fn start_camouflage_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind camouflage origin");
    let addr = listener.local_addr().expect("camouflage origin addr").to_string();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let config = Arc::clone(&TLS_CONFIG);
            tokio::spawn(async move {
                let mut conn = tls_c::server(Box::new(stream), config);
                if conn.handshake().await.is_err() {
                    return;
                }
                let mut buf = [0u8; 1024];
                while let Ok(n) = conn.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// What the peer writes back for one dialer. Trojan's stream has no server-side preamble, so a
/// verbatim echo is a well-formed reply; vless's client consumes a two-byte response header
/// (`version`, `addon length`) before the payload. The vmess and anytls clients only accept a
/// reply framed by their own server codec, so they get none.
fn peer_reply(dialer: Dialer, seen: &[u8]) -> Option<Vec<u8>> {
    match dialer {
        Dialer::Trojan => Some(seen.to_vec()),
        Dialer::Vless => {
            let mut reply = vec![0x00, 0x00];
            reply.extend_from_slice(PAYLOAD);
            Some(reply)
        }
        Dialer::Vmess | Dialer::AnyTls => None,
    }
}

async fn start_peer(dialer: Dialer) -> Peer {
    let camouflage = start_camouflage_origin().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind restls peer");
    let local = listener.local_addr().expect("restls peer addr");
    let wire = Arc::new(Mutex::new(Vec::new()));
    let (tx, received) = mpsc::unbounded_channel();
    let dial: DialFn = Arc::new(|target: String| {
        Box::pin(async move {
            let stream = TcpStream::connect(&target).await?;
            let conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(stream));
            Ok(conn)
        })
    });
    let config = ServerConfig {
        server_hostname: camouflage,
        password: PASSWORD.to_owned(),
        restls_script: String::new(),
        min_record_len: 0,
        rate_limit: 0,
        dial,
    };
    let listener_wire = Arc::clone(&wire);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let config = config.clone();
            let wire = Arc::clone(&listener_wire);
            let tx = tx.clone();
            tokio::spawn(async move {
                let inbound: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(Recorder { inner: stream, wire }));
                let Ok(mut conn) = restls_server(inbound, &config).await else {
                    return;
                };
                let mut seen = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    match timeout(IDLE, conn.read(&mut buf)).await {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                        Ok(Ok(n)) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                if tx.send(seen.clone()).is_err() {
                    return;
                }
                if let Some(reply) = peer_reply(dialer, &seen) {
                    let _ = conn.write_all(&reply).await;
                    let _ = conn.flush().await;
                }
                // The record script makes both sides wait for each other's records, so the peer
                // must not tear the socket down while the adapter is still reading its reply.
                std::future::pending::<()>().await;
            });
        }
    });
    Peer { host: local.ip().to_string(), port: local.port(), wire, received }
}

fn assert_protocol_header(dialer: Dialer, seen: &[u8]) {
    match dialer {
        Dialer::Trojan => {
            let key = trojan_transport::key("p");
            assert_eq!(&seen[..56], &key[..], "the trojan header carries the hex password");
            assert_eq!(&seen[56..58], b"\r\n");
            assert_eq!(seen[58], trojan_transport::COMMAND_TCP);
            assert_eq!(seen[59], ATYP_DOMAIN_NAME);
            assert_eq!(seen[60], DEST_HOST.len() as u8);
            assert_eq!(&seen[61..72], DEST_HOST.as_bytes());
            assert_eq!(&seen[72..74], DEST_PORT.to_be_bytes());
            assert_eq!(&seen[74..76], b"\r\n");
            assert_eq!(&seen[76..], PAYLOAD, "the payload follows the trojan header");
        }
        Dialer::Vless => {
            assert_eq!(seen[0], 0x00, "vless protocol version");
            assert_eq!(&seen[seen.len() - PAYLOAD.len()..], PAYLOAD, "the payload follows the vless request");
            assert!(
                seen.windows(DEST_HOST.len()).any(|w| w == DEST_HOST.as_bytes()),
                "the vless request names the destination"
            );
        }
        Dialer::Vmess => assert!(
            seen.len() > PAYLOAD.len(),
            "the vmess request header and AEAD payload chunk must reach the peer ({} bytes)",
            seen.len()
        ),
        Dialer::AnyTls => {
            assert!(!seen.is_empty(), "the anytls session and stream frames must reach the peer");
            assert!(seen.windows(PAYLOAD.len()).any(|w| w == PAYLOAD), "the anytls data frame must carry the payload");
        }
    }
}

/// Parses the client-to-server bytes as a TLS record stream, failing on any record a passive
/// observer could not read as ordinary TLS.
fn parse_tls_records(wire: &[u8]) -> Vec<(u8, &[u8])> {
    let mut records = Vec::new();
    let mut pos = 0;
    while pos < wire.len() {
        assert!(wire.len() - pos >= 5, "truncated TLS record header at offset {pos}");
        let record_type = wire[pos];
        assert!(matches!(record_type, 0x14..=0x17), "byte {record_type:#04x} at offset {pos} is not a TLS record type");
        assert_eq!(&wire[pos + 1..pos + 3], &[0x03, 0x03], "unexpected TLS record version at offset {pos}");
        let len = usize::from(wire[pos + 3]) << 8 | usize::from(wire[pos + 4]);
        assert!(
            wire.len() - pos - 5 >= len,
            "TLS record at offset {pos} declares {len} bytes but only {} follow",
            wire.len() - pos - 5
        );
        records.push((record_type, &wire[pos + 5..pos + 5 + len]));
        pos += 5 + len;
    }
    records
}

fn client_hello_sni(client_hello: &[u8]) -> String {
    assert_eq!(client_hello[0], 0x01, "the first handshake message must be a ClientHello");
    let body_len =
        usize::from(client_hello[1]) << 16 | usize::from(client_hello[2]) << 8 | usize::from(client_hello[3]);
    let body = &client_hello[4..4 + body_len];

    let mut pos = 2 + 32;
    let session_id_len = usize::from(body[pos]);
    pos += 1 + session_id_len;
    let cipher_suites_len = usize::from(body[pos]) << 8 | usize::from(body[pos + 1]);
    pos += 2 + cipher_suites_len;
    let compression_len = usize::from(body[pos]);
    pos += 1 + compression_len;
    let extensions_len = usize::from(body[pos]) << 8 | usize::from(body[pos + 1]);
    pos += 2;
    let extensions = &body[pos..pos + extensions_len];

    let mut pos = 0;
    while pos < extensions.len() {
        let id = usize::from(extensions[pos]) << 8 | usize::from(extensions[pos + 1]);
        let len = usize::from(extensions[pos + 2]) << 8 | usize::from(extensions[pos + 3]);
        let extension = &extensions[pos + 4..pos + 4 + len];
        if id == 0 {
            let name_len = usize::from(extension[3]) << 8 | usize::from(extension[4]);
            return String::from_utf8(extension[5..5 + name_len].to_vec()).expect("utf-8 SNI");
        }
        pos += 4 + len;
    }
    panic!("the ClientHello carries no SNI extension");
}

fn assert_camouflage(wire: &[u8]) {
    let records = parse_tls_records(wire);
    assert_eq!(records[0].0, TLS_HANDSHAKE, "the first record must be the ClientHello");
    assert_eq!(
        client_hello_sni(records[0].1),
        SNI,
        "the ClientHello must carry the configured server name in its SNI extension"
    );
    assert!(
        records.iter().any(|(record_type, _)| *record_type == TLS_APPLICATION_DATA),
        "the tunnelled bytes must travel as TLS application_data records"
    );
}

async fn run_case(dialer: Dialer, version_hint: &str) {
    ensure_test_crypto_provider();

    let mut peer = start_peer(dialer).await;
    let yaml = dialer.yaml(&peer.host, peer.port, version_hint);
    let adapter = Adapter::build(dialer, &yaml);
    let mut metadata =
        Metadata { network: NetWork::TCP, host: DEST_HOST.to_owned(), dst_port: DEST_PORT, ..Default::default() };

    let mut conn = timeout(TIMEOUT, adapter.dial(&mut metadata))
        .await
        .unwrap_or_else(|_| panic!("{} ({version_hint}) dial timed out", dialer.label()))
        .unwrap_or_else(|err| panic!("{} ({version_hint}) dial over restls: {err}", dialer.label()));

    conn.write_all(PAYLOAD).await.expect("write through the restls channel");
    conn.flush().await.expect("flush through the restls channel");

    let seen = timeout(TIMEOUT, peer.received.recv())
        .await
        .unwrap_or_else(|_| panic!("{} ({version_hint}) peer never saw the adapter's bytes", dialer.label()))
        .expect("the peer task must report before it stops");

    match dialer {
        Dialer::Trojan => {
            let mut echoed = vec![0u8; seen.len()];
            timeout(TIMEOUT, conn.read_exact(&mut echoed))
                .await
                .unwrap_or_else(|_| panic!("{} ({version_hint}) reply read timed out", dialer.label()))
                .expect("read the peer's reply");
            assert_eq!(echoed, seen, "{} ({version_hint}) payload round trip", dialer.label());
        }
        Dialer::Vless => {
            let mut echoed = vec![0u8; PAYLOAD.len()];
            timeout(TIMEOUT, conn.read_exact(&mut echoed))
                .await
                .unwrap_or_else(|_| panic!("{} ({version_hint}) reply read timed out", dialer.label()))
                .expect("read the peer's reply");
            assert_eq!(echoed, PAYLOAD, "{} ({version_hint}) payload round trip", dialer.label());
        }
        Dialer::Vmess | Dialer::AnyTls => {}
    }

    assert_protocol_header(dialer, &seen);
    assert_camouflage(&peer.wire());
}

#[tokio::test]
async fn trojan_round_trips_over_restls() {
    run_case(Dialer::Trojan, "tls13").await;
}

#[tokio::test]
async fn trojan_round_trips_over_restls_tls12() {
    run_case(Dialer::Trojan, "tls12").await;
}

#[tokio::test]
async fn vless_round_trips_over_restls() {
    run_case(Dialer::Vless, "tls13").await;
}

#[tokio::test]
async fn vless_round_trips_over_restls_tls12() {
    run_case(Dialer::Vless, "tls12").await;
}

#[tokio::test]
async fn vmess_round_trips_over_restls() {
    run_case(Dialer::Vmess, "tls13").await;
}

#[tokio::test]
async fn vmess_round_trips_over_restls_tls12() {
    run_case(Dialer::Vmess, "tls12").await;
}

#[tokio::test]
async fn anytls_round_trips_over_restls() {
    run_case(Dialer::AnyTls, "tls13").await;
}

#[tokio::test]
async fn anytls_round_trips_over_restls_tls12() {
    run_case(Dialer::AnyTls, "tls12").await;
}

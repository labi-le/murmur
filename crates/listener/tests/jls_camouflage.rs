//! Listener-level camouflage tests for the JLS-wrapped VLESS listener: a probe that fails the
//! JLS handshake must end up at the configured destination through the tunnel, never at the
//! VLESS service.
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

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::listen::default_listen_config;
use murmur_common_net::io::{Stream, StreamAsOldConn};
use murmur_component_nat::table::Table;
use murmur_constant::adapters::{NatTable, UDPPacket};
use murmur_constant::metadata::{Metadata, Type};
use murmur_constant::tunnel::Tunnel;
use murmur_listener::sing_vless::server::{new as new_vless_listener, Listener};
use murmur_listener_config::jls::{JLSConfig, JLSUser};
use murmur_listener_config::vless::{VlessServer, VlessUser};
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport_jls::client::{new_client, new_client_config};

const USERNAME: &str = "foo";
const PASSWORD: &str = "bar";
const SNI: &str = "example.com";
const UUID: &str = "b2b1e0aa-1c8f-4d3c-9d1f-2f2c1234abcd";
/// Nothing listens here: the test tunnel stands in for the dial, so `dest` is never dialed.
const DEST: &str = "127.0.0.1:8443";
const SERVED_ALPN: &str = "h2";
const UNSERVED_ALPN: &str = "h3";
const REPLY: &[u8] = b"CAMOUFLAGE-ORIGIN\r\n";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);
const FIRST_READ_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_CAPTURE: usize = 16 * 1024;

#[derive(Debug)]
struct Dial {
    address: String,
    type_: Type,
    received: Vec<u8>,
}

/// Stands in for both the tunnel and the camouflage origin: the fallback relay dials the
/// configured destination through the tunnel, so the bytes handed to `handle_tcp_conn` are the
/// bytes that would reach the camouflage server.
#[derive(Default)]
struct CamouflageTunnel {
    dials: Mutex<Vec<Dial>>,
}

impl CamouflageTunnel {
    fn take_dials(&self) -> Vec<Dial> {
        std::mem::take(&mut *self.dials.lock().expect("camouflage dial log"))
    }
}

#[async_trait]
impl Tunnel for CamouflageTunnel {
    async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, metadata: Metadata) {
        let mut received = Vec::new();
        let mut chunk = [0u8; 4096];
        if let Ok(Ok(n)) = tokio::time::timeout(FIRST_READ_TIMEOUT, conn.read(&mut chunk)).await {
            received.extend_from_slice(&chunk[..n]);
            while received.len() < MAX_CAPTURE {
                match tokio::time::timeout(IDLE_TIMEOUT, conn.read(&mut chunk)).await {
                    Ok(Ok(n)) if n > 0 => received.extend_from_slice(&chunk[..n]),
                    _ => break,
                }
            }
        }
        self.dials.lock().expect("camouflage dial log").push(Dial {
            address: metadata.remote_address(),
            type_: metadata.type_,
            received,
        });
        let _ = conn.write_all(REPLY).await;
        let _ = conn.flush().await;
    }

    fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {}

    fn nat_table(&self) -> Arc<dyn NatTable> {
        Arc::new(Table::default())
    }
}

/// Records what a client writes, so a fallback can be compared against the exact client bytes.
struct TapStream {
    inner: TcpStream,
    sent: Arc<Mutex<Vec<u8>>>,
}

impl tokio::io::AsyncRead for TapStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TapStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let n = match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        };
        this.sent.lock().expect("tap buffer").extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for TapStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
}

fn vless_config() -> VlessServer {
    VlessServer {
        enable: true,
        listen: "127.0.0.1:0".to_owned(),
        users: vec![VlessUser { username: USERNAME.to_owned(), uuid: UUID.to_owned(), flow: String::new() }],
        jls_config: JLSConfig {
            enable: true,
            users: vec![JLSUser { username: USERNAME.to_owned(), password: PASSWORD.to_owned() }],
            sni: SNI.to_owned(),
            dest: DEST.to_owned(),
            alpn: Some(vec![SERVED_ALPN.to_owned()]),
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn start(tunnel: Arc<CamouflageTunnel>) -> (Listener, SocketAddr) {
    let listener = new_vless_listener(vless_config(), default_listen_config(), tunnel, &[])
        .await
        .expect("the jls-wrapped vless listener builds");
    let addr = listener
        .addr_list()
        .first()
        .and_then(|addr| addr.string().parse().ok())
        .expect("the listener reports its bound address");
    (listener, addr)
}

async fn send_http_probe(listener_addr: SocketAddr) {
    let mut probe = TcpStream::connect(listener_addr).await.expect("connect the probe");
    probe.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n").await.expect("write the probe");
    let mut reply = [0u8; REPLY.len()];
    probe.read_exact(&mut reply).await.expect("the camouflage origin's reply reaches the probe");
    assert_eq!(&reply, REPLY, "the probe speaks to the camouflage origin, not to vless");
}

async fn send_unserved_alpn_client(listener_addr: SocketAddr) -> Vec<u8> {
    let raw = TcpStream::connect(listener_addr).await.expect("connect the jls client");
    let sent = Arc::new(Mutex::new(Vec::new()));
    let conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(TapStream { inner: raw, sent: Arc::clone(&sent) }));
    let config = new_client_config(SNI, USERNAME, PASSWORD, Some(vec![UNSERVED_ALPN.to_owned()]))
        .expect("the client config builds");
    let result = new_client(&CancellationToken::new(), conn, &config).await;
    assert!(result.is_err(), "an alpn the server does not serve must not be tunnelled");
    let hello = sent.lock().expect("tap buffer").clone();
    assert!(hello.len() >= 5 && hello[0] == 0x16, "the client sent a ClientHello, got {hello:?}");
    hello
}

/// `Server`: a handshake that fails before the first server byte is relayed to the fallback
/// destination rather than served.
#[tokio::test]
async fn a_plain_http_probe_is_relayed_to_the_camouflage_destination() {
    const PROBE: &[u8] = b"GET / HTTP/1.1\r\nHost: example.com\r\n";

    tokio::time::timeout(TEST_TIMEOUT, async {
        let tunnel = Arc::new(CamouflageTunnel::default());
        let (listener, addr) = start(Arc::clone(&tunnel)).await;

        send_http_probe(addr).await;

        let dials = tunnel.take_dials();
        assert_eq!(dials.len(), 1, "one probe means one relay, got {dials:?}");
        assert_eq!(dials[0].address, DEST, "the fallback relay dials the configured destination");
        assert_eq!(dials[0].type_, Type::INNER, "the tunnel handler tags the fallback dial INNER");
        assert_eq!(dials[0].received, PROBE, "the probe reaches the tunnel verbatim");

        listener.close().expect("close the listener");
    })
    .await
    .expect("the camouflage relay completes in time");
}

/// The fallback relay reached from the ALPN mismatch: the client is authenticated, but the ALPN
/// negotiation
/// fails before the first flight byte, so the ClientHello goes to the camouflage destination and no
/// JLS tunnel exists.
#[tokio::test]
async fn an_alpn_the_server_does_not_serve_is_relayed_to_the_camouflage_destination() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let tunnel = Arc::new(CamouflageTunnel::default());
        let (listener, addr) = start(Arc::clone(&tunnel)).await;

        let hello = send_unserved_alpn_client(addr).await;

        let dials = tunnel.take_dials();
        assert_eq!(dials.len(), 1, "one probe means one relay, got {dials:?}");
        assert_eq!(dials[0].address, DEST, "the fallback dials the configured destination");
        assert_eq!(dials[0].type_, Type::INNER, "the fallback dial goes through the tunnel as INNER");
        assert_eq!(dials[0].received, hello, "the ClientHello is replayed to the camouflage destination verbatim");

        listener.close().expect("close the listener");
    })
    .await
    .expect("the camouflage relay completes in time");
}

/// A handle-context listener's init: a failed handler closes the conn and never delivers it to
/// `Accept`, so the accept loop survives fallbacks.
#[tokio::test]
async fn the_listener_still_completes_a_jls_handshake_after_fallbacks() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let tunnel = Arc::new(CamouflageTunnel::default());
        let (listener, addr) = start(Arc::clone(&tunnel)).await;

        send_http_probe(addr).await;
        send_unserved_alpn_client(addr).await;

        let raw = TcpStream::connect(addr).await.expect("connect the jls client");
        let config = new_client_config(SNI, USERNAME, PASSWORD, Some(vec![SERVED_ALPN.to_owned()]))
            .expect("the client config builds");
        let conn = new_client(&CancellationToken::new(), Box::new(StreamAsOldConn::new(raw)), &config)
            .await
            .expect("a legitimate jls client still authenticates after two fallbacks");
        drop(conn);

        let dials = tunnel.take_dials();
        assert_eq!(dials.len(), 2, "only the two probes are relayed, got {dials:?}");
        assert!(
            dials.iter().all(|dial| dial.type_ == Type::INNER && dial.address == DEST),
            "every relay is the fallback dial to the configured destination; a vless tunnel would carry `Type::VLESS`, got {dials:?}"
        );

        listener.close().expect("close the listener");
    })
    .await
    .expect("the camouflage relay completes in time");
}

//! Shared test harness for `listener::inbound` integration tests.
//!
//! DEVIATION: the mock tunnel serves a connection by calling `hyper`'s `serve_connection` directly
//! from `handle_tcp_conn`, instead of handing it to a listener that serves it from a separate
//! task; the call blocks for exactly as long as the mock HTTP server serves that connection, so
//! the observable contract (a mock HTTP/HTTPS origin reachable at `REMOTE_ADDR:80` /
//! `REMOTE_ADDR:443`) is unchanged.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![cfg_attr(
    test,
    allow(
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
    )
)]

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::RngCore;
use tokio_util::sync::CancellationToken;

use murmur_common::utils::uuid::new_uuid_v4;
use murmur_common_net::io::Stream;
use murmur_common_pool::RELAY_BUFFER_SIZE;
use murmur_component::dialer::dialer::{new_dialer, Dialer as ComponentDialer};
use murmur_component_ca::config as ca_config;
use murmur_component_ca::keypair::{new_random_tls_key_pair, x509_key_pair, KeyPairType};
use murmur_component_ech::key::gen_ech_config;
use murmur_component_nat::table::Table;
use murmur_component_tls::utls;
use murmur_constant::adapters::{Conn as CConn, Dialer as CDialer, NatTable, ProxyAdapter as CProxyAdapter};
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_constant::tunnel::Tunnel;
use murmur_ntp::time::now as ntp_now;

pub const HTTP_PATH: &str = "/inbound_test";

pub static HTTP_DATA: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut data = vec![0u8; 2 * RELAY_BUFFER_SIZE];
    rand::rng().fill_bytes(&mut data);
    data
});

pub static REMOTE_ADDR: LazyLock<IpAddr> = LazyLock::new(|| IpAddr::from([1, 2, 3, 4]));

pub static USER_UUID: LazyLock<String> = LazyLock::new(|| new_uuid_v4().to_string());

/// `(certificate, private_key, fingerprint)`, the `tlsCertificate, tlsPrivateKey, tlsFingerprint`.
#[expect(clippy::expect_used, reason = "a key-generation failure must abort the test")]
pub static TLS_KEY_PAIR: LazyLock<(String, String, String)> =
    LazyLock::new(|| new_random_tls_key_pair(KeyPairType::P256).expect("key generation"));

/// the `tlsAuthCertificate, tlsAuthPrivateKey`: a second keypair used by client-cert-auth tests.
#[expect(clippy::expect_used, reason = "a key-generation failure must abort the test")]
pub static TLS_AUTH_KEY_PAIR: LazyLock<(String, String, String)> =
    LazyLock::new(|| new_random_tls_key_pair(KeyPairType::P256).expect("key generation"));

#[must_use]
pub fn tls_certificate() -> &'static str {
    &TLS_KEY_PAIR.0
}
#[must_use]
pub fn tls_private_key() -> &'static str {
    &TLS_KEY_PAIR.1
}
#[must_use]
pub fn tls_fingerprint() -> &'static str {
    &TLS_KEY_PAIR.2
}
#[must_use]
pub fn tls_auth_certificate() -> &'static str {
    &TLS_AUTH_KEY_PAIR.0
}
#[must_use]
pub fn tls_auth_private_key() -> &'static str {
    &TLS_AUTH_KEY_PAIR.1
}

/// The mock origin's server-side TLS config.
#[expect(clippy::expect_used, reason = "a certificate-loading failure must abort the test")]
pub static TLS_CONFIG: LazyLock<Arc<utls::Config>> = LazyLock::new(|| {
    let certificate = x509_key_pair(tls_certificate().as_bytes(), tls_private_key().as_bytes())
        .expect("well-formed self-signed certificate");
    Arc::new(utls::Config {
        time: Some(Arc::new(ntp_now)),
        certificates: vec![certificate],
        next_protos: vec!["h2".to_owned(), "http/1.1".to_owned()],
        // Tickets are disabled: one emitted after the client's `Finished` - what rustls and every
        // OpenSSL- or BoringSSL-backed destination do - would leak a trailing ciphertext record
        // onto shadow-tls v2's camouflage connection after the client switched to tunnel mode.
        session_tickets_disabled: true,
        ..Default::default()
    })
});

/// The test client's TLS config, pinned to `TLS_CONFIG`'s fingerprint.
///
/// `next_protos` must be set explicitly: the harness drives the TLS handshake directly instead of
/// through a transport that adds `h2` to the ALPN offer by default.
#[expect(clippy::expect_used, reason = "a fingerprint-verifier failure must abort the test")]
pub static TLS_CLIENT_CONFIG: LazyLock<Arc<utls::Config>> = LazyLock::new(|| {
    Arc::new(
        ca_config::get_tls_config(ca_config::Option {
            tls_config: Some(utls::Config {
                next_protos: vec!["h2".to_owned(), "http/1.1".to_owned()],
                ..Default::default()
            }),
            fingerprint: tls_fingerprint().to_owned(),
            ..Default::default()
        })
        .expect("fingerprint verifier construction"),
    )
});

pub const REALITY_DEST: &str = "itunes.apple.com";
/// The "dial the real destination" branch is unreachable, so it is omitted rather than stubbed.
pub const REALITY_REAL_DIAL: bool = false;

pub const ECH_PUBLIC_SNI: &str = "public.sni";
#[expect(clippy::expect_used, reason = "an ECH-config generation failure must abort the test")]
pub static ECH_CONFIG: LazyLock<(String, String)> =
    LazyLock::new(|| gen_ech_config(ECH_PUBLIC_SNI).expect("ech config generation"));
#[must_use]
pub fn ech_config_base64() -> &'static str {
    &ECH_CONFIG.0
}
#[must_use]
pub fn ech_key_pem() -> &'static str {
    &ECH_CONFIG.1
}

/// the `TestDialer`: retries a local dial that failed only from port exhaustion under
/// concurrent load, never from context cancellation.
#[derive(Debug)]
pub struct TestDialer {
    dialer: ComponentDialer,
    ctx: CancellationToken,
}

impl TestDialer {
    #[must_use]
    pub fn new(ctx: CancellationToken) -> Self {
        Self { dialer: new_dialer(Vec::new()), ctx }
    }
}

#[async_trait]
impl CDialer for TestDialer {
    async fn dial_context(&self, ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn Stream>> {
        loop {
            match self.dialer.dial_context(ctx, network, address).await {
                Ok(conn) => return Ok(conn),
                Err(err) if ctx.is_cancelled() || self.ctx.is_cancelled() => return Err(err),
                Err(_) => {}
            }
        }
    }

    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
        r_addr_port: Option<std::net::SocketAddr>,
    ) -> Result<Box<dyn murmur_common_net::io::Datagram>> {
        self.dialer.listen_packet(ctx, network, address, r_addr_port).await
    }
}

struct AsStreamConn(Box<dyn CConn>);

/// the harness closes every dialed connection when the function returns. Most protocols'
/// dialed conn is a thin wrapper over a real socket that closing on drop already tears down, but
/// `xhttp`'s dialed conn is a virtual handle over background tasks holding their own transport
/// `Arc`s (the stream-up/packet-up download GET in particular): nothing but an explicit `close()`
/// call ever fires `Conn`'s `on_close`, so without this the harness leaked one open download
/// connection and task per xhttp dial across a test run.
impl Drop for AsStreamConn {
    fn drop(&mut self) {
        let _ = self.0.shutdown_read();
        let _ = self.0.shutdown_write();
    }
}

impl tokio::io::AsyncRead for AsStreamConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for AsStreamConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

impl Stream for AsStreamConn {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.0.local_addr()
    }
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.0.peer_addr()
    }
    fn shutdown_read(&self) -> std::io::Result<()> {
        self.0.shutdown_read()
    }
    fn shutdown_write(&self) -> std::io::Result<()> {
        self.0.shutdown_write()
    }
}

async fn http_echo_handler(req: Request<Incoming>) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    let size: usize = req
        .uri()
        .query()
        .and_then(|query| query.split('&').find_map(|kv| kv.strip_prefix("size=")))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
        .min(HTTP_DATA.len());
    let _ = req.into_body().collect().await;
    let (payload, _) = HTTP_DATA.split_at(size);
    Ok(Response::new(Full::new(Bytes::copy_from_slice(payload))))
}

/// A tunnel whose `handle_tcp_conn` serves a mock HTTP/HTTPS origin at `REMOTE_ADDR:80` /
/// `REMOTE_ADDR:443` (or at `REALITY_DEST` for the reality tests), plus the helpers the tests
/// drive it with.
#[derive(Debug)]
pub struct HttpTestTunnel {
    ctx: CancellationToken,
    cancel: CancellationToken,
}

impl HttpTestTunnel {
    #[must_use]
    pub fn new() -> Arc<Self> {
        let ctx = CancellationToken::new();
        Arc::new(Self { ctx: ctx.clone(), cancel: ctx })
    }

    /// Cancels the shared context, stopping every connection the tunnel is serving.
    pub fn close(&self) {
        self.cancel.cancel();
    }

    #[must_use]
    pub fn new_dialer(&self) -> Arc<dyn CDialer> {
        Arc::new(TestDialer::new(self.ctx.clone()))
    }

    async fn request(&self, proxy: &dyn CProxyAdapter, proto: &str, size: usize) -> Result<()> {
        let Some(payload) = HTTP_DATA.get(..size) else {
            return Err(anyhow!("payload size {size} exceeds {}", HTTP_DATA.len()));
        };
        let dst_port: u16 = if proto == "https" { 443 } else { 80 };
        let mut metadata =
            Metadata { network: NetWork::TCP, dst_ip: Some(*REMOTE_ADDR), dst_port, ..Default::default() };
        let instance = proxy.dial_context(&self.ctx, &mut metadata).await?;
        let io = AsStreamConn(instance);
        let body = Full::new(Bytes::copy_from_slice(payload));
        let uri: hyper::Uri = format!("{proto}://{}{HTTP_PATH}?size={size}", *REMOTE_ADDR).parse()?;
        let host_header = format!("{}:{dst_port}", *REMOTE_ADDR);

        let (status, response_body, is_h2) = if proto == "https" {
            let tls_conn = utls::client(Box::new(io), TLS_CLIENT_CONFIG.clone());
            tls_conn.handshake_context(&self.ctx).await?;
            let negotiated_h2 = tls_conn.connection_state().negotiated_protocol == "h2";
            let tls_io = TokioIo::new(tls_conn);
            if negotiated_h2 {
                let (mut sender, conn) =
                    hyper::client::conn::http2::Builder::new(TokioExecutor::new()).handshake(tls_io).await?;
                let mut conn_task = tokio::spawn(conn);
                let req = Request::post(uri).header(hyper::header::HOST, host_header).body(body)?;
                let response = sender.send_request(req).await?;
                let status = response.status();
                let body = response.into_body().collect().await?.to_bytes();
                drop(sender);
                if tokio::time::timeout(std::time::Duration::from_millis(200), &mut conn_task).await.is_err() {
                    conn_task.abort();
                    let _ = conn_task.await;
                }
                (status, body, true)
            } else {
                let (mut sender, conn) = hyper::client::conn::http1::handshake(tls_io).await?;
                let mut conn_task = tokio::spawn(conn);
                let req = Request::post(uri).header(hyper::header::HOST, host_header).body(body)?;
                let response = sender.send_request(req).await?;
                let status = response.status();
                let body = response.into_body().collect().await?.to_bytes();
                drop(sender);
                if tokio::time::timeout(std::time::Duration::from_millis(200), &mut conn_task).await.is_err() {
                    conn_task.abort();
                    let _ = conn_task.await;
                }
                (status, body, false)
            }
        } else {
            let plain_io = TokioIo::new(io);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(plain_io).await?;
            let mut conn_task = tokio::spawn(conn);
            let req = Request::post(uri).header(hyper::header::HOST, host_header).body(body)?;
            let response = sender.send_request(req).await?;
            let status = response.status();
            let body = response.into_body().collect().await?.to_bytes();
            drop(sender);
            if tokio::time::timeout(std::time::Duration::from_millis(200), &mut conn_task).await.is_err() {
                conn_task.abort();
                let _ = conn_task.await;
            }
            (status, body, false)
        };

        if status != hyper::StatusCode::OK {
            return Err(anyhow!("unexpected status {status}"));
        }
        if proto == "https" && !is_h2 {
            return Err(anyhow!("https request did not negotiate http/2"));
        }
        if response_body.as_ref() != payload {
            return Err(anyhow!("response body mismatch for size {size}"));
        }
        Ok(())
    }

    #[expect(clippy::expect_used, reason = "a failed mock-origin round trip must abort the test")]
    pub async fn do_sequential_test(&self, proxy: &dyn CProxyAdapter) {
        if std::env::var_os("TRUST_HTTP_ONLY").is_some() {
            self.request(proxy, "http", HTTP_DATA.len()).await.expect("sequential http round trip");
            return;
        }
        if std::env::var_os("TRUST_HTTPS_ONLY").is_some() {
            let size = std::env::var("TRUST_SIZE").ok().and_then(|value| value.parse().ok()).unwrap_or(HTTP_DATA.len());
            self.request(proxy, "https", size).await.expect("sequential https round trip");
            return;
        }
        self.request(proxy, "http", HTTP_DATA.len()).await.expect("sequential http round trip");
        self.request(proxy, "https", HTTP_DATA.len()).await.expect("sequential https round trip");
    }

    /// The `SKIP_CONCURRENT_TEST` env var is honored the same way here.
    #[expect(clippy::expect_used, reason = "a failed mock-origin round trip must abort the test")]
    pub async fn do_concurrent_test(&self, proxy: &dyn CProxyAdapter) {
        if std::env::var("SKIP_CONCURRENT_TEST").ok().as_deref() == Some("true") {
            return;
        }
        let num = HTTP_DATA.len() / 1024;
        let mut tasks = Vec::with_capacity(num * 2);
        for i in 1..=num {
            tasks.push(("https", i * 1024));
        }
        for i in 1..=num {
            tasks.push(("http", i * 1024));
        }
        let results =
            futures::future::join_all(tasks.into_iter().map(|(proto, size)| self.request(proxy, proto, size))).await;
        for result in results {
            result.expect("concurrent round trip");
        }
    }

    pub async fn do_test(&self, proxy: &dyn CProxyAdapter) {
        self.do_sequential_test(proxy).await;
        self.do_concurrent_test(proxy).await;
    }
}

#[async_trait]
impl Tunnel for HttpTestTunnel {
    async fn handle_tcp_conn(&self, conn: Box<dyn Stream>, metadata: Metadata) {
        if metadata.dst_ip != Some(*REMOTE_ADDR) && metadata.host != REALITY_DEST {
            return;
        }
        if metadata.dst_port == 443 {
            let tls_conn = utls::server(conn, TLS_CONFIG.clone());
            if tls_conn.handshake_context(&self.ctx).await.is_err() {
                return;
            }
            let io = TokioIo::new(tls_conn);
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service_fn(http_echo_handler))
                .await;
        } else {
            let io = TokioIo::new(conn);
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service_fn(http_echo_handler))
                .await;
        }
    }

    fn handle_udp_packet(&self, _packet: Arc<dyn murmur_constant::adapters::UDPPacket>, _metadata: Metadata) {}

    fn nat_table(&self) -> Arc<dyn NatTable> {
        Arc::new(Table::default())
    }
}

/// the `TestTunnel`, specialised to real-dial the shadow-tls camouflage backend (so its own TLS
/// handshake relay works) while echoing every byte for any other destination verbatim.
///
/// Enough to prove a ShadowTLS v3 + inbound-protocol framing chain works end to end without
/// needing a real destination to dial for the wrapped protocol's own payload.
#[derive(Debug)]
pub struct EchoTunnel {
    pub camouflage_addr: String,
}

#[async_trait]
impl Tunnel for EchoTunnel {
    async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, metadata: Metadata) {
        if metadata.remote_address() == self.camouflage_addr {
            let Ok(mut backend) = tokio::net::TcpStream::connect(&self.camouflage_addr).await else { return };
            let _ = tokio::io::copy_bidirectional(&mut conn, &mut backend).await;
            return;
        }
        let mut buf = [0u8; 4096];
        loop {
            match tokio::io::AsyncReadExt::read(&mut conn, &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let Some(chunk) = buf.get(..n) else { break };
                    if tokio::io::AsyncWriteExt::write_all(&mut conn, chunk).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    fn handle_udp_packet(&self, _packet: Arc<dyn murmur_constant::adapters::UDPPacket>, _metadata: Metadata) {}

    fn nat_table(&self) -> Arc<dyn NatTable> {
        Arc::new(Table::default())
    }
}

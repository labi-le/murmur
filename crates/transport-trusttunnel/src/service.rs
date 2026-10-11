use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::StreamBody;
use hyper::body::{Frame, Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use murmur_common_httputils::addr::{set_addr_from_request, RemoteAddr};
use murmur_common_net::io::{OldConnAsStream, Stream};
use murmur_common_net::new_deadline_conn;
use murmur_common_net::sing::{ExtendedConn as SingExtendedConn, UpstreamNode};
use murmur_compat::sing_buf::Buffer;
use murmur_component_tls::utls as tls_c;
use murmur_sing::metadata::{parse_socksaddr, Socksaddr};
use murmur_sing::network::PacketConn as SingPacketConn;
use murmur_std_compat::net::{Addr, Conn as NetConn, Listener, PacketConn as StdPacketConn};

use super::icmp::IcmpConn;
use super::packet::ServerPacketConn;
use super::protocol::{
    parse_basic_auth, BodyWriter, DeferredBodyWriter, HttpConn, HEALTH_CHECK_MAGIC_ADDRESS, ICMP_MAGIC_ADDRESS,
    UDP_MAGIC_ADDRESS,
};
use super::quic;

/// The connection metadata vocabulary, re-exported from the crate that owns it.
pub use murmur_sing::metadata::Metadata as SingMetadata;

/// The per-connection and per-packet-session callbacks, not mirrored elsewhere in the crate.
///
/// NEEDED SHIM ITEM: a shared handler trait pair from `murmur_sing::network`.
#[async_trait]
pub trait Handler: Send + Sync {
    async fn new_connection(
        &self,
        ctx: &CancellationToken,
        conn: Box<dyn SingExtendedConn>,
        metadata: SingMetadata,
    ) -> Result<()>;

    async fn new_packet_connection(
        &self,
        ctx: &CancellationToken,
        conn: Arc<dyn SingPacketConn>,
        metadata: SingMetadata,
    ) -> Result<()>;
}

#[async_trait]
pub trait IcmpHandler: Send + Sync {
    async fn new_icmp_connection(&self, ctx: &CancellationToken, conn: Arc<IcmpConn>);
}

pub struct ServiceOptions {
    pub ctx: CancellationToken,
    pub handler: Arc<dyn Handler>,
    pub icmp_handler: Option<Arc<dyn IcmpHandler>>,
    pub quic_congestion_control: String,
    pub quic_cwnd: i32,
    pub quic_bbr_profile: String,
}

impl std::fmt::Debug for ServiceOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceOptions").finish_non_exhaustive()
    }
}

pub struct Service {
    pub(crate) ctx: CancellationToken,
    handler: Arc<dyn Handler>,
    icmp_handler: Option<Arc<dyn IcmpHandler>>,
    pub(crate) quic_congestion_control: String,
    pub(crate) quic_cwnd: i32,
    #[allow(
        dead_code,
        reason = "mirrors the service's BBR profile setting; quic.rs drives quinn directly instead of the vendored congestion controllers that accept a profile, not yet wired (see quic.rs's NEEDED SHIM ITEM note)"
    )]
    pub(crate) quic_bbr_profile: String,
    users: parking_lot::RwLock<std::collections::HashMap<String, String>>,
    closed: AtomicBool,
    pub(crate) h3_server: parking_lot::Mutex<Option<Arc<quic::Http3Server>>>,
    /// Closing the service shuts the h1/h2 listener down; this crate's accept loop owns the
    /// listener, so it is stopped through this token instead of a stored handle.
    shutdown: CancellationToken,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .field("users", &self.users.read().len())
            .finish_non_exhaustive()
    }
}

impl Service {
    #[must_use]
    pub fn new(options: ServiceOptions) -> Arc<Self> {
        Arc::new(Self {
            ctx: options.ctx,
            handler: options.handler,
            icmp_handler: options.icmp_handler,
            quic_congestion_control: options.quic_congestion_control,
            quic_cwnd: options.quic_cwnd,
            quic_bbr_profile: options.quic_bbr_profile,
            users: parking_lot::RwLock::new(std::collections::HashMap::new()),
            closed: AtomicBool::new(false),
            h3_server: parking_lot::Mutex::new(None),
            shutdown: CancellationToken::new(),
        })
    }

    #[expect(clippy::unused_async, reason = "the listener awaits this along with every other service lifecycle call")]
    pub async fn start(
        self: &Arc<Self>,
        tcp_listener: Option<Box<dyn Listener>>,
        udp_conn: Option<Box<dyn StdPacketConn>>,
        tls_config: Option<Arc<tls_c::Config>>,
    ) -> Result<()> {
        if let Some(tcp_listener) = tcp_listener {
            let this = Arc::clone(self);
            let tls_config = tls_config.clone();
            let shutdown = self.shutdown.clone();
            tokio::spawn(async move {
                loop {
                    let conn = tokio::select! {
                        biased;
                        () = shutdown.cancelled() => break,
                        conn = tcp_listener.accept() => match conn {
                            Ok(conn) => conn,
                            Err(_) => break,
                        },
                    };
                    let remote_addr = conn.remote_addr().ok().map(|addr| addr.string());
                    let conn: Box<dyn Stream> = Box::new(OldConnAsStream(conn));
                    let conn: Box<dyn Stream> = match &tls_config {
                        Some(tls_config) => Box::new(tls_c::server(conn, Arc::clone(tls_config))),
                        None => conn,
                    };
                    let this = Arc::clone(&this);
                    tokio::spawn(async move {
                        this.serve_conn(conn, remote_addr).await;
                    });
                }
            });
        }

        if let Some(udp_conn) = udp_conn {
            quic::config_http3_server(self, tls_config, udp_conn)?;
        }
        Ok(())
    }

    async fn serve_conn(self: &Arc<Self>, conn: Box<dyn Stream>, remote_addr: Option<String>) {
        let io = TokioIo::new(conn);
        let this = Arc::clone(self);
        let service = hyper::service::service_fn(move |mut request: hyper::Request<Incoming>| {
            let this = Arc::clone(&this);
            let remote_addr = remote_addr.clone();
            async move {
                if let Some(remote_addr) = remote_addr {
                    request.extensions_mut().insert(RemoteAddr(remote_addr));
                }
                Ok::<_, io::Error>(this.serve_http(request).await)
            }
        });
        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection(io, service).await;
    }

    pub fn update_users(&self, users: std::collections::HashMap<String, String>) {
        *self.users.write() = users;
    }

    #[expect(clippy::unused_async, reason = "callers await every service lifecycle method, so close stays async")]
    pub async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        self.shutdown.cancel();
        let h3_server = self.h3_server.lock().take();
        if let Some(h3_server) = h3_server {
            h3_server.close();
        }
        Ok(())
    }

    #[expect(
        clippy::unused_async,
        reason = "kept `async` because the hyper service hook awaits it as its request future"
    )]
    pub(crate) async fn serve_http(
        self: &Arc<Self>,
        request: hyper::Request<Incoming>,
    ) -> hyper::Response<StreamedBody> {
        let remote_addr = request.extensions().get::<RemoteAddr>().cloned().unwrap_or_default();
        let authorization =
            request.headers().get("Proxy-Authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
        let Some(username) = self.verify(&authorization) else {
            self.bad_request(&remote_addr.0, "authorization failed");
            return status_response(hyper::StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        };
        if request.method() != hyper::Method::CONNECT {
            self.bad_request(&remote_addr.0, &format!("unexpected HTTP method {}", request.method()));
            return status_response(hyper::StatusCode::METHOD_NOT_ALLOWED);
        }
        let ctx = self.ctx.clone();
        let host = request.uri().authority().map_or_else(
            || request.headers().get(hyper::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned(),
            ToString::to_string,
        );
        log::debug!("[{username}] request from {}", remote_addr.0);
        log::debug!("[{username}] request to {host}");

        match host.as_str() {
            UDP_MAGIC_ADDRESS => self.serve_udp(request, &remote_addr.0),
            ICMP_MAGIC_ADDRESS => self.serve_icmp(request, &remote_addr.0, &ctx),
            HEALTH_CHECK_MAGIC_ADDRESS => status_response(hyper::StatusCode::OK),
            _ => self.serve_tcp(request, &remote_addr.0, &host),
        }
    }

    /// The host-switch dispatch, shared between the h1/h2 and h3 (`quic.rs`'s `serve_h3`) server
    /// loops once each has built the matching [`HttpConn`] for its transport.
    pub(crate) async fn dispatch(self: &Arc<Self>, http_conn: Arc<HttpConn>, remote_addr: &str, host: &str) {
        match host {
            UDP_MAGIC_ADDRESS => self.dispatch_udp(http_conn, remote_addr).await,
            ICMP_MAGIC_ADDRESS => self.dispatch_icmp(http_conn),
            _ => self.dispatch_tcp(&http_conn, remote_addr, host),
        }
    }

    fn serve_udp(
        self: &Arc<Self>,
        request: hyper::Request<Incoming>,
        remote_addr: &str,
    ) -> hyper::Response<StreamedBody> {
        let http_conn = upgrade_http_conn(request);
        let this = Arc::clone(self);
        let remote_addr = remote_addr.to_owned();
        tokio::spawn(async move {
            this.dispatch_udp(http_conn, &remote_addr).await;
        });
        status_response(hyper::StatusCode::OK)
    }

    async fn dispatch_udp(self: &Arc<Self>, http_conn: Arc<HttpConn>, remote_addr: &str) {
        let conn = ServerPacketConn::new(Arc::clone(&http_conn));
        let mut first_packet = murmur_compat::sing_buf::new_packet();
        let destination = match conn.read_packet(&mut first_packet).await {
            Ok(destination) => destination,
            Err(err) => {
                first_packet.release();
                let _ = http_conn.close();
                self.bad_request(remote_addr, &format!("read first packet of {remote_addr}: {err}"));
                return;
            }
        };
        let destination = destination.unwrap();
        let cached_conn = CachedPacketConn {
            inner: conn,
            cached: parking_lot::Mutex::new(Some((first_packet, destination.clone()))),
        };
        let handler = Arc::clone(&self.handler);
        let ctx = self.ctx.clone();
        let source = parse_socksaddr(remote_addr);
        tokio::spawn(async move {
            let _ = handler
                .new_packet_connection(
                    &ctx,
                    Arc::new(cached_conn),
                    SingMetadata { protocol: "trusttunnel".to_owned(), source, destination },
                )
                .await;
        });
    }

    fn serve_icmp(
        self: &Arc<Self>,
        request: hyper::Request<Incoming>,
        remote_addr: &str,
        _ctx: &CancellationToken,
    ) -> hyper::Response<StreamedBody> {
        if self.icmp_handler.is_none() {
            return status_response(hyper::StatusCode::NOT_IMPLEMENTED);
        }
        let http_conn = upgrade_http_conn(request);
        let _ = remote_addr;
        self.dispatch_icmp(http_conn);
        status_response(hyper::StatusCode::OK)
    }

    fn dispatch_icmp(self: &Arc<Self>, http_conn: Arc<HttpConn>) {
        let Some(icmp_handler) = self.icmp_handler.clone() else {
            let _ = http_conn.close();
            return;
        };
        let conn = Arc::new(IcmpConn::new(http_conn));
        let ctx = self.ctx.clone();
        tokio::spawn(async move {
            icmp_handler.new_icmp_connection(&ctx, conn).await;
        });
    }

    /// `hyper`'s h1/h2 server special-cases a successful response to a CONNECT request: the real
    /// duplex tunnel is only reachable through `hyper::upgrade::on`, and both the request's
    /// `Incoming` body and any hand-built response body are silently discarded rather than
    /// carrying tunnel bytes (`hyper::proto::h2::server::H2Stream::poll2`). This mirrors the write
    /// side of [`super::client::H2RoundTripper::open`], which hits the same hijack on the client.
    fn serve_tcp(
        self: &Arc<Self>,
        request: hyper::Request<Incoming>,
        remote_addr: &str,
        host: &str,
    ) -> hyper::Response<StreamedBody> {
        let http_conn = upgrade_http_conn(request);
        self.dispatch_tcp(&http_conn, remote_addr, host);
        status_response(hyper::StatusCode::OK)
    }

    fn dispatch_tcp(self: &Arc<Self>, http_conn: &Arc<HttpConn>, remote_addr: &str, host: &str) {
        let tcp_conn = super::protocol::TcpConn::new(Arc::clone(http_conn));
        let closed = Arc::new(AtomicBool::new(false));
        let wrapper: Box<dyn SingExtendedConn> = Box::new(H2ConnWrapper::new(
            // S11: remove in U5, once TcpConn implements Stream.
            new_deadline_conn(OldConnAsStream(tcp_conn)),
            Arc::clone(&closed),
        ));
        let handler = Arc::clone(&self.handler);
        let ctx = self.ctx.clone();
        let source = parse_socksaddr(remote_addr);
        let destination = parse_socksaddr(host).unwrap();
        tokio::spawn(async move {
            let _ = handler
                .new_connection(&ctx, wrapper, SingMetadata { protocol: "trusttunnel".to_owned(), source, destination })
                .await;
            closed.store(true, Ordering::SeqCst);
        });
    }

    pub(crate) fn verify(&self, authorization: &str) -> Option<String> {
        let (username, password) = parse_basic_auth(authorization)?;
        let recorded = self.users.read().get(&username).cloned()?;
        if password != recorded {
            return None;
        }
        Some(username)
    }

    #[expect(
        clippy::unused_self,
        reason = "kept as a method so `serve_http` and the h3 path reach it through the service alongside `verify`"
    )]
    pub(crate) fn bad_request(&self, remote_addr: &str, reason: &str) {
        log::error!("process connection from {remote_addr}: {reason}");
    }
}

/// The caching packet connection, not mirrored elsewhere in the crate: replays the first packet
/// read out of [`ServerPacketConn`] before every following read.
///
/// NEEDED SHIM ITEM: a cached-packet-conn constructor in `murmur_sing::bufio`.
struct CachedPacketConn {
    inner: ServerPacketConn,
    cached: parking_lot::Mutex<Option<(Buffer, Socksaddr)>>,
}

#[async_trait]
impl murmur_sing::network::PacketReader for CachedPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        let cached = self.cached.lock().take();
        if let Some((cached, destination)) = cached {
            let mut cached = cached;
            let _ = buffer.write_bytes(cached.bytes());
            cached.release();
            return Ok(destination);
        }
        self.inner.read_packet(buffer).await
    }
}

#[async_trait]
impl murmur_sing::network::PacketWriter for CachedPacketConn {
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        ServerPacketConn::write_packet(&self.inner, buffer.to_owned_buffer(), destination.clone()).await
    }
}

#[async_trait]
impl SingPacketConn for CachedPacketConn {
    async fn close(&self) -> io::Result<()> {
        murmur_std_compat::net::PacketConn::close(&self.inner)
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        murmur_std_compat::net::PacketConn::local_addr(&self.inner)
    }
}

fn status_response(status: hyper::StatusCode) -> hyper::Response<StreamedBody> {
    let (_tx, rx) = mpsc::channel::<std::result::Result<Frame<Bytes>, io::Error>>(1);
    let stream: std::pin::Pin<Box<dyn futures::Stream<Item = std::result::Result<Frame<Bytes>, io::Error>> + Send>> =
        Box::pin(futures::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|item| (item, rx)) }));
    let mut response = hyper::Response::new(StreamBody::new(stream));
    *response.status_mut() = status;
    response
}

pub(crate) type StreamedBody =
    StreamBody<std::pin::Pin<Box<dyn futures::Stream<Item = std::result::Result<Frame<Bytes>, io::Error>> + Send>>>;

/// Shared by `serve_tcp`, `serve_udp` and the 200 branch of `serve_icmp`.
fn upgrade_http_conn(mut request: hyper::Request<Incoming>) -> Arc<HttpConn> {
    let on_upgrade = hyper::upgrade::on(&mut request);
    let writer = DeferredBodyWriter::new();
    let tunnel_writer: Arc<dyn BodyWriter> = Arc::<DeferredBodyWriter>::clone(&writer);
    let http_conn = HttpConn::new(tunnel_writer);
    set_addr_from_request(&http_conn.net_addr, &request);
    let http_conn_for_upgrade = Arc::clone(&http_conn);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let (read_half, write_half) = tokio::io::split(TokioIo::new(upgraded));
                http_conn_for_upgrade.setup(Some(Box::pin(read_half)), None);
                writer.resolve(Box::new(write_half)).await;
            }
            Err(err) => {
                writer.fail();
                http_conn_for_upgrade.setup(None, Some(anyhow::Error::from(err)));
            }
        }
    });
    http_conn
}

/// Used to avoid a write after the handler finished reaching the wrapped conn.
pub(crate) struct H2ConnWrapper {
    inner: Box<dyn SingExtendedConn>,
    closed: Arc<AtomicBool>,
}

impl H2ConnWrapper {
    fn new(inner: Box<dyn SingExtendedConn>, closed: Arc<AtomicBool>) -> Self {
        Self { inner, closed }
    }
}

impl tokio::io::AsyncRead for H2ConnWrapper {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut *this.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for H2ConnWrapper {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::SeqCst) {
            return std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "use of closed network connection",
            )));
        }
        std::pin::Pin::new(&mut *this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

impl Stream for H2ConnWrapper {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.inner.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.inner.shutdown_write()
    }
    fn old_conn(&self) -> Option<&dyn NetConn> {
        self.inner.old_conn()
    }
}

impl murmur_common_net::io::ExtendedStream for H2ConnWrapper {
    fn reader_replaceable(&self) -> bool {
        murmur_common_net::io::ExtendedStream::reader_replaceable(&self.inner)
    }
    fn writer_replaceable(&self) -> bool {
        murmur_common_net::io::ExtendedStream::writer_replaceable(&self.inner)
    }
}

impl UpstreamNode for H2ConnWrapper {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&*self.inner)
    }

    fn net_conn_node(&self) -> Option<&dyn UpstreamNode> {
        self.inner.net_conn_node()
    }

    fn upstream_reader_node(&self) -> Option<&dyn UpstreamNode> {
        self.inner.upstream_reader_node()
    }

    fn upstream_writer_node(&self) -> Option<&dyn UpstreamNode> {
        self.inner.upstream_writer_node()
    }

    fn reader_replaceable(&self) -> Option<bool> {
        UpstreamNode::reader_replaceable(&*self.inner)
    }

    fn writer_replaceable(&self) -> Option<bool> {
        UpstreamNode::writer_replaceable(&*self.inner)
    }

    fn reader_possibly_replaceable(&self) -> bool {
        self.inner.reader_possibly_replaceable()
    }

    fn writer_possibly_replaceable(&self) -> bool {
        self.inner.writer_possibly_replaceable()
    }

    fn front_headroom(&self) -> Option<i32> {
        self.inner.front_headroom()
    }

    fn rear_headroom(&self) -> Option<i32> {
        self.inner.rear_headroom()
    }

    fn lazy_headroom(&self) -> bool {
        self.inner.lazy_headroom()
    }

    fn reader_mtu(&self) -> Option<i32> {
        self.inner.reader_mtu()
    }

    fn writer_mtu(&self) -> Option<i32> {
        self.inner.writer_mtu()
    }
}

#[async_trait]
impl SingExtendedConn for H2ConnWrapper {
    /// Promoted unchanged from the embedded conn.
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        self.inner.read_buffer(buffer).await
    }

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection"));
        }
        self.inner.write_buffer(buffer).await
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use anyhow::Result;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    use murmur_component_ca::keypair::new_tls_key_pair_loader;
    use murmur_component_tls::utls as tls_c;
    use murmur_std_compat::net::Listener as NetListener;
    use murmur_testsupport::{tls_certificate, tls_private_key, TestDialer};
    use murmur_testsupport_probe::ensure_test_crypto_provider;
    use murmur_transport_vmess::tls::TlsConfig;

    use super::super::client::{Client, ClientOptions};
    use super::super::icmp::IcmpConn;
    use super::{Handler, IcmpHandler, Service, ServiceOptions, SingExtendedConn, SingMetadata, SingPacketConn};

    struct NoopHandler;

    #[async_trait::async_trait]
    impl Handler for NoopHandler {
        async fn new_connection(
            &self,
            _ctx: &CancellationToken,
            _conn: Box<dyn SingExtendedConn>,
            _metadata: SingMetadata,
        ) -> Result<()> {
            Ok(())
        }

        async fn new_packet_connection(
            &self,
            _ctx: &CancellationToken,
            _conn: std::sync::Arc<dyn SingPacketConn>,
            _metadata: SingMetadata,
        ) -> Result<()> {
            Ok(())
        }
    }

    /// Echoes every ping request straight back as a ping response: the server side of a fake
    /// `IcmpHandler`, driven with `Client::listen_icmp`/`write_ping`/`read_ping` over a plain TCP
    /// loopback connection. Exercises the 200 ICMP wire framing (`dispatch_icmp`, `IcmpConn`'s
    /// `read_ping_request`/`write_ping_response`) without a raw socket or root privileges, unlike
    /// the listener-level inbound tests, which always run with `icmp_handler: None`.
    struct EchoIcmpHandler;

    #[async_trait::async_trait]
    impl IcmpHandler for EchoIcmpHandler {
        async fn new_icmp_connection(&self, _ctx: &CancellationToken, conn: std::sync::Arc<IcmpConn>) {
            loop {
                let Ok((id, destination, sequence_number, _ttl, _size)) = conn.read_ping_request().await else {
                    return;
                };
                if conn.write_ping_response(id, destination, 0, 0, sequence_number).await.is_err() {
                    return;
                }
            }
        }
    }

    /// Hands the tunnel's far side to the test through a duplex, so the test drives a real
    /// full-duplex relay with backpressure in both directions.
    struct EchoHandler {
        peer: tokio::sync::mpsc::UnboundedSender<tokio::io::DuplexStream>,
    }

    #[async_trait::async_trait]
    impl Handler for EchoHandler {
        async fn new_connection(
            &self,
            _ctx: &CancellationToken,
            mut conn: Box<dyn SingExtendedConn>,
            _metadata: SingMetadata,
        ) -> Result<()> {
            let (mut tunnel_side, peer_side) = tokio::io::duplex(8 * 1024);
            self.peer.send(peer_side).expect("test holds the receiver");
            let _ = tokio::io::copy_bidirectional(&mut conn, &mut tunnel_side).await;
            Ok(())
        }

        async fn new_packet_connection(
            &self,
            _ctx: &CancellationToken,
            _conn: std::sync::Arc<dyn SingPacketConn>,
            _metadata: SingMetadata,
        ) -> Result<()> {
            Ok(())
        }
    }

    /// A CONNECT tunnel moving a payload larger than an HTTP/2 stream's default 65535-byte
    /// flow-control window deadlocked as soon as either side staged the bytes in a fixed 64 KiB
    /// buffer: the full buffer stopped the relay from reading the peer, and the peer was blocked
    /// writing into its own full buffer, so the window update that would free both never came.
    #[tokio::test(flavor = "multi_thread")]
    async fn connect_tunnel_transfers_more_than_one_flow_control_window() {
        ensure_test_crypto_provider();

        let mut tls_config =
            tls_c::Config { time: Some(std::sync::Arc::new(murmur_ntp::time::now)), ..Default::default() };
        let cert_loader = new_tls_key_pair_loader(tls_certificate(), tls_private_key()).expect("cert loader");
        tls_config.certificates = vec![cert_loader().expect("certificate")];
        tls_config.get_certificate =
            Some(std::sync::Arc::new(move |_info: &tls_c::ClientHelloInfo| cert_loader().map(Some)));
        let tls_config = std::sync::Arc::new(tls_config);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let listener: Box<dyn NetListener> = Box::new(listener);

        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        let service = Service::new(ServiceOptions {
            ctx: CancellationToken::new(),
            handler: std::sync::Arc::new(EchoHandler { peer: peer_tx }),
            icmp_handler: None,
            quic_congestion_control: String::new(),
            quic_cwnd: 0,
            quic_bbr_profile: String::new(),
        });
        service.update_users(std::iter::once(("test".to_owned(), "password".to_owned())).collect());
        service.start(Some(listener), None, Some(std::sync::Arc::clone(&tls_config))).await.expect("service start");

        let client_tls_config =
            TlsConfig { host: "127.0.0.1".to_owned(), skip_cert_verify: true, ..Default::default() };
        let client = Client::new(
            CancellationToken::new(),
            ClientOptions {
                dialer: std::sync::Arc::new(TestDialer::new(CancellationToken::new())),
                dial_options: None,
                server: addr.to_string(),
                username: "test".to_owned(),
                password: "password".to_owned(),
                tls_config: std::sync::Arc::new(client_tls_config),
                quic: false,
                quic_congestion_control: String::new(),
                quic_cwnd: 0,
                quic_bbr_profile: String::new(),
                health_check: false,
                max_connections: 0,
                min_streams: 0,
                max_streams: 0,
            },
        )
        .await
        .expect("client construction");

        let conn = client.dial("example.com:443").await.expect("dial through the tunnel");
        let mut peer = peer_rx.recv().await.expect("handler received the tunnel");
        let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        let (mut tunnel_reader, mut tunnel_writer) = tokio::io::split(conn);

        let upload = {
            let payload = payload.clone();
            tokio::spawn(async move {
                tunnel_writer.write_all(&payload).await.expect("upload");
                tunnel_writer.shutdown().await.expect("half close");
            })
        };
        let mut echoed_to_peer = vec![0u8; 64 * 1024];
        tokio::time::timeout(Duration::from_secs(10), peer.read_exact(&mut echoed_to_peer))
            .await
            .expect("upload must reach the relay peer")
            .expect("peer read");
        assert_eq!(echoed_to_peer, payload);
        peer.write_all(&echoed_to_peer).await.expect("peer echo");

        let mut received = vec![0u8; 64 * 1024];
        tokio::time::timeout(Duration::from_secs(10), tunnel_reader.read_exact(&mut received))
            .await
            .expect("download must not wedge on a full staging buffer")
            .expect("download");
        upload.await.expect("upload task joins");
        assert_eq!(received, payload);

        let mut trailing = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), peer.read_to_end(&mut trailing))
            .await
            .expect("the tunnel's half close must reach the relay")
            .expect("relay drain");
        assert!(trailing.is_empty());
        let _ = client.close();
        let _ = service.close().await;
    }

    /// Saturating both directions at once is a shape
    /// `connect_tunnel_transfers_more_than_one_flow_control_window` cannot reach: an HTTP/2 stream
    /// frees the opposite direction's window only by reading, so moving one direction and waiting
    /// for it never has both sides blocked at the same time. It is also the shape that broke when
    /// the client fed the tunnel through the CONNECT request body, which `hyper` never polls.
    #[tokio::test(flavor = "multi_thread")]
    async fn connect_tunnel_carries_both_directions_at_once() {
        ensure_test_crypto_provider();

        let mut tls_config =
            tls_c::Config { time: Some(std::sync::Arc::new(murmur_ntp::time::now)), ..Default::default() };
        let cert_loader = new_tls_key_pair_loader(tls_certificate(), tls_private_key()).expect("cert loader");
        tls_config.certificates = vec![cert_loader().expect("certificate")];
        tls_config.get_certificate =
            Some(std::sync::Arc::new(move |_info: &tls_c::ClientHelloInfo| cert_loader().map(Some)));
        let tls_config = std::sync::Arc::new(tls_config);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let listener: Box<dyn NetListener> = Box::new(listener);

        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        let service = Service::new(ServiceOptions {
            ctx: CancellationToken::new(),
            handler: std::sync::Arc::new(EchoHandler { peer: peer_tx }),
            icmp_handler: None,
            quic_congestion_control: String::new(),
            quic_cwnd: 0,
            quic_bbr_profile: String::new(),
        });
        service.update_users(std::iter::once(("test".to_owned(), "password".to_owned())).collect());
        service.start(Some(listener), None, Some(std::sync::Arc::clone(&tls_config))).await.expect("service start");

        let client_tls_config =
            TlsConfig { host: "127.0.0.1".to_owned(), skip_cert_verify: true, ..Default::default() };
        let client = Client::new(
            CancellationToken::new(),
            ClientOptions {
                dialer: std::sync::Arc::new(TestDialer::new(CancellationToken::new())),
                dial_options: None,
                server: addr.to_string(),
                username: "test".to_owned(),
                password: "password".to_owned(),
                tls_config: std::sync::Arc::new(client_tls_config),
                quic: false,
                quic_congestion_control: String::new(),
                quic_cwnd: 0,
                quic_bbr_profile: String::new(),
                health_check: false,
                max_connections: 0,
                min_streams: 0,
                max_streams: 0,
            },
        )
        .await
        .expect("client construction");

        const SIZE: usize = 128 * 1024;
        let upload: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
        let download: Vec<u8> = (0..SIZE).map(|i| (255 - i % 251) as u8).collect();

        let conn = client.dial("example.com:443").await.expect("dial through the tunnel");
        let peer = peer_rx.recv().await.expect("handler received the tunnel");
        let (mut peer_reader, mut peer_writer) = tokio::io::split(peer);
        let (mut tunnel_reader, mut tunnel_writer) = tokio::io::split(conn);

        let upload_task = {
            let upload = upload.clone();
            tokio::spawn(async move {
                tunnel_writer.write_all(&upload).await.expect("upload");
                tunnel_writer.shutdown().await.expect("tunnel half close");
            })
        };
        let download_task = {
            let download = download.clone();
            tokio::spawn(async move {
                peer_writer.write_all(&download).await.expect("download");
                peer_writer.shutdown().await.expect("peer half close");
            })
        };

        let mut received = vec![0u8; SIZE];
        tokio::time::timeout(Duration::from_secs(10), tunnel_reader.read_exact(&mut received))
            .await
            .expect("the download must not wait on the upload")
            .expect("download");
        assert_eq!(received, download);
        let mut trailing = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), tunnel_reader.read_to_end(&mut trailing))
            .await
            .expect("the peer's half close must reach the client")
            .expect("client drain");
        assert!(trailing.is_empty());

        let mut received = vec![0u8; SIZE];
        tokio::time::timeout(Duration::from_secs(10), peer_reader.read_exact(&mut received))
            .await
            .expect("the upload must not wait on the download")
            .expect("upload");
        assert_eq!(received, upload);
        let mut trailing = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), peer_reader.read_to_end(&mut trailing))
            .await
            .expect("the tunnel's half close must reach the peer")
            .expect("peer drain");
        assert!(trailing.is_empty());

        upload_task.await.expect("upload task joins");
        download_task.await.expect("download task joins");
        let _ = client.close();
        let _ = service.close().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn icmp_round_trip_through_fake_handler() {
        ensure_test_crypto_provider();

        let mut tls_config =
            tls_c::Config { time: Some(std::sync::Arc::new(murmur_ntp::time::now)), ..Default::default() };
        let cert_loader = new_tls_key_pair_loader(tls_certificate(), tls_private_key()).expect("cert loader");
        tls_config.certificates = vec![cert_loader().expect("certificate")];
        tls_config.get_certificate =
            Some(std::sync::Arc::new(move |_info: &tls_c::ClientHelloInfo| cert_loader().map(Some)));
        let tls_config = std::sync::Arc::new(tls_config);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let listener: Box<dyn NetListener> = Box::new(listener);

        let service = Service::new(ServiceOptions {
            ctx: CancellationToken::new(),
            handler: std::sync::Arc::new(NoopHandler),
            icmp_handler: Some(std::sync::Arc::new(EchoIcmpHandler)),
            quic_congestion_control: String::new(),
            quic_cwnd: 0,
            quic_bbr_profile: String::new(),
        });
        service.update_users(std::iter::once(("test".to_owned(), "password".to_owned())).collect());
        service.start(Some(listener), None, Some(std::sync::Arc::clone(&tls_config))).await.expect("service start");

        let client_tls_config =
            TlsConfig { host: "127.0.0.1".to_owned(), skip_cert_verify: true, ..Default::default() };
        let client = Client::new(
            CancellationToken::new(),
            ClientOptions {
                dialer: std::sync::Arc::new(TestDialer::new(CancellationToken::new())),
                dial_options: None,
                server: addr.to_string(),
                username: "test".to_owned(),
                password: "password".to_owned(),
                tls_config: std::sync::Arc::new(client_tls_config),
                quic: false,
                quic_congestion_control: String::new(),
                quic_cwnd: 0,
                quic_bbr_profile: String::new(),
                health_check: false,
                max_connections: 0,
                min_streams: 0,
                max_streams: 0,
            },
        )
        .await
        .expect("client construction");

        let icmp_conn = client.listen_icmp().await.expect("listen icmp");
        let destination: IpAddr = "203.0.113.7".parse().expect("valid ip");
        icmp_conn.write_ping(0x1234, destination, 7, 64, 32).await.expect("write ping");

        let (id, source, icmp_type, code, sequence_number) =
            tokio::time::timeout(Duration::from_secs(5), icmp_conn.read_ping())
                .await
                .expect("read ping timed out")
                .expect("read ping");

        assert_eq!(id, 0x1234);
        assert_eq!(source, destination);
        assert_eq!(icmp_type, 0);
        assert_eq!(code, 0);
        assert_eq!(sequence_number, 7);

        let _ = icmp_conn.close().await;
        let _ = client.close();
        let _ = service.close().await;
    }
}

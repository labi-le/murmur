use portable_atomic::AtomicI64;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::StreamExt as _;
use http_body_util::StreamBody;
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex as SyncMutex;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use murmur_common_httputils::force_close::RoundTripper;
use murmur_component::dialer::options::Option as DialerOption;
use murmur_constant::adapters::Dialer as CDialer;
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport_vmess as vmess;

use super::icmp::IcmpConn;
use super::packet::ClientPacketConn;
use super::protocol::{
    build_auth, BodyReader, BodyWriter, DeferredBodyWriter, HttpConn, DEFAULT_HEALTH_CHECK_TIMEOUT,
    HEALTH_CHECK_MAGIC_ADDRESS, HEALTH_CHECK_USER_AGENT, ICMP_MAGIC_ADDRESS, ICMP_USER_AGENT, TCP_USER_AGENT,
    UDP_MAGIC_ADDRESS, UDP_USER_AGENT,
};
use super::quic;

pub type DialOptionsFunc = Arc<dyn Fn() -> Vec<DialerOption> + Send + Sync>;

#[derive(Clone)]
pub struct ClientOptions {
    pub dialer: Arc<dyn CDialer>,
    pub dial_options: Option<DialOptionsFunc>,
    pub server: String,
    pub username: String,
    pub password: String,
    pub tls_config: Arc<vmess::tls::TlsConfig>,
    pub quic: bool,
    pub quic_congestion_control: String,
    pub quic_cwnd: i32,
    pub quic_bbr_profile: String,
    pub health_check: bool,
    pub max_connections: i32,
    pub min_streams: i32,
    pub max_streams: i32,
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions").field("server", &self.server).field("quic", &self.quic).finish_non_exhaustive()
    }
}

type ReqBody = StreamBody<futures::stream::BoxStream<'static, Result<Frame<Bytes>, io::Error>>>;

/// The shared abstraction over the h2 and h3 backends: one live connection, opening a
/// duplex-streamed request/response exchange per call.
#[async_trait::async_trait]
pub(crate) trait TunnelRoundTripper: RoundTripper {
    /// Opens one request/response exchange and returns the request-body writer plus a future
    /// resolving to the validated response body (or the request's outcome error).
    async fn open(
        &self,
        host: &str,
        user_agent: &str,
        auth: &str,
    ) -> Result<(Arc<dyn BodyWriter>, futures::future::BoxFuture<'static, Result<BodyReader>>)>;

    /// A one-shot request/response for the health check, which has no streamed body.
    async fn health_check_round_trip(&self, host: &str, user_agent: &str, auth: &str) -> Result<()>;
}

/// The h2 backend, dialing TLS through `c.dialer`. HTTP/2 multiplexes connections per destination
/// automatically; `hyper`'s `SendRequest<B>` handle is itself cheaply `Clone` and multiplexes
/// internally, so one lazily-established connection is reused here.
pub(crate) struct H2RoundTripper {
    dialer: Arc<dyn CDialer>,
    server: String,
    tls_config: Arc<vmess::tls::TlsConfig>,
    send_request: AsyncMutex<Option<hyper::client::conn::http2::SendRequest<ReqBody>>>,
}

impl H2RoundTripper {
    fn new(dialer: Arc<dyn CDialer>, server: String, tls_config: Arc<vmess::tls::TlsConfig>) -> Self {
        Self { dialer, server, tls_config, send_request: AsyncMutex::new(None) }
    }

    async fn connection(&self) -> Result<hyper::client::conn::http2::SendRequest<ReqBody>> {
        let mut guard = self.send_request.lock().await;
        if let Some(send_request) = guard.as_ref() {
            if send_request.is_ready() {
                return Ok(send_request.clone());
            }
        }
        let ctx = CancellationToken::new();
        let conn = self.dialer.dial_context(&ctx, "tcp", &self.server).await?;
        let tls_conn = vmess::tls::stream_tls_conn(&ctx, conn, &self.tls_config).await?;
        let io = TokioIo::new(tls_conn);
        let (send_request, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new()).handshake(io).await?;
        tokio::spawn(connection);
        *guard = Some(send_request.clone());
        drop(guard);
        Ok(send_request)
    }

    fn build_request(host: &str, user_agent: &str, auth: &str, body: ReqBody) -> Result<hyper::Request<ReqBody>> {
        let request = hyper::Request::builder()
            .method("CONNECT")
            .uri(host)
            .header("Host", host)
            .header("User-Agent", user_agent)
            .header("Proxy-Authorization", auth)
            .version(hyper::Version::HTTP_2)
            .body(body)?;
        Ok(request)
    }
}

impl RoundTripper for H2RoundTripper {
    fn close_idle_connections(&self) {}

    fn close_http2_connections(&self) {
        if let Ok(mut guard) = self.send_request.try_lock() {
            *guard = None;
        }
    }

    fn close(&self) {}
}

#[async_trait::async_trait]
impl TunnelRoundTripper for H2RoundTripper {
    async fn open(
        &self,
        host: &str,
        user_agent: &str,
        auth: &str,
    ) -> Result<(Arc<dyn BodyWriter>, futures::future::BoxFuture<'static, Result<BodyReader>>)> {
        let mut send_request = self.connection().await?;
        let empty_body: ReqBody = StreamBody::new(futures::stream::empty().boxed());
        let request = Self::build_request(host, user_agent, auth, empty_body)?;
        let response_future = send_request.send_request(request);
        let writer = DeferredBodyWriter::new();
        let writer_for_task = Arc::clone(&writer);
        let pending = Box::pin(async move {
            let mut response = match response_future.await {
                Ok(response) => response,
                Err(err) => {
                    writer_for_task.fail();
                    return Err(err.into());
                }
            };
            if response.status() != hyper::StatusCode::OK {
                writer_for_task.fail();
                return Err(anyhow!("unexpected status code: {}", response.status().as_u16()));
            }
            let upgraded = match hyper::upgrade::on(&mut response).await {
                Ok(upgraded) => upgraded,
                Err(err) => {
                    writer_for_task.fail();
                    return Err(err.into());
                }
            };
            let (read_half, write_half) = tokio::io::split(TokioIo::new(upgraded));
            writer_for_task.resolve(Box::new(write_half)).await;
            let body: BodyReader = Box::pin(read_half);
            Ok(body)
        });
        Ok((writer, pending))
    }

    async fn health_check_round_trip(&self, host: &str, user_agent: &str, auth: &str) -> Result<()> {
        let mut send_request = self.connection().await?;
        let body_stream: futures::stream::BoxStream<'static, Result<Frame<Bytes>, io::Error>> =
            futures::stream::empty().boxed();
        let request = Self::build_request(host, user_agent, auth, StreamBody::new(body_stream))?;
        let response = send_request.send_request(request).await?;
        if response.status() != hyper::StatusCode::OK {
            return Err(anyhow!("unexpected status code: {}", response.status().as_u16()));
        }
        Ok(())
    }
}

#[allow(
    dead_code,
    reason = "dialer/dial_options/server are cloned into H2RoundTripper at construction instead of re-read from self; the QUIC path skips them entirely"
)]
pub struct Client {
    ctx: CancellationToken,
    pub(crate) dialer: Arc<dyn CDialer>,
    pub(crate) dial_options: Option<DialOptionsFunc>,
    pub(crate) server: String,
    auth: String,
    round_tripper: Arc<dyn TunnelRoundTripper>,
    start_once: std::sync::Once,
    health_check: bool,
    health_check_handle: SyncMutex<Option<tokio::task::JoinHandle<()>>>,
    count: AtomicI64,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("server", &self.server)
            .field("count", &self.count.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Client {
    #[expect(
        clippy::unused_async,
        reason = "kept `async` because `PoolClient::new` and every lifecycle caller await it"
    )]
    pub async fn new(ctx: CancellationToken, options: ClientOptions) -> Result<Arc<Self>> {
        let auth = build_auth(&options.username, &options.password);
        let mut tls_config = (*options.tls_config).clone();

        let round_tripper: Arc<dyn TunnelRoundTripper> = if options.quic {
            if tls_config.next_protos.is_empty() {
                tls_config.next_protos = vec!["h3".to_owned()];
            } else if !tls_config.next_protos.iter().any(|p| p == "h3") {
                return Err(anyhow!("require alpn h3"));
            }
            quic::quic_round_tripper(
                &tls_config,
                &options.quic_congestion_control,
                options.quic_cwnd,
                &options.quic_bbr_profile,
                &options.server,
            )?
        } else {
            if tls_config.next_protos.is_empty() {
                tls_config.next_protos = vec!["h2".to_owned()];
            } else if !tls_config.next_protos.iter().any(|p| p == "h2") {
                return Err(anyhow!("require alpn h2"));
            }
            Arc::new(H2RoundTripper::new(Arc::clone(&options.dialer), options.server.clone(), Arc::new(tls_config)))
        };

        Ok(Arc::new(Self {
            ctx,
            dialer: options.dialer,
            dial_options: options.dial_options,
            server: options.server,
            auth,
            round_tripper,
            start_once: std::sync::Once::new(),
            health_check: options.health_check,
            health_check_handle: SyncMutex::new(None),
            count: AtomicI64::new(0),
        }))
    }

    fn start(self: &Arc<Self>) {
        if !self.health_check {
            return;
        }
        let this = Arc::clone(self);
        let handle = tokio::spawn(async move { this.loop_health_check().await });
        *self.health_check_handle.lock() = Some(handle);
    }

    // cancel-safe: `close` aborts the loop, which owns nothing but its timer.
    async fn loop_health_check(self: Arc<Self>) {
        loop {
            tokio::select! {
                () = tokio::time::sleep(DEFAULT_HEALTH_CHECK_TIMEOUT) => {}
                () = self.ctx.cancelled() => return,
            }
            let _ = tokio::time::timeout(DEFAULT_HEALTH_CHECK_TIMEOUT, self.health_check_inner()).await;
        }
    }

    /// The connection-established moment is not directly observable here as it is with a
    /// connect hook fired once a TCP/QUIC connection is assigned; `TunnelRoundTripper::open`
    /// returning is used as the equivalent signal instead, since both backends allocate the
    /// stream synchronously before awaiting the response.
    async fn round_trip(self: &Arc<Self>, host: &str, user_agent: &str) -> Result<Arc<HttpConn>> {
        self.start_once.call_once(|| {
            let this = Arc::clone(self);
            this.start();
        });
        self.count.fetch_add(1, Ordering::SeqCst);
        let (writer, pending) = self.round_tripper.open(host, user_agent, &self.auth).await.inspect_err(|_| {
            self.count.fetch_sub(1, Ordering::SeqCst);
        })?;
        let conn = HttpConn::new(writer);
        let client_for_close = Arc::clone(self);
        conn.set_close_fn(move || {
            client_for_close.count.fetch_sub(1, Ordering::SeqCst);
        });
        let conn_for_setup = Arc::clone(&conn);
        let pending_handle = tokio::spawn(async move {
            match pending.await {
                Ok(body) => conn_for_setup.setup(Some(body), None),
                Err(err) => conn_for_setup.setup(None, Some(err)),
            }
        });
        conn.set_cancel_fn(move || pending_handle.abort());
        Ok(conn)
    }

    fn new_connect_request_parts(host: &str, user_agent: &str) -> (String, String) {
        (host.to_owned(), user_agent.to_owned())
    }

    pub async fn dial(self: &Arc<Self>, host: &str) -> Result<Box<dyn NetConn>> {
        let (host, ua) = Self::new_connect_request_parts(host, &TCP_USER_AGENT);
        let conn = self.round_trip(&host, &ua).await?;
        Ok(Box::new(super::protocol::TcpConn::new(conn)))
    }

    pub async fn listen_packet(self: &Arc<Self>) -> Result<ClientPacketConn> {
        let (host, ua) = Self::new_connect_request_parts(UDP_MAGIC_ADDRESS, &UDP_USER_AGENT);
        let conn = self.round_trip(&host, &ua).await?;
        Ok(ClientPacketConn::new(conn))
    }

    pub async fn listen_icmp(self: &Arc<Self>) -> Result<IcmpConn> {
        let (host, ua) = Self::new_connect_request_parts(ICMP_MAGIC_ADDRESS, &ICMP_USER_AGENT);
        let conn = self.round_trip(&host, &ua).await?;
        Ok(IcmpConn::new(conn))
    }

    pub fn close(&self) -> Result<()> {
        self.round_tripper.close_idle_connections();
        self.round_tripper.close_http2_connections();
        self.round_tripper.close();
        let handle = self.health_check_handle.lock().take();
        if let Some(handle) = handle {
            handle.abort();
        }
        Ok(())
    }

    pub fn reset_connections(&self) {
        self.round_tripper.close_idle_connections();
        self.round_tripper.close_http2_connections();
        self.round_tripper.close();
    }

    // cancel-safe: the probe holds no state of its own; a drop abandons only that round trip.
    async fn health_check_inner(&self) -> Result<()> {
        self.round_tripper
            .health_check_round_trip(HEALTH_CHECK_MAGIC_ADDRESS, &HEALTH_CHECK_USER_AGENT, &self.auth)
            .await
    }

    pub async fn health_check(&self) -> Result<()> {
        self.health_check_inner().await
    }
}

pub struct PoolClient {
    inner: AsyncMutex<PoolClientInner>,
    max_connections: i32,
    min_streams: i32,
    max_streams: i32,
    ctx: CancellationToken,
    options: ClientOptions,
}

impl std::fmt::Debug for PoolClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolClient")
            .field("max_connections", &self.max_connections)
            .field("min_streams", &self.min_streams)
            .field("max_streams", &self.max_streams)
            .finish_non_exhaustive()
    }
}

struct PoolClientInner {
    clients: Vec<Arc<Client>>,
}

impl PoolClient {
    pub async fn new(ctx: CancellationToken, options: ClientOptions) -> Result<Arc<Self>> {
        let mut max_connections = options.max_connections;
        let mut min_streams = options.min_streams;
        let max_streams = options.max_streams;
        if max_connections == 0 && min_streams == 0 && max_streams == 0 {
            max_connections = 8;
            min_streams = 5;
        }
        let client = Client::new(ctx.clone(), options.clone()).await?;
        Ok(Arc::new(Self {
            inner: AsyncMutex::new(PoolClientInner { clients: vec![client] }),
            max_connections,
            min_streams,
            max_streams,
            ctx,
            options,
        }))
    }

    pub async fn dial(&self, host: &str) -> Result<Box<dyn NetConn>> {
        let client = self.client().await?;
        client.dial(host).await
    }

    pub async fn listen_packet(&self) -> Result<ClientPacketConn> {
        let client = self.client().await?;
        client.listen_packet().await
    }

    pub async fn listen_icmp(&self) -> Result<IcmpConn> {
        let client = self.client().await?;
        client.listen_icmp().await
    }

    pub async fn close(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let mut errs = Vec::new();
        for client in guard.clients.drain(..) {
            if let Err(err) = client.close() {
                errs.push(err.to_string());
            }
        }
        drop(guard);
        if errs.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(errs.join("; ")))
        }
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the guard must stay held while `new_transport_locked` appends to the pool it protects"
    )]
    async fn client(&self) -> Result<Arc<Client>> {
        let mut guard = self.inner.lock().await;
        let mut transport: Option<Arc<Client>> = None;
        for candidate in &guard.clients {
            let better = match &transport {
                None => true,
                Some(current) => candidate.count.load(Ordering::SeqCst) < current.count.load(Ordering::SeqCst),
            };
            if better {
                transport = Some(Arc::clone(candidate));
            }
        }
        let Some(transport) = transport else {
            return self.new_transport_locked(&mut guard).await;
        };
        let num_streams = transport.count.load(Ordering::SeqCst);
        if num_streams == 0 {
            return Ok(transport);
        }
        if self.max_connections > 0 {
            let connections = i32::try_from(guard.clients.len()).unwrap_or(i32::MAX);
            if connections >= self.max_connections || num_streams < i64::from(self.min_streams) {
                return Ok(transport);
            }
        } else if self.max_streams > 0 && num_streams < i64::from(self.max_streams) {
            return Ok(transport);
        }
        self.new_transport_locked(&mut guard).await
    }

    async fn new_transport_locked(&self, guard: &mut PoolClientInner) -> Result<Arc<Client>> {
        let transport = Client::new(self.ctx.clone(), self.options.clone()).await?;
        guard.clients.push(Arc::clone(&transport));
        Ok(transport)
    }
}

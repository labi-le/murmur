//! This crate speaks the already-dialed carrier connection with `hyper`'s HTTP/1.1 and HTTP/2
//! client halves and the pinned `h3`/`h3-quinn`/`quinn` stack for HTTP/3.
//!
//! The dialer's QUIC configuration parameter has no pinned mirror either; [`QuicConfig`]
//! narrows it to the three fields the transport builder sets.

use portable_atomic::AtomicU64;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use futures::future::BoxFuture;
use futures::stream::{BoxStream, StreamExt};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio_util::io::{ReaderStream, StreamReader};
use tokio_util::sync::CancellationToken;
use url::Position;

use murmur_common_httputils::addr::{new_addr_context, GotConnInfo, NetAddr};
use murmur_common_httputils::force_close;
use murmur_common_net::io::StreamAsOldConn;
use murmur_std_compat::net::{Addr, Conn as NetConn, TcpAddr};

use super::config::{Config, Range, Request, RequestBody, Response, RoundTripper};
use super::conn::{Conn as XConn, ReadCloser, WriteCloser};
use super::reuse::ReuseManager;

/// The maximum time an idle TCP session can survive in the tunnel, so it
/// should be consistent across HTTP versions and with other transports.
pub const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// The HTTP/3 keep-alive period.
pub const QUICGO_H3_KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(10);

/// The HTTP/2 keep-alive period, matching Chrome.
pub const CHROME_H2_KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(45);

/// The capacity of the in-process pipe standing in for the unbuffered pipe between the
/// tunnel's public `Conn` and the streaming HTTP request body.
const UPLOAD_PIPE_CAPACITY: usize = 64 * 1024;

pub type DialRawFunc =
    Arc<dyn Fn(CancellationToken) -> BoxFuture<'static, anyhow::Result<Box<dyn NetConn>>> + Send + Sync>;

pub type WrapTlsFunc = Arc<
    dyn Fn(CancellationToken, Box<dyn NetConn>, bool) -> BoxFuture<'static, anyhow::Result<Box<dyn NetConn>>>
        + Send
        + Sync,
>;

/// The QUIC configuration, narrowed to the fields the transport builder sets. The full such
/// configuration has no Rust mirror.
#[derive(Clone, Copy, Debug)]
pub struct QuicConfig {
    pub max_incoming_streams: i64,
    pub keep_alive_period: Duration,
    pub max_idle_timeout: Duration,
}

pub type DialQuicFunc =
    Arc<dyn Fn(CancellationToken, QuicConfig) -> BoxFuture<'static, anyhow::Result<quinn::Connection>> + Send + Sync>;

pub type TransportMaker = Arc<dyn Fn() -> Arc<dyn RoundTripper> + Send + Sync>;

fn base_url(cfg: &Config) -> anyhow::Result<url::Url> {
    let mut url = url::Url::parse(&format!("https://{}", cfg.host))
        .map_err(|e| anyhow!("xhttp: invalid host {}: {e}", cfg.host))?;
    url.set_path(&cfg.normalized_path());
    Ok(url)
}

// cancel-safe: a dropped copy only abandons a response body that is being discarded anyway.
async fn drain_body(mut body: Pin<Box<dyn AsyncRead + Send>>) {
    let mut sink = tokio::io::sink();
    let _ = tokio::io::copy(&mut body, &mut sink).await;
}

struct PacketUpWriterState {
    seq: u64,
    buf: Vec<u8>,
    timer: Option<tokio::task::JoinHandle<()>>,
    flush_err: Option<Arc<anyhow::Error>>,
}

struct PacketUpWriterInner {
    ctx: CancellationToken,
    cfg: Arc<Config>,
    sc_max_each_post_bytes: usize,
    sc_min_posts_interval_ms: Range,
    session_id: String,
    transport: Arc<dyn RoundTripper>,
    state: AsyncMutex<PacketUpWriterState>,
    notify: Notify,
}

impl PacketUpWriterInner {
    /// The write buffering loop.
    async fn enqueue(inner: &Arc<Self>, data: Bytes) -> io::Result<usize> {
        let total = data.len();
        let mut remaining = data;
        loop {
            let mut state = inner.state.lock().await;
            if let Some(err) = &state.flush_err {
                return Err(io::Error::other(err.to_string()));
            }
            if remaining.is_empty() {
                return Ok(total);
            }
            if state.timer.is_none() {
                let millis = inner.sc_min_posts_interval_ms.rand().max(0).cast_unsigned();
                let inner2 = Arc::clone(inner);
                // `flush` aborts `state.timer` to cancel a still-pending timer; spawning `flush`
                // as its own task, rather than running it as
                // this sleep task's continuation, keeps that abort from ever targeting the task
                // currently executing it — self-aborting mid-`round_trip` silently dropped the
                // packet-up POST future forever, which was the packet-up hang.
                state.timer = Some(tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(millis)).await;
                    tokio::spawn(async move { Self::flush(&inner2).await });
                }));
            }
            let room = inner.sc_max_each_post_bytes.saturating_sub(state.buf.len());
            let take = room.min(remaining.len());
            if take > 0 {
                state.buf.extend_from_slice(&remaining.split_to(take));
            }
            if state.buf.len() >= inner.sc_max_each_post_bytes {
                let notified = inner.notify.notified();
                drop(state);
                notified.await;
            }
        }
    }

    /// Flushes buffered data. The mutex is held across the POST, so the async equivalent is
    /// a `tokio::sync::Mutex` guard held across the `.await`.
    async fn flush(inner: &Arc<Self>) {
        let mut state = inner.state.lock().await;
        if let Some(handle) = state.timer.take() {
            handle.abort();
        }
        if state.flush_err.is_some() {
            return;
        }
        if state.buf.is_empty() {
            return;
        }
        let seq_str = state.seq.to_string();
        state.seq += 1;
        let data = std::mem::take(&mut state.buf);
        let result = Self::post(inner, &seq_str, &data).await;
        if let Err(err) = result {
            state.flush_err = Some(Arc::new(err));
        }
        // `notify_waiters` wakes tasks that immediately retake this lock in `enqueue`.
        drop(state);
        inner.notify.notify_waiters();
    }

    async fn post(inner: &Arc<Self>, seq_str: &str, data: &[u8]) -> anyhow::Result<()> {
        // See the matching comment in `dial_stream_up`'s upload task: an opaque transport
        // dials lazily inside `round_trip`, but this crate's transports need an explicit
        // `ensure_connected` first. `dial_packet_up` only connects `download_transport`, so
        // without this, every packet-up POST through a `download-settings`-provided (genuinely
        // separate) `upload_transport` failed with "transport is not connected" — silently,
        // since `PacketUpWriter::poll_write` only buffers and returns `Ok` before the flush
        // timer fires, so the caller saw a successful write into a session that was never
        // created, then hung waiting for a response that would never arrive.
        inner.transport.ensure_connected(inner.ctx.clone()).await?;

        let mut req = Request {
            method: inner.cfg.normalized_uplink_http_method(),
            url: base_url(&inner.cfg)?,
            host: inner.cfg.host.clone(),
            ..Request::default()
        };
        inner.cfg.fill_packet_request(&mut req, &inner.session_id, seq_str, data)?;
        req.host.clone_from(&inner.cfg.host);

        // NOT cancel-safe: a cancelled context drops the round trip mid-request, so a POST the
        // peer already received is lost rather than retried.
        let resp = tokio::select! {
            result = inner.transport.round_trip(req) => result?,
            () = inner.ctx.cancelled() => return Err(anyhow!("context canceled")),
        };
        // cancel-safe: only the response body being drained is abandoned.
        tokio::select! {
            () = drain_body(resp.body) => {}
            () = inner.ctx.cancelled() => {}
        }

        if resp.status_code != 200 {
            return Err(anyhow!("xhttp packet-up bad status: {}", resp.status));
        }
        Ok(())
    }
}

pub(crate) struct PacketUpWriter {
    inner: Arc<PacketUpWriterInner>,
    pending: Option<Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>>,
}

impl PacketUpWriter {
    fn new(
        ctx: CancellationToken,
        cfg: Arc<Config>,
        sc_max_each_post_bytes: usize,
        sc_min_posts_interval_ms: Range,
        session_id: String,
        transport: Arc<dyn RoundTripper>,
    ) -> Self {
        let inner = Arc::new(PacketUpWriterInner {
            ctx,
            cfg,
            sc_max_each_post_bytes,
            sc_min_posts_interval_ms,
            session_id,
            transport,
            state: AsyncMutex::new(PacketUpWriterState { seq: 0, buf: Vec::new(), timer: None, flush_err: None }),
            notify: Notify::new(),
        });
        Self { inner, pending: None }
    }
}

impl AsyncWrite for PacketUpWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending.is_none() {
            // Fast path: append straight into the shared buffer without a per-write `Bytes`
            // copy or a boxed future, matching `enqueue`'s "still room, no need to wait" branch.
            // Any other case (lock contended, buffer would fill or overflow, or a flush error is
            // already recorded) falls back unchanged to the general `enqueue` path below, which
            // owns the append itself and cannot double-buffer these bytes.
            if let Ok(mut state) = this.inner.state.try_lock() {
                if state.flush_err.is_none() && !buf.is_empty() {
                    let would_be = state.buf.len() + buf.len();
                    if would_be < this.inner.sc_max_each_post_bytes {
                        if state.timer.is_none() {
                            let millis = this.inner.sc_min_posts_interval_ms.rand().max(0).cast_unsigned();
                            let inner2 = Arc::clone(&this.inner);
                            state.timer = Some(tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(millis)).await;
                                tokio::spawn(async move { PacketUpWriterInner::flush(&inner2).await });
                            }));
                        }
                        state.buf.extend_from_slice(buf);
                        return Poll::Ready(Ok(buf.len()));
                    }
                }
            }
            let owned = Bytes::copy_from_slice(buf);
            let inner = Arc::clone(&this.inner);
            this.pending = Some(Box::pin(async move { PacketUpWriterInner::enqueue(&inner, owned).await }));
        }
        // `pending` holds a future on every path that reaches here.
        match this.pending.as_mut().map(|pending| pending.as_mut().poll(cx)) {
            Some(Poll::Ready(result)) => {
                this.pending = None;
                Poll::Ready(result)
            }
            Some(Poll::Pending) | None => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl WriteCloser for PacketUpWriter {
    /// Closes the writer, adapted to the fire-and-forget `close(&self)` contract:
    /// flush in the background with the same one-second cap, then cancel and force-close.
    fn close(&self) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let flush_task = tokio::spawn({
                let inner = Arc::clone(&inner);
                async move { PacketUpWriterInner::flush(&inner).await }
            });
            let _ = tokio::time::timeout(Duration::from_secs(1), flush_task).await;
            inner.ctx.cancel();
            force_close::close_transport(inner.transport.as_ref());
        });
        Ok(())
    }
}

pub(crate) type ReqBody = StreamBody<BoxStream<'static, Result<Frame<Bytes>, io::Error>>>;

fn request_body_stream(body: Option<RequestBody>) -> BoxStream<'static, Result<Frame<Bytes>, io::Error>> {
    match body {
        None => futures::stream::empty().boxed(),
        Some(RequestBody::Bytes(b)) => futures::stream::once(async move { Ok(Frame::data(b)) }).boxed(),
        Some(RequestBody::Stream(r)) => ReaderStream::new(r).map(|res| res.map(Frame::data)).boxed(),
    }
}

pub(crate) fn build_hyper_request(req: Request) -> anyhow::Result<hyper::Request<ReqBody>> {
    let method = http::Method::from_bytes(req.method.as_bytes())?;
    let path_and_query = req.url[Position::BeforePath..].to_string();
    let uri: http::Uri = path_and_query.parse()?;
    let body = request_body_stream(req.body);
    let mut builder = http::Request::builder().method(method).uri(uri);
    if let Some(headers) = builder.headers_mut() {
        *headers = req.header;
    }
    let mut hyper_req = builder.body(StreamBody::new(body))?;
    if !req.host.is_empty() {
        if let Ok(value) = http::HeaderValue::from_str(&req.host) {
            hyper_req.headers_mut().insert(http::header::HOST, value);
        }
    }
    // The outgoing length is reported only when it is non-zero, so a
    // packet body of zero bytes stays chunked exactly as an empty body does. The
    // streaming uploads never set it, matching their unknown-length pipe bodies.
    if req.content_length > 0 {
        hyper_req
            .headers_mut()
            .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_str(&req.content_length.to_string())?);
    }
    Ok(hyper_req)
}

fn convert_hyper_response(resp: hyper::Response<hyper::body::Incoming>) -> Response {
    let status_code = resp.status().as_u16();
    let status = resp.status().to_string();
    let header = resp.headers().clone();
    let stream = resp.into_body().into_data_stream().map(|res| res.map_err(io::Error::other));
    let reader = StreamReader::new(stream);
    Response { status_code, status, header, body: Box::pin(reader) }
}

/// An HTTP/1.1 transport over `hyper::client::conn::http1` with `alpn: [http/1.1]`. Unlike a
/// pooling transport, which dials as many physical connections as concurrent round trips
/// need, this struct pins exactly one handshaked connection; [`Http1PoolTransport`] supplies the missing pooling
/// behaviour so callers that issue two overlapping HTTP/1.1 requests (a long-lived download GET
/// alongside upload POSTs, or two independent xhttp sessions sharing one `reuse-settings` entry)
/// get a second physical connection instead of deadlocking or breaking the pipe on the shared one.
struct Http1Transport {
    dial_raw: DialRawFunc,
    wrap_tls: WrapTlsFunc,
    send_request: Arc<AsyncMutex<Option<hyper::client::conn::http1::SendRequest<ReqBody>>>>,
    addr: Mutex<Option<(Arc<dyn Addr>, Arc<dyn Addr>)>>,
    /// Set for the duration of a request-response cycle, including however long the caller takes
    /// to drain the response body: HTTP/1.1 cannot start a second request on this connection
    /// until the first one's body has been fully read, so [`Http1PoolTransport`] must treat this
    /// connection as unavailable for that whole span, not just until the response headers arrive.
    busy: Arc<AtomicBool>,
}

impl Http1Transport {
    fn new(dial_raw: DialRawFunc, wrap_tls: WrapTlsFunc) -> Self {
        Self {
            dial_raw,
            wrap_tls,
            send_request: Arc::new(AsyncMutex::new(None)),
            addr: Mutex::new(None),
            busy: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl RoundTripper for Http1Transport {
    async fn ensure_connected(&self, ctx: CancellationToken) -> anyhow::Result<()> {
        let mut guard = self.send_request.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let raw = (self.dial_raw)(ctx.clone()).await?;
        let local = raw.local_addr().ok().map(Arc::<dyn Addr>::from);
        let remote = raw.remote_addr().ok().map(Arc::<dyn Addr>::from);
        let wrapped = (self.wrap_tls)(ctx, raw, false).await?;
        let io = TokioIo::new(wrapped);
        let (send_request, connection) = hyper::client::conn::http1::Builder::new().handshake(io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        // Published under the same guard that marks the connection usable, so a concurrent
        // `ensure_connected` never observes "connected but no address".
        if let (Some(local), Some(remote)) = (local, remote) {
            *self.addr.lock() = Some((local, remote));
        }
        *guard = Some(send_request);
        drop(guard);
        Ok(())
    }

    // NOT cancel-safe: the request borrows a locked send half and has already started writing, so a dropped call abandons the request on a connection that cannot be reused safely; the arms that await it drop it only while the connection is being torn down.
    async fn round_trip(&self, req: Request) -> anyhow::Result<Response> {
        self.busy.store(true, Ordering::SeqCst);
        let result = async {
            let hyper_req = build_hyper_request(req)?;
            let mut guard = self.send_request.lock().await;
            let Some(send_request) = guard.as_mut() else {
                return Err(anyhow!("xhttp: http/1.1 transport is not connected"));
            };
            let resp = send_request.send_request(hyper_req).await?;
            drop(guard);
            Ok(convert_hyper_response(resp))
        }
        .await;
        match result {
            Ok(resp) => Ok(with_busy_guard(resp, Arc::clone(&self.busy))),
            Err(err) => {
                self.busy.store(false, Ordering::SeqCst);
                Err(err)
            }
        }
    }

    fn peer_addr(&self) -> Option<(Box<dyn Addr>, Box<dyn Addr>)> {
        self.addr.lock().as_ref().map(|(local, remote)| -> (Box<dyn Addr>, Box<dyn Addr>) {
            (Box::new(SharedAddr(Arc::clone(local))), Box::new(SharedAddr(Arc::clone(remote))))
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl force_close::RoundTripper for Http1Transport {
    /// A plain `try_lock` here silently did nothing whenever a request happened to be in flight
    /// at close time — leaving that physical connection (and its background `connection.await`
    /// task) running forever, since nothing else ever clears `send_request`. Falling back to a
    /// spawned task that waits for the lock only in the contended case guarantees the clear
    /// eventually happens without deferring the common uncontended case: an unconditional spawn
    /// left a window between `close()` returning and the spawned task first acquiring the lock
    /// where `ensure_connected` still saw a stale `Some` and skipped re-dialing, then a later
    /// `round_trip` failed "not connected" once the task finally ran. Clearing synchronously
    /// under a blocking lock would avoid that window but stall the caller, so the spawn fallback
    /// is taken only when the lock is contended.
    fn close(&self) {
        if let Ok(mut guard) = self.send_request.try_lock() {
            *guard = None;
        } else {
            let send_request = Arc::clone(&self.send_request);
            tokio::spawn(async move {
                *send_request.lock().await = None;
            });
        }
        self.busy.store(false, Ordering::SeqCst);
    }
}

/// Wraps a response body so the connection that produced it is marked idle again once the body
/// is fully drained, errors, or is dropped early — whichever comes first — rather than as soon as
/// the response headers arrive. A caller that keeps reading the body for the tunnel's whole
/// lifetime (the stream-up/packet-up download GET) correctly keeps the connection busy for that
/// whole lifetime.
struct BusyGuardBody {
    inner: Pin<Box<dyn AsyncRead + Send>>,
    busy: Arc<AtomicBool>,
    done: bool,
}

impl AsyncRead for BusyGuardBody {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let poll = this.inner.as_mut().poll_read(cx, buf);
        match &poll {
            Poll::Ready(Ok(())) if buf.filled().len() == before => {
                this.done = true;
                this.busy.store(false, Ordering::SeqCst);
            }
            Poll::Ready(Err(_)) => {
                this.done = true;
                this.busy.store(false, Ordering::SeqCst);
            }
            Poll::Ready(_) | Poll::Pending => {}
        }
        poll
    }
}

impl Drop for BusyGuardBody {
    /// Only a clean EOF/error (handled in `poll_read`, which already cleared `busy`) means the
    /// connection is safe to reuse. HTTP/1.1 cannot resume a connection whose previous response
    /// body was abandoned mid-stream — the leftover unread bytes leave it in an indeterminate
    /// state, and hyper aborts rather than reuses it — so an early drop (`!done`) must leave
    /// `busy` set: this physical connection is retired from the pool, not returned to it. Without
    /// this, marking the connection idle here let a later `pick_or_dial` hand it straight back
    /// out; hyper then canceled that request outright once it noticed the abandoned body.
    fn drop(&mut self) {}
}

fn with_busy_guard(mut resp: Response, busy: Arc<AtomicBool>) -> Response {
    resp.body = Box::pin(BusyGuardBody { inner: resp.body, busy, done: false });
    resp
}

/// An opaque transport dials as many physical HTTP/1.1 connections as concurrently in-flight
/// round trips need; this crate's [`Http1Transport`] pins exactly one. Everywhere this crate
/// hands out one nominal "transport" for two things that must happen concurrently over HTTP/1.1 —
/// `dial_stream_up`'s simultaneous download GET and upload POST, `dial_packet_up`'s simultaneous
/// download GET and upload POSTs, and `ReuseManager` handing the same entry's transport to several
/// concurrent xhttp sessions — that single pinned connection deadlocks or breaks the pipe, since
/// HTTP/1.1 cannot interleave two open requests on one connection. This grows a small pool of
/// [`Http1Transport`]s on demand instead, reusing an idle one when available and dialing a new
/// physical connection only when every existing one is busy, mirroring what the pooling
/// a pooling transport does implicitly.
struct Http1PoolTransport {
    dial_raw: DialRawFunc,
    wrap_tls: WrapTlsFunc,
    /// Each connection is paired with the `close_gen` it was dialed under, so a deferred close
    /// only reaches connections that existed, or were being dialed, when that close began.
    conns: Arc<AsyncMutex<Vec<(u64, Arc<Http1Transport>)>>>,
    /// Bumped by [`close`]. A latch (set-once, never cleared) closed every connection dialed
    /// forever afterward. Closing a pool is not a permanent state — `reuse.rs`'s `ReuseManager`
    /// can legitimately hand this same entry to a new session concurrently with an old session's
    /// `ReuseEntry::release` closing it
    /// (`pick_locked` has no `unreusable_at` filter). [`pick_or_dial`] instead snapshots this
    /// generation before dialing and only self-closes the freshly dialed connection if the
    /// generation changed during that one dial, so a close that happened before or well after a
    /// given dial never poisons it.
    ///
    /// [`close`]: force_close::RoundTripper::close
    /// [`pick_or_dial`]: Http1PoolTransport::pick_or_dial
    close_gen: AtomicU64,
}

impl Http1PoolTransport {
    fn new(dial_raw: DialRawFunc, wrap_tls: WrapTlsFunc) -> Self {
        Self { dial_raw, wrap_tls, conns: Arc::new(AsyncMutex::new(Vec::new())), close_gen: AtomicU64::new(0) }
    }

    /// Picks an idle pooled connection or dials a fresh one. `reserve` marks the chosen
    /// connection busy before this returns, still under `conns`' lock: [`ensure_connected`]
    /// passes `false` (it only needs *a* live connection to exist, for `peer_addr`), but
    /// [`round_trip`] passes `true`, because `Client::dial_stream_up`/`dial_packet_up` spawn the
    /// download and upload `round_trip` calls as separate tasks rather than awaiting them inline
    /// — marking a connection busy only once its own `round_trip` call happens to run left a
    /// window where a second, concurrently scheduled task could see the same connection as idle
    /// and reuse it, sending two overlapping requests on one HTTP/1.1 connection (one of which
    /// hyper then cancels).
    ///
    /// [`ensure_connected`]: Http1PoolTransport::ensure_connected
    /// [`round_trip`]: Http1PoolTransport::round_trip
    async fn pick_or_dial(&self, ctx: CancellationToken, reserve: bool) -> anyhow::Result<Arc<Http1Transport>> {
        if let Some(conn) = self.pick_available(reserve).await {
            return Ok(conn);
        }
        // Dialing (and the handshake inside `ensure_connected`) happens with the pool lock
        // released: an opaque transport dials as many connections concurrently as
        // callers need, and holding this lock across a real network round trip would serialize
        // every other pool user — including unrelated logical sessions sharing this pool through
        // `ReuseManager` — behind however long one dial takes, turning a single slow or stuck dial
        // into a total pool freeze instead of a delay local to that one caller.
        let dial_gen = self.close_gen.load(Ordering::SeqCst);
        let conn = Arc::new(Http1Transport::new(Arc::clone(&self.dial_raw), Arc::clone(&self.wrap_tls)));
        conn.ensure_connected(ctx).await?;
        if reserve {
            conn.busy.store(true, Ordering::SeqCst);
        }
        self.conns.lock().await.push((dial_gen, Arc::clone(&conn)));
        // A `close()` that ran anywhere between the generation snapshot above and this push
        // bumped `close_gen`, so it observed a `conns` state before this connection existed;
        // checking for that change here — rather than a one-shot latch — makes at least one of
        // `close()`'s scan and this check close the connection, without poisoning dials that start
        // after `close()` has already finished.
        if self.close_gen.load(Ordering::SeqCst) != dial_gen {
            force_close::close_transport(conn.as_ref());
        }
        Ok(conn)
    }

    /// Scans the pool for a connection that is neither busy nor already closed, pruning the dead
    /// slots it walks past. `reserve` marks the picked connection busy before `conns` is released.
    async fn pick_available(&self, reserve: bool) -> Option<Arc<Http1Transport>> {
        let mut conns = self.conns.lock().await;
        let mut i = 0;
        loop {
            let conn = conns.get(i).map(|slot| Arc::clone(&slot.1))?;
            if conn.busy.load(Ordering::SeqCst) {
                i += 1;
                continue;
            }
            // An idle slot whose `send_request` was already cleared by `close()` is a dead
            // physical connection: handing it out would make `round_trip` fail "not connected"
            // where the pool would simply dial a fresh connection instead. The lock result is
            // collapsed into `Option<bool>` in its own match, rather than matched directly, so the
            // `MutexGuard` (and the `try_lock()` temporary that outlives a match statement's whole
            // body) is dropped before `conn` moves out.
            let connected = match conn.send_request.try_lock() {
                Ok(guard) => Some(guard.is_some()),
                Err(_) => None,
            };
            match connected {
                Some(true) => {
                    if reserve {
                        conn.busy.store(true, Ordering::SeqCst);
                    }
                    return Some(conn);
                }
                Some(false) => {
                    conns.remove(i);
                }
                // A close() is mid-clear on this slot: treat it as unavailable rather than racing
                // it, and leave it for the next scan to prune.
                None => i += 1,
            }
        }
    }
}

#[async_trait]
impl RoundTripper for Http1PoolTransport {
    async fn ensure_connected(&self, ctx: CancellationToken) -> anyhow::Result<()> {
        self.pick_or_dial(ctx, false).await.map(|_| ())
    }

    // cancel-safe: delegates to the inner transport's own `round_trip`/`read_datagram` and holds no state of its own, so it inherits that implementation's cancel safety.
    async fn round_trip(&self, req: Request) -> anyhow::Result<Response> {
        let conn = self.pick_or_dial(CancellationToken::new(), true).await?;
        conn.round_trip(req).await
    }

    fn peer_addr(&self) -> Option<(Box<dyn Addr>, Box<dyn Addr>)> {
        self.conns.try_lock().ok().and_then(|conns| conns.first().and_then(|(_, conn)| conn.peer_addr()))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl force_close::RoundTripper for Http1PoolTransport {
    /// Mirrors the per-connection fix on `Http1Transport::close`: an unconditional spawn left a
    /// window where a `pick_or_dial` racing this close still saw pre-close `conns` state before
    /// the spawned task ran. `try_lock` first — clearing synchronously when the lock is free —
    /// and fall back to spawn-and-await only when `conns` is contended (a dial currently holds
    /// it).
    fn close(&self) {
        // Connections dialed under a generation below `closing` are this close's to end. One
        // dialed later started after this close returned and belongs to whoever dialed it; a
        // deferred sweep that ignored the tag would kill it (a close-idle-connections call only
        // touches connections that are idle at the time of the call).
        let closing = self.close_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let sweep = move |conns: &[(u64, Arc<Http1Transport>)]| {
            for (dial_gen, conn) in conns {
                if *dial_gen < closing {
                    force_close::close_transport(conn.as_ref());
                }
            }
        };
        if let Ok(conns) = self.conns.try_lock() {
            sweep(&conns);
        } else {
            let conns = Arc::clone(&self.conns);
            tokio::spawn(async move { sweep(&conns.lock().await) });
        }
    }
}

/// A client connection over `hyper::client::conn::http2`, standing in for the h2c branch
/// of the transport builder (Chrome-masquerading default mode).
struct Http2Transport {
    dial_raw: DialRawFunc,
    wrap_tls: WrapTlsFunc,
    keep_alive_period: Duration,
    send_request: Arc<AsyncMutex<Option<hyper::client::conn::http2::SendRequest<ReqBody>>>>,
    addr: Mutex<Option<(Arc<dyn Addr>, Arc<dyn Addr>)>>,
}

impl Http2Transport {
    fn new(dial_raw: DialRawFunc, wrap_tls: WrapTlsFunc, keep_alive_period: Duration) -> Self {
        Self {
            dial_raw,
            wrap_tls,
            keep_alive_period,
            send_request: Arc::new(AsyncMutex::new(None)),
            addr: Mutex::new(None),
        }
    }
}

#[async_trait]
impl RoundTripper for Http2Transport {
    async fn ensure_connected(&self, ctx: CancellationToken) -> anyhow::Result<()> {
        let mut guard = self.send_request.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let raw = (self.dial_raw)(ctx.clone()).await?;
        let local = raw.local_addr().ok().map(Arc::<dyn Addr>::from);
        let remote = raw.remote_addr().ok().map(Arc::<dyn Addr>::from);
        let wrapped = (self.wrap_tls)(ctx, raw, true).await?;
        let io = TokioIo::new(wrapped);
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        if !self.keep_alive_period.is_zero() {
            builder.keep_alive_interval(self.keep_alive_period);
        }
        let (send_request, connection) = builder.handshake(io).await?;
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                log::debug!("xhttp h2 connection failed: {err:?}");
            }
        });
        // Published under the same guard that marks the connection usable, so a concurrent
        // `ensure_connected` never observes "connected but no address".
        if let (Some(local), Some(remote)) = (local, remote) {
            *self.addr.lock() = Some((local, remote));
        }
        *guard = Some(send_request);
        drop(guard);
        Ok(())
    }

    // NOT cancel-safe: cancellation cannot undo a request already delivered to the peer.
    async fn round_trip(&self, req: Request) -> anyhow::Result<Response> {
        let hyper_req = build_hyper_request(req)?;
        let mut guard = self.send_request.lock().await;
        let Some(send_request) = guard.as_mut() else {
            return Err(anyhow!("xhttp: h2c transport is not connected"));
        };
        let response = send_request.send_request(hyper_req);
        drop(guard);
        let resp = response.await?;
        Ok(convert_hyper_response(resp))
    }

    fn peer_addr(&self) -> Option<(Box<dyn Addr>, Box<dyn Addr>)> {
        self.addr.lock().as_ref().map(|(local, remote)| -> (Box<dyn Addr>, Box<dyn Addr>) {
            (Box::new(SharedAddr(Arc::clone(local))), Box::new(SharedAddr(Arc::clone(remote))))
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl force_close::RoundTripper for Http2Transport {
    /// See the matching comment on `Http1Transport::close`: an unconditional spawn deferred the
    /// clear even when uncontended, leaving a window where `ensure_connected` saw a stale `Some`
    /// and skipped re-dialing. `try_lock` first, falling back to spawn-and-await only when
    /// contended.
    fn close(&self) {
        if let Ok(mut guard) = self.send_request.try_lock() {
            *guard = None;
        } else {
            let send_request = Arc::clone(&self.send_request);
            tokio::spawn(async move {
                *send_request.lock().await = None;
            });
        }
    }
}

struct ChannelAsyncRead {
    rx: tokio::sync::mpsc::Receiver<io::Result<Bytes>>,
    leftover: Option<Bytes>,
}

impl AsyncRead for ChannelAsyncRead {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(mut data) = this.leftover.take() {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data.split_to(n));
                if !data.is_empty() {
                    this.leftover = Some(data);
                }
                return Poll::Ready(Ok(()));
            }
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(bytes))) => {
                    this.leftover = Some(bytes);
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// The `h3`/`h3-quinn`/`quinn` stand-in for `http3.Transport`, standing in for `alpn: [h3]`.
struct H3Transport {
    dial_quic: DialQuicFunc,
    keep_alive_period: Duration,
    max_idle_timeout: Duration,
    send_request: Arc<AsyncMutex<Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>>>,
    driver: Mutex<Option<tokio::task::JoinHandle<()>>>,
    addr: Mutex<Option<(Arc<dyn Addr>, Arc<dyn Addr>)>>,
    /// Set once [`close`] has run; every later request then fails rather than silently dialing a
    /// new QUIC connection.
    ///
    /// [`close`]: force_close::RoundTripper::close
    closed: AtomicBool,
}

impl H3Transport {
    fn new(dial_quic: DialQuicFunc, keep_alive_period: Duration, max_idle_timeout: Duration) -> Self {
        Self {
            dial_quic,
            keep_alive_period,
            max_idle_timeout,
            send_request: Arc::new(AsyncMutex::new(None)),
            driver: Mutex::new(None),
            addr: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl RoundTripper for H3Transport {
    async fn ensure_connected(&self, ctx: CancellationToken) -> anyhow::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(anyhow!("http3: transport is closed"));
        }
        let mut guard = self.send_request.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let quic_cfg = QuicConfig {
            max_incoming_streams: -1,
            keep_alive_period: self.keep_alive_period,
            max_idle_timeout: self.max_idle_timeout,
        };
        let quic_conn = (self.dial_quic)(ctx, quic_cfg).await?;
        let local = quic_conn.local_ip().map(|ip| Arc::new(TcpAddr::new(ip, 0)));
        let remote = Arc::new(TcpAddr::from(quic_conn.remote_address()));
        let h3_conn = h3_quinn::Connection::new(quic_conn);
        let (mut driver, send_request) =
            h3::client::new(h3_conn).await.map_err(|e| anyhow!("xhttp: h3 handshake failed: {e}"))?;
        let handle = tokio::spawn(async move {
            let _ = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        // Published under the same guard that marks the connection usable, so a concurrent
        // `ensure_connected` never observes "connected but no address".
        if let Some(local) = local {
            *self.addr.lock() = Some((local, remote));
        }
        *self.driver.lock() = Some(handle);
        *guard = Some(send_request);
        drop(guard);
        Ok(())
    }

    // NOT cancel-safe: the request borrows a locked send half and has already started writing, so a dropped call abandons the request on a connection that cannot be reused safely; the arms that await it drop it only while the connection is being torn down.
    async fn round_trip(&self, req: Request) -> anyhow::Result<Response> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(anyhow!("http3: transport is closed"));
        }
        let method = http::Method::from_bytes(req.method.as_bytes())?;
        let path_and_query = req.url[Position::BeforePath..].to_string();
        let mut builder = http::Request::builder().method(method).uri(path_and_query);
        if let Some(headers) = builder.headers_mut() {
            *headers = req.header;
        }
        let mut send_request = {
            let guard = self.send_request.lock().await;
            guard.clone().ok_or_else(|| anyhow!("xhttp: h3 transport is not connected"))?
        };
        let http_req = builder.body(())?;
        let mut stream = send_request.send_request(http_req).await?;

        match req.body {
            None => {}
            Some(RequestBody::Bytes(data)) => {
                stream.send_data(data).await?;
            }
            Some(RequestBody::Stream(mut reader)) => {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = reader.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    let Some(chunk) = buf.get(..n) else {
                        return Err(anyhow!("xhttp: h3 read returned {n} bytes for a {}-byte buffer", buf.len()));
                    };
                    stream.send_data(Bytes::copy_from_slice(chunk)).await?;
                }
            }
        }
        stream.finish().await?;

        let resp = stream.recv_response().await?;
        let status_code = resp.status().as_u16();
        let status = resp.status().to_string();
        let header = resp.headers().clone();

        let (tx, rx) = tokio::sync::mpsc::channel::<io::Result<Bytes>>(16);
        tokio::spawn(async move {
            loop {
                match stream.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        if tx.send(Ok(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        let _ = tx.send(Err(io::Error::other(err.to_string()))).await;
                        break;
                    }
                }
            }
        });

        Ok(Response { status_code, status, header, body: Box::pin(ChannelAsyncRead { rx, leftover: None }) })
    }

    fn peer_addr(&self) -> Option<(Box<dyn Addr>, Box<dyn Addr>)> {
        self.addr.lock().as_ref().map(|(local, remote)| -> (Box<dyn Addr>, Box<dyn Addr>) {
            (Box::new(SharedAddr(Arc::clone(local))), Box::new(SharedAddr(Arc::clone(remote))))
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl force_close::RoundTripper for H3Transport {
    /// See the matching comment on `Http1Transport::close` for why `send_request` is cleared via
    /// `try_lock`-then-spawn rather than an unconditional spawn. Setting `closed` additionally
    /// makes every later request fail instead of quietly dialing a new QUIC connection.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.send_request.try_lock() {
            *guard = None;
        } else {
            let send_request = Arc::clone(&self.send_request);
            tokio::spawn(async move {
                *send_request.lock().await = None;
            });
        }
        let handle = self.driver.lock().take();
        if let Some(handle) = handle {
            handle.abort();
        }
    }
}

/// Keep-alive normalization in the transport builder: zero takes the HTTP-version default, a
/// negative value disables keep-alive.
fn normalized_keep_alive(configured: Duration, default: Duration) -> Duration {
    match configured.cmp(&Duration::ZERO) {
        std::cmp::Ordering::Equal => default,
        std::cmp::Ordering::Less => Duration::ZERO,
        std::cmp::Ordering::Greater => configured,
    }
}

pub fn new_transport(
    dial_raw: DialRawFunc,
    wrap_tls: WrapTlsFunc,
    dial_quic: DialQuicFunc,
    alpn: &[String],
    keep_alive_period: Duration,
) -> Arc<dyn RoundTripper> {
    match alpn {
        [only] if only == "h3" => {
            let keep_alive_period = normalized_keep_alive(keep_alive_period, QUICGO_H3_KEEP_ALIVE_PERIOD);
            Arc::new(H3Transport::new(dial_quic, keep_alive_period, CONN_IDLE_TIMEOUT))
        }
        [only] if only == "http/1.1" => Arc::new(Http1PoolTransport::new(dial_raw, wrap_tls)),
        _ => Arc::new(Http2Transport::new(
            dial_raw,
            wrap_tls,
            normalized_keep_alive(keep_alive_period, CHROME_H2_KEEP_ALIVE_PERIOD),
        )),
    }
}

/// Prevents the underlying transport from being closed by leaving every
/// `force_close::RoundTripper` hook a no-op.
struct OnlyRoundTripper(Arc<dyn RoundTripper>);

#[async_trait]
impl RoundTripper for OnlyRoundTripper {
    // cancel-safe: delegates to the inner transport's own `round_trip`/`read_datagram` and holds no state of its own, so it inherits that implementation's cancel safety.
    async fn round_trip(&self, req: Request) -> anyhow::Result<Response> {
        self.0.round_trip(req).await
    }

    async fn ensure_connected(&self, ctx: CancellationToken) -> anyhow::Result<()> {
        self.0.ensure_connected(ctx).await
    }

    fn peer_addr(&self) -> Option<(Box<dyn Addr>, Box<dyn Addr>)> {
        self.0.peer_addr()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl force_close::RoundTripper for OnlyRoundTripper {}

#[derive(Debug)]
struct SharedAddr(Arc<dyn Addr>);

impl Addr for SharedAddr {
    fn network(&self) -> &str {
        self.0.network()
    }

    fn string(&self) -> String {
        self.0.string()
    }

    fn addr_port(&self) -> Option<murmur_std_compat::net::AddrPort> {
        self.0.addr_port()
    }

    fn raw_addr(&self) -> Option<&dyn Addr> {
        self.0.raw_addr()
    }

    fn as_iface_prefix(&self) -> Option<ipnet::IpNet> {
        self.0.as_iface_prefix()
    }

    fn as_sock_addr(&self) -> Option<murmur_std_compat::net::SockAddr> {
        self.0.as_sock_addr()
    }
}

struct AddrOnlyConn {
    local: Arc<dyn Addr>,
    remote: Arc<dyn Addr>,
}

impl AsyncRead for AddrOnlyConn {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for AddrOnlyConn {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl NetConn for AddrOnlyConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(SharedAddr(Arc::clone(&self.local))))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(SharedAddr(Arc::clone(&self.remote))))
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Builds the address context with a "got connection" trace hook, invoked directly once a
/// transport's [`RoundTripper::peer_addr`] is known instead of racing on the trace hook
/// (see [`RoundTripper::ensure_connected`]'s doc comment).
fn populate_net_addr(net_addr: &Arc<NetAddr>, local: Box<dyn Addr>, remote: Box<dyn Addr>) {
    let trace = new_addr_context(Arc::clone(net_addr));
    if let Some(got_conn) = trace.got_conn {
        let conn: Arc<dyn NetConn> = Arc::new(AddrOnlyConn { local: Arc::from(local), remote: Arc::from(remote) });
        got_conn(&GotConnInfo { conn, reused: false });
    }
}

/// The unbuffered pipe half, made explicitly closable from outside the reader/writer that
/// owns it: closing drops the underlying `tokio::io::DuplexStream`, which makes the peer half's
/// pending and future reads observe EOF and its writes observe a broken pipe.
struct ClosableDuplex(Mutex<Option<tokio::io::DuplexStream>>);

impl ClosableDuplex {
    fn new(stream: tokio::io::DuplexStream) -> Self {
        Self(Mutex::new(Some(stream)))
    }

    fn close_marker(&self) {
        *self.0.lock() = None;
    }

    fn poll_read_ref(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.0.lock().as_mut() {
            Some(stream) => Pin::new(stream).poll_read(cx, buf),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_write_ref(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.0.lock().as_mut() {
            Some(stream) => Pin::new(stream).poll_write(cx, buf),
            None => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
        }
    }

    fn poll_flush_ref(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.0.lock().as_mut() {
            Some(stream) => Pin::new(stream).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown_ref(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.0.lock().as_mut() {
            Some(stream) => Pin::new(stream).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

struct SharedDuplexReader(Arc<ClosableDuplex>);

impl AsyncRead for SharedDuplexReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.get_mut().0.poll_read_ref(cx, buf)
    }
}

impl ReadCloser for SharedDuplexReader {
    fn close(&self) -> io::Result<()> {
        self.0.close_marker();
        Ok(())
    }
}

struct SharedDuplexWriter(Arc<ClosableDuplex>);

impl AsyncWrite for SharedDuplexWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().0.poll_write_ref(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().0.poll_flush_ref(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().0.poll_shutdown_ref(cx)
    }
}

impl WriteCloser for SharedDuplexWriter {
    fn close(&self) -> io::Result<()> {
        self.0.close_marker();
        Ok(())
    }
}

struct WaitReadCloserState {
    rc: Option<Pin<Box<dyn ReadCloser>>>,
    err: Option<Arc<io::Error>>,
    waker: Option<std::task::Waker>,
}

/// A read-closer that blocks `Read()` until the underlying `ReadCloser`
/// is provided via `Set`, so the caller can return a reader immediately while the real HTTP
/// response body is obtained asynchronously, breaking the synchronous round-trip deadlock with
/// CDN header buffering.
pub(crate) struct WaitReadCloser {
    state: Mutex<WaitReadCloserState>,
    once: AtomicBool,
}

impl WaitReadCloser {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(WaitReadCloserState { rc: None, err: None, waker: None }),
            once: AtomicBool::new(false),
        })
    }

    pub(crate) fn set(&self, rc: Pin<Box<dyn ReadCloser>>) {
        self.setup(Some(rc), None);
    }

    pub(crate) fn close_with_error(&self, err: io::Error) {
        self.setup(None, Some(Arc::new(err)));
    }

    fn setup(&self, rc: Option<Pin<Box<dyn ReadCloser>>>, err: Option<Arc<io::Error>>) {
        let already = self.once.swap(true, Ordering::SeqCst);
        if !already {
            let mut state = self.state.lock();
            state.rc = rc;
            state.err = err;
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
            drop(state);
            return;
        }
        if let Some(rc) = rc {
            let has_err = self.state.lock().err.is_some();
            if has_err {
                let _ = rc.close();
            }
        }
    }

    fn poll_read_impl(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut state = self.state.lock();
        if self.once.load(Ordering::SeqCst) {
            if let Some(rc) = state.rc.as_mut() {
                return rc.as_mut().poll_read(cx, buf);
            }
            let err = state.err.clone().unwrap_or_else(|| Arc::new(io::Error::other("xhttp: wait read closer closed")));
            return Poll::Ready(Err(io::Error::new(err.kind(), err.to_string())));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// Closes the reader, adapted so it never blocks: it deterministically wins or
    /// loses the `setup` race under the same lock the winning set or close-with-error call uses,
    /// so there is nothing left to wait on afterwards.
    fn close_impl(&self) -> io::Result<()> {
        self.setup(None, Some(Arc::new(io::Error::from(io::ErrorKind::NotConnected))));
        let state = self.state.lock();
        let result = state.rc.as_ref().map(|rc| rc.close());
        drop(state);
        match result {
            Some(result) => result,
            None => Ok(()),
        }
    }
}

struct WaitReadCloserHandle(Arc<WaitReadCloser>);

impl AsyncRead for WaitReadCloserHandle {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.0.poll_read_impl(cx, buf)
    }
}

impl ReadCloser for WaitReadCloserHandle {
    fn close(&self) -> io::Result<()> {
        self.0.close_impl()
    }
}

/// Adapts a bare `AsyncRead` (a `hyper`/`h3` response body) into a [`ReadCloser`]. Neither carrier
/// exposes an explicit close method, but closing the counterpart body still does real work on a
/// body that was not read to completion: for a
/// still-open response it aborts the read and prevents the underlying connection from being
/// reused. Dropping the boxed reader is the equivalent here — it releases `hyper`'s `Incoming`
/// handle, which lets `hyper` tear down the physical connection instead of holding it (and its
/// background `connection.await` task) open forever waiting for a body nobody will ever finish
/// reading. An earlier version made `close` a literal no-op, which correctly forwarded the
/// `WaitReadCloser` close path but never released anything: every `dial_stream_up`/`dial_packet_up`
/// download connection outlived the logical session that opened it.
struct NoCloseRead(Mutex<Option<Pin<Box<dyn AsyncRead + Send>>>>);

impl NoCloseRead {
    fn new(inner: Pin<Box<dyn AsyncRead + Send>>) -> Self {
        Self(Mutex::new(Some(inner)))
    }
}

impl AsyncRead for NoCloseRead {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().0.lock().as_mut() {
            Some(inner) => inner.as_mut().poll_read(cx, buf),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl ReadCloser for NoCloseRead {
    fn close(&self) -> io::Result<()> {
        self.0.lock().take();
        Ok(())
    }
}

/// Polls `download_fut` once so its request claims a pooled connection while the caller still
/// owns the dial, then finishes it in a task. A request that completes on that first poll is
/// settled from its own result rather than awaited again, which would panic with "`async fn`
/// resumed after completion" and strand `wrc` unset. The poll never suspends, so awaiting this
/// still happens before the caller spawns the upload leg.
async fn spawn_download<F>(mut download_fut: Pin<Box<F>>, wrc: Arc<WaitReadCloser>, bad_status: &'static str)
where
    F: Future<Output = anyhow::Result<Response>> + Send + 'static,
{
    let ready = match futures::poll!(&mut download_fut) {
        Poll::Ready(result) => Some(result),
        Poll::Pending => None,
    };
    tokio::spawn(async move {
        let result = match ready {
            Some(result) => result,
            None => download_fut.await,
        };
        match result {
            Ok(resp) if resp.status_code == 200 => wrc.set(Box::pin(NoCloseRead::new(resp.body))),
            Ok(resp) => {
                let err = io::Error::other(format!("{bad_status}: {}", resp.status));
                wrc.close_with_error(err);
            }
            Err(err) => wrc.close_with_error(io::Error::other(err.to_string())),
        }
    });
}

pub struct Client {
    ctx: CancellationToken,
    mode: String,
    cfg: Arc<Config>,
    sc_max_each_post_bytes: Range,
    sc_min_posts_interval_ms: Range,
    generate_session_id: Arc<dyn Fn() -> String + Send + Sync>,
    make_transport: TransportMaker,
    make_download_transport: Option<TransportMaker>,
    upload_manager: Option<Arc<ReuseManager>>,
    download_manager: Option<Arc<ReuseManager>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("mode", &self.mode)
            .field("cfg", &self.cfg)
            .field("sc_max_each_post_bytes", &self.sc_max_each_post_bytes)
            .field("sc_min_posts_interval_ms", &self.sc_min_posts_interval_ms)
            .field("upload_manager", &self.upload_manager.is_some())
            .field("download_manager", &self.download_manager.is_some())
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(
        cfg: Arc<Config>,
        make_transport: TransportMaker,
        make_download_transport: Option<TransportMaker>,
        has_reality: bool,
    ) -> anyhow::Result<Self> {
        let mode = cfg.effective_mode(has_reality);
        match mode.as_str() {
            "stream-one" | "stream-up" | "packet-up" => {}
            other => return Err(anyhow!("xhttp mode {other} is not implemented yet")),
        }
        let sc_max_each_post_bytes = cfg.normalized_sc_max_each_post_bytes()?;
        let sc_min_posts_interval_ms = cfg.normalized_sc_min_posts_interval_ms()?;
        let generate_session_id: Arc<dyn Fn() -> String + Send + Sync> = Arc::from(cfg.generate_session_id()?);
        let ctx = CancellationToken::new();

        let mut upload_manager = None;
        let mut download_manager = None;
        if cfg.reuse_config.is_some() {
            upload_manager = ReuseManager::new(cfg.reuse_config.as_deref(), Arc::clone(&make_transport))?.map(Arc::new);
            if let Some(download_cfg) = &cfg.download_config {
                let maker = make_download_transport
                    .clone()
                    .ok_or_else(|| anyhow!("xhttp: download manager requires download transport maker"))?;
                let manager = ReuseManager::new(download_cfg.reuse_config.as_deref(), maker)?.ok_or_else(|| {
                    anyhow!("xhttp: download reuse manager requires a reuse config, matching nil *ReuseManager.GetTransport method-value panic")
                })?;
                download_manager = Some(Arc::new(manager));
            }
        }

        Ok(Self {
            ctx,
            mode,
            cfg,
            sc_max_each_post_bytes,
            sc_min_posts_interval_ms,
            generate_session_id,
            make_transport,
            make_download_transport,
            upload_manager,
            download_manager,
        })
    }

    /// Closes the client. Cancels the context and closes both reuse managers; `ReuseManager::close`
    /// never fails, so there is nothing to collect.
    pub fn close(&self) -> anyhow::Result<()> {
        self.ctx.cancel();
        ReuseManager::close(self.upload_manager.as_deref());
        ReuseManager::close(self.download_manager.as_deref());
        Ok(())
    }

    pub async fn dial(&self, ctx: CancellationToken) -> anyhow::Result<Box<dyn NetConn>> {
        match self.mode.as_str() {
            "stream-one" => self.dial_stream_one(ctx).await,
            "stream-up" => self.dial_stream_up(ctx).await,
            "packet-up" => self.dial_packet_up(ctx).await,
            other => Err(anyhow!("xhttp mode {other} is not implemented yet")),
        }
    }

    fn transport(&self) -> (Arc<dyn RoundTripper>, Arc<dyn RoundTripper>) {
        let upload_transport = match &self.upload_manager {
            Some(manager) => manager.transport(),
            None => (self.make_transport)(),
        };
        let download_transport = match &self.download_manager {
            Some(manager) => manager.transport(),
            None => match &self.make_download_transport {
                Some(maker) => maker(),
                None => Arc::new(OnlyRoundTripper(Arc::clone(&upload_transport))),
            },
        };
        (upload_transport, download_transport)
    }

    pub async fn dial_stream_one(&self, ctx: CancellationToken) -> anyhow::Result<Box<dyn NetConn>> {
        let (transport, _) = self.transport();

        let (local_stream, remote_stream) = tokio::io::duplex(UPLOAD_PIPE_CAPACITY);
        let local_half = Arc::new(ClosableDuplex::new(local_stream));
        let remote_half = Arc::new(ClosableDuplex::new(remote_stream));

        let net_addr = Arc::new(NetAddr::default());

        let req_ctx = self.ctx.child_token();
        let stop = murmur_common::contextutils::after_func(&ctx, {
            let req_ctx = req_ctx.clone();
            move || req_ctx.cancel()
        });

        let result: anyhow::Result<Box<dyn NetConn>> = async {
            if let Err(err) = transport.ensure_connected(req_ctx.clone()).await {
                remote_half.close_marker();
                force_close::close_transport(transport.as_ref());
                return Err(err);
            }
            if let Some((local, remote)) = transport.peer_addr() {
                populate_net_addr(&net_addr, local, remote);
            }

            let mut req = Request {
                method: self.cfg.normalized_uplink_http_method(),
                url: base_url(&self.cfg)?,
                host: self.cfg.host.clone(),
                body: Some(RequestBody::Stream(Box::pin(SharedDuplexReader(Arc::clone(&remote_half))))),
                ..Request::default()
            };
            self.cfg.fill_stream_request(&mut req, "")?;
            req.host.clone_from(&self.cfg.host);

            let wrc = WaitReadCloser::new();
            let wrc_task = Arc::clone(&wrc);
            let transport_task = Arc::clone(&transport);
            tokio::spawn(async move {
                match transport_task.round_trip(req).await {
                    Ok(resp) if (200..300).contains(&resp.status_code) => {
                        wrc_task.set(Box::pin(NoCloseRead::new(resp.body)));
                    }
                    Ok(resp) => wrc_task
                        .close_with_error(io::Error::other(format!("xhttp stream-one bad status: {}", resp.status))),
                    Err(err) => wrc_task.close_with_error(io::Error::other(err.to_string())),
                }
            });

            let conn =
                XConn::new(Box::pin(SharedDuplexWriter(local_half)), Box::pin(WaitReadCloserHandle(wrc)), net_addr);
            let remote_close = Arc::clone(&remote_half);
            let transport_close = Arc::clone(&transport);
            let req_ctx_close = req_ctx.clone();
            conn.set_on_close(Box::new(move || {
                remote_close.close_marker();
                force_close::close_transport(transport_close.as_ref());
                req_ctx_close.cancel();
            }));

            let conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(conn));
            Ok(conn)
        }
        .await;

        drop(stop);
        result
    }

    pub async fn dial_stream_up(&self, ctx: CancellationToken) -> anyhow::Result<Box<dyn NetConn>> {
        let (upload_transport, download_transport) = self.transport();
        let download_cfg: &Config = self.cfg.download_config.as_deref().unwrap_or(&self.cfg);

        let (local_stream, remote_stream) = tokio::io::duplex(UPLOAD_PIPE_CAPACITY);
        let local_half = Arc::new(ClosableDuplex::new(local_stream));
        let remote_half = Arc::new(ClosableDuplex::new(remote_stream));

        let session_id = (self.generate_session_id)();
        let net_addr = Arc::new(NetAddr::default());

        let req_ctx = self.ctx.child_token();
        let stop = murmur_common::contextutils::after_func(&ctx, {
            let req_ctx = req_ctx.clone();
            move || req_ctx.cancel()
        });

        let result: anyhow::Result<Box<dyn NetConn>> = async {
            let mut download_req = Request {
                method: "GET".to_owned(),
                url: base_url(download_cfg)?,
                host: download_cfg.host.clone(),
                ..Request::default()
            };
            download_cfg.fill_download_request(&mut download_req, &session_id)?;
            download_req.host.clone_from(&download_cfg.host);

            let mut upload_req = Request {
                method: self.cfg.normalized_uplink_http_method(),
                url: base_url(&self.cfg)?,
                host: self.cfg.host.clone(),
                body: Some(RequestBody::Stream(Box::pin(SharedDuplexReader(Arc::clone(&remote_half))))),
                ..Request::default()
            };
            self.cfg.fill_stream_request(&mut upload_req, &session_id)?;
            upload_req.host.clone_from(&self.cfg.host);

            if let Err(err) = download_transport.ensure_connected(req_ctx.clone()).await {
                remote_half.close_marker();
                force_close::close_transport(upload_transport.as_ref());
                force_close::close_transport(download_transport.as_ref());
                return Err(err);
            }
            if let Some((local, remote)) = download_transport.peer_addr() {
                populate_net_addr(&net_addr, local, remote);
            }

            let wrc = WaitReadCloser::new();
            let wrc_task = Arc::clone(&wrc);
            let download_task = Arc::clone(&download_transport);
            let download_fut = Box::pin(async move { download_task.round_trip(download_req).await });
            // The pool reserves a connection only inside `round_trip`, so this future has to claim
            // the one `ensure_connected` created before the upload task below shares the pool; two
            // overlapping HTTP/1.1 requests never complete. `spawn_download` polls it now.
            spawn_download(download_fut, wrc_task, "xhttp stream-up download bad status").await;

            let upload_task = Arc::clone(&upload_transport);
            let local_for_error = Arc::clone(&local_half);
            let upload_req_ctx = req_ctx.clone();
            let upload_drain_ctx = req_ctx.clone();
            tokio::spawn(async move {
                // an opaque transport dials lazily inside the round trip; this crate's transports
                // require an explicit `ensure_connected` first, and only `download_transport` got
                // one above. That is harmless when `download_transport` is `OnlyRoundTripper`
                // wrapping this same `upload_transport` (the no-`download-settings` case), but
                // once `download-settings` gives it a real, separate transport, `upload_task`
                // here was never connected: every `round_trip` failed with "transport is not
                // connected", silently breaking the shared duplex pipe on the first write.
                if let Err(err) = upload_task.ensure_connected(upload_req_ctx).await {
                    log::debug!("xhttp stream-up upload connect failed: {err}");
                    local_for_error.close_marker();
                    return;
                }
                match upload_task.round_trip(upload_req).await {
                    Ok(resp) => {
                        let status_code = resp.status_code;
                        // `resp.body` is the server's stream-up padding channel: it stays open for
                        // the whole session (`server.rs`'s upload handler never closes its response
                        // sender on its own) and only ends when the session itself does. A read of
                        // such a body is normally aborted by the HTTP client the moment the
                        // request's context is canceled. This transport has no such automatic
                        // wiring, so
                        // draining without a `select!` against `req_ctx` left this task — and the
                        // `Arc<dyn RoundTripper>` (and its live socket) it holds — blocked forever
                        // once the caller has closed the session, one leaked connection per dial.
                        // cancel-safe: only the response body being drained is abandoned.
                        tokio::select! {
                            () = drain_body(resp.body) => {}
                            () = upload_drain_ctx.cancelled() => {}
                        }
                        if !(200..300).contains(&status_code) {
                            local_for_error.close_marker();
                        }
                    }
                    Err(_) => local_for_error.close_marker(),
                }
            });

            let conn =
                XConn::new(Box::pin(SharedDuplexWriter(local_half)), Box::pin(WaitReadCloserHandle(wrc)), net_addr);
            let remote_close = Arc::clone(&remote_half);
            let upload_close = Arc::clone(&upload_transport);
            let download_close = Arc::clone(&download_transport);
            let req_ctx_close = req_ctx.clone();
            conn.set_on_close(Box::new(move || {
                remote_close.close_marker();
                force_close::close_transport(upload_close.as_ref());
                force_close::close_transport(download_close.as_ref());
                req_ctx_close.cancel();
            }));

            let conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(conn));
            Ok(conn)
        }
        .await;

        let _ = stop();
        result
    }

    pub async fn dial_packet_up(&self, ctx: CancellationToken) -> anyhow::Result<Box<dyn NetConn>> {
        let (upload_transport, download_transport) = self.transport();
        let download_cfg: &Config = self.cfg.download_config.as_deref().unwrap_or(&self.cfg);
        let session_id = (self.generate_session_id)();

        let writer_ctx = self.ctx.child_token();
        let writer = PacketUpWriter::new(
            writer_ctx,
            Arc::clone(&self.cfg),
            usize::try_from(self.sc_max_each_post_bytes.rand().max(0)).unwrap_or(0),
            self.sc_min_posts_interval_ms,
            session_id.clone(),
            Arc::clone(&upload_transport),
        );

        let net_addr = Arc::new(NetAddr::default());

        let req_ctx = self.ctx.child_token();
        let stop = murmur_common::contextutils::after_func(&ctx, {
            let req_ctx = req_ctx.clone();
            move || req_ctx.cancel()
        });

        let result: anyhow::Result<Box<dyn NetConn>> = async {
            let mut download_req = Request {
                method: "GET".to_owned(),
                url: base_url(download_cfg)?,
                host: download_cfg.host.clone(),
                ..Request::default()
            };
            download_cfg.fill_download_request(&mut download_req, &session_id)?;
            download_req.host.clone_from(&download_cfg.host);

            if let Err(err) = download_transport.ensure_connected(req_ctx.clone()).await {
                force_close::close_transport(upload_transport.as_ref());
                force_close::close_transport(download_transport.as_ref());
                return Err(err);
            }
            if let Some((local, remote)) = download_transport.peer_addr() {
                populate_net_addr(&net_addr, local, remote);
            }

            let wrc = WaitReadCloser::new();
            let wrc_task = Arc::clone(&wrc);
            let download_task = Arc::clone(&download_transport);
            let download_fut = Box::pin(async move { download_task.round_trip(download_req).await });
            // Same claim as `dial_stream_up`: `spawn_download` polls the download request before
            // the packet writer below shares this pool, so its first POST cannot take the connection.
            spawn_download(download_fut, wrc_task, "xhttp packet-up download bad status").await;

            let conn = XConn::new(Box::pin(writer), Box::pin(WaitReadCloserHandle(wrc)), net_addr);
            let download_close = Arc::clone(&download_transport);
            let req_ctx_close = req_ctx.clone();
            conn.set_on_close(Box::new(move || {
                force_close::close_transport(download_close.as_ref());
                req_ctx_close.cancel();
            }));

            let conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(conn));
            Ok(conn)
        }
        .await;

        drop(stop);
        result
    }
}

#[cfg(test)]
mod close_race_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicUsize;

    use tokio::io::AsyncWriteExt;
    use tokio::sync::Notify;

    use super::*;

    struct DuplexConn(tokio::io::DuplexStream);

    impl AsyncRead for DuplexConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DuplexConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl NetConn for DuplexConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    fn passthrough_wrap_tls() -> WrapTlsFunc {
        Arc::new(|_ctx, conn, _is_h2| Box::pin(async move { Ok(conn) }))
    }

    fn counting_dial_raw(count: Arc<AtomicUsize>) -> DialRawFunc {
        Arc::new(move |_ctx| {
            let count = Arc::clone(&count);
            Box::pin(async move {
                count.fetch_add(1, Ordering::SeqCst);
                let (client, mut server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while matches!(server.read(&mut buf).await, Ok(n) if n > 0) {}
                });
                let conn: Box<dyn NetConn> = Box::new(DuplexConn(client));
                Ok(conn)
            })
        })
    }

    /// Like [`counting_dial_raw`], but the spawned peer answers every request that reaches
    /// `\r\n\r\n` with a minimal `200 OK`, so a real `round_trip` through hyper's HTTP/1.1 client
    /// completes instead of hanging on a response that never arrives.
    fn responding_dial_raw() -> DialRawFunc {
        Arc::new(move |_ctx| {
            Box::pin(async move {
                let (client, mut server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let mut received = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        match server.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                received.extend_from_slice(&chunk[..n]);
                                if received.windows(4).any(|w| w == b"\r\n\r\n") {
                                    if server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.is_err()
                                    {
                                        return;
                                    }
                                    received.clear();
                                }
                            }
                        }
                    }
                });
                let conn: Box<dyn NetConn> = Box::new(DuplexConn(client));
                Ok(conn)
            })
        })
    }

    /// Like [`responding_dial_raw`], but the response never ends: no `Content-Length`, no
    /// terminating chunk, and the connection is left open. Models `server.rs`'s stream-up upload
    /// response — its `channel_body` sender only drops when the session's own on-close callback
    /// removes it (`server.rs`'s stream-up upload handler), so draining it is only safe when
    /// tied to the caller's own session lifetime, the same way an HTTP client ties a response
    /// body read to the request's context.
    fn indefinite_response_dial_raw() -> DialRawFunc {
        Arc::new(move |_ctx| {
            Box::pin(async move {
                let (client, mut server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let mut received = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let mut responded = false;
                    loop {
                        match server.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                received.extend_from_slice(&chunk[..n]);
                                if !responded && received.windows(4).any(|w| w == b"\r\n\r\n") {
                                    responded = true;
                                    if server
                                        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                                        .await
                                        .is_err()
                                    {
                                        return;
                                    }
                                    received.clear();
                                }
                            }
                        }
                    }
                });
                let conn: Box<dyn NetConn> = Box::new(DuplexConn(client));
                Ok(conn)
            })
        })
    }

    /// Regression test for the stream-up upload task leak: `server.rs`'s stream-up upload
    /// endpoint responds with an indefinite body that only closes when the session ends, so
    /// `dial_stream_up`'s upload task — which drains that response body in the background — must
    /// stop draining once the session ends, exactly as a canceled request context aborts the
    /// read. This never calls `conn.close()` and never cancels
    /// `dial_ctx`: the only thing that can release the transport here is [`XConn`]'s `Drop`
    /// reaching `on_close`, the same way a Rust caller that errors out with `?` before an
    /// explicit `close()` still needs the session torn down.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stream_up_dropping_the_session_without_close_releases_the_upload_task() {
        let transport: Arc<dyn RoundTripper> =
            Arc::new(Http1PoolTransport::new(indefinite_response_dial_raw(), passthrough_wrap_tls()));
        let maker_transport = Arc::clone(&transport);
        let make_transport: TransportMaker = Arc::new(move || Arc::clone(&maker_transport));
        let baseline = Arc::strong_count(&transport);

        let cfg = Config { host: "example.com".to_owned(), mode: "stream-up".to_owned(), ..Config::default() };
        let client = Client::new(Arc::new(cfg), make_transport, None, false).expect("client construction");

        let dial_ctx = CancellationToken::new();
        let conn = client.dial_stream_up(dial_ctx.clone()).await.expect("dial_stream_up");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let during = Arc::strong_count(&transport);
        assert!(during > baseline, "dialing must take at least one extra reference on the transport");

        drop(conn);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && Arc::strong_count(&transport) > baseline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            Arc::strong_count(&transport),
            baseline,
            "dropping a stream-up session without ever calling close() must still release the \
             upload task's transport reference within a bounded time, not leave it draining the \
             server's indefinite padding response forever"
        );
    }

    /// Regression test for the same leak, exercised through an explicit `close()` instead of a
    /// bare drop. `upload_transport` here is wrapped in [`OnlyRoundTripper`], whose
    /// `force_close::RoundTripper::close` is a no-op, so `force_close::close_transport` in
    /// `on_close` cannot be what unblocks the drain: only `req_ctx`'s cancellation can, which is
    /// what this test actually needs to prove reaches the upload task's `select!`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stream_up_closing_the_session_releases_the_upload_task() {
        let transport: Arc<dyn RoundTripper> =
            Arc::new(Http1PoolTransport::new(indefinite_response_dial_raw(), passthrough_wrap_tls()));
        let maker_transport = Arc::clone(&transport);
        let make_transport: TransportMaker = Arc::new(move || {
            let wrapped: Arc<dyn RoundTripper> = Arc::new(OnlyRoundTripper(Arc::clone(&maker_transport)));
            wrapped
        });
        let baseline = Arc::strong_count(&transport);

        let cfg = Config { host: "example.com".to_owned(), mode: "stream-up".to_owned(), ..Config::default() };
        let client = Client::new(Arc::new(cfg), make_transport, None, false).expect("client construction");

        let dial_ctx = CancellationToken::new();
        let conn = client.dial_stream_up(dial_ctx.clone()).await.expect("dial_stream_up");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let during = Arc::strong_count(&transport);
        assert!(during > baseline, "dialing must take at least one extra reference on the transport");

        conn.close().expect("close must not fail");
        drop(conn);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && Arc::strong_count(&transport) > baseline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            Arc::strong_count(&transport),
            baseline,
            "closing a stream-up session must cancel the upload task's request context and \
             release its transport reference within a bounded time, even when the transport's \
             own close is a no-op"
        );
    }

    #[tokio::test]
    async fn http1_close_clears_synchronously_then_redials() {
        let dial_count = Arc::new(AtomicUsize::new(0));
        let transport = Http1Transport::new(counting_dial_raw(Arc::clone(&dial_count)), passthrough_wrap_tls());

        transport.ensure_connected(CancellationToken::new()).await.expect("first dial succeeds");
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);

        force_close::RoundTripper::close(&transport);
        assert!(
            transport.send_request.try_lock().expect("uncontended lock").is_none(),
            "uncontended close() must clear send_request before returning"
        );

        transport.ensure_connected(CancellationToken::new()).await.expect("re-dial succeeds");
        assert_eq!(dial_count.load(Ordering::SeqCst), 2, "ensure_connected after close must re-dial");
    }

    #[tokio::test]
    async fn http2_packet_up_sends_upload_while_download_headers_are_pending() {
        const PAYLOAD: &[u8] = b"packet-up must not wait for download headers";
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_io = Arc::new(AsyncMutex::new(Some(client_io)));
        let dial_raw: DialRawFunc = Arc::new(move |_ctx| {
            let client_io = Arc::clone(&client_io);
            Box::pin(async move {
                let io = client_io.lock().await.take().expect("both requests must share one H2 connection");
                let conn: Box<dyn NetConn> = Box::new(DuplexConn(io));
                Ok(conn)
            })
        });
        let download_received = Arc::new(Notify::new());
        let upload_received = Arc::new(Notify::new());
        let server_download_received = Arc::clone(&download_received);
        let server = tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let download_received = Arc::clone(&server_download_received);
                let upload_received = Arc::clone(&upload_received);
                async move {
                    assert_eq!(req.method(), http::Method::GET);
                    let body = if let Some(seq) = req.headers().get("x-seq") {
                        assert_eq!(seq, "0");
                        let body = req.into_body().collect().await.expect("upload body").to_bytes();
                        assert_eq!(body.as_ref(), PAYLOAD);
                        upload_received.notify_one();
                        Bytes::new()
                    } else {
                        download_received.notify_one();
                        // A CDN may buffer download headers until upstream traffic produces data.
                        upload_received.notified().await;
                        Bytes::from_static(PAYLOAD)
                    };
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(http_body_util::Full::new(body)))
                }
            });
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server_io), service)
                .await
        });
        let transport: Arc<dyn RoundTripper> =
            Arc::new(Http2Transport::new(dial_raw, passthrough_wrap_tls(), Duration::ZERO));
        let make_transport: TransportMaker = Arc::new(move || Arc::clone(&transport));
        let cfg = Config {
            host: "example.com".to_owned(),
            path: "/xhttp".to_owned(),
            mode: "packet-up".to_owned(),
            uplink_http_method: "GET".to_owned(),
            seq_placement: "header".to_owned(),
            sc_min_posts_interval_ms: "1".to_owned(),
            ..Config::default()
        };
        let client = Client::new(Arc::new(cfg), make_transport, None, false).expect("client construction");
        // NOT cancel-safe: timeout abandons this session; the client and server are torn down below.
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let mut conn = client.dial_packet_up(CancellationToken::new()).await.expect("packet-up dial");
            download_received.notified().await;
            conn.write_all(PAYLOAD).await.expect("packet-up upload");
            let mut echoed = vec![0; PAYLOAD.len()];
            conn.read_exact(&mut echoed).await.expect("packet-up download");
            assert_eq!(echoed, PAYLOAD);
            conn.close().expect("close packet-up session");
        })
        .await;
        client.close().expect("close client");
        server.abort();
        let _ = server.await;
        result.expect("upload must complete before the server sends download headers on the same H2 connection");
    }

    #[tokio::test]
    async fn http2_close_clears_synchronously_then_redials() {
        let dial_count = Arc::new(AtomicUsize::new(0));
        let transport =
            Http2Transport::new(counting_dial_raw(Arc::clone(&dial_count)), passthrough_wrap_tls(), Duration::ZERO);

        transport.ensure_connected(CancellationToken::new()).await.expect("first dial succeeds");
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);

        force_close::RoundTripper::close(&transport);
        assert!(
            transport.send_request.try_lock().expect("uncontended lock").is_none(),
            "uncontended close() must clear send_request before returning"
        );

        transport.ensure_connected(CancellationToken::new()).await.expect("re-dial succeeds");
        assert_eq!(dial_count.load(Ordering::SeqCst), 2, "ensure_connected after close must re-dial");
    }

    #[tokio::test]
    async fn h3_close_makes_ensure_connected_and_round_trip_fail_closed() {
        let dial_quic: DialQuicFunc = Arc::new(|_ctx, _cfg| Box::pin(async { panic!("must not dial after close") }));
        let transport = H3Transport::new(dial_quic, Duration::from_secs(0), CONN_IDLE_TIMEOUT);

        force_close::RoundTripper::close(&transport);

        match transport.ensure_connected(CancellationToken::new()).await {
            Err(err) => assert_eq!(err.to_string(), "http3: transport is closed"),
            Ok(()) => panic!("closed transport must reject ensure_connected"),
        }

        match transport.round_trip(Request::default()).await {
            Err(err) => assert_eq!(err.to_string(), "http3: transport is closed"),
            Ok(_) => panic!("closed transport must reject round_trip"),
        }
    }

    #[tokio::test]
    async fn pool_close_during_in_flight_dial_closes_the_late_connection() {
        let gate = Arc::new(Notify::new());
        let dial_started = Arc::new(Notify::new());

        let gate_dial = Arc::clone(&gate);
        let started_dial = Arc::clone(&dial_started);
        let dial_raw: DialRawFunc = Arc::new(move |_ctx| {
            let gate = Arc::clone(&gate_dial);
            let started = Arc::clone(&started_dial);
            Box::pin(async move {
                started.notify_one();
                gate.notified().await;
                let (client, mut server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while matches!(server.read(&mut buf).await, Ok(n) if n > 0) {}
                });
                let conn: Box<dyn NetConn> = Box::new(DuplexConn(client));
                Ok(conn)
            })
        });

        let pool = Arc::new(Http1PoolTransport::new(dial_raw, passthrough_wrap_tls()));

        let pool_for_dial = Arc::clone(&pool);
        let dial_join = tokio::spawn(async move { pool_for_dial.pick_or_dial(CancellationToken::new(), false).await });

        dial_started.notified().await;
        force_close::RoundTripper::close(pool.as_ref());
        gate.notify_one();

        let conn = dial_join.await.expect("task join").expect("dial succeeds");
        assert!(
            conn.send_request.try_lock().expect("uncontended lock").is_none(),
            "a connection dialed while the pool was closing must not be left open"
        );
    }

    /// Regression test for a one-shot `closed` latch: once a pool closed, every subsequent
    /// `pick_or_dial` dialed a real connection and then immediately closed it again, forever,
    /// because the latch never cleared. Fails on the latch-based implementation (dials succeed but
    /// the pooled connection is dead on arrival, so `round_trip` fails "not connected"); passes
    /// once `close()` is tracked as a generation counter that only poisons dials in flight at the
    /// moment of that particular `close()` call.
    #[tokio::test]
    async fn pool_stays_usable_for_dials_after_a_past_close() {
        let pool = Http1PoolTransport::new(responding_dial_raw(), passthrough_wrap_tls());

        force_close::RoundTripper::close(&pool);

        pool.ensure_connected(CancellationToken::new()).await.expect("dial after a past close must succeed");

        let req = Request { method: "GET".to_owned(), ..Request::default() };
        let resp = pool
            .round_trip(req)
            .await
            .expect("round_trip on a connection dialed after a past close must not see a dead connection");
        assert_eq!(resp.status_code, 200);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deferred_pool_close_spares_a_connection_dialed_after_it() {
        let pool = Http1PoolTransport::new(responding_dial_raw(), passthrough_wrap_tls());

        let held = pool.conns.lock().await;
        force_close::RoundTripper::close(&pool);
        drop(held);

        let conn = pool.pick_or_dial(CancellationToken::new(), false).await.expect("dial after close");
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            conn.send_request.lock().await.is_some(),
            "the deferred sweep of an earlier close must not reach a connection dialed after it"
        );
    }
}

/// `download-settings` gives a session a second transport for its download leg
/// ([`Config::download_config`] plus the second [`TransportMaker`] `adapter/outbound/vless.rs`
/// builds beside it). `auto`, `stream-up` and `packet-up` spend it on an explicit
/// `GET /path/{session}`; `stream-one` issues one request in total, so its downloads are that
/// request's response body and the transport goes untouched.
///
/// `stream-one` never reaches the split case — the outbound config rejects that combination — so
/// that mode's split behaviour had no coverage here either. These tests build the split transport
/// directly against a real xhttp server.
#[cfg(test)]
mod download_split_tests {
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;

    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::config::ReuseConfig;
    use crate::server::{ConnHandler, Handler, RequestHandler, ServerOption};

    const HOST: &str = "example.com";
    const PATH: &str = "/xhttp";

    /// Where a mode's downloads come from, which is the one thing the four modes disagree about.
    #[derive(Clone, Copy, Debug)]
    enum DownloadLeg {
        /// `auto` / `stream-up` / `packet-up`.
        OwnConnection,
        UploadResponse,
    }

    fn download_leg(mode: &str) -> DownloadLeg {
        match mode {
            "stream-one" => DownloadLeg::UploadResponse,
            "auto" | "stream-up" | "packet-up" => DownloadLeg::OwnConnection,
            other => panic!("not an xhttp mode: {other}"),
        }
    }

    fn passthrough_wrap_tls() -> WrapTlsFunc {
        Arc::new(|_ctx, conn, _is_h2| Box::pin(async move { Ok(conn) }))
    }

    fn echo_conn_handler() -> ConnHandler {
        Arc::new(|mut conn: Box<dyn NetConn>| {
            Box::pin(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = conn.close();
            })
        })
    }

    fn mode_config(mode: &str) -> Config {
        Config { host: HOST.to_owned(), path: PATH.to_owned(), mode: mode.to_owned(), ..Config::default() }
    }

    fn reuse_config() -> ReuseConfig {
        ReuseConfig {
            max_connections: "0".to_owned(),
            max_concurrency: "16-32".to_owned(),
            c_max_reuse_times: "0".to_owned(),
            h_max_request_times: "600-900".to_owned(),
            h_max_reusable_secs: "1800-3000".to_owned(),
        }
    }

    async fn spawn_echo_server(mode: &str) -> SocketAddr {
        let handler = RequestHandler::new(ServerOption {
            config: mode_config(mode),
            conn_handler: Some(echo_conn_handler()),
            http_handler: None,
        })
        .expect("valid xhttp server config");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = hyper::service::service_fn(move |req| {
                        let handler = Arc::clone(&handler);
                        async move { Ok::<_, std::convert::Infallible>(handler.serve(req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });
        addr
    }

    /// Dialing this fails with `ECONNREFUSED` rather than hanging, so a transport pointed here
    /// is provably unusable and a dial that still succeeds proves that transport went unused.
    async fn unreachable_addr() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");
        drop(listener);
        addr
    }

    fn counting_transport(addr: SocketAddr) -> (TransportMaker, Arc<AtomicUsize>) {
        let dials = Arc::new(AtomicUsize::new(0));
        let dial_raw: DialRawFunc = {
            let dials = Arc::clone(&dials);
            Arc::new(move |_ctx| {
                let dials = Arc::clone(&dials);
                Box::pin(async move {
                    dials.fetch_add(1, Ordering::SeqCst);
                    let conn: Box<dyn NetConn> = Box::new(tokio::net::TcpStream::connect(addr).await?);
                    Ok(conn)
                })
            })
        };
        let maker: TransportMaker = Arc::new(move || {
            let transport: Arc<dyn RoundTripper> =
                Arc::new(Http1PoolTransport::new(Arc::clone(&dial_raw), passthrough_wrap_tls()));
            transport
        });
        (maker, dials)
    }

    /// `download_addr` is the only thing that varies, so the same builder can aim the download
    /// leg at the live server or at a dead port.
    fn new_split_client(
        mode: &str,
        reuse: bool,
        upload_addr: SocketAddr,
        download_addr: SocketAddr,
    ) -> anyhow::Result<(Client, Arc<AtomicUsize>, Arc<AtomicUsize>)> {
        let (make_transport, upload_dials) = counting_transport(upload_addr);
        let (make_download_transport, download_dials) = counting_transport(download_addr);

        let mut download_cfg = mode_config(mode);
        let mut cfg = mode_config(mode);
        if reuse {
            cfg.reuse_config = Some(Box::new(reuse_config()));
            download_cfg.reuse_config = Some(Box::new(reuse_config()));
        }
        cfg.download_config = Some(Box::new(download_cfg));

        let client = Client::new(Arc::new(cfg), make_transport, Some(make_download_transport), false)?;
        Ok((client, upload_dials, download_dials))
    }

    fn probe_payload() -> Vec<u8> {
        (0..4096u32).map(|i| (i % 251) as u8).collect()
    }

    async fn assert_round_trips(mode: &str, reuse: bool, conn: &mut Box<dyn NetConn>) {
        let payload = probe_payload();
        conn.write_all(&payload).await.unwrap_or_else(|err| panic!("mode={mode} reuse={reuse} upload: {err}"));

        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(20), conn.read_exact(&mut echoed))
            .await
            .unwrap_or_else(|_| panic!("mode={mode} reuse={reuse} download never completed"))
            .unwrap_or_else(|err| panic!("mode={mode} reuse={reuse} download: {err}"));
        assert_eq!(echoed, payload, "mode={mode} reuse={reuse}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn download_settings_split_connection_round_trips_in_every_mode() {
        for reuse in [false, true] {
            for mode in ["auto", "stream-one", "stream-up", "packet-up"] {
                let server_addr = spawn_echo_server(mode).await;
                let (client, upload_dials, download_dials) =
                    new_split_client(mode, reuse, server_addr, server_addr).expect("client construction");

                let mut conn = client
                    .dial(CancellationToken::new())
                    .await
                    .unwrap_or_else(|err| panic!("mode={mode} reuse={reuse} dial: {err}"));
                assert_round_trips(mode, reuse, &mut conn).await;

                assert!(
                    upload_dials.load(Ordering::SeqCst) >= 1,
                    "mode={mode} reuse={reuse}: uploads need their own connection"
                );
                let downloads = download_dials.load(Ordering::SeqCst);
                match download_leg(mode) {
                    DownloadLeg::OwnConnection => assert!(
                        downloads >= 1,
                        "mode={mode} reuse={reuse}: the session download must ride the separate download connection"
                    ),
                    DownloadLeg::UploadResponse => assert_eq!(
                        downloads, 0,
                        "mode={mode} reuse={reuse}: stream-one's only request is the upload, so its downloads ride that \
                         response and the download transport must stay undialed"
                    ),
                }

                let _ = conn.close();
                client.close().expect("client close");
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_unusable_download_connection_only_breaks_the_modes_that_use_it() {
        let dead_addr = unreachable_addr().await;
        for reuse in [false, true] {
            for mode in ["auto", "stream-one", "stream-up", "packet-up"] {
                let server_addr = spawn_echo_server(mode).await;
                let (client, upload_dials, download_dials) =
                    new_split_client(mode, reuse, server_addr, dead_addr).expect("client construction");

                let dialed = client.dial(CancellationToken::new()).await;
                match download_leg(mode) {
                    DownloadLeg::OwnConnection => {
                        assert!(
                            dialed.is_err(),
                            "mode={mode} reuse={reuse}: a download transport that cannot connect must fail the dial"
                        );
                        assert!(
                            download_dials.load(Ordering::SeqCst) >= 1,
                            "mode={mode} reuse={reuse}: the dead address was only ever handed to the download transport"
                        );
                    }
                    DownloadLeg::UploadResponse => {
                        let mut conn = dialed.unwrap_or_else(|err| {
                            panic!("mode={mode} reuse={reuse}: stream-one must not depend on the download transport: {err}")
                        });
                        assert_round_trips(mode, reuse, &mut conn).await;
                        assert!(
                            upload_dials.load(Ordering::SeqCst) >= 1,
                            "mode={mode} reuse={reuse}: stream-one dials for its upload"
                        );
                        assert_eq!(
                            download_dials.load(Ordering::SeqCst),
                            0,
                            "mode={mode} reuse={reuse}: stream-one must not dial the download transport"
                        );
                        let _ = conn.close();
                    }
                }

                client.close().expect("client close");
            }
        }
    }
}

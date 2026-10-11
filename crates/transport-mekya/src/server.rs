//! This crate's server does its own request/response streaming.
//!
//! It drives `hyper-util`'s auto (h1/h2c) connection builder over each accepted transport
//! connection and streams the long-poll response through a small local `hyper::body::Body` impl
//! backed by an `mpsc` channel (`http_body_util::channel` needs the crate's `channel` Cargo
//! feature, which is not enabled). Closing cannot block until the accept loop has fully drained:
//! `close` cancels the shared token and closes the owned resources instead.
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use dashmap::{DashMap, Entry};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use murmur_std_compat::net::{Addr, Conn as NetConn, Listener as NetListener, PacketConn as NetPacketConn, TcpAddr};
use murmur_transport_mkcp as mkcp;

use super::bundle::{read_packet_bundle_sync, write_packet_bundle};
use super::config::Config;
use super::packetconn::{new_wrapped_packet_conn, SharedPacketConn, WrappedPacketConn};

type ResponseBody = BoxBody<Bytes, Infallible>;

/// The floor for a session's idle timeout; a live client re-POSTs at least once per long-poll
/// cycle, so only a client that has stopped talking entirely is ever idle this long.
const MIN_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// How often the reaper sweeps the session table.
const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// The bound on live sessions per listener; past it the least recently active session is evicted.
const MAX_SESSIONS: usize = 8192;

/// The bound on the decoded session id, so the map key cannot be a whole header value.
const MAX_SESSION_ID_LEN: usize = 64;

/// Why a client-supplied session id was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionIdRejection {
    Malformed,
    TooLong,
}

/// Decodes the `X-Session-ID` header, enforcing the length bound on the map key it becomes.
fn decode_session_id(header: &str) -> Result<Vec<u8>, SessionIdRejection> {
    let Ok(session_id) = URL_SAFE_NO_PAD.decode(header) else {
        return Err(SessionIdRejection::Malformed);
    };
    if session_id.len() > MAX_SESSION_ID_LEN {
        return Err(SessionIdRejection::TooLong);
    }
    Ok(session_id)
}

/// Stands in for `http_body_util::channel::Channel` (its `channel` Cargo feature is not enabled
/// for this crate): a `hyper::body::Body` that yields whatever `Bytes` chunks arrive on an `mpsc`
/// channel, ending the body when the sender drops.
struct ChannelBody {
    rx: mpsc::Receiver<Bytes>,
}

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        self.rx.poll_recv(cx).map(|chunk| chunk.map(|chunk| Ok(hyper::body::Frame::data(chunk))))
    }
}

fn channel_body(buffer: usize) -> (mpsc::Sender<Bytes>, ChannelBody) {
    let (tx, rx) = mpsc::channel(buffer);
    (tx, ChannelBody { rx })
}

fn text_response(status: StatusCode, message: &str) -> Response<ResponseBody> {
    let body = Full::new(Bytes::from(format!("{message}\n"))).boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

pub struct Listener {
    inner: Arc<ListenerInner>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("shutdown", &self.inner.shutdown)
            .field("closed", &self.inner.closed)
            .finish_non_exhaustive()
    }
}

struct ListenerInner {
    outer: Box<dyn NetListener>,
    packet_conn: Arc<WrappedPacketConn>,
    mkcp: mkcp::listener::Listener,
    shutdown: CancellationToken,
    closed: AtomicBool,
}

pub async fn listen(ctx: &CancellationToken, ln: Box<dyn NetListener>, cfg: Config) -> anyhow::Result<Listener> {
    let local: Arc<dyn Addr> = Arc::from(ln.addr()?);
    let shutdown = ctx.child_token();
    let packet_conn = new_wrapped_packet_conn(&shutdown, local);
    let server = new_server(shutdown.clone(), cfg.clone(), Arc::clone(&packet_conn));
    tokio::spawn(Arc::clone(&server).reap_idle_sessions());
    let shared_packet_conn = SharedPacketConn(Arc::clone(&packet_conn));
    let mkcp_listener = mkcp::listener::listen(&shutdown, Box::new(shared_packet_conn), cfg.kcp.clone()).await?;

    let inner = Arc::new(ListenerInner {
        outer: ln,
        packet_conn,
        mkcp: mkcp_listener,
        shutdown,
        closed: AtomicBool::new(false),
    });
    let listener = Listener { inner: Arc::clone(&inner) };

    let accept_loop_listener = Listener { inner: Arc::clone(&inner) };
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = inner.shutdown.cancelled() => break,
                accepted = inner.outer.accept() => {
                    let Ok(conn) = accepted else { break };
                    spawn_connection(Arc::clone(&server), conn);
                }
            }
        }
        let _ = accept_loop_listener.close();
    });

    Ok(listener)
}

fn spawn_connection(server: Arc<Server>, conn: Box<dyn NetConn>) {
    let remote_addr = conn
        .remote_addr()
        .ok()
        .and_then(|addr| match murmur_std_compat::net::sock_addr_of(addr.as_ref()) {
            Some(murmur_std_compat::net::SockAddr::Tcp(tcp)) => Some(tcp),
            _ => None,
        })
        .unwrap_or_else(|| TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    tokio::spawn(async move {
        let io = TokioIo::new(conn);
        let svc = service_fn(move |req: Request<Incoming>| {
            let server = Arc::clone(&server);
            let remote_addr = remote_addr;
            async move { Ok::<_, Infallible>(server.serve_http(req, remote_addr).await) }
        });
        let builder = auto::Builder::new(TokioExecutor::new());
        let _ = builder.serve_connection(io, svc).await;
    });
}

#[async_trait]
impl NetListener for Listener {
    // cancel-safe: forwards to the wrapped acceptor and only boxes the result, so a dropped call leaves the inner listener as it was.
    async fn accept(&self) -> io::Result<Box<dyn NetConn>> {
        self.inner.mkcp.accept().await
    }

    fn close(&self) -> io::Result<()> {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.inner.shutdown.cancel();
        let mkcp_result = self.inner.mkcp.close();
        let packet_conn_result = self.inner.packet_conn.close();
        let outer_result = self.inner.outer.close();
        mkcp_result.and(packet_conn_result).and(outer_result)
    }

    fn addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.outer.addr()
    }
}

#[derive(Debug)]
struct Server {
    ctx: CancellationToken,
    cfg: Config,
    packet_conn: Arc<WrappedPacketConn>,
    sessions: DashMap<Vec<u8>, Arc<ServerSession>>,
    max_sessions: usize,
}

fn new_server(ctx: CancellationToken, cfg: Config, packet_conn: Arc<WrappedPacketConn>) -> Arc<Server> {
    new_server_with_max_sessions(ctx, cfg, packet_conn, MAX_SESSIONS)
}

fn new_server_with_max_sessions(
    ctx: CancellationToken,
    cfg: Config,
    packet_conn: Arc<WrappedPacketConn>,
    max_sessions: usize,
) -> Arc<Server> {
    Arc::new(Server { ctx, cfg, packet_conn, sessions: DashMap::new(), max_sessions })
}

impl Server {
    async fn serve_http(self: Arc<Self>, req: Request<Incoming>, remote_addr: TcpAddr) -> Response<ResponseBody> {
        let session_id_header = req.headers().get("X-Session-ID").and_then(|v| v.to_str().ok()).unwrap_or("");
        let session_id = match decode_session_id(session_id_header) {
            Ok(session_id) => session_id,
            Err(SessionIdRejection::Malformed) => return text_response(StatusCode::BAD_REQUEST, "invalid session id"),
            Err(SessionIdRejection::TooLong) => {
                return text_response(StatusCode::BAD_REQUEST, "session id too long");
            }
        };
        let body = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => return text_response(StatusCode::BAD_REQUEST, &err.to_string()),
        };
        let session = match self.get_session(&session_id, remote_addr) {
            Ok(session) => session,
            Err(err) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        };
        if let Err(err) = session.ingest(&body).await {
            return text_response(StatusCode::BAD_REQUEST, &err.to_string());
        }

        let (tx, response_body) = channel_body(16);
        let ctx = self.ctx.clone();
        tokio::spawn(async move { session.write_response(&ctx, tx).await });
        let mut response = Response::new(response_body.boxed());
        *response.status_mut() = StatusCode::OK;
        response
    }

    fn get_session(self: &Arc<Self>, session_id: &[u8], remote_addr: TcpAddr) -> anyhow::Result<Arc<ServerSession>> {
        if let Some(existing) = self.sessions.get(session_id) {
            return Ok(Arc::clone(&existing));
        }
        if self.sessions.len() >= self.max_sessions {
            self.evict_least_recently_active();
        }
        let session_ctx = self.ctx.child_token();
        let session = Arc::new(ServerSession::new(session_ctx, session_id.to_owned(), remote_addr, Arc::clone(self)));
        match self.sessions.entry(session_id.to_owned()) {
            Entry::Occupied(entry) => Ok(Arc::clone(entry.get())),
            Entry::Vacant(entry) => {
                entry.insert(Arc::clone(&session));
                if let Err(err) = self.packet_conn.add_session(Arc::clone(&session)) {
                    self.sessions.remove(session_id);
                    return Err(err.into());
                }
                Ok(session)
            }
        }
    }

    /// Removes `session_id` only while it still maps to `session`: an evicted session's later
    /// `close` must not remove the replacement a client created under the same id meanwhile.
    fn remove_session_if(&self, session_id: &[u8], session: &Arc<ServerSession>) {
        self.sessions.remove_if(session_id, |_, stored| Arc::ptr_eq(stored, session));
    }

    /// Evicts the session that has been quiet the longest, so a full table keeps serving new
    /// clients instead of refusing them; an abandoned session is the quietest one.
    fn evict_least_recently_active(&self) {
        let victim = self
            .sessions
            .iter()
            .min_by_key(|entry| entry.value().last_activity())
            .map(|entry| Arc::clone(entry.value()));
        if let Some(victim) = victim {
            victim.close();
        }
    }

    /// Closes every session idle past its own timeout.
    fn sweep_idle_sessions(&self) {
        let now = Instant::now();
        let expired: Vec<Arc<ServerSession>> = self
            .sessions
            .iter()
            .filter(|entry| now.duration_since(entry.value().last_activity()) >= entry.value().idle_timeout())
            .map(|entry| Arc::clone(entry.value()))
            .collect();
        for session in expired {
            session.close();
        }
    }

    async fn reap_idle_sessions(self: Arc<Self>) {
        loop {
            tokio::select! {
                () = self.ctx.cancelled() => return,
                () = tokio::time::sleep(SESSION_SWEEP_INTERVAL) => self.sweep_idle_sessions(),
            }
        }
    }
}

/// A single-item-per-receive multi-consumer queue: however many `write_response` tasks a session
/// has open concurrently, each gets its own share. A send handed to an already-blocked receiver
/// (chosen FIFO) bypasses the buffer entirely, so it can never be stolen by another receiver.
/// `tokio::sync::mpsc::Receiver` has exactly one consumer, so serializing concurrent
/// write-response tasks behind a `Mutex<Receiver>` starves every task but the lock holder for
/// that holder's entire `max_write_duration`. A plain shared `VecDeque` drained by whichever
/// waiter wakes first does not reproduce the guarantee either: the write-response loop calls
/// `recv` again immediately after every delivery, so a waiter that happens to be scheduled first
/// can drain several queued packets on successive loop iterations before a different,
/// already-notified waiter ever gets polled — reproduced by
/// `tests::concurrent_write_responses_all_receive_packets` below (`left: 1`..`4` against `right:
/// 5` under a burst of `CONCURRENT` back-to-back pushes with `CONCURRENT` waiters already parked).
///
/// This instead gates every dequeue behind a [`tokio::sync::Semaphore`] permit, one added per
/// pushed item: `Semaphore::acquire` is documented FIFO-fair (waiters are granted permits in the
/// order they called `acquire`, preventing starvation) and self-dequeuing on cancellation (a
/// cancelled `acquire` loses its queue position without leaving any state behind for `try_push`
/// to skip over), so it reproduces the direct-handoff fairness without the per-call allocation
/// and manual cleanup a one-shot-per-waiter scheme would need — `review_stress` below covers both
/// the fairness (`stress_single_recv_waiters_vs_pushers`) and cancellation-heavy-throughput
/// (`stress_cancelled_waiters_exactly_once`) properties this depends on.
#[derive(Debug)]
struct WriterQueue {
    queue: Mutex<VecDeque<Vec<u8>>>,
    permits: tokio::sync::Semaphore,
    capacity: usize,
    parked: std::sync::atomic::AtomicUsize,
}

impl WriterQueue {
    fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            permits: tokio::sync::Semaphore::new(0),
            capacity,
            parked: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// A buffered send succeeds either while the buffer has room or while a receiver is already
    /// parked, since the value then goes straight to that receiver without touching the buffer.
    /// `parked` mirrors the second half of that rule: a push already handed to a waiter
    /// (via the permit `recv` is about to consume) must not also count against `capacity`, or a
    /// burst of sends with several long-polls already open drops everything past the first one.
    fn try_push(&self, packet: Vec<u8>) {
        let mut queue = self.queue.lock();
        let parked = self.parked.load(Ordering::SeqCst);
        if queue.len() < self.capacity + parked {
            queue.push_back(packet);
            drop(queue);
            self.permits.add_permits(1);
        }
    }

    /// A receive blocks until a packet is pushed. `parked` counts callers that have started waiting on
    /// `acquire()`; it is a lower bound, not proof every one of them is already enqueued in the
    /// semaphore's wait list, but `Semaphore::add_permits` buffers permits for however many have
    /// not reached `acquire` yet, so a push that lands just ahead of a waiter's registration still
    /// reaches it once that waiter calls `acquire`, rather than being lost. The guard decrements
    /// on every exit path, including a `select!` cancelling this future before `acquire` resolves,
    /// so a cancelled waiter never keeps inflating `try_push`'s admitted capacity.
    #[expect(
        clippy::expect_used,
        reason = "the semaphore is never closed and every granted permit corresponds to one queued item"
    )]
    // cancel-safe: takes its item from a queue/channel, so a dropped call leaves the item queued for the next one.
    async fn recv(&self) -> Vec<u8> {
        struct ParkedGuard<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for ParkedGuard<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        self.parked.fetch_add(1, Ordering::SeqCst);
        let _guard = ParkedGuard(&self.parked);
        self.permits.acquire().await.expect("writer queue semaphore is never closed").forget();
        self.queue.lock().pop_front().expect("a granted permit guarantees a queued item")
    }

    #[cfg(test)]
    fn parked_count(&self) -> usize {
        self.parked.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
struct WritingConnection {
    token: CancellationToken,
}

#[derive(Debug)]
pub(crate) struct ServerSession {
    ctx: CancellationToken,
    session_id: Vec<u8>,
    remote_addr: TcpAddr,
    server: Arc<Server>,
    writer_queue: WriterQueue,
    reader_tx: mpsc::Sender<Vec<u8>>,
    reader_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    max_write_size: i64,
    max_write_duration: Duration,
    max_simultaneous_write_connection: i64,
    writing_conns: Mutex<Vec<Arc<WritingConnection>>>,
    last_activity: Mutex<Instant>,
    idle_timeout: Duration,
}

fn err_context_canceled() -> io::Error {
    io::Error::other("context canceled")
}

impl ServerSession {
    fn new(ctx: CancellationToken, session_id: Vec<u8>, remote_addr: TcpAddr, server: Arc<Server>) -> Self {
        let writer_buffer = usize::try_from(server.cfg.packet_writing_buffer.max(1)).unwrap_or(1);
        let (reader_tx, reader_rx) = mpsc::channel(256);
        let max_write_duration_ms = server.cfg.max_write_duration_ms.max(0).cast_unsigned();
        let max_write_duration = Duration::from_millis(max_write_duration_ms);
        Self {
            ctx,
            session_id,
            remote_addr,
            max_write_size: server.cfg.max_write_size,
            max_write_duration,
            max_simultaneous_write_connection: server.cfg.max_simultaneous_write_connection,
            server,
            writer_queue: WriterQueue::new(writer_buffer),
            reader_tx,
            reader_rx: tokio::sync::Mutex::new(reader_rx),
            writing_conns: Mutex::new(Vec::new()),
            last_activity: Mutex::new(Instant::now()),
            idle_timeout: max_write_duration.saturating_mul(2).max(MIN_SESSION_IDLE_TIMEOUT),
        }
    }

    pub(crate) fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// The last traffic on this session, for the idle sweep.
    fn last_activity(&self) -> Instant {
        *self.last_activity.lock()
    }

    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    fn touch(&self) {
        *self.last_activity.lock() = Instant::now();
    }

    async fn ingest(&self, body: &[u8]) -> anyhow::Result<()> {
        self.touch();
        let mut reader = body;
        while !reader.is_empty() {
            let packet = read_packet_bundle_sync(&mut reader)?;
            tokio::select! {
                () = self.ctx.cancelled() => return Err(anyhow::anyhow!("context canceled")),
                result = self.reader_tx.send(packet) => {
                    result.map_err(|_| anyhow::anyhow!("context canceled"))?;
                }
            }
        }
        Ok(())
    }

    fn begin_writing_connection(&self, parent_ctx: &CancellationToken) -> (Arc<WritingConnection>, CancellationToken) {
        let write_ctx = parent_ctx.child_token();
        let conn = Arc::new(WritingConnection { token: write_ctx.clone() });
        let mut stale = Vec::new();
        {
            let mut writing = self.writing_conns.lock();
            writing.push(Arc::clone(&conn));
            if self.max_simultaneous_write_connection > 0 {
                while i64::try_from(writing.len()).unwrap_or(i64::MAX) > self.max_simultaneous_write_connection {
                    stale.push(writing.remove(0));
                }
            }
            drop(writing);
        }
        for old in stale {
            old.token.cancel();
        }
        (conn, write_ctx)
    }

    fn finish_writing_connection(&self, conn: &Arc<WritingConnection>) {
        conn.token.cancel();
        let mut writing = self.writing_conns.lock();
        if let Some(pos) = writing.iter().position(|item| Arc::ptr_eq(item, conn)) {
            writing.remove(pos);
        }
    }

    async fn write_response(self: Arc<Self>, ctx: &CancellationToken, tx: mpsc::Sender<Bytes>) {
        let (write_conn, write_ctx) = self.begin_writing_connection(ctx);
        let mut bytes_sent: i64 = 0;
        let sleep = tokio::time::sleep(self.max_write_duration);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                () = write_ctx.cancelled() => break,
                () = self.ctx.cancelled() => break,
                () = &mut sleep => break,
                packet = self.writer_queue.recv() => {
                    let mut buf = Vec::new();
                    if write_packet_bundle(&mut buf, &packet).is_err() {
                        break;
                    }
                    let frame_len = i64::try_from(buf.len()).unwrap_or(i64::MAX);
                    if tx.send(Bytes::from(buf)).await.is_err() {
                        break;
                    }
                    bytes_sent += frame_len;
                    if self.max_write_size > 0 && bytes_sent >= self.max_write_size {
                        break;
                    }
                }
            }
        }
        self.finish_writing_connection(&write_conn);
    }

    pub(crate) async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut reader_rx = self.reader_rx.lock().await;
        let result = tokio::select! {
            () = self.ctx.cancelled() => Err(err_context_canceled()),
            packet = reader_rx.recv() => match packet {
                Some(packet) => {
                    let n = buf.len().min(packet.len());
                    let (dst, _) = buf.split_at_mut(n);
                    let (src, _) = packet.split_at(n);
                    dst.copy_from_slice(src);
                    Ok(n)
                }
                None => Err(err_context_canceled()),
            }
        };
        drop(reader_rx);
        result
    }

    #[expect(
        clippy::unused_async,
        reason = "the session's I/O surface is awaited by its callers, matching the async `read` next to it"
    )]
    pub(crate) async fn write(&self, p: &[u8]) -> io::Result<usize> {
        if self.ctx.is_cancelled() {
            return Err(err_context_canceled());
        }
        self.touch();
        self.writer_queue.try_push(p.to_vec());
        Ok(p.len())
    }

    pub(crate) fn close(self: &Arc<Self>) {
        self.server.remove_session_if(&self.session_id, self);
        self.server.packet_conn.remove_session_if(&self.session_id, self);
        self.ctx.cancel();
    }
}

impl Addr for ServerSession {
    fn network(&self) -> &str {
        self.remote_addr.network()
    }

    fn string(&self) -> String {
        self.remote_addr.string()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use murmur_std_compat::net::TcpAddr;

    fn test_config() -> Config {
        Config {
            max_write_size: 0,
            max_write_duration_ms: 5000,
            max_simultaneous_write_connection: 16,
            packet_writing_buffer: 64,
            ..Config::default()
        }
    }

    /// Regression test for the starvation this module's `WriterQueue` replaces: the old
    /// `Mutex<mpsc::Receiver<Vec<u8>>>` gave one `write_response` call exclusive access to the
    /// packet stream until it returned, so with several long-poll requests concurrently open for
    /// one session, whichever call grabbed the lock first kept it — since nothing here ever hits
    /// `max_write_size` or times out on its own, the old code let a single winner drain every
    /// packet while the rest sat blocked on `.lock().await`, never even reaching their own select
    /// loop until this test cancels them. This queue has no such bottleneck: any number of tasks
    /// can wait on it concurrently, so each gets a share.
    ///
    /// Waits for `WriterQueue::parked_count()` to reach `CONCURRENT` instead of sleeping a fixed
    /// duration: under heavy scheduler contention a short sleep is not long enough for every
    /// spawned task to reach its first `.await`, so a packet pushed too early only has a subset
    /// of the intended waiters to reach — flaky under load (`left: 4, right: 5`) though
    /// `WriterQueue::recv`'s own delivery was not at fault (`review_stress` below covers that
    /// class of bug directly, 0 stranded/lost across tens of thousands of rounds). The gate is a
    /// lower bound rather than a hard proof that every waiter is enqueued in the semaphore's wait
    /// list yet, but that is harmless here: `Semaphore::add_permits` buffers a permit for however
    /// many callers have not reached `acquire` yet (unlike the single-slot permit a bare `Notify`
    /// would buffer), so a push landing just ahead of a waiter's registration still reaches it
    /// once that waiter calls `acquire`, rather than being lost.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_write_responses_all_receive_packets() {
        let ctx = CancellationToken::new();
        let local: Arc<dyn Addr> = Arc::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        let packet_conn = new_wrapped_packet_conn(&ctx, local);
        let server = new_server(ctx.clone(), test_config(), packet_conn);
        let remote_addr = TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let session = server.get_session(&[1, 2, 3], remote_addr).expect("get_session");

        const CONCURRENT: usize = 5;
        let req_ctx = CancellationToken::new();
        let mut handles = Vec::with_capacity(CONCURRENT);
        let mut receivers = Vec::with_capacity(CONCURRENT);
        for _ in 0..CONCURRENT {
            let session = Arc::clone(&session);
            let req_ctx = req_ctx.clone();
            let (tx, rx) = mpsc::channel::<Bytes>(16);
            receivers.push(rx);
            handles.push(tokio::spawn(async move {
                session.write_response(&req_ctx, tx).await;
            }));
        }

        while session.writer_queue.parked_count() < CONCURRENT {
            tokio::task::yield_now().await;
        }
        for i in 0..CONCURRENT {
            session.write(&[i as u8]).await.expect("write");
        }

        // Read every `rx` concurrently under a single overall timeout instead of racing
        // `req_ctx.cancel()` against a task's own wakeup: `write_response` only returns once its
        // `write_ctx` is cancelled, so cancelling before delivery is confirmed would make its
        // `tokio::select!` race a now-ready cancellation branch against an already-signalled but
        // not-yet-polled `recv()` — `select!` picks pseudo-randomly between two ready branches, so
        // that race (not `WriterQueue`, covered by `review_stress` below) produced `left: 2` after
        // removing this test's original fixed sleep before cancelling. Polling all five
        // `rx.recv()` futures together, rather than one at a time behind its own short timeout,
        // also keeps a scheduler stall on one task from starving the budget the others need.
        let all_received = tokio::time::timeout(
            Duration::from_secs(30),
            futures::future::join_all(receivers.iter_mut().map(mpsc::Receiver::recv)),
        )
        .await
        .unwrap_or_default();
        let received = all_received.iter().filter(|packet| packet.is_some()).count();
        req_ctx.cancel();
        for handle in handles {
            handle.await.expect("task");
        }
        assert_eq!(received, CONCURRENT, "every concurrently open long-poll response must get a packet");
    }

    #[tokio::test(start_paused = true)]
    async fn an_abandoned_session_is_evicted_once_it_is_idle() {
        let ctx = CancellationToken::new();
        let local: Arc<dyn Addr> = Arc::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        let packet_conn = new_wrapped_packet_conn(&ctx, local);
        let server = new_server(ctx.clone(), test_config(), Arc::clone(&packet_conn));
        let remote_addr = TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let session = server.get_session(&[9, 9, 9], remote_addr).expect("get_session");
        assert_eq!(server.sessions.len(), 1);
        assert_eq!(packet_conn.session_count(), 1);

        tokio::spawn(Arc::clone(&server).reap_idle_sessions());
        tokio::time::sleep(session.idle_timeout() + SESSION_SWEEP_INTERVAL * 2).await;

        assert!(server.sessions.is_empty(), "an abandoned session must leave the server's table");
        assert_eq!(packet_conn.session_count(), 0, "an abandoned session must leave the packet conn's table");
        assert!(session.write(&[1]).await.is_err(), "a reaped session must be closed");
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_that_keeps_polling_survives_the_idle_sweep() {
        let ctx = CancellationToken::new();
        let local: Arc<dyn Addr> = Arc::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        let packet_conn = new_wrapped_packet_conn(&ctx, local);
        let server = new_server(ctx.clone(), test_config(), Arc::clone(&packet_conn));
        let remote_addr = TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let session = server.get_session(&[5], remote_addr).expect("get_session");

        let half = session.idle_timeout() / 2;
        for _ in 0..3 {
            tokio::time::advance(half).await;
            session.ingest(&[]).await.expect("ingest");
            server.sweep_idle_sessions();
            assert_eq!(server.sessions.len(), 1, "a session that keeps polling must survive the sweep");
        }

        tokio::time::advance(session.idle_timeout()).await;
        server.sweep_idle_sessions();
        assert!(server.sessions.is_empty(), "the sweep must reap the session once its traffic stops");
        assert_eq!(packet_conn.session_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_session_table_evicts_the_least_recently_active_session() {
        const CAP: usize = 3;
        let ctx = CancellationToken::new();
        let local: Arc<dyn Addr> = Arc::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        let packet_conn = new_wrapped_packet_conn(&ctx, local);
        let server = new_server_with_max_sessions(ctx.clone(), test_config(), Arc::clone(&packet_conn), CAP);
        let remote_addr = TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let ids: Vec<Vec<u8>> = vec![vec![0], vec![1], vec![2]];
        for id in &ids {
            server.get_session(id, remote_addr).expect("get_session");
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert_eq!(server.sessions.len(), CAP);
        assert_eq!(packet_conn.session_count(), CAP);

        let newest = vec![9u8, 9];
        server.get_session(&newest, remote_addr).expect("get_session");
        assert_eq!(server.sessions.len(), CAP, "the table must stay at its cap");
        assert!(!server.sessions.contains_key(&ids[0]), "the least recently active session must be evicted");
        assert!(server.sessions.contains_key(&newest));
        assert_eq!(packet_conn.session_count(), CAP, "the evicted session must leave the packet conn's table too");
    }

    #[tokio::test(start_paused = true)]
    async fn closing_an_evicted_session_leaves_its_replacement_with_the_same_id() {
        let ctx = CancellationToken::new();
        let local: Arc<dyn Addr> = Arc::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        let packet_conn = new_wrapped_packet_conn(&ctx, local);
        let server = new_server(ctx.clone(), test_config(), Arc::clone(&packet_conn));
        let remote_addr = TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let id = vec![4u8, 2];

        let first = server.get_session(&id, remote_addr).expect("get_session");
        first.close();
        assert!(server.sessions.is_empty());
        let second = server.get_session(&id, remote_addr).expect("get_session");
        first.close();

        assert_eq!(server.sessions.len(), 1, "a stale close must not remove the replacement session");
        assert!(Arc::ptr_eq(&second, server.sessions.get(&id).expect("replacement").value()));
        assert_eq!(packet_conn.session_count(), 1, "the replacement must stay in the packet conn's table");
    }

    #[test]
    fn an_over_long_session_id_is_rejected_before_it_becomes_a_session_key() {
        assert_eq!(decode_session_id("%%%"), Err(SessionIdRejection::Malformed));

        let at_bound = URL_SAFE_NO_PAD.encode(vec![0u8; MAX_SESSION_ID_LEN]);
        assert!(decode_session_id(&at_bound).is_ok(), "an id at the bound is still accepted");

        let too_long = URL_SAFE_NO_PAD.encode(vec![0u8; MAX_SESSION_ID_LEN + 1]);
        assert_eq!(decode_session_id(&too_long), Err(SessionIdRejection::TooLong));

        let client_id = URL_SAFE_NO_PAD.encode(vec![0u8; 16]);
        assert_eq!(decode_session_id(&client_id).expect("the client's own id"), vec![0u8; 16]);
    }
}

/// Regression coverage for `WriterQueue`'s cross-core fairness and cancellation-heavy throughput.
/// `stress_single_recv_waiters_vs_pushers` uses real OS threads (their own `current_thread`
/// runtimes, so genuine cross-core parallelism, not cooperative scheduling within one
/// multi-threaded runtime) plus `spin_loop` jitter to scatter push timing across the round, and
/// checks that a pushed packet never sits in `queue` once every waiter has stopped waiting.
/// `stress_cancelled_waiters_exactly_once` covers the throughput property the
/// [`tokio::sync::Semaphore`]-based design depends on: a waiter repeatedly parked then cancelled
/// (as `write_response`'s `select!` does on every idle tick) must not leave any state behind for
/// `try_push` to scan past, since `Semaphore::acquire` self-dequeues on cancellation.
#[cfg(test)]
mod review_stress {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    use super::WriterQueue;

    /// tokio's `Timeout` always polls the wrapped future before checking whether the deadline
    /// has passed (documented on [`tokio::time::timeout`]), so a receiver thread that the OS
    /// finally schedules well past its nominal bound still succeeds immediately if a permit is
    /// already sitting there — a late wakeup alone can never manufacture a false "timed out"
    /// here. A real stranding therefore needs a pusher thread's own `try_push` to still be
    /// unscheduled by the time every receiver's single poll has already run and given up, which
    /// under 8-way-parallel host contention (this stress test run alongside 7 copies of itself
    /// plus a CPU burner) can push both sides' OS scheduling latency well past a few tens of
    /// milliseconds even though the semaphore itself never drops a permit. Two seconds absorbs
    /// that scheduling noise; a `WriterQueue` that genuinely lost a permit would still fail this
    /// assertion regardless of how generous the bound is, since the channel-shaped guarantee
    /// (and this design's `Semaphore`) never manufactures a delivery unprompted.
    #[test]
    fn stress_single_recv_waiters_vs_pushers() {
        const W: usize = 4;
        const P: usize = 4;
        const ROUNDS: usize = 20000;
        let q = Arc::new(WriterQueue::new(1 << 20));
        let start = Arc::new(Barrier::new(W + P + 1));
        let end = Arc::new(Barrier::new(W + P + 1));
        let ok = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();
        for _ in 0..W {
            let (q, start, end, ok) = (Arc::clone(&q), Arc::clone(&start), Arc::clone(&end), Arc::clone(&ok));
            threads.push(std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                for _ in 0..ROUNDS {
                    start.wait();
                    if rt.block_on(async { tokio::time::timeout(Duration::from_secs(2), q.recv()).await }).is_ok() {
                        ok.fetch_add(1, Ordering::SeqCst);
                    }
                    end.wait();
                }
            }));
        }
        for p in 0..P {
            let (q, start, end) = (Arc::clone(&q), Arc::clone(&start), Arc::clone(&end));
            threads.push(std::thread::spawn(move || {
                for r in 0..ROUNDS {
                    start.wait();
                    for _ in 0..((r * 7 + p * 13) % 64) {
                        std::hint::spin_loop();
                    }
                    q.try_push(vec![p as u8]);
                    end.wait();
                }
            }));
        }
        let mut stranded_rounds = 0;
        for _ in 0..ROUNDS {
            ok.store(0, Ordering::SeqCst);
            start.wait();
            end.wait();
            let got = ok.load(Ordering::SeqCst);
            let mut queue = q.queue.lock();
            if got < W && !queue.is_empty() {
                stranded_rounds += 1;
            }
            queue.clear();
            while let Ok(permit) = q.permits.try_acquire() {
                permit.forget();
            }
        }
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(stranded_rounds, 0, "a waiter timed out while a pushed packet sat in the queue");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn stress_cancelled_waiters_exactly_once() {
        const N: u64 = 200_000;
        const P: u64 = 4;
        const W: usize = 8;
        let q = Arc::new(WriterQueue::new(N as usize));
        let received = Arc::new(AtomicU64::new(0));
        let cancels = Arc::new(AtomicU64::new(0));
        let mut waiters = Vec::new();
        for w in 0..W {
            let (q, received, cancels) = (Arc::clone(&q), Arc::clone(&received), Arc::clone(&cancels));
            waiters.push(tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut rng: u64 = 0x9E37_79B9_7F4A_7C15 ^ (w as u64 + 1);
                let deadline = Instant::now() + Duration::from_secs(60);
                while received.load(Ordering::SeqCst) < N && Instant::now() < deadline {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    let mode = rng % 4;
                    tokio::select! {
                        p = q.recv() => {
                            seen.push(u64::from_le_bytes(p.try_into().unwrap()));
                            received.fetch_add(1, Ordering::SeqCst);
                        }
                        () = async {
                            match mode {
                                0 => tokio::task::yield_now().await,
                                1 => { tokio::task::yield_now().await; tokio::task::yield_now().await; }
                                2 => tokio::time::sleep(Duration::from_micros(50)).await,
                                _ => tokio::time::sleep(Duration::from_millis(5)).await,
                            }
                        } => { cancels.fetch_add(1, Ordering::Relaxed); }
                    }
                }
                seen
            }));
        }
        let mut pushers = Vec::new();
        for p in 0..P {
            let q = Arc::clone(&q);
            pushers.push(tokio::spawn(async move {
                let mut i = p;
                while i < N {
                    q.try_push(i.to_le_bytes().to_vec());
                    if i % 64 == 0 {
                        tokio::task::yield_now().await;
                    }
                    i += P;
                }
            }));
        }
        for h in pushers {
            h.await.unwrap();
        }
        let mut counts: HashMap<u64, u32> = HashMap::new();
        for h in waiters {
            for id in h.await.unwrap() {
                *counts.entry(id).or_default() += 1;
            }
        }
        let missing = (0..N).filter(|i| !counts.contains_key(i)).count();
        let dup = counts.values().filter(|&&c| c > 1).count();
        assert_eq!(missing, 0);
        assert_eq!(dup, 0);
    }

    #[test]
    fn capacity_drops_newest() {
        let q = WriterQueue::new(3);
        for i in 0..6u8 {
            q.try_push(vec![i]);
        }
        let v: Vec<u8> = q.queue.lock().iter().map(|p| p[0]).collect();
        assert_eq!(v, vec![0, 1, 2]);
    }

    /// Parent bug: `try_push` only compares `queue.len()` against `capacity`, so a permit that
    /// already went to a parked waiter still counts toward capacity until that waiter pops it.
    /// A send always succeeds when a receiver is already waiting, regardless of buffer occupancy,
    /// because the send hands off directly to that receiver. With `capacity == 1` and five
    /// receivers already parked in `recv()`, a direct handoff delivers 5 of 5 back-to-back sends;
    /// the buggy queue delivers only 1.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn try_push_admits_a_push_per_parked_receiver() {
        const PARKED: usize = 5;
        let q = Arc::new(WriterQueue::new(1));
        let mut receivers = Vec::with_capacity(PARKED);
        for _ in 0..PARKED {
            let q = Arc::clone(&q);
            receivers.push(tokio::spawn(async move { q.recv().await }));
        }
        while q.parked_count() < PARKED {
            tokio::task::yield_now().await;
        }
        for i in 0..PARKED as u8 {
            q.try_push(vec![i]);
        }
        let mut got = Vec::with_capacity(PARKED);
        for h in receivers {
            let packet =
                tokio::time::timeout(Duration::from_secs(2), h).await.expect("receiver must not hang").unwrap();
            got.push(packet[0]);
        }
        got.sort_unstable();
        assert_eq!(
            got,
            (0..PARKED as u8).collect::<Vec<_>>(),
            "every parked receiver must get a packet, matching the direct handoff"
        );
    }
}

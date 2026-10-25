use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{watch, Mutex as AsyncMutex, Notify};
use tokio_util::sync::CancellationToken;

use murmur_common_httputils::addr::NetAddr;
use murmur_constant::path::NAME;
use murmur_constant::version::VERSION;
use murmur_std_compat::net::{Addr, Conn as NetConn};

pub const UDP_MAGIC_ADDRESS: &str = "_udp2";
pub const ICMP_MAGIC_ADDRESS: &str = "_icmp";
pub const HEALTH_CHECK_MAGIC_ADDRESS: &str = "_check";

/// Chrome's default.
pub const DEFAULT_QUIC_STREAM_RECEIVE_WINDOW: u64 = 131_072;
pub const DEFAULT_CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
pub const DEFAULT_HEALTH_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(7);
pub const DEFAULT_QUIC_MAX_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2 * (30 + 7));
pub const DEFAULT_SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub static APP_NAME: &str = NAME;
pub static VERSION_STR: &str = VERSION;

/// The TCP user agent: `<platform> <app_name>`.
pub static TCP_USER_AGENT: LazyLock<String> =
    LazyLock::new(|| format!("{} {}/{}", std::env::consts::OS, APP_NAME, VERSION_STR));

/// The UDP user agent: `<platform> _udp2`.
pub static UDP_USER_AGENT: LazyLock<String> =
    LazyLock::new(|| format!("{} {}", std::env::consts::OS, UDP_MAGIC_ADDRESS));

/// The ICMP user agent: `<platform> _icmp`.
pub static ICMP_USER_AGENT: LazyLock<String> =
    LazyLock::new(|| format!("{} {}", std::env::consts::OS, ICMP_MAGIC_ADDRESS));

pub static HEALTH_CHECK_USER_AGENT: LazyLock<String> = LazyLock::new(|| std::env::consts::OS.to_owned());

pub(crate) fn build_auth(username: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{username}:{password}")))
}

/// Parses an HTTP Basic Authentication string, returning the user name and password.
pub(crate) fn parse_basic_auth(auth: &str) -> Option<(String, String)> {
    const PREFIX: &str = "Basic ";
    if !auth.get(..PREFIX.len()).is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX)) {
        return None;
    }
    let decoded = STANDARD.decode(auth.get(PREFIX.len()..)?).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_owned(), password.to_owned()))
}

pub(crate) fn parse16_bytes_ip(buffer: [u8; 16]) -> IpAddr {
    let is_zero_prefix = buffer[..12] == [0u8; 12];
    let is_loopback_v6_tail = buffer[12] == 0 && buffer[13] == 0 && buffer[14] == 0 && buffer[15] == 1;
    let is_ipv4 = is_zero_prefix && !is_loopback_v6_tail;
    if is_ipv4 {
        IpAddr::V4(Ipv4Addr::new(buffer[12], buffer[13], buffer[14], buffer[15]))
    } else {
        IpAddr::V6(Ipv6Addr::from(buffer))
    }
}

pub(crate) fn build_padding_ip(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V6(v6) => v6.octets(),
        IpAddr::V4(v4) => {
            let mut buffer = [0u8; 16];
            buffer[12..16].copy_from_slice(&v4.octets());
            buffer
        }
    }
}

/// The body of an http tunnel connection: bytes readable from the peer once the exchange is
/// established. Both the client half (a response body) and the server half (a request body) are
/// erased behind this so [`HttpConn`] does not need to know which side it is.
pub(crate) type BodyReader = Pin<Box<dyn AsyncRead + Send + 'static>>;

/// The write half of an http tunnel plus an explicit flush step: every write here is immediately
/// observable to the peer, so a separate flush step is not needed.
#[async_trait::async_trait]
pub(crate) trait BodyWriter: Send + Sync {
    async fn write_flush(&self, p: &[u8]) -> io::Result<usize>;

    /// Default no-op for writers with no buffered flush step; [`DeferredBodyWriter`] has a real
    /// stream to flush and the h3 writers have nothing buffered to push.
    async fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    /// Closes the underlying writer.
    fn close(&self) {}
}

/// The CONNECT stream's write half, as `hyper` hands it out once the upgrade resolves.
type StreamWriter = Box<dyn AsyncWrite + Send + Unpin>;

fn closed_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "closed pipe")
}

struct WriteRequest {
    bytes: Vec<u8>,
    result: tokio::sync::oneshot::Sender<io::Result<usize>>,
}

struct WriterState {
    stream: AsyncMutex<Option<tokio::sync::mpsc::Sender<WriteRequest>>>,
    resolved: Notify,
    closed: CancellationToken,
    close_started: AtomicBool,
    failed: AtomicBool,
}

/// The pipe between the relay and the HTTP request/response body. Writes are handed to a
/// dedicated pump with one bounded in-flight chunk; the caller waits for that chunk to reach the
/// upgraded stream. This keeps h2's flow-control polling off the relay task without introducing a
/// staging buffer that can deadlock the two tunnel directions.
pub(crate) struct DeferredBodyWriter {
    state: Arc<WriterState>,
}

impl DeferredBodyWriter {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(WriterState {
                stream: AsyncMutex::new(None),
                resolved: Notify::new(),
                closed: CancellationToken::new(),
                close_started: AtomicBool::new(false),
                failed: AtomicBool::new(false),
            }),
        })
    }

    /// Hands over upgraded stream and starts its serialized write pump.
    pub(crate) async fn resolve(&self, mut stream: StreamWriter) {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let mut guard = self.state.stream.lock().await;
        if self.state.closed.is_cancelled() {
            drop(guard);
            let _ = AsyncWriteExt::shutdown(&mut stream).await;
        } else {
            *guard = Some(sender);
            drop(guard);
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                while let Some(request) = receiver.recv().await {
                    let size = request.bytes.len();
                    let result = tokio::select! {
                        biased;
                        () = state.closed.cancelled() => Err(closed_pipe()),
                        result = AsyncWriteExt::write_all(&mut stream, &request.bytes) => result.map(|()| size),
                    };
                    let failed = result.is_err();
                    let _ = request.result.send(result);
                    if failed {
                        break;
                    }
                }
                let _ = AsyncWriteExt::shutdown(&mut stream).await;
            });
        }
        self.state.resolved.notify_waiters();
    }

    /// Releases every write waiting on an upgrade that will never arrive.
    pub(crate) fn fail(&self) {
        self.state.failed.store(true, Ordering::Release);
        self.state.resolved.notify_waiters();
    }

    async fn sender(&self) -> io::Result<tokio::sync::mpsc::Sender<WriteRequest>> {
        let mut guard = self.state.stream.lock().await;
        loop {
            if let Some(sender) = guard.as_ref() {
                return Ok(sender.clone());
            }
            let notified = self.state.resolved.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.failed.load(Ordering::Acquire) || self.state.closed.is_cancelled() {
                return Err(closed_pipe());
            }
            drop(guard);
            notified.await;
            guard = self.state.stream.lock().await;
        }
    }
}

#[async_trait::async_trait]
impl BodyWriter for DeferredBodyWriter {
    async fn write_flush(&self, p: &[u8]) -> io::Result<usize> {
        let sender = self.sender().await?;
        let (result, completion) = tokio::sync::oneshot::channel();
        sender.send(WriteRequest { bytes: p.to_vec(), result }).await.map_err(|_| closed_pipe())?;
        tokio::select! {
            biased;
            () = self.state.closed.cancelled() => Err(closed_pipe()),
            result = completion => result.unwrap_or_else(|_| Err(closed_pipe())),
        }
    }

    async fn flush(&self) -> io::Result<()> {
        let sender = self.sender().await?;
        let (result, completion) = tokio::sync::oneshot::channel();
        sender.send(WriteRequest { bytes: Vec::new(), result }).await.map_err(|_| closed_pipe())?;
        tokio::select! {
            biased;
            () = self.state.closed.cancelled() => Err(closed_pipe()),
            result = completion => match result {
                Ok(result) => result.map(|_| ()),
                Err(_) => Err(closed_pipe()),
            },
        }
    }

    fn close(&self) {
        if self.state.close_started.swap(true, Ordering::AcqRel) {
            return;
        }
        self.state.closed.cancel();
        self.state.resolved.notify_waiters();
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            state.stream.lock().await.take();
        });
    }
}

pub(crate) struct HttpConn {
    pub(crate) writer: Arc<dyn BodyWriter>,
    body: Mutex<Option<BodyReader>>,
    setup_done: AtomicBool,
    create_err: Mutex<Option<Arc<anyhow::Error>>>,
    created_tx: watch::Sender<bool>,
    created_rx: watch::Receiver<bool>,
    cancel_fn: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    close_fn: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    pub(crate) net_addr: NetAddr,
    deadline: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl HttpConn {
    pub(crate) fn new(writer: Arc<dyn BodyWriter>) -> Arc<Self> {
        let (created_tx, created_rx) = watch::channel(false);
        Arc::new(Self {
            writer,
            body: Mutex::new(None),
            setup_done: AtomicBool::new(false),
            create_err: Mutex::new(None),
            created_tx,
            created_rx,
            cancel_fn: Mutex::new(None),
            close_fn: Mutex::new(None),
            net_addr: NetAddr::default(),
            deadline: Mutex::new(None),
        })
    }

    pub(crate) fn setup(&self, body: Option<BodyReader>, err: Option<anyhow::Error>) {
        let had_body = body.is_some();
        let was_first = !self.setup_done.swap(true, Ordering::AcqRel);
        if was_first {
            *self.create_err.lock() = err.map(Arc::new);
            *self.body.lock() = body;
            let _ = self.created_tx.send(true);
            return;
        }
        let create_err_present = self.create_err.lock().is_some();
        if create_err_present && had_body {
            // The caller's body is dropped without being stored: the conn was already closed
            // before this (redundant) setup call arrived.
        }
    }

    pub(crate) async fn wait_created(&self) -> anyhow::Result<()> {
        let mut rx = self.created_rx.clone();
        if !*rx.borrow() {
            let _ = rx.changed().await;
        }
        if self.body.lock().is_some() {
            return Ok(());
        }
        let create_err = self.create_err.lock().clone();
        match create_err {
            Some(err) => Err(anyhow::anyhow!("{err}")),
            None => Ok(()),
        }
    }

    pub(crate) fn set_cancel_fn(&self, f: impl FnOnce() + Send + 'static) {
        *self.cancel_fn.lock() = Some(Box::new(f));
    }

    pub(crate) fn set_close_fn(&self, f: impl FnOnce() + Send + 'static) {
        *self.close_fn.lock() = Some(Box::new(f));
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "kept `Result`-returning so the whole close/shutdown surface shares the io contract"
    )]
    pub(crate) fn close(&self) -> io::Result<()> {
        self.setup(None, Some(anyhow::anyhow!("use of closed network connection")));
        self.writer.close();
        self.body.lock().take();
        let cancel_fn = self.cancel_fn.lock().take();
        if let Some(cancel_fn) = cancel_fn {
            cancel_fn();
        }
        let close_fn = self.close_fn.lock().take();
        if let Some(close_fn) = close_fn {
            close_fn();
        }
        let deadline = self.deadline.lock().take();
        if let Some(deadline) = deadline {
            deadline.abort();
        }
        Ok(())
    }

    /// The half-close the relay reaches for when a tunnel's upload side ends: the peer sees EOF
    /// while this side keeps reading, so a request that is already being answered survives its own
    /// body's end.
    pub(crate) fn shutdown_write(&self) {
        self.writer.close();
    }

    pub(crate) async fn write_flush(&self, p: &[u8]) -> io::Result<usize> {
        self.writer.write_flush(p).await
    }

    pub(crate) async fn flush(&self) -> io::Result<()> {
        self.writer.flush().await
    }

    #[expect(clippy::unnecessary_wraps, reason = "kept `Result`-returning to match the NetConn deadline contract")]
    pub(crate) fn set_deadline(self: &Arc<Self>, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let mut guard = self.deadline.lock();
        if let Some(handle) = guard.take() {
            handle.abort();
        }
        let Some(deadline) = deadline else {
            return Ok(());
        };
        let this = Arc::clone(self);
        *guard = Some(tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            let _ = this.close();
        }));
        drop(guard);
        Ok(())
    }

    pub(crate) async fn read_raw(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.wait_created().await.map_err(io::Error::other)?;
        let mut body = self.body.lock().take();
        let result = match body.as_mut() {
            Some(b) => tokio::io::AsyncReadExt::read(b, buf).await,
            None => Ok(0),
        };
        *self.body.lock() = body;
        result
    }
}

type PendingReadWrite = Mutex<Option<Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send>>>>;
type PendingFlush = Mutex<Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>>;

pub(crate) struct TcpConn {
    pub(crate) inner: Arc<HttpConn>,
    read: PendingReadWrite,
    read_buf: Mutex<Vec<u8>>,
    write: PendingReadWrite,
    write_buf: Mutex<Vec<u8>>,
    flush: PendingFlush,
}

impl TcpConn {
    pub(crate) fn new(inner: Arc<HttpConn>) -> Self {
        Self {
            inner,
            read: Mutex::new(None),
            read_buf: Mutex::new(Vec::new()),
            write: Mutex::new(None),
            write_buf: Mutex::new(Vec::new()),
            flush: Mutex::new(None),
        }
    }
}

impl AsyncRead for TcpConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut read = this.read.lock();
        let future = read.get_or_insert_with(|| {
            let inner = Arc::clone(&this.inner);
            let mut tmp = std::mem::take(&mut *this.read_buf.lock());
            tmp.clear();
            tmp.resize(buf.remaining(), 0);
            Box::pin(async move {
                let result = inner.read_raw(&mut tmp).await;
                (tmp, result)
            })
        });
        match future.as_mut().poll(cx) {
            Poll::Ready((tmp, result)) => {
                *read = None;
                drop(read);
                match result {
                    Ok(n) => {
                        buf.put_slice(tmp.get(..n).unwrap_or_default());
                        *this.read_buf.lock() = tmp;
                        Poll::Ready(Ok(()))
                    }
                    Err(err) => {
                        *this.read_buf.lock() = tmp;
                        Poll::Ready(Err(err))
                    }
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut write = this.write.lock();
        let future = write.get_or_insert_with(|| {
            let inner = Arc::clone(&this.inner);
            let mut data = std::mem::take(&mut *this.write_buf.lock());
            data.clear();
            data.extend_from_slice(buf);
            Box::pin(async move {
                let result = inner.write_flush(&data).await;
                (data, result)
            })
        });
        match future.as_mut().poll(cx) {
            Poll::Ready((data, result)) => {
                *write = None;
                drop(write);
                *this.write_buf.lock() = data;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut flush = this.flush.lock();
        let future = flush.get_or_insert_with(|| {
            let inner = Arc::clone(&this.inner);
            Box::pin(async move { inner.flush().await })
        });
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                *flush = None;
                drop(flush);
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Shutting the write side down half-closes it: the request body's pipe writer is what is
    /// closed, leaving the read half open.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.shutdown_write();
        Poll::Ready(Ok(()))
    }
}

impl NetConn for TcpConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.net_addr.local_addr_result()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.net_addr.remote_addr_result()
    }

    fn close(&self) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let _ = inner.close();
        });
        Ok(())
    }

    fn close_write(&self) -> io::Result<()> {
        self.inner.shutdown_write();
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.set_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.set_deadline(deadline)
    }
}

/// Adapts [`HttpConn`]'s body reader (only reachable through the async, deadline-free
/// [`HttpConn::read_raw`]) to `AsyncRead` so [`murmur_compat::sing_buf::Buffer::read_full_from`]
/// can drive it directly.
pub(crate) struct BodyCursor<'a>(pub(crate) &'a Arc<HttpConn>);

impl AsyncRead for BodyCursor<'_> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut body = self.0.body.lock();
        match body.as_mut() {
            Some(reader) => reader.as_mut().poll_read(cx, buf),
            None => Poll::Ready(Ok(())),
        }
    }
}

pub(crate) async fn skip_n(inner: &Arc<HttpConn>, n: usize) -> io::Result<()> {
    let mut remaining = n;
    let mut scratch = vec![0u8; n.min(4096)];
    while remaining > 0 {
        let want = remaining.min(scratch.len());
        let Some(scratch_slice) = scratch.get_mut(..want) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "scratch buffer shorter than the read length"));
        };
        let read = inner.read_raw(scratch_slice).await?;
        if read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        }
        remaining -= read;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncReadExt;

    use super::*;

    /// What `HttpTestTunnel` sends, and just over an HTTP/2 stream's default 65535-byte
    /// flow-control window, so a writer that buffers instead of writing into the stream has to
    /// interleave with the reader rather than swallow the whole transfer.
    const PAYLOAD: usize = 64 * 1024;

    fn payload() -> Vec<u8> {
        (0..PAYLOAD).map(|i| (i % 251) as u8).collect()
    }

    async fn resolve_with_duplex(writer: &DeferredBodyWriter, capacity: usize) -> DuplexPair {
        let (peer, tunnel) = tokio::io::duplex(capacity);
        let (read, write) = tokio::io::split(tunnel);
        writer.resolve(Box::new(write)).await;
        DuplexPair { peer, _read: read }
    }

    struct DuplexPair {
        peer: tokio::io::DuplexStream,
        _read: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn deferred_writer_moves_a_full_window_through_a_small_stream() {
        let writer = DeferredBodyWriter::new();
        let mut stream = resolve_with_duplex(&writer, 1024).await;

        let expected = payload();
        let write_task = {
            let writer = Arc::clone(&writer);
            let expected = expected.clone();
            tokio::spawn(async move {
                for chunk in expected.chunks(4096) {
                    writer.write_flush(chunk).await.expect("write chunk");
                }
                writer.close();
            })
        };

        let mut received = vec![0u8; PAYLOAD];
        tokio::time::timeout(Duration::from_secs(10), stream.peer.read_exact(&mut received))
            .await
            .expect("payload transfer must not wedge on an internal buffer")
            .expect("read payload");
        assert_eq!(received, expected);

        let mut trailing = Vec::new();
        stream.peer.read_to_end(&mut trailing).await.expect("drain");
        assert!(trailing.is_empty(), "close half closes the stream");
        write_task.await.expect("writer task joins");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn deferred_writer_waits_for_the_upgrade_instead_of_buffering() {
        let writer = DeferredBodyWriter::new();
        let write_task = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { writer.write_flush(b"payload").await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!write_task.is_finished(), "a write before the upgrade must wait for the stream");

        let mut stream = resolve_with_duplex(&writer, 64).await;
        let mut received = [0u8; 7];
        stream.peer.read_exact(&mut received).await.expect("read payload");
        assert_eq!(&received, b"payload");
        assert_eq!(write_task.await.expect("writer task joins").expect("write"), b"payload".len());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn deferred_writer_close_finishes_a_stream_that_arrives_late() {
        let writer = DeferredBodyWriter::new();
        let write_task = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { writer.write_flush(b"payload").await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        writer.close();
        assert_eq!(
            write_task.await.expect("writer task joins").expect_err("closed pipe").kind(),
            io::ErrorKind::BrokenPipe
        );

        let mut stream = resolve_with_duplex(&writer, 64).await;
        let mut received = Vec::new();
        stream.peer.read_to_end(&mut received).await.expect("drain");
        assert!(received.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn deferred_writer_fail_releases_a_waiting_write() {
        let writer = DeferredBodyWriter::new();
        let write_task = {
            let writer = Arc::clone(&writer);
            tokio::spawn(async move { writer.write_flush(b"payload").await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        writer.fail();
        assert_eq!(
            write_task.await.expect("writer task joins").expect_err("upgrade failed").kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    /// The half-close the relay asks for when the upload side ends:
    /// the peer sees EOF while the download side of the same conn keeps working.
    #[tokio::test(flavor = "multi_thread")]
    async fn http_conn_shutdown_write_leaves_the_body_readable() {
        let writer = DeferredBodyWriter::new();
        let mut stream = resolve_with_duplex(&writer, 64).await;
        let tunnel_writer: Arc<dyn BodyWriter> = Arc::<DeferredBodyWriter>::clone(&writer);
        let http_conn = HttpConn::new(tunnel_writer);
        let (upstream, mut downstream) = tokio::io::duplex(64);
        http_conn.setup(Some(Box::pin(upstream)), None);

        http_conn.write_flush(b"request").await.expect("write request");
        http_conn.shutdown_write();

        let mut received = [0u8; 7];
        stream.peer.read_exact(&mut received).await.expect("request reaches the peer");
        assert_eq!(&received, b"request");
        let mut trailing = Vec::new();
        stream.peer.read_to_end(&mut trailing).await.expect("drain");
        assert!(trailing.is_empty());

        downstream.write_all(b"response").await.expect("downstream write");
        let mut read_buf = [0u8; 8];
        http_conn.read_raw(&mut read_buf).await.expect("read response");
        assert_eq!(&read_buf, b"response");
    }
}

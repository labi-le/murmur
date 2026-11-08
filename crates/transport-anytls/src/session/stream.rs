use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::pipe::io_pipe::{pipe, PipeReader, PipeWriter};
use murmur_common_net::deadline::pipe::{make_pipe_deadline, PipeDeadline};
use murmur_common_net::io::{old_addr_to_socket_addr, Stream as NetStream};
use murmur_std_compat::net::deadline_time;
use murmur_std_compat::net::{Addr, Conn};

use super::frame::{new_frame, CMD_SYNACK};
use super::session::{err_closed_pipe, err_deadline_exceeded, err_net_closed, Session};

type DieHook = Box<dyn Fn() + Send + Sync>;
type PendingWrite = Mutex<Option<tokio::task::JoinHandle<io::Result<usize>>>>;

/// `Stream`, which implements `Conn`.
pub struct Stream {
    id: u32,

    sess: Arc<Session>,

    pipe_r: PipeReader,
    pipe_w: PipeWriter,
    write_deadline: PipeDeadline,

    die_once: AtomicBool,
    die_hook: Mutex<Option<DieHook>>,
    die_err: Mutex<Option<Arc<io::Error>>>,

    /// Frame write accepted by [`StreamConn::poll_write`] but possibly still running. the
    /// `Write` returns only after `writeDataFrame`, so a later `Close` always sends FIN after it;
    /// [`Stream::close`] awaits this slot to keep that order.
    pending_write: PendingWrite,

    report_once: AtomicBool,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream").field("id", &self.id).finish_non_exhaustive()
    }
}

pub(crate) fn new_stream(id: u32, sess: Arc<Session>) -> Stream {
    let (pipe_r, pipe_w) = pipe();
    Stream {
        id,
        sess,
        pipe_r,
        pipe_w,
        write_deadline: make_pipe_deadline(),
        die_once: AtomicBool::new(false),
        die_hook: Mutex::new(None),
        die_err: Mutex::new(None),
        pending_write: Mutex::new(None),
        report_once: AtomicBool::new(false),
    }
}

impl Stream {
    pub const fn id(&self) -> u32 {
        self.id
    }

    pub(crate) const fn pipe_w(&self) -> &PipeWriter {
        &self.pipe_w
    }

    pub(crate) fn set_die_hook(&self, hook: DieHook) {
        *self.die_hook.lock() = Some(hook);
    }

    fn die_error(&self) -> io::Error {
        match self.die_err.lock().as_ref() {
            Some(err) => io::Error::new(err.kind(), err.to_string()),
            None => err_closed_pipe(),
        }
    }

    fn has_die_error(&self) -> bool {
        self.die_err.lock().is_some()
    }

    pub async fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        match self.pipe_r.read(b).await {
            Ok(0) => {
                if self.has_die_error() {
                    return Err(self.die_error());
                }
                Ok(0)
            }
            Ok(n) => Ok(n),
            Err(err) => {
                if self.has_die_error() {
                    return Err(self.die_error());
                }
                Err(err.into())
            }
        }
    }

    pub async fn write(&self, b: &[u8]) -> io::Result<usize> {
        if self.write_deadline.wait().is_closed() {
            return Err(err_deadline_exceeded());
        }
        if self.has_die_error() {
            return Err(self.die_error());
        }
        self.sess.write_data_frame(self.id, b).await
    }

    pub async fn close(&self) -> io::Result<()> {
        self.close_with_error(err_closed_pipe()).await
    }

    /// Closes the stream without notifying the remote peer.
    pub fn close_locally(&self) {
        let once = !self.die_once.swap(true, Ordering::SeqCst);
        if once {
            *self.die_err.lock() = Some(Arc::new(err_net_closed()));
            let _ = self.pipe_r.close();
            let hook = self.die_hook.lock().take();
            if let Some(hook) = hook {
                hook();
            }
        }
    }

    /// Closes the stream with an error. The stream is marked dead first. A frame write already accepted
    /// by [`StreamConn`] then finishes before FIN, because the write returns only after
    /// the data frame; the control-frame deadline armed before the conn lock bounds that wait when
    /// the write is stuck on backpressure.
    pub async fn close_with_error(&self, err: io::Error) -> io::Result<()> {
        let once = !self.die_once.swap(true, Ordering::SeqCst);
        if once {
            *self.die_err.lock() = Some(Arc::new(err));
            let _ = self.pipe_r.close();
            let pending = self.pending_write.lock().take();
            if let Some(handle) = pending {
                self.sess.arm_control_write_deadline();
                // The stuck `Write` and FIN share this one deadline, so a data write that
                // failed (possibly mid-frame) makes FIN fail too and the session closes. Close it
                // here instead of giving FIN a fresh window that could follow a torn frame.
                if !matches!(handle.await, Ok(Ok(_))) {
                    let _ = self.sess.close();
                }
            }
            let result = self.sess.stream_closed(self.id).await;
            let hook = self.die_hook.lock().take();
            if let Some(hook) = hook {
                hook();
            }
            return result;
        }
        Err(self.die_error())
    }

    pub fn set_read_deadline(&self, t: Option<DateTime<Utc>>) -> io::Result<()> {
        self.pipe_r.set_read_deadline(t).map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))
    }

    pub fn set_write_deadline(&self, t: Option<DateTime<Utc>>) -> io::Result<()> {
        self.write_deadline.set(t);
        Ok(())
    }

    pub fn set_deadline(&self, t: Option<DateTime<Utc>>) -> io::Result<()> {
        self.set_write_deadline(t)?;
        self.set_read_deadline(t)
    }

    pub fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.sess.conn_addr(true)
    }

    pub fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.sess.conn_addr(false)
    }

    /// Reports a handshake failure, called when the server fails to create the outbound proxy.
    pub async fn handshake_failure(&self, err: Option<&anyhow::Error>) -> io::Result<()> {
        let once = !self.report_once.swap(true, Ordering::SeqCst);
        if once && err.is_some() && self.sess.peer_version() >= 2 {
            let mut f = new_frame(CMD_SYNACK, self.id);
            f.data = err.map(ToString::to_string).unwrap_or_default().into_bytes();
            self.sess.write_control_frame(f).await?;
        }
        Ok(())
    }

    /// Reports a handshake success, called when the server created the outbound proxy.
    pub async fn handshake_success(&self) -> io::Result<()> {
        let once = !self.report_once.swap(true, Ordering::SeqCst);
        if once && self.sess.peer_version() >= 2 {
            self.sess.write_control_frame(new_frame(CMD_SYNACK, self.id)).await?;
        }
        Ok(())
    }
}

type ReadFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;

/// The same `*Stream` is handed to the session's stream map and to the caller; it is shared as an
/// `Arc`, and this is that shared value seen as a `Conn`.
///
/// The read fills the caller's slice directly; a Rust reader must keep an in-flight
/// future between polls, and that future cannot borrow the caller's buffer, so the implementation
/// moves a reusable scratch buffer through it.
///
/// The write checks the deadline and any stored error once, synchronously, then lets
/// the data frame run on the calling task to completion — a bridge (`StreamAsOldConn`'s
/// `CancellableStream`) racing a deadline against that task cannot un-send bytes already
/// past the check. `poll_write` mirrors this exactly: the same synchronous checks, then the frame
/// write is handed to its own `tokio::spawn`ed task — independent of whether `StreamConn` is ever
/// polled again — and `poll_write` returns immediately. Ordering (only one frame in flight per
/// stream) and backpressure both come from awaiting the previous write's `JoinHandle` at the top
/// of the next `poll_write`/`poll_flush`/`poll_shutdown` call, which is also where a failed
/// previous write's error surfaces.
pub struct StreamConn {
    stream: Arc<Stream>,
    close_view: StreamCloseView,
    read: Mutex<Option<ReadFuture>>,
    /// Bytes an in-flight read (or a bridge-abandoned one) delivered that did not fit in the
    /// caller's buffer at the time; served to the next `poll_read` call before starting a new
    /// read. `leftover[leftover_pos..]` is the unconsumed tail.
    leftover: Vec<u8>,
    leftover_pos: usize,
    read_buf: Vec<u8>,
}

impl std::fmt::Debug for StreamConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamConn")
            .field("stream", &self.stream)
            .field("leftover_pos", &self.leftover_pos)
            .field("read_buf_len", &self.read_buf.len())
            .finish_non_exhaustive()
    }
}

impl StreamConn {
    pub fn new(stream: Arc<Stream>) -> Self {
        Self {
            close_view: StreamCloseView(Arc::clone(&stream)),
            stream,
            read: Mutex::new(None),
            leftover: Vec::new(),
            leftover_pos: 0,
            read_buf: Vec::new(),
        }
    }

    pub const fn stream(&self) -> &Arc<Stream> {
        &self.stream
    }

    /// Awaits the previous write, if any, clearing it either way. `Ready(Err)` surfaces that
    /// write's own failure exactly once; nothing re-reports it on a later call.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the guard owns the slot the in-flight write is polled from, so it has to span the poll"
    )]
    fn poll_previous_write(pending: &PendingWrite, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = pending.lock();
        let Some(handle) = guard.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(handle).poll(cx) {
            Poll::Ready(joined) => {
                *guard = None;
                Poll::Ready(match joined {
                    Ok(result) => result.map(|_written| ()),
                    Err(join_err) => Err(io::Error::other(join_err)),
                })
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for StreamConn {
    fn drop(&mut self) {
        if self.stream.die_once.load(Ordering::SeqCst) {
            return;
        }
        let stream = Arc::clone(&self.stream);
        tokio::spawn(async move {
            let _ = stream.close().await;
        });
    }
}

impl AsyncRead for StreamConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.leftover_pos < this.leftover.len() {
            let (_, tail) = this.leftover.split_at(this.leftover_pos);
            let n = tail.len().min(buf.remaining());
            let (served, _) = tail.split_at(n);
            buf.put_slice(served);
            this.leftover_pos += n;
            if this.leftover_pos == this.leftover.len() {
                this.leftover.clear();
                this.leftover_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        let mut read = this.read.lock();
        if read.is_none() {
            let stream = Arc::clone(&this.stream);
            let mut tmp = std::mem::take(&mut this.read_buf);
            tmp.clear();
            tmp.resize(buf.remaining(), 0);
            *read = Some(Box::pin(async move {
                let result = stream.read(&mut tmp).await;
                (tmp, result)
            }));
        }
        let Some(future) = read.as_mut() else {
            return Poll::Ready(Err(io::Error::other("the read future was just installed")));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready((tmp, result)) => {
                *read = None;
                drop(read);
                match result {
                    Ok(n) => {
                        let copy = n.min(buf.remaining());
                        let (served, remainder) = tmp.split_at(copy);
                        let (buffered, _) = remainder.split_at(n - copy);
                        buf.put_slice(served);
                        if copy < n {
                            this.leftover.clear();
                            this.leftover.extend_from_slice(buffered);
                            this.leftover_pos = 0;
                        }
                        this.read_buf = tmp;
                        Poll::Ready(Ok(()))
                    }
                    Err(err) => {
                        this.read_buf = tmp;
                        Poll::Ready(Err(err))
                    }
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for StreamConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Self::poll_previous_write(&this.stream.pending_write, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }

        // The write's synchronous entry check (`write_deadline`/`die_err`). Once it
        // passes, the frame write always runs, as `writeDataFrame` does, so the task below
        // calls the session directly instead of re-checking through `Stream::write`.
        if this.stream.write_deadline.wait().is_closed() {
            return Poll::Ready(Err(err_deadline_exceeded()));
        }
        if this.stream.has_die_error() {
            return Poll::Ready(Err(this.stream.die_error()));
        }

        let stream = Arc::clone(&this.stream);
        let data = buf.to_vec();
        let len = data.len();
        let handle = tokio::spawn(async move { stream.sess.write_data_frame(stream.id, &data).await });
        *this.stream.pending_write.lock() = Some(handle);
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Self::poll_previous_write(&this.stream.pending_write, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Self::poll_previous_write(&this.stream.pending_write, cx)
    }
}

/// [`StreamConn`] seen as a `Conn` (the compat connection trait), reached only via
/// [`NetStream::old_conn`] —
/// [`StreamAsOldConn`](murmur_common_net::io::StreamAsOldConn) forwards `close`/`set_*_deadline`
/// through it (this stream has no real half-close, so [`NetStream::shutdown_read`]/
/// [`shutdown_write`](NetStream::shutdown_write) stay the default no-op instead). Its
/// `AsyncRead`/`AsyncWrite` are never polled: only the capability methods below are reached
/// through `old_conn`.
struct StreamCloseView(Arc<Stream>);

impl AsyncRead for StreamCloseView {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("StreamCloseView is a close-only view, never read from")))
    }
}

impl AsyncWrite for StreamCloseView {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other("StreamCloseView is a close-only view, never written to")))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Conn for StreamCloseView {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.remote_addr()
    }

    fn close(&self) -> io::Result<()> {
        if self.0.die_once.load(Ordering::SeqCst) {
            return Err(self.0.die_error());
        }
        let stream = Arc::clone(&self.0);
        tokio::spawn(async move {
            let _ = stream.close().await;
        });
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_deadline(deadline_time(deadline))
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_read_deadline(deadline_time(deadline))
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_write_deadline(deadline_time(deadline))
    }
}

impl NetStream for StreamConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        old_addr_to_socket_addr(self.stream.local_addr()?.as_ref())
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        old_addr_to_socket_addr(self.stream.remote_addr()?.as_ref())
    }

    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(&self.close_view)
    }
}

#[cfg(test)]
mod bridge_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use arc_swap::ArcSwapOption;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    use murmur_common_net::io::{OldConnAsStream, StreamAsOldConn};
    use murmur_std_compat::net::TcpAddr;

    use super::*;
    use crate::padding::padding::{new_padding_factory, PaddingFactory};
    use crate::session::session::Session;

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

    impl Conn for DuplexConn {
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

    fn padding_pointer(scheme: &[u8]) -> Arc<ArcSwapOption<PaddingFactory>> {
        let factory = new_padding_factory(scheme).expect("test scheme parses");
        let pointer = ArcSwapOption::default();
        pointer.store(Some(Arc::new(factory)));
        Arc::new(pointer)
    }

    /// Opens one client stream over a live client/server session pair, with the server echoing
    /// back exactly `LEN` bytes for every stream it accepts. `Session::run`'s client side buffers
    /// its `CMD_SETTINGS` frame (and `open_stream`'s `CMD_SYN`) until the first real write on a
    /// stream flushes them together — matching the session's buffering — so the server never
    /// observes the stream until the caller writes to it; echoing from inside `on_new_stream`
    /// avoids the test racing to fetch a server-side handle that does not exist yet.
    async fn open_echoing_stream_pair<const LEN: usize>() -> Arc<Stream> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_session =
            Arc::new(Session::client(Box::new(DuplexConn(client_io)), padding_pointer(b"stop=0"), "meta".to_owned()));
        client_session.run().await;

        let server_session = Arc::new(Session::server(
            Box::new(DuplexConn(server_io)),
            Some(Arc::new(|stream: Arc<Stream>| {
                tokio::spawn(async move {
                    let mut server_conn = StreamAsOldConn::new(StreamConn::new(stream));
                    let mut buf = [0u8; LEN];
                    if server_conn.read_exact(&mut buf).await.is_ok() {
                        let _ = server_conn.write_all(&buf).await;
                    }
                });
            })),
            padding_pointer(b"stop=0"),
        ));
        let server_session_run = Arc::clone(&server_session);
        tokio::spawn(async move { server_session_run.run().await });

        client_session.open_stream().await.expect("client opens the first stream")
    }

    /// Opens a client stream with no peer application reading the other end, but the peer's
    /// duplex half stays alive (returned to the caller) so `Stream::close_with_error`'s `CMD_FIN`
    /// write still lands in the peer's buffer instead of failing with `BrokenPipe`. Sufficient for
    /// tests that only exercise the stream's local pipe/close mechanics.
    async fn open_lone_client_stream() -> (Arc<Stream>, tokio::io::DuplexStream) {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let client_session =
            Arc::new(Session::client(Box::new(DuplexConn(client_io)), padding_pointer(b"stop=0"), "meta".to_owned()));
        let stream = client_session.open_stream().await.expect("client opens the first stream");
        (stream, server_io)
    }

    /// Regression test for the "shared lock between read and write halves" hazard the migration
    /// contract calls out: `tokio::io::split` drives [`StreamConn`]'s read and write directions
    /// from two independent tasks. If they contended for one lock, the client's blocked read
    /// (waiting on the server's echo) would stall the writer feeding it, and this test would hang
    /// instead of completing inside the timeout.
    #[tokio::test]
    async fn stream_as_old_conn_full_duplex_roundtrip_does_not_stall() {
        let client_stream = open_echoing_stream_pair::<5>().await;

        let client_conn = StreamAsOldConn::new(StreamConn::new(client_stream));
        let (mut read_half, mut write_half) = tokio::io::split(client_conn);

        let read_task = tokio::spawn(async move {
            let mut echoed = [0u8; 5];
            timeout(Duration::from_secs(5), read_half.read_exact(&mut echoed)).await.expect("read did not stall")?;
            Ok::<_, io::Error>(echoed)
        });

        timeout(Duration::from_secs(5), write_half.write_all(b"ping!")).await.expect("write did not stall").unwrap();

        let echoed = read_task.await.expect("read task did not panic").expect("read succeeded");
        assert_eq!(&echoed, b"ping!");
    }

    /// [`StreamCloseView`] and [`StreamConn`] hold independent `Arc<Stream>` clones of the same
    /// stream, exactly as `StreamConn::new` wires them. Closing through one clone (what
    /// `NetStream::old_conn`'s bridge does) must unblock a read pending on the other, instead of
    /// leaving it parked forever on the stream's unbuffered internal pipe.
    #[tokio::test]
    async fn closing_one_stream_handle_unblocks_a_read_pending_on_another() {
        let (client_stream, _server_io) = open_lone_client_stream().await;
        let read_handle = Arc::clone(&client_stream);
        let close_handle = Arc::clone(&client_stream);

        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 1];
            read_handle.read(&mut buf).await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        close_handle.close_with_error(err_closed_pipe()).await.expect("closes exactly once");

        let result = timeout(Duration::from_secs(5), read_task).await.expect("close unblocked the pending read");
        let err =
            result.expect("read task did not panic").expect_err("closed stream surfaces the close error, not EOF");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    /// Regression test for the P1 the review of 454a86da found: `StreamAsOldConn`'s
    /// `CancellableStream` layer can time a `poll_read` call out for the caller while
    /// `StreamConn`'s own read future — sized for that call's buffer — keeps running underneath.
    /// A later, smaller-buffer read then resumes that same future; before the fix, its result
    /// went straight into `ReadBuf::put_slice` and panicked once it held more bytes than the new
    /// buffer could take. The surplus must instead be kept and served to the next call.
    #[tokio::test]
    async fn old_conn_read_after_deadline_serves_leftover_instead_of_overflowing() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let client_session =
            Arc::new(Session::client(Box::new(DuplexConn(client_io)), padding_pointer(b"stop=0"), "meta".to_owned()));
        client_session.run().await;

        let server_session = Arc::new(Session::server(
            Box::new(DuplexConn(server_io)),
            Some(Arc::new(|stream: Arc<Stream>| {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    let _ = stream.write(b"12345678").await;
                });
            })),
            padding_pointer(b"stop=0"),
        ));
        let server_run = Arc::clone(&server_session);
        tokio::spawn(async move { server_run.run().await });

        let client_stream = client_session.open_stream().await.expect("client opens the first stream");
        // `Session::run`'s client side buffers `CMD_SETTINGS`/`open_stream`'s `CMD_SYN` until the
        // first real write flushes them together (the session's buffering); this test only reads,
        // so prime the flush directly on the stream, ahead of the `StreamConn` under test.
        client_stream.write(b"x").await.expect("primes the buffered SETTINGS/SYN frame onto the wire");
        let mut client_conn = StreamAsOldConn::new(StreamConn::new(client_stream));

        client_conn
            .set_read_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(50)))
            .expect("sets the read deadline");
        let mut big = [0u8; 4096];
        let timed_out =
            timeout(Duration::from_secs(5), client_conn.read(&mut big)).await.expect("bounded by the test timeout");
        assert_eq!(timed_out.expect_err("the empty read times out").kind(), io::ErrorKind::TimedOut);

        client_conn.set_read_deadline(None).expect("clears the read deadline");

        let mut small = [0u8; 4];
        let n = timeout(Duration::from_secs(5), client_conn.read(&mut small))
            .await
            .expect("bounded by the test timeout")
            .expect("the abandoned read's data does not panic a smaller buffer");
        assert_eq!(n, 4);
        assert_eq!(&small, b"1234");

        let mut rest = [0u8; 4];
        let n2 = timeout(Duration::from_secs(5), client_conn.read(&mut rest))
            .await
            .expect("bounded by the test timeout")
            .expect("the leftover bytes are served next");
        assert_eq!(n2, 4);
        assert_eq!(&rest, b"5678");
    }

    /// The surplus a parked `StreamConn` read hands back is the bytes the caller did not take, not
    /// whatever follows them in the oversized buffer that read future was created with.
    #[tokio::test]
    async fn stream_conn_keeps_the_surplus_of_a_stale_read_future() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let client_session =
            Arc::new(Session::client(Box::new(DuplexConn(client_io)), padding_pointer(b"stop=0"), "meta".to_owned()));
        client_session.run().await;

        let server_session = Arc::new(Session::server(
            Box::new(DuplexConn(server_io)),
            Some(Arc::new(|stream: Arc<Stream>| {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    let _ = stream.write(b"12345678").await;
                });
            })),
            padding_pointer(b"stop=0"),
        ));
        let server_run = Arc::clone(&server_session);
        tokio::spawn(async move { server_run.run().await });

        let client_stream = client_session.open_stream().await.expect("client opens the first stream");
        client_stream.write(b"x").await.expect("primes the buffered SETTINGS/SYN frame onto the wire");
        let mut conn = StreamConn::new(client_stream);

        let mut big = [0u8; 4096];
        let parked = timeout(
            Duration::from_millis(50),
            std::future::poll_fn(|cx| Pin::new(&mut conn).poll_read(cx, &mut ReadBuf::new(&mut big))),
        )
        .await;
        assert!(parked.is_err(), "the peer writes 200ms in, so the oversized read parks first");

        let mut small = [0u8; 4];
        let filled = timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| {
                let mut buf = ReadBuf::new(&mut small);
                match Pin::new(&mut conn).poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) => Poll::Ready(buf.filled().len()),
                    Poll::Ready(Err(err)) => panic!("read failed: {err}"),
                    Poll::Pending => Poll::Pending,
                }
            }),
        )
        .await
        .expect("the parked read's bytes arrive");
        assert_eq!(filled, 4);
        assert_eq!(&small, b"1234");

        let mut rest = [0u8; 4];
        let filled = timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| {
                let mut buf = ReadBuf::new(&mut rest);
                match Pin::new(&mut conn).poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) => Poll::Ready(buf.filled().len()),
                    Poll::Ready(Err(err)) => panic!("read failed: {err}"),
                    Poll::Pending => Poll::Pending,
                }
            }),
        )
        .await
        .expect("the surplus of the parked read is served from the leftover");
        assert_eq!(filled, 4);
        assert_eq!(&rest, b"5678");
    }

    /// Regression test for the review-of-a3b6b536 P1, matching its exact repro: a large write
    /// with a short deadline, a peer that only starts draining afterward, then a second, unrelated
    /// write once the peer is draining. On a3b6b536 the large write times out while its frame is
    /// still queued behind the tiny, undrained duplex, but that second write later drains the
    /// stale future to completion "for free" to make room for its own — the side effect (bytes on
    /// the wire) still happens even though the result is discarded, so the peer ends up receiving
    /// a write the caller was told had failed. Under the fix, whichever way a write resolves, its
    /// presence on the wire agrees with what it reported: the write checks the deadline
    /// once, on entry, then runs to completion off the polling thread, so it cannot itself be
    /// caught still-queued by a deadline racing an unrelated later poll.
    #[tokio::test]
    async fn old_conn_timed_out_write_never_reaches_the_peer() {
        let (client_io, server_io) = tokio::io::duplex(64);
        let client_session =
            Arc::new(Session::client(Box::new(DuplexConn(client_io)), padding_pointer(b"stop=0"), "meta".to_owned()));
        client_session.run().await;
        let client_stream = client_session.open_stream().await.expect("client opens the first stream");
        let mut client_conn = StreamAsOldConn::new(StreamConn::new(client_stream));

        let received: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let received_writer = Arc::clone(&received);
        let _reader_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            let mut server_io = server_io;
            let mut buf = [0u8; 256];
            loop {
                match server_io.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received_writer.lock().extend_from_slice(&buf[..n]),
                }
            }
        });

        client_conn
            .set_write_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(50)))
            .expect("sets the write deadline");
        let accepted = vec![0xAAu8; 4096];
        let write1 = timeout(Duration::from_secs(5), client_conn.write(&accepted)).await.expect("bounded");
        client_conn.set_write_deadline(None).expect("clears the write deadline");

        // A different write, issued once the peer is draining, is what a3b6b536 uses to silently
        // drain (and thereby physically send) a still-stale write's stored future.
        let other = [0xCCu8; 4];
        let _ = timeout(Duration::from_secs(5), client_conn.write(&other)).await.expect("bounded");

        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(client_conn);

        let received = received.lock();
        match write1 {
            Ok(n) => {
                assert_eq!(n, accepted.len());
                let at = received
                    .windows(accepted.len())
                    .position(|w| w == accepted.as_slice())
                    .expect("an accepted write must fully reach the peer");
                assert!(
                    received[at + accepted.len()..].windows(other.len()).any(|w| w == other),
                    "the later write follows the accepted one"
                );
            }
            Err(err) => {
                assert_eq!(err.kind(), io::ErrorKind::TimedOut);
                assert!(
                    !received.windows(accepted.len()).any(|w| w == accepted.as_slice()),
                    "the timed-out write's bytes must never reach the peer"
                );
            }
        }
    }

    /// Regression test for the review of 454a86da, P3: anytls has no real half-close (the
    /// `Stream` has no `CloseRead`/`CloseWrite`), so [`StreamCloseView`] leaves `close_read`/
    /// `close_write` at their inherited no-op default. Before the fix, `StreamAsOldConn` armed
    /// its own bridge-side read/write `DeadlineToken` on every `close_read`/`close_write` call
    /// regardless of `old_conn`, so a caller that half-closed and kept using the other direction
    /// got `TimedOut` through the bridge even though the parent (`StreamConn` used directly) let it
    /// keep working.
    #[tokio::test]
    async fn stream_as_old_conn_half_close_stays_a_no_op_through_the_bridge() {
        let client_stream = open_echoing_stream_pair::<5>().await;
        let mut bridged = StreamAsOldConn::new(StreamConn::new(client_stream));

        bridged.close_read().expect("anytls has no real half-close: close_read stays a no-op");
        bridged.close_write().expect("anytls has no real half-close: close_write stays a no-op");

        timeout(Duration::from_secs(5), bridged.write_all(b"ping!"))
            .await
            .expect("write did not stall")
            .expect("a write after half-close must still succeed, matching the no-op CloseWrite");

        let mut echoed = [0u8; 5];
        timeout(Duration::from_secs(5), bridged.read_exact(&mut echoed))
            .await
            .expect("read did not stall")
            .expect("a read after half-close must still succeed, matching the no-op CloseRead");
        assert_eq!(&echoed, b"ping!");
    }

    /// Regression test for the review-of-a3b6b536 P1: an abandoned write (the caller stops
    /// polling this `StreamConn` after a timeout, without dropping it) must not wedge the whole
    /// session's `conn_lock`. The frame write now runs as its own `tokio::spawn`ed task, driven by
    /// the runtime independently of whether anyone ever calls `poll_write` on this stream again,
    /// so it still finishes once the peer starts draining and releases the lock a second stream's
    /// `open_stream` needs.
    #[tokio::test]
    async fn open_stream_does_not_wedge_behind_an_abandoned_write() {
        let (client_io, mut server_io) = tokio::io::duplex(64);
        let client_session =
            Arc::new(Session::client(Box::new(DuplexConn(client_io)), padding_pointer(b"stop=0"), "meta".to_owned()));
        client_session.run().await;

        let _drain_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let mut sink = Vec::new();
            let _ = server_io.read_to_end(&mut sink).await;
        });

        let stream_a = client_session.open_stream().await.expect("opens stream a");
        let mut conn_a = StreamConn::new(stream_a);
        let huge = vec![0xAAu8; 256 * 1024];
        let n = timeout(Duration::from_secs(5), conn_a.write(&huge))
            .await
            .expect("bounded by the test timeout")
            .expect("the write is accepted synchronously");
        assert_eq!(n, huge.len());
        // Abandoned: `conn_a` stays alive (not dropped) but nobody calls `poll_write` on it again,
        // matching the review's "set_deadline(now) then stop writing" pattern.

        let _stream_b = timeout(Duration::from_secs(5), client_session.open_stream())
            .await
            .expect("open_stream on the same session must not wedge behind the abandoned write")
            .expect("opens stream b");

        drop(conn_a);
    }

    /// Regression test for the review-of-21865c80 P1/P2: once `poll_write` returns `Ok`, the
    /// frame must reach the peer even if a close or an expired write deadline lands before the
    /// spawned frame write runs, and FIN must not overtake it. Repeated on a multi-thread runtime
    /// because the loss depended on task scheduling.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn accepted_write_reaches_the_peer_before_close_or_deadline() {
        const PAYLOAD: [u8; 16] = [0xBB; 16];
        for iteration in 0..60 {
            for mode in 0..3 {
                let (client_io, mut server_io) = tokio::io::duplex(1 << 20);
                let client_session = Arc::new(Session::client(
                    Box::new(DuplexConn(client_io)),
                    padding_pointer(b"stop=0"),
                    "meta".to_owned(),
                ));
                client_session.run().await;
                let stream = client_session.open_stream().await.expect("opens a stream");
                let mut conn = StreamAsOldConn::new(StreamConn::new(stream));
                timeout(Duration::from_secs(5), conn.write_all(&PAYLOAD))
                    .await
                    .expect("bounded")
                    .expect("the write is accepted");
                match mode {
                    0 => Conn::close(&conn).expect("closes"),
                    1 => conn.set_write_deadline(Some(tokio::time::Instant::now())).expect("sets deadline"),
                    _ => drop(conn),
                }

                let mut received = Vec::new();
                let mut buf = [0u8; 4096];
                while !received.windows(PAYLOAD.len()).any(|w| w == PAYLOAD) {
                    match timeout(Duration::from_secs(2), server_io.read(&mut buf)).await {
                        Ok(Ok(n)) if n > 0 => received.extend_from_slice(&buf[..n]),
                        _ => panic!("iteration {iteration} mode {mode}: accepted payload never reached the peer"),
                    }
                }
            }
        }
    }

    /// Regression tests for the review-of-8e78c25b and review-of-411bb95b P1s: closing a stream
    /// whose accepted frame write is stuck on backpressure must finish within the single 5 s
    /// control-frame deadline and tear the session down, whether or not the peer later starts
    /// draining, so no FIN or later frame follows a torn data frame.
    async fn close_behind_a_stuck_write(drain_after: Option<Duration>) {
        let (client_io, mut server_io) = tokio::io::duplex(64);
        let session_conn = StreamAsOldConn::new(OldConnAsStream(Box::new(DuplexConn(client_io))));
        let client_session =
            Arc::new(Session::client(Box::new(session_conn), padding_pointer(b"stop=0"), "meta".to_owned()));
        client_session.run().await;
        let stream = client_session.open_stream().await.expect("opens a stream");
        let mut conn = StreamConn::new(Arc::clone(&stream));
        let huge = vec![0xAAu8; 256 * 1024];
        let accepted = conn.write(&huge).await.expect("the write is accepted synchronously");
        assert_eq!(accepted, huge.len());

        let _drain_task = drain_after.map(|delay| {
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let mut sink = Vec::new();
                let _ = server_io.read_to_end(&mut sink).await;
            })
        });

        let closed = timeout(Duration::from_secs(7), stream.close()).await;
        assert!(closed.is_ok(), "close is bounded by one 5 s control deadline");
        assert!(stream.has_die_error(), "the stream is marked dead by close");
        assert!(client_session.is_closed(), "a failed stuck write tears the session down");
    }

    #[tokio::test]
    async fn close_behind_a_stuck_write_to_a_silent_peer() {
        close_behind_a_stuck_write(None).await;
    }

    #[tokio::test]
    async fn close_behind_a_stuck_write_to_a_peer_that_drains_late() {
        close_behind_a_stuck_write(Some(Duration::from_secs(6))).await;
    }
}

#[cfg(test)]
use std::any::Any;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_std_compat::net::{Addr, Conn};

// `murmur_quic::Stream` is the shared mirror `common::dial`,
// `v4::protocol` and `server` also build their `open_stream`/`accept_stream` on.
use murmur_quic::{Stream, StreamReadHalf, StreamWriteHalf};

pub type CloseDeferFn = Box<dyn Fn() + Send + Sync>;

/// Shared, `Arc`-owned state behind both [`QuicStreamConn`] and its [`QuicStreamCloseView`], so the
/// close-only view can reach the real close without `QuicStreamConn` dual-implementing the old
/// legacy conn trait. The inner [`Stream`] is split into a read half and a write half
/// (`Stream::split`), each behind its own `parking_lot::Mutex`, so a poll on one side never
/// contends with a poll on the other (the wave rule: never share one lock between the read and
/// write halves). Every lock is held only for the duration of one non-blocking
/// `poll_*`/`cancel_read`/`close`/`set_write_deadline` call, never across an `.await`.
struct Inner {
    read: Mutex<Box<dyn StreamReadHalf>>,
    write: Mutex<Box<dyn StreamWriteHalf>>,
    close_defer_fn: Option<CloseDeferFn>,
    close_result: OnceLock<Option<(io::ErrorKind, String)>>,
}

impl Inner {
    fn close_inner(&self) -> Option<(io::ErrorKind, String)> {
        let result = self.close_stream();
        if let Some(close_defer_fn) = &self.close_defer_fn {
            close_defer_fn();
        }
        result
    }

    /// The close order: setting the write deadline to now unblocks a writer parked on the send
    /// side; the read side is then cancelled, since that is cleaned up elsewhere and the close
    /// only ends the sending half; the close runs last.
    fn close_stream(&self) -> Option<(io::ErrorKind, String)> {
        let _ = self.write.lock().set_write_deadline(Some(tokio::time::Instant::now()));
        self.read.lock().cancel_read(0);
        self.write.lock().close().err().map(|err| (err.kind(), err.to_string()))
    }
}

struct QuicStreamConn {
    inner: Arc<Inner>,
    l_addr: Arc<dyn Addr>,
    r_addr: Arc<dyn Addr>,
    close_view: QuicStreamCloseView,
}

impl AsyncRead for QuicStreamConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut read = self.inner.read.lock();
        Pin::new(&mut *read).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStreamConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut write = self.inner.write.lock();
        Pin::new(&mut *write).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut write = self.inner.write.lock();
        Pin::new(&mut *write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut write = self.inner.write.lock();
        Pin::new(&mut *write).poll_shutdown(cx)
    }
}

impl murmur_common_net::io::Stream for QuicStreamConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        murmur_common_net::io::old_addr_to_socket_addr(self.l_addr.as_ref())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        murmur_common_net::io::old_addr_to_socket_addr(self.r_addr.as_ref())
    }

    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(&self.close_view)
    }
}

/// A close-only view, like `transport/vmess/h2.rs`'s `H2Transport`: never actually
/// polled — only ever answers [`Conn`]'s capability methods through [`Stream::old_conn`] — but
/// `Conn` requires `AsyncRead + AsyncWrite`, so this forwards to the same locked halves
/// [`QuicStreamConn`] itself reads/writes through.
struct QuicStreamCloseView {
    inner: Arc<Inner>,
    l_addr: Arc<dyn Addr>,
    r_addr: Arc<dyn Addr>,
}

impl AsyncRead for QuicStreamCloseView {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut read = self.inner.read.lock();
        Pin::new(&mut *read).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStreamCloseView {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut write = self.inner.write.lock();
        Pin::new(&mut *write).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut write = self.inner.write.lock();
        Pin::new(&mut *write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut write = self.inner.write.lock();
        Pin::new(&mut *write).poll_shutdown(cx)
    }
}

impl Conn for QuicStreamCloseView {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(AddrRef(Arc::clone(&self.l_addr))))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(AddrRef(Arc::clone(&self.r_addr))))
    }

    /// `io::Error` is not `Clone`, so a repeated close rebuilds the
    /// stored error from its kind and message.
    fn close(&self) -> io::Result<()> {
        match self.inner.close_result.get_or_init(|| self.inner.close_inner()) {
            None => Ok(()),
            Some((kind, message)) => Err(io::Error::new(*kind, message.clone())),
        }
    }

    /// `StreamReadHalf` carries no deadline setter (only `cancel_read`), so only the write
    /// direction can still be forwarded; a wrapping `CancellableStream` enforces the read side's
    /// own deadline independently of this inner `Stream`.
    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.set_write_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.write.lock().set_write_deadline(deadline)
    }
}

#[derive(Debug, Clone)]
struct AddrRef(Arc<dyn Addr>);

impl Addr for AddrRef {
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

#[must_use]
pub fn new_quic_stream_conn(
    stream: Box<dyn Stream>,
    l_addr: Box<dyn Addr>,
    r_addr: Box<dyn Addr>,
    close_defer_fn: Option<CloseDeferFn>,
) -> Box<dyn murmur_common_net::io::Stream> {
    let l_addr: Arc<dyn Addr> = Arc::from(l_addr);
    let r_addr: Arc<dyn Addr> = Arc::from(r_addr);
    let (read, write) = stream.split();
    let inner = Arc::new(Inner {
        read: Mutex::new(read),
        write: Mutex::new(write),
        close_defer_fn,
        close_result: OnceLock::new(),
    });
    Box::new(QuicStreamConn {
        inner: Arc::clone(&inner),
        l_addr: Arc::clone(&l_addr),
        r_addr: Arc::clone(&r_addr),
        close_view: QuicStreamCloseView { inner, l_addr, r_addr },
    })
}

/// A uni stream over a byte slice, shared by the server tests: it hands out `data` and then,
/// depending on `closes`, ends the stream or stays open.
#[cfg(test)]
pub(crate) struct StubUniStream {
    data: Vec<u8>,
    pos: usize,
    closes: bool,
}

#[cfg(test)]
impl StubUniStream {
    pub(crate) fn new(data: Vec<u8>, closes: bool) -> Self {
        Self { data, pos: 0, closes }
    }
}

#[cfg(test)]
impl AsyncRead for StubUniStream {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let rest = this.data.get(this.pos..).unwrap_or_default();
        if rest.is_empty() {
            return if this.closes { Poll::Ready(Ok(())) } else { Poll::Pending };
        }
        let n = rest.len().min(buf.remaining());
        buf.put_slice(&rest[..n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
impl murmur_quic::ReceiveStream for StubUniStream {
    fn stream_id(&self) -> murmur_quic::StreamId {
        0
    }

    fn cancel_read(&self, _error_code: murmur_quic::StreamErrorCode) {}

    fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Notify;

    use super::*;
    use murmur_quic::{StreamErrorCode, StreamId};
    use murmur_std_compat::net::TcpAddr;

    struct StreamState {
        written: Mutex<Vec<u8>>,
        read_data: Mutex<Vec<u8>>,
        read_waker: Mutex<Option<std::task::Waker>>,
        read_poll_hold: Duration,
        read_entered: Notify,
        close_error: bool,
        close_order: Mutex<Vec<&'static str>>,
    }

    impl StreamState {
        fn new(close_error: bool, read_poll_hold: Duration) -> Self {
            Self {
                written: Mutex::new(Vec::new()),
                read_data: Mutex::new(Vec::new()),
                read_waker: Mutex::new(None),
                read_poll_hold,
                read_entered: Notify::new(),
                close_error,
                close_order: Mutex::new(Vec::new()),
            }
        }
    }

    fn push_read_data(state: &StreamState, data: &[u8]) {
        state.read_data.lock().extend_from_slice(data);
        let pending_waker = state.read_waker.lock().take();
        if let Some(waker) = pending_waker {
            waker.wake();
        }
    }

    struct FakeStream(Arc<StreamState>);

    impl AsyncRead for FakeStream {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FakeStream {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.0.written.lock().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for FakeStream {
        fn stream_id(&self) -> StreamId {
            0
        }

        fn cancel_read(&self, _error_code: StreamErrorCode) {
            self.0.close_order.lock().push("cancel_read");
        }

        fn close(&self) -> io::Result<()> {
            self.0.close_order.lock().push("close");
            if self.0.close_error {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"));
            }
            Ok(())
        }

        fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.0.close_order.lock().push("set_write_deadline");
            Ok(())
        }

        fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            Ok(())
        }

        fn cancel_write(&self, _error_code: StreamErrorCode) {}

        fn set_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            Ok(())
        }

        fn split(self: Box<Self>) -> (Box<dyn StreamReadHalf>, Box<dyn StreamWriteHalf>) {
            (Box::new(FakeStreamReadHalf(Arc::clone(&self.0))), Box::new(FakeStreamWriteHalf(self.0)))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct FakeStreamReadHalf(Arc<StreamState>);

    impl AsyncRead for FakeStreamReadHalf {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            self.0.read_entered.notify_one();
            if !self.0.read_poll_hold.is_zero() {
                std::thread::sleep(self.0.read_poll_hold);
            }
            let mut data = self.0.read_data.lock();
            if data.is_empty() {
                *self.0.read_waker.lock() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let n = data.len().min(buf.remaining());
            buf.put_slice(&data[..n]);
            data.drain(..n);
            Poll::Ready(Ok(()))
        }
    }

    impl StreamReadHalf for FakeStreamReadHalf {
        fn cancel_read(&self, _error_code: StreamErrorCode) {
            self.0.close_order.lock().push("cancel_read");
        }
    }

    struct FakeStreamWriteHalf(Arc<StreamState>);

    impl AsyncWrite for FakeStreamWriteHalf {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.0.written.lock().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl StreamWriteHalf for FakeStreamWriteHalf {
        fn close(&self) -> io::Result<()> {
            self.0.close_order.lock().push("close");
            if self.0.close_error {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"));
            }
            Ok(())
        }

        fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.0.close_order.lock().push("set_write_deadline");
            Ok(())
        }
    }

    fn stream_conn(state: Arc<StreamState>) -> Box<dyn murmur_common_net::io::Stream> {
        let defer_state = Arc::clone(&state);
        new_quic_stream_conn(
            Box::new(FakeStream(state)),
            Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            Box::new(TcpAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 443)),
            Some(Box::new(move || {
                defer_state.close_order.lock().push("close_defer_fn");
            })),
        )
    }

    #[tokio::test]
    async fn writes_run_under_the_write_lock_and_addrs_are_reported() {
        let state = Arc::new(StreamState::new(false, Duration::ZERO));
        let mut conn = stream_conn(Arc::clone(&state));

        conn.write_all(b"hello").await.expect("the write succeeds");
        assert_eq!(b"hello", state.written.lock().as_slice());
        assert_eq!("0.0.0.0:0", conn.local_addr().expect("the local addr is set").to_string());
        assert_eq!("192.0.2.1:443", conn.peer_addr().expect("the remote addr is set").to_string());
    }

    /// Guards the `old_conn()` bridge and the close order: write-deadline, then
    /// read-cancel, then close, then the defer callback, exactly once even on a repeated close.
    #[tokio::test]
    async fn close_follows_the_documented_order() {
        let state = Arc::new(StreamState::new(false, Duration::ZERO));
        let conn = stream_conn(Arc::clone(&state));

        murmur_common_net::io::close_stream(&*conn).expect("the first close succeeds");
        murmur_common_net::io::close_stream(&*conn).expect("the repeated close repeats the result");

        let close_order = state.close_order.lock();
        assert_eq!(vec!["set_write_deadline", "cancel_read", "close", "close_defer_fn"], *close_order);
    }

    #[tokio::test]
    async fn a_failed_close_is_reported_again() {
        let state = Arc::new(StreamState::new(true, Duration::ZERO));
        let conn = stream_conn(Arc::clone(&state));

        for _ in 0..2 {
            let err = murmur_common_net::io::close_stream(&*conn).expect_err("the close fails");
            assert_eq!(io::ErrorKind::BrokenPipe, err.kind());
            assert_eq!("stream closed", err.to_string());
        }
        let close_order = state.close_order.lock();
        assert_eq!(1, close_order.iter().filter(|&&op| op == "close").count());
    }

    /// Regression for the wave rule "never share one lock between the read and write halves".
    /// `tokio::io::split` would reintroduce its own bilock across the two halves, masking the
    /// property under test, so these views instead forward straight to [`Inner`]'s own read and
    /// write locks, exactly as [`QuicStreamConn`] does. A `tokio::time::timeout` cannot preempt a
    /// blocking `parking_lot::Mutex::lock()` mid-poll, so the property is measured directly: the
    /// write must land in a small fraction of `read_poll_hold`, which only holds if it goes
    /// through a lock the read never touches.
    struct TestReadHalf(Arc<Inner>);

    impl AsyncRead for TestReadHalf {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let mut read = self.0.read.lock();
            Pin::new(&mut *read).poll_read(cx, buf)
        }
    }

    struct TestWriteHalf(Arc<Inner>);

    impl AsyncWrite for TestWriteHalf {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let mut write = self.0.write.lock();
            Pin::new(&mut *write).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut write = self.0.write.lock();
            Pin::new(&mut *write).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut write = self.0.write.lock();
            Pin::new(&mut *write).poll_shutdown(cx)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_slow_pending_read_does_not_block_a_concurrent_write() {
        let read_poll_hold = Duration::from_millis(500);
        let state = Arc::new(StreamState::new(false, read_poll_hold));
        let (read, write) = Box::new(FakeStream(Arc::clone(&state))).split();
        let inner = Arc::new(Inner {
            read: Mutex::new(read),
            write: Mutex::new(write),
            close_defer_fn: None,
            close_result: OnceLock::new(),
        });
        let mut read_half = TestReadHalf(Arc::clone(&inner));
        let mut write_half = TestWriteHalf(inner);

        let mut buf = [0u8; 4];
        let read_task = tokio::spawn(async move {
            let n = read_half.read(&mut buf).await?;
            io::Result::Ok((n, buf))
        });

        state.read_entered.notified().await;

        let write_start = std::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(5), write_half.write_all(b"ok"))
            .await
            .expect("the write must eventually complete")
            .expect("the write succeeds");
        let elapsed = write_start.elapsed();
        assert!(
            elapsed < read_poll_hold / 5,
            "the write must not wait for the read's slow, still-pending poll (took {elapsed:?})"
        );

        push_read_data(&state, b"rd");
        let (n, buf) = tokio::time::timeout(Duration::from_secs(2), read_task)
            .await
            .expect("the read task finished")
            .expect("no join error")
            .expect("the read succeeds");
        assert_eq!(2, n);
        assert_eq!(b"rd", &buf[..2]);
        assert_eq!(b"ok", state.written.lock().as_slice());
    }

    /// Regression: `QuicStreamCloseView::set_read_deadline` has no override (`StreamReadHalf`
    /// carries no deadline setter of its own, per the doc comment on `Conn::set_deadline` above),
    /// so `old_conn`'s own read-deadline enforcement is a no-op. `StreamAsOldConn`'s wrapping
    /// `CancellableStream` must still enforce the read deadline itself, falling back to its own
    /// token once the (no-op) `old_conn` path leaves the read genuinely `Pending`.
    #[tokio::test]
    async fn stream_as_old_conn_read_deadline_still_fires_since_quic_read_half_has_no_deadline_setter() {
        let state = Arc::new(StreamState::new(false, Duration::ZERO));
        let conn = stream_conn(Arc::clone(&state));
        let mut bridged = murmur_common_net::io::StreamAsOldConn::new(conn);

        Conn::set_read_deadline(&bridged, Some(tokio::time::Instant::now() + Duration::from_millis(30)))
            .expect("arm the read deadline");
        let mut buf = [0u8; 4];
        let err = bridged.read(&mut buf).await.expect_err(
            "a read deadline must still fire even though QuicStreamCloseView's set_read_deadline is a no-op",
        );
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        Conn::set_read_deadline(&bridged, None).expect("clear the read deadline");
        push_read_data(&state, b"ok");
        let n = tokio::time::timeout(Duration::from_secs(2), bridged.read(&mut buf))
            .await
            .expect("the read must not hang")
            .expect("the read succeeds once the deadline is cleared");
        assert_eq!(&buf[..n], b"ok");
    }
}

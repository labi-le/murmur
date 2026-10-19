//! Pipe adapter connecting a reader with a writer.

use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Error;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use murmur_common_net::deadline::pipe::{
    is_closed_chan, make_pipe_deadline, CloseSignal, CloseSignalWaiter, PipeDeadline,
};

/// The closed-pipe, EOF and deadline-exceeded sentinels, plus the error a caller stored with
/// `close_with_error`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PipeError {
    #[error("io: read/write on closed pipe")]
    ErrClosedPipe,
    #[error("EOF")]
    Eof,
    #[error("i/o timeout")]
    ErrDeadlineExceeded,
    #[error("{0}")]
    Custom(Arc<Error>),
}

impl From<PipeError> for std::io::Error {
    fn from(err: PipeError) -> Self {
        match err {
            PipeError::ErrClosedPipe => Self::new(std::io::ErrorKind::BrokenPipe, err),
            PipeError::Eof => Self::new(std::io::ErrorKind::UnexpectedEof, err),
            PipeError::ErrDeadlineExceeded => Self::new(std::io::ErrorKind::TimedOut, err),
            PipeError::Custom(_) => Self::other(err),
        }
    }
}

/// Stores an error once; later stores are ignored.
#[derive(Default, Debug)]
struct OnceError {
    err: Mutex<Option<PipeError>>,
}

impl OnceError {
    fn store(&self, err: PipeError) {
        let mut slot = self.err.lock();
        if slot.is_none() {
            *slot = Some(err);
        }
    }

    fn load(&self) -> Option<PipeError> {
        self.err.lock().clone()
    }
}

/// A pipe is the shared pipe structure underlying [`PipeReader`] and [`PipeWriter`].
#[derive(Debug)]
struct Pipe {
    wr_mu: tokio::sync::Mutex<()>,
    wr_ch: mpsc::UnboundedSender<(Bytes, oneshot::Sender<usize>)>,
    wr_rx: Mutex<mpsc::UnboundedReceiver<(Bytes, oneshot::Sender<usize>)>>,
    done: Arc<CloseSignal>,
    rerr: OnceError,
    werr: OnceError,

    read_deadline: PipeDeadline,
    write_deadline: PipeDeadline,
}

impl Pipe {
    fn poll_read(
        &self,
        waiters: &mut PipeReadWaiters,
        cx: &mut Context<'_>,
        b: &mut [u8],
    ) -> Poll<Result<usize, PipeError>> {
        if is_closed_chan(&self.done) {
            return Poll::Ready(Err(self.read_close_error()));
        }
        let deadline = self.read_deadline.wait();
        if is_closed_chan(&deadline) {
            return Poll::Ready(Err(PipeError::ErrDeadlineExceeded));
        }

        if waiters.done.poll_closed(&self.done, cx) {
            return Poll::Ready(Err(self.read_close_error()));
        }
        if waiters.read_deadline.poll_closed(&deadline, cx) {
            return Poll::Ready(Err(PipeError::ErrDeadlineExceeded));
        }

        let mut wr_rx = self.wr_rx.lock();
        let received = wr_rx.poll_recv(cx);
        drop(wr_rx);
        let Poll::Ready(received) = received else {
            return Poll::Pending;
        };
        waiters.reset(&self.done, &deadline);

        match received {
            Some((chunk, ack)) => {
                let nr = b.len().min(chunk.len());
                let (dst, _) = b.split_at_mut(nr);
                let (src, _) = chunk.split_at(nr);
                dst.copy_from_slice(src);
                let _ = ack.send(nr);
                Poll::Ready(Ok(nr))
            }
            // The sender lives in this same allocation, so the channel cannot be observed closed.
            None => Poll::Ready(Err(self.read_close_error())),
        }
    }

    fn read_close_error(&self) -> PipeError {
        let rerr = self.rerr.load();
        match (rerr, self.werr.load()) {
            (None, Some(werr)) => werr,
            _ => PipeError::ErrClosedPipe,
        }
    }

    fn write_close_error(&self) -> PipeError {
        let werr = self.werr.load();
        match (werr, self.rerr.load()) {
            (None, Some(rerr)) => rerr,
            _ => PipeError::ErrClosedPipe,
        }
    }

    fn close_read(&self, err: Option<Error>) {
        let err = err.map_or(PipeError::ErrClosedPipe, |err| PipeError::Custom(Arc::new(err)));
        self.rerr.store(err);
        // Closing the signal is idempotent already.
        self.done.close();
    }

    fn close_write(&self, err: Option<Error>) {
        let err = err.map_or(PipeError::Eof, |err| PipeError::Custom(Arc::new(err)));
        self.werr.store(err);
        self.done.close();
    }

    async fn write_bytes(self: &Arc<Self>, data: Bytes) -> Result<usize, PipeError> {
        if is_closed_chan(&self.done) {
            return Err(self.write_close_error());
        }
        if is_closed_chan(&self.write_deadline.wait()) {
            return Err(PipeError::ErrDeadlineExceeded);
        }

        let _wr_mu = self.wr_mu.lock().await;

        let mut n = 0;
        let mut offset = 0;
        let mut once = true;
        while once || offset < data.len() {
            once = false;

            let (ack_tx, mut ack_rx) = oneshot::channel();
            if self.wr_ch.send((data.slice(offset..), ack_tx)).is_err() {
                return Err(self.write_close_error());
            }

            let done = &self.done;
            let deadline = self.write_deadline.wait();
            let nw = tokio::select! {
                ack = &mut ack_rx => match ack {
                    Ok(nw) => nw,
                    Err(_) => return Err(self.write_close_error()),
                },
                () = done.wait() => return Err(self.write_close_error()),
                () = deadline.wait() => return Err(PipeError::ErrDeadlineExceeded),
            };

            offset += nw;
            n += nw;
        }
        Ok(n)
    }
}

/// The subscriptions one poll-based pipe reader owns.
#[derive(Debug, Default)]
struct PipeReadWaiters {
    done: CloseSignalWaiter,
    read_deadline: CloseSignalWaiter,
}

impl PipeReadWaiters {
    /// A settled read releases its wakers, so it does not retain the task that issued it.
    fn reset(&mut self, done: &Arc<CloseSignal>, read_deadline: &Arc<CloseSignal>) {
        self.done.reset(done);
        self.read_deadline.reset(read_deadline);
    }
}

/// A `PipeReader` is the read half of a pipe.
#[derive(Debug)]
pub struct PipeReader {
    pipe: Arc<Pipe>,
    read_waiters: PipeReadWaiters,
}

/// The in-flight [`PipeWriter::write`] call that [`AsyncWrite::poll_write`] has to keep between
/// polls.
type WriteFuture = Pin<Box<dyn Future<Output = Result<usize, PipeError>> + Send + 'static>>;

/// A `PipeWriter` is the write half of a pipe.
pub struct PipeWriter {
    r: PipeReader,
    /// The in-flight write; behind a lock because `WriteFuture` is `Send` but not `Sync`, and the
    /// conns built on this pipe must be `Sync`.
    write: Mutex<Option<WriteFuture>>,
}

impl std::fmt::Debug for PipeWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeWriter").field("r", &self.r).finish_non_exhaustive()
    }
}

impl PipeReader {
    /// Reads data from the pipe, blocking until a writer arrives or the write end is closed.
    // cancel-safe: pending reads consume no bytes and drop their close/deadline subscriptions.
    pub async fn read(&self, data: &mut [u8]) -> Result<usize, PipeError> {
        let mut waiters = PipeReadWaiters::default();
        poll_fn(|cx| self.pipe.poll_read(&mut waiters, cx, &mut *data)).await
    }

    /// Closes the reader. Subsequent writes to the write half of the pipe report
    /// the error [`PipeError::ErrClosedPipe`].
    pub fn close(&self) -> anyhow::Result<()> {
        self.close_with_error(None)
    }

    /// Closes the reader; subsequent writes to the write half of the pipe report the error `err`.
    /// The previous error is never overwritten, and the call itself cannot fail.
    pub fn close_with_error(&self, err: Option<Error>) -> anyhow::Result<()> {
        self.pipe.close_read(err);
        Ok(())
    }

    pub fn set_read_deadline(&self, t: Option<DateTime<Utc>>) -> anyhow::Result<()> {
        if is_closed_chan(&self.pipe.done) {
            return Err(PipeError::ErrClosedPipe.into());
        }
        self.pipe.read_deadline.set(t);
        Ok(())
    }
}

impl PipeWriter {
    /// Writes data to the pipe, blocking until one or more readers have consumed all the
    /// data or the read end is closed.
    ///
    /// The future owns its share of the pipe instead of borrowing the writer, so that it stays
    /// `Send` and can be awaited from a spawned task.
    pub fn write(&self, data: &[u8]) -> impl Future<Output = Result<usize, PipeError>> + Send + 'static {
        let pipe = Arc::clone(&self.r.pipe);
        let data = Bytes::copy_from_slice(data);
        async move { pipe.write_bytes(data).await }
    }

    /// Same as [`Self::write`], but takes ownership of an already-built `Bytes` instead of
    /// copying the caller's slice; the pooled buffer a caller wraps with [`Bytes::from`] is
    /// handed to the pipe without a second allocation.
    pub fn write_owned(&self, data: Bytes) -> impl Future<Output = Result<usize, PipeError>> + Send + 'static {
        let pipe = Arc::clone(&self.r.pipe);
        async move { pipe.write_bytes(data).await }
    }

    /// Closes the writer. Subsequent reads from the read half of the pipe report
    /// no bytes and end of stream.
    pub fn close(&self) -> anyhow::Result<()> {
        self.close_with_error(None)
    }

    /// Closes the writer. Subsequent reads from the read half of the pipe report no bytes
    /// and the error `err`, or end of stream when `err` is absent. The previous error is never
    /// overwritten, and the call itself cannot fail.
    pub fn close_with_error(&self, err: Option<Error>) -> anyhow::Result<()> {
        self.r.pipe.close_write(err);
        Ok(())
    }

    pub fn set_write_deadline(&self, t: Option<DateTime<Utc>>) -> anyhow::Result<()> {
        if is_closed_chan(&self.r.pipe.done) {
            return Err(PipeError::ErrClosedPipe.into());
        }
        self.r.pipe.write_deadline.set(t);
        Ok(())
    }
}

impl AsyncRead for PipeReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let unfilled = buf.initialize_unfilled();
        match this.pipe.poll_read(&mut this.read_waiters, cx, unfilled) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            // A closed write end reports EOF, which is a zero-length read.
            Poll::Ready(Err(PipeError::Eof)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PipeWriter {
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the guard owns the in-flight future and must stay held until the poll's outcome has been applied to the slot"
    )]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut slot = this.write.lock();
        if slot.is_none() {
            let pipe = Arc::clone(&this.r.pipe);
            let data = Bytes::copy_from_slice(buf);
            *slot = Some(Box::pin(async move { pipe.write_bytes(data).await }));
        }
        let Some(write) = slot.as_mut() else {
            return Poll::Ready(Err(std::io::Error::other("the write future was just installed")));
        };
        match write.as_mut().poll(cx) {
            Poll::Ready(res) => {
                *slot = None;
                Poll::Ready(res.map_err(std::io::Error::from))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// The pipe has no counterpart of the writer's `close`, which stays an explicit call.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Creates a synchronous in-memory pipe. It can be used to connect code expecting a reader
/// with code expecting a writer.
///
/// Reads and Writes on the pipe are matched one to one except when multiple Reads are needed to
/// consume a single Write. That is, each Write to the [`PipeWriter`] blocks until it has satisfied
/// one or more Reads from the [`PipeReader`] that fully consume the written data. The data is
/// copied directly from the Write to the corresponding Read (or Reads); there is no internal
/// buffering.
///
/// It is safe to call Read and Write in parallel with each other or with Close. Parallel calls to
/// Read and parallel calls to Write are also safe: the individual calls will be gated sequentially.
///
/// Adds read and write deadline support on top of the pipe.
#[must_use]
pub fn pipe() -> (PipeReader, PipeWriter) {
    let (wr_ch, wr_rx) = mpsc::unbounded_channel();
    let reader = PipeReader {
        pipe: Arc::new(Pipe {
            wr_mu: tokio::sync::Mutex::new(()),
            wr_ch,
            wr_rx: Mutex::new(wr_rx),
            done: Arc::new(CloseSignal::new()),
            rerr: OnceError::default(),
            werr: OnceError::default(),
            read_deadline: make_pipe_deadline(),
            write_deadline: make_pipe_deadline(),
        }),
        read_waiters: PipeReadWaiters::default(),
    };
    let writer = PipeWriter {
        r: PipeReader { pipe: Arc::clone(&reader.pipe), read_waiters: PipeReadWaiters::default() },
        write: Mutex::new(None),
    };
    (reader, writer)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Weak;
    use std::task::{Wake, Waker};
    use std::time::Duration;

    use chrono::{DateTime, TimeDelta, Utc};

    use super::*;

    fn past() -> Option<DateTime<Utc>> {
        Some(Utc::now() - TimeDelta::seconds(1))
    }

    #[tokio::test]
    async fn read_returns_what_the_writer_sent() {
        let (r, w) = pipe();
        let payload = b"hello pipe";
        let mut buf = [0u8; 32];
        let (written, read) = tokio::join!(w.write(payload), r.read(&mut buf));
        assert_eq!(written.expect("write"), payload.len());
        let n = read.expect("read");
        assert_eq!(&buf[..n], payload.as_slice());
    }

    #[tokio::test]
    async fn close_ends_the_read_and_close_with_error_reports_it() {
        let (r, w) = pipe();
        let mut buf = [0u8; 8];
        w.close().expect("close");
        assert!(matches!(r.read(&mut buf).await, Err(PipeError::Eof)));

        let (r, w) = pipe();
        w.close_with_error(Some(anyhow::anyhow!("boom"))).expect("close");
        match r.read(&mut buf).await {
            Err(PipeError::Custom(err)) => assert_eq!(err.to_string(), "boom"),
            other => panic!("{other:?}"),
        }

        let (r, w) = pipe();
        r.close().expect("close");
        assert!(matches!(w.write(b"x").await, Err(PipeError::ErrClosedPipe)));
    }

    #[tokio::test]
    async fn deadlines_expire_reads_and_writes() {
        let (r, w) = pipe();
        let mut buf = [0u8; 8];

        r.set_read_deadline(past()).expect("set");
        assert!(matches!(r.read(&mut buf).await, Err(PipeError::ErrDeadlineExceeded)));

        // A refresh clears the expired deadline, so the pipe waits again.
        r.set_read_deadline(None).expect("set");
        assert!(tokio::time::timeout(Duration::from_millis(50), r.read(&mut buf)).await.is_err());

        // An armed deadline wakes the blocked read.
        r.set_read_deadline(Some(Utc::now() + TimeDelta::milliseconds(20))).expect("set");
        assert!(matches!(r.read(&mut buf).await, Err(PipeError::ErrDeadlineExceeded)));

        w.set_write_deadline(past()).expect("set");
        assert!(matches!(w.write(b"x").await, Err(PipeError::ErrDeadlineExceeded)));
        assert!(w.set_write_deadline(None).is_ok());
    }

    #[tokio::test]
    async fn a_write_larger_than_the_read_buffer_arrives_in_pieces() {
        let (r, w) = pipe();
        let payload = b"abcdef".to_vec();
        let mut small = [0u8; 3];
        let mut got = Vec::new();
        let write = tokio::spawn(async move { w.write(&payload).await });
        for _ in 0..2 {
            let n = r.read(&mut small).await.expect("read");
            got.extend_from_slice(&small[..n]);
        }
        assert_eq!(got, b"abcdef");
        assert_eq!(write.await.expect("join").expect("write"), 6);
    }

    #[tokio::test]
    async fn write_owned_delivers_the_same_bytes_as_write() {
        let (r, w) = pipe();
        let payload = Bytes::from_static(b"owned pipe payload");
        let mut buf = [0u8; 32];
        let (written, read) = tokio::join!(w.write_owned(payload.clone()), r.read(&mut buf));
        assert_eq!(written.expect("write_owned"), payload.len());
        let n = read.expect("read");
        assert_eq!(&buf[..n], payload.as_ref());
    }

    #[tokio::test]
    async fn write_owned_bytes_are_reclaimable_after_the_write_completes() {
        let (r, w) = pipe();
        let data = Bytes::from(vec![7u8; 16]);
        let mut buf = [0u8; 16];
        let (written, read) = tokio::join!(w.write_owned(data.clone()), r.read(&mut buf));
        assert_eq!(written.expect("write_owned"), 16);
        assert_eq!(read.expect("read"), 16);
        // Once the write resolves, the reader has copied the bytes out and the pipe's internal
        // slice has been dropped, so our clone is the sole remaining reference.
        let reclaimed = data.try_into_mut().expect("bytes must be uniquely owned after the write completes");
        assert_eq!(&reclaimed[..], &[7u8; 16][..]);
    }

    struct WakeCount(AtomicUsize);

    impl WakeCount {
        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker() -> (Waker, Arc<WakeCount>, Weak<WakeCount>) {
        let task = Arc::new(WakeCount(AtomicUsize::new(0)));
        let weak = Arc::downgrade(&task);
        (Waker::from(Arc::clone(&task)), task, weak)
    }

    /// A parked read must replace its waker when it is polled again. A registry that only appends
    /// keeps every task that ever read this pipe alive until a close, and scans it linearly.
    #[tokio::test]
    async fn a_re_polled_reader_releases_the_retired_waker() {
        let (mut r, _w) = pipe();
        let mut buf = [0u8; 8];

        let (first, first_task, first_ref) = counting_waker();
        {
            let mut unfilled = ReadBuf::new(&mut buf);
            let polled = Pin::new(&mut r).poll_read(&mut Context::from_waker(&first), &mut unfilled);
            assert!(polled.is_pending());
        }
        drop(first);
        drop(first_task);
        assert!(first_ref.upgrade().is_some(), "the parked read must have registered its waker");

        let (second, _second_task, _) = counting_waker();
        {
            let mut unfilled = ReadBuf::new(&mut buf);
            let polled = Pin::new(&mut r).poll_read(&mut Context::from_waker(&second), &mut unfilled);
            assert!(polled.is_pending());
        }
        assert!(first_ref.upgrade().is_none(), "a re-poll must replace the retired waker, not accumulate it");
    }

    #[tokio::test]
    async fn a_cancelled_read_does_not_receive_deadline_or_close_notifications() {
        let (r, w) = pipe();
        let (waker, task, _) = counting_waker();
        let mut buf = [0u8; 8];
        {
            let mut read = Box::pin(r.read(&mut buf));
            assert!(read.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        }

        r.set_read_deadline(past()).expect("expire the read deadline");
        assert_eq!(task.count(), 0, "the cancelled read must unsubscribe from its deadline");
        w.close().expect("close the peer");
        assert_eq!(task.count(), 0, "the cancelled read must unsubscribe from the close signal");
    }

    /// The write half parks on the same signals, so an abandoned write must release its task too.
    #[tokio::test]
    async fn a_cancelled_write_releases_its_task() {
        let (_r, w) = pipe();
        let (waker, task, task_ref) = counting_waker();
        {
            let mut write = Box::pin(w.write_owned(Bytes::from_static(b"payload")));
            assert!(write.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        }
        drop(waker);
        drop(task);
        assert!(task_ref.upgrade().is_none(), "a dropped write must not keep its task alive");
    }

    /// Re-arming a deadline to a nearer time must wake a reader already parked on it. Installing a
    /// fresh signal on re-arm orphans the parked waker, so the read outlives its own deadline.
    #[tokio::test]
    async fn rearming_a_parked_read_deadline_wakes_the_reader() {
        let (r, _w) = pipe();
        r.set_read_deadline(Some(Utc::now() + TimeDelta::seconds(60))).expect("arm");

        let (waker, task, _) = counting_waker();
        let mut buf = [0u8; 8];
        let mut read = Box::pin(r.read(&mut buf));
        assert!(read.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());

        r.set_read_deadline(Some(Utc::now() + TimeDelta::milliseconds(20))).expect("rearm");
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(task.count() >= 1, "rearming to a nearer deadline must wake the parked reader");
    }

    /// One close wakes every parked reader, not only the most recent registrant.
    #[tokio::test]
    async fn one_close_wakes_every_parked_reader() {
        let (r, w) = pipe();
        let mut first_buf = [0u8; 4];
        let mut second_buf = [0u8; 4];
        let (first_waker, first_task, _) = counting_waker();
        let (second_waker, second_task, _) = counting_waker();
        let mut first = Box::pin(r.read(&mut first_buf));
        let mut second = Box::pin(r.read(&mut second_buf));
        assert!(first.as_mut().poll(&mut Context::from_waker(&first_waker)).is_pending());
        assert!(second.as_mut().poll(&mut Context::from_waker(&second_waker)).is_pending());

        w.close().expect("close");
        assert_eq!(first_task.count(), 1, "every parked reader is woken by one close");
        assert_eq!(second_task.count(), 1, "every parked reader is woken by one close");
    }
}

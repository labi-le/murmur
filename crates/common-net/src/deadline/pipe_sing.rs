use std::any::Any;
use std::fmt;
use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use murmur_compat::sing_buf::Buffer;
use murmur_sing::network::{ReadWaitOptions, ReadWaitable, ReadWaiter};
use murmur_std_compat::net::{deadline_time, Addr, Conn};

use super::conn::err_deadline_exceeded;
use super::pipe::{is_closed_chan, make_pipe_deadline, CloseSignal, CloseSignalWaiter, PipeDeadline};

pub(crate) fn err_closed_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")
}

pub(crate) fn err_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

/// Wraps `err` in the pipe operation error; an EOF or closed-pipe error stays unwrapped.
fn op_error(op: &str, err: io::Error) -> io::Error {
    if matches!(err.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe) {
        return err;
    }
    let kind = err.kind();
    io::Error::new(kind, format!("{op} pipe: {err}"))
}

#[derive(Debug, Clone, Copy)]
pub struct PipeAddr;

impl Addr for PipeAddr {
    fn network(&self) -> &'static str {
        "pipe"
    }

    fn string(&self) -> String {
        "pipe".to_owned()
    }
}

/// The consumed byte count and ownership of the unread tail.
type PipeAck = (usize, Bytes);

/// One half of `pipe`; the peer half shares the two channel ends.
struct Pipe {
    /// Serialize Write operations.
    wr_mu: tokio::sync::Mutex<()>,
    /// Used by local Read to interact with remote Write: a successful receive on `rd_rx` is always
    /// followed by an acknowledgement returning ownership of the unread tail.
    rd_rx: Mutex<mpsc::UnboundedReceiver<(Bytes, oneshot::Sender<PipeAck>)>>,
    /// Used by local Write to interact with remote Read.
    wr_tx: mpsc::UnboundedSender<(Bytes, oneshot::Sender<PipeAck>)>,

    local_done: Arc<CloseSignal>,
    remote_done: Arc<CloseSignal>,

    read_deadline: PipeDeadline,
    write_deadline: PipeDeadline,

    read_wait_options: Mutex<ReadWaitOptions>,
}

type PipeWriteFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send + Sync + 'static>>;

/// The subscriptions one poll-based pipe reader owns.
#[derive(Default)]
struct PipeReadWaiters {
    local_done: CloseSignalWaiter,
    remote_done: CloseSignalWaiter,
    read_deadline: CloseSignalWaiter,
}

impl PipeReadWaiters {
    /// A settled read releases its wakers, so it does not retain the task that issued it.
    fn reset(
        &mut self,
        local_done: &Arc<CloseSignal>,
        remote_done: &Arc<CloseSignal>,
        read_deadline: &Arc<CloseSignal>,
    ) {
        self.local_done.reset(local_done);
        self.remote_done.reset(remote_done);
        self.read_deadline.reset(read_deadline);
    }
}

/// A conn end of a `pipe`, which implements [`Conn`] and the read-waiter capability.
pub struct PipeConn {
    pipe: Arc<Pipe>,
    /// The in-flight write that `poll_write` has to keep between polls.
    write_future: Option<PipeWriteFuture>,
    read_waiters: PipeReadWaiters,
}

impl fmt::Debug for PipeConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipeConn").finish_non_exhaustive()
    }
}

impl Pipe {
    /// Reads without the pipe operation-error wrapper.
    fn poll_read(&self, waiters: &mut PipeReadWaiters, cx: &mut Context<'_>, b: &mut [u8]) -> Poll<io::Result<usize>> {
        let read_deadline = self.read_deadline.wait();
        if self.local_done.is_closed() {
            return Poll::Ready(Err(err_closed_pipe()));
        }
        if self.remote_done.is_closed() {
            return Poll::Ready(Err(err_eof()));
        }
        if is_closed_chan(&read_deadline) {
            return Poll::Ready(Err(err_deadline_exceeded()));
        }

        if waiters.local_done.poll_closed(&self.local_done, cx) {
            return Poll::Ready(Err(err_closed_pipe()));
        }
        if waiters.remote_done.poll_closed(&self.remote_done, cx) {
            return Poll::Ready(Err(err_eof()));
        }
        if waiters.read_deadline.poll_closed(&read_deadline, cx) {
            return Poll::Ready(Err(err_deadline_exceeded()));
        }

        let mut rd_rx = self.rd_rx.lock();
        let received = rd_rx.poll_recv(cx);
        drop(rd_rx);
        let Poll::Ready(received) = received else {
            return Poll::Pending;
        };
        waiters.reset(&self.local_done, &self.remote_done, &read_deadline);

        match received {
            Some((mut chunk, ack)) => {
                let nr = b.len().min(chunk.len());
                if let (Some(dst), Some(src)) = (b.get_mut(..nr), chunk.get(..nr)) {
                    dst.copy_from_slice(src);
                }
                chunk.advance(nr);
                let _ = ack.send((nr, chunk));
                Poll::Ready(Ok(nr))
            }
            // The sender lives in the peer half, so the channel is only closed when that half is
            // dropped.
            None => Poll::Ready(Err(err_closed_pipe())),
        }
    }

    /// Awaits a readable buffer without the pipe operation-error wrapper.
    async fn wait_read_buffer_inner(&self) -> io::Result<Buffer> {
        let mut local_waiter = CloseSignalWaiter::new();
        let mut remote_waiter = CloseSignalWaiter::new();
        let mut deadline_waiter = CloseSignalWaiter::new();
        let (mut chunk, ack) = poll_fn(|cx| {
            let read_deadline = self.read_deadline.wait();
            if local_waiter.poll_closed(&self.local_done, cx) {
                return Poll::Ready(Err(err_closed_pipe()));
            }
            if remote_waiter.poll_closed(&self.remote_done, cx) {
                return Poll::Ready(Err(err_eof()));
            }
            if deadline_waiter.poll_closed(&read_deadline, cx) {
                return Poll::Ready(Err(err_deadline_exceeded()));
            }
            let mut rd_rx = self.rd_rx.lock();
            match rd_rx.poll_recv(cx) {
                Poll::Ready(Some(item)) => Poll::Ready(Ok(item)),
                Poll::Ready(None) => Poll::Ready(Err(err_closed_pipe())),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        let options = *self.read_wait_options.lock();
        let mut buffer = options.new_buffer();
        let nr = match buffer.write_bytes(&chunk) {
            Ok(nr) => nr,
            Err(err) => {
                buffer.release();
                return Err(err);
            }
        };
        options.post_return(&mut buffer);
        chunk.advance(nr);
        let _ = ack.send((nr, chunk));
        Ok(buffer)
    }

    /// Writes without the pipe operation-error wrapper.
    // NOT cancel-safe: after sending the chunk, dropping the write abandons its acknowledgement.
    async fn write_inner(self: &Arc<Self>, mut b: Bytes) -> io::Result<usize> {
        if self.local_done.is_closed() {
            return Err(err_closed_pipe());
        }
        if self.remote_done.is_closed() {
            return Err(err_closed_pipe());
        }
        if is_closed_chan(&self.write_deadline.wait()) {
            return Err(err_deadline_exceeded());
        }

        let _wr_mu = self.wr_mu.lock().await; // Ensure entirety of b is written together

        let mut n = 0;
        let mut once = true;
        while once || !b.is_empty() {
            once = false;

            let (ack_tx, ack_rx) = oneshot::channel();
            if self.wr_tx.send((b, ack_tx)).is_err() {
                return Err(err_closed_pipe());
            }

            let local_done = Arc::clone(&self.local_done);
            let remote_done = Arc::clone(&self.remote_done);
            let write_deadline = self.write_deadline.wait();
            // The three cancellation arms are cancel-safe: an abandoned
            // `WaitForCancellationFuture` deregisters its waker on drop and holds no other state.
            let (nw, remaining) = tokio::select! {
                // NOT cancel-safe: losing this arm abandons the ack for a chunk the peer already took.
                ack = ack_rx => match ack {
                    Ok(nw) => nw,
                    Err(_) => return Err(err_closed_pipe()),
                },
                () = local_done.wait() => return Err(err_closed_pipe()),
                () = remote_done.wait() => return Err(err_closed_pipe()),
                () = write_deadline.wait() => return Err(err_deadline_exceeded()),
            };

            b = remaining;
            n += nw;
        }
        Ok(n)
    }
}

/// `Pipe`, creating a synchronous, in-memory, full duplex network connection.
#[must_use]
pub fn pipe() -> (PipeConn, PipeConn) {
    let (wr_tx1, rd_rx1) = mpsc::unbounded_channel();
    let (wr_tx2, rd_rx2) = mpsc::unbounded_channel();
    let done1 = Arc::new(CloseSignal::new());
    let done2 = Arc::new(CloseSignal::new());

    let p1 = Arc::new(Pipe {
        wr_mu: tokio::sync::Mutex::new(()),
        rd_rx: Mutex::new(rd_rx1),
        wr_tx: wr_tx2,
        local_done: Arc::clone(&done1),
        remote_done: Arc::clone(&done2),
        read_deadline: make_pipe_deadline(),
        write_deadline: make_pipe_deadline(),
        read_wait_options: Mutex::new(ReadWaitOptions::default()),
    });
    let p2 = Arc::new(Pipe {
        wr_mu: tokio::sync::Mutex::new(()),
        rd_rx: Mutex::new(rd_rx2),
        wr_tx: wr_tx1,
        local_done: done2,
        remote_done: done1,
        read_deadline: make_pipe_deadline(),
        write_deadline: make_pipe_deadline(),
        read_wait_options: Mutex::new(ReadWaitOptions::default()),
    });
    (
        PipeConn { pipe: p1, write_future: None, read_waiters: PipeReadWaiters::default() },
        PipeConn { pipe: p2, write_future: None, read_waiters: PipeReadWaiters::default() },
    )
}

impl AsyncRead for PipeConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let unfilled = buf.initialize_unfilled();
        match this.pipe.poll_read(&mut this.read_waiters, cx, unfilled) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(op_error("read", err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PipeConn {
    #[expect(clippy::expect_used, reason = "the future is inserted above in this same call")]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_future.is_none() {
            let pipe = Arc::clone(&this.pipe);
            let data = Bytes::copy_from_slice(buf);
            this.write_future = Some(Box::pin(async move { pipe.write_inner(data).await }));
        }
        let future = this.write_future.as_mut().expect("the write future was just set");
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.write_future = None;
                Poll::Ready(result.map_err(|err| op_error("write", err)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// A pipe has no half close; the whole-conn close is the only way to end a direction.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Conn for PipeConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(PipeAddr))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(PipeAddr))
    }

    fn close(&self) -> io::Result<()> {
        self.pipe.local_done.close();
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        if is_closed_chan(&self.pipe.local_done) || is_closed_chan(&self.pipe.remote_done) {
            return Err(err_closed_pipe());
        }
        let deadline = deadline_time(deadline);
        self.pipe.read_deadline.set(deadline);
        self.pipe.write_deadline.set(deadline);
        Ok(())
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        if is_closed_chan(&self.pipe.local_done) || is_closed_chan(&self.pipe.remote_done) {
            return Err(err_closed_pipe());
        }
        self.pipe.read_deadline.set(deadline_time(deadline));
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        if is_closed_chan(&self.pipe.local_done) || is_closed_chan(&self.pipe.remote_done) {
            return Err(err_closed_pipe());
        }
        self.pipe.write_deadline.set(deadline_time(deadline));
        Ok(())
    }
}

impl ReadWaitable for PipeConn {
    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        *self.pipe.read_wait_options.lock() = options;
        false
    }
}

#[async_trait]
impl ReadWaiter for PipeConn {
    async fn wait_read_buffer(&self) -> io::Result<Buffer> {
        self.pipe.wait_read_buffer_inner().await.map_err(|err| op_error("read", err))
    }
}

pub fn is_pipe(conn: &dyn Any) -> bool {
    conn.downcast_ref::<PipeConn>().is_some()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Weak;
    use std::task::{Context, Wake, Waker};
    use std::time::Duration;

    use tokio::io::{AsyncRead as _, AsyncWrite as _, ReadBuf};

    use super::*;

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

    fn poll_read_once(conn: &mut PipeConn, waker: &Waker, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(conn).poll_read(&mut Context::from_waker(waker), &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    #[tokio::test]
    async fn small_reads_preserve_the_payload_and_acknowledge_only_consumed_bytes() {
        let (mut client, mut peer) = pipe();
        let (waker, _, _) = counting_waker();
        let payload = [1u8, 2, 3, 4, 5, 6, 7];
        let mut context = Context::from_waker(&waker);
        assert!(Pin::new(&mut client).poll_write(&mut context, &payload).is_pending());

        for (index, expected) in payload.chunks(2).enumerate() {
            let mut received = [0u8; 2];
            match poll_read_once(&mut peer, &waker, &mut received) {
                Poll::Ready(Ok(n)) => {
                    assert_eq!(n, expected.len());
                    assert_eq!(&received[..n], expected);
                }
                other @ (Poll::Ready(_) | Poll::Pending) => panic!("partial read = {other:?}"),
            }

            let written = Pin::new(&mut client).poll_write(&mut context, &payload);
            if index == 3 {
                assert!(matches!(written, Poll::Ready(Ok(7))), "the last acknowledgement completes the write");
            } else {
                assert!(written.is_pending(), "unread bytes keep the write pending");
            }
        }
    }

    #[tokio::test]
    async fn a_parked_read_wakes_when_the_peer_closes() {
        let (mut client, peer) = pipe();
        let (waker, task, _) = counting_waker();
        let mut buf = [0u8; 8];
        assert!(poll_read_once(&mut client, &waker, &mut buf).is_pending());
        assert_eq!(task.count(), 0);

        peer.close().expect("close the peer half");

        assert_eq!(task.count(), 1, "closing the peer half must wake the parked read");
        match poll_read_once(&mut client, &waker, &mut buf) {
            Poll::Ready(Err(err)) => assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof),
            other @ (Poll::Ready(_) | Poll::Pending) => panic!("read after peer close = {other:?}, want EOF"),
        }
    }

    #[tokio::test]
    async fn a_parked_read_wakes_when_the_read_deadline_passes() {
        let (mut client, _peer) = pipe();
        let (waker, task, _) = counting_waker();
        let mut buf = [0u8; 8];
        assert!(poll_read_once(&mut client, &waker, &mut buf).is_pending());

        // `deadline_time` clamps a past instant to now, which `PipeDeadline::set` then sees as
        // already due and closes inline.
        let expired = tokio::time::Instant::now() - Duration::from_millis(1);
        client.set_read_deadline(Some(expired)).expect("arm the read deadline");

        assert_eq!(task.count(), 1, "an elapsed read deadline must wake the parked read");
        match poll_read_once(&mut client, &waker, &mut buf) {
            Poll::Ready(Err(err)) => assert_eq!(err.kind(), io::ErrorKind::TimedOut),
            other @ (Poll::Ready(_) | Poll::Pending) => panic!("read after deadline = {other:?}, want TimedOut"),
        }
    }

    #[tokio::test]
    async fn a_parked_write_wakes_when_the_peer_closes() {
        let (mut client, peer) = pipe();
        let (waker, task, _) = counting_waker();
        let data = [1u8; 4];
        assert!(Pin::new(&mut client).poll_write(&mut Context::from_waker(&waker), &data).is_pending());
        assert_eq!(task.count(), 0);

        peer.close().expect("close the peer half");

        assert_eq!(task.count(), 1, "closing the peer half must wake the parked write");
        match Pin::new(&mut client).poll_write(&mut Context::from_waker(&waker), &data) {
            Poll::Ready(Err(err)) => assert_eq!(err.kind(), io::ErrorKind::BrokenPipe),
            other @ (Poll::Ready(_) | Poll::Pending) => panic!("write after peer close = {other:?}, want BrokenPipe"),
        }
    }

    /// Neither a read nor a write that settled on the spot may keep the task that issued it
    /// alive: both drop the wakers they registered while parked.
    #[tokio::test]
    async fn settled_read_and_write_release_their_wakers() {
        let (mut client, mut peer) = pipe();
        let data = [7u8; 4];

        let (peer_waker, peer_task, peer_ref) = counting_waker();
        assert!(Pin::new(&mut peer).poll_write(&mut Context::from_waker(&peer_waker), &data).is_pending());

        let (reader_waker, reader_task, reader_ref) = counting_waker();
        let mut buf = [0u8; 8];
        match poll_read_once(&mut client, &reader_waker, &mut buf) {
            Poll::Ready(Ok(n)) => assert_eq!(n, 4),
            other @ (Poll::Ready(_) | Poll::Pending) => panic!("read = {other:?}, want 4 bytes"),
        }
        drop(reader_waker);
        drop(reader_task);
        assert!(reader_ref.upgrade().is_none(), "a settled read must not retain its waker");

        match Pin::new(&mut peer).poll_write(&mut Context::from_waker(&peer_waker), &data) {
            Poll::Ready(Ok(n)) => assert_eq!(n, 4),
            other @ (Poll::Ready(_) | Poll::Pending) => panic!("write = {other:?}, want 4 bytes"),
        }
        drop(peer_waker);
        drop(peer_task);
        assert!(peer_ref.upgrade().is_none(), "a settled write must not retain its waker");
    }
}

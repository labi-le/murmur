//! The half-pipe conn duplicates the in-process pipe internals (see
//! `murmur_common_net::deadline::pipe_sing`).
//!
//! The single close signal is split into independent read/write halves so
//! the read and write half-closes can be observed separately.

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use parking_lot::Mutex as SyncMutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use murmur_common_net::deadline::pipe::{CloseSignal, CloseSignalWaiter};
use murmur_common_net::io::Stream;

fn err_closed_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")
}

fn err_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

fn op_error(op: &str, err: io::Error) -> io::Error {
    if matches!(err.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe) {
        return err;
    }
    let kind = err.kind();
    io::Error::new(kind, format!("{op} pipe: {err}"))
}

struct HalfPipe {
    rd_rx: SyncMutex<mpsc::UnboundedReceiver<(Bytes, oneshot::Sender<usize>)>>,
    wr_tx: mpsc::UnboundedSender<(Bytes, oneshot::Sender<usize>)>,

    local_read_done: Arc<CloseSignal>,
    local_write_done: Arc<CloseSignal>,
    remote_read_done: Arc<CloseSignal>,
    remote_write_done: Arc<CloseSignal>,
}

/// The subscriptions owned by one `poll_read` caller.
#[derive(Default)]
struct ReadWaiters {
    local_read_done: CloseSignalWaiter,
    remote_write_done: CloseSignalWaiter,
}

impl ReadWaiters {
    /// A settled read releases its wakers, so it does not retain the task that issued it.
    fn reset(&mut self, local_read_done: &Arc<CloseSignal>, remote_write_done: &Arc<CloseSignal>) {
        self.local_read_done.reset(local_read_done);
        self.remote_write_done.reset(remote_write_done);
    }
}

impl HalfPipe {
    /// A read that surfaces the raw I/O result.
    fn poll_read(&self, waiters: &mut ReadWaiters, cx: &mut Context<'_>, b: &mut [u8]) -> Poll<io::Result<usize>> {
        if self.local_read_done.is_closed() {
            return Poll::Ready(Err(err_closed_pipe()));
        }
        if self.remote_write_done.is_closed() {
            return Poll::Ready(Err(err_eof()));
        }

        if waiters.local_read_done.poll_closed(&self.local_read_done, cx) {
            return Poll::Ready(Err(err_closed_pipe()));
        }
        if waiters.remote_write_done.poll_closed(&self.remote_write_done, cx) {
            return Poll::Ready(Err(err_eof()));
        }

        let mut rd_rx = self.rd_rx.lock();
        let received = rd_rx.poll_recv(cx);
        drop(rd_rx);
        let Poll::Ready(received) = received else {
            return Poll::Pending;
        };
        waiters.reset(&self.local_read_done, &self.remote_write_done);

        match received {
            Some((chunk, ack)) => {
                let nr = b.len().min(chunk.len());
                let (head, _) = b.split_at_mut(nr);
                head.copy_from_slice(chunk.split_at(nr).0);
                let _ = ack.send(nr);
                Poll::Ready(Ok(nr))
            }
            // The sender (`wr_tx`) can drop for two reasons: the peer called `shutdown_write`
            // (which closes `remote_write_done` before releasing its `Arc<HalfPipe>`), or the
            // peer's `HalfPipeConn` was simply dropped without an explicit half-close. Recheck
            // the signals rather than assuming the latter, so a caller that shuts down cleanly
            // still observes `err_eof()` here instead of a spurious broken-pipe error.
            None if self.local_read_done.is_closed() => Poll::Ready(Err(err_closed_pipe())),
            None if self.remote_write_done.is_closed() => Poll::Ready(Err(err_eof())),
            None => Poll::Ready(Err(err_closed_pipe())),
        }
    }

    /// Sends the leading (or only) chunk of a write synchronously so a reader already parked
    /// in `poll_read` is woken - and can drain the chunk - within the writer's own executor
    /// turn, rather than only once a separately spawned task happens to get its first poll.
    /// Returns the future that awaits this chunk's ack and resends any remainder the reader
    /// did not take in one poll; `poll_write` drives that future to completion via
    /// `pending_write`.
    fn start_write(self: &Arc<Self>, b: Bytes) -> io::Result<impl Future<Output = io::Result<usize>> + Send + 'static> {
        if self.local_write_done.is_closed() {
            return Err(err_closed_pipe());
        }
        if self.remote_read_done.is_closed() {
            return Err(err_closed_pipe());
        }

        let (ack_tx, ack_rx) = oneshot::channel();
        if self.wr_tx.send((b.clone(), ack_tx)).is_err() {
            return Err(err_closed_pipe());
        }
        let pipe = Arc::clone(self);
        Ok(async move { pipe.finish_write(b, ack_rx).await })
    }

    /// Awaits the ack for a chunk `start_write` already sent, resending whatever slice of `b`
    /// the reader did not take until the whole write is acked. The write's resend loop,
    /// split from the synchronous first send above.
    async fn finish_write(self: Arc<Self>, b: Bytes, first_ack: oneshot::Receiver<usize>) -> io::Result<usize> {
        // NOT cancel-safe: the ack the reader already holds is abandoned, so the chunk is left
        // half-written; every caller keeps the future alive until it returns.
        async fn await_ack(
            ack_rx: oneshot::Receiver<usize>,
            local_write_done: &CloseSignal,
            remote_read_done: &CloseSignal,
        ) -> io::Result<usize> {
            // The two cancellation arms are cancel-safe: an abandoned `WaitForCancellationFuture`
            // deregisters its waker on drop and holds no other state.
            tokio::select! {
                // NOT cancel-safe: losing this arm abandons the ack for a chunk the reader took.
                ack = ack_rx => ack.map_err(|_| err_closed_pipe()),
                () = local_write_done.wait() => Err(err_closed_pipe()),
                () = remote_read_done.wait() => Err(err_closed_pipe()),
            }
        }

        let local_write_done = Arc::clone(&self.local_write_done);
        let remote_read_done = Arc::clone(&self.remote_read_done);

        let mut n = await_ack(first_ack, &local_write_done, &remote_read_done).await?;
        let mut offset = n;
        while offset < b.len() {
            let (ack_tx, ack_rx) = oneshot::channel();
            if self.wr_tx.send((b.slice(offset..), ack_tx)).is_err() {
                return Err(err_closed_pipe());
            }
            let nw = await_ack(ack_rx, &local_write_done, &remote_read_done).await?;
            offset += nw;
            n += nw;
        }
        Ok(n)
    }
}

pub(crate) struct HalfPipeConn {
    pipe: Arc<HalfPipe>,
    /// the `Write` blocks until the pipe write finishes and returns its own result; a bridge
    /// layer (`StreamAsOldConn`'s `CancellableStream`) can only time the `poll_write` *call* out,
    /// not the write itself, so returning `Pending`/`Err` from a call that has already queued
    /// `buf` onto the pipe would break `AsyncWrite`'s contract (an error or `Pending` must mean
    /// the buffer was not taken). `poll_write` instead accepts the bytes immediately and spawns
    /// the write so it completes even if the caller never polls this conn again; its result
    /// becomes backpressure on the next `poll_write`/`poll_flush`/`poll_shutdown` call.
    pending_write: SyncMutex<Option<tokio::task::JoinHandle<io::Result<usize>>>>,
    /// Set synchronously by `shutdown_write`, which then also `take()`s `pending_write` to hand
    /// it to a background watcher (see there) - removing the only gate that otherwise stops a
    /// later `poll_write` from queuing a new chunk while an old write is still resending its
    /// unacked remainder, which would let the peer read bytes out of order. The write half-close
    /// closes the write side synchronously, so a later `Write` always fails at once with
    /// a closed-pipe error; this flag reproduces that instead of silently accepting the bytes.
    write_shutdown: AtomicBool,
    read_waiters: ReadWaiters,
}

impl fmt::Debug for HalfPipeConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HalfPipeConn").finish()
    }
}

impl HalfPipeConn {
    /// Polls a still-running background write (if any), clearing it and surfacing its result.
    /// Called before every `poll_write`/`poll_flush`/`poll_shutdown` so a previous write's error
    /// is never silently dropped and a caller that keeps writing gets real backpressure.
    fn poll_pending_write(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut pending = self.pending_write.lock();
        let Some(handle) = pending.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let joined = match Pin::new(handle).poll(cx) {
            Poll::Ready(joined) => joined,
            Poll::Pending => return Poll::Pending,
        };
        *pending = None;
        drop(pending);
        let result = joined.unwrap_or_else(|err| Err(io::Error::other(err)));
        Poll::Ready(result.map(|_| ()).map_err(|err| op_error("write", err)))
    }
}

pub(crate) fn new_half_pipe() -> (Box<dyn Stream>, Box<dyn Stream>) {
    let (wr_tx1, rd_rx1) = mpsc::unbounded_channel();
    let (wr_tx2, rd_rx2) = mpsc::unbounded_channel();

    let r1 = Arc::new(CloseSignal::new());
    let w1 = Arc::new(CloseSignal::new());
    let r2 = Arc::new(CloseSignal::new());
    let w2 = Arc::new(CloseSignal::new());

    let p1 = Arc::new(HalfPipe {
        rd_rx: SyncMutex::new(rd_rx1),
        wr_tx: wr_tx2,
        local_read_done: Arc::clone(&r1),
        local_write_done: Arc::clone(&w1),
        remote_read_done: Arc::clone(&r2),
        remote_write_done: Arc::clone(&w2),
    });
    let p2 = Arc::new(HalfPipe {
        rd_rx: SyncMutex::new(rd_rx2),
        wr_tx: wr_tx1,
        local_read_done: r2,
        local_write_done: w2,
        remote_read_done: r1,
        remote_write_done: w1,
    });

    (
        Box::new(HalfPipeConn {
            pipe: p1,
            pending_write: SyncMutex::new(None),
            write_shutdown: AtomicBool::new(false),
            read_waiters: ReadWaiters::default(),
        }),
        Box::new(HalfPipeConn {
            pipe: p2,
            pending_write: SyncMutex::new(None),
            write_shutdown: AtomicBool::new(false),
            read_waiters: ReadWaiters::default(),
        }),
    )
}

impl AsyncRead for HalfPipeConn {
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

impl AsyncWrite for HalfPipeConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_shutdown.load(Ordering::Acquire) {
            return Poll::Ready(Err(op_error("write", err_closed_pipe())));
        }
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let data = Bytes::copy_from_slice(buf);
        let len = data.len();
        let fut = match this.pipe.start_write(data) {
            Ok(fut) => fut,
            Err(err) => return Poll::Ready(Err(op_error("write", err))),
        };
        let handle = tokio::spawn(fut);
        *this.pending_write.lock() = Some(handle);
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_pending_write(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl Stream for HalfPipeConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.pipe.local_read_done.close();
        Ok(())
    }

    /// A pending background write (see [`HalfPipeConn::pending_write`]) races its `ack`/completion
    /// against `local_write_done` internally; closing that signal here before the write has
    /// actually run would abandon accepted-but-undelivered bytes (the caller was already told
    /// `poll_write` succeeded). Draining the pending write first, then closing, keeps that
    /// ordering intact without making this method async. The watcher keeps `self.pipe` itself
    /// alive (not just `local_write_done`): `HalfPipeConn` (and thus its `Arc<HalfPipe>`) is
    /// typically dropped by the caller right after this call returns, and if that drops the
    /// last reference before the watcher runs, `wr_tx` closes from the sender side - the
    /// reader then observes a bare mpsc `None` instead of the `remote_write_done` signal this
    /// method is supposed to set, surfacing as a broken-pipe error instead of a clean EOF.
    fn shutdown_write(&self) -> io::Result<()> {
        self.write_shutdown.store(true, Ordering::Release);
        let pending = self.pending_write.lock().take();
        match pending {
            Some(handle) => {
                let pipe = Arc::clone(&self.pipe);
                tokio::spawn(async move {
                    let _ = handle.await;
                    pipe.local_write_done.close();
                });
            }
            None => self.pipe.local_write_done.close(),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::new_half_pipe;

    #[tokio::test]
    async fn half_pipe_conn_preserves_half_close() {
        let (mut client, mut peer) = new_half_pipe();

        client.shutdown_write().expect("close write");

        let mut one = [0u8; 1];
        match peer.read(&mut one).await {
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {}
            other => panic!("peer read = {other:?}, want EOF"),
        }

        let response: &[u8] = b"response";
        tokio::spawn(async move {
            let _ = peer.write_all(response).await;
        });
        let mut got = vec![0u8; response.len()];
        client.read_exact(&mut got).await.expect("read after close write");
    }

    /// Regression: once `shutdown_write` returns, a later write must fail immediately (the
    /// The write half-close closes the write side synchronously, so any subsequent write fails with a
    /// closed-pipe error at once) rather than being silently accepted and racing the
    /// already-in-flight write's own resend loop for `wr_tx`.
    #[tokio::test]
    async fn write_after_shutdown_write_fails_immediately() {
        let (mut client, _peer) = new_half_pipe();

        client.write_all(b"first").await.expect("first write accepted");
        client.shutdown_write().expect("close write");

        let err = client.write_all(b"second").await.expect_err("write after shutdown_write must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe, "unexpected error: {err:?}");
    }
}

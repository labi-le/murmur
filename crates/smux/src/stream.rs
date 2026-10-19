//!
//! the `Read`/`Write` block the caller chunk-by-chunk inside the call itself; the
//! `tokio::io::{AsyncRead, AsyncWrite}` contract instead polls, so each blocking wait
//! (the v2 window wait) becomes a boxed future stashed on the `SmuxStream` value
//! between polls, and `Read`'s buffered-copy fast path stays fully synchronous (no future at
//! all) exactly like the v1/v2 read attempts.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use anyhow::anyhow;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::Stream as NetStream;

use crate::frame::{version_byte, Frame, UpdHeader, CMD_FIN, CMD_PSH, CMD_UPD, INITIAL_PEER_WINDOW};
use crate::session::{SessionInner, OPEN_CLOSE_TIMEOUT};
use crate::shaper::Class;
use crate::Config;

/// `data_notify`/`write_notify` stand in for the reader-wakeup and update channels: capacity-1
/// channels fed by a non-blocking send, so a signal raised while no waiter is parked is held
/// for the next one. That is why every signal below is `notify_one` — `notify_waiters` drops
/// it, and a PSH frame that beats a reader's `notified()` registration strands it forever.
pub(crate) struct StreamShared {
    pub(crate) id: u32,
    session: Weak<SessionInner>,
    frame_size: usize,
    version: i32,
    max_stream_buffer: u32,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,

    read_buf: Mutex<VecDeque<u8>>,
    data_notify: Notify,

    die: CancellationToken,
    fin: CancellationToken,

    num_read: AtomicU32,
    num_written: AtomicU32,
    incr: AtomicU32,
    peer_consumed: AtomicU32,
    peer_window: AtomicU32,
    write_notify: Notify,

    read_deadline: Mutex<Option<Instant>>,
    write_deadline: Mutex<Option<Instant>>,

    close_once: AtomicBool,
}

pub(crate) fn new_stream_shared(
    session: Weak<SessionInner>,
    id: u32,
    config: &Config,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> Arc<StreamShared> {
    #[expect(clippy::cast_sign_loss, reason = "`max_frame_size` is validated positive, so the sign is never lost")]
    let frame_size = config.max_frame_size as usize;
    #[expect(clippy::cast_possible_truncation, reason = "`max_stream_buffer` is validated below `i32::MAX`")]
    #[expect(clippy::cast_sign_loss, reason = "`max_stream_buffer` is validated positive, so the sign is never lost")]
    let max_stream_buffer = config.max_stream_buffer as u32;
    Arc::new(StreamShared {
        id,
        session,
        frame_size,
        version: config.version,
        max_stream_buffer,
        local_addr,
        peer_addr,
        read_buf: Mutex::new(VecDeque::new()),
        data_notify: Notify::new(),
        die: CancellationToken::new(),
        fin: CancellationToken::new(),
        num_read: AtomicU32::new(0),
        num_written: AtomicU32::new(0),
        incr: AtomicU32::new(0),
        peer_consumed: AtomicU32::new(0),
        peer_window: AtomicU32::new(INITIAL_PEER_WINDOW),
        write_notify: Notify::new(),
        read_deadline: Mutex::new(None),
        write_deadline: Mutex::new(None),
        close_once: AtomicBool::new(false),
    })
}

impl StreamShared {
    pub(crate) fn push_bytes(&self, data: Vec<u8>) {
        self.read_buf.lock().extend(data);
        self.data_notify.notify_one();
    }

    pub(crate) fn mark_fin(&self) {
        self.fin.cancel();
        self.data_notify.notify_one();
        self.write_notify.notify_one();
    }

    pub(crate) fn mark_die(&self) {
        self.die.cancel();
        self.data_notify.notify_one();
        self.write_notify.notify_one();
    }

    pub(crate) fn take_buffered_len(&self) -> usize {
        let mut rb = self.read_buf.lock();
        let n = rb.len();
        rb.clear();
        n
    }

    pub(crate) fn update_window(&self, consumed: u32, window: u32) {
        self.peer_consumed.store(consumed, Ordering::Release);
        self.peer_window.store(window, Ordering::Release);
        self.write_notify.notify_one();
    }

    fn session_error(&self) -> Option<io::Error> {
        match self.session.upgrade() {
            Some(session) if session.is_closed() => Some(io::Error::other(session.closed_error())),
            Some(_) => None,
            None => Some(closed_pipe_error()),
        }
    }

    /// Returns the consumed byte count the peer must be told about, when a v2 window update
    /// is due; a send failure surfaces to the reader.
    fn on_read_consumed(self_arc: &Arc<Self>, n: usize) -> Option<u32> {
        if let Some(session) = self_arc.session.upgrade() {
            session.return_tokens(n);
        }
        if self_arc.version != 2 {
            return None;
        }
        #[expect(clippy::cast_possible_truncation, reason = "`n` is bounded by the stream's own read buffer")]
        let n_u32 = n as u32;
        let num_read = self_arc.num_read.fetch_add(n_u32, Ordering::AcqRel) + n_u32;
        let incr = self_arc.incr.fetch_add(n_u32, Ordering::AcqRel) + n_u32;
        if incr >= self_arc.max_stream_buffer / 2 || num_read == n_u32 {
            self_arc.incr.store(0, Ordering::Release);
            return Some(num_read);
        }
        None
    }
}

type WindowUpdateFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

fn closed_pipe_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")
}

// cancel-safe: the next update re-reports the cumulative consumed count, so a dropped one is recovered.
async fn send_window_update(inner: &Arc<StreamShared>, consumed: u32) -> anyhow::Result<()> {
    let Some(session) = inner.session.upgrade() else {
        return Ok(());
    };
    let uh = UpdHeader::encode(consumed, inner.max_stream_buffer);
    let frame = Frame::with_data(version_byte(inner.version), CMD_UPD, inner.id, uh.0.to_vec());
    // The window update runs under the stream's read deadline, not the open/close timeout.
    let deadline = inner.read_deadline.lock().map(|d| d.saturating_duration_since(Instant::now()));
    session.write_frame(Class::Ctrl, frame, deadline).await?;
    Ok(())
}

// cancel-safe: it only observes wakeups, and the bytes stay in the read queue.
async fn wait_readable(inner: Arc<StreamShared>, deadline: Option<Instant>) -> io::Result<()> {
    let notified = inner.data_notify.notified();
    tokio::pin!(notified);
    let fin = inner.fin.cancelled();
    tokio::pin!(fin);
    let die = inner.die.cancelled();
    tokio::pin!(die);
    let sleep = async move {
        match deadline {
            Some(d) => tokio::time::sleep_until(d).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(sleep);
    tokio::select! {
        () = &mut notified => Ok(()),
        () = &mut fin => Ok(()),
        () = &mut die => Err(closed_pipe_error()),
        () = &mut sleep => Err(io::Error::new(io::ErrorKind::TimedOut, "timeout")),
    }
}

// cancel-safe: it only observes wakeups, and the window is re-read from the atomics.
async fn wait_writable(inner: Arc<StreamShared>, deadline: Option<Instant>) -> io::Result<()> {
    let notified = inner.write_notify.notified();
    tokio::pin!(notified);
    let fin = inner.fin.cancelled();
    tokio::pin!(fin);
    let die = inner.die.cancelled();
    tokio::pin!(die);
    let sleep = async move {
        match deadline {
            Some(d) => tokio::time::sleep_until(d).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(sleep);
    tokio::select! {
        () = &mut notified => Ok(()),
        () = &mut fin => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")),
        () = &mut die => Err(closed_pipe_error()),
        () = &mut sleep => Err(io::Error::new(io::ErrorKind::TimedOut, "timeout")),
    }
}

// NOT cancel-safe: the pieces already handed to the writer stay written, so the payload can end short.
async fn send_chunk(inner: Arc<StreamShared>, data: Vec<u8>) -> io::Result<usize> {
    let Some(session) = inner.session.upgrade() else {
        return Err(closed_pipe_error());
    };
    let frame_size = inner.frame_size.max(1);
    let deadline = inner.write_deadline.lock().map(|d| d.saturating_duration_since(Instant::now()));
    for piece in data.chunks(frame_size) {
        let frame = Frame::with_data(version_byte(inner.version), CMD_PSH, inner.id, piece.to_vec());
        session.write_frame(Class::Data, frame, deadline).await.map_err(io::Error::other)?;
        #[expect(clippy::cast_possible_truncation, reason = "a piece is at most `frame_size`, a 16-bit field")]
        let written = piece.len() as u32;
        inner.num_written.fetch_add(written, Ordering::AcqRel);
    }
    Ok(data.len())
}

// NOT cancel-safe: a cancel before the FIN lands skips the stream-table cleanup.
async fn close_stream_inner(inner: Arc<StreamShared>) -> io::Result<()> {
    let Some(session) = inner.session.upgrade() else {
        return Ok(());
    };
    let frame = Frame::new(version_byte(inner.version), CMD_FIN, inner.id);
    let result = session.write_frame(Class::Data, frame, Some(OPEN_CLOSE_TIMEOUT)).await;
    session.stream_closed(inner.id);
    result.map(|_| ()).map_err(io::Error::other)
}

type ReadWaitFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;
type WriteWaitFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;
type SendFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send + Sync>>;
type CloseFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

enum ReadState {
    Idle,
    Waiting(ReadWaitFuture),
    WindowUpdate(WindowUpdateFuture),
}

enum WriteState {
    Idle,
    WaitWindow(WriteWaitFuture),
    Sending(SendFuture),
}

/// `Stream`/`stream`.
pub struct SmuxStream {
    inner: Arc<StreamShared>,
    read_state: ReadState,
    write_state: WriteState,
    close_fut: Option<CloseFuture>,
}

/// The boxed waits carry no printable state, so only the stream identity is shown.
impl std::fmt::Debug for SmuxStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmuxStream").field("id", &self.inner.id).finish_non_exhaustive()
    }
}

impl SmuxStream {
    pub(crate) fn new(inner: Arc<StreamShared>) -> Self {
        Self { inner, read_state: ReadState::Idle, write_state: WriteState::Idle, close_fut: None }
    }

    fn poll_read_state(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.read_state {
                ReadState::Waiting(fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => self.read_state = ReadState::Idle,
                    Poll::Ready(Err(err)) => {
                        self.read_state = ReadState::Idle;
                        return Poll::Ready(Err(err));
                    }
                },
                ReadState::WindowUpdate(fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        self.read_state = ReadState::Idle;
                        if let Err(err) = result {
                            return Poll::Ready(Err(err));
                        }
                    }
                },
                ReadState::Idle => {}
            }

            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            let mut rb = self.inner.read_buf.lock();
            if !rb.is_empty() {
                let n = buf.remaining().min(rb.len());
                let chunk: Vec<u8> = rb.drain(..n).collect();
                drop(rb);
                buf.put_slice(&chunk);
                if let Some(consumed) = StreamShared::on_read_consumed(&self.inner, n) {
                    let inner = Arc::clone(&self.inner);
                    self.read_state = ReadState::WindowUpdate(Box::pin(async move {
                        send_window_update(&inner, consumed).await.map_err(io::Error::other)
                    }));
                }
                return Poll::Ready(Ok(()));
            }
            drop(rb);

            if self.inner.fin.is_cancelled() {
                return Poll::Ready(Ok(()));
            }
            if self.inner.die.is_cancelled() {
                return Poll::Ready(Err(closed_pipe_error()));
            }
            if let Some(err) = self.inner.session_error() {
                return Poll::Ready(Err(err));
            }

            let deadline = *self.inner.read_deadline.lock();
            let inner = Arc::clone(&self.inner);
            self.read_state = ReadState::Waiting(Box::pin(wait_readable(inner, deadline)));
        }
    }

    fn poll_write_state(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            match &mut self.write_state {
                WriteState::Sending(fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(res) => {
                        self.write_state = WriteState::Idle;
                        return Poll::Ready(res);
                    }
                },
                WriteState::WaitWindow(fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => self.write_state = WriteState::Idle,
                    Poll::Ready(Err(err)) => {
                        self.write_state = WriteState::Idle;
                        return Poll::Ready(Err(err));
                    }
                },
                WriteState::Idle => {}
            }
            if !matches!(self.write_state, WriteState::Idle) {
                continue;
            }

            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if self.inner.fin.is_cancelled() {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")));
            }
            if self.inner.die.is_cancelled() {
                return Poll::Ready(Err(closed_pipe_error()));
            }
            if let Some(err) = self.inner.session_error() {
                return Poll::Ready(Err(err));
            }

            let n = if self.inner.version == 2 {
                let num_written = self.inner.num_written.load(Ordering::Acquire);
                let peer_consumed = self.inner.peer_consumed.load(Ordering::Acquire);
                let inflight = num_written.wrapping_sub(peer_consumed).cast_signed();
                if inflight < 0 {
                    return Poll::Ready(Err(io::Error::other(anyhow!("peer consumed more than sent"))));
                }
                let peer_window = self.inner.peer_window.load(Ordering::Acquire);
                let win = peer_window.cast_signed().wrapping_sub(inflight);
                if win <= 0 {
                    let deadline = *self.inner.write_deadline.lock();
                    let inner = Arc::clone(&self.inner);
                    self.write_state = WriteState::WaitWindow(Box::pin(wait_writable(inner, deadline)));
                    continue;
                }
                buf.len().min(usize::try_from(win.cast_unsigned()).unwrap_or(usize::MAX))
            } else {
                buf.len()
            };

            let (head, _) = buf.split_at(n);
            let chunk = head.to_vec();
            let inner = Arc::clone(&self.inner);
            self.write_state = WriteState::Sending(Box::pin(send_chunk(inner, chunk)));
        }
    }

    fn poll_close_state(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.close_fut.is_none() {
            if self.inner.close_once.swap(true, Ordering::AcqRel) {
                return Poll::Ready(Ok(()));
            }
            self.inner.die.cancel();
            self.inner.data_notify.notify_one();
            self.inner.write_notify.notify_one();
            let inner = Arc::clone(&self.inner);
            self.close_fut = Some(Box::pin(close_stream_inner(inner)));
        }
        match self.close_fut.as_mut() {
            Some(fut) => match fut.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(res) => {
                    self.close_fut = None;
                    Poll::Ready(res)
                }
            },
            None => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncRead for SmuxStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.poll_read_state(cx, buf)
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_write_state(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_close_state(cx)
    }
}

impl NetStream for SmuxStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.inner.local_addr)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.inner.peer_addr)
    }

    fn shutdown_write(&self) -> io::Result<()> {
        if self.inner.close_once.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.inner.die.cancel();
        self.inner.data_notify.notify_one();
        self.inner.write_notify.notify_one();
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let _ = close_stream_inner(inner).await;
        });
        Ok(())
    }
}

impl crate::Stream for SmuxStream {}

/// The read, write and combined deadline setters, exposed as inherent methods since the
/// [`murmur_common_net::io::Stream`] trait carries no deadline vocabulary (see that trait's own
/// docs on the `CancellableStream`/`IdleTimeout` combinators used elsewhere instead).
impl SmuxStream {
    pub fn set_read_deadline(&self, deadline: Option<Instant>) {
        *self.inner.read_deadline.lock() = deadline;
        self.inner.data_notify.notify_one();
    }

    pub fn set_write_deadline(&self, deadline: Option<Instant>) {
        *self.inner.write_deadline.lock() = deadline;
        self.inner.write_notify.notify_one();
    }

    pub fn set_deadline(&self, deadline: Option<Instant>) {
        self.set_read_deadline(deadline);
        self.set_write_deadline(deadline);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use super::*;

    const PARKE: Duration = Duration::from_secs(1);

    fn shared() -> Arc<StreamShared> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        new_stream_shared(Weak::new(), 1, &crate::default_config(), addr, addr)
    }

    #[tokio::test]
    async fn read_wait_keeps_a_push_that_missed_its_waiter() {
        let inner = shared();
        inner.push_bytes(b"payload".to_vec());

        let woke = tokio::time::timeout(PARKE, wait_readable(Arc::clone(&inner), None))
            .await
            .expect("a cmdPSH delivered before the reader parked was dropped");
        assert!(woke.is_ok());
        let buffered: Vec<u8> = inner.read_buf.lock().iter().copied().collect();
        assert_eq!(buffered, b"payload");
    }

    #[tokio::test]
    async fn write_wait_keeps_a_window_update_that_missed_its_waiter() {
        let inner = shared();
        inner.update_window(0, INITIAL_PEER_WINDOW);

        let woke = tokio::time::timeout(PARKE, wait_writable(Arc::clone(&inner), None))
            .await
            .expect("a cmdUPD delivered before the writer parked was dropped");
        assert!(woke.is_ok());
    }
}

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common_httputils::addr::NetAddr;
use murmur_common_net::io::{old_addr_to_socket_addr, Stream};
use murmur_std_compat::net::{Addr, Conn as GoConn};

/// A write-closer, narrowed to what this crate's writers need: a poll-based
/// `AsyncWrite` plus a synchronous, best-effort `close`. A blocking close implementation
/// (one that waits on a channel) cannot block the async runtime thread
/// from a synchronous method, so `close` here is fire-and-forget: it marks the resource closed and
/// lets any pending async teardown complete in the background.
pub(crate) trait WriteCloser: AsyncWrite + Send {
    fn close(&self) -> io::Result<()>;
}

/// A read-closer, mirrored the same way as [`WriteCloser`].
pub(crate) trait ReadCloser: AsyncRead + Send {
    fn close(&self) -> io::Result<()>;
}

struct ConnState {
    writer: Pin<Box<dyn WriteCloser>>,
    reader: Pin<Box<dyn ReadCloser>>,
    on_close: Option<Box<dyn Fn() + Send + Sync>>,
}

struct Inner {
    state: Mutex<ConnState>,
    net_addr: Arc<NetAddr>,
    deadline_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    self_weak: Mutex<Weak<Self>>,
    closed: AtomicBool,
}

impl Inner {
    /// Idempotent, so both an explicit close and the drop-driven
    /// cleanup below can call it without running `on_close` twice.
    fn close_impl(&self) -> io::Result<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let state = self.state.lock();
        let err1 = state.writer.close();
        let err2 = state.reader.close();
        if let Some(on_close) = &state.on_close {
            on_close();
        }
        drop(state);
        err1.and(err2)
    }

    /// Reset on every call and stopped by a zero deadline.
    fn set_deadline_impl(&self, deadline: Option<tokio::time::Instant>) {
        let mut task = self.deadline_task.lock();
        if let Some(handle) = task.take() {
            handle.abort();
        }
        let Some(deadline) = deadline else {
            drop(task);
            return;
        };

        let weak = self.self_weak.lock().clone();
        *task = Some(tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            if let Some(inner) = weak.upgrade() {
                let _ = inner.close_impl();
            }
        }));
        drop(task);
    }
}

/// The conn carries its address and implements the connection interface directly (with no
/// separate read-close, write-close or stream-access methods), so this view answers only those old
/// `Conn` capabilities, forwarding
/// to the same [`Inner`] [`Conn`] itself reads, writes and closes through — [`Stream::old_conn`]
/// hands it to the `StreamAsOldConn` bridge so `close`/`set_*_deadline` reach this type's real
/// behaviour instead of the trait's shutdown-only defaults.
struct ConnCloseView(Arc<Inner>);

impl AsyncRead for ConnCloseView {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.state.lock();
        state.reader.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for ConnCloseView {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.0.state.lock();
        state.writer.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.state.lock();
        state.writer.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.state.lock();
        state.writer.as_mut().poll_shutdown(cx)
    }
}

impl GoConn for ConnCloseView {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.net_addr.local_addr_result()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.net_addr.remote_addr_result()
    }

    fn close(&self) -> io::Result<()> {
        self.0.close_impl()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_deadline_impl(deadline);
        Ok(())
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.set_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.set_deadline(deadline)
    }
}

pub struct Conn {
    inner: Arc<Inner>,
    close_view: ConnCloseView,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn").finish_non_exhaustive()
    }
}

impl Conn {
    pub(crate) fn new(
        writer: Pin<Box<dyn WriteCloser>>,
        reader: Pin<Box<dyn ReadCloser>>,
        net_addr: Arc<NetAddr>,
    ) -> Self {
        let inner = Arc::new_cyclic(|weak| Inner {
            state: Mutex::new(ConnState { writer, reader, on_close: None }),
            net_addr,
            deadline_task: Mutex::new(None),
            self_weak: Mutex::new(Weak::clone(weak)),
            closed: AtomicBool::new(false),
        });
        Self { close_view: ConnCloseView(Arc::clone(&inner)), inner }
    }

    #[must_use]
    pub fn net_addr(&self) -> &NetAddr {
        &self.inner.net_addr
    }

    pub(crate) fn set_on_close(&self, on_close: Box<dyn Fn() + Send + Sync>) {
        self.inner.state.lock().on_close = Some(on_close);
    }
}

/// Every exit path must reach the close logic, including ones that never call `Close()`
/// explicitly (e.g. an outbound whose handshake fails and drops the conn instead of closing it).
/// Rust has no such guarantee without `Drop`, so closing here on drop is what keeps `on_close`
/// (transport teardown, request-context cancellation) reachable from every path, not just the
/// ones that remember to call `close()`.
impl Drop for Conn {
    fn drop(&mut self) {
        let _ = self.inner.close_impl();
    }
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut state = self.inner.state.lock();
        state.reader.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut state = self.inner.state.lock();
        state.writer.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.inner.state.lock();
        state.writer.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.inner.state.lock();
        state.writer.as_mut().poll_shutdown(cx)
    }
}

impl Stream for Conn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.inner.net_addr.local_addr_result()?.as_ref())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.inner.net_addr.remote_addr_result()?.as_ref())
    }

    fn old_conn(&self) -> Option<&dyn GoConn> {
        Some(&self.close_view)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use murmur_common_net::io::StreamAsOldConn;

    use super::*;

    struct TestWriter(tokio::io::DuplexStream);

    impl AsyncWrite for TestWriter {
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

    impl WriteCloser for TestWriter {
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    struct TestReader(tokio::io::DuplexStream);

    impl AsyncRead for TestReader {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl ReadCloser for TestReader {
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Regression for the `impl GoConn for Conn` → `impl Stream for Conn` conversion: the
    /// Setting a deadline self-closes through a timer, and only reaches that
    /// real behaviour through the old-`Conn` bridge now via `Stream::old_conn`
    /// ([`ConnCloseView`]) rather than a direct trait impl. Proves the wiring still holds.
    #[tokio::test]
    async fn set_deadline_through_old_conn_bridge_reaches_self_close() {
        let (w_local, _w_remote) = tokio::io::duplex(64);
        let (r_local, _r_remote) = tokio::io::duplex(64);
        let conn =
            Conn::new(Box::pin(TestWriter(w_local)), Box::pin(TestReader(r_local)), Arc::new(NetAddr::default()));

        let closed = Arc::new(AtomicBool::new(false));
        let closed_flag = Arc::clone(&closed);
        conn.set_on_close(Box::new(move || {
            closed_flag.store(true, Ordering::SeqCst);
        }));

        let bridged: Box<dyn GoConn> = Box::new(StreamAsOldConn::new(conn));
        bridged.set_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(30))).expect("set_deadline");

        let waited = tokio::time::timeout(Duration::from_secs(5), async {
            while !closed.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            waited.is_ok(),
            "SetDeadline through the old-Conn bridge must still self-close after the deadline, \
             matching the deadline-triggered self-close"
        );
    }
}

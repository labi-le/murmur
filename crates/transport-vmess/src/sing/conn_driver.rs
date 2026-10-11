//! Generic boxed-future-driven-by-`poll_*` conn wrapper, the same shape `client::Conn` and
//! `transport::vmess::conn::Conn` each hand-write for their own state (see either module's doc for
//! why: a multi-`await` handshake cannot run inside one `poll_read`/`poll_write` call, which only
//! ever holds `Pin<&mut Self>` for that one call). [`service::Inner`] and [`xudp::Inner`] reuse
//! this generic version instead of two more copies.
//!
//! The read and write halves get independent `Arc<tokio::sync::Mutex<_>>`es (matching
//! `client::Conn`'s split — see its doc): sharing one would let a pending read that is lazily
//! waiting on the peer (a deferred response/request write, or simply the next chunk) starve out
//! the write that would unblock it, whenever a caller drives both directions from one `poll()`
//! (as `tokio::io::copy_bidirectional` and hyper's H1 client both do).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex as SyncMutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;

use murmur_common::shared_conn::SharedConn as VmessSharedConn;
use murmur_common_net::io::Stream;
use murmur_std_compat::net::Conn as NetConn;

pub(crate) trait DriveRead: Send + 'static {
    fn read<'a>(&'a mut self, b: &'a mut [u8]) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;
}

pub(crate) trait DriveWrite: Send + 'static {
    fn write<'a>(&'a mut self, b: &'a [u8]) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;
}

/// The driven conn behind a lock held only for one `poll_read`/`poll_write`/admin call at a time,
/// shared between [`DriveRead`]/[`DriveWrite`] implementors via [`ConnHandle`] so each can drive
/// its own multi-`.await` state machine independently of the other.
pub(crate) struct SharedConn(SyncMutex<Box<dyn Stream>>);

impl SharedConn {
    pub(crate) fn new(conn: Box<dyn Stream>) -> Arc<Self> {
        Arc::new(Self(SyncMutex::new(conn)))
    }
}

#[derive(Clone)]
pub(crate) struct ConnHandle(Arc<SharedConn>);

impl From<Arc<SharedConn>> for ConnHandle {
    fn from(shared: Arc<SharedConn>) -> Self {
        Self(shared)
    }
}

impl AsyncRead for ConnHandle {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.0 .0.lock();
        Pin::new(&mut **guard).poll_read(cx, buf)
    }
}

impl AsyncWrite for ConnHandle {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut guard = self.0 .0.lock();
        Pin::new(&mut **guard).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.0 .0.lock();
        Pin::new(&mut **guard).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.0 .0.lock();
        Pin::new(&mut **guard).poll_shutdown(cx)
    }
}

type ReadFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;
type WriteFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;

/// The driven conn's real close/deadline capability, kept alive outside [`SharedConn`]'s
/// `SyncMutex` (whose guard cannot outlive an `old_conn()` call) so [`Driven::old_conn`] can hand
/// out a stable reference. Wraps the same conn [`SharedConn`] wraps (via `OldConnAsStream`), so
/// its `close`/`close_read`/`close_write`/deadline setters are exactly that conn's own — for the
/// sing client `Conn` this carries in `packetaddr`/`xudp`, `close` really closes the vmess TCP
/// connection while `close_read`/`close_write` stay its own no-op defaults, unchanged.
pub(crate) struct Driven<R: DriveRead, W: DriveWrite> {
    shared: Arc<SharedConn>,
    close_handle: VmessSharedConn,
    read_state: Arc<AsyncMutex<R>>,
    write_state: Arc<AsyncMutex<W>>,
    read: SyncMutex<Option<ReadFuture>>,
    write: SyncMutex<Option<WriteFuture>>,
    read_buf: SyncMutex<Vec<u8>>,
    write_buf: SyncMutex<Vec<u8>>,
}

impl<R: DriveRead, W: DriveWrite> Driven<R, W> {
    pub(crate) fn new(shared: Arc<SharedConn>, close_handle: VmessSharedConn, read: R, write: W) -> Self {
        Self {
            shared,
            close_handle,
            read_state: Arc::new(AsyncMutex::new(read)),
            write_state: Arc::new(AsyncMutex::new(write)),
            read: SyncMutex::new(None),
            write: SyncMutex::new(None),
            read_buf: SyncMutex::new(Vec::new()),
            write_buf: SyncMutex::new(Vec::new()),
        }
    }
}

impl<R: DriveRead, W: DriveWrite> AsyncRead for Driven<R, W> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut read = this.read.lock();
        if read.is_none() {
            let state = Arc::clone(&this.read_state);
            let mut tmp = std::mem::take(&mut *this.read_buf.lock());
            tmp.clear();
            tmp.resize(buf.remaining(), 0);
            *read = Some(Box::pin(async move {
                let mut guard = state.lock().await;
                let result = guard.read(&mut tmp).await;
                drop(guard);
                (tmp, result)
            }));
        }
        let Some(future) = read.as_mut() else {
            return Poll::Ready(Err(io::Error::other("vmess: read future not installed")));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready((tmp, result)) => {
                *read = None;
                drop(read);
                match result {
                    Ok(n) => {
                        let (chunk, _) = tmp.split_at(n);
                        buf.put_slice(chunk);
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

impl<R: DriveRead, W: DriveWrite> AsyncWrite for Driven<R, W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut write = this.write.lock();
        if write.is_none() {
            let state = Arc::clone(&this.write_state);
            let mut data = std::mem::take(&mut *this.write_buf.lock());
            data.clear();
            data.extend_from_slice(buf);
            *write = Some(Box::pin(async move {
                let mut guard = state.lock().await;
                let result = guard.write(&data).await;
                drop(guard);
                (data, result)
            }));
        }
        let Some(future) = write.as_mut() else {
            return Poll::Ready(Err(io::Error::other("vmess: write future not installed")));
        };
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
        let mut guard = this.shared.0.lock();
        Pin::new(&mut **guard).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut guard = this.shared.0.lock();
        Pin::new(&mut **guard).poll_shutdown(cx)
    }
}

impl<R: DriveRead, W: DriveWrite> Stream for Driven<R, W> {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self.shared.0.try_lock() {
            Some(guard) => guard.local_addr(),
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "vmess conn busy")),
        }
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self.shared.0.try_lock() {
            Some(guard) => guard.peer_addr(),
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "vmess conn busy")),
        }
    }

    fn shutdown_read(&self) -> io::Result<()> {
        match self.shared.0.try_lock() {
            Some(guard) => guard.shutdown_read(),
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "vmess conn busy")),
        }
    }

    fn shutdown_write(&self) -> io::Result<()> {
        match self.shared.0.try_lock() {
            Some(guard) => guard.shutdown_write(),
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "vmess conn busy")),
        }
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(&self.close_handle)
    }
}

impl<R: DriveRead, W: DriveWrite> std::fmt::Debug for Driven<R, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("sing::Driven").finish_non_exhaustive()
    }
}

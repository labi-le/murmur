//! A cloneable handle over one conn, exposing the read/write/close surface [`Conn`] declares.
//!
//! `SharedConn`, split out of `common::net::context` (crate split: this type's base
//! read/write/close surface only needs [`murmur_compat::sing_buf`], but `murmur-sing`'s `uot`
//! also needs a cloneable shared conn handle and cannot depend on `common::net` (`common::net`
//! already depends on `murmur-sing` normally). `common::net::context` keeps the `UpstreamNode`
//! and `common::net::sing::ExtendedConn` impls, which do need `common::net::sing` internals.
//!
//! [`Conn`] mirrors `murmur_std_compat::net::Conn`'s shape (still `Box<dyn Addr>`, still real
//! deadline setters). The blanket impl below keeps every existing `murmur_std_compat::net::Conn`
//! caller compiling; the `Addr`-shaped surface here is intentionally not retyped and stays
//! until a later S11 unit removes `murmur_std_compat` from the workspace. The native `Stream` impl for
//! this type lives in [`crate::net`], next to the contract it implements.

use std::fmt;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_compat::sing_buf::Buffer;
use murmur_std_compat::net::Addr;

// S11: remove in U8, when the final net bridge is deleted.
/// Local mirror of `murmur_std_compat::net::Conn`'s shape.
pub trait Conn: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>>;
    fn remote_addr(&self) -> io::Result<Box<dyn Addr>>;
    fn close(&self) -> io::Result<()>;
    fn close_read(&self) -> io::Result<()>;
    fn close_write(&self) -> io::Result<()>;
    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
}

// S11: remove in U8, when the final net bridge is deleted.
impl<T: murmur_std_compat::net::Conn + ?Sized> Conn for T {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        murmur_std_compat::net::Conn::local_addr(self)
    }
    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        murmur_std_compat::net::Conn::remote_addr(self)
    }
    fn close(&self) -> io::Result<()> {
        murmur_std_compat::net::Conn::close(self)
    }
    fn close_read(&self) -> io::Result<()> {
        murmur_std_compat::net::Conn::close_read(self)
    }
    fn close_write(&self) -> io::Result<()> {
        murmur_std_compat::net::Conn::close_write(self)
    }
    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        murmur_std_compat::net::Conn::set_deadline(self, deadline)
    }
    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        murmur_std_compat::net::Conn::set_read_deadline(self, deadline)
    }
    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        murmur_std_compat::net::Conn::set_write_deadline(self, deadline)
    }
}

/// A shared handle over one conn. The context setup's `AfterFunc` closes the conn as the caller
/// reads it, which in Rust needs a cloneable handle over the same conn.
#[derive(Clone)]
pub struct SharedConn {
    inner: Arc<SharedConnInner>,
}

struct SharedConnInner {
    conn: Mutex<SharedBox>,
}

/// The conn behind the mutex, in whichever shape the caller already had it.
///
/// Two arms are needed because `Box<dyn murmur_std_compat::net::Conn>` cannot be unsized to
/// `Box<dyn Conn>`: the blanket impl above is not a declared supertrait relation, so rustc offers
/// no `Unsize` candidate.
enum SharedBox {
    Conn(Box<dyn Conn>),
    OldConn(Box<dyn murmur_std_compat::net::Conn>),
}

impl Conn for SharedBox {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        match self {
            Self::Conn(conn) => conn.local_addr(),
            Self::OldConn(conn) => conn.local_addr(),
        }
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        match self {
            Self::Conn(conn) => conn.remote_addr(),
            Self::OldConn(conn) => conn.remote_addr(),
        }
    }

    fn close(&self) -> io::Result<()> {
        match self {
            Self::Conn(conn) => conn.close(),
            Self::OldConn(conn) => conn.close(),
        }
    }

    fn close_read(&self) -> io::Result<()> {
        match self {
            Self::Conn(conn) => conn.close_read(),
            Self::OldConn(conn) => conn.close_read(),
        }
    }

    fn close_write(&self) -> io::Result<()> {
        match self {
            Self::Conn(conn) => conn.close_write(),
            Self::OldConn(conn) => conn.close_write(),
        }
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self {
            Self::Conn(conn) => conn.set_deadline(deadline),
            Self::OldConn(conn) => conn.set_deadline(deadline),
        }
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self {
            Self::Conn(conn) => conn.set_read_deadline(deadline),
            Self::OldConn(conn) => conn.set_read_deadline(deadline),
        }
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self {
            Self::Conn(conn) => conn.set_write_deadline(deadline),
            Self::OldConn(conn) => conn.set_write_deadline(deadline),
        }
    }
}

impl AsyncRead for SharedBox {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match &mut *self.get_mut() {
            Self::Conn(conn) => Pin::new(&mut **conn).poll_read(cx, buf),
            Self::OldConn(conn) => Pin::new(&mut **conn).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SharedBox {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match &mut *self.get_mut() {
            Self::Conn(conn) => Pin::new(&mut **conn).poll_write(cx, buf),
            Self::OldConn(conn) => Pin::new(&mut **conn).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self.get_mut() {
            Self::Conn(conn) => Pin::new(&mut **conn).poll_flush(cx),
            Self::OldConn(conn) => Pin::new(&mut **conn).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self.get_mut() {
            Self::Conn(conn) => Pin::new(&mut **conn).poll_shutdown(cx),
            Self::OldConn(conn) => Pin::new(&mut **conn).poll_shutdown(cx),
        }
    }
}

impl fmt::Debug for SharedConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedConn").finish_non_exhaustive()
    }
}

impl SharedConn {
    pub fn new<C: Conn + 'static>(conn: C) -> Self {
        Self::from_box(SharedBox::Conn(Box::new(conn)))
    }

    /// Takes over a conn the caller has already boxed, which [`Self::new`] would otherwise wrap in
    /// a second `Box` and cost an extra allocation plus a vtable hop on every operation.
    #[must_use]
    pub fn from_boxed(conn: Box<dyn murmur_std_compat::net::Conn>) -> Self {
        Self::from_box(SharedBox::OldConn(conn))
    }

    fn from_box(conn: SharedBox) -> Self {
        Self { inner: Arc::new(SharedConnInner { conn: Mutex::new(conn) }) }
    }

    fn lock(&self) -> parking_lot::MutexGuard<'_, SharedBox> {
        self.inner.conn.lock()
    }

    pub fn close(&self) -> io::Result<()> {
        self.lock().close()
    }

    pub fn close_read(&self) -> io::Result<()> {
        self.lock().close_read()
    }

    pub fn close_write(&self) -> io::Result<()> {
        self.lock().close_write()
    }

    pub fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.lock().local_addr()
    }

    pub fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.lock().remote_addr()
    }

    pub fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.lock().set_deadline(deadline)
    }

    pub fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.lock().set_read_deadline(deadline)
    }

    pub fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.lock().set_write_deadline(deadline)
    }

    /// One read; the lock is held only across the poll, never across a suspension.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        // cancel-safe: the inner poll either completes or leaves `buf` untouched.
        poll_fn(|cx| {
            let mut conn = self.lock();
            let mut read_buf = ReadBuf::new(buf);
            match Pin::new(&mut *conn).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            }
        })
        .await
    }

    pub async fn read_buffer(&self, buffer: &mut Buffer) -> io::Result<()> {
        // cancel-safe: `truncate` runs only after a completed poll, so a dropped call leaves the
        // buffer's length unchanged.
        poll_fn(|cx| {
            let mut conn = self.lock();
            let n = {
                let mut read_buf = ReadBuf::new(buffer.free_bytes());
                match Pin::new(&mut *conn).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => read_buf.filled().len(),
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            };
            buffer.truncate(n);
            Poll::Ready(Ok(()))
        })
        .await
    }

    pub async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        // NOT cancel-safe: `written` is local to this call, so a dropped call loses the offset and
        // a retry re-sends the bytes the conn already took.
        let mut written = 0;
        poll_fn(|cx| {
            let mut conn = self.lock();
            while written < buf.len() {
                let rest = buf.get(written..).unwrap_or_default();
                match Pin::new(&mut *conn).poll_write(cx, rest) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(n)) => written += n,
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }
            Poll::Ready(Ok(()))
        })
        .await
    }
}

impl AsyncRead for SharedConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().lock();
        Pin::new(&mut *conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for SharedConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut conn = self.get_mut().lock();
        Pin::new(&mut *conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().lock();
        Pin::new(&mut *conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().lock();
        Pin::new(&mut *conn).poll_shutdown(cx)
    }
}

// S11: remove in U8, when the final net bridge is deleted.
impl murmur_std_compat::net::Conn for SharedConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Self::local_addr(self)
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Self::remote_addr(self)
    }

    fn close(&self) -> io::Result<()> {
        Self::close(self)
    }

    fn close_read(&self) -> io::Result<()> {
        Self::close_read(self)
    }

    fn close_write(&self) -> io::Result<()> {
        Self::close_write(self)
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Self::set_deadline(self, deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Self::set_read_deadline(self, deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Self::set_write_deadline(self, deadline)
    }
}

// S11: remove in U8, when the final net bridge is deleted.
impl murmur_std_compat::net::ExtendedConn for SharedConn {
    fn upstream(&self) -> Option<&dyn std::any::Any> {
        None
    }
}

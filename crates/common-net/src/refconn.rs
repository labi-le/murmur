use std::any::Any;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_compat::sing_buf::Buffer;
use murmur_std_compat::net::{Addr, Conn, ExtendedConn as NetExtendedConn, TcpAddr};

use crate::io::{close_stream, ExtendedStream, Stream};

use super::sing::{new_extended_conn, ExtendedConn, UpstreamNode};

/// Keeps a handle alive for as long as the conn is used.
pub struct RefConn {
    conn: Box<dyn ExtendedConn>,
    #[allow(
        dead_code,
        reason = "keeps the source handle alive for RefConn's lifetime; Rust ownership does the runtime.KeepAlive(c.ref) job"
    )]
    ref_: Arc<dyn Any + Send + Sync>,
}

impl fmt::Debug for RefConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefConn").finish_non_exhaustive()
    }
}

impl RefConn {
    fn new(conn: Box<dyn ExtendedConn>, ref_: Arc<dyn Any + Send + Sync>) -> Self {
        Self { conn, ref_ }
    }
}

impl AsyncRead for RefConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for RefConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_shutdown(cx)
    }
}

impl Conn for RefConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.conn.local_addr()?)))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.conn.peer_addr()?)))
    }

    fn close(&self) -> io::Result<()> {
        close_stream(&*self.conn)
    }

    fn close_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.old_conn().map_or(Ok(()), |inner| inner.set_deadline(deadline))
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.old_conn().map_or(Ok(()), |inner| inner.set_read_deadline(deadline))
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.old_conn().map_or(Ok(()), |inner| inner.set_write_deadline(deadline))
    }
}

impl Stream for RefConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.conn.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.conn.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }
    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(self)
    }
}

impl ExtendedStream for RefConn {
    fn reader_replaceable(&self) -> bool {
        NetExtendedConn::reader_replaceable(self)
    }
    fn writer_replaceable(&self) -> bool {
        NetExtendedConn::writer_replaceable(self)
    }
}

impl NetExtendedConn for RefConn {
    fn reader_replaceable(&self) -> bool {
        true
    }

    fn writer_replaceable(&self) -> bool {
        true
    }
}

impl UpstreamNode for RefConn {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&*self.conn)
    }

    /// The node walk sees no conn trait, so the replaceable flags are repeated here.
    fn reader_replaceable(&self) -> Option<bool> {
        Some(NetExtendedConn::reader_replaceable(self))
    }

    fn writer_replaceable(&self) -> Option<bool> {
        Some(NetExtendedConn::writer_replaceable(self))
    }
}

#[async_trait]
impl ExtendedConn for RefConn {
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        self.conn.read_buffer(buffer).await
    }

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        self.conn.write_buffer(buffer).await
    }
}

/// Wraps a stream with a ref. A caller that already holds a `Box<dyn ExtendedConn>` is the
/// pass-through branch of `new_extended_conn` and keeps it.
pub fn new_ref_conn<C: Stream + 'static>(conn: C, ref_: Arc<dyn Any + Send + Sync>) -> Box<dyn ExtendedConn> {
    Box::new(RefConn::new(new_extended_conn(conn), ref_))
}

/// Like [`new_ref_conn`], for a caller that already holds a `Box<dyn ExtendedConn>` (Stream-shaped)
/// instead of the old `Box<dyn Conn>`.
pub fn new_ref_extended_conn(conn: Box<dyn ExtendedConn>, ref_: Arc<dyn Any + Send + Sync>) -> Box<dyn ExtendedConn> {
    Box::new(RefConn::new(conn, ref_))
}

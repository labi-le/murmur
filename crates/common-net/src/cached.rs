use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_compat::sing_buf::{as_, Buffer};
use murmur_std_compat::net::{Addr, Conn, ExtendedConn as NetExtendedConn, TcpAddr};

use crate::io::{close_stream, ExtendedStream, Stream};

use super::sing::{new_extended_conn, new_extended_conn_from_node, CachedReader, ExtendedConn, UpstreamNode};

pub struct CachedConn {
    extended_conn: Box<dyn ExtendedConn>,
    data: Bytes,
}

impl fmt::Debug for CachedConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedConn").field("data", &self.data).finish_non_exhaustive()
    }
}

pub fn new_cached_conn<C: Stream + 'static>(conn: C, data: Vec<u8>) -> CachedConn {
    CachedConn { extended_conn: new_extended_conn(conn), data: Bytes::from(data) }
}

/// Like [`new_cached_conn`], for a caller holding a value that is also a [`UpstreamNode`]: keeps
/// the wrapped conn discoverable through the node walk instead of erasing it.
pub fn new_cached_conn_from_node<C: Stream + UpstreamNode + 'static>(conn: C, data: Vec<u8>) -> CachedConn {
    CachedConn { extended_conn: new_extended_conn_from_node(conn), data: Bytes::from(data) }
}

impl AsyncRead for CachedConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.data.is_empty() {
            let n = core::cmp::min(buf.remaining(), this.data.len());
            buf.put_slice(this.data.get(..n).unwrap_or_default());
            let _ = this.data.split_to(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *this.extended_conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for CachedConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().extended_conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().extended_conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().extended_conn).poll_shutdown(cx)
    }
}

impl Conn for CachedConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.extended_conn.local_addr()?)))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.extended_conn.peer_addr()?)))
    }

    fn close(&self) -> io::Result<()> {
        close_stream(&*self.extended_conn)
    }

    fn close_read(&self) -> io::Result<()> {
        self.extended_conn.shutdown_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.extended_conn.shutdown_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.extended_conn.old_conn().map_or(Ok(()), |inner| inner.set_deadline(deadline))
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.extended_conn.old_conn().map_or(Ok(()), |inner| inner.set_read_deadline(deadline))
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.extended_conn.old_conn().map_or(Ok(()), |inner| inner.set_write_deadline(deadline))
    }
}

impl NetExtendedConn for CachedConn {
    fn reader_replaceable(&self) -> bool {
        self.data.is_empty()
    }

    fn writer_replaceable(&self) -> bool {
        true
    }
}

impl UpstreamNode for CachedConn {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&*self.extended_conn)
    }

    /// The node walk sees no conn trait, so the two replaceable flags are repeated here.
    fn reader_replaceable(&self) -> Option<bool> {
        Some(NetExtendedConn::reader_replaceable(self))
    }

    fn writer_replaceable(&self) -> Option<bool> {
        Some(NetExtendedConn::writer_replaceable(self))
    }
}

impl Stream for CachedConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.extended_conn.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.extended_conn.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.extended_conn.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.extended_conn.shutdown_write()
    }
    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(self)
    }
}

impl ExtendedStream for CachedConn {
    fn reader_replaceable(&self) -> bool {
        NetExtendedConn::reader_replaceable(self)
    }
    fn writer_replaceable(&self) -> bool {
        NetExtendedConn::writer_replaceable(self)
    }
}

#[async_trait]
impl ExtendedConn for CachedConn {
    /// Promotes to the inner conn's implementation, so the cached bytes are not served here.
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        self.extended_conn.read_buffer(buffer).await
    }

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        self.extended_conn.write_buffer(buffer).await
    }
}

impl CachedReader for CachedConn {
    /// Reads through the cached reader.
    fn read_cached(&mut self) -> Option<Buffer> {
        if !self.data.is_empty() {
            let data = core::mem::take(&mut self.data);
            return Some(as_(data.to_vec()));
        }
        None
    }
}

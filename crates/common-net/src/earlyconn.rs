use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common::once::once_native::{done, Once};
use murmur_compat::sing_buf::Buffer;
use murmur_std_compat::net::{Addr, Conn, ExtendedConn as NetExtendedConn, TcpAddr};

use crate::io::{close_stream, ExtendedStream, Stream};

use super::sing::{new_extended_conn, ExtendedConn, UpstreamNode};

/// the response error kept for every later read; `anyhow::Error` is not `Clone`.
#[derive(Debug, Clone)]
pub struct SharedError(Arc<anyhow::Error>);

impl fmt::Display for SharedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SharedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let err: &anyhow::Error = &self.0;
        Some(err.as_ref())
    }
}

/// The response callback of an early-conn connection.
///
/// It is polled rather than called synchronously while the read blocks, so a callback that reads
/// from the conn is a state machine driving the conn it is handed.
pub trait EarlyConnResponse: Send + Sync {
    fn poll_response(&mut self, cx: &mut Context<'_>, conn: &mut dyn ExtendedConn) -> Poll<anyhow::Result<()>>;
}

// Compatibility bridge: a caller's poll closure is the response callback.
impl<F> EarlyConnResponse for F
where
    F: FnMut(&mut Context<'_>, &mut dyn ExtendedConn) -> Poll<anyhow::Result<()>> + Send + Sync,
{
    fn poll_response(&mut self, cx: &mut Context<'_>, conn: &mut dyn ExtendedConn) -> Poll<anyhow::Result<()>> {
        self(cx, conn)
    }
}

pub struct EarlyConnImpl {
    extended_conn: Box<dyn ExtendedConn>,
    res_func: Option<Box<dyn EarlyConnResponse>>,
    res_once: Once,
    res_err: Option<Arc<anyhow::Error>>,
}

impl EarlyConnImpl {
    fn new(conn: Box<dyn ExtendedConn>, res_func: Box<dyn EarlyConnResponse>) -> Self {
        Self { extended_conn: conn, res_func: Some(res_func), res_once: Once::new(), res_err: None }
    }

    fn finish(&mut self, err: Option<anyhow::Error>) {
        self.res_func = None;
        self.res_err = err.map(Arc::new);
        self.res_once.call_once(|| {});
    }

    pub async fn response(&mut self) -> Result<(), SharedError> {
        poll_fn(|cx| self.poll_response(cx)).await
    }

    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SharedError>> {
        if done(&self.res_once) {
            return Poll::Ready(self.stored_response());
        }
        let Some(res_func) = self.res_func.as_mut() else {
            return Poll::Ready(self.stored_response());
        };
        match res_func.poll_response(cx, &mut *self.extended_conn) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                self.finish(None);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                self.finish(Some(err));
                Poll::Ready(self.stored_response())
            }
        }
    }

    fn stored_response(&self) -> Result<(), SharedError> {
        match &self.res_err {
            Some(err) => Err(SharedError(Arc::clone(err))),
            None => Ok(()),
        }
    }

    pub fn success(&self) -> bool {
        done(&self.res_once) && self.res_err.is_none()
    }
}

impl fmt::Debug for EarlyConnImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EarlyConnImpl").field("success", &self.success()).finish_non_exhaustive()
    }
}

impl AsyncRead for EarlyConnImpl {
    /// Reads, answering the response error before the read.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_response(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(io::Error::other(err))),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut *this.extended_conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for EarlyConnImpl {
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

impl Conn for EarlyConnImpl {
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

impl Stream for EarlyConnImpl {
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

impl ExtendedStream for EarlyConnImpl {
    fn reader_replaceable(&self) -> bool {
        NetExtendedConn::reader_replaceable(self)
    }
    fn writer_replaceable(&self) -> bool {
        NetExtendedConn::writer_replaceable(self)
    }
}

impl NetExtendedConn for EarlyConnImpl {
    fn reader_replaceable(&self) -> bool {
        self.success()
    }

    fn writer_replaceable(&self) -> bool {
        true
    }
}

impl UpstreamNode for EarlyConnImpl {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&*self.extended_conn)
    }

    /// The node walk sees no conn trait, so the replaceable flags are repeated here.
    fn reader_replaceable(&self) -> Option<bool> {
        Some(NetExtendedConn::reader_replaceable(self))
    }

    fn writer_replaceable(&self) -> Option<bool> {
        Some(NetExtendedConn::writer_replaceable(self))
    }

    fn reader_possibly_replaceable(&self) -> bool {
        !self.success()
    }
}

#[async_trait]
impl ExtendedConn for EarlyConnImpl {
    /// Reads a buffer, answering the response error before the read.
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        if let Err(err) = self.response().await {
            return Err(io::Error::other(err));
        }
        self.extended_conn.read_buffer(buffer).await
    }

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        self.extended_conn.write_buffer(buffer).await
    }
}

pub fn new_early_conn<C: Stream + 'static>(
    conn: C,
    res_func: impl EarlyConnResponse + 'static,
) -> Box<dyn ExtendedConn> {
    Box::new(EarlyConnImpl::new(new_extended_conn(conn), Box::new(res_func)))
}

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use murmur_common_net::io::{ExtendedStream, Stream};
use murmur_common_net::sing::{ExtendedConn, UpstreamNode};
use murmur_compat::sing_buf::Buffer;
use murmur_constant::adapters::{Chain, Conn as ConstantConn, ProxyAdapter};

/// The callback shape: `None` is the no-error case. `io::Error`
/// is not `Clone`, so the callback receives an error rebuilt from the write's kind and message.
pub type Callback = Box<dyn Fn(Option<anyhow::Error>) + Send + Sync>;

struct FirstWriteCallBackConn {
    conn: Box<dyn ConstantConn>,
    callback: Callback,
    written: bool,
}

impl FirstWriteCallBackConn {
    /// Fires the callback on the first write, with the write's error when it failed.
    fn fire(&mut self, err: Option<&io::Error>) {
        if !self.written {
            self.written = true;
            (self.callback)(err.map(|err| anyhow::Error::new(io::Error::new(err.kind(), err.to_string()))));
        }
    }
}

impl AsyncRead for FirstWriteCallBackConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for FirstWriteCallBackConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut *this.conn).poll_write(cx, buf) {
            Poll::Ready(result) => {
                this.fire(result.as_ref().err());
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_shutdown(cx)
    }
}

impl Stream for FirstWriteCallBackConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.conn.as_socket()
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn.old_conn()
    }
}

impl ExtendedStream for FirstWriteCallBackConn {
    fn reader_replaceable(&self) -> bool {
        true
    }

    fn writer_replaceable(&self) -> bool {
        self.written
    }
}

impl UpstreamNode for FirstWriteCallBackConn {
    fn reader_replaceable(&self) -> Option<bool> {
        Some(true)
    }

    fn writer_replaceable(&self) -> Option<bool> {
        Some(self.written)
    }
}

impl murmur_constant::adapters::Connection for FirstWriteCallBackConn {
    fn chains(&self) -> Chain {
        self.conn.chains()
    }

    fn provider_chains(&self) -> Chain {
        self.conn.provider_chains()
    }

    fn append_to_chains(&self, adapter: Arc<dyn ProxyAdapter>) {
        self.conn.append_to_chains(adapter);
    }

    fn remote_destination(&self) -> String {
        self.conn.remote_destination()
    }
}

#[async_trait]
impl ExtendedConn for FirstWriteCallBackConn {
    /// Reads into the buffer, which the erased conn cannot reach; the read
    /// goes through the async half, as `common::net::sing` does on an erased conn.
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        match self.conn.read(buffer.free_bytes()).await {
            Ok(n) => {
                buffer.truncate(n);
                Ok(())
            }
            Err(err) => {
                buffer.truncate(0);
                Err(err)
            }
        }
    }

    /// Writes the buffer; see [`Self::read_buffer`].
    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        let result = self.conn.write_all(buffer.bytes()).await;
        buffer.release();
        self.fire(result.as_ref().err());
        result
    }
}

#[must_use]
pub fn new_first_write_call_back_conn(c: Box<dyn ConstantConn>, callback: Callback) -> Box<dyn ConstantConn> {
    Box::new(FirstWriteCallBackConn { conn: c, callback, written: false })
}

//! The server-side conns prepend a one-byte status (success/error) to the first
//! outbound write only.
//!
//! Every later write and every read pass straight through. That asymmetry means only the write
//! side needs handshake state — read is stateless from the very first byte — so unlike
//! [`crate::client_conn`] there is no response to await and no persisted in-flight future to keep
//! across `Pending` polls: the prepended header and the caller's payload always go out as one
//! write, or the write hasn't happened yet.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;

use crate::protocol::{read_addr_port, STATUS_SUCCESS};
use crate::session::MuxStream;
use murmur_compat::sing_buf::Buffer;
use murmur_sing::metadata::{Socksaddr, SOCKSADDR_SERIALIZER};
use murmur_sing::network::{PacketConn as SingPacketConn, PacketReader, PacketWriter};
use murmur_std_compat::net::Addr;

pub struct ServerConn {
    inner: Box<dyn MuxStream>,
    response_written: bool,
    pending: Vec<u8>,
    pending_written: usize,
}

impl core::fmt::Debug for ServerConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerConn")
            .field("response_written", &self.response_written)
            .field("pending_len", &self.pending.len())
            .field("pending_written", &self.pending_written)
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn new_server_conn(stream: Box<dyn MuxStream>) -> ServerConn {
    ServerConn { inner: stream, response_written: false, pending: Vec::new(), pending_written: 0 }
}

impl ServerConn {
    pub async fn handshake_failure(&mut self, message: &str) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let mut buffer = vec![crate::protocol::STATUS_ERROR];
        crate::protocol::write_vstring(&mut buffer, message);
        self.inner.write_all(&buffer).await
    }

    fn drive_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        while self.pending_written < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, self.pending.split_at(self.pending_written).1) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    self.pending_written += n;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let payload_len = self.pending.len() - usize::from(!self.response_written);
        self.response_written = true;
        self.pending.clear();
        self.pending_written = 0;
        Poll::Ready(Ok(payload_len))
    }
}

impl AsyncRead for ServerConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ServerConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.pending.is_empty() {
            return this.drive_pending(cx);
        }
        if this.response_written {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        this.pending.push(STATUS_SUCCESS);
        this.pending.extend_from_slice(buf);
        this.drive_pending(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.pending.is_empty() {
            match this.drive_pending(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.pending.is_empty() {
            match this.drive_pending(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// The server packet conn and packet-addr conn, folded into one type the same way
/// [`crate::client_conn::ClientPacketConn`] folds its client-side counterparts.
pub struct ServerPacketConn {
    inner: AsyncMutex<Box<dyn MuxStream>>,
    destination: Socksaddr,
    packet_addr: bool,
    response_written: std::sync::atomic::AtomicBool,
}

impl core::fmt::Debug for ServerPacketConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerPacketConn")
            .field("destination", &self.destination)
            .field("packet_addr", &self.packet_addr)
            .field("response_written", &self.response_written)
            .finish_non_exhaustive()
    }
}

/// `&serverPacketConn{...}`/`&serverPacketAddrConn{...}`.
#[must_use]
pub fn new_server_packet_conn(
    stream: Box<dyn MuxStream>,
    destination: Socksaddr,
    packet_addr: bool,
) -> ServerPacketConn {
    ServerPacketConn {
        inner: AsyncMutex::new(stream),
        destination,
        packet_addr,
        response_written: std::sync::atomic::AtomicBool::new(false),
    }
}

#[async_trait]
impl PacketReader for ServerPacketConn {
    /// Reads one packet from the stream.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the stream is borrowed out of the locked slot and driven across the awaited reads, so the guard has to span the whole packet"
    )]
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        use tokio::io::AsyncReadExt;
        let mut inner = self.inner.lock().await;
        let destination = if self.packet_addr { read_addr_port(&mut *inner).await? } else { self.destination.clone() };
        let mut length = [0u8; 2];
        inner.read_exact(&mut length).await?;
        let length = u16::from_be_bytes(length) as usize;
        buffer.read_full_from(&mut *inner, length).await?;
        Ok(destination)
    }
}

#[async_trait]
impl PacketWriter for ServerPacketConn {
    /// Writes one packet to the stream.
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        use std::sync::atomic::Ordering;
        use tokio::io::AsyncWriteExt;
        let mut frame = Vec::new();
        if !self.response_written.swap(true, Ordering::AcqRel) {
            frame.push(STATUS_SUCCESS);
        }
        if self.packet_addr {
            SOCKSADDR_SERIALIZER.write_addr_port(&mut frame, destination)?;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the per-packet length is the 16-bit prefix the wire format defines, and a UDP payload never exceeds it"
        )]
        frame.extend_from_slice(&(buffer.len() as u16).to_be_bytes());
        frame.extend_from_slice(buffer.bytes());
        self.inner.lock().await.write_all(&frame).await
    }
}

#[async_trait]
impl SingPacketConn for ServerPacketConn {
    async fn close(&self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.inner.lock().await.shutdown().await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "sing-mux server packet conn has no local addr"))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn server_conn_prepends_status_once() {
        let (client, server) = duplex(4096);
        let mut server_conn = new_server_conn(Box::new(server));
        let mut client = client;

        server_conn.write_all(b"hello").await.unwrap();
        server_conn.write_all(b" world").await.unwrap();

        let mut buf = vec![0u8; 1 + 5 + 6];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], STATUS_SUCCESS);
        assert_eq!(&buf[1..], b"hello world");
    }
}

//! The packet-I/O surface over a tunnel: whole-packet reads and writes, and the write failures
//! that are recoverable.

use std::fmt;
use std::io;
use std::net::SocketAddr;

use anyhow::{bail, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio_util::sync::CancellationToken;

use crate::control::ErrClosed;
use murmur_common::errors::ErrOsClosed;
use murmur_common_net::io::Stream;
use murmur_common_pool as pool;

pub const ERR_PACKET_DROPPED: &str = "openvpn packet dropped";

/// The packet-dropped sentinel, matched by type.
#[derive(Debug, thiserror::Error)]
#[error("openvpn packet dropped")]
pub(crate) struct ErrPacketDropped;

/// The packet-dropped error: a recoverable single-packet write failure.
#[derive(Debug)]
pub(crate) struct PacketDroppedError {
    pub(crate) cause: anyhow::Error,
}

impl fmt::Display for PacketDroppedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{ERR_PACKET_DROPPED}: {}", self.cause)
    }
}

impl std::error::Error for PacketDroppedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

/// Matches the packet-dropped error by type.
pub(crate) fn is_packet_dropped(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| cause.is::<ErrPacketDropped>() || cause.is::<PacketDroppedError>())
}

pub(crate) fn packet_dropped_error(err: &anyhow::Error) -> Option<&PacketDroppedError> {
    err.chain().find_map(|cause| cause.downcast_ref::<PacketDroppedError>())
}

/// The packet-I/O surface. `read_packet` keeps the two-value shape: a complete packet may be
/// returned together with an error, and the packet precedes the error.
///
/// A datagram read that fails reports no packet, since tokio's `AsyncRead` has no way to hand
/// back a byte count together with an error.
#[async_trait]
pub trait PacketIO: Send + Sync {
    async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>);
    async fn write_packet(&self, packet: &[u8]) -> Result<()>;
    async fn close(&self) -> Result<()>;
    fn local_addr(&self) -> Option<SocketAddr>;
    fn remote_addr(&self) -> Option<SocketAddr>;
}

/// A duplex byte stream that only `Close` can interrupt. The split halves give the reader and
/// the writer independent halves, and the cancellation token stands in for the way a `Close`
/// unblocks an in-flight read or write.
struct PhysicalConn {
    read: tokio::sync::Mutex<Option<ReadHalf<Box<dyn Stream>>>>,
    write: tokio::sync::Mutex<Option<WriteHalf<Box<dyn Stream>>>>,
    closed: CancellationToken,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, ErrClosed)
}

impl PhysicalConn {
    fn new(conn: Box<dyn Stream>) -> Self {
        let local_addr = conn.local_addr().ok();
        let remote_addr = conn.peer_addr().ok();
        let (read, write) = tokio::io::split(conn);
        Self {
            read: tokio::sync::Mutex::new(Some(read)),
            write: tokio::sync::Mutex::new(Some(write)),
            closed: CancellationToken::new(),
            local_addr,
            remote_addr,
        }
    }

    // cancel-safe: `AsyncReadExt::read` stores nothing when it is dropped, and the read-half guard is
    // released with the future.
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self.read.lock().await;
        let Some(half) = guard.as_mut() else {
            return Err(closed_error());
        };
        let result = tokio::select! {
            biased;
            () = self.closed.cancelled() => Err(closed_error()),
            result = half.read(buf) => result,
        };
        drop(guard);
        result
    }

    /// Fills the buffer, including the EOF / unexpected-EOF split.
    async fn read_full(&self, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let (_, rest) = buf.split_at_mut(filled);
            let n = self.read(rest).await?;
            if n == 0 {
                return Err(if filled == 0 {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
                } else {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
                });
            }
            filled += n;
        }
        Ok(())
    }

    // cancel-safe: the write-half guard is released with the future, and a dropped write reports nothing
    // as written.
    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.write.lock().await;
        let Some(half) = guard.as_mut() else {
            return Err(closed_error());
        };
        let result = tokio::select! {
            biased;
            () = self.closed.cancelled() => Err(closed_error()),
            result = half.write(buf) => result,
        };
        drop(guard);
        result
    }

    // cancel-safe: the write-half guard is released with the future, and a dropped flush leaves the
    // buffered bytes for the next one.
    async fn flush(&self) -> io::Result<()> {
        let mut guard = self.write.lock().await;
        let Some(half) = guard.as_mut() else {
            return Err(closed_error());
        };
        let result = tokio::select! {
            biased;
            () = self.closed.cancelled() => Err(closed_error()),
            result = half.flush() => result,
        };
        drop(guard);
        result
    }

    /// the write-all contract, satisfied by writing
    /// until the buffer is drained: a short write is an error.
    async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        let mut written = 0;
        while written < buf.len() {
            let (_, rest) = buf.split_at(written);
            let n = self.write(rest).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
            }
            written += n;
        }
        Ok(())
    }

    async fn close(&self) {
        self.closed.cancel();
        let _ = self.read.lock().await.take();
        let _ = self.write.lock().await.take();
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }
}

struct StreamPacketIO {
    conn: PhysicalConn,
}

struct DatagramPacketIO {
    conn: PhysicalConn,
    recoverable_udp: bool,
}

/// A Rust `Stream` trait object carries no capability probe for a real kernel UDP socket, so
/// the classification comes from the caller instead (see
/// [`new_datagram_packet_io_recoverable`]).
///
/// This constructor is for a conn the caller does not know to be a real kernel UDP socket.
#[must_use]
pub fn new_datagram_packet_io(conn: Box<dyn Stream>) -> Box<dyn PacketIO> {
    boxed_datagram_packet_io(conn, false)
}

/// `new_datagram_packet_io` for a conn the caller dialed as a real UDP socket, whose
/// single-datagram write losses are recoverable.
#[must_use]
pub fn new_datagram_packet_io_recoverable(conn: Box<dyn Stream>) -> Box<dyn PacketIO> {
    boxed_datagram_packet_io(conn, true)
}

fn boxed_datagram_packet_io(conn: Box<dyn Stream>, recoverable_udp: bool) -> Box<dyn PacketIO> {
    Box::new(DatagramPacketIO { conn: PhysicalConn::new(conn), recoverable_udp })
}

#[must_use]
pub fn new_tcp_packet_io(conn: Box<dyn Stream>) -> Box<dyn PacketIO> {
    Box::new(StreamPacketIO { conn: PhysicalConn::new(conn) })
}

#[async_trait]
impl PacketIO for DatagramPacketIO {
    async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>) {
        let mut buf = vec![0u8; 64 * 1024];
        match self.conn.read(&mut buf).await {
            Ok(n) => {
                buf.truncate(n);
                (Some(buf), None)
            }
            Err(err) => (None, Some(err.into())),
        }
    }

    async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        let Err(err) = self.conn.write(packet).await else {
            return Ok(());
        };
        // A partial write would be terminal too, but `io::Result` reports it as `Ok(n)`, so it
        // is not detected here.
        let err = anyhow::Error::new(err);
        if !self.recoverable_udp || terminal_packet_io_error(&err) {
            return Err(err);
        }
        Err(anyhow::Error::new(PacketDroppedError { cause: err }))
    }

    async fn close(&self) -> Result<()> {
        self.conn.close().await;
        Ok(())
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.conn.local_addr()
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.conn.remote_addr()
    }
}

#[async_trait]
impl PacketIO for StreamPacketIO {
    async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>) {
        let mut length = [0u8; 2];
        if let Err(err) = self.conn.read_full(&mut length).await {
            return (None, Some(err.into()));
        }
        let size = usize::from(length[0]) << 8 | usize::from(length[1]);
        if size == 0 {
            return (None, Some(anyhow::anyhow!("empty openvpn TCP packet")));
        }
        let mut packet = vec![0u8; size];
        if let Err(err) = self.conn.read_full(&mut packet).await {
            return (None, Some(err.into()));
        }
        (Some(packet), None)
    }

    async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() > 0xffff {
            bail!("openvpn TCP packet too large: {}", packet.len());
        }
        let len = packet.len();
        #[expect(clippy::cast_possible_truncation, reason = "the 16-bit frame limit is enforced above")]
        let header = [(len >> 8) as u8, len as u8];
        let mut frame = pool::get(2 + len);
        let (head, body) = frame.split_at_mut(2);
        head.copy_from_slice(&header);
        body.copy_from_slice(packet);
        let result = self.conn.write_all(&frame).await;
        let _ = pool::put(frame);
        result?;
        self.conn.flush().await.map_err(anyhow::Error::from)
    }

    async fn close(&self) -> Result<()> {
        self.conn.close().await;
        Ok(())
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.conn.local_addr()
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.conn.remote_addr()
    }
}

/// The terminal packet-I/O error: a closed connection, an expired deadline, or a timeout.
fn terminal_packet_io_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if cause.is::<ErrClosed>() || cause.is::<ErrOsClosed>() {
            return true;
        }
        let Some(io_err) = cause.downcast_ref::<io::Error>() else {
            return false;
        };
        if io_err.kind() == io::ErrorKind::TimedOut {
            return true;
        }
        // `io::Error::source()` forwards to the wrapped custom error's own source rather than
        // that error itself, so a closed-connection error boxed inside a
        // `Custom` io::Error is invisible to `err.chain()`; inspect `get_ref()` directly.
        io_err.get_ref().is_some_and(|err| err.is::<ErrClosed>() || err.is::<ErrOsClosed>())
    })
}

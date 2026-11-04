//! Raw-`recvfrom` zero-copy fast path on a genuine `tokio::net::UdpSocket`, the
//! [`Datagram`]-shaped sibling of `packet_windows.rs`'s `EnhanceUDPConn`. Identity is
//! [`Datagram::as_any`] instead of a `PacketConn` downcast; everything else is unchanged. Not
//! built in this environment; the orchestrator's Windows lint pass covers it (see this unit's
//! report).

use std::io;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use socket2::SockRef;

use murmur_common_pool as pool;

use super::datagram::WaitReadFromDatagram;
use crate::io::{Datagram, UdpAcceptor};

pub(crate) struct EnhanceUdpDatagram {
    udp_conn: Arc<dyn Datagram>,
}

impl EnhanceUdpDatagram {
    pub(crate) fn new(udp_conn: Arc<dyn Datagram>) -> Self {
        Self { udp_conn }
    }

    fn udp_socket(&self) -> io::Result<&tokio::net::UdpSocket> {
        let any = self
            .udp_conn
            .as_any()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "enhance udp datagram: not a udp socket"))?;
        if let Some(socket) = any.downcast_ref::<tokio::net::UdpSocket>() {
            return Ok(socket);
        }
        any.downcast_ref::<UdpAcceptor>()
            .map(UdpAcceptor::raw_socket)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "enhance udp datagram: not a udp socket"))
    }

    fn close_token(&self) -> Option<tokio_util::sync::CancellationToken> {
        self.udp_conn.as_any().and_then(|any| any.downcast_ref::<UdpAcceptor>()).map(UdpAcceptor::close_token)
    }
}

#[async_trait]
impl WaitReadFromDatagram for EnhanceUdpDatagram {
    // cancel-safe: the syscall only runs on readiness, so a drop while closing loses at most one datagram.
    async fn wait_read_from(&self) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<SocketAddr>, io::Result<()>) {
        let socket = match self.udp_socket() {
            Ok(socket) => socket,
            Err(err) => return (Vec::new(), None, None, Err(err)),
        };
        let read = socket.async_io(tokio::io::Interest::READABLE, || {
            let mut read_buf = pool::get(pool::UDP_BUFFER_SIZE);
            match recvfrom(socket, &mut read_buf) {
                Ok((read_n, read_from)) => Ok((read_n, read_from, read_buf)),
                Err(err) => {
                    let _ = pool::put(read_buf);
                    Err(err)
                }
            }
        });
        tokio::pin!(read);
        let result = if let Some(closed) = self.close_token() {
            tokio::select! {
                biased;
                () = closed.cancelled() => Err(io::Error::new(io::ErrorKind::BrokenPipe, "use of closed network connection")),
                result = &mut read => result,
            }
        } else {
            read.await
        };
        match result {
            Ok((read_n, read_from, mut read_buf)) => {
                if read_n > 0 {
                    // Hand the pooled block itself to the caller, truncated to the datagram; the
                    // caller owns it and returns it with `pool::put(data)`. No payload copy and no
                    // callback retaining a second reference to the same allocation.
                    read_buf.truncate(read_n);
                    (read_buf, None, read_from, Ok(()))
                } else {
                    let _ = pool::put(read_buf);
                    (Vec::new(), None, read_from, Ok(()))
                }
            }
            Err(err) => (Vec::new(), None, None, Err(err)),
        }
    }
}

#[async_trait]
impl Datagram for EnhanceUdpDatagram {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.udp_conn.recv_from(buf).await
    }
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.udp_conn.send_to(buf, addr).await
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp_conn.local_addr()
    }
    fn close(&self) -> io::Result<()> {
        self.udp_conn.close()
    }
    fn as_socket(&self) -> Option<SockRef<'_>> {
        self.udp_conn.as_socket()
    }
}

#[expect(unsafe_code, reason = "`SockRef::recv_from` requires a `MaybeUninit` view the safe slice API cannot build")]
fn recvfrom(socket: &tokio::net::UdpSocket, read_buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
    // SAFETY: `read_buf` is writable for its whole length, and `recvfrom` writes at most that many
    // bytes, so the `MaybeUninit` view is fully the slice the syscall may initialise.
    let buf =
        unsafe { std::slice::from_raw_parts_mut(read_buf.as_mut_ptr().cast::<MaybeUninit<u8>>(), read_buf.len()) };
    let (read_n, read_from) = SockRef::from(socket).recv_from(buf)?;
    Ok((read_n, read_from.as_socket()))
}

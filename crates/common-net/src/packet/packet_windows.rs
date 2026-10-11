//! Raw-socket packet I/O for Windows targets.

use std::any::Any;
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use socket2::SockRef;

use murmur_common_pool as pool;
use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};

use super::packet::{ReaderWithUpstream, WaitReadFrom, WithUpstream, WriterWithUpstream};

pub(crate) struct EnhanceUDPConn {
    udp_conn: Arc<dyn PacketConn>,
}

impl EnhanceUDPConn {
    pub(crate) fn new(udp_conn: Arc<dyn PacketConn>) -> Self {
        Self { udp_conn }
    }

    fn udp_socket(&self) -> io::Result<&tokio::net::UdpSocket> {
        let udp_conn: &dyn Any = self.udp_conn.as_ref();
        udp_conn
            .downcast_ref::<tokio::net::UdpSocket>()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "enhance udp conn: not a udp conn"))
    }
}

#[async_trait]
impl WaitReadFrom for EnhanceUDPConn {
    // NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let socket = match self.udp_socket() {
            Ok(socket) => socket,
            Err(err) => return (Vec::new(), None, None, Err(err)),
        };
        // The buffer is taken inside the closure, once per invocation, so a wait that never sees
        // readiness never pins a pooled block; `async_io` may call this more than once on a
        // spurious wake, so each attempt gets its own buffer and returns it on failure, matching
        // the per-callback allocation from its buffer pool.
        let result = socket
            .async_io(tokio::io::Interest::READABLE, || {
                let mut read_buf = pool::get(pool::UDP_BUFFER_SIZE);
                match recvfrom(socket, &mut read_buf) {
                    Ok((read_n, read_from)) => Ok((read_n, read_from, read_buf)),
                    Err(err) => {
                        let _ = pool::put(read_buf);
                        Err(err)
                    }
                }
            })
            .await;
        match result {
            Ok((read_n, read_from, read_buf)) => {
                if read_n > 0 {
                    let data = read_buf.get(..read_n).unwrap_or_default().to_vec();
                    let put: Option<Box<dyn FnOnce() + Send>> = Some(Box::new(move || {
                        let _ = pool::put(read_buf);
                    }));
                    (data, put, read_from, Ok(()))
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
impl PacketConn for EnhanceUDPConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.udp_conn.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.udp_conn.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.udp_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.udp_conn.close()
    }

    fn as_socket(&self) -> Option<SockRef<'_>> {
        self.udp_conn.as_socket()
    }
}

impl WithUpstream for EnhanceUDPConn {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(self.udp_conn.as_ref())
    }
}

impl ReaderWithUpstream for EnhanceUDPConn {
    fn reader_replaceable(&self) -> bool {
        true
    }
}

impl WriterWithUpstream for EnhanceUDPConn {
    fn writer_replaceable(&self) -> bool {
        true
    }
}

#[expect(unsafe_code, reason = "`SockRef::recv_from` requires a `MaybeUninit` view the safe slice API cannot build")]
fn recvfrom(socket: &tokio::net::UdpSocket, read_buf: &mut [u8]) -> io::Result<(usize, Option<Box<dyn Addr>>)> {
    // SAFETY: `read_buf` is writable for its whole length, and `recvfrom` writes at most that many
    // bytes, so the `MaybeUninit` view is fully the slice the syscall may initialise.
    let buf =
        unsafe { std::slice::from_raw_parts_mut(read_buf.as_mut_ptr().cast::<MaybeUninit<u8>>(), read_buf.len()) };
    let (read_n, read_from) = SockRef::from(socket).recv_from(buf)?;
    // The socket layer reports the IPv6 scope id, which is the zone it formats.
    let addr: Option<Box<dyn Addr>> = match read_from.as_socket() {
        Some(SocketAddr::V4(from)) => Some(Box::new(UdpAddr::new(IpAddr::V4(*from.ip()), from.port()))),
        Some(SocketAddr::V6(from)) => {
            let mut addr = UdpAddr::new(IpAddr::V6(*from.ip()), from.port());
            if from.scope_id() != 0 {
                addr.zone = from.scope_id().to_string();
            }
            Some(Box::new(addr))
        }
        None => None,
    };
    Ok((read_n, addr))
}

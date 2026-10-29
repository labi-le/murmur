//! Raw-socket packet I/O for Unix targets.

use std::any::Any;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;

use murmur_common_pool as pool;
use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};

use super::packet::{ReaderWithUpstream, WaitReadFrom, WithUpstream, WriterWithUpstream};

pub(crate) struct EnhanceUDPConn {
    udp_conn: Arc<dyn PacketConn>,
    raw_conn: OnceLock<RawFd>,
}

impl EnhanceUDPConn {
    pub(crate) fn new(udp_conn: Arc<dyn PacketConn>) -> Self {
        Self { udp_conn, raw_conn: OnceLock::new() }
    }

    fn udp_socket(&self) -> io::Result<&tokio::net::UdpSocket> {
        let udp_conn: &dyn Any = self.udp_conn.as_ref();
        udp_conn
            .downcast_ref::<tokio::net::UdpSocket>()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "enhance udp conn: not a udp conn"))
    }

    /// The lazily assigned raw fd; only the crate's `tokio::net::UdpSocket` carries one.
    fn raw_conn(&self) -> io::Result<RawFd> {
        if let Some(raw_conn) = self.raw_conn.get() {
            return Ok(*raw_conn);
        }
        let raw_conn = self.udp_socket()?.as_raw_fd();
        let _ = self.raw_conn.set(raw_conn);
        Ok(raw_conn)
    }
}

#[async_trait]
impl WaitReadFrom for EnhanceUDPConn {
    // cancel-safe: the syscall only runs on readiness, so a drop while closing loses at most one datagram.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let raw_conn = match self.raw_conn() {
            Ok(raw_conn) => raw_conn,
            Err(err) => return (Vec::new(), None, None, Err(err)),
        };
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
                match recvmsg(raw_conn, &mut read_buf) {
                    Ok((read_n, read_from)) => Ok((read_n, read_from, read_buf)),
                    Err(err) => {
                        let _ = pool::put(read_buf);
                        Err(err)
                    }
                }
            })
            .await;
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

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
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

#[expect(unsafe_code, reason = "the manual `recvmsg` is the only way to obtain the datagram's source address")]
fn recvmsg(fd: RawFd, read_buf: &mut [u8]) -> io::Result<(usize, Option<Box<dyn Addr>>)> {
    // SAFETY: `read_buf` is writable for its whole length, `iov`/`msg` only point at locals that
    // outlive the call, and the returned source address is read only for the family `recvmsg`
    // reported after it wrote the storage.
    unsafe {
        let mut name: libc::sockaddr_storage = std::mem::zeroed();
        let mut iov = libc::iovec { iov_base: read_buf.as_mut_ptr().cast(), iov_len: read_buf.len() };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = std::ptr::addr_of_mut!(name).cast();
        msg.msg_namelen = libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sockaddr_storage exceeds socklen_t"))?;
        msg.msg_iov = std::ptr::addr_of_mut!(iov);
        msg.msg_iovlen = 1;
        let read_n = libc::recvmsg(fd, &raw mut msg, 0);
        if read_n < 0 {
            return Err(io::Error::last_os_error());
        }
        let addr: Option<Box<dyn Addr>> = match libc::c_int::from(name.ss_family) {
            libc::AF_INET => {
                let from = &*std::ptr::addr_of!(name).cast::<libc::sockaddr_in>();
                let ip = Ipv4Addr::from(from.sin_addr.s_addr.to_ne_bytes());
                Some(Box::new(UdpAddr::new(IpAddr::V4(ip), u16::from_be(from.sin_port))))
            }
            libc::AF_INET6 => {
                let from = &*std::ptr::addr_of!(name).cast::<libc::sockaddr_in6>();
                let ip = Ipv6Addr::from(from.sin6_addr.s6_addr);
                let mut addr = UdpAddr::new(IpAddr::V6(ip), u16::from_be(from.sin6_port));
                if from.sin6_scope_id != 0 {
                    addr.zone = from.sin6_scope_id.to_string();
                }
                Some(Box::new(addr))
            }
            _ => None,
        };
        Ok((read_n.cast_unsigned(), addr))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    /// Regresses a spin where a raw `recvmsg` after `readable().await` never cleared tokio's
    /// readiness bit, so every later `wait_read_from` returned immediately and a surrounding
    /// `select!`'s timer never got a chance to run. Runs the async body on its own OS thread
    /// with a channel so a regression (an infinite loop inside a single `Future::poll`) fails
    /// this test instead of hanging it.
    #[test]
    fn wait_read_from_does_not_spin_after_the_first_datagram() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let timer_fired = runtime.block_on(async {
                let server = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                let server_addr = server.local_addr().unwrap();
                let client = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                client.connect(server_addr).await.unwrap();
                client.send(b"hello").await.unwrap();

                let conn = EnhanceUDPConn::new(Arc::new(server));
                let (data, _put, _addr, res) = conn.wait_read_from().await;
                res.unwrap();
                assert_eq!(b"hello", data.as_slice());

                let timer_fired = AtomicBool::new(false);
                tokio::select! {
                    _ = conn.wait_read_from() => panic!("a second datagram should never arrive"),
                    () = tokio::time::sleep(Duration::from_millis(50)) => timer_fired.store(true, Ordering::SeqCst),
                }
                timer_fired.load(Ordering::SeqCst)
            });
            let _ = tx.send(timer_fired);
        });
        let fired =
            rx.recv_timeout(Duration::from_secs(2)).expect("wait_read_from spun instead of yielding to the 50ms timer");
        assert!(fired, "the timer branch of select! did not run");
    }

    /// Pins the note on `EnhanceUDPConn::wait_read_from`: a read dropped while it is parked on
    /// readiness consumes nothing, so the datagram that arrives afterwards is still there.
    #[tokio::test]
    async fn a_read_dropped_while_parked_leaves_the_datagram_to_the_next_read() {
        let server = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let conn = EnhanceUDPConn::new(Arc::new(server));

        {
            let read = conn.wait_read_from();
            tokio::pin!(read);
            assert!(futures::poll!(&mut read).is_pending(), "a read with no datagram must park");
        }

        client.send_to(b"hello", server_addr).await.unwrap();
        let (data, _put, _addr, res) = conn.wait_read_from().await;
        res.unwrap();
        assert_eq!(b"hello", data.as_slice(), "the datagram must survive the dropped read");
    }

    #[tokio::test]
    async fn wait_read_from_transfers_the_pooled_buffer_without_an_extra_copy() {
        let server = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client.send_to(b"pooled", server_addr).await.unwrap();

        let conn = EnhanceUDPConn::new(Arc::new(server));
        let (data, put, _addr, res) = conn.wait_read_from().await;
        res.unwrap();
        assert_eq!(b"pooled", data.as_slice());
        assert!(put.is_none(), "the pooled block itself is returned as `data`; there is nothing left for `put`");
        assert_eq!(data.capacity(), pool::UDP_BUFFER_SIZE, "the transferred block must remain poolable");
        pool::put(data).expect("caller must be able to recycle the returned buffer");

        client.send_to(b"", server_addr).await.unwrap();
        let (data, put, _addr, res) = conn.wait_read_from().await;
        res.unwrap();
        assert!(data.is_empty());
        assert!(put.is_none(), "a zero-length datagram releases its buffer internally");
        assert_eq!(data.capacity(), 0, "a zero-length datagram hands back no pooled block");
    }
}

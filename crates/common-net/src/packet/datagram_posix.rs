//! Raw-`recvmsg` zero-copy fast path on a genuine `tokio::net::UdpSocket`, the
//! [`Datagram`]-shaped sibling of `packet_posix.rs`'s `EnhanceUDPConn`. Identity is
//! [`Datagram::as_any`] instead of a `PacketConn` downcast; everything else — the per-attempt
//! pooled buffer, the raw `libc::recvmsg` call, the `SocketAddrV6::scope_id` round trip — is
//! unchanged.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;

use murmur_common_pool as pool;

use super::datagram::WaitReadFromDatagram;
use crate::io::{Datagram, UdpAcceptor};

pub(crate) struct EnhanceUdpDatagram {
    udp_conn: Arc<dyn Datagram>,
    raw_conn: OnceLock<RawFd>,
}

impl EnhanceUdpDatagram {
    pub(crate) fn new(udp_conn: Arc<dyn Datagram>) -> Self {
        Self { udp_conn, raw_conn: OnceLock::new() }
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
impl WaitReadFromDatagram for EnhanceUdpDatagram {
    // cancel-safe: the syscall only runs on readiness, so a drop while closing loses at most one datagram.
    async fn wait_read_from(&self) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<SocketAddr>, io::Result<()>) {
        let raw_conn = match self.raw_conn() {
            Ok(raw_conn) => raw_conn,
            Err(err) => return (Vec::new(), None, None, Err(err)),
        };
        let socket = match self.udp_socket() {
            Ok(socket) => socket,
            Err(err) => return (Vec::new(), None, None, Err(err)),
        };
        let read = socket.async_io(tokio::io::Interest::READABLE, || {
            let mut read_buf = pool::get(pool::UDP_BUFFER_SIZE);
            match recvmsg(raw_conn, &mut read_buf) {
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
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.udp_conn.as_socket()
    }
}

#[expect(unsafe_code, reason = "the manual `recvmsg` is the only way to obtain the datagram's source address")]
fn recvmsg(fd: RawFd, read_buf: &mut [u8]) -> io::Result<(usize, Option<SocketAddr>)> {
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
        let addr: Option<SocketAddr> = match libc::c_int::from(name.ss_family) {
            libc::AF_INET => {
                let from = &*std::ptr::addr_of!(name).cast::<libc::sockaddr_in>();
                let ip = Ipv4Addr::from(from.sin_addr.s_addr.to_ne_bytes());
                Some(SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be(from.sin_port))))
            }
            libc::AF_INET6 => {
                let from = &*std::ptr::addr_of!(name).cast::<libc::sockaddr_in6>();
                let ip = Ipv6Addr::from(from.sin6_addr.s6_addr);
                Some(SocketAddr::V6(SocketAddrV6::new(ip, u16::from_be(from.sin6_port), 0, from.sin6_scope_id)))
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

    /// Mirrors `packet_posix::tests::wait_read_from_does_not_spin_after_the_first_datagram`,
    /// retargeted onto `Datagram`.
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

                let conn = EnhanceUdpDatagram::new(Arc::new(server));
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

    #[tokio::test]
    async fn wait_read_from_returns_the_pooled_buffer_and_the_sender_address() {
        let server = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        client.connect(server_addr).await.unwrap();
        client.send(b"pooled").await.unwrap();

        let conn = EnhanceUdpDatagram::new(Arc::new(server));
        let (data, put, addr, res) = conn.wait_read_from().await;
        res.unwrap();
        assert_eq!(b"pooled", data.as_slice());
        assert_eq!(addr, Some(client_addr));
        assert!(put.is_none(), "the pooled block itself is returned as `data`; there is nothing left for `put`");
        assert_eq!(data.capacity(), pool::UDP_BUFFER_SIZE, "the transferred block must remain poolable");
        pool::put(data).expect("caller must be able to recycle the returned buffer");
    }

    /// Ownership-transfer semantics: every completed read hands the pooled block itself back as
    /// `data` with `put: None`, and the caller recycles it exactly once; a wait dropped before any
    /// datagram arrives never takes a buffer at all (it lives inside the `async_io` closure, which
    /// never runs); a zero-length datagram releases its buffer internally and hands back no block.
    #[tokio::test]
    async fn wait_read_from_transfers_the_pooled_block_once_per_read_and_takes_none_when_dropped_mid_wait() {
        let server = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client.connect(server_addr).await.unwrap();

        let conn = EnhanceUdpDatagram::new(Arc::new(server));

        let dropped_early = tokio::time::timeout(Duration::from_millis(20), conn.wait_read_from()).await;
        assert!(dropped_early.is_err(), "no datagram is pending, so the wait must still be running at the timeout");

        for i in 0..3u8 {
            client.send(&[i]).await.unwrap();
            let (data, put, _addr, res) = conn.wait_read_from().await;
            res.unwrap();
            assert_eq!(data, vec![i]);
            assert!(put.is_none(), "a transferred read has no release callback");
            assert_eq!(data.capacity(), pool::UDP_BUFFER_SIZE, "the transferred block must remain poolable");
            pool::put(data).expect("the caller recycles the transferred block");
        }

        client.send(b"").await.unwrap();
        let (data, put, _addr, res) = conn.wait_read_from().await;
        res.unwrap();
        assert!(data.is_empty());
        assert!(put.is_none(), "a zero-length datagram releases its buffer internally");
        assert_eq!(data.capacity(), 0, "a zero-length datagram hands back no pooled block");
    }
}

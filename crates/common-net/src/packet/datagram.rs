//! Datagram-shaped pooled read: the equivalent of [`super::packet::{WaitReadFrom,
//! EnhancePacketConn}`](super::packet) for [`crate::io::Datagram`]/[`crate::io::NamedDatagram`].
//!
//! Same zero-copy pooled-buffer behaviour and release semantics as the `PacketConn`-keyed
//! counterparts; the raw-`recvmsg`/`recvfrom` fast path lives in `datagram_posix.rs`/
//! `datagram_windows.rs`, dispatched the same way via [`Datagram::as_any`] instead of a
//! `PacketConn` downcast.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;

use murmur_common_pool as pool;
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Addr, PacketConn};

use super::packet::WaitReadFrom;
use crate::io::{old_addr_to_socket_addr, udp_addr_from_socket_addr, Datagram, NamedDatagram, UdpAcceptor};

#[cfg(not(target_os = "windows"))]
pub(crate) use super::datagram_posix::EnhanceUdpDatagram;
#[cfg(target_os = "windows")]
pub(crate) use super::datagram_windows::EnhanceUdpDatagram;

/// [`SocketAddr`]-keyed counterpart to [`WaitReadFrom`].
///
/// `put == None` means `data` is the transferred pooled block, to be returned with
/// `murmur_common_pool::put(data)` by the caller that consumes it.
#[async_trait]
pub trait WaitReadFromDatagram: Send + Sync {
    async fn wait_read_from(&self) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<SocketAddr>, io::Result<()>);
}

/// [`Datagram`]-shaped counterpart to [`super::packet::EnhancePacketConn`].
pub trait EnhanceDatagram: Datagram + WaitReadFromDatagram + Send + Sync {
    /// Capability: the concrete value, for a caller that must test which implementation
    /// `new_enhance_datagram` selected.
    fn as_enhance_any(&self) -> &dyn std::any::Any;
    fn as_datagram(&self) -> &dyn Datagram;
    fn into_datagram(self: Arc<Self>) -> Arc<dyn Datagram>;
}

// Compatibility bridge: the trait only re-erases an existing `Datagram` plus its waiter.
impl<T: Datagram + WaitReadFromDatagram + 'static> EnhanceDatagram for T {
    fn as_enhance_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_datagram(&self) -> &dyn Datagram {
        self
    }
    fn into_datagram(self: Arc<Self>) -> Arc<dyn Datagram> {
        self
    }
}

/// Generic pooled read, the [`Datagram`] equivalent of [`super::packet::wait_read_from`].
pub async fn wait_read_from_datagram(
    pc: &dyn Datagram,
) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<SocketAddr>, io::Result<()>) {
    let mut read_buf = pool::get(pool::UDP_BUFFER_SIZE);
    let (read_n, addr, err) = match pc.recv_from(&mut read_buf).await {
        Ok((read_n, addr)) => (read_n, Some(addr), Ok(())),
        Err(err) => (0, None, Err(err)),
    };
    if read_n == 0 {
        let _ = pool::put(read_buf);
        return (Vec::new(), None, addr, err);
    }
    read_buf.truncate(read_n);
    (read_buf, None, addr, err)
}

struct EnhanceDatagramImpl {
    inner: Arc<dyn Datagram>,
}

#[async_trait]
impl Datagram for EnhanceDatagramImpl {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, addr).await
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn close(&self) -> io::Result<()> {
        self.inner.close()
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.inner.as_socket()
    }
}

#[async_trait]
impl WaitReadFromDatagram for EnhanceDatagramImpl {
    // cancel-safe: forwards to the wrapped conn's `wait_read_from` and owns no state of its own, so dropping this future is exactly dropping the inner call.
    async fn wait_read_from(&self) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<SocketAddr>, io::Result<()>) {
        wait_read_from_datagram(&*self.inner).await
    }
}

/// [`Datagram`] equivalent of [`super::packet::new_enhance_packet_conn`].
///
/// It takes the raw-socket fast path for a genuine [`tokio::net::UdpSocket`] or
/// [`crate::io::UdpAcceptor`] (identity, via [`Datagram::as_any`] rather than a `PacketConn`
/// downcast) and the generic pooled path otherwise.
pub fn new_enhance_datagram(pc: Arc<dyn Datagram>) -> Arc<dyn EnhanceDatagram> {
    let is_raw_udp = pc.as_any().is_some_and(|any| any.is::<tokio::net::UdpSocket>() || any.is::<UdpAcceptor>());
    if is_raw_udp {
        return Arc::new(EnhanceUdpDatagram::new(pc));
    }
    Arc::new(EnhanceDatagramImpl { inner: pc })
}

/// [`Socksaddr`]-keyed counterpart to [`WaitReadFrom`].
///
/// `put == None` means `data` is the transferred pooled block, to be returned with
/// `murmur_common_pool::put(data)` by the caller that consumes it.
#[async_trait]
pub trait WaitReadFromNamedDatagram: Send + Sync {
    async fn wait_read_from(&self) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Socksaddr>, io::Result<()>);
}

/// [`NamedDatagram`]-shaped counterpart to [`EnhanceDatagram`].
pub trait EnhanceNamedDatagram: NamedDatagram + WaitReadFromNamedDatagram + Send + Sync {
    fn as_named_datagram(&self) -> &dyn NamedDatagram;
    fn into_named_datagram(self: Arc<Self>) -> Arc<dyn NamedDatagram>;
}

// Compatibility bridge: the trait only re-erases an existing `NamedDatagram` plus its waiter.
impl<T: NamedDatagram + WaitReadFromNamedDatagram + 'static> EnhanceNamedDatagram for T {
    fn as_named_datagram(&self) -> &dyn NamedDatagram {
        self
    }
    fn into_named_datagram(self: Arc<Self>) -> Arc<dyn NamedDatagram> {
        self
    }
}

/// Generic pooled read for [`NamedDatagram`].
///
/// No raw-socket fast path exists for this shape: every real implementor carries a
/// domain-name-aware layer above the bare socket, never a bare `tokio::net::UdpSocket` itself.
pub async fn wait_read_from_named_datagram(
    pc: &dyn NamedDatagram,
) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Socksaddr>, io::Result<()>) {
    let mut read_buf = pool::get(pool::UDP_BUFFER_SIZE);
    let (read_n, addr, err) = match pc.recv_from(&mut read_buf).await {
        Ok((read_n, addr)) => (read_n, Some(addr), Ok(())),
        Err(err) => (0, None, Err(err)),
    };
    if read_n == 0 {
        let _ = pool::put(read_buf);
        return (Vec::new(), None, addr, err);
    }
    read_buf.truncate(read_n);
    (read_buf, None, addr, err)
}

struct EnhanceNamedDatagramImpl {
    inner: Arc<dyn NamedDatagram>,
}

#[async_trait]
impl NamedDatagram for EnhanceNamedDatagramImpl {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        self.inner.recv_from(buf).await
    }
    async fn send_to(&self, buf: &[u8], addr: &Socksaddr) -> io::Result<usize> {
        self.inner.send_to(buf, addr).await
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn close(&self) -> io::Result<()> {
        self.inner.close()
    }
}

#[async_trait]
impl WaitReadFromNamedDatagram for EnhanceNamedDatagramImpl {
    // cancel-safe: forwards to the wrapped conn's `wait_read_from` and owns no state of its own, so dropping this future is exactly dropping the inner call.
    async fn wait_read_from(&self) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Socksaddr>, io::Result<()>) {
        wait_read_from_named_datagram(&*self.inner).await
    }
}

pub fn new_enhance_named_datagram(pc: Arc<dyn NamedDatagram>) -> Arc<dyn EnhanceNamedDatagram> {
    Arc::new(EnhanceNamedDatagramImpl { inner: pc })
}

fn boxed_udp_addr(addr: SocketAddr) -> Box<dyn Addr> {
    Box::new(udp_addr_from_socket_addr(addr))
}

/// Bridges an [`EnhanceDatagram`] to the old `PacketConn` + [`WaitReadFrom`] pair
/// (together, the old [`super::packet::EnhancePacketConn`], via that trait's blanket impl), so a
/// caller not yet migrated off the old trait keeps pooled reads and decorated addresses once the
/// value underneath is `Datagram`-shaped.
struct EnhanceDatagramAsOldEnhancePacketConn(Arc<dyn EnhanceDatagram>);

#[async_trait]
impl PacketConn for EnhanceDatagramAsOldEnhancePacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let (n, addr) = self.0.recv_from(buf).await?;
        Ok((n, Box::new(udp_addr_from_socket_addr(addr))))
    }
    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.0.send_to(buf, old_addr_to_socket_addr(addr)?).await
    }
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr().map(boxed_udp_addr)
    }
    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.0.as_socket()
    }
}

#[async_trait]
impl WaitReadFrom for EnhanceDatagramAsOldEnhancePacketConn {
    // cancel-safe: forwards to the wrapped conn's `wait_read_from` and owns no state of its own, so dropping this future is exactly dropping the inner call.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let (data, put, addr, err) = self.0.wait_read_from().await;
        (data, put, addr.map(boxed_udp_addr), err)
    }
}

/// Bridges an [`EnhanceDatagram`] to the old `EnhancePacketConn`, preserving pooled reads.
pub fn enhance_datagram_as_old_enhance_packet_conn(
    pc: Arc<dyn EnhanceDatagram>,
) -> Arc<dyn super::packet::EnhancePacketConn> {
    Arc::new(EnhanceDatagramAsOldEnhancePacketConn(pc))
}

/// The reverse of [`EnhanceDatagramAsOldEnhancePacketConn`]: bridges an old
/// [`super::packet::EnhancePacketConn`] to [`EnhanceDatagram`], for a caller newly written
/// against `Datagram` that must still consume a not-yet-migrated old source. The old trait has no
/// FQDN vocabulary; a genuinely-FQDN peer address fails `read_from`/`write_to`/`wait_read_from`
/// with `Unsupported`, the same as [`crate::io::OldPacketConnAsNamedDatagram`].
struct OldEnhancePacketConnAsEnhanceDatagram(Arc<dyn super::packet::EnhancePacketConn>);

#[async_trait]
impl Datagram for OldEnhancePacketConnAsEnhanceDatagram {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, addr) = self.0.read_from(buf).await?;
        Ok((n, old_addr_to_socket_addr(addr.as_ref())?))
    }
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.0.write_to(buf, &udp_addr_from_socket_addr(addr)).await
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.0.local_addr()?.as_ref())
    }
    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.0.as_socket()
    }
}

#[async_trait]
impl WaitReadFromDatagram for OldEnhancePacketConnAsEnhanceDatagram {
    // cancel-safe: forwards to the wrapped conn's `wait_read_from` and owns no state of its own, so dropping this future is exactly dropping the inner call.
    async fn wait_read_from(&self) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<SocketAddr>, io::Result<()>) {
        let (data, put, addr, err) = self.0.wait_read_from().await;
        let addr = match addr {
            Some(addr) => match old_addr_to_socket_addr(addr.as_ref()) {
                Ok(addr) => Some(addr),
                Err(err) => return (data, put, None, Err(err)),
            },
            None => None,
        };
        (data, put, addr, err)
    }
}

/// Bridges an old [`super::packet::EnhancePacketConn`] to [`EnhanceDatagram`], preserving pooled
/// reads. See [`OldEnhancePacketConnAsEnhanceDatagram`]'s doc for the FQDN caveat.
pub fn old_enhance_packet_conn_as_enhance_datagram(
    pc: Arc<dyn super::packet::EnhancePacketConn>,
) -> Arc<dyn EnhanceDatagram> {
    Arc::new(OldEnhancePacketConnAsEnhanceDatagram(pc))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV6};
    use std::time::Duration;

    use crate::io::UdpAcceptor;

    use murmur_std_compat::net::SockAddr;

    use super::*;

    struct FixedPayloadDatagram {
        payload: Vec<u8>,
    }

    #[async_trait]
    impl Datagram for FixedPayloadDatagram {
        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let n = self.payload.len();
            buf[..n].copy_from_slice(&self.payload);
            Ok((n, SocketAddr::from((Ipv4Addr::LOCALHOST, 9))))
        }
        async fn send_to(&self, _buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            unimplemented!()
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            unimplemented!()
        }
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn wait_read_from_datagram_returns_pooled_buffer_without_extra_copy() {
        let payload = b"hello pooled datagram".to_vec();
        let conn = FixedPayloadDatagram { payload: payload.clone() };
        let (data, put, addr, result) = wait_read_from_datagram(&conn).await;

        assert!(result.is_ok());
        assert!(addr.is_some());
        assert_eq!(data, payload);
        assert!(put.is_none(), "the pooled block itself is returned as `data`; there is nothing left for `put`");
        pool::put(data).expect("caller must be able to recycle the returned buffer");
    }

    #[test]
    fn udp_addr_round_trips_a_v6_scope_id() {
        let addr: SocketAddr = "[fe80::1%3]:53"
            .parse()
            .unwrap_or_else(|_| SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 3)));
        let udp = udp_addr_from_socket_addr(addr);
        assert_eq!(udp.zone, "3");
        let round_tripped = crate::io::socket_addr_from_udp_addr(&udp);
        assert_eq!(round_tripped, addr);
    }

    struct FixedNamedDatagram {
        payload: Vec<u8>,
        peer: Socksaddr,
    }

    #[async_trait]
    impl NamedDatagram for FixedNamedDatagram {
        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
            let n = self.payload.len();
            buf[..n].copy_from_slice(&self.payload);
            Ok((n, self.peer.clone()))
        }
        async fn send_to(&self, _buf: &[u8], _addr: &Socksaddr) -> io::Result<usize> {
            unimplemented!()
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            unimplemented!()
        }
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn wait_read_from_named_datagram_preserves_the_fqdn_peer_address() {
        let peer = Socksaddr::fqdn("example.com", 443);
        let conn = FixedNamedDatagram { payload: b"fqdn payload".to_vec(), peer: peer.clone() };
        let (data, put, addr, res) = wait_read_from_named_datagram(&conn).await;

        assert!(res.is_ok());
        assert_eq!(data, b"fqdn payload");
        assert!(put.is_none());
        assert_eq!(addr, Some(peer));
        pool::put(data).expect("caller must be able to recycle the returned buffer");
    }

    #[tokio::test]
    async fn enhance_named_datagram_preserves_the_fqdn_peer_address_through_the_enhance_wrapper() {
        let peer = Socksaddr::fqdn("backend.internal", 8443);
        let conn: Arc<dyn NamedDatagram> =
            Arc::new(FixedNamedDatagram { payload: b"decorated".to_vec(), peer: peer.clone() });
        let enhanced = new_enhance_named_datagram(conn);

        let (data, _put, addr, res) = enhanced.wait_read_from().await;
        assert!(res.is_ok());
        assert_eq!(data, b"decorated");
        assert_eq!(addr, Some(peer));
    }

    /// The old-`PacketConn` bridge must keep the decorated (v6-zone-carrying) peer address a
    /// [`Datagram`] read produces, round-tripping through the old `UdpAddr` and back.
    #[tokio::test]
    async fn enhance_datagram_as_old_enhance_packet_conn_preserves_a_decorated_v6_zone_address() {
        let decorated: SocketAddr = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 7));
        let conn: Arc<dyn Datagram> = Arc::new(FixedPayloadDatagram { payload: b"zoned".to_vec() });
        struct DecoratedDatagram(Arc<dyn Datagram>, SocketAddr);
        #[async_trait]
        impl Datagram for DecoratedDatagram {
            async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                let (n, _) = self.0.recv_from(buf).await?;
                Ok((n, self.1))
            }
            async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
                self.0.send_to(buf, addr).await
            }
            fn local_addr(&self) -> io::Result<SocketAddr> {
                self.0.local_addr()
            }
            fn close(&self) -> io::Result<()> {
                self.0.close()
            }
        }
        let decorated_conn: Arc<dyn Datagram> = Arc::new(DecoratedDatagram(conn, decorated));
        let enhanced = new_enhance_datagram(decorated_conn);
        let old = enhance_datagram_as_old_enhance_packet_conn(enhanced);

        let mut buf = [0u8; 16];
        let (n, addr) = old.read_from(&mut buf).await.expect("read_from");
        assert_eq!(&buf[..n], b"zoned");
        let sock = addr.as_sock_addr().expect("bridged read_from must answer a socket address");
        let SockAddr::Udp(udp) = sock else { panic!("expected a UdpAddr") };
        assert_eq!(udp.zone, "7", "the v6 scope id must survive the Datagram-to-old-PacketConn bridge");
    }

    /// `UdpAcceptor` adds only a close token around its socket. The enhanced raw path must retain
    /// that token while using the inner socket's readiness registration.
    #[tokio::test]
    async fn a_wrapped_udp_acceptor_still_selects_the_raw_socket_path() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind receiver");
        let addr = socket.local_addr().expect("receiver addr");
        let acceptor = UdpAcceptor::new(socket);
        assert!(
            Datagram::as_any(&acceptor).is_some_and(<dyn std::any::Any + 'static>::is::<UdpAcceptor>),
            "as_any must name the concrete cancellation wrapper"
        );

        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind sender");
        sender.send_to(b"ping", addr).await.expect("send probe");

        let enhanced = new_enhance_datagram(Arc::new(acceptor));
        assert!(
            enhanced.as_enhance_any().is::<EnhanceUdpDatagram>(),
            "the raw-socket fast path must be selected for a wrapped UdpSocket"
        );
        let (data, _put, from, err) =
            tokio::time::timeout(Duration::from_secs(5), enhanced.wait_read_from()).await.expect("read must not hang");
        err.expect("wait_read_from");
        assert_eq!(data, b"ping");
        assert_eq!(from, sender.local_addr().ok());

        let closing = UdpAcceptor::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind closing"));
        closing.close().expect("close");
        let mut buf = [0u8; 16];
        let err = tokio::time::timeout(Duration::from_secs(5), closing.recv_from(&mut buf))
            .await
            .expect("a closed acceptor's read must not hang")
            .expect_err("a closed acceptor's read must fail");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
}

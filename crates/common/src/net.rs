//! The native net contract, owned here rather than in
//! `murmur-common-net` because crates below `murmur-common-net` must be able to name and
//! implement it.
//!
//! `murmur-common-net` depends on `murmur-sing` (for `metadata::Socksaddr`, which
//! `NamedDatagram` needs), so `murmur-sing` cannot depend on `murmur-common-net` without a
//! cargo cycle. A contract defined only there is therefore unreachable from the two crates that
//! need it: `murmur-sing` implements [`Datagram`] for its own `uot::Conn`, and
//! `murmur-quic` names it in `TransportFactory::new_transport`. Both would have to be
//! routed through a bridge in `murmur-common-net` instead.
//!
//! `murmur-common` is the lowest crate besides `murmur-std-compat` — which this wave deletes — that
//! `murmur-sing`, `murmur-quic` and `murmur-common-net` all already depend on,
//! and it is where the sibling mirror contract ([`crate::shared_conn::Conn`]) lives.
//! `murmur-common-net::io` re-exports every item here, so a `dyn Stream` named through either path
//! is the same type and no existing consumer changes.
//!
//! `NamedDatagram` is the one contract that cannot move: it is keyed by
//! `murmur_sing::metadata::Socksaddr`, so it has to live at or above that crate. It stays
//! in `murmur-common-net::io`. `uot` does not need it — the crate's own `PacketReader`/
//! `PacketWriter` already carry a `Socksaddr` destination.
//!

use std::any::Any;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};

use crate::shared_conn::SharedConn;
use murmur_std_compat::net::{Addr, Conn, SockAddr, UdpAddr};

/// The native conn contract.
///
/// No `set_deadline`: see the deadline combinators in `murmur-common-net` (`CancellableStream`,
/// `IdleTimeout`) and the `tokio::time::timeout` pattern documented there for the call sites
/// that don't need a standing combinator.
pub trait Stream: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn shutdown_read(&self) -> io::Result<()> {
        Ok(())
    }
    fn shutdown_write(&self) -> io::Result<()> {
        Ok(())
    }
    /// Capability, not identity: `None` unless the concrete type embeds a real OS socket
    /// (`TcpStream` today).
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }
    /// Capability: `Some` when this `Stream` is, or transparently wraps, an old
    /// legacy conn whose `close`/`set_*_deadline` carry real behaviour (e.g. a dial-cancel,
    /// a socket close) that [`shutdown_read`](Self::shutdown_read)/
    /// [`shutdown_write`](Self::shutdown_write) and a bolted-on deadline token cannot
    /// reproduce. `OldConnAsStream` (in `murmur-common-net`) answers `Some(&self.0)`; a wrapper
    /// `Stream` built around one (obfs/protocol layers, `CancellableStream`) forwards to its
    /// inner value. `None` for anything genuinely new, like `TcpStream`.
    fn old_conn(&self) -> Option<&dyn Conn> {
        None
    }

    /// Capability: the concrete value behind an erased `&dyn Stream`, for the call sites that
    /// must re-test identity the way an interface type assertion does. `Box` forwards, so a
    /// boxed conn answers for its inner value rather than the box.
    fn as_any(&self) -> Option<&dyn Any> {
        None
    }

    /// Capability: the additional-read-deadline marker, inlined into the contract so
    /// an erased `&dyn Stream` answers the assertion without naming the concrete conn type.
    fn need_additional_read_deadline(&self) -> bool {
        false
    }
}

/// Shared close path for a [`Stream`].
///
/// Closes through the wrapped legacy conn ([`Stream::old_conn`]) when present, otherwise shuts
/// down both directions without letting a failed read-side shutdown skip the write side.
pub fn close_stream<S: Stream + ?Sized>(stream: &S) -> io::Result<()> {
    if let Some(inner) = stream.old_conn() {
        return inner.close();
    }
    let read_result = stream.shutdown_read();
    let write_result = stream.shutdown_write();
    read_result.and(write_result)
}

/// Splice/vision capability, kept distinct from [`Stream`] because most implementors don't need
/// it (the transport/vless splice-detection call sites do).
pub trait ExtendedStream: Stream {
    fn reader_replaceable(&self) -> bool {
        true
    }
    fn writer_replaceable(&self) -> bool {
        true
    }
}

/// The native datagram contract, used for the OS-socket-backed 99% case.
///
/// `Box<dyn Datagram>` is the dominant use, hence `#[async_trait]` rather than native
/// async-fn-in-trait, which is not dyn-compatible on this toolchain.
#[async_trait]
pub trait Datagram: Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn close(&self) -> io::Result<()> {
        Ok(())
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }
    /// Capability: the concrete value itself, for a caller that must test identity rather than
    /// borrow the OS socket (`as_socket()`) — the raw-`recvmsg`/`recvfrom` zero-copy UDP read
    /// path needs `tokio::net::UdpSocket::async_io`, which `SockRef` does not expose.
    fn as_any(&self) -> Option<&dyn Any> {
        None
    }
    fn into_std_udp(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "not a raw UDP socket"))
    }
}

impl<S: Stream + ?Sized> Stream for Box<S> {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        (**self).local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        (**self).peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        (**self).shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        (**self).shutdown_write()
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        (**self).as_socket()
    }
    fn old_conn(&self) -> Option<&dyn Conn> {
        (**self).old_conn()
    }

    fn as_any(&self) -> Option<&dyn Any> {
        (**self).as_any()
    }

    fn need_additional_read_deadline(&self) -> bool {
        (**self).need_additional_read_deadline()
    }
}

impl<S: ExtendedStream + ?Sized> ExtendedStream for Box<S> {
    fn reader_replaceable(&self) -> bool {
        (**self).reader_replaceable()
    }
    fn writer_replaceable(&self) -> bool {
        (**self).writer_replaceable()
    }
}

#[async_trait]
impl<D: Datagram + ?Sized> Datagram for Box<D> {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        (**self).recv_from(buf).await
    }
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        (**self).send_to(buf, addr).await
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        (**self).local_addr()
    }
    fn close(&self) -> io::Result<()> {
        (**self).close()
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        (**self).as_socket()
    }
    fn as_any(&self) -> Option<&dyn Any> {
        (**self).as_any()
    }
    fn into_std_udp(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        (*self).into_std_udp()
    }
}

impl Stream for TcpStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Self::peer_addr(self)
    }
    fn shutdown_read(&self) -> io::Result<()> {
        socket2::SockRef::from(self).shutdown(std::net::Shutdown::Read)
    }
    fn shutdown_write(&self) -> io::Result<()> {
        socket2::SockRef::from(self).shutdown(std::net::Shutdown::Write)
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        Some(socket2::SockRef::from(self))
    }
}

#[async_trait]
impl Datagram for UdpSocket {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Self::recv_from(self, buf).await
    }
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        Self::send_to(self, buf, addr).await
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        Some(socket2::SockRef::from(self))
    }
    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
    fn into_std_udp(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        (*self).into_std()
    }
}

impl Stream for SharedConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(Conn::local_addr(self)?.as_ref())
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(Conn::remote_addr(self)?.as_ref())
    }
    fn shutdown_read(&self) -> io::Result<()> {
        Conn::close_read(self)
    }
    fn shutdown_write(&self) -> io::Result<()> {
        Conn::close_write(self)
    }
    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(self)
    }
}

impl ExtendedStream for SharedConn {}

/// Translates a UDP address, restoring the `SocketAddrV6` scope from the numeric zone
/// `UdpAddr` carries in a string.
#[must_use]
pub fn socket_addr_from_udp_addr(addr: &UdpAddr) -> SocketAddr {
    match addr.ip {
        IpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, addr.port)),
        IpAddr::V6(ip) => {
            let scope_id = addr.zone.parse::<u32>().unwrap_or(0);
            SocketAddr::V6(SocketAddrV6::new(ip, addr.port, 0, scope_id))
        }
    }
}

/// Tries `as_sock_addr` (the socket-backed 99% case) first, then the structural `AddrPort`
/// capability, then falls back to parsing `Display`.
///
/// The structural capability covers e.g. `murmur_sing::metadata::Socksaddr` with an IP, or a
/// wrapper `Addr` that only implements `addr_port`. Only an `Addr` with none of the three — a
/// genuinely non-socket address such as `deadline::pipe_sing::PipeAddr` — is unsupported.
pub fn old_addr_to_socket_addr(addr: &dyn Addr) -> io::Result<SocketAddr> {
    if let Some(sock) = addr.as_sock_addr() {
        return Ok(match sock {
            SockAddr::Tcp(tcp) => SocketAddr::new(tcp.ip, tcp.port),
            SockAddr::Udp(udp) => socket_addr_from_udp_addr(&udp),
        });
    }
    if let Some(port) = addr.addr_port() {
        if let Some(ip) = port.ip {
            return Ok(SocketAddr::new(ip, port.port));
        }
    }
    addr.string()
        .parse::<SocketAddr>()
        .map_err(|_| io::Error::new(io::ErrorKind::Unsupported, "old conn address is not a socket address"))
}

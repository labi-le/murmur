//! The addressing traits (`Addr`, `Conn`, `PacketConn`, `Listener`) the rest of the workspace is
//! written against.

use std::any::Any;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};

fn boxed_addr<T: Addr>(addr: T) -> Box<dyn Addr> {
    Box::new(addr)
}

pub trait Addr: Any + Send + Sync + fmt::Debug {
    fn network(&self) -> &str;
    fn string(&self) -> String;

    /// The socket address of this value, when it has one: implemented by [`TcpAddr`], [`UdpAddr`] and the
    /// type wrapping a SOCKS address.
    fn addr_port(&self) -> Option<AddrPort> {
        None
    }

    /// The structural raw-address accessor, implemented by
    /// `common::net::addr::CustomAddrImpl` to expose the address it wraps.
    fn raw_addr(&self) -> Option<&dyn Addr> {
        None
    }

    /// The `*net.IPNet`/`*net.IPAddr` type switch `component::iface::iface::prefix_of` needs.
    fn as_iface_prefix(&self) -> Option<ipnet::IpNet> {
        None
    }

    /// Recovers the two concrete kinds this crate's socket call sites need back from a
    /// `&dyn Addr`: `TcpAddr`/`UdpAddr`. See [`SockAddr`].
    fn as_sock_addr(&self) -> Option<SockAddr> {
        None
    }
}

/// The structural address-and-port result. `fqdn` carries the hostname case, which has no
/// address-and-port equivalent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrPort {
    pub port: u16,
    pub ip: Option<IpAddr>,
    pub fqdn: Option<String>,
}

/// The deadline as a wall-clock time, computed from the crate's `tokio::time::Instant` deadline
/// representation: `None` is the zero-time "no deadline".
#[must_use]
pub fn deadline_time(deadline: Option<tokio::time::Instant>) -> Option<DateTime<Utc>> {
    let deadline = deadline?;
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    Some(Utc::now() + TimeDelta::from_std(remaining).unwrap_or(TimeDelta::MAX))
}

/// Joins a host and port for `TcpAddr`/`UdpAddr`'s own `Display`-style formatting, bracketing an
/// IPv6 literal host. Not `pub`: every other caller goes through
/// `component::dialer::bind::join_host_port`.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Formats an IPv6 zone the standard way: `%zone` appended before the
/// host-and-port bracketing. Only [`UdpAddr`] ever carries a non-empty zone (see its doc); when
/// the caller is any other one, `zone` is `""` and this is exactly the IP's own display form.
///
/// An address with zone `3` formats as `fe80::1%3`, then the host-and-port join
/// brackets it because it contains `:`: `[fe80::1%3]:53`. This is byte-identical to Rust's own
/// `SocketAddrV6` `Display`, which formats a nonzero `scope_id` the same way. The `Zone` is
/// numeric here because [`UdpAddr`]'s only producer (`recvfrom`) sets it from the raw
/// `sockaddr_in6.sin6_scope_id`, not from an interface-name lookup; see [`UdpAddr`]'s doc.
fn ip_str(ip: &IpAddr, zone: &str) -> String {
    if zone.is_empty() {
        ip.to_string()
    } else {
        format!("{ip}%{zone}")
    }
}

/// An owned TCP address, kept distinct from [`std::net::SocketAddr`] because call sites read
/// `.ip`/`.port` as fields.
///
/// It has no zone field: every construction site builds it from a `SocketAddr`, which discards the
/// IPv6 scope id, so a link-local IPv6 peer formats as `[fe80::1]:80` rather than `[fe80::1%3]:80`
/// as a connection-reported address does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpAddr {
    pub ip: IpAddr,
    pub port: u16,
}

impl TcpAddr {
    #[must_use]
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

impl Addr for TcpAddr {
    fn network(&self) -> &'static str {
        "tcp"
    }

    fn string(&self) -> String {
        join_host_port(&self.ip.to_string(), self.port)
    }

    fn addr_port(&self) -> Option<AddrPort> {
        Some(AddrPort { port: self.port, ip: Some(self.ip), fqdn: None })
    }

    fn as_sock_addr(&self) -> Option<SockAddr> {
        Some(SockAddr::Tcp(*self))
    }
}

/// An owned UDP address.
///
/// `zone` is the IPv6 scope id reported by the OS on `recvfrom`, formatted numerically, so a
/// link-local peer formats as `[fe80::1%3]:53`.
///
/// DEVIATION: `From<SocketAddr> for UdpAddr` drops `SocketAddrV6::scope_id` entirely, unlike a
/// connection-reported address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UdpAddr {
    pub ip: IpAddr,
    pub port: u16,
    pub zone: String,
}

impl UdpAddr {
    #[must_use]
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port, zone: String::new() }
    }
}

impl Addr for UdpAddr {
    fn network(&self) -> &'static str {
        "udp"
    }

    fn string(&self) -> String {
        join_host_port(&ip_str(&self.ip, &self.zone), self.port)
    }

    fn addr_port(&self) -> Option<AddrPort> {
        Some(AddrPort { port: self.port, ip: Some(self.ip), fqdn: None })
    }

    fn as_sock_addr(&self) -> Option<SockAddr> {
        Some(SockAddr::Udp(self.clone()))
    }
}

impl From<SocketAddr> for TcpAddr {
    fn from(addr: SocketAddr) -> Self {
        Self { ip: addr.ip(), port: addr.port() }
    }
}

impl From<SocketAddr> for UdpAddr {
    fn from(addr: SocketAddr) -> Self {
        Self { ip: addr.ip(), port: addr.port(), zone: String::new() }
    }
}

impl TryFrom<&TcpAddr> for SocketAddr {
    type Error = io::Error;

    fn try_from(addr: &TcpAddr) -> Result<Self, Self::Error> {
        Ok(Self::new(addr.ip, addr.port))
    }
}

impl TryFrom<&UdpAddr> for SocketAddr {
    type Error = io::Error;

    fn try_from(addr: &UdpAddr) -> Result<Self, Self::Error> {
        Ok(Self::new(addr.ip, addr.port))
    }
}

/// The two concrete `Addr` implementations every call site in this crate ever needs to recover
/// from a `&dyn Addr`.
///
/// Replaces the former `downcast_addr::<TcpAddr>()` / `downcast_addr::<UdpAddr>()` chains:
/// recovery happens once, here, and every caller matches the closed set instead of
/// independently repeating a runtime type test that a missed case turns into a silent `None`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SockAddr {
    Tcp(TcpAddr),
    Udp(UdpAddr),
}

impl SockAddr {
    #[must_use]
    pub const fn ip(&self) -> IpAddr {
        match self {
            Self::Tcp(addr) => addr.ip,
            Self::Udp(addr) => addr.ip,
        }
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        match self {
            Self::Tcp(addr) => addr.port,
            Self::Udp(addr) => addr.port,
        }
    }
}

impl TryFrom<&SockAddr> for SocketAddr {
    type Error = io::Error;

    fn try_from(addr: &SockAddr) -> Result<Self, Self::Error> {
        match addr {
            SockAddr::Tcp(addr) => Self::try_from(addr),
            SockAddr::Udp(addr) => Self::try_from(addr),
        }
    }
}

pub fn sock_addr_of(addr: &dyn Addr) -> Option<SockAddr> {
    addr.as_sock_addr()
}

pub trait Conn: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>>;
    fn remote_addr(&self) -> io::Result<Box<dyn Addr>>;
    fn close(&self) -> io::Result<()>;
    fn close_read(&self) -> io::Result<()> {
        Ok(())
    }
    fn close_write(&self) -> io::Result<()> {
        Ok(())
    }
    /// Sets a combined deadline. Only deadline-aware wrappers honour it
    /// (`murmur_common_net::deadline::Conn`); call sites that rely on the expiry must wrap
    /// the conn instead of assuming the default.
    fn set_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Ok(())
    }
    fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Ok(())
    }
    fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Ok(())
    }
    /// Capability: borrowed access to the OS socket underneath, for a conn backed by a real TCP
    /// socket. `None` for anything else, mirroring [`PacketConn::as_socket`]'s rule: a wrapper
    /// answers only if its own type embeds a concrete socket, not merely the `Conn` trait object.
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }
}

pub trait ExtendedConn: Conn {
    fn upstream(&self) -> Option<&dyn Any> {
        None
    }
    fn reader_replaceable(&self) -> bool {
        true
    }
    fn writer_replaceable(&self) -> bool {
        true
    }
}

fn shutdown_fd(stream: &TcpStream, how: std::net::Shutdown) -> io::Result<()> {
    socket2::SockRef::from(stream).shutdown(how)
}

impl Conn for TcpStream {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Self::local_addr(self).map(|addr| boxed_addr(TcpAddr::from(addr)))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Self::peer_addr(self).map(|addr| boxed_addr(TcpAddr::from(addr)))
    }

    fn close(&self) -> io::Result<()> {
        shutdown_fd(self, std::net::Shutdown::Both)
    }

    fn close_read(&self) -> io::Result<()> {
        shutdown_fd(self, std::net::Shutdown::Read)
    }

    fn close_write(&self) -> io::Result<()> {
        shutdown_fd(self, std::net::Shutdown::Write)
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        Some(socket2::SockRef::from(self))
    }
}

/// Moved from `common::net::io` (the crate split's orphan-rule fix): `Conn` and its blanket
/// `Box<C>` impl must live in the same crate.
impl<C: Conn + ?Sized> Conn for Box<C> {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        (**self).local_addr()
    }
    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        (**self).remote_addr()
    }
    fn close(&self) -> io::Result<()> {
        (**self).close()
    }
    fn close_read(&self) -> io::Result<()> {
        (**self).close_read()
    }
    fn close_write(&self) -> io::Result<()> {
        (**self).close_write()
    }
    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        (**self).set_deadline(deadline)
    }
    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        (**self).set_read_deadline(deadline)
    }
    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        (**self).set_write_deadline(deadline)
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        (**self).as_socket()
    }
}

/// Moved from `common::net::io` alongside `Conn for Box<C>` for the same reason.
impl<C: ExtendedConn + ?Sized> ExtendedConn for Box<C> {
    fn upstream(&self) -> Option<&dyn Any> {
        (**self).upstream()
    }
    fn reader_replaceable(&self) -> bool {
        (**self).reader_replaceable()
    }
    fn writer_replaceable(&self) -> bool {
        (**self).writer_replaceable()
    }
}

#[async_trait]
pub trait PacketConn: Any + Send + Sync {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)>;
    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize>;
    fn local_addr(&self) -> io::Result<Box<dyn Addr>>;
    fn close(&self) -> io::Result<()>;

    /// Borrowed access to the OS socket underneath, for a conn backed by a real UDP socket;
    /// `None` for anything else (QUIC-multiplexed, in-process, or otherwise socket-less conns).
    ///
    /// A wrapper answers `Some` only for a socket it owns directly: one that merely holds a
    /// [`PacketConn`] in a named field returns `None` here too.
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }
    fn into_std_udp(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "packet conn does not wrap a raw UDP socket"))
    }
    /// Sets a combined deadline; only deadline-aware wrappers honour it.
    fn set_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Ok(())
    }
    fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Ok(())
    }
    fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl PacketConn for UdpSocket {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let (n, addr) = Self::recv_from(self, buf).await?;
        Ok((n, Box::new(UdpAddr::from(addr))))
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let Some(SockAddr::Udp(addr)) = addr.as_sock_addr() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a udp address"));
        };
        Self::send_to(self, buf, SocketAddr::new(addr.ip, addr.port)).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Self::local_addr(self).map(|addr| boxed_addr(UdpAddr::from(addr)))
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        Some(socket2::SockRef::from(self))
    }

    fn into_std_udp(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        (*self).into_std()
    }
}

/// Moved from `common::net::io` alongside the other blanket `Box<T>` impls for the same reason.
#[async_trait]
impl<P: PacketConn + ?Sized> PacketConn for Box<P> {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        (**self).read_from(buf).await
    }
    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        (**self).write_to(buf, addr).await
    }
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        (**self).local_addr()
    }
    fn close(&self) -> io::Result<()> {
        (**self).close()
    }
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        (**self).as_socket()
    }
    fn into_std_udp(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        (*self).into_std_udp()
    }
    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        (**self).set_deadline(deadline)
    }
    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        (**self).set_read_deadline(deadline)
    }
    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        (**self).set_write_deadline(deadline)
    }
}

#[async_trait]
pub trait Listener: Send + Sync {
    async fn accept(&self) -> io::Result<Box<dyn Conn>>;
    fn close(&self) -> io::Result<()>;
    fn addr(&self) -> io::Result<Box<dyn Addr>>;
}

#[async_trait]
impl Listener for tokio::net::TcpListener {
    // cancel-safe: tokio's `TcpListener::accept` parks until a connection is ready and a dropped accept leaves the queued connection for the next call.
    async fn accept(&self) -> io::Result<Box<dyn Conn>> {
        let (stream, _) = Self::accept(self).await?;
        let _ = stream.set_nodelay(true);
        Ok(Box::new(stream))
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }

    fn addr(&self) -> io::Result<Box<dyn Addr>> {
        Self::local_addr(self).map(|addr| boxed_addr(TcpAddr::from(addr)))
    }
}

/// Moved from `common::net::io` alongside the other blanket `Box<T>` impls for the same reason.
#[async_trait]
impl<L: Listener + ?Sized> Listener for Box<L> {
    // cancel-safe: forwards to the wrapped acceptor and only boxes the result, so a dropped call leaves the inner listener as it was.
    async fn accept(&self) -> io::Result<Box<dyn Conn>> {
        (**self).accept().await
    }
    fn close(&self) -> io::Result<()> {
        (**self).close()
    }
    fn addr(&self) -> io::Result<Box<dyn Addr>> {
        (**self).addr()
    }
}

#[cfg(test)]
mod nodelay_tests {
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::Listener as NetListener;

    /// Accepting a connection sets `TCP_NODELAY` on it, as the production accept path
    /// (`impl Listener for tokio::net::TcpListener`) does.
    #[tokio::test]
    async fn accepted_tcp_conn_has_nodelay_set() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client_task = tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.expect("connect") });
        let conn = NetListener::accept(&listener).await.expect("accept");
        let _client = client_task.await.expect("client task");

        let sock = conn.as_socket().expect("accepted tcp conn exposes its socket");
        assert!(sock.tcp_nodelay().expect("getsockopt(TCP_NODELAY)"), "accepted connection must have TCP_NODELAY set");
    }

    /// Without `TCP_NODELAY`, Nagle's algorithm holds a second small write until the first
    /// segment's ACK arrives. A fresh connection quick-acks its first few segments, so a
    /// single round does not exercise the stall; several request/response rounds exhaust that
    /// budget and put the peer on the kernel's delayed-ACK timer (tens of milliseconds) for the
    /// steady-state round measured below.
    #[tokio::test]
    async fn accepted_tcp_conn_second_write_does_not_wait_for_delayed_ack() {
        const ROUNDS: usize = 8;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client_task = tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let mut resp = [0u8; 2];
            let mut round_trips = Vec::with_capacity(ROUNDS);
            for _ in 0..ROUNDS {
                let start = Instant::now();
                client.write_all(b"?").await.expect("request");
                client.read_exact(&mut resp).await.expect("response");
                round_trips.push(start.elapsed());
            }
            round_trips
        });
        let mut server = NetListener::accept(&listener).await.expect("accept");

        let mut req = [0u8; 1];
        for _ in 0..ROUNDS {
            server.read_exact(&mut req).await.expect("request");
            server.write_all(b"a").await.expect("first write");
            server.write_all(b"b").await.expect("second write");
        }
        let round_trips = client_task.await.expect("client task");

        let steady_state = round_trips.last().copied().expect("at least one round");
        assert!(
            steady_state < Duration::from_millis(10),
            "steady-state round trip must not wait for the peer's delayed ACK, rounds: {round_trips:?}"
        );
    }

    /// XNU's `sosetopt` returns `EINVAL` for a socket already shut down both ways
    /// (`uipc_socket.c`); a peer that resets the connection before `accept` finishes
    /// processing it can put the freshly accepted socket in that state. `accept` above
    /// drops the `set_nodelay` error, so this must still
    /// succeed.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn accept_survives_reset_before_nodelay_setsockopt() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        socket2::SockRef::from(&client).set_linger(Some(Duration::ZERO)).expect("set SO_LINGER");
        drop(client);
        tokio::time::sleep(Duration::from_millis(50)).await;

        NetListener::accept(&listener).await.expect("accept must not fail on a dropped set_nodelay error");
    }
}

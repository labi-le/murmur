//! The control hook a dialer or listener config carries, declared here as
//! `StdDialer`/`StdListenConfig`.
//!
//! A hook receives the raw descriptor itself, which the fd-based socket-option helpers already
//! assume, and the platform interface lookups a hook may need are async, so the hooks are futures
//! too.

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::future::BoxFuture;
use parking_lot::Mutex;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

use crate::keepalive::tcp_keepalive::tcp_keep_alive;
use crate::keepalive::tcp_keepalive_config::{KeepAliveConfig, KeepAliveFields};
use crate::mptcp::MultipathTcpFlag;
use crate::resolver::resolver::{lookup_ip_with_resolver, proxy_server_host_resolver};
use murmur_common::time::TimeDuration;
use murmur_common_net::io::{Acceptor, Datagram, Stream, TcpAcceptor, UdpAcceptor};
#[cfg(windows)]
use murmur_log::debugln;

use murmur_common::net_addr::split_host_port;

/// A control hook; the descriptor it receives is the raw socket.
pub type ControlFn =
    Arc<dyn Fn(&CancellationToken, String, String, usize) -> BoxFuture<'static, anyhow::Result<()>> + Send + Sync>;

/// A control hook with no context, for callers that have none.
pub type BasicControlFn = Arc<dyn Fn(String, String, usize) -> BoxFuture<'static, anyhow::Result<()>> + Send + Sync>;

#[derive(Clone)]
pub struct StdDialer {
    pub local_addr: Option<SocketAddr>,
    pub control: Option<BasicControlFn>,
    pub control_context: Option<ControlFn>,
    pub keep_alive: TimeDuration,
    pub keep_alive_config: KeepAliveConfig,
    pub multipath_tcp: bool,
}

impl std::fmt::Debug for StdDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdDialer")
            .field("local_addr", &self.local_addr)
            .field("keep_alive", &self.keep_alive)
            .field("keep_alive_config", &self.keep_alive_config)
            .field("multipath_tcp", &self.multipath_tcp)
            .finish_non_exhaustive()
    }
}

impl Default for StdDialer {
    fn default() -> Self {
        Self {
            local_addr: None,
            control: None,
            control_context: None,
            keep_alive: 0,
            keep_alive_config: KeepAliveConfig { enable: false, idle: 0, interval: 0, count: 0 },
            multipath_tcp: false,
        }
    }
}

impl KeepAliveFields for StdDialer {
    fn set_keep_alive(&mut self, keep_alive: TimeDuration) {
        self.keep_alive = keep_alive;
    }

    fn keep_alive_config_mut(&mut self) -> &mut KeepAliveConfig {
        &mut self.keep_alive_config
    }
}

impl MultipathTcpFlag for StdDialer {
    fn set_multipath_tcp(&mut self, open: bool) {
        self.multipath_tcp = open;
    }

    fn multipath_tcp(&self) -> bool {
        self.multipath_tcp
    }
}

#[derive(Clone)]
pub struct StdListenConfig {
    pub control: Option<BasicControlFn>,
    pub disable_tfo: bool,
    pub keep_alive: TimeDuration,
    pub keep_alive_config: KeepAliveConfig,
    pub multipath_tcp: bool,
}

impl std::fmt::Debug for StdListenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdListenConfig")
            .field("disable_tfo", &self.disable_tfo)
            .field("keep_alive", &self.keep_alive)
            .field("keep_alive_config", &self.keep_alive_config)
            .field("multipath_tcp", &self.multipath_tcp)
            .finish_non_exhaustive()
    }
}

impl Default for StdListenConfig {
    fn default() -> Self {
        Self {
            control: None,
            disable_tfo: true,
            keep_alive: 0,
            keep_alive_config: KeepAliveConfig { enable: false, idle: 0, interval: 0, count: 0 },
            multipath_tcp: false,
        }
    }
}

impl KeepAliveFields for StdListenConfig {
    fn set_keep_alive(&mut self, keep_alive: TimeDuration) {
        self.keep_alive = keep_alive;
    }

    fn keep_alive_config_mut(&mut self) -> &mut KeepAliveConfig {
        &mut self.keep_alive_config
    }
}

impl MultipathTcpFlag for StdListenConfig {
    fn set_multipath_tcp(&mut self, open: bool) {
        self.multipath_tcp = open;
    }

    fn multipath_tcp(&self) -> bool {
        self.multipath_tcp
    }
}

pub fn add_control_to_listen_config(lc: &mut StdListenConfig, fn_: ControlFn) {
    let llc = lc.clone();
    let previous = llc.control;
    lc.control = Some(Arc::new(move |network: String, address: String, fd: usize| {
        let previous = previous.clone();
        let fn_ = Arc::clone(&fn_);
        Box::pin(async move {
            if let Some(previous) = &previous {
                previous(network.clone(), address.clone(), fd).await?;
            }
            fn_(&CancellationToken::new(), network, address, fd).await
        })
    }));
}

pub(crate) fn add_control_to_dialer(d: &mut StdDialer, fn_: ControlFn) {
    let ld = d.clone();
    let previous_context = ld.control_context;
    let previous = ld.control;
    d.control_context = Some(Arc::new(move |ctx: &CancellationToken, network: String, address: String, fd: usize| {
        let previous_context = previous_context.clone();
        let previous = previous.clone();
        let fn_ = Arc::clone(&fn_);
        let ctx = ctx.clone();
        Box::pin(async move {
            if let Some(previous_context) = &previous_context {
                previous_context(&ctx, network.clone(), address.clone(), fd).await?;
            } else if let Some(previous) = &previous {
                previous(network.clone(), address.clone(), fd).await?;
            }
            fn_(&ctx, network, address, fd).await
        })
    }));
}

/// The raw descriptor, which the socket-option helpers take as an integer.
#[cfg(unix)]
pub(crate) fn socket_fd(socket: &Socket) -> usize {
    use std::os::fd::AsRawFd;
    #[expect(clippy::cast_sign_loss, reason = "a socket file descriptor is non-negative by construction")]
    let fd = socket.as_raw_fd() as usize;
    fd
}

#[cfg(windows)]
pub(crate) fn socket_fd(socket: &Socket) -> usize {
    use std::os::windows::io::AsRawSocket;
    usize::try_from(socket.as_raw_socket()).unwrap_or(usize::MAX)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn socket_fd(_socket: &Socket) -> usize {
    0
}

/// Disables the two ICMP-driven resets Windows reports on `recv`/`WSARecv` for UDP sockets that
/// BSD sockets never surface: `WSAECONNRESET` from a prior `ICMP_PORT_UNREACHABLE` and
/// `WSAECONNABORTED` from a prior `ICMP_NET_UNREACHABLE` to *any* peer this socket has sent to,
/// connected or not.
///
/// `SIO_UDP_CONNRESET` is required: unsupported means the platform cannot give BSD-like `recv`
/// semantics at all. `SIO_UDP_NETRESET` is best-effort here: Wine's `ws2_32` does not implement it
/// (`WSAEOPNOTSUPP`) even though real Windows (Vista+) does, and the rarer
/// `ICMP_NET_UNREACHABLE` case it guards against is not what this fix targets.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "`WSAIoctl` is a raw FFI call; the SAFETY comment below states the handle and buffer invariants"
)]
pub(crate) fn disable_udp_icmp_resets(socket: &Socket) -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{WSAIoctl, SIO_UDP_CONNRESET, SIO_UDP_NETRESET};

    // SAFETY: `sysfd` is the raw handle of `socket`, kept alive by the `&Socket` borrow for the
    // calls' duration. `flag` is a valid 4-byte input buffer and `returned` a valid 4-byte
    // output-length receiver; no overlapped I/O or completion routine is used.
    let ioctl = |code: u32| -> io::Result<()> {
        let flag: u32 = 0;
        let mut returned: u32 = 0;
        let rc = unsafe {
            WSAIoctl(
                socket_fd(socket),
                code,
                (&raw const flag).cast(),
                u32::try_from(size_of::<u32>()).unwrap_or(u32::MAX),
                std::ptr::null_mut(),
                0,
                &raw mut returned,
                std::ptr::null_mut(),
                None,
            )
        };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };

    ioctl(SIO_UDP_CONNRESET)?;
    if let Err(err) = ioctl(SIO_UDP_NETRESET) {
        debugln!("SIO_UDP_NETRESET unsupported on this UDP socket, ICMP net-unreachable resets stay enabled: {err}");
    }
    Ok(())
}

/// Pre-creates and binds the UDP socket `quinn::Endpoint::client` binds internally.
///
/// The socket is built exactly as `quinn`'s `Endpoint::client` builds it (`Domain::for_address`/
/// `Type::DGRAM`/`Protocol::UDP`, dual-stack for a wildcard IPv6 bind address), so a caller that
/// needs `disable_udp_icmp_resets` applied before the socket reaches quinn can hand this socket to
/// `quinn::Endpoint::new` with the same `EndpointConfig::default()`/`quinn::default_runtime()`.
pub fn bind_quic_client_socket(bind_addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(Protocol::UDP))?;
    if bind_addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    socket.bind(&SockAddr::from(bind_addr))?;
    #[cfg(windows)]
    disable_udp_icmp_resets(&socket)?;
    Ok(socket.into())
}

#[cfg(target_os = "linux")]
const IPPROTO_MPTCP: i32 = 0x106;

/// Probes the running kernel once for MPTCP support, by attempting to create an
/// `IPPROTO_MPTCP` socket, and caches the result. `EPROTONOSUPPORT`/`EINVAL` mean the kernel has
/// no MPTCP support (< 5.6); any other error is treated as "available but currently failing".
#[cfg(target_os = "linux")]
fn supports_multipath_tcp() -> bool {
    static AVAILABLE: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
        let domain = if supports_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        match Socket::new(domain, Type::STREAM, Some(Protocol::from(IPPROTO_MPTCP))) {
            Ok(_) => true,
            Err(err) => !matches!(err.raw_os_error(), Some(libc::EPROTONOSUPPORT | libc::EINVAL)),
        }
    });
    *AVAILABLE
}

/// Whether IPv4 works at all, narrowed to the one use here: which address family to probe MPTCP
/// availability with.
#[cfg(target_os = "linux")]
fn supports_ipv4() -> bool {
    static ENABLED: std::sync::LazyLock<bool> =
        std::sync::LazyLock::new(|| Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).is_ok());
    *ENABLED
}

#[cfg(target_os = "linux")]
fn mptcp_protocol(open: bool) -> Option<Protocol> {
    (open && supports_multipath_tcp()).then(|| Protocol::from(IPPROTO_MPTCP))
}

#[cfg(not(target_os = "linux"))]
fn mptcp_protocol(_open: bool) -> Option<Protocol> {
    None
}

fn is_connect_in_progress(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(libc::EINPROGRESS)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// The family-qualified network the hook sees.
fn ctrl_network(network: &str, remote: SocketAddr) -> String {
    if network.ends_with('4') || network.ends_with('6') {
        return network.to_owned();
    }
    if remote.is_ipv4() {
        format!("{network}4")
    } else {
        format!("{network}6")
    }
}

/// The address family to dial.
const fn dial_family(network: &str, remote: SocketAddr) -> Domain {
    match network.as_bytes().last() {
        Some(b'4') => Domain::IPV4,
        Some(b'6') => Domain::IPV6,
        _ => {
            if remote.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            }
        }
    }
}

/// Decides the family of a wildcard listener.
const fn supports_ipv4_map() -> bool {
    #[cfg(any(target_os = "dragonfly", target_os = "openbsd"))]
    {
        false
    }
    #[cfg(not(any(target_os = "dragonfly", target_os = "openbsd")))]
    {
        true
    }
}

/// The address family to listen on; `local` is `None` for a wildcard address.
fn listen_family(network: &str, local: Option<IpAddr>) -> (Domain, bool) {
    match network.as_bytes().last() {
        Some(b'4') => return (Domain::IPV4, false),
        Some(b'6') => return (Domain::IPV6, true),
        _ => {}
    }

    if local.is_none() && supports_ipv4_map() {
        return (Domain::IPV6, false);
    }

    match local {
        Some(IpAddr::V6(_)) => (Domain::IPV6, false),
        _ => (Domain::IPV4, false),
    }
}

/// The listen backlog to request. Windows' `SOMAXCONN` is `0x7fffffff`, a sentinel `listen()`
/// recognizes specially and expands to a large OS-chosen backlog; it is not a literal queue
/// length request. `android` takes the same `/proc` path as Linux. `darwin`/`ios` and `freebsd`
/// read a kernel sysctl by name; `openbsd` reads one by numeric MIB, since it has no
/// `sysctlbyname`. All of them fall back to the 128 that `SOMAXCONN` is on every platform this
/// binary targets when the read fails or reports zero.
fn listener_backlog() -> i32 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        std::fs::read_to_string("/proc/sys/net/core/somaxconn")
            .ok()
            .and_then(|value| value.split_whitespace().next()?.parse::<i64>().ok())
            .map_or(128, listener_backlog_from_somaxconn)
    }
    #[cfg(target_os = "windows")]
    {
        i32::MAX
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        sysctl_backlog("kern.ipc.somaxconn")
    }
    #[cfg(target_os = "freebsd")]
    {
        sysctl_backlog("kern.ipc.soacceptqueue")
    }
    #[cfg(target_os = "openbsd")]
    {
        sysctl_kern_somaxconn()
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "windows",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd"
    )))]
    {
        128
    }
}

/// Parsing `somaxconn` caps at `0xFFFFFF` and reports failure once the accumulated value reaches
/// it, so the backlog falls back to `SOMAXCONN` (128) instead of handing an overflowed value to
/// `max_ack_backlog`, the same fallback used for a literal zero.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn listener_backlog_from_somaxconn(value: i64) -> i32 {
    if value == 0 || value >= 0xFFFFFF {
        128
    } else {
        max_ack_backlog(value)
    }
}

/// The kernel stores the listen backlog as a `u16` before kernel 4.1 and a `u32` from 4.1
/// onward; truncate to that range instead of wrapping, unlike the flat `65535` clamp applied
/// previously on every kernel.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn max_ack_backlog(n: i64) -> i32 {
    let max = if kernel_version_at_least(4, 1) { i64::from(u32::MAX) } else { i64::from(u16::MAX) };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the kernel takes the backlog as a 32-bit int; the clamp above bounds the value to the uint32 range"
    )]
    let backlog = n.min(max).max(0) as i32;
    backlog
}

/// The kernel version: the first two dot-separated integers in
/// `uname().release`, or `(0, 0)` if it cannot be read or parsed.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[expect(unsafe_code, reason = "`uname` fills its result through an out-parameter, which safe Rust cannot express")]
fn kernel_version_at_least(want_major: u32, want_minor: u32) -> bool {
    // SAFETY: `uname` is a plain out-parameter call; `name` is default-initialized and large
    // enough for the struct the kernel fills in.
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&raw mut name) } != 0 {
        return false;
    }
    let release: Vec<u8> = name.release.iter().take_while(|&&c| c != 0).map(|&c| c.cast_unsigned()).collect();
    let release = String::from_utf8_lossy(&release);
    let mut parts = release.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty());
    let major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor) >= (want_major, want_minor)
}

/// Reads a `u32` sysctl by name, truncating as the backlog computation does: a zero or
/// errored read falls back to `SOMAXCONN` (128 on every BSD this binary
/// targets), and any value above `u16::MAX` is clamped because FreeBSD, like Linux, stores the
/// backlog in a `u16`.
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
#[expect(
    unsafe_code,
    reason = "`sysctlbyname` fills its result through out-parameters, which safe Rust cannot express"
)]
fn sysctl_backlog(name: &str) -> i32 {
    let Ok(name) = CString::new(name) else {
        return 128;
    };
    let mut value: u32 = 0;
    let mut length = std::mem::size_of::<u32>();
    // SAFETY: `value` is sized for a `u32` and `length` reports that size, so the kernel writes
    // at most `size_of::<u32>()` bytes into it.
    let ret = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::addr_of_mut!(value).cast::<libc::c_void>(),
            std::ptr::addr_of_mut!(length),
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || value == 0 {
        return 128;
    }
    value.min(u32::from(u16::MAX)) as i32
}

/// The `kern.somaxconn` sysctl on openbsd, which has no `sysctlbyname` and
/// resolves the name through the fixed `[CTL_KERN, KERN_SOMAXCONN]` MIB instead.
#[cfg(target_os = "openbsd")]
#[expect(unsafe_code, reason = "`sysctl` fills its result through out-parameters, which safe Rust cannot express")]
fn sysctl_kern_somaxconn() -> i32 {
    let mib = [libc::CTL_KERN, libc::KERN_SOMAXCONN];
    let mut value: u32 = 0;
    let mut length = std::mem::size_of::<u32>();
    // SAFETY: `value` is sized for a `u32` and `length` reports that size, so the kernel writes
    // at most `size_of::<u32>()` bytes into it.
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::addr_of_mut!(value).cast::<libc::c_void>(),
            std::ptr::addr_of_mut!(length),
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || value == 0 {
        return 128;
    }
    value.min(u32::from(u16::MAX)) as i32
}

fn closed_conn_error() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection")
}

/// The accepted network argument kinds; `Some(true)` is datagram.
fn network_kind(network: &str) -> Option<bool> {
    match network {
        "tcp" | "tcp4" | "tcp6" => Some(false),
        "udp" | "udp4" | "udp6" => Some(true),
        _ => None,
    }
}

fn address_matches(network: &str, addr: SocketAddr) -> bool {
    if network.ends_with('4') {
        return addr.is_ipv4();
    }
    if network.ends_with('6') {
        return addr.is_ipv6();
    }
    true
}

/// An empty address is shorthand for "any address, any port" (the host/port split is never even
/// attempted in that case); `split_host_port`
/// requires a port, so the empty-address case is handled before delegating to it.
fn resolve_local_address(address: &str) -> anyhow::Result<(Option<IpAddr>, u16)> {
    if address.is_empty() {
        return Ok((None, 0));
    }
    let (host, port) = split_host_port(address)?;
    let port = port.parse::<u16>()?;
    if host.is_empty() {
        return Ok((None, port));
    }
    Ok((Some(host.parse::<IpAddr>()?), port))
}

fn local_bind_addr(domain: Domain, local: Option<IpAddr>, port: u16) -> SocketAddr {
    match local {
        Some(ip) => SocketAddr::new(ip, port),
        None => {
            if domain == Domain::IPV6 {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
            }
        }
    }
}

/// Joins errors into one; the joined message is what a caller reads.
pub fn join_errors(mut errs: Vec<anyhow::Error>) -> anyhow::Error {
    if errs.len() > 1 {
        let messages: Vec<String> = errs.iter().map(ToString::to_string).collect();
        return anyhow::anyhow!("{}", messages.join("\n"));
    }
    errs.pop().unwrap_or_else(|| anyhow::anyhow!(""))
}

impl StdDialer {
    // cancel-safe: a cancelled attempt drops the connection it opened, and the control hook keeps
    // no state, so nothing outlives the call.
    pub async fn dial_context(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> anyhow::Result<Box<dyn Stream>> {
        if ctx.is_cancelled() {
            return Err(anyhow::anyhow!("context canceled"));
        }

        let Some(is_udp) = network_kind(network) else {
            return Err(anyhow::anyhow!("dial {network} {address}: unknown network {network}"));
        };

        let mut errs = Vec::new();
        let mut suitable = false;
        for remote in self.resolve_remote(ctx, address).await? {
            if !address_matches(network, remote) {
                continue;
            }
            suitable = true;
            match self.dial_addr(ctx, network, remote, address, is_udp).await {
                Ok(conn) => return Ok(conn),
                Err(err) => errs.push(err),
            }
        }

        if !suitable {
            return Err(anyhow::anyhow!("address {address}: no suitable address found"));
        }
        Err(join_errors(errs))
    }

    /// The dialer only ever hands this one an already-resolved literal; a name goes to this
    /// project's resolver (`proxy_server_host_resolver`, the default when no resolver is set).
    async fn resolve_remote(&self, ctx: &CancellationToken, address: &str) -> anyhow::Result<Vec<SocketAddr>> {
        if let Ok(addr) = address.parse::<SocketAddr>() {
            return Ok(vec![addr]);
        }
        let (host, port) = split_host_port(address)?;
        let port: u16 = port.parse().map_err(|_| anyhow::anyhow!("address {address}: unknown port {port}"))?;
        let ips = lookup_ip_with_resolver(ctx, &host, proxy_server_host_resolver().as_deref()).await?;
        Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
    }

    async fn dial_addr(
        &self,
        ctx: &CancellationToken,
        network: &str,
        remote: SocketAddr,
        address: &str,
        is_udp: bool,
    ) -> anyhow::Result<Box<dyn Stream>> {
        let plain_protocol = if is_udp { Protocol::UDP } else { Protocol::TCP };

        if let Some(protocol) = mptcp_protocol(self.multipath_tcp && !is_udp) {
            if let Ok(conn) = self.dial_addr_proto(ctx, network, remote, address, is_udp, protocol).await {
                return Ok(conn);
            }
        }

        self.dial_addr_proto(ctx, network, remote, address, is_udp, plain_protocol).await
    }

    /// One full dial attempt with a fixed protocol. The MPTCP path runs this whole attempt with
    /// `IPPROTO_MPTCP` and, on *any* error from it — not only socket creation — reruns it from
    /// scratch with plain TCP, including a second control-hook call; `dial_addr` mirrors that by
    /// calling this twice.
    // cancel-safe: the socket is owned by this call, so a drop before it returns closes it.
    async fn dial_addr_proto(
        &self,
        ctx: &CancellationToken,
        network: &str,
        remote: SocketAddr,
        address: &str,
        is_udp: bool,
        protocol: Protocol,
    ) -> anyhow::Result<Box<dyn Stream>> {
        let domain = dial_family(network, remote);
        let socket_type = if is_udp { Type::DGRAM } else { Type::STREAM };
        let ipv6only = network.ends_with('6');

        let socket = Socket::new(domain, socket_type, Some(protocol))?;
        socket.set_nonblocking(true)?;

        if domain == Domain::IPV6 {
            socket.set_only_v6(ipv6only)?;
        }
        if is_udp {
            socket.set_broadcast(true)?;
        } else {
            let _ = socket.set_tcp_nodelay(true);
        }

        self.apply_control(ctx, &ctrl_network(network, remote), address, &socket).await?;

        if let Some(local) = self.local_addr {
            socket.bind(&SockAddr::from(local))?;
        }

        #[cfg(windows)]
        if is_udp {
            disable_udp_icmp_resets(&socket)?;
        }

        match socket.connect(&SockAddr::from(remote)) {
            Ok(()) => {}
            Err(err) if is_connect_in_progress(&err) => {}
            Err(err) => return Err(err.into()),
        }

        if is_udp {
            let socket = UdpSocket::from_std(std::net::UdpSocket::from(socket))?;
            return Ok(Box::new(ConnectedUdpConn::new(socket)));
        }

        let stream = TcpStream::from_std(std::net::TcpStream::from(socket))?;
        tokio::select! {
            biased;
            () = ctx.cancelled() => return Err(anyhow::anyhow!("context canceled")),
            result = stream.writable() => result?,
        }
        if ctx.is_cancelled() {
            return Err(anyhow::anyhow!("context canceled"));
        }
        if let Some(err) = stream.take_error()? {
            return Err(err.into());
        }
        if ctx.is_cancelled() {
            return Err(anyhow::anyhow!("context canceled"));
        }
        tcp_keep_alive(&stream);

        Ok(Box::new(stream))
    }

    /// Both hook kinds can be set; the context-ful one wins.
    async fn apply_control(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
        socket: &Socket,
    ) -> anyhow::Result<()> {
        let fd = socket_fd(socket);
        if let Some(control) = &self.control_context {
            control(ctx, network.to_owned(), address.to_owned(), fd).await
        } else if let Some(control) = &self.control {
            control(network.to_owned(), address.to_owned(), fd).await
        } else {
            Ok(())
        }
    }
}

impl StdListenConfig {
    pub async fn listen(
        &self,
        _ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> anyhow::Result<Box<dyn Acceptor>> {
        if network_kind(network) != Some(false) {
            return Err(anyhow::anyhow!("listen {network} {address}: unknown network {network}"));
        }

        if let Some(protocol) = mptcp_protocol(self.multipath_tcp) {
            if let Ok(listener) = self.listen_proto(network, address, protocol).await {
                return Ok(listener);
            }
        }

        self.listen_proto(network, address, Protocol::TCP).await
    }

    /// One full listen attempt with a fixed protocol. The MPTCP path runs this whole attempt with
    /// `IPPROTO_MPTCP` and, on *any* error from it, reruns it from scratch with plain TCP,
    /// including a second control-hook call; `listen` mirrors that by calling this twice.
    async fn listen_proto(
        &self,
        network: &str,
        address: &str,
        protocol: Protocol,
    ) -> anyhow::Result<Box<dyn Acceptor>> {
        let (local_ip, port) = resolve_local_address(address)?;
        let (domain, ipv6only) = listen_family(network, local_ip);
        let bind_addr = local_bind_addr(domain, local_ip, port);

        let socket = Socket::new(domain, Type::STREAM, Some(protocol))?;
        socket.set_nonblocking(true)?;
        if domain == Domain::IPV6 {
            socket.set_only_v6(ipv6only)?;
        }

        // `SO_REUSEADDR` is set on Unix but deliberately not on Windows: there it lets a socket
        // forcibly steal a port already bound by another socket, so `SO_EXCLUSIVEADDRUSE` is left
        // unset too.
        #[cfg(unix)]
        socket.set_reuse_address(true)?;

        if let Some(control) = &self.control {
            control(ctrl_network(network, bind_addr), address.to_owned(), socket_fd(&socket)).await?;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if !self.disable_tfo {
            set_tfo_listener(&socket).map_err(|err| anyhow::anyhow!("setsockopt(TCP_FASTOPEN): {err}"))?;
        }

        socket.bind(&SockAddr::from(bind_addr))?;
        socket.listen(listener_backlog())?;

        let listener = TcpListener::from_std(std::net::TcpListener::from(socket))?;
        Ok(Box::new(TcpAcceptor::new(listener)))
    }

    pub async fn listen_packet(
        &self,
        _ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> anyhow::Result<Box<dyn Datagram>> {
        if network_kind(network) != Some(true) {
            return Err(anyhow::anyhow!("listen {network} {address}: unknown network {network}"));
        }

        let (local_ip, port) = resolve_local_address(address)?;
        let (domain, ipv6only) = listen_family(network, local_ip);

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        if domain == Domain::IPV6 {
            socket.set_only_v6(ipv6only)?;
        }
        socket.set_broadcast(true)?;

        let multicast = local_ip.is_some_and(|ip| ip.is_multicast());
        if multicast {
            #[cfg(unix)]
            {
                socket.set_reuse_address(true)?;
                #[cfg(not(target_os = "linux"))]
                murmur_common::sockopt::reuse_common::raw_conn_reuseaddr(&socket)?;
            }
            #[cfg(windows)]
            socket.set_reuse_address(true)?;
        }

        let bind_addr =
            if multicast { local_bind_addr(domain, None, port) } else { local_bind_addr(domain, local_ip, port) };

        if let Some(control) = &self.control {
            control(ctrl_network(network, bind_addr), address.to_owned(), socket_fd(&socket)).await?;
        }

        socket.bind(&SockAddr::from(bind_addr))?;

        #[cfg(windows)]
        disable_udp_icmp_resets(&socket)?;

        let socket = UdpSocket::from_std(std::net::UdpSocket::from(socket))?;
        Ok(Box::new(UdpAcceptor::new(socket)))
    }
}
#[cfg(any(target_os = "linux", target_os = "android"))]
#[expect(
    unsafe_code,
    reason = "`setsockopt` is a raw FFI call; the SAFETY comment below states the descriptor and buffer invariants"
)]
fn set_tfo_listener(socket: &Socket) -> io::Result<()> {
    let backlog = listener_backlog();
    let fd = libc::c_int::try_from(socket_fd(socket))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket descriptor does not fit an int"))?;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a `socklen_t` describes a length in bytes and is never narrower than the `int` above it"
    )]
    // SAFETY: socket remains alive during the call and `backlog` is a valid integer input.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            std::ptr::addr_of!(backlog).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The connected datagram conn a `udp` dial returns.
#[derive(Debug)]
pub struct ConnectedUdpConn {
    socket: Mutex<Option<Arc<UdpSocket>>>,
}

impl ConnectedUdpConn {
    fn new(socket: UdpSocket) -> Self {
        Self { socket: Mutex::new(Some(Arc::new(socket))) }
    }

    fn socket(&self) -> io::Result<Arc<UdpSocket>> {
        let guard = self.socket.lock();
        match guard.as_ref() {
            Some(socket) => Ok(Arc::clone(socket)),
            None => Err(closed_conn_error()),
        }
    }
}

impl AsyncRead for ConnectedUdpConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let guard = self.get_mut().socket.lock();
        let Some(socket) = guard.as_ref() else {
            return Poll::Ready(Err(closed_conn_error()));
        };
        let poll = socket.poll_recv(cx, buf).map_ok(|()| ());
        drop(guard);
        poll
    }
}

impl AsyncWrite for ConnectedUdpConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let guard = self.get_mut().socket.lock();
        let Some(socket) = guard.as_ref() else {
            return Poll::Ready(Err(closed_conn_error()));
        };
        let poll = socket.poll_send(cx, buf);
        drop(guard);
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for ConnectedUdpConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket()?.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.socket()?.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.socket.lock().take();
        Ok(())
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.socket.lock().take();
        Ok(())
    }
}

#[cfg(test)]
mod connected_udp_conn_tests {
    use std::net::Ipv4Addr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn read_and_write_round_trip_a_datagram() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client.connect(server_addr).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let mut conn = ConnectedUdpConn::new(client);

        conn.write_all(b"ping").await.unwrap();
        let mut recv_buf = [0u8; 16];
        let (n, from) = server.recv_from(&mut recv_buf).await.unwrap();
        assert_eq!(&recv_buf[..n], b"ping");
        assert_eq!(from, client_addr);

        server.send_to(b"pong!", client_addr).await.unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong!");
    }
}

#[cfg(test)]
mod dial_cancel_race_tests {
    use std::net::Ipv4Addr;

    use super::*;

    // a cancelled dial always ends in a cancellation error (a deferred cancel plus the guard on
    // `EINPROGRESS`). `dial_addr_proto` raced `stream.writable()`
    // against `ctx.cancelled()` in an unbiased `select!`, so a fast loopback connect could win
    // the race and hand back a live connection from an already-cancelled dial.
    #[tokio::test]
    async fn cancelled_dial_never_returns_a_live_conn() {
        let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let remote = server.local_addr().unwrap();
        std::thread::spawn(move || while server.accept().is_ok() {});

        let dialer = StdDialer::default();
        for _ in 0..300 {
            let ctx = CancellationToken::new();
            ctx.cancel();
            let result = dialer.dial_addr_proto(&ctx, "tcp", remote, &remote.to_string(), false, Protocol::TCP).await;
            assert!(result.is_err(), "cancelled dial returned a live connection");
        }
    }
}

#[cfg(test)]
mod resolve_remote_tests {
    use async_trait::async_trait;
    use hickory_proto::op::Message;

    use super::*;
    use crate::resolver::resolver::{set_proxy_server_host_resolver, Resolver, SharedResolver};

    /// Answers one canned address and records every host it was asked for.
    struct RecordingResolver {
        answer: IpAddr,
        asked: Mutex<Vec<String>>,
    }

    impl RecordingResolver {
        fn answer(&self, host: &str) -> anyhow::Result<Vec<IpAddr>> {
            self.asked.lock().push(host.to_owned());
            Ok(vec![self.answer])
        }
    }

    #[async_trait]
    impl Resolver for RecordingResolver {
        async fn lookup_ip(&self, _ctx: &CancellationToken, host: &str) -> anyhow::Result<Vec<IpAddr>> {
            self.answer(host)
        }

        async fn lookup_ipv4(&self, _ctx: &CancellationToken, host: &str) -> anyhow::Result<Vec<IpAddr>> {
            self.answer(host)
        }

        async fn lookup_ipv6(&self, _ctx: &CancellationToken, host: &str) -> anyhow::Result<Vec<IpAddr>> {
            self.answer(host)
        }

        async fn resolve_ech(&self, _ctx: &CancellationToken, _host: &str) -> anyhow::Result<Vec<u8>> {
            panic!("the recording resolver only resolves addresses")
        }

        async fn exchange_context(&self, _ctx: &CancellationToken, _m: &Message) -> anyhow::Result<Message> {
            panic!("the recording resolver only resolves addresses")
        }

        fn invalid(&self) -> bool {
            true
        }

        fn clear_cache(&self) {}

        fn reset_connection(&self) {}
    }

    #[tokio::test]
    async fn names_resolve_through_the_port_resolver_and_literals_do_not() {
        let previous: Option<SharedResolver> = proxy_server_host_resolver();
        let resolver = Arc::new(RecordingResolver {
            answer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            asked: Mutex::new(Vec::new()),
        });
        let resolver_arc = Arc::clone(&resolver);
        let installed: SharedResolver = resolver_arc;
        set_proxy_server_host_resolver(Some(installed));

        let dialer = StdDialer::default();
        let ctx = CancellationToken::new();

        let addrs = dialer.resolve_remote(&ctx, "example.com:443").await.expect("resolve example.com");
        assert_eq!(vec![SocketAddr::from(([192, 0, 2, 7], 443))], addrs);
        assert_eq!(vec!["example.com".to_owned()], *resolver.asked.lock());

        let literal: SocketAddr = "192.0.2.9:8443".parse().unwrap();
        assert_eq!(vec![literal], dialer.resolve_remote(&ctx, &literal.to_string()).await.expect("literal"));
        assert_eq!(vec!["example.com".to_owned()], *resolver.asked.lock(), "a literal must not reach the resolver");

        set_proxy_server_host_resolver(previous);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod mptcp_fallback_tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn can_create_mptcp_socket() -> bool {
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::from(IPPROTO_MPTCP))).is_ok()
    }

    fn counting_control(calls: Arc<AtomicUsize>, fail_first: bool) -> BasicControlFn {
        Arc::new(move |_network, _address, _fd| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if fail_first && n == 1 {
                    Err(anyhow::anyhow!("synthetic mptcp control failure"))
                } else {
                    Ok(())
                }
            })
        })
    }

    // The MPTCP path fails back to a complete plain-TCP retry on any error past socket creation,
    // including a second control-hook call, rather than surfacing the MPTCP-specific error.
    #[tokio::test]
    async fn dial_falls_back_to_plain_tcp_when_mptcp_attempt_fails_after_socket_creation() {
        if !can_create_mptcp_socket() {
            eprintln!("skipping: host cannot create IPPROTO_MPTCP sockets");
            return;
        }

        let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let remote = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let _ = server.accept();
        });

        let calls = Arc::new(AtomicUsize::new(0));
        let dialer = StdDialer {
            control: Some(counting_control(Arc::clone(&calls), true)),
            multipath_tcp: true,
            ..StdDialer::default()
        };

        let ctx = CancellationToken::new();
        let conn = dialer.dial_addr(&ctx, "tcp", remote, &remote.to_string(), false).await;
        assert!(
            conn.is_ok(),
            "dial should fall back to plain TCP: {}",
            conn.err().map(|e| e.to_string()).unwrap_or_default()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2, "control hook must run once per full attempt");
    }

    // the fallback has no error-type filter: it returns the conn on success and otherwise falls
    // through unconditionally. A refused port fails identically on both the MPTCP
    // and the plain-TCP attempt, so this proves the retry runs regardless of the error class.
    #[tokio::test]
    async fn dial_refused_port_retries_once_with_plain_tcp() {
        if !can_create_mptcp_socket() {
            eprintln!("skipping: host cannot create IPPROTO_MPTCP sockets");
            return;
        }

        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let remote = probe.local_addr().unwrap();
        drop(probe);

        let calls = Arc::new(AtomicUsize::new(0));
        let dialer = StdDialer {
            control: Some(counting_control(Arc::clone(&calls), false)),
            multipath_tcp: true,
            ..StdDialer::default()
        };

        let ctx = CancellationToken::new();
        let err = dialer.dial_addr(&ctx, "tcp", remote, &remote.to_string(), false).await.err().unwrap();
        assert!(
            err.to_string().to_lowercase().contains("refused"),
            "expected connection refused from the plain-TCP retry, got: {err}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the whole dial is retried on ANY error, including ECONNREFUSED");
    }

    // Like the dial case above: any error past socket creation reruns the whole listen with plain
    // TCP.
    #[tokio::test]
    async fn listen_falls_back_to_plain_tcp_when_mptcp_attempt_fails_after_socket_creation() {
        if !can_create_mptcp_socket() {
            eprintln!("skipping: host cannot create IPPROTO_MPTCP sockets");
            return;
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let listen_config = StdListenConfig {
            control: Some(counting_control(Arc::clone(&calls), true)),
            multipath_tcp: true,
            ..StdListenConfig::default()
        };

        let ctx = CancellationToken::new();
        let listener = listen_config.listen(&ctx, "tcp", "127.0.0.1:0").await;
        assert!(
            listener.is_ok(),
            "listen should fall back to plain TCP: {}",
            listener.err().map(|e| e.to_string()).unwrap_or_default()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2, "control hook must run once per full attempt");
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod listener_tfo_tests {
    use std::os::fd::AsRawFd;
    use std::sync::{
        atomic::{AtomicI32, Ordering},
        Arc,
    };

    use super::{listener_backlog, StdListenConfig};
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};
    use tokio_util::sync::CancellationToken;

    #[expect(
        unsafe_code,
        reason = "`getsockopt` is a raw FFI call; the SAFETY comment below states the descriptor and pointer invariants"
    )]
    fn tcp_fastopen(fd: libc::c_int) -> libc::c_int {
        let mut actual: libc::c_int = -1;
        let mut length = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: the caller holds the listener open and both output pointers are valid.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN,
                std::ptr::addr_of_mut!(actual).cast(),
                &raw mut length,
            )
        };
        assert_eq!(result, 0, "getsockopt(TCP_FASTOPEN): {}", std::io::Error::last_os_error());
        assert_eq!(length as usize, size_of::<libc::c_int>());
        actual
    }

    #[tokio::test]
    async fn listener_tfo_option_follows_disable_flag() {
        let ordinary = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        ordinary.bind(&SockAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))).unwrap();
        ordinary.listen(listener_backlog()).unwrap();
        let ordinary_tfo = tcp_fastopen(ordinary.as_raw_fd());
        for disable_tfo in [false, true] {
            let descriptor = Arc::new(AtomicI32::new(-1));
            let captured = Arc::clone(&descriptor);
            let config = StdListenConfig {
                disable_tfo,
                control: Some(Arc::new(move |_, _, fd| {
                    captured.store(fd as i32, Ordering::Relaxed);
                    Box::pin(async { Ok(()) })
                })),
                ..StdListenConfig::default()
            };
            let listener = config.listen(&CancellationToken::new(), "tcp4", "127.0.0.1:0").await.unwrap();
            let fd = descriptor.load(Ordering::Relaxed);
            assert!(fd >= 0);

            let actual = tcp_fastopen(fd);
            if disable_tfo {
                assert_eq!(actual, ordinary_tfo, "disabled TFO must match an ordinary listener");
            } else {
                assert!(actual > 0, "enabled TCP_FASTOPEN={actual}");
            }
            let mut client = timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(listener.addr().unwrap()))
                .await
                .unwrap()
                .unwrap();
            let mut accepted = timeout(Duration::from_secs(5), listener.accept()).await.unwrap().unwrap();
            client.write_all(b"x").await.unwrap();
            let mut payload = [0; 1];
            timeout(Duration::from_secs(5), accepted.read_exact(&mut payload)).await.unwrap().unwrap();
            assert_eq!(&payload, b"x");
            drop(listener);
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod listener_backlog_linux_tests {
    use super::{kernel_version_at_least, listener_backlog_from_somaxconn, max_ack_backlog};

    // only clamps to `u16::MAX` on kernels older than 4.1; every kernel
    // this binary runs its test suite on is newer, so a value between the old flat 65535 clamp
    // and `u32::MAX` must pass through unchanged.
    #[test]
    fn does_not_clamp_to_u16_max_on_a_modern_kernel() {
        assert!(kernel_version_at_least(4, 1), "test host must run a >=4.1 kernel for this assertion to hold");
        assert_eq!(max_ack_backlog(100_000), 100_000);
    }

    // Parsing caps at `0xFFFFFF` and reports failure once the value reaches it; the backlog then
    // falls back to `SOMAXCONN` (128) instead of passing the huge value to `max_ack_backlog`.
    #[test]
    fn falls_back_to_somaxconn_when_value_reaches_dtoi_big() {
        assert_eq!(listener_backlog_from_somaxconn(0xFFFFFF), 128);
        assert_eq!(listener_backlog_from_somaxconn(i64::MAX), 128);
        assert_eq!(listener_backlog_from_somaxconn(0xFFFFFE), max_ack_backlog(0xFFFFFE));
    }

    #[test]
    fn falls_back_to_somaxconn_when_value_is_zero() {
        assert_eq!(listener_backlog_from_somaxconn(0), 128);
    }
}

#[cfg(all(test, target_os = "windows"))]
mod listener_backlog_tests {
    use super::listener_backlog;

    // on Windows the backlog passes `SOMAXCONN` (`0x7fffffff`) straight to
    // `listen()`; a literal small backlog (previously 128, same as the Linux fallback) starves
    // once concurrent connection attempts reach that count, which `do_concurrent_test`'s 128-way
    // burst does under Wine's slower accept-loop scheduling.
    #[test]
    fn matches_windows_somaxconn_sentinel() {
        assert_eq!(listener_backlog(), i32::MAX);
    }
}

#[cfg(all(test, windows))]
mod udp_icmp_reset_tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::*;
    use murmur_testsupport_probe as test_support;

    fn closed_port() -> SocketAddr {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        probe.local_addr().unwrap()
    }

    /// Under Wine, `SIO_UDP_CONNRESET` is a stub that reports success without actually
    /// suppressing the reset (`dlls/ws2_32/socket.c` in wine-11.0), and Wine's `server/sock.c`
    /// never surfaces `ECONNRESET`/`ENETUNREACH` from Linux to an unconnected UDP socket in the
    /// first place, so both tests below pass identically with or without `disable_udp_icmp_resets`
    /// under Wine. They only prove anything on real Windows.
    #[tokio::test]
    async fn listen_packet_keeps_receiving_after_port_unreachable() {
        if test_support::is_wine() {
            return;
        }
        let ctx = CancellationToken::new();
        let pc = StdListenConfig::default().listen_packet(&ctx, "udp4", "127.0.0.1:0").await.unwrap();
        let local = pc.as_socket().unwrap().local_addr().unwrap().as_socket().unwrap();

        pc.send_to(b"x", closed_port()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let peer_addr = peer.local_addr().unwrap();
        peer.send_to(b"hello", local).unwrap();

        let mut buf = [0u8; 16];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), pc.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(from, peer_addr);
    }

    #[tokio::test]
    async fn dialed_udp_read_is_not_reset_by_port_unreachable() {
        if test_support::is_wine() {
            return;
        }
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ctx = CancellationToken::new();
        let mut conn = StdDialer::default().dial_context(&ctx, "udp4", &closed_port().to_string()).await.unwrap();
        conn.write_all(b"x").await.unwrap();

        let mut buf = [0u8; 16];
        let read = tokio::time::timeout(Duration::from_millis(800), conn.read(&mut buf)).await;
        assert!(read.is_err(), "read must stay pending, got {read:?}");
    }

    #[tokio::test]
    async fn bind_quic_client_socket_keeps_receiving_after_port_unreachable() {
        if test_support::is_wine() {
            return;
        }
        let std_socket = bind_quic_client_socket((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        std_socket.set_nonblocking(true).unwrap();
        let socket = UdpSocket::from_std(std_socket).unwrap();
        let local = socket.local_addr().unwrap();

        socket.send_to(b"x", closed_port()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let peer_addr = peer.local_addr().unwrap();
        peer.send_to(b"hello", local).unwrap();

        let mut buf = [0u8; 16];
        let (n, from) =
            tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(from, peer_addr);
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "ios")))]
mod listener_backlog_darwin_tests {
    use super::listener_backlog;

    // on darwin/ios the backlog reads `kern.ipc.somaxconn` via
    // `sysctl`; a literal 128 fallback (the previous behaviour) silently
    // diverges from a host whose sysctl differs from the default.
    #[test]
    fn matches_kern_ipc_somaxconn_sysctl() {
        let output = std::process::Command::new("sysctl")
            .args(["-n", "kern.ipc.somaxconn"])
            .output()
            .expect("sysctl(8) is present on darwin/ios");
        let want: u32 = String::from_utf8_lossy(&output.stdout).trim().parse().expect("integer sysctl value");
        assert_eq!(listener_backlog(), want.min(u32::from(u16::MAX)) as i32);
    }
}

#[cfg(all(test, target_os = "freebsd"))]
mod listener_backlog_freebsd_tests {
    use super::listener_backlog;

    // on freebsd the backlog reads `kern.ipc.soacceptqueue`, not
    // `kern.ipc.somaxconn`; a literal 128 fallback (the previous Rust behaviour) silently
    // diverges from a host whose sysctl differs from the default.
    #[test]
    fn matches_kern_ipc_soacceptqueue_sysctl() {
        let output = std::process::Command::new("sysctl")
            .args(["-n", "kern.ipc.soacceptqueue"])
            .output()
            .expect("sysctl(8) is present on freebsd");
        let want: u32 = String::from_utf8_lossy(&output.stdout).trim().parse().expect("integer sysctl value");
        assert_eq!(listener_backlog(), want.min(u32::from(u16::MAX)) as i32);
    }
}

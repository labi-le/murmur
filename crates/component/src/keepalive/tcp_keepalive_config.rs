use std::io;

use socket2::{SockRef, TcpKeepalive};

use murmur_common::time::{duration_from_nanos, TimeDuration};
use murmur_common_net::io::Stream;
use murmur_log::warnln;
use murmur_std_compat::net::Conn;

use super::tcp_keepalive::{disable_keep_alive, keep_alive_idle, keep_alive_interval};

/// The keep-alive settings; the durations are this project's signed nanosecond `TimeDuration`.
/// A non-positive `idle`/`interval` means "not configured": the OS default stays in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeepAliveConfig {
    pub enable: bool,
    pub idle: TimeDuration,
    pub interval: TimeDuration,
}

/// A conn that carries keep-alive settings.
pub trait TcpConn: Conn {
    fn set_keep_alive(&self, keepalive: bool) -> io::Result<()>;

    fn set_keep_alive_config(&self, config: KeepAliveConfig) -> io::Result<()>;
}

impl TcpConn for tokio::net::TcpStream {
    fn set_keep_alive(&self, keepalive: bool) -> io::Result<()> {
        SockRef::from(self).set_keepalive(keepalive)
    }

    fn set_keep_alive_config(&self, config: KeepAliveConfig) -> io::Result<()> {
        set_socket_keep_alive(&SockRef::from(self), config)
    }
}

/// Applies `config` to a live socket: `TcpConn` is the dial half's way in, and an accepted
/// connection reaches the same socket through `Stream::as_socket`.
pub fn set_socket_keep_alive(socket: &SockRef<'_>, config: KeepAliveConfig) -> io::Result<()> {
    socket.set_keepalive(config.enable)?;
    if !config.enable {
        return Ok(());
    }

    let mut keepalive = TcpKeepalive::new();
    if config.idle > 0 {
        keepalive = keepalive.with_time(duration_from_nanos(config.idle));
    }
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "windows",
        target_os = "cygwin",
    ))]
    if config.interval > 0 {
        keepalive = keepalive.with_interval(duration_from_nanos(config.interval));
    }
    socket.set_tcp_keepalive(&keepalive)
}

/// The accept half of `tcp_keep_alive`: an accepted connection is a `Stream`, which exposes its
/// OS socket through `as_socket`; one without a socket has no keep-alive to set.
pub fn tcp_keep_alive_stream(stream: &dyn Stream, config: KeepAliveConfig) {
    let Some(socket) = stream.as_socket() else {
        return;
    };
    if let Err(err) = set_socket_keep_alive(&socket, config) {
        warnln!("keep-alive settings were not applied to the accepted connection: {err}");
    }
}

#[must_use]
pub fn keep_alive_config() -> KeepAliveConfig {
    KeepAliveConfig { enable: true, idle: keep_alive_idle(), interval: keep_alive_interval() }
}

pub fn tcp_keep_alive<C: TcpConn + ?Sized>(tcp: &C) {
    let result = if disable_keep_alive() {
        tcp.set_keep_alive(false)
    } else {
        tcp.set_keep_alive_config(keep_alive_config())
    };
    if let Err(err) = result {
        warnln!("keep-alive settings were not applied to the connection: {err}");
    }
}

/// The keep-alive fields a dialer and listener config carry; as with `MultipathTcpFlag`,
/// they are reached through a trait instead of concrete types.
pub trait KeepAliveFields {
    fn set_keep_alive(&mut self, keep_alive: TimeDuration);

    fn keep_alive_config_mut(&mut self) -> &mut KeepAliveConfig;

    fn set_keep_alive_config(&mut self, config: KeepAliveConfig) {
        *self.keep_alive_config_mut() = config;
    }
}

pub fn set_net_dialer<D: KeepAliveFields + ?Sized>(dialer: &mut D) {
    if disable_keep_alive() {
        dialer.set_keep_alive(-1); // If negative, keep-alive probes are disabled.
        dialer.keep_alive_config_mut().enable = false;
    } else {
        dialer.set_keep_alive_config(keep_alive_config());
    }
}

pub fn set_net_listen_config<L: KeepAliveFields + ?Sized>(lc: &mut L) {
    if disable_keep_alive() {
        lc.set_keep_alive(-1); // If negative, keep-alive probes are disabled.
        lc.keep_alive_config_mut().enable = false;
    } else {
        lc.set_keep_alive_config(keep_alive_config());
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod keep_alive_socket_tests {
    use std::os::fd::AsRawFd;

    use socket2::{Domain, Protocol, SockRef, Socket, Type};

    use super::{set_socket_keep_alive, KeepAliveConfig};

    const SECOND: i64 = 1_000_000_000;

    /// The configuration a keep-alive-enabled dialer and listener carry by default (unset idle and
    /// interval) must not become a request the kernel refuses: a zero idle used to go to
    /// `TCP_KEEPIDLE`, Linux answered `EINVAL`, and the call's result was discarded.
    #[test]
    fn the_default_configuration_is_accepted() {
        let socket = socket();
        let config = KeepAliveConfig { enable: true, idle: 0, interval: 0 };
        let result = set_socket_keep_alive(&SockRef::from(&socket), config);
        assert!(result.is_ok(), "the default configuration must be accepted: {:?}", result.unwrap_err());
        assert!(socket.keepalive().unwrap());
    }

    #[expect(
        unsafe_code,
        reason = "`getsockopt` is a raw FFI call; the SAFETY comment below states the descriptor and pointer invariants"
    )]
    fn keep_alive_int(fd: libc::c_int, option: libc::c_int) -> libc::c_int {
        let mut actual: libc::c_int = -1;
        let mut length = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: the caller keeps `fd` open and both output pointers are valid.
        let result = unsafe {
            libc::getsockopt(fd, libc::IPPROTO_TCP, option, std::ptr::addr_of_mut!(actual).cast(), &raw mut length)
        };
        assert_eq!(result, 0, "getsockopt({option}): {}", std::io::Error::last_os_error());
        actual
    }

    fn socket() -> Socket {
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap()
    }

    #[test]
    fn a_configured_idle_and_interval_reach_the_socket() {
        let socket = socket();
        let config = KeepAliveConfig { enable: true, idle: 30 * SECOND, interval: 5 * SECOND };
        set_socket_keep_alive(&SockRef::from(&socket), config).unwrap();

        assert!(socket.keepalive().unwrap());
        let fd = socket.as_raw_fd();
        assert_eq!(keep_alive_int(fd, libc::TCP_KEEPIDLE), 30);
        assert_eq!(keep_alive_int(fd, libc::TCP_KEEPINTVL), 5);
    }

    /// A zero idle means "not configured": passing it on makes the kernel reject the whole call
    /// with `EINVAL`, which also drops the interval requested in the same call.
    #[test]
    fn an_unset_idle_leaves_the_os_default_and_still_applies_the_interval() {
        let socket = socket();
        let config = KeepAliveConfig { enable: true, idle: 0, interval: 5 * SECOND };
        set_socket_keep_alive(&SockRef::from(&socket), config).unwrap();

        assert!(socket.keepalive().unwrap());
        assert_eq!(keep_alive_int(socket.as_raw_fd(), libc::TCP_KEEPINTVL), 5);
    }

    #[test]
    fn a_disabled_config_turns_keep_alive_off() {
        let socket = socket();
        socket.set_keepalive(true).unwrap();
        set_socket_keep_alive(&SockRef::from(&socket), KeepAliveConfig { enable: false, idle: 30, interval: 5 })
            .unwrap();

        assert!(!socket.keepalive().unwrap());
    }

    /// Linux rejects a `TCP_KEEPIDLE` above 32767; the refusal must come back as an error for the
    /// caller to report instead of being discarded.
    #[test]
    fn a_refused_idle_surfaces_as_an_error() {
        let socket = socket();
        let config = KeepAliveConfig { enable: true, idle: 40_000 * SECOND, interval: 0 };

        let err = set_socket_keep_alive(&SockRef::from(&socket), config).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL), "{err}");
    }
}

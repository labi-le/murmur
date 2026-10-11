use std::io;

use socket2::{SockRef, TcpKeepalive};

use murmur_common::time::{duration_from_nanos, TimeDuration};
use murmur_std_compat::net::Conn;

use super::tcp_keepalive::{disable_keep_alive, keep_alive_idle, keep_alive_interval};
#[cfg(unix)]
use super::tcp_keepalive_config_unix::support_tcp_keep_alive_count;
#[cfg(target_os = "windows")]
use super::tcp_keepalive_config_windows::support_tcp_keep_alive_count;

/// The keep-alive settings; the durations are this project's signed nanosecond `TimeDuration`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeepAliveConfig {
    pub enable: bool,
    pub idle: TimeDuration,
    pub interval: TimeDuration,
    pub count: i32,
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
        let socket = SockRef::from(self);
        socket.set_keepalive(config.enable)?;
        if !config.enable {
            return Ok(());
        }
        let mut keepalive = TcpKeepalive::new();
        if config.idle >= 0 {
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
        if config.interval >= 0 {
            keepalive = keepalive.with_interval(duration_from_nanos(config.interval));
        }
        socket.set_tcp_keepalive(&keepalive)
    }
}

#[must_use]
pub fn keep_alive_config() -> KeepAliveConfig {
    let mut config =
        KeepAliveConfig { enable: true, idle: keep_alive_idle(), interval: keep_alive_interval(), count: 0 };
    if !support_tcp_keep_alive_count() {
        // it's recommended to set both Idle and Interval to non-negative values in conjunction with a -1
        // for Count on those old Windows if you intend to customize the TCP keep-alive settings.
        config.count = -1;
    }
    config
}

pub fn tcp_keep_alive<C: TcpConn + ?Sized>(tcp: &C) {
    if disable_keep_alive() {
        let _ = tcp.set_keep_alive(false);
    } else {
        let _ = tcp.set_keep_alive_config(keep_alive_config());
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

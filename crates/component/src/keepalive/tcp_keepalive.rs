use murmur_common::atomic::type_::{new_bool, new_int64, Bool, Int64};
use murmur_common::time::TimeDuration;

use super::tcp_keepalive_config::{KeepAliveFields, TcpConn};

pub(crate) static KEEP_ALIVE_IDLE: Int64 = new_int64(0);
pub(crate) static KEEP_ALIVE_INTERVAL: Int64 = new_int64(0);
pub(crate) static DISABLE_KEEP_ALIVE: Bool = new_bool(false);

pub fn set_keep_alive_idle(t: TimeDuration) {
    KEEP_ALIVE_IDLE.store(t);
}

pub fn set_keep_alive_interval(t: TimeDuration) {
    KEEP_ALIVE_INTERVAL.store(t);
}

pub fn keep_alive_idle() -> TimeDuration {
    KEEP_ALIVE_IDLE.load()
}

pub fn keep_alive_interval() -> TimeDuration {
    KEEP_ALIVE_INTERVAL.load()
}

pub fn set_disable_keep_alive(disable: bool) {
    if cfg!(target_os = "android") {
        set_disable_keep_alive_inner(true);
    } else {
        set_disable_keep_alive_inner(disable);
    }
}

/// The private setter; its name collapses onto the public setter's under snake-casing.
pub(crate) fn set_disable_keep_alive_inner(disable: bool) {
    DISABLE_KEEP_ALIVE.store(disable);
}

pub fn disable_keep_alive() -> bool {
    DISABLE_KEEP_ALIVE.load()
}

pub fn set_net_dialer<D: KeepAliveFields + ?Sized>(dialer: &mut D) {
    super::tcp_keepalive_config::set_net_dialer(dialer);
}

pub fn set_net_listen_config<L: KeepAliveFields + ?Sized>(lc: &mut L) {
    super::tcp_keepalive_config::set_net_listen_config(lc);
}

/// A conn is narrowed to the keep-alive-capable conn at run time, and that
/// assertion as a bound, so connections without the setters are not passed here.
pub fn tcp_keep_alive<C: TcpConn + ?Sized>(c: &C) {
    super::tcp_keepalive_config::tcp_keep_alive(c);
}

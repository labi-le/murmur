use std::net::IpAddr;
use std::sync::Once;

use murmur_log::warnln;

use super::control::{StdDialer, StdListenConfig};

static PRINT_MARK_WARN_ONCE: Once = Once::new();

pub(crate) fn print_mark_warn() {
    PRINT_MARK_WARN_ONCE.call_once(|| {
        warnln!("Routing mark on socket is not supported on current platform");
    });
}

pub(crate) fn bind_mark_to_dialer(_mark: i32, _dialer: &mut StdDialer, _network: &str, _destination: Option<IpAddr>) {
    print_mark_warn();
}

pub(crate) fn bind_mark_to_listen_config(_mark: i32, _lc: &mut StdListenConfig, _network: &str, _address: &str) {
    print_mark_warn();
}

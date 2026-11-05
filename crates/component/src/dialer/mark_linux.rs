use std::net::IpAddr;
use std::sync::Arc;

use murmur_common::sockopt;

use super::bind::{is_global_unicast, parse_addr_port};
use super::control::{add_control_to_dialer, add_control_to_listen_config, ControlFn, StdDialer, StdListenConfig};

pub(crate) fn bind_mark_to_dialer(mark: i32, dialer: &mut StdDialer, _network: &str, _destination: Option<IpAddr>) {
    add_control_to_dialer(dialer, bind_mark_to_control(mark));
}

pub(crate) fn bind_mark_to_listen_config(mark: i32, lc: &mut StdListenConfig, _network: &str, _address: &str) {
    add_control_to_listen_config(lc, bind_mark_to_control(mark));
}

fn bind_mark_to_control(mark: i32) -> ControlFn {
    Arc::new(move |_ctx, _network, address, fd| {
        Box::pin(async move {
            if let Some(addr_port) = parse_addr_port(&address) {
                if !is_global_unicast(Some(addr_port.ip())) {
                    return Ok(());
                }
            }

            sockopt::mark_common::raw_conn_mark(fd, mark)
        })
    })
}

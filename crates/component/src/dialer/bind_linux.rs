use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use super::bind::{is_global_unicast, parse_addr_port};
use super::control::{add_control_to_dialer, add_control_to_listen_config, ControlFn, StdDialer, StdListenConfig};

fn bind_control(iface_name: &str) -> ControlFn {
    let iface_name = iface_name.to_owned();
    Arc::new(move |_ctx, _network, address, fd| {
        let iface_name = iface_name.clone();
        Box::pin(async move {
            if let Some(addr_port) = parse_addr_port(&address) {
                if !is_global_unicast(Some(addr_port.ip())) {
                    return Ok(());
                }
            }

            bind_to_device(fd, &iface_name)
        })
    })
}

#[expect(
    unsafe_code,
    reason = "`BorrowedFd::borrow_raw` rebuilds a non-owning descriptor from the raw fd the dialer hook hands over"
)]
fn bind_to_device(fd: usize, device: &str) -> anyhow::Result<()> {
    // SAFETY: `fd` is a live socket and outlives this synchronous call.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd as std::os::fd::RawFd) };
    socket2::SockRef::from(&borrowed).bind_device(Some(device.as_bytes()))?;
    Ok(())
}

pub(crate) async fn bind_iface_to_dialer(
    iface_name: &str,
    dialer: &mut StdDialer,
    _network: &str,
    _destination: Option<IpAddr>,
) -> anyhow::Result<()> {
    add_control_to_dialer(dialer, bind_control(iface_name));

    Ok(())
}

pub(crate) async fn bind_iface_to_listen_config(
    iface_name: &str,
    lc: &mut StdListenConfig,
    _network: &str,
    address: &str,
    _r_addr_port: Option<SocketAddr>,
) -> anyhow::Result<String> {
    add_control_to_listen_config(lc, bind_control(iface_name));

    Ok(address.to_owned())
}

#[must_use]
pub fn parse_network(network: &str, _addr: Option<IpAddr>) -> String {
    network.to_owned()
}

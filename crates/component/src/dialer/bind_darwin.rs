use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::iface::iface;

use super::bind::{is_global_unicast, parse_addr_port};
use super::control::{add_control_to_dialer, add_control_to_listen_config, ControlFn, StdDialer, StdListenConfig};

fn bind_control(iface_idx: i32) -> ControlFn {
    Arc::new(move |_ctx, network, address, fd| {
        Box::pin(async move {
            if let Some(addr_port) = parse_addr_port(&address) {
                if !is_global_unicast(Some(addr_port.ip())) {
                    return Ok(());
                }
            }

            match network.as_str() {
                "tcp6" | "udp6" | "ip6" => set_sockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF, iface_idx),
                _ => set_sockopt_int(fd, libc::IPPROTO_IP, libc::IP_BOUND_IF, iface_idx),
            }
        })
    })
}

#[expect(
    unsafe_code,
    reason = "`setsockopt` is a raw FFI call; the SAFETY comment below states the descriptor and buffer invariants"
)]
fn set_sockopt_int(fd: usize, level: libc::c_int, optname: libc::c_int, value: libc::c_int) -> anyhow::Result<()> {
    // SAFETY: `fd` is a live socket and `value` outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            fd as libc::c_int,
            level,
            optname,
            std::ptr::addr_of!(value).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub(crate) async fn bind_iface_to_dialer(
    iface_name: &str,
    dialer: &mut StdDialer,
    _network: &str,
    _destination: Option<IpAddr>,
) -> anyhow::Result<()> {
    let iface_obj = iface::resolve_interface(iface_name).await?;

    add_control_to_dialer(dialer, bind_control(iface_obj.index));
    Ok(())
}

pub(crate) async fn bind_iface_to_listen_config(
    iface_name: &str,
    lc: &mut StdListenConfig,
    _network: &str,
    address: &str,
    _r_addr_port: Option<SocketAddr>,
) -> anyhow::Result<String> {
    let iface_obj = iface::resolve_interface(iface_name).await?;

    add_control_to_listen_config(lc, bind_control(iface_obj.index));
    Ok(address.to_string())
}

pub fn parse_network(network: &str, _addr: Option<IpAddr>) -> String {
    network.to_string()
}

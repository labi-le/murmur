use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::iface::iface;

use super::bind::{is_global_unicast, parse_addr_port, unicast_if_network_order_bytes, unmap_addr};
use super::control::{add_control_to_dialer, add_control_to_listen_config, ControlFn, StdDialer, StdListenConfig};

pub const IP_UNICAST_IF: i32 = 31;
pub const IPV6_UNICAST_IF: i32 = 31;

const IPPROTO_IP: i32 = 0;
const IPPROTO_IPV6: i32 = 41;

#[expect(
    unsafe_code,
    reason = "`setsockopt` is a raw FFI call; the SAFETY comment below states the descriptor and buffer invariants"
)]
fn setsockopt_int(socket: usize, level: i32, optname: i32, value: i32) -> anyhow::Result<()> {
    // SAFETY: `socket` is a live socket and `value` outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            socket,
            level,
            optname,
            std::ptr::addr_of!(value).cast(),
            libc::c_int::try_from(size_of::<i32>()).unwrap_or(libc::c_int::MAX),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn bind4(socket: usize, iface_idx: i32) -> anyhow::Result<()> {
    // IP_UNICAST_IF takes the index in network byte order (MSDN).
    setsockopt_bytes(socket, IPPROTO_IP, IP_UNICAST_IF, unicast_if_network_order_bytes(iface_idx))
        .map_err(|err| anyhow::anyhow!("bind4: {err}"))
}

fn bind6(socket: usize, iface_idx: i32) -> anyhow::Result<()> {
    // IPV6_UNICAST_IF takes the index in host byte order (MSDN), the opposite of bind4 above.
    setsockopt_int(socket, IPPROTO_IPV6, IPV6_UNICAST_IF, iface_idx).map_err(|err| anyhow::anyhow!("bind6: {err}"))
}

#[expect(
    unsafe_code,
    reason = "`setsockopt` is a raw FFI call; the SAFETY comment below states the descriptor and buffer invariants"
)]
fn setsockopt_bytes(socket: usize, level: i32, optname: i32, value: [u8; 4]) -> anyhow::Result<()> {
    // SAFETY: `socket` is a live socket and `value` outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            socket,
            level,
            optname,
            std::ptr::addr_of!(value).cast(),
            libc::c_int::try_from(value.len()).unwrap_or(libc::c_int::MAX),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn bind_control(iface_idx: i32, r_addr_port: Option<SocketAddr>) -> ControlFn {
    Arc::new(move |_ctx, network, address, fd| {
        Box::pin(async move {
            let addr_port = parse_addr_port(&address);
            if let Some(addr_port) = addr_port {
                if !is_global_unicast(Some(addr_port.ip())) {
                    return Ok(());
                }
            }

            let bind6err = bind6(fd, iface_idx).err();
            let bind4err = bind4(fd, iface_idx).err();

            let inner = match network.as_str() {
                "ip6" | "tcp6" => bind6err,
                "ip4" | "tcp4" | "udp4" => bind4err,
                // The network is udp6 when listening on a wildcard IP (eg: ":0", "")
                "udp6" => match bind6err {
                    Some(bind6err)
                        if addr_port.is_none_or(|addr_port| addr_port.ip().is_unspecified())
                            && r_addr_port.is_some_and(|r_addr_port| {
                                unmap_addr(Some(r_addr_port.ip())).is_some_and(|ip| ip.is_ipv4())
                            }) =>
                    {
                        // try bind ipv6, if failed, ignore. it's a workaround for windows disable interface ipv6
                        bind4err.map(|bind4err| anyhow::anyhow!("{bind6err} ({bind4err})"))
                    }
                    other => other,
                },
                _ => None,
            };

            match inner {
                Some(err) => Err(err),
                None => Ok(()),
            }
        })
    })
}

pub(crate) async fn bind_iface_to_dialer(
    iface_name: &str,
    dialer: &mut StdDialer,
    _network: &str,
    destination: Option<IpAddr>,
) -> anyhow::Result<()> {
    let iface_obj = iface::resolve_interface(iface_name).await?;

    add_control_to_dialer(dialer, bind_control(iface_obj.index, destination.map(|ip| SocketAddr::new(ip, 0))));
    Ok(())
}

pub(crate) async fn bind_iface_to_listen_config(
    iface_name: &str,
    lc: &mut StdListenConfig,
    _network: &str,
    address: &str,
    r_addr_port: Option<SocketAddr>,
) -> anyhow::Result<String> {
    let iface_obj = iface::resolve_interface(iface_name).await?;

    add_control_to_listen_config(lc, bind_control(iface_obj.index, r_addr_port));
    Ok(address.to_owned())
}

#[must_use]
pub fn parse_network(network: &str, _addr: Option<IpAddr>) -> String {
    network.to_owned()
}

#[cfg(test)]
mod bind_option_tests {
    use super::unicast_if_network_order_bytes;

    #[test]
    fn the_options_are_given_the_index_in_the_byte_order_msdn_documents() {
        // IP_UNICAST_IF is network order; bind6 passes IPV6_UNICAST_IF in host order, so on the
        // little-endian Windows targets the two buffers differ for the same index.
        assert_eq!(unicast_if_network_order_bytes(1), [0, 0, 0, 1]);
        assert_eq!(unicast_if_network_order_bytes(0x0102_0304), [1, 2, 3, 4]);
        assert_eq!(1i32.to_ne_bytes(), [1, 0, 0, 0]);
    }
}

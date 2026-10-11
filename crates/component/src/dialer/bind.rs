//! The address predicates this crate needs (unmap, 4-in-6 test, global-unicast test, slice
//! and address-port parsing) have no crate mirror, so they sit here with the binding helpers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::iface::iface::{self, ErrAddrNotFound};

use super::control::{StdDialer, StdListenConfig};

/// Unmaps a 4-in-6 address; `None` is the invalid zero address, which stays invalid.
#[must_use]
pub const fn unmap_addr(ip: Option<IpAddr>) -> Option<IpAddr> {
    match ip {
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => Some(IpAddr::V4(v4)),
            None => Some(IpAddr::V6(v6)),
        },
        other => other,
    }
}

pub(crate) const fn is4in6(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
}

const fn is_link_local_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 169 && v4.octets()[1] == 254,
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// Whether the address is globally unicast; `None` is the invalid zero address.
#[must_use]
pub fn is_global_unicast(ip: Option<IpAddr>) -> bool {
    let Some(ip) = unmap_addr(ip) else {
        return false;
    };

    if let IpAddr::V4(v4) = ip {
        if v4.is_unspecified() || v4 == Ipv4Addr::BROADCAST {
            return false;
        }
    }

    let unspecified = match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    };
    !unspecified && !ip.is_loopback() && !ip.is_multicast() && !is_link_local_unicast(ip)
}

/// Parses an address and port; a zone (`fe80::1%eth0`) is not representable in `SocketAddr`.
#[must_use]
pub fn parse_addr_port(address: &str) -> Option<SocketAddr> {
    address.parse().ok()
}

/// Joins a host and port into `host:port`, bracketing an IPv6 literal host.
pub fn join_host_port(host: &str, port: impl std::fmt::Display) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Parses a port split off an address (`common::net_addr::split_host_port`'s second element) as a
/// plain unsigned decimal.
///
/// `+80` or `-1` are not valid ports on the wire, so they are rejected rather than accepted by
/// `u16::from_str` and silently mapped to 0.
#[must_use]
pub fn parse_address_port(port: &str) -> u16 {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    port.parse().unwrap_or(0)
}

pub async fn lookup_local_addr_from_iface_name(
    iface_name: &str,
    network: &str,
    destination: Option<IpAddr>,
    port: u16,
) -> anyhow::Result<SocketAddr> {
    let iface_obj = iface::resolve_interface(iface_name).await?;
    let destination = unmap_addr(destination);

    let addr = match network {
        "udp4" | "tcp4" => iface_obj.pick_ipv4_addr(destination)?,
        "tcp6" | "udp6" => iface_obj.pick_ipv6_addr(destination)?,
        _ => match destination {
            Some(destination) => {
                if destination.is_ipv4() {
                    iface_obj.pick_ipv4_addr(Some(destination))?
                } else {
                    iface_obj.pick_ipv6_addr(Some(destination))?
                }
            }
            None => iface_obj.pick_ipv4_addr(None)?,
        },
    };

    if network.starts_with("tcp") || network.starts_with("udp") {
        return Ok(SocketAddr::new(addr.addr(), port));
    }

    Err(ErrAddrNotFound.into())
}

pub(crate) async fn fallback_bind_iface_to_dialer(
    iface_name: &str,
    dialer: &mut StdDialer,
    network: &str,
    destination: Option<IpAddr>,
) -> anyhow::Result<()> {
    if !is_global_unicast(destination) {
        return Ok(());
    }

    let local = dialer.local_addr.map_or(0, |local_addr| local_addr.port());

    let addr = lookup_local_addr_from_iface_name(iface_name, network, destination, local).await?;
    dialer.local_addr = Some(addr);

    Ok(())
}

pub(crate) async fn fallback_bind_iface_to_listen_config(
    iface_name: &str,
    _lc: &mut StdListenConfig,
    network: &str,
    address: &str,
    _r_addr_port: Option<SocketAddr>,
) -> anyhow::Result<String> {
    let port = match murmur_common::net_addr::split_host_port(address) {
        Ok((_, port)) => port,
        Err(_) => "0".to_owned(),
    };

    let local: u16 = parse_address_port(&port);

    let addr = lookup_local_addr_from_iface_name(iface_name, network, None, local).await?;

    Ok(addr.to_string())
}

#[allow(
    dead_code,
    reason = "only called from bind_others.rs, which is cfg-gated to targets other than linux/macos/windows; unreachable on this build target"
)]
pub(crate) fn fallback_parse_network(network: &str, addr: Option<IpAddr>) -> String {
    // fix fallbackBindIfaceToListenConfig() force bind to an ipv4 address
    if !network.ends_with('4') && !network.ends_with('6') && unmap_addr(addr).is_some_and(|ip| ip.is_ipv6()) {
        return format!("{network}6");
    }
    network.to_owned()
}

#[cfg(test)]
mod host_port_tests {
    use super::join_host_port;

    #[test]
    fn join_host_port_brackets_ipv6_literals() {
        assert_eq!(join_host_port("192.0.2.1", 80), "192.0.2.1:80");
        assert_eq!(join_host_port("::1", 80), "[::1]:80");
        assert_eq!(join_host_port("example.com", "http"), "example.com:http");
    }

    #[test]
    fn split_host_port_round_trips_join_host_port() {
        for (host, port) in [("192.0.2.1", "80"), ("::1", "80"), ("example.com", "http")] {
            assert_eq!(
                murmur_common::net_addr::split_host_port(&join_host_port(host, port)).unwrap(),
                (host.to_owned(), port.to_owned())
            );
        }
    }
}

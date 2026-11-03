use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};

use super::anet::is_force_anet;
use super::netlink_android::{
    netlink_rib, parse_netlink_message, parse_netlink_route_attr, NetlinkMessage, NetlinkRouteAttr, IFA_ADDRESS,
    IFA_LOCAL, NLMSG_DONE, RTM_GETADDR, RTM_NEWADDR, SIZEOF_IFADDRMSG,
};
use super::{
    cidr_mask, index_to_name, name_to_flags, name_to_mtu, net_interface_addrs, net_interface_addrs_of,
    net_interface_by_index, net_interface_by_name, net_interfaces, HardwareAddr, IPMask, IPNet, Interface, OpError,
};
use murmur_std_compat::net::Addr;

/// Sentinel errors for the interface lookups.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(crate) enum InterfaceError {
    #[error("invalid network interface")]
    InvalidInterface,
    #[error("invalid network interface index")]
    InvalidInterfaceIndex,
    #[error("invalid network interface name")]
    InvalidInterfaceName,
    #[error("no such network interface")]
    NoSuchInterface,
    #[error("no such multicast network interface")]
    NoSuchMulticastInterface,
}

const AF_UNSPEC: i32 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// The interface-address message fields this file reads.
#[derive(Clone, Copy, Debug)]
struct IfAddrmsg {
    family: u8,
    prefixlen: u8,
    index: u32,
}

impl IfAddrmsg {
    fn parse(b: &[u8]) -> Option<IfAddrmsg> {
        if b.len() < SIZEOF_IFADDRMSG {
            return None;
        }
        Some(IfAddrmsg { family: b[0], prefixlen: b[1], index: u32::from_ne_bytes([b[4], b[5], b[6], b[7]]) })
    }
}

fn op_error(err: anyhow::Error) -> anyhow::Error {
    anyhow!(OpError { op: "route".to_owned(), net: "ip+net".to_owned(), err })
}

/// Returns a list of the system's network interfaces.
pub fn interfaces() -> Result<Vec<Interface>> {
    if !is_force_anet() {
        if let Ok(ift) = net_interfaces() {
            return Ok(ift);
        }
    }
    interface_table(0).map_err(op_error)
}

/// Returns a list of the system's unicast interface addresses.
///
/// The returned list does not identify the associated interface; use `interfaces` and
/// `interface_addrs_by_interface` for more detail.
pub fn interface_addrs() -> Result<Vec<Box<dyn Addr>>> {
    if !is_force_anet() {
        if let Ok(ifat) = net_interface_addrs() {
            return Ok(ifat);
        }
    }
    interface_addr_table(None).map_err(op_error)
}

/// Returns the interface specified by index.
pub fn interface_by_index(index: i32) -> Result<Interface> {
    if !is_force_anet() {
        if let Ok(ifi) = net_interface_by_index(index) {
            return Ok(ifi);
        }
    }
    if index <= 0 {
        return Err(op_error(anyhow!(InterfaceError::InvalidInterfaceIndex)));
    }
    let ift = interface_table(index).map_err(op_error)?;
    find_interface_by_index(ift, index).map_err(op_error)
}

/// Returns the interface specified by name.
pub fn interface_by_name(name: &str) -> Result<Interface> {
    if !is_force_anet() {
        if let Ok(ifi) = net_interface_by_name(name) {
            return Ok(ifi);
        }
    }
    if name.is_empty() {
        return Err(op_error(anyhow!(InterfaceError::InvalidInterfaceName)));
    }
    let ift = interface_table(0).map_err(op_error)?;
    for ifi in ift {
        if name == ifi.name {
            return Ok(ifi);
        }
    }
    Err(op_error(anyhow!(InterfaceError::NoSuchInterface)))
}

/// Returns a list of the system's unicast interface addresses by
/// specific interface.
pub fn interface_addrs_by_interface(ifi: &Interface) -> Result<Vec<Box<dyn Addr>>> {
    if let Ok(ifat) = net_interface_addrs_of(ifi) {
        return Ok(ifat);
    }
    interface_addr_table(Some(ifi)).map_err(op_error)
}

/// If the ifindex is zero, `interface_table` returns mappings of all network interfaces. Otherwise
/// it returns a mapping of a specific interface.
fn interface_table(ifindex: i32) -> Result<Vec<Interface>> {
    let tab = netlink_rib(RTM_GETADDR, AF_UNSPEC).map_err(|err| anyhow!("netlinkrib: {err}"))?;
    let msgs = parse_netlink_message(&tab).map_err(|err| anyhow!("parsenetlinkmessage: {err}"))?;

    let mut ift: Vec<Interface> = Vec::new();
    let mut im: HashSet<u32> = HashSet::new();
    for m in &msgs {
        if m.header.type_ == NLMSG_DONE {
            break;
        }
        if m.header.type_ != RTM_NEWADDR {
            continue;
        }
        let Some(ifam) = IfAddrmsg::parse(m.data) else {
            continue;
        };
        if !im.insert(ifam.index) {
            continue;
        }

        if ifindex == 0 || ifindex == ifam.index as i32 {
            if let Some(ifi) = new_link(&ifam) {
                ift.push(ifi);
            }
            if ifindex == ifam.index as i32 {
                break;
            }
        }
    }

    Ok(ift)
}

fn new_link(ifam: &IfAddrmsg) -> Option<Interface> {
    let name = index_to_name(ifam.index).ok()?;
    let mtu = name_to_mtu(&name).ok()?;
    let flags = name_to_flags(&name).ok()?;
    Some(Interface { index: ifam.index as i32, mtu, name, hardware_addr: HardwareAddr::default(), flags })
}

/// If `ifi` is `None`, `interface_addr_table` returns addresses for all network interfaces.
/// Otherwise it returns addresses for a specific interface.
fn interface_addr_table(ifi: Option<&Interface>) -> Result<Vec<Box<dyn Addr>>> {
    let tab = netlink_rib(RTM_GETADDR, AF_UNSPEC).map_err(|err| anyhow!("netlinkrib: {err}"))?;
    let msgs = parse_netlink_message(&tab).map_err(|err| anyhow!("parsenetlinkmessage: {err}"))?;

    let mut ift: Vec<Interface> = Vec::new();
    if ifi.is_none() {
        ift = interface_table(0)?;
    }
    addr_table(&ift, ifi, &msgs)
}

fn addr_table(ift: &[Interface], ifi: Option<&Interface>, msgs: &[NetlinkMessage<'_>]) -> Result<Vec<Box<dyn Addr>>> {
    let mut ifat: Vec<Box<dyn Addr>> = Vec::new();
    for m in msgs {
        if m.header.type_ == NLMSG_DONE {
            break;
        }
        if m.header.type_ != RTM_NEWADDR {
            continue;
        }
        let Some(ifam) = IfAddrmsg::parse(m.data) else {
            continue;
        };
        let index = ifi.map_or(0, |i| i.index);
        if ift.is_empty() && index != ifam.index as i32 {
            continue;
        }
        let attrs = parse_netlink_route_attr(m).map_err(|err| anyhow!("parsenetlinkrouteattr: {err}"))?;
        if let Some(ifa) = new_addr(&ifam, &attrs) {
            ifat.push(ifa);
        }
    }
    Ok(ifat)
}

fn new_addr(ifam: &IfAddrmsg, attrs: &[NetlinkRouteAttr<'_>]) -> Option<Box<dyn Addr>> {
    let mut ip_point_to_point = false;
    // Seems like we need to make sure whether the IP interface stack consists of IP
    // point-to-point numbered or unnumbered addressing.
    for a in attrs {
        if a.attr.type_ == IFA_LOCAL {
            ip_point_to_point = true;
            break;
        }
    }
    for a in attrs {
        if ip_point_to_point && a.attr.type_ == IFA_ADDRESS {
            continue;
        }
        if ifam.family == AF_INET {
            let octets = a.value.get(0..4)?;
            let mask = cidr_mask(ifam.prefixlen as usize, 8 * 4).unwrap_or_else(|| IPMask(Vec::new()));
            return Some(Box::new(IPNet {
                ip: IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
                mask,
            }));
        }
        if ifam.family == AF_INET6 {
            let mut ip = [0u8; 16];
            let n = a.value.len().min(16);
            ip[..n].copy_from_slice(&a.value[..n]);
            let mask = cidr_mask(ifam.prefixlen as usize, 8 * 16).unwrap_or_else(|| IPMask(Vec::new()));
            return Some(Box::new(IPNet { ip: IpAddr::V6(Ipv6Addr::from(ip)), mask }));
        }
    }
    None
}

fn find_interface_by_index(ift: Vec<Interface>, index: i32) -> Result<Interface> {
    for ifi in ift {
        if index == ifi.index {
            return Ok(ifi);
        }
    }
    Err(anyhow!(InterfaceError::NoSuchInterface))
}

//! Addresses and prefixes have no crate mirror yet: this module uses `std::net::IpAddr` and
//! `ipnet::IpNet`, with `None` standing for the invalid zero value.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use ipnet::IpNet;

use crate::iface::anet;
#[cfg(not(target_os = "android"))]
use crate::iface::anet::interface::{interface_addrs_by_interface, interfaces as anet_interfaces};
#[cfg(target_os = "android")]
use crate::iface::anet::interface_android::{interface_addrs_by_interface, interfaces as anet_interfaces};
use murmur_common::singledo::singledo::{new_single, Single};
use murmur_std_compat::net::Addr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub index: i32,
    pub mtu: i32,
    pub name: String,
    pub hardware_addr: anet::HardwareAddr,
    pub flags: anet::Flags,
    pub addresses: Vec<IpNet>,
}

#[derive(Debug, thiserror::Error)]
#[error("interface not found")]
pub struct ErrIfaceNotFound;

#[derive(Debug, thiserror::Error)]
#[error("addr not found")]
pub struct ErrAddrNotFound;

/// A longest-prefix-match table, the one the cache looks
/// addresses up in.
#[derive(Default)]
pub(crate) struct IfaceTable {
    entries: Vec<(IpNet, Arc<Interface>)>,
}

impl IfaceTable {
    pub(crate) fn insert(&mut self, prefix: IpNet, iface: Arc<Interface>) {
        match self.entries.iter_mut().find(|(existing, _)| *existing == prefix) {
            Some(entry) => entry.1 = iface,
            None => self.entries.push((prefix, iface)),
        }
    }

    pub(crate) fn lookup(&self, addr: IpAddr) -> Option<Arc<Interface>> {
        let mut best: Option<(u8, &Arc<Interface>)> = None;
        for (prefix, iface) in &self.entries {
            if !prefix.contains(&addr) {
                continue;
            }
            if best.is_none_or(|(len, _)| prefix.prefix_len() > len) {
                best = Some((prefix.prefix_len(), iface));
            }
        }
        best.map(|(_, iface)| Arc::clone(iface))
    }
}

#[expect(
    clippy::struct_field_names,
    reason = "all three fields are interface-keyed lookups; `if` is this module's abbreviation for interface"
)]
pub(crate) struct IfaceCache {
    pub(crate) if_map_by_name: HashMap<String, Arc<Interface>>,
    pub(crate) if_map_by_addr: HashMap<IpAddr, Arc<Interface>>,
    pub(crate) if_table: IfaceTable,
}

pub(crate) static CACHES: LazyLock<Single<Arc<IfaceCache>>> = LazyLock::new(|| new_single(Duration::from_secs(20)));

const fn is_link_local_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 169 && v4.octets()[1] == 254,
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// The prefix of one interface address, if it has one.
fn prefix_of(addr: &dyn Addr) -> Option<IpNet> {
    addr.as_iface_prefix()
}

pub(crate) async fn get_cache() -> anyhow::Result<Arc<IfaceCache>> {
    let (value, _) = CACHES.do_(|| async { tokio::task::spawn_blocking(build_iface_cache).await? }).await;
    value
}

fn build_iface_cache() -> anyhow::Result<Arc<IfaceCache>> {
    let ifaces = anet_interfaces()?;

    let mut cache =
        IfaceCache { if_map_by_name: HashMap::new(), if_map_by_addr: HashMap::new(), if_table: IfaceTable::default() };

    for iface in &ifaces {
        let Ok(addrs) = interface_addrs_by_interface(iface) else {
            continue;
        };

        let mut ip_nets = Vec::with_capacity(addrs.len());
        for addr in &addrs {
            if let Some(pf) = prefix_of(addr.as_ref()) {
                ip_nets.push(pf);
            }
        }

        let iface_obj = Arc::new(Interface {
            index: iface.index,
            mtu: iface.mtu,
            name: iface.name.clone(),
            hardware_addr: iface.hardware_addr.clone(),
            flags: iface.flags,
            addresses: ip_nets,
        });
        cache.if_map_by_name.insert(iface_obj.name.clone(), Arc::clone(&iface_obj));

        if !iface_obj.flags.contains(anet::Flags::FLAG_UP) {
            continue; // interface down
        }
        for prefix in &iface_obj.addresses {
            cache.if_map_by_addr.insert(prefix.addr(), Arc::clone(&iface_obj));
            cache.if_table.insert(*prefix, Arc::clone(&iface_obj));
        }
    }

    Ok(Arc::new(cache))
}

pub async fn interfaces() -> anyhow::Result<HashMap<String, Arc<Interface>>> {
    let cache = get_cache().await?;
    Ok(cache.if_map_by_name.clone())
}

pub async fn resolve_interface(name: &str) -> anyhow::Result<Arc<Interface>> {
    let ifaces = interfaces().await?;

    match ifaces.get(name) {
        Some(iface) => Ok(Arc::clone(iface)),
        None => Err(ErrIfaceNotFound.into()),
    }
}

pub async fn resolve_interface_by_addr(addr: IpAddr) -> anyhow::Result<Arc<Interface>> {
    let cache = get_cache().await?;
    // maybe two interfaces have the same prefix but different address
    // so direct check address equal before do a route lookup (longest prefix match)
    if let Some(iface) = cache.if_map_by_addr.get(&addr) {
        return Ok(Arc::clone(iface));
    }
    match cache.if_table.lookup(addr) {
        Some(iface) => Ok(iface),
        None => Err(ErrIfaceNotFound.into()),
    }
}

pub async fn is_local_ip(addr: IpAddr) -> anyhow::Result<bool> {
    let cache = get_cache().await?;
    Ok(cache.if_map_by_addr.contains_key(&addr))
}

pub fn flush_cache() {
    CACHES.reset();
}

impl Interface {
    pub fn pick_ipv4_addr(&self, destination: Option<IpAddr>) -> anyhow::Result<IpNet> {
        self.pick_ip_addr(destination, |addr| addr.addr().is_ipv4())
    }

    pub fn pick_ipv6_addr(&self, destination: Option<IpAddr>) -> anyhow::Result<IpNet> {
        self.pick_ip_addr(destination, |addr| addr.addr().is_ipv6())
    }

    fn pick_ip_addr(&self, destination: Option<IpAddr>, accept: impl Fn(&IpNet) -> bool) -> anyhow::Result<IpNet> {
        let mut fallback: Option<IpNet> = None;

        for addr in &self.addresses {
            if !accept(addr) {
                continue;
            }

            if fallback.is_none() && !is_link_local_unicast(addr.addr()) {
                fallback = Some(*addr);

                if destination.is_none() {
                    break;
                }
            }

            if let Some(destination) = destination {
                if addr.contains(&destination) {
                    return Ok(*addr);
                }
            }
        }

        fallback.ok_or_else(|| ErrAddrNotFound.into())
    }
}

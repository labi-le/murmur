use std::net::IpAddr;
use std::sync::LazyLock;

use ipnet::IpNet;
use parking_lot::RwLock;

use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::Addr;

use super::util::prefixes_contains;

static LAN_ALLOWED_IPS: LazyLock<RwLock<Option<Vec<IpNet>>>> = LazyLock::new(|| RwLock::new(None));
static LAN_DIS_ALLOWED_IPS: LazyLock<RwLock<Option<Vec<IpNet>>>> = LazyLock::new(|| RwLock::new(None));

/// The `lan-allowed-ips` list. `None` means the key is absent from the config; `Some(vec![])` is
/// an explicitly empty `lan-allowed-ips: []`.
///
/// Both allow nothing, but render differently through `/configs` (`null` vs `[]`), matching the
/// distinction between an absent and an empty list.
pub fn set_allowed_ips(prefixes: Option<Vec<IpNet>>) {
    *LAN_ALLOWED_IPS.write() = prefixes;
}

/// The `lan-disallowed-ips` list. `None` means the key is absent from the config; `Some(vec![])`
/// is an explicitly empty `lan-disallowed-ips: []`.
///
/// Both disallow nothing, but render differently through `/configs` (`null` vs `[]`), matching the
/// distinction between an absent and an empty list.
pub fn set_dis_allowed_ips(prefixes: Option<Vec<IpNet>>) {
    *LAN_DIS_ALLOWED_IPS.write() = prefixes;
}

pub fn allowed_ips() -> Option<Vec<IpNet>> {
    LAN_ALLOWED_IPS.read().clone()
}

pub fn dis_allowed_ips() -> Option<Vec<IpNet>> {
    LAN_DIS_ALLOWED_IPS.read().clone()
}

#[must_use]
pub fn is_remote_addr_dis_allowed(addr: Option<&dyn Addr>) -> bool {
    let mut metadata = Metadata::default();
    if metadata.set_remote_addr(addr).is_err() {
        return false;
    }
    match metadata.addr_port() {
        Some(addr_port) => is_allowed(Some(addr_port.ip())) && !is_dis_allowed(Some(addr_port.ip())),
        None => false,
    }
}

fn is_allowed(addr: Option<IpAddr>) -> bool {
    prefixes_contains(LAN_ALLOWED_IPS.read().as_deref().unwrap_or(&[]), addr)
}

fn is_dis_allowed(addr: Option<IpAddr>) -> bool {
    prefixes_contains(LAN_DIS_ALLOWED_IPS.read().as_deref().unwrap_or(&[]), addr)
}

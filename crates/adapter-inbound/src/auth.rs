use std::net::IpAddr;
use std::sync::LazyLock;

use parking_lot::RwLock;

use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::Addr;

use super::util::prefixes_contains;

static SKIP_AUTH_PREFIXES: LazyLock<RwLock<Option<Vec<ipnet::IpNet>>>> = LazyLock::new(|| RwLock::new(None));

/// The `skip-auth-prefixes` list. `None` means the key is absent from the config; `Some(vec![])`
/// is an explicitly empty `skip-auth-prefixes: []`.
///
/// Both mean "skip nothing", but they render differently through `/configs` (`null` vs `[]`),
/// matching the distinction between an absent and an empty list.
pub fn set_skip_auth_prefixes(prefixes: Option<Vec<ipnet::IpNet>>) {
    *SKIP_AUTH_PREFIXES.write() = prefixes;
}

pub fn skip_auth_prefixes() -> Option<Vec<ipnet::IpNet>> {
    SKIP_AUTH_PREFIXES.read().clone()
}

#[must_use]
pub fn skip_auth_remote_addr(addr: Option<&dyn Addr>) -> bool {
    let mut metadata = Metadata::default();
    if metadata.set_remote_addr(addr).is_err() {
        return false;
    }
    skip_auth(metadata.addr_port().map(|addr_port| addr_port.ip()))
}

#[must_use]
pub fn skip_auth_remote_address(addr: &str) -> bool {
    let mut metadata = Metadata::default();
    if metadata.set_remote_address(addr).is_err() {
        return false;
    }
    skip_auth(metadata.addr_port().map(|addr_port| addr_port.ip()))
}

fn skip_auth(addr: Option<IpAddr>) -> bool {
    prefixes_contains(SKIP_AUTH_PREFIXES.read().as_deref().unwrap_or(&[]), addr)
}

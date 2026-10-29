use anyhow::Result;

use super::{net_interface_addrs, net_interface_addrs_of, net_interfaces, Interface};
use murmur_std_compat::net::Addr;

/// Returns a list of the system's network interfaces.
pub fn interfaces() -> Result<Vec<Interface>> {
    net_interfaces()
}

/// Returns a list of the system's unicast interface addresses.
///
/// The returned list does not identify the associated interface; use `interfaces` and
/// `interface_addrs_by_interface` for more detail.
pub fn interface_addrs() -> Result<Vec<Box<dyn Addr>>> {
    net_interface_addrs()
}

/// Returns a list of the system's unicast interface addresses by
/// specific interface.
pub fn interface_addrs_by_interface(ifi: &Interface) -> Result<Vec<Box<dyn Addr>>> {
    net_interface_addrs_of(ifi)
}

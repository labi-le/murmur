//! The two deterministic managed IPv6 forms ZeroTier derives from a network ID
//! and a member address, plus their reverse mappings.

use std::net::{IpAddr, Ipv6Addr};

use ipnet::IpNet;

use crate::address::{Address, ADDRESS_SIZE};

/// The address width, in bits, of an RFC4193-style managed prefix.
pub const RFC4193_PREFIX_LEN: u8 = 88;
/// The address width, in bits, of a 6plane managed prefix.
pub const SIX_PLANE_PREFIX_LEN: u8 = 40;

/// ZeroTier's RFC4193-style managed IPv6 prefix for one member.
#[must_use]
#[expect(clippy::expect_used, reason = "RFC4193_PREFIX_LEN is 88, always within the 128-bit IPv6 width")]
pub fn rfc4193_address(network_id: u64, address: Address) -> IpNet {
    let mut raw = [0u8; 16];
    raw[0] = 0xfd;
    raw[1..9].copy_from_slice(&network_id.to_be_bytes());
    raw[9] = 0x99;
    raw[10] = 0x93;
    raw[11..16].copy_from_slice(&address.bytes());
    IpNet::new(IpAddr::V6(Ipv6Addr::from(raw)), RFC4193_PREFIX_LEN).expect("88-bit IPv6 prefix")
}

/// Extracts the member address encoded by an RFC4193-style managed address.
#[must_use]
pub fn address_from_rfc4193(network_id: u64, ip: IpAddr) -> Option<Address> {
    let IpAddr::V6(value) = ip else {
        return None;
    };
    let raw = value.octets();
    if raw[0] != 0xfd || u64::from_be_bytes(raw[1..9].try_into().ok()?) != network_id {
        return None;
    }
    if raw[9] != 0x99 || raw[10] != 0x93 {
        return None;
    }
    let address = Address::from_bytes(&raw[11..11 + ADDRESS_SIZE]).ok()?;
    (!address.is_reserved()).then_some(address)
}

/// Folds a network ID into the 32-bit value the 6plane layout stores.
fn six_plane_fold(network_id: u64) -> u32 {
    let bytes = network_id.to_be_bytes();
    let high = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let low = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    high ^ low
}

/// ZeroTier's 6plane managed IPv6 prefix for one member.
#[must_use]
#[expect(clippy::expect_used, reason = "SIX_PLANE_PREFIX_LEN is 40, always within the 128-bit IPv6 width")]
pub fn six_plane_address(network_id: u64, address: Address) -> IpNet {
    let mut raw = [0u8; 16];
    raw[0] = 0xfc;
    let fold = six_plane_fold(network_id);
    raw[1..5].copy_from_slice(&fold.to_be_bytes());
    raw[5..10].copy_from_slice(&address.bytes());
    raw[15] = 1;
    IpNet::new(IpAddr::V6(Ipv6Addr::from(raw)), SIX_PLANE_PREFIX_LEN).expect("40-bit IPv6 prefix")
}

/// Extracts the member address encoded by a 6plane managed address.
#[must_use]
pub fn address_from_six_plane(network_id: u64, ip: IpAddr) -> Option<Address> {
    let IpAddr::V6(value) = ip else {
        return None;
    };
    let raw = value.octets();
    let fold = six_plane_fold(network_id);
    if raw[0] != 0xfc || u32::from_be_bytes(raw[1..5].try_into().ok()?) != fold {
        return None;
    }
    let address = Address::from_bytes(&raw[5..5 + ADDRESS_SIZE]).ok()?;
    (!address.is_reserved()).then_some(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK_ID: u64 = 0x17d7_0943_6c04_d6bc;
    const ADDRESS: u64 = 0x000f_1b56_d269;

    #[test]
    fn derives_the_official_managed_prefixes() {
        let address = Address::new(ADDRESS);
        assert_eq!(rfc4193_address(NETWORK_ID, address).to_string(), "fd17:d709:436c:4d6:bc99:930f:1b56:d269/88");
        assert_eq!(six_plane_address(NETWORK_ID, address).to_string(), "fc7b:d3df:ff0f:1b56:d269::1/40");
    }

    #[test]
    fn round_trips_each_managed_form() {
        let address = Address::new(ADDRESS);
        let rfc4193 = rfc4193_address(NETWORK_ID, address);
        let six_plane = six_plane_address(NETWORK_ID, address);
        assert_eq!(address_from_rfc4193(NETWORK_ID, rfc4193.addr()), Some(address));
        assert_eq!(address_from_six_plane(NETWORK_ID, six_plane.addr()), Some(address));
        assert_eq!(address_from_rfc4193(NETWORK_ID + 1, rfc4193.addr()), None);
        assert_eq!(address_from_six_plane(NETWORK_ID + 1, six_plane.addr()), None);
    }

    #[test]
    fn rejects_ipv4_and_foreign_prefixes() {
        assert_eq!(address_from_rfc4193(NETWORK_ID, IpAddr::from([192, 0, 2, 1])), None);
        assert_eq!(address_from_six_plane(NETWORK_ID, IpAddr::from([192, 0, 2, 1])), None);
        assert_eq!(address_from_rfc4193(NETWORK_ID, six_plane_address(NETWORK_ID, Address::new(ADDRESS)).addr()), None);
        assert_eq!(address_from_six_plane(NETWORK_ID, rfc4193_address(NETWORK_ID, Address::new(ADDRESS)).addr()), None);
    }
}

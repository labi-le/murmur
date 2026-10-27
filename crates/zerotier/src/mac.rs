//! ZeroTier's deterministic per-network virtual Ethernet addresses.

use crate::address::Address;

pub const ETHERNET_MAC_SIZE: usize = 6;
const MAC_MASK: u64 = 0xffff_ffff_ffff;

/// A 48-bit Ethernet address stored in host byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Mac(u64);

impl Mac {
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value & MAC_MASK)
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, MacError> {
        if raw.len() < ETHERNET_MAC_SIZE {
            return Err(MacError);
        }
        let value = raw.iter().take(ETHERNET_MAC_SIZE).fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
        Ok(Self::new(value))
    }

    #[must_use]
    pub fn uint64(self) -> u64 {
        self.0 & MAC_MASK
    }

    #[must_use]
    pub fn bytes(self) -> [u8; ETHERNET_MAC_SIZE] {
        let octets = self.uint64().to_be_bytes();
        [octets[2], octets[3], octets[4], octets[5], octets[6], octets[7]]
    }

    #[must_use]
    pub fn is_broadcast(self) -> bool {
        self.uint64() == MAC_MASK
    }

    #[must_use]
    pub fn is_multicast(self) -> bool {
        self.uint64() & 0x0100_0000_0000 != 0
    }
}

impl core::fmt::Display for Mac {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let octets = self.uint64().to_be_bytes();
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            octets[2], octets[3], octets[4], octets[5], octets[6], octets[7],
        )
    }
}

/// Reports a truncated Ethernet address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid Ethernet MAC")]
pub struct MacError;

/// The deterministic virtual MAC ZeroTier assigns to a node on a network. The
/// mapping is invertible so a received frame's MAC identifies the peer.
#[must_use]
pub fn mac_for_address(address: Address, network_id: u64) -> Mac {
    let mut value = u64::from(first_mac_octet(network_id)) << 40;
    value |= address.uint64();
    value ^= ((network_id >> 8) & 0xff) << 32;
    value ^= ((network_id >> 16) & 0xff) << 24;
    value ^= ((network_id >> 24) & 0xff) << 16;
    value ^= ((network_id >> 32) & 0xff) << 8;
    value ^= (network_id >> 40) & 0xff;
    Mac::new(value)
}

/// Reverses [`mac_for_address`].
#[must_use]
pub fn address_for_mac(mac: Mac, network_id: u64) -> Address {
    let mut value = mac.uint64() & crate::address::ADDRESS_MASK_U64;
    value ^= ((network_id >> 8) & 0xff) << 32;
    value ^= ((network_id >> 16) & 0xff) << 24;
    value ^= ((network_id >> 24) & 0xff) << 16;
    value ^= ((network_id >> 32) & 0xff) << 8;
    value ^= (network_id >> 40) & 0xff;
    Address::new(value)
}

/// Locally administered first octet, with `0x52` reserved for ZeroTier's own
/// root infrastructure.
#[must_use]
pub fn first_mac_octet(network_id: u64) -> u8 {
    let octet = (network_id & 0xfe) as u8 | 0x02;
    if octet == 0x52 {
        0x32
    } else {
        octet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_mapping_inverts() {
        let network_id = 0x8056_c2e2_1c00_0001;
        let address = Address::new(0x8e4d_f28b72);
        let mac = mac_for_address(address, network_id);
        assert_eq!(address_for_mac(mac, network_id), address);
        assert!(!mac.is_multicast());
        assert_ne!(mac.uint64() & 0x0200_0000_0000, 0, "mac {mac} lost its locally administered bit");
    }

    #[test]
    fn formatting_and_bytes_round_trip() {
        let mac = mac_for_address(Address::new(0x8e4d_f28b72), 0x8056_c2e2_1c00_0001);
        assert_eq!(Mac::from_bytes(&mac.bytes()).unwrap(), mac);
        assert_eq!(mac.to_string().len(), 17);
        assert!(Mac::new(0xffff_ffff_ffff).is_broadcast());
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(Mac::from_bytes(&[0; 5]).is_err());
    }
}

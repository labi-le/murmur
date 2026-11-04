//! 40-bit ZeroTier node addresses and the 64-bit network IDs that scope them.

/// Encoded size of a ZeroTier node address.
pub const ADDRESS_SIZE: usize = 5;
/// Retains the low 40 bits used by a node address.
pub const ADDRESS_MASK_U64: u64 = 0xff_ffff_ffff;
const ADDRESS_MASK: u64 = ADDRESS_MASK_U64;
/// The `0xff`-prefixed namespace cannot identify an ordinary node.
const RESERVED_PREFIX: u8 = 0xff;
pub const NETWORK_ID_HEX_SIZE: usize = 16;
pub const ADDRESS_HEX_SIZE: usize = 10;

/// Reports a malformed or reserved node address or network identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("invalid ZeroTier address")]
    InvalidAddress,
    #[error("invalid ZeroTier network ID")]
    InvalidNetworkID,
}

/// A 40-bit ZeroTier node address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Address(u64);

impl Address {
    pub const SIZE: usize = ADDRESS_SIZE;

    /// Truncates `value` to the low 40 bits of a node address.
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value & ADDRESS_MASK)
    }

    /// Parses a ten-character hexadecimal node address, rejecting the reserved
    /// namespace.
    pub fn parse(text: &str) -> Result<Self, AddressError> {
        if text.len() != ADDRESS_HEX_SIZE || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AddressError::InvalidAddress);
        }
        let raw = hex::decode(text).map_err(|_| AddressError::InvalidAddress)?;
        let address = Self::from_bytes(&raw)?;
        if address.is_reserved() {
            return Err(AddressError::InvalidAddress);
        }
        Ok(address)
    }

    /// Decodes a five-byte big-endian node address without the reserved check,
    /// which packet parsers need because on-the-wire fields carry reserved
    /// values such as broadcast.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, AddressError> {
        if raw.len() != ADDRESS_SIZE {
            return Err(AddressError::InvalidAddress);
        }
        let mut value = 0u64;
        for byte in raw {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn uint64(self) -> u64 {
        self.0 & ADDRESS_MASK
    }

    #[must_use]
    pub fn is_zero(self) -> bool {
        self.uint64() == 0
    }

    /// Whether this address falls in the namespace ZeroTier reserves for
    /// broadcast and controller placeholders.
    #[must_use]
    pub fn is_reserved(self) -> bool {
        self.is_zero() || self.uint64().to_be_bytes()[3] == RESERVED_PREFIX
    }

    pub fn append_to(self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.uint64().to_be_bytes()[3..]);
    }

    #[must_use]
    pub fn bytes(self) -> [u8; ADDRESS_SIZE] {
        let octets = self.uint64().to_be_bytes();
        [octets[3], octets[4], octets[5], octets[6], octets[7]]
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:010x}", self.uint64())
    }
}

/// Parses a 64-bit network ID and validates its encoded controller address.
pub fn parse_network_id(text: &str) -> Result<u64, AddressError> {
    if text.len() != NETWORK_ID_HEX_SIZE || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AddressError::InvalidNetworkID);
    }
    let raw = hex::decode(text).map_err(|_| AddressError::InvalidNetworkID)?;
    let network_id = u64::from_be_bytes(raw.try_into().map_err(|_| AddressError::InvalidNetworkID)?);
    if network_id == 0 || (!is_ad_hoc_network_id(network_id) && controller(network_id).is_reserved()) {
        return Err(AddressError::InvalidNetworkID);
    }
    Ok(network_id)
}

/// Whether `network_id` is in ZeroTier's controllerless `0xff`-prefixed
/// namespace, which peers configure out of band instead of via a controller.
#[must_use]
pub fn is_ad_hoc_network_id(network_id: u64) -> bool {
    network_id >> 56 == 0xff
}

/// The controller address a network ID encodes, which is the node address that
/// signs that network's configuration and tags.
#[must_use]
pub fn controller(network_id: u64) -> Address {
    Address::new(network_id >> 24)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_round_trip() {
        let address = Address::parse("0123456789").unwrap();
        assert_eq!(address.uint64(), 0x0001_2345_6789);
        assert_eq!(address.to_string(), "0123456789");
        assert_eq!(Address::from_bytes(&address.bytes()).unwrap(), address);
    }

    #[test]
    fn rejects_malformed_and_reserved_addresses() {
        assert_eq!(Address::parse("123456789"), Err(AddressError::InvalidAddress));
        assert_eq!(Address::parse("01234567890"), Err(AddressError::InvalidAddress));
        assert_eq!(Address::parse("zzzzzzzzzz"), Err(AddressError::InvalidAddress));
        assert_eq!(Address::parse("0000000000"), Err(AddressError::InvalidAddress));
        assert_eq!(Address::parse("ff00000000"), Err(AddressError::InvalidAddress));
        assert!(Address::from_bytes(&[0; 4]).is_err());
    }

    #[test]
    fn truncates_to_forty_bits() {
        let address = Address::new(0xdead_beef_1234_5678);
        assert_eq!(address.uint64(), 0x00ef_1234_5678);
        assert_eq!(address.to_string(), "ef12345678");
    }

    #[test]
    fn parses_network_ids() {
        assert_eq!(parse_network_id("8056c2e21c000001").unwrap(), 0x8056_c2e2_1c00_0001);
        assert!(is_ad_hoc_network_id(parse_network_id("ff1234567890abcd").unwrap()));
        assert!(!is_ad_hoc_network_id(0x8056_c2e2_1c00_0001));

        assert_eq!(parse_network_id("0000000000000000"), Err(AddressError::InvalidNetworkID));
        assert_eq!(parse_network_id("8056c2e21c00000"), Err(AddressError::InvalidNetworkID));
    }

    #[test]
    fn derives_controller_address() {
        assert_eq!(controller(0x8056_c2e2_1c00_0001).to_string(), "8056c2e21c");
    }
}

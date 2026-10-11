//! Certificates of ownership: a controller's signed set of MAC or IP address
//! claims. They are what lets a private network decide whether a frame came
//! from a device the network actually owns.

use std::net::IpAddr;

use crate::address::{controller, Address, ADDRESS_SIZE};
use crate::identity::{Identity, SIGNATURE_SIZE};
use crate::mac::Mac;

/// The maximum number of address claims in one ownership certificate.
pub const MAX_OWNERSHIP_THINGS: usize = 16;
/// The maximum number of ownership certificates in one network configuration.
pub const MAX_OWNERSHIP_CERTS: usize = 4;

/// Each claim stores a 16-byte value, so short claims are zero-extended.
const OWNERSHIP_VALUE_SIZE: usize = 16;

/// Reports a malformed ownership certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ZeroTier ownership certificate")]
pub struct InvalidOwnership;

/// The address family of an ownership claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipThingType {
    Mac,
    Ipv4,
    Ipv6,
}

impl OwnershipThingType {
    fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            1 => Some(Self::Mac),
            2 => Some(Self::Ipv4),
            3 => Some(Self::Ipv6),
            _ => None,
        }
    }

    #[must_use]
    pub fn bits(self) -> u8 {
        match self {
            Self::Mac => 1,
            Self::Ipv4 => 2,
            Self::Ipv6 => 3,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Mac => "mac",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

/// One MAC or IP claim in an ownership certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnershipThing {
    pub thing_type: OwnershipThingType,
    pub value: [u8; OWNERSHIP_VALUE_SIZE],
}

/// A controller-signed set of MAC or IP claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateOfOwnership {
    pub network_id: u64,
    pub timestamp: u64,
    pub flags: u64,
    pub id: u32,
    pub things: Vec<OwnershipThing>,
    pub issued_to: Address,
    pub signed_by: Address,
    pub signature: [u8; SIGNATURE_SIZE],
    /// The exact bytes this certificate was decoded from.
    raw: Vec<u8>,
}

impl CertificateOfOwnership {
    /// Decodes one ownership certificate, reporting bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), InvalidOwnership> {
        const FIXED_SIZE: usize = 8 + 8 + 8 + 4 + 2;
        if data.len() < FIXED_SIZE {
            return Err(InvalidOwnership);
        }
        let network_id = read_u64(data, 0);
        let timestamp = read_u64(data, 8);
        let flags = read_u64(data, 16);
        let id = u32::from_be_bytes(read_array::<4>(data, 24)?);
        let count = usize::from(u16::from_be_bytes(read_array::<2>(data, 28)?));
        if count > MAX_OWNERSHIP_THINGS {
            return Err(InvalidOwnership);
        }

        let mut pos = FIXED_SIZE;
        if data.len().saturating_sub(pos) < count * 17 + ADDRESS_SIZE * 2 + 3 {
            return Err(InvalidOwnership);
        }
        let mut things = Vec::with_capacity(count);
        for _ in 0..count {
            let bits = *data.get(pos).ok_or(InvalidOwnership)?;
            let thing_type = OwnershipThingType::from_bits(bits).ok_or(InvalidOwnership)?;
            let mut value = [0u8; OWNERSHIP_VALUE_SIZE];
            value.copy_from_slice(&read_array::<OWNERSHIP_VALUE_SIZE>(data, pos + 1)?);
            things.push(OwnershipThing { thing_type, value });
            pos += 17;
        }

        let issued_to = Address::from_bytes(&read_array::<ADDRESS_SIZE>(data, pos)?).map_err(|_| InvalidOwnership)?;
        pos += ADDRESS_SIZE;
        let signed_by = Address::from_bytes(&read_array::<ADDRESS_SIZE>(data, pos)?).map_err(|_| InvalidOwnership)?;
        pos += ADDRESS_SIZE;

        if data.len().saturating_sub(pos) < 3 {
            return Err(InvalidOwnership);
        }
        let [tag, length_high, length_low] = read_array::<3>(data, pos)?;
        if tag != 1 || usize::from(u16::from_be_bytes([length_high, length_low])) != SIGNATURE_SIZE {
            return Err(InvalidOwnership);
        }
        pos += 3;

        if data.len().saturating_sub(pos) < SIGNATURE_SIZE + 2 {
            return Err(InvalidOwnership);
        }
        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&read_array::<SIGNATURE_SIZE>(data, pos)?);
        pos += SIGNATURE_SIZE;

        let extension_length = usize::from(u16::from_be_bytes(read_array::<2>(data, pos)?));
        pos += 2;
        if data.len().saturating_sub(pos) < extension_length {
            return Err(InvalidOwnership);
        }
        pos += extension_length;

        Ok((
            Self {
                network_id,
                timestamp,
                flags,
                id,
                things,
                issued_to,
                signed_by,
                signature,
                raw: data.get(..pos).ok_or(InvalidOwnership)?.to_vec(),
            },
            pos,
        ))
    }

    /// The certificate's own wire encoding, as decoded.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Authenticates this certificate with its network controller identity.
    #[must_use]
    pub fn verify(&self, controller_identity: &Identity) -> bool {
        self.network_id != 0
            && !self.issued_to.is_zero()
            && self.signed_by == controller(self.network_id)
            && controller_identity.address() == self.signed_by
            && controller_identity.verify(&self.signed_data(), &self.signature)
    }

    /// Whether this certificate claims `mac`.
    #[must_use]
    pub fn owns_mac(&self, mac: Mac) -> bool {
        self.owns(OwnershipThingType::Mac, &mac.bytes())
    }

    /// Whether this certificate claims `address`. An IPv4-mapped IPv6 address
    /// is unmapped first, matching the `netip.Addr.Unmap`.
    #[must_use]
    pub fn owns_ip(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(ip) => self.owns(OwnershipThingType::Ipv4, &ip.octets()),
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(v4) => self.owns(OwnershipThingType::Ipv4, &v4.octets()),
                None => self.owns(OwnershipThingType::Ipv6, &ip.octets()),
            },
        }
    }

    /// Compares one typed claim with `value`, prefix-matching shorter values
    /// against the claim's zero-extended field.
    fn owns(&self, thing_type: OwnershipThingType, value: &[u8]) -> bool {
        self.things.iter().filter(|thing| thing.thing_type == thing_type).any(|thing| thing.value.starts_with(value))
    }

    /// The fields authenticated by the controller signature.
    #[expect(clippy::cast_possible_truncation, reason = "the claim count is a 16-bit wire field by definition")]
    fn signed_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 30 + self.things.len() * 17 + ADDRESS_SIZE * 2 + 2 + 8);
        data.extend_from_slice(&0x7f7f_7f7f_7f7f_7f7fu64.to_be_bytes());
        data.extend_from_slice(&self.network_id.to_be_bytes());
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.extend_from_slice(&self.flags.to_be_bytes());
        data.extend_from_slice(&self.id.to_be_bytes());
        data.extend_from_slice(&(self.things.len() as u16).to_be_bytes());
        for thing in &self.things {
            data.push(thing.thing_type.bits());
            data.extend_from_slice(&thing.value);
        }
        data.extend_from_slice(&self.issued_to.bytes());
        data.extend_from_slice(&self.signed_by.bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0x7f7f_7f7f_7f7f_7f7fu64.to_be_bytes());
        data
    }

    /// The complete wire encoding, re-serialized from the decoded fields.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the claim count is a 16-bit wire field and the signature length field holds SIGNATURE_SIZE (96)"
    )]
    pub fn append_binary(&self, mut data: Vec<u8>) -> Vec<u8> {
        if !self.raw.is_empty() {
            data.extend_from_slice(&self.raw);
            return data;
        }
        data.extend_from_slice(&self.network_id.to_be_bytes());
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.extend_from_slice(&self.flags.to_be_bytes());
        data.extend_from_slice(&self.id.to_be_bytes());
        data.extend_from_slice(&(self.things.len() as u16).to_be_bytes());
        for thing in &self.things {
            data.push(thing.thing_type.bits());
            data.extend_from_slice(&thing.value);
        }
        data.extend_from_slice(&self.issued_to.bytes());
        data.extend_from_slice(&self.signed_by.bytes());
        data.push(1);
        data.extend_from_slice(&(SIGNATURE_SIZE as u16).to_be_bytes());
        data.extend_from_slice(&self.signature);
        data.extend_from_slice(&0u16.to_be_bytes());
        data
    }
}

fn read_array<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], InvalidOwnership> {
    data.get(offset..offset + N).ok_or(InvalidOwnership)?.try_into().map_err(|_| InvalidOwnership)
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    read_array::<8>(data, offset).map_or(0, u64::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a controller-signed ownership certificate the way a real
    /// controller issues one: signed by the node that IS the network's
    /// controller address.
    fn issue(controller_identity: &Identity, issued_to: Address) -> CertificateOfOwnership {
        let network_id = controller_identity.address().uint64() << 24;
        let mac = Mac::new(0x0011_2233_4455);
        let mut mac_claim = [0u8; OWNERSHIP_VALUE_SIZE];
        mac_claim[..6].copy_from_slice(&mac.bytes());
        let things = vec![OwnershipThing { thing_type: OwnershipThingType::Mac, value: mac_claim }, {
            let mut ipv4_claim = [0u8; OWNERSHIP_VALUE_SIZE];
            ipv4_claim[..4].copy_from_slice(&[192, 0, 2, 10]);
            OwnershipThing { thing_type: OwnershipThingType::Ipv4, value: ipv4_claim }
        }];

        let mut certificate = CertificateOfOwnership {
            network_id,
            timestamp: 1_700_000_000,
            flags: 0,
            id: 7,
            things,
            issued_to,
            signed_by: controller_identity.address(),
            signature: [0u8; SIGNATURE_SIZE],
            raw: Vec::new(),
        };
        certificate.signature = controller_identity.sign(&certificate.signed_data()).expect("signs");

        let mut raw = Vec::new();
        raw.extend_from_slice(&network_id.to_be_bytes());
        raw.extend_from_slice(&certificate.timestamp.to_be_bytes());
        raw.extend_from_slice(&certificate.flags.to_be_bytes());
        raw.extend_from_slice(&certificate.id.to_be_bytes());
        raw.extend_from_slice(&(certificate.things.len() as u16).to_be_bytes());
        for thing in &certificate.things {
            raw.push(thing.thing_type.bits());
            raw.extend_from_slice(&thing.value);
        }
        raw.extend_from_slice(&issued_to.bytes());
        raw.extend_from_slice(&controller_identity.address().bytes());
        raw.push(1);
        raw.extend_from_slice(&(SIGNATURE_SIZE as u16).to_be_bytes());
        raw.extend_from_slice(&certificate.signature);
        raw.extend_from_slice(&0u16.to_be_bytes());

        let (parsed, _) = CertificateOfOwnership::parse(&raw).expect("parses issued certificate");
        parsed
    }

    #[test]
    fn a_controller_signed_ownership_certificate_verifies() {
        let controller_identity = Identity::generate();
        let owner = Identity::generate();
        let certificate = issue(&controller_identity, owner.address());

        assert!(certificate.verify(&controller_identity));
        assert_eq!(certificate.network_id, controller_identity.address().uint64() << 24);
        assert_eq!(certificate.issued_to, owner.address());
        assert_eq!(certificate.id, 7);
    }

    #[test]
    fn claims_are_matched_by_family() {
        let controller_identity = Identity::generate();
        let certificate = issue(&controller_identity, Identity::generate().address());

        assert!(certificate.owns_mac(Mac::new(0x0011_2233_4455)));
        assert!(!certificate.owns_mac(Mac::new(0x0011_2233_4456)));

        assert!(certificate.owns_ip("192.0.2.10".parse().unwrap()));
        assert!(!certificate.owns_ip("192.0.2.11".parse().unwrap()));
        assert!(!certificate.owns_ip("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn an_ipv4_mapped_ipv6_address_matches_the_ipv4_claim() {
        let controller_identity = Identity::generate();
        let certificate = issue(&controller_identity, Identity::generate().address());

        let mapped: IpAddr = "::ffff:192.0.2.10".parse().unwrap();
        assert!(certificate.owns_ip(mapped));
    }

    #[test]
    fn a_tampered_claim_breaks_the_signature() {
        let controller_identity = Identity::generate();
        let certificate = issue(&controller_identity, Identity::generate().address());
        let mut raw = certificate.bytes().to_vec();

        // The first claim's MAC begins right after the 30-byte fixed header.
        let claim = 30 + 1;
        raw[claim + 5] ^= 1;
        let (forged, _) = CertificateOfOwnership::parse(&raw).expect("structure still parses");
        assert!(!forged.verify(&controller_identity));
    }

    #[test]
    fn re_serialization_is_byte_stable() {
        let controller_identity = Identity::generate();
        let certificate = issue(&controller_identity, Identity::generate().address());
        assert_eq!(certificate.append_binary(Vec::new()), certificate.bytes());
    }

    #[test]
    fn rejects_malformed_structures() {
        assert_eq!(CertificateOfOwnership::parse(&[0u8; 8]), Err(InvalidOwnership));

        let mut too_many = vec![0u8; 30];
        too_many[28..30].copy_from_slice(&((MAX_OWNERSHIP_THINGS + 1) as u16).to_be_bytes());
        assert_eq!(CertificateOfOwnership::parse(&too_many), Err(InvalidOwnership));

        // Claim type 0 is not a valid ownership thing type.
        let mut bad_type = vec![0u8; 30 + 17 + 10 + 3 + 96 + 2];
        bad_type[30] = 0;
        assert_eq!(CertificateOfOwnership::parse(&bad_type), Err(InvalidOwnership));
    }

    #[test]
    fn an_empty_certificate_carries_no_claims() {
        let controller_identity = Identity::generate();
        let network_id = controller_identity.address().uint64() << 24;
        let mut raw = Vec::new();
        raw.extend_from_slice(&network_id.to_be_bytes());
        raw.extend_from_slice(&0u64.to_be_bytes());
        raw.extend_from_slice(&0u64.to_be_bytes());
        raw.extend_from_slice(&0u32.to_be_bytes());
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&Identity::generate().address().bytes());
        raw.extend_from_slice(&controller_identity.address().bytes());
        raw.push(1);
        raw.extend_from_slice(&(SIGNATURE_SIZE as u16).to_be_bytes());
        raw.extend_from_slice(&[0u8; SIGNATURE_SIZE]);
        raw.extend_from_slice(&0u16.to_be_bytes());

        let (certificate, consumed) = CertificateOfOwnership::parse(&raw).expect("parses");
        assert!(certificate.things.is_empty());
        assert_eq!(consumed, raw.len());
    }
}

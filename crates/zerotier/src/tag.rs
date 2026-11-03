//! Network tags: controller-signed integer attributes scoped to a network, used
//! by rules to grant a member capabilities.

use crate::address::{controller, Address, ADDRESS_SIZE};
use crate::identity::{Identity, SIGNATURE_SIZE};

/// The protocol limit for tags in one network configuration.
pub const MAX_NETWORK_TAGS: usize = 128;

/// Reports a malformed or unverifiable network tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ZeroTier network tag")]
pub struct InvalidTag;

/// A controller-signed network-scoped integer attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub network_id: u64,
    pub timestamp: u64,
    pub id: u32,
    pub value: u32,
    pub issued_to: Address,
    pub signed_by: Address,
    pub signature: [u8; SIGNATURE_SIZE],
    /// The exact bytes this tag was decoded from.
    raw: Vec<u8>,
}

impl Tag {
    /// Decodes one signed network tag, reporting bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), InvalidTag> {
        const FIXED_SIZE: usize = 8 + 8 + 4 + 4 + ADDRESS_SIZE * 2;
        if data.len() < FIXED_SIZE + 3 + SIGNATURE_SIZE + 2 {
            return Err(InvalidTag);
        }
        let network_id = read_u64(data, 0)?;
        let timestamp = read_u64(data, 8)?;
        let id = read_u32(data, 16)?;
        let value = read_u32(data, 20)?;

        let mut pos = 24;
        let issued_to = read_address(data, pos)?;
        pos += ADDRESS_SIZE;
        let signed_by = read_address(data, pos)?;
        pos += ADDRESS_SIZE;

        let signature_type = data.get(pos).copied().ok_or(InvalidTag)?;
        let signature_length = read_u16(data, pos + 1)?;
        if signature_type != 1 || usize::from(signature_length) != SIGNATURE_SIZE {
            return Err(InvalidTag);
        }
        pos += 3;
        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(data.get(pos..pos + SIGNATURE_SIZE).ok_or(InvalidTag)?);
        pos += SIGNATURE_SIZE;

        let extension_length = usize::from(read_u16(data, pos)?);
        pos += 2;
        if data.len().saturating_sub(pos) < extension_length {
            return Err(InvalidTag);
        }
        pos += extension_length;

        let raw = data.get(..pos).ok_or(InvalidTag)?.to_vec();
        Ok((Self { network_id, timestamp, id, value, issued_to, signed_by, signature, raw }, pos))
    }

    /// The tag's own wire encoding, as decoded.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Authenticates this tag with its network controller identity.
    #[must_use]
    pub fn verify(&self, controller_identity: &Identity) -> bool {
        self.network_id != 0
            && !self.issued_to.is_zero()
            && self.signed_by == controller(self.network_id)
            && controller_identity.address() == self.signed_by
            && controller_identity.verify(&self.signed_data(), &self.signature)
    }

    /// The fields authenticated by the controller signature.
    fn signed_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 24 + ADDRESS_SIZE * 2 + 2 + 8);
        data.extend_from_slice(&0x7f7f_7f7f_7f7f_7f7fu64.to_be_bytes());
        data.extend_from_slice(&self.network_id.to_be_bytes());
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.extend_from_slice(&self.id.to_be_bytes());
        data.extend_from_slice(&self.value.to_be_bytes());
        data.extend_from_slice(&self.issued_to.bytes());
        data.extend_from_slice(&self.signed_by.bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0x7f7f_7f7f_7f7f_7f7fu64.to_be_bytes());
        data
    }
}

/// Reads the `N` bytes at `offset`, or reports a truncated tag.
fn read_array<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], InvalidTag> {
    data.get(offset..offset + N).ok_or(InvalidTag)?.try_into().map_err(|_| InvalidTag)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, InvalidTag> {
    Ok(u16::from_be_bytes(read_array(data, offset)?))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, InvalidTag> {
    Ok(u32::from_be_bytes(read_array(data, offset)?))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, InvalidTag> {
    Ok(u64::from_be_bytes(read_array(data, offset)?))
}

fn read_address(data: &[u8], offset: usize) -> Result<Address, InvalidTag> {
    Address::from_bytes(&read_array::<ADDRESS_SIZE>(data, offset)?).map_err(|_| InvalidTag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(controller_identity: &Identity, issued_to: Address) -> Tag {
        let network_id = controller_identity.address().uint64() << 24;
        let mut tag = Tag {
            network_id,
            timestamp: 1_700_000_000,
            id: 3,
            value: 42,
            issued_to,
            signed_by: controller_identity.address(),
            signature: [0u8; SIGNATURE_SIZE],
            raw: Vec::new(),
        };
        tag.signature = controller_identity.sign(&tag.signed_data()).expect("signs");

        let mut raw = Vec::new();
        raw.extend_from_slice(&network_id.to_be_bytes());
        raw.extend_from_slice(&tag.timestamp.to_be_bytes());
        raw.extend_from_slice(&tag.id.to_be_bytes());
        raw.extend_from_slice(&tag.value.to_be_bytes());
        raw.extend_from_slice(&issued_to.bytes());
        raw.extend_from_slice(&controller_identity.address().bytes());
        raw.push(1);
        raw.extend_from_slice(&(SIGNATURE_SIZE as u16).to_be_bytes());
        raw.extend_from_slice(&tag.signature);
        raw.extend_from_slice(&0u16.to_be_bytes());

        let (parsed, _) = Tag::parse(&raw).expect("parses issued tag");
        parsed
    }

    #[test]
    fn a_controller_signed_tag_verifies() {
        let controller_identity = Identity::generate();
        let member = Identity::generate();
        let tag = issue(&controller_identity, member.address());

        assert!(tag.verify(&controller_identity));
        assert_eq!(tag.id, 3);
        assert_eq!(tag.value, 42);
        assert_eq!(tag.issued_to, member.address());
        assert_eq!(tag.bytes().len(), 24 + ADDRESS_SIZE * 2 + 3 + SIGNATURE_SIZE + 2);
    }

    #[test]
    fn a_tag_fails_under_the_wrong_controller() {
        let controller_identity = Identity::generate();
        let tag = issue(&controller_identity, Identity::generate().address());
        assert!(!tag.verify(&Identity::generate()));
    }

    #[test]
    fn a_tampered_value_breaks_the_signature() {
        let controller_identity = Identity::generate();
        let tag = issue(&controller_identity, Identity::generate().address());
        let mut raw = tag.bytes().to_vec();

        // The value field's low byte sits at offset 23.
        raw[23] ^= 1;
        let (forged, _) = Tag::parse(&raw).expect("structure still parses");
        assert!(!forged.verify(&controller_identity));
    }

    #[test]
    fn rejects_malformed_structures() {
        assert_eq!(Tag::parse(&[]), Err(InvalidTag));
        assert_eq!(Tag::parse(&[0u8; 24 + ADDRESS_SIZE * 2 + 2]), Err(InvalidTag));

        let controller_identity = Identity::generate();
        let mut raw = issue(&controller_identity, Identity::generate().address()).bytes().to_vec();
        let signature_type_at = 24 + ADDRESS_SIZE * 2;
        raw[signature_type_at] = 2;
        assert_eq!(Tag::parse(&raw), Err(InvalidTag));
    }
}

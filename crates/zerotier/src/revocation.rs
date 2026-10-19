//! Revocations: a controller's signed order invalidating a credential, or a
//! whole credential class, for one member.
//!
//! Revocations are themselves revocable, so a node that sees an older one keeps
//! the newer threshold.

use crate::address::{controller, Address, ADDRESS_SIZE};
use crate::identity::{Identity, SIGNATURE_SIZE};

/// Bounds revocations decoded from one credential packet.
pub const MAX_REVOCATIONS_PER_PACKET: usize = 64;

/// The signed fields a revocation occupies before its signature.
const REVOCATION_BASE_SIZE: usize = 4 + 4 + 8 + 4 + 4 + 8 + 8 + ADDRESS_SIZE * 2 + 1;

/// Reports a malformed or unverifiable revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ZeroTier revocation")]
pub struct InvalidRevocation;

/// Identifies which signed network credential a revocation applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialType {
    CertificateOfMembership,
    Capability,
    Tag,
    Ownership,
}

impl CredentialType {
    fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            1 => Some(Self::CertificateOfMembership),
            2 => Some(Self::Capability),
            3 => Some(Self::Tag),
            4 => Some(Self::Ownership),
            _ => None,
        }
    }

    fn bits(self) -> u8 {
        match self {
            Self::CertificateOfMembership => 1,
            Self::Capability => 2,
            Self::Tag => 3,
            Self::Ownership => 4,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::CertificateOfMembership => "com",
            Self::Capability => "capability",
            Self::Tag => "tag",
            Self::Ownership => "ownership",
        }
    }
}

/// Invalidates a signed network credential or credential class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub id: u32,
    pub network_id: u64,
    pub credential_id: u32,
    pub threshold: u64,
    pub flags: u64,
    pub target: Address,
    pub signed_by: Address,
    pub credential_type: CredentialType,
    pub signature: [u8; SIGNATURE_SIZE],
    /// The exact bytes this revocation was decoded from.
    raw: Vec<u8>,
}

impl Revocation {
    /// Decodes one signed credential revocation, reporting bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), InvalidRevocation> {
        if data.len() < REVOCATION_BASE_SIZE + 3 + SIGNATURE_SIZE + 2 {
            return Err(InvalidRevocation);
        }
        // The first four bytes are a reserved zero field.
        let id = read_u32(data, 4).ok_or(InvalidRevocation)?;
        let network_id = read_u64(data, 8).ok_or(InvalidRevocation)?;
        // Bytes 16..20 are a second reserved zero field.
        let credential_id = read_u32(data, 20).ok_or(InvalidRevocation)?;
        let threshold = read_u64(data, 24).ok_or(InvalidRevocation)?;
        let flags = read_u64(data, 32).ok_or(InvalidRevocation)?;

        let mut pos = 40;
        let target_bytes = data.get(pos..pos + ADDRESS_SIZE).ok_or(InvalidRevocation)?;
        let target = Address::from_bytes(target_bytes).map_err(|_| InvalidRevocation)?;
        pos += ADDRESS_SIZE;
        let signer_bytes = data.get(pos..pos + ADDRESS_SIZE).ok_or(InvalidRevocation)?;
        let signed_by = Address::from_bytes(signer_bytes).map_err(|_| InvalidRevocation)?;
        pos += ADDRESS_SIZE;

        let credential_bits = data.get(pos).copied().ok_or(InvalidRevocation)?;
        let credential_type = CredentialType::from_bits(credential_bits).ok_or(InvalidRevocation)?;
        pos += 1;
        let signature_marker = data.get(pos).copied().ok_or(InvalidRevocation)?;
        let signature_length = read_u16(data, pos + 1).ok_or(InvalidRevocation)?;
        if signature_marker != 1 || usize::from(signature_length) != SIGNATURE_SIZE {
            return Err(InvalidRevocation);
        }
        pos += 3;

        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(data.get(pos..pos + SIGNATURE_SIZE).ok_or(InvalidRevocation)?);
        pos += SIGNATURE_SIZE;

        let extension_length = usize::from(read_u16(data, pos).ok_or(InvalidRevocation)?);
        pos += 2;
        if data.len().saturating_sub(pos) < extension_length {
            return Err(InvalidRevocation);
        }
        pos += extension_length;

        Ok((
            Self {
                id,
                network_id,
                credential_id,
                threshold,
                flags,
                target,
                signed_by,
                credential_type,
                signature,
                raw: data.get(..pos).ok_or(InvalidRevocation)?.to_vec(),
            },
            pos,
        ))
    }

    /// The revocation's own wire encoding, as decoded.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Authenticates this revocation with its network controller identity.
    #[must_use]
    pub fn verify(&self, controller_identity: &Identity) -> bool {
        self.network_id != 0
            && !self.target.is_zero()
            && self.signed_by == controller(self.network_id)
            && controller_identity.address() == self.signed_by
            && controller_identity.verify(&self.signed_data(), &self.signature)
    }

    /// Whether this revocation asks peers to propagate it immediately rather
    /// than waiting for their normal configuration refresh.
    #[must_use]
    pub fn fast_propagate(&self) -> bool {
        self.flags & 1 != 0
    }

    /// The fields authenticated by the controller signature.
    fn signed_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(80);
        data.extend_from_slice(&0x7f7f_7f7f_7f7f_7f7fu64.to_be_bytes());
        data.extend_from_slice(&self.append_base());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0x7f7f_7f7f_7f7f_7f7fu64.to_be_bytes());
        data
    }

    /// The complete wire encoding, re-serialized from the decoded fields.
    #[must_use]
    #[expect(clippy::cast_possible_truncation, reason = "the signature-length wire field is 16 bits")]
    pub fn append_binary(&self, mut data: Vec<u8>) -> Vec<u8> {
        if !self.raw.is_empty() {
            data.extend_from_slice(&self.raw);
            return data;
        }
        data.extend_from_slice(&self.append_base());
        data.push(1);
        data.extend_from_slice(&(SIGNATURE_SIZE as u16).to_be_bytes());
        data.extend_from_slice(&self.signature);
        data.extend_from_slice(&0u16.to_be_bytes());
        data
    }

    /// The signed fields, shared by the wire encoding and the signature.
    fn append_base(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(REVOCATION_BASE_SIZE);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&self.id.to_be_bytes());
        data.extend_from_slice(&self.network_id.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&self.credential_id.to_be_bytes());
        data.extend_from_slice(&self.threshold.to_be_bytes());
        data.extend_from_slice(&self.flags.to_be_bytes());
        data.extend_from_slice(&self.target.bytes());
        data.extend_from_slice(&self.signed_by.bytes());
        data.push(self.credential_type.bits());
        data
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(controller_identity: &Identity, target: Address, flags: u64) -> Revocation {
        let network_id = controller_identity.address().uint64() << 24;
        let mut revocation = Revocation {
            id: 11,
            network_id,
            credential_id: 5,
            threshold: 1_700_000_500,
            flags,
            target,
            signed_by: controller_identity.address(),
            credential_type: CredentialType::Tag,
            signature: [0u8; SIGNATURE_SIZE],
            raw: Vec::new(),
        };
        revocation.signature = controller_identity.sign(&revocation.signed_data()).expect("signs");
        let (parsed, _) = Revocation::parse(&revocation.append_binary(Vec::new())).expect("parses");
        parsed
    }

    #[test]
    fn a_controller_signed_revocation_verifies() {
        let controller_identity = Identity::generate();
        let target = Identity::generate();
        let revocation = issue(&controller_identity, target.address(), 0);

        assert!(revocation.verify(&controller_identity));
        assert_eq!(revocation.id, 11);
        assert_eq!(revocation.credential_id, 5);
        assert_eq!(revocation.threshold, 1_700_000_500);
        assert_eq!(revocation.target, target.address());
        assert_eq!(revocation.credential_type, CredentialType::Tag);
        assert!(!revocation.fast_propagate());
    }

    #[test]
    fn the_fast_propagate_flag_is_read_from_the_flags_field() {
        let controller_identity = Identity::generate();
        let revocation = issue(&controller_identity, Identity::generate().address(), 1);
        assert!(revocation.fast_propagate());
    }

    #[test]
    fn a_revocation_fails_under_the_wrong_controller() {
        let controller_identity = Identity::generate();
        let revocation = issue(&controller_identity, Identity::generate().address(), 0);
        assert!(!revocation.verify(&Identity::generate()));
    }

    #[test]
    fn a_raised_threshold_breaks_the_signature() {
        let controller_identity = Identity::generate();
        let revocation = issue(&controller_identity, Identity::generate().address(), 0);
        let mut raw = revocation.bytes().to_vec();

        // The threshold field's low byte sits at offset 31.
        raw[31] ^= 1;
        let (forged, _) = Revocation::parse(&raw).expect("structure still parses");
        assert!(!forged.verify(&controller_identity));
    }

    #[test]
    fn re_serialization_is_byte_stable() {
        let controller_identity = Identity::generate();
        let revocation = issue(&controller_identity, Identity::generate().address(), 1);
        assert_eq!(revocation.append_binary(Vec::new()), revocation.bytes());
    }

    #[test]
    fn rejects_malformed_structures() {
        assert_eq!(Revocation::parse(&[0u8; 8]), Err(InvalidRevocation));

        let controller_identity = Identity::generate();
        let mut raw = issue(&controller_identity, Identity::generate().address(), 0).bytes().to_vec();
        // Credential type 5 is not valid: only 1..=4 may appear.
        raw[40 + ADDRESS_SIZE * 2] = 5;
        assert_eq!(Revocation::parse(&raw), Err(InvalidRevocation));
    }

    #[test]
    fn credential_type_names_are_stable() {
        assert_eq!(CredentialType::CertificateOfMembership.name(), "com");
        assert_eq!(CredentialType::Capability.name(), "capability");
        assert_eq!(CredentialType::Tag.name(), "tag");
        assert_eq!(CredentialType::Ownership.name(), "ownership");
    }
}

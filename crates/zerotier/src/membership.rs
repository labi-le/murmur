//! Certificates of membership: a controller's signed proof that a node is
//! authorized on a private network.
//!
//! A COM is a list of qualifiers rather than fixed fields. The standard ones
//! are ID 0 (timestamp), 1 (network), 2 (member address) and 3..=6 (the four
//! 64-bit words of the member's identity digest), but a controller may add
//! more, and two certificates "agree" when every qualifier of one is matched
//! by the other within its allowed delta.

use sha2::{Digest, Sha384};

use crate::address::{controller, Address, ADDRESS_SIZE};
use crate::identity::{Identity, PUBLIC_KEY_SIZE, SIGNATURE_SIZE};

/// The protocol limit for qualifiers in a membership certificate.
pub const MAX_COM_QUALIFIERS: usize = 8;

/// Standard qualifier IDs with fixed meanings.
pub const QUALIFIER_TIMESTAMP: u64 = 0;
pub const QUALIFIER_NETWORK: u64 = 1;
pub const QUALIFIER_MEMBER: u64 = 2;
/// The first of the four qualifier IDs carrying the member's identity digest.
pub const QUALIFIER_IDENTITY_WORD: u64 = 3;
/// The last of the four qualifier IDs carrying the member's identity digest.
pub const QUALIFIER_IDENTITY_WORD_LAST: u64 = 6;
/// Reports a malformed membership certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ZeroTier membership certificate")]
pub struct InvalidMembership;

/// One signed constraint in a certificate of membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComQualifier {
    pub id: u64,
    pub value: u64,
    /// How far the value may drift and still be considered the same member.
    pub max_delta: u64,
}

/// Proves that a node is authorized on a private network. Signed by the
/// network controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateOfMembership {
    pub qualifiers: Vec<ComQualifier>,
    pub signed_by: Address,
    pub signature: [u8; SIGNATURE_SIZE],
    /// The exact bytes this certificate was decoded from, so re-encoding is
    /// byte-stable.
    raw: Vec<u8>,
}

impl CertificateOfMembership {
    /// Decodes one binary membership certificate, reporting bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), InvalidMembership> {
        let [version, count_hi, count_lo, ..] = data else {
            return Err(InvalidMembership);
        };
        if *version != 1 {
            return Err(InvalidMembership);
        }
        let count = usize::from(u16::from_be_bytes([*count_hi, *count_lo]));
        if count == 0 || count > MAX_COM_QUALIFIERS {
            return Err(InvalidMembership);
        }
        let length = 3 + count * 24 + ADDRESS_SIZE;
        if data.len() < length {
            return Err(InvalidMembership);
        }

        let mut qualifiers = Vec::with_capacity(count);
        let mut pos = 3;
        let mut last_id = 0u64;
        for index in 0..count {
            let qualifier = ComQualifier {
                id: read_u64(data, pos).ok_or(InvalidMembership)?,
                value: read_u64(data, pos + 8).ok_or(InvalidMembership)?,
                max_delta: read_u64(data, pos + 16).ok_or(InvalidMembership)?,
            };
            // Qualifier IDs must be non-decreasing, which is what makes the
            // last-wins lookup below well defined.
            if index > 0 && qualifier.id < last_id {
                return Err(InvalidMembership);
            }
            last_id = qualifier.id;
            qualifiers.push(qualifier);
            pos += 24;
        }

        let signer_bytes = data.get(pos..pos + ADDRESS_SIZE).ok_or(InvalidMembership)?;
        let signed_by = Address::from_bytes(signer_bytes).map_err(|_| InvalidMembership)?;
        pos += ADDRESS_SIZE;

        let mut signature = [0u8; SIGNATURE_SIZE];
        if !signed_by.is_zero() {
            if data.len().saturating_sub(pos) < SIGNATURE_SIZE {
                return Err(InvalidMembership);
            }
            signature.copy_from_slice(data.get(pos..pos + SIGNATURE_SIZE).ok_or(InvalidMembership)?);
            pos += SIGNATURE_SIZE;
        }

        Ok((Self { qualifiers, signed_by, signature, raw: data.get(..pos).ok_or(InvalidMembership)?.to_vec() }, pos))
    }

    /// Decodes the legacy text certificate form a pre-version-6 controller
    /// publishes as `1:<qualifiers>:<signer>[:<signature>]`.
    pub fn from_legacy_string(value: &str) -> Result<Self, InvalidMembership> {
        let value = match value.find('\0') {
            Some(nul) => value.get(..nul).ok_or(InvalidMembership)?,
            None => value,
        };
        let parts: Vec<&str> = value.splitn(5, ':').collect();
        let (Some(version), Some(qualifier_text)) = (parts.first().copied(), parts.get(1).copied()) else {
            return Err(InvalidMembership);
        };
        if parts.len() < 3 || version != "1" || qualifier_text.is_empty() {
            return Err(InvalidMembership);
        }
        let qualifier_data = hex::decode(qualifier_text).map_err(|_| InvalidMembership)?;
        if qualifier_data.is_empty() || qualifier_data.len() % 24 != 0 || qualifier_data.len() / 24 > MAX_COM_QUALIFIERS
        {
            return Err(InvalidMembership);
        }
        let mut qualifiers: Vec<ComQualifier> = qualifier_data
            .chunks_exact(24)
            .map(|chunk| {
                Ok(ComQualifier {
                    id: read_u64(chunk, 0).ok_or(InvalidMembership)?,
                    value: read_u64(chunk, 8).ok_or(InvalidMembership)?,
                    max_delta: read_u64(chunk, 16).ok_or(InvalidMembership)?,
                })
            })
            .collect::<Result<Vec<ComQualifier>, InvalidMembership>>()?;
        qualifiers.sort_by_key(|qualifier| qualifier.id);
        qualifiers.dedup_by_key(|qualifier| qualifier.id);

        let signer_text = parts.get(2).copied().ok_or(InvalidMembership)?;
        let signed_by = Address::parse(signer_text).map_err(|_| InvalidMembership)?;
        let mut signature = [0u8; SIGNATURE_SIZE];
        if !signed_by.is_zero() {
            let text = parts.get(3).ok_or(InvalidMembership)?;
            if text.len() != SIGNATURE_SIZE * 2 {
                return Err(InvalidMembership);
            }
            let decoded = hex::decode(text).map_err(|_| InvalidMembership)?;
            signature.copy_from_slice(&decoded);
        }

        let mut certificate = Self { qualifiers, signed_by, signature, raw: Vec::new() };
        let qualifier_count = u8::try_from(certificate.qualifiers.len()).map_err(|_| InvalidMembership)?;
        let mut raw = vec![1u8, 0, qualifier_count];
        raw.extend_from_slice(&certificate.signed_data());
        raw.extend_from_slice(&signed_by.bytes());
        if !signed_by.is_zero() {
            raw.extend_from_slice(&signature);
        }
        certificate.raw = raw;
        Ok(certificate)
    }

    /// The certificate's own wire encoding, as decoded.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The standard timestamp qualifier.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.qualifier_value(QUALIFIER_TIMESTAMP)
    }

    /// The standard network qualifier.
    #[must_use]
    pub fn network_id(&self) -> u64 {
        self.qualifier_value(QUALIFIER_NETWORK)
    }

    /// The standard member-address qualifier.
    #[must_use]
    pub fn issued_to(&self) -> Address {
        Address::new(self.qualifier_value(QUALIFIER_MEMBER))
    }

    /// Authenticates this certificate with the network controller identity.
    #[must_use]
    pub fn verify(&self, controller_identity: &Identity) -> bool {
        if self.signed_by.is_zero()
            || self.signed_by != controller_identity.address()
            || self.signed_by != controller(self.network_id())
        {
            return false;
        }
        controller_identity.verify(&self.signed_data(), &self.signature)
    }

    /// Applies ZeroTier One's qualifier comparison. A node's own certificate
    /// acts as the membership template for remote certificates.
    #[must_use]
    pub fn agrees_with(&self, other: &Self, other_identity: &Identity) -> bool {
        self.agrees_with_public_key_hash(other, &public_key_hash(other_identity))
    }

    /// [`CertificateOfMembership::agrees_with`] with a precomputed digest.
    #[must_use]
    pub fn agrees_with_public_key_hash(&self, other: &Self, other_public_key_hash: &[u8; 48]) -> bool {
        if self.qualifiers.is_empty() || other.qualifiers.is_empty() {
            return false;
        }
        let mut check_identity_hash = false;
        for qualifier in &self.qualifiers {
            let Some(value) = last_qualifier_value(&other.qualifiers, qualifier.id) else {
                return false;
            };
            if absolute_difference(qualifier.value, value) > qualifier.max_delta {
                return false;
            }
            if (QUALIFIER_IDENTITY_WORD..=QUALIFIER_IDENTITY_WORD_LAST).contains(&qualifier.id) {
                check_identity_hash = true;
            }
        }
        if check_identity_hash {
            let mut digest_words = other_public_key_hash.chunks_exact(8);
            for word in 0..4u64 {
                let id = QUALIFIER_IDENTITY_WORD + word;
                let Some(value) = last_qualifier_value(&other.qualifiers, id) else {
                    return false;
                };
                let Some(chunk) = digest_words.next() else {
                    return false;
                };
                let mut word_bytes = [0u8; 8];
                word_bytes.copy_from_slice(chunk);
                if value != u64::from_be_bytes(word_bytes) {
                    return false;
                }
            }
        }
        true
    }

    fn signed_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.qualifiers.len() * 24);
        for qualifier in &self.qualifiers {
            data.extend_from_slice(&qualifier.id.to_be_bytes());
            data.extend_from_slice(&qualifier.value.to_be_bytes());
            data.extend_from_slice(&qualifier.max_delta.to_be_bytes());
        }
        data
    }

    fn qualifier_value(&self, id: u64) -> u64 {
        self.qualifiers.iter().find(|qualifier| qualifier.id == id).map_or(0, |qualifier| qualifier.value)
    }
}

/// The SHA-384 digest of an identity that COM identity qualifiers carry.
#[must_use]
pub fn public_key_hash(identity: &Identity) -> [u8; 48] {
    let mut bytes = [0u8; ADDRESS_SIZE + PUBLIC_KEY_SIZE];
    bytes[..ADDRESS_SIZE].copy_from_slice(&identity.address().bytes());
    bytes[ADDRESS_SIZE..].copy_from_slice(&identity.public_key());
    Sha384::digest(bytes).into()
}

/// Returns the LAST value for `id`, matching assignment into the map ZeroTier One
/// uses when a malformed certificate repeats an ID.
fn last_qualifier_value(qualifiers: &[ComQualifier], id: u64) -> Option<u64> {
    qualifiers.iter().rev().find(|qualifier| qualifier.id == id).map(|qualifier| qualifier.value)
}

fn absolute_difference(a: u64, b: u64) -> u64 {
    a.abs_diff(b)
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A network ID whose controller address is `controller_identity`, which is
    /// what makes that identity the only valid signer of its certificates.
    fn network_for(controller_identity: &Identity) -> u64 {
        controller_identity.address().uint64() << 24
    }

    /// Builds a controller-signed certificate with the standard qualifiers,
    /// the way a real network controller issues one.
    fn issue(controller_identity: &Identity, member: &Identity) -> CertificateOfMembership {
        let network_id = network_for(controller_identity);
        let digest = public_key_hash(member);
        let qualifiers = vec![
            ComQualifier { id: QUALIFIER_TIMESTAMP, value: 1_700_000_000, max_delta: 0 },
            ComQualifier { id: QUALIFIER_NETWORK, value: network_id, max_delta: 0 },
            ComQualifier { id: QUALIFIER_MEMBER, value: member.address().uint64(), max_delta: 0 },
            ComQualifier { id: 3, value: u64::from_be_bytes(digest[0..8].try_into().unwrap()), max_delta: 0 },
            ComQualifier { id: 4, value: u64::from_be_bytes(digest[8..16].try_into().unwrap()), max_delta: 0 },
            ComQualifier { id: 5, value: u64::from_be_bytes(digest[16..24].try_into().unwrap()), max_delta: 0 },
            ComQualifier { id: 6, value: u64::from_be_bytes(digest[24..32].try_into().unwrap()), max_delta: 0 },
        ];

        let mut signed = Vec::new();
        for qualifier in &qualifiers {
            signed.extend_from_slice(&qualifier.id.to_be_bytes());
            signed.extend_from_slice(&qualifier.value.to_be_bytes());
            signed.extend_from_slice(&qualifier.max_delta.to_be_bytes());
        }
        let signature = controller_identity.sign(&signed).expect("controller signs");

        let mut raw = vec![1u8];
        raw.extend_from_slice(&(qualifiers.len() as u16).to_be_bytes());
        for qualifier in &qualifiers {
            raw.extend_from_slice(&qualifier.id.to_be_bytes());
            raw.extend_from_slice(&qualifier.value.to_be_bytes());
            raw.extend_from_slice(&qualifier.max_delta.to_be_bytes());
        }
        raw.extend_from_slice(&controller_identity.address().bytes());
        raw.extend_from_slice(&signature);

        let (parsed, _) = CertificateOfMembership::parse(&raw).expect("parse issued certificate");
        parsed
    }

    /// An unsigned certificate whose timestamp qualifier is repeated, which the parse accepts.
    fn repeated_timestamp_certificate() -> CertificateOfMembership {
        let mut raw = vec![1u8];
        raw.extend_from_slice(&4u16.to_be_bytes());
        for (id, value) in
            [(QUALIFIER_TIMESTAMP, 1u64), (QUALIFIER_TIMESTAMP, 2), (QUALIFIER_NETWORK, 3), (QUALIFIER_MEMBER, 4)]
        {
            raw.extend_from_slice(&id.to_be_bytes());
            raw.extend_from_slice(&value.to_be_bytes());
            raw.extend_from_slice(&0u64.to_be_bytes());
        }
        raw.extend_from_slice(&[0u8; ADDRESS_SIZE]);
        CertificateOfMembership::parse(&raw).expect("parses").0
    }

    /// The reference reads a repeated qualifier id two ways: its accessors take the first record and
    /// its agreement map takes the last.
    #[test]
    fn a_repeated_qualifier_id_is_first_for_the_accessors_and_last_for_agreement() {
        let certificate = repeated_timestamp_certificate();

        assert_eq!(certificate.qualifiers.len(), 4);
        assert_eq!(certificate.timestamp(), 1, "the accessor reads the first record, as the reference's does");
        assert_eq!(
            last_qualifier_value(&certificate.qualifiers, QUALIFIER_TIMESTAMP),
            Some(2),
            "the agreement lookup reads the last record, as the reference's map does"
        );
    }

    #[test]
    fn a_controller_signed_certificate_verifies() {
        let controller_identity = Identity::generate();
        let member = Identity::generate();
        let certificate = issue(&controller_identity, &member);

        assert!(certificate.verify(&controller_identity));
        assert_eq!(certificate.network_id(), network_for(&controller_identity));
        assert_eq!(certificate.timestamp(), 1_700_000_000);
        assert_eq!(certificate.issued_to(), member.address());
    }

    #[test]
    fn a_certificate_fails_under_the_wrong_controller() {
        let controller_identity = Identity::generate();
        let impostor = Identity::generate();
        let certificate = issue(&controller_identity, &Identity::generate());

        assert!(!certificate.verify(&impostor));
    }

    #[test]
    fn tampering_with_a_qualifier_breaks_the_signature() {
        let controller_identity = Identity::generate();
        let certificate = issue(&controller_identity, &Identity::generate());
        let mut raw = certificate.bytes().to_vec();

        // The first qualifier's value sits after its 8-byte ID.
        raw[3 + 8] ^= 1;
        let (forged, _) = CertificateOfMembership::parse(&raw).expect("structure still parses");
        assert!(!forged.verify(&controller_identity));
    }

    #[test]
    fn certificates_agree_only_for_the_same_member() {
        let controller_identity = Identity::generate();
        let member = Identity::generate();
        let other = Identity::generate();

        let mine = issue(&controller_identity, &member);
        let theirs = issue(&controller_identity, &member);
        let stranger = issue(&controller_identity, &other);

        assert!(mine.agrees_with(&theirs, &member));
        assert!(!mine.agrees_with(&stranger, &other));
    }

    #[test]
    fn rejects_malformed_structures() {
        assert_eq!(CertificateOfMembership::parse(&[]), Err(InvalidMembership));
        assert_eq!(CertificateOfMembership::parse(&[0, 0, 1]), Err(InvalidMembership));

        let mut zero_qualifiers = vec![1u8, 0, 0];
        zero_qualifiers.extend_from_slice(&[0u8; ADDRESS_SIZE]);
        assert_eq!(CertificateOfMembership::parse(&zero_qualifiers), Err(InvalidMembership));

        let mut too_many = vec![1u8];
        too_many.extend_from_slice(&((MAX_COM_QUALIFIERS + 1) as u16).to_be_bytes());
        too_many.resize(3 + (MAX_COM_QUALIFIERS + 1) * 24 + ADDRESS_SIZE, 0);
        assert_eq!(CertificateOfMembership::parse(&too_many), Err(InvalidMembership));
    }

    #[test]
    fn rejects_descending_qualifier_ids() {
        let mut raw = vec![1u8];
        raw.extend_from_slice(&2u16.to_be_bytes());
        // A higher ID first, then a lower one.
        raw.extend_from_slice(&5u64.to_be_bytes());
        raw.extend_from_slice(&1u64.to_be_bytes());
        raw.extend_from_slice(&0u64.to_be_bytes());
        raw.extend_from_slice(&4u64.to_be_bytes());
        raw.extend_from_slice(&1u64.to_be_bytes());
        raw.extend_from_slice(&0u64.to_be_bytes());
        raw.extend_from_slice(&[0u8; ADDRESS_SIZE]);

        assert_eq!(CertificateOfMembership::parse(&raw), Err(InvalidMembership));
    }

    #[test]
    fn public_key_hash_is_stable_and_distinguishes_members() {
        let member = Identity::generate();
        assert_eq!(public_key_hash(&member), public_key_hash(&member));
        assert_ne!(public_key_hash(&member), public_key_hash(&Identity::generate()));
    }
}

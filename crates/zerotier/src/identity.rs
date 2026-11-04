//! ZeroTier node identities: the paired X25519/Ed25519 key material whose
//! SHA-512 memory-hard hash both yields and validates the 40-bit node address.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::address::Address;
use crate::ztcrypto::salsa::{xor_key_stream, xor_key_stream_in_place};

pub const PUBLIC_KEY_SIZE: usize = 64;
pub const PRIVATE_KEY_SIZE: usize = 64;
/// A ZeroTier identity signature is an Ed25519 signature over the SHA-512
/// digest of the message, with that digest appended.
pub const SIGNATURE_SIZE: usize = 96;
pub const SYMMETRIC_KEY_SIZE: usize = 48;

const IDENTITY_HASH_MEMORY_SIZE: usize = 2 * 1024 * 1024;
/// The address proof of work requires this leading byte to stay below the
/// threshold, giving roughly 1-in-150 acceptance.
const IDENTITY_HASH_THRESHOLD: u8 = 17;
const SERIALIZED_IDENTITY_SIZE: usize = Address::SIZE + 1 + PUBLIC_KEY_SIZE + 1;

/// Reports malformed identity data or failed key validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("invalid ZeroTier identity")]
    Invalid,
    #[error("ZeroTier identity has no private key")]
    NoPrivateKey,
}

/// ZeroTier's two public keys plus, optionally, their private seeds. Bytes
/// `0..32` are X25519 and bytes `32..64` are Ed25519.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    address: Address,
    public: [u8; PUBLIC_KEY_SIZE],
    private: Option<[u8; PRIVATE_KEY_SIZE]>,
}

/// Redacts the private half: an identity's secret string is a bearer credential
/// and must never reach a log line.
impl core::fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("address", &self.address)
            .field("public", &hex::encode(self.public))
            .field("has_private", &self.private.is_some())
            .finish()
    }
}

impl Identity {
    /// Creates a secret identity satisfying the address proof of work. Each
    /// rejected candidate walks the key space instead of redrawing entropy, so
    /// this is expected to take a few hundred attempts.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut ed_seed = [0u8; 32];
        rng.fill_bytes(&mut ed_seed);
        let signing = SigningKey::from_bytes(&ed_seed);

        let mut private = [0u8; PRIVATE_KEY_SIZE];
        private[32..].copy_from_slice(&ed_seed);
        rng.fill_bytes(&mut private[..32]);

        let mut public = [0u8; PUBLIC_KEY_SIZE];
        public[32..].copy_from_slice(signing.verifying_key().as_bytes());
        loop {
            public[..32].copy_from_slice(&x25519_basepoint(&dh_seed(&private)));
            let digest = identity_memory_hard_hash(&public);
            let candidate = Address::from_bytes(&digest[59..]);
            let accepted = match candidate {
                Ok(address) if digest[0] < IDENTITY_HASH_THRESHOLD && !address.is_reserved() => Some(address),
                _ => None,
            };
            if let Some(address) = accepted {
                return Self { address, public, private: Some(private) };
            }
            let mut seed = dh_seed(&private);
            increment_identity_private(&mut seed);
            private[..32].copy_from_slice(&seed);
        }
    }

    /// Wraps already-validated public key material without its private half.
    #[must_use]
    pub fn from_parts(address: Address, public: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self { address, public, private: None }
    }

    /// Decodes ZeroTier's colon-delimited identity form: `address:0:public` and
    /// optionally `:private`.
    pub fn parse(text: &str) -> Result<Self, IdentityError> {
        let parts: Vec<&str> = text.trim().split(':').collect();
        let [address_part, version, public_part, rest @ ..] = parts.as_slice() else {
            return Err(IdentityError::Invalid);
        };
        if rest.len() > 1 {
            return Err(IdentityError::Invalid);
        }
        let address = Address::parse(address_part).map_err(|_| IdentityError::Invalid)?;
        if *version != "0" {
            return Err(IdentityError::Invalid);
        }
        let public = decode_exact::<PUBLIC_KEY_SIZE>(public_part)?;
        let mut identity = Self::from_parts(address, public);
        if let Some(private_part) = rest.first() {
            let private = decode_exact::<PRIVATE_KEY_SIZE>(private_part)?;
            identity.private = Some(private);
            identity.validate_private()?;
        }
        Ok(identity)
    }

    /// Decodes one binary identity and reports how many bytes it consumed.
    pub fn parse_binary(data: &[u8]) -> Result<(Self, usize), IdentityError> {
        if data.len() < SERIALIZED_IDENTITY_SIZE {
            return Err(IdentityError::Invalid);
        }
        let (address_bytes, remainder) = data.split_at(Address::SIZE);
        let address = Address::from_bytes(address_bytes).map_err(|_| IdentityError::Invalid)?;
        let Some((&version, remainder)) = remainder.split_first() else {
            return Err(IdentityError::Invalid);
        };
        if version != 0 {
            return Err(IdentityError::Invalid);
        }
        let (public_bytes, remainder) = remainder.split_at(PUBLIC_KEY_SIZE);
        let mut public = [0u8; PUBLIC_KEY_SIZE];
        public.copy_from_slice(public_bytes);

        let Some((&private_len, remainder)) = remainder.split_first() else {
            return Err(IdentityError::Invalid);
        };
        let mut identity = Self::from_parts(address, public);
        let mut position = data.len() - remainder.len();
        if private_len != 0 {
            let private_len = usize::from(private_len);
            if private_len != PRIVATE_KEY_SIZE || remainder.len() < private_len {
                return Err(IdentityError::Invalid);
            }
            let (private_bytes, _) = remainder.split_at(private_len);
            let mut private = [0u8; PRIVATE_KEY_SIZE];
            private.copy_from_slice(private_bytes);
            identity.private = Some(private);
            identity.validate_private()?;
            position += private_len;
        }
        Ok((identity, position))
    }

    #[must_use]
    pub fn address(&self) -> Address {
        self.address
    }

    #[must_use]
    pub fn has_private(&self) -> bool {
        self.private.is_some()
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.public
    }

    /// The X25519 private seed, for protocol-13 ephemeral armor. A public-only
    /// identity has none.
    pub fn dh_seed(&self) -> Option<[u8; 32]> {
        self.private.as_ref().map(dh_seed)
    }

    /// The canonical public text form, `address:0:public`.
    #[must_use]
    pub fn public_string(&self) -> String {
        format!("{}:0:{}", self.address, hex_lower(&self.public))
    }

    /// The canonical secret text form, or an empty string when this identity
    /// carries no private key.
    #[must_use]
    pub fn secret_string(&self) -> String {
        match self.private {
            Some(private) => format!("{}:0:{}:{}", self.address, hex_lower(&self.public), hex_lower(&private)),
            None => String::new(),
        }
    }

    /// Appends the binary identity, including the private key when present and
    /// requested.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "PRIVATE_KEY_SIZE is the protocol's private-key length byte, whose value is 64 by definition"
    )]
    pub fn append_binary(&self, dst: &mut Vec<u8>, include_private: bool) {
        self.address.append_to(dst);
        dst.push(0);
        dst.extend_from_slice(&self.public);
        match (include_private, self.private) {
            (true, Some(private)) => {
                dst.push(PRIVATE_KEY_SIZE as u8);
                dst.extend_from_slice(&private);
            }
            _ => dst.push(0),
        }
    }

    /// Verifies the address proof of work and any included private key.
    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.address.is_reserved() {
            return Err(IdentityError::Invalid);
        }
        let digest = identity_memory_hard_hash(&self.public);
        if digest[0] >= IDENTITY_HASH_THRESHOLD || digest[59..] != self.address.bytes() {
            return Err(IdentityError::Invalid);
        }
        self.validate_private()
    }

    /// Verifies that the private seeds reproduce both public keys.
    pub fn validate_private(&self) -> Result<(), IdentityError> {
        let Some(private) = self.private else {
            return Ok(());
        };
        if x25519_basepoint(&dh_seed(&private)) != self.public[..32] {
            return Err(IdentityError::Invalid);
        }
        if signing_key(&private).verifying_key().as_bytes() != &self.public[32..] {
            return Err(IdentityError::Invalid);
        }
        Ok(())
    }

    /// Derives ZeroTier's 48-byte shared secret with `peer`: the first half of
    /// the SHA-512 of the raw X25519 output.
    pub fn agree(&self, peer: &Self) -> Result<[u8; SYMMETRIC_KEY_SIZE], IdentityError> {
        let private = self.private.ok_or(IdentityError::NoPrivateKey)?;
        let peer_public = <[u8; 32]>::try_from(&peer.public[..32]).map_err(|_| IdentityError::Invalid)?;
        Ok(agree_raw(&dh_seed(&private), &peer_public))
    }

    /// Signs `message` in ZeroTier's format: Ed25519 over the SHA-512 digest,
    /// with the digest appended so peers can spot a wrong-message signature
    /// before the curve check.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_SIZE], IdentityError> {
        let private = self.private.ok_or(IdentityError::NoPrivateKey)?;
        let digest = short_digest(message);
        let signature = signing_key(&private).sign(&digest);
        let mut out = [0u8; SIGNATURE_SIZE];
        out[..64].copy_from_slice(&signature.to_bytes());
        out[64..].copy_from_slice(&digest);
        Ok(out)
    }

    /// Authenticates a ZeroTier-encoded signature over `message`.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != SIGNATURE_SIZE {
            return false;
        }
        let digest = short_digest(message);
        let (signature_bytes, appended) = signature.split_at(64);
        let mut mismatch = 0u8;
        for (appended_byte, digest_byte) in appended.iter().zip(&digest) {
            mismatch |= *appended_byte ^ *digest_byte;
        }
        if mismatch != 0 {
            return false;
        }
        let Ok(public) = <[u8; 32]>::try_from(&self.public[32..]) else {
            return false;
        };
        let Ok(verifying) = VerifyingKey::from_bytes(&public) else {
            return false;
        };
        let Ok(signature_bytes) = <[u8; 64]>::try_from(signature_bytes) else {
            return false;
        };
        verifying.verify(&digest, &Signature::from_bytes(&signature_bytes)).is_ok()
    }
}

/// The first 32 bytes of the message SHA-512: ZeroTier signs that short digest
/// rather than the message itself, and appends it to every signature.
fn short_digest(message: &[u8]) -> [u8; 32] {
    let full: [u8; 64] = Sha512::digest(message).into();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&full[..32]);
    digest
}

/// The 32-byte AES key for a protocol-13 ephemeral peer key: the first half of
/// the SHA-512 of the raw X25519 shared secret.
pub fn agree_ephemeral(private: &[u8; 32], peer_public: &[u8]) -> Result<[u8; 32], IdentityError> {
    let peer = <[u8; 32]>::try_from(peer_public).map_err(|_| IdentityError::Invalid)?;
    let digest: [u8; 64] = Sha512::digest(agree_raw(private, &peer)).into();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    Ok(key)
}

fn agree_raw(private: &[u8; 32], peer_public: &[u8; 32]) -> [u8; SYMMETRIC_KEY_SIZE] {
    let secret = StaticSecret::from(*private);
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_public));
    let digest: [u8; 64] = Sha512::digest(shared.as_bytes()).into();
    let mut key = [0u8; SYMMETRIC_KEY_SIZE];
    key.copy_from_slice(&digest[..SYMMETRIC_KEY_SIZE]);
    key
}

fn dh_seed(private: &[u8; PRIVATE_KEY_SIZE]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&private[..32]);
    seed
}

fn signing_key(private: &[u8; PRIVATE_KEY_SIZE]) -> SigningKey {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&private[32..]);
    SigningKey::from_bytes(&seed)
}

fn x25519_basepoint(seed: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*seed)).to_bytes()
}

/// Mirrors ECC::generateSatisfying: increment the second native-endian `u64` of
/// the X25519 seed and decrement the third. ZeroTier's supported targets are
/// little endian.
fn increment_identity_private(private: &mut [u8; 32]) {
    let mut word = [0u8; 8];
    word.copy_from_slice(&private[8..16]);
    let second = u64::from_le_bytes(word).wrapping_add(1);
    private[8..16].copy_from_slice(&second.to_le_bytes());
    word.copy_from_slice(&private[16..24]);
    let third = u64::from_le_bytes(word).wrapping_sub(1);
    private[16..24].copy_from_slice(&third.to_le_bytes());
}

/// The memory-hard digest that both derives and validates a ZeroTier address:
/// a Salsa20-driven 2 MiB shuffle seeded by the public key, whose digest is
/// then randomly permuted 64,000 times.
#[must_use]
pub fn identity_memory_hard_hash(public: &[u8]) -> [u8; 64] {
    let mut digest: [u8; 64] = Sha512::digest(public).into();
    let mut memory = vec![0u8; IDENTITY_HASH_MEMORY_SIZE];
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    let mut counter = [0u8; 16];
    counter[..8].copy_from_slice(&digest[32..40]);

    let (first_block, _) = memory.split_at_mut(64);
    xor_key_stream_in_place(first_block, &counter, &key, 20);

    let mut stream_counter: u64 = 1;
    let mut index = 64;
    while index < memory.len() {
        counter[8..16].copy_from_slice(&stream_counter.to_le_bytes());
        let (previous, rest) = memory.split_at_mut(index);
        let (_, source) = previous.split_at(index - 64);
        let (current, _) = rest.split_at_mut(64);
        xor_key_stream(current, source, &counter, &key, 20);
        stream_counter += 1;
        index += 64;
    }

    let slots = memory.len() / 8;
    let mut tmp = [0u8; 8];
    let mut position = 0;
    while position < memory.len() {
        let (_, tail) = memory.split_at(position);
        let (pair, _) = tail.split_at(16);
        let (digest_offset, arena_offset) = shuffle_offsets(pair, slots);
        position += 16;

        let (_, arena_tail) = memory.split_at_mut(arena_offset);
        let (arena_window, _) = arena_tail.split_at_mut(8);
        let (_, digest_tail) = digest.split_at_mut(digest_offset);
        let (digest_window, _) = digest_tail.split_at_mut(8);
        tmp.copy_from_slice(arena_window);
        arena_window.copy_from_slice(digest_window);
        digest_window.copy_from_slice(&tmp);
        counter[8..16].copy_from_slice(&stream_counter.to_le_bytes());
        xor_key_stream_in_place(&mut digest, &counter, &key, 20);
        stream_counter += 1;
    }
    digest
}

/// The digest and arena byte offsets the next 16-byte memory block selects.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the protocol indexes the digest and arena with machine words; both offsets are bounded before use"
)]
fn shuffle_offsets(pair: &[u8], slots: usize) -> (usize, usize) {
    let (low, high) = pair.split_at(8);
    let mut word = [0u8; 8];
    word.copy_from_slice(low);
    let first = u64::from_be_bytes(word);
    word.copy_from_slice(high);
    let second = u64::from_be_bytes(word);
    ((first as usize & 7) * 8, (second as usize % slots) * 8)
}

fn decode_exact<const N: usize>(text: &str) -> Result<[u8; N], IdentityError> {
    let bytes = hex::decode(text).map_err(|_| IdentityError::Invalid)?;
    bytes.try_into().map_err(|_| IdentityError::Invalid)
}

fn hex_lower(data: &[u8]) -> String {
    hex::encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Identity {
        Identity::generate()
    }

    #[test]
    fn generated_identity_validates() {
        let identity = secret();
        assert!(identity.has_private());
        assert!(!identity.address().is_reserved());
        assert!(identity.validate().is_ok());
    }

    #[test]
    fn text_round_trips_both_forms() {
        let identity = secret();
        let public = identity.public_string();
        assert!(!identity.secret_string().is_empty());

        let parsed = Identity::parse(&public).unwrap();
        assert_eq!(parsed, identity.public_key_only());
        assert!(!parsed.has_private());

        let with_secret = Identity::parse(&identity.secret_string()).unwrap();
        assert!(with_secret.has_private());
        assert_eq!(with_secret, identity);
    }

    #[test]
    fn binary_round_trips() {
        let identity = secret();
        let mut buffer = Vec::new();
        identity.append_binary(&mut buffer, true);
        let (parsed, consumed) = Identity::parse_binary(&buffer).unwrap();
        assert_eq!(parsed, identity);
        assert_eq!(consumed, buffer.len());

        let mut public_only = Vec::new();
        identity.append_binary(&mut public_only, false);
        let (parsed, consumed) = Identity::parse_binary(&public_only).unwrap();
        assert_eq!(parsed, identity.public_key_only());
        assert_eq!(consumed, public_only.len());
    }

    #[test]
    fn signatures_round_trip_and_reject_tampering() {
        let signer = secret();
        let message = b"membership-update";
        let signature = signer.sign(message).unwrap();
        assert!(signer.verify(message, &signature));

        assert!(!signer.verify(b"membership-updated", &signature));
        assert!(!signer.verify(message, &signature[1..]));

        let mut tampered = signature;
        tampered[0] ^= 1;
        assert!(!signer.verify(message, &tampered));
    }

    #[test]
    fn agreement_is_symmetric() {
        let first = secret();
        let second = secret();
        assert_eq!(first.agree(&second).unwrap(), second.agree(&first).unwrap());
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(Identity::parse("not-an-identity").is_err());
        assert!(Identity::parse("").is_err());

        let secret_text = secret().secret_string();
        let parts: Vec<&str> = secret_text.split(':').collect();
        let mut bad_version = parts.clone();
        bad_version[1] = "1";
        assert!(Identity::parse(&bad_version.join(":")).is_err());

        let mut bad_address = parts.clone();
        bad_address[0] = "ffffffffff";
        assert!(Identity::parse(&bad_address.join(":")).is_err());
    }

    #[test]
    fn rejects_identity_whose_address_does_not_match_key() {
        let identity = secret();
        let other = secret();
        let forged = Identity::from_parts(identity.address(), other.public_key());
        assert!(forged.validate().is_err());
    }

    impl Identity {
        fn public_key_only(&self) -> Self {
            Self::from_parts(self.address, self.public)
        }
    }
}

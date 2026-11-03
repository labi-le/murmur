//! X25519 key material.

use anyhow::{anyhow, Result};
use rand::RngCore as _;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};

pub const KEY_SIZE: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PublicKey([u8; KEY_SIZE]);

impl PublicKey {
    /// Builds a public key from its 32 wire bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

/// A private key plus the public key derived from it.
#[derive(Clone)]
pub struct StaticKey(StaticSecret);

impl StaticKey {
    /// Builds a private key from bytes: a 32-byte scalar, clamped by the scalar
    /// multiplication itself.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Generates a clamped random scalar.
    #[must_use]
    pub fn random() -> Self {
        let mut bytes = [0u8; KEY_SIZE];
        rand::rng().fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(*DalekPublicKey::from(&self.0).as_bytes())
    }

    /// Rejects a small-order (all-zero) shared secret.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> Result<[u8; KEY_SIZE]> {
        let shared = self.0.diffie_hellman(&DalekPublicKey::from(peer.0));
        if !shared.was_contributory() {
            return Err(anyhow!("invalid public key"));
        }
        Ok(shared.to_bytes())
    }
}

impl std::fmt::Debug for StaticKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StaticKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct PresharedKey([u8; KEY_SIZE]);

impl PresharedKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// The pre-shared key of a peer that has none configured: 32 zero bytes.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self([0u8; KEY_SIZE])
    }

    /// The 32 wire bytes mixed into the transcript.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7748 §6.1.
    #[test]
    fn diffie_hellman_matches_rfc7748_vector() {
        let alice = StaticKey::from_bytes(hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
        let bob = StaticKey::from_bytes(hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
        let shared = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(
            alice.public_key().as_bytes().to_vec(),
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a").to_vec()
        );
        assert_eq!(
            bob.public_key().as_bytes().to_vec(),
            hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f").to_vec()
        );
        assert_eq!(alice.diffie_hellman(&bob.public_key()).expect("dh").to_vec(), shared.to_vec());
        assert_eq!(bob.diffie_hellman(&alice.public_key()).expect("dh").to_vec(), shared.to_vec());
    }

    #[test]
    fn small_order_points_are_rejected() {
        let key = StaticKey::random();
        assert!(key.diffie_hellman(&PublicKey::from_bytes([0u8; 32])).is_err());
    }

    #[test]
    fn public_key_derives_from_the_private_key_deterministically() {
        let key = StaticKey::from_bytes([9u8; 32]);
        assert_eq!(key.public_key(), key.clone().public_key());
        assert_ne!(key.public_key(), StaticKey::random().public_key());
    }

    fn hex32(input: &str) -> [u8; 32] {
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).expect("hex literal"))
            .collect::<Vec<u8>>()
            .try_into()
            .expect("32-byte hex literal")
    }
}

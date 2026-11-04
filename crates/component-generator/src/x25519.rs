//! DEVIATION: `PrivateKey`/`PublicKey` are minimal wrappers around raw 32-byte scalars.
//!
//! The standard library's `ecdh` key types have no equivalent in this crate's dependency
//! set, so these match the byte and public-key surface `cmd.rs` needs.

use anyhow::Result;
use rand::Rng as _;

pub const X25519_KEY_SIZE: usize = 32;

/// A public key, narrowed to the byte surface this package uses.
#[derive(Clone, Copy, Debug)]
pub struct PublicKey {
    bytes: [u8; X25519_KEY_SIZE],
}

impl PublicKey {
    #[must_use]
    pub const fn bytes(&self) -> [u8; X25519_KEY_SIZE] {
        self.bytes
    }
}

/// A private key, narrowed to the byte and public-key surface this package uses.
#[derive(Clone, Copy, Debug)]
pub struct PrivateKey {
    bytes: [u8; X25519_KEY_SIZE],
}

impl PrivateKey {
    #[must_use]
    pub const fn bytes(&self) -> [u8; X25519_KEY_SIZE] {
        self.bytes
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        let public = x25519_dalek::x25519(self.bytes, x25519_dalek::X25519_BASEPOINT_BYTES);
        PublicKey { bytes: public }
    }
}

pub fn gen_x25519_private_key() -> Result<PrivateKey> {
    let mut private_key = [0u8; X25519_KEY_SIZE];
    rand::rng().fill(&mut private_key);

    private_key[0] &= 0b1111_1000;
    private_key[31] &= 127;
    private_key[31] |= 64;

    Ok(PrivateKey { bytes: private_key })
}

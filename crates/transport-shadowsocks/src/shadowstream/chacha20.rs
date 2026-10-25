use std::fmt;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, XChaCha20};

use super::cipher::{Cipher, KeySizeError};

const KEY_SIZE: u8 = 32;

const NONCE_SIZE: usize = 8;

const I_NONCE_SIZE: usize = 12;

const X_NONCE_SIZE: usize = 24;

/// Builds a ChaCha20 stream, tolerating a counter overflow.
///
/// The variant is picked from the nonce length, and the 8-byte form is the IETF form with a
/// four-zero-byte nonce prefix. Only the counter-overflow tolerance departs from RFC 8439, and the
/// `chacha20` crate's ciphers have no state to protect against it, so they map onto this
/// directly.
#[expect(
    clippy::panic,
    reason = "the nonce arrives at the length `iv_size()` advertises, so the remaining arm is an invariant violation that aborts"
)]
pub(crate) fn new_chacha20(nonce: &[u8], key: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
    assert!(key.len() == usize::from(KEY_SIZE), "bad ChaCha20 key length");
    match nonce.len() {
        NONCE_SIZE => {
            let mut iv = [0u8; I_NONCE_SIZE];
            iv[I_NONCE_SIZE - NONCE_SIZE..].copy_from_slice(nonce);
            Box::new(new_cipher::<ChaCha20>(key, &iv))
        }
        I_NONCE_SIZE => Box::new(new_cipher::<ChaCha20>(key, nonce)),
        X_NONCE_SIZE => Box::new(new_cipher::<XChaCha20>(key, nonce)),
        _ => panic!("bad ChaCha20 nonce length"),
    }
}

/// Constructs the cipher; the only reachable error here is the key size `new_chacha20` already rejected.
#[expect(
    clippy::expect_used,
    reason = "`new_chacha20` asserts the key length and picks the iv length from the nonce size, so the constructor cannot report an error"
)]
fn new_cipher<C: KeyIvInit + StreamCipher + Send + Sync + 'static>(key: &[u8], iv: &[u8]) -> C {
    C::new_from_slices(key, iv).expect("bad ChaCha20 key length")
}

pub(crate) struct Chacha20Key {
    key: Vec<u8>,
}

impl Chacha20Key {
    fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}

impl fmt::Debug for Chacha20Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chacha20Key").finish_non_exhaustive()
    }
}

impl Cipher for Chacha20Key {
    fn iv_size(&self) -> usize {
        NONCE_SIZE
    }

    fn encrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
        new_chacha20(iv, &self.key)
    }

    fn decrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
        self.encrypter(iv)
    }
}

pub fn chacha20(key: &[u8]) -> anyhow::Result<Box<dyn Cipher>> {
    if key.len() != usize::from(KEY_SIZE) {
        return Err(KeySizeError(i32::from(KEY_SIZE)).into());
    }
    Ok(Box::new(Chacha20Key::new(key)))
}

/// The IETF variant of `ChaCha20`.
pub(crate) struct Chacha20IetfKey {
    key: Vec<u8>,
}

impl Chacha20IetfKey {
    fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}

impl fmt::Debug for Chacha20IetfKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chacha20IetfKey").finish_non_exhaustive()
    }
}

impl Cipher for Chacha20IetfKey {
    fn iv_size(&self) -> usize {
        I_NONCE_SIZE
    }

    fn encrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
        new_chacha20(iv, &self.key)
    }

    fn decrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
        self.encrypter(iv)
    }
}

pub fn chacha20ietf(key: &[u8]) -> anyhow::Result<Box<dyn Cipher>> {
    if key.len() != usize::from(KEY_SIZE) {
        return Err(KeySizeError(i32::from(KEY_SIZE)).into());
    }
    Ok(Box::new(Chacha20IetfKey::new(key)))
}

pub(crate) struct Xchacha20Key {
    key: Vec<u8>,
}

impl Xchacha20Key {
    fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}

impl fmt::Debug for Xchacha20Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Xchacha20Key").finish_non_exhaustive()
    }
}

impl Cipher for Xchacha20Key {
    fn iv_size(&self) -> usize {
        X_NONCE_SIZE
    }

    fn encrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
        new_chacha20(iv, &self.key)
    }

    fn decrypter(&self, iv: &[u8]) -> Box<dyn StreamCipher + Send + Sync> {
        self.encrypter(iv)
    }
}

pub fn xchacha20(key: &[u8]) -> anyhow::Result<Box<dyn Cipher>> {
    if key.len() != usize::from(KEY_SIZE) {
        return Err(KeySizeError(i32::from(KEY_SIZE)).into());
    }
    Ok(Box::new(Xchacha20Key::new(key)))
}

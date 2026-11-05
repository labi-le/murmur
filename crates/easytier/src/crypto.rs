//! Stateless, no `Reactor` state: every call is self-contained.
//!
//! `algorithm` 1 = AES-128-GCM
//! (16-byte key), 2 = AES-256-GCM (32-byte key); nonce MUST be exactly 12 bytes. Any other
//! algorithm/key-length/nonce-length combination is a soft [`CryptoStatus::Fallback`] signal, not
//! a hard error, matching the crypto-fallback convention: the guest is expected to fall
//! back to its own software crypto rather than treat this as fatal.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoStatus {
    #[error("unsupported AEAD algorithm/key-length/nonce-length combination: guest must fall back to software crypto")]
    Fallback,
    #[error("AEAD authentication failed (GCM tag mismatch)")]
    AuthFailed,
}

/// `crypto_aead_seal`. `buffer` is `[plaintext(text_len) | scratch(16)]` on entry and
/// `[ciphertext(text_len) | tag(16)]` on success, written in place.
pub fn aead_seal(
    algorithm: u8,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
    text_len: usize,
) -> Result<(), CryptoStatus> {
    if nonce.len() != NONCE_LEN || buffer.len() != text_len + TAG_LEN {
        return Err(CryptoStatus::Fallback);
    }
    let Some(plaintext) = buffer.get(..text_len) else { return Err(CryptoStatus::Fallback) };
    let sealed = seal_with(algorithm, key, nonce, aad, plaintext)?;
    if sealed.len() != text_len + TAG_LEN {
        return Err(CryptoStatus::Fallback);
    }
    buffer.copy_from_slice(&sealed);
    Ok(())
}

/// `crypto_aead_open`. `buffer` is `[ciphertext(text_len) | tag(16)]` on entry and
/// `[plaintext(text_len) | stale(16)]` on success, written in place.
pub fn aead_open(
    algorithm: u8,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
    text_len: usize,
) -> Result<(), CryptoStatus> {
    if nonce.len() != NONCE_LEN || buffer.len() != text_len + TAG_LEN {
        return Err(CryptoStatus::Fallback);
    }
    let Some(sealed) = buffer.get(..text_len + TAG_LEN) else { return Err(CryptoStatus::Fallback) };
    let opened = open_with(algorithm, key, nonce, aad, sealed)?;
    if opened.len() != text_len {
        return Err(CryptoStatus::AuthFailed);
    }
    let Some(plaintext) = buffer.get_mut(..text_len) else { return Err(CryptoStatus::Fallback) };
    plaintext.copy_from_slice(&opened);
    Ok(())
}

fn seal_with(algorithm: u8, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoStatus> {
    let Ok(nonce) = Nonce::try_from(nonce) else { return Err(CryptoStatus::Fallback) };
    match algorithm {
        1 => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| CryptoStatus::Fallback)?;
            cipher.encrypt(&nonce, Payload { msg: plaintext, aad }).map_err(|_| CryptoStatus::Fallback)
        }
        2 => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoStatus::Fallback)?;
            cipher.encrypt(&nonce, Payload { msg: plaintext, aad }).map_err(|_| CryptoStatus::Fallback)
        }
        _ => Err(CryptoStatus::Fallback),
    }
}

fn open_with(algorithm: u8, key: &[u8], nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoStatus> {
    let Ok(nonce) = Nonce::try_from(nonce) else { return Err(CryptoStatus::Fallback) };
    match algorithm {
        1 => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| CryptoStatus::Fallback)?;
            cipher.decrypt(&nonce, Payload { msg: sealed, aad }).map_err(|_| CryptoStatus::AuthFailed)
        }
        2 => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoStatus::Fallback)?;
            cipher.decrypt(&nonce, Payload { msg: sealed, aad }).map_err(|_| CryptoStatus::AuthFailed)
        }
        _ => Err(CryptoStatus::Fallback),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST SP 800-38D test case 2 (16-byte all-zero AES-128-GCM key/nonce/plaintext, empty
    /// AAD), also HostAbiMap §11's cross-implementation vector for AES-GCM.
    #[test]
    fn nist_aes128_gcm_zero_vector() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let mut buffer = [0u8; 32];

        aead_seal(1, &key, &nonce, &[], &mut buffer, 16).expect("seal");
        assert_eq!(hex::encode(&buffer[..16]), "0388dace60b6a392f328c2b971b2fe78");
        assert_eq!(hex::encode(&buffer[16..]), "ab6e47d42cec13bdf53a67b21257bddf");

        aead_open(1, &key, &nonce, &[], &mut buffer, 16).expect("open");
        assert_eq!(&buffer[..16], &[0u8; 16]);
    }

    #[test]
    fn fallback_on_unsupported_algorithm() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let mut buffer = [0u8; 32];
        assert_eq!(aead_seal(9, &key, &nonce, &[], &mut buffer, 16), Err(CryptoStatus::Fallback));
    }

    #[test]
    fn fallback_on_wrong_key_length() {
        let key = [0u8; 15];
        let nonce = [0u8; 12];
        let mut buffer = [0u8; 32];
        assert_eq!(aead_seal(1, &key, &nonce, &[], &mut buffer, 16), Err(CryptoStatus::Fallback));
    }

    #[test]
    fn fallback_on_wrong_nonce_length() {
        let key = [0u8; 16];
        let nonce = [0u8; 11];
        let mut buffer = [0u8; 32];
        assert_eq!(aead_seal(1, &key, &nonce, &[], &mut buffer, 16), Err(CryptoStatus::Fallback));
    }

    #[test]
    fn auth_failed_on_tampered_ciphertext() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let mut buffer = [0u8; 32];
        aead_seal(1, &key, &nonce, &[], &mut buffer, 16).expect("seal");
        buffer[0] ^= 0xFF;
        assert_eq!(aead_open(1, &key, &nonce, &[], &mut buffer, 16), Err(CryptoStatus::AuthFailed));
    }
}

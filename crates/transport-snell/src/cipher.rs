//! The Snell AEAD ciphers and their key derivation.

use std::fmt;

use aes::cipher::KeyInit as _;
use aes::Aes192;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{AeadInOut, Nonce, Tag};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey};

use murmur_transport_shadowsocks::shadowaead::cipher::{Aead, Cipher};

/// AES-192-GCM; the `aes-gcm` crate aliases only 128 and 256.
type Aes192Gcm = aes_gcm::AesGcm<Aes192, aes_gcm::aead::consts::U12>;

/// The GCM nonce and tag sizes, which ChaCha20-Poly1305 shares.
const TAG_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;

/// The key-size error reported for an unknown AES key length.
fn aes_key_size_error(size: usize) -> anyhow::Error {
    anyhow!("invalid key size {size}")
}

/// Which AEAD's error strings a [`TaggedAead`] reports.
#[derive(Debug, Clone, Copy)]
enum AeadKind {
    Gcm,
    Chacha,
}

/// An AEAD wrapper that appends the Poly1305 tag and reports errors tagged with the algorithm
/// that produced them.
#[derive(Debug)]
struct TaggedAead<C> {
    cipher: C,
    kind: AeadKind,
}

fn tagged_seal<C>(
    cipher: &C,
    dst: &mut Vec<u8>,
    nonce: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
    nonce_error: &str,
    too_large_error: &str,
) -> Result<()>
where
    C: AeadInOut<TagSize = U16>,
{
    let nonce = Nonce::<C>::try_from(nonce).map_err(|_| anyhow!("{nonce_error}"))?;
    let start = dst.len();
    dst.extend_from_slice(plaintext);
    let (_, plaintext_out) = dst.split_at_mut(start);
    let tag = cipher
        .encrypt_inout_detached(&nonce, additional_data, plaintext_out.into())
        .map_err(|_| anyhow!("{too_large_error}"))?;
    dst.extend_from_slice(&tag);
    Ok(())
}

fn tagged_open<C>(
    cipher: &C,
    nonce: &[u8],
    ciphertext: &[u8],
    additional_data: &[u8],
    nonce_error: &str,
    auth_error: &str,
) -> Result<Vec<u8>>
where
    C: AeadInOut<TagSize = U16>,
{
    let nonce = Nonce::<C>::try_from(nonce).map_err(|_| anyhow!("{nonce_error}"))?;
    if ciphertext.len() < TAG_SIZE {
        return Err(anyhow!("{auth_error}"));
    }
    let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - TAG_SIZE);
    let tag = Tag::<C>::try_from(tag).map_err(|_| anyhow!("{auth_error}"))?;
    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_inout_detached(&nonce, additional_data, (&mut plaintext[..]).into(), &tag)
        .map_err(|_| anyhow!("{auth_error}"))?;
    Ok(plaintext)
}

impl<C> Aead for TaggedAead<C>
where
    C: AeadInOut<TagSize = U16> + Send + Sync + fmt::Debug,
{
    fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    fn overhead(&self) -> usize {
        TAG_SIZE
    }

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> Result<()> {
        match self.kind {
            AeadKind::Gcm => tagged_seal(
                &self.cipher,
                dst,
                nonce,
                plaintext,
                additional_data,
                "incorrect nonce length for GCM",
                "cipher: message too large for GCM",
            ),
            AeadKind::Chacha => tagged_seal(
                &self.cipher,
                dst,
                nonce,
                plaintext,
                additional_data,
                "chacha20poly1305: bad nonce length passed to Seal",
                "chacha20poly1305: plaintext too large",
            ),
        }
    }

    fn open(&self, nonce: &[u8], ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>> {
        match self.kind {
            AeadKind::Gcm => tagged_open(
                &self.cipher,
                nonce,
                ciphertext,
                additional_data,
                "incorrect nonce length for GCM",
                "cipher: message authentication failed",
            ),
            AeadKind::Chacha => tagged_open(
                &self.cipher,
                nonce,
                ciphertext,
                additional_data,
                "chacha20poly1305: bad nonce length passed to Open",
                "chacha20poly1305: message authentication failed",
            ),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SnellCipher {
    psk: Vec<u8>,
    key_size: usize,
    make_aead: fn(&[u8]) -> Result<Box<dyn Aead>>,
}

impl Cipher for SnellCipher {
    fn key_size(&self) -> usize {
        self.key_size
    }

    fn salt_size(&self) -> usize {
        16
    }

    fn encrypter(&self, salt: &[u8]) -> Result<Box<dyn Aead>> {
        (self.make_aead)(&snell_kdf(&self.psk, salt, self.key_size)?)
    }

    fn decrypter(&self, salt: &[u8]) -> Result<Box<dyn Aead>> {
        (self.make_aead)(&snell_kdf(&self.psk, salt, self.key_size)?)
    }
}

/// The snell KDF: argon2id over the psk and salt, 3 passes, 8 KiB, 1 lane, a 32-byte output
/// truncated to the key size.
pub(crate) fn snell_kdf(psk: &[u8], salt: &[u8], key_size: usize) -> Result<Vec<u8>> {
    let params = Params::new(8, 3, 1, Some(32)).map_err(|err| anyhow!("argon2: {err}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(psk, salt, &mut key).map_err(|err| anyhow!("argon2: {err}"))?;
    let key = key.get(..key_size).ok_or_else(|| aes_key_size_error(key_size))?;
    Ok(key.to_vec())
}

pub(crate) fn aes_gcm(key: &[u8]) -> Result<Box<dyn Aead>> {
    let aead: Box<dyn Aead> = match key.len() {
        16 => Box::new(TaggedAead {
            cipher: Aes128Gcm::new_from_slice(key).map_err(|_| aes_key_size_error(key.len()))?,
            kind: AeadKind::Gcm,
        }),
        24 => Box::new(TaggedAead {
            cipher: Aes192Gcm::new_from_slice(key).map_err(|_| aes_key_size_error(key.len()))?,
            kind: AeadKind::Gcm,
        }),
        32 => Box::new(TaggedAead {
            cipher: Aes256Gcm::new_from_slice(key).map_err(|_| aes_key_size_error(key.len()))?,
            kind: AeadKind::Gcm,
        }),
        l => return Err(aes_key_size_error(l)),
    };
    Ok(aead)
}

pub(crate) fn chacha20poly1305_new(key: &[u8]) -> Result<Box<dyn Aead>> {
    let key = ChaChaKey::try_from(key).map_err(|_| anyhow!("chacha20poly1305: bad key length"))?;
    Ok(Box::new(TaggedAead { cipher: ChaCha20Poly1305::new(&key), kind: AeadKind::Chacha }))
}

#[must_use]
pub fn new_aes128gcm(psk: &[u8]) -> Box<dyn Cipher> {
    Box::new(SnellCipher { psk: psk.to_vec(), key_size: 16, make_aead: aes_gcm })
}

#[must_use]
pub fn new_chacha20poly1305(psk: &[u8]) -> Box<dyn Cipher> {
    Box::new(SnellCipher { psk: psk.to_vec(), key_size: 32, make_aead: chacha20poly1305_new })
}

#[cfg(test)]
mod tests {
    use super::snell_kdf;

    /// Known-answer test against an independently computed argon2id derivation;
    /// pins the argon2 crate's output bytes across the 0.5 -> 0.6 upgrade against the
    /// wire-visible key derivation it must match.
    #[test]
    fn test_snell_kdf_matches_argon2_id_key_vector() {
        let psk = b"test-password-snell-kat";
        let salt = b"fixed-salt-16by!";
        let expected = "d1eefca0925709131efc21639ca7ce4f8118ec01bf4c85879319744863ecb9dc";

        let key = match snell_kdf(psk, salt, 32) {
            Ok(key) => key,
            Err(err) => panic!("{err}"),
        };
        assert_eq!(hex::encode(&key), expected);

        let key16 = match snell_kdf(psk, salt, 16) {
            Ok(key) => key,
            Err(err) => panic!("{err}"),
        };
        assert_eq!(hex::encode(&key16), &expected[..32]);
    }
}

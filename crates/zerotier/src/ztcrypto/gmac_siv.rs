//! ZeroTier's AES-GMAC-SIV peer-packet protection.
//!
//! For a 48-byte shared secret `K`, an 8-byte packet IV, AAD `A` and plaintext
//! `P` this reproduces ZeroTierOne's `AES::GMACSIVEncryptor`:
//!
//! ```text
//! K0, K1 = KBKDF-HMAC-SHA-384(K, "ZT0"), (..., "ZT1")
//! T      = GMAC-K0(IV || 0^32, pad16(A) || P)
//! S      = IV || (T[0:8] XOR T[8:16])
//! O      = AES-K1(S)
//! C      = AES-CTR-K1(maskBit(O), P)
//! ```
//!
//! The 16-byte `O` replaces the packet's IV and MAC fields. This is not
//! AES-GCM-SIV (RFC 8452) and must not be used as a general-purpose AEAD; the
//! XOR fold leaves a 64-bit authenticator, so the forgery bound is 64 bits.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::Aes256;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha384;

const MASTER_KEY_SIZE: usize = 48;
const AES_KEY_SIZE: usize = 32;
const IV_SIZE: usize = 8;
pub const OPAQUE_SIZE: usize = 16;
const FOLDED_TAG_SIZE: usize = 8;

type HmacSha384 = Hmac<Sha384>;

/// Expanded AES keys for one ZeroTier peer secret.
///
/// Construct once when the peer is learned and reuse for every packet, as
/// ZeroTierOne does. The struct owns a packet-sized scratch buffer, so keep it
/// behind a mutex rather than sharing `&GmacSivKeys` across tasks.
pub struct GmacSivKeys {
    authentication: Aes256Gcm,
    encryption: Aes256,
    scratch: Vec<u8>,
    nonce: [u8; 12],
    tag: [u8; OPAQUE_SIZE],
}

impl core::fmt::Debug for GmacSivKeys {
    /// Key material is a bearer credential and never reaches a log line.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("GmacSivKeys")
    }
}

impl GmacSivKeys {
    /// Derives the AES-GMAC-SIV keys for a ZeroTier peer secret.
    pub fn new(key: &[u8]) -> Result<Self, InvalidGmacSiv> {
        let (k0, k1) = derive_keys(key)?;
        Ok(Self {
            authentication: Aes256Gcm::new((&k0).into()),
            encryption: Aes256::new((&k1).into()),
            scratch: Vec::new(),
            nonce: [0u8; 12],
            tag: [0u8; OPAQUE_SIZE],
        })
    }

    /// Authenticates and encrypts `plaintext`, returning the ciphertext and the
    /// detached opaque value that replaces the packet IV and MAC fields.
    pub fn seal(
        &mut self,
        iv: &[u8; IV_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<([u8; OPAQUE_SIZE], Vec<u8>), InvalidGmacSiv> {
        let tag = self.gmac(*iv, aad, plaintext)?;
        let mut synthetic = [0u8; OPAQUE_SIZE];
        synthetic[..IV_SIZE].copy_from_slice(iv);
        let (low, high) = tag.split_at(FOLDED_TAG_SIZE);
        for (folded, (low_byte, high_byte)) in synthetic[IV_SIZE..].iter_mut().zip(low.iter().zip(high.iter())) {
            *folded = low_byte ^ high_byte;
        }
        let mut opaque = [0u8; OPAQUE_SIZE];
        encrypt_block(&self.encryption, &mut opaque, &synthetic);

        let mut ctr = opaque;
        ctr[12] &= 0x7f;
        let mut ciphertext = plaintext.to_vec();
        apply_keystream(&self.encryption, &ctr, &mut ciphertext);
        Ok((opaque, ciphertext))
    }

    /// Authenticates and decrypts `ciphertext`. The plaintext is zeroed and
    /// `Err` returned when the authenticator does not match.
    pub fn open(
        &mut self,
        opaque: &[u8; OPAQUE_SIZE],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, InvalidGmacSiv> {
        let mut synthetic = [0u8; OPAQUE_SIZE];
        decrypt_block(&self.encryption, &mut synthetic, opaque);

        let mut ctr = *opaque;
        ctr[12] &= 0x7f;
        let mut plaintext = ciphertext.to_vec();
        apply_keystream(&self.encryption, &ctr, &mut plaintext);

        let mut iv = [0u8; IV_SIZE];
        iv.copy_from_slice(&synthetic[..IV_SIZE]);
        let tag = self.gmac(iv, aad, &plaintext)?;

        let (low, high) = tag.split_at(FOLDED_TAG_SIZE);
        let mut mismatch = 0u8;
        for (low_byte, (high_byte, check)) in low.iter().zip(high.iter().zip(synthetic[IV_SIZE..].iter())) {
            mismatch |= (low_byte ^ high_byte) ^ check;
        }
        if mismatch != 0 {
            plaintext.fill(0);
            return Err(InvalidGmacSiv);
        }
        Ok(plaintext)
    }

    /// GMAC over block-padded AAD followed by the plaintext. ZeroTier builds
    /// J0 as the 64-bit packet IV plus four zero bytes, which is exactly the
    /// 96-bit GCM nonce `IV || 0x00000001` that J0 expands to, so AES-GCM over
    /// this combined input with an empty message yields the same tag.
    fn gmac(&mut self, iv: [u8; IV_SIZE], aad: &[u8], plaintext: &[u8]) -> Result<[u8; OPAQUE_SIZE], InvalidGmacSiv> {
        self.nonce[..IV_SIZE].copy_from_slice(&iv);

        let padded_aad = aad.len().next_multiple_of(16);
        let total = padded_aad + plaintext.len();
        if self.scratch.len() < total {
            self.scratch.resize(total, 0);
        }
        let input = self.scratch.get_mut(..total).ok_or(InvalidGmacSiv)?;
        let (aad_part, rest) = input.split_at_mut(aad.len());
        let (padding, message) = rest.split_at_mut(padded_aad - aad.len());
        aad_part.copy_from_slice(aad);
        padding.fill(0);
        message.copy_from_slice(plaintext);

        let nonce = Nonce::try_from(&self.nonce[..]).map_err(|_| InvalidGmacSiv)?;
        let sealed =
            self.authentication.encrypt(&nonce, Payload { msg: &[], aad: input }).map_err(|_| InvalidGmacSiv)?;
        self.tag.copy_from_slice(&sealed);
        Ok(self.tag)
    }
}

/// Reports malformed input or a failed authenticator check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ZeroTier AES-GMAC-SIV data")]
pub struct InvalidGmacSiv;

fn encrypt_block(cipher: &Aes256, out: &mut [u8; 16], block: &[u8; 16]) {
    out.copy_from_slice(block);
    cipher.encrypt_block((&mut *out).into());
}

fn decrypt_block(cipher: &Aes256, out: &mut [u8; 16], block: &[u8; 16]) {
    out.copy_from_slice(block);
    cipher.decrypt_block((&mut *out).into());
}

/// AES-CTR over the full 128-bit big-endian counter, with a 16-byte IV.
fn apply_keystream(cipher: &Aes256, iv: &[u8; OPAQUE_SIZE], data: &mut [u8]) {
    let mut counter = *iv;
    let mut keystream = [0u8; OPAQUE_SIZE];
    for chunk in data.chunks_mut(OPAQUE_SIZE) {
        encrypt_block(cipher, &mut keystream, &counter);
        for (byte, mask) in chunk.iter_mut().zip(keystream.iter()) {
            *byte ^= mask;
        }
        for byte in counter.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
}

/// ZeroTier's SP 800-108 counter-mode KBKDF input:
/// `[iteration=0]_32 || "ZT" || label || 0 || context=0 || [L=384]_32`.
fn derive_keys(key: &[u8]) -> Result<([u8; AES_KEY_SIZE], [u8; AES_KEY_SIZE]), InvalidGmacSiv> {
    if key.len() < MASTER_KEY_SIZE {
        return Err(InvalidGmacSiv);
    }
    let mut k0 = [0u8; AES_KEY_SIZE];
    let mut k1 = [0u8; AES_KEY_SIZE];
    for (label, out) in [(b'0', &mut k0), (b'1', &mut k1)] {
        let mut message = [0u8; 13];
        message[0..4].copy_from_slice(&0u32.to_be_bytes());
        message[4] = b'Z';
        message[5] = b'T';
        message[6] = label;
        message[9..13].copy_from_slice(&384u32.to_be_bytes());

        let master_key = key.get(..MASTER_KEY_SIZE).ok_or(InvalidGmacSiv)?;
        let mut mac = <HmacSha384 as KeyInit>::new_from_slice(master_key).map_err(|_| InvalidGmacSiv)?;
        mac.update(&message);
        let digest = mac.finalize().into_bytes();
        for (slot, byte) in out.iter_mut().zip(digest.iter()) {
            *slot = *byte;
        }
    }
    Ok((k0, k1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sequential_key() -> [u8; MASTER_KEY_SIZE] {
        let mut key = [0u8; MASTER_KEY_SIZE];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        key
    }

    #[test]
    fn matches_official_vector() {
        let keys = &mut GmacSivKeys::new(&sequential_key()).unwrap();
        let iv: [u8; IV_SIZE] = [0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe];
        let aad = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x40, 0x55, 0x60];
        let plaintext = b"official-vector-payload";
        let want_opaque =
            [0xc1, 0xfd, 0x36, 0xf7, 0x7e, 0xc5, 0x87, 0xd7, 0x86, 0x05, 0xd0, 0x45, 0xa4, 0x5b, 0x11, 0xda];
        let want_ciphertext = hex::decode(concat!("8ddf8464da15909c5bf102d97df4060395", "7e063616de49",)).unwrap();

        let (opaque, ciphertext) = keys.seal(&iv, plaintext, &aad).unwrap();
        assert_eq!(opaque, want_opaque);
        assert_eq!(ciphertext, want_ciphertext);
        assert_eq!(keys.open(&opaque, &ciphertext, &aad).unwrap(), plaintext);
    }

    #[test]
    fn round_trips_and_rejects_tampering() {
        let key = sequential_key();
        let iv: [u8; IV_SIZE] = [0, 1, 2, 3, 4, 5, 6, 7];
        let aad = b"header-data";
        let plaintext = b"ZeroTier AES-GMAC-SIV test payload";
        let keys = &mut GmacSivKeys::new(&key).unwrap();

        let (opaque, ciphertext) = keys.seal(&iv, plaintext, aad).unwrap();
        assert_eq!(keys.open(&opaque, &ciphertext, aad).unwrap(), plaintext);
        assert_ne!(ciphertext, plaintext);

        let (opaque_again, ciphertext_again) = keys.seal(&iv, plaintext, aad).unwrap();
        assert_eq!(opaque_again, opaque);
        assert_eq!(ciphertext_again, ciphertext);

        let mut tampered = ciphertext.clone();
        tampered[0] ^= 1;
        assert!(keys.open(&opaque, &tampered, aad).is_err());

        let mut tampered_opaque = opaque;
        tampered_opaque[0] ^= 1;
        assert!(keys.open(&tampered_opaque, &ciphertext, aad).is_err());

        let mut tampered_aad = aad.to_vec();
        tampered_aad[0] ^= 1;
        assert!(keys.open(&opaque, &ciphertext, &tampered_aad).is_err());

        let mut wrong_key = key;
        wrong_key[0] ^= 1;
        let wrong = &mut GmacSivKeys::new(&wrong_key).unwrap();
        assert!(wrong.open(&opaque, &ciphertext, aad).is_err());
    }

    #[test]
    fn rejects_short_master_key() {
        let short = [0u8; MASTER_KEY_SIZE - 1];
        assert!(GmacSivKeys::new(&short).is_err());
    }
}

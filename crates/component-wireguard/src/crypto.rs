//! WireGuard's noise primitives: `HASH`, `MAC`, the `KDF_n` family and the transport AEAD,
//! implementing the protocol's byte-for-byte definitions.

use anyhow::{anyhow, Result};
use blake2::digest::consts::U16;
use blake2::digest::{Digest, FixedOutput, KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac};
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::ChaCha20Poly1305;

pub const HASH_SIZE: usize = 32;
pub const MAC_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub const TAG_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;
const BLOCK_SIZE: usize = 64;
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: &[u8] = b"mac1----";
pub const LABEL_COOKIE: &[u8] = b"cookie--";

#[must_use]
pub fn hash(input: &[u8]) -> [u8; HASH_SIZE] {
    Blake2s256::digest(input).into()
}

/// Mixes data into the hash: `HASH(h || data)`.
#[must_use]
pub fn mix_hash(h: &[u8; HASH_SIZE], data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Blake2s256::new();
    hasher.update(h);
    hasher.update(data);
    hasher.finalize().into()
}

/// Mixes data into the chain key: `KDF1(chainKey, data)`.
#[must_use]
pub fn mix_key(chain_key: &[u8; HASH_SIZE], data: &[u8]) -> [u8; HASH_SIZE] {
    kdf1(chain_key, data)
}

/// `HMAC1`/`HMAC2`: HMAC-BLAKE2s-256 over `parts` concatenated.
fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; HASH_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        block[..HASH_SIZE].copy_from_slice(&hash(key));
    } else {
        for (slot, byte) in block.iter_mut().zip(key) {
            *slot = *byte;
        }
    }
    let (mut inner_key, mut outer_key) = ([0u8; BLOCK_SIZE], [0u8; BLOCK_SIZE]);
    for ((inner, outer), byte) in inner_key.iter_mut().zip(outer_key.iter_mut()).zip(block) {
        *inner = byte ^ 0x36;
        *outer = byte ^ 0x5c;
    }

    let mut inner = Blake2s256::new();
    inner.update(inner_key);
    for part in parts {
        inner.update(part);
    }
    let inner: [u8; HASH_SIZE] = inner.finalize().into();

    let mut outer = Blake2s256::new();
    outer.update(outer_key);
    outer.update(inner);
    outer.finalize().into()
}

#[must_use]
pub fn kdf1(key: &[u8; HASH_SIZE], input: &[u8]) -> [u8; HASH_SIZE] {
    hmac(&hmac(key, &[input]), &[&[0x01]])
}

/// `KDF2`: `prk = HMAC(key, input)`, `t0 = HMAC(prk, 0x01)`, `t1 = HMAC(prk, t0 || 0x02)`.
#[must_use]
pub fn kdf2(key: &[u8; HASH_SIZE], input: &[u8]) -> ([u8; HASH_SIZE], [u8; HASH_SIZE]) {
    let prk = hmac(key, &[input]);
    let t0 = hmac(&prk, &[&[0x01]]);
    (t0, hmac(&prk, &[&t0, &[0x02]]))
}

/// `KDF3`: adds `t2 = HMAC(prk, t1 || 0x03)`.
#[must_use]
pub fn kdf3(key: &[u8; HASH_SIZE], input: &[u8]) -> ([u8; HASH_SIZE], [u8; HASH_SIZE], [u8; HASH_SIZE]) {
    let prk = hmac(key, &[input]);
    let t0 = hmac(&prk, &[&[0x01]]);
    let t1 = hmac(&prk, &[&t0, &[0x02]]);
    (t0, t1, hmac(&prk, &[&t1, &[0x03]]))
}

/// The keyed 16-byte MAC behind `mac1`/`mac2`. BLAKE2s caps the
/// key at 32 bytes, which is also the length of every key WireGuard derives.
pub fn mac(key: &[u8], data: &[u8]) -> Result<[u8; MAC_SIZE]> {
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(key)
        .map_err(|_| anyhow!("blake2s-128 key must not exceed 32 bytes"))?;
    mac.update(data);
    Ok(mac.finalize_fixed().into())
}

/// The initial chain key: a hash of the construction string.
#[must_use]
pub fn initial_chain_key() -> [u8; HASH_SIZE] {
    hash(CONSTRUCTION)
}

#[must_use]
pub fn initial_hash() -> [u8; HASH_SIZE] {
    mix_hash(&initial_chain_key(), IDENTIFIER)
}

/// The `mac1` key derived from the responder's static public key.
#[must_use]
pub fn mac1_key(responder_static: &[u8; 32]) -> [u8; HASH_SIZE] {
    let mut hasher = Blake2s256::new();
    hasher.update(LABEL_MAC1);
    hasher.update(responder_static);
    hasher.finalize().into()
}

/// The `mac2` encryption key derived from the responder's static public key.
#[must_use]
pub fn mac2_key(responder_static: &[u8; 32]) -> [u8; HASH_SIZE] {
    let mut hasher = Blake2s256::new();
    hasher.update(LABEL_COOKIE);
    hasher.update(responder_static);
    hasher.finalize().into()
}

/// ChaCha20-Poly1305 with the 12-byte nonce WireGuard uses.
#[derive(Clone)]
pub struct Aead(ChaCha20Poly1305);

impl core::fmt::Debug for Aead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Aead").finish_non_exhaustive()
    }
}

impl Aead {
    #[must_use]
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        use chacha20poly1305::KeyInit as _;
        #[expect(clippy::expect_used, reason = "the key type is exactly 32 bytes, so the constructor cannot fail")]
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("a 32-byte array is a valid chacha20poly1305 key");
        Self(cipher)
    }

    pub fn seal(&self, nonce: &[u8; NONCE_SIZE], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.0.encrypt(nonce.into(), Payload { msg: plaintext, aad }).map_err(|_| anyhow!("sealing failed"))
    }

    pub fn open(&self, nonce: &[u8; NONCE_SIZE], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.0
            .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
            .map_err(|_| anyhow!("message authentication failed"))
    }
}

/// The transport nonce: four zero bytes then the counter, little-endian.
#[must_use]
pub fn transport_nonce(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

#[must_use]
pub fn tai64n_now(now: std::time::SystemTime) -> [u8; 12] {
    const BASE: u64 = 0x4000_0000_0000_000a;
    const WHITENER_MASK: u32 = 0x100_0000 - 1;
    let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let mut stamp = [0u8; 12];
    stamp[..8].copy_from_slice(&(BASE + since_epoch.as_secs()).to_be_bytes());
    stamp[8..].copy_from_slice(&(since_epoch.subsec_nanos() & !WHITENER_MASK).to_be_bytes());
    stamp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(input: &str) -> Vec<u8> {
        (0..input.len()).step_by(2).map(|i| u8::from_str_radix(&input[i..i + 2], 16).expect("hex literal")).collect()
    }

    fn key32(input: &str) -> [u8; 32] {
        hex(input).try_into().expect("32-byte hex literal")
    }

    #[test]
    fn hash_matches_blake2s_vectors() {
        assert_eq!(hash(b"").to_vec(), hex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"));
        assert_eq!(hash(b"abc").to_vec(), hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"));
    }

    #[test]
    fn keyed_mac_matches_blake2s_keyed_vector() {
        let key: Vec<u8> = (0..32u8).collect();
        assert_eq!(mac(&key, b"").expect("32-byte key").to_vec(), hex("9536f9b267655743dee97b8a670f9f53"));
        assert!(mac(&[0u8; 33], b"").is_err());
    }

    #[test]
    fn mac1_matches_the_reference_construction() {
        let key = mac1_key(&[0u8; 32]);
        assert_eq!(key.to_vec(), hex("d84d593e94aac535d9107d24b9e4576f12a1d0c96b630c2961edee4259e3e3c5"));
        assert_eq!(mac(&key, b"").expect("mac1").to_vec(), hex("821f339ff1d8f56ea4a382e25b89c631"));
    }

    #[test]
    fn aead_matches_rfc8439_vector() {
        let nonce: [u8; 12] = hex("070000004041424344454647").try_into().expect("12-byte nonce");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aead = Aead::new(&key32("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"));
        let sealed = aead.seal(&nonce, &aad, plaintext).expect("seal");
        assert_eq!(
            sealed,
            hex(concat!(
                "d31a8d34648e60db7b86afbc53ef7ec2",
                "a4aded51296e08fea9e2b5a736ee62d6",
                "3dbea45e8ca9671282fafb69da92728b",
                "1a71de0a9e060b2905d6a5b67ecd3b36",
                "92ddbd7f2d778b8c9803aee328091b58",
                "fab324e4fad675945585808b4831d7bc",
                "3ff4def08e4b7a9de576d26586cec64b6116",
                "1ae10b594f09e26a7e902ecbd0600691"
            ))
        );
        assert_eq!(aead.open(&nonce, &aad, &sealed).expect("open"), plaintext.to_vec());

        let mut tampered = sealed;
        tampered[0] ^= 1;
        assert!(aead.open(&nonce, &aad, &tampered).is_err());
    }

    #[test]
    fn initial_state_is_the_documented_construction() {
        assert_eq!(initial_chain_key(), hash(CONSTRUCTION));
        assert_eq!(initial_hash(), mix_hash(&initial_chain_key(), IDENTIFIER));
        assert_ne!(initial_chain_key(), initial_hash());
    }

    #[test]
    fn kdf_outputs_depend_on_input_and_role() {
        let key = [7u8; HASH_SIZE];
        let (a, b) = kdf2(&key, b"dh");
        let (c, d) = kdf2(&key, b"dh2");
        assert_ne!(a, c);
        assert_ne!(a, b);
        assert_ne!(d, c);
        let (e, f, g) = kdf3(&key, b"dh");
        assert_eq!((a, b), (e, f));
        assert_ne!(g, f);
    }

    #[test]
    fn mac_keys_depend_on_the_peer_static() {
        let first = mac1_key(&[1u8; 32]);
        assert_ne!(first, mac1_key(&[2u8; 32]));
        assert_ne!(first, mac2_key(&[1u8; 32]));
    }

    #[test]
    fn tai64n_is_big_endian_and_strictly_increasing() {
        let stamp = tai64n_now(std::time::SystemTime::UNIX_EPOCH);
        assert_eq!(stamp[..8], 0x4000_0000_0000_000au64.to_be_bytes());
        let later = tai64n_now(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1));
        assert!(later > stamp);
    }

    #[test]
    fn transport_nonce_is_four_zero_bytes_then_the_counter() {
        assert_eq!(transport_nonce(1), [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
    }
}

//! The `tls-crypt` control-channel wrapper: encrypting and authenticating control packets
//! under a static key.

use std::fmt;

use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{bail, Result};
use ctr::Ctr128BE;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::packet::ControlCryptor;

pub const TLS_CRYPT_HEADER_SIZE: usize = 1 + 8;
pub const TLS_CRYPT_PID_SIZE: usize = 4 + 4;
pub const TLS_CRYPT_TAG_SIZE: usize = 32;

pub(crate) const STATIC_KEY_SIZE: usize = 256;
pub(crate) const KEY_SLOT_SIZE: usize = 128;
pub(crate) const CIPHER_KEY_SIZE: usize = 32;
pub(crate) const HMAC_KEY_SIZE: usize = 32;

const AES_BLOCK_SIZE: usize = 16;
const HMAC_KEY_OFFSET: usize = 64;

type Aes256Ctr = Ctr128BE<aes::Aes256>;

#[expect(
    clippy::struct_field_names,
    reason = "each field names which half of OpenVPN's `struct key` it holds; the shared `_key` suffix is the protocol's term"
)]
pub struct TLSCrypt {
    pub(crate) encrypt_cipher_key: Vec<u8>,
    pub(crate) encrypt_hmac_key: Vec<u8>,
    pub(crate) decrypt_cipher_key: Vec<u8>,
    pub(crate) decrypt_hmac_key: Vec<u8>,
}

impl fmt::Debug for TLSCrypt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TLSCrypt").finish_non_exhaustive()
    }
}

impl TLSCrypt {
    #[expect(clippy::unused_self, reason = "kept as a method so `wrap`/`unwrap` read as one wrapper's operations")]
    #[expect(clippy::expect_used, reason = "HMAC accepts a key of any length, so `new_from_slice` cannot fail")]
    pub(crate) fn hmac(&self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().to_vec()
    }
}

pub fn new_tls_crypt(static_key: &[u8], client: bool) -> Result<TLSCrypt> {
    if static_key.len() != STATIC_KEY_SIZE {
        bail!("invalid tls-crypt static key length {}, expected {}", static_key.len(), STATIC_KEY_SIZE);
    }

    let (key0, key1) = static_key.split_at(KEY_SLOT_SIZE);

    let (encrypt, decrypt) = if client { (key1, key0) } else { (key0, key1) };
    let (encrypt_cipher_key, encrypt_hmac_key) = key_slot(encrypt);
    let (decrypt_cipher_key, decrypt_hmac_key) = key_slot(decrypt);

    Ok(TLSCrypt {
        encrypt_cipher_key: clone_bytes(encrypt_cipher_key),
        encrypt_hmac_key: clone_bytes(encrypt_hmac_key),
        decrypt_cipher_key: clone_bytes(decrypt_cipher_key),
        decrypt_hmac_key: clone_bytes(decrypt_hmac_key),
    })
}

/// One `KEY_SLOT_SIZE` key slot as its `CIPHER_KEY_SIZE` cipher key and the HMAC key at
/// `HMAC_KEY_OFFSET`.
#[expect(
    clippy::indexing_slicing,
    reason = "both ranges are fixed offsets inside a `KEY_SLOT_SIZE` slot, which `new_tls_crypt` has already checked the static key against"
)]
fn key_slot(slot: &[u8]) -> (&[u8], &[u8]) {
    (&slot[..CIPHER_KEY_SIZE], &slot[HMAC_KEY_OFFSET..HMAC_KEY_OFFSET + HMAC_KEY_SIZE])
}

impl ControlCryptor for TLSCrypt {
    fn wrap(&self, header: &[u8], packet_id: u32, unix_time: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        if header.len() != TLS_CRYPT_HEADER_SIZE {
            bail!("invalid tls-crypt header length {}, expected {}", header.len(), TLS_CRYPT_HEADER_SIZE);
        }

        let mut ad = Vec::with_capacity(header.len() + TLS_CRYPT_PID_SIZE);
        ad.extend_from_slice(header);
        ad.extend_from_slice(&packet_id.to_be_bytes());
        ad.extend_from_slice(&unix_time.to_be_bytes());

        let tag = self.hmac(&self.encrypt_hmac_key, &[&ad, plaintext]);
        let ciphertext = aes256ctr(&self.encrypt_cipher_key, aes_block(&tag), plaintext)?;

        let mut out = Vec::with_capacity(ad.len() + tag.len() + ciphertext.len());
        out.extend_from_slice(&ad);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn unwrap(&self, packet: &[u8]) -> Result<(Vec<u8>, u32, u32, Vec<u8>)> {
        let Some((header, rest)) = packet.split_at_checked(TLS_CRYPT_HEADER_SIZE) else {
            bail!("tls-crypt packet too short");
        };
        let Some(ad) = packet.get(..TLS_CRYPT_HEADER_SIZE + TLS_CRYPT_PID_SIZE) else {
            bail!("tls-crypt packet too short");
        };
        let Some((pid, rest)) = rest.split_at_checked(TLS_CRYPT_PID_SIZE) else {
            bail!("tls-crypt packet too short");
        };
        let Some((tag, ciphertext)) = rest.split_at_checked(TLS_CRYPT_TAG_SIZE) else {
            bail!("tls-crypt packet too short");
        };

        let plaintext = aes256ctr(&self.decrypt_cipher_key, aes_block(tag), ciphertext)?;

        let tag_check = self.hmac(&self.decrypt_hmac_key, &[ad, &plaintext]);
        if tag.ct_eq(&tag_check).unwrap_u8() != 1 {
            bail!("tls-crypt authentication failed");
        }

        let packet_id = be_u32(pid, 0);
        let unix_time = be_u32(pid, 4);
        Ok((clone_bytes(header), packet_id, unix_time, plaintext))
    }
}

pub(crate) fn aes256ctr(key: &[u8], iv: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let key: [u8; 32] = key.try_into().map_err(|_| anyhow::anyhow!("invalid key size {}", key.len()))?;
    let iv: [u8; 16] = iv.try_into().map_err(|_| anyhow::anyhow!("invalid iv size {}", iv.len()))?;
    let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());
    let mut out = clone_bytes(input);
    cipher.apply_keystream(&mut out);
    Ok(out)
}

/// The AES-CTR initialisation vector: the leading block of the HMAC tag.
#[expect(clippy::indexing_slicing, reason = "`TLS_CRYPT_TAG_SIZE` is 32, so the leading 16-byte block always exists")]
fn aes_block(tag: &[u8]) -> &[u8] {
    &tag[..AES_BLOCK_SIZE]
}

pub(crate) fn clone_bytes(input: &[u8]) -> Vec<u8> {
    input.to_vec()
}

#[expect(
    clippy::indexing_slicing,
    reason = "every caller reads a word it has already bounds-checked"
)]
pub(crate) fn be_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_static_key() -> Vec<u8> {
        (0..=255u8).collect()
    }

    #[test]
    fn tls_crypt_client_server_round_trip() {
        let client = new_tls_crypt(&test_static_key(), true).expect("new tls-crypt client");
        let server = new_tls_crypt(&test_static_key(), false).expect("new tls-crypt server");

        let header = vec![0x38, 1, 2, 3, 4, 5, 6, 7, 8];
        let plaintext = b"client hello over openvpn control channel".to_vec();
        let packet = client.wrap(&header, 7, 1_714_567_890, &plaintext).expect("wrap");
        let want = TLS_CRYPT_HEADER_SIZE + TLS_CRYPT_PID_SIZE + TLS_CRYPT_TAG_SIZE + plaintext.len();
        assert_eq!(packet.len(), want, "unexpected tls-crypt packet length: got {}, want {want}", packet.len());
        assert_eq!(
            hex::encode(&packet),
            "3801020304050607080000000766323ad2d9b86357201263af3f72dc776e86bf935b0831c01cacc246ebd897f\
987478d4fcc92dcbba02af2d398f4789f261262e725302defcba25f3538904d5822f9a44f96b71069853658dd76",
        );

        let (got_header, packet_id, unix_time, got_plaintext) = server.unwrap(&packet).expect("unwrap");
        assert_eq!(got_header, header);
        assert!(packet_id == 7 && unix_time == 1_714_567_890, "unexpected packet id/time: {packet_id}/{unix_time}");
        assert_eq!(got_plaintext, plaintext);
    }

    #[test]
    fn tls_crypt_server_client_round_trip() {
        let client = new_tls_crypt(&test_static_key(), true).expect("new tls-crypt client");
        let server = new_tls_crypt(&test_static_key(), false).expect("new tls-crypt server");

        let header = vec![0x40, 8, 7, 6, 5, 4, 3, 2, 1];
        let plaintext = b"server hello over openvpn control channel".to_vec();
        let packet = server.wrap(&header, 9, 1_714_567_900, &plaintext).expect("wrap");
        assert_eq!(
            hex::encode(&packet),
            "4008070605040302010000000966323adccbfcb68bb1326d5a9c821ba0554d0c5bd8642f0a96b055f7f2c3996a\
60580557e3edc6059a8a42da46c92a2e2711de2fe0bf8fa338a77b332d95d340ada9293146ebda316fee9c8c91",
        );

        let (_got_header, packet_id, unix_time, got_plaintext) = client.unwrap(&packet).expect("unwrap");
        assert!(packet_id == 9 && unix_time == 1_714_567_900, "unexpected packet id/time: {packet_id}/{unix_time}");
        assert_eq!(got_plaintext, plaintext);
    }

    #[test]
    fn tls_crypt_rejects_tampered_packet() {
        let client = new_tls_crypt(&test_static_key(), true).expect("new tls-crypt client");
        let server = new_tls_crypt(&test_static_key(), false).expect("new tls-crypt server");

        let mut packet = client.wrap(&[0x38, 1, 2, 3, 4, 5, 6, 7, 8], 7, 1_714_567_890, b"hello").expect("wrap");
        let last = packet.len() - 1;
        packet[last] ^= 0xff;

        assert!(server.unwrap(&packet).is_err(), "expected authentication failure");
    }
}

//! The nested-HMAC chain: every level is HMAC-SHA256, whose digest size (32) and block size (64)
//! stay fixed regardless of nesting depth.
//!
//! Those fixed sizes make the chain a recursive function computing the same bytes rather than a
//! runtime-composed hash type — see [`nested_hmac_sha256`].

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes128Gcm;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub(crate) const KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
pub(crate) const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
pub(crate) const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
pub(crate) const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
pub(crate) const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const KDF_SALT_CONST_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
pub(crate) const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY: &[u8] = b"VMess Header AEAD Key";
pub(crate) const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce";
pub(crate) const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8] = b"VMess Header AEAD Key_Length";
pub(crate) const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce_Length";

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hmac_step(hmac_key: &[u8], data: &[u8], underlying: impl Fn(&[u8]) -> [u8; 32]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;

    let key_block = if hmac_key.len() > BLOCK_SIZE {
        let mut v = underlying(hmac_key).to_vec();
        v.resize(BLOCK_SIZE, 0);
        v
    } else {
        let mut v = hmac_key.to_vec();
        v.resize(BLOCK_SIZE, 0);
        v
    };

    let ipad: Vec<u8> = key_block.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = key_block.iter().map(|b| b ^ 0x5c).collect();

    let mut inner_msg = ipad;
    inner_msg.extend_from_slice(data);
    let inner = underlying(&inner_msg);

    let mut outer_msg = opad;
    outer_msg.extend_from_slice(&inner);
    underlying(&outer_msg)
}

/// The whole nested-HMAC chain folded into one call: `values` is the parent chain from outermost
/// (`values[0]`, the innermost hash's HMAC key) to innermost, and `key` is the message the
/// outermost HMAC hashes.
fn nested_hmac_sha256(values: &[&[u8]], key: &[u8]) -> [u8; 32] {
    match values.split_last() {
        None => sha256_digest(key),
        Some((last, rest)) => hmac_step(last, key, |m| nested_hmac_sha256(rest, m)),
    }
}

pub(crate) fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut values: Vec<&[u8]> = Vec::with_capacity(path.len() + 1);
    values.push(KDF_SALT_CONST_VMESS_AEAD_KDF);
    values.extend_from_slice(path);
    nested_hmac_sha256(&values, key)
}

pub(crate) fn create_auth_id(cmd_key: &[u8], time: i64) -> [u8; 16] {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&time.to_be_bytes());

    let mut random = [0u8; 4];
    rand::rng().fill_bytes(&mut random);
    buf.extend_from_slice(&random);

    let checksum = crc32fast::hash(&buf);
    buf.extend_from_slice(&checksum.to_be_bytes());

    let aes_key = &kdf(cmd_key, &[KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY])[..16];
    #[expect(clippy::expect_used, reason = "`aes_key` is a 16-byte prefix of a KDF digest, matching AES-128")]
    let aes_block = aes::Aes128::new_from_slice(aes_key).expect("16-byte AES-128 key");
    let mut block = [0u8; 16];
    block.copy_from_slice(&buf);
    let mut result = aes::Block::from(block);
    aes_block.encrypt_block(&mut result);
    result.into()
}

pub(crate) fn seal_vmess_aead_header(key: [u8; 16], data: &[u8], t: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
    let generated_auth_id = create_auth_id(&key, t.timestamp());
    let mut connection_nonce = [0u8; 8];
    rand::rng().fill_bytes(&mut connection_nonce);

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the VMess AEAD length field is exactly 2 bytes on the wire, and a request header is far below 64 KiB"
    )]
    let aead_payload_length_serialized_byte = (data.len() as u16).to_be_bytes();

    let payload_header_length_aead_key =
        &kdf(&key, &[KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, &generated_auth_id, &connection_nonce])[..16];
    let payload_header_length_aead_nonce =
        &kdf(&key, &[KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, &generated_auth_id, &connection_nonce])[..12];
    let payload_header_length_aead_encrypted = aes_gcm_seal(
        payload_header_length_aead_key,
        payload_header_length_aead_nonce,
        &aead_payload_length_serialized_byte,
        &generated_auth_id,
    );

    let payload_header_aead_key =
        &kdf(&key, &[KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY, &generated_auth_id, &connection_nonce])[..16];
    let payload_header_aead_nonce =
        &kdf(&key, &[KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, &generated_auth_id, &connection_nonce])[..12];
    let payload_header_aead_encrypted =
        aes_gcm_seal(payload_header_aead_key, payload_header_aead_nonce, data, &generated_auth_id);

    let mut output = Vec::with_capacity(
        generated_auth_id.len()
            + payload_header_length_aead_encrypted.len()
            + connection_nonce.len()
            + payload_header_aead_encrypted.len(),
    );
    output.extend_from_slice(&generated_auth_id);
    output.extend_from_slice(&payload_header_length_aead_encrypted);
    output.extend_from_slice(&connection_nonce);
    output.extend_from_slice(&payload_header_aead_encrypted);
    output
}

#[expect(
    clippy::expect_used,
    reason = "callers pass 16- and 12-byte KDF prefixes; sealing cannot fail for a VMess-sized header"
)]
fn aes_gcm_seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("16-byte AES-128-GCM key");
    cipher
        .encrypt(<&aes_gcm::Nonce<_>>::try_from(nonce).expect("12-byte GCM nonce"), Payload { msg: plaintext, aad })
        .expect("aead seal never fails")
}

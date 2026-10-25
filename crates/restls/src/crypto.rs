//! RFC 8446 §7.1 key schedule (HKDF-Expand-Label) and per-record AEAD.
//!
//! Restricted to the two SHA-256 cipher suites Restls actually needs on the wire:
//! `TLS_AES_128_GCM_SHA256` and `TLS_CHACHA20_POLY1305_SHA256`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as AesNonce};
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChachaNonce};
use hkdf::Hkdf;
use hmac::Mac;
use sha2::{Digest, Sha256, Sha384};

use crate::consts::{CIPHER_SUITE_AES_128_GCM_SHA256, CIPHER_SUITE_CHACHA20_POLY1305_SHA256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    Chacha20Poly1305Sha256,
}

impl CipherSuite {
    #[must_use]
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            CIPHER_SUITE_AES_128_GCM_SHA256 => Some(Self::Aes128GcmSha256),
            CIPHER_SUITE_CHACHA20_POLY1305_SHA256 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => CIPHER_SUITE_AES_128_GCM_SHA256,
            Self::Chacha20Poly1305Sha256 => CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
        }
    }

    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Chacha20Poly1305Sha256 => 32,
        }
    }
}

pub const HASH_LEN: usize = 32;
pub const IV_LEN: usize = 12;

/// RFC 8446 §7.1 `HKDF-Expand-Label`.
#[must_use]
pub fn hkdf_expand_label(secret: &[u8; HASH_LEN], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    #[expect(clippy::cast_possible_truncation, reason = "`length` is a restls key or hash length, at most 32 bytes")]
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    let full_label = format!("tls13 {label}");
    #[expect(clippy::cast_possible_truncation, reason = "the TLS 1.3 labels are short fixed strings")]
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());
    #[expect(clippy::cast_possible_truncation, reason = "the context is a 32-byte transcript hash")]
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    #[expect(clippy::expect_used, reason = "`secret` is a 32-byte SHA-256 PRK, which `from_prk` always accepts")]
    let hk = Hkdf::<Sha256>::from_prk(secret).expect("32-byte PRK is valid for SHA-256 HKDF");
    let mut out = vec![0u8; length];
    #[expect(
        clippy::expect_used,
        reason = "every restls key schedule keeps `length` inside HKDF-Expand's 255-hash-length limit"
    )]
    hk.expand(&hkdf_label, &mut out).expect("length <= 255*32 for every restls key schedule call");
    out
}

#[must_use]
pub fn derive_secret(secret: &[u8; HASH_LEN], label: &str, transcript_hash: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let expanded = hkdf_expand_label(secret, label, transcript_hash, HASH_LEN);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&expanded);
    out
}

#[must_use]
pub fn hkdf_extract(salt: &[u8; HASH_LEN], ikm: &[u8]) -> [u8; HASH_LEN] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

#[must_use]
pub fn empty_hash() -> [u8; HASH_LEN] {
    Sha256::digest([]).into()
}

#[must_use]
pub fn transcript_hash(bytes: &[u8]) -> [u8; HASH_LEN] {
    Sha256::digest(bytes).into()
}

/// A running TLS 1.3 handshake transcript hash (concatenation of every handshake message body,
/// hashed incrementally so the caller doesn't have to retain the whole byte history).
#[derive(Clone, Debug)]
pub struct Transcript(Sha256);

impl Transcript {
    #[must_use]
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    pub fn update(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    #[must_use]
    pub fn hash(&self) -> [u8; HASH_LEN] {
        self.0.clone().finalize().into()
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

/// RFC 8446 §7.2 traffic key/IV derivation.
pub struct TrafficKeys {
    pub key: Vec<u8>,
    pub iv: [u8; IV_LEN],
}

impl core::fmt::Debug for TrafficKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrafficKeys").field("key", &"<redacted>").field("iv", &self.iv).finish_non_exhaustive()
    }
}

#[must_use]
pub fn derive_traffic_keys(suite: CipherSuite, traffic_secret: &[u8; HASH_LEN]) -> TrafficKeys {
    let key = hkdf_expand_label(traffic_secret, "key", &[], suite.key_len());
    let iv_expanded = hkdf_expand_label(traffic_secret, "iv", &[], IV_LEN);
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&iv_expanded);
    TrafficKeys { key, iv }
}

fn per_record_nonce(iv: &[u8; IV_LEN], seq: u64) -> [u8; IV_LEN] {
    let mut nonce = *iv;
    for (byte, seq_byte) in nonce[IV_LEN - 8..].iter_mut().zip(seq.to_be_bytes()) {
        *byte ^= seq_byte;
    }
    nonce
}

/// One direction's AEAD state: fixed key/IV plus the record sequence number, which the caller
/// increments (`record_written`/`record_read`) once per TLS 1.3 record in that direction.
pub struct RecordProtection {
    suite: CipherSuite,
    key: Vec<u8>,
    iv: [u8; IV_LEN],
    seq: u64,
}

impl core::fmt::Debug for RecordProtection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecordProtection")
            .field("suite", &self.suite)
            .field("key", &"<redacted>")
            .field("iv", &self.iv)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl RecordProtection {
    #[must_use]
    pub fn new(suite: CipherSuite, keys: TrafficKeys) -> Self {
        Self { suite, key: keys.key, iv: keys.iv, seq: 0 }
    }

    pub fn advance(&mut self) {
        self.seq += 1;
    }

    /// Encrypts `inner_plaintext` (real content || inner content type || zero padding) into a
    /// full TLSCiphertext record body: `AEAD(key, nonce, plaintext, aad=record_header)`.
    /// `record_header` is the 5-byte `[type=0x17][ver 03 03][len16]` associated data.
    #[expect(
        clippy::expect_used,
        reason = "`self.key` always holds the suite's key length (`derive_traffic_keys` produced it), and a seal only fails past restls's maximum record size"
    )]
    #[must_use]
    pub fn seal(&self, inner_plaintext: &[u8], record_header: &[u8; 5]) -> Vec<u8> {
        let nonce = per_record_nonce(&self.iv, self.seq);
        match self.suite {
            CipherSuite::Aes128GcmSha256 => {
                let cipher = Aes128Gcm::new_from_slice(&self.key).expect("16-byte AES-128 key");
                cipher
                    .encrypt(&AesNonce::from(nonce), Payload { msg: inner_plaintext, aad: record_header })
                    .expect("AES-128-GCM seal never fails for restls-sized records")
            }
            CipherSuite::Chacha20Poly1305Sha256 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key).expect("32-byte ChaCha20 key");
                cipher
                    .encrypt(&ChachaNonce::from(nonce), Payload { msg: inner_plaintext, aad: record_header })
                    .expect("ChaCha20-Poly1305 seal never fails for restls-sized records")
            }
        }
    }

    /// Reverses [`Self::seal`]: `ciphertext` is the record body (ciphertext || 16-byte tag)
    /// exactly as it appeared on the wire, `record_header` its 5-byte AAD.
    pub fn open(&self, ciphertext: &[u8], record_header: &[u8; 5]) -> Result<Vec<u8>> {
        let nonce = per_record_nonce(&self.iv, self.seq);
        let result = match self.suite {
            CipherSuite::Aes128GcmSha256 => {
                let cipher = Aes128Gcm::new_from_slice(&self.key)
                    .map_err(|_| anyhow!("restls: AES-128-GCM key length mismatch"))?;
                cipher.decrypt(&AesNonce::from(nonce), Payload { msg: ciphertext, aad: record_header })
            }
            CipherSuite::Chacha20Poly1305Sha256 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|_| anyhow!("restls: ChaCha20-Poly1305 key length mismatch"))?;
                cipher.decrypt(&ChachaNonce::from(nonce), Payload { msg: ciphertext, aad: record_header })
            }
        };
        result.map_err(|_| anyhow!("restls: AEAD record open failed"))
    }
}

/// Strips the trailing zero padding and inner content-type byte off a decrypted
/// `TLSInnerPlaintext`, returning `(content_type, content)`.
pub fn unpad_inner_plaintext(mut plaintext: Vec<u8>) -> Result<(u8, Vec<u8>)> {
    while plaintext.last() == Some(&0) {
        plaintext.pop();
    }
    let Some(content_type) = plaintext.pop() else {
        bail!("restls: empty TLSInnerPlaintext");
    };
    Ok((content_type, plaintext))
}

/// Builds a `TLSInnerPlaintext`: `content || content_type`, with no padding (Restls's own real
/// handshake records never pad; the vendored fork doesn't either).
#[must_use]
pub fn pad_inner_plaintext(content: &[u8], content_type: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 1);
    out.extend_from_slice(content);
    out.push(content_type);
    out
}

/// RFC 8446 §4.4.4 `finished_key`/`verify_data`.
#[must_use]
pub fn finished_verify_data(traffic_secret: &[u8; HASH_LEN], transcript_hash: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    use hmac::{Hmac, Mac};
    let finished_key_expanded = hkdf_expand_label(traffic_secret, "finished", &[], HASH_LEN);
    let mut finished_key = [0u8; HASH_LEN];
    finished_key.copy_from_slice(&finished_key_expanded);
    #[expect(clippy::expect_used, reason = "HMAC accepts a key of any length, so `new_from_slice` cannot fail")]
    let mut mac = Hmac::<Sha256>::new_from_slice(&finished_key).expect("any key length is valid for HMAC-SHA256");
    mac.update(transcript_hash);
    mac.finalize().into_bytes().into()
}
/// RFC 5246 §5 TLS 1.2 PRF hash. The AES-128 GCM suites use SHA-256; the two
/// AES-256-GCM suites (`0xc030`/`0xc02c`) use SHA-384 (RFC 5289).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tls12PrfHash {
    Sha256,
    Sha384,
}

impl Tls12PrfHash {
    #[must_use]
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length, so `new_from_slice` cannot fail")]
fn p_hash_sha256(secret: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    type HmacSha256 = hmac::Hmac<Sha256>;
    let mut a = {
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(seed);
        mac.finalize().into_bytes().to_vec()
    };
    let mut out = Vec::with_capacity(out_len + 32);
    while out.len() < out_len {
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(&a);
        mac.update(seed);
        out.extend_from_slice(&mac.finalize().into_bytes());
        let mut next_a = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
        next_a.update(&a);
        a = next_a.finalize().into_bytes().to_vec();
    }
    out.truncate(out_len);
    out
}

#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length, so `new_from_slice` cannot fail")]
fn p_hash_sha384(secret: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    type HmacSha384 = hmac::Hmac<Sha384>;
    let mut a = {
        let mut mac = HmacSha384::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(seed);
        mac.finalize().into_bytes().to_vec()
    };
    let mut out = Vec::with_capacity(out_len + 48);
    while out.len() < out_len {
        let mut mac = HmacSha384::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(&a);
        mac.update(seed);
        out.extend_from_slice(&mac.finalize().into_bytes());
        let mut next_a = HmacSha384::new_from_slice(secret).expect("HMAC accepts any key length");
        next_a.update(&a);
        a = next_a.finalize().into_bytes().to_vec();
    }
    out.truncate(out_len);
    out
}

/// RFC 5246 §5 `PRF(secret, label, seed) = P_hash(secret, label + seed)`.
#[must_use]
pub fn tls12_prf(secret: &[u8], label: &[u8], seed: &[u8], out_len: usize, hash: Tls12PrfHash) -> Vec<u8> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);
    match hash {
        Tls12PrfHash::Sha256 => p_hash_sha256(secret, &label_seed, out_len),
        Tls12PrfHash::Sha384 => p_hash_sha384(secret, &label_seed, out_len),
    }
}

/// RFC 5246 §8.1 `master_secret = PRF(pre_master_secret, "master secret", client_random ||
/// server_random)[0:48]`.
#[must_use]
pub fn tls12_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    hash: Tls12PrfHash,
) -> [u8; 48] {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    let mut master_secret = [0u8; 48];
    master_secret.copy_from_slice(&tls12_prf(pre_master_secret, b"master secret", &seed, 48, hash));
    master_secret
}

/// RFC 5246 §7.4.9 `verify_data = PRF(master_secret, label, session_hash)[0:12]`.
///
/// `session_hash` is the running transcript hash (SHA-256 or SHA-384 depending on `hash`), not
/// TLS 1.3's 32-byte `Hash(handshake)`.
#[must_use]
pub fn tls12_finished_verify_data(
    master_secret: &[u8; 48],
    label: &[u8],
    session_hash: &[u8],
    hash: Tls12PrfHash,
) -> [u8; 12] {
    let mut verify_data = [0u8; 12];
    verify_data.copy_from_slice(&tls12_prf(master_secret, label, session_hash, 12, hash));
    verify_data
}

/// The RFC 5289 GCM cipher suites Restls offers on TLS 1.2; CBC-mode suites are
/// deliberately unsupported (see module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tls12CipherSuite {
    EcdheRsaAes128GcmSha256,
    EcdheEcdsaAes128GcmSha256,
    EcdheRsaAes256GcmSha384,
    EcdheEcdsaAes256GcmSha384,
}

impl Tls12CipherSuite {
    #[must_use]
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0xc02f => Some(Self::EcdheRsaAes128GcmSha256),
            0xc02b => Some(Self::EcdheEcdsaAes128GcmSha256),
            0xc030 => Some(Self::EcdheRsaAes256GcmSha384),
            0xc02c => Some(Self::EcdheEcdsaAes256GcmSha384),
            _ => None,
        }
    }

    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            Self::EcdheRsaAes128GcmSha256 => 0xc02f,
            Self::EcdheEcdsaAes128GcmSha256 => 0xc02b,
            Self::EcdheRsaAes256GcmSha384 => 0xc030,
            Self::EcdheEcdsaAes256GcmSha384 => 0xc02c,
        }
    }

    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Self::EcdheRsaAes128GcmSha256 | Self::EcdheEcdsaAes128GcmSha256 => 16,
            Self::EcdheRsaAes256GcmSha384 | Self::EcdheEcdsaAes256GcmSha384 => 32,
        }
    }

    #[must_use]
    pub fn prf_hash(self) -> Tls12PrfHash {
        match self {
            Self::EcdheRsaAes128GcmSha256 | Self::EcdheEcdsaAes128GcmSha256 => Tls12PrfHash::Sha256,
            Self::EcdheRsaAes256GcmSha384 | Self::EcdheEcdsaAes256GcmSha384 => Tls12PrfHash::Sha384,
        }
    }
}

/// RFC 5246 §6.3 key block, sliced per RFC 5288 GCM layout.
///
/// No MAC keys, just `client_write_key`/`server_write_key` and the 4-byte fixed
/// `client_write_IV`/`server_write_IV` salts (the other 8 bytes of the 12-byte GCM nonce are the
/// per-record explicit nonce).
pub struct Tls12KeyBlock {
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: [u8; 4],
    pub server_write_iv: [u8; 4],
}

impl core::fmt::Debug for Tls12KeyBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tls12KeyBlock")
            .field("client_write_key", &"<redacted>")
            .field("server_write_key", &"<redacted>")
            .field("client_write_iv", &self.client_write_iv)
            .field("server_write_iv", &self.server_write_iv)
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn tls12_key_block(
    master_secret: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    suite: Tls12CipherSuite,
) -> Tls12KeyBlock {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let key_len = suite.key_len();
    let block = tls12_prf(master_secret, b"key expansion", &seed, 2 * key_len + 8, suite.prf_hash());
    let (client_write_key, rest) = block.split_at(key_len);
    let (server_write_key, rest) = rest.split_at(key_len);
    let (client_write_iv, server_write_iv) = rest.split_at(4);
    let mut client_write_iv_arr = [0u8; 4];
    client_write_iv_arr.copy_from_slice(client_write_iv);
    let mut server_write_iv_arr = [0u8; 4];
    server_write_iv_arr.copy_from_slice(server_write_iv);
    Tls12KeyBlock {
        client_write_key: client_write_key.to_vec(),
        server_write_key: server_write_key.to_vec(),
        client_write_iv: client_write_iv_arr,
        server_write_iv: server_write_iv_arr,
    }
}

/// TLS 1.2 GCM nonce (mirrored in `component-tls/src/tls12_sequence_nonce.rs`): the 12-byte nonce
/// is the 4-byte `client_write_IV`/`server_write_IV` salt concatenated with the 8-byte explicit
/// nonce, which is simply the record sequence number, big-endian, starting at zero.
fn tls12_gcm_nonce(salt: [u8; 4], seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&salt);
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// RFC 5246 §6.2.3.3 additional data: `seq_num(8) || type(1) || version(2) || length(2)`, where
/// `length` is the plaintext (not on-wire ciphertext) length.
fn tls12_gcm_aad(seq: u64, record_type: u8, plaintext_len: u16) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = record_type;
    aad[9..11].copy_from_slice(&crate::consts::VERSION_TLS12.to_be_bytes());
    aad[11..13].copy_from_slice(&plaintext_len.to_be_bytes());
    aad
}

/// One direction's TLS 1.2 GCM AEAD state. Wire format per RFC 5246 §6.2.3.3: on-wire record body
/// is `explicit_nonce(8) || AEAD-ciphertext-with-16-byte-tag`.
pub struct Tls12RecordProtection {
    suite: Tls12CipherSuite,
    key: Vec<u8>,
    salt: [u8; 4],
    seq: u64,
}

impl core::fmt::Debug for Tls12RecordProtection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tls12RecordProtection")
            .field("suite", &self.suite)
            .field("key", &"<redacted>")
            .field("salt", &self.salt)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl Tls12RecordProtection {
    #[must_use]
    pub fn new(suite: Tls12CipherSuite, key: Vec<u8>, salt: [u8; 4]) -> Self {
        Self { suite, key, salt, seq: 0 }
    }

    pub fn advance(&mut self) {
        self.seq += 1;
    }

    #[expect(
        clippy::expect_used,
        reason = "`self.key` always holds the suite's key length (`tls12_key_block` produced it), and a seal only fails past restls's maximum record size"
    )]
    #[must_use]
    pub fn seal(&self, record_type: u8, plaintext: &[u8]) -> Vec<u8> {
        let nonce = tls12_gcm_nonce(self.salt, self.seq);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a TLS 1.2 record's plaintext length is a 16-bit field on the wire"
        )]
        let aad = tls12_gcm_aad(self.seq, record_type, plaintext.len() as u16);
        let ciphertext = if self.suite.key_len() == 16 {
            let cipher = Aes128Gcm::new_from_slice(&self.key).expect("16-byte AES-128 key");
            cipher
                .encrypt(&AesNonce::from(nonce), Payload { msg: plaintext, aad: &aad })
                .expect("AES-128-GCM seal never fails for restls-sized records")
        } else {
            let cipher = Aes256Gcm::new_from_slice(&self.key).expect("32-byte AES-256 key");
            cipher
                .encrypt(&AesNonce::from(nonce), Payload { msg: plaintext, aad: &aad })
                .expect("AES-256-GCM seal never fails for restls-sized records")
        };
        let mut out = Vec::with_capacity(8 + ciphertext.len());
        out.extend_from_slice(&nonce[4..]);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// `wire` is the record body exactly as it appeared on the wire: `explicit_nonce(8) ||
    /// ciphertext || tag(16)`.
    pub fn open(&self, record_type: u8, wire: &[u8]) -> Result<Vec<u8>> {
        let Some((explicit, ciphertext)) = wire.split_at_checked(8).filter(|(_, ciphertext)| ciphertext.len() >= 16)
        else {
            bail!("restls: TLS 1.2 GCM record too short");
        };
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(explicit);
        let plaintext_len =
            u16::try_from(ciphertext.len() - 16).map_err(|_| anyhow!("restls: TLS 1.2 GCM record too long"))?;
        let aad = tls12_gcm_aad(self.seq, record_type, plaintext_len);
        let result = if self.suite.key_len() == 16 {
            let cipher =
                Aes128Gcm::new_from_slice(&self.key).map_err(|_| anyhow!("restls: AES-128-GCM key length mismatch"))?;
            cipher.decrypt(&AesNonce::from(nonce), Payload { msg: ciphertext, aad: &aad })
        } else {
            let cipher =
                Aes256Gcm::new_from_slice(&self.key).map_err(|_| anyhow!("restls: AES-256-GCM key length mismatch"))?;
            cipher.decrypt(&AesNonce::from(nonce), Payload { msg: ciphertext, aad: &aad })
        };
        result.map_err(|_| anyhow!("restls: TLS 1.2 GCM record open failed"))
    }
}

#[cfg(test)]
mod tls12_tests {
    use super::*;

    /// Hand-computed against RFC 5246's `PRF(secret,label,seed)=P_SHA256(secret,label+seed)`
    /// definition using an independent Python `hmac`/`hashlib` P_hash chain (see worklog):
    /// `secret=b"secret"`, `label=b"label"`, `seed=b"seed"`, truncated to 16 bytes.
    #[test]
    fn tls12_prf_matches_hand_computed_p_sha256() {
        let out = tls12_prf(b"secret", b"label", b"seed", 16, Tls12PrfHash::Sha256);
        let expected: [u8; 16] =
            [0x7e, 0xd4, 0x2a, 0x23, 0xa1, 0x33, 0xad, 0x37, 0x9b, 0x99, 0x19, 0x6a, 0x86, 0xdb, 0x88, 0x7c];
        assert_eq!(out, expected);
    }

    #[test]
    fn tls12_prf_sha384_matches_hand_computed() {
        let out = tls12_prf(b"secret", b"label", b"seed", 16, Tls12PrfHash::Sha384);
        let expected: [u8; 16] =
            [0xe6, 0xa6, 0xf1, 0x99, 0xa9, 0xf1, 0x6f, 0x9a, 0x56, 0x65, 0x70, 0xcd, 0x0d, 0x8d, 0xa7, 0x1e];
        assert_eq!(out, expected);
    }

    #[test]
    fn tls12_gcm_nonce_matches_component_tls() {
        assert_eq!(tls12_gcm_nonce([1, 2, 3, 4], 0), [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(tls12_gcm_nonce([0xaa, 0xbb, 0xcc, 0xdd], 1), [0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            tls12_gcm_nonce([0, 0, 0, 0], 0x0102030405060708),
            [0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn tls12_record_protection_round_trips() {
        let mut sender =
            Tls12RecordProtection::new(Tls12CipherSuite::EcdheRsaAes128GcmSha256, vec![7u8; 16], [1, 2, 3, 4]);
        let mut receiver =
            Tls12RecordProtection::new(Tls12CipherSuite::EcdheRsaAes128GcmSha256, vec![7u8; 16], [1, 2, 3, 4]);
        for i in 0..3u8 {
            let plaintext = vec![i; 20];
            let wire = sender.seal(0x17, &plaintext);
            let opened = receiver.open(0x17, &wire).expect("open succeeds");
            assert_eq!(opened, plaintext);
            sender.advance();
            receiver.advance();
        }
    }

    #[test]
    fn tls12_record_protection_rejects_tampered_ciphertext() {
        let sender =
            Tls12RecordProtection::new(Tls12CipherSuite::EcdheEcdsaAes256GcmSha384, vec![9u8; 32], [5, 6, 7, 8]);
        let receiver =
            Tls12RecordProtection::new(Tls12CipherSuite::EcdheEcdsaAes256GcmSha384, vec![9u8; 32], [5, 6, 7, 8]);
        let mut wire = sender.seal(0x16, b"hello handshake");
        *wire.last_mut().unwrap() ^= 1;
        assert!(receiver.open(0x16, &wire).is_err());
    }

    #[test]
    fn tls12_master_secret_and_key_block_are_deterministic_and_distinct_per_direction() {
        let pms = [3u8; 32];
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        let ms = tls12_master_secret(&pms, &cr, &sr, Tls12PrfHash::Sha256);
        assert_eq!(ms.len(), 48);
        let kb = tls12_key_block(&ms, &cr, &sr, Tls12CipherSuite::EcdheRsaAes128GcmSha256);
        assert_ne!(kb.client_write_key, kb.server_write_key);
        assert_ne!(kb.client_write_iv, kb.server_write_iv);
        assert_eq!(kb.client_write_key.len(), 16);

        let verify = tls12_finished_verify_data(&ms, b"client finished", &[0u8; 32], Tls12PrfHash::Sha256);
        assert_eq!(verify.len(), 12);
    }
}

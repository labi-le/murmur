use std::fmt;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as _};
use aes::{Aes128, Aes256};
use anyhow::{anyhow, Result};
use chacha20::cipher::KeyIvInit as _;
use chacha20::{ChaCha8, R20};
use sha2::{Digest, Sha256};

use crate::shadowaead::cipher::{
    aes_ccm, aes_gcm, chacha20_poly1305, chacha8_poly1305, chacha_open, chacha_seal, xchacha20_poly1305, Aead,
};
use murmur_sing::metadata::Socksaddr;

pub(crate) const HEADER_TYPE_CLIENT: u8 = 0;
pub(crate) const HEADER_TYPE_SERVER: u8 = 1;
pub(crate) const MAX_PADDING_LENGTH: usize = 900;
pub(crate) const PACKET_NONCE_SIZE: usize = 24;
pub(crate) const REQUEST_HEADER_FIXED_CHUNK_LENGTH: usize = 1 + 8 + 2;
pub(crate) const PACKET_MINIMAL_HEADER_SIZE: usize = 30;
pub(crate) const OVERHEAD: usize = 16;
pub(crate) const PACKET_LENGTH_BUFFER_SIZE: usize = 2;
pub const AES_BLOCK_SIZE: usize = 16;
/// Unlike classic `shadowaead`, which masks the chunk length to `PAYLOAD_SIZE_MASK`, the 2022
/// ciphers cap it only by the 16-bit length prefix. `65535` is safe in both directions: the
/// client never emits a chunk above 16 KiB and the reader's buffer is sized to exactly 65535.
pub(crate) const MAX_CHUNK_SIZE: usize = 0xFFFF;

/// The `2022-blake3-*` methods: all six accepted ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    ChaCha8Poly1305,
    Aes128Ccm,
    Aes256Ccm,
}

impl CipherKind {
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "2022-blake3-aes-128-gcm" => Some(Self::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(Self::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            "2022-blake3-chacha8-poly1305" => Some(Self::ChaCha8Poly1305),
            "2022-blake3-aes-128-ccm" => Some(Self::Aes128Ccm),
            "2022-blake3-aes-256-ccm" => Some(Self::Aes256Ccm),
            _ => None,
        }
    }

    #[must_use]
    pub fn key_salt_length(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128Ccm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::ChaCha8Poly1305 | Self::Aes256Ccm => 32,
        }
    }

    #[must_use]
    pub fn is_aes(self) -> bool {
        matches!(self, Self::Aes128Gcm | Self::Aes256Gcm | Self::Aes128Ccm | Self::Aes256Ccm)
    }

    /// Builds the AEAD for `key`.
    pub fn make_aead(self, key: &[u8]) -> Result<Box<dyn Aead>> {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => aes_gcm(key),
            Self::Aes128Ccm | Self::Aes256Ccm => aes_ccm(key),
            Self::ChaCha20Poly1305 => chacha20_poly1305(key),
            Self::ChaCha8Poly1305 => chacha8_poly1305(key),
        }
    }

    /// The UDP AEAD selection: XChaCha20-Poly1305 or XChaCha8-Poly1305.
    /// Never called for an AES kind, which uses the block-cipher UDP header instead.
    pub fn make_udp_aead(self, key: &[u8]) -> Result<Box<dyn Aead>> {
        match self {
            Self::ChaCha20Poly1305 => xchacha20_poly1305(key),
            Self::ChaCha8Poly1305 => xchacha8_poly1305(key),
            Self::Aes128Gcm | Self::Aes256Gcm | Self::Aes128Ccm | Self::Aes256Ccm => {
                Err(anyhow!("AES ciphers use the block-cipher UDP header"))
            }
        }
    }
}

/// A genuine 8-round XChaCha, distinct from the classic `shadowaead` cipher list's
/// `xchacha8-ietf-poly1305`, which is wired to the full 20-round `XChaCha20Poly1305`.
struct XChaCha8Aead {
    key: [u8; 32],
}

impl fmt::Debug for XChaCha8Aead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XChaCha8Aead").finish_non_exhaustive()
    }
}

impl XChaCha8Aead {
    /// Setup for a 24-byte nonce always derives the XChaCha subkey with HChaCha20 (fixed 20
    /// rounds), then runs the keystream itself at the reduced round count (8 here); only the
    /// keystream, not the setup, receives the reduced round count. `chacha20::XChaCha8`
    /// derives the subkey with the same reduced rounds as the stream, so it must not be used
    /// here; do the two-stage derivation by hand instead.
    fn stream(&self, nonce: &[u8], error: &str) -> Result<ChaCha8> {
        let key = chacha20::Key::from(self.key);
        let nonce = chacha20::XNonce::try_from(nonce).map_err(|_| anyhow!("{error}"))?;
        let (prefix, suffix) = nonce.split_at(16);
        let subkey = chacha20::hchacha::<R20>(&key, prefix.try_into().map_err(|_| anyhow!("{error}"))?);
        let mut inner_nonce = chacha20::Nonce::default();
        for (dst, src) in inner_nonce.iter_mut().skip(4).zip(suffix.iter()) {
            *dst = *src;
        }
        Ok(ChaCha8::new(&subkey, &inner_nonce))
    }
}

impl Aead for XChaCha8Aead {
    fn nonce_size(&self) -> usize {
        24
    }

    fn overhead(&self) -> usize {
        16
    }

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> Result<()> {
        let mut cipher = self.stream(nonce, "chacha20poly1305: bad nonce length passed to Seal")?;
        chacha_seal(&mut cipher, dst, plaintext, additional_data)
    }

    fn open(&self, nonce: &[u8], ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>> {
        let mut cipher = self.stream(nonce, "chacha20poly1305: bad nonce length passed to Open")?;
        chacha_open(&mut cipher, ciphertext, additional_data)
    }
}

pub(crate) fn xchacha8_poly1305(key: &[u8]) -> Result<Box<dyn Aead>> {
    let key: [u8; 32] = key.try_into().map_err(|_| anyhow!("chacha20poly1305: bad key length"))?;
    Ok(Box::new(XChaCha8Aead { key }))
}

pub(crate) fn key(raw: &[u8], key_length: usize) -> Vec<u8> {
    let digest = Sha256::digest(raw);
    digest.get(..key_length).unwrap_or_default().to_vec()
}

/// The session subkey: `blake3::derive_key("shadowsocks 2022 session subkey", psk || salt)`.
/// BLAKE3's key-derivation output is an extendable-output stream, so truncating the crate's fixed
/// 32-byte `derive_key` to `key_length` bytes matches the shorter-length derivation exactly.
pub(crate) fn session_key(psk: &[u8], salt: &[u8], key_length: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    let out = blake3::derive_key("shadowsocks 2022 session subkey", &material);
    out.get(..key_length).unwrap_or_default().to_vec()
}

/// The identity subkey:
/// `blake3::derive_key("shadowsocks 2022 identity subkey", keyMaterial)`.
#[must_use]
pub fn identity_subkey(psk: &[u8], salt: &[u8], key_length: usize) -> Vec<u8> {
    let mut material = vec![0u8; key_length * 2];
    let (low, high) = material.split_at_mut(key_length);
    for (dst, src) in low.iter_mut().zip(psk) {
        *dst = *src;
    }
    for (dst, src) in high.iter_mut().zip(salt) {
        *dst = *src;
    }
    let out = blake3::derive_key("shadowsocks 2022 identity subkey", &material);
    out.get(..key_length).unwrap_or_default().to_vec()
}

/// The psk-hash construction: `blake3::hash(key)[..AES_BLOCK_SIZE]` for
/// every PSK but the first, concatenated.
#[must_use]
pub fn psk_hash_blocks(psk_list: &[Vec<u8>]) -> Option<Vec<u8>> {
    if psk_list.len() < 2 {
        return None;
    }
    let mut out = vec![0u8; (psk_list.len() - 1) * AES_BLOCK_SIZE];
    for (block, psk) in out.chunks_exact_mut(AES_BLOCK_SIZE).zip(psk_list.iter().skip(1)) {
        let hash = blake3::hash(psk);
        let (digest, _) = hash.as_bytes().split_at(AES_BLOCK_SIZE);
        block.copy_from_slice(digest);
    }
    Some(out)
}

/// A block cipher for the two AES key sizes `2022-blake3-*` uses.
#[derive(Clone)]
pub enum AesBlockCipher {
    Aes128(Box<Aes128>),
    Aes256(Box<Aes256>),
}

/// The expanded key schedule is key material, so it is redacted.
impl fmt::Debug for AesBlockCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes128(_) => f.debug_tuple("AesBlockCipher::Aes128").finish_non_exhaustive(),
            Self::Aes256(_) => f.debug_tuple("AesBlockCipher::Aes256").finish_non_exhaustive(),
        }
    }
}

impl AesBlockCipher {
    pub fn new(key: &[u8]) -> Result<Self> {
        match key.len() {
            16 => Ok(Self::Aes128(Box::new(
                Aes128::new_from_slice(key).map_err(|_| anyhow!("invalid AES key size {}", key.len()))?,
            ))),
            32 => Ok(Self::Aes256(Box::new(
                Aes256::new_from_slice(key).map_err(|_| anyhow!("invalid AES key size {}", key.len()))?,
            ))),
            other => Err(anyhow!("invalid AES key size {other}")),
        }
    }

    pub(crate) fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        let mut array = aes::Block::from(*block);
        match self {
            Self::Aes128(c) => c.encrypt_block(&mut array),
            Self::Aes256(c) => c.encrypt_block(&mut array),
        }
        block.copy_from_slice(array.as_slice());
    }

    pub fn decrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        let mut array = aes::Block::from(*block);
        match self {
            Self::Aes128(c) => c.decrypt_block(&mut array),
            Self::Aes256(c) => c.decrypt_block(&mut array),
        }
        block.copy_from_slice(array.as_slice());
    }
}

/// Little-endian increment with wraparound carry, shared by the TCP and UDP paths.
pub(crate) fn increase_nonce(nonce: &mut [u8]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            return;
        }
    }
}

/// A single-direction AEAD chunk cipher: a cipher and nonce pair, used for both the TCP
/// fixed/variable request-response chunks and the ordinary data
/// chunks that follow them.
pub(crate) struct ChunkCipher {
    aead: Box<dyn Aead>,
    nonce: Vec<u8>,
}

impl ChunkCipher {
    pub(crate) fn new(aead: Box<dyn Aead>) -> Self {
        let nonce = vec![0u8; aead.nonce_size()];
        Self { aead, nonce }
    }

    /// Seals `plaintext`, appending ciphertext and tag to `out`.
    pub(crate) fn seal_into(&mut self, out: &mut Vec<u8>, plaintext: &[u8]) -> Result<()> {
        self.aead.seal(out, &self.nonce, plaintext, &[])?;
        increase_nonce(&mut self.nonce);
        Ok(())
    }

    /// Opens one chunk (ciphertext and tag) in place.
    pub(crate) fn open(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        let out = self.aead.open(&self.nonce, chunk, &[])?;
        increase_nonce(&mut self.nonce);
        Ok(out)
    }

    /// Seals a 2-byte length record followed
    /// by the data record, matching a single `[length_chunk][data_chunk]` unit on the wire.
    pub(crate) fn seal_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(PACKET_LENGTH_BUFFER_SIZE + OVERHEAD * 2 + data.len());
        // The client caps a chunk at 16 KiB, so the 16-bit length prefix never saturates.
        self.seal_into(&mut out, &u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes())?;
        self.seal_into(&mut out, data)?;
        Ok(out)
    }

    pub(crate) fn open_length(&mut self, chunk: &[u8]) -> Result<usize> {
        let plain = self.open(chunk)?;
        let prefix: [u8; PACKET_LENGTH_BUFFER_SIZE] = plain
            .get(..PACKET_LENGTH_BUFFER_SIZE)
            .and_then(|head| head.try_into().ok())
            .ok_or_else(err_packet_too_short)?;
        Ok(usize::from(u16::from_be_bytes(prefix)))
    }
}

/// Encodes a socksaddr, using the same ATYP wire bytes
/// `adapter::outbound::shadowsocks`'s classic-cipher codec uses (`1`/`3`/`4`).
pub(crate) fn encode_socksaddr(dest: &Socksaddr) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    if dest.is_fqdn() {
        let fqdn_len = u8::try_from(dest.fqdn.len()).map_err(|_| anyhow!("shadowsocks 2022: fqdn too long"))?;
        buf.push(3u8);
        buf.push(fqdn_len);
        buf.write_all(dest.fqdn.as_bytes())?;
    } else {
        match dest.addr {
            Some(IpAddr::V4(v4)) => {
                buf.push(1u8);
                buf.extend_from_slice(&v4.octets());
            }
            Some(IpAddr::V6(v6)) => {
                buf.push(4u8);
                buf.extend_from_slice(&v6.octets());
            }
            None => return Err(anyhow!("shadowsocks 2022: invalid destination")),
        }
    }
    buf.extend_from_slice(&dest.port.to_be_bytes());
    Ok(buf)
}

fn err_short_dest_header() -> anyhow::Error {
    anyhow!("shadowsocks 2022: short destination header")
}

fn read_port(buf: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = buf
        .get(offset..)
        .and_then(|tail| tail.get(..2))
        .and_then(|tail| tail.try_into().ok())
        .ok_or_else(err_short_dest_header)?;
    Ok(u16::from_be_bytes(bytes))
}

/// Decodes a socksaddr. Returns the destination and the number of bytes
/// consumed from `buf`.
pub(crate) fn decode_socksaddr(buf: &[u8]) -> Result<(Socksaddr, usize)> {
    let Some(&atyp) = buf.first() else {
        return Err(anyhow!("shadowsocks 2022: empty destination header"));
    };
    match atyp {
        3 => {
            let len = usize::from(*buf.get(1).ok_or_else(err_short_dest_header)?);
            let Some(fqdn) = buf.get(2..2 + len) else {
                return Err(err_short_dest_header());
            };
            let port = read_port(buf, 2 + len)?;
            Ok((Socksaddr::fqdn(String::from_utf8_lossy(fqdn).into_owned(), port), 2 + len + 2))
        }
        1 => {
            let Some(octets) = buf.get(1..5).and_then(|ip| <[u8; 4]>::try_from(ip).ok()) else {
                return Err(err_short_dest_header());
            };
            let port = read_port(buf, 5)?;
            Ok((Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::from(octets)), port), 7))
        }
        4 => {
            let Some(octets) = buf.get(1..17).and_then(|ip| <[u8; 16]>::try_from(ip).ok()) else {
                return Err(err_short_dest_header());
            };
            let port = read_port(buf, 17)?;
            Ok((Socksaddr::from_ip(IpAddr::V6(Ipv6Addr::from(octets)), port), 19))
        }
        other => Err(anyhow!("shadowsocks 2022: unknown address type {other}")),
    }
}

pub(crate) fn err_bad_header_type(expected: u8, got: u8) -> anyhow::Error {
    anyhow!("bad header type: expected {expected}, got {got}")
}

pub(crate) fn err_bad_timestamp(epoch: u64, diff: i64) -> anyhow::Error {
    anyhow!("bad timestamp: received {epoch}, diff {diff}s")
}

pub(crate) fn err_bad_request_salt() -> anyhow::Error {
    anyhow!("bad request salt")
}

pub(crate) fn err_salt_not_unique() -> anyhow::Error {
    anyhow!("salt not unique")
}

pub(crate) fn err_bad_client_session_id() -> anyhow::Error {
    anyhow!("bad client session id")
}

pub(crate) fn err_packet_id_not_unique() -> anyhow::Error {
    anyhow!("packet id not unique")
}

pub(crate) fn err_too_many_server_sessions() -> anyhow::Error {
    anyhow!("server session changed more than once during the last minute")
}

/// Error for a short fixed-size read: "EOF" when nothing was left, "unexpected EOF" when some
/// bytes but not enough were read.
pub(crate) fn err_short_read(remaining: usize) -> anyhow::Error {
    if remaining == 0 {
        anyhow!("EOF")
    } else {
        anyhow!("unexpected EOF")
    }
}

pub(crate) fn err_packet_too_short() -> anyhow::Error {
    anyhow!("packet too short")
}

pub(crate) fn err_no_eih() -> anyhow::Error {
    anyhow!("Shadowsocks 2022 EIH support only available in AES ciphers")
}

/// The clock function: `Service`/`ClientMethod` each hold one, defaulting
/// to `murmur_ntp::time::now`, so a test can substitute a fixed or skewed clock without touching
/// process-wide state.
pub(crate) type TimeFn = Arc<dyn Fn() -> i64 + Send + Sync>;

pub(crate) fn system_time_fn() -> TimeFn {
    Arc::new(|| murmur_ntp::time::now().timestamp())
}

/// Accepts an epoch within 30 seconds of `now`. Converting `epoch` to `i64` wraps any value at or
/// above `2^63` into a negative one (numeric conversions reinterpret the bits, as Rust's `as i64`
/// does), and the intermediate `f64` loses precision above 2^53 before converting back — both
/// steps are reproduced here, so the reported diff matches that rounding rather than the
/// mathematically exact one once `epoch` is large enough for those steps to matter.
/// DEVIATION: when the rounded `f64` magnitude lands exactly on 2^63, a saturating conversion to
/// `i64` (as here) rejects the epoch, where a wrapping one would accept it. Rejecting is the
/// safer behaviour and is kept, at the cost of bit-for-bit parity for that narrow band of epochs
/// near `now ± 2^63`.
#[expect(
    clippy::cast_precision_loss,
    reason = "the i64 -> f64 step reproduces the lossy arithmetic documented above"
)]
#[expect(
    clippy::cast_possible_truncation,
    reason = "the f64 -> i64 step saturates, the deviation documented above from a wrapping conversion"
)]
pub(crate) fn check_timestamp(epoch: u64, now: i64) -> Result<()> {
    let diff = (now.wrapping_sub(epoch.cast_signed()) as f64).abs() as i64;
    if diff > 30 {
        return Err(err_bad_timestamp(epoch, diff));
    }
    Ok(())
}

pub(crate) fn now_unix(now: i64) -> u64 {
    now.cast_unsigned()
}

/// The session RNG: a keyed BLAKE3 XOF over an empty message
/// used as a CSPRNG for the XChaCha20 UDP packet nonces.
pub(crate) struct KeyedXof(blake3::OutputReader);

impl KeyedXof {
    pub(crate) fn new() -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut key);
        Self(blake3::Hasher::new_keyed(&key).finalize_xof())
    }

    pub(crate) fn read(&mut self, out: &mut [u8]) {
        self.0.fill(out);
    }

    pub(crate) fn read_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.read(&mut b);
        u64::from_be_bytes(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_matches_blake3_prefix_property() {
        let psk = b"0123456789abcdef";
        let salt = b"fedcba9876543210";
        let k16 = session_key(psk, salt, 16);
        let k32 = session_key(psk, salt, 32);
        assert_eq!(k16.len(), 16);
        assert_eq!(k32.len(), 32);
        assert_eq!(k16.as_slice(), &k32[..16]);
    }

    #[test]
    fn socksaddr_round_trips() {
        let dest = Socksaddr::fqdn("example.com", 443);
        let encoded = encode_socksaddr(&dest).unwrap();
        let (decoded, consumed) = decode_socksaddr(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.fqdn, dest.fqdn);
        assert_eq!(decoded.port, dest.port);
    }

    /// The diff wraps `epoch` reinterpreted as `i64` (a `uint64 >= 2^63` turns negative) and
    /// round-trips through `float64`, which loses precision above 2^53. Expected value computed with the same three steps in Python:
    /// `epoch=2^63+12345` wraps to `i64::MIN+12345`; `0 - that` wraps to `9223372036854763463`;
    /// rounding that through `f64` and back gives `9223372036854763520`, not the exact value.
    #[test]
    fn check_timestamp_matches_float64_diff_for_huge_epoch() {
        let epoch = (1u64 << 63) + 12345;
        let err = check_timestamp(epoch, 0).unwrap_err();
        assert_eq!(err.to_string(), format!("bad timestamp: received {epoch}, diff 9223372036854763520s"));
    }

    /// Known-answer test: the two-PSK EIH sub-header from a client with a deterministic random
    /// override, `2022-blake3-aes-128-gcm`, dialing with `KeyList: [psk1, psk2]`. Proves
    /// `identity_subkey`/`psk_hash_blocks`/`AesBlockCipher` reproduce the identity header byte for
    /// byte, independent of `ClientMethod::build_request`'s own random salt.
    #[test]
    fn kat_eih_identity_header_matches_reference_client() {
        let psk1 = hex::decode("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap();
        let psk2 = hex::decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let expected_identity_block = hex::decode("41fa8971ee5e477c8967229983a94976").unwrap();

        let hash_blocks = psk_hash_blocks(&[psk1.clone(), psk2.clone()]).unwrap();
        let subkey = identity_subkey(&psk1, &salt, 16);
        let cipher = AesBlockCipher::new(&subkey).unwrap();
        let mut block: [u8; AES_BLOCK_SIZE] = hash_blocks[..AES_BLOCK_SIZE].try_into().unwrap();
        cipher.encrypt_block(&mut block);
        assert_eq!(&block[..], &expected_identity_block[..AES_BLOCK_SIZE]);
    }

    #[test]
    fn aes_block_round_trips() {
        let cipher = AesBlockCipher::new(&[0u8; 16]).unwrap();
        let mut block = [1u8; 16];
        let original = block;
        cipher.encrypt_block(&mut block);
        assert_ne!(block, original);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, original);
    }
}

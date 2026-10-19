//! The JLS authentication mechanism layered on top of a TLS 1.3 handshake.
//!
//! JLS embeds an authenticator in the literal `ClientHello.random` /
//! `ServerHello.random` bytes sent on the wire: `FakeRandom = AEAD_Seal(key,
//! nonce, RandomSeed)` where `key` and `nonce` are derived from a per-user
//! secret plus `AuthData` (the surrounding hello message with the random
//! field, and any PSK binders, zeroed out). A peer that holds the matching
//! username/password can decrypt `FakeRandom` back to `RandomSeed`; anyone
//! else sees 32 bytes indistinguishable from real random.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AesGcm, KeyInit};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::{Result, TlsError};

pub const HELLO_RANDOM_LEN: usize = 32;
pub const RANDOM_SEED_LEN: usize = HELLO_RANDOM_LEN / 2;

/// RFC 8446 §4.1.3 downgrade-protection suffixes embedded in `ServerHello.random`
/// when a TLS 1.3-capable server negotiates down to TLS 1.2/1.1. The byte
/// sequences are fixed by the RFC.
const DOWNGRADE_CANARY_TLS12: &[u8; 8] = b"DOWNGRD\x01";
const DOWNGRADE_CANARY_TLS11: &[u8; 8] = b"DOWNGRD\x00";

/// RFC 8446 §4.1.3 `HelloRetryRequest` random constant. JLS v3 forbids HRR
/// entirely, so a `FakeRandom` ending in this constant's last 8 bytes must
/// also be avoided.
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11,
    0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

const EXT_PRE_SHARED_KEY: u16 = 41;
const HELLO_RANDOM_OFFSET: usize = 6;

/// A JLS user: the username and the password of one configured account.
#[derive(Clone, Debug)]
pub struct JlsUser {
    pub username: String,
    pub password: String,
}

/// AES-GCM with a 32-byte (SHA-256-sized) nonce. `aes-gcm`'s `AesGcm` is
/// generic over the nonce size for exactly this reason: with a `NonceSize`
/// other than the standard 96 bits, it derives the GCM counter block `J0` via
/// GHASH over the padded nonce and its bit length (NIST SP 800-38D §7.1.2).
///
/// The key is `sha256(password || authData)`, i.e. 32 bytes, used as an AES-256
/// key (the key length selects the AES variant); despite the crate name this is
/// AES-256-GCM, not AES-128-GCM.
type Aes256GcmLongNonce = AesGcm<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U32>;

fn derive_nonce_and_key(user: &JlsUser, auth_data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut nonce_hash = Sha256::new();
    nonce_hash.update(user.username.as_bytes());
    nonce_hash.update(auth_data);
    let nonce: [u8; 32] = nonce_hash.finalize().into();

    let mut key_hash = Sha256::new();
    key_hash.update(user.password.as_bytes());
    key_hash.update(auth_data);
    let key: [u8; 32] = key_hash.finalize().into();

    (nonce, key)
}
/// Encrypts `random16` (the low half of the yet-to-be-sent hello random) under the per-user
/// key/nonce derived from `auth_data`.
///
/// `random16` is redrawn from `rng` whenever the result would end in a forbidden downgrade/HRR
/// suffix.
pub fn jls_build_fake_random(
    user: &JlsUser,
    random16: &[u8; RANDOM_SEED_LEN],
    auth_data: &[u8],
    rng: &mut impl RngCore,
) -> Result<[u8; HELLO_RANDOM_LEN]> {
    let (nonce, key) = derive_nonce_and_key(user, auth_data);
    let cipher =
        Aes256GcmLongNonce::new_from_slice(&key).map_err(|_| TlsError::protocol("jls: invalid AES-256 key length"))?;
    let nonce_arr = aes_gcm::aead::Nonce::<Aes256GcmLongNonce>::from(nonce);

    let mut seed = *random16;
    loop {
        let fake_random = cipher
            .encrypt(&nonce_arr, Payload { msg: &seed, aad: &[] })
            .map_err(|_| TlsError::protocol("jls: GCM seal failed"))?;
        if !jls_has_forbidden_random_suffix(&fake_random) {
            let mut out = [0u8; HELLO_RANDOM_LEN];
            out.copy_from_slice(&fake_random);
            return Ok(out);
        }
        rng.fill_bytes(&mut seed);
    }
}
fn jls_has_forbidden_random_suffix(random: &[u8]) -> bool {
    const SUFFIX_LEN: usize = DOWNGRADE_CANARY_TLS12.len();
    if random.len() < SUFFIX_LEN {
        return false;
    }
    let hrr_suffix_start = HELLO_RETRY_REQUEST_RANDOM.len() - SUFFIX_LEN;
    let hrr_suffix = HELLO_RETRY_REQUEST_RANDOM.get(hrr_suffix_start..).unwrap_or_default();
    let Some(suffix) = random.get(random.len() - SUFFIX_LEN..) else {
        return false;
    };
    suffix == DOWNGRADE_CANARY_TLS12 || suffix == DOWNGRADE_CANARY_TLS11 || suffix == hrr_suffix
}
#[must_use]
pub fn jls_check_fake_random(user: &JlsUser, fake_random: &[u8; HELLO_RANDOM_LEN], auth_data: &[u8]) -> bool {
    let (nonce, key) = derive_nonce_and_key(user, auth_data);
    let Ok(cipher) = Aes256GcmLongNonce::new_from_slice(&key) else {
        return false;
    };
    let nonce_arr = aes_gcm::aead::Nonce::<Aes256GcmLongNonce>::from(nonce);
    match cipher.decrypt(&nonce_arr, Payload { msg: fake_random, aad: &[] }) {
        Ok(plain) => plain.len() == RANDOM_SEED_LEN,
        Err(_) => false,
    }
}

/// Zeroes the random field (fixed offset 6, per `4-byte handshake header + 2-byte
/// legacy_version`) of a raw `ClientHello`/`ServerHello` wire message and, on `ClientHello`
/// only, the PSK binders when a `pre_shared_key` extension (type 41) is present. This operates
/// on raw wire bytes directly: this engine always has the literal wire bytes available on both
/// sides, unlike the split "already parsed" vs "about to be marshalled" call sites.
fn zero_random_field(hello_raw: &[u8]) -> Result<Vec<u8>> {
    if hello_raw.len() < HELLO_RANDOM_OFFSET + HELLO_RANDOM_LEN {
        return Err(TlsError::protocol("jls: hello message too short"));
    }
    let mut msg = hello_raw.to_vec();
    let Some(random_field) = msg.get_mut(HELLO_RANDOM_OFFSET..HELLO_RANDOM_OFFSET + HELLO_RANDOM_LEN) else {
        return Err(TlsError::protocol("jls: hello message too short"));
    };
    random_field.fill(0);
    Ok(msg)
}

/// Zeroes the random field, then locates a `pre_shared_key` extension when one is present and
/// zeroes every PSK binder's bytes in place via `zero_psk_binders_in_place`.
pub fn jls_client_hello_auth_data(hello_raw: &[u8]) -> Result<Vec<u8>> {
    let mut msg = zero_random_field(hello_raw)?;
    zero_psk_binders_in_place(&mut msg)?;
    Ok(msg)
}

/// `ServerHello` never carries PSK binders.
pub fn jls_server_hello_auth_data(hello_raw: &[u8]) -> Result<Vec<u8>> {
    zero_random_field(hello_raw)
}

/// Finds the `pre_shared_key` extension (type 41) in a `ClientHello` body when
/// present, and zeroes every binder's bytes within its `PskBinderEntry` list
/// in place, rejecting the same malformed binder data (an oversized single
/// binder, or a binder list whose declared length does not fit the message).
fn zero_psk_binders_in_place(msg: &mut [u8]) -> Result<()> {
    let Some((ext_data_start, ext_data_len)) = find_extension(msg, EXT_PRE_SHARED_KEY)? else {
        return Ok(());
    };
    let Some(ext_data) = msg.get(ext_data_start..ext_data_start + ext_data_len) else {
        return Err(TlsError::protocol("jls: extension length overruns list"));
    };
    let identities_len = read_u16(ext_data, 0)? as usize;
    let binders_off_in_ext = 2 + identities_len;
    let binders_len_declared = read_u16(ext_data, binders_off_in_ext)? as usize;
    if binders_off_in_ext + 2 + binders_len_declared != ext_data.len() {
        return Err(TlsError::protocol("jls: malformed psk binders"));
    }

    let binders_start = ext_data_start + binders_off_in_ext + 2;
    let binders_end = binders_start + binders_len_declared;
    let mut off = binders_start;
    while off < binders_end {
        let binder_len = usize::from(*msg.get(off).ok_or_else(|| TlsError::protocol("jls: truncated psk binder"))?);
        off += 1;
        if binder_len > 0xff || off + binder_len > binders_end {
            return Err(TlsError::protocol("jls: psk binder too large"));
        }
        let Some(binder) = msg.get_mut(off..off + binder_len) else {
            return Err(TlsError::protocol("jls: psk binder too large"));
        };
        binder.fill(0);
        off += binder_len;
    }
    Ok(())
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .ok_or_else(|| TlsError::protocol("jls: truncated length field"))?
        .try_into()
        .map_err(|_| TlsError::protocol("jls: truncated length field"))?;
    Ok(u16::from_be_bytes(bytes))
}

/// Walks a `ClientHello` body's extension list looking for `ext_type`,
/// returning `(offset of its data within `msg`, length of its data)` if found.
fn find_extension(msg: &[u8], ext_type: u16) -> Result<Option<(usize, usize)>> {
    let too_short = || TlsError::protocol("jls: truncated client hello");
    let mut pos = 4 + 2 + 32;
    let session_id_len = usize::from(*msg.get(pos).ok_or_else(too_short)?);
    pos += 1 + session_id_len;
    let cipher_suites_len = read_u16(msg, pos)? as usize;
    pos += 2 + cipher_suites_len;
    let compression_len = usize::from(*msg.get(pos).ok_or_else(too_short)?);
    pos += 1 + compression_len;
    let extensions_len = read_u16(msg, pos)? as usize;
    pos += 2;
    let extensions_end = pos + extensions_len;
    if extensions_end != msg.len() {
        return Err(TlsError::protocol("jls: extensions length mismatch"));
    }

    while pos < extensions_end {
        let cur_type = read_u16(msg, pos)?;
        let cur_len = read_u16(msg, pos + 2)? as usize;
        let data_start = pos + 4;
        if data_start + cur_len > extensions_end {
            return Err(TlsError::protocol("jls: extension length overruns list"));
        }
        if cur_type == ext_type {
            return Ok(Some((data_start, cur_len)));
        }
        pos = data_start + cur_len;
    }
    Ok(None)
}
#[must_use]
pub fn check_server_name(configured_sni: &str, presented_sni: &str) -> bool {
    configured_sni.is_empty() || configured_sni == presented_sni
}

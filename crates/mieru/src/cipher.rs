use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use pbkdf2::pbkdf2;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};

use crate::trafficpattern::{NoncePattern, NonceType};

pub const DEFAULT_NONCE_SIZE: usize = 24;
pub const DEFAULT_OVERHEAD: usize = 16;
pub const DEFAULT_KEY_LEN: usize = 32;
pub const KEY_ITER: u32 = 64;
pub const KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(120);
pub const NONCE_PREFIX_LEN_FOR_USER_HINT: usize = 16;
pub const NONCE_SUFFIX_LEN_FOR_USER_HINT: usize = 4;
pub const MAX_USER_NAME_LEN: usize = 64;

#[derive(thiserror::Error, Debug)]
pub enum CipherError {
    #[error("ciphertext is too short")]
    CiphertextTooShort,
    #[error("AEAD open/seal failed")]
    Aead,
    #[error("EncryptWithNonce/DecryptWithNonce is not supported when implicit nonce is enabled")]
    ImplicitNonceUnsupported,
    #[error("unable to decrypt from any candidate key")]
    NoMatchingKey,
    #[error("password is empty")]
    EmptyPassword,
    #[error("user name length {0} exceeds maximum {MAX_USER_NAME_LEN}")]
    UserNameTooLong(usize),
}

type Result<T, E = CipherError> = std::result::Result<T, E>;

/// `HashPassword`: `sha256(raw_password || 0x00 || unique_value)`.
#[must_use]
pub fn hash_password(raw_password: &[u8], unique_value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(raw_password);
    hasher.update([0u8]);
    hasher.update(unique_value);
    hasher.finalize().into()
}

/// Rounds `unix_seconds` to the nearest multiple of `interval_secs` since the Unix epoch, ties
/// rounding up.
fn round_to_interval(unix_seconds: i64, interval_secs: i64) -> i64 {
    let q = unix_seconds.div_euclid(interval_secs);
    let r = unix_seconds.rem_euclid(interval_secs);
    if r * 2 >= interval_secs {
        (q + 1) * interval_secs
    } else {
        q * interval_secs
    }
}

fn salt_from_time(t: SystemTime) -> [[u8; 32]; 3] {
    let unix = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().cast_signed();
    let interval = KEY_REFRESH_INTERVAL.as_secs().cast_signed();
    let rounded = round_to_interval(unix, interval);
    let times = [rounded - interval, rounded, rounded + interval];
    let mut salts = [[0u8; 32]; 3];
    for (salt, secs) in salts.iter_mut().zip(times) {
        let mut hasher = Sha256::new();
        hasher.update(secs.cast_unsigned().to_be_bytes());
        *salt = hasher.finalize().into();
    }
    salts
}

fn derive_key(password: &[u8], salt: &[u8; 32]) -> [u8; DEFAULT_KEY_LEN] {
    let mut key = [0u8; DEFAULT_KEY_LEN];
    #[expect(
        clippy::expect_used,
        reason = "PBKDF2 only rejects an unusable key or output length; the output buffer is a fixed 32-byte array and HMAC accepts a key of any length, so this cannot fail"
    )]
    pbkdf2::<hmac::Hmac<Sha256>>(password, salt, KEY_ITER, &mut key)
        .expect("HMAC can be initialized with any key length");
    key
}

/// The three epoch keys derived from `password` for `now`, oldest to newest.
fn derive_key_epochs(password: &[u8], now: SystemTime) -> [[u8; DEFAULT_KEY_LEN]; 3] {
    let salts = salt_from_time(now);
    [derive_key(password, &salts[0]), derive_key(password, &salts[1]), derive_key(password, &salts[2])]
}

#[derive(Default)]
struct CipherState {
    implicit_nonce_enabled: bool,
    implicit_nonce: Option<[u8; DEFAULT_NONCE_SIZE]>,
    user_name: Option<String>,
    nonce_pattern: Option<NoncePattern>,
    /// Whether the pattern has shaped a nonce already. A stateless (UDP) block that has applied
    /// it once stops doing so unless the pattern asks for every packet to be shaped, so a client
    /// that shapes only its first datagram is indistinguishable from one that shapes none.
    nonce_pattern_applied: bool,
}

/// The AEAD block cipher: an XChaCha20Poly1305 wrapper with the two mieru nonce modes.
pub struct BlockCipher {
    aead: XChaCha20Poly1305,
    key: [u8; DEFAULT_KEY_LEN],
    state: Mutex<CipherState>,
}

impl core::fmt::Debug for BlockCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The key and the nonce state are secret.
        f.debug_struct("BlockCipher").finish_non_exhaustive()
    }
}

impl BlockCipher {
    /// Locks the nonce state. Poisoning is taken fail-fast rather than recovered: a state machine
    /// left half-updated must never seal or open another frame.
    fn lock_state(&self) -> MutexGuard<'_, CipherState> {
        #[expect(
            clippy::expect_used,
            reason = "the nonce mutex is only held across panic-free mutations, so it cannot be poisoned"
        )]
        let guard = self.state.lock().expect("cipher mutex poisoned");
        guard
    }

    #[must_use]
    pub fn new(key: [u8; DEFAULT_KEY_LEN]) -> Self {
        let aead = XChaCha20Poly1305::new(&Key::from(key));
        Self { aead, key, state: Mutex::new(CipherState::default()) }
    }

    pub fn nonce_size(&self) -> usize {
        DEFAULT_NONCE_SIZE
    }

    pub fn overhead(&self) -> usize {
        DEFAULT_OVERHEAD
    }

    pub fn set_implicit_nonce_mode(&self, enable: bool) {
        let mut state = self.lock_state();
        state.implicit_nonce_enabled = enable;
        if !enable {
            state.implicit_nonce = None;
        }
    }

    pub fn is_stateless(&self) -> bool {
        !self.lock_state().implicit_nonce_enabled
    }

    pub fn set_user_name(&self, name: Option<String>) {
        self.lock_state().user_name = name;
    }

    pub fn user_name(&self) -> Option<String> {
        self.lock_state().user_name.clone()
    }

    /// Clones: a fresh AEAD instance over the same key, preserving implicit-nonce mode/state
    /// and the user-name context.
    #[must_use]
    pub fn clone_full(&self) -> Self {
        let state = self.lock_state();
        let aead = XChaCha20Poly1305::new(&Key::from(self.key));
        Self {
            aead,
            key: self.key,
            state: Mutex::new(CipherState {
                implicit_nonce_enabled: state.implicit_nonce_enabled,
                implicit_nonce: state.implicit_nonce,
                user_name: state.user_name.clone(),
                nonce_pattern: state.nonce_pattern.clone(),
                nonce_pattern_applied: false,
            }),
        }
    }

    /// Clones without state: a fresh AEAD instance, no nonce state, no user-name context.
    #[must_use]
    pub fn clone_stateless_fast(&self) -> Self {
        Self::new(self.key)
    }

    /// `SetNoncePattern`: the traffic pattern's nonce shape, applied to every nonce this block
    /// generates. A stateless block shapes only its first nonce unless the pattern says otherwise.
    pub fn set_nonce_pattern(&self, pattern: Option<NoncePattern>) {
        let mut state = self.lock_state();
        state.nonce_pattern = pattern;
        state.nonce_pattern_applied = false;
    }

    /// Builds a random nonce with the traffic pattern's shape applied to its prefix.
    fn new_nonce(state: &mut CipherState) -> [u8; DEFAULT_NONCE_SIZE] {
        let mut nonce = [0u8; DEFAULT_NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce);
        apply_nonce_pattern(state, &mut nonce);
        nonce
    }

    /// Adds the user hint to the nonce: overwrite the last 4 bytes of `nonce` with
    /// `sha256(user_name || nonce[..16])[..4]`, when a user name is set.
    fn add_user_hint(user_name: Option<&str>, nonce: &mut [u8; DEFAULT_NONCE_SIZE]) -> Result<()> {
        let Some(user_name) = user_name else {
            return Ok(());
        };
        if user_name.len() > MAX_USER_NAME_LEN {
            return Err(CipherError::UserNameTooLong(user_name.len()));
        }
        let mut hasher = Sha256::new();
        hasher.update(user_name.as_bytes());
        hasher.update(&nonce[..NONCE_PREFIX_LEN_FOR_USER_HINT]);
        let digest: [u8; DEFAULT_KEY_LEN] = hasher.finalize().into();
        nonce[DEFAULT_NONCE_SIZE - NONCE_SUFFIX_LEN_FOR_USER_HINT..]
            .copy_from_slice(&digest[..NONCE_SUFFIX_LEN_FOR_USER_HINT]);
        Ok(())
    }

    /// `CheckUserFromHint`: does `nonce`'s hint suffix match `user`?
    #[must_use]
    pub fn check_user_from_hint(user: &str, nonce: &[u8]) -> bool {
        if user.is_empty() || user.len() > MAX_USER_NAME_LEN {
            return false;
        }
        if nonce.len() < NONCE_PREFIX_LEN_FOR_USER_HINT + NONCE_SUFFIX_LEN_FOR_USER_HINT {
            return false;
        }
        let mut hasher = Sha256::new();
        hasher.update(user.as_bytes());
        let Some(prefix) = nonce.first_chunk::<NONCE_PREFIX_LEN_FOR_USER_HINT>() else {
            return false;
        };
        hasher.update(prefix);
        let digest: [u8; DEFAULT_KEY_LEN] = hasher.finalize().into();
        let Some(hint) = nonce.last_chunk::<NONCE_SUFFIX_LEN_FOR_USER_HINT>() else {
            return false;
        };
        digest[..NONCE_SUFFIX_LEN_FOR_USER_HINT] == *hint
    }

    /// `Encrypt`: appends `nonce(if first call, implicit-nonce mode) || seal(nonce, plaintext)` to
    /// a fresh buffer.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, write_nonce) = {
            let mut state = self.lock_state();
            let user_name = state.user_name.clone();
            if !state.implicit_nonce_enabled {
                let mut nonce = Self::new_nonce(&mut state);
                Self::add_user_hint(user_name.as_deref(), &mut nonce)?;
                (nonce, true)
            } else if let Some(mut stored) = state.implicit_nonce {
                // The stored nonce is what the peer reconstructs for this segment, so it has to
                // advance in place: a copy would leave the sequence pinned one step behind.
                increase_nonce(&mut stored);
                state.implicit_nonce = Some(stored);
                (stored, false)
            } else {
                let mut nonce = Self::new_nonce(&mut state);
                Self::add_user_hint(user_name.as_deref(), &mut nonce)?;
                state.implicit_nonce = Some(nonce);
                drop(state);
                (nonce, true)
            }
        };
        let sealed = self.aead.encrypt(&XNonce::from(nonce), plaintext).map_err(|_| CipherError::Aead)?;
        let mut out = Vec::with_capacity(if write_nonce { DEFAULT_NONCE_SIZE } else { 0 } + sealed.len());
        if write_nonce {
            out.extend_from_slice(&nonce);
        }
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// `EncryptWithNonce`: stateless-only, seals `plaintext` under the caller-supplied `nonce`
    /// without transmitting it.
    pub fn encrypt_with_nonce(&self, nonce: &[u8; DEFAULT_NONCE_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
        let implicit_nonce_enabled = self.lock_state().implicit_nonce_enabled;
        if implicit_nonce_enabled {
            return Err(CipherError::ImplicitNonceUnsupported);
        }
        self.aead.encrypt(&XNonce::from(*nonce), plaintext).map_err(|_| CipherError::Aead)
    }

    /// `Decrypt`: reads the leading (or implicit) nonce from `ciphertext` and opens the rest.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, body) = {
            let mut state = self.lock_state();
            if !state.implicit_nonce_enabled {
                split_nonce(ciphertext)?
            } else if let Some(mut stored) = state.implicit_nonce {
                increase_nonce(&mut stored);
                state.implicit_nonce = Some(stored);
                (stored, ciphertext)
            } else {
                let (nonce, body) = split_nonce(ciphertext)?;
                state.implicit_nonce = Some(nonce);
                drop(state);
                (nonce, body)
            }
        };
        self.aead.decrypt(&XNonce::from(nonce), body).map_err(|_| CipherError::Aead)
    }

    /// `DecryptWithNonce`: stateless-only, opens `ciphertext` under the caller-supplied `nonce`.
    pub fn decrypt_with_nonce(&self, nonce: &[u8; DEFAULT_NONCE_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let implicit_nonce_enabled = self.lock_state().implicit_nonce_enabled;
        if implicit_nonce_enabled {
            return Err(CipherError::ImplicitNonceUnsupported);
        }
        self.aead.decrypt(&XNonce::from(*nonce), ciphertext).map_err(|_| CipherError::Aead)
    }
}

/// Splits a transmitted nonce off the front of `ciphertext`.
fn split_nonce(ciphertext: &[u8]) -> Result<([u8; DEFAULT_NONCE_SIZE], &[u8])> {
    let Some((head, body)) = ciphertext.split_at_checked(DEFAULT_NONCE_SIZE) else {
        return Err(CipherError::CiphertextTooShort);
    };
    let nonce = <[u8; DEFAULT_NONCE_SIZE]>::try_from(head).map_err(|_| CipherError::CiphertextTooShort)?;
    Ok((nonce, body))
}

fn increase_nonce(nonce: &mut [u8; DEFAULT_NONCE_SIZE]) {
    for byte in nonce.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

/// The pattern half of nonce generation: rewrite the leading nonce-rewrite-length bytes of a fresh random
/// nonce according to the traffic pattern. A `FIXED` pattern with no usable prefix leaves the
/// nonce random, which is the documented fallback rather than a failure.
fn apply_nonce_pattern(state: &mut CipherState, nonce: &mut [u8; DEFAULT_NONCE_SIZE]) {
    let Some(pattern) = state.nonce_pattern.clone() else { return };
    if !state.implicit_nonce_enabled && state.nonce_pattern_applied && !pattern.apply_to_all_udp_packet {
        return;
    }
    match pattern.nonce_type {
        NonceType::Random => {}
        NonceType::Printable => {
            let rewrite_len = nonce_rewrite_len(&pattern);
            crate::padding::to_printable_char(nonce, 0, rewrite_len);
        }
        NonceType::PrintableSubset => {
            let rewrite_len = nonce_rewrite_len(&pattern);
            crate::padding::to_common64_set(nonce, 0, rewrite_len);
        }
        NonceType::Fixed => {
            if !pattern.custom_hex_strings.is_empty() {
                let index = rand::rng().random_range(0..pattern.custom_hex_strings.len());
                if let Some(prefix) = pattern.custom_hex_strings.get(index).and_then(|hex| decode_hex_prefix(hex)) {
                    let len = prefix.len().min(DEFAULT_NONCE_SIZE);
                    let (target, _) = nonce.split_at_mut(len);
                    let (source, _) = prefix.split_at(len);
                    target.copy_from_slice(source);
                }
            }
        }
    }
    state.nonce_pattern_applied = true;
}

/// The nonce-rewrite length: a uniform value in `[minLen, maxLen]`, clamped to the nonce size. Equal
/// bounds skip the draw so a fixed-width pattern stays fixed-width.
fn nonce_rewrite_len(pattern: &NoncePattern) -> usize {
    let mut min_len = usize::try_from(pattern.min_len.max(0)).unwrap_or_default();
    let mut max_len = usize::try_from(pattern.max_len.max(0)).unwrap_or_default();
    if max_len > DEFAULT_NONCE_SIZE {
        max_len = DEFAULT_NONCE_SIZE;
    }
    if min_len > max_len {
        min_len = max_len;
    }
    if min_len == max_len {
        return min_len;
    }
    min_len + rand::rng().random_range(0..=max_len - min_len)
}

/// The pattern's custom hex strings are validated when the pattern is built, so a value that no
/// longer decodes is skipped rather than treated as a prefix.
fn decode_hex_prefix(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = char::from(*pair.first()?).to_digit(16)?;
            let lo = char::from(*pair.get(1)?).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

/// `BlockCipherFromPassword`: the middle (current) epoch key, stateless template cloned fresh.
pub fn block_cipher_from_password(password: &[u8], stateless: bool) -> Result<BlockCipher> {
    if password.is_empty() {
        return Err(CipherError::EmptyPassword);
    }
    let keys = derive_key_epochs(password, SystemTime::now());
    let block = BlockCipher::new(keys[1]);
    if !stateless {
        block.set_implicit_nonce_mode(true);
    }
    Ok(block)
}

/// `BlockCipherListFromPassword`: all three epoch keys, oldest to newest.
pub fn block_cipher_list_from_password(password: &[u8], stateless: bool) -> Result<[BlockCipher; 3]> {
    if password.is_empty() {
        return Err(CipherError::EmptyPassword);
    }
    let keys = derive_key_epochs(password, SystemTime::now());
    let blocks = keys.map(BlockCipher::new);
    if !stateless {
        for block in &blocks {
            block.set_implicit_nonce_mode(true);
        }
    }
    Ok(blocks)
}

/// `TryDecrypt`: tries every epoch key derived from `password` in turn, first success wins.
/// Returns a fresh stateless clone of the winning cipher plus the decrypted plaintext.
pub fn try_decrypt(data: &[u8], password: &[u8], stateless: bool) -> Result<(BlockCipher, Vec<u8>)> {
    let blocks = block_cipher_list_from_password(password, stateless)?;
    for block in &blocks {
        if let Ok(plaintext) = block.decrypt(data) {
            return Ok((block.clone_stateless_fast(), plaintext));
        }
    }
    Err(CipherError::NoMatchingKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateful_round_trip_uses_implicit_nonce_after_first_write() {
        let block = block_cipher_from_password(b"pw", false).expect("derive");
        let first = block.encrypt(b"hello").expect("encrypt 1");
        assert_eq!(first.len(), DEFAULT_NONCE_SIZE + b"hello".len() + DEFAULT_OVERHEAD);
        let second = block.encrypt(b"world").expect("encrypt 2");
        assert_eq!(second.len(), b"world".len() + DEFAULT_OVERHEAD);

        let recv = block_cipher_from_password(b"pw", false).expect("derive recv");
        recv.set_implicit_nonce_mode(false);
        recv.set_implicit_nonce_mode(true);
        assert_eq!(recv.decrypt(&first).expect("decrypt 1"), b"hello");
        assert_eq!(recv.decrypt(&second).expect("decrypt 2"), b"world");
    }

    #[test]
    fn stateless_round_trip_generates_fresh_nonce_every_call() {
        let block = block_cipher_from_password(b"pw", true).expect("derive");
        let a = block.encrypt(b"one").expect("encrypt a");
        let b = block.encrypt(b"two").expect("encrypt b");
        assert_ne!(a[..DEFAULT_NONCE_SIZE], b[..DEFAULT_NONCE_SIZE]);
        assert_eq!(block.decrypt(&a).expect("decrypt a"), b"one");
        assert_eq!(block.decrypt(&b).expect("decrypt b"), b"two");
    }

    /// What the packet underlay relies on: each stateless `encrypt` call carries its own nonce, so
    /// one message's nonce cannot open another message's ciphertext.
    #[test]
    fn a_metadata_nonce_does_not_open_a_separately_sealed_payload() {
        let block = block_cipher_from_password(b"pw", true).expect("derive");
        let metadata = block.encrypt(b"metadata").expect("encrypt metadata");
        let meta_nonce: [u8; DEFAULT_NONCE_SIZE] = metadata[..DEFAULT_NONCE_SIZE].try_into().expect("nonce slice");
        let payload = block.encrypt(b"payload").expect("encrypt payload");
        let payload_nonce: [u8; DEFAULT_NONCE_SIZE] = payload[..DEFAULT_NONCE_SIZE].try_into().expect("nonce slice");

        assert_ne!(meta_nonce, payload_nonce, "each stateless encrypt must carry its own nonce");
        assert_eq!(block.decrypt(&payload).expect("decrypt payload"), b"payload");
        assert!(
            block.decrypt_with_nonce(&meta_nonce, &payload[DEFAULT_NONCE_SIZE..]).is_err(),
            "the metadata's nonce must not open the payload"
        );
    }

    #[test]
    fn epoch_derivation_matches_across_clock_skew_window() {
        let now = SystemTime::now();
        let earlier = now - Duration::from_secs(90);
        let a = derive_key_epochs(b"shared-secret", now);
        let b = derive_key_epochs(b"shared-secret", earlier);
        assert!(a.iter().any(|key_a| b.contains(key_a)), "no overlapping epoch key across a 90s clock skew");
    }

    #[test]
    fn user_hint_round_trips_and_rejects_wrong_user() {
        let block = block_cipher_from_password(b"pw", true).expect("derive");
        block.set_user_name(Some("alice".to_owned()));
        let sealed = block.encrypt(b"hi").expect("encrypt");
        let nonce = &sealed[..DEFAULT_NONCE_SIZE];
        assert!(BlockCipher::check_user_from_hint("alice", nonce));
        assert!(!BlockCipher::check_user_from_hint("bob", nonce));
    }

    #[test]
    fn try_decrypt_finds_matching_epoch_key() {
        let sender = block_cipher_from_password(b"shared", true).expect("derive sender");
        let sealed = sender.encrypt(b"payload").expect("encrypt");
        let (_, plaintext) = try_decrypt(&sealed, b"shared", true).expect("try_decrypt");
        assert_eq!(plaintext, b"payload");
    }
}

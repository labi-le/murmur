//! TLS 1.3 cipher suite dispatch (RFC 8446 §5.1/§7.1-7.3), narrowed to the three standard
//! suites: whichever the real `dest` a REALITY server proxies through actually negotiates decides
//! this on the wire, so all three are implemented rather than picking one.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use anyhow::{anyhow, Result};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl CipherSuite {
    pub const fn id(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::Chacha20Poly1305Sha256 => 0x1303,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    pub const fn hash_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => 32,
            Self::Aes256GcmSha384 => 48,
        }
    }

    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::Chacha20Poly1305Sha256 => 32,
        }
    }

    pub const IV_LEN: usize = 12;

    pub fn transcript(self) -> Transcript {
        match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => Transcript::Sha256(Sha256::new()),
            Self::Aes256GcmSha384 => Transcript::Sha384(Sha384::new()),
        }
    }

    pub fn seal(self, key: &[u8], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes128GcmSha256 => Aes128Gcm::new_from_slice(key)
                .map_err(|err| anyhow!("aes-128-gcm key: {err}"))?
                .encrypt(nonce.into(), Payload { msg: plaintext, aad })
                .map_err(|err| anyhow!("aes-128-gcm seal: {err}")),
            Self::Aes256GcmSha384 => Aes256Gcm::new_from_slice(key)
                .map_err(|err| anyhow!("aes-256-gcm key: {err}"))?
                .encrypt(nonce.into(), Payload { msg: plaintext, aad })
                .map_err(|err| anyhow!("aes-256-gcm seal: {err}")),
            Self::Chacha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|err| anyhow!("chacha20poly1305 key: {err}"))?
                .encrypt(nonce.into(), Payload { msg: plaintext, aad })
                .map_err(|err| anyhow!("chacha20poly1305 seal: {err}")),
        }
    }

    pub fn open(self, key: &[u8], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes128GcmSha256 => Aes128Gcm::new_from_slice(key)
                .map_err(|err| anyhow!("aes-128-gcm key: {err}"))?
                .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
                .map_err(|_err| anyhow!("aes-128-gcm open: authentication failed")),
            Self::Aes256GcmSha384 => Aes256Gcm::new_from_slice(key)
                .map_err(|err| anyhow!("aes-256-gcm key: {err}"))?
                .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
                .map_err(|_err| anyhow!("aes-256-gcm open: authentication failed")),
            Self::Chacha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|err| anyhow!("chacha20poly1305 key: {err}"))?
                .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
                .map_err(|_err| anyhow!("chacha20poly1305 open: authentication failed")),
        }
    }
}

/// A running transcript hash (RFC 8446 §4.4.1): every handshake message's raw bytes, hashed
/// incrementally so an intermediate digest can be taken without losing the running state.
#[derive(Clone, Debug)]
pub enum Transcript {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl Transcript {
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => Digest::update(h, data),
            Self::Sha384(h) => Digest::update(h, data),
        }
    }

    /// The digest of everything written so far, without consuming the running hasher.
    pub fn digest(&self) -> Vec<u8> {
        match self {
            Self::Sha256(h) => h.clone().finalize().to_vec(),
            Self::Sha384(h) => h.clone().finalize().to_vec(),
        }
    }
}

fn hkdf_expand_label(suite: CipherSuite, secret: &[u8], label: &str, context: &[u8], out_len: usize) -> Vec<u8> {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    #[expect(clippy::cast_possible_truncation, reason = "`out_len` is a suite hash or key length, at most 48 bytes")]
    hkdf_label.extend_from_slice(&(out_len as u16).to_be_bytes());
    let full_label = format!("tls13 {label}");
    #[expect(clippy::cast_possible_truncation, reason = "the TLS 1.3 labels are short fixed strings")]
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());
    #[expect(clippy::cast_possible_truncation, reason = "the context is a transcript hash of at most 48 bytes")]
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    let mut out = vec![0u8; out_len];
    #[expect(
        clippy::expect_used,
        reason = "`from_prk` gets a secret at least as long as the hash, and `out_len` stays inside HKDF-Expand's 255-hash-length limit"
    )]
    match suite.transcript() {
        Transcript::Sha256(_) => {
            let hk = Hkdf::<Sha256>::from_prk(secret).expect("secret is at least the hash length");
            hk.expand(&hkdf_label, &mut out).expect("out_len fits HKDF-Expand's 255x limit");
        }
        Transcript::Sha384(_) => {
            let hk = Hkdf::<Sha384>::from_prk(secret).expect("secret is at least the hash length");
            hk.expand(&hkdf_label, &mut out).expect("out_len fits HKDF-Expand's 255x limit");
        }
    }
    out
}

fn derive_secret(suite: CipherSuite, secret: &[u8], label: &str, transcript_digest: &[u8]) -> Vec<u8> {
    hkdf_expand_label(suite, secret, label, transcript_digest, suite.hash_len())
}

fn hkdf_extract(suite: CipherSuite, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match suite.transcript() {
        Transcript::Sha256(_) => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
        Transcript::Sha384(_) => Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec(),
    }
}

/// Handshake and (once the peer's Finished is in) application traffic secrets, per RFC 8446
/// §7.1's key schedule. `client_hs`/`server_hs` come from the `ClientHello..ServerHello`
/// transcript; the application secrets and both Finished keys come from later transcript points
/// via [`KeySchedule::derive_master`]/`finished_key`.
pub(crate) struct KeySchedule {
    suite: CipherSuite,
    master_secret: Vec<u8>,
    pub client_handshake_secret: Vec<u8>,
    pub server_handshake_secret: Vec<u8>,
}

impl KeySchedule {
    /// `shared_secret` is the ECDHE output (X25519 raw shared point); `ch_sh_digest` is the
    /// transcript hash of `ClientHello || ServerHello` alone.
    pub(crate) fn new(suite: CipherSuite, shared_secret: &[u8], ch_sh_digest: &[u8]) -> Self {
        let zero_ikm = vec![0u8; suite.hash_len()];
        let zero_salt = vec![0u8; suite.hash_len()];
        let early_secret = hkdf_extract(suite, &zero_salt, &zero_ikm);
        let empty_digest = suite.transcript().digest();
        let derived_early = derive_secret(suite, &early_secret, "derived", &empty_digest);
        let handshake_secret = hkdf_extract(suite, &derived_early, shared_secret);
        let client_handshake_secret = derive_secret(suite, &handshake_secret, "c hs traffic", ch_sh_digest);
        let server_handshake_secret = derive_secret(suite, &handshake_secret, "s hs traffic", ch_sh_digest);
        let derived_handshake = derive_secret(suite, &handshake_secret, "derived", &empty_digest);
        let master_secret = hkdf_extract(suite, &derived_handshake, &zero_ikm);
        Self { suite, master_secret, client_handshake_secret, server_handshake_secret }
    }

    /// The `client ap traffic`/`server ap traffic` secrets, derived from the transcript up to and
    /// including the server's Finished (but not the client's).
    pub(crate) fn application_secrets(&self, ch_sf_digest: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (
            derive_secret(self.suite, &self.master_secret, "c ap traffic", ch_sf_digest),
            derive_secret(self.suite, &self.master_secret, "s ap traffic", ch_sf_digest),
        )
    }

    pub(crate) fn traffic_key_iv(&self, secret: &[u8]) -> (Vec<u8>, [u8; 12]) {
        let key = hkdf_expand_label(self.suite, secret, "key", &[], self.suite.key_len());
        let iv_vec = hkdf_expand_label(self.suite, secret, "iv", &[], CipherSuite::IV_LEN);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_vec);
        (key, iv)
    }

    pub(crate) fn finished_verify_data(&self, secret: &[u8], transcript_digest: &[u8]) -> Vec<u8> {
        let finished_key = hkdf_expand_label(self.suite, secret, "finished", &[], self.suite.hash_len());
        #[expect(clippy::expect_used, reason = "HMAC accepts a key of any length, so `new_from_slice` cannot fail")]
        match self.suite.transcript() {
            Transcript::Sha256(_) => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&finished_key).expect("HMAC accepts any key length");
                mac.update(transcript_digest);
                mac.finalize().into_bytes().to_vec()
            }
            Transcript::Sha384(_) => {
                let mut mac = Hmac::<Sha384>::new_from_slice(&finished_key).expect("HMAC accepts any key length");
                mac.update(transcript_digest);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    /// Verifies a received `Finished.verify_data` against the transcript. `verify_slice` decides
    /// equality without early exit, and a value of the wrong length is an error rather than a
    /// prefix match.
    pub(crate) fn verify_finished(&self, secret: &[u8], transcript_digest: &[u8], received: &[u8]) -> bool {
        let finished_key = hkdf_expand_label(self.suite, secret, "finished", &[], self.suite.hash_len());
        #[expect(clippy::expect_used, reason = "HMAC accepts a key of any length, so `new_from_slice` cannot fail")]
        match self.suite.transcript() {
            Transcript::Sha256(_) => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&finished_key).expect("HMAC accepts any key length");
                mac.update(transcript_digest);
                mac.verify_slice(received).is_ok()
            }
            Transcript::Sha384(_) => {
                let mut mac = Hmac::<Sha384>::new_from_slice(&finished_key).expect("HMAC accepts any key length");
                mac.update(transcript_digest);
                mac.verify_slice(received).is_ok()
            }
        }
    }
}

/// Record-layer AEAD nonce: the derived IV XORed with the big-endian 64-bit sequence number,
/// left-padded into the 12-byte IV per RFC 8446 §5.3.
pub(crate) fn record_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for (byte, seq_byte) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
        *byte ^= seq_byte;
    }
    nonce
}

/// A fresh ephemeral X25519 scalar (clamped per RFC 7748 §5) and its public point, shared by the
/// client's `ClientHello` key share and the server's `ServerHello` key share.
pub(crate) fn generate_x25519_keypair() -> ([u8; 32], [u8; 32]) {
    use rand::RngCore as _;
    let mut private = [0u8; 32];
    rand::rng().fill_bytes(&mut private);
    private[0] &= 0xF8;
    private[31] &= 127;
    private[31] |= 64;
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
    (private, public)
}

/// The REALITY `AuthKey` HKDF: always SHA-256, independent of the TLS cipher suite negotiated for
/// the rest of the handshake. `secret` is the raw X25519 ECDH output between the connection's
/// ephemeral key and the peer's long-term REALITY key; `salt` is `ClientHello.random[..20]`.
pub(crate) fn hkdf_sha256_reality(secret: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    #[expect(clippy::expect_used, reason = "32 bytes is one hash length, well inside HKDF-Expand's limit")]
    Hkdf::<Sha256>::new(Some(salt), secret).expand(b"REALITY", &mut out).expect("32 bytes fits HKDF-Expand's limit");
    out
}

//! TLS 1.2 AES-GCM cipher suites whose explicit nonce is the record sequence number.
//!
//! The record sequence number, big-endian, is the TLS 1.2 AES-GCM explicit nonce here: the first
//! application-layer record after `ChangeCipherSpec` carries explicit nonce `0x00*8`. rustls's own
//! `aws-lc-rs` TLS 1.2 GCM `Tls12AeadAlgorithm` instead XORs the sequence number into a random
//! base drawn from extra key-block bytes, a deliberate resumption-hardening choice that RFC 5288
//! does not mandate and that makes the first record's nonce non-zero. The tlsmirror carrier
//! hard-codes that wire shape and rejects a handshake whose first post-CCS record fails the zero
//! check, so this crate needs a byte-identical construction to interoperate with it. These cipher
//! suites reproduce the construction on the `aes-gcm` primitives this crate already depends on.
//!
//! Applied crate-wide in [`super::utls::build_provider`], not only for tlsmirror: the TLS stack
//! makes the same choice for every TLS 1.2 GCM connection, so matching it everywhere is
//! deliberate rather than a tlsmirror-only carve-out. TLS 1.3 is unaffected; it has no explicit
//! nonce.

use std::sync::LazyLock;

use aes_gcm::aead::{AeadInOut, KeyInit, Nonce as GcmNonce, Tag as GcmTag};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use rustls::crypto::cipher::{
    make_tls12_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm,
    UnsupportedOperationError, NONCE_LEN,
};
use rustls::{CipherSuite, CipherSuiteCommon, ConnectionTrafficSecrets, Error, SupportedCipherSuite, Tls12CipherSuite};

const EXPLICIT_NONCE_LEN: usize = 8;
const TAG_LEN: usize = 16;
const OVERHEAD: usize = EXPLICIT_NONCE_LEN + TAG_LEN;

/// `rustls`'s `msgs::fragmenter::MAX_FRAGMENT_LEN`, which is `pub(crate)` there; mirrored so this
/// decrypter enforces the same post-decryption size guard as rustls's own GCM decrypter.
const MAX_FRAGMENT_LEN: usize = 16384;

fn sequence_nonce(salt: [u8; 4], explicit: [u8; EXPLICIT_NONCE_LEN]) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..4].copy_from_slice(&salt);
    nonce[4..].copy_from_slice(&explicit);
    nonce
}

struct SequenceNonceEncrypter<C> {
    cipher: C,
    salt: [u8; 4],
}

impl<C: AeadInOut + Send + Sync + 'static> MessageEncrypter for SequenceNonceEncrypter<C> {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let mut payload = PrefixedPayload::with_capacity(self.encrypted_payload_len(msg.payload.len()));
        let explicit = seq.to_be_bytes();
        let nonce_bytes = sequence_nonce(self.salt, explicit);
        let nonce = GcmNonce::<C>::try_from(&nonce_bytes[..]).map_err(|_| Error::EncryptError)?;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        payload.extend_from_slice(&explicit);
        payload.extend_from_chunks(&msg.payload);
        let (_, plaintext) = payload.as_mut().split_at_mut(EXPLICIT_NONCE_LEN);
        let tag =
            self.cipher.encrypt_inout_detached(&nonce, &aad, plaintext.into()).map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + OVERHEAD
    }
}

struct SequenceNonceDecrypter<C> {
    cipher: C,
    salt: [u8; 4],
}

impl<C: AeadInOut + Send + Sync + 'static> MessageDecrypter for SequenceNonceDecrypter<C> {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload_len = msg.payload.len();
        if payload_len < OVERHEAD {
            return Err(Error::DecryptError);
        }
        let mut explicit = [0u8; EXPLICIT_NONCE_LEN];
        let (explicit_bytes, _) = msg.payload.split_at(EXPLICIT_NONCE_LEN);
        explicit.copy_from_slice(explicit_bytes);
        let nonce_bytes = sequence_nonce(self.salt, explicit);
        let nonce = GcmNonce::<C>::try_from(&nonce_bytes[..]).map_err(|_| Error::DecryptError)?;
        let tag_start = payload_len - TAG_LEN;
        let (ciphertext, tag_bytes) = msg.payload.split_at_mut(tag_start);
        let tag_slice: &[u8] = tag_bytes;
        let tag = GcmTag::<C>::try_from(tag_slice).map_err(|_| Error::DecryptError)?;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, tag_start - EXPLICIT_NONCE_LEN);
        let (_, body) = ciphertext.split_at_mut(EXPLICIT_NONCE_LEN);
        self.cipher.decrypt_inout_detached(&nonce, &aad, body.into(), &tag).map_err(|_| Error::DecryptError)?;
        let plain_len = tag_start - EXPLICIT_NONCE_LEN;
        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        Ok(msg.into_plain_message_range(EXPLICIT_NONCE_LEN..EXPLICIT_NONCE_LEN + plain_len))
    }
}

struct SequenceNonceGcm128;
struct SequenceNonceGcm256;

impl Tls12AeadAlgorithm for SequenceNonceGcm128 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _extra: &[u8]) -> Box<dyn MessageEncrypter> {
        #[expect(
            clippy::expect_used,
            reason = "key_block_shape pins enc_key_len to 16 for this suite, so rustls hands it a 16-byte key"
        )]
        let cipher = Aes128Gcm::new_from_slice(key.as_ref()).expect("16-byte AES-128-GCM key");
        let mut salt = [0u8; 4];
        salt.copy_from_slice(iv);
        Box::new(SequenceNonceEncrypter { cipher, salt })
    }

    fn decrypter(&self, dec_key: AeadKey, dec_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        #[expect(
            clippy::expect_used,
            reason = "key_block_shape pins enc_key_len to 16 for this suite, so rustls hands it a 16-byte key"
        )]
        let cipher = Aes128Gcm::new_from_slice(dec_key.as_ref()).expect("16-byte AES-128-GCM key");
        let mut salt = [0u8; 4];
        salt.copy_from_slice(dec_iv);
        Box::new(SequenceNonceDecrypter { cipher, salt })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape { enc_key_len: 16, fixed_iv_len: 4, explicit_nonce_len: 0 }
    }

    fn extract_keys(
        &self,
        _key: AeadKey,
        _iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }

    fn fips(&self) -> bool {
        false
    }
}

impl Tls12AeadAlgorithm for SequenceNonceGcm256 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _extra: &[u8]) -> Box<dyn MessageEncrypter> {
        #[expect(
            clippy::expect_used,
            reason = "key_block_shape pins enc_key_len to 32 for this suite, so rustls hands it a 32-byte key"
        )]
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte AES-256-GCM key");
        let mut salt = [0u8; 4];
        salt.copy_from_slice(iv);
        Box::new(SequenceNonceEncrypter { cipher, salt })
    }

    fn decrypter(&self, dec_key: AeadKey, dec_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        #[expect(
            clippy::expect_used,
            reason = "key_block_shape pins enc_key_len to 32 for this suite, so rustls hands it a 32-byte key"
        )]
        let cipher = Aes256Gcm::new_from_slice(dec_key.as_ref()).expect("32-byte AES-256-GCM key");
        let mut salt = [0u8; 4];
        salt.copy_from_slice(dec_iv);
        Box::new(SequenceNonceDecrypter { cipher, salt })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape { enc_key_len: 32, fixed_iv_len: 4, explicit_nonce_len: 0 }
    }

    fn extract_keys(
        &self,
        _key: AeadKey,
        _iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }

    fn fips(&self) -> bool {
        false
    }
}

static SEQUENCE_NONCE_GCM_128: SequenceNonceGcm128 = SequenceNonceGcm128;
static SEQUENCE_NONCE_GCM_256: SequenceNonceGcm256 = SequenceNonceGcm256;

fn sequence_nonce_suite(base: SupportedCipherSuite, aead_alg: &'static dyn Tls12AeadAlgorithm) -> Tls12CipherSuite {
    #[expect(
        clippy::unreachable,
        reason = "every caller passes one of rustls's TLS 1.2 AES-GCM constants, and a TLS 1.2 suite is always SupportedCipherSuite::Tls12"
    )]
    let SupportedCipherSuite::Tls12(base) = base
    else {
        unreachable!("aws-lc-rs TLS 1.2 GCM cipher suites are always SupportedCipherSuite::Tls12")
    };
    Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: base.common.suite,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        prf_provider: base.prf_provider,
        kx: base.kx,
        sign: base.sign,
        aead_alg,
    }
}

static SEQUENCE_NONCE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: LazyLock<Tls12CipherSuite> = LazyLock::new(|| {
    sequence_nonce_suite(
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        &SEQUENCE_NONCE_GCM_128,
    )
});
static SEQUENCE_NONCE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: LazyLock<Tls12CipherSuite> = LazyLock::new(|| {
    sequence_nonce_suite(
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        &SEQUENCE_NONCE_GCM_256,
    )
});
static SEQUENCE_NONCE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: LazyLock<Tls12CipherSuite> = LazyLock::new(|| {
    sequence_nonce_suite(
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        &SEQUENCE_NONCE_GCM_128,
    )
});
static SEQUENCE_NONCE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: LazyLock<Tls12CipherSuite> = LazyLock::new(|| {
    sequence_nonce_suite(
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        &SEQUENCE_NONCE_GCM_256,
    )
});

/// Replaces the `aws-lc-rs` TLS 1.2 AES-GCM cipher suites in `provider.cipher_suites` with
/// sequence-number-nonce equivalents, in place, preserving suite order and every other cipher suite untouched.
pub(super) fn apply(provider: &mut rustls::crypto::CryptoProvider) {
    let replacements: [(CipherSuite, &'static Tls12CipherSuite); 4] = [
        (CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &SEQUENCE_NONCE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        (CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, &SEQUENCE_NONCE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        (CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, &SEQUENCE_NONCE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        (CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, &SEQUENCE_NONCE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
    ];
    for suite in &mut provider.cipher_suites {
        if let Some((_, replacement)) = replacements.iter().find(|(id, _)| *id == suite.suite()) {
            *suite = SupportedCipherSuite::Tls12(replacement);
        }
    }
}

/// Builds a fresh `aws-lc-rs` provider with `apply` already run.
///
/// The provider is the process's installed default if one exists, else
/// `rustls::crypto::aws_lc_rs::default_provider()`. This is for callers that build a
/// `rustls::ClientConfig`/`ServerConfig` outside [`super::utls::build_provider`] and still need
/// the sequence-number TLS 1.2 AES-GCM explicit nonces.
#[must_use]
pub fn tls12_sequence_nonce_provider() -> rustls::crypto::CryptoProvider {
    let mut provider = match rustls::crypto::CryptoProvider::get_default() {
        Some(provider) => (**provider).clone(),
        None => rustls::crypto::aws_lc_rs::default_provider(),
    };
    apply(&mut provider);
    provider
}

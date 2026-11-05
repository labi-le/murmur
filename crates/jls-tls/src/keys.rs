//! RFC 8446 §7.1 key schedule, fixed to `TLS_AES_128_GCM_SHA256`: SHA-256
//! throughout.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::error::{Result, TlsError};

pub(crate) const ZERO32: [u8; 32] = [0u8; 32];

fn empty_hash() -> [u8; 32] {
    Sha256::digest([]).into()
}

fn hkdf_extract(salt: &[u8; 32], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// `HKDF-Expand-Label(Secret, Label, Context, Length)` per RFC 8446 §7.1:
/// `HkdfLabel = uint16(Length) || opaque8("tls13 " + Label) || opaque8(Context)`.
pub(crate) fn hkdf_expand_label(secret: &[u8; 32], label: &str, context: &[u8], out: &mut [u8]) -> Result<()> {
    let length: u16 = out.len().try_into().map_err(|_| TlsError::protocol("keys: expand-label output too long"))?;
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"tls13 ");
    full_label.extend_from_slice(label.as_bytes());
    let full_label_len: u8 =
        full_label.len().try_into().map_err(|_| TlsError::protocol("keys: expand-label label too long"))?;
    let context_len: u8 =
        context.len().try_into().map_err(|_| TlsError::protocol("keys: expand-label context too long"))?;

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&length.to_be_bytes());
    info.push(full_label_len);
    info.extend_from_slice(&full_label);
    info.push(context_len);
    info.extend_from_slice(context);

    let hk = Hkdf::<Sha256>::from_prk(secret).map_err(|_| TlsError::protocol("keys: invalid PRK length"))?;
    hk.expand(&info, out).map_err(|_| TlsError::protocol("keys: expand-label output too long for HKDF"))?;
    Ok(())
}

/// `Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label,
/// Transcript-Hash(Messages), 32)`.
pub(crate) fn derive_secret(secret: &[u8; 32], label: &str, transcript_hash: &[u8; 32]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hkdf_expand_label(secret, label, transcript_hash, &mut out)?;
    Ok(out)
}

/// Per-direction traffic keys: `key = HKDF-Expand-Label(secret, "key", "", 16)`,
/// `iv = HKDF-Expand-Label(secret, "iv", "", 12)`.
pub(crate) fn traffic_key_iv(secret: &[u8; 32]) -> Result<([u8; 16], [u8; 12])> {
    let mut key = [0u8; 16];
    hkdf_expand_label(secret, "key", &[], &mut key)?;
    let mut iv = [0u8; 12];
    hkdf_expand_label(secret, "iv", &[], &mut iv)?;
    Ok((key, iv))
}

/// `finished_key = HKDF-Expand-Label(BaseKey, "finished", "", 32)`.
fn finished_key(base_secret: &[u8; 32]) -> Result<[u8; 32]> {
    let mut fk = [0u8; 32];
    hkdf_expand_label(base_secret, "finished", &[], &mut fk)?;
    Ok(fk)
}

/// `verify_data = HMAC(finished_key, Transcript-Hash(handshake context))`.
pub(crate) fn compute_finished(base_secret: &[u8; 32], transcript_hash: &[u8; 32]) -> Result<[u8; 32]> {
    let fk = finished_key(base_secret)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&fk).map_err(|_| TlsError::protocol("keys: invalid HMAC key length"))?;
    mac.update(transcript_hash);
    Ok(mac.finalize().into_bytes().into())
}

/// Verifies a received `Finished.verify_data` in constant time.
pub(crate) fn verify_finished(base_secret: &[u8; 32], transcript_hash: &[u8; 32], received: &[u8; 32]) -> Result<bool> {
    let fk = finished_key(base_secret)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&fk).map_err(|_| TlsError::protocol("keys: invalid HMAC key length"))?;
    mac.update(transcript_hash);
    Ok(mac.verify_slice(received).is_ok())
}

/// RFC 8446 §7.1 `Early Secret = HKDF-Extract(0, PSK)`, where "0" is
/// Hash.length zero bytes. `None` is the certificate handshake's empty PSK,
/// which `KeySchedule::new` spells the same way.
pub(crate) fn early_secret(psk: Option<&[u8; 32]>) -> [u8; 32] {
    hkdf_extract(&ZERO32, psk.unwrap_or(&ZERO32))
}

/// RFC 8446 §7.1/§4.2.11.2: the `binder_key` of a PSK that came from a
/// `NewSessionTicket`, `Derive-Secret(Early Secret, "res binder", "")`.
pub(crate) fn resumption_binder_key(psk: &[u8; 32]) -> Result<[u8; 32]> {
    derive_secret(&early_secret(Some(psk)), "res binder", &empty_hash())
}

/// RFC 8446 §7.1: `Derive-Secret(Early Secret, "c e traffic", ClientHello)`,
/// the key the client's 0-RTT flight is protected with.
pub(crate) fn client_early_traffic_secret(psk: &[u8; 32], client_hello_hash: &[u8; 32]) -> Result<[u8; 32]> {
    derive_secret(&early_secret(Some(psk)), "c e traffic", client_hello_hash)
}

/// The full RFC 8446 §7.1 secret chain, from `Early Secret` down to the
/// application traffic secrets. Handshake traffic secrets are always
/// available; application traffic secrets are filled in by
/// [`KeySchedule::derive_application_secrets`] once the server's `Finished`
/// has been transcripted.
#[expect(
    clippy::struct_field_names,
    reason = "the fields are named for the RFC 8446 secrets they hold; the names are part of the crate-visible schedule"
)]
pub(crate) struct KeySchedule {
    handshake_secret: [u8; 32],
    master_secret: [u8; 32],
    pub client_handshake_traffic_secret: [u8; 32],
    pub server_handshake_traffic_secret: [u8; 32],
    pub client_application_traffic_secret: [u8; 32],
    pub server_application_traffic_secret: [u8; 32],
    pub resumption_master_secret: [u8; 32],
}

impl KeySchedule {
    /// Runs the schedule from `Early Secret` through the handshake traffic
    /// secrets, given the ECDHE shared secret and the transcript hash over
    /// `ClientHello .. ServerHello`. `psk` is the resumption PSK, or `None`
    /// for a certificate handshake, where RFC 8446 §7.1's `0` input is
    /// Hash.length zero bytes.
    pub(crate) fn new(
        psk: Option<&[u8; 32]>,
        shared_secret: &[u8; 32],
        client_server_hello_hash: &[u8; 32],
    ) -> Result<Self> {
        let salt1 = derive_secret(&early_secret(psk), "derived", &empty_hash())?;
        let handshake_secret = hkdf_extract(&salt1, shared_secret);
        let client_handshake_traffic_secret =
            derive_secret(&handshake_secret, "c hs traffic", client_server_hello_hash)?;
        let server_handshake_traffic_secret =
            derive_secret(&handshake_secret, "s hs traffic", client_server_hello_hash)?;
        Ok(Self {
            handshake_secret,
            master_secret: ZERO32,
            client_handshake_traffic_secret,
            server_handshake_traffic_secret,
            client_application_traffic_secret: ZERO32,
            server_application_traffic_secret: ZERO32,
            resumption_master_secret: ZERO32,
        })
    }

    /// Runs the schedule from `Handshake Secret` through `Master Secret` down
    /// to the application traffic secrets, given the transcript hash over
    /// `ClientHello .. server Finished`.
    pub(crate) fn derive_application_secrets(&mut self, full_transcript_hash: &[u8; 32]) -> Result<()> {
        let salt2 = derive_secret(&self.handshake_secret, "derived", &empty_hash())?;
        let master_secret = hkdf_extract(&salt2, &ZERO32);
        self.client_application_traffic_secret = derive_secret(&master_secret, "c ap traffic", full_transcript_hash)?;
        self.server_application_traffic_secret = derive_secret(&master_secret, "s ap traffic", full_transcript_hash)?;
        self.master_secret = master_secret;
        Ok(())
    }

    /// RFC 8446 §7.1 `Derive-Secret(Master Secret, "res master",
    /// ClientHello...client Finished)`. Only meaningful once
    /// [`Self::derive_application_secrets`] has been called and the client's
    /// `Finished` is in the transcript.
    pub(crate) fn derive_resumption_master_secret(&mut self, through_client_finished_hash: &[u8; 32]) -> Result<()> {
        self.resumption_master_secret = derive_secret(&self.master_secret, "res master", through_client_finished_hash)?;
        Ok(())
    }
}

/// RFC 8446 §4.6.1: `PSK = HKDF-Expand-Label(resumption_master_secret,
/// "resumption", ticket_nonce, Hash.length)`.
pub fn resumption_psk(resumption_master_secret: &[u8; 32], ticket_nonce: &[u8]) -> Result<[u8; 32]> {
    let mut psk = [0u8; 32];
    hkdf_expand_label(resumption_master_secret, "resumption", ticket_nonce, &mut psk)?;
    Ok(psk)
}

/// `nonce = static_iv XOR (0^32 || big_endian_u64(sequence_number))`.
pub(crate) fn record_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let (_, tail) = nonce.split_at_mut(4);
    for (slot, seq_byte) in tail.iter_mut().zip(seq.to_be_bytes()) {
        *slot ^= seq_byte;
    }
    nonce
}

/// RFC 9001 §5.2 initial secrets, derived from the client's original
/// destination connection ID rather than from the TLS key schedule, so both
/// peers can compute them before any handshake bytes exist.
const QUIC_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f,
    0x0a,
];
const QUIC_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e,
    0xd9,
];

/// The QUIC version whose salt and label set the packet protection keys use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicVersion {
    /// RFC 9000.
    V1,
    /// RFC 9369.
    V2,
}

impl QuicVersion {
    fn salt(self) -> &'static [u8; 20] {
        match self {
            Self::V1 => &QUIC_SALT_V1,
            Self::V2 => &QUIC_SALT_V2,
        }
    }

    fn key_label(self) -> &'static str {
        match self {
            Self::V1 => "quic key",
            Self::V2 => "quicv2 key",
        }
    }

    fn iv_label(self) -> &'static str {
        match self {
            Self::V1 => "quic iv",
            Self::V2 => "quicv2 iv",
        }
    }

    /// RFC 9001 §5.4 / RFC 9369 §3.3.1 header protection label.
    #[must_use]
    pub fn header_protection_label(&self) -> &'static str {
        match self {
            Self::V1 => "quic hp",
            Self::V2 => "quicv2 hp",
        }
    }
}

/// One side's Initial packet protection keys: AEAD key, IV and the header
/// protection key, all from the same traffic secret.
///
/// Its `Debug` reports none of the key material, so formatting one cannot
/// spill the packet protection keys into a log or a test failure.
pub struct QuicKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

impl core::fmt::Debug for QuicKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QuicKeys").finish_non_exhaustive()
    }
}

/// Derives packet protection keys from a QUIC traffic secret at any encryption
/// level, using the version's own label set.
pub fn quic_keys(traffic_secret: &[u8; 32], version: QuicVersion) -> Result<QuicKeys> {
    let mut key = [0u8; 16];
    hkdf_expand_label(traffic_secret, version.key_label(), &[], &mut key)?;
    let mut iv = [0u8; 12];
    hkdf_expand_label(traffic_secret, version.iv_label(), &[], &mut iv)?;
    let mut hp = [0u8; 16];
    hkdf_expand_label(traffic_secret, version.header_protection_label(), &[], &mut hp)?;
    Ok(QuicKeys { key, iv, hp })
}

/// RFC 9001 §5.2: the `(client, server)` Initial traffic secrets for a
/// connection, derived from the client's original destination connection ID.
pub fn quic_initial_secrets(dcid: &[u8], version: QuicVersion) -> Result<([u8; 32], [u8; 32])> {
    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(version.salt()), dcid);
    let initial_secret: [u8; 32] = initial_secret.into();
    let mut client = [0u8; 32];
    hkdf_expand_label(&initial_secret, "client in", &[], &mut client)?;
    let mut server = [0u8; 32];
    hkdf_expand_label(&initial_secret, "server in", &[], &mut server)?;
    Ok((client, server))
}

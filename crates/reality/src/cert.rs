//! The REALITY fake leaf certificate: a self-signed Ed25519 X.509 certificate whose
//! "signature" field is not a real signature at all, but `HMAC-SHA512(AuthKey, ed25519_pubkey)`.
//! A genuine REALITY peer never validates the certificate chain; it recomputes that same HMAC and
//! compares it against the signature bytes instead.

use anyhow::{anyhow, Result};
use hmac::{digest::KeyInit, Hmac, Mac};
use sha2::Sha512;

const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(tag);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the short form is guarded below 0x80, and the long form writes the low two length octets of a body this encoder keeps far below 0x10000"
    )]
    match body.len() {
        len if len < 0x80 => out.push(len as u8),
        len if len <= 0xff => {
            out.push(0x81);
            out.push(len as u8);
        }
        len => {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
    }
    out.extend_from_slice(body);
    out
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    der_tlv(0x30, &parts.concat())
}

fn der_oid(oid: &[u8]) -> Vec<u8> {
    der_tlv(0x06, oid)
}

fn der_integer_zero() -> Vec<u8> {
    der_tlv(0x02, &[0])
}

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes.len() + 1);
    body.push(0x00);
    body.extend_from_slice(bytes);
    der_tlv(0x03, &body)
}

fn der_explicit(tag: u8, body: &[u8]) -> Vec<u8> {
    der_tlv(0xa0 | tag, body)
}

fn der_utc_time(text: &str) -> Vec<u8> {
    der_tlv(0x17, text.as_bytes())
}

fn ed25519_algorithm_identifier() -> Vec<u8> {
    der_sequence(&[der_oid(OID_ED25519)])
}

/// Builds the DER bytes of a minimal self-signed Ed25519 certificate: empty subject/issuer,
/// serial number 0, a fixed one-year validity window, and a signature field that is *not* a real
/// Ed25519 signature -- it is exactly `hmac`, overwriting the certificate DER's trailing 64 bytes.
/// The signature's ASN.1 `BIT STRING` header (tag, length, zero unused-bits byte) is stable
/// because every other field here has a fixed size, so the trailing-64-bytes assumption holds.
pub(crate) fn build_fake_leaf(ed25519_public: &[u8; 32], hmac_signature: &[u8; 64]) -> Vec<u8> {
    let public_key_info = der_sequence(&[ed25519_algorithm_identifier(), der_bit_string(ed25519_public)]);
    let tbs = der_sequence(&[
        der_explicit(0, &der_integer_zero()), // version: v1 is the default, but be explicit
        der_integer_zero(),                   // serialNumber
        ed25519_algorithm_identifier(),       // signature (AlgorithmIdentifier)
        der_sequence(&[]),                    // issuer: empty RDNSequence
        der_sequence(&[der_utc_time("700101000000Z"), der_utc_time("700101000000Z")]), // validity
        der_sequence(&[]),                    // subject: empty RDNSequence
        public_key_info,
    ]);
    let mut cert = der_sequence(&[tbs, ed25519_algorithm_identifier(), der_bit_string(&[0u8; 64])]);
    let signature_start = cert.len() - 64;
    let (_, signature_field) = cert.split_at_mut(signature_start);
    signature_field.copy_from_slice(hmac_signature);
    cert
}

pub(crate) fn hmac_signature(auth_key: &[u8], ed25519_public: &[u8; 32]) -> [u8; 64] {
    #[expect(clippy::expect_used, reason = "HMAC accepts a key of any length, so `new_from_slice` cannot fail")]
    let mut mac = Hmac::<Sha512>::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(ed25519_public);
    mac.finalize().into_bytes().into()
}

/// A minimal, non-recursive-descent-general DER reader: just enough to walk into an arbitrary
/// leaf certificate's `TBSCertificate.subjectPublicKeyInfo` (to check for an Ed25519 key) and
/// the outer `Certificate.signatureValue`, without depending on this crate's own encoder's exact
/// layout (the peer's cert may come from a different REALITY implementation).
struct DerReader<'a> {
    buf: &'a [u8],
}

impl<'a> DerReader<'a> {
    fn tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let (&tag, after_tag) = self.buf.split_first().ok_or_else(|| anyhow!("DER: truncated tag/length"))?;
        let (&length_byte, after_length) =
            after_tag.split_first().ok_or_else(|| anyhow!("DER: truncated tag/length"))?;
        let (len, after_header) = match length_byte {
            len if len < 0x80 => (usize::from(len), after_length),
            0x81 => {
                let (&len_byte, rest) =
                    after_length.split_first().ok_or_else(|| anyhow!("DER: truncated long-form length"))?;
                (usize::from(len_byte), rest)
            }
            0x82 => {
                let (len_bytes, rest) =
                    after_length.split_at_checked(2).ok_or_else(|| anyhow!("DER: truncated long-form length"))?;
                let len = <[u8; 2]>::try_from(len_bytes).map_err(|_| anyhow!("DER: truncated long-form length"))?;
                (usize::from(u16::from_be_bytes(len)), rest)
            }
            other => return Err(anyhow!("DER: unsupported length form {other:#x}")),
        };
        let (value, rest) =
            after_header.split_at_checked(len).ok_or_else(|| anyhow!("DER: value shorter than declared length"))?;
        self.buf = rest;
        Ok((tag, value))
    }
}

/// Extracts `(ed25519_public_key, outer_signature)` from an arbitrary leaf certificate DER, or
/// `None` if its `SubjectPublicKeyInfo` algorithm is not Ed25519.
pub(crate) fn parse_ed25519_leaf(cert_der: &[u8]) -> Result<Option<([u8; 32], [u8; 64])>> {
    let mut outer = DerReader { buf: cert_der };
    let (tag, cert_body) = outer.tlv()?;
    if tag != 0x30 {
        return Err(anyhow!("DER: certificate is not a SEQUENCE"));
    }
    let mut cert_fields = DerReader { buf: cert_body };
    let (tbs_tag, tbs_body) = cert_fields.tlv()?;
    if tbs_tag != 0x30 {
        return Err(anyhow!("DER: tbsCertificate is not a SEQUENCE"));
    }
    let (_sig_alg_tag, _sig_alg_body) = cert_fields.tlv()?;
    let (sig_tag, sig_body) = cert_fields.tlv()?;
    if sig_tag != 0x03 || sig_body.is_empty() {
        return Err(anyhow!("DER: signatureValue is not a BIT STRING"));
    }
    let Some(signature_bytes) = sig_body.get(1..) else {
        return Err(anyhow!("DER: signatureValue is not a BIT STRING"));
    };
    if signature_bytes.len() != 64 {
        return Err(anyhow!("DER: signatureValue is {} bytes, want 64 (Ed25519)", signature_bytes.len()));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(signature_bytes);

    let mut tbs_fields = DerReader { buf: tbs_body };
    loop {
        let Ok((tag, body)) = tbs_fields.tlv() else { return Ok(None) };
        if tag != 0x30 {
            continue;
        }
        // The first SEQUENCE-of-SEQUENCE-with-an-OID-first-field whose OID is Ed25519's
        // AlgorithmIdentifier, immediately followed by a BIT STRING, is subjectPublicKeyInfo.
        let mut inner = DerReader { buf: body };
        let Ok((alg_tag, alg_body)) = inner.tlv() else { continue };
        if alg_tag != 0x30 {
            continue;
        }
        let mut alg_fields = DerReader { buf: alg_body };
        let Ok((oid_tag, oid_body)) = alg_fields.tlv() else { continue };
        if oid_tag != 0x06 || oid_body != OID_ED25519 {
            continue;
        }
        let Ok((key_tag, key_body)) = inner.tlv() else { continue };
        if key_tag != 0x03 || key_body.len() != 33 {
            continue;
        }
        let Some(key_bytes) = key_body.get(1..) else { continue };
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(key_bytes);
        return Ok(Some((public_key, signature)));
    }
}

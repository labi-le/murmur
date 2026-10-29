//! Minimal DER walker, scoped to exactly one job: pulling the P-256
//! `SubjectPublicKeyInfo` out of an X.509 certificate. This is not a general
//! X.509 parser -- it walks only the fixed prefix of `TBSCertificate` that
//! precedes `subjectPublicKeyInfo` and does not interpret extensions,
//! validity, or names.

use crate::error::{Result, TlsError};

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_CONTEXT_0: u8 = 0xa0;

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    rest: &'a [u8],
}

fn read_tlv(data: &[u8]) -> Result<Tlv<'_>> {
    let &tag = data.first().ok_or_else(|| TlsError::protocol("der: truncated tag"))?;
    let len_byte = *data.get(1).ok_or_else(|| TlsError::protocol("der: truncated length"))?;
    let (len, header_len) = if len_byte & 0x80 == 0 {
        (usize::from(len_byte), 2usize)
    } else {
        let n = usize::from(len_byte & 0x7f);
        if n == 0 || n > 4 {
            return Err(TlsError::protocol("der: unsupported length encoding"));
        }
        let bytes = data.get(2..2 + n).ok_or_else(|| TlsError::protocol("der: truncated long-form length"))?;
        let mut len = 0usize;
        for &b in bytes {
            len = len
                .checked_shl(8)
                .and_then(|v| v.checked_add(usize::from(b)))
                .ok_or_else(|| TlsError::protocol("der: length overflow"))?;
        }
        (len, 2 + n)
    };
    let value =
        data.get(header_len..header_len + len).ok_or_else(|| TlsError::protocol("der: value exceeds buffer"))?;
    let rest = data.get(header_len + len..).ok_or_else(|| TlsError::protocol("der: value exceeds buffer"))?;
    Ok(Tlv { tag, value, rest })
}

/// Extracts the 65-byte uncompressed SEC1 point (`0x04 || X || Y`) from a
/// DER-encoded X.509 certificate's `subjectPublicKeyInfo`, assuming (per this
/// crate's fixed scope) the key is always P-256.
///
/// Walks: `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
/// signatureValue }`, then within `tbsCertificate`: an optional `[0]`
/// EXPLICIT version, `serialNumber`, `signature`, `issuer`, `validity`,
/// `subject`, and finally `subjectPublicKeyInfo ::= SEQUENCE { algorithm,
/// subjectPublicKey BIT STRING }`.
pub(crate) fn extract_p256_spki_point(cert_der: &[u8]) -> Result<[u8; 65]> {
    let cert = read_tlv(cert_der)?;
    if cert.tag != TAG_SEQUENCE {
        return Err(TlsError::protocol("der: certificate is not a SEQUENCE"));
    }
    let tbs = read_tlv(cert.value)?;
    if tbs.tag != TAG_SEQUENCE {
        return Err(TlsError::protocol("der: tbsCertificate is not a SEQUENCE"));
    }
    let mut rest = tbs.value;

    let maybe_version = read_tlv(rest)?;
    if maybe_version.tag == TAG_CONTEXT_0 {
        rest = maybe_version.rest;
    }

    let serial = read_tlv(rest)?;
    if serial.tag != TAG_INTEGER {
        return Err(TlsError::protocol("der: expected serialNumber INTEGER"));
    }
    let sig_alg = read_tlv(serial.rest)?;
    let issuer = read_tlv(sig_alg.rest)?;
    let validity = read_tlv(issuer.rest)?;
    let subject = read_tlv(validity.rest)?;
    let spki = read_tlv(subject.rest)?;
    if spki.tag != TAG_SEQUENCE {
        return Err(TlsError::protocol("der: expected subjectPublicKeyInfo SEQUENCE"));
    }

    let algorithm = read_tlv(spki.value)?;
    let public_key_bits = read_tlv(algorithm.rest)?;
    if public_key_bits.tag != TAG_BIT_STRING {
        return Err(TlsError::protocol("der: expected subjectPublicKey BIT STRING"));
    }
    let Some((&unused_bits, point)) = public_key_bits.value.split_first() else {
        return Err(TlsError::protocol("der: empty subjectPublicKey BIT STRING"));
    };
    if unused_bits != 0 {
        return Err(TlsError::protocol("der: subjectPublicKey has non-zero unused bits"));
    }
    if point.len() != 65 || point.first() != Some(&0x04) {
        return Err(TlsError::protocol("der: subjectPublicKey is not an uncompressed P-256 point"));
    }
    let mut out = [0u8; 65];
    out.copy_from_slice(point);
    Ok(out)
}

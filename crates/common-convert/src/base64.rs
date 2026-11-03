use anyhow::anyhow;
use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::{DecodePaddingMode, Engine as _};

/// Standard alphabet, no padding, trailing bits unchecked, `\r`/`\n` ignored.
pub(crate) const ENC_RAW: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

pub(crate) const ENC: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

pub(crate) const ENC_RAW_URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

pub(crate) const ENC_URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// Decodes `data`, dropping the `\r` and `\n` bytes the decoder skips.
pub(crate) fn decode(engine: &GeneralPurpose, data: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    if data.iter().any(|b| *b == b'\r' || *b == b'\n') {
        let filtered: Vec<u8> = data.iter().copied().filter(|b| *b != b'\r' && *b != b'\n').collect();
        return engine.decode(&filtered);
    }
    engine.decode(data)
}

/// Decodes `content`, which can be unpadded or padded standard base64, or just
/// plaintext.
#[must_use]
pub fn decode_base64(buf: &[u8]) -> Vec<u8> {
    match try_decode_base64_bytes(buf) {
        Some(result) => result,
        None => buf.to_vec(),
    }
}

pub(crate) fn try_decode_base64_bytes(buf: &[u8]) -> Option<Vec<u8>> {
    match decode(&ENC_RAW, buf) {
        Ok(result) => Some(result),
        Err(_) => decode(&ENC, buf).ok(),
    }
}

pub(crate) fn url_safe(data: &str) -> String {
    data.replace('+', "-").replace('/', "_")
}

pub(crate) fn decode_url_safe(data: &str) -> String {
    match decode(&ENC_RAW_URL, data.as_bytes()) {
        Ok(decoded) => String::from_utf8_lossy(&decoded).into_owned(),
        Err(_) => String::new(),
    }
}

/// Decodes a base64 string, choosing the padded or raw alphabet by input length.
pub fn try_decode_base64(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.len().is_multiple_of(4) {
        if let Ok(decoded) = decode(&ENC, s.as_bytes()) {
            return Ok(decoded);
        }
        if let Ok(decoded) = decode(&ENC_URL, s.as_bytes()) {
            return Ok(decoded);
        }
    } else if let Ok(decoded) = decode(&ENC_RAW, s.as_bytes()) {
        return Ok(decoded);
    } else if let Ok(decoded) = decode(&ENC_RAW_URL, s.as_bytes()) {
        return Ok(decoded);
    }
    Err(anyhow!("invalid base64-encoded string"))
}

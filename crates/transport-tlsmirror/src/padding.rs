use byteorder::{BigEndian, ByteOrder};

#[expect(
    clippy::cast_possible_truncation,
    reason = "the payload is a TLS record fragment bounded by MAX_TLS_RECORD_PAYLOAD, so its length fits the 32-bit wire field"
)]
pub(crate) fn pack_padding(data: &[u8], padding_length: usize) -> Vec<u8> {
    let data_length = data.len();
    let mut out = Vec::with_capacity(data_length + padding_length + 4);
    out.extend_from_slice(data);
    out.resize(out.len() + padding_length, 0);
    let mut suffix = [0u8; 4];
    BigEndian::write_u32(&mut suffix, data_length as u32);
    out.extend_from_slice(&suffix);
    out
}

/// Unpacks padding. Returns `(None, dataLength)` / `(None, 0)` / `(None, paddingLength)` on the
/// respective failure cases, and `(Some(payload), paddingLength)` otherwise.
pub(crate) fn unpack_padding(data: &[u8]) -> (Option<&[u8]>, i64) {
    let data_length = i64::try_from(data.len()).unwrap_or(i64::MAX);
    if data_length < 4 {
        return (None, data_length);
    }
    let suffix_offset = data.len() - 4;
    let Some(suffix) = data.get(suffix_offset..).and_then(|suffix| <[u8; 4]>::try_from(suffix).ok()) else {
        return (None, data_length);
    };
    let payload_length = i64::from(u32::from_be_bytes(suffix));
    if payload_length > data_length - 4 {
        return (None, 0);
    }
    let padding_length = data_length - payload_length - 4;
    if padding_length < 0 {
        return (None, padding_length);
    }
    let Some(payload) = usize::try_from(payload_length).ok().and_then(|len| data.get(..len)) else {
        return (None, padding_length);
    };
    (Some(payload), padding_length)
}

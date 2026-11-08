//! The Restls application-record framing, shared by both peers.
//!
//! Every record carries an HMAC-authenticated header whose MAC and mask are keyed BLAKE3 over
//! the server random, the direction and the big-endian counter, followed by the record's own
//! bytes.
//!
//! [`restls_hmac`] takes every segment as a separate slice: BLAKE3's keyed hash is a plain
//! Merkle-tree hash over the concatenation of everything fed to it, so the segmentation does not
//! change the MAC.

use anyhow::{anyhow, bail, Result};
// `subtle` is not a direct dependency of this crate; `p256` re-exports it.
use p256::elliptic_curve::subtle::ConstantTimeEq;

use crate::consts::{
    RECORD_HEADER_LEN, RECORD_TYPE_APPLICATION_DATA, RESTLS_APP_DATA_AUTH_HEADER_LEN, RESTLS_APP_DATA_LEN_OFFSET,
    RESTLS_APP_DATA_MAC_LEN, RESTLS_APP_DATA_OFFSET, RESTLS_HANDSHAKE_MAC_LEN, RESTLS_MASK_LEN,
};
use crate::script::Command;

/// Keyed BLAKE3 fed every part in order.
fn restls_hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Derives the 32-byte Restls traffic key from `password` with the `"restls-traffic-key"` context.
#[must_use]
pub fn derive_restls_secret(password: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    blake3::Hasher::new_derive_key("restls-traffic-key").update(password).finalize_xof().fill(&mut out);
    out
}

fn direction_label(to_client: bool) -> &'static [u8] {
    if to_client {
        b"server-to-client"
    } else {
        b"client-to-server"
    }
}

fn xor_with_mac(buf: &mut [u8], mac: &[u8]) {
    for (byte, mask_byte) in buf.iter_mut().zip(mac.iter().cycle()) {
        *byte ^= *mask_byte;
    }
}

/// XORs the first 16 bytes right after the record header.
///
/// The mask is the first 16 bytes of the keyed HMAC over the server random — applied by the relay
/// server to the target's genuine first post-ServerHello encrypted record, and undone by the
/// client's trial decrypt.
pub fn mask_server_auth(secret: &[u8; 32], server_random: &[u8; 32], record: &mut [u8]) {
    let mac = restls_hmac(secret, &[server_random]);
    let payload = record.get_mut(RECORD_HEADER_LEN..).unwrap_or_default();
    for (byte, mask_byte) in payload.iter_mut().take(RESTLS_HANDSHAKE_MAC_LEN).zip(mac.iter()) {
        *byte ^= *mask_byte;
    }
}

/// Builds one Restls-framed application_data record body (after the 5-byte record header):
/// `[8-byte auth MAC][2-byte masked len][2-byte masked command][data][padding]`.
///
/// `client_finished` is the raw on-wire bytes of the real client `Finished` record, mixed into
/// the very first record's auth MAC in either direction and then consumed; pass `None` after the
/// first call.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn write_record(
    secret: &[u8; 32],
    server_random: &[u8; 32],
    to_client: bool,
    counter: u64,
    client_finished: Option<&[u8]>,
    data: &[u8],
    target_len: usize,
    command: Command,
) -> Vec<u8> {
    write_record_with_nonce(
        secret,
        server_random,
        to_client,
        counter,
        client_finished,
        data,
        target_len,
        command,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
#[expect(clippy::cast_possible_truncation, reason = "record lengths are 16-bit wire fields")]
#[must_use]
pub fn write_record_with_nonce(
    secret: &[u8; 32],
    server_random: &[u8; 32],
    to_client: bool,
    counter: u64,
    client_finished: Option<&[u8]>,
    data: &[u8],
    target_len: usize,
    command: Command,
    nonce: bool,
) -> Vec<u8> {
    let data_len = data.len().min(target_len);
    let padding_len = target_len.saturating_sub(data_len);
    let nonce_len = if nonce { 8 } else { 0 };
    let payload_len = nonce_len + RESTLS_APP_DATA_AUTH_HEADER_LEN + data_len + padding_len;

    let mut record = vec![0u8; RECORD_HEADER_LEN + payload_len];
    let [len_hi, len_lo] = (payload_len as u16).to_be_bytes();
    let (header, body) = record.split_at_mut(RECORD_HEADER_LEN);
    header.copy_from_slice(&[RECORD_TYPE_APPLICATION_DATA, 0x03, 0x03, len_hi, len_lo]);

    let offset = RECORD_HEADER_LEN + nonce_len;
    let (nonce_field, payload) = body.split_at_mut(nonce_len);
    if nonce {
        nonce_field.copy_from_slice(&(counter + 1).to_be_bytes());
    }
    let (_, plaintext) = payload.split_at_mut(RESTLS_APP_DATA_OFFSET);
    let (data_field, padding_field) = plaintext.split_at_mut(data_len);
    data_field.copy_from_slice(data.split_at(data_len).0);
    if padding_len > 0 {
        rand::Rng::fill(&mut rand::rng(), padding_field);
    }

    let counter_be = counter.to_be_bytes();
    let direction = direction_label(to_client);

    let sample_end = RESTLS_APP_DATA_OFFSET + (data_len + padding_len).min(32);
    let mask = {
        let sample = payload.get(RESTLS_APP_DATA_OFFSET..sample_end).unwrap_or_default();
        restls_hmac(secret, &[server_random, direction, &counter_be, sample])
    };

    let [data_hi, data_lo] = (data_len as u16).to_be_bytes();
    let [cmd_hi, cmd_lo] = command.to_bytes();
    let mut masked_header = [data_hi, data_lo, cmd_hi, cmd_lo];
    xor_with_mac(&mut masked_header, &mask[..RESTLS_MASK_LEN]);
    let (_, masked) = payload.split_at_mut(RESTLS_APP_DATA_LEN_OFFSET);
    let (masked_field, _) = masked.split_at_mut(RESTLS_MASK_LEN);
    masked_field.copy_from_slice(&masked_header);

    let auth_mac = match client_finished {
        Some(cf) => restls_hmac(
            secret,
            &[
                server_random,
                direction,
                &counter_be,
                cf,
                record.get(..offset).unwrap_or_default(),
                record.get(offset + RESTLS_APP_DATA_LEN_OFFSET..).unwrap_or_default(),
            ],
        ),
        None => restls_hmac(
            secret,
            &[
                server_random,
                direction,
                &counter_be,
                record.get(..offset).unwrap_or_default(),
                record.get(offset + RESTLS_APP_DATA_LEN_OFFSET..).unwrap_or_default(),
            ],
        ),
    };
    let (_, auth) = record.split_at_mut(offset);
    let (mac_field, _) = auth.split_at_mut(RESTLS_APP_DATA_MAC_LEN);
    mac_field.copy_from_slice(&auth_mac[..RESTLS_APP_DATA_MAC_LEN]);

    record
}

#[derive(Debug)]
pub struct ReadResult {
    pub data_len: usize,
    pub command: Command,
    pub data_offset: usize,
}

/// Verifies and unmasks a Restls-framed application_data record in place.
///
/// Returns where the plaintext data starts/ends within `record`. `to_client_expected` is the
/// direction the record travelled (i.e. `true` when this side is the client reading from the
/// server).
pub fn read_record(
    secret: &[u8; 32],
    server_random: &[u8; 32],
    to_client_expected: bool,
    counter: u64,
    client_finished: Option<&[u8]>,
    record: &mut [u8],
) -> Result<ReadResult> {
    read_record_with_nonce(secret, server_random, to_client_expected, counter, client_finished, record, false)
}

pub fn read_record_with_nonce(
    secret: &[u8; 32],
    server_random: &[u8; 32],
    to_client_expected: bool,
    counter: u64,
    client_finished: Option<&[u8]>,
    record: &mut [u8],
    nonce: bool,
) -> Result<ReadResult> {
    let offset = RECORD_HEADER_LEN + if nonce { 8 } else { 0 };
    if record.len() < offset + RESTLS_APP_DATA_AUTH_HEADER_LEN
        || !matches!(record.get(..RECORD_HEADER_LEN), Some([RECORD_TYPE_APPLICATION_DATA, 0x03, 0x03, ..]))
        || (nonce && record.get(RECORD_HEADER_LEN..offset) != Some((counter + 1).to_be_bytes().as_slice()))
    {
        bail!("restls: bad record MAC");
    }

    let counter_be = counter.to_be_bytes();
    let direction = direction_label(to_client_expected);

    let expect_auth = match client_finished {
        Some(cf) => restls_hmac(
            secret,
            &[
                server_random,
                direction,
                &counter_be,
                cf,
                record.get(..offset).unwrap_or_default(),
                record.get(offset + RESTLS_APP_DATA_LEN_OFFSET..).unwrap_or_default(),
            ],
        ),
        None => restls_hmac(
            secret,
            &[
                server_random,
                direction,
                &counter_be,
                record.get(..offset).unwrap_or_default(),
                record.get(offset + RESTLS_APP_DATA_LEN_OFFSET..).unwrap_or_default(),
            ],
        ),
    };
    let Some(payload) = record.get_mut(offset..) else {
        bail!("restls: bad record MAC");
    };
    let Some(received_mac) = payload.get(..RESTLS_APP_DATA_MAC_LEN) else {
        bail!("restls: bad record MAC");
    };
    if !bool::from(received_mac.ct_eq(&expect_auth[..RESTLS_APP_DATA_MAC_LEN])) {
        bail!("restls: bad record MAC");
    }

    let sample_end = RESTLS_APP_DATA_OFFSET + (payload.len() - RESTLS_APP_DATA_OFFSET).min(32);
    let mask = {
        let sample = payload.get(RESTLS_APP_DATA_OFFSET..sample_end).unwrap_or_default();
        restls_hmac(secret, &[server_random, direction, &counter_be, sample])
    };
    let Some(masked_header) = payload.get_mut(RESTLS_APP_DATA_LEN_OFFSET..RESTLS_APP_DATA_OFFSET) else {
        bail!("restls: bad record MAC");
    };
    xor_with_mac(masked_header, &mask[..RESTLS_MASK_LEN]);

    let Some(data_len_field) = payload
        .get(RESTLS_APP_DATA_LEN_OFFSET..RESTLS_APP_DATA_LEN_OFFSET + 2)
        .and_then(|field| <[u8; 2]>::try_from(field).ok())
    else {
        bail!("restls: bad record MAC");
    };
    let data_len = usize::from(u16::from_be_bytes(data_len_field));
    let command = Command::from_bytes(payload.get(RESTLS_APP_DATA_LEN_OFFSET + 2..).unwrap_or_default())
        .map_err(|_| anyhow!("restls: bad record MAC"))?;
    if data_len > payload.len() - RESTLS_APP_DATA_OFFSET {
        bail!("restls: bad record MAC");
    }
    Ok(ReadResult { data_len, command, data_offset: offset + RESTLS_APP_DATA_OFFSET })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls12_nonce_is_authenticated_and_required() {
        let secret = [7; 32];
        let random = [9; 32];
        let mut record = write_record_with_nonce(&secret, &random, false, 0, None, b"hello", 18, Command::Noop, true);
        assert_eq!(&record[5..13], &1u64.to_be_bytes());
        let result = read_record_with_nonce(&secret, &random, false, 0, None, &mut record, true).unwrap();
        assert_eq!(&record[result.data_offset..result.data_offset + result.data_len], b"hello");
        let mut corrupt = write_record_with_nonce(&secret, &random, false, 0, None, b"hello", 18, Command::Noop, true);
        corrupt[12] = 2;
        assert!(read_record_with_nonce(&secret, &random, false, 0, None, &mut corrupt, true).is_err());
    }

    /// The record MAC is decided byte-for-byte: a sealed record opens, and a MAC that differs in
    /// its last byte, was sealed under another key, or was cut short is rejected.
    #[test]
    fn the_record_mac_rejects_any_byte_difference() {
        let secret = [7; 32];
        let random = [9; 32];
        let mut record = write_record(&secret, &random, false, 0, None, b"hello", 18, Command::Noop);
        let result = read_record(&secret, &random, false, 0, None, &mut record).expect("a sealed record opens");
        assert_eq!(&record[result.data_offset..result.data_offset + result.data_len], b"hello");

        let mut one_byte_off = write_record(&secret, &random, false, 0, None, b"hello", 18, Command::Noop);
        one_byte_off[RECORD_HEADER_LEN + RESTLS_APP_DATA_MAC_LEN - 1] ^= 1;
        assert!(read_record(&secret, &random, false, 0, None, &mut one_byte_off).is_err(), "a MAC off by one byte");

        let mut other_key = write_record(&[8; 32], &random, false, 0, None, b"hello", 18, Command::Noop);
        assert!(read_record(&secret, &random, false, 0, None, &mut other_key).is_err(), "another key");

        let mut truncated = write_record(&secret, &random, false, 0, None, b"hello", 18, Command::Noop);
        truncated.truncate(RECORD_HEADER_LEN + RESTLS_APP_DATA_MAC_LEN);
        assert!(read_record(&secret, &random, false, 0, None, &mut truncated).is_err(), "a cut-short record");
    }
}

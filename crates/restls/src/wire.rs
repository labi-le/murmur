//! Raw TLS record I/O shared by the client and server handshake phases: reading one record with
//! its 5-byte header, and testing whether a byte starts a plausible TLS record.

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::consts::{
    MAX_PLAINTEXT, RECORD_HEADER_LEN, RECORD_TYPE_ALERT, RECORD_TYPE_APPLICATION_DATA, RECORD_TYPE_CHANGE_CIPHER_SPEC,
    RECORD_TYPE_HANDSHAKE, VERSION_TLS13,
};

const MAX_CIPHERTEXT: usize = 16384 + 2048;

fn is_tls_record_type(t: u8) -> bool {
    matches!(
        t,
        RECORD_TYPE_CHANGE_CIPHER_SPEC | RECORD_TYPE_ALERT | RECORD_TYPE_HANDSHAKE | RECORD_TYPE_APPLICATION_DATA
    )
}

/// Reads one full TLS record (header + payload) off `stream`, returning the raw bytes.
pub async fn read_tls_record<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Vec<u8>> {
    read_tls_record_preserving(stream).await.map_err(|(_, err)| err)
}

pub async fn read_tls_record_preserving<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> std::result::Result<Vec<u8>, (Vec<u8>, anyhow::Error)> {
    let mut record = Vec::with_capacity(RECORD_HEADER_LEN);
    while record.len() < RECORD_HEADER_LEN {
        let mut header = [0u8; RECORD_HEADER_LEN];
        let (slot, _) = header.split_at_mut(RECORD_HEADER_LEN - record.len());
        match stream.read(slot).await {
            Ok(0) => return Err((record, anyhow!("restls: connection closed while reading TLS record"))),
            Ok(n) => record.extend_from_slice(slot.get(..n).unwrap_or_default()),
            Err(err) => return Err((record, err.into())),
        }
    }
    let header: [u8; RECORD_HEADER_LEN] = record.as_slice().try_into().unwrap_or_default();
    let [record_type, version_hi, version_lo, len_hi, len_lo] = header;
    let payload_len = usize::from(len_hi) << 8 | usize::from(len_lo);
    let version = u16::from(version_hi) << 8 | u16::from(version_lo);
    if !is_tls_record_type(record_type) || !(0x0300..=VERSION_TLS13).contains(&version) || payload_len > MAX_CIPHERTEXT
    {
        return Err((record, anyhow!("restls: invalid TLS record header")));
    }
    record.reserve(payload_len);
    let mut scratch = [0u8; 4096];
    while record.len() < RECORD_HEADER_LEN + payload_len {
        let remaining = (RECORD_HEADER_LEN + payload_len - record.len()).min(scratch.len());
        let (slot, _) = scratch.split_at_mut(remaining);
        match stream.read(slot).await {
            Ok(0) => return Err((record, anyhow!("restls: connection closed while reading TLS record"))),
            Ok(n) => record.extend_from_slice(slot.get(..n).unwrap_or_default()),
            Err(err) => return Err((record, err.into())),
        }
    }
    Ok(record)
}

pub async fn write_tls_record<W: AsyncWrite + Unpin>(stream: &mut W, record_type: u8, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_PLAINTEXT + 256 {
        bail!("restls: outgoing TLS record too large");
    }
    let mut record = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
    record.push(record_type);
    record.push(0x03);
    record.push(0x03);
    let len = u16::try_from(payload.len()).map_err(|_| anyhow!("restls: outgoing TLS record too large"))?;
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(payload);
    stream.write_all(&record).await?;
    Ok(())
}

pub fn record_type(record: &[u8]) -> Result<u8> {
    record.first().copied().ok_or_else(|| anyhow!("restls: empty record"))
}

#[must_use]
pub fn record_payload(record: &[u8]) -> &[u8] {
    record.get(RECORD_HEADER_LEN..).unwrap_or_default()
}

#[must_use]
#[expect(clippy::expect_used, reason = "`record` holds a full header once `read_tls_record` returns it")]
pub fn record_header(record: &[u8]) -> [u8; RECORD_HEADER_LEN] {
    record.first_chunk::<RECORD_HEADER_LEN>().copied().expect("record has a header")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_header_returns_consumed_prefix_without_waiting_for_payload() {
        let (mut reader, mut writer) = tokio::io::duplex(64);
        writer.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let (prefix, _) = read_tls_record_preserving(&mut reader).await.unwrap_err();
        assert_eq!(prefix, b"GET /");
    }

    #[tokio::test]
    async fn truncated_record_returns_all_consumed_bytes() {
        let (mut reader, mut writer) = tokio::io::duplex(64);
        writer.write_all(&[22, 3, 3, 0, 4, 1, 2]).await.unwrap();
        drop(writer);
        let (prefix, _) = read_tls_record_preserving(&mut reader).await.unwrap_err();
        assert_eq!(prefix, &[22, 3, 3, 0, 4, 1, 2]);
    }
}

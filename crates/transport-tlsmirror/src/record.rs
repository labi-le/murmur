use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const RECORD_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub(crate) const RECORD_TYPE_ALERT: u8 = 21;
pub(crate) const RECORD_TYPE_HANDSHAKE: u8 = 22;
pub(crate) const RECORD_TYPE_APPLICATION_DATA: u8 = 23;

pub(crate) const MAX_TLS_RECORD_PAYLOAD: usize = 16384;

#[derive(Clone, Debug)]
#[expect(clippy::struct_field_names, reason = "the fields keep the TLS record header's terminology")]
pub(crate) struct Record {
    pub(crate) record_type: u8,
    pub(crate) version: [u8; 2],
    pub(crate) fragment: Vec<u8>,
    pub(crate) inserted: bool,
}

/// Reads one record. Returns `(None, raw, Err(_))` when the header cannot be read in full.
pub(crate) async fn read_record<R>(reader: &mut R) -> (Option<Record>, Vec<u8>, Result<()>)
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    if let Err((n, err)) = read_full(reader, &mut header).await {
        return (None, header.get(..n).unwrap_or_default().to_vec(), Err(err));
    }
    let [record_type, version_hi, version_lo, length_hi, length_lo] = header;
    let length = usize::from(u16::from_be_bytes([length_hi, length_lo]));
    if length > MAX_TLS_RECORD_PAYLOAD {
        return (None, header.to_vec(), Err(anyhow!("tlsmirror: tls record is too large")));
    }
    let mut fragment = vec![0u8; length];
    let (n, read_err) = match read_full(reader, &mut fragment).await {
        Ok(n) => (n, None),
        Err((n, err)) => (n, Some(err)),
    };
    let mut raw = Vec::with_capacity(header.len() + n);
    raw.extend_from_slice(&header);
    raw.extend_from_slice(fragment.get(..n).unwrap_or_default());
    if let Some(err) = read_err {
        return (None, raw, Err(err));
    }
    let record = Record { record_type, version: [version_hi, version_lo], fragment, inserted: false };
    (Some(record), raw, Ok(()))
}

/// Reads exactly `buf.len()` bytes, returning the bytes actually read alongside any error.
async fn read_full<R>(reader: &mut R, buf: &mut [u8]) -> std::result::Result<usize, (usize, anyhow::Error)>
where
    R: AsyncRead + Unpin,
{
    let mut read = 0;
    while read < buf.len() {
        let (_, remaining) = buf.split_at_mut(read);
        match reader.read(remaining).await {
            Ok(0) => {
                let err = if read == 0 { anyhow!("EOF") } else { anyhow!("unexpected EOF") };
                return Err((read, err));
            }
            Ok(n) => read += n,
            Err(err) => return Err((read, anyhow::Error::from(err))),
        }
    }
    Ok(read)
}

pub(crate) async fn write_record<W>(writer: &mut W, rec: &Record) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if rec.fragment.len() > MAX_TLS_RECORD_PAYLOAD {
        return Err(anyhow!("tlsmirror: tls record is too large"));
    }
    let length = u16::try_from(rec.fragment.len()).map_err(|_| anyhow!("tlsmirror: tls record is too large"))?;
    let [length_hi, length_lo] = length.to_be_bytes();
    let header = [rec.record_type, rec.version[0], rec.version[1], length_hi, length_lo];
    writer.write_all(&header).await?;
    writer.write_all(&rec.fragment).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) fn duplicate_record(rec: &Record) -> Record {
    Record {
        record_type: rec.record_type,
        version: rec.version,
        fragment: rec.fragment.clone(),
        inserted: rec.inserted,
    }
}

pub(crate) fn parse_client_random(fragment: &[u8]) -> Result<[u8; 32]> {
    if fragment.first() != Some(&1) {
        return Err(anyhow!("tlsmirror: invalid client hello"));
    }
    let Some(random) = fragment.get(6..38).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) else {
        return Err(anyhow!("tlsmirror: invalid client hello"));
    };
    Ok(random)
}

pub(crate) fn parse_server_hello(fragment: &[u8]) -> Result<([u8; 32], u16)> {
    if fragment.len() < 41 || fragment.first() != Some(&2) {
        return Err(anyhow!("tlsmirror: invalid server hello"));
    }
    let Some(random) = fragment.get(6..38).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) else {
        return Err(anyhow!("tlsmirror: invalid server hello"));
    };
    let Some(session_id_len) = fragment.get(38).copied().map(usize::from) else {
        return Err(anyhow!("tlsmirror: invalid server hello"));
    };
    let cipher_suite_offset = 39 + session_id_len;
    let Some(cipher_suite) =
        fragment.get(cipher_suite_offset..cipher_suite_offset + 2).and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
    else {
        return Err(anyhow!("tlsmirror: invalid server hello session id"));
    };
    Ok((random, u16::from_be_bytes(cipher_suite)))
}

pub(crate) fn has_zero_explicit_nonce(fragment: &[u8]) -> bool {
    fragment.get(..8).is_some_and(|nonce| nonce.iter().all(|&b| b == 0))
}

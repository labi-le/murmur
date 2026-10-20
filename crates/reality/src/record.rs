//! TLS 1.3 record layer (RFC 8446 §5): plaintext records for `ClientHello`/`ServerHello`, then
//! every later handshake message and all application data travels inside a `TLSInnerPlaintext`
//! wrapped in an outer `application_data`-typed record (RFC 8446 §5.2), encrypted with whichever
//! traffic secret is current for that direction.
//!
//! [`RecordLayer`] is used single-threaded during the handshake (one party talks, then listens,
//! never both at once). [`RecordLayer::split`] hands off to independent [`RecordReader`]/
//! [`RecordWriter`] halves for the application-data phase, where [`crate::stream::RealityStream`]
//! needs `AsyncRead` and `AsyncWrite` pollable concurrently.

use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::handshake::{CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE};
use crate::suite::{record_nonce, CipherSuite};

const MAX_FRAGMENT: usize = 16384;
const RECORD_HEADER_LEN: usize = 5;
const LEGACY_RECORD_VERSION: u16 = 0x0303;

struct TrafficKeys {
    suite: CipherSuite,
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
}

impl TrafficKeys {
    fn new(suite: CipherSuite, key: Vec<u8>, iv: [u8; 12]) -> Self {
        Self { suite, key, iv, seq: 0 }
    }
}

/// Redacts the traffic key and IV.
impl core::fmt::Debug for TrafficKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrafficKeys")
            .field("suite", &self.suite)
            .field("key", &"<redacted>")
            .field("iv", &"<redacted>")
            .field("seq", &self.seq)
            .finish()
    }
}

async fn write_raw_record<W: AsyncWrite + Unpin>(
    inner: &mut W,
    content_type: u8,
    payload: &[u8],
    record: &mut Vec<u8>,
) -> Result<()> {
    let mut header = [0u8; RECORD_HEADER_LEN];
    header[0] = content_type;
    header[1..3].copy_from_slice(&LEGACY_RECORD_VERSION.to_be_bytes());
    let Ok(payload_len) = u16::try_from(payload.len()) else {
        return Err(anyhow!("REALITY record layer: oversized record to write ({} bytes)", payload.len()));
    };
    header[3..5].copy_from_slice(&payload_len.to_be_bytes());
    record.clear();
    record.extend_from_slice(&header);
    record.extend_from_slice(payload);
    // Keep the record header and body in one write. A standalone
    // five-byte header packet is rejected by some REALITY-facing network paths.
    inner.write_all(record).await?;
    inner.flush().await?;
    Ok(())
}

async fn write_encrypted<W: AsyncWrite + Unpin>(
    inner: &mut W,
    keys: &mut TrafficKeys,
    content_type: u8,
    content: &[u8],
    record: &mut Vec<u8>,
) -> Result<()> {
    for chunk in content.chunks(MAX_FRAGMENT - 1) {
        let mut inner_plaintext = Vec::with_capacity(chunk.len() + 1);
        inner_plaintext.extend_from_slice(chunk);
        inner_plaintext.push(content_type);

        let nonce = record_nonce(&keys.iv, keys.seq);
        keys.seq += 1;
        let record_len = inner_plaintext.len() + 16;
        let Ok(header_len) = u16::try_from(record_len) else {
            return Err(anyhow!("REALITY record layer: oversized record to write ({record_len} bytes)"));
        };
        let mut header = [0u8; RECORD_HEADER_LEN];
        header[0] = CONTENT_TYPE_APPLICATION_DATA;
        header[1..3].copy_from_slice(&LEGACY_RECORD_VERSION.to_be_bytes());
        header[3..5].copy_from_slice(&header_len.to_be_bytes());
        let ciphertext = keys.suite.seal(&keys.key, &nonce, &inner_plaintext, &header)?;

        record.clear();
        record.extend_from_slice(&header);
        record.extend_from_slice(&ciphertext);
        inner.write_all(record).await?;
    }
    inner.flush().await?;
    Ok(())
}

async fn read_record<R: AsyncRead + Unpin>(inner: &mut R, keys: &mut Option<TrafficKeys>) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; RECORD_HEADER_LEN];
    inner.read_exact(&mut header).await?;
    let outer_type = header[0];
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > MAX_FRAGMENT + 256 {
        return Err(anyhow!("REALITY record layer: oversized record ({len} bytes)"));
    }
    let mut payload = vec![0u8; len];
    inner.read_exact(&mut payload).await?;

    if outer_type != CONTENT_TYPE_APPLICATION_DATA {
        return Ok((outer_type, payload));
    }
    let keys =
        keys.as_mut().ok_or_else(|| anyhow!("REALITY record layer: encrypted record before read keys were set"))?;
    let nonce = record_nonce(&keys.iv, keys.seq);
    keys.seq += 1;
    let mut plaintext = keys.suite.open(&keys.key, &nonce, &payload, &header)?;
    // RFC 8446 §5.2: the content type is the last non-zero octet, not the last byte -- a REALITY
    // server pads every handshake record to the length its `dest` used for the same message.
    let content_type_pos = plaintext
        .iter()
        .rposition(|byte| *byte != 0)
        .ok_or_else(|| anyhow!("REALITY record layer: TLSInnerPlaintext without a content type"))?;
    let content_type = plaintext
        .get(content_type_pos)
        .copied()
        .ok_or_else(|| anyhow!("REALITY record layer: TLSInnerPlaintext without a content type"))?;
    // Truncating in place keeps the allocation AEAD already made instead of copying the payload
    // into a second `Vec` and dropping the first. The padding and tag capacity stays attached
    // until the consumer drops the record, and only one record is held per connection.
    plaintext.truncate(content_type_pos);
    Ok((content_type, plaintext))
}

/// A REALITY handshake's record layer over an arbitrary byte stream, before the application-data
/// phase splits it. Read/write keys are set independently and mid-stream (handshake keys, then
/// application keys), each resetting its own sequence number to 0 per RFC 8446 §5.3.
#[derive(Debug)]
pub struct RecordLayer<S> {
    inner: S,
    read_keys: Option<TrafficKeys>,
    write_keys: Option<TrafficKeys>,
    handshake_read_buf: Vec<u8>,
    write_record: Vec<u8>,
}

impl<S> RecordLayer<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, read_keys: None, write_keys: None, handshake_read_buf: Vec::new(), write_record: Vec::new() }
    }

    pub fn set_read_keys(&mut self, suite: CipherSuite, key: Vec<u8>, iv: [u8; 12]) {
        self.read_keys = Some(TrafficKeys::new(suite, key, iv));
    }

    pub fn set_write_keys(&mut self, suite: CipherSuite, key: Vec<u8>, iv: [u8; 12]) {
        self.write_keys = Some(TrafficKeys::new(suite, key, iv));
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncWrite + Unpin> RecordLayer<S> {
    pub async fn write_plaintext_handshake(&mut self, msg: &[u8]) -> Result<()> {
        for chunk in msg.chunks(MAX_FRAGMENT) {
            write_raw_record(&mut self.inner, CONTENT_TYPE_HANDSHAKE, chunk, &mut self.write_record).await?;
        }
        Ok(())
    }

    /// Writes `content` as one or more encrypted records of the given inner content type
    /// (Handshake for a handshake message after ServerHello, ApplicationData for the tunneled
    /// payload once application keys are set).
    pub async fn write_encrypted(&mut self, content_type: u8, content: &[u8]) -> Result<()> {
        let keys = self.write_keys.as_mut().ok_or_else(|| anyhow!("REALITY record layer: no write keys set"))?;
        write_encrypted(&mut self.inner, keys, content_type, content, &mut self.write_record).await
    }
}

impl<S: AsyncRead + Unpin> RecordLayer<S> {
    pub async fn read_record(&mut self) -> Result<(u8, Vec<u8>)> {
        read_record(&mut self.inner, &mut self.read_keys).await
    }

    /// Reads and reassembles exactly one handshake message, buffering across as many records as
    /// its declared length needs.
    pub async fn read_handshake_message(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some(head) = self.handshake_read_buf.get(..4) {
                let mut prefix = [0u8; 4];
                prefix.copy_from_slice(head);
                let [_, b1, b2, b3] = prefix;
                let declared = 4 + u32::from_be_bytes([0, b1, b2, b3]) as usize;
                if self.handshake_read_buf.len() >= declared {
                    let msg: Vec<u8> = self.handshake_read_buf.drain(..declared).collect();
                    return Ok(msg);
                }
            }
            let (content_type, payload) = self.read_record().await?;
            match content_type {
                CONTENT_TYPE_HANDSHAKE => self.handshake_read_buf.extend_from_slice(&payload),
                crate::handshake::CONTENT_TYPE_CHANGE_CIPHER_SPEC => {} // RFC 8446 §5's middlebox-compat no-op
                crate::handshake::CONTENT_TYPE_ALERT => {
                    return Err(anyhow!("REALITY handshake: peer sent a TLS alert"))
                }
                other => return Err(anyhow!("REALITY handshake: unexpected record content type {other}")),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> RecordLayer<S> {
    /// Hands off to independent halves for the application-data phase, where reads and writes
    /// must be concurrently pollable.
    pub fn split(self) -> (RecordReader<ReadHalf<S>>, RecordWriter<WriteHalf<S>>) {
        let (read_half, write_half) = tokio::io::split(self.inner);
        (
            RecordReader { inner: read_half, keys: self.read_keys, handshake_buf: self.handshake_read_buf },
            RecordWriter { inner: write_half, keys: self.write_keys, write_record: self.write_record },
        )
    }
}

#[derive(Debug)]
pub struct RecordReader<R> {
    inner: R,
    keys: Option<TrafficKeys>,
    #[allow(
        dead_code,
        reason = "carried across the reader/writer split for symmetry; the application phase never has a partial handshake message pending"
    )]
    handshake_buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> RecordReader<R> {
    pub async fn read_record(&mut self) -> Result<(u8, Vec<u8>)> {
        read_record(&mut self.inner, &mut self.keys).await
    }
}

impl<R> RecordReader<R> {
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

#[derive(Debug)]
pub struct RecordWriter<W> {
    inner: W,
    keys: Option<TrafficKeys>,
    write_record: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> RecordWriter<W> {
    pub async fn write_encrypted(&mut self, content_type: u8, content: &[u8]) -> Result<()> {
        let keys = self.keys.as_mut().ok_or_else(|| anyhow!("REALITY record layer: no write keys set"))?;
        write_encrypted(&mut self.inner, keys, content_type, content, &mut self.write_record).await
    }
}

impl<W> RecordWriter<W> {
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

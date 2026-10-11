//! TLS 1.3 record layer (RFC 8446 §5), fixed to `TLS_AES_128_GCM_SHA256`.
//!
//! Handles: `TLSPlaintext` framing, `TLSInnerPlaintext`/`TLSCiphertext`
//! AEAD wrapping for post-handshake-secret records, handshake-message
//! reassembly across record boundaries, and discarding the middlebox
//! `ChangeCipherSpec` record (RFC 8446 Appendix D.4) without ever running it
//! through the transcript hash.
//!
//! Read and write sides are generic over independent transport halves
//! (`R`/`W`) rather than a single shared transport, so that
//! [`crate::stream::JlsStream`] can later poll both directions concurrently
//! (via `tokio::io::split`) without any shared mutable state or unsafe code.

use aes_gcm::aead::{Aead, Nonce, Payload};
use aes_gcm::{Aes128Gcm, KeyInit};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cursor::take_handshake_message;
use crate::error::{Result, TlsError};
use crate::keys::record_nonce;

pub(crate) const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
pub(crate) const CONTENT_ALERT: u8 = 21;
pub(crate) const CONTENT_HANDSHAKE: u8 = 22;
pub(crate) const CONTENT_APPLICATION_DATA: u8 = 23;

pub(crate) const LEGACY_VERSION_INITIAL: u16 = 0x0301;
pub(crate) const LEGACY_VERSION: u16 = 0x0303;

pub(crate) const MAX_PLAINTEXT_RECORD: usize = 16384;

// The largest body a record may declare, per version.
pub(crate) const MAX_CIPHERTEXT_RECORD: usize = MAX_PLAINTEXT_RECORD + 2048;
pub(crate) const MAX_CIPHERTEXT_RECORD_TLS13: usize = MAX_PLAINTEXT_RECORD + 256;

/// Direction-scoped AEAD state: static key/IV plus a strictly increasing
/// sequence number used to derive each record's nonce.
pub(crate) struct DirectionKeys {
    key: [u8; 16],
    iv: [u8; 12],
    seq: u64,
}

impl DirectionKeys {
    pub(crate) fn new(key: [u8; 16], iv: [u8; 12]) -> Self {
        Self { key, iv, seq: 0 }
    }

    fn next_nonce(&mut self) -> Result<[u8; 12]> {
        let nonce = record_nonce(&self.iv, self.seq);
        self.seq = self.seq.checked_add(1).ok_or_else(|| TlsError::protocol("record: sequence number overflow"))?;
        Ok(nonce)
    }
}

pub(crate) fn outer_header(content_type: u8, legacy_version: u16, len: u16) -> [u8; 5] {
    let mut h = [0u8; 5];
    h[0] = content_type;
    h[1..3].copy_from_slice(&legacy_version.to_be_bytes());
    h[3..5].copy_from_slice(&len.to_be_bytes());
    h
}

/// Encrypts one `TLSInnerPlaintext` (`plaintext || inner_content_type`) into
/// a full `TLSCiphertext` record (header + ciphertext + tag).
pub(crate) fn seal(keys: &mut DirectionKeys, inner_content_type: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut inner = Vec::with_capacity(plaintext.len() + 1);
    inner.extend_from_slice(plaintext);
    inner.push(inner_content_type);

    let cipher_len: u16 =
        (inner.len() + 16).try_into().map_err(|_| TlsError::protocol("record: plaintext too long for one record"))?;
    let header = outer_header(CONTENT_APPLICATION_DATA, LEGACY_VERSION, cipher_len);

    let cipher = Aes128Gcm::new_from_slice(&keys.key).map_err(|_| TlsError::protocol("record: invalid AEAD key"))?;
    let nonce: Nonce<Aes128Gcm> = keys.next_nonce()?.into();
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: &inner, aad: &header })
        .map_err(|_| TlsError::protocol("record: AEAD seal failed"))?;

    let mut record = header.to_vec();
    record.extend_from_slice(&ciphertext);
    Ok(record)
}

/// Decrypts one `TLSCiphertext` record body, returning `(inner content type,
/// plaintext)`. Strips `TLSInnerPlaintext` zero padding per RFC 8446 §5.4:
/// the real content type is the last non-zero byte.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "crate-visible record-layer entry point; the caller keeps the header it just parsed"
)]
pub(crate) fn open(keys: &mut DirectionKeys, header: &[u8; 5], ciphertext: &[u8]) -> Result<(u8, Vec<u8>)> {
    let cipher = Aes128Gcm::new_from_slice(&keys.key).map_err(|_| TlsError::protocol("record: invalid AEAD key"))?;
    let nonce: Nonce<Aes128Gcm> = keys.next_nonce()?.into();
    let mut inner = cipher
        .decrypt(&nonce, Payload { msg: ciphertext, aad: header })
        .map_err(|_| TlsError::protocol("record: AEAD open failed"))?;

    while inner.last() == Some(&0) {
        inner.pop();
    }
    let content_type = inner.pop().ok_or_else(|| TlsError::protocol("record: empty TLSInnerPlaintext"))?;
    Ok((content_type, inner))
}

/// Owns one read transport (`R`) and one write transport (`W`) plus their
/// independent AEAD state, and reassembles handshake messages across record
/// boundaries. Used only during the handshake; see [`crate::stream::JlsStream`]
/// for the post-handshake poll-based application-data record layer.
pub(crate) struct RecordIo<R, W> {
    read_half: R,
    write_half: W,
    hs_incoming: Vec<u8>,
    read_keys: Option<DirectionKeys>,
    write_keys: Option<DirectionKeys>,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> RecordIo<R, W> {
    pub(crate) fn from_halves(read_half: R, write_half: W) -> Self {
        Self { read_half, write_half, hs_incoming: Vec::new(), read_keys: None, write_keys: None }
    }

    pub(crate) fn set_read_keys(&mut self, keys: DirectionKeys) {
        self.read_keys = Some(keys);
    }

    pub(crate) fn set_write_keys(&mut self, keys: DirectionKeys) {
        self.write_keys = Some(keys);
    }

    /// Splits back into the raw halves plus whichever AEAD keys were
    /// installed on each side. `hs_incoming` is expected to be empty at any
    /// point this is called (always true right after a complete handshake
    /// message has just been read, since reassembly never buffers more than
    /// one message ahead).
    pub(crate) fn into_halves(self) -> (R, Option<DirectionKeys>, W, Option<DirectionKeys>) {
        (self.read_half, self.read_keys, self.write_half, self.write_keys)
    }

    async fn read_exact_owned(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_half.read_exact(&mut buf).await?;
        Ok(buf)
    }

    /// Reads and returns one logical record's `(content type, payload)`,
    /// transparently decrypting if read keys are installed and silently
    /// discarding middlebox `ChangeCipherSpec` records (never surfaced to the
    /// caller, never hashed).
    async fn read_one_record(&mut self) -> Result<(u8, Vec<u8>)> {
        loop {
            let header_bytes = self.read_exact_owned(5).await?;
            let header: [u8; 5] =
                header_bytes.as_slice().try_into().map_err(|_| TlsError::protocol("record: bad header"))?;
            let [content_type, vh, vl, lh, ll] = header;
            let version = u16::from_be_bytes([vh, vl]);
            let len = usize::from(u16::from_be_bytes([lh, ll]));

            // A header that cannot open a handshake is rejected before its body is
            // read; no version is negotiated yet, so reading the declared length
            // would hang a non-TLS camouflage probe forever.
            if self.read_keys.is_none()
                && ((content_type != CONTENT_HANDSHAKE && content_type != CONTENT_ALERT) || version >= 0x1000)
            {
                return Err(TlsError::protocol("tls: first record does not look like a TLS handshake"));
            }

            // The declared body is capped on the header as well, before a probe can
            // make the reader wait for bytes it never sends.
            let max_ciphertext =
                if self.read_keys.is_some() { MAX_CIPHERTEXT_RECORD_TLS13 } else { MAX_CIPHERTEXT_RECORD };
            if len > max_ciphertext {
                return Err(TlsError::protocol("record: oversized record"));
            }

            let payload = self.read_exact_owned(len).await?;

            if content_type == CONTENT_CHANGE_CIPHER_SPEC {
                continue;
            }

            if let Some(keys) = self.read_keys.as_mut() {
                if content_type != CONTENT_APPLICATION_DATA {
                    return Err(TlsError::protocol("record: non-application-data record after read keys installed"));
                }
                return open(keys, &header, &payload);
            }
            return Ok((content_type, payload));
        }
    }

    /// Reads and returns the next complete handshake message (header + body),
    /// buffering across record boundaries as needed. Returns a `TlsError` on
    /// a fatal alert or on any other unexpected content type.
    pub(crate) async fn read_handshake_message(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some(msg) = take_handshake_message(&mut self.hs_incoming) {
                return Ok(msg);
            }
            let (content_type, payload) = self.read_one_record().await?;
            match content_type {
                CONTENT_HANDSHAKE => self.hs_incoming.extend_from_slice(&payload),
                CONTENT_ALERT => return Err(alert_error(&payload)),
                _ => return Err(TlsError::protocol("record: unexpected content type during handshake")),
            }
        }
    }

    /// Writes one raw record (`content_type`/`legacy_version` used verbatim,
    /// no encryption) -- used for the plaintext `ClientHello`/`ServerHello`
    /// flight and for the always-cleartext middlebox `ChangeCipherSpec`.
    pub(crate) async fn write_plaintext_record(
        &mut self,
        content_type: u8,
        legacy_version: u16,
        payload: &[u8],
    ) -> Result<()> {
        let len: u16 = payload.len().try_into().map_err(|_| TlsError::protocol("record: payload too long"))?;
        let header = outer_header(content_type, legacy_version, len);
        self.write_half.write_all(&header).await?;
        self.write_half.write_all(payload).await?;
        Ok(())
    }

    /// Writes one handshake message, encrypting it as `TLSInnerPlaintext`
    /// under the installed write keys if any, else in the clear.
    pub(crate) async fn write_handshake_message(&mut self, msg: &[u8]) -> Result<()> {
        if let Some(keys) = self.write_keys.as_mut() {
            for chunk in msg.chunks(MAX_PLAINTEXT_RECORD) {
                let record = seal(keys, CONTENT_HANDSHAKE, chunk)?;
                self.write_half.write_all(&record).await?;
            }
            Ok(())
        } else {
            self.write_plaintext_record(CONTENT_HANDSHAKE, LEGACY_VERSION, msg).await
        }
    }

    /// Writes the dummy middlebox-compatibility `ChangeCipherSpec` record
    /// (RFC 8446 Appendix D.4): always sent in the clear, regardless of
    /// whether write keys are already installed.
    pub(crate) async fn write_change_cipher_spec(&mut self) -> Result<()> {
        self.write_plaintext_record(CONTENT_CHANGE_CIPHER_SPEC, LEGACY_VERSION, &[0x01]).await
    }
}

fn alert_error(payload: &[u8]) -> TlsError {
    match payload {
        [level, description] => TlsError::PeerAlert { level: *level, description: *description },
        _ => TlsError::protocol("record: malformed alert"),
    }
}

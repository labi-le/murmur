//! The `none/aes-128-gcm/chacha20-poly1305` body encodings are shared by the AEAD (`alterId = 0`)
//! and legacy (`alterId > 0`) header dialects. The separate `security = aes-128-cfb` body mode
//! is not implemented and never reaches this file.
//!
//! The readers and writers take the live conn as an explicit `&mut` parameter per call, matching
//! `transport::vmess::aead`/`chunk`'s established convention.

use std::io;
use std::sync::Arc;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes128Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest as _, Md5};
use parking_lot::Mutex as SyncMutex;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::shake128::Shake128Stream;
use crate::header::kdf;

pub(crate) const CIPHER_OVERHEAD: usize = 16;
pub(crate) const WRITE_CHUNK_SIZE: usize = 15000;
const MAX_PADDING_SIZE: u16 = 64;

/// Reads `buf.len()` bytes, but treats a zero-byte first read as a clean end of stream rather
/// than `UnexpectedEof`: a plain EOF (not "unexpected EOF") is reported when the peer closes
/// between chunks, and that EOF is the stream's normal end. A short first read
/// still fills the rest with `read_exact`, so a truncated prefix (peer closes mid-length-field)
/// keeps surfacing as `UnexpectedEof`.
async fn read_prefix_or_eof<R: AsyncRead + Unpin + ?Sized>(conn: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let n = conn.read(buf).await?;
    if n == 0 {
        return Ok(false);
    }
    if n < buf.len() {
        conn.read_exact(buf.split_at_mut(n).1).await?;
    }
    Ok(true)
}

/// The AEAD cipher used here (AES-128-GCM or ChaCha20-Poly1305, both 12-byte
/// nonce/16-byte overhead).
#[allow(
    clippy::large_enum_variant,
    reason = "the two AEAD arms carry their own expanded round keys, so the size gap is real state; boxing one arm would add a per-connection allocation"
)]
pub(crate) enum Cipher {
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl Cipher {
    pub(crate) fn new_aes_128_gcm(key: &[u8]) -> io::Result<Self> {
        use aes_gcm::KeyInit;
        Aes128Gcm::new_from_slice(key).map(Self::Aes128Gcm).map_err(io::Error::other)
    }

    pub(crate) fn new_chacha20_poly1305(key: &[u8]) -> io::Result<Self> {
        use chacha20poly1305::KeyInit;
        let expanded = generate_chacha20_poly1305_key(key);
        ChaCha20Poly1305::new_from_slice(&expanded).map(Self::ChaCha20Poly1305).map_err(io::Error::other)
    }

    #[expect(
        clippy::expect_used,
        reason = "sealing has no fallible input: the nonce is always 12 bytes and the AEAD only rejects plaintexts above its own length limit, which the `WRITE_CHUNK_SIZE` cap rules out; `AeadBodyWriter::seal`'s `Vec<u8>` return leaves no error channel"
    )]
    fn seal(&self, nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let payload = Payload { msg: plaintext, aad: &[] };
        match self {
            Self::Aes128Gcm(c) => c
                .encrypt(<&aes_gcm::Nonce<_>>::try_from(nonce).expect("12-byte GCM nonce"), payload)
                .expect("aead seal never fails"),
            Self::ChaCha20Poly1305(c) => c
                .encrypt(<&chacha20poly1305::Nonce>::try_from(nonce).expect("12-byte ChaCha20-Poly1305 nonce"), payload)
                .expect("aead seal never fails"),
        }
    }

    fn open(&self, nonce: &[u8], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload { msg: ciphertext, aad: &[] };
        let result = match self {
            Self::Aes128Gcm(c) => c.decrypt(
                <&aes_gcm::Nonce<_>>::try_from(nonce).map_err(|_| io::Error::other("cipher: nonce is not 12 bytes"))?,
                payload,
            ),
            Self::ChaCha20Poly1305(c) => c.decrypt(
                <&chacha20poly1305::Nonce>::try_from(nonce)
                    .map_err(|_| io::Error::other("cipher: nonce is not 12 bytes"))?,
                payload,
            ),
        };
        result.map_err(|_| io::Error::other("cipher: message authentication failed"))
    }
}

pub(crate) fn generate_chacha20_poly1305_key(b: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let first: [u8; 16] = Md5::digest(b).into();
    key[..16].copy_from_slice(&first);
    let second: [u8; 16] = Md5::digest(&key[..16]).into();
    key[16..].copy_from_slice(&second);
    key
}

fn nonce_with_count(base: &[u8; 12], count: u16) -> [u8; 12] {
    let mut nonce = *base;
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce
}

fn nonce_base(iv16: &[u8]) -> [u8; 12] {
    let (iv, _) = iv16.split_at(12);
    let mut base = [0u8; 12];
    base.copy_from_slice(iv);
    base
}

/// Shared masking/padding stream handle: one SHAKE128 stream serves both roles when
/// `chunk_masking == global_padding` (both options enabled), instead of seeding two independent
/// streams.
pub(crate) type SharedShake = Arc<SyncMutex<Shake128Stream>>;

pub(crate) fn new_shake(seed: &[u8]) -> SharedShake {
    Arc::new(SyncMutex::new(Shake128Stream::new(seed)))
}

/// The AEAD body writer: plain per-chunk AEAD seal, no length
/// prefix of its own (added by the outer [`StreamChunkWriter`]/[`AeadChunkWriter`] layer).
pub(crate) struct AeadBodyWriter {
    cipher: Cipher,
    nonce_base: [u8; 12],
    count: u16,
}

impl AeadBodyWriter {
    pub(crate) fn new(cipher: Cipher, iv16: &[u8]) -> Self {
        Self { cipher, nonce_base: nonce_base(iv16), count: 0 }
    }

    /// Seals `plaintext` (already ≤`WRITE_CHUNK_SIZE`) whole.
    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = nonce_with_count(&self.nonce_base, self.count);
        self.count = self.count.wrapping_add(1);
        self.cipher.seal(&nonce, plaintext)
    }
}

pub(crate) struct AeadBodyReader {
    cipher: Cipher,
    nonce_base: [u8; 12],
    count: u16,
}

impl AeadBodyReader {
    pub(crate) fn new(cipher: Cipher, iv16: &[u8]) -> Self {
        Self { cipher, nonce_base: nonce_base(iv16), count: 0 }
    }

    pub(crate) fn open(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = nonce_with_count(&self.nonce_base, self.count);
        self.count = self.count.wrapping_add(1);
        self.cipher.open(&nonce, ciphertext)
    }
}

/// `StreamChunkWriter`: length prefix (optionally shake128-masked), the already-sealed body,
/// then optional random padding.
pub(crate) struct StreamChunkWriter {
    chunk_masking: Option<SharedShake>,
    global_padding: Option<SharedShake>,
}

impl StreamChunkWriter {
    pub(crate) fn new(chunk_masking: Option<SharedShake>, global_padding: Option<SharedShake>) -> Self {
        Self { chunk_masking, global_padding }
    }

    /// Writes `body`, the already-sealed (or, for `security = none`, plaintext) chunk payload:
    /// frames it and writes the frame to `conn`.
    pub(crate) async fn write<W: AsyncWrite + Unpin + ?Sized>(&self, conn: &mut W, body: &[u8]) -> io::Result<()> {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the chunk length field is 16 bits on the wire and the value truncates into it; callers cap `body` at `WRITE_CHUNK_SIZE` (15000), so the wire width is the only narrowing"
        )]
        let mut data_len = body.len() as u16;
        let mut padding_len: u16 = 0;
        if let Some(padding) = &self.global_padding {
            padding_len = padding.lock().next_u16() % MAX_PADDING_SIZE;
            data_len = data_len.wrapping_add(padding_len);
        }
        if let Some(masking) = &self.chunk_masking {
            data_len ^= masking.lock().next_u16();
        }
        let mut frame = Vec::with_capacity(2 + body.len() + padding_len as usize);
        frame.extend_from_slice(&data_len.to_be_bytes());
        frame.extend_from_slice(body);
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len as usize];
            rand::rng().fill_bytes(&mut padding);
            frame.extend_from_slice(&padding);
        }
        conn.write_all(&frame).await
    }
}

pub(crate) struct StreamChunkReader {
    chunk_masking: Option<SharedShake>,
    global_padding: Option<SharedShake>,
    /// What an *empty* body still costs on the wire: `CIPHER_OVERHEAD` once the body is
    /// authenticated, `0` under `security = none`. A chunk stream ends on an empty write, and a
    /// reader stops exactly when the framed size equals the AEAD overhead plus padding — so a peer
    /// that authenticates its body spends this many bytes on its last, plaintext-free chunk.
    body_overhead: usize,
}

impl StreamChunkReader {
    pub(crate) fn new(
        chunk_masking: Option<SharedShake>,
        global_padding: Option<SharedShake>,
        body_overhead: usize,
    ) -> Self {
        Self { chunk_masking, global_padding, body_overhead }
    }

    /// Returns `Ok(None)` for a clean end of stream: `dataLen == 0`, or `dataLen ==
    /// body_overhead` for the empty-but-authenticated terminal chunk. A peer that never sends one
    /// (this crate's writer never writes an empty buffer) still ends on a clean read of zero bytes
    /// from the underlying conn.
    pub(crate) async fn read<R: AsyncRead + Unpin + ?Sized>(&self, conn: &mut R) -> io::Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 2];
        if !read_prefix_or_eof(conn, &mut len_buf).await? {
            return Ok(None);
        }
        let mut length = u16::from_be_bytes(len_buf);

        let padding_len: u16 =
            if let Some(padding) = &self.global_padding { padding.lock().next_u16() % MAX_PADDING_SIZE } else { 0 };
        if let Some(masking) = &self.chunk_masking {
            length ^= masking.lock().next_u16();
        }
        let data_len = usize::try_from(i32::from(length) - i32::from(padding_len))
            .map_err(|_| io::Error::other(format!("bad length chunk: length={length}, padding={padding_len}")))?;
        if data_len == 0 || data_len == self.body_overhead {
            return Ok(None);
        }
        let mut body = vec![0u8; data_len];
        conn.read_exact(&mut body).await?;
        if padding_len > 0 {
            let mut discard = vec![0u8; padding_len as usize];
            conn.read_exact(&mut discard).await?;
        }
        Ok(Some(body))
    }
}

/// The authenticated-length chunk writer: the 2-byte length is itself AEAD-sealed under a key
/// independently derived via `kdf(key, &[b"auth_len"])`, rather than XOR-masked with a shake128
/// stream.
pub(crate) struct AeadChunkWriter {
    length_cipher: Cipher,
    nonce_base: [u8; 12],
    count: u16,
    global_padding: Option<SharedShake>,
}

impl AeadChunkWriter {
    pub(crate) fn new(length_cipher: Cipher, iv16: &[u8], global_padding: Option<SharedShake>) -> Self {
        Self { length_cipher, nonce_base: nonce_base(iv16), count: 0, global_padding }
    }

    /// `body` is the already-sealed chunk payload (`AeadBodyWriter::seal`'s output, always
    /// `>= CIPHER_OVERHEAD` bytes).
    pub(crate) async fn write<W: AsyncWrite + Unpin + ?Sized>(&mut self, conn: &mut W, body: &[u8]) -> io::Result<()> {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the authenticated length field is 16 bits on the wire and the value truncates into it; `body` is a sealed chunk capped at `WRITE_CHUNK_SIZE` (15000) plus its AEAD tag, so the wire width is the only narrowing"
        )]
        let mut data_length = body.len() as u16;
        let mut padding_len: u16 = 0;
        if let Some(padding) = &self.global_padding {
            padding_len = padding.lock().next_u16() % MAX_PADDING_SIZE;
            data_length = data_length.wrapping_add(padding_len);
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "`CIPHER_OVERHEAD` is the fixed 16-byte AEAD tag and the length field that excludes it is 16 bits wide, so the tag width narrows to the field it is subtracted from"
        )]
        let overhead = CIPHER_OVERHEAD as u16;
        data_length = data_length.wrapping_sub(overhead);

        let nonce = nonce_with_count(&self.nonce_base, self.count);
        self.count = self.count.wrapping_add(1);
        let sealed_len = self.length_cipher.seal(&nonce, &data_length.to_be_bytes());

        let mut frame = Vec::with_capacity(sealed_len.len() + body.len() + padding_len as usize);
        frame.extend_from_slice(&sealed_len);
        frame.extend_from_slice(body);
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len as usize];
            rand::rng().fill_bytes(&mut padding);
            frame.extend_from_slice(&padding);
        }
        conn.write_all(&frame).await
    }
}

pub(crate) struct AeadChunkReader {
    length_cipher: Cipher,
    nonce_base: [u8; 12],
    count: u16,
    global_padding: Option<SharedShake>,
}

impl AeadChunkReader {
    pub(crate) fn new(length_cipher: Cipher, iv16: &[u8], global_padding: Option<SharedShake>) -> Self {
        Self { length_cipher, nonce_base: nonce_base(iv16), count: 0, global_padding }
    }

    /// Returns `Ok(None)` for a clean end of stream (`dataLen == 0`). The returned bytes are the
    /// still-sealed body chunk (caller opens it with the body cipher separately).
    pub(crate) async fn read<R: AsyncRead + Unpin + ?Sized>(&mut self, conn: &mut R) -> io::Result<Option<Vec<u8>>> {
        let mut sealed_len = [0u8; 2 + CIPHER_OVERHEAD];
        if !read_prefix_or_eof(conn, &mut sealed_len).await? {
            return Ok(None);
        }
        let nonce = nonce_with_count(&self.nonce_base, self.count);
        self.count = self.count.wrapping_add(1);
        let opened = self.length_cipher.open(&nonce, &sealed_len)?;
        let [low, high, ..] = opened.as_slice() else {
            return Err(io::Error::other("cipher: decrypted length field is shorter than 2 bytes"));
        };
        let length = u16::from_be_bytes([*low, *high]);

        let padding_len =
            self.global_padding.as_ref().map_or(0, |padding| usize::from(padding.lock().next_u16() % MAX_PADDING_SIZE));
        let wire_len = usize::from(length) + CIPHER_OVERHEAD;
        let data_len = wire_len
            .checked_sub(padding_len)
            .ok_or_else(|| io::Error::other(format!("bad length chunk: length={length}, padding={padding_len}")))?;
        if data_len == 0 {
            return Ok(None);
        }
        let mut body = vec![0u8; data_len];
        conn.read_exact(&mut body).await?;
        if padding_len > 0 {
            let mut discard = vec![0u8; padding_len];
            conn.read_exact(&mut discard).await?;
        }
        Ok(Some(body))
    }
}

/// `kdf(key, &[b"auth_len"])[..16]`, used to derive both the AES-128-GCM and (after
/// `generate_chacha20_poly1305_key`) the ChaCha20-Poly1305 length-framing key.
pub(crate) fn auth_len_key(key: &[u8]) -> Vec<u8> {
    kdf(key, &[b"auth_len"])[..16].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex")).collect()
    }

    #[test]
    fn generate_chacha_key_matches_known_answer() {
        let cmd_key = hex("2c2a0d02cd7bab29b8a06e236551d312");
        let got = generate_chacha20_poly1305_key(&cmd_key);
        assert_eq!(
            got.to_vec(),
            hex("44444d1a742624b2a8013742033499c5834ad3acac291773ad7d6a57b666d92a"),
            "GenerateChacha20Poly1305Key produces an unexpected key"
        );
    }
}

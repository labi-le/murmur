//! `Conn` (see `conn.rs`) drives multi-`await` reads and writes through a shared underlying conn,
//! so the aead reader and writer take the live conn as an explicit parameter per call.
//!
//! Sealing and opening build an owned `Vec` and copy it into the frame buffer instead of working in
//! place: the `RustCrypto` `aead` crate has no in-place API here — identical wire bytes, one extra
//! allocation per chunk.

use std::io;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes128Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use murmur_common_pool as pool;

use super::chunk::{CHUNK_SIZE, LEN_SIZE, MAX_SIZE};

/// The AEAD as used here: AES-128-GCM or ChaCha20-Poly1305, both with a 12-byte nonce and
/// 16-byte overhead.
#[allow(
    clippy::large_enum_variant,
    reason = "AES-128-GCM and ChaCha20-Poly1305 keep genuinely different round-key material sizes; boxing the larger arm would trade one heap allocation per connection for a marginal stack-size win with no correctness benefit"
)]
pub(crate) enum AeadCipher {
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl AeadCipher {
    #[expect(
        clippy::unused_self,
        reason = "kept as a receiver method to mirror the AEAD interface the crate-internal call sites read"
    )]
    pub(crate) const fn overhead(&self) -> usize {
        16
    }

    fn seal(&self, nonce: [u8; 12], plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload { msg: plaintext, aad: &[] };
        let sealed = match self {
            Self::Aes128Gcm(cipher) => cipher.encrypt(&aes_gcm::aead::Nonce::<Aes128Gcm>::from(nonce), payload),
            Self::ChaCha20Poly1305(cipher) => cipher.encrypt(&chacha20poly1305::Nonce::from(nonce), payload),
        };
        sealed.map_err(|_| io::Error::other("cipher: seal failed"))
    }

    fn open(&self, nonce: [u8; 12], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload { msg: ciphertext, aad: &[] };
        let opened = match self {
            Self::Aes128Gcm(cipher) => cipher.decrypt(&aes_gcm::aead::Nonce::<Aes128Gcm>::from(nonce), payload),
            Self::ChaCha20Poly1305(cipher) => cipher.decrypt(&chacha20poly1305::Nonce::from(nonce), payload),
        };
        opened.map_err(|_| io::Error::other("cipher: message authentication failed"))
    }
}

/// One key and IV carry exactly this many chunks: the 16-bit count is the whole of the nonce's
/// variable part, and the wire format defines no re-key.
const MAX_CHUNKS_PER_KEY: u32 = u16::MAX as u32 + 1;

/// The nonce's first two bytes hold the
/// big-endian chunk count and the remaining ten the IV's bytes 2..12. A count past the wire
/// field is an error rather than a repeat of a nonce already used under this key.
fn build_nonce(iv: &[u8], count: u32) -> io::Result<[u8; 12]> {
    let count = u16::try_from(count).map_err(|_| {
        io::Error::other(format!(
            "vmess: AEAD nonce counter exhausted after {MAX_CHUNKS_PER_KEY} chunks; refusing to reuse a nonce"
        ))
    })?;
    let mut nonce = [0u8; 12];
    let (count_field, iv_field) = nonce.split_at_mut(2);
    count_field.copy_from_slice(&count.to_be_bytes());
    let (_, iv_tail) = iv.split_at(2);
    let (iv_tail, _) = iv_tail.split_at(iv_field.len());
    iv_field.copy_from_slice(iv_tail);
    Ok(nonce)
}

pub(crate) struct AeadWriter {
    cipher: AeadCipher,
    iv: Vec<u8>,
    count: u32,
}

impl AeadWriter {
    pub(crate) const fn new(cipher: AeadCipher, iv: Vec<u8>) -> Self {
        Self { cipher, iv, count: 0 }
    }

    pub(crate) async fn write<W: AsyncWrite + Unpin + ?Sized>(&mut self, w: &mut W, b: &[u8]) -> io::Result<usize> {
        let overhead = self.cipher.overhead();
        let mut n = 0usize;
        let mut length = b.len();
        loop {
            if length == 0 {
                break;
            }
            let read_len = length.min(CHUNK_SIZE - overhead);
            let (_, remaining) = b.split_at(n);
            let (plaintext, _) = remaining.split_at(read_len);

            let nonce = build_nonce(&self.iv, self.count)?;
            let sealed = self.cipher.seal(nonce, plaintext)?;
            self.count += 1;

            let mut frame = Vec::with_capacity(LEN_SIZE + sealed.len());
            #[expect(
                clippy::cast_possible_truncation,
                reason = "`seal` adds 16 bytes of overhead to at most `CHUNK_SIZE - 16` plaintext bytes, so the sealed length fits the 16-bit length field"
            )]
            frame.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
            frame.extend_from_slice(&sealed);

            w.write_all(&frame).await?;
            w.flush().await?;
            n += read_len;
            length -= read_len;
        }
        Ok(n)
    }
}

pub(crate) struct AeadReader {
    cipher: AeadCipher,
    buf: Option<Vec<u8>>,
    offset: usize,
    iv: Vec<u8>,
    count: u32,
}

impl AeadReader {
    pub(crate) const fn new(cipher: AeadCipher, iv: Vec<u8>) -> Self {
        Self { cipher, buf: None, offset: 0, iv, count: 0 }
    }

    pub(crate) async fn read<R: AsyncRead + Unpin + ?Sized>(&mut self, r: &mut R, b: &mut [u8]) -> io::Result<usize> {
        if let Some(buf) = self.buf.take() {
            let (_, remaining) = buf.split_at(self.offset);
            let n = copy_bytes(b, remaining);
            self.offset += n;
            if self.offset != buf.len() {
                self.buf = Some(buf);
            }
            return Ok(n);
        }

        let mut size_buf = [0u8; LEN_SIZE];
        r.read_exact(&mut size_buf).await?;
        let size = u16::from_be_bytes(size_buf) as usize;
        if size > MAX_SIZE {
            return Err(io::Error::other("buffer is larger than standard"));
        }

        let nonce = build_nonce(&self.iv, self.count)?;
        self.count += 1;

        let mut buf = pool::get(size);
        if let Err(err) = r.read_exact(&mut buf).await {
            let _ = pool::put(buf);
            return Err(err);
        }

        let opened = match self.cipher.open(nonce, &buf) {
            Ok(opened) => opened,
            Err(err) => {
                let _ = pool::put(buf);
                return Err(err);
            }
        };
        let _ = pool::put(buf);

        let n = copy_bytes(b, &opened);
        if b.len() >= opened.len() {
            return Ok(n);
        }

        self.offset = n;
        self.buf = Some(opened);
        Ok(n)
    }
}

fn copy_bytes(dst: &mut [u8], src: &[u8]) -> usize {
    let n = dst.len().min(src.len());
    let (dst, _) = dst.split_at_mut(n);
    let (src, _) = src.split_at(n);
    dst.copy_from_slice(src);
    n
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use aes_gcm::KeyInit as _;

    use super::*;

    const IV: [u8; 16] = *b"0123456789abcdef";
    const KEY: [u8; 16] = *b"fedcba9876543210";
    /// One `write` call per chunk: a payload under the per-chunk cap emits exactly one frame.
    const ONE_CHUNK: [u8; 16] = [0x5a; 16];

    fn cipher() -> AeadCipher {
        AeadCipher::Aes128Gcm(Aes128Gcm::new_from_slice(&KEY).expect("16-byte key"))
    }

    fn sealed_frame(sealed: &[u8]) -> Vec<u8> {
        let mut frame = u16::try_from(sealed.len()).expect("short frame").to_be_bytes().to_vec();
        frame.extend_from_slice(sealed);
        frame
    }

    #[tokio::test]
    async fn aead_writer_seals_65536_chunks_then_refuses_to_repeat_a_nonce() {
        let mut writer = AeadWriter::new(cipher(), IV.to_vec());
        let mut frames = HashSet::new();
        for chunk in 0..=u16::MAX {
            let mut out = Vec::new();
            writer.write(&mut out, &ONE_CHUNK).await.expect("chunk inside the nonce space");
            assert!(frames.insert(out), "chunk {chunk} sealed under a nonce already used");
        }
        let err = writer.write(&mut Vec::new(), &ONE_CHUNK).await.expect_err("no unused nonce for chunk 65537");
        assert!(err.to_string().contains("nonce counter exhausted"), "{err}");
    }

    #[tokio::test]
    async fn aead_reader_refuses_a_chunk_beyond_the_nonce_space() {
        let mut writer = AeadWriter::new(cipher(), IV.to_vec());
        let mut wire = Vec::new();
        for _ in 0..=u16::MAX {
            writer.write(&mut wire, &ONE_CHUNK).await.expect("chunk inside the nonce space");
        }
        // The frame the writer now refuses to produce: chunk 1's nonce again.
        let sealed =
            cipher().seal(build_nonce(&IV, 0).expect("first nonce"), &ONE_CHUNK).expect("seal under the first nonce");
        wire.extend_from_slice(&sealed_frame(&sealed));

        let mut reader = AeadReader::new(cipher(), IV.to_vec());
        let mut cursor: &[u8] = &wire;
        let mut out = [0u8; 64];
        for chunk in 0..=u16::MAX {
            let read = reader.read(&mut cursor, &mut out).await.expect("chunk inside the nonce space");
            assert_eq!(read, ONE_CHUNK.len(), "chunk {chunk}");
        }
        let err = reader.read(&mut cursor, &mut out).await.expect_err("no unused nonce for chunk 65537");
        assert!(err.to_string().contains("nonce counter exhausted"), "{err}");
    }

    /// The nonce's first two bytes are the chunk count, so the space ends exactly at the `u16`.
    #[test]
    fn the_nonce_space_ends_at_the_u16_chunk_count() {
        assert_eq!(build_nonce(&IV, 0).expect("first chunk")[..2], [0x00, 0x00]);
        assert_eq!(build_nonce(&IV, MAX_CHUNKS_PER_KEY - 1).expect("last chunk")[..2], [0xff, 0xff]);
        let err = build_nonce(&IV, MAX_CHUNKS_PER_KEY).expect_err("chunk 65537 has no nonce");
        assert!(err.to_string().contains("nonce counter exhausted"), "{err}");
    }
}

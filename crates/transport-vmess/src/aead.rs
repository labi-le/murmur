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

/// The nonce's first two bytes hold the
/// big-endian chunk count and the remaining ten the IV's bytes 2..12.
fn build_nonce(iv: &[u8], count: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let (count_field, iv_field) = nonce.split_at_mut(2);
    count_field.copy_from_slice(&count.to_be_bytes());
    let (_, iv_tail) = iv.split_at(2);
    let (iv_tail, _) = iv_tail.split_at(iv_field.len());
    iv_field.copy_from_slice(iv_tail);
    nonce
}

pub(crate) struct AeadWriter {
    cipher: AeadCipher,
    iv: Vec<u8>,
    count: u16,
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

            let nonce = build_nonce(&self.iv, self.count);
            let sealed = self.cipher.seal(nonce, plaintext)?;
            self.count = self.count.wrapping_add(1);

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
    count: u16,
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

        let mut buf = pool::get(size);
        if let Err(err) = r.read_exact(&mut buf).await {
            let _ = pool::put(buf);
            return Err(err);
        }

        let nonce = build_nonce(&self.iv, self.count);
        self.count = self.count.wrapping_add(1);
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

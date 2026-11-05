use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use rand::rngs::OsRng;
use rand::TryRngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use murmur_common_net::io::Stream as NetStream;
use murmur_common_pool as pool;

use super::cipher::{Aead, Cipher};

/// The payload size mask: the maximum size of payload in bytes, `16*1024 - 1`.
pub(crate) const PAYLOAD_SIZE_MASK: usize = 0x3FFF;

/// Sized to hold a length record, a full payload record and both AEAD overheads.
pub(crate) const BUF_SIZE: usize = 17 * 1024;

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
#[error("zero chunk")]
pub struct ErrZeroChunk;

/// The clean end-of-stream error a full read reports.
fn eof_error() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

fn unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

/// The zero chunk ends a snell stream; recognisable across the `io::Error` boundary with a
/// downcast: `err.get_ref().and_then(|err| err.downcast_ref::<ErrZeroChunk>())`.
fn zero_chunk() -> io::Error {
    io::Error::other(ErrZeroChunk)
}

fn to_io_error(err: anyhow::Error) -> io::Error {
    io::Error::other(err)
}

/// Little-endian increment of an unsigned integer, wrapping around on overflow.
fn increment(b: &mut [u8]) {
    for byte in b.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

/// Fills `dst` fully: `Ok(false)` is a clean end of stream, a short read is an unexpected EOF.
fn poll_read_full<R>(reader: &mut R, cx: &mut Context<'_>, dst: &mut [u8], filled: &mut usize) -> Poll<io::Result<bool>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    while let Some(rest) = dst.get_mut(*filled..) {
        if rest.is_empty() {
            break;
        }
        let mut read_buf = ReadBuf::new(rest);
        ready!(Pin::new(&mut *reader).poll_read(cx, &mut read_buf))?;
        let n = read_buf.filled().len();
        if n == 0 {
            if *filled == 0 {
                return Poll::Ready(Ok(false));
            }
            return Poll::Ready(Err(unexpected_eof()));
        }
        *filled += n;
    }
    Poll::Ready(Ok(true))
}

/// Seals `plaintext` into `dst`, then advances the nonce.
fn seal(aead: &dyn Aead, nonce: &mut [u8], dst: &mut Vec<u8>, plaintext: &[u8]) -> io::Result<()> {
    aead.seal(dst, nonce, plaintext, &[]).map_err(to_io_error)?;
    increment(nonce);
    Ok(())
}

/// Writes one record, reporting how much of it the conn has taken.
fn poll_write_record<W>(writer: &mut W, cx: &mut Context<'_>, record: &[u8], sent: &mut usize) -> Poll<io::Result<()>>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    while let Some(rest) = record.get(*sent..) {
        if rest.is_empty() {
            break;
        }
        let n = match Pin::new(&mut *writer).poll_write(cx, rest) {
            Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };
        *sent += n;
    }
    Poll::Ready(Ok(()))
}

/// The writer's cipher side: the aead, nonce and pending-record state. Rust gives a value one
/// owner, so [`Conn`] keeps the wrapped stream and passes it in by reference on each call; the
/// standalone [`Writer`]/[`new_writer`] below own their stream instead.
struct WriteCipher {
    aead: Box<dyn Aead>,
    /// The nonce, 32 bytes, sufficient for every supported nonce size.
    nonce: [u8; 32],
    /// The pooled per-write buffer, kept because a poll can return before the record is out.
    record: Vec<u8>,
    record_sent: usize,
    record_plain_len: usize,
    /// Plaintext bytes of the caller's buffer already sealed, the `n`.
    written: usize,
}

impl Drop for WriteCipher {
    fn drop(&mut self) {
        let _ = pool::put(core::mem::take(&mut self.record));
    }
}

impl WriteCipher {
    fn new(aead: Box<dyn Aead>) -> Self {
        Self { aead, nonce: [0u8; 32], record: Vec::new(), record_sent: 0, record_plain_len: 0, written: 0 }
    }

    /// Reads from `r` until EOF or error, encrypting into `w`.
    async fn read_from_source<R, W>(&mut self, r: &mut R, w: &mut W) -> io::Result<i64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin + ?Sized,
    {
        let mut record = pool::get(BUF_SIZE);
        let mut chunk = pool::get(PAYLOAD_SIZE_MASK);
        let result = self.read_from_inner(r, w, &mut record, &mut chunk).await;
        let _ = pool::put(record);
        let _ = pool::put(chunk);
        result
    }

    async fn read_from_inner<R, W>(
        &mut self,
        r: &mut R,
        w: &mut W,
        record: &mut Vec<u8>,
        chunk: &mut [u8],
    ) -> io::Result<i64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin + ?Sized,
    {
        let nonce_size = self.aead.nonce_size();
        let mut n: i64 = 0;
        loop {
            let (nr, er) = match r.read(chunk).await {
                Ok(0) => (0, Some(ReadEnd::Eof)),
                Ok(nr) => (nr, None),
                Err(err) => (0, Some(ReadEnd::Error(err))),
            };
            #[expect(
                clippy::cast_possible_wrap,
                reason = "`nr` is a read count bounded by the chunk buffer, so it is exact in `i64`"
            )]
            let read_len = nr as i64;
            n += read_len;
            record.clear();
            // The 16-bit big-endian chunk length: the low two bytes of the count.
            let [.., hi, lo] = nr.to_be_bytes();
            let (nonce, _) = self.nonce.split_at_mut(nonce_size);
            seal(&*self.aead, nonce, record, &[hi, lo])?;
            let (plaintext, _) = chunk.split_at(nr);
            let (nonce, _) = self.nonce.split_at_mut(nonce_size);
            seal(&*self.aead, nonce, record, plaintext)?;
            w.write_all(record).await?;
            match er {
                None => {}
                Some(ReadEnd::Eof) => return Ok(n),
                Some(ReadEnd::Error(err)) => return Err(err),
            }
        }
    }

    fn poll_write_to<W>(&mut self, w: &mut W, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        if self.record.capacity() == 0 {
            self.record = pool::get(BUF_SIZE);
            self.record.clear();
        }
        let nonce_size = self.aead.nonce_size();

        if !self.record.is_empty() {
            ready!(poll_write_record(w, cx, &self.record, &mut self.record_sent))?;
            self.written += self.record_plain_len;
            self.record_plain_len = 0;
            self.record_sent = 0;
            self.record.clear();
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
        }

        // the `compatible with snell` branch: an empty payload writes one zero-length record.
        if buf.is_empty() {
            let (nonce, _) = self.nonce.split_at_mut(nonce_size);
            seal(&*self.aead, nonce, &mut self.record, &[0, 0])?;
            ready!(poll_write_record(w, cx, &self.record, &mut self.record_sent))?;
            self.record.clear();
            return Poll::Ready(Ok(0));
        }

        while self.written < buf.len() {
            let nr = core::cmp::min(PAYLOAD_SIZE_MASK, buf.len() - self.written);
            // The 16-bit big-endian chunk length: the low two bytes of the count.
            let [.., hi, lo] = nr.to_be_bytes();
            let (nonce, _) = self.nonce.split_at_mut(nonce_size);
            seal(&*self.aead, nonce, &mut self.record, &[hi, lo])?;
            let (_, plaintext) = buf.split_at(self.written);
            let (plaintext, _) = plaintext.split_at(nr);
            let (nonce, _) = self.nonce.split_at_mut(nonce_size);
            seal(&*self.aead, nonce, &mut self.record, plaintext)?;
            self.record_plain_len = nr;
            ready!(poll_write_record(w, cx, &self.record, &mut self.record_sent))?;
            self.written += nr;
            self.record_plain_len = 0;
            self.record_sent = 0;
            self.record.clear();
        }
        let n = self.written;
        self.written = 0;
        Poll::Ready(Ok(n))
    }
}

/// How a read ended: a clean end of stream or an error.
enum ReadEnd {
    Eof,
    Error(io::Error),
}

pub struct Writer {
    writer: Box<dyn AsyncWrite + Send + Sync + Unpin>,
    cipher: WriteCipher,
}

impl fmt::Debug for Writer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Writer").finish_non_exhaustive()
    }
}

/// Wraps a writer with authenticated encryption.
#[must_use]
pub fn new_writer(w: Box<dyn AsyncWrite + Send + Sync + Unpin>, aead: Box<dyn Aead>) -> Writer {
    Writer { writer: w, cipher: WriteCipher::new(aead) }
}

impl Writer {
    /// Reads from `r` until EOF or error, encrypting into the conn.
    pub async fn read_from<R>(&mut self, r: &mut R) -> io::Result<i64>
    where
        R: AsyncRead + Unpin,
    {
        self.cipher.read_from_source(r, &mut *self.writer).await
    }
}

impl AsyncWrite for Writer {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.cipher.poll_write_to(&mut *this.writer, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().writer).poll_shutdown(cx)
    }
}

/// The phase of the `read`: the size record first, then the payload record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordPhase {
    Size,
    Payload { size: usize },
}

/// What one read of the reader reported.
enum RecordStep {
    /// A record was decrypted into `ReadCipher::staging[off..record_len]`.
    Record,
    /// A full read reached a clean end of stream.
    Eof,
    /// The read returned an error.
    Error(io::Error),
}

/// The reader's cipher side: the aead, nonce and decrypted-record staging buffer. See
/// [`WriteCipher`]'s doc for why [`Conn`] keeps the wrapped stream and passes it in per call.
struct ReadCipher {
    aead: Box<dyn Aead>,
    /// The nonce, 32 bytes, sufficient for every supported nonce size.
    nonce: [u8; 32],
    /// The caller's read buffer, kept across polls; the decrypted record, once
    /// held, lives in place at `staging[off..record_len]` rather than in a separate allocation.
    staging: Vec<u8>,
    /// Offset to the unconsumed part of the decrypted record in `staging`.
    off: usize,
    /// Length of the decrypted record currently held in `staging`; `0` means none is pending.
    record_len: usize,
    phase: RecordPhase,
    filled: usize,
}

impl Drop for ReadCipher {
    fn drop(&mut self) {
        let _ = pool::put(core::mem::take(&mut self.staging));
    }
}

impl ReadCipher {
    fn new(aead: Box<dyn Aead>) -> Self {
        Self { aead, nonce: [0u8; 32], staging: Vec::new(), off: 0, record_len: 0, phase: RecordPhase::Size, filled: 0 }
    }

    /// One record part of the read, decrypted in place into `staging[..need]`. `Ok(None)` is a
    /// clean end of stream.
    fn poll_open_part<R>(&mut self, r: &mut R, cx: &mut Context<'_>, need: usize) -> Poll<io::Result<Option<usize>>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        if self.staging.capacity() == 0 {
            self.staging = pool::get(BUF_SIZE);
        }
        let (staging, _) = self.staging.split_at_mut(need);
        let full = ready!(poll_read_full(r, cx, staging, &mut self.filled))?;
        if !full {
            return Poll::Ready(Ok(None));
        }
        let nonce_size = self.aead.nonce_size();
        let plain_len = {
            let (nonce, _) = self.nonce.split_at(nonce_size);
            let (staging, _) = self.staging.split_at_mut(need);
            self.aead.open_in_place(nonce, staging, &[]).map_err(to_io_error)?.len()
        };
        let (nonce, _) = self.nonce.split_at_mut(nonce_size);
        increment(nonce);
        Poll::Ready(Ok(Some(plain_len)))
    }

    /// Decrypts one record into the caller's buffer, which here is `staging`.
    fn poll_record<R>(&mut self, r: &mut R, cx: &mut Context<'_>) -> Poll<RecordStep>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        let tag = self.aead.overhead();
        loop {
            match self.phase {
                RecordPhase::Size => {
                    let plain_len = match self.poll_open_part(r, cx, 2 + tag) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(Some(plain_len))) => plain_len,
                        Poll::Ready(Ok(None)) => return Poll::Ready(RecordStep::Eof),
                        Poll::Ready(Err(err)) => return Poll::Ready(RecordStep::Error(err)),
                    };
                    debug_assert_eq!(plain_len, 2);
                    let Some([hi, lo]) = self.staging.first_chunk::<2>() else {
                        return Poll::Ready(RecordStep::Error(unexpected_eof()));
                    };
                    let size = (usize::from(*hi) << 8 | usize::from(*lo)) & PAYLOAD_SIZE_MASK;
                    if size == 0 {
                        return Poll::Ready(RecordStep::Error(zero_chunk()));
                    }
                    self.phase = RecordPhase::Payload { size };
                    self.filled = 0;
                }
                RecordPhase::Payload { size } => {
                    let plain_len = match self.poll_open_part(r, cx, size + tag) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(Some(plain_len))) => plain_len,
                        Poll::Ready(Ok(None)) => return Poll::Ready(RecordStep::Eof),
                        Poll::Ready(Err(err)) => return Poll::Ready(RecordStep::Error(err)),
                    };
                    self.phase = RecordPhase::Size;
                    self.filled = 0;
                    self.off = 0;
                    self.record_len = plain_len;
                    return Poll::Ready(RecordStep::Record);
                }
            }
        }
    }

    /// Decrypts from `r` into `w` until the stream ends.
    async fn write_to_source<R, W>(&mut self, r: &mut R, w: &mut W) -> io::Result<i64>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin,
    {
        let mut n: i64 = 0;
        loop {
            if self.record_len > 0 {
                let mut err = None;
                while self.off < self.record_len {
                    let (_, pending) = self.staging.split_at(self.off);
                    let (pending, _) = pending.split_at(self.record_len - self.off);
                    match w.write(pending).await {
                        Ok(0) => {
                            err = Some(io::Error::from(io::ErrorKind::WriteZero));
                            break;
                        }
                        Ok(nw) => {
                            self.off += nw;
                            #[expect(
                                clippy::cast_possible_wrap,
                                reason = "`nw` is a write count bounded by the pending record, so it is exact in `i64`"
                            )]
                            let written = nw as i64;
                            n += written;
                        }
                        Err(nw_err) => {
                            err = Some(nw_err);
                            break;
                        }
                    }
                }
                if let Some(err) = err {
                    if self.off == self.record_len {
                        self.off = 0;
                        self.record_len = 0;
                    }
                    return Err(err);
                }
                self.off = 0;
                self.record_len = 0;
            }

            match poll_fn(|cx| self.poll_record(&mut *r, cx)).await {
                RecordStep::Eof => return Ok(n),
                RecordStep::Error(err) => return Err(err),
                RecordStep::Record => {}
            }
        }
    }

    /// The record read path, applied through a caller-supplied `r`.
    fn poll_read_from<R>(&mut self, r: &mut R, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        if self.record_len == 0 {
            match self.poll_record(r, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(RecordStep::Eof) => return Poll::Ready(Err(eof_error())),
                Poll::Ready(RecordStep::Error(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(RecordStep::Record) => {}
            }
            // A caller buffer that fits a whole record is served straight from the staging buffer.
            if buf.remaining() >= PAYLOAD_SIZE_MASK + self.aead.overhead() {
                let (_, pending) = self.staging.split_at(self.off);
                let (pending, _) = pending.split_at(self.record_len - self.off);
                buf.put_slice(pending);
                self.off = 0;
                self.record_len = 0;
                return Poll::Ready(Ok(()));
            }
        }

        let n = core::cmp::min(buf.remaining(), self.record_len - self.off);
        let (_, pending) = self.staging.split_at(self.off);
        let (pending, _) = pending.split_at(n);
        buf.put_slice(pending);
        self.off += n;
        if self.off == self.record_len {
            self.off = 0;
            self.record_len = 0;
        }
        Poll::Ready(Ok(()))
    }
}

pub struct Reader {
    reader: Box<dyn AsyncRead + Send + Sync + Unpin>,
    cipher: ReadCipher,
}

impl fmt::Debug for Reader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reader").finish_non_exhaustive()
    }
}

/// Wraps a reader with authenticated decryption.
#[must_use]
pub fn new_reader(r: Box<dyn AsyncRead + Send + Sync + Unpin>, aead: Box<dyn Aead>) -> Reader {
    Reader { reader: r, cipher: ReadCipher::new(aead) }
}

impl Reader {
    /// Decrypts into `w` until the stream ends.
    pub async fn write_to<W>(&mut self, w: &mut W) -> io::Result<i64>
    where
        W: AsyncWrite + Unpin,
    {
        self.cipher.write_to_source(&mut *self.reader, w).await
    }
}

impl AsyncRead for Reader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.cipher.poll_read_from(&mut *this.reader, cx, buf)
    }
}

/// `Conn`, a stream-oriented conn with the cipher applied to its payload.
pub struct Conn {
    stream: Box<dyn NetStream>,
    cipher: Box<dyn Cipher>,
    r: Option<ReadCipher>,
    w: Option<WriteCipher>,
    /// The read cipher's salt, filled in over polls; empty until the read starts.
    r_salt: Vec<u8>,
    r_salt_filled: usize,
    /// The write cipher's salt, written out over polls; empty until the write starts.
    w_salt: Vec<u8>,
    w_salt_sent: usize,
    /// The subkey the write cipher built before it wrote the salt out.
    w_aead: Option<Box<dyn Aead>>,
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn").finish_non_exhaustive()
    }
}

/// Wraps a stream-oriented conn with the cipher.
#[must_use]
pub fn new_conn(c: Box<dyn NetStream>, ciph: Box<dyn Cipher>) -> Conn {
    Conn {
        stream: c,
        cipher: ciph,
        r: None,
        w: None,
        r_salt: Vec::new(),
        r_salt_filled: 0,
        w_salt: Vec::new(),
        w_salt_sent: 0,
        w_aead: None,
    }
}

impl Conn {
    fn poll_init_reader(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.r_salt.is_empty() {
            self.r_salt = vec![0u8; self.cipher.salt_size()];
        }
        if self.r_salt_filled < self.r_salt.len() {
            let full = match poll_read_full(&mut *self.stream, cx, &mut self.r_salt, &mut self.r_salt_filled) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(full)) => full,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            };
            if !full {
                // The short-read error leaves the source unset, so the next read starts over.
                self.r_salt.clear();
                self.r_salt_filled = 0;
                return Poll::Ready(Err(eof_error()));
            }
        }

        let aead = match self.cipher.decrypter(&self.r_salt) {
            Ok(aead) => aead,
            Err(err) => {
                self.r_salt.clear();
                self.r_salt_filled = 0;
                return Poll::Ready(Err(io::Error::other(err)));
            }
        };
        self.r = Some(ReadCipher::new(aead));
        self.r_salt.clear();
        self.r_salt_filled = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_init_writer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.w_salt.is_empty() {
            let mut salt = vec![0u8; self.cipher.salt_size()];
            if let Err(err) = OsRng.try_fill_bytes(&mut salt) {
                return Poll::Ready(Err(io::Error::other(err.to_string())));
            }
            match self.cipher.encrypter(&salt) {
                Ok(aead) => self.w_aead = Some(aead),
                Err(err) => return Poll::Ready(Err(io::Error::other(err))),
            }
            self.w_salt = salt;
        }

        ready!(poll_write_record(&mut *self.stream, cx, &self.w_salt, &mut self.w_salt_sent))?;

        let Some(aead) = self.w_aead.take() else {
            self.w_salt.clear();
            self.w_salt_sent = 0;
            return Poll::Ready(Err(io::Error::other("shadowaead: writer cipher missing")));
        };
        self.w = Some(WriteCipher::new(aead));
        self.w_salt.clear();
        self.w_salt_sent = 0;
        Poll::Ready(Ok(()))
    }

    pub async fn read_from<R>(&mut self, r: &mut R) -> io::Result<i64>
    where
        R: AsyncRead + Unpin,
    {
        if self.w.is_none() {
            poll_fn(|cx| self.poll_init_writer(cx)).await?;
        }
        let Self { stream, w, .. } = self;
        let writer = w.as_mut().ok_or_else(|| io::Error::other("shadowaead: writer not initialised"))?;
        writer.read_from_source(r, &mut **stream).await
    }

    pub async fn write_to<W>(&mut self, w: &mut W) -> io::Result<i64>
    where
        W: AsyncWrite + Unpin,
    {
        if self.r.is_none() {
            poll_fn(|cx| self.poll_init_reader(cx)).await?;
        }
        let Self { stream, r, .. } = self;
        let reader = r.as_mut().ok_or_else(|| io::Error::other("shadowaead: reader not initialised"))?;
        reader.write_to_source(&mut **stream, w).await
    }
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.r.is_none() {
            ready!(this.poll_init_reader(cx))?;
        }
        let Self { stream, r, .. } = this;
        match r.as_mut() {
            Some(reader) => reader.poll_read_from(&mut **stream, cx, buf),
            None => Poll::Ready(Err(io::Error::other("shadowaead: reader not initialised"))),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.w.is_none() {
            ready!(this.poll_init_writer(cx))?;
        }
        let Self { stream, w, .. } = this;
        match w.as_mut() {
            Some(writer) => writer.poll_write_to(&mut **stream, cx, buf),
            None => Poll::Ready(Err(io::Error::other("shadowaead: writer not initialised"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_shutdown(cx)
    }
}

impl NetStream for Conn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.stream.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.stream.shutdown_write()
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.stream.old_conn()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::shadowaead::cipher::{aesgcm, chacha20poly1305};
    use murmur_common_net::deadline::pipe_sing::pipe;

    #[tokio::test]
    async fn close_through_stream_as_old_conn_reaches_the_real_socket() {
        use murmur_common_net::io::StreamAsOldConn;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let server_task = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
        let client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut server = server_task.await.expect("server task");

        let psk = [7u8; 16];
        let cipher = aesgcm(&psk).expect("cipher");
        let client_stream: Box<dyn NetStream> = Box::new(client);
        let conn = new_conn(client_stream, cipher);
        let old_conn: Box<dyn murmur_std_compat::net::Conn> = Box::new(StreamAsOldConn::new(conn));

        old_conn.close().expect("close");

        let mut buf = [0u8; 1];
        let n = server.read(&mut buf).await.expect("server sees the shutdown as EOF");
        assert_eq!(n, 0, "closing the outer bridge must shut down the real socket, not just the wrapper");
    }

    /// A minimal `Stream` wrapper standing in for a layered inner stream (TLS, obfs, mux):
    /// `as_socket` stays at the trait default, `None`, so `Conn`'s shutdown has no raw-fd
    /// shortcut available. Its own `shutdown_read`/`shutdown_write` forward to the wrapped
    /// `TcpStream`'s (already-correct) implementation — exactly how a real TLS/mux/websocket
    /// wrapper is expected to behave — so a passing test proves `Conn::shutdown_write` reaches
    /// this layer's own `Stream::shutdown_write` (a plain synchronous call, not a poll), rather
    /// than bypassing it.
    struct TrackingLayer {
        inner: tokio::net::TcpStream,
    }

    impl TrackingLayer {
        fn new(inner: tokio::net::TcpStream) -> Self {
            Self { inner }
        }
    }

    impl AsyncRead for TrackingLayer {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TrackingLayer {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl NetStream for TrackingLayer {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.inner.peer_addr()
        }
        fn shutdown_read(&self) -> io::Result<()> {
            self.inner.shutdown_read()
        }
        fn shutdown_write(&self) -> io::Result<()> {
            self.inner.shutdown_write()
        }
    }

    /// Regression test for the deadlock `SharedStream` (an `Arc<Mutex<Box<dyn Stream>>>` shared
    /// between the reader and writer halves) introduced: a stalled write direction must never
    /// block reads on the other direction of the same logical connection. Mirrors
    /// `murmur-listener`'s `snell::server::locking_tests::
    /// review_full_duplex_relay_with_stalled_download_still_reads_upload`, at the shadowaead
    /// level, over real sockets and through a layered (non-socket-identified) inner stream.
    #[tokio::test]
    async fn full_duplex_relay_with_stalled_download_still_completes_upload() {
        let psk = [7u8; 16];
        let client_cipher = aesgcm(&psk).expect("client cipher");
        let server_cipher = aesgcm(&psk).expect("server cipher");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let server_task = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
        let client_tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let server_tcp = server_task.await.expect("server task");

        let client_stream: Box<dyn NetStream> = Box::new(TrackingLayer::new(client_tcp));
        let server_stream: Box<dyn NetStream> = Box::new(TrackingLayer::new(server_tcp));
        let mut client_conn = new_conn(client_stream, client_cipher);
        let server_conn = new_conn(server_stream, server_cipher);

        // Split the server conn exactly like a relay would, and stall its write half by never
        // letting the client read: the loop below blocks on backpressure forever once the OS
        // send/receive buffers fill.
        let (mut server_read, mut server_write) = tokio::io::split(server_conn);
        let download_task = tokio::spawn(async move {
            let chunk = vec![0x42u8; 64 * 1024];
            loop {
                if server_write.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!download_task.is_finished(), "the download writer must be genuinely stalled on backpressure");

        let upload = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            client_conn.write_all(b"hello upload").await.expect("client write upload");
            client_conn.flush().await.expect("client flush");
            let mut buf = [0u8; 12];
            server_read.read_exact(&mut buf).await.expect("server read upload");
            buf
        })
        .await
        .expect("upload direction must not be blocked by the stalled download write");

        assert_eq!(&upload, b"hello upload");
        download_task.abort();
    }

    /// `shutdown_write` must reach the peer through the layered inner stream's own
    /// `Stream::shutdown_write` — `TrackingLayer::as_socket` stays `None`, so there is no
    /// duped-fd fallback available; if this test passes, the shutdown genuinely travelled
    /// through the layer's own synchronous shutdown, not around it via some other path.
    #[tokio::test]
    async fn shutdown_write_reaches_the_peer_through_a_layered_inner_stream() {
        use murmur_common_net::io::StreamAsOldConn;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let server_task = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
        let client_tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut server_tcp = server_task.await.expect("server task");

        let psk = [7u8; 16];
        let cipher = aesgcm(&psk).expect("cipher");
        let client_stream: Box<dyn NetStream> = Box::new(TrackingLayer::new(client_tcp));
        let conn = new_conn(client_stream, cipher);
        let old_conn: Box<dyn murmur_std_compat::net::Conn> = Box::new(StreamAsOldConn::new(conn));

        old_conn.close().expect("close");

        let mut buf = [0u8; 1];
        let n = server_tcp.read(&mut buf).await.expect("server sees the shutdown as EOF");
        assert_eq!(n, 0, "shutdown_write must reach the peer through the layer's own shutdown_write");
    }

    /// Regression test for the P1 finding in `ReviewSs`'s review of the first `SharedStream`
    /// fix (see `agent://ReviewSs` and its `close_through_stream_as_old_conn_reaches_the_real_socket`
    /// sibling above): `Conn` must forward [`NetStream::old_conn`], so [`StreamAsOldConn::close`]
    /// reaches the *wrapped old `Conn`'s own* `close()` — not merely `shutdown_read`/
    /// `shutdown_write` — since a real wrapper's `close()` may carry protocol behaviour
    /// (websocket close frame, TLS close_notify, TFO cancel) that
    /// the shutdown pair alone cannot reproduce. `FlagConn` here stands in for such a wrapper:
    /// its `close()` sets a flag nothing else in this test touches.
    #[tokio::test]
    async fn close_through_stream_as_old_conn_reaches_a_wrapped_old_conns_real_close() {
        use murmur_common_net::io::{OldConnAsStream, StreamAsOldConn};
        use murmur_std_compat::net::{Addr as OldAddr, Conn as OldConn};
        use std::sync::atomic::{AtomicBool, Ordering};

        struct FlagConn {
            inner: tokio::net::TcpStream,
            closed: Arc<AtomicBool>,
        }

        impl AsyncRead for FlagConn {
            fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
            }
        }

        impl AsyncWrite for FlagConn {
            fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
            }
            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_flush(cx)
            }
            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
            }
        }

        impl OldConn for FlagConn {
            fn local_addr(&self) -> io::Result<Box<dyn OldAddr>> {
                OldConn::local_addr(&self.inner)
            }
            fn remote_addr(&self) -> io::Result<Box<dyn OldAddr>> {
                OldConn::remote_addr(&self.inner)
            }
            fn close(&self) -> io::Result<()> {
                self.closed.store(true, Ordering::SeqCst);
                OldConn::close(&self.inner)
            }
        }

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let server_task = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
            let client_tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let mut server_tcp = server_task.await.expect("server task");

            let closed = Arc::new(AtomicBool::new(false));
            let flag_conn = FlagConn { inner: client_tcp, closed: Arc::clone(&closed) };
            let bridged: Box<dyn NetStream> = Box::new(OldConnAsStream(flag_conn));

            let psk = [7u8; 16];
            let cipher = aesgcm(&psk).expect("cipher");
            let conn = new_conn(bridged, cipher);
            let old_conn: Box<dyn murmur_std_compat::net::Conn> = Box::new(StreamAsOldConn::new(conn));

            old_conn.close().expect("close");

            assert!(
                closed.load(Ordering::SeqCst),
                "close() must reach the wrapped old Conn's own close(), not just shutdown_read/shutdown_write"
            );

            // The real socket must still see the shutdown too (close() forwards, it doesn't replace).
            let mut buf = [0u8; 1];
            let n = server_tcp.read(&mut buf).await.expect("server sees the shutdown as EOF");
            assert_eq!(n, 0);
        })
        .await
        .expect("test timed out");
    }

    /// Regression test for the P2 finding: `shutdown_write` must call the wrapped stream's own
    /// synchronous [`NetStream::shutdown_write`] directly, never poll `AsyncWrite::poll_shutdown`
    /// with a throwaway waker (which can return `Pending` and silently drop the shutdown for a
    /// layered inner like TLS). `PanicsOnPollShutdown::poll_shutdown` panics if it is ever
    /// reached from `Conn::shutdown_write`, so this test fails loudly instead of silently on the
    /// pre-fix code path.
    #[tokio::test]
    async fn shutdown_write_calls_the_wrapped_streams_shutdown_write_not_poll_shutdown() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct PanicsOnPollShutdown {
            inner: tokio::net::TcpStream,
            shutdown_write_called: Arc<AtomicBool>,
        }

        impl AsyncRead for PanicsOnPollShutdown {
            fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
            }
        }

        impl AsyncWrite for PanicsOnPollShutdown {
            fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
            }
            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().inner).poll_flush(cx)
            }
            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                panic!(
                    "Conn::shutdown_write must call Stream::shutdown_write directly, never AsyncWrite::poll_shutdown"
                );
            }
        }

        impl NetStream for PanicsOnPollShutdown {
            fn local_addr(&self) -> io::Result<SocketAddr> {
                self.inner.local_addr()
            }
            fn peer_addr(&self) -> io::Result<SocketAddr> {
                self.inner.peer_addr()
            }
            fn shutdown_write(&self) -> io::Result<()> {
                self.shutdown_write_called.store(true, Ordering::SeqCst);
                self.inner.shutdown_write()
            }
        }

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let server_task = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
            let client_tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let mut server_tcp = server_task.await.expect("server task");

            let called = Arc::new(AtomicBool::new(false));
            let stream: Box<dyn NetStream> =
                Box::new(PanicsOnPollShutdown { inner: client_tcp, shutdown_write_called: Arc::clone(&called) });
            let psk = [7u8; 16];
            let cipher = aesgcm(&psk).expect("cipher");
            let conn = new_conn(stream, cipher);

            conn.shutdown_write().expect("shutdown_write");
            assert!(called.load(Ordering::SeqCst), "shutdown_write must reach the wrapped stream's own shutdown_write");

            let mut buf = [0u8; 1];
            let n = server_tcp.read(&mut buf).await.expect("server sees the shutdown as EOF");
            assert_eq!(n, 0);
        })
        .await
        .expect("test timed out");
    }

    /// Regression test for the P2 finding: wrapping an already-open socket in a `shadowaead::Conn`
    /// must not duplicate its file descriptor (the pre-fix code held an extra `socket2::Socket`
    /// dup per conn, used only for a shutdown fallback that a plain forward, see the two tests
    /// above, no longer needs).
    ///
    /// The check counts the descriptors pointing at each client socket's inode rather than the
    /// process-wide descriptor total, so sibling tests opening sockets concurrently cannot move
    /// the number being asserted; only Linux exposes the descriptor targets in `/proc`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn new_conn_does_not_duplicate_the_wrapped_sockets_file_descriptor() {
        use std::os::fd::AsRawFd;

        /// The `/proc/self/fd` link target of every open descriptor, `socket:[N]` for sockets.
        fn open_fd_targets() -> Vec<String> {
            let Ok(dir) = std::fs::read_dir("/proc/self/fd") else {
                return Vec::new();
            };
            dir.filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
                .map(|target| target.to_string_lossy().into_owned())
                .collect()
        }

        fn descriptors_for(target: &str, all: &[String]) -> usize {
            all.iter().filter(|t| t.as_str() == target).count()
        }

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");

            let mut clients = Vec::new();
            let mut servers = Vec::new();
            for _ in 0..50 {
                let client = tokio::net::TcpStream::connect(addr).await.expect("connect");
                let (server, _) = listener.accept().await.expect("accept");
                clients.push(client);
                servers.push(server);
            }

            let client_targets: Vec<String> = clients
                .iter()
                .map(|client| {
                    std::fs::read_link(format!("/proc/self/fd/{}", client.as_raw_fd()))
                        .expect("read the client's own descriptor link")
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            let before = open_fd_targets();
            for target in &client_targets {
                assert_eq!(descriptors_for(target, &before), 1, "each client socket starts with one descriptor");
            }

            let psk = [7u8; 16];
            let mut conns = Vec::new();
            for client in clients {
                let cipher = aesgcm(&psk).expect("cipher");
                let stream: Box<dyn NetStream> = Box::new(client);
                conns.push(new_conn(stream, cipher));
            }

            let after = open_fd_targets();
            for (i, target) in client_targets.iter().enumerate() {
                assert_eq!(
                    descriptors_for(target, &after),
                    1,
                    "new_conn must not duplicate the wrapped stream's file descriptor (client {i} of {})",
                    client_targets.len()
                );
            }

            drop(conns);
            drop(servers);
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test]
    async fn writer_reader_round_trip_over_pipe() {
        let psk = [7u8; 16];
        let salt = [9u8; 16];
        let cipher = aesgcm(&psk).expect("aes-128-gcm cipher");
        let write_aead = cipher.encrypter(&salt).expect("writer subkey");
        let read_aead = cipher.decrypter(&salt).expect("reader subkey");

        let (client, server) = pipe();
        let mut writer = new_writer(Box::new(client), write_aead);
        let mut reader = new_reader(Box::new(server), read_aead);

        let payload = b"hello shadowaead framing";
        let write_task = tokio::spawn(async move {
            writer.write_all(payload).await.expect("write_all");
            writer.flush().await.expect("flush");
        });

        let mut buf = vec![0u8; payload.len()];
        reader.read_exact(&mut buf).await.expect("read_exact");
        write_task.await.expect("writer task");

        assert_eq!(&buf, payload);
    }

    /// Pins the writer's framing to fixed bytes: the salt-derived subkey, then two AEAD seal
    /// calls (the big-endian length record, then the payload record), each followed by a
    /// little-endian nonce increment, for a fixed psk and salt pair.
    async fn assert_writer_emits_reference_frames(cipher: Box<dyn Cipher>, salt: &[u8], want_hex: &str) {
        let payload = b"hello shadowaead framing";
        let aead = cipher.encrypter(salt).expect("subkey");
        let (client, server) = pipe();
        let mut writer = new_writer(Box::new(client), aead);

        let write_task = tokio::spawn(async move {
            writer.write_all(payload).await.expect("write_all");
            writer.flush().await.expect("flush");
        });

        let want = hex::decode(want_hex).expect("valid hex vector");
        let mut got = vec![0u8; want.len()];
        let mut server = server;
        server.read_exact(&mut got).await.expect("read exact frame");

        assert_eq!(got, want, "writer output diverges from the shadowaead.Writer.Write");

        let mut rest = Vec::new();
        if let Err(err) = server.read_to_end(&mut rest).await {
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "drain: {err}");
        }
        assert!(rest.is_empty(), "trailing bytes after the frame");

        write_task.await.expect("writer task");
    }

    /// Pins the reader to decode the same fixed bytes back to the original payload.
    async fn assert_reader_decodes_reference_frames(cipher: Box<dyn Cipher>, salt: &[u8], want_hex: &str) {
        let payload = b"hello shadowaead framing";
        let aead = cipher.decrypter(salt).expect("subkey");
        let want_bytes = hex::decode(want_hex).expect("valid hex vector");

        let (mut client, server) = pipe();
        let mut reader = new_reader(Box::new(server), aead);

        let feed_task = tokio::spawn(async move {
            client.write_all(&want_bytes).await.expect("feed reference bytes");
        });

        let mut got = vec![0u8; payload.len()];
        reader.read_exact(&mut got).await.expect("read_exact");
        feed_task.await.expect("feed task");

        assert_eq!(&got, payload);
    }

    #[tokio::test]
    async fn writer_emits_reference_frames_aes_128_gcm() {
        let psk = [7u8; 16];
        let salt = [9u8; 16];
        assert_writer_emits_reference_frames(
            aesgcm(&psk).expect("aes-128-gcm cipher"),
            &salt,
            "16e97361c2972e481ccdf4ad7704c57504c3ee97b5d9668819cbc0a1ddf90907a60482011fcfc6a08657378131ae735e77e90e572fc2c808c3bf",
        )
        .await;
    }

    #[tokio::test]
    async fn reader_decodes_reference_frames_aes_128_gcm() {
        let psk = [7u8; 16];
        let salt = [9u8; 16];
        assert_reader_decodes_reference_frames(
            aesgcm(&psk).expect("aes-128-gcm cipher"),
            &salt,
            "16e97361c2972e481ccdf4ad7704c57504c3ee97b5d9668819cbc0a1ddf90907a60482011fcfc6a08657378131ae735e77e90e572fc2c808c3bf",
        )
        .await;
    }

    #[tokio::test]
    async fn writer_emits_reference_frames_aes_256_gcm() {
        let psk = [7u8; 32];
        let salt = [9u8; 32];
        assert_writer_emits_reference_frames(
            aesgcm(&psk).expect("aes-256-gcm cipher"),
            &salt,
            "42cd3ffa6b366e4b6bc76e2720d668f0cf039e7ac2d00ce8aa8618a8e08885e4eb3aa9da823c3811bcc0ee08d2dc24dd8dc2d2de52aa2ff675f4",
        )
        .await;
    }

    #[tokio::test]
    async fn reader_decodes_reference_frames_aes_256_gcm() {
        let psk = [7u8; 32];
        let salt = [9u8; 32];
        assert_reader_decodes_reference_frames(
            aesgcm(&psk).expect("aes-256-gcm cipher"),
            &salt,
            "42cd3ffa6b366e4b6bc76e2720d668f0cf039e7ac2d00ce8aa8618a8e08885e4eb3aa9da823c3811bcc0ee08d2dc24dd8dc2d2de52aa2ff675f4",
        )
        .await;
    }

    #[tokio::test]
    async fn writer_emits_reference_frames_chacha20_ietf_poly1305() {
        let psk = [7u8; 32];
        let salt = [9u8; 32];
        assert_writer_emits_reference_frames(
            chacha20poly1305(&psk).expect("chacha20-ietf-poly1305 cipher"),
            &salt,
            "d8335a9db20d38efee3cf6f6e32f383fd3b666b41cf018f54080b52a709e6ee350b765cd08202de58141bba67772a90785ff403221830d20f776",
        )
        .await;
    }

    #[tokio::test]
    async fn reader_decodes_reference_frames_chacha20_ietf_poly1305() {
        let psk = [7u8; 32];
        let salt = [9u8; 32];
        assert_reader_decodes_reference_frames(
            chacha20poly1305(&psk).expect("chacha20-ietf-poly1305 cipher"),
            &salt,
            "d8335a9db20d38efee3cf6f6e32f383fd3b666b41cf018f54080b52a709e6ee350b765cd08202de58141bba67772a90785ff403221830d20f776",
        )
        .await;
    }
}

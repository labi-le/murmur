//! The Snell v4 frame protocol: chunked AEAD framing, padding and the salt exchange.

use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::{Rng, TryRngCore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common_net::io::Stream;
use murmur_transport_shadowsocks::shadowaead::cipher::Aead;
use murmur_transport_shadowsocks::shadowaead::stream::ErrZeroChunk;

use super::cipher::{aes_gcm, snell_kdf};
use super::snell::{poll_read_full, poll_write_once, to_io_error, unexpected_eof_error, MAX_LENGTH};

pub(crate) const V4_SALT_SIZE: usize = 16;
pub(crate) const V4_NONCE_SIZE: usize = 12;
pub(crate) const V4_HEADER_PLAIN_SIZE: usize = 7;
pub(crate) const V4_HEADER_CIPHER_SIZE: usize = V4_HEADER_PLAIN_SIZE + 16;
pub(crate) const V4_FRAME_SIZE: i32 = 1460;
pub(crate) const V4_INITIAL_PADDING_MIN: i32 = 0x100;
pub(crate) const V4_INITIAL_PADDING_SPAN: usize = 0x100;

/// The v4 frame's padding and payload lengths are 16-bit wire fields, and every value fed here is
/// bounded by `V4_FRAME_SIZE` (1460) or `MAX_LENGTH` (0x3FFF), so the saturation never clamps.
fn wire_u16(len: impl TryInto<u16>) -> u16 {
    len.try_into().unwrap_or(u16::MAX)
}

/// The zero-chunk sentinel as the `io::Error` a read hands back.
pub(crate) fn zero_chunk_error() -> io::Error {
    io::Error::other(ErrZeroChunk)
}

pub(crate) fn v4_aead(psk: &[u8], salt: &[u8]) -> anyhow::Result<Box<dyn Aead>> {
    aes_gcm(&snell_kdf(psk, salt, 16)?)
}

pub struct V4Conn {
    conn: Box<dyn Stream>,
    psk: Vec<u8>,
    r: Option<V4Reader>,
    w: Option<V4Writer>,
    r_salt: Vec<u8>,
    r_salt_filled: usize,
}

impl fmt::Debug for V4Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V4Conn").finish_non_exhaustive()
    }
}

pub(crate) fn new_v4_conn(conn: Box<dyn Stream>, psk: &[u8]) -> V4Conn {
    V4Conn { conn, psk: psk.to_vec(), r: None, w: None, r_salt: Vec::new(), r_salt_filled: 0 }
}

impl V4Conn {
    /// Initializes the reader. `Ok(false)` is the EOF from a peer that closed before the salt:
    /// the read side is at end of stream, which `AsyncRead` has to report as a zero-length read.
    fn poll_init_reader(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if self.r.is_some() {
            return Poll::Ready(Ok(true));
        }
        if self.r_salt.is_empty() {
            self.r_salt = vec![0u8; V4_SALT_SIZE];
        }
        if !ready!(poll_read_frame_part(&mut self.conn, cx, &mut self.r_salt, &mut self.r_salt_filled))? {
            self.r_salt.clear();
            self.r_salt_filled = 0;
            return Poll::Ready(Ok(false));
        }

        let aead = match v4_aead(&self.psk, &self.r_salt) {
            Ok(aead) => aead,
            Err(err) => {
                self.r_salt.clear();
                self.r_salt_filled = 0;
                return Poll::Ready(Err(to_io_error(err)));
            }
        };
        self.r = Some(V4Reader::new(aead));
        self.r_salt.clear();
        self.r_salt_filled = 0;
        Poll::Ready(Ok(true))
    }

    /// Initializes the writer; it does no I/O, so one poll finishes it.
    fn poll_init_writer(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.w.is_none() {
            match new_v4_writer(&self.psk) {
                Ok(w) => self.w = Some(w),
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
        Poll::Ready(Ok(()))
    }

    pub async fn write_packet_frame(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.len() > MAX_LENGTH {
            return Err(io::Error::other("snell v4 frame too large"));
        }

        poll_fn(|cx| {
            ready!(self.poll_init_writer(cx))?;
            let Self { conn, w, .. } = self;
            let Some(w) = w.as_mut() else {
                return Poll::Ready(Err(io::Error::other("snell v4 writer uninitialised")));
            };
            let padding_length = w.next_frame_padding_length(b.len());
            ready!(w.poll_write_frame(conn, cx, b, padding_length))?;
            Poll::Ready(Ok(b.len()))
        })
        .await
    }

    pub async fn write_to<W>(&mut self, w: &mut W) -> io::Result<i64>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        if self.r.is_none() && !poll_fn(|cx| self.poll_init_reader(cx)).await? {
            return Ok(0);
        }

        let mut written = 0i64;
        let mut buf = vec![0u8; MAX_LENGTH];
        loop {
            let n = tokio::io::AsyncReadExt::read(self, &mut buf).await?;
            if n == 0 {
                return Ok(written);
            }
            let (chunk, _) = buf.split_at(n);
            let nw = tokio::io::AsyncWriteExt::write(w, chunk).await?;
            #[expect(
                clippy::cast_possible_wrap,
                reason = "`nw` is a write count bounded by `MAX_LENGTH`, so it is exact in `i64`"
            )]
            let written_now = nw as i64;
            written += written_now;
            if nw != n {
                return Err(io::Error::other("short write"));
            }
        }
    }

    pub async fn read_from<R>(&mut self, r: &mut R) -> io::Result<i64>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        if self.w.is_none() {
            poll_fn(|cx| self.poll_init_writer(cx)).await?;
        }

        let mut read = 0i64;
        let mut buf = vec![0u8; MAX_LENGTH];
        loop {
            let n = match tokio::io::AsyncReadExt::read(r, &mut buf).await {
                // An in-memory reader answers with the EOF error value where a socket
                // answers a zero-length read.
                Ok(0) => return Ok(read),
                Ok(n) => n,
                Err(err) if is_eof(&err) => return Ok(read),
                Err(err) => return Err(err),
            };
            #[expect(
                clippy::cast_possible_wrap,
                reason = "`n` is a read count bounded by `MAX_LENGTH`, so it is exact in `i64`"
            )]
            let read_now = n as i64;
            read += read_now;
            let (chunk, _) = buf.split_at(n);
            tokio::io::AsyncWriteExt::write(self, chunk).await?;
        }
    }
}

/// The two-byte big-endian field at `offset` of a v4 frame header.
fn header_u16(header: &[u8], offset: usize) -> io::Result<u16> {
    let field = header
        .get(offset..)
        .and_then(|field| field.first_chunk::<2>())
        .ok_or_else(|| io::Error::other("snell v4 invalid frame header"))?;
    Ok(u16::from_be_bytes(*field))
}

fn is_eof(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::UnexpectedEof && err.to_string() == "EOF"
}

/// Read exactly one frame part, folding both spellings of a clean end of stream into
/// `Ok(false)`: a socket answers a zero-length read, an in-memory reader answers with the
/// EOF error value. The error spelling only counts as a clean end while nothing of the part
/// has arrived, so a torn frame keeps `UnexpectedEof`.
fn poll_read_frame_part<R>(
    conn: &mut R,
    cx: &mut Context<'_>,
    part: &mut [u8],
    filled: &mut usize,
) -> Poll<io::Result<bool>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    match poll_read_full(conn, cx, part, filled) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(complete)) => Poll::Ready(Ok(complete)),
        Poll::Ready(Err(err)) if is_eof(&err) => {
            if *filled == 0 {
                Poll::Ready(Ok(false))
            } else {
                Poll::Ready(Err(unexpected_eof_error()))
            }
        }
        Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
    }
}

impl AsyncRead for V4Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // A peer that closed before the salt is a half-close of the read side, not a failure: the
        // relay ends only that direction on the EOF this hands back.
        if !ready!(this.poll_init_reader(cx))? {
            return Poll::Ready(Ok(()));
        }
        match this.r.as_mut() {
            Some(r) => r.poll_read(&mut this.conn, cx, buf),
            None => Poll::Ready(Err(io::Error::other("snell v4: reader not initialised"))),
        }
    }
}

impl AsyncWrite for V4Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_init_writer(cx))?;

        let Self { conn, w, .. } = this;
        let Some(w) = w.as_mut() else {
            return Poll::Ready(Err(io::Error::other("snell v4 writer uninitialised")));
        };
        w.poll_write(conn, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl Stream for V4Conn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.conn.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn.old_conn()
    }
}

/// Which half of the blocking frame read is due.
enum ReadStage {
    Header,
    Payload,
}

pub(crate) struct V4Reader {
    aead: Box<dyn Aead>,
    nonce: [u8; V4_NONCE_SIZE],
    buf: Vec<u8>,
    stage: ReadStage,
    header_cipher: Vec<u8>,
    header_filled: usize,
    frame: Vec<u8>,
    frame_filled: usize,
    padding_length: usize,
    payload_cipher_length: usize,
}

impl V4Reader {
    pub(crate) fn new(aead: Box<dyn Aead>) -> Self {
        Self {
            aead,
            nonce: [0; V4_NONCE_SIZE],
            buf: Vec::new(),
            stage: ReadStage::Header,
            header_cipher: Vec::new(),
            header_filled: 0,
            frame: Vec::new(),
            frame_filled: 0,
            padding_length: 0,
            payload_cipher_length: 0,
        }
    }

    /// Reads, driven to completion; the conn paths use [`Self::poll_read`].
    #[cfg(test)]
    pub(crate) async fn read<R>(&mut self, conn: &mut R, b: &mut [u8]) -> io::Result<usize>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        poll_fn(|cx| {
            if self.buf.is_empty() && !ready!(self.poll_read_frame(conn, cx))? {
                return Poll::Ready(Ok(0));
            }
            let n = b.len().min(self.buf.len());
            b[..n].copy_from_slice(&self.buf[..n]);
            self.buf.drain(..n);
            Poll::Ready(Ok(n))
        })
        .await
    }

    fn poll_read<R>(&mut self, conn: &mut R, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        if self.buf.is_empty() && !ready!(self.poll_read_frame(conn, cx))? {
            return Poll::Ready(Ok(()));
        }
        let n = out.remaining().min(self.buf.len());
        let (chunk, _) = self.buf.split_at(n);
        out.put_slice(chunk);
        self.buf.drain(..n);
        Poll::Ready(Ok(()))
    }

    /// Reads one frame. `Ok(false)` is the end-of-stream at a frame boundary.
    fn poll_read_frame<R>(&mut self, conn: &mut R, cx: &mut Context<'_>) -> Poll<io::Result<bool>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        loop {
            match self.stage {
                ReadStage::Header => {
                    if self.header_cipher.len() != V4_HEADER_CIPHER_SIZE {
                        self.header_cipher.resize(V4_HEADER_CIPHER_SIZE, 0);
                    }
                    if !ready!(poll_read_frame_part(conn, cx, &mut self.header_cipher, &mut self.header_filled))? {
                        return Poll::Ready(Ok(false));
                    }
                    let header_len =
                        self.aead.open_in_place(&self.nonce, &mut self.header_cipher, &[]).map_err(to_io_error)?.len();
                    increment_v4_nonce(&mut self.nonce);
                    if header_len != V4_HEADER_PLAIN_SIZE || self.header_cipher.first() != Some(&4) {
                        return Poll::Ready(Err(io::Error::other("snell v4 invalid frame header")));
                    }

                    let padding_length = usize::from(header_u16(&self.header_cipher, 3)?);
                    let payload_length = usize::from(header_u16(&self.header_cipher, 5)?);
                    if payload_length == 0 {
                        if padding_length != 0 {
                            return Poll::Ready(Err(io::Error::other("snell v4 zero chunk with padding")));
                        }
                        return Poll::Ready(Err(zero_chunk_error()));
                    }
                    if payload_length > MAX_LENGTH || padding_length > MAX_LENGTH {
                        return Poll::Ready(Err(io::Error::other("snell v4 frame too large")));
                    }

                    self.payload_cipher_length = payload_length + self.aead.overhead();
                    let frame_len = padding_length + self.payload_cipher_length;
                    if self.frame.len() != frame_len {
                        self.frame.resize(frame_len, 0);
                    }
                    self.frame_filled = 0;
                    self.padding_length = padding_length;
                    self.header_filled = 0;
                    self.stage = ReadStage::Payload;
                }
                ReadStage::Payload => {
                    if !ready!(poll_read_frame_part(conn, cx, &mut self.frame, &mut self.frame_filled))? {
                        return Poll::Ready(Ok(false));
                    }
                    let (padding, payload_cipher) = self.frame.split_at_mut(self.padding_length);
                    if self.padding_length > 0 {
                        swap_padding(padding, payload_cipher);
                    }

                    let payload_len =
                        self.aead.open_in_place(&self.nonce, payload_cipher, &[]).map_err(to_io_error)?.len();
                    increment_v4_nonce(&mut self.nonce);

                    self.buf.clear();
                    let (plaintext, _) = payload_cipher.split_at(payload_len);
                    self.buf.extend_from_slice(plaintext);
                    self.frame_filled = 0;
                    self.padding_length = 0;
                    self.payload_cipher_length = 0;
                    self.stage = ReadStage::Header;
                    return Poll::Ready(Ok(true));
                }
            }
        }
    }
}

pub(crate) struct V4Writer {
    aead: Box<dyn Aead>,
    nonce: [u8; V4_NONCE_SIZE],
    salt: [u8; V4_SALT_SIZE],
    salt_sent: bool,
    initial_padding_length: u16,
    payload_limit: u16,
    last_write: Option<Instant>,
    /// The single write of one frame, which the conn resumes over polls.
    frame: Vec<u8>,
    frame_pending: bool,
    frame_offset: usize,
    /// End of the buffer range the in-flight frame covers, kept so a resumed poll re-frames the
    /// same bytes instead of a wider (and differently sized) range.
    frame_end: usize,
    /// The in-flight frame's padding, decided when the frame was built.
    frame_padding_length: usize,
    /// [`Self::build_frame`]'s scratch buffers, kept across calls instead of reallocated per frame.
    header_cipher: Vec<u8>,
    payload_cipher: Vec<u8>,
    /// The `Write` cursor over the buffer it was handed.
    written: usize,
    write_op_started: bool,
    /// The buffer the in-flight write covers, as an address: it belongs to the caller and may be
    /// gone by the time this writer is polled again. `poll_write` answers `Pending` or the whole
    /// count, so a resumed poll repeats the same slice and any other slice is a new operation.
    write_op: (usize, usize),
}

pub(crate) fn new_v4_writer(psk: &[u8]) -> io::Result<V4Writer> {
    let mut salt = [0u8; V4_SALT_SIZE];
    OsRng.try_fill_bytes(&mut salt).map_err(|err| io::Error::other(err.to_string()))?;

    let aead = v4_aead(psk, &salt).map_err(to_io_error)?;
    let padding_delta = wire_u16(crypto_random_int(V4_INITIAL_PADDING_SPAN));
    Ok(V4Writer {
        aead,
        nonce: [0; V4_NONCE_SIZE],
        salt,
        salt_sent: false,
        initial_padding_length: wire_u16(V4_INITIAL_PADDING_MIN + i32::from(padding_delta)),
        payload_limit: 0,
        last_write: None,
        frame: Vec::new(),
        frame_pending: false,
        frame_offset: 0,
        frame_end: 0,
        frame_padding_length: 0,
        header_cipher: Vec::new(),
        payload_cipher: Vec::new(),
        written: 0,
        write_op_started: false,
        write_op: (0, 0),
    })
}

impl V4Writer {
    /// The payload sizing for one write.
    fn next_payload_limit(&mut self) -> u16 {
        let now = Instant::now();
        let max_length = wire_u16(MAX_LENGTH);
        let payload_limit = match self.last_write {
            None => wire_u16(V4_FRAME_SIZE - 55 - i32::from(self.initial_padding_length)),
            Some(last_write) if now.duration_since(last_write) > Duration::from_secs(30) => {
                wire_u16(V4_FRAME_SIZE - 39)
            }
            Some(_) => self.payload_limit,
        };
        self.last_write = Some(now);

        if payload_limit < max_length {
            let next = i32::from(payload_limit) + V4_FRAME_SIZE - 39;
            self.payload_limit = if next > i32::from(max_length) { max_length } else { wire_u16(next) };
        } else {
            self.payload_limit = max_length;
        }
        payload_limit
    }

    fn next_frame_padding_length(&self, payload_length: usize) -> usize {
        if self.salt_sent || payload_length == 0 {
            return 0;
        }
        usize::from(self.initial_padding_length)
    }

    /// Writes, driven to completion; the conn paths use [`Self::poll_write`].
    #[cfg(test)]
    pub(crate) async fn write<W>(&mut self, w: &mut W, b: &[u8]) -> io::Result<usize>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        poll_fn(|cx| self.poll_write(w, cx, b)).await
    }

    fn poll_write<W>(&mut self, w: &mut W, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        if self.write_op_started && self.write_op != (buf.as_ptr() as usize, buf.len()) {
            // The write holds the mux for the whole call, so the next one can only start once
            // the abandoned frame is on the wire; the drain below writes it out here. An operation that
            // comes back afterwards re-frames its bytes, a duplication the mutex made unreachable.
            ready!(self.poll_drain_frame(w, cx))?;
            self.write_op_started = false;
        }
        if !self.write_op_started {
            self.written = 0;
            self.write_op = (buf.as_ptr() as usize, buf.len());
            self.write_op_started = true;
        }

        if buf.is_empty() {
            ready!(self.poll_write_frame(w, cx, &[], 0))?;
            self.write_op_started = false;
            return Poll::Ready(Ok(0));
        }

        loop {
            if self.written >= buf.len() {
                self.write_op_started = false;
                return Poll::Ready(Ok(self.written));
            }

            // The frame's extent belongs to the frame, not to the poll: the payload limit grows
            // on every call, so recomputing `end` on a resumed poll would move the write cursor
            // past the bytes the in-flight frame does not cover, dropping them.
            if !self.frame_pending {
                let max_length = i32::from(wire_u16(MAX_LENGTH));
                let mut payload_limit = i32::from(self.next_payload_limit());
                if payload_limit <= 0 || payload_limit > max_length {
                    payload_limit = max_length;
                }
                self.frame_end = (self.written + usize::from(wire_u16(payload_limit))).min(buf.len());
                self.frame_padding_length = self.next_frame_padding_length(self.frame_end - self.written);
            }
            let frame_end = self.frame_end;
            let padding_length = self.frame_padding_length;
            let (_, tail) = buf.split_at(self.written);
            let (frame, _) = tail.split_at(frame_end - self.written);
            ready!(self.poll_write_frame(w, cx, frame, padding_length))?;
            self.written = frame_end;
        }
    }

    /// Writes one frame, driven to completion; the conn paths use [`Self::poll_write_frame`].
    #[cfg(test)]
    async fn write_frame<W>(&mut self, w: &mut W, payload: &[u8], padding_length: usize) -> io::Result<()>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        poll_fn(|cx| self.poll_write_frame(w, cx, payload, padding_length)).await
    }

    fn poll_write_frame<W>(
        &mut self,
        w: &mut W,
        cx: &mut Context<'_>,
        payload: &[u8],
        padding_length: usize,
    ) -> Poll<io::Result<()>>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        if !self.frame_pending {
            self.build_frame(payload, padding_length)?;
            self.frame_pending = true;
            self.frame_offset = 0;
        }

        self.poll_drain_frame(w, cx)
    }

    /// Writes out the frame an earlier poll already built. No-op when no frame is in flight.
    fn poll_drain_frame<W>(&mut self, w: &mut W, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        if !self.frame_pending {
            return Poll::Ready(Ok(()));
        }

        ready!(poll_write_once(w, cx, &self.frame, &mut self.frame_offset))?;
        self.frame_pending = false;
        self.frame.clear();
        Poll::Ready(Ok(()))
    }

    /// Builds one frame directly into `self.frame`.
    fn build_frame(&mut self, payload: &[u8], padding_length: usize) -> io::Result<()> {
        if payload.len() > MAX_LENGTH || padding_length > MAX_LENGTH {
            return Err(io::Error::other("snell v4 frame too large"));
        }
        if payload.is_empty() && padding_length != 0 {
            return Err(io::Error::other("snell v4 zero chunk with padding"));
        }

        let mut header = [0u8; V4_HEADER_PLAIN_SIZE];
        header[0] = 4;
        header[3..5].copy_from_slice(&wire_u16(padding_length).to_be_bytes());
        header[5..7].copy_from_slice(&wire_u16(payload.len()).to_be_bytes());

        self.header_cipher.clear();
        self.aead.seal(&mut self.header_cipher, &self.nonce, &header, &[]).map_err(to_io_error)?;
        increment_v4_nonce(&mut self.nonce);

        self.payload_cipher.clear();
        if !payload.is_empty() {
            self.aead.seal(&mut self.payload_cipher, &self.nonce, payload, &[]).map_err(to_io_error)?;
            increment_v4_nonce(&mut self.nonce);
        }

        let frame_length = self.header_cipher.len()
            + padding_length
            + self.payload_cipher.len()
            + if self.salt_sent { 0 } else { V4_SALT_SIZE };
        self.frame.clear();
        self.frame.reserve(frame_length);
        if !self.salt_sent {
            self.frame.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
        self.frame.extend_from_slice(&self.header_cipher);
        if padding_length > 0 {
            let mut padding = make_v4_padding(&self.payload_cipher, padding_length)?;
            swap_padding(&mut padding, &mut self.payload_cipher);
            self.frame.extend_from_slice(&padding);
        }
        self.frame.extend_from_slice(&self.payload_cipher);

        Ok(())
    }
}

fn swap_padding(padding: &mut [u8], payload_cipher: &mut [u8]) {
    for (padding_byte, payload_byte) in padding.iter_mut().zip(payload_cipher.iter_mut()).step_by(2) {
        core::mem::swap(padding_byte, payload_byte);
    }
}

#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "the padding ratio is picked in `f64` and the resulting bit count truncated back to an integer; the bit counts are frame-sized and exact"
)]
fn make_v4_padding(payload_cipher: &[u8], padding_length: usize) -> io::Result<Vec<u8>> {
    if padding_length == 0 {
        return Ok(Vec::new());
    }

    let payload_ones = count_v4_payload_ones(payload_cipher);
    let payload_zeros = 8 * payload_cipher.len() - payload_ones;
    if payload_zeros == 0 {
        return make_v4_random_padding(padding_length);
    }

    let ratio = payload_ones as f64 / payload_zeros as f64;
    if ratio <= 0.5 || ratio >= 1.6 {
        return make_v4_random_padding(padding_length);
    }

    let target_ratio_base = if payload_zeros < payload_ones { 0.4 } else { 1.6 };
    let jitter = random_unit_float64();
    let target_ratio = target_ratio_base + jitter / 10.0;
    let total_bits = 8 * (padding_length + payload_cipher.len());
    let target_ones = (total_bits as f64).mul_add(target_ratio / (target_ratio + 1.0), -(payload_ones as f64)) as i64;
    if target_ones < 0 || target_ones > (8 * padding_length) as i64 {
        return make_v4_random_padding(padding_length);
    }

    make_v4_bit_count_padding(padding_length, target_ones as usize)
}

fn count_v4_payload_ones(payload_cipher: &[u8]) -> usize {
    let limit = payload_cipher.len() & !3;
    let (whole, _) = payload_cipher.split_at(limit);
    whole.iter().map(|byte| byte.count_ones() as usize).sum()
}

fn make_v4_random_padding(length: usize) -> io::Result<Vec<u8>> {
    let mut padding = vec![0u8; length];
    OsRng.try_fill_bytes(&mut padding).map_err(|err| io::Error::other(err.to_string()))?;
    Ok(padding)
}

fn make_v4_bit_count_padding(length: usize, one_bits: usize) -> io::Result<Vec<u8>> {
    let total_bits = 8 * length;
    if one_bits > total_bits {
        return Err(io::Error::other("snell v4 invalid padding bit count"));
    }

    let mut bitset = vec![0u8; total_bits];
    for bit in bitset.iter_mut().take(one_bits) {
        *bit = 1;
    }
    for i in (1..total_bits).rev() {
        let j = crypto_random_int(i + 1);
        bitset.swap(i, j);
    }

    let mut padding = vec![0u8; length];
    for (byte, bits) in padding.iter_mut().zip(bitset.chunks_exact(8)) {
        for (index, bit) in bits.iter().enumerate() {
            if *bit == 1 {
                *byte |= 1 << index;
            }
        }
    }
    Ok(padding)
}

/// The thread rng is the crate's uniform source and cannot fail.
fn crypto_random_int(max: usize) -> usize {
    rand::rng().random_range(0..max)
}

#[expect(
    clippy::cast_precision_loss,
    reason = "`DENOMINATOR` is 2^53 and the drawn value stays below it, so both conversions to `f64` are exact"
)]
fn random_unit_float64() -> f64 {
    const DENOMINATOR: u64 = 1 << 53;
    rand::rng().random_range(0..DENOMINATOR) as f64 / DENOMINATOR as f64
}

pub(crate) fn increment_v4_nonce(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::net::{TcpListener, TcpStream};

    use murmur_common_net::io::OldConnAsStream;
    use murmur_common_net::relay_streams;
    use murmur_std_compat::net::{Addr, Conn as NetConn, UdpAddr};
    use murmur_transport::socks5::socks5;

    use super::*;
    use crate::snell::{
        packet_conn, write_header_with_reuse, write_packet, write_packet_response, PacketConnConn, PacketFrameWriter,
        Snell, SnellConn, COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_ERROR, COMMAND_TUNNEL, COMMOND_UDP_FORWARD,
        MAX_LENGTH, VERSION1, VERSION2, VERSION4,
    };

    /// An in-memory pipe stand-in.
    struct PipeConn(DuplexStream);

    impl AsyncRead for PipeConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PipeConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl NetConn for PipeConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(DummyAddr("pipe")))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(DummyAddr("pipe")))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct BufferConn {
        buf: Vec<u8>,
        pos: usize,
    }

    impl BufferConn {
        fn with(data: &[u8]) -> BufferConn {
            BufferConn { buf: data.to_vec(), pos: 0 }
        }

        fn write_bytes(&mut self, data: &[u8]) {
            self.buf.extend_from_slice(data);
        }
    }

    impl AsyncRead for BufferConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let n = buf.remaining().min(this.buf.len() - this.pos);
            buf.put_slice(&this.buf[this.pos..this.pos + n]);
            this.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for BufferConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.get_mut().write_bytes(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl NetConn for BufferConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(DummyAddr("local")))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(DummyAddr("remote")))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingWriter {
        buf: Vec<u8>,
        writes: usize,
    }

    impl RecordingWriter {
        fn write_bytes(&mut self, b: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            self.buf.extend_from_slice(b);
            Ok(b.len())
        }
    }

    impl AsyncWrite for RecordingWriter {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(self.get_mut().write_bytes(buf))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[async_trait]
    impl PacketFrameWriter for RecordingWriter {
        async fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.write_bytes(b)
        }
    }

    #[derive(Debug)]
    struct DummyAddr(&'static str);

    impl Addr for DummyAddr {
        fn network(&self) -> &str {
            self.0
        }

        fn string(&self) -> String {
            self.0.to_owned()
        }
    }

    fn decode_v4_header_for_test(data: &[u8]) -> (usize, usize) {
        assert!(data.len() >= V4_SALT_SIZE + V4_HEADER_CIPHER_SIZE, "frame too short: {}", data.len());
        let aead = v4_aead(b"password", &data[..V4_SALT_SIZE]).expect("v4 aead");
        let nonce = [0u8; V4_NONCE_SIZE];
        let header =
            aead.open(&nonce, &data[V4_SALT_SIZE..V4_SALT_SIZE + V4_HEADER_CIPHER_SIZE], &[]).expect("open header");
        assert!(header.len() == V4_HEADER_PLAIN_SIZE && header[0] == 4, "invalid v4 header");
        (
            usize::from(u16::from_be_bytes([header[3], header[4]])),
            usize::from(u16::from_be_bytes([header[5], header[6]])),
        )
    }

    /// A real loopback pair, so `Stream::shutdown_write` is a FIN the peer observes as a
    /// zero-length read instead of a buffered no-op.
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("listener addr");
        let client = TcpStream::connect(addr).await.expect("connect loopback");
        let (server, _) = listener.accept().await.expect("accept loopback");
        (client, server)
    }

    /// A clean end of the v4 frame stream is a zero-length read at an `AsyncRead` boundary: a
    /// half-close, leaving the reverse direction open.
    #[tokio::test]
    async fn test_snell_v4_clean_eof_reads_as_zero_length() {
        let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
        let mut client = new_v4_conn(Box::new(OldConnAsStream(PipeConn(client_raw))), b"password");
        let mut server = new_v4_conn(Box::new(OldConnAsStream(PipeConn(server_raw))), b"password");

        client.write_all(b"hello").await.expect("first frame");
        client.shutdown().await.expect("half-close after the last frame");

        let mut buf = [0u8; 5];
        server.read_exact(&mut buf).await.expect("payload before the half-close");
        assert_eq!("hello", String::from_utf8_lossy(&buf));

        let mut out = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), server.read(&mut out))
            .await
            .expect("read must not hang after the peer's half-close")
            .expect("a clean end of stream is not a read error");
        assert_eq!(0, n, "the peer's half-close must read as EOF");

        server.write_all(b"still open").await.expect("write after the read side hit EOF");
        let mut back = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut back))
            .await
            .expect("the reverse direction must survive the peer's half-close")
            .expect("read the reverse direction");
        assert_eq!("still open", String::from_utf8_lossy(&back));
    }

    /// Reproduces the 1 MiB full-duplex hang: a peer that sends its last frame and half-closes
    /// must end only the download direction. A read error there instead tears the whole conn down
    /// and silently drops the upload the local peer keeps writing.
    #[tokio::test]
    async fn test_snell_v4_clean_eof_half_closes_the_relay() {
        const DOWNLOAD: usize = 1024 * 1024;
        const UPLOAD: &[u8] = b"upload after the peer's half-close";

        let (mut app, mut relay_left) = tcp_pair().await;
        let (relay_right, peer) = tcp_pair().await;
        let mut client = Box::new(new_v4_conn(Box::new(relay_right), b"password"));
        let mut server = new_v4_conn(Box::new(peer), b"password");

        let peer_task = tokio::spawn(async move {
            server.write_all(&vec![0x5Au8; DOWNLOAD]).await?;
            server.shutdown_write().expect("half-close the peer's write side");
            let mut upload = vec![0u8; UPLOAD.len()];
            tokio::time::timeout(Duration::from_secs(5), server.read_exact(&mut upload))
                .await
                .map_err(|_| io::Error::other("the upload written after the half-close never arrived"))??;
            Ok::<_, io::Error>(upload)
        });
        let relay_task = tokio::spawn(async move { relay_streams(&mut relay_left, &mut *client).await });

        let mut received = vec![0u8; DOWNLOAD];
        match tokio::time::timeout(Duration::from_secs(20), app.read_exact(&mut received)).await {
            Ok(Ok(_)) => {}
            other => {
                let peer = tokio::time::timeout(Duration::from_millis(500), peer_task).await;
                panic!(
                    "download {other:?}, peer {peer:?}, got {} bytes",
                    received.iter().position(|b| *b != 0x5A).unwrap_or(DOWNLOAD)
                );
            }
        }

        let mut eof = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(20), app.read(&mut eof))
            .await
            .expect("the peer's half-close must not hang")
            .expect("the peer's half-close must reach the local peer as EOF, not as a read error");
        assert_eq!(0, n, "the peer's half-close must not be reported as data");

        app.write_all(UPLOAD).await.expect("the local upload must survive the peer's half-close");
        app.shutdown().await.expect("close the local write side");

        let upload = tokio::time::timeout(Duration::from_secs(10), peer_task)
            .await
            .expect("the peer must not hang waiting for the upload")
            .expect("peer task")
            .expect("the peer must receive the upload written after its half-close");
        assert_eq!(UPLOAD, &upload[..], "the upload after the half-close was corrupted");
        tokio::time::timeout(Duration::from_secs(10), relay_task)
            .await
            .expect("relay must finish")
            .expect("relay task");
    }

    /// A frame that stops mid-way is not a half-close: the read reports
    /// `UnexpectedEof`, and a relay must not read a torn frame as a clean end of stream.
    #[tokio::test]
    async fn test_snell_v4_truncated_frame_is_not_a_clean_eof() {
        let mut raw = BufferConn::default();
        new_v4_writer(b"password").expect("v4 writer").write_frame(&mut raw, b"payload", 0).await.expect("frame");
        let data = raw.buf.clone();
        let mut reader = V4Reader::new(v4_aead(b"password", &data[..V4_SALT_SIZE]).expect("v4 aead"));

        let mut conn = BufferConn::with(&data[V4_SALT_SIZE..V4_SALT_SIZE + 4]);
        let err = reader.read(&mut conn, &mut [0u8; 7]).await.expect_err("a torn frame must not read as EOF");
        assert_eq!(io::ErrorKind::UnexpectedEof, err.kind(), "unexpected error for a torn frame");
    }

    /// A sink that takes `chunk` bytes per poll and goes `Pending` otherwise, the way a socket
    /// with a full send buffer does.
    struct ChunkedWriter {
        chunk: usize,
        buf: Vec<u8>,
        polls: usize,
    }

    impl AsyncWrite for ChunkedWriter {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.polls += 1;
            if this.polls.is_multiple_of(2) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = buf.len().min(this.chunk);
            this.buf.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// One frame is a single blocking write; the conn resumes a frame that only partly reached
    /// the conn. A resumed poll must frame the bytes the pending one started, or a transfer that
    /// outgrows the conn's write buffer (a 1 MiB download) silently loses the rest and the peer
    /// waits for data that never arrives.
    #[tokio::test]
    async fn test_snell_v4_write_resumes_a_pending_frame_without_dropping_bytes() {
        const DOWNLOAD: usize = 1024 * 1024;
        let payload: Vec<u8> = (0..DOWNLOAD).map(|i| (i % 251) as u8).collect();

        let mut sink = ChunkedWriter { chunk: 700, buf: Vec::new(), polls: 0 };
        new_v4_writer(b"password").expect("v4 writer").write(&mut sink, &payload).await.expect("write");

        let data = sink.buf.clone();
        let mut reader = V4Reader::new(v4_aead(b"password", &data[..V4_SALT_SIZE]).expect("v4 aead"));
        let mut conn = BufferConn::with(&data[V4_SALT_SIZE..]);
        let mut decoded = Vec::with_capacity(DOWNLOAD);
        let mut buf = vec![0u8; MAX_LENGTH];
        while decoded.len() < DOWNLOAD {
            let n = reader.read(&mut conn, &mut buf).await.expect("decode");
            assert!(n > 0, "the frame stream ended after {} of {DOWNLOAD} bytes", decoded.len());
            decoded.extend_from_slice(&buf[..n]);
        }
        assert_eq!(decoded, payload, "the v4 write dropped or reordered bytes across polls");
    }

    /// The `Write` cannot be abandoned half-way through a frame, so the writer has to notice that
    /// the next write is a different operation: finish the stale frame, then frame the new buffer
    /// from its first byte instead of reporting the stale frame's extent as this write's count.
    #[tokio::test]
    async fn test_snell_v4_write_after_an_abandoned_write_finishes_the_pending_frame() {
        const FIRST: usize = 64;
        const SECOND: usize = 32;

        let mut sink = ChunkedWriter { chunk: 8, buf: Vec::new(), polls: 0 };
        let mut writer = new_v4_writer(b"password").expect("v4 writer");

        // Poll once: the sink accepts a prefix, then parks. Do not let a timer race its wakes.
        let abandoned = vec![0x11u8; FIRST];
        let stalled = poll_fn(|cx| Poll::Ready(writer.poll_write(&mut sink, cx, &abandoned))).await;
        assert!(stalled.is_pending(), "the first write must stall mid-frame for this probe");
        assert!(writer.frame_offset > 0 && writer.frame_offset < writer.frame.len(), "a frame must be partly written");

        let second = vec![0x22u8; SECOND];
        let written = writer.write(&mut sink, &second).await.expect("second write");
        assert_eq!(written, SECOND, "a new write must report its own buffer's length");

        let data = sink.buf.clone();
        let mut reader = V4Reader::new(v4_aead(b"password", &data[..V4_SALT_SIZE]).expect("v4 aead"));
        let mut conn = BufferConn::with(&data[V4_SALT_SIZE..]);
        let mut decoded = Vec::with_capacity(FIRST + SECOND);
        let mut buf = vec![0u8; MAX_LENGTH];
        while decoded.len() < FIRST + SECOND {
            let n = reader.read(&mut conn, &mut buf).await.expect("decode");
            assert!(n > 0, "the frame stream ended after {} of {} bytes", decoded.len(), FIRST + SECOND);
            decoded.extend_from_slice(&buf[..n]);
        }
        let mut expected = vec![0x11u8; FIRST];
        expected.extend_from_slice(&second);
        assert_eq!(decoded, expected, "the abandoned frame must reach the wire before the new write's bytes");
    }

    #[tokio::test]
    async fn test_snell_v4_round_trip() {
        let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
        let mut client = new_v4_conn(Box::new(OldConnAsStream(PipeConn(client_raw))), b"password");
        let mut server = new_v4_conn(Box::new(OldConnAsStream(PipeConn(server_raw))), b"password");

        let write_err = tokio::spawn(async move { AsyncWriteExt::write(&mut client, b"hello").await.map(|_| ()) });

        let mut buf = [0u8; 5];
        if let Err(err) = server.read_exact(&mut buf).await {
            panic!("{err}");
        }
        assert_eq!("hello", String::from_utf8_lossy(&buf));
        match write_err.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("{err}"),
            Err(err) => panic!("{err}"),
        }
    }

    #[tokio::test]
    async fn test_snell_v4_zero_chunk() {
        let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
        let mut client = new_v4_conn(Box::new(OldConnAsStream(PipeConn(client_raw))), b"password");
        let mut server = new_v4_conn(Box::new(OldConnAsStream(PipeConn(server_raw))), b"password");

        let write_err = tokio::spawn(async move { AsyncWriteExt::write(&mut client, &[]).await.map(|_| ()) });

        let err = server.read_exact(&mut [0u8; 1]).await.expect_err("zero chunk");
        assert!(err.to_string().contains("zero chunk"), "expected zero chunk, got {err}");
        match write_err.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("{err}"),
            Err(err) => panic!("{err}"),
        }
    }

    #[tokio::test]
    async fn test_snell_v4_first_frame_includes_initial_padding() {
        let (client_raw, server_raw) = tokio::io::duplex(64 * 1024);
        let mut client = new_v4_conn(Box::new(OldConnAsStream(PipeConn(client_raw))), b"password");
        let mut server_raw = server_raw;

        let write_err = tokio::spawn(async move { AsyncWriteExt::write(&mut client, b"x").await.map(|_| ()) });

        let mut salt = [0u8; V4_SALT_SIZE];
        if let Err(err) = server_raw.read_exact(&mut salt).await {
            panic!("{err}");
        }

        let mut header_cipher = [0u8; V4_HEADER_CIPHER_SIZE];
        if let Err(err) = server_raw.read_exact(&mut header_cipher).await {
            panic!("{err}");
        }
        let aead = match v4_aead(b"password", &salt) {
            Ok(aead) => aead,
            Err(err) => panic!("{err}"),
        };
        let nonce = [0u8; V4_NONCE_SIZE];
        let header = match aead.open(&nonce, &header_cipher, &[]) {
            Ok(header) => header,
            Err(err) => panic!("{err}"),
        };
        let padding_length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let payload_length = usize::from(u16::from_be_bytes([header[5], header[6]]));
        assert!(
            padding_length >= V4_INITIAL_PADDING_MIN as usize
                && padding_length < (V4_INITIAL_PADDING_MIN as usize + V4_INITIAL_PADDING_SPAN),
            "unexpected initial padding length: {padding_length}"
        );
        assert_eq!(1, payload_length, "unexpected first payload length");

        let mut rest = vec![0u8; padding_length + payload_length + aead.overhead()];
        if let Err(err) = server_raw.read_exact(&mut rest).await {
            panic!("{err}");
        }
        match write_err.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("{err}"),
            Err(err) => panic!("{err}"),
        }
    }

    #[tokio::test]
    async fn test_snell_v4_padded_frame() {
        let mut raw = BufferConn::default();
        let mut writer = match new_v4_writer(b"password") {
            Ok(writer) => writer,
            Err(err) => panic!("{err}"),
        };
        if let Err(err) = writer.write_frame(&mut raw, b"payload", 13).await {
            panic!("{err}");
        }

        let data = raw.buf.clone();
        let aead = match v4_aead(b"password", &data[..V4_SALT_SIZE]) {
            Ok(aead) => aead,
            Err(err) => panic!("{err}"),
        };
        let mut reader = V4Reader::new(aead);

        let mut buf = [0u8; 7];
        let mut conn = BufferConn::with(&data[V4_SALT_SIZE..]);
        if let Err(err) = reader.read(&mut conn, &mut buf).await {
            panic!("{err}");
        }
        assert_eq!("payload", String::from_utf8_lossy(&buf));
    }

    #[test]
    fn test_snell_v4_bit_count_padding() {
        let padding = match make_v4_bit_count_padding(32, 77) {
            Ok(padding) => padding,
            Err(err) => panic!("{err}"),
        };
        assert_eq!(32, padding.len(), "unexpected padding length");

        let ones: u32 = padding.iter().map(|b| b.count_ones()).sum();
        assert_eq!(77, ones, "unexpected padding bit count");
    }

    #[tokio::test]
    async fn test_snell_v4_writer_defers_salt_until_first_frame() {
        let mut raw = RecordingWriter::default();
        let mut writer = match new_v4_writer(b"password") {
            Ok(writer) => writer,
            Err(err) => panic!("{err}"),
        };
        assert_eq!(0, raw.buf.len(), "salt was written before first frame");
        assert_eq!(0, raw.writes, "salt was written before first frame");

        if let Err(err) = writer.write(&mut raw, b"x").await {
            panic!("{err}");
        }

        let (padding_length, payload_length) = decode_v4_header_for_test(&raw.buf);
        assert!(
            padding_length >= V4_INITIAL_PADDING_MIN as usize
                && padding_length < (V4_INITIAL_PADDING_MIN as usize + V4_INITIAL_PADDING_SPAN),
            "unexpected initial padding length: {padding_length}"
        );
        assert_eq!(1, payload_length, "unexpected first payload length");
        let want_len = V4_SALT_SIZE + V4_HEADER_CIPHER_SIZE + 1 + writer.aead.overhead() + padding_length;
        assert_eq!(want_len, raw.buf.len(), "unexpected first frame length");
        assert_eq!(1, raw.writes, "first frame should be written with salt in one write");
    }

    #[test]
    fn test_snell_v4_payload_limit_matches_server() {
        let mut writer = match new_v4_writer(b"password") {
            Ok(writer) => writer,
            Err(err) => panic!("{err}"),
        };

        let initial_padding_length = writer.initial_padding_length;
        assert!(initial_padding_length >= V4_INITIAL_PADDING_MIN as u16);
        assert!(initial_padding_length < (V4_INITIAL_PADDING_MIN as u16 + V4_INITIAL_PADDING_SPAN as u16));

        assert_eq!(
            (V4_FRAME_SIZE - 55 - i32::from(initial_padding_length)) as u16,
            writer.next_payload_limit(),
            "initial payload limit mismatch"
        );
        assert_eq!(
            (V4_FRAME_SIZE - 55 - i32::from(initial_padding_length) + V4_FRAME_SIZE - 39) as u16,
            writer.next_payload_limit(),
            "grown payload limit mismatch"
        );

        writer.last_write = Some(Instant::now() - Duration::from_secs(31));
        assert_eq!((V4_FRAME_SIZE - 39) as u16, writer.next_payload_limit(), "reset payload limit mismatch");
    }

    #[tokio::test]
    async fn test_snell_v4_udp_write_keeps_datagram_in_single_frame() {
        let (client_raw, server_raw) = tokio::io::duplex(1 << 20);
        let client = Snell::new(SnellConn::V4(Box::new(new_v4_conn(
            Box::new(OldConnAsStream(PipeConn(client_raw))),
            b"password",
        ))));
        let mut server = new_v4_conn(Box::new(OldConnAsStream(PipeConn(server_raw))), b"password");
        let pc = packet_conn(PacketConnConn::Snell(client));
        let payload = vec![0x42u8; V4_FRAME_SIZE as usize];
        let addr = UdpAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 53);

        let payload_for_write = payload.clone();
        let write_err = tokio::spawn(async move { pc.write_to(&payload_for_write, &addr).await.map(|_| ()) });

        let mut buf = vec![0u8; MAX_LENGTH];
        let n = match AsyncReadExt::read(&mut server, &mut buf).await {
            Ok(n) => n,
            Err(err) => panic!("{err}"),
        };
        match write_err.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("{err}"),
            Err(err) => panic!("{err}"),
        }
        let want = 1 + 2 + 4 + 2 + payload.len();
        assert_eq!(want, n, "UDP request was split or truncated");
        assert_eq!(&[COMMOND_UDP_FORWARD, 0, 4, 1, 2, 3, 4, 0, 53], &buf[..9], "unexpected UDP request header");
    }

    #[tokio::test]
    async fn test_snell_write_packet_rejects_oversized_datagram() {
        let mut raw = RecordingWriter::default();
        let addr = UdpAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 53);
        let socks5_addr = match socks5::parse_addr_to_socks_addr(&addr) {
            Some(addr) => addr,
            None => panic!("socks5 addr"),
        };
        let payload = vec![0x42u8; MAX_LENGTH];

        let err = match write_packet(&mut raw, &socks5_addr.0, &payload).await {
            Ok(n) => panic!("expected oversized UDP payload to be rejected, wrote {n}"),
            Err(err) => err,
        };
        assert_eq!("snell UDP payload too large", err.to_string(), "unexpected error");
        assert_eq!(0, raw.buf.len(), "oversized datagram should not be written");
    }

    #[tokio::test]
    async fn test_snell_write_header_connect_command() {
        let tests = [
            ("v1", VERSION1, false, COMMAND_CONNECT),
            ("v2", VERSION2, false, COMMAND_CONNECT_V2),
            ("v4 no reuse", VERSION4, false, COMMAND_CONNECT),
            ("v4 reuse", VERSION4, true, COMMAND_CONNECT_V2),
        ];

        for (name, version, reuse, want) in tests {
            let mut conn = BufferConn::default();
            if let Err(err) = write_header_with_reuse(&mut conn, "example.com", 443, version, reuse).await {
                panic!("{name}: {err}");
            }
            let data = conn.buf.clone();
            assert!(data.len() >= 2, "{name}: header too short");
            assert_eq!(want, data[1], "{name}: unexpected command");
        }
    }

    #[tokio::test]
    async fn test_snell_read_reply_preserves_buffered_payload() {
        let mut snell =
            Snell::new(SnellConn::Plain(Box::new(OldConnAsStream(BufferConn::with(&[COMMAND_TUNNEL, b'o', b'k'])))));

        if let Err(err) = snell.read_reply().await {
            panic!("{err}");
        }
        let mut buf = [0u8; 2];
        if let Err(err) = snell.read_exact(&mut buf).await {
            panic!("{err}");
        }
        assert_eq!("ok", String::from_utf8_lossy(&buf), "unexpected buffered payload");
    }

    #[tokio::test]
    async fn test_snell_read_reply_error_response() {
        let mut data = vec![COMMAND_ERROR, 0x65, 10];
        data.extend_from_slice(b"Remote EOF");
        let mut snell = Snell::new(SnellConn::Plain(Box::new(OldConnAsStream(BufferConn::with(&data)))));

        let err = match snell.read_reply().await {
            Ok(()) => panic!("expected error response"),
            Err(err) => err,
        };
        assert_eq!("server reported code: 101, message: Remote EOF", err.to_string(), "unexpected error");
    }

    #[tokio::test]
    async fn test_write_packet_response_uses_socks_addr_parser() {
        let mut buf = RecordingWriter::default();
        let n = match write_packet_response(&mut buf, &DummyAddr("127.0.0.1:53"), b"ok").await {
            Ok(n) => n,
            Err(err) => panic!("{err}"),
        };
        assert_eq!(2, n, "written payload length");

        let want = [0x04, 127, 0, 0, 1, 0, 53, b'o', b'k'];
        assert_eq!(want, buf.buf.as_slice(), "packet mismatch");
    }

    /// Pins the writer's AEAD framing and nonce handling — independent of the argon2 KDF
    /// the AEAD derives its key through, which DepBump's unit pins separately — against an
    /// independently computed AES-128-GCM ciphertext over the same fixed raw key, skipping
    /// the KDF and AEAD on both sides. `salt_sent: true` and `padding_length: 0` avoid the
    /// writer's own randomized salt and initial padding, isolating the header-then-payload
    /// seal-and-increment-nonce sequence the writer performs.
    #[tokio::test]
    async fn build_frame_matches_raw_aead_vector() {
        let aead = aes_gcm(&[1u8; 16]).expect("aes-128-gcm aead");
        let mut writer = V4Writer {
            aead,
            nonce: [0u8; V4_NONCE_SIZE],
            salt: [0u8; V4_SALT_SIZE],
            salt_sent: true,
            initial_padding_length: 0,
            payload_limit: 0,
            last_write: None,
            frame: Vec::new(),
            frame_pending: false,
            frame_offset: 0,
            frame_end: 0,
            frame_padding_length: 0,
            header_cipher: Vec::new(),
            payload_cipher: Vec::new(),
            written: 0,
            write_op_started: false,
            write_op: (0, 0),
        };

        writer.build_frame(b"hi", 0).expect("build_frame");
        let frame = writer.frame.clone();
        let want = hex::decode("f7345273269501d6f8df04d684cf8ea22e26c2c585aa192929ec4eea6b548754e178975b4abca147ad")
            .expect("valid hex vector");
        assert_eq!(frame, want, "build_frame diverges from the v4Writer.writeFrame");
    }
}

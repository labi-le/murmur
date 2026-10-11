use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use murmur_compat::sing_buf::{as_, Buffer};
use murmur_std_compat::net::{Conn as NetConn, ExtendedConn as NetExtendedConn, TcpAddr};

use crate::io::{close_stream, Stream};

use super::sing::{CachedReader, ExtendedConn, UpstreamNode};

/// The buffer-full, invalid-unread-byte and negative-count errors.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum BufioError {
    #[error("bufio: buffer full")]
    BufferFull,
    #[error("bufio: invalid use of UnreadByte")]
    InvalidUnreadByte,
    #[error("bufio: negative count")]
    NegativeCount,
}

fn bufio_err(err: BufioError) -> io::Error {
    io::Error::other(err)
}

/// Reports whether `err` is the given buffer error.
#[must_use]
#[expect(
    clippy::needless_pass_by_value,
    reason = "the predicate is public API and a unit enum is cheaper to pass by value than by reference"
)]
pub fn is_bufio_error(err: &io::Error, expected: BufioError) -> bool {
    err.get_ref().and_then(|err| err.downcast_ref::<BufioError>()).is_some_and(|err| *err == expected)
}

/// The short-buffer error a `Buffer::read_once_from` reports.
fn err_short_buffer() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "short buffer")
}

fn err_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

fn err_no_progress() -> io::Error {
    io::Error::other("multiple Read calls return no data or error")
}

pub const DEFAULT_BUF_SIZE: usize = 4096;

const MIN_READ_BUFFER_SIZE: usize = 16;

const MAX_CONSECUTIVE_EMPTY_READS: usize = 100;

/// The buffer state of a buffered reader. The conn holds the reader and reads through the conn
/// it is given, so the reader carries no reader of its own.
#[derive(Debug)]
pub struct BufioReader {
    pub buf: Vec<u8>,
    pub r: usize,
    pub w: usize,
    pub(crate) err: Option<io::Error>,
    /// The last byte read, where -1 marks an invalid last byte.
    pub(crate) last_byte: i64,
    /// The size of the last rune; no runes are read, so it stays -1.
    pub(crate) last_rune_size: i64,
}

impl Default for BufioReader {
    fn default() -> Self {
        Self::new()
    }
}

impl BufioReader {
    #[must_use]
    pub fn new() -> Self {
        Self::with_size(DEFAULT_BUF_SIZE)
    }

    /// A reader whose buffer holds at least `size` bytes.
    #[must_use]
    pub fn with_size(size: usize) -> Self {
        Self {
            buf: vec![0u8; size.max(MIN_READ_BUFFER_SIZE)],
            r: 0,
            w: 0,
            err: None,
            last_byte: -1,
            last_rune_size: -1,
        }
    }

    #[must_use]
    pub const fn size(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub const fn buffered(&self) -> usize {
        self.w - self.r
    }

    #[must_use]
    pub fn buffered_bytes(&self) -> &[u8] {
        self.buf.get(self.r..self.w).unwrap_or_default()
    }

    pub fn free_space(&mut self) -> &mut [u8] {
        self.buf.get_mut(self.w..).unwrap_or_default()
    }

    pub const fn commit(&mut self, n: usize) {
        self.w += n;
    }

    /// Reads out any stored error, clearing it.
    pub fn read_err(&mut self) -> io::Result<()> {
        match self.err.take() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    pub(crate) const fn has_err(&self) -> bool {
        self.err.is_some()
    }

    /// The slide step of a buffer refill.
    fn slide(&mut self) {
        if self.r > 0 {
            self.buf.copy_within(self.r..self.w, 0);
            self.w -= self.r;
            self.r = 0;
        }
    }

    /// the bytes come from at most one read on the conn.
    fn poll_read_slice<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        p: &mut [u8],
        rd: &mut R,
    ) -> Poll<io::Result<usize>> {
        if p.is_empty() {
            if self.buffered() > 0 {
                return Poll::Ready(Ok(0));
            }
            return Poll::Ready(self.read_err().map(|()| 0));
        }
        if self.r == self.w {
            if self.has_err() {
                return Poll::Ready(self.read_err().map(|()| 0));
            }
            if p.len() >= self.buf.len() {
                // Large read, empty buffer: read straight into p to avoid the copy.
                let mut read_buf = ReadBuf::new(p);
                return match Pin::new(rd).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n > 0 {
                            self.last_byte = read_buf.filled().last().map_or(-1, |byte| i64::from(*byte));
                            self.last_rune_size = -1;
                        }
                        Poll::Ready(self.read_err().map(|()| n))
                    }
                    Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                    Poll::Pending => Poll::Pending,
                };
            }
            // One read; the comment: do not use the fill loop here.
            self.r = 0;
            self.w = 0;
            let mut read_buf = ReadBuf::new(&mut self.buf);
            match Pin::new(rd).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(self.read_err().map(|()| 0));
                    }
                    self.w += n;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let n = core::cmp::min(p.len(), self.buffered());
        if let (Some(dst), Some(src)) = (p.get_mut(..n), self.buf.get(self.r..self.r + n)) {
            dst.copy_from_slice(src);
        }
        self.r += n;
        self.last_byte = self.buf.get(self.r - 1).map_or(-1, |byte| i64::from(*byte));
        self.last_rune_size = -1;
        Poll::Ready(Ok(n))
    }
}

/// Fills the buffer, driven by the conn the reader's conn holds.
pub(crate) async fn fill<R: AsyncRead + Unpin + ?Sized>(reader: &mut BufioReader, rd: &mut R) {
    reader.slide();
    assert!(reader.w < reader.buf.len(), "bufio: tried to fill full buffer");
    if (0..MAX_CONSECUTIVE_EMPTY_READS).next().is_some() {
        match rd.read(reader.free_space()).await {
            // A zero-length read is the end of stream here.
            Ok(0) => {
                reader.err = Some(err_eof());
                return;
            }
            Ok(n) => {
                reader.commit(n);
                return;
            }
            Err(err) => {
                reader.err = Some(err);
                return;
            }
        }
    }
    reader.err = Some(err_no_progress());
}

pub struct BufferedConn {
    /// The buffered reader, dropped once `ReadCached` hands its bytes out.
    pub(crate) r: Option<BufioReader>,
    extended_conn: Box<dyn ExtendedConn>,
    peeked: bool,
}

impl fmt::Debug for BufferedConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferedConn").field("r", &self.r).field("peeked", &self.peeked).finish_non_exhaustive()
    }
}

/// Wraps a conn in buffered reading. An input that is already a [`BufferedConn`] cannot be
/// detected through the erased conn, so the caller's value is always wrapped.
#[must_use]
pub fn new_buffered_conn(conn: Box<dyn ExtendedConn>) -> BufferedConn {
    BufferedConn { r: Some(BufioReader::new()), extended_conn: conn, peeked: false }
}

/// Wraps `conn` in buffered reading when `br` still holds unread bytes; a conn owns its reader,
/// so there is no reader-identity check to make.
#[must_use]
pub fn warp_conn_with_bio_reader(conn: Box<dyn ExtendedConn>, br: Option<BufioReader>) -> Box<dyn ExtendedConn> {
    if let Some(br) = br {
        if br.buffered() > 0 {
            return Box::new(BufferedConn { r: Some(br), extended_conn: conn, peeked: true });
        }
    }
    conn
}

impl BufferedConn {
    #[must_use]
    pub const fn reader(&self) -> Option<&BufioReader> {
        self.r.as_ref()
    }

    pub const fn reset_peeked(&mut self) {
        self.peeked = false;
    }

    #[must_use]
    pub const fn peeked(&self) -> bool {
        self.peeked
    }

    /// Peeks, returning the bytes alongside the error that cut them short.
    #[expect(
        clippy::expect_used,
        reason = "the reader is dropped only by `read_cached`, and nothing calls this method after that"
    )]
    pub async fn peek(&mut self, n: usize) -> (&[u8], io::Result<()>) {
        self.peeked = true;
        let Self { r, extended_conn, .. } = self;
        let reader = r.as_mut().expect("the reader is dropped only by ReadCached");
        reader.last_byte = -1;
        reader.last_rune_size = -1;

        while reader.buffered() < n && reader.buffered() < reader.buf.len() && !reader.has_err() {
            fill(reader, &mut **extended_conn).await;
        }

        if n > reader.buf.len() {
            return (reader.buffered_bytes(), Err(bufio_err(BufioError::BufferFull)));
        }

        let mut n = n;
        let mut err = Ok(());
        if reader.buffered() < n {
            n = reader.buffered();
            err = reader.read_err();
            if err.is_ok() {
                err = Err(bufio_err(BufioError::BufferFull));
            }
        }
        (reader.buf.get(reader.r..reader.r + n).unwrap_or_default(), err)
    }

    /// Discards, returning the count alongside the error that cut it short.
    #[expect(
        clippy::expect_used,
        reason = "the reader is dropped only by `read_cached`, and nothing calls this method after that"
    )]
    pub async fn discard(&mut self, n: usize) -> (usize, io::Result<()>) {
        let Self { r, extended_conn, .. } = self;
        let reader = r.as_mut().expect("the reader is dropped only by ReadCached");
        reader.last_byte = -1;
        reader.last_rune_size = -1;

        let mut remain = n;
        loop {
            let mut skip = reader.buffered();
            if skip == 0 {
                fill(reader, &mut **extended_conn).await;
                skip = reader.buffered();
            }
            if skip > remain {
                skip = remain;
            }
            reader.r += skip;
            remain -= skip;
            if remain == 0 {
                return (n, Ok(()));
            }
            if reader.has_err() {
                return (n - remain, reader.read_err());
            }
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "the reader is dropped only by `read_cached`, and nothing calls this method after that"
    )]
    pub async fn read_byte(&mut self) -> io::Result<u8> {
        let Self { r, extended_conn, .. } = self;
        let reader = r.as_mut().expect("the reader is dropped only by ReadCached");
        reader.last_rune_size = -1;
        while reader.r == reader.w {
            if reader.has_err() {
                reader.read_err()?;
            }
            fill(reader, &mut **extended_conn).await;
        }
        let c = reader.buf.get(reader.r).copied().unwrap_or_default();
        reader.r += 1;
        reader.last_byte = i64::from(c);
        Ok(c)
    }

    #[expect(
        clippy::expect_used,
        reason = "the reader is dropped only by `read_cached`, and nothing calls this method after that"
    )]
    pub fn unread_byte(&mut self) -> io::Result<()> {
        let reader = self.r.as_mut().expect("the reader is dropped only by ReadCached");
        if reader.last_byte < 0 || reader.r == 0 && reader.w > 0 {
            return Err(bufio_err(BufioError::InvalidUnreadByte));
        }
        if reader.r > 0 {
            reader.r -= 1;
        } else {
            reader.w = 1;
        }
        let last_byte = u8::try_from(reader.last_byte).map_err(|_| bufio_err(BufioError::InvalidUnreadByte))?;
        if let Some(slot) = reader.buf.get_mut(reader.r) {
            *slot = last_byte;
        }
        reader.last_byte = -1;
        reader.last_rune_size = -1;
        Ok(())
    }

    pub fn buffered(&self) -> usize {
        self.r.as_ref().map_or(0, BufioReader::buffered)
    }
}

impl AsyncRead for BufferedConn {
    /// Reads, deferring to the buffered reader.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Self { r, extended_conn, .. } = this;
        let Some(reader) = r.as_mut() else {
            return Pin::new(&mut **extended_conn).poll_read(cx, buf);
        };
        let n = {
            let p = buf.initialize_unfilled();
            match reader.poll_read_slice(cx, p, &mut **extended_conn) {
                Poll::Ready(result) => result?,
                Poll::Pending => return Poll::Pending,
            }
        };
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for BufferedConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().extended_conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().extended_conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().extended_conn).poll_shutdown(cx)
    }
}

/// [`BufferedConn`]'s outward-facing old `Conn`: `extended_conn` is now [`crate::io::ExtendedStream`]-
/// shaped rather than old-`Conn`-shaped, so it has no `Box<dyn Addr>`
/// of its own, so `local_addr`/`remote_addr` fall back to [`TcpAddr`] the way
/// [`crate::io::StreamAsOldConn`] does; `close`/`close_read`/`close_write` go through
/// [`close_stream`]/`shutdown_read`/`shutdown_write`; the deadline setters forward to
/// [`Stream::old_conn`] when present (every reachable chain today bottoms out at a real old
/// `Conn`) and no-op otherwise, exactly as `StreamAsOldConn`'s own no-`old_conn` case does for a
/// closed deadline setter.
impl NetConn for BufferedConn {
    fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        Ok(Box::new(TcpAddr::from(self.extended_conn.local_addr()?)))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        Ok(Box::new(TcpAddr::from(self.extended_conn.peer_addr()?)))
    }

    fn close(&self) -> io::Result<()> {
        close_stream(&*self.extended_conn)
    }

    fn close_read(&self) -> io::Result<()> {
        self.extended_conn.shutdown_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.extended_conn.shutdown_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.extended_conn.old_conn().map_or(Ok(()), |inner| inner.set_deadline(deadline))
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.extended_conn.old_conn().map_or(Ok(()), |inner| inner.set_read_deadline(deadline))
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.extended_conn.old_conn().map_or(Ok(()), |inner| inner.set_write_deadline(deadline))
    }
}

impl NetExtendedConn for BufferedConn {
    fn reader_replaceable(&self) -> bool {
        self.r.as_ref().is_none_or(|reader| reader.buffered() == 0)
    }

    fn writer_replaceable(&self) -> bool {
        true
    }
}

impl Stream for BufferedConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        crate::io::old_addr_to_socket_addr(NetConn::local_addr(self)?.as_ref())
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        crate::io::old_addr_to_socket_addr(NetConn::remote_addr(self)?.as_ref())
    }
    fn shutdown_read(&self) -> io::Result<()> {
        NetConn::close_read(self)
    }
    fn shutdown_write(&self) -> io::Result<()> {
        NetConn::close_write(self)
    }
    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(self)
    }
}

impl crate::io::ExtendedStream for BufferedConn {
    fn reader_replaceable(&self) -> bool {
        NetExtendedConn::reader_replaceable(self)
    }
    fn writer_replaceable(&self) -> bool {
        NetExtendedConn::writer_replaceable(self)
    }
}

impl UpstreamNode for BufferedConn {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&*self.extended_conn)
    }

    /// The node walk sees no conn trait, so the two replaceable flags are repeated here.
    fn reader_replaceable(&self) -> Option<bool> {
        Some(NetExtendedConn::reader_replaceable(self))
    }

    fn writer_replaceable(&self) -> Option<bool> {
        Some(NetExtendedConn::writer_replaceable(self))
    }
}

#[async_trait]
impl ExtendedConn for BufferedConn {
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        let Self { r, extended_conn, .. } = self;
        let Some(reader) = r.as_mut() else {
            return extended_conn.read_buffer(buffer).await;
        };
        if reader.buffered() == 0 {
            return extended_conn.read_buffer(buffer).await;
        }
        if buffer.is_full() {
            return Err(err_short_buffer());
        }
        let n = poll_fn(|cx| reader.poll_read_slice(cx, buffer.free_bytes(), &mut **extended_conn)).await?;
        buffer.truncate(n);
        Ok(())
    }

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        self.extended_conn.write_buffer(buffer).await
    }
}

impl CachedReader for BufferedConn {
    /// Reads through the cached reader.
    fn read_cached(&mut self) -> Option<Buffer> {
        let reader = self.r.as_mut()?;
        if reader.buffered() > 0 {
            let length = reader.buffered();
            let data = reader.buffered_bytes().to_vec();
            reader.last_byte = -1;
            reader.last_rune_size = -1;
            reader.r += length;
            return Some(as_(data));
        }
        self.r = None;
        None
    }
}

/// [`Stream`]-backed counterpart to [`BufferedConn`], for a caller holding a `Box<dyn Stream>`
/// rather than [`ExtendedConn`].
///
/// Same buffering/peek/discard/read-byte semantics; close and half-close go through
/// [`crate::io::close_stream`]/[`Stream::shutdown_read`]/[`Stream::shutdown_write`] instead of the
/// old `Conn::close`/`close_read`/`close_write`. No `read_buffer`/`write_buffer` zero-copy
/// zero-copy buffer path or [`UpstreamNode`] walk: neither concept exists on `Stream`, and nothing
/// constructs this type from a value that had one.
pub struct BufferedStream {
    pub(crate) r: Option<BufioReader>,
    stream: Box<dyn Stream>,
    peeked: bool,
}

impl fmt::Debug for BufferedStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferedStream").field("r", &self.r).field("peeked", &self.peeked).finish_non_exhaustive()
    }
}

/// Wraps a [`Stream`] in buffered reading, mirroring [`new_buffered_conn`] for the new trait.
#[must_use]
pub fn new_buffered_stream(stream: Box<dyn Stream>) -> BufferedStream {
    BufferedStream { r: Some(BufioReader::new()), stream, peeked: false }
}

impl BufferedStream {
    #[must_use]
    pub const fn reader(&self) -> Option<&BufioReader> {
        self.r.as_ref()
    }

    pub const fn reset_peeked(&mut self) {
        self.peeked = false;
    }

    #[must_use]
    pub const fn peeked(&self) -> bool {
        self.peeked
    }

    /// Same short-read reporting as [`BufferedConn::peek`].
    #[expect(
        clippy::expect_used,
        reason = "the reader is dropped only by `read_cached`, and nothing calls this method after that"
    )]
    pub async fn peek(&mut self, n: usize) -> (&[u8], io::Result<()>) {
        self.peeked = true;
        let Self { r, stream, .. } = self;
        let reader = r.as_mut().expect("the reader is dropped only by ReadCached");
        reader.last_byte = -1;
        reader.last_rune_size = -1;

        while reader.buffered() < n && reader.buffered() < reader.buf.len() && !reader.has_err() {
            fill(reader, &mut **stream).await;
        }

        if n > reader.buf.len() {
            return (reader.buffered_bytes(), Err(bufio_err(BufioError::BufferFull)));
        }

        let mut n = n;
        let mut err = Ok(());
        if reader.buffered() < n {
            n = reader.buffered();
            err = reader.read_err();
            if err.is_ok() {
                err = Err(bufio_err(BufioError::BufferFull));
            }
        }
        (reader.buf.get(reader.r..reader.r + n).unwrap_or_default(), err)
    }

    /// Same short-discard reporting as [`BufferedConn::discard`].
    #[expect(
        clippy::expect_used,
        reason = "the reader is dropped only by `read_cached`, and nothing calls this method after that"
    )]
    pub async fn discard(&mut self, n: usize) -> (usize, io::Result<()>) {
        let Self { r, stream, .. } = self;
        let reader = r.as_mut().expect("the reader is dropped only by ReadCached");
        reader.last_byte = -1;
        reader.last_rune_size = -1;

        let mut remain = n;
        loop {
            let mut skip = reader.buffered();
            if skip == 0 {
                fill(reader, &mut **stream).await;
                skip = reader.buffered();
            }
            if skip > remain {
                skip = remain;
            }
            reader.r += skip;
            remain -= skip;
            if remain == 0 {
                return (n, Ok(()));
            }
            if reader.has_err() {
                return (n - remain, reader.read_err());
            }
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "the reader is dropped only by `read_cached`, and nothing calls this method after that"
    )]
    pub async fn read_byte(&mut self) -> io::Result<u8> {
        let Self { r, stream, .. } = self;
        let reader = r.as_mut().expect("the reader is dropped only by ReadCached");
        reader.last_rune_size = -1;
        while reader.r == reader.w {
            if reader.has_err() {
                reader.read_err()?;
            }
            fill(reader, &mut **stream).await;
        }
        let c = reader.buf.get(reader.r).copied().unwrap_or_default();
        reader.r += 1;
        reader.last_byte = i64::from(c);
        Ok(c)
    }

    #[expect(
        clippy::expect_used,
        reason = "the reader is dropped only by `read_cached`, and nothing calls this method after that"
    )]
    pub fn unread_byte(&mut self) -> io::Result<()> {
        let reader = self.r.as_mut().expect("the reader is dropped only by ReadCached");
        if reader.last_byte < 0 || reader.r == 0 && reader.w > 0 {
            return Err(bufio_err(BufioError::InvalidUnreadByte));
        }
        if reader.r > 0 {
            reader.r -= 1;
        } else {
            reader.w = 1;
        }
        let last_byte = u8::try_from(reader.last_byte).map_err(|_| bufio_err(BufioError::InvalidUnreadByte))?;
        if let Some(slot) = reader.buf.get_mut(reader.r) {
            *slot = last_byte;
        }
        reader.last_byte = -1;
        reader.last_rune_size = -1;
        Ok(())
    }

    pub fn buffered(&self) -> usize {
        self.r.as_ref().map_or(0, BufioReader::buffered)
    }
}

impl AsyncRead for BufferedStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Self { r, stream, .. } = this;
        let Some(reader) = r.as_mut() else {
            return Pin::new(&mut **stream).poll_read(cx, buf);
        };
        let n = {
            let p = buf.initialize_unfilled();
            match reader.poll_read_slice(cx, p, &mut **stream) {
                Poll::Ready(result) => result?,
                Poll::Pending => return Poll::Pending,
            }
        };
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for BufferedStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_shutdown(cx)
    }
}

impl Stream for BufferedStream {
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
    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.stream.as_socket()
    }
    fn old_conn(&self) -> Option<&dyn NetConn> {
        self.stream.old_conn()
    }
}

#[cfg(test)]
mod buffered_stream_tests {
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::io::close_stream;

    #[tokio::test]
    async fn buffered_stream_peek_then_read_then_shutdown_over_real_sockets() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (mut client, (server, _)) =
            tokio::try_join!(tokio::net::TcpStream::connect(addr), listener.accept()).expect("pair");

        let mut buffered = new_buffered_stream(Box::new(server));

        client.write_all(b"hello world").await.expect("client write");

        let (peeked, err) = buffered.peek(5).await;
        assert!(err.is_ok(), "peek(5) failed");
        assert_eq!(peeked, b"hello");
        assert!(buffered.peeked());

        let mut read_buf = vec![0u8; 5];
        buffered.read_exact(&mut read_buf).await.expect("read the peeked bytes");
        assert_eq!(read_buf, b"hello");

        let mut rest = vec![0u8; 6];
        buffered.read_exact(&mut rest).await.expect("read the rest");
        assert_eq!(rest, b" world");

        close_stream(&buffered).expect("close_stream must forward to shutdown_read/shutdown_write");

        let mut probe = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut probe))
            .await
            .expect("client must observe EOF after BufferedStream is closed")
            .expect("read");
        assert_eq!(n, 0, "client must see EOF, not hang, after close_stream shuts the buffered stream down");
    }
}

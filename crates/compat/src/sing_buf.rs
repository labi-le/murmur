//! A pooled byte buffer; murmur's own `common/buf` re-exports this.

use std::io;
use std::ops::Index;
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, Ordering};
use std::task::{Context, Poll};

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use murmur_common_pool::sing::default_allocator;
use murmur_std_compat::net::{Addr, PacketConn};

#[cfg(not(feature = "with_low_memory"))]
pub const BUFFER_SIZE: i32 = 32 * 1024;
#[cfg(feature = "with_low_memory")]
pub const BUFFER_SIZE: i32 = 16 * 1024;

// Datagram reads must accept a full UDP payload in every memory profile.
pub const UDP_BUFFER_SIZE: i32 = 64 * 1024;

fn short_buffer() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "short buffer")
}

fn unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

/// The default allocator is murmur's, so every sing allocation comes from
/// `murmur_common_pool`.
#[must_use]
pub fn get(size: i32) -> Vec<u8> {
    assert!(size >= 0, "alloc.Get: len out of range");
    #[expect(clippy::cast_sign_loss, reason = "the assert above keeps `size` non-negative")]
    let size = size as usize;
    default_allocator().get(size)
}

/// the `Put`, through the same default allocator.
pub fn put(buf: Vec<u8>) -> anyhow::Result<()> {
    default_allocator().put(buf)
}

/// Deprecated: use an array instead.
#[must_use]
pub fn make(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

/// A block from the default allocator, sized down to `size` but holding the block's whole allocation size:
/// the slice has that allocation size as its capacity, and the block stays addressable up to it.
fn get_block(size: i32) -> (Vec<u8>, usize) {
    let mut data = get(size);
    let raw_len = data.len();
    data.resize(data.capacity(), 0);
    (data, raw_len)
}

/// the bytes of `data` in `start..end`: `split_at` aborts on an out-of-range region exactly like
/// the slice it replaces, and the read accessors have no `Result` to report one through.
fn region(data: &[u8], start: usize, end: usize) -> &[u8] {
    let (_, tail) = data.split_at(start);
    let (head, _) = tail.split_at(end - start);
    head
}

/// [`region`], borrowing the block mutably.
fn region_mut(data: &mut [u8], start: usize, end: usize) -> &mut [u8] {
    let (_, tail) = data.split_at_mut(start);
    let (head, _) = tail.split_at_mut(end - start);
    head
}

/// A pooled byte buffer, re-exported here.
///
/// The `data` slice carries both a length and a capacity; the block's capacity is the `Vec`'s
/// length here, and `raw_len` is the raw length of the data.
#[derive(Debug)]
pub struct Buffer {
    data: Vec<u8>,
    raw_len: usize,
    start: usize,
    end: usize,
    capacity: usize,
    refs: AtomicI32,
    managed: bool,
}

impl Default for Buffer {
    fn default() -> Self {
        Self { data: Vec::new(), raw_len: 0, start: 0, end: 0, capacity: 0, refs: AtomicI32::new(0), managed: false }
    }
}

#[must_use]
pub fn new() -> Buffer {
    let (data, raw_len) = get_block(BUFFER_SIZE);
    Buffer { data, raw_len, start: 0, end: 0, capacity: raw_len, refs: AtomicI32::new(0), managed: true }
}

#[must_use]
pub fn new_packet() -> Buffer {
    let (data, raw_len) = get_block(UDP_BUFFER_SIZE);
    Buffer { data, raw_len, start: 0, end: 0, capacity: raw_len, refs: AtomicI32::new(0), managed: true }
}

#[must_use]
pub fn new_size(size: i32) -> Buffer {
    if size == 0 {
        return Buffer::default();
    }
    if size > 65535 {
        #[expect(clippy::cast_sign_loss, reason = "the guard above keeps `size` positive")]
        let size = size as usize;
        return Buffer {
            data: vec![0u8; size],
            raw_len: size,
            start: 0,
            end: 0,
            capacity: size,
            refs: AtomicI32::new(0),
            managed: false,
        };
    }
    let (data, raw_len) = get_block(size);
    Buffer { data, raw_len, start: 0, end: 0, capacity: raw_len, refs: AtomicI32::new(0), managed: true }
}

/// Wraps `data` as a full buffer: `start` stays at zero and `end` sits at its length.
#[must_use]
pub fn as_(mut data: Vec<u8>) -> Buffer {
    let raw_len = data.len();
    data.resize(data.capacity(), 0);
    Buffer { data, raw_len, start: 0, end: raw_len, capacity: raw_len, refs: AtomicI32::new(0), managed: false }
}

/// Wraps `data` as an empty buffer with room for `data.len()` bytes.
#[must_use]
pub fn with(mut data: Vec<u8>) -> Buffer {
    let raw_len = data.len();
    data.resize(data.capacity(), 0);
    Buffer { data, raw_len, start: 0, end: 0, capacity: raw_len, refs: AtomicI32::new(0), managed: false }
}

pub fn release_multi(buffers: &mut [Buffer]) {
    for buffer in buffers {
        buffer.release();
    }
}

pub fn len_multi(buffers: &[Buffer]) -> usize {
    let mut n = 0;
    for buffer in buffers {
        n += buffer.len();
    }
    n
}

pub fn to_slice_multi(buffers: &[Buffer]) -> Vec<&[u8]> {
    buffers.iter().map(Buffer::bytes).collect()
}

pub fn copy_multi(to_buffer: &mut [u8], buffers: &[Buffer]) -> usize {
    let mut n = 0;
    for buffer in buffers {
        let src = buffer.bytes();
        let len = core::cmp::min(to_buffer.len() - n, src.len());
        region_mut(to_buffer, n, n + len).copy_from_slice(region(src, 0, len));
        n += len;
    }
    n
}

pub fn error<V, E>(_value: V, err: E) -> E {
    err
}

#[expect(clippy::panic, reason = "the helper aborts on the first error; its signature has no `Result` to return")]
pub fn must<E>(errs: Vec<Option<E>>)
where
    E: Into<anyhow::Error>,
{
    if let Some(err) = errs.into_iter().flatten().next() {
        panic!("{}", err.into());
    }
}

#[expect(clippy::panic, reason = "the helper aborts when `err` is present; the signature returns the value")]
pub fn must1<T, E>(result: T, err: Option<E>) -> T
where
    E: Into<anyhow::Error>,
{
    if let Some(err) = err {
        panic!("{}", err.into());
    }
    result
}

#[expect(clippy::panic, reason = "the helper aborts when `err` is present; the signature returns the pair")]
pub fn must2<T, T2, E>(result: T, result2: T2, err: Option<E>) -> (T, T2)
where
    E: Into<anyhow::Error>,
{
    if let Some(err) = err {
        panic!("{}", err.into());
    }
    (result, result2)
}

impl Buffer {
    #[expect(clippy::indexing_slicing, reason = "an out-of-range frame offset aborts rather than reads a default byte")]
    pub fn byte(&self, index: usize) -> u8 {
        self.data[self.start + index]
    }

    #[expect(clippy::indexing_slicing, reason = "an out-of-range frame offset aborts rather than drops the write")]
    pub fn set_byte(&mut self, index: usize, value: u8) {
        self.data[self.start + index] = value;
    }

    pub fn extend(&mut self, n: usize) -> &mut [u8] {
        let end = self.end + n;
        assert!(end <= self.capacity, "buffer overflow: capacity {},end {}, need {}", self.capacity, self.end, n);
        let ext = region_mut(&mut self.data, self.end, end);
        self.end = end;
        ext
    }

    pub const fn advance(&mut self, from: usize) {
        self.start += from;
        if self.end < self.start {
            self.end = self.start;
        }
    }

    pub const fn truncate(&mut self, to: usize) {
        self.end = self.start + to;
    }

    pub fn extend_header(&mut self, n: usize) -> &mut [u8] {
        assert!(self.start >= n, "buffer overflow: capacity {},start {}, need {}", self.capacity, self.start, n);
        self.start -= n;
        region_mut(&mut self.data, self.start, self.start + n)
    }

    pub fn write_random(&mut self, size: usize) -> &mut [u8] {
        let buffer = self.extend(size);
        rand::rng().fill_bytes(&mut *buffer);
        buffer
    }

    pub fn write_byte(&mut self, d: u8) -> io::Result<()> {
        if self.is_full() {
            return Err(short_buffer());
        }
        let Some(slot) = self.data.get_mut(self.end) else {
            return Err(short_buffer());
        };
        *slot = d;
        self.end += 1;
        Ok(())
    }

    /// the `ReadOnceFrom` returns the count alongside the error; `AsyncRead` reports an error
    /// without one, so a partial read that then fails is not counted.
    pub async fn read_once_from<R>(&mut self, r: &mut R) -> io::Result<usize>
    where
        R: AsyncRead + Unpin,
    {
        // cancel-safe: `end` is committed only after the single read returns.
        if self.is_full() {
            return Err(short_buffer());
        }
        let Some(free) = self.data.get_mut(self.end..self.capacity) else {
            return Err(short_buffer());
        };
        let n = r.read(free).await?;
        self.end += n;
        Ok(n)
    }

    pub async fn read_packet_from(&mut self, r: &dyn PacketConn) -> io::Result<(usize, Box<dyn Addr>)> {
        // cancel-safe: `end` is committed only after the single read returns.
        if self.is_full() {
            return Err(short_buffer());
        }
        let Some(free) = self.data.get_mut(self.end..self.capacity) else {
            return Err(short_buffer());
        };
        let (n, addr) = r.read_from(free).await?;
        self.end += n;
        Ok((n, addr))
    }

    pub async fn read_at_least_from<R>(&mut self, r: &mut R, min: usize) -> io::Result<usize>
    where
        R: AsyncRead + Unpin,
    {
        // NOT cancel-safe: `end` is committed only after the loop, so a drop mid-read loses the bytes already read.
        if min == 0 {
            return self.read_once_from(r).await;
        }
        if self.is_full() || self.free_len() < min {
            return Err(short_buffer());
        }

        let mut n = 0;
        while n < min {
            let Some(free) = self.data.get_mut(self.end + n..self.capacity) else {
                self.end += n;
                return Err(short_buffer());
            };
            let read = r.read(free).await;
            let read = match read {
                Ok(read) => read,
                Err(err) => {
                    self.end += n;
                    return Err(err);
                }
            };
            if read == 0 {
                self.end += n;
                return Err(if n == 0 { eof() } else { unexpected_eof() });
            }
            n += read;
        }
        self.end += n;
        Ok(n)
    }

    pub async fn read_full_from<R>(&mut self, r: &mut R, size: usize) -> io::Result<usize>
    where
        R: AsyncRead + Unpin,
    {
        // NOT cancel-safe: `end` is committed only after the whole block, so a drop mid-read loses bytes.
        if self.end + size > self.capacity {
            return Err(short_buffer());
        }

        let mut n = 0;
        while n < size {
            let Some(free) = self.data.get_mut(self.end + n..self.end + size) else {
                self.end += n;
                return Err(short_buffer());
            };
            let read = r.read(free).await;
            match read {
                Ok(0) => break,
                Ok(read) => n += read,
                Err(err) => {
                    self.end += n;
                    return Err(err);
                }
            }
        }
        self.end += n;

        if n < size {
            return Err(if n == 0 { eof() } else { unexpected_eof() });
        }
        Ok(n)
    }

    /// the `ReadFrom` reports the bytes read next to the error; the pair is kept here, with the
    /// end-of-file mapped to no error.
    pub async fn read_from<R>(&mut self, reader: &mut R) -> (usize, io::Result<()>)
    where
        R: AsyncRead + Unpin,
    {
        // cancel-safe: `end` advances after every read, so a dropped call loses no bytes.
        let mut n = 0;
        loop {
            if self.is_full() {
                return (0, Err(short_buffer()));
            }
            let Some(free) = self.data.get_mut(self.end..self.capacity) else {
                return (n, Err(short_buffer()));
            };
            let read = reader.read(free).await;
            let read = match read {
                Ok(read) => read,
                Err(err) => return (n, Err(err)),
            };
            self.end += read;
            n += read;
            if read == 0 {
                return (n, Ok(()));
            }
        }
    }

    /// writes the first byte of the rune.
    pub fn write_rune(&mut self, s: char) -> io::Result<usize> {
        self.write_bytes(&[s as u8])
    }

    pub fn write_string(&mut self, s: &str) -> io::Result<usize> {
        self.write_bytes(s.as_bytes())
    }

    pub fn write_zero(&mut self) -> io::Result<()> {
        if self.is_full() {
            return Err(short_buffer());
        }
        let Some(slot) = self.data.get_mut(self.end) else {
            return Err(short_buffer());
        };
        *slot = 0;
        self.end += 1;
        Ok(())
    }

    pub fn write_zero_n(&mut self, n: usize) -> io::Result<()> {
        if self.end + n > self.capacity {
            return Err(short_buffer());
        }
        self.extend(n).fill(0);
        Ok(())
    }

    pub fn read_byte(&mut self) -> io::Result<u8> {
        if self.is_empty() {
            return Err(eof());
        }

        let nb = *self.data.get(self.start).ok_or_else(eof)?;
        self.start += 1;
        Ok(nb)
    }

    pub fn read_bytes(&mut self, n: usize) -> io::Result<&[u8]> {
        if self.end - self.start < n {
            return Err(eof());
        }

        let nb = self.data.get(self.start..self.start + n).ok_or_else(eof)?;
        self.start += n;
        Ok(nb)
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<usize>
    where
        W: AsyncWrite + Unpin,
    {
        // cancel-safe: tokio's `write` is cancel-safe and the buffer is not mutated.
        w.write(self.bytes()).await
    }

    pub const fn resize(&mut self, start: usize, end: usize) {
        self.start = start;
        self.end = self.start + end;
    }

    pub fn reserve(&mut self, n: usize) {
        assert!(n <= self.capacity, "buffer overflow: capacity {}, need {}", self.capacity, n);
        self.capacity -= n;
    }

    pub fn over_cap(&mut self, n: usize) {
        assert!(
            self.capacity + n <= self.raw_len,
            "buffer overflow: capacity {}, need {}",
            self.raw_len,
            self.capacity + n
        );
        self.capacity += n;
    }

    pub const fn reset(&mut self) {
        self.start = 0;
        self.end = 0;
        self.capacity = self.raw_len;
    }

    /// Deprecated: use `reset` instead.
    pub fn full_reset(&mut self) {
        self.reset();
    }

    pub fn inc_ref(&self) {
        self.refs.fetch_add(1, Ordering::SeqCst);
    }

    pub fn dec_ref(&self) {
        self.refs.fetch_sub(1, Ordering::SeqCst);
    }

    #[expect(clippy::panic, reason = "the block could not be returned to the pool and `release` has no `Result`")]
    pub fn release(&mut self) {
        if !self.managed {
            return;
        }
        if self.refs.load(Ordering::SeqCst) > 0 {
            return;
        }
        let data = core::mem::take(&mut self.data);
        if let Err(err) = put(data) {
            panic!("{err}");
        }
        *self = Self::default();
    }

    /// Panics only in a debug build; the normal build does not.
    pub fn leak(&mut self) {
        self.release();
    }

    pub const fn start(&self) -> usize {
        self.start
    }

    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    pub const fn is_empty(&self) -> bool {
        self.end - self.start == 0
    }

    pub const fn cap(&self) -> usize {
        self.capacity
    }

    pub const fn raw_cap(&self) -> usize {
        self.raw_len
    }

    pub fn bytes(&self) -> &[u8] {
        region(&self.data, self.start, self.end)
    }

    pub fn from(&self, n: usize) -> &[u8] {
        region(&self.data, self.start + n, self.end)
    }

    pub fn to(&self, n: usize) -> &[u8] {
        region(&self.data, self.start, self.start + n)
    }

    pub fn range(&self, start: usize, end: usize) -> &[u8] {
        region(&self.data, self.start + start, self.start + end)
    }

    pub const fn free_len(&self) -> usize {
        self.capacity - self.end
    }

    pub fn free_bytes(&mut self) -> &mut [u8] {
        region_mut(&mut self.data, self.end, self.capacity)
    }

    pub const fn is_full(&self) -> bool {
        self.end == self.capacity
    }

    /// Renamed from the `ToOwned`, which is a standard trait in Rust.
    #[must_use]
    pub fn to_owned_buffer(&self) -> Self {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_possible_wrap,
            reason = "every block is sized from an `i32` in the constructors, so its length fits the size API"
        )]
        let raw_len = self.raw_len as i32;
        let mut n = new_size(raw_len);
        region_mut(&mut n.data, self.start, self.end).copy_from_slice(region(&self.data, self.start, self.end));
        n.start = self.start;
        n.end = self.end;
        n.capacity = self.capacity;
        n
    }

    /// the `Write`: every error path there returns a zero count, so the count fits `Ok`.
    pub fn write_bytes(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.is_full() {
            return Err(short_buffer());
        }
        let n = core::cmp::min(self.capacity - self.end, data.len());
        let (Some(dst), Some(src)) = (self.data.get_mut(self.end..self.end + n), data.get(..n)) else {
            return Err(short_buffer());
        };
        dst.copy_from_slice(src);
        self.end += n;
        Ok(n)
    }
}

impl Index<usize> for Buffer {
    type Output = [u8];

    /// Indexing yields an empty slice at `start` bytes past the read cursor.
    fn index(&self, start: usize) -> &Self::Output {
        region(&self.data, self.start + start, self.start + start)
    }
}

impl AsyncRead for Buffer {
    /// An empty buffer reads as end of stream.
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let n = core::cmp::min(buf.remaining(), this.len());
        buf.put_slice(region(&this.data, this.start, this.start + n));
        this.start += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Buffer {
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

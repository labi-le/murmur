//! The snappy codec is implemented inline in `mod snappy` below rather than taken from a
//! dependency.
//!
//! It covers both formats: the block format (`encode`/`decode`) and the framing format
//! (`Writer`/`Reader`).
//!
//! Deviations, forced by Rust's borrowing rules:
//!
//! * the codec holds a writer and a reader over the same connection.
//!   `CompStream` owns the conn and both codec states instead, and drives them from
//!   `AsyncRead`/`AsyncWrite`.
//! * the writer queues each chunk instead of handing it straight to the conn; here the framed
//!   writer queues the bytes it frames and `poll_write` drains them, because a tokio write may be
//!   partial. Chunk order and content are unchanged.
//! * a reader with an empty destination returns immediately, since a zero-filled `poll_read`
//!   would signal EOF.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common_net::io::Stream;
use murmur_std_compat::net::Conn as NetConn;

/// `CompStream`: a connection wrapper that compresses data using snappy.
pub struct CompStream {
    conn: Box<dyn Stream>,
    w: snappy::Writer,
    r: snappy::Reader,
}

#[must_use]
pub fn new_comp_stream(conn: Box<dyn Stream>) -> CompStream {
    CompStream { conn, w: snappy::Writer::new(), r: snappy::Reader::new() }
}

impl fmt::Debug for CompStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompStream").finish_non_exhaustive()
    }
}

impl AsyncRead for CompStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.r.poll_read(&mut *this.conn, cx, buf)
    }
}

impl AsyncWrite for CompStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.w.poll_write(&mut *this.conn, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.w.poll_flush(&mut *this.conn, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.w.poll_flush(&mut *this.conn, cx))?;
        Pin::new(&mut *this.conn).poll_shutdown(cx)
    }
}

impl Stream for CompStream {
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

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.conn.as_socket()
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        self.conn.old_conn()
    }
}

/// The snappy codec, implementing the parts this transport uses.
pub mod snappy {
    use std::fmt;
    use std::io;
    use std::pin::Pin;
    use std::sync::LazyLock;
    use std::task::{ready, Context, Poll};

    use tokio::io::ReadBuf;

    use murmur_common_net::io::Stream as Conn;

    const MAGIC_CHUNK: [u8; 10] = *b"\xff\x06\x00\x00sNaPpY";

    const MAGIC_BODY: [u8; 6] = *b"sNaPpY";

    const CHECKSUM_SIZE: usize = 4;

    const CHUNK_HEADER_SIZE: usize = 4;

    const MAX_BLOCK_SIZE: usize = 65536;

    const MAX_ENCODED_LEN_OF_MAX_BLOCK_SIZE: usize = 76490;

    const INPUT_MARGIN: usize = 16 - 1;

    const MIN_NON_LITERAL_BLOCK_SIZE: usize = 1 + 1 + INPUT_MARGIN;

    const MAX_TABLE_SIZE: usize = 1 << 14;

    const TABLE_MASK: usize = MAX_TABLE_SIZE - 1;

    const CHUNK_TYPE_COMPRESSED_DATA: u8 = 0x00;

    const CHUNK_TYPE_UNCOMPRESSED_DATA: u8 = 0x01;

    const CHUNK_TYPE_STREAM_IDENTIFIER: u8 = 0xff;

    const TAG_LITERAL: u8 = 0x00;

    const TAG_COPY1: u8 = 0x01;

    const TAG_COPY2: u8 = 0x02;

    /// The codec's error type.
    #[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Error {
        #[error("snappy: corrupt input")]
        Corrupt,
        #[error("snappy: decoded block is too large")]
        TooLarge,
        #[error("snappy: unsupported input")]
        Unsupported,
        #[error("snappy: unsupported literal length")]
        UnsupportedLiteralLength,
    }

    fn corrupt() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, Error::Corrupt)
    }

    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, Error::Unsupported)
    }

    fn snappy_err(err: Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }

    const fn max_encoded_len(src_len: usize) -> usize {
        32 + src_len + src_len / 6
    }

    /// The low 16 bits of `x`, the width of a match-table entry.
    const fn low_u16(x: usize) -> u16 {
        let [lo, hi, ..] = x.to_le_bytes();
        u16::from_le_bytes([lo, hi])
    }

    /// The low 32 bits of `x`, the width of the encoder's hash word.
    const fn low_u32(x: u64) -> u32 {
        let [b0, b1, b2, b3, ..] = x.to_le_bytes();
        u32::from_le_bytes([b0, b1, b2, b3])
    }

    /// Reads the little-endian `u32` at `i`; every call site stays inside the
    /// `INPUT_MARGIN` window `encode_block` maintains.
    fn load32(src: &[u8], i: usize) -> u32 {
        let Some(&[b0, b1, b2, b3]) = src.get(i..i + 4) else {
            return 0;
        };
        u32::from_le_bytes([b0, b1, b2, b3])
    }

    /// Reads the little-endian `u64` at `i`, bounded as [`load32`] is.
    fn load64(src: &[u8], i: usize) -> u64 {
        let Some(&[b0, b1, b2, b3, b4, b5, b6, b7]) = src.get(i..i + 8) else {
            return 0;
        };
        u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7])
    }

    /// One source byte, read the way the match loop reads it: `src[i]` never runs
    /// past the end because the match start precedes the cursor.
    fn src_byte(src: &[u8], i: usize) -> u8 {
        src.get(i).copied().unwrap_or_default()
    }

    /// A match-table entry; `idx` is `TABLE_MASK`-bounded, so the entry exists.
    fn table_get(table: &[u16], idx: usize) -> usize {
        usize::from(table.get(idx).copied().unwrap_or_default())
    }

    /// Stores a match-table entry; `idx` is `TABLE_MASK`-bounded.
    fn table_set(table: &mut [u16], idx: usize, pos: usize) {
        let Some(slot) = table.get_mut(idx) else {
            return;
        };
        *slot = low_u16(pos);
    }

    const fn hash(u: u32, shift: u32) -> u32 {
        u.wrapping_mul(0x1e35_a7bd) >> shift
    }

    fn emit_literal(out: &mut Vec<u8>, lit: &[u8]) {
        let n = lit.len() - 1;
        let [n_lo, n_hi, ..] = n.to_le_bytes();
        if n < 60 {
            out.push(n_lo << 2 | TAG_LITERAL);
        } else if n < 1 << 8 {
            out.push(60 << 2 | TAG_LITERAL);
            out.push(n_lo);
        } else {
            out.push(61 << 2 | TAG_LITERAL);
            out.push(n_lo);
            out.push(n_hi);
        }
        out.extend_from_slice(lit);
    }

    fn emit_copy(out: &mut Vec<u8>, offset: usize, mut length: usize) {
        let [offset_lo, offset_hi, ..] = offset.to_le_bytes();
        while length >= 68 {
            out.push(63 << 2 | TAG_COPY2);
            out.push(offset_lo);
            out.push(offset_hi);
            length -= 64;
        }
        if length > 64 {
            out.push(59 << 2 | TAG_COPY2);
            out.push(offset_lo);
            out.push(offset_hi);
            length -= 60;
        }
        if length >= 12 || offset >= 2048 {
            let [len_lo, ..] = (length - 1).to_le_bytes();
            out.push(len_lo << 2 | TAG_COPY2);
            out.push(offset_lo);
            out.push(offset_hi);
            return;
        }
        let [len_lo, ..] = (length - 4).to_le_bytes();
        out.push(offset_hi << 5 | len_lo << 2 | TAG_COPY1);
        out.push(offset_lo);
    }

    /// Encodes a block, assuming the encoded length is already written.
    fn encode_block(out: &mut Vec<u8>, src: &[u8]) {
        let mut table = vec![0u16; MAX_TABLE_SIZE];
        let table = table.as_mut_slice();

        let mut shift: u32 = 32 - 8;
        let mut table_size = 1 << 8;
        while table_size < MAX_TABLE_SIZE && table_size < src.len() {
            shift -= 1;
            table_size *= 2;
        }

        let s_limit = src.len() - INPUT_MARGIN;
        let mut next_emit = 0;
        let mut s = 1;
        let mut next_hash = hash(load32(src, s), shift);
        let mut candidate;

        'emit_remainder: loop {
            let mut skip = 32;
            let mut next_s = s;
            loop {
                s = next_s;
                let bytes_between_hash_lookups = skip >> 5;
                next_s = s + bytes_between_hash_lookups;
                skip += bytes_between_hash_lookups;
                if next_s > s_limit {
                    break 'emit_remainder;
                }
                let idx = next_hash as usize & TABLE_MASK;
                candidate = table_get(table, idx);
                table_set(table, idx, s);
                next_hash = hash(load32(src, next_s), shift);
                if load32(src, s) == load32(src, candidate) {
                    break;
                }
            }

            emit_literal(out, src.get(next_emit..s).unwrap_or_default());

            loop {
                let base = s;
                s += 4;
                let mut i = candidate + 4;
                while s < src.len() && src_byte(src, i) == src_byte(src, s) {
                    i += 1;
                    s += 1;
                }
                emit_copy(out, base - candidate, s - base);
                next_emit = s;
                if s >= s_limit {
                    break 'emit_remainder;
                }
                let x = load64(src, s - 1);
                let prev_hash = hash(low_u32(x), shift);
                let idx = prev_hash as usize & TABLE_MASK;
                table_set(table, idx, s - 1);
                let curr_hash = hash(low_u32(x >> 8), shift);
                let idx = curr_hash as usize & TABLE_MASK;
                candidate = table_get(table, idx);
                table_set(table, idx, s);
                if low_u32(x >> 8) != load32(src, candidate) {
                    next_hash = hash(low_u32(x >> 16), shift);
                    s += 1;
                    break;
                }
            }
        }

        if next_emit < src.len() {
            emit_literal(out, src.get(next_emit..).unwrap_or_default());
        }
    }

    fn put_uvarint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            let [lo, ..] = v.to_le_bytes();
            out.push(lo | 0x80);
            v >>= 7;
        }
        let [lo, ..] = v.to_le_bytes();
        out.push(lo);
    }

    fn uvarint(buf: &[u8]) -> (u64, usize) {
        let mut x: u64 = 0;
        let mut s: u32 = 0;
        for (i, &b) in buf.iter().enumerate() {
            if i == 10 {
                return (0, 0);
            }
            if b < 0x80 {
                if i == 9 && b > 1 {
                    return (0, 0);
                }
                return (x | u64::from(b) << s, i + 1);
            }
            x |= u64::from(b & 0x7f) << s;
            s += 7;
        }
        (0, 0)
    }

    #[must_use]
    pub fn encode(src: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(max_encoded_len(src.len()));
        put_uvarint(&mut out, src.len() as u64);
        let mut rest = src;
        while !rest.is_empty() {
            let n = rest.len().min(MAX_BLOCK_SIZE);
            let (p, next) = rest.split_at(n);
            rest = next;
            if p.len() < MIN_NON_LITERAL_BLOCK_SIZE {
                emit_literal(&mut out, p);
            } else {
                encode_block(&mut out, p);
            }
        }
        out
    }

    fn decoded_len(src: &[u8]) -> Result<(usize, usize), Error> {
        let (v, n) = uvarint(src);
        if n == 0 || v > 0xffff_ffff {
            return Err(Error::Corrupt);
        }
        let d_len = usize::try_from(v).map_err(|_| Error::Corrupt)?;
        Ok((d_len, n))
    }

    /// One input byte, or `Error::Corrupt` when the stream ends mid-token.
    fn load_byte(src: &[u8], i: usize) -> Result<u8, Error> {
        src.get(i).copied().ok_or(Error::Corrupt)
    }

    /// Decodes a block, assuming the decoded length is already read.
    pub fn decode(dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        let mut d = 0;
        let mut s = 0;
        while s < src.len() {
            let length: usize;
            let offset: usize;
            let tag = load_byte(src, s)?;
            match tag & 0x03 {
                TAG_LITERAL => {
                    let mut x = u32::from(tag >> 2);
                    match x {
                        0..=59 => s += 1,
                        60 => {
                            s += 2;
                            x = u32::from(load_byte(src, s - 1)?);
                        }
                        61 => {
                            s += 3;
                            x = u32::from(load_byte(src, s - 2)?) | u32::from(load_byte(src, s - 1)?) << 8;
                        }
                        62 => {
                            s += 4;
                            x = u32::from(load_byte(src, s - 3)?)
                                | u32::from(load_byte(src, s - 2)?) << 8
                                | u32::from(load_byte(src, s - 1)?) << 16;
                        }
                        _ => {
                            s += 5;
                            x = u32::from(load_byte(src, s - 4)?)
                                | u32::from(load_byte(src, s - 3)?) << 8
                                | u32::from(load_byte(src, s - 2)?) << 16
                                | u32::from(load_byte(src, s - 1)?) << 24;
                        }
                    }
                    length = x as usize + 1;
                    if length > dst.len() - d || length > src.len() - s {
                        return Err(Error::Corrupt);
                    }
                    let (Some(dst_part), Some(src_part)) = (dst.get_mut(d..d + length), src.get(s..s + length)) else {
                        return Err(Error::Corrupt);
                    };
                    dst_part.copy_from_slice(src_part);
                    d += length;
                    s += length;
                    continue;
                }
                TAG_COPY1 => {
                    s += 2;
                    let b0 = load_byte(src, s - 2)?;
                    let b1 = load_byte(src, s - 1)?;
                    length = 4 + ((usize::from(b0) >> 2) & 0x7);
                    offset = ((u32::from(b0) & 0xe0) << 3 | u32::from(b1)) as usize;
                }
                TAG_COPY2 => {
                    s += 3;
                    length = (usize::from(load_byte(src, s - 3)?) >> 2) + 1;
                    offset = usize::from(load_byte(src, s - 2)?) | usize::from(load_byte(src, s - 1)?) << 8;
                }
                _ => {
                    s += 5;
                    length = (usize::from(load_byte(src, s - 5)?) >> 2) + 1;
                    offset = usize::from(load_byte(src, s - 4)?)
                        | usize::from(load_byte(src, s - 3)?) << 8
                        | usize::from(load_byte(src, s - 2)?) << 16
                        | usize::from(load_byte(src, s - 1)?) << 24;
                }
            }
            if offset == 0 || d < offset || length > dst.len() - d {
                return Err(Error::Corrupt);
            }
            if offset >= length {
                dst.copy_within(d - offset..d - offset + length, d);
                d += length;
                continue;
            }
            let mut k = 0;
            while k < length {
                let Some(&byte) = dst.get(d - offset + k) else {
                    return Err(Error::Corrupt);
                };
                let Some(slot) = dst.get_mut(d + k) else {
                    return Err(Error::Corrupt);
                };
                *slot = byte;
                k += 1;
            }
            d += length;
        }
        if d != dst.len() {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    pub fn decode_block(src: &[u8]) -> Result<Vec<u8>, Error> {
        let (d_len, header_len) = decoded_len(src)?;
        let mut dst = vec![0u8; d_len];
        decode(&mut dst, src.get(header_len..).ok_or(Error::Corrupt)?)?;
        Ok(dst)
    }

    fn crc(b: &[u8]) -> u32 {
        crc32c(b).rotate_right(15).wrapping_add(0xa282_ead8)
    }

    static CRC32C_TABLE: LazyLock<[u32; 256]> = LazyLock::new(|| {
        let mut table = [0u32; 256];
        for (entry, value) in table.iter_mut().zip(0u8..=u8::MAX) {
            let mut c = u32::from(value);
            for _ in 0..8 {
                c = if c & 1 != 0 { 0x82f6_3b78 ^ (c >> 1) } else { c >> 1 };
            }
            *entry = c;
        }
        table
    });

    fn crc32c(b: &[u8]) -> u32 {
        let table = &*CRC32C_TABLE;
        let mut c = 0xffff_ffffu32;
        for &byte in b {
            let idx = ((c ^ u32::from(byte)) & 0xff) as usize;
            c = table.get(idx).copied().unwrap_or_default() ^ (c >> 8);
        }
        !c
    }

    /// The framing-format writer.
    pub struct Writer {
        ibuf: Vec<u8>,
        out: Vec<u8>,
        out_pos: usize,
        wrote_stream_header: bool,
        pending: Option<usize>,
        err: Option<io::Error>,
    }

    impl fmt::Debug for Writer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Writer")
                .field("ibuf_len", &self.ibuf.len())
                .field("out_len", &self.out.len())
                .field("out_pos", &self.out_pos)
                .field("wrote_stream_header", &self.wrote_stream_header)
                .field("pending", &self.pending)
                .field("err", &self.err)
                .finish_non_exhaustive()
        }
    }

    impl Writer {
        #[must_use]
        pub fn new() -> Self {
            Self {
                ibuf: Vec::with_capacity(MAX_BLOCK_SIZE),
                out: Vec::new(),
                out_pos: 0,
                wrote_stream_header: false,
                pending: None,
                err: None,
            }
        }

        /// Writes one chunk and flushes the framed output.
        pub fn poll_write(&mut self, conn: &mut dyn Conn, cx: &mut Context<'_>, p: &[u8]) -> Poll<io::Result<usize>> {
            if let Some(err) = self.error() {
                return Poll::Ready(Err(err));
            }
            if self.pending.is_none() {
                let n = self.write(p);
                self.flush();
                self.pending = Some(n);
            }
            match self.poll_drain(conn, cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(())) => Poll::Ready(Ok(self.pending.take().unwrap_or(0))),
                Poll::Ready(Err(err)) => {
                    self.pending = None;
                    Poll::Ready(Err(self.fail(err)))
                }
            }
        }

        pub fn poll_flush(&mut self, conn: &mut dyn Conn, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if let Some(err) = self.error() {
                return Poll::Ready(Err(err));
            }
            self.flush();
            match self.poll_drain(conn, cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(())) => Pin::new(&mut *conn).poll_flush(cx),
                Poll::Ready(Err(err)) => Poll::Ready(Err(self.fail(err))),
            }
        }

        fn error(&self) -> Option<io::Error> {
            self.err.as_ref().map(|err| io::Error::new(err.kind(), err.to_string()))
        }

        fn fail(&mut self, err: io::Error) -> io::Error {
            let out = io::Error::new(err.kind(), err.to_string());
            self.err = Some(err);
            out
        }

        fn poll_drain(&mut self, conn: &mut dyn Conn, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            while self.out_pos < self.out.len() {
                let n = {
                    let chunk = self.out.get(self.out_pos..).unwrap_or_default();
                    ready!(Pin::new(&mut *conn).poll_write(cx, chunk))
                }?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "snappy: write zero bytes")));
                }
                self.out_pos += n;
            }
            self.out.clear();
            self.out_pos = 0;
            Poll::Ready(Ok(()))
        }

        fn write(&mut self, p: &[u8]) -> usize {
            let mut n_ret = 0;
            let mut p = p;
            while p.len() > MAX_BLOCK_SIZE - self.ibuf.len() {
                let n = if self.ibuf.is_empty() {
                    self.write_direct(p)
                } else {
                    let n = (MAX_BLOCK_SIZE - self.ibuf.len()).min(p.len());
                    self.ibuf.extend_from_slice(p.get(..n).unwrap_or_default());
                    self.flush();
                    n
                };
                n_ret += n;
                p = p.split_at(n).1;
            }
            let n = (MAX_BLOCK_SIZE - self.ibuf.len()).min(p.len());
            self.ibuf.extend_from_slice(p.get(..n).unwrap_or_default());
            n_ret + n
        }

        fn write_direct(&mut self, p: &[u8]) -> usize {
            let mut n_ret = 0;
            let mut p = p;
            while !p.is_empty() {
                let n = p.len().min(MAX_BLOCK_SIZE);
                let (uncompressed, rest) = p.split_at(n);
                p = rest;
                n_ret += uncompressed.len();
                self.write_chunk(uncompressed);
            }
            n_ret
        }

        fn write_chunk(&mut self, uncompressed: &[u8]) {
            if !self.wrote_stream_header {
                self.wrote_stream_header = true;
                self.out.extend_from_slice(&MAGIC_CHUNK);
            }
            let checksum = crc(uncompressed);
            let compressed = encode(uncompressed);
            let (chunk_type, body) = if compressed.len() >= uncompressed.len() - uncompressed.len() / 8 {
                (CHUNK_TYPE_UNCOMPRESSED_DATA, uncompressed)
            } else {
                (CHUNK_TYPE_COMPRESSED_DATA, compressed.as_slice())
            };
            let chunk_len = CHECKSUM_SIZE + body.len();
            let [len_lo, len_mid, len_hi, ..] = chunk_len.to_le_bytes();
            self.out.push(chunk_type);
            self.out.push(len_lo);
            self.out.push(len_mid);
            self.out.push(len_hi);
            self.out.extend_from_slice(&checksum.to_le_bytes());
            self.out.extend_from_slice(body);
        }

        fn flush(&mut self) {
            if self.ibuf.is_empty() {
                return;
            }
            let block = std::mem::take(&mut self.ibuf);
            self.write_chunk(&block);
            self.ibuf = block;
            self.ibuf.clear();
        }
    }

    impl Default for Writer {
        fn default() -> Self {
            Self::new()
        }
    }

    /// The framing-format reader.
    pub struct Reader {
        decoded: Vec<u8>,
        buf: Vec<u8>,
        i: usize,
        j: usize,
        read_header: bool,
        eof: bool,
        err: Option<io::Error>,
        header: [u8; CHUNK_HEADER_SIZE],
        header_have: usize,
        header_done: bool,
        chunk_type: u8,
        body_len: usize,
        body_have: usize,
    }

    impl fmt::Debug for Reader {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Reader")
                .field("decoded_len", &self.decoded.len())
                .field("buf_len", &self.buf.len())
                .field("i", &self.i)
                .field("j", &self.j)
                .field("eof", &self.eof)
                .finish_non_exhaustive()
        }
    }

    impl Reader {
        #[must_use]
        pub fn new() -> Self {
            Self {
                decoded: vec![0u8; MAX_BLOCK_SIZE],
                buf: vec![0u8; MAX_ENCODED_LEN_OF_MAX_BLOCK_SIZE + CHECKSUM_SIZE],
                i: 0,
                j: 0,
                read_header: false,
                eof: false,
                err: None,
                header: [0u8; CHUNK_HEADER_SIZE],
                header_have: 0,
                header_done: false,
                chunk_type: 0,
                body_len: 0,
                body_have: 0,
            }
        }

        pub fn poll_read(
            &mut self,
            conn: &mut dyn Conn,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(err) = &self.err {
                return Poll::Ready(Err(io::Error::new(err.kind(), err.to_string())));
            }
            if self.eof || out.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            while self.i >= self.j {
                ready!(self.poll_fill(conn, cx))?;
                if self.eof {
                    return Poll::Ready(Ok(()));
                }
            }
            let n = out.remaining().min(self.j - self.i);
            let chunk = self.decoded.get(self.i..self.i + n).unwrap_or_default();
            out.put_slice(chunk);
            self.i += n;
            Poll::Ready(Ok(()))
        }

        fn poll_fill(&mut self, conn: &mut dyn Conn, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            while self.i >= self.j {
                if !self.header_done {
                    if self.header_have < CHUNK_HEADER_SIZE {
                        let filled = {
                            let mut rb = ReadBuf::new(self.header.get_mut(self.header_have..).unwrap_or_default());
                            ready!(Pin::new(&mut *conn).poll_read(cx, &mut rb))?;
                            rb.filled().len()
                        };
                        if filled == 0 {
                            if self.header_have == 0 {
                                self.eof = true;
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(self.set_err(corrupt())));
                        }
                        self.header_have += filled;
                        if self.header_have < CHUNK_HEADER_SIZE {
                            continue;
                        }
                    }
                    let [chunk_type, len_lo, len_mid, len_hi] = self.header;
                    if !self.read_header {
                        if chunk_type != CHUNK_TYPE_STREAM_IDENTIFIER {
                            return Poll::Ready(Err(self.set_err(corrupt())));
                        }
                        self.read_header = true;
                    }
                    let chunk_len = usize::from(len_lo) | usize::from(len_mid) << 8 | usize::from(len_hi) << 16;
                    if chunk_len > self.buf.len() {
                        return Poll::Ready(Err(self.set_err(unsupported())));
                    }
                    if chunk_type == CHUNK_TYPE_STREAM_IDENTIFIER {
                        if chunk_len != MAGIC_BODY.len() {
                            return Poll::Ready(Err(self.set_err(corrupt())));
                        }
                    } else if chunk_type == CHUNK_TYPE_COMPRESSED_DATA || chunk_type == CHUNK_TYPE_UNCOMPRESSED_DATA {
                        if chunk_len < CHECKSUM_SIZE {
                            return Poll::Ready(Err(self.set_err(corrupt())));
                        }
                    } else if chunk_type <= 0x7f {
                        return Poll::Ready(Err(self.set_err(unsupported())));
                    }
                    self.chunk_type = chunk_type;
                    self.body_len = chunk_len;
                    self.body_have = 0;
                    self.header_have = 0;
                    self.header_done = true;
                }

                if self.body_have < self.body_len {
                    let filled = {
                        let range = self.body_have..self.body_len;
                        let dst = self.buf.get_mut(range).unwrap_or_default();
                        let mut rb = ReadBuf::new(dst);
                        ready!(Pin::new(&mut *conn).poll_read(cx, &mut rb))?;
                        rb.filled().len()
                    };
                    if filled == 0 {
                        return Poll::Ready(Err(self.set_err(corrupt())));
                    }
                    self.body_have += filled;
                    if self.body_have < self.body_len {
                        continue;
                    }
                }

                if let Err(err) = self.handle_body() {
                    return Poll::Ready(Err(self.set_err(err)));
                }
                self.header_done = false;
            }
            Poll::Ready(Ok(()))
        }

        /// The handling of a complete chunk body.
        fn handle_body(&mut self) -> io::Result<()> {
            match self.chunk_type {
                CHUNK_TYPE_COMPRESSED_DATA => {
                    let chunk_len = self.body_len;
                    let Some(&[c0, c1, c2, c3]) = self.buf.get(..CHECKSUM_SIZE) else {
                        return Err(corrupt());
                    };
                    let checksum = u32::from_le_bytes([c0, c1, c2, c3]);
                    let Some(body) = self.buf.get(CHECKSUM_SIZE..chunk_len) else {
                        return Err(corrupt());
                    };
                    let (d_len, header_len) = decoded_len(body).map_err(snappy_err)?;
                    if d_len > self.decoded.len() {
                        return Err(corrupt());
                    }
                    let Some(decoded) = self.decoded.get_mut(..d_len) else {
                        return Err(corrupt());
                    };
                    let Some(encoded) = body.get(header_len..) else {
                        return Err(corrupt());
                    };
                    decode(decoded, encoded).map_err(snappy_err)?;
                    if crc(decoded) != checksum {
                        return Err(corrupt());
                    }
                    self.i = 0;
                    self.j = d_len;
                    Ok(())
                }
                CHUNK_TYPE_UNCOMPRESSED_DATA => {
                    let chunk_len = self.body_len;
                    let Some(&[c0, c1, c2, c3]) = self.buf.get(..CHECKSUM_SIZE) else {
                        return Err(corrupt());
                    };
                    let checksum = u32::from_le_bytes([c0, c1, c2, c3]);
                    let n = chunk_len - CHECKSUM_SIZE;
                    if n > self.decoded.len() {
                        return Err(corrupt());
                    }
                    let Some(decoded) = self.decoded.get_mut(..n) else {
                        return Err(corrupt());
                    };
                    let Some(raw) = self.buf.get(CHECKSUM_SIZE..chunk_len) else {
                        return Err(corrupt());
                    };
                    decoded.copy_from_slice(raw);
                    if crc(decoded) != checksum {
                        return Err(corrupt());
                    }
                    self.i = 0;
                    self.j = n;
                    Ok(())
                }
                CHUNK_TYPE_STREAM_IDENTIFIER => {
                    if self.buf.get(..MAGIC_BODY.len()) != Some(MAGIC_BODY.as_slice()) {
                        return Err(corrupt());
                    }
                    Ok(())
                }
                _ => Ok(()),
            }
        }

        fn set_err(&mut self, err: io::Error) -> io::Error {
            let out = io::Error::new(err.kind(), err.to_string());
            self.err = Some(err);
            out
        }
    }

    impl Default for Reader {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg(test)]
    mod tests {
        //! Known-answer tests pinning this codec to its golden output; the golden bytes were
        //! produced at development time from a conforming encoder.
        use super::*;

        fn assert_block_roundtrip(src: &[u8], want_enc_hex: &str) {
            let want_enc = hex::decode(want_enc_hex).unwrap();
            assert_eq!(hex::encode(encode(src)), want_enc_hex, "encode() must match the golden encoding");
            let decoded = decode_block(&want_enc).expect("the own bytes must decode");
            assert_eq!(decoded, src, "Rust decode of the bytes must reproduce the input");
        }

        #[test]
        fn block_empty_matches_reference_encoder() {
            assert_block_roundtrip(b"", "00");
        }

        #[test]
        fn block_short_abcd_matches_reference_encoder() {
            assert_block_roundtrip(b"abcd", "040c61626364");
        }

        #[test]
        fn block_repetitive_150a_matches_reference_encoder() {
            let src = vec![b'A'; 150];
            assert_block_roundtrip(&src, "96010041fe0100fe0100520100");
        }

        #[test]
        fn block_incompressible_64_matches_reference_encoder() {
            let src = hex::decode(
                "0b7d36749dcdadbb424a377a00f6511e9aa52ec796287086a518ecc3c75284bb376e731cd2af6ebfa9246c6bccb304e2485f8907183f0020823264db7c303d0f",
            )
            .unwrap();
            assert_block_roundtrip(
                &src,
                "40f03f0b7d36749dcdadbb424a377a00f6511e9aa52ec796287086a518ecc3c75284bb376e731cd2af6ebfa9246c6bccb304e2485f8907183f0020823264db7c303d0f",
            );
        }

        /// 70001 bytes, crossing the 64 KiB (`MAX_BLOCK_SIZE`) block-splitting boundary in
        /// `encode`/`Encode`, exercising the multi-block path both encoders and decoders share.
        #[test]
        fn block_over_64kib_matches_reference_encoder() {
            let pattern = b"Hello, kcptun snappy golden vector! ";
            let mut src = Vec::with_capacity(70001);
            while src.len() < 70001 {
                src.extend_from_slice(pattern);
            }
            src.truncate(70001);

            let want_enc_hex = concat!(
                "f1a2049048656c6c6f2c206b637074756e20736e6170707920676f6c64656e20766563746f72212048fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe",
                "2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe24006a240090617070792067",
                "6f6c64656e20766563746f72212048656c6c6f2c206b637074756e20736e61fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe24",
                "00fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe24",
                "00fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe24",
                "00fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe2400fe24002e24",
                "00",
            );
            assert_block_roundtrip(&src, want_enc_hex);
        }

        /// The writer golden-output test: the exact framed byte
        /// sequence, including the two stream-checksum'd chunks and their CRC-32C masking,
        /// produced for this `write`/`flush` sequence.
        #[test]
        fn writer_golden_output_matches_reference_encoder() {
            let mut w = Writer::new();
            w.write(b"abcd");
            w.flush();
            w.write(&[b'A'; 150]);
            w.flush();
            w.write(&[b'B'; 68]);
            w.write(b"efC");
            w.write(&[b'C'; 20]);
            w.write(&[b'B'; 20]);
            w.write(b"g");
            w.flush();

            assert_eq!(
                hex::encode(&w.out),
                "ff060000734e61507059010800006810e6b661626364001100005febf21096010041fe0100fe010052010000180000308569eb700042ee01000d01086566434e01004e5a000067"
            );
        }
    }
}

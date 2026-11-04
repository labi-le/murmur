use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common_net::io::{close_stream, Stream as NetConn};

use super::conn::{
    eof, err_closed_pipe, map_miss, poll_read_limited, BufReaderState, WriteDrain, MIN_DECODE_READ_SIZE,
};
use super::layout::ByteLayout;
use super::padding_prob::pick_padding_threshold;
use super::pending::{append_decoded_byte, drain_pending, new_pending_buffer, PendingBuffer};
use super::rand::{fast_intn_from_uint32, new_seeded_rand, SudokuRand};
use super::table::Table;

const PACKED_PROTECTED_PREFIX_BYTES: usize = 14;
const PACKED_IO_BUFFER_SIZE: usize = 32 * 1024;
const PACKED_DECODE_BUFFER_SIZE: usize = 32 * 1024;

/// Encodes traffic with the packed Sudoku layout while preserving the same
/// padding model as the regular connection.
pub struct PackedConn {
    conn: Option<Box<dyn NetConn>>,
    table: Option<Arc<Table>>,
    reader: BufReaderState,

    raw_buf: Vec<u8>,
    pending_data: PendingBuffer,

    write_drain: WriteDrain,
    bit_buf: u64,
    bit_count: i32,

    read_bit_buf: u64,
    read_bits: i32,

    rng: SudokuRand,
    padding_threshold: u64,
    pad_marker: u8,
    pad_pool: Vec<u8>,
}

impl fmt::Debug for PackedConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackedConn")
            .field("table", &self.table.as_ref().map(|table| table.hint()))
            .field("bit_count", &self.bit_count)
            .field("read_bits", &self.read_bits)
            .field("padding_threshold", &self.padding_threshold)
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn new_packed_conn(c: Box<dyn NetConn>, table: Option<Arc<Table>>, p_min: i32, p_max: i32) -> PackedConn {
    let mut local_rng = new_seeded_rand();
    let padding_threshold = pick_padding_threshold(Some(&mut local_rng), p_min, p_max);

    let mut pc = PackedConn {
        conn: Some(c),
        table,
        reader: BufReaderState::new(PACKED_IO_BUFFER_SIZE),
        raw_buf: vec![0u8; PACKED_DECODE_BUFFER_SIZE],
        pending_data: new_pending_buffer(4096),
        write_drain: WriteDrain::with_capacity(4096),
        bit_buf: 0,
        bit_count: 0,
        read_bit_buf: 0,
        read_bits: 0,
        rng: local_rng,
        padding_threshold,
        pad_marker: 0,
        pad_pool: Vec::new(),
    };

    if let Some(table) = pc.table.as_ref() {
        if let Some(layout) = table.layout.as_deref() {
            pc.pad_marker = layout.pad_marker;
            for &b in &table.padding_pool {
                if b != pc.pad_marker {
                    pc.pad_pool.push(b);
                }
            }
        }
    }
    if pc.pad_pool.is_empty() {
        pc.pad_pool.push(pc.pad_marker);
    }
    pc
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the shift drops exactly the six bits just taken out of bit_buf, so the result is already below 0x40"
)]
const fn take_bit_group(bit_buf: &mut u64, bit_count: &mut i32) -> u8 {
    *bit_count -= 6;
    let shift = bit_count.cast_unsigned();
    let group = (*bit_buf >> shift) as u8;
    if *bit_count == 0 {
        *bit_buf = 0;
    } else {
        *bit_buf &= (1u64 << shift) - 1;
    }
    group
}

/// Pads a partial bit group out to a byte.
#[expect(
    clippy::cast_possible_truncation,
    reason = "fewer than six bits remain above the shift, so the padded value already fits a u8"
)]
const fn final_group(bit_buf: u64, bit_count: i32) -> u8 {
    (bit_buf << (6 - bit_count).cast_unsigned()) as u8
}

/// Takes the byte that the low `shift` bits of `bit_buf` have just completed.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the shift leaves the eight or fewer bits that make up one decoded byte"
)]
const fn shifted_byte(bit_buf: u64, shift: i32) -> u8 {
    (bit_buf >> shift.cast_unsigned()) as u8
}

/// `fast_intn_from_uint32` stays below `pad_pool.len()`, and callers only reach
/// this with a non-empty pool.
fn pick_pad_byte(rng: &mut SudokuRand, pad_pool: &[u8]) -> u8 {
    pad_pool.get(fast_intn_from_uint32(rng.uint32(), pad_pool.len())).copied().unwrap_or_default()
}

fn append_packed_group(
    out: &mut Vec<u8>,
    layout: &ByteLayout,
    rng: &mut SudokuRand,
    padding_threshold: u64,
    pad_pool: &[u8],
    group: u8,
) {
    if padding_threshold != 0 {
        let u = rng.uint32();
        if u64::from(u) < padding_threshold {
            out.push(pick_pad_byte(rng, pad_pool));
        }
    }
    out.push(layout.group_byte(group & 0x3F));
}

fn maybe_append_packed_padding(out: &mut Vec<u8>, rng: &mut SudokuRand, padding_threshold: u64, pad_pool: &[u8]) {
    if padding_threshold != 0 {
        let u = rng.uint32();
        if u64::from(u) < padding_threshold {
            out.push(pick_pad_byte(rng, pad_pool));
        }
    }
}

impl PackedConn {
    fn layout_missing(&self) -> bool {
        self.table.as_ref().is_none_or(|table| table.layout.is_none())
    }

    pub fn close_write(&self) -> io::Result<()> {
        match self.conn.as_ref() {
            Some(conn) => conn.shutdown_write(),
            None => Ok(()),
        }
    }

    pub fn close_read(&self) -> io::Result<()> {
        match self.conn.as_ref() {
            Some(conn) => conn.shutdown_read(),
            None => Ok(()),
        }
    }

    fn get_padding_byte(&mut self) -> u8 {
        let n = self.pad_pool.len();
        self.pad_pool.get(self.rng.intn(n)).copied().unwrap_or_default()
    }

    fn next_protected_prefix_gap(&mut self) -> usize {
        1 + self.rng.intn(2)
    }

    fn append_group(&mut self, out: &mut Vec<u8>, layout: &ByteLayout, group: u8) {
        append_packed_group(out, layout, &mut self.rng, self.padding_threshold, &self.pad_pool, group);
    }

    fn append_padding(&mut self, out: &mut Vec<u8>) {
        maybe_append_packed_padding(out, &mut self.rng, self.padding_threshold, &self.pad_pool);
    }

    fn write_protected_prefix(&mut self, out: &mut Vec<u8>, p: &[u8], layout: &ByteLayout) -> usize {
        if p.is_empty() {
            return 0;
        }

        let mut limit = p.len();
        if limit > PACKED_PROTECTED_PREFIX_BYTES {
            limit = PACKED_PROTECTED_PREFIX_BYTES;
        }

        for _ in 0..=self.rng.intn(2) {
            out.push(self.get_padding_byte());
        }

        let mut gap = self.next_protected_prefix_gap();
        let mut effective = 0usize;
        for &byte in p.iter().take(limit) {
            self.bit_buf = (self.bit_buf << 8) | u64::from(byte);
            self.bit_count += 8;
            while self.bit_count >= 6 {
                let group = take_bit_group(&mut self.bit_buf, &mut self.bit_count);
                self.append_group(out, layout, group);
            }

            effective += 1;
            if effective >= gap {
                out.push(self.get_padding_byte());
                effective = 0;
                gap = self.next_protected_prefix_gap();
            }
        }

        limit
    }

    fn encode_write(&mut self, p: &[u8]) -> io::Result<()> {
        let needed = if self.padding_threshold == 0 { p.len().div_ceil(3) * 4 + 32 } else { p.len() * 3 / 2 + 32 };
        let mut out = self.write_drain.take_buf();
        if out.capacity() < needed {
            out = Vec::with_capacity(needed);
        }
        out.clear();

        let Some(table) = self.table.clone() else {
            return Err(err_closed_pipe());
        };
        let Some(layout) = table.layout.as_deref() else {
            return Err(err_closed_pipe());
        };
        let prefix_n = self.write_protected_prefix(&mut out, p, layout);

        let mut rest = p.get(prefix_n..).unwrap_or_default();

        while self.bit_count > 0 {
            let Some((&byte, tail)) = rest.split_first() else {
                break;
            };
            rest = tail;
            self.push_byte_group(&mut out, layout, byte);
        }

        while rest.len() > 11 {
            let (block, tail) = rest.split_at(12);
            for chunk in block.chunks_exact(3) {
                let &[b1, b2, b3] = chunk else {
                    continue;
                };
                self.append_triple(&mut out, layout, b1, b2, b3);
            }
            rest = tail;
        }

        for chunk in rest.chunks_exact(3) {
            let &[b1, b2, b3] = chunk else {
                continue;
            };
            self.append_triple(&mut out, layout, b1, b2, b3);
        }

        for &byte in rest.chunks_exact(3).remainder() {
            self.push_byte_group(&mut out, layout, byte);
        }

        if self.bit_count > 0 {
            let group = final_group(self.bit_buf, self.bit_count);
            self.bit_buf = 0;
            self.bit_count = 0;
            self.append_group(&mut out, layout, group);
            out.push(self.pad_marker);
        }

        self.append_padding(&mut out);

        self.write_drain.put_buf(out);
        Ok(())
    }

    fn push_byte_group(&mut self, out: &mut Vec<u8>, layout: &ByteLayout, byte: u8) {
        self.bit_buf = (self.bit_buf << 8) | u64::from(byte);
        self.bit_count += 8;
        while self.bit_count >= 6 {
            let group = take_bit_group(&mut self.bit_buf, &mut self.bit_count);
            self.append_group(out, layout, group);
        }
    }

    fn append_triple(&mut self, out: &mut Vec<u8>, layout: &ByteLayout, b1: u8, b2: u8, b3: u8) {
        let g1 = (b1 >> 2) & 0x3F;
        let g2 = ((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F);
        let g3 = ((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03);
        let g4 = b3 & 0x3F;

        self.append_group(out, layout, g1);
        self.append_group(out, layout, g2);
        self.append_group(out, layout, g3);
        self.append_group(out, layout, g4);
    }
}

impl NetConn for PackedConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self.conn.as_ref() {
            Some(conn) => conn.local_addr(),
            None => Err(err_closed_pipe()),
        }
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self.conn.as_ref() {
            Some(conn) => conn.peer_addr(),
            None => Err(err_closed_pipe()),
        }
    }

    fn shutdown_read(&self) -> io::Result<()> {
        Self::close_read(self)
    }

    fn shutdown_write(&self) -> io::Result<()> {
        Self::close_write(self)
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn.as_ref().and_then(|c| c.old_conn())
    }
}

impl AsyncWrite for PackedConn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.conn.is_none() || this.layout_missing() || this.pad_pool.is_empty() {
            return Poll::Ready(Err(err_closed_pipe()));
        }

        if this.write_drain.idle() {
            if let Err(err) = this.encode_write(buf) {
                return Poll::Ready(Err(err));
            }
            this.write_drain.start(buf.len());
        }

        let Some(conn) = this.conn.as_mut() else {
            return Poll::Ready(Err(err_closed_pipe()));
        };
        this.write_drain.poll_drain(cx, &mut **conn)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.conn.is_none() || this.layout_missing() || this.pad_pool.is_empty() {
            return Poll::Ready(Err(err_closed_pipe()));
        }

        if !this.write_drain.idle() {
            let Some(conn) = this.conn.as_mut() else {
                return Poll::Ready(Err(err_closed_pipe()));
            };
            match this.write_drain.poll_drain(cx, &mut **conn) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let Some(table) = this.table.clone() else {
            return Poll::Ready(Err(err_closed_pipe()));
        };
        let Some(layout) = table.layout.as_deref() else {
            return Poll::Ready(Err(err_closed_pipe()));
        };
        let pad_marker = this.pad_marker;
        let mut out = this.write_drain.take_buf();
        out.clear();
        if this.bit_count > 0 {
            let group = final_group(this.bit_buf, this.bit_count);
            this.bit_buf = 0;
            this.bit_count = 0;
            out.push(layout.group_byte(group));
            out.push(pad_marker);
        }

        this.append_padding(&mut out);

        this.write_drain.put_buf(out);
        this.write_drain.start(1);

        let Some(conn) = this.conn.as_mut() else {
            return Poll::Ready(Err(err_closed_pipe()));
        };
        match this.write_drain.poll_drain(cx, &mut **conn) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.close_write())
    }
}

impl AsyncRead for PackedConn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.conn.is_none() || this.raw_buf.is_empty() || this.layout_missing() {
            return Poll::Ready(Err(err_closed_pipe()));
        }
        if this.pending_data.available() > 0 {
            let (n, _) = drain_pending(buf.initialize_unfilled(), &mut this.pending_data);
            buf.advance(n);
            return Poll::Ready(Ok(()));
        }

        let Some(table) = this.table.clone() else {
            return Poll::Ready(Err(err_closed_pipe()));
        };
        let Some(layout) = table.layout.as_deref() else {
            return Poll::Ready(Err(err_closed_pipe()));
        };

        loop {
            let want = packed_read_size(buf.remaining(), this.raw_buf.len()).min(this.raw_buf.len());
            let read = {
                let (dst, _) = this.raw_buf.split_at_mut(want);
                poll_read_limited(cx, this.conn.as_mut(), &mut this.reader, dst)
            };
            let (nr, r_err) = match read {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => (0, Some(eof())),
                Poll::Ready(Ok(n)) => (n, None),
                Poll::Ready(Err(err)) => (0, Some(err)),
            };

            let mut out_n = 0usize;
            if nr > 0 {
                let chunk = this.raw_buf.get(..nr).unwrap_or_default();
                let target = buf.initialize_unfilled();
                out_n = match decode_chunk(
                    chunk,
                    layout,
                    this.pad_marker,
                    &mut this.read_bit_buf,
                    &mut this.read_bits,
                    &mut this.pending_data,
                    target,
                ) {
                    Ok(n) => n,
                    Err(err) => return Poll::Ready(Err(err)),
                };
                buf.advance(out_n);
            }

            if let Some(err) = r_err {
                if err.kind() == io::ErrorKind::UnexpectedEof {
                    this.read_bit_buf = 0;
                    this.read_bits = 0;
                }
                if out_n > 0 {
                    return Poll::Ready(Ok(()));
                }
                let (n, ok) = drain_pending(buf.initialize_unfilled(), &mut this.pending_data);
                if ok {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                if err.kind() == io::ErrorKind::UnexpectedEof {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(err));
            }
            if out_n > 0 {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

/// Decodes one raw chunk into `target`, returning how many bytes it produced.
///
/// The bit state lives on the connection, so the caller hands its fields in
/// separately: the raw chunk is still borrowed from the same connection.
fn decode_chunk(
    chunk: &[u8],
    layout: &ByteLayout,
    pad_marker: u8,
    read_bit_buf: &mut u64,
    read_bits: &mut i32,
    pending: &mut PendingBuffer,
    target: &mut [u8],
) -> io::Result<usize> {
    let mut out_n = 0usize;
    let mut i = 0usize;
    while let Some(&b) = chunk.get(i) {
        if *read_bits == 0 && out_n + 3 <= target.len() {
            if let Some(&[b0, b1, b2, b3]) = chunk.get(i..i + 4) {
                if layout.is_hint(b0) && layout.is_hint(b1) && layout.is_hint(b2) && layout.is_hint(b3) {
                    let g1 = layout.decode_packed_group(b0).0;
                    let g2 = layout.decode_packed_group(b1).0;
                    let g3 = layout.decode_packed_group(b2).0;
                    let g4 = layout.decode_packed_group(b3).0;
                    if let Some(out) = target.get_mut(out_n..out_n + 3) {
                        out.copy_from_slice(&[(g1 << 2) | (g2 >> 4), (g2 << 4) | (g3 >> 2), (g3 << 6) | g4]);
                        out_n += 3;
                        i += 4;
                        continue;
                    }
                }
            }
        }

        i += 1;
        if !layout.is_hint(b) {
            if b == pad_marker {
                *read_bit_buf = 0;
                *read_bits = 0;
            }
            continue;
        }

        let (group, ok) = layout.decode_packed_group(b);
        if !ok {
            return Err(map_miss());
        }

        *read_bit_buf = (*read_bit_buf << 6) | u64::from(group);
        *read_bits += 6;

        if *read_bits >= 8 {
            *read_bits -= 8;
            let val = shifted_byte(*read_bit_buf, *read_bits);
            out_n = append_decoded_byte(target, out_n, pending, val);
            if *read_bits == 0 {
                *read_bit_buf = 0;
            } else {
                *read_bit_buf &= (1u64 << read_bits.cast_unsigned()) - 1;
            }
        }
    }
    Ok(out_n)
}

const fn packed_read_size(decoded_remaining: usize, max_raw: usize) -> usize {
    if max_raw <= MIN_DECODE_READ_SIZE || decoded_remaining == 0 {
        return max_raw;
    }
    if decoded_remaining > (max_raw - MIN_DECODE_READ_SIZE) / 2 {
        return max_raw;
    }

    decoded_remaining * 2 + MIN_DECODE_READ_SIZE
}

/// The same `PackedConn` is handed to both the downlink writer and the flush
/// closer; the shared handle keeps that aliasing with an internal mutex.
#[derive(Debug, Clone)]
pub struct PackedConnHandle {
    conn: Arc<Mutex<PackedConn>>,
    close_view: PackedConnCloseView,
}

impl PackedConnHandle {
    #[must_use]
    pub fn new(packed: PackedConn) -> Self {
        let conn = Arc::new(Mutex::new(packed));
        let close_view = PackedConnCloseView(Arc::clone(&conn));
        Self { conn, close_view }
    }

    pub async fn flush(&self) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            let mut guard = self.conn.lock();
            Pin::new(&mut *guard).poll_flush(cx)
        })
        .await
    }
}

impl AsyncWrite for PackedConnHandle {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut guard = self.conn.lock();
        Pin::new(&mut *guard).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.conn.lock();
        Pin::new(&mut *guard).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.conn.lock();
        Pin::new(&mut *guard).poll_shutdown(cx)
    }
}

impl AsyncRead for PackedConnHandle {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.conn.lock();
        Pin::new(&mut *guard).poll_read(cx, buf)
    }
}

impl NetConn for PackedConnHandle {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.lock().local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.lock().peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.lock().close_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.lock().close_write()
    }

    /// A full close (unlike the half-closes above) must reach whatever real inner conn the
    /// wrapped `PackedConn` itself answers `old_conn` with; a `MutexGuard` can't be returned as a
    /// `&'self` reference, so this goes through a view holding its own clone of the same `Arc`
    /// instead (see [`PackedConnCloseView`]), matching `handshake::SudokuConnHandle`'s twin.
    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        Some(&self.close_view)
    }
}

/// See [`PackedConnHandle::old_conn`].
#[derive(Debug, Clone)]
struct PackedConnCloseView(Arc<Mutex<PackedConn>>);

/// Never actually polled — reached only through [`NetConn::old_conn`] — but
/// [`murmur_std_compat::net::Conn`] requires `AsyncRead + AsyncWrite`, so this forwards to the same
/// mutex-guarded conn `PackedConnHandle` itself reads and writes through.
impl AsyncRead for PackedConnCloseView {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.get_mut().0.lock();
        Pin::new(&mut *guard).poll_read(cx, buf)
    }
}
impl AsyncWrite for PackedConnCloseView {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut guard = self.get_mut().0.lock();
        Pin::new(&mut *guard).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.get_mut().0.lock();
        Pin::new(&mut *guard).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.get_mut().0.lock();
        Pin::new(&mut *guard).poll_shutdown(cx)
    }
}
impl murmur_std_compat::net::Conn for PackedConnCloseView {
    fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        Ok(Box::new(murmur_std_compat::net::TcpAddr::from(self.0.lock().local_addr()?)))
    }
    fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        Ok(Box::new(murmur_std_compat::net::TcpAddr::from(self.0.lock().peer_addr()?)))
    }
    fn close(&self) -> io::Result<()> {
        close_stream(&*self.0.lock())
    }
    fn close_read(&self) -> io::Result<()> {
        self.0.lock().shutdown_read()
    }
    fn close_write(&self) -> io::Result<()> {
        self.0.lock().shutdown_write()
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use parking_lot::Mutex;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    use murmur_common_net::io::Stream as NetConn;

    use super::super::rand::new_sudoku_rand;
    use super::super::table::new_table;
    use super::new_packed_conn;

    #[derive(Default)]
    struct MockConn {
        read_buf: Arc<Mutex<Vec<u8>>>,
        write_buf: Arc<Mutex<Vec<u8>>>,
    }

    impl MockConn {
        fn with_read(read_buf: Vec<u8>) -> Self {
            Self { read_buf: Arc::new(Mutex::new(read_buf)), write_buf: Arc::new(Mutex::new(Vec::new())) }
        }
    }

    impl AsyncRead for MockConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let mut read_buf = this.read_buf.lock();
            if read_buf.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = buf.remaining().min(read_buf.len());
            buf.put_slice(&read_buf[..n]);
            read_buf.drain(..n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.get_mut().write_buf.lock().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl NetConn for MockConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }

        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    #[tokio::test]
    async fn test_packed_conn_protected_prefix_padding() {
        let table = new_table("packed-prefix-seed", "prefer_ascii");
        let mock = MockConn::default();
        let write_buf = Arc::clone(&mock.write_buf);
        let mut writer = new_packed_conn(Box::new(mock), Some(Arc::clone(&table)), 0, 0);
        writer.rng = new_sudoku_rand(1);

        let payload = vec![0u8; 32];
        writer.write_all(&payload).await.expect("write");

        let wire = write_buf.lock().clone();
        assert!(wire.len() >= 20, "wire too short: {}", wire.len());

        let mut first_hint: i32 = -1;
        let mut non_hint_count = 0;
        let mut max_hint_run = 0;
        let mut current_hint_run = 0;
        for (i, &b) in wire[..20].iter().enumerate() {
            if table.layout.as_deref().is_some_and(|layout| layout.is_hint(b)) {
                if first_hint == -1 {
                    first_hint = i as i32;
                }
                current_hint_run += 1;
                if current_hint_run > max_hint_run {
                    max_hint_run = current_hint_run;
                }
                continue;
            }
            non_hint_count += 1;
            current_hint_run = 0;
        }

        assert!((1..=2).contains(&first_hint), "expected 1-2 leading padding bytes, first hint index={first_hint}");
        assert!(
            non_hint_count >= 6,
            "expected dense prefix padding, got only {non_hint_count} non-hint bytes in first 20"
        );
        assert!(max_hint_run <= 3, "prefix still exposes long hint run: {max_hint_run}");

        let mut reader = new_packed_conn(Box::new(MockConn::with_read(wire)), Some(Arc::clone(&table)), 0, 0);
        let mut decoded = vec![0u8; payload.len()];
        reader.read_exact(&mut decoded).await.expect("read back");
        assert_eq!(decoded, payload, "roundtrip mismatch");
    }
}

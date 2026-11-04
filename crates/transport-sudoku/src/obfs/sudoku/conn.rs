use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common_net::io::Stream as NetConn;

use super::encode::encode_sudoku_payload;
use super::padding_prob::pick_padding_threshold;
use super::pending::{append_decoded_byte, drain_pending, new_pending_buffer, PendingBuffer};
use super::rand::{new_seeded_rand, SudokuRand};
use super::table::{pack_hint_bytes, SudokuError, Table};

pub const IO_BUFFER_SIZE: usize = 32 * 1024;

pub(crate) const MIN_DECODE_READ_SIZE: usize = 64;

pub(crate) static PERM4: [[u8; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

pub(crate) fn err_closed_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")
}

pub(crate) fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

pub(crate) fn map_miss() -> io::Error {
    io::Error::other(SudokuError::InvalidSudokuMapMiss)
}

/// Minimal buffered reader: a fixed-size buffer with `Buffered`/`Peek`/`Read`.
#[derive(Debug)]
pub(crate) struct BufReaderState {
    buf: Vec<u8>,
    r: usize,
    w: usize,
}

impl BufReaderState {
    pub(crate) fn new(size: usize) -> Self {
        Self { buf: vec![0u8; size], r: 0, w: 0 }
    }

    pub(crate) const fn buffered(&self) -> usize {
        self.w - self.r
    }

    const fn buf_len(&self) -> usize {
        self.buf.len()
    }

    fn unfilled_buf(&mut self) -> &mut [u8] {
        self.r = 0;
        self.w = 0;
        &mut self.buf
    }

    const fn set_written(&mut self, n: usize) {
        self.w = n;
    }

    fn take_buffered(&mut self, dst: &mut [u8]) -> usize {
        let n = dst.len().min(self.buffered());
        let (Some(head), Some(src)) = (dst.get_mut(..n), self.buf.get(self.r..self.r + n)) else {
            return 0;
        };
        head.copy_from_slice(src);
        self.r += n;
        if self.r == self.w {
            self.r = 0;
            self.w = 0;
        }
        n
    }

    pub(crate) fn peek(&self, n: usize) -> &[u8] {
        let end = (self.r + n).min(self.w);
        self.buf.get(self.r..end).unwrap_or_default()
    }
}

/// Encodes into the write buffer and hands the whole buffer to a single write;
/// a resumable `poll_write` needs the offset that already left.
#[derive(Debug, Default)]
pub(crate) struct WriteDrain {
    buf: Vec<u8>,
    from: usize,
    result: usize,
}

impl WriteDrain {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self { buf: Vec::with_capacity(capacity), from: 0, result: 0 }
    }

    pub(crate) const fn idle(&self) -> bool {
        self.result == 0
    }

    pub(crate) fn take_buf(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    pub(crate) fn put_buf(&mut self, buf: Vec<u8>) {
        self.buf = buf;
    }

    pub(crate) const fn start(&mut self, result: usize) {
        self.from = 0;
        self.result = result;
    }

    const fn reset(&mut self) {
        self.from = 0;
        self.result = 0;
    }

    pub(crate) fn poll_drain<W>(&mut self, cx: &mut Context<'_>, conn: &mut W) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        loop {
            let pending = self.buf.get(self.from..).unwrap_or_default();
            if pending.is_empty() {
                let n = self.result;
                self.reset();
                return Poll::Ready(Ok(n));
            }
            match Pin::new(&mut *conn).poll_write(cx, pending) {
                Poll::Ready(Ok(0)) => {
                    self.reset();
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write whole buffer")));
                }
                Poll::Ready(Ok(n)) => self.from += n,
                Poll::Ready(Err(err)) => {
                    self.reset();
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Reads raw, limited: serve from the buffered reader when it holds data, read
/// straight into large destinations, otherwise refill the internal buffer.
pub(crate) fn poll_read_limited(
    cx: &mut Context<'_>,
    conn: Option<&mut Box<dyn NetConn>>,
    reader: &mut BufReaderState,
    dst: &mut [u8],
) -> Poll<io::Result<usize>> {
    if dst.is_empty() {
        return Poll::Ready(Ok(0));
    }
    if reader.buffered() > 0 {
        return Poll::Ready(Ok(reader.take_buffered(dst)));
    }
    let Some(conn) = conn else {
        return Poll::Ready(Err(err_closed_pipe()));
    };
    if dst.len() >= reader.buf_len() {
        let mut rb = ReadBuf::new(dst);
        return match Pin::new(&mut **conn).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        };
    }

    let filled = {
        let mut rb = ReadBuf::new(reader.unfilled_buf());
        match Pin::new(&mut **conn).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => rb.filled().len(),
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    };
    reader.set_written(filled);
    if filled == 0 {
        return Poll::Ready(Ok(0));
    }
    Poll::Ready(Ok(reader.take_buffered(dst)))
}

pub struct Conn {
    inner: Option<Box<dyn NetConn>>,
    table: Option<Arc<Table>>,
    reader: BufReaderState,
    recorder: Option<Vec<u8>>,
    recording: bool,

    raw_buf: Vec<u8>,
    pending_data: PendingBuffer,
    hint_buf: [u8; 4],
    hint_count: usize,
    write_drain: WriteDrain,

    rng: Option<SudokuRand>,
    padding_threshold: u64,
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn")
            .field("table", &self.table.as_ref().map(|table| table.hint()))
            .field("recording", &self.recording)
            .field("hint_count", &self.hint_count)
            .field("padding_threshold", &self.padding_threshold)
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn new_conn(c: Box<dyn NetConn>, table: Option<Arc<Table>>, p_min: i32, p_max: i32, record: bool) -> Conn {
    let mut local_rng = new_seeded_rand();
    let padding_threshold = pick_padding_threshold(Some(&mut local_rng), p_min, p_max);

    let mut sc = Conn {
        inner: Some(c),
        table,
        reader: BufReaderState::new(IO_BUFFER_SIZE),
        recorder: None,
        recording: false,
        raw_buf: vec![0u8; IO_BUFFER_SIZE],
        pending_data: new_pending_buffer(4096),
        hint_buf: [0u8; 4],
        hint_count: 0,
        write_drain: WriteDrain::with_capacity(4096),
        rng: Some(local_rng),
        padding_threshold,
    };
    if record {
        sc.recorder = Some(Vec::new());
        sc.recording = true;
    }
    sc
}

impl Conn {
    fn layout_missing(&self) -> bool {
        self.table.as_ref().is_none_or(|table| table.layout.is_none())
    }

    pub fn close_write(&self) -> io::Result<()> {
        match self.inner.as_ref() {
            Some(conn) => conn.shutdown_write(),
            None => Ok(()),
        }
    }

    pub fn close_read(&self) -> io::Result<()> {
        match self.inner.as_ref() {
            Some(conn) => conn.shutdown_read(),
            None => Ok(()),
        }
    }

    pub fn stop_recording(&mut self) {
        self.recording = false;
        self.recorder = None;
    }

    pub fn get_buffered_and_recorded(&mut self) -> Vec<u8> {
        let mut recorded = match self.recorder.as_ref() {
            Some(recorder) => recorder.clone(),
            None => Vec::new(),
        };

        let buffered = self.reader.buffered();
        if buffered > 0 {
            let peeked = self.reader.peek(buffered);
            recorded.extend_from_slice(peeked);
        }
        recorded
    }
}

impl NetConn for Conn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self.inner.as_ref() {
            Some(conn) => conn.local_addr(),
            None => Err(err_closed_pipe()),
        }
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self.inner.as_ref() {
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
        self.inner.as_ref().and_then(|c| c.old_conn())
    }
}

impl AsyncWrite for Conn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.inner.is_none() || this.layout_missing() || this.rng.is_none() {
            return Poll::Ready(Err(err_closed_pipe()));
        }

        if this.write_drain.idle() {
            let Some(table) = this.table.clone() else {
                return Poll::Ready(Err(err_closed_pipe()));
            };
            let Some(rng) = this.rng.as_mut() else {
                return Poll::Ready(Err(err_closed_pipe()));
            };
            let threshold = this.padding_threshold;
            let mut out = this.write_drain.take_buf();
            encode_sudoku_payload(&mut out, &table, rng, threshold, buf);
            this.write_drain.put_buf(out);
            this.write_drain.start(buf.len());
        }

        let Some(conn) = this.inner.as_mut() else {
            return Poll::Ready(Err(err_closed_pipe()));
        };
        this.write_drain.poll_drain(cx, &mut **conn)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.inner.as_mut() {
            Some(conn) => Pin::new(&mut **conn).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.close_write())
    }
}

impl AsyncRead for Conn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.inner.is_none() || this.raw_buf.is_empty() || this.layout_missing() {
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
            let want = sudoku_read_size(buf.remaining(), this.raw_buf.len()).min(this.raw_buf.len());
            let read = {
                let Some(dst) = this.raw_buf.get_mut(..want) else {
                    return Poll::Ready(Err(err_closed_pipe()));
                };
                poll_read_limited(cx, this.inner.as_mut(), &mut this.reader, dst)
            };
            let (nr, r_err) = match read {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => (0, Some(eof())),
                Poll::Ready(Ok(n)) => (n, None),
                Poll::Ready(Err(err)) => (0, Some(err)),
            };

            let mut out_n = 0usize;
            if nr > 0 {
                let Some(chunk) = this.raw_buf.get(..nr) else {
                    return Poll::Ready(Err(err_closed_pipe()));
                };
                if this.recording {
                    if let Some(recorder) = this.recorder.as_mut() {
                        recorder.extend_from_slice(chunk);
                    }
                }

                match decode_chunk(
                    chunk,
                    &layout.hint_table,
                    &table,
                    &mut this.hint_buf,
                    &mut this.hint_count,
                    &mut this.pending_data,
                    buf.initialize_unfilled(),
                ) {
                    Ok(n) => out_n = n,
                    Err(err) => return Poll::Ready(Err(err)),
                }
                buf.advance(out_n);
            }

            if let Some(err) = r_err {
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

/// Decodes one raw chunk into `target`, carrying the pending hint group across calls.
/// A hint group the table cannot decode is reported as an error.
fn decode_chunk(
    chunk: &[u8],
    hint_table: &[bool; 256],
    table: &Table,
    hint_buf: &mut [u8; 4],
    hint_count: &mut usize,
    pending: &mut PendingBuffer,
    target: &mut [u8],
) -> io::Result<usize> {
    let is_hint = |b: u8| hint_table.get(usize::from(b)).copied().unwrap_or(false);
    let mut out_n = 0usize;
    let mut rest = chunk;
    while !rest.is_empty() {
        let fast = *hint_count == 0 && out_n < target.len();
        if fast {
            if let [a, b, c, d, tail @ ..] = rest {
                if is_hint(*a) && is_hint(*b) && is_hint(*c) && is_hint(*d) {
                    let key = pack_hint_bytes(*a, *b, *c, *d);
                    let Some(value) = table.decode_map.get(&key) else {
                        return Err(map_miss());
                    };
                    let Some(slot) = target.get_mut(out_n) else {
                        break;
                    };
                    *slot = *value;
                    out_n += 1;
                    rest = tail;
                    continue;
                }
            }
        }

        let Some((&b, tail)) = rest.split_first() else {
            break;
        };
        rest = tail;
        if !is_hint(b) {
            continue;
        }

        let Some(slot) = hint_buf.get_mut(*hint_count) else {
            break;
        };
        *slot = b;
        *hint_count += 1;
        if *hint_count != hint_buf.len() {
            continue;
        }

        let key = pack_hint_bytes(hint_buf[0], hint_buf[1], hint_buf[2], hint_buf[3]);
        let Some(value) = table.decode_map.get(&key) else {
            *hint_count = 0;
            return Err(map_miss());
        };
        out_n = append_decoded_byte(target, out_n, pending, *value);
        *hint_count = 0;
    }
    Ok(out_n)
}

const fn sudoku_read_size(decoded_remaining: usize, max_raw: usize) -> usize {
    if max_raw <= MIN_DECODE_READ_SIZE || decoded_remaining == 0 {
        return max_raw;
    }
    if decoded_remaining > (max_raw - MIN_DECODE_READ_SIZE) / 9 {
        return max_raw;
    }

    decoded_remaining * 9 + MIN_DECODE_READ_SIZE
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

    use murmur_common_net::io::Stream as NetConn;

    use super::super::table::{new_table, pack_hint_bytes};
    use super::new_conn;

    struct ChunkedConn {
        chunks: VecDeque<Vec<u8>>,
    }

    impl AsyncRead for ChunkedConn {
        fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let Some(chunk) = self.chunks.front_mut() else {
                return Poll::Ready(Ok(()));
            };
            if chunk.is_empty() {
                self.chunks.pop_front();
                return self.poll_read(_cx, buf);
            }
            let n = buf.remaining().min(chunk.len());
            buf.put_slice(&chunk[..n]);
            chunk.drain(..n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ChunkedConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl NetConn for ChunkedConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    #[tokio::test]
    async fn test_conn_map_miss_resets_hint_group() {
        let table = new_table("map-miss-seed", "prefer_ascii");
        let layout = table.layout.as_deref().expect("layout");
        let hints: Vec<u8> = (0u16..=255).map(|b| b as u8).filter(|b| layout.is_hint(*b)).take(8).collect();

        let bad: [u8; 4] = hints
            .iter()
            .flat_map(|a| hints.iter().map(move |b| [*a, *b]))
            .flat_map(|[a, b]| hints.iter().map(move |c| [a, b, *c]))
            .flat_map(|[a, b, c]| hints.iter().map(move |d| [a, b, c, *d]))
            .find(|quad| !table.decode_map.contains_key(&pack_hint_bytes(quad[0], quad[1], quad[2], quad[3])))
            .expect("layout must leave some hint quad undecodable");

        let chunks: VecDeque<Vec<u8>> = bad.iter().map(|b| vec![*b]).collect();
        let mut conn = new_conn(Box::new(ChunkedConn { chunks }), Some(Arc::clone(&table)), 0, 0, false);

        let mut buf = [0u8; 1];
        assert!(conn.read(&mut buf).await.is_err(), "undecodable hint quad must surface as a read error");
        assert_eq!(conn.hint_count, 0, "a map miss must not leave a half-filled hint group behind");
        assert_eq!(
            conn.read(&mut buf).await.unwrap_or(0),
            0,
            "the conn must end cleanly, not resume a stale hint group"
        );
    }
}

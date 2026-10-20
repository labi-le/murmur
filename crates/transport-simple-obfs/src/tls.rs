use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use rand::Rng as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common_net::io::{OldConnAsStream, Stream, StreamAsOldConn};
use murmur_common_pool as pool;
use murmur_ntp as ntp;
use murmur_std_compat::net::Conn;

/// The chunk size, 16 KiB.
pub(super) const CHUNK_SIZE: usize = 1 << 14;

/// `Ok(false)` is a clean end of stream; a partial read is an unexpected EOF.
pub(super) fn poll_read_full(
    conn: &mut dyn Stream,
    cx: &mut Context<'_>,
    dst: &mut [u8],
    filled: &mut usize,
) -> Poll<io::Result<bool>> {
    while *filled < dst.len() {
        let mut read_buf = ReadBuf::new(dst.get_mut(*filled..).unwrap_or_default());
        ready!(Pin::new(&mut *conn).poll_read(cx, &mut read_buf))?;
        let n = read_buf.filled().len();
        if n == 0 {
            if *filled == 0 {
                return Poll::Ready(Ok(false));
            }
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        *filled += n;
    }
    Poll::Ready(Ok(true))
}

/// One conn read call; `Ok(0)` means end of stream.
pub(super) fn poll_read_some(conn: &mut dyn Stream, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
    let mut read_buf = ReadBuf::new(buf);
    ready!(Pin::new(&mut *conn).poll_read(cx, &mut read_buf))?;
    Poll::Ready(Ok(read_buf.filled().len()))
}

/// The write framing: `0x17 0x03 0x03`, the big-endian length, then the payload.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the record length field is 16 bits by definition, so a longer payload wraps"
)]
pub(super) fn frame_record(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + b.len());
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
    out
}

/// The remaining-bytes update the branches apply once a read operation finishes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum RemainAdjust {
    /// Set to `length - n`, for the oversize-request branch.
    Set(i64),
    /// Decremented by `n`, for the remaining-bytes branch.
    Sub(i64),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TlsReadStep {
    Discard,
    Size,
    Short,
    Full,
}

/// Drives a framed read and the remaining-bytes branch across `poll_read` calls, holding
/// per-call scratch buffers. A completing branch truncates `data` and moves the allocation to
/// the caller; only an incomplete branch keeps it for the next poll.
pub(super) struct TlsReadOp {
    step: TlsReadStep,
    discard_n: usize,
    discard: Vec<u8>,
    discard_filled: usize,
    size: [u8; 2],
    size_filled: usize,
    caller_remaining: usize,
    length: usize,
    data: Vec<u8>,
    data_filled: usize,
    from_remain: bool,
    remain_adjust: Option<RemainAdjust>,
}

impl TlsReadOp {
    /// The remaining-bytes branch: reads exactly `length` bytes.
    pub(super) fn remain(length: usize, caller_remaining: usize) -> Self {
        Self { step: TlsReadStep::Full, length, from_remain: true, ..Self::framed(0, caller_remaining) }
    }

    /// Builds a framed read that discards `discard_n` bytes and hands the rest to the caller.
    pub(super) const fn framed(discard_n: usize, caller_remaining: usize) -> Self {
        Self {
            step: TlsReadStep::Discard,
            discard_n,
            discard: Vec::new(),
            discard_filled: 0,
            size: [0; 2],
            size_filled: 0,
            caller_remaining,
            length: 0,
            data: Vec::new(),
            data_filled: 0,
            from_remain: false,
            remain_adjust: None,
        }
    }

    /// The bytes to hand back, or an empty vector when the caller only sees the error or a clean
    /// end of stream.
    pub(super) fn poll(&mut self, conn: &mut dyn Stream, cx: &mut Context<'_>) -> Poll<io::Result<Vec<u8>>> {
        loop {
            match self.step {
                TlsReadStep::Discard => {
                    if self.discard.is_empty() {
                        self.discard = pool::get(self.discard_n);
                    }
                    let outcome = match poll_read_full(conn, cx, &mut self.discard, &mut self.discard_filled) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(full)) => Ok(full),
                        Poll::Ready(Err(err)) => Err(err),
                    };
                    // The buffer goes back to the pool before the outcome is inspected.
                    let discard = std::mem::take(&mut self.discard);
                    pool::put(discard).ok();
                    match outcome {
                        Ok(false) => return Poll::Ready(Ok(Vec::new())),
                        Ok(true) => self.step = TlsReadStep::Size,
                        Err(err) => return Poll::Ready(Err(err)),
                    }
                }
                TlsReadStep::Size => match poll_read_full(conn, cx, &mut self.size, &mut self.size_filled) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(false) | Err(_)) => return Poll::Ready(Ok(Vec::new())),
                    Poll::Ready(Ok(true)) => {
                        self.length = usize::from(u16::from_be_bytes(self.size));
                        self.step =
                            if self.length > self.caller_remaining { TlsReadStep::Short } else { TlsReadStep::Full };
                    }
                },
                TlsReadStep::Short => {
                    if self.data.is_empty() && self.caller_remaining > 0 {
                        self.data = vec![0u8; self.caller_remaining];
                    }
                    match poll_read_some(conn, cx, &mut self.data) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(n)) => {
                            let length = i64::try_from(self.length).unwrap_or(i64::MAX);
                            let read = i64::try_from(n).unwrap_or(i64::MAX);
                            self.remain_adjust = Some(RemainAdjust::Set(length - read));
                            // The op is cleared once this returns, so move the completed allocation
                            // out instead of copying its `n`-byte prefix into a second one.
                            self.data.truncate(n);
                            return Poll::Ready(Ok(std::mem::take(&mut self.data)));
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    }
                }
                TlsReadStep::Full => {
                    if self.data.is_empty() && self.length > 0 {
                        self.data = vec![0u8; self.length];
                    }
                    match poll_read_full(conn, cx, &mut self.data, &mut self.data_filled) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(false)) if self.data_filled == 0 => return Poll::Ready(Ok(Vec::new())),
                        Poll::Ready(Err(err)) if self.data_filled == 0 => return Poll::Ready(Err(err)),
                        Poll::Ready(Ok(_) | Err(_)) => {}
                    }
                    let filled = self.data_filled;
                    if self.from_remain {
                        self.remain_adjust = Some(RemainAdjust::Sub(i64::try_from(filled).unwrap_or(i64::MAX)));
                    }
                    // Partial success (an error after `filled` bytes) takes this path too: the
                    // bytes already read are handed back exactly as before, without copying them.
                    self.data.truncate(filled);
                    return Poll::Ready(Ok(std::mem::take(&mut self.data)));
                }
            }
        }
    }

    pub(super) const fn remain_adjust(&self) -> Option<RemainAdjust> {
        self.remain_adjust
    }
}

/// The TLS simple-obfs client.
pub struct TLSObfs {
    conn: Box<dyn Stream>,
    server: String,
    remain: i64,
    first_request: bool,
    first_response: bool,
    read_op: Option<TlsReadOp>,
    write_op: Option<TlsWriteOp>,
    /// Record bytes that did not fit the reading caller's buffer, served before the next conn read.
    leftover: Option<Vec<u8>>,
    leftover_offset: usize,
}

impl core::fmt::Debug for TLSObfs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TLSObfs")
            .field("server", &self.server)
            .field("remain", &self.remain)
            .field("first_request", &self.first_request)
            .field("first_response", &self.first_response)
            .finish_non_exhaustive()
    }
}

pub(super) struct TlsWriteOp {
    /// The index within the current chunk.
    offset: usize,
    pending: Vec<u8>,
    pending_written: usize,
}

impl TlsWriteOp {
    pub(super) const fn new() -> Self {
        Self { offset: 0, pending: Vec::new(), pending_written: 0 }
    }

    /// The chunked-write loop; `make_chunk` frames one chunk.
    pub(super) fn poll<F>(
        &mut self,
        conn: &mut dyn Stream,
        cx: &mut Context<'_>,
        buf: &[u8],
        mut make_chunk: F,
    ) -> Poll<io::Result<usize>>
    where
        F: FnMut(&[u8]) -> Vec<u8>,
    {
        if self.pending.is_empty() {
            let end = std::cmp::min(CHUNK_SIZE, buf.len());
            self.pending = make_chunk(buf.get(..end).unwrap_or_default());
            self.offset = end;
        }
        loop {
            if self.pending_written >= self.pending.len() {
                if self.offset >= buf.len() {
                    return Poll::Ready(Ok(self.offset));
                }
                let end = std::cmp::min(self.offset + CHUNK_SIZE, buf.len());
                self.pending = make_chunk(buf.get(self.offset..end).unwrap_or_default());
                self.pending_written = 0;
                self.offset = end;
                continue;
            }
            let chunk = self.pending.get(self.pending_written..).unwrap_or_default();
            match Pin::new(&mut *conn).poll_write(cx, chunk) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => self.pending_written += n,
            }
        }
    }
}

impl AsyncRead for TLSObfs {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if let Some(cached) = this.leftover.take() {
            let n = std::cmp::min(buf.remaining(), cached.len() - this.leftover_offset);
            buf.put_slice(cached.get(this.leftover_offset..this.leftover_offset + n).unwrap_or_default());
            this.leftover_offset += n;
            if this.leftover_offset < cached.len() {
                this.leftover = Some(cached);
            } else {
                this.leftover_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }

        if this.remain > 0 {
            let length = std::cmp::min(usize::try_from(this.remain).unwrap_or(usize::MAX), buf.remaining());
            if this.read_op.is_none() {
                this.read_op = Some(TlsReadOp::remain(length, buf.remaining()));
            }
            return this.poll_op_read(cx, buf);
        }

        if this.first_response {
            // type + ver + lensize + 91 = 96
            // type + ver + lensize + 1 = 6
            // type + ver = 3
            this.first_response = false;
            if this.read_op.is_none() {
                this.read_op = Some(TlsReadOp::framed(105, buf.remaining()));
            }
            return this.poll_op_read(cx, buf);
        }

        // type + ver = 3
        if this.read_op.is_none() {
            this.read_op = Some(TlsReadOp::framed(3, buf.remaining()));
        }
        this.poll_op_read(cx, buf)
    }
}

impl TLSObfs {
    fn poll_op_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let Some(op) = self.read_op.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let data = match op.poll(&mut *self.conn, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(data)) => data,
            Poll::Ready(Err(err)) => {
                self.read_op = None;
                return Poll::Ready(Err(err));
            }
        };
        match op.remain_adjust() {
            Some(RemainAdjust::Set(remain)) => self.remain = remain,
            Some(RemainAdjust::Sub(n)) => self.remain -= n,
            None => {}
        }
        self.read_op = None;
        let fit = std::cmp::min(data.len(), buf.remaining());
        buf.put_slice(data.get(..fit).unwrap_or_default());
        if fit < data.len() {
            self.leftover = Some(data);
            self.leftover_offset = fit;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TLSObfs {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.write_op.is_none() && buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut first_request = this.first_request;
        let server = &this.server;
        let op = this.write_op.get_or_insert_with(TlsWriteOp::new);
        let result = op.poll(&mut *this.conn, cx, buf, |chunk| {
            if first_request {
                first_request = false;
                make_client_hello_msg(chunk, server)
            } else {
                frame_record(chunk)
            }
        });
        this.first_request = first_request;
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(written)) => {
                this.write_op = None;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(err)) => {
                this.write_op = None;
                Poll::Ready(Err(err))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_shutdown(cx)
    }
}

impl Stream for TLSObfs {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
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

    fn old_conn(&self) -> Option<&dyn Conn> {
        self.conn.old_conn()
    }
}

/// Creates a TLS simple-obfs client.
#[must_use]
pub fn new_tls_obfs(conn: Box<dyn Conn>, server: String) -> Box<dyn Conn> {
    let conn: Box<dyn Stream> = Box::new(OldConnAsStream(conn));
    Box::new(StreamAsOldConn::new(TLSObfs {
        conn,
        server,
        remain: 0,
        first_request: true,
        first_response: true,
        read_op: None,
        write_op: None,
        leftover: None,
        leftover_offset: 0,
    }))
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "every length and version field of the hello is 16 or 32 bits by definition, so the low bits are the wire value"
)]
fn make_client_hello_msg(data: &[u8], server: &str) -> Vec<u8> {
    let mut random = vec![0u8; 28];
    let mut session_id = vec![0u8; 32];
    rand::rng().fill(&mut random[..]);
    rand::rng().fill(&mut session_id[..]);

    let mut buf = Vec::with_capacity(256 + data.len() + server.len());

    // handshake, TLS 1.0 version, length
    buf.push(22);
    buf.extend_from_slice(&[0x03, 0x01]);
    let length = (212 + data.len() + server.len()) as u16;
    buf.push((length >> 8) as u8);
    buf.push((length & 0xff) as u8);

    // clientHello, length, TLS 1.2 version
    buf.push(1);
    buf.push(0);
    buf.extend_from_slice(&((208 + data.len() + server.len()) as u16).to_be_bytes());
    buf.extend_from_slice(&[0x03, 0x03]);

    // random with timestamp, sid len, sid
    buf.extend_from_slice(&(ntp::time::now().timestamp() as u32).to_be_bytes());
    buf.extend_from_slice(&random);
    buf.push(32);
    buf.extend_from_slice(&session_id);

    // cipher suites
    buf.extend_from_slice(&[0x00, 0x38]);
    buf.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
        0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39,
        0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f,
        0x00, 0xff,
    ]);

    // compression
    buf.extend_from_slice(&[0x01, 0x00]);

    // extension length
    buf.extend_from_slice(&((79 + data.len() + server.len()) as u16).to_be_bytes());

    // session ticket
    buf.extend_from_slice(&[0x00, 0x23]);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);

    // server name
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&((server.len() + 5) as u16).to_be_bytes());
    buf.extend_from_slice(&((server.len() + 3) as u16).to_be_bytes());
    buf.push(0);
    buf.extend_from_slice(&(server.len() as u16).to_be_bytes());
    buf.extend_from_slice(server.as_bytes());

    // ec_point
    buf.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);

    // groups
    buf.extend_from_slice(&[0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18]);

    // signature
    buf.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03,
        0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);

    // encrypt then mac
    buf.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);

    // extended master secret
    buf.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    buf
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    /// The client-hello generator has no injectable randomness source: the 4-byte timestamp, the
    /// 28-byte client random and the 32-byte session id come from the RNG, so they cannot be
    /// pinned to fixed values. Everything else in the record is a pure function of `data` and
    /// `server`'s lengths, at the offsets asserted below.
    #[test]
    fn make_client_hello_msg_layout_outside_random_fields() {
        let data = b"hi";
        let server = "example.com";
        let msg = make_client_hello_msg(data, server);

        assert_eq!(msg.len(), 230);
        assert_eq!(&msg[0..11], &[0x16, 0x03, 0x01, 0x00, 0xe1, 0x01, 0x00, 0x00, 0xdd, 0x03, 0x03]);
        assert_eq!(msg[43], 32);

        assert_eq!(&msg[76..78], &[0x00, 0x38]);
        assert_eq!(
            &msg[78..134],
            &[
                0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00,
                0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14,
                0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00,
                0x35, 0x00, 0x2f, 0x00, 0xff,
            ]
        );
        assert_eq!(&msg[134..138], &[0x01, 0x00, 0x00, 0x5c]);
        assert_eq!(&msg[138..144], &[0x00, 0x23, 0x00, 0x02, b'h', b'i']);
        assert_eq!(
            &msg[144..164],
            &[
                0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
                b'c', b'o', b'm'
            ]
        );
        assert_eq!(
            &msg[164..230],
            &[
                0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00,
                0x17, 0x00, 0x19, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03,
                0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03,
                0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
            ]
        );
    }

    struct FlagConn {
        inner: tokio::io::DuplexStream,
        closes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
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
    impl Conn for FlagConn {
        fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
            Ok(Box::new(murmur_std_compat::net::TcpAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
            Ok(Box::new(murmur_std_compat::net::TcpAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn close(&self) -> io::Result<()> {
            self.closes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// An error after part of a record arrived still hands those bytes back; the move of the
    /// completed buffer must not turn the partial success into an error or an empty read.
    #[tokio::test]
    async fn a_partial_record_before_eof_returns_the_bytes_already_read() {
        let (client_side, server_side) = tokio::io::duplex(1 << 16);
        let mut peer = client_side;
        let closes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flag = FlagConn { inner: server_side, closes };
        let mut obfs = new_tls_obfs(Box::new(flag), "example.com".to_owned());

        peer.write_all(&[0u8; 105]).await.expect("write discard filler");
        peer.write_all(&[0x00, 0x04]).await.expect("write record length");
        peer.write_all(b"ab").await.expect("write partial payload");
        peer.shutdown().await.expect("close the payload writer");

        let mut buf = [0u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(5), obfs.read(&mut buf))
            .await
            .expect("partial read must not hang")
            .expect("partial read returns the bytes already read");
        assert_eq!(&buf[..read], b"ab");

        let read = tokio::time::timeout(Duration::from_secs(5), obfs.read(&mut buf))
            .await
            .expect("the follow-up read must not hang")
            .expect("clean end of stream after the partial record");
        assert_eq!(read, 0);
    }

    /// Bug #112: the parked read op kept the first poll's buffer size, and the completion truncated
    /// the record to whatever the resuming poll's buffer held, dropping the tail while still
    /// accounting it as delivered.
    #[tokio::test]
    async fn a_resumed_read_serves_the_whole_record_to_a_smaller_buffer() {
        let (client_side, server_side) = tokio::io::duplex(1 << 16);
        let mut peer = client_side;
        let closes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flag = FlagConn { inner: server_side, closes };
        let mut obfs = new_tls_obfs(Box::new(flag), "example.com".to_owned());

        peer.write_all(&[0u8; 105]).await.expect("write discard filler");
        peer.write_all(&[0x00, 0x04]).await.expect("write record length");

        let mut big = [0u8; 4096];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), obfs.read(&mut big)).await.is_err(),
            "the read must stay pending until the record payload arrives"
        );

        peer.write_all(b"abcd").await.expect("write payload");

        let mut one = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), obfs.read(&mut one))
            .await
            .expect("read must not hang")
            .expect("read one byte");
        assert_eq!(&one, b"a");

        let mut rest = [0u8; 4096];
        let read = tokio::time::timeout(Duration::from_secs(5), obfs.read(&mut rest))
            .await
            .expect("a resumed read must not hang on bytes the record already carried")
            .expect("read the tail");
        assert_eq!(&rest[..read], b"bcd");
    }

    /// Regression for `agent://ReviewS9Obfs`'s finding: `close()` through
    /// `StreamAsOldConn(TLSObfs{conn: OldConnAsStream(inner)})` used to reach only
    /// `shutdown_read`/`shutdown_write`, never the dialed conn's own `close()`.
    #[tokio::test]
    async fn close_reaches_the_dialed_conn() {
        let (_client, server) = tokio::io::duplex(64);
        let closes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flag = FlagConn { inner: server, closes: std::sync::Arc::clone(&closes) };
        let obfs = new_tls_obfs(Box::new(flag), "example.com".to_owned());
        obfs.close().expect("close");
        assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use byteorder::{BigEndian, ByteOrder};
use hmac::{HmacReset, KeyInit as _, Mac as _};
use parking_lot::Mutex;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{old_addr_to_socket_addr, ExtendedStream, Stream as NetStream};
use murmur_log::debugln;
use murmur_std_compat::net::Conn as NetConn;

use super::protocol::{read_frame, APPLICATION_DATA, MAX_TLS_PLAINTEXT, TLS_HEADER_SIZE};

pub(crate) type HmacSha1 = HmacReset<Sha1>;

#[expect(clippy::expect_used, reason = "HMAC accepts keys of any length, so `new_from_slice` is infallible here")]
pub(crate) fn new_hmac_sha1(password: &str) -> HmacSha1 {
    HmacSha1::new_from_slice(password.as_bytes()).expect("HMAC accepts keys of any length")
}

fn hmac_sum8(mac: &HmacSha1) -> Vec<u8> {
    mac.clone().finalize().into_bytes().iter().take(8).copied().collect()
}

#[derive(Clone)]
pub(crate) struct HashReadConn {
    conn: SharedConn,
    hmac: Arc<Mutex<HmacSha1>>,
}

impl HashReadConn {
    pub(crate) fn new(conn: Box<dyn NetConn>, password: &str) -> Self {
        Self { conn: SharedConn::from_boxed(conn), hmac: Arc::new(Mutex::new(new_hmac_sha1(password))) }
    }

    pub(crate) fn shared_conn(&self) -> SharedConn {
        self.conn.clone()
    }

    pub(crate) fn sum(&self) -> Vec<u8> {
        hmac_sum8(&self.hmac.lock())
    }
}

impl AsyncRead for HashReadConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.conn).poll_read(cx, buf);
        if let Some(read) = buf.filled().get(before..) {
            if !read.is_empty() {
                this.hmac.lock().update(read);
            }
        }
        result
    }
}

impl AsyncWrite for HashReadConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl NetStream for HashReadConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.conn.local_addr()?.as_ref())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.conn.remote_addr()?.as_ref())
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.close_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.close_write()
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(&self.conn)
    }
}

struct HashWriteState {
    hmac: Option<HmacSha1>,
    has_content: bool,
    last_sum: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct HashWriteConn {
    conn: SharedConn,
    state: Arc<Mutex<HashWriteState>>,
}

impl HashWriteConn {
    pub(crate) fn new(conn: Box<dyn NetConn>, password: &str) -> Self {
        Self {
            conn: SharedConn::from_boxed(conn),
            state: Arc::new(Mutex::new(HashWriteState {
                hmac: Some(new_hmac_sha1(password)),
                has_content: false,
                last_sum: Vec::new(),
            })),
        }
    }

    pub(crate) fn sums(&self) -> (Option<Vec<u8>>, Vec<u8>, bool) {
        let state = self.state.lock();
        let current = state.hmac.as_ref().map(hmac_sum8);
        (current, state.last_sum.clone(), state.has_content)
    }

    pub(crate) fn fallback(&self) {
        self.state.lock().hmac = None;
    }
}

impl AsyncRead for HashWriteConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for HashWriteConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.conn).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            if n > 0 {
                if let Some(written) = buf.get(..n) {
                    let mut state = this.state.lock();
                    if state.hmac.is_some() {
                        if state.has_content {
                            let sum = state.hmac.as_ref().map(hmac_sum8);
                            if let Some(sum) = sum {
                                state.last_sum = sum;
                            }
                        }
                        if let Some(mac) = state.hmac.as_mut() {
                            mac.update(written);
                        }
                        state.has_content = true;
                    }
                }
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl NetStream for HashWriteConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.conn.local_addr()?.as_ref())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.conn.remote_addr()?.as_ref())
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.close_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.close_write()
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(&self.conn)
    }
}

struct WriteRecordState {
    buf: Vec<u8>,
    offset: usize,
}

pub(crate) struct ShadowConn {
    conn: Box<dyn NetConn>,
    read_remaining: usize,
    read_header: [u8; TLS_HEADER_SIZE],
    read_header_offset: usize,
    write_state: Option<WriteRecordState>,
    /// See `VerifiedConn::torn` in `v3.rs`.
    torn: bool,
}

impl ShadowConn {
    pub(crate) fn new(conn: Box<dyn NetConn>) -> Self {
        Self {
            conn,
            read_remaining: 0,
            read_header: [0u8; TLS_HEADER_SIZE],
            read_header_offset: 0,
            write_state: None,
            torn: false,
        }
    }

    fn poll_write_record(&mut self, cx: &mut Context<'_>, payload: &[u8]) -> Poll<io::Result<()>> {
        if self.torn {
            return Poll::Ready(Err(shadowtls_torn_err()));
        }
        if let Some(state) = self.write_state.as_ref() {
            // See `VerifiedConn::poll_write_record` in `v3.rs`: only a buffer that does not
            // start with the bytes already sealed into this record is a genuine mismatch, not
            // one that merely grew across a `Pending` resume (`tokio::io::copy`, `BufWriter`).
            let matches_sealed = state.buf.get(TLS_HEADER_SIZE..).is_some_and(|sealed| payload.starts_with(sealed));
            if !matches_sealed {
                self.write_state = None;
                self.torn = true;
                return Poll::Ready(Err(shadowtls_torn_err()));
            }
        }
        if self.write_state.is_none() {
            let Ok(payload_len) = u16::try_from(payload.len()) else {
                return Poll::Ready(Err(io::Error::other(format!(
                    "shadow-tls: record payload of {} bytes overflows the TLS record length",
                    payload.len()
                ))));
            };
            let mut buf = Vec::with_capacity(TLS_HEADER_SIZE + payload.len());
            buf.push(APPLICATION_DATA);
            buf.push(3);
            buf.push(3);
            let mut length_bytes = [0u8; 2];
            BigEndian::write_u16(&mut length_bytes, payload_len);
            buf.extend_from_slice(&length_bytes);
            buf.extend_from_slice(payload);
            self.write_state = Some(WriteRecordState { buf, offset: 0 });
        }
        loop {
            let Some(state) = self.write_state.as_mut() else {
                return Poll::Ready(Err(shadowtls_torn_err()));
            };
            if state.offset >= state.buf.len() {
                break;
            }
            let offset = state.offset;
            let (_, unwritten) = state.buf.split_at(offset);
            match Pin::new(self.conn.as_mut()).poll_write(cx, unwritten) {
                Poll::Ready(Ok(0)) => {
                    let torn = state.offset > 0;
                    self.write_state = None;
                    self.torn |= torn;
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => state.offset += n,
                Poll::Ready(Err(err)) => {
                    // See `VerifiedConn::poll_write_record` in `v3.rs` (`agent://ReviewBridge2`
                    // P2): any byte already written before the rest of the record fails leaves
                    // the peer with a partial record, so the whole conn must tear down.
                    let torn = state.offset > 0;
                    self.write_state = None;
                    self.torn |= torn;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_state = None;
        Poll::Ready(Ok(()))
    }
}

fn shadowtls_torn_err() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "shadow-tls: conn torn by an abandoned mid-frame write")
}

fn poll_read_capped(
    conn: &mut Box<dyn NetConn>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
    cap_len: usize,
) -> Poll<io::Result<usize>> {
    let max = cap_len.min(buf.remaining());
    let (result, filled) = {
        let out = buf.initialize_unfilled_to(max);
        let mut sub = ReadBuf::new(out);
        let result = Pin::new(conn.as_mut()).poll_read(cx, &mut sub);
        (result, sub.filled().len())
    };
    buf.advance(filled);
    match result {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(())) => Poll::Ready(Ok(filled)),
        Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
    }
}

impl AsyncRead for ShadowConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.torn {
            return Poll::Ready(Err(shadowtls_torn_err()));
        }
        if this.read_remaining > 0 {
            let cap_len = this.read_remaining;
            return match poll_read_capped(&mut this.conn, cx, buf, cap_len) {
                Poll::Ready(Ok(n)) => {
                    this.read_remaining -= n;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            };
        }
        loop {
            let offset = this.read_header_offset;
            let Some(unread_header) = this.read_header.get_mut(offset..) else {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
            };
            let mut header_buf = ReadBuf::new(unread_header);
            match Pin::new(this.conn.as_mut()).poll_read(cx, &mut header_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let n = header_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                    }
                    this.read_header_offset += n;
                    if this.read_header_offset < TLS_HEADER_SIZE {
                        continue;
                    }
                }
            }
            break;
        }
        this.read_header_offset = 0;
        if this.read_header[0] != APPLICATION_DATA {
            return Poll::Ready(Err(io::Error::other(format!(
                "shadow-tls: unexpected TLS record type: {}",
                this.read_header[0]
            ))));
        }
        let length = usize::from(BigEndian::read_u16(&this.read_header[3..]));
        match poll_read_capped(&mut this.conn, cx, buf, length) {
            Poll::Ready(Ok(n)) => {
                this.read_remaining = length - n;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                this.read_remaining = length;
                Poll::Ready(Err(err))
            }
            Poll::Pending => {
                this.read_remaining = length;
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for ShadowConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return match this.poll_write_record(cx, &[]) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(0)),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            };
        }
        let length = buf.len().min(MAX_TLS_PLAINTEXT);
        let (head, _) = buf.split_at(length);
        match this.poll_write_record(cx, head) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(length)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().conn.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().conn.as_mut()).poll_shutdown(cx)
    }
}

impl NetStream for ShadowConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.conn.local_addr()?.as_ref())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.conn.remote_addr()?.as_ref())
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.close_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.close_write()
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(self.conn.as_ref())
    }
}

impl ExtendedStream for ShadowConn {}

struct PendingClientWrite {
    data: Vec<u8>,
    offset: usize,
    original_len: usize,
}

pub(crate) struct ClientConn {
    shadow_conn: ShadowConn,
    hash_conn: Option<HashReadConn>,
    pending: Option<PendingClientWrite>,
    /// See `VerifiedConn::torn` in `v3.rs`.
    torn: bool,
}

impl ClientConn {
    pub(crate) fn new(hash_conn: HashReadConn) -> Self {
        let shadow_conn = ShadowConn::new(Box::new(hash_conn.shared_conn()));
        Self { shadow_conn, hash_conn: Some(hash_conn), pending: None, torn: false }
    }
}

impl AsyncRead for ClientConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.torn {
            return Poll::Ready(Err(shadowtls_torn_err()));
        }
        Pin::new(&mut this.shadow_conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for ClientConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.torn {
            return Poll::Ready(Err(shadowtls_torn_err()));
        }
        if let Some(pending) = this.pending.as_ref() {
            // See `VerifiedConn::poll_write_record` in `v3.rs`: only a buffer that does not
            // start with the bytes this pending write was built from is a genuine mismatch, not
            // one that merely grew across a `Pending` resume. The caller-visible bytes are the
            // last `original_len` bytes of `data` (after the optional 8-byte hash prefix).
            let original =
                pending.data.len().checked_sub(pending.original_len).and_then(|start| pending.data.get(start..));
            if original.is_none_or(|bytes| !buf.starts_with(bytes)) {
                this.pending = None;
                this.torn = true;
                return Poll::Ready(Err(shadowtls_torn_err()));
            }
        }
        if this.pending.is_none() {
            let data = if let Some(hash_conn) = this.hash_conn.take() {
                let mut prefixed = Vec::with_capacity(8 + buf.len());
                prefixed.extend_from_slice(&hash_conn.sum());
                prefixed.extend_from_slice(buf);
                prefixed
            } else {
                buf.to_vec()
            };
            this.pending = Some(PendingClientWrite { data, offset: 0, original_len: buf.len() });
        }
        loop {
            let Some(pending) = this.pending.as_mut() else {
                return Poll::Ready(Err(shadowtls_torn_err()));
            };
            if pending.offset >= pending.data.len() {
                break;
            }
            let offset = pending.offset;
            let (_, unwritten) = pending.data.split_at(offset);
            match Pin::new(&mut this.shadow_conn).poll_write(cx, unwritten) {
                Poll::Ready(Ok(n)) => pending.offset += n,
                Poll::Ready(Err(err)) => {
                    // If an earlier, complete record for this same logical write already
                    // reached the peer before this later record failed, a fresh unrelated
                    // write must not be allowed to land right after it: the inner byte stream
                    // this framing carries would then interleave two different writes
                    // (`agent://ReviewBridge2` P2).
                    let torn = pending.offset > 0;
                    this.pending = None;
                    this.torn |= torn;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let Some(pending) = this.pending.take() else {
            return Poll::Ready(Err(shadowtls_torn_err()));
        };
        Poll::Ready(Ok(pending.original_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().shadow_conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().shadow_conn).poll_shutdown(cx)
    }
}

impl NetStream for ClientConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shadow_conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.shadow_conn.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.shadow_conn.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.shadow_conn.shutdown_write()
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        self.shadow_conn.old_conn()
    }
}

impl ExtendedStream for ClientConn {}

/// Permission denied: the handshake cannot continue and the caller must fall back.
#[derive(thiserror::Error, Debug)]
pub(crate) enum HandshakeCopyError {
    #[error("permission denied")]
    FallbackRequired,
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub(crate) async fn copy_until_handshake_finished_v2<W, R>(
    dst: &mut W,
    src: &mut R,
    hash_conn: &HashWriteConn,
    fallback_after: i32,
) -> Result<Vec<u8>, HandshakeCopyError>
where
    W: AsyncWrite + Unpin + ?Sized,
    R: AsyncRead + Unpin + ?Sized,
{
    use tokio::io::AsyncWriteExt;

    let mut application_data_count = 0i32;
    loop {
        let frame = read_frame(src).await?;
        let Some((&record_type, _)) = frame.split_first() else {
            return Err(HandshakeCopyError::Io(io::Error::other("shadow-tls: empty TLS record")));
        };
        if record_type == APPLICATION_DATA {
            let Some(payload) = frame.get(TLS_HEADER_SIZE..) else {
                return Err(HandshakeCopyError::Io(io::Error::from(io::ErrorKind::UnexpectedEof)));
            };
            let (current, previous, has_content) = hash_conn.sums();
            if has_content && payload.len() >= 8 {
                let (hash, body) = payload.split_at(8);
                if current.as_deref() == Some(hash) {
                    debugln!("[ShadowTLS] match current hashcode");
                    return Ok(body.to_vec());
                }
                if !previous.is_empty() && previous == hash {
                    debugln!("[ShadowTLS] match last hashcode");
                    return Ok(body.to_vec());
                }
                debugln!("[ShadowTLS] hashcode mismatch");
            }
            application_data_count += 1;
        }
        dst.write_all(&frame).await?;
        if application_data_count > fallback_after {
            return Err(HandshakeCopyError::FallbackRequired);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use murmur_std_compat::net::{Addr, TcpAddr};

    use super::*;

    const TEST_PASSWORD: &str = "shadowtls-v2-test-password";

    /// Accepts exactly one full record's worth of bytes on its first call, then fails every
    /// call after that — modelling a transport that durably delivers a first TLS record and
    /// then breaks mid-way through the next one.
    struct SplitRecordFlakyConn {
        calls: usize,
    }
    impl AsyncRead for SplitRecordFlakyConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for SplitRecordFlakyConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.calls += 1;
            if this.calls == 1 {
                Poll::Ready(Ok(buf.len()))
            } else {
                Poll::Ready(Err(io::Error::other("simulated transport failure")))
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl NetConn for SplitRecordFlakyConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1)))
        }
        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2)))
        }
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Regression for `agent://ReviewBridge2` P2: `ClientConn::poll_write` can span more than
    /// one TLS record for a single caller buffer (`MAX_TLS_PLAINTEXT` per record). If an earlier
    /// record for this same write already reached the peer and a later record then fails,
    /// clearing `pending` and returning bare `Err` used to leave the conn writable — so a later,
    /// unrelated write landed its fresh record right after the already-sent partial data,
    /// corrupting the inner byte stream this framing carries. `SplitRecordFlakyConn` delivers
    /// the first record whole, then breaks, proving the conn must refuse every write after that.
    #[tokio::test]
    async fn client_conn_write_tears_down_after_a_later_record_fails_mid_write() {
        let inner: Box<dyn NetConn> = Box::new(SplitRecordFlakyConn { calls: 0 });
        let hash_conn = HashReadConn::new(inner, TEST_PASSWORD);
        let mut conn = ClientConn::new(hash_conn);

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        // Larger than `MAX_TLS_PLAINTEXT` so the write spans two records: the first record
        // (including the 8-byte hash prefix) is accepted whole by the mock's first call, and
        // the second record hits every call after that, which fails.
        let payload = vec![0xAAu8; MAX_TLS_PLAINTEXT + 100];
        let err = match Pin::new(&mut conn).poll_write(&mut cx, &payload) {
            Poll::Ready(Err(err)) => err,
            other @ (Poll::Ready(_) | Poll::Pending) => {
                panic!("expected the second record's write to fail, got {other:?}")
            }
        };
        assert_eq!(err.to_string(), "simulated transport failure");

        let err = match Pin::new(&mut conn).poll_write(&mut cx, b"fresh, unrelated write") {
            Poll::Ready(Err(err)) => err,
            other @ (Poll::Ready(_) | Poll::Pending) => {
                panic!("a write after a partial multi-record failure must fail closed, got {other:?}")
            }
        };
        assert_eq!(
            err.kind(),
            io::ErrorKind::BrokenPipe,
            "the conn must stay torn so no later write ever puts a fresh record after the already-sent partial one"
        );
    }

    /// Hands out a scripted byte stream and records every read it is offered: the byte count and
    /// the address of the region those bytes would land in.
    struct ScriptedConn {
        data: Vec<u8>,
        offset: usize,
        reads: Arc<Mutex<Vec<(usize, usize)>>>,
    }

    impl AsyncRead for ScriptedConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let asked = buf.remaining();

            let take = asked.min(this.data.len().saturating_sub(this.offset));
            let end = this.offset.saturating_add(take);
            let chunk =
                this.data.get(this.offset..end).ok_or_else(|| io::Error::other("scripted read past the end"))?;
            this.offset = end;
            buf.put_slice(chunk);
            this.reads.lock().push((asked, buf.filled().as_ptr().addr()));
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedConn {
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

    impl NetConn for ScriptedConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1)))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2)))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A record read is capped by both the record's remaining length and the caller's buffer, and
    /// the capped read writes into the caller's own buffer rather than into a scratch copy of it.
    #[tokio::test]
    async fn a_record_read_is_capped_and_lands_in_the_callers_buffer() {
        let payload = b"v2 payload";
        let mut wire = Vec::with_capacity(TLS_HEADER_SIZE + payload.len());
        wire.push(APPLICATION_DATA);
        wire.extend_from_slice(&[3, 3]);
        wire.extend_from_slice(&u16::try_from(payload.len()).expect("the payload fits a record").to_be_bytes());
        wire.extend_from_slice(payload);

        let reads = Arc::new(Mutex::new(Vec::new()));
        let mut conn = ShadowConn::new(Box::new(ScriptedConn { data: wire, offset: 0, reads: Arc::clone(&reads) }));

        let mut small = [0u8; 8];
        let caller = small.as_ptr().addr()..small.as_ptr().addr().saturating_add(small.len());
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);

        let mut received = Vec::new();
        for _ in 0..payload.len().div_ceil(small.len()) {
            let mut buf = ReadBuf::new(&mut small);
            match Pin::new(&mut conn).poll_read(&mut cx, &mut buf) {
                Poll::Ready(Ok(())) => received.extend_from_slice(buf.filled()),
                other @ (Poll::Ready(_) | Poll::Pending) => {
                    panic!("every read of a complete record must be ready, got {other:?}")
                }
            }
        }

        assert_eq!(received, payload, "the record payload did not arrive whole");
        let reads = reads.lock().clone();
        let asked: Vec<usize> = reads.iter().map(|(asked, _)| *asked).collect();
        assert_eq!(
            asked,
            vec![TLS_HEADER_SIZE, 8, 2],
            "the reads were not capped by the header, the caller's buffer and the record's remainder"
        );
        for (asked, target) in reads.iter().skip(1) {
            assert!(
                caller.contains(target),
                "the read of {asked} bytes was handed a region outside the caller's buffer"
            );
        }
    }
}

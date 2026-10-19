use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use aes_gcm::aead::{AeadInOut, KeyInit as _, Nonce, Tag};
use aes_gcm::Aes256Gcm;
use anyhow::{anyhow, Result};
use chacha20poly1305::ChaCha20Poly1305;
use rand::Rng as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use x25519_dalek::{PublicKey, StaticSecret};

use murmur_common_net::io::{close_stream, ExtendedStream, Stream};
use murmur_common_pool as pool;
use murmur_std_compat::net::{Addr, Conn as NetConn, TcpAddr};
use parking_lot::Mutex;

use super::client::ClientInstance;
use super::xor::{AesCtrStream, XorConn};

pub struct CommonConn {
    pub conn: InnerConn,
    pub use_aes: bool,
    pub client: Option<Arc<ClientInstance>>,
    pub united_key: Vec<u8>,
    pub pre_write: Option<Vec<u8>>,
    pub aead: Option<AEAD>,
    pub peer_aead: Option<AEAD>,
    pub peer_padding: Option<Vec<u8>>,
    raw_input: Vec<u8>,
    input: BytesReader,
    out_bytes: Vec<u8>,
    pre_write_sent: usize,
    write_frame_len: usize,
    write_frame_sent: usize,
    write_frame_plain: usize,
    peer_random: [u8; 16],
    peer_random_filled: usize,
    peer_padding_filled: usize,
    peer_header: [u8; 5],
    peer_header_filled: usize,
    /// Frame length decoded from `peer_header`, kept across a `Pending` body read so a retry
    /// resumes reading the body instead of re-decoding a fresh header while the prior body read
    /// is still in flight on the same underlying reader. 0 means no header has been decoded yet.
    peer_frame_len: usize,
    raw_input_filled: usize,
}

/// Redacts `united_key` and the AEAD states; the remaining fields are protocol bookkeeping.
impl core::fmt::Debug for CommonConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommonConn")
            .field("use_aes", &self.use_aes)
            .field("write_frame_len", &self.write_frame_len)
            .field("peer_frame_len", &self.peer_frame_len)
            .field("united_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// The wrapped conn, which holds an `XorConn` once the XOR mode installs that layer.
/// Rust cannot type-assert a trait object back to `XorConn`, so the choice is kept here.
pub enum InnerConn {
    Plain(Box<dyn Stream>),
    Xor(Box<XorConn>),
}

/// The wrapped stream is a trait object without a `Debug` bound, so only the variant is shown.
impl core::fmt::Debug for InnerConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Plain(_) => f.write_str("InnerConn::Plain(..)"),
            Self::Xor(_) => f.write_str("InnerConn::Xor(..)"),
        }
    }
}

impl InnerConn {
    /// Wraps the conn this value holds.
    fn into_xor(self, ctr: AesCtrStream, peer_ctr: Option<AesCtrStream>, out_skip: usize, in_skip: usize) -> Self {
        let conn: Box<dyn Stream> = match self {
            Self::Plain(conn) => conn,
            Self::Xor(conn) => conn,
        };
        Self::Xor(Box::new(XorConn::new(conn, ctr, peer_ctr, out_skip, in_skip)))
    }

    fn conn(&self) -> &dyn Stream {
        match self {
            Self::Plain(conn) => conn.as_ref(),
            Self::Xor(conn) => conn.as_ref(),
        }
    }
}

impl CommonConn {
    #[must_use]
    pub fn new(conn: Box<dyn Stream>, use_aes: bool) -> Self {
        Self {
            conn: InnerConn::Plain(conn),
            use_aes,
            client: None,
            united_key: Vec::new(),
            pre_write: None,
            aead: None,
            peer_aead: None,
            peer_padding: None,
            raw_input: Vec::new(),
            input: BytesReader::new(),
            out_bytes: pool::get(5 + 8192 + 16),
            pre_write_sent: 0,
            write_frame_len: 0,
            write_frame_sent: 0,
            write_frame_plain: 0,
            peer_random: [0; 16],
            peer_random_filled: 0,
            peer_padding_filled: 0,
            peer_header: [0; 5],
            peer_header_filled: 0,
            peer_frame_len: 0,
            raw_input_filled: 0,
        }
    }
}

impl CommonConn {
    pub(crate) fn with_xor(
        mut self,
        ctr: AesCtrStream,
        peer_ctr: Option<AesCtrStream>,
        out_skip: usize,
        in_skip: usize,
    ) -> Self {
        self.conn = self.conn.into_xor(ctr, peer_ctr, out_skip, in_skip);
        self
    }

    /// Flushes the queued pre-write prefix and then the frame,
    /// returning the plaintext bytes of a frame that finished.
    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if let Some(pre_write) = self.pre_write.take() {
            match poll_write_all(&mut self.conn, cx, &pre_write, &mut self.pre_write_sent) {
                Poll::Ready(result) => {
                    result?;
                    self.pre_write_sent = 0;
                }
                Poll::Pending => {
                    self.pre_write = Some(pre_write);
                    return Poll::Pending;
                }
            }
        }
        if self.write_frame_len > 0 {
            let frame = self
                .out_bytes
                .get(..self.write_frame_len)
                .ok_or_else(|| io::Error::other("write frame exceeds the output buffer"))?;
            ready!(poll_write_all(&mut self.conn, cx, frame, &mut self.write_frame_sent))?;
            let plain = self.write_frame_plain;
            self.write_frame_len = 0;
            self.write_frame_sent = 0;
            self.write_frame_plain = 0;
            return Poll::Ready(Ok(plain));
        }
        Poll::Ready(Ok(0))
    }
}

/// A reader over the decrypted bytes that did not fit the caller's buffer.
struct BytesReader {
    buf: Vec<u8>,
    off: usize,
}

impl BytesReader {
    const fn new() -> Self {
        Self { buf: Vec::new(), off: 0 }
    }

    const fn len(&self) -> usize {
        self.buf.len() - self.off
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len());
        // `split_at` returns the head first and the tail second: the bytes to hand out are the
        // tail past `self.off`, so bind the second element (as in `buf[off..off + n]`).
        let (up_to_end, _) = self.buf.split_at(self.off + n);
        let (_, src) = up_to_end.split_at(self.off);
        let (dst, _) = out.split_at_mut(n);
        dst.copy_from_slice(src);
        self.off += n;
        n
    }

    fn reset(&mut self, data: &[u8]) {
        self.buf.clear();
        self.buf.extend_from_slice(data);
        self.off = 0;
    }

    /// Takes the unread bytes and clears the whole buffer, so the consumed prefix can never be
    /// handed out again after a direct-mode drain.
    fn take(&mut self) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.buf);
        let offset = std::mem::take(&mut self.off);
        buf.split_off(offset)
    }
}

pub(crate) fn poll_read_exact<T: Stream + ?Sized>(
    conn: &mut T,
    cx: &mut Context<'_>,
    dst: &mut [u8],
    filled: &mut usize,
) -> Poll<io::Result<()>> {
    while *filled < dst.len() {
        let (_, free) = dst.split_at_mut(*filled);
        let mut read_buf = ReadBuf::new(free);
        ready!(Pin::new(&mut *conn).poll_read(cx, &mut read_buf))?;
        let n = read_buf.filled().len();
        if n == 0 {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")));
        }
        *filled += n;
    }
    Poll::Ready(Ok(()))
}

/// Writes `buf` in full, remembering how far a partial write got.
pub(crate) fn poll_write_all<T: Stream + ?Sized>(
    conn: &mut T,
    cx: &mut Context<'_>,
    buf: &[u8],
    sent: &mut usize,
) -> Poll<io::Result<()>> {
    while *sent < buf.len() {
        let (_, unsent) = buf.split_at(*sent);
        match Pin::new(&mut *conn).poll_write(cx, unsent) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")));
            }
            Poll::Ready(Ok(n)) => *sent += n,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

impl AsyncWrite for InnerConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(conn) => Pin::new(conn.as_mut()).poll_write(cx, buf),
            Self::Xor(conn) => Pin::new(conn.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(conn) => Pin::new(conn.as_mut()).poll_flush(cx),
            Self::Xor(conn) => Pin::new(conn.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(conn) => Pin::new(conn.as_mut()).poll_shutdown(cx),
            Self::Xor(conn) => Pin::new(conn.as_mut()).poll_shutdown(cx),
        }
    }
}

impl AsyncRead for InnerConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(conn) => Pin::new(conn.as_mut()).poll_read(cx, buf),
            Self::Xor(conn) => Pin::new(conn.as_mut()).poll_read(cx, buf),
        }
    }
}

impl Stream for InnerConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn().local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn().peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn().shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn().shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.conn().as_socket()
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn().old_conn()
    }
}

impl AsyncWrite for CommonConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut total = 0;
        let mut off = 0;
        if this.pre_write.is_some() || this.write_frame_len > 0 {
            match this.poll_flush_pending(cx) {
                Poll::Ready(Ok(plain)) => {
                    total += plain;
                    // `plain` bytes of `buf`'s prefix were already sealed into the frame just
                    // flushed by an earlier, partially-completed call; re-sealing them here would
                    // double-count them in the returned total (`n <= buf.len()` would break).
                    off = plain.min(buf.len());
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        while off < buf.len() {
            let (_, mut b) = buf.split_at(off);
            if b.len() > 8192 {
                let (head, _) = b.split_at(8192);
                b = head; // for avoiding another copy() in peer's Read()
            }
            off += b.len();
            let frame_len = 5 + b.len() + 16;
            let Some(frame) = this.out_bytes.get_mut(..frame_len) else {
                return Poll::Ready(Err(io::Error::other("write frame exceeds the output buffer")));
            };
            let (header_out, sealed) = frame.split_at_mut(5);
            encode_header(header_out, b.len() + 16);
            let header: [u8; 5] = header_out.try_into().map_err(|_| io::Error::other("five header bytes"))?;
            let Some(aead) = this.aead.as_mut() else {
                return Poll::Ready(Err(io::Error::other("AEAD is set by Handshake")));
            };
            let max = aead.nonce == MAX_NONCE;
            aead.seal(sealed, None, b, &header).map_err(io::Error::other)?;
            if max {
                let Some(frame) = this.out_bytes.get(..frame_len) else {
                    return Poll::Ready(Err(io::Error::other("write frame exceeds the output buffer")));
                };
                this.aead = Some(AEAD::new(frame, &this.united_key, this.use_aes));
            }
            this.write_frame_len = frame_len;
            this.write_frame_sent = 0;
            this.write_frame_plain = b.len();
            match this.poll_flush_pending(cx) {
                Poll::Ready(Ok(plain)) => total += plain,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    return if total == 0 { Poll::Pending } else { Poll::Ready(Ok(total)) };
                }
            }
        }
        Poll::Ready(Ok(total))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_pending(cx))?;
        Pin::new(&mut this.conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.conn).poll_shutdown(cx)
    }
}

impl AsyncRead for CommonConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.peer_aead.is_none() {
            // client's 0-RTT
            ready!(poll_read_exact(&mut this.conn, cx, &mut this.peer_random, &mut this.peer_random_filled))?;
            this.peer_random_filled = 0;
            let server_random = this.peer_random;
            this.peer_aead = Some(AEAD::new(&server_random, &this.united_key, this.use_aes));
            if let InnerConn::Xor(xor_conn) = &mut this.conn {
                xor_conn.peer_ctr = Some(AesCtrStream::new(&this.united_key, &server_random));
            }
        }
        if let Some(peer_padding) = this.peer_padding.as_mut() {
            // client's 1-RTT
            let len = peer_padding.len();
            ready!(poll_read_exact(&mut this.conn, cx, peer_padding, &mut this.peer_padding_filled))?;
            this.peer_padding_filled = 0;
            this.peer_aead
                .as_mut()
                .ok_or_else(|| io::Error::other("peer AEAD is set before the padding"))?
                .open_in_place(peer_padding, None, len, &[])
                .map_err(io::Error::other)?;
            this.peer_padding = None;
        }
        if !this.input.is_empty() {
            let available = this.input.len().min(buf.remaining());
            let n = {
                let out = buf.initialize_unfilled_to(available);
                this.input.read(out)
            };
            buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        this.poll_read_frame(cx, buf)
    }
}

impl CommonConn {
    fn poll_read_frame(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self;
        if this.peer_frame_len == 0 {
            ready!(poll_read_exact(&mut this.conn, cx, &mut this.peer_header, &mut this.peer_header_filled))?;
            this.peer_header_filled = 0;
            let (l, err) = decode_header(&this.peer_header); // l: 17~17000
            if let Some(err) = err {
                if let Some(client) = &this.client {
                    // client's 0-RTT
                    let mut state = client.rw_lock.write();
                    if this.united_key.starts_with(&state.pfs_key) {
                        state.expire = None;
                    }
                    drop(state);
                    return Poll::Ready(Err(io::Error::other("new handshake needed")));
                }
                return Poll::Ready(Err(io::Error::other(err)));
            }
            this.client = None;
            if this.raw_input.len() < l {
                // no pool needed here, because we are always reading
                this.raw_input.resize(l, 0);
            }
            this.peer_frame_len = l;
        }
        let l = this.peer_frame_len;
        let peer_header = this.peer_header;
        let frame = this.raw_input.get_mut(..l).ok_or_else(|| io::Error::other("peer frame exceeds input buffer"))?;
        ready!(poll_read_exact(&mut this.conn, cx, frame, &mut this.raw_input_filled))?;
        this.raw_input_filled = 0;
        this.peer_frame_len = 0;
        let dst_len = l - 16;
        let peer_nonce = this.peer_aead.as_ref().ok_or_else(|| io::Error::other("peer AEAD is set"))?.nonce;
        let new_aead = if peer_nonce == MAX_NONCE {
            let frame = this.raw_input.get(..l).ok_or_else(|| io::Error::other("peer frame exceeds input buffer"))?;
            let mut ctx = Vec::with_capacity(5 + l);
            ctx.extend_from_slice(&peer_header);
            ctx.extend_from_slice(frame);
            Some(AEAD::new(&ctx, &this.united_key, this.use_aes))
        } else {
            None
        };
        if dst_len <= buf.remaining() {
            let unfilled = buf.initialize_unfilled_to(dst_len);
            let frame = this.raw_input.get(..l).ok_or_else(|| io::Error::other("peer frame exceeds input buffer"))?;
            this.peer_aead
                .as_mut()
                .ok_or_else(|| io::Error::other("peer AEAD is set"))?
                .open_into(unfilled, None, frame, &peer_header)
                .map_err(io::Error::other)?;
            buf.advance(dst_len); // avoids another copy()
        } else {
            let frame =
                this.raw_input.get_mut(..l).ok_or_else(|| io::Error::other("peer frame exceeds input buffer"))?;
            this.peer_aead
                .as_mut()
                .ok_or_else(|| io::Error::other("peer AEAD is set"))?
                .open_in_place(frame, None, l, &peer_header)
                .map_err(io::Error::other)?;
            let n = buf.remaining();
            let plain = this.raw_input.get(..n).ok_or_else(|| io::Error::other("peer frame exceeds input buffer"))?;
            buf.put_slice(plain);
            let rest =
                this.raw_input.get(n..dst_len).ok_or_else(|| io::Error::other("peer frame exceeds input buffer"))?;
            this.input.reset(rest);
        }
        if let Some(new_aead) = new_aead {
            this.peer_aead = Some(new_aead);
        }
        Poll::Ready(Ok(()))
    }
}

impl Stream for CommonConn {
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

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn.old_conn()
    }
}

impl ExtendedStream for CommonConn {}

impl CommonConn {
    /// Takes the plaintext this conn has already decrypted but not yet handed to the caller.
    ///
    /// A caller switching to the transport beneath the encryption layer (XTLS Vision direct mode)
    /// has to deliver these bytes before reading that transport. An encrypted frame still in
    /// flight cannot be re-injected, so the switch is refused instead of losing ciphertext.
    pub fn take_buffered_input(&mut self) -> io::Result<Vec<u8>> {
        if self.peer_frame_len != 0 || self.raw_input_filled != 0 {
            return Err(io::Error::other("XTLS Vision direct switch with an encryption frame in flight"));
        }
        Ok(self.input.take())
    }
}

/// One encryption conn shared by the Vision-facing stream and its direct-mode transport handle.
///
/// Vision normally polls this wrapper, which runs the VLESS encryption framing. After a DIRECT
/// switch it polls [`DirectCommonConn`] instead, which first drains the decrypted surplus and then
/// reads and writes the transport immediately beneath the encryption layer (the XOR layer when
/// one is installed), matching the reference's `UnwrapRawConn` behaviour for `CommonConn`.
pub struct SharedCommonConn {
    inner: Arc<Mutex<CommonConn>>,
}

impl SharedCommonConn {
    #[must_use]
    pub fn new(conn: CommonConn) -> Self {
        Self { inner: Arc::new(Mutex::new(conn)) }
    }

    #[must_use]
    pub fn direct(&self) -> DirectCommonConn {
        DirectCommonConn { inner: Arc::clone(&self.inner), pending: None }
    }
}

impl Clone for SharedCommonConn {
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner) }
    }
}

impl core::fmt::Debug for SharedCommonConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedCommonConn").finish_non_exhaustive()
    }
}

impl AsyncRead for SharedCommonConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner.lock()).poll_read(cx, buf)
    }
}

impl AsyncWrite for SharedCommonConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner.lock()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner.lock()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner.lock()).poll_shutdown(cx)
    }
}

impl Stream for SharedCommonConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.lock().local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.lock().peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.inner.lock().shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.inner.lock().shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(self)
    }
}

impl NetConn for SharedCommonConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.inner.lock().local_addr()?)))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.inner.lock().peer_addr()?)))
    }

    fn close(&self) -> io::Result<()> {
        close_stream(&*self.inner.lock())
    }

    fn close_read(&self) -> io::Result<()> {
        self.inner.lock().shutdown_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.inner.lock().shutdown_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let guard = self.inner.lock();
        match guard.conn.old_conn() {
            Some(conn) => conn.set_deadline(deadline),
            None => Ok(()),
        }
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let guard = self.inner.lock();
        match guard.conn.old_conn() {
            Some(conn) => conn.set_read_deadline(deadline),
            None => Ok(()),
        }
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let guard = self.inner.lock();
        match guard.conn.old_conn() {
            Some(conn) => conn.set_write_deadline(deadline),
            None => Ok(()),
        }
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }
}

/// The transport beneath the encryption layer, used after an XTLS Vision DIRECT switch.
///
/// Buffered plaintext is delivered first; afterwards reads and writes bypass the encryption
/// framing (but keep the XOR layer when the encryption installed one).
pub struct DirectCommonConn {
    inner: Arc<Mutex<CommonConn>>,
    pending: Option<(Vec<u8>, usize)>,
}

impl core::fmt::Debug for DirectCommonConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DirectCommonConn").finish_non_exhaustive()
    }
}

impl AsyncRead for DirectCommonConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut guard = this.inner.lock();
        if this.pending.is_none() {
            match guard.take_buffered_input() {
                Ok(pending) => this.pending = Some((pending, 0)),
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
        if let Some((pending, offset)) = &mut this.pending {
            if *offset < pending.len() {
                let n = (pending.len() - *offset).min(buf.remaining());
                let Some(chunk) = pending.get(*offset..*offset + n) else {
                    return Poll::Ready(Err(io::Error::other("direct pending buffer out of range")));
                };
                buf.put_slice(chunk);
                *offset += n;
                if *offset == pending.len() {
                    this.pending = None;
                }
                return Poll::Ready(Ok(()));
            }
            this.pending = None;
        }
        Pin::new(&mut guard.conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for DirectCommonConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner.lock().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner.lock().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner.lock().conn).poll_shutdown(cx)
    }
}

impl Stream for DirectCommonConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.lock().conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.lock().conn.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.inner.lock().conn.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.inner.lock().conn.shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(self)
    }
}

impl NetConn for DirectCommonConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.inner.lock().conn.local_addr()?)))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.inner.lock().conn.peer_addr()?)))
    }

    fn close(&self) -> io::Result<()> {
        close_stream(&self.inner.lock().conn)
    }

    fn close_read(&self) -> io::Result<()> {
        self.inner.lock().conn.shutdown_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.inner.lock().conn.shutdown_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let guard = self.inner.lock();
        match guard.conn.old_conn() {
            Some(conn) => conn.set_deadline(deadline),
            None => Ok(()),
        }
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let guard = self.inner.lock();
        match guard.conn.old_conn() {
            Some(conn) => conn.set_read_deadline(deadline),
            None => Ok(()),
        }
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let guard = self.inner.lock();
        match guard.conn.old_conn() {
            Some(conn) => conn.set_write_deadline(deadline),
            None => Ok(()),
        }
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }
}

/// An AEAD with the implicit nonce incremented per message.
#[derive(Debug)]
pub struct AEAD {
    cipher: Cipher,
    pub nonce: [u8; 12],
}

#[allow(clippy::large_enum_variant)]
// A union over the AES-GCM and ChaCha20-Poly1305 implementations; revisit boxing in the idiomatic-refactor phase
#[derive(Debug)]
enum Cipher {
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

pub static MAX_NONCE: [u8; 12] = [255; 12];

impl AEAD {
    #[allow(clippy::expect_used, reason = "k is the fixed 32-byte BLAKE3 DeriveKey output")]
    #[must_use]
    pub fn new(ctx: &[u8], key: &[u8], use_aes: bool) -> Self {
        let k = blake3_kdf::derive_key(ctx, key);
        let cipher = if use_aes {
            Cipher::Aes256Gcm(Aes256Gcm::new_from_slice(&k).expect("32-byte key"))
        } else {
            Cipher::ChaCha20Poly1305(ChaCha20Poly1305::new_from_slice(&k).expect("32-byte key"))
        };
        Self { cipher, nonce: [0; 12] }
    }

    fn next_nonce(&mut self, nonce: Option<&[u8]>) -> Result<[u8; 12]> {
        match nonce {
            Some(nonce) => nonce.try_into().map_err(|_| anyhow!("incorrect nonce length for GCM")),
            None => Ok(increase_nonce(&mut self.nonce)),
        }
    }

    fn seal_region(&self, region: &mut [u8], tag_dst: &mut [u8], nonce: &[u8], additional_data: &[u8]) -> Result<()> {
        match &self.cipher {
            Cipher::Aes256Gcm(cipher) => {
                let nonce =
                    Nonce::<Aes256Gcm>::try_from(nonce).map_err(|_| anyhow!("incorrect nonce length for GCM"))?;
                let tag = cipher.encrypt_inout_detached(&nonce, additional_data, region.into())?;
                tag_dst.copy_from_slice(&tag);
            }
            Cipher::ChaCha20Poly1305(cipher) => {
                let nonce = chacha20poly1305::Nonce::try_from(nonce)
                    .map_err(|_| anyhow!("chacha20poly1305: bad nonce length"))?;
                let tag = cipher.encrypt_inout_detached(&nonce, additional_data, region.into())?;
                tag_dst.copy_from_slice(&tag);
            }
        }
        Ok(())
    }

    fn open_region(&self, region: &mut [u8], tag_src: &[u8], nonce: &[u8], additional_data: &[u8]) -> Result<()> {
        match &self.cipher {
            Cipher::Aes256Gcm(cipher) => {
                let nonce =
                    Nonce::<Aes256Gcm>::try_from(nonce).map_err(|_| anyhow!("incorrect nonce length for GCM"))?;
                let tag = Tag::<Aes256Gcm>::try_from(tag_src).map_err(|_| anyhow!("incorrect tag length"))?;
                cipher
                    .decrypt_inout_detached(&nonce, additional_data, region.into(), &tag)
                    .map_err(|_| anyhow!("cipher: message authentication failed"))?;
            }
            Cipher::ChaCha20Poly1305(cipher) => {
                let nonce = chacha20poly1305::Nonce::try_from(nonce)
                    .map_err(|_| anyhow!("chacha20poly1305: bad nonce length"))?;
                let tag = chacha20poly1305::Tag::try_from(tag_src)
                    .map_err(|_| anyhow!("chacha20poly1305: bad tag length"))?;
                cipher
                    .decrypt_inout_detached(&nonce, additional_data, region.into(), &tag)
                    .map_err(|_| anyhow!("cipher: message authentication failed"))?;
            }
        }
        Ok(())
    }

    /// The region the ciphertext and tag land in, `plaintext.len() + 16`
    /// bytes long.
    pub fn seal(
        &mut self,
        dst: &mut [u8],
        nonce: Option<&[u8]>,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<()> {
        let nonce = self.next_nonce(nonce)?;
        let (region, tag_dst) = dst.split_at_mut(plaintext.len());
        region.copy_from_slice(plaintext);
        self.seal_region(region, tag_dst, &nonce, additional_data)
    }

    /// Seals for the call sites whose `dst` append lands on the plaintext itself, which
    /// therefore has to be encrypted where it already is.
    pub fn seal_in_place(
        &mut self,
        dst: &mut [u8],
        nonce: Option<&[u8]>,
        plaintext_len: usize,
        additional_data: &[u8],
    ) -> Result<()> {
        let nonce = self.next_nonce(nonce)?;
        let (region, tag_dst) = dst.split_at_mut(plaintext_len);
        self.seal_region(region, tag_dst, &nonce, additional_data)
    }

    /// Opens where the `dst` append target aliases the ciphertext: the first
    /// `ciphertext_len - 16` bytes of `buf` hold the plaintext afterwards.
    pub fn open_in_place(
        &mut self,
        buf: &mut [u8],
        nonce: Option<&[u8]>,
        ciphertext_len: usize,
        additional_data: &[u8],
    ) -> Result<()> {
        let nonce = self.next_nonce(nonce)?;
        if ciphertext_len < 16 {
            return Err(anyhow!("cipher: message authentication failed"));
        }
        let (region, tag_src) = buf
            .get_mut(..ciphertext_len)
            .ok_or_else(|| anyhow!("cipher: ciphertext is shorter than its declared length"))?
            .split_at_mut(ciphertext_len - 16);
        self.open_region(region, tag_src, &nonce, additional_data)
    }

    /// Opens where `dst` does not alias the ciphertext.
    pub fn open_into(
        &mut self,
        dst: &mut [u8],
        nonce: Option<&[u8]>,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<()> {
        let nonce = self.next_nonce(nonce)?;
        if ciphertext.len() < 16 {
            return Err(anyhow!("cipher: message authentication failed"));
        }
        let (body, tag_src) = ciphertext.split_at(ciphertext.len() - 16);
        dst.copy_from_slice(body);
        self.open_region(dst, tag_src, &nonce, additional_data)
    }

    /// Opens with no caller-supplied output buffer.
    pub fn open_alloc(&mut self, nonce: Option<&[u8]>, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(anyhow!("cipher: message authentication failed"));
        }
        let mut dst = vec![0u8; ciphertext.len() - 16];
        self.open_into(&mut dst, nonce, ciphertext, additional_data)?;
        Ok(dst)
    }
}

pub fn increase_nonce(nonce: &mut [u8; 12]) -> [u8; 12] {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
    *nonce
}

#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    reason = "the VLESS length header is a 16-bit wire field, so the truncation is the encoding"
)]
pub const fn encode_length(l: usize) -> [u8; 2] {
    (l as u16).to_be_bytes()
}

#[must_use]
pub fn decode_length(b: &[u8]) -> usize {
    let [hi, lo, ..] = b else {
        return 0;
    };
    usize::from(u16::from_be_bytes([*hi, *lo]))
}

/// The X25519 Diffie-Hellman, over `x25519_dalek::StaticSecret::diffie_hellman`.
pub fn x25519_diffie_hellman(secret: &StaticSecret, public: &PublicKey) -> Result<Vec<u8>> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(anyhow!("bad X25519 remote ECDH input: low order point"));
    }
    Ok(shared.to_bytes().to_vec())
}

pub fn encode_header(h: &mut [u8], l: usize) {
    let len_bytes = encode_length(l);
    let Some(header) = h.get_mut(..5) else {
        return;
    };
    header.copy_from_slice(&[23, 3, 3, len_bytes[0], len_bytes[1]]);
}

/// The invalid-header error; callers that would test it by identity instead match on this type.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid header: {header}")]
pub struct ErrInvalidHeader {
    /// The `h[:5]` bytes, formatted for the error message.
    header: String,
}

/// Returns the declared header length and any invalid-header error.
#[must_use]
pub fn decode_header(h: &[u8]) -> (usize, Option<ErrInvalidHeader>) {
    let Some(header) = h.get(..5) else {
        return (0, Some(ErrInvalidHeader { header: format_byte_slice(h) }));
    };
    let [23, 3, 3, hi, lo] = header else {
        return (0, Some(ErrInvalidHeader { header: format_byte_slice(header) }));
    };
    let l = usize::from(u16::from_be_bytes([*hi, *lo]));
    if !(17..=17000).contains(&l) {
        return (l, Some(ErrInvalidHeader { header: format_byte_slice(header) }));
    }
    (l, None)
}

pub fn parse_padding(padding: &str, padding_lens: &mut Vec<[i64; 3]>, padding_gaps: &mut Vec<[i64; 3]>) -> Result<()> {
    if padding.is_empty() {
        return Ok(());
    }
    let mut max_len = 0;
    for (i, s) in padding.split('.').enumerate() {
        let mut x = s.split('-');
        let (Some(chance), Some(lo), Some(hi)) = (x.next(), x.next(), x.next()) else {
            return Err(anyhow!("invalid padding lenth/gap parameter: {s}"));
        };
        if chance.is_empty() || lo.is_empty() || hi.is_empty() {
            return Err(anyhow!("invalid padding lenth/gap parameter: {s}"));
        }
        let mut y = [0i64; 3];
        for (field, value) in y.iter_mut().zip([chance, lo, hi]) {
            *field = value.parse::<i64>().map_err(|err| {
                let reason = if matches!(
                    err.kind(),
                    std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow
                ) {
                    "value out of range"
                } else {
                    "invalid syntax"
                };
                anyhow!("invalid number syntax: {value:?}: {reason}")
            })?;
        }
        if i == 0 && (y[0] < 100 || y[1] < 18 + 17 || y[2] < 18 + 17) {
            return Err(anyhow!("first padding length must not be smaller than 35"));
        }
        if i % 2 == 0 {
            padding_lens.push(y);
            max_len += y[1].max(y[2]);
        } else {
            padding_gaps.push(y);
        }
    }
    if max_len > 18 + 65535 {
        return Err(anyhow!("total padding length must not be larger than 65553"));
    }
    Ok(())
}

#[must_use]
pub fn creat_padding(
    padding_lens: &[[i64; 3]],
    padding_gaps: &[[i64; 3]],
) -> (i64, Vec<i64>, Vec<murmur_common::time::TimeDuration>) {
    let default_lens = [[100, 111, 1111], [50, 0, 3333]];
    let default_gaps = [[75, 0, 111]];
    let (padding_lens, padding_gaps) =
        if padding_lens.is_empty() { (&default_lens[..], &default_gaps[..]) } else { (padding_lens, padding_gaps) };
    let mut length = 0;
    let mut lens = Vec::with_capacity(padding_lens.len());
    for y in padding_lens {
        let l = if y[0] >= rand_between(0, 100) { rand_between(y[1], y[2]) } else { 0 };
        lens.push(l);
        length += l;
    }
    let mut gaps = Vec::with_capacity(padding_gaps.len());
    for y in padding_gaps {
        let g = if y[0] >= rand_between(0, 100) { rand_between(y[1], y[2]) } else { 0 };
        gaps.push(g * murmur_common::time::MILLISECOND);
    }
    (length, lens, gaps)
}

/// A uniform integer from `rand::rng` in the half-open range between the bounds.
pub(crate) fn rand_between(from: i64, to: i64) -> i64 {
    if from == to {
        return from;
    }
    let (from, to) = if to < from { (to, from) } else { (from, to) };
    from + rand::rng().random_range(0..to - from)
}

/// Formats a byte slice as space-separated decimal bytes inside brackets.
pub(crate) fn format_byte_slice(b: &[u8]) -> String {
    let mut out = String::from("[");
    for (i, byte) in b.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&byte.to_string());
    }
    out.push(']');
    out
}

/// Copies the smaller of the two lengths, returning how many bytes were copied.
pub(crate) fn copy_prefix(dst: &mut [u8], src: &[u8]) -> usize {
    let n = dst.len().min(src.len());
    let (dst, _) = dst.split_at_mut(n);
    let (src, _) = src.split_at(n);
    dst.copy_from_slice(src);
    n
}

/// BLAKE3's derive-key mode over the raw context bytes: it hashes the context as raw bytes,
/// while the pinned `blake3` crate's `derive_key` takes a `&str`, whose bytes
/// cannot carry an arbitrary IV or ciphertext.
mod blake3_kdf {
    const IV: [u32; 8] =
        [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
    const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
    const CHUNK_START: u32 = 1 << 0;
    const CHUNK_END: u32 = 1 << 1;
    const PARENT: u32 = 1 << 2;
    const ROOT: u32 = 1 << 3;
    const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
    const DERIVE_KEY_MATERIAL: u32 = 1 << 6;
    const BLOCK_LEN: usize = 64;
    const CHUNK_LEN: usize = 1024;

    pub(super) fn derive_key(context: &[u8], key_material: &[u8]) -> [u8; 32] {
        let context_hash = hash_all(context, &IV, DERIVE_KEY_CONTEXT);
        let mut context_key = [0u32; 8];
        for (word, bytes) in context_key.iter_mut().zip(context_hash.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        hash_all(key_material, &context_key, DERIVE_KEY_MATERIAL)
    }

    fn hash_all(input: &[u8], key: &[u32; 8], flags: u32) -> [u8; 32] {
        subtree_output(input, 0, key, flags).root_output()
    }

    fn subtree_output(input: &[u8], chunk_counter: u64, key: &[u32; 8], flags: u32) -> Output {
        if input.len() <= CHUNK_LEN {
            return chunk_output(input, chunk_counter, key, flags);
        }
        let left_len = left_subtree_len(input.len());
        let (left_bytes, right_bytes) = input.split_at(left_len);
        let left = subtree_output(left_bytes, chunk_counter, key, flags);
        let right = subtree_output(right_bytes, chunk_counter + (left_len / CHUNK_LEN) as u64, key, flags);
        parent_output(&left.chaining_value(), &right.chaining_value(), key, flags)
    }

    const fn left_subtree_len(input_len: usize) -> usize {
        let full_chunks = (input_len - 1) / CHUNK_LEN;
        let largest_power_of_two = 1usize << (usize::BITS - 1 - full_chunks.leading_zeros());
        largest_power_of_two * CHUNK_LEN
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "BLAKE3 block length is at most `BLOCK_LEN` = 64 bytes, so neither cast can truncate"
    )]
    fn chunk_output(chunk: &[u8], chunk_counter: u64, key: &[u32; 8], flags: u32) -> Output {
        let blocks = chunk.len().div_ceil(BLOCK_LEN).max(1);
        let mut cv = *key;
        let (head, last) = chunk.split_at((blocks - 1) * BLOCK_LEN);
        for (i, block) in head.chunks(BLOCK_LEN).enumerate() {
            let block_flags = flags | if i == 0 { CHUNK_START } else { 0 };
            cv = first_8_words(&compress(
                &cv,
                &words_from_le_bytes(block),
                chunk_counter,
                BLOCK_LEN as u32,
                block_flags,
            ));
        }
        let block_flags = flags | CHUNK_END | if blocks == 1 { CHUNK_START } else { 0 };
        Output {
            cv,
            block_words: words_from_le_bytes(last),
            counter: chunk_counter,
            block_len: last.len() as u32,
            flags: block_flags,
        }
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "BLAKE3 block length is `BLOCK_LEN` = 64 bytes, well within `u32`"
    )]
    fn parent_output(left: &[u32; 8], right: &[u32; 8], key: &[u32; 8], flags: u32) -> Output {
        let mut block_words = [0u32; 16];
        block_words[..8].copy_from_slice(left);
        block_words[8..].copy_from_slice(right);
        Output { cv: *key, block_words, counter: 0, block_len: BLOCK_LEN as u32, flags: PARENT | flags }
    }

    struct Output {
        cv: [u32; 8],
        block_words: [u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    }

    impl Output {
        fn chaining_value(&self) -> [u32; 8] {
            first_8_words(&compress(&self.cv, &self.block_words, self.counter, self.block_len, self.flags))
        }

        fn root_output(&self) -> [u8; 32] {
            let words = compress(&self.cv, &self.block_words, 0, self.block_len, self.flags | ROOT);
            let mut out = [0u8; 32];
            for (bytes, word) in out.chunks_mut(4).zip(&words) {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
            out
        }
    }

    fn first_8_words(compressed: &[u32; 16]) -> [u32; 8] {
        let mut cv = [0u32; 8];
        cv.copy_from_slice(&compressed[..8]);
        cv
    }

    #[expect(clippy::cast_possible_truncation, reason = "BLAKE3 splits the 64-bit counter into two 32-bit state words")]
    fn compress(cv: &[u32; 8], block_words: &[u32; 16], counter: u64, block_len: u32, flags: u32) -> [u32; 16] {
        let mut state = [0u32; 16];
        state[..8].copy_from_slice(cv);
        state[8..12].copy_from_slice(&IV[..4]);
        state[12] = counter as u32;
        state[13] = (counter >> 32) as u32;
        state[14] = block_len;
        state[15] = flags;
        let mut block = *block_words;
        round(&mut state, &block);
        for _ in 0..6 {
            permute(&mut block);
            round(&mut state, &block);
        }
        let mut out = [0u32; 16];
        for (word, (lo, hi)) in out.iter_mut().zip(state[..8].iter().zip(&state[8..])) {
            *word = lo ^ hi;
        }
        for (word, (s, c)) in out.iter_mut().skip(8).zip(state[8..].iter().zip(cv)) {
            *word = s ^ c;
        }
        out
    }

    fn round(state: &mut [u32; 16], m: &[u32; 16]) {
        g(state, 0, 4, 8, 12, m[0], m[1]);
        g(state, 1, 5, 9, 13, m[2], m[3]);
        g(state, 2, 6, 10, 14, m[4], m[5]);
        g(state, 3, 7, 11, 15, m[6], m[7]);
        g(state, 0, 5, 10, 15, m[8], m[9]);
        g(state, 1, 6, 11, 12, m[10], m[11]);
        g(state, 2, 7, 8, 13, m[12], m[13]);
        g(state, 3, 4, 9, 14, m[14], m[15]);
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "BLAKE3's G takes the four state-slot indexes and two message words as the spec defines them"
    )]
    #[expect(
        clippy::indexing_slicing,
        reason = "a, b, c, d are BLAKE3's fixed quarter-round slot indexes, always within the 16-word state; the const fn cannot use bounds-checked slice access"
    )]
    const fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    fn permute(block: &mut [u32; 16]) {
        let mut permuted = [0u32; 16];
        for (dst, src) in permuted.iter_mut().zip(MSG_PERMUTATION) {
            *dst = block.get(src).copied().unwrap_or_default();
        }
        *block = permuted;
    }

    fn words_from_le_bytes(block: &[u8]) -> [u32; 16] {
        let mut words = [0u32; 16];
        for (word, bytes) in words.iter_mut().zip(block.chunks(4)) {
            let mut buf = [0u8; 4];
            let (head, _) = buf.split_at_mut(bytes.len());
            head.copy_from_slice(bytes);
            *word = u32::from_le_bytes(buf);
        }
        words
    }
}

#[cfg(test)]
mod aead_open_tests {
    use super::*;

    #[test]
    fn open_in_place_rejects_short_ciphertext_instead_of_panicking() {
        let mut aead = AEAD::new(b"ctx", &[7u8; 32], true);
        let mut buf = vec![1u8, 2, 3];
        let err = aead.open_in_place(&mut buf, Some(&MAX_NONCE), 3, &[]).unwrap_err();
        assert_eq!("cipher: message authentication failed", err.to_string());
    }

    #[test]
    fn open_into_rejects_short_ciphertext_instead_of_panicking() {
        let mut aead = AEAD::new(b"ctx", &[7u8; 32], true);
        let mut dst = vec![0u8; 4];
        let err = aead.open_into(&mut dst, Some(&MAX_NONCE), &[1, 2, 3], &[]).unwrap_err();
        assert_eq!("cipher: message authentication failed", err.to_string());
    }

    #[test]
    fn open_alloc_rejects_short_ciphertext_instead_of_panicking() {
        let mut aead = AEAD::new(b"ctx", &[7u8; 32], true);
        let err = aead.open_alloc(Some(&MAX_NONCE), &[1, 2, 3], &[]).unwrap_err();
        assert_eq!("cipher: message authentication failed", err.to_string());
    }

    #[test]
    fn open_in_place_still_authenticates_a_well_formed_message() {
        let key = [9u8; 32];
        let mut sealer = AEAD::new(b"ctx", &key, true);
        let mut opener = AEAD::new(b"ctx", &key, true);
        let plaintext = b"hello vless";
        let mut dst = vec![0u8; plaintext.len() + 16];
        sealer.seal(&mut dst, Some(&MAX_NONCE), plaintext, &[]).unwrap();
        let dst_len = dst.len();
        opener.open_in_place(&mut dst, Some(&MAX_NONCE), dst_len, &[]).unwrap();
        assert_eq!(plaintext, &dst[..plaintext.len()]);
    }
}

#[cfg(test)]
mod common_conn_write_tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Mutex;

    use super::*;

    /// A `Conn` whose `poll_write` reports `Pending` on its first call (after registering the
    /// waker, matching real backpressure) and then accepts the retry in full, so a caller of
    /// `CommonConn::poll_write` is forced through exactly the partial-frame-then-retry path that
    /// [`CommonConn::poll_write`] must handle without re-consuming the buffer it already sealed.
    struct FlakyConn {
        pending_once: bool,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl FlakyConn {
        fn new(written: Arc<Mutex<Vec<u8>>>) -> Self {
            Self { pending_once: true, written }
        }
    }

    impl AsyncRead for FlakyConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for FlakyConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.pending_once {
                this.pending_once = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.written.lock().expect("mutex").extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for FlakyConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }
    }

    const KEY: [u8; 32] = [7u8; 32];

    fn make_common_conn(written: Arc<Mutex<Vec<u8>>>) -> CommonConn {
        let mut conn = CommonConn::new(Box::new(FlakyConn::new(written)), true);
        conn.aead = Some(AEAD::new(b"test-ctx", &KEY, true));
        conn.united_key = KEY.to_vec();
        conn
    }

    /// Decodes the one frame `CommonConn::poll_write` should have produced from `plaintext` and
    /// returns its payload, failing loudly if the wire instead carries more than one frame (the
    /// shape a re-sealed duplicate would take).
    fn decode_single_frame(wire: &[u8]) -> Vec<u8> {
        let mut opener = AEAD::new(b"test-ctx", &KEY, true);
        let header: [u8; 5] = wire[..5].try_into().expect("header");
        let (ciphertext_len, err) = decode_header(&header);
        assert!(err.is_none(), "unexpected header error");
        assert_eq!(wire.len(), 5 + ciphertext_len, "wire carries more than the one expected frame");
        opener.open_alloc(None, &wire[5..], &header).expect("frame authenticates")
    }

    #[test]
    fn poll_write_does_not_recount_a_frame_sealed_by_an_earlier_pending_call() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_common_conn(Arc::clone(&written));
        let plaintext = vec![0x42u8; 74];
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut conn).poll_write(&mut cx, &plaintext);
        assert!(matches!(first, Poll::Pending), "first attempt must observe the underlying Pending");

        let second = Pin::new(&mut conn).poll_write(&mut cx, &plaintext);
        let Poll::Ready(Ok(n)) = second else { panic!("expected the retry to complete: {second:?}") };
        assert!(n <= plaintext.len(), "poll_write reported {n} > buf.len() {}", plaintext.len());
        assert_eq!(n, plaintext.len());

        let wire = written.lock().expect("mutex").clone();
        assert_eq!(decode_single_frame(&wire), plaintext);
    }

    #[test]
    fn poll_write_vectored_does_not_recount_a_frame_sealed_by_an_earlier_pending_call() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_common_conn(Arc::clone(&written));
        let plaintext = vec![0x24u8; 68];
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let iov = [io::IoSlice::new(&plaintext)];

        let first = Pin::new(&mut conn).poll_write_vectored(&mut cx, &iov);
        assert!(matches!(first, Poll::Pending), "first attempt must observe the underlying Pending");

        let second = Pin::new(&mut conn).poll_write_vectored(&mut cx, &iov);
        let Poll::Ready(Ok(n)) = second else { panic!("expected the retry to complete: {second:?}") };
        assert!(n <= plaintext.len(), "poll_write_vectored reported {n} > total requested {}", plaintext.len());
        assert_eq!(n, plaintext.len());

        let wire = written.lock().expect("mutex").clone();
        assert_eq!(decode_single_frame(&wire), plaintext);
    }
}

#[cfg(test)]
mod peer_frame_len_tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    /// A `Conn` whose `poll_read` serves a fixed sequence of chunks: `Some(data)` fills `buf`
    /// with `data` and completes; `None` reports `Pending` once (waking the waker so a retry is
    /// well-formed), simulating a peer that delivers the 5-byte frame header, then stalls, then
    /// delivers the frame body across several short reads.
    struct PieceConn {
        chunks: VecDeque<Option<Vec<u8>>>,
    }

    impl PieceConn {
        fn new(chunks: Vec<Option<Vec<u8>>>) -> Self {
            Self { chunks: chunks.into() }
        }
    }

    impl AsyncRead for PieceConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            match this.chunks.pop_front() {
                None => Poll::Ready(Ok(())),
                Some(None) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Some(Some(data)) => {
                    let n = data.len().min(buf.remaining());
                    buf.put_slice(&data[..n]);
                    if n < data.len() {
                        this.chunks.push_front(Some(data[n..].to_vec()));
                    }
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    impl AsyncWrite for PieceConn {
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

    impl Stream for PieceConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }
    }

    const KEY: [u8; 32] = [9u8; 32];

    /// Chunks a mock peer's wire bytes into `piece_len`-sized reads, each preceded by one
    /// `Pending` so the caller must resume mid-frame rather than seeing the whole body at once.
    fn stall_between_pieces(wire: &[u8], piece_len: usize) -> Vec<Option<Vec<u8>>> {
        let mut chunks = Vec::new();
        for piece in wire.chunks(piece_len) {
            chunks.push(None);
            chunks.push(Some(piece.to_vec()));
        }
        chunks
    }

    /// Polls `conn` to fill `out` completely, looping past every `Pending` the way a real
    /// executor's repeated wakeups would, and fails loudly on a short or erroring `Ready`.
    fn read_exact_polling(conn: &mut CommonConn, out: &mut [u8]) {
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut read_buf = ReadBuf::new(out);
        loop {
            match Pin::new(&mut *conn).poll_read(&mut cx, &mut read_buf) {
                Poll::Ready(Ok(())) => break,
                Poll::Ready(Err(err)) => panic!("poll_read failed: {err}"),
                Poll::Pending => {}
            }
        }
        assert_eq!(read_buf.filled().len(), read_buf.capacity(), "short read");
    }

    /// A peer frame whose header arrives whole, then a `Pending` stall, then the body arrives in
    /// several short pieces (each also preceded by a stall) must round-trip with no dropped or
    /// duplicated bytes: `CommonConn::poll_read` must resume the body read on retry rather than
    /// re-decoding a fresh header (the `peer_frame_len` guard `common.rs` line ~397). Mutating
    /// that guard to always re-read the header makes this test fail, because the mock peer's next
    /// queued bytes are body bytes, not a valid header.
    #[test]
    fn poll_read_resumes_body_after_pending_without_redecoding_header() {
        let plaintext: Vec<u8> = (0..40u8).collect();
        let ciphertext_len = plaintext.len() + 16;
        let mut header = [0u8; 5];
        encode_header(&mut header, ciphertext_len);

        let mut sealer = AEAD::new(b"peer_frame_len test", &KEY, true);
        let mut wire = vec![0u8; ciphertext_len];
        sealer.seal(&mut wire, None, &plaintext, &header).expect("seal test frame");

        let mut chunks = vec![Some(header.to_vec())];
        chunks.extend(stall_between_pieces(&wire, 7));

        let mut conn = CommonConn::new(Box::new(PieceConn::new(chunks)), true);
        conn.peer_aead = Some(AEAD::new(b"peer_frame_len test", &KEY, true));
        conn.united_key = KEY.to_vec();

        let mut received = vec![0u8; plaintext.len()];
        read_exact_polling(&mut conn, &mut received);

        assert_eq!(received, plaintext, "payload must round-trip with no dropped or duplicated bytes");
    }
}

#[cfg(test)]
mod close_forwarding_tests {
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    use murmur_common_net::io::{OldConnAsStream, StreamAsOldConn};
    use murmur_std_compat::net::Conn as NetConn;

    use super::*;

    /// Regression for the `old_conn()` forwarding this unit adds through `CommonConn`'s new
    /// `Stream` impl: `StreamAsOldConn::close()` walks `Stream::old_conn()` down through
    /// `CommonConn` and `InnerConn` to the `OldConnAsStream`-wrapped real `TcpStream` at the
    /// bottom of the chain. Without that forwarding, `close()` would only shut down the bridge's
    /// own halves and the peer would never see the TCP FIN.
    #[tokio::test]
    async fn common_conn_close_reaches_the_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");
        let client = TcpStream::connect(addr).await.expect("connect loopback client");
        let (mut server, _) = listener.accept().await.expect("accept loopback client");

        let common: Box<dyn Stream> = Box::new(CommonConn::new(Box::new(OldConnAsStream(client)), false));
        let old_conn = StreamAsOldConn::new(common);

        old_conn.close().expect("close must succeed");

        let mut buf = [0u8; 8];
        let n = server.read(&mut buf).await.expect("server read after peer close");
        assert_eq!(n, 0, "server must observe EOF once CommonConn's close reaches the real socket through old_conn()");
    }
}

#[cfg(test)]
mod direct_handoff_tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::encryption::factory::{new_client, new_server};
    use crate::encryption::key::{gen_mlkem768, gen_x25519};
    use tokio::net::{TcpListener, TcpStream};

    /// A frame larger than the caller's read leaves decrypted plaintext buffered below. The direct
    /// handle must deliver that plaintext before switching, then bypass the encryption framing in
    /// both directions.
    #[tokio::test]
    async fn direct_handoff_drains_buffered_plaintext_then_bypasses_encryption() {
        let (seed, client_key, _) = gen_mlkem768("").expect("gen_mlkem768");
        let (private_key, password, _) = gen_x25519("").expect("gen_x25519");
        let decryption = format!("mlkem768x25519plus.native.600s.{private_key}.{seed}");
        let encryption = format!("mlkem768x25519plus.native.0rtt.{password}.{client_key}");

        let client_instance = Arc::new(new_client(&encryption).expect("client config").expect("client instance"));
        let server_instance = Arc::new(new_server(&decryption).expect("server config").expect("server instance"));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener address");
        let (client_io, server_io) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let client_stream: Box<dyn Stream> = Box::new(client_io.expect("connect"));
        let server_stream: Box<dyn Stream> = Box::new(server_io.expect("accept").0);
        let (client_conn, server_conn) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(client_instance.handshake(client_stream), server_instance.handshake(server_stream, None),)
        })
        .await
        .expect("encryption handshake timed out");
        let client_conn = client_conn.expect("client handshake");
        let mut server_conn = server_conn.expect("server handshake");

        let shared = SharedCommonConn::new(client_conn);
        let mut normal = shared.clone();
        let mut direct = shared.direct();

        let message = b"buffered-direct-payload";
        server_conn.write_all(message).await.expect("server write");
        server_conn.flush().await.expect("server flush");

        let mut prefix = [0u8; 4];
        normal.read_exact(&mut prefix).await.expect("prefix read");
        assert_eq!(&prefix, &message[..4]);
        // Consume part of the decrypted surplus through the normal handle first, so the direct
        // drain starts at a nonzero offset. Taking only the unread suffix must also clear the
        // consumed prefix; otherwise the next direct read replays it into the raw stream.
        let mut second = [0u8; 4];
        normal.read_exact(&mut second).await.expect("buffered prefix read");
        assert_eq!(&second, &message[4..8]);

        let mut buffered = vec![0u8; message.len() - 8];
        direct.read_exact(&mut buffered).await.expect("buffered direct read");
        assert_eq!(&buffered, &message[8..]);

        server_conn.conn.write_all(b"raw-downlink").await.expect("raw server write");
        server_conn.conn.flush().await.expect("raw server flush");
        let mut raw_down = [0u8; 12];
        direct.read_exact(&mut raw_down).await.expect("raw direct read");
        assert_eq!(&raw_down, b"raw-downlink");

        direct.write_all(b"raw-uplink").await.expect("raw direct write");
        direct.flush().await.expect("raw direct flush");
        let mut raw_up = [0u8; 10];
        server_conn.conn.read_exact(&mut raw_up).await.expect("raw server read");
        assert_eq!(&raw_up, b"raw-uplink");
    }
}

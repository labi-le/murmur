use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use ctr::Ctr128BE;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common_net::io::Stream;

use super::common::{decode_header, poll_write_all};

/// The AES-CTR keystream cipher.
pub struct AesCtrStream {
    cipher: Ctr128BE<Aes256>,
}

impl core::fmt::Debug for AesCtrStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesCtrStream").finish_non_exhaustive()
    }
}

impl AesCtrStream {
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "`new` has an infallible signature; `blake3::derive_key` always yields 32 bytes, so only a wrong-width caller iv can reach the expect"
    )]
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        let k = blake3::derive_key("VLESS", key); // avoids using key directly
        Self { cipher: Ctr128BE::<Aes256>::new_from_slices(&k, iv).expect("16-byte AES-CTR IV") }
    }

    /// XORs the keystream into the buffer in place.
    pub(crate) fn xor_key_stream(&mut self, buf: &mut [u8]) {
        self.cipher.apply_keystream(buf);
    }

    /// XORs the keystream from one buffer into a distinct one.
    pub(crate) fn xor_key_stream_b2b(&mut self, src: &[u8], dst: &mut [u8]) {
        self.cipher.apply_keystream_b2b(src, dst);
    }
}

pub struct XorConn {
    pub conn: Box<dyn Stream>,
    pub ctr: AesCtrStream,
    pub peer_ctr: Option<AesCtrStream>,
    pub out_skip: usize,
    pub out_header: Vec<u8>,
    pub in_skip: usize,
    pub in_header: Vec<u8>,
    /// Scratch buffer for the keystream-applied copy of the caller's bytes, written instead of
    /// padding the caller's buffer in place.
    write_buf: Vec<u8>,
    write_buf_sent: usize,
    write_buf_plain: usize,
}

impl core::fmt::Debug for XorConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XorConn").finish_non_exhaustive()
    }
}

impl XorConn {
    #[must_use]
    pub fn new(
        conn: Box<dyn Stream>,
        ctr: AesCtrStream,
        peer_ctr: Option<AesCtrStream>,
        out_skip: usize,
        in_skip: usize,
    ) -> Self {
        Self {
            conn,
            ctr,
            peer_ctr,
            out_skip,
            out_header: Vec::with_capacity(5),
            in_skip,
            in_header: Vec::with_capacity(5),
            write_buf: Vec::new(),
            write_buf_sent: 0,
            write_buf_plain: 0,
        }
    }

    /// The outgoing keystream loop, applied to the copy that is written out.
    fn apply_out_keystream(&mut self, out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(b);
        let mut pos = 0;
        loop {
            if out.len() - pos <= self.out_skip {
                self.out_skip -= out.len() - pos;
                break;
            }
            pos += self.out_skip;
            self.out_skip = 0;
            let need = 5 - self.out_header.len();
            let (_, rest) = out.split_at_mut(pos);
            if rest.len() < need {
                self.out_header.extend_from_slice(rest);
                self.ctr.xor_key_stream(rest);
                break;
            }
            let (chunk, _) = rest.split_at_mut(need);
            let mut header = [0u8; 5];
            let (head, tail) = header.split_at_mut(self.out_header.len());
            head.copy_from_slice(&self.out_header);
            tail.copy_from_slice(chunk);
            let (l, _) = decode_header(&header);
            self.out_skip = l;
            self.out_header.clear();
            self.ctr.xor_key_stream(chunk);
            pos += need;
        }
    }

    /// The incoming keystream loop, applied to the bytes the conn just produced. The peer counter is
    /// only dereferenced once `in_skip` is exceeded: a chunk that falls entirely inside the skip
    /// window never touches `peer_ctr` at all, which is the client's 0-RTT case — the early-return
    /// handshake leaves `peer_ctr` unset until the first real read, with `in_skip` wide enough
    /// to cover the server's unskip-needing random prefix. Checking `peer_ctr.is_none()` up front,
    /// before the skip check, rejected that still-covered chunk instead of consuming it.
    fn apply_in_keystream(&mut self, data: &mut [u8]) -> io::Result<()> {
        let end = data.len();
        let mut pos = 0;
        loop {
            if end - pos <= self.in_skip {
                self.in_skip -= end - pos;
                break;
            }
            pos += self.in_skip;
            self.in_skip = 0;
            let Some(peer_ctr) = self.peer_ctr.as_mut() else {
                return Err(io::Error::other("xor conn peer ctr is nil"));
            };
            let need = 5 - self.in_header.len();
            let (_, rest) = data.split_at_mut(pos);
            if rest.len() < need {
                peer_ctr.xor_key_stream(rest);
                self.in_header.extend_from_slice(rest);
                break;
            }
            let (chunk, _) = rest.split_at_mut(need);
            peer_ctr.xor_key_stream(chunk);
            let mut header = [0u8; 5];
            let (head, tail) = header.split_at_mut(self.in_header.len());
            head.copy_from_slice(&self.in_header);
            tail.copy_from_slice(chunk);
            let (l, _) = decode_header(&header);
            self.in_skip = l;
            self.in_header.clear();
            pos += need;
        }
        Ok(())
    }
}

impl AsyncWrite for XorConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.write_buf.is_empty() {
            let mut out = std::mem::take(&mut this.write_buf);
            this.apply_out_keystream(&mut out, buf);
            this.write_buf = out;
            this.write_buf_sent = 0;
            this.write_buf_plain = buf.len();
        }
        ready!(poll_write_all(&mut *this.conn, cx, &this.write_buf, &mut this.write_buf_sent))?;
        let plain = this.write_buf_plain;
        this.write_buf.clear();
        this.write_buf_sent = 0;
        this.write_buf_plain = 0;
        Poll::Ready(Ok(plain))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.conn).poll_shutdown(cx)
    }
}

impl AsyncRead for XorConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let filled_before = buf.filled().len();
        let poll = Pin::new(&mut *this.conn).poll_read(cx, buf);
        let filled = buf.filled().len();
        if filled > filled_before {
            let start = filled_before;
            let (_, after_start) = buf.filled_mut().split_at_mut(start);
            let (region, _) = after_start.split_at_mut(filled - start);
            if let Err(err) = this.apply_in_keystream(region) {
                return Poll::Ready(Err(err));
            }
        }
        poll
    }
}

impl Stream for XorConn {
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

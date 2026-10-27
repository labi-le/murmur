use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common_net::io::Stream as NetStream;
use murmur_common_pool as pool;

use super::protocol::Protocol;

/// The protocol wrapper around a stream connection.
pub struct Conn {
    inner: Box<dyn NetStream>,
    protocol: Box<dyn Protocol>,
    decoded: BytesMut,
    under_decoded: BytesMut,
    pending: Option<(BytesMut, usize)>,
    pending_length: usize,
}

impl core::fmt::Debug for Conn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Conn").field("pending_length", &self.pending_length).finish_non_exhaustive()
    }
}

impl Conn {
    #[must_use]
    pub fn new(conn: Box<dyn NetStream>, protocol: Box<dyn Protocol>) -> Self {
        Self {
            inner: conn,
            protocol,
            decoded: BytesMut::new(),
            under_decoded: BytesMut::new(),
            pending: None,
            pending_length: 0,
        }
    }
}

/// Reads out of the protocol's decoded buffer.
fn copy_out(decoded: &mut BytesMut, b: &mut ReadBuf<'_>) {
    let n = decoded.len().min(b.remaining());
    if let Some(head) = decoded.get(..n) {
        b.put_slice(head);
    }
    let _ = decoded.split_to(n);
}

/// Writes `buf` in full.
fn poll_write_all<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    cx: &mut Context<'_>,
    buf: &[u8],
    sent: &mut usize,
) -> Poll<io::Result<()>> {
    while *sent < buf.len() {
        let (_, rest) = buf.split_at(*sent);
        match Pin::new(&mut *w).poll_write(cx, rest) {
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

impl AsyncRead for Conn {
    ///
    /// One chunk is read from the socket and decoded before the read answers; a poll cannot retry,
    /// so the decoded bytes a read produced but the caller's buffer did not take stay in `decoded`,
    /// and a chunk that decoded to nothing loops back for the next one instead of reporting a
    /// zero-length read, which would read as end of stream.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.decoded.is_empty() {
            let mut buf = pool::get(pool::RELAY_BUFFER_SIZE);
            let read = {
                let mut read_buf = ReadBuf::new(&mut buf);
                match Pin::new(&mut *this.inner).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
                    Poll::Ready(Err(err)) => Err(err),
                    Poll::Pending => {
                        pool::put(buf).ok();
                        return Poll::Pending;
                    }
                }
            };
            let n = match read {
                Ok(n) => n,
                Err(err) => {
                    pool::put(buf).ok();
                    return Poll::Ready(Err(err));
                }
            };
            if n == 0 {
                pool::put(buf).ok();
                return Poll::Ready(Ok(()));
            }

            let (filled, _) = buf.split_at(n);
            this.under_decoded.extend_from_slice(filled);
            pool::put(buf).ok();

            if let Err(err) = this.protocol.decode(&mut this.decoded, &mut this.under_decoded) {
                return Poll::Ready(Err(io::Error::other(err)));
            }
        }
        copy_out(&mut this.decoded, b);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Conn {
    ///
    /// The encoded bytes are built once and written in full; they are kept along with how far the
    /// socket has taken them, so a partial write resumes instead of re-encoding.
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if b.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if this.pending.is_none() {
            let b_length = b.len();
            let mut buf = pool::get_buffer();
            if let Err(err) = this.protocol.encode(&mut buf, b) {
                pool::put_buffer(buf);
                return Poll::Ready(Err(io::Error::other(err)));
            }
            this.pending = Some((buf, 0));
            this.pending_length = b_length;
        }

        let Some((buf, sent)) = this.pending.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        ready!(poll_write_all(&mut *this.inner, cx, buf, sent))?;

        if let Some((written, _)) = this.pending.take() {
            pool::put_buffer(written);
        }
        Poll::Ready(Ok(this.pending_length))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl NetStream for Conn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.inner.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.inner.old_conn()
    }
}

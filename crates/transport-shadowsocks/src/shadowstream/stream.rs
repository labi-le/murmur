use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use cipher::StreamCipher;
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use murmur_common_net::io::Stream as NetStream;

use super::cipher::Cipher;

pub const BUF_SIZE: usize = 2048;

/// The unexpected-EOF error reported for a truncated IV.
fn err_unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

/// Writes `buf` in full, remembering how far a partial write got.
fn poll_write_all<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    cx: &mut Context<'_>,
    buf: &[u8],
    sent: &mut usize,
) -> Poll<io::Result<()>> {
    while *sent < buf.len() {
        let Some(unsent) = buf.get(*sent..) else {
            break;
        };
        match Pin::new(&mut *w).poll_write(cx, unsent) {
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

/// The reader's cipher side: the stream and the scratch buffer.
///
/// A reader would share its `Conn`'s stream, but Rust gives a value one owner, so the conn stays
/// in the `Conn` and the reader and writer sides are split off here.
struct ReadCipher {
    s: Box<dyn StreamCipher + Send + Sync>,
    buf: [u8; BUF_SIZE],
}

impl ReadCipher {
    fn new(s: Box<dyn StreamCipher + Send + Sync>) -> Self {
        Self { s, buf: [0u8; BUF_SIZE] }
    }

    fn poll_read_from<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        r: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buf.filled().len();
        match Pin::new(r).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled().len();
                let start = filled_before.min(filled);
                let filled_mut = buf.filled_mut();
                let (_, tail) = filled_mut.split_at_mut(start);
                let (region, _) = tail.split_at_mut(filled - start);
                self.s.apply_keystream(region);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                // Report `0, err`, dropping the bytes the read had produced.
                buf.set_filled(filled_before);
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    async fn write_to_source<R, W>(&mut self, r: &mut R, w: &mut W) -> io::Result<u64>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        let mut n: u64 = 0;
        loop {
            let nr = r.read(&mut self.buf).await?;
            if nr > 0 {
                let (chunk, _) = self.buf.split_at_mut(nr);
                self.s.apply_keystream(chunk);
                w.write_all(chunk).await?;
                n += nr as u64;
            }
            if nr == 0 {
                return Ok(n);
            }
        }
    }
}

/// The writer's cipher side: the stream, the scratch buffer and the pending chunk of a write.
struct WriteCipher {
    s: Box<dyn StreamCipher + Send + Sync>,
    buf: [u8; BUF_SIZE],
    pending: usize,
    sent: usize,
}

impl WriteCipher {
    fn new(s: Box<dyn StreamCipher + Send + Sync>) -> Self {
        Self { s, buf: [0u8; BUF_SIZE], pending: 0, sent: 0 }
    }

    /// Encrypts one chunk of at most `BUF_SIZE` bytes per iteration.
    ///
    /// A poll cannot retry the way the loop does, so the encrypted chunk stays pending until the
    /// sink has taken all of it.
    fn poll_write_to<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        w: &mut W,
        cx: &mut Context<'_>,
        p: &[u8],
    ) -> Poll<io::Result<usize>> {
        if p.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pending == 0 {
            let end = p.len().min(BUF_SIZE);
            let (dst, _) = self.buf.split_at_mut(end);
            let (head, _) = p.split_at(end);
            dst.copy_from_slice(head);
            self.s.apply_keystream(dst);
            self.pending = end;
            self.sent = 0;
        }
        let (pending, _) = self.buf.split_at(self.pending);
        ready!(poll_write_all(w, cx, pending, &mut self.sent))?;
        let n = self.pending;
        self.pending = 0;
        self.sent = 0;
        Poll::Ready(Ok(n))
    }

    async fn read_from_source<R, W>(&mut self, r: &mut R, w: &mut W) -> io::Result<u64>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        let mut n: u64 = 0;
        loop {
            let nr = r.read(&mut self.buf).await?;
            n += nr as u64;
            let (chunk, _) = self.buf.split_at_mut(nr);
            self.s.apply_keystream(chunk);
            w.write_all(chunk).await?;
            if nr == 0 {
                return Ok(n);
            }
        }
    }
}

pub struct Writer {
    w: Box<dyn AsyncWrite + Send + Sync + Unpin>,
    cipher: WriteCipher,
}

impl fmt::Debug for Writer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Writer").finish_non_exhaustive()
    }
}

#[must_use]
pub fn new_writer(w: Box<dyn AsyncWrite + Send + Sync + Unpin>, s: Box<dyn StreamCipher + Send + Sync>) -> Writer {
    Writer { w, cipher: WriteCipher::new(s) }
}

impl Writer {
    pub async fn read_from<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> io::Result<u64> {
        self.cipher.read_from_source(r, &mut *self.w).await
    }
}

impl AsyncWrite for Writer {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.cipher.poll_write_to(&mut *this.w, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().w).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().w).poll_shutdown(cx)
    }
}

pub struct Reader {
    r: Box<dyn AsyncRead + Send + Sync + Unpin>,
    cipher: ReadCipher,
}

impl fmt::Debug for Reader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reader").finish_non_exhaustive()
    }
}

#[must_use]
pub fn new_reader(r: Box<dyn AsyncRead + Send + Sync + Unpin>, s: Box<dyn StreamCipher + Send + Sync>) -> Reader {
    Reader { r, cipher: ReadCipher::new(s) }
}

impl Reader {
    pub async fn write_to<W: AsyncWrite + Unpin>(&mut self, w: &mut W) -> io::Result<u64> {
        self.cipher.write_to_source(&mut *self.r, w).await
    }
}

impl AsyncRead for Reader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.cipher.poll_read_from(&mut *this.r, cx, buf)
    }
}

/// `Conn`, a stream-oriented conn with the cipher applied to its payload.
pub struct Conn {
    inner: Box<dyn NetStream>,
    cipher: Box<dyn Cipher>,
    r: Option<ReadCipher>,
    w: Option<WriteCipher>,
    read_iv: Vec<u8>,
    read_iv_read: usize,
    write_iv: Vec<u8>,
    write_iv_sent: usize,
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn").finish_non_exhaustive()
    }
}

#[must_use]
pub fn new_conn(c: Box<dyn NetStream>, ciph: Box<dyn Cipher>) -> Conn {
    Conn {
        inner: c,
        cipher: ciph,
        r: None,
        w: None,
        read_iv: Vec::new(),
        read_iv_read: 0,
        write_iv: Vec::new(),
        write_iv_sent: 0,
    }
}

impl Conn {
    /// The write IV, drawn once and then kept.
    pub fn obtain_write_iv(&mut self) -> io::Result<&[u8]> {
        self.ensure_write_iv()?;
        Ok(&self.write_iv)
    }

    fn ensure_write_iv(&mut self) -> io::Result<()> {
        let iv_size = self.cipher.iv_size();
        if self.write_iv.len() == iv_size {
            return Ok(());
        }
        let mut iv = vec![0u8; iv_size];
        OsRng.try_fill_bytes(&mut iv).map_err(io::Error::other)?;
        self.write_iv = iv;
        Ok(())
    }

    /// The read IV, read once from the conn and then kept.
    pub async fn obtain_read_iv(&mut self) -> io::Result<Vec<u8>> {
        if self.read_iv_obtained() {
            return Ok(self.read_iv.clone());
        }
        let iv_size = self.cipher.iv_size();
        let mut iv = vec![0u8; iv_size];
        self.inner.read_exact(&mut iv).await?;
        self.read_iv.clone_from(&iv);
        self.read_iv_read = iv_size;
        Ok(iv)
    }

    fn read_iv_obtained(&self) -> bool {
        self.read_iv.len() == self.cipher.iv_size() && self.read_iv_read == self.read_iv.len()
    }

    /// Reads the read IV, then starts the reader.
    fn poll_init_reader(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.r.is_some() {
            return Poll::Ready(Ok(()));
        }
        if !self.read_iv_obtained() {
            let iv_size = self.cipher.iv_size();
            if self.read_iv.len() != iv_size {
                self.read_iv = vec![0u8; iv_size];
                self.read_iv_read = 0;
            }
            while self.read_iv_read < iv_size {
                let start = self.read_iv_read;
                let filled = {
                    let (_, unread) = self.read_iv.split_at_mut(start);
                    let mut buf = ReadBuf::new(unread);
                    ready!(Pin::new(&mut *self.inner).poll_read(cx, &mut buf))?;
                    buf.filled().len()
                };
                if filled == 0 {
                    return Poll::Ready(Err(err_unexpected_eof()));
                }
                self.read_iv_read += filled;
            }
        }
        self.r = Some(ReadCipher::new(self.cipher.decrypter(&self.read_iv)));
        Poll::Ready(Ok(()))
    }

    /// Draws the write IV, sends it, then starts the writer.
    fn poll_init_writer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.w.is_some() {
            return Poll::Ready(Ok(()));
        }
        if let Err(err) = self.ensure_write_iv() {
            return Poll::Ready(Err(err));
        }
        ready!(poll_write_all(&mut *self.inner, cx, &self.write_iv, &mut self.write_iv_sent))?;
        self.write_iv_sent = 0;
        self.w = Some(WriteCipher::new(self.cipher.encrypter(&self.write_iv)));
        Poll::Ready(Ok(()))
    }

    pub async fn read_from<R: AsyncRead + Unpin + ?Sized>(&mut self, r: &mut R) -> io::Result<u64> {
        poll_fn(|cx| self.poll_init_writer(cx)).await?;
        let Some(w) = self.w.as_mut() else {
            return Err(io::Error::other("shadowstream: writer is not initialized"));
        };
        w.read_from_source(r, &mut *self.inner).await
    }

    pub async fn write_to<W: AsyncWrite + Unpin + ?Sized>(&mut self, w: &mut W) -> io::Result<u64> {
        poll_fn(|cx| self.poll_init_reader(cx)).await?;
        let Some(r) = self.r.as_mut() else {
            return Err(io::Error::other("shadowstream: reader is not initialized"));
        };
        r.write_to_source(&mut *self.inner, w).await
    }
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_init_reader(cx))?;
        let Some(r) = this.r.as_mut() else {
            return Poll::Ready(Err(io::Error::other("shadowstream: reader is not initialized")));
        };
        r.poll_read_from(&mut *this.inner, cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_init_writer(cx))?;
        let Some(w) = this.w.as_mut() else {
            return Poll::Ready(Err(io::Error::other("shadowstream: writer is not initialized")));
        };
        w.poll_write_to(&mut *this.inner, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl NetStream for Conn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
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

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::shadowstream::cipher::aesctr;

    #[tokio::test]
    async fn close_through_stream_as_old_conn_reaches_the_real_socket() {
        use murmur_common_net::io::StreamAsOldConn;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let server_task = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
        let client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut server = server_task.await.expect("server task");

        let cipher = aesctr(&[7u8; 16]).expect("cipher");
        let client_stream: Box<dyn NetStream> = Box::new(client);
        let conn = new_conn(client_stream, cipher);
        let old_conn: Box<dyn murmur_std_compat::net::Conn> = Box::new(StreamAsOldConn::new(conn));

        old_conn.close().expect("close");

        let mut buf = [0u8; 1];
        let n = server.read(&mut buf).await.expect("server sees the shutdown as EOF");
        assert_eq!(n, 0, "closing the outer bridge must shut down the real socket, not just the wrapper");
    }
}

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::WaitForCancellationFutureOwned;

use crate::io::{CancellableStream, DeadlineToken, Stream};
use murmur_common::atomic::type_::Bool;
use murmur_compat::sing_buf::Buffer;
use murmur_std_compat::net::{Addr, Conn as NetConn, TcpAddr};

#[must_use]
pub fn err_deadline_exceeded() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

/// The buffer-based half of an extended conn, reading and writing whole buffers.
#[async_trait]
pub trait BufferConn: Send + Sync {
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()>;
    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()>;
}

pub struct Conn {
    stream: CancellableStream<Box<dyn Stream>>,
    has_deadline: Bool,
    deadline_token: DeadlineToken,
    read_cancel: Option<(u64, Pin<Box<WaitForCancellationFutureOwned>>)>,
    disable_pipe: Bool,
    in_read: Bool,
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn").finish_non_exhaustive()
    }
}

pub fn is_conn(conn: &dyn std::any::Any) -> bool {
    conn.downcast_ref::<Conn>().is_some()
}

/// Wraps a stream in the deadline layer.
pub fn new_conn<C: Stream + 'static>(conn: C) -> Conn {
    Conn {
        stream: CancellableStream::new(Box::new(conn)),
        has_deadline: Bool::default(),
        deadline_token: DeadlineToken::new(),
        read_cancel: None,
        disable_pipe: Bool::default(),
        in_read: Bool::default(),
    }
}

impl Conn {
    pub fn reader_replaceable(&self) -> bool {
        self.disable_pipe.load() || !self.has_deadline.load()
    }

    pub fn writer_replaceable(&self) -> bool {
        true
    }
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.disable_pipe.load() {
            return Pin::new(&mut this.stream).poll_read(cx, buf);
        }
        if !this.has_deadline.load() {
            this.in_read.store(true);
            let result = Pin::new(&mut this.stream).poll_read(cx, buf);
            this.in_read.store(false);
            return result;
        }

        let (token, generation) = this.deadline_token.token_with_generation();
        if token.is_cancelled() {
            this.read_cancel = None;
            return Poll::Ready(Err(err_deadline_exceeded()));
        }
        match Pin::new(&mut this.stream).poll_read(cx, buf) {
            Poll::Ready(result) => {
                this.read_cancel = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                let ready = {
                    // A stale generation drops the cached waiter, which the insert below rebuilds.
                    if !matches!(&this.read_cancel, Some((gen, _)) if *gen == generation) {
                        this.read_cancel = None;
                    }
                    let (_, cancel) =
                        this.read_cancel.get_or_insert_with(|| (generation, Box::pin(token.cancelled_owned())));
                    cancel.as_mut().poll(cx).is_ready()
                };
                if ready {
                    this.read_cancel = None;
                    return Poll::Ready(Err(err_deadline_exceeded()));
                }
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

// S11: remove in U2, when component-tls accepts Stream.
impl NetConn for Conn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        let addr: Box<dyn Addr> = Box::new(TcpAddr::from(Stream::local_addr(&self.stream)?));
        Ok(addr)
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        let addr: Box<dyn Addr> = Box::new(TcpAddr::from(Stream::peer_addr(&self.stream)?));
        Ok(addr)
    }

    fn close(&self) -> io::Result<()> {
        self.stream.old_close()
    }

    fn close_read(&self) -> io::Result<()> {
        self.stream.old_close_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.stream.old_close_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.stream.old_set_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.stream.old_set_write_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        if self.stream.is_closed() {
            return self.stream.old_set_read_deadline(deadline);
        }
        if self.disable_pipe.load() {
            return self.stream.old_set_read_deadline(deadline);
        } else if self.in_read.load() {
            self.disable_pipe.store(true);
            return self.stream.old_set_read_deadline(deadline);
        }
        self.deadline_token.set(deadline);
        self.has_deadline.store(deadline.is_some());
        Ok(())
    }
}

impl Stream for Conn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        NetConn::close_read(self)
    }
    fn shutdown_write(&self) -> io::Result<()> {
        NetConn::close_write(self)
    }
    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(self)
    }
}

#[async_trait]
impl BufferConn for Conn {
    // NOT cancel-safe: a dropped read abandons the caller's read and can leave the pipe state latched.
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        if self.disable_pipe.load() {
            return read_from_stream(&mut self.stream, buffer).await;
        }
        if !self.has_deadline.load() {
            self.in_read.store(true);
            let result = read_from_stream(&mut self.stream, buffer).await;
            self.in_read.store(false);
            return result;
        }

        let token = self.deadline_token.token();
        if token.is_cancelled() {
            return Err(err_deadline_exceeded());
        }
        tokio::select! {
            result = read_from_stream(&mut self.stream, buffer) => result,
            () = token.cancelled() => Err(err_deadline_exceeded()),
        }
    }

    /// Writes `buffer` in full, releasing it afterwards.
    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        let result = tokio::io::AsyncWriteExt::write_all(&mut self.stream, buffer.bytes()).await;
        buffer.release();
        result
    }
}

/// Reads into `buffer` through the deadline wrapper's conn.
// cancel-safe: the underlying `AsyncReadExt::read` only commits the bytes it returns, so dropping the future leaves the buffer and the stream untouched.
async fn read_from_stream(stream: &mut CancellableStream<Box<dyn Stream>>, buffer: &mut Buffer) -> io::Result<()> {
    match tokio::io::AsyncReadExt::read(stream, buffer.free_bytes()).await {
        Ok(n) => {
            buffer.truncate(n);
            Ok(())
        }
        Err(err) => {
            buffer.truncate(0);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::time::Instant;

    use super::*;
    use crate::io::{ExtendedStream, Stream};

    struct Dx(DuplexStream);

    impl AsyncRead for Dx {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for Dx {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }
    impl Stream for Dx {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }
    }
    impl ExtendedStream for Dx {}

    /// Regression for `agent://ReviewNetS1`'s P2: `poll_read`'s cached `read_cancel` future used
    /// to survive a read dropped while `Pending` (e.g. a `timeout()` that gave up), so a later
    /// `set_read_deadline(None)` + re-arm left the next read racing the abandoned future and
    /// failing `TimedOut` immediately, even with data already on the wire. Live on every outbound
    /// conn via `common::net::sing::new_deadline_conn`. Fails on be7f135f.
    #[tokio::test]
    async fn dropped_read_then_clear_and_rearm_still_reads() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut conn = new_conn(Dx(reader));

        conn.set_read_deadline(Some(Instant::now() + Duration::from_millis(30))).unwrap();
        let mut buf = [0u8; 1];
        let dropped = tokio::time::timeout(Duration::from_millis(5), conn.read(&mut buf)).await;
        assert!(dropped.is_err(), "the read must still be Pending when it is dropped");

        tokio::time::sleep(Duration::from_millis(60)).await;
        conn.set_read_deadline(None).unwrap();
        conn.set_read_deadline(Some(Instant::now() + Duration::from_secs(60))).unwrap();

        writer.write_all(b"z").await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), conn.read_exact(&mut buf))
            .await
            .expect("must not hang")
            .expect("read after dropping a Pending read, then clearing and re-arming, must succeed");
        assert_eq!(buf[0], b'z');
    }

    #[tokio::test]
    async fn closed_deadline_conn_cannot_clear_its_read_deadline() {
        let (_peer, stream) = tokio::io::duplex(64);
        let conn = new_conn(Dx(stream));
        NetConn::close(&conn).unwrap();
        assert_eq!(conn.set_read_deadline(None).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }
}

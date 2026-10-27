use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_quic::hysteria::Stream;

#[derive(Clone)]
pub(crate) struct WrappedQuicStream(Arc<dyn Stream>);

impl WrappedQuicStream {
    pub(crate) fn new(stream: Arc<dyn Stream>) -> Self {
        Self(stream)
    }

    pub(crate) fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_read_deadline(deadline)
    }

    pub(crate) fn close(&self) -> io::Result<()> {
        self.0.cancel_read(0);
        self.0.close()
    }

    pub(crate) fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_write_deadline(deadline)
    }

    pub(crate) fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_deadline(deadline)
    }
}

impl AsyncRead for WrappedQuicStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.0.poll_read(cx, buf)
    }
}

impl AsyncWrite for WrappedQuicStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.0.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

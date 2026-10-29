//! The wrapping stream sits between a multiplexer's stream and everything above it.
//!
//! It rewrites the underlying multiplexer's "this stream is gone" error into the end-of-stream /
//! closed-connection error that the rest of murmur's stack already knows how to classify
//! (the packet-error filter and every relay's EOF check). A stream that closed therefore reads
//! as a clean end-of-stream rather than as an error that tears the whole mux session down.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::session::MuxStream;

/// Wraps an error.
///
/// The `h2` crate reports a peer reset as a typed [`h2::Error`] carrying a [`Reason`](h2::Reason)
/// rather than as a distinct `io::Error` kind, so the classification is done here against the
/// typed reason rather than by matching error text.
#[must_use]
pub fn wrap_error(err: io::Error) -> io::Error {
    if is_h2_stream_gone(&err) {
        return io::Error::new(io::ErrorKind::NotConnected, err.to_string());
    }
    err
}

/// A peer that went away — cancel, refused stream, closed stream, or a clean no-error reset —
/// which reads as a closed connection.
fn is_h2_stream_gone(err: &io::Error) -> bool {
    err.get_ref().and_then(|source| source.downcast_ref::<h2::Error>()).and_then(h2::Error::reason).is_some_and(
        |reason| {
            reason == h2::Reason::CANCEL
                || reason == h2::Reason::REFUSED_STREAM
                || reason == h2::Reason::STREAM_CLOSED
                || reason == h2::Reason::NO_ERROR
        },
    )
}

pub struct WrapStream {
    inner: Box<dyn MuxStream>,
}

impl core::fmt::Debug for WrapStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WrapStream").finish_non_exhaustive()
    }
}

impl WrapStream {
    #[must_use]
    pub fn new(inner: Box<dyn MuxStream>) -> Self {
        Self { inner }
    }
}

impl AsyncRead for WrapStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_read(cx, buf) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(wrap_error(err))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WrapStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.get_mut().inner).poll_write(cx, buf) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(wrap_error(err))),
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_flush(cx) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(wrap_error(err))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_shutdown(cx) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(wrap_error(err))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Wraps a stream, applied at the three sites that need it: the client's opened stream, the
/// client's brutal-exchange stream, and each server-accepted stream.
#[must_use]
pub fn wrap_stream(stream: Box<dyn MuxStream>) -> Box<dyn MuxStream> {
    Box::new(WrapStream::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_cancelled_h2_stream_reads_as_a_closed_connection() {
        let err = io::Error::other(h2::Error::from(h2::Reason::CANCEL));
        assert_eq!(wrap_error(err).kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn a_truncated_h2_body_is_an_unexpected_eof() {
        let err = io::Error::from(io::ErrorKind::UnexpectedEof);
        assert_eq!(wrap_error(err).kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn an_unrelated_error_keeps_its_kind() {
        let err = io::Error::from(io::ErrorKind::ConnectionReset);
        assert_eq!(wrap_error(err).kind(), io::ErrorKind::ConnectionReset);
    }
}

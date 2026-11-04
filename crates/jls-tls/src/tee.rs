//! A passthrough `AsyncRead` wrapper that, while capturing is enabled,
//! records every byte actually read from the inner transport.
//!
//! Used by [`crate::server::server_handshake`] to satisfy the invariant that
//! a failed JLS authentication attempt can hand back every byte read from the
//! client so far: no bytes are written before authentication succeeds, and
//! every byte read up to that point can be replayed to a fallback destination.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

pub(crate) struct TeeReader<R> {
    inner: R,
    capture: Option<Vec<u8>>,
}

impl<R> TeeReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self { inner, capture: Some(Vec::new()) }
    }

    /// Stops capturing and returns everything captured so far.
    pub(crate) fn stop_capture(&mut self) -> Vec<u8> {
        self.capture.take().unwrap_or_default()
    }

    pub(crate) fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for TeeReader<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if poll.is_ready() {
            if let Some(capture) = self.capture.as_mut() {
                if let Some(read) = buf.filled().get(before..) {
                    capture.extend_from_slice(read);
                }
            }
        }
        poll
    }
}

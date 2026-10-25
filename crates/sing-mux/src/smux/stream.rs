//! A stream close both sends a FIN and unblocks the local reader/writer via its own
//! `die` channel: after `Close()`, the caller's own reads and writes stop working, not just the
//! peer's. This `MuxStream` has no separate stream-level close beyond `AsyncWrite::shutdown`
//! and `Drop`, so `poll_shutdown` here is a true half-close (send a FIN, refuse further local
//! writes, leave local reads untouched) and `Drop` does the stream-closed bookkeeping
//! (remove from the session's stream table, hand the unread bytes back to the receive window,
//! best-effort FIN in case `shutdown` was never called). A duplicate FIN from both
//! paths firing is harmless: the peer's FIN handler in `session.rs` is idempotent.
//!
//! Per `rule://wave-rules` #2, the in-flight write/shutdown acknowledgement future is kept across
//! `Pending` polls in `write_pending`/`shutdown_pending` instead of re-sending the frame.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use super::frame::Frame;
use super::session::{broken_pipe, SessionInner, WriteRequest, MAX_FRAME_SIZE};

pub(super) struct SmuxStreamHandle {
    id: u32,
    session: Arc<SessionInner>,
    data_rx: mpsc::UnboundedReceiver<Bytes>,
    current: Option<Bytes>,
    write_pending: Option<oneshot::Receiver<io::Result<usize>>>,
    shutdown_pending: Option<oneshot::Receiver<io::Result<usize>>>,
    shutdown_sent: bool,
}

impl SmuxStreamHandle {
    pub(super) fn new(id: u32, session: Arc<SessionInner>, data_rx: mpsc::UnboundedReceiver<Bytes>) -> Self {
        Self { id, session, data_rx, current: None, write_pending: None, shutdown_pending: None, shutdown_sent: false }
    }
}

impl Drop for SmuxStreamHandle {
    fn drop(&mut self) {
        // A stream-closed returns the bytes the stream still holds to the session bucket.
        // The table entry goes first: the reader task delivers under that lock, so once it is
        // gone no payload can land here and the drain below is final.
        self.session.remove_stream(self.id);
        let mut unread = self.current.take().map_or(0, |chunk| chunk.len());
        while let Ok(chunk) = self.data_rx.try_recv() {
            unread += chunk.len();
        }
        self.session.return_tokens(unread);
        let _ = self.session.write_tx().send(WriteRequest { frame: Frame::fin(self.id), resp: None });
    }
}

impl AsyncRead for SmuxStreamHandle {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(chunk) = self.current.take() {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(chunk.split_at(n).0);
                if n < chunk.len() {
                    self.current = Some(chunk.slice(n..));
                }
                self.session.return_tokens(n);
                return Poll::Ready(Ok(()));
            }
            match self.data_rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.current = Some(chunk);
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SmuxStreamHandle {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.write_pending.is_none() {
            if self.shutdown_sent {
                return Poll::Ready(Err(broken_pipe()));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let size = buf.len().min(MAX_FRAME_SIZE);
            let (tx, rx) = oneshot::channel();
            let frame = Frame::psh(self.id, Bytes::copy_from_slice(buf.split_at(size).0));
            if self.session.write_tx().send(WriteRequest { frame, resp: Some(tx) }).is_err() {
                return Poll::Ready(Err(broken_pipe()));
            }
            self.write_pending = Some(rx);
        }

        let rx = self.write_pending.as_mut().ok_or_else(broken_pipe)?;
        match Pin::new(rx).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => {
                self.write_pending = None;
                Poll::Ready(result)
            }
            Poll::Ready(Err(_)) => {
                self.write_pending = None;
                Poll::Ready(Err(broken_pipe()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_sent {
            return Poll::Ready(Ok(()));
        }
        if self.shutdown_pending.is_none() {
            let (tx, rx) = oneshot::channel();
            if self.session.write_tx().send(WriteRequest { frame: Frame::fin(self.id), resp: Some(tx) }).is_err() {
                self.shutdown_sent = true;
                return Poll::Ready(Ok(()));
            }
            self.shutdown_pending = Some(rx);
        }

        let rx = self.shutdown_pending.as_mut().ok_or_else(broken_pipe)?;
        match Pin::new(rx).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => {
                self.shutdown_sent = true;
                self.shutdown_pending = None;
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::task::Waker;

    use super::*;

    #[test]
    fn dropping_a_stream_hands_back_exactly_what_was_never_read() {
        let inner = SessionInner::for_test();
        let start = inner.bucket_level();
        let data_rx = inner.register_for_test(3);
        let mut stream = SmuxStreamHandle::new(3, Arc::clone(&inner), data_rx);

        inner.deliver_payload(3, Bytes::from(vec![1u8; 100]));
        inner.deliver_payload(3, Bytes::from(vec![2u8; 50]));
        assert_eq!(inner.bucket_level(), start - 150);

        let mut cx = Context::from_waker(Waker::noop());
        let mut buf = [0u8; 60];
        let mut read_buf = ReadBuf::new(&mut buf);
        assert!(matches!(Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf), Poll::Ready(Ok(()))));
        assert_eq!(read_buf.filled(), &[1u8; 60]);
        assert_eq!(inner.bucket_level(), start - 90, "40 bytes are still held in the stream");

        drop(stream);
        assert_eq!(inner.bucket_level(), start, "the 90 unread bytes must go back to the window");
        assert_eq!(inner.stream_count(), 0);
        inner.deliver_payload(3, Bytes::from(vec![3u8; 10]));
        assert_eq!(inner.bucket_level(), start, "a frame for the removed stream is charged nothing");
    }
}

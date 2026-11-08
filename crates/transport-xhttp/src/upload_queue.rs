use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use parking_lot::Mutex;
use thiserror::Error;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::Notify;

use super::conn::ReadCloser;

/// The "reader already exists" and closed-pipe error kinds.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum UploadQueueError {
    #[error("io: read/write on closed pipe")]
    ClosedPipe,
    #[error("uploadQueue.reader already exists")]
    ReaderAlreadyExists,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("packet queue is too large")]
pub struct ErrQueueTooLarge;

pub(crate) struct Packet {
    pub seq: u64,
    pub payload: Vec<u8>,
    pub reader: Option<Pin<Box<dyn ReadCloser>>>,
}

struct State {
    packets: HashMap<u64, Vec<u8>>,
    next_seq: u64,
    buf: Vec<u8>,
    /// Read cursor into `buf`, so a partial drain advances an offset instead of `split_off`-ing
    /// (and reallocating) the unread tail on every read.
    pos: usize,
    closed: bool,
    max_packets: usize,
    reader: Option<Pin<Box<dyn ReadCloser>>>,
}

pub struct UploadQueue {
    state: Mutex<State>,
    pushed: Notify,
    popped: Notify,
    wait_fut: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>>,
    self_weak: Mutex<Weak<Self>>,
}

impl std::fmt::Debug for UploadQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadQueue").finish_non_exhaustive()
    }
}

impl UploadQueue {
    #[must_use]
    pub fn new(max_packets: i64) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            state: Mutex::new(State {
                packets: HashMap::new(),
                next_seq: 0,
                buf: Vec::new(),
                pos: 0,
                closed: false,
                max_packets: usize::try_from(max_packets.max(0)).unwrap_or(usize::MAX),
                reader: None,
            }),
            pushed: Notify::new(),
            popped: Notify::new(),
            wait_fut: Mutex::new(None),
            self_weak: Mutex::new(Weak::clone(weak)),
        })
    }

    pub(crate) async fn push(&self, mut p: Packet) -> anyhow::Result<()> {
        loop {
            {
                let mut state = self.state.lock();
                if state.closed {
                    return Err(UploadQueueError::ClosedPipe.into());
                }
                if state.reader.is_some() {
                    return Err(UploadQueueError::ReaderAlreadyExists.into());
                }
                if let Some(reader) = p.reader.take() {
                    state.reader = Some(reader);
                    drop(state);
                    self.pushed.notify_waiters();
                    return Ok(());
                }
                if state.packets.len() <= state.max_packets {
                    state.packets.insert(p.seq, std::mem::take(&mut p.payload));
                    drop(state);
                    self.pushed.notify_waiters();
                    return Ok(());
                }
            }
            self.popped.notified().await;
        }
    }

    fn poll_read_self(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut state = self.state.lock();

            if state.pos < state.buf.len() {
                let n = (state.buf.len() - state.pos).min(buf.remaining());
                buf.put_slice(state.buf.get(state.pos..state.pos + n).unwrap_or_default());
                state.pos += n;
                if state.pos == state.buf.len() {
                    state.buf.clear();
                    state.pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            let next_seq = state.next_seq;
            if let Some(payload) = state.packets.remove(&next_seq) {
                state.next_seq += 1;
                state.buf = payload;
                state.pos = 0;
                drop(state);
                self.popped.notify_waiters();
                continue;
            }

            if let Some(reader) = state.reader.as_mut() {
                return reader.as_mut().poll_read(cx, buf);
            }

            if state.closed {
                return Poll::Ready(Ok(()));
            }

            if state.packets.len() > state.max_packets {
                return Poll::Ready(Err(io::Error::other(ErrQueueTooLarge)));
            }

            drop(state);

            let mut wait_fut = self.wait_fut.lock();
            let poll_result = {
                let future = wait_fut.get_or_insert_with(|| {
                    #[expect(clippy::expect_used, reason = "the queue is alive while a handle to it is polled")]
                    let this = self.self_weak.lock().upgrade().expect("UploadQueue polled after being dropped");
                    Box::pin(async move {
                        this.pushed.notified().await;
                    })
                });
                future.as_mut().poll(cx)
            };
            if poll_result.is_pending() {
                return Poll::Pending;
            }
            *wait_fut = None;
            drop(wait_fut);
        }
    }

    /// Exposed directly for callers (and this file's own tests) that
    /// want a `(usize, io::Result)` signature rather than driving `AsyncRead`.
    pub async fn read(self: &Arc<Self>, buf: &mut [u8]) -> io::Result<usize> {
        std::future::poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(buf);
            match self.poll_read_self(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    pub fn close(&self) -> io::Result<()> {
        let mut state = self.state.lock();
        let err = if let Some(reader) = &state.reader { reader.close() } else { Ok(()) };
        state.closed = true;
        drop(state);
        self.pushed.notify_waiters();
        self.popped.notify_waiters();
        err
    }
}

/// Handle implementing [`ReadCloser`] for a shared [`UploadQueue`]; `Arc<UploadQueue>` cannot
/// implement `AsyncRead` directly since neither the trait nor `Arc` are local to this crate.
pub(crate) struct UploadQueueHandle(pub Arc<UploadQueue>);

impl AsyncRead for UploadQueueHandle {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.0.poll_read_self(cx, buf)
    }
}

impl ReadCloser for UploadQueueHandle {
    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_upload_queue_max_packets() {
        let q = UploadQueue::new(2);
        let q_pusher = Arc::clone(&q);

        let pusher = tokio::spawn(async move {
            assert!(q_pusher.push(Packet { seq: 0, payload: vec![b'0'], reader: None }).await.is_ok());
            assert!(q_pusher.push(Packet { seq: 1, payload: vec![b'1'], reader: None }).await.is_ok());
            assert!(q_pusher.push(Packet { seq: 2, payload: vec![b'2'], reader: None }).await.is_ok());
            assert!(q_pusher.push(Packet { seq: 4, payload: vec![b'4'], reader: None }).await.is_ok());
            assert!(q_pusher.push(Packet { seq: 5, payload: vec![b'5'], reader: None }).await.is_ok());
            assert!(q_pusher.push(Packet { seq: 6, payload: vec![b'6'], reader: None }).await.is_ok());
            let err = q_pusher.push(Packet { seq: 7, payload: vec![b'7'], reader: None }).await.unwrap_err();
            assert_eq!(err.downcast_ref::<UploadQueueError>(), Some(&UploadQueueError::ClosedPipe));
        });

        let mut buf = [0u8; 20];

        let n = q.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(&buf[..n], b"0");

        let n = q.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(&buf[..n], b"1");

        let n = q.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(&buf[..n], b"2");

        let err = q.read(&mut buf).await.unwrap_err();
        assert_eq!(err.get_ref().and_then(|e| e.downcast_ref::<ErrQueueTooLarge>()), Some(&ErrQueueTooLarge));

        assert!(q.close().is_ok());

        pusher.await.unwrap();
    }

    #[tokio::test]
    async fn test_upload_queue_partial_reads_reassemble_one_packet() {
        let q = UploadQueue::new(4);
        assert!(q.push(Packet { seq: 0, payload: b"0123456789".to_vec(), reader: None }).await.is_ok());

        let mut got = Vec::new();
        let mut buf = [0u8; 3];
        for _ in 0..4 {
            let n = q.read(&mut buf).await.unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, b"0123456789");

        assert!(q.push(Packet { seq: 1, payload: b"next".to_vec(), reader: None }).await.is_ok());
        let n = q.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"nex");
    }
}

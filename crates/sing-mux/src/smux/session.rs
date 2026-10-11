//! A background reader task and a background writer task demultiplex frames onto per-stream
//! state guarded by one lock, each fed/drained through channels, so neither direction ever
//! blocks on the other (`rule://wave-rules` #2's background-task alternative). Protocol version 1
//! is always used, which has no `keepalive` command semantics tied to frame parsing, so
//! keepalive is not implemented: sing-mux always disables it.
//!
//! The receive-side token bucket is reproduced as-is: it
//! gates how much unread data the reader task is allowed to pull off the wire in total across
//! all streams, independent of any single stream's consumer speed, and is what proves flow
//! control doesn't deadlock under backpressure.
//! A payload is charged to it only once it is queued on a live stream, and a stream hands back
//! whatever it never read, so neither a frame for an unknown stream nor a dropped stream can
//! strand the window.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex as SyncMutex;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;

use crate::session::{MuxConn, MuxStream, Session};

use super::frame::{decode_header, encode_header, Cmd, Frame, HEADER_SIZE};
use super::stream::SmuxStreamHandle;

const ACCEPT_BACKLOG: usize = 1024;
pub(super) const MAX_FRAME_SIZE: usize = 32768;
const MAX_RECEIVE_BUFFER: i64 = 4_194_304;

pub(super) fn broken_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "smux session closed")
}

pub(super) struct WriteRequest {
    pub(super) frame: Frame,
    pub(super) resp: Option<oneshot::Sender<io::Result<usize>>>,
}

pub(super) struct StreamState {
    pub(super) data_tx: SyncMutex<Option<mpsc::UnboundedSender<Bytes>>>,
}

pub(super) struct SessionInner {
    next_stream_id: AtomicU32,
    streams: SyncMutex<HashMap<u32, Arc<StreamState>>>,
    write_tx: mpsc::UnboundedSender<WriteRequest>,
    bucket: AtomicI64,
    bucket_notify: Notify,
    closed: AtomicBool,
    reader_task: SyncMutex<Option<JoinHandle<()>>>,
    writer_task: SyncMutex<Option<JoinHandle<()>>>,
}

impl SessionInner {
    pub(super) fn write_tx(&self) -> &mpsc::UnboundedSender<WriteRequest> {
        &self.write_tx
    }

    pub(super) fn return_tokens(&self, n: usize) {
        if n == 0 {
            return;
        }
        #[expect(
            clippy::cast_possible_wrap,
            reason = "the receive budget is a few megabytes, far below `i64::MAX`, so a token count cannot wrap"
        )]
        let n = n as i64;
        let prev = self.bucket.fetch_add(n, Ordering::AcqRel);
        if prev + n > 0 {
            self.bucket_notify.notify_one();
        }
    }

    /// Charging the bucket in the same locked step as the hand-off keeps a frame for a missing
    /// stream free and stops a closing stream from handing back tokens the reader already spent.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the per-stream state and its sender slot are both borrowed out of their guards, and the send charges the receive window while they are held, so both guards have to span the hand-off"
    )]
    pub(super) fn deliver_payload(&self, sid: u32, payload: Bytes) {
        let len = payload.len();
        let streams = self.streams.lock();
        let Some(state) = streams.get(&sid) else {
            return;
        };
        let sender = state.data_tx.lock();
        let Some(tx) = sender.as_ref() else {
            return;
        };
        if tx.send(payload).is_ok() {
            #[expect(
                clippy::cast_possible_wrap,
                reason = "the receive budget is a few megabytes, far below `i64::MAX`, so a payload length cannot wrap"
            )]
            let len = len as i64;
            self.bucket.fetch_sub(len, Ordering::AcqRel);
        }
    }

    #[cfg(test)]
    pub(super) fn for_test() -> Arc<SessionInner> {
        let (write_tx, _write_rx) = mpsc::unbounded_channel();
        Arc::new(SessionInner {
            next_stream_id: AtomicU32::new(1),
            streams: SyncMutex::new(HashMap::new()),
            write_tx,
            bucket: AtomicI64::new(MAX_RECEIVE_BUFFER),
            bucket_notify: Notify::new(),
            closed: AtomicBool::new(false),
            reader_task: SyncMutex::new(None),
            writer_task: SyncMutex::new(None),
        })
    }

    #[cfg(test)]
    pub(super) fn bucket_level(&self) -> i64 {
        self.bucket.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn register_for_test(&self, sid: u32) -> mpsc::UnboundedReceiver<Bytes> {
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        let state = StreamState { data_tx: SyncMutex::new(Some(data_tx)) };
        self.streams.lock().insert(sid, Arc::new(state));
        data_rx
    }

    #[cfg(test)]
    pub(super) fn stream_count(&self) -> usize {
        self.streams.lock().len()
    }

    pub(super) fn remove_stream(&self, sid: u32) {
        self.streams.lock().remove(&sid);
    }

    fn fatal_close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.streams.lock().clear();
        let reader_task = self.reader_task.lock().take();
        if let Some(h) = reader_task {
            h.abort();
        }
        let writer_task = self.writer_task.lock().take();
        if let Some(h) = writer_task {
            h.abort();
        }
    }
}

pub(crate) struct SmuxSession {
    inner: Arc<SessionInner>,
    accept_rx: AsyncMutex<mpsc::Receiver<Box<dyn MuxStream>>>,
}

#[expect(
    clippy::unused_async,
    reason = "the pub(crate) client_session/server_session wrappers are async and awaited by \
              session::new_client_session, so the shared constructor keeps the same shape"
)]
async fn new_session(conn: Box<dyn MuxConn>, client: bool) -> io::Result<SmuxSession> {
    let (read_half, write_half) = split(conn);
    let (write_tx, write_rx) = mpsc::unbounded_channel::<WriteRequest>();
    let (accept_tx, accept_rx) = mpsc::channel::<Box<dyn MuxStream>>(ACCEPT_BACKLOG);

    let inner = Arc::new(SessionInner {
        next_stream_id: AtomicU32::new(u32::from(client)),
        streams: SyncMutex::new(HashMap::new()),
        write_tx,
        bucket: AtomicI64::new(MAX_RECEIVE_BUFFER),
        bucket_notify: Notify::new(),
        closed: AtomicBool::new(false),
        reader_task: SyncMutex::new(None),
        writer_task: SyncMutex::new(None),
    });

    let writer_handle = tokio::spawn(writer_loop(Arc::clone(&inner), write_half, write_rx));
    let reader_handle = tokio::spawn(reader_loop(Arc::clone(&inner), read_half, accept_tx));
    *inner.reader_task.lock() = Some(reader_handle);
    *inner.writer_task.lock() = Some(writer_handle);

    Ok(SmuxSession { inner, accept_rx: AsyncMutex::new(accept_rx) })
}

pub(crate) async fn client_session(conn: Box<dyn MuxConn>) -> io::Result<SmuxSession> {
    new_session(conn, true).await
}

pub(crate) async fn server_session(conn: Box<dyn MuxConn>) -> io::Result<SmuxSession> {
    new_session(conn, false).await
}

// cancel-safe: aborted only by `fatal_close`, which is tearing the carrier down, so a frame cut
// short by the abort goes down with the connection it belonged to.
async fn writer_loop(
    inner: Arc<SessionInner>,
    mut write_half: WriteHalf<Box<dyn MuxConn>>,
    mut write_rx: mpsc::UnboundedReceiver<WriteRequest>,
) {
    let mut header_buf = [0u8; HEADER_SIZE];
    while let Some(req) = write_rx.recv().await {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "a psh frame carries at most `MAX_FRAME_SIZE` bytes and the other commands none, so the payload length always fits the 16-bit header field"
        )]
        encode_header(&mut header_buf, req.frame.cmd, req.frame.sid, req.frame.data.len() as u16);
        let result: io::Result<usize> = async {
            write_half.write_all(&header_buf).await?;
            if !req.frame.data.is_empty() {
                write_half.write_all(&req.frame.data).await?;
            }
            Ok(req.frame.data.len())
        }
        .await;

        let failed = result.is_err();
        if let Some(resp) = req.resp {
            let _ = resp.send(result);
        }
        if failed {
            inner.fatal_close();
            return;
        }
    }
}

// cancel-safe: aborted only by `fatal_close`, which clears the stream table first, so a payload
// this task had not yet delivered has nowhere to go anyway.
async fn reader_loop(
    inner: Arc<SessionInner>,
    mut read_half: ReadHalf<Box<dyn MuxConn>>,
    accept_tx: mpsc::Sender<Box<dyn MuxStream>>,
) {
    let mut hdr = [0u8; HEADER_SIZE];
    loop {
        while inner.bucket.load(Ordering::Acquire) <= 0 {
            if inner.closed.load(Ordering::Acquire) {
                return;
            }
            inner.bucket_notify.notified().await;
        }

        if read_half.read_exact(&mut hdr).await.is_err() {
            inner.fatal_close();
            return;
        }

        let Some((cmd, sid, len)) = decode_header(hdr) else {
            inner.fatal_close();
            return;
        };

        match cmd {
            Cmd::Nop => {}
            Cmd::Syn => {
                let (data_tx, data_rx) = mpsc::unbounded_channel();
                let inserted = {
                    let mut map = inner.streams.lock();
                    if let Entry::Vacant(slot) = map.entry(sid) {
                        slot.insert(Arc::new(StreamState { data_tx: SyncMutex::new(Some(data_tx)) }));
                        true
                    } else {
                        false
                    }
                };
                if inserted {
                    let stream = SmuxStreamHandle::new(sid, Arc::clone(&inner), data_rx);
                    if accept_tx.send(Box::new(stream)).await.is_err() {
                        inner.remove_stream(sid);
                    }
                }
            }
            Cmd::Fin => {
                if let Some(state) = inner.streams.lock().get(&sid) {
                    state.data_tx.lock().take();
                }
            }
            Cmd::Psh => {
                if len == 0 {
                    continue;
                }
                let mut payload = vec![0u8; len as usize];
                if read_half.read_exact(&mut payload).await.is_err() {
                    inner.fatal_close();
                    return;
                }
                inner.deliver_payload(sid, Bytes::from(payload));
            }
        }
    }
}

#[async_trait]
impl Session for SmuxSession {
    async fn open(&self, tcp_timeout: Duration) -> io::Result<Box<dyn MuxStream>> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(broken_pipe());
        }

        let sid = self.inner.next_stream_id.fetch_add(2, Ordering::SeqCst) + 2;
        let (tx, rx) = oneshot::channel();
        self.inner.write_tx.send(WriteRequest { frame: Frame::syn(sid), resp: Some(tx) }).map_err(|_| broken_pipe())?;

        match tokio::time::timeout(tcp_timeout, rx).await {
            Ok(Ok(Ok(_))) => {}
            Ok(Ok(Err(e))) => return Err(e),
            Ok(Err(_)) => return Err(broken_pipe()),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "smux open timed out")),
        }

        let (data_tx, data_rx) = mpsc::unbounded_channel();
        self.inner.streams.lock().insert(sid, Arc::new(StreamState { data_tx: SyncMutex::new(Some(data_tx)) }));
        Ok(Box::new(SmuxStreamHandle::new(sid, Arc::clone(&self.inner), data_rx)))
    }

    async fn accept(&self) -> io::Result<Box<dyn MuxStream>> {
        self.accept_rx.lock().await.recv().await.ok_or_else(broken_pipe)
    }

    fn num_streams(&self) -> usize {
        if self.inner.closed.load(Ordering::Acquire) {
            0
        } else {
            self.inner.streams.lock().len()
        }
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.fatal_close();
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    fn can_take_new_request(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_for_an_unknown_stream_costs_no_tokens() {
        let inner = SessionInner::for_test();
        let start = inner.bucket_level();

        inner.deliver_payload(7, Bytes::from(vec![1u8; 64]));
        assert_eq!(inner.bucket_level(), start, "bytes nobody holds must not shrink the window");

        let mut data_rx = inner.register_for_test(7);
        inner.deliver_payload(7, Bytes::from(vec![2u8; 64]));
        assert_eq!(inner.bucket_level(), start - 64);
        assert_eq!(data_rx.try_recv().unwrap().len(), 64);
    }

    #[test]
    fn a_finished_stream_stops_being_charged() {
        let inner = SessionInner::for_test();
        let start = inner.bucket_level();
        let data_rx = inner.register_for_test(7);

        inner.deliver_payload(7, Bytes::from(vec![1u8; 32]));
        assert_eq!(inner.bucket_level(), start - 32);

        if let Some(state) = inner.streams.lock().get(&7) {
            state.data_tx.lock().take();
        }
        drop(data_rx);
        inner.deliver_payload(7, Bytes::from(vec![1u8; 32]));
        assert_eq!(inner.bucket_level(), start - 32, "a frame past cmdFIN is discarded, so it is not charged");
    }
}

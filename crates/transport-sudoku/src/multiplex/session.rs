use portable_atomic::AtomicI64;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::{Buf as _, Bytes};
use futures::channel::mpsc::{Receiver as FrameReceiver, Sender as FrameSender};
use futures::future::poll_fn;
use futures::sink::Sink as _;
use futures::StreamExt as _;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::write_chunks::write_all_chunks;
use murmur_common_net::io::Stream as NetStream;

const FRAME_OPEN: u8 = 0x01;
const FRAME_DATA: u8 = 0x02;
const FRAME_CLOSE: u8 = 0x03;
const FRAME_RESET: u8 = 0x04;

const HEADER_SIZE: usize = 1 + 4 + 4;
/// maxQueuedBytesPerStream bounds unread payload retained by a single logical stream.
/// A stream that exceeds the limit is reset so it cannot block the shared demux loop.
const MAX_QUEUED_BYTES_PER_STREAM: usize = 4 * 1024 * 1024;
const MAX_FRAME_SIZE: usize = 256 * 1024;
const MAX_DATA_PAYLOAD: usize = 128 * 1024;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Frames queued for the session's writer task. A writer blocks on the conn write
/// itself; a bounded queue is the poll-safe stand-in for that backpressure.
const WRITE_QUEUE_CAPACITY: usize = 8;

/// Channel depth of the server-side accept queue.
const ACCEPT_QUEUE_CAPACITY: usize = 256;

/// Caps the live stream table: the demux loop never waits on the accept queue, so without a
/// cardinality bound one `FRAME_OPEN` per peer frame adds an entry, a stream and a blocked task.
const MAX_STREAMS: usize = 1024;

fn err_mux_receive_queue_full() -> anyhow::Error {
    anyhow!("mux receive queue full")
}

fn err_closed_pipe() -> anyhow::Error {
    anyhow!("io: read/write on closed pipe")
}

fn closed_error(err: &Arc<anyhow::Error>) -> anyhow::Error {
    anyhow!("{err}")
}

fn io_closed_error(err: &Arc<anyhow::Error>) -> io::Error {
    io::Error::other(closed_error(err))
}

fn now_nanos() -> i64 {
    chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "every caller bounds payload_len by MAX_FRAME_SIZE before encoding, so the wire width is exact"
)]
fn encode_header(frame_type: u8, stream_id: u32, payload_len: usize) -> [u8; HEADER_SIZE] {
    let mut header = [0u8; HEADER_SIZE];
    header[0] = frame_type;
    header[1..5].copy_from_slice(&stream_id.to_be_bytes());
    header[5..9].copy_from_slice(&(payload_len as u32).to_be_bytes());
    header
}

/// One unit of work for the session's writer task. A `Data` command carries a whole
/// stream-write payload so that concurrent writes on one stream stay contiguous,
/// as the per-stream write lock guarantees.
enum WriteCmd {
    Data { stream_id: u32, payload: Vec<u8> },
    Frame { frame_type: u8, stream_id: u32, payload: Vec<u8> },
}

struct AcceptEvent {
    stream: Stream,
    payload: Vec<u8>,
}

struct SessionStreams {
    streams: HashMap<u32, Stream>,
    next_id: u32,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "the mux stream state machine is a flag set: close, half-close and queue states are independent"
)]
struct StreamState {
    closed: bool,
    local_read_closed: bool,
    local_write_closed: bool,
    remote_write_closed: bool,
    close_err: Option<Arc<anyhow::Error>>,
    read_buf: Bytes,
    /// queuedBytes includes unread bytes in `read_buf` and queue.
    queued_bytes: usize,
    queue_tx: Option<mpsc::UnboundedSender<Bytes>>,
}

struct StreamInner {
    session: Weak<Session>,
    id: u32,
    state: Mutex<StreamState>,
    queue_rx: Mutex<mpsc::UnboundedReceiver<Bytes>>,
    write_tx: Mutex<FrameSender<WriteCmd>>,
}

#[derive(Clone)]
pub struct Stream {
    inner: Arc<StreamInner>,
}

impl core::fmt::Debug for Stream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stream").field("id", &self.inner.id).finish_non_exhaustive()
    }
}

/// Session multiplexes logical streams over a single conn.
pub struct Session {
    write_tx: Mutex<FrameSender<WriteCmd>>,
    streams: Mutex<SessionStreams>,
    accept_tx: Option<mpsc::Sender<AcceptEvent>>,
    accept_rx: tokio::sync::Mutex<Option<mpsc::Receiver<AcceptEvent>>>,
    /// the `closed` channel plus the close reason guarded alongside it.
    closed: CancellationToken,
    close_once: AtomicBool,
    close_err: Mutex<Option<Arc<anyhow::Error>>>,
    last_write: AtomicI64,
    keepalive_once: Once,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session").field("closed", &self.is_closed()).finish_non_exhaustive()
    }
}

impl Session {
    #[must_use]
    pub fn client(conn: Box<dyn NetStream>) -> Arc<Self> {
        let session = Self::start(conn, false);
        session.start_keepalive(KEEPALIVE_INTERVAL);
        session
    }

    #[must_use]
    pub fn server(conn: Box<dyn NetStream>) -> Arc<Self> {
        let session = Self::start(conn, true);
        session.start_keepalive(KEEPALIVE_INTERVAL);
        session
    }

    fn start(conn: Box<dyn NetStream>, server: bool) -> Arc<Self> {
        let (read_half, write_half) = tokio::io::split(conn);
        let (write_tx, write_rx) = futures::channel::mpsc::channel::<WriteCmd>(WRITE_QUEUE_CAPACITY);
        let (accept_tx, accept_rx) = if server {
            let (tx, rx) = mpsc::channel::<AcceptEvent>(ACCEPT_QUEUE_CAPACITY);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let session = Arc::new(Self {
            write_tx: Mutex::new(write_tx),
            streams: Mutex::new(SessionStreams { streams: HashMap::new(), next_id: 0 }),
            accept_tx,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            closed: CancellationToken::new(),
            close_once: AtomicBool::new(false),
            close_err: Mutex::new(None),
            last_write: AtomicI64::new(0),
            keepalive_once: Once::new(),
        });
        session.last_write.store(now_nanos(), Ordering::SeqCst);

        tokio::spawn(Self::read_loop(Arc::clone(&session), read_half));
        tokio::spawn(Self::write_loop(Arc::clone(&session), write_rx, write_half));
        session
    }

    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    /// the `Done` channel: cancelled once the session is closed.
    pub fn done(&self) -> CancellationToken {
        self.closed.clone()
    }

    fn closed_err(&self) -> Arc<anyhow::Error> {
        let err = self.close_err.lock().clone();
        match err {
            Some(err) => err,
            None => Arc::new(err_closed_pipe()),
        }
    }

    pub fn close_with_error(&self, err: anyhow::Error) {
        if self.close_once.swap(true, Ordering::SeqCst) {
            return;
        }

        let err = Arc::new(err);
        {
            let mut close_err = self.close_err.lock();
            if close_err.is_none() {
                *close_err = Some(Arc::clone(&err));
            }
        }
        let streams: Vec<Stream> = {
            let mut streams = self.streams.lock();
            streams.streams.drain().map(|(_, st)| st).collect()
        };

        for st in streams {
            st.close_no_send(Arc::clone(&err));
        }

        self.closed.cancel();
    }

    pub fn close(&self) {
        self.close_with_error(err_closed_pipe());
    }

    fn register_stream(&self, st: Stream) {
        self.streams.lock().streams.insert(st.id(), st);
    }

    fn get_stream(&self, id: u32) -> Option<Stream> {
        self.streams.lock().streams.get(&id).cloned()
    }

    fn remove_stream(&self, id: u32) {
        self.streams.lock().streams.remove(&id);
    }

    fn next_stream_id(&self) -> u32 {
        let mut streams = self.streams.lock();
        streams.next_id = streams.next_id.wrapping_add(1);
        let mut id = streams.next_id;
        if id == 0 {
            streams.next_id = streams.next_id.wrapping_add(1);
            id = streams.next_id;
        }
        id
    }

    async fn enqueue(&self, cmd: WriteCmd) -> Result<()> {
        let mut cmd = Some(cmd);
        let queued = poll_fn(|cx| {
            let mut tx = self.write_tx.lock();
            match Pin::new(&mut *tx).poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    let Some(cmd) = cmd.take() else {
                        return Poll::Ready(false);
                    };
                    if tx.start_send(cmd).is_err() {
                        return Poll::Ready(false);
                    }
                    drop(tx);
                    Poll::Ready(true)
                }
                Poll::Ready(Err(_)) => Poll::Ready(false),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        if queued {
            Ok(())
        } else {
            Err(closed_error(&self.closed_err()))
        }
    }

    /// A frame send, for callers that cannot await (`Conn::close*`).
    fn send_frame_soon(self: &Arc<Self>, frame_type: u8, stream_id: u32, payload: Vec<u8>) -> io::Result<()> {
        if self.is_closed() {
            return Err(io_closed_error(&self.closed_err()));
        }
        if payload.len() > MAX_FRAME_SIZE {
            return Err(io::Error::other(anyhow!("mux payload too large: {}", payload.len())));
        }

        let cmd = WriteCmd::Frame { frame_type, stream_id, payload };
        let mut tx = self.write_tx.lock();
        match tx.try_send(cmd) {
            Ok(()) => Ok(()),
            Err(err) => {
                if !err.is_full() {
                    return Err(io_closed_error(&self.closed_err()));
                }
                let cmd = err.into_inner();
                drop(tx);
                let session = Arc::clone(self);
                tokio::spawn(async move {
                    let _ = session.enqueue(cmd).await;
                });
                Ok(())
            }
        }
    }

    async fn send_frame(&self, frame_type: u8, stream_id: u32, payload: &[u8]) -> Result<()> {
        if self.is_closed() {
            return Err(closed_error(&self.closed_err()));
        }
        if payload.len() > MAX_FRAME_SIZE {
            return Err(anyhow!("mux payload too large: {}", payload.len()));
        }
        self.enqueue(WriteCmd::Frame { frame_type, stream_id, payload: payload.to_vec() }).await
    }

    fn start_keepalive(self: &Arc<Self>, interval: Duration) {
        if interval.is_zero() {
            return;
        }
        let session = Arc::clone(self);
        let interval_nanos = i64::try_from(interval.as_nanos()).unwrap_or(i64::MAX);
        self.keepalive_once.call_once(move || {
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
                loop {
                    // cancel-safe: the tick only sends a keepalive frame; dropping the spawned task
                    // stops the pings.
                    tokio::select! {
                        () = session.closed.cancelled() => return,
                        _ = ticker.tick() => {
                            let last_write = session.last_write.load(Ordering::SeqCst);
                            if now_nanos().saturating_sub(last_write) < interval_nanos {
                                continue;
                            }
                            // Stream zero is never allocated. v0.4.7 peers ignore DATA
                            // frames for unknown streams, so this remains compatible.
                            if session.send_frame(FRAME_DATA, 0, &[]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        });
    }

    async fn send_reset(&self, stream_id: u32, msg: &str) {
        let msg = if msg.is_empty() { "reset" } else { msg };
        let _ = self.send_frame(FRAME_RESET, stream_id, msg.as_bytes()).await;
        let _ = self.send_frame(FRAME_CLOSE, stream_id, &[]).await;
    }

    pub async fn open_stream(self: &Arc<Self>, open_payload: &[u8]) -> Result<Stream> {
        if self.is_closed() {
            return Err(closed_error(&self.closed_err()));
        }

        let stream_id = self.next_stream_id();
        let st = Stream::new(self, stream_id);
        self.register_stream(st.clone());

        if let Err(err) = self.send_frame(FRAME_OPEN, stream_id, open_payload).await {
            st.close_no_send(Arc::new(anyhow!("{err}")));
            self.remove_stream(stream_id);
            return Err(anyhow!("mux open failed: {err}"));
        }
        Ok(st)
    }

    // cancel-safe: a cancelled receive leaves the accepted stream queued for the next call.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the accept queue guard has to stay held across the select so a cancelled accept cannot hand the queued stream to a second caller"
    )]
    pub async fn accept_stream(&self) -> Result<(Stream, Vec<u8>)> {
        if self.accept_tx.is_none() {
            return Err(anyhow!("accept is not supported on client sessions"));
        }
        let mut guard = self.accept_rx.lock().await;
        let Some(rx) = guard.as_mut() else {
            return Err(anyhow!("accept is not supported on client sessions"));
        };
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => Ok((ev.stream, ev.payload)),
                None => Err(closed_error(&self.closed_err())),
            },
            () = self.closed.cancelled() => Err(closed_error(&self.closed_err())),
        }
    }

    // NOT cancel-safe: a drop between taking a command off the queue and writing its frame leaves
    // the mux stream short a frame; the spawned loop is never aborted.
    async fn write_loop(
        session: Arc<Self>,
        mut write_rx: FrameReceiver<WriteCmd>,
        mut write_half: WriteHalf<Box<dyn NetStream>>,
    ) {
        loop {
            let cmd = tokio::select! {
                () = session.closed.cancelled() => break,
                cmd = write_rx.next() => cmd,
            };
            let Some(cmd) = cmd else {
                break;
            };

            let result = match cmd {
                WriteCmd::Data { stream_id, payload } => {
                    let mut err = None;
                    for chunk in payload.chunks(MAX_DATA_PAYLOAD) {
                        let header = encode_header(FRAME_DATA, stream_id, chunk.len());
                        if let Err(e) = write_all_chunks(&mut write_half, &[header.as_slice(), chunk]).await {
                            err = Some(e);
                            break;
                        }
                    }
                    err
                }
                WriteCmd::Frame { frame_type, stream_id, payload } => {
                    let header = encode_header(frame_type, stream_id, payload.len());
                    write_all_chunks(&mut write_half, &[header.as_slice(), payload.as_slice()]).await.err()
                }
            };

            if let Some(err) = result {
                session.close_with_error(anyhow!(err));
                break;
            }
            session.last_write.store(now_nanos(), Ordering::SeqCst);
        }
        let _ = write_half.shutdown().await;
    }

    // NOT cancel-safe: `read_exact` is not cancel-safe, so a drop mid-frame loses this side's
    // offset into the peer's stream; the spawned loop is never aborted.
    async fn read_loop(session: Arc<Self>, mut read_half: ReadHalf<Box<dyn NetStream>>) {
        let mut header = [0u8; HEADER_SIZE];
        loop {
            let read = tokio::select! {
                () = session.closed.cancelled() => return,
                read = read_half.read_exact(&mut header) => read,
            };
            if let Err(err) = read {
                session.close_with_error(anyhow!(err));
                return;
            }
            let frame_type = header[0];
            let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
            let n = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
            if n > MAX_FRAME_SIZE {
                session.close_with_error(anyhow!("invalid mux frame length: {n}"));
                return;
            }

            let payload = if n == 0 {
                Vec::new()
            } else {
                let mut buf = vec![0u8; n];
                let read = tokio::select! {
                    () = session.closed.cancelled() => return,
                    read = read_half.read_exact(&mut buf) => read,
                };
                if let Err(err) = read {
                    session.close_with_error(anyhow!(err));
                    return;
                }
                buf
            };

            if !Self::handle_frame(&session, frame_type, stream_id, payload).await {
                return;
            }
        }
    }

    /// Decodes and applies one frame; `false` means the session has to stop.
    async fn handle_frame(session: &Arc<Self>, frame_type: u8, stream_id: u32, payload: Vec<u8>) -> bool {
        match frame_type {
            FRAME_OPEN => {
                let Some(accept_tx) = session.accept_tx.clone() else {
                    session.send_reset(stream_id, "unexpected open").await;
                    return true;
                };
                if stream_id == 0 {
                    session.send_reset(stream_id, "invalid stream id").await;
                    return true;
                }
                if session.get_stream(stream_id).is_some() {
                    session.send_reset(stream_id, "stream already exists").await;
                    return true;
                }
                let live_streams = session.streams.lock().streams.len();
                if live_streams >= MAX_STREAMS {
                    session.send_reset(stream_id, "too many streams").await;
                    return true;
                }
                let st = Stream::new(session, stream_id);
                session.register_stream(st.clone());
                let acceptor = Arc::clone(session);
                tokio::spawn(async move {
                    // cancel-safe: both arms close the stream and unregister it, and the task is
                    // never aborted.
                    tokio::select! {
                        () = acceptor.closed.cancelled() => {
                            st.close_no_send(Arc::new(err_closed_pipe()));
                            acceptor.remove_stream(stream_id);
                        }
                        sent = accept_tx.send(AcceptEvent { stream: st.clone(), payload }) => {
                            if sent.is_err() {
                                st.close_no_send(Arc::new(err_closed_pipe()));
                                acceptor.remove_stream(stream_id);
                            }
                        }
                    }
                });
            }

            FRAME_DATA => {
                let Some(st) = session.get_stream(stream_id) else {
                    return true;
                };
                if payload.is_empty() {
                    return true;
                }
                if let Err(err) = st.enqueue(Bytes::from(payload)) {
                    let msg = err.to_string();
                    st.close_no_send(Arc::new(err));
                    session.remove_stream(stream_id);
                    let resetter = Arc::clone(session);
                    tokio::spawn(async move {
                        resetter.send_reset(stream_id, &msg).await;
                    });
                }
            }

            FRAME_CLOSE => {
                let Some(st) = session.get_stream(stream_id) else {
                    return true;
                };
                if st.close_remote_write() {
                    session.remove_stream(stream_id);
                }
            }

            FRAME_RESET => {
                let Some(st) = session.get_stream(stream_id) else {
                    return true;
                };
                let mut msg = trim_ascii(&payload);
                if msg.is_empty() {
                    "reset".clone_into(&mut msg);
                }
                st.close_no_send(Arc::new(anyhow!("{msg}")));
                session.remove_stream(stream_id);
            }

            _ => {
                session.close_with_error(anyhow!("unknown mux frame type: {frame_type}"));
                return false;
            }
        }
        true
    }
}

fn trim_ascii(b: &[u8]) -> String {
    let mut i = 0;
    let mut j = b.len();
    while i < j {
        let Some(&c) = b.get(i) else {
            break;
        };
        if c != b' ' && c != b'\n' && c != b'\r' && c != b'\t' {
            break;
        }
        i += 1;
    }
    while j > i {
        let Some(&c) = b.get(j - 1) else {
            break;
        };
        if c != b' ' && c != b'\n' && c != b'\r' && c != b'\t' {
            break;
        }
        j -= 1;
    }
    if i >= j {
        return String::new();
    }
    let Some(trimmed) = b.get(i..j) else {
        return String::new();
    };
    String::from_utf8_lossy(trimmed).into_owned()
}

impl Stream {
    fn new(session: &Arc<Session>, id: u32) -> Self {
        let (queue_tx, queue_rx) = mpsc::unbounded_channel::<Bytes>();
        Self {
            inner: Arc::new(StreamInner {
                session: Arc::downgrade(session),
                id,
                state: Mutex::new(StreamState {
                    closed: false,
                    local_read_closed: false,
                    local_write_closed: false,
                    remote_write_closed: false,
                    close_err: None,
                    read_buf: Bytes::new(),
                    queued_bytes: 0,
                    queue_tx: Some(queue_tx),
                }),
                queue_rx: Mutex::new(queue_rx),
                write_tx: Mutex::new(session.write_tx.lock().clone()),
            }),
        }
    }

    fn id(&self) -> u32 {
        self.inner.id
    }

    fn close_no_send(&self, err: Arc<anyhow::Error>) {
        let mut st = self.inner.state.lock();
        if st.closed {
            return;
        }
        st.closed = true;
        if st.close_err.is_none() {
            st.close_err = Some(err);
        }
        st.queue_tx = None;
    }

    fn close_remote_write(&self) -> bool {
        let mut st = self.inner.state.lock();
        if st.closed {
            return false;
        }
        st.remote_write_closed = true;
        let remove = st.local_write_closed;
        st.queue_tx = None;
        remove
    }

    /// The queue hand-off for a stream read: returns `false` when the payload was refused
    /// because the receive queue for this stream is over its limit.
    fn enqueue(&self, payload: Bytes) -> Result<()> {
        let mut st = self.inner.state.lock();
        if st.closed || st.local_read_closed || st.remote_write_closed {
            return Ok(());
        }
        if st.queued_bytes + payload.len() > MAX_QUEUED_BYTES_PER_STREAM {
            return Err(err_mux_receive_queue_full());
        }
        st.queued_bytes += payload.len();
        let Some(queue_tx) = st.queue_tx.clone() else {
            return Ok(());
        };
        drop(st);
        let _ = queue_tx.send(payload);
        Ok(())
    }

    fn close(&self) {
        let send_close = {
            let mut st = self.inner.state.lock();
            if st.closed {
                return;
            }
            let send_close = !st.local_write_closed;
            st.closed = true;
            st.local_read_closed = true;
            st.local_write_closed = true;
            if st.close_err.is_none() {
                st.close_err = Some(Arc::new(err_closed_pipe()));
            }
            st.read_buf = Bytes::new();
            st.queued_bytes = 0;
            st.queue_tx = None;
            send_close
        };
        self.drain_queue();

        let Some(session) = self.inner.session.upgrade() else {
            return;
        };
        if send_close {
            let _ = session.send_frame_soon(FRAME_CLOSE, self.inner.id, Vec::new());
        }
        session.remove_stream(self.inner.id);
    }

    fn close_write(&self) -> io::Result<()> {
        let remove = {
            let mut st = self.inner.state.lock();
            if st.closed || st.local_write_closed {
                return Ok(());
            }
            st.local_write_closed = true;
            st.remote_write_closed || st.local_read_closed
        };

        let Some(session) = self.inner.session.upgrade() else {
            return Ok(());
        };
        let err = session.send_frame_soon(FRAME_CLOSE, self.inner.id, Vec::new());
        if remove {
            session.remove_stream(self.inner.id);
        }
        err
    }

    fn drain_queue(&self) {
        let mut queue_rx = self.inner.queue_rx.lock();
        while queue_rx.try_recv().is_ok() {}
    }

    #[allow(
        dead_code,
        reason = "the real half-close-read has no reachable caller through the new Stream trait: relay_inner only ever calls shutdown_write for half-close, so shutdown_read maps to the full close() instead to keep close_stream()'s fallback composition equivalent to the old Close()"
    )]
    fn close_read(&self) {
        let remove = {
            let mut st = self.inner.state.lock();
            if st.closed || st.local_read_closed {
                return;
            }
            st.local_read_closed = true;
            st.read_buf = Bytes::new();
            st.queued_bytes = 0;
            let remove = st.local_write_closed;
            st.queue_tx = None;
            remove
        };
        self.drain_queue();

        if remove {
            if let Some(session) = self.inner.session.upgrade() {
                session.remove_stream(self.inner.id);
            }
        }
    }

    fn poll_read_state(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        {
            let mut st = self.inner.state.lock();
            if !st.read_buf.is_empty() {
                copy_out(&mut st, buf);
                return Poll::Ready(Ok(()));
            }
        }

        // A queued payload is taken before mapping a finished stream to EOF or an error.
        let polled = self.inner.queue_rx.lock().poll_recv(cx);
        match polled {
            Poll::Ready(Some(payload)) => {
                let mut st = self.inner.state.lock();
                st.read_buf = payload;
                copy_out(&mut st, buf);
                drop(st);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                let st = self.inner.state.lock();
                Poll::Ready(stream_finished(&st))
            }
            Poll::Pending => {
                let st = self.inner.state.lock();
                let finished = st.closed || st.local_read_closed || st.remote_write_closed;
                let res = finished.then_some(stream_finished(&st));
                drop(st);
                res.map_or(Poll::Pending, Poll::Ready)
            }
        }
    }

    fn poll_write_state(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        {
            let st = self.inner.state.lock();
            if st.closed {
                return Poll::Ready(Err(io_closed_error(&closed_err_locked(&st))));
            }
            if st.local_write_closed {
                return Poll::Ready(Err(io::Error::other(err_closed_pipe())));
            }
        }

        let Some(session) = self.inner.session.upgrade() else {
            return Poll::Ready(Err(io::Error::other(err_closed_pipe())));
        };
        if session.is_closed() {
            return Poll::Ready(Err(io_closed_error(&session.closed_err())));
        }

        let mut tx = self.inner.write_tx.lock();
        match Pin::new(&mut *tx).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let cmd = WriteCmd::Data { stream_id: self.inner.id, payload: buf.to_vec() };
                if tx.start_send(cmd).is_err() {
                    drop(tx);
                    return Poll::Ready(Err(io_closed_error(&session.closed_err())));
                }
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => {
                drop(tx);
                Poll::Ready(Err(io_closed_error(&session.closed_err())))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Maps a finished stream read to its result once the wait loop ends.
fn stream_finished(st: &StreamState) -> io::Result<()> {
    if st.closed {
        return Err(io_closed_error(&closed_err_locked(st)));
    }
    if st.local_read_closed {
        return Err(io::Error::other(err_closed_pipe()));
    }
    if st.remote_write_closed {
        return Ok(());
    }
    Err(io::Error::other(err_closed_pipe()))
}

fn closed_err_locked(st: &StreamState) -> Arc<anyhow::Error> {
    match &st.close_err {
        Some(err) => Arc::clone(err),
        None => Arc::new(err_closed_pipe()),
    }
}

fn copy_out(st: &mut StreamState, buf: &mut ReadBuf<'_>) {
    let n = std::cmp::min(buf.remaining(), st.read_buf.len());
    if let Some(chunk) = st.read_buf.get(..n) {
        buf.put_slice(chunk);
    }
    st.read_buf.advance(n);
    st.queued_bytes = st.queued_bytes.saturating_sub(n);
    if st.read_buf.is_empty() {
        st.read_buf = Bytes::new();
    }
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.poll_read_state(cx, buf)
    }
}

impl AsyncRead for &Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this: &Stream = self.get_mut();
        this.poll_read_state(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.poll_write_state(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Self::close_write(self.get_mut())?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for &Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this: &Stream = self.get_mut();
        this.poll_write_state(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this: &Stream = self.get_mut();
        this.close_write()?;
        Poll::Ready(Ok(()))
    }
}

impl NetStream for Stream {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn shutdown_read(&self) -> io::Result<()> {
        Self::close(self);
        Ok(())
    }

    fn shutdown_write(&self) -> io::Result<()> {
        Self::close_write(self)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::DuplexStream;

    use super::*;

    /// In-memory pipe stand-in: a bidirectional in-memory conn.
    struct PipeConn(DuplexStream);

    impl AsyncRead for PipeConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PipeConn {
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

    impl NetStream for PipeConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }

        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    fn pipe_pair() -> (Box<dyn NetStream>, Box<dyn NetStream>) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (Box::new(PipeConn(a)), Box::new(PipeConn(b)))
    }

    #[tokio::test]
    async fn session_keepalive_uses_v047_compatible_frame() {
        let (session_conn, mut peer_conn) = pipe_pair();
        let session = Session::start(session_conn, false);
        session.start_keepalive(Duration::from_millis(10));

        let mut header = [0u8; HEADER_SIZE];
        tokio::time::timeout(Duration::from_secs(1), peer_conn.read_exact(&mut header))
            .await
            .expect("read keepalive")
            .expect("read keepalive");

        assert_eq!(header[0], FRAME_DATA, "keepalive frame type = {}, want DATA", header[0]);
        let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        assert_eq!(stream_id, 0, "keepalive stream id = {stream_id}, want 0");
        let payload_len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
        assert_eq!(payload_len, 0, "keepalive payload length = {payload_len}, want 0");

        session.close_with_error(anyhow!("use of closed network connection"));
    }

    #[tokio::test]
    async fn session_slow_stream_does_not_block_other_streams() {
        let (client_conn, server_conn) = pipe_pair();
        let client_session = Session::client(client_conn);
        let server_session = Session::server(server_conn);

        let mut slow_conn = client_session.open_stream(&[]).await.expect("open slow stream");
        server_session.accept_stream().await.expect("accept slow stream");

        let payload = vec![0u8; MAX_DATA_PAYLOAD];
        let flood = tokio::spawn(async move {
            let mut queued = 0usize;
            while queued <= MAX_QUEUED_BYTES_PER_STREAM {
                if slow_conn.write_all(&payload).await.is_err() {
                    return;
                }
                queued += payload.len();
            }
        });
        tokio::time::timeout(Duration::from_secs(1), flood)
            .await
            .expect("failed to fill slow stream queue")
            .expect("flood task");

        let mut fast_conn = client_session.open_stream(&[]).await.expect("open fast stream");
        let fast_write = tokio::spawn(async move { fast_conn.write_all(b"still responsive").await });

        let (mut fast_server, _) =
            server_session.accept_stream().await.expect("slow stream blocked the entire mux session");
        let mut buf = vec![0u8; "still responsive".len()];
        fast_server.read_exact(&mut buf).await.expect("read fast stream");
        assert_eq!(buf, b"still responsive".to_vec(), "fast stream payload mismatch");
        fast_write.await.expect("write fast stream").expect("write fast stream");

        client_session.close();
        server_session.close();
    }

    #[tokio::test]
    async fn open_frames_past_the_stream_cap_are_reset_and_leave_the_table_bounded() {
        let (mut peer_conn, server_conn) = pipe_pair();
        let server_session = Session::server(server_conn);

        let opens = MAX_STREAMS as u32 + 8;
        for stream_id in 1..=opens {
            assert!(
                Session::handle_frame(&server_session, FRAME_OPEN, stream_id, vec![0u8; 8]).await,
                "an open past the cap must not stop the session"
            );
        }

        assert_eq!(
            server_session.streams.lock().streams.len(),
            MAX_STREAMS,
            "live streams after {opens} opens with a cap of {MAX_STREAMS}"
        );

        let rejected = opens as usize - MAX_STREAMS;
        let mut resets = 0usize;
        while resets < rejected {
            let mut header = [0u8; HEADER_SIZE];
            tokio::time::timeout(Duration::from_secs(1), peer_conn.read_exact(&mut header))
                .await
                .expect("reset frame header")
                .expect("read reset frame header");
            let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
            let mut payload = vec![0u8; len];
            if len > 0 {
                peer_conn.read_exact(&mut payload).await.expect("read reset payload");
            }
            if header[0] == FRAME_RESET {
                resets += 1;
                assert_eq!(payload, b"too many streams".to_vec(), "reset reason");
            }
        }

        server_session.close();
    }

    #[tokio::test]
    async fn stream_close_write_preserves_response() {
        let (client_conn, server_conn) = pipe_pair();
        let client_session = Session::client(client_conn);
        let server_session = Session::server(server_conn);

        let server_session_task = Arc::clone(&server_session);
        let server = tokio::spawn(async move {
            let (mut conn, _) = server_session_task.accept_stream().await?;
            let mut request = Vec::new();
            conn.read_to_end(&mut request).await?;
            if request != b"request" {
                return Err(anyhow!("request payload mismatch"));
            }
            conn.write_all(b"response").await?;
            conn.close_write()?;
            Ok::<(), anyhow::Error>(())
        });

        let mut client_stream = client_session.open_stream(&[]).await.expect("open stream");
        client_stream.write_all(b"request").await.expect("write request");
        client_stream.close_write().expect("close request side");

        let mut response = Vec::new();
        client_stream.read_to_end(&mut response).await.expect("read response");
        assert_eq!(response, b"response".to_vec(), "response payload mismatch");

        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("server did not finish half-closed exchange")
            .expect("server task")
            .expect("server stream");

        client_session.close();
        server_session.close();
    }

    #[tokio::test]
    async fn stream_concurrent_writes_remain_contiguous() {
        let (client_conn, server_conn) = pipe_pair();
        let client_session = Session::client(client_conn);
        let server_session = Session::server(server_conn);

        let client_stream = client_session.open_stream(&[]).await.expect("open stream");
        let (mut server_stream, _) = server_session.accept_stream().await.expect("accept stream");

        const WRITERS: usize = 8;
        let payload_size = MAX_DATA_PAYLOAD * 2 + 17;
        let reader = tokio::spawn(async move {
            let mut payload = Vec::new();
            server_stream.read_to_end(&mut payload).await.map(|_| payload)
        });

        let mut writers = Vec::with_capacity(WRITERS);
        for i in 0..WRITERS {
            let stream = client_stream.clone();
            writers.push(tokio::spawn(async move {
                let mut writer: &Stream = &stream;
                let payload = vec![(i + 1) as u8; payload_size];
                writer.write_all(&payload).await
            }));
        }
        for writer in writers {
            writer.await.expect("concurrent write task").expect("concurrent write");
        }
        client_stream.close_write().expect("close write");

        let result = reader.await.expect("read task").expect("read stream");
        assert_eq!(
            result.len(),
            WRITERS * payload_size,
            "payload size = {}, want {}",
            result.len(),
            WRITERS * payload_size
        );

        let mut seen = [false; WRITERS];
        for offset in (0..result.len()).step_by(payload_size) {
            let block = &result[offset..offset + payload_size];
            let marker = block[0];
            if marker == 0 || marker as usize > WRITERS {
                panic!("unexpected block marker {marker} at offset {offset}");
            }
            if seen[marker as usize - 1] {
                panic!("marker {marker} was split or duplicated");
            }
            seen[marker as usize - 1] = true;
            if block != vec![marker; payload_size] {
                panic!("write with marker {marker} was interleaved");
            }
        }

        client_session.close();
        server_session.close();
    }
}

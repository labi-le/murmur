//!
//! The three-channel error split (socket read, socket write, protocol) is
//! folded into one `close_err` + `closed: CancellationToken`: all three ultimately just tear
//! the session down and hand the stored error to every blocked waiter, which a single close
//! path does identically.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::anyhow;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::Stream as NetStream;

use crate::alloc::get_buffer;
use crate::frame::{
    encode_header, version_byte, Frame, RawHeader, UpdHeader, CMD_FIN, CMD_NOP, CMD_PSH, CMD_SYN, CMD_UPD, HEADER_SIZE,
    SIZE_OF_UPD,
};
use crate::shaper::{Class, ShaperQueue, WriteRequest};
use crate::stream::{new_stream_shared, StreamShared};
use crate::Config;

const DEFAULT_ACCEPT_BACKLOG: usize = 1024;

/// Bounds the control-frame writes of stream open and close, so a stalled underlying conn
/// surfaces `ErrTimeout` instead of hanging the caller forever.
pub(crate) const OPEN_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);

const MAX_SHAPER_SIZE: usize = 1024;

pub(crate) struct SessionInner {
    pub(crate) config: Config,
    pub(crate) local_addr: SocketAddr,
    pub(crate) peer_addr: SocketAddr,

    write_tx: mpsc::Sender<WriteRequest>,
    next_seq: AtomicU64,

    streams: Mutex<HashMap<u32, Arc<StreamShared>>>,
    next_stream_id: Mutex<u32>,
    go_away: AtomicBool,

    accept_tx: mpsc::Sender<Arc<StreamShared>>,
    accept_rx: AsyncMutex<mpsc::Receiver<Arc<StreamShared>>>,

    bucket: AtomicI64,
    bucket_notify: Notify,

    closed: CancellationToken,
    close_once: AtomicBool,
    close_err: Mutex<Option<Arc<anyhow::Error>>>,

    session_active: AtomicBool,
}

impl SessionInner {
    pub(crate) fn start(conn: Box<dyn NetStream>, config: Config, is_client: bool) -> Arc<Self> {
        let local_addr = conn.local_addr().unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        let peer_addr = conn.peer_addr().unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));

        let (read_half, write_half) = tokio::io::split(conn);
        let (write_tx, write_rx) = mpsc::channel::<WriteRequest>(MAX_SHAPER_SIZE);
        let (accept_tx, accept_rx) = mpsc::channel::<Arc<StreamShared>>(DEFAULT_ACCEPT_BACKLOG);
        let max_receive_buffer = config.max_receive_buffer;
        let keep_alive_disabled = config.keep_alive_disabled;

        let session = Arc::new(Self {
            config,
            local_addr,
            peer_addr,
            write_tx,
            next_seq: AtomicU64::new(0),
            streams: Mutex::new(HashMap::new()),
            next_stream_id: Mutex::new(u32::from(is_client)),
            go_away: AtomicBool::new(false),
            accept_tx,
            accept_rx: AsyncMutex::new(accept_rx),
            bucket: AtomicI64::new(max_receive_buffer),
            bucket_notify: Notify::new(),
            closed: CancellationToken::new(),
            close_once: AtomicBool::new(false),
            close_err: Mutex::new(None),
            session_active: AtomicBool::new(false),
        });

        tokio::spawn(recv_loop(Arc::clone(&session), read_half));
        tokio::spawn(writer_loop(Arc::downgrade(&session), session.closed.clone(), write_rx, write_half));
        if !keep_alive_disabled {
            tokio::spawn(keepalive_loop(Arc::clone(&session)));
        }
        session
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    pub(crate) fn closed_error(&self) -> anyhow::Error {
        let stored = self.close_err.lock().clone();
        match stored {
            Some(err) => anyhow!("{err}"),
            None => anyhow!("io: read/write on closed pipe"),
        }
    }

    pub(crate) fn close_with_error(&self, err: Option<anyhow::Error>) -> bool {
        if self.close_once.swap(true, Ordering::AcqRel) {
            return false;
        }
        let err = Arc::new(err.unwrap_or_else(|| anyhow!("io: read/write on closed pipe")));
        *self.close_err.lock() = Some(err);
        self.closed.cancel();
        for (_, st) in self.streams.lock().drain() {
            st.mark_die();
        }
        true
    }

    pub(crate) fn close(&self) {
        self.close_with_error(None);
    }

    pub(crate) fn return_tokens(&self, n: usize) {
        if n == 0 {
            return;
        }
        #[expect(clippy::cast_possible_wrap, reason = "`n` is a buffered byte count, far below `i64::MAX`")]
        let n = n as i64;
        let new_value = self.bucket.fetch_add(n, Ordering::AcqRel) + n;
        if new_value > 0 {
            self.bucket_notify.notify_one();
        }
    }

    pub(crate) fn stream_closed(&self, sid: u32) {
        let removed = self.streams.lock().remove(&sid);
        if let Some(st) = removed {
            let n = st.take_buffered_len();
            self.return_tokens(n);
        }
    }

    // NOT cancel-safe: a cancel after the request is queued still writes the frame and only loses the result.
    pub(crate) async fn write_frame(
        &self,
        class: Class,
        frame: Frame,
        deadline: Option<Duration>,
    ) -> anyhow::Result<usize> {
        let send = async {
            if self.closed.is_cancelled() {
                return Err(self.closed_error());
            }
            let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
            let req = WriteRequest { class, frame, seq, result: tx };
            tokio::select! {
                res = self.write_tx.send(req) => {
                    if res.is_err() {
                        return Err(self.closed_error());
                    }
                }
                () = self.closed.cancelled() => return Err(self.closed_error()),
            }
            tokio::select! {
                res = rx => match res {
                    Ok(Ok(n)) => Ok(n),
                    Ok(Err(err)) => Err(anyhow!(err)),
                    Err(_) => Err(self.closed_error()),
                },
                () = self.closed.cancelled() => Err(self.closed_error()),
            }
        };
        match deadline {
            Some(limit) => tokio::time::timeout(limit, send).await.unwrap_or_else(|_| Err(anyhow!("timeout"))),
            None => send.await,
        }
    }

    // NOT cancel-safe: as `write_frame`, a cancel after the frame is queued still writes it.
    pub(crate) async fn write_control_frame(&self, frame: Frame) -> anyhow::Result<usize> {
        self.write_frame(Class::Ctrl, frame, Some(OPEN_CLOSE_TIMEOUT)).await
    }

    // NOT cancel-safe: the SYN goes out before the stream is registered, so a cancel leaves the peer
    // with a stream this side never tracks.
    pub(crate) async fn open_stream(self: &Arc<Self>) -> anyhow::Result<Arc<StreamShared>> {
        if self.closed.is_cancelled() {
            return Err(self.closed_error());
        }
        if self.go_away.load(Ordering::Acquire) {
            return Err(anyhow!("stream id overflows, should start a new connection"));
        }

        let sid = {
            let mut next_id = self.next_stream_id.lock();
            let Some(candidate) = next_id.checked_add(2) else {
                self.go_away.store(true, Ordering::Release);
                return Err(anyhow!("stream id overflows, should start a new connection"));
            };
            *next_id = candidate;
            candidate
        };

        let st = new_stream_shared(Arc::downgrade(self), sid, &self.config, self.local_addr, self.peer_addr);

        self.write_control_frame(Frame::new(version_byte(self.config.version), CMD_SYN, sid)).await?;

        if self.closed.is_cancelled() {
            return Err(self.closed_error());
        }
        self.streams.lock().insert(sid, Arc::clone(&st));
        Ok(st)
    }

    // cancel-safe: a cancelled wait leaves the queued stream in the accept channel.
    pub(crate) async fn accept_stream(&self, deadline: Option<Instant>) -> anyhow::Result<Arc<StreamShared>> {
        let mut rx = self.accept_rx.lock().await;
        let recv = async {
            tokio::select! {
                ev = rx.recv() => ev.ok_or_else(|| self.closed_error()),
                () = self.closed.cancelled() => Err(self.closed_error()),
            }
        };
        match deadline {
            Some(at) => tokio::time::timeout_at(at, recv).await.unwrap_or_else(|_| Err(anyhow!("timeout"))),
            None => recv.await,
        }
    }

    pub(crate) fn num_streams(&self) -> usize {
        if self.closed.is_cancelled() {
            return 0;
        }
        self.streams.lock().len()
    }
}

// NOT cancel-safe: a header cut short is consumed from the socket, and only session teardown cancels it.
async fn read_header(
    session: &Arc<SessionInner>,
    read_half: &mut ReadHalf<Box<dyn NetStream>>,
) -> Option<[u8; HEADER_SIZE]> {
    while session.bucket.load(Ordering::Acquire) <= 0 {
        if session.closed.is_cancelled() {
            return None;
        }
        tokio::select! {
            () = session.bucket_notify.notified() => {}
            () = session.closed.cancelled() => return None,
        }
    }

    let mut hdr = [0u8; HEADER_SIZE];
    let read = tokio::select! {
        () = session.closed.cancelled() => return None,
        r = read_half.read_exact(&mut hdr) => r,
    };
    if let Err(err) = read {
        session.close_with_error(Some(anyhow!(err)));
        return None;
    }
    session.session_active.store(true, Ordering::Release);
    Some(hdr)
}

// cancel-safe: the accepted stream is either queued for `accept_stream` or never sent.
async fn recv_syn(session: &Arc<SessionInner>, sid: u32) -> bool {
    let accepted = {
        let mut streams = session.streams.lock();
        match streams.entry(sid) {
            std::collections::hash_map::Entry::Occupied(_) => None,
            std::collections::hash_map::Entry::Vacant(entry) => {
                let st = new_stream_shared(
                    Arc::downgrade(session),
                    sid,
                    &session.config,
                    session.local_addr,
                    session.peer_addr,
                );
                entry.insert(Arc::clone(&st));
                Some(st)
            }
        }
    };
    let Some(st) = accepted else {
        return true;
    };
    tokio::select! {
        res = session.accept_tx.send(st) => {
            if res.is_err() {
                session.streams.lock().remove(&sid);
            }
            true
        }
        () = session.closed.cancelled() => false,
    }
}

// NOT cancel-safe: bytes cut short are consumed from the socket and dropped, and only session teardown
// cancels it.
async fn recv_psh(
    session: &Arc<SessionInner>,
    read_half: &mut ReadHalf<Box<dyn NetStream>>,
    len: usize,
    sid: u32,
) -> bool {
    let mut payload = get_buffer(len);
    let read = tokio::select! {
        () = session.closed.cancelled() => return false,
        r = read_half.read_exact(&mut payload) => r,
    };
    if let Err(err) = read {
        session.close_with_error(Some(anyhow!(err)));
        return false;
    }
    let st = session.streams.lock().get(&sid).cloned();
    if let Some(st) = st {
        st.push_bytes(payload);
        #[expect(clippy::cast_possible_wrap, reason = "`len` is a 16-bit header field, so it cannot wrap `i64`")]
        let len = len as i64;
        session.bucket.fetch_sub(len, Ordering::AcqRel);
    }
    true
}

// NOT cancel-safe: an update cut short is consumed from the socket and dropped, and only session
// teardown cancels it.
async fn recv_upd(session: &Arc<SessionInner>, read_half: &mut ReadHalf<Box<dyn NetStream>>, sid: u32) -> bool {
    let mut upd = [0u8; SIZE_OF_UPD];
    let read = tokio::select! {
        () = session.closed.cancelled() => return false,
        r = read_half.read_exact(&mut upd) => r,
    };
    if let Err(err) = read {
        session.close_with_error(Some(anyhow!(err)));
        return false;
    }
    if session.config.version == 2 {
        let uh = UpdHeader(upd);
        let st = session.streams.lock().get(&sid).cloned();
        if let Some(st) = st {
            st.update_window(uh.consumed(), uh.window());
        }
    }
    true
}

/// Every handler answers whether the receive loop may continue.
// cancel-safe: only session teardown aborts it, so a frame cut short goes down with the carrier.
async fn recv_loop(session: Arc<SessionInner>, mut read_half: ReadHalf<Box<dyn NetStream>>) {
    loop {
        let Some(hdr) = read_header(&session, &mut read_half).await else {
            return;
        };
        let hdr = RawHeader(hdr);
        if hdr.version() != version_byte(session.config.version) {
            session.close_with_error(Some(anyhow!("invalid protocol")));
            return;
        }
        let sid = hdr.stream_id();
        let keep_going = match hdr.cmd() {
            CMD_NOP => true,
            CMD_SYN => recv_syn(&session, sid).await,
            CMD_FIN => {
                let st = session.streams.lock().get(&sid).cloned();
                if let Some(st) = st {
                    st.mark_fin();
                }
                true
            }
            CMD_PSH => {
                let len = hdr.length() as usize;
                if len == 0 {
                    true
                } else {
                    recv_psh(&session, &mut read_half, len, sid).await
                }
            }
            CMD_UPD => recv_upd(&session, &mut read_half, sid).await,
            _ => {
                session.close_with_error(Some(anyhow!("invalid protocol")));
                false
            }
        };
        if !keep_going {
            return;
        }
    }
}

/// tokio has `write_vectored` but no `write_all_vectored`, so drain the iovecs here, the
/// way std's own `write_all_vectored` does. A short write is backpressure, not failure:
/// only a zero-length write with bytes still queued is an error, exactly as `write_all`
/// reports for the same stall.
// NOT cancel-safe: a partial frame is already on the wire when it stops.
async fn write_all_vectored<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    bufs: &mut [std::io::IoSlice<'_>],
) -> std::io::Result<()> {
    let mut rest = bufs;
    std::io::IoSlice::advance_slices(&mut rest, 0);
    while !rest.is_empty() {
        let n = w.write_vectored(rest).await?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "failed to write whole frame"));
        }
        std::io::IoSlice::advance_slices(&mut rest, n);
    }
    Ok(())
}

// cancel-safe: aborted only by runtime shutdown, so a frame cut short goes down with the carrier.
async fn writer_loop(
    session: Weak<SessionInner>,
    closed: CancellationToken,
    mut write_rx: mpsc::Receiver<WriteRequest>,
    mut write_half: WriteHalf<Box<dyn NetStream>>,
) {
    let mut queue = ShaperQueue::new();
    loop {
        if queue.is_empty() {
            tokio::select! {
                () = closed.cancelled() => break,
                req = write_rx.recv() => match req {
                    Some(req) => queue.push(req),
                    None => break,
                },
            }
        }
        while let Ok(req) = write_rx.try_recv() {
            queue.push(req);
        }
        let Some(req) = queue.pop() else {
            continue;
        };

        let header = encode_header(&req.frame);
        let write_result: std::io::Result<()> = if write_half.is_write_vectored() {
            let mut bufs = [std::io::IoSlice::new(&header), std::io::IoSlice::new(&req.frame.data)];
            write_all_vectored(&mut write_half, &mut bufs).await
        } else {
            let mut joined = Vec::with_capacity(header.len() + req.frame.data.len());
            joined.extend_from_slice(&header);
            joined.extend_from_slice(&req.frame.data);
            write_half.write_all(&joined).await
        };

        match write_result {
            Ok(()) => {
                let _ = req.result.send(Ok(req.frame.data.len()));
            }
            Err(err) => {
                let _ = req.result.send(Err(std::io::Error::new(err.kind(), err.to_string())));
                if let Some(session) = session.upgrade() {
                    session.close_with_error(Some(anyhow!(err)));
                }
                break;
            }
        }
    }
    let _ = write_half.shutdown().await;
}

// cancel-safe: it only probes; an aborted tick is retried by the next interval.
async fn keepalive_loop(session: Arc<SessionInner>) {
    let mut ping = tokio::time::interval(session.config.keep_alive_interval);
    let mut timeout_ticker = tokio::time::interval(session.config.keep_alive_timeout);
    ping.tick().await;
    timeout_ticker.tick().await;

    loop {
        tokio::select! {
            () = session.closed.cancelled() => return,
            _ = ping.tick() => {
                let frame = Frame::new(version_byte(session.config.version), CMD_NOP, 0);
                // The NOP is bounded by the ping tick itself, so a wedged writer is noticed
                // one interval later instead of parking this task forever.
                let deadline = Some(session.config.keep_alive_interval);
                if session.write_frame(Class::Ctrl, frame, deadline).await.is_err() {
                    return;
                }
                session.bucket_notify.notify_one();
            }
            _ = timeout_ticker.tick() => {
                let was_active = session.session_active.swap(false, Ordering::AcqRel);
                if !was_active && session.bucket.load(Ordering::Acquire) > 0 {
                    session.close_with_error(Some(anyhow!("keep-alive timeout")));
                    return;
                }
            }
        }
    }
}

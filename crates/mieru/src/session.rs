//! Simplifications relative to the documented behaviour: a fixed sliding-window congestion
//! controller replaces CUBIC, and quotas and metrics are not implemented.
//!
//! Nonce shaping and traffic-pattern padding live in [`crate::cipher`] and [`crate::padding`],
//! applied by the underlay that owns this session's sink; low-entropy payload coding is still
//! unimplemented.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::Sleep;

use crate::wire::{
    self, DataAckStruct, ProtocolType, SessionStruct, MAX_PDU, MAX_SESSION_OPEN_PAYLOAD, METADATA_LENGTH,
};

pub const SEGMENT_CHAN_CAPACITY: usize = 256;
pub const SEGMENT_TREE_CAPACITY: usize = 4096;
pub const MIN_WINDOW_SIZE: u32 = 16;
pub const MAX_WINDOW_SIZE: u32 = 4096;
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub const HEARTBEAT_JITTER: Duration = Duration::from_secs(1);
pub const IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(60);
pub const TX_COUNT_LIMIT: u32 = 20;
pub const EARLY_RETRANSMISSION: u32 = 3;
pub const MIN_RTO: Duration = Duration::from_millis(200);
pub const MAX_RTO: Duration = Duration::from_secs(10);
const RETRANSMIT_TICK: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    Stream,
    Packet,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SessionState {
    Init = 0,
    Attached = 1,
    Established = 2,
    Closed = 3,
}

impl SessionState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Init,
            1 => Self::Attached,
            2 => Self::Established,
            _ => Self::Closed,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SessionError {
    #[error("session is not ready for write")]
    NotReady,
    #[error("session is closed")]
    Closed,
    #[error("write timed out")]
    WriteTimeout,
    #[error("read timed out")]
    ReadTimeout,
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("received an unexpected protocol direction")]
    ProtocolDirection,
    #[error("server rejected the session: status code {0}")]
    Rejected(u8),
    #[error("the underlay went away mid-session")]
    UnderlayClosed,
    #[error("wire error: {0}")]
    Wire(#[from] wire::WireError),
}

pub type Result<T, E = SessionError> = std::result::Result<T, E>;

/// Recovering a poisoned lock beats taking the whole process down with it: the guarded counters
/// and queues stay usable.
fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl From<SessionError> for io::Error {
    fn from(e: SessionError) -> Self {
        match e {
            SessionError::Io(e) => e,
            SessionError::Closed => Self::new(io::ErrorKind::BrokenPipe, e),
            SessionError::WriteTimeout | SessionError::ReadTimeout => Self::new(io::ErrorKind::TimedOut, e),
            SessionError::UnderlayClosed => Self::new(io::ErrorKind::UnexpectedEof, e),
            SessionError::NotReady
            | SessionError::ProtocolDirection
            | SessionError::Rejected(_)
            | SessionError::Wire(_) => Self::other(e),
        }
    }
}

/// Why a session stopped delivering data: a closed channel answers EOF, a read error a
/// truncated stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadEnd {
    Eof,
    UnderlayLost,
    Rejected(u8),
}

impl ReadEnd {
    fn into_result(self) -> Result<Option<Bytes>> {
        match self {
            Self::Eof => Ok(None),
            Self::UnderlayLost => Err(SessionError::UnderlayClosed),
            Self::Rejected(code) => Err(SessionError::Rejected(code)),
        }
    }
}

/// Where a session's already-marshaled, plaintext segment actually goes on the wire.
///
/// Implemented once per underlay: stream writes a shared, mutex-serialized `TcpStream`, packet
/// writes a shared `UdpSocket` to this session's remembered peer address.
#[async_trait::async_trait]
pub trait SegmentSink: Send + Sync {
    async fn send_segment(&self, meta: [u8; METADATA_LENGTH], payload: &[u8]) -> io::Result<()>;
}

struct RttStats {
    srtt: Duration,
    rttvar: Duration,
    initialized: bool,
}

impl RttStats {
    fn new() -> Self {
        Self { srtt: MIN_RTO, rttvar: Duration::ZERO, initialized: false }
    }

    fn update(&mut self, sample: Duration) {
        if self.initialized {
            let diff = self.srtt.abs_diff(sample);
            self.rttvar = (self.rttvar * 3 + diff) / 4;
            self.srtt = (self.srtt * 7 + sample) / 8;
        } else {
            self.srtt = sample;
            self.rttvar = sample / 2;
            self.initialized = true;
        }
    }

    fn rto(&self) -> Duration {
        (self.srtt + self.rttvar * 4).clamp(MIN_RTO, MAX_RTO)
    }
}

struct Outstanding {
    meta: [u8; METADATA_LENGTH],
    payload: Bytes,
    sent_at: Instant,
    tx_count: u32,
    ack_count: u32,
}

struct Inner {
    id: u32,
    is_client: bool,
    transport: Transport,
    fragment_size: usize,
    state: AtomicU8,
    close_requested: AtomicBool,
    open_request_sent: AtomicBool,
    sink: Arc<dyn SegmentSink>,
    next_send: AtomicU32,
    next_recv: AtomicU32,
    recv_reorder: AsyncMutex<BTreeMap<u32, Bytes>>,
    /// The read queue's sender, taken when the session tears down: dropping the last sender is
    /// what wakes a reader parked in [`Session::poll_read_chunk`], the way a closed channel and
    /// a read error wake a pending read.
    read_tx: StdMutex<Option<mpsc::Sender<Bytes>>>,
    read_rx: StdMutex<mpsc::Receiver<Bytes>>,
    /// Set once, when the session tears down, so a reader that gets nothing can tell a clean EOF
    /// from a lost underlay.
    read_end: StdMutex<Option<ReadEnd>>,
    /// The armed timer for `read_deadline`, kept across polls so a cancelled read does not
    /// re-arm it.
    read_timer: StdMutex<Option<Pin<Box<Sleep>>>>,
    unread: StdMutex<Option<Bytes>>,
    established: Notify,
    closed_notify: Notify,
    open_error: StdMutex<Option<SessionError>>,
    outstanding: AsyncMutex<BTreeMap<u32, Outstanding>>,
    send_window_notify: Notify,
    remote_window_size: AtomicU32,
    cwnd: AtomicU32,
    rtt: StdMutex<RttStats>,
    ack_on_data_recv: AtomicBool,
    last_ack_sent: StdMutex<Instant>,
    last_recv_time: StdMutex<Instant>,
    read_deadline: StdMutex<Option<Instant>>,
    write_deadline: StdMutex<Option<Instant>>,
    /// The local and peer addresses and the user name a listener reads off an accepted
    /// session, which the owning underlay supplies when the session is created.
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
    user_name: Option<String>,
}

impl Inner {
    fn state(&self) -> SessionState {
        SessionState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// Monotonic CAS state transition; a no-op if `target` is not strictly ahead of the current
    /// state.
    fn forward_state_to(&self, target: SessionState) {
        loop {
            let current = self.state.load(Ordering::Acquire);
            if current >= target as u8 {
                return;
            }
            if self.state.compare_exchange(current, target as u8, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                return;
            }
        }
    }

    /// The window the session advertises, as the wire's `u16` field.
    #[expect(clippy::cast_possible_truncation, reason = "SEGMENT_TREE_CAPACITY is 4096, far inside u16")]
    fn receive_window_size() -> u16 {
        SEGMENT_TREE_CAPACITY as u16
    }

    /// Closes with an error: everything parked on the session is released, and dropping the
    /// read queue's sender is what turns a parked read into an answer instead of a hang.
    fn tear_down(&self, end: ReadEnd) {
        self.state.store(SessionState::Closed as u8, Ordering::Release);
        {
            let mut read_end = lock(&self.read_end);
            if read_end.is_none() {
                *read_end = Some(end);
            }
        }
        drop(lock(&self.read_tx).take());
        self.established.notify_waiters();
        self.closed_notify.notify_waiters();
        self.send_window_notify.notify_waiters();
    }
}

pub struct Session {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.inner.id)
            .field("state", &self.inner.state())
            .finish_non_exhaustive()
    }
}

/// The peer facts a listener needs off an accepted session: the local and peer addresses and
/// the authenticated user name.
#[derive(Clone, Debug, Default)]
pub struct SessionPeer {
    pub local_addr: Option<SocketAddr>,
    pub peer_addr: Option<SocketAddr>,
    pub user_name: Option<String>,
}

impl Session {
    pub fn new(
        id: u32,
        is_client: bool,
        transport: Transport,
        fragment_size: usize,
        sink: Arc<dyn SegmentSink>,
        peer: SessionPeer,
    ) -> Self {
        let (read_tx, read_rx) = mpsc::channel(SEGMENT_CHAN_CAPACITY);
        let inner = Arc::new(Inner {
            id,
            is_client,
            transport,
            fragment_size,
            state: AtomicU8::new(SessionState::Attached as u8),
            close_requested: AtomicBool::new(false),
            open_request_sent: AtomicBool::new(false),
            sink,
            next_send: AtomicU32::new(0),
            next_recv: AtomicU32::new(0),
            recv_reorder: AsyncMutex::new(BTreeMap::new()),
            read_tx: StdMutex::new(Some(read_tx)),
            read_rx: StdMutex::new(read_rx),
            read_end: StdMutex::new(None),
            read_timer: StdMutex::new(None),
            unread: StdMutex::new(None),
            established: Notify::new(),
            closed_notify: Notify::new(),
            open_error: StdMutex::new(None),
            outstanding: AsyncMutex::new(BTreeMap::new()),
            send_window_notify: Notify::new(),
            remote_window_size: AtomicU32::new(MIN_WINDOW_SIZE),
            cwnd: AtomicU32::new(MIN_WINDOW_SIZE),
            rtt: StdMutex::new(RttStats::new()),
            ack_on_data_recv: AtomicBool::new(false),
            last_ack_sent: StdMutex::new(Instant::now()),
            last_recv_time: StdMutex::new(Instant::now()),
            read_deadline: StdMutex::new(None),
            write_deadline: StdMutex::new(None),
            local_addr: peer.local_addr,
            peer_addr: peer.peer_addr,
            user_name: peer.user_name,
        });
        if transport == Transport::Packet {
            spawn_retransmit_loop(Arc::clone(&inner));
        }
        Self { inner }
    }

    /// Random session id, never 0 (0 is reserved).
    #[must_use]
    pub fn random_id() -> u32 {
        loop {
            let id = rand::rng().next_u32();
            if id != 0 {
                return id;
            }
        }
    }

    #[must_use]
    pub fn id(&self) -> u32 {
        self.inner.id
    }

    #[must_use]
    pub fn is_client(&self) -> bool {
        self.inner.is_client
    }

    #[must_use]
    pub fn state(&self) -> SessionState {
        self.inner.state()
    }

    pub fn set_read_deadline(&self, deadline: Option<Instant>) {
        *lock(&self.inner.read_deadline) = deadline;
    }
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr
    }

    #[must_use]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr
    }

    /// the `mierucommon.UserContext.UserName`, i.e. the user this session authenticated as.
    #[must_use]
    pub fn user_name(&self) -> Option<&str> {
        self.inner.user_name.as_deref()
    }

    pub fn set_write_deadline(&self, deadline: Option<Instant>) {
        *lock(&self.inner.write_deadline) = deadline;
    }

    /// Waits until the session reaches [`SessionState::Established`] or is closed; used by a
    /// client that must observe the server's open-session response before proceeding.
    pub async fn wait_established(&self) -> Result<()> {
        loop {
            match self.inner.state() {
                SessionState::Established => return Ok(()),
                SessionState::Closed => {
                    let err = lock(&self.inner.open_error).take();
                    return Err(err.unwrap_or(SessionError::Closed));
                }
                SessionState::Init | SessionState::Attached => {
                    let notified = self.inner.established.notified();
                    if self.inner.state() == SessionState::Attached {
                        notified.await;
                    }
                }
            }
        }
    }

    /// The write preconditions, checked before a write is accepted: a session that is
    /// closed or not attached yet refuses, and an expired write deadline answers `i/o timeout`.
    fn check_write_allowed(&self) -> Result<()> {
        match self.inner.state() {
            SessionState::Init => return Err(SessionError::NotReady),
            SessionState::Closed => return Err(SessionError::Closed),
            SessionState::Attached | SessionState::Established => {}
        }
        if self.inner.close_requested.load(Ordering::Acquire) {
            return Err(SessionError::Closed);
        }
        let write_deadline = *lock(&self.inner.write_deadline);
        if let Some(deadline) = write_deadline {
            if Instant::now() >= deadline {
                return Err(SessionError::WriteTimeout);
            }
        }
        Ok(())
    }

    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        self.check_write_allowed()?;

        let is_first_write = self.inner.is_client
            && self.inner.state() == SessionState::Attached
            && !self.inner.open_request_sent.swap(true, Ordering::AcqRel);
        if is_first_write {
            self.send_open_session_request(buf).await?;
            if buf.len() <= MAX_SESSION_OPEN_PAYLOAD {
                return Ok(buf.len());
            }
        }

        if self.inner.transport == Transport::Packet && self.inner.is_client {
            self.wait_established().await?;
        }

        let mut rest = buf;
        while !rest.is_empty() {
            let chunk_len = rest.len().min(MAX_PDU);
            let (chunk, tail) = rest.split_at(chunk_len);
            self.write_chunk(chunk).await?;
            rest = tail;
        }
        Ok(buf.len())
    }

    async fn send_open_session_request(&self, buf: &[u8]) -> Result<()> {
        let seq = self.inner.next_send.fetch_add(1, Ordering::AcqRel);
        let payload: &[u8] = if buf.len() <= MAX_SESSION_OPEN_PAYLOAD { buf } else { &[] };
        #[expect(clippy::cast_possible_truncation, reason = "a payload here is capped by MAX_SESSION_OPEN_PAYLOAD")]
        let payload_len = payload.len() as u16;
        let meta = SessionStruct {
            protocol: ProtocolType::OpenSessionRequest as u8,
            timestamp: wire::now_minutes(),
            session_id: self.inner.id,
            seq,
            status_code: wire::STATUS_OK,
            payload_len,
            suffix_len: 0,
        };
        self.transmit(meta.marshal(), payload, seq).await
    }

    async fn write_chunk(&self, chunk: &[u8]) -> Result<()> {
        let fragment_size = self.inner.fragment_size;
        let n_fragment = chunk.len().div_ceil(fragment_size).max(1);
        let mut ptr = chunk;
        for i in (0..n_fragment).rev() {
            if self.inner.transport == Transport::Packet {
                self.wait_for_send_window().await?;
            }
            let part_len = ptr.len().min(fragment_size);
            let (part, rest) = ptr.split_at(part_len);
            ptr = rest;
            let seq = self.inner.next_send.fetch_add(1, Ordering::AcqRel);
            let protocol =
                if self.inner.is_client { ProtocolType::DataClientToServer } else { ProtocolType::DataServerToClient };
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the wire fragment field is a u8 and an MTU-sized fragment makes a PDU a handful of them"
            )]
            let fragment = i as u8;
            #[expect(
                clippy::cast_possible_truncation,
                reason = "one fragment is at most MAX_PDU bytes, the wire's u16 length field"
            )]
            let payload_len = part.len() as u16;
            let meta = DataAckStruct {
                protocol: protocol as u8,
                timestamp: wire::now_minutes(),
                session_id: self.inner.id,
                seq,
                un_ack_seq: self.inner.next_recv.load(Ordering::Acquire),
                window_size: Inner::receive_window_size(),
                fragment,
                prefix_len: 0,
                payload_len,
                suffix_len: 0,
            };
            self.transmit(meta.marshal(), part, seq).await?;
        }
        Ok(())
    }

    /// The packet send window: the gate on the send queue. The waiter is
    /// armed before the window is read, because a close landing in between would otherwise be
    /// swallowed: `notify_waiters` only reaches waiters already registered.
    async fn wait_for_send_window(&self) -> Result<()> {
        loop {
            let notified = self.inner.send_window_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.state() == SessionState::Closed {
                return Err(SessionError::Closed);
            }
            let outstanding = self.inner.outstanding.lock().await;
            let cwnd = self.inner.cwnd.load(Ordering::Acquire);
            let remote = self.inner.remote_window_size.load(Ordering::Acquire).max(MIN_WINDOW_SIZE);
            let window = cwnd.min(remote) as usize;
            if outstanding.len() < window {
                return Ok(());
            }
            drop(outstanding);
            notified.await;
        }
    }

    async fn transmit(&self, meta: [u8; METADATA_LENGTH], payload: &[u8], seq: u32) -> Result<()> {
        if self.inner.transport == Transport::Packet {
            let mut outstanding = self.inner.outstanding.lock().await;
            outstanding.insert(
                seq,
                Outstanding {
                    meta,
                    payload: Bytes::copy_from_slice(payload),
                    sent_at: Instant::now(),
                    tx_count: 1,
                    ack_count: 0,
                },
            );
        }
        self.inner.sink.send_segment(meta, payload).await.map_err(SessionError::Io)
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let Some(mut chunk) = self.read_chunk().await? else {
            return Ok(0);
        };
        let n = chunk.len().min(buf.len());
        let leftover = chunk.split_off(n);
        let (dst, _) = buf.split_at_mut(n);
        dst.copy_from_slice(&chunk);
        if !leftover.is_empty() {
            *lock(&self.inner.unread) = Some(leftover);
        }
        Ok(n)
    }

    async fn read_chunk(&self) -> Result<Option<Bytes>> {
        std::future::poll_fn(|cx| self.poll_read_chunk(cx)).await
    }

    /// The read side as one cancel-safe poll: the queue, the surplus bytes and the deadline all
    /// live on the session, so a caller that abandons the poll (a deadline firing, a stream being
    /// dropped) loses nothing and the next read carries on where this one stopped.
    ///
    /// `Ok(None)` is a clean end of stream; a session whose underlay died answers
    /// [`SessionError::UnderlayClosed`] instead, an unexpected end. Neither wait is
    /// unbounded: the queue is finite and its sender is dropped when the session tears down.
    fn poll_read_chunk(&self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>>> {
        let leftover = lock(&self.inner.unread).take();
        if let Some(leftover) = leftover {
            return Poll::Ready(Ok(Some(leftover)));
        }
        let read_deadline = *lock(&self.inner.read_deadline);
        if let Some(deadline) = read_deadline {
            let deadline: tokio::time::Instant = deadline.into();
            let mut timer = lock(&self.inner.read_timer);
            if timer.as_ref().is_none_or(|sleep| sleep.deadline() != deadline) {
                *timer = Some(Box::pin(tokio::time::sleep_until(deadline)));
            }
            if timer.as_mut().is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready()) {
                return Poll::Ready(Err(SessionError::ReadTimeout));
            }
        }
        let poll = lock(&self.inner.read_rx).poll_recv(cx);
        match poll {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(chunk)) => Poll::Ready(Ok(Some(chunk))),
            Poll::Ready(None) => Poll::Ready(lock(&self.inner.read_end).unwrap_or(ReadEnd::Eof).into_result()),
        }
    }

    pub async fn close(&self) -> Result<()> {
        if self.inner.close_requested.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let state = self.inner.state();
        if state == SessionState::Attached || state == SessionState::Established {
            let seq = self.inner.next_send.fetch_add(1, Ordering::AcqRel);
            let meta = SessionStruct {
                protocol: ProtocolType::CloseSessionRequest as u8,
                timestamp: wire::now_minutes(),
                session_id: self.inner.id,
                seq,
                status_code: wire::STATUS_OK,
                payload_len: 0,
                suffix_len: 0,
            };
            let _ = self.inner.sink.send_segment(meta.marshal(), &[]).await;
        }
        self.force_close();
        Ok(())
    }

    /// The clean-close path: a reader parked on the session answers end of stream.
    pub(crate) fn force_close(&self) {
        self.tear_down(ReadEnd::Eof);
    }

    /// The abnormal teardown: the reader must see the reason rather than a clean EOF.
    pub(crate) fn force_close_with_error(&self, end: ReadEnd) {
        self.tear_down(end);
    }

    fn tear_down(&self, end: ReadEnd) {
        self.inner.tear_down(end);
    }

    fn note_incoming(&self) {
        *lock(&self.inner.last_recv_time) = Instant::now();
    }

    #[must_use]
    pub fn is_idle(&self, timeout: Duration) -> bool {
        lock(&self.inner.last_recv_time).elapsed() > timeout
    }

    fn validate_direction(&self, protocol: ProtocolType) -> Result<()> {
        let ok = if self.inner.is_client {
            protocol.is_server_to_client() || protocol.is_session_struct()
        } else {
            protocol.is_client_to_server() || protocol.is_session_struct()
        };
        if ok {
            Ok(())
        } else {
            Err(SessionError::ProtocolDirection)
        }
    }

    /// Dispatches one decoded, already-authenticated incoming segment to this session. Called by
    /// the owning underlay's read loop after it demultiplexes by session id.
    // NOT cancel-safe: the packet is already consumed from the socket and the handler writes replies and mutates handshake state as it runs, so a dropped call cannot be retried.
    pub async fn handle_incoming(
        &self,
        protocol: ProtocolType,
        session_meta: SessionMeta,
        payload: Bytes,
    ) -> Result<()> {
        self.note_incoming();
        self.validate_direction(protocol)?;
        match protocol {
            ProtocolType::OpenSessionRequest | ProtocolType::OpenSessionResponse => {
                self.on_data_like(session_meta, payload).await?;
                if !self.inner.is_client
                    && protocol == ProtocolType::OpenSessionRequest
                    && self.inner.state() == SessionState::Attached
                {
                    self.reply_open_session().await?;
                }
                if self.inner.is_client && protocol == ProtocolType::OpenSessionResponse {
                    let SessionMeta::Session(s) = session_meta else {
                        return Err(SessionError::ProtocolDirection);
                    };
                    if s.status_code == wire::STATUS_OK {
                        self.inner.forward_state_to(SessionState::Established);
                        self.inner.established.notify_waiters();
                    } else {
                        *lock(&self.inner.open_error) = Some(SessionError::Rejected(s.status_code));
                        self.force_close_with_error(ReadEnd::Rejected(s.status_code));
                    }
                }
            }
            ProtocolType::DataClientToServer | ProtocolType::DataServerToClient => {
                self.on_data_like(session_meta, payload).await?;
            }
            ProtocolType::AckClientToServer | ProtocolType::AckServerToClient => {
                let SessionMeta::DataAck(d) = session_meta else {
                    return Err(SessionError::ProtocolDirection);
                };
                self.apply_cumulative_ack(d).await;
            }
            ProtocolType::CloseSessionRequest => {
                let seq = self.inner.next_send.fetch_add(1, Ordering::AcqRel);
                let meta = SessionStruct {
                    protocol: ProtocolType::CloseSessionResponse as u8,
                    timestamp: wire::now_minutes(),
                    session_id: self.inner.id,
                    seq,
                    status_code: wire::STATUS_OK,
                    payload_len: 0,
                    suffix_len: 0,
                };
                let _ = self.inner.sink.send_segment(meta.marshal(), &[]).await;
                self.force_close();
            }
            ProtocolType::CloseSessionResponse => {
                self.force_close();
            }
            ProtocolType::CloseConnRequest | ProtocolType::CloseConnResponse => {}
        }
        Ok(())
    }

    async fn reply_open_session(&self) -> Result<()> {
        let seq = self.inner.next_send.fetch_add(1, Ordering::AcqRel);
        let meta = SessionStruct {
            protocol: ProtocolType::OpenSessionResponse as u8,
            timestamp: wire::now_minutes(),
            session_id: self.inner.id,
            seq,
            status_code: wire::STATUS_OK,
            payload_len: 0,
            suffix_len: 0,
        };
        self.transmit(meta.marshal(), &[], seq).await?;
        self.inner.forward_state_to(SessionState::Established);
        Ok(())
    }

    /// Hands one received segment to the read side, answering `false` once the session is torn
    /// down, so a caller stops feeding a queue nobody reads.
    async fn deliver(&self, payload: Bytes) -> bool {
        let Some(tx) = lock(&self.inner.read_tx).clone() else { return false };
        tx.send(payload).await.is_ok()
    }

    async fn on_data_like(&self, meta: SessionMeta, payload: Bytes) -> Result<()> {
        match self.inner.transport {
            Transport::Stream => {
                if !payload.is_empty() {
                    let _ = self.deliver(payload).await;
                }
            }
            Transport::Packet => {
                let seq = match meta {
                    SessionMeta::Session(s) => s.seq,
                    SessionMeta::DataAck(d) => {
                        self.apply_cumulative_ack(d).await;
                        self.inner.ack_on_data_recv.store(true, Ordering::Release);
                        d.seq
                    }
                };
                if !payload.is_empty() {
                    let mut reorder = self.inner.recv_reorder.lock().await;
                    reorder.insert(seq, payload);
                    drop(reorder);
                    self.drain_reorder_buffer().await;
                } else if self.inner.next_recv.load(Ordering::Acquire) == seq {
                    self.inner.next_recv.fetch_add(1, Ordering::AcqRel);
                }
            }
        }
        Ok(())
    }

    async fn drain_reorder_buffer(&self) {
        loop {
            let next = self.inner.next_recv.load(Ordering::Acquire);
            let Some(payload) = self.inner.recv_reorder.lock().await.remove(&next) else { break };
            self.inner.next_recv.fetch_add(1, Ordering::AcqRel);
            if !self.deliver(payload).await {
                break;
            }
        }
    }

    async fn apply_cumulative_ack(&self, d: DataAckStruct) {
        self.inner.remote_window_size.store(u32::from(d.window_size).max(MIN_WINDOW_SIZE), Ordering::Release);
        let mut outstanding = self.inner.outstanding.lock().await;
        let acked: Vec<u32> = outstanding.range(..d.un_ack_seq).map(|(seq, _)| *seq).collect();
        if !acked.is_empty() {
            let mut rtt = lock(&self.inner.rtt);
            for seq in &acked {
                if let Some(entry) = outstanding.remove(seq) {
                    rtt.update(entry.sent_at.elapsed());
                }
            }
            drop(rtt);
            let cwnd = self.inner.cwnd.load(Ordering::Acquire);
            let acked_count = u32::try_from(acked.len()).unwrap_or(u32::MAX);
            self.inner.cwnd.store((cwnd + acked_count).min(MAX_WINDOW_SIZE), Ordering::Release);
            self.inner.send_window_notify.notify_waiters();
        }
        if let Some(seq_entry) = outstanding.get_mut(&d.un_ack_seq) {
            seq_entry.ack_count += 1;
        }
    }
}

/// Which of the two 32-byte metadata shapes an incoming segment carried.
#[derive(Clone, Copy, Debug)]
pub enum SessionMeta {
    Session(SessionStruct),
    DataAck(DataAckStruct),
}

fn spawn_retransmit_loop(inner: Arc<Inner>) {
    tokio::spawn(async move {
        // A ticker first fires after one interval; `interval` would fire at once.
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + RETRANSMIT_TICK, RETRANSMIT_TICK);
        loop {
            interval.tick().await;
            if inner.state() == SessionState::Closed {
                return;
            }
            retransmit_once(&inner).await;
            if inner.state() == SessionState::Closed {
                return;
            }
            maybe_send_heartbeat(&inner).await;
        }
    });
}

async fn retransmit_once(inner: &Arc<Inner>) {
    let rto = lock(&inner.rtt).rto();
    let mut to_resend = Vec::new();
    let mut dead = false;
    {
        let mut outstanding = inner.outstanding.lock().await;
        for (seq, entry) in outstanding.iter_mut() {
            #[expect(clippy::cast_possible_wrap, reason = "tx_count is capped by TX_COUNT_LIMIT")]
            let exponent = entry.tx_count as i32;
            let backoff = 1.5f64.powi(exponent).min(20.0);
            let effective_rto = rto.mul_f64(backoff.max(1.0));
            let early = entry.ack_count >= EARLY_RETRANSMISSION;
            if entry.sent_at.elapsed() >= effective_rto || early {
                if entry.tx_count >= TX_COUNT_LIMIT {
                    dead = true;
                    continue;
                }
                entry.tx_count += 1;
                entry.ack_count = 0;
                entry.sent_at = Instant::now();
                to_resend.push((*seq, entry.meta, entry.payload.clone()));
            }
        }
    }
    if !to_resend.is_empty() {
        let cwnd = inner.cwnd.load(Ordering::Acquire);
        inner.cwnd.store((cwnd / 2).max(MIN_WINDOW_SIZE), Ordering::Release);
    }
    for (_, meta, payload) in to_resend {
        let _ = inner.sink.send_segment(meta, &payload).await;
    }
    if dead {
        close_after_retransmit_failure(inner).await;
    }
}

/// The close-with-error path for a session that has spent its whole retransmission budget: the peer
/// is told the session is going away, what is still in flight is dropped, and the teardown wakes
/// the tasks parked on it. Merely marking the state closed strands a reader on a queue nobody
/// will ever fill and a writer on a send window that will never drain.
async fn close_after_retransmit_failure(inner: &Arc<Inner>) {
    if inner.close_requested.swap(true, Ordering::AcqRel) {
        return;
    }
    let seq = inner.next_send.fetch_add(1, Ordering::AcqRel);
    let meta = SessionStruct {
        protocol: ProtocolType::CloseSessionRequest as u8,
        timestamp: wire::now_minutes(),
        session_id: inner.id,
        seq,
        status_code: wire::STATUS_OK,
        payload_len: 0,
        suffix_len: 0,
    };
    let _ = inner.sink.send_segment(meta.marshal(), &[]).await;
    inner.outstanding.lock().await.clear();
    inner.tear_down(ReadEnd::Eof);
}

async fn maybe_send_heartbeat(inner: &Arc<Inner>) {
    let (due, ack_on_recv) = {
        let mut last_ack = lock(&inner.last_ack_sent);
        let jitter_bound = u64::try_from(HEARTBEAT_JITTER.as_millis()).unwrap_or(u64::MAX);
        let jitter = Duration::from_millis(u64::from(rand::rng().next_u32()) % jitter_bound);
        let due = last_ack.elapsed() >= HEARTBEAT_INTERVAL + jitter;
        let ack_on_recv = inner.ack_on_data_recv.swap(false, Ordering::AcqRel);
        if due || ack_on_recv {
            *last_ack = Instant::now();
        }
        drop(last_ack);
        (due, ack_on_recv)
    };
    if !due && !ack_on_recv {
        return;
    }

    let protocol = if inner.is_client { ProtocolType::AckClientToServer } else { ProtocolType::AckServerToClient };
    let last_sent = inner.next_send.load(Ordering::Acquire).saturating_sub(1);
    let meta = DataAckStruct {
        protocol: protocol as u8,
        timestamp: wire::now_minutes(),
        session_id: inner.id,
        seq: last_sent,
        un_ack_seq: inner.next_recv.load(Ordering::Acquire),
        window_size: Inner::receive_window_size(),
        fragment: 0,
        prefix_len: 0,
        payload_len: 0,
        suffix_len: 0,
    };
    let _ = inner.sink.send_segment(meta.marshal(), &[]).await;
}

/// How long a close waits for a write `poll_write` already accepted before it tears the session
/// down anyway, the bound the close path puts on a writer that never finishes.
const CLOSE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The write this stream has accepted but not yet seen land.
///
/// A connection keeps a `Write` going after the caller's deadline abandons the poll, so the
/// accepted bytes are handed to a task of their own rather than parked in a future between
/// polls: they reach the peer even when the poll is cancelled, a later poll still learns how
/// they fared, and the state stays `Sync` without an `unsafe impl`.
#[derive(Default)]
struct AcceptedWrite {
    handle: StdMutex<Option<JoinHandle<Result<()>>>>,
    /// Armed by the first close that has to wait for the accepted write.
    close_deadline: StdMutex<Option<Pin<Box<Sleep>>>>,
}

impl AcceptedWrite {
    /// Waits for the accepted write: `Ok(())` means none is outstanding or it landed, and a
    /// failure is reported to whoever polls next.
    fn poll_settled(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let mut slot = lock(&self.handle);
        let Some(handle) = slot.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(handle).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(outcome) => {
                *slot = None;
                drop(slot);
                *lock(&self.close_deadline) = None;
                Poll::Ready(match outcome {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(err)) => Err(err),
                    Err(_) => Err(SessionError::Io(io::Error::other("the session write task panicked"))),
                })
            }
        }
    }

    /// As [`Self::poll_settled`], but bounded: a frame that never lands must not keep a close
    /// from tearing the session down.
    fn poll_before_close(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let settled = self.poll_settled(cx);
        if settled.is_ready() {
            return settled;
        }
        let mut deadline = lock(&self.close_deadline);
        let sleep = deadline.get_or_insert_with(|| Box::pin(tokio::time::sleep(CLOSE_WRITE_TIMEOUT)));
        let timed_out = sleep.as_mut().poll(cx).is_ready();
        drop(deadline);
        if timed_out {
            return Poll::Ready(Err(SessionError::WriteTimeout));
        }
        Poll::Pending
    }

    /// Takes on `write`; only one is ever outstanding, so the peer's segment order stays ours.
    fn accept(&self, write: impl Future<Output = Result<()>> + Send + 'static) {
        *lock(&self.handle) = Some(tokio::spawn(write));
    }
}

/// Adapts a [`Session`] to [`tokio::io::AsyncRead`]/[`AsyncWrite`] for use as a generic
/// duplex stream (the CONNECT-command byte stream, or the UDP-associate framing on top).
pub struct SessionStream {
    session: Arc<Session>,
    /// The request header the `EarlyConn` sends with the caller's first write; see
    /// [`SessionStream::with_pending_request`].
    pending_request: Option<Bytes>,
    write: AcceptedWrite,
}

impl std::fmt::Debug for SessionStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStream")
            .field("session", &self.session)
            .field("pending_request_len", &self.pending_request.as_ref().map(Bytes::len))
            .finish_non_exhaustive()
    }
}

impl SessionStream {
    #[must_use]
    pub fn new(session: Arc<Session>) -> Self {
        Self { session, pending_request: None, write: AcceptedWrite::default() }
    }

    /// The first write prepends the lazily-sent request header, so the
    /// peer gets the handshake and the caller's first bytes in one combined session write. The
    /// response is not read back here; the caller reads it lazily off the normal stream.
    #[must_use]
    pub fn with_pending_request(session: Arc<Session>, request: Vec<u8>) -> Self {
        Self { session, pending_request: Some(Bytes::from(request)), write: AcceptedWrite::default() }
    }

    pub fn session(&self) -> &Arc<Session> {
        &self.session
    }
}

impl AsyncRead for SessionStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.session.poll_read_chunk(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Some(mut chunk))) => {
                let n = chunk.len().min(buf.remaining());
                let leftover = chunk.split_off(n);
                buf.put_slice(&chunk);
                if !leftover.is_empty() {
                    *lock(&self.session.inner.unread) = Some(leftover);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
        }
    }
}

impl AsyncWrite for SessionStream {
    /// the accept-on-start: the session's state is checked here, the framing of the accepted
    /// bytes runs to completion in its own task, and a failure is reported at the next write,
    /// flush or shutdown. A new write waits for the accepted one, so the segment order the peer
    /// sees is the order the caller wrote in.
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.write.poll_settled(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
            Poll::Ready(Ok(())) => {}
        }
        if let Err(err) = self.session.check_write_allowed() {
            return Poll::Ready(Err(err.into()));
        }
        let accepted = buf.len();
        let bytes = match self.pending_request.take() {
            Some(request) => {
                let mut combined = Vec::with_capacity(request.len() + accepted);
                combined.extend_from_slice(&request);
                combined.extend_from_slice(buf);
                Bytes::from(combined)
            }
            None => Bytes::copy_from_slice(buf),
        };
        let session = Arc::clone(&self.session);
        self.write.accept(async move { session.write(&bytes).await.map(|_| ()) });
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.write.poll_settled(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(result.map_err(Into::into)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.write.poll_before_close(cx) {
            Poll::Pending => Poll::Pending,
            // A torn frame gets no close frame: the peer must see the truncated stream a dead
            // connection would give it, not a clean close that hides the lost bytes.
            Poll::Ready(Err(err)) => {
                self.session.force_close();
                Poll::Ready(Err(err.into()))
            }
            Poll::Ready(Ok(())) => {
                let session = Arc::clone(&self.session);
                // The close is the session's last write, and it travels through the same
                // slot so it can never overtake an accepted data frame.
                self.write.accept(async move { session.close().await });
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    struct RecordingSink {
        sent: Arc<StdMutex<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl SegmentSink for RecordingSink {
        async fn send_segment(&self, _meta: [u8; METADATA_LENGTH], payload: &[u8]) -> io::Result<()> {
            lock(&self.sent).extend_from_slice(payload);
            Ok(())
        }
    }

    /// A client session with no peer answering, so a read on it can only end by being woken.
    fn detached_session() -> (Arc<Session>, Arc<StdMutex<Vec<u8>>>) {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::new(RecordingSink { sent: Arc::clone(&sent) });
        (Arc::new(Session::new(9, true, Transport::Stream, MAX_PDU, sink, SessionPeer::default())), sent)
    }

    /// A deliberately closed session answers the reader parked on it with EOF, rather than
    /// leaving that reader on an unbounded `recv`.
    #[tokio::test]
    async fn a_forced_close_wakes_a_pending_read_with_eof() {
        let (session, _) = detached_session();
        let mut stream = SessionStream::new(Arc::clone(&session));
        let mut buf = [0u8; 8];
        let reading = tokio::spawn(async move { stream.read(&mut buf).await });
        tokio::task::yield_now().await;

        session.force_close();

        let read = tokio::time::timeout(TIMEOUT, reading)
            .await
            .expect("a force-closed session must wake its reader")
            .expect("reader task");
        assert_eq!(read.expect("read"), 0, "a deliberately closed session reads as EOF");
    }

    /// A lost underlay is not a clean end of stream: the reader has to see the error so a relay
    /// can tell a truncated stream from a finished one.
    #[tokio::test]
    async fn a_lost_underlay_wakes_a_pending_read_with_an_error() {
        let (session, _) = detached_session();
        let mut stream = SessionStream::new(Arc::clone(&session));
        let mut buf = [0u8; 8];
        let reading = tokio::spawn(async move { stream.read(&mut buf).await });
        tokio::task::yield_now().await;

        session.force_close_with_error(ReadEnd::UnderlayLost);

        let read = tokio::time::timeout(TIMEOUT, reading)
            .await
            .expect("a torn-down session must wake its reader")
            .expect("reader task");
        assert_eq!(read.expect_err("a lost underlay must not read as EOF").kind(), io::ErrorKind::UnexpectedEof);
    }

    /// A write the poll accepted belongs to the session, not to the stream that took it on, so
    /// abandoning that poll must not swallow the bytes.
    #[tokio::test]
    async fn an_accepted_write_outlives_the_stream_that_took_it_on() {
        let (session, sent) = detached_session();
        let mut stream = SessionStream::new(session);
        assert_eq!(stream.write(b"payload").await.expect("write"), 7);

        drop(stream);

        tokio::time::timeout(TIMEOUT, async {
            loop {
                if !lock(&sent).is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("an accepted write must reach the peer even after its stream is dropped");
        assert_eq!(lock(&sent).as_slice(), b"payload");
    }

    /// A write refused because the session is gone has to reach the caller as an error, not as a
    /// silently accepted write.
    #[tokio::test]
    async fn a_write_on_a_closed_session_is_refused() {
        let (session, _) = detached_session();
        session.force_close();
        let mut stream = SessionStream::new(session);

        let mut buf = [0u8; 8];
        assert_eq!(stream.read(&mut buf).await.expect("read"), 0, "a closed session reads as EOF");
        assert_eq!(
            stream.write(b"payload").await.expect_err("a closed session must refuse writes").kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    /// A server-side packet session whose peer acknowledges nothing, so only the retransmission
    /// budget can end it. Server-side because a client waits for `Established` before its first
    /// fragment, and that is the only path a test can reach the send-window wait on.
    fn silent_packet_session() -> Arc<Session> {
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::new(RecordingSink { sent });
        Arc::new(Session::new(11, false, Transport::Packet, MAX_PDU, sink, SessionPeer::default()))
    }

    fn in_flight(payload: &'static [u8], tx_count: u32) -> Outstanding {
        Outstanding {
            meta: [0u8; METADATA_LENGTH],
            payload: Bytes::from_static(payload),
            sent_at: Instant::now(),
            tx_count,
            ack_count: 0,
        }
    }

    /// A segment that has used up its retransmissions leaves nothing on the wire to arrive
    /// later, so the session is over and its reader has to be told. The reader is answered with
    /// a clean end of stream; stopping at the state flag alone leaves it parked on a queue nobody will fill.
    #[tokio::test]
    async fn a_session_out_of_retransmissions_wakes_its_reader() {
        let session = silent_packet_session();
        let mut stream = SessionStream::new(Arc::clone(&session));
        let mut buf = [0u8; 8];
        let reading = tokio::spawn(async move { stream.read(&mut buf).await });
        tokio::task::yield_now().await;

        let mut abandoned = in_flight(b"never-acked", TX_COUNT_LIMIT);
        abandoned.sent_at = Instant::now() - MAX_RTO * 4;
        session.inner.outstanding.lock().await.insert(0, abandoned);

        let read = tokio::time::timeout(TIMEOUT, reading)
            .await
            .expect("a session with no retransmissions left must wake its reader")
            .expect("reader task");
        assert_eq!(read.expect("read"), 0, "an abandoned session reads as EOF, the way a closed one does");
        assert!(
            session.inner.outstanding.lock().await.is_empty(),
            "an abandoned session must not keep retransmitting what it can no longer deliver"
        );
    }

    /// The send window is a gate, not a queue: closing the session has to release whoever is
    /// standing at it, the way a chunk write watches the closed channel alongside the window.
    /// Otherwise a closed session leaves its writer waiting on a window that will never drain.
    #[tokio::test]
    async fn a_close_releases_a_writer_blocked_on_the_send_window() {
        let session = silent_packet_session();
        {
            let mut outstanding = session.inner.outstanding.lock().await;
            for seq in 0..MIN_WINDOW_SIZE {
                outstanding.insert(seq, in_flight(b"", 1));
            }
        }

        let writing = tokio::spawn({
            let session = Arc::clone(&session);
            async move { session.write(b"payload").await }
        });
        // Let the writer reach the gate before the close, so this exercises the release rather
        // than a writer that arrives at an already-closed session.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }

        session.close().await.expect("close");

        let written = tokio::time::timeout(TIMEOUT, writing)
            .await
            .expect("closing a session must release a writer blocked on the send window")
            .expect("writer task");
        assert!(
            matches!(written, Err(SessionError::Closed)),
            "a closed session must fail the write it was holding back, not report success"
        );
    }
}

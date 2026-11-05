//! The control channel: the reliable control-packet layer, its cancel context and the TLS
//! payload parking.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{anyhow, Error};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{watch, Notify, Semaphore, SemaphorePermit};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::packet::{
    decode_control_packet, ControlCryptor, ControlPacket, Opcode, SessionID, KEY_ID_MASK, P_ACK_V1,
    P_CONTROL_HARD_RESET_CLIENT_V2, P_CONTROL_HARD_RESET_CLIENT_V3, P_CONTROL_HARD_RESET_SERVER_V1,
    P_CONTROL_HARD_RESET_SERVER_V2, P_CONTROL_SOFT_RESET_V1, P_CONTROL_V1,
};
use crate::tlscrypt::clone_bytes;
use murmur_common::errors::error_is;

/// A context cancellation error: cancelled or deadline exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ContextError {
    #[error("context canceled")]
    Canceled,
    #[error("context deadline exceeded")]
    DeadlineExceeded,
}

/// The cause a context was cancelled with.
#[derive(Debug, Clone)]
pub enum Cause {
    Canceled,
    DeadlineExceeded,
    Error(Arc<dyn std::error::Error + Send + Sync>),
}

impl Cause {
    pub fn from_error<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Error(Arc::new(err))
    }

    pub fn from_arc(err: Arc<dyn std::error::Error + Send + Sync>) -> Self {
        Self::Error(err)
    }

    /// Matches a cause against a target the caller knows.
    #[must_use]
    pub fn is<T: std::error::Error + 'static>(&self) -> bool {
        match self {
            Self::Error(err) => {
                let err: &(dyn std::error::Error + 'static) = &**err;
                err.downcast_ref::<T>().is_some()
            }
            Self::Canceled | Self::DeadlineExceeded => false,
        }
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canceled => write!(f, "context canceled"),
            Self::DeadlineExceeded => write!(f, "context deadline exceeded"),
            Self::Error(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Error(err) => {
                let err: &(dyn std::error::Error + 'static) = &**err;
                Some(err)
            }
            Self::Canceled | Self::DeadlineExceeded => None,
        }
    }
}

impl From<ContextError> for Cause {
    fn from(err: ContextError) -> Self {
        match err {
            ContextError::Canceled => Self::Canceled,
            ContextError::DeadlineExceeded => Self::DeadlineExceeded,
        }
    }
}

static TOKEN_CAUSES: LazyLock<DashMap<CancellationToken, Cause>> = LazyLock::new(DashMap::new);

struct CtxInner {
    token: CancellationToken,
    cause: Mutex<Option<Cause>>,
    parent: Option<Arc<Self>>,
    has_done: bool,
}

impl CtxInner {
    fn chain_cause(&self) -> Option<Cause> {
        let recorded = self.cause.lock().clone();
        if let Some(cause) = recorded {
            return Some(cause);
        }
        if let Some(cause) = &self.parent {
            if let Some(cause) = cause.chain_cause() {
                return Some(cause);
            }
        }
        TOKEN_CAUSES.get(&self.token).map(|entry| entry.clone())
    }
}

impl Drop for CtxInner {
    fn drop(&mut self) {
        if self.cause.lock().is_some() {
            TOKEN_CAUSES.remove(&self.token);
        }
    }
}

/// A cancellation context: cancellation plus the cancellation cause, which a bare
/// `CancellationToken` cannot carry.
#[derive(Clone)]
pub struct CancelContext {
    inner: Arc<CtxInner>,
}

impl fmt::Debug for CancelContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancelContext").finish_non_exhaustive()
    }
}

impl Default for CancelContext {
    fn default() -> Self {
        Self::background()
    }
}

impl CancelContext {
    /// A background context: never cancelled by a parent, and never done.
    #[must_use]
    pub fn background() -> Self {
        Self {
            inner: Arc::new(CtxInner {
                token: CancellationToken::new(),
                cause: Mutex::new(None),
                parent: None,
                has_done: false,
            }),
        }
    }

    /// Wraps a token owned elsewhere; this context is cancelled when that token is.
    #[must_use]
    pub fn from_token(token: CancellationToken) -> Self {
        Self { inner: Arc::new(CtxInner { token, cause: Mutex::new(None), parent: None, has_done: true }) }
    }

    #[must_use]
    pub fn with_cancel_cause(&self) -> Self {
        Self {
            inner: Arc::new(CtxInner {
                token: self.inner.token.child_token(),
                cause: Mutex::new(None),
                parent: Some(Arc::clone(&self.inner)),
                has_done: true,
            }),
        }
    }

    /// A deadline context: the child is cancelled with `DeadlineExceeded` once the
    /// deadline elapses, or with its parent.
    #[must_use]
    pub fn with_deadline(&self, deadline: Instant) -> Self {
        let child = self.with_cancel_cause();
        let cancel = child.clone();
        let token = child.inner.token.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => {
                    cancel.cancel(Some(Cause::DeadlineExceeded));
                }
                () = token.cancelled() => {}
            }
        });
        child
    }

    /// Cancels with a cause: the first cancellation wins, `None` means `Canceled`.
    pub fn cancel(&self, cause: Option<Cause>) {
        let cause = cause.unwrap_or(Cause::Canceled);
        {
            let mut slot = self.inner.cause.lock();
            if slot.is_none() {
                *slot = Some(cause.clone());
                TOKEN_CAUSES.entry(self.inner.token.clone()).or_insert(cause);
            }
            drop(slot);
        }
        self.inner.token.cancel();
    }

    pub fn done(&self) -> impl Future<Output = ()> + Send + 'static {
        let token = self.inner.token.clone();
        async move { token.cancelled().await }
    }

    /// The underlying token, for `tokio::select!` and `contextutils::after_func`.
    #[must_use]
    pub fn token(&self) -> &CancellationToken {
        &self.inner.token
    }

    #[must_use]
    pub fn has_done(&self) -> bool {
        self.inner.has_done
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        self.inner.token.is_cancelled()
    }

    #[must_use]
    pub fn err(&self) -> Option<Error> {
        if !self.is_done() {
            return None;
        }
        match self.cause() {
            Some(Cause::DeadlineExceeded) => Some(Error::new(ContextError::DeadlineExceeded)),
            _ => Some(Error::new(ContextError::Canceled)),
        }
    }

    #[must_use]
    pub fn cause(&self) -> Option<Cause> {
        if !self.is_done() {
            return None;
        }
        self.inner.chain_cause().or(Some(Cause::Canceled))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("use of closed network connection")]
pub struct ErrClosed;

/// Builds the `io::Error` shape of [`ErrClosed`].
#[must_use]
pub fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, ErrClosed)
}

/// Boxes a channel error into an `io::Error`. `anyhow::Error`'s `Into<Box<dyn Error>>`
/// conversion does not preserve the concrete inner type for `downcast_ref`, so once `err`
/// is erased via `io::Error::other` below, only its `kind()`/`Display` stay visible to a
/// caller; an `ErrClosed` payload must be re-detected here, before erasure, and given
/// `closed_error()`'s `NotConnected` kind so `is_err_net_closed`'s kind fallback still finds it.
fn channel_io_error(err: Error) -> io::Error {
    if err.is::<ErrClosed>() {
        return closed_error();
    }
    io::Error::other(err)
}

/// Matches the parked-TLS error by type.
pub(crate) fn is_parked_tls(err: &Error) -> bool {
    error_is::<ErrParkedTLS>(err)
}

/// The packet-dropped error as the packetio module classifies it.
fn is_packet_dropped(err: &Error) -> bool {
    crate::packetio::is_packet_dropped(err)
}

#[async_trait]
pub trait ControlIO: Send + Sync {
    async fn read_packet(&self, ctx: &CancelContext) -> anyhow::Result<Vec<u8>>;
    async fn write_packet(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()>;
    async fn write_packet_allow_active_stop(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()>;
    async fn close(&self) -> anyhow::Result<()>;
    fn local_addr(&self) -> Option<SocketAddr>;
    fn remote_addr(&self) -> Option<SocketAddr>;

    /// The optional initial-packet-receiver interface, implemented by the packet mux.
    fn mark_initial_packet_received(&self) {}
}

pub(crate) struct ReplayState {
    pub(crate) time: u32,
    pub(crate) high_id: u32,
    pub(crate) slots: [i64; CONTROL_REPLAY_WINDOW],
    pub(crate) seen: bool,
}

/// Mirrors `OpenVPN`'s `REPLAY_WINDOW` (64) used for the control-channel `packet_id_rec`
/// `seq_backtrack`.
pub(crate) const CONTROL_REPLAY_WINDOW: usize = 64;
pub(crate) const CONTROL_REPLAY_TIME_BACKTRACK: Duration = Duration::from_secs(15);

/// Seconds and nanoseconds since the Unix epoch.
fn unix_nanos(t: DateTime<Utc>) -> i64 {
    t.timestamp() * 1_000_000_000 + i64::from(t.timestamp_subsec_nanos())
}

/// Reports whether an out-of-order control packet with the given message ID fits the receive
/// window. Unsigned subtraction stays correct
/// when the 32-bit sequence wraps.
#[expect(clippy::cast_possible_truncation, reason = "`RELIABLE_CAPACITY` is 12, which fits a `u32`")]
pub(crate) const fn recv_window_ok(recv_message: u32, message_id: u32, buffered: usize) -> bool {
    message_id.wrapping_sub(recv_message) < RELIABLE_CAPACITY as u32 && buffered < RELIABLE_CAPACITY
}

pub(crate) const fn reliable_message_before(message_id: u32, recv_message: u32) -> bool {
    message_id.wrapping_sub(recv_message) >= 1u32 << 31
}

pub(crate) struct ChannelState {
    pub(crate) clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    pub(crate) replay_clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    pub(crate) key_id: u8,
    pub(crate) remote: SessionID,
    pub(crate) send_packet_id: u32,
    pub(crate) send_packet_time: u32,
    pub(crate) send_message: u32,
    pub(crate) recv_message: u32,
    pub(crate) ack_pending: Vec<u32>,
    /// The MRU of recently acknowledged packet IDs:
    /// acks are copied here when sent and kept so later control packets repeat them.
    pub(crate) lru_acks: Vec<u32>,
    pub(crate) pending: HashMap<u32, Arc<ControlPacket>>,
    pub(crate) recv_pending: HashMap<u32, Arc<ControlPacket>>,
    /// A server soft reset that arrived while the current epoch was still doing TLS/key-method;
    /// `wait_for_soft_reset` consumes it so `ControlConn::read` cannot swallow it.
    pub(crate) pending_soft_reset: Option<Arc<ControlPacket>>,
    /// Same-epoch `P_CONTROL_V1` payloads that arrived while the watcher waited for a soft reset
    /// (typically a token-only `PUSH_REPLY`); `read_all` drains them into the TLS stream.
    pub(crate) parked_tls: Vec<Vec<u8>>,
    pub(crate) read_deadline: Option<Instant>,
    pub(crate) write_deadline: Option<Instant>,
    pub(crate) write_cancel: Option<CancelContext>,
    pub(crate) write_timer: Option<JoinHandle<()>>,
    pub(crate) write_deadline_generation: u64,
    pub(crate) write_generation: u64,
    /// Bumped by `signal_read_wake_locked`; the value doubles as the wake generation.
    pub(crate) read_wake: watch::Sender<u64>,
    /// Session-wide anti-replay window for tls-auth / tls-crypt protected control packets,
    /// mirroring `OpenVPN`'s `packet_id_rec`. Soft key resets do not replace the outer TLS wrapper
    /// or reset its packet IDs.
    pub(crate) rec_replay: ReplayState,
}

impl ChannelState {
    /// Validates a protected control packet's packet-id/timestamp against the anti-replay window.
    fn check_replay_locked(&mut self, packet_id: u32, unix_time: u32) -> anyhow::Result<()> {
        if packet_id == 0 {
            return Err(anyhow!("openvpn control replay: packet id 0"));
        }
        let replay_clock = Arc::clone(&self.replay_clock);
        let now = replay_clock();
        let r = &mut self.rec_replay;
        if !r.seen || unix_time > r.time {
            *r = ReplayState { time: unix_time, high_id: packet_id, slots: [0; CONTROL_REPLAY_WINDOW], seen: true };
            r.slots[0] = unix_nanos(now);
            return Ok(());
        }
        if unix_time < r.time {
            return Err(anyhow!("openvpn control replay: timestamp backtrack {unix_time} < {}", r.time));
        }
        r.reap(now);
        if packet_id > r.high_id {
            let shift = (packet_id - r.high_id) as usize;
            if shift >= CONTROL_REPLAY_WINDOW {
                r.slots = [0; CONTROL_REPLAY_WINDOW];
            } else {
                r.slots.copy_within(..CONTROL_REPLAY_WINDOW - shift, shift);
                let (vacated, _) = r.slots.split_at_mut(shift);
                vacated.fill(0);
            }
            r.high_id = packet_id;
            r.slots[0] = unix_nanos(now);
            return Ok(());
        }
        let diff = (r.high_id - packet_id) as usize;
        if diff >= CONTROL_REPLAY_WINDOW {
            return Err(anyhow!("openvpn control replay: stale packet id {packet_id}"));
        }
        let Some(accepted) = r.slots.get_mut(diff) else {
            return Err(anyhow!("openvpn control replay: stale packet id {packet_id}"));
        };
        if *accepted != 0 {
            return Err(anyhow!("openvpn control replay: replayed or expired packet id {packet_id}"));
        }
        *accepted = unix_nanos(now);
        Ok(())
    }

    /// Keeps packets from another session or key epoch out of the established control channel.
    fn classify_watch_packet_locked(&self, packet: &ControlPacket) -> (bool, bool) {
        if self.remote == SessionID::default() || packet.local_session != self.remote {
            return (false, false);
        }
        if packet.opcode == P_CONTROL_SOFT_RESET_V1 {
            // OpenVPN advances 0 -> 1 -> ... -> 7 -> 1. A delayed reset from a retiring epoch, or
            // key ID 0 after the initial epoch, must not move the client backwards, and a
            // new-epoch reset is always message 0.
            let expected = next_key_id(self.key_id);
            let valid = packet.key_id == expected && packet.message_id == 0;
            return (valid, valid);
        }
        (false, packet.key_id == self.key_id)
    }

    /// Moves `ack_pending` into the MRU and returns up to `max` ACK IDs to serialize on the
    /// outgoing packet. Mirrors `OpenVPN` `copy_acks_to_mru` + `reliable_ack_write`: each pending ID
    /// is moved to the front of the MRU (existing entries shift right; a duplicate is removed), so
    /// re-acked IDs are not evicted when the MRU is full. The MRU keeps its full capacity; `max`
    /// only bounds what is serialized on this packet.
    fn take_acks_locked(&mut self, max: usize) -> Vec<u32> {
        // Consume only the pending ACKs that can be serialized now, like `reliable_ack_write`:
        // keep the remainder pending for the next packet so the per-packet cap does not drop them.
        let mut n = self.ack_pending.len();
        if n > max {
            n = max;
        }
        for id in self.ack_pending.iter().take(n).rev().copied() {
            let mut moved = id;
            let mut found = false;
            for slot in &mut self.lru_acks {
                std::mem::swap(slot, &mut moved);
                if moved == id {
                    found = true;
                    break;
                }
            }
            if !found && self.lru_acks.len() < RELIABLE_ACK_SIZE {
                self.lru_acks.push(moved);
            }
        }
        let rest = self.ack_pending.split_off(n);
        self.ack_pending = if rest.is_empty() { Vec::new() } else { rest };
        if self.lru_acks.len() > RELIABLE_ACK_SIZE {
            self.lru_acks.truncate(RELIABLE_ACK_SIZE);
        }
        let mut k = self.lru_acks.len();
        if k > max {
            k = max;
        }
        let (serialized, _) = self.lru_acks.split_at(k);
        serialized.to_vec()
    }
}

impl Default for ReplayState {
    fn default() -> Self {
        Self { time: 0, high_id: 0, slots: [0; CONTROL_REPLAY_WINDOW], seen: false }
    }
}

/// Ages the long-form packet-id window.
impl ReplayState {
    fn reap(&mut self, now: DateTime<Utc>) {
        let mut expire = false;
        let now_nanos = unix_nanos(now);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the 15-second backtrack is far below the `i64` nanosecond range"
        )]
        let backtrack_nanos = CONTROL_REPLAY_TIME_BACKTRACK.as_nanos() as i64;
        for slot in &mut self.slots {
            let accepted = *slot;
            if accepted == 1 {
                break;
            }
            if !expire && accepted > 1 && accepted + backtrack_nanos < now_nanos {
                expire = true;
            }
            if expire {
                *slot = 1;
            }
        }
    }
}

/// The reliable ACK size, in bytes.
pub(crate) const RELIABLE_ACK_SIZE: usize = 8;

/// The receive reliable buffer capacity.
pub(crate) const RELIABLE_CAPACITY: usize = 12;

/// The maximum control-channel send ACKs.
pub(crate) const CONTROL_SEND_ACK_MAX: usize = 4;

/// Keeps each default `OpenVPN` control datagram below `TLS_MTU_DEFAULT` (1250) even with
/// tls-auth/tls-crypt and four piggyback ACKs. `OpenVPN` splits TLS ciphertext before placing it in
/// the reliable channel; the TLS stack may otherwise hand `write` a record much larger than one
/// datagram.
pub(crate) const MAX_TLS_CONTROL_PAYLOAD: usize = 1100;

/// The parked-TLS error: returned by `wait_for_soft_reset` when it parked a same-epoch TLS control
/// payload (token update / `AUTH_FAILED`) that must be consumed before waiting for a soft reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("parked tls control payload")]
pub struct ErrParkedTLS;

/// What `read_watch` does with a packet that already passed session validation.
enum WatchOutcome {
    /// The packet was consumed here (parked or dropped).
    Drop,
    /// The packet is resolved and goes back to the caller.
    Return(Arc<ControlPacket>),
    /// The packet continues into the reliable receive bookkeeping.
    Deliver,
}

#[derive(Clone)]
pub struct ControlChannel {
    pub(crate) io: Arc<dyn ControlIO>,
    pub(crate) crypt: Option<Arc<dyn ControlCryptor>>,
    pub(crate) local: SessionID,
    pub(crate) send_gate: Arc<Semaphore>,
    pub(crate) ack_wake: Arc<Notify>,
    pub(crate) state: Arc<Mutex<ChannelState>>,
}

impl fmt::Debug for ControlChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlChannel").field("local", &self.local).finish_non_exhaustive()
    }
}

pub fn new_control_channel(
    io: Arc<dyn ControlIO>,
    crypt: Option<Arc<dyn ControlCryptor>>,
    local: SessionID,
) -> ControlChannel {
    let (read_wake, _) = watch::channel(0u64);
    ControlChannel {
        io,
        crypt,
        local,
        send_gate: Arc::new(Semaphore::new(1)),
        ack_wake: Arc::new(Notify::new()),
        state: Arc::new(Mutex::new(ChannelState {
            clock: Arc::new(Utc::now),
            replay_clock: Arc::new(Utc::now),
            key_id: 0,
            remote: SessionID::default(),
            send_packet_id: 0,
            send_packet_time: 0,
            send_message: 0,
            recv_message: 0,
            ack_pending: Vec::new(),
            lru_acks: Vec::new(),
            pending: HashMap::new(),
            recv_pending: HashMap::new(),
            pending_soft_reset: None,
            parked_tls: Vec::new(),
            read_deadline: None,
            write_deadline: None,
            write_cancel: None,
            write_timer: None,
            write_deadline_generation: 0,
            write_generation: 0,
            read_wake,
            rec_replay: ReplayState::default(),
        })),
    }
}

impl Default for ControlChannel {
    fn default() -> Self {
        new_control_channel(Arc::new(NullControlIO), None, SessionID::default())
    }
}

/// Stand-in for a missing `ControlIO` value, which the zero-value `ControlChannel` used by
/// tests carries.
struct NullControlIO;

#[async_trait]
impl ControlIO for NullControlIO {
    async fn read_packet(&self, _ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
        Err(anyhow!("nil openvpn control io"))
    }

    async fn write_packet(&self, _ctx: &CancelContext, _packet: &[u8]) -> anyhow::Result<()> {
        Err(anyhow!("nil openvpn control io"))
    }

    async fn write_packet_allow_active_stop(&self, _ctx: &CancelContext, _packet: &[u8]) -> anyhow::Result<()> {
        Err(anyhow!("nil openvpn control io"))
    }

    async fn close(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }
}

#[allow(
    dead_code,
    reason = "crypt/state/check_replay_locked/classify_watch_packet_locked/begin_epoch_locked/take_acks_locked/cancel_write_generation are exercised only by #[cfg(test)] tests"
)]
impl ControlChannel {
    pub fn new(io: Arc<dyn ControlIO>, crypt: Option<Arc<dyn ControlCryptor>>, local: SessionID) -> Self {
        new_control_channel(io, crypt, local)
    }

    /// The configured control cryptor; exposed because the tests inspect it.
    pub(crate) fn crypt(&self) -> Option<&Arc<dyn ControlCryptor>> {
        self.crypt.as_ref()
    }

    /// The mutable channel state, mirroring the package-internal field access.
    pub(crate) const fn state(&self) -> &Arc<Mutex<ChannelState>> {
        &self.state
    }

    pub(crate) fn check_replay_locked(&self, packet_id: u32, unix_time: u32) -> anyhow::Result<()> {
        self.state.lock().check_replay_locked(packet_id, unix_time)
    }

    pub(crate) fn classify_watch_packet_locked(&self, packet: &ControlPacket) -> (bool, bool) {
        self.state.lock().classify_watch_packet_locked(packet)
    }

    pub(crate) fn begin_epoch_locked(&self, key_id: u8) {
        begin_epoch_locked(&mut self.state.lock(), key_id);
    }

    pub(crate) fn take_acks_locked(&self, max: usize) -> Vec<u32> {
        self.state.lock().take_acks_locked(max)
    }

    pub(crate) fn cancel_write_generation(
        &self,
        write_generation: u64,
        deadline_generation: u64,
        cancel: &CancelContext,
    ) {
        cancel_write_deadline_generation(&self.state, write_generation, deadline_generation, cancel);
    }
}

impl ControlChannel {
    #[must_use]
    pub const fn local_session_id(&self) -> SessionID {
        self.local
    }

    #[must_use]
    pub fn remote_session_id(&self) -> SessionID {
        self.state.lock().remote
    }

    pub fn set_remote_session_id(&self, id: SessionID) {
        self.state.lock().remote = id;
    }

    /// Overrides the wall clock used for the packet-id timestamp.
    pub fn set_clock(&self, clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>) {
        self.state.lock().clock = clock;
    }

    /// Overrides the wall clock used by the anti-replay window.
    pub fn set_replay_clock(&self, clock: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>) {
        self.state.lock().replay_clock = clock;
    }

    pub async fn send_reset(&self, ctx: &CancelContext) -> anyhow::Result<()> {
        let mut opcode = P_CONTROL_HARD_RESET_CLIENT_V2;
        let is_tls_crypt_v2 = self.crypt.as_ref().is_some_and(|crypt| crypt.wrapped_client_key().is_some());
        if is_tls_crypt_v2 {
            opcode = P_CONTROL_HARD_RESET_CLIENT_V3;
        }
        self.send(ctx, opcode, &[]).await?;
        Ok(())
    }

    #[must_use]
    pub fn key_id(&self) -> u8 {
        self.state.lock().key_id
    }

    /// Advances to the next local key epoch and resets reliable state.
    #[must_use]
    pub fn rotate_key_id(&self) -> u8 {
        let mut st = self.state.lock();
        let key_id = next_key_id(st.key_id);
        begin_epoch_locked(&mut st, key_id);
        st.key_id
    }

    /// Switches to the key ID supplied by the peer's soft-reset packet.
    pub fn adopt_key_id(&self, key_id: u8) {
        let mut st = self.state.lock();
        begin_epoch_locked(&mut st, key_id);
    }

    /// Records a reliable message ID to be acknowledged on the next send.
    pub fn queue_ack(&self, message_id: u32) {
        let mut st = self.state.lock();
        append_ack(&mut st.ack_pending, message_id);
        drop(st);
        signal_ack_locked(&self.ack_wake);
    }

    /// Waits until the channel signals a pending acknowledgement.
    pub async fn wait_ack_wake(&self) {
        self.ack_wake.notified().await;
    }

    #[must_use]
    pub fn ack_wake(&self) -> Arc<Notify> {
        Arc::clone(&self.ack_wake)
    }

    fn signal_ack(&self) {
        let _st = self.state.lock();
        signal_ack_locked(&self.ack_wake);
    }

    #[must_use]
    pub fn pending_acks(&self) -> usize {
        self.state.lock().ack_pending.len()
    }

    /// Advances the reliable receive sequence past `message_id`, used after a server soft reset has
    /// already been consumed by the watcher so the new epoch does not wait forever for message 0.
    pub fn mark_received(&self, message_id: u32) {
        let mut st = self.state.lock();
        let next = message_id.wrapping_add(1);
        if next != st.recv_message && !reliable_message_before(next, st.recv_message) {
            st.recv_message = next;
        }
        st.recv_pending.remove(&message_id);
    }

    /// Sends a `P_CONTROL_SOFT_RESET_V1` on the current key epoch. Call `adopt_key_id` or
    /// `rotate_key_id` first so the packet uses the new key ID.
    pub async fn send_soft_reset(&self, ctx: &CancelContext) -> anyhow::Result<()> {
        self.send(ctx, P_CONTROL_SOFT_RESET_V1, &[]).await?;
        Ok(())
    }

    pub async fn send(&self, ctx: &CancelContext, opcode: Opcode, payload: &[u8]) -> anyhow::Result<u32> {
        if !opcode.has_message_id() {
            return Err(anyhow!("opcode {opcode} cannot carry a reliable message"));
        }

        let (packet, message_id) = {
            let mut st = self.state.lock();
            let message_id = st.send_message;
            st.send_message = st.send_message.wrapping_add(1);
            let ack_ids = st.take_acks_locked(CONTROL_SEND_ACK_MAX);
            let packet = Arc::new(ControlPacket {
                opcode,
                key_id: st.key_id,
                local_session: self.local,
                ack_ids,
                ack_remote_session: st.remote,
                message_id,
                payload: clone_bytes(payload),
                received_at: None,
            });
            st.pending.insert(message_id, Arc::clone(&packet));
            drop(st);
            (packet, message_id)
        };

        self.write_control_packet(ctx, &packet).await?;
        Ok(message_id)
    }

    fn dedicated_ack_max(&self) -> usize {
        if self.crypt.is_none() {
            return CONTROL_SEND_ACK_MAX;
        }
        RELIABLE_ACK_SIZE
    }

    pub async fn send_ack(&self, ctx: &CancelContext) -> anyhow::Result<()> {
        // Select the ACK IDs and key epoch only after this write owns the logical send gate, so an
        // asynchronous ACK is never constructed for an old epoch and emitted after a new epoch's
        // first reliable packet.
        let has_pending = !self.state.lock().ack_pending.is_empty();
        if !has_pending {
            return Ok(());
        }
        let permit = acquire_write_gate(ctx, &self.send_gate).await?;
        if let Some(err) = ctx.err() {
            return Err(err);
        }
        let packet = {
            let mut st = self.state.lock();
            if st.ack_pending.is_empty() {
                return Ok(());
            }
            let max = self.dedicated_ack_max();
            let ack_ids = st.take_acks_locked(max);
            ControlPacket {
                opcode: P_ACK_V1,
                key_id: st.key_id,
                local_session: self.local,
                ack_ids,
                ack_remote_session: st.remote,
                message_id: 0,
                payload: Vec::new(),
                received_at: None,
            }
        };
        let result = self.write_control_packet_granted(ctx, &packet, true).await;
        drop(permit);
        result
    }

    pub async fn read(&self, ctx: &CancelContext) -> anyhow::Result<Arc<ControlPacket>> {
        self.read_watch(ctx, false).await
    }

    pub async fn wait_for_soft_reset(&self, ctx: &CancelContext) -> anyhow::Result<Arc<ControlPacket>> {
        {
            let mut st = self.state.lock();
            if let Some(packet) = st.pending_soft_reset.take() {
                // Defensive: a parked reset must be the strictly-next epoch and message 0; drop it
                // otherwise, never advancing the receive sequence off an invalid reset.
                let expected = next_key_id(st.key_id);
                if packet.key_id == expected && packet.message_id == 0 {
                    drop(st);
                    return Ok(packet);
                }
            }
        }

        loop {
            let packet = self.read_watch(ctx, true).await?;
            if packet.opcode == P_CONTROL_SOFT_RESET_V1 {
                return Ok(packet);
            }
            // A same-epoch P_CONTROL_V1 after a rekey is typically a token-only PUSH_REPLY
            // (`send_push_reply_auth_token`). Park the TLS payload for `read_all` instead of
            // ACK-and-dropping it, and return so the caller consumes it immediately: a late
            // AUTH_FAILED must not wait for the next soft reset. read() already ACKed.
            if packet.opcode == P_CONTROL_V1 && !packet.payload.is_empty() {
                self.state.lock().parked_tls.push(packet.payload.clone());
                return Err(Error::new(ErrParkedTLS));
            }
            self.signal_ack();
        }
    }

    /// Returns every queued control packet decoded so far, without touching the underlying TLS
    /// state of the active epoch. `pending_soft_reset` is deliberately left in place: it is the
    /// trigger for the next rekey, not TLS payload.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the epoch guard spans the drain loop, which re-reads the pending map on every iteration"
    )]
    #[must_use]
    pub fn read_all(&self) -> Vec<Arc<ControlPacket>> {
        let mut st = self.state.lock();
        let n = st.recv_pending.len() + st.parked_tls.len();
        if n == 0 {
            return Vec::new();
        }
        let mut out: Vec<Arc<ControlPacket>> = Vec::with_capacity(n);
        // Parked payloads were received out of order and already advanced `recv_message`, so they
        // logically precede any newly contiguous `recv_pending` entries; emitting them first keeps
        // the TLS byte stream in order after UDP reordering.
        for payload in st.parked_tls.drain(..) {
            let ControlPacket { key_id, local_session, ack_ids, ack_remote_session, message_id, received_at, .. } =
                ControlPacket::default();
            out.push(Arc::new(ControlPacket {
                opcode: P_CONTROL_V1,
                key_id,
                local_session,
                ack_ids,
                ack_remote_session,
                message_id,
                payload,
                received_at,
            }));
        }
        let mut id = st.recv_message;
        while let Some(packet) = st.recv_pending.remove(&id) {
            st.recv_message = id.wrapping_add(1);
            out.push(packet);
            id = id.wrapping_add(1);
        }
        out
    }

    async fn read_watch(&self, ctx: &CancelContext, watch_soft_reset: bool) -> anyhow::Result<Arc<ControlPacket>> {
        loop {
            if let Some(err) = ctx.err() {
                return Err(err);
            }
            if let Some(packet) = self.take_contiguous_packet(watch_soft_reset) {
                return Ok(packet);
            }

            let Some((packet, packet_id, unix_time)) = self.read_checked_packet(ctx).await? else {
                continue;
            };
            let Some(replay_checked) = self.resolve_watch_remote(&packet, packet_id, unix_time) else {
                continue;
            };

            let outcome = if watch_soft_reset {
                self.gate_watch_packet(&packet, packet_id, unix_time)
            } else {
                self.gate_epoch_packet(&packet, packet_id, unix_time, replay_checked)
            };
            match outcome {
                WatchOutcome::Drop => continue,
                WatchOutcome::Return(packet) => return Ok(packet),
                WatchOutcome::Deliver => {}
            }

            if let Some(packet) = self.queue_for_delivery(&packet) {
                return Ok(packet);
            }
        }
    }

    #[must_use]
    pub fn pending_messages(&self) -> usize {
        self.state.lock().pending.len()
    }

    pub async fn retransmit_pending(&self, ctx: &CancelContext) -> anyhow::Result<()> {
        let packets = {
            let mut st = self.state.lock();
            // Nothing to retransmit: do not consume pending ACKs, since moving them into the MRU
            // without emitting a packet would drop them.
            if st.pending.is_empty() {
                return Ok(());
            }
            let mut packets: Vec<ControlPacket> = Vec::with_capacity(st.pending.len());
            // Pull current acks into the MRU once, so every retransmitted packet carries the same
            // ack set, matching OpenVPN's retransmission of the original ack header.
            let ack_ids = st.take_acks_locked(CONTROL_SEND_ACK_MAX);
            let remote = st.remote;
            for packet in st.pending.values() {
                let mut packet = (**packet).clone();
                packet.ack_ids.clone_from(&ack_ids);
                packet.ack_remote_session = remote;
                packets.push(packet);
            }
            drop(st);
            packets
        };

        for packet in &packets {
            self.write_control_packet_with_abort(ctx, packet, false).await?;
        }
        Ok(())
    }

    pub async fn write_control_packet(&self, ctx: &CancelContext, packet: &ControlPacket) -> anyhow::Result<()> {
        self.write_control_packet_with_abort(ctx, packet, true).await
    }

    pub async fn write_control_packet_with_abort(
        &self,
        ctx: &CancelContext,
        packet: &ControlPacket,
        abort_active: bool,
    ) -> anyhow::Result<()> {
        let permit = acquire_write_gate(ctx, &self.send_gate).await?;
        if let Some(err) = ctx.err() {
            return Err(err);
        }
        let result = self.write_control_packet_granted(ctx, packet, abort_active).await;
        drop(permit);
        result
    }

    /// Writes while the caller owns `send_gate`.
    async fn write_control_packet_granted(
        &self,
        ctx: &CancelContext,
        packet: &ControlPacket,
        abort_active: bool,
    ) -> anyhow::Result<()> {
        let (op_ctx, packet_id, unix_time, generation) = {
            let mut st = self.state.lock();
            if self.crypt.is_some() && st.send_packet_id == u32::MAX {
                return Err(anyhow!("openvpn control packet id exhausted; new session required"));
            }
            if self.crypt.is_some() && st.send_packet_time == 0 {
                let clock = Arc::clone(&st.clock);
                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "the wire field is the `u32` second timestamp OpenVPN puts in the control header"
                )]
                let now = clock().timestamp() as u32;
                st.send_packet_time = now;
            }
            st.send_packet_id = st.send_packet_id.wrapping_add(1);
            let packet_id = st.send_packet_id;
            let unix_time = st.send_packet_time;
            let op_ctx = ctx.with_cancel_cause();
            st.write_generation = st.write_generation.wrapping_add(1);
            let generation = st.write_generation;
            st.write_cancel = Some(op_ctx.clone());
            schedule_write_deadline_locked(&mut st, &self.state);
            drop(st);
            (op_ctx, packet_id, unix_time, generation)
        };

        let result: anyhow::Result<()> = async {
            let mut encoded = packet.encode(self.crypt.as_deref(), packet_id, unix_time)?;
            if op_ctx.is_done() {
                return Err(op_ctx
                    .cause()
                    .map(Error::new)
                    .or_else(|| op_ctx.err())
                    .unwrap_or_else(|| Error::new(ContextError::Canceled)));
            }
            if packet.opcode == P_CONTROL_HARD_RESET_CLIENT_V3 && packet.message_id == 0 {
                if let Some(wrapped_client_key) = self.crypt.as_ref().and_then(|crypt| crypt.wrapped_client_key()) {
                    encoded.extend_from_slice(&wrapped_client_key);
                }
            }
            let err = if abort_active {
                self.io.write_packet(&op_ctx, &encoded).await
            } else {
                self.io.write_packet_allow_active_stop(&op_ctx, &encoded).await
            };
            if let Err(err) = err {
                if op_ctx.is_done() {
                    if let Some(cause) = op_ctx.cause() {
                        return Err(Error::new(cause));
                    }
                    return Err(err);
                }
                if is_packet_dropped(&err) {
                    return Ok(());
                }
                return Err(err);
            }
            Ok(())
        }
        .await;

        self.finish_write(generation, &op_ctx);
        result
    }

    // NOT cancel-safe: a drop between spawning the wake task and awaiting it leaves that task armed, and a
    // later wake cancels a context the caller has already moved on from.
    async fn read_raw_control_packet(&self, ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
        loop {
            let (deadline, mut wake_rx, generation) = {
                let st = self.state.lock();
                // Subscribing under the lock keeps a concurrent `set_deadline` from racing the
                // wake into a generation this read would never observe.
                let generation = *st.read_wake.borrow();
                let deadline = st.read_deadline;
                let wake_rx = st.read_wake.subscribe();
                drop(st);
                (deadline, wake_rx, generation)
            };

            let op_ctx = ctx.with_cancel_cause();
            let read_ctx = match deadline {
                Some(deadline) => op_ctx.with_deadline(deadline),
                None => op_ctx.clone(),
            };
            let wake_ctx = op_ctx.clone();
            let done_ctx = read_ctx.clone();
            let wake_done = tokio::spawn(async move {
                tokio::select! {
                    _ = wake_rx.changed() => wake_ctx.cancel(None),
                    () = done_ctx.done() => {}
                }
            });
            let raw = self.io.read_packet(&read_ctx).await;
            op_ctx.cancel(None);
            let _ = wake_done.await;

            let changed = *self.state.lock().read_wake.borrow() != generation;
            let err = match raw {
                Ok(raw) => return Ok(raw),
                Err(err) => err,
            };
            if changed && !ctx.is_done() {
                continue;
            }
            return Err(err);
        }
    }

    pub fn set_deadline(&self, t: Option<Instant>) -> io::Result<()> {
        let mut st = self.state.lock();
        st.read_deadline = t;
        st.write_deadline = t;
        signal_read_wake_locked(&st);
        schedule_write_deadline_locked(&mut st, &self.state);
        drop(st);
        Ok(())
    }

    pub fn set_read_deadline(&self, t: Option<Instant>) -> io::Result<()> {
        let mut st = self.state.lock();
        st.read_deadline = t;
        signal_read_wake_locked(&st);
        drop(st);
        Ok(())
    }

    pub fn set_write_deadline(&self, t: Option<Instant>) -> io::Result<()> {
        let mut st = self.state.lock();
        st.write_deadline = t;
        schedule_write_deadline_locked(&mut st, &self.state);
        drop(st);
        Ok(())
    }

    pub(crate) fn finish_write(&self, generation: u64, cancel: &CancelContext) {
        cancel.cancel(None);
        let mut st = self.state.lock();
        if st.write_generation == generation {
            if let Some(timer) = st.write_timer.take() {
                timer.abort();
            }
            st.write_cancel = None;
        }
    }

    fn interrupt_write(&self) {
        let st = self.state.lock();
        if let Some(cancel) = &st.write_cancel {
            cancel.cancel(None);
        }
    }

    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.io.local_addr()
    }

    #[must_use]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.io.remote_addr()
    }

    /// Returns the next contiguous packet already buffered for the current epoch, if any.
    fn take_contiguous_packet(&self, watch_soft_reset: bool) -> Option<Arc<ControlPacket>> {
        let mut st = self.state.lock();
        let key = st.recv_message;
        let packet = st.recv_pending.get(&key).cloned()?;
        if watch_soft_reset {
            let (soft_reset, valid) = st.classify_watch_packet_locked(&packet);
            if !valid {
                st.recv_pending.remove(&key);
                return None;
            }
            if soft_reset {
                st.recv_pending.remove(&key);
                return Some(packet);
            }
        }
        st.recv_pending.remove(&key);
        st.recv_message = st.recv_message.wrapping_add(1);
        drop(st);
        Some(packet)
    }

    /// Reads one datagram and decodes it, `None` when it must be treated as packet loss.
    async fn read_checked_packet(&self, ctx: &CancelContext) -> anyhow::Result<Option<(Arc<ControlPacket>, u32, u32)>> {
        let raw = self.read_raw_control_packet(ctx).await?;
        // Invalid control datagrams are packet loss, not TLS stream errors: OpenVPN drops
        // malformed/authentication-failed packets and keeps the reliable read alive for a valid
        // retransmission.
        let Ok((packet, packet_id, unix_time)) = decode_control_packet(self.crypt.as_deref(), &raw) else {
            return Ok(None);
        };
        if packet.local_session == SessionID::default() {
            return Ok(None);
        }
        if !packet.ack_ids.is_empty() && packet.ack_remote_session != self.local {
            return Ok(None);
        }
        Ok(Some((Arc::new(packet), packet_id, unix_time)))
    }

    /// Resolves the peer session for a decoded packet, consuming the initial hard reset. `None`
    /// means the packet must be dropped; the flag reports whether the tls-auth/tls-crypt replay
    /// window was already checked for it.
    fn resolve_watch_remote(&self, packet: &ControlPacket, packet_id: u32, unix_time: u32) -> Option<bool> {
        let mut st = self.state.lock();
        let mut replay_checked = false;
        if st.remote == SessionID::default() {
            let initial_reset = (packet.opcode == P_CONTROL_HARD_RESET_SERVER_V2
                || packet.opcode == P_CONTROL_HARD_RESET_SERVER_V1)
                && packet.key_id == st.key_id
                && packet.message_id == 0;
            if initial_reset && self.crypt.is_some() {
                if st.check_replay_locked(packet_id, unix_time).is_err() {
                    return None;
                }
                replay_checked = true;
            }
            if initial_reset {
                st.remote = packet.local_session;
                self.io.mark_initial_packet_received();
            }
        }
        let remote = st.remote;
        drop(st);
        if remote == SessionID::default() || packet.local_session != remote {
            return None;
        }
        Some(replay_checked)
    }

    /// Gates a packet read while the caller did not ask for a soft reset.
    fn gate_epoch_packet(
        &self,
        packet: &Arc<ControlPacket>,
        packet_id: u32,
        unix_time: u32,
        replay_checked: bool,
    ) -> WatchOutcome {
        let mut st = self.state.lock();
        let cur_key = st.key_id;
        let same_session = st.remote == SessionID::default() || packet.local_session == st.remote;
        if packet.opcode == P_CONTROL_SOFT_RESET_V1 {
            // Only park a soft reset for the strictly-next epoch and message 0 (a new-epoch reset
            // is always message 0). A delayed reset from a retiring epoch must not move the client
            // backwards, and an invalid one must not mutate ACK/pending-message state.
            if packet.key_id == next_key_id(cur_key) && packet.message_id == 0 && same_session {
                // tls-auth/tls-crypt packet IDs belong to the outer TLS session and remain
                // continuous across key-state soft resets.
                if self.crypt.is_some() && st.check_replay_locked(packet_id, unix_time).is_err() {
                    return WatchOutcome::Drop;
                }
                let packet = Arc::new(ControlPacket { received_at: Some(Instant::now()), ..(**packet).clone() });
                // Only one future key state can be negotiated at a time. A second distinct reset
                // would require the peer to advance again before this epoch completed, so keep the
                // first trigger and drop that protocol violation; retransmissions of the same reset
                // are acknowledged through the normal ACK state.
                if st.pending_soft_reset.is_none() {
                    st.pending_soft_reset = Some(Arc::clone(&packet));
                }
                for ack_id in &packet.ack_ids {
                    st.pending.remove(ack_id);
                }
            }
            return WatchOutcome::Drop;
        }
        if packet.key_id != cur_key {
            // Drop control packets from a retiring key epoch so they cannot be fed into the new
            // TLS session.
            return WatchOutcome::Drop;
        }
        if self.crypt.is_some() && !replay_checked && st.check_replay_locked(packet_id, unix_time).is_err() {
            return WatchOutcome::Drop;
        }
        drop(st);
        WatchOutcome::Deliver
    }

    /// Gates a packet read while the caller waits for a soft reset.
    fn gate_watch_packet(&self, packet: &Arc<ControlPacket>, packet_id: u32, unix_time: u32) -> WatchOutcome {
        let mut st = self.state.lock();
        let (soft_reset, valid) = st.classify_watch_packet_locked(packet);
        if !valid {
            return WatchOutcome::Drop;
        }
        if soft_reset {
            if self.crypt.is_some() && st.check_replay_locked(packet_id, unix_time).is_err() {
                return WatchOutcome::Drop;
            }
            let packet = Arc::new(ControlPacket { received_at: Some(Instant::now()), ..(**packet).clone() });
            drop(st);
            return WatchOutcome::Return(packet);
        }
        if self.crypt.is_some() && st.check_replay_locked(packet_id, unix_time).is_err() {
            return WatchOutcome::Drop;
        }
        drop(st);
        WatchOutcome::Deliver
    }

    /// Applies the reliable receive window to an accepted packet and returns it when it is
    /// contiguous and must be delivered.
    fn queue_for_delivery(&self, packet: &Arc<ControlPacket>) -> Option<Arc<ControlPacket>> {
        let mut st = self.state.lock();
        for ack_id in &packet.ack_ids {
            st.pending.remove(ack_id);
        }

        // OpenVPN `read_control_auth` acknowledges a message ID only when the packet is accepted
        // into the receive window (`reliable_wont_break_sequentiality` succeeds), whether it is new
        // or an in-window replay. A packet that would break the window is neither buffered nor
        // acknowledged, so the sender keeps it for retransmission.
        if packet.opcode == P_ACK_V1 {
            // A dedicated ACK packet carries no reliable message and nothing to deliver.
            return None;
        }
        if !packet.opcode.has_message_id() {
            return Some(Arc::clone(packet));
        }
        if reliable_message_before(packet.message_id, st.recv_message) {
            // In-window replay of an already-delivered packet: acknowledge so the sender stops
            // retransmitting, but do not redeliver.
            append_ack(&mut st.ack_pending, packet.message_id);
            signal_ack_locked(&self.ack_wake);
            return None;
        }
        if packet.message_id == st.recv_message {
            append_ack(&mut st.ack_pending, packet.message_id);
            signal_ack_locked(&self.ack_wake);
            st.recv_message = st.recv_message.wrapping_add(1);
            return Some(Arc::clone(packet));
        }
        if st.recv_pending.contains_key(&packet.message_id) {
            // A duplicate already buffered inside the window must be re-ACKed (its first ACK may
            // have been lost) without re-inserting it.
            append_ack(&mut st.ack_pending, packet.message_id);
            signal_ack_locked(&self.ack_wake);
            return None;
        }
        if recv_window_ok(st.recv_message, packet.message_id, st.recv_pending.len()) {
            st.recv_pending.insert(packet.message_id, Arc::clone(packet));
            append_ack(&mut st.ack_pending, packet.message_id);
            signal_ack_locked(&self.ack_wake);
        }
        drop(st);
        None
    }
}

pub(crate) fn begin_epoch_locked(st: &mut ChannelState, key_id: u8) {
    st.key_id = key_id & KEY_ID_MASK;
    st.send_message = 0;
    st.recv_message = 0;
    st.ack_pending = Vec::new();
    st.lru_acks = Vec::new();
    st.pending = HashMap::new();
    st.recv_pending = HashMap::new();
    st.parked_tls = Vec::new();
}

/// Returns the next `OpenVPN` key epoch id. `OpenVPN` reserves 0 for the initial epoch and then
/// advances 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 1.
#[must_use]
pub const fn next_key_id(current: u8) -> u8 {
    let next = current.wrapping_add(1) & KEY_ID_MASK;
    if next == 0 {
        return 1;
    }
    next
}

pub(crate) fn append_ack(acks: &mut Vec<u32>, ack: u32) {
    if !acks.contains(&ack) {
        acks.push(ack);
    }
}

fn signal_ack_locked(ack_wake: &Notify) {
    ack_wake.notify_one();
}

fn signal_read_wake_locked(st: &ChannelState) {
    st.read_wake.send_modify(|generation| {
        *generation = generation.wrapping_add(1);
    });
}

fn schedule_write_deadline_locked(st: &mut ChannelState, state: &Arc<Mutex<ChannelState>>) {
    st.write_deadline_generation = st.write_deadline_generation.wrapping_add(1);
    if let Some(timer) = st.write_timer.take() {
        timer.abort();
    }
    let cancel = match &st.write_cancel {
        Some(cancel) => cancel.clone(),
        None => return,
    };
    let Some(deadline) = st.write_deadline else {
        return;
    };
    let write_generation = st.write_generation;
    let deadline_generation = st.write_deadline_generation;
    if deadline <= Instant::now() {
        cancel.cancel(Some(Cause::DeadlineExceeded));
        return;
    }
    let state = Arc::clone(state);
    let handle = tokio::spawn(async move {
        tokio::time::sleep_until(deadline).await;
        cancel_write_deadline_generation(&state, write_generation, deadline_generation, &cancel);
    });
    st.write_timer = Some(handle);
}

fn cancel_write_deadline_generation(
    state: &Arc<Mutex<ChannelState>>,
    write_generation: u64,
    deadline_generation: u64,
    cancel: &CancelContext,
) {
    let st = state.lock();
    if st.write_generation == write_generation
        && st.write_deadline_generation == deadline_generation
        && st.write_cancel.is_some()
    {
        cancel.cancel(Some(Cause::DeadlineExceeded));
    }
}

// cancel-safe: the permit is taken only by the arm that resolves, and the cancelled arm returns the
// context error.
async fn acquire_write_gate<'a>(ctx: &CancelContext, gate: &'a Semaphore) -> anyhow::Result<SemaphorePermit<'a>> {
    tokio::select! {
        permit = gate.acquire() => match permit {
            Ok(permit) => Ok(permit),
            Err(_) => Err(ctx
                .err()
                .unwrap_or_else(|| Error::new(ContextError::Canceled))),
        },
        () = ctx.done() => Err(ctx
            .err()
            .unwrap_or_else(|| Error::new(ContextError::Canceled))),
    }
}

struct ConnState {
    read_buf: Vec<u8>,
    closed: bool,
    op_ctx: CancelContext,
    read_fut: Option<Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>>>,
    write_fut: Option<Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>>,
}

#[derive(Clone)]
pub struct ControlConn {
    channel: Arc<ControlChannel>,
    state: Arc<Mutex<ConnState>>,
    write_mu: Arc<tokio::sync::Mutex<()>>,
}

impl fmt::Debug for ControlConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlConn").finish_non_exhaustive()
    }
}

#[must_use]
pub fn new_control_conn(channel: Arc<ControlChannel>) -> ControlConn {
    ControlConn {
        channel,
        state: Arc::new(Mutex::new(ConnState {
            read_buf: Vec::new(),
            closed: false,
            op_ctx: CancelContext::background(),
            read_fut: None,
            write_fut: None,
        })),
        write_mu: Arc::new(tokio::sync::Mutex::new(())),
    }
}

impl ControlConn {
    #[must_use]
    pub fn new(channel: Arc<ControlChannel>) -> Self {
        new_control_conn(channel)
    }

    pub fn reset(&self) {
        let mut st = self.state.lock();
        st.op_ctx.cancel(None);
        st.op_ctx = CancelContext::background();
        st.closed = false;
        st.read_buf = Vec::new();
    }

    /// Snapshot of the pending TLS read buffer, read by the tests.
    #[allow(dead_code, reason = "called only from SharedControlConn::read_buf, itself test-only")]
    pub(crate) fn read_buf(&self) -> Vec<u8> {
        self.state.lock().read_buf.clone()
    }

    /// Pushes already-decoded control payload bytes into the TLS read buffer. The caller must have
    /// drained `read_all` and must not concurrently read or write the TLS stream.
    pub fn unsafe_feed(&self, payload: &[u8]) {
        let mut st = self.state.lock();
        st.read_buf.extend_from_slice(payload);
    }

    pub async fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let op_ctx = {
            let mut st = self.state.lock();
            if st.closed {
                return Err(closed_error());
            }
            if !st.read_buf.is_empty() {
                let n = b.len().min(st.read_buf.len());
                let (target, _) = b.split_at_mut(n);
                let (buffered, _) = st.read_buf.split_at(n);
                target.copy_from_slice(buffered);
                st.read_buf.drain(..n);
                return Ok(n);
            }
            st.op_ctx.clone()
        };

        loop {
            let packet = match self.channel.read(&op_ctx).await {
                Ok(packet) => packet,
                Err(err) => {
                    if self.state.lock().closed {
                        return Err(closed_error());
                    }
                    return Err(channel_io_error(err));
                }
            };
            if packet.opcode != P_CONTROL_V1 {
                continue;
            }
            if packet.payload.is_empty() {
                continue;
            }
            let n = b.len().min(packet.payload.len());
            let (target, _) = b.split_at_mut(n);
            let (head, tail) = packet.payload.split_at(n);
            target.copy_from_slice(head);
            if !tail.is_empty() {
                let mut st = self.state.lock();
                st.read_buf.extend_from_slice(tail);
            }
            return Ok(n);
        }
    }

    pub async fn write(&self, b: &[u8]) -> io::Result<usize> {
        control_conn_write(Arc::clone(&self.channel), Arc::clone(&self.state), Arc::clone(&self.write_mu), b.to_vec())
            .await
    }

    pub fn close(&self) -> io::Result<()> {
        {
            let mut st = self.state.lock();
            st.closed = true;
            st.op_ctx.cancel(None);
            st.read_buf = Vec::new();
            drop(st);
            // The control channel outlives a single TLS epoch: closing the mux here would tear down
            // the whole OpenVPN transport during a soft reset.
            self.channel.interrupt_write();
        }
        Ok(())
    }

    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.channel.local_addr()
    }

    #[must_use]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.channel.remote_addr()
    }

    pub fn set_deadline(&self, t: Option<Instant>) -> io::Result<()> {
        self.channel.set_deadline(t)
    }

    pub fn set_read_deadline(&self, t: Option<Instant>) -> io::Result<()> {
        self.channel.set_read_deadline(t)
    }

    pub fn set_write_deadline(&self, t: Option<Instant>) -> io::Result<()> {
        self.channel.set_write_deadline(t)
    }

    /// The `&self` form of [`AsyncRead::poll_read`], usable through an `Arc<ControlConn>`.
    pub fn poll_read_shared(&self, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        {
            let mut st = self.state.lock();
            if st.closed {
                return Poll::Ready(Err(closed_error()));
            }
            if !st.read_buf.is_empty() {
                let n = buf.remaining().min(st.read_buf.len());
                let (buffered, _) = st.read_buf.split_at(n);
                buf.put_slice(buffered);
                st.read_buf.drain(..n);
                drop(st);
                return Poll::Ready(Ok(()));
            }
        }

        let mut fut = {
            let mut st = self.state.lock();
            if st.read_fut.is_none() {
                let channel = Arc::clone(&self.channel);
                let op_ctx = st.op_ctx.clone();
                st.read_fut = Some(Box::pin(read_next_payload(channel, op_ctx)));
            }
            match st.read_fut.take() {
                Some(fut) => fut,
                None => {
                    return Poll::Ready(Err(io::Error::other("openvpn control conn read state missing")));
                }
            }
        };

        match fut.as_mut().poll(cx) {
            Poll::Pending => {
                self.state.lock().read_fut = Some(fut);
                Poll::Pending
            }
            Poll::Ready(Ok(payload)) => {
                let n = buf.remaining().min(payload.len());
                let (head, tail) = payload.split_at(n);
                buf.put_slice(head);
                if !tail.is_empty() {
                    let mut st = self.state.lock();
                    st.read_buf.extend_from_slice(tail);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                if self.state.lock().closed {
                    return Poll::Ready(Err(closed_error()));
                }
                Poll::Ready(Err(err))
            }
        }
    }

    /// The `&self` form of [`AsyncWrite::poll_write`], usable through an `Arc<ControlConn>`.
    pub fn poll_write_shared(&self, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        {
            let st = self.state.lock();
            if st.closed {
                return Poll::Ready(Err(closed_error()));
            }
        }

        let mut fut = {
            let mut st = self.state.lock();
            if st.write_fut.is_none() {
                st.write_fut = Some(Box::pin(control_conn_write(
                    Arc::clone(&self.channel),
                    Arc::clone(&self.state),
                    Arc::clone(&self.write_mu),
                    buf.to_vec(),
                )));
            }
            match st.write_fut.take() {
                Some(fut) => fut,
                None => {
                    return Poll::Ready(Err(io::Error::other("openvpn control conn write state missing")));
                }
            }
        };

        match fut.as_mut().poll(cx) {
            Poll::Pending => {
                self.state.lock().write_fut = Some(fut);
                Poll::Pending
            }
            Poll::Ready(result) => Poll::Ready(result),
        }
    }
}

impl AsyncRead for ControlConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_read_shared(cx, buf)
    }
}

impl AsyncWrite for ControlConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_shared(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().close() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

async fn read_next_payload(channel: Arc<ControlChannel>, op_ctx: CancelContext) -> io::Result<Vec<u8>> {
    loop {
        let packet = channel.read(&op_ctx).await.map_err(io::Error::other)?;
        if packet.opcode != P_CONTROL_V1 {
            continue;
        }
        if packet.payload.is_empty() {
            continue;
        }
        return Ok(packet.payload.clone());
    }
}

async fn control_conn_write(
    channel: Arc<ControlChannel>,
    state: Arc<Mutex<ConnState>>,
    write_mu: Arc<tokio::sync::Mutex<()>>,
    payload: Vec<u8>,
) -> io::Result<usize> {
    let _guard = write_mu.lock().await;
    let op_ctx = {
        let st = state.lock();
        if st.closed {
            return Err(closed_error());
        }
        st.op_ctx.clone()
    };

    // Flush any unacknowledged read BEFORE writing data, so the ACK does not piggyback onto this
    // control message and corrupt the TLS record.
    if let Err(err) = channel.send_ack(&op_ctx).await {
        if state.lock().closed {
            return Err(closed_error());
        }
        return Err(channel_io_error(err));
    }
    // Close may race with a successfully completed ACK write: never begin the TLS payload write
    // after the adapter has been closed.
    if state.lock().closed {
        return Err(closed_error());
    }

    let mut written = 0;
    while written < payload.len() {
        let n = (payload.len() - written).min(MAX_TLS_CONTROL_PAYLOAD);
        let end = written + n;
        let (_, remaining) = payload.split_at(written);
        let (chunk, _) = remaining.split_at(n);
        if let Err(err) = channel.send(&op_ctx, P_CONTROL_V1, chunk).await {
            if state.lock().closed {
                return Err(closed_error());
            }
            return Err(channel_io_error(err));
        }
        written = end;
    }
    Ok(written)
}

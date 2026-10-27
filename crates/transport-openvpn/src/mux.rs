//! The write gate and read demultiplexer shared over one tunnel connection.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};

use anyhow::{anyhow, Error};
use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;

use crate::control::{CancelContext, ContextError, ControlIO, ErrClosed};
use crate::packet::parse_opcode_key_id;
use crate::packetio::{is_packet_dropped, packet_dropped_error, PacketIO};
use murmur_common::contextutils;
use murmur_common::errors::error_is;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("openvpn control retransmitter stopped")]
pub(crate) struct ErrControlRetransmitStopped;

pub(crate) fn is_control_retransmit_stopped(err: &Error) -> bool {
    error_is::<ErrControlRetransmitStopped>(err)
}

/// An `anyhow::Error` kept in shared state; the wrapper keeps `Display` and the cause chain so
/// callers can still classify the stored terminal error.
#[derive(Debug, Clone)]
struct SharedError(Arc<Error>);

impl fmt::Display for SharedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SharedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let err: &Error = &self.0;
        let inner: &(dyn std::error::Error + Send + Sync + 'static) = err.as_ref();
        Some(inner)
    }
}

fn shared_error(err: &Arc<Error>) -> Error {
    Error::new(SharedError(Arc::clone(err)))
}

/// `anyhow::Error` is not `Clone`, so a borrowed error is re-created when it must be both stored
/// and returned; an `io::Error` keeps its errno, anything else keeps its message.
fn clone_error(err: &Error) -> Error {
    for cause in err.chain() {
        if let Some(io_err) = cause.downcast_ref::<io::Error>() {
            return match io_err.raw_os_error() {
                Some(code) => Error::new(io::Error::from_raw_os_error(code)),
                None => Error::new(io::Error::new(io_err.kind(), io_err.to_string())),
            };
        }
    }
    anyhow!("{err}")
}

fn is_net_unreachable(err: &Error) -> bool {
    err.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|io_err| io_err.raw_os_error() == Some(libc::ENETUNREACH))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveWriteCancelPolicy {
    IgnoreActiveWriteCancel,
    AbortActiveWrite,
    AllowActiveRetransmitStop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteWaiterState {
    Queued,
    Granted,
    Released,
}

struct WriteWaiter {
    ready: Notify,
    state: Mutex<WriteWaiterState>,
}

impl WriteWaiter {
    fn new() -> Self {
        Self { ready: Notify::new(), state: Mutex::new(WriteWaiterState::Queued) }
    }
}

struct GateState {
    active: bool,
    control: Vec<Arc<WriteWaiter>>,
    data: Vec<Arc<WriteWaiter>>,
}

struct PriorityWriteGate {
    mu: Mutex<GateState>,
}

impl PriorityWriteGate {
    const fn new() -> Self {
        Self { mu: Mutex::new(GateState { active: false, control: Vec::new(), data: Vec::new() }) }
    }

    // cancel-safe: a cancelled wait abandons its queue entry before returning.
    async fn acquire(
        &self,
        ctx: &CancelContext,
        done: &CancellationToken,
        control: bool,
    ) -> anyhow::Result<Option<Arc<WriteWaiter>>> {
        let waiter = {
            let mut state = self.mu.lock();
            if !state.active {
                state.active = true;
                return Ok(None);
            }
            let waiter = Arc::new(WriteWaiter::new());
            if control {
                state.control.push(Arc::clone(&waiter));
            } else {
                state.data.push(Arc::clone(&waiter));
            }
            waiter
        };

        let granted = {
            let ready = waiter.ready.notified();
            tokio::select! {
                () = ready => true,
                () = ctx.done() => false,
                () = done.cancelled() => false,
            }
        };
        if granted {
            return Ok(Some(waiter));
        }
        self.abandon(&waiter);
        if done.is_cancelled() {
            return Err(Error::new(ErrClosed));
        }
        Err(ctx.err().unwrap_or_else(|| Error::new(ContextError::Canceled)))
    }

    fn abandon(&self, waiter: &Arc<WriteWaiter>) {
        let mut state = self.mu.lock();
        let mut waiter_state = waiter.state.lock();
        match *waiter_state {
            WriteWaiterState::Queued => {
                remove_write_waiter(&mut state.control, waiter);
                remove_write_waiter(&mut state.data, waiter);
                *waiter_state = WriteWaiterState::Released;
            }
            WriteWaiterState::Granted => {
                *waiter_state = WriteWaiterState::Released;
                grant_next_locked(&mut state);
            }
            WriteWaiterState::Released => {}
        }
        drop(waiter_state);
        drop(state);
    }

    fn release(&self, waiter: Option<&Arc<WriteWaiter>>) {
        let mut state = self.mu.lock();
        let Some(waiter) = waiter else {
            grant_next_locked(&mut state);
            return;
        };
        let mut waiter_state = waiter.state.lock();
        if *waiter_state != WriteWaiterState::Granted {
            return;
        }
        *waiter_state = WriteWaiterState::Released;
        drop(waiter_state);
        grant_next_locked(&mut state);
    }
}

fn grant_next_locked(state: &mut GateState) {
    let waiter = if !state.control.is_empty() {
        state.control.remove(0)
    } else if !state.data.is_empty() {
        state.data.remove(0)
    } else {
        state.active = false;
        return;
    };
    *waiter.state.lock() = WriteWaiterState::Granted;
    waiter.ready.notify_one();
}

impl PriorityWriteGate {
    #[allow(dead_code, reason = "reachable only through PacketMux::gate_queue_lengths, itself test-only")]
    fn queue_lengths(&self) -> (usize, usize) {
        let state = self.mu.lock();
        (state.control.len(), state.data.len())
    }
}

fn remove_write_waiter(waiters: &mut Vec<Arc<WriteWaiter>>, target: &Arc<WriteWaiter>) {
    if let Some(index) = waiters.iter().position(|waiter| Arc::ptr_eq(waiter, target)) {
        waiters.remove(index);
    }
}

enum ReadOutcome {
    Packet(Vec<u8>),
    Closed,
    Cancelled,
}

struct ErrState {
    close_err: Option<SharedError>,
    /// Set only when the physical reader terminates. Packets it queued before the terminal read
    /// error remain valid and are delivered first.
    drain_reads: bool,
}

struct MuxInner {
    io: Arc<dyn PacketIO>,
    control_tx: mpsc::Sender<Vec<u8>>,
    control_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    data_tx: mpsc::Sender<Vec<u8>>,
    data_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    done: CancellationToken,
    gate: PriorityWriteGate,
    initial_packet_received: AtomicBool,
    close_once: Once,
    err_mu: Mutex<ErrState>,
}

impl MuxInner {
    fn read_after_close(&self, packets: &mut mpsc::Receiver<Vec<u8>>) -> anyhow::Result<Vec<u8>> {
        if self.should_drain_reads() {
            if let Ok(packet) = packets.try_recv() {
                return Ok(packet);
            }
        }
        Err(self.terminal_error())
    }

    fn should_drain_reads(&self) -> bool {
        self.err_mu.lock().drain_reads
    }

    fn current_error(&self) -> Option<Error> {
        if self.done.is_cancelled() {
            return Some(self.terminal_error());
        }
        None
    }

    fn terminal_error(&self) -> Error {
        let err_mu = self.err_mu.lock();
        match &err_mu.close_err {
            Some(err) => Error::new(err.clone()),
            None => Error::new(ErrClosed),
        }
    }

    fn close_with_error(&self, err: Arc<Error>) {
        self.close_with_error_mode(err, false);
    }

    fn close_with_read_error(&self, err: Error) {
        self.close_with_error_mode(Arc::new(err), true);
    }

    fn close_with_error_mode(&self, err: Arc<Error>, drain_reads: bool) {
        self.close_once.call_once(move || {
            {
                let mut err_state = self.err_mu.lock();
                err_state.close_err = Some(SharedError(err));
                err_state.drain_reads = drain_reads;
            }
            self.done.cancel();
            let io = Arc::clone(&self.io);
            tokio::spawn(async move {
                let _ = io.close().await;
            });
        });
    }
}

#[derive(Clone)]
pub struct PacketMux {
    inner: Arc<MuxInner>,
}

impl fmt::Debug for PacketMux {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketMux").finish_non_exhaustive()
    }
}

impl PacketMux {
    pub fn new(io: Arc<dyn PacketIO>) -> Self {
        let (control_tx, control_rx) = mpsc::channel(64);
        let (data_tx, data_rx) = mpsc::channel(256);
        Self {
            inner: Arc::new(MuxInner {
                io,
                control_tx,
                control_rx: tokio::sync::Mutex::new(control_rx),
                data_tx,
                data_rx: tokio::sync::Mutex::new(data_rx),
                done: CancellationToken::new(),
                gate: PriorityWriteGate::new(),
                initial_packet_received: AtomicBool::new(false),
                close_once: Once::new(),
                err_mu: Mutex::new(ErrState { close_err: None, drain_reads: false }),
            }),
        }
    }

    #[must_use]
    pub fn new_packet_mux(io: Box<dyn PacketIO>) -> Self {
        Self::new(Arc::from(io))
    }

    /// The sole physical reader. Logical read cancellation never reaches `PacketIO`; closing the
    /// mux is the only way to interrupt a blocked read.
    // NOT cancel-safe: a dropped loop leaves the underlying `read_packet` pending; the mux is stopped by
    // closing it, not by dropping this future.
    pub async fn run(&self) {
        loop {
            let (packet, err) = self.inner.io.read_packet().await;
            if let Some(packet) = packet {
                if let Some(&first) = packet.first() {
                    let (opcode, _) = parse_opcode_key_id(first);
                    let delivered = if opcode.is_control() {
                        tokio::select! {
                            result = self.inner.control_tx.send(packet) => result,
                            () = self.inner.done.cancelled() => return,
                        }
                    } else {
                        tokio::select! {
                            result = self.inner.data_tx.send(packet) => result,
                            () = self.inner.done.cancelled() => return,
                        }
                    };
                    let _ = delivered;
                }
            }
            if let Some(err) = err {
                self.inner.close_with_read_error(err);
                return;
            }
        }
    }

    pub async fn read_packet(&self, ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
        self.read(ctx, true).await
    }

    pub async fn read_data_packet(&self, ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
        self.read(ctx, false).await
    }

    // cancel-safe: the queue guard is dropped with the future, and a cancelled wait leaves the packet
    // queued.
    async fn read(&self, ctx: &CancelContext, control: bool) -> anyhow::Result<Vec<u8>> {
        let packets = if control { &self.inner.control_rx } else { &self.inner.data_rx };
        if self.inner.done.is_cancelled() {
            let mut packets = packets.lock().await;
            return self.inner.read_after_close(&mut packets);
        }

        let mut packets = packets.lock().await;
        let outcome = tokio::select! {
            packet = packets.recv() => match packet {
                Some(packet) => ReadOutcome::Packet(packet),
                None => ReadOutcome::Closed,
            },
            () = ctx.done() => ReadOutcome::Cancelled,
            () = self.inner.done.cancelled() => ReadOutcome::Closed,
        };
        let result = match outcome {
            ReadOutcome::Packet(packet) => Ok(packet),
            ReadOutcome::Closed => self.inner.read_after_close(&mut packets),
            ReadOutcome::Cancelled => Err(ctx.err().unwrap_or_else(|| Error::new(ContextError::Canceled))),
        };
        drop(packets);
        result
    }

    /// The `ControlIO` write used by `ControlChannel`.
    pub async fn write_packet(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
        self.write(ctx, packet, true, ActiveWriteCancelPolicy::AbortActiveWrite).await
    }

    /// Used by reliable retransmission: a normal retransmitter stop removes a queued write without
    /// aborting an active one; every other cancellation still terminates an active physical write.
    pub async fn write_packet_allow_active_stop(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
        self.write(ctx, packet, true, ActiveWriteCancelPolicy::AllowActiveRetransmitStop).await
    }

    pub async fn write_data_packet(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
        self.write(ctx, packet, false, ActiveWriteCancelPolicy::IgnoreActiveWriteCancel).await
    }

    pub(crate) fn mark_initial_packet_received(&self) {
        self.inner.initial_packet_received.store(true, Ordering::SeqCst);
    }

    async fn write(
        &self,
        ctx: &CancelContext,
        packet: &[u8],
        control: bool,
        cancel_policy: ActiveWriteCancelPolicy,
    ) -> anyhow::Result<()> {
        if let Some(err) = self.inner.current_error() {
            return Err(err);
        }
        let waiter = match self.inner.gate.acquire(ctx, &self.inner.done, control).await {
            Ok(waiter) => waiter,
            Err(err) => {
                if error_is::<ErrClosed>(&err) {
                    return Err(self.inner.terminal_error());
                }
                return Err(err);
            }
        };
        let result = self.write_granted(ctx, packet, cancel_policy).await;
        self.inner.gate.release(waiter.as_ref());
        result
    }

    async fn write_granted(
        &self,
        ctx: &CancelContext,
        packet: &[u8],
        cancel_policy: ActiveWriteCancelPolicy,
    ) -> anyhow::Result<()> {
        if let Some(err) = ctx.err() {
            return Err(err);
        }
        if let Some(err) = self.inner.current_error() {
            return Err(err);
        }

        // Linearize cancellation with the point that commits the physical write.
        let active = Arc::new(Mutex::new(false));
        let mut stop: Box<dyn Fn() -> bool + Send + Sync> = Box::new(|| true);
        let mut abort_done: Option<Arc<Notify>> = None;
        let track_active = cancel_policy != ActiveWriteCancelPolicy::IgnoreActiveWriteCancel && ctx.has_done();
        if track_active {
            let done = Arc::new(Notify::new());
            let inner = Arc::clone(&self.inner);
            let active_flag = Arc::clone(&active);
            let done_flag = Arc::clone(&done);
            let stop_ctx = ctx.clone();
            stop = Box::new(contextutils::after_func(ctx.token(), move || {
                let is_active = *active_flag.lock();
                if is_active {
                    let err = stop_ctx
                        .cause()
                        .map(Error::new)
                        .or_else(|| stop_ctx.err())
                        .unwrap_or_else(|| Error::new(ContextError::Canceled));
                    if !(cancel_policy == ActiveWriteCancelPolicy::AllowActiveRetransmitStop
                        && is_control_retransmit_stopped(&err))
                    {
                        inner.close_with_error(Arc::new(err));
                    }
                }
                done_flag.notify_one();
            }));
            {
                let mut is_active = active.lock();
                if let Some(err) = ctx.err() {
                    drop(is_active);
                    if !stop() {
                        done.notified().await;
                    }
                    return Err(err);
                }
                *is_active = true;
            }
            abort_done = Some(done);
        }

        let err = self.inner.io.write_packet(packet).await.err();
        if track_active {
            *active.lock() = false;
        }
        if !stop() {
            if let Some(done) = &abort_done {
                done.notified().await;
            }
        }
        // Cancellation can close the transport concurrently with a physical write that reports
        // success: once that close wins, the logical write must not be reported as successful.
        if let Some(terminal_err) = self.inner.current_error() {
            return Err(terminal_err);
        }
        let Some(err) = err else { return Ok(()) };
        if is_packet_dropped(&err) {
            // OpenVPN immediately restarts when the initial UDP path is unreachable. Once an
            // initial reset has been accepted, the same socket error is just loss of this datagram.
            if !self.inner.initial_packet_received.load(Ordering::SeqCst) && is_net_unreachable(&err) {
                let mut terminal_err = if let Some(dropped) = packet_dropped_error(&err) {
                    clone_error(&dropped.cause)
                } else {
                    Error::new(io::Error::from_raw_os_error(libc::ENETUNREACH))
                };
                if is_packet_dropped(&terminal_err) {
                    terminal_err = Error::new(io::Error::from_raw_os_error(libc::ENETUNREACH));
                }
                let stored = Arc::new(terminal_err);
                self.inner.close_with_error(Arc::clone(&stored));
                return Err(shared_error(&stored));
            }
            return Err(err);
        }
        let stored = Arc::new(err);
        self.inner.close_with_error(Arc::clone(&stored));
        Err(shared_error(&stored))
    }

    pub fn close(&self) -> anyhow::Result<()> {
        self.inner.close_with_error(Arc::new(Error::new(ErrClosed)));
        Ok(())
    }

    pub(crate) fn current_error(&self) -> Option<Error> {
        self.inner.current_error()
    }

    #[allow(dead_code, reason = "exercised only by #[cfg(test)] tests")]
    pub(crate) fn terminal_error(&self) -> Error {
        self.inner.terminal_error()
    }

    pub async fn wait_done(&self) {
        self.inner.done.cancelled().await;
    }

    /// A non-blocking probe of the done channel.
    #[allow(dead_code, reason = "exercised only by #[cfg(test)] tests")]
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.done.is_cancelled()
    }

    #[allow(dead_code, reason = "exercised only by #[cfg(test)] tests")]
    pub(crate) fn gate_queue_lengths(&self) -> (usize, usize) {
        self.inner.gate.queue_lengths()
    }

    /// Pushes a packet onto the control channel.
    #[allow(dead_code, reason = "exercised only by #[cfg(test)] tests")]
    pub(crate) async fn push_control_packet(&self, packet: Vec<u8>) -> anyhow::Result<()> {
        self.inner.control_tx.send(packet).await.map_err(|_| anyhow!("openvpn control channel closed"))
    }

    #[allow(dead_code, reason = "exercised only by #[cfg(test)] tests")]
    pub(crate) fn data_queue_len(&self) -> usize {
        self.inner.data_rx.try_lock().map_or(0, |packets| packets.len())
    }

    #[allow(dead_code, reason = "exercised only by #[cfg(test)] tests")]
    pub(crate) fn data_queue_capacity(&self) -> usize {
        self.inner.data_rx.try_lock().map_or(0, |packets| packets.max_capacity())
    }

    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.io.local_addr()
    }

    #[must_use]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.io.remote_addr()
    }
}

#[async_trait]
impl ControlIO for PacketMux {
    async fn read_packet(&self, ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
        Self::read_packet(self, ctx).await
    }

    async fn write_packet(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
        Self::write_packet(self, ctx, packet).await
    }

    async fn write_packet_allow_active_stop(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
        Self::write_packet_allow_active_stop(self, ctx, packet).await
    }

    async fn close(&self) -> anyhow::Result<()> {
        Self::close(self)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.io.local_addr()
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.io.remote_addr()
    }

    fn mark_initial_packet_received(&self) {
        Self::mark_initial_packet_received(self);
    }
}

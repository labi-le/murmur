use std::collections::HashMap;
use std::fmt;
use std::future::poll_fn;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, TimeDelta, Utc};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::futures::OwnedNotified;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use murmur_common_net::deadline::pipe::{CloseSignal, CloseSignalWaiter};
use murmur_common_net::io::{udp_addr_from_socket_addr, OldConnAsStream, Stream, StreamAsOldConn};
use murmur_std_compat::net::Conn as NetConn;

use super::config::Config;
use super::header::rand_u16;
use super::listener::{IoCloser, IoWriter};
use super::packet::{PacketReader, PacketWriter};
use super::segment::{
    AckSegment, CmdOnlySegment, Command, DataSegment, Segment, SegmentOption, COMMAND_PING, COMMAND_TERMINATE,
    DATA_SEGMENT_OVERHEAD, SEGMENT_OPTION_CLOSE,
};

pub(crate) fn err_closed_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")
}

pub(crate) fn err_net_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection")
}

fn err_deadline_exceeded() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

pub(crate) type ConnState = i32;

pub(crate) const STATE_ACTIVE: ConnState = 0;
pub(crate) const STATE_READY_TO_CLOSE: ConnState = 1;
pub(crate) const STATE_PEER_CLOSED: ConnState = 2;
pub(crate) const STATE_TERMINATING: ConnState = 3;
pub(crate) const STATE_PEER_TERMINATING: ConnState = 4;
pub(crate) const STATE_TERMINATED: ConnState = 5;

#[derive(Debug, Clone, Copy)]
struct AckItem {
    number: u32,
    timestamp: u32,
    next_flush: u32,
}

/// One consumer's reusable registration on a pulse [`Notify`].
///
/// The registration is owned per handle instead of the notify holding a registry of wakers, so a
/// re-poll replaces the previous waker in place and dropping the handle releases exactly that one.
#[derive(Debug, Default)]
struct NotifyWaiter {
    source: Option<Arc<Notify>>,
    registered: Option<Pin<Box<OwnedNotified>>>,
}

impl NotifyWaiter {
    /// Arms the registration before the caller samples the guarded state, so a pulse racing the
    /// state check is either visible in that state or delivered to this registration.
    fn arm(&mut self, source: &Arc<Notify>) {
        let subscribed = matches!(&self.source, Some(known) if Arc::ptr_eq(known, source));
        if subscribed && self.registered.is_some() {
            return;
        }
        self.source = Some(Arc::clone(source));
        let fresh = Arc::clone(source).notified_owned();
        let mut slot = match self.registered.take() {
            Some(mut slot) => {
                slot.set(fresh);
                slot
            }
            None => Box::pin(fresh),
        };
        slot.as_mut().enable();
        self.registered = Some(slot);
    }

    /// Whether a pulse landed on the registration; the caller then re-checks the guarded state.
    fn poll_pinged(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(source) = self.source.as_ref().map(Arc::clone) else {
            return false;
        };
        let Some(slot) = self.registered.as_mut() else {
            return false;
        };
        if slot.as_mut().poll(cx).is_pending() {
            return false;
        }
        slot.set(source.notified_owned());
        slot.as_mut().enable();
        true
    }
}

/// One arm of a deadline: the instant it fires and the latched signal it fires through.
///
/// Every arm installs a fresh signal, so a timer task that already passed its sleep can only close
/// the generation it was armed for, never a later one.
#[derive(Debug, Clone, Default)]
struct Deadline {
    value: Option<DateTime<Utc>>,
    signal: Arc<CloseSignal>,
}

impl Deadline {
    fn set(&mut self, t: Option<DateTime<Utc>>, task: &mut Option<JoinHandle<()>>) {
        if let Some(task) = task.take() {
            task.abort();
        }
        self.value = t;
        self.signal = Arc::new(CloseSignal::new());
        let Some(t) = t else {
            return;
        };
        let until = t.signed_duration_since(Utc::now());
        if until <= TimeDelta::zero() {
            self.signal.close();
            return;
        }
        let signal = Arc::clone(&self.signal);
        *task = Some(tokio::spawn(async move {
            tokio::time::sleep(until.to_std().unwrap_or(Duration::ZERO)).await;
            signal.close();
        }));
    }

    fn expired(&self) -> bool {
        self.value.is_some_and(|t| t <= Utc::now())
    }
}

pub struct Conn {
    inner: Arc<ConnInner>,
    close_view: ConnCloseView,
    read_waiter: NotifyWaiter,
    read_deadline_waiter: CloseSignalWaiter,
    write_waiter: NotifyWaiter,
    write_deadline_waiter: CloseSignalWaiter,
}

struct ConnInner {
    cfg: Config,
    writer: tokio::sync::Mutex<PacketWriter>,
    closer: Option<Box<dyn IoCloser>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    conv: u16,
    created: tokio::time::Instant,
    mss: i32,
    mu: Mutex<ConnData>,
    done: CancellationToken,
    flush_notify: Notify,
    read_notify: Arc<Notify>,
    write_notify: Arc<Notify>,
    once: std::sync::Once,
}

struct ConnData {
    state: ConnState,
    state_begin: u32,
    last_incoming: u32,
    last_ping: u32,

    read_buf: Vec<u8>,
    recv_cache: HashMap<u32, DataSegment>,
    recv_next: u32,
    ack_list: Vec<AckItem>,
    ack_dirty: bool,
    send_window: Vec<DataSegment>,
    send_next: u32,
    first_unacked: u32,
    remote_recv_win: u32,

    total_in_flight_size: u32,
    control_window: u32,
    first_unacked_was_updated: bool,

    rto: u32,
    rtt_variation: u32,
    srtt: u32,
    min_rtt: u32,
    rto_updated: u32,

    read_deadline: Deadline,
    write_deadline: Deadline,
    read_deadline_task: Option<JoinHandle<()>>,
    write_deadline_task: Option<JoinHandle<()>>,

    // the blocking write loop position, carried across `poll_write` calls.
    write_progress: usize,
}

impl Clone for Conn {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            close_view: ConnCloseView(Arc::clone(&self.inner)),
            read_waiter: NotifyWaiter::default(),
            read_deadline_waiter: CloseSignalWaiter::default(),
            write_waiter: NotifyWaiter::default(),
            write_deadline_waiter: CloseSignalWaiter::default(),
        }
    }
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn")
            .field("conv", &self.inner.conv)
            .field("local_addr", &self.inner.local_addr)
            .field("remote_addr", &self.inner.remote_addr)
            .finish_non_exhaustive()
    }
}

impl Stream for Conn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.inner.local_addr)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.inner.remote_addr)
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(&self.close_view)
    }
}

/// [`Conn`] seen as a [`murmur_std_compat::net::Conn`], reached only via [`Stream::old_conn`]
/// (`Conn`'s real close is a graceful state-machine teardown, not a bare
/// `shutdown_read`/`shutdown_write`, so it needs `old_conn` per wave-rule #4 the same way
/// `transport-vmess`'s `H2Transport` does). Its `AsyncRead`/`AsyncWrite` are never polled: only
/// the capability methods below are reached through `old_conn`.
struct ConnCloseView(Arc<ConnInner>);

impl AsyncRead for ConnCloseView {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("ConnCloseView is a close-only view, never read from")))
    }
}

impl AsyncWrite for ConnCloseView {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other("ConnCloseView is a close-only view, never written to")))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl NetConn for ConnCloseView {
    fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        Ok(Box::new(udp_addr_from_socket_addr(self.0.local_addr)))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        Ok(Box::new(udp_addr_from_socket_addr(self.0.remote_addr)))
    }

    fn close(&self) -> io::Result<()> {
        self.0.close()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_deadline(murmur_std_compat::net::deadline_time(deadline))
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_read_deadline(murmur_std_compat::net::deadline_time(deadline))
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_write_deadline(murmur_std_compat::net::deadline_time(deadline))
    }
}

static GLOBAL_CONV: LazyLock<AtomicU16> = LazyLock::new(|| AtomicU16::new(rand_u16()));

fn next_conv() -> u16 {
    GLOBAL_CONV.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
}

#[cfg_attr(
    not(test),
    expect(
        clippy::unused_async,
        reason = "`dial` is the transport's public entry point and every caller awaits it; dropping \
                  `async` would change that signature"
    )
)]
pub async fn dial(raw: Box<dyn NetConn>, cfg: Config) -> anyhow::Result<StreamAsOldConn<Conn>> {
    let security = cfg.security()?;
    let conversation = next_conv();
    let raw: Box<dyn Stream> = Box::new(OldConnAsStream(raw));
    let local_addr = raw.local_addr()?;
    let remote_addr = raw.peer_addr()?;
    let reader = PacketReader { security: Some(Arc::clone(&security)), header: Some(cfg.packet_header()) };
    let shared = Arc::new(SharedConn::new(raw));
    let writer = PacketWriter {
        security: Some(security),
        header: Some(cfg.packet_header()),
        writer: Box::new(Arc::clone(&shared)),
    };
    let conn = new_conn(local_addr, remote_addr, conversation, writer, Some(Box::new(Arc::clone(&shared))), cfg);

    let (cache_tx, mut cache_rx) = mpsc::channel::<Vec<u8>>(1024);
    {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let Ok(n) = shared.read(&mut buf).await else { break };
                if n == 0 {
                    break;
                }
                let payload = buf.get(..n).unwrap_or_default().to_vec();
                match cache_tx.try_send(payload) {
                    Ok(()) | Err(TrySendError::Full(_)) => {}
                    Err(TrySendError::Closed(_)) => break,
                }
            }
        });
    }
    let input_conn = conn.clone();
    tokio::spawn(async move {
        while let Some(payload) = cache_rx.recv().await {
            input_conn.input(reader.read(&payload));
        }
    });

    Ok(StreamAsOldConn::new(conn))
}

pub(crate) fn new_conn(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    conversation: u16,
    writer: PacketWriter,
    closer: Option<Box<dyn IoCloser>>,
    cfg: Config,
) -> Conn {
    let overhead = writer.overhead().saturating_add(DATA_SEGMENT_OVERHEAD);
    let overhead = u32::try_from(overhead).unwrap_or(u32::MAX);
    let mut mss = i32::try_from(cfg.mtu().saturating_sub(overhead)).unwrap_or(0);
    if mss < 576 {
        mss = 576;
    }
    let control_window = cfg.sending_in_flight_size();
    let min_rtt = cfg.tti();
    let inner = Arc::new(ConnInner {
        cfg,
        writer: tokio::sync::Mutex::new(writer),
        closer,
        local_addr,
        remote_addr,
        conv: conversation,
        created: tokio::time::Instant::now(),
        mss,
        mu: Mutex::new(ConnData {
            state: STATE_ACTIVE,
            state_begin: 0,
            last_incoming: 0,
            last_ping: 0,
            read_buf: Vec::new(),
            recv_cache: HashMap::new(),
            recv_next: 0,
            ack_list: Vec::new(),
            ack_dirty: false,
            send_window: Vec::new(),
            send_next: 0,
            first_unacked: 0,
            remote_recv_win: 32,
            total_in_flight_size: 0,
            control_window,
            first_unacked_was_updated: false,
            rto: 100,
            rtt_variation: 0,
            srtt: 0,
            min_rtt,
            rto_updated: 0,
            read_deadline: Deadline::default(),
            write_deadline: Deadline::default(),
            read_deadline_task: None,
            write_deadline_task: None,
            write_progress: 0,
        }),
        done: CancellationToken::new(),
        flush_notify: Notify::new(),
        read_notify: Arc::new(Notify::new()),
        write_notify: Arc::new(Notify::new()),
        once: std::sync::Once::new(),
    });
    let conn = Conn {
        inner: Arc::clone(&inner),
        close_view: ConnCloseView(inner),
        read_waiter: NotifyWaiter::default(),
        read_deadline_waiter: CloseSignalWaiter::default(),
        write_waiter: NotifyWaiter::default(),
        write_deadline_waiter: CloseSignalWaiter::default(),
    };
    tokio::spawn(flush_loop(conn.clone()));
    conn
}

impl Conn {
    #[allow(private_interfaces)]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "`input` is consumed through the public `Conn` API as an owned batch; taking a \
                  slice would change that signature"
    )]
    pub fn input(&self, segments: Vec<Segment>) {
        if segments.is_empty() {
            return;
        }
        let mut wake_flush = false;
        let mut terminate = false;
        {
            let mut data = self.inner.mu.lock();
            let current = self.inner.elapsed();
            if data.state == STATE_TERMINATED {
                return;
            }
            data.last_incoming = current;
            for seg in &segments {
                if seg.conversation() != self.inner.conv {
                    break;
                }
                match seg {
                    Segment::Data(s) => {
                        self.inner.handle_option_locked(&mut data, s.option);
                        ConnInner::process_sending_next_locked(&mut data, s.sending_next);
                        let idx = s.number.wrapping_sub(data.recv_next);
                        if idx < self.inner.cfg.receiving_in_flight_size() {
                            if let Some(existing) = data.ack_list.iter_mut().find(|a| a.number == s.number) {
                                existing.timestamp = s.timestamp;
                                existing.next_flush = 0;
                            } else {
                                data.ack_list.push(AckItem { number: s.number, timestamp: s.timestamp, next_flush: 0 });
                            }
                            data.ack_dirty = true;
                            data.recv_cache.entry(s.number).or_insert_with(|| s.clone());
                        }
                        self.inner.deliver_locked(&mut data);
                        self.inner.bound_ack_list_locked(&mut data);
                        wake_flush = true;
                    }
                    Segment::Ack(s) => {
                        self.inner.handle_option_locked(&mut data, s.option);
                        if s.receiving_window > data.remote_recv_win {
                            data.remote_recv_win = s.receiving_window;
                        }
                        self.inner.process_receiving_next_locked(&mut data, s.receiving_next);
                        if s.number_list.is_empty() {
                            continue;
                        }
                        let mut maxack: u32 = 0;
                        let mut maxack_removed = false;
                        for number in &s.number_list {
                            let removed = self.inner.process_ack_locked(&mut data, *number);
                            if maxack < *number {
                                maxack = *number;
                                maxack_removed = removed;
                            }
                        }
                        if maxack_removed {
                            ConnInner::handle_fast_ack_locked(&mut data, maxack);
                            let rtt = current.wrapping_sub(s.timestamp);
                            if rtt < 10000 {
                                ConnInner::update_rtt_locked(&mut data, rtt, current);
                            }
                        }
                        wake_flush = true;
                    }
                    Segment::CmdOnly(s) => {
                        self.inner.handle_option_locked(&mut data, s.option);
                        if s.cmd == COMMAND_TERMINATE {
                            match data.state {
                                STATE_ACTIVE | STATE_PEER_CLOSED => {
                                    self.inner.set_state_locked(&mut data, STATE_PEER_TERMINATING);
                                }
                                STATE_READY_TO_CLOSE => self.inner.set_state_locked(&mut data, STATE_TERMINATING),
                                STATE_TERMINATING => {
                                    self.inner.set_state_locked(&mut data, STATE_TERMINATED);
                                    terminate = true;
                                }
                                _ => {}
                            }
                        }
                        self.inner.process_receiving_next_locked(&mut data, s.receiving_next);
                        ConnInner::process_sending_next_locked(&mut data, s.sending_next);
                        ConnInner::update_peer_rto_locked(&mut data, s.peer_rto, current);
                        if s.option == SEGMENT_OPTION_CLOSE || s.cmd == COMMAND_TERMINATE {
                            self.inner.signal_read_locked();
                            self.inner.signal_write_locked();
                        }
                    }
                }
            }
        }
        if wake_flush {
            self.inner.wake_flush();
        }
        if terminate {
            self.terminate();
        }
    }

    pub(crate) fn terminate(&self) {
        self.inner.terminate();
    }

    pub(crate) fn close(&self) -> io::Result<()> {
        self.inner.close()
    }

    async fn flush(&self) {
        let mut terminate = false;
        let segments = {
            let mut data = self.inner.mu.lock();
            let current = self.inner.elapsed();
            if data.state == STATE_TERMINATED {
                return;
            }

            if data.state == STATE_ACTIVE && current.wrapping_sub(data.last_incoming) >= 30000 {
                self.inner.set_state_locked(&mut data, STATE_READY_TO_CLOSE);
            }
            if data.state == STATE_READY_TO_CLOSE && data.send_window.is_empty() {
                self.inner.set_state_locked(&mut data, STATE_TERMINATING);
            }
            if data.state == STATE_TERMINATING {
                let segments =
                    vec![Segment::CmdOnly(self.inner.ping_segment_locked(&mut data, COMMAND_TERMINATE, current))];
                if current.wrapping_sub(data.state_begin) > 8000 {
                    self.inner.set_state_locked(&mut data, STATE_TERMINATED);
                    terminate = true;
                }
                segments
            } else {
                if data.state == STATE_PEER_TERMINATING && current.wrapping_sub(data.state_begin) > 4000 {
                    self.inner.set_state_locked(&mut data, STATE_TERMINATING);
                }
                if data.state == STATE_READY_TO_CLOSE && current.wrapping_sub(data.state_begin) > 15000 {
                    self.inner.set_state_locked(&mut data, STATE_TERMINATING);
                }

                let mut segments = self.inner.flush_acks_locked(&mut data, current);
                segments.extend(self.inner.flush_send_locked(&mut data, current));
                if current.wrapping_sub(data.last_ping) >= 3000 {
                    segments.push(Segment::CmdOnly(self.inner.ping_segment_locked(&mut data, COMMAND_PING, current)));
                }
                terminate = data.state == STATE_TERMINATED;
                segments
            }
        };

        self.write_segments(segments).await;
        if terminate {
            self.terminate();
        }
    }

    async fn write_segments(&self, segments: Vec<Segment>) {
        for seg in &segments {
            for _ in 0..5 {
                let mut writer = self.inner.writer.lock().await;
                let err = writer.write_segment(seg).await;
                drop(writer);
                if err.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn flush_loop(conn: Conn) {
    let period = Duration::from_millis(u64::from(conn.inner.cfg.tti()));
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            () = conn.inner.flush_notify.notified() => {}
            () = conn.inner.done.cancelled() => break,
        }
        conn.flush().await;
    }
}

impl ConnInner {
    /// The caller holds `mu`, and a waiter arms before sampling the guarded state, so pulsing
    /// under the same lock as the state change cannot be lost.
    fn signal_read_locked(&self) {
        self.read_notify.notify_waiters();
    }

    /// The caller holds `mu`, exactly as on the read side.
    fn signal_write_locked(&self) {
        self.write_notify.notify_waiters();
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the millisecond count is truncated into the kcp timestamp domain, which wraps by design"
    )]
    fn elapsed(&self) -> u32 {
        self.created.elapsed().as_millis() as u32
    }

    fn wake_flush(&self) {
        self.flush_notify.notify_one();
    }

    fn handle_option_locked(&self, data: &mut ConnData, opt: SegmentOption) {
        if opt & SEGMENT_OPTION_CLOSE == SEGMENT_OPTION_CLOSE {
            match data.state {
                STATE_READY_TO_CLOSE => self.set_state_locked(data, STATE_TERMINATING),
                STATE_ACTIVE => self.set_state_locked(data, STATE_PEER_CLOSED),
                _ => {}
            }
        }
    }

    fn deliver_locked(&self, data: &mut ConnData) {
        let read_buf_cap = self.cfg.receiving_in_flight_size() as usize * usize::try_from(self.mss.max(0)).unwrap_or(0);
        let mut delivered = false;
        loop {
            if data.read_buf.len() >= read_buf_cap {
                break;
            }
            let Some(seg) = data.recv_cache.remove(&data.recv_next) else {
                break;
            };
            data.recv_next = data.recv_next.wrapping_add(1);
            data.read_buf.extend_from_slice(&seg.payload);
            delivered = true;
        }
        if delivered {
            self.signal_read_locked();
        }
    }

    /// Never evicts an entry that has not been flushed to the peer yet (`next_flush == 0`): a
    /// burst that crosses the bound before the next flush tick must still leave at least one
    /// entry for `flush_acks_locked` to emit, or the peer never learns the new `receiving_next`.
    /// If the hard cap still cannot be met by evicting already-flushed, already-covered entries,
    /// the oldest entries are dropped regardless of flush state to keep the bound absolute.
    fn bound_ack_list_locked(&self, data: &mut ConnData) {
        let limit = self.cfg.receiving_in_flight_size() as usize * 2;
        if data.ack_list.len() <= limit {
            return;
        }
        data.ack_list.retain(|ack| ack.next_flush == 0 || ack.number.wrapping_sub(data.recv_next) <= 0x7fff_ffff);
        if data.ack_list.len() > limit {
            let excess = data.ack_list.len() - limit;
            data.ack_list.drain(0..excess);
        }
    }

    fn process_sending_next_locked(data: &mut ConnData, next: u32) {
        let before = data.ack_list.len();
        data.ack_list.retain(|ack| ack.number >= next);
        if data.ack_list.len() != before {
            data.ack_dirty = true;
        }
    }

    fn process_receiving_next_locked(&self, data: &mut ConnData, next: u32) {
        let before = data.send_window.len();
        data.send_window.retain(|seg| seg.number >= next);
        Self::find_first_unacked_locked(data);
        if data.send_window.len() != before {
            self.signal_write_locked();
        }
    }

    fn process_ack_locked(&self, data: &mut ConnData, number: u32) -> bool {
        if number.wrapping_sub(data.first_unacked) > 0x7fff_ffff || number.wrapping_sub(data.send_next) < 0x7fff_ffff {
            return false;
        }
        let Some(index) = data.send_window.iter().position(|seg| seg.number == number) else {
            return false;
        };
        if data.total_in_flight_size > 0 {
            data.total_in_flight_size -= 1;
        }
        data.send_window.remove(index);
        Self::find_first_unacked_locked(data);
        self.signal_write_locked();
        true
    }

    fn handle_fast_ack_locked(data: &mut ConnData, number: u32) {
        if data.send_window.is_empty() {
            return;
        }
        let reduction = data.rto / 3;
        if reduction == 0 {
            return;
        }
        for seg in &mut data.send_window {
            if number == seg.number || number.wrapping_sub(seg.number) > 0x7fff_ffff {
                return;
            }
            if seg.transmit > 0 && seg.timeout > reduction {
                seg.timeout -= reduction;
            }
        }
    }

    fn find_first_unacked_locked(data: &mut ConnData) {
        let first = data.first_unacked;
        data.first_unacked = data.send_window.first().map_or(data.send_next, |seg| seg.number);
        if first != data.first_unacked {
            data.first_unacked_was_updated = true;
        }
    }

    fn set_state_locked(&self, data: &mut ConnData, state: ConnState) {
        if data.state == state {
            return;
        }
        data.state = state;
        data.state_begin = self.elapsed();
        match state {
            STATE_READY_TO_CLOSE => {
                self.signal_read_locked();
                self.signal_write_locked();
            }
            STATE_PEER_CLOSED => {
                data.send_window.clear();
                self.signal_write_locked();
            }
            STATE_TERMINATING | STATE_PEER_TERMINATING | STATE_TERMINATED => {
                data.send_window.clear();
                self.signal_read_locked();
                self.signal_write_locked();
            }
            _ => {}
        }
    }

    fn flush_acks_locked(&self, data: &mut ConnData, current: u32) -> Vec<Segment> {
        if data.ack_list.is_empty() {
            return Vec::new();
        }
        let mut segments: Vec<Segment> = Vec::with_capacity(1);
        let mut candidates: Vec<u32> = Vec::with_capacity(128);
        let mut ack = self.new_ack_segment_locked(data);
        for i in 0..data.ack_list.len() {
            let Some(item) = data.ack_list.get(i).copied() else { break };
            if item.next_flush > current {
                if candidates.len() < 128 {
                    candidates.push(item.number);
                }
                continue;
            }
            let number = item.number;
            let timestamp = item.timestamp;
            ack.number_list.push(number);
            if timestamp.wrapping_sub(ack.timestamp) < 0x7fff_ffff {
                ack.timestamp = timestamp;
            }
            let mut timeout = data.rto / 2;
            if timeout < 20 {
                timeout = 20;
            }
            if let Some(slot) = data.ack_list.get_mut(i) {
                slot.next_flush = current.wrapping_add(timeout);
            }
            if ack.number_list.len() == 128 {
                segments.push(Segment::Ack(ack));
                ack = self.new_ack_segment_locked(data);
                data.ack_dirty = false;
            }
        }
        if data.ack_dirty || !ack.number_list.is_empty() {
            for number in candidates {
                if ack.number_list.len() == 128 {
                    break;
                }
                ack.number_list.push(number);
            }
            segments.push(Segment::Ack(ack));
            data.ack_dirty = false;
        }
        segments
    }

    fn flush_send_locked(&self, data: &mut ConnData, current: u32) -> Vec<Segment> {
        if data.send_window.is_empty() {
            if data.first_unacked_was_updated {
                data.first_unacked_was_updated = false;
                let ping = self.ping_segment_locked(data, COMMAND_PING, current);
                return vec![Segment::CmdOnly(ping)];
            }
            return Vec::new();
        }
        let mut segments: Vec<Segment> = Vec::with_capacity(data.send_window.len());
        let mut cwnd = self.cfg.sending_in_flight_size();
        let remote_window = data.remote_recv_win.wrapping_sub(data.first_unacked);
        if cwnd > remote_window {
            cwnd = remote_window;
        }
        if self.cfg.congestion && cwnd > data.control_window {
            cwnd = data.control_window;
        }
        cwnd = cwnd.wrapping_mul(20);

        let mut lost: u32 = 0;
        let mut in_flight: u32 = 0;
        let mut total_in_flight_size = data.total_in_flight_size;
        for seg in &mut data.send_window {
            if current.wrapping_sub(seg.timeout) >= 0x7fff_ffff {
                continue;
            }
            if seg.transmit == 0 {
                total_in_flight_size = total_in_flight_size.wrapping_add(1);
            } else {
                lost = lost.wrapping_add(1);
            }
            seg.conv = self.conv;
            seg.timestamp = current;
            seg.sending_next = data.first_unacked;
            seg.option = 0;
            if data.state == STATE_READY_TO_CLOSE {
                seg.option = SEGMENT_OPTION_CLOSE;
            }
            seg.transmit = seg.transmit.wrapping_add(1);
            let mut timeout = data.rto;
            if timeout < self.cfg.tti() {
                timeout = self.cfg.tti();
            }
            seg.timeout = current.wrapping_add(timeout);
            segments.push(Segment::Data(seg.clone()));
            in_flight = in_flight.wrapping_add(1);
            if in_flight >= cwnd {
                break;
            }
        }
        data.total_in_flight_size = total_in_flight_size;
        if self.cfg.congestion && in_flight > 0 && data.total_in_flight_size != 0 {
            let rate = lost.wrapping_mul(100) / data.total_in_flight_size;
            self.on_packet_loss_locked(data, rate);
        }
        data.first_unacked_was_updated = false;
        segments
    }

    fn new_ack_segment_locked(&self, data: &ConnData) -> AckSegment {
        let mut ack = AckSegment {
            conv: self.conv,
            option: 0,
            receiving_window: data.recv_next.wrapping_add(self.cfg.receiving_in_flight_size()),
            receiving_next: data.recv_next,
            timestamp: 0,
            number_list: Vec::new(),
        };
        if data.state == STATE_READY_TO_CLOSE {
            ack.option = SEGMENT_OPTION_CLOSE;
        }
        ack
    }

    const fn ping_segment_locked(&self, data: &mut ConnData, cmd: Command, current: u32) -> CmdOnlySegment {
        let mut seg = CmdOnlySegment {
            conv: self.conv,
            cmd,
            option: 0,
            receiving_next: data.recv_next,
            sending_next: data.first_unacked,
            peer_rto: data.rto,
        };
        if data.state == STATE_READY_TO_CLOSE {
            seg.option = SEGMENT_OPTION_CLOSE;
        }
        data.last_ping = current;
        seg
    }

    const fn update_rtt_locked(data: &mut ConnData, rtt: u32, current: u32) {
        if rtt > 0x7fff_ffff {
            return;
        }
        if data.srtt == 0 {
            data.srtt = rtt;
            data.rtt_variation = rtt / 2;
        } else {
            let delta = if data.srtt > rtt { data.srtt - rtt } else { rtt.wrapping_sub(data.srtt) };
            data.rtt_variation = 3u32.wrapping_mul(data.rtt_variation).wrapping_add(delta) / 4;
            data.srtt = 7u32.wrapping_mul(data.srtt).wrapping_add(rtt) / 8;
            if data.srtt < data.min_rtt {
                data.srtt = data.min_rtt;
            }
        }
        let rto = if data.min_rtt < 4u32.wrapping_mul(data.rtt_variation) {
            data.srtt.wrapping_add(4u32.wrapping_mul(data.rtt_variation))
        } else {
            data.srtt.wrapping_add(data.rtt_variation)
        };
        let rto = if rto > 10000 { 10000 } else { rto };
        data.rto = rto.wrapping_mul(5) / 4;
        data.rto_updated = current;
    }

    const fn update_peer_rto_locked(data: &mut ConnData, rto: u32, current: u32) {
        if rto == 0 || current.wrapping_sub(data.rto_updated) < 3000 {
            return;
        }
        data.rto_updated = current;
        data.rto = rto;
    }

    fn on_packet_loss_locked(&self, data: &mut ConnData, loss_rate: u32) {
        if data.rto == 0 {
            return;
        }
        if loss_rate >= 15 {
            data.control_window = 3u32.wrapping_mul(data.control_window) / 4;
        } else if loss_rate <= 5 {
            data.control_window = data.control_window.wrapping_add(data.control_window / 4);
        }
        if data.control_window < 16 {
            data.control_window = 16;
        }
        let max = 2u32.wrapping_mul(self.cfg.sending_in_flight_size());
        if data.control_window > max {
            data.control_window = max;
        }
    }

    fn set_deadline(&self, t: Option<DateTime<Utc>>) -> io::Result<()> {
        self.set_read_deadline(t)?;
        self.set_write_deadline(t)
    }

    fn set_read_deadline(&self, t: Option<DateTime<Utc>>) -> io::Result<()> {
        let mut data = self.mu.lock();
        if data.state != STATE_ACTIVE {
            return Err(err_net_closed());
        }
        let mut task = data.read_deadline_task.take();
        data.read_deadline.set(t, &mut task);
        data.read_deadline_task = task;
        self.signal_read_locked();
        drop(data);
        Ok(())
    }

    fn set_write_deadline(&self, t: Option<DateTime<Utc>>) -> io::Result<()> {
        let mut data = self.mu.lock();
        if data.state != STATE_ACTIVE {
            return Err(err_net_closed());
        }
        let mut task = data.write_deadline_task.take();
        data.write_deadline.set(t, &mut task);
        data.write_deadline_task = task;
        self.signal_write_locked();
        drop(data);
        Ok(())
    }

    fn close(self: &Arc<Self>) -> io::Result<()> {
        let mut terminate = false;
        {
            let mut data = self.mu.lock();
            match data.state {
                STATE_READY_TO_CLOSE | STATE_TERMINATING | STATE_TERMINATED => {
                    return Err(err_net_closed());
                }
                STATE_ACTIVE => self.set_state_locked(&mut data, STATE_READY_TO_CLOSE),
                STATE_PEER_CLOSED => self.set_state_locked(&mut data, STATE_TERMINATING),
                STATE_PEER_TERMINATING => {
                    self.set_state_locked(&mut data, STATE_TERMINATED);
                    terminate = true;
                }
                _ => {}
            }
        }
        self.wake_flush();
        if terminate {
            self.terminate();
        }
        Ok(())
    }

    fn terminate(self: &Arc<Self>) {
        self.once.call_once(|| {
            {
                let mut data = self.mu.lock();
                self.set_state_locked(&mut data, STATE_TERMINATED);
                self.signal_read_locked();
                self.signal_write_locked();
            }
            self.done.cancel();
            if let Some(closer) = &self.closer {
                let _ = closer.close();
            }
        });
    }
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let inner = &this.inner;
        loop {
            this.read_waiter.arm(&inner.read_notify);
            let deadline = {
                let mut data = inner.mu.lock();
                if !data.read_buf.is_empty() {
                    let n = buf.remaining().min(data.read_buf.len());
                    buf.put_slice(data.read_buf.get(..n).unwrap_or_default());
                    data.read_buf.drain(..n);
                    inner.deliver_locked(&mut data);
                    drop(data);
                    inner.wake_flush();
                    return Poll::Ready(Ok(()));
                }
                if data.state == STATE_READY_TO_CLOSE
                    || data.state == STATE_TERMINATING
                    || data.state == STATE_TERMINATED
                {
                    return Poll::Ready(Ok(()));
                }
                data.read_deadline.clone()
            };
            if deadline.expired() {
                return Poll::Ready(Err(err_deadline_exceeded()));
            }
            if this.read_deadline_waiter.poll_closed(&deadline.signal, cx) {
                return Poll::Ready(Err(err_deadline_exceeded()));
            }
            if this.read_waiter.poll_pinged(cx) {
                continue;
            }
            return Poll::Pending;
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let inner = &this.inner;
        let len = buf.len();
        if len == 0 {
            return Poll::Ready(Ok(0));
        }
        loop {
            this.write_waiter.arm(&inner.write_notify);
            let deadline = {
                let mut data = inner.mu.lock();
                if data.state != STATE_ACTIVE {
                    data.write_progress = 0;
                    return Poll::Ready(Err(err_closed_pipe()));
                }
                if data.write_progress >= len {
                    data.write_progress = 0;
                    return Poll::Ready(Ok(len));
                }
                if data.send_window.len() <= inner.cfg.sending_buffer_size() as usize {
                    let step = usize::try_from(inner.mss.max(0)).unwrap_or(0);
                    let end = data.write_progress.saturating_add(step).min(len);
                    let payload = Bytes::copy_from_slice(buf.get(data.write_progress..end).unwrap_or_default());
                    let seg = DataSegment {
                        conv: 0,
                        option: 0,
                        timestamp: 0,
                        number: data.send_next,
                        sending_next: 0,
                        payload,
                        timeout: 0,
                        transmit: 0,
                    };
                    data.send_next = data.send_next.wrapping_add(1);
                    data.send_window.push(seg);
                    inner.signal_write_locked();
                    data.write_progress = end;
                    drop(data);
                    inner.wake_flush();
                    continue;
                }
                // Segments from this buffer are already queued: report them now instead of
                // parking with a live offset, so an abandoned or cancelled poll can never leave a
                // stale `write_progress` that a later, unrelated write would count as sent. the
                // `Write` returns `(n, err)`; the caller's next call blocks or hits the deadline.
                if data.write_progress > 0 {
                    let written = data.write_progress;
                    data.write_progress = 0;
                    return Poll::Ready(Ok(written));
                }
                data.write_deadline.clone()
            };
            if deadline.expired() {
                return Poll::Ready(Err(err_deadline_exceeded()));
            }
            if this.write_deadline_waiter.poll_closed(&deadline.signal, cx) {
                return Poll::Ready(Err(err_deadline_exceeded()));
            }
            if this.write_waiter.poll_pinged(cx) {
                continue;
            }
            return Poll::Pending;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.get_mut().close())
    }
}

pub(crate) struct SharedConn {
    conn: Mutex<Box<dyn Stream>>,
}

impl SharedConn {
    fn new(conn: Box<dyn Stream>) -> Self {
        Self { conn: Mutex::new(conn) }
    }

    /// Concurrent reads and writes are allowed; the lock is held only for the duration of a
    /// single poll, so the two directions never wait on each other.
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        poll_fn(|cx| {
            let mut conn = self.conn.lock();
            let mut read_buf = ReadBuf::new(&mut *buf);
            match Pin::new(&mut *conn).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    // NOT cancel-safe: the loop writes into the socket as it goes, so a dropped call leaves a partial write.
    async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        let mut written = 0;
        while written < buf.len() {
            let rest = buf.get(written..).unwrap_or_default();
            let n = poll_fn(|cx| {
                let mut conn = self.conn.lock();
                Pin::new(&mut *conn).poll_write(cx, rest)
            })
            .await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "mkcp: failed to write buffer"));
            }
            written += n;
        }
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        murmur_common_net::io::close_stream(&**self.conn.lock())
    }
}

#[async_trait::async_trait]
impl IoWriter for Arc<SharedConn> {
    async fn write(&self, b: &[u8]) -> io::Result<usize> {
        SharedConn::write_all(self, b).await?;
        Ok(b.len())
    }
}

impl IoCloser for Arc<SharedConn> {
    fn close(&self) -> io::Result<()> {
        SharedConn::close(self)
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Weak;
    use std::task::{Wake, Waker};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    struct DiscardWriter;

    #[async_trait::async_trait]
    impl IoWriter for DiscardWriter {
        async fn write(&self, b: &[u8]) -> io::Result<usize> {
            Ok(b.len())
        }
    }

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn test_conn(cfg: Config) -> Conn {
        let writer = PacketWriter { security: None, header: None, writer: Box::new(DiscardWriter) };
        new_conn(test_addr(1), test_addr(2), 7, writer, None, cfg)
    }

    fn data_segment(conv: u16, number: u32, sending_next: u32, payload: &[u8]) -> Segment {
        Segment::Data(DataSegment {
            conv,
            option: 0,
            timestamp: 0,
            number,
            sending_next,
            payload: Bytes::copy_from_slice(payload),
            timeout: 0,
            transmit: 0,
        })
    }

    /// Parent bug: every `COMMAND_DATA` segment pushed a new `AckItem` with no dedupe, so a peer
    /// resending the same never-completed segment number grows `ack_list` once per duplicate.
    #[tokio::test]
    async fn duplicate_data_segments_dedupe_instead_of_growing_ack_list() {
        let conn = test_conn(Config::default());
        for _ in 0..5000 {
            conn.input(vec![data_segment(7, 5, 0, &[])]);
        }
        let len = conn.inner.mu.lock().ack_list.len();
        assert_eq!(len, 1, "5000 duplicate DATA segments for one number must dedupe to one ack_list entry, got {len}");
    }

    /// Parent bug: nothing but a peer-controlled `sending_next` ever removed entries from
    /// `ack_list`, so a peer that lets `recv_next` advance (by completing segments) while never
    /// reporting `sending_next` accumulates one stale entry per segment forever.
    #[tokio::test]
    async fn stale_ack_entries_get_evicted_once_bounded() {
        let cfg = Config::default();
        let limit = cfg.receiving_in_flight_size() as usize * 2;
        let conn = test_conn(cfg);
        for number in 0..(limit as u32 * 3) {
            conn.input(vec![data_segment(7, number, 0, &[1])]);
        }
        let data = conn.inner.mu.lock();
        assert!(
            data.ack_list.len() <= limit,
            "ack_list grew to {} despite the {limit}-entry bound",
            data.ack_list.len()
        );
        assert_eq!(data.recv_next, limit as u32 * 3, "in-order segments must still be delivered and acked");
    }

    /// Parent bug: `flush()`/`input()` snapshotted `elapsed()` before acquiring `mu`, so a
    /// concurrent `input()` could record a later `last_incoming` than a `flush()` call already
    /// in flight; that `flush()`'s stale `current` then underflowed `current - last_incoming`
    /// to near `u32::MAX`, tripping the 30s idle check within milliseconds and closing a
    /// connection that was actively receiving data.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_input_never_spuriously_idle_closes_active_conn() {
        use std::sync::atomic::Ordering;

        struct StopOnDrop(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let conn = test_conn(Config::default());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _stop_guard = StopOnDrop(Arc::clone(&stop));
        let mut input_tasks = Vec::new();
        for t in 0..4u16 {
            let conn = conn.clone();
            let stop = Arc::clone(&stop);
            input_tasks.push(tokio::spawn(async move {
                let mut i: u32 = 0;
                while !stop.load(Ordering::Relaxed) {
                    conn.input(vec![data_segment(7, u32::from(t) * 10_000_000 + i, 0, &[0u8; 4])]);
                    i = i.wrapping_add(1);
                }
            }));
        }
        for _ in 0..20_000u32 {
            conn.flush().await;
        }
        drop(_stop_guard);
        stop.store(true, Ordering::Relaxed);
        for task in input_tasks {
            task.await.expect("input task must not panic");
        }
        let state = conn.inner.mu.lock().state;
        assert_eq!(
            state, STATE_ACTIVE,
            "conn must stay ACTIVE while input() keeps arriving concurrently with flush(), got state {state}"
        );
    }

    /// Parent bug: crossing the bound before any flush tick evicted every entry, including
    /// ones never flushed to the peer, so `flush_acks_locked` bailed out on an empty list and
    /// sent no ACK at all -- the peer would not learn the new `receiving_next` until the next
    /// in-window segment or ping, up to 3 s later.
    #[tokio::test]
    async fn crossing_the_ack_bound_still_flushes_an_ack() {
        let cfg = Config::default();
        let limit = cfg.receiving_in_flight_size() as usize * 2;
        let conn = test_conn(cfg);
        let total = limit as u32 + 1;
        for number in 0..total {
            conn.input(vec![data_segment(7, number, 0, &[1])]);
        }
        assert_eq!(conn.inner.mu.lock().recv_next, total);

        let current = conn.inner.elapsed();
        let acks = {
            let mut data = conn.inner.mu.lock();
            conn.inner.flush_acks_locked(&mut data, current)
        };
        assert!(!acks.is_empty(), "crossing the ack_list bound must not silence the flush entirely");
        let receiving_next = acks.iter().find_map(|seg| match seg {
            Segment::Ack(ack) => Some(ack.receiving_next),
            Segment::Data(_) | Segment::CmdOnly(_) => None,
        });
        assert_eq!(receiving_next, Some(total), "the flushed ACK must carry the current receiving_next");
    }

    /// A well-behaved, in-order transfer must still produce the same ACK output as before either
    /// fix: one explicit number per received segment while the list stays under its bound.
    #[tokio::test]
    async fn in_order_transfer_produces_identical_ack_segments() {
        let conn = test_conn(Config::default());
        for number in 0..5u32 {
            conn.input(vec![data_segment(7, number, 0, &[42])]);
        }
        let current = conn.inner.elapsed();
        let acks = {
            let mut data = conn.inner.mu.lock();
            conn.inner.flush_acks_locked(&mut data, current)
        };
        assert_eq!(acks.len(), 1);
        let Segment::Ack(ack) = &acks[0] else { panic!("expected an ack segment") };
        assert_eq!(ack.conv, 7);
        assert_eq!(ack.receiving_next, 5);
        assert_eq!(ack.number_list, vec![0, 1, 2, 3, 4]);
    }

    /// Parent bug: `deliver_locked` moved every in-order segment into `read_buf` regardless of
    /// whether the reader had consumed anything, so a fast peer grows `read_buf` without bound.
    #[tokio::test]
    async fn read_buf_growth_is_bounded_by_the_receive_window() {
        let cfg = Config { mtu: 2018, tti: 1, downlink_capacity: 1, ..Default::default() };
        let window = cfg.receiving_in_flight_size();
        let mut conn = test_conn(cfg);
        let cap = conn.inner.cfg.receiving_in_flight_size() as usize * conn.inner.mss as usize;
        let payload = vec![9u8; 1000];
        let total_segments = (cap / payload.len()) as u32 * 3;
        for number in 0..total_segments {
            conn.input(vec![data_segment(7, number, 0, &payload)]);
        }
        let (read_len, recv_next, recv_cache_len) = {
            let data = conn.inner.mu.lock();
            (data.read_buf.len(), data.recv_next, data.recv_cache.len())
        };
        assert!(read_len <= cap + payload.len(), "read_buf grew to {read_len} past cap {cap}");
        assert!(recv_next < total_segments, "recv_next must stall once read_buf fills, stayed at {recv_next}");
        assert!(recv_cache_len as u32 <= window, "recv_cache must stay window-bounded, got {recv_cache_len}");

        let mut buf = vec![0u8; cap];
        let n = conn.read(&mut buf).await.expect("read");
        assert!(n > 0);
        let recv_next_after_read = conn.inner.mu.lock().recv_next;
        assert!(recv_next_after_read >= recv_next, "reading must let more data be delivered");
    }

    /// Parent bug: `poll_write` never resets `write_progress` on the deadline-exceeded branch,
    /// so a write that times out after queueing some segments leaves that stale offset behind.
    /// a write returns the byte count and always restarts the next one from 0;
    /// here the next, unrelated write instead compares its own (shorter) buffer length against
    /// the leftover offset, so `write_progress >= len` fires immediately and the caller is told
    /// `Ok(len)` while the write queues nothing at all -- the bytes are silently lost. The fix
    /// reports the segments already queued as a partial write (a legitimate `AsyncWrite` result)
    /// and resets the offset, so the next, unrelated write starts clean like the does.
    #[tokio::test]
    async fn write_progress_resets_after_deadline_so_next_write_is_not_lost() {
        let cfg = Config { write_buffer: Config::default().mtu() * 2, ..Config::default() };
        let mut conn = test_conn(cfg);
        conn.inner.set_write_deadline(Some(Utc::now() - TimeDelta::seconds(1))).unwrap();

        let big = vec![7u8; 64 * 1024];
        let n = conn
            .write(&big)
            .await
            .expect("segments queued before the deadline hit must be reported as a partial write");
        assert!(n > 0 && n < big.len(), "expected a genuine partial write, got {n} of {}", big.len());

        let queued_before = conn.inner.mu.lock().send_window.len();
        assert!(queued_before > 0, "the partial write must have queued at least one segment first");
        assert_eq!(
            conn.inner.mu.lock().write_progress,
            0,
            "write_progress must reset once the deadline aborts a write, or the next write is corrupted"
        );

        conn.inner.set_write_deadline(None).unwrap();
        let small = vec![9u8; 10];
        let res = tokio::time::timeout(Duration::from_millis(200), conn.write(&small)).await;
        assert!(
            res.is_err(),
            "a write behind a still-full window must genuinely block, not report success while queuing nothing"
        );
        let queued_after = conn.inner.mu.lock().send_window.len();
        assert_eq!(queued_after, queued_before, "no new segment may appear while the write is genuinely blocked");
    }

    /// Review-of-45fd5a19 bug: a write that queued segments and then parked behind a full send
    /// window left `write_progress` set, so a caller that dropped the future (timeout, select!,
    /// or the bridge abandoning the poll) left an offset that the next unrelated write counted as
    /// already sent. The write must report its queued segments instead of parking.
    #[tokio::test]
    async fn a_dropped_write_leaves_no_stale_progress() {
        let cfg = Config { write_buffer: Config::default().mtu() * 2, ..Config::default() };
        let mut conn = test_conn(cfg);

        let big = vec![7u8; 64 * 1024];
        let _ = tokio::time::timeout(Duration::from_millis(100), conn.write(&big)).await;
        assert_eq!(conn.inner.mu.lock().write_progress, 0, "no offset may outlive the write call");

        let queued_before = conn.inner.mu.lock().send_window.len();
        let small = vec![9u8; 10];
        let res = tokio::time::timeout(Duration::from_millis(200), conn.write(&small)).await;
        assert!(res.is_err(), "the next write must block behind the full window, not report unsent bytes");
        assert_eq!(conn.inner.mu.lock().send_window.len(), queued_before);
    }

    /// `current` is `uint32(time.Since(created))`, so a connection past 2^32 milliseconds wraps
    /// into the kcp timestamp domain instead of pinning at `u32::MAX` and stalling every
    /// timestamp comparison against it.
    #[tokio::test(start_paused = true)]
    async fn elapsed_wraps_the_timestamp_domain_instead_of_saturating() {
        let conn = test_conn(Config::default());
        let advanced = Duration::from_secs(50 * 24 * 60 * 60);
        tokio::time::advance(advanced).await;

        let expected = (advanced.as_millis() % (1u128 << 32)) as u32;
        assert_eq!(conn.inner.elapsed(), expected, "a 50-day-old connection must wrap, not saturate");
    }

    struct WakeCount(AtomicUsize);

    impl WakeCount {
        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker() -> (Waker, Arc<WakeCount>, Weak<WakeCount>) {
        let task = Arc::new(WakeCount(AtomicUsize::new(0)));
        let weak = Arc::downgrade(&task);
        (Waker::from(Arc::clone(&task)), task, weak)
    }

    /// A parked read must replace its waker when it is polled again instead of appending another
    /// one, which would keep every task that ever read this conn alive until a close.
    #[tokio::test]
    async fn a_re_polled_read_releases_the_retired_waker() {
        let mut conn = test_conn(Config::default());
        let mut buf = [0u8; 8];

        let (first, first_task, first_ref) = counting_waker();
        {
            let mut read = Box::pin(conn.read(&mut buf));
            assert!(read.as_mut().poll(&mut Context::from_waker(&first)).is_pending());
        }
        drop(first);
        drop(first_task);
        assert!(first_ref.upgrade().is_some(), "the parked read must have registered its waker");

        let (second, _second_task, _) = counting_waker();
        {
            let mut read = Box::pin(conn.read(&mut buf));
            assert!(read.as_mut().poll(&mut Context::from_waker(&second)).is_pending());
        }
        assert!(first_ref.upgrade().is_none(), "a re-poll must replace the retired waker, not accumulate it");
    }

    /// The registration belongs to the conn handle; dropping that handle must drop it, rather than
    /// leaving the retired task reachable from the shared conn state forever.
    #[tokio::test]
    async fn dropping_the_conn_releases_the_registered_waker() {
        let mut conn = test_conn(Config::default());
        let (waker, task, task_ref) = counting_waker();
        let mut buf = [0u8; 8];
        {
            let mut read = Box::pin(conn.read(&mut buf));
            assert!(read.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        }
        drop(waker);
        drop(task);
        assert!(task_ref.upgrade().is_some(), "the parked conn must hold its own registration");

        drop(conn);
        assert!(task_ref.upgrade().is_none(), "dropping the conn must release its registration");
    }

    /// One read pulse wakes every conn clone currently parked in a read.
    #[tokio::test]
    async fn one_read_pulse_wakes_every_parked_conn() {
        let mut conn = test_conn(Config::default());
        let feeder = conn.clone();
        let mut second = conn.clone();
        let mut first_buf = [0u8; 8];
        let mut second_buf = [0u8; 8];
        let (first_waker, first_task, _) = counting_waker();
        let (second_waker, second_task, _) = counting_waker();
        let mut first = Box::pin(conn.read(&mut first_buf));
        let mut second_read = Box::pin(second.read(&mut second_buf));
        assert!(first.as_mut().poll(&mut Context::from_waker(&first_waker)).is_pending());
        assert!(second_read.as_mut().poll(&mut Context::from_waker(&second_waker)).is_pending());

        feeder.input(vec![data_segment(7, 0, 0, &[1, 2, 3])]);

        assert_eq!(first_task.count(), 1, "every parked conn is woken by one read pulse");
        assert_eq!(second_task.count(), 1, "every parked conn is woken by one read pulse");
    }

    /// Re-arming the read deadline must wake a parked reader so it observes the new deadline.
    #[tokio::test]
    async fn rearming_a_parked_read_deadline_wakes_the_reader() {
        let mut conn = test_conn(Config::default());
        conn.inner.set_read_deadline(Some(Utc::now() + TimeDelta::seconds(60))).expect("arm");

        let setter = conn.clone();
        let (waker, task, _) = counting_waker();
        let mut buf = [0u8; 8];
        let mut read = Box::pin(conn.read(&mut buf));
        assert!(read.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());

        setter.inner.set_read_deadline(Some(Utc::now() + TimeDelta::milliseconds(20))).expect("rearm");
        assert!(task.count() >= 1, "rearming the read deadline must wake the parked reader");

        drop(read);
        tokio::time::sleep(Duration::from_millis(60)).await;
        let mut read = Box::pin(conn.read(&mut buf));
        match read.as_mut().poll(&mut Context::from_waker(&waker)) {
            Poll::Ready(Err(err)) => assert_eq!(err.kind(), io::ErrorKind::TimedOut),
            other @ (Poll::Ready(_) | Poll::Pending) => {
                panic!("an expired read deadline must fail the read, got {other:?}");
            }
        }
    }

    /// Re-arming and clearing must leave a reader that follows the deadline in the state each arm
    /// implies, and a retired timer must not end the current arm early.
    #[tokio::test]
    async fn rearm_and_clear_leave_the_read_deadline_in_the_armed_state() {
        let mut conn = test_conn(Config::default());
        conn.inner.set_read_deadline(Some(Utc::now() + TimeDelta::milliseconds(10))).expect("arm");
        conn.inner.set_read_deadline(Some(Utc::now() + TimeDelta::seconds(60))).expect("rearm");
        tokio::time::sleep(Duration::from_millis(60)).await;

        let (waker, _task, _) = counting_waker();
        let mut buf = [0u8; 8];
        let mut read = Box::pin(conn.read(&mut buf));
        assert!(
            read.as_mut().poll(&mut Context::from_waker(&waker)).is_pending(),
            "the retired 10 ms timer must not end the 60 s re-arm"
        );

        drop(read);
        let setter = conn.clone();
        setter.inner.set_read_deadline(None).expect("clear");
        let mut read = Box::pin(conn.read(&mut buf));
        assert!(
            read.as_mut().poll(&mut Context::from_waker(&waker)).is_pending(),
            "a cleared deadline must leave the reader parked"
        );
    }
}

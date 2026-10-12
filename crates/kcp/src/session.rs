//! The generic session I/O path: plain `recv_from`/`send_to` on the underlying [`Datagram`],
//! with no batching and no ECN control messages.
//!
//! Linux batching and the out-of-band channel are out of scope: neither is part of the required
//! trait surface, and an out-of-band packet from a peer is simply dropped.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::Datagram;
use murmur_common_net::io::Stream as NetStream;

use crate::core::{Kcp, PacketType, IKCP_MTU_DEF, IKCP_OVERHEAD, IKCP_SN_OFFSET};
use crate::crypt::{self, BlockCrypt, CryptoMode};
use crate::fec::{FecDecoder, FecEncoder, FEC_HEADER_SIZE_PLUS2, TYPE_DATA, TYPE_OOB, TYPE_PARITY};

const CONV_SIZE: usize = 4;
/// The per-session outbound queue depth. A full queue drops the newest buffer; KCP retransmits it.
const DEV_BACKLOG: usize = 2048;
/// The listener's accept queue depth.
const ACCEPT_BACKLOG: usize = 128;
/// The listener's session idle timeout: an entry with no inbound packet for this long closes
/// itself, and that is what removes it from the table. `transport-mkcp` ages an active conn out
/// at the same 30 s.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// The most entries the listener's session table holds: past this, a packet from an unknown
/// source address is dropped instead of allocating a session, so a spoofed-address flood cannot
/// outrun the idle eviction.
const MAX_LISTENER_SESSIONS: usize = 4096;
/// The fixed "non-continuous data" threshold passed to the FEC encoder, in milliseconds.
const MAX_FEC_ENCODE_LATENCY_MS: u32 = 500;
/// The minimum accepted packet size: the smaller of the FEC header plus conv size and the KCP
/// overhead.
const MIN_PACKET_SIZE: usize = if FEC_HEADER_SIZE_PLUS2 + CONV_SIZE > IKCP_OVERHEAD as usize {
    IKCP_OVERHEAD as usize
} else {
    FEC_HEADER_SIZE_PLUS2 + CONV_SIZE
};

fn mode_of(block: Option<&Arc<dyn BlockCrypt>>) -> CryptoMode<'_> {
    match block {
        None => CryptoMode::None,
        Some(b) => match b.as_aead() {
            Some(aead) => CryptoMode::Aead(aead),
            None => CryptoMode::Block(b.as_ref()),
        },
    }
}

fn err_closed_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")
}

/// Reads a little-endian `u16` at `offset`, or `None` when the slice is too short.
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)?.try_into().ok().map(u16::from_le_bytes)
}

/// Reads a little-endian `u32` at `offset`, or `None` when the slice is too short.
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)?.try_into().ok().map(u32::from_le_bytes)
}

/// A simple token-bucket limiter. `0` bytes/sec means unlimited.
struct RateLimiter {
    bytes_per_second: u64,
    tokens: f64,
    capacity: f64,
    last: Instant,
}

fn err_invalid_operation() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "invalid operation")
}

/// Applies a DSCP value: the 6-bit field goes to `IP_TOS = dscp << 2` on IPv4 and
/// `IPV6_TCLASS = dscp` on IPv6, and either family succeeding is enough.
fn apply_dscp(conn: &dyn Datagram, dscp: i32) -> io::Result<()> {
    let Some(sock) = conn.as_socket() else {
        return Err(err_invalid_operation());
    };
    let tos = u32::try_from(dscp).ok().and_then(|v| v.checked_shl(2));
    let mut applied = false;
    if let Some(tos) = tos {
        if sock.set_tos_v4(tos).is_ok() {
            applied = true;
        }
    }
    if let Ok(tclass) = u32::try_from(dscp) {
        if set_tclass_v6(&sock, tclass).is_ok() {
            applied = true;
        }
    }
    if applied {
        Ok(())
    } else {
        Err(err_invalid_operation())
    }
}

/// `IPV6_TCLASS` is absent from `socket2`'s public surface outside the platforms its
/// `set_tclass_v6` is gated to; a v6-only host must still get a DSCP setting.
#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "cygwin",
    target_os = "illumos",
))]
fn set_tclass_v6(sock: &socket2::SockRef<'_>, tclass: u32) -> io::Result<()> {
    sock.set_tclass_v6(tclass)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "cygwin",
    target_os = "illumos",
)))]
fn set_tclass_v6(_sock: &socket2::SockRef<'_>, _tclass: u32) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "IPV6_TCLASS unavailable"))
}

/// the `SetReadBuffer`, reached through the underlying socket's `SO_RCVBUF`.
fn apply_read_buffer(conn: &dyn Datagram, bytes: i32) -> io::Result<()> {
    let Some(sock) = conn.as_socket() else {
        return Err(err_invalid_operation());
    };
    let size = usize::try_from(bytes).map_err(|_| err_invalid_operation())?;
    sock.set_recv_buffer_size(size)
}

/// the `SetWriteBuffer`, reached through the underlying socket's `SO_SNDBUF`.
fn apply_write_buffer(conn: &dyn Datagram, bytes: i32) -> io::Result<()> {
    let Some(sock) = conn.as_socket() else {
        return Err(err_invalid_operation());
    };
    let size = usize::try_from(bytes).map_err(|_| err_invalid_operation())?;
    sock.set_send_buffer_size(size)
}

impl RateLimiter {
    fn unlimited() -> Self {
        Self { bytes_per_second: 0, tokens: 0.0, capacity: 0.0, last: Instant::now() }
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "the rate is a `u32` and the budget a small byte count, so both are exact in `f64`"
    )]
    fn set(&mut self, bytes_per_second: u32) {
        self.bytes_per_second = u64::from(bytes_per_second);
        self.capacity = (64 * crypt::MTU_LIMIT) as f64;
        self.tokens = self.capacity;
        self.last = Instant::now();
    }

    /// Blocks (async) until `n` bytes' worth of budget is available.
    // cancel-safe: the bucket is only mutated inside the synchronous block ahead of the sleep, so
    // a dropped future loses no accounting.
    #[expect(
        clippy::cast_precision_loss,
        reason = "the rate is a `u32` and the budget a small byte count, so both are exact in `f64`"
    )]
    async fn consume(limiter: &StdMutex<Self>, n: usize) {
        loop {
            let wait = {
                let mut l = limiter.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if l.bytes_per_second == 0 {
                    return;
                }
                let now = Instant::now();
                let elapsed = now.duration_since(l.last).as_secs_f64();
                l.tokens = elapsed.mul_add(l.bytes_per_second as f64, l.tokens).min(l.capacity);
                l.last = now;
                if l.tokens >= n as f64 {
                    l.tokens -= n as f64;
                    return;
                }
                let deficit = n as f64 - l.tokens;
                Duration::from_secs_f64(deficit / l.bytes_per_second as f64)
            };
            tokio::time::sleep(wait).await;
        }
    }
}

/// `KCP`'s bookkeeping that the receive path (`kcp_input`, itself driven from either the
/// client's own reader task or the listener's shared monitor task) and the public `Read` share:
/// protected by one lock.
struct Engine {
    kcp: Kcp,
    fec_decoder: Option<FecDecoder>,
    recvbuf: Vec<u8>,
    recv_pos: usize,
    recv_len: usize,
    ack_no_delay: bool,
    write_delay: bool,
    /// When the last inbound packet reached this engine; the listener's idle eviction reads it.
    last_inbound: Instant,
}

impl Engine {
    fn try_read_leftover(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.recv_pos < self.recv_len {
            let n = (self.recv_len - self.recv_pos).min(buf.remaining());
            if let Some(leftover) = self.recvbuf.get(self.recv_pos..self.recv_pos + n) {
                buf.put_slice(leftover);
            }
            self.recv_pos += n;
            true
        } else {
            false
        }
    }

    fn try_read_kcp(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        let Ok(peek) = usize::try_from(self.kcp.peek_size()) else {
            return false;
        };
        if buf.remaining() >= peek {
            let mut tmp = vec![0u8; peek];
            self.kcp.recv(&mut tmp);
            buf.put_slice(&tmp);
        } else {
            if self.recvbuf.len() < peek {
                self.recvbuf.resize(peek, 0);
            }
            if let Some(dst) = self.recvbuf.get_mut(..peek) {
                self.kcp.recv(dst);
            }
            self.recv_len = peek;
            let n = buf.remaining();
            if let Some(head) = self.recvbuf.get(..n) {
                buf.put_slice(head);
            }
            self.recv_pos = n;
        }
        true
    }

    /// Feeds a decrypted, crc32-checked packet into KCP, unwrapping FEC framing
    /// first if present.
    fn kcp_input(&mut self, data: &[u8]) {
        self.last_inbound = Instant::now();
        if data.len() < CONV_SIZE + 2 {
            return;
        }
        let Some(fec_flag) = read_u16(data, CONV_SIZE) else {
            return;
        };
        match fec_flag {
            TYPE_DATA | TYPE_PARITY => {
                if data.len() < FEC_HEADER_SIZE_PLUS2 {
                    return;
                }
                if fec_flag == TYPE_DATA {
                    if let Some(payload) = data.get(FEC_HEADER_SIZE_PLUS2..) {
                        self.kcp.input(payload, PacketType::Regular, self.ack_no_delay);
                    }
                }
                if let Some(dec) = &mut self.fec_decoder {
                    for recovered in dec.decode(data) {
                        let Some(prefix) = read_u16(&recovered, 0) else {
                            continue;
                        };
                        let sz = usize::from(prefix);
                        if sz >= 2 && sz <= recovered.len() {
                            if let Some(payload) = recovered.get(2..sz) {
                                self.kcp.input(payload, PacketType::Fec, self.ack_no_delay);
                            }
                        }
                    }
                }
            }
            TYPE_OOB => {}
            _ => {
                self.kcp.input(data, PacketType::Regular, self.ack_no_delay);
            }
        }
    }
}

struct Wakers {
    read: Mutex<Option<Waker>>,
    write: Mutex<Option<Waker>>,
}

impl Wakers {
    fn new() -> Self {
        Self { read: Mutex::new(None), write: Mutex::new(None) }
    }

    fn wake_read(&self) {
        let waker = self.read.lock().take();
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn wake_write(&self) {
        let waker = self.write.lock().take();
        if let Some(w) = waker {
            w.wake();
        }
    }
}

struct Shared {
    conv: u32,
    remote: SocketAddr,
    conn: Arc<dyn Datagram>,
    block: Option<Arc<dyn BlockCrypt>>,
    own_conn: bool,
    engine: Mutex<Engine>,
    wakers: Wakers,
    closed: CancellationToken,
    rate_limiter: Arc<StdMutex<RateLimiter>>,
    socket_read_error: Mutex<Option<io::Error>>,
    listener: Option<Arc<ListenerShared>>,
    /// `None` for a session that owns its socket: nothing holds a strong handle to such a
    /// session, so `Drop for Shared` reaches its teardown and only a listener table entry leaks.
    idle_timeout: Option<Duration>,
    /// The postprocess task: given a bounded grace period to drain whatever `flush` above
    /// already queued onto the wire (`Close` keeps its post-processing task alive until that
    /// queue is empty) before it is force-aborted.
    postprocess_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Everything else (`updater`, the client's own reader loop): safe to abort immediately,
    /// they carry no unflushed data.
    ///
    /// These workers hold [`Weak<Shared>`], never a strong handle: a strong one would keep the
    /// session alive past the last [`Session`], so `Drop` could never reach its teardown and a
    /// dropped client session would leak its socket and its tasks.
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

/// How long [`Shared::close_now`] lets the postprocess task keep draining already-queued
/// output before force-aborting it: the close waits for post-processing to empty with no
/// explicit bound beyond the process's own lifetime; a small bounded wait is the practical
/// equivalent for a `Drop`-driven teardown that cannot itself `.await`.
const CLOSE_DRAIN_GRACE: Duration = Duration::from_millis(200);

impl Shared {
    fn idle_expired(&self) -> bool {
        let Some(idle_timeout) = self.idle_timeout else {
            return false;
        };
        self.engine.lock().last_inbound.elapsed() >= idle_timeout
    }

    /// Closes: flushes pending output, then tears down. Idempotent.
    fn close_now(&self) {
        if self.closed.is_cancelled() {
            return;
        }
        self.closed.cancel();
        {
            let mut eng = self.engine.lock();
            eng.kcp.flush(crate::core::FlushType::Full);
        }
        if let Some(listener) = &self.listener {
            // Remove the entry only while it still is this session: a teardown parked between its
            // cancel and this statement must not evict a replacement admitted for the same address
            // meanwhile.
            let this = std::ptr::from_ref(self);
            let mut sessions = listener.sessions.lock();
            if let Entry::Occupied(entry) = sessions.entry(self.remote) {
                if std::ptr::eq(Arc::as_ptr(&entry.get().0), this) {
                    entry.remove();
                }
            }
        } else if self.own_conn {
            let _ = self.conn.close();
        }
        self.wakers.wake_read();
        self.wakers.wake_write();
        self.abort_tasks();
        let postprocess = self.postprocess_task.lock().take();
        if let Some(task) = postprocess {
            // `Drop` can run on the runtime's shutdown path, where spawning panics; aborting a
            // task that is already stopping is a no-op.
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    tokio::time::sleep(CLOSE_DRAIN_GRACE).await;
                    task.abort();
                });
            } else {
                task.abort();
            }
        }
    }

    /// Aborts the workers that hold no unflushed data: what cancels them even when the last
    /// [`Session`] handle is dropped rather than closed explicitly.
    fn abort_tasks(&self) {
        for task in self.tasks.lock().drain(..) {
            task.abort();
        }
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.close_now();
    }
}

/// `*UDPSession`, as a cheap `Arc` handle so accept queues, the session map and the returned
/// `Box<dyn UdpSession>` all share one underlying session.
#[derive(Clone)]
pub struct Session(Arc<Shared>);

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Session").field(&self.0.remote).finish_non_exhaustive()
    }
}

impl Session {
    fn try_read(&self, buf: &mut ReadBuf<'_>) -> Option<io::Result<()>> {
        {
            let mut eng = self.0.engine.lock();
            if eng.try_read_leftover(buf) || eng.try_read_kcp(buf) {
                return Some(Ok(()));
            }
        }
        if self.0.closed.is_cancelled() {
            return Some(Err(err_closed_pipe()));
        }
        if let Some(err) = self.0.socket_read_error.lock().as_ref() {
            return Some(Err(io::Error::new(err.kind(), err.to_string())));
        }
        None
    }

    fn try_write(&self, data: &[u8]) -> Option<io::Result<usize>> {
        let mut eng = self.0.engine.lock();
        let waitsnd = eng.kcp.wait_snd();
        if waitsnd >= eng.kcp.snd_wnd as usize {
            drop(eng);
            if self.0.closed.is_cancelled() {
                return Some(Err(err_closed_pipe()));
            }
            return None;
        }

        let mut remaining = data;
        let mss = eng.kcp.mss as usize;
        loop {
            if remaining.len() <= mss {
                eng.kcp.send(remaining);
                break;
            }
            let (head, tail) = remaining.split_at(mss);
            eng.kcp.send(head);
            remaining = tail;
        }

        let waitsnd = eng.kcp.wait_snd();
        if waitsnd >= eng.kcp.snd_wnd as usize || !eng.write_delay {
            eng.kcp.flush(crate::core::FlushType::Full);
        }
        drop(eng);
        Some(Ok(data.len()))
    }
}

impl AsyncRead for Session {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(result) = this.try_read(buf) {
            return Poll::Ready(result);
        }
        *this.0.wakers.read.lock() = Some(cx.waker().clone());
        if let Some(result) = this.try_read(buf) {
            return Poll::Ready(result);
        }
        Poll::Pending
    }
}

impl AsyncWrite for Session {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(result) = this.try_write(buf) {
            return Poll::Ready(result);
        }
        *this.0.wakers.write.lock() = Some(cx.waker().clone());
        if let Some(result) = this.try_write(buf) {
            return Poll::Ready(result);
        }
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.close_now();
        Poll::Ready(Ok(()))
    }
}

impl NetStream for Session {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.0.remote)
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.0.close_now();
        Ok(())
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.0.close_now();
        Ok(())
    }
}

/// The UDP-session trait surface.
pub trait UdpSession: NetStream {
    fn set_stream_mode(&self, enable: bool);
    fn set_write_delay(&self, delay: bool);
    fn set_no_delay(&self, nodelay: i32, interval: i32, resend: i32, nc: i32);
    fn set_window_size(&self, sndwnd: i32, rcvwnd: i32);
    fn set_mtu(&self, mtu: i32);
    fn set_ack_no_delay(&self, nodelay: bool);
    fn set_rate_limit(&self, bytes_per_second: u32);
    fn set_dscp(&self, dscp: i32) -> io::Result<()>;
    fn set_read_buffer(&self, bytes: i32) -> io::Result<()>;
    fn set_write_buffer(&self, bytes: i32) -> io::Result<()>;
}

impl UdpSession for Session {
    fn set_stream_mode(&self, enable: bool) {
        self.0.engine.lock().kcp.stream = enable;
    }

    fn set_write_delay(&self, delay: bool) {
        self.0.engine.lock().write_delay = delay;
    }

    fn set_no_delay(&self, nodelay: i32, interval: i32, resend: i32, nc: i32) {
        self.0.engine.lock().kcp.no_delay(nodelay, interval, resend, nc);
    }

    fn set_window_size(&self, sndwnd: i32, rcvwnd: i32) {
        self.0.engine.lock().kcp.wnd_size(sndwnd, rcvwnd);
    }

    fn set_mtu(&self, mtu: i32) {
        let limit = i32::try_from(crypt::MTU_LIMIT).unwrap_or(i32::MAX);
        self.0.engine.lock().kcp.set_mtu(mtu.min(limit));
    }

    fn set_ack_no_delay(&self, nodelay: bool) {
        self.0.engine.lock().ack_no_delay = nodelay;
    }

    fn set_rate_limit(&self, bytes_per_second: u32) {
        self.0.rate_limiter.lock().unwrap_or_else(std::sync::PoisonError::into_inner).set(bytes_per_second);
    }

    fn set_dscp(&self, dscp: i32) -> io::Result<()> {
        if self.0.listener.is_some() {
            return Err(err_invalid_operation());
        }
        apply_dscp(self.0.conn.as_ref(), dscp)
    }

    fn set_read_buffer(&self, bytes: i32) -> io::Result<()> {
        if self.0.listener.is_some() {
            return Err(err_invalid_operation());
        }
        apply_read_buffer(self.0.conn.as_ref(), bytes)
    }

    fn set_write_buffer(&self, bytes: i32) -> io::Result<()> {
        if self.0.listener.is_some() {
            return Err(err_invalid_operation());
        }
        apply_write_buffer(self.0.conn.as_ref(), bytes)
    }
}

/// The listener trait surface.
#[async_trait]
pub trait Listener: Send + Sync {
    fn set_dscp(&self, dscp: i32) -> io::Result<()>;
    fn set_read_buffer(&self, bytes: i32) -> io::Result<()>;
    fn set_write_buffer(&self, bytes: i32) -> io::Result<()>;
    async fn accept_kcp(&self) -> Result<Box<dyn UdpSession>>;
    fn close(&self) -> io::Result<()>;
}

struct ListenerShared {
    conn: Arc<dyn Datagram>,
    block: Option<Arc<dyn BlockCrypt>>,
    data_shards: i32,
    parity_shards: i32,
    sessions: Mutex<HashMap<SocketAddr, Session>>,
    accept_tx: mpsc::Sender<Session>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<Session>>,
    closed: CancellationToken,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    limits: ListenerLimits,
}

/// The listener's table bounds. `serve_conn` uses the crate defaults; tests drive the same path
/// with tighter ones.
#[derive(Clone, Copy)]
struct ListenerLimits {
    idle_timeout: Duration,
    max_sessions: usize,
}

impl Default for ListenerLimits {
    fn default() -> Self {
        Self { idle_timeout: SESSION_IDLE_TIMEOUT, max_sessions: MAX_LISTENER_SESSIONS }
    }
}

pub struct KcpListener(Arc<ListenerShared>);

impl core::fmt::Debug for KcpListener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("KcpListener").field(&self.0.data_shards).finish_non_exhaustive()
    }
}

impl Drop for ListenerShared {
    fn drop(&mut self) {
        self.closed.cancel();
        let _ = self.conn.close();
        for task in self.tasks.lock().drain(..) {
            task.abort();
        }
    }
}

#[async_trait]
impl Listener for KcpListener {
    fn set_dscp(&self, dscp: i32) -> io::Result<()> {
        apply_dscp(self.0.conn.as_ref(), dscp)
    }

    fn set_read_buffer(&self, bytes: i32) -> io::Result<()> {
        apply_read_buffer(self.0.conn.as_ref(), bytes)
    }

    fn set_write_buffer(&self, bytes: i32) -> io::Result<()> {
        apply_write_buffer(self.0.conn.as_ref(), bytes)
    }

    // cancel-safe: the only await is on a cancel-safe `mpsc::Receiver::recv`, and the accept
    // queue guard is released before the result is returned.
    async fn accept_kcp(&self) -> Result<Box<dyn UdpSession>> {
        let mut rx = self.0.accept_rx.lock().await;
        let accepted = tokio::select! {
            session = rx.recv() => session.map(|s| -> Box<dyn UdpSession> { Box::new(s) }).ok_or_else(|| anyhow!("io: read/write on closed pipe")),
            () = self.0.closed.cancelled() => Err(anyhow!("io: read/write on closed pipe")),
        };
        drop(rx);
        accepted
    }

    fn close(&self) -> io::Result<()> {
        self.0.closed.cancel();
        self.0.conn.close()
    }
}

fn new_engine(
    conv: u32,
    data_shards: i32,
    parity_shards: i32,
    tx: mpsc::Sender<Vec<u8>>,
    header_size: usize,
) -> Engine {
    let kcp = Kcp::new(
        conv,
        Box::new(move |buf: &[u8]| {
            if buf.len() >= IKCP_OVERHEAD as usize {
                let mut framed = vec![0u8; header_size + buf.len()];
                if let Some(dst) = framed.get_mut(header_size..) {
                    dst.copy_from_slice(buf);
                }
                let _ = tx.try_send(framed);
            }
        }),
    );
    Engine {
        kcp,
        fec_decoder: FecDecoder::new(data_shards, parity_shards),
        recvbuf: vec![0u8; crypt::MTU_LIMIT],
        recv_pos: 0,
        recv_len: 0,
        ack_no_delay: false,
        write_delay: false,
        last_inbound: Instant::now(),
    }
}

/// Header sizes for a session: the crypto and FEC header lengths plus the initial
/// post-headroom MTU to apply.
struct HeaderLayout {
    fec_offset: usize,
    total_header: usize,
    initial_mtu: i32,
}

fn compute_header_layout(block: Option<&Arc<dyn BlockCrypt>>, fec_enabled: bool) -> HeaderLayout {
    let mode = mode_of(block);
    let crypto_header = crypt::header_size(&mode);
    let fec_offset = crypto_header;
    let total_header = if fec_enabled { crypto_header + FEC_HEADER_SIZE_PLUS2 } else { crypto_header };
    let overhead = total_header + crypt::aead_overhead(&mode);
    let mtu = (IKCP_MTU_DEF as usize).saturating_sub(overhead);
    HeaderLayout { fec_offset, total_header, initial_mtu: i32::try_from(mtu).unwrap_or(i32::MAX) }
}

/// The post-processing task: `KCP output -> FEC encoding -> CRC32 integrity -> encryption -> wire`.
// NOT cancel-safe: `fec_encoder` holds a partly filled shard group across the sends, and the
// task is only aborted once the session is torn down.
async fn postprocess_task(
    mut rx: mpsc::Receiver<Vec<u8>>,
    conn: Arc<dyn Datagram>,
    remote: SocketAddr,
    block: Option<Arc<dyn BlockCrypt>>,
    mut fec_encoder: Option<FecEncoder>,
    rate_limiter: Arc<StdMutex<RateLimiter>>,
) {
    while let Some(mut buf) = rx.recv().await {
        let mode = mode_of(block.as_ref());

        let ecc: Vec<Vec<u8>> = match &mut fec_encoder {
            Some(enc) => enc.encode(&mut buf, MAX_FEC_ENCODE_LATENCY_MS),
            None => Vec::new(),
        };

        crypt::seal_packet(&mode, &mut buf);
        let mut framed_ecc = Vec::with_capacity(ecc.len());
        for mut shard in ecc {
            crypt::seal_packet(&mode, &mut shard);
            framed_ecc.push(shard);
        }

        let total: usize = buf.len() + framed_ecc.iter().map(Vec::len).sum::<usize>();
        RateLimiter::consume(&rate_limiter, total).await;

        if conn.send_to(&buf, remote).await.is_err() {
            break;
        }
        for shard in framed_ecc {
            if conn.send_to(&shard, remote).await.is_err() {
                break;
            }
        }
    }
}

/// The per-session periodic flush loop, using the flush's own computed
/// next-update delay to reschedule itself (exactly like the timer reset), rather than a fixed
/// tick.
// cancel-safe: a flush is synchronous, so a dropped sleep only delays the next one. The idle
// check is what evicts a listener session the table's own clone would otherwise pin forever.
// The `Weak` keeps the session collectable: the task exits, rather than resurrecting it, once
// the last `Session` handle is gone.
async fn updater_task(weak: Weak<Shared>) {
    loop {
        let delay = {
            let Some(shared) = weak.upgrade() else {
                return;
            };
            let interval = {
                let mut eng = shared.engine.lock();
                let interval = eng.kcp.flush(crate::core::FlushType::Full);
                let waitsnd = eng.kcp.wait_snd();
                if waitsnd < eng.kcp.snd_wnd as usize {
                    drop(eng);
                    shared.wakers.wake_write();
                }
                interval
            };
            if shared.idle_expired() {
                shared.close_now();
                return;
            }
            if shared.closed.is_cancelled() {
                return;
            }
            interval
        };
        // Never park holding an upgraded `Arc`: doing so would keep the session alive from the
        // moment the last `Session` handle drops and stall its teardown indefinitely.
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(u64::from(delay))) => {}
            () = weak_cancelled(&weak) => return,
        }
    }
}

/// Waits for the session's close token through a [`Weak`] handle, so the waiter parks without
/// owning the session. Resolves once the session is gone, whether it closed itself or its last
/// handle was dropped.
// cancel-safe: `CancellationToken::cancelled` is cancel-safe, and this only ever observes the
// token, never mutating session state.
async fn weak_cancelled(weak: &Weak<Shared>) {
    let Some(shared) = weak.upgrade() else {
        return;
    };
    let closed = shared.closed.clone();
    drop(shared);
    closed.cancelled().await;
}

/// The client's own reader task (only used when this session owns its
/// `conn` exclusively, i.e. [`new_conn4`]).
// cancel-safe: `Datagram::recv_from` is cancel-safe, and a dropped iteration loses at most one
// datagram, which KCP retransmits.
// The `Weak` keeps the session collectable: a parked `recv_from` therefore cannot hold the
// socket open past the last `Session` handle.
async fn client_read_loop(weak: Weak<Shared>) {
    let Some(initial) = weak.upgrade() else {
        return;
    };
    // Holding the socket itself is what keeps it open: the session's own handle is released with
    // the session, and a parked `recv_from` on this task must not keep the session alive to do so.
    let conn = Arc::clone(&initial.conn);
    drop(initial);
    let mut buf = vec![0u8; crypt::MTU_LIMIT];
    loop {
        // Never park holding an upgraded `Arc`: the session must stay collectable while this task
        // waits for the next datagram.
        let (n, from) = tokio::select! {
            result = conn.recv_from(&mut buf) => match result {
                Ok(v) => v,
                Err(err) => {
                    if let Some(shared) = weak.upgrade() {
                        *shared.socket_read_error.lock() = Some(err);
                        shared.wakers.wake_read();
                    }
                    return;
                }
            },
            () = weak_cancelled(&weak) => return,
        };
        let Some(shared) = weak.upgrade() else {
            return;
        };
        if from != shared.remote {
            continue;
        }
        let Some(packet) = buf.get(..n) else { continue };
        let mode = mode_of(shared.block.as_ref());
        if let Some(data) = crypt::open_packet(&mode, packet.to_vec()) {
            if data.len() >= MIN_PACKET_SIZE {
                let mut eng = shared.engine.lock();
                eng.kcp_input(&data);
                let readable = eng.kcp.peek_size() > 0;
                let writable = eng.kcp.wait_snd() < eng.kcp.snd_wnd as usize;
                drop(eng);
                if readable {
                    shared.wakers.wake_read();
                }
                if writable {
                    shared.wakers.wake_write();
                }
            }
        }
    }
}

/// The shared socket's dispatch-by-conv-id loop.
// NOT cancel-safe: an iteration cancelled after the insert below leaves a session in the map
// that was never handed to the accept queue; the task is only aborted when the listener drops.
async fn listener_monitor(listener: Arc<ListenerShared>) {
    let mut buf = vec![0u8; crypt::MTU_LIMIT];
    loop {
        let (n, from) = tokio::select! {
            result = listener.conn.recv_from(&mut buf) => match result {
                Ok(v) => v,
                Err(_) => return,
            },
            () = listener.closed.cancelled() => return,
        };

        let Some(packet) = buf.get(..n) else { continue };
        let mode = mode_of(listener.block.as_ref());
        let Some(data) = crypt::open_packet(&mode, packet.to_vec()) else { continue };
        if data.len() < MIN_PACKET_SIZE {
            continue;
        }

        let existing = listener.sessions.lock().get(&from).cloned();

        let Some(fec_flag) = read_u16(&data, CONV_SIZE) else { continue };
        let (has_conv, conv, sn) = match fec_flag {
            TYPE_DATA => {
                if data.len() < FEC_HEADER_SIZE_PLUS2 + IKCP_OVERHEAD as usize {
                    (false, 0, 0)
                } else {
                    let Some(conv) = read_u32(&data, FEC_HEADER_SIZE_PLUS2) else { continue };
                    let Some(sn) = read_u32(&data, FEC_HEADER_SIZE_PLUS2 + IKCP_SN_OFFSET) else { continue };
                    (true, conv, sn)
                }
            }
            TYPE_PARITY => (false, 0, 0),
            TYPE_OOB => continue,
            _ => {
                if data.len() < IKCP_OVERHEAD as usize {
                    continue;
                }
                let Some(conv) = read_u32(&data, 0) else { continue };
                let Some(sn) = read_u32(&data, IKCP_SN_OFFSET) else { continue };
                (true, conv, sn)
            }
        };

        if let Some(session) = existing {
            if !has_conv || conv == session.0.conv {
                let mut eng = session.0.engine.lock();
                eng.kcp_input(&data);
                let readable = eng.kcp.peek_size() > 0;
                let writable = eng.kcp.wait_snd() < eng.kcp.snd_wnd as usize;
                drop(eng);
                if readable {
                    session.0.wakers.wake_read();
                }
                if writable {
                    session.0.wakers.wake_write();
                }
                continue;
            }
            if sn != 0 {
                continue;
            }
            session.0.close_now();
        }

        if !has_conv {
            continue;
        }

        // At the cap, a new source address is refused rather than evicting an entry a peer is
        // already using.
        if listener.sessions.lock().len() >= listener.limits.max_sessions {
            continue;
        }

        let session = new_session(
            conv,
            from,
            Arc::clone(&listener.conn),
            false,
            listener.block.clone(),
            listener.data_shards,
            listener.parity_shards,
            Some(Arc::clone(&listener)),
        );
        {
            let mut eng = session.0.engine.lock();
            eng.kcp_input(&data);
        }
        listener.sessions.lock().insert(from, session.clone());
        if listener.accept_tx.send(session).await.is_err() {
            return;
        }
    }
}

fn new_session(
    conv: u32,
    remote: SocketAddr,
    sock: Arc<dyn Datagram>,
    own_conn: bool,
    block: Option<Arc<dyn BlockCrypt>>,
    data_shards: i32,
    parity_shards: i32,
    listener: Option<Arc<ListenerShared>>,
) -> Session {
    let fec_enabled = data_shards > 0 && parity_shards > 0;
    let layout = compute_header_layout(block.as_ref(), fec_enabled);

    let (tx, rx) = mpsc::channel(DEV_BACKLOG);
    let engine = new_engine(conv, data_shards, parity_shards, tx, layout.total_header);

    let rate_limiter = Arc::new(StdMutex::new(RateLimiter::unlimited()));
    let idle_timeout = listener.as_ref().map(|listener| listener.limits.idle_timeout);
    let shared = Arc::new(Shared {
        conv,
        remote,
        conn: Arc::clone(&sock),
        block: block.clone(),
        own_conn,
        engine: Mutex::new(engine),
        wakers: Wakers::new(),
        closed: CancellationToken::new(),
        rate_limiter: Arc::clone(&rate_limiter),
        socket_read_error: Mutex::new(None),
        listener,
        idle_timeout,
        postprocess_task: Mutex::new(None),
        tasks: Mutex::new(Vec::new()),
    });
    shared.engine.lock().kcp.set_mtu(layout.initial_mtu.max(50));

    let fec_encoder = FecEncoder::new(data_shards, parity_shards, layout.fec_offset);
    let pp_task = tokio::spawn(postprocess_task(rx, sock, remote, block, fec_encoder, rate_limiter));
    let weak = Arc::downgrade(&shared);
    let up_task = tokio::spawn(updater_task(weak));
    *shared.postprocess_task.lock() = Some(pp_task);
    shared.tasks.lock().push(up_task);

    Session(shared)
}

pub fn new_conn4(
    convid: u32,
    raddr: SocketAddr,
    block: Option<Arc<dyn BlockCrypt>>,
    data_shards: i32,
    parity_shards: i32,
    own_conn: bool,
    conn: Box<dyn Datagram>,
) -> Result<Box<dyn UdpSession>> {
    let conn: Arc<dyn Datagram> = Arc::from(conn);
    let session = new_session(convid, raddr, conn, own_conn, block, data_shards, parity_shards, None);
    let read_task = tokio::spawn(client_read_loop(Arc::downgrade(&session.0)));
    session.0.tasks.lock().push(read_task);
    Ok(Box::new(session))
}

/// Builds a listener over a socket this crate owns from here on.
///
/// Unlike the public `serve_conn` (which leaves ownership with the caller), the `conn` here is
/// moved in — the caller has no handle left, so
/// the listener owns it and closes it on [`Listener::close`].
///
/// The listener's session table is bounded: an entry with no inbound packet for
/// `SESSION_IDLE_TIMEOUT` closes itself and leaves the table, and a packet from an unknown source
/// address is dropped while the table already holds `MAX_LISTENER_SESSIONS` entries.
pub fn serve_conn(
    block: Option<Arc<dyn BlockCrypt>>,
    data_shards: i32,
    parity_shards: i32,
    conn: Box<dyn Datagram>,
) -> Result<Box<dyn Listener>> {
    let conn: Arc<dyn Datagram> = Arc::from(conn);
    Ok(Box::new(KcpListener(new_listener(block, data_shards, parity_shards, conn, ListenerLimits::default()))))
}

fn new_listener(
    block: Option<Arc<dyn BlockCrypt>>,
    data_shards: i32,
    parity_shards: i32,
    conn: Arc<dyn Datagram>,
    limits: ListenerLimits,
) -> Arc<ListenerShared> {
    let (accept_tx, accept_rx) = mpsc::channel(ACCEPT_BACKLOG);
    let listener = Arc::new(ListenerShared {
        conn,
        block,
        data_shards,
        parity_shards,
        sessions: Mutex::new(HashMap::new()),
        accept_tx,
        accept_rx: tokio::sync::Mutex::new(accept_rx),
        closed: CancellationToken::new(),
        tasks: Mutex::new(Vec::new()),
        limits,
    });
    let mon = tokio::spawn(listener_monitor(Arc::clone(&listener)));
    listener.tasks.lock().push(mon);
    listener
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncWriteExt;
    use tokio::net::UdpSocket;

    async fn bound_socket() -> (UdpSocket, SocketAddr) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback udp socket");
        let addr = sock.local_addr().expect("local_addr");
        (sock, addr)
    }

    async fn listener_with(limits: ListenerLimits) -> (Arc<ListenerShared>, SocketAddr) {
        let (sock, addr) = bound_socket().await;
        let conn: Box<dyn Datagram> = Box::new(sock);
        (new_listener(None, 0, 0, Arc::from(conn), limits), addr)
    }

    fn session_count(listener: &Arc<ListenerShared>) -> usize {
        listener.sessions.lock().len()
    }

    async fn wait_until(deadline: Duration, what: &str, mut predicate: impl FnMut() -> bool + Send) {
        let waited = tokio::time::timeout(deadline, async {
            while !predicate() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "{what} did not happen within {deadline:?}");
    }

    /// Dials the listener from a socket of its own and writes one payload. The caller holds the
    /// returned session: dropping it closes the client's socket.
    async fn dial(addr: SocketAddr, conv: u32) -> Box<dyn UdpSession> {
        let (sock, _) = bound_socket().await;
        let mut client = new_conn4(conv, addr, None, 0, 0, true, Box::new(sock)).expect("new_conn4");
        client.write_all(&[0x5au8; 64]).await.expect("client write_all");
        client
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_listener_session_that_goes_idle_leaves_the_session_table() {
        let limits = ListenerLimits { idle_timeout: Duration::from_millis(500), max_sessions: MAX_LISTENER_SESSIONS };
        let (listener, addr) = listener_with(limits).await;

        let mut clients = Vec::new();
        for conv in 1..=8 {
            clients.push(dial(addr, conv).await);
        }
        wait_until(Duration::from_secs(5), "eight sessions entering the table", || session_count(&listener) == 8).await;

        let accepted = KcpListener(Arc::clone(&listener)).accept_kcp().await.expect("accept_kcp");
        drop(accepted);
        assert_eq!(session_count(&listener), 8, "an accepted handle the table does not hold must not evict");

        wait_until(Duration::from_secs(10), "the idle entries being evicted", || session_count(&listener) == 0).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_session_table_refuses_an_unknown_address_at_the_cap() {
        let limits = ListenerLimits { idle_timeout: SESSION_IDLE_TIMEOUT, max_sessions: 2 };
        let (listener, addr) = listener_with(limits).await;

        let mut clients = Vec::new();
        for conv in 1..=5 {
            clients.push(dial(addr, conv).await);
        }
        wait_until(Duration::from_secs(5), "the table reaching its cap", || session_count(&listener) >= 2).await;

        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(session_count(&listener), 2, "the refused clients keep retransmitting into a full table");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_replacement_admitted_during_a_teardown_survives_it() {
        let (listener, addr) = listener_with(ListenerLimits::default()).await;
        let stale = new_session(1, addr, Arc::clone(&listener.conn), false, None, 0, 0, Some(Arc::clone(&listener)));
        listener.sessions.lock().insert(addr, stale.clone());
        let replacement =
            new_session(2, addr, Arc::clone(&listener.conn), false, None, 0, 0, Some(Arc::clone(&listener)));
        let teardown = tokio::spawn({
            let closing = stale.clone();
            async move { closing.0.close_now() }
        });

        {
            // The table lock is what the teardown re-enters after cancelling its token: holding it
            // parks the teardown between its cancel and its removal, which is the racing window.
            let mut table = listener.sessions.lock();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !stale.0.closed.is_cancelled() {
                assert!(Instant::now() < deadline, "the teardown never reached its removal");
                std::thread::yield_now();
            }
            table.insert(addr, replacement.clone());
        }

        teardown.await.expect("teardown task");
        let stored = listener.sessions.lock().get(&addr).map(|stored| stored.0.conv);
        assert_eq!(stored, Some(2), "the replacement must survive the stale teardown");
    }

    #[tokio::test]
    async fn a_teardown_removes_the_table_entry_it_owns() {
        let (listener, addr) = listener_with(ListenerLimits::default()).await;
        let session = new_session(1, addr, Arc::clone(&listener.conn), false, None, 0, 0, Some(Arc::clone(&listener)));
        listener.sessions.lock().insert(addr, session.clone());

        session.0.close_now();

        assert_eq!(session_count(&listener), 0, "a teardown must remove its own entry");
    }

    /// A client socket that never yields an inbound packet, so only the teardown itself can stop
    /// the reader task, and that records its close calls. The `alive` marker is held by the session
    /// and by the reader's own socket clone: a `Weak` to it only dies once both released it, which
    /// is what makes a reader that leaked while parked observable.
    struct PendingDatagram {
        close_calls: Arc<AtomicUsize>,
        alive: Arc<()>,
    }

    #[async_trait]
    impl Datagram for PendingDatagram {
        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }

        async fn send_to(&self, buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 9)))
        }

        fn close(&self) -> io::Result<()> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_last_client_handle_closes_it_and_stops_its_workers() {
        let close_calls = Arc::new(AtomicUsize::new(0));
        let sock = Arc::new(PendingDatagram { close_calls: Arc::clone(&close_calls), alive: Arc::new(()) });
        let alive = Arc::downgrade(&sock.alive);
        let session_sock = Arc::clone(&sock);
        let client =
            new_session(0xdead_beef, SocketAddr::from(([127, 0, 0, 1], 9)), session_sock, true, None, 0, 0, None);
        let read_task = tokio::spawn(client_read_loop(Arc::downgrade(&client.0)));
        client.0.tasks.lock().push(read_task);
        let weak = Arc::downgrade(&client.0);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(weak.upgrade().is_some(), "the live session must be upgradeable");
        drop(sock);

        drop(client);
        // Let the runtime reap the workers before asking whether anything survived the drop.
        let deadline = Instant::now() + Duration::from_secs(5);
        while alive.upgrade().is_some() && Instant::now() < deadline {
            tokio::task::yield_now().await;
        }

        assert_eq!(close_calls.load(Ordering::SeqCst), 1, "the drop must reach the teardown's close hook");
        assert!(weak.upgrade().is_none(), "the dropped session must be collectable");
        assert!(
            alive.upgrade().is_none(),
            "the reader loop must exit and release its socket clone, not stay parked on a Weak-only session"
        );
    }
}

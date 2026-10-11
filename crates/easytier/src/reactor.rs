//! Host-import dispatch glue — see CoreAbiMap §6 and HostAbiMap §0/§9/§10/§13.
//!
//! [`Reactor`] is the non-blocking front door every wasmtime host-import closure (written in a
//! sibling `host_abi.rs`, not here) calls into. `start_X` claims an operation id, spawns a
//! `tokio::spawn`'d task to do the real async work through [`platform::Services`], and returns
//! immediately; `take_X` is a synchronous, non-blocking poll that returns
//! [`TakeOutcome::Pending`] until the task has stored its result. Completion is announced through
//! [`Reactor::doorbell`], a coalescing [`Notify`] — never a data channel — matching the
//! buffered-1 completion channel (CoreAbiMap §6.3).
//!
//! **Deviation**: operations are cancelled by combining a [`CancellationToken`]
//! (best-effort, honoured by [`platform::Services`] implementations that check it) with aborting
//! the underlying [`tokio::task::AbortHandle`] (a hard stop wasmtime's non-`async` host-import
//! closures can't await). [`Reactor::cancel_operation`] still leaves the operation claimed so the
//! guest must `take_X` once more to observe [`ReactorError::Cancelled`] and free the slot, mirroring
//! cancelling-and-waiting racing the operation's own completion.
//!
//! A TCP stream is split into directional halves, one lock each, so a pending `start_read` never
//! blocks the `start_write` that would end it. UDP and
//! TCP-listener resources need no such lock because [`PacketConn::read_from`]/`write_to` and
//! [`Listener::accept`] all take `&self`, so those tables hold plain `Arc<dyn _>`.
//!
//! **Deviation**: `start_udp_recv` performs one `read_from` per call instead of maintaining a
//! continuously-refilling 64-entry backlog; the guest already issues one `start_udp_recv` per
//! desired receive in this ABI, so the extra backlog buys nothing here.
//!
//! **Deviation**: closing a datagram handle closes the underlying socket immediately
//! instead of deferring close until the queued send backlog drains; any send still queued at
//! close time is dropped.

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex as SyncMutex;
use tokio::sync::{mpsc, Mutex as TokioMutex, Notify};
use tokio::task::AbortHandle;
use tokio_util::sync::CancellationToken;

use murmur_component_easytier::platform::platform;
use murmur_std_compat::net::{Addr as NetAddr, Conn, Listener, PacketConn, UdpAddr};

/// The starting value of the handle allocator (HostAbiMap §0): a separate numeric keyspace from
/// guest-chosen operation ids, purely for debug-trace distinguishability.
const FIRST_HANDLE: u64 = 1u64 << 48;
const UDP_RECEIVE_BUFFER_LEN: usize = 65_535;

/// A resolved network address: every socket/DNS/environment result the guest can see crosses the
/// ABI as one of these.
pub type Addr = Box<dyn NetAddr>;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// One connected stream handle. The read and write directions take separate locks so a pending
/// read never blocks the write that ends it.
struct StreamHandle {
    read: TokioMutex<Option<tokio::io::ReadHalf<Box<dyn Conn>>>>,
    write: TokioMutex<Option<tokio::io::WriteHalf<Box<dyn Conn>>>>,
}

impl StreamHandle {
    fn new(conn: Box<dyn Conn>) -> Self {
        let (read, write) = tokio::io::split(conn);
        Self { read: TokioMutex::new(Some(read)), write: TokioMutex::new(Some(write)) }
    }
}

/// Dropping both halves drops the underlying conn, which closes the socket.
fn closed_stream_error() -> ReactorError {
    ReactorError::Io(std::io::Error::new(std::io::ErrorKind::NotConnected, "stream handle is closed"))
}

/// Host-side callback for `start_management_call`/`take_management_call` (HostAbiMap §12).
///
/// The opaque request/response byte-blob schema lives outside `platform::Services` entirely, so a
/// later `host.rs`/`engine.rs` layer installs this via [`Reactor::set_management_handler`].
pub type ManagementHandler = Arc<dyn Fn(CancellationToken, Vec<u8>) -> BoxFuture<Vec<u8>> + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum ReactorError {
    #[error("operation {0} is already claimed")]
    AlreadyClaimed(u64),
    #[error("operation {0} is unknown (never started, or already taken)")]
    UnknownOperation(u64),
    #[error("operation {0} is not a {1:?} operation")]
    WrongOperationKind(u64, OperationKind),
    #[error("handle {0} is unknown (never minted, or already closed)")]
    UnknownHandle(u64),
    #[error("operation {0} was cancelled")]
    Cancelled(u64),
    #[error("send queue is full")]
    WouldBlock,
    #[error("no management handler is configured")]
    ManagementHandlerNotConfigured,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// The full operation-family vocabulary the ABI exposes (HostAbiMap §0's `operations` table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationKind {
    TcpConnect,
    UdpBind,
    TcpListen,
    TcpAccept,
    Read,
    Write,
    UdpRecv,
    UdpSend,
    DnsResolve,
    DnsTxt,
    DnsSrv,
    LocalAddrForRemote,
    Management,
    PacketWriteReady,
}

/// The result of polling a `take_X` call.
///
/// [`TakeOutcome::NeedsCapacity`] is only ever returned by the byte-buffer-backed families
/// (`take_read`, `take_management_call`) that can compare their buffered length against the
/// guest's supplied capacity without needing `wire.rs`'s encoding (HostAbiMap §7/§9's shared
/// "buffer too small" resize pattern); every other family always answers `Pending`/`Ready`.
#[derive(Debug)]
pub enum TakeOutcome<T> {
    Pending,
    Ready(T),
    NeedsCapacity(usize),
}

#[derive(Debug)]
pub struct StreamResult {
    pub handle: u64,
    pub local: Addr,
    pub peer: Addr,
}

#[derive(Debug)]
pub struct BoundResult {
    pub handle: u64,
    pub local: Addr,
}

#[derive(Debug)]
pub struct ReadResult {
    pub data: Vec<u8>,
    pub eof: bool,
}

#[derive(Debug)]
pub struct UdpDatagram {
    pub data: Vec<u8>,
    pub peer: Addr,
    pub truncated: bool,
}

struct DatagramSend {
    tx: mpsc::Sender<(Vec<u8>, Addr)>,
    sticky_error: Arc<SyncMutex<Option<ReactorError>>>,
}

type Slot = Arc<SyncMutex<Option<Box<dyn Any + Send>>>>;

struct OperationEntry {
    kind: OperationKind,
    cancel: CancellationToken,
    abort: AbortHandle,
    slot: Slot,
}

/// See the module doc for the concurrency contract every method here must uphold. Intended to be
/// shared as `Arc<Reactor>` (host-import closures each hold a clone).
pub struct Reactor {
    services: Arc<platform::Services>,
    runtime: tokio::runtime::Handle,
    next_handle: Arc<AtomicU64>,
    operations: SyncMutex<HashMap<u64, OperationEntry>>,
    cancelled: SyncMutex<HashSet<u64>>,
    doorbell: Arc<Notify>,
    streams: Arc<SyncMutex<HashMap<u64, Arc<StreamHandle>>>>,
    datagrams: Arc<SyncMutex<HashMap<u64, Arc<dyn PacketConn>>>>,
    datagram_sends: Arc<SyncMutex<HashMap<u64, Arc<DatagramSend>>>>,
    listeners: Arc<SyncMutex<HashMap<u64, Arc<dyn Listener>>>>,
    event_sinks: Arc<SyncMutex<HashMap<u64, mpsc::Sender<(String, String)>>>>,
    packet_sinks: Arc<SyncMutex<HashMap<u64, mpsc::Sender<Vec<u8>>>>>,
    management_handler: SyncMutex<Option<ManagementHandler>>,
}

impl core::fmt::Debug for Reactor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reactor").field("next_handle", &self.next_handle).finish_non_exhaustive()
    }
}

impl Reactor {
    /// The reactor spawns its I/O on the ambient runtime, so it must be built from inside one.
    #[must_use]
    pub fn new(services: Arc<platform::Services>) -> Self {
        Self {
            runtime: tokio::runtime::Handle::current(),
            services,
            next_handle: Arc::new(AtomicU64::new(FIRST_HANDLE)),
            operations: SyncMutex::new(HashMap::new()),
            cancelled: SyncMutex::new(HashSet::new()),
            doorbell: Arc::new(Notify::new()),
            streams: Arc::new(SyncMutex::new(HashMap::new())),
            datagrams: Arc::new(SyncMutex::new(HashMap::new())),
            datagram_sends: Arc::new(SyncMutex::new(HashMap::new())),
            listeners: Arc::new(SyncMutex::new(HashMap::new())),
            event_sinks: Arc::new(SyncMutex::new(HashMap::new())),
            packet_sinks: Arc::new(SyncMutex::new(HashMap::new())),
            management_handler: SyncMutex::new(None),
        }
    }

    /// The completion doorbell (CoreAbiMap §6.3): `.notified().await` in the actor task driving
    /// the wasmtime `Store`, woken once per batch of completions, never carrying data itself.
    pub fn doorbell(&self) -> Arc<Notify> {
        Arc::clone(&self.doorbell)
    }

    /// Chosen over a mutex-guarded counter (§0's handle allocation): a single `fetch_add`
    /// needs no critical section. `Arc`-wrapped so `start_X` closures can mint a handle from
    /// inside their spawned `'static` task without borrowing `self`.
    fn allocate_handle(&self) -> u64 {
        self.next_handle.fetch_add(1, Ordering::Relaxed)
    }

    pub fn set_management_handler(&self, handler: ManagementHandler) {
        *self.management_handler.lock() = Some(handler);
    }

    /// Claims `operation` under `kind` and spawns `work` to run it. Returns
    /// [`ReactorError::AlreadyClaimed`] without spawning anything if `operation` is already
    /// in flight, mirroring the operation claim.
    fn claim_operation<T, F, Fut>(&self, operation: u64, kind: OperationKind, work: F) -> Result<(), ReactorError>
    where
        T: Send + 'static,
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, ReactorError>> + Send + 'static,
    {
        let mut operations = self.operations.lock();
        if operations.contains_key(&operation) {
            return Err(ReactorError::AlreadyClaimed(operation));
        }
        let cancel = CancellationToken::new();
        let slot: Slot = Arc::new(SyncMutex::new(None));
        let slot_task = Arc::clone(&slot);
        let doorbell = Arc::clone(&self.doorbell);
        let cancel_task = cancel.clone();
        let join = self.runtime.spawn(async move {
            let result = work(cancel_task).await;
            let boxed: Box<dyn Any + Send> = Box::new(result);
            *slot_task.lock() = Some(boxed);
            doorbell.notify_one();
        });
        operations.insert(operation, OperationEntry { kind, cancel, abort: join.abort_handle(), slot });
        drop(operations);
        Ok(())
    }

    fn resolve_slot(&self, operation: u64, expected: OperationKind) -> Result<Slot, ReactorError> {
        let operations = self.operations.lock();
        let entry = operations.get(&operation).ok_or(ReactorError::UnknownOperation(operation))?;
        if entry.kind != expected {
            return Err(ReactorError::WrongOperationKind(operation, expected));
        }
        let slot = Arc::clone(&entry.slot);
        drop(operations);
        Ok(slot)
    }

    fn finish_operation(&self, operation: u64) {
        self.operations.lock().remove(&operation);
        self.cancelled.lock().remove(&operation);
    }

    /// The common `take_X` body for every family whose result, once ready, is always handed back
    /// whole (no buffer-too-small resize step).
    fn take_simple<T: Send + 'static>(
        &self,
        operation: u64,
        expected: OperationKind,
    ) -> Result<TakeOutcome<T>, ReactorError> {
        let slot = self.resolve_slot(operation, expected)?;
        let mut guard = slot.lock();
        let Some(boxed) = guard.take() else {
            if self.cancelled.lock().contains(&operation) {
                drop(guard);
                self.finish_operation(operation);
                return Err(ReactorError::Cancelled(operation));
            }
            return Ok(TakeOutcome::Pending);
        };
        drop(guard);
        self.finish_operation(operation);
        let result = *boxed
            .downcast::<Result<T, ReactorError>>()
            .map_err(|_| ReactorError::Other(anyhow::anyhow!("operation slot type mismatch")))?;
        result.map(TakeOutcome::Ready)
    }

    /// The shared "buffer too small" pattern (HostAbiMap §7/§9): if the ready value's encoded
    /// length exceeds `capacity`, the operation stays claimed and [`TakeOutcome::NeedsCapacity`]
    /// reports the length the guest must retry with.
    fn take_capacity_checked<T, F>(
        &self,
        operation: u64,
        expected: OperationKind,
        capacity: usize,
        len_of: F,
    ) -> Result<TakeOutcome<T>, ReactorError>
    where
        T: Send + 'static,
        F: Fn(&T) -> usize,
    {
        let slot = self.resolve_slot(operation, expected)?;
        let mut guard = slot.lock();
        let Some(boxed_ref) = guard.as_ref() else {
            if self.cancelled.lock().contains(&operation) {
                drop(guard);
                self.finish_operation(operation);
                return Err(ReactorError::Cancelled(operation));
            }
            return Ok(TakeOutcome::Pending);
        };
        let result_ref = boxed_ref
            .downcast_ref::<Result<T, ReactorError>>()
            .ok_or_else(|| ReactorError::Other(anyhow::anyhow!("operation slot type mismatch")))?;
        if let Ok(value) = result_ref {
            let needed = len_of(value);
            if needed > capacity {
                return Ok(TakeOutcome::NeedsCapacity(needed));
            }
        }
        let Some(boxed) = guard.take() else { return Ok(TakeOutcome::Pending) };
        drop(guard);
        self.finish_operation(operation);
        let result = *boxed
            .downcast::<Result<T, ReactorError>>()
            .map_err(|_| ReactorError::Other(anyhow::anyhow!("operation slot type mismatch")))?;
        result.map(TakeOutcome::Ready)
    }

    /// HostAbiMap §9 `cancel_operation`: a no-op if `operation` is unknown, matching the
    /// a lookup miss. See the module doc for the abort+flag deviation from the context
    /// cancellation.
    pub fn cancel_operation(&self, operation: u64) {
        let found = {
            let operations = self.operations.lock();
            operations.get(&operation).map(|entry| (entry.cancel.clone(), entry.abort.clone()))
        };
        let Some((cancel, abort)) = found else { return };
        cancel.cancel();
        abort.abort();
        self.cancelled.lock().insert(operation);
        self.doorbell.notify_one();
    }

    /// HostAbiMap §9 `close`: probes streams, then datagrams, then listeners, closing whichever
    /// table owns `handle`.
    pub fn close(&self, handle: u64) -> Result<(), ReactorError> {
        let conn = self.streams.lock().remove(&handle);
        if let Some(conn) = conn {
            let closed = match (conn.read.try_lock(), conn.write.try_lock()) {
                (Ok(mut read), Ok(mut write)) => {
                    *read = None;
                    *write = None;
                    true
                }
                _ => false,
            };
            if !closed {
                self.runtime.spawn(async move {
                    *conn.read.lock().await = None;
                    *conn.write.lock().await = None;
                });
            }
            return Ok(());
        }
        let conn = self.datagrams.lock().remove(&handle);
        if let Some(conn) = conn {
            self.datagram_sends.lock().remove(&handle);
            let _ = conn.close();
            return Ok(());
        }
        let listener = self.listeners.lock().remove(&handle);
        if let Some(listener) = listener {
            let _ = listener.close();
            return Ok(());
        }
        Err(ReactorError::UnknownHandle(handle))
    }

    // ---- TCP connect (§2) ----

    pub fn start_tcp_connect(&self, operation: u64, options: platform::TCPConnectOptions) -> Result<(), ReactorError> {
        let services = Arc::clone(&self.services);
        let streams = Arc::clone(&self.streams);
        let next_handle = Arc::clone(&self.next_handle);
        self.claim_operation(operation, OperationKind::TcpConnect, move |cancel| async move {
            let conn = services.sockets.connect_tcp(&cancel, options).await?;
            let local = conn.local_addr()?;
            let peer = conn.remote_addr()?;
            let handle = next_handle.fetch_add(1, Ordering::Relaxed);
            streams.lock().insert(handle, Arc::new(StreamHandle::new(conn)));
            Ok(StreamResult { handle, local, peer })
        })
    }

    pub fn take_tcp_connect(&self, operation: u64) -> Result<TakeOutcome<StreamResult>, ReactorError> {
        self.take_simple(operation, OperationKind::TcpConnect)
    }

    // ---- TCP listen / bind (§2) ----

    pub fn start_tcp_listen(&self, operation: u64, options: platform::TCPListenOptions) -> Result<(), ReactorError> {
        let services = Arc::clone(&self.services);
        let listeners = Arc::clone(&self.listeners);
        let next_handle = Arc::clone(&self.next_handle);
        self.claim_operation(operation, OperationKind::TcpListen, move |cancel| async move {
            let listener = services.sockets.listen_tcp(&cancel, options).await?;
            let local = listener.addr()?;
            let handle = next_handle.fetch_add(1, Ordering::Relaxed);
            let listener: Arc<dyn Listener> = Arc::from(listener);
            listeners.lock().insert(handle, listener);
            Ok(BoundResult { handle, local })
        })
    }

    pub fn take_tcp_listen(&self, operation: u64) -> Result<TakeOutcome<BoundResult>, ReactorError> {
        self.take_simple(operation, OperationKind::TcpListen)
    }

    // ---- TCP accept (§3) ----

    pub fn start_tcp_accept(&self, operation: u64, listener_handle: u64) -> Result<(), ReactorError> {
        let listener =
            self.listeners.lock().get(&listener_handle).cloned().ok_or(ReactorError::UnknownHandle(listener_handle))?;
        let streams = Arc::clone(&self.streams);
        let next_handle = Arc::clone(&self.next_handle);
        self.claim_operation(operation, OperationKind::TcpAccept, move |_cancel| async move {
            let conn = listener.accept().await?;
            let local = conn.local_addr()?;
            let peer = conn.remote_addr()?;
            let handle = next_handle.fetch_add(1, Ordering::Relaxed);
            streams.lock().insert(handle, Arc::new(StreamHandle::new(conn)));
            Ok(StreamResult { handle, local, peer })
        })
    }

    pub fn take_tcp_accept(&self, operation: u64) -> Result<TakeOutcome<StreamResult>, ReactorError> {
        self.take_simple(operation, OperationKind::TcpAccept)
    }

    // ---- UDP bind (§2) ----

    pub fn start_udp_bind(&self, operation: u64, options: platform::UDPBindOptions) -> Result<(), ReactorError> {
        let services = Arc::clone(&self.services);
        let datagrams = Arc::clone(&self.datagrams);
        let datagram_sends = Arc::clone(&self.datagram_sends);
        let next_handle = Arc::clone(&self.next_handle);
        let runtime = self.runtime.clone();
        self.claim_operation(operation, OperationKind::UdpBind, move |cancel| async move {
            let conn: Box<dyn PacketConn> = services.sockets.bind_udp(&cancel, options).await?;
            let local = conn.local_addr()?;
            let handle = next_handle.fetch_add(1, Ordering::Relaxed);
            let conn: Arc<dyn PacketConn> = Arc::from(conn);
            datagrams.lock().insert(handle, Arc::clone(&conn));

            let (tx, mut rx) = mpsc::channel::<(Vec<u8>, Addr)>(64);
            let sticky_error = Arc::new(SyncMutex::new(None));
            let send_conn = Arc::clone(&conn);
            let send_sticky = Arc::clone(&sticky_error);
            runtime.spawn(async move {
                while let Some((data, peer)) = rx.recv().await {
                    if let Err(err) = send_conn.write_to(&data, peer.as_ref()).await {
                        *send_sticky.lock() = Some(ReactorError::Io(err));
                    }
                }
            });
            datagram_sends.lock().insert(handle, Arc::new(DatagramSend { tx, sticky_error }));

            Ok(BoundResult { handle, local })
        })
    }

    pub fn take_udp_bind(&self, operation: u64) -> Result<TakeOutcome<BoundResult>, ReactorError> {
        self.take_simple(operation, OperationKind::UdpBind)
    }

    // ---- stream read/write (§9) ----

    pub fn start_read(&self, operation: u64, handle: u64, capacity: usize) -> Result<(), ReactorError> {
        let conn = self.streams.lock().get(&handle).cloned().ok_or(ReactorError::UnknownHandle(handle))?;
        self.claim_operation(operation, OperationKind::Read, move |_cancel| async move {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; capacity];
            let mut guard = conn.read.lock().await;
            let Some(half) = guard.as_mut() else { return Err(closed_stream_error()) };
            let n = half.read(&mut buf).await?;
            drop(guard);
            buf.truncate(n);
            Ok(ReadResult { data: buf, eof: n == 0 })
        })
    }

    /// See the shared "buffer too small" note on [`TakeOutcome::NeedsCapacity`]: unlike
    /// [`Reactor::take_udp_recv`], an oversized result is never silently truncated here.
    pub fn take_read(&self, operation: u64, capacity: usize) -> Result<TakeOutcome<ReadResult>, ReactorError> {
        self.take_capacity_checked(operation, OperationKind::Read, capacity, |r: &ReadResult| r.data.len())
    }

    pub fn start_write(&self, operation: u64, handle: u64, data: Vec<u8>) -> Result<(), ReactorError> {
        let conn = self.streams.lock().get(&handle).cloned().ok_or(ReactorError::UnknownHandle(handle))?;
        self.claim_operation(operation, OperationKind::Write, move |_cancel| async move {
            use tokio::io::AsyncWriteExt;
            let mut guard = conn.write.lock().await;
            let Some(half) = guard.as_mut() else { return Err(closed_stream_error()) };
            half.write_all(&data).await?;
            drop(guard);
            Ok(data.len())
        })
    }

    pub fn take_write(&self, operation: u64) -> Result<TakeOutcome<usize>, ReactorError> {
        self.take_simple(operation, OperationKind::Write)
    }

    // ---- UDP recv/send (§5) ----

    pub fn start_udp_recv(&self, operation: u64, handle: u64) -> Result<(), ReactorError> {
        let conn = self.datagrams.lock().get(&handle).cloned().ok_or(ReactorError::UnknownHandle(handle))?;
        self.claim_operation(operation, OperationKind::UdpRecv, move |_cancel| async move {
            let mut buf = vec![0u8; UDP_RECEIVE_BUFFER_LEN];
            let (n, peer) = conn.read_from(&mut buf).await?;
            buf.truncate(n);
            Ok(UdpDatagram { data: buf, peer, truncated: false })
        })
    }

    /// the `take_udp_recv` silently truncates an oversized datagram to `capacity` instead of
    /// rejecting it (HostAbiMap §5) — the opposite policy from [`Reactor::take_read`].
    pub fn take_udp_recv(&self, operation: u64, capacity: usize) -> Result<TakeOutcome<UdpDatagram>, ReactorError> {
        match self.take_simple::<UdpDatagram>(operation, OperationKind::UdpRecv)? {
            TakeOutcome::Pending => Ok(TakeOutcome::Pending),
            TakeOutcome::NeedsCapacity(n) => Ok(TakeOutcome::NeedsCapacity(n)),
            TakeOutcome::Ready(mut datagram) => {
                if datagram.data.len() > capacity {
                    datagram.data.truncate(capacity);
                    datagram.truncated = true;
                }
                Ok(TakeOutcome::Ready(datagram))
            }
        }
    }

    /// HostAbiMap §5 `try_udp_send`: non-blocking bounded-queue enqueue, `ReactorError::WouldBlock`
    /// if the 64-slot queue is full.
    pub fn try_udp_send(&self, handle: u64, data: Vec<u8>, peer: Addr) -> Result<(), ReactorError> {
        let send = self.datagram_sends.lock().get(&handle).cloned().ok_or(ReactorError::UnknownHandle(handle))?;
        send.tx.try_send((data, peer)).map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => ReactorError::WouldBlock,
            mpsc::error::TrySendError::Closed(_) => ReactorError::UnknownHandle(handle),
        })
    }

    pub fn start_udp_send_ready(&self, operation: u64, handle: u64) -> Result<(), ReactorError> {
        let send = self.datagram_sends.lock().get(&handle).cloned().ok_or(ReactorError::UnknownHandle(handle))?;
        self.claim_operation(operation, OperationKind::UdpSend, move |_cancel| async move {
            if let Ok(permit) = send.tx.reserve().await {
                drop(permit);
            }
            let sticky_error = send.sticky_error.lock().take();
            match sticky_error {
                Some(err) => Err(err),
                None => Ok(()),
            }
        })
    }

    pub fn take_udp_send_ready(&self, operation: u64) -> Result<TakeOutcome<()>, ReactorError> {
        self.take_simple(operation, OperationKind::UdpSend)
    }

    // ---- DNS (§7) ----

    pub fn start_dns_resolve(&self, operation: u64, query: platform::DNSQuery) -> Result<(), ReactorError> {
        let services = Arc::clone(&self.services);
        self.claim_operation(operation, OperationKind::DnsResolve, move |cancel| async move {
            Ok(services.dns.lookup_ip(&cancel, query).await?)
        })
    }

    /// Peeks the finished lookup, so the guest's size probe does not
    /// consume it and the retry with the reported capacity still finds it.
    pub fn take_dns_resolve(&self, operation: u64, capacity: usize) -> Result<TakeOutcome<Vec<IpAddr>>, ReactorError> {
        self.take_capacity_checked(operation, OperationKind::DnsResolve, capacity, |addresses: &Vec<IpAddr>| {
            crate::wire::encode_dns_addresses(addresses).len()
        })
    }

    pub fn start_dns_txt(&self, operation: u64, query: platform::DNSQuery) -> Result<(), ReactorError> {
        let services = Arc::clone(&self.services);
        self.claim_operation(operation, OperationKind::DnsTxt, move |cancel| async move {
            Ok(services.dns.lookup_txt(&cancel, query).await?)
        })
    }

    /// See [`Reactor::take_dns_resolve`].
    pub fn take_dns_txt(&self, operation: u64, capacity: usize) -> Result<TakeOutcome<String>, ReactorError> {
        self.take_capacity_checked(operation, OperationKind::DnsTxt, capacity, |text: &String| {
            crate::wire::encode_dns_txt(text).len()
        })
    }

    pub fn start_dns_srv(&self, operation: u64, query: platform::DNSQuery) -> Result<(), ReactorError> {
        let services = Arc::clone(&self.services);
        self.claim_operation(operation, OperationKind::DnsSrv, move |cancel| async move {
            Ok(services.dns.lookup_srv(&cancel, query).await?)
        })
    }

    /// See [`Reactor::take_dns_resolve`].
    pub fn take_dns_srv(
        &self,
        operation: u64,
        capacity: usize,
    ) -> Result<TakeOutcome<Vec<platform::Srv>>, ReactorError> {
        self.take_capacity_checked(operation, OperationKind::DnsSrv, capacity, |records: &Vec<platform::Srv>| {
            crate::wire::encode_dns_srv(records).len()
        })
    }

    // ---- environment (§6) ----

    /// HostAbiMap §6: the wire always carries a non-optional remote address, so `remote` is
    /// always wrapped `Some(&remote)` when calling [`platform::ConnectorEnvironment`].
    pub fn start_local_addr_for_remote(
        &self,
        operation: u64,
        remote: UdpAddr,
        socket_context: platform::SocketContext,
    ) -> Result<(), ReactorError> {
        let services = Arc::clone(&self.services);
        self.claim_operation(operation, OperationKind::LocalAddrForRemote, move |cancel| async move {
            Ok(services.environment.local_addr_for_remote(&cancel, Some(&remote), socket_context).await?)
        })
    }

    pub fn take_local_addr_for_remote(&self, operation: u64) -> Result<TakeOutcome<Addr>, ReactorError> {
        self.take_simple(operation, OperationKind::LocalAddrForRemote)
    }

    // ---- management (§12) ----

    pub fn start_management_call(&self, operation: u64, request: Vec<u8>) -> Result<(), ReactorError> {
        let handler = self.management_handler.lock().clone().ok_or(ReactorError::ManagementHandlerNotConfigured)?;
        self.claim_operation(operation, OperationKind::Management, move |cancel| async move {
            Ok(handler(cancel, request).await)
        })
    }

    pub fn take_management_call(&self, operation: u64, capacity: usize) -> Result<TakeOutcome<Vec<u8>>, ReactorError> {
        self.take_capacity_checked(operation, OperationKind::Management, capacity, |v: &Vec<u8>| v.len())
    }

    // ---- event sink (§10) ----

    pub fn register_event_sink(&self, capacity: usize) -> (u64, mpsc::Receiver<(String, String)>) {
        let (tx, rx) = mpsc::channel(capacity);
        let handle = self.allocate_handle();
        self.event_sinks.lock().insert(handle, tx);
        (handle, rx)
    }

    pub fn unregister_event_sink(&self, handle: u64) {
        self.event_sinks.lock().remove(&handle);
    }

    pub fn emit_event(&self, handle: u64, kind: String, message: String) -> Result<(), ReactorError> {
        let sinks = self.event_sinks.lock();
        let tx = sinks.get(&handle).ok_or(ReactorError::UnknownHandle(handle))?;
        let result = tx.try_send((kind, message)).map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => ReactorError::WouldBlock,
            mpsc::error::TrySendError::Closed(_) => ReactorError::UnknownHandle(handle),
        });
        drop(sinks);
        result
    }

    // ---- packet sink (§13) ----

    pub fn register_packet_sink(&self, capacity: usize) -> (u64, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(capacity);
        let handle = self.allocate_handle();
        self.packet_sinks.lock().insert(handle, tx);
        (handle, rx)
    }

    pub fn unregister_packet_sink(&self, handle: u64) {
        self.packet_sinks.lock().remove(&handle);
    }

    pub fn try_packet_write(&self, handle: u64, packet: Vec<u8>) -> Result<(), ReactorError> {
        let sinks = self.packet_sinks.lock();
        let tx = sinks.get(&handle).ok_or(ReactorError::UnknownHandle(handle))?;
        let result = tx.try_send(packet).map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => ReactorError::WouldBlock,
            mpsc::error::TrySendError::Closed(_) => ReactorError::UnknownHandle(handle),
        });
        drop(sinks);
        result
    }

    pub fn start_packet_write_ready(&self, operation: u64, handle: u64) -> Result<(), ReactorError> {
        let tx = self.packet_sinks.lock().get(&handle).cloned().ok_or(ReactorError::UnknownHandle(handle))?;
        self.claim_operation(operation, OperationKind::PacketWriteReady, move |_cancel| async move {
            tx.reserve().await.map(drop).map_err(|_| ReactorError::UnknownHandle(handle))
        })
    }

    pub fn take_packet_write_ready(&self, operation: u64) -> Result<TakeOutcome<()>, ReactorError> {
        self.take_simple(operation, OperationKind::PacketWriteReady)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use async_trait::async_trait;

    use super::*;

    struct FakeDns;

    #[async_trait]
    impl platform::DNSResolver for FakeDns {
        async fn lookup_ip(&self, _ctx: &CancellationToken, _query: platform::DNSQuery) -> anyhow::Result<Vec<IpAddr>> {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))])
        }

        async fn lookup_txt(&self, _ctx: &CancellationToken, _query: platform::DNSQuery) -> anyhow::Result<String> {
            Ok(String::new())
        }

        async fn lookup_srv(
            &self,
            _ctx: &CancellationToken,
            _query: platform::DNSQuery,
        ) -> anyhow::Result<Vec<platform::Srv>> {
            Ok(Vec::new())
        }
    }

    struct FakeEnvironment;

    #[async_trait]
    impl platform::ConnectorEnvironment for FakeEnvironment {
        async fn local_addr_for_remote(
            &self,
            _ctx: &CancellationToken,
            _remote: Option<&UdpAddr>,
            _socket_context: platform::SocketContext,
        ) -> anyhow::Result<Box<dyn NetAddr>> {
            unreachable!("not exercised by this test's Reactor coverage")
        }
    }

    struct FakeSockets;

    #[async_trait]
    impl platform::SocketFactory for FakeSockets {
        async fn connect_tcp(
            &self,
            _ctx: &CancellationToken,
            _options: platform::TCPConnectOptions,
        ) -> anyhow::Result<Box<dyn Conn>> {
            unreachable!("not exercised by this test's Reactor coverage")
        }

        async fn bind_udp(
            &self,
            _ctx: &CancellationToken,
            _options: platform::UDPBindOptions,
        ) -> anyhow::Result<Box<dyn PacketConn>> {
            unreachable!("not exercised by this test's Reactor coverage")
        }

        async fn listen_tcp(
            &self,
            _ctx: &CancellationToken,
            _options: platform::TCPListenOptions,
        ) -> anyhow::Result<Box<dyn Listener>> {
            unreachable!("not exercised by this test's Reactor coverage")
        }
    }

    fn test_reactor() -> Reactor {
        Reactor::new(Arc::new(platform::Services {
            sockets: Arc::new(FakeSockets),
            dns: Arc::new(FakeDns),
            environment: Arc::new(FakeEnvironment),
            snapshot: platform::EnvironmentSnapshot::default(),
        }))
    }

    #[tokio::test]
    async fn double_claim_is_rejected() {
        let reactor = test_reactor();
        reactor.start_dns_resolve(1, platform::DNSQuery { host: "example.com".into(), ..Default::default() }).unwrap();
        let err = reactor.start_dns_resolve(1, platform::DNSQuery::default()).unwrap_err();
        assert!(matches!(err, ReactorError::AlreadyClaimed(1)));
    }

    #[tokio::test]
    async fn take_before_ready_is_pending_then_becomes_ready() {
        let reactor = test_reactor();
        reactor.start_dns_resolve(7, platform::DNSQuery { host: "example.com".into(), ..Default::default() }).unwrap();

        assert!(matches!(reactor.take_dns_resolve(7, 0).unwrap(), TakeOutcome::Pending));

        let doorbell = reactor.doorbell();
        tokio::time::timeout(Duration::from_secs(1), doorbell.notified())
            .await
            .expect("doorbell fires once the DNS task completes");

        match reactor.take_dns_resolve(7, 64).unwrap() {
            TakeOutcome::Ready(addrs) => assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]),
            other @ (TakeOutcome::Pending | TakeOutcome::NeedsCapacity(_)) => panic!("expected Ready, got {other:?}"),
        }

        // The slot is consumed: a second take on the same (now-unknown) operation id errors.
        assert!(matches!(reactor.take_dns_resolve(7, 64), Err(ReactorError::UnknownOperation(7))));
    }

    #[tokio::test]
    async fn dns_size_probe_reports_the_encoding_and_keeps_the_result() {
        let reactor = test_reactor();
        reactor.start_dns_resolve(9, platform::DNSQuery { host: "example.com".into(), ..Default::default() }).unwrap();
        tokio::time::timeout(Duration::from_secs(1), reactor.doorbell().notified())
            .await
            .expect("doorbell fires once the DNS task completes");

        // 4-byte count plus one 5-byte IPv4 entry, and the probe must not consume the lookup.
        assert!(matches!(reactor.take_dns_resolve(9, 0), Ok(TakeOutcome::NeedsCapacity(9))));
        match reactor.take_dns_resolve(9, 9).unwrap() {
            TakeOutcome::Ready(addrs) => assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]),
            other @ (TakeOutcome::Pending | TakeOutcome::NeedsCapacity(_)) => panic!("expected Ready, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn take_wrong_family_is_rejected() {
        let reactor = test_reactor();
        reactor.start_dns_resolve(3, platform::DNSQuery::default()).unwrap();
        let err = reactor.take_dns_txt(3, 0).unwrap_err();
        assert!(matches!(err, ReactorError::WrongOperationKind(3, OperationKind::DnsTxt)));
    }

    #[tokio::test]
    async fn cancel_unknown_operation_is_a_no_op() {
        let reactor = test_reactor();
        reactor.cancel_operation(999);
    }

    #[tokio::test]
    async fn cancel_operation_surfaces_cancelled_on_take() {
        let reactor = test_reactor();
        reactor.start_dns_resolve(11, platform::DNSQuery::default()).unwrap();
        reactor.cancel_operation(11);

        // The abort and the completion race; poll a couple of times to give the aborted task's
        // demise time to land before asserting the deterministic outcome.
        for _ in 0..50 {
            if matches!(reactor.take_dns_resolve(11, 0), Err(ReactorError::Cancelled(11))) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("cancelled operation never surfaced ReactorError::Cancelled");
    }

    #[tokio::test]
    async fn unknown_handle_is_rejected() {
        let reactor = test_reactor();
        let err = reactor.close(42).unwrap_err();
        assert!(matches!(err, ReactorError::UnknownHandle(42)));
    }

    #[tokio::test]
    async fn event_sink_backpressure_returns_would_block() {
        let reactor = test_reactor();
        let (handle, mut rx) = reactor.register_event_sink(1);
        reactor.emit_event(handle, "k".into(), "m".into()).unwrap();
        assert!(matches!(reactor.emit_event(handle, "k".into(), "m".into()), Err(ReactorError::WouldBlock)));
        let (kind, message) = rx.recv().await.unwrap();
        assert_eq!((kind.as_str(), message.as_str()), ("k", "m"));
    }
}

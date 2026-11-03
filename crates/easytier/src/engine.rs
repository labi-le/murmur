//! `wasmtime::Store` is `!Sync`, so this crate uses a single actor task owning the store.
//!
//! That task serialises every guest call and drives every live instance in turn through one loop.
//! Instance handles stay guest-side integers inside the shared module.
//!
//! Every instance-bound call is a command into that loop's mailbox. A blocking operation is
//! submitted, registered in a pending map, and fulfilled by the next completion drain — the
//! an operation-ticket dance, with `oneshot` in place of the buffered result channels.
//!
//! The loop runs on its own OS thread rather than as a Tokio task, because `wasmtime-wasi`'s
//! synchronous `wasi_snapshot_preview1` shim calls `Handle::block_on` from inside a host import
//! (`in_tokio`), which panics on a thread that already has a Tokio context.
//! Leaving the thread context-free lets that shim fall back to its own ambient runtime, while the
//! reactor spawns its real I/O on the embedder's runtime through an explicit `Handle`.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, ensure, Context as _, Result};
use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio_util::sync::CancellationToken;
use wasmtime::{Engine as WasmEngine, Linker, Module, Store};

use murmur_common_net::io::{Acceptor, Datagram, Stream};
use murmur_component_easytier::platform::platform::{EnvironmentSnapshot, Services};

use crate::artifact;
pub use crate::core_abi::State;
use crate::core_abi::{
    Completion, Core, DataPlaneError, ErrorKind, OperationKind, OperationResult, RpcResponse, MAX_DATA_PLANE_TRANSFER,
};
use crate::host_abi;
use crate::reactor::Reactor;
use crate::store::HostState;
use crate::wire::DataPlaneSocketAddr;

const DEFAULT_PACKET_QUEUE_CAPACITY: usize = 64;
const DATA_PLANE_COMPLETION_BATCH: u32 = 64;
const INSTANCE_EVENT_QUEUE_CAPACITY: usize = 256;
/// The "no deadline" sentinel for the data-plane timeout arguments.
const NO_DEADLINE: u64 = u64::MAX;
/// The sentinel for "the guest has no pending timer", `i64::MAX`.
const NO_TIMER: i64 = i64::MAX;

/// Engine construction parameters.
#[derive(Clone)]
pub struct Options {
    /// Platform capabilities the embedded EasyTier component needs. Unset fields would merge in
    /// defaults; this crate has no such fallback because the Rust trait objects are
    /// total, so the caller always supplies all three.
    pub services: Arc<Services>,
    /// Guest-to-host mesh packet egress queue depth. `0` selects [`DEFAULT_PACKET_QUEUE_CAPACITY`].
    pub packet_queue_capacity: usize,
}

impl core::fmt::Debug for Options {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Options").field("packet_queue_capacity", &self.packet_queue_capacity).finish_non_exhaustive()
    }
}

/// One best-effort notification emitted by an EasyTier instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// Stable snake-case core event variant name.
    pub kind: String,
    /// Human-readable description intended for logging.
    pub message: String,
}

/// Embeds one `easytier_core.wasm` module and drives every EasyTier instance inside it.
pub struct Host {
    shared: Arc<Shared>,
}

impl core::fmt::Debug for Host {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Host").finish_non_exhaustive()
    }
}

struct Shared {
    signals: std::sync::mpsc::Sender<Signal>,
    reactor: Arc<Reactor>,
    /// Kept so the synchronous teardown paths can dispatch even when they run off-runtime, where
    /// `Handle::current` would find nothing and the guest resource would leak until close.
    runtime: tokio::runtime::Handle,
}

/// The driver thread's only input. A doorbell poke and a command are the same message so one
/// `recv_timeout` can wait on both.
enum Signal {
    Command(Command),
    Doorbell,
}

/// Set while a doorbell poke is queued, so a burst of completions costs one message, matching
/// the buffered-1 completion channel.
#[derive(Default)]
struct DoorbellLatch(AtomicBool);

/// The submit half of a data-plane command, evaluated inside the actor where the store lives.
type SubmitFn = Box<dyn FnOnce(&mut Core, &mut Store<HostState>) -> Result<u64> + Send>;

enum DataPlaneRequest {
    Submit { kind: OperationKind, submit: SubmitFn },
    Cancel { operation: u64 },
    CloseResource { resource: u64 },
    SetDeadline { resource: u64, direction: u32, timeout_millis: u64 },
}

enum DataPlaneResponse {
    Submitted { operation: u64, ticket: oneshot::Receiver<Result<OperationResult>> },
    Done,
    Failed(anyhow::Error),
}

struct RpcSubmit {
    operation: u64,
    ticket: oneshot::Receiver<Result<Vec<u8>>>,
}

enum Command {
    CreateInstance { config_toml: String, reply: oneshot::Sender<Result<Instance>> },
    Start { key: usize, reply: oneshot::Sender<Result<()>> },
    Stop { key: usize, reply: oneshot::Sender<Result<()>> },
    SendPacket { key: usize, packet: Vec<u8>, reply: oneshot::Sender<Result<()>> },
    DataPlane { key: usize, request: DataPlaneRequest, reply: oneshot::Sender<DataPlaneResponse> },
    Rpc { key: usize, request: Vec<u8>, reply: oneshot::Sender<Result<RpcSubmit>> },
    RpcFree { key: usize, operation: u64, reply: oneshot::Sender<Result<()>> },
    CloseInstance { key: usize, reply: oneshot::Sender<Result<()>> },
    CloseHost { reply: oneshot::Sender<Result<()>> },
}

struct InstanceState {
    core: Core,
    state_tx: watch::Sender<State>,
    sinks: InstanceSinks,
    /// Why the driver gave up, when it did. The terminal error, which `Wait` and `Close` report;
    /// without it a guest that dies mid-drive reports only a bare "stopped".
    terminal: Arc<Mutex<Option<String>>>,
    done: CancellationToken,
    deadline_ms: i64,
}

/// The handles one instance registers with the [`Reactor`]; grouping them makes their release
/// the one call every teardown path has to make, an explicit close as much as a fatal guest error.
struct InstanceSinks {
    packet_sink: u64,
    event_sink: u64,
    packets: Option<Arc<TokioMutex<mpsc::Receiver<Vec<u8>>>>>,
    events: Arc<Mutex<Option<mpsc::Receiver<Event>>>>,
}

impl InstanceSinks {
    /// The host half of instance shutdown. Dropping the event receiver closes the event stream,
    /// and a closed stream is the only thing a reader can observe when
    /// an instance goes away: an outbound's `serve()` loop restarts on it, so a teardown that
    /// skips this strands the instance with no restart and no readiness signal ever sent.
    fn release(&mut self, reactor: &Reactor) {
        reactor.unregister_packet_sink(self.packet_sink);
        reactor.unregister_event_sink(self.event_sink);
        self.packets.take();
        self.events.lock().take();
    }
}

struct Actor {
    store: Store<HostState>,
    instance: wasmtime::Instance,
    shared: Arc<Shared>,
    snapshot: EnvironmentSnapshot,
    packet_capacity: usize,
    instances: Vec<Option<InstanceState>>,
    pending_ops: HashMap<(usize, u64), (OperationKind, oneshot::Sender<Result<OperationResult>>)>,
    pending_rpcs: HashMap<(usize, u64), oneshot::Sender<Result<Vec<u8>>>>,
    fatal: Option<anyhow::Error>,
    closing: bool,
}

impl Host {
    /// Compiles the embedded core once and spawns the actor that owns the store. Must run inside
    /// a Tokio runtime: the actor task and every host import need one. The handle is cheap to
    /// clone and safe to use from any task.
    pub fn new(options: Options) -> Result<Self> {
        let Options { services, packet_queue_capacity } = options;
        let capacity = if packet_queue_capacity == 0 { DEFAULT_PACKET_QUEUE_CAPACITY } else { packet_queue_capacity };
        let reactor = Arc::new(Reactor::new(Arc::clone(&services)));
        let runtime = tokio::runtime::Handle::current();
        let engine = WasmEngine::default();
        let module = Module::from_binary(&engine, artifact::CORE_WASM)
            .map_err(|err| anyhow!("compile embedded EasyTier core: {err}"))?;
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |state: &mut HostState| &mut state.wasi)
            .map_err(|err| anyhow!("instantiate WASI preview1: {err}"))?;
        host_abi::add_to_linker(&mut linker).context("instantiate EasyTier host ABI")?;
        let mut store = Store::new(&engine, HostState::new(Arc::clone(&reactor), runtime.clone()));
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|err| anyhow!("instantiate embedded EasyTier core: {err}"))?;
        let snapshot = services.snapshot.clone();

        let (signals, commands) = std::sync::mpsc::channel();
        let shared = Arc::new(Shared { signals, reactor, runtime: runtime.clone() });
        let actor = Actor {
            store,
            instance,
            shared: Arc::clone(&shared),
            snapshot,
            packet_capacity: capacity,
            instances: Vec::new(),
            pending_ops: HashMap::new(),
            pending_rpcs: HashMap::new(),
            fatal: None,
            closing: false,
        };
        let doorbell = shared.reactor.doorbell();
        let latch = Arc::new(DoorbellLatch::default());
        runtime.spawn(watch_doorbell(doorbell, shared.signals.clone(), Arc::clone(&latch)));
        std::thread::Builder::new()
            .name("easytier-guest".to_owned())
            .spawn(move || actor.run_blocking(&commands, &latch))
            .map_err(|err| anyhow!("spawn the EasyTier guest driver thread: {err}"))?;
        Ok(Self { shared })
    }

    /// The reactor backing every host import of this host's guest module.
    #[must_use]
    pub fn reactor(&self) -> &Arc<Reactor> {
        &self.shared.reactor
    }

    /// Creates an instance from an already-rendered EasyTier TOML document.
    pub async fn create_instance(&self, config_toml: String) -> Result<Instance> {
        let (reply, response) = oneshot::channel();
        self.shared
            .signals
            .send(Signal::Command(Command::CreateInstance { config_toml, reply }))
            .map_err(|_| anyhow!("easytier engine host is closed"))?;
        response.await.map_err(|_| anyhow!("easytier engine host is closed"))?
    }

    /// Closes every instance, then tears the guest module down.
    pub async fn close(&self) -> Result<()> {
        let (reply, response) = oneshot::channel();
        if self.shared.signals.send(Signal::Command(Command::CloseHost { reply })).is_err() {
            return Ok(());
        }
        response.await.map_err(|_| anyhow!("easytier engine host is closed"))?
    }
}

impl Actor {
    /// Drives the guest from a thread with no Tokio context, blocking on the signal channel until
    /// the next command, doorbell poke, or instance deadline.
    fn run_blocking(mut self, commands: &std::sync::mpsc::Receiver<Signal>, latch: &DoorbellLatch) {
        loop {
            let deadline = self.earliest_deadline();
            let signal = if deadline == 0 {
                std::thread::yield_now();
                match commands.try_recv() {
                    Ok(signal) => Ok(signal),
                    Err(std::sync::mpsc::TryRecvError::Empty) => Ok(Signal::Doorbell),
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => Err(()),
                }
            } else {
                match commands.recv_timeout(deadline_to_wait(deadline)) {
                    Ok(signal) => Ok(signal),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(Signal::Doorbell),
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(()),
                }
            };
            match signal {
                Ok(Signal::Command(command)) => {
                    latch.0.store(false, Ordering::SeqCst);
                    self.dispatch(command);
                }
                Ok(Signal::Doorbell) => {
                    latch.0.store(false, Ordering::SeqCst);
                    self.drive_all(true);
                }
                Err(()) => break,
            }
            if self.closing {
                break;
            }
            if let Some(err) = self.fatal.take() {
                self.fail(&err.to_string());
                break;
            }
        }
        self.fail("easytier engine host stopped");
    }

    fn dispatch(&mut self, command: Command) {
        match command {
            Command::CreateInstance { config_toml, reply } => {
                let _ = reply.send(self.create_instance_inner(&config_toml));
            }
            Command::Start { key, reply } => {
                let _ = reply.send(self.run_core_command(key, Core::start));
            }
            Command::Stop { key, reply } => {
                let _ = reply.send(self.run_core_command(key, Core::stop));
            }
            Command::SendPacket { key, packet, reply } => {
                let _ = reply.send(self.run_core_command(key, |core, store| core.send_packet(store, &packet)));
            }
            Command::DataPlane { key, request, reply } => {
                let _ = reply.send(self.handle_data_plane(key, request));
            }
            Command::Rpc { key, request, reply } => {
                let _ = reply.send(self.handle_rpc_submit(key, &request));
            }
            Command::RpcFree { key, operation, reply } => {
                let _ = reply.send(self.handle_rpc_free(key, operation));
            }
            Command::CloseInstance { key, reply } => {
                let _ = reply.send(self.close_instance(key));
            }
            Command::CloseHost { reply } => {
                self.closing = true;
                let mut first = Ok(());
                for key in self.live_keys() {
                    if let Err(err) = self.close_instance(key) {
                        if first.is_ok() {
                            first = Err(err);
                        }
                    }
                }
                let _ = reply.send(first);
            }
        }
    }

    /// Command handling plus the `drive(false)` that follows every answered command.
    fn run_core_command(
        &mut self,
        key: usize,
        f: impl Fn(&mut Core, &mut Store<HostState>) -> Result<()>,
    ) -> Result<()> {
        let Self { store, instances, .. } = self;
        let state = live_state(instances, key)?;
        f(&mut state.core, store)?;
        self.drive_instance(key, false)
    }

    fn create_instance_inner(&mut self, config_toml: &str) -> Result<Instance> {
        ensure!(!self.closing, "create instance on closed EasyTier engine host");
        let key = self.instances.len();
        let envelope = encode_create_envelope(config_toml, &self.snapshot)?;
        let reactor = Arc::clone(&self.store.data().reactor);
        let (packet_sink, packets) = reactor.register_packet_sink(self.packet_capacity);
        let (event_sink, mut sink_events) = reactor.register_event_sink(INSTANCE_EVENT_QUEUE_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(INSTANCE_EVENT_QUEUE_CAPACITY);
        self.store.data().runtime.spawn(async move {
            while let Some((kind, message)) = sink_events.recv().await {
                if event_tx.send(Event { kind, message }).await.is_err() {
                    break;
                }
            }
        });
        let events = Arc::new(Mutex::new(Some(event_rx)));
        let mut core =
            Core::new(&mut self.store, &self.instance).map_err(|err| anyhow!("create EasyTier guest core: {err:#}"))?;
        if let Err(err) = core.create(&mut self.store, &envelope, packet_sink, event_sink) {
            reactor.unregister_packet_sink(packet_sink);
            reactor.unregister_event_sink(event_sink);
            return Err(err);
        }
        let (state_tx, state_rx) = watch::channel(State::Created);
        let done = CancellationToken::new();
        let packets = Arc::new(TokioMutex::new(packets));
        let terminal = Arc::new(Mutex::new(None));
        self.instances.push(Some(InstanceState {
            core,
            state_tx,
            sinks: InstanceSinks {
                packet_sink,
                event_sink,
                packets: Some(Arc::clone(&packets)),
                events: Arc::clone(&events),
            },
            terminal: Arc::clone(&terminal),
            done: done.clone(),
            deadline_ms: NO_TIMER,
        }));
        let inner = Arc::new(InstanceHandle {
            shared: Arc::clone(&self.shared),
            key,
            state_rx,
            done,
            packets,
            events,
            terminal,
        });
        Ok(Instance { inner })
    }

    fn handle_data_plane(&mut self, key: usize, request: DataPlaneRequest) -> DataPlaneResponse {
        match request {
            DataPlaneRequest::Submit { kind, submit } => self.submit_operation(key, kind, submit),
            DataPlaneRequest::Cancel { operation } => {
                if self.pending_ops.contains_key(&(key, operation)) {
                    self.plain_operation(key, |state, store| state.core.cancel_operation(store, operation))
                } else {
                    DataPlaneResponse::Done
                }
            }
            DataPlaneRequest::CloseResource { resource } => {
                self.plain_operation(key, |state, store| state.core.close_resource(store, resource))
            }
            DataPlaneRequest::SetDeadline { resource, direction, timeout_millis } => self
                .plain_operation(key, |state, store| {
                    state.core.set_resource_deadline(store, resource, direction, timeout_millis)
                }),
        }
    }

    fn submit_operation(&mut self, key: usize, kind: OperationKind, submit: SubmitFn) -> DataPlaneResponse {
        let Self { store, instances, .. } = self;
        let operation = match live_state(instances, key).and_then(|state| submit(&mut state.core, store)) {
            Ok(operation) => operation,
            Err(err) => return DataPlaneResponse::Failed(err),
        };
        let (tx, ticket) = oneshot::channel();
        self.pending_ops.insert((key, operation), (kind, tx));
        if let Err(err) = self.drive_instance(key, false) {
            self.pending_ops.remove(&(key, operation));
            return DataPlaneResponse::Failed(err);
        }
        DataPlaneResponse::Submitted { operation, ticket }
    }

    fn plain_operation(
        &mut self,
        key: usize,
        f: impl FnOnce(&mut InstanceState, &mut Store<HostState>) -> Result<()>,
    ) -> DataPlaneResponse {
        let Self { store, instances, .. } = self;
        match live_state(instances, key).and_then(|state| f(state, store)) {
            Ok(()) => DataPlaneResponse::Done,
            Err(err) => DataPlaneResponse::Failed(err),
        }
    }

    fn handle_rpc_submit(&mut self, key: usize, request: &[u8]) -> Result<RpcSubmit> {
        let Self { store, instances, .. } = self;
        let operation = live_state(instances, key)?.core.submit_rpc(store, request)?;
        let (tx, ticket) = oneshot::channel();
        self.pending_rpcs.insert((key, operation), tx);
        self.drive_instance(key, false)?;
        Ok(RpcSubmit { operation, ticket })
    }

    fn handle_rpc_free(&mut self, key: usize, operation: u64) -> Result<()> {
        if self.pending_rpcs.remove(&(key, operation)).is_none() {
            return Ok(());
        }
        let Self { store, instances, .. } = self;
        live_state(instances, key)?.core.free_rpc_operation(store, operation)
    }

    fn live_keys(&self) -> Vec<usize> {
        self.instances.iter().enumerate().filter_map(|(key, state)| state.is_some().then_some(key)).collect()
    }

    fn drive_all(&mut self, notify: bool) {
        for key in self.live_keys() {
            if let Err(err) = self.drive_instance(key, notify) {
                self.fatal = Some(err);
                return;
            }
        }
    }

    /// advance the guest, then harvest whatever it finished. A full
    /// completion batch forces deadline 0 so the next loop iteration drains again immediately.
    fn drive_instance(&mut self, key: usize, notify: bool) -> Result<()> {
        {
            let Self { store, instances, .. } = self;
            let state = live_state(instances, key)?;
            if notify {
                state.core.notify_completions(store)?;
            }
            let next_state = state.core.drive(store)?;
            let _ = state.state_tx.send(next_state);
        }
        let more = self.drain_completions(key)?;
        self.take_rpc_responses(key)?;
        let Self { store, instances, .. } = self;
        let state = live_state(instances, key)?;
        let deadline = state.core.next_deadline_millis(store)?;
        let deadline = if more { 0 } else { deadline };
        state.deadline_ms = deadline;
        Ok(())
    }

    fn earliest_deadline(&self) -> i64 {
        self.instances.iter().flatten().map(|state| state.deadline_ms).min().unwrap_or(NO_TIMER)
    }

    fn drain_completions(&mut self, key: usize) -> Result<bool> {
        if !self.pending_ops.keys().any(|(pending, _)| *pending == key) {
            return Ok(false);
        }
        let completions = {
            let Self { store, instances, .. } = self;
            live_state(instances, key)?.core.drain_completions(store, DATA_PLANE_COMPLETION_BATCH)?
        };
        let full = completions.len() == DATA_PLANE_COMPLETION_BATCH as usize;
        for completion in completions {
            let Some((kind, tx)) = self.pending_ops.remove(&(key, completion.operation)) else {
                return Err(anyhow!("EasyTier completed unknown data plane operation {}", completion.operation));
            };
            if kind != completion.kind {
                return Err(anyhow!(
                    "EasyTier completed operation {} as kind {:?}, want {kind:?}",
                    completion.operation,
                    completion.kind
                ));
            }
            let outcome = self.take_result(key, &completion);
            let _ = tx.send(outcome);
        }
        Ok(full)
    }

    fn take_result(&mut self, key: usize, completion: &Completion) -> Result<OperationResult> {
        let taken = {
            let Self { store, instances, .. } = self;
            live_state(instances, key)?.core.take_result(store, *completion)
        };
        match (completion.status, taken) {
            (ErrorKind::None, result) => result,
            (status, Err(err)) => {
                let reported = err
                    .downcast_ref::<DataPlaneError>()
                    .map(|data_plane| (data_plane.kind, data_plane.message.clone()));
                match reported {
                    Some((kind, message)) if kind == status => {
                        Err(anyhow::Error::new(DataPlaneError { kind, message }))
                    }
                    _ => Err(anyhow!(
                        "data plane operation {} status {status:?} disagrees with result: {err:#}",
                        completion.operation
                    )),
                }
            }
            (status, Ok(_)) => {
                Err(anyhow!("data plane operation {} reported {status:?} but took a result", completion.operation))
            }
        }
    }

    fn take_rpc_responses(&mut self, key: usize) -> Result<()> {
        let operations: Vec<u64> =
            self.pending_rpcs.keys().filter(|(pending, _)| *pending == key).map(|(_, operation)| *operation).collect();
        for operation in operations {
            let taken = {
                let Self { store, instances, .. } = self;
                live_state(instances, key)?.core.take_rpc_response(store, operation)?
            };
            let RpcResponse::Ready(response) = taken else {
                continue;
            };
            if let Some(tx) = self.pending_rpcs.remove(&(key, operation)) {
                let _ = tx.send(Ok(response));
            }
        }
        Ok(())
    }

    fn close_instance(&mut self, key: usize) -> Result<()> {
        let Some(mut state) = self.instances.get_mut(key).and_then(Option::take) else {
            return Ok(());
        };
        let reactor = Arc::clone(&self.store.data().reactor);
        let outcome = state.core.drop_instance(&mut self.store);
        // The run loop stores StateStopped before its shutdown half, so whatever the close
        // wakes must not be left observing the last state the guest happened to report.
        let _ = state.state_tx.send(State::Stopped);
        state.sinks.release(&reactor);
        state.done.cancel();
        outcome
    }

    /// The run loop's tail for a guest that died under the driver: the same teardown an
    /// explicit close performs, minus the instance drop this crate cannot safely make once the
    /// guest is already failing — the module is discarded moments later either way.
    fn fail(&mut self, reason: &str) {
        let reactor = Arc::clone(&self.store.data().reactor);
        for slot in &mut self.instances {
            let Some(mut state) = slot.take() else { continue };
            *state.terminal.lock() = Some(reason.to_owned());
            state.done.cancel();
            let _ = state.state_tx.send(State::Stopped);
            state.sinks.release(&reactor);
        }
        for (_, (_, tx)) in self.pending_ops.drain() {
            let _ = tx.send(Err(anyhow!("{reason}")));
        }
        for (_, tx) in self.pending_rpcs.drain() {
            let _ = tx.send(Err(anyhow!("{reason}")));
        }
    }
}

fn live_state(instances: &mut [Option<InstanceState>], key: usize) -> Result<&mut InstanceState> {
    instances.get_mut(key).and_then(Option::as_mut).ok_or_else(|| anyhow!("easytier instance is closed"))
}

/// The `i64::MAX` sentinel means "no timer armed", which the blocking loop expresses as an
/// unbounded wait.
fn deadline_to_wait(deadline: i64) -> Duration {
    match deadline {
        0 => Duration::ZERO,
        millis if millis > 0 && millis < NO_TIMER => Duration::from_millis(millis.unsigned_abs()),
        _ => Duration::from_secs(u64::MAX / 2),
    }
}

/// The data-plane transfer length to ask for when `requested` bytes are wanted.
fn transfer_capacity(requested: usize) -> u32 {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the value is clamped to MAX_DATA_PLANE_TRANSFER (1 MiB), which fits the ABI's u32 length field"
    )]
    let capacity = requested.min(MAX_DATA_PLANE_TRANSFER) as u32;
    capacity
}

/// Forwards reactor completions to the driver thread's blocking channel, coalescing a burst of
/// completions into one wakeup the way the buffered-1 doorbell does.
async fn watch_doorbell(doorbell: Arc<Notify>, signals: std::sync::mpsc::Sender<Signal>, latch: Arc<DoorbellLatch>) {
    loop {
        doorbell.notified().await;
        if !latch.0.swap(true, Ordering::SeqCst) && signals.send(Signal::Doorbell).is_err() {
            return;
        }
    }
}

struct InstanceHandle {
    shared: Arc<Shared>,
    key: usize,
    state_rx: watch::Receiver<State>,
    done: CancellationToken,
    packets: Arc<TokioMutex<mpsc::Receiver<Vec<u8>>>>,
    events: Arc<Mutex<Option<mpsc::Receiver<Event>>>>,
    terminal: Arc<Mutex<Option<String>>>,
}

/// One EasyTier instance inside the host's guest module.
#[derive(Clone)]
pub struct Instance {
    inner: Arc<InstanceHandle>,
}

impl core::fmt::Debug for Instance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Instance").field("key", &self.inner.key).finish_non_exhaustive()
    }
}

impl Instance {
    /// Last state the guest reported.
    #[must_use]
    pub fn state(&self) -> State {
        *self.inner.state_rx.borrow()
    }

    /// Why the driver gave up, once it has. `None` while the instance is healthy or after a close
    /// the guest accepted.
    #[must_use]
    pub fn terminal_error(&self) -> Option<String> {
        self.inner.terminal.lock().clone()
    }

    /// `": reason"` suffix for an error message, empty when the driver gave up cleanly.
    fn terminal_reason(&self) -> String {
        self.terminal_error().map(|reason| format!(": {reason}")).unwrap_or_default()
    }

    /// Takes the event stream. `None` once a previous caller took it or the instance closed.
    #[must_use]
    pub fn events(&self) -> Option<mpsc::Receiver<Event>> {
        self.inner.events.lock().take()
    }

    /// Starts the instance and waits until the guest reports [`State::Running`].
    pub async fn start(&self, ctx: &CancellationToken) -> Result<()> {
        self.command(ctx, |reply| Command::Start { key: self.inner.key, reply }).await?;
        self.wait_for_state(ctx, State::Running).await
    }

    /// Stops the instance and waits until the guest reports [`State::Stopped`].
    pub async fn stop(&self, ctx: &CancellationToken) -> Result<()> {
        self.command(ctx, |reply| Command::Stop { key: self.inner.key, reply }).await?;
        self.wait_for_state(ctx, State::Stopped).await
    }

    /// Hands one mesh packet to the guest's packet ingress.
    pub async fn send_packet(&self, ctx: &CancellationToken, packet: Vec<u8>) -> Result<()> {
        ensure!(!packet.is_empty(), "send empty packet");
        self.command(ctx, |reply| Command::SendPacket { key: self.inner.key, packet, reply }).await
    }

    /// Waits for the instance to stop or for the host to die.
    // cancel-safe: waits on a level-triggered notification and re-checks the state before parking, so a dropped wait misses nothing -- the next call re-reads the same state.
    pub async fn wait(&self, ctx: &CancellationToken) -> Result<()> {
        self.wait_for_state(ctx, State::Stopped).await
    }

    /// Takes the next decrypted mesh packet the guest wrote out of its packet sink.
    pub async fn receive_packet(&self, ctx: &CancellationToken) -> Result<Vec<u8>> {
        let mut packets = self.inner.packets.lock().await;
        let packet = tokio::select! {
            packet = packets.recv() => packet,
            () = ctx.cancelled() => return Err(anyhow!("context canceled")),
            () = self.inner.done.cancelled() => return Err(anyhow!("easytier instance is closed")),
        };
        drop(packets);
        packet.ok_or_else(|| anyhow!("easytier packet sink is closed"))
    }

    /// Issues one EasyTier management RPC and returns the raw response payload.
    pub async fn rpc(&self, ctx: &CancellationToken, request: Vec<u8>) -> Result<Vec<u8>> {
        let (tx, response) = oneshot::channel();
        self.inner
            .shared
            .signals
            .send(Signal::Command(Command::Rpc { key: self.inner.key, request, reply: tx }))
            .map_err(|_| anyhow!("easytier instance is closed"))?;
        let submitted = tokio::select! {
            value = response => value.map_err(|_| anyhow!("easytier instance is closed"))??,
            () = self.inner.done.cancelled() => return Err(anyhow!("easytier instance is closed")),
        };
        let RpcSubmit { operation, mut ticket } = submitted;
        if let Ok(value) = ticket.try_recv() {
            return value;
        }
        tokio::select! {
            value = &mut ticket => value.map_err(|_| anyhow!("easytier RPC operation vanished")).and_then(|value| value),
            () = ctx.cancelled() => {
                self.free_rpc(operation).await?;
                // the freeRPCAndWait ends in a `default:` arm, so a freed operation that produced
                // no response reports the caller's cancellation. Blocking here instead strands the
                // caller forever on a ticket the guest was just told to drop.
                ticket.try_recv().unwrap_or_else(|_| Err(anyhow!("context canceled")))
            }
            () = self.inner.done.cancelled() => Err(anyhow!("easytier instance is closed")),
        }
    }

    /// Opens a TCP stream to an overlay IPv4 peer. A [`CancellationToken`] carries no deadline, so
    /// the guest is left unbounded and the caller bounds the attempt by cancelling.
    pub async fn dial(&self, ctx: &CancellationToken, peer: DataPlaneSocketAddr) -> Result<StreamConn> {
        let result = self
            .perform_operation(
                ctx,
                OperationKind::TcpConnect,
                Box::new(move |core, store| core.submit_tcp_connect(store, peer, NO_DEADLINE)),
            )
            .await?;
        Ok(StreamConn::new(self.clone(), &result))
    }

    /// Opens a connected UDP socket to an overlay IPv4 peer.
    pub async fn dial_udp(&self, ctx: &CancellationToken, peer: DataPlaneSocketAddr) -> Result<DatagramConn> {
        let result = self
            .perform_operation(
                ctx,
                OperationKind::UdpBind,
                Box::new(|core, store| core.submit_udp_bind(store, 0, NO_DEADLINE)),
            )
            .await?;
        Ok(DatagramConn {
            instance: self.clone(),
            packet: PacketConn::new(self.clone(), &result),
            peer: socket_addr(peer),
            read_slot: Mutex::new(None),
            write_slot: Mutex::new(None),
        })
    }

    /// Binds an overlay TCP listener on `port`.
    pub async fn listen(&self, port: u16) -> Result<StreamListener> {
        let result = self
            .perform_operation(
                &CancellationToken::new(),
                OperationKind::TcpBind,
                Box::new(move |core, store| core.submit_tcp_bind(store, port, NO_DEADLINE)),
            )
            .await?;
        Ok(StreamListener {
            instance: self.clone(),
            resource: result.resource,
            local: socket_addr(result.local),
            closed: AtomicBool::new(false),
        })
    }

    /// Binds an overlay UDP socket on `port`.
    pub async fn listen_packet(&self, port: u16) -> Result<PacketConn> {
        let result = self
            .perform_operation(
                &CancellationToken::new(),
                OperationKind::UdpBind,
                Box::new(move |core, store| core.submit_udp_bind(store, port, NO_DEADLINE)),
            )
            .await?;
        Ok(PacketConn::new(self.clone(), &result))
    }

    /// Releases the instance's guest resources and unregisters its sinks.
    pub async fn close(&self) -> Result<()> {
        let (tx, response) = oneshot::channel();
        if self
            .inner
            .shared
            .signals
            .send(Signal::Command(Command::CloseInstance { key: self.inner.key, reply: tx }))
            .is_err()
        {
            return Ok(());
        }
        response.await.unwrap_or(Ok(()))
    }

    async fn udp_receive(&self, resource: u64, maximum: u32) -> Result<(Vec<u8>, SocketAddr, bool)> {
        let result = self
            .perform_operation(
                &CancellationToken::new(),
                OperationKind::UdpReceive,
                Box::new(move |core, store| core.submit_udp_receive(store, resource, maximum)),
            )
            .await?;
        Ok((result.data, socket_addr(result.peer), result.truncated))
    }

    async fn udp_send(&self, resource: u64, peer: DataPlaneSocketAddr, payload: Vec<u8>) -> Result<usize> {
        let result = self
            .perform_operation(
                &CancellationToken::new(),
                OperationKind::UdpSend,
                Box::new(move |core, store| core.submit_udp_send(store, resource, peer, &payload)),
            )
            .await?;
        Ok(result.length)
    }

    async fn command(
        &self,
        ctx: &CancellationToken,
        build: impl FnOnce(oneshot::Sender<Result<()>>) -> Command,
    ) -> Result<()> {
        let (tx, response) = oneshot::channel();
        self.inner
            .shared
            .signals
            .send(Signal::Command(build(tx)))
            .map_err(|_| anyhow!("easytier instance is closed"))?;
        tokio::select! {
            value = response => value.map_err(|_| anyhow!("easytier instance is closed"))?,
            () = ctx.cancelled() => Err(anyhow!("context canceled")),
            () = self.inner.done.cancelled() => Err(anyhow!("easytier instance is closed")),
        }
    }

    async fn wait_for_state(&self, ctx: &CancellationToken, target: State) -> Result<()> {
        let mut state_rx = self.inner.state_rx.clone();
        tokio::select! {
            outcome = state_rx.wait_for(|state| *state == target) => {
                outcome.map_err(|_| anyhow!("easytier instance is closed"))?;
                Ok(())
            }
            () = ctx.cancelled() => Err(anyhow!("context canceled")),
            () = self.inner.done.cancelled() => {
                let current = self.state();
                if current == target {
                    return Ok(());
                }
                Err(anyhow!("easytier instance stopped in state {current:?}{}", self.terminal_reason()))
            }
        }
    }

    async fn free_rpc(&self, operation: u64) -> Result<()> {
        let (tx, response) = oneshot::channel();
        self.inner
            .shared
            .signals
            .send(Signal::Command(Command::RpcFree { key: self.inner.key, operation, reply: tx }))
            .map_err(|_| anyhow!("easytier instance is closed"))?;
        response.await.map_err(|_| anyhow!("easytier instance is closed"))?
    }

    async fn perform_operation(
        &self,
        ctx: &CancellationToken,
        kind: OperationKind,
        submit: SubmitFn,
    ) -> Result<OperationResult> {
        let (tx, response) = oneshot::channel();
        self.inner
            .shared
            .signals
            .send(Signal::Command(Command::DataPlane {
                key: self.inner.key,
                request: DataPlaneRequest::Submit { kind, submit },
                reply: tx,
            }))
            .map_err(|_| anyhow!("easytier instance is closed"))?;
        let (operation, mut ticket) = tokio::select! {
            value = response => match value.map_err(|_| anyhow!("easytier instance is closed"))? {
                DataPlaneResponse::Submitted { operation, ticket } => (operation, ticket),
                DataPlaneResponse::Done => return Err(anyhow!("easytier data plane submit answered without a ticket")),
                DataPlaneResponse::Failed(err) => return Err(err),
            },
            () = self.inner.done.cancelled() => return Err(anyhow!("easytier instance is closed")),
        };
        if let Ok(value) = ticket.try_recv() {
            return value;
        }
        tokio::select! {
            value = &mut ticket => value.map_err(|_| anyhow!("easytier data plane operation vanished")).and_then(|value| value),
            () = ctx.cancelled() => self.cancel_and_wait(operation, ticket).await,
            () = self.inner.done.cancelled() => Err(anyhow!("easytier instance is closed")),
        }
    }

    /// Cancels and waits: a cancelled caller still has to see the operation's real outcome,
    /// because the guest may have completed it in the same tick as the cancel.
    async fn cancel_and_wait(
        &self,
        operation: u64,
        mut ticket: oneshot::Receiver<Result<OperationResult>>,
    ) -> Result<OperationResult> {
        let (tx, response) = oneshot::channel();
        self.inner
            .shared
            .signals
            .send(Signal::Command(Command::DataPlane {
                key: self.inner.key,
                request: DataPlaneRequest::Cancel { operation },
                reply: tx,
            }))
            .map_err(|_| anyhow!("easytier instance is closed"))?;
        tokio::select! {
            value = &mut ticket => cancelled_outcome(value),
            acknowledged = response => {
                if let Ok(DataPlaneResponse::Failed(err)) = acknowledged {
                    return Err(err);
                }
                tokio::select! {
                    value = &mut ticket => cancelled_outcome(value),
                    () = self.inner.done.cancelled() => Err(anyhow!("easytier instance is closed")),
                }
            }
            () = self.inner.done.cancelled() => Err(anyhow!("easytier instance is closed")),
        }
    }

    /// Sets a deadline on the stream and its read/write halves. `common_net::io::Stream` carries no
    /// deadline setters, so the overlay ABI's deadline primitive is reachable only from here.
    /// `timeout_millis` of `u64::MAX` clears the deadline.
    pub fn set_resource_deadline(&self, resource: u64, direction: u32, timeout_millis: u64) {
        self.fire_and_forget(DataPlaneRequest::SetDeadline { resource, direction, timeout_millis });
    }

    /// The teardown and deadline paths run from synchronous `close`/`shutdown_*` methods that
    /// cannot await, so the command is dispatched on the actor and its result dropped.
    fn fire_and_forget(&self, request: DataPlaneRequest) {
        let runtime = self.inner.shared.runtime.clone();
        let shared = Arc::clone(&self.inner.shared);
        let key = self.inner.key;
        runtime.spawn(async move {
            let (tx, response) = oneshot::channel();
            if shared.signals.send(Signal::Command(Command::DataPlane { key, request, reply: tx })).is_err() {
                return;
            }
            let _ = response.await;
        });
    }
}

fn cancelled_outcome(
    outcome: std::result::Result<Result<OperationResult>, oneshot::error::RecvError>,
) -> Result<OperationResult> {
    let outcome = outcome.map_err(|_| anyhow!("easytier data plane operation vanished"))?;
    match &outcome {
        Err(err) if err.downcast_ref::<DataPlaneError>().is_some_and(|dp| dp.kind == ErrorKind::Cancelled) => {
            Err(anyhow!("context canceled"))
        }
        _ => outcome,
    }
}

fn socket_addr(addr: DataPlaneSocketAddr) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(addr.ip), addr.port)
}

/// Maps a guest data-plane error kind onto the closest `std::io::ErrorKind`. Kinds with no Rust
/// equivalent keep `Other` and the guest's own message rather than borrowing a misleading kind.
fn io_error(err: &DataPlaneError) -> io::Error {
    let kind = match err.kind {
        ErrorKind::Cancelled => io::ErrorKind::Interrupted,
        ErrorKind::DeadlineExceeded => io::ErrorKind::TimedOut,
        ErrorKind::InstanceStopped | ErrorKind::HandleClosed => io::ErrorKind::NotConnected,
        ErrorKind::NoOverlayRoute | ErrorKind::PathNotReady => io::ErrorKind::NetworkUnreachable,
        ErrorKind::AddressFamilyUnsupported => io::ErrorKind::Unsupported,
        ErrorKind::AddressInUse => io::ErrorKind::AddrInUse,
        ErrorKind::ConnectionRefused => io::ErrorKind::ConnectionRefused,
        ErrorKind::NetworkChanged => io::ErrorKind::ConnectionReset,
        ErrorKind::BufferTooSmall => io::ErrorKind::InvalidInput,
        ErrorKind::None | ErrorKind::Io | ErrorKind::ResourceLimit => io::ErrorKind::Other,
    };
    let message = if err.message.is_empty() { format!("data plane error {:?}", err.kind) } else { err.message.clone() };
    io::Error::new(kind, message)
}

fn to_io_error(err: &anyhow::Error) -> io::Error {
    match err.downcast_ref::<DataPlaneError>() {
        Some(data_plane) => io_error(data_plane),
        None => io::Error::other(err.to_string()),
    }
}

/// A guest data-plane future driven directly from `poll_read`/`poll_write`. Keeping it in the
/// slot between polls is what makes a read that outlives one `poll` legal.
type Pending<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

/// Creates the future when the slot is empty, polls it, and clears it once ready. A caller that
/// drops the stream mid-poll leaves the future to be dropped with the slot.
fn poll_pending<T: Send + 'static>(
    slot: &Mutex<Option<Pending<T>>>,
    start: impl FnOnce() -> Pending<T>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<T>> {
    let mut guard = slot.lock();
    if guard.is_none() {
        *guard = Some(start());
    }
    let Some(future) = guard.as_mut() else {
        return Poll::Ready(Err(io::Error::other("easytier operation slot is empty")));
    };
    let polled = future.as_mut().poll(cx);
    if polled.is_ready() {
        guard.take();
    }
    polled
}

type ReadOutcome = Vec<u8>;

/// A TCP stream to an overlay peer, backed by one guest data-plane resource.
pub struct StreamConn {
    instance: Instance,
    resource: u64,
    local: SocketAddr,
    peer: SocketAddr,
    read_slot: Mutex<Option<Pending<ReadOutcome>>>,
    write_slot: Mutex<Option<Pending<usize>>>,
    closed: AtomicBool,
}

impl core::fmt::Debug for StreamConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StreamConn")
            .field("resource", &self.resource)
            .field("local", &self.local)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl StreamConn {
    fn new(instance: Instance, result: &OperationResult) -> Self {
        Self {
            instance,
            resource: result.resource,
            local: socket_addr(result.local),
            peer: socket_addr(result.peer),
            read_slot: Mutex::new(None),
            write_slot: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    /// Releases the guest resource. The overlay ABI has no half-close primitive, so this is the
    /// only teardown path and both [`Stream::shutdown_read`] and [`Stream::shutdown_write`]
    /// route to it.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.instance.fire_and_forget(DataPlaneRequest::CloseResource { resource: self.resource });
    }
}

impl Drop for StreamConn {
    fn drop(&mut self) {
        self.close();
    }
}

impl Stream for StreamConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.close();
        Ok(())
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.close();
        Ok(())
    }
}

impl tokio::io::AsyncRead for StreamConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected)));
        }
        let maximum = transfer_capacity(buf.remaining());
        let instance = self.instance.clone();
        let resource = self.resource;
        match poll_pending(
            &self.read_slot,
            move || {
                Box::pin(async move {
                    let result = instance
                        .perform_operation(
                            &CancellationToken::new(),
                            OperationKind::TcpRead,
                            Box::new(move |core, store| core.submit_tcp_read(store, resource, maximum)),
                        )
                        .await
                        .map_err(|err| to_io_error(&err))?;
                    if result.data.is_empty() && result.eof {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                    }
                    Ok(result.data)
                })
            },
            cx,
        ) {
            Poll::Ready(Ok(data)) => {
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for StreamConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected)));
        }
        let chunk = buf.to_vec();
        let instance = self.instance.clone();
        let resource = self.resource;
        match poll_pending(
            &self.write_slot,
            move || {
                Box::pin(async move {
                    let mut written = 0usize;
                    while written < chunk.len() {
                        let end = (written + MAX_DATA_PLANE_TRANSFER).min(chunk.len());
                        let piece = chunk.get(written..end).unwrap_or_default().to_vec();
                        let limit = piece.len();
                        let result = instance
                            .perform_operation(
                                &CancellationToken::new(),
                                OperationKind::TcpWrite,
                                Box::new(move |core, store| core.submit_tcp_write(store, resource, &piece)),
                            )
                            .await
                            .map_err(|err| to_io_error(&err))?;
                        if result.length == 0 || result.length > limit {
                            return Err(io::Error::from(io::ErrorKind::WriteZero));
                        }
                        written += result.length;
                    }
                    Ok(written)
                })
            },
            cx,
        ) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

/// A TCP listener bound to an overlay port.
#[derive(Debug)]
pub struct StreamListener {
    instance: Instance,
    resource: u64,
    local: SocketAddr,
    closed: AtomicBool,
}

#[async_trait::async_trait]
impl Acceptor for StreamListener {
    // NOT cancel-safe: the accepted connection is consumed by a handshake or request read that is already writing or reading on it, so a dropped call loses that connection rather than leaving it queued.
    async fn accept(&self) -> io::Result<Box<dyn Stream>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }
        let resource = self.resource;
        let result = self
            .instance
            .perform_operation(
                &CancellationToken::new(),
                OperationKind::TcpAccept,
                Box::new(move |core, store| core.submit_tcp_accept(store, resource, NO_DEADLINE)),
            )
            .await
            .map_err(|err| to_io_error(&err))?;
        Ok(Box::new(StreamConn::new(self.instance.clone(), &result)))
    }

    fn close(&self) -> io::Result<()> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.instance.fire_and_forget(DataPlaneRequest::CloseResource { resource: self.resource });
        }
        Ok(())
    }

    fn addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// A UDP socket bound to an overlay port.
#[derive(Debug)]
pub struct PacketConn {
    instance: Instance,
    resource: u64,
    local: SocketAddr,
    closed: AtomicBool,
}

impl PacketConn {
    fn new(instance: Instance, result: &OperationResult) -> Self {
        Self { instance, resource: result.resource, local: socket_addr(result.local), closed: AtomicBool::new(false) }
    }
}

#[async_trait::async_trait]
impl Datagram for PacketConn {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }
        let maximum = transfer_capacity(buf.len());
        let (data, peer, truncated) =
            self.instance.udp_receive(self.resource, maximum).await.map_err(|err| to_io_error(&err))?;
        let length = data.len().min(buf.len());
        buf.get_mut(..length).unwrap_or_default().copy_from_slice(data.get(..length).unwrap_or_default());
        if truncated {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("easytier datagram larger than {maximum} bytes was truncated to the supplied buffer"),
            ));
        }
        Ok((length, peer))
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }
        let peer = DataPlaneSocketAddr { ip: overlay_ipv4(addr)?, port: addr.port() };
        let sent = self.instance.udp_send(self.resource, peer, buf.to_vec()).await.map_err(|err| to_io_error(&err))?;
        if sent != buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("easytier sent {sent} of {} datagram bytes", buf.len()),
            ));
        }
        Ok(sent)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn close(&self) -> io::Result<()> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.instance.fire_and_forget(DataPlaneRequest::CloseResource { resource: self.resource });
        }
        Ok(())
    }
}

/// A UDP socket pinned to one overlay peer, presented as a stream.
pub struct DatagramConn {
    instance: Instance,
    packet: PacketConn,
    peer: SocketAddr,
    read_slot: Mutex<Option<Pending<ReadOutcome>>>,
    write_slot: Mutex<Option<Pending<usize>>>,
}

impl core::fmt::Debug for DatagramConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DatagramConn")
            .field("resource", &self.packet.resource)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl DatagramConn {
    /// Releases the guest resource behind the pinned socket.
    pub fn close(&self) {
        self.packet.close().ok();
    }
}

impl Drop for DatagramConn {
    fn drop(&mut self) {
        self.close();
    }
}

impl Stream for DatagramConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.packet.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.close();
        Ok(())
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.close();
        Ok(())
    }
}

impl tokio::io::AsyncRead for DatagramConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let capacity = transfer_capacity(buf.remaining());
        let resource = self.packet.resource;
        let instance = self.instance.clone();
        let pinned = self.peer;
        match poll_pending(
            &self.read_slot,
            move || {
                Box::pin(async move {
                    // The datagram read skips datagrams from other peers and keeps
                    // reading; an overlay socket is shared by every peer targeting its vport, so
                    // failing the read here tears the connection down over a stranger's packet.
                    loop {
                        let (data, source, truncated) =
                            instance.udp_receive(resource, capacity).await.map_err(|err| to_io_error(&err))?;
                        if source != pinned {
                            continue;
                        }
                        if truncated {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!(
                                    "easytier datagram larger than {capacity} bytes was truncated to the supplied buffer"
                                ),
                            ));
                        }
                        return Ok(data);
                    }
                })
            },
            cx,
        ) {
            Poll::Ready(Ok(data)) => {
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for DatagramConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Ok(ip) = overlay_ipv4(self.peer) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("easytier data plane requires an IPv4 address, got {}", self.peer),
            )));
        };
        let peer = DataPlaneSocketAddr { ip, port: self.peer.port() };
        let resource = self.packet.resource;
        let instance = self.instance.clone();
        let payload = buf.to_vec();
        let expected = payload.len();
        match poll_pending(
            &self.write_slot,
            move || {
                Box::pin(async move {
                    let sent = instance.udp_send(resource, peer, payload).await.map_err(|err| to_io_error(&err))?;
                    if sent == 0 {
                        return Err(io::Error::from(io::ErrorKind::WriteZero));
                    }
                    Ok(sent)
                })
            },
            cx,
        ) {
            Poll::Ready(Ok(sent)) if sent == expected => Poll::Ready(Ok(sent)),
            Poll::Ready(Ok(sent)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("easytier sent {sent} of {expected} bytes"),
            ))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

/// The overlay data plane is IPv4-only.
fn overlay_ipv4(addr: SocketAddr) -> io::Result<Ipv4Addr> {
    match addr {
        SocketAddr::V4(v4) => Ok(*v4.ip()),
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "easytier data plane requires an IPv4 address")),
    }
}

/// The create envelope sent to the guest, verbatim field names and version.
#[derive(Serialize)]
struct CreateEnvelope {
    version: u32,
    config: String,
    environment: EnvironmentEnvelope,
}

#[derive(Serialize)]
struct EnvironmentEnvelope {
    public_ipv4: Option<String>,
    interface_ipv4s: Vec<String>,
    public_ipv6: Option<String>,
    interface_ipv6s: Vec<String>,
    mapped_listeners: Vec<String>,
    local_ips: Vec<String>,
    protected_tcp_ports: Vec<u16>,
    preferred_ipv6_sources: Vec<PreferredIPv6SourceEnvelope>,
}

#[derive(Serialize)]
struct PreferredIPv6SourceEnvelope {
    ip: String,
    ifindex: u32,
}

const CREATE_CONFIG_VERSION: u32 = 14;

fn encode_create_envelope(config_toml: &str, snapshot: &EnvironmentSnapshot) -> Result<Vec<u8>> {
    ensure!(!config_toml.is_empty(), "EasyTier TOML configuration is empty");
    let environment = EnvironmentEnvelope {
        public_ipv4: snapshot.public_ipv4.map(render_ipv4).transpose()?,
        interface_ipv4s: snapshot.interface_ipv4s.iter().map(|ip| render_ipv4(*ip)).collect::<Result<_>>()?,
        public_ipv6: snapshot.public_ipv6.map(render_ipv6).transpose()?,
        interface_ipv6s: snapshot.interface_ipv6s.iter().map(|ip| render_ipv6(*ip)).collect::<Result<_>>()?,
        mapped_listeners: snapshot.mapped_listeners.clone(),
        local_ips: snapshot.local_ips.iter().map(ToString::to_string).collect(),
        protected_tcp_ports: snapshot.protected_tcp_ports.clone(),
        preferred_ipv6_sources: snapshot
            .preferred_ipv6_sources
            .iter()
            .map(|source| {
                let ip = source.ip.ok_or_else(|| anyhow!("easytier: preferred IPv6 source is absent"))?;
                Ok(PreferredIPv6SourceEnvelope { ip: render_ipv6(ip)?, ifindex: source.if_index })
            })
            .collect::<Result<_>>()?,
    };
    serde_json::to_vec(&CreateEnvelope { version: CREATE_CONFIG_VERSION, config: config_toml.to_owned(), environment })
        .context("encode EasyTier create envelope")
}

fn render_ipv4(ip: IpAddr) -> Result<String> {
    ensure!(ip.is_ipv4(), "easytier: {ip} is not an IPv4 address");
    Ok(ip.to_string())
}

fn render_ipv6(ip: IpAddr) -> Result<String> {
    match ip {
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() => Ok(v6.to_string()),
        other @ (IpAddr::V4(_) | IpAddr::V6(_)) => Err(anyhow!("easytier: {other} is not an IPv6 address")),
    }
}

#[cfg(test)]
mod tests {
    use murmur_constant::adapters::Dialer as ConstantDialer;

    use super::*;
    use crate::reactor::ReactorError;

    /// The sinks here never carry traffic; a dialer that refuses keeps any accidental use loud.
    struct UnusableDialer;

    #[async_trait::async_trait]
    impl ConstantDialer for UnusableDialer {
        async fn dial_context(
            &self,
            _ctx: &CancellationToken,
            _network: &str,
            address: &str,
        ) -> Result<Box<dyn Stream>> {
            Err(anyhow!("this test binds no sockets: {address}"))
        }

        async fn listen_packet(
            &self,
            _ctx: &CancellationToken,
            _network: &str,
            address: &str,
            _r_addr_port: Option<SocketAddr>,
        ) -> Result<Box<dyn Datagram>> {
            Err(anyhow!("this test binds no sockets: {address}"))
        }
    }

    /// An instance tears down the same way whether the caller closed it or the guest died under
    /// the driver, and the closed event stream is what an outbound's `serve()` loop watches to
    /// restart. A teardown that only cancelled the token leaves that reader parked forever, so the
    /// overlay never comes back and every later dial waits on a readiness signal nobody sends.
    #[tokio::test]
    async fn releasing_an_instance_ends_its_event_stream_and_its_sinks() {
        let services = Arc::new(murmur_component_easytier::platform::services(Arc::new(UnusableDialer)));
        let reactor = Reactor::new(services);
        let (packet_sink, packets) = reactor.register_packet_sink(4);
        let (event_sink, mut sink_events) = reactor.register_event_sink(4);

        // The hop `Actor::create_instance_inner` installs, plus the reader that holds the stream the
        // way `Instance::events` hands it to an outbound's `serve()` loop.
        let (sink_tx, mut sink_rx) = mpsc::channel::<(String, String)>(4);
        let (event_tx, event_rx) = mpsc::channel::<Event>(4);
        tokio::spawn(async move {
            while let Some((kind, message)) = sink_rx.recv().await {
                if event_tx.send(Event { kind, message }).await.is_err() {
                    break;
                }
            }
        });

        let mut sinks = InstanceSinks {
            packet_sink,
            event_sink,
            packets: Some(Arc::new(TokioMutex::new(packets))),
            events: Arc::new(Mutex::new(Some(event_rx))),
        };
        let mut reader = sinks.events.lock().take().expect("the stream is handed out once");
        sink_tx.send(("peer_added".to_owned(), "peer".to_owned())).await.expect("the sink is registered");
        drop(sink_tx);

        sinks.release(&reactor);

        assert_eq!(reader.recv().await.map(|event| event.kind), Some("peer_added".to_owned()));
        assert!(reader.recv().await.is_none(), "a released instance must end its event stream, not stall it");
        assert!(sink_events.recv().await.is_none(), "an unregistered sink must end the forwarding hop");
        assert!(matches!(
            reactor.emit_event(event_sink, "peer_removed".into(), "peer".into()),
            Err(ReactorError::UnknownHandle(_))
        ));
        assert!(matches!(reactor.try_packet_write(packet_sink, vec![0]), Err(ReactorError::UnknownHandle(_))));
    }
}

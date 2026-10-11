//! The engine is `murmur-zerotier`, whose `Node` is a protocol core with physical I/O
//! behind the `NodeHost` seam. The adapter is built from these engine calls:
//!
//! * `address::parse_network_id`; `Identity::parse`/`has_private`/`validate`;
//!   `Address::parse`/`is_reserved`; `world::World::parse_planet`; `world::parse_orbit`
//! * `network_config::{MIN,MAX}_NETWORK_MTU`; `util::ip_stack::IpStackOption`;
//!   `murmur_dns::resolver::PARSE_NAME_SERVER`
//! * `Node::new` (configured identity) or `Node::open`, and `Node::close`
//! * `Node::process_background_tasks`, polled
//! * `Node::join`/`orbit`/`network`/`refresh_network`
//! * `Node::set_network_config_callback` + `Node::run_callbacks`, and `Node::take_events`
//! * `UdpWire` plus [`ZeroTierHost`]
//!
//! The stored-identity rotation has no engine equivalent (see the DEVIATION below).
//!
//! The data plane runs: the runtime builds the link in [`super::zerotier_link`]
//! (ARP/NDP responders, neighbor cache and probes, source selection, MTU and destination
//! validation), installs one `new_ip_stack` device per configuration generation with a
//! stack-packet reader thread, and bridges the node's delivered frames back through
//! `Link::handle_frame`. `dial_context` and `listen_packet_context` dial through that device after
//! a stack lookup, and `listen_packet_context` revalidates every destination a caller writes to,
//! as the packet conn does.
//!
//! Broadcast and multicast frames reach the wire through the engine's multicast sender: the node
//! announces the groups its assigned addresses imply, the link subscribes the groups its
//! membership reports imply, and a replicated frame is delivered to every peer whose announcement
//! named the group.
//!
//! DEVIATION (stack engines and remote DNS): `new_ip_stack` serves the `mips` engine only, so
//! `auto` resolves to `mips` and an explicit `ip-stack: gvisor` still fails closed at device
//! creation, and the controller-provided DNS resolver is not installed — `remote-dns-resolve`/`dns`
//! are validated but resolution goes through the default resolver, as the control plane already
//! did.
//!
//! DEVIATION (node on its own thread): the engine's `NodeHost` and `StateStore` traits carry no
//! `Send` bound, so `Node` cannot move into a multi-threaded runtime task. Each running outbound
//! owns one OS thread with a current-thread runtime, running the node's background tasks plus its
//! network-config and inbound-frame loops.
//!
//! DEVIATION (options with no engine seam): `Node::new` hard-codes the `physical_mtu`,
//! `low_bandwidth` and `encrypted_hello` fields (all `pub(crate)` in `node/mod.rs` with no setter),
//! `Node::open` adopts a stored world only when its ID equals the embedded planet's (the
//! `load_stored_world(... planet_state_name())` check in `node/mod.rs`), and the node exposes no
//! remote-trace API. Setting `planet`, `physical-mtu`, `low-bandwidth`, `encrypted-hello` or
//! `remote-trace-target` therefore fails closed in `ZeroTier::new` instead of running without
//! them. `Node::new` also does not emit `NodeUp` the way `Node::open` does, so the "node
//! initialized" line appears only for a generated identity.
//!
//! DEVIATION (identity collision): the documented behaviour rotates the stored identity or backs
//! off 30 s for a configured one. The engine exposes neither, so a collision is reported as a
//! network failure.
//!
//! DEVIATION (TCP fallback): the engine has no `tcpfallback` module and no transport dialer, so
//! `tcp-fallback-mode: force` is refused and the default `auto` behaves as `disable`; the relay is
//! validated but never dialed. `dialer-proxy` only ever carried that relay, so it has no effect
//! here and is warned about at construction.
//!
//! DEVIATION (wire policy): `UdpWire` binds the wildcard address, so `interface` and
//! `routing-mark` cannot carry the physical sockets (warned at construction); it also merges
//! inbound datagrams from every socket without reporting which one received them, so inbound
//! packets are attributed to `ANY_LOCAL_SOCKET` instead of the per-socket handle. The
//! `secondary-port: 0` ("let the OS pick a second socket") has no equivalent and binds one socket;
//! `secondary-port: -1` reads as "no secondary socket".
//!
//! DEVIATION (peer cache): the engine keeps only an in-memory peer table and asks
//! `NodeHost::peer_identity` for identities it has not learned, so this adapter mirrors what the
//! node learns (`PeerIdentityLearned` plus `Node::peer_identity`) into its host and prunes that
//! mirror through `NodeHost::clean_peer_cache`. The on-disk peer tree and its memorized
//! endpoints (`NodeHost::path_lookup`) are not reimplemented, so peer discovery relies on
//! controller configuration, direct-path pushes and WHOIS. The state-filesystem wrapper is
//! replaced by the engine's `FileStore`, which writes the same object names with owner-only
//! permissions.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use murmur_common::net::Datagram;
use murmur_component::dialer::dialer::new_dialer;
use murmur_component::dialer::options::{with_net_dialer, with_resolver, NetDialer, Option as DialerOption};
use murmur_component::iface::anet;
use murmur_component::iface::iface::interfaces;
use murmur_component::resolver::resolver::default_resolver;
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_constant::path::PATH;
use murmur_dns::resolver::PARSE_NAME_SERVER;
use murmur_log::{debugln, errorln, infoln, warnln};
use murmur_zerotier::address::{is_ad_hoc_network_id, parse_network_id, Address};
use murmur_zerotier::frame::Frame;
use murmur_zerotier::identity::Identity;
use murmur_zerotier::network_config::{NetworkConfigData, DEFAULT_NETWORK_MTU, MAX_NETWORK_MTU, MIN_NETWORK_MTU};
use murmur_zerotier::node::{
    Event, EventType, FileStore, NetworkAuthenticationInfo, NetworkStatus, Node, NodeError, NodeHost, PeerRole,
    PeerRoute, ANY_LOCAL_SOCKET,
};
use murmur_zerotier::packet::{MAX_PHYSICAL_MTU, MIN_PHYSICAL_MTU};
use murmur_zerotier::wire::{UdpWire, WirePath};
use murmur_zerotier::world::{parse_orbit, World};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, Notify};
use tokio_util::sync::CancellationToken;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::util::ip_stack::{new_ip_stack, IpStack, IpStackOption};
use super::util::resolve_ip_with_resolver;
use super::zerotier_link::Link;

const DEFAULT_STATE_DIR: &str = "zerotier";
const OUTBOUND_CLOSED: &str = "ZeroTier outbound closed";
/// The largest accepted `remote-trace-level`.
const TRACE_LEVEL_INSANE: u64 = 30;
const DEFAULT_TCP_FALLBACK_RELAY: &str = "204.80.128.1:443";
/// The retry for the wire's direct-path list.
const DIRECT_PATH_REFRESH_PERIOD: Duration = Duration::from_secs(15);
/// Bounds the datagrams queued for the wire.
const SEND_QUEUE_DEPTH: usize = 2048;
/// Logs a dropped-datagram count every this many drops after the first one.
const DROP_LOG_INTERVAL: u64 = 4096;
/// The runtime loop's longest sleep, so maintenance and cancellation stay responsive.
const LOOP_TICK: Duration = Duration::from_secs(1);

#[derive(Clone, Default, Serialize, Deserialize)]
#[expect(clippy::struct_excessive_bools, reason = "the option struct mirrors the protocol's flag set field for field")]
pub struct ZeroTierOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "network")]
    pub network: String,
    #[serde(rename = "state-dir", default)]
    pub state_dir: String,
    #[serde(rename = "identity-secret", default)]
    pub identity_secret: String,
    #[serde(rename = "planet", default)]
    pub planet: String,
    #[serde(rename = "mtu", default)]
    pub mtu: i32,
    #[serde(rename = "ip-stack", default)]
    pub ip_stack: IpStackOption,
    #[serde(rename = "physical-mtu", default)]
    pub physical_mtu: i32,
    #[serde(rename = "udp", default)]
    pub udp: bool,
    #[serde(rename = "remote-dns-resolve", default)]
    pub remote_dns_resolve: bool,
    #[serde(rename = "dns", default)]
    pub dns: Vec<String>,
    #[serde(rename = "low-bandwidth", default)]
    pub low_bandwidth: bool,
    #[serde(rename = "encrypted-hello", default)]
    pub encrypted_hello: bool,
    #[serde(rename = "primary-port", default)]
    pub primary_port: i32,
    #[serde(rename = "secondary-port", default)]
    pub secondary_port: i32,
    #[serde(rename = "tcp-fallback-mode", default)]
    pub tcp_fallback_mode: String,
    #[serde(rename = "tcp-fallback-relay", default)]
    pub tcp_fallback_relay: String,
    #[serde(rename = "orbit", default)]
    pub orbit: Vec<ZeroTierOrbitOption>,
    #[serde(rename = "remote-trace-target", default)]
    pub remote_trace_target: String,
    #[serde(rename = "remote-trace-level", default)]
    pub remote_trace_level: u64,
}

impl core::fmt::Debug for ZeroTierOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `basic_option` has no `Debug`; the identity secret is never printed.
        f.debug_struct("ZeroTierOption")
            .field("name", &self.name)
            .field("network", &self.network)
            .field("state_dir", &self.state_dir)
            .field("identity_secret", &"<redacted>")
            .field("planet", &self.planet)
            .field("mtu", &self.mtu)
            .field("physical_mtu", &self.physical_mtu)
            .field("udp", &self.udp)
            .field("remote_dns_resolve", &self.remote_dns_resolve)
            .field("dns", &self.dns)
            .field("low_bandwidth", &self.low_bandwidth)
            .field("encrypted_hello", &self.encrypted_hello)
            .field("primary_port", &self.primary_port)
            .field("secondary_port", &self.secondary_port)
            .field("tcp_fallback_mode", &self.tcp_fallback_mode)
            .field("tcp_fallback_relay", &self.tcp_fallback_relay)
            .field("remote_trace_target", &self.remote_trace_target)
            .field("remote_trace_level", &self.remote_trace_level)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ZeroTierOrbitOption {
    #[serde(rename = "world")]
    pub world: String,
    #[serde(rename = "seed")]
    pub seed: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ZeroTierOrbit {
    world: u64,
    seed: Address,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TcpFallbackMode {
    Auto,
    Force,
    Disabled,
}

impl TcpFallbackMode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "" | "auto" => Ok(Self::Auto),
            "force" => Ok(Self::Force),
            "disable" => Ok(Self::Disabled),
            other => Err(anyhow!("invalid ZeroTier TCP fallback mode {other:?}; expected auto, force, or disable")),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Force => "force",
            Self::Disabled => "disable",
        }
    }
}

/// The option values carried into the node once validation passes.
struct ValidatedOptions {
    network_id: u64,
    identity: Option<Identity>,
    orbits: Vec<ZeroTierOrbit>,
    state_dir: String,
    primary_port: u16,
    secondary_port: u16,
}

/// The adapter state, shared with the runtime thread behind its mutex.
struct ZeroTierShared {
    outbound: String,
    network_id: u64,
    state: Mutex<NetworkState>,
    state_tx: watch::Sender<u64>,
}

#[derive(Default)]
struct NetworkState {
    closed: bool,
    /// the applied `config`; only `apply_network_config` sets it.
    config: Option<NetworkConfigData>,
    latest_config: Option<NetworkConfigData>,
    network_err: Option<Arc<anyhow::Error>>,
    auth_url: String,
    logged_failure: String,
    generation: u64,
    notifications: u64,
    /// The link, installed by the runtime thread before its loop starts.
    link: Option<Arc<Mutex<Link>>>,
    /// The userspace IP stack the current configuration installed.
    device: Option<Arc<dyn IpStack>>,
}

impl ZeroTierShared {
    fn new(outbound: String, network_id: u64) -> Self {
        let (state_tx, _) = watch::channel(0);
        Self { outbound, network_id, state: Mutex::new(NetworkState::default()), state_tx }
    }

    fn closed_error() -> Arc<anyhow::Error> {
        Arc::new(anyhow!("{OUTBOUND_CLOSED}"))
    }

    fn notify(&self) {
        let next = {
            let mut state = self.state.lock();
            state.notifications = state.notifications.wrapping_add(1);
            state.notifications
        };
        self.state_tx.send_replace(next);
    }

    fn set_network_failure(&self, err: Option<Arc<anyhow::Error>>, auth_url: &str) {
        {
            let mut state = self.state.lock();
            state.network_err = err;
            auth_url.clone_into(&mut state.auth_url);
        }
        self.notify();
    }

    fn reset_network_state(&self, err: Option<Arc<anyhow::Error>>) {
        {
            let mut state = self.state.lock();
            state.config = None;
            state.latest_config = None;
            state.network_err = err;
            state.auth_url = String::new();
            state.logged_failure = String::new();
            state.generation = state.generation.wrapping_add(1);
        }
        self.notify();
    }

    /// Invalidates the network state. The runtime-generation guard is absent because this adapter
    /// never retires a runtime.
    fn invalidate_network(&self, err: Option<Arc<anyhow::Error>>, auth_url: &str) -> bool {
        let failure = if auth_url.is_empty() {
            err.as_ref().map(ToString::to_string).unwrap_or_default()
        } else {
            format!("authentication-required:{auth_url}")
        };
        let should_log = {
            let mut state = self.state.lock();
            let should_log = state.logged_failure != failure;
            state.logged_failure = failure;
            state.generation = state.generation.wrapping_add(1);
            should_log
        };
        self.set_network_failure(err, auth_url);
        should_log
    }

    fn clear_logged_failure(&self) -> bool {
        let mut state = self.state.lock();
        if state.closed {
            return false;
        }
        state.logged_failure.clear();
        true
    }
}

/// A datagram [`NodeHost::send_wire`] queued for the runtime thread's wire.
struct OutboundDatagram {
    local_socket: i64,
    remote: SocketAddr,
    packet: Vec<u8>,
}

/// An identity the node learned, mirrored so [`NodeHost::peer_identity`] can answer.
struct KnownPeer {
    identity: Identity,
    touched: SystemTime,
}

/// The seam between the adapter's threads: the wire's endpoints and queue, and the peer cache.
struct RuntimeShared {
    name: String,
    endpoints: Mutex<Vec<SocketAddr>>,
    direct_paths: Mutex<Vec<SocketAddr>>,
    queue: Mutex<VecDeque<OutboundDatagram>>,
    wake: Notify,
    peers: Mutex<BTreeMap<Address, KnownPeer>>,
    dropped: AtomicU64,
}

impl RuntimeShared {
    fn new(name: String) -> Self {
        Self {
            name,
            endpoints: Mutex::new(Vec::new()),
            direct_paths: Mutex::new(Vec::new()),
            queue: Mutex::new(VecDeque::new()),
            wake: Notify::new(),
            peers: Mutex::new(BTreeMap::new()),
            dropped: AtomicU64::new(0),
        }
    }

    /// The protocol core drops rather than blocks, so a full queue loses the datagram and logs the
    /// loss at a bounded rate.
    fn push(&self, datagram: OutboundDatagram) {
        let queued = {
            let mut queue = self.queue.lock();
            if queue.len() < SEND_QUEUE_DEPTH {
                queue.push_back(datagram);
                true
            } else {
                false
            }
        };
        if queued {
            self.wake.notify_one();
            return;
        }
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped == 1 || dropped.is_multiple_of(DROP_LOG_INTERVAL) {
            warnln!("[ZeroTier]({}) dropped {dropped} outbound datagrams: the wire queue is full", self.name);
        }
    }

    fn learn(&self, identity: Identity) {
        let touched = SystemTime::now();
        self.peers.lock().insert(identity.address(), KnownPeer { identity, touched });
    }
}

/// The transport, as the engine's [`NodeHost`] seam: the sockets live in the runtime
/// thread, this type queues datagrams for it and answers the node's peer-cache questions.
#[derive(Clone)]
struct ZeroTierHost {
    shared: Arc<RuntimeShared>,
}

impl NodeHost for ZeroTierHost {
    fn peer_identity(&self, address: Address) -> Option<Identity> {
        self.shared.peers.lock().get(&address).map(|known| known.identity.clone())
    }

    fn send_wire(
        &mut self,
        local_socket: i64,
        remote: SocketAddr,
        packet: Vec<u8>,
    ) -> std::result::Result<(), NodeError> {
        self.shared.push(OutboundDatagram { local_socket, remote, packet });
        Ok(())
    }

    /// The engine runs the WHOIS exchange itself, so this hook only reports the request.
    fn request_whois(&mut self, address: Address) {
        debugln!("[ZeroTier]({}) whois requested for {address}", self.shared.name);
    }

    /// The engine announces the network's groups itself; this only reports the change.
    fn announce_multicast(&mut self, network_id: u64) {
        debugln!("[ZeroTier]({}) multicast subscriptions changed for network {network_id:016x}", self.shared.name);
    }

    /// Remote tracing is refused at construction, so there is nothing to record.
    fn trace_network_config_request(&mut self, network_id: u64, controller: Address) {
        debugln!(
            "[ZeroTier]({}) controller {controller} was asked for the configuration of network {network_id:016x}",
            self.shared.name
        );
    }

    fn direct_paths(&self) -> Vec<SocketAddr> {
        self.shared.direct_paths.lock().clone()
    }

    fn clean_peer_cache(&mut self, older_than: Duration) -> std::result::Result<(), NodeError> {
        let now = SystemTime::now();
        self.shared
            .peers
            .lock()
            .retain(|_, known| now.duration_since(known.touched).map_or(true, |age| age <= older_than));
        Ok(())
    }
}

/// The configuration one runtime thread needs to build and join its node.
struct RuntimeInputs {
    network_id: u64,
    configured_identity: Option<Identity>,
    orbits: Vec<ZeroTierOrbit>,
    state_dir: String,
    primary_port: u16,
    secondary_port: u16,
    mtu: i32,
    interface_name: String,
    /// The configured IP stack, carried into the runtime that builds the device.
    ip_stack: IpStackOption,
}

impl RuntimeInputs {
    /// A configured identity is used as given and is not persisted; otherwise the node loads or
    /// creates one through the state store.
    fn build_node(&self, host: &ZeroTierHost) -> Result<Node> {
        let store = Box::new(FileStore::new(&self.state_dir));
        match &self.configured_identity {
            Some(identity) => {
                let mut node = Node::new(identity.clone(), store, Box::new(host.clone()));
                // `Node::new` starts up without the topology install `Node::open` performs.
                node.refresh_topology_roots_locked();
                Ok(node)
            }
            None => Node::open(store, Box::new(host.clone())).map_err(|err| anyhow!("open ZeroTier node: {err}")),
        }
    }
}

/// One running node: the thread that owns it and the token that stops it.
struct RuntimeHandle {
    cancel: CancellationToken,
    thread: std::thread::JoinHandle<()>,
}

impl RuntimeHandle {
    fn close(self) {
        self.cancel.cancel();
        let _ = self.thread.join();
    }
}

/// Reports a cancelled dial context.
#[derive(Debug, thiserror::Error)]
#[error("context canceled or deadline exceeded")]
struct CtxDoneError;

/// Nothing is started here: the runtime is built lazily in `ensure_started`.
pub struct ZeroTier {
    /// `new_packet_conn` takes the `Arc<ZeroTier>` the receiver already is (see openvpn.rs).
    self_weak: Weak<Self>,
    base: Base,
    option: ZeroTierOption,
    shared: Arc<ZeroTierShared>,
    configured_identity: Option<Identity>,
    orbits: Vec<ZeroTierOrbit>,
    state_dir: String,
    primary_port: u16,
    secondary_port: u16,
    ctx: CancellationToken,
    start_lock: AsyncMutex<()>,
    runtime: Mutex<Option<RuntimeHandle>>,
}

impl core::fmt::Debug for ZeroTier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `base` and the identity have no `Debug`; the identity secret is never printed.
        f.debug_struct("ZeroTier")
            .field("name", &self.base.name)
            .field("network", &self.base.addr)
            .field("state_dir", &self.state_dir)
            .field("primary_port", &self.primary_port)
            .finish_non_exhaustive()
    }
}

impl ZeroTier {
    pub fn new(mut option: ZeroTierOption) -> Result<Arc<Self>> {
        let validated = validate_options(&mut option)?;
        warn_about_wire_options(&option);
        let shared = Arc::new(ZeroTierShared::new(option.name.clone(), validated.network_id));
        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr: option.network.clone(),
            type_: AdapterType::ZERO_TIER,
            provider_name: option.basic_option.provider_name.clone(),
            udp: option.udp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
            xudp: false,
            tfo: false,
            mptcp: false,
        });
        base.dialer = Some(option.basic_option.new_dialer(base.dial_options()));
        Ok(Arc::new_cyclic(|self_weak| Self {
            self_weak: Weak::clone(self_weak),
            base,
            option,
            shared,
            configured_identity: validated.identity,
            orbits: validated.orbits,
            state_dir: validated.state_dir,
            primary_port: validated.primary_port,
            secondary_port: validated.secondary_port,
            ctx: CancellationToken::new(),
            start_lock: AsyncMutex::new(()),
            runtime: Mutex::new(None),
        }))
    }

    fn runtime_inputs(&self) -> RuntimeInputs {
        RuntimeInputs {
            network_id: self.shared.network_id,
            configured_identity: self.configured_identity.clone(),
            orbits: self.orbits.clone(),
            state_dir: self.state_dir.clone(),
            primary_port: self.primary_port,
            secondary_port: self.secondary_port,
            mtu: self.option.mtu,
            interface_name: self.option.basic_option.interface.clone(),
            ip_stack: self.option.ip_stack.clone(),
        }
    }

    /// the `z` receiver, for the helpers that need the adapter itself.
    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("ZeroTier adapter dropped while still in use"))
    }

    /// Starts the runtime, retried per call rather than latched, so a transient bind failure does
    /// not poison the outbound.
    pub(crate) async fn start(&self) -> Result<()> {
        // NOT cancel-safe: it delegates to `start_runtime`, whose spawned runtime thread outlives a
        // dropped future.
        if self.ctx.is_cancelled() || self.shared.state.lock().closed {
            return Err(anyhow!("{OUTBOUND_CLOSED}"));
        }
        if self.live_runtime_stored() {
            return Ok(());
        }
        let _guard = self.start_lock.lock().await;
        if self.ctx.is_cancelled() || self.shared.state.lock().closed {
            return Err(anyhow!("{OUTBOUND_CLOSED}"));
        }
        if self.live_runtime_stored() {
            return Ok(());
        }
        self.start_runtime().await
    }

    /// Whether the stored runtime is still running. A handle whose thread has returned is dropped
    /// here, so `start` never reports a node the adapter no longer has.
    fn live_runtime_stored(&self) -> bool {
        let stopped = {
            let mut runtime = self.runtime.lock();
            match runtime.as_ref() {
                None => return false,
                Some(handle) if !handle.thread.is_finished() => return true,
                Some(_) => runtime.take(),
            }
        };
        if let Some(stopped) = stopped {
            stopped.close();
        }
        false
    }

    async fn start_runtime(&self) -> Result<()> {
        // NOT cancel-safe: the runtime thread it spawns is only reachable through the handle stored
        // on success, so a drop leaves that thread running with no way to cancel it.
        // The state directory is created owner-only (0700); `FileStore` creates object directories
        // itself.
        tokio::fs::create_dir_all(&self.state_dir)
            .await
            .map_err(|err| anyhow!("create ZeroTier state directory {}: {err}", self.state_dir))?;
        let shared = Arc::clone(&self.shared);
        let runtime_shared = Arc::new(RuntimeShared::new(self.base.name()));
        let host = ZeroTierHost { shared: Arc::clone(&runtime_shared) };
        let inputs = self.runtime_inputs();
        let cancel = self.ctx.child_token();
        let thread_cancel = cancel.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let thread_name = format!("zerotier-{}", self.base.name());
        let thread = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        let _ = ready_tx.send(Err(Arc::new(anyhow!("create ZeroTier runtime: {err}"))));
                        return;
                    }
                };
                runtime.block_on(run_runtime(shared, host, inputs, thread_cancel, ready_tx));
            })
            .map_err(|err| anyhow!("spawn ZeroTier runtime thread: {err}"))?;
        match ready_rx.await {
            Ok(Ok(())) => {
                *self.runtime.lock() = Some(RuntimeHandle { cancel, thread });
                Ok(())
            }
            Ok(Err(err)) => {
                cancel.cancel();
                Err(anyhow!("{err}"))
            }
            Err(_) => {
                cancel.cancel();
                Err(anyhow!("ZeroTier runtime thread exited before the node was up"))
            }
        }
    }

    /// Ensures the runtime is started. The explicit network retry is folded into the runtime loop,
    /// which retries the configuration the node keeps re-requesting.
    pub(crate) async fn ensure_started(&self, ctx: &CancellationToken) -> Result<()> {
        // NOT cancel-safe: it delegates to `start`, which reaches a runtime thread a dropped future
        // leaves unreachable. The wait below is the safe half: it only samples the shared state,
        // and the notification channel it subscribes to outlives the call.
        self.start().await?;
        let mut notifications = self.shared.state_tx.subscribe();
        loop {
            {
                let state = self.shared.state.lock();
                if let Some(err) = state.network_err.clone() {
                    return Err(anyhow!("{err}"));
                }
                if state.config.is_some() {
                    return Ok(());
                }
            }
            tokio::select! {
                changed = notifications.changed() => {
                    changed.map_err(|_| anyhow!("{OUTBOUND_CLOSED}"))?;
                }
                () = ctx.cancelled() => return Err(CtxDoneError.into()),
                () = self.ctx.cancelled() => return Err(anyhow!("{OUTBOUND_CLOSED}")),
            }
        }
    }

    /// The controller-provided resolver would be consulted when one is installed; none can be (see
    /// the module doc), so this is the no-resolver path.
    async fn resolve_udp_impl(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        if !metadata.resolved() && !metadata.host.is_empty() {
            let resolver = default_resolver();
            let ip = resolve_ip_with_resolver(ctx, &metadata.host, self.base.prefer, resolver.as_deref())
                .await
                .map_err(|err| anyhow!("can't resolve ip: {err}"))?;
            metadata.dst_ip = Some(ip);
        }
        Ok(())
    }
}

#[async_trait]
impl CProxyAdapter for ZeroTier {
    fn name(&self) -> String {
        self.base.name()
    }

    fn type_(&self) -> AdapterType {
        self.base.type_()
    }

    fn addr(&self) -> String {
        self.base.addr()
    }

    fn support_udp(&self) -> bool {
        self.base.support_udp()
    }

    fn proxy_info(&self) -> ProxyInfo {
        let mut info = self.base.proxy_info();
        info.dialer_proxy.clone_from(&self.option.basic_option.dialer_proxy);
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    /// The remote resolver cannot be installed (see the module doc), so the resolver branch uses
    /// the default resolver and an unresolved host dials through the stack-backed dialer.
    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        self.ensure_started(ctx).await?;
        let conn: Box<dyn murmur_std_compat::net::Conn> = if metadata.resolved() {
            let destination = metadata.addr_port().ok_or_else(|| anyhow!("ZeroTier destination is not resolved"))?;
            let device = network_stack_for(&self.shared, destination.ip())?;
            device.dial_tcp(ctx, "tcp", unspecified_addr(), destination).await?
        } else {
            let mut options = self.base.dial_options();
            options.push(with_resolver(default_resolver()));
            options.push(with_net_dialer(Arc::new(ZeroTierNetDialer { shared: Arc::clone(&self.shared) })));
            let stream = new_dialer(options).dial_context(ctx, "tcp", &metadata.remote_address()).await?;
            Box::new(murmur_common_net::io::StreamAsOldConn::new(stream))
        };
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(conn)), self))
    }

    /// Wraps the socket so every destination a caller writes to is revalidated against the
    /// installed link, as the packet conn does.
    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.ensure_started(ctx).await?;
        self.resolve_udp_impl(ctx, metadata).await?;
        let destination = metadata.dst_ip.ok_or_else(|| anyhow!("ZeroTier UDP destination is not resolved"))?;
        let device = network_stack_for(&self.shared, destination)?;
        let socket = device.listen_udp(ctx, "udp", unspecified_addr()).await?;
        let datagram = Arc::new(ValidatedDatagram {
            inner: Arc::new(murmur_common_net::io::OldPacketConnAsDatagram(socket)),
            shared: Arc::clone(&self.shared),
        });
        Ok(new_packet_conn(datagram, self.self_arc()?))
    }

    fn support_uot(&self) -> bool {
        self.base.support_uot()
    }

    fn is_l3_protocol(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.base.unwrap(metadata, touch)
    }

    /// the wire stops before the runtime is joined, so an in-flight write
    /// cannot hold up its own shutdown.
    fn close(&self) -> Result<()> {
        self.ctx.cancel();
        let runtime = self.runtime.lock().take();
        if let Some(runtime) = runtime {
            runtime.close();
        }
        {
            let mut state = self.shared.state.lock();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
        }
        self.shared.reset_network_state(Some(ZeroTierShared::closed_error()));
        Ok(())
    }
}

#[async_trait]
impl ProxyAdapter for ZeroTier {
    fn dial_options(&self) -> Vec<DialerOption> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.resolve_udp_impl(ctx, metadata).await
    }
}

/// The runtime loop: the wire's receive pump, the node's background tasks, the configuration
/// worker and the inbound-frame bridge.
#[expect(
    clippy::future_not_send,
    reason = "run_runtime is driven by block_on on the dedicated current-thread runtime, and Node is deliberately not Send"
)]
async fn run_runtime(
    shared: Arc<ZeroTierShared>,
    host: ZeroTierHost,
    inputs: RuntimeInputs,
    cancel: CancellationToken,
    ready: oneshot::Sender<std::result::Result<(), Arc<anyhow::Error>>>,
) {
    // NOT cancel-safe: only the cancel arm reaches the trailing flush and `node.close()`; an
    // external drop skips them.
    let mut wire = match UdpWire::bind(inputs.primary_port, inputs.secondary_port).await {
        Ok(wire) => wire,
        Err(err) => {
            let _ = ready.send(Err(Arc::new(anyhow!("bind ZeroTier UDP wire: {err}"))));
            return;
        }
    };
    *host.shared.endpoints.lock() = wire.local_endpoints().to_vec();
    refresh_direct_paths(&host.shared, &inputs.interface_name).await;

    let mut node = match inputs.build_node(&host) {
        Ok(node) => node,
        Err(err) => {
            let _ = ready.send(Err(Arc::new(err)));
            return;
        }
    };
    // The network-config callback is set on the node before `join`, so it is live before a cached
    // configuration can be loaded from the state store.
    let (config_tx, mut config_rx) = mpsc::unbounded_channel::<NetworkConfigData>();
    node.set_network_config_callback(Box::new(move |config| {
        let _ = config_tx.send(config.clone());
    }));
    for orbit in &inputs.orbits {
        if let Err(err) = node.orbit(orbit.world, orbit.seed, SystemTime::now()) {
            let _ = ready.send(Err(Arc::new(anyhow!("orbit ZeroTier world {:016x}: {err}", orbit.world))));
            return;
        }
    }
    if let Err(err) = node.join(inputs.network_id, SystemTime::now()) {
        let _ = ready.send(Err(Arc::new(anyhow!("join ZeroTier network: {err}"))));
        return;
    }
    // The link is created with the runtime, so a configuration loaded during the join has one to
    // apply to.
    let link = match Link::new(inputs.network_id, node.address()) {
        Ok(link) => Arc::new(Mutex::new(link)),
        Err(err) => {
            let _ = ready.send(Err(Arc::new(anyhow!("create ZeroTier IP link: {err}"))));
            return;
        }
    };
    shared.state.lock().link = Some(Arc::clone(&link));
    let _ = ready.send(Ok(()));

    let mut stack: Option<NetworkStack> = None;
    let mut next_direct_paths = SystemTime::now();
    loop {
        flush_datagrams(&wire, &host.shared).await;
        let now = SystemTime::now();
        let next_maintenance = node.process_background_tasks(now);
        node.run_callbacks();
        // What the stack transmitted becomes ZeroTier frames.
        if let Some(installed) = stack.as_ref() {
            pump_stack_packets(&link, &mut node, installed, &shared);
        }
        // What the node delivered becomes packets
        // for the stack, in delivery order.
        let frames = node.take_delivered_frames();
        if let Some(installed) = stack.as_ref() {
            pump_delivered_frames(&link, &mut node, installed, &frames, &shared);
        }
        // The runtime's background-task ticker.
        let maintenance = link.lock().process_background_tasks(&mut node, now);
        if let Err(err) = maintenance {
            debugln!("[ZeroTier]({}) IP link maintenance: {err}", shared.outbound);
        }
        for event in node.take_events() {
            handle_node_event(&shared, &host, &mut node, &event);
        }
        while let Ok(config) = config_rx.try_recv() {
            handle_network_config(&shared, &mut node, &inputs, &config, &mut stack);
        }
        let direct_paths_due =
            SystemTime::now().duration_since(next_direct_paths).map_or(true, |age| age >= DIRECT_PATH_REFRESH_PERIOD);
        if direct_paths_due {
            refresh_direct_paths(&host.shared, &inputs.interface_name).await;
            next_direct_paths = SystemTime::now();
        }
        tokio::select! {
            () = cancel.cancelled() => break,
            () = host.shared.wake.notified() => {}
            datagram = wire.recv_from() => match datagram {
                Some((data, remote)) => {
                    let _ = node.process_wire_packet(ANY_LOCAL_SOCKET, remote, &data, SystemTime::now());
                }
                None => break,
            },
            () = tokio::time::sleep(sleep_duration(next_maintenance)) => {}
        }
    }
    flush_datagrams(&wire, &host.shared).await;
    node.close();
    // A loop that ends without a cancellation would otherwise leave callers waiting on a wire that
    // no longer exists.
    if !cancel.is_cancelled() {
        shared.set_network_failure(
            Some(Arc::new(anyhow!("ZeroTier runtime stopped: the UDP wire is no longer readable"))),
            "",
        );
    }
}

/// What the stack transmitted becomes ZeroTier frames.
fn pump_stack_packets(link: &Mutex<Link>, node: &mut Node, stack: &NetworkStack, shared: &Arc<ZeroTierShared>) {
    while let Ok(packet) = stack.packets.try_recv() {
        let result = link.lock().write_packet(node, &packet, SystemTime::now());
        if let Err(err) = result {
            debugln!("[ZeroTier]({}) send IP packet: {err}", shared.outbound);
        }
    }
}

/// What the node delivered becomes packets for the
/// stack, in delivery order.
fn pump_delivered_frames(
    link: &Mutex<Link>,
    node: &mut Node,
    stack: &NetworkStack,
    frames: &[Frame],
    shared: &Arc<ZeroTierShared>,
) {
    for frame in frames {
        let outcome = link.lock().handle_frame(node, frame, SystemTime::now());
        match outcome {
            Ok(Some(packet)) => {
                let result = stack.device.write(&[packet], 0);
                if let Err(err) = result {
                    debugln!("[ZeroTier]({}) stack write: {err}", shared.outbound);
                }
            }
            Ok(None) => {}
            Err(err) => debugln!("[ZeroTier]({}) process inbound frame: {err}", shared.outbound),
        }
    }
}

/// Waits no longer than [`LOOP_TICK`] past the node's next useful maintenance time.
fn sleep_duration(next: SystemTime) -> Duration {
    next.duration_since(SystemTime::now()).unwrap_or_default().min(LOOP_TICK)
}

/// Moves everything [`NodeHost::send_wire`] queued onto the wire.
async fn flush_datagrams(wire: &UdpWire, shared: &Arc<RuntimeShared>) {
    loop {
        let Some(datagram) = shared.queue.lock().pop_front() else { return };
        let socket = socket_index(shared, datagram.remote, datagram.local_socket);
        if let Err(err) = wire.send(WirePath { remote: datagram.remote, socket }, &datagram.packet).await {
            debugln!("[ZeroTier]({}) send {} bytes to {}: {err}", shared.name, datagram.packet.len(), datagram.remote);
        }
    }
}

/// The engine's handle names the socket a path was learned on; a handle without a socket of its
/// own (`ANY_LOCAL_SOCKET`) picks one by address family.
fn socket_index(shared: &Arc<RuntimeShared>, remote: SocketAddr, local_socket: i64) -> usize {
    let endpoints = shared.endpoints.lock();
    if local_socket >= 0 {
        let index = usize::try_from(local_socket).unwrap_or(usize::MAX);
        if index < endpoints.len() {
            return index;
        }
    }
    endpoints.iter().position(|endpoint| endpoint.is_ipv6() == remote.is_ipv6()).unwrap_or(0)
}

/// bound non-wildcard endpoints plus every up, non-loopback
/// interface address carrying the port this node bound for its family.
async fn refresh_direct_paths(shared: &Arc<RuntimeShared>, interface_name: &str) {
    let mut paths = Vec::new();
    let mut ports_v4 = Vec::new();
    let mut ports_v6 = Vec::new();
    for endpoint in shared.endpoints.lock().iter().copied() {
        if endpoint.port() == 0 {
            continue;
        }
        if !endpoint.ip().is_unspecified() {
            paths.push(endpoint);
        } else if endpoint.is_ipv6() {
            ports_v6.push(endpoint.port());
        } else {
            ports_v4.push(endpoint.port());
        }
    }
    if ports_v4.is_empty() && ports_v6.is_empty() {
        *shared.direct_paths.lock() = paths;
        return;
    }
    let interfaces = match interfaces().await {
        Ok(interfaces) => interfaces,
        Err(err) => {
            debugln!("[ZeroTier]({}) enumerate interfaces for direct paths: {err}", shared.name);
            *shared.direct_paths.lock() = paths;
            return;
        }
    };
    for interface in interfaces.values() {
        let usable =
            interface.flags.contains(anet::Flags::FLAG_UP) && !interface.flags.contains(anet::Flags::FLAG_LOOPBACK);
        if !usable
            || (!interface_name.is_empty() && interface.name != interface_name)
            || interface_blacklisted(std::env::consts::OS, &interface.name)
        {
            continue;
        }
        for prefix in &interface.addresses {
            let address = unmap(prefix.addr());
            let ports = if address.is_ipv6() { &ports_v6 } else { &ports_v4 };
            for port in ports {
                paths.push(SocketAddr::new(address, *port));
            }
        }
    }
    *shared.direct_paths.lock() = paths;
}

fn interface_blacklisted(os: &str, name: &str) -> bool {
    match os {
        "linux" => {
            name.starts_with("lo") || name.starts_with("zt") || name.starts_with("tun") || name.starts_with("tap")
        }
        "macos" => {
            name.starts_with("feth")
                || name.starts_with("lo")
                || name.starts_with("zt")
                || name.starts_with("tun")
                || name.starts_with("tap")
                || name.starts_with("utun")
        }
        "freebsd" => name.starts_with("lo") || name.starts_with("zt"),
        "windows" => name.to_ascii_lowercase().starts_with("zerotier"),
        _ => false,
    }
}

fn unmap(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Handles a node event, minus the runtime generations this adapter never retires.
fn handle_node_event(shared: &Arc<ZeroTierShared>, host: &ZeroTierHost, node: &mut Node, event: &Event) {
    let outbound = &shared.outbound;
    match event.event_type {
        EventType::NodeDown => debugln!("[ZeroTier]({outbound}) node {} shut down", event.node_address),
        EventType::NodeUp => {
            if is_ad_hoc_network_id(shared.network_id) {
                infoln!("[ZeroTier]({outbound}) node {} initialized", event.node_address);
            } else {
                infoln!(
                    "[ZeroTier]({outbound}) node {} initialized; authorize this ID on network {:016x}",
                    event.node_address,
                    shared.network_id
                );
            }
        }
        EventType::NodeOnline => {
            infoln!("[ZeroTier]({outbound}) node {} is online via {:?}", event.node_address, event.endpoint);
        }
        EventType::NodeOffline => warnln!("[ZeroTier]({outbound}) node {} is offline", event.node_address),
        EventType::NodeIdentityCollision => {
            let err = Arc::new(anyhow!(
                "ZeroTier identity {} collided and the engine exposes no identity rotation (ZT.RotateIdentityState)",
                event.node_address
            ));
            warnln!("[ZeroTier]({outbound}) {err}");
            shared.set_network_failure(Some(err), "");
        }
        EventType::PeerIdentityLearned => handle_peer_identity(shared, host, node, event),
        EventType::PeerPathLearned => log_peer_path(shared, event),
        EventType::PeerRouteChanged => log_peer_route(shared, event),
        EventType::LocalSurfaceChanged => {
            debugln!(
                "[ZeroTier]({outbound}) external surface changed {:?} -> {:?} after report from {} root {}; revalidating {} paths",
                event.previous_endpoint,
                event.endpoint,
                event.peer_role.name(),
                event.reporter_address,
                event.path_count
            );
        }
        EventType::NetworkConfigPending => {
            debugln!("[ZeroTier]({outbound}) requesting configuration for network {:016x}", event.network_id);
        }
        EventType::NetworkConfigReady => {
            if !shared.clear_logged_failure() {
                return;
            }
            if is_ad_hoc_network_id(event.network_id) {
                infoln!("[ZeroTier]({outbound}) network {:016x} ad-hoc configuration created", event.network_id);
            } else {
                infoln!("[ZeroTier]({outbound}) network {:016x} controller configuration accepted", event.network_id);
            }
        }
        EventType::NetworkConfigChanged => {
            if !shared.clear_logged_failure() {
                return;
            }
            debugln!("[ZeroTier]({outbound}) network {:016x} configuration update accepted", event.network_id);
        }
        EventType::NetworkAccessDenied => handle_access_denied(shared, event),
        EventType::NetworkNotFound => handle_network_not_found(shared, event),
        EventType::NetworkAuthenticationRequired => handle_authentication_required(shared, event),
        EventType::NetworkLeft => handle_network_left(shared, event),
    }
}

fn handle_access_denied(shared: &Arc<ZeroTierShared>, event: &Event) {
    let err = Arc::new(anyhow!("ZeroTier network access denied"));
    if shared.invalidate_network(Some(err), "") {
        warnln!("[ZeroTier]({}) network {:016x} access denied", shared.outbound, event.network_id);
    }
}

fn handle_network_not_found(shared: &Arc<ZeroTierShared>, event: &Event) {
    let message = if is_ad_hoc_network_id(event.network_id) {
        "unsupported ZeroTier ad-hoc network ID"
    } else {
        "ZeroTier network not found or controller unsupported"
    };
    let err = Arc::new(anyhow!("{message}"));
    if shared.invalidate_network(Some(err), "") {
        warnln!("[ZeroTier]({}) network {:016x}: {message}", shared.outbound, event.network_id);
    }
}

fn handle_authentication_required(shared: &Arc<ZeroTierShared>, event: &Event) {
    match login_url(&event.authentication) {
        Ok(url) => {
            if shared.invalidate_network(None, &url) {
                infoln!(
                    "[ZeroTier]({}) network {:016x} authentication required; complete login at {url}",
                    shared.outbound,
                    event.network_id
                );
            }
        }
        Err(err) => {
            let err = Arc::new(anyhow!("ZeroTier network authentication required: {err}"));
            if shared.invalidate_network(Some(Arc::clone(&err)), "") {
                warnln!("[ZeroTier]({}) network {:016x}: {err}", shared.outbound, event.network_id);
            }
        }
    }
}

fn handle_network_left(shared: &Arc<ZeroTierShared>, event: &Event) {
    let err = Arc::new(anyhow!("ZeroTier network was left"));
    if shared.invalidate_network(Some(err), "") {
        warnln!("[ZeroTier]({}) network {:016x} was left", shared.outbound, event.network_id);
    }
}

/// The reported identity is filed with the host so later sessions reuse it.
fn handle_peer_identity(shared: &Arc<ZeroTierShared>, host: &ZeroTierHost, node: &mut Node, event: &Event) {
    let outbound = &shared.outbound;
    if let Some(identity) = node.peer_identity(event.peer_address, SystemTime::now()) {
        host.shared.learn(identity);
    }
    if event.peer_role == PeerRole::Leaf {
        debugln!("[ZeroTier]({outbound}) loaded peer identity {}", event.peer_address);
    } else {
        debugln!("[ZeroTier]({outbound}) loaded {} root identity {}", event.peer_role.name(), event.peer_address);
    }
}

fn log_peer_path(shared: &Arc<ZeroTierShared>, event: &Event) {
    debugln!(
        "[ZeroTier]({}) {} {} authenticated path {:?}",
        shared.outbound,
        event.peer_role.name(),
        event.peer_address,
        event.endpoint
    );
}

fn log_peer_route(shared: &Arc<ZeroTierShared>, event: &Event) {
    match event.route {
        PeerRoute::Direct => {
            if let Some(endpoint) = event.endpoint {
                debugln!(
                    "[ZeroTier]({}) peer {} selected direct route via {endpoint}",
                    shared.outbound,
                    event.peer_address
                );
            } else {
                debugln!(
                    "[ZeroTier]({}) peer {} selected {} direct paths",
                    shared.outbound,
                    event.peer_address,
                    event.path_count
                );
            }
        }
        PeerRoute::Relayed => {
            debugln!("[ZeroTier]({}) peer {} selected upstream relay route", shared.outbound, event.peer_address);
        }
        PeerRoute::Unknown => {
            debugln!("[ZeroTier]({}) peer {} selected an unknown route", shared.outbound, event.peer_address);
        }
    }
}

fn login_url(info: &NetworkAuthenticationInfo) -> Result<String> {
    if info.version == 1 {
        return Err(anyhow!("ZeroTier SSO v1 OIDC authentication is unsupported"));
    }
    if info.authentication_url.is_empty() {
        return Err(anyhow!("ZeroTier authentication URL is unavailable"));
    }
    if !is_http_url(&info.authentication_url) {
        return Err(anyhow!("invalid ZeroTier authentication URL"));
    }
    Ok(info.authentication_url.clone())
}

/// Whether this value parses as an HTTP URL with a non-empty host.
fn is_http_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("https://").or_else(|| lower.strip_prefix("http://")) else {
        return false;
    };
    !rest.split(['/', '?', '#']).next().unwrap_or_default().is_empty()
}

/// Bounds the packets a stack reader queues for the runtime loop.
const STACK_QUEUE_DEPTH: usize = 2048;

/// The outcome of applying a network configuration.
enum ApplyOutcome {
    Stale,
    Failed(anyhow::Error),
    /// The configuration is installed; a replaced device carries the reader the loop drains.
    Installed(Option<NetworkStack>),
}

/// The stack device plus the channel its reader thread feeds. The reader gets its own
/// thread because `IpStack::read` blocks and the runtime thread is a current-thread runtime.
struct NetworkStack {
    device: Arc<dyn IpStack>,
    packets: std::sync::mpsc::Receiver<Vec<u8>>,
}

impl NetworkStack {
    /// The read half of the stack pump. Closing the device ends the thread, which is what device
    /// invalidation relies on.
    fn spawn(device: Arc<dyn IpStack>) -> Self {
        let (sender, packets) = std::sync::mpsc::sync_channel(STACK_QUEUE_DEPTH);
        let reader = Arc::clone(&device);
        let spawned = std::thread::Builder::new().name("zerotier-stack".to_owned()).spawn(move || {
            let batch = reader.batch_size().max(1);
            let mtu = reader.mtu().map_or(64 * 1024, |mtu| usize::try_from(mtu).unwrap_or(usize::MAX)).max(1);
            let mut buffers = vec![vec![0u8; mtu]; batch];
            let mut sizes = vec![0usize; batch];
            loop {
                let count = match reader.read(&mut buffers, &mut sizes, 0) {
                    Ok(count) => count,
                    Err(err) => {
                        debugln!("read from the ZeroTier IP stack device: {err}");
                        return;
                    }
                };
                for (buffer, size) in buffers.iter().zip(&sizes).take(count) {
                    let Some(payload) = buffer.get(..(*size).min(mtu)) else {
                        debugln!("the ZeroTier IP stack device reported {size} bytes, more than the buffer holds");
                        return;
                    };
                    if sender.send(payload.to_vec()).is_err() {
                        return;
                    }
                }
            }
        });
        if let Err(err) = spawned {
            errorln!("spawn the ZeroTier IP stack reader: {err}");
        }
        Self { device, packets }
    }
}

/// the device-generation dance, the IP link configuration and
/// the reader the runtime loop drains. the post-validation rollback is absent because this
/// adapter applies configurations serially on the runtime thread, so no generation can change
/// under the call.
fn apply_network_config(
    shared: &Arc<ZeroTierShared>,
    node: &mut Node,
    inputs: &RuntimeInputs,
    config: &NetworkConfigData,
    generation: u64,
) -> ApplyOutcome {
    if !snapshot_current(shared, config, generation) {
        return ApplyOutcome::Stale;
    }
    if config.assigned.is_empty() {
        return ApplyOutcome::Failed(anyhow!("ZeroTier controller assigned no managed addresses"));
    }
    let mtu = effective_mtu(config, inputs.mtu);
    let (old_device, old_config, link) = {
        let state = shared.state.lock();
        (state.device.clone(), state.config.clone(), state.link.clone())
    };
    let Some(link) = link else {
        return ApplyOutcome::Failed(anyhow!("ZeroTier IP link is not installed"));
    };
    // The installed device is kept while the managed addresses and the effective MTU are stable.
    let replace_device = old_device.is_none()
        || old_config
            .as_ref()
            .is_none_or(|old| !old.managed_addresses_equal(config) || effective_mtu(old, inputs.mtu) != mtu);
    let device = if replace_device {
        match new_ip_stack(inputs.ip_stack.clone(), config.assigned.clone(), mtu) {
            Ok(device) => device,
            Err(err) => return ApplyOutcome::Failed(anyhow!("create ZeroTier stack device: {err}")),
        }
    } else {
        let Some(device) = old_device.clone() else {
            return ApplyOutcome::Failed(anyhow!("ZeroTier network configuration has no retained stack device"));
        };
        device
    };
    let applied = link.lock().apply_network_config(node, config, mtu);
    if let Err(err) = applied {
        if replace_device {
            let _ = device.close();
        }
        return ApplyOutcome::Failed(anyhow!("apply ZeroTier network configuration: {err}"));
    }
    {
        let mut state = shared.state.lock();
        state.config = Some(config.clone());
        state.device = Some(Arc::clone(&device));
        state.network_err = None;
        state.auth_url = String::new();
    }
    shared.notify();
    infoln!(
        "[ZeroTier]({}) joined network {:016x} ({}), addresses={:?} routes={} mtu={mtu}",
        shared.outbound,
        config.network_id,
        config.name,
        config.assigned,
        config.routes.len()
    );
    if !replace_device {
        return ApplyOutcome::Installed(None);
    }
    if let Some(old) = old_device {
        let _ = old.close();
    }
    ApplyOutcome::Installed(Some(NetworkStack::spawn(device)))
}

/// Reports whether the snapshot matches the current generation, dropping the runtime comparison
/// because a runtime is never replaced.
fn snapshot_current(shared: &Arc<ZeroTierShared>, config: &NetworkConfigData, generation: u64) -> bool {
    let state = shared.state.lock();
    state.generation == generation && state.latest_config.as_ref().is_some_and(|latest| latest.equal(config))
}

/// Queues a network configuration and wakes the worker that applies it.
fn handle_network_config(
    shared: &Arc<ZeroTierShared>,
    node: &mut Node,
    inputs: &RuntimeInputs,
    config: &NetworkConfigData,
    stack: &mut Option<NetworkStack>,
) {
    let accepted = node
        .network(config.network_id)
        .is_some_and(|network| network.status == NetworkStatus::Ok && network.config.equal(config));
    if !accepted {
        return;
    }
    let generation = {
        let mut state = shared.state.lock();
        state.latest_config = Some(config.clone());
        state.generation
    };
    shared.notify();
    match apply_network_config(shared, node, inputs, config, generation) {
        ApplyOutcome::Stale => {}
        ApplyOutcome::Failed(err) => {
            if !snapshot_current(shared, config, generation) {
                return;
            }
            let err = Arc::new(err);
            errorln!("[ZeroTier]({}) apply network configuration: {err}", shared.outbound);
            shared.set_network_failure(Some(err), "");
        }
        ApplyOutcome::Installed(installed) => {
            if let Some(installed) = installed {
                *stack = Some(installed);
            }
        }
    }
}

/// the installed device for a destination the link accepts.
fn network_stack_for(shared: &Arc<ZeroTierShared>, destination: IpAddr) -> Result<Arc<dyn IpStack>> {
    let (device, link, network_err) = {
        let state = shared.state.lock();
        (state.device.clone(), state.link.clone(), state.network_err.clone())
    };
    if let Some(err) = network_err {
        return Err(anyhow!("{err}"));
    }
    let Some(device) = device else {
        return Err(anyhow!("ZeroTier stack is not ready"));
    };
    let Some(link) = link else {
        return Err(anyhow!("ZeroTier IP link is not ready"));
    };
    link.lock().validate_destination(destination)?;
    let current = {
        let state = shared.state.lock();
        state.network_err.is_none() && state.device.as_ref().is_some_and(|installed| Arc::ptr_eq(installed, &device))
    };
    if !current {
        return Err(anyhow!("ZeroTier stack changed while validating destination"));
    }
    Ok(device)
}

/// The zero source address: let the stack pick.
const fn unspecified_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
}

/// Resolves through the resolver and dials the validated destination.
struct ZeroTierNetDialer {
    shared: Arc<ZeroTierShared>,
}

#[async_trait]
impl NetDialer for ZeroTierNetDialer {
    async fn dial_context(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> Result<Box<dyn murmur_common_net::io::Stream>> {
        let destination: SocketAddr = address.parse().map_err(|err| anyhow!("invalid address {address:?}: {err}"))?;
        let device = network_stack_for(&self.shared, destination.ip())?;
        let conn = if network.starts_with("tcp") {
            device.dial_tcp(ctx, network, unspecified_addr(), destination).await?
        } else if network.starts_with("udp") {
            device.dial_udp(ctx, network, unspecified_addr(), destination).await?
        } else {
            return Err(anyhow!("invalid network {network:?}"));
        };
        Ok(Box::new(murmur_common_net::io::OldConnAsStream(conn)))
    }
}

/// A datagram socket that refuses a destination the link no longer accepts.
struct ValidatedDatagram {
    inner: Arc<dyn Datagram>,
    shared: Arc<ZeroTierShared>,
}

#[async_trait]
impl Datagram for ValidatedDatagram {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        network_stack_for(&self.shared, addr.ip()).map_err(|err| std::io::Error::other(err.to_string()))?;
        self.inner.send_to(buf, addr).await
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn close(&self) -> std::io::Result<()> {
        self.inner.close()
    }
}

fn effective_mtu(config: &NetworkConfigData, configured: i32) -> u32 {
    let mut mtu = if config.mtu == 0 { DEFAULT_NETWORK_MTU } else { config.mtu };
    mtu = mtu.clamp(MIN_NETWORK_MTU, MAX_NETWORK_MTU);
    if let Ok(configured) = u32::try_from(configured) {
        if configured != 0 && configured < mtu {
            mtu = configured;
        }
    }
    mtu
}

/// The construction-time validation, including the engine seams this adapter refuses to run
/// without.
fn validate_options(option: &mut ZeroTierOption) -> Result<ValidatedOptions> {
    let network_id = parse_network_id(&option.network)?;
    let identity = parse_identity_secret(&option.identity_secret)?;
    validate_network_mtu(option.mtu)?;
    validate_physical_mtu(option.physical_mtu)?;
    if option.physical_mtu != 0 {
        return Err(anyhow!(
            "ZeroTier physical MTU is not configurable: the engine's Node::new hard-codes the pub(crate) physical_mtu field (crates/zerotier/src/node/mod.rs) and exposes no setter"
        ));
    }
    if !option.planet.is_empty() {
        read_planet(&option.planet)?;
        return Err(anyhow!(
            "ZeroTier planet files are not supported: the engine installs only its embedded planet (Node::open adopts a stored world only when its ID equals the embedded planet's, crates/zerotier/src/node/mod.rs) and exposes no planet setter"
        ));
    }
    let orbits = parse_orbits(&option.orbit)?;
    let fallback = TcpFallbackMode::parse(&option.tcp_fallback_mode)?;
    if fallback == TcpFallbackMode::Force {
        return Err(anyhow!(
            "ZeroTier TCP fallback is not implemented in the engine: it has no tcpfallback module or transport dialer, so tcp-fallback-mode \"force\" cannot be honored"
        ));
    }
    fallback.name().clone_into(&mut option.tcp_fallback_mode);
    if option.tcp_fallback_relay.is_empty() {
        DEFAULT_TCP_FALLBACK_RELAY.clone_into(&mut option.tcp_fallback_relay);
    }
    option.ip_stack.normalize();
    option.ip_stack.validate()?;
    if option.low_bandwidth {
        return Err(anyhow!(
            "ZeroTier low-bandwidth is not configurable: the engine's Node::new hard-codes the pub(crate) low_bandwidth field (crates/zerotier/src/node/mod.rs) and exposes no setter"
        ));
    }
    if option.encrypted_hello {
        return Err(anyhow!(
            "ZeroTier encrypted-hello is not configurable: the engine's Node::new hard-codes the pub(crate) encrypted_hello field (crates/zerotier/src/node/mod.rs) and exposes no setter"
        ));
    }
    if !option.remote_trace_target.is_empty() {
        let target = Address::parse(&option.remote_trace_target);
        match target {
            Ok(target) if !target.is_reserved() => {
                return Err(anyhow!(
                    "ZeroTier remote tracing is not implemented in the engine: the node has no remote trace target or level (ZT.NodeConfig.RemoteTraceTarget)"
                ));
            }
            _ => return Err(anyhow!("ZeroTier remote trace target must be a 10-digit node ID")),
        }
    }
    if option.remote_trace_level > TRACE_LEVEL_INSANE {
        return Err(anyhow!("ZeroTier remote trace level must be between 0 and {TRACE_LEVEL_INSANE}"));
    }
    if option.remote_dns_resolve && !option.dns.is_empty() {
        let parse_name_server =
            PARSE_NAME_SERVER.get().ok_or_else(|| anyhow!("ZeroTier dns: dns.ParseNameServer is not configured"))?;
        parse_name_server(&option.dns)?;
    }
    if option.state_dir.is_empty() {
        let instance = Sha256::digest(option.name.as_bytes());
        let short_id = instance.get(..6).unwrap_or_default();
        option.state_dir = format!("{DEFAULT_STATE_DIR}/{}-{}", option.network, hex::encode(short_id));
    }
    let state_dir = PATH.resolve(&option.state_dir);
    if !PATH.is_safe_path(&state_dir) {
        return Err(PATH.err_not_safe_path(&state_dir).into());
    }
    let primary_port = validate_primary_port(option.primary_port)?;
    let secondary_port = validate_secondary_port(option.primary_port, option.secondary_port)?;
    validate_tcp_fallback_relay(&option.tcp_fallback_relay)?;
    Ok(ValidatedOptions { network_id, identity, orbits, state_dir, primary_port, secondary_port })
}

/// Parses an identity secret, applying the private-key and validity checks construction applies.
fn parse_identity_secret(secret: &str) -> Result<Option<Identity>> {
    if secret.is_empty() {
        return Ok(None);
    }
    let identity = Identity::parse(secret).map_err(|err| anyhow!("parse ZeroTier identity-secret: {err}"))?;
    if !identity.has_private() {
        return Err(anyhow!("ZeroTier identity-secret must contain private keys"));
    }
    identity.validate().map_err(|err| anyhow!("validate ZeroTier identity-secret: {err}"))?;
    Ok(Some(identity))
}

fn validate_network_mtu(mtu: i32) -> Result<()> {
    let bounds =
        i32::try_from(MIN_NETWORK_MTU).unwrap_or(i32::MIN)..=i32::try_from(MAX_NETWORK_MTU).unwrap_or(i32::MAX);
    if mtu != 0 && !bounds.contains(&mtu) {
        return Err(anyhow!("ZeroTier MTU must be between {MIN_NETWORK_MTU} and {MAX_NETWORK_MTU}"));
    }
    Ok(())
}

fn validate_physical_mtu(mtu: i32) -> Result<()> {
    let bounds =
        i32::try_from(MIN_PHYSICAL_MTU).unwrap_or(i32::MIN)..=i32::try_from(MAX_PHYSICAL_MTU).unwrap_or(i32::MAX);
    if mtu != 0 && !bounds.contains(&mtu) {
        return Err(anyhow!("ZeroTier physical MTU must be between {MIN_PHYSICAL_MTU} and {MAX_PHYSICAL_MTU}"));
    }
    Ok(())
}

/// Reads a planet world from the file `planet:` names.
fn read_planet(path: &str) -> Result<World> {
    let resolved = PATH.resolve(path);
    if !PATH.is_safe_path(&resolved) {
        return Err(PATH.err_not_safe_path(&resolved).into());
    }
    let data = std::fs::read(&resolved).map_err(|err| anyhow!("read ZeroTier planet: {err}"))?;
    World::parse_planet(&data).map_err(|err| anyhow!("parse ZeroTier planet: {err}"))
}

/// Parses every `orbit:` entry, rejecting a repeated world.
fn parse_orbits(options: &[ZeroTierOrbitOption]) -> Result<Vec<ZeroTierOrbit>> {
    let mut orbits = Vec::with_capacity(options.len());
    let mut visited = Vec::with_capacity(options.len());
    for option in options {
        let (world, seed) = parse_orbit(&option.world, &option.seed)?;
        if visited.contains(&world) {
            return Err(anyhow!("duplicate ZeroTier orbit world {world:016x}"));
        }
        visited.push(world);
        orbits.push(ZeroTierOrbit { world, seed });
    }
    Ok(orbits)
}

/// Validates the primary port.
fn validate_primary_port(port: i32) -> Result<u16> {
    u16::try_from(port).map_err(|_| anyhow!("ZeroTier primary port must be between 0 and 65535"))
}

/// The secondary-port rules, where `-1` means "no secondary socket" and `0` ("let the OS pick
/// one") collapses onto a single socket.
fn validate_secondary_port(primary: i32, secondary: i32) -> Result<u16> {
    if secondary == -1 {
        return Ok(0);
    }
    let port = u16::try_from(secondary).map_err(|_| anyhow!("ZeroTier secondary port must be between -1 and 65535"))?;
    if primary != 0 && primary == secondary {
        return Err(anyhow!("ZeroTier primary and secondary ports must differ"));
    }
    Ok(port)
}

/// The TCP fallback relay check.
fn validate_tcp_fallback_relay(relay: &str) -> Result<()> {
    let Some((host, port)) = relay.rsplit_once(':') else {
        return Err(anyhow!("invalid ZeroTier TCP fallback relay: address {relay} is missing a port"));
    };
    let unbracketed = host.contains(':') && !(host.starts_with('[') && host.ends_with(']'));
    let port = port.parse::<u16>().map_err(|_| anyhow!("invalid ZeroTier TCP fallback relay: bad port"))?;
    if host.is_empty() || unbracketed || port == 0 {
        return Err(anyhow!("invalid ZeroTier TCP fallback relay: host and port must be non-zero"));
    }
    Ok(())
}

/// Warns about the options the engine's wire cannot carry, as the other L3 outbounds do.
fn warn_about_wire_options(option: &ZeroTierOption) {
    let name = &option.name;
    if !option.basic_option.interface.is_empty() || option.basic_option.routing_mark != 0 {
        warnln!(
            "[ZeroTier]({name}) interface and routing-mark cannot carry the engine's UDP wire: it binds the wildcard address, so the physical sockets ignore them"
        );
    }
    if !option.basic_option.dialer_proxy.is_empty() {
        warnln!(
            "[ZeroTier]({name}) dialer-proxy only carried the TCP fallback relay, which the engine does not implement, so it has no effect"
        );
    }
    if option.tcp_fallback_mode == TcpFallbackMode::Auto.name() && option.primary_port != 0 {
        debugln!("[ZeroTier]({name}) tcp-fallback-mode auto behaves as disable: the engine has no TCP fallback");
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::time::Instant;

    use murmur_constant_features::WITH_GVISOR;
    use murmur_zerotier::dictionary::{append_dictionary_entry, append_dictionary_uint};
    use murmur_zerotier::frame::{Frame, FrameDestination, ETHER_TYPE_ARP, ETHER_TYPE_IPV4};
    use murmur_zerotier::mac::{mac_for_address, Mac};
    use murmur_zerotier::network_config::{NetworkType, NETWORK_CONFIG_VERSION};
    use murmur_zerotier::node::peer::path_scope;
    use murmur_zerotier::node::{network_state_name, StateStore};

    use super::*;

    const NETWORK: &str = "8056c2e21c000001";
    /// The ad-hoc network the two-node seam tests join without a controller; its low byte makes
    /// the engine synthesize an accept-all rule set (`node/mod.rs`, `configure_ad_hoc_network`).
    const SEAM_NETWORK: u64 = 0xff00_0000_0000_0001;
    /// A controller-managed network, whose configuration only a cached dictionary can supply.
    const CONTROLLER_NETWORK: u64 = 0x8056_c2e2_1c00_0001;
    const WIRE_TIMEOUT: Duration = Duration::from_secs(10);

    fn option_yaml(body: &str) -> String {
        format!("name: zt\nnetwork: {NETWORK}\n{body}")
    }

    /// `ip-stack: mips`, the one engine `new_ip_stack` serves, as `validate_options` normalizes it.
    fn mips_stack_option() -> IpStackOption {
        IpStackOption { mode: "mips".to_owned(), congestion_controller: String::new() }
    }

    fn build(body: &str) -> Result<Arc<ZeroTier>> {
        ZeroTier::new(serde_yaml::from_str(&option_yaml(body)).expect("option decodes"))
    }

    fn failure(body: &str) -> String {
        match build(body) {
            Ok(_) => panic!("{body} was accepted"),
            Err(err) => err.to_string(),
        }
    }

    /// Every tag an operator may write, including the ones the engine refuses to honor.
    #[test]
    fn option_decodes_every_wire_name() {
        let option: ZeroTierOption = serde_yaml::from_str(
            "name: zt\n\
             network: 8056c2e21c000001\n\
             state-dir: zt-state\n\
             identity-secret: secret\n\
             planet: planet.bin\n\
             mtu: 1400\n\
             ip-stack:\n  mode: mips\n  congestion-controller: reno\n\
             physical-mtu: 1400\n\
             udp: true\n\
             remote-dns-resolve: true\n\
             dns:\n  - 192.0.2.1\n\
             low-bandwidth: true\n\
             encrypted-hello: true\n\
             primary-port: 9993\n\
             secondary-port: 9994\n\
             tcp-fallback-mode: disable\n\
             tcp-fallback-relay: 192.0.2.2:443\n\
             orbit:\n  - world: 8056c2e21c000001\n    seed: 0f1b56d269\n\
             remote-trace-target: 0f1b56d269\n\
             remote-trace-level: 10\n\
             interface-name: eth0\n\
             routing-mark: 7\n\
             dialer-proxy: direct\n",
        )
        .expect("option decodes");

        assert_identity_fields(&option);
        assert_transport_fields(&option);
    }

    fn assert_identity_fields(option: &ZeroTierOption) {
        assert_eq!(option.name, "zt");
        assert_eq!(option.network, NETWORK);
        assert_eq!(option.state_dir, "zt-state");
        assert_eq!(option.identity_secret, "secret");
        assert_eq!(option.planet, "planet.bin");
        assert_eq!(option.mtu, 1400);
        assert_eq!(option.ip_stack.mode, "mips");
        assert_eq!(option.ip_stack.congestion_controller, "reno");
        assert_eq!(option.physical_mtu, 1400);
        assert_eq!(option.remote_trace_target, "0f1b56d269");
        assert_eq!(option.remote_trace_level, 10);
        assert_eq!(option.basic_option.interface, "eth0");
        assert_eq!(option.basic_option.routing_mark, 7);
    }

    fn assert_transport_fields(option: &ZeroTierOption) {
        assert!(option.udp);
        assert!(option.remote_dns_resolve);
        assert_eq!(option.dns, vec!["192.0.2.1".to_owned()]);
        assert!(option.low_bandwidth);
        assert!(option.encrypted_hello);
        assert_eq!(option.primary_port, 9993);
        assert_eq!(option.secondary_port, 9994);
        assert_eq!(option.tcp_fallback_mode, "disable");
        assert_eq!(option.tcp_fallback_relay, "192.0.2.2:443");
        assert_eq!(option.orbit.len(), 1);
        assert_eq!(option.orbit[0].world, NETWORK);
        assert_eq!(option.orbit[0].seed, "0f1b56d269");
        assert_eq!(option.basic_option.dialer_proxy, "direct");
    }

    /// The defaults for the fields construction fills in, plus the base the framework reads.
    #[test]
    fn new_applies_the_default_options() {
        let outbound = build("udp: true\n").expect("a minimal option is valid");
        let instance = Sha256::digest(b"zt");

        assert_eq!(outbound.option.tcp_fallback_mode, "auto");
        assert_eq!(outbound.option.tcp_fallback_relay, DEFAULT_TCP_FALLBACK_RELAY);
        assert_eq!(outbound.option.ip_stack.mode, "auto");
        assert_eq!(
            outbound.state_dir,
            PATH.resolve(&format!("{DEFAULT_STATE_DIR}/{NETWORK}-{}", hex::encode(&instance[..6])))
        );
        assert_ne!(outbound.state_dir, PATH.resolve(&format!("{DEFAULT_STATE_DIR}/{NETWORK}")));
        assert_eq!(outbound.primary_port, 0);
        assert_eq!(outbound.secondary_port, 0);
        assert_eq!(outbound.name(), "zt");
        assert_eq!(outbound.addr(), NETWORK);
        assert_eq!(outbound.type_(), AdapterType::ZERO_TIER);
        assert!(outbound.support_udp());
        assert!(outbound.is_l3_protocol(&Metadata::default()));
        assert_eq!(outbound.shared.network_id, 0x8056_c2e2_1c00_0001);
    }

    /// The state directory derived from the outbound name must differ per name.
    #[test]
    fn default_state_dir_follows_the_outbound_name() {
        let first = build("").expect("valid");
        let second =
            ZeroTier::new(serde_yaml::from_str(&format!("name: zt-two\nnetwork: {NETWORK}\n")).expect("decode"))
                .expect("valid");
        assert_ne!(first.state_dir, second.state_dir);
    }

    /// Every documented validation, and the options this adapter refuses instead of ignoring.
    #[test]
    fn invalid_and_unsupported_options_fail_closed() {
        let cases: [(&str, &str); 16] = [
            ("identity-secret: not-an-identity\n", "parse ZeroTier identity-secret"),
            ("mtu: 1000\n", "ZeroTier MTU must be between"),
            ("mtu: 20000\n", "ZeroTier MTU must be between"),
            ("physical-mtu: 100\n", "ZeroTier physical MTU must be between"),
            ("physical-mtu: 1400\n", "physical MTU is not configurable"),
            ("low-bandwidth: true\n", "low-bandwidth is not configurable"),
            ("encrypted-hello: true\n", "encrypted-hello is not configurable"),
            ("remote-trace-target: nope\n", "must be a 10-digit node ID"),
            ("remote-trace-target: 0f1b56d269\n", "remote tracing is not implemented"),
            ("remote-trace-level: 31\n", "ZeroTier remote trace level must be between"),
            ("tcp-fallback-mode: bogus\n", "invalid ZeroTier TCP fallback mode"),
            ("tcp-fallback-mode: force\n", "TCP fallback is not implemented"),
            ("tcp-fallback-relay: 192.0.2.2\n", "invalid ZeroTier TCP fallback relay"),
            ("tcp-fallback-relay: 192.0.2.2:0\n", "invalid ZeroTier TCP fallback relay"),
            ("primary-port: 70000\n", "ZeroTier primary port must be between 0 and 65535"),
            ("secondary-port: -2\n", "ZeroTier secondary port must be between -1 and 65535"),
        ];
        for (body, expected) in cases {
            let message = failure(body);
            assert!(message.contains(expected), "{body} reported {message}");
        }

        let bad_network = ZeroTier::new(ZeroTierOption {
            name: "zt".to_owned(),
            network: "not-a-network".to_owned(),
            ..Default::default()
        });
        assert_eq!(bad_network.err().map(|err| err.to_string()), Some("invalid ZeroTier network ID".to_owned()));
        assert_eq!(
            failure("primary-port: 9993\nsecondary-port: 9993\n"),
            "ZeroTier primary and secondary ports must differ"
        );
        assert_eq!(
            failure("orbit:\n  - world: 8056c2e21c000001\n    seed: 0f1b56d269\n  - world: 8056c2e21c000001\n    seed: 0f1b56d269\n"),
            "duplicate ZeroTier orbit world 8056c2e21c000001"
        );
        assert_eq!(
            failure("orbit:\n  - world: nope\n    seed: 0f1b56d269\n"),
            "ZeroTier orbit world must be a 16-digit hexadecimal ID"
        );
        if WITH_GVISOR {
            assert!(build("ip-stack:\n  mode: gvisor\n").is_ok(), "the build tag admits the gVisor mode");
        } else {
            assert_eq!(failure("ip-stack:\n  mode: gvisor\n"), "gVisor IP stack requires the with_gvisor build tag");
        }
    }

    /// `secondary-port: -1` disables the secondary socket, and an unset one binds the OS port.
    #[test]
    fn secondary_port_minus_one_disables_the_secondary_socket() {
        assert_eq!(build("secondary-port: -1\n").expect("valid").secondary_port, 0);
        assert_eq!(build("primary-port: 9993\nsecondary-port: 9994\n").expect("valid").primary_port, 9993);
        assert_eq!(build("primary-port: 9993\nsecondary-port: 9994\n").expect("valid").secondary_port, 9994);
    }

    /// The planet file is read before the node is built; this adapter refuses the install.
    #[test]
    fn a_planet_file_is_parsed_and_then_refused() {
        let planet = World::default_planet().expect("embedded planet").serialize().expect("serialize");
        let path = PathBuf::from(PATH.resolve("zerotier-test-planet.bin"));
        std::fs::write(&path, &planet).expect("write planet file");
        let message = failure("planet: zerotier-test-planet.bin\n");
        let _ = std::fs::remove_file(&path);
        assert!(message.contains("planet files are not supported"), "{message}");

        let garbage = PathBuf::from(PATH.resolve("zerotier-test-planet-garbage.bin"));
        std::fs::write(&garbage, b"not a world").expect("write garbage planet file");
        let message = failure("planet: zerotier-test-planet-garbage.bin\n");
        let _ = std::fs::remove_file(&garbage);
        assert!(message.contains("parse ZeroTier planet"), "{message}");
    }

    /// The state directory is resolved against the safe paths.
    #[test]
    fn an_unsafe_state_dir_is_refused() {
        if std::env::var("SKIP_SAFE_PATH_CHECK").is_ok_and(|value| value == "1" || value == "true") {
            return;
        }
        if murmur_constant_features::CMFA {
            // `cmfa` makes `Constant::Path::is_safe_path` short-circuit to true, so a refusal
            // cannot be observed in that build; the guard mirrors the crate-level
            // `cfg!(feature = "cmfa")` branch in `murmur-constant`'s own path test.
            return;
        }
        let message = failure("state-dir: /etc/zerotier-adapter-state-dir\n");
        assert!(message.contains("path is not subpath of home directory"), "{message}");
    }

    /// The host is the peer cache `NodeHost::peer_identity` consults, and it prunes by age.
    #[test]
    fn host_mirrors_learned_identities_and_prunes_them() {
        let shared = Arc::new(RuntimeShared::new("zt".to_owned()));
        let mut host = ZeroTierHost { shared: Arc::clone(&shared) };
        let identity = Identity::generate();
        let address = identity.address();

        assert!(host.peer_identity(address).is_none());
        shared.learn(identity.clone());
        assert_eq!(host.peer_identity(address).map(|known| known.address()), Some(address));

        host.clean_peer_cache(Duration::from_secs(3600)).expect("fresh entries survive");
        assert!(host.peer_identity(address).is_some());

        let stale = SystemTime::now() - Duration::from_secs(7200);
        shared.peers.lock().get_mut(&address).expect("learned entry").touched = stale;
        host.clean_peer_cache(Duration::from_secs(3600)).expect("stale entries prune");
        assert!(host.peer_identity(address).is_none());
    }

    /// A datagram the node hands the host must reach a real socket over loopback.
    #[tokio::test]
    async fn host_seam_carries_a_queued_datagram_over_loopback() {
        let shared = Arc::new(RuntimeShared::new("zt".to_owned()));
        let mut wire = UdpWire::bind(0, 0).await.expect("bind an ephemeral wire");
        *shared.endpoints.lock() = wire.local_endpoints().to_vec();
        let mut host = ZeroTierHost { shared: Arc::clone(&shared) };

        let bound = wire.local_endpoints().first().copied().expect("a bound endpoint");
        assert_ne!(bound.port(), 0);
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound.port());
        host.send_wire(ANY_LOCAL_SOCKET, target, b"zerotier-seam".to_vec()).expect("queue the datagram");
        flush_datagrams(&wire, &shared).await;

        let (data, source) = tokio::time::timeout(Duration::from_secs(5), wire.recv_from())
            .await
            .expect("the datagram arrives")
            .expect("the wire is open");
        assert_eq!(data, b"zerotier-seam");
        assert_eq!(source.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        refresh_direct_paths(&shared, "").await;
        let paths = host.direct_paths();
        assert!(
            paths.iter().all(|path| path.port() == bound.port() && !path.ip().is_loopback()),
            "direct paths advertise the bound port on interface addresses only: {paths:?}"
        );
    }

    /// An ad-hoc network needs no controller, so this drives the whole runtime: the UDP wire, the
    /// node build, the join, the configuration callback and the installed data plane.
    #[tokio::test]
    async fn an_ad_hoc_network_start_installs_the_data_plane() {
        let state_dir = format!("zerotier-test-ad-hoc-{}", std::process::id());
        let _ = std::fs::remove_dir_all(PATH.resolve(&state_dir));
        let outbound = ZeroTier::new(ZeroTierOption {
            name: "zt-ad-hoc".to_owned(),
            network: "ff0000ff00000000".to_owned(),
            state_dir: state_dir.clone(),
            ..Default::default()
        })
        .expect("an ad-hoc network ID is a valid option");
        let ctx = CancellationToken::new();
        outbound.ensure_started(&ctx).await.expect("the ad-hoc configuration applies");

        let assigned = {
            let state = outbound.shared.state.lock();
            assert!(state.device.is_some(), "the userspace IP stack is installed");
            assert!(state.link.is_some(), "the IP link is installed");
            state.config.clone().expect("the ad-hoc configuration is installed").assigned
        };
        for prefix in &assigned {
            assert!(
                network_stack_for(&outbound.shared, prefix.addr()).is_ok(),
                "the managed address {prefix} validates on the installed link"
            );
        }
        outbound.close().expect("close");
        let _ = std::fs::remove_dir_all(PATH.resolve(&state_dir));
    }

    /// The outbound is unusable after `close`, before any runtime exists.
    #[tokio::test]
    async fn a_closed_outbound_fails_closed() {
        let outbound = build("").expect("valid");
        outbound.close().expect("close");
        let ctx = CancellationToken::new();

        let dial = outbound.dial_context(&ctx, &mut Metadata::default()).await;
        assert!(
            dial.err().is_some_and(|err| err.to_string().contains(OUTBOUND_CLOSED)),
            "dial after close reports the closed outbound"
        );
        assert!(outbound.ensure_started(&ctx).await.is_err());
        assert!(outbound.close().is_ok());
    }

    /// Waits until a runtime thread has returned, so a test pins what a stopped runtime leaves
    /// behind instead of a timing window.
    fn wait_for_thread_exit(thread: &std::thread::JoinHandle<()>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !thread.is_finished() {
            assert!(Instant::now() < deadline, "the runtime thread did not return");
            std::thread::yield_now();
        }
    }

    fn ad_hoc_outbound(name: &str, state_dir: &str) -> Arc<ZeroTier> {
        ZeroTier::new(ZeroTierOption {
            name: name.to_owned(),
            network: "ff0000ff00000000".to_owned(),
            state_dir: state_dir.to_owned(),
            ..Default::default()
        })
        .expect("an ad-hoc network ID is a valid option")
    }

    /// A handle whose thread has already returned must not be reported as a running node.
    #[tokio::test]
    async fn a_start_after_the_runtime_thread_stopped_starts_a_new_runtime() {
        let state_dir = format!("zerotier-test-stopped-{}", std::process::id());
        let _ = std::fs::remove_dir_all(PATH.resolve(&state_dir));
        let outbound = ad_hoc_outbound("zt-stopped", &state_dir);
        let stopped = RuntimeHandle { cancel: outbound.ctx.child_token(), thread: std::thread::spawn(|| {}) };
        wait_for_thread_exit(&stopped.thread);
        *outbound.runtime.lock() = Some(stopped);

        outbound.start().await.expect("the stopped runtime is replaced by a live one");
        assert!(
            outbound.runtime.lock().as_ref().is_some_and(|handle| !handle.thread.is_finished()),
            "start must leave a live runtime, not the dead handle it found"
        );

        outbound.close().expect("close");
        let _ = std::fs::remove_dir_all(PATH.resolve(&state_dir));
    }

    /// Only a host that is not already an address is resolved.
    #[tokio::test]
    async fn resolve_udp_leaves_resolved_metadata_alone() {
        let outbound = build("").expect("valid");
        let mut metadata = Metadata {
            host: "127.0.0.2".to_owned(),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            ..Default::default()
        };
        outbound
            .resolve_udp(&CancellationToken::new(), &mut metadata)
            .await
            .expect("an already resolved host needs no lookup");
        assert_eq!(metadata.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))));
    }

    /// One node built from the adapter's own runtime pieces and wired to a real UDP socket, so a
    /// test can pump it the way `run_runtime` does.
    struct SeamNode {
        node: Node,
        host: ZeroTierHost,
        shared: Arc<RuntimeShared>,
        state: Arc<ZeroTierShared>,
        wire: UdpWire,
        identity: Identity,
        endpoint: SocketAddr,
        received_from: Option<SocketAddr>,
        state_dir: PathBuf,
    }

    /// The engine drops loopback endpoints as paths (`node/peer.rs:530`), so a peer must be
    /// dialled at an address of the host's own interfaces.
    async fn local_path_address() -> IpAddr {
        let interfaces = interfaces().await.expect("enumerate the host interfaces");
        interfaces
            .values()
            .filter(|interface| {
                interface.flags.contains(anet::Flags::FLAG_UP) && !interface.flags.contains(anet::Flags::FLAG_LOOPBACK)
            })
            .filter(|interface| !interface_blacklisted(std::env::consts::OS, &interface.name))
            .flat_map(|interface| interface.addresses.iter())
            .map(|prefix| unmap(prefix.addr()))
            .find(|address| address.is_ipv4() && path_scope(*address) != 0)
            .expect("the host has a non-loopback IPv4 address")
    }

    /// Supplies the identities a WHOIS exchange would have, as the engine's own two-node test
    /// seeds its hosts.
    fn introduce(a: &SeamNode, b: &SeamNode) {
        a.shared.learn(b.identity.clone());
        b.shared.learn(a.identity.clone());
    }

    impl SeamNode {
        async fn new(name: &str, network_id: u64) -> Self {
            let identity = Identity::generate();
            let state_dir = std::env::temp_dir().join(format!("zt-seam-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&state_dir);
            let shared = Arc::new(RuntimeShared::new(name.to_owned()));
            let host = ZeroTierHost { shared: Arc::clone(&shared) };
            let inputs = RuntimeInputs {
                network_id,
                configured_identity: Some(identity.clone()),
                orbits: Vec::new(),
                state_dir: state_dir.to_string_lossy().into_owned(),
                primary_port: 0,
                secondary_port: 0,
                mtu: 0,
                interface_name: String::new(),
                ip_stack: mips_stack_option(),
            };
            let mut node = inputs.build_node(&host).expect("the adapter builds a node");
            node.join(network_id, SystemTime::now()).expect("the node joins the network");
            let wire = UdpWire::bind(0, 0).await.expect("bind an ephemeral wire");
            *shared.endpoints.lock() = wire.local_endpoints().to_vec();
            let bound = wire.local_endpoints().first().copied().expect("a bound endpoint");
            let endpoint = SocketAddr::new(local_path_address().await, bound.port());
            Self {
                node,
                host,
                shared,
                state: Arc::new(ZeroTierShared::new(name.to_owned(), network_id)),
                wire,
                identity,
                endpoint,
                received_from: None,
                state_dir,
            }
        }

        async fn flush(&self) {
            flush_datagrams(&self.wire, &self.shared).await;
        }

        async fn receive(&mut self) -> (Vec<u8>, SocketAddr) {
            tokio::time::timeout(WIRE_TIMEOUT, self.wire.recv_from())
                .await
                .expect("the peer's datagram crosses the loopback wire")
                .expect("the wire is open")
        }

        /// The runtime's inbound half: the node processes the datagram, then the adapter handles
        /// the events it emitted, which is how `RuntimeShared` mirrors peer identities.
        fn feed(&mut self, source: SocketAddr, data: &[u8]) -> Result<(), NodeError> {
            self.received_from = Some(source);
            let result = self.node.process_wire_packet(ANY_LOCAL_SOCKET, source, data, SystemTime::now());
            for event in self.node.take_events() {
                handle_node_event(&self.state, &self.host, &mut self.node, &event);
            }
            result
        }
    }

    /// Carries datagrams both ways until both wires fall quiet, so a reply that provokes a reply
    /// is carried too.
    async fn settle(a: &mut SeamNode, b: &mut SeamNode) {
        let deadline = Instant::now() + WIRE_TIMEOUT;
        loop {
            a.flush().await;
            b.flush().await;
            let mut moved = false;
            for _ in 0..4 {
                let from_b = tokio::time::timeout(Duration::from_millis(50), b.wire.recv_from()).await;
                if let Ok(Some((data, source))) = from_b {
                    let _ = b.feed(source, &data);
                    moved = true;
                }
                let from_a = tokio::time::timeout(Duration::from_millis(50), a.wire.recv_from()).await;
                if let Ok(Some((data, source))) = from_a {
                    let _ = a.feed(source, &data);
                    moved = true;
                }
            }
            if !moved {
                return;
            }
            assert!(Instant::now() < deadline, "the nodes never stopped exchanging datagrams");
        }
    }

    /// Two nodes built through the adapter's own runtime inputs and host seam, with every
    /// datagram travelling a real UDP socket before the other node sees it.
    #[tokio::test]
    async fn two_zerotier_seam_nodes_learn_each_others_paths_over_real_udp_wires() {
        let mut a = SeamNode::new("zt-seam-a", SEAM_NETWORK).await;
        let mut b = SeamNode::new("zt-seam-b", SEAM_NETWORK).await;
        introduce(&a, &b);

        a.node
            .send_hello_locked(b.node.address(), b.endpoint, SystemTime::now())
            .expect("A queues a HELLO for B's socket");
        settle(&mut a, &mut b).await;

        assert_eq!(
            b.host.peer_identity(a.node.address()).map(|identity| identity.address()),
            Some(a.node.address()),
            "B mirrored A's identity into the adapter's peer cache"
        );
        let now = SystemTime::now();
        let peer = a.node.peers(now).into_iter().find(|peer| peer.address == b.node.address()).expect("A knows B");
        assert_eq!(peer.paths.len(), 1, "the handshake established one direct path");
        assert_eq!(Some(peer.paths[0].endpoint), a.received_from, "the path is B's wire socket");
        assert!(peer.paths[0].preferred && peer.paths[0].active);
        assert_eq!(a.node.best_peer_endpoint(b.node.address(), now), a.received_from);
        assert!(b.node.peers(now).iter().any(|peer| peer.address == a.node.address()), "B knows A");

        let _ = std::fs::remove_dir_all(&a.state_dir);
        let _ = std::fs::remove_dir_all(&b.state_dir);
    }

    /// A controller configuration reaching the adapter's own network-config worker, which
    /// installs the IP link and the stack device its managed address needs.
    #[tokio::test]
    async fn a_controller_configuration_installs_the_data_plane() {
        let identity = Identity::generate();
        let state_dir = std::env::temp_dir().join(format!("zt-config-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state_dir);
        let mut store = FileStore::new(&state_dir);
        store
            .put(&network_state_name(CONTROLLER_NETWORK), &controller_config(CONTROLLER_NETWORK, identity.address()))
            .expect("cache the configuration");

        let shared = Arc::new(RuntimeShared::new("zt-config".to_owned()));
        let host = ZeroTierHost { shared: Arc::clone(&shared) };
        let inputs = RuntimeInputs {
            network_id: CONTROLLER_NETWORK,
            configured_identity: Some(identity.clone()),
            orbits: Vec::new(),
            state_dir: state_dir.to_string_lossy().into_owned(),
            primary_port: 0,
            secondary_port: 0,
            mtu: 0,
            interface_name: String::new(),
            ip_stack: mips_stack_option(),
        };
        let mut node = inputs.build_node(&host).expect("the adapter builds a node");
        let state = Arc::new(ZeroTierShared::new("zt-config".to_owned(), CONTROLLER_NETWORK));
        let (config_tx, mut config_rx) = mpsc::unbounded_channel::<NetworkConfigData>();
        node.set_network_config_callback(Box::new(move |config| {
            let _ = config_tx.send(config.clone());
        }));

        node.join(CONTROLLER_NETWORK, SystemTime::now()).expect("the cached configuration is loaded");
        node.run_callbacks();
        let config = config_rx.try_recv().expect("the cached configuration reached the callback");
        assert_eq!(
            config.assigned.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["192.0.2.10/24"],
            "the controller's managed address was parsed"
        );

        let mut stack = None;
        // The runtime installs the link at startup (`run_runtime`); this worker runs without one.
        state.state.lock().link =
            Some(Arc::new(Mutex::new(Link::new(CONTROLLER_NETWORK, node.address()).expect("a valid network ID"))));
        handle_network_config(&state, &mut node, &inputs, &config, &mut stack);
        {
            let installed = state.state.lock();
            assert!(installed.network_err.is_none(), "the configuration applies: {:?}", installed.network_err);
            assert!(installed.config.is_some(), "the configuration is installed");
            assert!(installed.device.is_some(), "the userspace IP stack is installed");
            assert!(installed.link.is_some(), "the IP link is installed");
        }
        assert!(stack.is_some(), "the runtime loop owns a stack reader");
        assert!(
            network_stack_for(&state, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))).is_ok(),
            "the controller's managed address validates on the installed link"
        );

        let _ = std::fs::remove_dir_all(&state_dir);
    }

    /// The frame path end to end: A's node hands its joined network a frame, the datagram crosses
    /// a real socket to B, and B delivers the payload to its embedding.
    #[tokio::test]
    async fn a_virtual_frame_crosses_the_zerotier_wire_and_reaches_the_peer_node() {
        const PAYLOAD: &[u8] = b"zerotier-adapter-frame";
        let mut a = SeamNode::new("zt-frame-a", SEAM_NETWORK).await;
        let mut b = SeamNode::new("zt-frame-b", SEAM_NETWORK).await;
        introduce(&a, &b);
        a.node
            .send_hello_locked(b.node.address(), b.endpoint, SystemTime::now())
            .expect("A queues a HELLO for B's socket");
        settle(&mut a, &mut b).await;
        assert!(a.shared.queue.lock().is_empty(), "the handshake drained A's queue");

        let destination = mac_for_address(b.node.address(), SEAM_NETWORK);
        assert_eq!(
            Frame::classify_destination(destination, SEAM_NETWORK),
            FrameDestination::Node(b.node.address()),
            "the destination MAC names B on the joined network"
        );

        a.node
            .send_frame(SEAM_NETWORK, destination, ETHER_TYPE_IPV4, PAYLOAD, SystemTime::now())
            .expect("A's node accepts the frame for the joined network");
        assert_eq!(a.shared.queue.lock().len(), 1, "one FRAME datagram is queued");
        a.flush().await;
        let (wire, source) = b.receive().await;
        assert_eq!(Some(source), b.received_from, "the frame arrives from the socket that carried the handshake");

        b.feed(source, &wire).expect("B accepts the datagram");
        let delivered = b.node.take_delivered_frames();
        assert_eq!(delivered.len(), 1, "B delivered exactly one frame");
        assert_eq!(delivered[0].network_id, SEAM_NETWORK);
        assert_eq!(delivered[0].ether_type, ETHER_TYPE_IPV4);
        assert_eq!(delivered[0].source, mac_for_address(a.node.address(), SEAM_NETWORK));
        assert_eq!(delivered[0].destination, destination);
        assert_eq!(delivered[0].payload, PAYLOAD, "the payload crossed the wire intact");

        let _ = std::fs::remove_dir_all(&a.state_dir);
        let _ = std::fs::remove_dir_all(&b.state_dir);
    }

    /// The bridge end to end: an IP packet written into A's link crosses the node's frame plane,
    /// reaches B and comes back out of B's link.
    #[tokio::test]
    async fn an_ip_packet_written_to_the_link_reaches_the_peer_link_over_the_wire() {
        let mut a = SeamNode::new("zt-link-a", SEAM_NETWORK).await;
        let mut b = SeamNode::new("zt-link-b", SEAM_NETWORK).await;
        introduce(&a, &b);
        a.node
            .send_hello_locked(b.node.address(), b.endpoint, SystemTime::now())
            .expect("A queues a HELLO for B's socket");
        settle(&mut a, &mut b).await;

        // NDP emulation resolves a managed /40 peer without the resolution traffic the engine's
        // missing multicast plane would have to carry.
        let mut config = a.node.network(SEAM_NETWORK).expect("A joined the ad-hoc network").config.clone();
        config.flags |= murmur_zerotier::network_config::NETWORK_CONFIG_FLAG_ENABLE_IPV6_NDP_EMULATION;
        let mtu = config.mtu;
        let mut link_a = Link::new(SEAM_NETWORK, a.node.address()).expect("a link");
        link_a.apply_network_config(&mut a.node, &config, mtu).expect("A's link takes the configuration");
        let mut link_b = Link::new(SEAM_NETWORK, b.node.address()).expect("a link");
        link_b.apply_network_config(&mut b.node, &config, mtu).expect("B's link takes the configuration");

        let source = six_plane_octets(a.node.address());
        let destination = six_plane_octets(b.node.address());
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[6] = 59;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        packet[40..].copy_from_slice(b"payload!");

        link_a
            .write_packet(&mut a.node, &packet, SystemTime::now())
            .expect("A's link frames the packet for B's managed MAC");
        assert_eq!(a.shared.queue.lock().len(), 1, "one FRAME datagram is queued");
        a.flush().await;
        let (wire, from) = b.receive().await;
        b.feed(from, &wire).expect("B accepts the datagram");

        let delivered = b.node.take_delivered_frames();
        assert_eq!(delivered.len(), 1, "B delivered exactly one frame");
        assert_eq!(delivered[0].destination, mac_for_address(b.node.address(), SEAM_NETWORK));
        let received =
            link_b.handle_frame(&mut b.node, &delivered[0], SystemTime::now()).expect("B's link accepts the frame");
        assert_eq!(received, Some(packet), "the packet crossed the frame plane intact");

        let _ = std::fs::remove_dir_all(&a.state_dir);
        let _ = std::fs::remove_dir_all(&b.state_dir);
    }

    /// A broadcast frame from the link reaches the peer node: A's link emits an ARP request for
    /// B's managed IPv4, the node replicates it to the group B announced, and B's link answers it.
    #[tokio::test]
    async fn an_arp_request_from_the_link_reaches_the_peer_node_as_a_replicated_frame() {
        let mut a = SeamNode::new("zt-arp-a", SEAM_NETWORK).await;
        let mut b = SeamNode::new("zt-arp-b", SEAM_NETWORK).await;
        introduce(&a, &b);
        a.node
            .send_hello_locked(b.node.address(), b.endpoint, SystemTime::now())
            .expect("A queues a HELLO for B's socket");
        settle(&mut a, &mut b).await;

        let config = a.node.network(SEAM_NETWORK).expect("A joined the ad-hoc network").config.clone();
        let mtu = config.mtu;
        let mut link_a = Link::new(SEAM_NETWORK, a.node.address()).expect("a link");
        link_a.apply_network_config(&mut a.node, &config, mtu).expect("A's link takes the configuration");
        let b_config = b.node.network(SEAM_NETWORK).expect("B joined the ad-hoc network").config.clone();
        let mut link_b = Link::new(SEAM_NETWORK, b.node.address()).expect("a link");
        link_b.apply_network_config(&mut b.node, &b_config, mtu).expect("B's link takes the configuration");

        // A unicast IPv6 packet to B's 6plane address makes B associate A, which is what makes B
        // announce the groups its assigned addresses imply.
        let mut hello = vec![0u8; 48];
        hello[0] = 0x60;
        hello[6] = 59;
        hello[4..6].copy_from_slice(&8u16.to_be_bytes());
        hello[8..24].copy_from_slice(&six_plane_octets(a.node.address()));
        hello[24..40].copy_from_slice(&six_plane_octets(b.node.address()));
        hello[40..].copy_from_slice(b"payload!");
        link_a.write_packet(&mut a.node, &hello, SystemTime::now()).expect("A's link frames the packet");
        a.flush().await;
        settle(&mut a, &mut b).await;
        assert_eq!(b.node.take_delivered_frames().len(), 1, "B received the unicast packet");

        let b_ipv4 = managed_ipv4(&b.node, SEAM_NETWORK);
        let a_ipv4 = managed_ipv4(&a.node, SEAM_NETWORK);
        let group = murmur_zerotier::frame::MulticastGroup::new(broadcast_mac(), u32::from_be_bytes(b_ipv4));
        assert!(
            a.node
                .network(SEAM_NETWORK)
                .expect("A joined the ad-hoc network")
                .multicast
                .get(&group)
                .is_some_and(|members| members.contains_key(&b.node.address())),
            "B's announcement named B as a member of the broadcast group its address selects"
        );

        let mut request = vec![0u8; 28];
        request[0] = 0x45;
        request[2..4].copy_from_slice(&(28u16).to_be_bytes());
        request[9] = 17;
        request[12..16].copy_from_slice(&a_ipv4);
        request[16..20].copy_from_slice(&b_ipv4);
        link_a
            .write_packet(&mut a.node, &request, SystemTime::now())
            .expect("A's link resolves B through the broadcast group");
        assert_eq!(a.shared.queue.lock().len(), 1, "one replicated frame is queued");
        a.flush().await;

        let (wire, from) = b.receive().await;
        b.feed(from, &wire).expect("B accepts the replicated frame");
        let delivered = b.node.take_delivered_frames();
        assert_eq!(delivered.len(), 1, "B delivered the broadcast frame");
        assert_eq!(delivered[0].ether_type, ETHER_TYPE_ARP);
        assert_eq!(delivered[0].destination, broadcast_mac());
        assert_eq!(delivered[0].source, mac_for_address(a.node.address(), SEAM_NETWORK));
        assert_eq!(&delivered[0].payload[24..28], &b_ipv4, "B's link is the requested target");

        link_b.handle_frame(&mut b.node, &delivered[0], SystemTime::now()).expect("B's link accepts the request");
        // Two frames go back to A: the ARP answer itself, and the `OK` acknowledging the group
        // frame A replicated, because that frame asked for the members of its group and B is a
        // subscriber of it.
        assert_eq!(b.shared.queue.lock().len(), 2, "B answered the ARP request and acknowledged the group frame");
        b.flush().await;
        for _ in 0..2 {
            let (wire, from) = a.receive().await;
            a.feed(from, &wire).expect("A accepts the reply");
        }
        let reply = a.node.take_delivered_frames();
        assert_eq!(reply.len(), 1, "A received the unicast ARP reply");
        assert_eq!(reply[0].ether_type, ETHER_TYPE_ARP);
        assert_eq!(&reply[0].payload[14..18], &b_ipv4, "the reply names B's managed address");
        assert_eq!(link_a.handle_frame(&mut a.node, &reply[0], SystemTime::now()).expect("A's link accepts it"), None);

        let _ = std::fs::remove_dir_all(&a.state_dir);
        let _ = std::fs::remove_dir_all(&b.state_dir);
    }

    /// The Ethernet broadcast address a replicated group frame is addressed to.
    fn broadcast_mac() -> Mac {
        Mac::new(0xffff_ffff_ffff)
    }

    /// The managed IPv4 address a node's ad-hoc configuration assigns it.
    fn managed_ipv4(node: &Node, network_id: u64) -> [u8; 4] {
        node.network(network_id)
            .expect("the network is joined")
            .config
            .assigned
            .iter()
            .find_map(|prefix| match prefix.addr() {
                IpAddr::V4(address) => Some(address.octets()),
                IpAddr::V6(_) => None,
            })
            .expect("an ad-hoc network assigns an IPv4 address")
    }

    /// The 6plane managed address of one member on the seam network.
    fn six_plane_octets(member: Address) -> [u8; 16] {
        match murmur_zerotier::managed_ip::six_plane_address(SEAM_NETWORK, member).addr() {
            IpAddr::V6(v6) => v6.octets(),
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        }
    }

    /// One controller configuration dictionary naming `member`, as a controller serves it.
    fn controller_config(network_id: u64, member: Address) -> Vec<u8> {
        let mut data = Vec::new();
        for (key, value) in [
            ("v", NETWORK_CONFIG_VERSION),
            ("nwid", network_id),
            ("id", member.uint64()),
            ("t", u64::from(NetworkType::PUBLIC.bits())),
            ("mtu", u64::from(DEFAULT_NETWORK_MTU)),
        ] {
            data = append_dictionary_uint(data, key, value).expect("dictionary entry");
        }
        let mut assigned = vec![4u8, 192, 0, 2, 10];
        assigned.extend_from_slice(&24u16.to_be_bytes());
        append_dictionary_entry(data, "I", &assigned).expect("dictionary entry")
    }
}

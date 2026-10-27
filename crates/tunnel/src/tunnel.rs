use portable_atomic::AtomicU64;
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Once};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex as TokioMutex, Notify, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::statistic::manager::DEFAULT_MANAGER;
use crate::statistic::tracker::{TcpTracker, UdpTracker};
use murmur_common::atomic::enum_::{new_int32_enum, Int32Enum};
use murmur_common::utils::callback::{new_callback, Callback};
use murmur_common::utils::global_id::map_hash;
use murmur_common_net::io::Stream;
use murmur_common_net::BufferedConn;
use murmur_component::resolver::enhancer;
use murmur_component::resolver::resolver as resolver_mod;
use murmur_component::slowdown::slowdown::SlowDown;
use murmur_component_loopback::detector::ErrReject;
use murmur_component_nat as nat;
use murmur_component_process::find_process_mode::FindProcessMode;
use murmur_component_process::process::{find_package_name, find_process_name};
use murmur_component_sniffer::dispatcher::Dispatcher;
use murmur_constant::adapters::{
    new_packet_adapter, AdapterType, Conn as ConstantConn, Connection, NatTable, PacketAdapter, PacketAdapterImpl,
    PacketConn, PacketSender, Proxy, ProxyAdapter, UDPPacket, WriteBackProxy, DEFAULT_TCP_TIMEOUT, DEFAULT_UDP_TIMEOUT,
};
use murmur_constant::context::ConnContext as ConnContextTrait;
use murmur_constant::dns::DNSMode;
use murmur_constant::listener::InboundListener;
use murmur_constant::metadata::{Metadata, NetWork, Type};
use murmur_constant::provider::interface::{ProxyProvider, RuleProvider, Tunnel as ProviderTunnel};
use murmur_constant::rule::{CheckPassRuleFn, Rule, RuleMatchHelper};
use murmur_constant::tunnel::Tunnel as TunnelTrait;
use murmur_constant_features::CMFA;
use murmur_context::conn::new_conn_context;
use murmur_log::{debugln, infoln, warnln};
use murmur_std_compat::net::Conn as NetConn;

use super::connection::{handle_socket, handle_udp_to_local, new_packet_sender};
use super::mode::TunnelMode;
use super::status::TunnelStatus;

/// The capacity of the TCP and UDP packet queues.
pub(crate) const QUEUE_CAPACITY: usize = 64;
/// The capacity of the packet-sender channel.
pub(crate) const SENDER_CAPACITY: usize = 128;
/// the default timeout for a UDP session.
pub(crate) const UDP_TIMEOUT: Duration = Duration::from_secs(60);

const STATUS_MASK: u64 = 3;
const APPLY_ACTIVE: u64 = 4;
const GENERATION_STEP: u64 = 8;
const ADMISSION_INNER: u64 = 1;
const ADMISSION_RUNNING: u64 = 2;
static ADMISSION: AtomicU64 = AtomicU64::new(0);
static ADMISSION_CHANGED: Notify = Notify::const_new();
static PENDING_TCP: Semaphore = Semaphore::const_new(QUEUE_CAPACITY);
static UDP_INIT: Once = Once::new();
static UDP_QUEUES: RwLock<Vec<mpsc::Sender<QueuedPacket>>> = RwLock::new(Vec::new());
static INNER_UDP_QUEUE: LazyLock<mpsc::Sender<QueuedPacket>> = LazyLock::new(|| {
    let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
    tokio::spawn(process_udp(rx));
    tx
});

#[derive(Clone, Copy)]
struct AdmissionWait {
    generation: u64,
    deadline: tokio::time::Instant,
}

struct QueuedPacket {
    packet: PacketAdapterImpl,
    wait: Option<AdmissionWait>,
}
static NAT_TABLE: LazyLock<Arc<dyn NatTable>> = LazyLock::new(|| Arc::new(nat::new()));

/// Holds the rules, listeners, sub-rules, proxies, providers, rule providers, sniffer dispatcher
/// and sniffing-enable items, all guarded by a single mutex.
#[derive(Default)]
struct ConfigState {
    rules: Vec<Arc<dyn Rule>>,
    listeners: HashMap<String, Arc<dyn InboundListener>>,
    sub_rules: HashMap<String, Vec<Arc<dyn Rule>>>,
    proxies: Arc<HashMap<String, Arc<dyn Proxy>>>,
    providers: HashMap<String, Arc<dyn ProxyProvider>>,
    rule_providers: HashMap<String, Arc<dyn RuleProvider>>,
    sniffer_dispatcher: Option<Arc<Dispatcher>>,
    sniffing_enable: bool,
}

static CONFIG: LazyLock<RwLock<ConfigState>> = LazyLock::new(|| RwLock::new(ConfigState::default()));

static TCP_QUEUE: LazyLock<mpsc::Sender<Box<dyn ConnContextTrait>>> = LazyLock::new(|| {
    let (tx, mut rx) = mpsc::channel::<Box<dyn ConnContextTrait>>(QUEUE_CAPACITY);
    tokio::spawn(async move {
        while let Some(conn_ctx) = rx.recv().await {
            tokio::spawn(handle_tcp_conn(conn_ctx));
        }
    });
    tx
});
static UDP_QUEUE: LazyLock<mpsc::Sender<Arc<dyn PacketAdapter>>> = LazyLock::new(|| {
    let (tx, mut rx) = mpsc::channel::<Arc<dyn PacketAdapter>>(QUEUE_CAPACITY);
    tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let metadata = packet.metadata().clone();
            TUNNEL.handle_udp_packet(packet, metadata);
        }
    });
    tx
});

static MODE: LazyLock<Int32Enum<TunnelMode>> = LazyLock::new(|| new_int32_enum(TunnelMode::RULE));
static FIND_PROCESS_MODE: LazyLock<Int32Enum<FindProcessMode>> =
    LazyLock::new(|| new_int32_enum(FindProcessMode::FIND_PROCESS_STRICT));
static RULE_UPDATE_CALLBACK: LazyLock<Callback<Arc<dyn RuleProvider>>> = LazyLock::new(new_callback);

#[derive(Clone, Copy, Default, Debug)]
pub struct Tunnel;

pub static TUNNEL: Tunnel = Tunnel;

#[async_trait]
impl TunnelTrait for Tunnel {
    // cancel-safe: a cancelled future only drops the connection handoff it was given.
    async fn handle_tcp_conn(&self, conn: Box<dyn Stream>, metadata: Metadata) {
        let conn_ctx: Box<dyn ConnContextTrait> = Box::new(new_conn_context(conn, metadata));
        handle_tcp_conn(conn_ctx).await;
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the UDP queue table guard stays held across the shard lookup and the early returns below, so it cannot be dropped earlier"
    )]
    fn handle_udp_packet(&self, packet: Arc<dyn UDPPacket>, metadata: Metadata) {
        prepare_udp();

        let packet_adapter = new_packet_adapter(packet, metadata);
        let state = ADMISSION.load(Ordering::Acquire);
        if state & STATUS_MASK != ADMISSION_RUNNING && state & APPLY_ACTIVE == 0 {
            packet_adapter.drop_();
            return;
        }
        let wait = admission_wait(state);
        let packet = QueuedPacket { packet: packet_adapter, wait };
        if packet.packet.metadata().type_ == Type::INNER {
            if let Err(err) = INNER_UDP_QUEUE.try_send(packet) {
                err.into_inner().packet.drop_();
            }
            return;
        }

        let hash = map_hash(packet.packet.key_ref());
        let queues = UDP_QUEUES.read();
        #[expect(clippy::cast_possible_truncation, reason = "the shard index takes the low bits of the hash")]
        let queue_no = (hash as usize) % queues.len();

        let Some(queue) = queues.get(queue_no) else {
            packet.packet.drop_();
            return;
        };
        match queue.try_send(packet) {
            Ok(()) => {}
            Err(
                mpsc::error::TrySendError::Full(packet_adapter) | mpsc::error::TrySendError::Closed(packet_adapter),
            ) => {
                packet_adapter.packet.drop_();
            }
        }
    }

    fn nat_table(&self) -> Arc<dyn NatTable> {
        nat_table()
    }

    fn proxies(&self) -> Option<HashMap<String, Arc<dyn Proxy>>> {
        Some(proxies())
    }
}

impl ProviderTunnel for Tunnel {
    fn providers(&self) -> HashMap<String, Arc<dyn ProxyProvider>> {
        providers()
    }

    fn rule_providers(&self) -> HashMap<String, Arc<dyn RuleProvider>> {
        rule_providers()
    }

    fn rule_update_callback(&self) -> &Callback<Arc<dyn RuleProvider>> {
        &RULE_UPDATE_CALLBACK
    }
}

/// Must run on the Tokio runtime that serves traffic: these process-global queues cannot restart
/// their workers after that runtime shuts down.
pub fn prepare_udp() {
    UDP_INIT.call_once(init_udp);
}

fn init_udp() {
    let mut num_udp_workers: usize = 4;
    if let Ok(available) = std::thread::available_parallelism() {
        if available.get() > num_udp_workers {
            num_udp_workers = available.get();
        }
    }

    let mut queues = Vec::with_capacity(num_udp_workers);
    for _ in 0..num_udp_workers {
        let (tx, rx) = mpsc::channel::<QueuedPacket>(QUEUE_CAPACITY);
        queues.push(tx);
        tokio::spawn(process_udp(rx));
    }
    *UDP_QUEUES.write() = queues;
}

/// The executor holds its apply mutex before acquiring this guard.
#[derive(Debug)]
pub struct ConfigApplyGuard {
    generation: u64,
    finished: bool,
}

pub fn begin_config_apply() -> Result<ConfigApplyGuard> {
    let mut state = ADMISSION.load(Ordering::Acquire);
    loop {
        if state & APPLY_ACTIVE != 0 {
            return Err(anyhow!("configuration apply already active"));
        }
        let previous = state & !(GENERATION_STEP - 1);
        // Successful consecutive applies share an epoch so delayed waiters survive both.
        let generation = if state & STATUS_MASK == ADMISSION_RUNNING {
            previous
        } else {
            previous.checked_add(GENERATION_STEP).ok_or_else(|| anyhow!("configuration generation exhausted"))?
        };
        match ADMISSION.compare_exchange(state, generation | APPLY_ACTIVE, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                ADMISSION_CHANGED.notify_waiters();
                return Ok(ConfigApplyGuard { generation, finished: false });
            }
            Err(current) => state = current,
        }
    }
}

impl ConfigApplyGuard {
    fn transition(&self, next: u64) -> Result<()> {
        let mut state = ADMISSION.load(Ordering::Acquire);
        loop {
            if state & !(GENERATION_STEP - 1) != self.generation || state & APPLY_ACTIVE == 0 {
                return Err(anyhow!("configuration apply cancelled"));
            }
            match ADMISSION.compare_exchange(state, self.generation | next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    ADMISSION_CHANGED.notify_waiters();
                    return Ok(());
                }
                Err(current) => state = current,
            }
        }
    }

    pub fn inner_loading(&self) -> Result<()> {
        self.transition(APPLY_ACTIVE | ADMISSION_INNER)
    }

    pub fn finish(mut self) -> Result<()> {
        self.transition(ADMISSION_RUNNING)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for ConfigApplyGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if ADMISSION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state & !(GENERATION_STEP - 1) == self.generation && state & APPLY_ACTIVE != 0)
                    .then_some(self.generation)
            })
            .is_ok()
        {
            ADMISSION_CHANGED.notify_waiters();
        }
    }
}

pub fn on_suspend() {
    ADMISSION.fetch_and(!(GENERATION_STEP - 1), Ordering::AcqRel);
    ADMISSION_CHANGED.notify_waiters();
}

pub fn status() -> TunnelStatus {
    match ADMISSION.load(Ordering::Acquire) & STATUS_MASK {
        1 => TunnelStatus::INNER,
        2 => TunnelStatus::RUNNING,
        _ => TunnelStatus::SUSPEND,
    }
}

fn admission_wait(state: u64) -> Option<AdmissionWait> {
    (state & APPLY_ACTIVE != 0).then(|| AdmissionWait {
        generation: state & !(GENERATION_STEP - 1),
        deadline: tokio::time::Instant::now() + DEFAULT_TCP_TIMEOUT,
    })
}

fn handles(state: u64, type_: Type) -> bool {
    let status = state & STATUS_MASK;
    status == ADMISSION_RUNNING || (status == ADMISSION_INNER && type_ == Type::INNER)
}

// cancel-safe: dropping the future releases its permit and notification registration.
async fn admit(type_: Type, queued: Option<AdmissionWait>, tcp: bool) -> bool {
    let state = ADMISSION.load(Ordering::Acquire);
    if queued.is_none() && handles(state, type_) {
        return true;
    }
    let Some(wait) = queued.or_else(|| admission_wait(state)) else {
        return false;
    };
    let _permit = if tcp {
        let Ok(permit) = PENDING_TCP.try_acquire() else {
            return false;
        };
        Some(permit)
    } else {
        None
    };
    loop {
        let notified = ADMISSION_CHANGED.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let state = ADMISSION.load(Ordering::Acquire);
        if state & !(GENERATION_STEP - 1) != wait.generation || tokio::time::Instant::now() >= wait.deadline {
            return false;
        }
        if handles(state, type_) {
            return true;
        }
        if state & APPLY_ACTIVE == 0 || tokio::time::timeout_at(wait.deadline, notified).await.is_err() {
            return false;
        }
    }
}

pub fn set_sniffing(b: bool) {
    let enabled = CONFIG.read().sniffer_dispatcher.as_ref().is_some_and(|dispatcher| dispatcher.enable());
    if enabled {
        CONFIG.write().sniffing_enable = b;
    }
}

pub fn is_sniffing() -> bool {
    CONFIG.read().sniffing_enable
}

/// The configured sniffer dispatcher, or `None` while sniffing is disabled.
fn sniff_dispatcher() -> Option<Arc<Dispatcher>> {
    let cfg = CONFIG.read();
    if cfg.sniffing_enable {
        cfg.sniffer_dispatcher.clone()
    } else {
        None
    }
}

/// The TCP fan-in queue.
/// Deprecated: using [`TUNNEL`] instead.
pub fn tcp_in() -> mpsc::Sender<Box<dyn ConnContextTrait>> {
    TCP_QUEUE.clone()
}

/// The UDP fan-in queue.
/// Deprecated: using [`TUNNEL`] instead.
pub fn udp_in() -> mpsc::Sender<Arc<dyn PacketAdapter>> {
    UDP_QUEUE.clone()
}

/// The NAT table.
pub fn nat_table() -> Arc<dyn NatTable> {
    NAT_TABLE.clone()
}

/// All rules.
pub fn rules() -> Vec<Arc<dyn Rule>> {
    CONFIG.read().rules.clone()
}

pub fn listeners() -> HashMap<String, Arc<dyn InboundListener>> {
    CONFIG.read().listeners.clone()
}

/// Replaces the rules, sub-rules and rule providers.
#[expect(clippy::implicit_hasher, reason = "the exported signature is the crate's public API")]
pub fn update_rules(
    new_rules: Vec<Arc<dyn Rule>>,
    new_sub_rule: HashMap<String, Vec<Arc<dyn Rule>>>,
    rp: HashMap<String, Arc<dyn RuleProvider>>,
) {
    let mut cfg = CONFIG.write();
    cfg.rules = new_rules;
    cfg.rule_providers = rp;
    cfg.sub_rules = new_sub_rule;
}

/// All proxies.
pub fn proxies() -> HashMap<String, Arc<dyn Proxy>> {
    (*CONFIG.read().proxies).clone()
}

/// All compatible providers.
pub fn providers() -> HashMap<String, Arc<dyn ProxyProvider>> {
    CONFIG.read().providers.clone()
}

/// All loaded rule providers.
pub fn rule_providers() -> HashMap<String, Arc<dyn RuleProvider>> {
    CONFIG.read().rule_providers.clone()
}

/// Replaces the proxies and providers.
#[expect(clippy::implicit_hasher, reason = "the exported signature is the crate's public API")]
pub fn update_proxies(
    new_proxies: HashMap<String, Arc<dyn Proxy>>,
    new_providers: HashMap<String, Arc<dyn ProxyProvider>>,
) {
    let mut cfg = CONFIG.write();
    cfg.proxies = Arc::new(new_proxies);
    cfg.providers = new_providers;
}

#[expect(clippy::implicit_hasher, reason = "the exported signature is the crate's public API")]
pub fn update_listeners(new_listeners: HashMap<String, Arc<dyn InboundListener>>) {
    CONFIG.write().listeners = new_listeners;
}

pub fn update_sniffer(dispatcher: Arc<Dispatcher>) {
    let mut cfg = CONFIG.write();
    let enable = dispatcher.enable();
    cfg.sniffer_dispatcher = Some(dispatcher);
    cfg.sniffing_enable = enable;
}

/// The current mode.
pub fn mode() -> TunnelMode {
    MODE.load()
}

/// Changes the mode of the tunnel.
pub fn set_mode(m: TunnelMode) {
    MODE.store(m);
}

pub fn find_process_mode() -> FindProcessMode {
    FIND_PROCESS_MODE.load()
}

/// Changes the find-process mode.
pub fn set_find_process_mode(m: FindProcessMode) {
    FIND_PROCESS_MODE.store(m);
}

fn fix_metadata(metadata: &mut Metadata) {
    metadata.dst_ip = murmur_component::dialer::bind::unmap_addr(metadata.dst_ip);
    if let Ok(ip) = murmur_component::resolver::host::parse_addr(&metadata.host) {
        metadata.dst_ip = murmur_component::dialer::bind::unmap_addr(Some(ip));
        metadata.host = String::new();
    }
}

/// The destination ip to run through the ip-mapping enhancer, if this metadata needs that lookup.
fn need_lookup_ip(metadata: &Metadata) -> Option<IpAddr> {
    if enhancer::mapping_enabled() && metadata.host.is_empty() {
        metadata.dst_ip
    } else {
        None
    }
}

// cancel-safe: the hosts/dns lookups it awaits carry no connection state.
pub(crate) async fn pre_handle_metadata(metadata: &mut Metadata) -> Result<()> {
    if let Some(dst_ip) = need_lookup_ip(metadata) {
        if let Some(host) = enhancer::find_host_by_ip(dst_ip) {
            metadata.host.clone_from(&host);
            metadata.dns_mode = DNSMode::DNS_MAPPING;
            if enhancer::is_fake_ip(dst_ip) {
                metadata.dst_ip = None;
                metadata.dns_mode = DNSMode::DNS_FAKE_IP;
            } else {
                match resolver_mod::default_hosts().search(&host, false).await {
                    Some((node, true)) => {
                        if let Ok(dst_ip) = node.rand_ip() {
                            metadata.dst_ip = Some(dst_ip);
                        }
                    }
                    Some((node, false)) if node.is_domain => {
                        metadata.host.clone_from(&node.domain);
                    }
                    _ => {}
                }
            }
        } else if enhancer::is_fake_ip(dst_ip) {
            return Err(anyhow!("fake DNS record {dst_ip} missing"));
        }
    } else if let Some((node, true)) = resolver_mod::default_hosts().search(&metadata.host, true).await {
        metadata.host = node.domain;
    }
    Ok(())
}

/// The base name (Unix-style separator; only the Linux/macOS path is supported).
fn filepath_base(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_owned();
    }
    match trimmed.rsplit_once('/') {
        Some((_, base)) => base.to_owned(),
        None => trimmed.to_owned(),
    }
}

/// Fills `metadata.dst_ip` from the host once, guarded by the connection's flag.
fn resolve_ip_callback(resolved: Arc<AtomicBool>) -> Arc<dyn Fn(&mut Metadata) + Send + Sync> {
    Arc::new(move |metadata: &mut Metadata| {
        if resolved.load(Ordering::SeqCst) {
            return;
        }
        if metadata.host.is_empty() || metadata.resolved() {
            return;
        }
        let host = metadata.host.clone();
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let (cancel, timeout_task) = new_timeout_cancellation(resolver_mod::default_dns_timeout());
                let result = resolver_mod::resolve_ip(&cancel, &host).await;
                timeout_task.abort();
                result
            })
        });
        match result {
            Err(err) => debugln!("[DNS] resolve {host} error: {err}"),
            Ok(ip) => {
                debugln!("[DNS] {host} --> {ip}");
                metadata.dst_ip = Some(ip);
            }
        }
        resolved.store(true, Ordering::SeqCst);
    })
}

fn find_process(metadata: &mut Metadata) {
    if CMFA {
        match find_package_name(metadata) {
            Err(err) => debugln!("[Process] find process error for {}: {err}", metadata.string()),
            Ok(pkg) => metadata.process = pkg,
        }
    } else {
        match find_process_name(&metadata.network.string(), metadata.src_ip, i32::from(metadata.src_port)) {
            Err(err) => debugln!("[Process] find process error for {}: {err}", metadata.string()),
            Ok((uid, path)) => {
                metadata.process = filepath_base(&path);
                metadata.process_path = path;
                metadata.uid = uid;
                if let Ok(pkg) = find_package_name(metadata) {
                    metadata.process = pkg;
                }
            }
        }
    }
}

fn find_process_callback(attempt_process_lookup: Arc<AtomicBool>) -> Arc<dyn Fn(&mut Metadata) + Send + Sync> {
    Arc::new(move |metadata: &mut Metadata| {
        if attempt_process_lookup.swap(false, Ordering::SeqCst) {
            find_process(metadata);
        }
    })
}

/// Walks the adapter chain from `adapter_name` looking for the pass-rule step.
fn check_pass_rule_callback(proxies_snapshot: Arc<HashMap<String, Arc<dyn Proxy>>>) -> CheckPassRuleFn {
    Arc::new(move |metadata: &Metadata, adapter_name: &str| {
        let Some(mut adapter) = proxies_snapshot.get(adapter_name).cloned() else {
            return false;
        };
        loop {
            if adapter.type_() == AdapterType::PASS_RULE {
                return true;
            }
            match adapter.unwrap(metadata, false) {
                Some(next) => adapter = next,
                None => return false,
            }
        }
    })
}

// NOT cancel-safe: a cancel leaves the caller's metadata partially resolved.
pub(crate) async fn resolve_metadata(
    metadata: &mut Metadata,
) -> Result<(Option<Arc<dyn Proxy>>, Option<Arc<dyn Rule>>)> {
    if !metadata.special_proxy.is_empty() {
        return match CONFIG.read().proxies.get(&metadata.special_proxy).cloned() {
            Some(proxy) => Ok((Some(proxy), None)),
            None => Err(anyhow!("proxy {} not found", metadata.special_proxy)),
        };
    }

    let resolved = if let Some((node, _)) = resolver_mod::default_hosts().search(&metadata.host, false).await {
        if let Ok(dst_ip) = node.rand_ip() {
            metadata.dst_ip = Some(dst_ip);
        }
        true
    } else {
        false
    };

    let proxies_snapshot = Arc::clone(&CONFIG.read().proxies);
    let process_mode = find_process_mode();
    if process_mode == FindProcessMode::FIND_PROCESS_ALWAYS && metadata.type_ != Type::INNER {
        find_process(metadata);
    }

    match mode() {
        TunnelMode::DIRECT => Ok((proxies_snapshot.get("DIRECT").cloned(), None)),
        TunnelMode::GLOBAL => Ok((proxies_snapshot.get("GLOBAL").cloned(), None)),
        _ => {
            let find_process = if metadata.type_ != Type::INNER
                && process_mode != FindProcessMode::FIND_PROCESS_OFF
                && process_mode != FindProcessMode::FIND_PROCESS_ALWAYS
            {
                Some(find_process_callback(Arc::new(AtomicBool::new(true))))
            } else {
                None
            };
            let helper = RuleMatchHelper {
                resolve_ip: Some(resolve_ip_callback(Arc::new(AtomicBool::new(resolved)))),
                find_process,
                check_pass_rule: Some(check_pass_rule_callback(proxies_snapshot)),
            };
            match_(metadata, helper).await
        }
    }
}

/// Starts a loop to handle UDP packets.
// cancel-safe: cancellation only stops dequeuing; the queue senders stay usable.
async fn process_udp(mut queue: mpsc::Receiver<QueuedPacket>) {
    while let Some(packet) = queue.recv().await {
        handle_queued_udp(packet).await;
    }
}

/// Handles one dequeued UDP datagram.
///
/// The queue loop is the production caller. The per-datagram measurement in
/// `benches/udp_dispatch.rs` calls this directly so the established-hit and miss paths are measured
/// through the real function rather than a copy of its operations.
// NOT cancel-safe: a cancel after the nat-table insert leaves that entry to expire.
#[doc(hidden)]
pub async fn handle_udp_conn(packet_adapter: PacketAdapterImpl) {
    handle_queued_udp(QueuedPacket { packet: packet_adapter, wait: None }).await;
}

// NOT cancel-safe: after admission this delegates to NAT insertion and packet delivery.
async fn handle_queued_udp(packet: QueuedPacket) {
    let QueuedPacket { packet: mut packet_adapter, wait } = packet;
    if !admit(packet_adapter.metadata().type_, wait, false).await {
        packet_adapter.drop_();
        return;
    }

    if !packet_adapter.metadata().valid() {
        packet_adapter.drop_();
        warnln!("[Metadata] not valid: {:?}", packet_adapter.metadata());
        return;
    }
    fix_metadata(packet_adapter.metadata_mut());

    if let Err(err) = pre_handle_metadata(packet_adapter.metadata_mut()).await {
        packet_adapter.drop_();
        debugln!("[Metadata PreHandle] error: {err}");
        return;
    }

    // An established key needs neither the metadata cell nor a maker: both exist for the first
    // packet, which the sniffer may mutate and the dial task consumes. A `None` here is not proof
    // of absence — a concurrent creation can store the key just after the lookup — so the miss path
    // below still runs the atomic `get_or_create`.
    let nat = nat_table();
    if let Some(sender) = nat.get(packet_adapter.key_ref()) {
        sender.send(Arc::new(packet_adapter)).await;
        return;
    }

    let key = packet_adapter.key();
    let raw_packet = Arc::clone(&packet_adapter.packet);
    let metadata_cell = Arc::new(Mutex::new(packet_adapter.metadata().clone()));
    let sniff_packet: Arc<dyn PacketAdapter> = Arc::new(packet_adapter);

    let maker: Box<dyn FnOnce() -> Arc<dyn PacketSender> + Send> = {
        let sniff_packet = Arc::clone(&sniff_packet);
        let metadata_cell = Arc::clone(&metadata_cell);
        Box::new(move || {
            let sender = new_packet_sender();
            if let Some(dispatcher) = sniff_dispatcher().filter(|dispatcher| dispatcher.enable()) {
                let mut metadata = metadata_cell.lock();
                return dispatcher.udp_sniff(&sniff_packet, &mut metadata, sender);
            }
            sender
        })
    };

    let (sender, loaded) = nat.get_or_create(&key, maker);

    let packet: Arc<dyn PacketAdapter> = if loaded {
        sniff_packet
    } else {
        let metadata = metadata_cell.lock().clone();
        let packet: Arc<dyn PacketAdapter> = Arc::new(new_packet_adapter(raw_packet, metadata.clone()));

        let sender_task = Arc::clone(&sender);
        let key_task = key.clone();
        let packet_for_writeback = Arc::clone(&packet);
        tokio::spawn(async move {
            if let Ok((pc, proxy)) =
                handle_udp_dial(Arc::clone(&sender_task), key_task.clone(), metadata, packet_for_writeback).await
            {
                sender_task.process(pc, proxy).await;
            } else {
                sender_task.close();
                nat_table().delete(&key_task);
            }
        });
        packet
    };
    sender.send(packet).await;
}

/// The dial closure built when a UDP connection is handled.
// NOT cancel-safe: an aborted dial skips the nat-table cleanup its caller performs.
async fn handle_udp_dial(
    sender: Arc<dyn PacketSender>,
    key: String,
    starting_metadata: Metadata,
    packet: Arc<dyn PacketAdapter>,
) -> Result<(Arc<dyn PacketConn>, Arc<dyn WriteBackProxy>)> {
    let origin_metadata = starting_metadata.clone();
    let mut metadata = starting_metadata;

    if let Err(err) = sender.do_sniff(&mut metadata).await {
        warnln!("[UDP] DoSniff error: {err}");
        return Err(err);
    }

    let _ = pre_handle_metadata(&mut metadata).await;

    let (proxy, rule) = match resolve_metadata(&mut metadata).await {
        Ok(result) => result,
        Err(err) => {
            warnln!("[UDP] Parse metadata failed: {err}");
            return Err(err);
        }
    };
    let Some(proxy) = proxy else {
        return Err(anyhow!("no proxy resolved"));
    };

    let dial_metadata = metadata.pure();
    let (cancel, timeout_task) = new_timeout_cancellation(DEFAULT_UDP_TIMEOUT);

    let raw_pc = retry::<Arc<dyn PacketConn>>(
        &cancel,
        {
            let proxy = Arc::clone(&proxy);
            move |ctx| {
                let proxy = Arc::clone(&proxy);
                let mut dial_metadata = dial_metadata.clone();
                Box::pin(async move { proxy.listen_packet_context(&ctx, &mut dial_metadata).await })
            }
        },
        {
            let rule = rule.clone();
            let proxy = Arc::clone(&proxy);
            let metadata = metadata.clone();
            move |err: &anyhow::Error| log_metadata_err(&metadata, rule.as_deref(), proxy.as_ref(), err)
        },
    )
    .await;
    timeout_task.abort();
    let raw_pc = raw_pc?;

    log_metadata(&metadata, rule.as_deref(), raw_pc.as_ref());

    let pc = UdpTracker::new(raw_pc, &DEFAULT_MANAGER, &mut metadata, rule, 0, 0, true);

    sender.add_mapping(&origin_metadata, &metadata);
    let Some(o_addr_port) = metadata.addr_port() else {
        return Err(anyhow!("dial metadata has no resolved address"));
    };
    let write_back_proxy = nat::new_write_back_proxy(packet);

    let pc: Arc<dyn PacketConn> = pc;
    // No target type on the binding: `Arc::clone` must infer its parameter from the
    // argument, and only then is the result coerced at the call site.
    let write_back = Arc::clone(&write_back_proxy);
    tokio::spawn(handle_udp_to_local(write_back, Arc::clone(&pc), sender, key, o_addr_port));

    Ok((pc, write_back_proxy))
}

/// The missing early-conn boundary on socket handling: `constant::adapters::Conn` does not
/// currently expose the early-conn chain, so this always reports `false`, matching how
/// `crate::statistic::tracker`'s `TcpTracker` already treats this same boundary.
fn need_handshake(_conn: &dyn ConstantConn) -> bool {
    false
}

// cancel-safe: a cancelled future drops, and so closes, the connection it owns.
async fn handle_tcp_conn(mut conn_ctx: Box<dyn ConnContextTrait>) {
    if !admit(conn_ctx.metadata().type_, None, true).await {
        let _ = conn_ctx.conn().lock().await.close();
        return;
    }

    let conn = conn_ctx.conn();
    handle_tcp_conn_body(&mut conn_ctx, &conn).await;
    let _ = conn.lock().await.close();
}

/// The body of TCP connection handling, after the handle check's early return and its deferred
/// close.
// NOT cancel-safe: dropping it mid-flight strands the buffered connection its caller closes.
async fn handle_tcp_conn_body(conn_ctx: &mut Box<dyn ConnContextTrait>, conn: &Arc<TokioMutex<BufferedConn>>) {
    if !conn_ctx.metadata().valid() {
        warnln!("[Metadata] not valid: {:?}", conn_ctx.metadata());
        return;
    }
    fix_metadata(conn_ctx.metadata_mut());

    let mut pre_handle_failed = if let Err(err) = pre_handle_metadata(conn_ctx.metadata_mut()).await {
        debugln!("[Metadata PreHandle] error: {err}");
        true
    } else {
        false
    };

    conn.lock().await.reset_peeked();

    if let Some(dispatcher) = sniff_dispatcher().filter(|dispatcher| dispatcher.enable()) {
        let mut guard = conn.lock().await;
        if dispatcher.tcp_sniff(&mut guard, conn_ctx.metadata_mut()).await {
            pre_handle_failed = false;
        }
    }

    if pre_handle_failed {
        debugln!(
            "[Metadata PreHandle] failed to sniff a domain for connection {} --> {}, give up",
            conn_ctx.metadata().source_detail(),
            conn_ctx.metadata().remote_address(),
        );
        return;
    }

    let peek_mutex = Arc::new(TokioMutex::new(()));
    if !conn.lock().await.peeked() {
        spawn_background_peek(conn, &peek_mutex).await;
    }

    let (proxy, rule) = match resolve_metadata(conn_ctx.metadata_mut()).await {
        Ok(result) => result,
        Err(err) => {
            warnln!("[Metadata] parse failed: {err}");
            return;
        }
    };
    let Some(proxy) = proxy else {
        warnln!("[Metadata] parse failed: no proxy resolved");
        return;
    };

    let dial_metadata = dial_metadata_for(conn_ctx).await;

    let peek_state: Arc<Mutex<(Vec<u8>, usize)>> = Arc::new(Mutex::new((Vec::new(), 0)));
    let (cancel, timeout_task) = new_timeout_cancellation(DEFAULT_TCP_TIMEOUT);

    let proxy_for_fe = Arc::clone(&proxy);
    let rule_for_fe = rule.clone();
    let metadata_snapshot = conn_ctx.metadata().clone();

    let remote_conn_result = retry::<Box<dyn ConstantConn>>(
        &cancel,
        {
            let proxy = Arc::clone(&proxy);
            let dial_metadata = dial_metadata.clone();
            let conn = Arc::clone(conn);
            let peek_mutex = Arc::clone(&peek_mutex);
            let peek_state = Arc::clone(&peek_state);
            move |ctx| {
                let proxy = Arc::clone(&proxy);
                let mut dial_metadata = dial_metadata.clone();
                let conn = Arc::clone(&conn);
                let peek_mutex = Arc::clone(&peek_mutex);
                let peek_state = Arc::clone(&peek_state);
                Box::pin(
                    async move { dial_once(&proxy, &mut dial_metadata, &conn, &peek_mutex, &peek_state, &ctx).await },
                )
            }
        },
        move |err: &anyhow::Error| {
            log_metadata_err(&metadata_snapshot, rule_for_fe.as_deref(), proxy_for_fe.as_ref(), err);
        },
    )
    .await;
    timeout_task.abort();

    let Ok(remote_conn) = remote_conn_result else {
        return;
    };

    log_metadata(conn_ctx.metadata(), rule.as_deref(), remote_conn.as_ref());

    let peek_len = peek_state.lock().1;
    #[expect(clippy::cast_possible_wrap, reason = "a peeked byte count is bounded by the connection buffer")]
    let mut remote_conn =
        TcpTracker::new(remote_conn, &DEFAULT_MANAGER, conn_ctx.metadata_mut(), rule, peek_len as i64, 0, true);

    relay_both_ways(conn, &peek_mutex, &mut remote_conn).await;
}

/// The dial metadata: the connection metadata, overridden by the hosts entry when it has one.
// cancel-safe: its only await precedes every write to the caller's metadata.
async fn dial_metadata_for(conn_ctx: &mut Box<dyn ConnContextTrait>) -> Metadata {
    let mut dial_metadata = conn_ctx.metadata().clone();
    if !conn_ctx.metadata().host.is_empty() {
        if let Some((node, true)) = resolver_mod::default_hosts().search(&conn_ctx.metadata().host, false).await {
            if let Ok(dst_ip) = node.rand_ip() {
                if !enhancer::is_fake_ip(dst_ip) {
                    let metadata = conn_ctx.metadata_mut();
                    metadata.dst_ip = Some(dst_ip);
                    metadata.dns_mode = DNSMode::DNS_HOSTS;
                    dial_metadata = metadata.pure();
                }
            }
        }
    }
    dial_metadata
}

/// Starts the best-effort background peek, taking `peek_mutex` so it cannot race a dial.
// cancel-safe: the spawned peeker owns only the guard and the shared connection.
async fn spawn_background_peek(conn: &Arc<TokioMutex<BufferedConn>>, peek_mutex: &Arc<TokioMutex<()>>) {
    let guard = Arc::clone(peek_mutex).lock_owned().await;
    let conn_for_peek = Arc::clone(conn);
    tokio::spawn(async move {
        let _guard = guard;
        let mut c = conn_for_peek.lock().await;
        let _ = c.set_read_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(200)));
        let _ = c.peek(1).await;
        let _ = c.set_read_deadline(None);
    });
}

/// One dial attempt, including the early-conn handshake against the buffered bytes.
// NOT cancel-safe: cancelling drops the freshly dialed connection; only the retry loop replaces it.
#[expect(
    clippy::significant_drop_tightening,
    reason = "`bytes` borrows the buffer behind the guard, so the guard has to outlive `to_vec`"
)]
async fn dial_once(
    proxy: &Arc<dyn Proxy>,
    dial_metadata: &mut Metadata,
    conn: &Arc<TokioMutex<BufferedConn>>,
    peek_mutex: &Arc<TokioMutex<()>>,
    peek_state: &Arc<Mutex<(Vec<u8>, usize)>>,
    ctx: &CancellationToken,
) -> Result<Box<dyn ConstantConn>> {
    let mut remote_conn = proxy.dial_context(ctx, dial_metadata).await?;

    if need_handshake(remote_conn.as_ref()) {
        let _peek_guard = peek_mutex.lock().await;
        let peek_bytes = {
            let mut c = conn.lock().await;
            let n = c.buffered();
            let (bytes, _) = c.peek(n).await;
            bytes.to_vec()
        };
        match remote_conn.write(&peek_bytes).await {
            Ok(_) => {
                let len = peek_bytes.len();
                if len > 0 {
                    let _ = conn.lock().await.discard(len).await;
                }
                *peek_state.lock() = (peek_bytes, len);
            }
            Err(write_err) => {
                let _ = remote_conn.shutdown_read();
                let _ = remote_conn.shutdown_write();
                let is_reject = remote_conn.chains().0.iter().any(|chain| chain == "REJECT");
                if !is_reject {
                    return Err(anyhow::Error::new(write_err));
                }
            }
        }
    }
    Ok(remote_conn)
}

/// The connection's tail: clears the peek deadline, takes the main peek guard, then relays.
// NOT cancel-safe: a cancel drops the half-forwarded byte stream.
async fn relay_both_ways(
    conn: &Arc<TokioMutex<BufferedConn>>,
    peek_mutex: &Arc<TokioMutex<()>>,
    remote_conn: &mut TcpTracker,
) {
    {
        let c = conn.lock().await;
        let _ = c.set_read_deadline(Some(tokio::time::Instant::now()));
    }
    let _main_peek_guard = peek_mutex.lock().await;
    {
        let c = conn.lock().await;
        let _ = c.set_read_deadline(None);
    }

    handle_socket(&mut *conn.lock().await, remote_conn).await;
    let _ = murmur_common_net::io::close_stream(remote_conn);
}

pub(crate) fn log_metadata_err(
    metadata: &Metadata,
    rule: Option<&dyn Rule>,
    proxy: &dyn ProxyAdapter,
    err: &anyhow::Error,
) {
    match rule {
        None => warnln!(
            "[{}] dial {} {} --> {} error: {err}",
            metadata.network.string().to_uppercase(),
            proxy.name(),
            metadata.source_detail(),
            metadata.remote_address(),
        ),
        Some(rule) => warnln!(
            "[{}] dial {} (match {}/{}) {} --> {} error: {err}",
            metadata.network.string().to_uppercase(),
            proxy.name(),
            rule.rule_type().string(),
            rule.payload(),
            metadata.source_detail(),
            metadata.remote_address(),
        ),
    }
}

pub(crate) fn log_metadata(metadata: &Metadata, rule: Option<&dyn Rule>, remote_conn: &dyn Connection) {
    if !metadata.special_proxy.is_empty() {
        infoln!(
            "[{}] {} --> {} using {}",
            metadata.network.string().to_uppercase(),
            metadata.source_detail(),
            metadata.remote_address(),
            remote_conn.chains().string(),
        );
        return;
    }
    if let Some(rule) = rule {
        if rule.payload().is_empty() {
            infoln!(
                "[{}] {} --> {} match {} using {}",
                metadata.network.string().to_uppercase(),
                metadata.source_detail(),
                metadata.remote_address(),
                rule.rule_type().string(),
                remote_conn.chains().string(),
            );
        } else {
            infoln!(
                "[{}] {} --> {} match {}({}) using {}",
                metadata.network.string().to_uppercase(),
                metadata.source_detail(),
                metadata.remote_address(),
                rule.rule_type().string(),
                rule.payload(),
                remote_conn.chains().string(),
            );
        }
        return;
    }
    match mode() {
        TunnelMode::GLOBAL => infoln!(
            "[{}] {} --> {} using GLOBAL",
            metadata.network.string().to_uppercase(),
            metadata.source_detail(),
            metadata.remote_address(),
        ),
        TunnelMode::DIRECT => infoln!(
            "[{}] {} --> {} using DIRECT",
            metadata.network.string().to_uppercase(),
            metadata.source_detail(),
            metadata.remote_address(),
        ),
        _ => infoln!(
            "[{}] {} --> {} doesn't match any rule using {}",
            metadata.network.string().to_uppercase(),
            metadata.source_detail(),
            metadata.remote_address(),
            remote_conn.chains().string(),
        ),
    }
}

/// The rule lookup, folded into `match_` below since it needs the same `CONFIG` guard.
fn get_rules<'a>(cfg: &'a ConfigState, metadata: &Metadata) -> &'a [Arc<dyn Rule>] {
    if let Some(sub_rules) = cfg.sub_rules.get(&metadata.special_rules) {
        debugln!("[Rule] use {} rules", metadata.special_rules);
        sub_rules
    } else {
        debugln!("[Rule] use default rules");
        &cfg.rules
    }
}

/// `match`; the name is a Rust keyword, hence the trailing underscore.
///
/// The config read guard is held for the whole call, including across the rematch proxy's dial.
/// `parking_lot::RwLockReadGuard` is not `Send`, so holding it across the `.await` below would make
/// this function's future non-`Send` (required for `TunnelTrait::handle_tcp_conn`'s `async_trait`
/// bound). The guard is dropped before the await and re-acquired on the next loop iteration
/// instead: a config update can now land in that narrow window where the lock would have blocked
/// it, which is the one observable deviation here.
// NOT cancel-safe: a rematch cancel leaves the metadata updated by the previous dial.
async fn match_(
    metadata: &mut Metadata,
    helper: RuleMatchHelper,
) -> Result<(Option<Arc<dyn Proxy>>, Option<Arc<dyn Rule>>)> {
    enum Outcome {
        Matched(Option<Arc<dyn Proxy>>, Option<Arc<dyn Rule>>),
        Rematch(Arc<dyn Proxy>, Option<Arc<dyn Rule>>),
    }

    let mut rematch_chain: Vec<String> = Vec::new();
    loop {
        let outcome = {
            let cfg = CONFIG.read();
            let mut rematch_proxy: Option<Arc<dyn Proxy>> = None;
            let mut rematch_rule: Option<Arc<dyn Rule>> = None;

            'get_rules: for rule in get_rules(&cfg, metadata) {
                let (matched, ada) = rule.match_(metadata, &helper);
                if !matched {
                    continue;
                }
                let Some(base_adapter) = cfg.proxies.get(ada.as_ref()).cloned() else {
                    continue;
                };

                let mut adapter = Some(Arc::clone(&base_adapter));
                while let Some(current) = adapter {
                    if current.type_() == AdapterType::PASS {
                        debugln!("{} match Pass rule", current.name());
                        continue 'get_rules;
                    }
                    if current.type_() == AdapterType::REMATCH {
                        debugln!("{} match Rematch rule", current.name());
                        rematch_proxy = Some(Arc::clone(&current));
                        rematch_rule = Some(Arc::clone(rule));
                        break 'get_rules;
                    }
                    adapter = current.unwrap(metadata, false);
                }

                if metadata.network == NetWork::UDP && !base_adapter.support_udp() {
                    debugln!("{} UDP is not supported", base_adapter.name());
                    continue;
                }

                return Ok((Some(base_adapter), Some(Arc::clone(rule))));
            }

            if let Some(rematch_proxy) = rematch_proxy {
                if rematch_chain.contains(&rematch_proxy.name()) {
                    warnln!("[Rule] rematch cycle detected on {}", rematch_proxy.name());
                    return Ok((Some(rematch_proxy), rematch_rule));
                }
                rematch_chain.push(rematch_proxy.name());
                Outcome::Rematch(rematch_proxy, rematch_rule)
            } else {
                Outcome::Matched(cfg.proxies.get("DIRECT").cloned(), None)
            }
        };

        let (rematch_proxy, rematch_rule) = match outcome {
            Outcome::Matched(proxy, rule) => return Ok((proxy, rule)),
            Outcome::Rematch(proxy, rule) => (proxy, rule),
        };

        let cancel = CancellationToken::new();
        let mut rematch_metadata = metadata.clone();
        let dial_result = rematch_proxy.dial_context(&cancel, &mut rematch_metadata).await;
        *metadata = rematch_metadata;
        match dial_result {
            Ok(conn) => {
                let _ = conn.shutdown_read();
                let _ = conn.shutdown_write();
            }
            Err(err) => {
                warnln!("[Rule] rematch proxy {} failed to update metadata: {err}", rematch_proxy.name());
                return Ok((Some(rematch_proxy), rematch_rule));
            }
        }
        debugln!(
            "[Rule] rematch proxy {} update metadata to rematch-name={:?} sub-rule={:?}",
            rematch_proxy.name(),
            metadata.in_name,
            metadata.special_rules,
        );
    }
}

fn should_stop_retry(err: &anyhow::Error) -> bool {
    if let Some(resolver_err) = err.downcast_ref::<resolver_mod::ResolverError>() {
        if resolver_err.is_ip_not_found()
            || matches!(
                resolver_err,
                resolver_mod::ResolverError::IpVersion | resolver_mod::ResolverError::Ipv6Disabled
            )
        {
            return true;
        }
    }
    err.downcast_ref::<ErrReject>().is_some()
}

type RetryFut<T> = Pin<Box<dyn Future<Output = Result<T>> + Send>>;

// NOT cancel-safe: a cancel drops the in-flight attempt and its last error.
async fn retry<T>(
    ctx: &CancellationToken,
    mut ft: impl FnMut(CancellationToken) -> RetryFut<T> + Send,
    fe: impl Fn(&anyhow::Error) + Send + Sync,
) -> Result<T> {
    let s = SlowDown::new();
    let mut last_err = anyhow!("retry: ft was never called");
    for _ in 0..10 {
        match ft(ctx.clone()).await {
            Ok(t) => return Ok(t),
            Err(err) => {
                fe(&err);
                if should_stop_retry(&err) {
                    return Err(err);
                }
                last_err = err;
                if s.wait(ctx).await.is_ok() {
                    continue;
                }
                return Err(last_err);
            }
        }
    }
    Err(last_err)
}

/// A fresh cancellation token that fires after `duration`; the returned handle mirrors the cancel
/// call.
fn new_timeout_cancellation(duration: Duration) -> (CancellationToken, tokio::task::JoinHandle<()>) {
    let token = CancellationToken::new();
    let child = token.clone();
    let handle = tokio::spawn(async move {
        tokio::time::sleep(duration).await;
        child.cancel();
    });
    (token, handle)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::task::{Context as TaskContext, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;
    use murmur_common::utils::ranges::IntRanges;
    use murmur_component::resolver::enhancer::{self as comp_enhancer, Enhancer, SharedEnhancer};
    use murmur_constant::adapters::WriteBack;
    use murmur_constant::adapters::{Chain, DelayHistory, ProxyInfo, ProxyState};
    use murmur_constant::rule::RuleType;

    static TEST_LOCK: TokioMutex<()> = TokioMutex::const_new(());

    #[derive(Default)]
    struct StubConn {
        read: io::Cursor<Vec<u8>>,
        written: Option<Arc<Mutex<Vec<u8>>>>,
    }

    impl AsyncRead for StubConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let read = &mut self.get_mut().read;
            let start = read.position() as usize;
            let size = buf.remaining().min(read.get_ref().len() - start);
            buf.put_slice(&read.get_ref()[start..start + size]);
            read.set_position((start + size) as u64);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for StubConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            if let Some(written) = &self.written {
                written.lock().extend_from_slice(buf);
            }
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for StubConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Err(io::Error::other("stub"))
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Err(io::Error::other("stub"))
        }
    }

    impl murmur_common_net::io::ExtendedStream for StubConn {}

    impl Connection for StubConn {
        fn chains(&self) -> Chain {
            Chain::default()
        }
        fn provider_chains(&self) -> Chain {
            Chain::default()
        }
        fn append_to_chains(&self, _adapter: Arc<dyn ProxyAdapter>) {}
        fn remote_destination(&self) -> String {
            String::new()
        }
    }

    enum DialBehavior {
        Fail,
        SucceedSetSpecialRules(String),
        RecordWrites(Arc<Mutex<Vec<u8>>>),
    }

    struct StubProxy {
        name: String,
        type_: AdapterType,
        support_udp: bool,
        unwrap_to: Option<Arc<dyn Proxy>>,
        dial_behavior: Option<DialBehavior>,
        dial_count: AtomicUsize,
        max_dials: usize,
    }

    impl StubProxy {
        fn new(name: &str, type_: AdapterType) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_owned(),
                type_,
                support_udp: true,
                unwrap_to: None,
                dial_behavior: None,
                dial_count: AtomicUsize::new(0),
                max_dials: usize::MAX,
            })
        }
    }

    #[async_trait]
    impl ProxyAdapter for StubProxy {
        fn name(&self) -> String {
            self.name.clone()
        }
        fn type_(&self) -> AdapterType {
            self.type_
        }
        fn addr(&self) -> String {
            String::new()
        }
        fn support_udp(&self) -> bool {
            self.support_udp
        }
        fn proxy_info(&self) -> ProxyInfo {
            ProxyInfo::default()
        }
        fn marshal_json(&self) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        async fn dial_context(
            &self,
            _ctx: &CancellationToken,
            metadata: &mut Metadata,
        ) -> Result<Box<dyn ConstantConn>> {
            let dials = self.dial_count.fetch_add(1, Ordering::SeqCst) + 1;
            assert!(
                dials <= self.max_dials,
                "StubProxy {:?} dialed {dials} times, exceeding the test's limit of {}",
                self.name,
                self.max_dials
            );
            match &self.dial_behavior {
                Some(DialBehavior::Fail) => Err(anyhow!("dial failed")),
                Some(DialBehavior::SucceedSetSpecialRules(rules)) => {
                    metadata.special_rules = rules.clone();
                    Ok(Box::new(StubConn::default()))
                }
                Some(DialBehavior::RecordWrites(written)) => {
                    Ok(Box::new(StubConn { written: Some(Arc::clone(written)), ..Default::default() }))
                }
                None => Err(anyhow!("dial not configured for this test")),
            }
        }
        async fn listen_packet_context(
            &self,
            _ctx: &CancellationToken,
            _metadata: &mut Metadata,
        ) -> Result<Arc<dyn PacketConn>> {
            Err(anyhow!("not implemented"))
        }
        fn support_uot(&self) -> bool {
            false
        }
        fn is_l3_protocol(&self, _metadata: &Metadata) -> bool {
            false
        }
        fn unwrap(&self, _metadata: &Metadata, _touch: bool) -> Option<Arc<dyn Proxy>> {
            self.unwrap_to.clone()
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Proxy for StubProxy {
        fn adapter(&self) -> Arc<dyn ProxyAdapter> {
            unimplemented!("not exercised by match_ tests")
        }
        fn alive_for_test_url(&self, _url: &str) -> bool {
            true
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            Vec::new()
        }
        fn extra_delay_histories(&self) -> HashMap<String, ProxyState> {
            HashMap::new()
        }
        fn last_delay_for_test_url(&self, _url: &str) -> u16 {
            0
        }
        // cancel-safe: the stub returns immediately and publishes no state.
        async fn url_test(
            &self,
            _ctx: &CancellationToken,
            _url: &str,
            _expected_status: IntRanges<u16>,
        ) -> Result<u16> {
            Ok(0)
        }
    }

    struct StubRule {
        target: String,
        matches: bool,
    }

    impl Rule for StubRule {
        fn rule_type(&self) -> RuleType {
            RuleType::DOMAIN
        }
        fn match_(&self, _metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
            (self.matches, Cow::Borrowed(self.target.as_str()))
        }
        fn adapter(&self) -> String {
            self.target.clone()
        }
        fn payload(&self) -> String {
            String::new()
        }
        fn provider_names(&self) -> Vec<String> {
            Vec::new()
        }
    }

    fn reset_config() {
        *CONFIG.write() = ConfigState::default();
    }

    #[cfg(target_os = "linux")]
    struct ProcessRule {
        expected_path: String,
    }

    #[cfg(target_os = "linux")]
    impl Rule for ProcessRule {
        fn rule_type(&self) -> RuleType {
            RuleType::PROCESS_PATH
        }

        fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
            if let Some(find_process) = &helper.find_process {
                find_process(metadata);
                find_process(metadata);
            }
            let matches =
                if CMFA { metadata.process == "example-package" } else { metadata.process_path == self.expected_path };
            (matches, Cow::Borrowed("process-match"))
        }

        fn adapter(&self) -> String {
            "process-match".to_owned()
        }

        fn payload(&self) -> String {
            self.expected_path.clone()
        }

        fn provider_names(&self) -> Vec<String> {
            Vec::new()
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn routing_modes_preserve_process_enrichment_and_inner_suppression() {
        use murmur_component_process::process::DEFAULT_PACKAGE_NAME_RESOLVER;
        use std::os::unix::fs::MetadataExt;

        fn package_name(_metadata: &Metadata) -> Result<String> {
            Ok("example-package".to_owned())
        }

        let _guard = TEST_LOCK.lock().await;
        reset_config();
        let previous_mode = mode();
        let previous_process_mode = find_process_mode();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let source = socket.local_addr().unwrap();
        let expected_path = std::fs::read_link("/proc/self/exe").unwrap().to_string_lossy().into_owned();
        let expected_uid = std::fs::metadata("/proc/self").unwrap().uid();
        let previous_package_resolver = DEFAULT_PACKAGE_NAME_RESOLVER.write().replace(package_name);
        {
            let mut config = CONFIG.write();
            config.proxies = Arc::new(
                ["DIRECT", "GLOBAL", "process-match"]
                    .into_iter()
                    .map(|name| {
                        let proxy: Arc<dyn Proxy> = StubProxy::new(name, AdapterType::DIRECT);
                        (name.to_owned(), proxy)
                    })
                    .collect(),
            );
            config.rules = vec![Arc::new(ProcessRule { expected_path: expected_path.clone() })];
        }

        for (routing_mode, fallback) in
            [(TunnelMode::DIRECT, "DIRECT"), (TunnelMode::GLOBAL, "GLOBAL"), (TunnelMode::RULE, "DIRECT")]
        {
            set_mode(routing_mode);
            for process_mode in [
                FindProcessMode::FIND_PROCESS_OFF,
                FindProcessMode::FIND_PROCESS_STRICT,
                FindProcessMode::FIND_PROCESS_ALWAYS,
            ] {
                set_find_process_mode(process_mode);
                for type_ in [Type::SOCKS5, Type::INNER] {
                    let mut metadata = Metadata {
                        network: NetWork::UDP,
                        type_,
                        src_ip: Some(source.ip()),
                        src_port: source.port(),
                        dst_ip: Some("192.0.2.1".parse().unwrap()),
                        dst_port: 443,
                        process: "unchanged".to_owned(),
                        process_path: "unchanged".to_owned(),
                        uid: u32::MAX,
                        ..Default::default()
                    };
                    let mut special_metadata = metadata.clone();
                    special_metadata.special_proxy = "process-match".to_owned();
                    let (proxy, rule) = resolve_metadata(&mut special_metadata).await.unwrap();
                    assert_eq!(proxy.unwrap().name(), "process-match");
                    assert!(rule.is_none());
                    assert_eq!(special_metadata.process, "unchanged");
                    assert_eq!(special_metadata.process_path, "unchanged");
                    assert_eq!(special_metadata.uid, u32::MAX);
                    let (proxy, rule) = resolve_metadata(&mut metadata).await.unwrap();
                    let enriched = type_ != Type::INNER
                        && (process_mode == FindProcessMode::FIND_PROCESS_ALWAYS
                            || (routing_mode == TunnelMode::RULE
                                && process_mode == FindProcessMode::FIND_PROCESS_STRICT));
                    let matched = routing_mode == TunnelMode::RULE && enriched;
                    assert_eq!(proxy.unwrap().name(), if matched { "process-match" } else { fallback });
                    assert_eq!(rule.is_some(), matched);
                    if enriched {
                        assert_eq!(metadata.process, "example-package");
                        if CMFA {
                            assert_eq!(metadata.process_path, "unchanged");
                            assert_eq!(metadata.uid, u32::MAX);
                        } else {
                            assert_eq!(metadata.process_path, expected_path);
                            assert_eq!(metadata.uid, expected_uid);
                        }
                    } else {
                        assert_eq!(metadata.process_path, "unchanged");
                        assert_eq!(metadata.process, "unchanged");
                        assert_eq!(metadata.uid, u32::MAX);
                    }
                }
            }
        }
        *DEFAULT_PACKAGE_NAME_RESOLVER.write() = previous_package_resolver;
        set_mode(previous_mode);
        set_find_process_mode(previous_process_mode);
        reset_config();
    }

    #[tokio::test]
    async fn routing_modes_resolve_hosts_but_special_proxy_bypasses_enrichment() {
        use murmur_component::resolver::host::{HostValue, Hosts};

        let _guard = TEST_LOCK.lock().await;
        reset_config();
        let previous_mode = mode();
        let previous_process_mode = find_process_mode();
        let previous_hosts = resolver_mod::default_hosts();
        let mut hosts = Hosts { domain_trie: Default::default() };
        let expected_ip = "192.0.2.17".parse().unwrap();
        hosts.domain_trie.insert("example.com", HostValue::by_ips(vec![expected_ip]).unwrap()).unwrap();
        resolver_mod::set_default_hosts(hosts);
        CONFIG.write().proxies = Arc::new(
            ["DIRECT", "GLOBAL", "special"]
                .into_iter()
                .map(|name| {
                    let proxy: Arc<dyn Proxy> = StubProxy::new(name, AdapterType::DIRECT);
                    (name.to_owned(), proxy)
                })
                .collect(),
        );
        set_find_process_mode(FindProcessMode::FIND_PROCESS_ALWAYS);
        for (routing_mode, expected_proxy) in
            [(TunnelMode::DIRECT, "DIRECT"), (TunnelMode::GLOBAL, "GLOBAL"), (TunnelMode::RULE, "DIRECT")]
        {
            set_mode(routing_mode);
            let mut metadata = Metadata { host: "example.com".to_owned(), type_: Type::INNER, ..Default::default() };
            let (proxy, rule) = resolve_metadata(&mut metadata).await.unwrap();
            assert_eq!(proxy.unwrap().name(), expected_proxy);
            assert!(rule.is_none());
            assert_eq!(metadata.dst_ip, Some(expected_ip));

            metadata.dst_ip = None;
            metadata.special_proxy = "special".to_owned();
            let (proxy, rule) = resolve_metadata(&mut metadata).await.unwrap();
            assert_eq!(proxy.unwrap().name(), "special");
            assert!(rule.is_none());
            assert_eq!(metadata.dst_ip, None);
            metadata.special_proxy = "missing".to_owned();
            assert!(resolve_metadata(&mut metadata).await.is_err());
            assert_eq!(metadata.dst_ip, None);
        }
        resolver_mod::set_default_hosts(Arc::try_unwrap(previous_hosts).unwrap());
        set_mode(previous_mode);
        set_find_process_mode(previous_process_mode);
        reset_config();
    }

    struct HostsPassRule {
        expected_ip: Option<IpAddr>,
    }

    impl Rule for HostsPassRule {
        fn rule_type(&self) -> RuleType {
            RuleType::IPCIDR
        }

        fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
            if let Some(resolve_ip) = &helper.resolve_ip {
                resolve_ip(metadata);
                resolve_ip(metadata);
            }
            let pass = helper.check_pass_rule.as_ref().is_some_and(|check| check(metadata, "pass"));
            (metadata.dst_ip == self.expected_ip && pass, Cow::Borrowed("GLOBAL"))
        }

        fn adapter(&self) -> String {
            "GLOBAL".to_owned()
        }

        fn payload(&self) -> String {
            String::new()
        }

        fn provider_names(&self) -> Vec<String> {
            Vec::new()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rule_routing_keeps_hosts_resolution_and_pass_rule_callbacks_when_process_is_off() {
        use murmur_component::resolver::host::{HostValue, Hosts};

        let _guard = TEST_LOCK.lock().await;
        reset_config();
        let previous_mode = mode();
        let previous_process_mode = find_process_mode();
        let previous_hosts = resolver_mod::default_hosts();
        let expected_ip: IpAddr = "192.0.2.17".parse().unwrap();
        let mut hosts = Hosts { domain_trie: Default::default() };
        hosts.domain_trie.insert("example.com", HostValue::by_ips(vec![expected_ip]).unwrap()).unwrap();
        hosts.domain_trie.insert("192.0.2.18", HostValue::by_domain("unresolved.example.com").unwrap()).unwrap();
        resolver_mod::set_default_hosts(hosts);
        let direct: Arc<dyn Proxy> = StubProxy::new("DIRECT", AdapterType::DIRECT);
        let global: Arc<dyn Proxy> = StubProxy::new("GLOBAL", AdapterType::DIRECT);
        let pass: Arc<dyn Proxy> = StubProxy::new("pass", AdapterType::PASS_RULE);
        CONFIG.write().proxies = Arc::new(HashMap::from([
            ("DIRECT".to_owned(), direct),
            ("GLOBAL".to_owned(), global),
            ("pass".to_owned(), pass),
        ]));
        set_mode(TunnelMode::RULE);
        set_find_process_mode(FindProcessMode::FIND_PROCESS_OFF);
        for (host, expected_ip) in [("example.com", Some(expected_ip)), ("192.0.2.18", None)] {
            CONFIG.write().rules = vec![Arc::new(HostsPassRule { expected_ip })];
            let mut metadata = Metadata { host: host.to_owned(), type_: Type::SOCKS5, ..Default::default() };
            let (proxy, rule) = resolve_metadata(&mut metadata).await.unwrap();
            assert_eq!(proxy.unwrap().name(), "GLOBAL");
            assert!(rule.is_some());
            assert_eq!(metadata.dst_ip, expected_ip);
        }
        resolver_mod::set_default_hosts(Arc::try_unwrap(previous_hosts).unwrap());
        set_mode(previous_mode);
        set_find_process_mode(previous_process_mode);
        reset_config();
    }

    #[tokio::test]
    async fn match_skips_pass_found_anywhere_in_the_unwrap_chain() {
        let _guard = TEST_LOCK.lock().await;
        reset_config();

        let inner_pass = StubProxy::new("inner-pass", AdapterType::PASS);
        let outer = Arc::new(StubProxy {
            name: "outer".to_owned(),
            type_: AdapterType::SELECTOR,
            support_udp: true,
            unwrap_to: Some(inner_pass),
            dial_behavior: None,
            dial_count: AtomicUsize::new(0),
            max_dials: usize::MAX,
        });
        let direct = StubProxy::new("direct", AdapterType::DIRECT);

        {
            let mut cfg = CONFIG.write();
            let mut proxies = (*cfg.proxies).clone();
            let outer_arc = Arc::clone(&outer);
            let outer: Arc<dyn Proxy> = outer_arc;
            proxies.insert("outer".to_owned(), outer);
            let direct_arc = Arc::clone(&direct);
            let direct: Arc<dyn Proxy> = direct_arc;
            proxies.insert("direct".to_owned(), direct);
            cfg.proxies = Arc::new(proxies);
            cfg.rules = vec![
                Arc::new(StubRule { target: "outer".to_owned(), matches: true }),
                Arc::new(StubRule { target: "direct".to_owned(), matches: true }),
            ];
        }

        let mut metadata = Metadata::default();
        let (proxy, _rule) = match_(&mut metadata, RuleMatchHelper::default()).await.unwrap();
        assert_eq!(proxy.unwrap().name(), "direct");

        reset_config();
    }

    #[tokio::test]
    async fn match_falls_through_to_direct_when_nothing_matches() {
        let _guard = TEST_LOCK.lock().await;
        reset_config();

        let direct = StubProxy::new("DIRECT", AdapterType::DIRECT);
        {
            let mut cfg = CONFIG.write();
            let mut proxies = (*cfg.proxies).clone();
            proxies.insert("DIRECT".to_owned(), direct);
            cfg.proxies = Arc::new(proxies);
            cfg.rules = vec![Arc::new(StubRule { target: "nope".to_owned(), matches: false })];
        }

        let mut metadata = Metadata::default();
        let (proxy, rule) = match_(&mut metadata, RuleMatchHelper::default()).await.unwrap();
        assert_eq!(proxy.unwrap().name(), "DIRECT");
        assert!(rule.is_none());

        reset_config();
    }

    #[tokio::test]
    async fn match_skips_udp_unsupported_adapters_and_tries_the_next_rule() {
        let _guard = TEST_LOCK.lock().await;
        reset_config();

        let no_udp = Arc::new(StubProxy {
            name: "no-udp".to_owned(),
            type_: AdapterType::DIRECT,
            support_udp: false,
            unwrap_to: None,
            dial_behavior: None,
            dial_count: AtomicUsize::new(0),
            max_dials: usize::MAX,
        });
        let with_udp = StubProxy::new("with-udp", AdapterType::DIRECT);

        {
            let mut cfg = CONFIG.write();
            let mut proxies = (*cfg.proxies).clone();
            proxies.insert("no-udp".to_owned(), no_udp);
            proxies.insert("with-udp".to_owned(), with_udp);
            cfg.proxies = Arc::new(proxies);
            cfg.rules = vec![
                Arc::new(StubRule { target: "no-udp".to_owned(), matches: true }),
                Arc::new(StubRule { target: "with-udp".to_owned(), matches: true }),
            ];
        }

        let mut metadata = Metadata { network: NetWork::UDP, ..Default::default() };
        let (proxy, _rule) = match_(&mut metadata, RuleMatchHelper::default()).await.unwrap();
        assert_eq!(proxy.unwrap().name(), "with-udp");

        reset_config();
    }

    #[tokio::test]
    async fn match_rematch_updates_metadata_and_detects_a_cycle() {
        let _guard = TEST_LOCK.lock().await;
        reset_config();

        let looper = Arc::new(StubProxy {
            name: "looper".to_owned(),
            type_: AdapterType::REMATCH,
            support_udp: true,
            unwrap_to: None,
            dial_behavior: Some(DialBehavior::SucceedSetSpecialRules("loop".to_owned())),
            dial_count: AtomicUsize::new(0),
            max_dials: 2,
        });

        {
            let mut cfg = CONFIG.write();
            let mut proxies = (*cfg.proxies).clone();
            let looper_arc = Arc::clone(&looper);
            let looper: Arc<dyn Proxy> = looper_arc;
            proxies.insert("looper".to_owned(), looper);
            cfg.proxies = Arc::new(proxies);
            cfg.rules = vec![Arc::new(StubRule { target: "looper".to_owned(), matches: true })];
            cfg.sub_rules
                .insert("loop".to_owned(), vec![Arc::new(StubRule { target: "looper".to_owned(), matches: true })]);
        }

        let mut metadata = Metadata::default();
        let result =
            tokio::time::timeout(Duration::from_secs(5), match_(&mut metadata, RuleMatchHelper::default())).await;
        let (proxy, _rule) = result.expect("rematch cycle detection must terminate").unwrap();
        assert_eq!(proxy.unwrap().name(), "looper");
        assert_eq!(metadata.special_rules, "loop");
        assert_eq!(looper.dial_count.load(Ordering::SeqCst), 1, "the rematch proxy is dialed exactly once");

        reset_config();
    }

    #[tokio::test]
    async fn match_rematch_dial_failure_returns_the_rematch_proxy() {
        let _guard = TEST_LOCK.lock().await;
        reset_config();

        let broken = Arc::new(StubProxy {
            name: "broken".to_owned(),
            type_: AdapterType::REMATCH,
            support_udp: true,
            unwrap_to: None,
            dial_behavior: Some(DialBehavior::Fail),
            dial_count: AtomicUsize::new(0),
            max_dials: 1,
        });

        {
            let mut cfg = CONFIG.write();
            let mut proxies = (*cfg.proxies).clone();
            let broken_arc = Arc::clone(&broken);
            let broken: Arc<dyn Proxy> = broken_arc;
            proxies.insert("broken".to_owned(), broken);
            cfg.proxies = Arc::new(proxies);
            cfg.rules = vec![Arc::new(StubRule { target: "broken".to_owned(), matches: true })];
        }

        let mut metadata = Metadata::default();
        let (proxy, rule) = match_(&mut metadata, RuleMatchHelper::default()).await.unwrap();
        assert_eq!(proxy.unwrap().name(), "broken");
        assert!(rule.is_some());
        assert_eq!(
            broken.dial_count.load(Ordering::SeqCst),
            1,
            "a rematch dial failure returns straight away, instead of looping back and \
             rematching again"
        );

        reset_config();
    }

    struct MockEnhancer {
        mapping: HashMap<IpAddr, String>,
        fake_ip: IpAddr,
    }

    impl Enhancer for MockEnhancer {
        fn fake_ip_enabled(&self) -> bool {
            true
        }
        fn mapping_enabled(&self) -> bool {
            true
        }
        fn is_fake_ip(&self, ip: IpAddr) -> bool {
            ip == self.fake_ip
        }
        fn is_fake_broadcast_ip(&self, _ip: IpAddr) -> bool {
            false
        }
        fn is_exist_fake_ip(&self, ip: IpAddr) -> bool {
            self.mapping.contains_key(&ip)
        }
        fn find_host_by_ip(&self, ip: IpAddr) -> Option<String> {
            self.mapping.get(&ip).cloned()
        }
        fn flush_fake_ip(&self) -> Result<()> {
            Ok(())
        }
        fn insert_host_by_ip(&self, _ip: IpAddr, _host: &str) {}
        fn store_fake_pool_state(&self) {}
    }

    #[tokio::test]
    async fn pre_handle_metadata_restores_the_host_for_a_mapped_fake_ip() {
        let _guard = TEST_LOCK.lock().await;
        let fake_ip: IpAddr = "198.18.0.1".parse().unwrap();
        let mapper: SharedEnhancer =
            Arc::new(MockEnhancer { mapping: HashMap::from([(fake_ip, "example.com".to_owned())]), fake_ip });
        comp_enhancer::set_default_host_mapper(Some(mapper));

        let mut metadata = Metadata { host: String::new(), dst_ip: Some(fake_ip), ..Default::default() };
        let result = pre_handle_metadata(&mut metadata).await;

        comp_enhancer::set_default_host_mapper(None);

        result.unwrap();
        assert_eq!(metadata.host, "example.com");
        assert_eq!(metadata.dst_ip, None);
        assert_eq!(metadata.dns_mode, DNSMode::DNS_FAKE_IP);
    }

    #[tokio::test]
    async fn pre_handle_metadata_errors_on_an_unmapped_fake_ip() {
        let _guard = TEST_LOCK.lock().await;
        let fake_ip: IpAddr = "198.18.0.2".parse().unwrap();
        let mapper: SharedEnhancer = Arc::new(MockEnhancer { mapping: HashMap::new(), fake_ip });
        comp_enhancer::set_default_host_mapper(Some(mapper));

        let mut metadata = Metadata { host: String::new(), dst_ip: Some(fake_ip), ..Default::default() };
        let result = pre_handle_metadata(&mut metadata).await;

        comp_enhancer::set_default_host_mapper(None);

        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "fake DNS record 198.18.0.2 missing");
    }

    struct RecordingPacket {
        local: SocketAddr,
        data: Vec<u8>,
        session_key: Option<&'static str>,
    }

    #[async_trait]
    impl WriteBack for RecordingPacket {
        async fn write_back(&self, _b: &[u8], _addr: Option<SocketAddr>) -> Result<usize> {
            Ok(0)
        }
    }

    impl UDPPacket for RecordingPacket {
        fn data(&self) -> &[u8] {
            &self.data
        }

        fn drop_(&self) {}

        fn local_addr(&self) -> SocketAddr {
            self.local
        }

        fn nat_key(&self) -> String {
            self.session_key.map_or_else(|| self.local.to_string(), str::to_owned)
        }
    }

    struct RecordingSender {
        sent: Mutex<Vec<usize>>,
        delivered: Notify,
    }

    #[async_trait]
    impl PacketSender for RecordingSender {
        async fn send(&self, packet: Arc<dyn PacketAdapter>) {
            self.sent.lock().push(packet.data().len());
            self.delivered.notify_one();
        }

        async fn process(&self, _conn: Arc<dyn PacketConn>, _proxy: Arc<dyn WriteBackProxy>) {}

        fn close(&self) {}

        async fn do_sniff(&self, _metadata: &mut Metadata) -> Result<()> {
            Ok(())
        }

        fn add_mapping(&self, _origin_metadata: &Metadata, _metadata: &Metadata) {}

        fn restore_read_from(&self, addr: IpAddr) -> IpAddr {
            addr
        }
    }

    #[tokio::test]
    async fn inner_udp_progresses_while_bounded_external_queue_waits() {
        let _guard = TEST_LOCK.lock().await;
        reset_config();
        on_suspend();
        let apply = begin_config_apply().unwrap();
        let external = Arc::new(RecordingSender { sent: Mutex::new(Vec::new()), delivered: Notify::new() });
        let inner = Arc::new(RecordingSender { sent: Mutex::new(Vec::new()), delivered: Notify::new() });
        let keys = ["apply-queue-external", "apply-queue-inner"];
        for (key, sender) in keys.into_iter().zip([&external, &inner]) {
            let sender: Arc<dyn PacketSender> = Arc::<RecordingSender>::clone(sender);
            nat_table().get_or_create(key, Box::new(move || sender));
        }
        let send = |type_, key| {
            let packet = Arc::new(RecordingPacket {
                local: "127.0.0.1:58234".parse().unwrap(),
                data: vec![42; 17],
                session_key: Some(key),
            });
            let metadata = Metadata {
                network: NetWork::UDP,
                type_,
                dst_ip: Some("192.0.2.1".parse().unwrap()),
                dst_port: 443,
                ..Default::default()
            };
            TUNNEL.handle_udp_packet(packet, metadata);
        };
        for _ in 0..QUEUE_CAPACITY + 8 {
            send(Type::TUN, keys[0]);
        }
        apply.inner_loading().unwrap();
        send(Type::INNER, keys[1]);
        tokio::time::timeout(DEFAULT_TCP_TIMEOUT, inner.delivered.notified()).await.unwrap();
        assert_eq!(*inner.sent.lock(), [17]);
        assert!(external.sent.lock().is_empty());
        apply.finish().unwrap();
        tokio::time::timeout(DEFAULT_TCP_TIMEOUT, async {
            while external.sent.lock().len() != QUEUE_CAPACITY {
                external.delivered.notified().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(external.sent.lock().len(), QUEUE_CAPACITY);
        for key in keys {
            nat_table().delete(key);
        }
        on_suspend();
    }

    async fn pending_once(mut future: Pin<&mut impl Future>) {
        assert!(std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending())).await);
    }

    #[tokio::test]
    async fn startup_waits_but_terminal_suspend_rejects() {
        let _guard = TEST_LOCK.lock().await;
        on_suspend();
        assert!(!admit(Type::TUN, None, true).await);
        assert!(!admit(Type::INNER, None, false).await);
        let apply = begin_config_apply().unwrap();
        assert!(begin_config_apply().is_err());
        let external = admit(Type::TUN, None, true);
        tokio::pin!(external);
        pending_once(external.as_mut()).await;
        apply.inner_loading().unwrap();
        assert!(admit(Type::INNER, None, true).await);
        assert!(admit(Type::INNER, None, false).await);
        pending_once(external.as_mut()).await;
        apply.finish().unwrap();
        assert!(external.await);
        on_suspend();
    }

    #[tokio::test]
    async fn cancelled_apply_wakes_waiters_and_new_arrivals_fail_closed() {
        let _guard = TEST_LOCK.lock().await;
        on_suspend();
        let apply = begin_config_apply().unwrap();
        struct WakeCount(AtomicUsize);
        impl std::task::Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(Arc::clone(&wakes));
        let mut context = TaskContext::from_waker(&waker);
        let pending = admit(Type::TUN, None, true);
        let pending_udp = admit(Type::TUN, None, false);
        tokio::pin!(pending_udp);
        assert!(pending_udp.as_mut().poll(&mut context).is_pending());
        tokio::pin!(pending);
        assert!(pending.as_mut().poll(&mut context).is_pending());
        drop(apply);
        assert!(wakes.0.load(Ordering::SeqCst) >= 2);
        assert!(!pending.await);
        assert!(!pending_udp.await);
        assert!(!admit(Type::TUN, None, true).await);
        assert!(!admit(Type::INNER, None, false).await);
    }

    #[tokio::test]
    async fn a_new_success_cannot_revive_waiters_from_a_failed_generation() {
        let _guard = TEST_LOCK.lock().await;
        let failed = begin_config_apply().unwrap();
        let pending = admit(Type::TUN, None, true);
        tokio::pin!(pending);
        pending_once(pending.as_mut()).await;
        let queued = admission_wait(ADMISSION.load(Ordering::Acquire));
        drop(failed);
        begin_config_apply().unwrap().finish().unwrap();
        assert!(!pending.await);
        assert!(!admit(Type::TUN, queued, false).await);
        on_suspend();
    }

    #[tokio::test]
    async fn terminal_suspend_invalidates_an_apply_guard() {
        let _guard = TEST_LOCK.lock().await;
        let apply = begin_config_apply().unwrap();
        let pending = admit(Type::TUN, None, false);
        tokio::pin!(pending);
        pending_once(pending.as_mut()).await;
        on_suspend();
        assert!(!pending.await);
        assert!(apply.inner_loading().is_err());
        assert!(apply.finish().is_err());
        assert!(!admit(Type::TUN, None, true).await);
    }

    #[tokio::test]
    async fn stale_guard_drop_cannot_cancel_a_new_apply() {
        let _guard = TEST_LOCK.lock().await;
        let stale = begin_config_apply().unwrap();
        on_suspend();
        let current = begin_config_apply().unwrap();
        drop(stale);
        current.inner_loading().unwrap();
        current.finish().unwrap();
        assert!(admit(Type::TUN, None, true).await);
        on_suspend();
    }

    #[tokio::test]
    async fn resume_before_wait_registration_is_not_lost() {
        let _guard = TEST_LOCK.lock().await;
        let apply = begin_config_apply().unwrap();
        let queued = admission_wait(ADMISSION.load(Ordering::Acquire));
        apply.finish().unwrap();
        assert!(admit(Type::TUN, queued, false).await);
        on_suspend();
    }

    #[tokio::test(start_paused = true)]
    async fn pending_tcp_is_bounded_and_cancellation_releases_capacity() {
        let _guard = TEST_LOCK.lock().await;
        let apply = begin_config_apply().unwrap();
        let mut pending = Vec::new();
        for _ in 0..QUEUE_CAPACITY {
            let mut future = Box::pin(admit(Type::TUN, None, true));
            pending_once(future.as_mut()).await;
            pending.push(future);
        }
        assert!(!admit(Type::TUN, None, true).await);
        apply.inner_loading().unwrap();
        assert!(admit(Type::INNER, None, true).await);
        assert!(admit(Type::INNER, None, false).await);
        drop(pending.pop());
        let mut replacement = Box::pin(admit(Type::TUN, None, true));
        pending_once(replacement.as_mut()).await;
        tokio::time::advance(DEFAULT_TCP_TIMEOUT / 2).await;
        apply.inner_loading().unwrap();
        pending_once(replacement.as_mut()).await;
        tokio::time::advance(DEFAULT_TCP_TIMEOUT / 2).await;
        assert!(!replacement.await);
        for future in pending {
            assert!(!future.await);
        }
        let fresh = admit(Type::TUN, None, true);
        tokio::pin!(fresh);
        pending_once(fresh.as_mut()).await;
        apply.finish().unwrap();
        assert!(fresh.await);
        on_suspend();
    }

    #[tokio::test(start_paused = true)]
    async fn queued_udp_deadline_does_not_restart_when_dequeued() {
        let _guard = TEST_LOCK.lock().await;
        let apply = begin_config_apply().unwrap();
        let queued = admission_wait(ADMISSION.load(Ordering::Acquire));
        tokio::time::advance(DEFAULT_TCP_TIMEOUT).await;
        apply.finish().unwrap();
        assert!(!admit(Type::TUN, queued, false).await);
        on_suspend();
    }

    #[tokio::test]
    async fn consecutive_successful_applies_keep_pending_admissions() {
        let _guard = TEST_LOCK.lock().await;
        let first = begin_config_apply().unwrap();
        let pending = admit(Type::TUN, None, true);
        tokio::pin!(pending);
        pending_once(pending.as_mut()).await;
        let queued = admission_wait(ADMISSION.load(Ordering::Acquire));
        first.finish().unwrap();
        let second = begin_config_apply().unwrap();
        pending_once(pending.as_mut()).await;
        second.finish().unwrap();
        assert!(pending.await);
        assert!(admit(Type::TUN, queued, false).await);
        on_suspend();
    }

    #[tokio::test]
    async fn applying_configuration_holds_tcp_until_resume() {
        let _guard = TEST_LOCK.lock().await;
        reset_config();
        let written = Arc::new(Mutex::new(Vec::new()));
        let proxy = Arc::new(StubProxy {
            name: "DIRECT".to_owned(),
            type_: AdapterType::DIRECT,
            support_udp: true,
            unwrap_to: None,
            dial_behavior: Some(DialBehavior::RecordWrites(Arc::clone(&written))),
            dial_count: AtomicUsize::new(0),
            max_dials: 1,
        });
        let outbound: Arc<dyn Proxy> = Arc::<StubProxy>::clone(&proxy);
        update_proxies(HashMap::from([("DIRECT".to_owned(), outbound)]), HashMap::new());
        let metadata = Metadata {
            type_: Type::TUN,
            dst_ip: Some("203.0.113.9".parse().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        let apply = begin_config_apply().unwrap();
        let inbound = StubConn { read: io::Cursor::new(b"held payload".to_vec()), written: None };
        let pending = TUNNEL.handle_tcp_conn(Box::new(inbound), metadata);
        tokio::pin!(pending);
        assert!(std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx).is_pending())).await);
        assert_eq!(proxy.dial_count.load(Ordering::SeqCst), 0);
        assert!(written.lock().is_empty());
        apply.finish().unwrap();
        pending.await;
        assert_eq!(proxy.dial_count.load(Ordering::SeqCst), 1);
        assert_eq!(*written.lock(), b"held payload");
        on_suspend();
        reset_config();
    }

    #[tokio::test]
    async fn applying_configuration_holds_udp_until_resume() {
        let _guard = TEST_LOCK.lock().await;
        reset_config();
        let recording = Arc::new(RecordingSender { sent: Mutex::new(Vec::new()), delivered: Notify::new() });
        let sender: Arc<dyn PacketSender> = Arc::<RecordingSender>::clone(&recording);
        let key = "pending-apply-datagram";
        nat_table().get_or_create(key, Box::new(move || sender));
        let packet = Arc::new(RecordingPacket {
            local: "127.0.0.1:58233".parse().unwrap(),
            data: vec![42; 17],
            session_key: Some(key),
        });
        let metadata = Metadata {
            network: NetWork::UDP,
            type_: Type::TUN,
            dst_ip: Some("203.0.113.9".parse().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        let apply = begin_config_apply().unwrap();
        let pending = handle_udp_conn(new_packet_adapter(packet, metadata));
        tokio::pin!(pending);
        assert!(std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx).is_pending())).await);
        assert!(recording.sent.lock().is_empty());
        apply.finish().unwrap();
        pending.await;
        assert_eq!(*recording.sent.lock(), [17]);
        nat_table().delete(key);
        on_suspend();
    }

    /// Datagrams for a key that is already in the NAT table go straight to the stored sender: one
    /// sender, no second dial, for every packet of the flow.
    #[tokio::test]
    async fn an_established_udp_key_reuses_its_sender_for_every_datagram() {
        const PACKETS: usize = 1000;
        let _guard = TEST_LOCK.lock().await;
        reset_config();
        begin_config_apply().unwrap().finish().unwrap();

        let recording = Arc::new(RecordingSender { sent: Mutex::new(Vec::new()), delivered: Notify::new() });
        let shared = Arc::clone(&recording);
        let sender: Arc<dyn PacketSender> = shared;
        let registered = Arc::clone(&sender);
        let local: SocketAddr = "127.0.0.1:58231".parse().expect("valid loopback address");
        let key = local.to_string();
        let (stored, loaded) = nat_table().get_or_create(&key, Box::new(move || registered));
        assert!(!loaded, "the test registered the key itself");
        assert!(Arc::ptr_eq(&stored, &sender), "the test's sender was not stored");

        for _ in 0..PACKETS {
            let metadata = Metadata {
                network: NetWork::UDP,
                type_: Type::TUN,
                dst_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
                dst_port: 443,
                ..Default::default()
            };
            let packet: Arc<dyn UDPPacket> =
                Arc::new(RecordingPacket { local, data: vec![0x2a; 64], session_key: None });
            let adapter = new_packet_adapter(packet, metadata);
            assert_eq!(adapter.key_ref(), key, "the established lookup key changed");
            handle_udp_conn(adapter).await;
        }

        assert_eq!(recording.sent.lock().len(), PACKETS, "a datagram did not reach the stored sender");
        nat_table().delete(&key);
        on_suspend();
    }

    #[tokio::test]
    async fn multiplexed_udp_sessions_at_one_peer_keep_distinct_senders() {
        let _guard = TEST_LOCK.lock().await;
        reset_config();
        begin_config_apply().unwrap().finish().unwrap();
        let local: SocketAddr = "127.0.0.1:58232".parse().unwrap();
        let first = Arc::new(RecordingSender { sent: Mutex::new(Vec::new()), delivered: Notify::new() });
        let second = Arc::new(RecordingSender { sent: Mutex::new(Vec::new()), delivered: Notify::new() });
        let keys = ["tunnel-test-session-one", "tunnel-test-session-two"];

        for (key, sender) in keys.into_iter().zip([&first, &second]) {
            let registered: Arc<dyn PacketSender> = Arc::<RecordingSender>::clone(sender);
            let (_, loaded) = nat_table().get_or_create(key, Box::new(move || registered));
            assert!(!loaded);
        }
        for (key, size, destination) in
            [(keys[0], 11, "203.0.113.1"), (keys[1], 22, "2001:db8::1"), (keys[0], 33, "203.0.113.2")]
        {
            let packet = Arc::new(RecordingPacket { local, data: vec![0x2a; size], session_key: Some(key) });
            let metadata = Metadata {
                network: NetWork::UDP,
                type_: Type::TUN,
                dst_ip: Some(destination.parse().unwrap()),
                dst_port: 443,
                ..Default::default()
            };
            handle_udp_conn(new_packet_adapter(packet, metadata)).await;
        }

        assert_eq!(*first.sent.lock(), [11, 33]);
        assert_eq!(*second.sent.lock(), [22]);
        for key in keys {
            nat_table().delete(key);
        }
        on_suspend();
    }
}

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
use tokio::sync::{mpsc, Mutex as TokioMutex};
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

static STATUS: LazyLock<Int32Enum<TunnelStatus>> = LazyLock::new(|| new_int32_enum(TunnelStatus::SUSPEND));
static UDP_INIT: Once = Once::new();
static UDP_QUEUES: RwLock<Vec<mpsc::Sender<PacketAdapterImpl>>> = RwLock::new(Vec::new());
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
        UDP_INIT.call_once(init_udp);

        let packet_adapter = new_packet_adapter(packet, metadata);
        let key = packet_adapter.key();

        let hash = map_hash(&key);
        let queues = UDP_QUEUES.read();
        #[expect(clippy::cast_possible_truncation, reason = "the shard index takes the low bits of the hash")]
        let queue_no = (hash as usize) % queues.len();

        let Some(queue) = queues.get(queue_no) else {
            packet_adapter.drop_();
            return;
        };
        match queue.try_send(packet_adapter) {
            Ok(()) => {}
            Err(
                mpsc::error::TrySendError::Full(packet_adapter) | mpsc::error::TrySendError::Closed(packet_adapter),
            ) => {
                packet_adapter.drop_();
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

fn init_udp() {
    let mut num_udp_workers: usize = 4;
    if let Ok(available) = std::thread::available_parallelism() {
        if available.get() > num_udp_workers {
            num_udp_workers = available.get();
        }
    }

    let mut queues = Vec::with_capacity(num_udp_workers);
    for _ in 0..num_udp_workers {
        let (tx, rx) = mpsc::channel::<PacketAdapterImpl>(QUEUE_CAPACITY);
        queues.push(tx);
        tokio::spawn(process_udp(rx));
    }
    *UDP_QUEUES.write() = queues;
}

pub fn on_suspend() {
    STATUS.store(TunnelStatus::SUSPEND);
}

pub fn on_inner_loading() {
    STATUS.store(TunnelStatus::INNER);
}

pub fn on_running() {
    STATUS.store(TunnelStatus::RUNNING);
}

pub fn status() -> TunnelStatus {
    STATUS.load()
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

fn is_handle(t: Type) -> bool {
    let current = status();
    current == TunnelStatus::RUNNING || (current == TunnelStatus::INNER && t == Type::INNER)
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

/// Fills the process (or package, on Android) once, guarded by the same flag.
fn find_process_callback(attempt_process_lookup: Arc<AtomicBool>) -> Arc<dyn Fn(&mut Metadata) + Send + Sync> {
    Arc::new(move |metadata: &mut Metadata| {
        if !attempt_process_lookup.swap(false, Ordering::SeqCst) {
            return;
        }
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

    let resolved = Arc::new(AtomicBool::new(false));
    let attempt_process_lookup = Arc::new(AtomicBool::new(metadata.type_ != Type::INNER));

    if let Some((node, _)) = resolver_mod::default_hosts().search(&metadata.host, false).await {
        if let Ok(dst_ip) = node.rand_ip() {
            metadata.dst_ip = Some(dst_ip);
        }
        resolved.store(true, Ordering::SeqCst);
    }

    let resolve_ip = resolve_ip_callback(Arc::clone(&resolved));
    let find_process = find_process_callback(Arc::clone(&attempt_process_lookup));

    let proxies_snapshot = Arc::clone(&CONFIG.read().proxies);
    let check_pass_rule = check_pass_rule_callback(Arc::clone(&proxies_snapshot));

    let mut helper = RuleMatchHelper {
        resolve_ip: Some(resolve_ip),
        find_process: Some(find_process),
        check_pass_rule: Some(check_pass_rule),
    };

    match find_process_mode() {
        FindProcessMode::FIND_PROCESS_ALWAYS => {
            if let Some(f) = &helper.find_process {
                f(metadata);
            }
            helper.find_process = None;
        }
        FindProcessMode::FIND_PROCESS_OFF => {
            helper.find_process = None;
        }
        _ => {}
    }

    match mode() {
        TunnelMode::DIRECT => Ok((proxies_snapshot.get("DIRECT").cloned(), None)),
        TunnelMode::GLOBAL => Ok((proxies_snapshot.get("GLOBAL").cloned(), None)),
        _ => match_(metadata, helper).await,
    }
}

/// Starts a loop to handle UDP packets.
// cancel-safe: cancellation only stops dequeuing; the queue senders stay usable.
async fn process_udp(mut queue: mpsc::Receiver<PacketAdapterImpl>) {
    while let Some(packet) = queue.recv().await {
        handle_udp_conn(packet).await;
    }
}

/// Handles one dequeued UDP datagram.
///
/// The queue loop is the production caller. The per-datagram measurement in
/// `benches/udp_dispatch.rs` calls this directly so the established-hit and miss paths are measured
/// through the real function rather than a copy of its operations.
// NOT cancel-safe: a cancel after the nat-table insert leaves that entry to expire.
#[doc(hidden)]
pub async fn handle_udp_conn(mut packet_adapter: PacketAdapterImpl) {
    if !is_handle(packet_adapter.metadata().type_) {
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
    if !is_handle(conn_ctx.metadata().type_) {
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

    struct StubConn;

    impl AsyncRead for StubConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for StubConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
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
                    Ok(Box::new(StubConn))
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
    }

    struct RecordingSender {
        sent: Mutex<Vec<usize>>,
    }

    #[async_trait]
    impl PacketSender for RecordingSender {
        async fn send(&self, packet: Arc<dyn PacketAdapter>) {
            self.sent.lock().push(packet.data().len());
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

    /// Datagrams for a key that is already in the NAT table go straight to the stored sender: one
    /// sender, no second dial, for every packet of the flow.
    #[tokio::test]
    async fn an_established_udp_key_reuses_its_sender_for_every_datagram() {
        const PACKETS: usize = 1000;
        let _guard = TEST_LOCK.lock().await;
        reset_config();
        on_running();

        let recording = Arc::new(RecordingSender { sent: Mutex::new(Vec::new()) });
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
            let packet: Arc<dyn UDPPacket> = Arc::new(RecordingPacket { local, data: vec![0x2a; 64] });
            let adapter = new_packet_adapter(packet, metadata);
            assert_eq!(adapter.key_ref(), key, "the established lookup key changed");
            handle_udp_conn(adapter).await;
        }

        assert_eq!(recording.sent.lock().len(), PACKETS, "a datagram did not reach the stored sender");
        nat_table().delete(&key);
        on_suspend();
    }
}

//! The `corehost` engine runs the pinned `easytier_core.wasm` under `wasmtime` and hands back the
//! `Host`/`Instance` surface this file calls.
//!
//! It is embedded by [`murmur_easytier::host`], so the control flow, config rendering, instance-id
//! persistence, DNS synthesis and overlay lookups below stay one-to-one with it.
//!
//! `new_conn` takes the adapter by borrow (`&dyn CProxyAdapter`), so `dial_context` needs no
//! self-`Arc`; `new_packet_conn` retains the adapter for `resolve_udp`, so that path resolves the
//! self-`Arc` problem with `Arc::new_cyclic` + a `self_weak: Weak<Self>` field, the convention this
//! wave settled on for every `adapter::outbound` unit (deviation recorded in the wave report).

use std::future::Future;
use std::io::Write;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path as StdPath;
use std::sync::{Arc, LazyLock, Weak};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use murmur_component::dialer::dialer::new_dialer;
use murmur_component::resolver::resolver::{lookup_ipv4_with_resolver, proxy_server_host_resolver};
use murmur_component_easytier::overlay::{
    ipv4_from_uint32, is_magic_dns, lookup_overlay_host, lookup_overlay_ptr, normalize_zone, parse_node_ipv4,
    parse_ptr_ipv4, Node,
};
use murmur_component_easytier::platform;
use murmur_component_easytier::toml;
use murmur_constant::adapters::AdapterType;
use murmur_constant::adapters::{
    Conn as CConn, PacketConn as CPacketConn, ProxyAdapter as CProxyAdapter, ProxyInfo, DEFAULT_TCP_TIMEOUT,
};
use murmur_constant::metadata::Metadata;
use murmur_constant::path::PATH;
use murmur_dns::easytier::register_easy_tier_dns_client;
use murmur_dns::resolver::DnsClient;
use murmur_easytier::host::{self, State};
use murmur_log::{debugln, infoln, warnln};

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};

const EASY_TIER_DEFAULT_STATE_DIR: &str = "easytier";
const EASY_TIER_INSTANCE_ID_FILE: &str = "instance_id";
const EASY_TIER_DNS_TTL: u32 = 60;
const EASY_TIER_MIN_BACKOFF: Duration = Duration::from_secs(1);
const EASY_TIER_MAX_BACKOFF: Duration = Duration::from_secs(30);

fn err_easytier_closed() -> anyhow::Error {
    anyhow!("easytier outbound closed")
}

/// The `ensure_started` wait. `ready` is captured before `running` reads the instance, so a ready
/// signal landing between the two must still wake this waiter instead of stranding it until the
/// next restart.
async fn wait_for_ready(
    ready: &mut tokio::sync::watch::Receiver<u64>,
    ctx: &CancellationToken,
    adapter: &CancellationToken,
    adapter_closed: impl Fn() -> bool,
    mut running: impl FnMut() -> bool,
) -> Result<()> {
    // cancel-safe: it only samples the instance state, and the watch it waits on outlives the call.
    loop {
        if adapter.is_cancelled() || adapter_closed() {
            return Err(err_easytier_closed());
        }
        if running() {
            return Ok(());
        }
        tokio::select! {
            () = ctx.cancelled() => return Err(anyhow!("context canceled")),
            () = adapter.cancelled() => return Err(err_easytier_closed()),
            changed = ready.changed() => changed.map_err(|_| err_easytier_closed())?,
        }
    }
}

/// The single deadline `shutdown` sets: one timeout covers both guest closes, so a wedged
/// instance close leaves the host close only the remainder of `DEFAULT_TCP_TIMEOUT`.
async fn close_bounded(close: impl Future<Output = Result<()>>, deadline: tokio::time::Instant) -> Result<()> {
    // NOT cancel-safe: a drop abandons the guest close it is timing, leaving that close unfinished.
    match tokio::time::timeout_at(deadline, close).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!("easytier: close exceeded the {DEFAULT_TCP_TIMEOUT:?} shutdown deadline")),
    }
}

/// Cranelift compilation of the embedded 6.85 MiB core is seconds of CPU, so it runs on the
/// blocking pool instead of parking a runtime worker, and the one-permit gate keeps concurrent
/// outbounds from paying for the same module at once.
async fn new_host(services: platform::Services) -> Result<Arc<host::Host>> {
    static COMPILE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::const_new(1)));
    let _permit = COMPILE.clone().acquire_owned().await.map_err(|_| anyhow!("the compile gate is never closed"))?;
    let options = host::Options { platform: services };
    tokio::task::spawn_blocking(move || host::Host::new(options)).await?.map(Arc::new)
}

/// The dialer type check when binding TCP listeners: the basic option yields that concrete type
/// only when neither an API dialer nor a dialer proxy applies, and the check is what lets EasyTier
/// bind its TCP listeners instead of failing every external purpose.
fn is_direct_dialer(basic: &BasicOption) -> bool {
    basic.dialer_for_api.is_none() && basic.dialer_proxy.is_empty()
}

struct StartState {
    closed: bool,
}

#[derive(Default)]
struct RuntimeState {
    host: Option<Arc<host::Host>>,
    instance: Option<Arc<host::Instance>>,
    instance_id: String,
}

pub struct EasyTier {
    self_weak: Weak<Self>,
    base: Base,
    option: EasyTierOption,
    config_toml: String,
    state_dir: String,
    zone: String,
    ctx: CancellationToken,
    loop_once: std::sync::Once,
    start: Mutex<StartState>,
    ready: tokio::sync::watch::Sender<u64>,
    state: Mutex<RuntimeState>,
    unregister: Mutex<Option<Box<dyn FnOnce() + Send + Sync>>>,
}

impl std::fmt::Debug for EasyTier {
    /// Redacts the option's key material so a stray `{:?}` cannot log it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EasyTier").field("name", &self.option.name).finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct EasyTierOption {
    #[serde(flatten)]
    pub basic: BasicOption,
    #[serde(rename = "name", default)]
    pub name: String,
    #[serde(rename = "network-name", default)]
    pub network_name: String,
    #[serde(rename = "network-secret", default)]
    pub network_secret: String,
    #[serde(rename = "hostname", default)]
    pub hostname: String,
    #[serde(rename = "ipv4", default)]
    pub ipv4: String,
    #[serde(rename = "dhcp", default)]
    pub dhcp: bool,
    #[serde(rename = "peers", default)]
    pub peers: Vec<String>,
    #[serde(rename = "listeners", default)]
    pub listeners: Vec<String>,
    #[serde(rename = "no-listener", default)]
    pub no_listener: Option<bool>,
    #[serde(rename = "mapped-listeners", default)]
    pub mapped_listeners: Vec<String>,
    #[serde(rename = "exit-nodes", default)]
    pub exit_nodes: Vec<String>,
    #[serde(rename = "proxy-networks", default)]
    pub proxy_networks: Vec<String>,
    #[serde(rename = "instance-name", default)]
    pub instance_name: String,
    #[serde(rename = "state-dir", default)]
    pub state_dir: String,
    #[serde(rename = "udp", default)]
    pub udp: bool,
    #[serde(rename = "accept-dns", default)]
    pub accept_dns: Option<bool>,
    #[serde(rename = "enable-exit-node", default)]
    pub enable_exit_node: Option<bool>,
    #[serde(rename = "enable-encryption", default)]
    pub enable_encryption: Option<bool>,
    #[serde(rename = "encryption-algorithm", default)]
    pub encryption_algorithm: String,
    #[serde(rename = "private-mode", default)]
    pub private_mode: Option<bool>,
    #[serde(rename = "latency-first", default)]
    pub latency_first: Option<bool>,
    #[serde(rename = "disable-p2p", default)]
    pub disable_p2p: Option<bool>,
    #[serde(rename = "enable-kcp-proxy", default)]
    pub enable_kcp_proxy: Option<bool>,
    #[serde(rename = "disable-kcp-input", default)]
    pub disable_kcp_input: Option<bool>,
    #[serde(rename = "enable-quic-proxy", default)]
    pub enable_quic_proxy: Option<bool>,
    #[serde(rename = "disable-quic-input", default)]
    pub disable_quic_input: Option<bool>,
    #[serde(rename = "mtu", default)]
    pub mtu: i32,
    #[serde(rename = "tld-dns-zone", default)]
    pub tld_dns_zone: String,
    #[serde(rename = "secure-mode", default)]
    pub secure_mode: Option<bool>,
    #[serde(rename = "local-private-key", default)]
    pub local_private_key: String,
    #[serde(rename = "local-public-key", default)]
    pub local_public_key: String,
}

impl std::fmt::Debug for EasyTierOption {
    /// Redacts the network secret and the local private key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EasyTierOption")
            .field("name", &self.name)
            .field("network_name", &self.network_name)
            .field("network_secret", &"<redacted>")
            .field("local_private_key", &"<redacted>")
            .field("local_public_key", &self.local_public_key)
            .finish_non_exhaustive()
    }
}

impl EasyTierOption {
    fn structured_config(&self) -> toml::Config {
        let instance_name = if self.instance_name.is_empty() { self.name.clone() } else { self.instance_name.clone() };
        toml::Config {
            network_name: self.network_name.clone(),
            network_secret: self.network_secret.clone(),
            hostname: self.hostname.clone(),
            ipv4: self.ipv4.clone(),
            dhcp: self.dhcp,
            peers: self.peers.clone(),
            listeners: self.listeners.clone(),
            no_listener: self.no_listener,
            mapped_listeners: self.mapped_listeners.clone(),
            exit_nodes: self.exit_nodes.clone(),
            proxy_networks: self.proxy_networks.clone(),
            instance_name,
            accept_dns: self.accept_dns,
            enable_exit_node: self.enable_exit_node,
            enable_encryption: self.enable_encryption,
            encryption_algorithm: self.encryption_algorithm.clone(),
            private_mode: self.private_mode,
            latency_first: self.latency_first,
            disable_p2p: self.disable_p2p,
            enable_kcp_proxy: self.enable_kcp_proxy,
            disable_kcp_input: self.disable_kcp_input,
            enable_quic_proxy: self.enable_quic_proxy,
            disable_quic_input: self.disable_quic_input,
            mtu: self.mtu,
            tld_dns_zone: self.tld_dns_zone.clone(),
            secure_mode: self.secure_mode,
            local_private_key: self.local_private_key.clone(),
            local_public_key: self.local_public_key.clone(),
        }
    }
}

impl EasyTier {
    pub fn new(option: EasyTierOption) -> Result<Arc<Self>> {
        let config_toml = option.structured_config().render_toml()?;
        let config_toml = toml::apply_required_flags(&config_toml);

        let state_dir = if option.state_dir.is_empty() {
            StdPath::new(EASY_TIER_DEFAULT_STATE_DIR).join(&option.name).to_string_lossy().into_owned()
        } else {
            option.state_dir.clone()
        };
        let state_dir = PATH.resolve(&state_dir);
        if !PATH.is_safe_path(&state_dir) {
            return Err(PATH.err_not_safe_path(&state_dir).into());
        }

        let addr = if option.network_name.is_empty() { "easytier".to_owned() } else { option.network_name.clone() };
        let ctx = CancellationToken::new();
        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr,
            type_: AdapterType::EASY_TIER,
            provider_name: option.basic.provider_name.clone(),
            udp: option.udp,
            interface: option.basic.interface.clone(),
            routing_mark: option.basic.routing_mark,
            prefer: option.basic.ip_version,
            xudp: false,
            tfo: false,
            mptcp: false,
        });
        base.dialer = Some(option.basic.new_dialer(base.dial_options()));
        let zone = normalize_zone(&option.tld_dns_zone);

        let outbound = Arc::new_cyclic(|self_weak| Self {
            self_weak: Weak::clone(self_weak),
            base,
            zone,
            config_toml,
            state_dir,
            ctx,
            loop_once: std::sync::Once::new(),
            start: Mutex::new(StartState { closed: false }),
            ready: tokio::sync::watch::Sender::new(0),
            state: Mutex::new(RuntimeState::default()),
            unregister: Mutex::new(None),
            option,
        });
        let unregister = register_easy_tier_dns_client(
            &outbound.option.name,
            Arc::new(EasyTierDnsTransport { easytier: Arc::clone(&outbound) }),
        );
        *outbound.unregister.lock() = Some(Box::new(unregister));
        Ok(outbound)
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("EasyTier adapter dropped while in use"))
    }

    async fn ensure_started(&self, ctx: &CancellationToken) -> Result<()> {
        self.loop_once.call_once(|| {
            if let Ok(easytier) = self.self_arc() {
                tokio::spawn(async move { easytier.run_loop().await });
            }
        });
        let mut ready = self.ready.subscribe();
        wait_for_ready(
            &mut ready,
            ctx,
            &self.ctx,
            || self.start.lock().closed,
            || self.state.lock().instance.as_ref().is_some_and(|instance| instance.state() == State::Running),
        )
        .await
    }

    /// Bumps the ready generation; `Close` releases waiters the same way.
    fn signal_ready(&self) {
        self.ready.send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    async fn run_loop(&self) {
        // NOT cancel-safe: a drop between `init` and `shutdown` leaves the instance running with
        // nothing supervising it.
        let mut backoff = EASY_TIER_MIN_BACKOFF;
        loop {
            if self.ctx.is_cancelled() {
                return;
            }
            if self.start.lock().closed {
                return;
            }
            if let Err(err) = self.init().await {
                warnln!("[EasyTier]({}) start failed: {}; retry in {:?}", self.name(), err, backoff);
                let _ = self.shutdown().await;
                tokio::select! {
                    () = self.ctx.cancelled() => return,
                    () = sleep(backoff) => {}
                }
                backoff = std::cmp::min(backoff * 2, EASY_TIER_MAX_BACKOFF);
                continue;
            }
            backoff = EASY_TIER_MIN_BACKOFF;
            self.signal_ready();
            let reason = self.serve().await;
            let _ = self.shutdown().await;
            if self.ctx.is_cancelled() {
                return;
            }
            if self.start.lock().closed {
                return;
            }
            let reason = if reason.is_empty() { "instance stopped".to_owned() } else { reason };
            warnln!("[EasyTier]({}) {}; restarting in {:?}", self.name(), reason, backoff);
            tokio::select! {
                () = self.ctx.cancelled() => return,
                () = sleep(backoff) => {}
            }
            backoff = std::cmp::min(backoff * 2, EASY_TIER_MAX_BACKOFF);
        }
    }

    async fn init(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.state_dir).await.map_err(|e| anyhow!("easytier: create state-dir: {e}"))?;
        let state_dir = self.state_dir.clone();
        let instance_id = tokio::task::spawn_blocking(move || load_instance_id(&state_dir))
            .await
            .map_err(|err| anyhow!("easytier: read instance id: {err}"))?;
        let instance_name = if self.option.instance_name.is_empty() {
            self.option.name.clone()
        } else {
            self.option.instance_name.clone()
        };

        let dialer = self.base.dialer.clone().ok_or_else(|| anyhow!("easytier: dialer is not configured"))?;
        let services = if is_direct_dialer(&self.option.basic) {
            platform::services_with_direct_dialer(dialer, new_dialer(self.base.dial_options()).opt)
        } else {
            platform::services(dialer)
        };
        let host = new_host(services).await?;
        self.state.lock().host = Some(Arc::clone(&host));

        let instance = host.create_instance_toml(&self.ctx, &instance_name, &instance_id, &self.config_toml).await?;
        let instance = Arc::new(instance);
        let id = instance.id().to_owned();
        {
            let mut state = self.state.lock();
            state.instance = Some(Arc::clone(&instance));
            state.instance_id.clone_from(&id);
        }
        let state_dir = self.state_dir.clone();
        let id_to_write = id.clone();
        tokio::task::spawn_blocking(move || write_instance_id(&state_dir, &id_to_write))
            .await
            .map_err(|err| anyhow!("easytier: write instance id: {err}"))??;
        instance.start(&self.ctx).await?;
        infoln!("[EasyTier]({}) instance {} running", self.name(), id);
        Ok(())
    }

    fn current_instance(&self) -> Result<Arc<host::Instance>> {
        self.state.lock().instance.clone().ok_or_else(|| anyhow!("easytier instance is not ready"))
    }

    async fn serve(&self) -> String {
        // cancel-safe: it only drains the instance's event queue, and the caller shuts the instance
        // down afterwards.
        let instance = self.state.lock().instance.clone();
        let Some(instance) = instance else {
            return "instance is not ready".to_owned();
        };
        let Some(mut events) = instance.events() else {
            return match instance.wait(&self.ctx).await {
                Err(err) if !self.ctx.is_cancelled() => err.to_string(),
                _ => "instance stopped".to_owned(),
            };
        };
        loop {
            tokio::select! {
                () = self.ctx.cancelled() => return String::new(),
                event = events.recv() => {
                    let Some(event) = event else { return "instance stopped".to_owned() };
                    match event.kind.as_str() {
                        "peer_added" | "peer_removed" => infoln!("[EasyTier]({}) {}: {}", self.name(), event.kind, event.message),
                        _ => debugln!("[EasyTier]({}) {}: {}", self.name(), event.kind, event.message),
                    }
                }
            }
        }
    }

    async fn overlay_nodes(&self, ctx: &CancellationToken) -> Result<Vec<Node>> {
        let instance = self.current_instance()?;
        let mut nodes = Vec::new();
        if let Ok(info) = instance.show_node_info(ctx).await {
            let mut node = Node { hostname: info.hostname.clone(), ipv4: None };
            if let Ok(ip) = parse_node_ipv4(&info.ipv4_addr) {
                node.ipv4 = Some(ip);
            }
            if !node.hostname.is_empty() || node.ipv4.is_some() {
                nodes.push(node);
            }
        }
        match instance.list_route(ctx).await {
            Ok(routes) => {
                for route in routes {
                    let Some(addr) = route.ipv4_addr else { continue };
                    nodes.push(Node { hostname: route.hostname, ipv4: Some(ipv4_from_uint32(addr)) });
                }
                Ok(nodes)
            }
            Err(err) => {
                if nodes.is_empty() {
                    Err(err)
                } else {
                    Ok(nodes)
                }
            }
        }
    }

    async fn resolve_ipv4(&self, ctx: &CancellationToken, host: &str) -> Result<IpAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return match murmur_component::resolver::host::unmap_addr(ip) {
                IpAddr::V4(v4) => Ok(IpAddr::V4(v4)),
                IpAddr::V6(_) => Err(anyhow!("easytier: overlay dial supports IPv4 only")),
            };
        }
        let nodes = self.overlay_nodes(ctx).await?;
        if let Some(ip) = lookup_overlay_host(host, &self.zone, &nodes) {
            return Ok(ip);
        }
        if is_magic_dns(host, &self.zone) {
            return Err(anyhow!("easytier: overlay hostname {host:?} was not found"));
        }
        let ips = lookup_ipv4_with_resolver(ctx, host, proxy_server_host_resolver().as_deref()).await?;
        ips.into_iter().next().ok_or_else(|| anyhow!("easytier: resolve {host:?}: no IPv4 address"))
    }

    /// Shuts the instance down, with guest closes bounded by `DEFAULT_TCP_TIMEOUT` so a wedged
    /// guest cannot pin `Close` or the restart loop forever.
    async fn shutdown(&self) -> Result<()> {
        let ctx = CancellationToken::new();
        let deadline = tokio::time::Instant::now() + DEFAULT_TCP_TIMEOUT;
        let (instance, host) = {
            let mut state = self.state.lock();
            (state.instance.take(), state.host.take())
        };
        let mut err = None;
        if let Some(instance) = instance {
            if let Err(e) = close_bounded(instance.close(&ctx), deadline).await {
                err = Some(e);
            }
        }
        if let Some(host) = host {
            if let Err(e) = close_bounded(host.close(&ctx), deadline).await {
                if err.is_none() {
                    err = Some(e);
                }
            }
        }
        err.map_or(Ok(()), Err)
    }
}

#[async_trait]
impl CProxyAdapter for EasyTier {
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
        info.dialer_proxy.clone_from(&self.option.basic.dialer_proxy);
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        self.ensure_started(ctx).await?;
        let host = if !metadata.host.is_empty() {
            metadata.host.clone()
        } else if let Some(ip) = metadata.dst_ip {
            ip.to_string()
        } else {
            String::new()
        };
        let ip = self.resolve_ipv4(ctx, &host).await?;
        let instance = self.current_instance()?;
        let address = format!("{}:{}", ip, metadata.dst_port);
        let conn = instance.dial(ctx, "tcp4", &address).await?;
        Ok(new_conn(conn, self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.ensure_started(ctx).await?;
        self.resolve_udp(ctx, metadata).await?;
        let instance = self.current_instance()?;
        let pc = instance.listen_packet("udp4", ":0").await?;
        Ok(new_packet_conn(Arc::from(pc), self.self_arc()?))
    }

    fn support_uot(&self) -> bool {
        self.base.support_uot()
    }

    fn is_l3_protocol(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn murmur_constant::adapters::Proxy>> {
        self.base.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        self.ctx.cancel();
        let unregister = self.unregister.lock().take();
        if let Some(unregister) = unregister {
            unregister();
        }
        self.start.lock().closed = true;
        self.signal_ready();
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(self.shutdown()))
    }
}

#[async_trait]
impl ProxyAdapter for EasyTier {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        if !metadata.host.is_empty() {
            let ip = self.resolve_ipv4(ctx, &metadata.host).await.map_err(|e| anyhow!("can't resolve ip: {e}"))?;
            metadata.dst_ip = Some(ip);
            return Ok(());
        }
        if let Some(IpAddr::V6(_)) = metadata.dst_ip {
            return Err(anyhow!("easytier: overlay dial supports IPv4 only"));
        }
        Ok(())
    }
}

struct EasyTierDnsTransport {
    easytier: Arc<EasyTier>,
}

#[async_trait]
impl DnsClient for EasyTierDnsTransport {
    async fn exchange_context(&self, ctx: &CancellationToken, msg: &Message) -> Result<Message> {
        let Some(q) = msg.queries.first() else {
            return Err(anyhow!("should have one question at least"));
        };
        self.easytier.ensure_started(ctx).await?;
        let nodes = self.easytier.overlay_nodes(ctx).await?;

        let mut reply = Message::new(msg.metadata.id, MessageType::Response, OpCode::Query);
        reply.queries.clone_from(&msg.queries);
        reply.metadata.authoritative = true;
        reply.metadata.recursion_available = true;
        // The remaining half of the reply setup: a query opcode keeps the request's own flags.
        reply.metadata.recursion_desired = msg.metadata.recursion_desired;
        reply.metadata.checking_disabled = msg.metadata.checking_disabled;

        match q.query_type() {
            RecordType::A => match lookup_overlay_host(&q.name().to_utf8(), &self.easytier.zone, &nodes) {
                Some(IpAddr::V4(ip)) => {
                    reply.answers.push(Record::from_rdata(q.name().clone(), EASY_TIER_DNS_TTL, RData::A(A(ip))));
                }
                _ => reply.metadata.response_code = ResponseCode::NXDomain,
            },
            RecordType::PTR => {
                let ip = parse_ptr_ipv4(&q.name().to_utf8());
                match ip.and_then(|ip| lookup_overlay_ptr(Some(ip), &self.easytier.zone, &nodes)) {
                    Some(name) => {
                        let ptr_name = Name::from_utf8(if name.ends_with('.') { name } else { format!("{name}.") })
                            .unwrap_or_else(|_| q.name().clone());
                        reply.answers.push(Record::from_rdata(
                            q.name().clone(),
                            EASY_TIER_DNS_TTL,
                            RData::PTR(PTR(ptr_name)),
                        ));
                    }
                    None => reply.metadata.response_code = ResponseCode::NXDomain,
                }
            }
            RecordType::AAAA
            | RecordType::ANAME
            | RecordType::ANY
            | RecordType::AXFR
            | RecordType::CAA
            | RecordType::CDS
            | RecordType::CDNSKEY
            | RecordType::CERT
            | RecordType::CNAME
            | RecordType::DNAME
            | RecordType::CSYNC
            | RecordType::DNSKEY
            | RecordType::DS
            | RecordType::HINFO
            | RecordType::HTTPS
            | RecordType::IXFR
            | RecordType::KEY
            | RecordType::MX
            | RecordType::NAPTR
            | RecordType::NS
            | RecordType::NSEC
            | RecordType::NSEC3
            | RecordType::NSEC3PARAM
            | RecordType::NULL
            | RecordType::OPENPGPKEY
            | RecordType::OPT
            | RecordType::RRSIG
            | RecordType::SIG
            | RecordType::SMIMEA
            | RecordType::SOA
            | RecordType::SRV
            | RecordType::SSHFP
            | RecordType::SVCB
            | RecordType::TLSA
            | RecordType::TSIG
            | RecordType::TXT
            | RecordType::Unknown(_)
            | RecordType::ZERO
            | _ => reply.metadata.response_code = ResponseCode::NoError,
        }
        Ok(reply)
    }

    fn address(&self) -> String {
        format!("easytier://{}", self.easytier.name())
    }

    fn reset_connection(&self) {}
}

fn load_instance_id(state_dir: &str) -> String {
    std::fs::read_to_string(StdPath::new(state_dir).join(EASY_TIER_INSTANCE_ID_FILE))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

/// The persisted network identity is kept readable only by its owner (mode 0600).
fn write_instance_id(state_dir: &str, id: &str) -> Result<()> {
    if id.is_empty() {
        return Ok(());
    }
    let path = StdPath::new(state_dir).join(EASY_TIER_INSTANCE_ID_FILE);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&path)?;
    file.write_all(format!("{id}\n").as_bytes())?;
    // `OpenOptions::mode` reaches only files this call creates, so an instance-id file an earlier
    // run left at a wider mode is tightened here.
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[test]
    fn direct_dialer_needs_neither_an_api_dialer_nor_a_proxy() {
        let mut option = EasyTierOption::default();
        assert!(is_direct_dialer(&option.basic));
        option.basic.dialer_proxy = "relay".to_owned();
        assert!(!is_direct_dialer(&option.basic));
    }

    #[tokio::test]
    async fn ready_signal_during_the_state_read_is_not_lost() {
        let (ready_tx, mut ready_rx) = tokio::sync::watch::channel(0u64);
        let ctx = CancellationToken::new();
        let adapter = CancellationToken::new();
        let running = AtomicBool::new(false);
        let first_read = AtomicBool::new(false);

        let wait = wait_for_ready(
            &mut ready_rx,
            &ctx,
            &adapter,
            || false,
            || {
                if first_read.swap(true, Ordering::SeqCst) {
                    return running.load(Ordering::SeqCst);
                }
                running.store(true, Ordering::SeqCst);
                ready_tx.send_modify(|generation| *generation += 1);
                false
            },
        );
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .expect("waiter never woke")
            .expect("waiter must succeed once the instance is running");
    }

    #[tokio::test]
    async fn shutdown_bound_reports_close_outcomes() {
        let deadline = || tokio::time::Instant::now() + DEFAULT_TCP_TIMEOUT;
        close_bounded(async { Ok(()) }, deadline()).await.expect("clean close");
        let failure = close_bounded(async { Err(anyhow!("guest gone")) }, deadline()).await;
        assert_eq!(failure.expect_err("close error").to_string(), "guest gone");
        let wedged = close_bounded(std::future::pending::<Result<()>>(), deadline()).await;
        assert!(wedged.expect_err("wedged close must time out").to_string().contains("shutdown deadline"));
    }

    /// `shutdown` hands both guest closes the one deadline it made, so an instance close that eats
    /// the budget must leave the host close nothing rather than a second full window.
    #[tokio::test]
    async fn shutdown_budget_is_shared_by_both_closes() {
        let window = Duration::from_millis(400);
        let deadline = tokio::time::Instant::now() + window;
        let instance = close_bounded(std::future::pending::<Result<()>>(), deadline).await;
        assert!(instance.is_err(), "a wedged instance close must not outlive the shared budget");

        let started = std::time::Instant::now();
        let host = close_bounded(std::future::pending::<Result<()>>(), deadline).await;
        assert!(host.is_err(), "the host close must not outlive the shared budget");
        let elapsed = started.elapsed();
        assert!(
            elapsed < window / 2,
            "the host close waited {elapsed:?}, so it got a fresh {window:?} budget instead of the spent one"
        );
    }

    #[cfg(unix)]
    #[test]
    fn instance_id_file_is_owner_only() {
        let dir = std::env::temp_dir().join(format!("murmur-easytier-instance-id-{}", std::process::id()));
        let state_dir = dir.to_str().expect("utf-8 temp dir");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(EASY_TIER_INSTANCE_ID_FILE);

        write_instance_id(state_dir, "first").unwrap();
        let mode = || std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(), 0o600);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_instance_id(state_dir, "second").unwrap();
        assert_eq!(mode(), 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

//! Adapter over the `geiserx_tailscale` crate (lib name `tailscale`, `tsnet` feature).
//!
//! The adapter drives `tsnet::Server` for the node lifecycle and `Device` for the client calls.
//! The steps map onto these engine calls:
//!
//! * `tsnet::Server::start` (builds and spawns the `Device`)
//! * `Device::watch_ipn_bus`, `Device::status`, `Device::query_dns`
//! * `Device::set_accept_routes` for the `accept-routes` pref, `Device::set_exit_node` for
//!   `exit-node`
//! * `Device::dial_tcp`, `Device::listen_packet`, `Device::tailscale_ips`
//! * `tsnet::Server::close`
//!
//! Hooks with no engine counterpart: hostinfo registration (the engine reports its own node
//! version; only the app name is reachable, through `Config::client_name`), env-knob overrides
//! (the engine logs through `tracing`), the interface-getter registration (the engine has its own
//! interface monitor), the system dialer/packet listener/lookup hook (the engine dials its own
//! underlay), extra root CAs (the engine's control and DERP TLS uses its own roots), and the
//! logging hooks. Setting `interface`, `routing-mark` or `dialer-proxy` therefore cannot carry the
//! node's control, DERP or underlay traffic: `Tailscale::new` warns when one is configured rather
//! than letting the option silently do nothing. `build_tailscale_masked_prefs` likewise returns
//! only the prefs the engine can apply at start.
//!
//! DEVIATION (`exit-node: auto:*`): the engine's `ExitNodeSelector` is `StableId`/`Ip`/`Name` and
//! its `Config` has no automatic-exit-node field, so an automatic exit-node choice fails closed in
//! `apply_prefs` with the missing pref named. `Device::suggest_exit_node` is a local latency
//! heuristic, not the control-side selection, so it is deliberately not substituted.
//!
//! DEVIATION (`exit-node-allow-lan-access`): the engine has the pref on `Config` but never acts on
//! it — the field is documented as carried only and never advertised to control, nothing reads it,
//! and the engine publishes no live setter — so the value is stored for completeness and
//! `Tailscale::new` warns that it has no effect. The pref is applied at start and again while the
//! node runs.
//!
//! NOTE (the start returns before the node is up): the server start brings the backend up and
//! returns, leaving the node to come up on its own, and the engine's `Server::start` does the same;
//! both watchers therefore start from the backend's initial state, the engine's
//! `DeviceState::Connecting`, and `watch_backend_state` latches `backend_initialized` on the first
//! state past it.
//!
//! DEVIATION (no cancellation): the engine's `Device` calls take no context, so the 30 s timeout
//! around the pref application is realized here with `with_timeout` (a cancel token) plus
//! `with_ctx` (a `select!` against that token).
//!
//! DEVIATION (source-bound dial): the netstack dial is bound to the node's own address of the
//! destination's family; `Device::dial_tcp` chooses the same address internally but also picks the
//! source port itself (a random one, with no collision check), so `dial_context` hands it the
//! address instead of a bound netstack handle.
//!
//! The engine refuses to build a `Device` unless `TS_RS_EXPERIMENT=this_is_unstable_software` is in
//! the process environment (`check_magic_env`, the acknowledgment the crate requires of linked
//! code). `init` and `Tailscale::new` set it.
//!
//! `new_conn` takes the adapter by borrow, so `dial_context` needs no self-`Arc`;
//! `listen_packet_context` retains the adapter via `new_packet_conn`, so `self_weak: Weak<Self>` +
//! `Arc::new_cyclic` is used (this wave's convention). `TailscaleDnsTransport` holds
//! `tailscale: Weak<Tailscale>` rather than `Arc<Tailscale>`: the adapter's `dns_resolver` transitively
//! holds the transport (via `dns::resolver::Resolver::main`), so a strong back-reference would
//! leak a reference cycle.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::future::BoxFuture;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tailscale::tsnet::Server;
use tailscale::{DeviceState, ExitNodeSelector, NotifyWatchOpt, Status};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_component::dialer::dialer::new_dialer;
use murmur_component::dialer::options::{with_net_dialer, with_resolver, NetDialerFunc, Option as DialerOption};
use murmur_component::resolver::resolver::SharedResolver;
use murmur_constant::adapters::AdapterType;
use murmur_constant::adapters::{
    Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_constant::path::PATH;
use murmur_constant::version::PROJECT_NAME;
use murmur_dns::resolver::{DnsClient, Resolver};
use murmur_dns::tailscale::register_tailscale_dns_client;
use murmur_log::warnln;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::util::resolve_ip_with_resolver;

/// The acknowledgment the engine requires in the process environment before it will build a node.
const ENGINE_GATE_VAR: &str = "TS_RS_EXPERIMENT";
const ENGINE_GATE_VALUE: &str = "this_is_unstable_software";

pub struct Tailscale {
    base: Base,
    /// The engine facade, taken out by `close` so the shutdown can have it by value: the engine's
    /// `Server::close` consumes the server.
    server: Mutex<Option<Arc<Server>>>,
    dns_resolver: SharedResolver,
    option: TailscaleOption,
    ctx: CancellationToken,

    start_result: tokio::sync::OnceCell<Result<(), Arc<anyhow::Error>>>,

    backend_init_once: Once,
    backend_init_tx: tokio::sync::watch::Sender<Option<Result<(), Arc<anyhow::Error>>>>,

    server_started: AtomicBool,

    unregister_dns_resolver: Option<Box<dyn Fn() + Send + Sync>>,

    self_weak: Weak<Self>,
}

impl core::fmt::Debug for Tailscale {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `base` and the engine facade have no `Debug`; the auth key stays in `option` unprinted.
        f.debug_struct("Tailscale")
            .field("name", &self.base.name)
            .field("addr", &self.base.addr)
            .field("started", &self.server_started.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TailscaleOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "hostname", default)]
    pub hostname: String,
    #[serde(rename = "auth-key", default)]
    pub auth_key: String,
    #[serde(rename = "control-url", default)]
    pub control_url: String,
    #[serde(rename = "state-dir", default)]
    pub state_dir: String,
    #[serde(rename = "ephemeral", default)]
    pub ephemeral: bool,
    #[serde(rename = "udp", default)]
    pub udp: bool,

    #[serde(rename = "accept-routes", default)]
    pub accept_routes: Option<bool>,
    #[serde(rename = "exit-node", default)]
    pub exit_node: String,
    #[serde(rename = "exit-node-allow-lan-access", default)]
    pub exit_node_allow_lan_access: Option<bool>,
}

impl core::fmt::Debug for TailscaleOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `basic_option` has no `Debug`; the auth key is never printed.
        f.debug_struct("TailscaleOption")
            .field("name", &self.name)
            .field("hostname", &self.hostname)
            .field("auth_key", &"<redacted>")
            .field("control_url", &self.control_url)
            .field("state_dir", &self.state_dir)
            .field("ephemeral", &self.ephemeral)
            .field("udp", &self.udp)
            .field("accept_routes", &self.accept_routes)
            .field("exit_node", &self.exit_node)
            .field("exit_node_allow_lan_access", &self.exit_node_allow_lan_access)
            .finish_non_exhaustive()
    }
}

pub fn init() {
    acknowledge_engine();
}

/// Satisfy the engine's `TS_RS_EXPERIMENT` gate. The crate's own tests and examples set the same
/// variable from the outside; here the linked code does it, as `SECURITY.md` requires of an embedder.
fn acknowledge_engine() {
    if std::env::var(ENGINE_GATE_VAR).as_deref() != Ok(ENGINE_GATE_VALUE) {
        std::env::set_var(ENGINE_GATE_VAR, ENGINE_GATE_VALUE);
    }
}

impl Tailscale {
    pub fn new(mut option: TailscaleOption) -> Result<Arc<Self>> {
        acknowledge_engine();

        if option.state_dir.is_empty() {
            "tailscale".clone_into(&mut option.state_dir);
        }
        option.state_dir = PATH.resolve(&option.state_dir);
        if !PATH.is_safe_path(&option.state_dir) {
            return Err(PATH.err_not_safe_path(&option.state_dir).into());
        }

        let addr = if option.control_url.is_empty() { "tailscale".to_owned() } else { option.control_url.clone() };
        let ctx = CancellationToken::new();

        let mut server = Server::new();
        server.hostname = non_empty(&option.hostname);
        server.auth_key = non_empty(&option.auth_key);
        server.control_url = non_empty(&option.control_url);
        server.ephemeral = option.ephemeral;
        server.dir = Some(PathBuf::from(&option.state_dir));
        let allow_lan_access = option.exit_node_allow_lan_access;
        let client_name = PROJECT_NAME.to_owned();
        server.configure(move |config| {
            // The client build is reported through the node version; the engine fills that
            // from its own crate version and takes only the application name from here.
            config.client_name = Some(client_name.clone());
            if let Some(allow) = allow_lan_access {
                config.exit_node_allow_lan_access = allow;
            }
        });
        warn_about_underlay_options(&option);
        if option.exit_node_allow_lan_access.is_some() {
            warnln!(
                "[Tailscale]({}) the engine stores exit-node-allow-lan-access but never applies it, so the pref has no effect",
                option.name
            );
        }

        let outbound = Arc::new_cyclic(|weak: &Weak<Self>| {
            let mut base = Base::new(BaseOption {
                name: option.name.clone(),
                addr: addr.clone(),
                type_: AdapterType::TAILSCALE,
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

            let dns_transport = Arc::new(TailscaleDnsTransport { tailscale: Weak::clone(weak) });
            let dns_client = Arc::clone(&dns_transport);
            let dns_client: Arc<dyn DnsClient> = dns_client;
            let dns_resolver: SharedResolver = Arc::new(Resolver::from_client(dns_client));
            let unregister_dns_resolver: Option<Box<dyn Fn() + Send + Sync>> =
                Some(Box::new(register_tailscale_dns_client(&option.name, dns_transport)));

            let (backend_init_tx, _rx) = tokio::sync::watch::channel(None);

            Self {
                base,
                server: Mutex::new(Some(Arc::new(server))),
                dns_resolver,
                option: option.clone(),
                ctx,
                start_result: tokio::sync::OnceCell::new(),
                backend_init_once: Once::new(),
                backend_init_tx,
                server_started: AtomicBool::new(false),
                unregister_dns_resolver,
                self_weak: Weak::clone(weak),
            }
        });
        Ok(outbound)
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("Tailscale adapter dropped while still in use"))
    }

    /// The engine facade, or an error once `close` has taken it.
    fn engine_server(&self) -> Result<Arc<Server>> {
        self.server.lock().clone().ok_or_else(|| anyhow!("tailscale: the outbound is closed"))
    }

    pub(crate) async fn start(&self) -> Result<()> {
        let result = self
            .start_result
            .get_or_init(|| async {
                let server = match self.engine_server() {
                    Ok(server) => server,
                    Err(err) => {
                        let err = Arc::new(err);
                        self.set_backend_initialized(Some(Arc::clone(&err)));
                        return Err(err);
                    }
                };
                if let Err(err) = server.start().await {
                    let err = Arc::new(engine_error(err));
                    self.set_backend_initialized(Some(Arc::clone(&err)));
                    return Err(err);
                }
                self.server_started.store(true, Ordering::SeqCst);
                let ctx = with_timeout(&self.ctx, Duration::from_secs(30));
                if let Err(err) = self.apply_prefs(&ctx).await {
                    let err = Arc::new(err);
                    self.set_backend_initialized(Some(Arc::clone(&err)));
                    return Err(err);
                }
                if let Ok(this) = self.self_arc() {
                    tokio::spawn(this.watch_backend_state());
                }
                Ok(())
            })
            .await;
        result.clone().map_err(|err| anyhow!("{err}"))
    }

    pub(crate) async fn ensure_started(&self, ctx: &CancellationToken) -> Result<()> {
        self.start().await?;
        self.wait_backend_initialized(ctx).await
    }

    pub(crate) async fn watch_backend_state(self: Arc<Self>) {
        let server = match self.engine_server() {
            Ok(server) => server,
            Err(err) => {
                self.set_backend_initialized(Some(Arc::new(err)));
                return;
            }
        };
        let device = match server.device().await {
            Ok(device) => device,
            Err(err) => {
                self.set_backend_initialized(Some(Arc::new(engine_error(err))));
                return;
            }
        };
        let mut watcher = match device.watch_ipn_bus(NotifyWatchOpt::INITIAL_STATE).await {
            Ok(watcher) => watcher,
            Err(err) => {
                self.set_backend_initialized(Some(Arc::new(engine_error(err))));
                return;
            }
        };

        let mut backend_initialized = false;
        let exit_node_needs_status = tailscale_exit_node_needs_status(&self.option);
        // dropping the watcher ends the bus subscription here.
        loop {
            let Some(notify) = watcher.next().await else {
                self.set_backend_initialized(Some(Arc::new(anyhow!("tailscale: the engine's notification bus ended"))));
                return;
            };
            let Some(state) = notify.state else { continue };

            if !matches!(state, DeviceState::Connecting) && !backend_initialized {
                self.set_backend_initialized(None);
                backend_initialized = true;
                if !exit_node_needs_status {
                    return;
                }
            }
            if exit_node_needs_status && matches!(state, DeviceState::Running) {
                if let Err(err) = self.apply_exit_node_prefs(&self.ctx).await {
                    warnln!("[Tailscale]({}) set exit node failed: {err}", self.name());
                }
                return;
            }
        }
    }

    /// Closing the channel is sticky for waiters that arrive afterwards; `watch::Sender::send` is
    /// not, since it stores nothing while the adapter holds no receiver, which is its steady state
    /// between calls.
    pub(crate) fn set_backend_initialized(&self, err: Option<Arc<anyhow::Error>>) {
        self.backend_init_once.call_once(|| {
            let _ = self.backend_init_tx.send_replace(Some(match err {
                Some(err) => Err(err),
                None => Ok(()),
            }));
        });
    }

    pub(crate) async fn wait_backend_initialized(&self, ctx: &CancellationToken) -> Result<()> {
        // cancel-safe: it only watches the backend-init channel, which the next call re-reads.
        let mut rx = self.backend_init_tx.subscribe();
        loop {
            let initialized = rx.borrow_and_update().clone();
            if let Some(result) = initialized {
                return result.map_err(|err| anyhow!("{err}"));
            }
            tokio::select! {
                changed = rx.changed() => {
                    changed.map_err(|_| anyhow!("tailscale: backend init channel closed"))?;
                }
                () = ctx.cancelled() => return Err(CtxDoneError.into()),
                () = self.ctx.cancelled() => return Err(CtxDoneError.into()),
            }
        }
    }

    /// The prefs, applied through the engine's per-pref setters.
    pub(crate) async fn apply_prefs(&self, ctx: &CancellationToken) -> Result<()> {
        let Some(prefs) = build_tailscale_masked_prefs(&self.option) else { return Ok(()) };
        if let Some(auto_exit_node) = &prefs.auto_exit_node {
            return Err(anyhow!(
                "tailscale: the engine has no AutoExitNode pref, so exit-node \"auto:{auto_exit_node}\" cannot be selected"
            ));
        }
        let Some(route_all) = prefs.route_all else { return Ok(()) };
        let server = self.engine_server()?;
        let device = server.device().await.map_err(engine_error)?;
        with_ctx(ctx, device.set_accept_routes(route_all)).await
    }

    pub(crate) async fn apply_exit_node_prefs(&self, ctx: &CancellationToken) -> Result<()> {
        let ctx = with_timeout(ctx, Duration::from_secs(30));

        let server = self.engine_server()?;
        let device = server.device().await.map_err(engine_error)?;
        let status = with_ctx(&ctx, device.status()).await?;
        let ipn_status = ipn_status_from_engine(&status, backend_state_name(&device.device_state()));
        let exit_node_ip = ipn::exit_node_ip_of_arg(&self.option.exit_node, &ipn_status)?;
        with_ctx(&ctx, device.set_exit_node(Some(ExitNodeSelector::Ip(exit_node_ip)))).await
    }

    async fn tailscale_ips(&self) -> Result<(Ipv4Addr, Option<Ipv6Addr>)> {
        let server = self.engine_server()?;
        // The engine's `Device` hangs off the server's once-cell, so calls go through a local
        // handle to it rather than a borrow held across methods.
        let device = server.device().await.map_err(engine_error)?;
        device.tailscale_ips().await.map_err(engine_error)
    }

    async fn resolve_udp_impl(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        if !metadata.host.is_empty() {
            let ip = resolve_ip_with_resolver(ctx, &metadata.host, self.base.prefer, Some(self.dns_resolver.as_ref()))
                .await
                .map_err(|err| anyhow!("can't resolve ip: {err}"))?;
            metadata.dst_ip = Some(ip);
        }
        Ok(())
    }
}

/// The prefs this adapter applies at start. The third branch (`exit-node-allow-lan-access`) is
/// applied when the engine server is built, since the engine exposes that pref only on `Config`
/// (see the module doc). There is no error return.
pub(crate) fn build_tailscale_masked_prefs(option: &TailscaleOption) -> Option<ipn::MaskedPrefs> {
    let mut prefs = ipn::MaskedPrefs::default();
    let mut changed = if let Some(accept_routes) = option.accept_routes {
        prefs.route_all = Some(accept_routes);
        true
    } else {
        false
    };
    if !option.exit_node.is_empty() {
        let (auto_exit_node, ok) = ipn::parse_auto_exit_node_string(&option.exit_node);
        if ok {
            prefs.auto_exit_node = Some(auto_exit_node);
            changed = true;
        }
    }
    if !changed {
        return None;
    }
    Some(prefs)
}

pub(crate) fn tailscale_exit_node_needs_status(option: &TailscaleOption) -> bool {
    if option.exit_node.is_empty() {
        return false;
    }
    let (_, ok) = ipn::parse_auto_exit_node_string(&option.exit_node);
    !ok
}

/// The server fields are plain strings where the empty value means "engine default"; the engine
/// spells the same thing as `None`.
fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

/// The engine dials its own underlay, so these server options (which reached it through the system
/// dialer and packet listener) have nowhere to go.
fn warn_about_underlay_options(option: &TailscaleOption) {
    let mut ignored = Vec::new();
    if !option.basic_option.dialer_proxy.is_empty() {
        ignored.push("dialer-proxy");
    }
    if !option.basic_option.interface.is_empty() {
        ignored.push("interface-name");
    }
    if option.basic_option.routing_mark != 0 {
        ignored.push("routing-mark");
    }
    if !ignored.is_empty() {
        warnln!(
            "[Tailscale]({}) the engine has no SystemDialer/SystemPacketListener hook, so {} cannot carry the node's control, DERP or underlay traffic",
            option.name,
            ignored.join(", ")
        );
    }
}

/// The engine's lifecycle state as a string, which [`ipn::exit_node_ip_of_arg`] compares against
/// `"Running"`.
fn backend_state_name(state: &DeviceState) -> &'static str {
    match state {
        DeviceState::Running => "Running",
        DeviceState::NeedsMachineAuth => "NeedsMachineAuth",
        DeviceState::NeedsLogin(_) => "NeedsLogin",
        DeviceState::Expired | DeviceState::Failed(_) => "Stopped",
        // `DeviceState` is non-exhaustive: `Connecting` and `Reauthenticating` report "Starting"
        // too, as does any state the engine adds later.
        DeviceState::Connecting | DeviceState::Reauthenticating | _ => "Starting",
    }
}

/// Projects the engine's status onto the `ipn` status type, the input
/// [`ipn::exit_node_ip_of_arg`] consumes.
fn ipn_status_from_engine(status: &Status, backend_state: &str) -> ipn::ipnstate::Status {
    let suffix = status.magic_dns_suffix.as_deref();
    ipn::ipnstate::Status {
        peer: status
            .peers
            .iter()
            .map(|node| ipn::ipnstate::PeerStatus {
                dns_name: dns_name_of(&node.display_name, suffix),
                tailscale_ips: node.tailscale_ips.clone(),
                exit_node_option: node.is_exit_node,
            })
            .collect(),
        tailscale_ips: status.self_node.as_ref().map(|node| node.tailscale_ips.clone()).unwrap_or_default(),
        magic_dns_suffix: suffix.unwrap_or_default().to_owned(),
        backend_state: backend_state.to_owned(),
    }
}

/// The peer's fully-qualified MagicDNS name, trailing dot included; the engine's
/// `StatusNode::display_name` drops it.
fn dns_name_of(display_name: &str, suffix: Option<&str>) -> String {
    let name = display_name.as_bytes();
    let is_fqdn = suffix.is_some_and(|suffix| {
        let suffix = suffix.as_bytes();
        let Some(dot) = name.len().checked_sub(suffix.len() + 1) else { return false };
        !suffix.is_empty()
            && name.get(dot + 1..).is_some_and(|rest| rest.eq_ignore_ascii_case(suffix))
            && name.get(dot) == Some(&b'.')
    });
    if is_fqdn {
        format!("{display_name}.")
    } else {
        display_name.to_owned()
    }
}

/// Map an engine error into this adapter's error type. The engine error is returned unchanged;
/// its typed errors carry their own rendering.
fn engine_error(err: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("{err}")
}

fn with_timeout(parent: &CancellationToken, dur: Duration) -> CancellationToken {
    let child = parent.child_token();
    let child_for_task = child.clone();
    tokio::spawn(async move {
        tokio::select! {
            () = tokio::time::sleep(dur) => child_for_task.cancel(),
            () = child_for_task.cancelled() => {}
        }
    });
    child
}

/// The engine's `Device` calls take no context, so the context argument is honored by racing the
/// call against it.
async fn with_ctx<T, E: std::fmt::Display>(
    ctx: &CancellationToken,
    call: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    // cancel-safe: it owns nothing but the wrapped call, which a drop cancels with it.
    tokio::select! {
        result = call => result.map_err(engine_error),
        () = ctx.cancelled() => Err(CtxDoneError.into()),
    }
}

/// Stands in for the deadline-exceeded/canceled check.
#[derive(Debug, thiserror::Error)]
#[error("context canceled or deadline exceeded")]
struct CtxDoneError;

#[async_trait]
impl CProxyAdapter for Tailscale {
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

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        self.ensure_started(ctx).await?;
        let server = self.engine_server()?;

        let mut options = self.dial_options();
        options.push(with_resolver(Some(Arc::clone(&self.dns_resolver))));
        options.push(with_net_dialer(Arc::new(NetDialerFunc::new({
            move |_ctx: CancellationToken,
                  _network: String,
                  address: String|
                  -> BoxFuture<'static, Result<Box<dyn murmur_common_net::io::Stream>>> {
                let server = Arc::clone(&server);
                Box::pin(async move {
                    let device = server.device().await.map_err(engine_error)?;
                    let stream = device.dial_tcp(&address).await.map_err(engine_error)?;
                    let stream: Box<dyn murmur_common_net::io::Stream> = Box::new(NetstackStream(stream));
                    Ok(stream)
                })
            }
        }))));

        // A null-conn guard here has no Rust equivalent: `Box<dyn Conn>` can never be a null
        // pointer, so that branch is dropped.
        let conn = new_dialer(options).dial_context(ctx, "tcp", &metadata.remote_address()).await?;
        Ok(new_conn(conn, self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.ensure_started(ctx).await?;
        self.resolve_udp_impl(ctx, metadata).await?;
        let (v4, v6) = self.tailscale_ips().await?;
        let src = if metadata.dst_ip.is_some_and(|ip| ip.is_ipv6()) {
            IpAddr::V6(v6.ok_or_else(|| anyhow!("tailscale: this node has no IPv6 tailnet address"))?)
        } else {
            IpAddr::V4(v4)
        };

        let server = self.engine_server()?;
        let device = server.device().await.map_err(engine_error)?;
        let pc = device
            .listen_packet("udp", &murmur_component::dialer::bind::join_host_port(&src.to_string(), "0"))
            .await
            .map_err(engine_error)?;
        // Same null-check omission as `dial_context` above.
        let pc: Arc<dyn murmur_common_net::io::Datagram> = Arc::new(NetstackUdpSocket(pc));
        Ok(new_packet_conn(pc, self.self_arc()?))
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

    fn close(&self) -> Result<()> {
        self.ctx.cancel();
        if let Some(unregister) = &self.unregister_dns_resolver {
            unregister();
        }
        // The start-once mechanism unconditionally poisons the once-cell here if `start()` never ran.
        // `tokio::sync::OnceCell::set` gives the same "first writer wins" outcome without the
        // blocking-on-a-concurrent-in-flight-start guarantee a `Once` has; deviation recorded in
        // the wave report.
        let _ = self.start_result.set(Err(Arc::new(anyhow!("tailscale outbound closed"))));
        let server = self.server.lock().take();
        if !self.server_started.load(Ordering::SeqCst) {
            return Ok(());
        }
        // The engine's `Server::close` consumes the server and is async, while this method is not;
        // The server close blocks, so the shutdown is handed to a task instead.
        if let Some(server) = server {
            tokio::spawn(async move {
                if let Some(server) = Arc::into_inner(server) {
                    if !server.close(None).await {
                        warnln!("[Tailscale] close: the engine could not reclaim the device for a graceful shutdown");
                    }
                } else {
                    warnln!(
                        "[Tailscale] close: another task still holds the engine server, so the device shuts down only once that task releases it"
                    );
                }
            });
        }
        Ok(())
    }
}

#[async_trait]
impl ProxyAdapter for Tailscale {
    fn dial_options(&self) -> Vec<DialerOption> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.resolve_udp_impl(ctx, metadata).await
    }
}

/// Holds `Weak<Tailscale>` rather than `Arc<Tailscale>`: see the
/// module doc comment.
struct TailscaleDnsTransport {
    tailscale: Weak<Tailscale>,
}

#[async_trait]
impl DnsClient for TailscaleDnsTransport {
    async fn exchange_context(&self, ctx: &CancellationToken, msg: &Message) -> Result<Message> {
        let tailscale = self.tailscale.upgrade().ok_or_else(|| anyhow!("tailscale: adapter dropped"))?;
        tailscale.ensure_started(ctx).await?;

        let Some(q) = msg.queries.first() else {
            return Err(anyhow!("should have one question at least"));
        };
        let record_type = q.query_type();
        if let RecordType::Unknown(code) = record_type {
            return Err(anyhow!("unsupported query type: {code}"));
        }
        let qtype = u16::from(record_type);

        let server = tailscale.engine_server()?;
        let device = server.device().await.map_err(engine_error)?;
        // The DNS query's resolver list is ignored; the engine reports it as
        // `DnsQueryResult::resolvers_consulted`.
        let result = with_ctx(ctx, device.query_dns(&q.name().to_utf8(), qtype)).await?;
        let mut response_msg = Message::from_vec(&result.response)?;
        response_msg.metadata.id = msg.metadata.id;
        Ok(response_msg)
    }

    /// The raw pointer is always valid; the `Weak` upgrade can theoretically fail if the outer
    /// adapter was already dropped, in which case an empty name is reported instead of erroring
    /// (the trait method has no `Result` return).
    fn address(&self) -> String {
        let name = self.tailscale.upgrade().map(|t| t.name()).unwrap_or_default();
        format!("tailscale://{name}")
    }

    fn reset_connection(&self) {}
}

/// The engine's netstack TCP stream, seen as this workspace's [`murmur_common_net::io::Stream`].
struct NetstackStream(tailscale::netstack::TcpStream);

impl AsyncRead for NetstackStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for NetstackStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl murmur_common_net::io::Stream for NetstackStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.0.local_addr())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.0.remote_addr())
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.0.shutdown_write();
        Ok(())
    }
}

/// The engine's netstack UDP socket, seen as this workspace's [`murmur_common_net::io::Datagram`].
/// The engine closes the socket on drop, so `Datagram::close` keeps its default no-op.
struct NetstackUdpSocket(tailscale::netstack::UdpSocket);

#[async_trait]
impl murmur_common_net::io::Datagram for NetstackUdpSocket {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (addr, len) = self.0.recv_from(buf).await.map_err(io::Error::other)?;
        Ok((len, addr))
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        // The engine's `send_to` is all-or-nothing.
        self.0.send_to(addr, buf).await.map_err(io::Error::other)?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.0.local_addr())
    }
}

/// The prefs decision and the exit-node resolution run before the result is handed to the engine.
mod ipn {
    use std::net::IpAddr;

    /// The masked prefs this adapter applies: each `Option` carries the meaning of the matching
    /// `…Set` mask bit.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub(crate) struct MaskedPrefs {
        /// The `accept-routes` pref, applied through `Device::set_accept_routes`.
        pub route_all: Option<bool>,
        /// The `exit-node: auto:*` pref, which the engine has no equivalent for.
        pub auto_exit_node: Option<String>,
    }

    const AUTO_EXIT_NODE_PREFIX: &str = "auto:";

    /// The backend state when the backend is up, which the exit-node lookup compares against.
    const BACKEND_STATE_RUNNING: &str = "Running";

    pub(super) type ExitNodeExpression = String;

    pub(super) fn parse_auto_exit_node_string(s: &str) -> (ExitNodeExpression, bool) {
        if let Some(expr) = s.strip_prefix(AUTO_EXIT_NODE_PREFIX) {
            if !expr.is_empty() {
                return (expr.to_owned(), true);
            }
        }
        (String::new(), false)
    }

    /// The exit-node errors: a local-IP rejection, an invalid argument, and a verbatim message
    /// variant.
    #[derive(Debug, PartialEq, Eq, thiserror::Error)]
    pub(super) enum ExitNodeError {
        #[error("invalid argument")]
        InvalidArgument,
        #[error("cannot use {host_or_ip} as an exit node as it is a local IP address to this machine")]
        LocalIp { host_or_ip: String },
        #[error("{0}")]
        Message(String),
    }

    fn peer_with_tailscale_ip(st: &ipnstate::Status, ip: IpAddr) -> Option<&ipnstate::PeerStatus> {
        st.peer.iter().find(|ps| ps.tailscale_ips.contains(&ip))
    }

    fn is_remote_ip(st: &ipnstate::Status, ip: IpAddr) -> bool {
        !st.tailscale_ips.contains(&ip)
    }

    fn has_suffix(name: &str, suffix: &str) -> bool {
        let name = name.strip_suffix('.').unwrap_or(name);
        let suffix = suffix.strip_suffix('.').unwrap_or(suffix);
        let suffix = suffix.strip_prefix('.').unwrap_or(suffix);
        let name_base = name.strip_suffix(suffix).unwrap_or(name);
        name_base.len() < name.len() && name_base.ends_with('.')
    }

    /// Removes `suffix` at a label boundary and always drops the trailing root dot.
    fn trim_suffix<'a>(name: &'a str, suffix: &str) -> &'a str {
        let mut name = name;
        if has_suffix(name, suffix) {
            name = name.strip_suffix('.').unwrap_or(name);
            name = name.strip_suffix(suffix.trim_matches('.')).unwrap_or(name);
        }
        name.strip_suffix('.').unwrap_or(name)
    }

    /// The fold used for MagicDNS names: the whole Unicode simple set is folded, though a
    /// MagicDNS name is LDH (or punycode), for which ASCII folding covers all of it.
    fn equal_fold(a: &str, b: &str) -> bool {
        a.eq_ignore_ascii_case(b)
    }

    /// A zone-qualified literal (`fe80::1%eth0`), which Rust's parser rejects, falls through to
    /// the hostname branch and is rejected there.
    pub(super) fn exit_node_ip_of_arg(s: &str, st: &ipnstate::Status) -> Result<IpAddr, ExitNodeError> {
        if s.is_empty() {
            return Err(ExitNodeError::InvalidArgument);
        }

        if let Ok(ip) = s.parse::<IpAddr>() {
            if !is_remote_ip(st, ip) {
                return Err(ExitNodeError::LocalIp { host_or_ip: s.to_owned() });
            }
            if st.backend_state == BACKEND_STATE_RUNNING {
                let Some(ps) = peer_with_tailscale_ip(st, ip) else {
                    return Err(ExitNodeError::Message(format!("no node found in netmap with IP {ip}")));
                };
                if !ps.exit_node_option {
                    return Err(ExitNodeError::Message(format!("node {ip} is not advertising an exit node")));
                }
            }
            return Ok(ip);
        }

        if st.peer.is_empty() {
            return Err(ExitNodeError::Message(
                "cannot resolve exit node by hostname while Tailscale is starting up; please use its Tailscale IP address instead"
                    .to_owned(),
            ));
        }

        let mut matched = 0usize;
        let mut ip = None;
        for ps in &st.peer {
            let fqdn = &ps.dns_name;
            let base_name = trim_suffix(fqdn, &st.magic_dns_suffix);
            let fqdn_sans_dot = trim_suffix(fqdn, ".");
            if !equal_fold(s, base_name) && !equal_fold(s, fqdn) && !equal_fold(s, fqdn_sans_dot) {
                continue;
            }
            matched += 1;
            let Some(peer_ip) = ps.tailscale_ips.first().copied() else {
                return Err(ExitNodeError::Message(format!("node {s:?} has no Tailscale IP?")));
            };
            if !ps.exit_node_option {
                return Err(ExitNodeError::Message(format!("node {s:?} is not advertising an exit node")));
            }
            ip = Some(peer_ip);
        }

        match matched {
            0 => {
                Err(ExitNodeError::Message(format!("invalid value {s:?} for --exit-node; must be IP or peer hostname")))
            }
            1 => {
                let ip = ip.ok_or(ExitNodeError::InvalidArgument)?;
                if is_remote_ip(st, ip) {
                    Ok(ip)
                } else {
                    Err(ExitNodeError::LocalIp { host_or_ip: s.to_owned() })
                }
            }
            _ => Err(ExitNodeError::Message(format!("ambiguous exit node name {s:?}"))),
        }
    }

    /// Holds only the fields the exit-node lookup reads.
    pub(super) mod ipnstate {
        use std::net::IpAddr;

        #[derive(Debug, Default, Clone, PartialEq, Eq)]
        pub(crate) struct PeerStatus {
            pub dns_name: String,
            pub tailscale_ips: Vec<IpAddr>,
            pub exit_node_option: bool,
        }

        /// The status type the exit-node lookup consumes, projected from the engine's
        /// [`Status`](tailscale::Status) by `ipn_status_from_engine`.
        #[derive(Debug, Default, Clone, PartialEq, Eq)]
        pub(crate) struct Status {
            pub peer: Vec<PeerStatus>,
            pub tailscale_ips: Vec<IpAddr>,
            pub magic_dns_suffix: String,
            pub backend_state: String,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::ipn::ipnstate::{PeerStatus, Status};
    use super::ipn::{exit_node_ip_of_arg, ExitNodeError};
    use super::*;
    use tailscale::{Status as EngineStatus, StatusNode};

    const SUFFIX: &str = ".tail1234.ts.net.";

    fn peer(name: &str, ip: &str, exit_node: bool) -> PeerStatus {
        PeerStatus {
            dns_name: format!("{name}{SUFFIX}"),
            tailscale_ips: vec![ip.parse::<IpAddr>().expect("peer ip")],
            exit_node_option: exit_node,
        }
    }

    fn status(peers: Vec<PeerStatus>) -> Status {
        Status {
            peer: peers,
            tailscale_ips: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))],
            magic_dns_suffix: SUFFIX.to_owned(),
            backend_state: "Running".to_owned(),
        }
    }

    #[test]
    fn exit_node_by_ip_literal_uses_the_literal() {
        let st = status(vec![peer("exit", "100.64.0.9", true)]);
        assert_eq!(exit_node_ip_of_arg("100.64.0.9", &st), Ok("100.64.0.9".parse().unwrap()));
    }

    #[test]
    fn exit_node_by_ip_literal_checks_the_netmap_only_once_running() {
        let mut starting = status(vec![]);
        starting.backend_state = "Starting".to_owned();
        assert_eq!(exit_node_ip_of_arg("100.64.0.9", &starting), Ok("100.64.0.9".parse().unwrap()));

        let running = status(vec![]);
        assert_eq!(
            exit_node_ip_of_arg("100.64.0.9", &running).unwrap_err().to_string(),
            "no node found in netmap with IP 100.64.0.9"
        );
    }

    #[test]
    fn exit_node_rejects_a_peer_that_does_not_advertise_one() {
        let st = status(vec![peer("gw", "100.64.0.9", false)]);
        assert_eq!(
            exit_node_ip_of_arg("gw", &st).unwrap_err().to_string(),
            "node \"gw\" is not advertising an exit node"
        );
    }

    #[test]
    fn exit_node_matches_base_name_fqdn_and_fqdn_without_the_trailing_dot() {
        for arg in ["gw", "gw.tail1234.ts.net.", "gw.tail1234.ts.net", "GW"] {
            let st = status(vec![peer("gw", "100.64.0.9", true)]);
            assert_eq!(exit_node_ip_of_arg(arg, &st), Ok("100.64.0.9".parse().unwrap()), "{arg}");
        }
    }

    #[test]
    fn exit_node_refuses_this_node_s_own_address() {
        let mut st = status(vec![peer("self", "100.64.0.2", true)]);
        let by_name = exit_node_ip_of_arg("self", &st).unwrap_err();
        assert!(matches!(&by_name, ExitNodeError::LocalIp { host_or_ip } if host_or_ip == "self"), "{by_name:?}");

        st.tailscale_ips.push("100.64.0.9".parse().unwrap());
        let by_ip = exit_node_ip_of_arg("100.64.0.9", &st).unwrap_err();
        assert!(matches!(&by_ip, ExitNodeError::LocalIp { host_or_ip } if host_or_ip == "100.64.0.9"), "{by_ip:?}");
    }

    #[test]
    fn exit_node_name_must_be_unambiguous() {
        let st = status(vec![peer("gw", "100.64.0.9", true), peer("gw", "100.64.0.10", true)]);
        assert_eq!(exit_node_ip_of_arg("gw", &st).unwrap_err().to_string(), "ambiguous exit node name \"gw\"");
    }

    #[test]
    fn exit_node_name_needs_a_populated_netmap_and_a_known_peer() {
        let empty = status(vec![]);
        assert_eq!(
            exit_node_ip_of_arg("gw", &empty).unwrap_err().to_string(),
            "cannot resolve exit node by hostname while Tailscale is starting up; please use its Tailscale IP address instead"
        );
        assert_eq!(exit_node_ip_of_arg("", &empty), Err(ExitNodeError::InvalidArgument));

        let st = status(vec![peer("other", "100.64.0.9", true)]);
        assert_eq!(
            exit_node_ip_of_arg("gw", &st).unwrap_err().to_string(),
            "invalid value \"gw\" for --exit-node; must be IP or peer hostname"
        );
    }

    #[test]
    fn a_peer_without_a_tailscale_ip_cannot_be_an_exit_node() {
        let mut ps = peer("gw", "100.64.0.9", true);
        ps.tailscale_ips.clear();
        let st = status(vec![ps]);
        assert_eq!(exit_node_ip_of_arg("gw", &st).unwrap_err().to_string(), "node \"gw\" has no Tailscale IP?");
    }

    #[test]
    fn masked_prefs_without_an_option_changes_nothing() {
        let mut option = TailscaleOption::default();
        assert!(build_tailscale_masked_prefs(&option).is_none());
        assert!(!tailscale_exit_node_needs_status(&option));

        option.accept_routes = Some(true);
        let prefs = build_tailscale_masked_prefs(&option).expect("route-all is a change");
        assert_eq!(prefs.route_all, Some(true));
        assert_eq!(prefs.auto_exit_node, None);
    }

    #[test]
    fn auto_exit_node_needs_no_status_but_a_named_one_does() {
        let mut option = TailscaleOption { exit_node: "auto:any".to_owned(), ..Default::default() };
        assert!(!tailscale_exit_node_needs_status(&option));
        let prefs = build_tailscale_masked_prefs(&option).expect("auto exit node is a change");
        assert_eq!(prefs.auto_exit_node.as_deref(), Some("any"));

        option.exit_node = "gw".to_owned();
        assert!(tailscale_exit_node_needs_status(&option));
        assert!(build_tailscale_masked_prefs(&option).is_none());
    }

    fn status_node(display_name: &str, ip: &str, exit_node: bool) -> StatusNode {
        StatusNode {
            stable_id: tailscale::StableNodeId(format!("{display_name}-id")),
            display_name: display_name.to_owned(),
            ipv4: ip.parse().expect("ipv4"),
            ipv6: "fd7a:115c:a1e0::1".parse().expect("ipv6"),
            tailscale_ips: vec![ip.parse().expect("peer ip")],
            online: Some(true),
            last_seen: None,
            allowed_routes: Vec::new(),
            is_exit_node: exit_node,
            cur_addr: None,
            relay: None,
            ssh_host_keys: Vec::new(),
            expired: false,
        }
    }

    /// An engine status with one peer and this node at `100.64.0.2`.
    fn engine_status(peers: Vec<StatusNode>, suffix: &str) -> EngineStatus {
        EngineStatus {
            self_node: Some(status_node("self", "100.64.0.2", false)),
            peers,
            active_exit_node: None,
            magic_dns_suffix: Some(suffix.to_owned()),
            health: Vec::new(),
        }
    }

    /// The engine reports peers and the MagicDNS suffix without dots, while the status names are
    /// fully qualified; the projection must restore the shape for the exit-node resolution.
    #[test]
    fn engine_status_projects_onto_the_exit_node_resolution() {
        let status = engine_status(vec![status_node("gw.ts.net", "100.64.0.9", true)], "ts.net");
        let ipn_status = ipn_status_from_engine(&status, backend_state_name(&DeviceState::Running));

        assert_eq!(ipn_status.peer[0].dns_name, "gw.ts.net.");
        assert_eq!(ipn_status.magic_dns_suffix, "ts.net");
        assert_eq!(ipn_status.backend_state, "Running");
        assert_eq!(ipn_status.tailscale_ips, vec!["100.64.0.2".parse::<IpAddr>().expect("self ip")]);

        for arg in ["gw", "GW", "gw.ts.net", "gw.ts.net."] {
            assert_eq!(exit_node_ip_of_arg(arg, &ipn_status), Ok("100.64.0.9".parse().expect("peer ip")), "{arg}");
        }
    }

    /// The DNS name keeps the root dot the status carries; a bare hostname (a node with no tailnet
    /// component) is left as the engine reported it.
    #[test]
    fn peer_dns_names_are_fully_qualified_only_when_the_engine_reports_a_tailnet_name() {
        assert_eq!(dns_name_of("gw.ts.net", Some("ts.net")), "gw.ts.net.");
        assert_eq!(dns_name_of("gw", Some("ts.net")), "gw");
        assert_eq!(dns_name_of("gw", None), "gw");
        assert_eq!(dns_name_of("gw.ts.net", Some("")), "gw.ts.net");
    }

    /// "tail1234.ts.net" is a raw string tail of "gw.mytail1234.ts.net" but not a label suffix of
    /// it, so the boundary check leaves the name alone and the truncated hostname must not match.
    #[test]
    fn a_suffix_without_a_label_boundary_is_not_stripped() {
        let status = engine_status(vec![status_node("gw.mytail1234.ts.net", "100.64.0.9", true)], "tail1234.ts.net");
        let ipn_status = ipn_status_from_engine(&status, backend_state_name(&DeviceState::Running));

        assert_eq!(ipn_status.peer[0].dns_name, "gw.mytail1234.ts.net");
        assert_eq!(
            exit_node_ip_of_arg("gw.my", &ipn_status).unwrap_err().to_string(),
            "invalid value \"gw.my\" for --exit-node; must be IP or peer hostname"
        );
        assert_eq!(
            exit_node_ip_of_arg("gw.mytail1234.ts.net", &ipn_status),
            Ok("100.64.0.9".parse().expect("peer ip"))
        );
    }

    /// Options → prefs → the engine: the adapter constructs a real `tsnet::Server`, starts it
    /// (which builds the engine's `Device`), and the start-time prefs land on that device. A
    /// Tailscale node needs no control connection to be built, so this runs without network access.
    #[tokio::test]
    async fn options_reach_the_engine_and_its_server_starts() {
        let option = TailscaleOption {
            name: "ts-adopt".to_owned(),
            state_dir: format!("{}/tailscale-adopt", PATH.home_dir()),
            accept_routes: Some(true),
            ..Default::default()
        };
        let adapter = Tailscale::new(option).expect("construction needs no engine");
        assert_eq!(adapter.option.accept_routes, Some(true));
        assert_eq!(build_tailscale_masked_prefs(&adapter.option).expect("a change").route_all, Some(true));

        adapter.start().await.expect("the engine server starts without a control connection");
        assert_eq!(
            std::env::var(ENGINE_GATE_VAR).as_deref(),
            Ok(ENGINE_GATE_VALUE),
            "the engine's experiment gate was satisfied by this adapter"
        );

        let server = adapter.engine_server().expect("server");
        let device = server.device().await.expect("the engine built its device");
        assert!(device.accept_routes(), "the start-time prefs reached the engine");

        adapter.close().expect("close");
        let _ = std::fs::remove_dir_all(&adapter.option.state_dir);
    }

    /// `auto:any` is the control-side exit-node selection; the engine has no automatic-exit-node pref,
    /// so the adapter must say exactly that instead of starting without the pref applied.
    #[tokio::test]
    async fn an_auto_exit_node_fails_closed_on_the_missing_engine_pref() {
        let option = TailscaleOption {
            name: "ts-auto".to_owned(),
            state_dir: format!("{}/tailscale-auto-exit-node", PATH.home_dir()),
            exit_node: "auto:any".to_owned(),
            ..Default::default()
        };
        let adapter = Tailscale::new(option).expect("construction needs no engine");

        let err = adapter.start().await.expect_err("the engine cannot select an exit node").to_string();
        assert!(err.contains("AutoExitNode") && err.contains("auto:any"), "{err}");

        let ctx = CancellationToken::new();
        let err = adapter.wait_backend_initialized(&ctx).await.expect_err("the error latched").to_string();
        assert!(err.contains("AutoExitNode"), "{err}");

        adapter.close().expect("close");
        let _ = std::fs::remove_dir_all(&adapter.option.state_dir);
    }
}

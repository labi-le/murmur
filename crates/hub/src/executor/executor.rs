//! `config` cannot import `executor` (that would be circular), so `hub::executor` registers
//! [`temporary_update_parse_geodata`] into `config::config::GENERAL_UPDATE_HOOK` once.
//!
//! The registration goes through [`ensure_general_update_hook_registered`], which
//! `murmur_config::config::parse_raw_config` calls; the rollback handle is a `Drop`-based guard.
//!
//! The geodata loaders are not wired by import-time side effects here: `memconservative::memc::init`
//! and `standard::standard::init` must each run once before the first `geodata::get_geo_data_loader`
//! call. [`parse_with_bytes`] is that first opportunity reachable from every one of this file's
//! `Parse`/`ParseWithPath`/`ParseWithBytes` entry points (rule/rule-provider parsing inside
//! `config::parse` needs the geosite/geoip loaders already registered), so the two `init()` calls
//! are wired there, guarded by a `std::sync::Once`.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Once};

use anyhow::{anyhow, Result};
use futures::stream::{self, StreamExt};
use tokio::sync::Mutex as AsyncMutex;

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "mips")))]
use super::concurrent_load_limit::CONCURRENT_COUNT;
#[cfg(target_arch = "mips")]
use super::concurrent_load_single::CONCURRENT_COUNT;
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
use super::concurrent_load_unlimit::CONCURRENT_COUNT;
use murmur_adapter::adapter::UNIFIED_DELAY;
use murmur_adapter_inbound::auth as inbound_auth;
use murmur_adapter_inbound::ipfilter as inbound_ipfilter;
use murmur_adapter_inbound::listen as inbound_listen;
use murmur_adapter_outboundgroup::util as outboundgroup_util;
use murmur_common::time::SECOND;
use murmur_component::auth::auth::new_authenticator;
use murmur_component::dialer::dialer as dialer_dialer;
use murmur_component::dialer::options::{DEFAULT_INTERFACE, DEFAULT_ROUTING_MARK};
use murmur_component::iface::iface as iface_iface;
use murmur_component::keepalive::tcp_keepalive as keepalive_tcp;
use murmur_component::resolver::enhancer as comp_enhancer;
use murmur_component::resolver::host as comp_host;
use murmur_component::resolver::ip4p as comp_ip4p;
use murmur_component::resolver::resolver as comp_resolver;
use murmur_component::resolver::service as comp_service;
use murmur_component_ca::config as ca_config;
use murmur_component_geodata::init as geodata_init;
use murmur_component_geodata::memconservative::memc as geodata_memc;
use murmur_component_geodata::standard::standard as geodata_standard;
use murmur_component_geodata::utils as geodata_utils;
use murmur_component_http::http as http_http;
use murmur_component_profile::cachefile::cache as cachefile_cache;
use murmur_component_profile::STORE_SELECTED;
use murmur_component_resource::vehicle as resource_vehicle;
use murmur_component_sniffer::dispatcher as sniffer_dispatcher;
use murmur_component_updater::update_geo;
use murmur_component_updater::update_ui;
use murmur_config::config as cfgmod;
use murmur_config::config::Config;
use murmur_config::config::{Experimental, General, IPTables, NTP};
use murmur_constant::adapters::Proxy as CProxy;
use murmur_constant::listener::InboundListener;
use murmur_constant::path::PATH;
use murmur_constant::provider::interface::{Provider, ProviderType, ProxyProvider, RuleProvider, VehicleType};
use murmur_constant::tunnel::Tunnel as ConstantTunnel;
use murmur_dns::enhancer as dns_enhancer;
use murmur_dns::resolver as dns_resolver;
use murmur_dns::server as dns_server;
use murmur_dns::service as dns_service;
use murmur_listener::auth::auth as listener_auth;
use murmur_listener::listener;
use murmur_listener_config::tunnel::Tunnel as ListenerTunnel;
use murmur_listener_inner::tcp as inner_tcp;
use murmur_listener_tproxy::tproxy_iptables;
use murmur_log::{errorln, infoln, warnln};
use murmur_tunnel::tunnel::{
    find_process_mode, is_sniffing, mode, on_inner_loading, on_running, on_suspend, set_find_process_mode, set_mode,
    update_proxies, update_rules, update_sniffer as tunnel_update_sniffer, TUNNEL,
};

static MUX: AsyncMutex<()> = AsyncMutex::const_new(());

static GEODATA_LOADERS_INIT: Once = Once::new();

fn ensure_geodata_loaders_registered() {
    GEODATA_LOADERS_INIT.call_once(|| {
        geodata_memc::init();
        geodata_standard::init();
    });
}

static GENERAL_UPDATE_HOOK_INIT: Once = Once::new();

/// The registered general-update hook; see `config::config::GENERAL_UPDATE_HOOK`'s doc comment for
/// why this is a runtime-registered callback rather than a plain `use`.
fn general_update_hook(general: &General) -> Pin<Box<dyn Future<Output = Box<dyn FnOnce() + Send>> + Send + '_>> {
    Box::pin(async move {
        let rollback: Box<dyn FnOnce() + Send> = Box::new(temporary_update_parse_geodata(general));
        rollback
    })
}

fn ensure_general_update_hook_registered() {
    GENERAL_UPDATE_HOOK_INIT.call_once(|| {
        cfgmod::set_general_update_hook(general_update_hook);
    });
}

fn tunnel_arc() -> Arc<dyn ConstantTunnel> {
    Arc::new(TUNNEL)
}

/// The file-missing check only distinguishes "file missing" from every other `metadata` failure
/// (which is ignored and left for the following read to report); that split is kept exact.
async fn read_config(path: &str) -> Result<Vec<u8>> {
    if let Err(err) = tokio::fs::metadata(path).await {
        if err.kind() == std::io::ErrorKind::NotFound {
            return Err(err.into());
        }
    }

    let data = tokio::fs::read(path).await?;
    if data.is_empty() {
        return Err(anyhow!("configuration file {path} is empty"));
    }
    Ok(data)
}

/// `Parse` config with default config path.
pub async fn parse() -> Result<Config> {
    parse_with_path(&PATH.config()).await
}

/// `ParseWithPath` parse config with custom config path.
pub async fn parse_with_path(path: &str) -> Result<Config> {
    let buf = read_config(path).await?;
    parse_with_bytes(&buf).await
}

/// `ParseWithBytes` config with buffer.
pub async fn parse_with_bytes(buf: &[u8]) -> Result<Config> {
    // The general-update hook this parse fires publishes the candidate geodata settings and
    // restores them at the end of the parse; a concurrent test that reads those geodata settings
    // must not interleave.
    // `CONFIG_OPERATION`, which every production entry point takes first (`hub::parse`,
    // `PUT /configs`, `PATCH /configs`), is what serialises those callers; this test-only lock
    // keeps direct `parse_with_bytes` callers in the test suite honest, and is never taken before
    // `CONFIG_OPERATION`.
    #[cfg(test)]
    let _tunnel_state = crate::test_support::TUNNEL_STATE_LOCK.lock().await;
    ensure_geodata_loaders_registered();
    ensure_general_update_hook_registered();
    cfgmod::parse(buf).await
}

fn as_proxy_provider(p: Arc<dyn ProxyProvider>) -> Arc<dyn Provider> {
    p
}

fn as_rule_provider(p: Arc<dyn RuleProvider>) -> Arc<dyn Provider> {
    p
}

/// A single function over the `Provider` supertrait object, built by upcasting each concrete
/// `ProxyProvider`/`RuleProvider` map at the two call sites; the bounded-concurrency buffered
/// channel becomes `for_each_concurrent` with the same concurrency limit.
async fn load_provider(providers: HashMap<String, Arc<dyn Provider>>) {
    async fn load(name: String, pv: Arc<dyn Provider>) {
        if pv.vehicle_type() == VehicleType::COMPATIBLE {
            infoln!("Start initial compatible provider {name}");
        } else {
            infoln!("Start initial provider {name}");
        }

        if let Err(err) = pv.initial().await {
            match pv.type_() {
                ProviderType::PROXY => errorln!("initial proxy provider {name} error: {err}"),
                ProviderType::RULE => errorln!("initial rule provider {name} error: {err}"),
                _ => {}
            }
        }
    }

    stream::iter(providers).for_each_concurrent(CONCURRENT_COUNT, |(name, pv)| load(name, pv)).await;
}

fn update_experimental(c: &Experimental) {
    if c.quic_go_disable_gso {
        std::env::set_var("QUIC_GO_DISABLE_GSO", "true");
    }
    if c.quic_go_disable_ecn {
        std::env::set_var("QUIC_GO_DISABLE_ECN", "true");
    }
    comp_ip4p::set_ip4p_enable(c.ip4p_enable);
}

fn update_ntp(c: &NTP) {
    if c.enable {
        murmur_ntp::ntp::service::re_create_ntp_service(
            murmur_component::dialer::bind::join_host_port(&c.server, c.port),
            murmur_common::time::duration_from_nanos(i64::from(c.interval)),
            c.dialer_proxy.clone(),
            tunnel_arc(),
            c.write_to_system,
        );
    } else {
        murmur_ntp::ntp::service::re_create_ntp_service(
            String::new(),
            std::time::Duration::ZERO,
            String::new(),
            tunnel_arc(),
            false,
        );
    }
}

fn update_dns(c: cfgmod::DNS, general_ipv6: bool) {
    if !c.enable {
        comp_resolver::set_default_resolver(None);
        comp_enhancer::set_default_host_mapper(None);
        comp_service::set_default_service(None);
        comp_resolver::set_proxy_server_host_resolver(None);
        comp_resolver::set_direct_host_resolver(None);
        dns_server::re_create_server("", None, None);
        return;
    }

    let ipv6 = c.ipv6 && general_ipv6;

    let resolvers = dns_resolver::Resolvers::new(dns_resolver::Config {
        main: c.name_server,
        fallback: c.fallback,
        default: c.default_nameserver,
        proxy_server: c.proxy_server_nameserver,
        direct_server: c.direct_nameserver,
        direct_follow_policy: c.direct_follow_policy,
        ipv6,
        ipv6_timeout: c.ipv6_timeout,
        fallback_ip_filter: c.fallback_ip_filter,
        fallback_domain_filter: c.fallback_domain_filter,
        fallback_lazy_query: c.fallback_lazy_query,
        policy: c.name_server_policy,
        proxy_server_policy: c.proxy_server_policy,
        cache_algorithm: c.cache_algorithm,
        cache_max_size: c.cache_max_size,
    });

    let m = dns_enhancer::ResolverEnhancer::new(dns_enhancer::EnhancerConfig {
        ipv6,
        enhanced_mode: c.enhanced_mode,
        fake_ip_pool: c.fake_ip_pool.map(Arc::new),
        fake_ip_pool6: c.fake_ip_pool6.map(Arc::new),
        fake_ip_skipper: c.fake_ip_skipper.map(Arc::new),
        fake_ip_ttl: c.fake_ip_ttl,
        use_hosts: c.use_hosts,
    });

    // The source is the current default host mapper, so a mapper installed by any other writer is
    // still patched from, and a foreign one is skipped instead of asserted.
    let old_mapper = comp_enhancer::default_host_mapper();
    if let Some(old) =
        old_mapper.as_ref().and_then(|mapper| mapper.as_any().downcast_ref::<dns_enhancer::ResolverEnhancer>())
    {
        m.patch_from(old);
    }

    let m = Arc::new(m);

    let shared_resolver: comp_resolver::SharedResolver = Arc::new(resolvers.resolver);
    let shared_service: comp_service::SharedService =
        Arc::new(dns_service::Service::new(Arc::clone(&shared_resolver), &m));

    comp_resolver::set_default_resolver(Some(Arc::clone(&shared_resolver)));
    let shared_enhancer: comp_enhancer::SharedEnhancer = m;
    comp_enhancer::set_default_host_mapper(Some(shared_enhancer));
    comp_service::set_default_service(Some(Arc::clone(&shared_service)));
    comp_host::set_use_system_hosts(c.use_system_hosts);

    match resolvers.proxy_resolver {
        Some(pr) if pr.invalid() => {
            comp_resolver::set_proxy_server_host_resolver(Some(Arc::new(pr)));
        }
        _ => {
            comp_resolver::set_proxy_server_host_resolver(Some(Arc::clone(&shared_resolver)));
        }
    }

    match resolvers.direct_resolver {
        Some(dr) if dr.invalid() => {
            comp_resolver::set_direct_host_resolver(Some(Arc::new(dr)));
        }
        _ => {
            comp_resolver::set_direct_host_resolver(Some(shared_resolver));
        }
    }

    let mut lc = inbound_listen::new_listen_config();
    lc.set_route_mark(c.listen_routing_mark);
    dns_server::re_create_server(&c.listen, Some(Arc::new(lc)), Some(shared_service));
}

fn update_hosts(tree: murmur_component_trie::domain::DomainTrie<comp_host::HostValue>) {
    comp_resolver::set_default_hosts(comp_host::new_hosts(tree));
}

/// The outcome of one apply step that can report several independent failures: one error naming
/// them all, or `Ok(())` when the list is empty. An empty `step` reports the failures alone.
fn step_outcome(step: &str, failures: Vec<anyhow::Error>) -> Result<()> {
    if failures.is_empty() {
        return Ok(());
    }
    let joined = failures.into_iter().map(|error| error.to_string()).collect::<Vec<_>>().join("; ");
    if step.is_empty() {
        return Err(anyhow!("{joined}"));
    }
    Err(anyhow!("{step}: {joined}"))
}

/// Recreates the inbound listeners. Every listener is attempted even when an earlier one fails,
/// and the failures come back as one error: the caller has to know that the running configuration
/// is incomplete, but a listener that could not bind must not stop the others from starting.
async fn update_listeners(
    general: &General,
    listeners: &HashMap<String, Arc<dyn InboundListener>>,
    force: bool,
) -> Result<()> {
    let tunnel = tunnel_arc();
    let mut failures = Vec::new();

    if let Err(err) = listener::patch_inbound_listeners(listeners, Arc::clone(&tunnel), true).await {
        failures.push(err);
    }
    if !force {
        return step_outcome("listeners", failures);
    }

    listener::set_allow_lan(general.inbound.allow_lan);
    inbound_auth::set_skip_auth_prefixes(general.inbound.skip_auth_prefixes.clone());
    inbound_ipfilter::set_allowed_ips(general.inbound.lan_allowed_ips.clone());
    inbound_ipfilter::set_dis_allowed_ips(general.inbound.lan_dis_allowed_ips.clone());

    listener::set_bind_address(&general.inbound.bind_address);
    for result in [
        listener::re_create_http(general.inbound.port, Arc::clone(&tunnel)).await,
        listener::re_create_socks(general.inbound.socks_port, Arc::clone(&tunnel)).await,
        listener::re_create_redir(general.inbound.redir_port, Arc::clone(&tunnel)).await,
        listener::re_create_tproxy(general.inbound.tproxy_port, Arc::clone(&tunnel)).await,
        listener::re_create_mixed(general.inbound.mixed_port, Arc::clone(&tunnel)).await,
        listener::re_create_shadow_socks(&general.inbound.shadow_socks_config, Arc::clone(&tunnel)).await,
        listener::re_create_vmess(&general.inbound.vmess_config, Arc::clone(&tunnel)).await,
        listener::re_create_tuic(general.inbound.tuic_server.clone(), tunnel).await,
    ] {
        if let Err(err) = result {
            failures.push(err);
        }
    }

    step_outcome("listeners", failures)
}

fn update_general(general: &General, logging: bool) {
    set_mode(general.mode);
    set_find_process_mode(general.find_process_mode);
    comp_resolver::set_disable_ipv6(!general.ipv6);

    dialer_dialer::set_tcp_concurrent(general.tcp_concurrent);
    if logging && general.tcp_concurrent {
        infoln!("Use tcp concurrent");
    }

    inbound_listen::set_tfo(general.inbound.inbound_tfo);
    inbound_listen::set_mptcp(general.inbound.inbound_mptcp);

    keepalive_tcp::set_keep_alive_idle(i64::from(general.keep_alive_idle) * SECOND);
    keepalive_tcp::set_keep_alive_interval(i64::from(general.keep_alive_interval) * SECOND);
    keepalive_tcp::set_disable_keep_alive(general.disable_keep_alive);

    UNIFIED_DELAY.store(general.unified_delay);

    DEFAULT_INTERFACE.store(general.interface.clone());
    DEFAULT_ROUTING_MARK.store(general.routing_mark);
    if logging && general.routing_mark > 0 {
        infoln!("Use routing mark: {:#x}", general.routing_mark);
    }

    iface_iface::flush_cache();

    geodata_utils::set_geodata_mode(general.geodata_mode);
    geodata_utils::set_loader(&general.geodata_loader);
    geodata_utils::set_site_matcher(&general.geosite_matcher);
    geodata_init::set_geo_ip_url(&general.geo_x_url.geo_ip);
    geodata_init::set_geo_site_url(&general.geo_x_url.geo_site);
    geodata_init::set_mmdb_url(&general.geo_x_url.mmdb);
    geodata_init::set_asn_url(&general.geo_x_url.asn);
    http_http::set_ua(general.global_ua.clone());
    resource_vehicle::set_etag(general.etag_support);
}

fn update_users(users: &[murmur_component::auth::auth::AuthUser]) {
    let authenticator = new_authenticator(users);
    let has_auth = authenticator.is_some();
    listener_auth::DEFAULT.set_authenticator(authenticator);
    if has_auth {
        infoln!("Authentication of local server updated");
    }
}

fn update_profile(profile_cfg: cfgmod::Profile, proxies: &HashMap<String, Arc<dyn CProxy>>) {
    STORE_SELECTED.store(profile_cfg.store_selected);
    if profile_cfg.store_selected {
        patch_select_group(proxies);
    }
}

fn patch_select_group(proxies: &HashMap<String, Arc<dyn CProxy>>) {
    patch_select_group_from(cachefile_cache::cache().as_ref(), proxies);
}

/// [`patch_select_group`] over an explicit cache: the singleton is process-wide and exclusively
/// file-locked, so a test cannot share it with another test binary on the host.
fn patch_select_group_from(cache: &cachefile_cache::CacheFile, proxies: &HashMap<String, Arc<dyn CProxy>>) {
    let mapping = cache.selected_map();
    if mapping.is_empty() {
        return;
    }

    for (name, outbound) in proxies {
        let adapter = outbound.adapter();
        let Some(selector) = outboundgroup_util::as_select_able(adapter.as_ref()) else {
            continue;
        };

        let Some(selected) = mapping.get(name) else {
            continue;
        };

        selector.force_set(selected);
    }
}

/// The deferred error handling runs on every return path; the same `Result` is collected and the
/// deferred handling performed once at the end, after the iptables cleanup and the disabled-path
/// early return (which the deferred handling never reaches either, since it is installed after
/// them).
async fn update_iptables(iptables: &IPTables, general: &General, dns_enable: bool, dns_listen: &str) {
    tproxy_iptables::cleanup_tproxy_iptables().await;

    if !cfg!(target_os = "linux") || !iptables.enable {
        return;
    }

    let result = try_set_iptables(iptables, general, dns_enable, dns_listen).await;
    match result {
        Ok(()) => infoln!("[IPTABLES] Setting iptables completed"),
        Err(err) => {
            errorln!("[IPTABLES] setting iptables failed: {}", err);
            std::process::exit(2);
        }
    }
}

async fn try_set_iptables(iptables: &IPTables, general: &General, dns_enable: bool, dns_listen: &str) -> Result<()> {
    let mut inbound_interface = "lo".to_owned();
    let t_proxy_port = general.inbound.tproxy_port;
    let dns_redirect = iptables.dns_redirect;

    if t_proxy_port == 0 {
        return Err(anyhow!("tproxy-port must be greater than zero"));
    }
    let t_proxy_port = u16::try_from(t_proxy_port).map_err(|_| anyhow!("tproxy-port must fit a port number"))?;

    let dns_port: u16 = if dns_redirect {
        if !dns_enable {
            return Err(anyhow!("DNS server must be enable"));
        }

        let addr: SocketAddr = dns_listen.parse().map_err(|_| anyhow!("DNS server must be correct"))?;
        addr.port()
    } else {
        0
    };

    if !iptables.inbound_interface.is_empty() {
        inbound_interface = iptables.inbound_interface.clone();
    }

    let _ = DEFAULT_ROUTING_MARK.compare_and_swap(0, 2158);

    tproxy_iptables::set_tproxy_iptables(&inbound_interface, &iptables.bypass, t_proxy_port, dns_redirect, dns_port)
        .await?;

    Ok(())
}

async fn update_tunnels(tunnels: &[ListenerTunnel]) -> Result<()> {
    listener::patch_tunnel(tunnels, tunnel_arc()).await
}

async fn update_updater(geo_auto_update: bool, geo_update_interval: i32, controller: &cfgmod::Controller) {
    update_geo::set_geo_auto_update(geo_auto_update);
    update_geo::set_geo_update_interval(geo_update_interval);

    let ui_updater =
        update_ui::new_ui_updater(&controller.external_ui, &controller.external_ui_url, &controller.external_ui_name);
    let ui_updater = update_ui::install_ui_updater(ui_updater);
    ui_updater.auto_download_ui().await;
}

fn init_inner_tcp() {
    inner_tcp::new(tunnel_arc());
}

/// Dispatches the configuration to all parts except the external controller.
///
/// Every part is still applied when one of them fails: the failures are collected and returned once
/// at the end, so a caller can tell the running state is incomplete without the configuration being
/// abandoned half-way.
pub async fn apply_config(cfg: Config, force: bool) -> Result<()> {
    let _guard = MUX.lock().await;

    murmur_log::set_level(cfg.general.log_level);

    on_suspend();

    ca_config::reset_certificate();
    for c in &cfg.tls.custom_trust_cert {
        if let Err(err) = ca_config::add_certificate(c) {
            warnln!("{c}\nadd error: {err}");
        }
    }

    update_experimental(&cfg.experimental);
    update_users(&cfg.users);
    update_proxies(cfg.proxies.clone(), cfg.providers.clone());
    update_rules(cfg.rules, cfg.sub_rules, cfg.rule_providers.clone());
    update_sniffer(&cfg.sniffer);
    update_hosts(cfg.hosts);
    update_general(&cfg.general, true);

    let dns_enable = cfg.dns.enable;
    let dns_listen = cfg.dns.listen.clone();
    let general_ipv6 = cfg.general.ipv6;
    update_dns(cfg.dns, general_ipv6);

    update_ntp(&cfg.ntp);
    let mut failures = Vec::new();
    if let Err(err) = update_listeners(&cfg.general, &cfg.listeners, force).await {
        failures.push(err);
    }
    // A tun failure is a documented degradation, not an incomplete apply: the listener clears
    // `enable` and stores that conf, so the next apply with the same section is a no-op.
    listener::re_create_tun(cfg.general.inbound.tun.clone(), tunnel_arc()).await;
    update_iptables(&cfg.iptables, &cfg.general, dns_enable, &dns_listen).await;
    if let Err(err) = update_tunnels(&cfg.tunnels).await {
        failures.push(err);
    }

    on_inner_loading();

    init_inner_tcp();
    let providers: HashMap<String, Arc<dyn Provider>> =
        cfg.providers.iter().map(|(k, v)| (k.clone(), as_proxy_provider(Arc::clone(v)))).collect();
    load_provider(providers).await;
    update_profile(cfg.profile, &cfg.proxies);
    let rule_providers: HashMap<String, Arc<dyn Provider>> =
        cfg.rule_providers.iter().map(|(k, v)| (k.clone(), as_rule_provider(Arc::clone(v)))).collect();
    load_provider(rule_providers).await;
    // A forced collection has no equivalent (the allocator is not manually collected), so this
    // step is dropped.
    on_running();
    update_updater(cfg.general.geo_auto_update, cfg.general.geo_update_interval, &cfg.controller).await;

    comp_resolver::reset_connection();

    step_outcome("", failures)
}

fn update_sniffer(sniffer_config: &sniffer_dispatcher::Config) {
    let dispatcher = match sniffer_dispatcher::new_dispatcher(sniffer_config) {
        Ok(dispatcher) => dispatcher,
        Err(err) => {
            warnln!("initial sniffer failed, err:{err}");
            let disabled = sniffer_dispatcher::Config {
                enable: false,
                sniffers: HashMap::new(),
                force_domain: Vec::new(),
                skip_src_address: Vec::new(),
                skip_dst_address: Vec::new(),
                skip_domain: Vec::new(),
                force_dns_mapping: false,
                parse_pure_ip: false,
            };
            let Ok(dispatcher) = sniffer_dispatcher::new_dispatcher(&disabled) else {
                warnln!("disabled sniffer dispatcher could not be built; keeping the previous one");
                return;
            };
            dispatcher
        }
    };

    tunnel_update_sniffer(Arc::new(dispatcher));

    if sniffer_config.enable {
        infoln!("Sniffer is loaded and working");
    } else {
        infoln!("Sniffer is closed");
    }
}

/// `get_general` reports keep-alive values as the signed second count the config surface carries,
/// saturated outside its range.
fn keep_alive_seconds(nanos: murmur_common::time::TimeDuration) -> i32 {
    i32::try_from(nanos / SECOND).unwrap_or(if nanos < 0 { i32::MIN } else { i32::MAX })
}

pub async fn get_general() -> General {
    let ports = listener::get_ports().await;
    let authenticator = listener_auth::DEFAULT.authenticator().map(|auth| auth.users()).unwrap_or_default();

    General {
        inbound: cfgmod::Inbound {
            port: ports.port,
            socks_port: ports.socks_port,
            redir_port: ports.redir_port,
            tproxy_port: ports.tproxy_port,
            mixed_port: ports.mixed_port,
            tuic_server: listener::get_tuic_conf().await,
            tun: listener::get_tun_conf(),
            shadow_socks_config: ports.shadow_socks_config,
            vmess_config: ports.vmess_config,
            authentication: authenticator,
            skip_auth_prefixes: inbound_auth::skip_auth_prefixes(),
            lan_allowed_ips: inbound_ipfilter::allowed_ips(),
            lan_dis_allowed_ips: inbound_ipfilter::dis_allowed_ips(),
            allow_lan: listener::allow_lan(),
            bind_address: listener::bind_address(),
            inbound_tfo: inbound_listen::tfo(),
            inbound_mptcp: inbound_listen::mptcp(),
        },
        mode: mode(),
        unified_delay: UNIFIED_DELAY.load(),
        log_level: murmur_log::level(),
        ipv6: !comp_resolver::disable_ipv6(),
        interface: DEFAULT_INTERFACE.load(),
        routing_mark: DEFAULT_ROUTING_MARK.load(),
        geo_x_url: cfgmod::GeoXUrl {
            geo_ip: geodata_init::geo_ip_url(),
            mmdb: geodata_init::mmdb_url(),
            asn: geodata_init::asn_url(),
            geo_site: geodata_init::geo_site_url(),
        },
        geo_auto_update: update_geo::geo_auto_update(),
        geo_update_interval: update_geo::geo_update_interval(),
        geodata_mode: geodata_utils::geodata_mode(),
        geodata_loader: geodata_utils::loader_name(),
        geosite_matcher: geodata_utils::site_matcher_name(),
        tcp_concurrent: dialer_dialer::get_tcp_concurrent(),
        find_process_mode: find_process_mode(),
        sniffing: is_sniffing(),
        global_ua: http_http::ua(),
        etag_support: resource_vehicle::etag(),
        keep_alive_interval: keep_alive_seconds(keepalive_tcp::keep_alive_interval()),
        keep_alive_idle: keep_alive_seconds(keepalive_tcp::keep_alive_idle()),
        disable_keep_alive: keepalive_tcp::disable_keep_alive(),
    }
}

/// The general-update entry point; see the module doc comment.
/// Applies the settings a parse reads through the live accessors, and only those: rule and
/// rule-provider construction consults the geodata matching strategy, loader and geo-x URLs
/// (`rules-common::geoip`, `component-geodata`). The rest of the candidate general config
/// (routing mode, resolver and dialer settings, listener options, interface) is deliberately left
/// untouched, because traffic threads read those globals without holding `CONFIG_OPERATION`: a
/// candidate that later fails validation would otherwise be visible to live connections.
pub(crate) fn temporary_update_parse_geodata(general: &General) -> impl FnOnce() {
    let old = ParseGeodata::capture();
    geodata_utils::set_geodata_mode(general.geodata_mode);
    geodata_utils::set_loader(&general.geodata_loader);
    geodata_utils::set_site_matcher(&general.geosite_matcher);
    geodata_init::set_geo_ip_url(&general.geo_x_url.geo_ip);
    geodata_init::set_mmdb_url(&general.geo_x_url.mmdb);
    geodata_init::set_geo_site_url(&general.geo_x_url.geo_site);
    geodata_init::set_asn_url(&general.geo_x_url.asn);
    move || old.restore()
}

/// The geodata settings a parse may publish, captured so the hook restores them when the parse
/// finishes, whether or not it succeeds.
struct ParseGeodata {
    mode: bool,
    loader: String,
    site_matcher: String,
    geo_ip_url: String,
    mmdb_url: String,
    geo_site_url: String,
    asn_url: String,
}

impl ParseGeodata {
    fn capture() -> Self {
        Self {
            mode: geodata_utils::geodata_mode(),
            loader: geodata_utils::loader_name(),
            site_matcher: geodata_utils::site_matcher_name(),
            geo_ip_url: geodata_init::geo_ip_url(),
            mmdb_url: geodata_init::mmdb_url(),
            geo_site_url: geodata_init::geo_site_url(),
            asn_url: geodata_init::asn_url(),
        }
    }

    fn restore(self) {
        geodata_utils::set_geodata_mode(self.mode);
        geodata_utils::set_loader(&self.loader);
        geodata_utils::set_site_matcher(&self.site_matcher);
        geodata_init::set_geo_ip_url(&self.geo_ip_url);
        geodata_init::set_mmdb_url(&self.mmdb_url);
        geodata_init::set_geo_site_url(&self.geo_site_url);
        geodata_init::set_asn_url(&self.asn_url);
    }
}

pub async fn shutdown() {
    listener::cleanup().await;
    tproxy_iptables::cleanup_tproxy_iptables().await;
    comp_enhancer::store_fake_pool_state();

    warnln!("murmur shutting down");
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use murmur_constant::dns::DNSMode;

    use super::*;

    /// The production singleton is host-shared and exclusively locked, so a second test binary
    /// makes its `Db::open` time out; drive the same body over a private cache file instead.
    #[tokio::test(flavor = "multi_thread")]
    async fn patch_select_group_restores_persisted_selection() {
        use murmur_component_profile::cachefile::bolt::{Db, Options};

        let yaml = b"proxy-groups:\n  - name: PatchSelectGroupTest\n    type: select\n    proxies:\n      - DIRECT\n      - REJECT\n";
        let cfg = parse_with_bytes(yaml).await.expect("minimal select-group config must parse");

        let outbound = cfg.proxies.get("PatchSelectGroupTest").expect("select group present in parsed config");
        let adapter = outbound.adapter();
        let group = outboundgroup_util::as_proxy_group(adapter.as_ref()).expect("select group downcasts to ProxyGroup");
        assert_eq!(group.now(), "DIRECT", "default selection before any persisted choice");

        let dir = std::env::temp_dir().join(format!("murmur-patch-select-group-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create private cache directory");
        let path = dir.join("cache.db");
        let options = Options { timeout: Some(std::time::Duration::from_secs(1)), no_statistics: true };
        let db = Db::open(&path.to_string_lossy(), 0o666, &options).expect("open the private cache file");
        let cache = cachefile_cache::CacheFile { db: Some(db) };

        let _restore = StoreSelectedGuard::force(true);
        cache.set_selected("PatchSelectGroupTest", "REJECT");
        patch_select_group_from(&cache, &cfg.proxies);

        assert_eq!(group.now(), "REJECT", "patch_select_group must restore the persisted selection on reload");

        drop(cache);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Restores `STORE_SELECTED` on drop, so a panicking assertion cannot leak the write.
    struct StoreSelectedGuard(bool);

    impl StoreSelectedGuard {
        fn force(value: bool) -> Self {
            let previous = STORE_SELECTED.load();
            STORE_SELECTED.store(value);
            Self(previous)
        }
    }

    impl Drop for StoreSelectedGuard {
        fn drop(&mut self) {
            STORE_SELECTED.store(self.0);
        }
    }

    /// The new enhancer is patched from the default host mapper itself. A private record of this
    /// function's own previous write named a different object whenever the mapper was installed by
    /// any other writer, silently dropping the mapped host on reload.
    #[tokio::test(flavor = "multi_thread")]
    async fn update_dns_patches_from_the_current_default_host_mapper() {
        let ip: IpAddr = "198.18.0.7".parse().expect("fake ip literal");
        let old = dns_enhancer::ResolverEnhancer::new(dns_enhancer::EnhancerConfig {
            enhanced_mode: DNSMode::DNS_MAPPING,
            ..Default::default()
        });
        old.insert_host_by_ip(ip, "patched.example.com");
        comp_enhancer::set_default_host_mapper(Some(Arc::new(old)));

        let dns = cfgmod::DNS { enable: true, enhanced_mode: DNSMode::DNS_MAPPING, ..Default::default() };
        update_dns(dns, false);

        let found = comp_enhancer::find_host_by_ip(ip);
        update_dns(cfgmod::DNS::default(), false);

        assert_eq!(
            found.as_deref(),
            Some("patched.example.com"),
            "update_dns must patch the new enhancer from the live DefaultHostMapper"
        );
    }

    /// The parse hook publishes only the geodata settings that rule construction reads. The
    /// routing mode, resolver and dialer globals stay at the applied configuration, so traffic
    /// cannot observe a candidate general config while a parse that may be rejected is running.
    #[tokio::test]
    async fn the_parse_hook_leaves_traffic_visible_general_settings_alone() {
        use murmur_tunnel::mode::TunnelMode;

        let _tunnel_state = crate::test_support::TUNNEL_STATE_LOCK.lock().await;
        struct RestoreGeodata(Option<ParseGeodata>);
        impl Drop for RestoreGeodata {
            fn drop(&mut self) {
                if let Some(previous) = self.0.take() {
                    previous.restore();
                }
            }
        }
        let _restore = RestoreGeodata(Some(ParseGeodata::capture()));

        let applied_mode = mode();
        let applied_disable_ipv6 = comp_resolver::disable_ipv6();
        let applied_tcp_concurrent = dialer_dialer::get_tcp_concurrent();
        let applied_geodata = ParseGeodata::capture();

        let mut general = get_general().await;
        general.mode = if applied_mode == TunnelMode::RULE { TunnelMode::DIRECT } else { TunnelMode::RULE };
        general.ipv6 = applied_disable_ipv6; // `update_general` maps `ipv6 == true` to `disable_ipv6 == false`
        general.tcp_concurrent = !applied_tcp_concurrent;
        general.geodata_mode = !applied_geodata.mode;
        general.geodata_loader =
            if applied_geodata.loader == "standard" { "memconservative".to_owned() } else { "standard".to_owned() };

        let rollback = temporary_update_parse_geodata(&general);
        assert_eq!(mode(), applied_mode, "a candidate routing mode must not reach live traffic");
        assert_eq!(
            comp_resolver::disable_ipv6(),
            applied_disable_ipv6,
            "a candidate resolver setting must not reach live traffic"
        );
        assert_eq!(
            dialer_dialer::get_tcp_concurrent(),
            applied_tcp_concurrent,
            "a candidate dialer setting must not reach live traffic"
        );
        assert_eq!(
            geodata_utils::geodata_mode(),
            general.geodata_mode,
            "rule construction must see the candidate geodata mode"
        );
        assert_eq!(
            geodata_utils::loader_name(),
            general.geodata_loader,
            "rule construction must see the candidate geodata loader"
        );
        rollback();
        assert_eq!(
            (geodata_utils::geodata_mode(), geodata_utils::loader_name()),
            (applied_geodata.mode, applied_geodata.loader),
            "the hook must restore the applied geodata settings"
        );
    }
}

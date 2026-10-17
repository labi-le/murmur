use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};

use anyhow::anyhow;
use serde::Serialize;
use tokio::sync::Mutex as AsyncMutex;

use crate::http::server as http_server;
use crate::mixed::mixed as mixed_server;
use crate::redir::tcp as redir_tcp;
use crate::shadowsocks::utils::parse_ss_url;
use crate::sing_shadowsocks::server as sing_shadowsocks;
use crate::sing_vmess::server::{self as sing_vmess, parse_vmess_url};
use crate::socks::tcp as socks_tcp;
use crate::socks::udp as socks_udp;
use crate::tuic::server as tuic_server;
use crate::tunnel::tcp as tunnel_tcp;
use crate::tunnel::udp as tunnel_udp;
use murmur_adapter_inbound::listen::default_listen_config;
use murmur_common_net::tcpip::split_host_port;
use murmur_constant::listener::{InboundListener, Listener as ConstListener, MultiAddrListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::shadowsocks::ShadowsocksServer as LcShadowsocksServer;
use murmur_listener_config::tuic::TuicServer as LcTuicServer;
use murmur_listener_config::tun::Tun;
use murmur_listener_config::tunnel::Tunnel as LcTunnel;
use murmur_listener_config::vmess::{VmessServer as LcVmessServer, VmessUser as LcVmessUser};
use murmur_listener_tproxy::tproxy as tproxy_tcp;
use murmur_listener_tproxy::udp as tproxy_udp;
use murmur_log::{errorln, infoln, warnln};

#[derive(Debug, Clone, Default, Serialize)]
pub struct Ports {
    #[serde(rename = "port")]
    pub port: i32,
    #[serde(rename = "socks-port")]
    pub socks_port: i32,
    #[serde(rename = "redir-port")]
    pub redir_port: i32,
    #[serde(rename = "tproxy-port")]
    pub tproxy_port: i32,
    #[serde(rename = "mixed-port")]
    pub mixed_port: i32,
    #[serde(rename = "ss-config")]
    pub shadow_socks_config: String,
    #[serde(rename = "vmess-config")]
    pub vmess_config: String,
}

static ALLOW_LAN: AtomicBool = AtomicBool::new(false);
static BIND_ADDRESS: LazyLock<parking_lot::Mutex<String>> = LazyLock::new(|| parking_lot::Mutex::new("*".to_owned()));
static LAST_TUN_CONF: LazyLock<parking_lot::Mutex<Tun>> = LazyLock::new(|| parking_lot::Mutex::new(Tun::default()));
static TUN_MUX: LazyLock<AsyncMutex<Option<Arc<crate::tun::Listener>>>> = LazyLock::new(|| AsyncMutex::new(None));

struct SocksState {
    listener: Option<Arc<socks_tcp::Listener>>,
    udp_listener: Option<Arc<socks_udp::UdpListener>>,
}
static SOCKS_MUX: AsyncMutex<SocksState> = AsyncMutex::const_new(SocksState { listener: None, udp_listener: None });

struct HttpState {
    listener: Option<http_server::Listener>,
}
static HTTP_MUX: AsyncMutex<HttpState> = AsyncMutex::const_new(HttpState { listener: None });

struct RedirState {
    listener: Option<redir_tcp::Listener>,
    udp_listener: Option<Arc<tproxy_udp::UdpListener>>,
}
static REDIR_MUX: AsyncMutex<RedirState> = AsyncMutex::const_new(RedirState { listener: None, udp_listener: None });

struct TproxyState {
    listener: Option<Arc<tproxy_tcp::Listener>>,
    udp_listener: Option<Arc<tproxy_udp::UdpListener>>,
}
static TPROXY_MUX: AsyncMutex<TproxyState> = AsyncMutex::const_new(TproxyState { listener: None, udp_listener: None });

struct MixedState {
    listener: Option<Arc<mixed_server::Listener>>,
    udp_listener: Option<Arc<socks_udp::UdpListener>>,
}
static MIXED_MUX: AsyncMutex<MixedState> = AsyncMutex::const_new(MixedState { listener: None, udp_listener: None });

struct TunnelState {
    tcp: HashMap<String, Arc<tunnel_tcp::Listener>>,
    udp: HashMap<String, Arc<tunnel_udp::PacketConn>>,
}
static TUNNEL_MUX: LazyLock<AsyncMutex<TunnelState>> =
    LazyLock::new(|| AsyncMutex::new(TunnelState { tcp: HashMap::new(), udp: HashMap::new() }));

static INBOUND_MUX: LazyLock<AsyncMutex<HashMap<String, Arc<dyn InboundListener>>>> =
    LazyLock::new(|| AsyncMutex::new(HashMap::new()));

static SS_MUX: AsyncMutex<Option<Arc<dyn MultiAddrListener>>> = AsyncMutex::const_new(None);
static VMESS_MUX: AsyncMutex<Option<Arc<sing_vmess::Listener>>> = AsyncMutex::const_new(None);

struct TuicState {
    listener: Option<tuic_server::Listener>,
    last_conf: LcTuicServer,
}
static TUIC_MUX: LazyLock<AsyncMutex<TuicState>> =
    LazyLock::new(|| AsyncMutex::new(TuicState { listener: None, last_conf: LcTuicServer::default() }));

pub async fn get_tuic_conf() -> LcTuicServer {
    let state = TUIC_MUX.lock().await;
    match &state.listener {
        None => LcTuicServer::default(),
        Some(listener) => listener.config(),
    }
}

/// The stored tuic conf that a `tuic-server` PATCH merges onto, not onto
/// [`get_tuic_conf`], which reports a zero conf while no tuic listener runs.
pub async fn last_tuic_conf() -> LcTuicServer {
    TUIC_MUX.lock().await.last_conf.clone()
}

pub fn allow_lan() -> bool {
    ALLOW_LAN.load(Ordering::SeqCst)
}

pub fn bind_address() -> String {
    BIND_ADDRESS.lock().clone()
}

pub fn set_allow_lan(al: bool) {
    ALLOW_LAN.store(al, Ordering::SeqCst);
}

pub fn set_bind_address(host: &str) {
    host.clone_into(&mut BIND_ADDRESS.lock());
}

/// The stored conf that a `tun:` PATCH merges onto.
pub fn get_tun_conf() -> Tun {
    LAST_TUN_CONF.lock().clone()
}

/// Re-creating the TUN sorts the conf before storing it.
pub fn set_tun_conf(mut tun: Tun) {
    tun.sort();
    *LAST_TUN_CONF.lock() = tun;
}

/// Sorts and stores the conf, then creates, keeps or closes the device.
///
/// A conf the device cannot honour is logged and stored with
/// `enable` cleared, so `get_tun_conf` reports what actually runs and a later PATCH with the
/// same options is seen as a change and retried.
///
/// The conf-unchanged path also reloads, which only touches the default routing mark
/// and the default interface finder; both are set from `auto-redirect-output-mark` and
/// `auto-detect-interface`, which `tun::reject_unsupported` refuses by name, so there is nothing
/// to reload.
pub async fn re_create_tun(mut config: Tun, tunnel: Arc<dyn Tunnel>) {
    config.sort();
    let previous = get_tun_conf();
    let mut state = TUN_MUX.lock().await;

    if config != previous {
        if let Some(listener) = state.take() {
            let _ = listener.close();
        }
        if config.enable {
            match crate::tun::new(config.clone(), tunnel, Vec::new()).await {
                Ok(listener) => {
                    crate::tun::log_startup(&listener.address());
                    *state = Some(listener);
                    drop(state);
                }
                Err(err) => {
                    errorln!("Start TUN listening error: {}", err);
                    config.enable = false;
                }
            }
        }
    }

    *LAST_TUN_CONF.lock() = config;
}

/// `Cleanup`: closes the TUN listener and nothing else:
/// its `Close` reverts the addresses and routes the device installed, so a restart does not
/// inherit a route pointing at a device that is gone.
pub async fn cleanup() {
    let listener = TUN_MUX.lock().await.take();
    if let Some(listener) = listener {
        let _ = listener.close();
    }
}

pub async fn re_create_http(port: i32, tunnel: Arc<dyn Tunnel>) -> anyhow::Result<()> {
    let mut state = HTTP_MUX.lock().await;

    let addr = gen_addr(&bind_address(), port, allow_lan());

    if let Some(listener) = &state.listener {
        if listener.raw_address() == addr {
            return Ok(());
        }
        let _ = listener.close();
        state.listener = None;
    }

    if port_is_zero(&addr) {
        return Ok(());
    }

    let mut failed = false;
    match http_server::new(&addr, tunnel, &[]).await {
        Ok(listener) => {
            infoln!("HTTP proxy listening at: {}", listener.address());
            state.listener = Some(listener);
            drop(state);
        }
        Err(e) => {
            // The error is logged twice: here, and from the deferred check that still sees the
            // same error on this return path.
            errorln!("Start HTTP server error: {}", e);
            errorln!("Start HTTP server error: {}", e);
            failed = true;
        }
    }
    if failed {
        return Err(anyhow!("the http listener did not start"));
    }
    Ok(())
}

pub async fn re_create_socks(port: i32, tunnel: Arc<dyn Tunnel>) -> anyhow::Result<()> {
    let mut state = SOCKS_MUX.lock().await;

    let addr = gen_addr(&bind_address(), port, allow_lan());

    let mut should_tcp_ignore = false;
    let mut should_udp_ignore = false;

    if let Some(listener) = &state.listener {
        if listener.raw_address() == addr {
            should_tcp_ignore = true;
        } else {
            let _ = listener.close();
            state.listener = None;
        }
    }

    if let Some(listener) = &state.udp_listener {
        if listener.raw_address() == addr {
            should_udp_ignore = true;
        } else {
            let _ = listener.close();
            state.udp_listener = None;
        }
    }

    if should_tcp_ignore && should_udp_ignore {
        return Ok(());
    }

    if port_is_zero(&addr) {
        return Ok(());
    }

    let tcp_listener = match socks_tcp::new(&addr, Arc::clone(&tunnel), Vec::new()).await {
        Ok(l) => l,
        Err(e) => {
            errorln!("Start SOCKS server error: {}", e);
            return Err(anyhow!("the socks listener did not start"));
        }
    };

    let udp_listener = match socks_udp::new_udp(&addr, tunnel, Vec::new()).await {
        Ok(l) => l,
        Err(e) => {
            let _ = tcp_listener.close();
            errorln!("Start SOCKS server error: {}", e);
            return Err(anyhow!("the socks listener did not start"));
        }
    };

    infoln!("SOCKS proxy listening at: {}", tcp_listener.address());
    state.listener = Some(tcp_listener);
    state.udp_listener = Some(udp_listener);
    drop(state);
    Ok(())
}

/// Re-creates the redir halves.
///
/// Each half is bound on its own: a UDP bind that failed earlier is retried by the next reload
/// (`udp_listener` stays empty), and a TCP half already serving `addr` stays bound.
pub async fn re_create_redir(port: i32, tunnel: Arc<dyn Tunnel>) -> anyhow::Result<()> {
    let mut state = REDIR_MUX.lock().await;

    let addr = gen_addr(&bind_address(), port, allow_lan());

    let mut should_tcp_ignore = false;
    let mut should_udp_ignore = false;

    if let Some(listener) = &state.listener {
        if listener.raw_address() == addr {
            should_tcp_ignore = true;
        } else {
            let _ = listener.close();
            state.listener = None;
        }
    }

    if let Some(listener) = &state.udp_listener {
        if listener.raw_address() == addr {
            should_udp_ignore = true;
        } else {
            let _ = listener.close();
            state.udp_listener = None;
        }
    }

    if should_tcp_ignore && should_udp_ignore {
        return Ok(());
    }

    if port_is_zero(&addr) {
        return Ok(());
    }

    if !should_tcp_ignore {
        match redir_tcp::new(&addr, Arc::clone(&tunnel), &[]).await {
            Ok(listener) => {
                infoln!("Redirect proxy listening at: {}", listener.address());
                state.listener = Some(listener);
            }
            Err(e) => {
                errorln!("Start Redir server error: {}", e);
                return Err(anyhow!("the redir listener did not start"));
            }
        }
    }

    if !should_udp_ignore {
        match tproxy_udp::new_udp(&addr, tunnel, Vec::new()).await {
            Ok(l) => state.udp_listener = Some(l),
            Err(e) => {
                warnln!("Failed to start Redir UDP Listener: {}", e);
                errorln!("Start Redir server error: {}", e);
                // TCP redirection works on every platform; the redir UDP half is the Linux
                // implementation, and `setsockopt_other` refuses it by name elsewhere. On those
                // platforms the absent half is the documented TCP-only redirection, not a failed
                // apply, so the binary must keep serving it instead of aborting.
                #[cfg(target_os = "linux")]
                return Err(anyhow!("the redir listener did not start"));
            }
        }
    }

    drop(state);
    Ok(())
}

pub async fn re_create_shadow_socks(shadow_socks_config: &str, tunnel: Arc<dyn Tunnel>) -> anyhow::Result<()> {
    let mut state = SS_MUX.lock().await;

    let ss_config = match parse_ss_url(shadow_socks_config) {
        Ok((addr, cipher, password)) => {
            let LcShadowsocksServer { mux_option, shadow_tls, res_tls, jls_config, kcp_tun, simple_obfs, .. } =
                LcShadowsocksServer::default();
            LcShadowsocksServer {
                enable: !shadow_socks_config.is_empty(),
                listen: addr,
                password,
                cipher,
                udp: true,
                mux_option,
                shadow_tls,
                res_tls,
                jls_config,
                kcp_tun,
                simple_obfs,
            }
        }
        Err(_) => LcShadowsocksServer::default(),
    };

    let mut should_ignore = false;
    if let Some(listener) = state.as_ref() {
        if listener.config() == ss_config.to_string() {
            should_ignore = true;
        } else {
            let _ = listener.close();
            *state = None;
        }
    }

    if should_ignore {
        return Ok(());
    }
    if !ss_config.enable {
        return Ok(());
    }

    let listener = match sing_shadowsocks::new(ss_config, default_listen_config(), tunnel, Vec::new()).await {
        Ok(l) => l,
        Err(e) => {
            errorln!("Start ShadowSocks server error: {}", e);
            return Err(anyhow!("the shadowsocks listener did not start"));
        }
    };

    for addr in listener.addr_list() {
        infoln!("ShadowSocks proxy listening at: {}", addr.string());
    }

    *state = Some(listener);
    drop(state);
    Ok(())
}

pub async fn re_create_vmess(vmess_config: &str, tunnel: Arc<dyn Tunnel>) -> anyhow::Result<()> {
    let mut state = VMESS_MUX.lock().await;

    let vs_config = match parse_vmess_url(vmess_config) {
        Ok((addr, username, password)) => {
            let LcVmessServer {
                ws_path,
                grpc_service_name,
                certificate,
                private_key,
                client_auth_type,
                client_auth_cert,
                ech_key,
                shadow_tls,
                res_tls,
                jls_config,
                reality_config,
                tls_mirror_config,
                mekya_config,
                mkcp_config,
                mux_option,
                ..
            } = LcVmessServer::default();
            LcVmessServer {
                enable: !vmess_config.is_empty(),
                listen: addr,
                users: vec![LcVmessUser { username, uuid: password, alter_id: 1 }],
                ws_path,
                grpc_service_name,
                certificate,
                private_key,
                client_auth_type,
                client_auth_cert,
                ech_key,
                shadow_tls,
                res_tls,
                jls_config,
                reality_config,
                tls_mirror_config,
                mekya_config,
                mkcp_config,
                mux_option,
            }
        }
        Err(_) => LcVmessServer::default(),
    };

    let mut should_ignore = false;
    if let Some(listener) = state.as_ref() {
        if listener.config() == vs_config.to_string() {
            should_ignore = true;
        } else {
            let _ = listener.close();
            *state = None;
        }
    }

    if should_ignore {
        return Ok(());
    }
    if !vs_config.enable {
        return Ok(());
    }

    let listener = match sing_vmess::new(vs_config, default_listen_config(), tunnel, Vec::new()).await {
        Ok(l) => l,
        Err(e) => {
            errorln!("Start Vmess server error: {}", e);
            return Err(anyhow!("the vmess listener did not start"));
        }
    };

    for addr in listener.addr_list() {
        infoln!("Vmess proxy listening at: {}", addr.string());
    }

    *state = Some(listener);
    drop(state);
    Ok(())
}

pub async fn re_create_tuic(config: LcTuicServer, tunnel: Arc<dyn Tunnel>) -> anyhow::Result<()> {
    let mut state = TUIC_MUX.lock().await;

    let should_ignore = if let Some(listener) = &state.listener {
        if listener.config().to_string() == config.to_string() {
            true
        } else {
            let _ = listener.close();
            state.listener = None;
            false
        }
    } else {
        false
    };

    let mut failed = false;
    if !should_ignore && config.enable {
        match tuic_server::new(config.clone(), default_listen_config(), tunnel, &[]).await {
            Ok(listener) => {
                for addr in listener.addr_list() {
                    infoln!("Tuic proxy listening at: {}", addr.string());
                }
                state.listener = Some(listener);
            }
            Err(e) => {
                errorln!("Start Tuic server error: {}", e);
                failed = true;
            }
        }
    }

    state.last_conf = config;
    drop(state);
    if failed {
        return Err(anyhow!("the tuic listener did not start"));
    }
    Ok(())
}

/// The tproxy counterpart of [`re_create_redir`], with the same per-half retry.
pub async fn re_create_tproxy(port: i32, tunnel: Arc<dyn Tunnel>) -> anyhow::Result<()> {
    let mut state = TPROXY_MUX.lock().await;

    let addr = gen_addr(&bind_address(), port, allow_lan());

    let mut should_tcp_ignore = false;
    let mut should_udp_ignore = false;

    if let Some(listener) = &state.listener {
        if listener.raw_address() == addr {
            should_tcp_ignore = true;
        } else {
            let _ = listener.close();
            state.listener = None;
        }
    }

    if let Some(listener) = &state.udp_listener {
        if listener.raw_address() == addr {
            should_udp_ignore = true;
        } else {
            let _ = listener.close();
            state.udp_listener = None;
        }
    }

    if should_tcp_ignore && should_udp_ignore {
        return Ok(());
    }

    if port_is_zero(&addr) {
        return Ok(());
    }

    let mut failed = false;
    if !should_tcp_ignore {
        match tproxy_tcp::new(&addr, Arc::clone(&tunnel), Vec::new()).await {
            Ok(listener) => {
                infoln!("TProxy server listening at: {}", listener.address());
                state.listener = Some(listener);
            }
            Err(e) => {
                errorln!("Start TProxy server error: {}", e);
                return Err(anyhow!("the tproxy listener did not start"));
            }
        }
    }

    if !should_udp_ignore {
        match tproxy_udp::new_udp(&addr, tunnel, Vec::new()).await {
            Ok(l) => state.udp_listener = Some(l),
            Err(e) => {
                warnln!("Failed to start TProxy UDP Listener: {}", e);
                errorln!("Start TProxy server error: {}", e);
                failed = true;
            }
        }
    }

    drop(state);
    if failed {
        return Err(anyhow!("the tproxy listener did not start"));
    }
    Ok(())
}

pub async fn re_create_mixed(port: i32, tunnel: Arc<dyn Tunnel>) -> anyhow::Result<()> {
    let mut state = MIXED_MUX.lock().await;

    let addr = gen_addr(&bind_address(), port, allow_lan());

    let mut should_tcp_ignore = false;
    let mut should_udp_ignore = false;

    if let Some(listener) = &state.listener {
        if listener.raw_address() == addr {
            should_tcp_ignore = true;
        } else {
            let _ = listener.close();
            state.listener = None;
        }
    }

    if let Some(listener) = &state.udp_listener {
        if listener.raw_address() == addr {
            should_udp_ignore = true;
        } else {
            let _ = listener.close();
            state.udp_listener = None;
        }
    }

    if should_tcp_ignore && should_udp_ignore {
        return Ok(());
    }

    if port_is_zero(&addr) {
        return Ok(());
    }

    let listener = match mixed_server::new(&addr, Arc::clone(&tunnel), Vec::new()).await {
        Ok(l) => l,
        Err(e) => {
            errorln!("Start Mixed(http+socks) server error: {}", e);
            return Err(anyhow!("the mixed listener did not start"));
        }
    };

    let udp_listener = match socks_udp::new_udp(&addr, tunnel, Vec::new()).await {
        Ok(l) => l,
        Err(e) => {
            let _ = listener.close();
            errorln!("Start Mixed(http+socks) server error: {}", e);
            return Err(anyhow!("the mixed listener did not start"));
        }
    };

    infoln!("Mixed(http+socks) proxy listening at: {}", listener.address());
    state.listener = Some(listener);
    state.udp_listener = Some(udp_listener);
    drop(state);
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct AddrProxy {
    network: String,
    addr: String,
    target: String,
    proxy: String,
}

fn addr_proxy_from_key(network: &str, key: &str) -> AddrProxy {
    let mut parts = key.split('/');
    AddrProxy {
        network: network.to_owned(),
        addr: parts.next().unwrap_or_default().to_owned(),
        target: parts.next().unwrap_or_default().to_owned(),
        proxy: parts.next().unwrap_or_default().to_owned(),
    }
}

fn union_dedup(a: Vec<AddrProxy>, b: Vec<AddrProxy>) -> Vec<AddrProxy> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in a.into_iter().chain(b) {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

fn difference(a: &[AddrProxy], b: &[AddrProxy]) -> (Vec<AddrProxy>, Vec<AddrProxy>) {
    let a_set: HashSet<&AddrProxy> = a.iter().collect();
    let b_set: HashSet<&AddrProxy> = b.iter().collect();
    let only_a = a.iter().filter(|x| !b_set.contains(x)).cloned().collect();
    let only_b = b.iter().filter(|x| !a_set.contains(x)).cloned().collect();
    (only_a, only_b)
}

pub async fn patch_tunnel(tunnels: &[LcTunnel], tunnel: Arc<dyn Tunnel>) -> anyhow::Result<()> {
    let mut state = TUNNEL_MUX.lock().await;

    let tcp_old: Vec<AddrProxy> = state.tcp.keys().map(|key| addr_proxy_from_key("tcp", key)).collect();
    let udp_old: Vec<AddrProxy> = state.udp.keys().map(|key| addr_proxy_from_key("udp", key)).collect();
    let old_elm = union_dedup(tcp_old, udp_old);

    let new_elm: Vec<AddrProxy> = tunnels
        .iter()
        .flat_map(|t| {
            t.network
                .iter()
                .map(|network| AddrProxy {
                    network: network.clone(),
                    addr: t.address.clone(),
                    target: t.target.clone(),
                    proxy: t.proxy.clone(),
                })
                .collect::<Vec<_>>()
        })
        .collect();

    let (need_close, need_create) = difference(&old_elm, &new_elm);

    for elm in &need_close {
        let key = format!("{}/{}/{}", elm.addr, elm.target, elm.proxy);
        if elm.network == "tcp" {
            if let Some(l) = state.tcp.remove(&key) {
                let _ = l.close();
            }
        } else if let Some(l) = state.udp.remove(&key) {
            let _ = l.close();
        }
    }

    let lc = default_listen_config();
    let mut failed = false;
    for elm in &need_create {
        let key = format!("{}/{}/{}", elm.addr, elm.target, elm.proxy);
        if elm.network == "tcp" {
            match tunnel_tcp::new(&elm.addr, &elm.target, &elm.proxy, Arc::clone(&lc), Arc::clone(&tunnel), Vec::new())
                .await
            {
                Ok(l) => {
                    infoln!("Tunnel(tcp/{}) proxy {} listening at: {}", elm.target, elm.proxy, l.address());
                    state.tcp.insert(key, l);
                }
                Err(e) => {
                    errorln!("Start tunnel {} error: {}", elm.target, e);
                    failed = true;
                }
            }
        } else {
            match tunnel_udp::new_udp(
                &elm.addr,
                &elm.target,
                &elm.proxy,
                Arc::clone(&lc),
                Arc::clone(&tunnel),
                Vec::new(),
            )
            .await
            {
                Ok(l) => {
                    infoln!("Tunnel(udp/{}) proxy {} listening at: {}", elm.target, elm.proxy, l.address());
                    state.udp.insert(key, l);
                }
                Err(e) => {
                    errorln!("Start tunnel {} error: {}", elm.target, e);
                    failed = true;
                }
            }
        }
    }
    drop(state);
    if failed {
        return Err(anyhow!("one or more tunnels did not start"));
    }
    Ok(())
}

#[expect(clippy::implicit_hasher, reason = "the public signature takes the caller's concrete HashMap")]
pub async fn patch_inbound_listeners(
    new_listener_map: &HashMap<String, Arc<dyn InboundListener>>,
    tunnel: Arc<dyn Tunnel>,
    drop_old: bool,
) -> anyhow::Result<()> {
    let mut listeners = INBOUND_MUX.lock().await;

    let mut failed = false;
    for (name, new_listener) in new_listener_map {
        if let Some(old_listener) = listeners.get(name) {
            if old_listener.config().equal(new_listener.config().as_ref()) {
                continue;
            }
            let _ = old_listener.close();
        }
        if let Err(e) = new_listener.listen(Arc::clone(&tunnel)).await {
            errorln!("Listener {} listen err: {}", name, e);
            failed = true;
            continue;
        }
        listeners.insert(name.clone(), Arc::clone(new_listener));
    }

    if drop_old {
        let to_remove: Vec<String> =
            listeners.keys().filter(|name| !new_listener_map.contains_key(*name)).cloned().collect();
        for name in to_remove {
            if let Some(old_listener) = listeners.remove(&name) {
                let _ = old_listener.close();
            }
        }
    }
    if failed {
        return Err(anyhow!("one or more inbound listeners did not start"));
    }
    Ok(())
}

pub async fn get_ports() -> Ports {
    let mut ports = Ports::default();

    if let Some(listener) = &HTTP_MUX.lock().await.listener {
        ports.port = parse_port(&listener.address());
    }

    if let Some(listener) = &SOCKS_MUX.lock().await.listener {
        ports.socks_port = parse_port(&listener.address());
    }

    if let Some(listener) = &REDIR_MUX.lock().await.listener {
        ports.redir_port = parse_port(&listener.address());
    }

    if let Some(listener) = &TPROXY_MUX.lock().await.listener {
        ports.tproxy_port = parse_port(&listener.address());
    }

    if let Some(listener) = &MIXED_MUX.lock().await.listener {
        ports.mixed_port = parse_port(&listener.address());
    }

    if let Some(listener) = SS_MUX.lock().await.as_ref() {
        ports.shadow_socks_config = listener.config();
    }

    if let Some(listener) = VMESS_MUX.lock().await.as_ref() {
        ports.vmess_config = listener.config();
    }

    ports
}

fn parse_port(addr: &str) -> i32 {
    match split_host_port(addr) {
        Ok((_, port, _)) => i32::try_from(murmur_constant::metadata::parse_int(&port)).unwrap_or(0),
        Err(_) => 0,
    }
}

fn port_is_zero(addr: &str) -> bool {
    match split_host_port(addr) {
        Ok((_, port, _)) => port == "0" || port.is_empty(),
        Err(_) => true,
    }
}

fn gen_addr(host: &str, port: i32, allow_lan: bool) -> String {
    if allow_lan {
        if host == "*" {
            return format!("0.0.0.0:{port}");
        }
        return format!("{host}:{port}");
    }
    format!("127.0.0.1:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use murmur_common::observable::subscriber::Subscription;
    use murmur_common_net::io::Stream;
    use murmur_component_nat::table::Table;
    use murmur_constant::adapters::{NatTable, UDPPacket};
    use murmur_constant::metadata::Metadata;
    use murmur_log::Event;

    #[tokio::test]
    async fn wildcard_lan_address_accepts_ipv4_tcp_connections() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(gen_addr("*", 0, true)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut client = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        client.write_all(b"wildcard TCP").await.unwrap();
        let mut payload = [0u8; 12];
        tokio::time::timeout(std::time::Duration::from_secs(2), server.read_exact(&mut payload))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&payload, b"wildcard TCP");
    }

    #[tokio::test]
    async fn wildcard_lan_address_round_trips_ipv4_udp_datagrams() {
        let server = tokio::net::UdpSocket::bind(gen_addr("*", 0, true)).await.unwrap();
        let port = server.local_addr().unwrap().port();
        let client = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client.send_to(b"wildcard UDP", (std::net::Ipv4Addr::LOCALHOST, port)).await.unwrap();
        let mut payload = [0u8; 64];
        let (received, peer) = tokio::time::timeout(std::time::Duration::from_secs(2), server.recv_from(&mut payload))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&payload[..received], b"wildcard UDP");
        server.send_to(&payload[..received], peer).await.unwrap();
        let (received, _) = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_from(&mut payload))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&payload[..received], b"wildcard UDP");
    }

    struct NullTunnel;

    #[async_trait::async_trait]
    impl Tunnel for NullTunnel {
        async fn handle_tcp_conn(&self, _conn: Box<dyn Stream>, _metadata: Metadata) {}

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {}

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    fn null_tunnel() -> Arc<dyn Tunnel> {
        Arc::new(NullTunnel)
    }

    /// The conf is sorted before it is stored, so a conf that only differs in field order is the
    /// same conf and no device is created for it twice.
    #[tokio::test]
    async fn re_create_tun_stores_the_sorted_conf_without_opening_a_device() {
        let config = Tun {
            enable: false,
            device: "utun11".to_owned(),
            dns_hijack: Some(vec!["b:53".to_owned(), "a:53".to_owned()]),
            ..Default::default()
        };
        re_create_tun(config.clone(), null_tunnel()).await;
        assert_eq!(get_tun_conf().dns_hijack, Some(vec!["a:53".to_owned(), "b:53".to_owned()]));

        re_create_tun(config, null_tunnel()).await;
        assert!(!get_tun_conf().enable);
        assert_eq!(get_tun_conf().dns_hijack, Some(vec!["a:53".to_owned(), "b:53".to_owned()]));
    }

    /// Re-creating the TUN clears `Enable` when the device rejects the conf, so the stored
    /// conf reports what actually runs and a later PATCH with the same options is retried. Every
    /// conf here is refused by `reject_unsupported`, which runs before any descriptor is opened,
    /// including the default shape whose `dns-hijack` is non-empty and the
    /// `auto-detect-interface: true` that starts a netlink monitor.
    #[tokio::test]
    async fn re_create_tun_clears_enable_when_the_device_refuses_the_conf() {
        let base = Tun {
            enable: true,
            device: "utun9".to_owned(),
            disable_icmp_forwarding: true,
            mtu: 9000,
            ..Default::default()
        };
        let configs = [
            Tun { stack: murmur_constant::tun::TunStack::System, ..base.clone() },
            Tun { auto_detect_interface: true, ..base.clone() },
            Tun { dns_hijack: Some(vec!["0.0.0.0:53".to_owned()]), ..base.clone() },
        ];

        for config in configs {
            re_create_tun(config.clone(), null_tunnel()).await;

            let stored = get_tun_conf();
            assert!(!stored.enable, "a refused device must not stay enabled: {config:?}");
            assert_eq!(stored.device, "utun9");
            assert_eq!(stored.mtu, 9000);
            assert_eq!(stored.stack, config.stack);
        }
    }

    async fn redir_state(port: i32) -> (bool, bool) {
        let state = REDIR_MUX.lock().await;
        let addr = gen_addr(&bind_address(), port, allow_lan());
        (state.listener.as_ref().is_some_and(|listener| listener.raw_address() == addr), state.udp_listener.is_some())
    }

    async fn close_redir() {
        let mut state = REDIR_MUX.lock().await;
        if let Some(listener) = state.listener.take() {
            let _ = listener.close();
        }
        if let Some(listener) = state.udp_listener.take() {
            let _ = listener.close();
        }
    }

    /// Waits for `want` redir-UDP warnings, so a retry that never happens fails the count instead
    /// of hanging the run.
    async fn redir_udp_warnings(logs: &Subscription<Event>, want: usize) -> usize {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut seen = 0;
        while seen < want {
            let Ok(Some(event)) = tokio::time::timeout_at(deadline, logs.recv()).await else {
                break;
            };
            if event.payload.contains("Failed to start Redir UDP Listener") {
                seen += 1;
            }
        }
        seen
    }

    /// The redir UDP half tolerates a failed bind and stays absent, so the next re-create has to
    /// reach the UDP bind again even though the TCP half already serves the same address.
    #[tokio::test]
    async fn a_failed_redir_udp_bind_is_retried_on_the_next_re_create() {
        let logs = murmur_log::subscribe().await.expect("a log subscription");
        // The port has to be free for TCP and held for UDP. Its number comes from an ephemeral UDP
        // bind (there is no other way to name a UDP port), so the TCP side is probed, and when a
        // parallel test binary takes it between the probe and the bind the probe is repeated on a
        // fresh number instead of asserting on the first attempt. That collision is how this test
        // failed the workspace gate while passing in the crate's own run.
        for _ in 0..20 {
            let (holder, port) = {
                let mut probed = None;
                for _ in 0..200 {
                    let holder =
                        std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("a held UDP port");
                    let port = holder.local_addr().expect("the held address").port();
                    if std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok() {
                        probed = Some((holder, i32::from(port)));
                        break;
                    }
                }
                probed.expect("an ephemeral port free for both halves")
            };

            let _ = re_create_redir(port, null_tunnel()).await;
            if !redir_state(port).await.0 {
                // The TCP side was taken between the probe and the bind; try a different number.
                drop(holder);
                close_redir().await;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                continue;
            }

            assert!(!redir_state(port).await.1, "the held UDP port cannot be bound");
            assert!(redir_udp_warnings(&logs, 1).await >= 1);

            drop(holder);
            let _ = re_create_redir(port, null_tunnel()).await;

            if !redir_state(port).await.1 {
                assert_eq!(redir_udp_warnings(&logs, 1).await, 1, "the retry must reach the UDP bind");
            }
            close_redir().await;
            murmur_log::un_subscribe(logs).await;
            return;
        }
        panic!("no probed port stayed free for the TCP half");
    }
}

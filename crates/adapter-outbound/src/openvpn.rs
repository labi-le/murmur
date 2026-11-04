//! The OpenVPN adapter: `self_weak` gives `new_packet_conn` the `Arc<OpenVPN>` the receiver
//! already is (see the wave report).
//!
//! The semaphore-based double-checked locking and background packet loops are implemented with
//! `tokio::sync::Semaphore` + `tokio::spawn`, following the same idiom
//! `transport/masque/l4proxy.rs`'s `L4Client` already establishes in this crate.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use ipnet::IpNet;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::{OnceCell, Semaphore};
use tokio_util::sync::CancellationToken;

use murmur_common::contextutils::after_func;
use murmur_common::errors::{error_is, ErrOsClosed};
use murmur_common::time::SECOND;
use murmur_component::dialer::dialer::new_dialer;
use murmur_component::dialer::options::{with_net_dialer, with_resolver, Option as DialerOption};
use murmur_component::resolver::resolver::{default_resolver, SharedResolver};
use murmur_constant::adapters::AdapterType;
use murmur_constant::adapters::{
    Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_dns::resolver::{Config as DnsConfig, NameServer, Resolvers, PARSE_NAME_SERVER};
use murmur_log::{debugln, errorln, warnln};
use murmur_transport_openvpn::client::{is_err_net_closed, Client};
use murmur_transport_openvpn::config::{ClientConfig, PROTO_TCP, PROTO_UDP};
use murmur_transport_openvpn::control::ContextError;
use murmur_transport_openvpn::packetio::{
    new_datagram_packet_io, new_datagram_packet_io_recoverable, new_tcp_packet_io, PacketIO,
};

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::util::ip_stack::{new_ip_stack, IpStack, IpStackNetDialer, IpStackOption};
use super::util::resolve_ip_with_resolver;

pub struct OpenVPN {
    self_weak: Weak<Self>,
    base: Base,
    option: OpenVPNOption,
    config: Arc<ClientConfig>,
    dns: Vec<NameServer>,

    run_ctx: CancellationToken,
    run_lock: Arc<Semaphore>,
    state: Mutex<OpenVpnState>,
}

impl core::fmt::Debug for OpenVPN {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenVPN").field("addr", &self.base.addr()).finish_non_exhaustive()
    }
}

struct OpenVpnState {
    tun_device: Option<Arc<dyn IpStack>>,
    client: Option<Arc<Client>>,
    resolver: Option<SharedResolver>,
    running: bool,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct OpenVPNOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server")]
    pub server: String,
    #[serde(rename = "port")]
    pub port: i32,
    #[serde(rename = "proto", default)]
    pub proto: String,
    #[serde(rename = "dev", default)]
    pub dev: String,
    #[serde(rename = "cipher", default)]
    pub cipher: String,
    #[serde(rename = "data-ciphers", default)]
    pub data_ciphers: Vec<String>,
    #[serde(rename = "data-ciphers-fallback", default)]
    pub data_cipher_fallback: String,
    #[serde(rename = "auth", default)]
    pub auth: String,
    #[serde(rename = "comp-lzo", default)]
    pub comp_lzo: String,
    #[serde(rename = "ca")]
    pub ca: String,
    #[serde(rename = "cert", default)]
    pub cert: String,
    #[serde(rename = "key", default)]
    pub key: String,
    #[serde(rename = "tls-auth", default)]
    pub tls_auth: String,
    #[serde(rename = "key-direction", default)]
    pub key_direction: String,
    #[serde(rename = "tls-crypt", default)]
    pub tls_crypt: String,
    #[serde(rename = "tls-crypt-v2", default)]
    pub tls_crypt_v2: String,
    #[serde(rename = "username", default)]
    pub username: String,
    #[serde(rename = "password", default)]
    pub password: String,
    #[serde(rename = "peer-info", default)]
    pub peer_info: HashMap<String, String>,
    #[serde(rename = "ping", default)]
    pub ping: i32,
    #[serde(rename = "ping-restart", default)]
    pub ping_restart: i32,
    #[serde(rename = "tran-window", default)]
    pub tran_window: Option<i32>,
    #[serde(rename = "handshake-timeout", default)]
    pub handshake_timeout: i32,
    #[serde(rename = "mtu", default)]
    pub mtu: i32,
    #[serde(rename = "udp", default)]
    pub udp: bool,
    #[serde(rename = "ip-stack", default)]
    pub ip_stack: IpStackOption,
    #[serde(rename = "remote-dns-resolve", default)]
    pub remote_dns_resolve: bool,
    #[serde(rename = "dns", default)]
    pub dns: Vec<String>,
}

impl core::fmt::Debug for OpenVPNOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenVPNOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("proto", &self.proto)
            .field("dev", &self.dev)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("key", &"<redacted>")
            .field("tls_auth", &"<redacted>")
            .field("tls_crypt", &"<redacted>")
            .field("tls_crypt_v2", &"<redacted>")
            .finish_non_exhaustive()
    }
}

pub(crate) fn open_vpn_transition_window(value: Option<i64>) -> Result<(i64, bool)> {
    let Some(value) = value else {
        return Ok((0, false));
    };
    if value < 0 {
        bail!("openvpn tran-window must be non-negative");
    }
    if value > i64::MAX / SECOND {
        bail!("openvpn tran-window is too large");
    }
    Ok((value * SECOND, true))
}

impl OpenVPN {
    pub fn new(mut option: OpenVPNOption) -> Result<Arc<Self>> {
        if option.handshake_timeout < 0 {
            bail!("openvpn handshake timeout must be non-negative");
        }
        let (transition_window, transition_window_set) = open_vpn_transition_window(option.tran_window.map(i64::from))?;
        let remote_port =
            u16::try_from(option.port).map_err(|_| anyhow!("OpenVPN: port {} is out of range", option.port))?;
        option.ip_stack.normalize();
        option.ip_stack.validate()?;

        let mut cfg = ClientConfig {
            remote_host: option.server.clone(),
            remote_port,
            proto: option.proto.clone(),
            dev: option.dev.clone(),
            cipher: option.cipher.clone(),
            data_ciphers: option.data_ciphers.clone(),
            fallback_cipher: option.data_cipher_fallback.clone(),
            auth: option.auth.clone(),
            comp_lzo: option.comp_lzo.clone(),
            ca: option.ca.clone().into_bytes(),
            cert: option.cert.clone().into_bytes(),
            key: option.key.clone().into_bytes(),
            tls_auth: option.tls_auth.clone().into_bytes(),
            key_direction: option.key_direction.clone(),
            tls_crypt: option.tls_crypt.clone().into_bytes(),
            tls_crypt_v2: option.tls_crypt_v2.clone().into_bytes(),
            username: option.username.clone(),
            password: option.password.clone(),
            peer_info: option.peer_info.clone(),
            ping_interval: i64::from(option.ping) * SECOND,
            ping_restart: i64::from(option.ping_restart) * SECOND,
            transition_window,
            transition_window_set,
            tls_crypt_key: Vec::new(),
            tls_auth_key: Vec::new(),
            tls_crypt_v2_key: Vec::new(),
            tls_crypt_v2_wrapped_key: Vec::new(),
        };
        cfg.prepare()?;
        let cfg = Arc::new(cfg);

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr: cfg.remote_address(),
            type_: AdapterType::OPEN_VPN,
            provider_name: option.basic_option.provider_name.clone(),
            udp: true,
            xudp: false,
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
        });

        let dns_servers = if option.remote_dns_resolve && !option.dns.is_empty() {
            parse_name_server(&option.dns)?
        } else {
            Vec::new()
        };

        base.dialer = Some(option.basic_option.new_dialer(base.dial_options()));

        Ok(Arc::new_cyclic(|self_weak| Self {
            self_weak: Weak::clone(self_weak),
            base,
            option,
            config: cfg,
            dns: dns_servers,
            run_ctx: CancellationToken::new(),
            run_lock: Arc::new(Semaphore::new(1)),
            state: Mutex::new(OpenVpnState { tun_device: None, client: None, resolver: None, running: false }),
        }))
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("OpenVPN adapter dropped while still in use"))
    }

    async fn run(&self, ctx: &CancellationToken) -> Result<(Arc<dyn IpStack>, Option<SharedResolver>)> {
        let run_ctx = ctx.child_token();
        let run_ctx_for_stop = run_ctx.clone();
        let stop = after_func(&self.run_ctx, move || {
            run_ctx_for_stop.cancel();
        });

        let result = self.run_body(&run_ctx).await;

        let _ = stop();
        run_ctx.cancel();
        result
    }

    async fn run_body(&self, run_ctx: &CancellationToken) -> Result<(Arc<dyn IpStack>, Option<SharedResolver>)> {
        // NOT cancel-safe: the start task it spawns keeps the permit, so a drop leaves the client
        // running until the adapter's own context is cancelled.
        let permit = tokio::select! {
            permit = Arc::clone(&self.run_lock).acquire_owned() => permit.map_err(|err| anyhow!(err))?,
            () = run_ctx.cancelled() => return Err(ContextError::Canceled.into()),
        };

        {
            let state = self.state.lock();
            if state.running {
                return match &state.tun_device {
                    Some(tun_device) => Ok((Arc::clone(tun_device), state.resolver.clone())),
                    None => Err(err_closed()),
                };
            }
        }
        if self.run_ctx.is_cancelled() {
            return Err(ContextError::Canceled.into());
        }

        if self.option.handshake_timeout > 0 {
            let self_arc = self.self_arc()?;
            #[expect(clippy::cast_sign_loss, reason = "`new` rejects a negative handshake timeout")]
            let handshake_timeout = Duration::from_secs(self.option.handshake_timeout as u64);
            let (tx, rx) = tokio::sync::oneshot::channel();
            let run_ctx_owned = self.run_ctx.clone();
            tokio::spawn(async move {
                let handshake_ctx = with_timeout_token(&run_ctx_owned, handshake_timeout);
                let result = self_arc.start_locked(&handshake_ctx).await;
                drop(permit);
                let _ = tx.send(result);
            });

            return tokio::select! {
                result = rx => result.unwrap_or_else(|_| Err(anyhow!("openvpn run task ended without a result"))),
                () = run_ctx.cancelled() => Err(ContextError::Canceled.into()),
            };
        }

        let result = self.self_arc()?.start_locked(run_ctx).await;
        drop(permit);
        result
    }

    async fn start_locked(
        self: &Arc<Self>,
        handshake_ctx: &CancellationToken,
    ) -> Result<(Arc<dyn IpStack>, Option<SharedResolver>)> {
        let packet_io =
            self.open_packet_io(handshake_ctx).await.map_err(|err| anyhow!("connect OpenVPN server: {err}"))?;
        let client = match Client::new(Arc::clone(&self.config), Arc::clone(&packet_io)) {
            Ok(client) => client,
            Err(err) => {
                let _ = packet_io.close().await;
                return Err(err);
            }
        };
        let push = match client.handshake(handshake_ctx).await {
            Ok(push) => push,
            Err(err) => {
                let _ = client.close().await;
                return Err(anyhow!("make OpenVPN handshake: {err}"));
            }
        };
        debugln!(
            "[OpenVPN]({}) handshake complete: prefixes={} routes={} peer-id={} dns={} redirect={} block-ipv6={}",
            self.base.name(),
            display_slice(&push.prefixes),
            display_slice(&push.routes),
            push.peer_id,
            display_slice(&push.dns),
            push.redirect,
            push.block_ipv6,
        );

        let mtu = if self.option.mtu == 0 { 1500 } else { self.option.mtu };
        let tun_device = match new_ip_stack(self.option.ip_stack.clone(), push.prefixes.clone(), mtu.cast_unsigned()) {
            Ok(tun_device) => tun_device,
            Err(err) => {
                let _ = client.close().await;
                return Err(anyhow!("create OpenVPN stack device: {err}"));
            }
        };
        if let Err(err) = tun_device.start().await {
            let _ = client.close().await;
            let _ = tun_device.close();
            return Err(err);
        }

        let resolver_out = {
            let mut state = self.state.lock();
            state.client = Some(Arc::clone(&client));
            state.tun_device = Some(Arc::clone(&tun_device));
            state.running = true;
            if self.option.remote_dns_resolve && !self.dns.is_empty() && state.resolver.is_none() {
                let mut nss = self.dns.clone();
                let self_as_adapter = self.self_arc()?;
                for ns in &mut nss {
                    let adapter = Arc::clone(&self_as_adapter);
                    let adapter: Arc<dyn ProxyAdapter> = adapter;
                    ns.proxy_adapter = Some(adapter);
                }
                let resolvers = Resolvers::new(DnsConfig {
                    main: nss,
                    ipv6: open_vpn_prefixes_has6(&push.prefixes),
                    fallback: Vec::new(),
                    default: Vec::new(),
                    proxy_server: Vec::new(),
                    direct_server: Vec::new(),
                    direct_follow_policy: false,
                    ipv6_timeout: 0,
                    fallback_ip_filter: Vec::new(),
                    fallback_domain_filter: Vec::new(),
                    fallback_lazy_query: false,
                    policy: Vec::new(),
                    proxy_server_policy: Vec::new(),
                    cache_algorithm: String::new(),
                    cache_max_size: 0,
                });
                let resolver: SharedResolver = Arc::new(resolvers.resolver);
                state.resolver = Some(resolver);
            }
            state.resolver.clone()
        };

        self.start_packet_loops(&client, &tun_device);
        Ok((tun_device, resolver_out))
    }

    async fn open_packet_io(&self, ctx: &CancellationToken) -> Result<Arc<dyn PacketIO>> {
        let dialer =
            self.base.dialer.clone().ok_or_else(|| anyhow!("OpenVPN.base.dialer must be set before openPacketIO"))?;
        let direct_dial =
            self.option.basic_option.dialer_for_api.is_none() && self.option.basic_option.dialer_proxy.is_empty();
        match self.config.proto.as_str() {
            PROTO_UDP => {
                let stream = dialer.dial_context(ctx, "udp", &self.base.addr()).await?;
                Ok(Arc::from(if direct_dial {
                    new_datagram_packet_io_recoverable(stream)
                } else {
                    new_datagram_packet_io(stream)
                }))
            }
            PROTO_TCP => {
                let stream = dialer.dial_context(ctx, "tcp", &self.base.addr()).await?;
                Ok(Arc::from(new_tcp_packet_io(stream)))
            }
            proto => Err(anyhow!("unsupported openvpn proto {proto:?}")),
        }
    }

    fn start_packet_loops(self: &Arc<Self>, client: &Arc<Client>, tun_device: &Arc<dyn IpStack>) {
        let run_ctx = self.run_ctx.child_token();
        let stop = PacketLoopStop {
            openvpn: Arc::clone(self),
            run_ctx: run_ctx.clone(),
            client: Arc::clone(client),
            tun_device: Arc::clone(tun_device),
            once: Arc::new(OnceCell::new()),
        };
        let name = self.base.name();
        spawn_stack_reader(&run_ctx, client, tun_device, &stop, &name);
        spawn_link_reader(&run_ctx, client, tun_device, &stop, &name);
        if self.config.ping_interval > 0 {
            spawn_ping_loop(&run_ctx, client, &stop, &name, self.config.ping_interval);
        }
        if self.config.ping_restart > 0 {
            spawn_ping_restart_loop(&run_ctx, client, &stop, &name, self.config.ping_restart);
        }
    }
}

fn spawn_stack_reader(
    run_ctx: &CancellationToken,
    client: &Arc<Client>,
    tun_device: &Arc<dyn IpStack>,
    stop: &PacketLoopStop,
    name: &str,
) {
    let run_ctx = run_ctx.clone();
    let client = Arc::clone(client);
    let tun_device = Arc::clone(tun_device);
    let stop = stop.clone();
    let name = name.to_owned();
    tokio::spawn(async move {
        let mut bufs = vec![vec![0u8; 64 * 1024]];
        let mut sizes = vec![0usize];
        while !run_ctx.is_cancelled() {
            if let Err(err) = tun_device.read(&mut bufs, &mut sizes, 0) {
                if !run_ctx.is_cancelled() && !is_err_net_closed(&err) && !is_os_closed(&err) {
                    errorln!("[OpenVPN]({name}) error reading from stack device: {err}");
                }
                break;
            }
            let packet = bufs.first().zip(sizes.first()).and_then(|(buf, size)| buf.get(..*size));
            let Some(packet) = packet else {
                break;
            };
            if let Err(err) = client.write_ip_packet(&run_ctx, packet).await {
                if !is_context_canceled(&err) && !is_err_net_closed(&err) {
                    warnln!("[OpenVPN]({name}) error writing packet to OpenVPN link: {err}");
                }
                break;
            }
        }
        stop.stop().await;
    });
}

fn spawn_link_reader(
    run_ctx: &CancellationToken,
    client: &Arc<Client>,
    tun_device: &Arc<dyn IpStack>,
    stop: &PacketLoopStop,
    name: &str,
) {
    let run_ctx = run_ctx.clone();
    let client = Arc::clone(client);
    let tun_device = Arc::clone(tun_device);
    let stop = stop.clone();
    let name = name.to_owned();
    tokio::spawn(async move {
        while !run_ctx.is_cancelled() {
            let packet = match client.read_ip_packet(&run_ctx).await {
                Ok(packet) => packet,
                Err(err) => {
                    if !run_ctx.is_cancelled() && (is_err_net_closed(&err) || is_os_closed(&err)) {
                        warnln!("[OpenVPN]({name}) OpenVPN link closed while reading packet: {err}");
                    } else if !is_context_canceled(&err) && !is_err_net_closed(&err) && !is_os_closed(&err) {
                        warnln!("[OpenVPN]({name}) error reading packet from OpenVPN link: {err}");
                    }
                    break;
                }
            };
            if let Err(err) = tun_device.write(&[packet], 0) {
                if !is_err_net_closed(&err) {
                    errorln!("[OpenVPN]({name}) error writing to stack device: {err}");
                }
                break;
            }
        }
        stop.stop().await;
    });
}

fn spawn_ping_loop(
    run_ctx: &CancellationToken,
    client: &Arc<Client>,
    stop: &PacketLoopStop,
    name: &str,
    ping_interval_nanos: i64,
) {
    let run_ctx = run_ctx.clone();
    let client = Arc::clone(client);
    let stop = stop.clone();
    let name = name.to_owned();
    let ping_interval = murmur_common::time::duration_from_nanos(ping_interval_nanos);
    tokio::spawn(async move {
        let mut ticker = keepalive_ticker(ping_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        while !run_ctx.is_cancelled() {
            tokio::select! {
                _ = ticker.tick() => {
                    let since_send = client.since_send();
                    if since_send >= ping_interval_nanos {
                        if let Err(err) = client.write_ping(&run_ctx).await {
                            if !is_context_canceled(&err) && !is_err_net_closed(&err) {
                                warnln!("[OpenVPN]({name}) error writing ping packet: {err}");
                            }
                            break;
                        }
                        let rounded = round_duration_to_seconds(murmur_common::time::duration_from_nanos(since_send));
                        debugln!("[OpenVPN]({name}) sent ping packet after {rounded:?} idle");
                    }
                }
                () = run_ctx.cancelled() => break,
            }
        }
        stop.stop().await;
    });
}

fn spawn_ping_restart_loop(
    run_ctx: &CancellationToken,
    client: &Arc<Client>,
    stop: &PacketLoopStop,
    name: &str,
    ping_restart_nanos: i64,
) {
    let run_ctx = run_ctx.clone();
    let client = Arc::clone(client);
    let stop = stop.clone();
    let name = name.to_owned();
    let ping_restart = murmur_common::time::duration_from_nanos(ping_restart_nanos);
    tokio::spawn(async move {
        let mut ticker = keepalive_ticker(ping_restart);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        while !run_ctx.is_cancelled() {
            tokio::select! {
                _ = ticker.tick() => {
                    let since_receive = client.since_receive();
                    if since_receive >= ping_restart_nanos {
                        let rounded =
                            round_duration_to_seconds(murmur_common::time::duration_from_nanos(since_receive));
                        warnln!("[OpenVPN]({name}) ping-restart timeout: no packet received for {rounded:?}");
                        break;
                    }
                }
                () = run_ctx.cancelled() => break,
            }
        }
        stop.stop().await;
    });
}

impl OpenVPN {
    async fn resolve_udp_inner(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
        r: Option<SharedResolver>,
    ) -> Result<()> {
        if (!metadata.resolved() || r.is_some()) && !metadata.host.is_empty() {
            let r = r.or_else(default_resolver);
            let ip = resolve_ip_with_resolver(ctx, &metadata.host, self.base.prefer, r.as_deref())
                .await
                .map_err(|err| anyhow!("can't resolve ip: {err}"))?;
            metadata.dst_ip = Some(ip);
        }
        Ok(())
    }
}

/// The `stop` closure captured by the four packet loops, sharing one `OnceCell`.
#[derive(Clone)]
struct PacketLoopStop {
    openvpn: Arc<OpenVPN>,
    run_ctx: CancellationToken,
    client: Arc<Client>,
    tun_device: Arc<dyn IpStack>,
    once: Arc<OnceCell<()>>,
}

impl PacketLoopStop {
    async fn stop(&self) {
        self.once
            .get_or_init(|| async {
                self.run_ctx.cancel();
                let _ = self.client.close().await;
                let _ = self.tun_device.close();
                let permit = Arc::clone(&self.openvpn.run_lock).acquire_owned().await.ok();
                {
                    let mut state = self.openvpn.state.lock();
                    if state.client.as_ref().is_some_and(|current| Arc::ptr_eq(current, &self.client)) {
                        state.client = None;
                        state.tun_device = None;
                        state.running = false;
                    }
                }
                drop(permit);
            })
            .await;
    }
}

#[async_trait]
impl CProxyAdapter for OpenVPN {
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

    /// A null-conn check after a successful dial — defensive against a null-interface conn — has no
    /// counterpart: `Box<dyn Conn>` cannot be null in Rust, so that branch is unreachable here and
    /// is dropped.
    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let (tun_device, mut r) = self.run(ctx).await?;
        let conn: Box<dyn murmur_std_compat::net::Conn> = if !metadata.resolved() || r.is_some() {
            if r.is_none() {
                r = default_resolver();
            }
            let mut options = self.base.dial_options();
            options.push(with_resolver(r.clone()));
            options.push(with_net_dialer(Arc::new(IpStackNetDialer { stack: Arc::clone(&tun_device) })));
            let stream = new_dialer(options).dial_context(ctx, "tcp", &metadata.remote_address()).await?;
            // S11: remove with std-compat (unifies with the tun_device.dial_tcp branch below; util::ip_stack::IpStack still murmur_std_compat::net::Conn based)
            Box::new(murmur_common_net::io::StreamAsOldConn::new(stream))
        } else {
            let destination = metadata
                .addr_port()
                .ok_or_else(|| anyhow!("metadata.dst_ip must be set once Resolved() reports true"))?;
            tun_device.dial_tcp(ctx, "tcp", unspecified_addr(), destination).await?
        };
        // S11: remove with std-compat (util::ip_stack::IpStack still murmur_std_compat::net::Conn based)
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(conn)), self))
    }

    /// See `dial_context` for the dropped null-`pc` check.
    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        let (tun_device, r) = self.run(ctx).await?;
        self.resolve_udp_inner(ctx, metadata, r).await?;
        let pc = tun_device.listen_udp(ctx, "udp", unspecified_addr()).await?;
        // S11: remove with std-compat (util::ip_stack::IpStack still murmur_std_compat::net::PacketConn based)
        Ok(new_packet_conn(Arc::new(murmur_common_net::io::OldPacketConnAsDatagram(pc)), self.self_arc()?))
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
        self.run_ctx.cancel();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let permit = Arc::clone(&self.run_lock).acquire_owned().await.ok();
                let (client, tun_device) = {
                    let mut state = self.state.lock();
                    let client = state.client.take();
                    let tun_device = state.tun_device.take();
                    state.running = false;
                    drop(state);
                    (client, tun_device)
                };
                drop(permit);

                if let Some(client) = client {
                    let _ = client.close().await;
                }
                if let Some(tun_device) = tun_device {
                    return tun_device.close();
                }
                Ok(())
            })
        })
    }
}

#[async_trait]
impl ProxyAdapter for OpenVPN {
    fn dial_options(&self) -> Vec<DialerOption> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        let (_, r) = self.run(ctx).await?;
        self.resolve_udp_inner(ctx, metadata, r).await
    }
}

pub(crate) fn open_vpn_prefixes_has6(prefixes: &[IpNet]) -> bool {
    prefixes.iter().any(|prefix| match prefix.addr() {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_none(),
    })
}

const fn unspecified_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

fn err_closed() -> anyhow::Error {
    anyhow!("use of closed network connection")
}

fn is_context_canceled(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| matches!(cause.downcast_ref::<ContextError>(), Some(ContextError::Canceled)))
}

fn is_os_closed(err: &anyhow::Error) -> bool {
    error_is::<ErrOsClosed>(err)
}

/// Bracketed, space-separated rendering of a slice's `Display` elements.
fn display_slice<T: std::fmt::Display>(items: &[T]) -> String {
    let mut out = String::from("[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&item.to_string());
    }
    out.push(']');
    out
}

/// The keep-alive ticker: the first tick arrives after one full period. `tokio::time::interval`
/// fires its first tick at once, which ran one ping / ping-restart pass too early.
fn keepalive_ticker(period: Duration) -> tokio::time::Interval {
    tokio::time::interval_at(tokio::time::Instant::now() + period, period)
}

fn round_duration_to_seconds(d: Duration) -> Duration {
    const SEC_NANOS: u128 = 1_000_000_000;
    let nanos = d.as_nanos();
    let rounded = ((nanos + SEC_NANOS / 2) / SEC_NANOS) * SEC_NANOS;
    Duration::from_nanos(u64::try_from(rounded.min(u128::from(u64::MAX))).unwrap_or(u64::MAX))
}

fn with_timeout_token(parent: &CancellationToken, dur: Duration) -> CancellationToken {
    let child = parent.child_token();
    let sleeper = child.clone();
    tokio::spawn(async move {
        tokio::select! {
            () = tokio::time::sleep(dur) => sleeper.cancel(),
            () = sleeper.cancelled() => {}
        }
    });
    child
}

/// Assigned by the config layer's init.
fn parse_name_server(servers: &[String]) -> Result<Vec<NameServer>> {
    let f = PARSE_NAME_SERVER
        .get()
        .ok_or_else(|| anyhow!("dns::resolver::PARSE_NAME_SERVER must be set before ParseNameServer is called"))?;
    f(servers)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::Ipv4Addr;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::UdpSocket;

    use murmur_common_net::io::{Datagram, Stream};
    use murmur_constant::adapters::Dialer as CDialer;
    use murmur_transport_openvpn::packetio::ERR_PACKET_DROPPED;

    use super::*;

    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    fn test_option(server_port: u16) -> OpenVPNOption {
        OpenVPNOption {
            server: Ipv4Addr::LOCALHOST.to_string(),
            port: i32::from(server_port),
            proto: "udp".to_owned(),
            ca: TEST_CA_PEM.to_owned(),
            username: "user".to_owned(),
            ..Default::default()
        }
    }

    /// An oversized UDP datagram triggers a real `EMSGSIZE`/"Message too long" from the kernel on
    /// the physical write, exercising the same classification path the syscall-conn check used to
    /// gate.
    fn oversized_datagram() -> Vec<u8> {
        vec![0u8; 70_000]
    }

    /// A raw connected UDP `Stream`, standing in for `component::dialer::control::ConnectedUdpConn`
    /// (not constructible outside its crate) so the direct-dial path here still exercises a real
    /// OS socket.
    struct RawUdpStream(UdpSocket);

    impl AsyncRead for RawUdpStream {
        fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            self.get_mut().0.poll_recv(cx, buf)
        }
    }

    impl AsyncWrite for RawUdpStream {
        fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.get_mut().0.poll_send(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for RawUdpStream {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.0.local_addr()
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.0.peer_addr()
        }
    }

    /// Stands in for a `dialer-proxy` chain: the packet conn embeds no syscall conn, so the
    /// datagram packet IO's syscall-conn assertion is false and physical write errors stay fatal.
    struct ProxiedUdpDialer;

    #[async_trait]
    impl CDialer for ProxiedUdpDialer {
        async fn dial_context(
            &self,
            _ctx: &CancellationToken,
            _network: &str,
            address: &str,
        ) -> Result<Box<dyn Stream>> {
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
            socket.connect(address).await?;
            Ok(Box::new(RawUdpStream(socket)))
        }

        async fn listen_packet(
            &self,
            _ctx: &CancellationToken,
            _network: &str,
            _address: &str,
            _r_addr_port: Option<SocketAddr>,
        ) -> Result<Box<dyn Datagram>> {
            unreachable!("not exercised by this test")
        }
    }

    /// Both keep-alive tickers are armed so that the first tick lands one full period after the
    /// ticker is built. An immediate tick instead sent a ping for an idle counter that was never
    /// awaited, and ran the ping-restart check, which must only run once the timeout has actually
    /// elapsed.
    #[tokio::test(start_paused = true)]
    async fn keepalive_tickers_first_tick_waits_one_period() {
        for period in [Duration::from_secs(5), Duration::from_secs(10)] {
            let start = tokio::time::Instant::now();
            let mut ticker = keepalive_ticker(period);

            ticker.tick().await;
            assert_eq!(tokio::time::Instant::now() - start, period, "first tick fired before one full period elapsed");

            ticker.tick().await;
            assert_eq!(tokio::time::Instant::now() - start, period * 2, "second tick must follow one period later");
        }
    }

    #[tokio::test]
    async fn direct_udp_dial_classifies_emsgsize_as_packet_dropped() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind udp server");
        let server_addr = server.local_addr().expect("server addr");

        let openvpn = OpenVPN::new(test_option(server_addr.port())).expect("construct direct openvpn adapter");
        let packet_io = openvpn.open_packet_io(&CancellationToken::new()).await.expect("open direct packet io");

        let err = packet_io.write_packet(&oversized_datagram()).await.expect_err("oversized udp write must fail");
        assert!(
            err.to_string().contains(ERR_PACKET_DROPPED),
            "direct dial classified a real UDP EMSGSIZE as fatal instead of packet-dropped: {err}"
        );
    }

    #[tokio::test]
    async fn proxied_udp_dial_classifies_emsgsize_as_fatal() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind udp server");
        let server_addr = server.local_addr().expect("server addr");

        let mut option = test_option(server_addr.port());
        option.basic_option.dialer_for_api = Some(Arc::new(ProxiedUdpDialer));
        let openvpn = OpenVPN::new(option).expect("construct proxied openvpn adapter");
        let packet_io = openvpn.open_packet_io(&CancellationToken::new()).await.expect("open proxied packet io");

        let err = packet_io.write_packet(&oversized_datagram()).await.expect_err("oversized udp write must fail");
        assert!(
            !err.to_string().contains(ERR_PACKET_DROPPED),
            "proxied dial wrongly classified a fatal EMSGSIZE as packet-dropped: {err}"
        );
    }
}

//! The wireguard outbound: murmur's dialer, a WireGuard device and a userspace IP stack.
//!
//! Three things are wired together here: murmur's own dialer (so `interface`, `routing-mark` and
//! `dialer-proxy` apply to the tunnel's own UDP), a WireGuard device, and a userspace IP stack in
//! front of it. The device and the stack are `murmur_component_wireguard`; what stays here is the
//! option struct, the IPC-config generation, the lazy `init` and the dial/listen paths.
//!
//! Two features are unsupported and both fail closed with a named reason instead of running
//! something weaker under the same name: `amnezia-wg-option` needs AmneziaWG's own device, and
//! `remote-dns-resolve` needs a resolver whose nameserver traffic is dialed back through
//! this adapter, which the IP stack itself does not provide. `dns` is only read when
//! `remote-dns-resolve` is set, so with that option refused the `dns` list is inert here.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use base64::Engine as _;
use ipnet::IpNet;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::Stream;
use murmur_component::dialer::dialer::{new_dialer, Dialer};
use murmur_component::dialer::options::{with_net_dialer, with_resolver, NetDialer, Option as DialerOption};
use murmur_component::resolver::resolver::default_resolver;
use murmur_component_wireguard::bind::{Bind, ConnectedBind, DatagramBind, ReservedBind};
use murmur_component_wireguard::device::{Device, DeviceConfig, PeerConfig};
use murmur_component_wireguard::keys::{PresharedKey, PublicKey, StaticKey};
use murmur_component_wireguard::stack::{Stack, StackConfig};
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::dns::DNSPrefer;
use murmur_constant::metadata::Metadata;
use murmur_log::{debugln, warnln};

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::util::ip_stack::IpStackOption;
use super::util::resolve_ip_with_resolver;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct WireGuardOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server", default)]
    pub server: String,
    #[serde(rename = "port", default)]
    pub port: u16,
    #[serde(rename = "ip", default)]
    pub ip: String,
    #[serde(rename = "ipv6", default)]
    pub ipv6: String,
    #[serde(rename = "private-key", default)]
    pub private_key: String,
    #[serde(rename = "public-key", default)]
    pub public_key: String,
    #[serde(rename = "pre-shared-key", default)]
    pub pre_shared_key: String,
    #[serde(rename = "reserved", default)]
    pub reserved: Vec<u8>,
    /// The single-peer path never reads this: the IPC config writes `0.0.0.0/0` (plus `::/0` when
    /// a local prefix is IPv6) instead, so it is decoded and then ignored.
    #[serde(rename = "allowed-ips", default)]
    pub allowed_ips: Vec<String>,
    /// The device's worker routines are sized from this; this adapter runs one task and ignores it.
    #[serde(rename = "workers", default)]
    pub workers: i32,
    #[serde(rename = "mtu", default)]
    pub mtu: i32,
    #[serde(rename = "udp", default)]
    pub udp: bool,
    #[serde(rename = "persistent-keepalive", default)]
    pub persistent_keepalive: i32,
    #[serde(rename = "ip-stack", default)]
    pub ip_stack: IpStackOption,
    #[serde(rename = "peers", default)]
    pub peers: Vec<WireGuardPeerOption>,
    #[serde(rename = "remote-dns-resolve", default)]
    pub remote_dns_resolve: bool,
    #[serde(rename = "dns", default)]
    pub dns: Vec<String>,
    #[serde(rename = "refresh-server-ip-interval", default)]
    pub refresh_server_ip_interval: i32,
    /// Only its presence matters, because the only thing this adapter can do with the block is
    /// refuse the configuration.
    #[serde(rename = "amnezia-wg-option", skip_serializing)]
    pub amnezia_wg_option: Option<serde::de::IgnoredAny>,
}

impl std::fmt::Debug for WireGuardOption {
    /// Redacts `private_key` and `pre_shared_key` so `{:?}` cannot leak key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("ip", &self.ip)
            .field("ipv6", &self.ipv6)
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .field("pre_shared_key", &"<redacted>")
            .field("reserved", &self.reserved)
            .field("allowed_ips", &self.allowed_ips)
            .field("workers", &self.workers)
            .field("mtu", &self.mtu)
            .field("udp", &self.udp)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("ip_stack", &self.ip_stack)
            .field("peers", &self.peers)
            .field("remote_dns_resolve", &self.remote_dns_resolve)
            .field("dns", &self.dns)
            .field("refresh_server_ip_interval", &self.refresh_server_ip_interval)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct WireGuardPeerOption {
    #[serde(rename = "server", default)]
    pub server: String,
    #[serde(rename = "port", default)]
    pub port: u16,
    #[serde(rename = "public-key", default)]
    pub public_key: String,
    #[serde(rename = "pre-shared-key", default)]
    pub pre_shared_key: String,
    #[serde(rename = "reserved", default)]
    pub reserved: Vec<u8>,
    #[serde(rename = "allowed-ips", default)]
    pub allowed_ips: Vec<String>,
}

impl std::fmt::Debug for WireGuardPeerOption {
    /// Redacts `pre_shared_key` so `{:?}` cannot leak key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardPeerOption")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("public_key", &self.public_key)
            .field("pre_shared_key", &"<redacted>")
            .field("reserved", &self.reserved)
            .field("allowed_ips", &self.allowed_ips)
            .finish()
    }
}

pub(crate) fn wireguard_prefixes(ip: &str, ipv6: &str) -> Result<Vec<IpNet>> {
    let mut prefixes = Vec::with_capacity(2);
    if !ip.is_empty() {
        let candidate = if ip.contains('/') { ip.to_owned() } else { format!("{ip}/32") };
        prefixes.push(candidate.parse::<IpNet>().map_err(|err| anyhow!("ip address parse error: {err}"))?);
    }
    if !ipv6.is_empty() {
        let candidate = if ipv6.contains('/') { ipv6.to_owned() } else { format!("{ipv6}/128") };
        prefixes.push(candidate.parse::<IpNet>().map_err(|err| anyhow!("ipv6 address parse error: {err}"))?);
    }
    if prefixes.is_empty() {
        bail!("missing local address");
    }
    Ok(prefixes)
}

/// Standard base64 decoding followed by hex encoding, which the UAPI configuration carries
/// instead of the base64 the YAML has.
fn decode_key(what: &str, value: &str) -> Result<[u8; 32]> {
    let bytes =
        base64::engine::general_purpose::STANDARD.decode(value).map_err(|err| anyhow!("decode {what}: {err}"))?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| anyhow!("decode {what}: key must be 32 bytes, got {len}"))
}

struct WgPeer {
    server: String,
    port: u16,
    public_key: PublicKey,
    preshared_key: PresharedKey,
    reserved: [u8; 3],
    allowed_ips: Vec<IpNet>,
}

struct WgState {
    device: Arc<Device>,
    stack: Arc<Stack>,
}

pub struct WireGuard {
    self_weak: Weak<Self>,
    base: Base,
    dialer: Dialer,
    option: WireGuardOption,
    prefixes: Vec<IpNet>,
    peers: Vec<WgPeer>,
    private_key: StaticKey,
    /// The connect mode: with fewer than two peers the bind dials one endpoint.
    is_connect: bool,
    reserved: [u8; 3],
    mtu: u16,
    keepalive: u16,
    server_addr_time: Mutex<Option<std::time::Instant>>,
    start: OnceCell<Arc<WgState>>,
    ctx: CancellationToken,
    up: AtomicBool,
}

impl std::fmt::Debug for WireGuard {
    /// Redacts the static key and the option block, which carry key material and credentials.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuard")
            .field("name", &self.base.name())
            .field("addr", &self.base.addr())
            .field("option", &self.option)
            .field("prefixes", &self.prefixes)
            .field("peers", &self.peers.len())
            .field("is_connect", &self.is_connect)
            .field("reserved", &self.reserved)
            .field("mtu", &self.mtu)
            .field("keepalive", &self.keepalive)
            .field("private_key", &"<redacted>")
            .field("up", &self.up.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl WireGuard {
    pub fn new(mut option: WireGuardOption) -> Result<Arc<Self>> {
        if option.amnezia_wg_option.is_some() {
            bail!("amnezia-wg-option is not supported: the AmneziaWG device is not implemented");
        }
        if option.remote_dns_resolve {
            bail!("remote-dns-resolve is not supported on the wireguard outbound: no resolver is dialed back through this tunnel");
        }
        if option.persistent_keepalive < 0 {
            bail!("wireguard persistent-keepalive cannot be negative");
        }

        let reserved = match option.reserved.as_slice() {
            [] => [0u8; 3],
            [a, b, c] => [*a, *b, *c],
            other => bail!("invalid reserved value, required 3 bytes, got {}", other.len()),
        };

        let private_key = StaticKey::from_bytes(decode_key("private key", &option.private_key)?);
        let prefixes = wireguard_prefixes(&option.ip, &option.ipv6)?;

        let peers = if option.peers.is_empty() {
            vec![WgPeer {
                server: option.server.clone(),
                port: option.port,
                public_key: PublicKey::from_bytes(decode_key("peer public key", &option.public_key)?),
                preshared_key: optional_key("pre shared key", &option.pre_shared_key)?,
                reserved,
                allowed_ips: default_allowed_ips(&prefixes)?,
            }]
        } else {
            let mut peers = Vec::with_capacity(option.peers.len());
            for (index, peer) in option.peers.iter().enumerate() {
                let peer_reserved = match peer.reserved.as_slice() {
                    [] => [0u8; 3],
                    [a, b, c] => [*a, *b, *c],
                    other => {
                        bail!("invalid reserved value for peer {index}, required 3 bytes, got {}", other.len());
                    }
                };
                if peer.allowed_ips.is_empty() {
                    bail!("missing allowed_ips for peer {index}");
                }
                peers.push(WgPeer {
                    server: peer.server.clone(),
                    port: peer.port,
                    public_key: PublicKey::from_bytes(decode_key(
                        &format!("public key for peer {index}"),
                        &peer.public_key,
                    )?),
                    preshared_key: optional_key(&format!("pre shared key for peer {index}"), &peer.pre_shared_key)?,
                    reserved: peer_reserved,
                    allowed_ips: parse_allowed_ips(&peer.allowed_ips)?,
                });
            }
            peers
        };
        let is_connect = peers.len() < 2;

        option.ip_stack.normalize();
        option.ip_stack.validate()?;
        if option.ip_stack.mode == "gvisor" {
            bail!(
                "wireguard ip-stack mode \"gvisor\" is not supported: the sing-wireguard stack device is not implemented"
            );
        }

        let mtu = match option.mtu {
            0 => 1408,
            value => u16::try_from(value).map_err(|_| anyhow!("wireguard mtu {value} does not fit in 16 bits"))?,
        };
        let keepalive = u16::try_from(option.persistent_keepalive).unwrap_or_default();

        let base = Base::new(BaseOption {
            name: option.name.clone(),
            addr: format!("{}:{}", option.server, option.port),
            type_: AdapterType::WIRE_GUARD,
            provider_name: option.basic_option.provider_name.clone(),
            udp: option.udp,
            xudp: false,
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
        });
        let dialer = new_dialer(base.dial_options());

        Ok(Arc::new_cyclic(|self_weak| Self {
            self_weak: Weak::clone(self_weak),
            base,
            dialer,
            option,
            prefixes,
            peers,
            private_key,
            is_connect,
            reserved,
            mtu,
            keepalive,
            server_addr_time: Mutex::new(None),
            start: OnceCell::new(),
            ctx: CancellationToken::new(),
            up: AtomicBool::new(false),
        }))
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("WireGuard adapter dropped while still in use"))
    }

    /// Initializes the device and refreshes the server address.
    async fn init(&self) -> Result<Arc<WgState>> {
        let this = self.self_arc()?;
        let state = Arc::clone(this.start.get_or_try_init(|| this.init0()).await?);
        this.update_server_addr(&state).await;
        Ok(state)
    }

    /// resolve every peer, open the bind, build the device, then the
    /// stack in front of it. A resolve failure is not latched, so the next dial retries it.
    async fn init0(self: &Arc<Self>) -> Result<Arc<WgState>> {
        let endpoints = self.resolve_endpoints().await?;
        let bind = self.open_bind(endpoints.first().copied().flatten()).await?;
        let configs = self.peer_configs(&endpoints);
        for (peer, config) in self.peers.iter().zip(&configs) {
            if peer.reserved != [0u8; 3] {
                if let Some(endpoint) = config.endpoint {
                    bind.set_reserved_for_endpoint(endpoint, peer.reserved);
                }
            }
        }

        let (device, tun) = Device::new(
            self.base.name(),
            Arc::clone(&bind),
            DeviceConfig { private_key: self.private_key.clone(), peers: configs, mtu: self.mtu },
        )?;
        let stack = Stack::new(StackConfig { local_addresses: self.prefixes.clone(), mtu: self.mtu }, tun)?;
        self.up.store(true, Ordering::Relaxed);
        *self.server_addr_time.lock() = Some(std::time::Instant::now());
        debugln!("[WireGuard]({}) tunnel up", self.base.name());
        Ok(Arc::new(WgState { device, stack }))
    }

    /// Resolves every peer endpoint: an address literal is used as is, a name goes through the
    /// system resolver.
    async fn resolve_endpoints(&self) -> Result<Vec<Option<SocketAddr>>> {
        let prefer = self.base.prefer;
        let mut endpoints = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            endpoints.push(if peer.server.is_empty() {
                None
            } else {
                Some(SocketAddr::new(resolve_endpoint(&peer.server, prefer).await?, peer.port))
            });
        }
        Ok(endpoints)
    }

    /// The peer block of the IPC config, with the endpoints this call resolved.
    fn peer_configs(&self, endpoints: &[Option<SocketAddr>]) -> Vec<PeerConfig> {
        self.peers
            .iter()
            .zip(endpoints)
            .map(|(peer, endpoint)| PeerConfig {
                public_key: peer.public_key,
                preshared_key: peer.preshared_key,
                endpoint: *endpoint,
                allowed_ips: peer.allowed_ips.clone(),
                persistent_keepalive: self.keepalive,
            })
            .collect()
    }

    /// The client bind and its lazy connect are performed up front so the dialer's connected socket
    /// exists before the device can send on it.
    async fn open_bind(&self, connect_addr: Option<SocketAddr>) -> Result<Arc<ReservedBind>> {
        let inner: Arc<dyn Bind> = if self.is_connect {
            let endpoint =
                connect_addr.ok_or_else(|| anyhow!("wireguard connect mode needs a resolved peer endpoint"))?;
            let stream = self.dialer.dial_context(&self.ctx, "udp", &endpoint.to_string()).await?;
            Arc::new(ConnectedBind::new(stream, endpoint)?)
        } else {
            let datagram = self.dialer.listen_packet(&self.ctx, "udp", "0.0.0.0:0", None).await?;
            Arc::new(DatagramBind::new(datagram))
        };
        Ok(Arc::new(ReservedBind::new(inner, self.reserved)))
    }

    /// re-resolve the endpoints on the configured
    /// interval and push the new addresses into the device.
    async fn update_server_addr(&self, state: &Arc<WgState>) {
        if self.option.refresh_server_ip_interval == 0 {
            return;
        }
        #[expect(
            clippy::cast_sign_loss,
            reason = "a negative refresh interval is not rejected by the option loader, so the widening cast keeps the duration that is compared against"
        )]
        let interval = Duration::from_secs(self.option.refresh_server_ip_interval as u64);
        if self.server_addr_time.lock().is_some_and(|last| last.elapsed() <= interval) {
            return;
        }
        let Ok(endpoints) = self.resolve_endpoints().await else {
            warnln!("[WireGuard]({}) update server address: resolve failed", self.base.name());
            return;
        };
        if let Err(err) = state.device.update_peers(self.peer_configs(&endpoints)).await {
            warnln!("[WireGuard]({}) update server address: {err}", self.base.name());
            return;
        }
        *self.server_addr_time.lock() = Some(std::time::Instant::now());
    }
}

/// The stack-backed dialer: an unresolved destination is resolved by murmur and the TCP connection
/// is still opened through this tunnel, as the dial requires. A local
/// `NetDialer` rather than `util::ip_stack::IpStackNetDialer` because this adapter dials the
/// concrete stack it built over its own WireGuard device, not a `new_ip_stack` stack.
struct TunNetDialer(Arc<Stack>);

#[async_trait]
impl NetDialer for TunNetDialer {
    async fn dial_context(&self, _ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn Stream>> {
        let destination: SocketAddr = address.parse().map_err(|err| anyhow!("invalid address {address:?}: {err}"))?;
        if !network.starts_with("tcp") {
            bail!("invalid network {network:?}");
        }
        Ok(Box::new(self.0.dial_tcp(None, destination).await?))
    }
}

#[async_trait]
impl CProxyAdapter for WireGuard {
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

    /// A null-conn check cannot exist here: a boxed trait object is never null.
    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let state = self.init().await?;
        let conn: Box<dyn Stream> = if metadata.resolved() {
            let destination = metadata
                .addr_port()
                .ok_or_else(|| anyhow!("metadata must carry a destination address once Resolved() reports true"))?;
            Box::new(state.stack.dial_tcp(None, destination).await?)
        } else {
            let mut options = self.base.dial_options();
            options.push(with_resolver(default_resolver()));
            options.push(with_net_dialer(Arc::new(TunNetDialer(Arc::clone(&state.stack)))));
            new_dialer(options).dial_context(ctx, "tcp", &metadata.remote_address()).await?
        };
        Ok(new_conn(conn, self))
    }

    /// The null-`pc` check is dropped for the same reason as the one above.
    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        let state = self.init().await?;
        self.resolve_udp(ctx, metadata).await?;
        let packet_conn = state.stack.listen_udp(None).await?;
        Ok(new_packet_conn(Arc::new(packet_conn), self.self_arc()?))
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
        self.up.store(false, Ordering::Relaxed);
        self.ctx.cancel();
        if let Some(state) = self.start.get() {
            state.stack.close();
            let _ = state.device.close();
        }
        Ok(())
    }
}

#[async_trait]
impl ProxyAdapter for WireGuard {
    fn dial_options(&self) -> Vec<DialerOption> {
        self.base.dial_options()
    }

    /// A dedicated resolver would also be consulted, but it is only built when
    /// `remote-dns-resolve` is set, and that option is refused above.
    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        if !metadata.resolved() && !metadata.host.is_empty() {
            let ip = resolve_ip_with_resolver(ctx, &metadata.host, self.base.prefer, default_resolver().as_deref())
                .await
                .map_err(|err| anyhow!("can't resolve ip: {err}"))?;
            metadata.dst_ip = Some(ip);
        }
        Ok(())
    }
}

fn optional_key(what: &str, value: &str) -> Result<PresharedKey> {
    if value.is_empty() {
        return Ok(PresharedKey::zeroed());
    }
    Ok(PresharedKey::from_bytes(decode_key(what, value)?))
}

fn parse_allowed_ips(values: &[String]) -> Result<Vec<IpNet>> {
    values
        .iter()
        .map(|value| value.parse::<IpNet>().map_err(|err| anyhow!("parse allowed ip {value:?}: {err}")))
        .collect()
}

/// The single-peer `allowed_ip` lines of the IPC config: one default route per family the local
/// prefixes hold.
fn default_allowed_ips(prefixes: &[IpNet]) -> Result<Vec<IpNet>> {
    let mut has4 = false;
    let mut has6 = false;
    for prefix in prefixes {
        match prefix.addr() {
            IpAddr::V4(_) => has4 = true,
            IpAddr::V6(address) => {
                if address.to_ipv4_mapped().is_none() {
                    has6 = true;
                }
            }
        }
    }
    let mut allowed = Vec::with_capacity(usize::from(has4) + usize::from(has6));
    for (wanted, route) in [(has4, "0.0.0.0/0"), (has6, "::/0")] {
        if !wanted {
            continue;
        }
        match route.parse::<IpNet>() {
            Ok(prefix) => allowed.push(prefix),
            Err(err) => bail!("{route} is a literal prefix: {err}"),
        }
    }
    Ok(allowed)
}

async fn resolve_endpoint(server: &str, prefer: DNSPrefer) -> Result<IpAddr> {
    if let Ok(address) = server.parse::<IpAddr>() {
        return Ok(address);
    }
    resolve_ip_with_resolver(&CancellationToken::new(), server, prefer, default_resolver().as_deref()).await
}

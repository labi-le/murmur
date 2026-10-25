//! `Masque::dial_quic` dials `quinn` directly rather than bridging the tuic QUIC mirror.
//!
//! `transport/tuic/common::dial_quic` returns a local structural mirror of a QUIC connection, not
//! a real `quinn::Connection`; `transport/masque::l4proxy::L4Client` and
//! `transport/masque::masque::ConnectTunnel` both require a real `quinn::Connection`. No bridge
//! between the two exists anywhere in the tree (checked `transport/tuic/*` and
//! `transport/hysteria/*`), so `Masque::dial_quic` dials directly against `quinn`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use futures::future::BoxFuture;
use ipnet::IpNet;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use crate::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use crate::util::ip_stack::{new_ip_stack, IpStack, IpStackNetDialer, IpStackOption};
use crate::util::{resolve_ip_with_resolver, resolve_udp_addr};
use murmur_common::atomic::type_::{new_bool, Bool};
use murmur_common::contextutils::after_func;
use murmur_common_pool as pool;
use murmur_component::dialer::dialer::new_dialer;
use murmur_component::dialer::options::{with_net_dialer, with_resolver, NetDialer, Option as DialerOption};
use murmur_component::resolver::resolver::{default_resolver, SharedResolver};
use murmur_constant::adapters::AdapterType;
use murmur_constant::adapters::{
    Conn as CConn, Dialer as CDialer, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_dns::resolver::{Config as DnsResolverConfig, Resolvers, PARSE_NAME_SERVER};
use murmur_log::{errorln, warnln};
use murmur_std_compat::net::{Addr, Conn, PacketConn, UdpAddr};
use murmur_transport_masque::client_h2::{self, DialTlsFn, H2Transport, Http2Config};
use murmur_transport_masque::l4proxy::{DialQuicFn, L4Client, L4_CONNECT_SNI};
use murmur_transport_masque::masque::{
    self as masque_transport, context_canceled, prepare_tls_config, EcdsaPrivateKey, EcdsaPublicKey, IpConn, TlsConfig,
    CONNECT_SNI, CONNECT_URI,
};

/// The congestion senders take a connection type this file no longer dials, and quinn only accepts
/// a congestion controller factory at `TransportConfig` build time (no post-handshake swap). The
/// closest behaviour-preserving equivalent is quinn's own built-in controllers, selected before
/// dialing instead of after and pinned to the same initial-window byte counts the senders compute;
/// `bbr_profile` has no quinn equivalent and is unused.
///
/// The initial packet size for masque, which the TUIC congestion modules both read back verbatim
/// as their datagram-size input for `cubic`/`new_reno`/`bbr`/`bbr_meta_v2` and for the untouched
/// default sender (fed the same field when the client connection is built).
const MASQUE_INITIAL_PACKET_SIZE: u64 = 1242;

/// The fixed multiplier the `bbr_meta_v1` sender construction uses instead of the connection's
/// actual initial packet size.
const BBR_V1_INITIAL_PACKET_SIZE: u64 = 1280;

/// The `if cwnd == 0 { cwnd = 32 }` default; also the initial congestion window both the default
/// sender and its `cubic`/`new_reno` arms start from, which is why they land on the same initial
/// window as `bbr` with `cwnd` omitted.
const DEFAULT_CWND_PACKETS: u64 = 32;

/// The congestion-controller match, parsed once instead of re-matched per dial. `Unset` is the
/// missing default arm (empty/unrecognized `congestion-controller`), where the default sender is
/// left untouched. `BbrMetaV1` is split from `Bbr` because `cwnd` is multiplied by a different
/// constant for each (`BBR_V1_INITIAL_PACKET_SIZE` vs `MASQUE_INITIAL_PACKET_SIZE`). The YAML
/// spelling of `congestion-controller` is unaffected.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum CongestionController {
    #[default]
    Unset,
    Cubic,
    NewReno,
    Bbr,
    BbrMetaV1,
}

impl CongestionController {
    fn parse(value: &str) -> Self {
        match value {
            "cubic" => Self::Cubic,
            "new_reno" => Self::NewReno,
            "bbr_meta_v1" => Self::BbrMetaV1,
            "bbr_meta_v2" | "bbr" => Self::Bbr,
            _ => Self::Unset,
        }
    }
}

/// The congestion-controller selection. `Unset`, `Cubic` and `NewReno` all ignore `cwnd` and land
/// on `DEFAULT_CWND_PACKETS * MASQUE_INITIAL_PACKET_SIZE`: `cubic`/`new_reno` because the cubic
/// sender takes no `cwnd` argument at all, and the untouched default for the same reason. `Unset`
/// builds the Reno variant of that sender: the untouched default sender is the same sender with
/// Reno enabled. `Bbr` and `BbrMetaV1` use `cwnd`, defaulting to `DEFAULT_CWND_PACKETS` when it is
/// 0, each times its own packet-size constant. A negative `cwnd`, which the documented behaviour
/// passes through as a negative window, is also treated as 0 here.
fn congestion_controller_factory(
    cc: CongestionController,
    cwnd: i32,
) -> Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> {
    let cwnd_packets = if cwnd > 0 { u64::from(cwnd.cast_unsigned()) } else { DEFAULT_CWND_PACKETS };
    match cc {
        CongestionController::Cubic => {
            let mut cfg = quinn::congestion::CubicConfig::default();
            cfg.initial_window(DEFAULT_CWND_PACKETS * MASQUE_INITIAL_PACKET_SIZE);
            Arc::new(cfg)
        }
        CongestionController::Unset | CongestionController::NewReno => {
            let mut cfg = quinn::congestion::NewRenoConfig::default();
            cfg.initial_window(DEFAULT_CWND_PACKETS * MASQUE_INITIAL_PACKET_SIZE);
            Arc::new(cfg)
        }
        CongestionController::Bbr => {
            let mut cfg = quinn::congestion::BbrConfig::default();
            cfg.initial_window(cwnd_packets * MASQUE_INITIAL_PACKET_SIZE);
            Arc::new(cfg)
        }
        CongestionController::BbrMetaV1 => {
            let mut cfg = quinn::congestion::BbrConfig::default();
            cfg.initial_window(cwnd_packets * BBR_V1_INITIAL_PACKET_SIZE);
            Arc::new(cfg)
        }
    }
}

/// The closed-connection/closed-pipe check. `IpConn`'s methods return `anyhow::Error`, so the
/// closest equivalent inspects the wrapped `io::Error` kind.
fn is_closed_conn_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<io::Error>().is_some_and(|e| {
        matches!(e.kind(), io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionAborted)
    })
}

/// A sync closer restricted to the two concrete tunnel-establishment transports the start path
/// produces (the QUIC transport and the H2 client conn), since Rust has no interface value for an
/// arbitrary sync closer.
enum TunnelCloser {
    Quic(masque_transport::h3::Transport),
    H2(client_h2::H2ClientConn),
}

impl TunnelCloser {
    fn close(&self) -> Result<()> {
        match self {
            Self::Quic(t) => t.close(),
            Self::H2(c) => c.close(),
        }
    }
}

/// The packet conn the QUIC dial would return: quinn's `Endpoint` owns the underlying socket
/// directly and does not hand it back, so this reports only what the client dial and its
/// early-failure cleanup actually use it for (local address, close).
struct EndpointPacketConn(quinn::Endpoint);

#[async_trait]
impl PacketConn for EndpointPacketConn {
    async fn read_from(&self, _buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "masque: quic endpoint packet conn has no direct I/O"))
    }

    async fn write_to(&self, _buf: &[u8], _addr: &dyn Addr) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "masque: quic endpoint packet conn has no direct I/O"))
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr().map(|addr| -> Box<dyn Addr> { Box::new(UdpAddr::from(addr)) })
    }

    fn close(&self) -> io::Result<()> {
        self.0.close(0u32.into(), b"");
        Ok(())
    }
}

/// The TLS stream handed to the HTTP/2 transport: an async `Conn` delegating `local_addr`,
/// `remote_addr` and `close` to the wrapped conn.
struct H2TlsStream {
    inner: Mutex<tokio_rustls::client::TlsStream<Box<dyn Conn>>>,
}

impl AsyncRead for H2TlsStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner.get_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for H2TlsStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner.get_mut()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner.get_mut()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner.get_mut()).poll_shutdown(cx)
    }
}

impl Conn for H2TlsStream {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.lock().get_ref().0.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.lock().get_ref().0.remote_addr()
    }

    /// Drains any buffered ciphertext (and sends `close_notify`) through the TLS layer before
    /// closing the raw conn beneath it; reaching straight into `get_ref().0` and closing that
    /// directly, as this used to, drops whatever the TLS layer still held (same class of bug as
    /// `component::tls::utls::Conn::close`). The TLS layer's own `poll_shutdown` already treats
    /// a `NotConnected` inner shutdown as success (the peer may finish tearing the connection
    /// down as soon as our half-close reaches it); the final raw close below can race the same
    /// way once that happens, so it gets the same tolerance rather than surfacing a spurious
    /// error for a connection that is, by construction, already gone.
    fn close(&self) -> io::Result<()> {
        let mut guard = self.inner.lock();
        let shutdown_result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(std::future::poll_fn(|cx| Pin::new(&mut *guard).poll_shutdown(cx)))
        });
        shutdown_result.and_then(|()| match guard.get_mut().0.close() {
            Err(err) if err.kind() == io::ErrorKind::NotConnected => Ok(()),
            result => result,
        })
    }
}

/// The QUIC config field subset this file sets.
#[derive(Clone, Debug)]
struct MasqueQuicConfig {
    enable_datagrams: bool,
    initial_packet_size: u16,
    keep_alive_period: Duration,
}

pub struct Masque {
    self_weak: Weak<Self>,
    base: Base,
    tls_config: TlsConfig,
    quic_config: MasqueQuicConfig,
    tun_device: Option<Arc<dyn IpStack>>,
    resolver: std::sync::OnceLock<SharedResolver>,
    uri: String,
    h2_transport: Option<H2Transport>,
    l4_client: Option<Arc<L4Client>>,

    run_ctx: CancellationToken,
    run_lock: Arc<tokio::sync::Semaphore>,
    running: Bool,
    run_device: Bool,

    congestion_controller: CongestionController,

    option: MasqueOption,
}

impl core::fmt::Debug for Masque {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `base` and `tls_config` have no `Debug`; the pinned key and the TLS config stay unprinted.
        f.debug_struct("Masque")
            .field("name", &self.base.name)
            .field("addr", &self.base.addr)
            .field("uri", &self.uri)
            .field("congestion_controller", &self.congestion_controller)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MasqueOption {
    #[serde(flatten)]
    pub basic: BasicOption,
    #[serde(rename = "name", default)]
    pub name: String,
    #[serde(rename = "server", default)]
    pub server: String,
    #[serde(rename = "port", default)]
    pub port: i32,
    #[serde(rename = "private-key", default)]
    pub private_key: String,
    #[serde(rename = "public-key", default)]
    pub public_key: String,
    #[serde(rename = "ip", default)]
    pub ip: String,
    #[serde(rename = "ipv6", default)]
    pub ipv6: String,
    #[serde(rename = "uri", default)]
    pub uri: String,
    #[serde(rename = "sni", default)]
    pub sni: String,
    #[serde(rename = "mtu", default)]
    pub mtu: i32,
    #[serde(rename = "udp", default)]
    pub udp: bool,
    #[serde(rename = "handshake-timeout", default)]
    pub handshake_timeout: i32,
    #[serde(rename = "skip-cert-verify", default)]
    pub skip_cert_verify: bool,
    /// Placeholder: MASQUE does not verify certificate names.
    #[serde(rename = "name-cert-verify", default)]
    pub name_cert_verify: String,
    #[serde(rename = "network", default)]
    pub network: String,
    #[serde(rename = "congestion-controller", default)]
    pub congestion_controller: String,
    #[serde(rename = "cwnd", default)]
    pub cwnd: i32,
    #[serde(rename = "bbr-profile", default)]
    pub bbr_profile: String,
    #[serde(rename = "ip-stack", default)]
    pub ip_stack: IpStackOption,
    #[serde(rename = "remote-dns-resolve", default)]
    pub remote_dns_resolve: bool,
    #[serde(rename = "dns", default)]
    pub dns: Vec<String>,
}

impl core::fmt::Debug for MasqueOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `basic` has no `Debug`; the two keys are never printed.
        f.debug_struct("MasqueOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .field("ip", &self.ip)
            .field("ipv6", &self.ipv6)
            .field("uri", &self.uri)
            .field("sni", &self.sni)
            .field("mtu", &self.mtu)
            .field("udp", &self.udp)
            .field("network", &self.network)
            .field("congestion_controller", &self.congestion_controller)
            .field("cwnd", &self.cwnd)
            .finish_non_exhaustive()
    }
}

impl MasqueOption {
    pub fn prefixes(&self) -> Result<Vec<IpNet>> {
        let mut local_prefixes = Vec::with_capacity(2);
        if !self.ip.is_empty() {
            let ip_str = if self.ip.contains('/') { self.ip.clone() } else { format!("{}/32", self.ip) };
            let prefix = ip_str.parse::<IpNet>().map_err(|e| anyhow!("ip address parse error: {e}"))?;
            local_prefixes.push(prefix);
        }
        if !self.ipv6.is_empty() {
            let ip_str = if self.ipv6.contains('/') { self.ipv6.clone() } else { format!("{}/128", self.ipv6) };
            let prefix = ip_str.parse::<IpNet>().map_err(|e| anyhow!("ipv6 address parse error: {e}"))?;
            local_prefixes.push(prefix);
        }
        if local_prefixes.is_empty() {
            return Err(anyhow!("missing local address"));
        }
        Ok(local_prefixes)
    }
}

/// The TLS dial for `network: h2`: the plain conn comes from `dialer`, TLS runs over it, and the
/// result is the TLS conn the H2 client expects. `None` for other networks.
fn build_h2_transport(
    option: &MasqueOption,
    tls_config: &mut TlsConfig,
    dialer: &Arc<dyn CDialer>,
    addr: &str,
) -> Option<H2Transport> {
    if option.network != "h2" {
        return None;
    }
    tls_config.config.alpn_protocols = vec![b"h2".to_vec()];
    let dial_tls: DialTlsFn = {
        let dialer = Arc::clone(dialer);
        let addr = addr.to_owned();
        let tls_client_config = Arc::new(tls_config.config.clone());
        let server_name = tls_config.server_name.clone();
        Arc::new(
            move |ctx: CancellationToken,
                  _network: &'static str,
                  _addr: String|
                  -> BoxFuture<'static, Result<Box<dyn Conn>>> {
                let dialer = Arc::clone(&dialer);
                let addr = addr.clone();
                let tls_client_config = Arc::clone(&tls_client_config);
                let server_name = server_name.clone();
                Box::pin(async move {
                    let conn = dialer.dial_context(&ctx, "tcp", &addr).await?;
                    // S11: remove with std-compat (murmur_transport_masque::client_h2::DialTlsFn still returns old murmur_std_compat::net::Conn)
                    let conn: Box<dyn Conn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(conn));
                    let connector = tokio_rustls::TlsConnector::from(tls_client_config);
                    let tls_stream = connector.connect(server_name, conn).await.map_err(|e| anyhow!("{e}"))?;
                    let conn: Box<dyn Conn> = Box::new(H2TlsStream { inner: Mutex::new(tls_stream) });
                    Ok(conn)
                })
            },
        )
    };
    let Http2Config { ping_timeout, .. } = Http2Config::default();
    let http2 = Http2Config { send_ping_timeout: Some(Duration::from_secs(30)), ping_timeout };
    Some(H2Transport::new(dial_tls, http2))
}

/// The TUN device `Masque` runs on, plus whether any local prefix is IPv6. L4 proxy mode carries
/// no device at all and always reports IPv6 (its dialer is the L4 client, not the stack).
fn build_ip_stack(
    option: &MasqueOption,
    ip_stack_option: IpStackOption,
    l4proxy: bool,
    mtu: u32,
    base: &mut Base,
) -> Result<(Option<Arc<dyn IpStack>>, bool)> {
    if l4proxy {
        if base.udp {
            warnln!("[Masque]({}) L4 proxy mode is not supported for UDP", base.name);
            base.udp = false;
        }
        return Ok((None, true));
    }
    let prefixes = option.prefixes()?;
    if prefixes.is_empty() {
        return Err(anyhow!("missing local address"));
    }
    let tun_device =
        Some(new_ip_stack(ip_stack_option, prefixes.clone(), mtu).map_err(|e| anyhow!("create device: {e}"))?);
    let has6 = prefixes.iter().any(|address| !matches!(address.addr(), IpAddr::V4(_)));
    Ok((tun_device, has6))
}

impl Masque {
    pub fn new(option: MasqueOption) -> Result<Arc<Self>> {
        if option.handshake_timeout < 0 {
            return Err(anyhow!("masque handshake timeout must be non-negative"));
        }
        let mut ip_stack_option = option.ip_stack.clone();
        ip_stack_option.normalize();
        ip_stack_option.validate()?;

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr: murmur_component::dialer::bind::join_host_port(&option.server, option.port),
            type_: AdapterType::MASQUE,
            provider_name: option.basic.provider_name.clone(),
            udp: option.udp,
            interface: option.basic.interface.clone(),
            routing_mark: option.basic.routing_mark,
            prefer: option.basic.ip_version,
            xudp: false,
            tfo: false,
            mptcp: false,
        });
        let dialer = option.basic.new_dialer(base.dial_options());
        base.dialer = Some(Arc::clone(&dialer));

        let run_ctx = CancellationToken::new();

        let priv_key_der =
            BASE64_STANDARD.decode(&option.private_key).map_err(|e| anyhow!("failed to decode private key: {e}"))?;
        let priv_key = EcdsaPrivateKey::parse_ec_private_key(&priv_key_der)
            .map_err(|e| anyhow!("failed to parse private key: {e}"))?;

        let pub_key_der =
            BASE64_STANDARD.decode(&option.public_key).map_err(|e| anyhow!("failed to decode public key: {e}"))?;
        // A type assertion after the parse has no counterpart: `EcdsaPublicKey::parse_pkix_public_key`
        // already only succeeds for EC keys, so that assertion has no separate failure mode left to
        // preserve here (see DEVIATIONS).
        let ec_pub_key = EcdsaPublicKey::parse_pkix_public_key(&pub_key_der)
            .map_err(|e| anyhow!("failed to parse public key: {e}"))?;

        let l4proxy = option.network == "h3-l4proxy";

        let uri = if option.uri.is_empty() { CONNECT_URI.to_owned() } else { option.uri.clone() };

        let sni = if !option.sni.is_empty() {
            option.sni.clone()
        } else if l4proxy {
            L4_CONNECT_SNI.to_owned()
        } else {
            CONNECT_SNI.to_owned()
        };

        let mut tls_config = prepare_tls_config(&priv_key, &ec_pub_key, &sni, option.skip_cert_verify)
            .map_err(|e| anyhow!("failed to prepare TLS config: {e}\n"))?;

        let h2_transport = build_h2_transport(&option, &mut tls_config, &dialer, &base.addr);

        let quic_config = MasqueQuicConfig {
            enable_datagrams: true,
            initial_packet_size: 1242,
            keep_alive_period: Duration::from_secs(30),
        };

        let mtu = if option.mtu == 0 { 1280 } else { option.mtu.cast_unsigned() };

        let (tun_device, has6) = build_ip_stack(&option, ip_stack_option, l4proxy, mtu, &mut base)?;

        let outbound = Arc::new_cyclic(|self_weak: &Weak<Self>| {
            let l4_client = if l4proxy {
                let dial_fn: DialQuicFn = {
                    let self_weak = Weak::clone(self_weak);
                    Arc::new(move |ctx: CancellationToken| -> BoxFuture<'static, Result<(Box<dyn PacketConn>, quinn::Connection)>> {
                    let self_weak = Weak::clone(&self_weak);
                    Box::pin(async move {
                        let masque = self_weak.upgrade().ok_or_else(|| anyhow!("Masque: adapter dropped while in use"))?;
                        masque.dial_quic(&ctx).await
                    })
                })
                };
                Some(Arc::new(L4Client::new(run_ctx.clone(), dial_fn)))
            } else {
                None
            };

            Self {
                self_weak: Weak::clone(self_weak),
                base,
                tls_config,
                quic_config,
                tun_device,
                resolver: std::sync::OnceLock::new(),
                uri,
                h2_transport,
                l4_client,
                run_ctx,
                run_lock: Arc::new(tokio::sync::Semaphore::new(1)),
                running: new_bool(false),
                run_device: new_bool(false),
                congestion_controller: CongestionController::parse(&option.congestion_controller),
                option,
            }
        });

        outbound.install_resolvers(has6)?;

        Ok(outbound)
    }

    /// built only for `remote-dns-resolve` with a configured name server
    /// list, and every name server dials back through this adapter.
    fn install_resolvers(self: &Arc<Self>, has6: bool) -> Result<()> {
        if !self.option.remote_dns_resolve || self.option.dns.is_empty() {
            return Ok(());
        }
        let parse_name_server =
            PARSE_NAME_SERVER.get().ok_or_else(|| anyhow!("masque: dns.ParseNameServer is not configured"))?;
        let mut nss = parse_name_server(&self.option.dns)?;
        for ns in &mut nss {
            let adapter = Arc::clone(self);
            let adapter: Arc<dyn CProxyAdapter> = adapter;
            ns.proxy_adapter = Some(adapter);
        }
        let resolvers = Resolvers::new(DnsResolverConfig {
            main: nss,
            ipv6: has6,
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
        let _ = self.resolver.set(Arc::new(resolvers.resolver));
        Ok(())
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("Masque: adapter dropped while in use"))
    }

    fn resolver_snapshot(&self) -> Option<SharedResolver> {
        self.resolver.get().cloned()
    }

    /// See the module doc: dials `quinn` directly instead of bridging through
    /// `transport/tuic/common::dial_quic`'s structural QUIC mirror.
    async fn dial_quic(&self, ctx: &CancellationToken) -> Result<(Box<dyn PacketConn>, quinn::Connection)> {
        // cancel-safe: the endpoint and the in-flight quinn connect are owned here, so a drop
        // cancels the handshake with them.
        let udp_addr = resolve_udp_addr(ctx, "udp", &self.base.addr, self.base.prefer).await?;
        let remote = SocketAddr::try_from(&udp_addr).map_err(|e| anyhow!("{e}"))?;
        let bind_addr = match remote.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };

        // `quinn::Endpoint::client` binds its own fresh socket and does not honour the dial options
        // (interface/routing-mark/TFO); quinn exposes no way to dial through an arbitrary
        // pre-created dialer-bound socket short of implementing `quinn_proto::AsyncUdpSocket`. See
        // DEVIATIONS: NEEDED SHIM ITEM. The socket is still pre-created here (rather than through
        // `quinn::Endpoint::client` itself) so `disable_udp_icmp_resets` can run on it before
        // `quinn` ever touches it, same as `dial_addr`/`listen_packet`.
        let socket = murmur_component::dialer::control::bind_quic_client_socket(bind_addr)
            .map_err(|e| anyhow!("masque: failed to bind quic endpoint socket: {e}"))?;
        let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("masque: no async runtime found"))?;
        let mut endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
            .map_err(|e| anyhow!("masque: failed to create quic endpoint: {e}"))?;

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(self.tls_config.config.clone())
            .map_err(|e| anyhow!("masque: invalid TLS config for quic: {e}"))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

        let mut transport = quinn::TransportConfig::default();
        if self.quic_config.keep_alive_period > Duration::ZERO {
            transport.keep_alive_interval(Some(self.quic_config.keep_alive_period));
        }
        if self.quic_config.initial_packet_size >= 1200 {
            let _ = transport.initial_mtu(self.quic_config.initial_packet_size);
        }
        if self.quic_config.enable_datagrams {
            transport.datagram_receive_buffer_size(Some(pool::UDP_BUFFER_SIZE));
            transport.datagram_send_buffer_size(pool::UDP_BUFFER_SIZE);
        }
        transport
            .congestion_controller_factory(congestion_controller_factory(self.congestion_controller, self.option.cwnd));
        client_config.transport_config(Arc::new(transport));
        endpoint.set_default_client_config(client_config);

        let server_name = self.tls_config.server_name.to_str().into_owned();
        let connecting =
            endpoint.connect(remote, &server_name).map_err(|e| anyhow!("masque: quic connect failed: {e}"))?;
        let connection = tokio::select! {
            result = connecting => result.map_err(|e| anyhow!("masque: quic handshake failed: {e}"))?,
            () = ctx.cancelled() => return Err(context_canceled()),
        };

        let pc: Box<dyn PacketConn> = Box::new(EndpointPacketConn(endpoint));
        Ok((pc, connection))
    }

    pub async fn run(self: &Arc<Self>, ctx: &CancellationToken) -> Result<()> {
        // NOT cancel-safe: once the permit passes to the start task, a drop leaves that task
        // running and `run_ctx` uncancelled.
        if self.running.load() {
            return Ok(());
        }
        let run_ctx = ctx.child_token();
        let stop = after_func(&self.run_ctx, {
            let run_ctx = run_ctx.clone();
            move || run_ctx.cancel()
        });

        let result: Result<()> = async {
            let permit = tokio::select! {
                permit = Arc::clone(&self.run_lock).acquire_owned() => permit.map_err(|e| anyhow!("{e}"))?,
                () = run_ctx.cancelled() => return Err(context_canceled()),
            };

            if self.running.load() {
                return Ok(());
            }
            if self.run_ctx.is_cancelled() {
                return Err(context_canceled());
            }

            if self.option.handshake_timeout > 0 {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let self_arc = Arc::clone(self);
                let handshake_timeout = Duration::from_secs(u64::from(self.option.handshake_timeout.cast_unsigned()));
                let parent_run_ctx = self.run_ctx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let handshake_ctx = parent_run_ctx.child_token();
                    let sleeper = {
                        let handshake_ctx = handshake_ctx.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(handshake_timeout).await;
                            handshake_ctx.cancel();
                        })
                    };
                    let result = Self::start_locked(&self_arc, &handshake_ctx).await;
                    sleeper.abort();
                    let _ = tx.send(result);
                });

                tokio::select! {
                    result = rx => result.map_err(|_| anyhow!("masque: run task ended unexpectedly"))?,
                    () = run_ctx.cancelled() => Err(context_canceled()),
                }
            } else {
                let result = Self::start_locked(self, &run_ctx).await;
                drop(permit);
                result
            }
        }
        .await;

        let _ = stop();
        run_ctx.cancel();
        result
    }

    async fn start_locked(self: &Arc<Self>, ctx: &CancellationToken) -> Result<()> {
        if !self.run_device.load() {
            let tun_device =
                self.tun_device.as_ref().ok_or_else(|| anyhow!("start_locked requires tun_device when not l4proxy"))?;
            tun_device.start().await?;
            self.run_device.store(true);
        }

        let mut pc: Option<Box<dyn PacketConn>> = None;
        let closer: TunnelCloser;
        let ip_conn: Box<dyn IpConn>;

        if let Some(h2_transport) = &self.h2_transport {
            let (h2_conn, conn) = client_h2::connect_tunnel_h2(ctx.clone(), h2_transport, &self.uri).await?;
            closer = TunnelCloser::H2(h2_conn);
            ip_conn = conn;
        } else {
            let (dialed_pc, quic_conn) = self.dial_quic(ctx).await?;
            let (transport, conn) =
                masque_transport::connect_tunnel(ctx.clone(), quic_conn, &self.uri).await.inspect_err(|_| {
                    let _ = dialed_pc.close();
                })?;
            closer = TunnelCloser::Quic(transport);
            ip_conn = Box::new(conn);
            pc = Some(dialed_pc);
        }

        self.running.store(true);

        let run_ctx = self.run_ctx.child_token();
        let ip_conn: Arc<tokio::sync::Mutex<Box<dyn IpConn>>> = Arc::new(tokio::sync::Mutex::new(ip_conn));

        {
            let self_arc = Arc::clone(self);
            let ip_conn = Arc::clone(&ip_conn);
            let _ = after_func(&run_ctx, move || {
                self_arc.running.store(false);
                tokio::spawn(async move {
                    let _ = ip_conn.lock().await.close().await;
                    let _ = closer.close();
                    if let Some(pc) = pc {
                        let _ = pc.close();
                    }
                });
            });
        }

        Self::spawn_tun_to_ip_task(
            Arc::clone(
                self.tun_device.as_ref().ok_or_else(|| anyhow!("start_locked requires tun_device when not l4proxy"))?,
            ),
            Arc::clone(&ip_conn),
            run_ctx.clone(),
            self.base.name.clone(),
        );

        {
            let tun_device = Arc::clone(
                self.tun_device.as_ref().ok_or_else(|| anyhow!("start_locked requires tun_device when not l4proxy"))?,
            );
            let ip_conn = Arc::clone(&ip_conn);
            let run_ctx = run_ctx;
            let name = self.base.name.clone();
            tokio::spawn(async move {
                while !run_ctx.is_cancelled() {
                    let read_result = ip_conn.lock().await.read_packet().await;
                    let buf = match read_result {
                        Ok(buf) => buf,
                        Err(e) => {
                            if is_closed_conn_error(&e) {
                                errorln!("[Masque]({name}) connection closed while writing to IP connection: {e}");
                                break;
                            }
                            warnln!("[Masque]({name}) error reading from IP connection: {e}, continuing...");
                            continue;
                        }
                    };
                    if let Err(e) = tun_device.write(&[buf], 0) {
                        errorln!("[Masque]({name}) error writing to TUN device: {e}");
                        break;
                    }
                }
                run_ctx.cancel();
            });
        }

        Ok(())
    }

    /// Pumps datagrams from the TUN device into the tunnel, writing any ICMP the tunnel hands
    /// back out through the device. Ends (and cancels `run_ctx`) as soon as either side closes.
    fn spawn_tun_to_ip_task(
        tun_device: Arc<dyn IpStack>,
        ip_conn: Arc<tokio::sync::Mutex<Box<dyn IpConn>>>,
        run_ctx: CancellationToken,
        name: String,
    ) {
        tokio::spawn(async move {
            let mut bufs = vec![pool::get(pool::UDP_BUFFER_SIZE)];
            let mut sizes = vec![0usize];
            while !run_ctx.is_cancelled() {
                if let Err(e) = tun_device.read(&mut bufs, &mut sizes, 0) {
                    errorln!("[Masque]({name}) error reading from TUN device: {e}");
                    break;
                }
                let Some(size) = sizes.first().copied() else { break };
                let Some(payload) = bufs.first_mut().and_then(|buf| buf.get_mut(..size)) else {
                    errorln!("[Masque]({name}) TUN device reported {size} bytes, more than the receive buffer holds");
                    break;
                };
                let write_result = ip_conn.lock().await.write_packet(payload).await;
                match write_result {
                    Ok(Some(icmp)) if !icmp.is_empty() => {
                        if let Err(e) = tun_device.write(&[icmp], 0) {
                            warnln!("[Masque]({name}) error writing ICMP to TUN device: {e}, continuing...");
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        if is_closed_conn_error(&e) {
                            errorln!("[Masque]({name}) connection closed while writing to IP connection: {e}");
                            break;
                        }
                        warnln!("[Masque]({name}) error writing to IP connection: {e}, continuing...");
                    }
                }
            }
            if let Some(buf) = bufs.pop() {
                let _ = pool::put(buf);
            }
            run_ctx.cancel();
        });
    }

    async fn dial_context_l4(&self, ctx: &CancellationToken, metadata: &Metadata) -> Result<Box<dyn CConn>> {
        let l4_client = self.l4_client.as_ref().ok_or_else(|| anyhow!("dial_context_l4 requires l4_client"))?;
        let conn: Box<dyn Conn> = if !metadata.resolved() || self.resolver_snapshot().is_some() {
            let r = self.resolver_snapshot().or_else(default_resolver);
            let mut options: Vec<DialerOption> = self.base.dial_options();
            options.push(with_resolver(r));
            let dialer = Arc::clone(l4_client);
            let dialer: Arc<dyn NetDialer> = dialer;
            options.push(with_net_dialer(dialer));
            // S11: remove with std-compat (unifies with the L4Client::dial_context branch below, which still returns old murmur_std_compat::net::Conn)
            Box::new(murmur_common_net::io::StreamAsOldConn::new(
                new_dialer(options).dial_context(ctx, "tcp", &metadata.remote_address()).await?,
            ))
        } else {
            let addr = metadata
                .addr_port()
                .ok_or_else(|| anyhow!("metadata.resolved() implies addr_port is Some"))?
                .to_string();
            l4_client.dial_context(ctx.clone(), "tcp", &addr).await?
        };
        // S11: remove with std-compat (murmur_transport_masque::l4proxy::L4Client::dial_context still returns old murmur_std_compat::net::Conn)
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(conn)), self))
    }
}

#[async_trait]
impl CProxyAdapter for Masque {
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
        if self.l4_client.is_some() {
            return self.dial_context_l4(ctx, metadata).await;
        }
        let self_arc = self.self_arc()?;
        Self::run(&self_arc, ctx).await?;
        let tun_device =
            self.tun_device.as_ref().ok_or_else(|| anyhow!("dial_context requires tun_device when not l4proxy"))?;
        let conn: Box<dyn Conn> = if !metadata.resolved() || self.resolver_snapshot().is_some() {
            let r = self.resolver_snapshot().or_else(default_resolver);
            let mut options: Vec<DialerOption> = self.base.dial_options();
            options.push(with_resolver(r));
            options.push(with_net_dialer(Arc::new(IpStackNetDialer { stack: Arc::clone(tun_device) })));
            // S11: remove with std-compat (unifies with the tun_device.dial_tcp branch below; util::ip_stack::IpStack still murmur_std_compat::net::Conn based)
            Box::new(murmur_common_net::io::StreamAsOldConn::new(
                new_dialer(options).dial_context(ctx, "tcp", &metadata.remote_address()).await?,
            ))
        } else {
            let source = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
            let destination =
                metadata.addr_port().ok_or_else(|| anyhow!("metadata.resolved() implies addr_port is Some"))?;
            tun_device.dial_tcp(ctx, "tcp", source, destination).await?
        };
        // S11: remove with std-compat (util::ip_stack::IpStack still murmur_std_compat::net::Conn based)
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(conn)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        if self.l4_client.is_some() {
            return Err(anyhow!("masque L4 proxy mode is not supported for UDP"));
        }
        let self_arc = self.self_arc()?;
        Self::run(&self_arc, ctx).await?;
        ProxyAdapter::resolve_udp(self, ctx, metadata).await?;
        let tun_device = self
            .tun_device
            .as_ref()
            .ok_or_else(|| anyhow!("listen_packet_context requires tun_device when not l4proxy"))?;
        let local = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let pc = tun_device.listen_udp(ctx, "udp", local).await?;
        // S11: remove with std-compat (util::ip_stack::IpStack still murmur_std_compat::net::PacketConn based)
        Ok(new_packet_conn(Arc::new(murmur_common_net::io::OldPacketConnAsDatagram(pc)), self_arc))
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
        if let Some(tun_device) = &self.tun_device {
            let _ = tun_device.close();
        }
        if let Some(l4_client) = &self.l4_client {
            let l4_client = Arc::clone(l4_client);
            let _ = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(l4_client.close()));
        }
        Ok(())
    }
}

#[async_trait]
impl ProxyAdapter for Masque {
    fn dial_options(&self) -> Vec<DialerOption> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        if (!metadata.resolved() || self.resolver_snapshot().is_some()) && !metadata.host.is_empty() {
            let r = self.resolver_snapshot().or_else(default_resolver);
            let ip = resolve_ip_with_resolver(ctx, &metadata.host, self.base.prefer, r.as_deref())
                .await
                .map_err(|e| anyhow!("can't resolve ip: {e}"))?;
            metadata.dst_ip = Some(ip);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use murmur_component_ca::keypair::{new_random_tls_key_pair, KeyPairType};
    use murmur_testsupport_probe::ensure_test_crypto_provider;

    /// The controller is left untouched for an empty/unrecognized `congestion-controller`, which
    /// must stay a distinct variant from an explicit `"cubic"` rather than collapse into it.
    #[test]
    fn congestion_controller_parse_distinguishes_unset_from_explicit_cubic() {
        assert_eq!(CongestionController::parse(""), CongestionController::Unset);
        assert_eq!(CongestionController::parse("not-a-real-controller"), CongestionController::Unset);
        assert_eq!(CongestionController::parse("cubic"), CongestionController::Cubic);
        assert_ne!(CongestionController::parse("cubic"), CongestionController::Unset);
        assert_eq!(CongestionController::parse("new_reno"), CongestionController::NewReno);
        assert_eq!(CongestionController::parse("bbr"), CongestionController::Bbr);
        assert_eq!(CongestionController::parse("bbr_meta_v2"), CongestionController::Bbr);
        assert_eq!(CongestionController::parse("bbr_meta_v1"), CongestionController::BbrMetaV1);
        assert_ne!(CongestionController::parse("bbr_meta_v1"), CongestionController::Bbr);
    }

    /// Pins every arm's initial window to the value computed for masque's initial packet size of
    /// `1242`. `unset`/`cubic`/`new_reno` ignore `cwnd` and land on `32 * 1242 = 39744`: the
    /// untouched default sender (fed `1242` when the client connection is built) and the cubic
    /// sender both hard-code the multiplier `32` and take no `cwnd` argument. `bbr`/`bbr_meta_v2`
    /// multiply `cwnd` (defaulted to `32` when 0) by the same `1242`. `bbr_meta_v1` multiplies the
    /// same defaulted `cwnd` by the fixed `1280` instead.
    #[test]
    fn congestion_controller_factory_matches_the_initial_windows() {
        fn window(cc: CongestionController, cwnd: i32) -> u64 {
            congestion_controller_factory(cc, cwnd).build(std::time::Instant::now(), 1280).initial_window()
        }

        for cwnd in [0, 16] {
            assert_eq!(window(CongestionController::Unset, cwnd), 32 * 1242, "cwnd={cwnd}");
            assert_eq!(window(CongestionController::Cubic, cwnd), 32 * 1242, "cwnd={cwnd}");
            assert_eq!(window(CongestionController::NewReno, cwnd), 32 * 1242, "cwnd={cwnd}");
        }

        assert_eq!(window(CongestionController::Bbr, 0), 32 * 1242);
        assert_eq!(window(CongestionController::Bbr, 16), 16 * 1242);
        assert_eq!(window(CongestionController::BbrMetaV1, 0), 32 * 1280);
        assert_eq!(window(CongestionController::BbrMetaV1, 16), 16 * 1280);
    }

    /// The untouched default sender runs in Reno mode, so `Unset` must build the same controller as
    /// explicit `new_reno`, and explicit `cubic` a different one.
    #[test]
    fn unset_congestion_controller_builds_the_new_reno_default() {
        fn controller(cc: CongestionController) -> Box<dyn std::any::Any> {
            congestion_controller_factory(cc, 0).build(std::time::Instant::now(), 1280).into_any()
        }

        assert!(controller(CongestionController::Unset).is::<quinn::congestion::NewReno>());
        assert!(controller(CongestionController::NewReno).is::<quinn::congestion::NewReno>());
        assert!(controller(CongestionController::Cubic).is::<quinn::congestion::Cubic>());
    }

    fn generate_test_server_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        use murmur_component_ca::config::pem_sections;

        let (cert_pem, key_pem, _fingerprint) =
            new_random_tls_key_pair(KeyPairType::P256).expect("generate test tls server certificate");
        let cert_der = pem_sections(cert_pem.as_bytes())
            .into_iter()
            .find(|(label, _, _)| label == "CERTIFICATE")
            .map(|(_, der, _)| CertificateDer::from(der))
            .expect("parse test tls server certificate");
        let key_der = pem_sections(key_pem.as_bytes())
            .into_iter()
            .find_map(|(label, der, _)| match label.as_str() {
                "PRIVATE KEY" => Some(PrivateKeyDer::Pkcs8(der.into())),
                "EC PRIVATE KEY" => Some(PrivateKeyDer::Sec1(der.into())),
                "RSA PRIVATE KEY" => Some(PrivateKeyDer::Pkcs1(der.into())),
                _ => None,
            })
            .expect("parse test tls server certificate key");
        (cert_der, key_der)
    }

    #[derive(Debug)]
    struct NoVerify;

    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::CryptoProvider::get_default()
                .expect("crypto provider installed")
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// Regression test for the sibling of the flush defect: `H2TlsStream::close` used to reach
    /// into `self.inner.get_ref().0` and close the raw conn directly, bypassing
    /// `tokio_rustls::TlsStream::poll_shutdown` entirely (never flushing, never sending
    /// `close_notify`) — the same bug class as `component::tls::utls::Conn::close`. `rustls`
    /// caps its outgoing plaintext/ciphertext buffers at 64KiB (`DEFAULT_BUFFER_LIMIT`), so a
    /// single `write_all` call for a body under that cap is accepted and reported as fully
    /// written in one shot regardless of how much of it actually reached the socket; shrinking
    /// the client's send buffer and the server's receive buffer to a couple KiB, with nobody
    /// reading yet, guarantees most of that body is still sitting in the TLS layer, unsent, the
    /// instant `close()` is called.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn h2_tls_stream_close_delivers_full_write() {
        ensure_test_crypto_provider();

        fn shrink_send_buffer(stream: &TcpStream) {
            socket2::SockRef::from(stream).set_send_buffer_size(2 * 1024).expect("set send buffer size");
        }

        fn shrink_recv_buffer(stream: &TcpStream) {
            socket2::SockRef::from(stream).set_recv_buffer_size(2 * 1024).expect("set recv buffer size");
        }

        let (cert_der, key_der) = generate_test_server_cert();
        let mut server_tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("build test tls server config");
        // Unread tickets left in the kernel receive buffer make Linux send RST on close,
        // dropping the client's unacked write.
        server_tls_config.send_tls13_tickets = 0;
        let server_tls_config = Arc::new(server_tls_config);
        let client_tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");

        let client_raw = TcpStream::connect(addr).await.expect("client connect");
        shrink_send_buffer(&client_raw);
        let (server_raw, _) = listener.accept().await.expect("accept");
        shrink_recv_buffer(&server_raw);

        let server_name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
        let client_io: Box<dyn Conn> = Box::new(client_raw);
        let (client_result, server_result) = tokio::join!(
            tokio_rustls::TlsConnector::from(client_tls_config).connect(server_name, client_io),
            tokio_rustls::TlsAcceptor::from(server_tls_config).accept(server_raw),
        );
        let client_tls = client_result.expect("client handshake");
        let mut server_tls = server_result.expect("server handshake");

        // Comfortably under rustls's 64KiB `DEFAULT_BUFFER_LIMIT`, so the whole body is accepted
        // by a single `poll_write` call and `write_all` returns success without needing any read
        // on the peer side at all.
        let body = "x".repeat(50_000);

        let read_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                match server_tls.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            buf
        });

        let client_conn: Box<dyn Conn> = Box::new(H2TlsStream { inner: Mutex::new(client_tls) });
        {
            let mut client_conn = client_conn;
            client_conn.write_all(body.as_bytes()).await.expect("write body");
            client_conn.close().expect("close");
        }

        let received = tokio::time::timeout(Duration::from_secs(30), read_task)
            .await
            .expect("read timed out")
            .expect("read task panicked");
        assert_eq!(received.len(), body.len(), "write truncated by close");
        assert_eq!(received, body.as_bytes(), "write corrupted");
    }

    /// `generate_cert` used to fail every construction with a "NEEDED CRATE" error; this proves the
    /// construction path (key parsing, TLS config) completes end to end for the `h3-l4proxy` network
    /// mode. The default h3/h2 connect-ip modes build their TUN device later, on the first dial, so
    /// they are not covered here.
    #[test]
    fn masque_new_constructs_with_a_valid_config() {
        use murmur_component_ca::keypair::{
            concat, der_bit_string, der_oid, der_sequence, OID_EC_PUBLIC_KEY, OID_PRIME256V1,
        };

        let mut seed = [0u8; 32];
        let secret_key = loop {
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
            if let Ok(secret_key) = p256::SecretKey::from_bytes(&seed.into()) {
                break secret_key;
            }
        };
        let private_key_der = secret_key.to_sec1_der().expect("encode sec1 der").to_vec();
        let signing_key = p256::ecdsa::SigningKey::from(&secret_key);
        let public_key_bytes = signing_key.verifying_key().to_sec1_point(false).as_ref().to_vec();
        let public_key_der = der_sequence(&concat(&[
            der_sequence(&concat(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_PRIME256V1)])),
            der_bit_string(&public_key_bytes),
        ]));

        let option = MasqueOption {
            name: "test-masque".to_owned(),
            server: "example.com".to_owned(),
            port: 443,
            private_key: BASE64_STANDARD.encode(&private_key_der),
            public_key: BASE64_STANDARD.encode(&public_key_der),
            network: "h3-l4proxy".to_owned(),
            ..Default::default()
        };

        Masque::new(option).expect("Masque::new must construct with a valid config now that generate_cert works");
    }
}

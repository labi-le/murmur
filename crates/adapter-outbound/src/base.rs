use std::any::Any;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Once};
use std::task::{Context as TaskContext, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use murmur_common::utils::uuid::new_uuid_v4;
use murmur_common_net::io::{CancellableStream, Datagram, ExtendedStream, Stream};
use murmur_common_net::tcpip::split_host_port;
use murmur_common_net::{
    new_deadline_enhance_packet_conn, new_enhance_datagram, new_ref_packet_conn, EnhancePacketConn, WaitReadFrom,
};
use murmur_component::dialer::dialer::new_dialer;
use murmur_component::dialer::options::{
    with_interface, with_mptcp, with_only_single_stack, with_prefer_ipv4, with_prefer_ipv6, with_routing_mark,
    with_tfo, Option as DialerOption,
};
use murmur_component::resolver::resolver::default_resolver;
use murmur_component_proxydialer::byname::new_by_name;
use murmur_constant::adapters::{
    err_not_support, AdapterType, Chain, Conn as CConn, Connection, Dialer as CDialer, PacketConn as CPacketConn,
    Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::dns::DNSPrefer;
use murmur_constant::metadata::Metadata;
use murmur_log::debugln;
use murmur_std_compat::net::{Addr, Conn, PacketConn};

use super::util::resolve_ip_with_resolver;

#[async_trait]
pub trait ProxyAdapter: CProxyAdapter {
    fn dial_options(&self) -> Vec<DialerOption>;

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()>;
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "wire-format mirror; the flags are independent protocol options and collapsing them \
              would change the public shape"
)]
pub struct Base {
    pub(crate) name: String,
    pub(crate) addr: String,
    pub(crate) tp: AdapterType,
    pub(crate) pd_name: String,
    pub(crate) udp: bool,
    pub(crate) xudp: bool,
    pub(crate) tfo: bool,
    pub(crate) mp_tcp: bool,
    pub(crate) iface: String,
    pub(crate) rmark: i32,
    pub(crate) prefer: DNSPrefer,
    pub(crate) dialer: Option<Arc<dyn CDialer>>,
    pub(crate) id: Uuid,
}

impl core::fmt::Debug for Base {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Base")
            .field("name", &self.name)
            .field("addr", &self.addr)
            .field("tp", &self.tp)
            .field("pd_name", &self.pd_name)
            .field("udp", &self.udp)
            .field("xudp", &self.xudp)
            .field("tfo", &self.tfo)
            .field("mp_tcp", &self.mp_tcp)
            .field("iface", &self.iface)
            .field("rmark", &self.rmark)
            .field("prefer", &self.prefer)
            .field("dialer", &self.dialer.is_some())
            .field("id", &self.id)
            .finish()
    }
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "wire-format mirror; the flags are independent protocol options and collapsing them \
              would change the public shape"
)]
#[derive(Clone, Debug)]
pub struct BaseOption {
    pub name: String,
    pub addr: String,
    pub type_: AdapterType,
    pub provider_name: String,
    pub udp: bool,
    pub xudp: bool,
    pub tfo: bool,
    pub mptcp: bool,
    pub interface: String,
    pub routing_mark: i32,
    pub prefer: DNSPrefer,
}
impl Default for BaseOption {
    /// Every field at its reference zero value. Written out rather than derived so that adding a
    /// field to `BaseOption` cannot default silently: this impl stops compiling until the new field is
    /// named here (RUST_GUIDELINES.md section 3, functional-update struct literals).
    fn default() -> Self {
        Self {
            name: <String as Default>::default(),
            addr: <String as Default>::default(),
            type_: <AdapterType as Default>::default(),
            provider_name: <String as Default>::default(),
            udp: <bool as Default>::default(),
            xudp: <bool as Default>::default(),
            tfo: <bool as Default>::default(),
            mptcp: <bool as Default>::default(),
            interface: <String as Default>::default(),
            routing_mark: <i32 as Default>::default(),
            prefer: <DNSPrefer as Default>::default(),
        }
    }
}

impl Base {
    #[must_use]
    pub fn new(opt: BaseOption) -> Self {
        Self {
            name: opt.name,
            addr: opt.addr,
            tp: opt.type_,
            pd_name: opt.provider_name,
            udp: opt.udp,
            xudp: opt.xudp,
            tfo: opt.tfo,
            mp_tcp: opt.mptcp,
            iface: opt.interface,
            rmark: opt.routing_mark,
            prefer: opt.prefer,
            dialer: None,
            id: new_uuid_v4(),
        }
    }

    #[must_use]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    #[must_use]
    pub fn id(&self) -> String {
        self.id.to_string()
    }

    #[must_use]
    pub const fn type_(&self) -> AdapterType {
        self.tp
    }

    #[expect(clippy::unused_async, reason = "kept `async` because callers await it, matching `CProxyAdapter`")]
    pub async fn dial_context(&self, _ctx: &CancellationToken, _metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        Err(err_not_support())
    }

    #[expect(clippy::unused_async, reason = "kept `async` because callers await it, matching `CProxyAdapter`")]
    pub async fn listen_packet_context(
        &self,
        _ctx: &CancellationToken,
        _metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        Err(err_not_support())
    }

    #[must_use]
    pub const fn support_uot(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn support_udp(&self) -> bool {
        self.udp
    }

    #[must_use]
    pub fn proxy_info(&self) -> ProxyInfo {
        ProxyInfo {
            xudp: self.xudp,
            tfo: self.tfo,
            mptcp: self.mp_tcp,
            smux: false,
            interface: self.iface.clone(),
            routing_mark: self.rmark,
            provider_name: self.pd_name.clone(),
            dialer_proxy: String::new(),
        }
    }

    #[must_use]
    pub const fn is_l3_protocol(&self, _metadata: &Metadata) -> bool {
        false
    }

    pub fn marshal_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&serde_json::json!({
            "type": self.tp.string(),
            "id": self.id(),
        }))?)
    }

    #[must_use]
    pub fn addr(&self) -> String {
        self.addr.clone()
    }

    #[must_use]
    pub fn unwrap(&self, _metadata: &Metadata, _touch: bool) -> Option<Arc<dyn Proxy>> {
        None
    }

    #[must_use]
    pub fn dial_options(&self) -> Vec<DialerOption> {
        let mut opts: Vec<DialerOption> = Vec::new();

        if !self.iface.is_empty() {
            opts.push(with_interface(&self.iface));
        }

        if self.rmark != 0 {
            opts.push(with_routing_mark(self.rmark));
        }

        match self.prefer {
            DNSPrefer::IPV4_ONLY => opts.push(with_only_single_stack(true)),
            DNSPrefer::IPV6_ONLY => opts.push(with_only_single_stack(false)),
            DNSPrefer::IPV4_PREFER => opts.push(with_prefer_ipv4()),
            DNSPrefer::IPV6_PREFER => opts.push(with_prefer_ipv6()),
            _ => {}
        }

        if self.tfo {
            opts.push(with_tfo(true));
        }

        if self.mp_tcp {
            opts.push(with_mptcp(true));
        }

        opts
    }

    pub async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        if !metadata.resolved() {
            let ip = resolve_ip_with_resolver(ctx, &metadata.host, self.prefer, default_resolver().as_deref())
                .await
                .map_err(|e| anyhow!("can't resolve ip: {e}"))?;
            metadata.dst_ip = Some(ip);
        }
        Ok(())
    }

    pub const fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// A null value leaves the field alone instead of failing the config, matching the YAML decoder's
/// early return on null before it inspects the destination.
pub(crate) mod null_as_default {
    use serde::{Deserialize, Deserializer};

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BasicOption {
    #[serde(rename = "tfo", default, deserialize_with = "null_as_default::deserialize")]
    pub tfo: bool,
    #[serde(rename = "mptcp", default, deserialize_with = "null_as_default::deserialize")]
    pub mptcp: bool,
    #[serde(rename = "interface-name", default, deserialize_with = "null_as_default::deserialize")]
    pub interface: String,
    #[serde(rename = "routing-mark", default, deserialize_with = "null_as_default::deserialize")]
    pub routing_mark: i32,
    #[serde(rename = "ip-version", default, deserialize_with = "null_as_default::deserialize")]
    pub ip_version: DNSPrefer,
    #[serde(rename = "dialer-proxy", default, deserialize_with = "null_as_default::deserialize")]
    pub dialer_proxy: String,

    /// These fields are internal: the config decoder never assigns them.
    #[serde(skip)]
    pub dialer_for_api: Option<Arc<dyn CDialer>>,
    #[serde(skip)]
    pub tunnel_for_api: Option<Arc<dyn murmur_constant::tunnel::Tunnel>>,
    #[serde(skip)]
    pub provider_name: String,
}
impl Default for BasicOption {
    /// Every field at its reference zero value. Written out rather than derived so that adding a
    /// field to `BasicOption` cannot default silently: this impl stops compiling until the new field is
    /// named here (RUST_GUIDELINES.md section 3, functional-update struct literals).
    fn default() -> Self {
        Self {
            tfo: <bool as Default>::default(),
            mptcp: <bool as Default>::default(),
            interface: <String as Default>::default(),
            routing_mark: <i32 as Default>::default(),
            ip_version: <DNSPrefer as Default>::default(),
            dialer_proxy: <String as Default>::default(),
            dialer_for_api: <Option<Arc<dyn CDialer>> as Default>::default(),
            tunnel_for_api: <Option<Arc<dyn murmur_constant::tunnel::Tunnel>> as Default>::default(),
            provider_name: <String as Default>::default(),
        }
    }
}

impl core::fmt::Debug for BasicOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BasicOption")
            .field("tfo", &self.tfo)
            .field("mptcp", &self.mptcp)
            .field("interface", &self.interface)
            .field("routing_mark", &self.routing_mark)
            .field("ip_version", &self.ip_version)
            .field("dialer_proxy", &self.dialer_proxy)
            .field("dialer_for_api", &self.dialer_for_api.is_some())
            .field("tunnel_for_api", &self.tunnel_for_api.is_some())
            .field("provider_name", &self.provider_name)
            .finish()
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RealityOpts {
    #[serde(rename = "public-key")]
    pub public_key: String,
    #[serde(rename = "short-id", default, deserialize_with = "null_as_default::deserialize")]
    pub short_id: String,
    #[serde(rename = "support-x25519mlkem768", default, deserialize_with = "null_as_default::deserialize")]
    pub support_x25519_mlkem768: bool,
}

/// `RealityOpts`' wire form. `public-key` is required, so a block omitting it fails the config
/// (`'reality-opts' has unset fields: public-key`) rather than quietly dropping REALITY; a null
/// block decodes to the default.
#[derive(Deserialize)]
struct RealityOptsRepr {
    #[serde(rename = "public-key")]
    public_key: String,
    #[serde(rename = "short-id", default, deserialize_with = "null_as_default::deserialize")]
    short_id: String,
    #[serde(rename = "support-x25519mlkem768", default, deserialize_with = "null_as_default::deserialize")]
    support_x25519_mlkem768: bool,
}

impl<'de> Deserialize<'de> for RealityOpts {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let Some(repr) = Option::<RealityOptsRepr>::deserialize(deserializer)? else {
            return Ok(Self::default());
        };
        Ok(Self {
            public_key: repr.public_key,
            short_id: repr.short_id,
            support_x25519_mlkem768: repr.support_x25519_mlkem768,
        })
    }
}

impl RealityOpts {
    /// An empty `public-key` yields `Ok(None)`.
    ///
    /// `support_x25519mlkem768` is accepted but not acted on: the ClientHello is built by
    /// `murmur_reality::connect_reality_client`, which never offers the X25519MLKEM768 key share —
    /// the same handshake produced for the flag's `false` default.
    pub fn parse(&self) -> Result<Option<murmur_reality::RealityClientConfig>> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        if self.public_key.is_empty() {
            return Ok(None);
        }
        let decoded = URL_SAFE_NO_PAD.decode(&self.public_key).map_err(|_| anyhow!("invalid REALITY public key"))?;
        let public_key: [u8; 32] = decoded.try_into().map_err(|_| anyhow!("invalid REALITY public key"))?;

        // The bound applies to the decoded form, not the raw length, so an odd length of
        // `2 * MAX + 1` characters falls through to the hex decode and reports the decoding
        // failure instead.
        if self.short_id.len() / 2 > murmur_reality::MAX_SHORT_ID_LEN {
            return Err(anyhow!("invalid REALITY short id"));
        }
        let decoded_short_id = hex::decode(&self.short_id).map_err(|_| anyhow!("invalid REALITY short ID"))?;
        if decoded_short_id.len() > murmur_reality::MAX_SHORT_ID_LEN {
            return Err(anyhow!("invalid REALITY short ID"));
        }
        let mut short_id = [0u8; murmur_reality::MAX_SHORT_ID_LEN];
        let dest = short_id.get_mut(..decoded_short_id.len()).ok_or_else(|| anyhow!("invalid REALITY short ID"))?;
        dest.copy_from_slice(&decoded_short_id);

        Ok(Some(murmur_reality::RealityClientConfig { public_key, short_id }))
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RestlsOptions {
    #[serde(rename = "password")]
    pub password: String,
    #[serde(rename = "version-hint")]
    pub version_hint: String,
    #[serde(rename = "restls-script")]
    pub restls_script: String,
}

/// `RestlsOptions`' wire form. All three fields are optional, so a block that leaves one out
/// decodes to its zero value rather than failing the config, and a null block is a no-op.
#[derive(Deserialize)]
struct RestlsOptionsRepr {
    #[serde(rename = "password", default, deserialize_with = "null_as_default::deserialize")]
    password: String,
    #[serde(rename = "version-hint", default, deserialize_with = "null_as_default::deserialize")]
    version_hint: String,
    #[serde(rename = "restls-script", default, deserialize_with = "null_as_default::deserialize")]
    restls_script: String,
}

impl<'de> Deserialize<'de> for RestlsOptions {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let Some(repr) = Option::<RestlsOptionsRepr>::deserialize(deserializer)? else {
            return Ok(Self::default());
        };
        Ok(Self { password: repr.password, version_hint: repr.version_hint, restls_script: repr.restls_script })
    }
}

impl RestlsOptions {
    /// All three fields are optional, so unlike JLS an incomplete block is not a decode error; an
    /// unusable `version-hint` still is, because the validation happens inside the config build.
    ///
    /// `client-fingerprint` selects a uTLS `ClientHelloID` when the Restls config is built. The
    /// engine hand-builds its ClientHello, so the value could only be discarded and is not taken.
    ///
    /// `next_protos` is left empty here because `stream_tls_conn` sets it from the dialer's own
    /// `alpn`, not at parse time; every caller here reaches that same branch.
    pub fn parse(&self, server_name: &str) -> Result<Option<Arc<murmur_restls::Config>>> {
        if self.password.is_empty() && self.version_hint.is_empty() && self.restls_script.is_empty() {
            return Ok(None);
        }
        let config =
            murmur_restls::new_restls_config(server_name, &self.password, &self.version_hint, &self.restls_script)?;
        Ok(Some(Arc::new(config)))
    }
}

impl BasicOption {
    #[must_use]
    pub fn new_dialer(&self, opts: Vec<DialerOption>) -> Arc<dyn CDialer> {
        if let Some(c_dialer) = self.dialer_for_api.clone() {
            return c_dialer;
        }
        if self.dialer_proxy.is_empty() {
            Arc::new(BasicDialer(new_dialer(opts)))
        } else {
            new_by_name(self.dialer_proxy.clone(), self.new_tunnel())
        }
    }

    #[must_use]
    #[expect(clippy::expect_used, reason = "the config decoder sets `tunnel_for_api` before any dialer can call this")]
    pub fn new_tunnel(&self) -> Arc<dyn murmur_constant::tunnel::Tunnel> {
        self.tunnel_for_api.clone().expect("BasicOption.tunnel_for_api must be set before NewTunnel is called")
    }
}

/// `component::dialer::dialer::Dialer` exposes only inherent methods; this local adapter gives it
/// the `constant::adapters::Dialer` vocabulary `Base`'s dialer slot and `byname::new_by_name`
/// require, matching the precedent in `ntp::ntp::service::DefaultDialer`.
struct BasicDialer(murmur_component::dialer::dialer::Dialer);

#[async_trait]
impl CDialer for BasicDialer {
    async fn dial_context(&self, ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn Stream>> {
        self.0.dial_context(ctx, network, address).await
    }

    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
        r_addr_port: Option<SocketAddr>,
    ) -> Result<Box<dyn Datagram>> {
        self.0.listen_packet(ctx, network, address, r_addr_port).await
    }
}

/// A keep-alive marker: rewrapping the inner conn keeps the marker alive; `keep_alive` does that
/// directly instead. `stream` is wrapped in
/// `CancellableStream` so `close`/`set_*_deadline` below have a real, always-available mechanism
/// to fail a parked read/write even when the dialed `Stream` has no `old_conn` of its own (a raw
/// `TcpStream`/`TfoConn`): `Stream::shutdown_read`/`shutdown_write` alone only half-close such a
/// conn, which is a clean EOF, not the hard error a killed connection produces.
pub struct ConnWrapper {
    stream: CancellableStream<Box<dyn Stream>>,
    keep_alive: Mutex<Vec<Arc<dyn Any + Send + Sync>>>,
    chain: Mutex<Chain>,
    pd_chain: Mutex<Chain>,
    adapter_addr: String,
}

impl core::fmt::Debug for ConnWrapper {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConnWrapper")
            .field("adapter_addr", &self.adapter_addr)
            .field("keep_alive", &self.keep_alive.lock().len())
            .field("chain", &self.chain.lock().0)
            .field("pd_chain", &self.pd_chain.lock().0)
            .finish_non_exhaustive()
    }
}

impl ConnWrapper {
    fn new(stream: Box<dyn Stream>, adapter_addr: String) -> Self {
        Self {
            stream: CancellableStream::new(stream),
            keep_alive: Mutex::new(Vec::new()),
            chain: Mutex::new(Chain::default()),
            pd_chain: Mutex::new(Chain::default()),
            adapter_addr,
        }
    }

    fn remote_destination_impl(&self) -> String {
        if let Ok(remote_addr) = self.stream.peer_addr() {
            let remote_addr = murmur_std_compat::net::TcpAddr::from(remote_addr);
            let mut m = Metadata::default();
            if m.set_remote_addr(Some(&remote_addr)).is_ok() && m.valid() {
                return m.string();
            }
        }
        let (host, _, _) = split_host_port(&self.adapter_addr).unwrap_or_default();
        host
    }
}

impl AsyncRead for ConnWrapper {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for ConnWrapper {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl Stream for ConnWrapper {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.stream.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.stream.shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.stream.as_socket()
    }

    /// Forwards to the real `old_conn` when the dialed `Stream` wraps one (already-correct
    /// existing behaviour, unchanged: `close_stream` reaches the genuine innermost close). When
    /// it doesn't (DIRECT/COMPATIBLE: a raw `TcpStream`/`TfoConn`), falls back to `self`, whose
    /// own `Conn` impl below arms `stream`'s `CancellableStream` deadlines so a parked read/write
    /// actually errors out instead of silently continuing.
    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(self.stream.old_conn().unwrap_or(self))
    }
}

impl Conn for ConnWrapper {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(murmur_std_compat::net::TcpAddr::from(self.stream.local_addr()?)))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(murmur_std_compat::net::TcpAddr::from(self.stream.peer_addr()?)))
    }

    /// Only reached via [`Stream::old_conn`]'s fallback, i.e. the dialed `Stream` has no real
    /// `old_conn`: arms both deadlines to fire immediately (any parked poll fails with
    /// `TimedOut` on its next wakeup) before running the ordinary half-close.
    fn close(&self) -> io::Result<()> {
        let now = tokio::time::Instant::now();
        self.stream.read_deadline().set(Some(now));
        self.stream.write_deadline().set(Some(now));
        murmur_common_net::io::close_stream(&self.stream)
    }

    fn close_read(&self) -> io::Result<()> {
        self.stream.read_deadline().set(Some(tokio::time::Instant::now()));
        self.stream.shutdown_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.stream.write_deadline().set(Some(tokio::time::Instant::now()));
        self.stream.shutdown_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.stream.read_deadline().set(deadline);
        self.stream.write_deadline().set(deadline);
        Ok(())
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.stream.read_deadline().set(deadline);
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.stream.write_deadline().set(deadline);
        Ok(())
    }
}

impl ExtendedStream for ConnWrapper {
    fn reader_replaceable(&self) -> bool {
        true
    }

    fn writer_replaceable(&self) -> bool {
        true
    }
}

impl Connection for ConnWrapper {
    fn chains(&self) -> Chain {
        self.chain.lock().clone()
    }

    fn provider_chains(&self) -> Chain {
        self.pd_chain.lock().clone()
    }

    fn append_to_chains(&self, a: Arc<dyn CProxyAdapter>) {
        self.chain.lock().0.push(a.name());
        self.pd_chain.lock().0.push(a.proxy_info().provider_name);
    }

    fn remote_destination(&self) -> String {
        self.remote_destination_impl()
    }
}

pub trait AddRef {
    fn add_ref(&self, ref_: Arc<dyn Any + Send + Sync>);
}

impl AddRef for ConnWrapper {
    fn add_ref(&self, ref_: Arc<dyn Any + Send + Sync>) {
        self.keep_alive.lock().push(ref_);
    }
}

/// `Stream` carries no deadline API (see `io.rs`'s `CancellableStream`/
/// `IdleTimeout` combinators), so the fake-deadline wrap has nothing left to do here.
pub fn new_conn(c: Box<dyn Stream>, a: &dyn CProxyAdapter) -> Box<dyn CConn> {
    let cc = ConnWrapper::new(c, a.addr());
    cc.chain.lock().0.push(a.name());
    cc.pd_chain.lock().0.push(a.proxy_info().provider_name);
    Box::new(cc)
}

pub struct PacketConnWrapper {
    enhance: Mutex<Arc<dyn EnhancePacketConn>>,
    chain: Mutex<Chain>,
    pd_chain: Mutex<Chain>,
    adapter_name: String,
    conn_id: String,
    adapter_addr: String,
    resolver: Arc<dyn ProxyAdapter>,
}

impl core::fmt::Debug for PacketConnWrapper {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketConnWrapper")
            .field("adapter_name", &self.adapter_name)
            .field("conn_id", &self.conn_id)
            .field("adapter_addr", &self.adapter_addr)
            .field("resolver", &self.resolver.name())
            .field("chain", &self.chain.lock().0)
            .field("pd_chain", &self.pd_chain.lock().0)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PacketConn for PacketConnWrapper {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let pc = self.enhance.lock().clone();
        pc.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let pc = self.enhance.lock().clone();
        pc.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        let l_addr = self.enhance.lock().clone().local_addr()?;
        Ok(murmur_common_net::new_custom_addr(self.adapter_name.clone(), self.conn_id.clone(), l_addr))
    }

    fn close(&self) -> io::Result<()> {
        self.enhance.lock().clone().close()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.enhance.lock().clone().set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.enhance.lock().clone().set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.enhance.lock().clone().set_write_deadline(deadline)
    }
}

#[async_trait]
impl WaitReadFrom for PacketConnWrapper {
    // cancel-safe: forwards to the wrapped conn's `wait_read_from` and owns no state of its own, so dropping this future is exactly dropping the inner call.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let pc = self.enhance.lock().clone();
        pc.wait_read_from().await
    }
}

impl Connection for PacketConnWrapper {
    fn chains(&self) -> Chain {
        self.chain.lock().clone()
    }

    fn provider_chains(&self) -> Chain {
        self.pd_chain.lock().clone()
    }

    fn append_to_chains(&self, a: Arc<dyn CProxyAdapter>) {
        self.chain.lock().0.push(a.name());
        self.pd_chain.lock().0.push(a.proxy_info().provider_name);
    }

    fn remote_destination(&self) -> String {
        let (host, _, _) = split_host_port(&self.adapter_addr).unwrap_or_default();
        host
    }
}

#[async_trait]
impl CPacketConn for PacketConnWrapper {
    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.resolver.resolve_udp(ctx, metadata).await
    }
}

impl AddRef for PacketConnWrapper {
    fn add_ref(&self, ref_: Arc<dyn Any + Send + Sync>) {
        let mut guard = self.enhance.lock();
        let inner_pc = Arc::clone(&*guard).into_packet_conn();
        *guard = new_ref_packet_conn(inner_pc, ref_);
    }
}

/// `S11: remove with std-compat` shared bridge. `Arc<dyn PacketConn>` has no blanket old-`PacketConn`
/// impl the way `Box<dyn PacketConn>` does (`common_net::io::OldPacketConnAsDatagram` needs an
/// owned `PacketConn`): adding one would shadow existing `Arc<ConcreteType>` inherent methods
/// elsewhere in the tree (see `transport-shadowquic::packet::AssociationHandle`'s doc for exactly
/// that shadowing). This is the one bridge every UoT/thread-safe-packet-conn call site in this
/// crate shares instead of each defining its own copy.
struct ArcPacketConnAsDatagram(Arc<dyn PacketConn>);

#[async_trait]
impl Datagram for ArcPacketConnAsDatagram {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, addr) = self.0.read_from(buf).await?;
        Ok((n, murmur_common_net::io::old_addr_to_socket_addr(addr.as_ref())?))
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.0.write_to(buf, &murmur_common_net::io::udp_addr_from_socket_addr(addr)).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        murmur_common_net::io::old_addr_to_socket_addr(self.0.local_addr()?.as_ref())
    }

    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
}

pub(crate) fn arc_packet_conn_as_datagram(pc: Arc<dyn PacketConn>) -> Arc<dyn Datagram> {
    Arc::new(ArcPacketConnAsDatagram(pc))
}

/// `constant::adapters::PacketConn` still requires the old
/// `EnhancePacketConn` (`murmur_std_compat::net::PacketConn`-based); bridging the dial's `Datagram` through it
/// here, rather than making `PacketConnWrapper` itself old-typed, is the S10 transport-boundary
/// exception.
pub fn new_packet_conn(pc: Arc<dyn Datagram>, a: Arc<dyn ProxyAdapter>) -> Arc<dyn CPacketConn> {
    let enhanced = new_enhance_datagram(pc);
    let epc = new_deadline_enhance_packet_conn(enhanced);
    let cpc = PacketConnWrapper {
        enhance: Mutex::new(epc),
        chain: Mutex::new(Chain::default()),
        pd_chain: Mutex::new(Chain::default()),
        adapter_name: a.name(),
        conn_id: new_uuid_v4().to_string(),
        adapter_addr: a.addr(),
        resolver: a,
    };
    cpc.chain.lock().0.push(cpc.resolver.name());
    cpc.pd_chain.lock().0.push(cpc.resolver.proxy_info().provider_name);
    Arc::new(cpc)
}

/// The adapter is closed from a GC finalizer the first time it becomes
/// unreachable; Rust has no finalizers, so `Drop` (fired deterministically on the last `Arc` drop)
/// is the closest behaviour-preserving equivalent — strictly better, since it can never race a
/// pending close against a GC pause. A keep-alive guard additionally keeps the adapter alive so
/// the close cannot fire mid-use; the packet-conn half is implemented (`Arc<dyn CPacketConn>`
/// upcasts to `&dyn Any` to test for `PacketConnWrapper`), but `murmur_std_compat::net::Conn`
/// deliberately carries no such supertrait, so the `Conn`/TCP half of that guard has no
/// counterpart without changing a trait owned by another unit; recorded as a deviation, with
/// `NEEDED SHIM ITEM` in the report.
pub struct AutoCloseProxyAdapter {
    inner: Arc<dyn ProxyAdapter>,
    close_once: Once,
    close_err: Mutex<Option<String>>,
    self_weak: std::sync::Weak<Self>,
}

impl core::fmt::Debug for AutoCloseProxyAdapter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AutoCloseProxyAdapter")
            .field("name", &self.inner.name())
            .field("close_err", &self.close_err.lock())
            .finish_non_exhaustive()
    }
}

impl AutoCloseProxyAdapter {
    fn close_impl(&self) -> Result<()> {
        self.close_once.call_once(|| {
            debugln!("Closing outdated proxy [{}]", self.inner.name());
            if let Err(e) = self.inner.close() {
                *self.close_err.lock() = Some(e.to_string());
            }
        });
        match &*self.close_err.lock() {
            Some(e) => Err(anyhow!("{e}")),
            None => Ok(()),
        }
    }
}

impl Drop for AutoCloseProxyAdapter {
    fn drop(&mut self) {
        let _ = self.close_impl();
    }
}

#[async_trait]
impl CProxyAdapter for AutoCloseProxyAdapter {
    fn name(&self) -> String {
        self.inner.name()
    }

    fn type_(&self) -> AdapterType {
        self.inner.type_()
    }

    fn addr(&self) -> String {
        self.inner.addr()
    }

    fn support_udp(&self) -> bool {
        self.inner.support_udp()
    }

    fn proxy_info(&self) -> ProxyInfo {
        self.inner.proxy_info()
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.inner.marshal_json()
    }

    /// See the struct doc: the keep-alive step has no counterpart here, because
    /// `murmur_std_compat::net::Conn` carries no `as_any`.
    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        self.inner.dial_context(ctx, metadata).await
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        let pc = self.inner.listen_packet_context(ctx, metadata).await?;
        let pc_any: &dyn Any = pc.as_ref();
        if let Some(concrete) = pc_any.downcast_ref::<PacketConnWrapper>() {
            let self_arc = self
                .self_weak
                .upgrade()
                .ok_or_else(|| anyhow!("AutoCloseProxyAdapter dropped while listen_packet_context is running"))?;
            concrete.add_ref(self_arc);
        }
        Ok(pc)
    }

    fn support_uot(&self) -> bool {
        self.inner.support_uot()
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.inner.is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.inner.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        self.close_impl()
    }
}

#[async_trait]
impl ProxyAdapter for AutoCloseProxyAdapter {
    fn dial_options(&self) -> Vec<DialerOption> {
        self.inner.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.inner.resolve_udp(ctx, metadata).await
    }
}

/// Uses `Arc::new_cyclic` to give the adapter a `Weak` handle to itself, which
/// `listen_packet_context` upgrades to the keep-alive.
pub fn new_auto_close_proxy_adapter(adapter: Arc<dyn ProxyAdapter>) -> Arc<dyn ProxyAdapter> {
    Arc::new_cyclic(|self_weak| AutoCloseProxyAdapter {
        inner: adapter,
        close_once: Once::new(),
        close_err: Mutex::new(None),
        self_weak: std::sync::Weak::clone(self_weak),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[derive(Debug, Deserialize)]
    struct TlsOptions {
        #[serde(rename = "reality-opts", default)]
        reality_opts: RealityOpts,
        #[serde(rename = "jls-opts", default)]
        jls_opts: crate::jls::JlsOptions,
        #[serde(rename = "restls-opts", default)]
        restls_opts: RestlsOptions,
    }

    fn parse(yaml: &str) -> serde_yaml::Result<TlsOptions> {
        serde_yaml::from_str(yaml)
    }

    fn reality_cfg(short_id: &str) -> Result<Option<murmur_reality::RealityClientConfig>> {
        RealityOpts { public_key: PUBLIC_KEY.to_owned(), short_id: short_id.to_owned(), support_x25519_mlkem768: false }
            .parse()
    }

    #[test]
    fn blocks_with_unset_fields_are_accepted() {
        for yaml in [
            "{}\n",
            "reality-opts: null\njls-opts: null\nrestls-opts: null\n",
            "restls-opts: {}\n",
            "restls-opts:\n  password: \"\"\n",
            "jls-opts:\n  username: \"\"\n  password: \"\"\n",
            "jls-opts:\n  username: null\n  password: null\n",
        ] {
            parse(yaml).unwrap_or_else(|err| panic!("{yaml:?} must not enable an option: {err}"));
        }
        assert!(parse("jls-opts: {}\n").is_err());
        assert!(parse("jls-opts:\n  username: u\n").is_err());
        assert!(parse("jls-opts:\n  password: p\n").is_err());
    }

    #[test]
    fn restls_credentials_select_restls_and_an_undeclared_key_is_ignored() {
        let holder = parse("restls-opts:\n  pass: p\n  password: p\n  version-hint: tls13\n").expect("decodes");
        let config = holder.restls_opts.parse("example.com").expect("parses");
        let config = config.expect("selects Restls");
        assert_eq!(config.server_name, "example.com");

        // All three fields are optional, so a block of only undeclared keys decodes to an empty
        // struct and the parse returns `None` — no security mode, no error.
        let holder = parse("restls-opts:\n  pass: p\n").expect("decodes");
        assert!(holder.restls_opts.parse("example.com").expect("parses").is_none());
    }

    #[test]
    fn a_configured_restls_block_with_an_unusable_version_hint_is_rejected() {
        let holder = parse("restls-opts:\n  password: p\n  version-hint: tls11\n").expect("decodes");
        let Err(err) = holder.restls_opts.parse("example.com") else {
            panic!("an unusable version-hint must be rejected");
        };
        let err = err.to_string();
        assert!(err.contains("invalid version hint"), "{err}");
    }

    #[test]
    fn a_restls_version_hint_alone_selects_restls_and_the_block_parses_script_and_server_name() {
        let holder =
            parse("restls-opts:\n  version-hint: tls12\n  restls-script: 250?100<1,350~100\n").expect("decodes");
        let config = holder.restls_opts.parse("sni.example").expect("parses");
        let config = config.expect("selects Restls");
        assert_eq!(config.server_name, "sni.example");
        // Session tickets stay enabled for the TLS 1.2 hint and are disabled otherwise.
        assert!(!config.session_tickets_disabled);
    }

    #[test]
    fn jls_credentials_decode_instead_of_being_rejected() {
        let holder = parse("jls-opts:\n  username: u\n  password: p\n").expect("decodes");
        let config = holder.jls_opts.parse().expect("parses").expect("selects JLS");
        assert_eq!(config.user.username, "u");
        assert_eq!(config.user.password, "p");
    }

    #[test]
    fn a_reality_block_present_without_a_public_key_is_rejected() {
        let err = parse("reality-opts:\n  short-id: ab\n").unwrap_err();
        assert!(err.to_string().contains("public-key"), "{err}");
        assert!(parse("reality-opts:\n  public-key: \"\"\n").unwrap().reality_opts.parse().unwrap().is_none());
    }

    #[test]
    fn a_reality_short_id_past_the_decoded_length_bound_is_rejected() {
        // The bound applies to the decoded form, so 18 hex characters trip it and 17 fail in the
        // hex decode it guards.
        let err = |short_id: String| reality_cfg(&short_id).expect_err("rejected").to_string();
        assert_eq!(err("ab".repeat(9)), "invalid REALITY short id");
        assert_eq!(err(format!("{}a", "ab".repeat(8))), "invalid REALITY short ID");
        assert!(reality_cfg(&"ab".repeat(8)).unwrap().is_some());
    }

    #[derive(Deserialize)]
    struct FlattenedOption {
        #[serde(rename = "name")]
        _name: String,
        #[serde(flatten)]
        basic_option: BasicOption,
    }

    #[test]
    fn null_option_values_leave_the_field_at_its_zero_value() {
        let yaml = concat!(
            "name: p\n",
            "tfo: null\n",
            "mptcp: null\n",
            "interface-name: null\n",
            "routing-mark: null\n",
            "ip-version: null\n",
            "dialer-proxy: null\n",
        );
        let direct: BasicOption = serde_yaml::from_str(yaml).unwrap();
        let flattened: FlattenedOption = serde_yaml::from_str(yaml).unwrap();

        assert!(!direct.tfo && !flattened.basic_option.tfo);
        assert!(direct.interface.is_empty() && direct.dialer_proxy.is_empty() && direct.routing_mark == 0);
        assert_eq!(direct.ip_version, DNSPrefer::default());
    }
}

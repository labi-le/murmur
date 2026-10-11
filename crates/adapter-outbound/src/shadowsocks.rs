//! The Shadowsocks method interface is not available from any crate in this tree.
//!
//! `NEEDED CRATE: sing-shadowsocks2` would provide it; the destination-header framing that method
//! implements is implemented locally in [`Method`], atop
//! `murmur_transport_shadowsocks::core::cipher::pick_cipher`. The uot half is `murmur_sing::uot`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context as TaskContext, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use crate::ech::ECHOptions;
use murmur_common::shared_conn::SharedConn;
use murmur_common::structure::structure as structure_mod;
use murmur_common_net::{
    new_bind_packet_conn, new_enhance_packet_conn, new_thread_safe_packet_conn, setup_context_for_conn,
    EnhancePacketConn,
};
use murmur_constant::adapters::AdapterType;
use murmur_constant::adapters::{
    Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_sing::metadata::{parse_socksaddr_host_port, socksaddr_from_net, Socksaddr};
use murmur_sing::uot;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn};
use murmur_transport::gost::websocket as gost;
use murmur_transport::v2ray_plugin::websocket as v2ray_obfs;
use murmur_transport_jls::client as jls;
use murmur_transport_kcptun::client as kcptun;
use murmur_transport_kcptun::common as kcptun_common;
use murmur_transport_shadowsocks::core::cipher::{pick_cipher, Cipher};
use murmur_transport_shadowsocks::shadowaead_2022::client as ss2022_client;
use murmur_transport_shadowtls::client as shadowtls;
use murmur_transport_simple_obfs::{http as simple_obfs_http, tls as simple_obfs_tls};

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::util::{resolve_udp_addr, safe_conn_close};

const ATYP_IPV4: u8 = murmur_transport::socks5::socks5::ATYP_IPV4;
const ATYP_IPV6: u8 = murmur_transport::socks5::socks5::ATYP_IPV6;
const ATYP_DOMAIN_NAME: u8 = murmur_transport::socks5::socks5::ATYP_DOMAIN_NAME;

pub struct ShadowSocks {
    base: Base,
    method: Method,

    option: ShadowSocksOption,
    obfs_mode: String,
    obfs_option: Option<SimpleObfsOption>,
    v2ray_option: Option<v2ray_obfs::Option>,
    gost_option: Option<gost::Option>,
    shadow_tls_option: Option<shadowtls::ShadowTLSOption>,
    restls_config: Option<Arc<murmur_restls::Config>>,
    jls_option: Option<jls::ClientConfig>,
    kcptun_client: Option<kcptun::Client>,

    self_weak: Weak<Self>,
}

impl core::fmt::Debug for ShadowSocks {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShadowSocks").field("obfs_mode", &self.obfs_mode).finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ShadowSocksOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server")]
    pub server: String,
    #[serde(rename = "port")]
    pub port: i32,
    #[serde(rename = "password")]
    pub password: String,
    #[serde(rename = "cipher")]
    pub cipher: String,
    #[serde(rename = "udp", default)]
    pub udp: bool,
    #[serde(rename = "plugin", default)]
    pub plugin: String,
    #[serde(rename = "plugin-opts", default)]
    pub plugin_opts: serde_yaml::Mapping,
    #[serde(rename = "udp-over-tcp", default)]
    pub udp_over_tcp: bool,
    #[serde(rename = "udp-over-tcp-version", default)]
    pub udp_over_tcp_version: i32,
    #[serde(rename = "client-fingerprint", default)]
    pub client_fingerprint: String,
}

impl core::fmt::Debug for ShadowSocksOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShadowSocksOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("password", &"[redacted]")
            .field("cipher", &self.cipher)
            .field("udp", &self.udp)
            .field("plugin", &self.plugin)
            .field("udp_over_tcp", &self.udp_over_tcp)
            .field("udp_over_tcp_version", &self.udp_over_tcp_version)
            .field("client_fingerprint", &self.client_fingerprint)
            .finish_non_exhaustive()
    }
}

fn default_bing_host() -> String {
    "bing.com".to_owned()
}

const fn default_true() -> bool {
    true
}

const fn default_shadowtls_version() -> i32 {
    2
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct SimpleObfsOption {
    #[serde(rename = "mode", default)]
    pub(crate) mode: String,
    #[serde(rename = "host", default = "default_bing_host")]
    pub(crate) host: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the option struct mirrors the plugin's flag set key for key, so the bools stay separate"
)]
struct V2rayObfsOption {
    #[serde(rename = "mode")]
    mode: String,
    #[serde(rename = "host", default = "default_bing_host")]
    host: String,
    #[serde(rename = "path", default)]
    path: String,
    #[serde(rename = "tls", default)]
    tls: bool,
    #[serde(rename = "ech-opts", default)]
    ech_opts: ECHOptions,
    #[serde(rename = "fingerprint", default)]
    fingerprint: String,
    #[serde(rename = "certificate", default)]
    certificate: String,
    #[serde(rename = "private-key", default)]
    private_key: String,
    #[serde(rename = "headers", default)]
    headers: HashMap<String, String>,
    #[serde(rename = "skip-cert-verify", default)]
    skip_cert_verify: bool,
    #[serde(rename = "name-cert-verify", default)]
    name_cert_verify: String,
    #[serde(rename = "mux", default = "default_true")]
    mux: bool,
    #[serde(rename = "v2ray-http-upgrade", default)]
    v2ray_http_upgrade: bool,
    #[serde(rename = "v2ray-http-upgrade-fast-open", default)]
    v2ray_http_upgrade_fast_open: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct RestlsOption {
    #[serde(rename = "password")]
    pub(crate) password: String,
    #[serde(rename = "host")]
    pub(crate) host: String,
    #[serde(rename = "version-hint")]
    pub(crate) version_hint: String,
    #[serde(rename = "restls-script")]
    pub(crate) restls_script: String,
    #[serde(rename = "fingerprint")]
    pub(crate) fingerprint: String,
    #[serde(rename = "skip-cert-verify")]
    pub(crate) skip_cert_verify: bool,
    #[serde(rename = "name-cert-verify")]
    pub(crate) name_cert_verify: String,
    #[serde(rename = "force-tls12")]
    pub(crate) force_tls12: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct GostObfsOption {
    #[serde(rename = "mode")]
    mode: String,
    #[serde(rename = "host", default = "default_bing_host")]
    host: String,
    #[serde(rename = "path", default)]
    path: String,
    #[serde(rename = "tls", default)]
    tls: bool,
    #[serde(rename = "ech-opts", default)]
    ech_opts: ECHOptions,
    #[serde(rename = "fingerprint", default)]
    fingerprint: String,
    #[serde(rename = "certificate", default)]
    certificate: String,
    #[serde(rename = "private-key", default)]
    private_key: String,
    #[serde(rename = "headers", default)]
    headers: HashMap<String, String>,
    #[serde(rename = "skip-cert-verify", default)]
    skip_cert_verify: bool,
    #[serde(rename = "name-cert-verify", default)]
    name_cert_verify: String,
    #[serde(rename = "mux", default = "default_true")]
    mux: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct ShadowTLSOption {
    #[serde(rename = "password", default)]
    pub(crate) password: String,
    #[serde(rename = "host")]
    pub(crate) host: String,
    #[serde(rename = "fingerprint", default)]
    pub(crate) fingerprint: String,
    #[serde(rename = "certificate", default)]
    pub(crate) certificate: String,
    #[serde(rename = "private-key", default)]
    pub(crate) private_key: String,
    #[serde(rename = "skip-cert-verify", default)]
    pub(crate) skip_cert_verify: bool,
    #[serde(rename = "name-cert-verify", default)]
    pub(crate) name_cert_verify: String,
    #[serde(rename = "version", default = "default_shadowtls_version")]
    pub(crate) version: i32,
    #[serde(rename = "alpn", default)]
    pub(crate) alpn: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct JlsOption {
    #[serde(rename = "host")]
    pub(crate) host: String,
    #[serde(rename = "username", default)]
    pub(crate) username: String,
    #[serde(rename = "password", default)]
    pub(crate) password: String,
    #[serde(rename = "alpn", default)]
    pub(crate) alpn: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct KcpTunOption {
    #[serde(rename = "key", default)]
    key: String,
    #[serde(rename = "crypt", default)]
    crypt: String,
    #[serde(rename = "mode", default)]
    mode: String,
    #[serde(rename = "conn", default)]
    conn: i32,
    #[serde(rename = "autoexpire", default)]
    auto_expire: i32,
    #[serde(rename = "scavengettl", default)]
    scavenge_ttl: i32,
    #[serde(rename = "mtu", default)]
    mtu: i32,
    #[serde(rename = "ratelimit", default)]
    rate_limit: i32,
    #[serde(rename = "sndwnd", default)]
    snd_wnd: i32,
    #[serde(rename = "rcvwnd", default)]
    rcv_wnd: i32,
    #[serde(rename = "datashard", default)]
    data_shard: i32,
    #[serde(rename = "parityshard", default)]
    parity_shard: i32,
    #[serde(rename = "dscp", default)]
    dscp: i32,
    #[serde(rename = "nocomp", default)]
    no_comp: bool,
    #[serde(rename = "acknodelay", default)]
    ack_nodelay: bool,
    #[serde(rename = "nodelay", default)]
    no_delay: i32,
    #[serde(rename = "interval", default)]
    interval: i32,
    #[serde(rename = "resend", default)]
    resend: i32,
    #[serde(rename = "nc", default)]
    no_congestion: i32,
    #[serde(rename = "sockbuf", default)]
    sock_buf: i32,
    #[serde(rename = "smuxver", default)]
    smux_ver: i32,
    #[serde(rename = "smuxbuf", default)]
    smux_buf: i32,
    #[serde(rename = "framesize", default)]
    frame_size: i32,
    #[serde(rename = "streambuf", default)]
    stream_buf: i32,
    #[serde(rename = "keepalive", default)]
    keep_alive: i32,
}

fn to_io_error(err: anyhow::Error) -> io::Error {
    io::Error::other(err)
}

fn encode_socksaddr_header(dest: &Socksaddr) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    if dest.is_fqdn() {
        buf.push(ATYP_DOMAIN_NAME);
        buf.push(u8::try_from(dest.fqdn.len()).map_err(|_| anyhow!("shadowsocks: fqdn too long"))?);
        buf.extend_from_slice(dest.fqdn.as_bytes());
    } else {
        match dest.addr {
            Some(IpAddr::V4(v4)) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            Some(IpAddr::V6(v6)) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
            None => return Err(anyhow!("shadowsocks: invalid destination")),
        }
    }
    buf.push((dest.port >> 8) as u8);
    buf.push((dest.port & 0xff) as u8);
    Ok(buf)
}

fn decode_socksaddr_header(buf: &[u8]) -> Result<(Socksaddr, usize)> {
    let Some((&atyp, rest)) = buf.split_first() else {
        return Err(anyhow!("shadowsocks: empty destination header"));
    };
    match atyp {
        ATYP_DOMAIN_NAME => {
            let Some((&len, rest)) = rest.split_first() else {
                return Err(anyhow!("shadowsocks: short destination header"));
            };
            let len = usize::from(len);
            let Some((fqdn_bytes, port_bytes)) = rest.split_at_checked(len) else {
                return Err(anyhow!("shadowsocks: short destination header"));
            };
            let Some(&[hi, lo]) = port_bytes.first_chunk::<2>() else {
                return Err(anyhow!("shadowsocks: short destination header"));
            };
            let fqdn = String::from_utf8_lossy(fqdn_bytes).into_owned();
            Ok((Socksaddr::fqdn(fqdn, u16::from_be_bytes([hi, lo])), 2 + len + 2))
        }
        ATYP_IPV4 => {
            let Some(&[a, b, c, d, hi, lo]) = rest.first_chunk::<6>() else {
                return Err(anyhow!("shadowsocks: short destination header"));
            };
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            Ok((Socksaddr::from_ip(ip, u16::from_be_bytes([hi, lo])), 7))
        }
        ATYP_IPV6 => {
            let Some((&octets, port_bytes)) = rest.split_first_chunk::<16>() else {
                return Err(anyhow!("shadowsocks: short destination header"));
            };
            let Some(&[hi, lo]) = port_bytes.first_chunk::<2>() else {
                return Err(anyhow!("shadowsocks: short destination header"));
            };
            let ip = IpAddr::V6(Ipv6Addr::from(octets));
            Ok((Socksaddr::from_ip(ip, u16::from_be_bytes([hi, lo])), 19))
        }
        other => Err(anyhow!("shadowsocks: unknown address type {other}")),
    }
}

#[derive(Debug, Clone)]
struct SocksaddrNetAddr(Socksaddr);

impl Addr for SocksaddrNetAddr {
    fn network(&self) -> &'static str {
        "udp"
    }

    fn string(&self) -> String {
        self.0.string()
    }
}

fn socksaddr_to_addr(dest: Socksaddr) -> Box<dyn Addr> {
    match dest.udp_addr() {
        Some(addr) => Box::new(addr),
        None => Box::new(SocksaddrNetAddr(dest)),
    }
}

/// Every obfs mode that needs a handshake already set `use_early` above, before this call, so only
/// the websocket modes could still move the term. `murmur_std_compat::net::Conn`
/// carries no identity accessor, so the `Box<dyn NetConn>` arriving here is not walkable at all
/// until the `Method` chain leaves the std-compat traits.
fn need_handshake(_conn: &dyn NetConn) -> bool {
    false
}

enum PendingHeader {
    Destination(Socksaddr),
}

impl PendingHeader {
    fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Destination(dest) => encode_socksaddr_header(dest),
        }
    }
}

enum WriteState {
    Pending(PendingHeader),
    InFlight { data: Vec<u8>, offset: usize, want: usize },
    Done,
}

/// The header is combined with the first payload write and sent as one write call, deferred until
/// that first call.
struct LazyHeaderConn {
    conn: Box<dyn NetConn>,
    state: WriteState,
}

impl LazyHeaderConn {
    fn new(conn: Box<dyn NetConn>, header: PendingHeader) -> Self {
        Self { conn, state: WriteState::Pending(header) }
    }
}

impl AsyncRead for LazyHeaderConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for LazyHeaderConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                WriteState::Done => return Pin::new(&mut this.conn).poll_write(cx, buf),
                WriteState::Pending(header) => {
                    let mut data = header.encode().map_err(to_io_error)?;
                    let want = buf.len();
                    data.extend_from_slice(buf);
                    this.state = WriteState::InFlight { data, offset: 0, want };
                }
                WriteState::InFlight { data, offset, want } => {
                    while *offset < data.len() {
                        let Some(remaining) = data.get(*offset..) else {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        };
                        match Pin::new(&mut this.conn).poll_write(cx, remaining) {
                            Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                            Poll::Ready(Ok(n)) => *offset += n,
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        }
                    }
                    let want = *want;
                    this.state = WriteState::Done;
                    return Poll::Ready(Ok(want));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl NetConn for LazyHeaderConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.remote_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.conn.close()
    }

    fn close_read(&self) -> io::Result<()> {
        self.conn.close_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.conn.close_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_write_deadline(deadline)
    }
}

/// The bound remote a packet conn was built over, exposed as a `PacketConn`:
/// each read/write is exactly one datagram to/from the bound remote.
struct BoundPacketConnAdapter {
    conn: SharedConn,
}

impl BoundPacketConnAdapter {
    fn new(conn: Box<dyn NetConn>) -> Self {
        Self { conn: SharedConn::from_boxed(conn) }
    }
}

#[async_trait]
impl PacketConn for BoundPacketConnAdapter {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let n = self.conn.read(buf).await?;
        Ok((n, self.conn.remote_addr()?))
    }

    async fn write_to(&self, buf: &[u8], _addr: &dyn Addr) -> io::Result<usize> {
        self.conn.write_all(buf).await?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.conn.close()
    }
}

const MAX_UDP_PACKET: usize = 64 * 1024;

/// Prepends/strips the destination header the raw AEAD packet cipher
/// (`self.inner`) does not know about.
struct SsClientPacketConn {
    inner: Arc<dyn EnhancePacketConn>,
}

#[async_trait]
impl PacketConn for SsClientPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut tmp = vec![0u8; MAX_UDP_PACKET];
        let (n, _from) = self.inner.read_from(&mut tmp).await?;
        tmp.truncate(n);
        let (destination, consumed) = decode_socksaddr_header(&tmp).map_err(to_io_error)?;
        let Some(payload) = tmp.get(consumed..) else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "shadowsocks: udp short buffer"));
        };
        let Some(dst) = buf.get_mut(..payload.len()) else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "shadowsocks: udp short buffer"));
        };
        dst.copy_from_slice(payload);
        Ok((payload.len(), socksaddr_to_addr(destination)))
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let destination = socksaddr_from_net(Some(addr));
        let mut plaintext = encode_socksaddr_header(&destination).map_err(to_io_error)?;
        plaintext.extend_from_slice(buf);
        self.inner.write_to(&plaintext, addr).await?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.inner.close()
    }
}

/// `Method`. The classic-cipher branch is reimplemented
/// locally atop `murmur_transport_shadowsocks::core::cipher::pick_cipher` (see the module doc);
/// the `2022-blake3-*` branch wires in `murmur_transport_shadowsocks::shadowaead_2022::client`.
enum Method {
    Classic(Box<dyn Cipher>),
    Aead2022(Arc<ss2022_client::ClientMethod>),
}

/// Adapts `Arc<dyn EnhancePacketConn>` (what [`ss2022_client::ClientMethod::dial_packet_conn`]
/// returns) down to the `Arc<dyn PacketConn>` [`Method::dial_packet_conn`] must return; the two
/// traits have no supertrait relationship the compiler can upcast automatically.
struct AeadPacketConn(Arc<dyn EnhancePacketConn>);

#[async_trait]
impl PacketConn for AeadPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.0.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.0.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
}

impl Method {
    async fn dial_conn(&self, conn: Box<dyn NetConn>, destination: Socksaddr) -> Result<Box<dyn NetConn>> {
        match self {
            Self::Classic(cipher) => {
                let stream = cipher.stream_conn(conn)?;
                let shared = SharedConn::from_boxed(stream);
                let header = encode_socksaddr_header(&destination)?;
                shared.write_all(&header).await?;
                Ok(Box::new(shared))
            }
            Self::Aead2022(method) => {
                let stream =
                    method.dial_conn(Box::new(murmur_common_net::io::OldConnAsStream(conn)), destination).await?;
                Ok(Box::new(murmur_common_net::io::StreamAsOldConn::new(stream)))
            }
        }
    }

    fn dial_early_conn(&self, conn: Box<dyn NetConn>, destination: Socksaddr) -> Result<Box<dyn NetConn>> {
        match self {
            Self::Classic(cipher) => {
                let stream = cipher.stream_conn(conn)?;
                Ok(Box::new(LazyHeaderConn::new(stream, PendingHeader::Destination(destination))))
            }
            Self::Aead2022(method) => {
                let stream =
                    method.dial_early_conn(Box::new(murmur_common_net::io::OldConnAsStream(conn)), destination);
                Ok(Box::new(murmur_common_net::io::StreamAsOldConn::new(stream)))
            }
        }
    }

    fn dial_packet_conn(&self, conn: Box<dyn NetConn>) -> Result<Arc<dyn PacketConn>> {
        let adapter: Arc<dyn EnhancePacketConn> = new_enhance_packet_conn(Arc::new(BoundPacketConnAdapter::new(conn)));
        match self {
            Self::Classic(cipher) => {
                let ciphered = cipher.packet_conn(adapter)?;
                Ok(Arc::new(SsClientPacketConn { inner: ciphered }))
            }
            Self::Aead2022(method) => Ok(Arc::new(AeadPacketConn(method.dial_packet_conn(adapter)))),
        }
    }
}

impl ShadowSocks {
    #[expect(
        clippy::too_many_lines,
        reason = "linear plugin-dispatch sequence; splitting it would obscure the option resolution order"
    )]
    pub fn new(mut option: ShadowSocksOption) -> Result<Arc<Self>> {
        let addr = murmur_component::dialer::bind::join_host_port(&option.server, option.port);
        // The dispatcher this `Method` stands in for (see the module doc) special-cases "none" the
        // same way `listener::sing_shadowsocks::server` does for the inbound side; `pick_cipher`
        // itself only recognizes "DUMMY".
        let method = if option.cipher.starts_with("2022-blake3-") {
            Method::Aead2022(
                ss2022_client::ClientMethod::new(&option.cipher, &option.password)
                    .map_err(|err| anyhow!("ss {addr} cipher: {} initialize error: {err}", option.cipher))?,
            )
        } else {
            let pick_cipher_name = if option.cipher == "none" { "dummy" } else { option.cipher.as_str() };
            let cipher = pick_cipher(pick_cipher_name, None, &option.password)
                .map_err(|err| anyhow!("ss {addr} cipher: {} initialize error: {err}", option.cipher))?;
            Method::Classic(cipher)
        };

        let mut v2ray_option = None;
        let mut gost_option = None;
        let mut obfs_option = None;
        let mut shadow_tls_option = None;
        let mut restls_config: Option<Arc<murmur_restls::Config>> = None;
        let mut jls_option: Option<jls::ClientConfig> = None;
        let mut kcptun_client = None;
        let mut obfs_mode = String::new();

        let decoder = structure_mod::new_decoder(structure_mod::Option {
            tag_name: "obfs".to_owned(),
            weakly_typed_input: true,
            key_replacer: None,
        });

        match option.plugin.as_str() {
            "obfs" => {
                let opts: SimpleObfsOption = decoder
                    .decode(&option.plugin_opts)
                    .map_err(|err| anyhow!("ss {addr} initialize obfs error: {err}"))?;
                if opts.mode != "tls" && opts.mode != "http" {
                    return Err(anyhow!("ss {addr} obfs mode error: {}", opts.mode));
                }
                obfs_mode.clone_from(&opts.mode);
                obfs_option = Some(opts);
            }
            "v2ray-plugin" => {
                let opts: V2rayObfsOption = decoder
                    .decode(&option.plugin_opts)
                    .map_err(|err| anyhow!("ss {addr} initialize v2ray-plugin error: {err}"))?;
                if opts.mode != "websocket" {
                    return Err(anyhow!("ss {addr} obfs mode error: {}", opts.mode));
                }
                obfs_mode.clone_from(&opts.mode);
                let mut opt = v2ray_obfs::Option {
                    host: opts.host.clone(),
                    path: opts.path.clone(),
                    headers: opts.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                    mux: opts.mux,
                    v2ray_http_upgrade: opts.v2ray_http_upgrade,
                    v2ray_http_upgrade_fast_open: opts.v2ray_http_upgrade_fast_open,
                    port: String::new(),
                    tls: false,
                    ech_config: None,
                    skip_cert_verify: false,
                    name_cert_verify: String::new(),
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                };
                if opts.tls {
                    opt.tls = true;
                    opt.skip_cert_verify = opts.skip_cert_verify;
                    opt.name_cert_verify.clone_from(&opts.name_cert_verify);
                    opt.fingerprint.clone_from(&opts.fingerprint);
                    opt.certificate.clone_from(&opts.certificate);
                    opt.private_key.clone_from(&opts.private_key);
                    let ech_config = opts
                        .ech_opts
                        .parse()
                        .map_err(|err| anyhow!("ss {addr} initialize v2ray-plugin error: {err}"))?;
                    opt.ech_config = ech_config.map(Arc::new);
                }
                v2ray_option = Some(opt);
            }
            "gost-plugin" => {
                let opts: GostObfsOption = decoder
                    .decode(&option.plugin_opts)
                    .map_err(|err| anyhow!("ss {addr} initialize gost-plugin error: {err}"))?;
                if opts.mode != "websocket" {
                    return Err(anyhow!("ss {addr} obfs mode error: {}", opts.mode));
                }
                obfs_mode.clone_from(&opts.mode);
                let mut opt = gost::Option {
                    host: opts.host.clone(),
                    path: opts.path.clone(),
                    headers: opts.headers.clone(),
                    mux: opts.mux,
                    port: String::new(),
                    tls: false,
                    ech_config: None,
                    skip_cert_verify: false,
                    name_cert_verify: String::new(),
                    fingerprint: String::new(),
                    certificate: String::new(),
                    private_key: String::new(),
                };
                if opts.tls {
                    opt.tls = true;
                    opt.skip_cert_verify = opts.skip_cert_verify;
                    opt.name_cert_verify.clone_from(&opts.name_cert_verify);
                    opt.fingerprint.clone_from(&opts.fingerprint);
                    opt.certificate.clone_from(&opts.certificate);
                    opt.private_key.clone_from(&opts.private_key);
                    let ech_config = opts
                        .ech_opts
                        .parse()
                        .map_err(|err| anyhow!("ss {addr} initialize gost-plugin error: {err}"))?;
                    opt.ech_config = ech_config.map(Arc::new);
                }
                gost_option = Some(opt);
            }
            mode if mode == shadowtls::MODE => {
                shadowtls::MODE.clone_into(&mut obfs_mode);
                let opt: ShadowTLSOption = decoder
                    .decode(&option.plugin_opts)
                    .map_err(|err| anyhow!("ss {addr} initialize shadow-tls-plugin error: {err}"))?;
                let alpn = match opt.alpn {
                    Some(alpn) => alpn,
                    None => shadowtls::DEFAULT_ALPN.clone(),
                };
                shadow_tls_option = Some(shadowtls::ShadowTLSOption {
                    password: opt.password,
                    host: opt.host,
                    fingerprint: opt.fingerprint,
                    certificate: opt.certificate,
                    private_key: opt.private_key,
                    client_fingerprint: option.client_fingerprint.clone(),
                    skip_cert_verify: opt.skip_cert_verify,
                    name_cert_verify: opt.name_cert_verify,
                    version: opt.version,
                    alpn,
                });
            }
            "restls" => {
                "restls".clone_into(&mut obfs_mode);
                let opt: RestlsOption = decoder
                    .decode(&option.plugin_opts)
                    .map_err(|err| anyhow!("ss {addr} initialize restls-plugin error: {err}"))?;
                let version_hint = if opt.force_tls12 { "tls12" } else { opt.version_hint.as_str() };
                let mut config =
                    murmur_restls::new_restls_config(&opt.host, &opt.password, version_hint, &opt.restls_script)
                        .map_err(|err| anyhow!("ss {addr} initialize restls-plugin error: {err}"))?;
                config.insecure_skip_verify = opt.skip_cert_verify;
                if !opt.fingerprint.is_empty() {
                    murmur_restls::config::set_fingerprint(&mut config, &opt.fingerprint, &opt.name_cert_verify)
                        .map_err(|err| anyhow!("ss {addr} initialize restls-plugin error: {err}"))?;
                } else if !opt.name_cert_verify.is_empty() {
                    murmur_restls::config::set_name_cert_verify(&mut config, &opt.name_cert_verify);
                }
                restls_config = Some(Arc::new(config));
            }
            mode if mode == jls::MODE => {
                jls::MODE.clone_into(&mut obfs_mode);
                let opt: JlsOption = decoder
                    .decode(&option.plugin_opts)
                    .map_err(|err| anyhow!("ss {addr} initialize jls-plugin error: {err}"))?;
                jls_option = Some(
                    jls::new_client_config(&opt.host, &opt.username, &opt.password, opt.alpn)
                        .map_err(|err| anyhow!("ss {addr} initialize jls-plugin error: {err}"))?,
                );
            }
            mode if mode == kcptun::MODE => {
                kcptun::MODE.clone_into(&mut obfs_mode);
                let opt: KcpTunOption = decoder
                    .decode(&option.plugin_opts)
                    .map_err(|err| anyhow!("ss {addr} initialize kcptun-plugin error: {err}"))?;
                let config = kcptun_common::Config {
                    key: opt.key,
                    crypt: opt.crypt,
                    mode: opt.mode,
                    conn: opt.conn,
                    auto_expire: opt.auto_expire,
                    scavenge_ttl: opt.scavenge_ttl,
                    mtu: opt.mtu,
                    rate_limit: opt.rate_limit,
                    snd_wnd: opt.snd_wnd,
                    rcv_wnd: opt.rcv_wnd,
                    data_shard: opt.data_shard,
                    parity_shard: opt.parity_shard,
                    dscp: opt.dscp,
                    no_comp: opt.no_comp,
                    ack_nodelay: opt.ack_nodelay,
                    no_delay: opt.no_delay,
                    interval: opt.interval,
                    resend: opt.resend,
                    no_congestion: opt.no_congestion,
                    sock_buf: opt.sock_buf,
                    smux_ver: opt.smux_ver,
                    smux_buf: opt.smux_buf,
                    frame_size: opt.frame_size,
                    stream_buf: opt.stream_buf,
                    keep_alive: opt.keep_alive,
                };
                kcptun_client = Some(kcptun::Client::new(config));
                option.udp_over_tcp = true;
            }
            _ => {}
        }

        match option.udp_over_tcp_version {
            v if v == i32::from(uot::VERSION) || v == i32::from(uot::LEGACY_VERSION) => {}
            0 => option.udp_over_tcp_version = i32::from(uot::LEGACY_VERSION),
            _ => {
                return Err(anyhow!(
                    "ss {addr} unknown udp over tcp protocol version: {}",
                    option.udp_over_tcp_version
                ));
            }
        }

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr,
            type_: AdapterType::SHADOWSOCKS,
            provider_name: option.basic_option.provider_name.clone(),
            udp: option.udp,
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
            xudp: false,
        });
        base.dialer = Some(option.basic_option.new_dialer(base.dial_options()));

        Ok(Arc::new_cyclic(|self_weak| Self {
            base,
            method,
            obfs_mode,
            v2ray_option,
            gost_option,
            obfs_option,
            shadow_tls_option,
            restls_config,
            jls_option,
            kcptun_client,
            self_weak: Weak::clone(self_weak),
            option,
        }))
    }
    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("ShadowSocks adapter dropped while still in use"))
    }

    async fn stream_conn_context(
        &self,
        ctx: &CancellationToken,
        mut c: Box<dyn NetConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn NetConn>> {
        // NOT cancel-safe: the restls handshake consumes the connection, so a drop loses it.
        let mut use_early = false;
        match self.obfs_mode.as_str() {
            "tls" => {
                let opts = self.obfs_option.as_ref().ok_or_else(|| anyhow!("obfs_option set for tls mode"))?;
                let host = opts.host.clone();
                c = simple_obfs_tls::new_tls_obfs(c, host);
            }
            "http" => {
                let (_, port, _) = murmur_common_net::split_host_port(&self.base.addr).unwrap_or_default();
                let opts = self.obfs_option.as_ref().ok_or_else(|| anyhow!("obfs_option set for http mode"))?;
                let host = opts.host.clone();
                c = simple_obfs_http::new_http_obfs(c, host, port);
            }
            "websocket" => {
                if let Some(opt) = &self.v2ray_option {
                    c = v2ray_obfs::new_v2ray_obfs(ctx, c, opt)
                        .await
                        .map_err(|err| anyhow!("{} connect error: {err}", self.base.addr))?;
                } else if let Some(opt) = &self.gost_option {
                    c = gost::new_gost_websocket(ctx, c, opt)
                        .await
                        .map_err(|err| anyhow!("{} connect error: {err}", self.base.addr))?;
                } else {
                    return Err(anyhow!("plugin options is required"));
                }
            }
            mode if mode == shadowtls::MODE => {
                c = Box::new(murmur_common_net::io::StreamAsOldConn::new(
                    shadowtls::new_shadow_tls(
                        ctx,
                        Box::new(murmur_common_net::io::OldConnAsStream(c)),
                        self.shadow_tls_option.as_ref(),
                    )
                    .await?,
                ));
                use_early = true;
            }
            "restls" => {
                let config = self.restls_config.as_ref().ok_or_else(|| anyhow!("restls_config set for restls mode"))?;
                c = tokio::select! {
                    biased;
                    () = ctx.cancelled() => return Err(anyhow!("{} (restls) connect error: context canceled", self.base.addr)),
                    result = murmur_restls::new_restls(c, config) => {
                        result.map_err(|err| anyhow!("{} (restls) connect error: {err}", self.base.addr))?
                    }
                };
                use_early = true;
            }
            mode if mode == jls::MODE => {
                c = jls::new_client(ctx, c, self.jls_option.as_ref().ok_or_else(|| anyhow!("jls: nil client option"))?)
                    .await?;
                use_early = true;
            }
            _ => {}
        }

        use_early = use_early || need_handshake(&*c);

        let shared = SharedConn::from_boxed(c);
        let done = if use_early { None } else { Some(setup_context_for_conn(ctx, shared.clone())) };
        let c: Box<dyn NetConn> = Box::new(shared);

        let dial_result = if metadata.network == NetWork::UDP && self.option.udp_over_tcp {
            let uot_version = u8::try_from(self.option.udp_over_tcp_version)
                .map_err(|_| anyhow!("ss {} unsupported udp over tcp version", self.base.addr))?;
            let uot_destination = uot::request_destination(uot_version);
            if use_early {
                self.method.dial_early_conn(c, uot_destination)
            } else {
                self.method.dial_conn(c, uot_destination).await
            }
        } else {
            let destination = parse_socksaddr_host_port(&metadata.string(), metadata.dst_port);
            if use_early {
                self.method.dial_early_conn(c, destination)
            } else {
                self.method.dial_conn(c, destination).await
            }
        };

        let Some(mut done) = done else {
            return dial_result;
        };
        let (value, mut err) = match dial_result {
            Ok(value) => (Some(value), None),
            Err(err) => (None, Some(err)),
        };
        done.call(&mut err).await;
        match err {
            Some(err) => Err(err),
            None => value.ok_or_else(|| anyhow!("no error means the dial succeeded")),
        }
    }

    async fn raw_dial_context(&self, ctx: &CancellationToken) -> Result<Box<dyn NetConn>> {
        if let Some(client) = &self.kcptun_client {
            let self_arc = self.self_arc()?;
            let dial: kcptun::DialFn = Box::new(move |ctx: CancellationToken| {
                let self_arc = Arc::clone(&self_arc);
                Box::pin(async move { self_arc.raw_listen_packet_context(&ctx).await })
            });
            let stream = client.open_stream(ctx, &dial).await?;
            return Ok(stream);
        }
        let stream = self
            .base
            .dialer
            .as_ref()
            .ok_or_else(|| anyhow!("dialer set in ShadowSocks::new"))?
            .dial_context(ctx, "tcp", &self.base.addr)
            .await?;
        // S11: remove with std-compat (Method::dial_conn/dial_early_conn chain still murmur_std_compat::net::Conn based, see module doc)
        Ok(Box::new(murmur_common_net::io::StreamAsOldConn::new(stream)))
    }

    async fn raw_listen_packet_context(&self, ctx: &CancellationToken) -> Result<(Box<dyn PacketConn>, Box<dyn Addr>)> {
        let addr = resolve_udp_addr(ctx, "udp", &self.base.addr, self.base.prefer).await?;
        let r_addr_port = SocketAddr::try_from(&addr).ok();
        let pc = self
            .base
            .dialer
            .as_ref()
            .ok_or_else(|| anyhow!("dialer set in ShadowSocks::new"))?
            .listen_packet(ctx, "udp", "", r_addr_port)
            .await?;
        // S11: remove in U6 (raw_listen_packet_context/Method::dial_packet_conn chain still murmur_std_compat::net::PacketConn based)
        let pc: Box<dyn PacketConn> = Box::new(murmur_common_net::io::DatagramAsOldPacketConn(pc));
        Ok((pc, Box::new(addr)))
    }
}

#[async_trait]
impl CProxyAdapter for ShadowSocks {
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
        let c = self.raw_dial_context(ctx).await.map_err(|err| anyhow!("{} connect error: {err}", self.base.addr))?;
        let shared = SharedConn::from_boxed(c);
        let result = self.stream_conn_context(ctx, Box::new(shared.clone()), metadata).await;
        safe_conn_close(Some(&shared), result.is_err());
        let c = result?;
        // S11: remove with std-compat (Method chain still murmur_std_compat::net::Conn based, see module doc)
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(c)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        if self.option.udp_over_tcp {
            let c = self.dial_context(ctx, metadata).await?;
            let c: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(c));
            let shared = SharedConn::from_boxed(c);

            let result = self.resolve_udp(ctx, metadata).await;
            safe_conn_close(Some(&shared), result.is_err());
            result?;

            let udp_addr = metadata.udp_addr();
            let destination = socksaddr_from_net(udp_addr.as_ref().map(|addr| -> &dyn Addr { addr }));
            let request = uot::Request { is_connect: false, destination };
            let uot_conn = if self.option.udp_over_tcp_version == i32::from(uot::LEGACY_VERSION) {
                uot::new_conn(Box::new(shared), request)
            } else {
                uot::new_lazy_conn(Box::new(shared), request)
            };
            let pc = new_thread_safe_packet_conn(Arc::new(uot_conn)).into_packet_conn();
            // S11: remove with std-compat (murmur_sing::uot / new_thread_safe_packet_conn chain still murmur_std_compat::net::PacketConn based)
            return Ok(new_packet_conn(super::base::arc_packet_conn_as_datagram(pc), self.self_arc()?));
        }

        self.resolve_udp(ctx, metadata).await?;

        let (pc, addr) = self.raw_listen_packet_context(ctx).await?;
        let pc: Arc<dyn PacketConn> = Arc::from(pc);
        let r_addr = murmur_common_net::io::old_addr_to_socket_addr(addr.as_ref())?;
        let bound_conn = new_bind_packet_conn(pc, r_addr);
        // S11: remove in U6 (Method::dial_packet_conn chain still murmur_std_compat::net::PacketConn based, see module doc)
        let bound_conn = Box::new(murmur_common_net::io::StreamAsOldConn::new(bound_conn));
        let pc = self.method.dial_packet_conn(bound_conn)?;
        Ok(new_packet_conn(super::base::arc_packet_conn_as_datagram(pc), self.self_arc()?))
    }

    fn support_uot(&self) -> bool {
        self.option.udp_over_tcp
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.base.is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.base.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        if let Some(client) = &self.kcptun_client {
            return client.close();
        }
        Ok(())
    }
}

#[async_trait]
impl ProxyAdapter for ShadowSocks {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}

#[cfg(test)]
mod restls_tests {
    use std::sync::Arc as StdArc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};

    use super::*;
    use murmur_component_ca::config::pem_sections;
    use murmur_component_ca::keypair::{new_random_tls_key_pair, KeyPairType};
    use murmur_restls::{restls_server, DialFn, ServerConfig};
    use murmur_testsupport_probe::ensure_test_crypto_provider;

    const DEADLINE: Duration = Duration::from_secs(15);
    const PASSWORD: &str = "shadowsocks-restls-test";
    const CAMOUFLAGE_NAME: &str = "camouflage.example";

    #[tokio::test]
    async fn stalled_restls_handshake_obeys_cancellation() {
        let adapter = ShadowSocks::new(ShadowSocksOption {
            cipher: "none".into(),
            server: "localhost".into(),
            port: 443,
            plugin: "restls".into(),
            plugin_opts: serde_yaml::from_str("host: localhost\npassword: secret\nversion-hint: tls13").unwrap(),
            ..Default::default()
        })
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let ctx = CancellationToken::new();
        let cancel = ctx.clone();
        let server_task = async move {
            let mut first_byte = [0];
            server.read_exact(&mut first_byte).await.unwrap();
            cancel.cancel();
            let mut rest = [0; 4096];
            loop {
                if server.read(&mut rest).await.unwrap() == 0 {
                    break 0;
                }
            }
        };
        let metadata = Metadata::default();
        let (result, remaining) = timeout(Duration::from_secs(2), async {
            tokio::join!(adapter.stream_conn_context(&ctx, Box::new(client), &metadata), server_task)
        })
        .await
        .expect("cancelled Restls handshake stalled");
        let err = result.err().expect("cancelled handshake succeeded");
        assert!(err.to_string().contains("cancel"), "{err}");
        assert_eq!(remaining, 0);
    }

    fn test_server_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let (cert_pem, key_pem, _) = new_random_tls_key_pair(KeyPairType::P256).expect("generate test certificate");
        let cert_der = pem_sections(cert_pem.as_bytes())
            .into_iter()
            .find(|(label, _, _)| label == "CERTIFICATE")
            .map(|(_, der, _)| CertificateDer::from(der))
            .expect("parse test certificate");
        let key_der = pem_sections(key_pem.as_bytes())
            .into_iter()
            .find_map(|(label, der, _)| match label.as_str() {
                "PRIVATE KEY" => Some(PrivateKeyDer::Pkcs8(der.into())),
                "EC PRIVATE KEY" => Some(PrivateKeyDer::Sec1(der.into())),
                "RSA PRIVATE KEY" => Some(PrivateKeyDer::Pkcs1(der.into())),
                _ => None,
            })
            .expect("parse test certificate key");
        (cert_der, key_der)
    }

    /// Restls enables early data, so the destination header has to share the first payload's Restls
    /// record instead of taking a short record of its own, which the per-record script would then
    /// pad into a second, separate message. The Restls server hands out one record per
    /// read, so the first chunk it yields tells the two cases apart.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn restls_defers_destination_header_into_the_first_payload_record() {
        ensure_test_crypto_provider();

        let metadata =
            Metadata { network: NetWork::TCP, host: "target.example".to_owned(), dst_port: 443, ..Default::default() };
        let header =
            encode_socksaddr_header(&parse_socksaddr_host_port(&metadata.string(), metadata.dst_port)).expect("header");
        let payload = b"restls-early-header-probe";
        let mut expected = header.clone();
        expected.extend_from_slice(payload);

        let (cert_der, key_der) = test_server_cert();
        let camouflage_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("build camouflage tls server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(StdArc::new(camouflage_tls));

        // The camouflage site only has to terminate the TLS handshake the Restls server relays to
        // it; the payload never reaches it, because the record carrying it is what the Restls
        // server holds back as the client's first authenticated record.
        let camouflage = TcpListener::bind("127.0.0.1:0").await.expect("bind camouflage listener");
        let camouflage_addr = camouflage.local_addr().expect("camouflage listener addr");
        let camouflage_task = tokio::spawn(async move {
            let (raw, _) = camouflage.accept().await.expect("accept camouflage conn");
            let mut tls = acceptor.accept(raw).await.expect("camouflage tls handshake");
            let mut drain = Vec::new();
            let _ = tls.read_to_end(&mut drain).await;
        });

        let camouflage_dial: DialFn = StdArc::new(move |_| {
            Box::pin(async move {
                let conn: Box<dyn NetConn> = Box::new(TcpStream::connect(camouflage_addr).await?);
                Ok(conn)
            })
        });

        let restls_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind restls listener");
        let restls_addr = restls_listener.local_addr().expect("restls listener addr");
        let restls_config = ServerConfig {
            server_hostname: CAMOUFLAGE_NAME.to_owned(),
            password: PASSWORD.to_owned(),
            restls_script: String::new(),
            min_record_len: 0,
            rate_limit: 0,
            dial: camouflage_dial,
        };
        let (records_tx, mut records_rx) = mpsc::unbounded_channel();
        let restls_task = tokio::spawn(async move {
            let (inbound, _) = restls_listener.accept().await.expect("accept restls conn");
            let mut server = restls_server(Box::new(inbound), &restls_config).await.expect("restls server handshake");
            let mut chunk = [0u8; 512];
            loop {
                match server.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if records_tx.send(chunk[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let adapter = ShadowSocks::new(ShadowSocksOption {
            cipher: "none".into(),
            server: "127.0.0.1".into(),
            port: i32::from(restls_addr.port()),
            plugin: "restls".into(),
            plugin_opts: serde_yaml::from_str(&format!(
                "host: {CAMOUFLAGE_NAME}\npassword: {PASSWORD}\nversion-hint: tls13\nskip-cert-verify: true"
            ))
            .expect("parse restls plugin opts"),
            ..Default::default()
        })
        .expect("build restls shadowsocks adapter");

        let raw = TcpStream::connect(restls_addr).await.expect("connect restls");
        let mut conn =
            timeout(DEADLINE, adapter.stream_conn_context(&CancellationToken::new(), Box::new(raw), &metadata))
                .await
                .expect("restls setup stalled")
                .expect("restls setup failed");

        conn.write_all(payload).await.expect("write payload");
        conn.flush().await.expect("flush payload");

        let first_record = timeout(DEADLINE, records_rx.recv())
            .await
            .expect("no restls record arrived")
            .expect("restls server stopped");
        assert_eq!(first_record, expected, "destination header and first payload must share one restls record");

        restls_task.abort();
        camouflage_task.abort();
    }
}

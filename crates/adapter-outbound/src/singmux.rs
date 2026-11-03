use std::io;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context as TaskContext, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_common::utils::mbps::string_to_bps;
use murmur_component_proxydialer::proxydialer::new as new_proxy_dialer;
use murmur_component_proxydialer::sing::{new_sing_dialer, SingDialer};
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_sing::metadata::{parse_socksaddr_host_port, Socksaddr};
use murmur_sing_mux::brutal::raw_socket;
use murmur_sing_mux::client::{
    new_client, BrutalOptions as MuxBrutalOptions, Client, Dialed as MuxDialed, Dialer as MuxDialer,
    Options as MuxOptions,
};
use murmur_sing_mux::protocol::{PROTOCOL_H2MUX, PROTOCOL_SMUX, PROTOCOL_YAMUX};
use murmur_sing_mux::session::MuxConn;
use murmur_std_compat::net::Conn as NetConn;

use super::base::{new_conn, new_packet_conn, ProxyAdapter};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the option struct mirrors the configuration keys one for one; collapsing the flags would \
              change the public shape"
)]
pub struct SingMuxOption {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: String,
    #[serde(rename = "max-connections", default)]
    pub max_connections: i64,
    #[serde(rename = "min-streams", default)]
    pub min_streams: i64,
    #[serde(rename = "max-streams", default)]
    pub max_streams: i64,
    #[serde(default)]
    pub padding: bool,
    #[serde(default)]
    pub statistic: bool,
    #[serde(rename = "only-tcp", default)]
    pub only_tcp: bool,
    #[serde(rename = "brutal-opts", default)]
    pub brutal_opts: BrutalOption,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BrutalOption {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub up: String,
    #[serde(default)]
    pub down: String,
}

/// Bridges `component_proxydialer::sing::SingDialer` (two methods) onto
/// `murmur_sing_mux::client::Dialer` (one method); the mux client never calls `listen_packet`.
struct MuxClientDialer(Arc<dyn SingDialer>);

#[async_trait]
impl MuxDialer for MuxClientDialer {
    async fn dial_context(&self, ctx: &CancellationToken, destination: &Socksaddr) -> io::Result<MuxDialed> {
        let conn = self.0.dial_context(ctx, "tcp", destination.clone()).await.map_err(io::Error::other)?;
        let socket = raw_socket(conn.as_socket());
        Ok(MuxDialed { conn: Box::new(NetConnAsMuxConn(conn)), socket })
    }
}

struct NetConnAsMuxConn(Box<dyn NetConn>);

impl AsyncRead for NetConnAsMuxConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for NetConnAsMuxConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// Bridges the mux `Box<dyn MuxConn>` a dialed TCP stream comes back as into
/// `murmur_common_net::io::Stream`, the vocabulary [`base::new_conn`] needs. `peer_addr` reports
/// the dialed destination (matching the client conn's own remote address); `local_addr` has no
/// faithful answer left once the carrier is
/// erased behind [`MuxConn`] (`NEEDED SHIM ITEM: as_any` on the sing dialer boundary, same gap
/// `crate::brutal` documents), so it reports the unspecified address the way this codebase's other
/// erased-carrier wrappers already do.
struct MuxConnAsStream {
    inner: Box<dyn MuxConn>,
    peer_addr: std::net::SocketAddr,
}

impl AsyncRead for MuxConnAsStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxConnAsStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl murmur_common_net::io::Stream for MuxConnAsStream {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(self.peer_addr)
    }
}

/// Bridges the mux `Box<dyn murmur_sing::network::PacketConn>` `Client::listen_packet` returns
/// into `murmur_common_net::io::Datagram`.
struct MuxPacketConnAsDatagram(Arc<dyn murmur_sing::network::PacketConn>);

#[async_trait]
impl murmur_common_net::io::Datagram for MuxPacketConnAsDatagram {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        let size = i32::try_from(buf.len()).map_err(|_| io::Error::other("packet buffer too large"))?;
        let mut buffer = murmur_compat::sing_buf::new_size(size);
        let destination = self.0.read_packet(&mut buffer).await?;
        let source = buffer.bytes();
        let n = source.len().min(buf.len());
        let (Some(source), Some(target)) = (source.get(..n), buf.get_mut(..n)) else {
            return Err(io::Error::other("packet copy length out of range"));
        };
        target.copy_from_slice(source);
        Ok((
            n,
            destination
                .addr_port()
                .unwrap_or(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)),
        ))
    }

    async fn send_to(&self, buf: &[u8], addr: std::net::SocketAddr) -> io::Result<usize> {
        let size = i32::try_from(buf.len()).map_err(|_| io::Error::other("packet buffer too large"))?;
        let mut buffer = murmur_compat::sing_buf::new_size(size);
        buffer.write_bytes(buf)?;
        self.0.write_packet(&buffer, &Socksaddr::from_socket_addr(addr)).await?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        murmur_common_net::io::old_addr_to_socket_addr(self.0.local_addr()?.as_ref())
    }
}

/// `self_weak` upgrades to an `Arc<Self>` for [`new_packet_conn`].
///
/// `new_packet_conn` needs an owned adapter handle to push onto the packet conn's chain (the
/// method-value receiver `s` is already that handle; Rust needs `Arc::new_cyclic` to get one from
/// `&self`).
pub struct SingMux {
    inner: Arc<dyn ProxyAdapter>,
    client: Arc<Client>,
    only_tcp: bool,
    self_weak: Weak<Self>,
}

impl core::fmt::Debug for SingMux {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The wrapped adapter and the mux client carry no `Debug`.
        f.debug_struct("SingMux").field("only_tcp", &self.only_tcp).finish_non_exhaustive()
    }
}

impl SingMux {
    fn socksaddr_for(metadata: &Metadata) -> Socksaddr {
        parse_socksaddr_host_port(&metadata.string(), metadata.dst_port)
    }
}

#[async_trait]
impl CProxyAdapter for SingMux {
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
        if self.only_tcp {
            return self.inner.support_udp();
        }
        true
    }

    fn proxy_info(&self) -> ProxyInfo {
        let mut info = self.inner.proxy_info();
        info.smux = true;
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.inner.marshal_json()
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let destination = Self::socksaddr_for(metadata);
        let conn = self.client.dial_context(ctx, "tcp", destination.clone()).await?;
        let peer_addr = destination
            .addr_port()
            .unwrap_or(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));
        let stream: Box<dyn murmur_common_net::io::Stream> = Box::new(MuxConnAsStream { inner: conn, peer_addr });
        Ok(new_conn(stream, self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        if self.only_tcp {
            return self.inner.listen_packet_context(ctx, metadata).await;
        }
        self.resolve_udp(ctx, metadata).await?;
        let destination = metadata
            .raw_dst_addr
            .as_ref()
            .and_then(|addr| murmur_common_net::io::old_addr_to_socket_addr(addr.as_ref()).ok())
            .map_or_else(|| Self::socksaddr_for(metadata), Socksaddr::from_socket_addr);
        let pc = self.client.listen_packet(ctx, destination).await?;
        let pc: Arc<dyn murmur_sing::network::PacketConn> = Arc::from(pc);
        let datagram: Arc<dyn murmur_common_net::io::Datagram> = Arc::new(MuxPacketConnAsDatagram(pc));
        let self_arc: Arc<dyn ProxyAdapter> = self
            .self_weak
            .upgrade()
            .ok_or_else(|| anyhow!("SingMux dropped while listen_packet_context is running"))?;
        Ok(new_packet_conn(datagram, self_arc))
    }

    fn support_uot(&self) -> bool {
        if self.only_tcp {
            return self.inner.support_uot();
        }
        true
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.inner.is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.inner.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        let client = Arc::clone(&self.client);
        tokio::spawn(async move { client.close().await });
        self.inner.close()
    }
}

#[async_trait]
impl ProxyAdapter for SingMux {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.inner.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.inner.resolve_udp(ctx, metadata).await
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the exported constructor keeps its by-value option, the owned config value the adapter \
              parser hands over; taking it by reference would change the public API"
)]
pub fn new_sing_mux(option: SingMuxOption, proxy: Arc<dyn ProxyAdapter>) -> Result<Arc<dyn ProxyAdapter>> {
    // Bind unannotated so `Arc::clone` infers `Arc<dyn ProxyAdapter>`, then coerce at
    // the second binding; an annotation on the clone would force the generic parameter.
    let proxy_arc = Arc::clone(&proxy);
    let proxy_as_cproxy: Arc<dyn CProxyAdapter> = proxy_arc;
    let sing_dialer = new_sing_dialer(new_proxy_dialer(proxy_as_cproxy, option.statistic));
    let protocol = match option.protocol.as_str() {
        "" | "h2mux" => PROTOCOL_H2MUX,
        "smux" => PROTOCOL_SMUX,
        "yamux" => PROTOCOL_YAMUX,
        other => return Err(anyhow!("unknown protocol: {other}")),
    };
    let client = new_client(MuxOptions {
        dialer: Arc::new(MuxClientDialer(sing_dialer)),
        protocol,
        max_connections: usize::try_from(option.max_connections.max(0))
            .map_err(|_| anyhow!("max-connections out of range"))?,
        min_streams: usize::try_from(option.min_streams.max(0)).map_err(|_| anyhow!("min-streams out of range"))?,
        max_streams: usize::try_from(option.max_streams.max(0)).map_err(|_| anyhow!("max-streams out of range"))?,
        padding: option.padding,
        tcp_timeout: murmur_constant::adapters::DEFAULT_TCP_TIMEOUT,
        brutal: MuxBrutalOptions {
            enabled: option.brutal_opts.enabled,
            send_bps: string_to_bps(&option.brutal_opts.up),
            receive_bps: string_to_bps(&option.brutal_opts.down),
        },
    })
    .map_err(|err| anyhow!("{err}"))?;
    let client = Arc::new(client);
    Ok(Arc::new_cyclic(|self_weak| SingMux {
        inner: proxy,
        client,
        only_tcp: option.only_tcp,
        self_weak: Weak::clone(self_weak),
    }))
}

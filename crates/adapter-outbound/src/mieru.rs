use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{Datagram, Stream as NetStream};
use murmur_component::dialer::bind::join_host_port;
use murmur_component::resolver::resolver::proxy_server_host_resolver;
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, Dialer as CDialer, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter,
    ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_mieru::client::{Client, ClientConfig, DialedSession, HandshakeMode, MultiplexLevel, Stream};
use murmur_mieru::io::{boxed_stream, ClientDialer, DialedPacket, DialedStream, PacketIo};
use murmur_mieru::model::{AddrSpec, UdpAssociateWrapper};
use murmur_mieru::session::Transport;
use murmur_mieru::trafficpattern::Config;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter as BaseProxyAdapter};
use super::util::resolve_ip_with_resolver;

pub struct Mieru {
    base: Base,
    option: MieruOption,
    client: Arc<Client>,
    self_weak: Weak<Self>,
}

impl core::fmt::Debug for Mieru {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mieru").field("name", &self.option.name).finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct MieruOption {
    pub basic_option: BasicOption,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub port_range: String,
    pub transport: String,
    pub udp: bool,
    pub user_name: String,
    pub password: String,
    pub multiplexing: String,
    pub handshake_mode: String,
    pub traffic_pattern: String,
}

impl core::fmt::Debug for MieruOption {
    /// Redacts `password` so `{:?}` cannot leak the credential.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MieruOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("port_range", &self.port_range)
            .field("transport", &self.transport)
            .field("udp", &self.udp)
            .field("user_name", &self.user_name)
            .field("password", &"<redacted>")
            .field("multiplexing", &self.multiplexing)
            .field("handshake_mode", &self.handshake_mode)
            .field("traffic_pattern", &self.traffic_pattern)
            .finish_non_exhaustive()
    }
}

impl Mieru {
    pub fn new(option: MieruOption) -> Result<Arc<Self>> {
        let (port_start, port_end) =
            validate_mieru_option(&option).map_err(|err| anyhow!("failed to validate mieru option: {err}"))?;
        let traffic_pattern = parse_traffic_pattern(&option.traffic_pattern)?;
        let multiplex = if option.multiplexing.is_empty() {
            MultiplexLevel::default()
        } else {
            MultiplexLevel::from_config(&option.multiplexing)?
        };
        let handshake_mode = if option.handshake_mode.is_empty() {
            HandshakeMode::default()
        } else {
            HandshakeMode::from_config(&option.handshake_mode)?
        };
        let transport = match option.transport.as_str() {
            "TCP" => Transport::Stream,
            "UDP" => Transport::Packet,
            other => return Err(anyhow!("transport must be TCP or UDP, got {other}")),
        };

        // The proxy address carries the range's begin port, not the range itself, so it stays a
        // dialable `host:port` (an IPv6 literal is bracketed).
        let addr = join_host_port(&option.server, port_start);
        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr,
            type_: AdapterType::MIERU,
            provider_name: option.basic_option.provider_name.clone(),
            udp: option.udp,
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
            xudp: false,
        });
        let dialer = option.basic_option.new_dialer(base.dial_options());
        base.dialer = Some(Arc::clone(&dialer));

        let client = Client::with_dialer(
            ClientConfig {
                server: option.server.clone(),
                port_start,
                port_end,
                username: option.user_name.clone(),
                password: option.password.clone(),
                transport,
                multiplex,
                handshake_mode,
                traffic_pattern,
            },
            Arc::new(MieruDialer { dialer, prefer: option.basic_option.ip_version }),
        );

        Ok(Arc::new_cyclic(|weak| Self { base, option, client: Arc::new(client), self_weak: Weak::clone(weak) }))
    }

    fn dest_addr(metadata: &Metadata) -> Result<AddrSpec> {
        if !metadata.host.is_empty() {
            return Ok(AddrSpec::Fqdn(metadata.host.clone(), metadata.dst_port));
        }
        let ip = metadata.dst_ip.ok_or_else(|| anyhow!("{} has neither a host nor an IP", metadata.string()))?;
        Ok(AddrSpec::Ip(ip, metadata.dst_port))
    }
}

/// The traffic-pattern step of the client config. An unset option still reaches mieru as the
/// implicit pattern `Config::new(None)` generates, so it must not become `None`.
///
/// DEVIATION: low-entropy payload coding is refused, not applied; the documented behaviour applies
/// it.
fn parse_traffic_pattern(encoded: &str) -> Result<Option<Config>> {
    if !encoded.is_empty() {
        return Client::parse_traffic_pattern(encoded)
            .map_err(|err| anyhow!("invalid traffic pattern {encoded:?}: {err}"));
    }
    let implicit = Config::new(None).map_err(|err| anyhow!("failed to generate mieru traffic pattern: {err}"))?;
    Ok(Some(implicit))
}

/// Validates the option and answers the port range the client dials from.
fn validate_mieru_option(option: &MieruOption) -> Result<(u16, u16)> {
    if option.name.is_empty() {
        return Err(anyhow!("name is empty"));
    }
    if option.server.is_empty() {
        return Err(anyhow!("server is empty"));
    }
    if option.port == 0 && option.port_range.is_empty() {
        return Err(anyhow!("either port or port-range must be set"));
    }
    if option.port != 0 && !option.port_range.is_empty() {
        return Err(anyhow!("port and port-range cannot be set at the same time"));
    }
    if option.transport != "TCP" && option.transport != "UDP" {
        return Err(anyhow!("transport must be TCP or UDP"));
    }
    if option.user_name.is_empty() {
        return Err(anyhow!("username is empty"));
    }
    if option.password.is_empty() {
        return Err(anyhow!("password is empty"));
    }
    if option.port_range.is_empty() {
        return Ok((option.port, option.port));
    }
    let (begin, end) = parse_port_range(&option.port_range).ok_or_else(|| anyhow!("invalid port-range format"))?;
    let begin = u16::try_from(begin).map_err(|_| anyhow!("begin port must be between 1 and 65535"))?;
    let end = u16::try_from(end).map_err(|_| anyhow!("end port must be between 1 and 65535"))?;
    if begin == 0 {
        return Err(anyhow!("begin port must be between 1 and 65535"));
    }
    if end == 0 {
        return Err(anyhow!("end port must be between 1 and 65535"));
    }
    if begin > end {
        return Err(anyhow!("begin port must be less than or equal to end port"));
    }
    Ok((begin, end))
}

/// A scan for a number, a literal `-`, then a number, with trailing text ignored. The bounds are
/// checked by the caller, so a value above 65535 parses here and is rejected there.
fn parse_port_range(value: &str) -> Option<(u32, u32)> {
    let (begin, rest) = split_leading_number(value)?;
    let (end, _) = split_leading_number(rest.strip_prefix('-')?)?;
    Some((begin, end))
}

fn split_leading_number(value: &str) -> Option<(u32, &str)> {
    let digits = value.len() - value.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    if digits == 0 {
        return None;
    }
    let (head, tail) = value.split_at(digits);
    head.parse().ok().map(|n| (n, tail))
}

#[async_trait]
impl CProxyAdapter for Mieru {
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
        let dest = Self::dest_addr(metadata)?;
        let dialed =
            self.client.dial_connect(ctx, dest.clone()).await.map_err(|err| anyhow!("dial to {dest} failed: {err}"))?;
        Ok(new_conn(
            Box::new(MieruConn { stream: dialed.stream, local_addr: dialed.local_addr, peer_addr: dialed.peer_addr }),
            self,
        ))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        BaseProxyAdapter::resolve_udp(self, ctx, metadata).await?;
        let dest = Self::dest_addr(metadata)?;
        let dialed = self.client.dial_udp_associate(ctx, dest).await?;
        let pc: Arc<dyn Datagram> = Arc::new(MieruDatagram::new(dialed));
        let this = self.self_weak.upgrade().ok_or_else(|| anyhow!("Mieru adapter dropped"))?;
        Ok(new_packet_conn(pc, this))
    }

    fn support_uot(&self) -> bool {
        true
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.base.is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.base.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        let client = Arc::clone(&self.client);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            tokio::task::block_in_place(|| handle.block_on(client.close()));
        }
        self.base.close()
    }
}

#[async_trait]
impl BaseProxyAdapter for Mieru {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}

/// the `Mieru` dialer: the underlay connections go through murmur's own dialer, so they carry
/// its interface binding, routing mark and dialer-proxy chain.
struct MieruDialer {
    dialer: Arc<dyn CDialer>,
    prefer: murmur_constant::dns::DNSPrefer,
}

#[async_trait]
impl ClientDialer for MieruDialer {
    async fn dial_stream(&self, ctx: &CancellationToken, host: &str, port: u16) -> io::Result<DialedStream> {
        let address = join_host_port(host, port.to_string());
        let stream = self.dialer.dial_context(ctx, "tcp", &address).await.map_err(io::Error::other)?;
        let local_addr = stream.local_addr();
        let peer_addr = stream.peer_addr();
        Ok(DialedStream { stream: boxed_stream(stream), local_addr, peer_addr })
    }

    async fn dial_packet(&self, ctx: &CancellationToken, host: &str, port: u16) -> io::Result<DialedPacket> {
        let ip = self.resolve(ctx, host).await?;
        let peer_addr = SocketAddr::new(ip, port);
        let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = self.dialer.listen_packet(ctx, "udp", bind, Some(peer_addr)).await.map_err(io::Error::other)?;
        let local_addr = socket.local_addr();
        Ok(DialedPacket { socket: Arc::new(MieruPacketIo(socket)), local_addr, peer_addr })
    }
}

impl MieruDialer {
    async fn resolve(&self, ctx: &CancellationToken, host: &str) -> io::Result<IpAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(ip);
        }
        resolve_ip_with_resolver(ctx, host, self.prefer, proxy_server_host_resolver().as_deref())
            .await
            .map_err(io::Error::other)
    }
}

/// Adapts murmur's datagram socket to the packet underlay's socket seam.
struct MieruPacketIo(Box<dyn Datagram>);

#[async_trait]
impl PacketIo for MieruPacketIo {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, target).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

/// The session as a connection: the wrapper's `local_addr`/`peer_addr` are the underlay socket's.
struct MieruConn {
    stream: Stream,
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
}

impl AsyncRead for MieruConn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.stream.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for MieruConn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.stream.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.as_mut().poll_shutdown(cx)
    }
}

#[async_trait]
impl NetStream for MieruConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr.ok_or_else(|| io::Error::other("mieru underlay has no local address"))
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.peer_addr.ok_or_else(|| io::Error::other("mieru underlay has no peer address"))
    }
}

/// The UDP-associate session as a packet conn. Read and write run off independent halves of the
/// duplex, matching the thread-safe packet conn, which serializes writes only and leaves the
/// read free.
struct MieruDatagram {
    reader: AsyncMutex<UdpAssociateWrapper<tokio::io::ReadHalf<Stream>>>,
    writer: AsyncMutex<UdpAssociateWrapper<tokio::io::WriteHalf<Stream>>>,
    local_addr: Option<SocketAddr>,
}

impl MieruDatagram {
    fn new(dialed: DialedSession) -> Self {
        let (read_half, write_half) = tokio::io::split(dialed.stream);
        Self {
            reader: AsyncMutex::new(UdpAssociateWrapper::new(read_half)),
            writer: AsyncMutex::new(UdpAssociateWrapper::new(write_half)),
            local_addr: dialed.local_addr,
        }
    }
}

#[async_trait]
impl Datagram for MieruDatagram {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (payload, from) = self.reader.lock().await.recv_from().await.map_err(io::Error::other)?;
        let n = payload.len().min(buf.len());
        let (dst, _) = buf.split_at_mut(n);
        let (src, _) = payload.split_at(n);
        dst.copy_from_slice(src);
        Ok((n, addr_spec_to_socket_addr(from)?))
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.writer
            .lock()
            .await
            .send_to(buf, &AddrSpec::Ip(target.ip(), target.port()))
            .await
            .map_err(io::Error::other)?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr.ok_or_else(|| io::Error::other("mieru underlay has no local address"))
    }
}

fn addr_spec_to_socket_addr(addr: AddrSpec) -> io::Result<SocketAddr> {
    match addr {
        AddrSpec::Ip(ip, port) => Ok(SocketAddr::new(ip, port)),
        AddrSpec::Fqdn(host, port) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cannot use the domain name {host}:{port} as a packet address"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    use murmur_constant::metadata::{Metadata, NetWork};
    use murmur_mieru::cipher::DEFAULT_NONCE_SIZE;
    use murmur_mieru::padding::{PRINTABLE_CHAR_SUB, PRINTABLE_CHAR_SUP};
    use murmur_mieru::trafficpattern::{self, NoncePatternProto, NonceType, TrafficPattern};

    use super::*;

    const USER: &str = "alice";
    const PASSWORD: &str = "correct horse battery staple";

    /// A peer that answers nothing, so the client's first segment is the only thing on the wire.
    /// It stays open until the client hangs up, so a close cannot race the client's flush.
    async fn raw_peer() -> (SocketAddr, tokio::sync::oneshot::Receiver<[u8; DEFAULT_NONCE_SIZE]>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind the raw peer");
        let bound = listener.local_addr().expect("raw peer address");
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut nonce = [0u8; DEFAULT_NONCE_SIZE];
            socket.read_exact(&mut nonce).await.expect("read the first nonce");
            let _ = tx.send(nonce);
            let mut rest = Vec::new();
            let _ = socket.read_to_end(&mut rest).await;
        });
        (bound, rx)
    }

    fn outbound(server: SocketAddr, traffic_pattern: &str) -> Arc<Mieru> {
        Mieru::new(MieruOption {
            basic_option: BasicOption::default(),
            name: "mieru_outbound".to_owned(),
            server: server.ip().to_string(),
            port: server.port(),
            transport: "TCP".to_owned(),
            udp: true,
            user_name: USER.to_owned(),
            password: PASSWORD.to_owned(),
            traffic_pattern: traffic_pattern.to_owned(),
            handshake_mode: "HANDSHAKE_NO_WAIT".to_owned(),
            ..Default::default()
        })
        .expect("mieru outbound construction")
    }

    /// Writes one byte so the NoWait client puts its first segment on the wire, and returns the
    /// connection with the outbound that owns its mux so the segment stays readable.
    async fn write_first_segment(server: SocketAddr, traffic_pattern: &str) -> (Arc<Mieru>, Box<dyn CConn>) {
        let outbound = outbound(server, traffic_pattern);
        let mut metadata = Metadata {
            network: NetWork::TCP,
            dst_ip: Some("192.0.2.1".parse().expect("destination ip")),
            dst_port: 8080,
            ..Metadata::default()
        };
        let mut conn = CProxyAdapter::dial_context(&*outbound, &CancellationToken::new(), &mut metadata)
            .await
            .expect("mieru dial");
        conn.write_all(b"probe").await.expect("client write");
        conn.flush().await.expect("client flush");
        (outbound, conn)
    }

    /// The configured `traffic-pattern` must reach the session: its nonce pattern is what makes
    /// the first twelve nonce bytes printable ASCII, which a dropped option cannot produce.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_configured_traffic_pattern_shapes_the_session_nonce() {
        let (server, peer) = raw_peer().await;
        let pattern = TrafficPattern {
            nonce: Some(NoncePatternProto {
                nonce_type: Some(NonceType::Printable as i32),
                apply_to_all_udp_packet: Some(true),
                min_len: Some(12),
                max_len: Some(12),
                ..Default::default()
            }),
            ..Default::default()
        };
        let encoded = trafficpattern::encode(&pattern);

        let _session = write_first_segment(server, &encoded).await;
        let nonce = peer.await.expect("raw peer task");
        assert!(
            nonce[..12].iter().all(|b| (PRINTABLE_CHAR_SUB..=PRINTABLE_CHAR_SUP).contains(b)),
            "the configured nonce pattern must shape the first 12 nonce bytes, got {nonce:02x?}"
        );
    }

    /// An unset `traffic-pattern` behaves as the: mieru generates an implicit pattern whose nonce
    /// type is never `RANDOM` and whose rewrite window is at least six bytes, so those six bytes
    /// are printable ASCII even though the user configured nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unset_traffic_pattern_still_shapes_the_nonce() {
        let (server, peer) = raw_peer().await;

        let _session = write_first_segment(server, "").await;
        let nonce = peer.await.expect("raw peer task");
        assert!(
            nonce[..6].iter().all(|b| (PRINTABLE_CHAR_SUB..=PRINTABLE_CHAR_SUP).contains(b)),
            "the implicit pattern must shape the first 6 nonce bytes, got {nonce:02x?}"
        );
    }
}

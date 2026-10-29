use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::mieru::server as mieru_server;
use murmur_common::utils::ranges::new_unsigned_ranges;
use murmur_constant::listener::{InboundConfig, InboundListener, MultiAddrListener};
use murmur_constant::tunnel::Tunnel;
use murmur_log::infoln;
use murmur_mieru::io::ServerEndpoint;
use murmur_mieru::server::Server as MieruServer;
use murmur_mieru::session::Transport;
use murmur_mieru::trafficpattern::Config;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct MieruOption {
    pub base: BaseOption,
    pub transport: String,
    pub users: HashMap<String, String>,
    pub traffic_pattern: String,
    pub user_hint_is_mandatory: bool,
}

impl InboundConfig for MieruOption {
    fn name(&self) -> String {
        self.base.name()
    }

    fn equal(&self, config: &dyn InboundConfig) -> bool {
        config_equal(self, config)
    }

    fn option_to_string(&self) -> String {
        option_to_string(self)
    }
}

pub struct Mieru {
    base: Base,
    config: Arc<MieruOption>,
    l: Mutex<Option<Arc<mieru_server::Listener>>>,
    transport: Transport,
    users: HashMap<String, String>,
    user_hint_is_mandatory: bool,
    traffic_pattern: Option<Config>,
    addrs: Vec<String>,
}

impl core::fmt::Debug for Mieru {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mieru").field("base", &self.base).field("config", &self.config).finish_non_exhaustive()
    }
}

impl Mieru {
    pub fn new(options: Arc<MieruOption>) -> Result<Self> {
        let mut owned = Arc::unwrap_or_clone(options);
        let base = Base::new(Arc::new(owned.base.clone()))?;
        if new_unsigned_ranges::<u16>(&owned.base.port)?.is_empty() {
            return Err(anyhow!("port is not set"));
        }
        let transport = match owned.transport.as_str() {
            "TCP" => Transport::Stream,
            "UDP" => Transport::Packet,
            other => return Err(anyhow!("mieru inbound transport must be TCP or UDP, got {other}")),
        };
        let traffic_pattern = parse_traffic_pattern(&owned.traffic_pattern)?;
        if owned.users.is_empty() {
            return Err(anyhow!("users is empty"));
        }
        for (username, password) in &owned.users {
            if username.is_empty() {
                return Err(anyhow!("username is empty"));
            }
            if password.is_empty() {
                return Err(anyhow!("password is empty"));
            }
        }
        let users = std::mem::take(&mut owned.users);
        let addrs =
            base.raw_address().split(',').map(|addr| addr.trim().to_owned()).filter(|addr| !addr.is_empty()).collect();
        let user_hint_is_mandatory = owned.user_hint_is_mandatory;
        Ok(Self {
            base,
            config: Arc::new(owned),
            l: Mutex::new(None),
            transport,
            users,
            user_hint_is_mandatory,
            traffic_pattern,
            addrs,
        })
    }
}

/// The traffic-pattern step: an unset option still reaches mieru as the implicit default pattern,
/// so it must not become `None`.
///
/// DEVIATION: low-entropy payload coding is refused, not applied.
fn parse_traffic_pattern(encoded: &str) -> Result<Option<Config>> {
    if !encoded.is_empty() {
        return MieruServer::parse_traffic_pattern(encoded)
            .map_err(|err| anyhow!("invalid traffic pattern {encoded:?}: {err}"));
    }
    let implicit = Config::new(None).map_err(|err| anyhow!("failed to generate mieru traffic pattern: {err}"))?;
    Ok(Some(implicit))
}

#[async_trait]
impl InboundListener for Mieru {
    fn name(&self) -> String {
        self.base.name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let endpoints = bind_endpoints(self.transport, &self.addrs, self.base.listen_config()).await?;
        let listener = mieru_server::new(
            &self.users,
            endpoints,
            self.user_hint_is_mandatory,
            self.traffic_pattern.clone(),
            tunnel,
            self.base.additions(),
        )
        .await?;
        *self.l.lock() = Some(listener);
        infoln!("Mieru[{}] inbound listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        self.l.lock().as_ref().map_or(Ok(()), |l| l.close())
    }

    fn address(&self) -> String {
        self.l
            .lock()
            .as_ref()
            .map(|l| l.addr_list().iter().map(|addr| addr.string()).collect::<Vec<_>>().join(","))
            .unwrap_or_default()
    }

    fn raw_address(&self) -> String {
        self.base.raw_address()
    }

    fn config(&self) -> Arc<dyn InboundConfig> {
        upcast_config(Arc::clone(&self.config))
    }
}

/// The inbound's own listen config is handed to the mieru server as its
/// stream and packet listener factory, so the listeners honour the same interface binding,
/// routing mark and address reuse as every other inbound.
async fn bind_endpoints(
    transport: Transport,
    addrs: &[String],
    lc: Arc<dyn murmur_constant::listener::InboundListenConfig>,
) -> Result<Vec<ServerEndpoint>> {
    let mut endpoints = Vec::with_capacity(addrs.len());
    for addr in addrs {
        let endpoint = match transport {
            Transport::Stream => {
                let acceptor = lc
                    .listen(&tokio_util::sync::CancellationToken::new(), "tcp", addr)
                    .await
                    .map_err(|err| anyhow!("listen tcp {addr} failed: {err}"))?;
                ServerEndpoint::Stream(Arc::new(MieruAcceptor { inner: acceptor }))
            }
            Transport::Packet => {
                let socket = lc
                    .listen_packet(&tokio_util::sync::CancellationToken::new(), "udp", addr)
                    .await
                    .map_err(|err| anyhow!("listen udp {addr} failed: {err}"))?;
                ServerEndpoint::Packet(Arc::new(MieruDatagram { inner: socket }))
            }
        };
        endpoints.push(endpoint);
    }
    Ok(endpoints)
}

/// Adapts the listener to the mieru server's accept seam.
struct MieruAcceptor {
    inner: Box<dyn murmur_common_net::io::Acceptor>,
}

#[async_trait]
impl murmur_mieru::io::Acceptor for MieruAcceptor {
    // cancel-safe: forwards to the wrapped acceptor's `accept` and only boxes the result, so a dropped call leaves the listener exactly as it was.
    async fn accept(&self) -> std::io::Result<murmur_mieru::io::AcceptedStream> {
        let conn = self.inner.accept().await?;
        let local_addr = conn.local_addr();
        let peer_addr = conn.peer_addr();
        let stream = murmur_mieru::io::boxed_stream(conn);
        Ok(murmur_mieru::io::AcceptedStream { stream, local_addr, peer_addr })
    }

    fn close(&self) -> std::io::Result<()> {
        self.inner.close()
    }

    fn addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.addr()
    }
}

/// Adapts the datagram socket to the mieru server's socket seam.
struct MieruDatagram {
    inner: Box<dyn murmur_common_net::io::Datagram>,
}

#[async_trait]
impl murmur_mieru::io::PacketIo for MieruDatagram {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], target: std::net::SocketAddr) -> std::io::Result<usize> {
        self.inner.send_to(buf, target).await
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use murmur_adapter_outbound::base::BasicOption;
    use murmur_adapter_outbound::mieru::{Mieru as MieruOutbound, MieruOption as MieruOutboundOption};
    use murmur_common_net::io::Stream as NetStream;
    use murmur_component_nat::table::Table;
    use murmur_constant::adapters::{NatTable, PacketConn, ProxyAdapter, UDPPacket};
    use murmur_constant::listener::InboundListener;
    use murmur_constant::metadata::{Metadata, NetWork};
    use murmur_constant::tunnel::Tunnel;

    use super::{Mieru, MieruOption};
    use crate::inbound::base::BaseOption;

    const TIMEOUT: Duration = Duration::from_secs(10);
    const USER: &str = "alice";
    const PASSWORD: &str = "correct horse battery staple";
    /// The encoded form of a TCP-fragment traffic pattern with `maxSleepMs: 10`.
    const TRAFFIC_PATTERN: &str = "GgQIARAK";

    fn inbound(transport: &str, traffic_pattern: &str) -> Mieru {
        Mieru::new(Arc::new(MieruOption {
            base: BaseOption {
                name_str: "mieru_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            transport: transport.to_owned(),
            users: HashMap::from([(USER.to_owned(), PASSWORD.to_owned())]),
            traffic_pattern: traffic_pattern.to_owned(),
            ..Default::default()
        }))
        .expect("mieru inbound construction")
    }

    fn outbound(transport: &str, server: SocketAddr, traffic_pattern: &str) -> Arc<MieruOutbound> {
        MieruOutbound::new(MieruOutboundOption {
            basic_option: BasicOption::default(),
            name: "mieru_outbound".to_owned(),
            server: server.ip().to_string(),
            port: server.port(),
            transport: transport.to_owned(),
            udp: true,
            user_name: USER.to_owned(),
            password: PASSWORD.to_owned(),
            traffic_pattern: traffic_pattern.to_owned(),
            ..Default::default()
        })
        .expect("mieru outbound construction")
    }

    #[test]
    fn an_inbound_without_a_port_is_rejected() {
        let err = Mieru::new(Arc::new(MieruOption {
            base: BaseOption {
                name_str: "mieru_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                ..Default::default()
            },
            transport: "TCP".to_owned(),
            users: HashMap::from([(USER.to_owned(), PASSWORD.to_owned())]),
            ..Default::default()
        }))
        .expect_err("an inbound with no port must be rejected");
        assert!(err.to_string().contains("port is not set"), "unexpected error: {err}");
    }

    /// Echoes both directions and reports the TCP metadata, so the test can assert the source and
    /// in-address the inbound filled in from the mieru session's underlay.
    struct EchoTunnel {
        tcp_meta: mpsc::UnboundedSender<Metadata>,
    }

    #[async_trait]
    impl Tunnel for EchoTunnel {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn NetStream>, metadata: Metadata) {
            let _ = self.tcp_meta.send(metadata);
            let mut buf = vec![0u8; 1024];
            loop {
                let Ok(n) = conn.read(&mut buf).await else { return };
                if n == 0 || conn.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }

        fn handle_udp_packet(&self, packet: Arc<dyn UDPPacket>, metadata: Metadata) {
            let target = metadata
                .raw_dst_addr
                .as_ref()
                .and_then(|addr| murmur_common_net::io::old_addr_to_socket_addr(addr.as_ref()).ok())
                .expect("mieru UDP destination");
            assert!(metadata.raw_src_addr.is_some(), "a UDP-associate packet must carry a source address");
            assert!(metadata.in_ip.is_some(), "the packet.InAddr() must reach the metadata");
            tokio::spawn(async move {
                let socket = UdpSocket::bind("127.0.0.1:0").await.expect("UDP forward socket");
                socket.send_to(packet.data(), target).await.expect("forward UDP payload");
                let mut buf = [0u8; 1024];
                let Ok(Ok((n, source))) = tokio::time::timeout(TIMEOUT, socket.recv_from(&mut buf)).await else {
                    return;
                };
                let _ = packet.write_back(&buf[..n], Some(source)).await;
            });
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    /// `MIERU_OK` must come back over the relay, which only happens when the client's hashed
    /// credential matches the server's, so a raw-password or hint-based shortcut fails here.
    async fn tcp_round_trip(transport: &str, traffic_pattern: &str) {
        let inbound = inbound(transport, traffic_pattern);
        let (tcp_meta, mut tcp_meta_rx) = mpsc::unbounded_channel();
        inbound.listen(Arc::new(EchoTunnel { tcp_meta })).await.expect("mieru inbound listen");
        let inbound_addr: SocketAddr = inbound.address().parse().expect("bound address");

        let echo = TcpListener::bind("127.0.0.1:0").await.expect("TCP echo listener");
        let echo_addr = echo.local_addr().expect("TCP echo address");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        let outbound = outbound(transport, inbound_addr, traffic_pattern);
        let mut metadata = Metadata {
            network: NetWork::TCP,
            dst_ip: Some(echo_addr.ip()),
            dst_port: echo_addr.port(),
            ..Metadata::default()
        };
        let mut conn = tokio::time::timeout(
            TIMEOUT,
            ProxyAdapter::dial_context(&*outbound, &CancellationToken::new(), &mut metadata),
        )
        .await
        .expect("mieru dial timed out")
        .expect("mieru dial");

        conn.write_all(b"MIERU_OK").await.expect("write through the mieru relay");
        let mut buf = [0u8; 8];
        tokio::time::timeout(TIMEOUT, conn.read_exact(&mut buf))
            .await
            .expect("mieru read timed out")
            .expect("mieru read");
        assert_eq!(&buf, b"MIERU_OK", "the relayed bytes must come back unchanged");

        let meta = tokio::time::timeout(TIMEOUT, tcp_meta_rx.recv())
            .await
            .expect("tunnel metadata timed out")
            .expect("tunnel metadata");
        assert_eq!(meta.dst_ip, Some(echo_addr.ip()), "the tunnel must see the CONNECT destination");
        assert!(meta.src_ip.is_some(), "the WithSrcAddr(conn.RemoteAddr()) must reach the metadata");
        assert!(meta.in_ip.is_some(), "the WithInAddr(conn.LocalAddr()) must reach the metadata");

        outbound.close().expect("mieru outbound close");
        inbound.close().expect("mieru inbound close");
    }

    /// A packet-associate reply has to come back over the same mieru session, addressed to the
    /// client that asked for it, so the tunnel's `write_back` is the only path exercised here.
    async fn udp_round_trip(transport: &str, traffic_pattern: &str) {
        let inbound = inbound(transport, traffic_pattern);
        let (tcp_meta, _) = mpsc::unbounded_channel();
        inbound.listen(Arc::new(EchoTunnel { tcp_meta })).await.expect("mieru inbound listen");
        let inbound_addr: SocketAddr = inbound.address().parse().expect("bound address");

        let echo = UdpSocket::bind("127.0.0.1:0").await.expect("UDP echo socket");
        let echo_addr = echo.local_addr().expect("UDP echo address");
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((n, source)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], source).await;
            }
        });

        let outbound = outbound(transport, inbound_addr, traffic_pattern);
        let mut metadata = Metadata {
            network: NetWork::UDP,
            dst_ip: Some(echo_addr.ip()),
            dst_port: echo_addr.port(),
            ..Metadata::default()
        };
        let pc: Arc<dyn PacketConn> = tokio::time::timeout(
            TIMEOUT,
            ProxyAdapter::listen_packet_context(&*outbound, &CancellationToken::new(), &mut metadata),
        )
        .await
        .expect("mieru UDP associate timed out")
        .expect("mieru UDP associate");

        pc.write_to(b"MIERU_UDP", &murmur_std_compat::net::UdpAddr::from(echo_addr))
            .await
            .expect("send through the mieru relay");
        let mut buf = [0u8; 1024];
        let (n, _) = tokio::time::timeout(TIMEOUT, pc.read_from(&mut buf))
            .await
            .expect("mieru UDP read timed out")
            .expect("mieru UDP read");
        assert_eq!(&buf[..n], b"MIERU_UDP", "the relayed datagram must come back unchanged");

        outbound.close().expect("mieru outbound close");
        inbound.close().expect("mieru inbound close");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_configured_user_relays_tcp_over_the_stream_transport() {
        tcp_round_trip("TCP", "").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_configured_user_relays_udp_over_the_packet_transport() {
        udp_round_trip("UDP", "").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_configured_traffic_pattern_relays_tcp_over_the_stream_transport() {
        tcp_round_trip("TCP", TRAFFIC_PATTERN).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_configured_traffic_pattern_relays_udp_over_the_packet_transport() {
        udp_round_trip("UDP", TRAFFIC_PATTERN).await;
    }
}

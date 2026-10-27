use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;

use murmur_adapter_inbound::addition::{apply_additions, with_in_addr, with_in_name, with_src_addr, Addition};
use murmur_adapter_inbound::packet::new_packet;
use murmur_common_net::io::{udp_addr_from_socket_addr, Stream as NetStream};
use murmur_constant::adapters::{UDPPacket, WriteBack};
use murmur_constant::listener::MultiAddrListener;
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_constant::tunnel::Tunnel;
use murmur_log::debugln;
use murmur_mieru::io::ServerEndpoint;
use murmur_mieru::model::{AddrSpec, Response, UdpAssociateWrapper, CMD_CONNECT, CMD_UDP_ASSOCIATE};
use murmur_mieru::server::Server;
use murmur_mieru::session::SessionStream;
use murmur_mieru::trafficpattern::Config;
use murmur_std_compat::net::Addr;

pub struct Listener {
    server: Arc<Server>,
    closed: AtomicBool,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Listener").field("closed", &self.closed.load(Ordering::Relaxed)).finish_non_exhaustive()
    }
}

impl Listener {
    /// The bound addresses, one per configured port.
    pub fn bound_addrs(&self) -> &[SocketAddr] {
        self.server.bound_addrs()
    }

    /// Answers the request, then relays the session as a TCP connection or as a UDP-associate
    /// packet stream.
    async fn handle(
        &self,
        stream: SessionStream,
        request: &murmur_mieru::model::Request,
        tunnel: Arc<dyn Tunnel>,
        additions: Vec<Addition>,
    ) {
        let mut stream = stream;
        if let Err(err) = Response::success().write_to(&mut stream).await {
            debugln!("Mieru inbound: writing the response failed: {err}");
            return;
        }
        match request.command {
            CMD_CONNECT => self.handle_tcp(stream, request, tunnel, additions).await,
            CMD_UDP_ASSOCIATE => self.handle_udp(stream, request, tunnel, additions).await,
            other => debugln!("Mieru inbound: unknown command {other}"),
        }
    }

    async fn handle_tcp(
        &self,
        stream: SessionStream,
        request: &murmur_mieru::model::Request,
        tunnel: Arc<dyn Tunnel>,
        additions: Vec<Addition>,
    ) {
        let session = Arc::clone(stream.session());
        let mut metadata = Metadata {
            network: NetWork::TCP,
            type_: murmur_constant::metadata::Type::MIERU,
            dst_port: request.dst_addr.port(),
            ..Metadata::default()
        };
        match &request.dst_addr {
            AddrSpec::Fqdn(host, _) => metadata.host = host.clone(),
            AddrSpec::Ip(ip, _) => metadata.dst_ip = Some(*ip),
        }
        let src_addr = session.peer_addr().map(boxed_udp_addr);
        let in_addr = session.local_addr().map(boxed_udp_addr);

        apply_additions(
            &mut metadata,
            &[with_in_name(session.user_name().unwrap_or_default()), with_src_addr(src_addr), with_in_addr(in_addr)],
        );
        apply_additions(&mut metadata, &additions);
        tunnel.handle_tcp_conn(Box::new(SessionConn { session: stream }), metadata).await;
    }

    async fn handle_udp(
        &self,
        stream: SessionStream,
        _request: &murmur_mieru::model::Request,
        tunnel: Arc<dyn Tunnel>,
        additions: Vec<Addition>,
    ) {
        let session = Arc::clone(stream.session());
        let (read_half, write_half) = tokio::io::split(stream);
        let writer = Arc::new(AsyncMutex::new(UdpAssociateWrapper::new(write_half)));
        let mut reader = UdpAssociateWrapper::new(read_half);
        let peer_addr = session.peer_addr();
        let local_addr = session.local_addr();

        loop {
            let Ok((payload, from)) = reader.recv_from().await else {
                break;
            };
            let target = murmur_transport::socks5::socks5::Addr(from.encode());
            let packet =
                Arc::new(MieruUdpPacket { data: payload, writer: Arc::clone(&writer), source: peer_addr, local_addr });
            // Bind unannotated first: annotating `Arc::clone` would fix its generic
            // parameter to the trait object and reject the unsizing coercion.
            let packet_arc = Arc::clone(&packet);
            let packet_dyn: Arc<dyn UDPPacket> = packet_arc;
            let (packet, metadata) =
                new_packet(&target, packet_dyn, murmur_constant::metadata::Type::MIERU, &additions);
            tunnel.handle_udp_packet(packet, metadata);
        }
    }
}

/// The mieru session presented as a conn: `conn` goes straight to the tunnel.
struct SessionConn {
    session: SessionStream,
}

impl AsyncRead for SessionConn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.session).poll_read(cx, buf)
    }
}

impl AsyncWrite for SessionConn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.session).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.session).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.session).poll_shutdown(cx)
    }
}

#[async_trait]
impl NetStream for SessionConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.session.session().local_addr().ok_or_else(|| io::Error::other("mieru session has no local address"))
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.session.session().peer_addr().ok_or_else(|| io::Error::other("mieru session has no peer address"))
    }
}

/// `packet`: replies go back through the same UDP-associate stream, addressed to the source the
/// request came from. The writer is generic so a test can drive `write_back` over an in-memory
/// stream; production only ever instantiates it with the session's own write half.
struct MieruUdpPacket<W> {
    data: Vec<u8>,
    writer: Arc<AsyncMutex<UdpAssociateWrapper<W>>>,
    source: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
}

/// The zero address stand-in: a mieru session with no recorded underlay address reports the
/// unspecified address, the same way [`UDPPacket::local_addr`] does.
const UNSPECIFIED: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// The session's underlay addresses are handed to the additions as generic address values, so
/// both the TCP and the
/// UDP-associate path box them through here.
fn boxed_udp_addr(addr: SocketAddr) -> Box<dyn Addr> {
    Box::new(udp_addr_from_socket_addr(addr))
}

#[async_trait]
impl<W: AsyncWrite + Unpin + Send> WriteBack for MieruUdpPacket<W> {
    async fn write_back(&self, b: &[u8], addr: Option<SocketAddr>) -> Result<usize> {
        // An absent caller address makes the UDP encoder fail, which breaks the tunnel's
        // UDP-to-local loop. Substituting the request destination here instead would
        // attribute the reply to a peer the client never addressed, or emit an unroutable
        // `0.0.0.0:0` header when the session recorded no underlay address.
        let addr = addr.ok_or_else(|| anyhow::anyhow!("mieru: udp reply has no source address"))?;
        self.writer.lock().await.send_to(b, &AddrSpec::Ip(addr.ip(), addr.port())).await?;
        Ok(b.len())
    }
}

impl<W: AsyncWrite + Unpin + Send> UDPPacket for MieruUdpPacket<W> {
    fn data(&self) -> &[u8] {
        &self.data
    }

    fn drop_(&self) {}

    fn local_addr(&self) -> SocketAddr {
        self.source.unwrap_or(UNSPECIFIED)
    }

    /// the tunnel's own local address, i.e. the mieru session's.
    fn in_addr(&self) -> Option<SocketAddr> {
        Some(self.local_addr.unwrap_or(UNSPECIFIED))
    }
}

/// `New`: starts the mieru server on the already-bound endpoints and serves accepted sessions.
#[expect(clippy::unused_async, reason = "the listener factory is awaited by every caller; the body only spawns")]
#[expect(clippy::implicit_hasher, reason = "public signature: callers pass the inbound's own users map")]
pub async fn new(
    users: &HashMap<String, String>,
    endpoints: Vec<ServerEndpoint>,
    user_hint_is_mandatory: bool,
    traffic_pattern: Option<Config>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<Listener>> {
    let server = Arc::new(Server::new(users, endpoints, user_hint_is_mandatory, traffic_pattern)?);
    let listener = Arc::new(Listener { server, closed: AtomicBool::new(false) });

    let accept_listener = Arc::clone(&listener);
    let accept_tunnel = Arc::clone(&tunnel);
    let accept_additions = additions.clone();
    tokio::spawn(async move {
        while let Some((stream, request)) = accept_listener.server.accept().await {
            if accept_listener.closed.load(Ordering::SeqCst) {
                break;
            }
            let listener = Arc::clone(&accept_listener);
            let tunnel = Arc::clone(&accept_tunnel);
            let additions = accept_additions.clone();
            tokio::spawn(async move { listener.handle(stream, &request, tunnel, additions).await });
        }
    });

    Ok(listener)
}

impl MultiAddrListener for Listener {
    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        self.server.close();
        Ok(())
    }

    fn config(&self) -> String {
        String::new()
    }

    fn addr_list(&self) -> Vec<Box<dyn Addr>> {
        self.server
            .bound_addrs()
            .iter()
            .map(|addr| -> Box<dyn Addr> { Box::new(murmur_std_compat::net::TcpAddr::from(*addr)) })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `WriteBack` encodes the caller-supplied reply address into the SOCKS5 UDP header, and passes
    /// the session address only as the write destination, which the stream tunnel discards. The
    /// tunnel supplies the real source of the reply, so encoding the session's
    /// TCP peer instead makes every reply header name the mieru client rather than the origin.
    #[tokio::test]
    async fn write_back_encodes_the_caller_supplied_reply_address() {
        let (client_side, server_side) = tokio::io::duplex(4096);
        let writer = Arc::new(AsyncMutex::new(UdpAssociateWrapper::new(server_side)));
        let session_peer: SocketAddr = "198.51.100.7:40000".parse().expect("session peer");
        let packet = MieruUdpPacket {
            data: b"request-payload".to_vec(),
            writer,
            source: Some(session_peer),
            local_addr: Some("203.0.113.4:5000".parse().expect("local addr")),
        };

        let reply_from: SocketAddr = "192.0.2.53:5353".parse().expect("reply source");
        packet.write_back(b"reply-payload", Some(reply_from)).await.expect("write back");

        let (payload, addr) =
            UdpAssociateWrapper::new(client_side).recv_from().await.expect("read the reply packet off the wire");
        assert_eq!(payload, b"reply-payload");
        assert_eq!(
            addr,
            AddrSpec::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 53)), 5353),
            "the SOCKS5 reply header must carry the caller's address, not the session's TCP peer"
        );
    }

    /// The write-back has no fallback: with an absent caller address the encoder fails and the
    /// tunnel's UDP-to-local loop breaks. Substituting the request's own
    /// destination produced a well-formed header naming a peer the client never sent to, and an
    /// unroutable `0.0.0.0:0` whenever the session carried no underlay address.
    #[tokio::test]
    async fn write_back_without_a_reply_address_fails_instead_of_inventing_one() {
        let (mut client_side, server_side) = tokio::io::duplex(4096);
        let writer = Arc::new(AsyncMutex::new(UdpAssociateWrapper::new(server_side)));
        let packet = MieruUdpPacket { data: b"request-payload".to_vec(), writer, source: None, local_addr: None };

        let err = packet
            .write_back(b"reply-payload", None)
            .await
            .expect_err("a reply with no source address must not be encoded");
        assert!(err.to_string().contains("no source address"), "unexpected error: {err}");

        let mut reader = UdpAssociateWrapper::new(&mut client_side);
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), reader.recv_from()).await;
        assert!(read.is_err(), "nothing may reach the wire: {read:?}");
    }
}

#![cfg(feature = "extra-protocols")]
//! Drives the wireguard outbound's `dial_context` end to end: option decode, the connected
//! UDP bind, the device handshake, the engine's stack and a payload round trip, against a
//! peer that answers on a real loopback socket.
//!
//! The peer's side of the tunnel is a minimal smoltcp host, because the engine stack exposes
//! only a TCP client; the tun the peer's device decrypts into is the wire between them.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::pedantic,
    clippy::nursery
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use base64::Engine as _;
use murmur_adapter_outbound::wireguard::WireGuard;
use murmur_component_wireguard::bind::{Bind, ReservedBind};
use murmur_component_wireguard::device::{Device, DeviceConfig, PeerConfig, Tun};
use murmur_component_wireguard::keys::{PresharedKey, PublicKey, StaticKey};
use murmur_component_wireguard::stack::ChannelPhy;
use murmur_constant::adapters::ProxyAdapter as CProxyAdapter;
use murmur_constant::metadata::{Metadata, NetWork};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, IpListenEndpoint, Ipv4Address, Ipv4Cidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

const CLIENT_PREFIX: &str = "10.0.0.2/32";
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const CLIENT_PRIVATE: [u8; 32] = [0x21; 32];
const SERVER_PRIVATE: [u8; 32] = [0x42; 32];
const ECHO_PORT: u16 = 8_080;
const MTU: u16 = 1_408;
const PAYLOAD: &[u8] = b"wireguard-adapter-e2e";
const TIMEOUT: Duration = Duration::from_secs(20);

/// The peer's UDP transport: the socket the adapter's dialer reaches, and the address the
/// device sends every handshake and transport message to.
struct SocketBind {
    socket: UdpSocket,
}

#[async_trait::async_trait]
impl Bind for SocketBind {
    async fn send_to(&self, packet: &[u8], endpoint: SocketAddr) -> std::io::Result<()> {
        self.socket.send_to(packet, endpoint).await.map(|_| ())
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buffer).await
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn close(&self) -> std::io::Result<()> {
        Ok(())
    }
}

static ORIGIN: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);

fn now() -> SmolInstant {
    SmolInstant::from_millis(ORIGIN.elapsed().as_millis() as i64)
}

fn smoltcp_address(address: Ipv4Addr) -> Ipv4Address {
    let octets = address.octets();
    Ipv4Address::new(octets[0], octets[1], octets[2], octets[3])
}

/// A TCP echo host inside the tunnel: one smoltcp interface over the peer's tun, listening
/// on `ECHO_PORT` and writing back whatever it receives.
async fn run_echo_host(tun: Tun) {
    let mut device = ChannelPhy::new(tun, usize::from(MTU));
    let mut iface = Interface::new(IfaceConfig::new(HardwareAddress::Ip), &mut device, now());
    iface.update_ip_addrs(|addresses| {
        let _ = addresses.push(IpCidr::Ipv4(Ipv4Cidr::new(smoltcp_address(SERVER_IP), 32)));
    });
    iface.routes_mut().add_default_ipv4_route(Ipv4Address::UNSPECIFIED).expect("default route");
    let mut sockets = SocketSet::new(vec![]);
    let handle = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
    ));

    loop {
        {
            let socket: &mut tcp::Socket = sockets.get_mut(handle);
            if !socket.is_open() {
                let _ = socket.listen(IpListenEndpoint { addr: None, port: ECHO_PORT });
            }
        }
        iface.poll(now(), &mut device, &mut sockets);
        let socket: &mut tcp::Socket = sockets.get_mut(handle);
        while socket.can_recv() {
            let mut buffer = [0u8; 1024];
            match socket.recv_slice(&mut buffer) {
                Ok(size) if size != 0 => {
                    if socket.send_slice(&buffer[..size]).is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

fn credential(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// A peer listening on a real loopback socket, with an echo host behind its tun. The device
/// answers only a handshake from `client_public`, so a wrong key never gets through.
async fn start_peer(client_public: PublicKey) -> (Arc<Device>, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("peer socket");
    let address = socket.local_addr().expect("peer address");
    let (responder, tun) = Device::new(
        "wireguard-e2e-responder".to_owned(),
        Arc::new(ReservedBind::new(Arc::new(SocketBind { socket }), [0u8; 3])),
        DeviceConfig {
            private_key: StaticKey::from_bytes(SERVER_PRIVATE),
            peers: vec![PeerConfig {
                public_key: client_public,
                preshared_key: PresharedKey::zeroed(),
                endpoint: None,
                allowed_ips: vec![CLIENT_PREFIX.parse().expect("client prefix")],
                persistent_keepalive: 0,
            }],
            mtu: MTU,
        },
    )
    .expect("responder device");
    tokio::spawn(run_echo_host(tun));
    (responder, address)
}

fn outbound(peer: SocketAddr, client_private: [u8; 32], peer_public: &[u8; 32]) -> Arc<WireGuard> {
    let yaml = format!(
        "name: wireguard-e2e\n\
         server: {}\n\
         port: {}\n\
         ip: {CLIENT_PREFIX}\n\
         private-key: {}\n\
         public-key: {}\n\
         mtu: {MTU}\n",
        peer.ip(),
        peer.port(),
        credential(&client_private),
        credential(peer_public),
    );
    WireGuard::new(yaml_serde::from_str(&yaml).expect("wireguard option")).expect("wireguard outbound")
}

fn tcp_metadata() -> Metadata {
    Metadata { network: NetWork::TCP, dst_ip: Some(IpAddr::V4(SERVER_IP)), dst_port: ECHO_PORT, ..Default::default() }
}

/// The outbound's whole dial path: the YAML option, the lazily built device and stack, and a
/// TCP payload that crosses the handshake, gets echoed by the peer and comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_wireguard_outbound_dials_a_tcp_payload_through_the_tunnel() {
    let client_private = CLIENT_PRIVATE;
    let client_static = StaticKey::from_bytes(client_private);
    let server_public = StaticKey::from_bytes(SERVER_PRIVATE).public_key();
    let (responder, peer) = start_peer(client_static.public_key()).await;
    let outbound = outbound(peer, client_private, server_public.as_bytes());

    let ctx = CancellationToken::new();
    let mut metadata = tcp_metadata();
    let mut conn =
        tokio::time::timeout(TIMEOUT, <WireGuard as CProxyAdapter>::dial_context(&*outbound, &ctx, &mut metadata))
            .await
            .expect("the adapter never finished dialing")
            .expect("dial through the tunnel");

    conn.write_all(PAYLOAD).await.expect("write through the tunnel");
    conn.flush().await.expect("flush through the tunnel");
    let mut echoed = vec![0u8; PAYLOAD.len()];
    tokio::time::timeout(TIMEOUT, conn.read_exact(&mut echoed))
        .await
        .expect("the echo never came back")
        .expect("read the echo");

    assert_eq!(echoed, PAYLOAD, "the peer must see exactly what the adapter sent");
    responder.close().expect("close responder");
}

/// The same dial against a peer that holds a different public key never gets a handshake, so
/// the tunnel cannot come up: the payload above only arrives because the keys really match.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_wireguard_outbound_never_completes_a_mismatched_handshake() {
    let client_static = StaticKey::from_bytes(CLIENT_PRIVATE);
    let wrong_public = StaticKey::from_bytes([0x77u8; 32]).public_key();
    let (responder, peer) = start_peer(client_static.public_key()).await;
    let outbound = outbound(peer, CLIENT_PRIVATE, wrong_public.as_bytes());

    let ctx = CancellationToken::new();
    let mut metadata = tcp_metadata();
    let dial = tokio::time::timeout(
        Duration::from_secs(3),
        <WireGuard as CProxyAdapter>::dial_context(&*outbound, &ctx, &mut metadata),
    )
    .await;
    assert!(dial.is_err(), "a mismatched key must not reach a TCP connection");
    responder.close().expect("close responder");
}

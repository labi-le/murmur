//! Drives the ZeroTier outbound the way an operator would: option YAML into `ZeroTier::new`, a
//! real runtime thread and UDP wire, and an engine peer that reaches the running node over the
//! host's own interface address.
//!
//! The runtime installs its data plane — the IP link and the stack device the ad-hoc
//! configuration assigns — before `ensure_started` returns. So the first test listens on the
//! runtime's own managed address and the second proves the link answers a frame the peer writes,
//! with the reply framed and delivered back over the same authenticated path.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![cfg(feature = "zerotier")]
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

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use murmur_adapter_outbound::zerotier::{ZeroTier, ZeroTierOption};
use murmur_component::iface::anet;
use murmur_component::iface::iface::interfaces;
use murmur_constant::adapters::{PacketConn as CPacketConn, ProxyAdapter as CProxyAdapter};
use murmur_constant::metadata::Metadata;
use murmur_constant::path::PATH;
use murmur_zerotier::address::Address;
use murmur_zerotier::frame::{Frame, ETHER_TYPE_ARP, ETHER_TYPE_IPV4};
use murmur_zerotier::identity::Identity;
use murmur_zerotier::mac::{mac_for_address, Mac};
use murmur_zerotier::node::peer::path_scope;
use murmur_zerotier::node::{MemoryStore, Node, NodeError, NodeHost, ANY_LOCAL_SOCKET};
use murmur_zerotier::six_plane_address;
use murmur_zerotier::wire::{UdpWire, WirePath};
use tokio_util::sync::CancellationToken;

/// The ad-hoc network whose low byte makes the engine synthesize an accept-all rule set, so a
/// controller is never needed and both nodes accept the frame.
const NETWORK: &str = "ff00000000000001";
const NETWORK_ID: u64 = 0xff00_0000_0000_0001;
const TIMEOUT: Duration = Duration::from_secs(30);

/// A UDP port nothing holds, taken by binding and releasing it.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .expect("bind a probe socket")
        .local_addr()
        .expect("the probe socket is bound")
        .port()
}

/// The engine drops loopback endpoints as paths (`node/peer.rs:530`), so the peer must dial an
/// address of the host's own interfaces.
async fn local_path_endpoint(port: u16) -> SocketAddr {
    let interfaces = interfaces().await.expect("enumerate the host interfaces");
    let address = interfaces
        .values()
        .filter(|interface| {
            interface.flags.contains(anet::Flags::FLAG_UP) && !interface.flags.contains(anet::Flags::FLAG_LOOPBACK)
        })
        .flat_map(|interface| interface.addresses.iter())
        .map(|prefix| prefix.addr())
        .find(|address| address.is_ipv4() && path_scope(*address) != 0)
        .expect("the host has a non-loopback IPv4 address");
    SocketAddr::new(address, port)
}

/// The IPv4 the engine's ad-hoc configuration assigns this node (`configure_ad_hoc_network_locked`).
fn ad_hoc_ipv4(address: Address) -> Ipv4Addr {
    let local = address.uint64();
    Ipv4Addr::new((NETWORK_ID >> 48) as u8, (local >> 16) as u8, (local >> 8) as u8, local as u8)
}

/// The 28-byte ARP request `Link::handle_arp` parses, with `sha` the sender's own MAC.
fn arp_request(sha: Mac, spa: Ipv4Addr, tpa: Ipv4Addr) -> Vec<u8> {
    let mut payload = vec![0u8; 28];
    payload[0..2].copy_from_slice(&1u16.to_be_bytes());
    payload[2..4].copy_from_slice(&ETHER_TYPE_IPV4.to_be_bytes());
    payload[4] = 6;
    payload[5] = 4;
    payload[6..8].copy_from_slice(&1u16.to_be_bytes());
    payload[8..14].copy_from_slice(&sha.bytes());
    payload[14..18].copy_from_slice(&spa.octets());
    payload[24..28].copy_from_slice(&tpa.octets());
    payload
}

struct Runtime {
    outbound: Arc<ZeroTier>,
    cancel: CancellationToken,
    port: u16,
    state_dir: String,
}

impl Runtime {
    fn new(name: &str) -> Self {
        let port = free_udp_port();
        let state_dir = format!("zerotier-e2e-{name}-{}", std::process::id());
        let _ = std::fs::remove_dir_all(PATH.resolve(&state_dir));
        let option: ZeroTierOption = yaml_serde::from_str(&format!(
            "name: {name}\nnetwork: {NETWORK}\nstate-dir: {state_dir}\nprimary-port: {port}\n"
        ))
        .expect("the option decodes");
        Self {
            outbound: ZeroTier::new(option).expect("the option is valid"),
            cancel: CancellationToken::new(),
            port,
            state_dir,
        }
    }
}

/// The identity the runtime persisted. Its first `listen_packet_context` returns only after the
/// runtime installed its configuration, and the runtime writes the identity before that.
fn persisted_identity(state_dir: &str) -> Identity {
    let path = PathBuf::from(PATH.resolve(state_dir)).join("identity.public");
    let text = std::fs::read_to_string(&path).expect("the runtime persisted an identity");
    Identity::parse(&text).expect("the persisted identity parses")
}

/// Starts the runtime and listens on the address its own configuration assigns it. The first
/// listen starts the runtime, and the managed address follows from the identity it persisted.
async fn listen_on_managed_address(
    outbound: &ZeroTier,
    cancel: &CancellationToken,
    state_dir: &str,
) -> (Identity, anyhow::Result<Arc<dyn CPacketConn>>) {
    let probe = <ZeroTier as CProxyAdapter>::listen_packet_context(outbound, cancel, &mut Metadata::default())
        .await
        .err()
        .expect("a listen without a resolved destination cannot reach the data plane");
    assert!(
        probe.to_string().contains("destination is not resolved"),
        "the probe is refused for its unresolved destination, not because the runtime failed to start: {probe}"
    );
    let remote = persisted_identity(state_dir);
    let managed = six_plane_address(NETWORK_ID, remote.address()).addr();
    let mut metadata = Metadata { dst_ip: Some(managed), ..Metadata::default() };
    let conn = <ZeroTier as CProxyAdapter>::listen_packet_context(outbound, cancel, &mut metadata).await;
    (remote, conn)
}

struct PeerHost {
    remote: Identity,
    queue: Arc<Mutex<VecDeque<(SocketAddr, Vec<u8>)>>>,
}

impl NodeHost for PeerHost {
    fn peer_identity(&self, address: Address) -> Option<Identity> {
        (address == self.remote.address()).then(|| self.remote.clone())
    }

    fn send_wire(&mut self, _local_socket: i64, remote: SocketAddr, packet: Vec<u8>) -> Result<(), NodeError> {
        self.queue.lock().expect("lock").push_back((remote, packet));
        Ok(())
    }

    fn request_whois(&mut self, _address: Address) {}

    fn announce_multicast(&mut self, _network_id: u64) {}

    fn trace_network_config_request(&mut self, _network_id: u64, _controller: Address) {}
}

/// The engine peer that talks to the running runtime over its own real UDP socket.
struct PeerNode {
    node: Node,
    wire: UdpWire,
    queue: Arc<Mutex<VecDeque<(SocketAddr, Vec<u8>)>>>,
    identity: Identity,
    remote: Identity,
    remote_endpoint: SocketAddr,
    remote_seen: Option<SocketAddr>,
    frames: Vec<Frame>,
}

impl PeerNode {
    async fn new(remote: Identity, remote_endpoint: SocketAddr) -> Self {
        let identity = Identity::generate();
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let host = PeerHost { remote: remote.clone(), queue: Arc::clone(&queue) };
        let mut node = Node::new(identity.clone(), Box::new(MemoryStore::new()), Box::new(host));
        node.join(NETWORK_ID, SystemTime::now()).expect("the peer joins the ad-hoc network");
        let wire = UdpWire::bind(0, 0).await.expect("bind the peer wire");
        Self { node, wire, queue, identity, remote, remote_endpoint, remote_seen: None, frames: Vec::new() }
    }

    async fn flush(&mut self) {
        loop {
            let Some((remote, packet)) = self.queue.lock().expect("lock").pop_front() else {
                return;
            };
            self.wire.send(WirePath { remote, socket: 0 }, &packet).await.expect("the peer wire sends");
        }
    }

    async fn collect(&mut self, quiet: Duration) -> Vec<Vec<u8>> {
        let mut inbound = Vec::new();
        while let Ok(Some((data, source))) = tokio::time::timeout(quiet, self.wire.recv_from()).await {
            self.remote_seen = Some(source);
            let _ = self.node.process_wire_packet(ANY_LOCAL_SOCKET, source, &data, SystemTime::now());
            let _ = self.node.take_events();
            self.frames.extend(self.node.take_delivered_frames());
            inbound.push(data);
        }
        inbound
    }

    async fn pump_until(&mut self, timeout: Duration, ready: impl Fn(&Node) -> bool) -> (Vec<Vec<u8>>, bool) {
        let start = Instant::now();
        let mut inbound = Vec::new();
        loop {
            self.flush().await;
            inbound.extend(self.collect(Duration::from_millis(20)).await);
            if ready(&self.node) {
                return (inbound, true);
            }
            if start.elapsed() >= timeout {
                return (inbound, false);
            }
        }
    }

    async fn handshake(&mut self, timeout: Duration) -> bool {
        let remote = self.remote.address();
        self.node.send_hello_locked(remote, self.remote_endpoint, SystemTime::now()).expect("the peer queues a HELLO");
        let (_, ready) =
            self.pump_until(timeout, move |node| node.best_peer_endpoint(remote, SystemTime::now()).is_some()).await;
        ready
    }

    fn queued(&self) -> usize {
        self.queue.lock().expect("lock").len()
    }

    async fn pump_until_frame(&mut self, timeout: Duration, matches: impl Fn(&Frame) -> bool) -> Option<Frame> {
        let start = Instant::now();
        loop {
            self.flush().await;
            self.collect(Duration::from_millis(50)).await;
            if let Some(index) = self.frames.iter().position(&matches) {
                return Some(self.frames.remove(index));
            }
            if start.elapsed() >= timeout {
                return None;
            }
        }
    }

    /// Hands `request` to the peer's node and pumps the wire until the runtime's ARP reply is
    /// delivered, re-asking while the runtime may still be entering its frame loop.
    async fn arp_round_trip(&mut self, runtime_mac: Mac, request: &[u8], timeout: Duration) -> Frame {
        let deadline = Instant::now() + timeout;
        loop {
            let queued_before = self.queued();
            self.node
                .send_frame(NETWORK_ID, runtime_mac, ETHER_TYPE_ARP, request, SystemTime::now())
                .expect("the peer's rules accept the ARP request");
            assert_eq!(
                self.queued(),
                queued_before + 1,
                "the frame becomes exactly one FRAME datagram on the peer's wire queue"
            );
            let reply = self
                .pump_until_frame(Duration::from_secs(2), |frame| {
                    frame.ether_type == ETHER_TYPE_ARP && frame.source == runtime_mac
                })
                .await;
            if let Some(reply) = reply {
                return reply;
            }
            assert!(Instant::now() < deadline, "the runtime never answered the peer's ARP request");
        }
    }
}

#[tokio::test]
async fn an_engine_peer_reaches_the_running_zerotier_runtime_and_its_data_plane() {
    let Runtime { outbound, cancel, port, state_dir, .. } = Runtime::new("zt-e2e-reach");
    let peer_endpoint = local_path_endpoint(port).await;
    let (runtime_identity, conn) = listen_on_managed_address(&outbound, &cancel, &state_dir).await;
    let mut peer = PeerNode::new(runtime_identity.clone(), peer_endpoint).await;
    let handshaked = peer.handshake(TIMEOUT).await;

    assert!(
        conn.is_ok(),
        "the runtime's data plane serves its own managed address: {:?}",
        conn.as_ref().err().map(ToString::to_string)
    );
    drop(conn);
    assert!(handshaked, "the running runtime answered the peer's HELLO from its own socket");

    let runtime_address = runtime_identity.address();
    let managed = six_plane_address(NETWORK_ID, runtime_address).addr();
    assert_eq!(
        murmur_zerotier::address_from_six_plane(NETWORK_ID, managed),
        Some(runtime_address),
        "the address the data plane serves belongs to the running node"
    );
    let now = SystemTime::now();
    let runtime_source = peer.remote_seen.expect("the runtime answered from its own socket");
    assert_eq!(peer.node.best_peer_endpoint(runtime_address, now), Some(runtime_source));
    let paths = peer
        .node
        .peers(now)
        .into_iter()
        .find(|known| known.address == runtime_address)
        .expect("the runtime is a known peer")
        .paths;
    assert_eq!(paths.len(), 1, "the peer holds exactly one authenticated path");
    assert!(paths[0].active && paths[0].preferred);
    assert_eq!(paths[0].endpoint, runtime_source, "the path is the runtime's own socket");
    assert_eq!(paths[0].endpoint.port(), port, "the runtime answers from its configured port");

    let secret = std::fs::read_to_string(PathBuf::from(PATH.resolve(&state_dir)).join("identity.secret"))
        .expect("the runtime persisted its identity on disk");
    assert!(Identity::parse(&secret).expect("the persisted identity parses").has_private());

    outbound.close().expect("close the outbound");
    let mut metadata = Metadata::default();
    let again = <ZeroTier as CProxyAdapter>::dial_context(&*outbound, &cancel, &mut metadata).await;
    assert!(
        again.err().is_some_and(|err| err.to_string().contains("ZeroTier outbound closed")),
        "a closed outbound fails closed"
    );

    let _ = std::fs::remove_dir_all(PATH.resolve(&state_dir));
}

/// The running runtime takes the peer's ARP request into its link and answers it with a reply
/// the peer's node then delivers: both directions of the frame path are exercised over the wire.
#[tokio::test]
async fn the_running_zerotier_runtime_answers_a_peer_frame_over_the_wire() {
    let Runtime { outbound, cancel, port, state_dir, .. } = Runtime::new("zt-e2e-frame");
    let peer_endpoint = local_path_endpoint(port).await;
    let (runtime_identity, conn) = listen_on_managed_address(&outbound, &cancel, &state_dir).await;
    let mut peer = PeerNode::new(runtime_identity.clone(), peer_endpoint).await;
    let handshaked = peer.handshake(TIMEOUT).await;

    assert!(
        conn.is_ok(),
        "the runtime's data plane serves its own managed address: {:?}",
        conn.as_ref().err().map(ToString::to_string)
    );
    drop(conn);
    assert!(handshaked, "the running runtime answered the peer's HELLO from its own socket");
    assert_eq!(
        peer.node
            .peers(SystemTime::now())
            .into_iter()
            .filter(|known| known.address == runtime_identity.address())
            .count(),
        1,
        "the peer learned the runtime's node"
    );

    let runtime_address = runtime_identity.address();
    let runtime_mac = mac_for_address(runtime_address, NETWORK_ID);
    let peer_mac = mac_for_address(peer.identity.address(), NETWORK_ID);
    let runtime_ipv4 = ad_hoc_ipv4(runtime_address);
    let peer_ipv4 = ad_hoc_ipv4(peer.identity.address());
    let request = arp_request(peer_mac, peer_ipv4, runtime_ipv4);
    let reply = peer.arp_round_trip(runtime_mac, &request, TIMEOUT).await;

    assert_eq!(reply.network_id, NETWORK_ID);
    assert_eq!(reply.destination, peer_mac, "the reply is unicast to the peer that asked");
    assert_eq!(reply.payload.len(), 28, "an ARP reply carries the 28-byte IPv4 body");
    let payload = &reply.payload;
    assert_eq!(u16::from_be_bytes([payload[6], payload[7]]), 2, "the operation is a reply");
    assert_eq!(&payload[8..14], &runtime_mac.bytes()[..], "the runtime answers with its own MAC");
    assert_eq!(&payload[14..18], &runtime_ipv4.octets()[..], "the sender address is the runtime's managed IPv4");
    assert_eq!(&payload[18..24], &peer_mac.bytes()[..], "the target hardware address is the peer's MAC");
    assert_eq!(&payload[24..28], &peer_ipv4.octets()[..], "the target address is the peer's own source");

    outbound.close().expect("close the outbound");
    let _ = std::fs::remove_dir_all(PATH.resolve(&state_dir));
}

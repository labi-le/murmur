//! End-to-end exercises for the two halves that only fail when they run together: the
//! userspace IP stack over a real `smoltcp` driver, and the WireGuard device over a real
//! initiator/responder handshake.
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

use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use murmur_common::net::Datagram;
use murmur_component_wireguard::bind::Bind;
use murmur_component_wireguard::cookie::{address_bytes, CookieChecker, CookieGenerator, MessageCookieReply};
use murmur_component_wireguard::device::{Device, DeviceConfig, PeerConfig, QUEUE_HANDSHAKE_SIZE};
use murmur_component_wireguard::handshake::Initiator;
use murmur_component_wireguard::keys::{PresharedKey, StaticKey};
use murmur_component_wireguard::stack::{Events, Stack, StackConfig, PACKET_QUEUE_SIZE, UDP_SOCKET_PACKETS};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant as SmolInstant;

/// One direction of a wire: a queue the driver drains, and the peer's queue to fill. The
/// events handle belongs to the stack that drains the queue, exactly as a packet device
/// signals its own reader.
struct Wire {
    queue: Mutex<VecDeque<Vec<u8>>>,
    events: Events,
}

impl Wire {
    fn new(events: Events) -> Self {
        Self { queue: Mutex::new(VecDeque::new()), events }
    }

    fn push(&self, packet: Vec<u8>) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.push_back(packet);
        }
        self.events.notify();
    }

    fn pop(&self) -> Option<Vec<u8>> {
        self.queue.lock().ok().and_then(|mut queue| queue.pop_front())
    }
}

struct Endpoint {
    inbound: Arc<Wire>,
    outbound: Arc<Wire>,
}

struct Loopback {
    inbound: Arc<Wire>,
    outbound: Arc<Wire>,
    mtu: usize,
    scratch: Vec<u8>,
}

impl phy::Device for Loopback {
    type RxToken<'a> = Rx<'a>;
    type TxToken<'a> = Tx;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Rx<'_>, Tx)> {
        let packet = self.inbound.pop()?;
        let len = packet.len().min(self.scratch.len());
        self.scratch[..len].copy_from_slice(&packet[..len]);
        Some((Rx(&self.scratch[..len]), Tx(Arc::clone(&self.outbound))))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Tx> {
        Some(Tx(Arc::clone(&self.outbound)))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

struct Rx<'a>(&'a [u8]);

impl phy::RxToken for Rx<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0)
    }
}

struct Tx(Arc<Wire>);

impl phy::TxToken for Tx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.0.push(buffer);
        result
    }
}

fn linked() -> (Endpoint, Endpoint, Events, Events) {
    let a_events = Events::default();
    let b_events = Events::default();
    let a_in = Arc::new(Wire::new(a_events.clone()));
    let b_in = Arc::new(Wire::new(b_events.clone()));
    (
        Endpoint { inbound: Arc::clone(&a_in), outbound: Arc::clone(&b_in) },
        Endpoint { inbound: Arc::clone(&b_in), outbound: Arc::clone(&a_in) },
        a_events,
        b_events,
    )
}

fn loopback(endpoint: &Endpoint, mtu: usize) -> Loopback {
    Loopback {
        inbound: Arc::clone(&endpoint.inbound),
        outbound: Arc::clone(&endpoint.outbound),
        mtu,
        scratch: vec![0u8; mtu],
    }
}

fn prefix(address: &str) -> ipnet::IpNet {
    address.parse().expect("literal prefix")
}

async fn with_timeout<F: Future>(label: &str, future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(20), future).await.unwrap_or_else(|_| panic!("{label} timed out"))
}

/// A datagram written into one stack's UDP socket has to come out of the other one's, with
/// the same payload and the sender's address restored.
#[tokio::test]
async fn a_udp_datagram_crosses_the_stack() {
    let (a, b, a_events, b_events) = linked();
    let client = Stack::with_device(
        StackConfig { local_addresses: vec![prefix("10.0.0.2/32")], mtu: 1500 },
        loopback(&a, 1500),
        a_events,
    )
    .expect("client stack");
    let server = Stack::with_device(
        StackConfig { local_addresses: vec![prefix("10.0.0.1/32")], mtu: 1500 },
        loopback(&b, 1500),
        b_events,
    )
    .expect("server stack");

    let listener = with_timeout("listen_udp", server.listen_udp(None)).await.expect("bind");
    let listener_port = listener.local_endpoint().port();
    assert_ne!(listener_port, 0, "a wildcard bind must hold a real port");
    let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), listener_port);
    let sender = with_timeout("dial_udp", client.dial_udp(None, destination)).await.expect("dial");

    Datagram::send_to(&sender, b"ping", destination).await.expect("send");

    let mut buffer = [0u8; 64];
    let (size, source) = with_timeout("recv_from", listener.recv_from(&mut buffer)).await.expect("receive");
    assert_eq!(&buffer[..size], b"ping");
    assert_eq!(source.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_ne!(source.port(), 0, "the client socket must hold a real ephemeral port");
}

/// A socket whose reader has stopped polling must not let the peer's stream pile up in this
/// process. The read side drains `smoltcp`'s receive buffer into the per-socket event queue, so
/// that queue's bound is what stops the drain once the consumer stalls: the backlog the socket
/// will hand over stays at the queue plus the `smoltcp` buffer rather than growing with the
/// sender's stream, and reading again restarts the drain.
#[tokio::test]
async fn a_non_reading_socket_bounds_the_backlog_the_stack_keeps() {
    const SENT: usize = 4096;
    let (_, server_end, _, server_events) = linked();
    let server = Stack::with_device(
        StackConfig { local_addresses: vec![prefix("10.0.0.1/32")], mtu: 1500 },
        loopback(&server_end, 1500),
        server_events,
    )
    .expect("server stack");

    let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9);
    let listener = with_timeout("listen_udp", server.listen_udp(Some(bound))).await.expect("bind");

    // The reader never runs while the peer writes, which is the stalled-consumer case. The
    // packets are paced so the driver moves each one off the wire before the next arrives:
    // only the event queue's bound can then stop the stack emptying the receive buffer.
    for _ in 0..SENT {
        server_end.inbound.push(udp_packet(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), b"x"));
        tokio::time::sleep(Duration::from_micros(200)).await;
    }
    // Let the tail of the stream arrive and be dropped by the socket's own `smoltcp` buffer, so
    // nothing is left in flight when the reader starts.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut buffer = [0u8; 64];
    let mut received = 0usize;
    loop {
        match tokio::time::timeout(Duration::from_secs(1), listener.recv_from(&mut buffer)).await {
            Ok(Ok(_)) => received += 1,
            Ok(Err(_)) | Err(_) => break,
        }
        assert!(received <= SENT, "the sender only wrote {SENT} datagrams");
    }
    assert!(received > PACKET_QUEUE_SIZE, "reading must restart the drain, got {received}");
    assert!(
        received <= PACKET_QUEUE_SIZE + 2 * UDP_SOCKET_PACKETS,
        "a stalled reader must bound the backlog to the queue and the socket's own buffer, \
         not to the sender's whole stream: got {received} of {SENT}"
    );
}

/// A minimal IPv4 + UDP packet; the device only reads the IP header and the length.
fn udp_packet(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let checksum = ones_complement(&packet[0..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&53_000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&9u16.to_be_bytes());
    packet[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

fn ones_complement(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !(sum as u16)
}

/// `sing-wireguard`'s `ClientBind` reduced to a pair of queues, so two devices can talk
/// without a socket.
struct PipeBind {
    outbound: Arc<Wire>,
    inbound: Arc<Wire>,
    endpoint: SocketAddr,
}

#[async_trait::async_trait]
impl Bind for PipeBind {
    async fn send_to(&self, packet: &[u8], _endpoint: SocketAddr) -> std::io::Result<()> {
        self.outbound.push(packet.to_vec());
        Ok(())
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        loop {
            if let Some(packet) = self.inbound.pop() {
                let size = packet.len().min(buffer.len());
                buffer[..size].copy_from_slice(&packet[..size]);
                return Ok((size, self.endpoint));
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.endpoint)
    }

    fn close(&self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A packet written into the initiator's tun crosses a completed handshake and is decrypted
/// into the responder's tun, and the reverse direction works the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_pair_carries_traffic_both_ways() {
    let initiator_static = StaticKey::from_bytes([0x11; 32]);
    let responder_static = StaticKey::from_bytes([0x22; 32]);
    let preshared = PresharedKey::from_bytes([0x33; 32]);
    let a_in = Arc::new(Wire::new(Events::default()));
    let b_in = Arc::new(Wire::new(Events::default()));
    let initiator_endpoint: SocketAddr = "192.0.2.1:51820".parse().expect("addr");
    let responder_endpoint: SocketAddr = "192.0.2.2:51820".parse().expect("addr");

    let (responder_device, mut responder_tun) = Device::new(
        "responder".to_owned(),
        Arc::new(murmur_component_wireguard::bind::ReservedBind::new(
            Arc::new(PipeBind {
                outbound: Arc::clone(&b_in),
                inbound: Arc::clone(&a_in),
                endpoint: initiator_endpoint,
            }),
            [0u8; 3],
        )),
        DeviceConfig {
            private_key: responder_static.clone(),
            peers: vec![PeerConfig {
                public_key: initiator_static.public_key(),
                preshared_key: preshared,
                endpoint: Some(initiator_endpoint),
                allowed_ips: vec![prefix("10.0.0.0/24")],
                persistent_keepalive: 0,
            }],
            mtu: 1408,
        },
    )
    .expect("responder device");

    let (initiator_device, mut initiator_tun) = Device::new(
        "initiator".to_owned(),
        Arc::new(murmur_component_wireguard::bind::ReservedBind::new(
            Arc::new(PipeBind {
                outbound: Arc::clone(&a_in),
                inbound: Arc::clone(&b_in),
                endpoint: responder_endpoint,
            }),
            [0u8; 3],
        )),
        DeviceConfig {
            private_key: initiator_static.clone(),
            peers: vec![PeerConfig {
                public_key: responder_static.public_key(),
                preshared_key: preshared,
                endpoint: Some(responder_endpoint),
                allowed_ips: vec![prefix("10.0.0.2/32")],
                persistent_keepalive: 0,
            }],
            mtu: 1408,
        },
    )
    .expect("initiator device");

    let destination = Ipv4Addr::new(10, 0, 0, 2);
    initiator_tun.write(udp_packet(Ipv4Addr::new(10, 0, 0, 1), destination, b"outbound"));

    let mut seen = Vec::new();
    for _ in 0..2_000 {
        if let Some(packet) = responder_tun.try_receive() {
            if packet.len() >= 28 && &packet[28..] == b"outbound" {
                seen = packet;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(&seen[28..], b"outbound", "the responder never decrypted the packet");
    assert_eq!(&seen[12..16], &Ipv4Addr::new(10, 0, 0, 1).octets());
    assert_eq!(&seen[16..20], &destination.octets());

    responder_tun.write(udp_packet(destination, Ipv4Addr::new(10, 0, 0, 1), b"inbound"));
    let mut seen = Vec::new();
    for _ in 0..2_000 {
        if let Some(packet) = initiator_tun.try_receive() {
            if packet.len() >= 28 && &packet[28..] == b"inbound" {
                seen = packet;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(&seen[28..], b"inbound", "the initiator never decrypted the reply");

    initiator_device.close().expect("close initiator");
    responder_device.close().expect("close responder");
    assert!(!initiator_device.is_up());
    assert!(!responder_device.is_up());
}

/// `listen_udp` has to bind the address it was given: the server stack holds two addresses,
/// so a listener that quietly fell back to the wildcard would take the datagram sent to the
/// other one.
#[tokio::test]
async fn a_udp_listener_holds_the_requested_local_address() {
    let (a, b, a_events, b_events) = linked();
    let client = Stack::with_device(
        StackConfig { local_addresses: vec![prefix("10.0.0.2/32")], mtu: 1500 },
        loopback(&a, 1500),
        a_events,
    )
    .expect("client stack");
    let server = Stack::with_device(
        StackConfig { local_addresses: vec![prefix("10.0.0.1/32"), prefix("10.0.0.3/32")], mtu: 1500 },
        loopback(&b, 1500),
        b_events,
    )
    .expect("server stack");

    let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 51_820);
    let listener = with_timeout("listen_udp", server.listen_udp(Some(bound))).await.expect("bind");
    assert_eq!(listener.local_endpoint(), bound, "the bind must keep the requested address and port");

    let elsewhere = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), bound.port());
    let other = with_timeout("dial_udp", client.dial_udp(None, elsewhere)).await.expect("dial");
    let owner = with_timeout("dial_udp", client.dial_udp(None, bound)).await.expect("dial");
    Datagram::send_to(&other, b"not-me", elsewhere).await.expect("send");
    Datagram::send_to(&owner, b"me", bound).await.expect("send");

    let mut buffer = [0u8; 64];
    let (size, _) = with_timeout("recv_from", listener.recv_from(&mut buffer)).await.expect("receive");
    assert_eq!(&buffer[..size], b"me", "the listener bound to 10.0.0.3 must not take a datagram for 10.0.0.1");
}

/// The wildcard keeps the requested port, and the stack refuses an address it does not hold.
#[tokio::test]
async fn a_udp_listener_refuses_a_foreign_address() {
    let (a, b, a_events, b_events) = linked();
    let _client = Stack::with_device(
        StackConfig { local_addresses: vec![prefix("10.0.0.2/32")], mtu: 1500 },
        loopback(&a, 1500),
        a_events,
    )
    .expect("client stack");
    let server = Stack::with_device(
        StackConfig { local_addresses: vec![prefix("10.0.0.1/32")], mtu: 1500 },
        loopback(&b, 1500),
        b_events,
    )
    .expect("server stack");

    let wildcard =
        with_timeout("listen_udp", server.listen_udp(Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 51_821))))
            .await
            .expect("bind");
    assert_eq!(wildcard.local_endpoint().port(), 51_821);

    let foreign = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)), 51_822);
    assert!(server.listen_udp(Some(foreign)).await.is_err(), "an address the stack does not hold has to be refused");
}

/// Waits for a packet the device put on `wire`, dropping everything the predicate rejects.
async fn wait_for(wire: &Wire, budget: Duration, predicate: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if let Some(packet) = wire.pop() {
            if predicate(&packet) {
                return Some(packet);
            }
            continue;
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// Packets that carry a valid `mac1` but cannot decrypt a static key, which is enough to
/// drive the responder's load counter without touching any peer's state.
fn flood_handshakes(wire: &Wire, cookies: &mut CookieGenerator) {
    for round in 0..QUEUE_HANDSHAKE_SIZE / 8 + 2 {
        let mut packet = vec![0u8; 148];
        packet[0..4].copy_from_slice(&1u32.to_le_bytes());
        packet[8] = round as u8;
        packet[40..88].copy_from_slice(&[0x5a; 48]);
        cookies.add_macs(&mut packet);
        wire.push(packet);
    }
}

/// The responder's under-load branch: a handshake whose `mac2` it cannot verify gets a
/// cookie reply rather than a dropped packet, and once the retry carries the derived `mac2`
/// the handshake completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_under_load_responder_answers_unverified_handshakes_with_a_cookie() {
    let initiator_static = StaticKey::from_bytes([0x11; 32]);
    let responder_static = StaticKey::from_bytes([0x22; 32]);
    let peer_endpoint: SocketAddr = "192.0.2.1:51820".parse().expect("addr");
    let a_in = Arc::new(Wire::new(Events::default()));
    let b_in = Arc::new(Wire::new(Events::default()));

    let (responder, _tun) = Device::new(
        "responder".to_owned(),
        Arc::new(murmur_component_wireguard::bind::ReservedBind::new(
            Arc::new(PipeBind { outbound: Arc::clone(&b_in), inbound: Arc::clone(&a_in), endpoint: peer_endpoint }),
            [0u8; 3],
        )),
        DeviceConfig {
            private_key: responder_static.clone(),
            peers: vec![PeerConfig {
                public_key: initiator_static.public_key(),
                preshared_key: PresharedKey::zeroed(),
                endpoint: Some(peer_endpoint),
                allowed_ips: vec![prefix("10.0.0.0/24")],
                persistent_keepalive: 0,
            }],
            mtu: 1408,
        },
    )
    .expect("responder device");

    let (_, initiation) =
        Initiator::create_message_initiation(&initiator_static, &responder_static.public_key(), 7).expect("initiation");
    let mut initiation = initiation.to_vec();
    let mut cookies = CookieGenerator::new(responder_static.public_key().as_bytes());
    cookies.add_macs(&mut initiation);
    assert_eq!(&initiation[132..], &[0u8; 16], "a first attempt carries mac1 only");
    let mut flood_cookies = CookieGenerator::new(responder_static.public_key().as_bytes());
    let is_our_cookie_reply = |packet: &[u8]| packet.len() == 64 && packet[4..8] == 7u32.to_le_bytes();

    flood_handshakes(&a_in, &mut flood_cookies);
    a_in.push(initiation.clone());
    let denial = wait_for(&b_in, Duration::from_secs(10), is_our_cookie_reply)
        .await
        .expect("the responder never sent a cookie reply");
    assert_eq!(&denial[0..4], &3u32.to_le_bytes(), "message type 3 is the cookie reply");
    assert!(
        cookies.consume_reply(&MessageCookieReply::unmarshal(&denial).expect("cookie reply")),
        "the reply must decrypt under the mac1 of the message it answers"
    );

    let mut forged = initiation.clone();
    cookies.add_macs(&mut forged);
    forged[147] ^= 1;
    flood_handshakes(&a_in, &mut flood_cookies);
    a_in.push(forged);
    let denial = wait_for(&b_in, Duration::from_secs(10), is_our_cookie_reply)
        .await
        .expect("a forged mac2 must be denied with another cookie reply");
    assert_eq!(&denial[0..4], &3u32.to_le_bytes());

    let mut retry = initiation;
    cookies.add_macs(&mut retry);
    flood_handshakes(&a_in, &mut flood_cookies);
    a_in.push(retry);
    let response =
        wait_for(&b_in, Duration::from_secs(10), |packet| packet.len() == 92 && packet[0..4] == 2u32.to_le_bytes())
            .await
            .expect("the responder never answered the verified handshake");
    assert_eq!(&response[8..12], &7u32.to_le_bytes(), "the response answers our sender index");
    assert!(
        wait_for(&b_in, Duration::from_millis(500), |packet| {
            packet.len() == 32 && packet[0..4] == 4u32.to_le_bytes()
        })
        .await
        .is_none(),
        "the new keypair is parked in `next`, so the responder sends no keepalive of its own"
    );

    responder.close().expect("close responder");
}

/// The initiator's half: the cookie a denied handshake earns is stored, and the
/// retransmission after the rekey timeout later carries the `mac2` derived from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_initiator_retries_with_the_cookie_it_was_given() {
    let initiator_static = StaticKey::from_bytes([0x44; 32]);
    let responder_static = StaticKey::from_bytes([0x55; 32]);
    let responder_endpoint: SocketAddr = "192.0.2.2:51820".parse().expect("addr");
    let a_in = Arc::new(Wire::new(Events::default()));
    let b_in = Arc::new(Wire::new(Events::default()));

    let (initiator, tun) = Device::new(
        "initiator".to_owned(),
        Arc::new(murmur_component_wireguard::bind::ReservedBind::new(
            Arc::new(PipeBind {
                outbound: Arc::clone(&a_in),
                inbound: Arc::clone(&b_in),
                endpoint: responder_endpoint,
            }),
            [0u8; 3],
        )),
        DeviceConfig {
            private_key: initiator_static.clone(),
            peers: vec![PeerConfig {
                public_key: responder_static.public_key(),
                preshared_key: PresharedKey::zeroed(),
                endpoint: Some(responder_endpoint),
                allowed_ips: vec![prefix("10.0.0.0/24")],
                persistent_keepalive: 0,
            }],
            mtu: 1408,
        },
    )
    .expect("initiator device");

    tun.write(udp_packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), b"cookie"));
    let first = wait_for(&a_in, Duration::from_secs(5), |packet| packet.len() == 148)
        .await
        .expect("the initiator never sent a handshake initiation");
    assert_eq!(&first[132..], &[0u8; 16], "an initiation without a cookie carries mac1 only");

    let mut checker = CookieChecker::new(responder_static.public_key().as_bytes());
    let sender = u32::from_le_bytes(first[4..8].try_into().expect("sender index"));
    let reply = checker.create_reply(&first, sender, &address_bytes(responder_endpoint.ip())).expect("cookie reply");
    b_in.push(reply.marshal().to_vec());

    let retry = wait_for(&a_in, Duration::from_secs(12), |packet| packet.len() == 148 && packet[4..8] != first[4..8])
        .await
        .expect("the initiator never retransmitted the handshake");
    assert!(
        checker.check_mac2(&retry, &address_bytes(responder_endpoint.ip())),
        "the retransmission must carry a mac2 derived from the cookie it was given"
    );
    initiator.close().expect("close initiator");
}

/// A bind that reports its own close, so a test can see that the device task reached its end.
struct ClosingBind {
    inner: PipeBind,
    closed: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl Bind for ClosingBind {
    async fn send_to(&self, packet: &[u8], endpoint: SocketAddr) -> std::io::Result<()> {
        self.inner.send_to(packet, endpoint).await
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buffer).await
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn close(&self) -> std::io::Result<()> {
        self.closed.notify_one();
        self.inner.close()
    }
}

/// The `Tun` holds the only sender into the device task, so dropping it has to stop the device
/// instead of leaving the loop re-entering on a channel that answers `None` forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_tun_stops_the_device() {
    let closed = Arc::new(tokio::sync::Notify::new());
    let peer_endpoint: SocketAddr = "192.0.2.1:51820".parse().expect("addr");
    let bind = Arc::new(ClosingBind {
        inner: PipeBind {
            outbound: Arc::new(Wire::new(Events::default())),
            inbound: Arc::new(Wire::new(Events::default())),
            endpoint: peer_endpoint,
        },
        closed: Arc::clone(&closed),
    });
    let (_device, tun) = Device::new(
        "dropped".to_owned(),
        Arc::new(murmur_component_wireguard::bind::ReservedBind::new(bind, [0u8; 3])),
        DeviceConfig {
            private_key: StaticKey::from_bytes([0x66; 32]),
            peers: vec![PeerConfig {
                public_key: StaticKey::from_bytes([0x77; 32]).public_key(),
                preshared_key: PresharedKey::zeroed(),
                endpoint: Some(peer_endpoint),
                allowed_ips: vec![prefix("10.0.0.0/24")],
                persistent_keepalive: 0,
            }],
            mtu: 1408,
        },
    )
    .expect("device");

    drop(tun);
    tokio::time::timeout(Duration::from_secs(5), closed.notified())
        .await
        .expect("the device task must stop when its tun handle is dropped");
}

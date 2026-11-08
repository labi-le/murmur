//! The ZeroTier packet plane: wire reassembly, HELLO/OK/ECHO/ERROR exchanges,
//! path probing and keepalive, and the outbound path selection that bonding
//! drives.
//!
//! Everything here runs above [`crate::node::NodeHost`]: a datagram arrives through
//! [`Node::process_wire_packet`], is reassembled if fragmented, authenticated
//! with the peer's negotiated armor, and dispatched by verb. Outbound packets
//! are armored and handed back to the host one datagram at a time.
//!
//! Remote-trace emission is not implemented here, and neither is
//! the credential verb handler; the frame and multicast verbs are dispatched
//! into [`crate::node::frames`] and [`crate::node::multicast`], and the verbs
//! with no layer behind them fail closed with [`NodeError::Unsupported`].

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use crate::address::{Address, ADDRESS_SIZE};
use crate::bonding::{packet_flow_id, packet_network_id, BondingPolicy, NO_FLOW_ID};
use crate::frame::MulticastGroup;
use crate::identity::Identity;
use crate::mac::Mac;
use crate::network_config::SPECIALIST_TYPE_ACTIVE_BRIDGE;
use crate::node::network::{NetworkAuthenticationInfo, NetworkStatus};
use crate::node::peer::{path_scope, peer_has_active_endpoint, unmap, PathKey, PeerPathState};
use crate::node::{
    elapsed, Event, EventType, Node, NodeError, ANY_LOCAL_SOCKET, MAX_FRAGMENT_ASSEMBLIES, MAX_PEER_PATHS,
    MAX_PENDING_INCOMING_PACKETS, MAX_PENDING_TRANSMITS, MAX_PUSHED_PATHS_PER_SCOPE_AND_FAMILY, MAX_SURFACE_ENTRIES,
    MEMORIZED_PATH_RETRY_PERIOD, NODE_VERSION_MAJOR, NODE_VERSION_MINOR, NODE_VERSION_REVISION,
    PEER_GENERAL_RATE_LIMIT, PEER_PATH_PROBE_WINDOW, PEER_ROUTE_REPORT_INTERVAL, PEER_WHOIS_RATE_LIMIT,
    PENDING_INCOMING_EXPIRATION, PENDING_TRANSMIT_EXPIRATION, PROTOCOL_VERSION, PROTOCOL_VERSION_MIN,
    PUSH_DIRECT_PATHS_CUTOFF_LIMIT, PUSH_DIRECT_PATHS_CUTOFF_TIME, TRUST_EXPIRATION, WHOIS_RETRY_PERIOD,
};
use crate::packet::{Packet, Verb, FLAG_FRAGMENTED, MAX_PACKET_SIZE, MIN_PACKET_SIZE, PAYLOAD_OFFSET};
use crate::world::{World, WorldType};

/// The size of a non-head ZeroTier packet fragment.
pub const FRAGMENT_HEADER_SIZE: usize = 16;
/// The serialized size of one node identity without its private half.
pub const SERIALIZED_IDENTITY_SIZE: usize = ADDRESS_SIZE + 1 + 64 + 1;
/// The largest remote-trace record accepted from a peer.
pub const MAX_REMOTE_TRACE_SIZE: usize = 1024;
/// The unknown-local-socket handle, re-exported for the host seam.
pub use crate::node::ANY_LOCAL_SOCKET as ANY_LOCAL_SOCKET_HANDLE;

/// Control flow for one inbound packet, mirroring the official core's
/// retry/not-accepted markers. A peer that is not yet known is reported as
/// [`NodeError::UnknownPeer`], which is the only retry signal this layer
/// produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PacketOutcome {
    /// Drop the packet without accounting it as accepted traffic.
    NotAccepted,
    /// The verb payload was unusable but the packet was authentic.
    Authenticated(Box<NodeError>),
    /// The packet needs state that is not here yet; the caller may retain it.
    Retry,
}

impl From<NodeError> for PacketOutcome {
    fn from(error: NodeError) -> Self {
        Self::Authenticated(Box::new(error))
    }
}

/// Marks a verb payload that failed validation on an authenticated packet.
fn unusable(error: NodeError) -> PacketOutcome {
    PacketOutcome::Authenticated(Box::new(error))
}

/// Reads the big-endian field of `N` bytes at `offset`; a short buffer yields
/// `None` so a truncated packet becomes a protocol error instead of a panic.
fn read_be<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

/// The peer-controlled extension fields of a HELLO payload.
struct HelloExtensions {
    external_surface: Option<SocketAddr>,
    planet_id: u64,
    planet_timestamp: u64,
    moons: Vec<(u64, u64)>,
    timestamp: u64,
}

/// Parses the optional endpoint operand at `position`, reporting the endpoint
/// and the position after it; an absent operand leaves both unchanged.
fn parse_optional_endpoint(payload: &[u8], position: usize) -> Result<(Option<SocketAddr>, usize), NodeError> {
    if position >= payload.len() {
        return Ok((None, position));
    }
    let remaining = payload.get(position..).ok_or(NodeError::InvalidPacket)?;
    let Some((endpoint, length)) = parse_inet_address(remaining) else {
        return Err(NodeError::InvalidPacket);
    };
    Ok((endpoint, position + length))
}

/// The result of validating the identity a HELLO announces.
enum HelloIdentity {
    /// The handshake may continue; `true` when a peer entry was created.
    Accepted(bool),
    /// The HELLO is dropped without a reply.
    Discarded,
}

/// Parses the extensions a HELLO carries after `position`, decrypting the
/// bookmark block in place.
fn parse_hello_extensions(
    packet: &mut Packet,
    key: &[u8; crate::identity::SYMMETRIC_KEY_SIZE],
    position: usize,
) -> Result<HelloExtensions, PacketOutcome> {
    let payload = packet.bytes();
    let (external_surface, mut cursor) = parse_optional_endpoint(payload, position).map_err(unusable)?;
    let mut planet_id = 0u64;
    let mut planet_timestamp = 0u64;
    if payload.len() - cursor >= 16 {
        let Some(planet) = payload.get(cursor..cursor + 16) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let (Some(identifier), Some(timestamp)) = (read_be::<8>(planet, 0), read_be::<8>(planet, 8)) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        planet_id = u64::from_be_bytes(identifier);
        planet_timestamp = u64::from_be_bytes(timestamp);
        cursor += 16;
    }
    let moons = if cursor < payload.len() { parse_hello_moons(packet, key, cursor)?.0 } else { Vec::new() };
    let Some(timestamp) = read_be::<8>(packet.bytes(), PAYLOAD_OFFSET + 5) else {
        return Err(unusable(NodeError::InvalidPacket));
    };
    Ok(HelloExtensions {
        external_surface,
        planet_id,
        planet_timestamp,
        moons,
        timestamp: u64::from_be_bytes(timestamp),
    })
}

/// Parses the encrypted moon bookmark block at `position`, returning the moon
/// bookmarks this node tracks and the offset just past them.
fn parse_hello_moons(
    packet: &mut Packet,
    key: &[u8; crate::identity::SYMMETRIC_KEY_SIZE],
    position: usize,
) -> Result<(Vec<(u64, u64)>, usize), PacketOutcome> {
    if packet.crypt_field(key, position, packet.bytes().len() - position).is_err() {
        return Err(unusable(NodeError::InvalidPacket));
    }
    let payload = packet.bytes();
    if payload.len() - position < 2 {
        return Err(unusable(NodeError::InvalidPacket));
    }
    let Some(count) = read_be::<2>(payload, position).map(u16::from_be_bytes) else {
        return Err(unusable(NodeError::InvalidPacket));
    };
    let count = usize::from(count);
    let mut position = position + 2;
    if count > (payload.len() - position) / 17 {
        return Err(unusable(NodeError::InvalidPacket));
    }
    let mut moons: Vec<(u64, u64)> = Vec::new();
    for _ in 0..count {
        let Some([world_type, world @ ..]) = payload.get(position..position + 17) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let (Some(identifier), Some(timestamp)) = (read_be::<8>(world, 0), read_be::<8>(world, 8)) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        position += 17;
        if *world_type == WorldType::Moon.bits() {
            moons.push((u64::from_be_bytes(identifier), u64::from_be_bytes(timestamp)));
        }
    }
    Ok((moons, position))
}

/// Decodes one advertised endpoint operand, or `None` when its type or length
/// is not one this build understands.
fn decode_direct_path_endpoint(address_type: u8, address_data: &[u8]) -> Option<SocketAddr> {
    match address_type {
        4 if address_data.len() == 6 => {
            let (raw, port) = (read_be::<4>(address_data, 0)?, read_be::<2>(address_data, 4)?);
            Some(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(raw)), u16::from_be_bytes(port)))
        }
        6 if address_data.len() == 18 => {
            let (raw, port) = (read_be::<16>(address_data, 0)?, read_be::<2>(address_data, 16)?);
            Some(SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(raw)), u16::from_be_bytes(port)))
        }
        _ => None,
    }
}

/// A packet as it arrived on the physical wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedWirePacket {
    pub local_socket: i64,
    pub remote: SocketAddr,
    pub data: Vec<u8>,
    pub received_at: SystemTime,
    pub last_tried: SystemTime,
    pub authenticated: bool,
}

/// The received pieces of one fragmented wire packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentAssembly {
    pub active: bool,
    pub packet_id: u64,
    pub slot: usize,
    pub storage: Vec<u8>,
    pub used: usize,
    pub head: Option<Vec<u8>>,
    pub fragments: [Option<Vec<u8>>; 7],
    pub total: usize,
    pub local_socket: i64,
    pub remote: Option<SocketAddr>,
    pub created_at: SystemTime,
    pub head_received_at: SystemTime,
}

impl Default for FragmentAssembly {
    fn default() -> Self {
        Self {
            active: false,
            packet_id: 0,
            slot: 0,
            storage: Vec::new(),
            used: 0,
            head: None,
            fragments: Default::default(),
            total: 0,
            local_socket: 0,
            remote: None,
            created_at: SystemTime::UNIX_EPOCH,
            head_received_at: SystemTime::UNIX_EPOCH,
        }
    }
}

/// An outbound packet held until peer discovery completes.
#[derive(Debug, Clone)]
pub struct PendingTransmit {
    pub packet: Packet,
    pub encrypt: bool,
    pub flow_id: i32,
    pub created_at: SystemTime,
}

/// Identifies an observed local socket and address-family surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SurfaceKey {
    pub reporter: Address,
    pub path: PathKey,
    pub scope: u8,
}

/// The most recently observed endpoint for one surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceState {
    pub endpoint: SocketAddr,
    pub updated: SystemTime,
    pub trusted: bool,
}

/// A recently advertised peer endpoint and its probe flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PushedDirectPath {
    endpoint: SocketAddr,
    forget: bool,
    cluster: bool,
}

impl Node {
    /// Validates, reassembles, authenticates, and dispatches one wire datagram.
    pub fn process_wire_packet(
        &mut self,
        local_socket: i64,
        remote: SocketAddr,
        data: &[u8],
        now: SystemTime,
    ) -> Result<(), NodeError> {
        let mut input = ReceivedWirePacket {
            local_socket,
            remote,
            data: data.to_vec(),
            received_at: now,
            last_tried: now,
            authenticated: false,
        };
        match self.reassemble_wire_packet(&mut input, now) {
            Ok(None) => return Ok(()),
            Err(NodeError::NodeClosed) => return Err(NodeError::NodeClosed),
            Err(error) => {
                if self.closed {
                    return Err(NodeError::NodeClosed);
                }
                return Err(error);
            }
            Ok(Some(assembled)) => input = assembled,
        }
        if self.closed {
            return Err(NodeError::NodeClosed);
        }
        match self.process_wire_packet_locked(&mut input, now, true) {
            Ok(()) | Err(PacketOutcome::NotAccepted | PacketOutcome::Retry) => Ok(()),
            Err(PacketOutcome::Authenticated(cause)) => Err(*cause),
        }
    }

    /// Authenticates and dispatches one complete wire packet, optionally
    /// queuing traffic from an unknown peer.
    pub(crate) fn process_wire_packet_locked(
        &mut self,
        input: &mut ReceivedWirePacket,
        now: SystemTime,
        queue_unknown: bool,
    ) -> Result<(), PacketOutcome> {
        let local_socket = input.local_socket;
        let remote = input.remote;
        let mut packet = Packet::parse(&input.data).map_err(|_| unusable(NodeError::InvalidPacket))?;
        let local = self.identity.address();
        if packet.destination() != local || packet.source() == local {
            return Err(unusable(NodeError::InvalidPacket));
        }
        if !input.authenticated
            && packet.cipher() == Some(crate::packet::Cipher::C25519Poly1305None)
            && !packet.extended_armor()
            && packet.verb() == Some(Verb::Hello)
        {
            return self.handle_hello_locked(local_socket, remote, &mut packet, now, false);
        }
        let trusted_path = packet.cipher() == Some(crate::packet::Cipher::TrustedPath);
        if !input.authenticated && trusted_path {
            if !self.inbound_path_trusted_locked(remote, packet.trusted_path_id()) {
                return Err(unusable(NodeError::InvalidPacket));
            }
            input.authenticated = true;
        }
        let source = packet.source();
        if self.load_peer_cache_locked(source, now).is_none() {
            if queue_unknown {
                let queued = input.clone();
                if self.enqueue_pending_incoming_locked(source, queued, now) {
                    self.request_whois_locked(source, now);
                }
            }
            return Err(unusable(NodeError::UnknownPeer));
        }
        if !input.authenticated {
            let Some(peer_key) = self.peers.get(&source).map(|peer| peer.key) else {
                return Err(unusable(NodeError::UnknownPeer));
            };
            let aes_keys = self.peers.get_mut(&source).map(|peer| &mut peer.aes_keys);
            let result = packet.dearmor_with(&peer_key, aes_keys, Some(&self.identity));
            if result.is_err() {
                if let Some(path) =
                    self.peers.get_mut(&source).and_then(|peer| peer.paths.get_mut(&PathKey::new(local_socket, remote)))
                {
                    path.packet_error = path.packet_error.mul_add(0.984375, 0.015625);
                }
                return Err(unusable(NodeError::InvalidPacket));
            }
            input.authenticated = true;
        }
        if packet.uncompress().is_err() {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let key = PathKey::new(local_socket, remote);
        let mut record_receive = true;
        let outcome = self.dispatch_wire_packet_verb_locked(source, key, &mut packet, now, &mut record_receive);
        if outcome == Err(PacketOutcome::Retry) {
            if queue_unknown {
                let queued = input.clone();
                let _ = self.enqueue_pending_incoming_locked(source, queued, now);
            }
            return Err(PacketOutcome::Retry);
        }
        if outcome == Err(PacketOutcome::NotAccepted) {
            return Ok(());
        }
        let cause = match outcome {
            Err(PacketOutcome::Authenticated(cause)) => Some(cause),
            Ok(()) | Err(PacketOutcome::NotAccepted | PacketOutcome::Retry) => None,
        };
        if record_receive {
            self.account_incoming_wire_packet_locked(source, key, &packet, now);
        }
        match cause {
            Some(cause) => Err(PacketOutcome::Authenticated(cause)),
            None => Ok(()),
        }
    }

    /// Dispatches one authenticated packet by verb, clearing `record_receive`
    /// for verbs that are not accounted as received traffic.
    fn dispatch_wire_packet_verb_locked(
        &mut self,
        source: Address,
        key: PathKey,
        packet: &mut Packet,
        now: SystemTime,
        record_receive: &mut bool,
    ) -> Result<(), PacketOutcome> {
        let local_socket = key.local_socket;
        let remote = key.endpoint;
        match packet.verb() {
            Some(Verb::Hello) => self.handle_hello_locked(local_socket, remote, packet, now, true),
            Some(Verb::Ok) => self.dispatch_ok_verb_locked(key, source, packet, now, record_receive),
            Some(Verb::Whois) => self.dispatch_whois_verb_locked(key, source, packet, now),
            Some(Verb::Echo) => self.dispatch_echo_verb_locked(key, source, packet, now),
            Some(Verb::Rendezvous) => self.handle_rendezvous_locked(local_socket, source, packet, now),
            Some(Verb::Error) => self.handle_error_locked(source, packet, now),
            Some(Verb::Frame) => self.handle_frame_locked(key, packet, now),
            Some(Verb::ExtFrame) => self.handle_ext_frame_locked(key, packet, now),
            Some(Verb::NetworkCredentials) => self.dispatch_network_credentials_verb_locked(source, now),
            Some(Verb::NetworkConfigRequest) => {
                self.handle_unsupported_network_config_request_locked(source, key, packet)
            }
            Some(Verb::NetworkConfig) => {
                self.handle_network_config_push_locked(local_socket, remote, source, packet, now)
            }
            Some(Verb::MulticastLike) => self.handle_multicast_like_locked(source, packet, now),
            Some(Verb::MulticastGather) => self.handle_multicast_gather_locked(key, source, packet, now),
            Some(Verb::MulticastFrame) => self.handle_multicast_frame_locked(key, source, packet, now),
            Some(Verb::PushDirectPaths) => {
                self.dispatch_push_direct_paths_verb_locked(key, source, packet, now, record_receive)
            }
            Some(Verb::UserMessage | Verb::RemoteTrace) => {
                Err(unusable(NodeError::Unsupported("user message delivery")))
            }
            Some(Verb::Ack) => {
                *record_receive = false;
                Ok(())
            }
            Some(Verb::QosMeasurement) => {
                *record_receive = false;
                self.handle_qos_measurement_locked(source, key, packet, now);
                Ok(())
            }
            Some(Verb::PathNegotiation) => {
                *record_receive = false;
                self.handle_path_negotiation_locked(source, key, packet, now);
                Ok(())
            }
            Some(Verb::Nop) | None => Ok(()),
        }
    }

    /// Dispatches an `OK` reply, reporting whether its request is still pending.
    fn dispatch_ok_verb_locked(
        &mut self,
        key: PathKey,
        source: Address,
        packet: &Packet,
        now: SystemTime,
        record_receive: &mut bool,
    ) -> Result<(), PacketOutcome> {
        let payload = packet.payload();
        *record_receive = false;
        if let Some(in_reply_to) = payload.first().copied() {
            if let Some(request_id) = read_be::<8>(payload, 1).map(u64::from_be_bytes) {
                *record_receive = self.pending.get(request_id).is_some_and(|request| {
                    request.verb.bits() == in_reply_to && (request.peer.is_zero() || request.peer == source)
                });
            }
        }
        self.handle_ok_locked(key.local_socket, key.endpoint, source, packet, now)
    }

    /// Dispatches a `WHOIS` request under the per-peer rate limit.
    fn dispatch_whois_verb_locked(
        &mut self,
        key: PathKey,
        source: Address,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let rate_limited = self.peers.get(&source).is_some_and(|peer| {
            peer.last_whois_request.is_some_and(|requested| elapsed(now, requested) < PEER_WHOIS_RATE_LIMIT)
        });
        if rate_limited {
            return Err(PacketOutcome::NotAccepted);
        }
        if let Some(peer) = self.peers.get_mut(&source) {
            peer.last_whois_request = Some(now);
        }
        self.handle_whois_locked(key.local_socket, key.endpoint, source, packet, now)
    }

    /// Dispatches an `ECHO` request under the per-peer rate limit.
    fn dispatch_echo_verb_locked(
        &mut self,
        key: PathKey,
        source: Address,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let rate_limited = self
            .peers
            .get(&source)
            .and_then(|peer| peer.last_echo_request.get(&key))
            .is_some_and(|last| elapsed(now, *last) < PEER_GENERAL_RATE_LIMIT / 6);
        if rate_limited {
            return Err(PacketOutcome::NotAccepted);
        }
        self.note_echo_request_locked(source, key, now);
        self.handle_echo_locked(key.local_socket, key.endpoint, source, packet)
    }

    /// Dispatches a credential push, which this build does not implement.
    fn dispatch_network_credentials_verb_locked(
        &mut self,
        source: Address,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let rate_limited = self.peers.get(&source).is_some_and(|peer| {
            peer.last_credentials_receive
                .is_some_and(|received| elapsed(now, received) < crate::node::PEER_CREDENTIALS_RATE_LIMIT)
        });
        if rate_limited {
            return Err(PacketOutcome::NotAccepted);
        }
        if let Some(peer) = self.peers.get_mut(&source) {
            peer.last_credentials_receive = Some(now);
        }
        Err(unusable(NodeError::Unsupported("network credentials")))
    }

    /// Dispatches pushed direct paths under the per-peer cutoff.
    fn dispatch_push_direct_paths_verb_locked(
        &mut self,
        key: PathKey,
        source: Address,
        packet: &Packet,
        now: SystemTime,
        record_receive: &mut bool,
    ) -> Result<(), PacketOutcome> {
        let Some(peer) = self.peers.get_mut(&source) else {
            return Err(unusable(NodeError::UnknownPeer));
        };
        let count = if elapsed(now, peer.last_direct_path_push.unwrap_or(now)) <= PUSH_DIRECT_PATHS_CUTOFF_TIME {
            peer.direct_path_push_count + 1
        } else {
            0
        };
        peer.last_direct_path_push = Some(now);
        peer.direct_path_push_count = count;
        if count >= PUSH_DIRECT_PATHS_CUTOFF_LIMIT {
            *record_receive = false;
            return Ok(());
        }
        self.handle_push_direct_paths_locked(key.local_socket, key.endpoint, source, packet, now)
    }

    /// Accounts an inbound packet against its peer, path, and bond flow.
    fn account_incoming_wire_packet_locked(&mut self, source: Address, key: PathKey, packet: &Packet, now: SystemTime) {
        let flow_id = packet_flow_id(packet);
        self.record_incoming_bond_packet_locked(source, key, packet, flow_id, now);
        if packet.hops() == 0 && packet.verb() != Some(Verb::Ok) {
            let network_id = packet_network_id(packet);
            self.observe_authenticated_packet_path_locked(
                source,
                key.local_socket,
                key.endpoint,
                packet.verb(),
                packet.packet_id(),
                network_id,
                now,
            );
        }
        let nontrivial = matches!(
            packet.verb(),
            Some(
                Verb::Frame | Verb::ExtFrame | Verb::NetworkConfigRequest | Verb::NetworkConfig | Verb::MulticastFrame
            )
        );
        if let Some(peer) = self.peers.get_mut(&source) {
            peer.last_receive = Some(now);
            if nontrivial {
                peer.last_nontrivial_receive = Some(now);
            }
        }
        self.mark_root_receive_locked(source, key.endpoint, now);
    }

    fn note_echo_request_locked(&mut self, address: Address, key: PathKey, now: SystemTime) {
        let Some(peer) = self.peers.get_mut(&address) else {
            return;
        };
        if !peer.last_echo_request.contains_key(&key) && peer.last_echo_request.len() >= MAX_PEER_PATHS {
            let oldest = peer.last_echo_request.iter().min_by_key(|(_, received)| **received).map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                peer.last_echo_request.remove(&oldest);
            }
        }
        peer.last_echo_request.insert(key, now);
    }

    /// Accepts a datagram or fragment and returns complete wire data.
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "crate API: this seam is handed the same packet buffer the caller owns mutably for dispatch"
    )]
    pub(crate) fn reassemble_wire_packet(
        &mut self,
        input: &mut ReceivedWirePacket,
        now: SystemTime,
    ) -> Result<Option<ReceivedWirePacket>, NodeError> {
        if self.closed {
            return Err(NodeError::NodeClosed);
        }
        let key = PathKey::new(input.local_socket, input.remote);
        self.note_wire_path_receive(key, now);
        let data = &input.data;
        if data.len() > MAX_PACKET_SIZE {
            return Err(NodeError::InvalidPacket);
        }
        if data.len() > FRAGMENT_HEADER_SIZE && data.get(13) == Some(&0xff) {
            let (header, body) = data.split_at_checked(FRAGMENT_HEADER_SIZE).ok_or(NodeError::InvalidPacket)?;
            let destination = Address::from_bytes(header.get(8..13).ok_or(NodeError::InvalidPacket)?)
                .map_err(|_| NodeError::InvalidPacket)?;
            if destination != self.identity.address() {
                return Err(NodeError::InvalidPacket);
            }
            let packet_id = u64::from_be_bytes(read_be::<8>(header, 0).ok_or(NodeError::InvalidPacket)?);
            let fragment_flags = header.get(14).copied().unwrap_or_default();
            let total = usize::from(fragment_flags >> 4);
            let number = usize::from(fragment_flags & 0x0f);
            if !(2..=7).contains(&total) || number < 1 || number >= total {
                return Err(NodeError::InvalidPacket);
            }
            match self.fragments.get(&packet_id) {
                None => self.new_fragment_assembly_locked(packet_id, now),
                Some(assembly) if assembly.total != 0 && assembly.total != total => {
                    return Err(NodeError::InvalidPacket);
                }
                Some(_) => {}
            }
            if self
                .fragments
                .get(&packet_id)
                .and_then(|assembly| assembly.fragments.get(number))
                .and_then(Option::as_ref)
                .is_some()
            {
                return Ok(None);
            }
            let Some(assembly) = self.fragments.get_mut(&packet_id) else {
                return Err(NodeError::InvalidPacket);
            };
            assembly.total = total;
            let body = body.to_vec();
            if let Some(packet) = self.finish_assembly_locked(packet_id, number, &body, None, now)? {
                return Ok(Some(packet));
            }
            if !self.store_fragment_locked(packet_id, number, &body) {
                self.remove_fragment_assembly_locked(packet_id);
                return Err(NodeError::InvalidPacket);
            }
            return Ok(None);
        }
        if data.len() < MIN_PACKET_SIZE {
            return Err(NodeError::InvalidPacket);
        }
        if data.get(crate::packet::FLAGS_OFFSET).copied().unwrap_or_default() & FLAG_FRAGMENTED == 0 {
            return Ok(Some(input.clone()));
        }
        let destination = Address::from_bytes(
            data.get(crate::packet::DEST_OFFSET..crate::packet::SOURCE_OFFSET).ok_or(NodeError::InvalidPacket)?,
        )
        .map_err(|_| NodeError::InvalidPacket)?;
        let source = Address::from_bytes(
            data.get(crate::packet::SOURCE_OFFSET..crate::packet::FLAGS_OFFSET).ok_or(NodeError::InvalidPacket)?,
        )
        .map_err(|_| NodeError::InvalidPacket)?;
        if destination != self.identity.address() || source == self.identity.address() {
            return Err(NodeError::InvalidPacket);
        }
        let packet_id = u64::from_be_bytes(read_be::<8>(data, 0).ok_or(NodeError::InvalidPacket)?);
        match self.fragments.get(&packet_id) {
            None => self.new_fragment_assembly_locked(packet_id, now),
            Some(assembly) if assembly.head.is_some() => return Ok(None),
            Some(_) => {}
        }
        {
            let Some(assembly) = self.fragments.get_mut(&packet_id) else {
                return Err(NodeError::InvalidPacket);
            };
            assembly.local_socket = input.local_socket;
            assembly.remote = Some(input.remote);
            assembly.head_received_at = now;
        }
        let head = data.clone();
        if let Some(packet) = self.finish_assembly_locked(packet_id, 0, &head, Some(input.clone()), now)? {
            return Ok(Some(packet));
        }
        if !self.store_fragment_locked(packet_id, 0, &head) {
            self.remove_fragment_assembly_locked(packet_id);
            return Err(NodeError::InvalidPacket);
        }
        Ok(None)
    }

    /// Copies one incomplete wire piece into the assembly's reusable storage.
    fn store_fragment_locked(&mut self, packet_id: u64, number: usize, data: &[u8]) -> bool {
        let Some(assembly) = self.fragments.get_mut(&packet_id) else {
            return false;
        };
        if number >= assembly.fragments.len() || assembly.storage.len() - assembly.used < data.len() {
            return false;
        }
        let start = assembly.used;
        let Some(window) = assembly.storage.get_mut(start..start + data.len()) else {
            return false;
        };
        window.copy_from_slice(data);
        let stored = window.to_vec();
        assembly.used += data.len();
        if number == 0 {
            assembly.head = Some(stored);
        } else if let Some(slot) = assembly.fragments.get_mut(number) {
            *slot = Some(stored);
        } else {
            return false;
        }
        true
    }

    /// Reuses one fixed reassembly slot for `packet_id`.
    fn new_fragment_assembly_locked(&mut self, packet_id: u64, now: SystemTime) {
        let slot = self.fragment_cursor;
        self.fragment_cursor = (self.fragment_cursor + 1) % MAX_FRAGMENT_ASSEMBLIES;
        if let Some(previous) = self.fragment_slots.get(slot).copied().flatten() {
            self.remove_fragment_assembly_locked(previous);
        }
        if let Some(entry) = self.fragment_slots.get_mut(slot) {
            *entry = Some(packet_id);
        }
        self.fragments.insert(
            packet_id,
            FragmentAssembly {
                active: true,
                packet_id,
                slot,
                storage: vec![0u8; MAX_PACKET_SIZE],
                created_at: now,
                ..Default::default()
            },
        );
    }

    /// Deactivates and clears `packet_id` when it is still current.
    fn remove_fragment_assembly_locked(&mut self, packet_id: u64) {
        if let Some(assembly) = self.fragments.remove(&packet_id) {
            if self.fragment_slots.get(assembly.slot) == Some(&Some(packet_id)) {
                if let Some(slot) = self.fragment_slots.get_mut(assembly.slot) {
                    *slot = None;
                }
            }
        }
    }

    /// Joins an assembly when `current` supplies its last missing part.
    /// `current_number` is zero for the packet head.
    fn finish_assembly_locked(
        &mut self,
        packet_id: u64,
        current_number: usize,
        current: &[u8],
        current_packet: Option<ReceivedWirePacket>,
        now: SystemTime,
    ) -> Result<Option<ReceivedWirePacket>, NodeError> {
        let assembly = self.fragments.get(&packet_id).cloned().unwrap_or_default();
        if assembly.total < 2 {
            return Ok(None);
        }
        let head = if current_number == 0 {
            current.to_vec()
        } else {
            match &assembly.head {
                Some(head) => head.clone(),
                None => return Ok(None),
            }
        };
        if head.is_empty() {
            return Ok(None);
        }
        let mut total_length = head.len();
        let mut pieces: Vec<Vec<u8>> = Vec::with_capacity(assembly.total);
        pieces.push(head);
        for number in 1..assembly.total {
            let fragment = if number == current_number {
                current.to_vec()
            } else {
                match assembly.fragments.get(number).and_then(|fragment| fragment.as_ref()) {
                    Some(fragment) => fragment.clone(),
                    None => return Ok(None),
                }
            };
            if fragment.is_empty() {
                return Ok(None);
            }
            if fragment.len() > MAX_PACKET_SIZE - total_length {
                self.remove_fragment_assembly_locked(packet_id);
                return Err(NodeError::InvalidPacket);
            }
            total_length += fragment.len();
            pieces.push(fragment);
        }
        let mut packet = current_packet.unwrap_or_else(|| ReceivedWirePacket {
            local_socket: assembly.local_socket,
            remote: assembly.remote.unwrap_or_else(unspecified_endpoint),
            data: Vec::new(),
            received_at: assembly.head_received_at,
            last_tried: now,
            authenticated: false,
        });
        packet.data = Vec::with_capacity(total_length);
        for piece in pieces {
            packet.data.extend_from_slice(&piece);
        }
        self.remove_fragment_assembly_locked(packet_id);
        Ok(Some(packet))
    }

    /// The number of packets deferred for identity discovery.
    #[must_use]
    pub fn pending_incoming_count_locked(&self) -> usize {
        self.pending_incoming.values().map(Vec::len).sum()
    }

    /// Queues one bounded inbound packet for `address`.
    pub(crate) fn enqueue_pending_incoming_locked(
        &mut self,
        address: Address,
        mut packet: ReceivedWirePacket,
        now: SystemTime,
    ) -> bool {
        if let Some(packet_id) = read_be::<8>(&packet.data, 0).map(u64::from_be_bytes) {
            if self.pending_incoming.get(&address).is_some_and(|packets| {
                packets.iter().any(|pending| read_be::<8>(&pending.data, 0).map(u64::from_be_bytes) == Some(packet_id))
            }) {
                return false;
            }
        }
        if self.pending_incoming_count_locked() >= MAX_PENDING_INCOMING_PACKETS {
            return false;
        }
        packet.last_tried = now;
        self.pending_incoming.entry(address).or_default().push(packet);
        true
    }

    /// Retries non-expired deferred inbound packets.
    pub(crate) fn retry_pending_incoming_locked(&mut self, now: SystemTime) {
        let addresses: Vec<Address> = self.pending_incoming.keys().copied().collect();
        for address in addresses {
            let packets = self.pending_incoming.remove(&address).unwrap_or_default();
            let mut kept = Vec::new();
            for mut packet in packets {
                if elapsed(now, packet.received_at) > PENDING_INCOMING_EXPIRATION {
                    continue;
                }
                if elapsed(now, packet.last_tried) >= WHOIS_RETRY_PERIOD {
                    packet.last_tried = now;
                    match self.process_wire_packet_locked(&mut packet, now, false) {
                        Err(PacketOutcome::Retry) => {}
                        // Only a peer that is still unknown is worth retrying;
                        // any other handler error drops the packet.
                        Err(PacketOutcome::Authenticated(cause)) if matches!(*cause, NodeError::UnknownPeer) => {}
                        Ok(()) | Err(PacketOutcome::Authenticated(_) | PacketOutcome::NotAccepted) => continue,
                    }
                }
                kept.push(packet);
            }
            if !kept.is_empty() {
                self.pending_incoming.insert(address, kept);
            }
        }
    }
}

fn unspecified_endpoint() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
}

impl Node {
    /// Sends a full handshake using an endpoint and the host's socket choice.
    pub fn send_hello_locked(
        &mut self,
        address: Address,
        endpoint: SocketAddr,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        self.send_hello_at_path_locked(address, PathKey::new(ANY_LOCAL_SOCKET, endpoint), now, 0, 0)
    }

    /// Sends a full handshake on one explicit path with path priority and an
    /// optional network context.
    pub fn send_hello_at_path_locked(
        &mut self,
        address: Address,
        path: PathKey,
        now: SystemTime,
        priority: i32,
        network_id: u64,
    ) -> Result<(), NodeError> {
        if self.load_peer_cache_locked(address, now).is_none() {
            return Err(NodeError::UnknownPeer);
        }
        let local = self.identity.address();
        let Ok(mut packet) = Packet::new(address, local, Verb::Hello) else {
            return Err(NodeError::InvalidPacket);
        };
        let _ = packet.append(&[PROTOCOL_VERSION, NODE_VERSION_MAJOR, NODE_VERSION_MINOR]);
        let _ = packet.append_u16(NODE_VERSION_REVISION);
        let _ = packet.append_u64(crate::node::unix_millis(now));
        let mut identity_bytes = Vec::new();
        self.identity.append_binary(&mut identity_bytes, false);
        let _ = packet.append(&identity_bytes);
        let mut endpoint_bytes = Vec::new();
        append_inet_address(&mut endpoint_bytes, path.endpoint);
        let _ = packet.append(&endpoint_bytes);
        let _ = packet.append_u64(self.planet.id);
        let _ = packet.append_u64(self.planet.timestamp);
        let encrypted_at = packet.bytes().len();
        let mut moon_ids: BTreeSet<u64> = self.moons.keys().copied().collect();
        moon_ids.extend(self.moon_seeds.keys().copied());
        let _ = packet.append_u16(u16::try_from(moon_ids.len()).unwrap_or(0));
        for world_id in moon_ids {
            let timestamp = self.moons.get(&world_id).map_or(0, |moon| moon.timestamp);
            let _ = packet.append_u8(WorldType::Moon.bits());
            let _ = packet.append_u64(world_id);
            let _ = packet.append_u64(timestamp);
        }
        let Some(key) = self.peers.get(&address).map(|peer| peer.key) else {
            return Err(NodeError::UnknownPeer);
        };
        if packet.crypt_field(&key, encrypted_at, packet.bytes().len() - encrypted_at).is_err() {
            return Err(NodeError::InvalidPacket);
        }
        let mut send_path = path;
        if !self.low_bandwidth {
            send_path.local_socket = ANY_LOCAL_SOCKET;
        }
        let packet_id = packet.packet_id();
        self.add_pending_locked(
            packet_id,
            crate::node::PendingRequest {
                verb: Verb::Hello,
                peer: address,
                network_id,
                sent_at: Some(now),
                slot: 0,
                generation: 0,
                path: Some(send_path),
                priority,
                reply_paths: None,
            },
        )?;
        let extended = self.encrypted_hello;
        if let Err(error) = self.send_packet_via_path_locked(address, packet, false, send_path, extended) {
            self.delete_pending_locked(packet_id);
            return Err(error);
        }
        if send_path != path {
            self.note_wire_path_send_locked(path, now);
            if let Some(state) = self.peers.get_mut(&address).and_then(|peer| peer.paths.get_mut(&path)) {
                state.last_send = Some(now);
            }
        }
        Ok(())
    }

    /// Validates a peer handshake and replies with negotiated version and path
    /// data.
    pub(crate) fn handle_hello_locked(
        &mut self,
        local_socket: i64,
        remote: SocketAddr,
        packet: &mut Packet,
        now: SystemTime,
        already_authenticated: bool,
    ) -> Result<(), PacketOutcome> {
        let identity_offset = PAYLOAD_OFFSET + 1 + 1 + 1 + 2 + 8;
        if packet.bytes().len() < identity_offset + SERIALIZED_IDENTITY_SIZE {
            return Err(unusable(NodeError::InvalidPacket));
        }
        if packet.bytes().get(PAYLOAD_OFFSET).copied().unwrap_or_default() < PROTOCOL_VERSION_MIN {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let identity_bytes = packet.bytes().get(identity_offset..).ok_or_else(|| unusable(NodeError::InvalidPacket))?;
        let (identity, identity_length) =
            Identity::parse_binary(identity_bytes).map_err(|_| unusable(NodeError::InvalidIdentity))?;
        let address = identity.address();
        if address != packet.source() {
            return Err(unusable(NodeError::InvalidIdentity));
        }
        let new_peer = match self.negotiate_hello_identity_locked(
            PathKey::new(local_socket, remote),
            identity,
            packet,
            now,
            already_authenticated,
        )? {
            HelloIdentity::Accepted(new_peer) => new_peer,
            HelloIdentity::Discarded => return Ok(()),
        };
        let Some(key) = self.peers.get(&address).map(|peer| peer.key) else {
            return Err(unusable(NodeError::UnknownPeer));
        };
        let extensions = parse_hello_extensions(packet, &key, identity_offset + identity_length)?;
        let worlds = self.collect_hello_worlds_locked(&extensions)?;
        if packet.hops() == 0 {
            if let Some(surface) = extensions.external_surface {
                self.observe_surface_locked(address, local_socket, remote, surface, now);
            }
        }
        self.send_hello_ok_locked(
            address,
            PathKey::new(local_socket, remote),
            packet.packet_id(),
            &extensions,
            &worlds,
        )?;
        let payload = packet.bytes();
        let fields = payload.get(PAYLOAD_OFFSET..PAYLOAD_OFFSET + 5).unwrap_or_default();
        let [protocol, major, minor, revision_high, revision_low] = fields else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.protocol = *protocol;
            peer.major = *major;
            peer.minor = *minor;
            peer.revision = u16::from_be_bytes([*revision_high, *revision_low]);
            peer.last_receive = Some(now);
        }
        if !already_authenticated {
            self.record_incoming_bond_packet_locked(
                address,
                PathKey::new(local_socket, remote),
                packet,
                NO_FLOW_ID,
                now,
            );
        }
        self.mark_root_receive_locked(address, remote, now);
        if !already_authenticated && packet.hops() == 0 {
            self.observe_authenticated_path_locked(address, local_socket, remote, now);
        }
        if new_peer {
            self.peer_added_locked(address, now);
        }
        Ok(())
    }

    /// Validates the identity a HELLO announces against the peer table.
    ///
    /// A rate-limited identity validation drops the HELLO without a reply.
    fn negotiate_hello_identity_locked(
        &mut self,
        key: PathKey,
        identity: Identity,
        packet: &mut Packet,
        now: SystemTime,
        already_authenticated: bool,
    ) -> Result<HelloIdentity, PacketOutcome> {
        let address = identity.address();
        if self.load_peer_cache_locked(address, now).is_none() {
            if already_authenticated {
                return Err(unusable(NodeError::InvalidPacket));
            }
            if !self.allow_identity_validation_locked(key.endpoint.ip(), now) {
                return Ok(HelloIdentity::Discarded);
            }
            let dearmor = self.identity.agree(&identity).map_err(|_| unusable(NodeError::InvalidIdentity))?;
            if packet.dearmor(&dearmor).is_err() {
                return Err(unusable(NodeError::InvalidPacket));
            }
            if identity.validate().is_err() {
                return Err(unusable(NodeError::InvalidIdentity));
            }
            let root = self.is_root_address_locked(address);
            let peer = self.new_peer_locked(identity, root).map_err(unusable)?;
            self.peers.insert(address, peer);
            return Ok(HelloIdentity::Accepted(true));
        }
        let same_key = self.peers.get(&address).map(|peer| peer.identity.public_key()) == Some(identity.public_key());
        if same_key {
            if !already_authenticated {
                let Some(peer_key) = self.peers.get(&address).map(|peer| peer.key) else {
                    return Err(unusable(NodeError::UnknownPeer));
                };
                if packet.dearmor(&peer_key).is_err() {
                    return Err(unusable(NodeError::InvalidPacket));
                }
            }
            return Ok(HelloIdentity::Accepted(false));
        }
        if already_authenticated {
            return Ok(HelloIdentity::Accepted(false));
        }
        if !self.allow_identity_validation_locked(key.endpoint.ip(), now) {
            return Ok(HelloIdentity::Discarded);
        }
        let dearmor = self.identity.agree(&identity).map_err(|_| unusable(NodeError::InvalidIdentity))?;
        if packet.dearmor(&dearmor).is_err() {
            return Err(unusable(NodeError::InvalidPacket));
        }
        self.reject_identity_collision_locked(address, packet, &dearmor, key)
    }

    /// Answers a HELLO whose address is already held by another public key.
    fn reject_identity_collision_locked(
        &mut self,
        address: Address,
        packet: &Packet,
        key: &[u8; crate::identity::SYMMETRIC_KEY_SIZE],
        path: PathKey,
    ) -> Result<HelloIdentity, PacketOutcome> {
        let Ok(mut reply) = Packet::new(address, self.identity.address(), Verb::Error) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let _ = reply.append_u8(Verb::Hello.bits());
        let _ = reply.append_u64(packet.packet_id());
        let _ = reply.append_u8(0x04);
        let _ = self.send_packet_via_path_with_key_locked(address, reply, true, path, key);
        Err(PacketOutcome::Authenticated(Box::new(NodeError::IdentityCollision)))
    }

    /// Sends the credentials a peer asked for on the network it named.
    fn handle_credentials_request_error_locked(
        &mut self,
        payload: &[u8],
        address: Address,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        if payload.len() < 18 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let Some(network_id) = read_be::<8>(payload, 10).map(u64::from_be_bytes) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        if !self.networks.contains_key(&network_id) {
            return Ok(());
        }
        let rate_limited = self
            .peers
            .get(&address)
            .and_then(|peer| peer.last_credentials_request)
            .is_some_and(|requested| elapsed(now, requested) < PEER_GENERAL_RATE_LIMIT);
        if rate_limited {
            return Ok(());
        }
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.last_credentials_request = Some(now);
            peer.credentials_sent.remove(&network_id);
        }
        let _ = self.send_credentials_locked(network_id, address, now);
        Ok(())
    }

    /// Forgets the multicast group a peer reported it can no longer receive.
    fn handle_multicast_error_locked(&mut self, payload: &[u8], address: Address) {
        let Some(network_id) = read_be::<8>(payload, 10).map(u64::from_be_bytes) else {
            return;
        };
        let Some(mac_bytes) = payload.get(18..24) else {
            return;
        };
        let Ok(mac) = Mac::from_bytes(mac_bytes) else {
            return;
        };
        if !mac.is_multicast() {
            return;
        }
        let Some(adi) = read_be::<4>(payload, 24).map(u32::from_be_bytes) else {
            return;
        };
        self.forget_multicast_group_locked(network_id, address, MulticastGroup::new(mac, adi));
    }

    /// Serializes the planet and moon bookmarks the peer is behind on.
    fn collect_hello_worlds_locked(&self, extensions: &HelloExtensions) -> Result<Vec<u8>, PacketOutcome> {
        let mut worlds: Vec<u8> = Vec::new();
        if extensions.planet_id == self.planet.id && extensions.planet_timestamp < self.planet.timestamp {
            if let Ok(serialized) = self.planet.serialize() {
                worlds.extend_from_slice(&serialized);
            }
        }
        for (world_id, remote_timestamp) in &extensions.moons {
            if let Some(moon) = self.moons.get(world_id) {
                if *remote_timestamp < moon.timestamp {
                    if let Ok(serialized) = moon.serialize() {
                        worlds.extend_from_slice(&serialized);
                    }
                }
            }
        }
        if worlds.len() > usize::from(u16::MAX) {
            return Err(unusable(NodeError::InvalidPacket));
        }
        Ok(worlds)
    }

    /// Sends the OK reply that accepts a HELLO on `key`.
    fn send_hello_ok_locked(
        &mut self,
        address: Address,
        key: PathKey,
        packet_id: u64,
        extensions: &HelloExtensions,
        worlds: &[u8],
    ) -> Result<(), PacketOutcome> {
        let Ok(mut reply) = Packet::new(address, self.identity.address(), Verb::Ok) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let _ = reply.append_u8(Verb::Hello.bits());
        let _ = reply.append_u64(packet_id);
        let _ = reply.append_u64(extensions.timestamp);
        let _ = reply.append(&[PROTOCOL_VERSION, NODE_VERSION_MAJOR, NODE_VERSION_MINOR]);
        let _ = reply.append_u16(NODE_VERSION_REVISION);
        let mut endpoint_bytes = Vec::new();
        append_inet_address(&mut endpoint_bytes, key.endpoint);
        let _ = reply.append(&endpoint_bytes);
        let _ = reply.append_u16(u16::try_from(worlds.len()).unwrap_or(0));
        let _ = reply.append(worlds);
        let _ = self.send_packet_via_path_locked(address, reply, true, key, false);
        Ok(())
    }
}

/// Appends ZeroTier's tagged endpoint representation to `dst`.
pub fn append_inet_address(dst: &mut Vec<u8>, address: SocketAddr) {
    match unmap(address.ip()) {
        IpAddr::V4(address) => {
            dst.push(4);
            dst.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            dst.push(6);
            dst.extend_from_slice(&address.octets());
        }
    }
    dst.extend_from_slice(&address.port().to_be_bytes());
}

/// Decodes ZeroTier's tagged IPv4 or IPv6 endpoint form.
#[must_use]
pub fn parse_inet_address(data: &[u8]) -> Option<(Option<SocketAddr>, usize)> {
    match *data.first()? {
        0 => Some((None, 1)),
        4 => {
            if data.len() < 7 {
                return None;
            }
            let ip = std::net::Ipv4Addr::from(read_be::<4>(data, 1)?);
            let port = u16::from_be_bytes(read_be::<2>(data, 5)?);
            Some((Some(SocketAddr::new(IpAddr::V4(ip), port)), 7))
        }
        6 => {
            if data.len() < 19 {
                return None;
            }
            let octets = read_be::<16>(data, 1)?;
            let port = u16::from_be_bytes(read_be::<2>(data, 17)?);
            Some((Some(SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(octets)), port)), 19))
        }
        _ => None,
    }
}

impl Node {
    /// Dispatches a response according to the acknowledged verb.
    pub(crate) fn handle_ok_locked(
        &mut self,
        local_socket: i64,
        remote: SocketAddr,
        address: Address,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let payload = packet.payload();
        if payload.len() < 9 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let in_reply_to = payload.first().copied().unwrap_or_default();
        let in_reply_to_packet =
            u64::from_be_bytes(read_be::<8>(payload, 1).ok_or_else(|| unusable(NodeError::InvalidPacket))?);
        let Some(pending) = self.pending.get(in_reply_to_packet).cloned() else {
            return Ok(());
        };
        if pending.verb.bits() != in_reply_to || (!pending.peer.is_zero() && pending.peer != address) {
            return Ok(());
        }
        // A HELLO sent through AnyLocalSocket may leave through several sockets
        // with one packet ID, so its expectation is retained for the normal
        // short pending window.
        let mut consume_pending = pending.verb != Verb::NetworkConfigRequest && pending.verb != Verb::Hello;
        let outcome = match pending.verb {
            Verb::Hello => {
                self.handle_hello_ok_locked(payload, address, local_socket, remote, packet, now)?;
                Ok(())
            }
            Verb::Whois => {
                if !self.peers.get(&address).is_some_and(|peer| peer.root) {
                    return Ok(());
                }
                self.handle_whois_ok_locked(payload, address, now)?;
                Ok(())
            }
            Verb::NetworkConfigRequest => {
                self.handle_network_config_request_ok_locked(payload, packet, now, &mut consume_pending)?;
                Ok(())
            }
            Verb::ExtFrame => {
                Self::handle_ext_frame_ok_locked(payload, pending.network_id)?;
                Ok(())
            }
            Verb::MulticastGather => self.handle_multicast_gather_ok_locked(payload, now).map_err(unusable),
            Verb::MulticastFrame => self.handle_multicast_frame_ok_locked(payload, now).map_err(unusable),
            Verb::Echo
            | Verb::Nop
            | Verb::Error
            | Verb::Ok
            | Verb::Rendezvous
            | Verb::Frame
            | Verb::MulticastLike
            | Verb::NetworkCredentials
            | Verb::NetworkConfig
            | Verb::PushDirectPaths
            | Verb::Ack
            | Verb::QosMeasurement
            | Verb::UserMessage
            | Verb::RemoteTrace
            | Verb::PathNegotiation => Ok(()),
        };
        let cause = match outcome {
            Ok(()) => None,
            Err(PacketOutcome::Authenticated(cause)) => Some(cause),
            other => return other,
        };
        if consume_pending {
            self.consume_pending_reply_locked(in_reply_to_packet, &pending, PathKey::new(local_socket, remote));
        }
        self.apply_ok_reply_locked(address, PathKey::new(local_socket, remote), packet, &pending, payload, now)?;
        match cause {
            Some(cause) => Err(PacketOutcome::Authenticated(cause)),
            None => Ok(()),
        }
    }

    /// Applies an accepted OK reply to the peer's path state.
    fn apply_ok_reply_locked(
        &mut self,
        address: Address,
        key: PathKey,
        packet: &Packet,
        pending: &crate::node::PendingRequest,
        payload: &[u8],
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        if packet.hops() == 0 {
            let packet_id = packet.packet_id();
            self.observe_authenticated_packet_path_locked(
                address,
                key.local_socket,
                key.endpoint,
                Some(Verb::Ok),
                packet_id,
                pending.network_id,
                now,
            );
            if let Some(path) = self.peers.get_mut(&address).and_then(|peer| peer.paths.get_mut(&key)) {
                if pending.priority > path.priority {
                    path.priority = pending.priority;
                    if pending.priority > 1 {
                        self.prune_lower_priority_paths_locked(address, key, pending.priority);
                    }
                }
            }
        }
        if pending.verb == Verb::Hello {
            if packet.hops() == 0 {
                let Some(sent_at) = read_be::<8>(payload, 9).map(u64::from_be_bytes) else {
                    return Err(unusable(NodeError::InvalidPacket));
                };
                self.update_path_latency_locked(address, key, sent_at, now);
            }
            self.mark_root_receive_locked(address, key.endpoint, now);
        }
        Ok(())
    }

    /// Applies an OK reply to a HELLO: the peer's negotiated version, the
    /// surface it reports, and the world bookmarks it pushes.
    fn handle_hello_ok_locked(
        &mut self,
        payload: &[u8],
        address: Address,
        local_socket: i64,
        remote: SocketAddr,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        if payload.len() < 22 || payload.get(17).copied().unwrap_or_default() < PROTOCOL_VERSION_MIN {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let Some(header) = payload.get(17..22) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let [protocol, major, minor, revision_high, revision_low] = header else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let (external_surface, position) = parse_optional_endpoint(payload, 22).map_err(unusable)?;
        if payload.len() - position >= 2 {
            self.apply_world_bookmarks_locked(address, payload, position)?;
        }
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.protocol = *protocol;
            peer.major = *major;
            peer.minor = *minor;
            peer.revision = u16::from_be_bytes([*revision_high, *revision_low]);
        }
        if packet.hops() == 0 {
            if let Some(surface) = external_surface {
                self.observe_surface_locked(address, local_socket, remote, surface, now);
            }
        }
        Ok(())
    }

    /// Applies the world bookmarks an OK reply pushes when the reply comes from
    /// a peer this node accepts world updates from.
    fn apply_world_bookmarks_locked(
        &mut self,
        address: Address,
        payload: &[u8],
        position: usize,
    ) -> Result<(), PacketOutcome> {
        let Some(worlds_length) = read_be::<2>(payload, position).map(u16::from_be_bytes) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let worlds_length = usize::from(worlds_length);
        let position = position + 2;
        if worlds_length > payload.len() - position {
            return Err(unusable(NodeError::InvalidPacket));
        }
        if !self.should_accept_world_update_from_locked(address) {
            return Ok(());
        }
        let mut cursor = position;
        let end = position + worlds_length;
        while cursor < end {
            let Some(worlds) = payload.get(cursor..end) else {
                return Err(unusable(NodeError::InvalidWorld));
            };
            let Ok((world, consumed)) = World::parse(worlds) else {
                return Err(unusable(NodeError::InvalidWorld));
            };
            if consumed == 0 {
                return Err(unusable(NodeError::InvalidWorld));
            }
            let _ = self.add_world_locked(world, false);
            cursor += consumed;
        }
        Ok(())
    }

    /// Applies an OK reply to a WHOIS: the identities the root returned and the
    /// controllers still owed a configuration request.
    fn handle_whois_ok_locked(
        &mut self,
        payload: &[u8],
        _address: Address,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let mut position = 9;
        while position < payload.len() {
            let Some(remaining) = payload.get(position..) else {
                return Err(unusable(NodeError::InvalidIdentity));
            };
            let Ok((identity, consumed)) = Identity::parse_binary(remaining) else {
                return Err(unusable(NodeError::InvalidIdentity));
            };
            if identity.validate().is_err() {
                return Err(unusable(NodeError::InvalidIdentity));
            }
            let root = self.is_root_address_locked(identity.address());
            if let Err(error) = self.add_peer_locked(identity, root) {
                return Err(unusable(error));
            }
            position += consumed;
        }
        let controllers: Vec<u64> = self
            .networks
            .iter()
            .filter(|(network_id, network)| {
                self.peers.contains_key(&crate::address::controller(**network_id))
                    && (network.status == NetworkStatus::RequestingConfiguration
                        || network.last_config_request.is_none())
            })
            .map(|(network_id, _)| *network_id)
            .collect();
        for network_id in controllers {
            let _ = self.send_network_config_request_packet_locked(network_id, now);
        }
        Ok(())
    }

    /// Applies an OK reply to a configuration request chunk, retaining the
    /// pending request when the network serial advanced.
    fn handle_network_config_request_ok_locked(
        &mut self,
        payload: &[u8],
        packet: &Packet,
        now: SystemTime,
        consume_pending: &mut bool,
    ) -> Result<(), PacketOutcome> {
        let network_id = read_be::<8>(payload, 9).map(u64::from_be_bytes);
        let previous_serial = network_id
            .and_then(|network_id| self.networks.get(&network_id).map(|network| network.config_update_serial));
        if let Err(error) = self.handle_network_config_chunk_locked(packet, 9, now) {
            return Err(unusable(error));
        }
        if let Some(network_id) = network_id {
            if let Some(network) = self.networks.get(&network_id) {
                if Some(network.config_update_serial) != previous_serial {
                    *consume_pending = true;
                }
            }
        }
        Ok(())
    }

    /// Applies an OK reply to an EXT_FRAME, which acknowledges receipt of a
    /// frame that arrived in its own packet and carries no frame.
    fn handle_ext_frame_ok_locked(payload: &[u8], network_id: u64) -> Result<(), PacketOutcome> {
        if read_be::<8>(payload, 9).map(u64::from_be_bytes) != Some(network_id) {
            return Err(unusable(NodeError::InvalidPacket));
        }
        Ok(())
    }

    /// Answers identity requests when the requested peer is known.
    pub(crate) fn handle_whois_locked(
        &mut self,
        local_socket: i64,
        remote: SocketAddr,
        requesting: Address,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let Ok(mut reply) = Packet::new(requesting, self.identity.address(), Verb::Ok) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let _ = reply.append_u8(Verb::Whois.bits());
        let _ = reply.append_u64(packet.packet_id());
        let mut count = 0;
        let bytes = packet.bytes();
        let mut position = PAYLOAD_OFFSET;
        while position + ADDRESS_SIZE <= bytes.len() {
            let Some(requested) = bytes.get(position..position + ADDRESS_SIZE) else {
                break;
            };
            let Ok(address) = Address::from_bytes(requested) else {
                break;
            };
            position += ADDRESS_SIZE;
            if address == self.identity.address() {
                let mut identity_bytes = Vec::new();
                self.identity.append_binary(&mut identity_bytes, false);
                let _ = reply.append(&identity_bytes);
                count += 1;
            } else if let Some(known) = self.peers.get(&address) {
                let mut identity_bytes = Vec::new();
                known.identity.append_binary(&mut identity_bytes, false);
                let _ = reply.append(&identity_bytes);
                count += 1;
            } else {
                self.request_whois_locked(address, now);
            }
        }
        if count == 0 {
            return Ok(());
        }
        let _ = self.send_packet_via_path_locked(requesting, reply, true, PathKey::new(local_socket, remote), false);
        Ok(())
    }

    /// Replies to a path liveness probe.
    pub(crate) fn handle_echo_locked(
        &mut self,
        local_socket: i64,
        remote: SocketAddr,
        address: Address,
        packet: &Packet,
    ) -> Result<(), PacketOutcome> {
        let Ok(mut reply) = Packet::new(address, self.identity.address(), Verb::Ok) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let _ = reply.append_u8(Verb::Echo.bits());
        let _ = reply.append_u64(packet.packet_id());
        let _ = reply.append(packet.payload());
        let _ = self.send_packet_via_path_locked(address, reply, true, PathKey::new(local_socket, remote), false);
        Ok(())
    }

    /// Validates candidate endpoint advice from a root and probes it.
    pub(crate) fn handle_rendezvous_locked(
        &mut self,
        local_socket: i64,
        source: Address,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let payload = packet.payload();
        if !self.peers.get(&source).is_some_and(|peer| peer.root) {
            return Ok(());
        }
        if payload.len() < 9 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let Some((address_bytes, rest)) = payload.get(1..).and_then(|tail| tail.split_at_checked(ADDRESS_SIZE)) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let Ok(address) = Address::from_bytes(address_bytes) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let (Some(port), Some(length)) = (read_be::<2>(rest, 0), rest.get(2).copied()) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let port = u16::from_be_bytes(port);
        let length = usize::from(length);
        if port == 0 || (length != 4 && length != 16) {
            return Ok(());
        }
        if payload.len() < 9 + length {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let endpoint = if length == 4 {
            let Some(raw) = read_be::<4>(payload, 9) else {
                return Err(unusable(NodeError::InvalidPacket));
            };
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(raw)), port)
        } else {
            let Some(raw) = read_be::<16>(payload, 9) else {
                return Err(unusable(NodeError::InvalidPacket));
            };
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(raw)), port)
        };
        if self.load_peer_cache_locked(address, now).is_none() {
            self.request_whois_locked(address, now);
            return Ok(());
        }
        if !self.path_allowed_locked(address, endpoint, local_socket) {
            return Ok(());
        }
        // Sending from the same local socket is what opens NAT and stateful
        // firewall state, so four random bytes precede the probe.
        let mut junk = [0u8; 4];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut junk);
        let _ = self.host.send_wire(local_socket, endpoint, junk.to_vec());
        let _ = self.send_path_probe_locked(address, local_socket, endpoint, now, None);
        Ok(())
    }

    /// Validates and probes authenticated peer path advertisements.
    pub(crate) fn handle_push_direct_paths_locked(
        &mut self,
        local_socket: i64,
        remote: SocketAddr,
        address: Address,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let payload = packet.payload();
        if payload.len() < 2 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let pushed = Self::parse_pushed_direct_paths(payload)?;
        let mut count_per_scope = [[0u8; 2]; 8];
        for candidate in pushed {
            if candidate.forget {
                continue;
            }
            if !self.path_allowed_locked(address, candidate.endpoint, local_socket) {
                continue;
            }
            if !candidate.cluster
                && self.peers.get(&address).is_some_and(|peer| peer_has_active_endpoint(peer, candidate.endpoint, now))
            {
                continue;
            }
            let scope = usize::from(path_scope(candidate.endpoint.ip()));
            let family = usize::from(candidate.endpoint.is_ipv6());
            if !candidate.cluster {
                let Some(scope_count) = count_per_scope.get_mut(scope).and_then(|counts| counts.get_mut(family)) else {
                    continue;
                };
                if *scope_count >= MAX_PUSHED_PATHS_PER_SCOPE_AND_FAMILY {
                    continue;
                }
                *scope_count += 1;
            }
            let priority = if candidate.cluster {
                self.peers
                    .get(&address)
                    .and_then(|peer| peer.paths.get(&PathKey::new(local_socket, remote)))
                    .map_or(3, |path| path.priority + 2)
            } else {
                1
            };
            if candidate.cluster {
                let _ =
                    self.send_cluster_redirect_probe_locked(address, local_socket, candidate.endpoint, now, priority);
            } else {
                let _ = self.send_path_probe_locked(address, local_socket, candidate.endpoint, now, Some(priority));
            }
        }
        Ok(())
    }

    /// Decodes the endpoint advertisements of a PUSH_DIRECT_PATHS payload.
    fn parse_pushed_direct_paths(payload: &[u8]) -> Result<Vec<PushedDirectPath>, PacketOutcome> {
        let Some(count) = read_be::<2>(payload, 0).map(u16::from_be_bytes) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let mut position = 2;
        let mut pushed: Vec<PushedDirectPath> = Vec::new();
        for _ in 0..usize::from(count) {
            let (entry, next) = Self::read_pushed_direct_path(payload, position)?;
            position = next;
            if let Some(entry) = entry {
                pushed.push(entry);
            }
        }
        Ok(pushed)
    }

    /// Decodes one PUSH_DIRECT_PATHS entry, returning it with the offset of the
    /// next entry.
    fn read_pushed_direct_path(
        payload: &[u8],
        position: usize,
    ) -> Result<(Option<PushedDirectPath>, usize), PacketOutcome> {
        if payload.len() - position < 5 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let Some(entry) = payload.get(position..position + 5) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let [flags, extension_high, extension_low, address_type, address_length] = entry else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let flags = *flags;
        let address_type = *address_type;
        let address_length = usize::from(*address_length);
        let extension_length = usize::from(u16::from_be_bytes([*extension_high, *extension_low]));
        let mut next = position + 3;
        if payload.len() - next < extension_length + 2 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        next += extension_length + 2;
        if payload.len() - next < address_length {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let Some(address_data) = payload.get(next..next + address_length) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        next += address_length;
        let Some(endpoint) = decode_direct_path_endpoint(address_type, address_data) else {
            return Ok((None, next));
        };
        if endpoint.port() == 0 || path_scope(endpoint.ip()) == 0 {
            return Ok((None, next));
        }
        Ok((Some(PushedDirectPath { endpoint, forget: flags & 0x01 != 0, cluster: flags & 0x02 != 0 }), next))
    }

    /// Returns the protocol error for a configuration request this node cannot
    /// serve.
    pub(crate) fn handle_unsupported_network_config_request_locked(
        &mut self,
        address: Address,
        path: PathKey,
        packet: &Packet,
    ) -> Result<(), PacketOutcome> {
        let payload = packet.payload();
        if payload.len() < 8 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let Ok(mut reply) = Packet::new(address, self.identity.address(), Verb::Error) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let _ = reply.append_u8(Verb::NetworkConfigRequest.bits());
        let _ = reply.append_u64(packet.packet_id());
        let _ = reply.append_u8(0x05);
        let _ = reply.append(payload.get(..8).unwrap_or_default());
        let _ = self.send_packet_via_path_locked(address, reply, true, path, false);
        Ok(())
    }

    /// Accepts a controller-pushed configuration chunk and acknowledges it.
    pub(crate) fn handle_network_config_push_locked(
        &mut self,
        local_socket: i64,
        remote: SocketAddr,
        address: Address,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let payload = packet.payload();
        if payload.len() < 8 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let Some(network_id) = read_be::<8>(payload, 0).map(u64::from_be_bytes) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let previous_update_id = match self.networks.get(&network_id) {
            Some(network) => network.last_config_update_id,
            None => return Ok(()),
        };
        if let Err(error) = self.handle_network_config_chunk_locked(packet, 0, now) {
            return Err(unusable(error));
        }
        let update_id = self.networks.get(&network_id).map(|network| network.last_config_update_id).unwrap_or_default();
        if update_id == 0 || update_id == previous_update_id {
            return Ok(());
        }
        // ZeroTier One acknowledges a pushed configuration with an ECHO despite
        // the protocol comment describing a NETWORK_CONFIG acknowledgement.
        let Ok(mut reply) = Packet::new(address, self.identity.address(), Verb::Ok) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let _ = reply.append_u8(Verb::Echo.bits());
        let _ = reply.append_u64(packet.packet_id());
        let _ = reply.append_u64(network_id);
        let _ = reply.append_u64(update_id);
        let _ = self.send_packet_via_path_locked(address, reply, true, PathKey::new(local_socket, remote), false);
        Ok(())
    }

    /// Applies a peer or controller protocol error to pending state.
    pub(crate) fn handle_error_locked(
        &mut self,
        address: Address,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let payload = packet.payload();
        if payload.len() < 10 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let in_reply_to = payload.first().copied().unwrap_or_default();
        let code = payload.get(9).copied().unwrap_or_default();
        match code {
            0x03 | 0x05 => {
                if in_reply_to == Verb::NetworkConfigRequest.bits() && payload.len() < 18 {
                    return Err(unusable(NodeError::InvalidPacket));
                }
            }
            0x06 | 0x07 | 0x09 => {
                if payload.len() < 18 {
                    return Err(unusable(NodeError::InvalidPacket));
                }
            }
            0x08 if payload.len() < 28 => return Err(unusable(NodeError::InvalidPacket)),
            _ => {}
        }
        let root = self.peers.get(&address).is_some_and(|peer| peer.root);
        if code == 0x04 && root {
            self.emit(Event::new(EventType::NodeIdentityCollision));
            return Err(unusable(NodeError::IdentityCollision));
        }
        if code == 0x06 {
            return self.handle_credentials_request_error_locked(payload, address, now);
        }
        if code == 0x08 {
            self.handle_multicast_error_locked(payload, address);
            return Ok(());
        }
        if payload.len() < 18 {
            return Ok(());
        }
        let Some(network_id) = read_be::<8>(payload, 10).map(u64::from_be_bytes) else {
            return Ok(());
        };
        let Some(network) = self.networks.get(&network_id) else {
            return Ok(());
        };
        if address != crate::address::controller(network_id) {
            return Ok(());
        }
        let is_controller = network.status == NetworkStatus::Ok || network.id == network_id;
        if !is_controller {
            return Ok(());
        }
        match code {
            0x07 => self.set_network_failure_locked(
                network_id,
                NetworkStatus::AccessDenied,
                NetworkAuthenticationInfo::default(),
                EventType::NetworkAccessDenied,
            ),
            0x03 | 0x05 => {
                if in_reply_to != Verb::NetworkConfigRequest.bits() {
                    return Ok(());
                }
                self.set_network_failure_locked(
                    network_id,
                    NetworkStatus::NotFound,
                    NetworkAuthenticationInfo::default(),
                    EventType::NetworkNotFound,
                );
            }
            0x09 => {
                let Some(authentication) = payload.get(18..).and_then(parse_authentication_info) else {
                    return Ok(());
                };
                self.set_network_failure_locked(
                    network_id,
                    NetworkStatus::AuthenticationRequired,
                    authentication,
                    EventType::NetworkAuthenticationRequired,
                );
            }
            _ => {}
        }
        Ok(())
    }
}

/// Extracts an authentication-required error payload. An absent dictionary is
/// an implicit version-zero request; a present malformed one is ignored.
fn parse_authentication_info(payload: &[u8]) -> Option<NetworkAuthenticationInfo> {
    if payload.len() <= 2 {
        return Some(NetworkAuthenticationInfo::default());
    }
    let length = usize::from(u16::from_be_bytes(read_be::<2>(payload, 0)?));
    if length > payload.len() - 2 {
        return None;
    }
    let dictionary = crate::dictionary::parse_dictionary(payload.get(2..2 + length)?).ok()?;
    let mut info = NetworkAuthenticationInfo { version: dictionary.uint("aV", 0), ..Default::default() };
    if info.version == 0 {
        info.authentication_url = dictionary_string(&dictionary, "aU", MAX_AUTHENTICATION_URL);
        return (!info.authentication_url.is_empty()).then_some(info);
    }
    if info.version != 1 {
        return None;
    }
    info.issuer_url = dictionary_string(&dictionary, "iU", MAX_AUTHENTICATION_URL);
    info.central_auth_url = dictionary_string(&dictionary, "aCU", MAX_AUTHENTICATION_URL);
    info.nonce = dictionary_string(&dictionary, "aN", MAX_SSO_NONCE_LENGTH);
    info.state = dictionary_string(&dictionary, "aS", MAX_SSO_STATE_LENGTH);
    info.client_id = dictionary_string(&dictionary, "aCID", MAX_SSO_CLIENT_ID_LENGTH);
    info.provider = dictionary_string(&dictionary, "aSSOp", MAX_SSO_PROVIDER_LENGTH);
    if info.provider.is_empty() {
        "default".clone_into(&mut info.provider);
    }
    Some(info)
}

/// The bounds the official core applies to authentication dictionary strings.
const MAX_AUTHENTICATION_URL: usize = 2047;
const MAX_SSO_NONCE_LENGTH: usize = 127;
const MAX_SSO_STATE_LENGTH: usize = 255;
const MAX_SSO_CLIENT_ID_LENGTH: usize = 255;
const MAX_SSO_PROVIDER_LENGTH: usize = 63;

fn dictionary_string(dictionary: &crate::dictionary::Dictionary, key: &str, maximum: usize) -> String {
    let value = dictionary.get(key).unwrap_or_default();
    let value = match value.iter().position(|byte| *byte == 0) {
        Some(nul) => value.get(..nul).unwrap_or_default(),
        None => value,
    };
    String::from_utf8_lossy(value.get(..maximum).unwrap_or(value)).into_owned()
}

impl Node {
    /// Sends `packet` using its derived bonding flow.
    pub fn send_packet_locked(&mut self, address: Address, packet: Packet, encrypt: bool) -> Result<(), NodeError> {
        self.send_packet_with_flow_locked(address, packet, encrypt, NO_FLOW_ID)
    }

    /// Sends `packet` using an explicit bonding flow, deferring it when no path
    /// is available yet.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "crate API: the packet is retained for the deferred-transmit queue when no path is available"
    )]
    pub fn send_packet_with_flow_locked(
        &mut self,
        address: Address,
        packet: Packet,
        encrypt: bool,
        flow_id: i32,
    ) -> Result<(), NodeError> {
        if packet.err() {
            return Err(NodeError::InvalidPacket);
        }
        let now = SystemTime::now();
        match self.try_send_packet_with_flow_locked(address, packet.clone(), encrypt, flow_id, now) {
            Err(NodeError::NoPath) => {
                let now = SystemTime::now();
                self.enqueue_pending_transmit_locked(&packet, encrypt, flow_id, now);
                Ok(())
            }
            other => other,
        }
    }

    /// Selects paths, armors `packet`, and attempts output.
    fn try_send_packet_with_flow_locked(
        &mut self,
        address: Address,
        packet: Packet,
        encrypt: bool,
        flow_id: i32,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        let Some(peer) = self.peers.get(&address) else {
            return Err(NodeError::UnknownPeer);
        };
        let root = peer.root;
        let direct_path = self.best_direct_peer_path(peer, now);
        if !root && direct_path.is_none() {
            self.try_memorized_paths_locked(address, now);
        }
        let verb = packet.verb().unwrap_or(Verb::Nop);
        let report_user_route = !root && user_traffic_verb(verb);
        let packet_id = packet.packet_id();
        let selected = self.bonded_paths_locked(address, verb, flow_id, packet_id, now);
        if selected.as_slice().is_empty() {
            return Err(NodeError::NoPath);
        }
        let paths = selected.as_slice().to_vec();
        let direct_route =
            self.peers.get(&address).is_some_and(|peer| paths.iter().any(|path| peer.paths.contains_key(path)));
        if paths.len() == 1 {
            let Some(path) = paths.first().copied() else {
                return Err(NodeError::NoPath);
            };
            let result =
                self.send_packet_via_path_with_flow_locked(address, packet, encrypt, path, false, flow_id).map(|_| ());
            if result.is_ok() && report_user_route {
                self.observe_peer_user_route_locked(address, direct_route, Some(path.endpoint), 1, now);
            }
            return result;
        }
        let clear_packet = packet.clone();
        let old_packet_id = packet.packet_id();
        let pending = self.pending.get(old_packet_id).cloned();
        let (sent_paths, send_error) = self.send_packet_copies_locked(
            address,
            &packet,
            &clear_packet,
            encrypt,
            flow_id,
            &paths,
            pending,
            old_packet_id,
        );
        if report_user_route && !sent_paths.is_empty() {
            let endpoint = match sent_paths.as_slice() {
                [only] => Some(only.endpoint),
                _ => None,
            };
            self.observe_peer_user_route_locked(address, direct_route, endpoint, sent_paths.len(), now);
        }
        if sent_paths.is_empty() {
            if let Some(error) = send_error {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Transmits an armored copy of `packet` on each selected path, reporting
    /// the paths that carried a copy and the first failure.
    fn send_packet_copies_locked(
        &mut self,
        address: Address,
        packet: &Packet,
        clear_packet: &Packet,
        encrypt: bool,
        flow_id: i32,
        paths: &[PathKey],
        pending: Option<crate::node::PendingRequest>,
        old_packet_id: u64,
    ) -> (Vec<PathKey>, Option<NodeError>) {
        let mut sent_copies: Vec<(u64, BTreeSet<PathKey>)> = Vec::new();
        let mut sent_paths: Vec<PathKey> = Vec::new();
        let mut send_error: Option<NodeError> = None;
        for (index, path) in paths.iter().enumerate() {
            let candidate = if index == 0 { packet.clone() } else { clear_packet.clone() };
            if let Some(request) = &pending {
                // Armor rejects a duplicate packet ID, so the expectation is
                // temporarily visible under the pre-armor identifier.
                let _ = self.pending.add(old_packet_id, request.clone());
            }
            let result = match self.armor_packet_for_path(address, candidate, encrypt, *path, false) {
                Ok(armored) => {
                    let candidate_id = armored.packet_id();
                    let sent = self.transmit_armored_packet(address, armored, *path, flow_id);
                    if pending.is_some() {
                        self.pending.delete(candidate_id);
                        self.pending.delete(old_packet_id);
                    }
                    match sent {
                        Ok(_) => {
                            if pending.is_some() {
                                match sent_copies.iter_mut().find(|(id, _)| *id == candidate_id) {
                                    Some((_, remaining)) => {
                                        remaining.insert(*path);
                                    }
                                    None => sent_copies.push((candidate_id, BTreeSet::from([*path]))),
                                }
                            }
                            sent_paths.push(*path);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    }
                }
                Err(error) => {
                    if pending.is_some() {
                        self.pending.delete(old_packet_id);
                    }
                    Err(error)
                }
            };
            if let Err(error) = result {
                if send_error.is_none() {
                    send_error = Some(error);
                }
            }
        }
        if let Some(request) = pending {
            for (packet_id, remaining) in sent_copies {
                let mut request = request.clone();
                request.reply_paths = Some(remaining);
                let _ = self.pending.add(packet_id, request);
            }
        }
        (sent_paths, send_error)
    }

    /// Armors and transmits `packet` on one explicit path.
    pub fn send_packet_via_path_locked(
        &mut self,
        address: Address,
        packet: Packet,
        encrypt: bool,
        path: PathKey,
        extended_hello: bool,
    ) -> Result<(), NodeError> {
        self.send_packet_via_path_with_flow_locked(address, packet, encrypt, path, extended_hello, NO_FLOW_ID)
            .map(|_| ())
    }

    /// Transmits `packet` on `path` and records its flow.
    pub fn send_packet_via_path_with_flow_locked(
        &mut self,
        address: Address,
        packet: Packet,
        encrypt: bool,
        path: PathKey,
        extended_hello: bool,
        flow_id: i32,
    ) -> Result<u64, NodeError> {
        let packet = self.armor_packet_for_path(address, packet, encrypt, path, extended_hello)?;
        self.transmit_armored_packet(address, packet, path, flow_id)
    }

    /// Applies the path's armor to `packet` and returns it ready for the wire.
    /// The returned packet's ID is the one the receiver will see.
    fn armor_packet_for_path(
        &mut self,
        address: Address,
        mut packet: Packet,
        encrypt: bool,
        path: PathKey,
        extended_hello: bool,
    ) -> Result<Packet, NodeError> {
        if packet.err() {
            return Err(NodeError::InvalidPacket);
        }
        let (mtu, trusted_path_id) = self.outbound_path_info(path.endpoint);
        let wire_length =
            packet.bytes().len() + if extended_hello { crate::packet::EXTENDED_ARMOR_KEY_SIZE } else { 0 };
        packet.set_fragmented(wire_length > mtu);
        let old_packet_id = packet.packet_id();
        if trusted_path_id != 0 {
            packet.set_trusted(trusted_path_id);
        } else if extended_hello {
            let Some((public_key, key)) = self.peers.get(&address).map(|peer| (peer.identity.public_key(), peer.key))
            else {
                return Err(NodeError::UnknownPeer);
            };
            packet.armor_extended(&key, &public_key).map_err(|_| NodeError::InvalidPacket)?;
        } else {
            self.armor_for_peer_locked(address, &mut packet, encrypt)?;
        }
        self.move_pending_packet_id_locked(old_packet_id, packet.packet_id())?;
        Ok(packet)
    }

    /// Sends one armored packet on `path` and records its flow.
    fn transmit_armored_packet(
        &mut self,
        address: Address,
        packet: Packet,
        path: PathKey,
        _flow_id: i32,
    ) -> Result<u64, NodeError> {
        let verb = packet.verb().unwrap_or(Verb::Nop);
        let (mtu, _) = self.outbound_path_info(path.endpoint);
        let now = SystemTime::now();
        let packet_id = packet.packet_id();
        self.record_outgoing_bond_packet_locked(address, path, packet_id, verb, now);
        let sent = self.send_wire_packet_via_path_locked(path, packet.into_bytes(), mtu)?;
        if sent {
            self.note_wire_path_send_locked(path, now);
            if let Some(state) = self.peers.get_mut(&address).and_then(|peer| peer.paths.get_mut(&path)) {
                state.last_send = Some(now);
            }
        }
        Ok(packet_id)
    }

    /// Armors `packet` on one path with an explicit peer key, for a peer that
    /// is not in the table (an address collision reply).
    fn send_packet_via_path_with_key_locked(
        &mut self,
        address: Address,
        mut packet: Packet,
        encrypt: bool,
        path: PathKey,
        key: &[u8; crate::identity::SYMMETRIC_KEY_SIZE],
    ) -> Result<(), NodeError> {
        if packet.err() {
            return Err(NodeError::InvalidPacket);
        }
        let (mtu, trusted_path_id) = self.outbound_path_info(path.endpoint);
        if trusted_path_id != 0 {
            packet.set_trusted(trusted_path_id);
        } else {
            packet.armor(key, encrypt).map_err(|_| NodeError::InvalidPacket)?;
        }
        let _ = address;
        self.send_wire_packet_via_path_locked(path, packet.into_bytes(), mtu)?;
        Ok(())
    }

    /// Applies the negotiated packet protection for one peer.
    fn armor_for_peer_locked(&mut self, address: Address, packet: &mut Packet, encrypt: bool) -> Result<(), NodeError> {
        let (protocol, key) = match self.peers.get(&address) {
            Some(peer) => (peer.protocol, peer.key),
            None => return Err(NodeError::UnknownPeer),
        };
        if encrypt && protocol >= 12 {
            let Some(keys) = self.peers.get_mut(&address).map(|peer| &mut peer.aes_keys) else {
                return Err(NodeError::UnknownPeer);
            };
            packet.armor_aes_with(keys).map_err(|_| NodeError::InvalidPacket)
        } else {
            packet.armor(&key, encrypt).map_err(|_| NodeError::InvalidPacket)
        }
    }

    /// Fragments `data` to `mtu` and hands each piece to the host. The boolean
    /// result reports whether at least one datagram was sent.
    fn send_wire_packet_via_path_locked(
        &mut self,
        path: PathKey,
        data: Vec<u8>,
        mtu: usize,
    ) -> Result<bool, NodeError> {
        if data.len() <= mtu {
            return self.host.send_wire(path.local_socket, path.endpoint, data).map(|()| true);
        }
        let remaining = data.len() - mtu;
        let fragment_payload = mtu.saturating_sub(FRAGMENT_HEADER_SIZE);
        if fragment_payload == 0 {
            return Err(NodeError::InvalidPacket);
        }
        let total = 1 + remaining.div_ceil(fragment_payload);
        if total > 7 {
            return Err(NodeError::InvalidPacket);
        }
        let mut fragments: Vec<Vec<u8>> = Vec::with_capacity(total - 1);
        for (index, start) in (mtu..data.len()).step_by(fragment_payload).enumerate() {
            let end = (start + fragment_payload).min(data.len());
            let number = u8::try_from(index + 1).map_err(|_| NodeError::InvalidPacket)?;
            let count = u8::try_from(total).map_err(|_| NodeError::InvalidPacket)?;
            let mut fragment = Vec::with_capacity(FRAGMENT_HEADER_SIZE + end - start);
            fragment.extend_from_slice(data.get(..13).unwrap_or_default());
            fragment.push(0xff);
            fragment.push((count << 4) | number);
            fragment.resize(FRAGMENT_HEADER_SIZE, 0);
            fragment.extend_from_slice(data.get(start..end).unwrap_or_default());
            fragments.push(fragment);
        }
        let head = data.get(..mtu).unwrap_or_default().to_vec();
        self.host.send_wire(path.local_socket, path.endpoint, head)?;
        for fragment in fragments {
            self.host.send_wire(path.local_socket, path.endpoint, fragment)?;
        }
        Ok(true)
    }

    /// Transfers request tracking after re-armor changed the packet ID.
    fn move_pending_packet_id_locked(&mut self, old_packet_id: u64, new_packet_id: u64) -> Result<(), NodeError> {
        if new_packet_id == old_packet_id {
            return Ok(());
        }
        let Some(request) = self.pending.get(old_packet_id).cloned() else {
            return Ok(());
        };
        self.pending.delete(old_packet_id);
        match self.pending.add(new_packet_id, request) {
            Ok(()) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Records the responding physical path. Broadcast copies can share a
    /// packet ID, so a duplicate response from one path must not consume the
    /// response expected from another.
    fn consume_pending_reply_locked(&mut self, packet_id: u64, request: &crate::node::PendingRequest, path: PathKey) {
        if request.verb == Verb::Hello || request.path.is_some_and(|known| known.local_socket == ANY_LOCAL_SOCKET) {
            return;
        }
        if let Some(mut remaining) = request.reply_paths.clone() {
            if !remaining.remove(&path) {
                return;
            }
            if !remaining.is_empty() {
                return;
            }
        }
        self.pending.delete(packet_id);
    }

    /// Retains a packet until its peer has a usable path.
    pub(crate) fn enqueue_pending_transmit_locked(
        &mut self,
        packet: &Packet,
        encrypt: bool,
        flow_id: i32,
        now: SystemTime,
    ) {
        if self.pending_transmits.len() >= MAX_PENDING_TRANSMITS {
            let dropped = self.pending_transmits.remove(0);
            self.pending.delete(dropped.packet.packet_id());
        }
        self.pending_transmits.push(PendingTransmit { packet: packet.clone(), encrypt, flow_id, created_at: now });
    }

    /// Retries non-expired deferred packet output. A `None` destination retries
    /// the whole queue.
    pub(crate) fn retry_pending_transmits_locked(&mut self, destination: Option<Address>, now: SystemTime) {
        if self.pending_transmits.is_empty() {
            return;
        }
        let transmits = std::mem::take(&mut self.pending_transmits);
        let mut kept: Vec<PendingTransmit> = Vec::with_capacity(transmits.len());
        for transmit in transmits {
            if elapsed(now, transmit.created_at) > PENDING_TRANSMIT_EXPIRATION {
                self.pending.delete(transmit.packet.packet_id());
                continue;
            }
            let target = transmit.packet.destination();
            if destination.is_some_and(|wanted| wanted != target) {
                kept.push(transmit);
                continue;
            }
            if !self.peers.contains_key(&target) {
                kept.push(transmit);
                continue;
            }
            let original_id = transmit.packet.packet_id();
            let tracked = self.pending.get(original_id).cloned();
            match self.try_send_packet_with_flow_locked(
                target,
                transmit.packet.clone(),
                transmit.encrypt,
                transmit.flow_id,
                now,
            ) {
                Err(NodeError::NoPath) => kept.push(transmit),
                Err(_) => {
                    // The queue cannot report an asynchronous send failure to
                    // its original caller, so only this request's tracking is
                    // dropped, under either identifier.
                    if let Some(request) = &tracked {
                        if self.pending.get(original_id) == Some(request) {
                            self.pending.delete(original_id);
                        }
                        let armor_id = transmit.packet.packet_id();
                        if self.pending.get(armor_id) == Some(request) {
                            self.pending.delete(armor_id);
                        }
                    }
                }
                Ok(()) => {}
            }
        }
        self.pending_transmits = kept;
    }

    /// Probes cached endpoints for a peer without live paths.
    fn try_memorized_paths_locked(&mut self, address: Address, now: SystemTime) {
        let configured = self.peer_paths.get(&address).cloned();
        let looked_up = self.host.path_lookup(address);
        if configured.is_none() && looked_up.is_empty() {
            return;
        }
        let retry_due = self
            .peers
            .get(&address)
            .and_then(|peer| peer.last_path_lookup)
            .is_none_or(|looked| elapsed(now, looked) >= MEMORIZED_PATH_RETRY_PERIOD);
        if !retry_due {
            return;
        }
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.last_path_lookup = Some(now);
        }
        let mut endpoints = configured.map(|config| config.try_endpoints).unwrap_or_default();
        endpoints.extend(looked_up);
        for endpoint in endpoints {
            if !self.path_allowed_locked(address, endpoint, ANY_LOCAL_SOCKET) {
                continue;
            }
            let _ = self.send_path_probe_locked(address, ANY_LOCAL_SOCKET, endpoint, now, None);
        }
    }

    /// Reports successful route-kind and endpoint changes, coalescing
    /// same-kind changes so an oscillating path cannot flood diagnostics.
    pub(crate) fn observe_peer_user_route_locked(
        &mut self,
        address: Address,
        direct: bool,
        endpoint: Option<SocketAddr>,
        path_count: usize,
        now: SystemTime,
    ) {
        let (route, endpoint, path_count) = if direct {
            let endpoint = if path_count == 1 { endpoint } else { None };
            (crate::node::PeerRoute::Direct, endpoint, path_count)
        } else {
            (crate::node::PeerRoute::Relayed, None, 0)
        };
        let Some(peer) = self.peers.get_mut(&address) else {
            return;
        };
        if peer.reported_user_route == route
            && peer.reported_user_endpoint == endpoint
            && peer.reported_user_path_count == path_count
        {
            peer.pending_user_route = crate::node::PeerRoute::Unknown;
            peer.pending_user_endpoint = None;
            peer.pending_user_path_count = 0;
            return;
        }
        let rate_limited = peer.reported_user_route == route
            && peer.last_user_route_report.is_some_and(|reported| now < reported + PEER_ROUTE_REPORT_INTERVAL);
        if rate_limited {
            peer.pending_user_route = route;
            peer.pending_user_endpoint = endpoint;
            peer.pending_user_path_count = path_count;
            return;
        }
        self.emit_peer_user_route_locked(address, route, endpoint, path_count, now);
    }

    /// Emits the latest coalesced route detail once its window elapsed.
    pub(crate) fn flush_pending_peer_user_route_locked(&mut self, address: Address, now: SystemTime) {
        let Some(peer) = self.peers.get(&address) else {
            return;
        };
        if peer.pending_user_route == crate::node::PeerRoute::Unknown {
            return;
        }
        if peer.last_user_route_report.is_some_and(|reported| now < reported + PEER_ROUTE_REPORT_INTERVAL) {
            return;
        }
        let (route, endpoint, path_count) =
            (peer.pending_user_route, peer.pending_user_endpoint, peer.pending_user_path_count);
        self.emit_peer_user_route_locked(address, route, endpoint, path_count, now);
    }

    fn emit_peer_user_route_locked(
        &mut self,
        address: Address,
        route: crate::node::PeerRoute,
        endpoint: Option<SocketAddr>,
        path_count: usize,
        now: SystemTime,
    ) {
        let Some(role) = self.peers.get(&address).map(|peer| peer.role) else {
            return;
        };
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.reported_user_route = route;
            peer.reported_user_endpoint = endpoint;
            peer.reported_user_path_count = path_count;
            peer.last_user_route_report = Some(now);
            peer.pending_user_route = crate::node::PeerRoute::Unknown;
            peer.pending_user_endpoint = None;
            peer.pending_user_path_count = 0;
        }
        let mut event = Event::new(EventType::PeerRouteChanged)
            .with_peer_identity(address, role)
            .with_route(route)
            .with_path_count(path_count);
        if let Some(endpoint) = endpoint {
            event = event.with_endpoint(endpoint);
        }
        self.emit(event);
    }
}

/// Reports whether a verb carries embedding-provided network traffic rather
/// than protocol maintenance.
fn user_traffic_verb(verb: Verb) -> bool {
    matches!(verb, Verb::Frame | Verb::ExtFrame | Verb::MulticastFrame)
}

impl Node {
    /// Sends a normal probe to one peer endpoint. A caller that obtained
    /// `endpoint` from an unauthenticated source must validate it first.
    pub fn send_path_probe_locked(
        &mut self,
        address: Address,
        local_socket: i64,
        endpoint: SocketAddr,
        now: SystemTime,
        priority: Option<i32>,
    ) -> Result<bool, NodeError> {
        self.send_path_probe_for_network_mode_locked(address, local_socket, endpoint, 0, now, false, priority)
    }

    /// Probes an endpoint learned from a cluster redirect.
    fn send_cluster_redirect_probe_locked(
        &mut self,
        address: Address,
        local_socket: i64,
        endpoint: SocketAddr,
        now: SystemTime,
        priority: i32,
    ) -> Result<bool, NodeError> {
        self.send_path_probe_for_network_mode_locked(address, local_socket, endpoint, 0, now, true, Some(priority))
    }

    /// Selects full HELLO or lightweight ECHO probing with optional network
    /// context, reporting whether a probe was sent rather than suppressed by
    /// the duplicate-probe window.
    fn send_path_probe_for_network_mode_locked(
        &mut self,
        address: Address,
        local_socket: i64,
        endpoint: SocketAddr,
        network_id: u64,
        now: SystemTime,
        full_hello: bool,
        priority: Option<i32>,
    ) -> Result<bool, NodeError> {
        let Some(peer) = self.peers.get(&address) else {
            return Err(NodeError::UnknownPeer);
        };
        let stale: Vec<PathKey> = peer
            .path_probe
            .iter()
            .filter(|(_, probed)| elapsed(now, **probed) > PEER_PATH_PROBE_WINDOW)
            .map(|(key, _)| *key)
            .collect();
        let key = PathKey::new(local_socket, endpoint);
        let recent = peer.path_probe.get(&key).is_some_and(|probed| elapsed(now, *probed) <= PEER_PATH_PROBE_WINDOW);
        let full = peer.path_probe.len() >= MAX_PEER_PATHS;
        let legacy = peer.protocol < 5 || (peer.major == 1 && peer.minor == 1 && peer.revision == 0);
        if let Some(peer) = self.peers.get_mut(&address) {
            for key in stale {
                peer.path_probe.remove(&key);
            }
        }
        if recent {
            return Ok(false);
        }
        if full && !self.peers.get(&address).is_some_and(|peer| peer.path_probe.contains_key(&key)) {
            return Err(NodeError::TooManyPathProbes);
        }
        let priority = priority.unwrap_or(1).max(1);
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.path_probe.insert(key, now);
        }
        if full_hello || legacy {
            if let Err(error) = self.send_hello_at_path_locked(address, key, now, priority, network_id) {
                if let Some(peer) = self.peers.get_mut(&address) {
                    peer.path_probe.remove(&key);
                }
                return Err(error);
            }
            return Ok(true);
        }
        let Ok(packet) = Packet::new(address, self.identity.address(), Verb::Echo) else {
            return Err(NodeError::InvalidPacket);
        };
        let packet_id = packet.packet_id();
        self.add_pending_locked(
            packet_id,
            crate::node::PendingRequest {
                verb: Verb::Echo,
                peer: address,
                network_id,
                sent_at: Some(now),
                slot: 0,
                generation: 0,
                path: Some(key),
                priority,
                reply_paths: None,
            },
        )?;
        if let Err(error) = self.send_packet_via_path_locked(address, packet, true, key, false) {
            self.delete_pending_locked(packet_id);
            if let Some(peer) = self.peers.get_mut(&address) {
                peer.path_probe.remove(&key);
            }
            return Err(error);
        }
        Ok(true)
    }

    /// Advertises local direct candidates when due.
    fn maybe_push_direct_paths_locked(&mut self, address: Address, path: PathKey, now: SystemTime, have_path: bool) {
        if !self.peer_trusted_locked(address, now) {
            return;
        }
        let interval = if have_path {
            let base = crate::node::DIRECT_PATH_PUSH_HAVE_PATH_INTERVAL;
            if self.low_bandwidth {
                base * 16
            } else {
                base
            }
        } else {
            crate::node::DIRECT_PATH_PUSH_INTERVAL
        };
        let due = self
            .peers
            .get(&address)
            .and_then(|peer| peer.last_direct_path_push_sent)
            .is_none_or(|sent| elapsed(now, sent) >= interval);
        if !due {
            return;
        }
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.last_direct_path_push_sent = Some(now);
        }
        let mut candidates = self.direct_path_candidates_locked();
        while !candidates.is_empty() {
            let mut items: Vec<u8> = Vec::with_capacity(1150);
            let mut count = 0;
            for endpoint in &candidates {
                let mut encoded = Vec::new();
                append_pushed_direct_path(&mut encoded, *endpoint);
                if !items.is_empty() && PAYLOAD_OFFSET + 2 + items.len() + encoded.len() >= 1200 {
                    break;
                }
                items.extend_from_slice(&encoded);
                count += 1;
            }
            let Ok(mut packet) = Packet::new(address, self.identity.address(), Verb::PushDirectPaths) else {
                return;
            };
            let _ = packet.append_u16(u16::try_from(count).unwrap_or(0));
            let _ = packet.append(&items);
            let _ = packet.compress();
            let _ = self.send_packet_via_path_locked(address, packet, true, path, false);
            candidates.drain(..count);
        }
    }

    /// Reports whether `peer` has recently established network trust.
    fn peer_trusted_locked(&self, address: Address, now: SystemTime) -> bool {
        let Some(peer) = self.peers.get(&address) else {
            return false;
        };
        if peer.root {
            return true;
        }
        peer.last_trust_established.is_some_and(|established| elapsed(now, established) < TRUST_EXPIRATION)
    }

    /// Filters embedding-provided endpoints for advertisement.
    #[must_use]
    pub fn direct_path_candidates_locked(&self) -> Vec<SocketAddr> {
        let mut result = Vec::new();
        let mut add = |endpoint: SocketAddr| {
            if endpoint.port() == 0 || path_scope(endpoint.ip()) == 0 {
                return;
            }
            if !result.contains(&endpoint) {
                result.push(endpoint);
            }
        };
        for endpoint in self.host.direct_paths() {
            add(endpoint);
        }
        for surface in self.surfaces.values() {
            add(surface.endpoint);
        }
        result
    }

    /// Reports the external UDP endpoints reported by authenticated peers.
    #[must_use]
    pub fn surface_addresses(&self) -> Vec<SocketAddr> {
        let mut addresses: Vec<SocketAddr> = Vec::new();
        for surface in self.surfaces.values() {
            if !addresses.contains(&surface.endpoint) {
                addresses.push(surface.endpoint);
            }
        }
        addresses
    }

    /// Records a peer report of the local external endpoint.
    pub(crate) fn observe_surface_locked(
        &mut self,
        address: Address,
        local_socket: i64,
        remote: SocketAddr,
        external: SocketAddr,
        now: SystemTime,
    ) {
        let scope = path_scope(external.ip());
        if scope == 0 || scope != path_scope(remote.ip()) || external.is_ipv6() != remote.is_ipv6() {
            return;
        }
        let Some(reporter) = self.peers.get(&address) else {
            return;
        };
        let trusted = reporter.root;
        let role = reporter.role;
        let key = SurfaceKey { reporter: address, path: PathKey::new(local_socket, remote), scope };
        let previous = self.surfaces.get(&key).copied();
        if previous.is_none() && self.surfaces.len() >= MAX_SURFACE_ENTRIES {
            if let Some(oldest) = self.surfaces.iter().min_by_key(|(_, state)| state.updated).map(|(key, _)| *key) {
                self.surfaces.remove(&oldest);
            }
        }
        self.surfaces.insert(key, SurfaceState { endpoint: external, updated: now, trusted });
        let Some(previous) = previous else {
            return;
        };
        if !trusted
            || elapsed(now, previous.updated) < Duration::from_secs(600)
            || unmap(previous.endpoint.ip()) == unmap(external.ip())
        {
            return;
        }
        let doomed: Vec<SurfaceKey> = self
            .surfaces
            .keys()
            .filter(|candidate| **candidate != key && candidate.scope == scope && candidate.path.endpoint != remote)
            .copied()
            .collect();
        for candidate in doomed {
            self.surfaces.remove(&candidate);
        }
        let mut reset_paths = 0usize;
        let addresses: Vec<Address> = self.peers.keys().copied().collect();
        for candidate in addresses {
            let stale: Vec<PathKey> = self
                .peers
                .get(&candidate)
                .map(|peer| {
                    peer.paths
                        .iter()
                        .filter(|(path, _)| {
                            path.endpoint.is_ipv6() == external.is_ipv6() && path_scope(path.endpoint.ip()) == scope
                        })
                        .map(|(path, _)| *path)
                        .collect()
                })
                .unwrap_or_default();
            for path in stale {
                if let Some(state) = self.peers.get_mut(&candidate).and_then(|peer| peer.paths.get_mut(&path)) {
                    state.last_receive = None;
                }
                let _ = self.send_path_probe_locked(candidate, path.local_socket, path.endpoint, now, None);
                reset_paths += 1;
            }
        }
        let _ = role;
        self.emit(
            Event::new(EventType::LocalSurfaceChanged)
                .with_reporter(address)
                .with_endpoint(external)
                .with_previous_endpoint(previous.endpoint)
                .with_path_count(reset_paths)
                .with_peer_identity(address, role),
        );
    }

    /// Records an authenticated path without packet-specific context.
    pub(crate) fn observe_authenticated_path_locked(
        &mut self,
        address: Address,
        local_socket: i64,
        remote: SocketAddr,
        now: SystemTime,
    ) {
        self.observe_authenticated_packet_path_locked(address, local_socket, remote, Some(Verb::Hello), 0, 0, now);
    }

    /// Refreshes a path and emits discovery events when it is new.
    pub(crate) fn observe_authenticated_packet_path_locked(
        &mut self,
        address: Address,
        local_socket: i64,
        remote: SocketAddr,
        verb: Option<Verb>,
        packet_id: u64,
        network_id: u64,
        now: SystemTime,
    ) {
        let key = PathKey::new(local_socket, remote);
        if let Some(peer) = self.peers.get_mut(&address) {
            if let Some(path) = peer.paths.get_mut(&key) {
                path.last_receive = Some(now);
                peer.path_probe.remove(&key);
            }
        }
        if self.peers.get(&address).is_some_and(|peer| peer.paths.contains_key(&key)) {
            self.maybe_push_direct_paths_locked(address, key, now, true);
            return;
        }
        if self.bonding_policy_for_peer_locked(address) == BondingPolicy::None {
            let remote_ip = unmap(remote.ip());
            let duplicate = self.peers.get(&address).is_some_and(|peer| {
                peer.paths.iter().any(|(known, path)| {
                    known.local_socket == local_socket
                        && unmap(known.endpoint.ip()) == remote_ip
                        && self.wire_path_age(*known, path, now) < crate::node::PEER_PATH_ACTIVE_TIME
                })
            });
            if duplicate {
                return;
            }
        }
        if !self.path_allowed_locked(address, remote, local_socket) {
            return;
        }
        if verb == Some(Verb::Ok) {
            let full = self.peers.get(&address).is_some_and(|peer| peer.paths.len() >= MAX_PEER_PATHS);
            if full && !self.evict_oldest_path_locked(address, now) {
                return;
            }
            self.add_peer_path_locked(
                address,
                key,
                PeerPathState { last_receive: Some(now), last_probe: Some(now), priority: 1, ..Default::default() },
                now,
            );
            if let Some(peer) = self.peers.get_mut(&address) {
                peer.bond_last_maintenance = None;
                peer.path_probe.remove(&key);
            }
            self.maybe_push_direct_paths_locked(address, key, now, true);
            let Some(role) = self.peers.get(&address).map(|peer| peer.role) else {
                return;
            };
            self.emit(
                Event::new(EventType::PeerPathLearned)
                    .with_peer_identity(address, role)
                    .with_network(network_id)
                    .with_endpoint(remote)
                    .with_path_count(1),
            );
            return;
        }
        // An authenticated path learned from other traffic is confirmed with a
        // full HELLO; a lightweight ECHO is reserved for known paths.
        let _ = packet_id;
        let _ =
            self.send_path_probe_for_network_mode_locked(address, local_socket, remote, network_id, now, true, None);
        self.maybe_push_direct_paths_locked(address, key, now, false);
    }

    /// Schedules bounded identity discovery for `address`.
    pub fn request_whois_locked(&mut self, address: Address, now: SystemTime) {
        if self.load_peer_cache_locked(address, now).is_some() {
            return;
        }
        if self.pending_whois.get(&address).is_some_and(|requested| elapsed(now, *requested) < WHOIS_RETRY_PERIOD) {
            return;
        }
        let (Some(root), Some(path)) = self.best_root_peer_path(now) else {
            return;
        };
        let Ok(mut packet) = Packet::new(root, self.identity.address(), Verb::Whois) else {
            return;
        };
        let _ = packet.append(&address.bytes());
        let packet_id = packet.packet_id();
        if self
            .add_pending_locked(
                packet_id,
                crate::node::PendingRequest {
                    verb: Verb::Whois,
                    peer: root,
                    network_id: 0,
                    sent_at: Some(now),
                    slot: 0,
                    generation: 0,
                    path: Some(path),
                    priority: 0,
                    reply_paths: None,
                },
            )
            .is_err()
        {
            return;
        }
        self.pending_whois.insert(address, now);
        if self.send_packet_via_path_locked(root, packet, true, path, false).is_err() {
            self.delete_pending_locked(packet_id);
            self.pending_whois.remove(&address);
        }
    }

    /// Sends due identity requests for every address this node is waiting on.
    pub fn retry_pending_whois_locked(&mut self, now: SystemTime) {
        let mut requested: BTreeSet<Address> = BTreeSet::new();
        let local = self.identity.address();
        let add = |address: Address, requested: &mut BTreeSet<Address>| {
            if address != local && !address.is_reserved() && !self.peers.contains_key(&address) {
                requested.insert(address);
            }
        };
        for address in self.pending_incoming.keys().copied() {
            add(address, &mut requested);
        }
        for address in self.pending_frames.keys().copied() {
            add(address, &mut requested);
        }
        for transmit in &self.pending_transmits {
            add(transmit.packet.destination(), &mut requested);
        }
        for network in self.networks.values() {
            for (group, pending) in &network.pending_multicast {
                for item in pending {
                    if let Some(targets) = &item.targets {
                        for address in targets {
                            if !item.sent.contains(address) {
                                add(*address, &mut requested);
                            }
                        }
                        continue;
                    }
                    if let Some(members) = network.multicast.get(group) {
                        for (address, seen) in members {
                            if elapsed(now, *seen) >= crate::node::MULTICAST_MEMBER_EXPIRATION
                                || item.sent.contains(address)
                            {
                                continue;
                            }
                            add(*address, &mut requested);
                        }
                    }
                    for address in network.config.specialist_addresses(SPECIALIST_TYPE_ACTIVE_BRIDGE) {
                        if !item.sent.contains(&address) {
                            add(address, &mut requested);
                        }
                    }
                }
            }
        }
        for address in requested {
            self.request_whois_locked(address, now);
        }
    }

    /// Reports whether identity discovery remains queued.
    #[must_use]
    pub fn has_pending_whois_work_locked(&self) -> bool {
        !self.pending_incoming.is_empty()
            || !self.pending_frames.is_empty()
            || !self.pending_transmits.is_empty()
            || self
                .networks
                .values()
                .any(|network| network.pending_multicast.values().any(|pending| !pending.is_empty()))
    }
}

/// Serializes one direct endpoint advertisement.
pub fn append_pushed_direct_path(dst: &mut Vec<u8>, endpoint: SocketAddr) {
    dst.extend_from_slice(&[0, 0, 0]);
    match unmap(endpoint.ip()) {
        IpAddr::V4(address) => {
            dst.push(4);
            dst.push(6);
            dst.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            dst.push(6);
            dst.push(18);
            dst.extend_from_slice(&address.octets());
        }
    }
    dst.extend_from_slice(&endpoint.port().to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary::append_dictionary_uint;
    use crate::identity::SIGNATURE_SIZE;
    use crate::network_config::{NetworkType, DEFAULT_NETWORK_MTU, NETWORK_CONFIG_VERSION};
    use crate::node::{MemoryStore, NodeHost, PendingRequest};
    use std::sync::{Arc, Mutex};

    /// The local socket handle the harness reports for a received datagram, so
    /// learned paths carry a concrete socket rather than the embedding's
    /// "choose one for me" handle.
    const TEST_SOCKET: i64 = 7;

    /// One node's in-process physical wire.
    #[derive(Clone, Default)]
    struct Wire {
        queue: Arc<Mutex<Vec<(i64, Vec<u8>)>>>,
        direct: Arc<Mutex<Vec<SocketAddr>>>,
    }

    impl Wire {
        fn take(&self) -> Vec<(i64, Vec<u8>)> {
            std::mem::take(&mut *self.queue.lock().expect("lock"))
        }

        fn pending(&self) -> usize {
            self.queue.lock().expect("lock").len()
        }
    }

    #[derive(Clone, Default)]
    struct WireHost {
        wire: Wire,
        peers: Arc<Mutex<std::collections::BTreeMap<Address, Identity>>>,
        whois: Arc<Mutex<Vec<Address>>>,
    }

    impl WireHost {
        fn learn(&self, identity: &Identity) {
            self.peers.lock().expect("lock").insert(identity.address(), identity.clone());
        }

        fn set_direct_paths(&self, endpoints: Vec<SocketAddr>) {
            *self.wire.direct.lock().expect("lock") = endpoints;
        }
    }

    impl NodeHost for WireHost {
        fn peer_identity(&self, address: Address) -> Option<Identity> {
            self.peers.lock().expect("lock").get(&address).cloned()
        }

        fn send_wire(&mut self, local_socket: i64, _remote: SocketAddr, packet: Vec<u8>) -> Result<(), NodeError> {
            self.wire.queue.lock().expect("lock").push((local_socket, packet));
            Ok(())
        }

        fn request_whois(&mut self, address: Address) {
            self.whois.lock().expect("lock").push(address);
        }

        fn announce_multicast(&mut self, _network_id: u64) {}

        fn trace_network_config_request(&mut self, _network_id: u64, _controller: Address) {}

        fn direct_paths(&self) -> Vec<SocketAddr> {
            self.wire.direct.lock().expect("lock").clone()
        }
    }

    /// Two nodes wired to each other through in-process datagram queues.
    struct Topology {
        a: Node,
        b: Node,
        a_host: WireHost,
        a_addr: SocketAddr,
        b_addr: SocketAddr,
        a_identity: Identity,
        b_identity: Identity,
        a_wire: Wire,
        b_wire: Wire,
    }

    impl Topology {
        fn new() -> Self {
            let a_identity = Identity::generate();
            let b_identity = Identity::generate();
            let a_addr: SocketAddr = "192.0.2.10:9991".parse().expect("endpoint");
            let b_addr: SocketAddr = "198.51.100.20:9992".parse().expect("endpoint");
            let a_host = WireHost::default();
            let b_host = WireHost::default();
            a_host.learn(&b_identity);
            b_host.learn(&a_identity);
            let a_wire = a_host.wire.clone();
            let b_wire = b_host.wire.clone();
            let a = Node::new(a_identity.clone(), Box::new(MemoryStore::new()), Box::new(a_host.clone()));
            let b = Node::new(b_identity.clone(), Box::new(MemoryStore::new()), Box::new(b_host.clone()));
            Self { a, b, a_host, a_addr, b_addr, a_identity, b_identity, a_wire, b_wire }
        }

        /// Delivers every queued datagram to the other node until both wires
        /// settle, so a reply that provokes a reply is also carried.
        fn pump(&mut self, now: SystemTime) {
            for _ in 0..8 {
                let mut moved = false;
                for (_, bytes) in self.a_wire.take() {
                    moved = true;
                    self.b
                        .process_wire_packet(TEST_SOCKET, self.a_addr, &bytes, now)
                        .expect("B accepts a datagram from A");
                }
                for (_, bytes) in self.b_wire.take() {
                    moved = true;
                    self.a
                        .process_wire_packet(TEST_SOCKET, self.b_addr, &bytes, now)
                        .expect("A accepts a datagram from B");
                }
                if !moved {
                    return;
                }
            }
            panic!("the wire did not settle");
        }
    }

    /// Gives `address` one direct path so a protocol send is not deferred.
    fn install_path(node: &mut Node, address: Address, endpoint: SocketAddr, now: SystemTime) -> PathKey {
        node.load_peer_cache_locked(address, now).expect("peer identity is cached");
        let key = PathKey::new(ANY_LOCAL_SOCKET, endpoint);
        node.add_peer_path_locked(
            address,
            key,
            PeerPathState { last_receive: Some(now), last_probe: Some(now), priority: 1, ..Default::default() },
            now,
        );
        key
    }

    /// A synthetic planet whose only root is `identity`, so root-only paths
    /// work without the embedded Earth topology.
    fn set_test_planet(node: &mut Node, identity: &Identity) {
        node.planet = World {
            world_type: WorldType::Planet,
            id: 0x0123_4567,
            timestamp: 1,
            updates_must_be_signed_by: [0u8; 64],
            signature: [0u8; 96],
            roots: vec![crate::world::WorldRoot { identity: identity.clone(), endpoints: Vec::new() }],
        };
        node.refresh_topology_roots_locked();
    }

    /// The packet ID of the only outstanding request of `verb`.
    fn pending_id(node: &Node, verb: Verb) -> u64 {
        node.pending()
            .iter()
            .find(|(_, request)| request.verb == verb)
            .map(|(packet_id, _)| packet_id)
            .expect("the request is outstanding")
    }

    fn append_test_network_config(network_id: u64, member: Address) -> Vec<u8> {
        let entries = [
            ("v", NETWORK_CONFIG_VERSION),
            ("nwid", network_id),
            ("id", member.uint64()),
            ("t", u64::from(NetworkType::PUBLIC.bits())),
            ("mtu", u64::from(DEFAULT_NETWORK_MTU)),
            ("r", 0x1122_3344_5566_7788),
            ("ts", 0x8877_6655_4433_2211),
        ];
        let mut config = Vec::new();
        for (key, value) in entries {
            config = append_dictionary_uint(config, key, value).expect("dictionary entry");
        }
        config
    }

    /// One controller-signed configuration chunk payload, exactly as the
    /// controller signs it.
    fn signed_config_chunk(controller: &Identity, network_id: u64, update_id: u64, chunk: &[u8]) -> Vec<u8> {
        let mut signed = Vec::new();
        signed.extend_from_slice(&network_id.to_be_bytes());
        signed.extend_from_slice(&u16::try_from(chunk.len()).expect("chunk length").to_be_bytes());
        signed.extend_from_slice(chunk);
        signed.push(0x01);
        signed.extend_from_slice(&update_id.to_be_bytes());
        signed.extend_from_slice(&u32::try_from(chunk.len()).expect("total").to_be_bytes());
        signed.extend_from_slice(&0u32.to_be_bytes());
        let signature = controller.sign(&signed).expect("signs");
        signed.push(1);
        signed.extend_from_slice(&(SIGNATURE_SIZE as u16).to_be_bytes());
        signed.extend_from_slice(&signature);
        signed
    }

    /// One controller `OK` reply carrying the configuration chunk.
    fn ok_config_chunk(
        controller: &Identity,
        member: Address,
        request_id: u64,
        network_id: u64,
        update_id: u64,
        chunk: &[u8],
    ) -> Packet {
        let mut packet = Packet::new(member, controller.address(), Verb::Ok).expect("reply packet");
        let _ = packet.append_u8(Verb::NetworkConfigRequest.bits());
        let _ = packet.append_u64(request_id);
        let _ = packet.append(&signed_config_chunk(controller, network_id, update_id, chunk));
        packet
    }

    #[test]
    fn two_nodes_complete_a_hello_exchange() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        topology
            .a
            .send_hello_locked(topology.b_identity.address(), topology.b_addr, now)
            .expect("the handshake is queued");
        assert_eq!(topology.a_wire.pending(), 1, "one HELLO datagram leaves A");
        topology.pump(now);

        let b_peers = topology.b.peers(now);
        assert_eq!(b_peers.len(), 1, "B learned exactly one peer");
        assert_eq!(b_peers[0].address, topology.a_identity.address());
        assert_eq!(b_peers[0].protocol, PROTOCOL_VERSION);
        assert_eq!(b_peers[0].version_major, Some(NODE_VERSION_MAJOR));
        assert_eq!(b_peers[0].version_revision, Some(NODE_VERSION_REVISION));

        let a_peers = topology.a.peers(now);
        assert_eq!(a_peers.len(), 1);
        assert_eq!(a_peers[0].protocol, PROTOCOL_VERSION, "the OK negotiated the version");
        assert_eq!(a_peers[0].paths.len(), 1, "the OK established one direct path");
        assert_eq!(a_peers[0].paths[0].endpoint, topology.b_addr);
        assert!(a_peers[0].paths[0].preferred);
        assert!(a_peers[0].paths[0].active);
        assert_eq!(a_peers[0].paths[0].latency, Duration::ZERO, "the first sample is the round trip");
        assert!(
            topology.a.take_events().iter().any(|event| event.event_type == EventType::PeerPathLearned),
            "A reports the learned path"
        );
        assert_eq!(topology.a.best_peer_endpoint(topology.b_identity.address(), now), Some(topology.b_addr));
    }

    #[test]
    fn an_echo_probe_is_acknowledged_and_refreshes_the_path() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        topology.a.send_hello_locked(topology.b_identity.address(), topology.b_addr, now).expect("handshake queued");
        topology.pump(now);
        let before: BTreeSet<u64> = topology.a.pending().iter().map(|(packet_id, _)| packet_id).collect();
        let later = now + Duration::from_secs(20);
        assert!(topology
            .a
            .send_path_probe_locked(topology.b_identity.address(), TEST_SOCKET, topology.b_addr, later, None,)
            .expect("probe sent"));
        let after: BTreeSet<u64> = topology.a.pending().iter().map(|(packet_id, _)| packet_id).collect();
        let probe_ids: Vec<u64> = after.difference(&before).copied().collect();
        assert_eq!(probe_ids.len(), 1, "one ECHO expectation was recorded");
        let echo_id = probe_ids[0];
        topology.pump(later);
        assert!(!topology.a.pending().contains(echo_id), "the ECHO acknowledgement released its expectation");
        let key = PathKey::new(TEST_SOCKET, topology.b_addr);
        let peer = topology.a.peer(topology.b_identity.address()).expect("peer");
        assert!(peer.paths.contains_key(&key), "the probe used the learned path");
        assert_eq!(peer.paths[&key].last_receive, Some(later), "the reply refreshed the path");
        assert_eq!(topology.a.peers(later)[0].paths[0].latency, Duration::ZERO, "the ECHO changed no latency sample");
    }

    #[test]
    fn a_controller_reply_applies_a_network_configuration() {
        let mut topology = Topology::new();
        let controller_identity = Identity::generate();
        let controller = controller_identity.address();
        let network_id = (controller.uint64() << 24) | 0x4321;
        let controller_addr: SocketAddr = "203.0.113.5:9993".parse().expect("endpoint");
        let now = SystemTime::now();
        topology.a_host.learn(&controller_identity);
        install_path(&mut topology.a, controller, controller_addr, now);
        topology.a.join(network_id, now).expect("the network request is sent");
        assert_eq!(topology.a_wire.pending(), 1, "the configuration request left A");
        let request_id = pending_id(&topology.a, Verb::NetworkConfigRequest);

        let raw = append_test_network_config(network_id, topology.a_identity.address());
        const UPDATE_ID: u64 = 0x0102_0304_0506_0708;
        let mut reply = ok_config_chunk(
            &controller_identity,
            topology.a_identity.address(),
            request_id,
            network_id,
            UPDATE_ID,
            &raw,
        );
        let shared = controller_identity.agree(&topology.a_identity).expect("shared key");
        reply.armor(&shared, true).expect("armors as the controller");
        topology
            .a
            .process_wire_packet(ANY_LOCAL_SOCKET, controller_addr, reply.bytes(), now)
            .expect("the configuration is accepted");

        let network = topology.a.network(network_id).expect("network joined");
        assert_eq!(network.status, NetworkStatus::Ok);
        assert_eq!(network.last_config_update_id, UPDATE_ID);
        assert!(topology.a.take_events().iter().any(|event| event.event_type == EventType::NetworkConfigReady));
    }

    #[test]
    fn a_root_rendezvous_advice_is_probed() {
        let host = WireHost::default();
        let wire = host.wire.clone();
        let root_identity = Identity::generate();
        let target_identity = Identity::generate();
        host.learn(&target_identity);
        let mut node = Node::new(Identity::generate(), Box::new(MemoryStore::new()), Box::new(host));
        let now = SystemTime::now();
        set_test_planet(&mut node, &root_identity);
        let root_address = root_identity.address();
        let advised: SocketAddr = "198.51.100.77:4000".parse().expect("endpoint");
        let target_address = target_identity.address();
        let mut packet = Packet::new(node.identity().address(), root_address, Verb::Rendezvous).expect("packet");
        let _ = packet.append_u8(0);
        let _ = packet.append(&target_address.bytes());
        let _ = packet.append_u16(advised.port());
        let _ = packet.append_u8(4);
        let _ = packet.append(&match advised.ip() {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(_) => unreachable!("the test uses an IPv4 advice"),
        });
        node.handle_rendezvous_locked(ANY_LOCAL_SOCKET, root_address, &packet, now).expect("advice accepted");
        let sent = wire.take();
        assert_eq!(sent.len(), 2, "a NAT-opening datagram precedes the probe");
        assert_eq!(sent[0].1.len(), 4, "the NAT-opening datagram is four bytes");
        let probe = Packet::parse(&sent[1].1).expect("parses the probe");
        assert_eq!(probe.destination(), target_address);
        assert_eq!(probe.verb(), Some(Verb::Hello));
    }

    #[test]
    fn a_pushed_direct_path_is_probed_unless_it_is_forgotten() {
        let host = WireHost::default();
        let wire = host.wire.clone();
        let identity = Identity::generate();
        let address = identity.address();
        host.learn(&identity);
        let mut node = Node::new(Identity::generate(), Box::new(MemoryStore::new()), Box::new(host));
        let now = SystemTime::now();
        let known: SocketAddr = "192.0.2.30:9993".parse().expect("endpoint");
        install_path(&mut node, address, known, now);
        let pushed: SocketAddr = "198.51.100.88:4001".parse().expect("endpoint");

        let mut packet = Packet::new(node.identity().address(), address, Verb::PushDirectPaths).expect("packet");
        let _ = packet.append_u16(1);
        append_pushed_direct_path(&mut packet.payload_mut().to_vec(), pushed);
        let mut advertised = Vec::new();
        append_pushed_direct_path(&mut advertised, pushed);
        let mut packet = Packet::new(node.identity().address(), address, Verb::PushDirectPaths).expect("packet");
        let _ = packet.append_u16(1);
        let _ = packet.append(&advertised);
        node.handle_push_direct_paths_locked(ANY_LOCAL_SOCKET, known, address, &packet, now)
            .expect("advertisement accepted");
        let sent = wire.take();
        assert_eq!(sent.len(), 1, "one probe was sent");
        let probe = Packet::parse(&sent[0].1).expect("parses the probe");
        assert_eq!(probe.destination(), address);
        assert_eq!(probe.verb(), Some(Verb::Hello));

        let mut forgotten = Vec::new();
        forgotten.extend_from_slice(&[0x01, 0x00, 0x00]);
        forgotten.push(4);
        forgotten.push(6);
        forgotten.extend_from_slice(&[198, 51, 100, 89]);
        forgotten.extend_from_slice(&4002u16.to_be_bytes());
        let mut packet = Packet::new(node.identity().address(), address, Verb::PushDirectPaths).expect("packet");
        let _ = packet.append_u16(1);
        let _ = packet.append(&forgotten);
        node.handle_push_direct_paths_locked(ANY_LOCAL_SOCKET, known, address, &packet, now)
            .expect("advertisement accepted");
        assert_eq!(wire.pending(), 0, "a forgotten endpoint is not contacted");
    }

    #[test]
    fn a_rendezvous_from_a_non_root_is_ignored() {
        let host = WireHost::default();
        let wire = host.wire.clone();
        let identity = Identity::generate();
        host.learn(&identity);
        let mut node = Node::new(Identity::generate(), Box::new(MemoryStore::new()), Box::new(host));
        let now = SystemTime::now();
        node.add_peer_locked(identity.clone(), false).expect("leaf peer");
        let address = identity.address();
        let mut packet = Packet::new(node.identity().address(), address, Verb::Rendezvous).expect("packet");
        let _ = packet.append_u8(0);
        let _ = packet.append(&address.bytes());
        let _ = packet.append_u16(4000);
        let _ = packet.append_u8(4);
        let _ = packet.append(&[198, 51, 100, 200]);
        node.handle_rendezvous_locked(ANY_LOCAL_SOCKET, address, &packet, now).expect("advice ignored");
        assert_eq!(wire.pending(), 0, "a leaf cannot redirect another peer");
    }

    #[test]
    fn an_unknown_peer_is_queued_and_requested() {
        let host = WireHost::default();
        let wire = host.wire.clone();
        let root_identity = Identity::generate();
        let mut node = Node::new(Identity::generate(), Box::new(MemoryStore::new()), Box::new(host));
        let now = SystemTime::now();
        set_test_planet(&mut node, &root_identity);
        let root_address = root_identity.address();
        let root_endpoint: SocketAddr = "192.0.2.60:9993".parse().expect("endpoint");
        node.add_peer_path_locked(
            root_address,
            PathKey::new(ANY_LOCAL_SOCKET, root_endpoint),
            PeerPathState { last_receive: Some(now), priority: 1, ..Default::default() },
            now,
        );
        let stranger = Identity::generate();
        let stranger_address = stranger.address();
        let stranger_endpoint: SocketAddr = "198.51.100.61:9993".parse().expect("endpoint");
        let mut packet = Packet::new(node.identity().address(), stranger_address, Verb::Echo).expect("packet");
        let key = node.identity().agree(&stranger).expect("shared key");
        packet.armor(&key, false).expect("armors");
        let error = node
            .process_wire_packet(ANY_LOCAL_SOCKET, stranger_endpoint, packet.bytes(), now)
            .expect_err("an unknown peer is reported");
        assert_eq!(error, NodeError::UnknownPeer);
        assert_eq!(node.pending_incoming_count_locked(), 1, "the packet is retained");
        assert!(node.pending_whois.contains_key(&stranger_address), "identity discovery is armed for the unknown peer");
        let sent = wire.take();
        assert_eq!(sent.len(), 1, "a WHOIS request went to the root");
        let mut whois_packet = Packet::parse(&sent[0].1).expect("parses");
        let shared = node.identity().agree(&root_identity).expect("shared key");
        whois_packet.dearmor(&shared).expect("dearmors");
        assert_eq!(whois_packet.verb(), Some(Verb::Whois));
        assert_eq!(&whois_packet.payload()[..5], &stranger_address.bytes());
    }

    #[test]
    fn a_bad_mac_reports_an_authenticated_failure() {
        let host = WireHost::default();
        let identity = Identity::generate();
        let address = identity.address();
        host.learn(&identity);
        let mut node = Node::new(Identity::generate(), Box::new(MemoryStore::new()), Box::new(host));
        let now = SystemTime::now();
        install_path(&mut node, address, "192.0.2.70:9993".parse().expect("endpoint"), now);
        let mut packet = Packet::new(node.identity().address(), address, Verb::Echo).expect("packet");
        packet.armor(&[0u8; 32], false).expect("armors with the wrong key");
        let installed: SocketAddr = "192.0.2.70:9993".parse().expect("endpoint");
        let error = node
            .process_wire_packet(ANY_LOCAL_SOCKET, installed, packet.bytes(), now)
            .expect_err("the MAC does not verify");
        assert_eq!(error, NodeError::InvalidPacket);
        assert_eq!(
            node.peer(address).expect("peer").paths[&PathKey::new(ANY_LOCAL_SOCKET, installed)].packet_error,
            0.015625,
            "an armor failure raises the path's packet-error ratio"
        );
    }

    #[test]
    fn a_fragmented_packet_round_trips_through_reassembly() {
        let host = WireHost::default();
        let wire = host.wire.clone();
        let receiver_identity = Identity::generate();
        let receiver_address = receiver_identity.address();
        host.learn(&receiver_identity);
        let mut sender = Node::new(Identity::generate(), Box::new(MemoryStore::new()), Box::new(host));
        let now = SystemTime::now();
        let path = install_path(&mut sender, receiver_address, "192.0.2.80:9993".parse().expect("endpoint"), now);
        if let Some(peer) = sender.peers.get_mut(&receiver_address) {
            peer.protocol = PROTOCOL_VERSION;
        }
        let payload = vec![7u8; 3000];
        let mut packet = Packet::new(receiver_address, sender.identity().address(), Verb::Echo).expect("packet");
        let _ = packet.append(&payload);
        sender
            .send_packet_via_path_locked(receiver_address, packet, true, path, false)
            .expect("the packet is fragmented");
        let sent = wire.take();
        assert_eq!(sent.len(), 3, "one head and two fragments leave the sender");
        assert!(sent[0].1.len() <= crate::packet::DEFAULT_PHYSICAL_MTU);
        assert_eq!(sent[1].1[13], 0xff, "a fragment carries the fragment marker");
        assert_eq!(sent[1].1[14] >> 4, 3, "the first fragment announces the total");
        assert_eq!(sent[1].1[14] & 0x0f, 1, "the first fragment is number one");
        assert_eq!(sent[2].1[14] & 0x0f, 2, "the second fragment is number two");

        let receiver_host = WireHost::default();
        receiver_host.learn(&sender.identity().clone());
        let receiver_wire = receiver_host.wire.clone();
        let mut receiver = Node::new(receiver_identity, Box::new(MemoryStore::new()), Box::new(receiver_host));
        let source: SocketAddr = "192.0.2.80:9993".parse().expect("endpoint");
        for (index, (local_socket, bytes)) in sent.iter().enumerate() {
            receiver
                .process_wire_packet(*local_socket, source, bytes, now)
                .unwrap_or_else(|error| panic!("fragment {index} rejected: {error}"));
        }
        let replies = receiver_wire.take();
        assert_eq!(replies.len(), 4, "the receiver answers with a fragmented ECHO and a confirming HELLO");
        assert_ne!(replies[0].1[13], 0xff, "the first reply is the fragmented head");
        assert_eq!(replies[1].1[13], 0xff);
        assert_eq!(replies[2].1[13], 0xff);
        let reassembled = reassemble_fragments(&replies[..3]);
        let mut reply = Packet::parse(&reassembled).expect("parses");
        let shared = receiver.identity().agree(&sender.identity().clone()).expect("shared key");
        reply.dearmor(&shared).expect("dearmors the reassembled reply");
        assert_eq!(reply.verb(), Some(Verb::Ok));
        assert_eq!(reply.payload()[0], Verb::Echo.bits());
        assert_eq!(&reply.payload()[9..], payload.as_slice(), "the echo carries the whole payload");
        let mut confirming = Packet::parse(&replies[3].1).expect("parses");
        confirming.dearmor(&shared).expect("dearmors the confirming handshake");
        assert_eq!(
            confirming.verb(),
            Some(Verb::Hello),
            "an authenticated path learned from traffic is confirmed with a full HELLO"
        );
    }

    /// Reassembles one fragmented wire packet from its head and fragments.
    fn reassemble_fragments(datagrams: &[(i64, Vec<u8>)]) -> Vec<u8> {
        let mut assembled = datagrams[0].1.clone();
        for (_, fragment) in &datagrams[1..] {
            assembled.extend_from_slice(&fragment[FRAGMENT_HEADER_SIZE..]);
        }
        assembled
    }

    #[test]
    fn local_direct_paths_are_advertised_to_a_trusted_peer() {
        let host = WireHost::default();
        let wire = host.wire.clone();
        let identity = Identity::generate();
        host.learn(&identity);
        let local_endpoint: SocketAddr = "192.0.2.200:9993".parse().expect("endpoint");
        host.set_direct_paths(vec![local_endpoint]);
        let mut node = Node::new(Identity::generate(), Box::new(MemoryStore::new()), Box::new(host));
        let now = SystemTime::now();
        node.add_peer_locked(identity.clone(), true).expect("root peer");
        let remote: SocketAddr = "198.51.100.90:9993".parse().expect("endpoint");
        let path = PathKey::new(ANY_LOCAL_SOCKET, remote);
        node.add_peer_path_locked(
            identity.address(),
            path,
            PeerPathState { last_receive: Some(now), priority: 1, ..Default::default() },
            now,
        );
        node.maybe_push_direct_paths_locked(identity.address(), path, now, true);
        let sent = wire.take();
        assert_eq!(sent.len(), 1, "one push advertisement is sent");
        let shared = node.identity().agree(&identity).expect("shared key");
        let mut push = Packet::parse(&sent[0].1).expect("parses");
        push.dearmor(&shared).expect("dearmors");
        push.uncompress().expect("uncompresses");
        assert_eq!(push.verb(), Some(Verb::PushDirectPaths));
        let payload = push.payload();
        assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1);
        assert_eq!(payload[2], 0, "the advertisement carries no flags");
        assert_eq!(payload[5], 4, "an IPv4 endpoint is advertised as type 4");
        assert_eq!(payload[6], 6);
        assert_eq!(&payload[7..11], &[192, 0, 2, 200]);
        assert_eq!(u16::from_be_bytes([payload[11], payload[12]]), 9993);
    }

    #[test]
    fn a_stale_pending_request_is_dropped_after_thirty_seconds() {
        let host = WireHost::default();
        let mut node = Node::new(Identity::generate(), Box::new(MemoryStore::new()), Box::new(host));
        let now = SystemTime::now();
        let request = PendingRequest {
            verb: Verb::Whois,
            peer: Address::new(1),
            network_id: 0,
            sent_at: Some(now),
            slot: 0,
            generation: 0,
            path: None,
            priority: 0,
            reply_paths: None,
        };
        node.pending.add(1, request).expect("tracked");
        node.pending.retain_recent(now + Duration::from_secs(29), Duration::from_secs(30));
        assert!(node.pending.contains(1), "a young expectation survives");
        node.pending.retain_recent(now + Duration::from_secs(31), Duration::from_secs(30));
        assert!(!node.pending.contains(1), "a stale expectation is dropped");
    }

    #[test]
    fn a_pushed_configuration_chunk_is_acknowledged_with_an_echo() {
        let mut topology = Topology::new();
        let controller_identity = Identity::generate();
        let controller = controller_identity.address();
        let network_id = (controller.uint64() << 24) | 0x4321;
        let controller_addr: SocketAddr = "203.0.113.6:9993".parse().expect("endpoint");
        let now = SystemTime::now();
        topology.a_host.learn(&controller_identity);
        install_path(&mut topology.a, controller, controller_addr, now);
        topology.a.join(network_id, now).expect("joins");
        let request_id = pending_id(&topology.a, Verb::NetworkConfigRequest);
        let raw = append_test_network_config(network_id, topology.a_identity.address());
        const UPDATE_ID: u64 = 0x0f0e_0d0c_0b0a_0908;
        let mut reply = ok_config_chunk(
            &controller_identity,
            topology.a_identity.address(),
            request_id,
            network_id,
            UPDATE_ID,
            &raw,
        );
        let shared = controller_identity.agree(&topology.a_identity).expect("shared key");
        reply.armor(&shared, true).expect("armors");
        topology
            .a
            .process_wire_packet(ANY_LOCAL_SOCKET, controller_addr, reply.bytes(), now)
            .expect("applies the requested configuration");
        let _ = topology.a_wire.take();

        let mut push =
            Packet::new(topology.a_identity.address(), controller, Verb::NetworkConfig).expect("push packet");
        let _ = push.append(&signed_config_chunk(&controller_identity, network_id, UPDATE_ID + 1, &raw));
        push.armor(&shared, true).expect("armors");
        topology
            .a
            .process_wire_packet(ANY_LOCAL_SOCKET, controller_addr, push.bytes(), now)
            .expect("the pushed chunk is accepted");
        assert_eq!(topology.a.network(network_id).expect("joined").last_config_update_id, UPDATE_ID + 1);
        let sent = topology.a_wire.take();
        assert_eq!(sent.len(), 1, "one acknowledgement is sent");
        let mut ack = Packet::parse(&sent[0].1).expect("parses");
        ack.dearmor(&shared).expect("dearmors");
        assert_eq!(ack.verb(), Some(Verb::Ok));
        assert_eq!(ack.payload()[0], Verb::Echo.bits(), "the push is acknowledged with ECHO");
        assert_eq!(u64::from_be_bytes(ack.payload()[17..25].try_into().expect("eight bytes")), UPDATE_ID + 1);
    }

    #[test]
    fn an_absent_endpoint_operand_leaves_the_position_unchanged() {
        assert_eq!(parse_optional_endpoint(&[], 0), Ok((None, 0)));
        assert_eq!(parse_optional_endpoint(&[0], 1), Ok((None, 1)));
        assert_eq!(
            parse_optional_endpoint(&[4, 192, 0, 2, 1, 0x1f, 0x90], 0),
            Ok((Some("192.0.2.1:8080".parse().expect("endpoint")), 7,))
        );
        assert_eq!(parse_optional_endpoint(&[0], 0), Ok((None, 1)));
        assert_eq!(parse_optional_endpoint(&[4, 192, 0, 2], 0), Err(NodeError::InvalidPacket));
    }

    #[test]
    fn a_hello_ending_at_the_identity_has_no_optional_fields() {
        let mut packet = Packet::new(Address::new(2), Address::new(1), Verb::Hello).expect("packet");
        packet.append(&[0u8; 13]).expect("payload header");
        let position = packet.bytes().len();
        assert_eq!(position, PAYLOAD_OFFSET + 13);
        let key = [0u8; crate::identity::SYMMETRIC_KEY_SIZE];
        let extensions = parse_hello_extensions(&mut packet, &key, position).expect("optional fields absent");
        assert!(extensions.external_surface.is_none());
        assert_eq!((extensions.planet_id, extensions.planet_timestamp), (0, 0));
        assert!(extensions.moons.is_empty());
        assert_eq!(extensions.timestamp, 0);
    }
}

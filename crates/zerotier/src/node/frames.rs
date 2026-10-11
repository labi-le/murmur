//! The virtual frame plane: outbound frame submission, inbound `FRAME` and
//! `EXT_FRAME` admission, and the seam that hands delivered frames to the
//! embedding.
//!
//! A frame crossing the wire is armored by the packet plane; this module owns
//! what happens on either side of it. Delivery is queued in
//! [`Node::delivered_frames`] and drained by the frame callback
//! installed with [`Node::set_frame_callback`] or by
//! [`Node::take_delivered_frames`]; an embedding that does neither accumulates
//! frames. A multicast destination is replicated through
//! [`crate::node::multicast`].

use std::time::SystemTime;

use rand::Rng;

use crate::address::{controller, Address};
use crate::bonding::frame_flow_id;
use crate::frame::{build_native_packet, Frame};
use crate::mac::{address_for_mac, first_mac_octet, mac_for_address, Mac};
use crate::membership::CertificateOfMembership;
use crate::network_config::{NetworkConfigData, NetworkType, SPECIALIST_TYPE_ACTIVE_BRIDGE};
use crate::node::handshake::PacketOutcome;
use crate::node::network::{Network, NetworkStatus};
use crate::node::peer::PathKey;
use crate::node::{
    elapsed, BridgeRoute, Node, NodeError, PendingRequest, BRIDGE_ROUTE_EXPIRATION, MAX_BRIDGE_ROUTES, MAX_BRIDGE_SPAM,
    MAX_PENDING_FRAMES, MULTICAST_LIKE_PERIOD, PENDING_TRANSMIT_EXPIRATION, TRUST_EXPIRATION,
};
use crate::packet::{Packet, Verb, MAX_PACKET_SIZE, MIN_PACKET_SIZE};
use crate::rules::{
    rule_forward_flags, rule_forward_payload, rule_redirect_flags, FrameRuleContext, FrameRuleDecision, RuleResult,
    RuleTeeDecision,
};

/// One outbound frame held until its destination peer is discovered.
#[derive(Debug, Clone)]
pub struct PendingOutboundFrame {
    pub frame: Frame,
    pub extended: bool,
    pub extended_flags: u8,
    pub payload_length: usize,
    pub flow_id: i32,
    pub created_at: SystemTime,
}

pub(crate) fn unusable(error: NodeError) -> PacketOutcome {
    PacketOutcome::Authenticated(Box::new(error))
}

/// the bridge-route store: the shuffle keeps one destination from always
/// reaching the same bridge first.
pub(crate) fn shuffle_addresses(addresses: &mut [Address]) {
    let mut rng = rand::rng();
    for index in (1..addresses.len()).rev() {
        addresses.swap(index, rng.random_range(0..=index));
    }
}

/// Reads the eight-byte network ID that prefixes a frame verb payload.
fn frame_network_id(payload: &[u8]) -> Result<u64, PacketOutcome> {
    let header = payload.get(..8).ok_or_else(|| unusable(NodeError::InvalidPacket))?;
    let header: [u8; 8] = header.try_into().map_err(|_| unusable(NodeError::InvalidPacket))?;
    Ok(u64::from_be_bytes(header))
}

/// Appends a two-byte count slot and every entry that still fits, then backfills the count.
fn append_counted_section(
    payload: &mut Vec<u8>,
    entries: &[Vec<u8>],
    at: &mut usize,
    entry_overhead: usize,
    capacity: usize,
) -> Result<bool, NodeError> {
    let count_at = payload.len();
    payload.extend_from_slice(&[0, 0]);
    let start = *at;
    let mut progress = false;
    while let Some(entry) = entries.get(*at) {
        if payload.len() + entry.len() + entry_overhead > capacity {
            break;
        }
        payload.extend_from_slice(entry);
        *at += 1;
        progress = true;
    }
    if *at == start && *at < entries.len() {
        return Err(NodeError::InvalidPacket);
    }
    let count = u16::try_from(*at - start).map_err(|_| NodeError::InvalidPacket)?;
    payload.get_mut(count_at..count_at + 2).ok_or(NodeError::InvalidPacket)?.copy_from_slice(&count.to_be_bytes());
    Ok(progress)
}

/// Parses the bridged Ethernet header and payload that follow the credentials.
fn parse_bridged_frame(body: &[u8], network_id: u64) -> Result<Frame, NodeError> {
    let header = body.get(..14).ok_or(NodeError::InvalidPacket)?;
    let header: [u8; 14] = header.try_into().map_err(|_| NodeError::InvalidPacket)?;
    Ok(Frame {
        network_id,
        source: Mac::from_bytes(&header[6..12]).map_err(|_| NodeError::InvalidPacket)?,
        destination: Mac::from_bytes(&header[..6]).map_err(|_| NodeError::InvalidPacket)?,
        ether_type: u16::from_be_bytes([header[12], header[13]]),
        payload: body.get(14..).unwrap_or_default().to_vec(),
    })
}

impl Node {
    /// Submits one virtual Ethernet frame to a joined network.
    #[expect(clippy::cast_possible_truncation, reason = "a MAC is 48 bits wide, so the shift leaves one octet")]
    pub fn send_frame(
        &mut self,
        network_id: u64,
        destination: Mac,
        ether_type: u16,
        payload: &[u8],
        now: SystemTime,
    ) -> Result<(), NodeError> {
        if self.closed {
            return Err(NodeError::NodeClosed);
        }
        let mtu = match self.networks.get(&network_id) {
            Some(network) if network.status == NetworkStatus::Ok => {
                usize::try_from(network.config.mtu).unwrap_or(usize::MAX)
            }
            _ => return Err(NodeError::NetworkNotReady),
        };
        if payload.is_empty() || payload.len() > mtu {
            return Err(NodeError::InvalidPacket);
        }
        let source = mac_for_address(self.identity.address(), network_id);
        let frame = Frame { network_id, source, destination, ether_type, payload: payload.to_vec() };
        if destination == source {
            self.deliver_frame_locked(frame);
            return Ok(());
        }
        let destination_zt =
            if !destination.is_multicast() && first_mac_octet(network_id) == (destination.uint64() >> 40) as u8 {
                address_for_mac(destination, network_id)
            } else {
                Address::default()
            };
        let flow_id = frame_flow_id(ether_type, payload);
        let decision = self.outbound_frame_decision(network_id, &frame, destination_zt);
        if decision.result != RuleResult::Accept {
            return Err(NodeError::FrameRejected);
        }
        self.send_rule_tees_locked(network_id, &decision, &frame, false, now);
        if !decision.redirect.is_zero() {
            let flags = rule_redirect_flags(false);
            return self.send_rule_frame_with_flow_locked(
                network_id,
                decision.redirect,
                &frame,
                flags,
                0,
                flow_id,
                now,
            );
        }
        if destination.is_multicast() {
            return self.send_multicast_locked(network_id, &frame, now);
        }
        if first_mac_octet(network_id) != (destination.uint64() >> 40) as u8 {
            return self.send_bridged_frame_locked(network_id, &frame, now);
        }
        self.queue_or_send_frame_locked(network_id, address_for_mac(destination, network_id), &frame, flow_id, now)
    }

    /// Routes a frame whose MAC destination is not a native node mapping to the
    /// bridges that could own it.
    fn send_bridged_frame_locked(&mut self, network_id: u64, frame: &Frame, now: SystemTime) -> Result<(), NodeError> {
        let local = self.identity.address();
        let mut bridges = Vec::new();
        let learned = self.networks.get(&network_id).and_then(|network| {
            network.bridge_routes.get(&frame.destination).and_then(|route| {
                let fresh = elapsed(now, route.learned) < BRIDGE_ROUTE_EXPIRATION;
                let owns_mac = network.config.is_specialist(route.bridge, SPECIALIST_TYPE_ACTIVE_BRIDGE);
                (fresh && owns_mac && route.bridge != local).then_some(route.bridge)
            })
        });
        if let Some(bridge) = learned {
            bridges.push(bridge);
        } else {
            if let Some(network) = self.networks.get_mut(&network_id) {
                network.bridge_routes.remove(&frame.destination);
            }
            let Some(network) = self.networks.get(&network_id) else {
                return Err(NodeError::NetworkNotFound);
            };
            let mut candidates = network.config.specialist_addresses(SPECIALIST_TYPE_ACTIVE_BRIDGE);
            candidates.retain(|bridge| *bridge != local);
            shuffle_addresses(&mut candidates);
            candidates.truncate(MAX_BRIDGE_SPAM);
            bridges = candidates;
        }
        if bridges.is_empty() {
            return Err(NodeError::UnsupportedEthernet);
        }
        let flow_id = frame_flow_id(frame.ether_type, &frame.payload);
        let mut result = None;
        for bridge in bridges {
            match self.filter_replicated_outbound_locked(network_id, bridge, frame, now) {
                Err(error) => {
                    result.get_or_insert(error);
                }
                Ok(false) => {}
                Ok(true) => {
                    if let Err(error) =
                        self.send_rule_frame_with_flow_locked(network_id, bridge, frame, 0, 0, flow_id, now)
                    {
                        result.get_or_insert(error);
                    }
                }
            }
        }
        match result {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Sends a frame to one discovered destination, or defers it until
    /// discovery completes.
    fn queue_or_send_frame_locked(
        &mut self,
        network_id: u64,
        destination: Address,
        frame: &Frame,
        flow_id: i32,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        if self.load_peer_cache_locked(destination, now).is_none() {
            self.enqueue_pending_frame_locked(
                destination,
                PendingOutboundFrame {
                    frame: frame.clone(),
                    extended: false,
                    extended_flags: 0,
                    payload_length: 0,
                    flow_id,
                    created_at: now,
                },
            );
            self.request_whois_locked(destination, now);
            return Ok(());
        }
        self.send_credentials_locked(network_id, destination, now)?;
        let packet =
            build_native_packet(frame, destination, self.identity.address()).map_err(|_| NodeError::InvalidPacket)?;
        self.send_packet_with_flow_locked(destination, packet, true, flow_id)
    }

    /// Sends a rule-generated tee, watch, or redirect frame.
    fn send_rule_frame_with_flow_locked(
        &mut self,
        network_id: u64,
        destination: Address,
        frame: &Frame,
        flags: u8,
        payload_length: usize,
        flow_id: i32,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        if self.load_peer_cache_locked(destination, now).is_none() {
            self.enqueue_pending_frame_locked(
                destination,
                PendingOutboundFrame {
                    frame: frame.clone(),
                    extended: true,
                    extended_flags: flags,
                    payload_length,
                    flow_id,
                    created_at: now,
                },
            );
            self.request_whois_locked(destination, now);
            return Ok(());
        }
        self.send_credentials_locked(network_id, destination, now)?;
        let body = rule_forward_payload(frame, flags, payload_length);
        let mut packet =
            Packet::with_payload_capacity(destination, self.identity.address(), Verb::ExtFrame, body.len())
                .map_err(|_| NodeError::InvalidPacket)?;
        packet.append(&body).map_err(|_| NodeError::InvalidPacket)?;
        let packet_id = packet.packet_id();
        if flags & 0x10 != 0 {
            self.add_pending_locked(
                packet_id,
                PendingRequest {
                    verb: Verb::ExtFrame,
                    peer: destination,
                    network_id,
                    sent_at: Some(now),
                    slot: 0,
                    generation: 0,
                    path: None,
                    priority: 0,
                    reply_paths: None,
                },
            )?;
        }
        if let Err(error) = self.send_packet_with_flow_locked(destination, packet, true, flow_id) {
            self.delete_pending_locked(packet_id);
            return Err(error);
        }
        Ok(())
    }

    /// Sends the network's currently valid credentials to `address`.
    pub fn send_credentials_locked(
        &mut self,
        network_id: u64,
        address: Address,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        let Some(network) = self.networks.get(&network_id) else {
            return Ok(());
        };
        let config = &network.config;
        let ungoverned = config.ownership.is_empty() && config.tags.is_empty() && config.capabilities.is_empty();
        if config.network_type == NetworkType::PUBLIC && ungoverned {
            return Ok(());
        }
        if config.network_type != NetworkType::PUBLIC && config.com.is_none() {
            return Err(NodeError::NetworkNotReady);
        }
        let recently_sent = self
            .peers
            .get(&address)
            .and_then(|peer| peer.credentials_sent.get(&network_id).copied())
            .is_some_and(|sent| elapsed(now, sent) < MULTICAST_LIKE_PERIOD);
        if recently_sent {
            return Ok(());
        }
        let com = config.com.as_ref().map(|certificate| certificate.bytes().to_vec());
        let capabilities = config
            .capabilities
            .iter()
            .map(|capability| capability.append_binary(Vec::new()).map_err(|_| NodeError::InvalidPacket))
            .collect::<Result<Vec<_>, _>>()?;
        let tags: Vec<Vec<u8>> = config.tags.iter().map(|tag| tag.bytes().to_vec()).collect();
        let ownership = config
            .ownership
            .iter()
            .map(|certificate| certificate.append_binary(Vec::new()).map_err(|_| NodeError::InvalidPacket))
            .collect::<Result<Vec<_>, _>>()?;
        let capacity = MAX_PACKET_SIZE - MIN_PACKET_SIZE;
        let mut send_com = com.is_some();
        let (mut capability_at, mut tag_at, mut ownership_at) = (0usize, 0usize, 0usize);
        while send_com || capability_at < capabilities.len() || tag_at < tags.len() || ownership_at < ownership.len() {
            let mut payload: Vec<u8> = Vec::with_capacity(capacity);
            let mut progress = if send_com {
                let raw = com.as_deref().unwrap_or_default();
                if raw.len() + 7 > capacity {
                    return Err(NodeError::InvalidPacket);
                }
                payload.extend_from_slice(raw);
                send_com = false;
                true
            } else {
                false
            };
            payload.push(0);
            progress |= append_counted_section(&mut payload, &capabilities, &mut capability_at, 6, capacity)?;

            progress |= append_counted_section(&mut payload, &tags, &mut tag_at, 4, capacity)?;
            payload.extend_from_slice(&[0, 0]);

            progress |= append_counted_section(&mut payload, &ownership, &mut ownership_at, 0, capacity)?;
            if !progress {
                return Err(NodeError::InvalidPacket);
            }
            let mut packet = Packet::new(address, self.identity.address(), Verb::NetworkCredentials)
                .map_err(|_| NodeError::InvalidPacket)?;
            packet.append(&payload).map_err(|_| NodeError::InvalidPacket)?;
            packet.compress().map_err(|_| NodeError::InvalidPacket)?;
            self.send_packet_locked(address, packet, true)?;
        }
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.credentials_sent.insert(network_id, now);
        }
        Ok(())
    }

    /// Validates and delivers one native virtual Ethernet frame.
    pub(crate) fn handle_frame_locked(
        &mut self,
        path: PathKey,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let payload = packet.payload();
        if payload.len() < 8 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let network_id = frame_network_id(payload)?;
        let source = packet.source();
        if !self.networks.contains_key(&network_id) || !self.peers.contains_key(&source) {
            return Ok(());
        }
        if !self.network_allows_peer_locked(network_id, source) {
            let _ = self.send_need_credentials_locked(source, path, packet, network_id);
            return Err(PacketOutcome::Retry);
        }
        self.mark_network_trust_locked(network_id, source, now);
        let decoded = Frame::decode_native(payload, self.identity.address(), source)
            .map_err(|_| unusable(NodeError::InvalidPacket))?;
        let Some(frame) = decoded else {
            return Ok(());
        };
        let decision = self.inbound_frame_decision(network_id, &frame, source);
        if decision.result != RuleResult::Accept {
            return Ok(());
        }
        if !self.apply_inbound_rule_effects_locked(network_id, &decision, &frame, now) {
            return Ok(());
        }
        self.deliver_frame_locked(frame);
        Ok(())
    }

    /// Validates and delivers one bridged Ethernet frame.
    pub(crate) fn handle_ext_frame_locked(
        &mut self,
        path: PathKey,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let payload = packet.payload();
        if payload.len() < 8 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let network_id = frame_network_id(payload)?;
        let source = packet.source();
        if !self.networks.contains_key(&network_id) || !self.peers.contains_key(&source) {
            return Ok(());
        }
        if payload.len() < 9 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let Some(flags) = payload.get(8).copied() else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let mut position = 9;
        if flags & 0x01 != 0 {
            let Some(remainder) = payload.get(position..) else {
                return Err(unusable(NodeError::InvalidPacket));
            };
            let Ok((certificate, consumed)) = CertificateOfMembership::parse(remainder) else {
                return Err(unusable(NodeError::InvalidPacket));
            };
            position += consumed;
            let _ = self.add_membership_locked(network_id, &certificate);
        }
        if !self.network_allows_peer_locked(network_id, source) {
            let _ = self.send_need_credentials_locked(source, path, packet, network_id);
            return Err(PacketOutcome::Retry);
        }
        if payload.len() - position < 14 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        self.mark_network_trust_locked(network_id, source, now);
        if payload.len() - position == 14 {
            if flags & 0x10 != 0 {
                let _ = self.send_ext_frame_ack_locked(source, path, packet.packet_id(), network_id);
            }
            return Ok(());
        }
        let body = payload.get(position..).ok_or_else(|| unusable(NodeError::InvalidPacket))?;
        let frame = parse_bridged_frame(body, network_id).map_err(unusable)?;
        if !frame.is_deliverable(self.identity.address(), network_id) {
            return Ok(());
        }
        let decision = self.inbound_frame_decision(network_id, &frame, source);
        if decision.result != RuleResult::Accept {
            if flags & 0x10 != 0 {
                let _ = self.send_ext_frame_ack_locked(source, path, packet.packet_id(), network_id);
            }
            return Ok(());
        }
        if !decision.super_accept {
            let Some((peer_is_bridge, local_is_bridge, multicast_limit)) =
                self.networks.get(&network_id).map(|network| {
                    (
                        network.config.is_specialist(source, SPECIALIST_TYPE_ACTIVE_BRIDGE),
                        network.config.is_specialist(self.identity.address(), SPECIALIST_TYPE_ACTIVE_BRIDGE),
                        network.config.multicast_limit,
                    )
                })
            else {
                return Ok(());
            };
            let peer_mac = mac_for_address(source, network_id);
            if frame.source != peer_mac && !peer_is_bridge {
                return Ok(());
            }
            if frame.source != peer_mac {
                self.learn_bridge_route_locked(network_id, frame.source, source, now);
            }
            let local_mac = mac_for_address(self.identity.address(), network_id);
            if frame.destination != local_mac && !frame.destination.is_multicast() && !local_is_bridge {
                return Ok(());
            }
            if frame.destination.is_multicast() && multicast_limit == 0 {
                return Ok(());
            }
        }
        if !self.apply_inbound_rule_effects_locked(network_id, &decision, &frame, now) {
            if flags & 0x10 != 0 {
                let _ = self.send_ext_frame_ack_locked(source, path, packet.packet_id(), network_id);
            }
            return Ok(());
        }
        self.deliver_frame_locked(frame);
        if flags & 0x10 != 0 {
            let _ = self.send_ext_frame_ack_locked(source, path, packet.packet_id(), network_id);
        }
        Ok(())
    }

    /// Emits inbound tees and applies redirection.
    pub(crate) fn apply_inbound_rule_effects_locked(
        &mut self,
        network_id: u64,
        decision: &FrameRuleDecision,
        frame: &Frame,
        now: SystemTime,
    ) -> bool {
        self.send_rule_tees_locked(network_id, decision, frame, true, now);
        if !decision.redirect.is_zero() {
            let flags = rule_redirect_flags(true);
            let flow_id = frame_flow_id(frame.ether_type, &frame.payload);
            let _ = self.send_rule_frame_with_flow_locked(network_id, decision.redirect, frame, flags, 0, flow_id, now);
            return false;
        }
        true
    }

    /// Emits every tee and watch copy the decision asked for.
    fn send_rule_tees_locked(
        &mut self,
        network_id: u64,
        decision: &FrameRuleDecision,
        frame: &Frame,
        inbound: bool,
        now: SystemTime,
    ) {
        let mut tees = decision.additional_tee.clone();
        if !decision.tee.is_zero() {
            tees.insert(
                0,
                RuleTeeDecision { target: decision.tee, length: decision.tee_length, watch: decision.watch },
            );
        }
        let flow_id = frame_flow_id(frame.ether_type, &frame.payload);
        for tee in tees {
            let flags = rule_forward_flags(inbound, tee.watch);
            let _ =
                self.send_rule_frame_with_flow_locked(network_id, tee.target, frame, flags, tee.length, flow_id, now);
        }
    }

    /// Acknowledges a bridged frame that asked for a receipt.
    fn send_ext_frame_ack_locked(
        &mut self,
        address: Address,
        path: PathKey,
        packet_id: u64,
        network_id: u64,
    ) -> Result<(), NodeError> {
        let mut reply =
            Packet::new(address, self.identity.address(), Verb::Ok).map_err(|_| NodeError::InvalidPacket)?;
        let _ = reply.append_u8(Verb::ExtFrame.bits());
        let _ = reply.append_u64(packet_id);
        let _ = reply.append_u64(network_id);
        self.send_packet_via_path_locked(address, reply, true, path, false)
    }

    /// Reports the credentials a frame needs before it can be processed.
    pub(crate) fn send_need_credentials_locked(
        &mut self,
        address: Address,
        path: PathKey,
        request: &Packet,
        network_id: u64,
    ) -> Result<(), NodeError> {
        let mut packet =
            Packet::new(address, self.identity.address(), Verb::Error).map_err(|_| NodeError::InvalidPacket)?;
        let _ = packet.append_u8(request.verb().map(Verb::bits).unwrap_or_default());
        let _ = packet.append_u64(request.packet_id());
        let _ = packet.append_u8(0x06);
        let _ = packet.append_u64(network_id);
        self.send_packet_via_path_locked(address, packet, true, path, false)
    }

    /// Validates and installs one membership certificate.
    pub fn add_membership_locked(
        &mut self,
        network_id: u64,
        certificate: &CertificateOfMembership,
    ) -> Result<(), NodeError> {
        let Some(controller_peer) = self.peers.get(&controller(network_id)) else {
            return Err(NodeError::UnknownPeer);
        };
        let target = certificate.issued_to();
        if certificate.network_id() != network_id || target.is_zero() || !certificate.verify(&controller_peer.identity)
        {
            return Err(NodeError::InvalidPacket);
        }
        let stale = self
            .networks
            .get(&network_id)
            .and_then(|network| network.members.get(&target))
            .is_some_and(|existing| certificate.timestamp() < existing.timestamp());
        if stale {
            return Err(NodeError::InvalidPacket);
        }
        if let Some(network) = self.networks.get_mut(&network_id) {
            network.members.insert(target, certificate.clone());
        }
        Ok(())
    }

    /// Reports whether `address` has valid membership in `network_id`.
    #[must_use]
    pub fn network_allows_peer_locked(&self, network_id: u64, address: Address) -> bool {
        let Some(network) = self.networks.get(&network_id) else {
            return false;
        };
        network_allows(&network.config, network, address, self.peers.get(&address))
    }

    /// Refreshes peer trust after valid network credentials.
    pub fn mark_network_trust_locked(&mut self, network_id: u64, address: Address, now: SystemTime) {
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.last_trust_established = Some(now);
        }
        let newly_associated = self
            .networks
            .get(&network_id)
            .and_then(|network| network.associated.get(&address).copied())
            .is_none_or(|associated| elapsed(now, associated) >= TRUST_EXPIRATION);
        if let Some(network) = self.networks.get_mut(&network_id) {
            network.associated.insert(address, now);
            if newly_associated {
                network.multicast_announcements.remove(&address);
            }
        }
        if newly_associated {
            let groups = self.subscribed_multicast_groups_locked(network_id);
            self.announce_multicast_to_peer_locked(network_id, address, &groups, now);
        }
    }

    /// Queues an inbound frame for the embedding.
    pub fn deliver_frame_locked(&mut self, frame: Frame) {
        self.delivered_frames.push(frame);
    }

    /// The deferred unicast frames awaiting peer discovery.
    pub fn pending_frames_count_locked(&self) -> usize {
        self.pending_frames.values().map(Vec::len).sum()
    }

    /// Retains one frame for peer discovery, evicting the oldest at capacity so
    /// discovery pressure stays packet loss.
    pub fn enqueue_pending_frame_locked(&mut self, destination: Address, pending: PendingOutboundFrame) {
        if self.pending_frames_count_locked() >= MAX_PENDING_FRAMES {
            let mut oldest: Option<(Address, usize, SystemTime)> = None;
            for (address, frames) in &self.pending_frames {
                for (index, frame) in frames.iter().enumerate() {
                    let replace = match oldest {
                        None => true,
                        Some((oldest_address, oldest_index, oldest_at)) => {
                            frame.created_at < oldest_at
                                || (frame.created_at == oldest_at
                                    && (*address < oldest_address
                                        || (*address == oldest_address && index < oldest_index)))
                        }
                    };
                    if replace {
                        oldest = Some((*address, index, frame.created_at));
                    }
                }
            }
            if let Some((address, index, _)) = oldest {
                if let Some(frames) = self.pending_frames.get_mut(&address) {
                    frames.remove(index);
                    if frames.is_empty() {
                        self.pending_frames.remove(&address);
                    }
                }
            }
        }
        self.pending_frames.entry(destination).or_default().push(pending);
    }

    /// Sends the frames that were waiting for a newly published peer.
    pub fn flush_pending_frames_locked(&mut self, address: Address, now: SystemTime) {
        let frames = self.pending_frames.remove(&address).unwrap_or_default();
        for pending in frames {
            if elapsed(now, pending.created_at) > PENDING_TRANSMIT_EXPIRATION {
                continue;
            }
            let ready =
                self.networks.get(&pending.frame.network_id).is_some_and(|network| network.status == NetworkStatus::Ok);
            if !ready {
                continue;
            }
            if pending.extended {
                let _ = self.send_rule_frame_with_flow_locked(
                    pending.frame.network_id,
                    address,
                    &pending.frame,
                    pending.extended_flags,
                    pending.payload_length,
                    pending.flow_id,
                    now,
                );
            } else {
                let _ = self.queue_or_send_frame_locked(
                    pending.frame.network_id,
                    address,
                    &pending.frame,
                    pending.flow_id,
                    now,
                );
            }
        }
    }

    /// Drops deferred frames older than the transmit lifetime.
    pub fn expire_pending_frames_locked(&mut self, now: SystemTime) {
        self.pending_frames.retain(|_, frames| {
            frames.retain(|frame| elapsed(now, frame.created_at) <= PENDING_TRANSMIT_EXPIRATION);
            !frames.is_empty()
        });
    }

    /// Records the bridge last seen sourcing `mac`.
    pub fn learn_bridge_route_locked(&mut self, network_id: u64, mac: Mac, bridge: Address, now: SystemTime) {
        let Some(network) = self.networks.get_mut(&network_id) else {
            return;
        };
        if mac.uint64() == 0
            || mac.is_multicast()
            || !network.config.is_specialist(bridge, SPECIALIST_TYPE_ACTIVE_BRIDGE)
        {
            return;
        }
        if !network.bridge_routes.contains_key(&mac) && network.bridge_routes.len() >= MAX_BRIDGE_ROUTES {
            if let Some(candidate) = network.bridge_routes.keys().next().copied() {
                network.bridge_routes.remove(&candidate);
            }
        }
        network.bridge_routes.insert(mac, BridgeRoute { bridge, learned: now });
    }

    /// Drops learned bridge routes whose bridge is no longer a specialist.
    pub fn expire_bridge_routes_locked(&mut self, now: SystemTime) {
        for network in self.networks.values_mut() {
            let Network { config, bridge_routes, .. } = network;
            bridge_routes.retain(|_, route| {
                elapsed(now, route.learned) < BRIDGE_ROUTE_EXPIRATION
                    && config.is_specialist(route.bridge, SPECIALIST_TYPE_ACTIVE_BRIDGE)
            });
        }
    }

    fn outbound_frame_decision(&self, network_id: u64, frame: &Frame, destination_zt: Address) -> FrameRuleDecision {
        let Some(network) = self.networks.get(&network_id) else {
            return FrameRuleDecision::default();
        };
        let config = &network.config;
        config.filter_frame(
            frame,
            FrameRuleContext {
                inbound: false,
                trace_rules: false,
                source_zt: self.identity.address(),
                destination_zt,
                ownership: config.ownership.clone(),
                local_tags: config.tags.clone(),
                remote_tags: network.tags.get(&destination_zt).cloned().unwrap_or_default(),
                capabilities: config.capabilities.clone(),
                super_accept: false,
            },
        )
    }

    pub(crate) fn inbound_frame_decision(&self, network_id: u64, frame: &Frame, peer: Address) -> FrameRuleDecision {
        let Some(network) = self.networks.get(&network_id) else {
            return FrameRuleDecision::default();
        };
        network.config.filter_frame(
            frame,
            FrameRuleContext {
                inbound: true,
                trace_rules: false,
                source_zt: peer,
                destination_zt: self.identity.address(),
                ownership: network.ownership.get(&peer).cloned().unwrap_or_default(),
                local_tags: network.config.tags.clone(),
                remote_tags: network.tags.get(&peer).cloned().unwrap_or_default(),
                capabilities: network.capabilities.get(&peer).cloned().unwrap_or_default(),
                super_accept: false,
            },
        )
    }

    /// Applies outbound rules to one replicated copy of a frame.
    pub(crate) fn filter_replicated_outbound_locked(
        &mut self,
        network_id: u64,
        destination: Address,
        frame: &Frame,
        now: SystemTime,
    ) -> Result<bool, NodeError> {
        let decision = {
            let Some(network) = self.networks.get(&network_id) else {
                return Ok(false);
            };
            let config = &network.config;
            config.filter_frame(
                frame,
                FrameRuleContext {
                    inbound: false,
                    trace_rules: false,
                    source_zt: self.identity.address(),
                    destination_zt: destination,
                    ownership: config.ownership.clone(),
                    local_tags: config.tags.clone(),
                    remote_tags: network.tags.get(&destination).cloned().unwrap_or_default(),
                    capabilities: config.capabilities.clone(),
                    super_accept: false,
                },
            )
        };
        if decision.result != RuleResult::Accept {
            return Ok(false);
        }
        if !decision.redirect.is_zero() {
            let flags = rule_redirect_flags(false);
            let flow_id = frame_flow_id(frame.ether_type, &frame.payload);
            return self
                .send_rule_frame_with_flow_locked(network_id, decision.redirect, frame, flags, 0, flow_id, now)
                .map(|()| false);
        }
        Ok(true)
    }
}

fn network_allows(
    config: &NetworkConfigData,
    network: &Network,
    address: Address,
    peer: Option<&crate::node::Peer>,
) -> bool {
    if config.network_type == NetworkType::PUBLIC {
        return true;
    }
    let Some(certificate) = network.members.get(&address) else {
        return false;
    };
    let (Some(peer), Some(com)) = (peer, config.com.as_ref()) else {
        return false;
    };
    // the credential-revoked term is absent: revocations arrive with the
    // credentials verb, which this crate does not implement.
    com.agrees_with_public_key_hash(certificate, &peer.public_key_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{MulticastGroup, ETHER_TYPE_ARP, ETHER_TYPE_IPV4};
    use crate::identity::Identity;
    use crate::node::peer::PeerPathState;
    use crate::node::store::MemoryStore;
    use crate::node::{NodeHost, ANY_LOCAL_SOCKET};
    use crate::rules::{NetworkRule, RULE_ACTION_ACCEPT, RULE_ACTION_DROP, RULE_MATCH_ETHER_TYPE};
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    const TEST_SOCKET: i64 = 7;
    /// An ad-hoc network whose synthesized configuration accepts every frame.
    const NETWORK_ID: u64 = 0xff00_0000_0000_0001;
    const A_ENDPOINT: &str = "192.0.2.10:9991";
    const B_ENDPOINT: &str = "198.51.100.20:9992";

    #[derive(Clone, Default)]
    struct Wire {
        queue: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Wire {
        fn take(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.queue.lock().expect("lock"))
        }

        fn pending(&self) -> usize {
            self.queue.lock().expect("lock").len()
        }
    }

    struct TestHost {
        wire: Wire,
        peers: Mutex<BTreeMap<Address, Identity>>,
        whois: Mutex<Vec<Address>>,
    }

    impl NodeHost for TestHost {
        fn peer_identity(&self, address: Address) -> Option<Identity> {
            self.peers.lock().expect("lock").get(&address).cloned()
        }

        fn send_wire(&mut self, _local_socket: i64, _remote: SocketAddr, packet: Vec<u8>) -> Result<(), NodeError> {
            self.wire.queue.lock().expect("lock").push(packet);
            Ok(())
        }

        fn request_whois(&mut self, address: Address) {
            self.whois.lock().expect("lock").push(address);
        }

        fn announce_multicast(&mut self, _network_id: u64) {}

        fn trace_network_config_request(&mut self, _network_id: u64, _controller: Address) {}
    }

    struct Topology {
        a: Node,
        b: Node,
        a_wire: Wire,
        b_wire: Wire,
        a_addr: SocketAddr,
        b_addr: SocketAddr,
        a_identity: Identity,
        b_identity: Identity,
    }

    impl Topology {
        fn new() -> Self {
            let a_identity = Identity::generate();
            let b_identity = Identity::generate();
            let a_addr: SocketAddr = A_ENDPOINT.parse().expect("endpoint");
            let b_addr: SocketAddr = B_ENDPOINT.parse().expect("endpoint");
            let a_wire = Wire::default();
            let b_wire = Wire::default();
            let mut a = Node::new(
                a_identity.clone(),
                Box::new(MemoryStore::new()),
                Box::new(TestHost {
                    wire: a_wire.clone(),
                    peers: Mutex::new(BTreeMap::from([(b_identity.address(), b_identity.clone())])),
                    whois: Mutex::new(Vec::new()),
                }),
            );
            let mut b = Node::new(
                b_identity.clone(),
                Box::new(MemoryStore::new()),
                Box::new(TestHost {
                    wire: b_wire.clone(),
                    peers: Mutex::new(BTreeMap::from([(a_identity.address(), a_identity.clone())])),
                    whois: Mutex::new(Vec::new()),
                }),
            );
            let now = SystemTime::now();
            a.join(NETWORK_ID, now).expect("A joins the ad-hoc network");
            b.join(NETWORK_ID, now).expect("B joins the ad-hoc network");
            assert_eq!(a.network(NETWORK_ID).map(|network| network.status), Some(NetworkStatus::Ok));
            assert_eq!(b.network(NETWORK_ID).map(|network| network.status), Some(NetworkStatus::Ok));
            install_path(&mut a, b_identity.address(), b_addr, now);
            install_path(&mut b, a_identity.address(), a_addr, now);
            Self { a, b, a_wire, b_wire, a_addr, b_addr, a_identity, b_identity }
        }

        /// Delivers every queued datagram to the other node until both wires
        /// settle, so a reply that provokes a reply is also carried.
        fn pump(&mut self, now: SystemTime) {
            for _ in 0..8 {
                let mut moved = false;
                for bytes in self.a_wire.take() {
                    moved = true;
                    self.b
                        .process_wire_packet(TEST_SOCKET, self.a_addr, &bytes, now)
                        .expect("B accepts a datagram from A");
                }
                for bytes in self.b_wire.take() {
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
    fn install_path(node: &mut Node, address: Address, endpoint: SocketAddr, now: SystemTime) {
        node.load_peer_cache_locked(address, now).expect("peer identity is cached");
        node.add_peer_path_locked(
            address,
            PathKey::new(TEST_SOCKET, endpoint),
            PeerPathState { last_receive: Some(now), last_probe: Some(now), priority: 1, ..Default::default() },
            now,
        );
    }

    /// An accept-only rule set, so a test can isolate one rule evaluation.
    fn rules(rule_type: u8, value: &[u8]) -> Vec<NetworkRule> {
        vec![
            NetworkRule { rule_type, value: value.to_vec() },
            NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
            NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() },
        ]
    }

    fn set_rules(node: &mut Node, rules: Vec<NetworkRule>) {
        node.networks.get_mut(&NETWORK_ID).expect("network joined").config.rules = rules;
    }

    fn payload() -> Vec<u8> {
        (0u8..96).map(|index| index.wrapping_mul(11)).collect()
    }

    /// The IPv4 address an ad-hoc network assigns this node.
    fn managed_ipv4(node: &Node, network_id: u64) -> [u8; 4] {
        node.network(network_id)
            .expect("network joined")
            .config
            .assigned
            .iter()
            .find_map(|prefix| match prefix.addr() {
                std::net::IpAddr::V4(address) => Some(address.octets()),
                std::net::IpAddr::V6(_) => None,
            })
            .expect("an ad-hoc network assigns an IPv4 address")
    }

    /// A 28-byte ARP request whose target address is the group's ADI.
    fn arp_request(source: Address, network_id: u64, requester: [u8; 4], target: [u8; 4]) -> Vec<u8> {
        let mut payload = vec![0u8; 28];
        payload[0..2].copy_from_slice(&1u16.to_be_bytes());
        payload[2..4].copy_from_slice(&ETHER_TYPE_IPV4.to_be_bytes());
        payload[4] = 6;
        payload[5] = 4;
        payload[6..8].copy_from_slice(&1u16.to_be_bytes());
        payload[8..14].copy_from_slice(&mac_for_address(source, network_id).bytes());
        payload[14..18].copy_from_slice(&requester);
        payload[24..28].copy_from_slice(&target);
        payload
    }

    #[test]
    fn a_sent_frame_reaches_the_peer_delivery_seam() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        let payload = payload();
        let destination = mac_for_address(topology.b_identity.address(), NETWORK_ID);
        topology
            .a
            .send_frame(NETWORK_ID, destination, ETHER_TYPE_IPV4, &payload, now)
            .expect("the local rules accept the frame");
        assert_eq!(topology.a_wire.pending(), 1, "one FRAME datagram leaves A");

        topology.pump(now);

        let frames = topology.b.take_delivered_frames();
        assert_eq!(frames.len(), 1, "B delivered exactly one frame");
        assert_eq!(frames[0].network_id, NETWORK_ID);
        assert_eq!(frames[0].source, mac_for_address(topology.a_identity.address(), NETWORK_ID));
        assert_eq!(frames[0].destination, destination);
        assert_eq!(frames[0].ether_type, ETHER_TYPE_IPV4);
        assert_eq!(frames[0].payload, payload, "the payload survives the wire intact");
        assert_eq!(topology.b.pending_frames_count_locked(), 0, "nothing stayed deferred");
    }

    #[test]
    fn a_compressed_frame_packet_is_delivered_after_decompression() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        let frame = Frame {
            network_id: NETWORK_ID,
            source: mac_for_address(topology.a_identity.address(), NETWORK_ID),
            destination: mac_for_address(topology.b_identity.address(), NETWORK_ID),
            ether_type: ETHER_TYPE_IPV4,
            payload: vec![0x45; 160],
        };
        let mut packet = build_native_packet(&frame, topology.b_identity.address(), topology.a_identity.address())
            .expect("a FRAME packet is built");
        packet.compress().expect("the payload compresses");
        assert!(packet.compressed(), "the wire form carries the compression flag");
        topology
            .a
            .send_packet_locked(topology.b_identity.address(), packet, true)
            .expect("the armored packet is queued");

        topology.pump(now);

        let frames = topology.b.take_delivered_frames();
        assert_eq!(frames.len(), 1, "the compressed verb payload is expanded before dispatch");
        assert_eq!(frames[0], frame);
    }

    #[test]
    fn a_frame_the_receiving_rules_drop_is_not_delivered() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        set_rules(&mut topology.b, rules(RULE_MATCH_ETHER_TYPE, &ETHER_TYPE_ARP.to_be_bytes()));
        let destination = mac_for_address(topology.b_identity.address(), NETWORK_ID);
        topology
            .a
            .send_frame(NETWORK_ID, destination, ETHER_TYPE_IPV4, &payload(), now)
            .expect("A's own rules accept the frame");
        assert_eq!(topology.a_wire.pending(), 1, "the frame still reaches the wire");

        topology.pump(now);

        assert!(topology.b.take_delivered_frames().is_empty(), "B's rules admit only ARP frames");
    }

    #[test]
    fn a_frame_the_sending_rules_reject_is_refused() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        set_rules(&mut topology.a, rules(RULE_MATCH_ETHER_TYPE, &ETHER_TYPE_ARP.to_be_bytes()));
        let destination = mac_for_address(topology.b_identity.address(), NETWORK_ID);
        let error = topology
            .a
            .send_frame(NETWORK_ID, destination, ETHER_TYPE_IPV4, &payload(), now)
            .expect_err("A's rules admit only ARP frames");
        assert_eq!(error, NodeError::FrameRejected);
        assert_eq!(topology.a_wire.pending(), 0, "a rejected frame never reaches the wire");
    }

    #[test]
    fn a_frame_larger_than_the_network_mtu_is_rejected() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        let mtu = topology.a.network(NETWORK_ID).expect("network joined").config.mtu as usize;
        let oversized = vec![0u8; mtu + 1];
        let destination = mac_for_address(topology.b_identity.address(), NETWORK_ID);
        assert_eq!(
            topology.a.send_frame(NETWORK_ID, destination, ETHER_TYPE_IPV4, &oversized, now),
            Err(NodeError::InvalidPacket)
        );
        assert_eq!(
            topology.a.send_frame(NETWORK_ID, destination, ETHER_TYPE_IPV4, &[], now),
            Err(NodeError::InvalidPacket)
        );
        assert_eq!(
            topology.a.send_frame(0x8056_c2e2_1c00_0002, destination, ETHER_TYPE_IPV4, &oversized, now),
            Err(NodeError::NetworkNotReady)
        );
    }

    #[test]
    fn a_broadcast_arp_request_reaches_the_peer_that_announced_the_group() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        let target = managed_ipv4(&topology.b, NETWORK_ID);
        let requester = managed_ipv4(&topology.a, NETWORK_ID);
        let unicast = mac_for_address(topology.b_identity.address(), NETWORK_ID);
        topology
            .a
            .send_frame(NETWORK_ID, unicast, ETHER_TYPE_IPV4, &payload(), now)
            .expect("A reaches B directly, which is what makes B announce its groups");
        topology.pump(now);
        assert_eq!(topology.b.take_delivered_frames().len(), 1);
        assert!(
            topology
                .b
                .network(NETWORK_ID)
                .expect("network joined")
                .associated
                .contains_key(&topology.a_identity.address()),
            "B associated A, so B announced its multicast groups to A"
        );

        let request = arp_request(topology.a_identity.address(), NETWORK_ID, requester, target);
        topology
            .a
            .send_frame(NETWORK_ID, Mac::new(0xffff_ffff_ffff), ETHER_TYPE_ARP, &request, now)
            .expect("the broadcast ARP request is replicated to the learned members");

        topology.pump(now);

        let frames = topology.b.take_delivered_frames();
        assert_eq!(frames.len(), 1, "B delivered the broadcast frame");
        assert_eq!(frames[0].network_id, NETWORK_ID);
        assert_eq!(frames[0].source, mac_for_address(topology.a_identity.address(), NETWORK_ID));
        assert_eq!(frames[0].destination, Mac::new(0xffff_ffff_ffff));
        assert_eq!(frames[0].ether_type, ETHER_TYPE_ARP);
        assert_eq!(frames[0].payload, request, "the ARP request crossed intact");
        assert_eq!(
            topology.a.pending_frames_count_locked(),
            0,
            "a replicated frame is not deferred as a unicast frame"
        );
    }

    #[test]
    fn a_broadcast_group_the_network_disables_is_refused() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        let request =
            arp_request(topology.a_identity.address(), NETWORK_ID, managed_ipv4(&topology.a, NETWORK_ID), [0; 4]);
        let mut broadcast_without_adi = request.clone();
        broadcast_without_adi[7] = 2;
        assert_eq!(
            topology.a.send_frame(NETWORK_ID, Mac::new(0xffff_ffff_ffff), ETHER_TYPE_ARP, &broadcast_without_adi, now),
            Err(NodeError::UnsupportedEthernet),
            "the ad-hoc network does not enable the plain broadcast group"
        );
        assert_eq!(topology.a_wire.pending(), 0);
    }

    #[test]
    fn a_like_records_a_member_and_a_gather_answers_with_the_local_subscription() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        let (b_address, a_address) = (topology.b_identity.address(), topology.a_identity.address());
        let target = managed_ipv4(&topology.b, NETWORK_ID);
        let group = MulticastGroup::new(Mac::new(0xffff_ffff_ffff), u32::from_be_bytes(target));

        let mut like = Packet::new(b_address, a_address, Verb::MulticastLike).expect("a LIKE header");
        like.append_u64(NETWORK_ID).expect("network ID");
        like.append(&group.mac.bytes()).expect("group MAC");
        like.append_u32(group.adi).expect("group ADI");
        topology.a.send_packet_locked(b_address, like, true).expect("the LIKE is queued");
        let datagrams = topology.a_wire.take();
        assert_eq!(datagrams.len(), 1, "one LIKE datagram leaves A");
        topology.b.process_wire_packet(TEST_SOCKET, topology.a_addr, &datagrams[0], now).expect("B accepts the LIKE");

        let network = topology.b.network(NETWORK_ID).expect("B joined the network");
        assert_eq!(
            network.multicast.get(&group).and_then(|members| members.get(&a_address)).copied(),
            Some(now),
            "the LIKE recorded its sender as a member"
        );
        assert!(network.associated.contains_key(&a_address), "the LIKE associated the authenticated peer");

        let mut gather = Packet::new(b_address, a_address, Verb::MulticastGather).expect("a GATHER header");
        gather.append_u64(NETWORK_ID).expect("network ID");
        gather.append_u8(0).expect("flags");
        gather.append(&group.mac.bytes()).expect("group MAC");
        gather.append_u32(group.adi).expect("group ADI");
        gather.append_u32(4).expect("limit");
        let gather_id = gather.packet_id();
        topology.a.send_packet_locked(b_address, gather, true).expect("the GATHER is queued");
        let datagrams = topology.a_wire.take();
        assert_eq!(datagrams.len(), 1);
        topology.b.process_wire_packet(TEST_SOCKET, topology.a_addr, &datagrams[0], now).expect("B accepts the GATHER");

        let shared = topology.a_identity.agree(&topology.b_identity).expect("the shared key");
        let mut replies: Vec<Packet> = topology
            .b_wire
            .take()
            .into_iter()
            .filter_map(|data| {
                let mut packet = Packet::parse(&data).ok()?;
                packet.dearmor(&shared).ok()?;
                (packet.destination() == a_address && packet.verb() == Some(Verb::Ok)).then_some(packet)
            })
            .collect();
        assert_eq!(replies.len(), 1, "B answers the gather on the incoming path");
        let reply = replies.pop().expect("the reply");
        let payload = reply.payload();
        assert_eq!(payload[0], Verb::MulticastGather.bits());
        assert_eq!(u64::from_be_bytes(payload[1..9].try_into().expect("eight bytes")), gather_id);
        assert_eq!(u64::from_be_bytes(payload[9..17].try_into().expect("eight bytes")), NETWORK_ID);
        assert_eq!(Mac::from_bytes(&payload[17..23]).expect("MAC"), group.mac);
        assert_eq!(u32::from_be_bytes(payload[23..27].try_into().expect("four bytes")), group.adi);
        assert_eq!(u32::from_be_bytes(payload[27..31].try_into().expect("four bytes")), 2, "self and the requester");
        assert_eq!(u16::from_be_bytes([payload[31], payload[32]]), 1, "the requester is not its own result");
        assert_eq!(
            Address::from_bytes(&payload[33..38]).expect("address"),
            b_address,
            "the reply carries B's own subscription"
        );
    }

    #[test]
    fn an_invalid_multicast_destination_still_refreshes_the_authenticated_peer() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        let (b_address, a_address) = (topology.b_identity.address(), topology.a_identity.address());
        let mut packet = Packet::new(b_address, a_address, Verb::MulticastFrame).expect("a MULTICAST_FRAME header");
        packet.append_u64(NETWORK_ID).expect("network ID");
        packet.append_u8(0).expect("flags");
        packet.append(&mac_for_address(b_address, NETWORK_ID).bytes()).expect("a unicast destination");
        packet.append_u32(0).expect("group ADI");
        packet.append_u16(ETHER_TYPE_IPV4).expect("ether type");
        packet.append(&[0x45]).expect("payload");
        topology.a.send_packet_locked(b_address, packet, true).expect("the frame is queued");

        topology.pump(now);

        assert!(topology.b.take_delivered_frames().is_empty(), "a unicast destination is not a group frame");
        assert_eq!(
            topology.b.peers[&a_address].last_receive,
            Some(now),
            "the authenticated peer is still accounted for"
        );
    }

    #[test]
    fn a_local_frame_loops_back_to_the_seam() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        let payload = payload();
        let own = mac_for_address(topology.a_identity.address(), NETWORK_ID);
        topology
            .a
            .send_frame(NETWORK_ID, own, ETHER_TYPE_IPV4, &payload, now)
            .expect("a frame addressed to this node is delivered locally");
        assert_eq!(topology.a_wire.pending(), 0);
        let frames = topology.a.take_delivered_frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, payload);
    }

    #[test]
    fn an_extended_frame_from_a_bridge_is_delivered_and_acknowledged() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        let bridged = Mac::new(0xaabb_ccdd_eeff);
        let payload = payload();
        let frame = Frame {
            network_id: NETWORK_ID,
            source: bridged,
            destination: mac_for_address(topology.a_identity.address(), NETWORK_ID),
            ether_type: ETHER_TYPE_IPV4,
            payload: payload.clone(),
        };

        // A is not an active bridge, so B rejects the frame's foreign source.
        topology
            .b
            .send_rule_frame_with_flow_locked(NETWORK_ID, topology.a_identity.address(), &frame, 0x10, 0, 0, now)
            .expect("the EXT_FRAME is queued");
        topology.pump(now);
        assert!(topology.a.take_delivered_frames().is_empty(), "bridging is only allowed from an active bridge");

        topology
            .a
            .networks
            .get_mut(&NETWORK_ID)
            .expect("network joined")
            .config
            .specialists
            .push(SPECIALIST_TYPE_ACTIVE_BRIDGE | topology.b_identity.address().uint64());
        topology
            .b
            .send_rule_frame_with_flow_locked(NETWORK_ID, topology.a_identity.address(), &frame, 0x10, 0, 0, now)
            .expect("the EXT_FRAME is queued again");
        topology.pump(now);

        let frames = topology.a.take_delivered_frames();
        assert_eq!(frames.len(), 1, "A accepts the frame from the bridge");
        assert_eq!(frames[0].source, bridged, "the bridged source MAC is preserved");
        assert_eq!(frames[0].payload, payload);
        assert_eq!(
            topology.b.pending().iter().filter(|(_, request)| request.verb == Verb::ExtFrame).count(),
            1,
            "only the second receipt request was acknowledged; the first was refused without one"
        );
        assert!(
            topology.a.networks.get(&NETWORK_ID).expect("network joined").bridge_routes.contains_key(&bridged),
            "A remembered which bridge owns the bridged MAC"
        );
    }

    #[test]
    fn a_bridged_destination_is_routed_to_the_learned_bridge() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        let bridged = Mac::new(0xaabb_ccdd_eeff);
        let fallback = Mac::new(0xaabb_ccdd_ee11);
        let bridge = SPECIALIST_TYPE_ACTIVE_BRIDGE | topology.b_identity.address().uint64();
        for node in [&mut topology.a, &mut topology.b] {
            node.networks.get_mut(&NETWORK_ID).expect("network joined").config.specialists.push(bridge);
        }
        let from_bridge = Frame {
            network_id: NETWORK_ID,
            source: bridged,
            destination: mac_for_address(topology.a_identity.address(), NETWORK_ID),
            ether_type: ETHER_TYPE_IPV4,
            payload: vec![0x11; 8],
        };
        topology
            .b
            .send_rule_frame_with_flow_locked(NETWORK_ID, topology.a_identity.address(), &from_bridge, 0, 0, 0, now)
            .expect("the bridged frame is queued");
        topology.pump(now);
        assert_eq!(topology.a.take_delivered_frames().len(), 1);
        assert!(
            topology.a.networks.get(&NETWORK_ID).expect("network joined").bridge_routes.contains_key(&bridged),
            "A learned the bridge that owns the bridged MAC"
        );

        let routed_payload = payload();
        topology
            .a
            .send_frame(NETWORK_ID, bridged, ETHER_TYPE_IPV4, &routed_payload, now)
            .expect("a frame for the learned bridged MAC is routed");
        topology.pump(now);
        let frames = topology.b.take_delivered_frames();
        assert_eq!(frames.len(), 1, "the frame reached the bridge through the learned route");
        assert_eq!(frames[0].destination, bridged);
        assert_eq!(frames[0].source, mac_for_address(topology.a_identity.address(), NETWORK_ID));
        assert_eq!(frames[0].payload, routed_payload);

        topology.a.networks.get_mut(&NETWORK_ID).expect("network joined").bridge_routes.clear();
        let fallback_payload = payload();
        topology
            .a
            .send_frame(NETWORK_ID, fallback, ETHER_TYPE_IPV4, &fallback_payload, now)
            .expect("an unlearned bridged MAC falls back to the bridge specialists");
        topology.pump(now);
        let frames = topology.b.take_delivered_frames();
        assert_eq!(frames.len(), 1, "the specialist fallback reached the bridge");
        assert_eq!(frames[0].destination, fallback);
        assert_eq!(frames[0].payload, fallback_payload);
    }

    #[test]
    fn a_private_network_needs_a_membership_certificate() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        topology.a.networks.get_mut(&NETWORK_ID).expect("network joined").config.network_type = NetworkType::PRIVATE;
        assert!(!topology.a.network_allows_peer_locked(NETWORK_ID, topology.b_identity.address()));

        let destination = mac_for_address(topology.b_identity.address(), NETWORK_ID);
        assert_eq!(
            topology.a.send_frame(NETWORK_ID, destination, ETHER_TYPE_IPV4, &payload(), now),
            Err(NodeError::NetworkNotReady),
            "sending credentials needs a network membership certificate"
        );
    }

    #[test]
    fn a_frame_from_a_peer_without_credentials_is_deferred() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        topology.b.networks.get_mut(&NETWORK_ID).expect("network joined").config.network_type = NetworkType::PRIVATE;
        let destination = mac_for_address(topology.b_identity.address(), NETWORK_ID);
        topology
            .a
            .send_frame(NETWORK_ID, destination, ETHER_TYPE_IPV4, &payload(), now)
            .expect("A's acceptance is local");

        topology.pump(now);

        assert!(topology.b.take_delivered_frames().is_empty(), "B cannot admit a peer without membership");
        assert_eq!(
            topology.a_wire.pending(),
            0,
            "B's need-credentials ERROR was answered, and A sends no credentials for a public network"
        );
        assert!(topology.a.take_delivered_frames().is_empty(), "the ERROR is not a frame");
    }

    #[test]
    fn deferred_frames_flush_once_the_peer_is_known() {
        let mut topology = Topology::new();
        let now = SystemTime::now();
        let unknown = Identity::generate();
        let frame = Frame {
            network_id: NETWORK_ID,
            source: mac_for_address(topology.a_identity.address(), NETWORK_ID),
            destination: mac_for_address(unknown.address(), NETWORK_ID),
            ether_type: ETHER_TYPE_IPV4,
            payload: payload(),
        };
        topology
            .a
            .send_frame(NETWORK_ID, frame.destination, ETHER_TYPE_IPV4, &frame.payload, now)
            .expect("the frame is deferred");
        assert_eq!(topology.a.pending_frames_count_locked(), 1);
        assert_eq!(topology.a_wire.pending(), 0, "nothing is sent for an unknown peer");

        topology.a.expire_pending_frames_locked(now + PENDING_TRANSMIT_EXPIRATION * 2);
        assert_eq!(topology.a.pending_frames_count_locked(), 0, "the deferred frame expires");

        let fresh = PendingOutboundFrame {
            frame: frame.clone(),
            extended: false,
            extended_flags: 0,
            payload_length: 0,
            flow_id: ANY_LOCAL_SOCKET as i32,
            created_at: now,
        };
        topology.a.add_peer_locked(unknown.clone(), false).expect("the peer is added");
        topology.a.enqueue_pending_frame_locked(unknown.address(), fresh);
        assert_eq!(topology.a.pending_frames_count_locked(), 1);
        topology.a.flush_pending_frames_locked(unknown.address(), now);
        assert_eq!(topology.a_wire.pending(), 0, "a peer with no path defers the frame on the transmit queue instead");
        assert_eq!(topology.a.pending_frames_count_locked(), 0);
    }
}

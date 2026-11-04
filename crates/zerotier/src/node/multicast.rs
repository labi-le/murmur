//! Multicast replication and group membership.
//!
//! Membership is learned from `MULTICAST_LIKE` announcements,
//! `MULTICAST_GATHER` member queries and their `OK` replies, and the
//! `MULTICAST_FRAME` copies a sender or replicator emits.
//!
//! A group is an Ethernet group address plus an ADI, which separates the
//! broadcast groups an ARP request's target address selects. A frame whose
//! recipients are not yet known is held in the network's pending table until an
//! announcement, a gather result, or a peer identity arrives.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::address::{controller, Address};
use crate::bonding::{frame_flow_id, NO_FLOW_ID};
use crate::frame::{Frame, MulticastGroup, ETHER_TYPE_ARP, ETHER_TYPE_IPV4};
use crate::mac::{mac_for_address, Mac, ETHERNET_MAC_SIZE};
use crate::membership::CertificateOfMembership;
use crate::network_config::{
    MAX_NETWORK_MTU, NETWORK_CONFIG_FLAG_ENABLE_BROADCAST, SPECIALIST_TYPE_ACTIVE_BRIDGE,
    SPECIALIST_TYPE_MULTICAST_REPLICATOR, SPECIALIST_TYPE_NETWORK_RELAY,
};
use crate::node::frames::{shuffle_addresses, unusable};
use crate::node::handshake::PacketOutcome;
use crate::node::network::{NetworkStatus, PendingMulticastFrame};
use crate::node::peer::path_latency;
use crate::node::{
    ad_hoc_network_hub, elapsed, Node, NodeError, PathKey, PendingRequest, MAX_MULTICAST_GROUPS,
    MAX_MULTICAST_GROUP_MEMBERS, MAX_PENDING_FRAMES, MAX_PENDING_MULTICAST_GROUP, MULTICAST_EXPLICIT_GATHER,
    MULTICAST_LIKE_PERIOD, MULTICAST_MEMBER_EXPIRATION, MULTICAST_TRANSMIT_TIMEOUT, TRUST_EXPIRATION,
};
use crate::packet::{Packet, Verb, MAX_PACKET_SIZE, MIN_PACKET_SIZE};
use crate::rules::RuleResult;

/// Derives the group a frame addresses, including the ADI an ARP request uses
/// to select one of the broadcast groups.
#[must_use]
pub fn multicast_group_for_frame(frame: &Frame) -> MulticastGroup {
    let mut group = MulticastGroup::new(frame.destination, 0);
    if frame.destination.is_broadcast() && frame.ether_type == ETHER_TYPE_ARP {
        group.adi = arp_request_adi(&frame.payload).unwrap_or(0);
    }
    group
}

/// The ADI an ARP request selects its broadcast group by, absent when the
/// payload is not an IPv4 request.
fn arp_request_adi(payload: &[u8]) -> Option<u32> {
    let header: &[u8; 28] = payload.get(..28)?.try_into().ok()?;
    if u16::from_be_bytes([header[2], header[3]]) != ETHER_TYPE_IPV4
        || header[4] as usize != ETHERNET_MAC_SIZE
        || header[5] != 4
        || header[7] != 1
    {
        return None;
    }
    Some(u32::from_be_bytes([header[24], header[25], header[26], header[27]]))
}

/// Converts the configured member limit to a bounded host value.
#[must_use]
pub fn effective_multicast_limit(limit: u32) -> usize {
    (limit as usize).min(MAX_MULTICAST_GROUP_MEMBERS)
}

impl Node {
    /// Selects known recipients for a group frame, or starts member discovery.
    pub(crate) fn send_multicast_locked(
        &mut self,
        network_id: u64,
        frame: &Frame,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        let group = multicast_group_for_frame(frame);
        let Some(network) = self.networks.get(&network_id) else {
            return Err(NodeError::NetworkNotFound);
        };
        if group.mac.is_broadcast()
            && group.adi == 0
            && network.config.flags & NETWORK_CONFIG_FLAG_ENABLE_BROADCAST == 0
        {
            return Err(NodeError::UnsupportedEthernet);
        }
        if network.config.multicast_limit == 0 {
            return Err(NodeError::UnsupportedEthernet);
        }
        let local = self.identity.address();
        let is_replicator = network.config.is_specialist(local, SPECIALIST_TYPE_ACTIVE_BRIDGE)
            || network.config.is_specialist(local, SPECIALIST_TYPE_MULTICAST_REPLICATOR);
        if !is_replicator {
            if let Some(replicator) = self.best_multicast_replicator_locked(network_id, now) {
                if self.send_multicast_frame_locked(network_id, replicator, group, frame, 0, true, now).is_ok() {
                    return Ok(());
                }
            }
        }
        self.send_multicast_sender_locked(network_id, Address::default(), group, frame, now)
    }

    /// Sends or replicates a group frame on behalf of `origin`.
    pub(crate) fn send_multicast_sender_locked(
        &mut self,
        network_id: u64,
        origin: Address,
        group: MulticastGroup,
        frame: &Frame,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        let local = self.identity.address();
        let Some(network) = self.networks.get(&network_id) else {
            return Err(NodeError::NetworkNotFound);
        };
        let limit = effective_multicast_limit(network.config.multicast_limit);
        let members: Vec<Address> = network
            .multicast
            .get(&group)
            .map(|members| {
                members
                    .iter()
                    .filter(|(address, seen)| **address != local && elapsed(now, **seen) < MULTICAST_MEMBER_EXPIRATION)
                    .map(|(address, _)| *address)
                    .collect()
            })
            .unwrap_or_default();
        let bridges = network.config.specialist_addresses(SPECIALIST_TYPE_ACTIVE_BRIDGE);
        let bridges_outside_limit = members.len() >= limit;
        let gather_limit = if bridges_outside_limit { 1 } else { gather_limit_for(limit, members.len())? };
        let bridge_set: BTreeSet<Address> = bridges.iter().copied().collect();
        let mut fixed_targets: Option<BTreeSet<Address>> = bridges_outside_limit.then(BTreeSet::new);
        let mut sent_to: BTreeSet<Address> = BTreeSet::new();
        for bridge in &bridges {
            if *bridge == local || *bridge == origin || (!bridges_outside_limit && sent_to.len() >= limit) {
                continue;
            }
            if let Some(targets) = fixed_targets.as_mut() {
                targets.insert(*bridge);
            }
            if !self.peers.contains_key(bridge) {
                self.request_whois_locked(*bridge, now);
                continue;
            }
            if self.send_multicast_frame_locked(network_id, *bridge, group, frame, gather_limit, false, now).is_ok() {
                sent_to.insert(*bridge);
            }
        }
        let mut member_sent = 0usize;
        let mut member_selected = 0usize;
        for address in &members {
            if *address == origin
                || (bridges_outside_limit && member_selected >= limit)
                || (!bridges_outside_limit && (member_sent >= limit || sent_to.len() >= limit))
            {
                continue;
            }
            if bridge_set.contains(address) {
                continue;
            }
            if let Some(targets) = fixed_targets.as_mut() {
                member_selected += 1;
                targets.insert(*address);
            }
            if !self.peers.contains_key(address) {
                self.request_whois_locked(*address, now);
                continue;
            }
            if self.send_multicast_frame_locked(network_id, *address, group, frame, gather_limit, false, now).is_ok() {
                sent_to.insert(*address);
                member_sent += 1;
            }
        }
        let mut complete = sent_to.len() >= limit;
        if bridges_outside_limit {
            complete = true;
            if let Some(targets) = &fixed_targets {
                for address in targets {
                    complete = complete && sent_to.contains(address);
                }
            }
        }
        let queued = self.pending_multicast_count_locked(network_id, group);
        if !complete
            && queued.is_some_and(|count| count < MAX_PENDING_MULTICAST_GROUP)
            && self.total_pending_multicast_locked() < MAX_PENDING_FRAMES
        {
            if let Some(network) = self.networks.get_mut(&network_id) {
                network.pending_multicast.entry(group).or_default().push(PendingMulticastFrame {
                    frame: frame.clone(),
                    origin,
                    sent: sent_to,
                    targets: fixed_targets,
                    gather_limit,
                    bridges_outside_limit,
                    created_at: now,
                });
            }
        }
        if bridges_outside_limit {
            return Ok(());
        }
        self.gather_multicast_locked(network_id, group, gather_limit, now)
    }

    /// The deferred frames retained for one group, absent when the network is
    /// gone (the `len(network.pendingMulticast[group])`).
    fn pending_multicast_count_locked(&self, network_id: u64, group: MulticastGroup) -> Option<usize> {
        self.networks.get(&network_id).map(|network| network.pending_multicast.get(&group).map_or(0, Vec::len))
    }

    /// Deferred multicast frames across every joined network.
    fn total_pending_multicast_locked(&self) -> usize {
        self.networks.values().flat_map(|network| network.pending_multicast.values()).map(Vec::len).sum()
    }

    /// Selects the reachable configured replicator with the best latency.
    fn best_multicast_replicator_locked(&self, network_id: u64, now: SystemTime) -> Option<Address> {
        let network = self.networks.get(&network_id)?;
        let mut best: Option<(Address, Duration)> = None;
        for address in network.config.specialist_addresses(SPECIALIST_TYPE_MULTICAST_REPLICATOR) {
            let Some(peer) = self.peers.get(&address) else {
                continue;
            };
            let Some(path) = self.best_direct_peer_path(peer, now) else {
                continue;
            };
            let Some(state) = peer.paths.get(&path) else {
                continue;
            };
            let quality = path_latency(state);
            if best.is_none_or(|(_, best_quality)| quality < best_quality) {
                best = Some((address, quality));
            }
        }
        best.map(|(address, _)| address)
    }

    /// Encodes and sends one multicast frame operation.
    pub(crate) fn send_multicast_frame_locked(
        &mut self,
        network_id: u64,
        destination: Address,
        group: MulticastGroup,
        frame: &Frame,
        gather_limit: u32,
        replicate: bool,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        // A replicator is a transport hop rather than a recipient, so its own
        // rules are not consulted here; it filters when it fans the frame out.
        if !replicate && !self.filter_replicated_outbound_locked(network_id, destination, frame, now)? {
            return Ok(());
        }
        self.send_credentials_locked(network_id, destination, now)?;
        let mut packet = Packet::new(destination, self.identity.address(), Verb::MulticastFrame)
            .map_err(|_| NodeError::InvalidPacket)?;
        let mut flags = 0u8;
        if gather_limit > 0 {
            flags |= 0x02;
        }
        if replicate || frame.source != mac_for_address(self.identity.address(), network_id) {
            flags |= 0x04;
        }
        if replicate {
            flags |= 0x08;
        }
        let writes = [
            packet.append_u64(network_id),
            packet.append_u8(flags),
            if gather_limit > 0 { packet.append_u32(gather_limit) } else { Ok(()) },
            if flags & 0x04 != 0 { packet.append(&frame.source.bytes()) } else { Ok(()) },
            packet.append(&group.mac.bytes()),
            packet.append_u32(group.adi),
            packet.append_u16(frame.ether_type),
            packet.append(&frame.payload),
        ];
        if writes.into_iter().any(|write| write.is_err()) {
            return Err(NodeError::InvalidPacket);
        }
        let packet_id = packet.packet_id();
        if gather_limit > 0 {
            self.add_pending_locked(
                packet_id,
                PendingRequest {
                    verb: Verb::MulticastFrame,
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
        let flow_id = frame_flow_id(frame.ether_type, &frame.payload);
        let result = packet
            .compress()
            .map_err(|_| NodeError::InvalidPacket)
            .and_then(|()| self.send_packet_with_flow_locked(destination, packet, true, flow_id));
        if result.is_err() && gather_limit > 0 {
            self.delete_pending_locked(packet_id);
        }
        result
    }

    /// Requests the current members of a group from the controller, a root, or
    /// a relay.
    pub(crate) fn gather_multicast_locked(
        &mut self,
        network_id: u64,
        group: MulticastGroup,
        limit: u32,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        let local = self.identity.address();
        let gather_period = if self.low_bandwidth { MULTICAST_EXPLICIT_GATHER * 3 } else { MULTICAST_EXPLICIT_GATHER };
        let Some(network) = self.networks.get(&network_id) else {
            return Err(NodeError::NetworkNotFound);
        };
        let learned = network.multicast.get(&group).is_some_and(|members| !members.is_empty());
        let recent = network.last_multicast_gather.get(&group).is_some_and(|last| elapsed(now, *last) < gather_period);
        if learned && recent {
            return Ok(());
        }
        let mut addresses: Vec<Address> = Vec::with_capacity(18);
        let primary = ad_hoc_network_hub(network_id).unwrap_or_else(|| controller(network_id));
        addresses.push(primary);
        if let Some(root) = self.best_root_peer_path(now).0 {
            if root != primary {
                addresses.push(root);
            }
        }
        let mut specialists =
            network.config.specialist_addresses(SPECIALIST_TYPE_NETWORK_RELAY | SPECIALIST_TYPE_MULTICAST_REPLICATOR);
        shuffle_addresses(&mut specialists);
        for address in specialists {
            if addresses.len() >= 16 {
                break;
            }
            addresses.push(address);
        }
        let com = network.config.com.clone();
        if let Some(network) = self.networks.get_mut(&network_id) {
            network.last_multicast_gather.insert(group, now);
        }
        let mut seen: BTreeSet<Address> = BTreeSet::new();
        let mut first_error = None;
        for address in addresses {
            if address == local || !seen.insert(address) {
                continue;
            }
            let mut packet =
                Packet::new(address, local, Verb::MulticastGather).map_err(|_| NodeError::InvalidPacket)?;
            let writes = [
                packet.append_u64(network_id),
                packet.append_u8(u8::from(com.is_some())),
                packet.append(&group.mac.bytes()),
                packet.append_u32(group.adi),
                packet.append_u32(limit),
            ];
            let certificate = com.as_ref().map(|com| com.bytes().to_vec());
            let appended = writes.into_iter().all(|write| write.is_ok())
                && certificate.as_deref().is_none_or(|raw| packet.append(raw).is_ok());
            if !appended {
                return Err(NodeError::InvalidPacket);
            }
            let packet_id = packet.packet_id();
            if let Err(error) = self.add_pending_locked(
                packet_id,
                PendingRequest {
                    verb: Verb::MulticastGather,
                    peer: address,
                    network_id,
                    sent_at: Some(now),
                    slot: 0,
                    generation: 0,
                    path: None,
                    priority: 0,
                    reply_paths: None,
                },
            ) {
                first_error = first_error.or(Some(error));
                continue;
            }
            if !self.peers.contains_key(&address) {
                self.enqueue_pending_transmit_locked(&packet, true, NO_FLOW_ID, now);
                self.request_whois_locked(address, now);
                continue;
            }
            if let Err(error) = self.send_packet_locked(address, packet, true) {
                self.delete_pending_locked(packet_id);
                first_error = first_error.or(Some(error));
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Records the members a gather reply reported.
    pub(crate) fn handle_multicast_gather_ok_locked(
        &mut self,
        payload: &[u8],
        now: SystemTime,
    ) -> Result<(), NodeError> {
        if payload.len() < 33 {
            return Err(NodeError::InvalidPacket);
        }
        let network_id = be_u64(payload, 9)?;
        let Some(group) = group_from_payload(field(payload, 17, 10)?) else {
            return Err(NodeError::InvalidPacket);
        };
        self.add_multicast_gather_results_locked(network_id, group, rest(payload, 27)?, now)
    }

    /// Records gather results piggybacked on a frame acknowledgement.
    pub(crate) fn handle_multicast_frame_ok_locked(
        &mut self,
        payload: &[u8],
        now: SystemTime,
    ) -> Result<(), NodeError> {
        if payload.len() < 28 {
            return Err(NodeError::InvalidPacket);
        }
        let network_id = be_u64(payload, 9)?;
        let Some(group) = group_from_payload(field(payload, 17, 10)?) else {
            return Err(NodeError::InvalidPacket);
        };
        let flags = byte_at(payload, 27)?;
        let mut position = 28;
        if flags & 0x01 != 0 {
            let (certificate, consumed) =
                CertificateOfMembership::parse(rest(payload, position)?).map_err(|_| NodeError::InvalidPacket)?;
            position += consumed;
            let _ = self.add_membership_locked(network_id, &certificate);
        }
        if flags & 0x02 == 0 {
            return Ok(());
        }
        self.add_multicast_gather_results_locked(network_id, group, rest(payload, position)?, now)
    }

    /// Records authenticated member addresses.
    fn add_multicast_gather_results_locked(
        &mut self,
        network_id: u64,
        group: MulticastGroup,
        results: &[u8],
        now: SystemTime,
    ) -> Result<(), NodeError> {
        if results.len() < 6 {
            return Err(NodeError::InvalidPacket);
        }
        let count = usize::from(be_u16(results, 4)?);
        if results.len() - 6 < count * Address::SIZE {
            return Err(NodeError::InvalidPacket);
        }
        if !self.ensure_multicast_group_locked(network_id, group) {
            return Ok(());
        }
        let local = self.identity.address();
        for chunk in rest(results, 6)?.chunks_exact(Address::SIZE).take(count) {
            let Ok(address) = Address::from_bytes(chunk) else {
                return Err(NodeError::InvalidPacket);
            };
            if address == local {
                continue;
            }
            if let Some(members) =
                self.networks.get_mut(&network_id).and_then(|network| network.multicast.get_mut(&group))
            {
                if members.contains_key(&address) || members.len() < MAX_MULTICAST_GROUP_MEMBERS {
                    members.insert(address, now);
                }
            }
            if !self.peers.contains_key(&address) {
                self.request_whois_locked(address, now);
            }
        }
        self.flush_pending_multicast_locked(network_id, group, now);
        Ok(())
    }

    /// Records a peer's group announcements.
    pub(crate) fn handle_multicast_like_locked(
        &mut self,
        address: Address,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let payload = packet.payload();
        if !payload.len().is_multiple_of(18) {
            return Err(unusable(NodeError::InvalidPacket));
        }
        for record in payload.chunks_exact(18) {
            let Ok(network_id) = be_u64(record, 0) else {
                continue;
            };
            if !self.networks.contains_key(&network_id) || !self.network_allows_peer_locked(network_id, address) {
                continue;
            }
            self.mark_network_trust_locked(network_id, address, now);
            let Ok(mac) = mac_at(record, 8) else {
                continue;
            };
            if !mac.is_multicast() {
                continue;
            }
            let Ok(adi) = be_u32(record, 14) else {
                continue;
            };
            let group = MulticastGroup::new(mac, adi);
            if !self.ensure_multicast_group_locked(network_id, group) {
                continue;
            }
            if let Some(members) =
                self.networks.get_mut(&network_id).and_then(|network| network.multicast.get_mut(&group))
            {
                if members.contains_key(&address) || members.len() < MAX_MULTICAST_GROUP_MEMBERS {
                    members.insert(address, now);
                }
            }
            self.flush_pending_multicast_locked(network_id, group, now);
        }
        Ok(())
    }

    /// Answers a peer's member request.
    pub(crate) fn handle_multicast_gather_locked(
        &mut self,
        path: PathKey,
        address: Address,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let payload = packet.payload();
        if payload.len() < 23 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let network_id = be_u64(payload, 0).map_err(unusable)?;
        if !self.networks.contains_key(&network_id) {
            return Ok(());
        }
        let flags = byte_at(payload, 8).map_err(unusable)?;
        let Some(group) = group_from_payload(field(payload, 9, 10).map_err(unusable)?) else {
            return Err(unusable(NodeError::InvalidPacket));
        };
        let limit = be_u32(payload, 19).map_err(unusable)?;
        if flags & 0x01 != 0 {
            if let Ok((certificate, _)) = CertificateOfMembership::parse(rest(payload, 23).map_err(unusable)?) {
                let _ = self.add_membership_locked(network_id, &certificate);
            }
        }
        if !self.network_allows_peer_locked(network_id, address) {
            return Ok(());
        }
        self.mark_network_trust_locked(network_id, address, now);
        if limit == 0 {
            return Ok(());
        }
        let (total, addresses) = self.gather_multicast_members_locked(network_id, group, address, limit, now);
        if addresses.is_empty() {
            return Ok(());
        }
        let mut reply =
            Packet::new(address, self.identity.address(), Verb::Ok).map_err(|_| unusable(NodeError::InvalidPacket))?;
        let writes = [
            reply.append_u8(Verb::MulticastGather.bits()),
            reply.append_u64(packet.packet_id()),
            reply.append_u64(network_id),
            reply.append(&group.mac.bytes()),
            reply.append_u32(group.adi),
            reply.append_u32(total),
            reply.append_u16(u16::try_from(addresses.len()).map_err(|_| unusable(NodeError::InvalidPacket))?),
        ];
        if writes.into_iter().any(|write| write.is_err()) {
            return Err(unusable(NodeError::InvalidPacket));
        }
        for member in addresses {
            if reply.append(&member.bytes()).is_err() {
                return Err(unusable(NodeError::InvalidPacket));
            }
        }
        let _ = self.send_packet_via_path_locked(address, reply, true, path, false);
        Ok(())
    }

    /// Validates, delivers, and optionally replicates one inbound group frame.
    pub(crate) fn handle_multicast_frame_locked(
        &mut self,
        path: PathKey,
        address: Address,
        packet: &Packet,
        now: SystemTime,
    ) -> Result<(), PacketOutcome> {
        let payload = packet.payload();
        if payload.len() < 9 {
            return Err(unusable(NodeError::InvalidPacket));
        }
        let network_id = be_u64(payload, 0).map_err(unusable)?;
        let local = self.identity.address();
        let Some(multicast_limit) = self.networks.get(&network_id).map(|network| network.config.multicast_limit) else {
            return Err(PacketOutcome::NotAccepted);
        };
        let flags = byte_at(payload, 8).map_err(unusable)?;
        let mut position = 9;
        if flags & 0x01 != 0 {
            let Ok((certificate, consumed)) =
                CertificateOfMembership::parse(rest(payload, position).map_err(unusable)?)
            else {
                return Err(unusable(NodeError::InvalidPacket));
            };
            position += consumed;
            let _ = self.add_membership_locked(network_id, &certificate);
        }
        if !self.network_allows_peer_locked(network_id, address) {
            let _ = self.send_need_credentials_locked(address, path, packet, network_id);
            return Err(PacketOutcome::Retry);
        }
        let body = parse_multicast_frame_body(address, network_id, payload, flags, position).map_err(unusable)?;
        let frame = Frame {
            network_id,
            source: body.source,
            destination: body.group.mac,
            ether_type: body.ether_type,
            payload: body.payload,
        };
        let group = body.group;
        let gather_limit = body.gather_limit;
        if multicast_limit == 0 {
            return Ok(());
        }
        self.mark_network_trust_locked(network_id, address, now);
        if frame.payload.is_empty() || frame.payload.len() > MAX_NETWORK_MTU as usize {
            self.send_gather_ok_if_requested_locked(network_id, address, path, packet, group, gather_limit, now);
            return Ok(());
        }
        if !frame.destination.is_multicast() {
            return Ok(());
        }
        if frame.source.uint64() == 0
            || frame.source.is_multicast()
            || frame.source == mac_for_address(local, network_id)
        {
            return Ok(());
        }
        let (peer_is_bridge, local_is_replicator) = self.networks.get(&network_id).map_or((false, false), |network| {
            (
                network.config.is_specialist(address, SPECIALIST_TYPE_ACTIVE_BRIDGE),
                network.config.is_specialist(local, SPECIALIST_TYPE_MULTICAST_REPLICATOR),
            )
        });
        let peer_source = mac_for_address(address, network_id);
        if frame.source != peer_source && !peer_is_bridge {
            return Ok(());
        }
        if frame.source != peer_source {
            self.learn_bridge_route_locked(network_id, frame.source, address, now);
        }
        if flags & 0x08 != 0 && local_is_replicator {
            self.replicate_multicast_locked(network_id, address, group, &frame, now);
        }
        let decision = self.inbound_frame_decision(network_id, &frame, address);
        if decision.result != RuleResult::Accept {
            self.send_gather_ok_if_requested_locked(network_id, address, path, packet, group, gather_limit, now);
            return Ok(());
        }
        if !self.apply_inbound_rule_effects_locked(network_id, &decision, &frame, now) {
            self.send_gather_ok_if_requested_locked(network_id, address, path, packet, group, gather_limit, now);
            return Ok(());
        }
        self.deliver_frame_locked(frame);
        self.send_gather_ok_if_requested_locked(network_id, address, path, packet, group, gather_limit, now);
        Ok(())
    }

    /// Acknowledges a group frame with the members gathered for its sender,
    /// when the frame asked for them.
    fn send_gather_ok_if_requested_locked(
        &mut self,
        network_id: u64,
        address: Address,
        path: PathKey,
        packet: &Packet,
        group: MulticastGroup,
        gather_limit: u32,
        now: SystemTime,
    ) {
        if gather_limit > 0 {
            let _ = self.send_multicast_frame_gather_ok_locked(
                network_id,
                address,
                path,
                packet.packet_id(),
                group,
                gather_limit,
                now,
            );
        }
    }

    /// Acknowledges a group frame with the members gathered for its sender.
    fn send_multicast_frame_gather_ok_locked(
        &mut self,
        network_id: u64,
        address: Address,
        path: PathKey,
        packet_id: u64,
        group: MulticastGroup,
        limit: u32,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        let (total, addresses) = self.gather_multicast_members_locked(network_id, group, address, limit, now);
        if addresses.is_empty() {
            return Ok(());
        }
        let mut reply =
            Packet::new(address, self.identity.address(), Verb::Ok).map_err(|_| NodeError::InvalidPacket)?;
        let writes = [
            reply.append_u8(Verb::MulticastFrame.bits()),
            reply.append_u64(packet_id),
            reply.append_u64(network_id),
            reply.append(&group.mac.bytes()),
            reply.append_u32(group.adi),
            reply.append_u8(0x02),
            reply.append_u32(total),
            reply.append_u16(u16::try_from(addresses.len()).map_err(|_| NodeError::InvalidPacket)?),
        ];
        if writes.into_iter().any(|write| write.is_err()) {
            return Err(NodeError::InvalidPacket);
        }
        for member in addresses {
            if reply.append(&member.bytes()).is_err() {
                return Err(NodeError::InvalidPacket);
            }
        }
        self.send_packet_via_path_locked(address, reply, true, path, false)
    }

    /// Selects eligible members up to `limit`, the local node first when it is
    /// itself subscribed.
    pub(crate) fn gather_multicast_members_locked(
        &mut self,
        network_id: u64,
        group: MulticastGroup,
        requester: Address,
        limit: u32,
        now: SystemTime,
    ) -> (u32, Vec<Address>) {
        let local = self.identity.address();
        let mut addresses: Vec<Address> = Vec::with_capacity(8);
        if self.subscribed_to_multicast_group_locked(network_id, group) {
            addresses.push(local);
        }
        let mut total = u32::try_from(addresses.len()).unwrap_or(u32::MAX);
        let mut others: Vec<Address> = Vec::new();
        if let Some(members) = self.networks.get_mut(&network_id).and_then(|network| network.multicast.get_mut(&group))
        {
            let expired: Vec<Address> = members
                .iter()
                .filter(|(_, seen)| elapsed(now, **seen) >= MULTICAST_MEMBER_EXPIRATION)
                .map(|(address, _)| *address)
                .collect();
            for address in expired {
                members.remove(&address);
            }
            for address in members.keys() {
                total += 1;
                if *address != requester && *address != local {
                    others.push(*address);
                }
            }
        }
        shuffle_addresses(&mut others);
        addresses.extend(others);
        let mut max_results = (MAX_PACKET_SIZE - (MIN_PACKET_SIZE + 9 + 8 + 6 + 4 + 6)) / Address::SIZE;
        if (limit as usize) < max_results {
            max_results = limit as usize;
        }
        addresses.truncate(max_results);
        (total, addresses)
    }

    /// Forwards a group frame to selected members.
    pub(crate) fn replicate_multicast_locked(
        &mut self,
        network_id: u64,
        origin: Address,
        group: MulticastGroup,
        frame: &Frame,
        now: SystemTime,
    ) {
        let _ = self.send_multicast_sender_locked(network_id, origin, group, frame, now);
    }

    /// Retries frames waiting for gathered membership.
    pub(crate) fn flush_pending_multicast_locked(&mut self, network_id: u64, group: MulticastGroup, now: SystemTime) {
        let Some(pending) =
            self.networks.get_mut(&network_id).and_then(|network| network.pending_multicast.remove(&group))
        else {
            return;
        };
        let Some(network) = self.networks.get(&network_id) else {
            return;
        };
        let limit = effective_multicast_limit(network.config.multicast_limit);
        let bridges = network.config.specialist_addresses(SPECIALIST_TYPE_ACTIVE_BRIDGE);
        let members: Vec<(Address, SystemTime)> = network
            .multicast
            .get(&group)
            .map(|members| members.iter().map(|(address, seen)| (*address, *seen)).collect())
            .unwrap_or_default();
        let bridge_set: BTreeSet<Address> = bridges.iter().copied().collect();
        let mut kept = Vec::with_capacity(pending.len());
        for mut item in pending {
            if elapsed(now, item.created_at) >= MULTICAST_TRANSMIT_TIMEOUT {
                continue;
            }
            if let Some(complete) = self.flush_pending_fixed_targets_locked(&mut item, network_id, group, now) {
                if !complete {
                    kept.push(item);
                }
                continue;
            }
            if !self.flush_pending_widened_locked(
                &mut item,
                network_id,
                group,
                limit,
                &bridges,
                &members,
                &bridge_set,
                now,
            ) {
                kept.push(item);
            }
        }
        if !kept.is_empty() {
            if let Some(network) = self.networks.get_mut(&network_id) {
                network.pending_multicast.insert(group, kept);
            }
        }
    }

    /// Serves the recipients a pending frame fixed at capacity, absent when it
    /// named none, and reports whether every copy was accepted.
    fn flush_pending_fixed_targets_locked(
        &mut self,
        item: &mut PendingMulticastFrame,
        network_id: u64,
        group: MulticastGroup,
        now: SystemTime,
    ) -> Option<bool> {
        let targets = item.targets.clone()?;
        let mut complete = true;
        for address in targets {
            if item.sent.contains(&address) {
                continue;
            }
            complete = false;
            if !self.peers.contains_key(&address) {
                self.request_whois_locked(address, now);
                continue;
            }
            if self
                .send_multicast_frame_locked(network_id, address, group, &item.frame, item.gather_limit, false, now)
                .is_ok()
            {
                item.sent.insert(address);
            }
        }
        if !complete {
            complete = item.targets.iter().flatten().all(|address| item.sent.contains(address));
        }
        Some(complete)
    }

    /// Serves the bridges and known members of a pending frame that has no fixed
    /// targets, reporting whether its limit was reached.
    fn flush_pending_widened_locked(
        &mut self,
        item: &mut PendingMulticastFrame,
        network_id: u64,
        group: MulticastGroup,
        limit: usize,
        bridges: &[Address],
        members: &[(Address, SystemTime)],
        bridge_set: &BTreeSet<Address>,
        now: SystemTime,
    ) -> bool {
        let local = self.identity.address();
        for bridge in bridges {
            if *bridge == local
                || *bridge == item.origin
                || (!item.bridges_outside_limit && item.sent.len() >= limit)
                || item.sent.contains(bridge)
            {
                continue;
            }
            if !self.peers.contains_key(bridge) {
                self.request_whois_locked(*bridge, now);
                continue;
            }
            if self
                .send_multicast_frame_locked(network_id, *bridge, group, &item.frame, item.gather_limit, false, now)
                .is_ok()
            {
                item.sent.insert(*bridge);
            }
        }
        let mut member_sent = item.sent.iter().filter(|address| !bridge_set.contains(address)).count();
        for (address, seen) in members {
            if member_sent >= limit || (!item.bridges_outside_limit && item.sent.len() >= limit) {
                break;
            }
            if *address == item.origin
                || elapsed(now, *seen) >= MULTICAST_MEMBER_EXPIRATION
                || bridge_set.contains(address)
                || item.sent.contains(address)
            {
                continue;
            }
            if !self.peers.contains_key(address) {
                self.request_whois_locked(*address, now);
                continue;
            }
            if self
                .send_multicast_frame_locked(network_id, *address, group, &item.frame, item.gather_limit, false, now)
                .is_ok()
            {
                item.sent.insert(*address);
                member_sent += 1;
            }
        }
        let mut complete = item.sent.len() >= limit;
        if item.bridges_outside_limit {
            complete = member_sent >= limit;
            for bridge in bridges {
                if *bridge != local && *bridge != item.origin {
                    complete = complete && item.sent.contains(bridge);
                }
            }
        }
        complete
    }

    /// Advertises the network's groups to every eligible peer.
    pub(crate) fn announce_multicast_locked(&mut self, network_id: u64, now: SystemTime) {
        let local = self.identity.address();
        let groups = self.subscribed_multicast_groups_locked(network_id);
        let Some(network) = self.networks.get(&network_id) else {
            return;
        };
        let mut addresses = vec![controller(network_id)];
        for root in self.all_roots_locked() {
            addresses.push(root.identity.address());
        }
        addresses.extend(
            network.config.specialist_addresses(SPECIALIST_TYPE_NETWORK_RELAY | SPECIALIST_TYPE_MULTICAST_REPLICATOR),
        );
        if !groups.is_empty() {
            let members: Vec<Address> = network
                .members
                .keys()
                .filter(|address| {
                    self.peers.contains_key(address) && self.network_allows_peer_locked(network_id, **address)
                })
                .copied()
                .collect();
            addresses.extend(members);
        }
        addresses.extend(
            network
                .associated
                .iter()
                .filter(|(_, associated)| elapsed(now, **associated) < TRUST_EXPIRATION)
                .map(|(address, _)| *address),
        );
        let mut seen: BTreeSet<Address> = BTreeSet::new();
        for address in addresses {
            if address == local || !seen.insert(address) {
                continue;
            }
            if !self.peers.contains_key(&address) {
                self.request_whois_locked(address, now);
                continue;
            }
            self.announce_multicast_to_peer_locked(network_id, address, &groups, now);
        }
    }

    /// Sends the current group set to one peer.
    pub(crate) fn announce_multicast_to_peer_locked(
        &mut self,
        network_id: u64,
        address: Address,
        groups: &[MulticastGroup],
        now: SystemTime,
    ) {
        let announced_recently = self
            .networks
            .get(&network_id)
            .and_then(|network| network.multicast_announcements.get(&address).copied())
            .is_some_and(|announced| elapsed(now, announced) < MULTICAST_LIKE_PERIOD);
        if announced_recently {
            return;
        }
        if self.send_credentials_locked(network_id, address, now).is_err() {
            return;
        }
        if groups.is_empty() {
            if let Some(network) = self.networks.get_mut(&network_id) {
                network.multicast_announcements.insert(address, now);
            }
            return;
        }
        let mut offset = 0usize;
        while offset < groups.len() {
            let Ok(mut packet) = Packet::new(address, self.identity.address(), Verb::MulticastLike) else {
                return;
            };
            for group in groups.iter().skip(offset) {
                if packet.bytes().len() + 18 > MAX_PACKET_SIZE {
                    break;
                }
                let writes =
                    [packet.append_u64(network_id), packet.append(&group.mac.bytes()), packet.append_u32(group.adi)];
                if writes.into_iter().any(|write| write.is_err()) {
                    return;
                }
                offset += 1;
            }
            if packet.compress().is_err() || self.send_packet_locked(address, packet, true).is_err() {
                return;
            }
        }
        if let Some(network) = self.networks.get_mut(&network_id) {
            network.multicast_announcements.insert(address, now);
        }
    }

    /// The groups this node announces: the broadcast group when the network
    /// enables it, one per assigned address, and explicit subscriptions.
    pub(crate) fn subscribed_multicast_groups_locked(&self, network_id: u64) -> Vec<MulticastGroup> {
        let Some(network) = self.networks.get(&network_id) else {
            return Vec::new();
        };
        let mut groups: Vec<MulticastGroup> = Vec::new();
        let mut seen: BTreeSet<MulticastGroup> = BTreeSet::new();
        let mut push = |group: MulticastGroup, groups: &mut Vec<MulticastGroup>| {
            if seen.insert(group) {
                groups.push(group);
            }
        };
        let broadcast = Mac::new(0xffff_ffff_ffff);
        if network.config.flags & NETWORK_CONFIG_FLAG_ENABLE_BROADCAST != 0 {
            push(MulticastGroup::new(broadcast, 0), &mut groups);
        }
        for prefix in &network.config.assigned {
            match prefix.addr() {
                IpAddr::V4(address) => {
                    push(MulticastGroup::new(broadcast, u32::from_be_bytes(address.octets())), &mut groups);
                }
                IpAddr::V6(address) => {
                    let raw = address.octets();
                    let mac =
                        0x3333_ff00_0000 | u64::from(raw[13]) << 16 | u64::from(raw[14]) << 8 | u64::from(raw[15]);
                    push(MulticastGroup::new(Mac::new(mac), 0), &mut groups);
                }
            }
        }
        for group in &network.multicast_subscriptions {
            push(*group, &mut groups);
        }
        groups
    }

    /// Reports whether `wanted` matches a local subscription.
    pub(crate) fn subscribed_to_multicast_group_locked(&self, network_id: u64, wanted: MulticastGroup) -> bool {
        self.subscribed_multicast_groups_locked(network_id).contains(&wanted)
    }

    /// Creates the member table for a group, reporting whether it now exists.
    fn ensure_multicast_group_locked(&mut self, network_id: u64, group: MulticastGroup) -> bool {
        let Some(network) = self.networks.get_mut(&network_id) else {
            return false;
        };
        if network.multicast.contains_key(&group) {
            return true;
        }
        if network.multicast.len() >= MAX_MULTICAST_GROUPS {
            return false;
        }
        network.multicast.insert(group, BTreeMap::new());
        true
    }

    /// Releases the multicast work waiting for a newly published peer.
    pub(crate) fn flush_peer_multicast_locked(&mut self, address: Address, now: SystemTime) {
        let groups: Vec<(u64, MulticastGroup)> = self
            .networks
            .iter()
            .flat_map(|(network_id, network)| {
                let is_bridge = network.config.is_specialist(address, SPECIALIST_TYPE_ACTIVE_BRIDGE);
                network
                    .multicast
                    .iter()
                    .filter(|(_, members)| is_bridge || members.contains_key(&address))
                    .map(|(group, _)| (*network_id, *group))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (network_id, group) in groups {
            self.flush_pending_multicast_locked(network_id, group, now);
        }
    }

    /// Adds a local group to this node's announcements.
    pub fn subscribe_multicast(
        &mut self,
        network_id: u64,
        group: MulticastGroup,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        if !group.mac.is_multicast() {
            return Err(NodeError::InvalidPacket);
        }
        if self.closed {
            return Err(NodeError::NodeClosed);
        }
        let Some(network) = self.networks.get_mut(&network_id) else {
            return Err(NodeError::NetworkNotFound);
        };
        if !network.multicast_subscriptions.contains(&group)
            && network.multicast_subscriptions.len() >= MAX_MULTICAST_GROUPS
        {
            return Err(NodeError::TooManyMulticastSubscriptions);
        }
        network.multicast_subscriptions.insert(group);
        network.multicast_announcements.clear();
        let ready = network.status == NetworkStatus::Ok;
        if ready {
            self.announce_multicast_locked(network_id, now);
        }
        Ok(())
    }

    /// Removes a local group from this node's announcements.
    pub fn unsubscribe_multicast(&mut self, network_id: u64, group: MulticastGroup) -> Result<(), NodeError> {
        if self.closed {
            return Err(NodeError::NodeClosed);
        }
        let Some(network) = self.networks.get_mut(&network_id) else {
            return Err(NodeError::NetworkNotFound);
        };
        network.multicast_subscriptions.remove(&group);
        network.multicast_announcements.clear();
        Ok(())
    }

    /// Drops a peer's membership in a group it no longer wants.
    pub(crate) fn forget_multicast_group_locked(&mut self, network_id: u64, address: Address, group: MulticastGroup) {
        if !self.network_allows_peer_locked(network_id, address) {
            return;
        }
        if let Some(members) = self.networks.get_mut(&network_id).and_then(|network| network.multicast.get_mut(&group))
        {
            members.remove(&address);
        }
    }
}

/// The `len`-byte field of `raw` at `offset`, absent when `raw` is too short.
fn field(raw: &[u8], offset: usize, len: usize) -> Result<&[u8], NodeError> {
    let end = offset.checked_add(len).ok_or(NodeError::InvalidPacket)?;
    raw.get(offset..end).ok_or(NodeError::InvalidPacket)
}

/// The gather limit to advertise: one above the room left under `limit`.
fn gather_limit_for(limit: usize, members: usize) -> Result<u32, NodeError> {
    u32::try_from(limit - members + 1).map_err(|_| NodeError::InvalidPacket)
}

/// Everything of `raw` from `offset` on.
fn rest(raw: &[u8], offset: usize) -> Result<&[u8], NodeError> {
    raw.get(offset..).ok_or(NodeError::InvalidPacket)
}

/// The byte of `raw` at `offset`.
fn byte_at(raw: &[u8], offset: usize) -> Result<u8, NodeError> {
    raw.get(offset).copied().ok_or(NodeError::InvalidPacket)
}

/// A big-endian `u16` read at `offset`.
fn be_u16(raw: &[u8], offset: usize) -> Result<u16, NodeError> {
    Ok(u16::from_be_bytes(field(raw, offset, 2)?.try_into().map_err(|_| NodeError::InvalidPacket)?))
}

/// A big-endian `u32` read at `offset`.
fn be_u32(raw: &[u8], offset: usize) -> Result<u32, NodeError> {
    Ok(u32::from_be_bytes(field(raw, offset, 4)?.try_into().map_err(|_| NodeError::InvalidPacket)?))
}

/// A big-endian `u64` read at `offset`.
fn be_u64(raw: &[u8], offset: usize) -> Result<u64, NodeError> {
    Ok(u64::from_be_bytes(field(raw, offset, 8)?.try_into().map_err(|_| NodeError::InvalidPacket)?))
}

/// The MAC address at `offset`.
fn mac_at(raw: &[u8], offset: usize) -> Result<Mac, NodeError> {
    Mac::from_bytes(field(raw, offset, ETHERNET_MAC_SIZE)?).map_err(|_| NodeError::InvalidPacket)
}

/// The group and Ethernet frame a multicast frame operation carries: the
/// optional gather limit and explicit source, then the destination group.
struct MulticastFrameBody {
    source: Mac,
    group: MulticastGroup,
    ether_type: u16,
    payload: Vec<u8>,
    gather_limit: u32,
}

/// Decodes the body of a multicast frame operation, whose optional fields are
/// selected by `flags` and start at `position`.
fn parse_multicast_frame_body(
    address: Address,
    network_id: u64,
    payload: &[u8],
    flags: u8,
    mut position: usize,
) -> Result<MulticastFrameBody, NodeError> {
    let mut gather_limit = 0u32;
    if flags & 0x02 != 0 {
        gather_limit = be_u32(payload, position)?;
        position += 4;
    }
    let mut source = mac_for_address(address, network_id);
    if flags & 0x04 != 0 {
        source = mac_at(payload, position)?;
        position += ETHERNET_MAC_SIZE;
    }
    let destination = mac_at(payload, position)?;
    // The destination MAC and the ADI are adjacent: the four ADI bytes start
    // right after the six MAC bytes.
    let group = MulticastGroup::new(destination, be_u32(payload, position + ETHERNET_MAC_SIZE)?);
    position += 10;
    let ether_type = be_u16(payload, position)?;
    Ok(MulticastFrameBody { source, group, ether_type, payload: rest(payload, position + 2)?.to_vec(), gather_limit })
}

/// Reads a group from its wire form: six MAC bytes and a big-endian ADI.
fn group_from_payload(raw: &[u8]) -> Option<MulticastGroup> {
    let mac = Mac::from_bytes(raw.get(..ETHERNET_MAC_SIZE)?).ok()?;
    let adi = u32::from_be_bytes(raw.get(ETHERNET_MAC_SIZE..ETHERNET_MAC_SIZE + 4)?.try_into().ok()?);
    Some(MulticastGroup::new(mac, adi))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::network_config::{NetworkType, DEFAULT_NETWORK_MTU, NETWORK_CONFIG_FLAG_ENABLE_BROADCAST};
    use crate::node::peer::PeerPathState;
    use crate::node::store::MemoryStore;
    use crate::node::{Network, NodeHost, WHOIS_RETRY_PERIOD};
    use crate::rules::{NetworkRule, RULE_ACTION_ACCEPT, RULE_ACTION_DROP, RULE_MATCH_DEST_ZT_ADDRESS};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    const TEST_SOCKET: i64 = 7;
    /// An ad-hoc network that accepts every frame (`networkID&0xff == 0x01`).
    const NETWORK_ID: u64 = 0xff00_0000_0000_0001;
    const PEER_ENDPOINT: &str = "192.0.2.20:9993";

    #[derive(Default)]
    struct Recorder {
        wire: Mutex<Vec<(i64, SocketAddr, Vec<u8>)>>,
        peers: Mutex<BTreeMap<Address, Identity>>,
    }

    impl Recorder {
        fn destinations(&self) -> Vec<Address> {
            self.wire
                .lock()
                .expect("lock")
                .iter()
                .filter_map(|(_, _, data)| Packet::parse(data).ok().map(|packet| packet.destination()))
                .collect()
        }

        fn datagrams(&self) -> usize {
            self.wire.lock().expect("lock").len()
        }
    }

    struct TestHost {
        recorder: Arc<Recorder>,
    }

    impl NodeHost for TestHost {
        fn peer_identity(&self, address: Address) -> Option<Identity> {
            self.recorder.peers.lock().expect("lock").get(&address).cloned()
        }

        fn send_wire(&mut self, local_socket: i64, remote: SocketAddr, packet: Vec<u8>) -> Result<(), NodeError> {
            self.recorder.wire.lock().expect("lock").push((local_socket, remote, packet));
            Ok(())
        }

        fn request_whois(&mut self, _address: Address) {}

        fn announce_multicast(&mut self, _network_id: u64) {}

        fn trace_network_config_request(&mut self, _network_id: u64, _controller: Address) {}
    }

    fn test_node() -> (Node, Arc<Recorder>) {
        let recorder = Arc::new(Recorder::default());
        let mut node = Node::new(
            Identity::generate(),
            Box::new(MemoryStore::new()),
            Box::new(TestHost { recorder: Arc::clone(&recorder) }),
        );
        let now = SystemTime::now();
        node.join(NETWORK_ID, now).expect("the ad-hoc network configures itself");
        (node, recorder)
    }

    /// Adds a peer with an authenticated direct path, as discovery would.
    fn add_peer(node: &mut Node, recorder: &Recorder, now: SystemTime) -> Identity {
        let identity = Identity::generate();
        recorder.peers.lock().expect("lock").insert(identity.address(), identity.clone());
        publish_peer(node, &identity, now);
        add_path(node, identity.address(), now);
        identity
    }

    /// `Node::add_peer_locked` stamps the wall clock; a test's frames expire against its own
    /// clock, so the peer is published at `now` instead.
    fn publish_peer(node: &mut Node, identity: &Identity, now: SystemTime) {
        let peer = node.new_peer_locked(identity.clone(), false).expect("the peer is published");
        node.peers.insert(identity.address(), peer);
        node.peer_added_locked(identity.address(), now);
    }

    fn add_path(node: &mut Node, address: Address, now: SystemTime) {
        let endpoint: SocketAddr = PEER_ENDPOINT.parse().expect("endpoint");
        node.add_peer_path_locked(
            address,
            PathKey::new(TEST_SOCKET, endpoint),
            PeerPathState { last_receive: Some(now), last_probe: Some(now), priority: 1, ..Default::default() },
            now,
        );
    }

    /// Gives the node a reachable root, which identity discovery needs.
    fn add_root_path(node: &mut Node, now: SystemTime) -> Address {
        node.refresh_topology_roots_locked();
        let root = node.all_roots_locked().first().expect("the planet has roots").identity.address();
        add_path(node, root, now);
        root
    }

    fn broadcast_group() -> MulticastGroup {
        MulticastGroup::new(Mac::new(0xffff_ffff_ffff), 0)
    }

    fn broadcast_frame(ether_type: u16, payload: Vec<u8>) -> Frame {
        Frame {
            network_id: NETWORK_ID,
            source: Mac::new(0x0200_0000_0001),
            destination: Mac::new(0xffff_ffff_ffff),
            ether_type,
            payload,
        }
    }

    fn arp_payload(target: u32) -> Vec<u8> {
        let mut payload = vec![0u8; 28];
        payload[0..2].copy_from_slice(&1u16.to_be_bytes());
        payload[2..4].copy_from_slice(&ETHER_TYPE_IPV4.to_be_bytes());
        payload[4] = 6;
        payload[5] = 4;
        payload[6..8].copy_from_slice(&1u16.to_be_bytes());
        payload[24..28].copy_from_slice(&target.to_be_bytes());
        payload
    }

    fn set_multicast_limit(node: &mut Node, limit: u32) {
        node.networks.get_mut(&NETWORK_ID).expect("network joined").config.multicast_limit = limit;
    }

    /// Enables the plain broadcast group, which an ad-hoc network leaves off.
    fn enable_broadcast(node: &mut Node) {
        node.networks.get_mut(&NETWORK_ID).expect("network joined").config.flags |=
            NETWORK_CONFIG_FLAG_ENABLE_BROADCAST;
    }

    fn pending_in_group(node: &Node, group: MulticastGroup) -> usize {
        node.networks
            .get(&NETWORK_ID)
            .and_then(|network| network.pending_multicast.get(&group))
            .map(Vec::len)
            .unwrap_or(0)
    }

    /// A pending item with no negotiated recipients yet, held for one group.
    fn queue_pending(node: &mut Node, group: MulticastGroup, frame: Frame, now: SystemTime) {
        node.networks.get_mut(&NETWORK_ID).expect("network joined").pending_multicast.insert(
            group,
            vec![PendingMulticastFrame {
                frame,
                origin: Address::default(),
                sent: BTreeSet::new(),
                targets: None,
                gather_limit: 0,
                bridges_outside_limit: false,
                created_at: now,
            }],
        );
    }

    fn learn_member(node: &mut Node, group: MulticastGroup, address: Address, now: SystemTime) {
        learn_member_in(node, NETWORK_ID, group, address, now);
    }

    fn learn_member_in(node: &mut Node, network_id: u64, group: MulticastGroup, address: Address, now: SystemTime) {
        node.networks
            .get_mut(&network_id)
            .expect("network joined")
            .multicast
            .entry(group)
            .or_default()
            .insert(address, now);
    }

    #[test]
    fn the_member_limit_is_bounded() {
        assert_eq!(effective_multicast_limit(u32::MAX), MAX_MULTICAST_GROUP_MEMBERS);
        assert_eq!(effective_multicast_limit(123), 123);
    }

    #[test]
    fn an_arp_request_selects_its_broadcast_group_by_target_address() {
        let frame = broadcast_frame(ETHER_TYPE_ARP, arp_payload(0xc000_0201));
        assert_eq!(multicast_group_for_frame(&frame), MulticastGroup::new(Mac::new(0xffff_ffff_ffff), 0xc000_0201));

        let reply = broadcast_frame(ETHER_TYPE_ARP, {
            let mut payload = arp_payload(0xc000_0201);
            payload[7] = 2;
            payload
        });
        assert_eq!(multicast_group_for_frame(&reply), broadcast_group(), "an ARP reply carries no ADI");

        let short = broadcast_frame(ETHER_TYPE_ARP, vec![0u8; 12]);
        assert_eq!(multicast_group_for_frame(&short), broadcast_group());
    }

    #[test]
    fn gather_returns_the_local_subscription_before_cached_members() {
        let (mut node, _recorder) = test_node();
        let now = SystemTime::now();
        let member = Identity::generate().address();
        let requester = Identity::generate().address();
        let group = broadcast_group();
        node.networks.get_mut(&NETWORK_ID).expect("network joined").multicast_subscriptions.insert(group);
        learn_member(&mut node, group, member, now);

        let (total, addresses) = node.gather_multicast_members_locked(NETWORK_ID, group, requester, 1, now);

        assert_eq!(total, 2, "the requester and the cached member are both counted");
        assert_eq!(addresses, vec![node.identity.address()], "the local subscription comes first");
    }

    #[test]
    fn a_replicator_needs_an_active_direct_path() {
        let (mut node, recorder) = test_node();
        let now = SystemTime::now();
        let replicator = Identity::generate();
        recorder.peers.lock().expect("lock").insert(replicator.address(), replicator.clone());
        publish_peer(&mut node, &replicator, now);
        node.networks
            .get_mut(&NETWORK_ID)
            .expect("network joined")
            .config
            .specialists
            .push(SPECIALIST_TYPE_MULTICAST_REPLICATOR | replicator.address().uint64());

        assert_eq!(node.best_multicast_replicator_locked(NETWORK_ID, now), None);

        add_path(&mut node, replicator.address(), now);
        assert_eq!(node.best_multicast_replicator_locked(NETWORK_ID, now), Some(replicator.address()));
    }

    #[test]
    fn a_pending_frame_waits_for_the_member_identity() {
        let (mut node, recorder) = test_node();
        let now = SystemTime::now();
        add_root_path(&mut node, now);
        set_multicast_limit(&mut node, 1);
        let member = Identity::generate();
        let group = broadcast_group();
        learn_member(&mut node, group, member.address(), now);
        queue_pending(&mut node, group, broadcast_frame(ETHER_TYPE_IPV4, vec![0x45]), now);

        node.flush_pending_multicast_locked(NETWORK_ID, group, now);
        assert_eq!(pending_in_group(&node, group), 1, "an unknown member keeps the frame pending");
        assert!(node.pending_whois.contains_key(&member.address()), "the member is looked up");

        publish_peer(&mut node, &member, now);
        add_path(&mut node, member.address(), now);
        node.flush_peer_multicast_locked(member.address(), now);

        assert_eq!(pending_in_group(&node, group), 0, "the frame is released once the identity is known");
        assert!(recorder.datagrams() > 0, "the frame reached the member");
    }

    #[test]
    fn pending_whois_is_retried() {
        let (mut node, recorder) = test_node();
        let now = SystemTime::now();
        add_root_path(&mut node, now);
        let group = broadcast_group();
        let member = Identity::generate().address();
        learn_member(&mut node, group, member, now);
        queue_pending(&mut node, group, broadcast_frame(ETHER_TYPE_IPV4, vec![0x45]), now);

        node.retry_pending_whois_locked(now);
        assert!(node.pending_whois.contains_key(&member));
        let first = recorder.datagrams();

        node.retry_pending_whois_locked(now + WHOIS_RETRY_PERIOD);

        assert!(node.pending_whois.contains_key(&member));
        assert!(recorder.datagrams() > first, "the identity request is retried");
        assert_eq!(pending_in_group(&node, group), 1, "a requested identity does not drop the frame");
    }

    #[test]
    fn pending_whois_uses_the_fixed_targets_only() {
        let (mut node, _recorder) = test_node();
        let now = SystemTime::now();
        add_root_path(&mut node, now);
        let group = broadcast_group();
        let selected = Identity::generate().address();
        let later = Identity::generate().address();
        learn_member(&mut node, group, selected, now);
        learn_member(&mut node, group, later, now);
        queue_pending(&mut node, group, broadcast_frame(ETHER_TYPE_IPV4, vec![0x45]), now);
        node.networks.get_mut(&NETWORK_ID).expect("network joined").pending_multicast.insert(
            group,
            vec![PendingMulticastFrame {
                frame: broadcast_frame(ETHER_TYPE_IPV4, vec![0x45]),
                origin: Address::default(),
                sent: BTreeSet::new(),
                targets: Some(BTreeSet::from([selected])),
                gather_limit: 1,
                bridges_outside_limit: true,
                created_at: now,
            }],
        );

        node.retry_pending_whois_locked(now);

        assert!(node.pending_whois.contains_key(&selected));
        assert!(!node.pending_whois.contains_key(&later), "an item with fixed targets never widens them");
    }

    #[test]
    fn a_member_limit_at_capacity_still_reaches_an_active_bridge() {
        let (mut node, recorder) = test_node();
        let now = SystemTime::now();
        add_root_path(&mut node, now);
        set_multicast_limit(&mut node, 1);
        enable_broadcast(&mut node);
        let member = add_peer(&mut node, &recorder, now);
        let bridge = Identity::generate();
        node.networks
            .get_mut(&NETWORK_ID)
            .expect("network joined")
            .config
            .specialists
            .push(SPECIALIST_TYPE_ACTIVE_BRIDGE | bridge.address().uint64());
        let group = broadcast_group();
        learn_member(&mut node, group, member.address(), now);

        node.send_multicast_locked(NETWORK_ID, &broadcast_frame(ETHER_TYPE_IPV4, vec![0x45]), now)
            .expect("the group frame is replicated");

        assert_eq!(pending_in_group(&node, group), 1, "the unknown bridge keeps the frame pending");
        assert!(recorder.destinations().contains(&member.address()), "the known member was served first");

        publish_peer(&mut node, &bridge, now);

        assert_eq!(pending_in_group(&node, group), 0);
        assert!(recorder.destinations().contains(&bridge.address()), "the bridge received its copy");
    }

    #[test]
    fn a_member_limit_at_capacity_does_not_widen_the_fixed_targets() {
        let (mut node, recorder) = test_node();
        let now = SystemTime::now();
        add_root_path(&mut node, now);
        set_multicast_limit(&mut node, 1);
        enable_broadcast(&mut node);
        let selected = Identity::generate();
        let later = Identity::generate();
        for identity in [&selected, &later] {
            recorder.peers.lock().expect("lock").insert(identity.address(), identity.clone());
        }
        let group = broadcast_group();
        learn_member(&mut node, group, selected.address(), now);

        node.send_multicast_locked(NETWORK_ID, &broadcast_frame(ETHER_TYPE_IPV4, vec![0x45]), now)
            .expect("the group frame is replicated");
        assert_eq!(pending_in_group(&node, group), 1, "the unknown selected member is retained");

        publish_peer(&mut node, &later, now);
        learn_member(&mut node, group, later.address(), now);
        node.flush_pending_multicast_locked(NETWORK_ID, group, now);

        publish_peer(&mut node, &selected, now);

        let destinations = recorder.destinations();
        assert_eq!(pending_in_group(&node, group), 0);
        assert!(destinations.contains(&selected.address()), "the fixed target was served");
        assert!(!destinations.contains(&later.address()), "a target fixed at capacity is never widened");
    }

    #[test]
    fn a_replicator_is_not_filtered_as_a_recipient() {
        let (mut node, recorder) = test_node();
        let now = SystemTime::now();
        set_multicast_limit(&mut node, 1);
        enable_broadcast(&mut node);
        let replicator = add_peer(&mut node, &recorder, now);
        {
            let network = node.networks.get_mut(&NETWORK_ID).expect("network joined");
            network.config.specialists.push(SPECIALIST_TYPE_MULTICAST_REPLICATOR | replicator.address().uint64());
            network.config.rules = vec![
                NetworkRule { rule_type: RULE_MATCH_DEST_ZT_ADDRESS, value: replicator.address().bytes().to_vec() },
                NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
            ];
        }

        node.send_multicast_locked(NETWORK_ID, &broadcast_frame(ETHER_TYPE_IPV4, vec![0x45]), now)
            .expect("a configured replicator carries the frame");

        assert_eq!(
            recorder.destinations(),
            vec![replicator.address()],
            "the replicator is a transport hop, so its own rules do not drop the copy"
        );
    }

    #[test]
    fn a_replicator_sender_never_reflects_the_frame_to_its_origin() {
        let (mut node, recorder) = test_node();
        let now = SystemTime::now();
        set_multicast_limit(&mut node, 1);
        let origin = Identity::generate();
        let member = add_peer(&mut node, &recorder, now);
        let bridge = add_peer(&mut node, &recorder, now);
        node.networks
            .get_mut(&NETWORK_ID)
            .expect("network joined")
            .config
            .specialists
            .push(SPECIALIST_TYPE_ACTIVE_BRIDGE | bridge.address().uint64());
        let group = broadcast_group();
        learn_member(&mut node, group, origin.address(), now);
        learn_member(&mut node, group, member.address(), now);

        node.replicate_multicast_locked(
            NETWORK_ID,
            origin.address(),
            group,
            &broadcast_frame(ETHER_TYPE_IPV4, vec![0x45]),
            now,
        );

        let destinations = recorder.destinations();
        assert!(destinations.contains(&member.address()), "the member received the replica");
        assert!(destinations.contains(&bridge.address()), "the bridge received the replica");
        assert!(!destinations.contains(&origin.address()), "the origin never receives its own frame");
    }

    #[test]
    fn an_announcement_is_rate_limited_per_peer() {
        let (mut node, recorder) = test_node();
        let now = SystemTime::now();
        let first = add_peer(&mut node, &recorder, now);
        let second = add_peer(&mut node, &recorder, now);
        node.networks.get_mut(&NETWORK_ID).expect("network joined").associated.insert(first.address(), now);
        node.networks.get_mut(&NETWORK_ID).expect("network joined").associated.insert(second.address(), now);
        node.networks
            .get_mut(&NETWORK_ID)
            .expect("network joined")
            .multicast_announcements
            .insert(first.address(), now);

        node.announce_multicast_locked(NETWORK_ID, now);

        assert_eq!(
            recorder.destinations(),
            vec![second.address()],
            "the peer announced within the last period is skipped"
        );
    }

    #[test]
    fn a_gather_waits_for_the_target_identity_and_the_rate_limit() {
        let (mut node, recorder) = test_node();
        let now = SystemTime::now();
        let controller = Identity::generate();
        let controller_network = (controller.address().uint64() << 24) | 0x0012_3456;
        let root = add_root_path(&mut node, now);
        let mut network = Network::new(controller_network);
        network.status = NetworkStatus::Ok;
        network.config = crate::network_config::NetworkConfigData {
            version: 1,
            network_id: controller_network,
            network_type: NetworkType::PUBLIC,
            mtu: DEFAULT_NETWORK_MTU,
            multicast_limit: 32,
            ..Default::default()
        };
        node.networks.insert(controller_network, network);
        let group = MulticastGroup::new(Mac::new(0xffff_ffff_ffff), 0xc000_0201);

        node.gather_multicast_locked(controller_network, group, 32, now).expect("the first gather");
        node.gather_multicast_locked(controller_network, group, 32, now + Duration::from_millis(1))
            .expect("the second gather");

        assert_eq!(node.pending_transmits.len(), 2, "the controller is unknown, so its gathers wait for WHOIS");
        assert!(recorder.destinations().contains(&root), "the root received a gather through its path");

        learn_member_in(&mut node, controller_network, group, Address::new(1), now);
        let sent = recorder.datagrams();
        node.gather_multicast_locked(controller_network, group, 32, now + Duration::from_millis(2))
            .expect("a learned group is rate limited");
        assert_eq!(recorder.datagrams(), sent, "known membership does not bypass the gather period");
        assert_eq!(node.pending_transmits.len(), 2);

        recorder.peers.lock().expect("lock").insert(controller.address(), controller.clone());
        publish_peer(&mut node, &controller, now);

        assert_eq!(node.pending_transmits.len(), 0, "the deferred gathers went out once the identity was known");
    }

    #[test]
    fn a_truncated_optional_source_is_refused() {
        let (mut node, recorder) = test_node();
        let now = SystemTime::now();
        let peer = add_peer(&mut node, &recorder, now);
        let mut packet =
            Packet::new(node.identity.address(), peer.address(), Verb::MulticastFrame).expect("a packet header");
        packet.append_u64(NETWORK_ID).expect("network ID");
        packet.append_u8(0x04).expect("the explicit-source flag");

        let outcome = node.handle_multicast_frame_locked(
            PathKey::new(TEST_SOCKET, PEER_ENDPOINT.parse().expect("endpoint")),
            peer.address(),
            &packet,
            now,
        );

        assert_eq!(outcome.err(), Some(unusable(NodeError::InvalidPacket)));
    }

    #[test]
    fn a_multicast_frame_body_reads_its_adi_after_the_destination_mac() {
        let destination = Mac::new(0x0100_5e00_0001);
        let adi: u32 = 0xdead_beef;
        let mut raw = Vec::new();
        raw.extend_from_slice(&destination.bytes());
        raw.extend_from_slice(&adi.to_be_bytes());
        raw.extend_from_slice(&0x0806u16.to_be_bytes());
        raw.extend_from_slice(&[0xaa, 0xbb]);

        let body = parse_multicast_frame_body(Address::new(1), NETWORK_ID, &raw, 0, 0).expect("a frame body");

        assert_eq!(body.group, MulticastGroup::new(destination, adi));
        assert_eq!(body.ether_type, 0x0806);
        assert_eq!(body.payload, vec![0xaa, 0xbb]);
        assert_eq!(body.gather_limit, 0);
    }

    #[test]
    fn a_multicast_frame_body_places_its_fields_after_the_optional_ones() {
        let source = Mac::new(0x0200_0000_00ff);
        let destination = Mac::new(0x0100_5e00_0002);
        let mut raw = Vec::new();
        raw.extend_from_slice(&7u32.to_be_bytes());
        raw.extend_from_slice(&source.bytes());
        raw.extend_from_slice(&destination.bytes());
        raw.extend_from_slice(&9u32.to_be_bytes());
        raw.extend_from_slice(&0x0800u16.to_be_bytes());

        let body = parse_multicast_frame_body(Address::new(1), NETWORK_ID, &raw, 0x02 | 0x04, 0).expect("a body");

        assert_eq!(body.gather_limit, 7);
        assert_eq!(body.source, source);
        assert_eq!(body.group, MulticastGroup::new(destination, 9));
    }

    #[test]
    fn a_group_the_peer_no_longer_wants_is_forgotten() {
        let (mut node, recorder) = test_node();
        let now = SystemTime::now();
        let peer = add_peer(&mut node, &recorder, now);
        let group = broadcast_group();
        learn_member(&mut node, group, peer.address(), now);

        node.forget_multicast_group_locked(NETWORK_ID, peer.address(), group);

        assert!(
            !node.networks.get(&NETWORK_ID).expect("network joined").multicast[&group].contains_key(&peer.address())
        );
    }

    #[test]
    fn subscriptions_are_validated_and_recorded() {
        let (mut node, _recorder) = test_node();
        let now = SystemTime::now();
        let group = broadcast_group();

        assert_eq!(
            node.subscribe_multicast(NETWORK_ID, MulticastGroup::new(Mac::new(0x0200_0000_0001), 0), now),
            Err(NodeError::InvalidPacket)
        );
        assert_eq!(node.subscribe_multicast(0x1234_5678_90ab_cdef, group, now), Err(NodeError::NetworkNotFound));
        node.subscribe_multicast(NETWORK_ID, group, now).expect("a group subscription");
        assert!(node.networks.get(&NETWORK_ID).expect("network joined").multicast_subscriptions.contains(&group));

        node.unsubscribe_multicast(NETWORK_ID, group).expect("an unsubscription");
        assert!(!node.networks.get(&NETWORK_ID).expect("network joined").multicast_subscriptions.contains(&group));
        assert_eq!(node.unsubscribe_multicast(0x1234_5678_90ab_cdef, group), Err(NodeError::NetworkNotFound));
    }

    #[test]
    fn the_broadcast_group_is_announced_only_when_the_network_enables_it() {
        let (node, _recorder) = test_node();
        assert_eq!(node.subscribed_multicast_groups_locked(NETWORK_ID).len(), 2, "one group per assigned address");

        let (mut node, _recorder) = test_node();
        node.networks.get_mut(&NETWORK_ID).expect("network joined").config.flags |=
            NETWORK_CONFIG_FLAG_ENABLE_BROADCAST;
        let groups = node.subscribed_multicast_groups_locked(NETWORK_ID);
        assert_eq!(groups.len(), 3);
        assert!(groups.contains(&broadcast_group()));
    }
}

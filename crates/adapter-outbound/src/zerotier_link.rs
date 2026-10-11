//! [`Link`] bridges a userspace IP stack to a ZeroTier virtual Ethernet segment.
//!
//! The bridge covers ARP and NDP resolution, IPv4/IPv6 source selection, the MTU and destination
//! validation policy, and the IP-multicast bookkeeping that bounds which Ethernet groups the link
//! may use.
//!
//! The public surface is [`Link::new`], [`Link::apply_network_config`],
//! [`Link::validate_destination`] / [`Link::source_for`], [`Link::write_packet`],
//! [`Link::handle_frame`] and [`Link::process_background_tasks`], with an explicit
//! `now: SystemTime` argument instead of an implicit clock.
//!
//! The engine node is a [`MulticastSubscriber`]: [`FrameSender::multicast_subscriber`] reproduces
//! the type assertion, so the link's desired group set is mirrored onto the node's announcements.
//! A sender that is not a subscriber still follows the fallback of tracking the desired set
//! without reconciling it.
//!
//! A missing frame sender has no counterpart: the sender is a generic parameter, so a missing one
//! does not typecheck.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use ipnet::IpNet;
use murmur_zerotier::address::Address;
use murmur_zerotier::frame::{Frame, ETHER_TYPE_ARP, ETHER_TYPE_IPV4, ETHER_TYPE_IPV6};
use murmur_zerotier::mac::{mac_for_address, Mac};
use murmur_zerotier::managed_ip::{address_from_rfc4193, address_from_six_plane};
use murmur_zerotier::network_config::{
    NetworkConfigData, NetworkRoute, DEFAULT_NETWORK_MTU, MAX_NETWORK_MTU, MIN_NETWORK_MTU,
    NETWORK_CONFIG_FLAG_ENABLE_BROADCAST, NETWORK_CONFIG_FLAG_ENABLE_IPV6_NDP_EMULATION,
};
use murmur_zerotier::node::NodeError;

const NEIGHBOR_REQUEST_PERIOD: Duration = Duration::from_secs(1);
const NEIGHBOR_CACHE_REFRESH_AFTER: Duration = Duration::from_secs(10 * 60);
const NEIGHBOR_DELAY_PROBE_TIME: Duration = Duration::from_secs(5);
const NEIGHBOR_MAXIMUM_PROBES: u8 = 3;
const PENDING_NEIGHBOR_EXPIRATION: Duration = Duration::from_secs(10);
const MAX_NEIGHBOR_CACHE_ENTRIES: usize = 4096;
const MAX_PENDING_DESTINATIONS: usize = 256;
const MAX_PENDING_PACKETS_PER_DESTINATION: usize = 16 * 1024;
const MAX_PENDING_NEIGHBOR_PACKETS: usize = 32 * 1024;
const MAX_PENDING_NEIGHBOR_BYTES: usize = 4 * 1024 * 1024;
const MAX_PENDING_NEIGHBOR_BYTES_PER_DESTINATION: usize = MAX_PENDING_NEIGHBOR_BYTES / 4;
const MAX_MULTICAST_GROUPS: usize = 4096;
const MAX_REPORTED_MULTICAST_SOURCES: usize = 4096;
const MEMBERSHIP_DEFAULT_ROBUSTNESS: u32 = 2;
const MEMBERSHIP_DEFAULT_QUERY_INTERVAL: Duration = Duration::from_secs(125);
const MEMBERSHIP_DEFAULT_RESPONSE_TIME: Duration = Duration::from_secs(10);
const IPV4_MEMBERSHIP_INVALID_FRAGMENT_BITS: u16 = 0xbfff;
/// The all-ones Ethernet destination.
fn broadcast_mac() -> Mac {
    Mac::new(0xffff_ffff_ffff)
}
/// One millisecond, the unit the membership code decoders take.
const MILLI: Duration = Duration::from_millis(1);

/// Reports a link operation that could not complete. Every message is the engine's own error text.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("invalid ZeroTier network ID")]
    InvalidNetworkId,
    #[error("ZeroTier IP link is not configured")]
    NotConfigured,
    #[error("ZeroTier network configuration is for {have:016x}, want {want:016x}")]
    WrongNetwork { have: u64, want: u64 },
    #[error("ZeroTier controller assigned no managed addresses")]
    NoManagedAddresses,
    #[error("invalid ZeroTier managed address {0}")]
    InvalidManagedAddress(IpNet),
    #[error("invalid ZeroTier destination address")]
    InvalidDestination,
    #[error("invalid IPv6 multicast destination")]
    InvalidIpv6Multicast,
    #[error("IPv6 interface-local multicast cannot leave the host")]
    InterfaceLocalMulticast,
    #[error("ZeroTier network has multicast disabled")]
    MulticastDisabled,
    #[error("ZeroTier network has broadcast disabled")]
    BroadcastDisabled,
    #[error("destination {0} is outside ZeroTier managed routes")]
    OutsideManagedRoutes(IpAddr),
    #[error("ZeroTier network has no managed IPv4 address")]
    NoManagedIpv4,
    #[error("ZeroTier network has no managed IPv6 address")]
    NoManagedIpv6,
    #[error("short IP packet")]
    ShortIpPacket,
    #[error("IP packet length {0} exceeds ZeroTier MTU {1}")]
    PacketExceedsMtu(usize, u32),
    #[error("invalid IPv4 header length")]
    InvalidIpv4HeaderLength,
    #[error("invalid IPv4 packet length")]
    InvalidIpv4PacketLength,
    #[error("short IPv6 packet")]
    ShortIpv6Packet,
    #[error("invalid IPv6 packet length")]
    InvalidIpv6PacketLength,
    #[error("unsupported IP version")]
    UnsupportedIpVersion,
    #[error("too many unresolved ZeroTier neighbor destinations")]
    TooManyUnresolvedDestinations,
    #[error("ZeroTier unresolved neighbor destination queue is full")]
    DestinationQueueFull,
    #[error("ZeroTier unresolved neighbor queue is full")]
    NeighborQueueFull,
    #[error("ZeroTier IPv4 route has a non-IPv4 next hop")]
    NonIpv4NextHop,
    #[error("ZeroTier route has an invalid neighbor address")]
    InvalidNeighborAddress,
    #[error("too many ZeroTier IP multicast groups")]
    TooManyMulticastGroups,
    #[error(transparent)]
    Node(#[from] NodeError),
    #[error("{first}\n{second}")]
    Joined { first: Box<Self>, second: Box<Self> },
}

impl LinkError {
    /// A join whose message is the two errors separated by a newline.
    fn join(self, other: Self) -> Self {
        Self::Joined { first: Box::new(self), second: Box::new(other) }
    }
}

/// The link addresses a group by MAC alone; the engine keys it by MAC and ADI.
pub use murmur_zerotier::frame::MulticastGroup;

/// A `Node` satisfies this through [`FrameSender::send_frame`].
///
/// The sender's address is not a trait method: a node's address never changes,
/// so [`Link::new`] takes it once at construction.
pub trait FrameSender {
    fn send_frame(
        &mut self,
        network_id: u64,
        destination: Mac,
        ether_type: u16,
        payload: &[u8],
        now: SystemTime,
    ) -> Result<(), NodeError>;
    /// The multicast-subscriber type assertion. The default is the "sender
    /// without multicast subscription support", whose group set the link tracks but cannot apply.
    fn multicast_subscriber(&mut self) -> Option<&mut dyn MulticastSubscriber> {
        None
    }
}

pub trait MulticastSubscriber {
    fn subscribe_multicast(&mut self, network_id: u64, group: MulticastGroup) -> Result<(), NodeError>;
    fn unsubscribe_multicast(&mut self, network_id: u64, group: MulticastGroup) -> Result<(), NodeError>;
}

/// The engine node performs the subscription and unsubscription.
impl MulticastSubscriber for murmur_zerotier::node::Node {
    fn subscribe_multicast(&mut self, network_id: u64, group: MulticastGroup) -> Result<(), NodeError> {
        Self::subscribe_multicast(self, network_id, group, SystemTime::now())
    }

    fn unsubscribe_multicast(&mut self, network_id: u64, group: MulticastGroup) -> Result<(), NodeError> {
        Self::unsubscribe_multicast(self, network_id, group)
    }
}

impl FrameSender for murmur_zerotier::node::Node {
    fn send_frame(
        &mut self,
        network_id: u64,
        destination: Mac,
        ether_type: u16,
        payload: &[u8],
        now: SystemTime,
    ) -> Result<(), NodeError> {
        Self::send_frame(self, network_id, destination, ether_type, payload, now)
    }

    fn multicast_subscriber(&mut self) -> Option<&mut dyn MulticastSubscriber> {
        Some(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NeighborState {
    Reachable,
    Delay,
    Probe,
}

#[derive(Debug, Clone, Copy)]
struct NeighborEntry {
    mac: Mac,
    deadline: SystemTime,
    state: NeighborState,
    probes: u8,
}

/// A zero `requested_at` is `None`.
#[derive(Debug)]
struct PendingNeighbor {
    packets: Vec<Vec<u8>>,
    bytes: usize,
    created_at: SystemTime,
    requested_at: Option<SystemTime>,
    ether_type: u16,
    source: IpAddr,
}

#[derive(Debug, Default, Clone)]
struct ReportedMulticastFilter {
    exclude: bool,
    incomplete: bool,
    last_report: Option<SystemTime>,
    query_deadline: Option<SystemTime>,
    sources: BTreeSet<IpAddr>,
}

impl ReportedMulticastFilter {
    fn active(&self) -> bool {
        self.exclude || self.incomplete || !self.sources.is_empty()
    }
    fn add_sources(&mut self, sources: &[IpAddr]) {
        for source in sources {
            if self.sources.contains(source) {
                continue;
            }
            if self.sources.len() >= MAX_REPORTED_MULTICAST_SOURCES {
                self.incomplete = true;
                return;
            }
            self.sources.insert(*source);
        }
    }
}

struct ReportedMembershipRecord {
    group: IpAddr,
    record_type: u8,
    sources: Vec<IpAddr>,
}

/// What one record did to the retained filter of its group.
enum RecordOutcome {
    Skipped,
    Updated(ReportedMulticastFilter),
    Removed,
    Unchanged,
    Unrecognized,
}

/// Two mutexes are absent: the adapter drives one link from one runtime loop, so every
/// method takes `&mut self` instead.
#[derive(Debug)]
pub struct Link {
    network_id: u64,
    sender_address: Address,
    configured: bool,
    flags: u64,
    mtu: u32,
    multicast_limit: u32,
    assigned: Vec<IpNet>,
    routes: Vec<NetworkRoute>,
    neighbor_cache: BTreeMap<IpAddr, NeighborEntry>,
    neighbor_pending: BTreeMap<IpAddr, PendingNeighbor>,
    pending_neighbor_packets: usize,
    pending_neighbor_bytes: usize,
    reported_memberships: BTreeMap<IpAddr, ReportedMulticastFilter>,
    automatic_subscriptions: BTreeMap<IpAddr, MulticastGroup>,
    active_multicast: BTreeSet<MulticastGroup>,
    multicast_dirty: bool,
}

/// `sender_address` is the sender's address, which is immutable for a
/// node's lifetime; the sender itself arrives per call because the engine's frame methods need
/// `&mut Node`.
pub fn new(network_id: u64, sender_address: Address) -> Result<Link, LinkError> {
    Link::new(network_id, sender_address)
}

impl Link {
    pub fn new(network_id: u64, sender_address: Address) -> Result<Self, LinkError> {
        if network_id == 0 {
            return Err(LinkError::InvalidNetworkId);
        }
        Ok(Self {
            network_id,
            sender_address,
            configured: false,
            flags: 0,
            mtu: 0,
            multicast_limit: 0,
            assigned: Vec::new(),
            routes: Vec::new(),
            neighbor_cache: BTreeMap::new(),
            neighbor_pending: BTreeMap::new(),
            pending_neighbor_packets: 0,
            pending_neighbor_bytes: 0,
            reported_memberships: BTreeMap::new(),
            automatic_subscriptions: BTreeMap::new(),
            active_multicast: BTreeSet::new(),
            multicast_dirty: false,
        })
    }

    /// `mtu` is the adapter's effective MTU, clamped here exactly as the link clamps it.
    pub fn apply_network_config<S: FrameSender>(
        &mut self,
        sender: &mut S,
        config: &NetworkConfigData,
        mtu: u32,
    ) -> Result<(), LinkError> {
        if config.network_id != self.network_id {
            return Err(LinkError::WrongNetwork { have: config.network_id, want: self.network_id });
        }
        if config.assigned.is_empty() {
            return Err(LinkError::NoManagedAddresses);
        }
        let assigned = normalize_assigned_addresses(&config.assigned)?;
        let routes = normalize_routes(&config.routes, &assigned);
        let mtu = clamp_mtu(mtu);
        let automatic = automatic_multicast_subscriptions(&assigned);

        let interface_changed = self.configured && (!prefixes_equal(&self.assigned, &assigned) || self.mtu != mtu);
        let previous_automatic = std::mem::take(&mut self.automatic_subscriptions);
        let previous_reported = std::mem::take(&mut self.reported_memberships);
        self.automatic_subscriptions = automatic;
        if interface_changed {
            self.reported_memberships.clear();
        }
        if let Err(err) = self.refresh_multicast_groups(sender) {
            self.automatic_subscriptions = previous_automatic;
            self.reported_memberships = previous_reported;
            return Err(match self.sync_multicast_groups(sender) {
                Ok(()) => err,
                Err(sync) => err.join(sync),
            });
        }
        if !prefixes_equal(&self.assigned, &assigned) || !routes_equal(&self.routes, &routes) || self.mtu != mtu {
            self.neighbor_cache.clear();
            self.neighbor_pending.clear();
            self.pending_neighbor_packets = 0;
            self.pending_neighbor_bytes = 0;
        }
        self.flags = config.flags;
        self.mtu = mtu;
        self.multicast_limit = config.multicast_limit;
        self.assigned = assigned;
        self.routes = routes;
        self.configured = true;
        Ok(())
    }

    pub fn validate_destination(&self, destination: IpAddr) -> Result<(), LinkError> {
        self.source_for(destination).map(|_| ())
    }

    pub fn source_for(&self, destination: IpAddr) -> Result<IpAddr, LinkError> {
        self.source_for_inner(destination)
    }

    fn source_for_inner(&self, destination: IpAddr) -> Result<IpAddr, LinkError> {
        if !self.configured {
            return Err(LinkError::NotConfigured);
        }
        let destination = unmap(destination);
        let next_hop = if destination.is_multicast() {
            if let IpAddr::V6(v6) = destination {
                if !valid_ipv6_multicast_group(v6) {
                    return Err(LinkError::InvalidIpv6Multicast);
                }
                if v6.octets()[1] & 0x0f == 1 {
                    return Err(LinkError::InterfaceLocalMulticast);
                }
            }
            if self.multicast_limit == 0 {
                return Err(LinkError::MulticastDisabled);
            }
            destination
        } else if self.is_ipv4_broadcast(destination) {
            if self.flags & NETWORK_CONFIG_FLAG_ENABLE_BROADCAST == 0 {
                return Err(LinkError::BroadcastDisabled);
            }
            if self.multicast_limit == 0 {
                return Err(LinkError::MulticastDisabled);
            }
            destination
        } else {
            self.route_for(destination).ok_or(LinkError::OutsideManagedRoutes(destination))?
        };
        if next_hop.is_ipv4() {
            return self.local_ipv4_for(IpAddr::V4(Ipv4Addr::UNSPECIFIED), next_hop).ok_or(LinkError::NoManagedIpv4);
        }
        if next_hop.is_ipv6() {
            return self.local_ipv6_for(IpAddr::V6(Ipv6Addr::UNSPECIFIED), next_hop).ok_or(LinkError::NoManagedIpv6);
        }
        Err(LinkError::InvalidDestination)
    }

    /// Sends one layer-3 packet over the virtual network.
    pub fn write_packet<S: FrameSender>(
        &mut self,
        sender: &mut S,
        packet: &[u8],
        now: SystemTime,
    ) -> Result<(), LinkError> {
        if !self.configured {
            return Err(LinkError::NotConfigured);
        }
        let version = validate_ip_packet(packet, self.mtu)?;
        match version {
            4 => {
                let source = IpAddr::V4(ipv4_at(packet, 12).ok_or(LinkError::ShortIpPacket)?);
                let destination = IpAddr::V4(ipv4_at(packet, 16).ok_or(LinkError::ShortIpPacket)?);
                if let Some(mac) = ipv4_multicast_mac(destination) {
                    // Membership is local interface state: the node retains the subscription so
                    // it is already available when multicast is enabled again.
                    self.handle_ipv4_membership(sender, packet, now);
                    self.source_for_inner(destination)?;
                    return sender
                        .send_frame(self.network_id, mac, ETHER_TYPE_IPV4, packet, now)
                        .map_err(LinkError::from);
                }
                if self.is_ipv4_broadcast(destination) {
                    self.source_for_inner(destination)?;
                    return sender
                        .send_frame(self.network_id, broadcast_mac(), ETHER_TYPE_IPV4, packet, now)
                        .map_err(LinkError::from);
                }
                let next_hop = self.route_for(destination).ok_or(LinkError::OutsideManagedRoutes(destination))?;
                self.send_ipv4_packet(sender, source, next_hop, packet, now)
            }
            6 => {
                let destination = IpAddr::V6(ipv6_at(packet, 24).ok_or(LinkError::ShortIpv6Packet)?);
                let source = IpAddr::V6(ipv6_at(packet, 8).ok_or(LinkError::ShortIpv6Packet)?);
                if destination.is_multicast() {
                    self.handle_ipv6_membership(sender, packet, now);
                    self.source_for_inner(destination)?;
                    return sender
                        .send_frame(self.network_id, ipv6_multicast_mac(destination), ETHER_TYPE_IPV6, packet, now)
                        .map_err(LinkError::from);
                }
                let next_hop = self.route_for(destination).ok_or(LinkError::OutsideManagedRoutes(destination))?;
                if let Some(mac) = self.managed_ipv6_mac(next_hop) {
                    return sender
                        .send_frame(self.network_id, mac, ETHER_TYPE_IPV6, packet, now)
                        .map_err(LinkError::from);
                }
                self.send_ipv6_packet(sender, source, next_hop, packet, now)
            }
            _ => Err(LinkError::UnsupportedIpVersion),
        }
    }

    /// The IP packet a received frame carries, if any.
    pub fn handle_frame<S: FrameSender>(
        &mut self,
        sender: &mut S,
        frame: &Frame,
        now: SystemTime,
    ) -> Result<Option<Vec<u8>>, LinkError> {
        if frame.network_id != self.network_id {
            return Ok(None);
        }
        match frame.ether_type {
            ETHER_TYPE_ARP => {
                self.handle_arp(sender, frame, now)?;
                Ok(None)
            }
            ETHER_TYPE_IPV6 => {
                if self.inspect_inbound_ipv6_membership(&frame.payload, now) {
                    return Ok(None);
                }
                if self.handle_ndp(sender, frame, now)? {
                    return Ok(None);
                }
                Ok(Some(frame.payload.clone()))
            }
            ETHER_TYPE_IPV4 => {
                if self.inspect_inbound_ipv4_membership(&frame.payload, now) {
                    return Ok(None);
                }
                Ok(Some(frame.payload.clone()))
            }
            _ => Ok(None),
        }
    }

    fn send_ipv4_packet<S: FrameSender>(
        &mut self,
        sender: &mut S,
        source: IpAddr,
        next_hop: IpAddr,
        packet: &[u8],
        now: SystemTime,
    ) -> Result<(), LinkError> {
        self.clean_neighbors(now);
        if let Some((mac, probe)) = self.neighbor_for_send(next_hop, now) {
            let sent = sender.send_frame(self.network_id, mac, ETHER_TYPE_IPV4, packet, now).map_err(LinkError::from);
            if probe {
                // A failed probe does not change a packet already sent through the stale
                // mapping; the bounded state machine still advances.
                self.send_neighbor_probe(sender, source, next_hop, Some(mac), now)?;
            }
            return sent;
        }
        let request = self.enqueue_pending_neighbor(source, next_hop, ETHER_TYPE_IPV4, packet, now)?;
        if request {
            return self.send_neighbor_probe(sender, source, next_hop, None, now);
        }
        Ok(())
    }

    fn send_arp_request<S: FrameSender>(
        &self,
        sender: &mut S,
        source: IpAddr,
        target: IpAddr,
        destination: Option<Mac>,
        now: SystemTime,
    ) -> Result<(), LinkError> {
        let IpAddr::V4(target) = target else {
            return Err(LinkError::NonIpv4NextHop);
        };
        let local = self.local_ipv4_for(source, IpAddr::V4(target)).ok_or(LinkError::NoManagedIpv4)?;
        let IpAddr::V4(local) = local else {
            return Err(LinkError::NoManagedIpv4);
        };
        let mut payload = [0u8; 28];
        payload[0..2].copy_from_slice(&1u16.to_be_bytes());
        payload[2..4].copy_from_slice(&ETHER_TYPE_IPV4.to_be_bytes());
        payload[4] = 6;
        payload[5] = 4;
        payload[6..8].copy_from_slice(&1u16.to_be_bytes());
        payload[8..14].copy_from_slice(&mac_for_address(self.sender_address, self.network_id).bytes());
        payload[14..18].copy_from_slice(&local.octets());
        payload[24..28].copy_from_slice(&target.octets());
        let destination = destination.unwrap_or_else(broadcast_mac);
        sender.send_frame(self.network_id, destination, ETHER_TYPE_ARP, &payload, now).map_err(LinkError::from)
    }

    fn handle_arp<S: FrameSender>(&mut self, sender: &mut S, frame: &Frame, now: SystemTime) -> Result<(), LinkError> {
        let Some(payload) = frame.payload.first_chunk::<28>() else {
            return Ok(());
        };
        if u16::from_be_bytes([payload[0], payload[1]]) != 1
            || u16::from_be_bytes([payload[2], payload[3]]) != ETHER_TYPE_IPV4
            || payload[4] != 6
            || payload[5] != 4
        {
            return Ok(());
        }
        let operation = u16::from_be_bytes([payload[6], payload[7]]);
        if operation != 1 && operation != 2 {
            return Ok(());
        }
        let Ok(sender_mac) = Mac::from_bytes(&payload[8..14]) else {
            return Ok(());
        };
        if sender_mac != frame.source {
            return Ok(());
        }
        let sender_ip = IpAddr::V4(Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]));
        let target_ip = IpAddr::V4(Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]));
        let learned = self.learn_neighbor(sender, sender_ip, sender_mac, true, now);
        if operation != 1 {
            return learned;
        }
        let Some(local_ip) = self.local_ipv4_for(IpAddr::V4(Ipv4Addr::UNSPECIFIED), target_ip) else {
            return learned;
        };
        if target_ip != local_ip {
            return learned;
        }
        let IpAddr::V4(local) = local_ip else {
            return learned;
        };
        let IpAddr::V4(sender_v4) = sender_ip else {
            return learned;
        };
        let mut reply = [0u8; 28];
        reply[0..8].copy_from_slice(&payload[0..8]);
        reply[6..8].copy_from_slice(&2u16.to_be_bytes());
        reply[8..14].copy_from_slice(&mac_for_address(self.sender_address, self.network_id).bytes());
        reply[14..18].copy_from_slice(&local.octets());
        reply[18..24].copy_from_slice(&sender_mac.bytes());
        reply[24..28].copy_from_slice(&sender_v4.octets());
        let sent = sender.send_frame(self.network_id, sender_mac, ETHER_TYPE_ARP, &reply, now).map_err(LinkError::from);
        merge(learned, sent)
    }

    fn learn_neighbor<S: FrameSender>(
        &mut self,
        sender: &mut S,
        address: IpAddr,
        mac: Mac,
        override_existing: bool,
        now: SystemTime,
    ) -> Result<(), LinkError> {
        if address.is_unspecified() || address.is_multicast() || mac.uint64() == 0 || mac.is_multicast() {
            return Ok(());
        }
        self.clean_neighbors(now);
        if let Some(entry) = self.neighbor_cache.get(&address) {
            if entry.mac != mac && !override_existing {
                return Ok(());
            }
        }
        if !self.neighbor_cache.contains_key(&address) && self.neighbor_cache.len() >= MAX_NEIGHBOR_CACHE_ENTRIES {
            self.evict_oldest_neighbor();
        }
        self.neighbor_cache.insert(
            address,
            NeighborEntry {
                mac,
                deadline: now + NEIGHBOR_CACHE_REFRESH_AFTER,
                state: NeighborState::Reachable,
                probes: 0,
            },
        );
        let pending = self.remove_pending_neighbor(address);
        let mut result = Ok(());
        for packet in pending.packets {
            result = merge(
                result,
                sender.send_frame(self.network_id, mac, pending.ether_type, &packet, now).map_err(LinkError::from),
            );
        }
        result
    }

    fn local_ipv4_for(&self, source: IpAddr, target: IpAddr) -> Option<IpAddr> {
        if source.is_ipv4() {
            for prefix in &self.assigned {
                if prefix.addr().is_ipv4() && prefix.addr() == source {
                    return Some(source);
                }
            }
        }
        let mut fallback = None;
        for prefix in &self.assigned {
            let IpAddr::V4(candidate) = prefix.addr() else {
                continue;
            };
            let candidate = IpAddr::V4(candidate);
            if fallback.is_none() {
                fallback = Some(candidate);
            }
            if target.is_ipv4() && prefix.contains(&target) {
                return Some(candidate);
            }
        }
        fallback
    }

    fn local_ipv6_for(&self, source: IpAddr, target: IpAddr) -> Option<IpAddr> {
        if let IpAddr::V6(source) = source {
            if !source.is_unspecified() {
                for prefix in &self.assigned {
                    if prefix.addr().is_ipv6() && prefix.addr() == IpAddr::V6(source) {
                        return Some(IpAddr::V6(source));
                    }
                }
            }
        }
        let mut fallback = None;
        for prefix in &self.assigned {
            let IpAddr::V6(candidate) = prefix.addr() else {
                continue;
            };
            let candidate = IpAddr::V6(candidate);
            if fallback.is_none() {
                fallback = Some(candidate);
            }
            if target.is_ipv6() && prefix.contains(&target) {
                return Some(candidate);
            }
        }
        fallback
    }

    fn send_ipv6_packet<S: FrameSender>(
        &mut self,
        sender: &mut S,
        source: IpAddr,
        next_hop: IpAddr,
        packet: &[u8],
        now: SystemTime,
    ) -> Result<(), LinkError> {
        self.clean_neighbors(now);
        if let Some((mac, probe)) = self.neighbor_for_send(next_hop, now) {
            let sent = sender.send_frame(self.network_id, mac, ETHER_TYPE_IPV6, packet, now).map_err(LinkError::from);
            if probe {
                self.send_neighbor_probe(sender, source, next_hop, Some(mac), now)?;
            }
            return sent;
        }
        let request = self.enqueue_pending_neighbor(source, next_hop, ETHER_TYPE_IPV6, packet, now)?;
        if !request {
            return Ok(());
        }
        self.send_neighbor_probe(sender, source, next_hop, None, now)
    }

    /// Retains one packet while `next_hop` is unresolved and reports whether a new resolution
    /// request is due.
    fn enqueue_pending_neighbor(
        &mut self,
        source: IpAddr,
        next_hop: IpAddr,
        ether_type: u16,
        packet: &[u8],
        now: SystemTime,
    ) -> Result<bool, LinkError> {
        let (queued, queued_bytes) =
            self.neighbor_pending.get(&next_hop).map_or((0, 0), |pending| (pending.packets.len(), pending.bytes));
        if queued == 0 && self.neighbor_pending.len() >= MAX_PENDING_DESTINATIONS {
            return Err(LinkError::TooManyUnresolvedDestinations);
        }
        if queued >= MAX_PENDING_PACKETS_PER_DESTINATION
            || packet.len() > MAX_PENDING_NEIGHBOR_BYTES_PER_DESTINATION.saturating_sub(queued_bytes)
        {
            return Err(LinkError::DestinationQueueFull);
        }
        if self.pending_neighbor_packets >= MAX_PENDING_NEIGHBOR_PACKETS
            || packet.len() > MAX_PENDING_NEIGHBOR_BYTES.saturating_sub(self.pending_neighbor_bytes)
        {
            return Err(LinkError::NeighborQueueFull);
        }
        let pending = self.neighbor_pending.entry(next_hop).or_insert_with(|| PendingNeighbor {
            packets: Vec::new(),
            bytes: 0,
            created_at: now,
            requested_at: None,
            ether_type,
            source,
        });
        if pending.packets.is_empty() {
            pending.created_at = now;
            pending.ether_type = ether_type;
            pending.source = source;
        }
        pending.packets.push(packet.to_vec());
        pending.bytes += packet.len();
        self.pending_neighbor_packets += 1;
        self.pending_neighbor_bytes += packet.len();
        let request = pending.requested_at.is_none_or(|requested| elapsed(now, requested) >= NEIGHBOR_REQUEST_PERIOD);
        if request {
            pending.requested_at = Some(now);
        }
        Ok(request)
    }

    fn remove_pending_neighbor(&mut self, address: IpAddr) -> PendingNeighbor {
        let pending = self.neighbor_pending.remove(&address).unwrap_or(PendingNeighbor {
            packets: Vec::new(),
            bytes: 0,
            created_at: SystemTime::UNIX_EPOCH,
            requested_at: None,
            ether_type: 0,
            source: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        });
        self.pending_neighbor_packets -= pending.packets.len();
        self.pending_neighbor_bytes -= pending.bytes;
        pending
    }

    /// A usable mapping and whether it needs a probe.
    fn neighbor_for_send(&mut self, address: IpAddr, now: SystemTime) -> Option<(Mac, bool)> {
        let mut entry = self.neighbor_cache.get(&address).copied()?;
        if entry.state == NeighborState::Reachable {
            if now < entry.deadline {
                return Some((entry.mac, false));
            }
            // The packet that uses a stale entry goes out before the DELAY timer, so
            // upper-layer reachability confirmation has time to arrive.
            entry.state = NeighborState::Delay;
            entry.deadline = now + NEIGHBOR_DELAY_PROBE_TIME;
            self.neighbor_cache.insert(address, entry);
            return Some((entry.mac, false));
        }
        if now < entry.deadline {
            return Some((entry.mac, false));
        }
        if entry.state == NeighborState::Probe && entry.probes >= NEIGHBOR_MAXIMUM_PROBES {
            self.neighbor_cache.remove(&address);
            return None;
        }
        entry.state = NeighborState::Probe;
        entry.probes += 1;
        entry.deadline = now + NEIGHBOR_REQUEST_PERIOD;
        self.neighbor_cache.insert(address, entry);
        Some((entry.mac, true))
    }

    fn send_neighbor_probe<S: FrameSender>(
        &self,
        sender: &mut S,
        source: IpAddr,
        target: IpAddr,
        destination: Option<Mac>,
        now: SystemTime,
    ) -> Result<(), LinkError> {
        if target.is_ipv4() {
            return self.send_arp_request(sender, source, target, destination, now);
        }
        if !target.is_ipv6() {
            return Err(LinkError::InvalidNeighborAddress);
        }
        let local = self.local_ipv6_for(source, target).ok_or(LinkError::NoManagedIpv6)?;
        self.send_neighbor_solicitation(sender, local, target, destination, now)
    }

    fn send_neighbor_solicitation<S: FrameSender>(
        &self,
        sender: &mut S,
        source: IpAddr,
        target: IpAddr,
        destination_mac: Option<Mac>,
        now: SystemTime,
    ) -> Result<(), LinkError> {
        let (destination, destination_mac) = match destination_mac {
            Some(mac) if mac.uint64() != 0 => (target, mac),
            _ => {
                let destination = solicited_node_multicast(target);
                (destination, ipv6_multicast_mac(destination))
            }
        };
        let mut icmp = [0u8; 32];
        icmp[0] = 135;
        icmp[8..24].copy_from_slice(&octets16(target));
        icmp[24] = 1;
        icmp[25] = 1;
        icmp[26..32].copy_from_slice(&mac_for_address(self.sender_address, self.network_id).bytes());
        let packet = make_ipv6_icmp_packet(source, destination, &icmp);
        sender.send_frame(self.network_id, destination_mac, ETHER_TYPE_IPV6, &packet, now).map_err(LinkError::from)
    }

    /// Whether the frame was consumed as neighbor discovery.
    fn handle_ndp<S: FrameSender>(
        &mut self,
        sender: &mut S,
        frame: &Frame,
        now: SystemTime,
    ) -> Result<bool, LinkError> {
        let packet = &frame.payload;
        let Some(header) = packet.first_chunk::<40>() else {
            return Ok(false);
        };
        if header[0] >> 4 != 6 {
            return Ok(false);
        }
        let Some((icmp, protocol, fragmented)) = ipv6_payload(packet) else {
            return Ok(false);
        };
        let Some(&icmp_type) = icmp.first() else {
            return Ok(false);
        };
        if protocol != 58 {
            return Ok(false);
        }
        if icmp_type != 135 && icmp_type != 136 {
            return Ok(false);
        }
        if fragmented {
            return Ok(true);
        }
        if header[7] != 255 {
            return Ok(true);
        }
        let Some(icmp_header) = icmp.first_chunk::<8>() else {
            return Ok(true);
        };
        let mut source_raw = [0u8; 16];
        source_raw.copy_from_slice(&header[8..24]);
        let mut destination_raw = [0u8; 16];
        destination_raw.copy_from_slice(&header[24..40]);
        let source = IpAddr::V6(Ipv6Addr::from(source_raw));
        let destination = IpAddr::V6(Ipv6Addr::from(destination_raw));
        if icmp_header[1] != 0 || icmpv6_checksum(source, destination, icmp) != 0 {
            return Ok(true);
        }
        match icmp_type {
            135 => self.handle_neighbor_solicitation(sender, frame, icmp, source, destination, now),
            136 => self.handle_neighbor_advertisement(sender, frame, icmp, source, destination, now),
            _ => Ok(false),
        }
    }

    /// The `Neighbor Solicitation` half of NDP handling.
    fn handle_neighbor_solicitation<S: FrameSender>(
        &mut self,
        sender: &mut S,
        frame: &Frame,
        icmp: &[u8],
        source: IpAddr,
        destination: IpAddr,
        now: SystemTime,
    ) -> Result<bool, LinkError> {
        let Some(header) = icmp.first_chunk::<24>() else {
            return Ok(true);
        };
        let mut target_raw = [0u8; 16];
        target_raw.copy_from_slice(&header[8..24]);
        let target = IpAddr::V6(Ipv6Addr::from(target_raw));
        if target.is_unspecified() || target.is_multicast() {
            return Ok(true);
        }
        let Some((option_mac, has_option)) = ndp_option_mac(icmp.get(24..).unwrap_or_default(), 1) else {
            return Ok(true);
        };
        if source.is_unspecified() {
            if has_option || destination != solicited_node_multicast(target) {
                return Ok(true);
            }
        } else {
            if source.is_multicast()
                || source.is_loopback()
                || (destination != target && destination != solicited_node_multicast(target))
            {
                return Ok(true);
            }
            if has_option && option_mac != Some(frame.source) {
                return Ok(true);
            }
            self.learn_neighbor(sender, source, frame.source, true, now)?;
        }
        if !self.is_local_address(target) {
            return Ok(true);
        }
        self.send_neighbor_advertisement(sender, target, source, Some(frame.source), now)?;
        Ok(true)
    }

    /// The `Neighbor Advertisement` half of NDP handling.
    fn handle_neighbor_advertisement<S: FrameSender>(
        &mut self,
        sender: &mut S,
        frame: &Frame,
        icmp: &[u8],
        source: IpAddr,
        destination: IpAddr,
        now: SystemTime,
    ) -> Result<bool, LinkError> {
        let Some(header) = icmp.first_chunk::<24>() else {
            return Ok(true);
        };
        let mut target_raw = [0u8; 16];
        target_raw.copy_from_slice(&header[8..24]);
        let target = IpAddr::V6(Ipv6Addr::from(target_raw));
        if source.is_unspecified()
            || source.is_multicast()
            || source.is_loopback()
            || target.is_unspecified()
            || target.is_multicast()
        {
            return Ok(true);
        }
        let all_nodes = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        if destination.is_unspecified() || (destination.is_multicast() && destination != all_nodes) {
            return Ok(true);
        }
        let flags = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        if flags & 0x4000_0000 != 0 && destination.is_multicast() {
            return Ok(true);
        }
        let mut mac = frame.source;
        let Some((option_mac, has_option)) = ndp_option_mac(icmp.get(24..).unwrap_or_default(), 2) else {
            return Ok(true);
        };
        if has_option {
            let Some(option_mac) = option_mac else {
                return Ok(true);
            };
            if option_mac != frame.source {
                return Ok(true);
            }
            mac = option_mac;
        }
        self.learn_neighbor(sender, target, mac, flags & 0x2000_0000 != 0, now)?;
        Ok(true)
    }

    fn send_neighbor_advertisement<S: FrameSender>(
        &self,
        sender: &mut S,
        target: IpAddr,
        destination: IpAddr,
        destination_mac: Option<Mac>,
        now: SystemTime,
    ) -> Result<(), LinkError> {
        let mut flags = 0x2000_0000u32;
        let (destination, destination_mac) = if destination.is_unspecified() {
            let destination = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
            (destination, ipv6_multicast_mac(destination))
        } else {
            flags |= 0x4000_0000;
            (destination, destination_mac.unwrap_or_else(broadcast_mac))
        };
        let mut icmp = [0u8; 32];
        icmp[0] = 136;
        icmp[4..8].copy_from_slice(&flags.to_be_bytes());
        icmp[8..24].copy_from_slice(&octets16(target));
        icmp[24] = 2;
        icmp[25] = 1;
        icmp[26..32].copy_from_slice(&mac_for_address(self.sender_address, self.network_id).bytes());
        let packet = make_ipv6_icmp_packet(target, destination, &icmp);
        sender.send_frame(self.network_id, destination_mac, ETHER_TYPE_IPV6, &packet, now).map_err(LinkError::from)
    }

    fn is_ipv4_broadcast(&self, address: IpAddr) -> bool {
        let IpAddr::V4(address) = address else {
            return false;
        };
        let value = u32::from(address);
        if value == 0xffff_ffff {
            return true;
        }
        for prefix in &self.assigned {
            if !prefix.addr().is_ipv4() || prefix.prefix_len() > 30 {
                continue;
            }
            let IpAddr::V4(prefix_address) = prefix.addr() else {
                continue;
            };
            let mask = u32::MAX << (32 - u32::from(prefix.prefix_len()));
            if value == (u32::from(prefix_address) & mask) | !mask {
                return true;
            }
        }
        false
    }

    fn is_local_address(&self, address: IpAddr) -> bool {
        self.assigned.iter().any(|prefix| prefix.addr() == address)
    }

    fn valid_igmp_report_source_locked(&self, address: IpAddr) -> bool {
        if address.is_unspecified() {
            return true;
        }
        match address {
            IpAddr::V4(address) => address.octets()[0] != 0 && self.is_local_address(IpAddr::V4(address)),
            IpAddr::V6(_) => false,
        }
    }

    fn clean_neighbors(&mut self, now: SystemTime) {
        let expired: Vec<IpAddr> = self
            .neighbor_pending
            .iter()
            .filter(|(_, pending)| elapsed(now, pending.created_at) >= PENDING_NEIGHBOR_EXPIRATION)
            .map(|(address, _)| *address)
            .collect();
        for address in expired {
            self.remove_pending_neighbor(address);
        }
    }

    /// Polled by the adapter's runtime loop.
    pub fn process_background_tasks<S: FrameSender>(
        &mut self,
        sender: &mut S,
        now: SystemTime,
    ) -> Result<(), LinkError> {
        struct Request {
            address: IpAddr,
            source: IpAddr,
            destination: Option<Mac>,
        }
        if !self.configured {
            return Err(LinkError::NotConfigured);
        }
        let mut requests: Vec<Request> = Vec::new();
        let mut result = Ok(());
        let now_expired: Vec<IpAddr> = self
            .neighbor_pending
            .iter()
            .filter(|(_, pending)| elapsed(now, pending.created_at) >= PENDING_NEIGHBOR_EXPIRATION)
            .map(|(address, _)| *address)
            .collect();
        for address in now_expired {
            self.remove_pending_neighbor(address);
        }
        let due: Vec<IpAddr> = self
            .neighbor_pending
            .iter()
            .filter(|(_, pending)| {
                pending.requested_at.is_none_or(|requested| elapsed(now, requested) >= NEIGHBOR_REQUEST_PERIOD)
            })
            .map(|(address, _)| *address)
            .collect();
        for address in due {
            if let Some(pending) = self.neighbor_pending.get_mut(&address) {
                pending.requested_at = Some(now);
                requests.push(Request { address, source: pending.source, destination: None });
            }
        }
        let probing: Vec<IpAddr> = self
            .neighbor_cache
            .iter()
            .filter(|(_, entry)| entry.state != NeighborState::Reachable)
            .map(|(address, _)| *address)
            .collect();
        for address in probing {
            if let Some((mac, probe)) = self.neighbor_for_send(address, now) {
                if probe {
                    // A zero `IpAddr`, which the source selection reads as "pick by target".
                    requests.push(Request {
                        address,
                        source: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        destination: Some(mac),
                    });
                }
            }
        }
        let membership_changed = self.expire_queried_memberships(now);
        if self.multicast_dirty || membership_changed {
            result = merge(result, self.sync_multicast_groups(sender));
        }
        for request in requests {
            result = merge(
                result,
                self.send_neighbor_probe(sender, request.source, request.address, request.destination, now),
            );
        }
        result
    }

    fn evict_oldest_neighbor(&mut self) {
        let oldest = self.neighbor_cache.iter().min_by_key(|(_, entry)| entry.deadline).map(|(address, _)| *address);
        if let Some(address) = oldest {
            self.neighbor_cache.remove(&address);
        }
    }

    fn sync_multicast_groups<S: FrameSender>(&mut self, sender: &mut S) -> Result<(), LinkError> {
        self.reconcile_multicast_groups(sender, false)
    }

    /// A node may have replaced its per-network state while the link's cache survived, so the
    /// subscription is repeated.
    fn refresh_multicast_groups<S: FrameSender>(&mut self, sender: &mut S) -> Result<(), LinkError> {
        self.reconcile_multicast_groups(sender, true)
    }

    fn reconcile_multicast_groups<S: FrameSender>(&mut self, sender: &mut S, refresh: bool) -> Result<(), LinkError> {
        let desired = self.active_multicast_groups();
        if desired.len() > MAX_MULTICAST_GROUPS {
            self.multicast_dirty = true;
            return Err(LinkError::TooManyMulticastGroups);
        }
        let Some(subscriber) = sender.multicast_subscriber() else {
            self.active_multicast = desired;
            self.multicast_dirty = false;
            return Ok(());
        };
        let mut result = Ok(());
        for group in self.active_multicast.clone() {
            if desired.contains(&group) {
                continue;
            }
            match subscriber.unsubscribe_multicast(self.network_id, group) {
                Err(err) => result = merge(result, Err(LinkError::from(err))),
                Ok(()) => {
                    self.active_multicast.remove(&group);
                }
            }
        }
        for group in desired {
            let exists = self.active_multicast.contains(&group);
            if exists && !refresh {
                continue;
            }
            match subscriber.subscribe_multicast(self.network_id, group) {
                Err(err) => {
                    result = merge(result, Err(LinkError::from(err)));
                    if refresh {
                        self.active_multicast.remove(&group);
                    }
                }
                Ok(()) => {
                    self.active_multicast.insert(group);
                }
            }
        }
        self.multicast_dirty = result.is_err();
        result
    }

    fn active_multicast_groups(&self) -> BTreeSet<MulticastGroup> {
        let mut groups = BTreeSet::new();
        for (address, filter) in &self.reported_memberships {
            if !filter.active() {
                continue;
            }
            if let Some(group) = multicast_group_for_ip(*address) {
                groups.insert(group);
            }
        }
        groups.extend(self.automatic_subscriptions.values().copied());
        groups
    }

    fn multicast_group_active(&self, wanted: MulticastGroup) -> bool {
        if self.automatic_subscriptions.values().any(|group| *group == wanted) {
            return true;
        }
        self.reported_memberships
            .iter()
            .any(|(address, filter)| filter.active() && multicast_group_for_ip(*address) == Some(wanted))
    }

    fn can_add_reported_multicast(&self, address: IpAddr) -> bool {
        if self.reported_memberships.contains_key(&address) {
            return true;
        }
        if self.reported_memberships.len() >= MAX_MULTICAST_GROUPS {
            return false;
        }
        let Some(group) = multicast_group_for_ip(address) else {
            return false;
        };
        self.multicast_group_active(group) || self.active_multicast_groups().len() < MAX_MULTICAST_GROUPS
    }

    /// Consumes a Query or a legacy Report, and observes a General Query's interval.
    fn inspect_inbound_ipv4_membership(&mut self, packet: &[u8], now: SystemTime) -> bool {
        let Some(header) = packet.first_chunk::<28>() else {
            return false;
        };
        if header[0] >> 4 != 4 || header[8] != 1 || header[9] != 2 {
            return false;
        }
        let header_length = usize::from(header[0] & 0x0f) * 4;
        let total_length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let Some(datagram) = packet.get(..total_length) else {
            return false;
        };
        let Some(ip_header) = datagram.get(..header_length) else {
            return false;
        };
        let Some(igmp) = datagram.get(header_length..) else {
            return false;
        };
        if header_length < 20
            || total_length < header_length + 8
            || internet_checksum(ip_header) != 0
            || u16::from_be_bytes([header[6], header[7]]) & IPV4_MEMBERSHIP_INVALID_FRAGMENT_BITS != 0
        {
            return false;
        }
        // Ethernet may pad a short IPv4 packet, so every check stops at the declared datagram
        // boundary.
        if internet_checksum(igmp) != 0 {
            return false;
        }
        let Some(router_alert) = ipv4_membership_options(ip_header.get(20..).unwrap_or_default()) else {
            return false;
        };
        let source = IpAddr::V4(Ipv4Addr::new(header[12], header[13], header[14], header[15]));
        let target = IpAddr::V4(Ipv4Addr::new(header[16], header[17], header[18], header[19]));
        let Some(&igmp_type) = igmp.first() else {
            return false;
        };
        match igmp_type {
            0x11 => {
                let Some((interval, version)) = ipv4_membership_query_interval(igmp) else {
                    return false;
                };
                let all_systems = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
                if !self.valid_igmp_query_source(source)
                    || (version >= 2 && !router_alert)
                    || !self.accepts_membership_control_destination(target, all_systems)
                {
                    return false;
                }
                self.observe_general_membership_query(false, now, interval);
                false
            }
            0x12 | 0x16 => {
                let Some(igmp_header) = igmp.first_chunk::<8>() else {
                    return false;
                };
                if !valid_igmp_report_source(source, self.is_ipv4_broadcast(source))
                    || (igmp_type == 0x16 && !router_alert)
                {
                    return false;
                }
                let group = IpAddr::V4(Ipv4Addr::new(igmp_header[4], igmp_header[5], igmp_header[6], igmp_header[7]));
                if multicast_group_for_ip(group).is_none()
                    || !self.accepts_membership_control_destination(target, group)
                {
                    return false;
                }
                true
            }
            _ => false,
        }
    }

    /// MLDv1 Done is not suppressive and stays visible to raw L3 listeners.
    fn inspect_inbound_ipv6_membership(&mut self, packet: &[u8], now: SystemTime) -> bool {
        let Some((icmp, protocol, _)) = ipv6_payload(packet) else {
            return false;
        };
        let Some(header) = packet.first_chunk::<40>() else {
            return false;
        };
        let Some(icmp_header) = icmp.first_chunk::<8>() else {
            return false;
        };
        if protocol != 58 || icmp_header[1] != 0 || header[7] != 1 || !ipv6_membership_router_alert(packet) {
            return false;
        }
        let mut source_raw = [0u8; 16];
        source_raw.copy_from_slice(&header[8..24]);
        let mut target_raw = [0u8; 16];
        target_raw.copy_from_slice(&header[24..40]);
        let source = IpAddr::V6(Ipv6Addr::from(source_raw));
        let target = IpAddr::V6(Ipv6Addr::from(target_raw));
        if icmpv6_checksum(source, target, icmp) != 0 {
            return false;
        }
        match icmp_header[0] {
            130 => {
                let Some((interval, true)) = ipv6_membership_query_interval(icmp) else {
                    return false;
                };
                let link_local = matches!(source, IpAddr::V6(v6) if v6.is_unicast_link_local());
                let all_nodes = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
                if !link_local || !self.accepts_membership_control_destination(target, all_nodes) {
                    return false;
                }
                self.observe_general_membership_query(true, now, interval);
                false
            }
            131 => {
                let link_local = matches!(source, IpAddr::V6(v6) if v6.is_unicast_link_local());
                let Some(group_header) = icmp.first_chunk::<24>() else {
                    return false;
                };
                if !source.is_unspecified() && !link_local {
                    return false;
                }
                let mut group_raw = [0u8; 16];
                group_raw.copy_from_slice(&group_header[8..24]);
                let group = IpAddr::V6(Ipv6Addr::from(group_raw));
                if multicast_group_for_ip(group).is_none()
                    || !self.accepts_membership_control_destination(target, group)
                {
                    return false;
                }
                true
            }
            _ => false,
        }
    }

    fn valid_igmp_query_source(&self, address: IpAddr) -> bool {
        let IpAddr::V4(v4) = address else {
            return false;
        };
        if v4.is_unspecified() || v4.is_multicast() || v4.is_loopback() || self.is_ipv4_broadcast(address) {
            return false;
        }
        v4.octets()[0] != 0
    }

    fn accepts_membership_control_destination(&self, target: IpAddr, expected: IpAddr) -> bool {
        let target = unmap(target);
        if target == expected || self.is_local_address(target) {
            return true;
        }
        if !target.is_multicast() {
            return false;
        }
        let reported = self.reported_memberships.get(&target).is_some_and(ReportedMulticastFilter::active);
        reported || self.automatic_subscriptions.contains_key(&target)
    }

    /// The earlier of overlapping observations wins, so periodic Queries cannot keep a stale
    /// subscription alive.
    fn observe_general_membership_query(&mut self, v6: bool, now: SystemTime, interval: Duration) {
        let deadline = now + interval;
        for (group, filter) in &mut self.reported_memberships {
            if group.is_ipv6() != v6 || !filter.active() {
                continue;
            }
            if filter.last_report.is_some_and(|report| report > now) {
                continue;
            }
            if filter.query_deadline.is_none_or(|current| deadline < current) {
                filter.query_deadline = Some(deadline);
            }
        }
    }

    /// A group without a query deadline is retained indefinitely.
    fn expire_queried_memberships(&mut self, now: SystemTime) -> bool {
        let expired: Vec<IpAddr> = self
            .reported_memberships
            .iter()
            .filter(|(_, filter)| filter.query_deadline.is_some_and(|deadline| now >= deadline))
            .map(|(group, _)| *group)
            .collect();
        for group in &expired {
            self.reported_memberships.remove(group);
        }
        !expired.is_empty()
    }

    fn handle_ipv4_membership<S: FrameSender>(&mut self, sender: &mut S, packet: &[u8], now: SystemTime) {
        let Some(header) = packet.first_chunk::<20>() else {
            return;
        };
        if header[9] != 2 || header[8] != 1 {
            return;
        }
        let header_length = usize::from(header[0] & 0x0f) * 4;
        let Some(ip_header) = packet.get(..header_length) else {
            return;
        };
        let Some(igmp) = packet.get(header_length..) else {
            return;
        };
        if header_length < 20 || igmp.len() < 8 || internet_checksum(ip_header) != 0 {
            return;
        }
        let source = IpAddr::V4(Ipv4Addr::new(header[12], header[13], header[14], header[15]));
        let target = IpAddr::V4(Ipv4Addr::new(header[16], header[17], header[18], header[19]));
        if u16::from_be_bytes([header[6], header[7]]) & IPV4_MEMBERSHIP_INVALID_FRAGMENT_BITS != 0 {
            return;
        }
        if internet_checksum(igmp) != 0 {
            return;
        }
        let Some(router_alert) = ipv4_membership_options(ip_header.get(20..).unwrap_or_default()) else {
            return;
        };
        let Some(igmp_header) = igmp.first_chunk::<8>() else {
            return;
        };
        match igmp_header[0] {
            0x12 | 0x16 => {
                if !self.valid_igmp_report_source_locked(source) {
                    return;
                }
                if igmp_header[0] == 0x16 && !router_alert {
                    return;
                }
                let group = IpAddr::V4(Ipv4Addr::new(igmp_header[4], igmp_header[5], igmp_header[6], igmp_header[7]));
                if target == group {
                    self.apply_legacy_membership(sender, group, true, now);
                }
            }
            0x17 => {
                if !self.is_local_address(source) || !router_alert {
                    return;
                }
                if target == IpAddr::V4(Ipv4Addr::new(224, 0, 0, 2)) {
                    let group =
                        IpAddr::V4(Ipv4Addr::new(igmp_header[4], igmp_header[5], igmp_header[6], igmp_header[7]));
                    self.apply_legacy_membership(sender, group, false, now);
                }
            }
            0x22 => {
                if !self.valid_igmp_report_source_locked(source) {
                    return;
                }
                if target != IpAddr::V4(Ipv4Addr::new(224, 0, 0, 22)) || !router_alert {
                    return;
                }
                let count = usize::from(u16::from_be_bytes([igmp_header[6], igmp_header[7]]));
                if count > (igmp.len() - 8) / 8 {
                    return;
                }
                let Some(records) = self.ipv4_membership_records(igmp, count) else {
                    return;
                };
                self.apply_membership_records(sender, &records, now);
            }
            _ => {}
        }
    }

    /// The `0x22` report records of an IGMPv3 membership report; `None` drops the report.
    fn ipv4_membership_records(&self, igmp: &[u8], count: usize) -> Option<Vec<ReportedMembershipRecord>> {
        let mut records = Vec::with_capacity(count);
        let mut pos = 8;
        for _ in 0..count {
            let record = igmp.get(pos..).and_then(|rest| rest.first_chunk::<8>())?;
            let record_type = record[0];
            let aux_length = usize::from(record[1]) * 4;
            let source_count = usize::from(u16::from_be_bytes([record[2], record[3]]));
            let length = 8 + source_count * 4 + aux_length;
            if length > igmp.len() - pos {
                return None;
            }
            let recognized = (1..=6).contains(&record_type);
            let retained = if recognized { source_count.min(MAX_REPORTED_MULTICAST_SOURCES + 1) } else { 0 };
            let mut sources = Vec::with_capacity(retained);
            for source_index in 0..source_count {
                let source_pos = pos + 8 + source_index * 4;
                let reported = IpAddr::V4(ipv4_at(igmp, source_pos)?);
                if recognized && !self.valid_reported_multicast_source(reported, false) {
                    return None;
                }
                if source_index < retained {
                    sources.push(reported);
                }
            }
            if recognized {
                let group = IpAddr::V4(Ipv4Addr::new(record[4], record[5], record[6], record[7]));
                records.push(ReportedMembershipRecord { group, record_type, sources });
            }
            pos += length;
        }
        Some(records)
    }

    fn handle_ipv6_membership<S: FrameSender>(&mut self, sender: &mut S, packet: &[u8], now: SystemTime) {
        let Some((icmp, protocol, _)) = ipv6_payload(packet) else {
            return;
        };
        let Some(header) = packet.first_chunk::<40>() else {
            return;
        };
        let Some(icmp_header) = icmp.first_chunk::<8>() else {
            return;
        };
        if protocol != 58 || header[7] != 1 || icmp_header[1] != 0 || !ipv6_membership_router_alert(packet) {
            return;
        }
        let mut source_raw = [0u8; 16];
        source_raw.copy_from_slice(&header[8..24]);
        let mut target_raw = [0u8; 16];
        target_raw.copy_from_slice(&header[24..40]);
        let source = IpAddr::V6(Ipv6Addr::from(source_raw));
        let target = IpAddr::V6(Ipv6Addr::from(target_raw));
        let link_local = matches!(source, IpAddr::V6(v6) if v6.is_unicast_link_local());
        if (!source.is_unspecified() && (!link_local || !self.is_local_address(source)))
            || icmpv6_checksum(source, target, icmp) != 0
        {
            return;
        }
        match icmp_header[0] {
            131 | 132 => {
                let Some(group_header) = icmp.first_chunk::<24>() else {
                    return;
                };
                let mut group_raw = [0u8; 16];
                group_raw.copy_from_slice(&group_header[8..24]);
                let group = IpAddr::V6(Ipv6Addr::from(group_raw));
                let expected =
                    if icmp_header[0] == 132 { IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2)) } else { group };
                if target == expected {
                    self.apply_legacy_membership(sender, group, icmp_header[0] == 131, now);
                }
            }
            143 => {
                if target != IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16)) {
                    return;
                }
                let count = usize::from(u16::from_be_bytes([icmp_header[6], icmp_header[7]]));
                if count > (icmp.len() - 8) / 20 {
                    return;
                }
                let mut records = Vec::with_capacity(count);
                let mut pos = 8;
                for _ in 0..count {
                    let Some(record) = icmp.get(pos..).and_then(|rest| rest.first_chunk::<20>()) else {
                        return;
                    };
                    let record_type = record[0];
                    let aux_length = usize::from(record[1]) * 4;
                    let source_count = usize::from(u16::from_be_bytes([record[2], record[3]]));
                    let length = 20 + source_count * 16 + aux_length;
                    if length > icmp.len() - pos {
                        return;
                    }
                    let recognized = (1..=6).contains(&record_type);
                    let retained = if recognized { source_count.min(MAX_REPORTED_MULTICAST_SOURCES + 1) } else { 0 };
                    let mut sources = Vec::with_capacity(retained);
                    for source_index in 0..source_count {
                        let source_pos = pos + 20 + source_index * 16;
                        let Some(reported) = ipv6_at(icmp, source_pos) else {
                            return;
                        };
                        let reported = IpAddr::V6(reported);
                        if recognized && !self.valid_reported_multicast_source(reported, true) {
                            return;
                        }
                        if source_index < retained {
                            sources.push(reported);
                        }
                    }
                    if recognized {
                        let Some(group) = ipv6_at(icmp, pos + 4) else {
                            return;
                        };
                        records.push(ReportedMembershipRecord { group: IpAddr::V6(group), record_type, sources });
                    }
                    pos += length;
                }
                self.apply_membership_records(sender, &records, now);
            }
            _ => {}
        }
    }

    fn valid_reported_multicast_source(&self, address: IpAddr, v6: bool) -> bool {
        if matches!(address, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()) {
            return false;
        }
        let address = unmap(address);
        if address.is_unspecified() || address.is_multicast() || address.is_loopback() || address.is_ipv6() != v6 {
            return false;
        }
        match address {
            IpAddr::V4(v4) => v4.octets()[0] != 0 && !self.is_ipv4_broadcast(address),
            IpAddr::V6(_) => true,
        }
    }

    fn apply_legacy_membership<S: FrameSender>(
        &mut self,
        sender: &mut S,
        group: IpAddr,
        joined: bool,
        now: SystemTime,
    ) {
        let group = unmap(group);
        if multicast_group_for_ip(group).is_none() {
            return;
        }
        if joined {
            if !self.can_add_reported_multicast(group) {
                return;
            }
            self.reported_memberships.insert(
                group,
                ReportedMulticastFilter {
                    exclude: true,
                    last_report: Some(now),
                    incomplete: false,
                    query_deadline: None,
                    sources: BTreeSet::new(),
                },
            );
        } else {
            self.reported_memberships.remove(&group);
        }
        let _ = self.sync_multicast_groups(sender);
    }

    /// The reported-multicast capacity check applied to the batch's running counts.
    fn can_create_record(
        &self,
        state_present: bool,
        counts: &BTreeMap<MulticastGroup, usize>,
        group: MulticastGroup,
    ) -> bool {
        state_present
            || (self.reported_memberships.len() < MAX_MULTICAST_GROUPS
                && (counts.get(&group).copied().unwrap_or(0) != 0 || counts.len() < MAX_MULTICAST_GROUPS))
    }

    /// Applies one membership record.
    fn apply_membership_record(
        &mut self,
        record: &ReportedMembershipRecord,
        group: IpAddr,
        zero_tier_group: MulticastGroup,
        counts: &BTreeMap<MulticastGroup, usize>,
    ) -> RecordOutcome {
        let mut state = self.reported_memberships.get(&group).cloned();
        match record.record_type {
            1 => {
                if record.sources.is_empty() {
                    self.reported_memberships.remove(&group);
                    RecordOutcome::Removed
                } else if state.as_ref().is_none_or(|filter| filter.exclude || !filter.incomplete) {
                    if !self.can_create_record(state.is_some(), counts, zero_tier_group) {
                        return RecordOutcome::Skipped;
                    }
                    let mut filter = ReportedMulticastFilter {
                        incomplete: true,
                        exclude: false,
                        last_report: None,
                        query_deadline: None,
                        sources: BTreeSet::new(),
                    };
                    filter.add_sources(&record.sources);
                    RecordOutcome::Updated(filter)
                } else if let Some(filter) = state.as_mut() {
                    filter.add_sources(&record.sources);
                    RecordOutcome::Updated(filter.clone())
                } else {
                    RecordOutcome::Unchanged
                }
            }
            2 | 4 => {
                if !self.can_create_record(state.is_some(), counts, zero_tier_group) {
                    return RecordOutcome::Skipped;
                }
                RecordOutcome::Updated(ReportedMulticastFilter {
                    exclude: true,
                    incomplete: false,
                    last_report: None,
                    query_deadline: None,
                    sources: BTreeSet::new(),
                })
            }
            3 => {
                if record.sources.is_empty() {
                    self.reported_memberships.remove(&group);
                    return RecordOutcome::Removed;
                }
                if !self.can_create_record(state.is_some(), counts, zero_tier_group) {
                    return RecordOutcome::Skipped;
                }
                // One non-EXCLUDE record may be split across reports, so a later fragment
                // or BLOCK cannot prove the group inactive.
                let mut filter = ReportedMulticastFilter {
                    incomplete: true,
                    exclude: false,
                    last_report: None,
                    query_deadline: None,
                    sources: BTreeSet::new(),
                };
                filter.add_sources(&record.sources);
                RecordOutcome::Updated(filter)
            }
            5 => {
                if !self.can_create_record(state.is_some(), counts, zero_tier_group) {
                    return RecordOutcome::Skipped;
                }
                if state.is_none() && !record.sources.is_empty() {
                    state = Some(ReportedMulticastFilter::default());
                }
                match state.as_mut() {
                    Some(filter) if !filter.exclude => {
                        filter.add_sources(&record.sources);
                        RecordOutcome::Updated(filter.clone())
                    }
                    _ => RecordOutcome::Unchanged,
                }
            }
            6 => {
                let Some(filter) = state.as_mut() else {
                    return RecordOutcome::Unchanged;
                };
                if filter.exclude {
                    return RecordOutcome::Unchanged;
                }
                for source in &record.sources {
                    filter.sources.remove(source);
                }
                if !filter.incomplete && filter.sources.is_empty() {
                    self.reported_memberships.remove(&group);
                    RecordOutcome::Removed
                } else {
                    RecordOutcome::Updated(filter.clone())
                }
            }
            _ => RecordOutcome::Unrecognized,
        }
    }

    fn apply_membership_records<S: FrameSender>(
        &mut self,
        sender: &mut S,
        records: &[ReportedMembershipRecord],
        now: SystemTime,
    ) {
        if records.is_empty() {
            return;
        }
        let mut active_counts: BTreeMap<MulticastGroup, usize> = BTreeMap::new();
        for group in self.automatic_subscriptions.values() {
            *active_counts.entry(*group).or_default() += 1;
        }
        for (address, filter) in &self.reported_memberships {
            if !filter.active() {
                continue;
            }
            if let Some(group) = multicast_group_for_ip(*address) {
                *active_counts.entry(group).or_default() += 1;
            }
        }
        for record in records {
            let group = unmap(record.group);
            let Some(zero_tier_group) = multicast_group_for_ip(group) else {
                continue;
            };
            let was_active = self.reported_memberships.get(&group).is_some_and(ReportedMulticastFilter::active);
            let mut recognized = true;
            match self.apply_membership_record(record, group, zero_tier_group, &active_counts) {
                RecordOutcome::Skipped => continue,
                RecordOutcome::Updated(filter) => {
                    self.reported_memberships.insert(group, filter);
                }
                RecordOutcome::Removed | RecordOutcome::Unchanged => {}
                RecordOutcome::Unrecognized => recognized = false,
            }
            if recognized {
                let inactive = self.reported_memberships.get_mut(&group).is_some_and(|filter| {
                    filter.last_report = Some(now);
                    filter.query_deadline = None;
                    !filter.active()
                });
                if inactive {
                    self.reported_memberships.remove(&group);
                }
            }
            let is_active = self.reported_memberships.get(&group).is_some_and(ReportedMulticastFilter::active);
            if was_active == is_active {
                continue;
            }
            if is_active {
                *active_counts.entry(zero_tier_group).or_default() += 1;
            } else {
                match active_counts.get(&zero_tier_group).copied().unwrap_or(0) {
                    0 => {}
                    1 => {
                        active_counts.remove(&zero_tier_group);
                    }
                    other => {
                        active_counts.insert(zero_tier_group, other - 1);
                    }
                }
            }
        }
        let _ = self.sync_multicast_groups(sender);
    }

    fn managed_ipv6_mac(&self, address: IpAddr) -> Option<Mac> {
        if !address.is_ipv6() {
            return None;
        }
        if !self.configured || self.flags & NETWORK_CONFIG_FLAG_ENABLE_IPV6_NDP_EMULATION == 0 {
            return None;
        }
        for prefix in &self.assigned {
            if !prefix.addr().is_ipv6() || !prefix.contains(&address) {
                continue;
            }
            let node = match prefix.prefix_len() {
                88 => address_from_rfc4193(self.network_id, address),
                40 => address_from_six_plane(self.network_id, address),
                _ => None,
            };
            if let Some(node) = node {
                return Some(mac_for_address(node, self.network_id));
            }
        }
        None
    }

    /// The longest-prefix route or on-link next hop.
    fn route_for(&self, destination: IpAddr) -> Option<IpAddr> {
        if !self.configured {
            return None;
        }
        let mut best_bits: i32 = -1;
        let mut best_metric = u16::MAX;
        let mut next_hop = None;
        for route in &self.routes {
            if route.target.addr().is_ipv4() != destination.is_ipv4() || !route.target.contains(&destination) {
                continue;
            }
            let bits = i32::from(route.target.prefix_len());
            if bits > best_bits || (bits == best_bits && route.metric < best_metric) {
                best_bits = bits;
                best_metric = route.metric;
                next_hop = Some(route.via.map_or(destination, unmap));
            }
        }
        for prefix in &self.assigned {
            if prefix.addr().is_ipv4() != destination.is_ipv4() || !prefix.contains(&destination) {
                continue;
            }
            if i32::from(prefix.prefix_len()) > best_bits {
                best_bits = i32::from(prefix.prefix_len());
                next_hop = Some(destination);
            }
        }
        if best_bits >= 0 {
            next_hop
        } else {
            None
        }
    }
}

fn merge(first: Result<(), LinkError>, second: Result<(), LinkError>) -> Result<(), LinkError> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), Ok(())) | (Ok(()), Err(err)) => Err(err),
        (Err(first), Err(second)) => Err(first.join(second)),
    }
}

fn elapsed(now: SystemTime, then: SystemTime) -> Duration {
    now.duration_since(then).unwrap_or_default()
}

fn unmap(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

fn octets16(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn ipv4_at(data: &[u8], offset: usize) -> Option<Ipv4Addr> {
    let octets = <[u8; 4]>::try_from(data.get(offset..offset + 4)?).ok()?;
    Some(Ipv4Addr::from(octets))
}

fn ipv6_at(data: &[u8], offset: usize) -> Option<Ipv6Addr> {
    let octets = <[u8; 16]>::try_from(data.get(offset..offset + 16)?).ok()?;
    Some(Ipv6Addr::from(octets))
}

fn clamp_mtu(mtu: u32) -> u32 {
    if mtu == 0 {
        DEFAULT_NETWORK_MTU
    } else {
        mtu.clamp(MIN_NETWORK_MTU, MAX_NETWORK_MTU)
    }
}

fn automatic_multicast_subscriptions(assigned: &[IpNet]) -> BTreeMap<IpAddr, MulticastGroup> {
    let mut automatic = BTreeMap::new();
    for prefix in assigned {
        let address = if prefix.addr().is_ipv6() {
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1))
        } else {
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))
        };
        if let Some(group) = multicast_group_for_ip(address) {
            automatic.insert(address, group);
        }
        if prefix.addr().is_ipv6() {
            let solicited = solicited_node_multicast(prefix.addr());
            if let Some(group) = multicast_group_for_ip(solicited) {
                automatic.insert(solicited, group);
            }
        }
    }
    automatic
}

fn internet_checksum(payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum_be_words(&mut sum, payload);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the fold above leaves the sum below 0x10000, so its low half is the whole value"
    )]
    let folded = sum as u16;
    !folded
}

fn sum_be_words(sum: &mut u32, data: &[u8]) {
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let [high, low] = chunk else {
            break;
        };
        *sum += u32::from(u16::from_be_bytes([*high, *low]));
    }
    if let [last] = chunks.remainder() {
        *sum += u32::from(*last) << 8;
    }
}

fn make_ipv6_icmp_packet(source: IpAddr, destination: IpAddr, icmp: &[u8]) -> Vec<u8> {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the IPv6 payload-length field is 16 bits, so the protocol cannot express a longer datagram"
    )]
    let payload_length = icmp.len() as u16;
    let mut header = [0u8; 40];
    header[0] = 0x60;
    header[4..6].copy_from_slice(&payload_length.to_be_bytes());
    header[6] = 58;
    header[7] = 255;
    header[8..24].copy_from_slice(&octets16(source));
    header[24..40].copy_from_slice(&octets16(destination));
    let mut packet = Vec::with_capacity(40 + icmp.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(icmp);
    let checksum = icmpv6_checksum(source, destination, icmp);
    let Some(field) = packet.get_mut(42..44) else {
        return packet;
    };
    field.copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn icmpv6_checksum(source: IpAddr, destination: IpAddr, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum_be_words(&mut sum, &octets16(source));
    sum_be_words(&mut sum, &octets16(destination));
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the ICMPv6 pseudo-header length field is 32 bits, so the protocol cannot express a longer datagram"
    )]
    let length = payload.len() as u32;
    sum += length >> 16;
    sum += length & 0xffff;
    sum += 58;
    sum_be_words(&mut sum, payload);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the fold above leaves the sum below 0x10000, so its low half is the whole value"
    )]
    let folded = sum as u16;
    !folded
}

/// `None` means no valid options were found.
fn ndp_option_mac(options: &[u8], wanted: u8) -> Option<(Option<Mac>, bool)> {
    let mut found = None;
    let mut has_found = false;
    let mut rest = options;
    while !rest.is_empty() {
        let [kind, units, ..] = rest else {
            return None;
        };
        let length = usize::from(*units) * 8;
        if length == 0 || length > rest.len() {
            return None;
        }
        if *kind == wanted {
            if length != 8 || has_found {
                return None;
            }
            let mac = Mac::from_bytes(rest.get(2..8)?).ok()?;
            if mac.uint64() == 0 || mac.is_multicast() {
                return None;
            }
            found = Some(mac);
            has_found = true;
        }
        rest = rest.get(length..)?;
    }
    Some((found, has_found))
}

fn solicited_node_multicast(address: IpAddr) -> IpAddr {
    let raw = octets16(address);
    let mut multicast = [0u8; 16];
    multicast[0] = 0xff;
    multicast[1] = 0x02;
    multicast[11] = 0x01;
    multicast[12] = 0xff;
    multicast[13..].copy_from_slice(&raw[13..]);
    IpAddr::V6(Ipv6Addr::from(multicast))
}

fn ipv6_multicast_mac(address: IpAddr) -> Mac {
    let raw = octets16(address);
    Mac::new(0x3333_0000_0000 | u64::from(u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]])))
}

fn ipv4_multicast_mac(address: IpAddr) -> Option<Mac> {
    let IpAddr::V4(v4) = address else {
        return None;
    };
    if !v4.is_multicast() {
        return None;
    }
    Some(Mac::new(0x0100_5e00_0000 | u64::from(u32::from(v4) & 0x7f_ffff)))
}

fn multicast_group_for_ip(address: IpAddr) -> Option<MulticastGroup> {
    let address = unmap(address);
    if let Some(mac) = ipv4_multicast_mac(address) {
        return Some(MulticastGroup::new(mac, 0));
    }
    if let IpAddr::V6(v6) = address {
        if valid_ipv6_multicast_group(v6) && v6.octets()[1] & 0x0f > 1 {
            return Some(MulticastGroup::new(ipv6_multicast_mac(address), 0));
        }
    }
    None
}

/// The RFC 4291/RFC 7346 flag and scope rules plus the RFC 3306/RFC 3956 dependencies between R,
/// P, and T.
fn valid_ipv6_multicast_group(address: Ipv6Addr) -> bool {
    if !address.is_multicast() {
        return false;
    }
    let raw = address.octets();
    let flags = raw[1] >> 4;
    let scope = raw[1] & 0x0f;
    if scope == 0 || scope == 0x0f || flags & 8 != 0 {
        return false;
    }
    let transient = flags & 1 != 0;
    let prefix_based = flags & 2 != 0;
    let embedded_rp = flags & 4 != 0;
    (!prefix_based || transient) && (!embedded_rp || prefix_based)
}

fn valid_igmp_report_source(address: IpAddr, broadcast: bool) -> bool {
    let IpAddr::V4(v4) = address else {
        return false;
    };
    if v4.is_multicast() || v4.is_loopback() || broadcast {
        return false;
    }
    if v4.is_unspecified() {
        return true;
    }
    v4.octets()[0] != 0
}

/// `None` means the query is not general.
fn ipv4_membership_query_interval(igmp: &[u8]) -> Option<(Duration, u8)> {
    let header = igmp.first_chunk::<8>()?;
    let group = IpAddr::V4(Ipv4Addr::new(header[4], header[5], header[6], header[7]));
    if igmp.len() == 8 {
        let (version, response_time) = if header[1] == 0 {
            (1u8, MEMBERSHIP_DEFAULT_RESPONSE_TIME)
        } else {
            (2u8, Duration::from_millis(u64::from(header[1]) * 100))
        };
        if !group.is_unspecified() {
            return None;
        }
        return Some((MEMBERSHIP_DEFAULT_QUERY_INTERVAL * MEMBERSHIP_DEFAULT_ROBUSTNESS + response_time * 2, version));
    }
    let version_three = igmp.get(8..).and_then(|rest| rest.first_chunk::<4>())?;
    let source_count = usize::from(u16::from_be_bytes([version_three[2], version_three[3]]));
    if source_count > (igmp.len() - 12) / 4 || !group.is_unspecified() || source_count != 0 {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "membershipDefaultRobustness is 2, which the three-bit field holds"
    )]
    let default_robustness = MEMBERSHIP_DEFAULT_ROBUSTNESS as u8;
    let robustness =
        if (version_three[0] & 7).trailing_zeros() >= 3 { default_robustness } else { version_three[0] & 7 };
    let query_interval = match decode_membership_code8(version_three[1], Duration::from_secs(1)) {
        interval if interval.is_zero() => MEMBERSHIP_DEFAULT_QUERY_INTERVAL,
        interval => interval,
    };
    let response_time = decode_membership_code8(header[1], Duration::from_millis(100));
    Some((query_interval * u32::from(robustness) + response_time * 2, 3))
}

fn ipv6_membership_query_interval(icmp: &[u8]) -> Option<(Duration, bool)> {
    let header = icmp.first_chunk::<24>()?;
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&header[8..24]);
    if !IpAddr::V6(Ipv6Addr::from(raw)).is_unspecified() {
        return None;
    }
    let response_time = Duration::from_millis(u64::from(u16::from_be_bytes([header[4], header[5]])));
    if icmp.len() == 24 {
        return Some((MEMBERSHIP_DEFAULT_QUERY_INTERVAL * MEMBERSHIP_DEFAULT_ROBUSTNESS + response_time, true));
    }
    let version_two = icmp.get(24..).and_then(|rest| rest.first_chunk::<4>())?;
    let source_count = usize::from(u16::from_be_bytes([version_two[2], version_two[3]]));
    if source_count > (icmp.len() - 28) / 16 || source_count != 0 {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "membershipDefaultRobustness is 2, which the three-bit field holds"
    )]
    let default_robustness = MEMBERSHIP_DEFAULT_ROBUSTNESS as u8;
    let robustness = if (version_two[0] & 7).trailing_zeros() >= 3 { default_robustness } else { version_two[0] & 7 };
    let query_interval = match decode_membership_code8(version_two[1], Duration::from_secs(1)) {
        interval if interval.is_zero() => MEMBERSHIP_DEFAULT_QUERY_INTERVAL,
        interval => interval,
    };
    let response_time = decode_membership_code16(u16::from_be_bytes([header[4], header[5]]), MILLI);
    Some((query_interval * u32::from(robustness) + response_time, true))
}

fn decode_membership_code8(code: u8, unit: Duration) -> Duration {
    let value =
        if code >= 128 { u32::from((code & 0x0f) | 0x10) << ((u32::from(code >> 4) & 7) + 3) } else { u32::from(code) };
    unit * value
}

fn decode_membership_code16(code: u16, unit: Duration) -> Duration {
    let value = if code >= 0x8000 {
        u32::from((code & 0x0fff) | 0x1000) << ((u32::from(code >> 12) & 7) + 3)
    } else {
        u32::from(code)
    };
    unit * value
}

/// `None` means the options are invalid.
fn ipv4_membership_options(options: &[u8]) -> Option<bool> {
    let mut router_alert = false;
    let mut record_route = false;
    let mut timestamp = false;
    let mut offset = 0usize;
    while offset < options.len() {
        let kind = *options.get(offset)?;
        match kind {
            0 => {
                if options.get(offset + 1..).unwrap_or_default().iter().any(|padding| *padding != 0) {
                    return None;
                }
                return Some(router_alert);
            }
            1 => {
                offset += 1;
                continue;
            }
            _ => {}
        }
        let rest = options.get(offset..)?;
        let [_, length_byte, ..] = rest else {
            return None;
        };
        let length = usize::from(*length_byte);
        if length < 2 || length > rest.len() {
            return None;
        }
        match kind {
            // Source routing is rejected: a report observed at an option-rewritten destination
            // would not describe membership on this link.
            131 | 137 => return None,
            7 => {
                if record_route || length < 3 {
                    return None;
                }
                record_route = true;
                let pointer = usize::from(*rest.get(2)?);
                if pointer < 4 || (pointer <= length && pointer + 3 > length) {
                    return None;
                }
            }
            68 => {
                if timestamp || length < 4 {
                    return None;
                }
                timestamp = true;
                let pointer = usize::from(*rest.get(2)?);
                let flag = *rest.get(3)? & 0x0f;
                if pointer < 5 {
                    return None;
                }
                if pointer <= length {
                    let required = if flag == 1 || flag == 3 { 8 } else { 4 };
                    if pointer + required - 1 > length {
                        return None;
                    }
                } else if flag != 3 && *rest.get(3)? >> 4 == 15 {
                    return None;
                }
            }
            148 => {
                if router_alert || length != 4 || *rest.get(2)? != 0 || *rest.get(3)? != 0 {
                    return None;
                }
                router_alert = true;
            }
            _ => {}
        }
        offset += length;
    }
    Some(router_alert)
}

/// The zero-valued RFC 2711 option in the mandatory first Hop-by-Hop header of an MLD message.
fn ipv6_membership_router_alert(packet: &[u8]) -> bool {
    if packet.get(6).copied() != Some(0) {
        return false;
    }
    let Some(&units) = packet.get(41) else {
        return false;
    };
    let length = (usize::from(units) + 1) * 8;
    let Some(header) = packet.get(40..).and_then(|payload| payload.get(..length)) else {
        return false;
    };
    let mut found = false;
    let mut offset = 2usize;
    while let Some(rest) = header.get(offset..) {
        let Some(&kind) = rest.first() else {
            break;
        };
        if kind == 0 {
            offset += 1;
            continue;
        }
        let Some(&length_byte) = rest.get(1) else {
            return false;
        };
        let option_length = usize::from(length_byte) + 2;
        if option_length > rest.len() {
            return false;
        }
        if kind == 5 {
            let [_, _, first, second, ..] = rest else {
                return false;
            };
            if found || option_length != 4 || *first != 0 || *second != 0 {
                return false;
            }
            found = true;
        }
        offset += option_length;
    }
    found
}

/// The payload, its protocol, and whether an atomic Fragment Header was crossed. Non-atomic
/// fragments stay incomplete and are rejected.
fn ipv6_payload(packet: &[u8]) -> Option<(&[u8], u8, bool)> {
    let fixed = packet.first_chunk::<40>()?;
    if fixed[0] >> 4 != 6 {
        return None;
    }
    let payload_length = usize::from(u16::from_be_bytes([fixed[4], fixed[5]]));
    if payload_length > packet.len() - 40 {
        return None;
    }
    let end = 40 + payload_length;
    let mut pos = 40usize;
    let mut protocol = fixed[6];
    let mut seen_hop = false;
    let mut seen_fragment = false;
    let mut fragmented = false;
    loop {
        let rest = packet.get(pos..end)?;
        match protocol {
            0 | 43 | 60 | 135 => {
                let header_type = protocol;
                if header_type == 0 {
                    if pos != 40 || seen_hop {
                        return None;
                    }
                    seen_hop = true;
                }
                let window = rest.first_chunk::<8>()?;
                let length = usize::from(window[1]) * 8 + 8;
                if length > rest.len() {
                    return None;
                }
                let header = rest.get(..length)?;
                if ((header_type == 0 || header_type == 60) && !valid_ipv6_membership_options(header))
                    || (header_type == 43 && window[3] != 0)
                {
                    return None;
                }
                protocol = window[0];
                pos += length;
            }
            44 => {
                let window = rest.first_chunk::<8>()?;
                if seen_fragment || u16::from_be_bytes([window[2], window[3]]) & 0xfff9 != 0 {
                    return None;
                }
                fragmented = true;
                seen_fragment = true;
                protocol = window[0];
                pos += 8;
            }
            _ => return Some((packet.get(pos..end)?, protocol, fragmented)),
        }
    }
}

fn valid_ipv6_membership_options(header: &[u8]) -> bool {
    if header.len() < 8 {
        return false;
    }
    let mut offset = 2usize;
    while let Some(rest) = header.get(offset..) {
        let Some(&kind) = rest.first() else {
            break;
        };
        if kind == 0 {
            offset += 1;
            continue;
        }
        let Some(&length_byte) = rest.get(1) else {
            return false;
        };
        let length = usize::from(length_byte) + 2;
        if length > rest.len() || kind >> 6 != 0 {
            return false;
        }
        offset += length;
    }
    true
}

fn validate_ip_packet(packet: &[u8], mtu: u32) -> Result<u8, LinkError> {
    let fixed = packet.first_chunk::<20>().ok_or(LinkError::ShortIpPacket)?;
    if mtu != 0 && packet.len() as u64 > u64::from(mtu) {
        return Err(LinkError::PacketExceedsMtu(packet.len(), mtu));
    }
    let version = fixed[0] >> 4;
    match version {
        4 => {
            let header_length = usize::from(fixed[0] & 0x0f) * 4;
            if header_length < 20 || header_length > packet.len() {
                return Err(LinkError::InvalidIpv4HeaderLength);
            }
            let total_length = usize::from(u16::from_be_bytes([fixed[2], fixed[3]]));
            if total_length < header_length || total_length != packet.len() {
                return Err(LinkError::InvalidIpv4PacketLength);
            }
        }
        6 => {
            let Some(header) = packet.first_chunk::<40>() else {
                return Err(LinkError::ShortIpv6Packet);
            };
            let payload_length = usize::from(u16::from_be_bytes([header[4], header[5]]));
            if payload_length != packet.len() - 40 {
                return Err(LinkError::InvalidIpv6PacketLength);
            }
        }
        _ => return Err(LinkError::UnsupportedIpVersion),
    }
    Ok(version)
}

fn normalize_assigned_addresses(assigned: &[IpNet]) -> Result<Vec<IpNet>, LinkError> {
    let mut normalized: Vec<IpNet> = Vec::with_capacity(assigned.len());
    for prefix in assigned {
        let address = prefix.addr();
        if address.is_unspecified() || address.is_multicast() {
            return Err(LinkError::InvalidManagedAddress(*prefix));
        }
        if normalized.contains(prefix) {
            continue;
        }
        normalized.push(*prefix);
    }
    Ok(normalized)
}

/// Invalid routes and routes redundant with local assignments are dropped.
fn normalize_routes(routes: &[NetworkRoute], assigned: &[IpNet]) -> Vec<NetworkRoute> {
    let mut normalized: Vec<NetworkRoute> = Vec::with_capacity(routes.len());
    for route in routes {
        let mut redundant = assigned.iter().any(|local| {
            local.addr().is_ipv4() == route.target.addr().is_ipv4()
                && local.prefix_len() == route.target.prefix_len()
                && route.target.contains(&local.addr())
        });
        if redundant {
            continue;
        }
        match route.via {
            Some(via) => {
                let via = unmap(via);
                if via.is_unspecified() {
                    normalized.push(NetworkRoute { via: None, ..route.clone() });
                    continue;
                }
                if via.is_ipv4() != route.target.addr().is_ipv4() || via.is_multicast() || via.is_loopback() {
                    continue;
                }
                redundant = assigned.iter().any(|local| unmap(local.addr()) == via);
                if redundant {
                    continue;
                }
                normalized.push(NetworkRoute { via: Some(via), ..route.clone() });
            }
            None => normalized.push(route.clone()),
        }
    }
    normalized
}

/// A multiset comparison that ignores configuration order.
fn prefixes_equal(left: &[IpNet], right: &[IpNet]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut matched = vec![false; right.len()];
    for item in left {
        let mut found = false;
        for (flag, candidate) in matched.iter_mut().zip(right) {
            if !*flag && item == candidate {
                *flag = true;
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    true
}

fn routes_equal(left: &[NetworkRoute], right: &[NetworkRoute]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut matched = vec![false; right.len()];
    for item in left {
        let mut found = false;
        for (flag, candidate) in matched.iter_mut().zip(right) {
            if !*flag && item == candidate {
                *flag = true;
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use murmur_zerotier::mac::Mac;
    use murmur_zerotier::managed_ip::{rfc4193_address, six_plane_address};

    const NETWORK_ID: u64 = 0x17d709436c04d6bc;
    const LOCAL_ADDRESS: u64 = 0x0f1b56d269;
    const REMOTE_ADDRESS: u64 = 0x46a9a1d071;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedFrame {
        destination: Mac,
        ether_type: u16,
        payload: Vec<u8>,
    }

    #[derive(Default)]
    struct RecordingSender {
        frames: Vec<RecordedFrame>,
        subscriptions: BTreeMap<MulticastGroup, bool>,
    }

    impl FrameSender for RecordingSender {
        fn send_frame(
            &mut self,
            _network_id: u64,
            destination: Mac,
            ether_type: u16,
            payload: &[u8],
            _now: SystemTime,
        ) -> Result<(), NodeError> {
            self.frames.push(RecordedFrame { destination, ether_type, payload: payload.to_vec() });
            Ok(())
        }

        fn multicast_subscriber(&mut self) -> Option<&mut dyn MulticastSubscriber> {
            Some(self)
        }
    }

    impl MulticastSubscriber for RecordingSender {
        fn subscribe_multicast(&mut self, _network_id: u64, group: MulticastGroup) -> Result<(), NodeError> {
            self.subscriptions.insert(group, true);
            Ok(())
        }

        fn unsubscribe_multicast(&mut self, _network_id: u64, group: MulticastGroup) -> Result<(), NodeError> {
            self.subscriptions.remove(&group);
            Ok(())
        }
    }

    /// A sender with no multicast subscription support.
    #[derive(Default)]
    struct FrameOnlySender {
        frames: Vec<RecordedFrame>,
    }

    impl FrameSender for FrameOnlySender {
        fn send_frame(
            &mut self,
            _network_id: u64,
            destination: Mac,
            ether_type: u16,
            payload: &[u8],
            _now: SystemTime,
        ) -> Result<(), NodeError> {
            self.frames.push(RecordedFrame { destination, ether_type, payload: payload.to_vec() });
            Ok(())
        }
    }

    fn address(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    fn prefix(text: &str) -> IpNet {
        text.parse().expect("test prefix")
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn link() -> Link {
        Link::new(NETWORK_ID, Address::new(LOCAL_ADDRESS)).expect("a valid network id")
    }

    fn config(assigned: &[&str]) -> NetworkConfigData {
        NetworkConfigData {
            network_id: NETWORK_ID,
            assigned: assigned.iter().map(|item| prefix(item)).collect(),
            ..NetworkConfigData::default()
        }
    }

    fn apply(link: &mut Link, sender: &mut RecordingSender, config: &NetworkConfigData, mtu: u32) {
        link.apply_network_config(sender, config, mtu).expect("the configuration applies");
    }

    fn octets4(text: &str) -> [u8; 4] {
        match address(text) {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => panic!("test packet needs an IPv4 address"),
        }
    }

    fn ipv4_packet(source: &str, destination: &str, protocol: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[9] = protocol;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[12..16].copy_from_slice(&octets4(source));
        packet[16..20].copy_from_slice(&octets4(destination));
        packet
    }

    fn arp_packet(operation: u16, sender_mac: Mac, sender_ip: &str, target_mac: Mac, target_ip: &str) -> Vec<u8> {
        let mut payload = vec![0u8; 28];
        payload[0..2].copy_from_slice(&1u16.to_be_bytes());
        payload[2..4].copy_from_slice(&ETHER_TYPE_IPV4.to_be_bytes());
        payload[4] = 6;
        payload[5] = 4;
        payload[6..8].copy_from_slice(&operation.to_be_bytes());
        payload[8..14].copy_from_slice(&sender_mac.bytes());
        payload[14..18].copy_from_slice(&octets4(sender_ip));
        payload[18..24].copy_from_slice(&target_mac.bytes());
        payload[24..28].copy_from_slice(&octets4(target_ip));
        payload
    }

    fn ipv6_packet(source: &str, destination: &str, next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload.len()];
        packet[0] = 0x60;
        packet[6] = next_header;
        packet[7] = 64;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[8..24].copy_from_slice(&octets16(address(source)));
        packet[24..40].copy_from_slice(&octets16(address(destination)));
        packet[40..].copy_from_slice(payload);
        packet
    }

    fn legacy_igmp_packet(
        source: &str,
        target: &str,
        group: &str,
        message_type: u8,
        response_code: u8,
        router_alert: bool,
    ) -> Vec<u8> {
        let mut igmp = vec![0u8; 8];
        igmp[0] = message_type;
        igmp[1] = response_code;
        igmp[4..8].copy_from_slice(&octets4(group));
        let checksum = internet_checksum(&igmp);
        igmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        let header_length = if router_alert { 24 } else { 20 };
        let mut packet = vec![0u8; header_length + igmp.len()];
        packet[0] = if router_alert { 0x46 } else { 0x45 };
        packet[8] = 1;
        packet[9] = 2;
        if router_alert {
            packet[20..24].copy_from_slice(&[148, 4, 0, 0]);
        }
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[12..16].copy_from_slice(&octets4(source));
        packet[16..20].copy_from_slice(&octets4(target));
        let header_checksum = internet_checksum(&packet[..header_length]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet[header_length..].copy_from_slice(&igmp);
        packet
    }

    fn local_mac() -> Mac {
        mac_for_address(Address::new(LOCAL_ADDRESS), NETWORK_ID)
    }

    fn remote_mac() -> Mac {
        mac_for_address(Address::new(REMOTE_ADDRESS), NETWORK_ID)
    }

    #[test]
    fn route_selection() {
        let mut sender = RecordingSender::default();
        let mut link = link();
        let mut config = config(&["192.168.192.7/24"]);
        config.routes = vec![
            NetworkRoute { target: prefix("0.0.0.0/0"), via: Some(address("192.168.192.254")), flags: 0, metric: 100 },
            NetworkRoute { target: prefix("10.0.0.0/8"), via: Some(address("192.168.192.1")), flags: 0, metric: 10 },
        ];
        apply(&mut link, &mut sender, &config, 0);
        assert_eq!(link.route_for(address("10.20.30.40")), Some(address("192.168.192.1")));
        assert_eq!(link.route_for(address("192.168.192.8")), Some(address("192.168.192.8")));
    }

    #[test]
    fn source_for_uses_route_next_hop() {
        let mut sender = RecordingSender::default();
        let mut link = link();
        let mut config = config(&["192.0.2.10/24", "198.51.100.10/24"]);
        config.routes = vec![NetworkRoute {
            target: prefix("203.0.113.0/24"),
            via: Some(address("198.51.100.1")),
            flags: 0,
            metric: 0,
        }];
        apply(&mut link, &mut sender, &config, 0);
        assert_eq!(link.source_for(address("203.0.113.8")).expect("a managed source"), address("198.51.100.10"));
    }

    #[test]
    fn managed_route_normalization() {
        let mut sender = RecordingSender::default();
        let mut link = link();
        let mut config = config(&["192.0.2.10/24"]);
        config.routes = vec![
            NetworkRoute { target: prefix("192.0.2.0/24"), via: Some(address("192.0.2.1")), flags: 0, metric: 0 },
            NetworkRoute { target: prefix("198.51.100.0/24"), via: Some(address("192.0.2.10")), flags: 0, metric: 0 },
            NetworkRoute { target: prefix("203.0.113.0/24"), via: Some(address("fd00::1")), flags: 0, metric: 0 },
            NetworkRoute { target: prefix("10.0.0.0/8"), via: Some(address("224.0.0.1")), flags: 0, metric: 0 },
            NetworkRoute { target: prefix("172.16.0.0/12"), via: Some(address("0.0.0.0")), flags: 0, metric: 0 },
        ];
        apply(&mut link, &mut sender, &config, 0);
        assert_eq!(link.route_for(address("192.0.2.20")), Some(address("192.0.2.20")));
        for destination in ["198.51.100.1", "203.0.113.1", "10.0.0.1"] {
            assert!(link.route_for(address(destination)).is_none(), "{destination} kept an invalid route");
        }
        assert_eq!(link.route_for(address("172.16.1.1")), Some(address("172.16.1.1")));
    }

    #[test]
    fn managed_ipv6_uses_direct_mapping_when_enabled() {
        let local = Address::new(LOCAL_ADDRESS);
        let remote = Address::new(REMOTE_ADDRESS);
        for (name, assigned, destination) in [
            ("RFC4193", rfc4193_address(NETWORK_ID, local), rfc4193_address(NETWORK_ID, remote).addr()),
            ("6plane", six_plane_address(NETWORK_ID, local), six_plane_address(NETWORK_ID, remote).addr()),
        ] {
            let mut sender = RecordingSender::default();
            let mut link = link();
            let prefix = IpNet::new(assigned.addr(), assigned.prefix_len()).expect("a managed prefix");
            let mut config =
                NetworkConfigData { network_id: NETWORK_ID, assigned: vec![prefix], ..NetworkConfigData::default() };
            apply(&mut link, &mut sender, &config, 0);
            link.validate_destination(destination).unwrap_or_else(|err| panic!("{name}: {err}"));
            assert!(link.managed_ipv6_mac(destination).is_none(), "{name} mapped with NDP emulation disabled");
            config.flags = NETWORK_CONFIG_FLAG_ENABLE_IPV6_NDP_EMULATION;
            apply(&mut link, &mut sender, &config, 0);
            link.validate_destination(destination).unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(
                link.managed_ipv6_mac(destination),
                Some(mac_for_address(remote, NETWORK_ID)),
                "{name} direct mapping"
            );
        }
    }

    #[test]
    fn ipv4_arp_resolution() {
        let now = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["192.168.192.7/24"]), 0);

        let packet = ipv4_packet("192.168.192.7", "192.168.192.8", 17);
        link.write_packet(&mut sender, &packet, now).expect("the packet reaches the ARP path");
        assert_eq!(sender.frames.len(), 1);
        assert_eq!(sender.frames[0].ether_type, ETHER_TYPE_ARP);
        assert_eq!(sender.frames[0].destination, broadcast_mac());
        assert_eq!(&sender.frames[0].payload[24..28], &octets4("192.168.192.8"));

        let reply = arp_packet(2, remote_mac(), "192.168.192.8", local_mac(), "192.168.192.7");
        let frame = Frame {
            network_id: NETWORK_ID,
            source: remote_mac(),
            destination: local_mac(),
            ether_type: ETHER_TYPE_ARP,
            payload: reply,
        };
        link.handle_frame(&mut sender, &frame, now).expect("the reply is accepted");
        assert_eq!(sender.frames.len(), 2, "the pending packet is flushed");
        assert_eq!(sender.frames[1].ether_type, ETHER_TYPE_IPV4);
        assert_eq!(sender.frames[1].destination, remote_mac());
        assert_eq!(sender.frames[1].payload, packet);

        let request = arp_packet(1, remote_mac(), "192.168.192.8", Mac::new(0), "192.168.192.7");
        let frame = Frame {
            network_id: NETWORK_ID,
            source: remote_mac(),
            destination: broadcast_mac(),
            ether_type: ETHER_TYPE_ARP,
            payload: request,
        };
        link.handle_frame(&mut sender, &frame, now).expect("the request is answered");
        let last = sender.frames.last().expect("an ARP reply");
        assert_eq!(last.ether_type, ETHER_TYPE_ARP);
        assert_eq!(last.destination, remote_mac());
        assert_eq!(u16::from_be_bytes([last.payload[6], last.payload[7]]), 2);
    }

    #[test]
    fn ipv4_uses_packet_source_for_arp_and_maps_broadcast_multicast() {
        let now = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        let mut config = config(&["10.0.0.1/24", "192.168.1.1/24"]);
        config.multicast_limit = 32;
        config.flags = NETWORK_CONFIG_FLAG_ENABLE_BROADCAST;
        apply(&mut link, &mut sender, &config, 0);

        let packet = ipv4_packet("192.168.1.1", "192.168.1.20", 17);
        link.write_packet(&mut sender, &packet, now).expect("the packet resolves its neighbor");
        assert_eq!(&sender.frames[0].payload[14..18], &octets4("192.168.1.1"));

        sender.frames.clear();
        let broadcast = ipv4_packet("192.168.1.1", "192.168.1.255", 17);
        link.write_packet(&mut sender, &broadcast, now).expect("the broadcast is sent");
        assert_eq!(sender.frames.len(), 1);
        assert_eq!(sender.frames[0].destination, broadcast_mac());

        sender.frames.clear();
        let multicast = ipv4_packet("192.168.1.1", "239.1.2.3", 17);
        link.write_packet(&mut sender, &multicast, now).expect("the multicast is sent");
        let want = Mac::new(0x0100_5e01_0203);
        assert_eq!(sender.frames.len(), 1);
        assert_eq!(sender.frames[0].destination, want);
        assert!(
            !sender.subscriptions.get(&MulticastGroup::new(want, 0)).copied().unwrap_or(false),
            "sending multicast data created a persistent subscription"
        );
    }

    #[test]
    fn neighbor_resolution_background_retry_and_expiration() {
        let base = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["192.0.2.10/24"]), 0);
        let packet = ipv4_packet("192.0.2.10", "192.0.2.20", 17);
        link.write_packet(&mut sender, &packet, base).expect("resolution starts");
        assert_eq!(sender.frames.len(), 1);
        assert_eq!(sender.frames[0].ether_type, ETHER_TYPE_ARP);

        link.process_background_tasks(&mut sender, base + NEIGHBOR_REQUEST_PERIOD).expect("retry");
        assert_eq!(sender.frames.len(), 2);
        assert_eq!(sender.frames[1].ether_type, ETHER_TYPE_ARP);

        link.process_background_tasks(&mut sender, base + PENDING_NEIGHBOR_EXPIRATION).expect("expiry");
        assert!(link.neighbor_pending.is_empty(), "the expired destination is dropped");
        assert_eq!(sender.frames.len(), 2);
    }

    #[test]
    fn stale_ipv4_neighbor_remains_usable_while_refreshing() {
        let base = at(1_700_000_000);
        let mut now = base + NEIGHBOR_CACHE_REFRESH_AFTER;
        let local = address("192.0.2.10");
        let remote = address("192.0.2.20");
        let remote_mac = Mac::new(0x0200_0000_0020);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["192.0.2.10/24"]), 0);
        link.neighbor_cache.insert(
            remote,
            NeighborEntry { mac: remote_mac, deadline: now, state: NeighborState::Reachable, probes: 0 },
        );
        let packet = ipv4_packet("192.0.2.10", "192.0.2.20", 17);

        link.write_packet(&mut sender, &packet, now).expect("the stale mapping sends the packet");
        assert_eq!(sender.frames.len(), 1);
        assert_eq!(sender.frames[0].destination, remote_mac);
        assert_eq!(sender.frames[0].ether_type, ETHER_TYPE_IPV4);
        let entry = link.neighbor_cache[&remote];
        assert_eq!(entry.state, NeighborState::Delay);
        assert_eq!(entry.deadline, now + NEIGHBOR_DELAY_PROBE_TIME);
        assert_eq!(entry.probes, 0);
        assert!(link.neighbor_pending.is_empty());

        link.process_background_tasks(&mut sender, now + NEIGHBOR_DELAY_PROBE_TIME - Duration::from_millis(1))
            .expect("no probe before the delay expires");
        assert_eq!(sender.frames.len(), 1);

        now += NEIGHBOR_DELAY_PROBE_TIME;
        link.process_background_tasks(&mut sender, now).expect("the delayed probe");
        assert_eq!(sender.frames.len(), 2);
        assert_eq!(sender.frames[1].destination, remote_mac);
        assert_eq!(sender.frames[1].ether_type, ETHER_TYPE_ARP);
        let entry = link.neighbor_cache[&remote];
        assert_eq!(entry.state, NeighborState::Probe);
        assert_eq!(entry.probes, 1);
        assert_eq!(entry.deadline, now + NEIGHBOR_REQUEST_PERIOD);

        link.learn_neighbor(&mut sender, remote, remote_mac, true, now).expect("the mapping refreshes");
        let entry = link.neighbor_cache[&remote];
        assert_eq!(entry.state, NeighborState::Reachable);
        assert_eq!(entry.probes, 0);
        assert_eq!(entry.deadline, now + NEIGHBOR_CACHE_REFRESH_AFTER);

        now += NEIGHBOR_CACHE_REFRESH_AFTER - Duration::from_secs(1);
        let frames_before = sender.frames.len();
        link.write_packet(&mut sender, &packet, now).expect("the fresh mapping sends the packet");
        assert_eq!(sender.frames.len(), frames_before + 1);
        assert_eq!(sender.frames[frames_before].ether_type, ETHER_TYPE_IPV4);
        assert_eq!(local, address("192.0.2.10"));
    }

    #[test]
    fn stale_ipv6_neighbor_remains_usable_while_refreshing() {
        let base = at(1_700_000_000);
        let mut now = base + NEIGHBOR_CACHE_REFRESH_AFTER;
        let remote = address("fd00::20");
        let remote_mac = Mac::new(0x0200_0000_0020);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["fd00::10/64"]), 0);
        link.neighbor_cache.insert(
            remote,
            NeighborEntry { mac: remote_mac, deadline: now, state: NeighborState::Reachable, probes: 0 },
        );
        let packet = ipv6_packet("fd00::10", "fd00::20", 17, &[1]);

        link.write_packet(&mut sender, &packet, now).expect("the stale mapping sends the packet");
        assert_eq!(sender.frames.len(), 1);
        assert_eq!(sender.frames[0].destination, remote_mac);
        assert_eq!(sender.frames[0].ether_type, ETHER_TYPE_IPV6);
        assert!(link.neighbor_pending.is_empty());

        now += NEIGHBOR_DELAY_PROBE_TIME;
        link.process_background_tasks(&mut sender, now).expect("the NDP probe");
        assert_eq!(sender.frames.len(), 2);
        let probe = &sender.frames[1];
        assert_eq!(probe.destination, remote_mac);
        assert_eq!(probe.ether_type, ETHER_TYPE_IPV6);
        assert!(probe.payload.len() >= 41);
        assert_eq!(probe.payload[6], 58);
        assert_eq!(probe.payload[40], 135);
        assert_eq!(&probe.payload[24..40], &octets16(remote)[..]);

        link.learn_neighbor(&mut sender, remote, remote_mac, true, now).expect("the mapping refreshes");
        let entry = link.neighbor_cache[&remote];
        assert_eq!(entry.state, NeighborState::Reachable);
        assert_eq!(entry.probes, 0);
        assert_eq!(entry.deadline, now + NEIGHBOR_CACHE_REFRESH_AFTER);
    }

    #[test]
    fn stale_neighbor_probe_failure_restarts_resolution() {
        let mut now = at(1_700_000_000);
        let remote = address("192.0.2.20");
        let remote_mac = Mac::new(0x0200_0000_0020);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["192.0.2.10/24"]), 0);
        link.neighbor_cache.insert(
            remote,
            NeighborEntry { mac: remote_mac, deadline: now, state: NeighborState::Reachable, probes: 0 },
        );
        let packet = ipv4_packet("192.0.2.10", "192.0.2.20", 17);
        link.write_packet(&mut sender, &packet, now).expect("the stale mapping sends the packet");

        now += NEIGHBOR_DELAY_PROBE_TIME;
        for probe in 0..NEIGHBOR_MAXIMUM_PROBES {
            link.process_background_tasks(&mut sender, now).expect("the unicast probe");
            let index = usize::from(probe) + 1;
            assert_eq!(sender.frames.len(), index + 1, "probe {}", usize::from(probe) + 1);
            assert_eq!(sender.frames[index].destination, remote_mac);
            assert_eq!(sender.frames[index].ether_type, ETHER_TYPE_ARP);
            now += NEIGHBOR_REQUEST_PERIOD;
        }
        link.process_background_tasks(&mut sender, now).expect("the failed mapping is dropped");
        assert!(!link.neighbor_cache.contains_key(&remote), "a failed mapping stays cached");
        assert_eq!(sender.frames.len(), usize::from(NEIGHBOR_MAXIMUM_PROBES) + 1);

        link.write_packet(&mut sender, &packet, now).expect("resolution restarts");
        let pending = link.neighbor_pending.get(&remote).expect("a pending destination");
        let last = sender.frames.last().expect("the resolution request");
        assert_eq!(pending.packets.len(), 1);
        assert_eq!(pending.requested_at, Some(now));
        assert_eq!(last.ether_type, ETHER_TYPE_ARP);
        assert_eq!(last.destination, broadcast_mac());
    }

    #[test]
    fn ipv6_neighbor_discovery() {
        let now = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["fd00::1/64"]), 0);
        let packet = ipv6_packet("fd00::1", "fd00::2", 17, &[1, 2, 3, 4]);
        link.write_packet(&mut sender, &packet, now).expect("the solicitation is sent");
        assert_eq!(sender.frames.len(), 1);
        assert_eq!(sender.frames[0].destination, Mac::new(0x3333_ff00_0002));
        assert_eq!(sender.frames[0].payload[40], 135);

        let mut icmp = vec![0u8; 32];
        icmp[0] = 136;
        icmp[4..8].copy_from_slice(&0x6000_0000u32.to_be_bytes());
        icmp[8..24].copy_from_slice(&octets16(address("fd00::2")));
        icmp[24] = 2;
        icmp[25] = 1;
        icmp[26..32].copy_from_slice(&remote_mac().bytes());
        let advertisement = make_ipv6_icmp_packet(address("fd00::2"), address("fd00::1"), &icmp);
        let frame = Frame {
            network_id: NETWORK_ID,
            source: remote_mac(),
            destination: local_mac(),
            ether_type: ETHER_TYPE_IPV6,
            payload: advertisement,
        };
        link.handle_frame(&mut sender, &frame, now).expect("the advertisement is accepted");
        assert_eq!(sender.frames.len(), 2);
        assert_eq!(sender.frames[1].destination, remote_mac());
        assert_eq!(sender.frames[1].payload, packet);
    }

    #[test]
    fn ipv6_neighbor_solicitation_gets_advertisement() {
        let now = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["fd00::1/64"]), 0);
        let mut icmp = vec![0u8; 32];
        icmp[0] = 135;
        icmp[8..24].copy_from_slice(&octets16(address("fd00::1")));
        icmp[24] = 1;
        icmp[25] = 1;
        icmp[26..32].copy_from_slice(&remote_mac().bytes());
        let solicited = solicited_node_multicast(address("fd00::1"));
        let solicitation = make_ipv6_icmp_packet(address("fd00::2"), solicited, &icmp);
        let frame = Frame {
            network_id: NETWORK_ID,
            source: remote_mac(),
            destination: ipv6_multicast_mac(solicited),
            ether_type: ETHER_TYPE_IPV6,
            payload: solicitation,
        };
        link.handle_frame(&mut sender, &frame, now).expect("the solicitation is answered");
        assert_eq!(sender.frames.len(), 1);
        assert_eq!(sender.frames[0].destination, remote_mac());
        assert_eq!(sender.frames[0].payload[40], 136);
    }

    #[test]
    fn ipv6_duplicate_address_detection_gets_unsolicited_advertisement() {
        let now = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["fd00::1/64"]), 0);
        let mut icmp = vec![0u8; 24];
        icmp[0] = 135;
        icmp[8..24].copy_from_slice(&octets16(address("fd00::1")));
        let solicited = solicited_node_multicast(address("fd00::1"));
        let solicitation = make_ipv6_icmp_packet(IpAddr::V6(Ipv6Addr::UNSPECIFIED), solicited, &icmp);
        let frame = Frame {
            network_id: NETWORK_ID,
            source: remote_mac(),
            destination: ipv6_multicast_mac(solicited),
            ether_type: ETHER_TYPE_IPV6,
            payload: solicitation,
        };
        link.handle_frame(&mut sender, &frame, now).expect("the probe is answered");
        assert_eq!(sender.frames.len(), 1);
        let response = &sender.frames[0];
        let all_nodes = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(response.destination, ipv6_multicast_mac(all_nodes));
        assert_eq!(
            u32::from_be_bytes([
                response.payload[44],
                response.payload[45],
                response.payload[46],
                response.payload[47]
            ]),
            0x2000_0000
        );
    }

    #[test]
    fn ipv6_neighbor_discovery_behind_extension_header() {
        let now = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["fd00::1/64"]), 0);
        let mut icmp = vec![0u8; 32];
        icmp[0] = 135;
        icmp[8..24].copy_from_slice(&octets16(address("fd00::1")));
        icmp[24] = 1;
        icmp[25] = 1;
        icmp[26..32].copy_from_slice(&remote_mac().bytes());
        let destination = solicited_node_multicast(address("fd00::1"));
        let checksum = icmpv6_checksum(address("fd00::2"), destination, &icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        let hop_by_hop = [58u8, 0, 5, 2, 0, 0, 1, 0];
        let mut payload = hop_by_hop.to_vec();
        payload.extend_from_slice(&icmp);
        let mut packet = ipv6_packet("fd00::2", &destination.to_string(), 0, &payload);
        packet[7] = 255;
        let frame = Frame {
            network_id: NETWORK_ID,
            source: remote_mac(),
            destination: ipv6_multicast_mac(destination),
            ether_type: ETHER_TYPE_IPV6,
            payload: packet,
        };
        link.handle_frame(&mut sender, &frame, now).expect("the solicitation is answered");
        assert_eq!(sender.frames.len(), 1);
        assert_eq!(sender.frames[0].destination, remote_mac());
        assert_eq!(sender.frames[0].payload[40], 136);

        sender.frames.clear();
        // An RFC 8200 atomic Fragment header after the mandatory Hop-by-Hop header.
        let mut atomic = vec![0u8; frame.payload.len() + 8];
        atomic[..48].copy_from_slice(&frame.payload[..48]);
        atomic[40] = 44;
        atomic[48] = 58;
        atomic[56..].copy_from_slice(&frame.payload[48..]);
        let length = (atomic.len() - 40) as u16;
        atomic[4..6].copy_from_slice(&length.to_be_bytes());
        let atomic_frame = Frame { payload: atomic, ..frame };
        let returned = link.handle_frame(&mut sender, &atomic_frame, now).expect("an atomic fragment");
        assert!(returned.is_none());
        assert!(sender.frames.is_empty(), "an atomic fragment produced a response");
    }

    #[test]
    fn ndp_rejects_malformed_options() {
        let now = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["fd00::1/64"]), 0);
        let mut icmp = vec![0u8; 32];
        icmp[0] = 135;
        icmp[8..24].copy_from_slice(&octets16(address("fd00::1")));
        icmp[24] = 1;
        let destination = solicited_node_multicast(address("fd00::1"));
        let packet = make_ipv6_icmp_packet(address("fd00::2"), destination, &icmp);
        let frame = Frame {
            network_id: NETWORK_ID,
            source: remote_mac(),
            destination: ipv6_multicast_mac(destination),
            ether_type: ETHER_TYPE_IPV6,
            payload: packet,
        };
        link.handle_frame(&mut sender, &frame, now).expect("a malformed option is ignored");
        assert!(sender.frames.is_empty());
        assert!(!link.neighbor_cache.contains_key(&address("fd00::2")));
    }

    #[test]
    fn membership_router_alert_validation() {
        let mut packet = vec![0u8; 48];
        packet[6] = 0;
        packet[40] = 58;
        packet[42..48].copy_from_slice(&[5, 2, 0, 0, 1, 0]);
        assert!(ipv6_membership_router_alert(&packet), "a Router Alert followed by PadN stays valid");

        packet[42..48].copy_from_slice(&[5, 2, 0, 0, 0, 0]);
        assert!(ipv6_membership_router_alert(&packet), "a Router Alert followed by Pad1 bytes stays valid");

        packet[47] = 8;
        assert!(!ipv6_membership_router_alert(&packet), "a trailing option without a length byte is rejected");

        let mut hop_by_hop = vec![58, 0, 5, 2, 0, 0, 0, 0];
        hop_by_hop.extend_from_slice(&[0u8; 8]);
        let packet = ipv6_packet("fe80::10", "ff02::1", 0, &hop_by_hop);
        let Some((body, protocol, fragmented)) = ipv6_payload(&packet) else {
            panic!("a Pad1-padded Hop-by-Hop header is a valid IPv6 payload");
        };
        assert_eq!(protocol, 58);
        assert!(!fragmented);
        assert_eq!(body, &hop_by_hop[8..]);

        hop_by_hop[2..8].fill(0);
        let packet = ipv6_packet("fe80::10", "ff02::1", 0, &hop_by_hop);
        assert!(ipv6_payload(&packet).is_some(), "a padding-only Hop-by-Hop header is a valid IPv6 payload");
    }

    #[test]
    fn neighbor_advertisement_honors_override() {
        let now = at(1_700_000_000);
        let remote = address("fd00::2");
        let old_mac = mac_for_address(Address::new(REMOTE_ADDRESS), NETWORK_ID);
        let new_mac = mac_for_address(Address::new(0x0012_3456_789a), NETWORK_ID);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["fd00::1/64"]), 0);
        link.learn_neighbor(&mut sender, remote, old_mac, true, now).expect("the initial mapping");
        fn advertise(
            link: &mut Link,
            sender: &mut RecordingSender,
            remote: IpAddr,
            new_mac: Mac,
            flags: u32,
            now: SystemTime,
        ) {
            let mut icmp = vec![0u8; 32];
            icmp[0] = 136;
            icmp[4..8].copy_from_slice(&flags.to_be_bytes());
            icmp[8..24].copy_from_slice(&octets16(remote));
            icmp[24] = 2;
            icmp[25] = 1;
            icmp[26..32].copy_from_slice(&new_mac.bytes());
            let packet = make_ipv6_icmp_packet(remote, address("fd00::1"), &icmp);
            let frame = Frame {
                network_id: NETWORK_ID,
                source: new_mac,
                destination: local_mac(),
                ether_type: ETHER_TYPE_IPV6,
                payload: packet,
            };
            link.handle_frame(sender, &frame, now).expect("the advertisement is accepted");
        }
        advertise(&mut link, &mut sender, remote, new_mac, 0, now);
        assert_eq!(link.neighbor_cache[&remote].mac, old_mac, "a plain advertisement must not override");
        advertise(&mut link, &mut sender, remote, new_mac, 0x2000_0000, now);
        assert_eq!(link.neighbor_cache[&remote].mac, new_mac, "an overriding advertisement wins");
    }

    #[test]
    fn handle_frame_returns_ip_packet() {
        let now = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        let payload = vec![0x45, 0, 0, 20];
        let frame = Frame {
            network_id: NETWORK_ID,
            source: Mac::new(0),
            destination: Mac::new(0),
            ether_type: ETHER_TYPE_IPV4,
            payload: payload.clone(),
        };
        assert_eq!(link.handle_frame(&mut sender, &frame, now).expect("a plain packet"), Some(payload.clone()));
        let foreign = Frame { network_id: NETWORK_ID + 1, ..frame };
        assert_eq!(link.handle_frame(&mut sender, &foreign, now).expect("a foreign network"), None);
    }

    #[test]
    fn validate_ipv4_route_requires_managed_ipv4_address() {
        let mut sender = RecordingSender::default();
        let mut link = link();
        let mut config = config(&["fd00::1/64"]);
        config.routes = vec![NetworkRoute { target: prefix("0.0.0.0/0"), via: None, flags: 0, metric: 0 }];
        apply(&mut link, &mut sender, &config, 0);
        assert!(link.validate_destination(address("192.0.2.1")).is_err());
    }

    #[test]
    fn validate_multicast_and_broadcast_policy() {
        let now = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        let mut link_config = config(&["fd00::1/64"]);
        link_config.multicast_limit = 1;
        apply(&mut link, &mut sender, &link_config, 0);
        link.validate_destination(address("ff02::1")).expect("managed IPv6 multicast");
        assert!(link.validate_destination(address("ff01::1234")).is_err(), "interface-local multicast");
        assert!(link.validate_destination(address("239.1.2.3")).is_err(), "IPv4 multicast without a source");

        let mut link_config = config(&["192.0.2.1/24"]);
        apply(&mut link, &mut sender, &link_config, 0);
        let multicast = ipv4_packet("192.0.2.1", "239.1.2.3", 17);
        assert!(link.write_packet(&mut sender, &multicast, now).is_err(), "multicast disabled");
        let broadcast = ipv4_packet("192.0.2.1", "192.0.2.255", 17);

        link_config.flags = NETWORK_CONFIG_FLAG_ENABLE_BROADCAST;
        apply(&mut link, &mut sender, &link_config, 0);
        assert!(link.validate_destination(address("192.0.2.255")).is_err(), "broadcast with multicast off");
        assert!(link.write_packet(&mut sender, &broadcast, now).is_err());

        link_config.flags = 0;
        link_config.multicast_limit = 1;
        apply(&mut link, &mut sender, &link_config, 0);
        assert!(link.validate_destination(address("192.0.2.255")).is_err(), "broadcast disabled");
        assert!(link.write_packet(&mut sender, &broadcast, now).is_err());

        link_config.flags = NETWORK_CONFIG_FLAG_ENABLE_BROADCAST;
        apply(&mut link, &mut sender, &link_config, 0);
        link.validate_destination(address("192.0.2.255")).expect("enabled directed broadcast");
        sender.frames.clear();
        link.write_packet(&mut sender, &broadcast, now).expect("the broadcast is sent");
        assert_eq!(sender.frames.len(), 1);
        assert_eq!(sender.frames[0].destination, broadcast_mac());
    }

    #[test]
    fn multicast_group_for_ip_validates_ipv6_flags_and_scope() {
        for valid in ["ff02::1234", "ff32::1234", "ff72::1234"] {
            assert!(multicast_group_for_ip(address(valid)).is_some(), "{valid} is a valid group");
        }
        for invalid in ["ff00::1234", "ff01::1234", "ff0f::1234", "ff22::1234", "ff42::1234", "ff82::1234"] {
            assert!(multicast_group_for_ip(address(invalid)).is_none(), "{invalid} is not a group");
        }
    }

    #[test]
    fn write_packet_validates_mtu_and_header_length() {
        let now = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["192.0.2.1/24"]), MIN_NETWORK_MTU);

        let mut packet = vec![0u8; usize::try_from(MIN_NETWORK_MTU).expect("a small MTU") + 1];
        packet[0] = 0x45;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[12..16].copy_from_slice(&octets4("192.0.2.1"));
        packet[16..20].copy_from_slice(&octets4("192.0.2.2"));
        assert!(link.write_packet(&mut sender, &packet, now).is_err(), "oversized packet");

        let mut packet = ipv4_packet("192.0.2.1", "192.0.2.2", 17);
        let short = (packet.len() - 1) as u16;
        packet[2..4].copy_from_slice(&short.to_be_bytes());
        assert!(link.write_packet(&mut sender, &packet, now).is_err(), "inconsistent total length");
        assert!(link.neighbor_pending.is_empty());
        assert_eq!(link.pending_neighbor_packets, 0);
        assert_eq!(link.pending_neighbor_bytes, 0);
    }

    #[test]
    fn frame_sender_without_multicast_subscription_support() {
        let now = at(1_700_000_000);
        let mut sender = FrameOnlySender::default();
        let mut link = link();
        let mut config = config(&["192.0.2.10/24", "fe80::10/64"]);
        config.multicast_limit = 32;
        link.apply_network_config(&mut sender, &config, 0).expect("the configuration applies");
        let group = address("239.32.33.34");
        let report = legacy_igmp_packet("192.0.2.10", "239.32.33.34", "239.32.33.34", 0x16, 0, true);
        link.write_packet(&mut sender, &report, now).expect("the report is a multicast frame");
        assert_eq!(sender.frames.len(), 1);
        assert_eq!(sender.frames[0].destination, Mac::new(0x0100_5e20_2122));
        assert_eq!(sender.frames[0].payload, report);
        assert!(multicast_group_for_ip(group).is_some());
        link.process_background_tasks(&mut sender, now).expect("maintenance without a subscriber");
    }

    #[test]
    fn automatic_all_hosts_multicast_subscriptions() {
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["192.0.2.10/24", "fd00::1/64"]), 0);
        for address in [address("224.0.0.1"), address("ff02::1"), solicited_node_multicast(address("fd00::1"))] {
            let group = multicast_group_for_ip(address).expect("a group");
            assert!(sender.subscriptions.get(&group).copied().unwrap_or(false), "{address} subscribed");
        }
    }

    #[test]
    fn multicast_mac_subscription_reference_counting() {
        let now = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        let first = address("224.1.2.3");
        let second = address("225.1.2.3");
        let group = multicast_group_for_ip(first).expect("a group");
        assert_eq!(multicast_group_for_ip(second), Some(group), "the addresses share a MAC");
        link.apply_legacy_membership(&mut sender, first, true, now);
        link.apply_legacy_membership(&mut sender, second, true, now);
        link.apply_legacy_membership(&mut sender, first, false, now);
        assert!(sender.subscriptions.get(&group).copied().unwrap_or(false), "one mapping remains");
        link.apply_legacy_membership(&mut sender, second, false, now);
        assert!(!sender.subscriptions.get(&group).copied().unwrap_or(false), "the last mapping left");
    }

    #[test]
    fn membership_expires_only_after_unanswered_query() {
        let mut now = at(1000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        let mut config = config(&["192.0.2.10/24"]);
        config.multicast_limit = 32;
        apply(&mut link, &mut sender, &config, 0);

        let group = address("239.21.22.23");
        let report = legacy_igmp_packet("192.0.2.10", "239.21.22.23", "239.21.22.23", 0x12, 0, false);
        link.write_packet(&mut sender, &report, now).expect("the report is a multicast frame");
        let want = multicast_group_for_ip(group).expect("a group");

        now += Duration::from_secs(24 * 60 * 60);
        link.process_background_tasks(&mut sender, now).expect("maintenance");
        assert!(sender.subscriptions.get(&want).copied().unwrap_or(false), "no Query, no expiry");

        let query_at = now;
        let query = legacy_igmp_packet("192.0.2.20", "224.0.0.1", "0.0.0.0", 0x11, 0, false);
        let mut padded = query.clone();
        padded.resize(46, 0);
        let frame = Frame {
            network_id: NETWORK_ID,
            source: remote_mac(),
            destination: local_mac(),
            ether_type: ETHER_TYPE_IPV4,
            payload: padded.clone(),
        };
        assert_eq!(link.handle_frame(&mut sender, &frame, now).expect("the Query is observed"), Some(padded));
        let interval =
            MEMBERSHIP_DEFAULT_QUERY_INTERVAL * MEMBERSHIP_DEFAULT_ROBUSTNESS + MEMBERSHIP_DEFAULT_RESPONSE_TIME * 2;
        now = query_at + interval;
        link.process_background_tasks(&mut sender, now).expect("maintenance");
        assert!(!sender.subscriptions.get(&want).copied().unwrap_or(false), "the unanswered Query expires");

        now += Duration::from_secs(1);
        link.write_packet(&mut sender, &report, now).expect("the report is a multicast frame");
        let query_at = now + Duration::from_secs(1);
        now = query_at;
        link.handle_frame(&mut sender, &frame, now).expect("the Query is observed");
        now += Duration::from_secs(1);
        link.write_packet(&mut sender, &report, now).expect("the report answers the Query");
        now = query_at + interval;
        link.process_background_tasks(&mut sender, now).expect("maintenance");
        assert!(sender.subscriptions.get(&want).copied().unwrap_or(false), "a response retains membership");
    }

    #[test]
    fn pending_neighbor_queues_enforce_their_limits() {
        let now = at(1_700_000_000);
        let mut sender = RecordingSender::default();
        let mut link = link();
        apply(&mut link, &mut sender, &config(&["10.0.0.1/8"]), MAX_NETWORK_MTU);
        let size = usize::try_from(MAX_NETWORK_MTU).expect("a small MTU");
        let mut packet = vec![0u8; size];
        packet[0] = 0x45;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[12..16].copy_from_slice(&octets4("10.0.0.1"));

        packet[16..20].copy_from_slice(&octets4("10.0.0.2"));
        let mut error = None;
        while error.is_none() {
            error = link.write_packet(&mut sender, &packet, now).err();
        }
        let (queued_packets, queued_bytes) = {
            let pending = link.neighbor_pending.get(&address("10.0.0.2")).expect("a pending destination");
            (pending.packets.len(), pending.bytes)
        };
        assert!(queued_bytes <= MAX_PENDING_NEIGHBOR_BYTES_PER_DESTINATION);
        assert!(queued_bytes > MAX_PENDING_NEIGHBOR_BYTES_PER_DESTINATION - packet.len());
        assert_eq!(link.pending_neighbor_packets, queued_packets);
        assert_eq!(link.pending_neighbor_bytes, queued_bytes);

        let mut error = None;
        for destination in 3u8..255 {
            packet[19] = destination;
            for _ in 0..64 {
                if link.write_packet(&mut sender, &packet, now).is_err() {
                    error = Some(());
                    break;
                }
            }
            if error.is_some() {
                break;
            }
        }
        assert!(error.is_some(), "the global byte limit is enforced");
        assert!(link.pending_neighbor_bytes <= MAX_PENDING_NEIGHBOR_BYTES);
        assert!(link.pending_neighbor_bytes > MAX_PENDING_NEIGHBOR_BYTES - packet.len());
        assert!(link.pending_neighbor_packets <= MAX_PENDING_NEIGHBOR_PACKETS);

        link.process_background_tasks(&mut sender, now + PENDING_NEIGHBOR_EXPIRATION).expect("expiry");
        assert_eq!(link.pending_neighbor_packets, 0);
        assert_eq!(link.pending_neighbor_bytes, 0);
        assert!(link.neighbor_pending.is_empty());
    }
}

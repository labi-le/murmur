//! The ZeroTier node: network configuration ownership, the peer table, the
//! physical path machinery, and the protocol state machine that drives them.
//!
//! Physical I/O stays behind [`NodeHost`], which transmits already-armored wire
//! datagrams and answers identity-discovery questions. Everything above that
//! seam — HELLO/OK/ECHO/ERROR exchanges, path selection, bonding, root
//! handling, the controller configuration cycle — runs in-process and
//! is exercised by two-node topologies that loop datagrams back through
//! [`Node::process_wire_packet`].
//!
//! Verbs owned by layers outside this module (network credentials, user
//! messages, remote trace) fail closed with [`NodeError::Unsupported`] rather
//! than being silently dropped.

pub mod frames;
pub mod handshake;
pub mod multicast;
pub mod network;
pub mod peer;
pub mod store;

pub use frames::PendingOutboundFrame;
pub use network::{
    ad_hoc_network_hub, authentication_from_config, network_state_name, strconv_hex16, uint64_rule_value, BridgeRoute,
    ConfigAssembly, Network, NetworkAuthenticationInfo, NetworkStatus, PendingMulticastFrame,
};
pub use peer::{PathKey, Peer, PeerPath, PeerRole, PeerRoute, PeerStatus};
pub use store::{FileStore, MemoryStore, StateStore, StoreError};

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime};

use ipnet::IpNet;

use crate::address::{controller, is_ad_hoc_network_id, Address};
use crate::bonding::{default_bonding_options, BondingOptions, BondingOptionsInput, BondingPolicy};
use crate::frame::Frame;
use crate::identity::{Identity, SIGNATURE_SIZE};
use crate::managed_ip::six_plane_address;
use crate::network_config::{
    build_network_config_metadata, parse_network_config, NetworkConfigData, NetworkType, DEFAULT_NETWORK_MTU,
    MAX_NETWORK_CONFIG_SIZE, NETWORK_CONFIG_FLAG_ENABLE_IPV6_NDP_EMULATION, NETWORK_CONFIG_VERSION,
};
use crate::packet::{Packet, Verb, DEFAULT_PHYSICAL_MTU};
use crate::rules::{
    NetworkRule, RULE_ACTION_ACCEPT, RULE_ACTION_DROP, RULE_FLAG_NOT, RULE_FLAG_OR, RULE_MATCH_CHARACTERISTICS,
    RULE_MATCH_ETHER_TYPE, RULE_MATCH_IP_DEST_PORT, RULE_MATCH_IP_PROTOCOL,
};
use crate::world::{World, WorldRoot, WorldType};

/// The official `2 hours` credential freshness window in milliseconds.
const CREDENTIAL_TIME_MAX_DELTA_MILLIS: u64 = 7_200_000;
/// Concurrent configuration assemblies retained for one network.
const MAX_INFO_ASSEMBLIES: usize = 3;
/// The official 256-by-32 expecting-reply ring.
pub const MAX_PENDING_REQUESTS: usize = 256 * 32;

/// The ZeroTier wire protocol version advertised in HELLO and requests.
pub const PROTOCOL_VERSION: u8 = 13;
/// The oldest peer protocol accepted in HELLO and its OK response.
pub const PROTOCOL_VERSION_MIN: u8 = 4;
/// The advertised ZeroTier One compatibility version.
pub const NODE_VERSION_MAJOR: u8 = 1;
pub const NODE_VERSION_MINOR: u8 = 16;
pub const NODE_VERSION_REVISION: u16 = 2;
/// The normal cadence for contacting the roots.
pub const ROOT_CONTACT_PERIOD: Duration = Duration::from_secs(5);
/// The root silence that changes an online node offline.
pub const ROOT_OFFLINE_TIMEOUT: Duration = Duration::from_secs(500);
/// The normal controller refresh cadence.
pub const NETWORK_CONFIG_REFRESH_PERIOD: Duration = Duration::from_secs(60);
/// The retry cadence before initial configuration.
pub const NETWORK_CONFIG_RETRY_PERIOD: Duration = Duration::from_secs(5);
/// The keepalive cadence for an active peer path.
pub const PEER_PATH_PING_PERIOD: Duration = Duration::from_secs(14);
/// The cadence for refreshing a peer handshake.
pub const PEER_FULL_HELLO_PERIOD: Duration = Duration::from_secs(60);
/// The receive-age window for preferring a direct path.
pub const PEER_PATH_ACTIVE_TIME: Duration = Duration::from_secs(19);
/// The receive-age limit for retaining a peer path.
pub const PEER_PATH_EXPIRATION: Duration = Duration::from_secs(243);
/// Bounds outstanding and duplicate path probes.
pub const PEER_PATH_PROBE_WINDOW: Duration = Duration::from_secs(1);
/// The longest interval between root path probes.
pub const ROOT_PATH_PING_PERIOD: Duration = Duration::from_secs(16 * 14);
/// Bounds the physical paths retained for one peer.
pub const MAX_PEER_PATHS: usize = 64;
/// Bounds each direct-path push scope and address family.
pub const MAX_PUSHED_PATHS_PER_SCOPE_AND_FAMILY: u8 = 8;
/// Bounds packets waiting for peer identity data.
pub const MAX_PENDING_INCOMING_PACKETS: usize = 32;
/// Bounds payloads waiting for peer discovery.
pub const MAX_PENDING_TRANSMITS: usize = 32;
/// Bounds concurrent fragmented-packet reassembly.
pub const MAX_FRAGMENT_ASSEMBLIES: usize = 32;
/// Bounds non-root peers held in active memory.
pub const MAX_LEARNED_PEERS: usize = 4096;
/// Bounds remembered local socket and address surfaces.
pub const MAX_SURFACE_ENTRIES: usize = 128;
/// The lifetime of a deferred inbound packet.
pub const PENDING_INCOMING_EXPIRATION: Duration = Duration::from_secs(5);
/// The lifetime of a deferred outbound payload.
pub const PENDING_TRANSMIT_EXPIRATION: Duration = Duration::from_secs(5);
/// The interval gating repeated credential sends and multicast announcements.
pub const MULTICAST_LIKE_PERIOD: Duration = Duration::from_secs(60);
/// Deferred unicast frames retained across all destinations.
pub const MAX_PENDING_FRAMES: usize = 256;

/// How long a learned multicast member stays eligible without a new LIKE.
pub const MULTICAST_MEMBER_EXPIRATION: Duration = Duration::from_secs(600);

/// How long a deferred multicast frame may wait for its recipients.
pub const MULTICAST_TRANSMIT_TIMEOUT: Duration = Duration::from_secs(5);

/// The shortest interval between explicit gathers for one group.
pub const MULTICAST_EXPLICIT_GATHER: Duration = Duration::from_secs(60);

/// The deferred frames retained for one multicast group.
pub const MAX_PENDING_MULTICAST_GROUP: usize = 32;

/// The learned multicast group table bound.
pub const MAX_MULTICAST_GROUPS: usize = 4096;

/// The learned members retained per multicast group.
pub const MAX_MULTICAST_GROUP_MEMBERS: usize = 4096;

/// Bridge destinations selected for one unknown MAC.
pub const MAX_BRIDGE_SPAM: usize = 32;
/// Learned virtual MAC-to-bridge routes per network.
pub const MAX_BRIDGE_ROUTES: usize = 65536;
/// The inactivity limit for a learned bridge route.
pub const BRIDGE_ROUTE_EXPIRATION: Duration = Duration::from_secs(600);
/// Limits repeated identity discovery requests.
pub const WHOIS_RETRY_PERIOD: Duration = Duration::from_millis(500);
/// Limits credential packets accepted from a peer.
pub const PEER_CREDENTIALS_RATE_LIMIT: Duration = Duration::from_secs(1);
/// Limits WHOIS requests accepted from a peer.
pub const PEER_WHOIS_RATE_LIMIT: Duration = Duration::from_millis(100);
/// Supplies rate limits for other peer requests.
pub const PEER_GENERAL_RATE_LIMIT: Duration = Duration::from_secs(1);
/// The window for limiting repeated path pushes.
pub const PUSH_DIRECT_PATHS_CUTOFF_TIME: Duration = Duration::from_secs(30);
/// The allowed path-push count in one window.
pub const PUSH_DIRECT_PATHS_CUTOFF_LIMIT: u32 = 8;
/// The cadence when no usable path was advertised.
pub const DIRECT_PATH_PUSH_INTERVAL: Duration = Duration::from_secs(15);
/// The cadence when a usable path exists.
pub const DIRECT_PATH_PUSH_HAVE_PATH_INTERVAL: Duration = Duration::from_secs(120);
/// Limits diagnostic reports when direct path quality oscillates.
pub const PEER_ROUTE_REPORT_INTERVAL: Duration = Duration::from_secs(1);
/// Limits attempts of cached physical paths.
pub const MEMORIZED_PATH_RETRY_PERIOD: Duration = Duration::from_secs(30);
/// The inactivity limit for a non-root peer.
pub const LEARNED_PEER_EXPIRATION: Duration = Duration::from_secs(500);
/// The lifetime of peer trust established by credentials.
pub const TRUST_EXPIRATION: Duration = Duration::from_secs(600);
/// The power-of-two identity validation limiter table size.
pub const IDENTITY_VALIDATION_BUCKETS: usize = 16384;
/// The sentinel cost assigned to an unmeasured path.
pub const UNKNOWN_PATH_LATENCY: Duration = Duration::from_millis(0xffff);
/// The interval at which a peer cache host is asked to drop stale entries.
pub const PEER_CACHE_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Elapsed time from `earlier` to `now`, saturating at zero.
pub(crate) fn elapsed(now: SystemTime, earlier: SystemTime) -> Duration {
    now.duration_since(earlier).unwrap_or_default()
}

/// One configured physical path class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalPathConfig {
    pub network: IpNet,
    /// A non-zero trusted-path ID disables ZeroTier packet encryption and MACs
    /// on the matching physical network, which must therefore be private.
    pub trusted_path_id: u64,
    pub mtu: usize,
    pub blacklist: bool,
}

/// Memorized physical endpoints and path exclusions for one peer.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerPathConfig {
    pub address: Address,
    pub try_endpoints: Vec<SocketAddr>,
    pub blacklist: Vec<IpNet>,
    pub bonding_policy: BondingPolicy,
    pub bonding_policy_set: bool,
    pub bonding_options: Option<BondingOptions>,
}

/// Reports a failed node-layer operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeError {
    #[error("invalid ZeroTier packet")]
    InvalidPacket,
    #[error("unknown ZeroTier peer")]
    UnknownPeer,
    #[error("ZeroTier network not found")]
    NetworkNotFound,
    #[error("ZeroTier network is not ready")]
    NetworkNotReady,
    #[error("ZeroTier network rules rejected frame")]
    FrameRejected,
    #[error("unsupported ZeroTier Ethernet destination")]
    UnsupportedEthernet,
    #[error("invalid ZeroTier network ID")]
    InvalidNetworkID,
    #[error("duplicate ZeroTier packet ID")]
    DuplicatePacketId,
    /// A packet whose armor and peer identity were valid but whose verb payload
    /// was not usable, which the official core still accounts as peer traffic.
    #[error("authenticated ZeroTier packet carried unusable content")]
    AuthenticatedContent(Box<Self>),
    #[error("no ZeroTier path")]
    NoPath,
    #[error("ZeroTier node is closed")]
    NodeClosed,
    #[error("ZeroTier identity collision")]
    IdentityCollision,
    #[error("invalid ZeroTier identity")]
    InvalidIdentity,
    #[error("invalid ZeroTier world")]
    InvalidWorld,
    #[error("too many learned ZeroTier peers")]
    TooManyLearnedPeers,
    #[error("too many pending ZeroTier path probes")]
    TooManyPathProbes,
    /// A verb whose handler layer is not part of this crate yet. Failing closed
    /// keeps an unimplemented path from looking like a delivered packet.
    #[error("ZeroTier {0} handling is not implemented in this crate")]
    Unsupported(&'static str),
    #[error("too many ZeroTier multicast subscriptions")]
    TooManyMulticastSubscriptions,
}

impl NodeError {
    /// The error beneath any authenticated-content marker.
    #[must_use]
    pub fn root(self) -> Self {
        match self {
            Self::AuthenticatedContent(inner) => *inner,
            Self::InvalidPacket
            | Self::UnknownPeer
            | Self::NetworkNotFound
            | Self::NetworkNotReady
            | Self::FrameRejected
            | Self::UnsupportedEthernet
            | Self::InvalidNetworkID
            | Self::DuplicatePacketId
            | Self::NoPath
            | Self::NodeClosed
            | Self::IdentityCollision
            | Self::InvalidIdentity
            | Self::InvalidWorld
            | Self::TooManyLearnedPeers
            | Self::TooManyPathProbes
            | Self::Unsupported(_)
            | Self::TooManyMulticastSubscriptions => self,
        }
    }

    fn authenticated(self) -> Self {
        Self::AuthenticatedContent(Box::new(self))
    }
}

/// The physical and identity services the protocol engine runs against.
///
/// [`NodeHost::send_wire`] receives an already-armored datagram and must not
/// call back into the same node. [`NodeHost::peer_identity`] takes `&self`
/// because capability validation resolves several signer identities while
/// network state is borrowed.
pub trait NodeHost {
    /// A peer identity from the active peer table or the persisted peer cache.
    fn peer_identity(&self, address: Address) -> Option<Identity>;
    /// Transmits one already-armored wire datagram to `remote` through
    /// `local_socket`, which is either a handle supplied to
    /// [`Node::process_wire_packet`] or [`ANY_LOCAL_SOCKET`].
    fn send_wire(&mut self, local_socket: i64, remote: SocketAddr, packet: Vec<u8>) -> Result<(), NodeError>;
    /// Starts bounded identity discovery for an address.
    fn request_whois(&mut self, address: Address);
    /// Notifies the embedding that one network's multicast subscriptions
    /// changed. The node performs the protocol announcement itself; this hook
    /// only reports it.
    fn announce_multicast(&mut self, network_id: u64);
    /// Records one controller configuration request in the remote trace.
    fn trace_network_config_request(&mut self, network_id: u64, controller: Address);
    /// The embedding's local external endpoints, advertised in pushes.
    fn direct_paths(&self) -> Vec<SocketAddr> {
        Vec::new()
    }
    /// Decides whether a candidate physical path may be probed or learned.
    /// Changing the result does not revoke a path that is already authenticated.
    fn path_check(&self, _address: Address, _local_socket: i64, _endpoint: SocketAddr) -> bool {
        true
    }
    /// Memorized physical endpoints for a peer without a live path.
    fn path_lookup(&self, _address: Address) -> Vec<SocketAddr> {
        Vec::new()
    }
    /// Drops peer cache entries that are older than `older_than`.
    fn clean_peer_cache(&mut self, _older_than: Duration) -> Result<(), NodeError> {
        Ok(())
    }
}

/// Identifies a packet not associated with one local physical socket, asking
/// [`NodeHost::send_wire`] to choose a suitable one.
pub const ANY_LOCAL_SOCKET: i64 = -1;

/// A node, network, peer, or path state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventType {
    NodeUp,
    NodeOnline,
    NodeOffline,
    NodeDown,
    NodeIdentityCollision,
    NetworkConfigPending,
    NetworkConfigReady,
    NetworkConfigChanged,
    NetworkAccessDenied,
    NetworkNotFound,
    NetworkAuthenticationRequired,
    NetworkLeft,
    PeerIdentityLearned,
    PeerPathLearned,
    PeerRouteChanged,
    LocalSurfaceChanged,
}

impl EventType {
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::NodeUp => 1,
            Self::NodeOnline => 2,
            Self::NodeOffline => 3,
            Self::NodeDown => 4,
            Self::NodeIdentityCollision => 5,
            Self::NetworkConfigPending => 6,
            Self::NetworkConfigReady => 7,
            Self::NetworkConfigChanged => 8,
            Self::NetworkAccessDenied => 9,
            Self::NetworkNotFound => 10,
            Self::NetworkAuthenticationRequired => 11,
            Self::NetworkLeft => 12,
            Self::PeerIdentityLearned => 13,
            Self::PeerPathLearned => 14,
            Self::PeerRouteChanged => 15,
            Self::LocalSurfaceChanged => 16,
        }
    }

    /// The stable diagnostic name of this event type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NodeUp => "node-up",
            Self::NodeOnline => "node-online",
            Self::NodeOffline => "node-offline",
            Self::NodeDown => "node-down",
            Self::NodeIdentityCollision => "node-identity-collision",
            Self::NetworkConfigPending => "network-config-pending",
            Self::NetworkConfigReady => "network-config-ready",
            Self::NetworkConfigChanged => "network-config-changed",
            Self::NetworkAccessDenied => "network-access-denied",
            Self::NetworkNotFound => "network-not-found",
            Self::NetworkAuthenticationRequired => "network-authentication-required",
            Self::NetworkLeft => "network-left",
            Self::PeerIdentityLearned => "peer-identity-learned",
            Self::PeerPathLearned => "peer-path-learned",
            Self::PeerRouteChanged => "peer-route-changed",
            Self::LocalSurfaceChanged => "local-surface-changed",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        const ALL: [EventType; 16] = [
            EventType::NodeUp,
            EventType::NodeOnline,
            EventType::NodeOffline,
            EventType::NodeDown,
            EventType::NodeIdentityCollision,
            EventType::NetworkConfigPending,
            EventType::NetworkConfigReady,
            EventType::NetworkConfigChanged,
            EventType::NetworkAccessDenied,
            EventType::NetworkNotFound,
            EventType::NetworkAuthenticationRequired,
            EventType::NetworkLeft,
            EventType::PeerIdentityLearned,
            EventType::PeerPathLearned,
            EventType::PeerRouteChanged,
            EventType::LocalSurfaceChanged,
        ];
        ALL.into_iter().find(|candidate| candidate.name() == name)
    }
}

/// One node, network, peer, or path state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub event_type: EventType,
    pub node_address: Address,
    pub network_id: u64,
    pub authentication: NetworkAuthenticationInfo,
    pub peer_address: Address,
    pub peer_role: PeerRole,
    pub endpoint: Option<SocketAddr>,
    pub previous_endpoint: Option<SocketAddr>,
    pub path_count: usize,
    pub route: PeerRoute,
    pub reporter_address: Address,
}

impl Default for Event {
    fn default() -> Self {
        Self {
            event_type: EventType::NodeUp,
            node_address: Address::new(0),
            network_id: 0,
            authentication: NetworkAuthenticationInfo::default(),
            peer_address: Address::new(0),
            peer_role: PeerRole::Leaf,
            endpoint: None,
            previous_endpoint: None,
            path_count: 0,
            route: PeerRoute::Unknown,
            reporter_address: Address::new(0),
        }
    }
}

impl Event {
    /// An event of `event_type`, with the remaining fields defaulted.
    #[must_use]
    pub fn new(event_type: EventType) -> Self {
        Self { event_type, ..Default::default() }
    }

    #[must_use]
    pub fn with_network(mut self, network_id: u64) -> Self {
        self.network_id = network_id;
        self
    }

    #[must_use]
    pub fn with_authentication(mut self, authentication: NetworkAuthenticationInfo) -> Self {
        self.authentication = authentication;
        self
    }

    #[must_use]
    pub fn with_address(mut self, address: Address) -> Self {
        self.node_address = address;
        self
    }

    #[must_use]
    pub fn with_peer_identity(mut self, address: Address, role: PeerRole) -> Self {
        self.peer_address = address;
        self.peer_role = role;
        self
    }

    #[must_use]
    pub fn with_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    #[must_use]
    pub fn with_previous_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.previous_endpoint = Some(endpoint);
        self
    }

    #[must_use]
    pub fn with_path_count(mut self, path_count: usize) -> Self {
        self.path_count = path_count;
        self
    }

    #[must_use]
    pub fn with_route(mut self, route: PeerRoute) -> Self {
        self.route = route;
        self
    }

    #[must_use]
    pub fn with_reporter(mut self, address: Address) -> Self {
        self.reporter_address = address;
        self
    }
}

/// One outbound request awaiting an `OK` or `ERROR` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    pub verb: Verb,
    pub peer: Address,
    pub network_id: u64,
    pub sent_at: Option<SystemTime>,
    pub slot: usize,
    pub generation: u64,
    /// The path the request was sent on, absent when the request was not
    /// associated with one physical socket.
    pub path: Option<PathKey>,
    /// The path priority the response should confirm.
    pub priority: i32,
    /// The successful physical copies of a broadcast request that have not yet
    /// produced a response. Allocated only when one request is broadcast.
    pub reply_paths: Option<std::collections::BTreeSet<PathKey>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PendingRequestSlot {
    packet_id: u64,
    generation: u64,
}

/// The bounded expecting-reply ring.
///
/// A new request at capacity replaces the oldest expectation in constant time
/// instead of failing the protocol operation that created it, matching the
/// official 256-by-32 ring.
#[derive(Debug, Clone)]
pub struct PendingRequests {
    entries: BTreeMap<u64, PendingRequest>,
    slots: Vec<PendingRequestSlot>,
    cursor: usize,
    generation: u64,
}

impl Default for PendingRequests {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            slots: vec![PendingRequestSlot::default(); MAX_PENDING_REQUESTS],
            cursor: 0,
            generation: 0,
        }
    }
}

impl PendingRequests {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn get(&self, packet_id: u64) -> Option<&PendingRequest> {
        self.entries.get(&packet_id)
    }

    #[must_use]
    pub fn contains(&self, packet_id: u64) -> bool {
        self.entries.contains_key(&packet_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &PendingRequest)> {
        self.entries.iter().map(|(packet_id, request)| (*packet_id, request))
    }

    /// Records `packet_id`, replacing the oldest ring entry when full.
    pub fn add(&mut self, packet_id: u64, request: PendingRequest) -> Result<(), NodeError> {
        if self.entries.contains_key(&packet_id) {
            return Err(NodeError::DuplicatePacketId);
        }
        let slot_index = self.cursor;
        self.cursor += 1;
        if self.cursor == self.slots.len() {
            self.cursor = 0;
        }
        let slot = self.slots.get(slot_index).copied().unwrap_or_default();
        if slot.generation != 0 {
            if let Some(existing) = self.entries.get(&slot.packet_id) {
                if existing.slot == slot_index && existing.generation == slot.generation {
                    self.entries.remove(&slot.packet_id);
                }
            }
        }
        self.generation += 1;
        if self.generation == 0 {
            self.generation += 1;
        }
        let mut request = request;
        request.slot = slot_index;
        request.generation = self.generation;
        if let Some(slot) = self.slots.get_mut(slot_index) {
            *slot = PendingRequestSlot { packet_id, generation: request.generation };
        }
        self.entries.insert(packet_id, request);
        Ok(())
    }

    /// Removes `packet_id`, clearing its ring slot only while it still owns it.
    pub fn delete(&mut self, packet_id: u64) {
        let Some(request) = self.entries.remove(&packet_id) else {
            return;
        };
        if request.generation == 0 || request.slot >= self.slots.len() {
            return;
        }
        let Some(slot) = self.slots.get_mut(request.slot) else {
            return;
        };
        if slot.packet_id == packet_id && slot.generation == request.generation {
            *slot = PendingRequestSlot::default();
        }
    }

    /// Drops expectations that have been outstanding longer than `max_age`.
    pub fn retain_recent(&mut self, now: SystemTime, max_age: Duration) {
        let stale: Vec<u64> = self
            .entries
            .iter()
            .filter(|(_, request)| request.sent_at.is_some_and(|sent| elapsed(now, sent) > max_age))
            .map(|(packet_id, _)| *packet_id)
            .collect();
        for packet_id in stale {
            self.delete(packet_id);
        }
    }
}

/// The cached credentials a node has already sent to one peer.
type PeerCredentials = BTreeMap<u64, SystemTime>;

/// A ZeroTier protocol core whose physical I/O is supplied by the embedding.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the protocol models these as independent named flags; packing them would obscure the wire mapping"
)]
pub struct Node {
    pub(crate) identity: Identity,
    pub(crate) store: Box<dyn StateStore>,
    pub(crate) host: Box<dyn NodeHost>,
    pub(crate) networks: BTreeMap<u64, Network>,
    pub(crate) peer_credentials: BTreeMap<Address, PeerCredentials>,
    pub(crate) pending: PendingRequests,
    pub(crate) events: Vec<Event>,
    pub(crate) callbacks: Vec<NetworkConfigData>,
    pub(crate) on_network_config: Option<Box<dyn FnMut(&NetworkConfigData) + Send>>,
    pub(crate) delivered_frames: Vec<Frame>,
    pub(crate) on_frame: Option<Box<dyn FnMut(&Frame) + Send>>,
    pub(crate) pending_frames: BTreeMap<Address, Vec<PendingOutboundFrame>>,
    pub(crate) peers: BTreeMap<Address, Peer>,
    pub(crate) wire_paths: BTreeMap<PathKey, peer::WirePathActivity>,
    pub(crate) peer_paths: BTreeMap<Address, PeerPathConfig>,
    pub(crate) physical_paths: Vec<PhysicalPathConfig>,
    pub(crate) physical_mtu: usize,
    pub(crate) bonding_policy: BondingPolicy,
    pub(crate) bonding_options: BondingOptions,
    pub(crate) low_bandwidth: bool,
    pub(crate) encrypted_hello: bool,
    pub(crate) planet: World,
    pub(crate) moons: BTreeMap<u64, World>,
    pub(crate) moon_seeds: BTreeMap<u64, Address>,
    pub(crate) pending_incoming: BTreeMap<Address, Vec<handshake::ReceivedWirePacket>>,
    pub(crate) pending_whois: BTreeMap<Address, SystemTime>,
    pub(crate) pending_transmits: Vec<handshake::PendingTransmit>,
    pub(crate) fragments: BTreeMap<u64, handshake::FragmentAssembly>,
    pub(crate) fragment_slots: Vec<Option<u64>>,
    pub(crate) fragment_cursor: usize,
    pub(crate) identity_checks: Vec<Option<SystemTime>>,
    pub(crate) surfaces: BTreeMap<handshake::SurfaceKey, handshake::SurfaceState>,
    pub(crate) last_root_contact: Option<SystemTime>,
    pub(crate) last_root_receive: Option<SystemTime>,
    pub(crate) last_peer_cache_cleanup: Option<SystemTime>,
    pub(crate) online: bool,
    pub(crate) closed: bool,
}

impl core::fmt::Debug for Node {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Node")
            .field("address", &self.identity.address())
            .field("networks", &self.networks.len())
            .field("peers", &self.peers.len())
            .field("paths", &self.physical_paths.len())
            .field("online", &self.online)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl Node {
    /// Creates a node with the embedded planet and the protocol defaults.
    ///
    /// Lifecycle events are emitted by [`Node::open`], which is the entry point
    /// an embedding uses; this constructor starts the node already up.
    #[must_use]
    pub fn new(identity: Identity, store: Box<dyn StateStore>, host: Box<dyn NodeHost>) -> Self {
        Self {
            identity,
            store,
            host,
            networks: BTreeMap::new(),
            peer_credentials: BTreeMap::new(),
            pending: PendingRequests::new(),
            events: Vec::new(),
            callbacks: Vec::new(),
            on_network_config: None,
            delivered_frames: Vec::new(),
            on_frame: None,
            pending_frames: BTreeMap::new(),
            peers: BTreeMap::new(),
            wire_paths: BTreeMap::new(),
            peer_paths: BTreeMap::new(),
            physical_paths: Vec::new(),
            physical_mtu: DEFAULT_PHYSICAL_MTU,
            bonding_policy: BondingPolicy::None,
            bonding_options: default_bonding_options(),
            low_bandwidth: false,
            encrypted_hello: false,
            planet: embedded_planet().clone(),
            moons: BTreeMap::new(),
            moon_seeds: BTreeMap::new(),
            pending_incoming: BTreeMap::new(),
            pending_whois: BTreeMap::new(),
            pending_transmits: Vec::new(),
            fragments: BTreeMap::new(),
            fragment_slots: vec![None; MAX_FRAGMENT_ASSEMBLIES],
            fragment_cursor: 0,
            identity_checks: vec![None; IDENTITY_VALIDATION_BUCKETS],
            surfaces: BTreeMap::new(),
            last_root_contact: None,
            last_root_receive: None,
            last_peer_cache_cleanup: None,
            online: false,
            closed: false,
        }
    }

    /// Loads or creates the node identity and installs the planet's roots, as
    /// the official node does when it starts.
    pub fn open(mut store: Box<dyn StateStore>, host: Box<dyn NodeHost>) -> Result<Self, NodeError> {
        let identity = load_or_create_identity(store.as_mut())?;
        let mut node = Self::new(identity, store, host);
        if let Some(cached) = load_stored_world(node.store.as_ref(), &planet_state_name()) {
            if cached.world_type == WorldType::Planet
                && cached.id == node.planet.id
                && cached.timestamp >= node.planet.timestamp
                && cached.validate_roots().is_ok()
            {
                node.planet = cached;
            }
        }
        node.refresh_topology_roots_locked();
        node.emit(Event::new(EventType::NodeUp));
        Ok(node)
    }

    /// Prevents further protocol work and emits the node-down event.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.fragments.clear();
        for slot in &mut self.fragment_slots {
            *slot = None;
        }
        self.emit(Event::new(EventType::NodeDown));
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Reports whether root traffic has been received recently.
    #[must_use]
    pub fn online(&self) -> bool {
        self.online
    }

    /// An independently owned snapshot of the active planet.
    #[must_use]
    pub fn planet(&self) -> World {
        self.planet.clone()
    }

    /// Adds a federated root world, queuing identity discovery for its seed.
    pub fn orbit(&mut self, world_id: u64, seed: Address, now: SystemTime) -> Result<(), NodeError> {
        if world_id == 0 || (!seed.is_zero() && seed.is_reserved()) {
            return Err(NodeError::InvalidWorld);
        }
        if self.closed {
            return Err(NodeError::NodeClosed);
        }
        if self.moons.contains_key(&world_id) {
            return Ok(());
        }
        if let Some(cached) = load_stored_world(self.store.as_ref(), &moon_state_name(world_id)) {
            if cached.world_type == WorldType::Moon && cached.id == world_id && cached.validate_roots().is_ok() {
                return self.add_world_locked(cached, true);
            }
        }
        if !seed.is_zero() {
            self.moon_seeds.insert(world_id, seed);
            self.request_whois_locked(seed, now);
        }
        Ok(())
    }

    /// Removes a moon and its persisted topology from the node.
    pub fn deorbit(&mut self, world_id: u64) -> Result<(), NodeError> {
        if self.closed {
            return Err(NodeError::NodeClosed);
        }
        self.moons.remove(&world_id);
        self.moon_seeds.remove(&world_id);
        self.refresh_topology_roots_locked();
        let _ = self.store.delete(&moon_state_name(world_id));
        Ok(())
    }

    /// Independently owned snapshots of the active moons, ordered by world ID.
    #[must_use]
    pub fn moons(&self) -> Vec<World> {
        self.moons.values().cloned().collect()
    }

    /// A known active or persisted public identity for `address`.
    pub fn peer_identity(&mut self, address: Address, now: SystemTime) -> Option<Identity> {
        self.load_peer_cache_locked(address, now)?;
        self.peers.get(&address).map(|peer| peer.identity.clone())
    }

    /// A diagnostic snapshot of every known peer, ordered by address.
    #[must_use]
    pub fn peers(&self, now: SystemTime) -> Vec<PeerStatus> {
        self.peers_snapshot(now)
    }

    /// The bonding policy this node applies to peers without an override.
    #[must_use]
    pub fn bonding_policy(&self) -> BondingPolicy {
        self.bonding_policy
    }

    pub fn set_bonding_policy(&mut self, policy: BondingPolicy) {
        self.bonding_policy = policy;
    }

    #[must_use]
    pub fn bonding_options(&self) -> &BondingOptions {
        &self.bonding_options
    }

    /// Applies validated bonding options.
    pub fn set_bonding_options(&mut self, options: BondingOptionsInput) -> Result<(), crate::bonding::BondingError> {
        self.bonding_options = crate::bonding::normalize_bonding_options(options)?;
        Ok(())
    }

    #[must_use]
    pub fn peer_path_configs(&self) -> &BTreeMap<Address, PeerPathConfig> {
        &self.peer_paths
    }

    /// Installs the memorized endpoints and bonding override for one peer.
    pub fn set_peer_path_config(&mut self, config: PeerPathConfig) {
        self.peer_paths.insert(config.address, config);
    }

    #[must_use]
    pub fn physical_paths(&self) -> &[PhysicalPathConfig] {
        &self.physical_paths
    }

    pub fn set_physical_paths(&mut self, paths: Vec<PhysicalPathConfig>) {
        self.physical_paths = paths;
    }
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    #[must_use]
    pub fn address(&self) -> Address {
        self.identity.address()
    }

    #[must_use]
    pub fn network(&self, network_id: u64) -> Option<&Network> {
        self.networks.get(&network_id)
    }

    pub fn networks(&self) -> impl Iterator<Item = (u64, &Network)> {
        self.networks.iter().map(|(network_id, network)| (*network_id, network))
    }

    #[must_use]
    pub fn pending(&self) -> &PendingRequests {
        &self.pending
    }

    pub fn pending_mut(&mut self) -> &mut PendingRequests {
        &mut self.pending
    }

    #[must_use]
    pub fn peer_credentials(&self) -> &BTreeMap<Address, PeerCredentials> {
        &self.peer_credentials
    }

    pub fn peer_credentials_mut(&mut self) -> &mut BTreeMap<Address, PeerCredentials> {
        &mut self.peer_credentials
    }

    pub fn set_network_config_callback(&mut self, callback: Box<dyn FnMut(&NetworkConfigData) + Send>) {
        self.on_network_config = Some(callback);
    }

    /// Installs the callback that receives frames delivered to this node.
    pub fn set_frame_callback(&mut self, callback: Box<dyn FnMut(&Frame) + Send>) {
        self.on_frame = Some(callback);
    }

    /// Drains the frames delivered to this node when no frame callback is
    /// installed.
    pub fn take_delivered_frames(&mut self) -> Vec<Frame> {
        std::mem::take(&mut self.delivered_frames)
    }

    /// The frames waiting for the frame callback or [`Node::take_delivered_frames`].
    #[must_use]
    pub fn delivered_frames(&self) -> &[Frame] {
        &self.delivered_frames
    }

    /// Drains the queued events, which the embedding delivers after the
    /// protocol operation that produced them completes.
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Runs the queued configuration callbacks against deep copies of the
    /// configuration each one was queued for, then hands every frame delivered
    /// since the last call to the frame callback.
    pub fn run_callbacks(&mut self) {
        let pending = std::mem::take(&mut self.callbacks);
        if let Some(callback) = self.on_network_config.as_mut() {
            for config in &pending {
                callback(config);
            }
        }
        if let Some(callback) = self.on_frame.as_mut() {
            for frame in std::mem::take(&mut self.delivered_frames) {
                callback(&frame);
            }
        }
    }

    /// The configurations waiting for the configuration callback.
    #[must_use]
    pub fn pending_callbacks(&self) -> &[NetworkConfigData] {
        &self.callbacks
    }

    /// Creates network state, loads cached configuration, and contacts the
    /// controller.
    pub fn join(&mut self, network_id: u64, now: SystemTime) -> Result<(), NodeError> {
        if network_id == 0 || (!is_ad_hoc_network_id(network_id) && controller(network_id).is_reserved()) {
            return Err(NodeError::InvalidNetworkID);
        }
        if self.networks.contains_key(&network_id) {
            return Ok(());
        }
        self.networks.insert(network_id, Network::new(network_id));
        self.emit(Event::new(EventType::NetworkConfigPending).with_network(network_id));
        self.load_cached_network_config_locked(network_id);
        self.request_network_config_locked(network_id, now)
    }

    /// Requests a fresh configuration for a joined network.
    ///
    /// A failed network emits configuration-pending and arms its next
    /// controller failure, while its public status keeps the last authoritative
    /// controller result until the request completes.
    pub fn refresh_network(&mut self, network_id: u64, now: SystemTime) -> Result<(), NodeError> {
        let Some(network) = self.networks.get(&network_id) else {
            return Err(NodeError::NetworkNotFound);
        };
        let retrying_failure =
            network.status != NetworkStatus::Ok && network.status != NetworkStatus::RequestingConfiguration;
        if retrying_failure {
            if let Some(network) = self.networks.get_mut(&network_id) {
                network.report_next_failure = true;
            }
            self.emit(Event::new(EventType::NetworkConfigPending).with_network(network_id));
        }
        let result = self.request_network_config_locked(network_id, now);
        if result.is_err() && retrying_failure {
            if let Some(network) = self.networks.get_mut(&network_id) {
                network.report_next_failure = false;
            }
        }
        result
    }

    /// Removes a joined network and its cached configuration.
    pub fn leave(&mut self, network_id: u64) -> Result<(), NodeError> {
        if self.networks.remove(&network_id).is_none() {
            return Ok(());
        }
        self.emit(Event::new(EventType::NetworkLeft).with_network(network_id));
        let _ = self.store.delete(&network_state_name(network_id));
        Ok(())
    }

    /// Chooses local ad-hoc setup or controller contact for `network_id`.
    pub fn request_network_config_locked(&mut self, network_id: u64, now: SystemTime) -> Result<(), NodeError> {
        if is_ad_hoc_network_id(network_id) {
            return self.configure_ad_hoc_network_locked(network_id, now);
        }
        let controller_address = controller(network_id);
        if controller_address == self.identity.address() {
            if self.networks.contains_key(&network_id) {
                self.set_network_failure_locked(
                    network_id,
                    NetworkStatus::NotFound,
                    NetworkAuthenticationInfo::default(),
                    EventType::NetworkNotFound,
                );
            }
            return Ok(());
        }
        if self.load_peer_cache_locked(controller_address, now).is_none() {
            self.request_whois_locked(controller_address, now);
            return Ok(());
        }
        self.send_network_config_request_packet_locked(network_id, now)
    }

    /// Synthesizes the deterministic public ad-hoc configuration.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the ad-hoc ID packs each port and the IPv4 octet into fixed 16-bit and 8-bit fields"
    )]
    pub fn configure_ad_hoc_network_locked(&mut self, network_id: u64, now: SystemTime) -> Result<(), NodeError> {
        let Some(network) = self.networks.get(&network_id) else {
            return Err(NodeError::NetworkNotFound);
        };
        let event_type = if network.status == NetworkStatus::Ok {
            EventType::NetworkConfigChanged
        } else {
            EventType::NetworkConfigReady
        };
        let mut config = NetworkConfigData {
            version: NETWORK_CONFIG_VERSION,
            network_id,
            timestamp: unix_millis(now),
            revision: 1,
            issued_to: self.identity.address(),
            flags: NETWORK_CONFIG_FLAG_ENABLE_IPV6_NDP_EMULATION,
            credential_time_max_delta: CREDENTIAL_TIME_MAX_DELTA_MILLIS,
            network_type: NetworkType::PUBLIC,
            mtu: DEFAULT_NETWORK_MTU,
            ..Default::default()
        };
        if network_id.trailing_zeros() >= 24 {
            let start_port = (network_id >> 40) as u16;
            let end_port = (network_id >> 24) as u16;
            if end_port < start_port {
                return self.reject_ad_hoc_network_locked(network_id, now);
            }
            config.name = format!("adhoc-{start_port:04x}-{end_port:04x}");
            config.assigned = vec![six_plane_address(network_id, self.identity.address())];
            let mut port_range = Vec::with_capacity(4);
            port_range.extend_from_slice(&start_port.to_be_bytes());
            port_range.extend_from_slice(&end_port.to_be_bytes());
            config.rules = vec![
                NetworkRule { rule_type: RULE_MATCH_ETHER_TYPE | RULE_FLAG_NOT, value: vec![0x86, 0xdd] },
                NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() },
                NetworkRule { rule_type: RULE_MATCH_IP_PROTOCOL, value: vec![58] },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
                NetworkRule { rule_type: RULE_MATCH_IP_PROTOCOL, value: vec![17] },
                NetworkRule { rule_type: RULE_MATCH_IP_PROTOCOL | RULE_FLAG_OR, value: vec![6] },
                NetworkRule { rule_type: RULE_MATCH_IP_DEST_PORT, value: port_range },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
                NetworkRule {
                    rule_type: RULE_MATCH_CHARACTERISTICS | RULE_FLAG_NOT,
                    value: uint64_rule_value(0x02).to_vec(),
                },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
                NetworkRule { rule_type: RULE_MATCH_CHARACTERISTICS, value: uint64_rule_value(0x02).to_vec() },
                NetworkRule { rule_type: RULE_MATCH_CHARACTERISTICS, value: uint64_rule_value(0x10).to_vec() },
                NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() },
                NetworkRule { rule_type: RULE_ACTION_DROP, value: Vec::new() },
            ];
        } else if network_id & 0xff == 0x01 {
            let local = self.identity.address().uint64();
            let octet = (network_id >> 48) as u8;
            let ipv4 = Ipv4Addr::new(octet, (local >> 16) as u8, (local >> 8) as u8, local as u8);
            config.name = format!("adhoc-{octet}.0.0.0");
            config.multicast_limit = 1024;
            config.assigned = vec![
                six_plane_address(network_id, self.identity.address()),
                IpNet::new(IpAddr::V4(ipv4), 8).map_err(|_| NodeError::InvalidNetworkID)?,
            ];
            config.rules = vec![NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() }];
            if let Some(hub) = ad_hoc_network_hub(network_id) {
                config.specialists = vec![hub.uint64()];
                self.host.request_whois(hub);
            }
        } else {
            return self.reject_ad_hoc_network_locked(network_id, now);
        }
        if let Some(network) = self.networks.get_mut(&network_id) {
            network.config = config.clone();
        }
        self.invalidate_network_credentials_locked(network_id);
        if let Some(network) = self.networks.get_mut(&network_id) {
            network.multicast_announcements.clear();
            network.authentication = NetworkAuthenticationInfo::default();
            network.status = NetworkStatus::Ok;
            network.report_next_failure = false;
            network.last_config_request = Some(now);
            network.last_config_receive = Some(now);
            network.config_update_serial += 1;
        }
        if self.on_network_config.is_some() {
            self.callbacks.push(config);
        }
        self.emit(Event::new(event_type).with_network(network_id));
        self.announce_multicast_locked(network_id, now);
        self.host.announce_multicast(network_id);
        Ok(())
    }

    /// Marks an unsupported ad-hoc ID as not found.
    pub fn reject_ad_hoc_network_locked(&mut self, network_id: u64, now: SystemTime) -> Result<(), NodeError> {
        let Some(network) = self.networks.get_mut(&network_id) else {
            return Err(NodeError::NetworkNotFound);
        };
        network.last_config_request = Some(now);
        self.set_network_failure_locked(
            network_id,
            NetworkStatus::NotFound,
            NetworkAuthenticationInfo::default(),
            EventType::NetworkNotFound,
        );
        Ok(())
    }

    /// Updates a controller failure, emitting only a real status or
    /// authentication-detail transition.
    pub fn set_network_failure_locked(
        &mut self,
        network_id: u64,
        status: NetworkStatus,
        authentication: NetworkAuthenticationInfo,
        event_type: EventType,
    ) {
        let Some(network) = self.networks.get_mut(&network_id) else {
            return;
        };
        let report = network.report_next_failure;
        network.report_next_failure = false;
        if !report && network.status == status && network.authentication == authentication {
            return;
        }
        network.status = status;
        network.authentication = authentication.clone();
        self.emit(Event::new(event_type).with_network(network_id).with_authentication(authentication));
    }

    /// Sends one controller configuration request and records it as pending.
    pub fn send_network_config_request_packet_locked(
        &mut self,
        network_id: u64,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        let controller_address = controller(network_id);
        if self.load_peer_cache_locked(controller_address, now).is_none() {
            return Err(NodeError::UnknownPeer);
        }
        let metadata = build_network_config_metadata().map_err(|_| NodeError::InvalidPacket)?;
        let mut packet = Packet::new(controller_address, self.identity.address(), Verb::NetworkConfigRequest)
            .map_err(|_| NodeError::InvalidPacket)?;
        let _ = packet.append_u64(network_id);
        let _ = packet.append_u16(u16::try_from(metadata.len()).unwrap_or(0));
        let _ = packet.append(&metadata);
        match self.networks.get(&network_id) {
            Some(network) if network.config.network_id == network_id => {
                let _ = packet.append_u64(network.config.revision);
                let _ = packet.append_u64(network.config.timestamp);
            }
            _ => {
                let _ = packet.append(&[0u8; 16]);
            }
        }
        packet.compress().map_err(|_| NodeError::InvalidPacket)?;
        let packet_id = packet.packet_id();
        self.pending.add(
            packet_id,
            PendingRequest {
                verb: Verb::NetworkConfigRequest,
                peer: controller_address,
                network_id,
                sent_at: Some(now),
                slot: 0,
                generation: 0,
                path: None,
                priority: 0,
                reply_paths: None,
            },
        )?;
        if let Err(error) = self.send_packet_locked(controller_address, packet, true) {
            self.pending.delete(packet_id);
            return Err(error);
        }
        self.host.trace_network_config_request(network_id, controller_address);
        if let Some(network) = self.networks.get_mut(&network_id) {
            network.last_config_request = Some(now);
        }
        Ok(())
    }

    /// Applies a valid persisted configuration.
    pub fn load_cached_network_config_locked(&mut self, network_id: u64) {
        let Some(data) = self.store.get(&network_state_name(network_id)) else {
            return;
        };
        let Ok(config) = parse_network_config(&data) else {
            return;
        };
        let local = self.identity.address();
        if config.network_id != network_id || config.issued_to != local {
            return;
        }
        if config.network_type != NetworkType::PUBLIC {
            let Some(com) = config.com.as_ref() else {
                return;
            };
            if com.network_id() != network_id || com.issued_to() != local {
                return;
            }
            if let Some(network) = self.networks.get_mut(&network_id) {
                network.members.insert(local, com.clone());
            }
        }
        for certificate in &config.ownership {
            if certificate.network_id != network_id
                || certificate.issued_to != local
                || certificate.signed_by != controller(network_id)
            {
                return;
            }
        }
        for tag in &config.tags {
            if tag.network_id != network_id || tag.issued_to != local || tag.signed_by != controller(network_id) {
                return;
            }
        }
        for capability in &config.capabilities {
            if capability.network_id != network_id
                || capability.issued_to() != local
                || capability.custody.first().is_none_or(|entry| entry.from != controller(network_id))
            {
                return;
            }
        }
        let event = {
            let Some(network) = self.networks.get_mut(&network_id) else {
                return;
            };
            network.config = config.clone();
            network.multicast_announcements.clear();
            network.authentication = authentication_from_config(&config);
            network.status = NetworkStatus::Ok;
            network.report_next_failure = false;
            Event::new(EventType::NetworkConfigReady).with_network(network_id).with_address(local)
        };
        self.invalidate_network_credentials_locked(network_id);
        if self.on_network_config.is_some() {
            self.callbacks.push(config);
        }
        self.emit(event);
    }

    /// Validates and stores one configuration chunk.
    pub fn handle_network_config_chunk_locked(
        &mut self,
        packet: &Packet,
        payload_offset: usize,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        let payload = packet.payload();
        if payload_offset > payload.len() || payload.len() - payload_offset < 10 {
            return Err(NodeError::InvalidPacket);
        }
        let start = payload_offset;
        let mut offset = payload_offset;
        let network_id = read_u64_be(payload, offset).ok_or(NodeError::InvalidPacket)?;
        offset += 8;
        let chunk_length = usize::from(read_u16_be(payload, offset).ok_or(NodeError::InvalidPacket)?);
        offset += 2;
        if payload.len() - offset < chunk_length {
            return Err(NodeError::InvalidPacket);
        }
        let chunk = payload.get(offset..offset + chunk_length).ok_or(NodeError::InvalidPacket)?.to_vec();
        offset += chunk_length;
        if !self.networks.contains_key(&network_id) {
            return Ok(());
        }
        let source = packet.source();
        let (update_id, total_length, chunk_index, fast_propagate) = if offset == payload.len() {
            if source != controller(network_id) {
                return Err(NodeError::InvalidPacket.authenticated());
            }
            (packet.packet_id(), chunk_length, 0, false)
        } else {
            self.parse_config_chunk_envelope(payload, network_id, start, offset, chunk_length)?
        };
        let Some(network) = self.networks.get_mut(&network_id) else {
            return Ok(());
        };
        if update_id == network.last_config_update_id {
            return Ok(());
        }
        let sized = network.assemblies.get(&update_id).is_some_and(|assembly| assembly.data.len() == total_length);
        if !sized {
            if !network.assemblies.contains_key(&update_id) && network.assemblies.len() >= MAX_INFO_ASSEMBLIES {
                let oldest =
                    network.assemblies.iter().min_by_key(|(_, candidate)| candidate.updated_at).map(|(id, _)| *id);
                if let Some(oldest) = oldest {
                    network.assemblies.remove(&oldest);
                }
            }
            network.assemblies.insert(update_id, ConfigAssembly::new(update_id, total_length));
        }
        let (new_bytes, complete) = {
            let Some(assembly) = network.assemblies.get_mut(&update_id) else {
                return Ok(());
            };
            (merge_config_chunk(assembly, chunk_index, &chunk, now)?, assembly.complete())
        };
        if fast_propagate && new_bytes {
            self.propagate_network_config_chunk_locked(network_id, source, payload.get(start..).unwrap_or_default());
        }
        if !complete {
            return Ok(());
        }
        self.apply_network_config_assembly_locked(network_id, update_id, now).map_err(NodeError::authenticated)
    }

    /// Parses and authenticates the signed envelope of one chunk reply.
    fn parse_config_chunk_envelope(
        &self,
        payload: &[u8],
        network_id: u64,
        start: usize,
        offset: usize,
        chunk_length: usize,
    ) -> Result<(u64, usize, usize, bool), NodeError> {
        if payload.len() - offset < 17 + 3 + SIGNATURE_SIZE {
            return Err(NodeError::InvalidPacket);
        }
        let fast_propagate = payload.get(offset).copied().ok_or(NodeError::InvalidPacket)? & 0x01 != 0;
        let mut offset = offset + 1;
        let update_id = read_u64_be(payload, offset).ok_or(NodeError::InvalidPacket)?;
        offset += 8;
        let total_length = read_u32_be(payload, offset).ok_or(NodeError::InvalidPacket)? as usize;
        offset += 4;
        let chunk_index = read_u32_be(payload, offset).ok_or(NodeError::InvalidPacket)? as usize;
        offset += 4;
        if update_id == 0
            || total_length == 0
            || total_length > MAX_NETWORK_CONFIG_SIZE
            || chunk_index + chunk_length > total_length
        {
            return Err(NodeError::InvalidPacket.authenticated());
        }
        let version = payload.get(offset).copied().ok_or_else(|| NodeError::InvalidPacket.authenticated())?;
        let signature_length =
            read_u16_be(payload, offset + 1).ok_or_else(|| NodeError::InvalidPacket.authenticated())?;
        if version != 1
            || usize::from(signature_length) != SIGNATURE_SIZE
            || payload.len() - offset < 3 + SIGNATURE_SIZE
        {
            return Err(NodeError::InvalidPacket.authenticated());
        }
        let signature_range = offset + 3..offset + 3 + SIGNATURE_SIZE;
        let signature = payload.get(signature_range).ok_or_else(|| NodeError::InvalidPacket.authenticated())?;
        let Some(identity) = self.host.peer_identity(controller(network_id)) else {
            return Err(NodeError::InvalidPacket.authenticated());
        };
        let signed = payload.get(start..offset).ok_or_else(|| NodeError::InvalidPacket.authenticated())?;
        if !identity.verify(signed, signature) {
            return Err(NodeError::InvalidPacket.authenticated());
        }
        Ok((update_id, total_length, chunk_index, fast_propagate))
    }

    /// Parses and installs a complete configuration assembly.
    pub fn apply_network_config_assembly_locked(
        &mut self,
        network_id: u64,
        update_id: u64,
        now: SystemTime,
    ) -> Result<(), NodeError> {
        let Some(assembly) = self.networks.get(&network_id).and_then(|network| network.assemblies.get(&update_id))
        else {
            return Ok(());
        };
        if !assembly.complete() {
            return Ok(());
        }
        let raw = assembly.data.clone();
        let Ok(config) = parse_network_config(&raw) else {
            self.discard_assembly(network_id, update_id);
            return Err(NodeError::InvalidPacket);
        };
        let local = self.identity.address();
        if config.network_id != network_id || config.issued_to != local {
            self.discard_assembly(network_id, update_id);
            return Err(NodeError::InvalidPacket);
        }
        let accepted = self
            .networks
            .get(&network_id)
            .is_some_and(|network| network.status == NetworkStatus::Ok && network.config.equal(&config));
        if accepted {
            if let Some(network) = self.networks.get_mut(&network_id) {
                network.assemblies.remove(&update_id);
                network.last_config_update_id = update_id;
                network.last_config_receive = Some(now);
            }
            self.clear_pending_network_config_requests_locked(network_id);
            return Ok(());
        }
        let ready = self.networks.get(&network_id).is_some_and(|network| network.status == NetworkStatus::Ok);
        let event_type = if ready { EventType::NetworkConfigChanged } else { EventType::NetworkConfigReady };
        let controller_identity = self.host.peer_identity(controller(network_id));
        if config.network_type != NetworkType::PUBLIC {
            let proven = config.com.as_ref().is_some_and(|com| {
                com.issued_to() == local
                    && com.network_id() == network_id
                    && controller_identity.as_ref().is_some_and(|identity| com.verify(identity))
            });
            if !proven {
                self.discard_assembly(network_id, update_id);
                return Err(NodeError::InvalidPacket);
            }
        }
        for certificate in &config.ownership {
            let proven = controller_identity.as_ref().is_some_and(|identity| {
                certificate.network_id == network_id && certificate.issued_to == local && certificate.verify(identity)
            });
            if !proven {
                self.discard_assembly(network_id, update_id);
                return Err(NodeError::InvalidPacket);
            }
        }
        for tag in &config.tags {
            let proven = controller_identity
                .as_ref()
                .is_some_and(|identity| tag.network_id == network_id && tag.issued_to == local && tag.verify(identity));
            if !proven {
                self.discard_assembly(network_id, update_id);
                return Err(NodeError::InvalidPacket);
            }
        }
        for capability in &config.capabilities {
            if capability.network_id != network_id || capability.issued_to() != local {
                self.discard_assembly(network_id, update_id);
                return Err(NodeError::InvalidPacket);
            }
            let (missing, valid) = capability.verify_chain(|address| self.host.peer_identity(address));
            if !valid {
                if !missing.is_zero() {
                    self.host.request_whois(missing);
                    return Err(NodeError::UnknownPeer);
                }
                self.discard_assembly(network_id, update_id);
                return Err(NodeError::InvalidPacket);
            }
        }
        self.invalidate_network_credentials_locked(network_id);
        if let Some(network) = self.networks.get_mut(&network_id) {
            network.status = NetworkStatus::Ok;
            network.report_next_failure = false;
            network.config = config.clone();
            network.multicast_announcements.clear();
            network.authentication = authentication_from_config(&config);
            network.assemblies.remove(&update_id);
            network.last_config_update_id = update_id;
            network.config_update_serial += 1;
            network.last_config_receive = Some(now);
        }
        let _ = self.store.put(&network_state_name(network_id), &config.raw);
        self.clear_pending_network_config_requests_locked(network_id);
        if self.on_network_config.is_some() {
            self.callbacks.push(config);
        }
        self.emit(Event::new(event_type).with_network(network_id).with_address(local));
        self.announce_multicast_locked(network_id, now);
        self.host.announce_multicast(network_id);
        Ok(())
    }

    /// Removes requests satisfied for one network.
    pub fn clear_pending_network_config_requests_locked(&mut self, network_id: u64) {
        let packet_ids: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, request)| request.verb == Verb::NetworkConfigRequest && request.network_id == network_id)
            .map(|(packet_id, _)| packet_id)
            .collect();
        for packet_id in packet_ids {
            self.pending.delete(packet_id);
        }
    }

    /// Forgets the credentials already sent to every peer for one network, so
    /// they are re-sent against the changed configuration.
    pub fn invalidate_network_credentials_locked(&mut self, network_id: u64) {
        for sent in self.peer_credentials.values_mut() {
            sent.remove(&network_id);
        }
    }

    /// Reapplies assemblies deferred for peer identity discovery.
    pub fn retry_completed_config_assemblies_locked(&mut self, now: SystemTime) {
        let pending: Vec<(u64, u64)> = self
            .networks
            .values()
            .flat_map(|network| {
                network
                    .assemblies
                    .values()
                    .filter(|assembly| assembly.complete())
                    .map(|assembly| (network.id, assembly.update_id))
            })
            .collect();
        for (network_id, update_id) in pending {
            let _ = self.apply_network_config_assembly_locked(network_id, update_id, now);
        }
    }

    /// Forwards controller chunks to eligible network members.
    pub fn propagate_network_config_chunk_locked(&mut self, network_id: u64, sent_from: Address, chunk: &[u8]) {
        let Some(network) = self.networks.get(&network_id) else {
            return;
        };
        let recipients = network.credential_recipients();
        let controller_address = controller(network_id);
        let local = self.identity.address();
        for address in recipients {
            if address == sent_from || address == controller_address || address == local {
                continue;
            }
            if !self.peers.contains_key(&address) {
                continue;
            }
            let Ok(mut packet) = Packet::new(address, local, Verb::NetworkConfig) else {
                continue;
            };
            if packet.append(chunk).is_err() {
                continue;
            }
            let _ = self.send_packet_locked(address, packet, true);
        }
    }

    fn discard_assembly(&mut self, network_id: u64, update_id: u64) {
        if let Some(network) = self.networks.get_mut(&network_id) {
            network.assemblies.remove(&update_id);
        }
    }

    fn emit(&mut self, mut event: Event) {
        if event.node_address.is_zero() {
            event.node_address = self.identity.address();
        }
        self.events.push(event);
    }
}

fn read_u64_be(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_be_bytes(raw))
}

fn read_u32_be(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(raw))
}

fn read_u16_be(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(raw))
}

/// Merges `chunk` into `assembly` at `chunk_index`, reporting whether it carried bytes that were not already received.
fn merge_config_chunk(
    assembly: &mut ConfigAssembly,
    chunk_index: usize,
    chunk: &[u8],
    now: SystemTime,
) -> Result<bool, NodeError> {
    assembly.updated_at = Some(now);
    let end = chunk_index + chunk.len();
    let received = assembly.received.get(chunk_index..end).ok_or_else(|| NodeError::InvalidPacket.authenticated())?;
    let data = assembly.data.get(chunk_index..end).ok_or_else(|| NodeError::InvalidPacket.authenticated())?;
    for (flag, (existing, byte)) in received.iter().zip(data.iter().zip(chunk)) {
        if *flag && existing != byte {
            return Err(NodeError::InvalidPacket.authenticated());
        }
    }
    assembly
        .data
        .get_mut(chunk_index..end)
        .ok_or_else(|| NodeError::InvalidPacket.authenticated())?
        .copy_from_slice(chunk);
    let mut new_bytes = false;
    let received =
        assembly.received.get_mut(chunk_index..end).ok_or_else(|| NodeError::InvalidPacket.authenticated())?;
    for flag in received.iter_mut() {
        if !*flag {
            *flag = true;
            assembly.count += 1;
            new_bytes = true;
        }
    }
    Ok(new_bytes)
}

/// The embedded Earth trust anchor, parsed once per process.
#[expect(clippy::expect_used, reason = "the embedded planet is a build-time constant; parsing it is a crate invariant")]
fn embedded_planet() -> &'static World {
    static PLANET: std::sync::LazyLock<World> =
        std::sync::LazyLock::new(|| World::default_planet().expect("the embedded planet is valid"));
    &PLANET
}

/// The persistent object name of the node's secret identity.
pub const IDENTITY_SECRET_STATE_NAME: &str = "identity.secret";
/// The persistent object name of the node's public identity.
pub const IDENTITY_PUBLIC_STATE_NAME: &str = "identity.public";

/// Maps a source IP into the identity validation limiter table.
fn identity_validation_bucket(address: IpAddr) -> usize {
    let mask = IDENTITY_VALIDATION_BUCKETS - 1;
    match peer::unmap(address) {
        IpAddr::V4(address) => {
            let raw = address.octets();
            let mut hash = (usize::from(raw[0]) << 16) | (usize::from(raw[1]) << 8) | usize::from(raw[2]);
            hash ^= hash >> 14;
            hash & mask
        }
        IpAddr::V6(address) => {
            let raw = address.octets();
            let mut hash = 0usize;
            for value in &raw[..6] {
                hash = hash.wrapping_shl(1).wrapping_add(usize::from(*value));
            }
            hash & mask
        }
    }
}

/// Reports whether `world` contains a root with `address`.
#[must_use]
pub fn world_has_root(world: &World, address: Address) -> bool {
    world.roots.iter().any(|root| root.identity.address() == address)
}

/// Reads and fully validates one persisted world object.
pub fn load_stored_world(store: &dyn StateStore, name: &str) -> Option<World> {
    let data = store.get(name)?;
    let (world, consumed) = World::parse(&data).ok()?;
    (consumed == data.len()).then_some(world)
}

/// The official persistent planet object name.
#[must_use]
pub fn planet_state_name() -> String {
    "planet".to_owned()
}

/// The official persistent object name for a moon.
#[must_use]
pub fn moon_state_name(world_id: u64) -> String {
    format!("moons.d/{world_id:016x}.moon")
}

/// Restores a valid secret identity or persists a new one.
pub fn load_or_create_identity(store: &mut dyn StateStore) -> Result<Identity, NodeError> {
    if let Some(data) = store.get(IDENTITY_SECRET_STATE_NAME) {
        if !data.is_empty() {
            let identity = Identity::parse(&String::from_utf8_lossy(&data)).map_err(|_| NodeError::InvalidIdentity)?;
            identity.validate().map_err(|_| NodeError::InvalidIdentity)?;
            if let Some(public) = store.get(IDENTITY_PUBLIC_STATE_NAME) {
                if !public.is_empty() && public != identity.public_string().as_bytes() {
                    // The public half is a cache of the secret; the secret wins.
                }
            }
            return Ok(identity);
        }
    }
    let identity = Identity::generate();
    let _ = store.put(IDENTITY_SECRET_STATE_NAME, identity.secret_string().as_bytes());
    let _ = store.put(IDENTITY_PUBLIC_STATE_NAME, identity.public_string().as_bytes());
    Ok(identity)
}

pub(crate) fn unix_millis(now: SystemTime) -> u64 {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

impl Node {
    /// The trust role assigned by the active planet and moons.
    #[must_use]
    pub fn peer_role_locked(&self, address: Address) -> PeerRole {
        if world_has_root(&self.planet, address) {
            return PeerRole::Planet;
        }
        if self.moons.values().any(|moon| world_has_root(moon, address)) {
            return PeerRole::Moon;
        }
        PeerRole::Leaf
    }

    /// Validates and installs a peer identity under the capacity policy.
    pub fn add_peer_locked(&mut self, identity: Identity, root: bool) -> Result<(), NodeError> {
        let address = identity.address();
        if address == self.identity.address() {
            return Ok(());
        }
        let role = self.peer_role_locked(address);
        if let Some(existing) = self.peers.get_mut(&address) {
            if existing.identity.public_string() != identity.public_string() {
                return Err(NodeError::IdentityCollision);
            }
            if root {
                existing.root = true;
                existing.role = if role == PeerRole::Leaf { PeerRole::Planet } else { role };
            }
            return Ok(());
        }
        let peer = self.new_peer_locked(identity, root)?;
        self.peers.insert(address, peer);
        self.peer_added_locked(address, SystemTime::now());
        Ok(())
    }

    /// Constructs an unpublished peer and applies the learned-peer capacity
    /// policy, so a caller may finish restoring state before publishing it.
    pub fn new_peer_locked(&mut self, identity: Identity, root: bool) -> Result<Peer, NodeError> {
        let public_key_hash = crate::membership::public_key_hash(&identity);
        let key = self.identity.agree(&identity).map_err(|_| NodeError::InvalidIdentity)?;
        let aes_keys = crate::ztcrypto::gmac_siv::GmacSivKeys::new(&key).map_err(|_| NodeError::InvalidIdentity)?;
        if !root && self.learned_peer_count_locked() >= MAX_LEARNED_PEERS && !self.evict_oldest_learned_peer_locked() {
            return Err(NodeError::TooManyLearnedPeers);
        }
        let mut role = PeerRole::Leaf;
        if root {
            role = self.peer_role_locked(identity.address());
            if role == PeerRole::Leaf {
                role = PeerRole::Planet;
            }
        }
        Ok(Peer::new(identity, public_key_hash, key, aes_keys, root, role))
    }

    /// Releases the work that was waiting for a newly published peer.
    pub fn peer_added_locked(&mut self, address: Address, now: SystemTime) {
        let role = self.peers.get(&address).map(|peer| peer.role).unwrap_or_default();
        self.emit(Event::new(EventType::PeerIdentityLearned).with_peer_identity(address, role));
        self.flush_pending_frames_locked(address, now);
        self.flush_peer_multicast_locked(address, now);
        self.retry_pending_transmits_locked(Some(address), now);
    }

    /// The number of active non-root peers.
    #[must_use]
    pub fn learned_peer_count_locked(&self) -> usize {
        self.peers.values().filter(|peer| !peer.root).count()
    }

    /// Removes the stalest learned peer, reporting whether one was available.
    pub fn evict_oldest_learned_peer_locked(&mut self) -> bool {
        let oldest = self
            .peers
            .iter()
            .filter(|(_, peer)| !peer.root)
            .min_by_key(|(address, peer)| (peer.last_receive, **address))
            .map(|(address, _)| *address);
        match oldest {
            Some(address) => {
                self.remove_peer_locked(address);
                true
            }
            None => false,
        }
    }

    /// Removes a peer and the network state recorded for it.
    pub fn remove_peer_locked(&mut self, address: Address) {
        let keys: Vec<PathKey> =
            self.peers.get(&address).map(|peer| peer.paths.keys().copied().collect()).unwrap_or_default();
        for key in keys {
            self.delete_peer_path_locked(address, key);
        }
        self.peers.remove(&address);
        for network in self.networks.values_mut() {
            network.members.remove(&address);
            network.ownership.remove(&address);
            network.tags.remove(&address);
            network.capabilities.remove(&address);
            network.associated.remove(&address);
            network.multicast_announcements.remove(&address);
            network.multicast.retain(|_, members| {
                members.remove(&address);
                !members.is_empty()
            });
            network.bridge_routes.retain(|_, route| route.bridge != address);
        }
    }

    /// The active peer, loading its identity from the host's peer cache when
    /// the node has not learned it yet.
    pub fn load_peer_cache_locked(&mut self, address: Address, _now: SystemTime) -> Option<Address> {
        if address.is_zero() || address.is_reserved() || address == self.identity.address() {
            return None;
        }
        if self.peers.contains_key(&address) {
            return Some(address);
        }
        // The persisted `peers.d/*.peer` cache is an embedding service, exposed
        // through NodeHost::peer_identity rather than a file tree here. Unlike
        // the on-disk cache reader, a host may hand back an identity that still
        // carries its private half; only the public half is ever serialized.
        let identity = self.host.peer_identity(address)?;
        if identity.address() != address || identity.validate().is_err() {
            return None;
        }
        let root = self.is_root_address_locked(address);
        let peer = self.new_peer_locked(identity, root).ok()?;
        self.peers.insert(address, peer);
        self.peer_added_locked(address, SystemTime::now());
        Some(address)
    }

    /// Every planet and moon root, ordered with the planet first.
    #[must_use]
    pub fn all_roots_locked(&self) -> Vec<WorldRoot> {
        let mut roots = self.planet.roots.clone();
        for moon in self.moons.values() {
            roots.extend(moon.roots.iter().cloned());
        }
        roots
    }

    /// Reports whether `address` belongs to the active topology.
    #[must_use]
    pub fn is_root_address_locked(&self, address: Address) -> bool {
        self.all_roots_locked().iter().any(|root| root.identity.address() == address)
    }

    /// Validates a topology update sender.
    #[must_use]
    pub fn should_accept_world_update_from_locked(&self, address: Address) -> bool {
        if self.peers.get(&address).is_some_and(|peer| peer.root) {
            return true;
        }
        self.moon_seeds.values().any(|seed| *seed == address)
    }

    /// Validates, orders, persists, and applies a planet or moon.
    pub fn add_world_locked(&mut self, world: World, always_accept_new: bool) -> Result<(), NodeError> {
        world.validate_roots().map_err(|_| NodeError::InvalidWorld)?;
        match world.world_type {
            WorldType::Planet => {
                if !self.planet.should_be_replaced_by(&world) {
                    return Err(NodeError::InvalidWorld);
                }
                let serialized = world.serialize().ok();
                self.planet = world;
                if let Some(data) = serialized {
                    let _ = self.store.put(&planet_state_name(), &data);
                }
            }
            WorldType::Moon => {
                let world_id = world.id;
                match self.moons.get(&world_id) {
                    Some(current) => {
                        if !current.should_be_replaced_by(&world) {
                            return Err(NodeError::InvalidWorld);
                        }
                    }
                    None if !always_accept_new => {
                        let accepted = self.moon_seeds.get(&world_id).is_some_and(|seed| world_has_root(&world, *seed));
                        if !accepted {
                            return Err(NodeError::InvalidWorld);
                        }
                    }
                    None => {}
                }
                let serialized = world.serialize().ok();
                self.moons.insert(world_id, world);
                self.moon_seeds.remove(&world_id);
                if let Some(data) = serialized {
                    let _ = self.store.put(&moon_state_name(world_id), &data);
                }
            }
            WorldType::Null => return Err(NodeError::InvalidWorld),
        }
        self.refresh_topology_roots_locked();
        Ok(())
    }

    /// Reconciles the active root peers with the planet and moons.
    pub fn refresh_topology_roots_locked(&mut self) {
        for peer in self.peers.values_mut() {
            peer.root = false;
            peer.role = PeerRole::Leaf;
        }
        let roots: Vec<Identity> = self.all_roots_locked().into_iter().map(|root| root.identity).collect();
        for identity in roots {
            let _ = self.add_peer_locked(identity, true);
        }
    }

    /// The best current path to any root.
    #[must_use]
    pub fn best_root_path(&self, now: SystemTime) -> Option<PathKey> {
        self.best_root_peer_path(now).1
    }

    /// The best root peer, which may have no authenticated path yet so that a
    /// caller can still select its identity.
    #[must_use]
    pub fn best_root_peer_path(&self, now: SystemTime) -> (Option<Address>, Option<PathKey>) {
        let mut fallback: Option<Address> = None;
        let mut selected: Option<(Address, PathKey)> = None;
        let mut best_quality = u64::from(u32::MAX);
        for root in self.all_roots_locked() {
            let address = root.identity.address();
            let Some(peer) = self.peers.get(&address) else {
                continue;
            };
            if fallback.is_none() {
                fallback = Some(address);
            }
            let Some(path) = self.best_direct_peer_path(peer, now) else {
                continue;
            };
            let age = peer.last_receive.map_or(LEARNED_PEER_EXPIRATION, |received| elapsed(now, received));
            let quality = if age < LEARNED_PEER_EXPIRATION {
                let latency = peer.paths.get(&path).map_or(UNKNOWN_PATH_LATENCY, peer::path_latency);
                let latency_millis = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
                let missed_pings = age.as_secs() / (PEER_FULL_HELLO_PERIOD.as_secs() + 1) + 1;
                latency_millis.saturating_mul(missed_pings).min(u64::from(u32::MAX))
            } else {
                u64::from(u32::MAX)
            };
            if selected.is_none() || quality <= best_quality {
                selected = Some((address, path));
                best_quality = quality;
            }
        }
        match selected {
            Some((address, path)) => (Some(address), Some(path)),
            None => (fallback, None),
        }
    }

    /// Updates online state after traffic from an allowed root.
    pub fn mark_root_receive_locked(&mut self, address: Address, remote: SocketAddr, now: SystemTime) {
        let Some(peer) = self.peers.get_mut(&address) else {
            return;
        };
        if !peer.root {
            return;
        }
        let (role, peer_address) = (peer.role, peer.identity.address());
        self.last_root_receive = Some(now);
        if !self.online {
            self.online = true;
            self.emit(Event::new(EventType::NodeOnline).with_peer_identity(peer_address, role).with_endpoint(remote));
        }
    }

    /// Reports whether this address may spend an identity validation slot.
    pub fn allow_identity_validation_locked(&mut self, address: IpAddr, now: SystemTime) -> bool {
        let bucket = identity_validation_bucket(address);
        let previous = self.identity_checks.get(bucket).copied().flatten();
        if previous.is_some_and(|at| elapsed(now, at) < Self::identity_validation_rate_limit()) {
            return false;
        }
        if let Some(slot) = self.identity_checks.get_mut(bucket) {
            *slot = Some(now);
        }
        true
    }

    /// The configured MTU and trusted-path ID for an endpoint.
    #[must_use]
    pub fn outbound_path_info(&self, endpoint: SocketAddr) -> (usize, u64) {
        let address = peer::unmap(endpoint.ip());
        for physical_path in &self.physical_paths {
            if physical_path.network.contains(&address) {
                let mtu = if physical_path.mtu != 0 { physical_path.mtu } else { self.physical_mtu };
                return (mtu, physical_path.trusted_path_id);
            }
        }
        (self.physical_mtu, 0)
    }

    /// Validates a trusted-path ID against the endpoint policy.
    #[must_use]
    pub fn inbound_path_trusted_locked(&self, endpoint: SocketAddr, trusted_path_id: u64) -> bool {
        if trusted_path_id == 0 {
            return false;
        }
        let address = peer::unmap(endpoint.ip());
        self.physical_paths.iter().any(|physical_path| {
            physical_path.trusted_path_id == trusted_path_id && physical_path.network.contains(&address)
        })
    }

    /// Applies physical network and peer path restrictions to an endpoint.
    #[must_use]
    pub fn path_allowed_locked(&self, address: Address, endpoint: SocketAddr, local_socket: i64) -> bool {
        if endpoint.port() == 0 || peer::path_scope(endpoint.ip()) == 0 {
            return false;
        }
        let root = self.peers.get(&address).is_some_and(|peer| peer.root);
        if root && !self.root_endpoint_allowed_locked(address, endpoint.ip()) {
            return false;
        }
        let unmapped = peer::unmap(endpoint.ip());
        if self.physical_paths.iter().any(|path| path.blacklist && path.network.contains(&unmapped)) {
            return false;
        }
        if let Some(configured) = self.peer_paths.get(&address) {
            if configured.blacklist.iter().any(|network| network.contains(&unmapped)) {
                return false;
            }
        }
        for network in self.networks.values() {
            for assigned in &network.config.assigned {
                if assigned.contains(&unmapped) {
                    return false;
                }
            }
        }
        self.host.path_check(address, local_socket, endpoint)
    }

    /// Validates an endpoint against a root definition.
    #[must_use]
    pub fn root_endpoint_allowed_locked(&self, address: Address, endpoint: IpAddr) -> bool {
        let mut found_root = false;
        for root in self.all_roots_locked() {
            if root.identity.address() != address {
                continue;
            }
            found_root = true;
            if root.endpoints.is_empty() {
                return true;
            }
            if root.endpoints.iter().any(|stable| peer::unmap(stable.ip()) == peer::unmap(endpoint)) {
                return true;
            }
        }
        !found_root
    }

    /// The interval between identity validation attempts for one source.
    fn identity_validation_rate_limit() -> Duration {
        #[cfg(target_arch = "x86_64")]
        {
            Duration::from_secs(2)
        }
        #[cfg(target_arch = "x86")]
        {
            Duration::from_secs(5)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            Duration::from_secs(10)
        }
    }

    /// Installs one pending request under `packet_id`.
    pub fn add_pending_locked(&mut self, packet_id: u64, request: PendingRequest) -> Result<(), NodeError> {
        self.pending.add(packet_id, request)
    }

    pub fn delete_pending_locked(&mut self, packet_id: u64) {
        self.pending.delete(packet_id);
    }

    /// Contacts roots, maintains peers and paths, and reports the next useful
    /// call time.
    pub fn process_background_tasks(&mut self, now: SystemTime) -> SystemTime {
        if self.closed {
            return now + PEER_CACHE_CLEANUP_INTERVAL;
        }
        let contact_period = if self.low_bandwidth { ROOT_CONTACT_PERIOD * 5 } else { ROOT_CONTACT_PERIOD };
        let config_refresh_period =
            if self.low_bandwidth { NETWORK_CONFIG_REFRESH_PERIOD * 64 } else { NETWORK_CONFIG_REFRESH_PERIOD };
        let contact_due = self.last_root_contact.is_none_or(|contacted| elapsed(now, contacted) >= contact_period);
        if contact_due {
            self.last_root_contact = Some(now);
            self.contact_roots_locked(now);
            let network_ids: Vec<u64> = self.networks.keys().copied().collect();
            for network_id in network_ids {
                let Some(network) = self.networks.get(&network_id) else {
                    continue;
                };
                let awaiting = network.last_config_receive < network.last_config_request;
                let due = network.status != NetworkStatus::Ok
                    || network.last_config_request.is_none()
                    || (awaiting
                        && network
                            .last_config_request
                            .is_none_or(|sent| elapsed(now, sent) >= NETWORK_CONFIG_RETRY_PERIOD))
                    || (!awaiting
                        && network.last_config_request.is_none_or(|sent| elapsed(now, sent) >= config_refresh_period));
                if due {
                    let _ = self.request_network_config_locked(network_id, now);
                }
                let ready = self.networks.get(&network_id).is_some_and(|network| network.status == NetworkStatus::Ok);
                if ready && !self.low_bandwidth {
                    self.announce_multicast_locked(network_id, now);
                }
            }
        }
        self.retry_pending_incoming_locked(now);
        self.retry_pending_transmits_locked(None, now);
        self.expire_pending_frames_locked(now);
        self.expire_bridge_routes_locked(now);
        self.pending.retain_recent(now, Duration::from_secs(30));
        self.retry_pending_whois_locked(now);
        let addresses: Vec<Address> = self.peers.keys().copied().collect();
        for address in addresses {
            self.maintain_peer_locked(address, now, contact_due);
        }
        self.maintain_peer_cache_locked(now);
        self.expire_learned_peers_locked(now);
        if self.online && self.last_root_receive.is_none_or(|received| elapsed(now, received) >= ROOT_OFFLINE_TIMEOUT) {
            self.online = false;
            self.emit(Event::new(EventType::NodeOffline));
        }
        self.next_background_deadline_locked(now, contact_period)
    }

    /// Sends a full HELLO to every configured root when due.
    fn contact_roots_locked(&mut self, now: SystemTime) {
        for root in self.all_roots_locked() {
            let address = root.identity.address();
            let Some(peer) = self.peers.get(&address) else {
                continue;
            };
            let recently_helloed = !peer.paths.is_empty()
                && peer.last_full_hello.is_some_and(|helloed| elapsed(now, helloed) <= ROOT_PATH_PING_PERIOD);
            if recently_helloed {
                continue;
            }
            let max_priority = peer.paths.values().map(|path| path.priority).max().unwrap_or(1);
            let stale: Vec<PathKey> = peer
                .paths
                .iter()
                .filter(|(_, path)| {
                    path.last_receive.is_none_or(|received| elapsed(now, received) >= PEER_PATH_EXPIRATION)
                        || (path.priority > 0 && path.priority < max_priority)
                })
                .map(|(key, _)| *key)
                .collect();
            for key in stale {
                self.delete_peer_path_locked(address, key);
            }
            let paths: Vec<PathKey> =
                self.peers.get(&address).map(|peer| peer.paths.keys().copied().collect()).unwrap_or_default();
            let mut sent_v4 = false;
            let mut sent_v6 = false;
            for key in paths {
                if let Some(path) = self.peers.get_mut(&address).and_then(|peer| peer.paths.get_mut(&key)) {
                    path.last_probe = Some(now);
                }
                if self.send_hello_at_path_locked(address, key, now, 0, 0).is_err() {
                    continue;
                }
                if key.endpoint.is_ipv4() {
                    sent_v4 = true;
                } else {
                    sent_v6 = true;
                }
            }
            if let Some(peer) = self.peers.get_mut(&address) {
                peer.last_full_hello = Some(now);
            }
            for endpoint in &root.endpoints {
                if endpoint.is_ipv4() {
                    if sent_v4 {
                        continue;
                    }
                    sent_v4 = true;
                } else {
                    if sent_v6 {
                        continue;
                    }
                    sent_v6 = true;
                }
                let _ = self.send_hello_at_path_locked(address, PathKey::new(ANY_LOCAL_SOCKET, *endpoint), now, 0, 0);
            }
        }
        let seeds: Vec<Address> = self.moon_seeds.values().copied().collect();
        for seed in seeds {
            if !self.peers.contains_key(&seed) {
                self.request_whois_locked(seed, now);
                continue;
            }
            let path = self.peers.get(&seed).and_then(|peer| self.best_peer_path(peer, now));
            if let Some(path) = path {
                let _ = self.send_hello_at_path_locked(seed, path, now, 0, 0);
            }
        }
    }

    /// Heartbeats, expires, and re-bonds one peer's paths.
    fn maintain_peer_locked(&mut self, address: Address, now: SystemTime, contact_due: bool) {
        self.flush_pending_peer_user_route_locked(address, now);
        let Some(peer) = self.peers.get(&address) else {
            return;
        };
        let root = peer.root;
        self.expire_peer_echo_requests_locked(address, now);
        if root {
            self.expire_root_paths_locked(address, now);
            self.send_qos_measurements_locked(address, now);
            return;
        }
        let active = self
            .peers
            .get(&address)
            .and_then(|peer| peer.last_nontrivial_receive)
            .is_some_and(|received| elapsed(now, received) < LEARNED_PEER_EXPIRATION);
        let run_heartbeat = active && (!self.low_bandwidth || contact_due);
        let send_full_hello = run_heartbeat
            && self
                .peers
                .get(&address)
                .and_then(|peer| peer.last_full_hello)
                .is_none_or(|helloed| elapsed(now, helloed) >= PEER_FULL_HELLO_PERIOD);
        if send_full_hello {
            if let Some(peer) = self.peers.get_mut(&address) {
                peer.last_full_hello = Some(now);
            }
        }
        self.expire_leaf_paths_locked(address, now);
        if run_heartbeat {
            let due: Vec<PathKey> = self
                .peers
                .get(&address)
                .map(|peer| {
                    peer.paths
                        .iter()
                        .filter(|(key, path)| {
                            send_full_hello
                                || self
                                    .wire_path_last_send(**key, path)
                                    .is_none_or(|sent| elapsed(now, sent) >= PEER_PATH_PING_PERIOD)
                        })
                        .map(|(key, _)| *key)
                        .collect()
                })
                .unwrap_or_default();
            for key in due {
                if let Some(path) = self.peers.get_mut(&address).and_then(|peer| peer.paths.get_mut(&key)) {
                    path.last_probe = Some(now);
                }
                if send_full_hello {
                    let _ = self.send_hello_at_path_locked(address, key, now, 0, 0);
                } else {
                    let _ = self.send_path_probe_locked(address, key.local_socket, key.endpoint, now, None);
                }
            }
        }
        self.expire_peer_probe_state_locked(address, now);
        self.maintain_bond_paths_locked(address, now);
        self.send_qos_measurements_locked(address, now);
    }

    fn expire_peer_echo_requests_locked(&mut self, address: Address, now: SystemTime) {
        let expired: Vec<PathKey> = self
            .peers
            .get(&address)
            .map(|peer| {
                peer.last_echo_request
                    .iter()
                    .filter(|(_, last)| elapsed(now, **last) >= PEER_GENERAL_RATE_LIMIT / 6)
                    .map(|(key, _)| *key)
                    .collect()
            })
            .unwrap_or_default();
        if let Some(peer) = self.peers.get_mut(&address) {
            for key in expired {
                peer.last_echo_request.remove(&key);
            }
        }
    }

    fn expire_root_paths_locked(&mut self, address: Address, now: SystemTime) {
        let expired: Vec<PathKey> = self
            .peers
            .get(&address)
            .map(|peer| {
                peer.paths
                    .iter()
                    .filter(|(_, path)| {
                        path.last_receive.is_none_or(|received| elapsed(now, received) >= PEER_PATH_EXPIRATION)
                    })
                    .map(|(key, _)| *key)
                    .collect()
            })
            .unwrap_or_default();
        for key in expired {
            self.delete_peer_path_locked(address, key);
        }
    }

    fn expire_leaf_paths_locked(&mut self, address: Address, now: SystemTime) {
        let expired: Vec<PathKey> = self
            .peers
            .get(&address)
            .map(|peer| {
                let max_priority = peer.paths.values().map(|path| path.priority).max().unwrap_or(1);
                peer.paths
                    .iter()
                    .filter(|(_, path)| {
                        path.last_receive.is_none_or(|received| elapsed(now, received) >= PEER_PATH_EXPIRATION)
                            || (path.priority > 0 && path.priority < max_priority)
                    })
                    .map(|(key, _)| *key)
                    .collect()
            })
            .unwrap_or_default();
        for key in expired {
            self.delete_peer_path_locked(address, key);
        }
    }

    fn expire_peer_probe_state_locked(&mut self, address: Address, now: SystemTime) {
        let stale_probes: Vec<PathKey> = self
            .peers
            .get(&address)
            .map(|peer| {
                peer.path_probe
                    .iter()
                    .filter(|(_, probed)| elapsed(now, **probed) > PEER_PATH_PROBE_WINDOW)
                    .map(|(key, _)| *key)
                    .collect()
            })
            .unwrap_or_default();
        let stale_flows: Vec<i32> = self
            .peers
            .get(&address)
            .map(|peer| {
                peer.bond_flows
                    .iter()
                    .filter(|(_, flow)| elapsed(now, flow.last_active) >= PEER_PATH_EXPIRATION)
                    .map(|(flow_id, _)| *flow_id)
                    .collect()
            })
            .unwrap_or_default();
        for key in stale_probes {
            if let Some(peer) = self.peers.get_mut(&address) {
                peer.path_probe.remove(&key);
            }
        }
        for flow_id in stale_flows {
            let path = self.peers.get(&address).and_then(|peer| peer.bond_flows.get(&flow_id)).map(|flow| flow.path);
            if let Some(path) = path {
                if let Some(peer) = self.peers.get_mut(&address) {
                    peer.bond_flows.remove(&flow_id);
                    if let Some(state) = peer.paths.get_mut(&path) {
                        state.bond_assigned_flows = state.bond_assigned_flows.saturating_sub(1);
                    }
                }
            }
        }
    }

    fn maintain_bond_paths_locked(&mut self, address: Address, now: SystemTime) {
        let policy = self.bonding_policy_for_peer_locked(address);
        if policy == BondingPolicy::None {
            return;
        }
        let options = self.bonding_options_for_peer_static(address);
        self.maintain_bond_locked(address, policy, &options, now);
        let monitor_interval = options.failover_interval / 3;
        let due: Vec<PathKey> = self
            .peers
            .get(&address)
            .map(|peer| {
                peer.paths
                    .iter()
                    .filter(|(key, path)| {
                        if !crate::bonding::bond_path_allowed(**key, &options) {
                            return false;
                        }
                        let interval = if path.bond_alive { monitor_interval } else { options.failover_interval };
                        interval > Duration::ZERO
                            && self.wire_path_age(**key, path, now) >= interval
                            && path.last_probe.is_none_or(|probed| elapsed(now, probed) >= interval)
                    })
                    .map(|(key, _)| *key)
                    .collect()
            })
            .unwrap_or_default();
        for key in due {
            if let Some(path) = self.peers.get_mut(&address).and_then(|peer| peer.paths.get_mut(&key)) {
                path.last_probe = Some(now);
            }
            let _ = self.send_path_probe_locked(address, key.local_socket, key.endpoint, now, None);
        }
        if policy == BondingPolicy::ActiveBackup {
            self.process_bond_negotiation_locked(address, &options, now);
        }
    }

    /// Removes peers that have been silent for the learned-peer window.
    fn expire_learned_peers_locked(&mut self, now: SystemTime) {
        let expired: Vec<Address> = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                !peer.root && peer.last_receive.is_none_or(|received| elapsed(now, received) >= LEARNED_PEER_EXPIRATION)
            })
            .map(|(address, _)| *address)
            .collect();
        for address in expired {
            self.remove_peer_locked(address);
        }
    }

    /// Runs best-effort stale peer cache cleanup when due.
    fn maintain_peer_cache_locked(&mut self, now: SystemTime) {
        let due =
            self.last_peer_cache_cleanup.is_none_or(|cleaned| elapsed(now, cleaned) >= PEER_CACHE_CLEANUP_INTERVAL);
        if !due {
            return;
        }
        self.last_peer_cache_cleanup = Some(now);
        let _ = self.host.clean_peer_cache(PEER_CACHE_CLEANUP_INTERVAL);
    }

    fn next_background_deadline_locked(&self, now: SystemTime, contact_period: Duration) -> SystemTime {
        let mut next = self.last_root_contact.map_or(now, |contacted| contacted + contact_period);
        if next <= now {
            next = now + Duration::from_millis(1);
        }
        if let Some(cleaned) = self.last_peer_cache_cleanup {
            let deadline = cleaned + PEER_CACHE_CLEANUP_INTERVAL;
            if deadline < next {
                next = deadline;
            }
        }
        if !self.pending_transmits.is_empty() {
            let deadline = now + WHOIS_RETRY_PERIOD;
            if deadline < next {
                next = deadline;
            }
            if let Some(first) = self.pending_transmits.first() {
                let deadline = first.created_at + PENDING_TRANSMIT_EXPIRATION;
                if deadline < next {
                    next = deadline;
                }
            }
        }
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;
    use crate::dictionary::{append_dictionary_entry, append_dictionary_uint};
    use crate::node::peer::PeerPathState;
    use std::sync::{Arc, Mutex};

    const TEST_CONFIG_REVISION: u64 = 0x1122_3344_5566_7788;
    const TEST_CONFIG_TIMESTAMP: u64 = 0x8877_6655_4433_2211;
    const KNOWN_GOOD_IDENTITY: &str = "8e4df28b72:0:ac3d46abe0c21f3cfe7a6c8d6a85cfcffcb82fbd55af6a4d6350657c68200843fa2e16f9418bbd9702cae365f2af5fb4c420908b803a681d4daef6114d78a2d7:bd8dd6e4ce7022d2f812797a80c6ee8ad180dc4ebf301dec8b06d1be08832bddd63a2f1cfa7b2c504474c75bdc8898ba476ef92e8e2d0509f8441985171ff16e";

    #[derive(Default, Clone)]
    struct TestHost {
        state: Arc<Mutex<HostState>>,
    }

    #[derive(Default)]
    struct HostState {
        identities: BTreeMap<Address, Identity>,
        sent: Vec<(i64, SocketAddr, Vec<u8>)>,
        whois: Vec<Address>,
        multicast: Vec<u64>,
        traces: Vec<(u64, Address)>,
    }

    impl TestHost {
        fn insert_identity(&self, address: Address, identity: Identity) {
            self.state.lock().expect("lock").identities.insert(address, identity);
        }

        fn sent(&self) -> Vec<(i64, SocketAddr, Vec<u8>)> {
            self.state.lock().expect("lock").sent.clone()
        }

        fn whois(&self) -> Vec<Address> {
            self.state.lock().expect("lock").whois.clone()
        }

        fn multicast(&self) -> Vec<u64> {
            self.state.lock().expect("lock").multicast.clone()
        }

        fn traces(&self) -> Vec<(u64, Address)> {
            self.state.lock().expect("lock").traces.clone()
        }
    }

    impl NodeHost for TestHost {
        fn peer_identity(&self, address: Address) -> Option<Identity> {
            self.state.lock().expect("lock").identities.get(&address).cloned()
        }

        fn send_wire(&mut self, local_socket: i64, remote: SocketAddr, packet: Vec<u8>) -> Result<(), NodeError> {
            self.state.lock().expect("lock").sent.push((local_socket, remote, packet));
            Ok(())
        }

        fn request_whois(&mut self, address: Address) {
            self.state.lock().expect("lock").whois.push(address);
        }

        fn announce_multicast(&mut self, network_id: u64) {
            self.state.lock().expect("lock").multicast.push(network_id);
        }

        fn trace_network_config_request(&mut self, network_id: u64, controller: Address) {
            self.state.lock().expect("lock").traces.push((network_id, controller));
        }
    }

    struct FailingStore;

    impl StateStore for FailingStore {
        fn get(&self, _name: &str) -> Option<Vec<u8>> {
            None
        }

        fn put(&mut self, _name: &str, _value: &[u8]) -> Result<(), StoreError> {
            Err(StoreError::InvalidName)
        }

        fn delete(&mut self, _name: &str) -> Result<(), StoreError> {
            Err(StoreError::InvalidName)
        }
    }

    fn test_identity() -> Identity {
        Identity::parse(KNOWN_GOOD_IDENTITY).expect("parses the fixed test identity")
    }

    fn test_node(host: TestHost, store: Box<dyn StateStore>) -> Node {
        Node::new(test_identity(), store, Box::new(host))
    }

    const TEST_ENDPOINT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 40)), 9999);

    /// Resolves `address` through the peer cache and gives it one direct path,
    /// so a protocol send leaves the node instead of being deferred.
    fn install_direct_path(node: &mut Node, address: Address, now: SystemTime) -> PathKey {
        node.load_peer_cache_locked(address, now).expect("peer identity is cached");
        let key = PathKey::new(ANY_LOCAL_SOCKET, TEST_ENDPOINT);
        node.add_peer_path_locked(
            address,
            key,
            PeerPathState { last_receive: Some(now), last_probe: Some(now), priority: 1, ..Default::default() },
            now,
        );
        key
    }

    /// Reverses the node's armor so a test can assert the packet it sent.
    fn dearmor_sent(node: &Node, peer: &Identity, bytes: &[u8]) -> Packet {
        let key = node.identity().agree(peer).expect("shared key");
        let mut packet = Packet::parse(bytes).expect("parses the wire form");
        packet.dearmor_with(&key, None, Some(node.identity())).expect("dearmors");
        packet.uncompress().expect("uncompresses");
        packet
    }

    /// The controller request/response vectors use a public configuration whose
    /// member is the fixed test identity.
    fn append_test_network_config(network_id: u64, member: Address) -> Vec<u8> {
        let entries = [
            ("v", NETWORK_CONFIG_VERSION),
            ("nwid", network_id),
            ("id", member.uint64()),
            ("t", u64::from(NetworkType::PUBLIC.bits())),
            ("mtu", u64::from(DEFAULT_NETWORK_MTU)),
            ("r", TEST_CONFIG_REVISION),
            ("ts", TEST_CONFIG_TIMESTAMP),
        ];
        let mut config = Vec::new();
        for (key, value) in entries {
            config = append_dictionary_uint(config, key, value).expect("valid dictionary entry");
        }
        config
    }

    fn config_with_credentials(network_id: u64, member: Address, capability: Option<&Capability>) -> Vec<u8> {
        let mut config = append_test_network_config(network_id, member);
        if let Some(capability) = capability {
            config = append_dictionary_entry(config, "CAP", &capability.append_binary(Vec::new()).expect("the capability encodes"))
                .expect("valid dictionary entry");
        }
        config
    }

    fn completed_assembly(update_id: u64, raw: &[u8]) -> ConfigAssembly {
        let mut assembly = ConfigAssembly::new(update_id, raw.len());
        assembly.data.copy_from_slice(raw);
        assembly.received.iter_mut().for_each(|received| *received = true);
        assembly.count = raw.len();
        assembly
    }

    /// A controller-signed capability with a one-link custody chain, built from
    /// the wire form because only the decoder may populate a capability.
    fn signed_capability(controller_identity: &Identity, network_id: u64, custodian: Address) -> Capability {
        let mut base = Vec::new();
        base.extend_from_slice(&network_id.to_be_bytes());
        base.extend_from_slice(&3u64.to_be_bytes());
        base.extend_from_slice(&4u32.to_be_bytes());
        base.extend_from_slice(&1u16.to_be_bytes());
        base.push(RULE_ACTION_ACCEPT);
        base.push(0);
        base.push(1);
        let mut signed = Vec::new();
        signed.extend_from_slice(&0x7f7f_7f7f_7f7f_7f7fu64.to_be_bytes());
        signed.extend_from_slice(&base);
        signed.extend_from_slice(&0u16.to_be_bytes());
        signed.extend_from_slice(&0x7f7f_7f7f_7f7f_7f7fu64.to_be_bytes());
        let signature = controller_identity.sign(&signed).expect("signs");

        let mut raw = base;
        raw.extend_from_slice(&custodian.bytes());
        raw.extend_from_slice(&controller_identity.address().bytes());
        raw.push(1);
        raw.extend_from_slice(&(SIGNATURE_SIZE as u16).to_be_bytes());
        raw.extend_from_slice(&signature);
        raw.extend_from_slice(&[0u8; crate::address::ADDRESS_SIZE]);
        raw.extend_from_slice(&0u16.to_be_bytes());
        Capability::parse(&raw).expect("parses").0
    }

    fn error_events(node: &mut Node) -> Vec<EventType> {
        node.take_events().into_iter().map(|event| event.event_type).collect()
    }

    #[test]
    fn duplicate_network_config_does_not_reapply() {
        let identity = test_identity();
        let controller_identity = Identity::generate();
        let network_id = (controller_identity.address().uint64() << 24) | 0x1234;
        let raw = append_test_network_config(network_id, identity.address());
        let config = parse_network_config(&raw).expect("parses");
        let host = TestHost::default();
        host.insert_identity(controller_identity.address(), controller_identity.clone());
        let mut node = test_node(host.clone(), Box::new(MemoryStore::new()));
        const UPDATE_ID: u64 = 0x0102_0304_0506_0708;
        let now = SystemTime::now();
        let mut network = Network::new(network_id);
        network.status = NetworkStatus::Ok;
        network.config = config;
        network.config_update_serial = 7;
        network.assemblies.insert(UPDATE_ID, completed_assembly(UPDATE_ID, &raw));
        node.networks.insert(network_id, network);
        node.pending
            .add(
                9,
                PendingRequest {
                    verb: Verb::NetworkConfigRequest,
                    peer: controller_identity.address(),
                    network_id,
                    sent_at: Some(now),
                    slot: 0,
                    generation: 0,
                    path: None,
                    priority: 0,
                    reply_paths: None,
                },
            )
            .expect("records the request");

        node.apply_network_config_assembly_locked(network_id, UPDATE_ID, now).expect("applies");
        let network = node.network(network_id).expect("joined");
        assert!(!network.assemblies.contains_key(&UPDATE_ID));
        assert!(!node.pending().contains(9));
        assert_eq!(network.config_update_serial, 7);
        assert_eq!(network.last_config_update_id, UPDATE_ID);
        assert_eq!(network.last_config_receive, Some(now));
        assert!(node.pending_callbacks().is_empty());
        assert!(node.events().is_empty());
    }

    #[test]
    fn duplicate_network_config_recovers_a_failure_state() {
        let identity = test_identity();
        let network_id = 0x1234_5678_90ab_cdef;
        let raw = append_test_network_config(network_id, identity.address());
        let config = parse_network_config(&raw).expect("parses");
        for status in [NetworkStatus::AccessDenied, NetworkStatus::NotFound, NetworkStatus::AuthenticationRequired] {
            let callback_count = Arc::new(Mutex::new(0usize));
            let counter = Arc::clone(&callback_count);
            let mut node = test_node(TestHost::default(), Box::new(MemoryStore::new()));
            node.set_network_config_callback(Box::new(move |_| {
                *counter.lock().expect("lock") += 1;
            }));
            const UPDATE_ID: u64 = 0x0102_0304_0506_0708;
            let mut network = Network::new(network_id);
            network.status = status;
            network.config = config.clone();
            network.authentication = NetworkAuthenticationInfo {
                version: 1,
                authentication_url: "https://auth.example".to_owned(),
                ..Default::default()
            };
            network.config_update_serial = 7;
            network.assemblies.insert(UPDATE_ID, completed_assembly(UPDATE_ID, &raw));
            node.networks.insert(network_id, network);

            node.apply_network_config_assembly_locked(network_id, UPDATE_ID, SystemTime::now()).expect("applies");
            node.run_callbacks();
            let network = node.network(network_id).expect("joined");
            assert_eq!(network.status, NetworkStatus::Ok, "status {status:?}");
            assert_eq!(network.config_update_serial, 8, "status {status:?}");
            assert_eq!(network.authentication, NetworkAuthenticationInfo::default());
            assert_eq!(*callback_count.lock().expect("lock"), 1);
            assert_eq!(error_events(&mut node), vec![EventType::NetworkConfigReady]);
        }
    }

    #[test]
    fn changed_network_config_emits_an_update_instead_of_ready() {
        let identity = test_identity();
        let controller_identity = Identity::generate();
        let network_id = (controller_identity.address().uint64() << 24) | 0x1234;
        let raw = append_test_network_config(network_id, identity.address());
        let config = parse_network_config(&raw).expect("parses");
        let old_timestamp = format!("ts={TEST_CONFIG_TIMESTAMP:016x}").into_bytes();
        let new_timestamp = format!("ts={:016x}", TEST_CONFIG_TIMESTAMP + 1).into_bytes();
        let updated = replace_first(&raw, &old_timestamp, &new_timestamp).expect("timestamp present");
        let host = TestHost::default();
        host.insert_identity(controller_identity.address(), controller_identity);
        let mut node = test_node(host.clone(), Box::new(MemoryStore::new()));
        const UPDATE_ID: u64 = 0x0102_0304_0506_0708;
        let mut network = Network::new(network_id);
        network.status = NetworkStatus::Ok;
        network.config = config;
        network.assemblies.insert(UPDATE_ID, completed_assembly(UPDATE_ID, &updated));
        node.networks.insert(network_id, network);

        node.apply_network_config_assembly_locked(network_id, UPDATE_ID, SystemTime::now()).expect("applies");
        let events = error_events(&mut node);
        assert_eq!(events.first(), Some(&EventType::NetworkConfigChanged), "{events:?}");
        assert!(
            !events.contains(&EventType::NetworkConfigReady),
            "a changed configuration is not a first one: {events:?}"
        );
    }

    #[test]
    fn a_permanently_invalid_completed_config_is_discarded() {
        let network_id = 0x1234_5678_90ab_cdef;
        let raw = append_test_network_config(network_id, Address::new(0x0012_3456_7890));
        let mut node = test_node(TestHost::default(), Box::new(MemoryStore::new()));
        const UPDATE_ID: u64 = 0x0102_0304_0506_0708;
        let mut network = Network::new(network_id);
        network.assemblies.insert(UPDATE_ID, completed_assembly(UPDATE_ID, &raw));
        node.networks.insert(network_id, network);

        let error = node
            .apply_network_config_assembly_locked(network_id, UPDATE_ID, SystemTime::now())
            .expect_err("rejects a configuration issued to another member");
        assert_eq!(error.root(), NodeError::InvalidPacket);
        assert!(!node.network(network_id).expect("joined").assemblies.contains_key(&UPDATE_ID));
    }

    #[test]
    fn a_config_capability_for_another_member_discards_the_assembly() {
        let local = test_identity();
        let controller_identity = Identity::generate();
        let other = Identity::generate();
        let network_id = (controller_identity.address().uint64() << 24) | 0x1234;
        let capability = signed_capability(&controller_identity, network_id, other.address());
        let raw = config_with_credentials(network_id, local.address(), Some(&capability));
        let host = TestHost::default();
        host.insert_identity(controller_identity.address(), controller_identity);
        let mut node = test_node(host.clone(), Box::new(MemoryStore::new()));
        const UPDATE_ID: u64 = 0x1122_3344_5566_7788;
        let mut network = Network::new(network_id);
        network.assemblies.insert(UPDATE_ID, completed_assembly(UPDATE_ID, &raw));
        node.networks.insert(network_id, network);

        let error = node
            .apply_network_config_assembly_locked(network_id, UPDATE_ID, SystemTime::now())
            .expect_err("rejects a capability issued to another member");
        assert_eq!(error.root(), NodeError::InvalidPacket);
        assert!(!node.network(network_id).expect("joined").assemblies.contains_key(&UPDATE_ID));
    }

    #[test]
    fn ad_hoc_networks_get_the_official_deterministic_configuration() {
        let identity = test_identity();
        let callback_count = Arc::new(Mutex::new(0usize));
        let counter = Arc::clone(&callback_count);
        let host = TestHost::default();
        let mut node = test_node(host.clone(), Box::new(MemoryStore::new()));
        node.set_network_config_callback(Box::new(move |_| {
            *counter.lock().expect("lock") += 1;
        }));

        const PORT_NETWORK: u64 = 0xff00_1600_5000_0000;
        let now = SystemTime::now();
        node.join(PORT_NETWORK, now).expect("joins the port ad-hoc network");
        let port = node.network(PORT_NETWORK).expect("joined");
        assert_eq!(port.status, NetworkStatus::Ok);
        assert_eq!(port.config.name, "adhoc-0016-0050");
        assert_eq!(port.config.network_type, NetworkType::PUBLIC);
        assert_eq!(port.config.multicast_limit, 0);
        assert_eq!(port.config.assigned, vec![six_plane_address(PORT_NETWORK, identity.address())]);
        assert_eq!(port.config.rules.len(), 14);
        assert_eq!(port.config.rules[6].value, vec![0x00, 0x16, 0x00, 0x50]);

        let hub_network = 0xff0a_0123_4567_8901u64;
        node.join(hub_network, now).expect("joins the hub ad-hoc network");
        let hub = node.network(hub_network).expect("joined");
        let local = identity.address().uint64();
        let want_ipv4 =
            IpNet::new(IpAddr::V4(Ipv4Addr::new(10, (local >> 16) as u8, (local >> 8) as u8, local as u8)), 8)
                .expect("8-bit IPv4 prefix");
        assert_eq!(hub.status, NetworkStatus::Ok);
        assert_eq!(hub.config.name, "adhoc-10.0.0.0");
        assert_eq!(hub.config.multicast_limit, 1024);
        assert_eq!(hub.config.assigned.len(), 2);
        assert_eq!(hub.config.assigned[1], want_ipv4);
        assert_eq!(hub.config.specialists, vec![Address::new(0x0001_2345_6789).uint64()]);

        node.refresh_network(PORT_NETWORK, now).expect("refreshes the port network");
        assert_eq!(host.whois(), vec![Address::new(0x0001_2345_6789)]);
        assert_eq!(host.multicast(), vec![PORT_NETWORK, hub_network, PORT_NETWORK]);

        const INVALID_NETWORK: u64 = 0xff00_1600_5000_0002;
        node.join(INVALID_NETWORK, now).expect("joins the invalid ad-hoc network");
        assert_eq!(node.network(INVALID_NETWORK).expect("joined").status, NetworkStatus::NotFound);
        node.run_callbacks();
        assert_eq!(*callback_count.lock().expect("lock"), 3);
        assert_eq!(
            error_events(&mut node),
            vec![
                EventType::NetworkConfigPending,
                EventType::NetworkConfigReady,
                EventType::NetworkConfigPending,
                EventType::NetworkConfigReady,
                EventType::NetworkConfigChanged,
                EventType::NetworkConfigPending,
                EventType::NetworkNotFound,
            ]
        );
    }

    #[test]
    fn a_failed_persistence_write_still_applies_the_configuration() {
        let identity = test_identity();
        let controller_identity = Identity::generate();
        let network_id = (controller_identity.address().uint64() << 24) | 0x1234;
        let raw = append_test_network_config(network_id, identity.address());
        let host = TestHost::default();
        host.insert_identity(controller_identity.address(), controller_identity);
        let mut node = test_node(host, Box::new(FailingStore));
        const UPDATE_ID: u64 = 0x0102_0304_0506_0708;
        let mut network = Network::new(network_id);
        network.assemblies.insert(UPDATE_ID, completed_assembly(UPDATE_ID, &raw));
        node.networks.insert(network_id, network);

        node.apply_network_config_assembly_locked(network_id, UPDATE_ID, SystemTime::now())
            .expect("applies despite the failed write");
        let network = node.network(network_id).expect("joined");
        assert_eq!(network.status, NetworkStatus::Ok);
        assert_eq!(network.config.network_id, network_id);
    }

    #[test]
    fn join_restores_a_cached_network_configuration() {
        let identity = test_identity();
        let controller_identity = Identity::generate();
        let network_id = (controller_identity.address().uint64() << 24) | 0x1234;
        let raw = append_test_network_config(network_id, identity.address());
        let mut store = MemoryStore::new();
        store.put(&network_state_name(network_id), &raw).expect("stores the cache");
        let restore_count = Arc::new(Mutex::new(0usize));
        let restored_count = Arc::clone(&restore_count);
        let host = TestHost::default();
        host.insert_identity(controller_identity.address(), controller_identity.clone());
        let mut node = test_node(host, Box::new(store));
        node.set_network_config_callback(Box::new(move |config| {
            assert_eq!(config.network_id, network_id);
            *restored_count.lock().expect("lock") += 1;
        }));

        node.join(network_id, SystemTime::now()).expect("joins");
        node.run_callbacks();
        let network = node.network(network_id).expect("joined");
        assert_eq!(network.status, NetworkStatus::Ok);
        assert_eq!(network.config.network_id, network_id);
        assert_eq!(network.last_config_receive, None);
        assert_eq!(*restore_count.lock().expect("lock"), 1);
        let events = error_events(&mut node);
        assert_eq!(events[0], EventType::NetworkConfigPending);
        assert_eq!(events[1], EventType::NetworkConfigReady);
        // The join still contacts the controller for a fresh configuration.
        assert_eq!(node.pending().len(), 1);
    }

    #[test]
    fn a_network_config_callback_cannot_mutate_node_state() {
        let identity = test_identity();
        let controller_identity = Identity::generate();
        let network_id = (controller_identity.address().uint64() << 24) | 0x1234;
        let assigned = IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 24).expect("prefix");
        let mut raw = config_with_credentials(network_id, identity.address(), None);
        let mut assigned_bytes = vec![4u8, 192, 0, 2, 10];
        assigned_bytes.extend_from_slice(&24u16.to_be_bytes());
        raw = append_dictionary_entry(raw, "I", &assigned_bytes).expect("valid entry");
        raw = append_dictionary_entry(raw, "R", &[RULE_ACTION_ACCEPT, 0]).expect("valid entry");
        let original = raw.clone();
        let mut store = MemoryStore::new();
        store.put(&network_state_name(network_id), &raw).expect("stores the cache");
        let mut node = test_node(TestHost::default(), Box::new(store));
        node.set_network_config_callback(Box::new(|config| {
            let mut mutated = config.clone();
            mutated.assigned[0] = IpNet::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 24).expect("prefix");
            mutated.rules[0].rule_type = RULE_ACTION_DROP;
            mutated.raw[0] ^= 0xff;
        }));

        node.join(network_id, SystemTime::now()).expect("joins");
        node.run_callbacks();
        let network = node.network(network_id).expect("joined");
        assert_eq!(network.config.assigned.len(), 1);
        assert_eq!(network.config.assigned[0].addr(), assigned.addr());
        assert_eq!(network.config.assigned[0].prefix_len(), 24);
        assert_eq!(network.config.rules.len(), 1);
        assert_eq!(network.config.rules[0].rule_type, RULE_ACTION_ACCEPT);
        assert_eq!(network.config.raw, original);
    }

    #[test]
    fn a_configuration_request_uses_the_controller_identity_and_revision() {
        let identity = test_identity();
        let controller_identity = Identity::generate();
        let network_id = (controller_identity.address().uint64() << 24) | 0x1234;
        let config = parse_network_config(&append_test_network_config(network_id, identity.address())).expect("parses");
        let host = TestHost::default();
        host.insert_identity(controller_identity.address(), controller_identity.clone());
        let mut node = test_node(host.clone(), Box::new(MemoryStore::new()));
        let now = SystemTime::now();
        let mut network = Network::new(network_id);
        network.status = NetworkStatus::Ok;
        network.config = config;
        node.networks.insert(network_id, network);

        install_direct_path(&mut node, controller_identity.address(), now);
        node.send_network_config_request_packet_locked(network_id, now).expect("sends");
        let sent = host.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, TEST_ENDPOINT);
        let packet = dearmor_sent(&node, &controller_identity, &sent[0].2);
        assert_eq!(packet.destination(), controller_identity.address());
        assert_eq!(packet.source(), identity.address());
        assert_eq!(packet.verb(), Some(Verb::NetworkConfigRequest));
        let payload = packet.payload();
        assert_eq!(&payload[..8], &network_id.to_be_bytes());
        let metadata_length = usize::from(u16::from_be_bytes([payload[8], payload[9]]));
        let version_offset = 10 + metadata_length;
        assert!(payload.len() - version_offset >= 16);
        assert_eq!(
            u64::from_be_bytes(payload[version_offset..version_offset + 8].try_into().unwrap()),
            TEST_CONFIG_REVISION
        );
        assert_eq!(
            u64::from_be_bytes(payload[version_offset + 8..version_offset + 16].try_into().unwrap()),
            TEST_CONFIG_TIMESTAMP
        );
        assert_eq!(host.traces(), vec![(network_id, controller_identity.address())]);
    }

    #[test]
    fn multiple_ok_chunks_assemble_into_one_configuration() {
        let identity = test_identity();
        let controller_identity = Identity::generate();
        let network_id = (controller_identity.address().uint64() << 24) | 0x1234;
        let config_bytes = append_test_network_config(network_id, identity.address());
        let split = config_bytes.len() / 2;
        let host = TestHost::default();
        host.insert_identity(controller_identity.address(), controller_identity.clone());
        let mut node = test_node(host.clone(), Box::new(MemoryStore::new()));
        const REQUEST_ID: u64 = 0x0102_0304_0506_0708;
        const UPDATE_ID: u64 = 0x8877_6655_4433_2211;
        let now = SystemTime::now();
        node.networks.insert(network_id, Network::new(network_id));
        node.pending
            .add(
                REQUEST_ID,
                PendingRequest {
                    verb: Verb::NetworkConfigRequest,
                    peer: controller_identity.address(),
                    network_id,
                    sent_at: Some(now),
                    slot: 0,
                    generation: 0,
                    path: None,
                    priority: 0,
                    reply_paths: None,
                },
            )
            .expect("records the request");

        let first = chunk_packet(
            &controller_identity,
            identity.address(),
            REQUEST_ID,
            network_id,
            UPDATE_ID,
            config_bytes.len(),
            0,
            &config_bytes[..split],
            0,
        );
        node.handle_network_config_chunk_locked(&first, 9, now).expect("accepts the first chunk");
        assert!(node.pending().contains(REQUEST_ID));
        assert_ne!(node.network(network_id).expect("joined").status, NetworkStatus::Ok);

        let second = chunk_packet(
            &controller_identity,
            identity.address(),
            REQUEST_ID,
            network_id,
            UPDATE_ID,
            config_bytes.len(),
            split,
            &config_bytes[split..],
            0,
        );
        node.handle_network_config_chunk_locked(&second, 9, now).expect("accepts the second chunk");
        assert!(!node.pending().contains(REQUEST_ID));
        let network = node.network(network_id).expect("joined");
        assert_eq!(network.status, NetworkStatus::Ok);
        assert_eq!(network.config.network_id, network_id);
    }

    #[test]
    fn a_tampered_chunk_signature_is_rejected() {
        let identity = test_identity();
        let controller_identity = Identity::generate();
        let network_id = (controller_identity.address().uint64() << 24) | 0x1234;
        let config_bytes = append_test_network_config(network_id, identity.address());
        let host = TestHost::default();
        host.insert_identity(controller_identity.address(), controller_identity.clone());
        let mut node = test_node(host.clone(), Box::new(MemoryStore::new()));
        node.networks.insert(network_id, Network::new(network_id));
        let mut packet = chunk_packet(
            &controller_identity,
            identity.address(),
            7,
            network_id,
            0x8877_6655_4433_2211,
            config_bytes.len(),
            0,
            &config_bytes,
            0,
        );
        let last = packet.payload().len() - 1;
        packet.payload_mut()[last] ^= 0x01;
        let error = node
            .handle_network_config_chunk_locked(&packet, 9, SystemTime::now())
            .expect_err("rejects a tampered chunk");
        assert_eq!(error.root(), NodeError::InvalidPacket);
    }

    #[test]
    fn changed_credentials_are_forgotten_and_republished() {
        let identity = test_identity();
        let controller_identity = Identity::generate();
        let network_id = (controller_identity.address().uint64() << 24) | 0x1234;
        let raw = append_test_network_config(network_id, identity.address());
        let peer_identity = Identity::generate();
        let peer = peer_identity.address();
        let host = TestHost::default();
        host.insert_identity(controller_identity.address(), controller_identity.clone());
        host.insert_identity(peer, peer_identity.clone());
        let mut node = test_node(host.clone(), Box::new(MemoryStore::new()));
        let now = SystemTime::now();
        const UPDATE_ID: u64 = 0x0102_0304_0506_0708;
        install_direct_path(&mut node, peer, now);
        node.peer_credentials_mut().insert(peer, BTreeMap::from([(network_id, now)]));
        let mut network = Network::new(network_id);
        network.associated.insert(peer, now);
        node.networks.insert(network_id, network);

        let packet =
            chunk_packet(&controller_identity, identity.address(), 7, network_id, UPDATE_ID, raw.len(), 0, &raw, 0x01);
        node.handle_network_config_chunk_locked(&packet, 9, now).expect("applies the fast-propagated configuration");
        assert_eq!(node.network(network_id).expect("joined").status, NetworkStatus::Ok);
        assert!(node.peer_credentials()[&peer].is_empty());
        let sent = host.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, TEST_ENDPOINT);
        let propagated = dearmor_sent(&node, &peer_identity, &sent[0].2);
        assert_eq!(propagated.verb(), Some(Verb::NetworkConfig));
        assert_eq!(propagated.payload(), &packet.payload()[9..]);
    }

    #[test]
    fn pending_requests_replace_the_oldest_ring_entry() {
        let mut pending = PendingRequests::new();
        let request = |network_id: u64| PendingRequest {
            verb: Verb::NetworkConfigRequest,
            peer: Address::new(1),
            network_id,
            sent_at: None,
            slot: 0,
            generation: 0,
            path: None,
            priority: 0,
            reply_paths: None,
        };
        pending.add(1, request(1)).expect("adds");
        assert!(matches!(pending.add(1, request(1)), Err(NodeError::DuplicatePacketId)));
        for index in 0..MAX_PENDING_REQUESTS {
            pending.add(index as u64 + 2, request(index as u64)).expect("adds");
        }
        assert_eq!(pending.len(), MAX_PENDING_REQUESTS);
        // The first expectation was replaced once the ring wrapped to its slot.
        assert!(!pending.contains(1));
        assert!(pending.contains(MAX_PENDING_REQUESTS as u64 + 1));
        pending.delete(MAX_PENDING_REQUESTS as u64 + 1);
        pending.delete(MAX_PENDING_REQUESTS as u64 + 1);
        assert_eq!(pending.len(), MAX_PENDING_REQUESTS - 1);
    }

    /// Builds one `OK` reply carrying a configuration chunk exactly as the
    /// controller signs it.
    #[allow(clippy::too_many_arguments)]
    fn chunk_packet(
        controller_identity: &Identity,
        member: Address,
        request_id: u64,
        network_id: u64,
        update_id: u64,
        total_length: usize,
        chunk_index: usize,
        chunk: &[u8],
        flags: u8,
    ) -> Packet {
        let mut packet = Packet::new(member, controller_identity.address(), Verb::Ok).expect("packet");
        let _ = packet.append_u8(Verb::NetworkConfigRequest.bits());
        let _ = packet.append_u64(request_id);
        let signed_at = packet.payload().len();
        let _ = packet.append_u64(network_id);
        let _ = packet.append_u16(u16::try_from(chunk.len()).expect("chunk length"));
        let _ = packet.append(chunk);
        let _ = packet.append_u8(flags);
        let _ = packet.append_u64(update_id);
        let _ = packet.append_u32(u32::try_from(total_length).expect("total length"));
        let _ = packet.append_u32(u32::try_from(chunk_index).expect("chunk index"));
        let signed = packet.payload()[signed_at..].to_vec();
        let signature = controller_identity.sign(&signed).expect("signs");
        let _ = packet.append_u8(1);
        let _ = packet.append_u16(SIGNATURE_SIZE as u16);
        let _ = packet.append(&signature);
        packet
    }

    fn replace_first(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Option<Vec<u8>> {
        let at = haystack.windows(needle.len()).position(|window| window == needle)?;
        let mut out = haystack[..at].to_vec();
        out.extend_from_slice(replacement);
        out.extend_from_slice(&haystack[at + needle.len()..]);
        Some(out)
    }
}

//! Peer and physical-path state: the authenticated identity, path table,
//! liveness bookkeeping, and path selection of one remote ZeroTier node.
//!
//! ZeroTier One keeps one `Path` per local socket and remote endpoint, with
//! its own receive clock, quality score, and (in this implementation) bonding
//! counters. Physical receive activity is tracked per socket and endpoint
//! rather than per peer, because the same physical path can be reached before
//! a peer identity is known.
//!
//! DEVIATION: wire-path activity uses an atomic millisecond counter so a
//! receive racing a path change cannot move the clock backwards. This crate's
//! [`Node`] owns all protocol state exclusively, so the counter is a plain
//! `i64` and the clamp is a simple maximum.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use crate::address::Address;
use crate::identity::{Identity, SYMMETRIC_KEY_SIZE};
use crate::node::{Node, PEER_PATH_ACTIVE_TIME, PEER_PATH_EXPIRATION, UNKNOWN_PATH_LATENCY};
use crate::ztcrypto::gmac_siv::GmacSivKeys;

/// Milliseconds in one second, for the protocol's millisecond arithmetic.
const MILLIS: u32 = 1_000;

/// A path identifier: one local socket and one remote physical endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathKey {
    pub local_socket: i64,
    pub endpoint: SocketAddr,
}

impl PathKey {
    #[must_use]
    pub fn new(local_socket: i64, endpoint: SocketAddr) -> Self {
        Self { local_socket, endpoint }
    }
}

impl Ord for PathKey {
    /// Orders paths by socket, address, then port, so selection is
    /// deterministic where the official core uses fixed path slots.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.local_socket
            .cmp(&other.local_socket)
            .then_with(|| ip_order(&self.endpoint.ip(), &other.endpoint.ip()))
            .then_with(|| self.endpoint.port().cmp(&other.endpoint.port()))
    }
}

impl PartialOrd for PathKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Compares addresses in the network-byte order `netip.Addr.Compare` uses:
/// IPv4 sorts before IPv6, and an IPv4-mapped address is unmapped first.
fn ip_order(left: &IpAddr, right: &IpAddr) -> std::cmp::Ordering {
    let left = unmap(*left);
    let right = unmap(*right);
    match (left, right) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets().cmp(&b.octets()),
        (IpAddr::V6(a), IpAddr::V6(b)) => a.octets().cmp(&b.octets()),
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
    }
}

/// Drops the IPv4-mapped IPv6 form, as `netip.Addr.Unmap` does.
#[must_use]
pub fn unmap(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// The canonical physical activity for one local socket and remote endpoint.
#[derive(Debug, Clone)]
pub struct WirePathActivity {
    receive_origin: SystemTime,
    receive_elapsed_millis: i64,
    pub last_send: Option<SystemTime>,
    pub references: usize,
}

impl WirePathActivity {
    #[must_use]
    pub fn new(now: SystemTime) -> Self {
        Self { receive_origin: now, receive_elapsed_millis: 1, last_send: None, references: 0 }
    }

    /// Advances the physical receive clock, never backwards.
    pub fn receive(&mut self, now: SystemTime) {
        let Some(elapsed) = now.duration_since(self.receive_origin).ok() else {
            return;
        };
        let received_at = i64::try_from(elapsed.as_millis() / u128::from(MILLIS) + 1).unwrap_or(i64::MAX);
        if received_at > self.receive_elapsed_millis {
            self.receive_elapsed_millis = received_at;
        }
    }

    #[must_use]
    pub fn last_receive(&self) -> Option<SystemTime> {
        if self.receive_elapsed_millis == 0 {
            return None;
        }
        self.receive_origin.checked_add(Duration::from_millis((self.receive_elapsed_millis - 1).cast_unsigned()))
    }
}

/// Liveness, quality, and bonding state of one physical peer path.
#[expect(
    clippy::struct_excessive_bools,
    reason = "wire-format mirror; collapsing the independent flags would change the public shape"
)]
#[derive(Debug, Clone)]
pub struct PeerPathState {
    pub last_receive: Option<SystemTime>,
    pub last_send: Option<SystemTime>,
    pub latency: Duration,
    pub latency_measured: bool,
    pub bond_latency: Duration,
    pub last_probe: Option<SystemTime>,
    pub priority: i32,
    pub qos_incoming: BTreeMap<u64, SystemTime>,
    pub qos_outgoing: BTreeMap<u64, SystemTime>,
    pub last_qos_sent: Option<SystemTime>,
    pub last_qos_receive: Option<SystemTime>,
    pub qos_latency_samples: Vec<Duration>,
    pub qos_latency_next: usize,
    pub jitter: Duration,
    pub loss: f64,
    pub packet_error: f64,
    pub bond_nominated: Option<SystemTime>,
    pub bond_alive_since: Option<SystemTime>,
    pub bond_eligible_at: Option<SystemTime>,
    pub bond_alive: bool,
    pub bond_eligible: bool,
    pub bond_avoid: bool,
    pub bond_negotiated: bool,
    pub bond_refractory: Duration,
    pub bond_quality: f64,
    pub bond_capacity: f64,
    pub bond_score: i32,
    pub bond_assigned_flows: u16,
    pub bond_packets_in: u64,
    pub bond_packets_out: u64,
}
impl Default for PeerPathState {
    /// Every field at its reference zero value. Written out rather than derived so that adding a
    /// field to `PeerPathState` cannot default silently: this impl stops compiling until the new field is
    /// named here (RUST_GUIDELINES.md section 3, functional-update struct literals).
    fn default() -> Self {
        Self {
            last_receive: <Option<SystemTime> as Default>::default(),
            last_send: <Option<SystemTime> as Default>::default(),
            latency: <Duration as Default>::default(),
            latency_measured: <bool as Default>::default(),
            bond_latency: <Duration as Default>::default(),
            last_probe: <Option<SystemTime> as Default>::default(),
            priority: <i32 as Default>::default(),
            qos_incoming: <BTreeMap<u64, SystemTime> as Default>::default(),
            qos_outgoing: <BTreeMap<u64, SystemTime> as Default>::default(),
            last_qos_sent: <Option<SystemTime> as Default>::default(),
            last_qos_receive: <Option<SystemTime> as Default>::default(),
            qos_latency_samples: <Vec<Duration> as Default>::default(),
            qos_latency_next: <usize as Default>::default(),
            jitter: <Duration as Default>::default(),
            loss: <f64 as Default>::default(),
            packet_error: <f64 as Default>::default(),
            bond_nominated: <Option<SystemTime> as Default>::default(),
            bond_alive_since: <Option<SystemTime> as Default>::default(),
            bond_eligible_at: <Option<SystemTime> as Default>::default(),
            bond_alive: <bool as Default>::default(),
            bond_eligible: <bool as Default>::default(),
            bond_avoid: <bool as Default>::default(),
            bond_negotiated: <bool as Default>::default(),
            bond_refractory: <Duration as Default>::default(),
            bond_quality: <f64 as Default>::default(),
            bond_capacity: <f64 as Default>::default(),
            bond_score: <i32 as Default>::default(),
            bond_assigned_flows: <u16 as Default>::default(),
            bond_packets_in: <u64 as Default>::default(),
            bond_packets_out: <u64 as Default>::default(),
        }
    }
}

/// A flow's assigned path and last use, for bounded eviction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondFlow {
    pub path: PathKey,
    pub last_active: SystemTime,
}

/// The trust role a peer holds in the active planet and moons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerRole {
    #[default]
    Leaf,
    Planet,
    Moon,
}

impl PeerRole {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Leaf => "leaf",
            Self::Planet => "planet",
            Self::Moon => "moon",
        }
    }
}

/// How a peer's traffic currently reaches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerRoute {
    #[default]
    Unknown,
    Direct,
    Relayed,
}

impl PeerRoute {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Direct => "direct",
            Self::Relayed => "relayed",
        }
    }
}

/// An authenticated peer: identity, shared keys, paths, and protocol state.
#[derive(Debug)]
pub struct Peer {
    pub identity: Identity,
    pub public_key_hash: [u8; 48],
    pub key: [u8; SYMMETRIC_KEY_SIZE],
    pub aes_keys: GmacSivKeys,
    pub root: bool,
    pub role: PeerRole,
    pub paths: BTreeMap<PathKey, PeerPathState>,
    pub last_receive: Option<SystemTime>,
    pub last_nontrivial_receive: Option<SystemTime>,
    pub last_full_hello: Option<SystemTime>,
    pub protocol: u8,
    pub major: u8,
    pub minor: u8,
    pub revision: u16,
    pub credentials_sent: BTreeMap<u64, SystemTime>,
    pub path_probe: BTreeMap<PathKey, SystemTime>,
    pub last_credentials_receive: Option<SystemTime>,
    pub last_credentials_request: Option<SystemTime>,
    pub last_whois_request: Option<SystemTime>,
    pub last_echo_request: BTreeMap<PathKey, SystemTime>,
    pub last_direct_path_push: Option<SystemTime>,
    pub direct_path_push_count: u32,
    pub last_direct_path_push_sent: Option<SystemTime>,
    pub last_trust_established: Option<SystemTime>,
    pub last_path_lookup: Option<SystemTime>,
    pub bond_flows: BTreeMap<i32, BondFlow>,
    pub bond_rr_index: u64,
    pub bond_rr_packets: u64,
    pub last_qos_rate_check: Option<SystemTime>,
    pub qos_rate_count: u16,
    pub bond_active: Option<PathKey>,
    pub bond_failover: Vec<PathKey>,
    pub bond_negotiated: Option<PathKey>,
    pub bond_local_utility: i16,
    pub bond_negotiation_tries: u8,
    pub bond_last_negotiation: Option<SystemTime>,
    pub bond_last_negotiation_tx: Option<SystemTime>,
    pub bond_last_negotiation_rx: Option<SystemTime>,
    pub bond_negotiation_rx_count: u16,
    pub bond_last_active_change: Option<SystemTime>,
    pub bond_last_maintenance: Option<SystemTime>,
    pub bond_paths: Vec<PathKey>,
    pub bond_known_path_count: usize,
    pub reported_user_route: PeerRoute,
    pub reported_user_endpoint: Option<SocketAddr>,
    pub reported_user_path_count: usize,
    pub last_user_route_report: Option<SystemTime>,
    pub pending_user_route: PeerRoute,
    pub pending_user_endpoint: Option<SocketAddr>,
    pub pending_user_path_count: usize,
}

impl Peer {
    /// Builds the unpublished peer state for `identity`.
    #[must_use]
    pub fn new(
        identity: Identity,
        public_key_hash: [u8; 48],
        key: [u8; SYMMETRIC_KEY_SIZE],
        aes_keys: GmacSivKeys,
        root: bool,
        role: PeerRole,
    ) -> Self {
        Self {
            identity,
            public_key_hash,
            key,
            aes_keys,
            root,
            role,
            paths: BTreeMap::new(),
            last_receive: None,
            last_nontrivial_receive: None,
            last_full_hello: None,
            protocol: 0,
            major: 0,
            minor: 0,
            revision: 0,
            credentials_sent: BTreeMap::new(),
            path_probe: BTreeMap::new(),
            last_credentials_receive: None,
            last_credentials_request: None,
            last_whois_request: None,
            last_echo_request: BTreeMap::new(),
            last_direct_path_push: None,
            direct_path_push_count: 0,
            last_direct_path_push_sent: None,
            last_trust_established: None,
            last_path_lookup: None,
            bond_flows: BTreeMap::new(),
            bond_rr_index: 0,
            bond_rr_packets: 0,
            last_qos_rate_check: None,
            qos_rate_count: 0,
            bond_active: None,
            bond_failover: Vec::new(),
            bond_negotiated: None,
            bond_local_utility: 0,
            bond_negotiation_tries: 0,
            bond_last_negotiation: None,
            bond_last_negotiation_tx: None,
            bond_last_negotiation_rx: None,
            bond_negotiation_rx_count: 0,
            bond_last_active_change: None,
            bond_last_maintenance: None,
            bond_paths: Vec::new(),
            bond_known_path_count: 0,
            reported_user_route: PeerRoute::Unknown,
            reported_user_endpoint: None,
            reported_user_path_count: 0,
            last_user_route_report: None,
            pending_user_route: PeerRoute::Unknown,
            pending_user_endpoint: None,
            pending_user_path_count: 0,
        }
    }

    /// The throwaway peer used to answer an address collision, before the
    /// colliding identity has any path or map state.
    #[expect(clippy::expect_used, reason = "a fixed 48-byte zero key always yields a key schedule")]
    #[must_use]
    pub fn temporary(identity: Identity, key: [u8; SYMMETRIC_KEY_SIZE]) -> Self {
        let aes_keys = GmacSivKeys::new(&[0u8; SYMMETRIC_KEY_SIZE]).expect("48-byte key schedule");
        Self::new(identity, [0u8; 48], key, aes_keys, false, PeerRole::Leaf)
    }
}

/// A diagnostic snapshot of one physical path to a peer.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerPath {
    pub local_socket: i64,
    pub endpoint: SocketAddr,
    pub last_send: Option<SystemTime>,
    pub last_receive: Option<SystemTime>,
    pub active: bool,
    pub preferred: bool,
    pub priority: i32,
    pub trusted_path_id: u64,
    pub latency: Duration,
    pub jitter: Duration,
    pub packet_loss: f64,
    pub packet_error: f64,
}

/// A diagnostic snapshot of one known peer and its paths.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerStatus {
    pub address: Address,
    pub role: PeerRole,
    pub protocol: u8,
    pub version_major: Option<u8>,
    pub version_minor: Option<u8>,
    pub version_revision: Option<u16>,
    pub route: PeerRoute,
    pub paths: Vec<PeerPath>,
}

impl Node {
    /// Attaches `state` to the canonical physical activity of its path.
    pub(crate) fn add_peer_path_locked(
        &mut self,
        address: Address,
        key: PathKey,
        state: PeerPathState,
        now: SystemTime,
    ) {
        if self.peer(address).is_none() {
            return;
        }
        if self.peer(address).is_some_and(|peer| peer.paths.contains_key(&key)) {
            self.delete_peer_path_locked(address, key);
        }
        let activity = self.wire_paths.entry(key).or_insert_with(|| WirePathActivity::new(now));
        activity.receive(now);
        if activity.last_send < state.last_send {
            activity.last_send = state.last_send;
        }
        activity.references += 1;
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.paths.insert(key, state);
        }
    }

    /// Releases one peer reference to a physical path.
    pub(crate) fn delete_peer_path_locked(&mut self, address: Address, key: PathKey) {
        let Some(peer) = self.peers.get_mut(&address) else {
            return;
        };
        if peer.paths.remove(&key).is_none() {
            return;
        }
        if let Some(activity) = self.wire_paths.get_mut(&key) {
            activity.references = activity.references.saturating_sub(1);
            if activity.references == 0 {
                self.wire_paths.remove(&key);
            }
        }
    }

    /// Records physical activity before a packet has been authenticated.
    pub(crate) fn note_wire_path_receive(&mut self, key: PathKey, now: SystemTime) {
        if let Some(activity) = self.wire_paths.get_mut(&key) {
            activity.receive(now);
        }
    }

    /// Records successful physical output on `key`.
    pub(crate) fn note_wire_path_send_locked(&mut self, key: PathKey, now: SystemTime) {
        if let Some(activity) = self.wire_paths.get_mut(&key) {
            if activity.last_send < Some(now) {
                activity.last_send = Some(now);
            }
        }
    }

    /// The physical receive age the protocol uses for liveness, falling back to
    /// the authenticated receive time of a path not installed through
    /// [`Node::add_peer_path_locked`].
    pub(crate) fn wire_path_age(&self, key: PathKey, path: &PeerPathState, now: SystemTime) -> Duration {
        if let Some(activity) = self.wire_paths.get(&key) {
            if let Some(last_receive) = activity.last_receive() {
                return now.duration_since(last_receive).unwrap_or_default();
            }
        }
        path.last_receive.and_then(|last_receive| now.duration_since(last_receive).ok()).unwrap_or_default()
    }

    /// The canonical physical receive time reported by peer diagnostics.
    pub(crate) fn wire_path_last_receive(&self, key: PathKey, path: &PeerPathState) -> Option<SystemTime> {
        if let Some(activity) = self.wire_paths.get(&key) {
            if let Some(last_receive) = activity.last_receive() {
                return Some(last_receive);
            }
        }
        path.last_receive
    }

    /// The canonical physical send time reported by peer diagnostics.
    pub(crate) fn wire_path_last_send(&self, key: PathKey, path: &PeerPathState) -> Option<SystemTime> {
        if let Some(activity) = self.wire_paths.get(&key) {
            if activity.last_send.is_some() {
                return activity.last_send;
            }
        }
        path.last_send
    }

    pub(crate) fn peer(&self, address: Address) -> Option<&Peer> {
        self.peers.get(&address)
    }

    /// The endpoint of the current best peer path.
    #[must_use]
    pub fn best_peer_endpoint(&self, address: Address, now: SystemTime) -> Option<SocketAddr> {
        let peer = self.peers.get(&address)?;
        self.best_peer_path(peer, now).map(|key| key.endpoint)
    }

    /// Follows the send fallback order: an unexpired direct path, a relay
    /// through a root, then a retained expired direct path.
    #[must_use]
    pub fn best_peer_path(&self, peer: &Peer, now: SystemTime) -> Option<PathKey> {
        if let Some(selected) = self.best_direct_peer_path(peer, now) {
            return Some(selected);
        }
        if let Some(selected) = self.best_root_peer_path(now).1 {
            return Some(selected);
        }
        self.best_peer_path_candidate(peer, now, true)
    }

    /// Ranks eligible direct paths by priority and quality.
    #[must_use]
    pub fn best_direct_peer_path(&self, peer: &Peer, now: SystemTime) -> Option<PathKey> {
        self.best_peer_path_candidate(peer, now, false)
    }

    /// Ranks retained peer paths. `include_expired` is used only as the final
    /// send fallback after no root relay is available.
    #[must_use]
    pub fn best_peer_path_candidate(&self, peer: &Peer, now: SystemTime, include_expired: bool) -> Option<PathKey> {
        let mut selected: Option<PathKey> = None;
        let mut best_quality = Duration::MAX;
        for (candidate, path) in &peer.paths {
            let Some(quality) = self.direct_peer_path_quality(peer, *candidate, path, now, include_expired) else {
                continue;
            };
            let replace = match selected {
                None => true,
                Some(current) => quality < best_quality || (quality == best_quality && *candidate < current),
            };
            if replace {
                best_quality = quality;
                selected = Some(*candidate);
            }
        }
        selected
    }

    /// The legacy `Path::quality` score. Time values are reduced to the
    /// protocol's millisecond clock so scheduler precision cannot manufacture
    /// path preference changes.
    #[must_use]
    pub fn direct_peer_path_quality(
        &self,
        _peer: &Peer,
        candidate: PathKey,
        path: &PeerPathState,
        now: SystemTime,
        include_expired: bool,
    ) -> Option<Duration> {
        let authenticated_age =
            path.last_receive.and_then(|last_receive| now.duration_since(last_receive).ok()).unwrap_or_default()
                / MILLIS
                * MILLIS;
        if !include_expired && authenticated_age >= PEER_PATH_EXPIRATION {
            return None;
        }
        let scope = path_scope(candidate.endpoint.ip());
        if scope == 0 {
            return None;
        }
        let priority = u128::from(path.priority.max(1).unsigned_abs());
        let mut quality = path_latency(path);
        let physical_age = self.wire_path_age(candidate, path, now) / MILLIS * MILLIS;
        if physical_age >= PEER_PATH_ACTIVE_TIME {
            let maximum_age = 10 * crate::node::PEER_PATH_PING_PERIOD;
            let quality_age = physical_age.min(maximum_age);
            quality += UNKNOWN_PATH_LATENCY + quality_age;
        }
        quality *= u32::from(8 - scope);
        Some(quality / u32::try_from(priority).unwrap_or(u32::MAX))
    }

    /// Removes paths superseded by `keep`.
    pub(crate) fn prune_lower_priority_paths_locked(&mut self, address: Address, keep: PathKey, priority: i32) {
        let Some(peer) = self.peers.get(&address) else {
            return;
        };
        let doomed: Vec<PathKey> = peer
            .paths
            .keys()
            .filter(|key| {
                **key != keep
                    && (peer.paths.get(*key).is_some_and(|path| path.priority < priority)
                        || same_cluster_path_ip(key.endpoint.ip(), keep.endpoint.ip()))
            })
            .copied()
            .collect();
        for key in doomed {
            self.delete_peer_path_locked(address, key);
        }
    }

    /// Removes the least recently active path, reporting whether one could be
    /// replaced.
    pub(crate) fn evict_oldest_path_locked(&mut self, address: Address, now: SystemTime) -> bool {
        let Some(peer) = self.peers.get(&address) else {
            return false;
        };
        let mut oldest: Option<PathKey> = None;
        let mut oldest_age = Duration::ZERO;
        for (key, path) in &peer.paths {
            let age = self.wire_path_age(*key, path, now);
            let older = match oldest {
                None => true,
                Some(current) => age > oldest_age || (age == oldest_age && *key < current),
            };
            if age > Duration::ZERO && older {
                oldest_age = age;
                oldest = Some(*key);
            }
        }
        match oldest {
            Some(key) => {
                self.delete_peer_path_locked(address, key);
                true
            }
            None => false,
        }
    }

    /// Applies a HELLO's echoed wire timestamp to the path that returned the
    /// response, which may use a different port than the request target.
    pub(crate) fn update_path_latency_locked(
        &mut self,
        address: Address,
        key: PathKey,
        sent_at_millis: u64,
        now: SystemTime,
    ) {
        let now_millis = crate::node::unix_millis(now);
        if sent_at_millis > now_millis {
            return;
        }
        let Some(peer) = self.peers.get_mut(&address) else {
            return;
        };
        let Some(path) = peer.paths.get_mut(&key) else {
            return;
        };
        let latency_millis = now_millis - sent_at_millis;
        if latency_millis > (u64::MAX / 2) / u64::from(MILLIS) {
            return;
        }
        let previous_millis = u64::try_from(path.latency.as_millis()).unwrap_or(u64::MAX);
        if (!path.latency_measured && path.latency.is_zero()) || previous_millis >= 0xffff {
            path.latency = Duration::from_millis(latency_millis);
        } else {
            path.latency = Duration::from_millis(u64::midpoint(previous_millis, latency_millis));
        }
        path.latency_measured = true;
    }

    /// A diagnostic snapshot of every known peer, ordered by address.
    #[must_use]
    pub fn peers_snapshot(&self, now: SystemTime) -> Vec<PeerStatus> {
        let mut peers = Vec::with_capacity(self.peers.len());
        for (address, peer) in &self.peers {
            let preferred = self.best_direct_peer_path(peer, now);
            let versioned = peer.major != 0 || peer.minor != 0 || peer.revision != 0;
            let mut paths = Vec::with_capacity(peer.paths.len());
            for (key, path) in &peer.paths {
                let (_, trusted_path_id) = self.outbound_path_info(key.endpoint);
                let authenticated_age =
                    path.last_receive.and_then(|last_receive| now.duration_since(last_receive).ok());
                let active = authenticated_age.is_some_and(|age| age < PEER_PATH_EXPIRATION)
                    && path_scope(key.endpoint.ip()) != 0;
                paths.push(PeerPath {
                    local_socket: key.local_socket,
                    endpoint: key.endpoint,
                    last_send: self.wire_path_last_send(*key, path),
                    last_receive: self.wire_path_last_receive(*key, path),
                    active,
                    preferred: preferred == Some(*key),
                    priority: path.priority,
                    trusted_path_id,
                    latency: path.latency,
                    jitter: path.jitter,
                    packet_loss: path.loss,
                    packet_error: path.packet_error,
                });
            }
            paths.sort_by(|left, right| {
                right
                    .preferred
                    .cmp(&left.preferred)
                    .then_with(|| left.endpoint.cmp(&right.endpoint))
                    .then_with(|| left.local_socket.cmp(&right.local_socket))
            });
            peers.push(PeerStatus {
                address: *address,
                role: peer.role,
                protocol: peer.protocol,
                version_major: versioned.then_some(peer.major),
                version_minor: versioned.then_some(peer.minor),
                version_revision: versioned.then_some(peer.revision),
                route: peer.reported_user_route,
                paths,
            });
        }
        peers.sort_by_key(|status| status.address);
        peers
    }
}

/// Reports whether `endpoint` remains an authenticated peer path. ZeroTier One
/// uses the full path-expiration window here, not the shorter physical alive
/// interval.
#[must_use]
pub fn peer_has_active_endpoint(peer: &Peer, endpoint: SocketAddr, now: SystemTime) -> bool {
    peer.paths.iter().any(|(key, path)| {
        key.endpoint == endpoint
            && path
                .last_receive
                .and_then(|last_receive| now.duration_since(last_receive).ok())
                .is_some_and(|age| age < PEER_PATH_EXPIRATION)
    })
}

/// Reports whether addresses are equivalent for cluster path suppression.
#[must_use]
pub fn same_cluster_path_ip(left: IpAddr, right: IpAddr) -> bool {
    let left = unmap(left);
    let right = unmap(right);
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => left == right,
        (IpAddr::V6(left), IpAddr::V6(right)) => left.octets()[..8] == right.octets()[..8],
        _ => false,
    }
}

/// Mirrors `InetAddress::ipScope` and `Path::isAddressValidForPath`.
///
/// Only the scopes supported for physical ZeroTier traffic are returned;
/// link-local paths cannot be represented without an interface zone.
#[must_use]
pub fn path_scope(address: IpAddr) -> u8 {
    match unmap(address) {
        IpAddr::V4(address) => {
            let octets = address.octets();
            let value = u32::from_be_bytes(octets);
            match octets[0] {
                0 | 127 | 255 => 0,
                6 | 11 | 21 | 22 | 25 | 26 | 28 | 29 | 30 | 51 | 55 | 56 => 3,
                10 => 7,
                100 if value & 0xffc0_0000 == 0x6440_0000 => 7,
                169 if value & 0xffff_0000 == 0xa9fe_0000 => 0,
                172 if value & 0xfff0_0000 == 0xac10_0000 => 7,
                192 if value & 0xffff_0000 == 0xc0a8_0000 || value & 0xffff_ff00 == 0xc000_0200 => 7,
                198 if value & 0xfffe_0000 == 0xc612_0000 || value & 0xffff_ff00 == 0xc633_6400 => 7,
                203 if value & 0xffff_ff00 == 0xcb00_7100 => 7,
                _ => {
                    if octets[0] & 0xf0 == 0xe0 {
                        0
                    } else if octets[0] & 0xf0 == 0xf0 {
                        3
                    } else {
                        4
                    }
                }
            }
        }
        IpAddr::V6(address) => {
            let octets = address.octets();
            if address.is_unspecified() || address.is_loopback() || address.is_multicast() || is_link_local_v6(&octets)
            {
                return 0;
            }
            if octets[0] & 0xfe == 0xfc {
                return 7;
            }
            // ZeroTier One blacklists HE tunnelbroker paths: unstable MTU and
            // latency.
            if octets[..4] == [0x20, 0x01, 0x04, 0x70] {
                return 0;
            }
            4
        }
    }
}

fn is_link_local_v6(octets: &[u8; 16]) -> bool {
    octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
}

/// Reports whether `address` has ZeroTier's global IP scope, without the
/// additional HE-tunnel validity filter.
#[must_use]
pub fn is_global_physical_address(address: IpAddr) -> bool {
    match unmap(address) {
        IpAddr::V4(_) => path_scope(address) == 4,
        IpAddr::V6(address) => {
            let octets = address.octets();
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !is_link_local_v6(&octets)
                && octets[0] & 0xfe != 0xfc
        }
    }
}

/// A measured path latency, or the unknown-latency sentinel.
#[must_use]
pub fn path_latency(path: &PeerPathState) -> Duration {
    if !path.latency_measured && path.latency.is_zero() {
        return UNKNOWN_PATH_LATENCY;
    }
    path.latency
}

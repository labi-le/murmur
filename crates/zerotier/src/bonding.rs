//! Bonding policies: how traffic is distributed over the simultaneous direct
//! physical paths to one peer, plus the QoS measurements that feed the
//! quality-aware policies.
//!
//! The policies mirror ZeroTier One's `Bond`: `active-backup` keeps one path
//! active and negotiates a switch, `broadcast` duplicates each frame over every
//! eligible path, `balance-rr` sends runs of packets per link, `balance-xor`
//! pins a flow to a path chosen from its flow identifier, and `balance-aware`
//! distributes flows using measured path quality and configured link capacity.
//!
//! DEVIATION: QoS records are serialized little endian regardless of host byte
//! order; ZeroTier's supported targets are little endian.

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::address::Address;
use crate::node::peer::{PathKey, Peer, PeerPathState};
use crate::node::{elapsed, Node, MAX_PEER_PATHS, PEER_PATH_ACTIVE_TIME, PEER_PATH_EXPIRATION};
use crate::packet::{Packet, Verb};

/// Marks packets for which a stable bonding flow cannot be derived.
pub const NO_FLOW_ID: i32 = -1;
/// The default packet run assigned to one path by `balance-rr`.
pub const BOND_ROUND_ROBIN_PACKETS: usize = 64;
/// Bounds remembered flow-to-path assignments for one peer.
pub const MAX_BOND_FLOWS: usize = 64 * 1024;
/// Bounds one serialized QoS measurement payload.
pub const QOS_MEASUREMENT_MAX_SIZE: usize = 1400;
/// The maximum number of ten-byte records in one QoS measurement payload.
pub const QOS_MEASUREMENT_RECORDS: usize = QOS_MEASUREMENT_MAX_SIZE / 10;
/// Bounds unsent or unmatched QoS measurement records.
pub const QOS_MAX_PENDING_RECORDS: usize = QOS_MEASUREMENT_RECORDS * 3;
/// Bounds the rolling path-latency sample window.
pub const QOS_LATENCY_WINDOW_SIZE: usize = 64;
/// The sample count required before estimating jitter.
pub const QOS_LATENCY_MINIMUM: usize = 4;
/// The default maximum silence before a path fails.
pub const BOND_DEFAULT_FAILOVER: Duration = Duration::from_secs(5);
/// The shortest accepted failover interval.
pub const BOND_MINIMUM_FAILOVER: Duration = Duration::from_millis(500);
/// Limits active path changes and quality negotiation.
pub const BOND_OPTIMIZE_INTERVAL: Duration = Duration::from_secs(15);
/// The initial penalty after a path becomes ineligible.
pub const BOND_DEFAULT_REFRACTORY: Duration = Duration::from_secs(8);
/// Caps the repeated-ineligibility penalty.
pub const BOND_MAXIMUM_REFRACTORY: Duration = Duration::from_secs(600);
/// Bounds one sequence of path utility negotiations.
pub const BOND_NEGOTIATION_WINDOW: Duration = Duration::from_secs(60);
/// Limits transmissions in one negotiation sequence.
pub const BOND_NEGOTIATION_TRIES: u8 = 3;
/// The minimum interval between path-set rebuilds.
pub const BOND_MAINTENANCE_PERIOD: Duration = Duration::from_millis(100);

/// Selects how traffic is distributed over simultaneous direct paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum BondingPolicy {
    #[default]
    None,
    ActiveBackup,
    Broadcast,
    BalanceRoundRobin,
    BalanceXor,
    BalanceAware,
}

impl BondingPolicy {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ActiveBackup => "active-backup",
            Self::Broadcast => "broadcast",
            Self::BalanceRoundRobin => "balance-rr",
            Self::BalanceXor => "balance-xor",
            Self::BalanceAware => "balance-aware",
        }
    }

    /// Parses an embedding-facing policy name. An empty name selects `none`.
    pub fn parse(value: &str) -> Result<Self, BondingError> {
        Ok(match value {
            "" | "none" => Self::None,
            "active-backup" => Self::ActiveBackup,
            "broadcast" => Self::Broadcast,
            "balance-rr" => Self::BalanceRoundRobin,
            "balance-xor" => Self::BalanceXor,
            "balance-aware" => Self::BalanceAware,
            _ => return Err(BondingError::UnknownPolicy),
        })
    }
}

/// Controls when `active-backup` returns to another link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum BondingLinkSelectMethod {
    #[default]
    Always,
    Better,
    Failure,
    Optimize,
}

impl BondingLinkSelectMethod {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Better => "better",
            Self::Failure => "failure",
            Self::Optimize => "optimize",
        }
    }

    pub fn parse(value: &str) -> Result<Self, BondingError> {
        Ok(match value {
            "" | "always" => Self::Always,
            "better" => Self::Better,
            "failure" => Self::Failure,
            "optimize" => Self::Optimize,
            _ => return Err(BondingError::UnknownLinkSelectMethod),
        })
    }
}

/// Assigns an `active-backup` role to a physical link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum BondingLinkMode {
    #[default]
    Primary,
    Spare,
}

impl BondingLinkMode {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Spare => "spare",
        }
    }

    pub fn parse(value: &str) -> Result<Self, BondingError> {
        Ok(match value {
            "primary" => Self::Primary,
            "spare" => Self::Spare,
            _ => return Err(BondingError::InvalidLinkMode),
        })
    }
}

/// Reports a rejected bonding configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BondingError {
    #[error("unknown ZeroTier bonding policy")]
    UnknownPolicy,
    #[error("unknown ZeroTier bonding link select method")]
    UnknownLinkSelectMethod,
    #[error("invalid ZeroTier bonding link mode")]
    InvalidLinkMode,
    #[error("ZeroTier bonding failover interval must be at least 500ms")]
    FailoverIntervalTooShort,
    #[error("ZeroTier bonding packets per link must be between 0 and 65535")]
    PacketsPerLinkOutOfRange,
    #[error("ZeroTier bonding quality weights must be non-negative and total 1")]
    InvalidQualityWeights,
    #[error("ZeroTier bonding quality limits must be positive")]
    InvalidQualityLimits,
    #[error("ZeroTier bonding links require a name and local sockets")]
    IncompleteLink,
    #[error("duplicate ZeroTier bonding link name")]
    DuplicateLinkName,
    #[error("ZeroTier bonding link IP preference must be 0, 4, 6, 46, or 64")]
    InvalidIpPreference,
    #[error("a spare ZeroTier bonding link cannot define failover-to")]
    SpareWithFailover,
    #[error("a ZeroTier local socket belongs to multiple bonding links")]
    DuplicateLocalSocket,
    #[error("ZeroTier bonding failover-to references an unknown link")]
    UnknownFailoverLink,
}

/// Configures `balance-aware` path quality limits and weights.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BondingQuality {
    pub latency_max: Duration,
    pub jitter_max: Duration,
    pub packet_loss_max: f64,
    pub packet_error_max: f64,
    pub latency_weight: f64,
    pub jitter_weight: f64,
    pub packet_loss_weight: f64,
    pub packet_error_weight: f64,
}

impl BondingQuality {
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            latency_max: Duration::from_millis(500),
            jitter_max: Duration::from_millis(100),
            packet_loss_max: 0.001,
            packet_error_max: 0.0001,
            latency_weight: 0.25,
            jitter_weight: 0.25,
            packet_loss_weight: 0.25,
            packet_error_weight: 0.25,
        }
    }
}

/// Groups the local sockets that represent one physical link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondingLink {
    pub name: String,
    pub local_sockets: Vec<i64>,
    pub capacity: u32,
    pub ip_preference: u8,
    pub mode: BondingLinkMode,
    pub failover_to: String,
    pub disabled: bool,
}

/// Customizes one of the standard bonding policies.
#[derive(Debug, Clone, PartialEq)]
pub struct BondingOptions {
    pub failover_interval: Duration,
    pub up_delay: Duration,
    pub down_delay: Duration,
    /// Zero selects a path for each packet instead of sending a run on a link.
    pub packets_per_link: usize,
    pub link_select_method: BondingLinkSelectMethod,
    pub quality: BondingQuality,
    pub links: Vec<BondingLink>,
}

impl Default for BondingOptions {
    fn default() -> Self {
        default_bonding_options()
    }
}

/// The protocol-compatible bonding defaults.
#[must_use]
pub fn default_bonding_options() -> BondingOptions {
    BondingOptions {
        failover_interval: BOND_DEFAULT_FAILOVER,
        up_delay: Duration::ZERO,
        down_delay: Duration::ZERO,
        packets_per_link: BOND_ROUND_ROBIN_PACKETS,
        link_select_method: BondingLinkSelectMethod::Always,
        quality: BondingQuality::defaults(),
        links: Vec::new(),
    }
}

/// The caller-supplied half of [`BondingOptions`], where an absent field takes
/// the protocol default.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BondingOptionsInput {
    pub failover_interval: Option<Duration>,
    pub up_delay: Option<Duration>,
    pub down_delay: Option<Duration>,
    pub packets_per_link: Option<usize>,
    pub link_select_method: Option<BondingLinkSelectMethod>,
    pub quality: Option<BondingQuality>,
    pub links: Vec<BondingLink>,
}

/// Applies defaults, validates links, and owns the link slices.
pub fn normalize_bonding_options(input: BondingOptionsInput) -> Result<BondingOptions, BondingError> {
    let mut normalized = default_bonding_options();
    if let Some(interval) = input.failover_interval {
        normalized.failover_interval = interval;
    }
    if normalized.failover_interval < BOND_MINIMUM_FAILOVER {
        return Err(BondingError::FailoverIntervalTooShort);
    }
    normalized.up_delay = input.up_delay.unwrap_or_default();
    normalized.down_delay = input.down_delay.unwrap_or_default();
    if let Some(packets) = input.packets_per_link {
        if packets > u16::MAX as usize {
            return Err(BondingError::PacketsPerLinkOutOfRange);
        }
        normalized.packets_per_link = packets;
    }
    if let Some(method) = input.link_select_method {
        normalized.link_select_method = method;
    }
    if let Some(quality) = input.quality {
        if quality.latency_max != Duration::ZERO {
            normalized.quality.latency_max = quality.latency_max;
        }
        if quality.jitter_max != Duration::ZERO {
            normalized.quality.jitter_max = quality.jitter_max;
        }
        if quality.packet_loss_max != 0.0 {
            normalized.quality.packet_loss_max = quality.packet_loss_max;
        }
        if quality.packet_error_max != 0.0 {
            normalized.quality.packet_error_max = quality.packet_error_max;
        }
        let weight_total =
            quality.latency_weight + quality.jitter_weight + quality.packet_loss_weight + quality.packet_error_weight;
        if weight_total != 0.0 {
            let negative = quality.latency_weight < 0.0
                || quality.jitter_weight < 0.0
                || quality.packet_loss_weight < 0.0
                || quality.packet_error_weight < 0.0;
            if (weight_total - 1.0).abs() > 0.01 || negative {
                return Err(BondingError::InvalidQualityWeights);
            }
            normalized.quality.latency_weight = quality.latency_weight;
            normalized.quality.jitter_weight = quality.jitter_weight;
            normalized.quality.packet_loss_weight = quality.packet_loss_weight;
            normalized.quality.packet_error_weight = quality.packet_error_weight;
        }
    }
    if normalized.quality.latency_max <= Duration::ZERO
        || normalized.quality.jitter_max <= Duration::ZERO
        || normalized.quality.packet_loss_max <= 0.0
        || normalized.quality.packet_error_max <= 0.0
    {
        return Err(BondingError::InvalidQualityLimits);
    }
    let mut links: Vec<BondingLink> = Vec::with_capacity(input.links.len());
    let mut sockets: Vec<i64> = Vec::new();
    for link in input.links {
        let mut link = link;
        let name = link.name.trim().to_owned();
        if name.is_empty() || link.local_sockets.is_empty() {
            return Err(BondingError::IncompleteLink);
        }
        link.name = name;
        if links.iter().any(|known| known.name == link.name) {
            return Err(BondingError::DuplicateLinkName);
        }
        if !matches!(link.ip_preference, 0 | 4 | 6 | 46 | 64) {
            return Err(BondingError::InvalidIpPreference);
        }
        if link.mode == BondingLinkMode::Spare && !link.failover_to.is_empty() {
            return Err(BondingError::SpareWithFailover);
        }
        for socket in &link.local_sockets {
            if sockets.contains(socket) {
                return Err(BondingError::DuplicateLocalSocket);
            }
            sockets.push(*socket);
        }
        links.push(link);
    }
    for link in &links {
        if !link.failover_to.is_empty() && !links.iter().any(|known| known.name == link.failover_to) {
            return Err(BondingError::UnknownFailoverLink);
        }
    }
    normalized.links = links;
    Ok(normalized)
}

/// The physical paths selected for one outbound packet. A single path is the
/// common result and carries no allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BondPaths {
    Empty,
    Single(PathKey),
    Many(Vec<PathKey>),
}

impl BondPaths {
    pub(crate) fn as_slice(&self) -> &[PathKey] {
        match self {
            Self::Empty => &[],
            Self::Single(path) => std::slice::from_ref(path),
            Self::Many(paths) => paths,
        }
    }

    fn single(path: Option<PathKey>) -> Self {
        match path {
            Some(path) => Self::Single(path),
            None => Self::Empty,
        }
    }
}

/// One path's normalized impairment scores.
struct BondMetrics {
    latency: f64,
    jitter: f64,
    loss: f64,
    packet_error: f64,
}

impl Node {
    /// Resolves a peer bonding override or the node default.
    pub(crate) fn bonding_policy_for_peer_locked(&self, address: Address) -> BondingPolicy {
        match self.peer_paths.get(&address) {
            Some(configured) if configured.bonding_policy_set => configured.bonding_policy,
            _ => self.bonding_policy,
        }
    }

    /// Resolves peer-specific or default bond options.
    pub(crate) fn bonding_options_for_peer_locked(&self, address: Address) -> &BondingOptions {
        self.peer_paths
            .get(&address)
            .and_then(|configured| configured.bonding_options.as_ref())
            .unwrap_or(&self.bonding_options)
    }

    /// The measurement cadence for one peer.
    fn bond_qos_interval_locked(&self, address: Address) -> Duration {
        2 * self.bonding_options_for_peer_locked(address).failover_interval
    }

    /// Selects the physical paths for one outbound packet.
    pub(crate) fn bonded_paths_locked(
        &mut self,
        address: Address,
        verb: Verb,
        flow_id: i32,
        packet_id: u64,
        now: SystemTime,
    ) -> BondPaths {
        let policy = self.bonding_policy_for_peer_locked(address);
        let root = self.peers.get(&address).is_some_and(|peer| peer.root);
        let best = |node: &Self| node.peers.get(&address).and_then(|peer| node.best_peer_path(peer, now));
        if root || policy == BondingPolicy::None {
            return BondPaths::single(best(self));
        }
        if policy == BondingPolicy::Broadcast {
            let Some(peer) = self.peers.get(&address) else {
                return BondPaths::single(best(self));
            };
            let paths = self.active_direct_peer_paths(peer, now);
            if paths.is_empty() {
                return BondPaths::single(best(self));
            }
            if matches!(verb, Verb::Frame | Verb::ExtFrame) {
                return BondPaths::Many(paths);
            }
            return BondPaths::Many(paths.get(..1).unwrap_or_default().to_vec());
        }
        let Some(peer) = self.peers.get(&address) else {
            return BondPaths::single(best(self));
        };
        let due = match peer.bond_last_maintenance {
            None => true,
            Some(maintained) => elapsed(now, maintained) >= BOND_MAINTENANCE_PERIOD,
        };
        let stale = due || peer.bond_known_path_count != peer.paths.len();
        let paths = if stale {
            let options = self.bonding_options_for_peer_static(address);
            self.maintain_bond_locked(address, policy, &options, now)
        } else {
            self.peers.get(&address).map(|peer| peer.bond_paths.clone()).unwrap_or_default()
        };
        if paths.is_empty() {
            return BondPaths::single(best(self));
        }
        if policy == BondingPolicy::ActiveBackup {
            let active = self.peers.get(&address).and_then(|peer| peer.bond_active);
            if let Some(active) = active {
                if paths.contains(&active) {
                    return BondPaths::Single(active);
                }
            }
            return BondPaths::single(paths.first().copied());
        }
        if policy == BondingPolicy::BalanceRoundRobin {
            let options = self.bonding_options_for_peer_static(address);
            return BondPaths::single(self.bond_round_robin_path(address, &paths, &options, packet_id));
        }
        if flow_id == NO_FLOW_ID {
            let index = usize::try_from(packet_id % paths.len() as u64).unwrap_or_default();
            return BondPaths::single(paths.get(index).copied());
        }
        BondPaths::single(self.bonded_flow_path_locked(address, &paths, policy, flow_id, now))
    }

    /// One flow-pinned selection, remembering the assignment.
    fn bonded_flow_path_locked(
        &mut self,
        address: Address,
        paths: &[PathKey],
        policy: BondingPolicy,
        flow_id: i32,
        now: SystemTime,
    ) -> Option<PathKey> {
        let policy_avoids_flow = |node: &Self, flow_path: PathKey| {
            policy != BondingPolicy::BalanceAware
                || node
                    .peers
                    .get(&address)
                    .and_then(|peer| peer.paths.get(&flow_path))
                    .is_some_and(|state| state.bond_avoid)
        };
        let known_flow = self.peers.get(&address).and_then(|peer| peer.bond_flows.get(&flow_id).copied());
        if let Some(flow) = known_flow {
            if paths.contains(&flow.path) && !policy_avoids_flow(self, flow.path) {
                if let Some(peer) = self.peers.get_mut(&address) {
                    if let Some(entry) = peer.bond_flows.get_mut(&flow_id) {
                        entry.last_active = now;
                    }
                }
                return Some(flow.path);
            }
            self.release_bond_flow(address, flow_id, flow.path);
        }
        let flow_count = self.peers.get(&address).map_or(0, |peer| peer.bond_flows.len());
        if flow_count >= MAX_BOND_FLOWS {
            self.evict_oldest_bond_flow_locked(address);
        }
        let selected = if policy == BondingPolicy::BalanceAware {
            let peer = self.peers.get(&address)?;
            aware_bond_path(peer, paths, flow_id)
        } else {
            let index = usize::try_from(flow_id.cast_unsigned()).unwrap_or_default() % paths.len();
            paths.get(index).copied()?
        };
        if let Some(peer) = self.peers.get_mut(&address) {
            if let Some(state) = peer.paths.get_mut(&selected) {
                state.bond_assigned_flows = state.bond_assigned_flows.saturating_add(1);
            }
            peer.bond_flows.insert(flow_id, crate::node::peer::BondFlow { path: selected, last_active: now });
        }
        Some(selected)
    }

    /// One `balance-rr` selection, advancing the peer's packet run.
    fn bond_round_robin_path(
        &mut self,
        address: Address,
        paths: &[PathKey],
        options: &BondingOptions,
        packet_id: u64,
    ) -> Option<PathKey> {
        if options.packets_per_link == 0 {
            let index = usize::try_from(packet_id % paths.len() as u64).unwrap_or_default();
            return paths.get(index).copied();
        }
        let peer = self.peers.get(&address)?;
        let (mut index, mut packets) = (peer.bond_rr_index, peer.bond_rr_packets);
        if packets >= options.packets_per_link as u64 {
            packets = 0;
            index += 1;
        }
        let selected = paths.get(usize::try_from(index % paths.len() as u64).unwrap_or_default()).copied();
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.bond_rr_index = index;
            peer.bond_rr_packets = packets + 1;
        }
        selected
    }

    fn release_bond_flow(&mut self, address: Address, flow_id: i32, path: PathKey) {
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.bond_flows.remove(&flow_id);
            if let Some(state) = peer.paths.get_mut(&path) {
                state.bond_assigned_flows = state.bond_assigned_flows.saturating_sub(1);
            }
        }
    }

    /// Removes the least recently active flow assignment.
    pub(crate) fn evict_oldest_bond_flow_locked(&mut self, address: Address) {
        let oldest = self.peers.get(&address).and_then(|peer| {
            peer.bond_flows.iter().min_by_key(|(_, flow)| flow.last_active).map(|(id, flow)| (*id, flow.path))
        });
        if let Some((flow_id, path)) = oldest {
            self.release_bond_flow(address, flow_id, path);
        }
    }

    /// Currently eligible direct paths.
    pub(crate) fn active_direct_peer_paths(&self, peer: &Peer, now: SystemTime) -> Vec<PathKey> {
        let mut paths: Vec<PathKey> = peer
            .paths
            .iter()
            .filter(|(key, state)| self.wire_path_age(**key, state, now) < PEER_PATH_ACTIVE_TIME)
            .map(|(key, _)| *key)
            .collect();
        sort_bond_paths(&mut paths);
        paths
    }

    /// Refreshes path eligibility, quality, and active selection.
    pub(crate) fn maintain_bond_locked(
        &mut self,
        address: Address,
        policy: BondingPolicy,
        options: &BondingOptions,
        now: SystemTime,
    ) -> Vec<PathKey> {
        let Some(peer) = self.peers.get(&address) else {
            return Vec::new();
        };
        let candidates: Vec<(PathKey, PeerPathState)> =
            peer.paths.iter().map(|(key, state)| (*key, state.clone())).collect();
        let mut all = Vec::with_capacity(candidates.len());
        let mut updated = Vec::with_capacity(candidates.len());
        for (key, mut state) in candidates {
            let allowed = bond_path_allowed(key, options);
            let nominated = if let Some(nominated) = state.bond_nominated {
                nominated
            } else {
                state.bond_nominated = Some(now);
                state.bond_eligible_at = Some(now);
                state.bond_eligible = true;
                now
            };
            let physical_age = self.wire_path_age(key, &state, now);
            let alive = physical_age < options.failover_interval;
            if alive && !state.bond_alive {
                state.bond_alive_since = Some(now);
            }
            state.bond_alive = alive;
            let in_trial = elapsed(now, nominated) < BOND_OPTIMIZE_INTERVAL;
            let acceptable_age = physical_age < options.failover_interval + options.down_delay;
            let satisfied_up_delay =
                state.bond_alive_since.is_some_and(|since| elapsed(now, since) >= options.up_delay);
            let fresh_qos_age = match state.last_qos_receive {
                None => in_trial,
                Some(received) => elapsed(now, received) < PEER_PATH_EXPIRATION,
            };
            let acceptable_qos_age = policy == BondingPolicy::ActiveBackup || fresh_qos_age;
            let eligible = allowed && ((acceptable_age && satisfied_up_delay && acceptable_qos_age) || in_trial);
            if eligible {
                state.bond_eligible_at = Some(now);
                if state.bond_refractory > Duration::ZERO && state.bond_alive {
                    let drain = state.bond_alive_since.map(|since| elapsed(now, since)).unwrap_or_default();
                    if drain >= state.bond_refractory {
                        state.bond_refractory = Duration::ZERO;
                    }
                }
            } else if state.bond_eligible {
                state.bond_refractory = if state.bond_refractory == Duration::ZERO {
                    BOND_DEFAULT_REFRACTORY
                } else {
                    (BOND_DEFAULT_REFRACTORY + 2 * state.bond_refractory).min(BOND_MAXIMUM_REFRACTORY)
                };
                state.bond_avoid = true;
            }
            state.bond_eligible = eligible;
            if eligible {
                all.push(key);
            }
            updated.push((key, state));
        }
        if let Some(peer) = self.peers.get_mut(&address) {
            for (key, state) in updated {
                peer.paths.insert(key, state);
            }
        }
        sort_bond_paths(&mut all);
        if policy == BondingPolicy::ActiveBackup {
            self.estimate_bond_quality_locked(address, &all, options);
            all = self.maintain_active_backup_locked(address, &all, options, now);
        } else {
            all = self.select_bonded_link_paths(address, &all, options);
            self.estimate_bond_quality_locked(address, &all, options);
        }
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.bond_paths.clone_from(&all);
            peer.bond_last_maintenance = Some(now);
            peer.bond_known_path_count = peer.paths.len();
        }
        all
    }

    /// Applies link roles and family preferences to `paths`.
    fn select_bonded_link_paths(
        &mut self,
        address: Address,
        paths: &[PathKey],
        options: &BondingOptions,
    ) -> Vec<PathKey> {
        let result = select_bonded_link_paths(paths, options);
        if let Some(peer) = self.peers.get_mut(&address) {
            for key in &result {
                if let Some(state) = peer.paths.get_mut(key) {
                    state.bond_eligible = true;
                }
            }
        }
        result
    }

    /// Updates normalized path impairment and capacity scores.
    pub(crate) fn estimate_bond_quality_locked(
        &mut self,
        address: Address,
        paths: &[PathKey],
        options: &BondingOptions,
    ) {
        let mut max_capacity = 0u32;
        for key in paths {
            max_capacity = max_capacity.max(bond_link_capacity(options, key.local_socket));
        }
        let have_configured_capacity = max_capacity != 0;
        if !have_configured_capacity {
            max_capacity = 1;
        }
        let mut metrics = Vec::with_capacity(paths.len());
        let (mut max_latency, mut max_jitter, mut max_loss, mut max_packet_error) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
        for key in paths {
            let Some(state) = self.peers.get(&address).and_then(|peer| peer.paths.get(key)).cloned() else {
                continue;
            };
            let capacity = if have_configured_capacity { bond_link_capacity(options, key.local_socket) } else { 1 };
            let quality = options.quality;
            let metric = BondMetrics {
                // Both sides are scaled to seconds; only their ratio is used.
                latency: bond_metric_score(state.bond_latency.as_secs_f64(), quality.latency_max.as_secs_f64()),
                jitter: bond_metric_score(state.jitter.as_secs_f64(), quality.jitter_max.as_secs_f64()),
                loss: bond_metric_score(state.loss, quality.packet_loss_max),
                packet_error: bond_metric_score(state.packet_error, quality.packet_error_max),
            };
            max_latency = max_latency.max(metric.latency);
            max_jitter = max_jitter.max(metric.jitter);
            max_loss = max_loss.max(metric.loss);
            max_packet_error = max_packet_error.max(metric.packet_error);
            let avoid = state.bond_latency > quality.latency_max
                || state.jitter > quality.jitter_max
                || state.loss > quality.packet_loss_max
                || state.packet_error > quality.packet_error_max;
            if let Some(state) = self.peers.get_mut(&address).and_then(|peer| peer.paths.get_mut(key)) {
                state.bond_capacity = f64::from(capacity) / f64::from(max_capacity);
                state.bond_avoid = avoid;
            }
            metrics.push((*key, metric));
        }
        let mut total = 0.0;
        for (key, metric) in &metrics {
            let quality = options.quality;
            #[expect(
                clippy::suboptimal_flops,
                reason = "the terms sum as separate products, and fusing them changes the low bits of the score"
            )]
            let score = quality.latency_weight * relative_bond_metric(metric.latency, max_latency)
                + quality.jitter_weight * relative_bond_metric(metric.jitter, max_jitter)
                + quality.packet_loss_weight * relative_bond_metric(metric.loss, max_loss)
                + quality.packet_error_weight * relative_bond_metric(metric.packet_error, max_packet_error);
            if let Some(state) = self.peers.get_mut(&address).and_then(|peer| peer.paths.get_mut(key)) {
                state.bond_quality = score * state.bond_capacity;
                total += state.bond_quality;
            }
        }
        if total > 0.0 {
            if let Some(peer) = self.peers.get_mut(&address) {
                for key in paths {
                    if let Some(state) = peer.paths.get_mut(key) {
                        state.bond_quality /= total;
                    }
                }
            }
        }
    }

    /// Selects and orders the active and failover paths.
    pub(crate) fn maintain_active_backup_locked(
        &mut self,
        address: Address,
        paths: &[PathKey],
        options: &BondingOptions,
        now: SystemTime,
    ) -> Vec<PathKey> {
        let explicit_failover = bonding_has_failover_instructions(options);
        if paths.is_empty() {
            if let Some(peer) = self.peers.get_mut(&address) {
                peer.bond_active = None;
                peer.bond_failover.clear();
            }
            return Vec::new();
        }
        self.score_bond_paths_locked(address, paths, options, explicit_failover);
        self.inherit_bond_failover_scores_locked(address, paths, options);
        let mut ordered = paths.to_vec();
        ordered.sort_by_key(|key| std::cmp::Reverse(self.bond_path_score_of(address, key)));
        let previous_active = self.peers.get(&address).and_then(|peer| peer.bond_active);
        let negotiated =
            self.peers.get(&address).and_then(|peer| peer.bond_negotiated).filter(|key| ordered.contains(key));
        let active_valid = previous_active.is_some_and(|key| ordered.contains(&key));
        let mut active = if active_valid {
            previous_active
        } else if previous_active.is_some() {
            ordered.first().copied()
        } else {
            initial_active_backup_path(paths, options)
        };
        if let Some(negotiated) = negotiated {
            active = Some(negotiated);
            if let Some(state) = self.peers.get_mut(&address).and_then(|peer| peer.paths.get_mut(&negotiated)) {
                state.bond_negotiated = true;
            }
            if let Some(peer) = self.peers.get_mut(&address) {
                peer.bond_negotiated = None;
            }
        }
        if let (Some(best), Some(active_key)) = (ordered.first().copied(), active) {
            if active_key != best
                && self.should_switch_bond_path(address, options, explicit_failover, best, active_key, now)
            {
                active = Some(best);
            }
        }
        let Some(active) = active else {
            return ordered;
        };
        if previous_active != Some(active) {
            self.reset_bond_path_counters_locked(address, &ordered, now);
        }
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.bond_active = Some(active);
            peer.bond_failover = ordered.iter().filter(|key| **key != active).copied().collect();
        }
        ordered
    }

    /// Clears the packet counters after the active path changes.
    fn reset_bond_path_counters_locked(&mut self, address: Address, paths: &[PathKey], now: SystemTime) {
        if let Some(peer) = self.peers.get_mut(&address) {
            peer.bond_last_active_change = Some(now);
            for key in paths {
                if let Some(state) = peer.paths.get_mut(key) {
                    state.bond_packets_in = 0;
                    state.bond_packets_out = 0;
                }
            }
        }
    }

    /// Assigns each path its quality, family, and role score.
    fn score_bond_paths_locked(
        &mut self,
        address: Address,
        paths: &[PathKey],
        options: &BondingOptions,
        explicit_failover: bool,
    ) {
        for key in paths {
            let link = bonding_link_for_socket(options, key.local_socket);
            let quality = self
                .peers
                .get(&address)
                .and_then(|peer| peer.paths.get(key))
                .map(|state| state.bond_quality)
                .unwrap_or_default();
            let mut score = bond_path_score(quality);
            if link.is_none_or(|link| bonding_link_prefers_address(link, key.endpoint.ip())) {
                score += 500;
            }
            if link.is_none_or(|link| link.mode == BondingLinkMode::Primary)
                && (options.link_select_method != BondingLinkSelectMethod::Optimize || explicit_failover)
            {
                score += 1000;
            }
            if let Some(state) = self.peers.get_mut(&address).and_then(|peer| peer.paths.get_mut(key)) {
                state.bond_score = score;
            }
        }
    }

    /// The current score of one path, or zero when the path is unknown.
    fn bond_path_score_of(&self, address: Address, key: &PathKey) -> i32 {
        self.peers.get(&address).and_then(|peer| peer.paths.get(key)).map(|state| state.bond_score).unwrap_or_default()
    }

    /// Lowers each failover target below the link that names it.
    fn inherit_bond_failover_scores_locked(&mut self, address: Address, paths: &[PathKey], options: &BondingOptions) {
        for _ in 0..options.links.len() {
            for source in paths {
                let Some(link) = bonding_link_for_socket(options, source.local_socket) else {
                    continue;
                };
                if link.failover_to.is_empty() {
                    continue;
                }
                for target in paths {
                    let Some(target_link) = bonding_link_for_socket(options, target.local_socket) else {
                        continue;
                    };
                    if target_link.name != link.failover_to {
                        continue;
                    }
                    let mut inherited = self.bond_path_score_of(address, source) - 10;
                    if !bonding_link_prefers_address(&target_link, target.endpoint.ip()) {
                        inherited -= 1;
                    }
                    if self.bond_path_score_of(address, target) < inherited {
                        if let Some(state) = self.peers.get_mut(&address).and_then(|peer| peer.paths.get_mut(target)) {
                            state.bond_score = inherited;
                        }
                    }
                }
            }
        }
    }

    /// Whether the active path should yield to a better candidate.
    fn should_switch_bond_path(
        &self,
        address: Address,
        options: &BondingOptions,
        explicit_failover: bool,
        best: PathKey,
        active: PathKey,
        now: SystemTime,
    ) -> bool {
        let active_primary =
            bonding_link_for_socket(options, active.local_socket).is_none_or(|link| link.mode == BondingLinkMode::Primary);
        let best_primary =
            bonding_link_for_socket(options, best.local_socket).is_none_or(|link| link.mode == BondingLinkMode::Primary);
        match options.link_select_method {
            BondingLinkSelectMethod::Always => !active_primary && best_primary,
            BondingLinkSelectMethod::Better => {
                !active_primary
                    && best_primary
                    && self.bond_path_score_of(address, &best) > self.bond_path_score_of(address, &active)
            }
            BondingLinkSelectMethod::Optimize => {
                let quality = self
                    .peers
                    .get(&address)
                    .and_then(|peer| peer.paths.get(&active))
                    .map(|state| state.bond_quality)
                    .unwrap_or_default();
                let threshold = if explicit_failover { 0 } else { bond_switch_threshold(quality) };
                let since_change = self
                    .peers
                    .get(&address)
                    .and_then(|peer| peer.bond_last_active_change)
                    .map_or(BOND_OPTIMIZE_INTERVAL, |changed| elapsed(now, changed));
                since_change >= BOND_OPTIMIZE_INTERVAL
                    && self.bond_path_score_of(address, &best) - self.bond_path_score_of(address, &active) > threshold
            }
            BondingLinkSelectMethod::Failure => false,
        }
    }

    /// Records QoS and flow state for one transmission.
    pub(crate) fn record_outgoing_bond_packet_locked(
        &mut self,
        address: Address,
        key: PathKey,
        packet_id: u64,
        verb: Verb,
        now: SystemTime,
    ) {
        let policy = self.bonding_policy_for_peer_locked(address);
        let root = self.peers.get(&address).is_some_and(|peer| peer.root);
        if policy == BondingPolicy::None || root {
            return;
        }
        if !bond_path_allowed(key, self.bonding_options_for_peer_locked(address)) {
            return;
        }
        let Some(peer) = self.peers.get_mut(&address) else {
            return;
        };
        let Some(path) = peer.paths.get_mut(&key) else {
            return;
        };
        if matches!(verb, Verb::Echo | Verb::Frame | Verb::ExtFrame) {
            path.bond_packets_out += 1;
        }
        if verb == Verb::Ack || verb == Verb::QosMeasurement || packet_id.is_multiple_of(2) {
            return;
        }
        if path.qos_outgoing.len() < QOS_MAX_PENDING_RECORDS {
            path.qos_outgoing.insert(packet_id, now);
        }
    }

    /// Records QoS, flow, and liveness observations for one arrival.
    pub(crate) fn record_incoming_bond_packet_locked(
        &mut self,
        address: Address,
        key: PathKey,
        packet: &Packet,
        flow_id: i32,
        now: SystemTime,
    ) {
        let policy = self.bonding_policy_for_peer_locked(address);
        let root = self.peers.get(&address).is_some_and(|peer| peer.root);
        if policy == BondingPolicy::None || root {
            return;
        }
        if !bond_path_allowed(key, self.bonding_options_for_peer_locked(address)) {
            return;
        }
        let verb = packet.verb();
        let packet_id = packet.packet_id();
        let flow_tracking = matches!(
            policy,
            BondingPolicy::BalanceRoundRobin | BondingPolicy::BalanceXor | BondingPolicy::BalanceAware
        );
        let flow_count = self.peers.get(&address).map(|peer| peer.bond_flows.len()).unwrap_or_default();
        let tracked = self.peers.get(&address).is_some_and(|peer| peer.bond_flows.contains_key(&flow_id));
        let Some(peer) = self.peers.get_mut(&address) else {
            return;
        };
        let Some(path) = peer.paths.get_mut(&key) else {
            return;
        };
        path.packet_error *= 0.984375;
        if matches!(verb, Some(Verb::Echo | Verb::Frame | Verb::ExtFrame)) {
            path.bond_packets_in += 1;
        }
        if !matches!(verb, Some(Verb::Ack | Verb::QosMeasurement))
            && packet_id & 1 != 0
            && path.qos_incoming.len() < QOS_MAX_PENDING_RECORDS
        {
            path.qos_incoming.insert(packet_id, now);
        }
        if flow_id != NO_FLOW_ID && flow_tracking && !tracked {
            if flow_count >= MAX_BOND_FLOWS {
                self.evict_oldest_bond_flow_locked(address);
            }
            let Some(peer) = self.peers.get_mut(&address) else {
                return;
            };
            if let Some(path) = peer.paths.get_mut(&key) {
                path.bond_assigned_flows = path.bond_assigned_flows.saturating_add(1);
            }
            peer.bond_flows.insert(flow_id, crate::node::peer::BondFlow { path: key, last_active: now });
        }
    }

    /// Sends pending packet timing records to `address`.
    pub(crate) fn send_qos_measurements_locked(&mut self, address: Address, now: SystemTime) {
        let policy = self.bonding_policy_for_peer_locked(address);
        let root = self.peers.get(&address).is_some_and(|peer| peer.root);
        if policy == BondingPolicy::None || root {
            return;
        }
        let options = self.bonding_options_for_peer_locked(address);
        let interval = 2 * options.failover_interval;
        let paths: Vec<PathKey> = match self.peers.get(&address) {
            Some(peer) => peer.paths.keys().copied().collect(),
            None => return,
        };
        let allowed: Vec<PathKey> = paths.into_iter().filter(|key| bond_path_allowed(*key, options)).collect();
        for key in allowed {
            self.expire_qos_records_locked(address, key, now, 3 * interval);
            let (due, ids, peer_address) = {
                let Some(peer) = self.peers.get(&address) else {
                    return;
                };
                let Some(path) = peer.paths.get(&key) else {
                    continue;
                };
                let due = !path.qos_incoming.is_empty()
                    && path.last_qos_sent.is_none_or(|sent| elapsed(now, sent) >= interval);
                let mut ids: Vec<u64> = path.qos_incoming.keys().copied().collect();
                ids.sort_unstable();
                ids.truncate(QOS_MEASUREMENT_RECORDS);
                (due, ids, peer.identity.address())
            };
            if !due {
                continue;
            }
            let Ok(mut packet) = Packet::new(peer_address, self.identity().address(), Verb::QosMeasurement) else {
                continue;
            };
            let Some(peer) = self.peers.get_mut(&address) else {
                return;
            };
            let Some(path) = peer.paths.get_mut(&key) else {
                continue;
            };
            for packet_id in ids {
                let Some(received) = path.qos_incoming.remove(&packet_id) else {
                    continue;
                };
                let holding = u64::try_from(elapsed(now, received).as_millis()).unwrap_or(u64::MAX);
                let mut record = [0u8; 10];
                let (head, tail) = record.split_at_mut(8);
                head.copy_from_slice(&packet_id.to_le_bytes());
                // Saturates, unlike the crate's other wire encoders, which truncate
                // with `as u16`. Truncation would wrap a holding time past 65.5s down
                // to a near-zero value, understating the path's QoS, so the divergence
                // is kept on purpose. With the default 5s failover interval records
                // expire after 30s, so this branch needs a failover interval above
                // ~12s to be hit.
                tail.copy_from_slice(&u16::try_from(holding).unwrap_or(u16::MAX).to_le_bytes());
                if packet.append(&record).is_err() {
                    break;
                }
            }
            path.last_qos_sent = Some(now);
            let _ = self.send_packet_via_path_locked(address, packet, true, key, false);
        }
    }

    /// Matches peer timing records to local sends.
    pub(crate) fn handle_qos_measurement_locked(
        &mut self,
        address: Address,
        key: PathKey,
        packet: &Packet,
        now: SystemTime,
    ) {
        let policy = self.bonding_policy_for_peer_locked(address);
        let root = self.peers.get(&address).is_some_and(|peer| peer.root);
        if policy == BondingPolicy::None || root {
            return;
        }
        let interval = self.bond_qos_interval_locked(address);
        let (count, options) = {
            let Some(peer) = self.peers.get_mut(&address) else {
                return;
            };
            let peer_limit = u32::try_from(MAX_PEER_PATHS).unwrap_or(u32::MAX);
            let rate_limited =
                peer.last_qos_rate_check.is_some_and(|checked| elapsed(now, checked) <= interval / peer_limit);
            peer.qos_rate_count = if rate_limited { peer.qos_rate_count + 1 } else { 0 };
            peer.last_qos_rate_check = Some(now);
            (peer.qos_rate_count, self.bonding_options_for_peer_locked(address))
        };
        if count >= u16::try_from(MAX_PEER_PATHS * 2).unwrap_or(u16::MAX) {
            return;
        }
        let payload = packet.payload();
        if payload.len() < 10 || payload.len() > QOS_MEASUREMENT_MAX_SIZE || !payload.len().is_multiple_of(10) {
            return;
        }
        if !bond_path_allowed(key, options) {
            return;
        }
        let Some(peer) = self.peers.get_mut(&address) else {
            return;
        };
        let Some(path) = peer.paths.get_mut(&key) else {
            return;
        };
        path.last_qos_receive = Some(now);
        for record in payload.chunks_exact(10) {
            let Some(id) = record.first_chunk::<8>() else {
                continue;
            };
            let Some(delay) = record.last_chunk::<2>() else {
                continue;
            };
            let packet_id = u64::from_le_bytes(*id);
            let holding = u64::from(u16::from_le_bytes(*delay));
            let Some(sent_at) = path.qos_outgoing.remove(&packet_id) else {
                continue;
            };
            let round_trip_millis = u64::try_from(elapsed(now, sent_at).as_millis()).unwrap_or(u64::MAX);
            if round_trip_millis < holding {
                continue;
            }
            record_qos_latency_sample(path, Duration::from_millis((round_trip_millis - holding) / 2));
            path.loss *= 0.95;
        }
    }

    /// Resolves bond options as an owned value, for callers that keep them across a mutable borrow
    /// of the node.
    pub(crate) fn bonding_options_for_peer_static(&self, address: Address) -> BondingOptions {
        self.bonding_options_for_peer_locked(address).clone()
    }

    #[expect(
        clippy::suboptimal_flops,
        reason = "the terms multiply and add separately, and fusing them changes the low bits of the loss estimate"
    )]
    fn expire_qos_records_locked(&mut self, address: Address, key: PathKey, now: SystemTime, expiration: Duration) {
        let Some(peer) = self.peers.get_mut(&address) else {
            return;
        };
        let Some(path) = peer.paths.get_mut(&key) else {
            return;
        };
        let expired: Vec<u64> = path
            .qos_outgoing
            .iter()
            .filter(|(_, sent_at)| elapsed(now, **sent_at) >= expiration)
            .map(|(packet_id, _)| *packet_id)
            .collect();
        for packet_id in expired {
            path.qos_outgoing.remove(&packet_id);
            path.loss = path.loss * 0.95 + 0.05;
        }
        path.qos_incoming.retain(|_, received| elapsed(now, *received) < expiration);
    }

    /// Exchanges utility proposals for `optimize` mode.
    pub(crate) fn process_bond_negotiation_locked(
        &mut self,
        address: Address,
        options: &BondingOptions,
        now: SystemTime,
    ) {
        let policy_due = {
            let Some(peer) = self.peers.get(&address) else {
                return;
            };
            options.link_select_method == BondingLinkSelectMethod::Optimize
                && peer.bond_last_negotiation.is_none_or(|last| elapsed(now, last) >= BOND_OPTIMIZE_INTERVAL)
        };
        if !policy_due {
            return;
        }
        let (mut max_in, mut max_out) = (0u64, 0u64);
        let (mut max_in_path, mut max_out_path) = (None, None);
        {
            let Some(peer) = self.peers.get_mut(&address) else {
                return;
            };
            peer.bond_last_negotiation = Some(now);
            for (key, state) in &mut peer.paths {
                if state.bond_packets_in > max_in {
                    max_in = state.bond_packets_in;
                    max_in_path = Some(*key);
                }
                if state.bond_packets_out > max_out {
                    max_out = state.bond_packets_out;
                    max_out_path = Some(*key);
                }
                state.bond_packets_in = 0;
                state.bond_packets_out = 0;
            }
        }
        let (Some(max_in_path), Some(max_out_path)) = (max_in_path, max_out_path) else {
            return;
        };
        if max_in == 0 || max_out == 0 || max_in_path == max_out_path {
            return;
        }
        let utility = {
            let Some(peer) = self.peers.get(&address) else {
                return;
            };
            let Some(out) = peer.paths.get(&max_out_path) else {
                return;
            };
            let Some(incoming) = peer.paths.get(&max_in_path) else {
                return;
            };
            let mut utility = out.bond_score - incoming.bond_score;
            if out.bond_negotiated {
                utility -= 5000;
            }
            utility.clamp(i32::from(i16::MIN), i32::from(i16::MAX))
        };
        let local_address = self.identity().address();
        let (local_utility, tries, last_tx) = {
            let Some(peer) = self.peers.get_mut(&address) else {
                return;
            };
            peer.bond_local_utility = i16::try_from(utility).unwrap_or_default();
            if peer.bond_last_negotiation_tx.is_none_or(|tx| elapsed(now, tx) > BOND_NEGOTIATION_WINDOW) {
                peer.bond_negotiation_tries = 0;
            }
            (peer.bond_local_utility, peer.bond_negotiation_tries, peer.bond_last_negotiation_tx)
        };
        if tries < BOND_NEGOTIATION_TRIES && local_utility >= 0 {
            let Ok(mut packet) = Packet::new(address, local_address, Verb::PathNegotiation) else {
                return;
            };
            let _ = packet.append_u16(local_utility.cast_unsigned());
            if self.send_packet_via_path_locked(address, packet, true, max_out_path, false).is_ok() {
                if let Some(peer) = self.peers.get_mut(&address) {
                    peer.bond_negotiation_tries += 1;
                    peer.bond_last_negotiation_tx = Some(now);
                }
            }
        } else if tries >= BOND_NEGOTIATION_TRIES
            && utility == 0
            && last_tx.is_none_or(|tx| elapsed(now, tx) > 2 * BOND_OPTIMIZE_INTERVAL)
        {
            if let Some(peer) = self.peers.get_mut(&address) {
                peer.bond_negotiated = Some(max_in_path);
            }
        }
    }

    /// Applies one authenticated peer utility proposal.
    pub(crate) fn handle_path_negotiation_locked(
        &mut self,
        address: Address,
        key: PathKey,
        packet: &Packet,
        now: SystemTime,
    ) {
        let payload = packet.payload();
        let [low, high] = payload else {
            return;
        };
        let policy = self.bonding_policy_for_peer_locked(address);
        let window = BOND_NEGOTIATION_WINDOW / u32::try_from(MAX_PEER_PATHS).unwrap_or(u32::MAX);
        let (count, negotiated_at, local_utility) = {
            let Some(peer) = self.peers.get_mut(&address) else {
                return;
            };
            peer.bond_negotiation_rx_count =
                if peer.bond_last_negotiation_rx.is_some_and(|received| elapsed(now, received) <= window) {
                    peer.bond_negotiation_rx_count + 1
                } else {
                    0
                };
            peer.bond_last_negotiation_rx = Some(now);
            (peer.bond_negotiation_rx_count, peer.bond_last_negotiation, peer.bond_local_utility)
        };
        if count >= u16::try_from(MAX_PEER_PATHS * 2).unwrap_or(u16::MAX) {
            return;
        }
        if policy != BondingPolicy::ActiveBackup {
            return;
        }
        let options = self.bonding_options_for_peer_static(address);
        if options.link_select_method != BondingLinkSelectMethod::Optimize {
            return;
        }
        if negotiated_at.is_none() {
            return;
        }
        self.maintain_bond_locked(address, BondingPolicy::ActiveBackup, &options, now);
        let eligible =
            self.peers.get(&address).and_then(|peer| peer.paths.get(&key)).is_some_and(|state| state.bond_eligible);
        if !eligible {
            return;
        }
        let remote_utility = i16::from_be_bytes([*low, *high]);
        let local_address = self.identity().address();
        if remote_utility > local_utility || (remote_utility == local_utility && address > local_address) {
            if let Some(peer) = self.peers.get_mut(&address) {
                peer.bond_negotiated = Some(key);
                if let Some(state) = peer.paths.get_mut(&key) {
                    state.bond_negotiated = true;
                }
            }
        }
    }
}

#[must_use]
pub fn contains_path(paths: &[PathKey], wanted: PathKey) -> bool {
    paths.contains(&wanted)
}

/// Applies the configured bonding-link policy to `key`. An empty table is the implicit
/// single-socket link, which allows everything.
#[must_use]
pub fn bond_path_allowed(key: PathKey, options: &BondingOptions) -> bool {
    if options.links.is_empty() {
        return true;
    }
    bonding_link_for_socket(options, key.local_socket)
        .is_some_and(|link| !link.disabled && bonding_link_allows_address(link, key.endpoint.ip()))
}

/// The configured physical link owning `local_socket`, when the options table names one.
#[must_use]
pub fn bonding_link_for_socket(options: &BondingOptions, local_socket: i64) -> Option<&BondingLink> {
    options.links.iter().find(|link| link.local_sockets.contains(&local_socket))
}

/// The capacity of the link owning `local_socket`: the implicit single-socket link when the table
/// is empty, and none when the table does not name the socket.
fn bond_link_capacity(options: &BondingOptions, local_socket: i64) -> u32 {
    if options.links.is_empty() {
        return 1;
    }
    bonding_link_for_socket(options, local_socket).map_or(0, |link| link.capacity)
}

fn bonding_link_allows_address(link: &BondingLink, address: IpAddr) -> bool {
    match link.ip_preference {
        4 => address.is_ipv4(),
        6 => address.is_ipv6(),
        _ => true,
    }
}

/// Reports whether `address` matches a link's preferred family.
#[must_use]
pub fn bonding_link_prefers_address(link: &BondingLink, address: IpAddr) -> bool {
    match link.ip_preference {
        4 | 46 => address.is_ipv4(),
        6 | 64 => address.is_ipv6(),
        _ => true,
    }
}

/// Applies link roles and family preferences to `paths`.
#[must_use]
pub fn select_bonded_link_paths(paths: &[PathKey], options: &BondingOptions) -> Vec<PathKey> {
    if paths.is_empty() {
        return Vec::new();
    }
    let have_primary = paths
        .iter()
        .any(|key| bonding_link_for_socket(options, key.local_socket).is_none_or(|link| link.mode == BondingLinkMode::Primary));
    let mut by_link: Vec<(String, Vec<PathKey>)> = Vec::new();
    for key in paths {
        let link = bonding_link_for_socket(options, key.local_socket);
        let mode = link.map_or(BondingLinkMode::Primary, |link| link.mode);
        if (have_primary && mode == BondingLinkMode::Spare) || (!have_primary && mode != BondingLinkMode::Spare) {
            continue;
        }
        // An empty table is the implicit single-socket link, whose name is the socket itself.
        let name = link.map_or_else(
            || if options.links.is_empty() { key.local_socket.to_string() } else { String::new() },
            |link| link.name.clone(),
        );
        match by_link.iter_mut().find(|(known, _)| *known == name) {
            Some((_, candidates)) => candidates.push(*key),
            None => by_link.push((name, vec![*key])),
        }
    }
    let mut result = Vec::with_capacity(paths.len());
    for (_, mut candidates) in by_link {
        let Some(first) = candidates.first().copied() else {
            continue;
        };
        if let Some(link) = bonding_link_for_socket(options, first.local_socket) {
            if matches!(link.ip_preference, 46 | 64) {
                let preferred: Vec<PathKey> = candidates
                    .iter()
                    .copied()
                    .filter(|key| bonding_link_prefers_address(link, key.endpoint.ip()))
                    .collect();
                if !preferred.is_empty() {
                    candidates = preferred;
                }
            }
        }
        result.extend(candidates);
    }
    result
}

/// Normalizes `value` against the largest observed score.
#[must_use]
pub fn relative_bond_metric(value: f64, maximum: f64) -> f64 {
    if maximum <= 0.0 {
        return 0.0;
    }
    value / maximum
}

/// Maps a bounded impairment value to an exponential quality score.
#[must_use]
pub fn bond_metric_score(value: f64, maximum: f64) -> f64 {
    let value = value.clamp(0.0, maximum);
    (-4.0 * value / maximum).exp()
}

/// Selects a capacity-eligible path, falling back to the best quality.
#[must_use]
#[expect(
    clippy::indexing_slicing,
    reason = "the caller only passes non-empty path sets, and an empty set has no path to return"
)]
pub fn aware_bond_path(peer: &Peer, paths: &[PathKey], flow_id: i32) -> PathKey {
    let mut ordered = paths.to_vec();
    shuffle_bond_paths(&mut ordered);
    let capacity_gate = random_bond_fraction(flow_id);
    let mut best = ordered[0];
    let mut best_quality = -1.0;
    for key in &ordered {
        let Some(state) = peer.paths.get(key) else {
            continue;
        };
        if !state.bond_avoid && capacity_gate <= state.bond_capacity {
            return *key;
        }
        if state.bond_quality > best_quality {
            best = *key;
            best_quality = state.bond_quality;
        }
    }
    best
}

/// Converts a normalized path quality to the integer path score.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the quality score is normalized to [0, 1], so the rounded product with 255 stays inside the i32 range"
)]
fn bond_path_score(quality: f64) -> i32 {
    (quality * 255.0).round() as i32
}

/// Converts a normalized path quality to the `optimize` switch threshold.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the quality score is normalized to [0, 1], so the rounded product with 25.5 stays inside the i32 range"
)]
fn bond_switch_threshold(quality: f64) -> i32 {
    (quality * 255.0 * 0.10).ceil() as i32
}

fn shuffle_bond_paths(paths: &mut [PathKey]) {
    for index in (1..paths.len()).rev() {
        let random: u64 = rand::random();
        let swap = usize::try_from(random % (index as u64 + 1)).unwrap_or_default();
        paths.swap(index, swap);
    }
}

/// A random capacity gate in `[0, 1]`. The thread generator here cannot report
/// an entropy-source failure, so there is no flow-derived fallback.
fn random_bond_fraction(_flow_id: i32) -> f64 {
    f64::from(rand::random::<u8>()) / 255.0
}

/// Orders paths deterministically by socket and endpoint.
pub fn sort_bond_paths(paths: &mut [PathKey]) {
    paths.sort();
}

/// Reports whether any link names a failover target.
#[must_use]
pub fn bonding_has_failover_instructions(options: &BondingOptions) -> bool {
    options.links.iter().any(|link| !link.failover_to.is_empty())
}

/// Selects the first active path using link preferences.
#[must_use]
pub fn initial_active_backup_path(paths: &[PathKey], options: &BondingOptions) -> Option<PathKey> {
    let first = *paths.first()?;
    if options.links.is_empty() {
        return Some(first);
    }
    let mut primary = None;
    for key in paths {
        let link = bonding_link_for_socket(options, key.local_socket);
        if link.is_some_and(|link| link.mode != BondingLinkMode::Primary) {
            continue;
        }
        if primary.is_none() {
            primary = Some(*key);
        }
        if link.is_none_or(|link| bonding_link_prefers_address(link, key.endpoint.ip())) {
            return Some(*key);
        }
    }
    primary.or(Some(first))
}

/// Updates the rolling path latency and jitter estimates.
///
/// The estimator runs in the protocol's nanosecond domain, as the
/// `float64(time.Duration)` does, so the rounding of a millisecond value never
/// drifts into the reported estimate.
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the sample count and the nanosecond values stay far below 2^53, and both the mean and the jitter estimate are non-negative"
)]
pub fn record_qos_latency_sample(path: &mut PeerPathState, sample: Duration) {
    if path.qos_latency_samples.len() < QOS_LATENCY_WINDOW_SIZE {
        path.qos_latency_samples.push(sample);
    } else {
        if let Some(slot) = path.qos_latency_samples.get_mut(path.qos_latency_next) {
            *slot = sample;
        }
        path.qos_latency_next = (path.qos_latency_next + 1) % QOS_LATENCY_WINDOW_SIZE;
    }
    if path.qos_latency_samples.len() < QOS_LATENCY_MINIMUM {
        return;
    }
    let count = path.qos_latency_samples.len() as f64;
    let total: f64 = path.qos_latency_samples.iter().map(|value| value.as_nanos() as f64).sum();
    let mean = total / count;
    let squared_deviation: f64 = path
        .qos_latency_samples
        .iter()
        .map(|value| {
            let delta = value.as_nanos() as f64 - mean;
            delta * delta
        })
        .sum();
    path.bond_latency = Duration::from_nanos(mean as u64);
    path.jitter = Duration::from_nanos((squared_deviation / (count - 1.0)).sqrt() as u64);
}

/// Derives the bonding flow identifier from a frame's transport ports.
#[must_use]
pub fn frame_flow_id(ether_type: u16, payload: &[u8]) -> i32 {
    let Some((protocol, offset)) = frame_transport_offset(ether_type, payload) else {
        return NO_FLOW_ID;
    };
    if !matches!(protocol, 6 | 17 | 132 | 136) {
        return NO_FLOW_ID;
    }
    let Some(ports) = payload.get(offset..offset + 4) else {
        return NO_FLOW_ID;
    };
    let Some(source) = ports.first_chunk::<2>() else {
        return NO_FLOW_ID;
    };
    let Some(destination) = ports.last_chunk::<2>() else {
        return NO_FLOW_ID;
    };
    let source_port = u16::from_be_bytes(*source);
    let destination_port = u16::from_be_bytes(*destination);
    i32::from(source_port ^ destination_port ^ u16::from(protocol))
}

/// Locates the transport header in an IPv4 or IPv6 frame.
#[must_use]
pub fn frame_transport_offset(ether_type: u16, packet: &[u8]) -> Option<(u8, usize)> {
    match ether_type {
        crate::frame::ETHER_TYPE_IPV4 => {
            let version = *packet.first()?;
            if packet.len() < 20 || version >> 4 != 4 {
                return None;
            }
            let offset = usize::from(version & 0x0f) * 4;
            if offset < 20 || offset > packet.len() {
                return None;
            }
            Some((*packet.get(9)?, offset))
        }
        crate::frame::ETHER_TYPE_IPV6 => {
            let version = *packet.first()?;
            if packet.len() < 40 || version >> 4 != 6 {
                return None;
            }
            let mut protocol = *packet.get(6)?;
            let mut offset = 40;
            loop {
                match protocol {
                    0 | 43 | 60 | 135 => {
                        let next = *packet.get(offset)?;
                        let length = *packet.get(offset + 1)?;
                        offset += (usize::from(length) + 1) * 8;
                        protocol = next;
                    }
                    _ => return (offset <= packet.len()).then_some((protocol, offset)),
                }
                if offset > packet.len() {
                    return None;
                }
            }
        }
        _ => None,
    }
}

/// Derives a bonding flow identifier from a frame-bearing packet.
#[must_use]
pub fn packet_flow_id(packet: &Packet) -> i32 {
    let payload = packet.payload();
    match packet.verb() {
        Some(Verb::Frame) => {
            let Some(ether_type) = payload.get(8..10) else {
                return NO_FLOW_ID;
            };
            let Some(frame) = payload.get(10..) else {
                return NO_FLOW_ID;
            };
            frame_flow_id(u16::from_be_bytes(ether_type.try_into().unwrap_or_default()), frame)
        }
        Some(Verb::ExtFrame) => {
            let Some(ether_type) = payload.get(21..23) else {
                return NO_FLOW_ID;
            };
            let Some(frame) = payload.get(23..) else {
                return NO_FLOW_ID;
            };
            frame_flow_id(u16::from_be_bytes(ether_type.try_into().unwrap_or_default()), frame)
        }
        _ => NO_FLOW_ID,
    }
}

/// Extracts the network ID from verbs whose payload begins with one.
#[must_use]
pub fn packet_network_id(packet: &Packet) -> u64 {
    let payload = packet.payload();
    let Some(id) = payload.first_chunk::<8>() else {
        return 0;
    };
    match packet.verb() {
        Some(
            Verb::Frame
            | Verb::ExtFrame
            | Verb::NetworkConfigRequest
            | Verb::NetworkConfig
            | Verb::MulticastLike
            | Verb::MulticastGather
            | Verb::MulticastFrame,
        ) => u64::from_be_bytes(*id),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::identity::Identity;
    use crate::node::peer::PeerPathState;
    use crate::node::{MemoryStore, NodeError, NodeHost, PendingRequest};
    use crate::packet::Packet;
    use std::collections::BTreeSet;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Recorder {
        state: Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>,
    }

    impl Recorder {
        fn sent(&self) -> Vec<(SocketAddr, Vec<u8>)> {
            self.state.lock().expect("lock").clone()
        }
    }

    #[derive(Clone, Default)]
    struct BondHost {
        recorder: Recorder,
        fail: Arc<Mutex<Option<SocketAddr>>>,
    }

    impl NodeHost for BondHost {
        fn peer_identity(&self, _address: Address) -> Option<Identity> {
            None
        }

        fn send_wire(&mut self, _local_socket: i64, remote: SocketAddr, packet: Vec<u8>) -> Result<(), NodeError> {
            if self.fail.lock().expect("lock").as_ref() == Some(&remote) {
                return Err(NodeError::NoPath);
            }
            self.recorder.state.lock().expect("lock").push((remote, packet));
            Ok(())
        }

        fn request_whois(&mut self, _address: Address) {}

        fn announce_multicast(&mut self, _network_id: u64) {}

        fn trace_network_config_request(&mut self, _network_id: u64, _controller: Address) {}
    }

    fn key(socket: i64, address: &str) -> PathKey {
        PathKey::new(socket, address.parse().expect("test endpoint"))
    }

    /// A node with one peer whose paths the test seeds directly.
    fn bonded_node(policy: BondingPolicy, options: BondingOptions) -> (Node, Address, Recorder) {
        let host = BondHost::default();
        let recorder = host.recorder.clone();
        let mut node = Node::new(Identity::generate(), Box::new(MemoryStore::new()), Box::new(host));
        node.set_bonding_policy(policy);
        node.bonding_options = options;
        let identity = Identity::generate();
        let address = identity.address();
        let peer = node.new_peer_locked(identity, false).expect("peer");
        node.peers.insert(address, peer);
        (node, address, recorder)
    }

    fn seed_path(node: &mut Node, address: Address, path: PathKey, state: PeerPathState) {
        node.peers.get_mut(&address).expect("peer present").paths.insert(path, state);
    }

    fn path_state(now: SystemTime) -> PeerPathState {
        PeerPathState { last_receive: Some(now), ..Default::default() }
    }

    /// Refreshes only the receive clock, as the official tests do; the rest of
    /// the bonding state must survive across maintenance passes.
    fn set_last_receive(node: &mut Node, address: Address, path: PathKey, now: SystemTime) {
        node.peers.get_mut(&address).expect("peer present").paths.get_mut(&path).expect("path present").last_receive =
            Some(now);
    }

    #[test]
    fn bonding_selects_paths_per_policy() {
        let now = SystemTime::now();
        let first = key(0, "192.0.2.1:9993");
        let second = key(1, "198.51.100.1:9993");
        let (mut node, address, _) = bonded_node(BondingPolicy::Broadcast, default_bonding_options());
        let mut first_state = path_state(now);
        first_state.latency = Duration::from_millis(20);
        let mut second_state = path_state(now);
        second_state.latency = Duration::from_millis(30);
        seed_path(&mut node, address, first, first_state);
        seed_path(&mut node, address, second, second_state);

        let selected = node.bonded_paths_locked(address, Verb::Frame, NO_FLOW_ID, 1, now);
        assert_eq!(selected.as_slice().len(), 2);
        let selected = node.bonded_paths_locked(address, Verb::Echo, NO_FLOW_ID, 1, now);
        assert_eq!(selected.as_slice().len(), 1);

        node.set_bonding_policy(BondingPolicy::None);
        node.peer_paths.insert(
            address,
            crate::node::PeerPathConfig {
                address,
                try_endpoints: Vec::new(),
                blacklist: Vec::new(),
                bonding_policy: BondingPolicy::Broadcast,
                bonding_policy_set: true,
                bonding_options: None,
            },
        );
        let selected = node.bonded_paths_locked(address, Verb::Frame, NO_FLOW_ID, 1, now);
        assert_eq!(selected.as_slice().len(), 2, "peer-specific policy wins");
        node.peer_paths.clear();

        node.set_bonding_policy(BondingPolicy::BalanceXor);
        let selected = node.bonded_paths_locked(address, Verb::Frame, 1234, 1, now);
        let again = node.bonded_paths_locked(address, Verb::Frame, 1234, 2, now + Duration::from_secs(1));
        assert_eq!(selected.as_slice(), again.as_slice(), "balance-xor keeps flow affinity");

        node.set_bonding_policy(BondingPolicy::BalanceRoundRobin);
        if let Some(peer) = node.peers.get_mut(&address) {
            peer.bond_rr_index = 0;
            peer.bond_rr_packets = 0;
        }
        for packet_id in 0..BOND_ROUND_ROBIN_PACKETS as u64 {
            let selected = node.bonded_paths_locked(address, Verb::Frame, NO_FLOW_ID, packet_id, now);
            assert_eq!(selected.as_slice(), &[first], "packet {packet_id} stays on the first link");
        }
        let selected = node.bonded_paths_locked(address, Verb::Frame, NO_FLOW_ID, 65, now);
        assert_eq!(selected.as_slice(), &[second], "the run rotates after {BOND_ROUND_ROBIN_PACKETS} packets");
    }

    #[test]
    fn active_backup_applies_failover_hysteresis() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let first = key(0, "192.0.2.1:9993");
        let second = key(1, "198.51.100.1:9993");
        let mut options = default_bonding_options();
        options.up_delay = Duration::from_secs(2);
        options.down_delay = Duration::from_secs(1);
        options.link_select_method = BondingLinkSelectMethod::Failure;
        let (mut node, address, _) = bonded_node(BondingPolicy::ActiveBackup, options.clone());
        let mut first_state = path_state(now);
        first_state.latency = Duration::from_millis(1);
        let mut second_state = path_state(now);
        second_state.latency = Duration::from_millis(20);
        seed_path(&mut node, address, first, first_state);
        seed_path(&mut node, address, second, second_state);

        let selected = node.bonded_paths_locked(address, Verb::Frame, NO_FLOW_ID, 1, now);
        assert_eq!(selected.as_slice(), &[first], "the lowest-latency path opens active");

        let stable = now + Duration::from_secs(16);
        set_last_receive(&mut node, address, first, stable);
        set_last_receive(&mut node, address, second, stable);
        node.maintain_bond_locked(address, BondingPolicy::ActiveBackup, &options, stable);

        let failed = stable + options.failover_interval + options.down_delay;
        set_last_receive(&mut node, address, second, failed);
        let selected = node.bonded_paths_locked(address, Verb::Frame, NO_FLOW_ID, 2, failed);
        assert_eq!(selected.as_slice(), &[second], "a silent active path fails over");

        let recovered = failed + Duration::from_secs(1);
        set_last_receive(&mut node, address, first, recovered);
        node.maintain_bond_locked(address, BondingPolicy::ActiveBackup, &options, recovered);
        assert!(!node.peers[&address].paths[&first].bond_eligible, "a recovered path waits out its up-delay");
        let recovered = recovered + options.up_delay;
        set_last_receive(&mut node, address, first, recovered);
        node.maintain_bond_locked(address, BondingPolicy::ActiveBackup, &options, recovered);
        let peer = &node.peers[&address];
        assert!(peer.paths[&first].bond_eligible);
        assert_eq!(peer.bond_active, Some(second), "failure mode keeps the backup");
    }

    #[test]
    fn active_backup_failure_selects_the_highest_scored_path() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let active = key(0, "192.0.2.1:9993");
        let poor = key(1, "198.51.100.1:9993");
        let best = key(2, "203.0.113.1:9993");
        let mut options = default_bonding_options();
        options.link_select_method = BondingLinkSelectMethod::Failure;
        let (mut node, address, _) = bonded_node(BondingPolicy::ActiveBackup, options.clone());
        seed_path(&mut node, address, active, path_state(now));
        let mut poor_state = path_state(now);
        poor_state.bond_latency = options.quality.latency_max;
        seed_path(&mut node, address, poor, poor_state);
        seed_path(&mut node, address, best, path_state(now));
        node.maintain_bond_locked(address, BondingPolicy::ActiveBackup, &options, now);
        assert_eq!(node.peers[&address].bond_active, Some(active));

        let later = now + BOND_OPTIMIZE_INTERVAL + options.failover_interval;
        set_last_receive(&mut node, address, poor, later);
        set_last_receive(&mut node, address, best, later);
        node.maintain_bond_locked(address, BondingPolicy::ActiveBackup, &options, later);
        assert_eq!(
            node.peers[&address].bond_active,
            Some(best),
            "a failed active path selects the strongest eligible score"
        );
    }

    /// The link lookup runs per packet, so it must borrow the configured link instead of copying it.
    #[test]
    fn the_link_lookup_borrows_the_configured_link() {
        let (options, _, _) = role_options(BondingLinkSelectMethod::Always);
        let configured = &options.links[0].name;

        let link = bonding_link_for_socket(&options, 0).expect("socket 0 owns a configured link");

        assert!(std::ptr::eq(configured, &link.name), "the lookup must borrow the configured link");
    }

    fn role_options(method: BondingLinkSelectMethod) -> (BondingOptions, PathKey, PathKey) {
        let options = normalize_bonding_options(BondingOptionsInput {
            link_select_method: Some(method),
            links: vec![
                BondingLink {
                    name: "primary".to_owned(),
                    local_sockets: vec![0],
                    capacity: 0,
                    ip_preference: 0,
                    mode: BondingLinkMode::Primary,
                    failover_to: "spare".to_owned(),
                    disabled: false,
                },
                BondingLink {
                    name: "spare".to_owned(),
                    local_sockets: vec![1],
                    capacity: 0,
                    ip_preference: 0,
                    mode: BondingLinkMode::Spare,
                    failover_to: String::new(),
                    disabled: false,
                },
            ],
            ..Default::default()
        })
        .expect("valid links");
        (options, key(0, "192.0.2.1:9993"), key(1, "198.51.100.1:9993"))
    }

    #[test]
    fn active_backup_always_reselects_the_primary_link() {
        let now = SystemTime::now();
        let (options, primary, spare) = role_options(BondingLinkSelectMethod::Always);
        let (mut node, address, _) = bonded_node(BondingPolicy::ActiveBackup, options.clone());
        seed_path(&mut node, address, primary, path_state(now));
        seed_path(&mut node, address, spare, path_state(now));
        node.maintain_bond_locked(address, BondingPolicy::ActiveBackup, &options, now);
        assert_eq!(node.peers[&address].bond_active, Some(primary));

        let later = now + BOND_OPTIMIZE_INTERVAL + options.failover_interval;
        set_last_receive(&mut node, address, spare, later);
        node.maintain_bond_locked(address, BondingPolicy::ActiveBackup, &options, later);
        assert_eq!(node.peers[&address].bond_active, Some(spare), "a failed primary uses the spare");

        let recovered = later + Duration::from_secs(1);
        set_last_receive(&mut node, address, primary, recovered);
        set_last_receive(&mut node, address, spare, recovered);
        node.maintain_bond_locked(address, BondingPolicy::ActiveBackup, &options, recovered);
        assert_eq!(node.peers[&address].bond_active, Some(primary), "recovered primary is reselected");
    }

    #[test]
    fn explicit_failover_reselects_the_primary_while_optimizing() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let (options, primary, spare) = role_options(BondingLinkSelectMethod::Optimize);
        let (mut node, address, _) = bonded_node(BondingPolicy::ActiveBackup, options.clone());
        let mut primary_state = path_state(now);
        primary_state.bond_latency = options.quality.latency_max;
        seed_path(&mut node, address, primary, primary_state);
        seed_path(&mut node, address, spare, path_state(now));
        node.maintain_bond_locked(address, BondingPolicy::ActiveBackup, &options, now);
        assert_eq!(node.peers[&address].bond_active, Some(primary));

        let failed = now + BOND_OPTIMIZE_INTERVAL + options.failover_interval;
        set_last_receive(&mut node, address, spare, failed);
        node.maintain_bond_locked(address, BondingPolicy::ActiveBackup, &options, failed);
        assert_eq!(node.peers[&address].bond_active, Some(spare), "the failed primary fails over");

        let recovered = failed + BOND_OPTIMIZE_INTERVAL + Duration::from_secs(1);
        set_last_receive(&mut node, address, primary, recovered);
        set_last_receive(&mut node, address, spare, recovered);
        node.maintain_bond_locked(address, BondingPolicy::ActiveBackup, &options, recovered);
        assert_eq!(
            node.peers[&address].bond_active,
            Some(primary),
            "an explicit failover chain outranks the quality threshold"
        );
    }

    #[test]
    fn custom_round_robin_prefers_the_configured_family() {
        let now = SystemTime::now();
        let v4 = key(0, "192.0.2.1:9993");
        let v6 = key(1, "[2001:db8::1]:9993");
        let spare = key(2, "198.51.100.1:9993");
        let options = normalize_bonding_options(BondingOptionsInput {
            packets_per_link: Some(1),
            links: vec![
                BondingLink {
                    name: "primary".to_owned(),
                    local_sockets: vec![0, 1],
                    capacity: 0,
                    ip_preference: 46,
                    mode: BondingLinkMode::Primary,
                    failover_to: String::new(),
                    disabled: false,
                },
                BondingLink {
                    name: "spare".to_owned(),
                    local_sockets: vec![2],
                    capacity: 0,
                    ip_preference: 0,
                    mode: BondingLinkMode::Spare,
                    failover_to: String::new(),
                    disabled: false,
                },
            ],
            ..Default::default()
        })
        .expect("valid links");
        let (mut node, address, _) = bonded_node(BondingPolicy::BalanceRoundRobin, options.clone());
        seed_path(&mut node, address, v4, path_state(now));
        seed_path(&mut node, address, v6, path_state(now));
        seed_path(&mut node, address, spare, path_state(now));
        for packet_id in 0..3u64 {
            let selected = node.bonded_paths_locked(address, Verb::Frame, NO_FLOW_ID, packet_id, now);
            assert_eq!(selected.as_slice(), &[v4], "selection {packet_id} uses the preferred family");
        }
    }

    #[test]
    fn custom_round_robin_honours_the_run_length() {
        let now = SystemTime::now();
        let first = key(0, "192.0.2.1:9993");
        let second = key(1, "198.51.100.1:9993");
        let options =
            normalize_bonding_options(BondingOptionsInput { packets_per_link: Some(1), ..Default::default() })
                .expect("valid options");
        let (mut node, address, _) = bonded_node(BondingPolicy::BalanceRoundRobin, options);
        seed_path(&mut node, address, first, path_state(now));
        seed_path(&mut node, address, second, path_state(now));
        let selected = node.bonded_paths_locked(address, Verb::Frame, NO_FLOW_ID, 1, now);
        assert_eq!(selected.as_slice(), &[first]);
        let selected = node.bonded_paths_locked(address, Verb::Frame, NO_FLOW_ID, 2, now);
        assert_eq!(selected.as_slice(), &[second]);
    }

    #[test]
    fn balance_aware_weights_link_capacity() {
        let now = SystemTime::now();
        let slow = key(0, "192.0.2.1:9993");
        let fast = key(1, "198.51.100.1:9993");
        let options = normalize_bonding_options(BondingOptionsInput {
            links: vec![
                BondingLink {
                    name: "slow".to_owned(),
                    local_sockets: vec![0],
                    capacity: 1,
                    ip_preference: 0,
                    mode: BondingLinkMode::Primary,
                    failover_to: String::new(),
                    disabled: false,
                },
                BondingLink {
                    name: "fast".to_owned(),
                    local_sockets: vec![1],
                    capacity: 3,
                    ip_preference: 0,
                    mode: BondingLinkMode::Primary,
                    failover_to: String::new(),
                    disabled: false,
                },
            ],
            ..Default::default()
        })
        .expect("valid links");
        let (mut node, address, _) = bonded_node(BondingPolicy::BalanceAware, options.clone());
        let mut slow_state = path_state(now);
        slow_state.bond_latency = Duration::from_millis(1);
        let mut fast_state = path_state(now);
        fast_state.bond_latency = Duration::from_millis(1);
        seed_path(&mut node, address, slow, slow_state);
        seed_path(&mut node, address, fast, fast_state);

        let mut slow_count = 0;
        let mut fast_count = 0;
        let mut slow_flow = 0;
        for flow_id in 1..=512i32 {
            let selected = node.bonded_paths_locked(address, Verb::Frame, flow_id, flow_id as u64, now);
            match selected.as_slice() {
                [path] if *path == slow => {
                    slow_count += 1;
                    if slow_flow == 0 {
                        slow_flow = flow_id;
                    }
                }
                [path] if *path == fast => fast_count += 1,
                other => panic!("unexpected selection {other:?}"),
            }
        }
        assert!(fast_count > 2 * slow_count, "capacity weighting selected slow={slow_count} fast={fast_count}");

        let mut slow_state = node.peers[&address].paths[&slow].clone();
        slow_state.bond_latency = options.quality.latency_max + Duration::from_millis(1);
        seed_path(&mut node, address, slow, slow_state);
        let selected = node.bonded_paths_locked(address, Verb::Frame, slow_flow, 1000, now + BOND_MAINTENANCE_PERIOD);
        assert_eq!(selected.as_slice(), &[fast], "a flow on an avoided path is reassigned");
    }

    #[test]
    fn frame_flow_ids_track_transport_ports() {
        let mut ipv4 = vec![0u8; 24];
        ipv4[0] = 0x45;
        ipv4[9] = 17;
        ipv4[20..24].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(frame_flow_id(crate::frame::ETHER_TYPE_IPV4, &ipv4), i32::from(0x1234u16 ^ 0x5678 ^ 17));

        let mut ipv6 = vec![0u8; 52];
        ipv6[0] = 0x60;
        ipv6[6] = 0;
        ipv6[40] = 6;
        ipv6[48..52].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(frame_flow_id(crate::frame::ETHER_TYPE_IPV6, &ipv6), i32::from(0x1234u16 ^ 0x5678 ^ 6));

        let mut fragmented = vec![0u8; 56];
        fragmented[0] = 0x60;
        fragmented[6] = 44;
        fragmented[40] = 17;
        fragmented[48..52].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(frame_flow_id(crate::frame::ETHER_TYPE_IPV6, &fragmented), NO_FLOW_ID);

        let mut mobility = vec![0u8; 52];
        mobility[0] = 0x60;
        mobility[6] = 135;
        mobility[40] = 17;
        mobility[48..52].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(frame_flow_id(crate::frame::ETHER_TYPE_IPV6, &mobility), i32::from(0x1234u16 ^ 0x5678 ^ 17));
    }

    #[test]
    fn an_even_incoming_packet_id_still_learns_its_flow() {
        let now = SystemTime::now();
        let path = key(1, "198.51.100.55:9993");
        let (mut node, address, _) = bonded_node(BondingPolicy::BalanceXor, default_bonding_options());
        seed_path(&mut node, address, path, path_state(now));
        let mut packet = Packet::new(Address::new(1), Address::new(2), Verb::Frame).expect("packet");
        packet.bytes_mut()[7] &= !1;
        node.record_incoming_bond_packet_locked(address, path, &packet, 1234, now);
        let peer = &node.peers[&address];
        assert_eq!(peer.bond_flows[&1234].path, path);
        assert!(peer.paths[&path].qos_incoming.is_empty(), "even IDs are not sampled");
    }

    #[test]
    fn a_round_robin_arrival_records_the_inbound_flow() {
        let now = SystemTime::now();
        let path = key(1, "198.51.100.56:9993");
        let (mut node, address, _) = bonded_node(BondingPolicy::BalanceRoundRobin, default_bonding_options());
        seed_path(&mut node, address, path, path_state(now));
        let packet = Packet::new(Address::new(1), Address::new(2), Verb::Frame).expect("packet");
        node.record_incoming_bond_packet_locked(address, path, &packet, 1234, now);
        let flow = node.peers[&address].bond_flows[&1234];
        assert_eq!(flow.path, path);
        assert_eq!(flow.last_active, now);
    }

    #[test]
    fn a_qos_measurement_updates_the_path_estimate() {
        let now = SystemTime::now();
        let path = key(0, "192.0.2.1:9993");
        let (mut node, address, _) = bonded_node(BondingPolicy::BalanceAware, default_bonding_options());
        let mut state = path_state(now);
        for (index, round_trip) in [40u64, 60, 80, 100].into_iter().enumerate() {
            state.qos_outgoing.insert(123 + index as u64, now - Duration::from_millis(round_trip));
        }
        seed_path(&mut node, address, path, state);
        let mut packet = Packet::new(Address::new(1), Address::new(2), Verb::QosMeasurement).expect("packet");
        for index in 0..4u64 {
            let mut record = [0u8; 10];
            record[..8].copy_from_slice(&(123 + index).to_le_bytes());
            record[8..].copy_from_slice(&20u16.to_le_bytes());
            packet.append(&record).expect("record");
        }
        node.handle_qos_measurement_locked(address, path, &packet, now);
        let state = &node.peers[&address].paths[&path];
        assert_eq!(state.bond_latency, Duration::from_millis(25));
        assert_eq!(state.jitter, Duration::from_nanos(12_909_944), "jitter is the sample standard deviation");
        assert_eq!(state.last_qos_receive, Some(now));
        assert!(state.qos_outgoing.is_empty(), "acknowledged samples are dropped");
    }

    #[test]
    fn an_expired_qos_record_decays_loss_by_separate_multiply_and_add() {
        let now = SystemTime::now();
        let path = key(0, "192.0.2.1:9993");
        let (mut node, address, _) = bonded_node(BondingPolicy::BalanceAware, default_bonding_options());
        let mut state = path_state(now);
        state.loss = 0.1;
        state.qos_outgoing.insert(7, now - Duration::from_secs(60));
        seed_path(&mut node, address, path, state);

        node.expire_qos_records_locked(address, path, now, Duration::from_secs(3));

        assert_eq!(node.peers[&address].paths[&path].loss, 0.1 * 0.95 + 0.05, "the terms multiply and add separately");
    }

    #[test]
    fn path_quality_sums_its_weighted_products_in_the_reference_order() {
        let now = SystemTime::now();
        let first = key(0, "192.0.2.1:9993");
        let second = key(1, "198.51.100.1:9993");
        let inputs =
            [(first, 0.250f64, 0.050f64, 0.0005f64, 0.00003f64), (second, 0.450f64, 0.080f64, 0.0005f64, 0.00005f64)];
        let mut options = default_bonding_options();
        options.quality = BondingQuality {
            latency_weight: 0.5,
            jitter_weight: 0.3,
            packet_loss_weight: 0.15,
            packet_error_weight: 0.05,
            ..BondingQuality::defaults()
        };
        let quality = options.quality;
        let (mut node, address, _) = bonded_node(BondingPolicy::BalanceAware, options.clone());
        for (path, latency, jitter, loss, packet_error) in inputs {
            let mut state = path_state(now);
            state.bond_latency = Duration::from_secs_f64(latency);
            state.jitter = Duration::from_secs_f64(jitter);
            state.loss = loss;
            state.packet_error = packet_error;
            seed_path(&mut node, address, path, state);
        }

        let metrics: Vec<[f64; 4]> = inputs
            .iter()
            .map(|(_, latency, jitter, loss, packet_error)| {
                [
                    bond_metric_score(*latency, quality.latency_max.as_secs_f64()),
                    bond_metric_score(*jitter, quality.jitter_max.as_secs_f64()),
                    bond_metric_score(*loss, quality.packet_loss_max),
                    bond_metric_score(*packet_error, quality.packet_error_max),
                ]
            })
            .collect();
        let maxima = [0, 1, 2, 3].map(|index| metrics[0][index].max(metrics[1][index]));
        let reference: Vec<f64> = metrics
            .iter()
            .map(|metric| {
                quality.latency_weight * relative_bond_metric(metric[0], maxima[0])
                    + quality.jitter_weight * relative_bond_metric(metric[1], maxima[1])
                    + quality.packet_loss_weight * relative_bond_metric(metric[2], maxima[2])
                    + quality.packet_error_weight * relative_bond_metric(metric[3], maxima[3])
            })
            .collect();
        let total: f64 = reference.iter().sum();

        node.estimate_bond_quality_locked(address, &[first, second], &options);

        assert_eq!(node.peers[&address].paths[&first].bond_quality, reference[0] / total);
        assert_eq!(node.peers[&address].paths[&second].bond_quality, reference[1] / total);
    }

    #[test]
    fn qos_latency_keeps_the_last_64_samples() {
        let mut state = PeerPathState::default();
        for i in 0..=QOS_LATENCY_WINDOW_SIZE as u32 {
            record_qos_latency_sample(&mut state, Duration::from_millis(u64::from(i)));
        }
        assert_eq!(state.qos_latency_samples.len(), QOS_LATENCY_WINDOW_SIZE);
        assert_eq!(state.bond_latency, Duration::from_micros(32_500));
        let expected_jitter = 18_618_987u128;
        let jitter = state.jitter.as_nanos();
        assert!(jitter.abs_diff(expected_jitter) <= 1_000, "jitter was {:?}", state.jitter);
    }

    #[test]
    fn balance_aware_normalizes_every_metric_across_the_bond() {
        let now = SystemTime::now();
        let first = key(0, "192.0.2.10:9993");
        let second = key(1, "198.51.100.10:9993");
        let options = default_bonding_options();
        let (mut node, address, _) = bonded_node(BondingPolicy::BalanceAware, options.clone());
        let mut first_state = path_state(now);
        first_state.loss = 0.1;
        let mut second_state = path_state(now);
        second_state.bond_latency = Duration::from_millis(100);
        second_state.loss = 0.05;
        seed_path(&mut node, address, first, first_state);
        seed_path(&mut node, address, second, second_state);
        let mut quality_options = options;
        quality_options.quality = BondingQuality {
            latency_max: Duration::from_millis(100),
            jitter_max: Duration::from_millis(1),
            packet_loss_max: 0.1,
            packet_error_max: 0.1,
            latency_weight: 0.5,
            jitter_weight: 0.0,
            packet_loss_weight: 0.5,
            packet_error_weight: 0.0,
        };
        node.estimate_bond_quality_locked(address, &[first, second], &quality_options);
        let peer = &node.peers[&address];
        assert!(
            (0.52..0.54).contains(&peer.paths[&first].bond_quality),
            "first-path quality was {}",
            peer.paths[&first].bond_quality
        );
        assert!(
            (0.46..0.48).contains(&peer.paths[&second].bond_quality),
            "second-path quality was {}",
            peer.paths[&second].bond_quality
        );
    }

    #[test]
    fn bond_quality_excludes_unbonded_spare_paths() {
        let now = SystemTime::now();
        let first = key(1, "192.0.2.20:9993");
        let second = key(2, "198.51.100.20:9993");
        let spare = key(3, "203.0.113.20:9993");
        let mut options = default_bonding_options();
        options.links = vec![
            BondingLink {
                name: "first".to_owned(),
                local_sockets: vec![1],
                capacity: 1,
                ip_preference: 0,
                mode: BondingLinkMode::Primary,
                failover_to: String::new(),
                disabled: false,
            },
            BondingLink {
                name: "second".to_owned(),
                local_sockets: vec![2],
                capacity: 1,
                ip_preference: 0,
                mode: BondingLinkMode::Primary,
                failover_to: String::new(),
                disabled: false,
            },
            BondingLink {
                name: "spare".to_owned(),
                local_sockets: vec![3],
                capacity: 1,
                ip_preference: 0,
                mode: BondingLinkMode::Spare,
                failover_to: String::new(),
                disabled: false,
            },
        ];
        let (mut node, address, _) = bonded_node(BondingPolicy::BalanceAware, options.clone());
        seed_path(&mut node, address, first, path_state(now));
        seed_path(&mut node, address, second, path_state(now));
        seed_path(&mut node, address, spare, path_state(now));
        let paths = node.maintain_bond_locked(address, BondingPolicy::BalanceAware, &options, now);
        assert_eq!(paths.len(), 2);
        assert!(!paths.contains(&spare), "a spare path is not bonded");
        let peer = &node.peers[&address];
        let total = peer.paths[&first].bond_quality + peer.paths[&second].bond_quality;
        assert!((total - 1.0).abs() < 1e-9, "bonded quality total was {total}");
    }

    #[test]
    fn an_all_avoided_bond_falls_back_to_the_best_quality() {
        let first = key(0, "192.0.2.11:9993");
        let second = key(1, "198.51.100.11:9993");
        let (mut node, address, _) = bonded_node(BondingPolicy::BalanceAware, default_bonding_options());
        let mut first_state = path_state(SystemTime::now());
        first_state.bond_avoid = true;
        first_state.bond_capacity = 0.25;
        first_state.bond_quality = 0.8;
        let mut second_state = path_state(SystemTime::now());
        second_state.bond_avoid = true;
        second_state.bond_capacity = 1.0;
        second_state.bond_quality = 0.2;
        seed_path(&mut node, address, first, first_state);
        seed_path(&mut node, address, second, second_state);
        for flow_id in 0..32 {
            let peer = &node.peers[&address];
            assert_eq!(
                aware_bond_path(peer, &[first, second], flow_id),
                first,
                "the highest-quality path is the fallback"
            );
        }
    }

    #[test]
    fn a_qos_measurement_packet_carries_native_order_records() {
        let (mut node, address, recorder) = bonded_node(BondingPolicy::BalanceXor, default_bonding_options());
        let now = SystemTime::now();
        let path = key(0, "192.0.2.1:9993");
        let mut state = path_state(now);
        state.qos_incoming.insert(123, now - Duration::from_millis(20));
        seed_path(&mut node, address, path, state);
        node.send_qos_measurements_locked(address, now);
        let sent = recorder.sent();
        assert_eq!(sent.len(), 1, "one measurement was sent");
        let key_material = node.identity().agree(&node.peers[&address].identity).expect("shared key");
        let mut packet = Packet::parse(&sent[0].1).expect("parses");
        packet.dearmor(&key_material).expect("dearmors");
        assert_eq!(packet.verb(), Some(Verb::QosMeasurement));
        let payload = packet.payload();
        assert_eq!(payload.len(), 10);
        assert_eq!(u64::from_le_bytes(payload[..8].try_into().unwrap()), 123);
        assert_eq!(u16::from_le_bytes(payload[8..].try_into().unwrap()), 20);
    }

    #[test]
    fn a_qos_holding_time_past_the_u16_range_saturates_instead_of_wrapping() {
        // The default 5s failover interval expires records older than 30s, so the
        // saturating branch needs a wide interval to be exercised at all.
        let options = BondingOptions { failover_interval: Duration::from_secs(60), ..default_bonding_options() };
        let (mut node, address, recorder) = bonded_node(BondingPolicy::BalanceXor, options);
        let now = SystemTime::now();
        let path = key(0, "192.0.2.1:9993");
        let mut state = path_state(now);
        state.qos_incoming.insert(1, now - Duration::from_millis(1_000));
        state.qos_incoming.insert(2, now - Duration::from_millis(70_000));
        seed_path(&mut node, address, path, state);
        node.send_qos_measurements_locked(address, now);
        let sent = recorder.sent();
        assert_eq!(sent.len(), 1, "one measurement was sent");
        let key_material = node.identity().agree(&node.peers[&address].identity).expect("shared key");
        let mut packet = Packet::parse(&sent[0].1).expect("parses");
        packet.dearmor(&key_material).expect("dearmors");
        let payload = packet.payload();
        assert_eq!(payload.len(), 20, "both held records are reported");
        assert_eq!(u64::from_le_bytes(payload[..8].try_into().unwrap()), 1, "records are ordered by packet id");
        assert_eq!(u16::from_le_bytes(payload[8..10].try_into().unwrap()), 1_000);
        assert_eq!(u64::from_le_bytes(payload[10..18].try_into().unwrap()), 2);
        assert_eq!(
            u16::from_le_bytes(payload[18..].try_into().unwrap()),
            u16::MAX,
            "70s of holding saturates; truncation would have wrapped it to 4464"
        );
    }

    #[test]
    fn an_excluded_bond_path_does_not_participate_in_monitoring() {
        let options = normalize_bonding_options(BondingOptionsInput {
            links: vec![BondingLink {
                name: "allowed".to_owned(),
                local_sockets: vec![1],
                capacity: 0,
                ip_preference: 0,
                mode: BondingLinkMode::Primary,
                failover_to: String::new(),
                disabled: false,
            }],
            ..Default::default()
        })
        .expect("valid links");
        let (mut node, address, recorder) = bonded_node(BondingPolicy::BalanceXor, options.clone());
        let now = SystemTime::now();
        let allowed = key(1, "192.0.2.1:9993");
        let excluded = key(2, "198.51.100.1:9993");
        let mut allowed_state = path_state(now);
        allowed_state.qos_incoming.insert(1, now - Duration::from_millis(1));
        let mut excluded_state = path_state(now);
        excluded_state.qos_incoming.insert(3, now - Duration::from_millis(1));
        seed_path(&mut node, address, allowed, allowed_state);
        seed_path(&mut node, address, excluded, excluded_state);
        if let Some(peer) = node.peers.get_mut(&address) {
            peer.protocol = crate::node::PROTOCOL_VERSION;
            peer.last_receive = Some(now);
        }
        let packet = Packet::new(node.identity().address(), address, Verb::Frame).expect("packet");
        node.record_incoming_bond_packet_locked(address, excluded, &packet, NO_FLOW_ID, now);
        node.record_outgoing_bond_packet_locked(address, excluded, 5, Verb::Frame, now);
        node.send_qos_measurements_locked(address, now);
        assert!(
            node.peers[&address].paths[&excluded].qos_outgoing.is_empty(),
            "an excluded path records no outgoing samples"
        );
        let sent = recorder.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, allowed.endpoint);
    }

    #[test]
    fn a_broadcast_send_retains_only_the_successful_packet_ids() {
        let failing = "198.51.100.10:9993".parse::<SocketAddr>().expect("endpoint");
        let host = BondHost::default();
        let recorder = host.recorder.clone();
        *host.fail.lock().expect("lock") = Some(failing);
        let mut node = Node::new(Identity::generate(), Box::new(MemoryStore::new()), Box::new(host));
        node.set_bonding_policy(BondingPolicy::Broadcast);
        node.set_physical_paths(vec![crate::node::PhysicalPathConfig {
            network: "192.0.2.0/24".parse().expect("prefix"),
            trusted_path_id: 7,
            mtu: 0,
            blacklist: false,
        }]);
        let identity = Identity::generate();
        let address = identity.address();
        let peer = node.new_peer_locked(identity, false).expect("peer");
        node.peers.insert(address, peer);
        if let Some(peer) = node.peers.get_mut(&address) {
            peer.protocol = crate::node::PROTOCOL_VERSION;
        }
        let now = SystemTime::now();
        let failing_path = key(2, &failing.to_string());
        let successful_path = key(1, "192.0.2.10:9993");
        node.add_peer_path_locked(address, failing_path, path_state(now), now);
        node.add_peer_path_locked(address, successful_path, path_state(now), now);
        assert_eq!(node.active_direct_peer_paths(&node.peers[&address], now).len(), 2);

        let packet = Packet::new(address, node.identity().address(), Verb::Frame).expect("packet");
        let request = PendingRequest {
            verb: Verb::Frame,
            peer: address,
            network_id: 0,
            sent_at: Some(now),
            slot: 0,
            generation: 0,
            path: None,
            priority: 0,
            reply_paths: None,
        };
        node.pending.add(packet.packet_id(), request).expect("request tracked");
        node.send_packet_locked(address, packet, true).expect("one copy is sent");
        let successful_id = u64::from_be_bytes(recorder.sent()[0].1[..8].try_into().unwrap());
        assert_ne!(successful_id, 0);
        assert_eq!(node.pending.len(), 1, "only the successful copy is tracked");
        let tracked = node.pending.get(successful_id).expect("tracked under its sent ID");
        assert_eq!(tracked.verb, Verb::Frame);
        let remaining = tracked.reply_paths.clone().expect("broadcast reply paths");
        assert_eq!(remaining, BTreeSet::from([successful_path]));
    }

    #[test]
    fn a_protocol_error_does_not_consume_a_broadcast_expectation() {
        let (mut node, address, _) = bonded_node(BondingPolicy::None, default_bonding_options());
        let first = key(1, "192.0.2.30:9993");
        let second = key(2, "198.51.100.30:9993");
        let request = Packet::new(address, node.identity().address(), Verb::ExtFrame).expect("packet");
        let request_id = request.packet_id();
        let mut reply = Packet::new(node.identity().address(), address, Verb::Error).expect("reply");
        let _ = reply.append_u8(Verb::ExtFrame.bits());
        let _ = reply.append_u64(request_id);
        let _ = reply.append_u8(0x01);
        node.pending
            .add(
                request_id,
                PendingRequest {
                    verb: Verb::ExtFrame,
                    peer: address,
                    network_id: 0,
                    sent_at: Some(SystemTime::now()),
                    slot: 0,
                    generation: 0,
                    path: None,
                    priority: 0,
                    reply_paths: Some(BTreeSet::from([first, second])),
                },
            )
            .expect("tracked");
        let now = SystemTime::now();
        node.handle_error_locked(address, &reply, now).expect("applies");
        node.handle_error_locked(address, &reply, now).expect("applies");
        let tracked = node.pending.get(request_id).expect("still tracked");
        assert_eq!(
            tracked.reply_paths.clone().expect("reply paths").len(),
            2,
            "a protocol error leaves the broadcast expectation alone"
        );
    }
}

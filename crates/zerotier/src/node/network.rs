//! Joined-network state: the controller configuration a network holds, the
//! chunk assemblies that build it, and the persistence naming it uses.

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use crate::address::{is_ad_hoc_network_id, Address};
use crate::capability::Capability;
use crate::frame::{Frame, MulticastGroup};
use crate::mac::Mac;
use crate::membership::CertificateOfMembership;
use crate::network_config::NetworkConfigData;
use crate::ownership::CertificateOfOwnership;
use crate::tag::Tag;

/// The controller-configuration state of one joined network.
///
/// The numeric values are library-local and leave no gaps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkStatus {
    #[default]
    RequestingConfiguration,
    Ok,
    AccessDenied,
    NotFound,
    AuthenticationRequired,
}

impl NetworkStatus {
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::RequestingConfiguration => 0,
            Self::Ok => 1,
            Self::AccessDenied => 2,
            Self::NotFound => 3,
            Self::AuthenticationRequired => 4,
        }
    }

    /// The stable diagnostic name of this status.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RequestingConfiguration => "requesting-configuration",
            Self::Ok => "ok",
            Self::AccessDenied => "access-denied",
            Self::NotFound => "not-found",
            Self::AuthenticationRequired => "authentication-required",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "requesting-configuration" => Some(Self::RequestingConfiguration),
            "ok" => Some(Self::Ok),
            "access-denied" => Some(Self::AccessDenied),
            "not-found" => Some(Self::NotFound),
            "authentication-required" => Some(Self::AuthenticationRequired),
            _ => None,
        }
    }
}

/// The external authentication a controller requested for a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAuthenticationInfo {
    pub version: u64,
    pub authentication_url: String,
    pub issuer_url: String,
    pub central_auth_url: String,
    pub nonce: String,
    pub state: String,
    pub client_id: String,
    pub provider: String,
}
impl Default for NetworkAuthenticationInfo {
    /// Every field at its reference zero value. Written out rather than derived so that adding a
    /// field to `NetworkAuthenticationInfo` cannot default silently: this impl stops compiling until the new field is
    /// named here (RUST_GUIDELINES.md section 3, functional-update struct literals).
    fn default() -> Self {
        Self {
            version: <u64 as Default>::default(),
            authentication_url: <String as Default>::default(),
            issuer_url: <String as Default>::default(),
            central_auth_url: <String as Default>::default(),
            nonce: <String as Default>::default(),
            state: <String as Default>::default(),
            client_id: <String as Default>::default(),
            provider: <String as Default>::default(),
        }
    }
}

/// Chunks of one in-progress controller configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigAssembly {
    pub update_id: u64,
    pub data: Vec<u8>,
    pub received: Vec<bool>,
    pub count: usize,
    pub updated_at: Option<SystemTime>,
}

impl ConfigAssembly {
    /// An empty assembly sized for `total_length` configuration bytes.
    #[must_use]
    pub fn new(update_id: u64, total_length: usize) -> Self {
        Self {
            update_id,
            data: vec![0u8; total_length],
            received: vec![false; total_length],
            count: 0,
            updated_at: None,
        }
    }

    /// Whether every byte of the configuration has arrived.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.count == self.data.len()
    }
}

/// The bridge last seen sourcing one virtual MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeRoute {
    pub bridge: Address,
    pub learned: SystemTime,
}

/// One multicast frame held until its group's recipients are known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMulticastFrame {
    pub frame: Frame,
    /// The peer whose frame is being replicated; it is never a recipient.
    pub origin: Address,
    pub sent: BTreeSet<Address>,
    /// The recipients fixed when the member limit was already reached. Absent
    /// while the frame may still be sent to later-learned members.
    pub targets: Option<BTreeSet<Address>>,
    pub gather_limit: u32,
    pub bridges_outside_limit: bool,
    pub created_at: SystemTime,
}

/// A joined network's status, accepted configuration, and credential caches.
///
/// The credential maps are keyed by member address and hold what peers have
/// published; the node's credential handling fills them, and rule evaluation
/// reads them through [`crate::rules::FrameRuleContext`].
#[derive(Debug, Clone)]
pub struct Network {
    pub id: u64,
    pub status: NetworkStatus,
    pub config: NetworkConfigData,
    pub assemblies: BTreeMap<u64, ConfigAssembly>,
    pub members: BTreeMap<Address, CertificateOfMembership>,
    pub ownership: BTreeMap<Address, Vec<CertificateOfOwnership>>,
    pub tags: BTreeMap<Address, Vec<Tag>>,
    pub capabilities: BTreeMap<Address, Vec<Capability>>,
    pub associated: BTreeMap<Address, SystemTime>,
    pub bridge_routes: BTreeMap<Mac, BridgeRoute>,
    /// Learned members per multicast group, with the time each was last seen.
    pub multicast: BTreeMap<MulticastGroup, BTreeMap<Address, SystemTime>>,
    /// Frames waiting for their group's recipients to be learned.
    pub pending_multicast: BTreeMap<MulticastGroup, Vec<PendingMulticastFrame>>,
    /// Groups the embedding subscribed to on this network.
    pub multicast_subscriptions: BTreeSet<MulticastGroup>,
    /// The last explicit gather per group, which bounds gather frequency.
    pub last_multicast_gather: BTreeMap<MulticastGroup, SystemTime>,
    pub multicast_announcements: BTreeMap<Address, SystemTime>,
    pub last_config_update_id: u64,
    pub config_update_serial: u64,
    pub report_next_failure: bool,
    pub last_config_request: Option<SystemTime>,
    pub last_config_receive: Option<SystemTime>,
    pub authentication: NetworkAuthenticationInfo,
}
impl Default for Network {
    /// Every field at its reference zero value. Written out rather than derived so that adding a
    /// field to `Network` cannot default silently: this impl stops compiling until the new field is
    /// named here (RUST_GUIDELINES.md section 3, functional-update struct literals).
    fn default() -> Self {
        Self {
            id: <u64 as Default>::default(),
            status: <NetworkStatus as Default>::default(),
            config: <NetworkConfigData as Default>::default(),
            assemblies: <BTreeMap<u64, ConfigAssembly> as Default>::default(),
            members: <BTreeMap<Address, CertificateOfMembership> as Default>::default(),
            ownership: <BTreeMap<Address, Vec<CertificateOfOwnership>> as Default>::default(),
            tags: <BTreeMap<Address, Vec<Tag>> as Default>::default(),
            capabilities: <BTreeMap<Address, Vec<Capability>> as Default>::default(),
            associated: <BTreeMap<Address, SystemTime> as Default>::default(),
            bridge_routes: <BTreeMap<Mac, BridgeRoute> as Default>::default(),
            multicast: <BTreeMap<MulticastGroup, BTreeMap<Address, SystemTime>> as Default>::default(),
            pending_multicast: <BTreeMap<MulticastGroup, Vec<PendingMulticastFrame>> as Default>::default(),
            multicast_subscriptions: <BTreeSet<MulticastGroup> as Default>::default(),
            last_multicast_gather: <BTreeMap<MulticastGroup, SystemTime> as Default>::default(),
            multicast_announcements: <BTreeMap<Address, SystemTime> as Default>::default(),
            last_config_update_id: <u64 as Default>::default(),
            config_update_serial: <u64 as Default>::default(),
            report_next_failure: <bool as Default>::default(),
            last_config_request: <Option<SystemTime> as Default>::default(),
            last_config_receive: <Option<SystemTime> as Default>::default(),
            authentication: <NetworkAuthenticationInfo as Default>::default(),
        }
    }
}

impl Network {
    #[must_use]
    pub fn new(network_id: u64) -> Self {
        Self { id: network_id, ..Default::default() }
    }

    /// Members eligible to receive this network's credentials.
    #[must_use]
    pub fn credential_recipients(&self) -> BTreeSet<Address> {
        let mut recipients = BTreeSet::new();
        recipients.extend(self.associated.keys().copied());
        recipients.extend(self.members.keys().copied());
        recipients.extend(self.capabilities.keys().copied());
        recipients.extend(self.tags.keys().copied());
        recipients.extend(self.ownership.keys().copied());
        recipients
    }
}

/// The embedding-facing authentication details of one configuration.
#[must_use]
pub fn authentication_from_config(config: &NetworkConfigData) -> NetworkAuthenticationInfo {
    NetworkAuthenticationInfo {
        version: config.sso_version,
        authentication_url: config.authentication_url.clone(),
        issuer_url: config.issuer_url.clone(),
        central_auth_url: config.central_auth_url.clone(),
        nonce: config.sso_nonce.clone(),
        state: config.sso_state.clone(),
        client_id: config.sso_client_id.clone(),
        provider: config.sso_provider.clone(),
    }
}

/// The persistent state object name holding one network's configuration.
#[must_use]
pub fn network_state_name(network_id: u64) -> String {
    format!("networks.d/{}.conf", strconv_hex16(network_id))
}

/// Formats a value as sixteen lowercase hexadecimal digits.
#[must_use]
pub fn strconv_hex16(value: u64) -> String {
    format!("{value:016x}")
}

/// Encodes a network rule operand in network byte order.
#[must_use]
pub fn uint64_rule_value(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// The hub address a supported ad-hoc network ID encodes.
#[must_use]
pub fn ad_hoc_network_hub(network_id: u64) -> Option<Address> {
    if is_ad_hoc_network_id(network_id) && network_id & 0xff == 0x01 {
        let hub = Address::new(network_id >> 8);
        if !hub.is_zero() && !hub.is_reserved() {
            return Some(hub);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_official_state_object_name() {
        assert_eq!(network_state_name(0x17d7_0943_6c04_d6bc), "networks.d/17d709436c04d6bc.conf");
        assert_eq!(strconv_hex16(0), "0000000000000000");
        assert_eq!(strconv_hex16(u64::MAX), "ffffffffffffffff");
    }

    #[test]
    fn extracts_the_hub_of_a_supported_ad_hoc_network() {
        assert_eq!(ad_hoc_network_hub(0xff0a_0123_4567_8901), Some(Address::new(0x0001_2345_6789)));
        assert_eq!(ad_hoc_network_hub(0xff0a_0123_4567_8902), None);
        assert_eq!(ad_hoc_network_hub(0x0000_0000_0000_0001), None);
    }

    #[test]
    fn status_names_round_trip() {
        for status in [
            NetworkStatus::RequestingConfiguration,
            NetworkStatus::Ok,
            NetworkStatus::AccessDenied,
            NetworkStatus::NotFound,
            NetworkStatus::AuthenticationRequired,
        ] {
            assert_eq!(NetworkStatus::parse(status.name()), Some(status));
        }
        assert_eq!(NetworkStatus::parse("event(7)"), None);
    }

    #[test]
    fn assemblies_track_received_bytes() {
        let mut assembly = ConfigAssembly::new(7, 3);
        assert!(!assembly.complete());
        assembly.count = 3;
        assert!(assembly.complete());
        assert_eq!(assembly.update_id, 7);
    }

    #[test]
    fn credential_recipients_union_every_cache() {
        let mut network = Network::new(1);
        network.tags.insert(Address::new(4), Vec::new());
        network.ownership.insert(Address::new(5), Vec::new());
        network.associated.insert(Address::new(3), SystemTime::now());
        let recipients: Vec<Address> = network.credential_recipients().into_iter().collect();
        assert_eq!(recipients, vec![Address::new(3), Address::new(4), Address::new(5)]);
    }
}

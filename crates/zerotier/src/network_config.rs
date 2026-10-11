//! Controller network configurations: the dictionary a ZeroTier controller
//! sends to describe one virtual network, plus the request metadata a node
//! advertises when it asks for one.

use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;

use crate::address::Address;
use crate::capability::{Capability, MAX_CAPABILITY_RULES, MAX_NETWORK_CAPABILITIES};
use crate::dictionary::{append_dictionary_entry, append_dictionary_uint, parse_dictionary, Dictionary};
use crate::membership::CertificateOfMembership;
use crate::ownership::{CertificateOfOwnership, MAX_OWNERSHIP_CERTS};
use crate::rules::{parse_network_rules, NetworkRule, MAX_NETWORK_RULES, RULE_ACTION_ACCEPT, RULE_MATCH_ETHER_TYPE};
use crate::tag::{Tag, MAX_NETWORK_TAGS};

/// The dictionary format emitted in configuration requests and locally
/// generated configurations.
pub const NETWORK_CONFIG_VERSION: u64 = 7;
/// Bounds chunk assembly memory; one MiB accommodates the official rule and
/// capability maxima within the uint32 wire length.
pub const MAX_NETWORK_CONFIG_SIZE: usize = 1 << 20;
/// Used when a configuration does not specify a valid virtual network MTU.
pub const DEFAULT_NETWORK_MTU: u32 = 2800;
/// The smallest accepted virtual network MTU.
pub const MIN_NETWORK_MTU: u32 = 1280;
/// The largest accepted virtual network MTU.
pub const MAX_NETWORK_MTU: u32 = 10000;

/// The ZeroTier wire protocol version advertised in configuration requests.
pub const PROTOCOL_VERSION: u64 = 13;
/// The advertised ZeroTier One compatibility major version.
pub const NODE_VERSION_MAJOR: u64 = 1;
/// The advertised ZeroTier One compatibility minor version.
pub const NODE_VERSION_MINOR: u64 = 16;
/// The advertised ZeroTier One compatibility patch version.
pub const NODE_VERSION_REVISION: u64 = 2;

/// Permits Ethernet broadcast frames.
pub const NETWORK_CONFIG_FLAG_ENABLE_BROADCAST: u64 = 0x02;
/// Permits deterministic ZeroTier IPv6 addresses to use NDP emulation.
pub const NETWORK_CONFIG_FLAG_ENABLE_IPV6_NDP_EMULATION: u64 = 0x04;

/// Identifies a member allowed to bridge frames.
pub const SPECIALIST_TYPE_ACTIVE_BRIDGE: u64 = 0x0000_0200_0000_0000;
/// Identifies a member that replicates multicast traffic.
pub const SPECIALIST_TYPE_MULTICAST_REPLICATOR: u64 = 0x0000_0800_0000_0000;
/// Identifies a member that relays network frames.
pub const SPECIALIST_TYPE_NETWORK_RELAY: u64 = 0x0000_1000_0000_0000;

/// Bounds specialist records accepted from a controller configuration.
const MAX_NETWORK_SPECIALISTS: usize = 512;
/// Bounds managed addresses accepted from a controller.
const MAX_ASSIGNED_ADDRESSES: usize = 32;
/// Bounds managed routes accepted from a controller.
const MAX_NETWORK_ROUTES: usize = 128;
/// Bounds the decoded network name.
const MAX_NETWORK_NAME_LENGTH: usize = 127;
/// Bounds decoded external-authentication URLs.
const MAX_AUTHENTICATION_URL: usize = 2047;
/// Bounds a decoded legacy SSO nonce.
const MAX_SSO_NONCE_LENGTH: usize = 127;
/// Bounds a decoded legacy SSO state value.
const MAX_SSO_STATE_LENGTH: usize = 255;
/// Bounds a decoded legacy SSO client identifier.
const MAX_SSO_CLIENT_ID_LENGTH: usize = 255;
/// Bounds a decoded legacy SSO provider name.
const MAX_SSO_PROVIDER_LENGTH: usize = 63;
/// Bounds legacy comma-separated configuration fields.
const MAX_LEGACY_TEXT_LENGTH: usize = 1023;

/// Reports malformed controller configuration data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ZeroTier network configuration")]
pub struct InvalidNetworkConfig;

/// Reports a network type name that is neither private nor public.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ZeroTier network type")]
pub struct InvalidNetworkType;

/// A controller configuration's membership model.
///
/// Unrecognized values are preserved rather than rejected; every value other
/// than [`NetworkType::PUBLIC`] requires a membership certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkType(u8);

impl NetworkType {
    /// Requires a valid certificate of membership.
    pub const PRIVATE: Self = Self(0);
    /// Accepts members without a certificate of membership.
    pub const PUBLIC: Self = Self(1);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// The stable configuration name of this type.
    #[must_use]
    pub fn name(self) -> String {
        match self.0 {
            0 => "private".to_owned(),
            1 => "public".to_owned(),
            other => format!("network-type({other})"),
        }
    }

    /// Parses the stable configuration name of a network type.
    pub fn parse(text: &str) -> Result<Self, InvalidNetworkType> {
        match text {
            "private" => Ok(Self::PRIVATE),
            "public" => Ok(Self::PUBLIC),
            _ => Err(InvalidNetworkType),
        }
    }
}

impl Default for NetworkType {
    fn default() -> Self {
        Self::PRIVATE
    }
}

/// One controller-managed route installed on a virtual link.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkRoute {
    pub target: IpNet,
    pub via: Option<IpAddr>,
    pub flags: u16,
    pub metric: u16,
}

/// The validated controller configuration for one network.
///
/// `Clone` is a deep copy: every field is owned, so a clone is already safe to
/// hand to callbacks and snapshots.
#[derive(Debug, Clone)]
pub struct NetworkConfigData {
    pub version: u64,
    pub network_id: u64,
    pub timestamp: u64,
    pub revision: u64,
    pub issued_to: Address,
    pub flags: u64,
    pub credential_time_max_delta: u64,
    pub network_type: NetworkType,
    pub name: String,
    pub mtu: u32,
    pub multicast_limit: u32,
    pub assigned: Vec<IpNet>,
    pub routes: Vec<NetworkRoute>,
    pub dns_domain: String,
    pub dns_servers: Vec<SocketAddr>,
    pub sso_enabled: bool,
    pub sso_version: u64,
    pub authentication_url: String,
    pub authentication_expiry: u64,
    pub issuer_url: String,
    pub central_auth_url: String,
    pub sso_nonce: String,
    pub sso_state: String,
    pub sso_client_id: String,
    pub sso_provider: String,
    pub remote_trace_target: Address,
    pub remote_trace_level: u64,
    pub com: Option<CertificateOfMembership>,
    pub ownership: Vec<CertificateOfOwnership>,
    pub tags: Vec<Tag>,
    pub capabilities: Vec<Capability>,
    pub specialists: Vec<u64>,
    pub rules_raw: Vec<u8>,
    pub rules: Vec<NetworkRule>,
    pub raw: Vec<u8>,
}
impl Default for NetworkConfigData {
    /// Every field at its reference zero value. Written out rather than derived so that adding a
    /// field to `NetworkConfigData` cannot default silently: this impl stops compiling until the new field is
    /// named here (RUST_GUIDELINES.md section 3, functional-update struct literals).
    fn default() -> Self {
        Self {
            version: <u64 as Default>::default(),
            network_id: <u64 as Default>::default(),
            timestamp: <u64 as Default>::default(),
            revision: <u64 as Default>::default(),
            issued_to: <Address as Default>::default(),
            flags: <u64 as Default>::default(),
            credential_time_max_delta: <u64 as Default>::default(),
            network_type: <NetworkType as Default>::default(),
            name: <String as Default>::default(),
            mtu: <u32 as Default>::default(),
            multicast_limit: <u32 as Default>::default(),
            assigned: <Vec<IpNet> as Default>::default(),
            routes: <Vec<NetworkRoute> as Default>::default(),
            dns_domain: <String as Default>::default(),
            dns_servers: <Vec<SocketAddr> as Default>::default(),
            sso_enabled: <bool as Default>::default(),
            sso_version: <u64 as Default>::default(),
            authentication_url: <String as Default>::default(),
            authentication_expiry: <u64 as Default>::default(),
            issuer_url: <String as Default>::default(),
            central_auth_url: <String as Default>::default(),
            sso_nonce: <String as Default>::default(),
            sso_state: <String as Default>::default(),
            sso_client_id: <String as Default>::default(),
            sso_provider: <String as Default>::default(),
            remote_trace_target: <Address as Default>::default(),
            remote_trace_level: <u64 as Default>::default(),
            com: <Option<CertificateOfMembership> as Default>::default(),
            ownership: <Vec<CertificateOfOwnership> as Default>::default(),
            tags: <Vec<Tag> as Default>::default(),
            capabilities: <Vec<Capability> as Default>::default(),
            specialists: <Vec<u64> as Default>::default(),
            rules_raw: <Vec<u8> as Default>::default(),
            rules: <Vec<NetworkRule> as Default>::default(),
            raw: <Vec<u8> as Default>::default(),
        }
    }
}

impl NetworkConfigData {
    /// Reports whether both values produce the same effective configuration.
    ///
    /// Dictionary ordering, unknown keys, the parsed format version and cached
    /// wire encodings do not affect the result, matching `NetworkConfigData`'s
    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        self.network_id == other.network_id
            && self.timestamp == other.timestamp
            && self.revision == other.revision
            && self.issued_to == other.issued_to
            && self.flags == other.flags
            && self.credential_time_max_delta == other.credential_time_max_delta
            && self.network_type == other.network_type
            && self.name == other.name
            && self.mtu == other.mtu
            && self.multicast_limit == other.multicast_limit
            && self.assigned == other.assigned
            && self.routes == other.routes
            && self.dns_domain == other.dns_domain
            && self.dns_servers == other.dns_servers
            && self.sso_enabled == other.sso_enabled
            && self.sso_version == other.sso_version
            && self.authentication_url == other.authentication_url
            && self.authentication_expiry == other.authentication_expiry
            && self.issuer_url == other.issuer_url
            && self.central_auth_url == other.central_auth_url
            && self.sso_nonce == other.sso_nonce
            && self.sso_state == other.sso_state
            && self.sso_client_id == other.sso_client_id
            && self.sso_provider == other.sso_provider
            && self.remote_trace_target == other.remote_trace_target
            && self.remote_trace_level == other.remote_trace_level
            && com_equal(self.com.as_ref(), other.com.as_ref())
            && ownership_equal(&self.ownership, &other.ownership)
            && tags_equal(&self.tags, &other.tags)
            && capabilities_equal(&self.capabilities, &other.capabilities)
            && self.specialists == other.specialists
            && self.rules == other.rules
    }

    /// Reports whether both configurations assign the same prefixes, ignoring
    /// controller-provided ordering.
    #[must_use]
    pub fn managed_addresses_equal(&self, other: &Self) -> bool {
        if self.assigned.len() != other.assigned.len() {
            return false;
        }
        let mut unmatched: Vec<&IpNet> = other.assigned.iter().collect();
        for prefix in &self.assigned {
            let Some(position) = unmatched.iter().position(|candidate| *candidate == prefix) else {
                return false;
            };
            unmatched.remove(position);
        }
        true
    }

    /// Whether the configuration assigns at least one IPv6 prefix to the local
    /// member.
    #[must_use]
    pub fn has_managed_ipv6(&self) -> bool {
        self.assigned.iter().any(|prefix| prefix.addr().is_ipv6())
    }

    /// Members carrying any specialist bit in `mask`.
    #[must_use]
    pub fn specialist_addresses(&self, mask: u64) -> Vec<Address> {
        self.specialists
            .iter()
            .filter(|specialist| *specialist & mask != 0)
            .map(|specialist| Address::new(*specialist))
            .collect()
    }

    /// Whether `address` carries a specialist bit in `mask`.
    #[must_use]
    pub fn is_specialist(&self, address: Address, mask: u64) -> bool {
        self.specialists.iter().any(|specialist| specialist & mask != 0 && Address::new(*specialist) == address)
    }
}

/// Decodes current or legacy controller dictionary data.
pub fn parse_network_config(data: &[u8]) -> Result<NetworkConfigData, InvalidNetworkConfig> {
    if data.is_empty() || data.len() > MAX_NETWORK_CONFIG_SIZE {
        return Err(InvalidNetworkConfig);
    }
    let dictionary = parse_dictionary(data).map_err(|_| InvalidNetworkConfig)?;
    let mut config = NetworkConfigData {
        version: dictionary.uint("v", 0),
        network_id: dictionary.uint("nwid", 0),
        timestamp: dictionary.uint("ts", 0),
        revision: dictionary.uint("r", 0),
        issued_to: Address::new(dictionary.uint("id", 0)),
        flags: dictionary.uint("f", 0),
        credential_time_max_delta: dictionary.uint("ctmd", 0),
        network_type: NetworkType::from_bits(low_byte(dictionary.uint("t", 0))),
        name: dictionary_string(&dictionary, "n", MAX_NETWORK_NAME_LENGTH),
        mtu: low_u32(dictionary.uint("mtu", u64::from(DEFAULT_NETWORK_MTU))),
        multicast_limit: low_u32(dictionary.uint("ml", 0)),
        sso_enabled: dictionary.bool("ssoe", false),
        sso_version: dictionary.uint("ssov", 0),
        authentication_url: dictionary_string(&dictionary, "aurl", MAX_AUTHENTICATION_URL),
        authentication_expiry: dictionary.uint("aexpt", 0),
        issuer_url: dictionary_string(&dictionary, "iurl", MAX_AUTHENTICATION_URL),
        central_auth_url: dictionary_string(&dictionary, "ssoce", MAX_AUTHENTICATION_URL),
        sso_nonce: dictionary_string(&dictionary, "sson", MAX_SSO_NONCE_LENGTH),
        sso_state: dictionary_string(&dictionary, "ssos", MAX_SSO_STATE_LENGTH),
        sso_client_id: dictionary_string(&dictionary, "ssocid", MAX_SSO_CLIENT_ID_LENGTH),
        sso_provider: dictionary_string(&dictionary, "ssop", MAX_SSO_PROVIDER_LENGTH),
        remote_trace_target: Address::new(dictionary.uint("tt", 0)),
        remote_trace_level: dictionary.uint("tl", 0),
        rules_raw: dictionary.get("R").unwrap_or_default().to_vec(),
        raw: data.to_vec(),
        ..Default::default()
    };
    if config.network_id == 0 || config.issued_to.is_zero() {
        return Err(InvalidNetworkConfig);
    }
    config.mtu = config.mtu.clamp(MIN_NETWORK_MTU, MAX_NETWORK_MTU);
    if config.version < 6 {
        parse_legacy_network_config(&dictionary, &mut config)?;
        return Ok(config);
    }
    normalize_network_authentication(&mut config);
    if let Some(value) = dictionary.get("I").filter(|value| !value.is_empty()) {
        parse_assigned_addresses(value, &mut config)?;
    }
    if let Some(value) = dictionary.get("RT").filter(|value| !value.is_empty()) {
        parse_network_routes(value, &mut config)?;
    }
    if let Some(value) = dictionary.get("DNS").filter(|value| !value.is_empty()) {
        parse_dns_servers(value, &mut config)?;
    }
    if let Some(value) = dictionary.get("C").filter(|value| !value.is_empty()) {
        let (certificate, consumed) = CertificateOfMembership::parse(value).map_err(|_| InvalidNetworkConfig)?;
        if consumed != value.len() {
            return Err(InvalidNetworkConfig);
        }
        config.com = Some(certificate);
    }
    if let Some(value) = dictionary.get("COO").filter(|value| !value.is_empty()) {
        parse_ownership_certificates(value, &mut config)?;
    }
    if let Some(value) = dictionary.get("TAG").filter(|value| !value.is_empty()) {
        parse_tags(value, &mut config);
    }
    if let Some(value) = dictionary.get("CAP").filter(|value| !value.is_empty()) {
        parse_capabilities(value, &mut config);
    }
    if let Some(value) = dictionary.get("S").filter(|value| !value.is_empty()) {
        parse_specialists(value, &mut config.specialists);
    }
    if let Some(value) = dictionary.get("R").filter(|value| !value.is_empty()) {
        config.rules = parse_network_rules(value).map_err(|_| InvalidNetworkConfig)?;
    }
    Ok(config)
}

/// Decodes the `I` field into the managed address assignments.
fn parse_assigned_addresses(value: &[u8], config: &mut NetworkConfigData) -> Result<(), InvalidNetworkConfig> {
    let mut pos = 0;
    while pos < value.len() && config.assigned.len() < MAX_ASSIGNED_ADDRESSES {
        let (address, consumed) = parse_inet_address(value.get(pos..).ok_or(InvalidNetworkConfig)?)?;
        let address = address.ok_or(InvalidNetworkConfig)?;
        let bits = usize::from(address.port());
        if bits > bit_len(address.ip()) {
            return Err(InvalidNetworkConfig);
        }
        config.assigned.push(net_from_address(address, bits)?);
        pos += consumed;
    }
    Ok(())
}

/// Decodes the `RT` field into the managed routes.
fn parse_network_routes(value: &[u8], config: &mut NetworkConfigData) -> Result<(), InvalidNetworkConfig> {
    let mut pos = 0;
    while pos < value.len() && config.routes.len() < MAX_NETWORK_ROUTES {
        let (target, consumed) = parse_inet_address(value.get(pos..).ok_or(InvalidNetworkConfig)?)?;
        pos += consumed;
        let (via, consumed) = parse_inet_address(value.get(pos..).ok_or(InvalidNetworkConfig)?)?;
        pos += consumed;
        let mut header = [0u8; 4];
        header.copy_from_slice(value.get(pos..pos + 4).ok_or(InvalidNetworkConfig)?);
        pos += 4;
        let flags = u16::from_be_bytes([header[0], header[1]]);
        let metric = u16::from_be_bytes([header[2], header[3]]);
        let target = match target {
            Some(target) => target,
            None => match via {
                None => continue,
                Some(via) => SocketAddr::new(unspecified_of(via.ip()), 0),
            },
        };
        let bits = usize::from(target.port());
        if bits > bit_len(target.ip()) {
            return Err(InvalidNetworkConfig);
        }
        config.routes.push(NetworkRoute {
            target: net_from_address(target, bits)?,
            via: via.map(|via| via.ip()),
            flags,
            metric,
        });
    }
    Ok(())
}

/// Decodes the `DNS` field: a 128-byte domain name followed by four endpoints.
fn parse_dns_servers(value: &[u8], config: &mut NetworkConfigData) -> Result<(), InvalidNetworkConfig> {
    let Some((domain, _)) = value.split_at_checked(128) else {
        return Err(InvalidNetworkConfig);
    };
    String::from_utf8_lossy(domain).trim_end_matches('\0').clone_into(&mut config.dns_domain);
    let mut pos = 128;
    for _ in 0..4 {
        let (server, consumed) = parse_inet_address(value.get(pos..).ok_or(InvalidNetworkConfig)?)?;
        if let Some(server) = server {
            config.dns_servers.push(server);
        }
        pos += consumed;
    }
    Ok(())
}

/// Decodes the `COO` field into the certificate-of-ownership chain.
fn parse_ownership_certificates(value: &[u8], config: &mut NetworkConfigData) -> Result<(), InvalidNetworkConfig> {
    let mut pos = 0;
    while pos < value.len() {
        let (certificate, consumed) = CertificateOfOwnership::parse(value.get(pos..).ok_or(InvalidNetworkConfig)?)
            .map_err(|_| InvalidNetworkConfig)?;
        if consumed == 0 {
            return Err(InvalidNetworkConfig);
        }
        if config.ownership.len() < MAX_OWNERSHIP_CERTS {
            config.ownership.push(certificate);
        }
        pos += consumed;
    }
    Ok(())
}

/// Decodes the `TAG` field, keeping the leading records that parse.
fn parse_tags(value: &[u8], config: &mut NetworkConfigData) {
    let mut pos = 0;
    while pos < value.len() && config.tags.len() < MAX_NETWORK_TAGS {
        let Some(chunk) = value.get(pos..) else {
            break;
        };
        let Ok((tag, consumed)) = Tag::parse(chunk) else {
            break;
        };
        if consumed == 0 {
            break;
        }
        config.tags.push(tag);
        pos += consumed;
    }
    config.tags.sort_by_key(|tag| tag.id);
}

/// Decodes the `CAP` field, keeping the leading records that parse.
fn parse_capabilities(value: &[u8], config: &mut NetworkConfigData) {
    let mut pos = 0;
    while pos < value.len() && config.capabilities.len() < MAX_NETWORK_CAPABILITIES {
        let Some(chunk) = value.get(pos..) else {
            break;
        };
        let Ok((capability, consumed)) = Capability::parse(chunk) else {
            break;
        };
        if consumed == 0 {
            break;
        }
        config.capabilities.push(capability);
        pos += consumed;
    }
    config.capabilities.sort_by_key(|capability| capability.id);
}

/// Decodes the `S` field into the specialist records.
fn parse_specialists(value: &[u8], specialists: &mut Vec<u64>) {
    for chunk in value.chunks_exact(8) {
        if specialists.len() >= MAX_NETWORK_SPECIALISTS {
            break;
        }
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        specialists.push(u64::from_be_bytes(word));
    }
}

/// The low byte of a dictionary integer: one-byte wire fields are truncated
/// rather than rejected.
fn low_byte(value: u64) -> u8 {
    value.to_le_bytes()[0]
}

/// The low 32 bits of a dictionary integer, the width of a `u32` wire field.
fn low_u32(value: u64) -> u32 {
    let bytes = value.to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Encodes this implementation's controller request capabilities.
pub fn build_network_config_metadata() -> Result<Vec<u8>, InvalidNetworkConfig> {
    build_network_config_metadata_for(std::env::consts::OS, std::env::consts::ARCH)
}

/// [`build_network_config_metadata`] with an explicit target, for tests.
fn build_network_config_metadata_for(os: &str, arch: &str) -> Result<Vec<u8>, InvalidNetworkConfig> {
    let entries: [(&str, u64); 12] = [
        ("v", NETWORK_CONFIG_VERSION),
        ("vend", 1),
        ("pv", PROTOCOL_VERSION),
        ("majv", NODE_VERSION_MAJOR),
        ("minv", NODE_VERSION_MINOR),
        ("revv", NODE_VERSION_REVISION),
        ("mr", MAX_NETWORK_RULES as u64),
        ("mc", MAX_NETWORK_CAPABILITIES as u64),
        ("mcr", MAX_CAPABILITY_RULES as u64),
        ("mt", MAX_NETWORK_TAGS as u64),
        ("f", 0),
        ("revr", 1),
    ];
    let mut data = Vec::new();
    for (key, value) in entries {
        data = append_dictionary_uint(data, key, value).map_err(|_| InvalidNetworkConfig)?;
    }
    append_dictionary_entry(data, "o", zero_tier_target_name(os, arch).as_bytes()).map_err(|_| InvalidNetworkConfig)
}

/// Maps a toolchain target to ZeroTier's controller platform name.
///
/// Target spellings differ between toolchains (`amd64` against `x86_64`,
/// `darwin` against `macos`), so both names are accepted for every platform.
fn zero_tier_target_name(os: &str, arch: &str) -> String {
    let platform = match os {
        "windows" | "android" | "linux" | "aix" => os,
        "solaris" | "illumos" => "solaris",
        "darwin" | "macos" => "macos",
        "ios" => "ios_iphone",
        "freebsd" | "netbsd" | "openbsd" | "dragonfly" => "bsd",
        _ => "unknown",
    };
    let architecture = match arch {
        "amd64" | "x86_64" => "x86_64",
        "386" | "x86" => "x86",
        "arm" => "arm",
        "arm64" | "aarch64" => "arm64",
        "loong64" | "loongarch64" => "loongarch",
        "mips" | "mips64" | "mips64le" | "mips64p32" | "mips64p32le" | "mipsle" => "mips",
        "riscv64" => "riscv",
        "ppc64" | "ppc64le" | "powerpc" | "powerpc64" => "powerpc",
        "s390x" => "s390",
        _ => "unknown",
    };
    format!("{platform}/{architecture}")
}

/// Translates legacy dictionary fields into the current configuration
/// structure.
fn parse_legacy_network_config(
    dictionary: &Dictionary,
    config: &mut NetworkConfigData,
) -> Result<(), InvalidNetworkConfig> {
    config.sso_enabled = false;
    config.sso_version = 0;
    config.authentication_url = String::new();
    config.authentication_expiry = 0;
    config.issuer_url = String::new();
    config.central_auth_url = String::new();
    config.sso_nonce = String::new();
    config.sso_state = String::new();
    config.sso_client_id = String::new();
    config.sso_provider = String::new();
    config.flags = NETWORK_CONFIG_FLAG_ENABLE_IPV6_NDP_EMULATION;
    if dictionary.bool("eb", false) {
        config.flags |= NETWORK_CONFIG_FLAG_ENABLE_BROADCAST;
    }
    config.network_type = NetworkType::PRIVATE;
    if !dictionary.bool("p", true) {
        config.network_type = NetworkType::PUBLIC;
    }
    for key in ["v4s", "v6s"] {
        for value in dictionary_string(dictionary, key, MAX_LEGACY_TEXT_LENGTH).split(',') {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            if config.assigned.len() >= MAX_ASSIGNED_ADDRESSES {
                break;
            }
            let Ok(prefix) = value.parse::<IpNet>() else {
                return Err(InvalidNetworkConfig);
            };
            if prefix.addr().is_unspecified() || prefix.addr().is_multicast() {
                return Err(InvalidNetworkConfig);
            }
            let bits = usize::from(prefix.prefix_len());
            if bits > 0 && bits < bit_len(prefix.addr()) && prefix.network() == prefix.addr() {
                continue;
            }
            config.assigned.push(prefix);
        }
    }
    let legacy_com = dictionary_string(dictionary, "com", MAX_LEGACY_TEXT_LENGTH);
    if !legacy_com.is_empty() {
        config.com = Some(CertificateOfMembership::from_legacy_string(&legacy_com).map_err(|_| InvalidNetworkConfig)?);
    }
    let ether_types = dictionary_string(dictionary, "et", MAX_LEGACY_TEXT_LENGTH).trim().to_owned();
    if ether_types.is_empty() {
        config.rules = vec![NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() }];
    } else {
        for value in ether_types.split(',') {
            let value = value.trim();
            let parsed = u16::from_str_radix(value, 16);
            if config.rules.len() + 2 > MAX_NETWORK_RULES {
                break;
            }
            let parsed = parsed.map_err(|_| InvalidNetworkConfig)?;
            if parsed != 0 {
                let matched = parsed.to_be_bytes().to_vec();
                config.rules.push(NetworkRule { rule_type: RULE_MATCH_ETHER_TYPE, value: matched });
            }
            config.rules.push(NetworkRule { rule_type: RULE_ACTION_ACCEPT, value: Vec::new() });
        }
    }
    for value in dictionary_string(dictionary, "ab", MAX_LEGACY_TEXT_LENGTH).split(',') {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let parsed = u64::from_str_radix(value, 16);
        if config.specialists.len() >= MAX_NETWORK_SPECIALISTS {
            break;
        }
        let parsed = parsed.map_err(|_| InvalidNetworkConfig)?;
        let address = Address::new(parsed);
        if address.is_reserved() {
            return Err(InvalidNetworkConfig);
        }
        config.specialists.push(SPECIALIST_TYPE_ACTIVE_BRIDGE | address.uint64());
    }
    Ok(())
}

/// Returns a NUL-terminated dictionary value truncated to a protocol-specific
/// byte limit.
fn dictionary_string(dictionary: &Dictionary, key: &str, maximum: usize) -> String {
    let value = dictionary.get(key).unwrap_or_default();
    let value = value.split(|byte| *byte == 0).next().unwrap_or_default();
    let value = value.get(..maximum).unwrap_or(value);
    String::from_utf8_lossy(value).into_owned()
}

/// Clears fields not valid for the advertised SSO version.
fn normalize_network_authentication(config: &mut NetworkConfigData) {
    if !config.sso_enabled {
        config.authentication_url = String::new();
        config.authentication_expiry = 0;
        config.issuer_url = String::new();
        config.central_auth_url = String::new();
        config.sso_nonce = String::new();
        config.sso_state = String::new();
        config.sso_client_id = String::new();
        config.sso_provider = String::new();
        return;
    }
    if config.sso_version == 0 {
        config.issuer_url = String::new();
        config.central_auth_url = String::new();
        config.sso_nonce = String::new();
        config.sso_state = String::new();
        config.sso_client_id = String::new();
        config.sso_provider = String::new();
        return;
    }
    if config.sso_version == 1 {
        if config.sso_provider.is_empty() {
            "default".clone_into(&mut config.sso_provider);
        }
        return;
    }
    config.authentication_url = String::new();
    config.authentication_expiry = 0;
    config.issuer_url = String::new();
    config.central_auth_url = String::new();
    config.sso_nonce = String::new();
    config.sso_state = String::new();
    config.sso_client_id = String::new();
    config.sso_provider = String::new();
}

/// Decodes ZeroTier's tagged IPv4 or IPv6 endpoint form, reporting bytes
/// consumed and `None` for the zero-tag empty value.
fn parse_inet_address(data: &[u8]) -> Result<(Option<SocketAddr>, usize), InvalidNetworkConfig> {
    match data.first().copied().ok_or(InvalidNetworkConfig)? {
        0 => Ok((None, 1)),
        4 => {
            let Some(body) = data.get(1..7) else {
                return Err(InvalidNetworkConfig);
            };
            let (address, port) = body.split_at(4);
            let mut octets = [0u8; 4];
            octets.copy_from_slice(address);
            let mut port_bytes = [0u8; 2];
            port_bytes.copy_from_slice(port);
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(octets));
            let port = u16::from_be_bytes(port_bytes);
            Ok((Some(SocketAddr::new(ip, port)), 7))
        }
        6 => {
            let Some(body) = data.get(1..19) else {
                return Err(InvalidNetworkConfig);
            };
            let (address, port) = body.split_at(16);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(address);
            let mut port_bytes = [0u8; 2];
            port_bytes.copy_from_slice(port);
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(octets));
            let port = u16::from_be_bytes(port_bytes);
            Ok((Some(SocketAddr::new(ip, port)), 19))
        }
        _ => Err(InvalidNetworkConfig),
    }
}

/// Appends ZeroTier's tagged endpoint representation to `dst`.
#[cfg(test)]
fn append_inet_address(mut dst: Vec<u8>, address: Option<SocketAddr>) -> Vec<u8> {
    let Some(address) = address else {
        dst.push(0);
        return dst;
    };
    match address.ip() {
        IpAddr::V4(ip) => {
            dst.push(4);
            dst.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            dst.push(6);
            dst.extend_from_slice(&ip.octets());
        }
    }
    dst.extend_from_slice(&address.port().to_be_bytes());
    dst
}

/// Builds a prefix from an endpoint whose port field carries the prefix length;
/// callers bound `bits` by the address width, so only its low byte can be set.
fn net_from_address(address: SocketAddr, bits: usize) -> Result<IpNet, InvalidNetworkConfig> {
    IpNet::new(address.ip(), bits.to_le_bytes()[0]).map_err(|_| InvalidNetworkConfig)
}

fn bit_len(address: IpAddr) -> usize {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn unspecified_of(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    }
}

fn com_equal(left: Option<&CertificateOfMembership>, right: Option<&CertificateOfMembership>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.qualifiers == right.qualifiers
                && left.signed_by == right.signed_by
                && left.signature == right.signature
        }
        _ => false,
    }
}

fn ownership_equal(left: &[CertificateOfOwnership], right: &[CertificateOfOwnership]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.network_id == right.network_id
                && left.timestamp == right.timestamp
                && left.flags == right.flags
                && left.id == right.id
                && left.things == right.things
                && left.issued_to == right.issued_to
                && left.signed_by == right.signed_by
                && left.signature == right.signature
        })
}

fn tags_equal(left: &[Tag], right: &[Tag]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.network_id == right.network_id
                && left.timestamp == right.timestamp
                && left.id == right.id
                && left.value == right.value
                && left.issued_to == right.issued_to
                && left.signed_by == right.signed_by
                && left.signature == right.signature
        })
}

fn capabilities_equal(left: &[Capability], right: &[Capability]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.network_id == right.network_id
                && left.timestamp == right.timestamp
                && left.id == right.id
                && left.rules == right.rules
                && left.max_custody_chain_length == right.max_custody_chain_length
                && left.custody == right.custody
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    const NETWORK_ID: u64 = 0x1234_5678_90ab_cdef;
    const MEMBER: u64 = 0x0046_a9a1_d071;

    /// The dictionary a modern controller sends for a public network with no
    /// other fields, which most parse tests extend.
    fn base_dictionary() -> Vec<u8> {
        let data = append_dictionary_uint(Vec::new(), "nwid", NETWORK_ID).unwrap();
        let data = append_dictionary_uint(data, "v", NETWORK_CONFIG_VERSION).unwrap();
        append_dictionary_uint(data, "id", MEMBER).unwrap()
    }

    #[test]
    fn parses_a_configuration_larger_than_the_legacy_uint16_limit() {
        let data = append_dictionary_uint(Vec::new(), "v", NETWORK_CONFIG_VERSION).unwrap();
        let data = append_dictionary_uint(data, "nwid", NETWORK_ID).unwrap();
        let data = append_dictionary_uint(data, "id", MEMBER).unwrap();
        let data = append_dictionary_entry(data, "padding", &vec![b'x'; 70 * 1024]).unwrap();

        let config = parse_network_config(&data).unwrap();
        assert_eq!(config.network_id, NETWORK_ID);
        assert_eq!(config.issued_to, Address::new(MEMBER));
    }

    #[test]
    fn equality_ignores_wire_only_differences() {
        let base = NetworkConfigData {
            network_id: 0x17d7_0943_6c04_d6bc,
            issued_to: Address::new(0x000f_1b56_d269),
            timestamp: 1234,
            revision: 5,
            raw: b"configuration".to_vec(),
            ..Default::default()
        };
        let mut equal = base.clone();
        equal.raw = b"configuration".to_vec();
        assert!(base.equal(&equal));

        let mut different_raw = equal.clone();
        different_raw.raw = b"different".to_vec();
        assert!(base.equal(&different_raw));

        let mut different_revision = equal.clone();
        different_revision.revision += 1;
        assert!(!base.equal(&different_revision));

        let mut locally_generated = base.clone();
        locally_generated.raw = Vec::new();
        assert!(locally_generated.equal(&locally_generated));

        let empty_slices = NetworkConfigData {
            assigned: Vec::new(),
            routes: Vec::new(),
            dns_servers: Vec::new(),
            ownership: Vec::new(),
            tags: Vec::new(),
            capabilities: Vec::new(),
            specialists: Vec::new(),
            rules: Vec::new(),
            ..base.clone()
        };
        assert!(base.equal(&empty_slices));
    }

    #[test]
    fn managed_address_helpers_ignore_ordering() {
        let v4: IpNet = "192.0.2.1/24".parse().unwrap();
        let v6: IpNet = "2001:db8::1/64".parse().unwrap();
        let first = NetworkConfigData { assigned: vec![v4, v6], ..Default::default() };
        let second = NetworkConfigData { assigned: vec![v6, v4], ..Default::default() };
        assert!(first.managed_addresses_equal(&second));
        assert!(second.managed_addresses_equal(&first));
        assert!(first.has_managed_ipv6());

        let different =
            NetworkConfigData { assigned: vec![v4, "2001:db8:1::1/64".parse().unwrap()], ..Default::default() };
        assert!(!first.managed_addresses_equal(&different));
        assert!(!NetworkConfigData { assigned: vec![v4], ..Default::default() }.has_managed_ipv6());
    }

    #[test]
    fn equality_ignores_dictionary_order_and_unknown_keys() {
        let first = append_dictionary_uint(Vec::new(), "v", NETWORK_CONFIG_VERSION).unwrap();
        let first = append_dictionary_uint(first, "nwid", NETWORK_ID).unwrap();
        let first = append_dictionary_uint(first, "id", MEMBER).unwrap();
        let first = append_dictionary_entry(first, "n", b"example").unwrap();

        let second = append_dictionary_entry(Vec::new(), "unknown", b"ignored").unwrap();
        let second = append_dictionary_entry(second, "n", b"example").unwrap();
        let second = append_dictionary_uint(second, "id", MEMBER).unwrap();
        let second = append_dictionary_uint(second, "nwid", NETWORK_ID).unwrap();
        let second = append_dictionary_uint(second, "v", NETWORK_CONFIG_VERSION).unwrap();

        let first_config = parse_network_config(&first).unwrap();
        let second_config = parse_network_config(&second).unwrap();
        assert!(first_config.equal(&second_config));
    }

    #[test]
    fn parses_specialists_and_exposes_their_flags() {
        let data = append_dictionary_uint(Vec::new(), "nwid", NETWORK_ID).unwrap();
        let data = append_dictionary_uint(data, "v", NETWORK_CONFIG_VERSION).unwrap();
        let data = append_dictionary_uint(data, "id", MEMBER).unwrap();
        let specialist = SPECIALIST_TYPE_MULTICAST_REPLICATOR | SPECIALIST_TYPE_NETWORK_RELAY | MEMBER;
        let data = append_dictionary_entry(data, "S", &specialist.to_be_bytes()).unwrap();

        let config = parse_network_config(&data).unwrap();
        let want = Address::new(MEMBER);
        assert!(config.is_specialist(want, SPECIALIST_TYPE_MULTICAST_REPLICATOR));
        assert!(config.is_specialist(want, SPECIALIST_TYPE_NETWORK_RELAY));
        assert_eq!(config.specialist_addresses(SPECIALIST_TYPE_MULTICAST_REPLICATOR), vec![want]);
    }

    #[test]
    fn maps_target_names_for_both_toolchain_spellings() {
        for (os, arch, want) in [
            ("darwin", "amd64", "macos/x86_64"),
            ("macos", "x86_64", "macos/x86_64"),
            ("freebsd", "arm64", "bsd/arm64"),
            ("linux", "386", "linux/x86"),
            ("linux", "mips64le", "linux/mips"),
            ("linux", "mips64p32", "linux/mips"),
            ("linux", "riscv64", "linux/riscv"),
            ("linux", "s390x", "linux/s390"),
            ("ios", "arm64", "ios_iphone/arm64"),
            ("plan9", "wasm", "unknown/unknown"),
        ] {
            assert_eq!(zero_tier_target_name(os, arch), want, "{os}/{arch}");
        }
    }

    #[test]
    fn request_metadata_advertises_the_protocol_limits() {
        let metadata = build_network_config_metadata_for("linux", "x86_64").unwrap();
        let dictionary = parse_dictionary(&metadata).unwrap();
        assert_eq!(dictionary.uint("v", 0), NETWORK_CONFIG_VERSION);
        assert_eq!(dictionary.uint("vend", 0), 1);
        assert_eq!(dictionary.uint("pv", 0), PROTOCOL_VERSION);
        assert_eq!(dictionary.uint("majv", 0), NODE_VERSION_MAJOR);
        assert_eq!(dictionary.uint("minv", 0), NODE_VERSION_MINOR);
        assert_eq!(dictionary.uint("revv", 0), NODE_VERSION_REVISION);
        assert_eq!(dictionary.uint("mr", 0), MAX_NETWORK_RULES as u64);
        assert_eq!(dictionary.uint("mc", 0), MAX_NETWORK_CAPABILITIES as u64);
        assert_eq!(dictionary.uint("mcr", 0), MAX_CAPABILITY_RULES as u64);
        assert_eq!(dictionary.uint("mt", 0), MAX_NETWORK_TAGS as u64);
        assert_eq!(dictionary.uint("f", 0), 0);
        assert_eq!(dictionary.uint("revr", 0), 1);
        assert_eq!(dictionary.string("o"), "linux/x86_64");
    }

    #[test]
    fn parses_sso_and_trace_fields() {
        let mut data = append_dictionary_uint(Vec::new(), "nwid", NETWORK_ID).unwrap();
        data = append_dictionary_uint(data, "v", NETWORK_CONFIG_VERSION).unwrap();
        for (key, value) in [
            ("id", "0000001234567890"),
            ("ssoe", "1"),
            ("ssov", "0000000000000001"),
            ("aurl", "https://auth.example/legacy"),
            ("aexpt", "0000018bcfe56800"),
            ("iurl", "https://issuer.example"),
            ("ssoce", "https://central.example"),
            ("sson", "nonce"),
            ("ssos", "state"),
            ("ssocid", "client"),
            ("ssop", "provider"),
            ("tt", "00000046a9a1d071"),
            ("tl", "0000000000000002"),
        ] {
            data = append_dictionary_entry(data, key, value.as_bytes()).unwrap();
        }

        let config = parse_network_config(&data).unwrap();
        assert!(config.sso_enabled);
        assert_eq!(config.sso_version, 1);
        assert_eq!(config.authentication_url, "https://auth.example/legacy");
        assert_eq!(config.issuer_url, "https://issuer.example");
        assert_eq!(config.central_auth_url, "https://central.example");
        assert_eq!(config.sso_nonce, "nonce");
        assert_eq!(config.sso_state, "state");
        assert_eq!(config.sso_client_id, "client");
        assert_eq!(config.sso_provider, "provider");
        assert_eq!(config.remote_trace_target, Address::new(0x0046_a9a1_d071));
        assert_eq!(config.remote_trace_level, 2);
    }

    #[test]
    fn truncates_fixed_length_string_fields() {
        let mut data = append_dictionary_uint(Vec::new(), "nwid", NETWORK_ID).unwrap();
        data = append_dictionary_uint(data, "v", NETWORK_CONFIG_VERSION).unwrap();
        data = append_dictionary_uint(data, "id", MEMBER).unwrap();
        for (key, length) in [
            ("n", MAX_NETWORK_NAME_LENGTH),
            ("aurl", MAX_AUTHENTICATION_URL),
            ("iurl", MAX_AUTHENTICATION_URL),
            ("ssoce", MAX_AUTHENTICATION_URL),
            ("sson", MAX_SSO_NONCE_LENGTH),
            ("ssos", MAX_SSO_STATE_LENGTH),
            ("ssocid", MAX_SSO_CLIENT_ID_LENGTH),
            ("ssop", MAX_SSO_PROVIDER_LENGTH),
        ] {
            data = append_dictionary_entry(data, key, &vec![b'x'; length + 10]).unwrap();
        }
        data = append_dictionary_entry(data, "ssoe", b"true").unwrap();
        data = append_dictionary_uint(data, "ssov", 1).unwrap();

        let config = parse_network_config(&data).unwrap();
        let lengths = [
            config.name.len(),
            config.authentication_url.len(),
            config.issuer_url.len(),
            config.central_auth_url.len(),
            config.sso_nonce.len(),
            config.sso_state.len(),
            config.sso_client_id.len(),
            config.sso_provider.len(),
        ];
        assert_eq!(
            lengths,
            [
                MAX_NETWORK_NAME_LENGTH,
                MAX_AUTHENTICATION_URL,
                MAX_AUTHENTICATION_URL,
                MAX_AUTHENTICATION_URL,
                MAX_SSO_NONCE_LENGTH,
                MAX_SSO_STATE_LENGTH,
                MAX_SSO_CLIENT_ID_LENGTH,
                MAX_SSO_PROVIDER_LENGTH,
            ]
        );
    }

    #[test]
    fn parses_a_legacy_public_configuration() {
        let mut data = append_dictionary_uint(Vec::new(), "nwid", NETWORK_ID).unwrap();
        data = append_dictionary_uint(data, "id", MEMBER).unwrap();
        data = append_dictionary_entry(data, "p", b"0").unwrap();
        data = append_dictionary_entry(data, "eb", b"1").unwrap();
        data = append_dictionary_entry(data, "v4s", b"192.0.2.10/24,198.51.100.10/24").unwrap();
        data = append_dictionary_entry(data, "et", b"0800,86dd").unwrap();
        data = append_dictionary_entry(data, "ab", b"46a9a1d071").unwrap();

        let config = parse_network_config(&data).unwrap();
        let want_flags = NETWORK_CONFIG_FLAG_ENABLE_BROADCAST | NETWORK_CONFIG_FLAG_ENABLE_IPV6_NDP_EMULATION;
        assert_eq!(config.network_type, NetworkType::PUBLIC);
        assert_eq!(config.flags & want_flags, want_flags);
        assert_eq!(config.assigned.len(), 2);
        assert_eq!(config.rules.len(), 4);
        assert_eq!(config.specialists.len(), 1);
        assert!(config.is_specialist(Address::new(MEMBER), SPECIALIST_TYPE_ACTIVE_BRIDGE));
    }

    #[test]
    fn legacy_ether_types_accept_the_wildcard_and_network_addresses_are_skipped() {
        let mut data = append_dictionary_uint(Vec::new(), "nwid", NETWORK_ID).unwrap();
        data = append_dictionary_uint(data, "id", MEMBER).unwrap();
        data = append_dictionary_entry(data, "v4s", b"192.0.2.0/24,192.0.2.10/24").unwrap();
        data = append_dictionary_entry(data, "et", b"0000,0800").unwrap();

        let config = parse_network_config(&data).unwrap();
        assert_eq!(config.assigned, vec!["192.0.2.10/24".parse::<IpNet>().unwrap()]);
        assert_eq!(config.rules.len(), 3);
        assert_eq!(config.rules[0].rule_type, RULE_ACTION_ACCEPT);
        assert_eq!(config.rules[1].rule_type, RULE_MATCH_ETHER_TYPE);
        assert_eq!(config.rules[1].value, vec![0x08, 0x00]);
        assert_eq!(config.rules[2].rule_type, RULE_ACTION_ACCEPT);
    }

    #[test]
    fn legacy_mtu_is_clamped() {
        for (mtu, want) in [(1u64, MIN_NETWORK_MTU), (u64::from(MAX_NETWORK_MTU) + 1, MAX_NETWORK_MTU)] {
            let data = append_dictionary_uint(Vec::new(), "nwid", NETWORK_ID).unwrap();
            let data = append_dictionary_uint(data, "id", MEMBER).unwrap();
            let data = append_dictionary_uint(data, "mtu", mtu).unwrap();

            assert_eq!(parse_network_config(&data).unwrap().mtu, want);
        }
    }

    #[test]
    fn legacy_private_configuration_parses_its_membership_certificate() {
        let controller = Identity::generate();
        let member = Identity::generate();
        let network_id = controller.address().uint64() << 24 | 0x1234;
        let mut signed = Vec::new();
        for (id, value, max_delta) in
            [(0u64, 1_000_000u64, 0u64), (1, network_id, 0), (2, member.address().uint64(), 0)]
        {
            signed.extend_from_slice(&id.to_be_bytes());
            signed.extend_from_slice(&value.to_be_bytes());
            signed.extend_from_slice(&max_delta.to_be_bytes());
        }
        let signature = controller.sign(&signed).unwrap();
        let legacy = format!("1:{}:{}:{}", hex::encode(&signed), controller.address(), hex::encode(signature));

        let data = append_dictionary_uint(Vec::new(), "nwid", network_id).unwrap();
        let data = append_dictionary_uint(data, "id", member.address().uint64()).unwrap();
        let data = append_dictionary_entry(data, "com", legacy.as_bytes()).unwrap();

        let config = parse_network_config(&data).unwrap();
        assert_eq!(config.network_type, NetworkType::PRIVATE);
        assert!(config.com.as_ref().expect("legacy COM was decoded").verify(&controller));
    }

    #[test]
    fn truncates_fixed_capacity_fields() {
        let mut data = append_dictionary_uint(Vec::new(), "nwid", NETWORK_ID).unwrap();
        data = append_dictionary_uint(data, "v", NETWORK_CONFIG_VERSION).unwrap();
        data = append_dictionary_uint(data, "id", MEMBER).unwrap();

        let assigned = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)), 24);
        let mut value = Vec::new();
        for _ in 0..MAX_ASSIGNED_ADDRESSES + 1 {
            value = append_inet_address(value, Some(assigned));
        }
        data = append_dictionary_entry(data, "I", &value).unwrap();

        let mut routes = Vec::new();
        for metric in 0..MAX_NETWORK_ROUTES + 1 {
            routes = append_inet_address(
                routes,
                Some(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 0)), 24)),
            );
            routes = append_inet_address(routes, None);
            routes.extend_from_slice(&0u16.to_be_bytes());
            routes.extend_from_slice(&(metric as u16).to_be_bytes());
        }
        data = append_dictionary_entry(data, "RT", &routes).unwrap();

        let mut specialists = Vec::new();
        for index in 0..MAX_NETWORK_SPECIALISTS + 1 {
            specialists.extend_from_slice(&(SPECIALIST_TYPE_NETWORK_RELAY | (index as u64 + 1)).to_be_bytes());
        }
        data = append_dictionary_entry(data, "S", &specialists).unwrap();

        let config = parse_network_config(&data).unwrap();
        assert_eq!(config.assigned.len(), MAX_ASSIGNED_ADDRESSES);
        assert_eq!(config.routes.len(), MAX_NETWORK_ROUTES);
        assert_eq!(config.specialists.len(), MAX_NETWORK_SPECIALISTS);
    }

    #[test]
    fn retains_a_valid_credential_prefix() {
        let data = append_dictionary_uint(Vec::new(), "nwid", NETWORK_ID).unwrap();
        let data = append_dictionary_uint(data, "v", NETWORK_CONFIG_VERSION).unwrap();
        let data = append_dictionary_uint(data, "id", MEMBER).unwrap();

        let mut tags = Vec::new();
        tags.extend_from_slice(&NETWORK_ID.to_be_bytes());
        tags.extend_from_slice(&1u64.to_be_bytes());
        tags.extend_from_slice(&1u32.to_be_bytes());
        tags.extend_from_slice(&2u32.to_be_bytes());
        tags.extend_from_slice(&Address::new(MEMBER).bytes());
        tags.extend_from_slice(&Address::new(1).bytes());
        tags.push(1);
        tags.extend_from_slice(&(96u16).to_be_bytes());
        tags.extend_from_slice(&[0u8; 96]);
        tags.extend_from_slice(&0u16.to_be_bytes());
        tags.push(0xff);
        let data = append_dictionary_entry(data, "TAG", &tags).unwrap();

        let mut capabilities = Vec::new();
        capabilities.extend_from_slice(&NETWORK_ID.to_be_bytes());
        capabilities.extend_from_slice(&3u64.to_be_bytes());
        capabilities.extend_from_slice(&4u32.to_be_bytes());
        capabilities.extend_from_slice(&0u16.to_be_bytes());
        capabilities.push(1);
        capabilities.extend_from_slice(&Address::new(0).bytes());
        capabilities.extend_from_slice(&0u16.to_be_bytes());
        capabilities.push(0xff);
        let data = append_dictionary_entry(data, "CAP", &capabilities).unwrap();

        let config = parse_network_config(&data).unwrap();
        assert_eq!(config.tags.len(), 1);
        assert_eq!(config.tags[0].id, 1);
        assert_eq!(config.capabilities.len(), 1);
        assert_eq!(config.capabilities[0].id, 4);
    }

    #[test]
    fn a_null_route_target_uses_the_gateway_family() {
        let data = append_dictionary_uint(Vec::new(), "nwid", NETWORK_ID).unwrap();
        let data = append_dictionary_uint(data, "v", NETWORK_CONFIG_VERSION).unwrap();
        let data = append_dictionary_uint(data, "id", MEMBER).unwrap();
        let mut routes = append_inet_address(Vec::new(), None);
        routes =
            append_inet_address(routes, Some(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)), 0)));
        routes.extend_from_slice(&7u16.to_be_bytes());
        routes.extend_from_slice(&9u16.to_be_bytes());
        let data = append_dictionary_entry(data, "RT", &routes).unwrap();

        let config = parse_network_config(&data).unwrap();
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].target, "0.0.0.0/0".parse::<IpNet>().unwrap());
        assert_eq!(config.routes[0].via, Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))));
        assert_eq!(config.routes[0].flags, 7);
        assert_eq!(config.routes[0].metric, 9);
    }

    #[test]
    fn rejects_truncated_dns_data() {
        let data = append_dictionary_entry(base_dictionary(), "DNS", &[0u8; 128]).unwrap();
        assert_eq!(parse_network_config(&data).unwrap_err(), InvalidNetworkConfig);
    }
}

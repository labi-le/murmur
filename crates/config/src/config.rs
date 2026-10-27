//! DEVIATIONS: the `trie::domain_set::DomainSet` and `cidr::ipcidr_set::IpCidrSet` ports only
//! expose an inherent `match_domain`/`match_ip`.
//!
//! They do not `impl constant::matcher::{DomainMatcher,IpMatcher}`; this file wraps them locally
//! (`DomainSetMatcher`/`IpCidrSetMatcher`) the same way `component/fakeip/skipper.rs`'s tests do.
//! `ipnet::IpNet` has no serde support at the pinned feature set (see
//! `listener/config/tun.rs::ip_net_vec`); this file's own `opt_ip_net_vec` repeats that CIDR-text
//! logic for its `Option<Vec<IpNet>>`-shaped fields.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use anyhow::{anyhow, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use yaml_serde::{Mapping, Value};

use murmur_adapter::adapter::Proxy;
use murmur_adapter::parser::{parse_proxy, with_tunnel_for_api};
use murmur_adapter_outbound::direct::{new_compatible, new_direct};
use murmur_adapter_outbound::reject::{new_pass, new_pass_rule, new_reject, new_reject_drop};
use murmur_adapter_outboundgroup::parser::{parse_proxy_group, GroupCommonOption};
use murmur_adapter_outboundgroup::selector::{Selector, SelectorOption};
use murmur_adapter_provider::healthcheck::new_health_check;
use murmur_adapter_provider::parser::parse_proxy_provider;
use murmur_adapter_provider::provider::{new_compatible_provider, RESERVED_NAME};
use murmur_common::orderedmap::orderedmap::OrderedMap;
use murmur_common::utils::ranges::{new_unsigned_ranges_from_list, IntRanges};
use murmur_common::utils::slice::to_string_slice;
use murmur_common::yaml::flexible;
use murmur_component::age::age::decrypt_bytes;
use murmur_component::auth::auth::AuthUser;
use murmur_component::cidr::ipcidr_set::IpCidrSet;
use murmur_component::resolver::host::HostValue;
use murmur_component_fakeip::pool::{self, Pool};
use murmur_component_fakeip::skipper::{Skipper, USE_FAKE_IP, USE_REAL_IP};
use murmur_component_geodata as geodata;
use murmur_component_process::find_process_mode::FindProcessMode;
use murmur_component_sniffer::base_sniffer::SnifferConfig;
use murmur_component_sniffer::dispatcher::Config as SnifferDispatcherConfig;
use murmur_component_trie::domain::{valid_and_split_domain, DomainTrie};
use murmur_component_trie::domain_set::{DomainSet, DomainSetBuilder};
use murmur_constant::adapters::{AdapterType, Proxy as CProxy};
use murmur_constant::dns::{DNSMode, FilterMode};
use murmur_constant::listener::InboundListener;
use murmur_constant::matcher::{DomainMatcher, IpMatcher};
use murmur_constant::path::PATH;
use murmur_constant::provider::interface::{ProxyProvider, RuleBehavior, RuleProvider};
use murmur_constant::rule::{Rule, RuleType};
use murmur_constant::sniffer::sniffer::{Type as SnifferType, LIST as SNIFFER_TYPE_LIST};
use murmur_constant::tun::TunStack;
use murmur_constant::version::VERSION;
use murmur_dns::dialer::RESPECT_RULES;
use murmur_dns::resolver::{NameServer, NsNetType, Policy, PARSE_NAME_SERVER};
use murmur_listener::parse::parse_listener;
#[cfg(feature = "extra-protocols")]
use murmur_listener_config::tuic::TuicServer;
use murmur_listener_config::tun::Tun;
use murmur_listener_config::tunnel::Tunnel as ListenerTunnel;
use murmur_log::LogLevel;
use murmur_log::{errorln, infoln, warnln};
use murmur_rules::bundle::bundle::make_bundle_file;
use murmur_rules::parser::parse_rule;
use murmur_rules::provider::parse::parse_rule_provider;
use murmur_rules::provider::provider::set_tunnel as set_rule_provider_tunnel;
use murmur_rules::provider::rule_set::RuleSet;
use murmur_rules::wrapper::wrapper::new_rule_wrapper;
use murmur_rules_common::base::{parse_rule_payload, ParseRuleFunc};
use murmur_rules_common::geoip::GEOIP;
use murmur_rules_common::geosite::GEOSITE;
use murmur_tunnel::mode::TunnelMode;
use murmur_tunnel::tunnel::TUNNEL;

use super::utils::{proxy_groups_dag_sort, validate_dialer_proxies, verify_ip6};

/// Like `ip_net_vec`, but preserving the absent-vs-empty distinction for a `skip-auth-prefixes`
/// / `lan-disallowed-ips`-shaped field: an absent key stays `None` (the merge in
/// `common::yaml::yaml::unmarshal` never touches it, so the pre-populated `None` default survives),
/// an explicit `[]` becomes `Some(vec![])`.
mod opt_ip_net_vec {
    use ipnet::IpNet;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[expect(clippy::ref_option, reason = "serde's derive passes the field as `&Option<T>`")]
    pub(super) fn serialize<S: Serializer>(value: &Option<Vec<IpNet>>, serializer: S) -> Result<S::Ok, S::Error> {
        let strings = value.as_ref().map(|prefixes| prefixes.iter().map(ToString::to_string).collect::<Vec<_>>());
        strings.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<IpNet>>, D::Error> {
        let strings: Option<Vec<String>> = Option::deserialize(deserializer)?;
        strings
            .map(|values| values.into_iter().map(|s| s.parse().map_err(serde::de::Error::custom)).collect())
            .transpose()
    }
}

/// `ipnet::IpNet` has no `serde` support at the pinned feature set; this serializes it as CIDR
/// text for `Vec<IpNet>` fields.
mod ip_net_vec {
    use ipnet::IpNet;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(value: &[IpNet], serializer: S) -> Result<S::Ok, S::Error> {
        let strings: Vec<String> = value.iter().map(ToString::to_string).collect();
        strings.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<IpNet>, D::Error> {
        let strings = Vec::<String>::deserialize(deserializer)?;
        strings.into_iter().map(|s| s.parse().map_err(serde::de::Error::custom)).collect()
    }
}

/// Address text serialization for `loopback-address`.
mod ip_addr_vec {
    use std::net::IpAddr;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(value: &[IpAddr], serializer: S) -> Result<S::Ok, S::Error> {
        let strings: Vec<String> = value.iter().map(ToString::to_string).collect();
        strings.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<IpAddr>, D::Error> {
        let strings = Vec::<String>::deserialize(deserializer)?;
        strings.iter().map(|s| s.parse().map_err(serde::de::Error::custom)).collect()
    }
}

/// A `trie::domain_set::DomainSet` adapted to `constant::matcher::DomainMatcher`; see the module
/// doc comment.
struct DomainSetMatcher(DomainSet);

impl DomainMatcher for DomainSetMatcher {
    fn match_domain(&self, domain: &str) -> bool {
        self.0.match_domain(domain)
    }
}

/// A `cidr::ipcidr_set::IpCidrSet` adapted to `constant::matcher::IpMatcher`; see the module doc
/// comment.
struct IpCidrSetMatcher(IpCidrSet);

impl IpMatcher for IpCidrSetMatcher {
    fn match_ip(&self, ip: IpAddr) -> bool {
        self.0.match_ip(ip)
    }
}

/// `General` config.
#[expect(clippy::struct_excessive_bools, reason = "the flags mirror the configuration keys one for one")]
pub struct General {
    pub inbound: Inbound,
    pub mode: TunnelMode,
    pub unified_delay: bool,
    pub log_level: LogLevel,
    pub ipv6: bool,
    pub interface: String,
    pub routing_mark: i32,
    pub geo_x_url: GeoXUrl,
    pub geo_auto_update: bool,
    pub geo_update_interval: i32,
    pub geodata_mode: bool,
    pub geodata_loader: String,
    pub geosite_matcher: String,
    pub tcp_concurrent: bool,
    pub find_process_mode: FindProcessMode,
    pub sniffing: bool,
    pub global_ua: String,
    pub etag_support: bool,
    pub keep_alive_idle: i32,
    pub keep_alive_interval: i32,
    pub disable_keep_alive: bool,
}

/// `Inbound` config: promoted onto `General` through struct embedding; the same read access is
/// exposed through `Deref`/`DerefMut`.
pub struct Inbound {
    pub port: i32,
    pub socks_port: i32,
    pub redir_port: i32,
    pub tproxy_port: i32,
    pub mixed_port: i32,
    #[cfg(feature = "extra-protocols")]
    pub tuic_server: TuicServer,
    pub tun: Tun,
    #[cfg(feature = "extra-protocols")]
    pub shadow_socks_config: String,
    pub vmess_config: String,
    pub authentication: Vec<String>,
    pub skip_auth_prefixes: Option<Vec<IpNet>>,
    pub lan_allowed_ips: Option<Vec<IpNet>>,
    pub lan_dis_allowed_ips: Option<Vec<IpNet>>,
    pub allow_lan: bool,
    pub bind_address: String,
    pub inbound_tfo: bool,
    pub inbound_mptcp: bool,
}

/// `GeoXUrl` config.
#[derive(Clone, Debug, Default, Serialize)]
pub struct GeoXUrl {
    #[serde(rename = "geo-ip")]
    pub geo_ip: String,
    #[serde(rename = "mmdb")]
    pub mmdb: String,
    #[serde(rename = "asn")]
    pub asn: String,
    #[serde(rename = "geo-site")]
    pub geo_site: String,
}

/// `Controller` config.
pub struct Controller {
    pub external_controller: String,
    pub external_controller_tls: String,
    pub external_controller_unix: String,
    pub external_controller_pipe: String,
    pub external_controller_routing_mark: i32,
    pub external_ui: String,
    pub external_ui_url: String,
    pub external_ui_name: String,
    pub external_doh_server: String,
    pub secret: String,
    pub cors: Cors,
}

#[derive(Debug)]
pub struct Cors {
    pub allow_origins: Vec<String>,
    pub allow_private_network: bool,
}

/// `Experimental` config.
#[derive(Debug)]
pub struct Experimental {
    pub quic_go_disable_gso: bool,
    pub quic_go_disable_ecn: bool,
    pub ip4p_enable: bool,
}

/// `IPTables` config.
#[derive(Debug)]
pub struct IPTables {
    pub enable: bool,
    pub inbound_interface: String,
    pub bypass: Vec<String>,
    pub dns_redirect: bool,
}

/// `NTP` config.
#[derive(Debug)]
pub struct NTP {
    pub enable: bool,
    pub server: String,
    pub port: i32,
    pub interval: i32,
    pub dialer_proxy: String,
    pub write_to_system: bool,
}

/// `DNS` config.
#[expect(clippy::struct_excessive_bools, reason = "the flags mirror the configuration keys one for one")]
#[derive(Default)]
pub struct DNS {
    pub enable: bool,
    pub prefer_h3: bool,
    pub ipv6: bool,
    pub ipv6_timeout: u32,
    pub use_hosts: bool,
    pub use_system_hosts: bool,
    pub name_server: Vec<NameServer>,
    pub fallback: Vec<NameServer>,
    pub fallback_ip_filter: Vec<Arc<dyn IpMatcher>>,
    pub fallback_domain_filter: Vec<Arc<dyn DomainMatcher>>,
    pub fallback_lazy_query: bool,
    pub listen: String,
    pub listen_routing_mark: i32,
    pub enhanced_mode: DNSMode,
    pub default_nameserver: Vec<NameServer>,
    pub cache_algorithm: String,
    pub cache_max_size: i32,
    pub fake_ip_range: Option<IpNet>,
    pub fake_ip_pool: Option<Pool>,
    pub fake_ip_range6: Option<IpNet>,
    pub fake_ip_pool6: Option<Pool>,
    pub fake_ip_skipper: Option<Skipper>,
    pub fake_ip_ttl: i32,
    pub name_server_policy: Vec<Policy>,
    pub proxy_server_nameserver: Vec<NameServer>,
    pub proxy_server_policy: Vec<Policy>,
    pub direct_nameserver: Vec<NameServer>,
    pub direct_follow_policy: bool,
}

/// `Profile` config.
#[derive(Clone, Copy, Debug, Default)]
pub struct Profile {
    pub store_selected: bool,
    pub store_fake_ip: bool,
}

/// `TLS` config.
#[derive(Clone, Debug, Default)]
pub struct TLS {
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
    pub custom_trust_cert: Vec<String>,
}

/// `clash-for-android` config: the Android client's settings carried in the same profile.
#[derive(Clone, Debug, Default)]
pub struct ClashForAndroid {
    pub append_system_dns: bool,
    pub ui_subtitle_pattern: String,
}

/// `Config` is the murmur config manager.
pub struct Config {
    pub general: General,
    pub controller: Controller,
    pub experimental: Experimental,
    pub iptables: IPTables,
    pub ntp: NTP,
    pub dns: DNS,
    pub hosts: DomainTrie<HostValue>,
    pub profile: Profile,
    pub rules: Vec<Arc<dyn Rule>>,
    pub sub_rules: HashMap<String, Vec<Arc<dyn Rule>>>,
    pub users: Vec<AuthUser>,
    pub proxies: HashMap<String, Arc<dyn CProxy>>,
    pub listeners: HashMap<String, Arc<dyn InboundListener>>,
    pub providers: HashMap<String, Arc<dyn ProxyProvider>>,
    pub rule_providers: HashMap<String, Arc<dyn RuleProvider>>,
    pub tunnels: Vec<ListenerTunnel>,
    pub sniffer: SnifferDispatcherConfig,
    pub tls: TLS,
    pub clash_for_android: ClashForAndroid,
}

impl std::fmt::Debug for General {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("General")
            .field("inbound", &self.inbound)
            .field("unified_delay", &self.unified_delay)
            .field("ipv6", &self.ipv6)
            .field("interface", &self.interface)
            .field("routing_mark", &self.routing_mark)
            .field("tcp_concurrent", &self.tcp_concurrent)
            .field("global_ua", &self.global_ua)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Inbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbound")
            .field("port", &self.port)
            .field("socks_port", &self.socks_port)
            .field("redir_port", &self.redir_port)
            .field("tproxy_port", &self.tproxy_port)
            .field("mixed_port", &self.mixed_port)
            .field("allow_lan", &self.allow_lan)
            .field("bind_address", &self.bind_address)
            .field("inbound_tfo", &self.inbound_tfo)
            .field("inbound_mptcp", &self.inbound_mptcp)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Controller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controller")
            .field("external_controller", &self.external_controller)
            .field("external_ui", &self.external_ui)
            .field("external_controller_routing_mark", &self.external_controller_routing_mark)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for DNS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DNS")
            .field("enable", &self.enable)
            .field("ipv6", &self.ipv6)
            .field("listen", &self.listen)
            .field("cache_algorithm", &self.cache_algorithm)
            .field("cache_max_size", &self.cache_max_size)
            .field("fake_ip_ttl", &self.fake_ip_ttl)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("general", &self.general)
            .field("controller", &self.controller)
            .field("experimental", &self.experimental)
            .field("iptables", &self.iptables)
            .field("ntp", &self.ntp)
            .field("dns", &self.dns)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawCors {
    #[serde(rename = "allow-origins", default)]
    pub allow_origins: Vec<String>,
    #[serde(rename = "allow-private-network", default)]
    pub allow_private_network: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[expect(clippy::struct_excessive_bools, reason = "the flags mirror the configuration keys one for one")]
pub struct RawDNS {
    #[serde(rename = "enable", default)]
    pub enable: bool,
    #[serde(rename = "prefer-h3", default)]
    pub prefer_h3: bool,
    #[serde(rename = "ipv6", default)]
    pub ipv6: bool,
    #[serde(rename = "ipv6-timeout", default)]
    pub ipv6_timeout: u32,
    #[serde(rename = "use-hosts", default)]
    pub use_hosts: bool,
    #[serde(rename = "use-system-hosts", default)]
    pub use_system_hosts: bool,
    #[serde(rename = "respect-rules", default)]
    pub respect_rules: bool,
    #[serde(rename = "nameserver", default)]
    pub name_server: Vec<String>,
    #[serde(rename = "fallback", default)]
    pub fallback: Vec<String>,
    #[serde(rename = "fallback-filter", default)]
    pub fallback_filter: RawFallbackFilter,
    #[serde(rename = "fallback-lazy-query", default)]
    pub fallback_lazy_query: bool,
    #[serde(rename = "listen", default)]
    pub listen: String,
    #[serde(rename = "listen-routing-mark", default)]
    pub listen_routing_mark: i32,
    #[serde(rename = "enhanced-mode", default)]
    pub enhanced_mode: DNSMode,
    #[serde(rename = "fake-ip-range", default)]
    pub fake_ip_range: String,
    #[serde(rename = "fake-ip-range6", default)]
    pub fake_ip_range6: String,
    #[serde(rename = "fake-ip-filter", default)]
    pub fake_ip_filter: Vec<String>,
    #[serde(rename = "fake-ip-filter-mode", default)]
    pub fake_ip_filter_mode: FilterMode,
    #[serde(rename = "fake-ip-ttl", default)]
    pub fake_ip_ttl: i32,
    #[serde(rename = "default-nameserver", default)]
    pub default_nameserver: Vec<String>,
    #[serde(rename = "cache-algorithm", default)]
    pub cache_algorithm: String,
    #[serde(rename = "cache-max-size", default)]
    pub cache_max_size: i32,
    #[serde(rename = "nameserver-policy", default)]
    pub name_server_policy: Option<OrderedMap<String, Value>>,
    #[serde(rename = "proxy-server-nameserver", default)]
    pub proxy_server_nameserver: Vec<String>,
    #[serde(rename = "proxy-server-nameserver-policy", default)]
    pub proxy_server_nameserver_policy: Option<OrderedMap<String, Value>>,
    #[serde(rename = "direct-nameserver", default)]
    pub direct_nameserver: Vec<String>,
    #[serde(rename = "direct-nameserver-follow-policy", default)]
    pub direct_nameserver_follow_policy: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawFallbackFilter {
    #[serde(rename = "geoip", default)]
    pub geo_ip: bool,
    #[serde(rename = "geoip-code", default)]
    pub geo_ip_code: String,
    #[serde(rename = "ipcidr", default)]
    pub ip_cidr: Vec<String>,
    #[serde(rename = "domain", default)]
    pub domain: Vec<String>,
    #[serde(rename = "geosite", default)]
    pub geo_site: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawClashForAndroid {
    #[serde(rename = "append-system-dns", default)]
    pub append_system_dns: bool,
    #[serde(rename = "ui-subtitle-pattern", default)]
    pub ui_subtitle_pattern: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawNTP {
    #[serde(rename = "enable", default)]
    pub enable: bool,
    #[serde(rename = "server", default)]
    pub server: String,
    #[serde(rename = "port", default)]
    pub port: i32,
    #[serde(rename = "interval", default)]
    pub interval: i32,
    #[serde(rename = "dialer-proxy", default)]
    pub dialer_proxy: String,
    #[serde(rename = "write-to-system", default)]
    pub write_to_system: bool,
}

/// `parse_tun` maps it into the tun config handed to the listener, and a disabled section is
/// parsed, stored and rendered back through `/configs` field for field.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[expect(clippy::struct_excessive_bools, reason = "the flags mirror the configuration keys one for one")]
pub struct RawTun {
    #[serde(rename = "enable", default)]
    pub enable: bool,
    #[serde(rename = "device", default)]
    pub device: String,
    #[serde(rename = "stack", default)]
    pub stack: TunStack,
    #[serde(rename = "dns-hijack", default)]
    pub dns_hijack: Option<Vec<String>>,
    #[serde(rename = "auto-route", default)]
    pub auto_route: bool,
    #[serde(rename = "auto-detect-interface", default)]
    pub auto_detect_interface: bool,
    #[serde(rename = "mtu", default)]
    pub mtu: u32,
    #[serde(rename = "gso", default)]
    pub gso: bool,
    #[serde(rename = "gso-max-size", default)]
    pub gso_max_size: u32,
    #[serde(rename = "inet6-address", default, with = "ip_net_vec")]
    pub inet6_address: Vec<IpNet>,
    #[serde(rename = "iproute2-table-index", default)]
    pub iproute2_table_index: i64,
    #[serde(rename = "iproute2-rule-index", default)]
    pub iproute2_rule_index: i64,
    #[serde(rename = "auto-redirect", default)]
    pub auto_redirect: bool,
    #[serde(rename = "auto-redirect-input-mark", default)]
    pub auto_redirect_input_mark: u32,
    #[serde(rename = "auto-redirect-output-mark", default)]
    pub auto_redirect_output_mark: u32,
    #[serde(rename = "auto-redirect-iproute2-fallback-rule-index", default)]
    pub auto_redirect_iproute2_fallback_rule_index: i64,
    #[serde(rename = "loopback-address", default, with = "ip_addr_vec")]
    pub loopback_address: Vec<IpAddr>,
    #[serde(rename = "strict-route", default)]
    pub strict_route: bool,
    #[serde(rename = "route-address", default, with = "ip_net_vec")]
    pub route_address: Vec<IpNet>,
    #[serde(rename = "route-address-set", default)]
    pub route_address_set: Vec<String>,
    #[serde(rename = "route-exclude-address", default, with = "ip_net_vec")]
    pub route_exclude_address: Vec<IpNet>,
    #[serde(rename = "route-exclude-address-set", default)]
    pub route_exclude_address_set: Vec<String>,
    #[serde(rename = "include-interface", default)]
    pub include_interface: Vec<String>,
    #[serde(rename = "exclude-interface", default)]
    pub exclude_interface: Vec<String>,
    #[serde(rename = "include-uid", default)]
    pub include_uid: Vec<u32>,
    #[serde(rename = "include-uid-range", default)]
    pub include_uid_range: Vec<String>,
    #[serde(rename = "exclude-uid", default)]
    pub exclude_uid: Vec<u32>,
    #[serde(rename = "exclude-uid-range", default)]
    pub exclude_uid_range: Vec<String>,
    #[serde(rename = "exclude-src-port", default)]
    pub exclude_src_port: Vec<u16>,
    #[serde(rename = "exclude-src-port-range", default)]
    pub exclude_src_port_range: Vec<String>,
    #[serde(rename = "exclude-dst-port", default)]
    pub exclude_dst_port: Vec<u16>,
    #[serde(rename = "exclude-dst-port-range", default)]
    pub exclude_dst_port_range: Vec<String>,
    #[serde(rename = "include-android-user", default)]
    pub include_android_user: Vec<i64>,
    #[serde(rename = "include-package", default)]
    pub include_package: Vec<String>,
    #[serde(rename = "exclude-package", default)]
    pub exclude_package: Vec<String>,
    #[serde(rename = "include-mac-address", default)]
    pub include_mac_address: Vec<String>,
    #[serde(rename = "exclude-mac-address", default)]
    pub exclude_mac_address: Vec<String>,
    #[serde(rename = "endpoint-independent-nat", default)]
    pub endpoint_independent_nat: bool,
    #[serde(rename = "udp-timeout", default)]
    pub udp_timeout: i64,
    #[serde(rename = "icmp-timeout", default)]
    pub icmp_timeout: i64,
    #[serde(rename = "disable-icmp-forwarding", default)]
    pub disable_icmp_forwarding: bool,
    #[serde(rename = "file-descriptor", default)]
    pub file_descriptor: i32,
    #[serde(rename = "inet4-route-address", default, with = "ip_net_vec")]
    pub inet4_route_address: Vec<IpNet>,
    #[serde(rename = "inet6-route-address", default, with = "ip_net_vec")]
    pub inet6_route_address: Vec<IpNet>,
    #[serde(rename = "inet4-route-exclude-address", default, with = "ip_net_vec")]
    pub inet4_route_exclude_address: Vec<IpNet>,
    #[serde(rename = "inet6-route-exclude-address", default, with = "ip_net_vec")]
    pub inet6_route_exclude_address: Vec<IpNet>,
    #[serde(rename = "recvmsgx", default)]
    pub recvmsgx: bool,
    #[serde(rename = "sendmsgx", default)]
    pub sendmsgx: bool,
    #[serde(rename = "processors-per-channel", default)]
    pub processors_per_channel: i32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawTuicServer {
    #[serde(rename = "enable", default)]
    pub enable: bool,
    #[serde(rename = "listen", default)]
    pub listen: String,
    #[serde(rename = "token", default)]
    pub token: Vec<String>,
    #[serde(rename = "users", default)]
    pub users: HashMap<String, String>,
    #[serde(rename = "certificate", default)]
    pub certificate: String,
    #[serde(rename = "private-key", default)]
    pub private_key: String,
    #[serde(rename = "congestion-controller", default)]
    pub congestion_controller: String,
    #[serde(rename = "max-idle-time", default)]
    pub max_idle_time: i32,
    #[serde(rename = "authentication-timeout", default)]
    pub authentication_timeout: i32,
    #[serde(rename = "alpn", default)]
    pub alpn: Vec<String>,
    #[serde(rename = "max-udp-relay-packet-size", default)]
    pub max_udp_relay_packet_size: i32,
    #[serde(rename = "cwnd", default)]
    pub cwnd: i32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawIPTables {
    #[serde(rename = "enable", default)]
    pub enable: bool,
    #[serde(rename = "inbound-interface", default)]
    pub inbound_interface: String,
    #[serde(rename = "bypass", default)]
    pub bypass: Vec<String>,
    #[serde(rename = "dns-redirect", default)]
    pub dns_redirect: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawExperimental {
    #[serde(rename = "fingerprints", default)]
    pub fingerprints: Vec<String>,
    #[serde(rename = "quic-go-disable-gso", default)]
    pub quic_go_disable_gso: bool,
    #[serde(rename = "quic-go-disable-ecn", default)]
    pub quic_go_disable_ecn: bool,
    #[serde(rename = "dialer-ip4p-convert", default)]
    pub ip4p_enable: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawProfile {
    #[serde(rename = "store-selected", default)]
    pub store_selected: bool,
    #[serde(rename = "store-fake-ip", default)]
    pub store_fake_ip: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawGeoXUrl {
    #[serde(rename = "geoip", default)]
    pub geo_ip: String,
    #[serde(rename = "mmdb", default)]
    pub mmdb: String,
    #[serde(rename = "asn", default)]
    pub asn: String,
    #[serde(rename = "geosite", default)]
    pub geo_site: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[expect(clippy::struct_excessive_bools, reason = "the flags mirror the configuration keys one for one")]
pub struct RawSniffer {
    #[serde(rename = "enable", default)]
    pub enable: bool,
    #[serde(rename = "override-destination", default)]
    pub override_dest: bool,
    #[serde(rename = "sniffing", default)]
    pub sniffing: Vec<String>,
    #[serde(rename = "force-domain", default)]
    pub force_domain: Vec<String>,
    #[serde(rename = "skip-src-address", default)]
    pub skip_src_address: Vec<String>,
    #[serde(rename = "skip-dst-address", default)]
    pub skip_dst_address: Vec<String>,
    #[serde(rename = "skip-domain", default)]
    pub skip_domain: Vec<String>,
    #[serde(rename = "port-whitelist", default, deserialize_with = "flexible::string_vec")]
    pub ports: Vec<String>,
    #[serde(rename = "force-dns-mapping", default)]
    pub force_dns_mapping: bool,
    #[serde(rename = "parse-pure-ip", default)]
    pub parse_pure_ip: bool,

    #[serde(rename = "sniff", default)]
    pub sniff: HashMap<String, RawSniffingConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawSniffingConfig {
    #[serde(rename = "ports", default, deserialize_with = "flexible::string_vec")]
    pub ports: Vec<String>,
    #[serde(rename = "override-destination", default)]
    pub override_dest: Option<bool>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawTLS {
    #[serde(rename = "certificate", default)]
    pub certificate: String,
    #[serde(rename = "private-key", default)]
    pub private_key: String,
    #[serde(rename = "client-auth-type", default)]
    pub client_auth_type: String,
    #[serde(rename = "client-auth-cert", default)]
    pub client_auth_cert: String,
    #[serde(rename = "ech-key", default)]
    pub ech_key: String,
    #[serde(rename = "custom-certifactes", default)]
    pub custom_trust_cert: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[expect(clippy::struct_excessive_bools, reason = "the flags mirror the configuration keys one for one")]
pub struct RawConfig {
    #[serde(rename = "port", default)]
    pub port: i32,
    #[serde(rename = "socks-port", default)]
    pub socks_port: i32,
    #[serde(rename = "redir-port", default)]
    pub redir_port: i32,
    #[serde(rename = "tproxy-port", default)]
    pub tproxy_port: i32,
    #[serde(rename = "mixed-port", default)]
    pub mixed_port: i32,
    #[serde(rename = "ss-config", default)]
    pub shadow_socks_config: String,
    #[serde(rename = "vmess-config", default)]
    pub vmess_config: String,
    #[serde(rename = "inbound-tfo", default)]
    pub inbound_tfo: bool,
    #[serde(rename = "inbound-mptcp", default)]
    pub inbound_mptcp: bool,
    #[serde(rename = "authentication", default)]
    pub authentication: Vec<String>,
    #[serde(rename = "skip-auth-prefixes", default, with = "opt_ip_net_vec")]
    pub skip_auth_prefixes: Option<Vec<IpNet>>,
    #[serde(rename = "lan-allowed-ips", default, with = "opt_ip_net_vec")]
    pub lan_allowed_ips: Option<Vec<IpNet>>,
    #[serde(rename = "lan-disallowed-ips", default, with = "opt_ip_net_vec")]
    pub lan_dis_allowed_ips: Option<Vec<IpNet>>,
    #[serde(rename = "allow-lan", default)]
    pub allow_lan: bool,
    #[serde(rename = "bind-address", default)]
    pub bind_address: String,
    #[serde(rename = "mode", default)]
    pub mode: TunnelMode,
    #[serde(rename = "unified-delay", default)]
    pub unified_delay: bool,
    #[serde(rename = "log-level", default)]
    pub log_level: LogLevel,
    #[serde(rename = "ipv6", default)]
    pub ipv6: bool,
    #[serde(rename = "external-controller", default)]
    pub external_controller: String,
    #[serde(rename = "external-controller-routing-mark", default)]
    pub external_controller_routing_mark: i32,
    #[serde(rename = "external-controller-pipe", default)]
    pub external_controller_pipe: String,
    #[serde(rename = "external-controller-unix", default)]
    pub external_controller_unix: String,
    #[serde(rename = "external-controller-tls", default)]
    pub external_controller_tls: String,
    #[serde(rename = "external-controller-cors", default)]
    pub external_controller_cors: RawCors,
    #[serde(rename = "external-ui", default)]
    pub external_ui: String,
    #[serde(rename = "external-ui-url", default)]
    pub external_ui_url: String,
    #[serde(rename = "external-ui-name", default)]
    pub external_ui_name: String,
    #[serde(rename = "external-doh-server", default)]
    pub external_doh_server: String,
    #[serde(rename = "secret", default)]
    pub secret: String,
    #[serde(rename = "interface-name", default)]
    pub interface: String,
    #[serde(rename = "routing-mark", default)]
    pub routing_mark: i32,
    #[serde(rename = "tunnels", default)]
    pub tunnels: Vec<ListenerTunnel>,
    #[serde(rename = "geo-auto-update", default)]
    pub geo_auto_update: bool,
    #[serde(rename = "geo-update-interval", default)]
    pub geo_update_interval: i32,
    #[serde(rename = "geodata-mode", default)]
    pub geodata_mode: bool,
    #[serde(rename = "geodata-loader", default)]
    pub geodata_loader: String,
    #[serde(rename = "geosite-matcher", default)]
    pub geosite_matcher: String,
    #[serde(rename = "tcp-concurrent", default)]
    pub tcp_concurrent: bool,
    #[serde(rename = "find-process-mode", default)]
    pub find_process_mode: FindProcessMode,
    #[serde(rename = "global-client-fingerprint", default)]
    pub global_client_fingerprint: String,
    #[serde(rename = "global-ua", default)]
    pub global_ua: String,
    #[serde(rename = "etag-support", default)]
    pub etag_support: bool,
    #[serde(rename = "keep-alive-idle", default)]
    pub keep_alive_idle: i32,
    #[serde(rename = "keep-alive-interval", default)]
    pub keep_alive_interval: i32,
    #[serde(rename = "disable-keep-alive", default)]
    pub disable_keep_alive: bool,

    #[serde(rename = "proxy-providers", default)]
    pub proxy_provider: HashMap<String, Mapping>,
    #[serde(rename = "rule-providers", default)]
    pub rule_provider: HashMap<String, Mapping>,
    #[serde(rename = "proxies", default)]
    pub proxy: Vec<Mapping>,
    #[serde(rename = "proxy-groups", default)]
    pub proxy_group: Vec<Mapping>,
    #[serde(rename = "rules", default)]
    pub rule: Vec<String>,
    #[serde(rename = "sub-rules", default)]
    pub sub_rules: HashMap<String, Vec<String>>,
    #[serde(rename = "listeners", default)]
    pub listeners: Vec<Mapping>,
    #[serde(rename = "hosts", default)]
    pub hosts: HashMap<String, Value>,
    #[serde(rename = "dns", default)]
    pub dns: RawDNS,
    #[serde(rename = "ntp", default)]
    pub ntp: RawNTP,
    #[serde(rename = "tun", default)]
    pub tun: RawTun,
    #[serde(rename = "tuic-server", default)]
    pub tuic_server: RawTuicServer,
    #[serde(rename = "iptables", default)]
    pub iptables: RawIPTables,
    #[serde(rename = "experimental", default)]
    pub experimental: RawExperimental,
    #[serde(rename = "profile", default)]
    pub profile: RawProfile,
    #[serde(rename = "geox-url", default)]
    pub geo_x_url: RawGeoXUrl,
    #[serde(rename = "sniffer", default)]
    pub sniffer: RawSniffer,
    #[serde(rename = "tls", default)]
    pub tls: RawTLS,

    #[serde(rename = "clash-for-android", default)]
    pub clash_for_android: RawClashForAndroid,
}

/// `Parse` config.
pub async fn parse(buf: &[u8]) -> Result<Config> {
    let raw_cfg = unmarshal_raw_config(buf)?;
    parse_raw_config(raw_cfg).await
}

#[expect(
    clippy::too_many_lines,
    reason = "one literal assembling the default configuration; the length is the key list, not logic"
)]
fn default_raw_config() -> Result<RawConfig> {
    Ok(RawConfig {
        allow_lan: false,
        bind_address: "*".to_owned(),
        lan_allowed_ips: Some(vec!["0.0.0.0/0".parse()?, "::/0".parse()?]),
        ipv6: true,
        mode: TunnelMode::RULE,
        geo_auto_update: false,
        geo_update_interval: 24,
        geodata_mode: geodata::utils::geodata_mode(),
        geodata_loader: "memconservative".to_owned(),
        unified_delay: false,
        authentication: Vec::new(),
        log_level: LogLevel::INFO,
        hosts: HashMap::new(),
        rule: Vec::new(),
        proxy: Vec::new(),
        proxy_group: Vec::new(),
        tcp_concurrent: false,
        find_process_mode: FindProcessMode::FIND_PROCESS_STRICT,
        global_ua: format!("clash.meta/{VERSION}"),
        etag_support: true,
        dns: default_raw_dns(),
        ntp: RawNTP {
            enable: false,
            write_to_system: false,
            server: "time.apple.com".to_owned(),
            port: 123,
            interval: 30,
            dialer_proxy: String::new(),
        },
        tun: default_raw_tun()?,
        tuic_server: RawTuicServer {
            enable: false,
            token: Vec::new(),
            users: HashMap::new(),
            certificate: String::new(),
            private_key: String::new(),
            listen: String::new(),
            congestion_controller: String::new(),
            max_idle_time: 15000,
            authentication_timeout: 1000,
            alpn: vec!["h3".to_owned()],
            max_udp_relay_packet_size: 1500,
            cwnd: 0,
        },
        iptables: RawIPTables {
            enable: false,
            inbound_interface: "lo".to_owned(),
            bypass: Vec::new(),
            dns_redirect: true,
        },
        experimental: RawExperimental {
            quic_go_disable_ecn: true,
            fingerprints: Vec::new(),
            quic_go_disable_gso: false,
            ip4p_enable: false,
        },
        profile: RawProfile { store_selected: true, store_fake_ip: false },
        geo_x_url: RawGeoXUrl {
            mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb".to_owned(),
            asn: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb".to_owned(),
            geo_ip: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat".to_owned(),
            geo_site: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat".to_owned(),
        },
        sniffer: RawSniffer {
            enable: false,
            sniff: HashMap::new(),
            force_domain: Vec::new(),
            skip_domain: Vec::new(),
            ports: Vec::new(),
            force_dns_mapping: true,
            parse_pure_ip: true,
            override_dest: true,
            sniffing: Vec::new(),
            skip_src_address: Vec::new(),
            skip_dst_address: Vec::new(),
        },
        external_ui_url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip".to_owned(),
        external_controller_cors: RawCors { allow_origins: vec!["*".to_owned()], allow_private_network: true },
        port: 0,
        socks_port: 0,
        redir_port: 0,
        tproxy_port: 0,
        mixed_port: 0,
        shadow_socks_config: String::new(),
        vmess_config: String::new(),
        inbound_tfo: false,
        inbound_mptcp: false,
        skip_auth_prefixes: None,
        lan_dis_allowed_ips: None,
        external_controller: String::new(),
        external_controller_routing_mark: 0,
        external_controller_pipe: String::new(),
        external_controller_unix: String::new(),
        external_controller_tls: String::new(),
        external_ui: String::new(),
        external_ui_name: String::new(),
        external_doh_server: String::new(),
        secret: String::new(),
        interface: String::new(),
        routing_mark: 0,
        tunnels: Vec::new(),
        geosite_matcher: String::new(),
        global_client_fingerprint: String::new(),
        keep_alive_idle: 0,
        keep_alive_interval: 0,
        disable_keep_alive: false,
        proxy_provider: HashMap::new(),
        rule_provider: HashMap::new(),
        sub_rules: HashMap::new(),
        listeners: Vec::new(),
        tls: RawTLS::default(),
        clash_for_android: RawClashForAndroid::default(),
    })
}

fn default_raw_dns() -> RawDNS {
    RawDNS {
        enable: false,
        ipv6: false,
        use_hosts: true,
        use_system_hosts: true,
        ipv6_timeout: 100,
        enhanced_mode: DNSMode::DNS_MAPPING,
        fake_ip_range: "198.18.0.1/16".to_owned(),
        fake_ip_ttl: 1,
        fallback_filter: RawFallbackFilter {
            geo_ip: true,
            geo_ip_code: "CN".to_owned(),
            ip_cidr: Vec::new(),
            geo_site: Vec::new(),
            domain: Vec::new(),
        },
        default_nameserver: vec![
            "114.114.114.114".to_owned(),
            "223.5.5.5".to_owned(),
            "8.8.8.8".to_owned(),
            "1.0.0.1".to_owned(),
        ],
        name_server: vec!["https://doh.pub/dns-query".to_owned(), "tls://223.5.5.5:853".to_owned()],
        fake_ip_filter: vec![
            "dns.msftnsci.com".to_owned(),
            "www.msftnsci.com".to_owned(),
            "www.msftconnecttest.com".to_owned(),
        ],
        fake_ip_filter_mode: FilterMode::FILTER_BLACK_LIST,
        prefer_h3: false,
        respect_rules: false,
        fallback: Vec::new(),
        fallback_lazy_query: false,
        listen: String::new(),
        listen_routing_mark: 0,
        fake_ip_range6: String::new(),
        cache_algorithm: String::new(),
        cache_max_size: 0,
        name_server_policy: None,
        proxy_server_nameserver: Vec::new(),
        proxy_server_nameserver_policy: None,
        direct_nameserver: Vec::new(),
        direct_nameserver_follow_policy: false,
    }
}

fn default_raw_tun() -> Result<RawTun> {
    Ok(RawTun {
        stack: TunStack::Gvisor,
        dns_hijack: Some(vec!["0.0.0.0:53".to_owned()]),
        auto_route: true,
        auto_detect_interface: true,
        inet6_address: vec!["fdfe:dcba:9876::1/126".parse()?],
        recvmsgx: true,
        processors_per_channel: 1,
        enable: false,
        device: String::new(),
        mtu: 0,
        gso: false,
        gso_max_size: 0,
        iproute2_table_index: 0,
        iproute2_rule_index: 0,
        auto_redirect: false,
        auto_redirect_input_mark: 0,
        auto_redirect_output_mark: 0,
        auto_redirect_iproute2_fallback_rule_index: 0,
        loopback_address: Vec::new(),
        strict_route: false,
        route_address: Vec::new(),
        route_address_set: Vec::new(),
        route_exclude_address: Vec::new(),
        route_exclude_address_set: Vec::new(),
        include_interface: Vec::new(),
        exclude_interface: Vec::new(),
        include_uid: Vec::new(),
        include_uid_range: Vec::new(),
        exclude_uid: Vec::new(),
        exclude_uid_range: Vec::new(),
        exclude_src_port: Vec::new(),
        exclude_src_port_range: Vec::new(),
        exclude_dst_port: Vec::new(),
        exclude_dst_port_range: Vec::new(),
        include_android_user: Vec::new(),
        include_package: Vec::new(),
        exclude_package: Vec::new(),
        include_mac_address: Vec::new(),
        exclude_mac_address: Vec::new(),
        endpoint_independent_nat: false,
        udp_timeout: 0,
        icmp_timeout: 0,
        disable_icmp_forwarding: false,
        file_descriptor: 0,
        inet4_route_address: Vec::new(),
        inet6_route_address: Vec::new(),
        inet4_route_exclude_address: Vec::new(),
        inet6_route_exclude_address: Vec::new(),
        sendmsgx: false,
    })
}

fn unmarshal_raw_config(buf: &[u8]) -> Result<RawConfig> {
    let mut raw_cfg = default_raw_config()?;

    let buf = decrypt_bytes(buf, &[]).map_err(|err| anyhow!("decrypt config error: {err}"))?;

    murmur_common::yaml::yaml::unmarshal(&buf, &mut raw_cfg)?;

    Ok(raw_cfg)
}

/// Runs the restore closure once the guard drops, on every exit path (success, `?`, or panic
/// unwind).
struct RollbackGuard<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for RollbackGuard<F> {
    fn drop(&mut self) {
        if let Some(rollback) = self.0.take() {
            rollback();
        }
    }
}

/// Registered by `hub::executor` at startup through [`set_general_update_hook`], so the update can
/// be triggered from here while the dependency stays one-way (`hub::executor` depends on `config`).
type GeneralUpdateHook = fn(&General) -> Pin<Box<dyn Future<Output = Box<dyn FnOnce() + Send>> + Send + '_>>;

static GENERAL_UPDATE_HOOK: OnceLock<GeneralUpdateHook> = OnceLock::new();

/// Called once by `hub::executor` before the first [`parse_raw_config`]; see
/// [`GENERAL_UPDATE_HOOK`]'s doc comment.
pub fn set_general_update_hook(hook: GeneralUpdateHook) {
    let _ = GENERAL_UPDATE_HOOK.set(hook);
}

pub async fn parse_raw_config(raw_cfg: RawConfig) -> Result<Config> {
    #[cfg(not(feature = "extra-protocols"))]
    {
        if !raw_cfg.shadow_socks_config.is_empty() {
            return Err(anyhow!("ss-config requires feature extra-protocols"));
        }
        if raw_cfg.tuic_server.enable {
            return Err(anyhow!("tuic-server requires feature extra-protocols"));
        }
    }
    PARSE_NAME_SERVER.get_or_init(|| Box::new(|servers: &[String]| parse_name_server(servers, false, false)));

    infoln!("Start initial configuration in progress");
    let start_time = Instant::now();

    let general = parse_general(&raw_cfg);

    // Rule/rule-provider parsing below relies on geodata settings (mode, loader, geo-x URLs)
    // from this config's `general`, not whatever is currently applied; the hook publishes only
    // those settings and restores them once parsing finishes. It must not publish the candidate
    // routing mode, resolver or dialer settings: traffic threads read those without the
    // configuration lock, and a candidate that is rejected would otherwise be visible to them.
    let hook = GENERAL_UPDATE_HOOK
        .get()
        .ok_or_else(|| anyhow!("hub::executor registers the general-update hook before any config parses"))?;
    let rollback = hook(&general).await;
    let _rollback_guard = RollbackGuard(Some(rollback));

    let controller = parse_controller(&raw_cfg)?;
    let experimental = parse_experimental(&raw_cfg);
    let iptables = parse_iptables(&raw_cfg);
    let ntp = parse_ntp(&raw_cfg);
    let profile = parse_profile(&raw_cfg);
    let tls = parse_tls(&raw_cfg);

    let (proxies, providers) = parse_proxies(&raw_cfg)?;

    let listeners = parse_listeners(&raw_cfg)?;

    infoln!("Geodata Loader mode: {}", geodata::utils::loader_name());
    infoln!("Geosite Matcher implementation: {}", geodata::utils::site_matcher_name());
    let rule_providers = parse_rule_providers(&raw_cfg)?;

    let sub_rules = parse_sub_rules(&raw_cfg, &proxies, &rule_providers)?;

    let rules = parse_rules(&raw_cfg.rule, &proxies, &rule_providers, &sub_rules, "rules")?;

    let hosts = parse_hosts(&raw_cfg)?;

    let mut raw_cfg = raw_cfg;
    parse_ipv6(&mut raw_cfg);

    let dns = parse_dns(&raw_cfg, &rule_providers)?;

    let mut general = general;
    parse_tun(&raw_cfg.tun, &dns, &mut general)?;

    #[cfg(feature = "extra-protocols")]
    parse_tuic_server(&raw_cfg.tuic_server, &mut general);

    let users = parse_authentication(&raw_cfg.authentication);

    let tunnels = raw_cfg.tunnels.clone();
    for t in &tunnels {
        if !t.proxy.is_empty() && !proxies.contains_key(&t.proxy) {
            return Err(anyhow!("tunnel proxy {} not found", t.proxy));
        }
    }

    let sniffer = parse_sniffer(&raw_cfg.sniffer, &rule_providers)?;

    let elapsed_time = start_time.elapsed().as_millis();
    infoln!("Initial configuration complete, total time: {elapsed_time}ms");

    Ok(Config {
        general,
        controller,
        experimental,
        iptables,
        ntp,
        dns,
        hosts,
        profile,
        rules,
        sub_rules,
        users,
        proxies,
        listeners,
        providers,
        rule_providers,
        tunnels,
        sniffer,
        tls,
        clash_for_android: parse_clash_for_android(&raw_cfg.clash_for_android),
    })
}

fn parse_general(cfg: &RawConfig) -> General {
    if !cfg.global_client_fingerprint.is_empty() {
        errorln!("The `global-client-fingerprint` configuration is removed, please set `client-fingerprint` directly on the proxy instead");
    }
    General {
        inbound: Inbound {
            port: cfg.port,
            socks_port: cfg.socks_port,
            redir_port: cfg.redir_port,
            tproxy_port: cfg.tproxy_port,
            mixed_port: cfg.mixed_port,
            #[cfg(feature = "extra-protocols")]
            tuic_server: TuicServer::default(),
            tun: Tun::default(),
            #[cfg(feature = "extra-protocols")]
            shadow_socks_config: cfg.shadow_socks_config.clone(),
            vmess_config: cfg.vmess_config.clone(),
            authentication: Vec::new(),
            skip_auth_prefixes: cfg.skip_auth_prefixes.clone(),
            lan_allowed_ips: cfg.lan_allowed_ips.clone(),
            lan_dis_allowed_ips: cfg.lan_dis_allowed_ips.clone(),
            allow_lan: cfg.allow_lan,
            bind_address: cfg.bind_address.clone(),
            inbound_tfo: cfg.inbound_tfo,
            inbound_mptcp: cfg.inbound_mptcp,
        },
        mode: cfg.mode,
        unified_delay: cfg.unified_delay,
        log_level: cfg.log_level,
        ipv6: cfg.ipv6,
        interface: cfg.interface.clone(),
        routing_mark: cfg.routing_mark,
        geo_x_url: GeoXUrl {
            geo_ip: cfg.geo_x_url.geo_ip.clone(),
            mmdb: cfg.geo_x_url.mmdb.clone(),
            asn: cfg.geo_x_url.asn.clone(),
            geo_site: cfg.geo_x_url.geo_site.clone(),
        },
        geo_auto_update: cfg.geo_auto_update,
        geo_update_interval: cfg.geo_update_interval,
        geodata_mode: cfg.geodata_mode,
        geodata_loader: cfg.geodata_loader.clone(),
        geosite_matcher: cfg.geosite_matcher.clone(),
        tcp_concurrent: cfg.tcp_concurrent,
        find_process_mode: cfg.find_process_mode,
        sniffing: false,
        global_ua: cfg.global_ua.clone(),
        etag_support: cfg.etag_support,
        keep_alive_idle: cfg.keep_alive_idle,
        keep_alive_interval: cfg.keep_alive_interval,
        disable_keep_alive: cfg.disable_keep_alive,
    }
}

fn parse_controller(cfg: &RawConfig) -> Result<Controller> {
    if !cfg.external_ui.is_empty() && !PATH.is_safe_path(&cfg.external_ui) {
        return Err(PATH.err_not_safe_path(&cfg.external_ui).into());
    }
    if !cfg.external_ui_name.is_empty() && !murmur_constant::path::is_local_path(&cfg.external_ui_name) {
        return Err(anyhow!("external UI name is not local: {}", cfg.external_ui_name));
    }
    Ok(Controller {
        external_controller: cfg.external_controller.clone(),
        external_ui: cfg.external_ui.clone(),
        external_ui_url: cfg.external_ui_url.clone(),
        external_ui_name: cfg.external_ui_name.clone(),
        secret: cfg.secret.clone(),
        external_controller_routing_mark: cfg.external_controller_routing_mark,
        external_controller_pipe: cfg.external_controller_pipe.clone(),
        external_controller_unix: cfg.external_controller_unix.clone(),
        external_controller_tls: cfg.external_controller_tls.clone(),
        external_doh_server: cfg.external_doh_server.clone(),
        cors: Cors {
            allow_origins: cfg.external_controller_cors.allow_origins.clone(),
            allow_private_network: cfg.external_controller_cors.allow_private_network,
        },
    })
}

const fn parse_experimental(cfg: &RawConfig) -> Experimental {
    Experimental {
        quic_go_disable_gso: cfg.experimental.quic_go_disable_gso,
        quic_go_disable_ecn: cfg.experimental.quic_go_disable_ecn,
        ip4p_enable: cfg.experimental.ip4p_enable,
    }
}

fn parse_iptables(cfg: &RawConfig) -> IPTables {
    IPTables {
        enable: cfg.iptables.enable,
        inbound_interface: cfg.iptables.inbound_interface.clone(),
        bypass: cfg.iptables.bypass.clone(),
        dns_redirect: cfg.iptables.dns_redirect,
    }
}

fn parse_ntp(cfg: &RawConfig) -> NTP {
    NTP {
        enable: cfg.ntp.enable,
        server: cfg.ntp.server.clone(),
        port: cfg.ntp.port,
        interval: cfg.ntp.interval,
        dialer_proxy: cfg.ntp.dialer_proxy.clone(),
        write_to_system: cfg.ntp.write_to_system,
    }
}

const fn parse_profile(cfg: &RawConfig) -> Profile {
    Profile { store_selected: cfg.profile.store_selected, store_fake_ip: cfg.profile.store_fake_ip }
}

fn parse_tls(cfg: &RawConfig) -> TLS {
    TLS {
        certificate: cfg.tls.certificate.clone(),
        private_key: cfg.tls.private_key.clone(),
        client_auth_type: cfg.tls.client_auth_type.clone(),
        client_auth_cert: cfg.tls.client_auth_cert.clone(),
        ech_key: cfg.tls.ech_key.clone(),
        custom_trust_cert: cfg.tls.custom_trust_cert.clone(),
    }
}

fn parse_clash_for_android(cfg: &RawClashForAndroid) -> ClashForAndroid {
    ClashForAndroid { append_system_dns: cfg.append_system_dns, ui_subtitle_pattern: cfg.ui_subtitle_pattern.clone() }
}

/// Exposed as `pub(crate)` so `config::utils`'s test can call it directly.
pub(crate) fn parse_proxies(
    cfg: &RawConfig,
) -> Result<(HashMap<String, Arc<dyn CProxy>>, HashMap<String, Arc<dyn ProxyProvider>>)> {
    let mut proxies: HashMap<String, Arc<dyn CProxy>> = HashMap::new();
    let mut providers_map: HashMap<String, Arc<dyn ProxyProvider>> = HashMap::new();
    let mut groups_config = cfg.proxy_group.clone();

    let mut proxy_list: Vec<String> = Vec::new();
    let mut all_proxies: Vec<String> = Vec::new();
    let mut has_global = false;

    let tunnel_for_api: Arc<dyn murmur_constant::tunnel::Tunnel> = Arc::new(TUNNEL);

    proxies.insert("DIRECT".to_owned(), Proxy::new(new_direct()));
    proxies.insert("REJECT".to_owned(), Proxy::new(new_reject()));
    proxies.insert("REJECT-DROP".to_owned(), Proxy::new(new_reject_drop()));
    proxies.insert("COMPATIBLE".to_owned(), Proxy::new(new_compatible()));
    proxies.insert("PASS".to_owned(), Proxy::new(new_pass()));
    proxies.insert("PASS-RULE".to_owned(), Proxy::new(new_pass_rule()));
    proxy_list.push("DIRECT".to_owned());
    proxy_list.push("REJECT".to_owned());

    for (idx, mapping) in cfg.proxy.iter().enumerate() {
        let proxy = parse_proxy(mapping, &[with_tunnel_for_api(Arc::clone(&tunnel_for_api))])
            .map_err(|err| anyhow!("proxy {idx}: {err}"))?;

        let name = proxy.name();
        if proxies.contains_key(&name) {
            return Err(anyhow!("proxy {name} is the duplicate name"));
        }
        proxies.insert(name.clone(), proxy);
        proxy_list.push(name.clone());
        all_proxies.push(name);
    }

    for (idx, mapping) in groups_config.iter().enumerate() {
        let Some(group_name) = mapping.get("name").and_then(|v| v.as_str()) else {
            return Err(anyhow!("proxy group {idx}: missing name"));
        };
        if group_name == "GLOBAL" {
            has_global = true;
        }
        proxy_list.push(group_name.to_owned());
    }

    proxy_groups_dag_sort(&mut groups_config)?;

    let mut all_providers: Vec<String> = Vec::new();
    for (name, mapping) in &cfg.proxy_provider {
        if name == RESERVED_NAME {
            return Err(anyhow!("can not defined a provider called `{RESERVED_NAME}`"));
        }

        let pd = parse_proxy_provider(name, mapping, Arc::clone(&tunnel_for_api))
            .map_err(|err| anyhow!("parse proxy provider {name} error: {err:#}"))?;

        providers_map.insert(name.clone(), pd);
        all_providers.push(name.clone());
    }

    all_proxies.sort();
    all_providers.sort();

    for (idx, mapping) in groups_config.iter().enumerate() {
        let group = parse_proxy_group(mapping, &proxies, &mut providers_map, &all_proxies, &all_providers)
            .map_err(|err| anyhow!("proxy group[{idx}]: {err}"))?;

        let group_name = group.name();
        if proxies.contains_key(&group_name) {
            return Err(anyhow!("proxy group {group_name}: the duplicate name"));
        }

        proxies.insert(group_name, Proxy::new(group));
    }

    let mut ps: Vec<Arc<dyn CProxy>> = Vec::new();
    for v in &proxy_list {
        let proxy = proxies.get(v).ok_or_else(|| anyhow!("proxy {v} not found"))?;
        if proxy.type_() == AdapterType::PASS || proxy.type_() == AdapterType::PASS_RULE {
            continue;
        }
        ps.push(Arc::clone(proxy));
    }
    let hc = new_health_check(ps.clone(), "", 5000, 0, true, IntRanges::default());
    let pd = new_compatible_provider(RESERVED_NAME, ps, hc)?;
    providers_map.insert(RESERVED_NAME.to_owned(), Arc::new(pd));

    if !has_global {
        let empty_fallback =
            Arc::clone(proxies.get("COMPATIBLE").ok_or_else(|| anyhow!("COMPATIBLE proxy not found"))?);
        let reserved_provider =
            Arc::clone(providers_map.get(RESERVED_NAME).ok_or_else(|| anyhow!("{RESERVED_NAME} provider not found"))?);
        let global = new_global_group(empty_fallback, reserved_provider)?;
        proxies.insert("GLOBAL".to_owned(), Proxy::new(global));
    }

    validate_dialer_proxies(&proxies)?;

    Ok((proxies, providers_map))
}

fn new_global_group(
    empty_fallback: Arc<dyn CProxy>,
    reserved_provider: Arc<dyn ProxyProvider>,
) -> Result<Arc<Selector>> {
    let global_option = GroupCommonOption {
        name: "GLOBAL".to_owned(),
        type_: String::new(),
        proxies: Vec::new(),
        use_: Vec::new(),
        url: String::new(),
        interval: 0,
        test_timeout: 0,
        max_failed_times: 0,
        empty_fallback: String::new(),
        lazy: false,
        disable_udp: false,
        filter: String::new(),
        exclude_filter: String::new(),
        exclude_type: String::new(),
        expected_status: String::new(),
        include_all: false,
        include_all_proxies: false,
        include_all_providers: false,
        hidden: false,
        icon: String::new(),
    };
    Selector::new(global_option, SelectorOption::default(), empty_fallback, vec![reserved_provider])
        .map_err(|err| anyhow!("new GLOBAL proxy group error: {err}"))
}

fn parse_listeners(cfg: &RawConfig) -> Result<HashMap<String, Arc<dyn InboundListener>>> {
    let mut listeners = HashMap::new();
    for (index, mapping) in cfg.listeners.iter().enumerate() {
        let inbound_listener = parse_listener(mapping).map_err(|err| anyhow!("listener {index}: {err}"))?;

        let name = inbound_listener.name();
        if listeners.contains_key(&name) {
            return Err(anyhow!("listener {name} is the duplicate name"));
        }

        listeners.insert(name, inbound_listener);
    }
    Ok(listeners)
}

fn parse_rule_providers(cfg: &RawConfig) -> Result<HashMap<String, Arc<dyn RuleProvider>>> {
    set_rule_provider_tunnel(Arc::new(TUNNEL));
    let mut rule_providers: HashMap<String, Arc<dyn RuleProvider>> = HashMap::new();
    for (name, mapping) in &cfg.rule_provider {
        let parse_fn: ParseRuleFunc = Arc::new(parse_rule);
        let rp = parse_rule_provider(name, mapping, parse_fn, &make_bundle_file)?;
        rule_providers.insert(name.clone(), rp);
    }
    Ok(rule_providers)
}

fn parse_sub_rules(
    cfg: &RawConfig,
    proxies: &HashMap<String, Arc<dyn CProxy>>,
    rule_providers: &HashMap<String, Arc<dyn RuleProvider>>,
) -> Result<HashMap<String, Vec<Arc<dyn Rule>>>> {
    let mut sub_rules: HashMap<String, Vec<Arc<dyn Rule>>> = HashMap::new();
    for name in cfg.sub_rules.keys() {
        sub_rules.insert(name.clone(), Vec::new());
    }
    for (name, raw_rules) in &cfg.sub_rules {
        if name.is_empty() {
            return Err(anyhow!("sub-rule name is empty"));
        }
        let rules = parse_rules(raw_rules, proxies, rule_providers, &sub_rules, &format!("sub-rules[{name}]"))?;
        sub_rules.insert(name.clone(), rules);
    }

    verify_sub_rule(&sub_rules)?;

    Ok(sub_rules)
}

fn verify_sub_rule(sub_rules: &HashMap<String, Vec<Arc<dyn Rule>>>) -> Result<()> {
    for name in sub_rules.keys() {
        verify_sub_rule_circular_references(name, sub_rules, &[])?;
    }
    Ok(())
}

fn verify_sub_rule_circular_references(
    n: &str,
    sub_rules: &HashMap<String, Vec<Arc<dyn Rule>>>,
    arr: &[String],
) -> Result<()> {
    let mut arr = arr.to_vec();
    arr.push(n.to_owned());

    if let Some(rules) = sub_rules.get(n) {
        for (i, rule) in rules.iter().enumerate() {
            if rule.rule_type() == RuleType::SUB_RULES {
                let adapter = rule.adapter();
                if !sub_rules.contains_key(&adapter) {
                    return Err(anyhow!("sub-rule[{i}:{n}] error: [{adapter}] not found"));
                }
                if arr.iter().any(|v| v == &adapter) {
                    arr.push(adapter);
                    return Err(anyhow!("sub-rule error: circular references [{}]", arr.join("->")));
                }

                verify_sub_rule_circular_references(&adapter, sub_rules, &arr)?;
            }
        }
    }
    Ok(())
}

fn parse_rules(
    rules_config: &[String],
    proxies: &HashMap<String, Arc<dyn CProxy>>,
    rule_providers: &HashMap<String, Arc<dyn RuleProvider>>,
    sub_rules: &HashMap<String, Vec<Arc<dyn Rule>>>,
    format: &str,
) -> Result<Vec<Arc<dyn Rule>>> {
    let mut rules: Vec<Arc<dyn Rule>> = Vec::new();

    for (idx, line) in rules_config.iter().enumerate() {
        let (tp, payload, target, params) = parse_rule_payload(line, true);
        if target.is_empty() {
            return Err(anyhow!("{format}[{idx}] [{line}] error: format invalid"));
        }

        if !proxies.contains_key(&target) {
            if tp != "SUB-RULE" {
                return Err(anyhow!("{format}[{idx}] [{line}] error: proxy [{target}] not found"));
            } else if !sub_rules.contains_key(&target) {
                return Err(anyhow!("{format}[{idx}] [{line}] error: sub-rule [{target}] not found"));
            }
        }

        let parsed = parse_rule(&tp, &payload, &target, &params, sub_rules)
            .map_err(|err| anyhow!("{format}[{idx}] [{line}] error: {err}"))?;

        for name in parsed.provider_names() {
            if !rule_providers.contains_key(&name) {
                return Err(anyhow!("{format}[{idx}] [{line}] error: rule set [{name}] not found"));
            }
        }

        let parsed: Arc<dyn Rule> = if format == "rules" { new_rule_wrapper(parsed) } else { parsed };

        rules.push(parsed);
    }

    Ok(rules)
}

fn parse_hosts(cfg: &RawConfig) -> Result<DomainTrie<HostValue>> {
    let mut tree = DomainTrie::<HostValue>::new();

    let localhost_value = HostValue::by_ips(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).unwrap_or_else(|_| HostValue {
        is_domain: false,
        ips: Vec::new(),
        domain: String::new(),
    });
    if let Err(err) = tree.insert("localhost", localhost_value) {
        errorln!("insert localhost to host error: {err}");
    }

    if !cfg.hosts.is_empty() {
        for (domain, any_value) in &cfg.hosts {
            let mut hosts = to_string_slice(any_value)?;
            if matches!(hosts.as_slice(), [only] if only == "lan") {
                match if_addrs::get_if_addrs() {
                    Err(err) => errorln!("insert lan to host error: {err}"),
                    Ok(addrs) => {
                        hosts = addrs
                            .iter()
                            .filter(|addr| !addr.is_loopback() && !addr.is_link_local())
                            .map(|addr| addr.ip().to_string())
                            .collect();
                    }
                }
            }
            let Ok(value) = HostValue::new(&hosts) else {
                return Err(anyhow!("{any_value:?} is not a valid value"));
            };
            if value.is_domain {
                let mut current = tree.search(&value.domain);
                while let Some(node) = current {
                    if !node.data().is_domain {
                        break;
                    }
                    if node.data().domain == *domain {
                        return Err(anyhow!("{domain}, there is a cycle in domain name mapping"));
                    }
                    let next_domain = node.data().domain.clone();
                    current = tree.search(&next_domain);
                }
            }
            if let Err(err) = tree.insert(domain, value) {
                warnln!("skip invalid hosts entry: {err}");
            }
        }
    }
    tree.optimize();

    Ok(tree)
}

fn net_join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn host_with_default_port(host: &str, def_port: &str) -> Result<String> {
    match murmur_common::net_addr::split_host_port(host) {
        Ok((hostname, port)) => Ok(net_join_host_port(&hostname, &port)),
        Err(murmur_common::net_addr::SplitHostPortError::MissingPort(_)) => {
            let host = format!("{host}:{def_port}");
            let (hostname, port) = murmur_common::net_addr::split_host_port(&host)?;
            Ok(net_join_host_port(&hostname, &port))
        }
        Err(err) => Err(err.into()),
    }
}

fn parse_name_server(servers: &[String], respect_rules: bool, prefer_h3: bool) -> Result<Vec<NameServer>> {
    let mut nameservers: Vec<NameServer> = Vec::new();

    for (idx, server) in servers.iter().enumerate() {
        let server = parse_pure_dns_server(server);
        let u = url::Url::parse(&server).map_err(|err| anyhow!("DNS NameServer[{idx}] format error: {err}"))?;

        let mut proxy_name = String::new();
        let mut params: HashMap<String, String> = HashMap::new();
        if let Some(fragment) = u.fragment() {
            for s in fragment.split('&') {
                if let Some((name, value)) = s.split_once('=') {
                    params.insert(name.to_owned(), value.to_owned());
                } else {
                    s.clone_into(&mut proxy_name);
                }
            }
        }

        let host_and_port = match (u.host_str(), u.port()) {
            (Some(host), Some(port)) => format!("{host}:{port}"),
            (Some(host), None) => host.to_owned(),
            (None, _) => String::new(),
        };

        let (dns_net_type, addr) = resolve_name_server_addr(idx, &u, &server, &host_and_port)?;

        if respect_rules && proxy_name.is_empty() {
            RESPECT_RULES.clone_into(&mut proxy_name);
        }

        let nameserver = NameServer { net: dns_net_type, addr, proxy_adapter: None, proxy_name, params, prefer_h3 };
        if nameservers.iter().any(|existing| existing.equal(&nameserver)) {
            continue;
        }

        nameservers.push(nameserver);
    }
    Ok(nameservers)
}

fn resolve_name_server_addr(
    idx: usize,
    u: &url::Url,
    server: &str,
    host_and_port: &str,
) -> Result<(NsNetType, String)> {
    let mut addr = String::new();
    let mut dns_net_type = NsNetType::Udp;
    let mut err_msg: Option<String> = None;

    match u.scheme() {
        "udp" => match host_with_default_port(host_and_port, "53") {
            Ok(a) => addr = a,
            Err(e) => err_msg = Some(e.to_string()),
        },
        "tcp" => {
            dns_net_type = NsNetType::Tcp;
            match host_with_default_port(host_and_port, "53") {
                Ok(a) => addr = a,
                Err(e) => err_msg = Some(e.to_string()),
            }
        }
        "tls" => {
            dns_net_type = NsNetType::Tls;
            match host_with_default_port(host_and_port, "853") {
                Ok(a) => addr = a,
                Err(e) => err_msg = Some(e.to_string()),
            }
        }
        "http" | "https" => {
            dns_net_type = NsNetType::Https;
            let def_port = if u.scheme() == "http" { "80" } else { "443" };
            match clear_https_addr(u, def_port, host_and_port) {
                Ok(a) => addr = a,
                Err(e) => err_msg = Some(e),
            }
        }
        "quic" => {
            dns_net_type = NsNetType::Quic;
            match host_with_default_port(host_and_port, "853") {
                Ok(a) => addr = a,
                Err(e) => err_msg = Some(e.to_string()),
            }
        }
        "system" => {
            dns_net_type = NsNetType::System;
        }
        "ts" | "tailscale" => {
            host_and_port.clone_into(&mut addr);
            dns_net_type = NsNetType::Tailscale;
            if addr.is_empty() {
                err_msg = Some("missing Tailscale proxy name".to_owned());
            }
        }
        "et" | "easytier" => {
            host_and_port.clone_into(&mut addr);
            dns_net_type = NsNetType::Easytier;
            if addr.is_empty() {
                err_msg = Some("missing EasyTier proxy name".to_owned());
            }
        }
        "dhcp" => {
            server.strip_prefix("dhcp://").unwrap_or(server).clone_into(&mut addr);
            dns_net_type = NsNetType::Dhcp;
            if addr == "system" {
                dns_net_type = NsNetType::System;
                addr = String::new();
            }
        }
        "rcode" => {
            dns_net_type = NsNetType::Rcode;
            host_and_port.clone_into(&mut addr);
            match addr.as_str() {
                "success" | "format_error" | "server_failure" | "name_error" | "not_implemented" | "refused" => {}
                _ => err_msg = Some(format!("unsupported RCode type: {addr}")),
            }
        }
        other => return Err(anyhow!("DNS NameServer[{idx}] unsupport scheme: {other}")),
    }

    if let Some(msg) = err_msg {
        return Err(anyhow!("DNS NameServer[{idx}] format error: {msg}"));
    }

    Ok((dns_net_type, addr))
}

fn clear_https_addr(u: &url::Url, default_port: &str, host_and_port: &str) -> Result<String, String> {
    let host = host_with_default_port(host_and_port, default_port).map_err(|err| err.to_string())?;
    let mut clear_url = format!("{}://", u.scheme());
    if let Some(password) = u.password() {
        let _ = write!(clear_url, "{}:{password}@", u.username());
    } else if !u.username().is_empty() {
        let _ = write!(clear_url, "{}@", u.username());
    }
    clear_url.push_str(&host);
    clear_url.push_str(u.path());
    Ok(clear_url)
}

fn parse_pure_dns_server(server: &str) -> String {
    let add_pre = |server: &str| format!("udp://{server}");

    if server == "system" {
        return "system://".to_owned();
    }

    match server.parse::<IpAddr>() {
        Err(_) => {
            if server.contains("://") {
                server.to_owned()
            } else {
                add_pre(server)
            }
        }
        Ok(ip) => {
            if ip.is_ipv4() {
                add_pre(server)
            } else {
                add_pre(&format!("[{server}]"))
            }
        }
    }
}

fn strip_prefix_ascii_case_insensitive<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        text.get(prefix.len()..)
    } else {
        None
    }
}

fn parse_name_server_policy(
    ns_policy: Option<&OrderedMap<String, Value>>,
    adapter_name: &str,
    rule_providers: &HashMap<String, Arc<dyn RuleProvider>>,
    respect_rules: bool,
    prefer_h3: bool,
) -> Result<Vec<Policy>> {
    let mut policy: Vec<Policy> = Vec::new();

    if let Some(ns_policy) = ns_policy {
        let mut cursor = ns_policy.oldest();
        while let Some(pair) = cursor {
            let k = pair.key().clone();
            let v = pair.value().clone();
            cursor = pair.next();

            let servers = to_string_slice(&v)?;
            let nameservers = parse_name_server(&servers, respect_rules, prefer_h3)?;
            let k_lower = k.to_lowercase();

            if k_lower.contains(',') {
                if let Some(rest) = strip_prefix_ascii_case_insensitive(&k, "geosite:") {
                    for subkey in rest.split(',') {
                        policy.push(Policy {
                            domain: format!("geosite:{subkey}"),
                            matcher: None,
                            name_servers: nameservers.clone(),
                        });
                    }
                } else if let Some(rest) = strip_prefix_ascii_case_insensitive(&k, "rule-set:") {
                    for subkey in rest.split(',') {
                        policy.push(Policy {
                            domain: format!("rule-set:{subkey}"),
                            matcher: None,
                            name_servers: nameservers.clone(),
                        });
                    }
                } else {
                    for subkey in k.split(',') {
                        policy.push(Policy {
                            domain: subkey.to_owned(),
                            matcher: None,
                            name_servers: nameservers.clone(),
                        });
                    }
                }
            } else if let Some(rest) = strip_prefix_ascii_case_insensitive(&k, "geosite:") {
                policy.push(Policy { domain: format!("geosite:{rest}"), matcher: None, name_servers: nameservers });
            } else if let Some(rest) = strip_prefix_ascii_case_insensitive(&k, "rule-set:") {
                policy.push(Policy { domain: format!("rule-set:{rest}"), matcher: None, name_servers: nameservers });
            } else {
                policy.push(Policy { domain: k, matcher: None, name_servers: nameservers });
            }
        }
    }

    for (idx, p) in policy.iter_mut().enumerate() {
        let domain = p.domain.clone();

        if let Some(domain_set_name) = domain.strip_prefix("rule-set:") {
            let matcher = parse_domain_rule_set(domain_set_name, adapter_name, rule_providers)?;
            p.domain = String::new();
            p.matcher = Some(matcher);
        } else if let Some(country) = domain.strip_prefix("geosite:") {
            let matcher: Arc<dyn DomainMatcher> = Arc::new(GEOSITE::new(country, adapter_name)?);
            p.domain = String::new();
            p.matcher = Some(matcher);
        } else if let Err(err) = valid_and_split_domain(&domain) {
            return Err(anyhow!("{adapter_name}[{idx}]: {err}"));
        }
    }

    Ok(policy)
}

fn dns_from_raw(cfg: &RawDNS) -> DNS {
    DNS {
        enable: cfg.enable,
        listen: cfg.listen.clone(),
        listen_routing_mark: cfg.listen_routing_mark,
        prefer_h3: cfg.prefer_h3,
        ipv6_timeout: cfg.ipv6_timeout,
        ipv6: cfg.ipv6,
        use_hosts: cfg.use_hosts,
        use_system_hosts: cfg.use_system_hosts,
        enhanced_mode: cfg.enhanced_mode,
        cache_algorithm: cfg.cache_algorithm.clone(),
        cache_max_size: cfg.cache_max_size,
        name_server: Vec::new(),
        fallback: Vec::new(),
        fallback_ip_filter: Vec::new(),
        fallback_domain_filter: Vec::new(),
        fallback_lazy_query: false,
        default_nameserver: Vec::new(),
        fake_ip_range: None,
        fake_ip_pool: None,
        fake_ip_range6: None,
        fake_ip_pool6: None,
        fake_ip_skipper: None,
        fake_ip_ttl: 0,
        name_server_policy: Vec::new(),
        proxy_server_nameserver: Vec::new(),
        proxy_server_policy: Vec::new(),
        direct_nameserver: Vec::new(),
        direct_follow_policy: false,
    }
}

fn parse_dns(raw_cfg: &RawConfig, rule_providers: &HashMap<String, Arc<dyn RuleProvider>>) -> Result<DNS> {
    let cfg = &raw_cfg.dns;
    if cfg.enable && cfg.name_server.is_empty() {
        return Err(anyhow!("if DNS configuration is turned on, NameServer cannot be empty"));
    }

    if cfg.respect_rules && cfg.proxy_server_nameserver.is_empty() {
        return Err(anyhow!(
            "if \u{201c}respect-rules\u{201d} is turned on, \u{201c}proxy-server-nameserver\u{201d} cannot be empty"
        ));
    }

    let mut dns_cfg = dns_from_raw(cfg);

    dns_cfg.name_server = parse_name_server(&cfg.name_server, cfg.respect_rules, cfg.prefer_h3)?;
    dns_cfg.fallback = parse_name_server(&cfg.fallback, cfg.respect_rules, cfg.prefer_h3)?;
    dns_cfg.name_server_policy = parse_name_server_policy(
        cfg.name_server_policy.as_ref(),
        "dns.nameserver-policy",
        rule_providers,
        cfg.respect_rules,
        cfg.prefer_h3,
    )?;

    dns_cfg.proxy_server_nameserver = parse_name_server(&cfg.proxy_server_nameserver, false, cfg.prefer_h3)?;
    dns_cfg.proxy_server_policy = parse_name_server_policy(
        cfg.proxy_server_nameserver_policy.as_ref(),
        "dns.proxy-server-nameserver-policy",
        rule_providers,
        false,
        cfg.prefer_h3,
    )?;
    if !dns_cfg.proxy_server_policy.is_empty() && dns_cfg.proxy_server_nameserver.is_empty() {
        return Err(anyhow!("disallow empty `proxy-server-nameserver` when `proxy-server-nameserver-policy` is set"));
    }

    dns_cfg.direct_nameserver = parse_name_server(&cfg.direct_nameserver, false, cfg.prefer_h3)?;
    dns_cfg.direct_follow_policy = cfg.direct_nameserver_follow_policy;

    if cfg.default_nameserver.is_empty() {
        return Err(anyhow!("default nameserver should have at least one nameserver"));
    }
    dns_cfg.default_nameserver = parse_name_server(&cfg.default_nameserver, false, cfg.prefer_h3)?;
    validate_default_nameserver(&dns_cfg)?;

    // `clash-for-android.append-system-dns` asks for the device resolver alongside the configured
    // default nameservers; the port honours it rather than dropping the parsed value.
    if raw_cfg.clash_for_android.append_system_dns
        && !dns_cfg.default_nameserver.iter().any(|ns| ns.net == NsNetType::System)
    {
        dns_cfg.default_nameserver.extend(parse_name_server(&["system".to_owned()], false, cfg.prefer_h3)?);
    }

    if !cfg.fake_ip_range.is_empty() {
        let fake_ip_range: IpNet = cfg.fake_ip_range.parse()?;
        if !matches!(fake_ip_range, IpNet::V4(_)) {
            return Err(anyhow!("dns.fake-ip-range must be a IPv4 prefix"));
        }
        dns_cfg.fake_ip_range = Some(fake_ip_range);
    }

    if !cfg.fake_ip_range6.is_empty() {
        let fake_ip_range6: IpNet = cfg.fake_ip_range6.parse()?;
        if !matches!(fake_ip_range6, IpNet::V6(_)) {
            return Err(anyhow!("dns.fake-ip-range6 must be a IPv6 prefix"));
        }
        dns_cfg.fake_ip_range6 = Some(fake_ip_range6);
    }

    if cfg.enhanced_mode == DNSMode::DNS_FAKE_IP {
        parse_dns_fake_ip(cfg, &mut dns_cfg, raw_cfg, rule_providers)?;
    }

    if !cfg.fallback.is_empty() {
        parse_dns_fallback_filter(cfg, &mut dns_cfg)?;
    }

    Ok(dns_cfg)
}

fn validate_default_nameserver(dns_cfg: &DNS) -> Result<()> {
    for ns in &dns_cfg.default_nameserver {
        if ns.net == NsNetType::System {
            continue;
        }
        let is_pure_ip = match murmur_common::net_addr::split_host_port(&ns.addr) {
            Ok((host, _)) => host.parse::<IpAddr>().is_ok(),
            Err(_) => false,
        };
        if !is_pure_ip {
            let u = url::Url::parse(&ns.addr).ok();
            let ok = u.is_some_and(|u| {
                let host = u.host_str().unwrap_or_default();
                if host.parse::<IpAddr>().is_ok() {
                    return true;
                }
                match murmur_common::net_addr::split_host_port(host) {
                    Ok((ip, _)) => ip.parse::<IpAddr>().is_ok(),
                    Err(_) => false,
                }
            });
            if !ok {
                return Err(anyhow!("default nameserver should be pure IP"));
            }
        }
    }
    Ok(())
}

fn parse_dns_fake_ip(
    cfg: &RawDNS,
    dns_cfg: &mut DNS,
    raw_cfg: &RawConfig,
    rule_providers: &HashMap<String, Arc<dyn RuleProvider>>,
) -> Result<()> {
    let fake_ip_domain_set_builder =
        if cfg.fake_ip_filter_mode != FilterMode::FILTER_RULE && !dns_cfg.fallback.is_empty() {
            let mut builder = DomainSetBuilder::default();
            for fb in &dns_cfg.fallback {
                if fb.addr.parse::<IpAddr>().is_ok() {
                    continue;
                }
                if let Err(err) = builder.insert(&fb.addr) {
                    warnln!("skip fallback nameserver in fake-ip filter: {err}");
                }
            }
            Some(builder)
        } else {
            None
        };

    let mut skipper = Skipper { rules: Vec::new(), host: Vec::new(), mode: cfg.fake_ip_filter_mode };

    if cfg.fake_ip_filter_mode == FilterMode::FILTER_RULE {
        skipper.rules = parse_fake_ip_rules(&cfg.fake_ip_filter, rule_providers)?;
    } else {
        skipper.host =
            parse_domain(&cfg.fake_ip_filter, fake_ip_domain_set_builder, "dns.fake-ip-filter", rule_providers)?;
    }

    dns_cfg.fake_ip_ttl = cfg.fake_ip_ttl;

    if let Some(fake_ip_range) = dns_cfg.fake_ip_range {
        let options = pool::Options { ip_net: fake_ip_range, size: 1000, persistence: raw_cfg.profile.store_fake_ip };
        dns_cfg.fake_ip_pool = Some(pool::new(options)?);
    }

    if let Some(fake_ip_range6) = dns_cfg.fake_ip_range6 {
        let options = pool::Options { ip_net: fake_ip_range6, size: 1000, persistence: raw_cfg.profile.store_fake_ip };
        dns_cfg.fake_ip_pool6 = Some(pool::new(options)?);
    }

    dns_cfg.fake_ip_skipper = Some(skipper);

    if dns_cfg.fake_ip_pool.is_none() && dns_cfg.fake_ip_pool6.is_none() {
        return Err(anyhow!("disallow `fake-ip-range` and `fake-ip-range6` both empty with fake-ip mode"));
    }

    Ok(())
}

fn parse_dns_fallback_filter(cfg: &RawDNS, dns_cfg: &mut DNS) -> Result<()> {
    if cfg.fallback_filter.geo_ip {
        let geoip = Arc::new(
            GEOIP::new(&cfg.fallback_filter.geo_ip_code, "dns.fallback-filter.geoip", false, true)
                .map_err(|err| anyhow!("load GeoIP dns fallback filter error, {err}"))?,
        );
        dns_cfg.fallback_ip_filter.push(geoip.dns_fallback_filter());
    }
    if !cfg.fallback_filter.ip_cidr.is_empty() {
        let mut cidr_set = IpCidrSet::new_ip_cidr_set();
        for (idx, ipcidr) in cfg.fallback_filter.ip_cidr.iter().enumerate() {
            cidr_set
                .add_ip_cidr_for_string(ipcidr)
                .map_err(|err| anyhow!("DNS FallbackIP[{idx}] format error: {err}"))?;
        }
        cidr_set.merge()?;
        dns_cfg.fallback_ip_filter.push(Arc::new(IpCidrSetMatcher(cidr_set)));
    }
    if !cfg.fallback_filter.domain.is_empty() {
        let mut domain_set_builder = DomainSetBuilder::default();
        for (idx, domain) in cfg.fallback_filter.domain.iter().enumerate() {
            domain_set_builder
                .insert(domain)
                .map_err(|err| anyhow!("DNS FallbackDomain[{idx}] format error: {err}"))?;
        }
        if let Some(set) = domain_set_builder.build() {
            dns_cfg.fallback_domain_filter.push(Arc::new(DomainSetMatcher(set)));
        }
    }
    if !cfg.fallback_filter.geo_site.is_empty() {
        warnln!("replace fallback-filter.geosite with nameserver-policy, it will be removed in the future");
        for (idx, geo_site) in cfg.fallback_filter.geo_site.iter().enumerate() {
            let matcher = GEOSITE::new(geo_site, "dns.fallback-filter.geosite")
                .map_err(|err| anyhow!("DNS FallbackGeosite[{idx}] format error: {err}"))?;
            dns_cfg.fallback_domain_filter.push(Arc::new(matcher));
        }
    }
    dns_cfg.fallback_lazy_query = cfg.fallback_lazy_query;
    Ok(())
}

fn parse_fake_ip_rules(
    raw_rules: &[String],
    rule_providers: &HashMap<String, Arc<dyn RuleProvider>>,
) -> Result<Vec<Arc<dyn Rule>>> {
    let mut rules: Vec<Arc<dyn Rule>> = Vec::new();

    for (idx, line) in raw_rules.iter().enumerate() {
        let (tp, payload, action, params) = parse_rule_payload(line, true);

        let action = action.to_lowercase();
        if action != USE_FAKE_IP && action != USE_REAL_IP {
            return Err(anyhow!(
                "dns.fake-ip-filter[{idx}] [{line}] error: invalid action '{action}', must be 'fake-ip' or 'real-ip'"
            ));
        }

        if tp == "RULE-SET" {
            match rule_providers.get(&payload) {
                None => {
                    return Err(anyhow!("dns.fake-ip-filter[{idx}] [{line}] error: rule-set '{payload}' not found"))
                }
                Some(rp) => match rp.behavior() {
                    RuleBehavior::IPCIDR => {
                        return Err(anyhow!(
                            "dns.fake-ip-filter[{idx}] [{line}] error: rule-set behavior is {}, must be domain or classical",
                            rp.behavior()
                        ));
                    }
                    RuleBehavior::CLASSICAL => {
                        warnln!(
                            "{} provider is {}, only matching domain rules in fake-ip-filter",
                            rp.name(),
                            rp.behavior()
                        );
                    }
                    _ => {}
                },
            }
        }

        let parsed = parse_rule(&tp, &payload, &action, &params, &HashMap::new())
            .map_err(|err| anyhow!("dns.fake-ip-filter[{idx}] [{line}] error: {err}"))?;

        if !is_domain_rule(parsed.rule_type()) && parsed.rule_type() != RuleType::MATCH {
            return Err(anyhow!(
                "dns.fake-ip-filter[{idx}] [{line}] error: rule type '{tp}' not supported, only domain-based rules allowed"
            ));
        }

        rules.push(parsed);
    }

    Ok(rules)
}

const fn is_domain_rule(rt: RuleType) -> bool {
    matches!(
        rt,
        RuleType::DOMAIN
            | RuleType::DOMAIN_SUFFIX
            | RuleType::DOMAIN_KEYWORD
            | RuleType::DOMAIN_REGEX
            | RuleType::DOMAIN_WILDCARD
            | RuleType::GEOSITE
            | RuleType::RULE_SET
    )
}

fn parse_authentication(raw_records: &[String]) -> Vec<AuthUser> {
    let mut users = Vec::new();
    for line in raw_records {
        if let Some((user, pass)) = line.split_once(':') {
            users.push(AuthUser { user: user.to_owned(), pass: pass.to_owned() });
        }
    }
    users
}

fn parse_ipv6(raw_cfg: &mut RawConfig) {
    if !raw_cfg.ipv6 || !verify_ip6() {
        raw_cfg.dns.fake_ip_range6.clear();
        raw_cfg.tun.inet6_address.clear();
    }
}

/// Builds the tun config from the parsed `RawTun`, deriving `inet4-address` from `dns.fake-ip-range`
/// re-prefixed to `/30`; an unsupported device is refused non-fatally.
fn parse_tun(raw_tun: &RawTun, dns: &DNS, general: &mut General) -> Result<()> {
    let tun_address_prefix = match dns.fake_ip_range {
        Some(range) => range,
        None => "198.18.0.1/16".parse::<IpNet>()?,
    };
    let inet4_address =
        IpNet::new(tun_address_prefix.addr(), 30).map_err(|err| anyhow!("invalid tun inet4 address prefix: {err}"))?;
    general.inbound.tun = Tun {
        enable: raw_tun.enable,
        device: raw_tun.device.clone(),
        stack: raw_tun.stack,
        dns_hijack: raw_tun.dns_hijack.clone(),
        auto_route: raw_tun.auto_route,
        auto_detect_interface: raw_tun.auto_detect_interface,
        mtu: raw_tun.mtu,
        gso: raw_tun.gso,
        gso_max_size: raw_tun.gso_max_size,
        inet4_address: vec![inet4_address],
        inet6_address: raw_tun.inet6_address.clone(),
        iproute2_table_index: raw_tun.iproute2_table_index,
        iproute2_rule_index: raw_tun.iproute2_rule_index,
        auto_redirect: raw_tun.auto_redirect,
        auto_redirect_input_mark: raw_tun.auto_redirect_input_mark,
        auto_redirect_output_mark: raw_tun.auto_redirect_output_mark,
        auto_redirect_iproute2_fallback_rule_index: raw_tun.auto_redirect_iproute2_fallback_rule_index,
        loopback_address: raw_tun.loopback_address.clone(),
        strict_route: raw_tun.strict_route,
        route_address: raw_tun.route_address.clone(),
        route_address_set: raw_tun.route_address_set.clone(),
        route_exclude_address: raw_tun.route_exclude_address.clone(),
        route_exclude_address_set: raw_tun.route_exclude_address_set.clone(),
        include_interface: raw_tun.include_interface.clone(),
        exclude_interface: raw_tun.exclude_interface.clone(),
        include_uid: raw_tun.include_uid.clone(),
        include_uid_range: raw_tun.include_uid_range.clone(),
        exclude_uid: raw_tun.exclude_uid.clone(),
        exclude_uid_range: raw_tun.exclude_uid_range.clone(),
        exclude_src_port: raw_tun.exclude_src_port.clone(),
        exclude_src_port_range: raw_tun.exclude_src_port_range.clone(),
        exclude_dst_port: raw_tun.exclude_dst_port.clone(),
        exclude_dst_port_range: raw_tun.exclude_dst_port_range.clone(),
        include_android_user: raw_tun.include_android_user.clone(),
        include_package: raw_tun.include_package.clone(),
        exclude_package: raw_tun.exclude_package.clone(),
        include_mac_address: raw_tun.include_mac_address.clone(),
        exclude_mac_address: raw_tun.exclude_mac_address.clone(),
        endpoint_independent_nat: raw_tun.endpoint_independent_nat,
        udp_timeout: raw_tun.udp_timeout,
        icmp_timeout: raw_tun.icmp_timeout,
        disable_icmp_forwarding: raw_tun.disable_icmp_forwarding,
        file_descriptor: raw_tun.file_descriptor,
        inet4_route_address: raw_tun.inet4_route_address.clone(),
        inet6_route_address: raw_tun.inet6_route_address.clone(),
        inet4_route_exclude_address: raw_tun.inet4_route_exclude_address.clone(),
        inet6_route_exclude_address: raw_tun.inet6_route_exclude_address.clone(),
        recvmsgx: raw_tun.recvmsgx,
        sendmsgx: raw_tun.sendmsgx,
        processors_per_channel: raw_tun.processors_per_channel,
    };
    Ok(())
}

#[cfg(feature = "extra-protocols")]
#[expect(clippy::default_trait_access, reason = "`murmur-listener-config` does not re-export the `MuxOption` type")]
fn parse_tuic_server(raw_tuic: &RawTuicServer, general: &mut General) {
    general.inbound.tuic_server = TuicServer {
        enable: raw_tuic.enable,
        listen: raw_tuic.listen.clone(),
        token: raw_tuic.token.clone(),
        users: raw_tuic.users.clone().into_iter().collect(),
        certificate: raw_tuic.certificate.clone(),
        private_key: raw_tuic.private_key.clone(),
        client_auth_type: String::new(),
        client_auth_cert: String::new(),
        ech_key: String::new(),
        congestion_controller: raw_tuic.congestion_controller.clone(),
        max_idle_time: raw_tuic.max_idle_time,
        authentication_timeout: raw_tuic.authentication_timeout,
        alpn: raw_tuic.alpn.clone(),
        max_udp_relay_packet_size: raw_tuic.max_udp_relay_packet_size,
        max_datagram_frame_size: 0,
        cwnd: raw_tuic.cwnd,
        bbr_profile: String::new(),
        mux_option: Default::default(),
    };
}

fn parse_sniffer(
    sniffer_raw: &RawSniffer,
    rule_providers: &HashMap<String, Arc<dyn RuleProvider>>,
) -> Result<SnifferDispatcherConfig> {
    let mut sniffer_config = SnifferDispatcherConfig {
        enable: sniffer_raw.enable,
        force_dns_mapping: sniffer_raw.force_dns_mapping,
        parse_pure_ip: sniffer_raw.parse_pure_ip,
        sniffers: HashMap::new(),
        force_domain: Vec::new(),
        skip_src_address: Vec::new(),
        skip_dst_address: Vec::new(),
        skip_domain: Vec::new(),
    };
    let mut load_sniffer: HashMap<SnifferType, SnifferConfig> = HashMap::new();

    if sniffer_raw.sniff.is_empty() {
        if sniffer_config.enable && !sniffer_raw.sniffing.is_empty() {
            warnln!("Deprecated: Use Sniff instead");
        }
        let global_ports = new_unsigned_ranges_from_list::<_, u16>(&sniffer_raw.ports)?;

        for sniffer_name in &sniffer_raw.sniffing {
            let mut find = false;
            for sniffer_type in SNIFFER_TYPE_LIST {
                if sniffer_type.string() == sniffer_name.to_uppercase() {
                    find = true;
                    load_sniffer.insert(
                        sniffer_type,
                        SnifferConfig { ports: global_ports.clone(), override_dest: sniffer_raw.override_dest },
                    );
                }
            }

            if !find {
                return Err(anyhow!("not find the sniffer[{sniffer_name}]"));
            }
        }
    } else {
        for (sniff_type, sniff_config) in &sniffer_raw.sniff {
            let mut find = false;
            let ports = new_unsigned_ranges_from_list::<_, u16>(&sniff_config.ports)?;
            let override_dest = sniff_config.override_dest.unwrap_or(sniffer_raw.override_dest);
            for sniffer_type in SNIFFER_TYPE_LIST {
                if sniffer_type.string() == sniff_type.to_uppercase() {
                    find = true;
                    load_sniffer.insert(sniffer_type, SnifferConfig { ports: ports.clone(), override_dest });
                }
            }

            if !find {
                return Err(anyhow!("not find the sniffer[{sniff_type}]"));
            }
        }
    }

    sniffer_config.sniffers = load_sniffer;

    sniffer_config.force_domain =
        parse_domain(&sniffer_raw.force_domain, None, "sniffer.force-domain", rule_providers)?;

    sniffer_config.skip_src_address =
        parse_ipcidr(&sniffer_raw.skip_src_address, None, "sniffer.skip-src-address", rule_providers)
            .map_err(|err| anyhow!("error in skip-src-address, error:{err}"))?;

    sniffer_config.skip_dst_address =
        parse_ipcidr(&sniffer_raw.skip_dst_address, None, "sniffer.skip-dst-address", rule_providers)
            .map_err(|err| anyhow!("error in skip-dst-address, error:{err}"))?;

    sniffer_config.skip_domain = parse_domain(&sniffer_raw.skip_domain, None, "sniffer.skip-domain", rule_providers)?;

    Ok(sniffer_config)
}

fn parse_ipcidr(
    addresses: &[String],
    cidr_set: Option<IpCidrSet>,
    adapter_name: &str,
    rule_providers: &HashMap<String, Arc<dyn RuleProvider>>,
) -> Result<Vec<Arc<dyn IpMatcher>>> {
    let mut matchers: Vec<Arc<dyn IpMatcher>> = Vec::new();
    let mut cidr_set = cidr_set;

    for ipcidr in addresses {
        if let Some(rest) = strip_prefix_ascii_case_insensitive(ipcidr, "geoip:") {
            for country in rest.split(',') {
                let matcher = GEOIP::new(country, adapter_name, false, false)?;
                matchers.push(Arc::new(matcher));
            }
        } else if let Some(rest) = strip_prefix_ascii_case_insensitive(ipcidr, "rule-set:") {
            for domain_set_name in rest.split(',') {
                let matcher = parse_ip_rule_set(domain_set_name, adapter_name, rule_providers)?;
                matchers.push(matcher);
            }
        } else {
            let set = cidr_set.get_or_insert_with(IpCidrSet::new_ip_cidr_set);
            set.add_ip_cidr_for_string(ipcidr)?;
        }
    }
    if let Some(mut set) = cidr_set {
        if !set.is_empty() {
            set.merge()?;
            matchers.push(Arc::new(IpCidrSetMatcher(set)));
        }
    }
    Ok(matchers)
}

fn parse_domain(
    domains: &[String],
    domain_set_builder: Option<DomainSetBuilder>,
    adapter_name: &str,
    rule_providers: &HashMap<String, Arc<dyn RuleProvider>>,
) -> Result<Vec<Arc<dyn DomainMatcher>>> {
    let mut matchers: Vec<Arc<dyn DomainMatcher>> = Vec::new();
    let mut domain_set_builder = domain_set_builder;

    for (idx, domain) in domains.iter().enumerate() {
        if let Some(rest) = strip_prefix_ascii_case_insensitive(domain, "geosite:") {
            for country in rest.split(',') {
                let matcher = GEOSITE::new(country, adapter_name)
                    .map_err(|err| anyhow!("{adapter_name}[{idx}] {domain:?}: {err}"))?;
                matchers.push(Arc::new(matcher));
            }
        } else if let Some(rest) = strip_prefix_ascii_case_insensitive(domain, "rule-set:") {
            for domain_set_name in rest.split(',') {
                let matcher = parse_domain_rule_set(domain_set_name, adapter_name, rule_providers)
                    .map_err(|err| anyhow!("{adapter_name}[{idx}] {domain:?}: {err}"))?;
                matchers.push(matcher);
            }
        } else {
            let builder = domain_set_builder.get_or_insert_with(DomainSetBuilder::default);
            builder.insert(domain).map_err(|err| anyhow!("{adapter_name}[{idx}]: {err}"))?;
        }
    }
    if let Some(mut builder) = domain_set_builder {
        if !builder.is_empty() {
            if let Some(set) = builder.build() {
                matchers.push(Arc::new(DomainSetMatcher(set)));
            }
        }
    }
    Ok(matchers)
}

fn parse_ip_rule_set(
    domain_set_name: &str,
    adapter_name: &str,
    rule_providers: &HashMap<String, Arc<dyn RuleProvider>>,
) -> Result<Arc<dyn IpMatcher>> {
    match rule_providers.get(domain_set_name) {
        None => return Err(anyhow!("not found rule-set: {domain_set_name}")),
        Some(rp) => match rp.behavior() {
            RuleBehavior::DOMAIN => {
                return Err(anyhow!("rule provider type error, expect ipcidr,actual {}", rp.behavior()))
            }
            RuleBehavior::CLASSICAL => {
                warnln!("{} provider is {}, only matching it contain ip rule", rp.name(), rp.behavior());
            }
            _ => {}
        },
    }
    Ok(Arc::new(RuleSet::new(domain_set_name, adapter_name, false, true)?))
}

fn parse_domain_rule_set(
    domain_set_name: &str,
    adapter_name: &str,
    rule_providers: &HashMap<String, Arc<dyn RuleProvider>>,
) -> Result<Arc<dyn DomainMatcher>> {
    match rule_providers.get(domain_set_name) {
        None => return Err(anyhow!("not found rule-set: {domain_set_name}")),
        Some(rp) => match rp.behavior() {
            RuleBehavior::IPCIDR => {
                return Err(anyhow!("rule provider type error, expect domain,actual {}", rp.behavior()))
            }
            RuleBehavior::CLASSICAL => {
                warnln!("{} provider is {}, only matching it contain domain rule", rp.name(), rp.behavior());
            }
            _ => {}
        },
    }
    Ok(Arc::new(RuleSet::new(domain_set_name, adapter_name, false, true)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "extra-protocols"))]
    #[tokio::test]
    async fn legacy_removed_listeners_fail_before_configuration_initialization() {
        for yaml in ["ss-config: ss://example\n", "tuic-server:\n  enable: true\n"] {
            let raw = unmarshal_raw_config(yaml.as_bytes()).expect("raw config");
            let Err(error) = parse_raw_config(raw).await else {
                panic!("removed legacy listener must fail");
            };
            assert!(error.to_string().contains("extra-protocols"), "{error}");
        }
    }

    #[cfg(not(feature = "extra-protocols"))]
    #[test]
    fn inline_provider_rejection_reports_the_unavailable_protocol_in_plain_display() {
        let raw = unmarshal_raw_config(
            br#"
proxy-providers:
  fixture:
    type: inline
    payload:
      - {name: retained, type: direct}
      - {name: removed, type: ss}
"#,
        )
        .expect("raw config");
        let error = parse_proxies(&raw).err().expect("removed provider protocol must fail");
        let message = error.to_string();
        assert!(message.contains("fixture"), "{message}");
        assert!(message.contains("proxy 1"), "{message}");
        assert!(message.contains("outbound protocol ss"), "{message}");
        assert!(message.contains("extra-protocols"), "{message}");
    }

    #[test]
    fn sniffer_ports_accept_mixed_int_and_string_scalars() {
        let yaml = "sniff:\n  HTTP:\n    ports: [80, 8080-8880]\nport-whitelist: [80, \"443\"]\n";
        let sniffer: RawSniffer = yaml_serde::from_str(yaml).expect("mixed-typed ports should decode");
        assert_eq!(sniffer.ports, vec!["80".to_owned(), "443".to_owned()]);
        assert_eq!(sniffer.sniff["HTTP"].ports, vec!["80".to_owned(), "8080-8880".to_owned()]);
    }

    #[test]
    fn raw_tun_deserializes_loopback_addresses() {
        let tun: RawTun = yaml_serde::from_str("loopback-address: [\"127.0.0.1\", \"::1\"]\n").unwrap();
        let addrs: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()];
        assert_eq!(tun.loopback_address, addrs);
    }

    #[test]
    fn raw_tun_rejects_a_zoned_ipv6_loopback_address() {
        let err = yaml_serde::from_str::<RawTun>("loopback-address: [\"fe80::1%eth0\"]\n").unwrap_err();
        assert!(err.to_string().contains("invalid IP address syntax"), "unexpected error: {err}");
    }

    #[test]
    fn host_with_default_port_error_text_matches_split_host_port() {
        assert_eq!(host_with_default_port("1.2.3.4", "53").unwrap(), "1.2.3.4:53");
        assert_eq!(host_with_default_port("1.2.3.4:53", "80").unwrap(), "1.2.3.4:53");
        assert_eq!(host_with_default_port("[::1]", "53").unwrap(), "[::1]:53");

        let err = host_with_default_port("1.2:3.4:53", "80").unwrap_err();
        assert_eq!(err.to_string(), "address 1.2:3.4:53: too many colons in address");

        let err = murmur_common::net_addr::split_host_port("1.2:3.4:53").unwrap_err();
        assert_eq!(err.to_string(), "address 1.2:3.4:53: too many colons in address");

        let err = murmur_common::net_addr::split_host_port("1.2.3.4").unwrap_err();
        assert_eq!(err.to_string(), "address 1.2.3.4: missing port in address");
    }

    #[test]
    fn parse_name_server_covers_every_scheme_and_default_port() {
        let cases: &[(&str, NsNetType, &str)] = &[
            ("udp://1.1.1.1", NsNetType::Udp, "1.1.1.1:53"),
            ("1.1.1.1", NsNetType::Udp, "1.1.1.1:53"),
            ("tcp://1.1.1.1:5353", NsNetType::Tcp, "1.1.1.1:5353"),
            ("tls://1.1.1.1", NsNetType::Tls, "1.1.1.1:853"),
            ("https://dns.google/dns-query", NsNetType::Https, "https://dns.google:443/dns-query"),
            ("http://dns.google/dns-query", NsNetType::Https, "http://dns.google:80/dns-query"),
            ("quic://dns.adguard.com", NsNetType::Quic, "dns.adguard.com:853"),
            ("system", NsNetType::System, ""),
            ("system://", NsNetType::System, ""),
            ("dhcp://en0", NsNetType::Dhcp, "en0"),
            ("dhcp://system", NsNetType::System, ""),
            ("rcode://success", NsNetType::Rcode, "success"),
            ("ts://myproxy", NsNetType::Tailscale, "myproxy"),
            ("tailscale://myproxy", NsNetType::Tailscale, "myproxy"),
            ("et://myproxy", NsNetType::Easytier, "myproxy"),
            ("tls://[2001:db8::1]:8853", NsNetType::Tls, "[2001:db8::1]:8853"),
            ("udp://[2001:db8::1]", NsNetType::Udp, "[2001:db8::1]:53"),
        ];
        for (input, expected_net, expected_addr) in cases {
            let got =
                parse_name_server(&[(*input).to_owned()], false, false).unwrap_or_else(|err| panic!("{input}: {err}"));
            assert_eq!(got.len(), 1, "{input}");
            assert_eq!(got[0].net, *expected_net, "{input}");
            assert_eq!(got[0].addr, *expected_addr, "{input}");
        }
    }

    #[test]
    fn parse_name_server_https_fragment_params_and_proxy_name() {
        let got = parse_name_server(
            &["https://dns.google/dns-query#h3=true&ecs=1.2.3.0/24&ecs-override=true".to_owned()],
            false,
            false,
        )
        .unwrap();
        assert_eq!(got[0].proxy_name, "");
        assert_eq!(got[0].params.get("h3").map(String::as_str), Some("true"));
        assert_eq!(got[0].params.get("ecs").map(String::as_str), Some("1.2.3.0/24"));
        assert_eq!(got[0].params.get("ecs-override").map(String::as_str), Some("true"));

        let got = parse_name_server(&["tls://1.1.1.1#PROXY".to_owned()], false, false).unwrap();
        assert_eq!(got[0].proxy_name, "PROXY");
        assert!(got[0].params.is_empty());
    }

    #[test]
    fn parse_name_server_fragment_last_bare_segment_wins_as_proxy_name() {
        let got = parse_name_server(&["udp://1.1.1.1#PROXY1&PROXY2".to_owned()], false, false).unwrap();
        assert_eq!(got[0].proxy_name, "PROXY2");

        let got = parse_name_server(&["udp://1.1.1.1#h3=true&PROXY&ecs=1.2.3.0/24".to_owned()], false, false).unwrap();
        assert_eq!(got[0].proxy_name, "PROXY");
        assert_eq!(got[0].params.len(), 2);
    }

    #[test]
    fn parse_name_server_rejects_unsupported_rcode_and_scheme() {
        let err = parse_name_server(&["rcode://bogus".to_owned()], false, false).err().unwrap();
        assert_eq!(err.to_string(), "DNS NameServer[0] format error: unsupported RCode type: bogus");

        let err = parse_name_server(&["foo://1.1.1.1".to_owned()], false, false).err().unwrap();
        assert_eq!(err.to_string(), "DNS NameServer[0] unsupport scheme: foo");

        let err = parse_name_server(&["ts://".to_owned()], false, false).err().unwrap();
        assert_eq!(err.to_string(), "DNS NameServer[0] format error: missing Tailscale proxy name");

        let err = parse_name_server(&["et://".to_owned()], false, false).err().unwrap();
        assert_eq!(err.to_string(), "DNS NameServer[0] format error: missing EasyTier proxy name");
    }

    #[test]
    fn parse_name_server_deduplicates_equal_entries() {
        let got = parse_name_server(&["udp://1.1.1.1".to_owned(), "1.1.1.1".to_owned()], false, false).unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn parse_name_server_respect_rules_only_fills_a_missing_proxy_name() {
        let got = parse_name_server(&["udp://1.1.1.1".to_owned()], true, false).unwrap();
        assert_eq!(got[0].proxy_name, RESPECT_RULES);

        let got = parse_name_server(&["udp://1.1.1.1#PROXY".to_owned()], true, false).unwrap();
        assert_eq!(got[0].proxy_name, "PROXY");
    }

    #[test]
    fn parse_name_server_propagates_prefer_h3() {
        let got = parse_name_server(&["https://dns.google/dns-query".to_owned()], false, true).unwrap();
        assert!(got[0].prefer_h3);

        let got = parse_name_server(&["https://dns.google/dns-query".to_owned()], false, false).unwrap();
        assert!(!got[0].prefer_h3);
    }

    #[test]
    fn parse_name_server_policy_preserves_yaml_key_order() {
        let mut ns_policy: OrderedMap<String, Value> = OrderedMap::new();
        ns_policy.set("b.com".to_owned(), Value::String("udp://2.2.2.2".to_owned()));
        ns_policy.set("a.com".to_owned(), Value::String("udp://1.1.1.1".to_owned()));

        let policies =
            parse_name_server_policy(Some(&ns_policy), "dns.nameserver-policy", &HashMap::new(), false, false).unwrap();

        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].domain, "b.com");
        assert_eq!(policies[0].name_servers[0].addr, "2.2.2.2:53");
        assert_eq!(policies[1].domain, "a.com");
        assert_eq!(policies[1].name_servers[0].addr, "1.1.1.1:53");
    }

    #[test]
    fn parse_name_server_policy_splits_comma_separated_plain_domain_keys_in_order() {
        let mut ns_policy: OrderedMap<String, Value> = OrderedMap::new();
        ns_policy.set("a.com,b.com".to_owned(), Value::String("udp://1.1.1.1".to_owned()));

        let policies =
            parse_name_server_policy(Some(&ns_policy), "dns.nameserver-policy", &HashMap::new(), false, false).unwrap();

        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].domain, "a.com");
        assert_eq!(policies[1].domain, "b.com");
    }

    #[test]
    fn parse_name_server_policy_rejects_an_invalid_domain_key() {
        let mut ns_policy: OrderedMap<String, Value> = OrderedMap::new();
        ns_policy.set("a..com".to_owned(), Value::String("udp://1.1.1.1".to_owned()));

        let err = parse_name_server_policy(Some(&ns_policy), "dns.nameserver-policy", &HashMap::new(), false, false)
            .err()
            .unwrap();
        assert!(err.to_string().starts_with("dns.nameserver-policy[0]:"), "{err}");
    }

    #[test]
    fn parse_name_server_policy_rule_set_key_errors_when_the_provider_is_unknown() {
        let mut ns_policy: OrderedMap<String, Value> = OrderedMap::new();
        ns_policy.set("rule-set:myset".to_owned(), Value::String("udp://1.1.1.1".to_owned()));

        let err = parse_name_server_policy(Some(&ns_policy), "dns.nameserver-policy", &HashMap::new(), false, false)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "not found rule-set: myset");
    }

    #[test]
    fn parse_name_server_policy_rule_set_key_is_case_insensitive_and_strips_the_prefix() {
        let mut ns_policy: OrderedMap<String, Value> = OrderedMap::new();
        ns_policy.set("RULE-SET:myset".to_owned(), Value::String("udp://1.1.1.1".to_owned()));

        let err = parse_name_server_policy(Some(&ns_policy), "dns.nameserver-policy", &HashMap::new(), false, false)
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "not found rule-set: myset");
    }

    #[test]
    fn parse_name_server_policy_none_input_returns_an_empty_list() {
        let policies = parse_name_server_policy(None, "dns.nameserver-policy", &HashMap::new(), false, false).unwrap();
        assert!(policies.is_empty());
    }

    #[test]
    fn default_raw_config_pins_defaults_for_frozen_keys() {
        let cfg = default_raw_config().unwrap();

        assert_eq!(cfg.mode, TunnelMode::RULE);
        assert_eq!(cfg.log_level, LogLevel::INFO);
        assert!(!cfg.unified_delay);
        assert!(!cfg.tcp_concurrent);
        assert!(cfg.ipv6);
        assert_eq!(cfg.find_process_mode, FindProcessMode::FIND_PROCESS_STRICT);
        assert!(cfg.etag_support);
        assert!(cfg.profile.store_selected);

        assert!(!cfg.dns.enable);
        assert!(!cfg.dns.ipv6);
        assert_eq!(cfg.dns.enhanced_mode, DNSMode::DNS_MAPPING);
        assert_eq!(cfg.dns.fake_ip_range, "198.18.0.1/16");
        assert_eq!(cfg.dns.fake_ip_filter_mode, FilterMode::FILTER_BLACK_LIST);
        assert_eq!(cfg.dns.ipv6_timeout, 100);
        assert_eq!(cfg.dns.name_server, vec!["https://doh.pub/dns-query".to_owned(), "tls://223.5.5.5:853".to_owned()]);
        assert_eq!(
            cfg.dns.default_nameserver,
            vec!["114.114.114.114".to_owned(), "223.5.5.5".to_owned(), "8.8.8.8".to_owned(), "1.0.0.1".to_owned(),]
        );
    }

    #[test]
    fn unmarshal_raw_config_of_an_empty_document_keeps_defaults() {
        let got = unmarshal_raw_config(b"").unwrap();
        let want = default_raw_config().unwrap();
        assert_eq!(yaml_serde::to_string(&got).unwrap(), yaml_serde::to_string(&want).unwrap());
    }

    #[test]
    fn unmarshal_raw_config_merges_explicit_dns_keys_onto_defaults() {
        let got = unmarshal_raw_config(b"dns:\n  enable: true\n  enhanced-mode: fake-ip\n").unwrap();

        assert!(got.dns.enable);
        assert_eq!(got.dns.enhanced_mode, DNSMode::DNS_FAKE_IP);
        assert_eq!(got.dns.fake_ip_range, "198.18.0.1/16");
        assert_eq!(got.dns.name_server, vec!["https://doh.pub/dns-query".to_owned(), "tls://223.5.5.5:853".to_owned()]);
        assert_eq!(got.mode, TunnelMode::RULE);
    }

    /// Assigning null onto an existing non-pointer field is a no-op, so a bare `tun: ~` (or `tun:`
    /// with no value) leaves `DefaultRawConfig`'s tun defaults untouched.
    #[test]
    fn unmarshal_raw_config_null_tun_section_keeps_defaults() {
        let got = unmarshal_raw_config(b"tun: ~\n").unwrap();
        let want = default_raw_config().unwrap();
        assert_eq!(yaml_serde::to_string(&got.tun).unwrap(), yaml_serde::to_string(&want.tun).unwrap());
    }

    /// Within a named sub-key, `dns-hijack: ~` merges onto a sequence-typed field and null replaces
    /// it (the field goes to `None`); every other `tun:` field keeps its default.
    #[test]
    fn unmarshal_raw_config_null_tun_dns_hijack_clears_only_that_field() {
        let got = unmarshal_raw_config(b"tun:\n  dns-hijack: ~\n").unwrap();
        let want = default_raw_config().unwrap();
        assert_eq!(got.tun.dns_hijack, None);
        assert_eq!(got.tun.stack, want.tun.stack);
        assert_eq!(got.tun.auto_route, want.tun.auto_route);
        assert_eq!(got.tun.auto_detect_interface, want.tun.auto_detect_interface);
        assert_eq!(got.tun.recvmsgx, want.tun.recvmsgx);
        assert_eq!(got.tun.processors_per_channel, want.tun.processors_per_channel);
    }

    /// Same null-onto-mapping no-op as tun, for `dns:`.
    #[test]
    fn unmarshal_raw_config_null_dns_section_keeps_defaults() {
        let got = unmarshal_raw_config(b"dns: ~\n").unwrap();
        let want = default_raw_config().unwrap();
        assert_eq!(yaml_serde::to_string(&got.dns).unwrap(), yaml_serde::to_string(&want.dns).unwrap());
    }

    /// Same null-onto-mapping no-op as tun, for `sniffer:`; the default `force_dns_mapping`,
    /// `parse_pure_ip` and `override_dest` are all `true`, so this also guards against a
    /// `#[derive(Default)]`-shaped regression that would silently zero them.
    #[test]
    fn unmarshal_raw_config_null_sniffer_section_keeps_defaults() {
        let got = unmarshal_raw_config(b"sniffer: ~\n").unwrap();
        let want = default_raw_config().unwrap();
        assert_eq!(yaml_serde::to_string(&got.sniffer).unwrap(), yaml_serde::to_string(&want.sniffer).unwrap());
        assert!(got.sniffer.force_dns_mapping);
        assert!(got.sniffer.parse_pure_ip);
        assert!(got.sniffer.override_dest);
    }

    /// Same null-onto-mapping no-op as tun, for `profile:`; the default `store_selected` is
    /// `true`.
    #[test]
    fn unmarshal_raw_config_null_profile_section_keeps_defaults() {
        let got = unmarshal_raw_config(b"profile: ~\n").unwrap();
        let want = default_raw_config().unwrap();
        assert_eq!(yaml_serde::to_string(&got.profile).unwrap(), yaml_serde::to_string(&want.profile).unwrap());
        assert!(got.profile.store_selected);
    }

    #[test]
    fn parse_dns_rejects_enable_without_name_server() {
        let mut raw_cfg = default_raw_config().unwrap();
        raw_cfg.dns.enable = true;
        raw_cfg.dns.name_server = Vec::new();

        let err = parse_dns(&raw_cfg, &HashMap::new()).err().unwrap();
        assert_eq!(err.to_string(), "if DNS configuration is turned on, NameServer cannot be empty");
    }

    #[test]
    fn parse_dns_builds_a_fake_ip_pool_from_the_default_fake_ip_range() {
        let mut raw_cfg = default_raw_config().unwrap();
        raw_cfg.dns.enable = true;
        raw_cfg.dns.enhanced_mode = DNSMode::DNS_FAKE_IP;

        let dns_cfg = parse_dns(&raw_cfg, &HashMap::new()).unwrap();

        assert_eq!(dns_cfg.enhanced_mode, DNSMode::DNS_FAKE_IP);
        assert!(dns_cfg.fake_ip_pool.is_some());
        assert!(dns_cfg.fake_ip_pool6.is_none());
        assert_eq!(dns_cfg.name_server.len(), 2);
        assert_eq!(dns_cfg.name_server[0].net, NsNetType::Https);
        assert_eq!(dns_cfg.name_server[1].net, NsNetType::Tls);
    }

    /// Bug #104: `clash-for-android.append-system-dns` was parsed but never applied.
    #[test]
    fn parse_dns_appends_the_system_resolver_when_clash_for_android_asks_for_it() {
        let mut raw_cfg = default_raw_config().unwrap();
        raw_cfg.dns.enable = true;
        raw_cfg.clash_for_android.append_system_dns = true;

        let dns_cfg = parse_dns(&raw_cfg, &HashMap::new()).unwrap();

        assert!(
            dns_cfg.default_nameserver.iter().any(|ns| ns.net == NsNetType::System),
            "`clash-for-android.append-system-dns` must append the system resolver: {:?}",
            dns_cfg.default_nameserver
        );
    }

    #[test]
    fn append_system_dns_does_not_duplicate_a_configured_system_nameserver() {
        let mut raw_cfg = default_raw_config().unwrap();
        raw_cfg.dns.enable = true;
        raw_cfg.dns.default_nameserver = vec!["system".to_owned(), "1.1.1.1".to_owned()];
        raw_cfg.clash_for_android.append_system_dns = true;

        let dns_cfg = parse_dns(&raw_cfg, &HashMap::new()).unwrap();

        assert_eq!(dns_cfg.default_nameserver.iter().filter(|ns| ns.net == NsNetType::System).count(), 1);
    }

    #[test]
    fn parse_clash_for_android_carries_both_fields_onto_the_runtime_config() {
        let raw = RawClashForAndroid { append_system_dns: true, ui_subtitle_pattern: "subtitle".to_owned() };

        let got = parse_clash_for_android(&raw);

        assert!(got.append_system_dns);
        assert_eq!(got.ui_subtitle_pattern, "subtitle");
    }

    // With no `nameserver` key the DefaultRawConfig lists are kept, so the default resolvers are
    // the ones dialled.
    #[test]
    fn parse_dns_keeps_defaults_when_the_dns_section_omits_nameserver() {
        let raw_cfg = unmarshal_raw_config(b"dns:\n  enable: true\n").unwrap();
        let dns_cfg = parse_dns(&raw_cfg, &HashMap::new()).unwrap();

        assert_eq!(
            dns_cfg.name_server.iter().map(|ns| ns.addr.as_str()).collect::<Vec<_>>(),
            ["https://doh.pub:443/dns-query", "223.5.5.5:853"]
        );
        assert_eq!(
            dns_cfg.default_nameserver.iter().map(|ns| ns.addr.as_str()).collect::<Vec<_>>(),
            ["114.114.114.114:53", "223.5.5.5:53", "8.8.8.8:53", "1.0.0.1:53"]
        );
    }

    #[test]
    fn parse_dns_rejects_an_empty_default_nameserver_list() {
        let mut raw_cfg = default_raw_config().unwrap();
        raw_cfg.dns.default_nameserver = Vec::new();

        let err = parse_dns(&raw_cfg, &HashMap::new()).err().unwrap();
        assert_eq!(err.to_string(), "default nameserver should have at least one nameserver");
    }
}

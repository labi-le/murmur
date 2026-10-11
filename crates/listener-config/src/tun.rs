use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use murmur_constant::tun::TunStack;

/// The merged TUN configuration.
///
/// Built from the parsed `config::config::RawTun` by `config::config::parse_tun` and from a
/// `type: tun` listener's `TunOption` by `listener::inbound::tun::Tun::new`. The
/// `tun_mtu`/`dns_hijack_addrs`/route-family helpers below derive the values the live device in
/// `murmur_listener::tun` consumes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[expect(clippy::struct_excessive_bools, reason = "the flags mirror the TUN config schema")]
pub struct Tun {
    pub enable: bool,
    pub device: String,
    pub stack: TunStack,
    pub dns_hijack: Option<Vec<String>>,
    pub auto_route: bool,
    pub auto_detect_interface: bool,
    pub mtu: u32,
    pub gso: bool,
    pub gso_max_size: u32,
    pub inet4_address: Vec<IpNet>,
    pub inet6_address: Vec<IpNet>,
    pub iproute2_table_index: i64,
    pub iproute2_rule_index: i64,
    pub auto_redirect: bool,
    pub auto_redirect_input_mark: u32,
    pub auto_redirect_output_mark: u32,
    pub auto_redirect_iproute2_fallback_rule_index: i64,
    pub loopback_address: Vec<IpAddr>,
    pub strict_route: bool,
    pub route_address: Vec<IpNet>,
    pub route_address_set: Vec<String>,
    pub route_exclude_address: Vec<IpNet>,
    pub route_exclude_address_set: Vec<String>,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
    pub include_uid: Vec<u32>,
    pub include_uid_range: Vec<String>,
    pub exclude_uid: Vec<u32>,
    pub exclude_uid_range: Vec<String>,
    pub exclude_src_port: Vec<u16>,
    pub exclude_src_port_range: Vec<String>,
    pub exclude_dst_port: Vec<u16>,
    pub exclude_dst_port_range: Vec<String>,
    pub include_android_user: Vec<i64>,
    pub include_package: Vec<String>,
    pub exclude_package: Vec<String>,
    pub include_mac_address: Vec<String>,
    pub exclude_mac_address: Vec<String>,
    pub endpoint_independent_nat: bool,
    pub udp_timeout: i64,
    pub icmp_timeout: i64,
    pub disable_icmp_forwarding: bool,
    pub file_descriptor: i32,
    pub inet4_route_address: Vec<IpNet>,
    pub inet6_route_address: Vec<IpNet>,
    pub inet4_route_exclude_address: Vec<IpNet>,
    pub inet6_route_exclude_address: Vec<IpNet>,
    pub recvmsgx: bool,
    pub sendmsgx: bool,
    pub processors_per_channel: i32,
}

impl Tun {
    /// Sorts the address lists; called by `listener.rs`'s `re_create_tun` before the conf is
    /// stored. `exclude-src-port(-range)` and `exclude-dst-port(-range)` are deliberately left
    /// alone.
    pub fn sort(&mut self) {
        if let Some(v) = &mut self.dns_hijack {
            v.sort();
        }
        self.inet4_address.sort_by(compare_prefix);
        self.inet6_address.sort_by(compare_prefix);
        self.route_address.sort_by(compare_prefix);
        self.route_address_set.sort();
        self.route_exclude_address.sort_by(compare_prefix);
        self.route_exclude_address_set.sort();
        self.include_interface.sort();
        self.exclude_interface.sort();
        self.include_uid.sort_unstable();
        self.include_uid_range.sort();
        self.exclude_uid.sort_unstable();
        self.exclude_uid_range.sort();
        self.include_android_user.sort_unstable();
        self.include_package.sort();
        self.exclude_package.sort();
        self.include_mac_address.sort();
        self.exclude_mac_address.sort();
        self.inet4_route_address.sort_by(compare_prefix);
        self.inet6_route_address.sort_by(compare_prefix);
        self.inet4_route_exclude_address.sort_by(compare_prefix);
        self.inet6_route_exclude_address.sort_by(compare_prefix);
    }

    /// The configured MTU, or the default when unset.
    #[must_use]
    pub fn tun_mtu(&self) -> u32 {
        if self.mtu == 0 {
            murmur_constant::tun::DEFAULT_MTU
        } else {
            self.mtu
        }
    }

    /// The configured GSO maximum size, or the default when unset.
    #[must_use]
    pub fn gso_max_size(&self) -> u32 {
        if self.gso_max_size == 0 {
            murmur_constant::tun::DEFAULT_GSO_MAX_SIZE
        } else {
            self.gso_max_size
        }
    }

    /// `route-address` followed by the family-specific lists, split by family. Appending rather
    /// than replacing is what lets `inet4-route-address` be used on its own.
    #[must_use]
    pub fn inet4_route_address(&self) -> Vec<IpNet> {
        self.merged_route_addresses().into_iter().filter(|p| p.addr().is_ipv4()).collect()
    }

    /// The IPv6 half of the merged route addresses.
    #[must_use]
    pub fn inet6_route_address(&self) -> Vec<IpNet> {
        self.merged_route_addresses().into_iter().filter(|p| p.addr().is_ipv6()).collect()
    }

    /// The IPv4 half of the merged route-exclude addresses.
    #[must_use]
    pub fn inet4_route_exclude_address(&self) -> Vec<IpNet> {
        self.merged_route_exclude_addresses().into_iter().filter(|p| p.addr().is_ipv4()).collect()
    }

    /// The IPv6 half of the merged route-exclude addresses.
    #[must_use]
    pub fn inet6_route_exclude_address(&self) -> Vec<IpNet> {
        self.merged_route_exclude_addresses().into_iter().filter(|p| p.addr().is_ipv6()).collect()
    }

    fn merged_route_addresses(&self) -> Vec<IpNet> {
        let mut merged = self.route_address.clone();
        merged.extend(self.inet4_route_address.iter().copied());
        merged.extend(self.inet6_route_address.iter().copied());
        merged
    }

    fn merged_route_exclude_addresses(&self) -> Vec<IpNet> {
        let mut merged = self.route_exclude_address.clone();
        merged.extend(self.inet4_route_exclude_address.iter().copied());
        merged.extend(self.inet6_route_exclude_address.iter().copied());
        merged
    }

    /// Whether `target` should be answered by the TUN's own resolver. An entry bound to an
    /// unspecified address matches any destination on port 53, which is how
    /// `dns-hijack: ["any:53"]` also catches traffic aimed at a third-party resolver's own
    /// address.
    #[must_use]
    pub fn should_hijack_dns(&self, target: std::net::SocketAddr) -> bool {
        self.dns_hijack_addrs()
            .is_ok_and(|addrs| addrs.iter().any(|a| *a == target || (a.ip().is_unspecified() && target.port() == 53)))
    }

    /// Each `dns-hijack` entry with an optional `://` scheme and one `any` → `0.0.0.0`
    /// substitution, then the address just past each configured interface address — the resolver
    /// address the TUN answers on itself.
    pub fn dns_hijack_addrs(&self) -> Result<Vec<std::net::SocketAddr>, String> {
        let mut addrs = Vec::new();
        for entry in self.dns_hijack.iter().flatten() {
            let after_scheme = entry.split_once("://").map_or(entry.as_str(), |(_, after)| after);
            let rewritten = after_scheme.replacen("any", "0.0.0.0", 1);
            let addr =
                parse_hijack_addr(&rewritten).ok_or_else(|| format!("parse dns-hijack url error: {rewritten}"))?;
            addrs.push(addr);
        }
        for prefix in self.inet4_address.iter().chain(self.inet6_address.iter()) {
            if let Some(next) = next_addr(prefix.addr()) {
                addrs.push(std::net::SocketAddr::new(next, 53));
            }
        }
        Ok(addrs)
    }

    /// The resolver addresses the TUN answers on.
    #[must_use]
    pub fn dns_server_ips(&self) -> Vec<IpAddr> {
        self.inet4_address.iter().chain(self.inet6_address.iter()).filter_map(|p| next_addr(p.addr())).collect()
    }

    /// A destination inside the TUN interface's own range is answered locally instead of
    /// forwarded, which is what keeps the resolver address above reachable.
    #[must_use]
    pub fn is_own_address(&self, addr: IpAddr) -> bool {
        self.inet4_address.iter().chain(self.inet6_address.iter()).any(|p| p.contains(&addr))
    }
}
/// Parses `addr:port`, with the brackets an IPv6 literal needs — the same grammar
/// `SocketAddr`'s own parser accepts.
fn parse_hijack_addr(s: &str) -> Option<std::net::SocketAddr> {
    s.parse().ok()
}

/// The following address, or `None` past the end of the space.
fn next_addr(addr: IpAddr) -> Option<IpAddr> {
    match addr {
        IpAddr::V4(v4) => u32::from(v4).checked_add(1).map(|next| IpAddr::V4(Ipv4Addr::from(next))),
        IpAddr::V6(v6) => u128::from(v6).checked_add(1).map(|next| IpAddr::V6(Ipv6Addr::from(next))),
    }
}

/// Sorts by address family (IPv4 before IPv6), then by prefix length, then by address.
fn compare_prefix(a: &IpNet, b: &IpNet) -> std::cmp::Ordering {
    let family = |n: &IpNet| matches!(n, IpNet::V6(_));
    family(a).cmp(&family(b)).then_with(|| a.prefix_len().cmp(&b.prefix_len())).then_with(|| a.addr().cmp(&b.addr()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mixed-prefix-length `route-address` list sorts by family, then prefix length, then
    /// address.
    #[test]
    fn tun_sort_orders_mixed_family_prefixes() {
        let mut tun = Tun {
            route_address: ["fd00::/8", "10.0.0.0/8", "10.0.0.0/7", "10.0.0.1/8", "1.2.3.4/8", "::ffff:1.2.3.4/104"]
                .iter()
                .map(|s| s.parse().unwrap())
                .collect(),
            ..Default::default()
        };
        tun.sort();
        let got: Vec<String> = tun.route_address.iter().map(ToString::to_string).collect();
        assert_eq!(got, ["10.0.0.0/7", "1.2.3.4/8", "10.0.0.0/8", "10.0.0.1/8", "fd00::/8", "::ffff:1.2.3.4/104"]);
    }

    /// A patched `route-address` list sorts by family, then prefix length.
    #[test]
    fn tun_sort_orders_by_family_then_prefix_length() {
        let mut tun = Tun {
            route_address: ["10.0.0.0/8", "1.0.0.0/16", "fd00::/8", "::/0"]
                .iter()
                .map(|s| s.parse().unwrap())
                .collect(),
            ..Default::default()
        };
        tun.sort();
        let got: Vec<String> = tun.route_address.iter().map(ToString::to_string).collect();
        assert_eq!(got, ["10.0.0.0/8", "1.0.0.0/16", "::/0", "fd00::/8"]);
    }

    /// `inet6-route-address`: `2000::` sorts before `fd00::` by address, so this only passes under
    /// [`compare_prefix`]'s prefix-length-first ordering, not a plain address sort.
    #[test]
    fn tun_sort_orders_inet6_route_address_by_prefix_length() {
        let mut tun = Tun {
            inet6_route_address: ["2000::/16", "fd00::/8"].iter().map(|s| s.parse().unwrap()).collect(),
            ..Default::default()
        };
        tun.sort();
        let got: Vec<String> = tun.inet6_route_address.iter().map(ToString::to_string).collect();
        assert_eq!(got, ["fd00::/8", "2000::/16"]);
    }

    fn prefixes(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    /// The merged `route-address` list is split by family rather than read from the
    /// family-specific lists directly, so a mixed `route-address` reaches both.
    #[test]
    fn route_address_families_merge_every_source_before_splitting() {
        let tun = Tun {
            route_address: prefixes(&["10.0.0.0/8", "fd00::/8"]),
            inet4_route_address: prefixes(&["192.0.2.0/24"]),
            inet6_route_address: prefixes(&["2001:db8::/32"]),
            ..Default::default()
        };
        assert_eq!(tun.inet4_route_address(), prefixes(&["10.0.0.0/8", "192.0.2.0/24"]));
        assert_eq!(tun.inet6_route_address(), prefixes(&["fd00::/8", "2001:db8::/32"]));
    }

    #[test]
    fn route_exclude_address_families_merge_every_source_before_splitting() {
        let tun = Tun {
            route_exclude_address: prefixes(&["10.0.0.0/8", "fd00::/8"]),
            inet4_route_exclude_address: prefixes(&["192.0.2.0/24"]),
            inet6_route_exclude_address: prefixes(&["2001:db8::/32"]),
            ..Default::default()
        };
        assert_eq!(tun.inet4_route_exclude_address(), prefixes(&["10.0.0.0/8", "192.0.2.0/24"]));
        assert_eq!(tun.inet6_route_exclude_address(), prefixes(&["fd00::/8", "2001:db8::/32"]));
    }

    /// `dns-hijack` entries are accepted with or without a scheme, and the TUN's own resolver
    /// address is the one just past each configured interface address.
    #[test]
    fn dns_hijack_addrs_cover_scheme_prefix_wildcard_and_the_tun_resolver() {
        let tun = Tun {
            dns_hijack: Some(vec!["any:53".into(), "tcp://8.8.8.8:53".into(), "[fd00::1]:5353".into()]),
            inet4_address: prefixes(&["198.18.0.1/30"]),
            inet6_address: prefixes(&["fd00::2/126"]),
            ..Default::default()
        };
        let got: Vec<String> = tun.dns_hijack_addrs().expect("hijack addrs").iter().map(ToString::to_string).collect();
        assert_eq!(got, ["0.0.0.0:53", "8.8.8.8:53", "[fd00::1]:5353", "198.18.0.2:53", "[fd00::3]:53"]);
    }

    #[test]
    fn dns_hijack_addrs_reject_a_bare_address() {
        let tun = Tun { dns_hijack: Some(vec!["8.8.8.8".into()]), ..Default::default() };
        assert_eq!(tun.dns_hijack_addrs().unwrap_err(), "parse dns-hijack url error: 8.8.8.8");
    }

    /// The `any` wildcard is an unspecified address, so it captures every destination on port 53
    /// while a specific address only captures itself.
    #[test]
    fn should_hijack_dns_widens_an_unspecified_entry_to_the_whole_port() {
        let tun = Tun { dns_hijack: Some(vec!["any:53".into()]), ..Default::default() };
        assert!(tun.should_hijack_dns("1.1.1.1:53".parse().unwrap()));
        assert!(!tun.should_hijack_dns("1.1.1.1:5353".parse().unwrap()));

        let specific = Tun { dns_hijack: Some(vec!["8.8.8.8:53".into()]), ..Default::default() };
        assert!(specific.should_hijack_dns("8.8.8.8:53".parse().unwrap()));
        assert!(!specific.should_hijack_dns("1.1.1.1:53".parse().unwrap()));
    }

    #[test]
    fn tun_mtu_and_gso_max_size_fall_back_to_the_defaults() {
        assert_eq!(Tun::default().tun_mtu(), 9000);
        assert_eq!(Tun::default().gso_max_size(), 65536);
        let tun = Tun { mtu: 1500, gso_max_size: 4096, ..Default::default() };
        assert_eq!(tun.tun_mtu(), 1500);
        assert_eq!(tun.gso_max_size(), 4096);
    }

    #[test]
    fn is_own_address_covers_both_interface_families() {
        let tun = Tun {
            inet4_address: prefixes(&["198.18.0.0/30"]),
            inet6_address: prefixes(&["fd00::/126"]),
            ..Default::default()
        };
        assert!(tun.is_own_address("198.18.0.2".parse().unwrap()));
        assert!(tun.is_own_address("fd00::3".parse().unwrap()));
        assert!(!tun.is_own_address("198.18.0.4".parse().unwrap()));
    }

    /// The address space has no successor at its end, so the resolver address list stops there
    /// rather than wrapping to 0.0.0.0.
    #[test]
    fn next_addr_has_no_successor_at_the_end_of_the_address_space() {
        assert_eq!(next_addr("198.18.0.1".parse().unwrap()), Some("198.18.0.2".parse().unwrap()));
        assert_eq!(next_addr("255.255.255.255".parse().unwrap()), None);
        assert_eq!(next_addr("::".parse().unwrap()), Some("::1".parse().unwrap()));
        assert_eq!(next_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()), None);
    }
}

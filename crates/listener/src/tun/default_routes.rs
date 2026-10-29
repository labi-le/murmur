//! The default routes a TUN `auto-route` is about to displace.
//!
//! `auto-route` installs `0.0.0.0/0` and `::/0` without a metric, which outranks an uplink's
//! `default ... metric 1000`. When that breaks connectivity, the startup log is the only place
//! the cause can be seen without a second SSH session, so it names the defaults that were in the
//! table before the TUN replaced them. Reading is best effort: a missing table must not stop the
//! listener from starting.

use std::fmt;
use std::fs;

/// One default route as the kernel tables report it.
#[derive(Debug, PartialEq, Eq)]
struct DefaultRoute {
    interface: String,
    metric: u32,
}

impl fmt::Display for DefaultRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "default dev {} metric {}", self.interface, self.metric)
    }
}

/// Every default route the main table holds, or a phrase saying there is none.
#[cfg(target_os = "linux")]
pub(super) fn describe() -> String {
    let mut routes = Vec::new();
    if let Ok(table) = fs::read_to_string("/proc/net/route") {
        routes.extend(ipv4_defaults(&table));
    }
    if let Ok(table) = fs::read_to_string("/proc/net/ipv6_route") {
        routes.extend(ipv6_defaults(&table));
    }
    describe_routes(&routes)
}

/// Only the Linux device installs routes, and only Linux keeps the tables this reads.
#[cfg(not(target_os = "linux"))]
pub(super) fn describe() -> String {
    "not inspected on this platform".to_owned()
}

fn describe_routes(routes: &[DefaultRoute]) -> String {
    if routes.is_empty() {
        return "none installed".to_owned();
    }
    routes.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

/// `/proc/net/route`: `Iface Destination Gateway Flags RefCnt Use Metric Mask ...`, with the
/// address columns as host-endian hex. A default route has a zero destination *and* a zero mask.
fn ipv4_defaults(table: &str) -> Vec<DefaultRoute> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (Some(interface), Some(destination), Some(metric), Some(mask)) =
                (fields.first(), fields.get(1), fields.get(6), fields.get(7))
            else {
                return None;
            };
            if *destination != "00000000" || *mask != "00000000" {
                return None;
            }
            Some(DefaultRoute { interface: (*interface).to_owned(), metric: u32::from_str_radix(metric, 16).ok()? })
        })
        .collect()
}

/// `/proc/net/ipv6_route`: `destination prefix_len source source_len next_hop metric refcnt use
/// flags interface`, with the metric as hex. A default route is an all-zero destination with a
/// zero prefix length.
fn ipv6_defaults(table: &str) -> Vec<DefaultRoute> {
    table
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (Some(destination), Some(prefix_len), Some(metric), Some(interface)) =
                (fields.first(), fields.get(1), fields.get(5), fields.get(9))
            else {
                return None;
            };
            if destination.bytes().any(|byte| byte != b'0') || *prefix_len != "00" {
                return None;
            }
            Some(DefaultRoute { interface: (*interface).to_owned(), metric: u32::from_str_radix(metric, 16).ok()? })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{describe_routes, ipv4_defaults, ipv6_defaults, DefaultRoute};

    /// A table carries one default plus connected and gateway routes; only the zero
    /// destination *and* zero mask pair is a default, and the metric is hex.
    #[test]
    fn ipv4_table_keeps_only_the_default_route() {
        let table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
ppp0\t00000000\t0101A8C0\t0003\t0\t0\t000003E8\t00000000\t0\t0\t0
br0\t00A8C001\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0
";
        assert_eq!(
            ipv4_defaults(table),
            vec![
                DefaultRoute { interface: "ppp0".to_owned(), metric: 1000 },
                DefaultRoute { interface: "eth0".to_owned(), metric: 0 },
            ]
        );
    }

    /// IPv6 columns are plain hex, not host-endian words; a non-default prefix is skipped even
    /// when the destination bytes are zero.
    #[test]
    fn ipv6_table_keeps_only_the_zero_prefix_route() {
        let table = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000003 ppp0
00000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 00000003 br0
fd000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000003 ppp0
";
        assert_eq!(ipv6_defaults(table), vec![DefaultRoute { interface: "ppp0".to_owned(), metric: 0x400 }]);
    }

    #[test]
    fn an_empty_table_says_so_instead_of_printing_an_empty_list() {
        assert_eq!(describe_routes(&[]), "none installed");
    }
}

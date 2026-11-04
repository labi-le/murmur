use std::net::{IpAddr, Ipv4Addr};

use anyhow::{anyhow, Result};
use ipnet::IpNet;

use murmur_component::resolver::host::unmap_addr;

pub const DEFAULT_TLD_DNS_ZONE: &str = "et.net.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub hostname: String,
    /// The IPv4 address; `None` is its invalid zero value.
    pub ipv4: Option<IpAddr>,
}

#[must_use]
pub fn normalize_dns_name(name: &str) -> String {
    let name = name.trim();
    name.strip_suffix('.').unwrap_or(name).to_lowercase()
}

#[must_use]
pub fn normalize_zone(zone: &str) -> String {
    let zone = normalize_dns_name(zone);
    if zone.is_empty() {
        return normalize_dns_name(DEFAULT_TLD_DNS_ZONE);
    }
    zone
}

#[must_use]
pub fn overlay_names(hostname: &str, zone: &str) -> Vec<String> {
    let hostname = normalize_dns_name(hostname);
    if hostname.is_empty() {
        return Vec::new();
    }
    let zone = normalize_zone(zone);
    let mut names = vec![hostname.clone()];
    if hostname != zone && !hostname.ends_with(&format!(".{zone}")) {
        names.push(format!("{hostname}.{zone}"));
    }
    names
}

#[must_use]
pub fn is_magic_dns(host: &str, zone: &str) -> bool {
    let host = normalize_dns_name(host);
    if host.is_empty() {
        return false;
    }
    let zone = normalize_zone(zone);
    host == zone || host.ends_with(&format!(".{zone}"))
}

#[must_use]
pub fn lookup_overlay_host(host: &str, zone: &str, nodes: &[Node]) -> Option<IpAddr> {
    let host = normalize_dns_name(host);
    if host.is_empty() {
        return None;
    }
    for node in nodes {
        let Some(ipv4) = node.ipv4 else { continue };
        if !ipv4.is_ipv4() {
            continue;
        }
        for name in overlay_names(&node.hostname, zone) {
            if host == name {
                return Some(ipv4);
            }
        }
    }
    None
}

#[must_use]
pub fn lookup_overlay_ptr(ip: Option<IpAddr>, zone: &str, nodes: &[Node]) -> Option<String> {
    let ip = ip?;
    if !ip.is_ipv4() {
        return None;
    }
    let zone = normalize_zone(zone);
    for node in nodes {
        if node.ipv4 != Some(ip) {
            continue;
        }
        let names = overlay_names(&node.hostname, &zone);
        let Some(last) = names.last() else { continue };
        return Some(format!("{last}."));
    }
    None
}

pub fn parse_node_ipv4(value: &str) -> Result<IpAddr> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("easytier: empty overlay IPv4 address"));
    }
    if let Ok(prefix) = value.parse::<IpNet>() {
        return Ok(unmap_addr(prefix.addr()));
    }
    let ip = value.parse::<IpAddr>()?;
    Ok(unmap_addr(ip))
}

#[must_use]
pub fn ipv4_from_uint32(addr: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(addr.to_be_bytes()))
}

#[must_use]
pub fn parse_ptr_ipv4(name: &str) -> Option<IpAddr> {
    const SUFFIX: &str = ".in-addr.arpa";
    let name = normalize_dns_name(name);
    let stripped = name.strip_suffix(SUFFIX)?;
    let labels: Vec<&str> = stripped.split('.').collect();
    if labels.len() != 4 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for (label, byte) in labels.iter().rev().zip(bytes.iter_mut()) {
        *byte = u8::try_from(label.parse::<i32>().ok()?).ok()?;
    }
    Some(IpAddr::V4(Ipv4Addr::from(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_overlay_host() {
        let ip: IpAddr = "10.144.0.2".parse().expect("overlay address");
        let nodes = vec![Node { hostname: "peer".to_owned(), ipv4: Some(ip) }];
        assert_eq!(Some(ip), lookup_overlay_host("peer.et.net.", "et.net.", &nodes));
        assert_eq!(None, lookup_overlay_host("missing", "et.net.", &nodes));
    }

    #[test]
    fn test_parse_ptr_and_node_ipv4() {
        let ip = parse_ptr_ipv4("2.0.144.10.in-addr.arpa.").expect("ptr record");
        assert_eq!("10.144.0.2", ip.to_string());
        let got = parse_node_ipv4("10.144.0.1/24").expect("node address");
        assert_eq!("10.144.0.1", got.to_string());
    }

    #[test]
    fn test_is_magic_dns() {
        assert!(!is_magic_dns("peer", "et.net."));
        assert!(is_magic_dns("peer.et.net", ""));
        assert!(!is_magic_dns("example.com", "et.net."));
    }
}

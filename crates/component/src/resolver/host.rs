use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;

use anyhow::{anyhow, Result};
use rand::Rng;

use crate::resolver::hosts::hosts::lookup_static_host;
use murmur_component_trie::domain::DomainTrie;

/// Parses a boolean literal; `None` for an unrecognised value.
fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Whether system hosts are disabled; an unparsable value leaves it off.
pub static DISABLE_SYSTEM_HOSTS: LazyLock<bool> =
    LazyLock::new(|| std::env::var("DISABLE_SYSTEM_HOSTS").ok().and_then(|value| parse_bool(&value)).unwrap_or(false));

static USE_SYSTEM_HOSTS: AtomicBool = AtomicBool::new(false);

pub fn use_system_hosts() -> bool {
    USE_SYSTEM_HOSTS.load(Ordering::Relaxed)
}

pub fn set_use_system_hosts(value: bool) {
    USE_SYSTEM_HOSTS.store(value, Ordering::Relaxed);
}

/// Parses an address. `std::net::IpAddr`'s `FromStr` has no zoned-address form, so an IPv6 address
/// carrying a `%zone` suffix is rejected rather than accepted with the zone dropped.
pub fn parse_addr(host: &str) -> Result<IpAddr> {
    host.parse::<IpAddr>().map_err(|err| anyhow!(err))
}

/// Unmaps a 4-in-6 address to its IPv4 form.
#[must_use]
pub const fn unmap_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => ip,
    }
}

/// The hosts table, which embeds the `DomainTrie<HostValue>`.
#[derive(Debug)]
pub struct Hosts {
    pub domain_trie: DomainTrie<HostValue>,
}

#[must_use]
pub const fn new_hosts(hosts: DomainTrie<HostValue>) -> Hosts {
    Hosts { domain_trie: hosts }
}

impl Hosts {
    /// The lookup, returning the result and the match of the `is_domain` parameter; `None` is no
    /// match. Reading `/etc/hosts` is asynchronous here.
    pub async fn search(&self, domain: &str, is_domain: bool) -> Option<(HostValue, bool)> {
        if let Some(value) = self.domain_trie.search(domain) {
            let mut host_value = value.data().clone();
            loop {
                if is_domain && host_value.is_domain {
                    return Some((host_value, true));
                } else if let Some(node) = self.domain_trie.search(&host_value.domain) {
                    host_value = node.data().clone();
                } else {
                    break;
                }
            }
            if is_domain == host_value.is_domain {
                return Some((host_value, true));
            }
            return Some((host_value, false));
        }

        if !is_domain && !*DISABLE_SYSTEM_HOSTS && use_system_hosts() {
            let (addr, _) = lookup_static_host(domain).await;
            if let Ok(host_value) = HostValue::new(&addr) {
                return Some((host_value, true));
            }
        }
        None
    }
}

#[derive(Clone, Debug)]
pub struct HostValue {
    pub is_domain: bool,
    pub ips: Vec<IpAddr>,
    pub domain: String,
}

impl HostValue {
    pub fn new(value: &[String]) -> Result<Self> {
        let mut is_domain = true;
        let mut ips: Vec<IpAddr> = Vec::with_capacity(value.len());
        let mut domain = String::new();
        match value {
            [] => return Err(anyhow!("value is empty")),
            [host] => match parse_addr(host) {
                Ok(ip) => {
                    ips.push(unmap_addr(ip));
                    is_domain = false;
                }
                Err(_) => domain.clone_from(host),
            },
            _ => {
                is_domain = false;
                for string in value {
                    let ip = parse_addr(string)?;
                    ips.push(unmap_addr(ip));
                }
            }
        }
        if is_domain {
            return Self::by_domain(&domain);
        }
        Self::by_ips(ips)
    }

    pub fn by_ips(ips: Vec<IpAddr>) -> Result<Self> {
        if ips.is_empty() {
            return Err(anyhow!("ip list is empty"));
        }
        Ok(Self { is_domain: false, ips, domain: String::new() })
    }

    pub fn by_domain(domain: &str) -> Result<Self> {
        let domain = domain.trim_matches('.');
        if domain.split('.').count() < 2 {
            return Err(anyhow!("invalid domain"));
        }
        Ok(Self { is_domain: true, ips: Vec::new(), domain: domain.to_owned() })
    }
}

impl HostValue {
    pub fn rand_ip(&self) -> Result<IpAddr> {
        if self.is_domain {
            return Err(anyhow!("value type is error"));
        }
        let index = rand::rng().random_range(0..self.ips.len());
        self.ips.get(index).copied().ok_or_else(|| anyhow!("ip list is empty"))
    }
}

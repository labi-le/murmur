//! Fixtures used only by the metrics case registry. The Criterion `vless` target does not compile
//! this module or `cases.rs`.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use murmur_component_fakeip::pool::{new as new_fakeip_pool, Options as FakeIpOptions, Pool as FakeIpPool};
use murmur_component_trie::domain_map::{DomainMap, DomainMapBuilder};
use murmur_component_trie::ipcidr_trie::IpCidrTrie;
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{CheckPassRuleFn, Rule, RuleMatchHelper, RuleType};
use murmur_rules_common::domain::Domain;
use murmur_rules_common::domain_keyword::DomainKeyword;
use murmur_rules_common::domain_suffix::DomainSuffix;
use murmur_rules_common::ipcidr::IPCIDR;
use murmur_rules_common::port::Port;
use murmur_transport_vless::vless::{DstAddr, ATYP_DOMAIN_NAME, ATYP_IPV4};

const LOOKUP_COUNT: usize = 10_000;
pub const DOMAIN_VALUE: u32 = 1;
pub const DOMAIN_EXACT_KEY: &str = "host0.example.com";
pub const FAKEIP_HIT_HOSTS: usize = 64;
pub const FAKEIP_MISS_HOSTS: usize = 8192;
pub const FAKEIP_MISS_POOL_SIZE: i32 = 256;
const FAKEIP_IP_NET: &str = "198.18.0.0/16";
const RULE_CHAIN_LEN: usize = 256;

/// Observe the complete buffer without adding a payload-sized hashing pass to the measurement.
/// Exact wire/body validation happens during untimed fixture setup.
pub fn checksum_bytes(bytes: &[u8]) -> u64 {
    let bytes = std::hint::black_box(bytes);
    (bytes.len() as u64).rotate_left(16)
        ^ u64::from(bytes.first().copied().unwrap_or_default())
        ^ (u64::from(bytes.last().copied().unwrap_or_default()) << 8)
}

pub fn checksum_ip(ip: IpAddr) -> u64 {
    let mut hash = 0u64;
    match ip {
        IpAddr::V4(v4) => hash = u64::from(u32::from(v4)),
        IpAddr::V6(v6) => {
            for segment in v6.segments() {
                hash = hash.wrapping_mul(31).wrapping_add(u64::from(segment));
            }
        }
    }
    hash
}

pub fn dst_ipv4() -> DstAddr {
    DstAddr { udp: false, addr_type: ATYP_IPV4, addr: vec![192, 0, 2, 1], port: 443, mux: false }
}

pub fn dst_domain() -> DstAddr {
    let mut addr = vec![u8::try_from("example.com".len()).expect("domain fits a byte")];
    addr.extend_from_slice(b"example.com");
    DstAddr { udp: false, addr_type: ATYP_DOMAIN_NAME, addr, port: 80, mux: false }
}

pub fn dst_mux() -> DstAddr {
    DstAddr { udp: false, addr_type: ATYP_IPV4, addr: Vec::new(), port: 0, mux: true }
}

fn lookup_domains() -> Vec<String> {
    let mut domains = Vec::with_capacity(LOOKUP_COUNT + 7);
    for index in 0..LOOKUP_COUNT {
        let base = format!("host{index}.example.com");
        domains.push(match index % 5 {
            0 => base,
            1 => format!("+.{base}"),
            2 => format!(".{base}"),
            3 => format!("*.{base}"),
            _ => format!("service.*.{base}"),
        });
    }
    domains.push("*.*.overlap.example.com".to_owned());
    domains.push("dead.*.a.overlap.example.com".to_owned());
    domains.push("dead.b.a.overlap.example.com".to_owned());
    domains.push("api.service.region.cluster.internal.prod.company.example.com".to_owned());
    domains.push("例子.测试".to_owned());
    domains.push("bücher.example".to_owned());
    domains.push("xn--fsqu00a.xn--0zwm56d".to_owned());
    domains
}

pub fn domain_map_10k() -> DomainMap<u32> {
    let mut builder = DomainMapBuilder::<u32>::default();
    for domain in lookup_domains() {
        builder.insert(&domain, DOMAIN_VALUE).expect("valid domain pattern");
    }
    builder.build().expect("non-empty domain map")
}

pub fn ip_cidr_trie_256() -> IpCidrTrie {
    let mut trie = IpCidrTrie::new_ip_cidr_trie();
    for index in 0..256u32 {
        trie.add_ip_cidr_for_string(&format!("10.0.{index}.0/24")).expect("valid ipv4 cidr");
        trie.add_ip_cidr_for_string(&format!("2001:db8:{index:x}::/48")).expect("valid ipv6 cidr");
    }
    trie
}

pub fn fakeip_pool(size: i32) -> FakeIpPool {
    new_fakeip_pool(FakeIpOptions { ip_net: FAKEIP_IP_NET.parse().expect("valid ipnet"), size, persistence: false })
        .expect("valid fake-ip pool options")
}

pub fn fakeip_hit_hosts() -> Vec<String> {
    (0..FAKEIP_HIT_HOSTS).map(|index| format!("hit{index}.example.com")).collect()
}

pub fn fakeip_cold_hosts() -> Vec<String> {
    (0..FAKEIP_MISS_HOSTS).map(|index| format!("cold{index}.example.com")).collect()
}

fn build_rule_chain(count: usize) -> Vec<Arc<dyn Rule>> {
    let mut chain: Vec<Arc<dyn Rule>> = Vec::with_capacity(count);
    chain.push(Arc::new(DomainSuffix::new("probe-first.example.com", "FIRST")));
    for index in 0..count.saturating_sub(2) {
        let rule: Arc<dyn Rule> = match index % 5 {
            0 => Arc::new(DomainSuffix::new(&format!("mid{index}.example.com"), "MID")),
            1 => Arc::new(DomainKeyword::new(&format!("kwmid{index}"), "MID")),
            2 => {
                let second_octet = index % 256;
                Arc::new(IPCIDR::new(&format!("10.{second_octet}.0.0/16"), "MID", &[]).expect("valid ipnet"))
            }
            3 => Arc::new(Domain::new(&format!("midx{index}.example.com"), "MID")),
            _ => {
                let port = 20_000 + index % 1_000;
                Arc::new(Port::new(&format!("{port}"), "MID", RuleType::DST_PORT).expect("valid port range"))
            }
        };
        chain.push(rule);
    }
    chain.push(Arc::new(DomainSuffix::new("probe-last.example.com", "LAST")));
    chain
}

pub fn rule_chain_256() -> Vec<Arc<dyn Rule>> {
    build_rule_chain(RULE_CHAIN_LEN)
}

pub fn rule_metadata_miss() -> Metadata {
    Metadata {
        host: "nomatch.invalid".to_owned(),
        dst_ip: Some("203.0.113.7".parse().expect("valid ipv4")),
        dst_port: 443,
        ..Default::default()
    }
}

pub fn rule_helper_populated() -> RuleMatchHelper {
    // Cached resolution: never overwrite an existing destination, and default to a fixed
    // non-matching address so the chain's visited-rule count is unchanged.
    let resolved_fallback: IpAddr = "198.51.100.9".parse().expect("valid ipv4");
    let resolve_ip: Arc<dyn Fn(&mut Metadata) + Send + Sync> = Arc::new(move |metadata: &mut Metadata| {
        if metadata.dst_ip.is_none() {
            metadata.dst_ip = Some(resolved_fallback);
        }
    });

    // One-shot process lookup, without touching the OS.
    let attempt_process_lookup = Arc::new(AtomicBool::new(true));
    let find_process: Arc<dyn Fn(&mut Metadata) + Send + Sync> = Arc::new(move |metadata: &mut Metadata| {
        if !attempt_process_lookup.swap(false, Ordering::SeqCst) {
            return;
        }
        metadata.process = "murmur-bench".to_owned();
    });

    // PASS-RULE predicate over a scoped adapter name instead of the proxy graph.
    let check_pass_rule: CheckPassRuleFn = Arc::new(|_metadata: &Metadata, adapter: &str| adapter == "PASS-RULE");

    RuleMatchHelper {
        resolve_ip: Some(resolve_ip),
        find_process: Some(find_process),
        check_pass_rule: Some(check_pass_rule),
    }
}

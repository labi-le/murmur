//! Heap allocation census of the hot-path
//! operations a UDP datagram runs.
//!
//! Every figure is per operation, not per packet.
//! Allocation counts come from dhat as the global
//! allocator, deltaed across the measured loop.
//!
//! `metadata_clone` is the baseline number. A clone
//! allocates exactly one block per heap-owning field
//! in `crates/constant/src/metadata.rs`, and that count
//! is fourteen: two `Option<Vec<String>>` and twelve
//! `String`. Both vectors carry one element each and
//! every string is non-empty here, so each field
//! allocates once and the measured figure must equal
//! the arithmetic one. An earlier audit of this tree
//! claimed sixteen by hand; that was wrong, and this
//! column is what makes the error visible rather than
//! only arguable.
//!
//! `domain_set_has` and `domain_map_lookup` each
//! run over a lowercase key and over an upper-case
//! key. Both lowercase a query only when it holds
//! a non-ASCII byte, so an upper-case ASCII key
//! stays borrowed and neither case allocates: the
//! trie walk itself is allocation-free.
//!
//! `rule_chain_*` scans the same ordered chain the
//! tunnel loop walks, with the helper shape
//! `rule_match.rs` uses, at three chain lengths, on
//! a first-rule hit and on a full-chain miss. Chain
//! construction sits outside the measured loop.
//!
//! Every chain case measures zero except a
//! first-rule hit, which measures exactly one block:
//! that is `scan` calling `into_owned` on the adapter
//! to hand it back as a `String`. The rule itself
//! allocates nothing on a hit, returning
//! `Cow::Borrowed`. One allocation per matched packet
//! is this harness, not the rule chain.
//!
//! The reference rules package has no benchmarks,
//! so the workload shapes are [INFERENCE] from the
//! Rust implementation.
#![allow(
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::pedantic,
    clippy::nursery
)]

use std::hint::black_box;
use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use murmur_component_trie::domain_map::{DomainMap, DomainMapBuilder};
use murmur_component_trie::domain_set::{DomainSet, DomainSetBuilder};

use murmur_constant::metadata::{Metadata, NetWork, Type};
use murmur_constant::rule::{CheckPassRuleFn, Rule, RuleMatchHelper, RuleType};

use murmur_rules_common::domain::Domain;
use murmur_rules_common::domain_keyword::DomainKeyword;
use murmur_rules_common::domain_suffix::DomainSuffix;
use murmur_rules_common::ipcidr::IPCIDR;
use murmur_rules_common::port::Port;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const ITERATIONS: usize = 2_000;
/// The hand count the module docs describe.
const METADATA_CLONE_ARITHMETIC: u64 = 14;

/// A case separates what runs once from what the loop repeats: `setup` builds the state outside
/// the measured window, `run` performs the single operation under measurement.
struct Case {
    name: &'static str,
    setup: Box<dyn Fn() -> Box<dyn FnMut() -> u64>>,
}

fn fully_populated_metadata() -> Metadata {
    Metadata {
        network: NetWork::UDP,
        type_: Type::VMESS,
        src_ip: Some("198.51.100.7".parse().expect("valid ipv4")),
        dst_ip: Some("203.0.113.9".parse().expect("valid ipv4")),
        src_geo_ip: Some(vec!["us".to_owned(), "cloud".to_owned()]),
        dst_geo_ip: Some(vec!["de".to_owned()]),
        src_ipasn: "AS64496".to_owned(),
        dst_ipasn: "AS64500".to_owned(),
        src_port: 53_000,
        dst_port: 443,
        in_ip: Some("192.0.2.1".parse().expect("valid ipv4")),
        in_port: 7890,
        in_name: "mixed-in".to_owned(),
        in_user: "bench".to_owned(),
        rematch_name: String::new(),
        host: "target.example.com".to_owned(),
        dns_mode: Default::default(),
        uid: 0,
        process: "curl".to_owned(),
        process_path: "/usr/bin/curl".to_owned(),
        special_proxy: "DIRECT".to_owned(),
        special_rules: String::new(),
        remote_dst: "remote.example.net".to_owned(),
        dscp: 0,
        raw_src_addr: None,
        raw_dst_addr: None,
        sniff_host: String::new(),
    }
}

fn clone_metadata_setup() -> Box<dyn FnMut() -> u64> {
    let metadata = fully_populated_metadata();
    Box::new(move || {
        let clone = black_box(metadata.clone());
        black_box(&clone).host.len() as u64
    })
}

const SET_PATTERNS: [&str; 5] =
    ["example.com", "ads.example.net", "cn.example.org", "a.b.c.example.co.uk", "*.wildcard.example.io"];

fn domain_set() -> DomainSet {
    let mut builder = DomainSetBuilder::default();
    for pattern in SET_PATTERNS {
        builder.insert(pattern).expect("valid domain pattern");
    }
    builder.build().expect("a non-empty builder builds a set")
}

fn domain_map() -> DomainMap<u32> {
    let mut builder = DomainMapBuilder::<u32>::default();
    for (index, pattern) in
        ["example.com", "ads.example.net", "cn.example.org", "a.b.c.example.co.uk"].iter().enumerate()
    {
        builder.insert(pattern, index as u32 + 1).expect("valid domain pattern");
    }
    builder.build().expect("a non-empty builder builds a map")
}

fn has_ascii_setup() -> Box<dyn FnMut() -> u64> {
    let set = domain_set();
    Box::new(move || u64::from(set.has("ads.example.net")))
}

fn has_upper_case_setup() -> Box<dyn FnMut() -> u64> {
    let set = domain_set();
    Box::new(move || u64::from(set.has("ADS.Example.NET")))
}

fn lookup_ascii_setup() -> Box<dyn FnMut() -> u64> {
    let map = domain_map();
    Box::new(move || u64::from(black_box(map.lookup("ads.example.net").copied()).unwrap_or_default()))
}

fn lookup_upper_case_setup() -> Box<dyn FnMut() -> u64> {
    let map = domain_map();
    Box::new(move || u64::from(black_box(map.lookup("ADS.Example.NET").copied()).unwrap_or_default()))
}

fn build_chain(count: usize) -> Vec<Arc<dyn Rule>> {
    assert!(count >= 2, "a chain needs a first and a last rule");
    let mut chain: Vec<Arc<dyn Rule>> = Vec::with_capacity(count);
    chain.push(Arc::new(DomainSuffix::new("probe-first.example.com", "FIRST")));
    for index in 0..count - 2 {
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

fn populated_helper() -> RuleMatchHelper {
    let resolved_fallback: IpAddr = "198.51.100.9".parse().expect("valid ipv4");
    let resolve_ip: Arc<dyn Fn(&mut Metadata) + Send + Sync> = Arc::new(move |metadata: &mut Metadata| {
        if metadata.dst_ip.is_none() {
            metadata.dst_ip = Some(resolved_fallback);
        }
    });
    let attempt_process_lookup = Arc::new(AtomicBool::new(true));
    let find_process: Arc<dyn Fn(&mut Metadata) + Send + Sync> = Arc::new(move |metadata: &mut Metadata| {
        if !attempt_process_lookup.swap(false, Ordering::SeqCst) {
            return;
        }
        metadata.process = "murmur-bench".to_owned();
    });
    let check_pass_rule: CheckPassRuleFn = Arc::new(|_metadata: &Metadata, adapter: &str| adapter == "PASS-RULE");
    RuleMatchHelper {
        resolve_ip: Some(resolve_ip),
        find_process: Some(find_process),
        check_pass_rule: Some(check_pass_rule),
    }
}

fn scan(chain: &[Arc<dyn Rule>], metadata: &mut Metadata, helper: &RuleMatchHelper) -> Option<String> {
    for rule in chain.iter() {
        let (matched, adapter) = rule.match_(metadata, helper);
        if matched {
            return Some(adapter.into_owned());
        }
    }
    None
}

fn chain_setup(count: usize, host: String) -> Box<dyn FnMut() -> u64> {
    let chain = build_chain(count);
    let helper = populated_helper();
    let mut metadata = Metadata { host, dst_port: 443, ..Default::default() };
    Box::new(move || match scan(&chain, &mut metadata, &helper) {
        Some(adapter) => adapter.len() as u64,
        None => 0,
    })
}

fn cases() -> Vec<Case> {
    let mut cases = vec![
        Case { name: "metadata_clone", setup: Box::new(clone_metadata_setup) },
        Case { name: "domain_set_has_ascii_key", setup: Box::new(has_ascii_setup) },
        Case { name: "domain_set_has_upper_case_key", setup: Box::new(has_upper_case_setup) },
        Case { name: "domain_map_lookup_ascii_key", setup: Box::new(lookup_ascii_setup) },
        Case { name: "domain_map_lookup_upper_case_key", setup: Box::new(lookup_upper_case_setup) },
    ];
    for (count, first, miss) in [
        (16usize, "rule_chain_16_first_hit", "rule_chain_16_miss"),
        (256, "rule_chain_256_first_hit", "rule_chain_256_miss"),
        (1024, "rule_chain_1024_first_hit", "rule_chain_1024_miss"),
    ] {
        cases.push(Case {
            name: first,
            setup: Box::new(move || chain_setup(count, "probe-first.example.com".to_owned())),
        });
        cases.push(Case { name: miss, setup: Box::new(move || chain_setup(count, "nomatch.invalid".to_owned())) });
    }
    cases
}

fn measure(case: &Case, iterations: usize) -> u64 {
    let mut operation = (case.setup)();
    let mut accumulator = operation();
    let before = dhat::HeapStats::get();
    for _ in 0..iterations {
        accumulator = accumulator.wrapping_add(operation());
    }
    let after = dhat::HeapStats::get();
    black_box(accumulator);
    after.total_blocks - before.total_blocks
}

fn main() -> ExitCode {
    let cases = cases();
    if std::env::args().skip(1).any(|arg| arg == "--list") {
        for case in &cases {
            println!("{}", case.name);
        }
        return ExitCode::SUCCESS;
    }

    let _profiler = dhat::Profiler::builder().testing().trim_backtraces(Some(0)).build();

    println!("alloc_census: heap allocations per operation, not per packet");
    println!("{:<32} {:>11} {:>11} {:>11}", "case", "blocks/op", "arithmetic", "delta");
    for case in &cases {
        let allocations = measure(case, ITERATIONS);
        let per_op = allocations as f64 / ITERATIONS as f64;
        if case.name == "metadata_clone" {
            println!(
                "{:<32} {per_op:>11.3} {METADATA_CLONE_ARITHMETIC:>11} {:>11.3}",
                case.name,
                per_op - METADATA_CLONE_ARITHMETIC as f64
            );
        } else {
            println!("{:<32} {per_op:>11.3}", case.name);
        }
    }
    ExitCode::SUCCESS
}

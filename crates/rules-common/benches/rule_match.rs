//! Microbenchmarks for the ordered rule-chain scan: the tunnel loop's
//! `for rule in rules { rule.match_(metadata, helper) }` with a representative mix of
//! `DomainSuffix`/`DomainKeyword`/`Domain`/`IPCIDR`/`Port` rules. This measures the rule-chain
//! scan only, not full tunnel routing latency (adapter resolution, GeoIP lookups and DNS are out of
//! scope).
//!
//! `rule_chain/*` runs with an all-`None` helper; `rule_chain_populated/*` runs the identical
//! chains and metadata with all three hooks populated by the I/O-free stand-ins in
//! `populated_helper`, isolating the cost of carrying a populated helper through the scan. The
//! populated `resolve_ip` simulates the tunnel's cached resolution without DNS I/O, and
//! `find_process`/`check_pass_rule` do no process or OS work.
//!
//! The reference `rules` package has no benchmarks, so the workload shapes are [INFERENCE] from the
//! Rust implementation.
//!
//! `wrapped_chain/*` measures the counting wrapper shape that production actually runs around every
//! rule, against the bare rule over the same chain, the same metadata and the same helper, so the
//! delta is attributable to the wrapper alone. It is NOT the real wrapper type. The real one lives
//! in the separate `murmur-rules` crate, which already depends on `murmur-rules-common`, so this
//! crate cannot name it without a dependency cycle, and adding a dev-dependency back-edge would
//! mean editing this crate's manifest, which is out of scope here. `ModelRuleWrapper` is a MODEL of
//! it: the same forwarding of the rule trait, the same two atomic counters, and the same counter
//! bump plus clock read plus timestamp store on every hit and on every miss. Read the numbers as the
//! cost of that shape, not as a measurement of the real production type.
//!
//! `clock_read/*` isolates the clock read itself. The wrapper takes a wall-clock reading per match,
//! but `chrono` is not reachable from this crate either, so the loop measures the standard library
//! wall clock, which on Linux takes the same realtime clock vDSO path chrono takes; chrono adds
//! only the cheap arithmetic that turns that reading into a date-time value. The
//! wrapped-versus-bare delta is therefore expected to exceed this number slightly, and the excess is
//! the counter stores plus that conversion.
#![allow(
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

use std::borrow::Cow;
use std::hint::black_box;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{CheckPassRuleFn, Rule, RuleMatchHelper, RuleType};

use murmur_rules_common::domain::Domain;
use murmur_rules_common::domain_keyword::DomainKeyword;
use murmur_rules_common::domain_suffix::DomainSuffix;
use murmur_rules_common::ipcidr::IPCIDR;
use murmur_rules_common::port::Port;

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

fn metadata_for(case: &str) -> Metadata {
    let (host, dst_ip) = match case {
        "first" => ("probe-first.example.com", None),
        "last" => ("probe-last.example.com", None),
        _ => ("nomatch.invalid", Some("203.0.113.7".parse().expect("valid ipv4"))),
    };
    Metadata { host: host.to_owned(), dst_ip, dst_port: 443, ..Default::default() }
}

fn populated_helper() -> RuleMatchHelper {
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

fn scan(chain: &[Arc<dyn Rule>], metadata: &mut Metadata, helper: &RuleMatchHelper) -> (usize, Option<String>) {
    for (index, rule) in chain.iter().enumerate() {
        let (matched, adapter) = rule.match_(metadata, helper);
        if matched {
            return (index + 1, Some(adapter.into_owned()));
        }
    }
    (chain.len(), None)
}

/// A counting wrapper model, not the type itself; the module docs explain the dependency cycle that
/// forced the model. It mirrors the production shape: forward the rule trait, bump one of two
/// atomic counters, take a wall-clock reading, store it as unix nanoseconds in an atomic i64, on
/// every hit and on every miss.
struct ModelRuleWrapper {
    rule: Arc<dyn Rule>,
    disabled: AtomicBool,
    hit_count: AtomicU64,
    hit_at: AtomicI64,
    miss_count: AtomicU64,
    miss_at: AtomicI64,
}

impl ModelRuleWrapper {
    fn new(rule: Arc<dyn Rule>) -> Self {
        Self {
            rule,
            disabled: AtomicBool::new(false),
            hit_count: AtomicU64::new(0),
            hit_at: AtomicI64::new(0),
            miss_count: AtomicU64::new(0),
            miss_at: AtomicI64::new(0),
        }
    }

    fn hit(&self) {
        self.hit_count.fetch_add(1, Ordering::SeqCst);
        self.hit_at.store(unix_nanos(), Ordering::SeqCst);
    }

    fn miss(&self) {
        self.miss_count.fetch_add(1, Ordering::SeqCst);
        self.miss_at.store(unix_nanos(), Ordering::SeqCst);
    }
}

/// The production wrapper takes a wall-clock reading per match; chrono is unreachable from this
/// crate, so this is the same realtime clock reading reduced to unix nanoseconds.
fn unix_nanos() -> i64 {
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH);
    let nanos = since_epoch.unwrap_or_default().as_nanos();
    i64::try_from(nanos).unwrap_or(i64::MAX)
}

impl Rule for ModelRuleWrapper {
    fn rule_type(&self) -> RuleType {
        self.rule.rule_type()
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        if self.disabled.load(Ordering::SeqCst) {
            return (false, Cow::Borrowed(""));
        }
        let (ok, adapter) = self.rule.match_(metadata, helper);
        if ok {
            self.hit();
        } else {
            self.miss();
        }
        (ok, adapter)
    }

    fn adapter(&self) -> String {
        self.rule.adapter()
    }

    fn payload(&self) -> String {
        self.rule.payload()
    }

    fn provider_names(&self) -> Vec<String> {
        self.rule.provider_names()
    }
}

fn bench_chain(c: &mut Criterion, label: &str, helper: &RuleMatchHelper) {
    for count in [16usize, 256, 1024] {
        let chain = build_chain(count);
        let mut group = c.benchmark_group(format!("{label}/{count}"));
        for case in ["first", "last", "miss"] {
            let expected = match case {
                "first" => Some("FIRST".to_owned()),
                "last" => Some("LAST".to_owned()),
                _ => None,
            };
            let expected_visited = if case == "first" { 1 } else { count };
            let mut metadata = metadata_for(case);
            let (visited, adapter) = scan(&chain, &mut metadata, helper);
            assert_eq!(adapter, expected, "{count}/{case} adapter");
            assert_eq!(visited, expected_visited, "{count}/{case} scan length");

            group.throughput(Throughput::Elements(u64::try_from(visited).expect("scan length fits u64")));
            group.bench_function(case, |b| b.iter(|| black_box(scan(&chain, &mut metadata, helper))));
        }
        group.finish();
    }
}

fn bench_rule_chain(c: &mut Criterion) {
    bench_chain(c, "rule_chain", &RuleMatchHelper::default());
    bench_chain(c, "rule_chain_populated", &populated_helper());
}

/// The wrapped chain against the bare chain over the same rules, the same metadata and the same
/// helper, so the only difference between the two cases is the per-rule wrapper.
fn bench_wrapped_vs_bare(c: &mut Criterion) {
    let helper = RuleMatchHelper::default();
    for count in [16usize, 256, 1024] {
        let bare = build_chain(count);
        let wrapped: Vec<Arc<dyn Rule>> =
            bare.iter().cloned().map(|rule| -> Arc<dyn Rule> { Arc::new(ModelRuleWrapper::new(rule)) }).collect();

        for case in ["first", "miss"] {
            let expected = if case == "first" { Some("FIRST".to_owned()) } else { None };
            let expected_visited = if case == "first" { 1 } else { count };

            let mut bare_metadata = metadata_for(case);
            let (bare_visited, bare_adapter) = scan(&bare, &mut bare_metadata, &helper);
            let mut wrapped_metadata = metadata_for(case);
            let (wrapped_visited, wrapped_adapter) = scan(&wrapped, &mut wrapped_metadata, &helper);
            assert_eq!(bare_adapter, expected, "{count}/{case} bare adapter");
            assert_eq!(wrapped_adapter, expected, "{count}/{case} wrapped adapter");
            assert_eq!(bare_visited, expected_visited, "{count}/{case} bare scan length");
            assert_eq!(wrapped_visited, expected_visited, "{count}/{case} wrapped scan length");

            let mut group = c.benchmark_group(format!("wrapped_chain/{count}/{case}"));
            group.throughput(Throughput::Elements(u64::try_from(expected_visited).expect("scan length fits u64")));
            group.bench_function("bare", |b| b.iter(|| black_box(scan(&bare, &mut bare_metadata, &helper))));
            group.bench_function("wrapped", |b| b.iter(|| black_box(scan(&wrapped, &mut wrapped_metadata, &helper))));
            group.finish();
        }
    }
}

/// One clock read on its own, so the wrapped-versus-bare delta above can be split into the clock
/// read and the counter stores.
fn bench_clock_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("clock_read");
    group.throughput(Throughput::Elements(1));
    group.bench_function("wall_clock_nanos", |b| b.iter(|| black_box(unix_nanos())));
    group.bench_function("wall_clock_raw", |b| b.iter(|| black_box(SystemTime::now())));
    group.finish();
}

criterion_group!(benches, bench_rule_chain, bench_wrapped_vs_bare, bench_clock_read);
criterion_main!(benches);

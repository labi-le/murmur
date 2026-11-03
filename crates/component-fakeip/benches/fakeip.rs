//! Microbenchmarks for the fake-IP `Pool` memory store (`persistence = false`). No benchmarks
//! exist to compare against, so the workload shapes are [INFERENCE] from this implementation.
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
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use murmur_component_fakeip::pool::{new, Options, Pool};
use murmur_component_fakeip::skipper::{Skipper, USE_REAL_IP};
use murmur_component_trie::domain_set::{DomainSet, DomainSetBuilder};
use murmur_constant::dns::FilterMode;
use murmur_constant::matcher::DomainMatcher;
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType};

const IP_NET: &str = "198.18.0.0/16";
const HIT_HOSTS: usize = 64;
const MISS_HOSTS: usize = 8192;
/// Far below `MISS_HOSTS`, so a host looked up 8192 probes ago has already been evicted.
const MISS_POOL_SIZE: i32 = 256;

fn new_pool(size: i32) -> Pool {
    new(Options { ip_net: IP_NET.parse().expect("valid ipnet"), size, persistence: false })
        .expect("valid fake-ip pool options")
}

fn hit_hosts() -> Vec<String> {
    (0..HIT_HOSTS).map(|index| format!("hit{index}.example.com")).collect()
}

fn cold_hosts() -> Vec<String> {
    (0..MISS_HOSTS).map(|index| format!("cold{index}.example.com")).collect()
}

fn populate(pool: &Pool, hosts: &[String]) -> Vec<IpAddr> {
    hosts.iter().map(|host| pool.lookup(host)).collect()
}

/// `component/trie` gives `DomainSet` only an inherent `match_domain`, and neither crate depends on
/// the other, so a `DomainMatcher` impl here would be an orphan impl. Wrap it in a newtype.
struct BenchDomainSet(DomainSet);

impl DomainMatcher for BenchDomainSet {
    fn match_domain(&self, domain: &str) -> bool {
        self.0.match_domain(domain)
    }
}

struct DomainSuffixRule {
    set: DomainSet,
    payload: String,
}

impl Rule for DomainSuffixRule {
    fn rule_type(&self) -> RuleType {
        RuleType::DOMAIN_SUFFIX
    }

    fn match_(&self, metadata: &mut Metadata, _helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        (self.set.match_domain(&metadata.host), Cow::Borrowed(self.payload.as_str()))
    }

    fn adapter(&self) -> String {
        String::new()
    }

    fn payload(&self) -> String {
        self.payload.clone()
    }

    fn provider_names(&self) -> Vec<String> {
        Vec::new()
    }
}

const SKIP_RULES: usize = 64;

fn skip_rules(count: usize) -> Vec<Arc<dyn Rule>> {
    (0..count)
        .map(|index| {
            let mut builder = DomainSetBuilder::default();
            let domain = format!("ruleset{index}.example.com");
            builder.insert(&domain).expect("valid domain");
            let rule = DomainSuffixRule {
                set: builder.build().expect("non-empty domain set"),
                payload: USE_REAL_IP.to_owned(),
            };
            let rule: Arc<dyn Rule> = Arc::new(rule);
            rule
        })
        .collect()
}

fn empty_skipper() -> Skipper {
    let mut builder = DomainSetBuilder::default();
    builder.insert("example.com").expect("valid domain");
    Skipper {
        rules: Vec::new(),
        host: vec![Arc::new(BenchDomainSet(builder.build().expect("non-empty domain set")))],
        mode: FilterMode::default(),
    }
}

fn bench_should_skipped(c: &mut Criterion) {
    let hosts: Vec<String> = (0..HIT_HOSTS).map(|index| format!("query{index}.example.com")).collect();

    let empty = empty_skipper();
    let skipper = Skipper { rules: skip_rules(SKIP_RULES), host: Vec::new(), mode: FilterMode::default() };
    for host in &hosts {
        assert!(!empty.should_skipped(host), "empty-rules path must still answer");
        assert!(!skipper.should_skipped(host), "no rule matches the query host");
    }
    assert!(skipper.should_skipped("ruleset0.example.com"), "the first rule must match");

    let mut group = c.benchmark_group("should_skipped");
    group.throughput(Throughput::Elements(1));
    group.bench_function("empty_rules", |b| {
        let mut index = 0usize;
        b.iter(|| {
            let host = &hosts[index % hosts.len()];
            index = index.wrapping_add(1);
            black_box(empty.should_skipped(black_box(host.as_str())))
        });
    });
    group.bench_function("rules_miss", |b| {
        let mut index = 0usize;
        b.iter(|| {
            let host = &hosts[index % hosts.len()];
            index = index.wrapping_add(1);
            black_box(skipper.should_skipped(black_box(host.as_str())))
        });
    });
    group.finish();
}

fn bench_lookup_hit(c: &mut Criterion) {
    let pool = new_pool(65_536);
    assert_eq!(pool.gateway(), "198.18.0.1".parse::<IpAddr>().expect("valid ipv4"));
    assert_eq!(pool.broadcast(), "198.18.255.255".parse::<IpAddr>().expect("valid ipv4"));

    let hosts = hit_hosts();
    let ips = populate(&pool, &hosts);
    for (host, ip) in hosts.iter().zip(&ips) {
        assert!(pool.ip_net().contains(ip), "{host} outside the fake-ip net");
        assert_eq!(pool.lookup(host), *ip, "{host} is not a stable hit");
        assert_eq!(pool.look_back(*ip).as_deref(), Some(host.as_str()));
    }

    let mut group = c.benchmark_group("lookup");
    group.throughput(Throughput::Elements(1));
    group.bench_function("hit", |b| {
        let mut index = 0usize;
        b.iter(|| {
            let host = &hosts[index % hosts.len()];
            index = index.wrapping_add(1);
            black_box(pool.lookup(black_box(host.as_str())))
        });
    });
    group.finish();
}

fn bench_lookup_miss(c: &mut Criterion) {
    let pool = new_pool(MISS_POOL_SIZE);
    let hosts = cold_hosts();

    let first = pool.lookup(&hosts[0]);
    let window = usize::try_from(MISS_POOL_SIZE).expect("pool size is positive");
    for host in &hosts[1..=window] {
        pool.lookup(host);
    }
    assert!(!pool.exist(first), "the bounded pool must have evicted the oldest mapping");

    let mut group = c.benchmark_group("lookup");
    group.throughput(Throughput::Elements(1));
    // Continue across Criterion batches so small warmup batches cannot reuse recent hosts.
    let mut index = 0usize;
    group.bench_function("miss_cold", |b| {
        b.iter(|| {
            let host = &hosts[index % hosts.len()];
            index = index.wrapping_add(1);
            black_box(pool.lookup(black_box(host.as_str())))
        });
    });
    group.finish();
}

fn bench_look_back(c: &mut Criterion) {
    let pool = new_pool(65_536);
    let hosts = hit_hosts();
    let ips = populate(&pool, &hosts);

    for (host, ip) in hosts.iter().zip(&ips) {
        assert_eq!(pool.look_back(*ip).as_deref(), Some(host.as_str()));
    }
    let never_assigned: IpAddr = "198.18.0.2".parse().expect("valid ipv4");
    assert_eq!(pool.look_back(never_assigned), None);

    let mut group = c.benchmark_group("look_back");
    group.throughput(Throughput::Elements(1));
    group.bench_function("hit", |b| {
        let mut index = 0usize;
        b.iter(|| {
            let ip = ips[index % ips.len()];
            index = index.wrapping_add(1);
            black_box(pool.look_back(black_box(ip)))
        });
    });
    group.bench_function("miss", |b| b.iter(|| black_box(pool.look_back(black_box(never_assigned)))));
    group.finish();
}

fn bench_exist(c: &mut Criterion) {
    let pool = new_pool(65_536);
    let hosts = hit_hosts();
    let ips = populate(&pool, &hosts);

    for ip in &ips {
        assert!(pool.exist(*ip));
    }
    let never_assigned: IpAddr = "198.18.0.2".parse().expect("valid ipv4");
    assert!(!pool.exist(never_assigned));

    let mut group = c.benchmark_group("exist");
    group.throughput(Throughput::Elements(1));
    group.bench_function("hit", |b| {
        let mut index = 0usize;
        b.iter(|| {
            let ip = ips[index % ips.len()];
            index = index.wrapping_add(1);
            black_box(pool.exist(black_box(ip)))
        });
    });
    group.bench_function("miss", |b| b.iter(|| black_box(pool.exist(black_box(never_assigned)))));
    group.finish();
}

criterion_group!(benches, bench_should_skipped, bench_lookup_hit, bench_lookup_miss, bench_look_back, bench_exist);
criterion_main!(benches);

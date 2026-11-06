//! Microbenchmarks for the domain index (`DomainSet`/`DomainMap`/`DomainTrie`) and the IPv4/IPv6
//! `IpCidrTrie`. The lookup workload shapes (exact/suffix/wildcard/wildcard_fallback/miss/deep/
//! unicode/punycode) and the 10,000-entry pattern mix; the build generator is a deterministic
//! variant of the same shapes, and IPv4/IPv6 CIDR lookup has no benchmark.
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

use std::hint::black_box;
use std::net::IpAddr;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use murmur_component_trie::domain::DomainTrie;
use murmur_component_trie::domain_map::DomainMapBuilder;
use murmur_component_trie::domain_set::DomainSetBuilder;
use murmur_component_trie::ipcidr_trie::IpCidrTrie;

const LOOKUP_COUNT: usize = 10_000;
const VALUE: u32 = 1;

struct QueryCase {
    name: &'static str,
    keys: &'static [&'static str],
    found: bool,
}

/// Five pattern shapes cycle across the 10,000 entries so the exact/suffix/wildcard/miss probes
/// each land on a different code path.
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
    domains.push(LONG_64.to_owned());
    domains.push(LONG_512.to_owned());
    domains.push("bücher.example".to_owned());
    domains.push("xn--fsqu00a.xn--0zwm56d".to_owned());
    domains
}

/// 64 single-character labels plus a real TLD: 143 bytes of legal DNS, far past any
/// real-world name length, so a short key cannot reach the per-byte cost this measures.
const LONG_64: &str = concat!(
    "www.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.example.com"
);

/// 512 single-character labels plus a real TLD: 1039 bytes of legal DNS, far past any
/// real-world name length, so a short key cannot reach the per-byte cost this measures.
const LONG_512: &str = concat!(
    "www.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.l.",
    "l.l.l.l.l.l.l.l.l.l.l.l.l.l.example.com"
);

fn query_cases() -> Vec<QueryCase> {
    vec![
        QueryCase { name: "exact", keys: &["host0.example.com", "HOST9995.EXAMPLE.COM"], found: true },
        QueryCase { name: "suffix", keys: &["www.host1.example.com", "a.b.host2.example.com"], found: true },
        QueryCase { name: "wildcard", keys: &["www.host3.example.com", "service.eu.host4.example.com"], found: true },
        QueryCase {
            name: "wildcard_fallback",
            keys: &["b.a.overlap.example.com", "c.a.overlap.example.com"],
            found: true,
        },
        QueryCase {
            name: "miss",
            keys: &["host0.example.net", "www.host0.example.com", "other.eu.host4.example.com"],
            found: false,
        },
        QueryCase {
            name: "deep",
            keys: &[
                "api.service.region.cluster.internal.prod.company.example.com",
                "prod.eu-west-1.api.metrics.host1.example.com",
            ],
            found: true,
        },
        QueryCase { name: "long_key_64", keys: &[LONG_64], found: true },
        QueryCase { name: "long_key_512", keys: &[LONG_512], found: true },
        QueryCase { name: "unicode", keys: &["例子.测试", "BÜCHER.EXAMPLE"], found: true },
        QueryCase { name: "punycode", keys: &["xn--fsqu00a.xn--0zwm56d"], found: true },
    ]
}

fn domain_set(domains: &[String]) -> murmur_component_trie::domain_set::DomainSet {
    let mut builder = DomainSetBuilder::default();
    for domain in domains {
        builder.insert(domain).expect("valid domain pattern");
    }
    builder.build().expect("non-empty domain set")
}

fn bench_domain_set(c: &mut Criterion) {
    let domains = lookup_domains();
    let queries = query_cases();
    let set = domain_set(&domains);

    for query in &queries {
        let name = query.name;
        for key in query.keys {
            assert_eq!(set.has(key), query.found, "{name} {key}");
        }
    }

    let mut group = c.benchmark_group("domain_set/has");
    group.throughput(Throughput::Elements(1));
    for query in &queries {
        let keys = query.keys;
        group.bench_function(query.name, |b| {
            let mut index = 0usize;
            b.iter(|| {
                let key = keys[index % keys.len()];
                index = index.wrapping_add(1);
                black_box(set.has(black_box(key)))
            });
        });
    }
    group.finish();
}

fn bench_domain_map(c: &mut Criterion) {
    let domains = lookup_domains();
    let queries = query_cases();
    let mut builder = DomainMapBuilder::<u32>::default();
    for domain in &domains {
        builder.insert(domain, VALUE).expect("valid domain pattern");
    }
    let map = builder.build().expect("non-empty domain map");

    for query in &queries {
        let name = query.name;
        for key in query.keys {
            assert_eq!(map.lookup(key).copied(), query.found.then_some(VALUE), "{name} {key}");
        }
    }

    let mut group = c.benchmark_group("domain_map/lookup");
    group.throughput(Throughput::Elements(1));
    for query in &queries {
        let keys = query.keys;
        group.bench_function(query.name, |b| {
            let mut index = 0usize;
            b.iter(|| {
                let key = keys[index % keys.len()];
                index = index.wrapping_add(1);
                black_box(map.lookup(black_box(key)))
            });
        });
    }
    group.finish();
}

fn bench_domain_trie(c: &mut Criterion) {
    let domains = lookup_domains();
    let queries = query_cases();
    let mut trie = DomainTrie::<u32>::new();
    for domain in &domains {
        trie.insert(domain, VALUE).expect("valid domain pattern");
    }
    trie.optimize();

    for query in &queries {
        let name = query.name;
        for key in query.keys {
            let found = trie.search(key).map(|node| *node.data());
            assert_eq!(found, query.found.then_some(VALUE), "{name} {key}");
        }
    }

    let mut group = c.benchmark_group("domain_trie/search");
    group.throughput(Throughput::Elements(1));
    for query in &queries {
        let keys = query.keys;
        group.bench_function(query.name, |b| {
            let mut index = 0usize;
            b.iter(|| {
                let key = keys[index % keys.len()];
                index = index.wrapping_add(1);
                black_box(trie.search(black_box(key)).map(|node| *node.data()))
            });
        });
    }
    group.finish();
}

fn build_hash(value: u32) -> u32 {
    let mut value = value;
    value ^= value >> 16;
    value = value.wrapping_mul(0x7feb_352d);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846c_a68b);
    value ^ (value >> 16)
}

fn build_domains(count: usize) -> Vec<String> {
    const SUFFIXES: [&str; 12] = [
        "google.com",
        "github.io",
        "cloudflare.net",
        "mozilla.org",
        "amazonaws.com",
        "apple.com",
        "telegram.org",
        "example.co.uk",
        "example.com.au",
        "example.com.tw",
        "example.co.jp",
        "example.de",
    ];
    let mut domains = Vec::with_capacity(count);
    for index in 0..count {
        let hash = build_hash(u32::try_from(index).expect("index fits u32")) as usize;
        let suffix = SUFFIXES[hash % SUFFIXES.len()];
        let base = format!("host{index}.{suffix}");
        domains.push(match (hash >> 8) % 5 {
            0 => base,
            1 => format!(".{base}"),
            2 => format!("*.{base}"),
            3 => format!("service.*.{base}"),
            _ => format!("+.{base}"),
        });
    }
    domains
}

fn bench_domain_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_build");
    for count in [100usize, 10_000] {
        let domains = build_domains(count);
        group.throughput(Throughput::Elements(u64::try_from(count).expect("count fits u64")));

        let build_set = || {
            let mut builder = DomainSetBuilder::default();
            for domain in &domains {
                builder.insert(domain).expect("valid domain pattern");
            }
            builder.build().expect("nonempty domain fixture")
        };
        assert!(build_set().has("host0.google.com"));
        group.bench_function(format!("set/{count}").as_str(), |b| {
            b.iter_batched(|| (), |()| black_box(build_set()), BatchSize::LargeInput);
        });

        let build_map = || {
            let mut builder = DomainMapBuilder::<u32>::default();
            for domain in &domains {
                builder.insert(domain, VALUE).expect("valid domain pattern");
            }
            builder.build().expect("nonempty domain fixture")
        };
        assert_eq!(build_map().lookup("host0.google.com"), Some(&VALUE));
        group.bench_function(format!("map/{count}").as_str(), |b| {
            b.iter_batched(|| (), |()| black_box(build_map()), BatchSize::LargeInput);
        });

        let build_trie = || {
            let mut trie = DomainTrie::<u32>::new();
            for domain in &domains {
                trie.insert(domain, VALUE).expect("valid domain pattern");
            }
            trie.optimize();
            trie
        };
        assert_eq!(build_trie().search("host0.google.com").map(|node| *node.data()), Some(VALUE));
        group.bench_function(format!("trie/{count}").as_str(), |b| {
            b.iter_batched(|| (), |()| black_box(build_trie()), BatchSize::LargeInput);
        });
    }
    group.finish();
}

fn bench_ip_cidr(c: &mut Criterion) {
    let mut trie = IpCidrTrie::new_ip_cidr_trie();
    for index in 0..256u32 {
        trie.add_ip_cidr_for_string(&format!("10.0.{index}.0/24")).expect("valid ipv4 cidr");
        trie.add_ip_cidr_for_string(&format!("2001:db8:{index:x}::/48")).expect("valid ipv6 cidr");
    }

    let v4_hit: IpAddr = "10.0.42.7".parse().expect("valid ipv4");
    let v4_miss: IpAddr = "10.1.42.7".parse().expect("valid ipv4");
    let v6_hit: IpAddr = "2001:db8:2a::1".parse().expect("valid ipv6");
    let v6_miss: IpAddr = "2001:db9:2a::1".parse().expect("valid ipv6");
    assert!(trie.is_contain(&v4_hit));
    assert!(!trie.is_contain(&v4_miss));
    assert!(trie.is_contain(&v6_hit));
    assert!(!trie.is_contain(&v6_miss));

    let mut group = c.benchmark_group("ip_cidr/is_contain");
    group.throughput(Throughput::Elements(1));
    group.bench_function("ipv4_hit", |b| b.iter(|| black_box(trie.is_contain(black_box(&v4_hit)))));
    group.bench_function("ipv4_miss", |b| b.iter(|| black_box(trie.is_contain(black_box(&v4_miss)))));
    group.bench_function("ipv6_hit", |b| b.iter(|| black_box(trie.is_contain(black_box(&v6_hit)))));
    group.bench_function("ipv6_miss", |b| b.iter(|| black_box(trie.is_contain(black_box(&v6_miss)))));
    group.finish();
}

criterion_group!(benches, bench_domain_set, bench_domain_map, bench_domain_trie, bench_domain_build, bench_ip_cidr);
criterion_main!(benches);

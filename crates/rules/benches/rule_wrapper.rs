//! Compare production wrapper overhead for steady all-miss and last-rule-hit chains.
//! Both outcomes retain independent timestamp sampling state across scans.
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
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleWrapper as CRuleWrapper};

use murmur_rules_common::domain_suffix::DomainSuffix;

use murmur_rules::wrapper::wrapper::new_rule_wrapper;

/// Only the final rule in a last-hit chain matches this host.
const HIT_HOST: &str = "probe.example.com";

/// The host no rule in the bench matches, so an all-miss walk reaches the end of the chain.
const MISS_HOST: &str = "nomatch.invalid";

fn build_rules(count: usize, last_hit: bool) -> Vec<Arc<dyn Rule>> {
    (0..count)
        .map(|index| -> Arc<dyn Rule> {
            let suffix =
                if last_hit && index + 1 == count { HIT_HOST.to_owned() } else { format!("{HIT_HOST}.{index}") };
            Arc::new(DomainSuffix::new(&suffix, "WRAP-BENCH"))
        })
        .collect()
}

fn wrap(rules: &[Arc<dyn Rule>]) -> Vec<Arc<dyn CRuleWrapper>> {
    rules.iter().cloned().map(new_rule_wrapper).collect()
}

fn scan_bare(chain: &[Arc<dyn Rule>], metadata: &mut Metadata, helper: &RuleMatchHelper) -> (usize, bool) {
    let mut visited = 0;
    for rule in chain {
        visited += 1;
        if rule.match_(metadata, helper).0 {
            return (visited, true);
        }
    }
    (visited, false)
}

fn scan_wrapped(chain: &[Arc<dyn CRuleWrapper>], metadata: &mut Metadata, helper: &RuleMatchHelper) -> (usize, bool) {
    let mut visited = 0;
    for rule in chain {
        visited += 1;
        if rule.match_(metadata, helper).0 {
            return (visited, true);
        }
    }
    (visited, false)
}

fn metadata_for(host: &str) -> Metadata {
    Metadata { host: host.to_owned(), dst_port: 443, ..Default::default() }
}

fn bench_pair(
    c: &mut Criterion,
    group_name: &str,
    bare: &[Arc<dyn Rule>],
    wrapped: &[Arc<dyn CRuleWrapper>],
    host: &str,
    expected_hit: bool,
) {
    let helper = RuleMatchHelper::default();
    let mut bare_metadata = metadata_for(host);
    let mut wrapped_metadata = metadata_for(host);
    let expected = (bare.len(), expected_hit);
    assert_eq!(scan_bare(bare, &mut bare_metadata, &helper), expected, "{group_name} bare outcome");
    assert_eq!(scan_wrapped(wrapped, &mut wrapped_metadata, &helper), expected, "{group_name} wrapped outcome");

    for (index, rule) in wrapped.iter().enumerate() {
        let hit = u64::from(expected_hit && index + 1 == bare.len());
        assert_eq!(rule.hit_count(), hit, "{group_name} rule {index} hits");
        assert_eq!(rule.miss_count(), 1 - hit, "{group_name} rule {index} misses");
    }
    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Elements(u64::try_from(bare.len()).expect("chain length fits u64")));
    group.bench_function("bare", |b| b.iter(|| black_box(scan_bare(bare, &mut bare_metadata, &helper))));
    group.bench_function("wrapped", |b| b.iter(|| black_box(scan_wrapped(wrapped, &mut wrapped_metadata, &helper))));
    group.finish();
}

fn bench_all_miss(c: &mut Criterion) {
    for count in [16usize, 256, 1024] {
        let bare = build_rules(count, false);
        let wrapped = wrap(&bare);
        bench_pair(c, &format!("wrapper_all_miss/{count}"), &bare, &wrapped, MISS_HOST, false);
    }
}

fn bench_last_hit_steady(c: &mut Criterion) {
    for count in [16usize, 256, 1024] {
        let bare = build_rules(count, true);
        let wrapped = wrap(&bare);
        bench_pair(c, &format!("wrapper_last_hit_steady/{count}"), &bare, &wrapped, HIT_HOST, true);
    }
}

criterion_group!(benches, bench_all_miss, bench_last_hit_steady);
criterion_main!(benches);

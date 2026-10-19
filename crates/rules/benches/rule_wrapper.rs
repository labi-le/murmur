//! Benchmarks on the real `RuleWrapper`: a bare chain of rules against the same chain wrapped in
//! the production wrapper, at chain lengths 16, 256 and 1024.
//!
//! Two access patterns. The all-miss walk runs the chain to completion with no rule matching, so
//! the streak gate is cold and each rule pays a wall-clock reading. The steady all-hit walk is run
//! repeatedly over the same wrappers, leaving each rule deep inside a streak of one outcome, where
//! the clock reading is taken once per 256 matches instead of on every match. That is the case the
//! streak gate optimises, and the all-miss case alone would not show it.
//!
//! The workload shapes are [INFERENCE] from this implementation; no benchmarks exist to compare
//! against.
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

/// The host every rule in the bench matches.
const HIT_HOST: &str = "probe.example.com";

/// The host no rule in the bench matches, so an all-miss walk reaches the end of the chain.
const MISS_HOST: &str = "nomatch.invalid";

fn build_rules(count: usize) -> Vec<Arc<dyn Rule>> {
    (0..count)
        .map(|index| -> Arc<dyn Rule> { Arc::new(DomainSuffix::new(&format!("{HIT_HOST}.{index}"), "WRAP-BENCH")) })
        .collect()
}

fn wrap(rules: &[Arc<dyn Rule>]) -> Vec<Arc<dyn CRuleWrapper>> {
    rules.iter().cloned().map(new_rule_wrapper).collect()
}

fn scan_bare(chain: &[Arc<dyn Rule>], metadata: &mut Metadata, helper: &RuleMatchHelper) -> usize {
    let mut visited = 0;
    for rule in chain {
        visited += 1;
        if rule.match_(metadata, helper).0 {
            break;
        }
    }
    visited
}

fn scan_wrapped(chain: &[Arc<dyn CRuleWrapper>], metadata: &mut Metadata, helper: &RuleMatchHelper) -> usize {
    let mut visited = 0;
    for rule in chain {
        visited += 1;
        if rule.match_(metadata, helper).0 {
            break;
        }
    }
    visited
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
) {
    let helper = RuleMatchHelper::default();
    let mut bare_metadata = metadata_for(host);
    let mut wrapped_metadata = metadata_for(host);
    assert_eq!(scan_bare(bare, &mut bare_metadata, &helper), bare.len(), "{group_name} bare walks the whole chain");
    assert_eq!(
        scan_wrapped(wrapped, &mut wrapped_metadata, &helper),
        bare.len(),
        "{group_name} wrapped walks the whole chain"
    );

    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Elements(u64::try_from(bare.len()).expect("chain length fits u64")));
    group.bench_function("bare", |b| b.iter(|| black_box(scan_bare(bare, &mut bare_metadata, &helper))));
    group.bench_function("wrapped", |b| b.iter(|| black_box(scan_wrapped(wrapped, &mut wrapped_metadata, &helper))));
    group.finish();
}

fn bench_all_miss(c: &mut Criterion) {
    for count in [16usize, 256, 1024] {
        let bare = build_rules(count);
        let wrapped = wrap(&bare);
        bench_pair(c, &format!("wrapper_all_miss/{count}"), &bare, &wrapped, MISS_HOST);
    }
}

fn bench_all_hit_steady(c: &mut Criterion) {
    for count in [16usize, 256, 1024] {
        let bare = build_rules(count);
        let wrapped = wrap(&bare);
        bench_pair(c, &format!("wrapper_all_hit_steady/{count}"), &bare, &wrapped, HIT_HOST);
    }
}

criterion_group!(benches, bench_all_miss, bench_all_hit_steady);
criterion_main!(benches);

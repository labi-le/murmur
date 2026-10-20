//! Benchmarks for the metadata preparation in the UDP connection loop (`handle_udp_conn` in
//! `src/tunnel.rs`).
//!
//! This is NOT an end-to-end measurement of `handle_udp_conn`. That function needs a live socket,
//! a NAT table and a runtime, so it belongs in an integration test, not in a benchmark. What is
//! measured here is the allocation behaviour of the individual operations the loop performs, so
//! the cost of a `Metadata` clone can be attributed.
//!
//! On an established NAT key the clone no longer runs: `handle_udp_conn` borrows the key and asks
//! the table for the stored sender before building the metadata cell, and `udp_hit_path` measures
//! that path. The clone remains the first-packet cost — the cell the sniffer may mutate and the
//! dial task consumes — and `pre_handle_metadata` mutates the packet adapter's own metadata in
//! place through `metadata_mut()`, so it clones nothing. The per-dial
//! `starting_metadata.clone()` in `handle_udp_dial` runs once per dial, not once per datagram.
//!
//! Allocation count per clone: `crates/constant/src/metadata.rs` carries **14** heap-backed
//! fields, being twelve `String` and two `Option<Vec<String>>`, plus two address arcs that are
//! reference bumps rather than fresh buffers. A fully populated clone therefore costs **14**
//! heap allocations, measured by `rules-common/benches/alloc_census.rs` and printed there beside
//! the field count so the two can be compared directly.
//!
//! A benchmark is allowed to panic: it is a measurement harness, not a runtime path, and
//! `criterion`'s own helpers abort the process on a config error. Panicking here means "this number
//! is not trustworthy", which is the correct outcome for a measurement.

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
use std::net::{IpAddr, Ipv4Addr};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use murmur_constant::dns::DNSMode;
use murmur_constant::metadata::{Metadata, NetWork, Type};

/// Loop size for the two-shape comparison. Large enough that the per-datagram cost dominates
/// criterion's own loop overhead, small enough that one iteration stays well under a second.
const LOOP_ITERATIONS: usize = 4096;

/// A `Metadata` shaped the way a real UDP packet arriving through a tun or socks listener fills it:
/// both endpoint addresses, a host, geo lookups, ports and an outbound pinned to DIRECT.
fn populated_metadata() -> Metadata {
    Metadata {
        network: NetWork::UDP,
        type_: Type::TUN,
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        src_geo_ip: Some(vec!["private".to_owned(), "vpn".to_owned()]),
        dst_geo_ip: Some(vec!["US".to_owned(), "cloudflare".to_owned()]),
        src_ipasn: "AS64500".to_owned(),
        dst_ipasn: "AS13335".to_owned(),
        src_port: 53_000,
        dst_port: 443,
        in_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))),
        in_port: 7890,
        in_name: "tun-in".to_owned(),
        in_user: String::new(),
        rematch_name: String::new(),
        host: "example.com".to_owned(),
        dns_mode: DNSMode::DNS_NORMAL,
        uid: 1000,
        process: "murmur".to_owned(),
        process_path: "/usr/bin/murmur".to_owned(),
        special_proxy: "DIRECT".to_owned(),
        special_rules: String::new(),
        remote_dst: String::new(),
        dscp: 0,
        raw_src_addr: None,
        raw_dst_addr: None,
        sniff_host: String::new(),
    }
}

fn metadata_clone(criterion: &mut Criterion) {
    let metadata = populated_metadata();
    let mut group = criterion.benchmark_group("metadata_clone");
    group.throughput(Throughput::Elements(1));

    group.bench_function("clone", |bencher| {
        bencher.iter(|| {
            let cloned = metadata.clone();
            black_box(&cloned);
        });
    });

    group.bench_function("baseline", |bencher| {
        bencher.iter(|| black_box(&()));
    });

    group.finish();
}

/// The clone-versus-reuse shape: a miss pays for the clone once per flow, while the same clone
/// reused across datagrams pays once. The gap bounds what a miss-path clone costs; it is not a
/// candidate saving on the established path, which no longer clones (`udp_hit_path`).
fn clone_versus_reuse(criterion: &mut Criterion) {
    let metadata = populated_metadata();
    let iterations = u64::try_from(LOOP_ITERATIONS).unwrap_or(1);
    let mut group = criterion.benchmark_group("metadata_clone_shape");
    group.throughput(Throughput::Elements(iterations));

    group.bench_function("clone_per_datagram", |bencher| {
        bencher.iter_batched(
            || (),
            |()| {
                for _ in 0..LOOP_ITERATIONS {
                    black_box(&metadata.clone());
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("clone_once_reused", |bencher| {
        bencher.iter_batched(
            || (),
            |()| {
                let shared = black_box(metadata.clone());
                for _ in 0..LOOP_ITERATIONS {
                    black_box(&shared);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, metadata_clone, clone_versus_reuse);
criterion_main!(benches);

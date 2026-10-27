//! Microbenchmarks for the pooled buffer allocator: the global `get`/`put` block pool, a cold
//! (never-reused) allocation for comparison, and the `BytesMut` buffer pool.
//!
//! No prior benchmarks cover the allocator itself, only a bit trick, so these workload shapes
//! are [INFERENCE] from the Rust implementation.
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

use bytes::BytesMut;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use murmur_common_pool::alloc::{new_allocator, Allocator};
use murmur_common_pool::{get, get_buffer, put, put_buffer};

/// Relay/UDP sizes, pooled class boundaries, and an allocation above the 64 KiB pool ceiling.
const SIZES: [usize; 6] = [64, 1024, 16 * 1024, 32 * 1024, 64 * 1024, 128 * 1024];
const FILL: u8 = 0xA5;

fn fill_buffer(buf: &mut [u8]) {
    buf.fill(FILL);
    black_box(buf);
}

fn bench_pool_reuse(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool");
    for size in SIZES {
        let mut probe = get(size);
        assert_eq!(probe.len(), size, "get({size}) length");
        assert!(probe.capacity() >= size, "get({size}) capacity");
        fill_buffer(&mut probe);
        assert!(probe.iter().all(|byte| *byte == FILL), "fill({size}) content");
        put(probe).expect("allocator-owned buffers can be returned");

        group.throughput(Throughput::Elements(1));
        group.bench_function(format!("get_put/{size}").as_str(), |b| {
            b.iter(|| {
                let buf = black_box(get(black_box(size)));
                put(buf).expect("allocator-owned buffers can be returned");
            });
        });

        group.throughput(Throughput::Bytes(u64::try_from(size).expect("size fits u64")));
        group.bench_function(format!("get_fill_put/{size}").as_str(), |b| {
            b.iter(|| {
                let mut buf = get(black_box(size));
                fill_buffer(&mut buf);
                put(buf).expect("allocator-owned buffers can be returned");
            });
        });
    }
    group.finish();
}

fn bench_cold_alloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool_cold");
    for size in SIZES {
        group.throughput(Throughput::Bytes(u64::try_from(size).expect("size fits u64")));
        // A fresh allocator per iteration, so nothing is ever recycled: this is the
        // allocate-and-zero path the reuse group leaves out.
        group.bench_function(format!("get_drop/{size}").as_str(), |b| {
            b.iter(|| {
                let allocator = new_allocator();
                let buf = allocator.get(size);
                black_box(buf);
            });
        });
    }
    group.finish();
}

/// Idle ceiling the pool enforces on `put_buffer`, and the shape it is measured against.
const MAX_IDLE_CAPACITY: usize = 64 * 1024;
/// Slots in the ring-reuse scenario.
const RING_SLOTS: usize = 8;
/// Small-buffer width: an auth header, far below the idle ceiling.
const SMALL: usize = 64;

/// Drains the pool so a census run starts from a known state. There is no public drain, so this
/// pops until a default (zero-capacity) buffer comes back; that is the empty marker the pool
/// returns when it is empty, and anything real in the pool has capacity above it.
fn drain_pool() -> usize {
    let mut drained = 0;
    while get_buffer().capacity() != 0 {
        drained += 1;
        assert!(drained < 4096, "pool drain does not terminate");
    }
    drained
}

/// A buffer that occupies exactly the requested capacity, grown by writing so the allocation is
/// real rather than merely reserved.
fn sized(capacity: usize) -> BytesMut {
    let mut buf = BytesMut::with_capacity(capacity);
    buf.resize(capacity, FILL);
    assert_eq!(buf.capacity(), capacity, "resize must honour the requested capacity");
    buf
}

/// SCENARIO 1: high-water retention. One 64 KiB buffer is handed back, then small buffers are
/// cycled. The printed sequence is the capacity each small get actually returned.
fn census_high_water_retention() {
    drain_pool();
    put_buffer(sized(MAX_IDLE_CAPACITY));

    let mut sequence = Vec::new();
    for _ in 0..8 {
        let mut buf = get_buffer();
        buf.resize(SMALL, FILL);
        sequence.push(buf.capacity());
        put_buffer(buf);
    }
    println!("retention_after_64k_put/8_small_gets: {sequence:?}");
    println!(
        "  small gets returning >= 64 KiB: {}/8",
        sequence.iter().filter(|cap| **cap >= MAX_IDLE_CAPACITY).count()
    );
    println!("  untouched small buffer capacity: {}", sized(SMALL).capacity());
}

/// SCENARIO 2: ring reuse. A ring of buffers is pooled, one slot poisoned by a 64 KiB write, and
/// then one slot is drained at a time. How many gets come back large is the blast radius of one
/// oversized write.
fn census_ring_reuse() {
    drain_pool();
    for index in 0..RING_SLOTS {
        put_buffer(sized(if index == RING_SLOTS - 1 { MAX_IDLE_CAPACITY } else { SMALL }));
    }

    let mut sequence = Vec::new();
    for _ in 0..RING_SLOTS {
        let mut buf = get_buffer();
        buf.resize(SMALL, FILL);
        sequence.push(buf.capacity());
        put_buffer(buf);
    }
    println!("ring_reuse/{RING_SLOTS}_slots_1_poisoned: {sequence:?}");
    println!(
        "  slots handing back a large buffer: {}/{RING_SLOTS}",
        sequence.iter().filter(|cap| **cap >= MAX_IDLE_CAPACITY).count()
    );
}

/// SCENARIO 3, cost side. The first case is the pool as it stands: a caller that writes small
/// finds a 64 KiB block waiting and never reallocates. The second is what a shrink threshold
/// would add on every crossing: one right-sized allocation plus one drop of the large block.
fn bench_shrink_cost(c: &mut Criterion) {
    drain_pool();
    put_buffer(sized(MAX_IDLE_CAPACITY));

    let mut group = c.benchmark_group("bytes_buffer");
    group.throughput(Throughput::Elements(1));
    group.bench_function("shrink_cost/stay_pooled_64k", |b| {
        b.iter(|| {
            let mut buf = get_buffer();
            buf.resize(SMALL, FILL);
            let observed = black_box(buf.capacity());
            put_buffer(buf);
            black_box(observed)
        });
    });
    group.bench_function("shrink_cost/realloc_64k_to_64b", |b| {
        b.iter(|| {
            let mut big = sized(MAX_IDLE_CAPACITY);
            black_box(&mut big);
            let mut right_sized = sized(SMALL);
            right_sized.extend_from_slice(&big[..SMALL]);
            black_box(&mut right_sized);
            drop(big);
            black_box(right_sized.capacity())
        });
    });
    group.finish();
}

fn bench_bytes_buffer(c: &mut Criterion) {
    let mut seeded = BytesMut::with_capacity(4096);
    seeded.extend_from_slice(b"seed");
    put_buffer(seeded);
    let recycled = get_buffer();
    assert!(recycled.capacity() >= 4096, "the buffer pool must retain capacity");
    assert!(recycled.is_empty(), "a pooled buffer must come back cleared");
    put_buffer(recycled);

    let mut group = c.benchmark_group("bytes_buffer");
    group.throughput(Throughput::Elements(1));
    group.bench_function("get_put", |b| {
        b.iter(|| {
            let buf = get_buffer();
            let observed = black_box(buf.capacity());
            put_buffer(buf);
            black_box(observed)
        });
    });
    group.finish();
}

fn bench_census(c: &mut Criterion) {
    census_high_water_retention();
    census_ring_reuse();
    let mut group = c.benchmark_group("buffer_census");
    group.bench_function("scenarios", |b| b.iter(|| black_box(RING_SLOTS + SMALL)));
    group.finish();
}

criterion_group!(benches, bench_census, bench_pool_reuse, bench_cold_alloc, bench_bytes_buffer, bench_shrink_cost);
criterion_main!(benches);

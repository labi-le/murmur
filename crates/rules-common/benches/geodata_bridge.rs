//! Bridge cost benchmark.
//!
//! Bench scaffolding, not product code: the bans on `unwrap`/`expect` and the style tiers exist to
//! keep a long-lived server process alive, and a benchmark that panics should abort the run.
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
    clippy::nursery,
    clippy::as_conversions
)]

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use futures_util::FutureExt;

#[expect(clippy::unused_async, reason = "the ready future is the baseline this bench measures against")]
async fn warm_hit() -> usize {
    1
}

async fn yielding_hit() -> usize {
    tokio::task::yield_now().await;
    1
}

fn bridge_block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
}

fn bench_bridge(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("multi-thread runtime");

    let mut group = c.benchmark_group("geodata_bridge");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ready_future_with_bridge", |b| {
        let _guard = runtime.enter();
        b.iter(|| bridge_block_on(warm_hit()));
    });

    group.bench_function("yielding_future_with_bridge", |b| {
        let _guard = runtime.enter();
        b.iter(|| bridge_block_on(yielding_hit()));
    });

    group.bench_function("harness_loop_only", |b| {
        b.iter(|| warm_hit().now_or_never().expect("ready future"));
    });

    group.bench_function("on_worker_with_bridge", |b| {
        b.iter(|| {
            runtime
                .block_on(async { tokio::spawn(async { bridge_block_on(warm_hit()) }).await })
                .expect("join the bridge task")
        });
    });

    group.bench_function("on_worker_without_bridge", |b| {
        b.iter(|| {
            runtime.block_on(async { tokio::spawn(async { warm_hit().await }).await }).expect("join the bare task")
        });
    });

    group.finish();
}

criterion_group!(benches, bench_bridge);
criterion_main!(benches);

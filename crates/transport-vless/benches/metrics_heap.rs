//! Isolated heap-allocation metrics target. One case runs per process under `dhat`; the report
//! gives cumulative allocation/byte deltas across the measured loop plus the process lifetime peak.
//! `realloc` counts the whole new block size (dhat's accounting), so deltas over-count growing
//! buffers relative to incremental accounting.
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
use std::path::Path;
use std::process::ExitCode;

use serde::Serialize;

mod support;

use support::cases::{find, names, run_batch, Case, CASES};
use support::cli;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const TARGET: &str = "metrics_heap";
const SCHEMA_VERSION: u32 = 1;
const HEAP_PEAK_SCOPE: &str = "setup + warmup + measured loop, before report emission";
const HEAP_PEAK_BLOCKS_SCOPE: &str = "live blocks at peak heap bytes";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListRecord {
    schema_version: u32,
    target: &'static str,
    cases: Vec<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeapRecord {
    schema_version: u32,
    target: &'static str,
    case: &'static str,
    iterations: u64,
    warmup: u64,
    checksum: u64,
    bytes_per_operation: u64,
    operation_scope: &'static str,
    allocation_count: u64,
    allocated_bytes: u64,
    allocations_per_operation: f64,
    allocated_bytes_per_operation: f64,
    live_blocks_before: u64,
    live_blocks_after: u64,
    live_bytes_before: u64,
    live_bytes_after: u64,
    peak_heap_bytes_lifetime: u64,
    peak_heap_blocks_lifetime: u64,
    heap_peak_scope: &'static str,
    heap_peak_blocks_scope: &'static str,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("metrics_heap: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = cli::parse(TARGET, true)?;
    if args.list || (args.case.is_none() && !args.smoke) {
        return print_list();
    }

    let profiler = build_profiler(args.dhat_json.as_deref());
    if args.smoke {
        let mut records = Vec::with_capacity(CASES.len());
        for case in CASES {
            records.push(measure(case, 1, 0)?);
        }
        drop(profiler);
        for record in &records {
            print_record(record)?;
        }
        return Ok(());
    }

    let name = args.case.as_deref().expect("a case name is required outside smoke mode");
    let case = find(name).ok_or_else(|| format!("unknown case '{name}'"))?;
    let record = measure(case, args.iterations, args.warmup)?;
    drop(profiler);
    print_record(&record)
}

fn build_profiler(path: Option<&Path>) -> dhat::Profiler {
    match path {
        Some(path) => dhat::Profiler::builder().file_name(path).build(),
        None => dhat::Profiler::builder().testing().trim_backtraces(Some(0)).build(),
    }
}

fn measure(case: &'static Case, iterations: u64, warmup: u64) -> Result<HeapRecord, String> {
    let iterations_usize = usize::try_from(iterations).expect("iterations fits usize");
    let warmup_usize = usize::try_from(warmup).expect("warmup fits usize");

    let mut runner = (case.setup)();
    black_box(run_batch(&mut runner, warmup_usize, 0));

    let before = dhat::HeapStats::get();
    let checksum = run_batch(&mut runner, iterations_usize, warmup_usize);
    let after = dhat::HeapStats::get();

    let allocation_count = after.total_blocks - before.total_blocks;
    let allocated_bytes = after.total_bytes - before.total_bytes;
    let divisor = iterations as f64;
    Ok(HeapRecord {
        schema_version: SCHEMA_VERSION,
        target: TARGET,
        case: case.name,
        iterations,
        warmup,
        checksum,
        bytes_per_operation: case.bytes_per_operation,
        operation_scope: case.operation_scope,
        allocation_count,
        allocated_bytes,
        allocations_per_operation: allocation_count as f64 / divisor,
        allocated_bytes_per_operation: allocated_bytes as f64 / divisor,
        live_blocks_before: before.curr_blocks as u64,
        live_blocks_after: after.curr_blocks as u64,
        live_bytes_before: before.curr_bytes as u64,
        live_bytes_after: after.curr_bytes as u64,
        peak_heap_bytes_lifetime: after.max_bytes as u64,
        peak_heap_blocks_lifetime: after.max_blocks as u64,
        heap_peak_scope: HEAP_PEAK_SCOPE,
        heap_peak_blocks_scope: HEAP_PEAK_BLOCKS_SCOPE,
    })
}

fn print_list() -> Result<(), String> {
    let record = ListRecord { schema_version: SCHEMA_VERSION, target: TARGET, cases: names() };
    print_record(&record)
}

fn print_record<T: Serialize>(record: &T) -> Result<(), String> {
    let line = serde_json::to_string(record).map_err(|error| format!("cannot serialize record: {error}"))?;
    println!("{line}");
    Ok(())
}

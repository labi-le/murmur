//! CPU timing metrics target. One case runs per process; timing is a single amortized batch
//! elapsed (no per-iteration `Instant`), with RSS/HWM read from `/proc/self/status` outside the
//! timed window. Perf hardware counters are merged by the host orchestrator, not measured here.
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
use std::process::ExitCode;
use std::time::Instant;

use serde::Serialize;

mod support;

use support::cases::{find, names, run_batch, Case, CASES};
use support::cli;

const TARGET: &str = "metrics_cpu";
const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListRecord {
    schema_version: u32,
    target: &'static str,
    cases: Vec<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CpuRecord {
    schema_version: u32,
    target: &'static str,
    case: &'static str,
    iterations: u64,
    warmup: u64,
    checksum: u64,
    bytes_per_operation: u64,
    operation_scope: &'static str,
    elapsed_ns: u64,
    ns_per_operation: f64,
    #[serde(rename = "rssBeforeKiB")]
    rss_before_kib: u64,
    #[serde(rename = "rssAfterKiB")]
    rss_after_kib: u64,
    #[serde(rename = "hwmKiB")]
    hwm_kib: u64,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("metrics_cpu: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = cli::parse(TARGET, false)?;
    if args.list || (args.case.is_none() && !args.smoke) {
        return print_record(&ListRecord { schema_version: SCHEMA_VERSION, target: TARGET, cases: names() });
    }

    if args.smoke {
        for case in CASES {
            print_record(&measure(case, 1, 0)?)?;
        }
        return Ok(());
    }

    let name = args.case.as_deref().expect("a case name is required outside smoke mode");
    let case = find(name).ok_or_else(|| format!("unknown case '{name}'"))?;
    print_record(&measure(case, args.iterations, args.warmup)?)
}

fn measure(case: &'static Case, iterations: u64, warmup: u64) -> Result<CpuRecord, String> {
    let iterations_usize = usize::try_from(iterations).expect("iterations fits usize");
    let warmup_usize = usize::try_from(warmup).expect("warmup fits usize");

    let mut runner = (case.setup)();
    black_box(run_batch(&mut runner, warmup_usize, 0));

    let rss_before_kib = read_status_kib("VmRSS")?;
    let start = Instant::now();
    let checksum = run_batch(&mut runner, iterations_usize, warmup_usize);
    let elapsed_ns = u64::try_from(start.elapsed().as_nanos()).map_err(|_| "elapsed time exceeds u64".to_owned())?;
    let rss_after_kib = read_status_kib("VmRSS")?;
    let hwm_kib = read_status_kib("VmHWM")?;

    Ok(CpuRecord {
        schema_version: SCHEMA_VERSION,
        target: TARGET,
        case: case.name,
        iterations,
        warmup,
        checksum,
        bytes_per_operation: case.bytes_per_operation,
        operation_scope: case.operation_scope,
        elapsed_ns,
        ns_per_operation: elapsed_ns as f64 / iterations as f64,
        rss_before_kib,
        rss_after_kib,
        hwm_kib,
    })
}

fn read_status_kib(field: &str) -> Result<u64, String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("cannot read /proc/self/status: {error}"))?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            let value = rest.strip_prefix(':').ok_or_else(|| format!("/proc/self/status: malformed {field} line"))?;
            let number =
                value.split_whitespace().next().ok_or_else(|| format!("/proc/self/status: {field} has no value"))?;
            return number.parse::<u64>().map_err(|error| format!("/proc/self/status: cannot parse {field}: {error}"));
        }
    }
    Err(format!("/proc/self/status: {field} not found"))
}

fn print_record<T: Serialize>(record: &T) -> Result<(), String> {
    let line = serde_json::to_string(record).map_err(|error| format!("cannot serialize record: {error}"))?;
    println!("{line}");
    Ok(())
}

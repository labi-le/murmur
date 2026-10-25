//! The pprof HTTP mount: the `/debug` subrouter plus the profile handlers it serves.
//!
//! Endpoints that answer here: `index`, `cmdline`, `profile`, `symbol`, plus the `/debug/` and
//! `/debug/pprof` redirects and the no-cache headers set on every response. Everything else is
//! refused with a 501 and the reason:
//!
//! - DEVIATION `trace`: there is no runtime execution trace to emit.
//! - DEVIATION the runtime profiles `allocs`, `block`, `heap`, `mutex`, `threadcreate`: the Rust
//!   runtime keeps none of those registries.
//! - DEVIATION `/vars`: expvar has no registry to publish from.
//!
//! `profile` samples with the `pprof` crate (SIGPROF plus `backtrace`) and answers 500 when the
//! process is already profiling; the crate's own advice drops samples whose leaf frame is in
//! libc/libgcc/pthread/vdso. Differences that remain: the body is built before it is written
//! instead of streamed, `seconds` is read from the query string only (not a POST form body), and
//! the CPU sampler and the `symbol` symbolizer are Unix-only (the crate links `nix`/`findshlibs`),
//! so Windows answers 501 and a symbol count of 0 rather than inventing symbol data. `symbol`
//! accepts the `0x`/`0b`/`0o`/octal/decimal program counters but not digit-separator forms, and
//! `index` lists only the routes that answer here.
//!
//! With `diagnostic-profiling` disabled, `profile` and `symbol` answer 501; the mount stays intact.

use std::fmt::Write as _;

#[cfg(feature = "diagnostic-profiling")]
use http_body_util::BodyExt as _;
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{Method, Response, StatusCode};

use super::common::{empty_body, finish_response, full_body, status_only, Req, RespBody};
#[cfg(feature = "diagnostic-profiling")]
use super::server::query_param;

#[cfg(feature = "diagnostic-profiling")]
/// The profile default when `seconds` is absent, malformed or non-positive.
const DEFAULT_PROFILE_SECONDS: i64 = 30;

/// Expvar has no registry to read here.
const EXPVAR_UNAVAILABLE: &str = "vars: expvar has no equivalent here: nothing is published";

const TRACE_UNAVAILABLE: &str = "trace: Rust's runtime cannot record an execution trace";

/// The runtime profiles that are known here but not served, each with the reason.
const RUNTIME_PROFILES: &[(&str, &str)] = &[
    ("allocs", "no sampled allocation profile exists in Rust"),
    ("block", "no blocking-profile instrumentation exists in Rust"),
    ("goroutine", "there is no goroutine scheduler with an accessible stack registry"),
    ("heap", "no sampling heap profiler exists in Rust"),
    ("mutex", "no mutex contention instrumentation exists in Rust"),
    ("threadcreate", "no runtime thread-creation profile exists in Rust"),
];

/// The entries the index page lists for the handlers this module owns.
const INDEX_ENTRIES: &[(&str, &str)] = &[
    ("cmdline", "The command line invocation of the current program"),
    (
        "profile",
        "CPU profile. You can specify the duration in the seconds GET parameter. After you get the profile file, use the go tool pprof command to investigate the profile.",
    ),
    (
        "symbol",
        "Maps given program counters to function names. Counters can be specified in a GET raw query or POST body, multiple counters are separated by '+'.",
    ),
    (
        "trace",
        "A trace of execution of the current program. You can specify the duration in the seconds GET parameter. After you get the trace file, use the go tool trace command to investigate the trace.",
    ),
];

/// The pprof subrouter, mounted at `/debug`; `rest` is the request path after the `/debug`
/// prefix. `/debug/gc` is handled ahead of this mount, so it is the one route under `/debug` that
/// does not carry the no-cache headers.
pub(crate) async fn route(req: Req, rest: &str) -> Response<RespBody> {
    with_no_cache(dispatch(req, rest).await)
}

async fn dispatch(req: Req, rest: &str) -> Response<RespBody> {
    match rest {
        // The router normalizes both `/debug` and `/debug/` to the subrouter's `/`, whose GET
        // redirects to the request URI plus "/pprof/" - on `/debug/` that is the own double slash.
        "" | "/" => {
            if req.method() == Method::GET {
                redirect(&format!("{}/pprof/", request_uri(&req)))
            } else {
                status_only(StatusCode::METHOD_NOT_ALLOWED)
            }
        }
        "/pprof" => redirect(&format!("{}/", request_uri(&req))),
        "/vars" => plain_error(StatusCode::NOT_IMPLEMENTED, EXPVAR_UNAVAILABLE),
        _ => {
            let Some(name) = rest.strip_prefix("/pprof/") else {
                return status_only(StatusCode::NOT_FOUND);
            };
            match name {
                "" => index(),
                "cmdline" => cmdline(),
                "profile" => profile(&req).await,
                "symbol" => symbol(req).await,
                "trace" => unsupported("trace", TRACE_UNAVAILABLE),
                name => named_profile(name),
            }
        }
    }
}

/// Adds the no-cache headers every pprof response carries.
fn with_no_cache(mut resp: Response<RespBody>) -> Response<RespBody> {
    let headers = resp.headers_mut();
    headers.insert(header::EXPIRES, HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, no-transform, must-revalidate, private, max-age=0"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(HeaderName::from_static("x-accel-expires"), HeaderValue::from_static("0"));
    resp
}

/// The raw request target, query string included.
fn request_uri(req: &Req) -> String {
    match req.uri().path_and_query() {
        Some(path_and_query) => path_and_query.as_str().to_owned(),
        None => req.uri().path().to_owned(),
    }
}

fn redirect(location: &str) -> Response<RespBody> {
    Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, location)
        .body(empty_body())
        .unwrap_or_else(|_| status_only(StatusCode::INTERNAL_SERVER_ERROR))
}

fn plain_error(status: StatusCode, txt: &str) -> Response<RespBody> {
    text_response(status, txt, false)
}

/// The pprof error response, which differs from the plain one only by the pprof marker header.
fn serve_error(status: StatusCode, txt: &str) -> Response<RespBody> {
    text_response(status, txt, true)
}

fn text_response(status: StatusCode, txt: &str, mark_as_pprof: bool) -> Response<RespBody> {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff");
    if mark_as_pprof {
        builder = builder.header("X-Go-Pprof", "1");
    }
    let mut body = txt.to_owned();
    body.push('\n');
    finish_response(builder, full_body(body.into_bytes()))
}

/// The index page over the profiles that answer here.
fn index() -> Response<RespBody> {
    let mut html = String::from(
        "<html>\n<head>\n<title>/debug/pprof/</title>\n<style>\n.profile-name{\n\tdisplay:inline-block;\n\twidth:6rem;\n}\n</style>\n</head>\n<body>\n/debug/pprof/\n<br>\n<p>Set debug=1 as a query parameter to export in legacy text format</p>\n<br>\nTypes of profiles available:\n<table>\n<thead><td>Count</td><td>Profile</td></thead>\n",
    );
    for (name, _) in INDEX_ENTRIES {
        let _ = writeln!(html, "<tr><td>0</td><td><a href='{name}?debug=1'>{name}</a></td></tr>");
    }
    html.push_str("</table>\n<p>\nProfile Descriptions:\n<ul>\n");
    for (name, description) in INDEX_ENTRIES {
        let _ = writeln!(html, "<li><div class=profile-name>{name}: </div> {description}</li>");
    }
    html.push_str(
        "</ul>\n</p>\n<p>\nNot listed here: the runtime profiles (allocs, block, goroutine, heap, mutex, threadcreate) and /debug/vars, which this build answers with a 501.\n</p>\n</body>\n</html>",
    );
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff");
    finish_response(builder, full_body(html.into_bytes()))
}

/// The command line joined with NUL bytes.
fn cmdline() -> Response<RespBody> {
    let mut body: Vec<u8> = Vec::new();
    for (index, arg) in std::env::args_os().enumerate() {
        if index > 0 {
            body.push(0);
        }
        body.extend_from_slice(&arg_bytes(&arg));
    }
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff");
    finish_response(builder, full_body(body))
}

#[cfg(unix)]
fn arg_bytes(arg: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;

    arg.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn arg_bytes(arg: &std::ffi::OsStr) -> Vec<u8> {
    arg.to_string_lossy().into_owned().into_bytes()
}

/// Per-name routing: the known runtime profiles are refused with a reason, any other name answers
/// 404 `Unknown profile`.
fn named_profile(name: &str) -> Response<RespBody> {
    match RUNTIME_PROFILES.iter().find(|(profile, _)| *profile == name) {
        Some((_, reason)) => unsupported(name, reason),
        None => serve_error(StatusCode::NOT_FOUND, "Unknown profile"),
    }
}

fn unsupported(name: &str, reason: &str) -> Response<RespBody> {
    serve_error(StatusCode::NOT_IMPLEMENTED, &format!("{name}: not available in this build: {reason}"))
}

#[cfg(not(feature = "diagnostic-profiling"))]
#[expect(clippy::unused_async, reason = "matches the enabled handler signature")]
async fn symbol(_req: Req) -> Response<RespBody> {
    unsupported("symbol", "diagnostic-profiling feature is disabled")
}

#[cfg(feature = "diagnostic-profiling")]
/// Program counters from the raw query (GET) or body (POST), split on `+`.
async fn symbol(req: Req) -> Response<RespBody> {
    let mut body = String::from(if SYMBOL_LOOKUP_AVAILABLE { "num_symbols: 1\n" } else { "num_symbols: 0\n" });

    let input = if req.method() == Method::POST {
        match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(err) => {
                let _ = writeln!(body, "reading request: {err}");
                return symbol_response(body);
            }
        }
    } else {
        req.uri().query().unwrap_or("").as_bytes().to_vec()
    };

    for word in input.split(|byte| *byte == b'+') {
        if let Some(pc) = parse_program_counter(word) {
            if pc != 0 {
                if let Some(name) = resolve_program_counter(pc) {
                    let _ = writeln!(body, "{pc:#x} {name}");
                }
            }
        }
    }
    symbol_response(body)
}

#[cfg(feature = "diagnostic-profiling")]
fn symbol_response(body: String) -> Response<RespBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff");
    finish_response(builder, full_body(body.into_bytes()))
}

#[cfg(all(feature = "diagnostic-profiling", unix))]
const SYMBOL_LOOKUP_AVAILABLE: bool = true;

#[cfg(all(feature = "diagnostic-profiling", not(unix)))]
const SYMBOL_LOOKUP_AVAILABLE: bool = false;

#[cfg(feature = "diagnostic-profiling")]
/// Base 0 means the `0x`/`0b`/`0o` prefixes and a bare
/// leading zero for octal; anything else is decimal.
fn parse_program_counter(word: &[u8]) -> Option<u64> {
    let word = std::str::from_utf8(word).ok()?;
    let (digits, radix) = if let Some(rest) = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X")) {
        (rest, 16)
    } else if let Some(rest) = word.strip_prefix("0b").or_else(|| word.strip_prefix("0B")) {
        (rest, 2)
    } else if let Some(rest) = word.strip_prefix("0o").or_else(|| word.strip_prefix("0O")) {
        (rest, 8)
    } else if let Some(rest) = word.strip_prefix('0').filter(|rest| !rest.is_empty()) {
        (rest, 8)
    } else {
        (word, 10)
    };
    u64::from_str_radix(digits, radix).ok()
}

/// Resolves a program counter through the `backtrace` symbolizer the `pprof` crate already links,
/// which resolves an address against the executable and its shared objects. DEVIATION the address
/// is adjusted the way an unwinder treats a return address, so a bare function entry does not
/// resolve here.
#[cfg(all(feature = "diagnostic-profiling", unix))]
fn resolve_program_counter(pc: u64) -> Option<String> {
    let pc = usize::try_from(pc).ok()?;
    let mut name = None;
    backtrace::resolve(pc as *mut std::ffi::c_void, |symbol| {
        if name.is_none() {
            name = symbol.name().map(|name| name.to_string());
        }
    });
    name
}

#[cfg(all(feature = "diagnostic-profiling", not(unix)))]
fn resolve_program_counter(_pc: u64) -> Option<String> {
    None
}

#[cfg(not(feature = "diagnostic-profiling"))]
#[expect(clippy::unused_async, reason = "matches the enabled handler signature")]
async fn profile(_req: &Req) -> Response<RespBody> {
    unsupported("profile", "diagnostic-profiling feature is disabled")
}

#[cfg(feature = "diagnostic-profiling")]
async fn profile(req: &Req) -> Response<RespBody> {
    let seconds = query_param(req.uri().query().unwrap_or(""), "seconds")
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(DEFAULT_PROFILE_SECONDS);

    match collect_cpu_profile(seconds).await {
        Ok(body) => {
            let builder = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_DISPOSITION, "attachment; filename=\"profile\"")
                .header("X-Content-Type-Options", "nosniff");
            finish_response(builder, full_body(body))
        }
        Err(resp) => resp,
    }
}

#[cfg(all(feature = "diagnostic-profiling", unix))]
async fn collect_cpu_profile(seconds: i64) -> Result<Vec<u8>, Response<RespBody>> {
    let builder = ::pprof::ProfilerGuardBuilder::default().frequency(protobuf::CPU_SAMPLING_FREQUENCY);
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64", target_arch = "loongarch64"))]
    let builder = builder.blocklist(&["libc", "libgcc", "pthread", "vdso"]);
    let guard = builder.build().map_err(|err| {
        serve_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("Could not enable CPU profiling: {err}"))
    })?;

    let seconds = u64::try_from(seconds).unwrap_or(DEFAULT_PROFILE_SECONDS.unsigned_abs());
    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;

    let report = guard.report().build().map_err(|err| {
        serve_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("Could not collect CPU profile: {err}"))
    })?;
    Ok(protobuf::encode_gzip(
        &report.data,
        &protobuf::Timing {
            frequency: report.timing.frequency,
            start_time: report.timing.start_time,
            duration: report.timing.duration,
        },
    ))
}

#[cfg(all(feature = "diagnostic-profiling", not(unix)))]
#[expect(
    clippy::unused_async,
    reason = "the shared handler awaits this; on Unix the sampler behind it awaits for real"
)]
async fn collect_cpu_profile(_seconds: i64) -> Result<Vec<u8>, Response<RespBody>> {
    Err(unsupported("profile", "the CPU sampler builds on Unix targets only"))
}

/// The CPU profile writer, which emits a gzipped pprof profile. The `pprof` crate's own protobuf
/// backend is left disabled so its older `prost` major does not enter the lock file; these
/// messages are the subset of the profile protobuf that a CPU profile populates.
#[cfg(all(feature = "diagnostic-profiling", unix))]
mod protobuf {
    use std::collections::HashMap;
    use std::io::Write as _;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use prost::Message as _;

    /// The default CPU sampling frequency.
    pub(super) const CPU_SAMPLING_FREQUENCY: i32 = 100;

    const NANOS_PER_SECOND: i64 = 1_000_000_000;

    /// The parts of `pprof::ReportTiming` a profile carries. The type itself is private to the
    /// crate's `timer` module, so this is how its values reach here.
    pub(super) struct Timing {
        pub(super) frequency: i32,
        pub(super) start_time: SystemTime,
        pub(super) duration: Duration,
    }

    pub(super) fn encode_gzip(data: &HashMap<::pprof::Frames, isize>, timing: &Timing) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        let _ = encoder.write_all(&encode(data, timing));
        // The writer is a `Vec`, so `finish` can only hand back the buffer it built.
        encoder.finish().unwrap_or_default()
    }

    /// Locations are keyed by function, file and line rather than by demangled name alone, so
    /// same-named inlinees keep their own source line.
    fn encode(data: &HashMap<::pprof::Frames, isize>, timing: &Timing) -> Vec<u8> {
        let mut strings = StringTable::new();
        let samples = strings.intern("samples");
        let count = strings.intern("count");
        let cpu = strings.intern("cpu");
        let nanoseconds = strings.intern("nanoseconds");
        let thread = strings.intern("thread");

        let mut functions: Vec<Function> = Vec::new();
        let mut locations: Vec<Location> = Vec::new();
        let mut samples_out: Vec<Sample> = Vec::new();
        let mut function_ids: HashMap<(String, String, String), u64> = HashMap::new();
        let mut location_ids: HashMap<(String, String, String, u32), u64> = HashMap::new();

        for (frames, sample_count) in data {
            let mut sample_locations = Vec::new();
            for frame in &frames.frames {
                for symbol in frame {
                    let name = symbol.name();
                    let system_name = symbol.sys_name().into_owned();
                    let filename = symbol.filename().into_owned();
                    let line = symbol.lineno();
                    if let Some(id) = location_ids.get(&(name.clone(), system_name.clone(), filename.clone(), line)) {
                        sample_locations.push(*id);
                        continue;
                    }
                    let function = (name.clone(), system_name.clone(), filename.clone());
                    let function_id = if let Some(id) = function_ids.get(&function) {
                        *id
                    } else {
                        let id = u64::try_from(functions.len()).unwrap_or(u64::MAX) + 1;
                        functions.push(Function {
                            id,
                            name: strings.intern(&name),
                            system_name: strings.intern(&system_name),
                            filename: strings.intern(&filename),
                            start_line: 0,
                        });
                        function_ids.insert(function, id);
                        id
                    };
                    let id = u64::try_from(locations.len()).unwrap_or(u64::MAX) + 1;
                    locations.push(Location {
                        id,
                        mapping_id: 0,
                        address: symbol.addr.map_or(0, |addr| addr as usize as u64),
                        line: vec![Line { function_id, line: i64::from(line) }],
                        is_folded: false,
                    });
                    location_ids.insert((name, system_name, filename, line), id);
                    sample_locations.push(id);
                }
            }

            let count_value = *sample_count as i64;
            samples_out.push(Sample {
                location_id: sample_locations,
                value: vec![
                    count_value,
                    count_value.saturating_mul(NANOS_PER_SECOND) / i64::from(timing.frequency.max(1)),
                ],
                label: vec![Label {
                    key: thread,
                    str: strings.intern(&frames.thread_name_or_id()),
                    num: 0,
                    num_unit: 0,
                }],
            });
        }

        let period = NANOS_PER_SECOND / i64::from(timing.frequency.max(1));
        let cpu_value = ValueType { ty: cpu, unit: nanoseconds };
        let profile = Profile {
            sample_type: vec![ValueType { ty: samples, unit: count }, cpu_value.clone()],
            sample: samples_out,
            location: locations,
            function: functions,
            string_table: strings.table,
            time_nanos: timing.start_time.duration_since(UNIX_EPOCH).map_or(0, nanos),
            duration_nanos: nanos(timing.duration),
            period_type: Some(cpu_value),
            period,
        };
        profile.encode_to_vec()
    }

    fn nanos(duration: Duration) -> i64 {
        i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
    }

    /// The message fields are private to this module, so tests assert through the shape a pprof
    /// consumer reads.
    #[cfg(test)]
    pub(super) struct Decoded {
        pub(super) string_table: Vec<String>,
        pub(super) sample_type: Vec<(String, String)>,
        pub(super) sample_values: Vec<Vec<i64>>,
        pub(super) duration_nanos: i64,
        pub(super) period: i64,
    }

    #[cfg(test)]
    pub(super) fn decode(encoded: &[u8]) -> Option<Decoded> {
        fn string(table: &[String], index: i64) -> Option<String> {
            table.get(usize::try_from(index).ok()?).cloned()
        }

        let profile = Profile::decode(encoded).ok()?;
        let sample_type = profile
            .sample_type
            .iter()
            .map(|value| Some((string(&profile.string_table, value.ty)?, string(&profile.string_table, value.unit)?)))
            .collect::<Option<Vec<_>>>()?;
        Some(Decoded {
            string_table: profile.string_table,
            sample_type,
            sample_values: profile.sample.iter().map(|sample| sample.value.clone()).collect(),
            duration_nanos: profile.duration_nanos,
            period: profile.period,
        })
    }

    struct StringTable {
        table: Vec<String>,
        index: HashMap<String, i64>,
    }

    impl StringTable {
        fn new() -> Self {
            // The first entry of a profile's string table must be the empty string.
            Self { table: vec![String::new()], index: HashMap::new() }
        }

        fn intern(&mut self, value: &str) -> i64 {
            if let Some(id) = self.index.get(value) {
                return *id;
            }
            let id = i64::try_from(self.table.len()).unwrap_or(i64::MAX);
            self.table.push(value.to_owned());
            self.index.insert(value.to_owned(), id);
            id
        }
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct Profile {
        #[prost(message, repeated, tag = "1")]
        sample_type: Vec<ValueType>,
        #[prost(message, repeated, tag = "2")]
        sample: Vec<Sample>,
        #[prost(message, repeated, tag = "4")]
        location: Vec<Location>,
        #[prost(message, repeated, tag = "5")]
        function: Vec<Function>,
        #[prost(string, repeated, tag = "6")]
        string_table: Vec<String>,
        #[prost(int64, tag = "9")]
        time_nanos: i64,
        #[prost(int64, tag = "10")]
        duration_nanos: i64,
        #[prost(message, optional, tag = "11")]
        period_type: Option<ValueType>,
        #[prost(int64, tag = "12")]
        period: i64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct ValueType {
        #[prost(int64, tag = "1")]
        ty: i64,
        #[prost(int64, tag = "2")]
        unit: i64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct Sample {
        #[prost(uint64, repeated, tag = "1")]
        location_id: Vec<u64>,
        #[prost(int64, repeated, tag = "2")]
        value: Vec<i64>,
        #[prost(message, repeated, tag = "3")]
        label: Vec<Label>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct Label {
        #[prost(int64, tag = "1")]
        key: i64,
        #[prost(int64, tag = "2")]
        str: i64,
        #[prost(int64, tag = "3")]
        num: i64,
        #[prost(int64, tag = "4")]
        num_unit: i64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct Location {
        #[prost(uint64, tag = "1")]
        id: u64,
        #[prost(uint64, tag = "2")]
        mapping_id: u64,
        #[prost(uint64, tag = "3")]
        address: u64,
        #[prost(message, repeated, tag = "4")]
        line: Vec<Line>,
        #[prost(bool, tag = "5")]
        is_folded: bool,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct Line {
        #[prost(uint64, tag = "1")]
        function_id: u64,
        #[prost(int64, tag = "2")]
        line: i64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct Function {
        #[prost(uint64, tag = "1")]
        id: u64,
        #[prost(int64, tag = "2")]
        name: i64,
        #[prost(int64, tag = "3")]
        system_name: i64,
        #[prost(int64, tag = "4")]
        filename: i64,
        #[prost(int64, tag = "5")]
        start_line: i64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::server::test_http::{exchange, RawResponse};

    async fn pprof_request(rest: &'static str, method: &str, target: &str, extra: &str) -> RawResponse {
        let request = format!("{method} {target} HTTP/1.1\r\nHost: test\r\n{extra}Connection: close\r\n\r\n");
        exchange(move |req: Req| async move { route(req, rest).await }, &request).await
    }

    #[cfg(not(feature = "diagnostic-profiling"))]
    #[tokio::test]
    async fn disabled_diagnostics_refuse_profile_and_symbol_requests() {
        for (rest, target) in
            [("/pprof/profile", "/debug/pprof/profile?seconds=1"), ("/pprof/symbol", "/debug/pprof/symbol?0x10")]
        {
            for method in ["GET", "POST"] {
                let resp = pprof_request(rest, method, target, "Content-Length: 0\r\n").await;
                assert_eq!(resp.status, StatusCode::NOT_IMPLEMENTED);
                assert_eq!(resp.header("x-go-pprof"), Some("1"));
                assert_eq!(
                    resp.header("cache-control"),
                    Some("no-cache, no-store, no-transform, must-revalidate, private, max-age=0")
                );
                assert!(resp.body_text().contains("diagnostic-profiling feature is disabled"));
            }
        }
    }

    #[cfg(feature = "diagnostic-profiling")]
    fn marker() -> &'static str {
        if cfg!(unix) {
            "num_symbols: 1\n"
        } else {
            "num_symbols: 0\n"
        }
    }

    #[cfg(feature = "diagnostic-profiling")]
    #[test]
    fn parse_program_counter_accepts_gos_base_zero_forms() {
        assert_eq!(parse_program_counter(b"0x10"), Some(16));
        assert_eq!(parse_program_counter(b"0X10"), Some(16));
        assert_eq!(parse_program_counter(b"0b101"), Some(5));
        assert_eq!(parse_program_counter(b"0o17"), Some(15));
        assert_eq!(parse_program_counter(b"017"), Some(15));
        assert_eq!(parse_program_counter(b"17"), Some(17));
        assert_eq!(parse_program_counter(b"0"), Some(0));
        assert_eq!(parse_program_counter(b""), None);
        assert_eq!(parse_program_counter(b"0x"), None);
        assert_eq!(parse_program_counter(b"-1"), None);
        assert_eq!(parse_program_counter(b"abcdef"), None);
    }

    #[tokio::test]
    async fn index_lists_the_profiles_that_answer_here() {
        let resp = pprof_request("/pprof/", "GET", "/debug/pprof/", "").await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.header("content-type"), Some("text/html; charset=utf-8"));
        assert_eq!(resp.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(
            resp.header("cache-control"),
            Some("no-cache, no-store, no-transform, must-revalidate, private, max-age=0")
        );
        let body = resp.body_text();
        assert!(body.contains("Types of profiles available:"), "body: {body}");
        for name in ["cmdline", "profile", "symbol", "trace"] {
            assert!(body.contains(&format!("<a href='{name}?debug=1'>{name}</a>")), "body: {body}");
        }
    }

    #[tokio::test]
    async fn cmdline_joins_the_process_arguments_with_nul() {
        let resp = pprof_request("/pprof/cmdline", "GET", "/debug/pprof/cmdline", "").await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.header("content-type"), Some("text/plain; charset=utf-8"));
        assert_eq!(resp.header("x-content-type-options"), Some("nosniff"));
        assert!(!resp.body.is_empty());
        assert_ne!(resp.body.last(), Some(&0));
        assert_eq!(resp.body.split(|byte| *byte == 0).count(), std::env::args().count());
        assert!(resp.body.split(|byte| *byte == 0).all(|arg| !arg.is_empty()));
    }

    #[cfg(feature = "diagnostic-profiling")]
    #[tokio::test]
    async fn symbol_answers_the_go_shaped_table() {
        let resp = pprof_request("/pprof/symbol", "GET", "/debug/pprof/symbol", "").await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.header("content-type"), Some("text/plain; charset=utf-8"));
        assert_eq!(resp.body_text(), marker());
    }

    #[cfg(feature = "diagnostic-profiling")]
    #[tokio::test]
    async fn symbol_skips_counters_it_cannot_parse() {
        let resp = pprof_request("/pprof/symbol", "GET", "/debug/pprof/symbol?0+zzzz+0x", "").await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body_text(), marker());
    }

    #[cfg(all(feature = "diagnostic-profiling", unix))]
    #[inline(never)]
    fn pprof_symbol_lookup_target(seed: u64) -> u64 {
        std::hint::black_box(seed).wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17) ^ 0x5BEA_7D3F
    }

    #[cfg(all(feature = "diagnostic-profiling", unix))]
    #[tokio::test]
    async fn symbol_resolves_a_program_counter() {
        // One byte past the entry: the symbolizer adjusts an address the way an unwinder treats a
        // return address, which is the shape the counters in a profile come in as.
        let target: fn(u64) -> u64 = pprof_symbol_lookup_target;
        let pc = (target as usize) + 1;

        let resp = pprof_request("/pprof/symbol", "GET", &format!("/debug/pprof/symbol?{pc:#x}"), "").await;
        assert_eq!(resp.status, StatusCode::OK);
        let body = resp.body_text();
        assert!(body.starts_with(&format!("num_symbols: 1\n{pc:#x} ")), "body: {body}");
        assert!(body.contains("pprof_symbol_lookup_target"), "body: {body}");
    }

    #[tokio::test]
    async fn trace_runtime_profiles_and_expvar_are_refused() {
        let resp = pprof_request("/pprof/trace", "GET", "/debug/pprof/trace?seconds=1", "").await;
        assert_eq!(resp.status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(resp.header("x-go-pprof"), Some("1"));
        assert!(resp.body_text().starts_with("trace: not available in this build:"));

        let resp = pprof_request("/pprof/goroutine", "GET", "/debug/pprof/goroutine?debug=2", "").await;
        assert_eq!(resp.status, StatusCode::NOT_IMPLEMENTED);
        assert!(resp.body_text().starts_with("goroutine: not available in this build:"));

        let resp = pprof_request("/vars", "GET", "/debug/vars", "").await;
        assert_eq!(resp.status, StatusCode::NOT_IMPLEMENTED);
        assert!(resp.body_text().starts_with("vars:"));
    }

    #[tokio::test]
    async fn unknown_profile_answers_gos_404() {
        let resp = pprof_request("/pprof/<script>scripty<script>", "GET", "/debug/pprof/%3Cscript%3E", "").await;
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
        assert_eq!(resp.body_text(), "Unknown profile\n");
        assert_eq!(resp.header("x-go-pprof"), Some("1"));
    }

    #[tokio::test]
    async fn redirects_point_at_the_index() {
        let resp = pprof_request("/pprof", "GET", "/debug/pprof", "").await;
        assert_eq!(resp.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(resp.header("location"), Some("/debug/pprof/"));

        let resp = pprof_request("/", "GET", "/debug/", "").await;
        assert_eq!(resp.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(resp.header("location"), Some("/debug//pprof/"));

        let resp = pprof_request("/", "POST", "/debug/", "").await;
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[cfg(all(feature = "diagnostic-profiling", unix))]
    fn gunzip(body: &[u8]) -> Vec<u8> {
        use std::io::Read as _;

        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(body).read_to_end(&mut decoded).expect("body is gzip");
        decoded
    }

    #[cfg(all(feature = "diagnostic-profiling", unix))]
    #[test]
    fn encode_emits_a_pprof_profile_for_a_known_report() {
        let frame = ::pprof::Frames {
            frames: vec![vec![::pprof::Symbol {
                name: Some(b"_ZN3foo3barE".to_vec()),
                addr: None,
                lineno: Some(12),
                filename: Some(std::path::PathBuf::from("src/foo.rs")),
            }]],
            thread_name: "test".to_owned(),
            thread_id: 7,
            sample_timestamp: std::time::SystemTime::UNIX_EPOCH,
        };
        let data = std::collections::HashMap::from([(frame, 3_isize)]);
        let timing = protobuf::Timing {
            frequency: 100,
            start_time: std::time::SystemTime::UNIX_EPOCH,
            duration: std::time::Duration::from_secs(1),
        };

        let profile = protobuf::decode(&gunzip(&protobuf::encode_gzip(&data, &timing))).expect("profile decodes");
        assert_eq!(profile.string_table.first().map(String::as_str), Some(""));
        assert!(profile.string_table.contains(&"foo::bar".to_owned()), "table: {:?}", profile.string_table);
        assert_eq!(
            profile.sample_type,
            [("samples".to_owned(), "count".to_owned()), ("cpu".to_owned(), "nanoseconds".to_owned())]
        );
        assert_eq!(profile.period, 10_000_000);
        assert_eq!(profile.duration_nanos, 1_000_000_000);
        assert_eq!(profile.sample_values, [[3, 30_000_000]]);
    }

    #[cfg(all(feature = "diagnostic-profiling", unix))]
    #[tokio::test]
    async fn profile_endpoint_serves_a_gzipped_pprof_profile() {
        let resp = pprof_request("/pprof/profile", "GET", "/debug/pprof/profile?seconds=1", "").await;
        assert_eq!(resp.status, StatusCode::OK, "body: {}", resp.body_text());
        assert_eq!(resp.header("content-type"), Some("application/octet-stream"));
        assert_eq!(resp.header("content-disposition"), Some("attachment; filename=\"profile\""));
        assert_eq!(resp.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(resp.body.first(), Some(&0x1f));
        assert_eq!(resp.body.get(1), Some(&0x8b));

        let profile = protobuf::decode(&gunzip(&resp.body)).expect("profile decodes");
        assert_eq!(profile.string_table.first().map(String::as_str), Some(""));
        assert_eq!(profile.period, 10_000_000);
        assert!(profile.duration_nanos > 0);
    }

    #[cfg(all(feature = "diagnostic-profiling", not(unix)))]
    #[tokio::test]
    async fn profile_endpoint_is_refused_without_a_cpu_sampler() {
        let resp = pprof_request("/pprof/profile", "GET", "/debug/pprof/profile", "").await;
        assert_eq!(resp.status, StatusCode::NOT_IMPLEMENTED);
        assert!(resp.body_text().starts_with("profile: not available in this build:"));
    }
}

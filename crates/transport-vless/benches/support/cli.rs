//! Argument parsing shared by `metrics_heap` and `metrics_cpu`.

use std::path::PathBuf;

pub const DEFAULT_ITERATIONS: u64 = 1000;
pub const DEFAULT_WARMUP: u64 = 100;

#[derive(Debug)]
pub struct Args {
    pub list: bool,
    pub smoke: bool,
    pub case: Option<String>,
    pub iterations: u64,
    pub warmup: u64,
    pub dhat_json: Option<PathBuf>,
}

/// Parses the target's argv. `allow_dhat` is false for `metrics_cpu`, which has no allocator
/// instrumentation to dump.
pub fn parse(target: &str, allow_dhat: bool) -> Result<Args, String> {
    let mut args = Args {
        list: false,
        smoke: false,
        case: None,
        iterations: DEFAULT_ITERATIONS,
        warmup: DEFAULT_WARMUP,
        dhat_json: None,
    };
    let mut raw = std::env::args().skip(1);
    while let Some(arg) = raw.next() {
        match arg.as_str() {
            "--bench" => {}
            "--test" | "--smoke" => args.smoke = true,
            "--list" => args.list = true,
            "--case" => {
                let value = raw.next().ok_or_else(|| "--case requires a value".to_owned())?;
                if value.is_empty() {
                    return Err("--case requires a non-empty value".to_owned());
                }
                args.case = Some(value);
            }
            "--iterations" => {
                let value = raw.next().ok_or_else(|| "--iterations requires a value".to_owned())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| format!("--iterations expects a positive integer, got '{value}'"))?;
                if parsed == 0 {
                    return Err("--iterations must be positive".to_owned());
                }
                args.iterations = parsed;
            }
            "--warmup" => {
                let value = raw.next().ok_or_else(|| "--warmup requires a value".to_owned())?;
                args.warmup = value
                    .parse::<u64>()
                    .map_err(|_| format!("--warmup expects a nonnegative integer, got '{value}'"))?;
            }
            "--dhat-json" => {
                if !allow_dhat {
                    return Err("--dhat-json is only valid for the metrics_heap target".to_owned());
                }
                let value = raw.next().ok_or_else(|| "--dhat-json requires a path".to_owned())?;
                if value.is_empty() {
                    return Err("--dhat-json requires a non-empty path".to_owned());
                }
                args.dhat_json = Some(PathBuf::from(value));
            }
            other => return Err(format!("{target}: unknown argument '{other}'")),
        }
    }
    Ok(args)
}

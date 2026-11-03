//! No cgroup CPU quota is applied: the tokio runtime sizes its worker pool from
//! `available_parallelism`, which is quota-aware on Linux.
//!
//! Nothing enforces that the OS resolver stays unused — there is no hookable global resolver —
//! so `murmur_dns::system` keeps the `system` policy off it, while `tokio::net::lookup_host`
//! sites elsewhere in the workspace do use it.
//!
//! `-v` prints `RUSTC_VERSION` from `build.rs`; `CARGO_PKG_RUST_VERSION` is the manifest's MSRV,
//! not the compiler in use.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![cfg_attr(
    test,
    allow(
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
    )
)]

use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use murmur_component::age::age as age_mod;
use murmur_component_generator::cmd as generator_cmd;
use murmur_component_geodata::utils as geodata_utils;
use murmur_component_updater::update_geo;
use murmur_config::initial as config_initial;
use murmur_constant::path::PATH;
use murmur_constant::version;
use murmur_constant_features as features;
use murmur_dns::system as dns_system;
use murmur_hub::executor::executor as hub_executor;
use murmur_hub::hub;
use murmur_hub::watch as hub_watch;
use murmur_log::{debugln, errorln, fatalln, infoln};
use murmur_rules::provider::mrs_converter;

#[derive(Clone)]
enum FlagValue {
    Bool(bool),
    Str(String),
    Int(i32),
}

impl FlagValue {
    fn type_name(&self) -> &'static str {
        match self {
            Self::Bool(_) => "",
            Self::Str(_) => "string",
            Self::Int(_) => "int",
        }
    }

    fn is_zero(&self) -> bool {
        match self {
            Self::Bool(b) => !*b,
            Self::Str(s) => s.is_empty(),
            Self::Int(i) => *i == 0,
        }
    }

    fn display(&self) -> String {
        match self {
            Self::Bool(b) => b.to_string(),
            Self::Str(s) => format!("{s:?}"),
            Self::Int(i) => i.to_string(),
        }
    }

    fn set(&mut self, raw: &str) -> std::result::Result<(), ()> {
        match self {
            Self::Bool(b) => {
                *b = parse_bool_literal(raw)?;
            }
            Self::Str(s) => raw.clone_into(s),
            Self::Int(i) => *i = raw.parse::<i32>().map_err(|_| ())?,
        }
        Ok(())
    }

    fn set_true(&mut self) {
        if let Self::Bool(b) = self {
            *b = true;
        }
    }
}

fn parse_bool_literal(raw: &str) -> std::result::Result<bool, ()> {
    match raw {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(()),
    }
}

struct FlagDef {
    name: &'static str,
    usage: &'static str,
    default: FlagValue,
    value: FlagValue,
}

impl FlagDef {
    fn new(name: &'static str, usage: &'static str, default: FlagValue) -> Self {
        let value = default.clone();
        Self { name, usage, default, value }
    }
}

/// Reproduces the exact CLI surface.
#[expect(clippy::print_stderr, reason = "usage text is this CLI's user interface and goes to stderr")]
fn print_usage(prog: &str, flags: &[FlagDef]) {
    eprintln!("Usage of {prog}:");
    let mut sorted: Vec<&FlagDef> = flags.iter().collect();
    sorted.sort_by_key(|flag| flag.name);
    for flag in sorted {
        let mut line = format!("  -{}", flag.name);
        let type_name = flag.default.type_name();
        if !type_name.is_empty() {
            line.push(' ');
            line.push_str(type_name);
        }
        if line.len() <= 4 {
            line.push('\t');
        } else {
            line.push_str("\n    \t");
        }
        line.push_str(&flag.usage.replace('\n', "\n    \t"));
        if !flag.default.is_zero() {
            line.push_str(" (default ");
            line.push_str(&flag.default.display());
            line.push(')');
        }
        eprintln!("{line}");
    }
}

/// Parses `args` with exit-on-error semantics: on error or `-h`/`-help` this exits the process
/// directly.
#[expect(clippy::print_stderr, reason = "flag parse errors are this CLI's user interface and go to stderr")]
fn parse_flags(prog: &str, args: &[String], flags: &mut [FlagDef]) {
    let name_index: HashMap<&'static str, usize> = flags.iter().enumerate().map(|(i, f)| (f.name, i)).collect();
    let mut idx = 0;
    while idx < args.len() {
        let Some(s) = args.get(idx) else {
            break;
        };
        if s.len() < 2 || !s.starts_with('-') {
            break;
        }
        let (_, tail) = s.split_at(1);
        let mut rest = tail;
        if rest.starts_with('-') {
            if s.len() == 2 {
                break;
            }
            let (_, tail) = s.split_at(2);
            rest = tail;
        }
        if rest.is_empty() || rest.starts_with('-') || rest.starts_with('=') {
            eprintln!("bad flag syntax: {s}");
            print_usage(prog, flags);
            std::process::exit(2);
        }
        idx += 1;

        let (name, has_value, mut value) = match rest.find('=') {
            Some(pos) => {
                let (name, tail) = rest.split_at(pos);
                let (_, value) = tail.split_at(1);
                (name.to_owned(), true, value.to_owned())
            }
            None => (rest.to_owned(), false, String::new()),
        };

        let Some(&fi) = name_index.get(name.as_str()) else {
            if name == "help" || name == "h" {
                print_usage(prog, flags);
                std::process::exit(0);
            }
            eprintln!("flag provided but not defined: -{name}");
            print_usage(prog, flags);
            std::process::exit(2);
        };

        let Some(flag) = flags.get_mut(fi) else {
            break;
        };

        if matches!(flag.value, FlagValue::Bool(_)) {
            if has_value {
                if flag.value.set(&value).is_err() {
                    eprintln!("invalid boolean value {value:?} for -{name}: parse error");
                    print_usage(prog, flags);
                    std::process::exit(2);
                }
            } else {
                flag.value.set_true();
            }
            continue;
        }

        if !has_value {
            let Some(next) = args.get(idx) else {
                eprintln!("flag needs an argument: -{name}");
                print_usage(prog, flags);
                std::process::exit(2);
            };
            value.clone_from(next);
            idx += 1;
        }
        if flag.value.set(&value).is_err() {
            eprintln!("invalid value {value:?} for flag -{name}: parse error");
            print_usage(prog, flags);
            std::process::exit(2);
        }
    }
}

fn flag_str(flags: &[FlagDef], name: &str) -> String {
    flags
        .iter()
        .find(|f| f.name == name)
        .and_then(|f| match &f.value {
            FlagValue::Str(s) => Some(s.clone()),
            FlagValue::Bool(_) | FlagValue::Int(_) => None,
        })
        .unwrap_or_default()
}

fn flag_bool(flags: &[FlagDef], name: &str) -> bool {
    flags
        .iter()
        .find(|f| f.name == name)
        .and_then(|f| match &f.value {
            FlagValue::Bool(b) => Some(*b),
            FlagValue::Str(_) | FlagValue::Int(_) => None,
        })
        .unwrap_or(false)
}

fn flag_int(flags: &[FlagDef], name: &str) -> i32 {
    flags
        .iter()
        .find(|f| f.name == name)
        .and_then(|f| match &f.value {
            FlagValue::Int(i) => Some(*i),
            FlagValue::Bool(_) | FlagValue::Str(_) => None,
        })
        .unwrap_or(0)
}

fn get_int_env(key: &str) -> i32 {
    std::env::var(key).ok().and_then(|value| value.parse::<i32>().ok()).unwrap_or(0)
}

/// Joins a relative `path` onto the current directory.
fn resolve_relative(path: &str) -> String {
    if Path::new(path).is_absolute() {
        return path.to_owned();
    }
    let current_dir = std::env::current_dir().unwrap_or_default();
    current_dir.join(path).to_string_lossy().into_owned()
}

/// the package-level `var` block plus `init()`'s `flag.*Var` registrations.
fn define_flags() -> Vec<FlagDef> {
    vec![
        FlagDef::new(
            "d",
            "set configuration directory",
            FlagValue::Str(std::env::var("CLASH_HOME_DIR").unwrap_or_default()),
        ),
        FlagDef::new(
            "f",
            "specify configuration file",
            FlagValue::Str(std::env::var("CLASH_CONFIG_FILE").unwrap_or_default()),
        ),
        FlagDef::new(
            "config",
            "specify base64-encoded configuration string",
            FlagValue::Str(std::env::var("CLASH_CONFIG_STRING").unwrap_or_default()),
        ),
        FlagDef::new(
            "age-secret-key",
            "specify age secret key to decrypt configuration",
            FlagValue::Str(std::env::var("CLASH_AGE_SECRET_KEY").unwrap_or_default()),
        ),
        FlagDef::new(
            "ext-ui",
            "override external ui directory",
            FlagValue::Str(std::env::var("CLASH_OVERRIDE_EXTERNAL_UI_DIR").unwrap_or_default()),
        ),
        FlagDef::new(
            "ext-ctl",
            "override external controller address",
            FlagValue::Str(std::env::var("CLASH_OVERRIDE_EXTERNAL_CONTROLLER").unwrap_or_default()),
        ),
        FlagDef::new(
            "ext-ctl-tls",
            "override external controller tls address",
            FlagValue::Str(std::env::var("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_TLS").unwrap_or_default()),
        ),
        FlagDef::new(
            "ext-ctl-unix",
            "override external controller unix address",
            FlagValue::Str(std::env::var("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX").unwrap_or_default()),
        ),
        FlagDef::new(
            "ext-ctl-pipe",
            "override external controller pipe address",
            FlagValue::Str(std::env::var("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_PIPE").unwrap_or_default()),
        ),
        FlagDef::new(
            "ext-ctl-routing-mark",
            "override external controller routing mark",
            FlagValue::Int(get_int_env("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_ROUTING_MARK")),
        ),
        FlagDef::new(
            "secret",
            "override secret for RESTful API",
            FlagValue::Str(std::env::var("CLASH_OVERRIDE_SECRET").unwrap_or_default()),
        ),
        FlagDef::new(
            "post-up",
            "set post-up script",
            FlagValue::Str(std::env::var("CLASH_POST_UP").unwrap_or_default()),
        ),
        FlagDef::new(
            "post-down",
            "set post-down script",
            FlagValue::Str(std::env::var("CLASH_POST_DOWN").unwrap_or_default()),
        ),
        FlagDef::new(
            "watch-config",
            "watch the configuration file and reload it after every change (default: off)",
            FlagValue::Bool(false),
        ),
        FlagDef::new("m", "set geodata mode", FlagValue::Bool(false)),
        FlagDef::new("v", "show current version of murmur", FlagValue::Bool(false)),
        FlagDef::new("t", "test configuration and exit", FlagValue::Bool(false)),
    ]
}

/// Resolves after the watched file has stopped changing, returning its path.
///
/// Never resolves without a watcher, so the arm it backs is inert unless `--watch-config` is on.
///
/// cancel-safe: a queued tick stays in the channel and the quiet period restarts, so a cancelled
/// wait loses no change.
async fn watched_change(watch: &mut Option<hub_watch::ConfigWatcher>) -> PathBuf {
    match watch {
        Some(watch) => {
            watch.settled().await;
            watch.target().to_path_buf()
        }
        None => std::future::pending().await,
    }
}

/// Applies the watched file and reports what happened to it.
async fn reload_watched(target: &Path, options: &[hub::Option], applied: &mut Option<Vec<u8>>, force: bool) {
    match hub_watch::reload_from_disk(target, options, applied, force).await {
        hub_watch::Reload::Applied => infoln!("configuration file {} reloaded", target.display()),
        hub_watch::Reload::Unchanged => {
            debugln!("configuration file {} is unchanged; nothing to reload", target.display());
        }
        hub_watch::Reload::Failed(err) => {
            errorln!("configuration file {} was not applied: {err}", target.display());
        }
    }
}

#[cfg(unix)]
async fn wait_for_signal_or_reload(
    config_bytes: &[u8],
    options: &[hub::Option],
    mut watch: Option<hub_watch::ConfigWatcher>,
    mut applied: Option<Vec<u8>>,
) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(err) => {
            errorln!("failed to register SIGINT handler: {err}");
            return;
        }
    };
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(err) => {
            errorln!("failed to register SIGTERM handler: {err}");
            return;
        }
    };
    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(err) => {
            errorln!("failed to register SIGHUP handler: {err}");
            return;
        }
    };

    let watched = watch.as_ref().map(|watch| watch.target().to_path_buf());

    loop {
        tokio::select! {
            _ = sigint.recv() => return,
            _ = sigterm.recv() => return,
            _ = sighup.recv() => {
                match watched.as_deref() {
                    // Forced: an operator's SIGHUP reapplies the file even when it did not change,
                    // which is also what undoes a change made over the API.
                    Some(target) => reload_watched(target, options, &mut applied, true).await,
                    None => {
                        if let Err(err) = hub::parse(config_bytes, options).await {
                            errorln!("Parse config error: {err}");
                        }
                    }
                }
            }
            path = watched_change(&mut watch) => {
                infoln!("configuration file {} changed", path.display());
                reload_watched(&path, options, &mut applied, false).await;
            }
        }
    }
}

/// Windows has no `SIGHUP`-equivalent config-reload signal reachable without extra dependencies
/// beyond this crate's pinned dependency set, so the automatic watcher is the only reload path
/// here (deviation).
#[cfg(not(unix))]
async fn wait_for_signal_or_reload(
    _config_bytes: &[u8],
    options: &[hub::Option],
    mut watch: Option<hub_watch::ConfigWatcher>,
    mut applied: Option<Vec<u8>>,
) {
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);

    loop {
        tokio::select! {
            _ = &mut interrupt => return,
            path = watched_change(&mut watch) => {
                infoln!("configuration file {} changed", path.display());
                reload_watched(&path, options, &mut applied, false).await;
            }
        }
    }
}

#[expect(clippy::print_stdout, reason = "the version banner is this CLI's user interface")]
fn print_version() {
    println!(
        "murmur {} {} {} with rustc {} {}",
        version::VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH,
        option_env!("RUSTC_VERSION").unwrap_or(env!("CARGO_PKG_RUST_VERSION")),
        version::BUILD_TIME
    );
    println!("Protocol set: {}", if cfg!(feature = "extra-protocols") { "full" } else { "vvt" });
    if !cfg!(feature = "extra-protocols") {
        println!("Core updates: manual installation only");
    }
    let mut tags = features::tags();
    for (tag, enabled) in [
        ("no_easytier", cfg!(all(feature = "easytier", not(feature = "no_easytier")))),
        ("no_tailscale", cfg!(all(feature = "tailscale", feature = "with_gvisor", not(feature = "no_tailscale")))),
        ("no_zerotier", cfg!(all(feature = "zerotier", not(feature = "no_zerotier")))),
    ] {
        if !enabled && !tags.iter().any(|existing| existing == tag) {
            tags.push(tag.to_owned());
        }
    }
    if !tags.is_empty() {
        println!("Use tags: {}", tags.join(", "));
    }
}

/// The subcommand dispatch; `true` means the subcommand took the process over.
fn run_subcommand(raw_args: &[String]) -> bool {
    if raw_args.get(1).is_some_and(|arg| arg == "convert-ruleset") {
        mrs_converter::convert_main(raw_args.get(2..).unwrap_or_default());
        return true;
    }
    if raw_args.get(1).is_some_and(|arg| arg == "generate") {
        generator_cmd::main(raw_args.get(2..).unwrap_or_default());
        return true;
    }
    if raw_args.get(1).is_some_and(|arg| arg == "age") {
        age_mod::main(raw_args.get(2..).unwrap_or_default());
        return true;
    }
    false
}

fn apply_early_flags(flags: &[FlagDef]) {
    let home_dir = flag_str(flags, "d");
    if !home_dir.is_empty() {
        PATH.set_home_dir(&resolve_relative(&home_dir));
    }

    if flag_bool(flags, "m") {
        geodata_utils::set_geodata_mode(true);
    }

    let age_secret_key = flag_str(flags, "age-secret-key");
    if !age_secret_key.is_empty() {
        let keys = [age_secret_key];
        if let Err(err) = age_mod::verity_secret_keys(&keys) {
            errorln!("Parse age-secret-key error: {err}");
        }
        age_mod::set_global_secret_keys(&keys);
    }
}

/// `None` means the failure was reported already and `main` should return `Ok(())`.
fn initial_config_bytes(flags: &[FlagDef]) -> Option<Vec<u8>> {
    let config_string = flag_str(flags, "config");
    let mut config_file = flag_str(flags, "f");
    if !config_string.is_empty() {
        return match STANDARD.decode(&config_string) {
            Ok(bytes) => Some(bytes),
            Err(err) => {
                fatalln!("Initial configuration error: {err}");
                None
            }
        };
    }
    if config_file == "-" {
        let mut buf = Vec::new();
        if let Err(err) = std::io::stdin().read_to_end(&mut buf) {
            fatalln!("Initial configuration error: {err}");
            return None;
        }
        return Some(buf);
    }
    if config_file.is_empty() {
        config_file = Path::new(&PATH.home_dir()).join(PATH.config()).to_string_lossy().into_owned();
    } else {
        config_file = resolve_relative(&config_file);
    }
    PATH.set_config(&config_file);

    if let Err(err) = config_initial::init(&PATH.home_dir()) {
        fatalln!("Initial configuration directory error: {err}");
        return None;
    }
    Some(Vec::new())
}

#[expect(clippy::print_stdout, reason = "the configuration test result is this CLI's user interface")]
async fn test_configuration(config_bytes: &[u8]) {
    if !config_bytes.is_empty() {
        if let Err(err) = hub_executor::parse_with_bytes(config_bytes).await {
            errorln!("{err}");
            println!("configuration test failed");
            std::process::exit(1);
        }
    } else if let Err(err) = hub_executor::parse().await {
        errorln!("{err}");
        println!("configuration file {} test failed", PATH.config());
        std::process::exit(1);
    }
    println!("configuration file {} test is successful", PATH.config());
}

fn hub_options(flags: &[FlagDef]) -> Vec<hub::Option> {
    let mut options: Vec<hub::Option> = Vec::new();
    let external_ui = flag_str(flags, "ext-ui");
    if !external_ui.is_empty() {
        options.push(hub::with_external_ui(&external_ui));
    }
    let external_controller = flag_str(flags, "ext-ctl");
    if !external_controller.is_empty() {
        options.push(hub::with_external_controller(&external_controller));
    }
    let external_controller_tls = flag_str(flags, "ext-ctl-tls");
    if !external_controller_tls.is_empty() {
        options.push(hub::with_external_controller_tls(&external_controller_tls));
    }
    let external_controller_unix = flag_str(flags, "ext-ctl-unix");
    if !external_controller_unix.is_empty() {
        options.push(hub::with_external_controller_unix(&external_controller_unix));
    }
    let external_controller_pipe = flag_str(flags, "ext-ctl-pipe");
    if !external_controller_pipe.is_empty() {
        options.push(hub::with_external_controller_pipe(&external_controller_pipe));
    }
    let external_controller_routing_mark = flag_int(flags, "ext-ctl-routing-mark");
    if external_controller_routing_mark != 0 {
        options.push(hub::with_external_controller_routing_mark(external_controller_routing_mark));
    }
    let secret = flag_str(flags, "secret");
    if !secret.is_empty() {
        options.push(hub::with_secret(&secret));
    }
    options
}

/// Whether `--watch-config` was asked for and its startup source can be watched.
///
/// The watched file is the one `-f` resolves at startup (`PATH.config()`), never a fixed file name.
/// `-f -` and `--config` carry the configuration in the process arguments, so there is nothing on
/// disk to watch: watch mode is refused for them instead of falling back to the default path. This
/// runs before the source is read, because `-f -` would otherwise wait for stdin to close.
fn watch_requested(flags: &[FlagDef]) -> Result<bool> {
    if !flag_bool(flags, "watch-config") {
        return Ok(false);
    }
    if !flag_str(flags, "config").is_empty() || flag_str(flags, "f") == "-" {
        bail!(
            "--watch-config needs a configuration file on disk; `-f -` and `--config` keep the configuration in the process arguments"
        );
    }
    Ok(true)
}

#[tokio::main]
async fn main() -> Result<()> {
    dns_system::init();
    #[cfg(all(feature = "tailscale", feature = "with_gvisor", not(feature = "no_tailscale")))]
    murmur_adapter_outbound::tailscale::init();

    let raw_args: Vec<String> = std::env::args().collect();
    let prog = raw_args.first().cloned().unwrap_or_default();
    let mut flags = define_flags();
    parse_flags(&prog, raw_args.get(1..).unwrap_or_default(), &mut flags);

    if run_subcommand(&raw_args) {
        return Ok(());
    }

    if flag_bool(&flags, "v") {
        print_version();
        return Ok(());
    }

    apply_early_flags(&flags);

    // A watch mode whose source has no file is refused before that source is read: `-f -` would
    // otherwise wait for stdin to close. `-t` never starts a watcher, so it keeps the plain
    // "read the configuration, then exit" behaviour.
    let watching = if flag_bool(&flags, "t") {
        false
    } else {
        match watch_requested(&flags) {
            Ok(watching) => watching,
            Err(err) => {
                fatalln!("watch mode error: {err}");
                return Ok(());
            }
        }
    };

    let Some(config_bytes) = initial_config_bytes(&flags) else {
        return Ok(());
    };

    if flag_bool(&flags, "t") {
        test_configuration(&config_bytes).await;
        return Ok(());
    }

    let options = hub_options(&flags);

    // The watch registers before the file is read: a replacement landing between the read and the
    // registration would otherwise be missed, and the process would keep the bytes it parsed
    // until the next edit. An event arriving during startup stays queued in the watcher.
    let watch = if watching {
        match hub_watch::ConfigWatcher::new(&PATH.config()).await {
            Ok(watcher) => Some(watcher),
            Err(err) => {
                fatalln!("watch mode error: {err}");
                return Ok(());
            }
        }
    } else {
        None
    };

    // Watch mode reads the file itself and hands those exact bytes to the first parse, so the
    // reload loop starts holding the configuration that is already running: a byte-identical save
    // is then skipped as unchanged instead of replacing a change made over the API. Reading the
    // file after the parse instead would race with an edit.
    let (config_bytes, applied) = if watching {
        match tokio::fs::read(PATH.config()).await {
            Ok(bytes) => {
                let applied = Some(bytes.clone());
                (bytes, applied)
            }
            Err(err) => {
                fatalln!("Initial configuration error: cannot read {}: {err}", PATH.config());
                return Ok(());
            }
        }
    } else {
        (config_bytes, None)
    };

    murmur_tunnel::tunnel::prepare_udp();
    if let Err(err) = hub::parse(&config_bytes, &options).await {
        fatalln!("Parse config error: {err}");
        return Ok(());
    }

    if update_geo::geo_auto_update() {
        update_geo::register_geo_updater();
    }

    let post_up = flag_str(&flags, "post-up");
    if !post_up.is_empty() {
        if let Err(err) = murmur_common::cmd::exec_shell(&post_up).await {
            fatalln!("post-up script error: {err}");
            return Ok(());
        }
    }

    wait_for_signal_or_reload(&config_bytes, &options, watch, applied).await;

    hub_executor::shutdown().await;

    let post_down = flag_str(&flags, "post-down");
    if !post_down.is_empty() {
        if let Err(err) = murmur_common::cmd::exec_shell(&post_down).await {
            errorln!("post-down script error: {err}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Vec<FlagDef> {
        let mut flags = define_flags();
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        parse_flags("murmur", &args, &mut flags);
        flags
    }

    #[test]
    fn bool_literals_accept_the_expected_forms() {
        for raw in ["1", "t", "T", "TRUE", "true", "True"] {
            assert_eq!(parse_bool_literal(raw), Ok(true), "{raw}");
        }
        for raw in ["0", "f", "F", "FALSE", "false", "False"] {
            assert_eq!(parse_bool_literal(raw), Ok(false), "{raw}");
        }
        for raw in ["", "yes", "TRUE ", "2"] {
            assert!(parse_bool_literal(raw).is_err(), "{raw}");
        }
    }

    /// Boolean flags accept a bare and an `=`-valued form; the last occurrence wins.
    #[test]
    fn bool_flags_take_bare_and_valued_forms() {
        assert!(flag_bool(&parse(&["-v"]), "v"));
        assert!(flag_bool(&parse(&["--v"]), "v"));
        assert!(!flag_bool(&parse(&["-v=false"]), "v"));
        assert!(flag_bool(&parse(&["-v=false", "-v"]), "v"));
        assert!(!flag_bool(&parse(&["-v", "-v=false"]), "v"));
    }

    /// A non-boolean flag takes the next argument verbatim, flags included.
    #[test]
    fn value_flags_consume_the_next_argument() {
        let flags = parse(&["-f", "-v"]);
        assert_eq!(flag_str(&flags, "f"), "-v");
        assert!(!flag_bool(&flags, "v"));

        let flags = parse(&["--secret", "s3cret", "-d", "/tmp/murmur", "-ext-ctl-routing-mark", "7"]);
        assert_eq!(flag_str(&flags, "secret"), "s3cret");
        assert_eq!(flag_str(&flags, "d"), "/tmp/murmur");
        assert_eq!(flag_int(&flags, "ext-ctl-routing-mark"), 7);
    }

    /// Parsing stops at the first non-flag argument or `--`, leaving it free for subcommand
    /// dispatch.
    #[test]
    fn parsing_stops_at_the_first_non_flag_argument() {
        assert!(!flag_bool(&parse(&["convert-ruleset", "-v"]), "v"));
        assert!(!flag_bool(&parse(&["--", "-v"]), "v"));
    }

    /// `--watch-config` is refused for the startup sources that keep the configuration in the
    /// process arguments, and stays off unless it is asked for.
    #[test]
    fn watch_mode_is_refused_without_a_configuration_file() {
        assert!(!watch_requested(&parse(&[])).expect("watch mode defaults to off"));

        for args in [&["-f", "-", "--watch-config"][..], &["--config", "Z2VuZXJhbDoge30=", "--watch-config"][..]] {
            assert!(watch_requested(&parse(args)).is_err(), "{args:?} has no file to watch");
        }

        let file = parse(&["-f", "/tmp/murmur-config.yaml", "--watch-config"]);
        assert!(watch_requested(&file).expect("a file path is watchable"));
    }
}

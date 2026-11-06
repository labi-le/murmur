//! `murmur --watch-config` against the real binary: the file it watches is the path `-f` resolved,
//! and an atomic replacement of that file changes proxy routing with no signal, no API call and no
//! restart. It runs the binary in its own process, so the listeners and the process-global
//! configuration it installs cannot race the unit tests beside it.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
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

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long one step may take: a watched edit is applied after the quiet period, and the process
/// needs its own startup time.
const DEADLINE: Duration = Duration::from_secs(20);

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_murmur")
}

/// A directory under the system temp directory, one per test name and process.
fn fixture_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("murmur-watch-config-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("the fixture directory must be creatable");
    dir
}

/// A configuration whose proxied requests are routed by the rule this file names.
fn config_yaml(proxy: u16, rules: &str) -> String {
    format!("mixed-port: {proxy}\nmode: rule\nlog-level: info\nrules:\n{rules}")
}

/// Replaces `path` through a sibling file and a rename, the way an editor or a configuration
/// generator saves it.
fn replace(path: &Path, content: &str) {
    let replacement = path.with_extension("replacement");
    fs::write(&replacement, content).expect("the replacement must be writable");
    fs::rename(&replacement, path).expect("the replacement must be renamed over the target");
}

/// Serves `ok` once per connection, `delay` after reading the request, and counts the connections
/// it accepts so a test can tell that a flow is established before it reloads.
fn spawn_origin(delay: Duration) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the origin must bind");
    let port = listener.local_addr().expect("the origin has an address").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            std::thread::sleep(delay);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (port, accepted)
}

/// A loopback port nothing holds right now, for the mixed listener under test.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the probe must bind");
    let port = listener.local_addr().expect("the probe has an address").port();
    drop(listener);
    port
}

fn request(origin: u16) -> String {
    format!("GET http://127.0.0.1:{origin}/ HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\nConnection: close\r\n\r\n")
}

/// One proxied `GET` through the mixed listener, or `None` when the proxy refused the connection.
fn get_through_proxy(proxy: u16, origin: u16) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy)).ok()?;
    stream.set_read_timeout(Some(DEADLINE)).ok()?;
    stream.write_all(request(origin).as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    response.split_whitespace().nth(1)?.parse().ok()
}

/// Polls the proxy until it answers `want`, then returns the answer.
fn await_proxy(proxy: u16, origin: u16, want: &str, predicate: impl Fn(Option<u16>) -> bool) -> Option<u16> {
    let deadline = Instant::now() + DEADLINE;
    let mut last = None;
    while Instant::now() < deadline {
        last = get_through_proxy(proxy, origin);
        if predicate(last) {
            return last;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the proxy never {want}; the last answer was {last:?}");
}

/// The status line of the response on an established flow, read until the origin closes it.
fn read_status(stream: &mut TcpStream) -> u16 {
    stream.set_read_timeout(Some(DEADLINE)).expect("the read timeout must be settable");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("the established flow must still deliver the response");
    response.split_whitespace().nth(1).expect("a status line").parse().expect("a status code")
}

/// Whether the child is still the same running process.
fn still_running(child: &mut Child) -> bool {
    child.try_wait().expect("the child state must be queryable").is_none()
}

/// Polls the child's log until it has logged `needle` at least `count` times.
fn await_log(log: &Path, needle: &str, count: usize) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let logged = fs::read_to_string(log).unwrap_or_default();
        if logged.matches(needle).count() >= count {
            return;
        }
        assert!(Instant::now() < deadline, "the log never contained {count} {needle:?}: {logged}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Polls until the loopback port accepts a connection, or stops accepting one.
fn await_port(port: u16, expect_open: bool) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() == expect_open {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "127.0.0.1:{port} never {}",
            if expect_open { "accepted a connection" } else { "released the port" }
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Polls until the origin has accepted `count` connections.
fn await_accepted(accepted: &AtomicUsize, count: usize) {
    let deadline = Instant::now() + DEADLINE;
    while accepted.load(Ordering::SeqCst) < count {
        assert!(Instant::now() < deadline, "the origin was not reached {count} times");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn spawn_watching(dir: &Path, config: &Path, log_path: &Path) -> Child {
    let log = fs::File::create(log_path).expect("the log file must be creatable");
    Command::new(binary())
        .arg("-d")
        .arg(dir)
        .arg("-f")
        .arg(config)
        .arg("--watch-config")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().expect("the log handle must clone")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("the murmur binary must start")
}

/// The `MATCH,DIRECT` rule this file is written with, as the fixture's own line.
const DIRECT: &str = "  - MATCH,DIRECT\n";
/// The same outcome through a longer list, for a change that only touches the rules.
const DIRECT_WITH_EXTRA_RULE: &str = "  - DOMAIN,unrelated.example,REJECT\n  - MATCH,DIRECT\n";

/// A disk edit changes observable routing without a signal, an API call or a restart; a malformed
/// edit leaves the running rule in place and a later valid save recovers.
#[test]
fn an_atomic_config_replacement_changes_routing_without_a_signal_or_restart() {
    let (origin, _accepted) = spawn_origin(Duration::ZERO);
    let proxy = free_port();
    let dir = fixture_dir("replace");
    let config = dir.join("config.yaml");
    let log_path = dir.join("murmur.log");
    fs::write(&config, config_yaml(proxy, DIRECT)).expect("the configuration must be writable");

    let mut child = spawn_watching(&dir, &config, &log_path);
    assert_eq!(
        await_proxy(proxy, origin, "proxied the first request", |status| status == Some(200)),
        Some(200),
        "the seeded direct rule must proxy the request"
    );

    replace(&config, &config_yaml(proxy, "  - MATCH,REJECT\n"));
    let rejected = await_proxy(proxy, origin, "rejected the request", |status| status != Some(200));
    assert_ne!(rejected, Some(200), "the replaced rule must reject the request");
    assert!(still_running(&mut child), "the process must not have been restarted");

    // Wait for the watcher to have read the malformed file before checking what is still running:
    // the rejection is the observable that says it did.
    replace(&config, "rules: [\n");
    await_log(&log_path, "was not applied", 1);
    assert_ne!(
        get_through_proxy(proxy, origin),
        Some(200),
        "a malformed file must leave the last good configuration running"
    );
    assert!(still_running(&mut child), "the process must survive a rejected configuration");

    replace(&config, &config_yaml(proxy, DIRECT));
    let recovered = await_proxy(proxy, origin, "recovered", |status| status == Some(200));
    assert_eq!(recovered, Some(200), "a later valid save must recover");
    assert!(still_running(&mut child), "the process must not have been restarted");

    child.kill().expect("the child must be killable");
    let _ = child.wait();

    let logged = fs::read_to_string(&log_path).expect("the log must be readable");
    assert!(logged.contains("configuration file"), "the reload path logged nothing: {logged}");
    assert!(logged.contains("reloaded"), "a completed reload must be logged: {logged}");
    assert!(logged.contains("was not applied"), "a configuration that did not apply must be logged: {logged}");

    let _ = fs::remove_dir_all(&dir);
}

/// A rules-only reload leaves the flow that was already running: the response to a request that
/// was in flight when the file changed still arrives on the same connection.
#[test]
fn a_rules_only_reload_leaves_an_established_flow_running() {
    let (origin, accepted) = spawn_origin(Duration::from_secs(3));
    let proxy = free_port();
    let dir = fixture_dir("flow");
    let config = dir.join("config.yaml");
    let log_path = dir.join("murmur.log");
    fs::write(&config, config_yaml(proxy, DIRECT)).expect("the configuration must be writable");

    let mut child = spawn_watching(&dir, &config, &log_path);

    await_port(proxy, true);
    let mut flow = TcpStream::connect(("127.0.0.1", proxy)).expect("the proxy must accept the flow");
    flow.write_all(request(origin).as_bytes()).expect("the request must be written");
    await_accepted(&accepted, 1);

    replace(&config, &config_yaml(proxy, DIRECT_WITH_EXTRA_RULE));
    await_log(&log_path, "reloaded", 1);

    assert_eq!(read_status(&mut flow), 200, "the established flow must survive a rules-only reload");
    assert!(still_running(&mut child), "the process must not have been restarted");

    child.kill().expect("the child must be killable");
    let _ = child.wait();
    let _ = fs::remove_dir_all(&dir);
}

/// Watch mode is refused, not silently redirected to another file, when the startup configuration
/// has no path to watch.
#[test]
fn watch_mode_is_refused_for_inputs_without_a_file() {
    let dir = fixture_dir("refused");

    for args in [
        ["--watch-config", "-f", "-"].as_slice(),
        ["--watch-config", "--config", "bG9nLWxldmVsOiBpbmZvCg=="].as_slice(),
    ] {
        let output = Command::new(binary())
            .args(args)
            .arg("-d")
            .arg(&dir)
            .stdin(Stdio::null())
            .output()
            .expect("the murmur binary must run");
        let said = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(!output.status.success(), "watch mode must be refused for {args:?}: {said}");
        assert!(said.contains("--watch-config"), "the refusal must name the flag: {said}");
    }

    let _ = fs::remove_dir_all(&dir);
}

/// A configuration with a controller, so the API paths can be driven alongside the watcher.
fn config_yaml_with_controller(proxy: u16, control: u16, secret: &str, rules: &str) -> String {
    format!(
        "mixed-port: {proxy}\nmode: rule\nlog-level: info\nexternal-controller: 127.0.0.1:{control}\nsecret: {secret}\nrules:\n{rules}"
    )
}

/// One `PATCH /configs` on the controller, returning the status code.
fn patch_configs(control: u16, secret: &str, body: &str) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", control)).expect("the controller must accept the connection");
    stream.set_read_timeout(Some(DEADLINE)).expect("the read timeout must be settable");
    let request = format!(
        "PATCH /configs HTTP/1.1\r\nHost: 127.0.0.1:{control}\r\nAuthorization: Bearer {secret}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("the request must be written");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("the response must be readable");
    response.split_whitespace().nth(1).expect("a status line").parse().expect("a status code")
}

/// A file that is already running is not applied again when it is saved byte-identically, so a
/// change made over the API is not replaced by an unchanged file.
#[test]
fn an_unchanged_save_does_not_replace_a_runtime_change() {
    let proxy = free_port();
    let control = free_port();
    let socks = free_port();
    let secret = "watch-config-secret";
    let dir = fixture_dir("unchanged");
    let config = dir.join("config.yaml");
    let log_path = dir.join("murmur.log");
    let started = config_yaml_with_controller(proxy, control, secret, DIRECT);
    fs::write(&config, &started).expect("the configuration must be writable");

    let mut child = spawn_watching(&dir, &config, &log_path);
    await_port(proxy, true);

    let body = format!("{{\"socks-port\":{socks}}}");
    assert_eq!(patch_configs(control, secret, &body), 204, "the PATCH must be accepted");
    await_port(socks, true);

    // The same bytes as the file that is already applied: the watcher must report the event and
    // then skip the reload, leaving the PATCH's listener alone.
    replace(&config, &started);
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        TcpStream::connect(("127.0.0.1", socks)).is_ok(),
        "an unchanged save replaced a runtime change made over the API"
    );
    assert!(still_running(&mut child), "the process must not have been restarted");

    child.kill().expect("the child must be killable");
    let _ = child.wait();
    let _ = fs::remove_dir_all(&dir);
}

/// Watch mode is refused before the configuration is read: `-f -` with a stdin writer that stays
/// open must fail rather than wait for end of file.
#[test]
fn watch_mode_with_stdin_is_refused_without_waiting_for_stdin() {
    let dir = fixture_dir("stdin");
    let mut child = Command::new(binary())
        .args(["--watch-config", "-f", "-", "-d"])
        .arg(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the murmur binary must start");

    // The write end stays open for the whole test: end of file is never delivered.
    let stdin = child.stdin.take().expect("the child must have a stdin pipe");
    let deadline = Instant::now() + DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait().expect("the child state must be queryable") {
            break status;
        }
        assert!(Instant::now() < deadline, "murmur waited for stdin instead of refusing watch mode");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(!status.success(), "watch mode with stdin must be refused");

    let mut said = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut said);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut said);
    }
    assert!(said.contains("--watch-config"), "the refusal must name the flag: {said}");

    drop(stdin);
    let _ = fs::remove_dir_all(&dir);
}

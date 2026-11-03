use std::fmt::Write as _;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};

use chrono::{Local, SecondsFormat};
use tokio::sync::mpsc;

use murmur_common::observable::observable::{new_observable, Observable};
use murmur_common::observable::subscriber::Subscription;

use super::level::LogLevel;

/// The channel is buffered and drops on overflow: the senders are synchronous and cannot await a
/// free slot.
const LOG_CHANNEL_CAPACITY: usize = 1024;

/// The effective default level. Debug output sits behind this gate, so `INFO` decides what is
/// printed.
static LEVEL: AtomicI32 = AtomicI32::new(LogLevel::INFO.0);

static SENDER: OnceLock<mpsc::Sender<Event>> = OnceLock::new();

/// the `source`; created by the first `subscribe`, which is where a runtime is guaranteed.
static SOURCE: tokio::sync::Mutex<Option<Arc<Observable<Event>>>> = tokio::sync::Mutex::const_new(None);

#[derive(Clone, Debug)]
pub struct Event {
    pub log_level: LogLevel,
    pub payload: String,
}

impl Event {
    #[must_use]
    pub fn type_(&self) -> String {
        self.log_level.to_string()
    }
}

/// the `Infoln` body, shared with the `infoln!` macro.
pub fn log_line(log_level: LogLevel, payload: String) {
    let event = new_log(log_level, payload);
    print(&event);
    emit(event);
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the exported signature takes the owned payload and every caller already holds one; only a borrowed form is read before the process exits"
)]
pub fn fatal_line(payload: String) {
    write_line("fatal", &payload);
    std::process::exit(1);
}

pub async fn subscribe() -> anyhow::Result<Subscription<Event>> {
    SUBSCRIBERS.fetch_add(1, Ordering::SeqCst);
    let mut source = SOURCE.lock().await;
    if source.is_none() {
        let (sender, receiver) = mpsc::channel(LOG_CHANNEL_CAPACITY);
        let _ = SENDER.set(sender);
        *source = Some(new_observable(receiver));
    }
    let Some(observable) = source.as_ref().cloned() else {
        drop(source);
        release_subscriber();
        return Err(anyhow::anyhow!("log source is not initialized"));
    };
    drop(source);
    match observable.subscribe().await {
        Ok(subscription) => Ok(subscription),
        Err(err) => {
            release_subscriber();
            Err(err)
        }
    }
}

pub async fn un_subscribe(sub: Subscription<Event>) {
    let observable = SOURCE.lock().await.as_ref().cloned();
    if let Some(observable) = observable {
        observable.unsubscribe(sub).await;
    }
    release_subscriber();
}

pub fn level() -> LogLevel {
    LogLevel(LEVEL.load(Ordering::SeqCst))
}

pub fn set_level(new_level: LogLevel) {
    LEVEL.store(new_level.0, Ordering::SeqCst);
}

/// Whether a record at `log_level` is worth building: it passes the stdout gate, or a subscriber
/// may still receive it through `emit`, which the `/logs` route thresholds per request.
#[must_use]
pub fn enabled(log_level: LogLevel) -> bool {
    log_level >= level() || SUBSCRIBERS.load(Ordering::SeqCst) > 0
}

/// The live subscriptions. It may over-count, which only costs formatting work; it must never
/// under-count, since a record that was never built cannot be recovered for a subscriber.
static SUBSCRIBERS: AtomicUsize = AtomicUsize::new(0);

fn release_subscriber() {
    let _ = SUBSCRIBERS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| Some(count.saturating_sub(1)));
}

/// The payload has already been formatted by the caller's macro.
pub(crate) const fn new_log(log_level: LogLevel, payload: String) -> Event {
    Event { log_level, payload }
}

pub(crate) fn print(data: &Event) {
    let stdout = std::io::stdout();
    print_to(data, &mut stdout.lock());
}

/// the `print` against an explicit sink, so the level gate is reachable from tests.
fn print_to<W: Write>(data: &Event, out: &mut W) {
    if data.log_level < level() {
        return;
    }

    match data.log_level {
        LogLevel::INFO => write_line_to(out, "info", &data.payload),
        LogLevel::WARNING => write_line_to(out, "warning", &data.payload),
        LogLevel::ERROR => write_line_to(out, "error", &data.payload),
        LogLevel::DEBUG => write_line_to(out, "debug", &data.payload),
        _ => {}
    }
}

/// Delivers the event to the subscribers; the channel drops on overflow (see `LOG_CHANNEL_CAPACITY`).
fn emit(event: Event) {
    let Some(sender) = SENDER.get() else {
        return;
    };
    let _ = sender.try_send(event);
}

/// The formatter used for all log output.
struct TextFormatter {
    /// Produces RFC 3339 timestamps with nanosecond precision.
    timestamp: fn() -> String,
    /// Whether output is colourised, decided once for the process.
    colored: bool,
}

impl TextFormatter {
    /// Builds the process formatter, taking the colour decision once rather than per record.
    fn new() -> Self {
        Self::with_color_decision(detect_colored())
    }

    /// Builds a formatter with the colour decision given.
    fn with_color_decision(colored: bool) -> Self {
        Self { timestamp: || Local::now().to_rfc3339_opts(SecondsFormat::Nanos, true), colored }
    }

    fn is_colored(&self) -> bool {
        self.colored
    }

    /// Writes one colourised line.
    fn print_colored(&self, out: &mut String, level_name: &str, payload: &str) {
        let level_color = match level_name {
            "debug" | "trace" => 37,
            "warning" => 33,
            "error" | "fatal" | "panic" => 31,
            _ => 36,
        };
        let level_text = level_text(level_name);
        let message = payload.strip_suffix('\n').unwrap_or(payload);
        let timestamp = (self.timestamp)();
        let _ = write!(out, "\x1b[{level_color}m{level_text}\x1b[0m[{timestamp}] {message:<44} ");
    }
}

/// Whether output is colourised: a non-Windows terminal, overridable by `CLICOLOR_FORCE`/`CLICOLOR`.
fn detect_colored() -> bool {
    #[cfg(test)]
    COLOR_DETECTIONS.fetch_add(1, Ordering::SeqCst);
    let mut is_colored = std::io::stdout().is_terminal() && !cfg!(windows);
    match std::env::var("CLICOLOR_FORCE") {
        Ok(force) if force != "0" => is_colored = true,
        Ok(_) => is_colored = false,
        Err(_) => {
            if std::env::var("CLICOLOR").as_deref() == Ok("0") {
                is_colored = false;
            }
        }
    }
    is_colored
}

/// Counts the colour detections, so a test can pin that the decision is taken once per process.
#[cfg(test)]
static COLOR_DETECTIONS: AtomicUsize = AtomicUsize::new(0);

/// The four-character upper-case label for a level name, so a record is not upper-cased into a
/// fresh `String` to be rendered.
fn level_text(level_name: &str) -> &'static str {
    match level_name {
        "debug" => "DEBU",
        "trace" => "TRAC",
        "warning" => "WARN",
        "error" => "ERRO",
        "fatal" => "FATA",
        "panic" => "PANI",
        _ => "INFO",
    }
}

static TEXT_FORMATTER: LazyLock<TextFormatter> = LazyLock::new(TextFormatter::new);

/// Writes one line to stdout.
fn write_line(level_name: &str, payload: &str) {
    let stdout = std::io::stdout();
    write_line_to(&mut stdout.lock(), level_name, payload);
}

fn write_line_to<W: Write>(out: &mut W, level_name: &str, payload: &str) {
    let formatter = &*TEXT_FORMATTER;
    let mut line = String::new();
    if formatter.is_colored() {
        formatter.print_colored(&mut line, level_name, payload);
    } else {
        append_key_value(&mut line, "time", &(formatter.timestamp)());
        append_key_value(&mut line, "level", level_name);
        if !payload.is_empty() {
            append_key_value(&mut line, "msg", payload);
        }
    }
    line.push('\n');

    #[expect(
        clippy::print_stderr,
        reason = "the log sink itself failed to write; routing this through the logger would recurse back into the same failing writer"
    )]
    if let Err(err) = out.write_all(line.as_bytes()) {
        eprintln!("Failed to write to log, {err}");
    }
}

/// Whether a value needs quoting when written.
fn needs_quoting(text: &str) -> bool {
    text.chars().any(|ch| !is_plain_char(ch))
}

/// Characters that never need quoting.
const fn is_plain_char(ch: char) -> bool {
    ch.is_ascii_lowercase()
        || ch.is_ascii_uppercase()
        || ch.is_ascii_digit()
        || matches!(ch, '-' | '.' | '_' | '/' | '@' | '^' | '+')
}

/// Appends `key=value` to the line, quoting the value when needed.
fn append_key_value(out: &mut String, key: &str, value: &str) {
    if !out.is_empty() {
        out.push(' ');
    }
    out.push_str(key);
    out.push('=');
    append_value(out, value);
}

/// Appends the value, quoting it when required.
fn append_value(out: &mut String, value: &str) {
    if needs_quoting(value) {
        let _ = write!(out, "{value:?}");
    } else {
        out.push_str(value);
    }
}

/// the `Infoln`, taking no arguments or a Rust format string.
#[macro_export]
macro_rules! infoln {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::level::LogLevel::INFO) {
            $crate::log::log_line($crate::level::LogLevel::INFO, format!($($arg)*))
        }
    };
}

/// the `Warnln`, taking no arguments or a Rust format string.
#[macro_export]
macro_rules! warnln {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::level::LogLevel::WARNING) {
            $crate::log::log_line($crate::level::LogLevel::WARNING, format!($($arg)*))
        }
    };
}

/// The error logger, taking no arguments or a Rust format string.
#[macro_export]
macro_rules! errorln {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::level::LogLevel::ERROR) {
            $crate::log::log_line($crate::level::LogLevel::ERROR, format!($($arg)*))
        }
    };
}

/// the `Debugln`, taking no arguments or a Rust format string.
#[macro_export]
macro_rules! debugln {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::level::LogLevel::DEBUG) {
            $crate::log::log_line($crate::level::LogLevel::DEBUG, format!($($arg)*))
        }
    };
}

/// Writes the entry and exits with status 1.
#[macro_export]
macro_rules! fatalln {
    ($($arg:tt)*) => {
        $crate::log::fatal_line(format!($($arg)*))
    };
}

pub use crate::{debugln, errorln, fatalln, infoln, warnln};

#[cfg(test)]
mod tests {
    use super::*;

    /// The default level hides debug lines; `SetLevel` is the config path that exposes them.
    #[test]
    fn default_level_hides_debug_lines_until_set_level() {
        assert_eq!(level(), LogLevel::INFO);

        let mut info_out = Vec::new();
        print_to(&new_log(LogLevel::DEBUG, "hidden".to_owned()), &mut info_out);
        assert!(info_out.is_empty(), "debug line printed at the default level: {}", String::from_utf8_lossy(&info_out));
        print_to(&new_log(LogLevel::INFO, "visible".to_owned()), &mut info_out);
        let info_text = String::from_utf8_lossy(&info_out);
        assert!(info_text.contains("visible"), "info line missing: {info_text}");

        set_level(LogLevel::DEBUG);
        let mut debug_out = Vec::new();
        print_to(&new_log(LogLevel::DEBUG, "debug line".to_owned()), &mut debug_out);
        set_level(LogLevel::INFO);
        let debug_text = String::from_utf8_lossy(&debug_out);
        assert!(debug_text.contains("debug line"), "debug line missing: {debug_text}");
    }

    /// Forcing the `LazyLock` first makes the count final: `detect_colored` runs from
    /// `TextFormatter::new` alone, which the lock calls once per process.
    #[test]
    fn the_colour_decision_is_taken_once_for_the_process_formatter() {
        LazyLock::force(&TEXT_FORMATTER);
        let before = COLOR_DETECTIONS.load(Ordering::SeqCst);

        let mut first = Vec::new();
        write_line_to(&mut first, "info", "first");
        let mut second = Vec::new();
        write_line_to(&mut second, "info", "second");

        assert_eq!(
            COLOR_DETECTIONS.load(Ordering::SeqCst),
            before,
            "a rendered record must not re-detect colour support"
        );
        assert!(!first.is_empty() && !second.is_empty(), "both records must be rendered");
    }

    #[test]
    fn a_formatter_renders_the_colour_decision_it_was_built_with() {
        let mut line = String::new();
        TextFormatter::with_color_decision(true).print_colored(&mut line, "warning", "x");
        assert!(line.contains("\x1b[33mWARN\x1b[0m"), "the coloured line lost its label: {line:?}");

        assert!(TextFormatter::with_color_decision(true).is_colored());
        assert!(
            !TextFormatter::with_color_decision(false).is_colored(),
            "the stored decision must not be re-derived from the environment"
        );
    }

    #[test]
    fn a_level_name_maps_to_its_four_character_label() {
        assert_eq!(level_text("info"), "INFO");
        assert_eq!(level_text("warning"), "WARN");
        assert_eq!(level_text("error"), "ERRO");
        assert_eq!(level_text("debug"), "DEBU");
        assert_eq!(level_text("fatal"), "FATA");
        assert_eq!(level_text("panic"), "PANI");
        assert_eq!(level_text("trace"), "TRAC");
    }
}

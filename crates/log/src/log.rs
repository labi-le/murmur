use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Once};

use chrono::{Local, SecondsFormat};
use parking_lot::{Mutex, RwLock};
use portable_atomic::AtomicU64;
use tokio::sync::mpsc;
use tracing::field::{Field as TracingField, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Level, Metadata, Subscriber};

use murmur_common::observable::observable::{new_observable, Observable};
use murmur_common::observable::subscriber::Subscription;

use super::level::LogLevel;

/// The channel is buffered and drops on overflow: the senders are synchronous and cannot await a
/// free slot.
const LOG_CHANNEL_CAPACITY: usize = 1024;

/// The effective default level. Debug output sits behind this gate, so `INFO` decides what is
/// printed.
static LEVEL: AtomicI32 = AtomicI32::new(LogLevel::INFO.0);

static SENDER: Mutex<Option<mpsc::Sender<Event>>> = Mutex::new(None);

/// the `source`; created by the first `subscribe`, which is where a runtime is guaranteed.
static SOURCE: tokio::sync::Mutex<Option<(Arc<Observable<Event>>, tokio::task::JoinHandle<()>)>> =
    tokio::sync::Mutex::const_new(None);

static INIT: Once = Once::new();
static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);
static SPANS: LazyLock<RwLock<HashMap<u64, SpanState>>> = LazyLock::new(|| RwLock::new(HashMap::new()));

thread_local! {
    static SPAN_STACK: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    static IN_LOGGER: Cell<bool> = const { Cell::new(false) };
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Field {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub log_level: LogLevel,
    pub payload: String,
    pub fields: Vec<Field>,
}

impl Event {
    #[must_use]
    pub fn type_(&self) -> String {
        self.log_level.to_string()
    }
}

pub fn init() {
    INIT.call_once(|| {
        static LOGGER: MurmurLogBridge = MurmurLogBridge;
        let _ = tracing::subscriber::set_global_default(MurmurSubscriber);
        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(log::LevelFilter::Trace);
        }
    });
}

pub fn log_line(log_level: LogLevel, payload: String) {
    init();
    let event = new_log_with_fields(log_level, payload, active_span_fields());
    print(&event);
    emit(event);
}

pub fn log_line_with_meta(log_level: LogLevel, payload: String, target: &'static str, source: &'static str) {
    init();
    let mut fields = active_span_fields();
    upsert_field(&mut fields, "target", target.to_owned());
    upsert_field(&mut fields, "source", source.to_owned());
    let event = new_log_with_fields(log_level, payload, fields);
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
    init();
    SUBSCRIBERS.fetch_add(1, Ordering::SeqCst);
    let mut source = SOURCE.lock().await;
    let needs_init = match source.as_ref() {
        None => true,
        Some((_, watcher)) => watcher.is_finished(),
    };
    if needs_init {
        let (sender, receiver) = mpsc::channel(LOG_CHANNEL_CAPACITY);
        *SENDER.lock() = Some(sender);
        let observable = new_observable(receiver);
        let watcher = tokio::spawn(std::future::pending::<()>());
        *source = Some((observable, watcher));
    }
    let Some(observable) = source.as_ref().map(|(obs, _)| Arc::clone(obs)) else {
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
    let observable = SOURCE.lock().await.as_ref().map(|(obs, _)| Arc::clone(obs));
    if let Some(observable) = observable {
        observable.unsubscribe(sub).await;
    }
    release_subscriber();
}

pub fn level() -> LogLevel {
    LogLevel(LEVEL.load(Ordering::SeqCst))
}

pub fn set_level(new_level: LogLevel) {
    init();
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

#[cfg(test)]
const fn new_log(log_level: LogLevel, payload: String) -> Event {
    Event { log_level, payload, fields: Vec::new() }
}

const fn new_log_with_fields(log_level: LogLevel, payload: String, fields: Vec<Field>) -> Event {
    Event { log_level, payload, fields }
}

fn upsert_field(fields: &mut Vec<Field>, key: &str, value: String) {
    if let Some(existing) = fields.iter_mut().find(|field| field.key == key) {
        existing.value = value;
    } else {
        fields.push(Field { key: key.to_owned(), value });
    }
}

struct SpanState {
    parent: Option<u64>,
    fields: Vec<Field>,
    ref_count: usize,
}

#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    fields: Vec<Field>,
}

impl FieldVisitor {
    fn record_pair(&mut self, field: &TracingField, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            upsert_field(&mut self.fields, field.name(), value);
        }
    }
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &TracingField, value: &str) {
        self.record_pair(field, value.to_owned());
    }

    fn record_i64(&mut self, field: &TracingField, value: i64) {
        self.record_pair(field, value.to_string());
    }

    fn record_u64(&mut self, field: &TracingField, value: u64) {
        self.record_pair(field, value.to_string());
    }

    fn record_i128(&mut self, field: &TracingField, value: i128) {
        self.record_pair(field, value.to_string());
    }

    fn record_u128(&mut self, field: &TracingField, value: u128) {
        self.record_pair(field, value.to_string());
    }

    fn record_bool(&mut self, field: &TracingField, value: bool) {
        self.record_pair(field, value.to_string());
    }

    fn record_f64(&mut self, field: &TracingField, value: f64) {
        self.record_pair(field, value.to_string());
    }

    fn record_error(&mut self, field: &TracingField, value: &(dyn std::error::Error + 'static)) {
        self.record_pair(field, value.to_string());
    }

    fn record_debug(&mut self, field: &TracingField, value: &dyn fmt::Debug) {
        self.record_pair(field, format!("{value:?}"));
    }
}

const fn map_tracing_level(level: Level) -> LogLevel {
    match level {
        Level::ERROR => LogLevel::ERROR,
        Level::WARN => LogLevel::WARNING,
        Level::INFO => LogLevel::INFO,
        Level::DEBUG | Level::TRACE => LogLevel::DEBUG,
    }
}

const fn map_log_level(level: log::Level) -> LogLevel {
    match level {
        log::Level::Error => LogLevel::ERROR,
        log::Level::Warn => LogLevel::WARNING,
        log::Level::Info => LogLevel::INFO,
        log::Level::Debug | log::Level::Trace => LogLevel::DEBUG,
    }
}

fn current_thread_span() -> Option<u64> {
    SPAN_STACK.with(|stack| stack.borrow().last().copied())
}

fn span_fields_for(leaf: Option<u64>) -> Vec<Field> {
    let Some(mut cur) = leaf else {
        return Vec::new();
    };
    let spans = SPANS.read();
    let mut chain = Vec::new();
    let mut depth = 0usize;
    while depth < 64 {
        let Some(state) = spans.get(&cur) else {
            break;
        };
        chain.push(cur);
        let Some(parent) = state.parent else {
            break;
        };
        cur = parent;
        depth += 1;
    }
    let mut out = Vec::new();
    for span_id in chain.into_iter().rev() {
        if let Some(state) = spans.get(&span_id) {
            for field in &state.fields {
                upsert_field(&mut out, &field.key, field.value.clone());
            }
        }
    }
    out
}

fn active_span_fields() -> Vec<Field> {
    span_fields_for(current_thread_span())
}

struct MurmurSubscriber;

impl Subscriber for MurmurSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        if metadata.is_span() {
            return true;
        }
        enabled(map_tracing_level(*metadata.level()))
    }

    fn new_span(&self, span: &Attributes<'_>) -> Id {
        let id = NEXT_SPAN_ID.fetch_add(1, Ordering::Relaxed);
        let parent = if span.is_root() {
            None
        } else if let Some(explicit) = span.parent() {
            Some(explicit.into_u64())
        } else {
            current_thread_span()
        };
        let mut visitor = FieldVisitor::default();
        span.record(&mut visitor);
        SPANS.write().insert(id, SpanState { parent, fields: visitor.fields, ref_count: 1 });
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut visitor = FieldVisitor::default();
        values.record(&mut visitor);
        if visitor.fields.is_empty() {
            return;
        }
        if let Some(state) = SPANS.write().get_mut(&span.into_u64()) {
            for field in visitor.fields {
                upsert_field(&mut state.fields, &field.key, field.value);
            }
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let log_level = map_tracing_level(*event.metadata().level());
        if !enabled(log_level) {
            return;
        }
        let parent = if event.is_root() {
            None
        } else if let Some(explicit) = event.parent() {
            Some(explicit.into_u64())
        } else {
            current_thread_span()
        };
        let mut fields = span_fields_for(parent);
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        for field in visitor.fields {
            upsert_field(&mut fields, &field.key, field.value);
        }
        let meta = event.metadata();
        upsert_field(&mut fields, "target", meta.target().to_owned());
        if let (Some(file), Some(line)) = (meta.file(), meta.line()) {
            upsert_field(&mut fields, "source", format!("{file}:{line}"));
        }
        let record = new_log_with_fields(log_level, visitor.message.unwrap_or_default(), fields);
        print(&record);
        emit(record);
    }

    fn enter(&self, span: &Id) {
        SPAN_STACK.with(|stack| stack.borrow_mut().push(span.into_u64()));
    }

    fn exit(&self, span: &Id) {
        let target = span.into_u64();
        SPAN_STACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            if let Some(pos) = stack.iter().rposition(|&id| id == target) {
                stack.remove(pos);
            }
        });
    }

    fn clone_span(&self, id: &Id) -> Id {
        if let Some(state) = SPANS.write().get_mut(&id.into_u64()) {
            state.ref_count = state.ref_count.saturating_add(1);
        }
        id.clone()
    }

    fn try_close(&self, id: Id) -> bool {
        let raw = id.into_u64();
        let mut spans = SPANS.write();
        let remove = spans.get_mut(&raw).is_some_and(|state| {
            state.ref_count = state.ref_count.saturating_sub(1);
            state.ref_count == 0
        });
        if remove {
            spans.remove(&raw);
        }
        remove
    }
}

struct MurmurLogBridge;

impl log::Log for MurmurLogBridge {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        let log_level = map_log_level(metadata.level());
        if !metadata.target().starts_with("murmur") && log_level < level() {
            return false;
        }
        enabled(log_level)
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let already_in = IN_LOGGER.with(|flag| {
            if flag.get() {
                true
            } else {
                flag.set(true);
                false
            }
        });
        if already_in {
            return;
        }
        let log_level = map_log_level(record.level());
        let mut fields = active_span_fields();
        upsert_field(&mut fields, "target", record.target().to_owned());
        if let (Some(file), Some(line)) = (record.file(), record.line()) {
            upsert_field(&mut fields, "source", format!("{file}:{line}"));
        }
        let event = new_log_with_fields(log_level, record.args().to_string(), fields);
        print(&event);
        emit(event);
        IN_LOGGER.with(|flag| flag.set(false));
    }

    fn flush(&self) {}
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
    let sender = SENDER.lock().as_ref().cloned();
    if let Some(sender) = sender {
        let _ = sender.try_send(event);
    }
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
            $crate::log::log_line_with_meta(
                $crate::level::LogLevel::INFO,
                format!($($arg)*),
                module_path!(),
                concat!(file!(), ":", line!()),
            )
        }
    };
}

#[macro_export]
macro_rules! warnln {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::level::LogLevel::WARNING) {
            $crate::log::log_line_with_meta(
                $crate::level::LogLevel::WARNING,
                format!($($arg)*),
                module_path!(),
                concat!(file!(), ":", line!()),
            )
        }
    };
}

#[macro_export]
macro_rules! errorln {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::level::LogLevel::ERROR) {
            $crate::log::log_line_with_meta(
                $crate::level::LogLevel::ERROR,
                format!($($arg)*),
                module_path!(),
                concat!(file!(), ":", line!()),
            )
        }
    };
}

#[macro_export]
macro_rules! debugln {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::level::LogLevel::DEBUG) {
            $crate::log::log_line_with_meta(
                $crate::level::LogLevel::DEBUG,
                format!($($arg)*),
                module_path!(),
                concat!(file!(), ":", line!()),
            )
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

    fn field_value<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
        event.fields.iter().find(|field| field.key == key).map(|field| field.value.as_str())
    }

    #[tokio::test]
    async fn tracing_spans_and_instrumented_futures_attach_fields_to_events() {
        use tracing::Instrument as _;

        init();
        let sub = subscribe().await.expect("log subscription");

        let unique = "span-in-scope-test-payload";
        tracing::info_span!("flow", conn_id = "abc", rule = "DIRECT").in_scope(|| {
            infoln!("{unique}");
        });

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while let Some(ev) = sub.recv().await {
                if ev.payload == unique {
                    return ev;
                }
            }
            panic!("subscription closed before event arrived");
        })
        .await
        .expect("timed out waiting for in_scope event");

        assert_eq!(field_value(&event, "conn_id"), Some("abc"));
        assert_eq!(field_value(&event, "rule"), Some("DIRECT"));
        assert!(field_value(&event, "target").is_some_and(|t| t.contains("murmur_log")));
        assert!(field_value(&event, "source").is_some_and(|s| s.contains("log.rs")));

        let async_unique = "span-instrument-await-test-payload";
        let async_span = tracing::info_span!("async_flow", conn_id = "xyz", outbound = tracing::field::Empty);
        let record_span = async_span.clone();
        async move {
            tokio::task::yield_now().await;
            record_span.record("outbound", "proxy-a");
            infoln!("{async_unique}");
        }
        .instrument(async_span)
        .await;

        let async_event = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while let Some(ev) = sub.recv().await {
                if ev.payload == async_unique {
                    return ev;
                }
            }
            panic!("subscription closed before async event arrived");
        })
        .await
        .expect("timed out waiting for instrumented async event");

        assert_eq!(field_value(&async_event, "conn_id"), Some("xyz"));
        assert_eq!(field_value(&async_event, "outbound"), Some("proxy-a"));

        let direct_unique = "direct-tracing-event-payload";
        tracing::info!(peer = "192.0.2.1:443", "{direct_unique}");

        let direct_event = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while let Some(ev) = sub.recv().await {
                if ev.payload == direct_unique {
                    return ev;
                }
            }
            panic!("subscription closed before direct tracing event arrived");
        })
        .await
        .expect("timed out waiting for direct tracing event");

        assert_eq!(direct_event.payload, direct_unique);
        assert_eq!(field_value(&direct_event, "peer"), Some("192.0.2.1:443"));

        un_subscribe(sub).await;
    }
}

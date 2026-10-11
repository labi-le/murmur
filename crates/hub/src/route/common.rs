//! A websocket upgrade writes the HTTP/1.1 101 response by hand and then continues on the raw
//! stream.
//!
//! This crate's HTTP server is `hyper`, whose supported upgrade path is
//! `hyper::upgrade::on`: the caller returns an ordinary `Response` carrying the 101 status and
//! upgrade headers, and receives the raw duplex stream from the upgrade future once that response
//! has been flushed. [`ws_upgrade`] therefore returns `Result<Response, Response>` (`Ok` is the 101
//! response to hand back to hyper, `Err` is an already-built error response) instead of a raw
//! connection plus its buffered reader/writer; every caller pairs it with [`stream_response`],
//! which performs the `hyper::upgrade::on` continuation in a spawned task and drives the loop body
//! against a [`StreamSink`] that abstracts over the websocket and plain-HTTP-chunked-stream
//! duality.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::{header, Method, Request, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use murmur_adapter_outboundgroup::util::{self, ProxyGroup, SelectAble};
use murmur_common::utils::path_unescape::path_unescape;
use murmur_common_net::get_websocket_sec_accept;
use murmur_constant::adapters::ProxyAdapter;
use murmur_constant::provider::interface::{ProxyProvider, RuleProvider};

/// Finds a concrete provider's serializer through the trait object; see
/// [`ProxyProvider`]/[`RuleProvider`]'s module doc in `constant/provider/interface.rs`.
pub(crate) fn proxy_provider_marshal_json(provider: &dyn ProxyProvider) -> anyhow::Result<Vec<u8>> {
    provider.marshal_json()
}

/// See [`proxy_provider_marshal_json`].
pub(crate) fn rule_provider_marshal_json(provider: &dyn RuleProvider) -> anyhow::Result<Vec<u8>> {
    provider.marshal_json()
}

/// The JSON response for a value whose JSON form comes from a serializer-style byte-producing
/// method (`constant::adapters::ProxyAdapter::marshal_json`,
/// [`proxy_provider_marshal_json`]/[`rule_provider_marshal_json`]) instead of `serde::Serialize`.
pub(crate) fn marshal_json_response(status: StatusCode, result: anyhow::Result<Vec<u8>>) -> Response<RespBody> {
    match result {
        Ok(bytes) => {
            response_with(status, &[(header::CONTENT_TYPE, "application/json")], full_body(encode_preset_json(&bytes)))
        }
        Err(err) => json_response(StatusCode::INTERNAL_SERVER_ERROR, &super::errors::HttpError::new(err.to_string())),
    }
}

/// Renders a proxy adapter as a JSON response.
pub(crate) fn proxy_json_response(status: StatusCode, proxy: &dyn ProxyAdapter) -> Response<RespBody> {
    marshal_json_response(status, proxy.marshal_json())
}

pub(crate) fn as_proxy_group(adapter: &dyn ProxyAdapter) -> Option<&dyn ProxyGroup> {
    util::as_proxy_group(adapter)
}

pub(crate) fn as_select_able(adapter: &dyn ProxyAdapter) -> Option<&dyn SelectAble> {
    util::as_select_able(adapter)
}

/// The boxed response body type shared by every route handler.
pub(crate) type RespBody = BoxBody<Bytes, Infallible>;
pub(crate) type Req = Request<Incoming>;

pub(crate) fn full_body(bytes: impl Into<Bytes>) -> RespBody {
    Full::new(bytes.into()).map_err(|never: Infallible| match never {}).boxed()
}

pub(crate) fn empty_body() -> RespBody {
    Empty::new().map_err(|never: Infallible| match never {}).boxed()
}

/// Assembles a response without `Response::builder()`: the builder is fallible only for a status
/// code or header value it does not accept, and every value passed here is a compile-time
/// constant.
pub(crate) fn response_with(
    status: StatusCode,
    headers: &[(header::HeaderName, &'static str)],
    body: RespBody,
) -> Response<RespBody> {
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    let map = resp.headers_mut();
    for (name, value) in headers {
        map.append(name.clone(), header::HeaderValue::from_static(value));
    }
    resp
}

/// Finishes a `Response::builder()` chain whose header values are computed at runtime. A value
/// this crate builds itself is always accepted, so the builder's error is unreachable; it answers
/// a 500 rather than panicking inside the connection task.
pub(crate) fn finish_response(builder: hyper::http::response::Builder, body: RespBody) -> Response<RespBody> {
    builder.body(body).unwrap_or_else(|_| status_only(StatusCode::INTERNAL_SERVER_ERROR))
}

/// Decodes only the first JSON value from the request body stream (trailing bytes are not an
/// error), then drains whatever is left on every return path, decode failure included, without
/// buffering it. Frames arrive over `body.frame().await`, never a blocking-pool thread, so a
/// stalled client cannot pin one.
///
/// [`ValueBoundaryScanner`] tells this function when the buffer holds a complete first value or
/// is definitely invalid, so it attempts a parse exactly once instead of retrying on
/// `serde_json`'s EOF classification: `serde_json`'s ignored-field number path and its map-key
/// path both report a non-EOF syntax error when a partial buffer ends inside them
/// (`InvalidNumber`, `ExpectedNumericKey`, `ExpectedDoubleQuote`), which would otherwise reject a
/// body that becomes valid once the rest arrives.
///
/// A body frame that errors (not a clean end of stream) always fails the decode: only a clean end
/// of stream can complete a value that is still pending; any other read error is returned as-is
/// regardless of scan state.
pub(crate) async fn decode_json_body<T, B>(mut body: B) -> Result<T, ()>
where
    T: serde::de::DeserializeOwned,
    B: Body<Data = Bytes> + Unpin,
{
    let mut buf = bytes::BytesMut::new();
    let mut scanner = ValueBoundaryScanner::new();
    let result = loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    buf.extend_from_slice(&data);
                }
            }
            Some(Err(_)) => break Err(()),
            None => break parse_json_value(&buf),
        }
        match scanner.advance(&buf) {
            ScanOutcome::Complete => {
                let Some(value) = buf.get(..scanner.boundary) else { break Err(()) };
                break parse_json_value(value);
            }
            ScanOutcome::Invalid => break Err(()),
            ScanOutcome::Incomplete => {}
        }
    };
    while let Some(Ok(_)) = body.frame().await {}
    result
}

fn parse_json_value<T: serde::de::DeserializeOwned>(buf: &[u8]) -> Result<T, ()> {
    let mut de = serde_json::Deserializer::from_slice(buf);
    T::deserialize(&mut de).map_err(|_| ())
}

/// The nesting limit the scanner enforces on `{`/`[`.
const MAX_JSON_NESTING_DEPTH: usize = 10_000;

/// A container level the scanner is inside.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ParseState {
    ObjectKey,
    ObjectValue,
    ArrayValue,
}

/// The scanner's current state; each variant is one step of its state machine.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanStep {
    BeginValue,
    BeginValueOrEmpty,
    BeginStringOrEmpty,
    BeginString,
    EndValue,
    InString,
    InStringEsc,
    InStringEscU,
    InStringEscU1,
    InStringEscU12,
    InStringEscU123,
    Neg,
    Num1,
    Num0,
    Dot,
    Dot0,
    Exp,
    ExpSign,
    Exp0,
    T,
    Tr,
    Tru,
    F,
    Fa,
    Fal,
    Fals,
    N,
    Nu,
    Nul,
}

enum StepResult {
    Continue,
    /// The current byte completed the value. `include_byte` is false when the byte that
    /// revealed completion is not itself part of the value (a bare top-level scalar's
    /// lookahead byte, or the trailing byte after a bare top-level string/literal closes),
    /// which the caller must exclude from the value's byte range.
    /// True when the byte itself closes the value (an object/array's own `}`/`]`).
    Complete {
        include_byte: bool,
    },
    Invalid,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanOutcome {
    Incomplete,
    Complete,
    Invalid,
}

/// Finds the end of the first JSON value in an incrementally growing buffer without buffering it
/// twice or rescanning bytes already seen (`pos` resumes each call). It rejects a syntactically
/// invalid body -- an unterminated string escape, a bad `true`/`false`/`null` spelling, a
/// malformed number, a value where a container expected a comma or closing bracket -- at the
/// offending byte, instead of buffering the rest of an unbounded invalid body waiting for
/// brackets to balance.
struct ValueBoundaryScanner {
    pos: usize,
    state: ScanStep,
    stack: Vec<ParseState>,
    complete: bool,
    invalid: bool,
    /// Set once `advance` returns `ScanOutcome::Complete`: the exclusive end offset of the
    /// value within the buffer passed to `advance`. Bytes at or past this offset were never
    /// part of the value (trailing garbage, or -- for a bare scalar -- the lookahead byte that
    /// merely confirmed the value had ended) and must not be handed to the parser.
    boundary: usize,
}

impl ValueBoundaryScanner {
    fn new() -> Self {
        Self { pos: 0, state: ScanStep::BeginValue, stack: Vec::new(), complete: false, invalid: false, boundary: 0 }
    }

    fn is_space(c: u8) -> bool {
        matches!(c, b' ' | b'\t' | b'\r' | b'\n')
    }

    /// Pushes a container level, failing once `MAX_JSON_NESTING_DEPTH`
    /// is exceeded.
    fn push(&mut self, ps: ParseState) -> bool {
        self.stack.push(ps);
        self.stack.len() <= MAX_JSON_NESTING_DEPTH
    }

    fn begin_value(&mut self, c: u8) -> StepResult {
        if Self::is_space(c) {
            return StepResult::Continue;
        }
        match c {
            b'{' => {
                self.state = ScanStep::BeginStringOrEmpty;
                if self.push(ParseState::ObjectKey) {
                    StepResult::Continue
                } else {
                    StepResult::Invalid
                }
            }
            b'[' => {
                self.state = ScanStep::BeginValueOrEmpty;
                if self.push(ParseState::ArrayValue) {
                    StepResult::Continue
                } else {
                    StepResult::Invalid
                }
            }
            b'"' => {
                self.state = ScanStep::InString;
                StepResult::Continue
            }
            b'-' => {
                self.state = ScanStep::Neg;
                StepResult::Continue
            }
            b'0' => {
                self.state = ScanStep::Num0;
                StepResult::Continue
            }
            b't' => {
                self.state = ScanStep::T;
                StepResult::Continue
            }
            b'f' => {
                self.state = ScanStep::F;
                StepResult::Continue
            }
            b'n' => {
                self.state = ScanStep::N;
                StepResult::Continue
            }
            b'1'..=b'9' => {
                self.state = ScanStep::Num1;
                StepResult::Continue
            }
            _ => StepResult::Invalid,
        }
    }

    fn begin_string(&mut self, c: u8) -> StepResult {
        if Self::is_space(c) {
            return StepResult::Continue;
        }
        if c == b'"' {
            self.state = ScanStep::InString;
            StepResult::Continue
        } else {
            StepResult::Invalid
        }
    }

    /// The state after completing a value inside a container: awaiting `:` after an object key,
    /// `,`/`}` after an object value, `,`/`]` after an array element. Once the container stack is
    /// empty, the state after completing the top-level value, which completes unconditionally on
    /// whatever byte follows (a non-space trailing byte is an error but the value is still
    /// complete).
    fn end_value(&mut self, c: u8) -> StepResult {
        let Some(top) = self.stack.last().copied() else {
            return StepResult::Complete { include_byte: false };
        };
        if Self::is_space(c) {
            self.state = ScanStep::EndValue;
            return StepResult::Continue;
        }
        match top {
            ParseState::ObjectKey => {
                if c == b':' {
                    let Some(top) = self.stack.last_mut() else { return StepResult::Invalid };
                    *top = ParseState::ObjectValue;
                    self.state = ScanStep::BeginValue;
                    StepResult::Continue
                } else {
                    StepResult::Invalid
                }
            }
            ParseState::ObjectValue => {
                if c == b',' {
                    let Some(top) = self.stack.last_mut() else { return StepResult::Invalid };
                    *top = ParseState::ObjectKey;
                    self.state = ScanStep::BeginString;
                    StepResult::Continue
                } else if c == b'}' {
                    self.stack.pop();
                    if self.stack.is_empty() {
                        StepResult::Complete { include_byte: true }
                    } else {
                        self.state = ScanStep::EndValue;
                        StepResult::Continue
                    }
                } else {
                    StepResult::Invalid
                }
            }
            ParseState::ArrayValue => {
                if c == b',' {
                    self.state = ScanStep::BeginValue;
                    StepResult::Continue
                } else if c == b']' {
                    self.stack.pop();
                    if self.stack.is_empty() {
                        StepResult::Complete { include_byte: true }
                    } else {
                        self.state = ScanStep::EndValue;
                        StepResult::Continue
                    }
                } else {
                    StepResult::Invalid
                }
            }
        }
    }

    /// `state0`/state1`'s fallback: past the integer part of a number, `.` or `e`/`E` extend
    /// it, anything else ends it.
    fn number_tail(&mut self, c: u8) -> StepResult {
        if c == b'.' {
            self.state = ScanStep::Dot;
            StepResult::Continue
        } else if c == b'e' || c == b'E' {
            self.state = ScanStep::Exp;
            StepResult::Continue
        } else {
            self.end_value(c)
        }
    }

    fn exp_sign(&mut self, c: u8) -> StepResult {
        if c.is_ascii_digit() {
            self.state = ScanStep::Exp0;
            StepResult::Continue
        } else {
            StepResult::Invalid
        }
    }

    fn step(&mut self, c: u8) -> StepResult {
        match self.state {
            ScanStep::BeginValue => self.begin_value(c),
            ScanStep::BeginValueOrEmpty => self.begin_value_or_empty(c),
            ScanStep::BeginStringOrEmpty => self.begin_string_or_empty(c),
            ScanStep::BeginString => self.begin_string(c),
            ScanStep::EndValue => self.end_value(c),
            ScanStep::InString => self.in_string_step(c),
            ScanStep::InStringEsc => self.in_string_esc_step(c),
            ScanStep::InStringEscU => self.hex_escape_step(c, ScanStep::InStringEscU1),
            ScanStep::InStringEscU1 => self.hex_escape_step(c, ScanStep::InStringEscU12),
            ScanStep::InStringEscU12 => self.hex_escape_step(c, ScanStep::InStringEscU123),
            ScanStep::InStringEscU123 => self.hex_escape_step(c, ScanStep::InString),
            ScanStep::Neg => self.neg_step(c),
            ScanStep::Num1 => {
                if c.is_ascii_digit() {
                    StepResult::Continue
                } else {
                    self.number_tail(c)
                }
            }
            ScanStep::Num0 => self.number_tail(c),
            ScanStep::Dot => {
                if c.is_ascii_digit() {
                    self.enter(ScanStep::Dot0)
                } else {
                    StepResult::Invalid
                }
            }
            ScanStep::Dot0 => self.dot_tail(c),
            ScanStep::Exp => {
                if c == b'+' || c == b'-' {
                    self.enter(ScanStep::ExpSign)
                } else {
                    self.exp_sign(c)
                }
            }
            ScanStep::ExpSign => self.exp_sign(c),
            ScanStep::Exp0 => {
                if c.is_ascii_digit() {
                    StepResult::Continue
                } else {
                    self.end_value(c)
                }
            }
            ScanStep::T => self.literal_step(c, b'r', ScanStep::Tr),
            ScanStep::Tr => self.literal_step(c, b'u', ScanStep::Tru),
            ScanStep::Tru | ScanStep::Fals => self.literal_step(c, b'e', ScanStep::EndValue),
            ScanStep::F => self.literal_step(c, b'a', ScanStep::Fa),
            ScanStep::Fa => self.literal_step(c, b'l', ScanStep::Fal),
            ScanStep::Fal => self.literal_step(c, b's', ScanStep::Fals),
            ScanStep::N => self.literal_step(c, b'u', ScanStep::Nu),
            ScanStep::Nu => self.literal_step(c, b'l', ScanStep::Nul),
            ScanStep::Nul => self.literal_step(c, b'l', ScanStep::EndValue),
        }
    }

    fn enter(&mut self, next: ScanStep) -> StepResult {
        self.state = next;
        StepResult::Continue
    }

    /// An empty array (`]`) ends the container, anything else starts an
    /// element.
    fn begin_value_or_empty(&mut self, c: u8) -> StepResult {
        if Self::is_space(c) {
            StepResult::Continue
        } else if c == b']' {
            self.end_value(c)
        } else {
            self.begin_value(c)
        }
    }

    /// An empty object (`}`) ends the container, anything else starts a
    /// key.
    fn begin_string_or_empty(&mut self, c: u8) -> StepResult {
        if Self::is_space(c) {
            return StepResult::Continue;
        }
        if c != b'}' {
            return self.begin_string(c);
        }
        let Some(top) = self.stack.last_mut() else { return StepResult::Invalid };
        *top = ParseState::ObjectValue;
        self.end_value(c)
    }

    /// A closing quote completes the string, a backslash starts an escape, and a
    /// raw control byte is invalid.
    fn in_string_step(&mut self, c: u8) -> StepResult {
        if c == b'"' {
            self.enter(ScanStep::EndValue)
        } else if c == b'\\' {
            self.enter(ScanStep::InStringEsc)
        } else if c < 0x20 {
            StepResult::Invalid
        } else {
            StepResult::Continue
        }
    }

    /// The single-character escapes return to the string, `\u` starts the
    /// four hex digits.
    fn in_string_esc_step(&mut self, c: u8) -> StepResult {
        match c {
            b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"' => self.enter(ScanStep::InString),
            b'u' => self.enter(ScanStep::InStringEscU),
            _ => StepResult::Invalid,
        }
    }

    /// One of the four `\uXXXX` digit states.
    fn hex_escape_step(&mut self, c: u8, next: ScanStep) -> StepResult {
        if c.is_ascii_hexdigit() {
            self.enter(next)
        } else {
            StepResult::Invalid
        }
    }

    /// The sign is followed by a digit, `0` taking the leading-zero state.
    fn neg_step(&mut self, c: u8) -> StepResult {
        if c == b'0' {
            self.enter(ScanStep::Num0)
        } else if c.is_ascii_digit() {
            self.enter(ScanStep::Num1)
        } else {
            StepResult::Invalid
        }
    }

    /// A further digit extends the fraction, `e`/`E` starts the exponent, anything
    /// else ends the number.
    fn dot_tail(&mut self, c: u8) -> StepResult {
        if c.is_ascii_digit() {
            StepResult::Continue
        } else if c == b'e' || c == b'E' {
            self.enter(ScanStep::Exp)
        } else {
            self.end_value(c)
        }
    }

    /// Shared body of the literal states: each expects
    /// exactly one fixed next byte and advances to a fixed next state.
    fn literal_step(&mut self, c: u8, want: u8, next: ScanStep) -> StepResult {
        if c == want {
            self.state = next;
            StepResult::Continue
        } else {
            StepResult::Invalid
        }
    }

    /// Consumes buffered bytes from where the previous call left off. Returns `Complete` or
    /// `Invalid` the instant either is known, without scanning bytes past that point; `Incomplete`
    /// once every buffered byte has been consumed with the value still open.
    fn advance(&mut self, buf: &[u8]) -> ScanOutcome {
        if self.complete {
            return ScanOutcome::Complete;
        }
        if self.invalid {
            return ScanOutcome::Invalid;
        }
        while let Some(&c) = buf.get(self.pos) {
            self.pos += 1;
            match self.step(c) {
                StepResult::Continue => {}
                StepResult::Complete { include_byte } => {
                    self.complete = true;
                    self.boundary = if include_byte { self.pos } else { self.pos - 1 };
                    return ScanOutcome::Complete;
                }
                StepResult::Invalid => {
                    self.invalid = true;
                    return ScanOutcome::Invalid;
                }
            }
        }
        ScanOutcome::Incomplete
    }
}

/// The JSON response. HTML escaping is left on and a newline appended, so every body written is
/// HTML-escaped and newline-terminated.
pub(crate) fn json_response(status: StatusCode, value: &impl Serialize) -> Response<RespBody> {
    response_with(status, &[(header::CONTENT_TYPE, "application/json")], full_body(encode_json(value)))
}

/// The JSON-encoding equivalent for bytes a serializer-style method produced.
pub(crate) fn encode_preset_json(bytes: &[u8]) -> Vec<u8> {
    let mut out = escape_html_entities(bytes);
    out.push(b'\n');
    out
}

/// The JSON bytes for `value`.
pub(crate) fn encode_json(value: &impl Serialize) -> Vec<u8> {
    encode_preset_json(&serde_json::to_vec(value).unwrap_or_default())
}

/// Escapes the HTML-significant bytes. A compact JSON document only contains these bytes inside
/// a string literal, so no string state has to be tracked.
fn escape_html_entities(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 8);
    let mut rest = bytes;
    while let Some((&first, tail)) = rest.split_first() {
        match first {
            b'<' => {
                out.extend_from_slice(br"\u003c");
                rest = tail;
            }
            b'>' => {
                out.extend_from_slice(br"\u003e");
                rest = tail;
            }
            b'&' => {
                out.extend_from_slice(br"\u0026");
                rest = tail;
            }
            0xE2 if tail.starts_with(&[0x80, 0xA8]) => {
                out.extend_from_slice(br"\u2028");
                rest = tail.get(2..).unwrap_or_default();
            }
            0xE2 if tail.starts_with(&[0x80, 0xA9]) => {
                out.extend_from_slice(br"\u2029");
                rest = tail.get(2..).unwrap_or_default();
            }
            other => {
                out.push(other);
                rest = tail;
            }
        }
    }
    out
}

/// Wraps a `Full<Bytes>` body so that hyper draining its final frame -- the closest signal this
/// crate's response model exposes to "the connection task now has everything it needs to write"
/// -- fires a oneshot exactly once, whether that happens on end-of-stream or the body being
/// dropped early (a connection abort still resolves it, so the awaiting side never hangs).
/// [`restart::restart_executable`](super::restart::restart_executable) and `upgrade::upgrade_core`
/// order shutdown-and-re-exec after this signal instead of a bare fixed delay, the closest match
/// this response model allows to a synchronous flush before the spawn.
struct SignalOnCompleteBody {
    inner: Full<Bytes>,
    signal: Option<oneshot::Sender<()>>,
}

impl SignalOnCompleteBody {
    fn fire(&mut self) {
        if let Some(tx) = self.signal.take() {
            let _ = tx.send(());
        }
    }
}

impl Body for SignalOnCompleteBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(poll, Poll::Ready(None)) {
            self.fire();
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        Body::size_hint(&self.inner)
    }
}

impl Drop for SignalOnCompleteBody {
    fn drop(&mut self) {
        self.fire();
    }
}

/// The JSON response, plus a completion signal for handlers that must order a disruptive action
/// (shutdown, re-exec) after the response hand-off; see [`SignalOnCompleteBody`].
pub(crate) fn json_response_with_completion(
    status: StatusCode,
    value: &impl Serialize,
) -> (Response<RespBody>, oneshot::Receiver<()>) {
    let body = encode_json(value);
    let (tx, rx) = oneshot::channel();
    let signal_body = SignalOnCompleteBody { inner: Full::new(Bytes::from(body)), signal: Some(tx) };
    let resp = response_with(status, &[(header::CONTENT_TYPE, "application/json")], BodyExt::boxed(signal_body));
    (resp, rx)
}

pub(crate) fn no_content() -> Response<RespBody> {
    response_with(StatusCode::NO_CONTENT, &[], empty_body())
}

pub(crate) fn plain_text(status: StatusCode, text: &str) -> Response<RespBody> {
    response_with(status, &[(header::CONTENT_TYPE, "text/plain; charset=utf-8")], full_body(text.to_owned()))
}

pub(crate) fn status_only(status: StatusCode) -> Response<RespBody> {
    response_with(status, &[], empty_body())
}

/// The 405 response: one `Allow` header per method registered on the route.
pub(crate) fn method_not_allowed(methods: &[&str]) -> Response<RespBody> {
    let mut resp = status_only(StatusCode::METHOD_NOT_ALLOWED);
    for method in methods {
        if let Ok(value) = header::HeaderValue::from_str(method) {
            resp.headers_mut().append(header::ALLOW, value);
        }
    }
    resp
}

/// Percent-decodes `param`, falling back to the raw value when it is not a complete escape
/// sequence.
pub(crate) fn get_escape_param(param: &str) -> String {
    path_unescape(param).unwrap_or_else(|_| param.to_owned())
}

fn header_str<'a>(req: &'a Req, name: &str) -> &'a str {
    req.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

/// Explained in the module documentation: this upgrade has its own rules.
#[expect(clippy::result_large_err, reason = "boxing the `Err` would change the published signature of `ws_upgrade`")]
pub(crate) fn ws_upgrade(req: &Req) -> Result<Response<RespBody>, Response<RespBody>> {
    if req.method() != Method::GET {
        return Err(plain_text(StatusCode::METHOD_NOT_ALLOWED, "handshake error: bad HTTP request method"));
    }
    if req.version() == Version::HTTP_09 || req.version() == Version::HTTP_10 {
        return Err(plain_text(StatusCode::HTTP_VERSION_NOT_SUPPORTED, "handshake error: bad HTTP protocol version"));
    }
    let host = header_str(req, header::HOST.as_str());
    if host.is_empty() {
        return Err(plain_text(StatusCode::BAD_REQUEST, "handshake error: bad Host header"));
    }
    let upgrade = header_str(req, "upgrade");
    if upgrade != "websocket" && !upgrade.eq_ignore_ascii_case("websocket") {
        return Err(plain_text(StatusCode::BAD_REQUEST, "handshake error: bad Upgrade header"));
    }
    let connection = header_str(req, "connection");
    if connection != "Upgrade" && !connection.to_lowercase().contains("upgrade") {
        return Err(plain_text(StatusCode::BAD_REQUEST, "handshake error: bad Connection header"));
    }
    let nonce = header_str(req, "sec-websocket-key").to_owned();
    if nonce.len() != 24 {
        return Err(plain_text(StatusCode::BAD_REQUEST, "handshake error: bad Sec-WebSocket-Key header"));
    }
    let version = header_str(req, "sec-websocket-version");
    if version != "13" {
        let body = "handshake error: bad Sec-WebSocket-Version header";
        let mut builder = Response::builder()
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(header::CONTENT_LENGTH, body.len());
        builder = if version.is_empty() {
            builder.status(StatusCode::BAD_REQUEST)
        } else {
            builder.header("Sec-WebSocket-Version", "13").status(StatusCode::UPGRADE_REQUIRED)
        };
        return Err(finish_response(builder, full_body(body)));
    }

    Ok(finish_response(
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::UPGRADE, "websocket")
            .header(header::CONNECTION, "Upgrade")
            .header("Sec-WebSocket-Accept", get_websocket_sec_accept(&nonce)),
        empty_body(),
    ))
}

/// Writes a message to `w`, from the server side.
#[expect(
    clippy::cast_possible_truncation,
    reason = "each branch bounds data_len to the width of the frame length field it writes (under 126, then under 65536), so neither narrowing cast can truncate"
)]
pub(crate) async fn ws_write_server_message(
    w: &mut (impl AsyncWrite + Unpin),
    op: u8,
    p: &[u8],
) -> std::io::Result<()> {
    let data_len = p.len();
    let mut bts = [0u8; 14];
    bts[0] |= 0x80;
    bts[0] |= op;
    let n = if data_len < 126 {
        bts[1] = data_len as u8;
        2
    } else if data_len < 65536 {
        bts[1] = 126;
        bts[2..4].copy_from_slice(&(data_len as u16).to_be_bytes());
        4
    } else {
        bts[1] = 127;
        bts[2..10].copy_from_slice(&(data_len as u64).to_be_bytes());
        10
    };
    let (header, _) = bts.split_at(n);
    w.write_all(header).await?;
    w.write_all(p).await
}

/// The same as `ws_write_server_message` with the text opcode.
pub(crate) async fn ws_write_server_text(w: &mut (impl AsyncWrite + Unpin), p: &[u8]) -> std::io::Result<()> {
    const OP_TEXT: u8 = 0x1;
    ws_write_server_message(w, OP_TEXT, p).await
}

/// Stands in for `http_body_util::channel::Channel` (its `channel` Cargo feature is not enabled
/// for this crate; see `listener/hysteria2_realm/api.rs`'s identical adapter).
struct ChannelBody {
    rx: mpsc::Receiver<Bytes>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.rx.poll_recv(cx).map(|chunk| chunk.map(|chunk| Ok(Frame::data(chunk))))
    }
}

fn channel_body(buffer: usize) -> (mpsc::Sender<Bytes>, RespBody) {
    let (tx, rx) = mpsc::channel(buffer);
    (tx, ChannelBody { rx }.boxed())
}

/// The two destinations streamed JSON is written to: an HTTP body channel, or the websocket
/// connection after an upgrade.
pub(crate) enum StreamSink {
    Http(mpsc::Sender<Bytes>),
    Ws(TokioIo<hyper::upgrade::Upgraded>),
}

impl StreamSink {
    /// Returns `false` once the sink can no longer accept data, which ends the stream.
    pub(crate) async fn write_text(&mut self, data: &[u8]) -> bool {
        match self {
            Self::Http(tx) => tx.send(Bytes::copy_from_slice(data)).await.is_ok(),
            Self::Ws(io) => ws_write_server_text(io, data).await.is_ok(),
        }
    }

    /// When a handler returns early (a bad `interval`, or a zero-period ticker), the websocket
    /// connection is left open and never written to again; reading until the peer closes
    /// reproduces that without leaking the socket.
    pub(crate) async fn idle_until_peer_closes(mut self) {
        let Self::Ws(io) = &mut self else { return };
        let mut buf = [0u8; 512];
        loop {
            match io.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }
}

/// Shared shape of the streaming routes (`traffic`, `memory`, `logs`, `connections`): each
/// either upgrades the connection to a websocket or streams `application/json` chunks over the
/// plain response, then drives `run` against whichever sink it ended up with. Returns the response
/// to hand back to hyper immediately; `run` continues in a spawned task.
pub(crate) fn stream_response<F, Fut>(req: Req, run: F) -> Response<RespBody>
where
    F: FnOnce(StreamSink) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    if header_str(&req, "upgrade") == "websocket" {
        match ws_upgrade(&req) {
            Err(resp) => resp,
            Ok(resp) => {
                tokio::spawn(async move {
                    let Ok(upgraded) = hyper::upgrade::on(req).await else { return };
                    run(StreamSink::Ws(TokioIo::new(upgraded))).await;
                });
                resp
            }
        }
    } else {
        let (tx, body) = channel_body(32);
        tokio::spawn(async move {
            run(StreamSink::Http(tx)).await;
        });
        response_with(StatusCode::OK, &[(header::CONTENT_TYPE, "application/json")], body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt as _;

    /// `restart::restart_executable`/`upgrade::upgrade_core` await this signal before shutting
    /// down, in place of a bare fixed delay; this proves the signal is actually tied to the body
    /// being drained rather than firing on construction.
    #[tokio::test]
    async fn completion_signal_fires_once_the_body_is_fully_drained() {
        let (resp, mut rx) = json_response_with_completion(StatusCode::OK, &serde_json::json!({"status": "ok"}));
        assert!(rx.try_recv().is_err(), "signal must not fire before the body is drained");

        let body = resp.into_body().collect().await.expect("collect body").to_bytes();
        assert_eq!(&body[..], b"{\"status\":\"ok\"}\n");

        rx.await.expect("signal must fire once the body is fully drained");
    }

    /// A response whose body is dropped without ever being polled to completion (a connection
    /// abort) still resolves the signal, so an awaiting task never hangs.
    #[tokio::test]
    async fn completion_signal_fires_on_early_drop() {
        let (resp, rx) = json_response_with_completion(StatusCode::OK, &serde_json::json!({"status": "ok"}));
        drop(resp);
        rx.await.expect("signal must fire when the body is dropped early");
    }

    fn body_of(frames: Vec<std::io::Result<Frame<Bytes>>>) -> impl Body<Data = Bytes, Error = std::io::Error> {
        http_body_util::StreamBody::new(futures::stream::iter(frames))
    }

    /// Decoding stops once the first JSON value is complete; bytes after it are neither parsed
    /// nor rejected.
    #[tokio::test]
    async fn trailing_garbage_after_a_valid_value_is_accepted() {
        let body = body_of(vec![Ok(Frame::data(Bytes::from_static(br#"{"a":1}NOT VALID JSON AT ALL"#)))]);
        let value: serde_json::Value = decode_json_body(body).await.expect("decodes the leading object");
        assert_eq!(value, serde_json::json!({"a": 1}));
    }

    /// Draining the body is best-effort: a stream that errors once the JSON value is already
    /// complete must not turn a successful decode into a failure, and the decode must not need to
    /// read that far to finish -- proof this does not collect the whole body before parsing, the
    /// way `BodyExt::collect` would.
    #[tokio::test]
    async fn decode_does_not_need_the_tail_and_ignores_a_drain_error() {
        let body = body_of(vec![
            Ok(Frame::data(Bytes::from_static(br#"{"a":1}"#))),
            Err(std::io::Error::other("connection reset mid-tail")),
        ]);
        let value: serde_json::Value = decode_json_body(body).await.expect("decode ignores the later drain error");
        assert_eq!(value, serde_json::json!({"a": 1}));
    }

    /// Regression for a value whose boundary only becomes visible partway through a later frame:
    /// the first frame ends inside the object, so the scanner reports "incomplete" and no parse
    /// is attempted; the second frame closes it. The resulting attempt must still accept the
    /// trailing garbage, not fail as if
    /// `serde_json::from_slice`'s trailing-data check had run.
    #[tokio::test]
    async fn decode_completes_after_split_boundary_with_trailing_garbage() {
        let body = body_of(vec![
            Ok(Frame::data(Bytes::from_static(br#"{"a":1"#))),
            Ok(Frame::data(Bytes::from_static(br#"} x"#))),
        ]);
        let value: serde_json::Value =
            decode_json_body(body).await.expect("decode after a split boundary must still succeed");
        assert_eq!(value, serde_json::json!({"a": 1}));
    }

    /// A bare top-level scalar never reaches the scanner's `Complete` state on its own frame: an
    /// unterminated number/literal could still extend with the next byte (`1` vs `12`), so the
    /// scanner reports `Incomplete` and waits for more. A non-EOF read error therefore always
    /// fails the decode, even for a value the scanner would have closed out had the stream ended
    /// cleanly instead.
    #[tokio::test]
    async fn decode_of_a_bare_scalar_fails_on_a_later_transport_error() {
        let body = body_of(vec![
            Ok(Frame::data(Bytes::from_static(b"1"))),
            Err(std::io::Error::other("connection reset mid-tail")),
        ]);
        let result: Result<serde_json::Value, ()> = decode_json_body(body).await;
        assert_eq!(result, Err(()), "a transport error must fail a still-pending scalar, not complete it");
    }

    /// Regression for a51e95fb: an ignored (unknown to `S`) field's number split right after `-`,
    /// `1.` or `1e` used to end decoding, because `serde_json`'s ignore-value path reports a
    /// non-EOF invalid-number error at that point instead of the EOF a decoder would see on
    /// the same partial input. The value is still bounded by `S`'s enclosing `{}`, so the scanner
    /// must wait for the second frame rather than let that syntax error end the decode.
    #[tokio::test]
    async fn decode_waits_out_a_split_number_in_an_ignored_field() {
        #[derive(serde::Deserialize)]
        struct S {
            a: i64,
        }
        for split in [br#"{"b":-"#.as_slice(), br#"{"b":1."#.as_slice(), br#"{"b":1e"#.as_slice()] {
            let body = body_of(vec![
                Ok(Frame::data(Bytes::copy_from_slice(split))),
                Ok(Frame::data(Bytes::from_static(br#"5,"a":1}"#))),
            ]);
            let value: S = decode_json_body(body).await.expect("ignored-field number split must not end decoding");
            assert_eq!(value.a, 1);
        }
    }

    /// Regression for a51e95fb: splitting a numeric map key (`PATCH /rules/disable`'s
    /// `HashMap<i64, bool>`) inside its quotes used to end decoding, because `serde_json`'s
    /// numeric-key path reports a non-EOF `ExpectedDoubleQuote`/`ExpectedNumericKey` there instead
    /// of the EOF. The key is still inside the map's enclosing `{}`, so the scanner must wait.
    #[tokio::test]
    async fn decode_waits_out_a_split_numeric_map_key() {
        let body = body_of(vec![
            Ok(Frame::data(Bytes::from_static(br#"{"1"#))),
            Ok(Frame::data(Bytes::from_static(br#"":true}"#))),
        ]);
        let value: std::collections::HashMap<i64, bool> =
            decode_json_body(body).await.expect("numeric map key split must not end decoding");
        assert_eq!(value.get(&1), Some(&true));
    }

    /// Regression for the scanner's escape state carrying across a frame boundary: a body split
    /// right after the backslash of an escaped quote must not treat the still-open string as
    /// closed, nor the object as complete, before the second frame arrives.
    #[tokio::test]
    async fn decode_waits_out_a_split_escape_sequence() {
        let body = body_of(vec![
            Ok(Frame::data(Bytes::from_static(br#"{"a":"x\"#))),
            Ok(Frame::data(Bytes::from_static(br#""y"}"#))),
        ]);
        let value: serde_json::Value = decode_json_body(body).await.expect("split escape must not end decoding");
        assert_eq!(value, serde_json::json!({"a": "x\"y"}));
    }

    /// Regression for a drain that never stops: an h2 body whose stream ended in error (a client
    /// reset mid-request, `hyper-1.11.1` `body/incoming.rs`, `h2-0.4.19` `proto/streams/state.rs`)
    /// returns that same error on every subsequent poll instead of `None`. The old
    /// `std::io::copy` drain, and the streaming copy, both stop at the first read error; a drain that
    /// kept polling here would spin a worker at 100% CPU forever instead of returning. The error
    /// tail is capped at 16 (rather than infinite) so a drain that fails to stop hits the
    /// `POLLED` assertion below deterministically instead of hanging the test past its timeout --
    /// `repeat_with`'s closure never yields to the executor, so an unbounded tail would never let
    /// `tokio::time::timeout`'s deadline get polled either.
    #[tokio::test]
    async fn drain_stops_at_the_first_error_instead_of_spinning() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static POLLED: AtomicUsize = AtomicUsize::new(0);

        let head =
            futures::stream::once(async { Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(br#"{"a":1}"#))) });
        let tail = futures::stream::repeat_with(|| {
            POLLED.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::other("permanent h2 stream error"))
        })
        .take(16);
        let body = Box::pin(http_body_util::StreamBody::new(head.chain(tail)));

        let value: serde_json::Value = tokio::time::timeout(std::time::Duration::from_secs(2), decode_json_body(body))
            .await
            .expect("drain must not spin forever on a permanently erroring body")
            .expect("decode succeeds despite the later permanent error");
        assert_eq!(value, serde_json::json!({"a": 1}));
        assert_eq!(POLLED.load(Ordering::SeqCst), 1, "drain must stop after the first error, not keep polling");
    }

    /// An empty body is a decode error.
    #[tokio::test]
    async fn empty_body_is_a_decode_error() {
        let body = body_of(vec![]);
        let result: Result<serde_json::Value, ()> = decode_json_body(body).await;
        assert_eq!(result, Err(()));
    }

    /// Malformed JSON is a decode error.
    #[tokio::test]
    async fn malformed_json_is_a_decode_error() {
        let body = body_of(vec![Ok(Frame::data(Bytes::from_static(b"not json")))]);
        let result: Result<serde_json::Value, ()> = decode_json_body(body).await;
        assert_eq!(result, Err(()));
    }

    /// Regression for buffering the whole body before decoding (`BodyExt::collect` then
    /// `serde_json::from_slice`): a lazily generated tail of drop-tracked chunks never has more
    /// than a couple alive at once while it drains, which a whole-body collect (holding every
    /// chunk, then the joined copy) would not.
    #[tokio::test]
    async fn a_huge_trailing_tail_is_not_buffered() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        const CHUNK: usize = 64 * 1024;
        const CHUNKS: usize = 4096; // 256 MiB total, generated and dropped one chunk at a time
        static ALIVE: AtomicUsize = AtomicUsize::new(0);
        static PEAK: AtomicUsize = AtomicUsize::new(0);

        struct CountedChunk(Vec<u8>);
        impl AsRef<[u8]> for CountedChunk {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl Drop for CountedChunk {
            fn drop(&mut self) {
                ALIVE.fetch_sub(1, Ordering::SeqCst);
            }
        }

        let head =
            futures::stream::once(async { Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(br#"{"a":1}"#))) });
        let tail = futures::stream::unfold(0usize, |i| async move {
            if i >= CHUNKS {
                return None;
            }
            let alive = ALIVE.fetch_add(1, Ordering::SeqCst) + 1;
            PEAK.fetch_max(alive, Ordering::SeqCst);
            let bytes = Bytes::from_owner(CountedChunk(vec![b'x'; CHUNK]));
            Some((Ok(Frame::data(bytes)), i + 1))
        });
        let body = Box::pin(http_body_util::StreamBody::new(head.chain(tail)));
        let value: serde_json::Value = decode_json_body(body).await.expect("decodes the leading object");
        assert_eq!(value, serde_json::json!({"a": 1}));

        let peak = PEAK.load(Ordering::SeqCst);
        assert!(peak < CHUNKS / 4, "peak {peak} of {CHUNKS} tail chunks alive at once; body was collected up front");
    }

    /// Regression for `spawn_blocking` + `SyncIoBridge`: a body that never yields more data must
    /// not hold the sole blocking-pool thread hostage, so a concurrent `spawn_blocking` task
    /// still runs. `decode_fut` is polled once before the competing task is spawned so the old
    /// implementation's internal `spawn_blocking` claims the sole pool thread first; otherwise the
    /// trivial task races ahead and the test passes for the wrong reason. The runtime that could
    /// then deadlock (a `max_blocking_threads(1)` runtime, old implementation) runs on its own
    /// `std::thread`; the test thread bounds the wait with `recv_timeout` rather than
    /// `tokio::time::timeout`, because a deadlock that also wedges the runtime's own driver thread
    /// would otherwise never let an in-runtime timer fire, hanging `cargo test` instead of failing
    /// it.
    #[test]
    fn stalled_body_does_not_pin_a_blocking_pool_thread() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .max_blocking_threads(1)
                .enable_all()
                .build()
                .expect("build runtime");
            let result = rt.block_on(async {
                let stalled_body =
                    http_body_util::StreamBody::new(futures::stream::pending::<std::io::Result<Frame<Bytes>>>());
                let mut decode_fut = std::pin::pin!(decode_json_body::<serde_json::Value, _>(stalled_body));
                let _ = futures::poll!(&mut decode_fut);
                let blocking = tokio::task::spawn_blocking(|| 42);
                tokio::select! {
                    _ = &mut decode_fut => panic!("decode must never complete: the stalled body never yields data"),
                    result = blocking => result.expect("spawn_blocking task panicked"),
                }
            });
            rt.shutdown_background();
            let _ = tx.send(result);
        });

        let result = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("spawn_blocking starved: the stalled body pinned the sole blocking-pool thread");
        assert_eq!(result, 42);
    }

    /// Regression for buffering an invalid body in full before rejecting it
    /// (`ValueBoundaryScanner` used to track only string/escape state and bracket depth, so any
    /// alphanumeric byte looked like it could still be part of a scalar): a body that is invalid
    /// from its second byte on (`n` starts `null`, but `x` cannot follow `n`) must fail as soon as
    /// the scanner sees that byte, never buffering the megabytes of tail that follow it, the same
    /// way `a_huge_trailing_tail_is_not_buffered` proves a valid decode does not buffer its tail.
    #[tokio::test]
    async fn an_invalid_body_is_rejected_before_its_tail_is_buffered() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        const CHUNK: usize = 64 * 1024;
        const CHUNKS: usize = 4096;
        static ALIVE: AtomicUsize = AtomicUsize::new(0);
        static PEAK: AtomicUsize = AtomicUsize::new(0);

        struct CountedChunk(Vec<u8>);
        impl AsRef<[u8]> for CountedChunk {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl Drop for CountedChunk {
            fn drop(&mut self) {
                ALIVE.fetch_sub(1, Ordering::SeqCst);
            }
        }

        let head = futures::stream::once(async { Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(b"n"))) });
        let tail = futures::stream::unfold(0usize, |i| async move {
            if i >= CHUNKS {
                return None;
            }
            let alive = ALIVE.fetch_add(1, Ordering::SeqCst) + 1;
            PEAK.fetch_max(alive, Ordering::SeqCst);
            let bytes = Bytes::from_owner(CountedChunk(vec![b'x'; CHUNK]));
            Some((Ok(Frame::data(bytes)), i + 1))
        });
        let body = Box::pin(http_body_util::StreamBody::new(head.chain(tail)));
        let result: Result<serde_json::Value, ()> = decode_json_body(body).await;
        assert_eq!(result, Err(()), "`nx...` is not valid JSON");

        let peak = PEAK.load(Ordering::SeqCst);
        assert!(
            peak < CHUNKS / 4,
            "peak {peak} of {CHUNKS} tail chunks alive at once; invalid body was buffered whole"
        );
    }

    /// The scanner rejects a value that continues past where its container expects a delimiter,
    /// not just an unbalanced bracket: `[1x]` is invalid. A scanner that tracked only bracket
    /// depth accepted this.
    #[tokio::test]
    async fn a_value_without_a_following_delimiter_inside_a_container_is_invalid() {
        let body = body_of(vec![Ok(Frame::data(Bytes::from_static(b"[1x]")))]);
        let result: Result<serde_json::Value, ()> = decode_json_body(body).await;
        assert_eq!(result, Err(()));
    }

    /// the scanner requires the exact spelling of `true`/`false`/`null`; a bare top-level
    /// misspelling like `nul` followed by garbage is invalid, not a truncated-but-otherwise-fine
    /// literal that the old alnum-based scanner would have kept buffering as "still scalar".
    #[tokio::test]
    async fn a_misspelled_literal_is_invalid() {
        let body = body_of(vec![Ok(Frame::data(Bytes::from_static(b"nulx")))]);
        let result: Result<serde_json::Value, ()> = decode_json_body(body).await;
        assert_eq!(result, Err(()));
    }

    /// The encoder escapes `<`, `>`, `&` and U+2028/U+2029, and appends a trailing newline.
    #[test]
    fn encode_json_escapes_html_and_line_separators() {
        assert_eq!(
            encode_json(&serde_json::json!({"payload": "a<b>c&d"})),
            b"{\"payload\":\"a\\u003cb\\u003ec\\u0026d\"}\n".to_vec()
        );
        assert_eq!(
            encode_json(&serde_json::json!({"payload": "x\u{2028}y\u{2029}z"})),
            b"{\"payload\":\"x\\u2028y\\u2029z\"}\n".to_vec()
        );
    }

    /// A response body whose strings carry HTML escapes them and ends in a newline.
    #[tokio::test]
    async fn json_response_escapes_html_and_appends_a_newline() {
        let resp = json_response(StatusCode::OK, &serde_json::json!({"payload": "<b>&</b>"}));
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).expect("content type"), "application/json");
        let body = resp.into_body().collect().await.expect("collect body").to_bytes();
        let mut expected = br#"{"payload":"\u003cb\u003e\u0026\u003c/b\u003e"}"#.to_vec();
        expected.push(b'\n');
        assert_eq!(&body[..], expected.as_slice());
    }

    /// A 405 carries one `Allow` per method the route was registered with.
    #[test]
    fn method_not_allowed_lists_every_registered_method() {
        let resp = method_not_allowed(&["GET"]);
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp.headers().get(header::ALLOW).expect("allow header"), "GET");

        let resp = method_not_allowed(&["GET", "DELETE"]);
        let allow: Vec<&str> =
            resp.headers().get_all(header::ALLOW).iter().map(|value| value.to_str().expect("ascii")).collect();
        assert_eq!(allow, ["GET", "DELETE"]);
    }
}

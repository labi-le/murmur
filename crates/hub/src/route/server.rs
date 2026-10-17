//! HTTP dispatch for the controller API.
//!
//! [`dispatch`] parses the request path into segments and matches them against each mounted
//! sub-package's `route` function (`configs::route`, `proxies::route`, …), the same convention
//! `listener/hysteria2_realm/api.rs` and `transport/xhttp/server.rs` use. A `route` returns
//! `None` for an unrecognized path shape (→ 404) or `Some(response)` once it has decided the
//! exact status, so the not-found/method-not-allowed distinction lives in each handler's own
//! method check:
//!
//! * a known route with a wrong method answers 405 with an `Allow` header;
//! * a matched mount hands the sub-router the path segments after the boundary, with a trailing
//!   empty segment preserved (see [`mount_rest`] for which boundary absorbs it);
//! * anything else answers the plain text 404 page.
//!
//! [`Cors::preflight`] and [`Cors::apply_captured`] cover the CORS behaviour this API needs
//! (origin echoing, `Vary: Origin`, preflight `OPTIONS`).
//!
//! Websocket upgrades (`traffic`/`memory`/`logs`) and chunked streaming go through
//! `common.rs`'s `stream_response`/`StreamSink`, built on `hyper::upgrade::on` and a
//! channel-backed body; see that module's doc comment.
//!
//! The pprof HTTP mount (gated by the debug flag) lives in [`super::pprof`], which [`debug_route`]
//! delegates every `/debug` path but `/gc` to. `/debug/gc` is a no-op 200: the global allocator
//! has no forced-collection call.
//!
//! The `/ui` static mount is served by [`serve_ui_file`] and [`serve_content`]: path
//! cleaning/localizing, its `index.html` and trailing-slash redirects, and the content type,
//! `Last-Modified`, `If-*` preconditions, `Range` and `HEAD` handling.
//! [`serve_content`] documents the content differences that remain. One more is a DEVIATION:
//! `/ui` and `/ui/*` answer `HEAD`, where only `GET` is registered.

use std::convert::Infallible;
use std::io::SeekFrom;
use std::path::{Path as StdPath, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::anyhow;
use chrono::{DateTime, NaiveDateTime, Utc};
use futures::StreamExt as _;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::{header, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt as _};
use tokio::task::JoinHandle;
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::listen::new_listen_config;
#[cfg(not(target_os = "windows"))]
use murmur_adapter_inbound::listen_notwindows::{listen_named_pipe, SUPPORT_NAMED_PIPE};
#[cfg(target_os = "windows")]
use murmur_adapter_inbound::listen_windows::{listen_named_pipe, SUPPORT_NAMED_PIPE};
use murmur_common_net::io::{Acceptor, OldListenerAsAcceptor};
use murmur_component_ca::auth::{
    client_auth_type_from_string, NO_CLIENT_CERT, REQUIRE_AND_VERIFY_CLIENT_CERT, VERIFY_CLIENT_CERT_IF_GIVEN,
};
use murmur_component_ca::keypair::{load_certificates, new_tls_key_pair_loader, KeyPairLoader};
use murmur_component_ech::load_ech_key;
use murmur_component_tls::utls::{new_listener as tls_new_listener, Config as TlsConfig};
use murmur_constant::path::{clean_path, PATH};
use murmur_log::level::LOG_LEVEL_MAPPING;
use murmur_log::{errorln, infoln, subscribe, un_subscribe, Event};
use murmur_std_compat::net::Listener as NetListener;
use murmur_tunnel::statistic::manager::DEFAULT_MANAGER;

use super::common::{
    empty_body, encode_json, finish_response, full_body, get_escape_param, json_response, method_not_allowed,
    response_with, status_only, stream_response, Req, RespBody, StreamSink,
};
use super::errors::err_unauthorized;
use super::{
    cache, configs, connections, dns, doh, external, groups, provider, proxies, restart, rules, storage, upgrade,
};

static EMBED_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_embed_mode(embed: bool) {
    EMBED_MODE.store(embed, Ordering::SeqCst);
}

/// The embed-mode flag, exposed for the sibling modules that read it.
pub(crate) fn embed_mode() -> bool {
    EMBED_MODE.load(Ordering::SeqCst)
}

#[derive(Serialize)]
struct Traffic {
    up: i64,
    down: i64,
    #[serde(rename = "upTotal")]
    up_total: i64,
    #[serde(rename = "downTotal")]
    down_total: i64,
}

#[derive(Serialize)]
struct Memory {
    inuse: u64,
    oslimit: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub addr: String,
    pub tls_addr: String,
    pub unix_addr: String,
    pub pipe_addr: String,
    /// The `external-ui` root as configured; an empty value unmounts `/ui`.
    pub ui_path: String,
    pub routing_mark: i32,
    pub secret: String,
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
    pub doh_server: String,
    pub is_debug: bool,
    pub cors: Cors,
}

#[derive(Clone, Debug, Default)]
pub struct Cors {
    pub allow_origins: Vec<String>,
    pub allow_private_network: bool,
}

impl Cors {
    fn origin_allowed(&self, origin: &str) -> bool {
        self.allow_origins.iter().any(|o| o == "*" || o.eq_ignore_ascii_case(origin))
    }

    /// Applied to every response the router produces. The request's `Origin`/private-network
    /// preflight headers are passed in already extracted, because the response is decorated
    /// after routing has consumed the request.
    fn apply_captured(&self, origin: Option<&str>, private_network_requested: bool, resp: &mut Response<RespBody>) {
        // `Vary: Origin` is set before the header is inspected, so every response carries it,
        // whether or not an `Origin` was sent.
        resp.headers_mut().append(header::VARY, header::HeaderValue::from_static("Origin"));
        let Some(origin) = origin else {
            return;
        };
        if !self.origin_allowed(origin) {
            return;
        }
        if let Ok(value) = header::HeaderValue::from_str(origin) {
            resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        }
        resp.headers_mut().append(header::VARY, header::HeaderValue::from_static("Origin"));
        if self.allow_private_network && private_network_requested {
            resp.headers_mut().insert("Access-Control-Allow-Private-Network", header::HeaderValue::from_static("true"));
        }
    }

    fn preflight(&self, req: &Req) -> Option<Response<RespBody>> {
        if req.method() != Method::OPTIONS || req.headers().get("Access-Control-Request-Method").is_none() {
            return None;
        }
        let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok());
        let private_network_requested = req.headers().get("Access-Control-Request-Private-Network").is_some();
        let mut resp = status_only(StatusCode::OK);
        self.apply_captured(origin, private_network_requested, &mut resp);
        resp.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            header::HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE"),
        );
        resp.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            header::HeaderValue::from_static("Content-Type, Authorization"),
        );
        resp.headers_mut().insert(header::ACCESS_CONTROL_MAX_AGE, header::HeaderValue::from_static("300"));
        Some(resp)
    }
}

/// Replaces every controller transport with the one `cfg` names.
///
/// The starts are awaited rather than spawned: a caller that reports the outcome of a configuration
/// application has to see a transport that could not bind, otherwise it records a partial apply as
/// a completed one and skips the retry.
pub async fn re_create_server(cfg: Arc<Config>) -> anyhow::Result<()> {
    let mut failures = Vec::new();
    for result in [start(Arc::clone(&cfg)).await, start_tls(Arc::clone(&cfg)).await, start_unix(Arc::clone(&cfg)).await]
    {
        if let Err(err) = result {
            failures.push(err);
        }
    }
    if SUPPORT_NAMED_PIPE {
        if let Err(err) = start_pipe(cfg).await {
            failures.push(err);
        }
    }
    if failures.is_empty() {
        return Ok(());
    }
    let joined = failures.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ");
    Err(anyhow!("{joined}"))
}

struct RunningServer {
    listener: Arc<dyn NetListener>,
    closed: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl RunningServer {
    /// Closing the server leaves the address free to rebind; here the socket dies with the
    /// accept loop's reference, so wait for that loop and drop ours. The loop is aborted because
    /// `Listener::close` only unparks the accept — a listener that ignores it must not keep the
    /// port.
    async fn close(self) {
        let Self { listener, closed, task } = self;
        closed.store(true, Ordering::SeqCst);
        let _ = listener.close();
        task.abort();
        let _ = task.await;
        drop(listener);
    }
}

struct TlsRunningServer {
    listener: Arc<dyn Acceptor>,
    closed: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl TlsRunningServer {
    /// See [`RunningServer::close`].
    async fn close(self) {
        let Self { listener, closed, task } = self;
        closed.store(true, Ordering::SeqCst);
        let _ = listener.close();
        task.abort();
        let _ = task.await;
        drop(listener);
    }
}

static HTTP_SERVER: Mutex<Option<RunningServer>> = Mutex::new(None);
static TLS_SERVER: Mutex<Option<TlsRunningServer>> = Mutex::new(None);
static UNIX_SERVER: Mutex<Option<RunningServer>> = Mutex::new(None);
static PIPE_SERVER: Mutex<Option<RunningServer>> = Mutex::new(None);

/// Percent-decodes the value (and turns `+` into a space) via query parsing instead of comparing
/// the still raw-encoded query string.
pub(crate) fn query_param(query: &str, key: &str) -> Option<String> {
    let value = murmur_common_convert::v::parse_query(query).0.get(key);
    (!value.is_empty()).then_some(value)
}

/// A constant-time comparison; the length check is not constant-time either.
fn safe_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn cut_once(s: &str, sep: char) -> (&str, &str, bool) {
    match s.find(sep) {
        Some(idx) => {
            let (head, tail) = s.split_at(idx);
            (head, tail.get(sep.len_utf8()..).unwrap_or_default(), true)
        }
        None => (s, "", false),
    }
}

/// `authentication`. Returns `Some(response)` to short-circuit with a 401, or `None` to let
/// the request continue.
fn check_authentication(req: &Req, secret: &str) -> Option<Response<RespBody>> {
    let upgrade = req.headers().get("upgrade").and_then(|v| v.to_str().ok()).unwrap_or("");
    if upgrade == "websocket" {
        let query = req.uri().query().unwrap_or("");
        if let Some(token) = query_param(query, "token") {
            if !safe_equal(&token, secret) {
                return Some(json_response(StatusCode::UNAUTHORIZED, &err_unauthorized()));
            }
            return None;
        }
    }

    let header = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    let (bearer, token, found) = cut_once(header, ' ');
    let has_invalid_header = bearer != "Bearer";
    let has_invalid_secret = !found || !safe_equal(token, secret);
    if has_invalid_header || has_invalid_secret {
        return Some(json_response(StatusCode::UNAUTHORIZED, &err_unauthorized()));
    }
    None
}

fn hello() -> Response<RespBody> {
    json_response(StatusCode::OK, &serde_json::json!({"hello": "murmur"}))
}

fn traffic(req: Req) -> Response<RespBody> {
    stream_response(req, |mut sink: StreamSink| async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        tick.tick().await;
        loop {
            tick.tick().await;
            let (up, down) = DEFAULT_MANAGER.now();
            let (up_total, down_total) = DEFAULT_MANAGER.total();
            let buf = encode_json(&Traffic { up, down, up_total, down_total });
            if !sink.write_text(&buf).await {
                break;
            }
        }
    })
}

fn memory(req: Req) -> Response<RespBody> {
    stream_response(req, |mut sink: StreamSink| async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        tick.tick().await;
        let mut first = true;
        loop {
            tick.tick().await;
            let mut inuse = DEFAULT_MANAGER.memory().await;
            if first {
                inuse = 0;
                first = false;
            }
            let buf = encode_json(&Memory { inuse, oslimit: 0 });
            if !sink.write_text(&buf).await {
                break;
            }
        }
    })
}

#[derive(Serialize)]
struct Log {
    #[serde(rename = "type")]
    type_: String,
    payload: String,
}

#[derive(Serialize)]
struct LogStructuredField {
    #[allow(
        dead_code,
        reason = "clash-compatible JSON wire shape for the log-fields array element; the own encoder always sends an empty array too, so the fields are schema-only on both sides"
    )]
    key: String,
    #[allow(
        dead_code,
        reason = "clash-compatible JSON wire shape for the log-fields array element; the own encoder always sends an empty array too, so the fields are schema-only on both sides"
    )]
    value: String,
}

#[derive(Serialize)]
struct LogStructured {
    time: String,
    level: String,
    message: String,
    fields: Vec<LogStructuredField>,
}

fn get_logs(req: Req) -> Response<RespBody> {
    let query = req.uri().query().unwrap_or("").to_owned();
    let level_text = {
        let v = query_param(&query, "level").unwrap_or_default();
        if v.is_empty() {
            "info".to_owned()
        } else {
            v
        }
    };
    let is_structured = query_param(&query, "format").as_deref() == Some("structured");

    let Some(&level) = LOG_LEVEL_MAPPING.get(level_text.as_str()) else {
        return json_response(StatusCode::BAD_REQUEST, &super::errors::err_bad_request());
    };

    stream_response(req, move |mut sink: StreamSink| async move {
        let Ok(sub) = subscribe().await else { return };
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(1024);
        let forward_sub = sub.clone();
        let forwarder = tokio::spawn(async move {
            while let Some(event) = forward_sub.recv().await {
                let _ = tx.try_send(event);
            }
        });

        while let Some(log_m) = rx.recv().await {
            if log_m.log_level < level {
                continue;
            }

            let buf = if is_structured {
                let mut new_level = log_m.type_();
                if new_level == "warning" {
                    new_level.clear();
                    new_level.push_str("warn");
                }
                encode_json(&LogStructured {
                    time: chrono::Local::now().format("%H:%M:%S").to_string(),
                    level: new_level,
                    message: log_m.payload.clone(),
                    fields: Vec::new(),
                })
            } else {
                encode_json(&Log { type_: log_m.type_(), payload: log_m.payload.clone() })
            };

            if !sink.write_text(&buf).await {
                break;
            }
        }

        forwarder.abort();
        un_subscribe(sub).await;
    })
}

fn version() -> Response<RespBody> {
    json_response(
        StatusCode::OK,
        &serde_json::json!({"meta": murmur_constant::version::META, "version": murmur_constant::version::VERSION}),
    )
}

/// Top-level dispatch over the mounted routes; see the module doc comment for the overall shape.
async fn dispatch(req: Req, cfg: Arc<RouterState>) -> Response<RespBody> {
    if let Some(resp) = cfg.cors.preflight(&req) {
        return resp;
    }

    let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let private_network_requested = req.headers().get("Access-Control-Request-Private-Network").is_some();

    let mut resp = dispatch_inner(req, &cfg).await;
    // A websocket handler hijacks the connection and writes its own 101 by hand, so the CORS
    // headers never reach the wire on an upgrade; hyper does not hijack, so the equivalent is to
    // leave the 101 alone.
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        cfg.cors.apply_captured(origin.as_deref(), private_network_requested, &mut resp);
    }
    resp
}

struct RouterState {
    is_debug: bool,
    secret: String,
    doh_server: String,
    ui_path: String,
    cors: Cors,
}

impl RouterState {
    /// The state every listener serves from, built from the same `Config`: a listener that spelled
    /// its own literal could drop an input the others carried, as the Unix and pipe listeners did
    /// with `secret`.
    fn from_config(cfg: &Config) -> Self {
        Self {
            is_debug: cfg.is_debug,
            secret: cfg.secret.clone(),
            doh_server: cfg.doh_server.clone(),
            // Resolving an empty path would mount the home directory, so the empty value that
            // disables the mount has to survive.
            ui_path: if cfg.ui_path.is_empty() { String::new() } else { PATH.resolve(&cfg.ui_path) },
            cors: cfg.cors.clone(),
        }
    }
}

async fn dispatch_inner(req: Req, cfg: &RouterState) -> Response<RespBody> {
    let path = req.uri().path().to_owned();

    if cfg.is_debug {
        if let Some(rest) = path.strip_prefix("/debug") {
            return debug_route(req, rest).await;
        }
    }

    if !cfg.ui_path.is_empty() {
        if path == "/ui" {
            return if matches!(req.method(), &Method::GET | &Method::HEAD) {
                response_with(StatusCode::TEMPORARY_REDIRECT, &[(header::LOCATION, "/ui/")], empty_body())
            } else {
                method_not_allowed(&["GET"])
            };
        }
        if let Some(rest) = path.strip_prefix("/ui/") {
            return serve_ui_file(&cfg.ui_path, &req, rest).await;
        }
    }

    if !cfg.doh_server.is_empty()
        && cfg.doh_server.starts_with('/')
        && (path == cfg.doh_server || path.starts_with(&format!("{}/", cfg.doh_server)))
    {
        return doh::route(req, &[]).await.unwrap_or_else(not_found);
    }

    if !cfg.secret.is_empty() {
        if let Some(resp) = check_authentication(&req, &cfg.secret) {
            return resp;
        }
    }

    // A trailing slash is a segment of its own, so the empty ones must survive to keep
    // `/traffic/` a 404 while `/connections/` still routes.
    let segs: Vec<&str> = path.strip_prefix('/').unwrap_or(&path).split('/').collect();
    route_authenticated(req, &segs).await
}

/// Absorbs the trailing empty segment of a mount boundary: every nested resource is mounted at
/// both `/pattern` and `/pattern/`, so a trailing slash is accepted at the sub-router's own root
/// and at each nested mount — `/proxies/{name}/` and `/providers/proxies/{provider}/{proxy}/`
/// route, while `/cache/fakeip/flush/` and `/connections/{id}/` (a plain param route, not a
/// mount) are 404s.
///
/// `nested_mounts` counts only the boundaries the sub-router does not trim itself: `provider.rs`
/// trims each of its own with an identical `mount_tail`, so its callers pass 0 there, while
/// `proxies.rs`/`groups.rs` have no such helper and get their single `/{name}` boundary from here.
/// Trimming a boundary the sub-router models would erase the distinction between a static route
/// and the mount below it (`/providers/proxies/{p}/healthcheck` vs `.../healthcheck/`).
fn mount_rest<'a, 'b>(rest: &'a [&'b str], nested_mounts: usize) -> &'a [&'b str] {
    let Some((last, trimmed)) = rest.split_last() else { return rest };
    if !last.is_empty() {
        return rest;
    }
    if trimmed.len() <= nested_mounts {
        trimmed
    } else {
        rest
    }
}

async fn route_authenticated(req: Req, segs: &[&str]) -> Response<RespBody> {
    let result: Option<Response<RespBody>> = match segs {
        [""] => Some(if req.method() == Method::GET { hello() } else { method_not_allowed(&["GET"]) }),
        ["logs"] => Some(if req.method() == Method::GET { get_logs(req) } else { method_not_allowed(&["GET"]) }),
        ["traffic"] => Some(if req.method() == Method::GET { traffic(req) } else { method_not_allowed(&["GET"]) }),
        ["memory"] => Some(if req.method() == Method::GET { memory(req) } else { method_not_allowed(&["GET"]) }),
        ["version"] => Some(if req.method() == Method::GET { version() } else { method_not_allowed(&["GET"]) }),
        ["configs", rest @ ..] => configs::route(req, mount_rest(rest, 0)).await,
        ["proxies", rest @ ..] => proxies::route(req, mount_rest(rest, 1)).await,
        ["group", rest @ ..] => groups::route(req, mount_rest(rest, 1)).await,
        ["rules", rest @ ..] => rules::route(req, mount_rest(rest, 0)).await,
        ["connections", rest @ ..] => connections::route(req, mount_rest(rest, 0)).await,
        ["providers", "proxies", rest @ ..] => provider::route(req, mount_rest(rest, 0)).await,
        ["providers", "rules", rest @ ..] => provider::rule_route(req, mount_rest(rest, 0)).await,
        ["cache", rest @ ..] => cache::route(req, mount_rest(rest, 0)).await,
        ["dns", rest @ ..] => dns::route(req, mount_rest(rest, 0)).await,
        ["storage", rest @ ..] => storage::route(req, mount_rest(rest, 0)).await,
        ["restart", rest @ ..] if !embed_mode() => restart::route(req, mount_rest(rest, 0)).await,
        ["upgrade", rest @ ..] => upgrade::route(req, mount_rest(rest, 0)).await,
        _ => return finish_unmatched(req).await,
    };
    result.unwrap_or_else(not_found)
}

async fn finish_unmatched(req: Req) -> Response<RespBody> {
    external::add_external_routers(req).await.unwrap_or_else(not_found)
}

/// The `/debug` subrouter: `/gc` is handled ahead of the pprof mount, so it is the one route
/// under `/debug` without that mount's no-cache headers.
async fn debug_route(req: Req, rest: &str) -> Response<RespBody> {
    if rest == "/gc" {
        return if req.method() == Method::PUT { status_only(StatusCode::OK) } else { method_not_allowed(&["PUT"]) };
    }
    super::pprof::route(req, rest).await
}

const MIME_TYPES: &[(&str, &str)] = &[
    ("html", "text/html; charset=utf-8"),
    ("htm", "text/html; charset=utf-8"),
    ("css", "text/css; charset=utf-8"),
    ("js", "text/javascript; charset=utf-8"),
    ("mjs", "text/javascript; charset=utf-8"),
    ("json", "application/json"),
    ("svg", "image/svg+xml"),
    ("png", "image/png"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("gif", "image/gif"),
    ("ico", "image/x-icon"),
    ("webp", "image/webp"),
    ("woff", "font/woff"),
    ("woff2", "font/woff2"),
    ("ttf", "font/ttf"),
    ("wasm", "application/wasm"),
    ("map", "application/json"),
    ("txt", "text/plain; charset=utf-8"),
];

fn content_type_for(path: &str) -> &'static str {
    let ext = StdPath::new(path).extension().and_then(|e| e.to_str()).unwrap_or("");
    MIME_TYPES.iter().find(|(e, _)| e.eq_ignore_ascii_case(ext)).map_or("application/octet-stream", |(_, mime)| mime)
}

/// Serves a file from the `/ui` static mount. The whole `rest` string is percent-decoded once,
/// then cleaned as an absolute path rather than decoding each `/`-split raw segment on its own:
/// decoding per segment let a `%2F` inside one segment smuggle a `..` traversal past the
/// per-segment `".."` check, and a literal `//` produced an absolute `rel` that `PathBuf::join`
/// let replace `ui_path` outright.
///
/// Symlinks pointing outside `ui_path` — including ones reached through a `..`-collapsed
/// intermediate — are followed. A directory without an `index.html` answers 404.
async fn serve_ui_file(ui_path: &str, req: &Req, rest: &str) -> Response<RespBody> {
    let decoded = get_escape_param(rest);
    let upath = if decoded.starts_with('/') { decoded } else { format!("/{decoded}") };
    let had_trailing_slash = upath.ends_with('/');

    // The cleaned path.
    let cleaned = clean_path(&upath);
    // The cleaned name, with an empty result mapping to ".".
    let mut localized = clean_path(&format!("/{cleaned}"));
    localized.remove(0);
    if localized.is_empty() {
        localized.push('.');
    }

    // ".../index.html" redirects to "./" before the filesystem is touched.
    if upath.ends_with("/index.html") {
        return local_redirect(req, "./");
    }

    if !is_localizable(&localized) {
        return not_found();
    }

    let full = PathBuf::from(ui_path).join(&localized);
    let metadata = match tokio::fs::metadata(&full).await {
        Ok(metadata) => metadata,
        Err(err) => return open_error_response(&err),
    };

    let (full, metadata) = if metadata.is_dir() {
        if !had_trailing_slash {
            let base = upath.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            return local_redirect(req, &format!("{}/", escape_location_component(base)));
        }
        let index = full.join("index.html");
        match tokio::fs::metadata(&index).await {
            Ok(index_meta) if index_meta.is_file() => (index, index_meta),
            _ => return not_found(),
        }
    } else if metadata.is_file() {
        if had_trailing_slash {
            // a file asked for with a trailing slash redirects to "../base".
            let base = upath.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            if base.is_empty() || base == "." {
                return serve_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "http: attempting to traverse a non-directory",
                );
            }
            return local_redirect(req, &format!("../{}", escape_location_component(base)));
        }
        (full, metadata)
    } else {
        return not_found();
    };

    let file = match tokio::fs::File::open(&full).await {
        Ok(file) => file,
        Err(err) => return open_error_response(&err),
    };

    serve_content(req, &full, metadata.len(), &metadata, file).await
}

/// Serves the opened file for the `/ui` mount with the usual conditional-request and range
/// handling. The content type comes from the file extension; an unknown one is answered as
/// `application/octet-stream` rather than sniffed, and a multi-range request is answered with the
/// whole file rather than a `multipart/byteranges` body.
async fn serve_content(
    req: &Req,
    full: &StdPath,
    size: u64,
    metadata: &std::fs::Metadata,
    mut file: tokio::fs::File,
) -> Response<RespBody> {
    let modtime = metadata.modified().ok();
    let last_modified = modtime.filter(|time| !is_zero_time(*time)).map(format_http_date);

    match check_if_match(req) {
        Cond::False => return precondition_failed(last_modified.as_deref()),
        Cond::None => {
            if check_if_unmodified_since(req, modtime) == Cond::False {
                return precondition_failed(last_modified.as_deref());
            }
        }
        Cond::True => {}
    }
    match check_if_none_match(req) {
        Cond::False => {
            return if matches!(req.method(), &Method::GET | &Method::HEAD) {
                not_modified(last_modified.as_deref())
            } else {
                precondition_failed(last_modified.as_deref())
            };
        }
        Cond::None => {
            if check_if_modified_since(req, modtime) == Cond::False {
                return not_modified(last_modified.as_deref());
            }
        }
        Cond::True => {}
    }

    let mut range_header = request_header(req, header::RANGE).to_owned();
    if !range_header.is_empty() && check_if_range(req, modtime) == Cond::False {
        range_header.clear();
    }

    let ranges = match parse_range(&range_header, size) {
        Ok(ranges) => ranges,
        // An empty file ignores the range header instead of answering 416.
        Err(RangeError::NoOverlap) if size == 0 => Vec::new(),
        Err(err) => return range_not_satisfiable(size, err),
    };
    let total = ranges.iter().fold(0_u64, |total, range| total.saturating_add(range.length));
    let ranges = if total > size { Vec::new() } else { ranges };

    let (status, start, length, content_range) = match ranges.as_slice() {
        [range] => (
            StatusCode::PARTIAL_CONTENT,
            range.start,
            range.length,
            Some(format!("bytes {}-{}/{size}", range.start, range.start + range.length - 1)),
        ),
        _ => (StatusCode::OK, 0, size, None),
    };

    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type_for(&full.to_string_lossy()))
        .header(header::CONTENT_LENGTH, length.to_string())
        .header(header::ACCEPT_RANGES, "bytes");
    if let Some(content_range) = content_range {
        builder = builder.header(header::CONTENT_RANGE, content_range);
    }
    if let Some(last_modified) = last_modified {
        builder = builder.header(header::LAST_MODIFIED, last_modified);
    }

    if req.method() == Method::HEAD {
        return finish_response(builder, empty_body());
    }
    if start > 0 {
        if let Err(err) = file.seek(SeekFrom::Start(start)).await {
            return serve_error_response(StatusCode::RANGE_NOT_SATISFIABLE, &err.to_string());
        }
    }
    finish_response(builder, stream_file_body(file, length))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cond {
    None,
    True,
    False,
}

/// Reads a request header for the `If-*` preconditions; a value that is not valid UTF-8 is
/// treated as absent, which a date parse would reject anyway.
fn request_header(req: &Req, name: header::HeaderName) -> &str {
    req.headers().get(name).and_then(|value| value.to_str().ok()).unwrap_or("")
}

/// An RFC 7232 entity tag plus the text following it, or `None` if what starts there is not one.
fn scan_etag(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_matches(|c: char| c.is_ascii_whitespace());
    let start = if value.starts_with("W/") { 2 } else { 0 };
    let bytes = value.as_bytes();
    let rest = bytes.get(start..)?;
    let (&opening, tail) = rest.split_first()?;
    if opening != b'"' || tail.is_empty() {
        return None;
    }
    for (offset, &byte) in tail.iter().enumerate() {
        match byte {
            0x21 | 0x23..=0x7E => {}
            b'"' => {
                let end = start + 1 + offset;
                return Some((value.get(..=end)?, value.get(end + 1..)?));
            }
            byte if byte >= 0x80 => {}
            _ => return None,
        }
    }
    None
}

/// Every listed tag is compared against the response's ETag, which is never set, so only `*` can
/// pass.
fn check_if_match(req: &Req) -> Cond {
    let mut rest = request_header(req, header::IF_MATCH);
    if rest.is_empty() {
        return Cond::None;
    }
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
        if let Some(stripped) = rest.strip_prefix(',') {
            rest = stripped;
            continue;
        }
        if rest.starts_with('*') {
            return Cond::True;
        }
        match scan_etag(rest) {
            Some((_, remain)) => rest = remain,
            None => break,
        }
    }
    Cond::False
}

fn check_if_unmodified_since(req: &Req, modtime: Option<SystemTime>) -> Cond {
    let value = request_header(req, header::IF_UNMODIFIED_SINCE);
    let Some(modtime) = modtime.filter(|time| !is_zero_time(*time)) else {
        return Cond::None;
    };
    let Some(since) = parse_http_date(value) else {
        return Cond::None;
    };
    if http_seconds(modtime) <= http_seconds(since) {
        Cond::True
    } else {
        Cond::False
    }
}

fn check_if_none_match(req: &Req) -> Cond {
    let mut rest = request_header(req, header::IF_NONE_MATCH);
    if rest.is_empty() {
        return Cond::None;
    }
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
        if let Some(stripped) = rest.strip_prefix(',') {
            rest = stripped;
            continue;
        }
        if rest.starts_with('*') {
            return Cond::False;
        }
        match scan_etag(rest) {
            Some((_, remain)) => rest = remain,
            None => break,
        }
    }
    Cond::True
}

/// Only considers `GET` and `HEAD`.
fn check_if_modified_since(req: &Req, modtime: Option<SystemTime>) -> Cond {
    if !matches!(req.method(), &Method::GET | &Method::HEAD) {
        return Cond::None;
    }
    let value = request_header(req, header::IF_MODIFIED_SINCE);
    let Some(modtime) = modtime.filter(|time| !is_zero_time(*time)) else {
        return Cond::None;
    };
    let Some(since) = parse_http_date(value) else {
        return Cond::None;
    };
    if http_seconds(modtime) <= http_seconds(since) {
        Cond::False
    } else {
        Cond::True
    }
}

/// With no ETag on the response only its date form can match.
fn check_if_range(req: &Req, modtime: Option<SystemTime>) -> Cond {
    if !matches!(req.method(), &Method::GET | &Method::HEAD) {
        return Cond::None;
    }
    let value = request_header(req, header::IF_RANGE);
    if value.is_empty() {
        return Cond::None;
    }
    if scan_etag(value).is_some() {
        return Cond::False;
    }
    let Some(modtime) = modtime.filter(|time| !is_zero_time(*time)) else {
        return Cond::False;
    };
    match parse_http_date(value) {
        Some(since) if http_seconds(since) == http_seconds(modtime) => Cond::True,
        _ => Cond::False,
    }
}

const HTTP_TIME_FORMAT: &str = "%a, %d %b %Y %H:%M:%S GMT";

/// An unspecified modification time carries no `Last-Modified`.
fn is_zero_time(time: SystemTime) -> bool {
    time == SystemTime::UNIX_EPOCH
}

fn format_http_date(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).format(HTTP_TIME_FORMAT).to_string()
}

/// The full parse accepts the standard HTTP format first and then RFC 850 and ANSI C dates, which
/// is not done here; a client that omits the `GMT` suffix is treated as having sent no date.
fn parse_http_date(value: &str) -> Option<SystemTime> {
    let parsed = NaiveDateTime::parse_from_str(value.trim(), HTTP_TIME_FORMAT).ok()?;
    Some(SystemTime::from(parsed.and_utc()))
}

fn http_seconds(time: SystemTime) -> i64 {
    DateTime::<Utc>::from(time).timestamp()
}

struct HttpRange {
    start: u64,
    length: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RangeError {
    Invalid,
    NoOverlap,
}

impl RangeError {
    fn text(self) -> &'static str {
        match self {
            Self::Invalid => "invalid range",
            Self::NoOverlap => "invalid range: failed to overlap",
        }
    }
}

/// Parses a `bytes=` range header into the requested ranges.
fn parse_range(header: &str, size: u64) -> Result<Vec<HttpRange>, RangeError> {
    let Some(spec) = header.strip_prefix("bytes=") else {
        return if header.is_empty() { Ok(Vec::new()) } else { Err(RangeError::Invalid) };
    };
    let mut ranges = Vec::new();
    let mut no_overlap = false;
    for range in spec.split(',') {
        let range = range.trim_matches(|c: char| c.is_ascii_whitespace());
        if range.is_empty() {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            return Err(RangeError::Invalid);
        };
        let (start, end) = (start.trim(), end.trim());
        if start.is_empty() {
            let Ok(length) = end.parse::<i64>() else {
                return Err(RangeError::Invalid);
            };
            if length < 0 {
                return Err(RangeError::Invalid);
            }
            let length = length.unsigned_abs().min(size);
            ranges.push(HttpRange { start: size - length, length });
            continue;
        }
        let Ok(start) = start.parse::<i64>() else {
            return Err(RangeError::Invalid);
        };
        if start < 0 {
            return Err(RangeError::Invalid);
        }
        let start = start.unsigned_abs();
        if start >= size {
            no_overlap = true;
            continue;
        }
        let length = if end.is_empty() {
            size - start
        } else {
            let Ok(end) = end.parse::<i64>() else {
                return Err(RangeError::Invalid);
            };
            if end < 0 || start > end.unsigned_abs() {
                return Err(RangeError::Invalid);
            }
            end.unsigned_abs().min(size - 1) - start + 1
        };
        ranges.push(HttpRange { start, length });
    }
    if no_overlap && ranges.is_empty() {
        return Err(RangeError::NoOverlap);
    }
    Ok(ranges)
}

/// The 416 path: the unsatisfiable range keeps its `Content-Range` while the rest of the
/// response is the error text.
fn range_not_satisfiable(size: u64, err: RangeError) -> Response<RespBody> {
    let mut resp = serve_error_response(StatusCode::RANGE_NOT_SATISFIABLE, err.text());
    if err == RangeError::NoOverlap {
        let header_value = format!("bytes */{size}");
        if let Ok(header_value) = header_value.parse() {
            resp.headers_mut().insert(header::CONTENT_RANGE, header_value);
        }
    }
    resp
}

fn not_modified(last_modified: Option<&str>) -> Response<RespBody> {
    let mut builder = Response::builder().status(StatusCode::NOT_MODIFIED);
    if let Some(last_modified) = last_modified {
        builder = builder.header(header::LAST_MODIFIED, last_modified);
    }
    finish_response(builder, empty_body())
}

fn precondition_failed(last_modified: Option<&str>) -> Response<RespBody> {
    let mut builder = Response::builder().status(StatusCode::PRECONDITION_FAILED);
    if let Some(last_modified) = last_modified {
        builder = builder.header(header::LAST_MODIFIED, last_modified);
    }
    finish_response(builder, empty_body())
}

fn not_found() -> Response<RespBody> {
    serve_error_response(StatusCode::NOT_FOUND, "404 page not found")
}

fn serve_error_response(status: StatusCode, text: &str) -> Response<RespBody> {
    let mut body = text.to_owned();
    body.push('\n');
    response_with(
        status,
        &[
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::HeaderName::from_static("x-content-type-options"), "nosniff"),
        ],
        full_body(body.into_bytes()),
    )
}

/// The error path: the status is picked and the text written.
fn open_error_response(err: &std::io::Error) -> Response<RespBody> {
    let status = map_open_error(err);
    let text = if status == StatusCode::NOT_FOUND {
        "404 page not found"
    } else if status == StatusCode::FORBIDDEN {
        "403 Forbidden"
    } else {
        "500 Internal Server Error"
    };
    serve_error_response(status, text)
}

/// A redirect with a relative `Location`, preserving the query string.
fn local_redirect(req: &Req, new_path: &str) -> Response<RespBody> {
    let mut location = new_path.to_owned();
    if let Some(query) = req.uri().query() {
        if !query.is_empty() {
            location.push('?');
            location.push_str(query);
        }
    }
    Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, location)
        .body(empty_body())
        .unwrap_or_else(|_| status_only(StatusCode::INTERNAL_SERVER_ERROR))
}

/// Rejects an embedded NUL; on Windows it additionally rejects `:`, `\` and any reserved device
/// name per path element. Run on the already-cleaned, `/`-only path.
fn is_localizable(path: &str) -> bool {
    if path.contains('\0') {
        return false;
    }
    #[cfg(windows)]
    {
        if path.contains(':') || path.contains('\\') {
            return false;
        }
        for part in path.split('/') {
            if murmur_constant::path::is_reserved_name(part) {
                return false;
            }
        }
    }
    true
}

/// Percent-encodes only the bytes `HeaderValue` refuses (control bytes below `0x20` other than
/// tab, and `0x7F`); everything else, including multi-byte UTF-8 sequences, passes through raw
/// the way a redirect writes the base name into `Location` untouched. A directory
/// name cannot normally contain a control byte, but nothing stops a crafted UI archive entry from
/// having one, and building an invalid `HeaderValue` from it must not be able to panic the task.
fn escape_location_component(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    for &byte in s.as_bytes() {
        match byte {
            0x00..=0x08 | 0x0A..=0x1F | 0x7F => out.extend_from_slice(format!("%{byte:02X}").as_bytes()),
            _ => out.push(byte),
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_owned())
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "std::io::ErrorKind is #[non_exhaustive], so the remaining variants cannot be listed; every other kind answers the 500 returned here"
)]
fn map_open_error(err: &std::io::Error) -> StatusCode {
    match err.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Bounds the read by `len` (the file's size) instead of
/// reading to EOF, and streams frames instead of buffering the whole file, so a special file that
/// never reaches EOF (`/dev/zero`) cannot exhaust memory or hang the response.
fn stream_file_body(file: tokio::fs::File, len: u64) -> RespBody {
    let stream = ReaderStream::new(file.take(len)).filter_map(|chunk| {
        futures::future::ready(match chunk {
            Ok(bytes) => Some(Ok::<_, Infallible>(Frame::data(bytes))),
            Err(err) => {
                errorln!("serving ui file: {err}");
                None
            }
        })
    });
    BodyExt::boxed(StreamBody::new(stream))
}

async fn serve_connection<C>(conn: C, state: Arc<RouterState>, use_auto: bool)
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(conn);
    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let state = Arc::clone(&state);
        async move { Ok::<_, Infallible>(Box::pin(dispatch(req, state)).await) }
    });
    if use_auto {
        let builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        let _ = builder.serve_connection_with_upgrades(io, svc).await;
    } else {
        let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).with_upgrades().await;
    }
}

// cancel-safe: `RunningServer::close` sets `closed` and then aborts, so a drop at the pending
// accept abandons nothing but that accept.
async fn accept_loop(
    listener: Arc<dyn NetListener>,
    closed: Arc<AtomicBool>,
    state: Arc<RouterState>,
    use_auto: bool,
    error_prefix: &'static str,
) {
    loop {
        let conn = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                if closed.load(Ordering::SeqCst) {
                    break;
                }
                errorln!("{}: {}", error_prefix, err);
                continue;
            }
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move { serve_connection(conn, state, use_auto).await });
    }
}

async fn start(cfg: Arc<Config>) -> anyhow::Result<()> {
    let old = HTTP_SERVER.lock().take();
    if let Some(server) = old {
        server.close().await;
    }

    if cfg.addr.is_empty() {
        return Ok(());
    }

    let mut lc = new_listen_config();
    lc.set_route_mark(cfg.routing_mark);
    let ctx = CancellationToken::new();
    let l = match lc.listen(&ctx, "tcp", &cfg.addr).await {
        Ok(l) => l,
        Err(err) => {
            errorln!("External controller listen error: {}", err);
            return Err(anyhow!("external controller cannot bind {}: {err}", cfg.addr));
        }
    };
    infoln!("RESTful API listening at: {}", l.addr().map(|a| a.string()).unwrap_or_default());

    let listener: Arc<dyn NetListener> = Arc::from(l);
    let closed = Arc::new(AtomicBool::new(false));

    let state = Arc::new(RouterState::from_config(&cfg));
    let task = tokio::spawn(accept_loop(
        Arc::clone(&listener),
        Arc::clone(&closed),
        state,
        false,
        "External controller serve error",
    ));
    *HTTP_SERVER.lock() = Some(RunningServer { listener, closed, task });
    Ok(())
}

// cancel-safe: `TlsRunningServer::close` sets `closed` and then aborts, so a drop at the pending
// accept abandons nothing but that accept.
async fn tls_accept_loop(listener: Arc<dyn Acceptor>, closed: Arc<AtomicBool>, state: Arc<RouterState>) {
    loop {
        let stream = match listener.accept().await {
            Ok(stream) => stream,
            Err(err) => {
                if closed.load(Ordering::SeqCst) {
                    break;
                }
                errorln!("External controller tls serve error: {}", err);
                continue;
            }
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move { serve_connection(stream, state, true).await });
    }
}

async fn start_tls(cfg: Arc<Config>) -> anyhow::Result<()> {
    let old = TLS_SERVER.lock().take();
    if let Some(server) = old {
        server.close().await;
    }

    if cfg.tls_addr.is_empty() {
        return Ok(());
    }

    let cert_loader = match new_tls_key_pair_loader(&cfg.certificate, &cfg.private_key) {
        Ok(loader) => loader,
        Err(err) => {
            errorln!("External controller tls listen error: {}", err);
            return Err(anyhow!("external controller tls material is unusable: {err}"));
        }
    };

    let mut lc = new_listen_config();
    lc.set_route_mark(cfg.routing_mark);
    let ctx = CancellationToken::new();
    let l = match lc.listen(&ctx, "tcp", &cfg.tls_addr).await {
        Ok(l) => l,
        Err(err) => {
            errorln!("External controller tls listen error: {}", err);
            return Err(anyhow!("external controller cannot bind tls {}: {err}", cfg.tls_addr));
        }
    };
    infoln!("RESTful API tls listening at: {}", l.addr().map(|a| a.string()).unwrap_or_default());

    let Some(tls_config) = tls_config_for(&cfg, &cert_loader) else {
        return Err(anyhow!("external controller tls configuration is incomplete"));
    };

    let tls_listener: Arc<dyn Acceptor> =
        Arc::from(tls_new_listener(Arc::new(OldListenerAsAcceptor(l)), Arc::new(tls_config)));
    let closed = Arc::new(AtomicBool::new(false));

    let state = Arc::new(RouterState::from_config(&cfg));
    let task = tokio::spawn(tls_accept_loop(Arc::clone(&tls_listener), Arc::clone(&closed), state));
    *TLS_SERVER.lock() = Some(TlsRunningServer { listener: tls_listener, closed, task });
    Ok(())
}

/// The controller's TLS config: the defaults plus the certificate loader, the client-auth mode and
/// the ECH keys named by `cfg`. `None` is a failure the caller has already logged.
fn tls_config_for(cfg: &Config, cert_loader: &KeyPairLoader) -> Option<TlsConfig> {
    let TlsConfig {
        rand,
        certificates,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        server_name,
        client_cas,
        insecure_skip_verify,
        cipher_suites,
        session_tickets_disabled,
        min_version,
        max_version,
        curve_preferences,
        renegotiation,
        key_log_writer,
        encrypted_client_hello_config_list,
        encrypted_client_hello_rejection_verify,
        encrypted_client_hello_keys,
        get_encrypted_client_hello_keys,
        session_id_generator,
        ..
    } = TlsConfig::default();
    let cert_loader = Arc::clone(cert_loader);
    let mut tls_config = TlsConfig {
        rand,
        time: Some(Arc::new(murmur_ntp::time::now)),
        certificates,
        get_certificate: Some(Arc::new(move |_info| cert_loader().map(Some))),
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        next_protos: vec!["h2".to_owned(), "http/1.1".to_owned()],
        server_name,
        client_auth: client_auth_type_from_string(&cfg.client_auth_type),
        client_cas,
        insecure_skip_verify,
        cipher_suites,
        session_tickets_disabled,
        min_version,
        max_version,
        curve_preferences,
        renegotiation,
        key_log_writer,
        encrypted_client_hello_config_list,
        encrypted_client_hello_rejection_verify,
        encrypted_client_hello_keys,
        get_encrypted_client_hello_keys,
        session_id_generator,
    };
    if !cfg.client_auth_cert.is_empty() && tls_config.client_auth == NO_CLIENT_CERT {
        tls_config.client_auth = REQUIRE_AND_VERIFY_CLIENT_CERT;
    }
    if tls_config.client_auth == VERIFY_CLIENT_CERT_IF_GIVEN || tls_config.client_auth == REQUIRE_AND_VERIFY_CLIENT_CERT
    {
        match load_certificates(&cfg.client_auth_cert) {
            Ok(pool) => tls_config.client_cas = Some(pool),
            Err(err) => {
                errorln!("External controller tls listen error: {}", err);
                return None;
            }
        }
    }

    if !cfg.ech_key.is_empty() {
        if let Err(err) = load_ech_key(&cfg.ech_key, &mut tls_config) {
            errorln!("External controller tls serve error: {}", err);
            return None;
        }
    }

    Some(tls_config)
}

async fn start_unix(cfg: Arc<Config>) -> anyhow::Result<()> {
    let old = UNIX_SERVER.lock().take();
    if let Some(server) = old {
        server.close().await;
    }

    if cfg.unix_addr.is_empty() {
        return Ok(());
    }

    let addr = PATH.resolve(&cfg.unix_addr);
    if let Some(dir) = StdPath::new(&addr).parent() {
        if tokio::fs::metadata(dir).await.is_err() {
            if let Err(err) = tokio::fs::create_dir_all(dir).await {
                errorln!("External controller unix listen error: {}", err);
                return Err(anyhow!("external controller cannot create the unix socket directory: {err}"));
            }
        }
    }

    let _ = tokio::fs::remove_file(&addr).await;

    let mut lc = new_listen_config();
    lc.set_route_mark(0);
    let ctx = CancellationToken::new();
    let l = match lc.listen(&ctx, "unix", &addr).await {
        Ok(l) => l,
        Err(err) => {
            errorln!("External controller unix listen error: {}", err);
            return Err(anyhow!("external controller cannot bind unix {}: {err}", cfg.unix_addr));
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&addr, std::fs::Permissions::from_mode(0o666)).await;
    }
    infoln!("RESTful API unix listening at: {}", l.addr().map(|a| a.string()).unwrap_or_default());

    let listener: Arc<dyn NetListener> = Arc::from(l);
    let closed = Arc::new(AtomicBool::new(false));

    let state = Arc::new(RouterState::from_config(&cfg));
    let task = tokio::spawn(accept_loop(
        Arc::clone(&listener),
        Arc::clone(&closed),
        state,
        false,
        "External controller unix serve error",
    ));
    *UNIX_SERVER.lock() = Some(RunningServer { listener, closed, task });
    Ok(())
}

async fn start_pipe(cfg: Arc<Config>) -> anyhow::Result<()> {
    let old = PIPE_SERVER.lock().take();
    if let Some(server) = old {
        server.close().await;
    }

    if cfg.pipe_addr.is_empty() {
        return Ok(());
    }

    if !cfg.pipe_addr.starts_with(r"\\.\pipe\") {
        errorln!(r#"External controller pipe listen error: windows namedpipe must start with "\\.\pipe\""#);
        return Err(anyhow!("external controller pipe address is not a named pipe"));
    }

    let l = match listen_named_pipe(&cfg.pipe_addr) {
        Ok(l) => l,
        Err(err) => {
            errorln!("External controller pipe listen error: {}", err);
            return Err(anyhow!("external controller cannot open the pipe: {err}"));
        }
    };
    infoln!("RESTful API pipe listening at: {}", l.addr().map(|a| a.string()).unwrap_or_default());

    let listener: Arc<dyn NetListener> = Arc::from(l);
    let closed = Arc::new(AtomicBool::new(false));

    let state = Arc::new(RouterState::from_config(&cfg));
    let task = tokio::spawn(accept_loop(
        Arc::clone(&listener),
        Arc::clone(&closed),
        state,
        false,
        "External controller pipe serve error",
    ));
    *PIPE_SERVER.lock() = Some(RunningServer { listener, closed, task });
    Ok(())
}

/// Drives handlers over a real HTTP/1.1 connection: `Req` wraps `hyper::body::Incoming`, which
/// cannot be hand-built, the same reason `configs.rs`'s `patch_configs_over_http` opens a socket.
#[cfg(test)]
pub(crate) mod test_http {
    use std::future::Future;

    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::{Infallible, Req, RespBody, Response, StatusCode};

    pub(crate) struct RawResponse {
        pub(crate) status: StatusCode,
        pub(crate) headers: Vec<(String, String)>,
        pub(crate) body: Vec<u8>,
    }

    impl RawResponse {
        pub(crate) fn header(&self, name: &str) -> Option<&str> {
            self.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
        }

        pub(crate) fn body_text(&self) -> String {
            String::from_utf8_lossy(&self.body).into_owned()
        }
    }

    pub(crate) async fn exchange<F, Fut>(serve: F, request: &str) -> RawResponse
    where
        F: Fn(Req) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response<RespBody>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener has a local address");
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept loopback connection");
            let service = service_fn(move |req: Req| {
                let response = serve(req);
                async move { Ok::<_, Infallible>(response.await) }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(conn), service).await;
        });

        let mut stream = TcpStream::connect(addr).await.expect("connect to loopback listener");
        stream.write_all(request.as_bytes()).await.expect("write request");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        parse(&raw)
    }

    fn parse(raw: &[u8]) -> RawResponse {
        let split = raw.windows(4).position(|window| window == b"\r\n\r\n").expect("response head is terminated");
        let head = std::str::from_utf8(&raw[..split]).expect("response head is utf-8");
        let mut lines = head.split("\r\n");
        let status_line = lines.next().expect("status line");
        let status = StatusCode::from_bytes(status_line.split_whitespace().nth(1).expect("status code").as_bytes())
            .expect("valid status code");
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        RawResponse { status, headers, body: raw[split + 4..].to_vec() }
    }
}

/// `re_create_server` keeps the listeners in process-wide statics, and the next call closes
/// whatever the previous one installed — including the transports the new config does not name —
/// so no two callers may interleave. Every test that drives it holds this for its whole body: the
/// controller tests below, and the config-watch reload tests that run a full `hub::parse`.
#[cfg(test)]
pub(crate) static CONTROLLER_LISTENERS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::test_http::{exchange, RawResponse};
    use super::*;

    #[test]
    fn query_param_percent_and_plus_decodes_url_query_values() {
        assert_eq!(query_param("token=a%2Bb%2Fc", "token").as_deref(), Some("a+b/c"));
        assert_eq!(query_param("token=a+b", "token").as_deref(), Some("a b"));
        assert_eq!(query_param("format=structured", "format").as_deref(), Some("structured"));
        assert_eq!(query_param("token=", "token"), None);
        assert_eq!(query_param("", "token"), None);
    }

    struct UiFixture {
        root: PathBuf,
        outside_secret: PathBuf,
    }

    impl Drop for UiFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
            let _ = std::fs::remove_file(&self.outside_secret);
        }
    }

    fn build_ui_fixture(name: &str) -> UiFixture {
        let root = std::env::temp_dir().join(format!("murmur-serve-ui-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("assets")).expect("create ui root");
        std::fs::write(root.join("index.html"), b"ROOT_INDEX").expect("write index.html");
        std::fs::write(root.join("assets").join("app.js"), b"console.log(1)").expect("write asset");

        let outside_secret = root.parent().unwrap().join(format!("murmur-outside-secret-{name}.txt"));
        std::fs::write(&outside_secret, b"SECRET_OUTSIDE_UI_ROOT").expect("write outside secret");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_secret, root.join("escape-link")).expect("create symlink");

        UiFixture { root, outside_secret }
    }

    /// `rest` is what `dispatch_inner` strips off `/ui/`, so a request target and the serving rest
    /// are passed separately.
    async fn ui_request(
        fixture: &UiFixture,
        rest: &'static str,
        method: &str,
        target: &str,
        extra: &str,
    ) -> RawResponse {
        let root = fixture.root.to_str().expect("fixture root is utf-8").to_owned();
        let request = format!("{method} {target} HTTP/1.1\r\nHost: test\r\n{extra}Connection: close\r\n\r\n");
        let serve = move |req: Req| {
            let root = root.clone();
            async move { serve_ui_file(&root, &req, rest).await }
        };
        exchange(serve, &request).await
    }

    fn last_modified(resp: &RawResponse) -> String {
        resp.header("last-modified").expect("served with Last-Modified").to_owned()
    }

    #[tokio::test]
    async fn serve_ui_file_serves_root_index_and_nested_asset() {
        let fixture = build_ui_fixture("legit");

        let resp = ui_request(&fixture, "", "GET", "/ui/", "").await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, b"ROOT_INDEX");

        let resp = ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", "").await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.header("content-type"), Some("text/javascript; charset=utf-8"));
        assert_eq!(resp.header("content-length"), Some("14"));
        assert_eq!(resp.header("accept-ranges"), Some("bytes"));
        assert!(last_modified(&resp).ends_with("GMT"));
        assert_eq!(resp.body, b"console.log(1)");
    }

    #[tokio::test]
    async fn serve_ui_file_redirects_index_html_to_the_directory_url() {
        let fixture = build_ui_fixture("index-redirect");

        let resp = ui_request(&fixture, "index.html", "GET", "/ui/index.html", "").await;
        assert_eq!(resp.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(resp.header("location"), Some("./"));
    }

    #[tokio::test]
    async fn serve_ui_file_answers_a_conditional_get_with_304() {
        let fixture = build_ui_fixture("conditional");
        let modified = last_modified(&ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", "").await);

        let resp = ui_request(
            &fixture,
            "assets/app.js",
            "GET",
            "/ui/assets/app.js",
            &format!("If-Modified-Since: {modified}\r\n"),
        )
        .await;
        assert_eq!(resp.status, StatusCode::NOT_MODIFIED);
        assert_eq!(resp.header("last-modified"), Some(modified.as_str()));
        assert_eq!(resp.header("content-type"), None);
        assert!(resp.body.is_empty());

        let resp = ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", "If-None-Match: *\r\n").await;
        assert_eq!(resp.status, StatusCode::NOT_MODIFIED);

        let resp =
            ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", "If-Modified-Since: bogus\r\n").await;
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn serve_ui_file_rejects_a_failed_precondition_with_412() {
        let fixture = build_ui_fixture("precondition");

        let resp = ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", "If-Match: \"stale\"\r\n").await;
        assert_eq!(resp.status, StatusCode::PRECONDITION_FAILED);

        let resp = ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", "If-Match: *\r\n").await;
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn serve_ui_file_serves_a_single_range_as_206() {
        let fixture = build_ui_fixture("range");

        let resp = ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", "Range: bytes=0-6\r\n").await;
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.header("content-range"), Some("bytes 0-6/14"));
        assert_eq!(resp.header("content-length"), Some("7"));
        assert_eq!(resp.body, b"console");

        let resp = ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", "Range: bytes=-3\r\n").await;
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.header("content-range"), Some("bytes 11-13/14"));
        assert_eq!(resp.body, b"(1)");

        let resp = ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", "Range: bytes=5-\r\n").await;
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.header("content-range"), Some("bytes 5-13/14"));
        assert_eq!(resp.body, b"le.log(1)");
    }

    #[tokio::test]
    async fn serve_ui_file_rejects_an_unsatisfiable_range_with_416() {
        let fixture = build_ui_fixture("range-416");

        let resp = ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", "Range: bytes=99-\r\n").await;
        assert_eq!(resp.status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(resp.header("content-range"), Some("bytes */14"));
        assert_eq!(resp.body_text(), "invalid range: failed to overlap\n");

        let resp = ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", "Range: bytes=abc\r\n").await;
        assert_eq!(resp.status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(resp.header("content-range"), None);
        assert_eq!(resp.body_text(), "invalid range\n");
    }

    #[tokio::test]
    async fn serve_ui_file_answers_head_with_headers_and_no_body() {
        let fixture = build_ui_fixture("head");

        let resp = ui_request(&fixture, "assets/app.js", "HEAD", "/ui/assets/app.js", "").await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.header("content-type"), Some("text/javascript; charset=utf-8"));
        assert_eq!(resp.header("content-length"), Some("14"));
        assert!(resp.body.is_empty());

        let resp = ui_request(&fixture, "assets/app.js", "HEAD", "/ui/assets/app.js", "Range: bytes=0-6\r\n").await;
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.header("content-range"), Some("bytes 0-6/14"));
        assert!(resp.body.is_empty());
    }

    #[tokio::test]
    async fn serve_ui_file_redirects_a_file_asked_for_with_a_trailing_slash() {
        let fixture = build_ui_fixture("file-slash");

        let resp = ui_request(&fixture, "assets/app.js/", "GET", "/ui/assets/app.js/", "").await;
        assert_eq!(resp.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(resp.header("location"), Some("../app.js"));
    }

    #[tokio::test]
    async fn serve_ui_file_honours_if_range_before_a_range() {
        let fixture = build_ui_fixture("if-range");
        let modified = last_modified(&ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", "").await);

        let matching = format!("Range: bytes=0-6\r\nIf-Range: {modified}\r\n");
        let resp = ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", &matching).await;
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.header("content-range"), Some("bytes 0-6/14"));

        let stale = "Range: bytes=0-6\r\nIf-Range: \"stale\"\r\n";
        let resp = ui_request(&fixture, "assets/app.js", "GET", "/ui/assets/app.js", stale).await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.header("content-range"), None);
        assert_eq!(resp.body, b"console.log(1)");
    }

    #[tokio::test]
    async fn serve_ui_file_refuses_double_slash_absolute_escape() {
        let fixture = build_ui_fixture("double-slash");

        // `GET /ui//etc/passwd` -> dispatch strips literal "/ui/", leaving this as `rest`.
        let resp = ui_request(&fixture, "/etc/passwd", "GET", "/ui//etc/passwd", "").await;
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
        assert_eq!(resp.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(resp.body_text(), "404 page not found\n");
    }

    #[tokio::test]
    async fn serve_ui_file_refuses_percent_encoded_dotdot_escape() {
        let fixture = build_ui_fixture("percent-dotdot");

        // `GET /ui/..%2F..%2F..%2Fetc%2Fpasswd`.
        let resp =
            ui_request(&fixture, "..%2F..%2F..%2Fetc%2Fpasswd", "GET", "/ui/..%2F..%2F..%2Fetc%2Fpasswd", "").await;
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn serve_ui_file_dotdot_segments_never_escape_root() {
        let fixture = build_ui_fixture("dotdot-segment");
        let secret = std::fs::read(&fixture.outside_secret).unwrap();

        for (rest, target) in [("%2e%2e/", "/ui/%2e%2e/"), ("..%2F", "/ui/..%2F"), ("../../../", "/ui/../../../")] {
            let resp = ui_request(&fixture, rest, "GET", target, "").await;
            assert_ne!(resp.body, secret, "rest {rest:?} must never disclose the outside secret");
            if resp.status == StatusCode::OK {
                assert_eq!(resp.body, b"ROOT_INDEX", "rest {rest:?} landed on root, must serve the safe index");
            } else {
                assert_eq!(resp.status, StatusCode::NOT_FOUND, "rest {rest:?} unexpected status");
            }
        }
    }

    #[tokio::test]
    async fn serve_ui_file_refuses_embedded_nul() {
        let fixture = build_ui_fixture("nul");

        let resp = ui_request(&fixture, "index.html%00.png", "GET", "/ui/index.html%00.png", "").await;
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn serve_ui_file_treats_literal_backslashes_as_an_ordinary_filename_character_on_unix() {
        let fixture = build_ui_fixture("backslash");

        let resp = ui_request(&fixture, r"..\..\..\etc\passwd", "GET", "/ui/..%5C..%5C..%5Cetc%5Cpasswd", "").await;
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn serve_ui_file_follows_a_symlink_pointing_outside_root() {
        let fixture = build_ui_fixture("symlink");

        let resp = ui_request(&fixture, "escape-link", "GET", "/ui/escape-link", "").await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, b"SECRET_OUTSIDE_UI_ROOT");
    }

    #[tokio::test]
    async fn serve_ui_file_redirects_a_directory_missing_its_trailing_slash() {
        let fixture = build_ui_fixture("dir-redirect");
        std::fs::write(fixture.root.join("assets").join("index.html"), b"ASSETS_INDEX").unwrap();

        let resp = ui_request(&fixture, "assets", "GET", "/ui/assets", "").await;
        assert_eq!(resp.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(resp.header("location"), Some("assets/"));

        let resp = ui_request(&fixture, "assets/", "GET", "/ui/assets/", "").await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, b"ASSETS_INDEX");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn serve_ui_file_redirect_survives_a_control_byte_in_the_directory_name() {
        let fixture = build_ui_fixture("ctl-redirect");
        std::fs::create_dir(fixture.root.join("dir\u{1}name")).expect("create dir with control byte in its name");

        let resp = ui_request(&fixture, "dir%01name", "GET", "/ui/dir%01name", "").await;
        assert_eq!(resp.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(resp.header("location"), Some("dir%01name/"));
    }

    fn router_state(is_debug: bool) -> Arc<RouterState> {
        Arc::new(RouterState::from_config(&Config { is_debug, ..Config::default() }))
    }

    #[tokio::test]
    async fn dispatch_serves_the_pprof_index_only_in_debug_mode() {
        let state = router_state(true);
        let resp = exchange(
            move |req| {
                let state = Arc::clone(&state);
                async move { dispatch(req, state).await }
            },
            "GET /debug/pprof/ HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.header("content-type"), Some("text/html; charset=utf-8"));
        assert_eq!(
            resp.header("cache-control"),
            Some("no-cache, no-store, no-transform, must-revalidate, private, max-age=0")
        );
        assert!(resp.body_text().contains("Types of profiles available:"));

        let state = router_state(false);
        let resp = exchange(
            move |req| {
                let state = Arc::clone(&state);
                async move { dispatch(req, state).await }
            },
            "GET /debug/pprof/ HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn dispatch_keeps_debug_gc_off_the_pprof_no_cache_headers() {
        let state = router_state(true);
        let put = exchange(
            move |req| {
                let state = Arc::clone(&state);
                async move { dispatch(req, state).await }
            },
            "PUT /debug/gc HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(put.status, StatusCode::OK);
        assert_eq!(put.header("cache-control"), None);

        let state = router_state(true);
        let get = exchange(
            move |req| {
                let state = Arc::clone(&state);
                async move { dispatch(req, state).await }
            },
            "GET /debug/gc HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert_eq!(get.status, StatusCode::METHOD_NOT_ALLOWED);
    }

    /// One raw `GET` on an established connection: the status code and the whole response.
    async fn get_on<S>(stream: &mut S, target: &str, secret: Option<&str>) -> (u16, String)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let auth = secret.map(|token| format!("Authorization: Bearer {token}\r\n")).unwrap_or_default();
        let request = format!("GET {target} HTTP/1.1\r\nHost: test\r\n{auth}Connection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.expect("write request");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        let head = String::from_utf8_lossy(&raw).into_owned();
        let status = head.split_whitespace().nth(1).expect("status code").parse().expect("numeric status");
        (status, head)
    }

    /// [`get_on`] against whatever `re_create_server` most recently installed on `addr`, waiting
    /// for the accept loop to bind.
    async fn controller_response(addr: &str, target: &str, secret: Option<&str>) -> (u16, String) {
        use std::time::Duration;

        for _ in 0..500 {
            if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
                return get_on(&mut stream, target, secret).await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no external controller answered {target} on {addr}");
    }

    /// [`get_on`] against the Unix listener, which has no credential of its own.
    #[cfg(unix)]
    async fn unix_response(socket: &str, target: &str, secret: Option<&str>) -> (u16, String) {
        use std::time::Duration;

        for _ in 0..500 {
            if let Ok(mut stream) = tokio::net::UnixStream::connect(socket).await {
                return get_on(&mut stream, target, secret).await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no external controller answered {target} on the unix socket {socket}");
    }

    /// A reload (`SIGHUP` → `hub::parse`) runs `re_create_server` again on the same address: the
    /// new listener must not find the port still held by the previous one, and the reloaded config
    /// must be the one answering.
    #[tokio::test]
    async fn re_create_server_rebinds_the_same_port_and_serves_the_reloaded_config() {
        let _guard = CONTROLLER_LISTENERS.lock().await;

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("probe a free loopback port");
        let addr = probe.local_addr().expect("probe local address").to_string();
        drop(probe);

        re_create_server(Arc::new(Config { addr: addr.clone(), ..Config::default() }))
            .await
            .expect("the test controller must start");
        let (status, body) = controller_response(&addr, "/version", None).await;
        assert_eq!(status, 200, "the first server did not answer: {body}");
        assert!(body.contains("\"version\""), "unexpected /version body: {body}");

        let cfg = Arc::new(Config { addr: addr.clone(), secret: "reload-secret".to_owned(), ..Config::default() });
        re_create_server(cfg).await.expect("the reloaded test controller must start");

        let (status, body) = controller_response(&addr, "/version", None).await;
        assert_eq!(status, 401, "something other than the reloaded server is listening: {body}");
        let (status, body) = controller_response(&addr, "/version", Some("reload-secret")).await;
        assert_eq!(status, 200, "the reloaded server did not answer: {body}");
    }

    /// The reload rebuilds the router from the new config; a config that no longer names
    /// `external-ui` must unmount `/ui` instead of keeping the root the previous one named.
    #[tokio::test]
    async fn re_create_server_unmounts_the_ui_root_when_the_reloaded_config_clears_it() {
        let _guard = CONTROLLER_LISTENERS.lock().await;
        let fixture = build_ui_fixture("reload-unmount");
        let ui_root = fixture.root.to_str().expect("fixture root is utf-8").to_owned();

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("probe a free loopback port");
        let addr = probe.local_addr().expect("probe local address").to_string();
        drop(probe);

        re_create_server(Arc::new(Config { addr: addr.clone(), ui_path: ui_root, ..Config::default() }))
            .await
            .expect("the test controller must start");
        let (status, body) = controller_response(&addr, "/ui/", None).await;
        assert_eq!(status, 200, "the configured ui root did not serve: {body}");
        assert!(body.ends_with("ROOT_INDEX"), "unexpected /ui/ body: {body}");

        re_create_server(Arc::new(Config { addr: addr.clone(), ..Config::default() }))
            .await
            .expect("the test controller must start");
        let (status, body) = controller_response(&addr, "/ui/", None).await;
        assert_eq!(status, 404, "the reloaded config still serves the root it dropped: {body}");
        assert!(body.ends_with("404 page not found\n"), "unexpected /ui/ body: {body}");
    }

    /// The Unix socket carries no credential of its own, so the configured secret is the only
    /// thing between a local user and the whole API there, and the Windows pipe listener serves
    /// from the same state. The socket is bound here because `start_unix`'s `listen("unix", …)`
    /// is refused by the component listen config ("unknown network unix").
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_controller_requires_the_configured_secret() {
        let socket = std::env::temp_dir().join(format!("murmur-ctl-secret-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind the unix socket");
        let socket_path = socket.to_str().expect("a utf-8 temp path").to_owned();

        let state =
            Arc::new(RouterState::from_config(&Config { secret: "unix-secret".to_owned(), ..Config::default() }));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = Arc::clone(&state);
                tokio::spawn(async move { serve_connection(stream, state, false).await });
            }
        });

        let (status, body) = unix_response(&socket_path, "/version", None).await;
        assert_eq!(status, 401, "the unix controller served the API without a credential: {body}");

        let (status, body) = unix_response(&socket_path, "/version", Some("wrong-secret")).await;
        assert_eq!(status, 401, "the unix controller accepted a credential it was not given: {body}");

        let (status, body) = unix_response(&socket_path, "/version", Some("unix-secret")).await;
        assert_eq!(status, 200, "the unix controller rejected the configured secret: {body}");
        assert!(body.contains("\"version\""), "unexpected /version body: {body}");

        let _ = std::fs::remove_file(&socket);
    }

    /// Every listener builds its router state with [`RouterState::from_config`], including the
    /// Windows pipe mount no test on this host can bind.
    #[test]
    fn the_controller_state_carries_the_configured_secret() {
        let state = RouterState::from_config(&Config { secret: "state-secret".to_owned(), ..Config::default() });
        assert_eq!(state.secret, "state-secret");
        assert!(RouterState::from_config(&Config::default()).secret.is_empty());
    }
}

/// Wire-shape checks for the routes this file owns.
#[cfg(test)]
mod wire_parity_tests {
    use super::test_http::{exchange, RawResponse};
    use super::*;

    async fn request(request_line: &str) -> RawResponse {
        let state = Arc::new(RouterState::from_config(&Config::default()));
        exchange(
            move |req| {
                let state = Arc::clone(&state);
                async move { dispatch(req, state).await }
            },
            request_line,
        )
        .await
    }

    fn get(path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
    }

    fn methods<'a>(resp: &'a RawResponse, name: &str) -> Vec<&'a str> {
        resp.headers.iter().filter(|(key, _)| key == name).map(|(_, value)| value.as_str()).collect()
    }

    /// Route bodies end in a trailing newline and use a bare `application/json` content type.
    #[tokio::test]
    async fn json_route_bodies_are_encoder_terminated_with_json_content_type() {
        let resp = request(&get("/version")).await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.header("content-type"), Some("application/json"));

        let body = resp.body_text();
        assert!(body.ends_with("}\n"), "{body:?}");
        assert_eq!(resp.header("content-length"), Some(body.len().to_string().as_str()));
    }

    /// `Vary: Origin` is set before the header is inspected, so every response carries it,
    /// including a 404 and a request that sent no `Origin`.
    #[tokio::test]
    async fn vary_origin_is_on_every_response() {
        for line in [get("/version"), get("/not-a-route")] {
            let resp = request(&line).await;
            assert_eq!(resp.header("vary"), Some("Origin"), "{line}");
        }
    }

    /// `GET` routes answer 405 with `Allow: GET`; the connections sub-router is registered for
    /// its own `GET` and `DELETE`.
    #[tokio::test]
    async fn non_get_methods_on_the_stream_routes_are_405_with_allow() {
        for path in ["/traffic", "/logs", "/memory", "/version"] {
            let resp = request(&format!("POST {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")).await;
            assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
            assert_eq!(methods(&resp, "allow"), ["GET"], "{path}");
        }

        let resp = request("DELETE /logs HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").await;
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(methods(&resp, "allow"), ["GET"]);

        let resp = request("PUT /connections HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").await;
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(methods(&resp, "allow"), ["GET", "DELETE"]);
    }

    /// A trailing slash is a 404 on the plain routes, while `/connections/` still reaches the
    /// mounted sub-router's own `/` route.
    #[tokio::test]
    async fn a_trailing_slash_is_only_accepted_on_mounted_routes() {
        for path in
            ["/traffic/", "/logs/", "/memory/", "/version/", "/dns/query/", "/storage/key/", "/connections/abc/"]
        {
            let resp = request(&get(path)).await;
            assert_eq!(resp.status, StatusCode::NOT_FOUND, "{path}");
        }

        let resp = request(&get("/connections/")).await;
        assert_eq!(resp.status, StatusCode::OK);
        assert!(resp.body_text().ends_with("}\n"), "{:?}", resp.body_text());
    }

    /// A trailing slash is dropped only at a mount boundary: the sub-router's own root, and each
    /// nested route pattern that the sub-router does not trim itself. Anywhere else it stays
    /// a different, unmatched path.
    #[test]
    fn a_trailing_slash_is_absorbed_only_at_a_mount_boundary() {
        assert!(mount_rest(&[""], 1).is_empty(), "the mount's own slash form is the sub-router root");
        assert_eq!(mount_rest(&["COMPATIBLE", ""], 1), &["COMPATIBLE"][..]);
        assert_eq!(mount_rest(&["COMPATIBLE"], 1), &["COMPATIBLE"][..]);
        assert_eq!(mount_rest(&["COMPATIBLE", "delay", ""], 1), &["COMPATIBLE", "delay", ""][..]);
        assert_eq!(mount_rest(&["abc", ""], 0), &["abc", ""][..], "connections has no nested mount");
        assert_eq!(
            mount_rest(&["default", "healthcheck", ""], 0),
            &["default", "healthcheck", ""][..],
            "provider.rs trims its own nested mounts, so the dispatcher must hand it the raw tail"
        );
        assert!(mount_rest(&[""], 0).is_empty());
    }

    /// An unmatched path answers the plain 404 page rather than an empty body.
    #[tokio::test]
    async fn unmatched_paths_answer_the_plain_404_page() {
        for path in ["/not-a-route", "/traffic/", "//traffic"] {
            let resp = request(&get(path)).await;
            assert_eq!(resp.status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(resp.body_text(), "404 page not found\n", "{path}");
            assert_eq!(resp.header("content-type"), Some("text/plain; charset=utf-8"), "{path}");
            assert_eq!(resp.header("x-content-type-options"), Some("nosniff"), "{path}");
        }
    }
}

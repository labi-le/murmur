use std::collections::HashMap;
use std::pin::Pin;

use anyhow::anyhow;
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use rand::Rng;
use tokio::io::AsyncRead;

use murmur_common_httputils::force_close;

pub const PLACEMENT_QUERY_IN_HEADER: &str = "queryInHeader";
pub const PLACEMENT_COOKIE: &str = "cookie";
pub const PLACEMENT_HEADER: &str = "header";
pub const PLACEMENT_QUERY: &str = "query";
pub const PLACEMENT_PATH: &str = "path";
pub const PLACEMENT_BODY: &str = "body";
pub const PLACEMENT_AUTO: &str = "auto";

/// A request, narrowed to the fields and methods this crate uses.
///
/// `Header`/`Cookie` manipulation goes through the helpers below rather than a separate cookie
/// jar, since cookies live in the `Cookie`/`Set-Cookie` headers.
pub struct Request {
    pub method: String,
    pub url: url::Url,
    pub host: String,
    pub header: http::HeaderMap,
    pub body: Option<RequestBody>,
    pub content_length: i64,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            method: String::new(),
            url: default_url(),
            host: String::new(),
            header: http::HeaderMap::new(),
            body: None,
            content_length: 0,
        }
    }
}

#[expect(clippy::expect_used, reason = "the placeholder URL is a constant that always parses")]
fn default_url() -> url::Url {
    url::Url::parse("http://localhost/").expect("static URL")
}

pub enum RequestBody {
    Bytes(Bytes),
    Stream(Pin<Box<dyn AsyncRead + Send>>),
}

impl std::fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes(b) => f.debug_tuple("Bytes").field(&b.len()).finish(),
            Self::Stream(_) => f.debug_tuple("Stream").finish(),
        }
    }
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("host", &self.host)
            .field("header", &self.header)
            .field("body", &self.body)
            .field("content_length", &self.content_length)
            .finish()
    }
}

/// A cookie, narrowed to name and value.
#[derive(Clone, Debug)]
pub struct Cookie {
    pub name: String,
    pub value: String,
}

impl Request {
    pub fn add_cookie(&mut self, cookie: &Cookie) {
        add_cookie_header(&mut self.header, cookie);
    }

    pub fn cookie(&self, name: &str) -> Option<Cookie> {
        cookie_header(&self.header, name).map(|value| Cookie { name: name.to_owned(), value })
    }
}

/// Appends `name=value` to the existing `Cookie` header.
pub fn add_cookie_header(header: &mut http::HeaderMap, cookie: &Cookie) {
    let pair = format!("{}={}", cookie.name, cookie.value);
    let existing = header.get(http::header::COOKIE).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let combined = match existing {
        Some(existing) if !existing.is_empty() => format!("{existing}; {pair}"),
        _ => pair,
    };
    if let Ok(value) = http::HeaderValue::from_str(&combined) {
        header.insert(http::header::COOKIE, value);
    }
}

/// Reads `name=value` out of the `Cookie` header.
pub fn cookie_header(header: &http::HeaderMap, name: &str) -> Option<String> {
    let raw = header.get(http::header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k == name {
                return Some(v.to_owned());
            }
        }
    }
    None
}

pub fn set_response_cookie(header: &mut http::HeaderMap, name: &str, value: &str, path: &str) {
    let raw = format!("{name}={value}; Path={path}");
    if let Ok(header_value) = http::HeaderValue::from_str(&raw) {
        header.append(http::header::SET_COOKIE, header_value);
    }
}

/// A response, narrowed to the fields this crate uses.
pub struct Response {
    pub status_code: u16,
    pub status: String,
    pub header: http::HeaderMap,
    pub body: Pin<Box<dyn AsyncRead + Send>>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status_code", &self.status_code)
            .field("status", &self.status)
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

/// The round-trip surface. `force_close::RoundTripper` is a supertrait so
/// `httputils::close_transport` can be called on any `dyn RoundTripper` through trait upcasting.
#[async_trait]
pub trait RoundTripper: force_close::RoundTripper {
    async fn round_trip(&self, req: Request) -> anyhow::Result<Response>;

    /// Not part of the round-trip surface: this crate dials its own connections rather than
    /// using an opaque transport, so `Client::dial_stream_one`/`dial_stream_up`/
    /// `dial_packet_up` call this to observe "TCP connected" directly instead of racing on a
    /// trace hook. The default is a no-op for transports (like
    /// `ReuseTransport`) that only forward to another `RoundTripper`.
    async fn ensure_connected(&self, _ctx: tokio_util::sync::CancellationToken) -> anyhow::Result<()> {
        Ok(())
    }

    /// Not part of the round-trip surface either: `Client::dial_stream_one`/`dial_stream_up`/
    /// `dial_packet_up` use it after [`Self::ensure_connected`] to fill `Conn`'s `NetAddr` with
    /// the connected socket's peer address.
    fn peer_addr(&self) -> Option<(Box<dyn murmur_std_compat::net::Addr>, Box<dyn murmur_std_compat::net::Addr>)> {
        None
    }

    /// Type assertions on a round-tripper trait object, the analogue of a runtime type switch.
    fn as_any(&self) -> &dyn std::any::Any;
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub host: String,
    pub path: String,
    pub mode: String,
    pub headers: HashMap<String, String>,
    pub no_grpc_header: bool,
    pub x_padding_bytes: String,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_placement: String,
    pub x_padding_method: String,
    pub uplink_http_method: String,
    pub session_placement: String,
    pub session_key: String,
    pub session_table: String,
    pub session_length: String,
    pub seq_placement: String,
    pub seq_key: String,
    pub uplink_data_placement: String,
    pub uplink_data_key: String,
    pub uplink_chunk_size: String,
    pub no_sse_header: bool,
    pub sc_stream_up_server_secs: String,
    pub sc_max_buffered_posts: String,
    pub sc_max_each_post_bytes: String,
    pub sc_min_posts_interval_ms: String,
    pub reuse_config: Option<Box<ReuseConfig>>,
    pub download_config: Option<Box<Self>>,
}

#[derive(Clone, Debug, Default)]
pub struct ReuseConfig {
    pub max_concurrency: String,
    pub max_connections: String,
    pub c_max_reuse_times: String,
    pub h_max_request_times: String,
    pub h_max_reusable_secs: String,
}

impl Config {
    #[must_use]
    pub fn normalized_mode(&self) -> String {
        if self.mode.is_empty() {
            "auto".to_owned()
        } else {
            self.mode.clone()
        }
    }

    #[must_use]
    pub fn effective_mode(&self, has_reality: bool) -> String {
        let mode = self.normalized_mode();
        if mode != "auto" {
            return mode;
        }
        if has_reality {
            if self.download_config.is_some() {
                return "stream-up".to_owned();
            }
            return "stream-one".to_owned();
        }
        "packet-up".to_owned()
    }

    #[must_use]
    pub fn normalized_path(&self) -> String {
        let mut path = self.path.clone();
        if path.is_empty() {
            "/".clone_into(&mut path);
        }
        if !path.starts_with('/') {
            path = format!("/{path}");
        }
        if (self.normalized_session_placement() == PLACEMENT_PATH || self.normalized_seq_placement() == PLACEMENT_PATH)
            && !path.ends_with('/')
        {
            path.push('/');
        }
        path
    }

    #[must_use]
    pub fn request_header(&self) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in &self.headers {
            if let (Ok(name), Ok(value)) = (http::HeaderName::from_bytes(k.as_bytes()), http::HeaderValue::from_str(v))
            {
                h.insert(name, value);
            }
        }
        super::browser::try_default_headers_with(&mut h, "fetch");
        h
    }

    #[must_use]
    pub fn request_header_with_payload(&self, payload: &[u8], uplink_chunk_size: Range) -> http::HeaderMap {
        let mut header = self.request_header();
        let key = &self.uplink_data_key;
        let mut encoded_data = URL_SAFE_NO_PAD.encode(payload);

        let mut i: i64 = 0;
        while !encoded_data.is_empty() {
            let mut chunk_size = usize::try_from(uplink_chunk_size.rand().max(0)).unwrap_or(usize::MAX);
            if encoded_data.len() < chunk_size {
                chunk_size = encoded_data.len();
            }
            let chunk: String = encoded_data.drain(..chunk_size).collect();
            let header_key = format!("{key}-{i}");
            if let (Ok(name), Ok(value)) =
                (http::HeaderName::from_bytes(header_key.as_bytes()), http::HeaderValue::from_str(&chunk))
            {
                header.insert(name, value);
            }
            i += 1;
        }

        header
    }

    #[must_use]
    pub fn request_cookies_with_payload(&self, payload: &[u8], uplink_chunk_size: Range) -> Vec<Cookie> {
        let mut cookies = Vec::new();
        let key = &self.uplink_data_key;
        let mut encoded_data = URL_SAFE_NO_PAD.encode(payload);

        let mut i: i64 = 0;
        while !encoded_data.is_empty() {
            let mut chunk_size = usize::try_from(uplink_chunk_size.rand().max(0)).unwrap_or(usize::MAX);
            if encoded_data.len() < chunk_size {
                chunk_size = encoded_data.len();
            }
            let chunk: String = encoded_data.drain(..chunk_size).collect();
            cookies.push(Cookie { name: format!("{key}_{i}"), value: chunk });
            i += 1;
        }

        cookies
    }

    /// Writes the response header. Narrowed to the response header map: only the response
    /// headers are written, never a status line or body.
    pub fn write_response_header(
        &self,
        response_header: &mut http::HeaderMap,
        request_method: &str,
        request_header: &http::HeaderMap,
    ) {
        let origin = request_header.get(http::header::ORIGIN).and_then(|v| v.to_str().ok()).unwrap_or("");
        if origin.is_empty() {
            response_header.insert("access-control-allow-origin", http::HeaderValue::from_static("*"));
        } else if let Ok(value) = http::HeaderValue::from_str(origin) {
            response_header.insert("access-control-allow-origin", value);
        }

        if self.normalized_session_placement() == PLACEMENT_COOKIE
            || self.normalized_seq_placement() == PLACEMENT_COOKIE
            || self.x_padding_placement == PLACEMENT_COOKIE
            || self.normalized_uplink_data_placement() == PLACEMENT_COOKIE
        {
            response_header.insert("access-control-allow-credentials", http::HeaderValue::from_static("true"));
        }

        if request_method == "OPTIONS" {
            let requested_method =
                request_header.get("access-control-request-method").and_then(|v| v.to_str().ok()).unwrap_or("");
            if requested_method.is_empty() {
                response_header.insert("access-control-allow-methods", http::HeaderValue::from_static("*"));
            } else if let Ok(value) = http::HeaderValue::from_str(requested_method) {
                response_header.insert("access-control-allow-methods", value);
            }

            let requested_headers =
                request_header.get("access-control-request-headers").and_then(|v| v.to_str().ok()).unwrap_or("");
            if requested_headers.is_empty() {
                response_header.insert("access-control-allow-headers", http::HeaderValue::from_static("*"));
            } else if let Ok(value) = http::HeaderValue::from_str(requested_headers) {
                response_header.insert("access-control-allow-headers", value);
            }
        }
    }

    #[must_use]
    pub fn normalized_uplink_http_method(&self) -> String {
        if self.uplink_http_method.is_empty() {
            "POST".to_owned()
        } else {
            self.uplink_http_method.clone()
        }
    }

    pub fn normalized_sc_stream_up_server_secs(&self) -> anyhow::Result<Range> {
        parse_range(&self.sc_stream_up_server_secs, "20-80")
            .map_err(|e| anyhow!("invalid sc-stream-up-server-secs: {e}"))
    }

    pub fn normalized_sc_max_buffered_posts(&self) -> anyhow::Result<Range> {
        let r = parse_range(&self.sc_max_buffered_posts, "30")
            .map_err(|e| anyhow!("invalid sc-max-buffered-posts: {e}"))?;
        if r.max == 0 {
            return Err(anyhow!("invalid sc-max-buffered-posts: must be greater than zero"));
        }
        Ok(r)
    }

    pub fn normalized_sc_max_each_post_bytes(&self) -> anyhow::Result<Range> {
        let r = parse_range(&self.sc_max_each_post_bytes, "1000000")
            .map_err(|e| anyhow!("invalid sc-max-each-post-bytes: {e}"))?;
        if r.max == 0 {
            return Err(anyhow!("invalid sc-max-each-post-bytes: must be greater than zero"));
        }
        Ok(r)
    }

    pub fn normalized_sc_min_posts_interval_ms(&self) -> anyhow::Result<Range> {
        let r = parse_range(&self.sc_min_posts_interval_ms, "30")
            .map_err(|e| anyhow!("invalid sc-min-posts-interval-ms: {e}"))?;
        if r.max == 0 {
            return Err(anyhow!("invalid sc-min-posts-interval-ms: must be greater than zero"));
        }
        Ok(r)
    }

    pub fn normalized_uplink_chunk_size(&self) -> anyhow::Result<Range> {
        let mut uplink_chunk_size =
            parse_range(&self.uplink_chunk_size, "0").map_err(|e| anyhow!("invalid uplink-chunk-size: {e}"))?;
        if uplink_chunk_size.max == 0 {
            return match self.normalized_uplink_data_placement().as_str() {
                PLACEMENT_COOKIE => Ok(Range { min: 2 * 1024, max: 3 * 1024 }),
                PLACEMENT_HEADER => Ok(Range { min: 3 * 1024, max: 4 * 1024 }),
                _ => self.normalized_sc_max_each_post_bytes(),
            };
        } else if uplink_chunk_size.min < 64 {
            uplink_chunk_size.min = 64;
            if uplink_chunk_size.max < 64 {
                uplink_chunk_size.max = 64;
            }
        }
        Ok(uplink_chunk_size)
    }

    #[must_use]
    pub fn normalized_session_placement(&self) -> String {
        if self.session_placement.is_empty() {
            PLACEMENT_PATH.to_owned()
        } else {
            self.session_placement.clone()
        }
    }

    #[must_use]
    pub fn normalized_seq_placement(&self) -> String {
        if self.seq_placement.is_empty() {
            PLACEMENT_PATH.to_owned()
        } else {
            self.seq_placement.clone()
        }
    }

    #[must_use]
    pub fn normalized_uplink_data_placement(&self) -> String {
        if self.uplink_data_placement.is_empty() {
            PLACEMENT_BODY.to_owned()
        } else {
            self.uplink_data_placement.clone()
        }
    }

    #[must_use]
    pub fn normalized_session_key(&self) -> String {
        if !self.session_key.is_empty() {
            return self.session_key.clone();
        }
        match self.normalized_session_placement().as_str() {
            PLACEMENT_HEADER => "X-Session".to_owned(),
            PLACEMENT_COOKIE | PLACEMENT_QUERY => "x_session".to_owned(),
            _ => String::new(),
        }
    }

    #[must_use]
    pub fn normalized_seq_key(&self) -> String {
        if !self.seq_key.is_empty() {
            return self.seq_key.clone();
        }
        match self.normalized_seq_placement().as_str() {
            PLACEMENT_HEADER => "X-Seq".to_owned(),
            PLACEMENT_COOKIE | PLACEMENT_QUERY => "x_seq".to_owned(),
            _ => String::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Range {
    pub min: i64,
    pub max: i64,
}

impl Range {
    #[must_use]
    pub fn rand(&self) -> i64 {
        if self.min == self.max {
            return self.min;
        }
        self.min + rand::rng().random_range(0..=(self.max - self.min))
    }
}

pub fn parse_range(s: &str, fallback: &str) -> anyhow::Result<Range> {
    if s.trim().is_empty() {
        return parse_range_str(fallback);
    }
    parse_range_str(s)
}

/// The parse step of [`parse_range`], split out so the exported entry point can apply its
/// empty-string fallback.
fn parse_range_str(s: &str) -> anyhow::Result<Range> {
    let trimmed = s.trim();
    let mut parts = trimmed.splitn(3, '-');
    let head = parts.next().unwrap_or_default();
    match (parts.next(), parts.next()) {
        (None, _) => {
            let v: i64 = head.parse()?;
            Ok(Range { min: v, max: v })
        }
        (Some(tail), None) => {
            let min_val: i64 = head.trim().parse()?;
            let max_val: i64 = tail.trim().parse()?;
            if min_val < 0 || max_val < min_val {
                return Err(anyhow!("invalid range: {s}"));
            }
            Ok(Range { min: min_val, max: max_val })
        }
        _ => Err(anyhow!("invalid range: {s}")),
    }
}

impl ReuseConfig {
    pub fn resolve_manager_config(this: Option<&Self>) -> anyhow::Result<(Range, Range)> {
        let Some(c) = this else {
            return Ok((Range::default(), Range::default()));
        };
        let max_concurrency =
            parse_range(&c.max_concurrency, "0").map_err(|e| anyhow!("invalid max-concurrency: {e}"))?;
        let max_connections =
            parse_range(&c.max_connections, "0").map_err(|e| anyhow!("invalid max-connections: {e}"))?;
        Ok((max_concurrency, max_connections))
    }

    pub fn resolve_entry_config(this: Option<&Self>) -> anyhow::Result<(Range, Range, Range)> {
        let Some(c) = this else {
            return Ok((Range::default(), Range::default(), Range::default()));
        };
        let c_max_reuse_times =
            parse_range(&c.c_max_reuse_times, "0").map_err(|e| anyhow!("invalid c-max-reuse-times: {e}"))?;
        let h_max_request_times =
            parse_range(&c.h_max_request_times, "0").map_err(|e| anyhow!("invalid h-max-request-times: {e}"))?;
        let h_max_reusable_secs =
            parse_range(&c.h_max_reusable_secs, "0").map_err(|e| anyhow!("invalid h-max-reusable-secs: {e}"))?;
        Ok((c_max_reuse_times, h_max_request_times, h_max_reusable_secs))
    }
}

pub(crate) fn append_to_path(path: &str, value: &str) -> String {
    if path.ends_with('/') {
        format!("{path}{value}")
    } else {
        format!("{path}/{value}")
    }
}

impl Config {
    pub fn apply_meta_to_request(&self, req: &mut Request, session_id: &str, seq_str: &str) {
        let session_placement = self.normalized_session_placement();
        let seq_placement = self.normalized_seq_placement();
        let session_key = self.normalized_session_key();
        let seq_key = self.normalized_seq_key();

        if !session_id.is_empty() {
            match session_placement.as_str() {
                PLACEMENT_PATH => {
                    let path = append_to_path(req.url.path(), session_id);
                    req.url.set_path(&path);
                }
                PLACEMENT_QUERY => {
                    req.url.query_pairs_mut().append_pair(&session_key, session_id);
                }
                PLACEMENT_HEADER => {
                    if let Ok(name) = http::HeaderName::from_bytes(session_key.as_bytes()) {
                        if let Ok(value) = http::HeaderValue::from_str(session_id) {
                            req.header.insert(name, value);
                        }
                    }
                }
                PLACEMENT_COOKIE => {
                    req.add_cookie(&Cookie { name: session_key, value: session_id.to_owned() });
                }
                _ => {}
            }
        }

        if !seq_str.is_empty() {
            match seq_placement.as_str() {
                PLACEMENT_PATH => {
                    let path = append_to_path(req.url.path(), seq_str);
                    req.url.set_path(&path);
                }
                PLACEMENT_QUERY => {
                    req.url.query_pairs_mut().append_pair(&seq_key, seq_str);
                }
                PLACEMENT_HEADER => {
                    if let Ok(name) = http::HeaderName::from_bytes(seq_key.as_bytes()) {
                        if let Ok(value) = http::HeaderValue::from_str(seq_str) {
                            req.header.insert(name, value);
                        }
                    }
                }
                PLACEMENT_COOKIE => req.add_cookie(&Cookie { name: seq_key, value: seq_str.to_owned() }),
                _ => {}
            }
        }
    }

    pub fn extract_meta_from_request(&self, req: &Request, path: &str) -> (String, String) {
        let session_placement = self.normalized_session_placement();
        let seq_placement = self.normalized_seq_placement();
        let session_key = self.normalized_session_key();
        let seq_key = self.normalized_seq_key();

        let mut subpath: Vec<&str> = Vec::new();
        let mut path_part = 0usize;
        if session_placement == PLACEMENT_PATH || seq_placement == PLACEMENT_PATH {
            let rest = req.url.path().get(path.len()..).unwrap_or("");
            subpath = rest.split('/').collect();
        }

        let mut session_id = String::new();
        match session_placement.as_str() {
            PLACEMENT_PATH => {
                if let Some(part) = subpath.get(path_part) {
                    (*part).clone_into(&mut session_id);
                    path_part += 1;
                }
            }
            PLACEMENT_QUERY => {
                session_id = req
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == session_key.as_str())
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
            }
            PLACEMENT_HEADER => {
                req.header.get(&session_key).and_then(|v| v.to_str().ok()).unwrap_or("").clone_into(&mut session_id);
            }
            PLACEMENT_COOKIE => {
                if let Some(cookie) = req.cookie(&session_key) {
                    session_id = cookie.value;
                }
            }
            _ => {}
        }

        let mut seq_str = String::new();
        match seq_placement.as_str() {
            PLACEMENT_PATH => {
                if let Some(part) = subpath.get(path_part) {
                    (*part).clone_into(&mut seq_str);
                }
            }
            PLACEMENT_QUERY => {
                seq_str = req
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == seq_key.as_str())
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
            }
            PLACEMENT_HEADER => {
                req.header.get(&seq_key).and_then(|v| v.to_str().ok()).unwrap_or("").clone_into(&mut seq_str);
            }
            PLACEMENT_COOKIE => {
                if let Some(cookie) = req.cookie(&seq_key) {
                    seq_str = cookie.value;
                }
            }
            _ => {}
        }

        (session_id, seq_str)
    }

    pub fn fill_stream_request(&self, req: &mut Request, session_id: &str) -> anyhow::Result<()> {
        req.header = self.request_header();
        let x_padding_bytes = self.normalized_x_padding_bytes()?;
        let length = x_padding_bytes.rand();
        let mut config = super::xpadding::XPaddingConfig {
            length,
            placement: super::xpadding::XPaddingPlacement::default(),
            method: super::xpadding::PaddingMethod::default(),
        };

        if self.x_padding_obfs_mode {
            config.placement = super::xpadding::XPaddingPlacement {
                placement: self.x_padding_placement.clone(),
                key: self.x_padding_key.clone(),
                header: self.x_padding_header.clone(),
                raw_url: req.url.to_string(),
            };
            config.method = super::xpadding::PaddingMethod(self.x_padding_method.clone());
        } else {
            config.placement = super::xpadding::XPaddingPlacement {
                placement: PLACEMENT_QUERY_IN_HEADER.to_owned(),
                key: "x_padding".to_owned(),
                header: "Referer".to_owned(),
                raw_url: req.url.to_string(),
            };
        }

        self.apply_x_padding_to_request(req, &config);
        self.apply_meta_to_request(req, session_id, "");

        if req.body.is_some() && !self.no_grpc_header {
            req.header.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/grpc"));
        }

        Ok(())
    }

    pub fn fill_download_request(&self, req: &mut Request, session_id: &str) -> anyhow::Result<()> {
        self.fill_stream_request(req, session_id)
    }

    pub fn fill_packet_request(
        &self,
        request: &mut Request,
        session_id: &str,
        seq_str: &str,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let data_placement = self.normalized_uplink_data_placement();

        if data_placement == PLACEMENT_BODY || data_placement == PLACEMENT_AUTO {
            request.header = self.request_header();
            request.body = Some(RequestBody::Bytes(Bytes::copy_from_slice(data)));
            request.content_length = i64::try_from(data.len()).unwrap_or(i64::MAX);
        } else {
            request.body = None;
            request.content_length = 0;
            match data_placement.as_str() {
                PLACEMENT_HEADER => {
                    let uplink_chunk_size = self.normalized_uplink_chunk_size()?;
                    request.header = self.request_header_with_payload(data, uplink_chunk_size);
                }
                PLACEMENT_COOKIE => {
                    request.header = self.request_header();
                    let uplink_chunk_size = self.normalized_uplink_chunk_size()?;
                    for cookie in self.request_cookies_with_payload(data, uplink_chunk_size) {
                        request.add_cookie(&cookie);
                    }
                }
                _ => {}
            }
        }

        let x_padding_bytes = self.normalized_x_padding_bytes()?;
        let length = x_padding_bytes.rand();
        let mut config = super::xpadding::XPaddingConfig {
            length,
            placement: super::xpadding::XPaddingPlacement::default(),
            method: super::xpadding::PaddingMethod::default(),
        };

        if self.x_padding_obfs_mode {
            config.placement = super::xpadding::XPaddingPlacement {
                placement: self.x_padding_placement.clone(),
                key: self.x_padding_key.clone(),
                header: self.x_padding_header.clone(),
                raw_url: request.url.to_string(),
            };
            config.method = super::xpadding::PaddingMethod(self.x_padding_method.clone());
        } else {
            config.placement = super::xpadding::XPaddingPlacement {
                placement: PLACEMENT_QUERY_IN_HEADER.to_owned(),
                key: "x_padding".to_owned(),
                header: "Referer".to_owned(),
                raw_url: request.url.to_string(),
            };
        }

        self.apply_x_padding_to_request(request, &config);
        self.apply_meta_to_request(request, session_id, seq_str);

        Ok(())
    }
}

/// The room size. Arbitrary-precision integers have no pinned Rust equivalent; since the caller only compares the
/// result against a fixed threshold, saturating `u128` arithmetic (`u128::MAX` standing in for "at
/// least that large") is behaviour-preserving for this use.
fn room_size(table_size: i64, min: i64, max: i64) -> u128 {
    let base = u128::try_from(table_size).unwrap_or(u128::MAX);
    let mut sum: u128 = 0;
    for k in min..=max {
        let mut term: u128 = 1;
        let mut overflowed = false;
        for _ in 0..k {
            if let Some(v) = term.checked_mul(base) {
                term = v;
            } else {
                overflowed = true;
                break;
            }
        }
        if overflowed {
            return u128::MAX;
        }
        sum = sum.saturating_add(term);
        if sum == u128::MAX {
            return u128::MAX;
        }
    }
    sum
}

fn predefined_table(name: &str) -> Option<&'static str> {
    match name {
        "ALPHABET" => Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "Alphabet" => Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
        "BASE36" => Some("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "Base62" => Some("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
        "HEX" => Some("0123456789ABCDEF"),
        "alphabet" => Some("abcdefghijklmnopqrstuvwxyz"),
        "base36" => Some("0123456789abcdefghijklmnopqrstuvwxyz"),
        "hex" => Some("0123456789abcdef"),
        "number" => Some("0123456789"),
        _ => None,
    }
}

impl Config {
    pub fn generate_session_id(&self) -> anyhow::Result<Box<dyn Fn() -> String + Send + Sync>> {
        match self.session_table.as_str() {
            "" => Ok(Box::new(|| {
                let mut b = [0u8; 16];
                rand::rng().fill(&mut b);
                hex::encode(b)
            })),
            "uuid" => Ok(Box::new(|| murmur_common::utils::uuid::new_uuid_v4().to_string())),
            _ => {
                let mut session_table = self.session_table.clone();
                if let Some(predefined) = predefined_table(&session_table) {
                    predefined.clone_into(&mut session_table);
                }
                let session_length =
                    parse_range(&self.session_length, "16-32").map_err(|e| anyhow!("invalid session-length: {e}"))?;
                let room = room_size(
                    i64::try_from(session_table.len()).unwrap_or(i64::MAX),
                    session_length.min,
                    session_length.max,
                );
                if room < (2u128 << 30) {
                    return Err(anyhow!("session-table or session-length is too small"));
                }
                if session_length.min <= 0 {
                    return Err(anyhow!("session-length must be greater than 0"));
                }
                for b in session_table.bytes() {
                    if b >= 0x80 {
                        return Err(anyhow!("session-table must contain only ASCII characters"));
                    }
                }
                let table_bytes = session_table.into_bytes();
                Ok(Box::new(move || {
                    let length = usize::try_from(session_length.rand().max(0)).unwrap_or_default();
                    let mut id = vec![0u8; length];
                    for byte in &mut id {
                        let index = rand::rng().random_range(0..table_bytes.len());
                        *byte = table_bytes.get(index).copied().unwrap_or_default();
                    }
                    String::from_utf8(id).unwrap_or_default()
                }))
            }
        }
    }
}

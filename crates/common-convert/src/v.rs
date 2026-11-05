use std::collections::HashMap;
use std::fmt::Write as _;

use serde_json::{json, Map, Value};
use url::Url as StdUrl;

use super::converter::{parse_bool, unique_name};
use super::util::rand_user_agent;

/// The crate parses to the WHATWG view; the view differs from the raw text, which is why the raw
/// input is kept.
#[derive(Debug, Clone)]
pub(crate) struct Url {
    parsed: StdUrl,
    raw: String,
    host_override: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct UrlValues {
    pairs: Vec<(String, String)>,
}

/// The `escape` modes that the URL handling needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    Path,
    UserPassword,
    QueryComponent,
    Fragment,
    Host,
}

const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

fn is_hex(c: u8) -> bool {
    c.is_ascii_digit() || (b'a'..=b'f').contains(&c) || (b'A'..=b'F').contains(&c)
}

const fn unhex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn should_escape(c: u8, mode: Encoding) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }

    if mode == Encoding::Host
        && matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
    {
        return false;
    }

    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => {
            return match mode {
                Encoding::Path => c == b'?',
                Encoding::UserPassword => matches!(c, b'@' | b'/' | b'?' | b':'),
                Encoding::QueryComponent => true,
                Encoding::Fragment | Encoding::Host => false,
            };
        }
        _ => {}
    }

    if mode == Encoding::Fragment && matches!(c, b'!' | b'(' | b')' | b'*') {
        return false;
    }

    true
}

#[expect(
    clippy::indexing_slicing,
    reason = "`c >> 4` and `c & 15` are the two nibbles of a byte, so both are always within UPPER_HEX's 16 entries"
)]
pub(crate) fn escape(s: &str, mode: Encoding) -> String {
    if !s.bytes().any(|c| should_escape(c, mode)) {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.bytes() {
        if c == b' ' && mode == Encoding::QueryComponent {
            out.push('+');
        } else if should_escape(c, mode) {
            out.push('%');
            out.push(UPPER_HEX[(c >> 4) as usize] as char);
            out.push(UPPER_HEX[(c & 15) as usize] as char);
        } else {
            out.push(c as char);
        }
    }
    out
}

/// The error a malformed `%` escape reports, quoting up to three bytes from it.
fn invalid_escape(rest: &[u8]) -> anyhow::Error {
    let invalid = String::from_utf8_lossy(rest.get(..3).unwrap_or(rest));
    anyhow::anyhow!("invalid URL escape {invalid:?}")
}

pub(crate) fn unescape(s: &str, mode: Encoding) -> anyhow::Result<String> {
    let bytes = s.as_bytes();
    let mut has_plus = false;

    let mut rest = bytes;
    loop {
        match rest {
            [b'%', hi, lo, ..] if is_hex(*hi) && is_hex(*lo) => {
                if mode == Encoding::Host && unhex(*hi) < 8 && !rest.starts_with(b"%25") {
                    return Err(invalid_escape(rest));
                }
                rest = rest.get(3..).unwrap_or_default();
            }
            [b'%', ..] => return Err(invalid_escape(rest)),
            [b'+', ..] => {
                if mode == Encoding::QueryComponent {
                    has_plus = true;
                }
                rest = rest.get(1..).unwrap_or_default();
            }
            [_, ..] => rest = rest.get(1..).unwrap_or_default(),
            [] => break,
        }
    }

    if !has_plus && !bytes.contains(&b'%') {
        return Ok(s.to_owned());
    }

    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match rest {
            [b'%', hi, lo, ..] => {
                out.push(unhex(*hi) << 4 | unhex(*lo));
                rest = rest.get(3..).unwrap_or_default();
            }
            [b'+', ..] => {
                out.push(if mode == Encoding::QueryComponent { b' ' } else { b'+' });
                rest = rest.get(1..).unwrap_or_default();
            }
            [first, ..] => {
                out.push(*first);
                rest = rest.get(1..).unwrap_or_default();
            }
            [] => break,
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

pub(crate) fn query_escape(s: &str) -> String {
    escape(s, Encoding::QueryComponent)
}

pub(crate) fn query_unescape(s: &str) -> anyhow::Result<String> {
    unescape(s, Encoding::QueryComponent)
}

#[must_use]
pub fn parse_query(query: &str) -> (UrlValues, Option<anyhow::Error>) {
    let mut values = UrlValues::default();
    let mut first_err = None;
    for key in query.split('&') {
        if key.is_empty() {
            continue;
        }
        if key.contains(';') {
            if first_err.is_none() {
                first_err = Some(anyhow::anyhow!("invalid semicolon separator in query"));
            }
            continue;
        }
        let (key, value) = match key.split_once('=') {
            Some((key, value)) => (key, value),
            None => (key, ""),
        };
        let key = match query_unescape(key) {
            Ok(key) => key,
            Err(err) => {
                if first_err.is_none() {
                    first_err = Some(err);
                }
                continue;
            }
        };
        let value = match query_unescape(value) {
            Ok(value) => value,
            Err(err) => {
                if first_err.is_none() {
                    first_err = Some(err);
                }
                continue;
            }
        };
        values.pairs.push((key, value));
    }
    (values, first_err)
}

impl UrlValues {
    #[must_use]
    pub fn get(&self, key: &str) -> String {
        self.pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).unwrap_or_default()
    }

    /// the map indexing `v[key]`, which keeps every value and its order.
    pub(crate) fn values(&self, key: &str) -> Vec<String> {
        self.pairs.iter().filter(|(k, _)| k == key).map(|(_, v)| v.clone()).collect()
    }

    pub(crate) fn del(&mut self, key: &str) {
        self.pairs.retain(|(k, _)| k != key);
    }

    pub(crate) fn encode(&self) -> String {
        let mut keys: Vec<&str> = self.pairs.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        keys.dedup();
        let mut out = String::new();
        for key in keys {
            for value in self.values(key) {
                if !out.is_empty() {
                    out.push('&');
                }
                let _ = write!(out, "{}={}", query_escape(key), query_escape(&value));
            }
        }
        out
    }
}

/// The relative reference form a `VMess` `path` option accepts.
#[derive(Debug, Clone)]
pub(crate) struct PathUrl {
    /// The escaped path, or the opaque form.
    before_query: String,
    raw_query: String,
    force_query: bool,
    raw_fragment: Option<String>,
}

fn get_scheme(raw: &str) -> (&str, &str) {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return ("", raw);
                }
            }
            b':' => {
                if i == 0 {
                    return ("", raw);
                }
                let (scheme, after_scheme) = raw.split_at(i);
                return (scheme, after_scheme.strip_prefix(':').unwrap_or_default());
            }
            _ => return ("", raw),
        }
    }
    ("", raw)
}

impl PathUrl {
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        if raw.bytes().any(|c| c < 0x20 || c == 0x7f) {
            return None;
        }
        let (rest, raw_fragment) = match raw.split_once('#') {
            Some((rest, fragment)) => (rest, Some(fragment)),
            None => (raw, None),
        };
        let (rest, raw_query, force_query) = if rest.ends_with('?') && rest.matches('?').count() == 1 {
            (rest.strip_suffix('?').unwrap_or_default(), "", true)
        } else {
            match rest.split_once('?') {
                Some((rest, query)) => (rest, query, false),
                None => (rest, "", false),
            }
        };

        let (scheme, after_scheme) = get_scheme(rest);
        // Reject an authority after "//" (but not "///"); a VMess path option never carries one.
        if after_scheme.starts_with("//") && !after_scheme.starts_with("///") {
            return None;
        }
        let before_query = if after_scheme.starts_with('/') {
            unescape(after_scheme, Encoding::Path).ok()?;
            after_scheme.to_owned()
        } else if scheme.is_empty() {
            if after_scheme.split('/').next().unwrap_or("").contains(':') {
                return None;
            }
            after_scheme.to_owned()
        } else {
            rest.to_owned()
        };
        let fragment = match raw_fragment {
            Some(fragment) => {
                unescape(fragment, Encoding::Fragment).ok()?;
                Some(fragment.to_owned())
            }
            None => None,
        };
        Some(Self { before_query, raw_query: raw_query.to_owned(), force_query, raw_fragment: fragment })
    }

    pub(crate) fn query(&self) -> UrlValues {
        let (values, _) = parse_query(&self.raw_query);
        values
    }

    pub(crate) fn set_raw_query(&mut self, raw_query: String) {
        self.raw_query = raw_query;
    }

    pub(crate) fn string(&self) -> String {
        let mut result = self.before_query.clone();
        if self.force_query || !self.raw_query.is_empty() {
            result.push('?');
            result.push_str(&self.raw_query);
        }
        if let Some(fragment) = &self.raw_fragment {
            result.push('#');
            result.push_str(fragment);
        }
        result
    }
}

impl Url {
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        if raw.bytes().any(|c| c < 0x20 || c == 0x7f) {
            return None;
        }
        let url = StdUrl::parse(raw).ok()?;
        unescape(url.path(), Encoding::Path).ok()?;
        unescape(url.username(), Encoding::UserPassword).ok()?;
        if let Some(password) = url.password() {
            unescape(password, Encoding::UserPassword).ok()?;
        }
        if let Some(fragment) = url.fragment() {
            unescape(fragment, Encoding::Fragment).ok()?;
        }
        if let Some(host) = url.host_str() {
            unescape(host, Encoding::Host).ok()?;
        }
        Some(Self { parsed: url, raw: raw.to_owned(), host_override: None })
    }

    /// the `Host` field assignment.
    pub(crate) fn set_host(&mut self, host: &str) {
        self.host_override = Some(host.to_owned());
    }

    pub(crate) fn query(&self) -> UrlValues {
        let (values, _) = parse_query(self.parsed.query().unwrap_or(""));
        values
    }

    pub(crate) fn fragment(&self) -> String {
        match self.parsed.fragment() {
            Some(fragment) => unescape(fragment, Encoding::Fragment).unwrap_or_default(),
            None => String::new(),
        }
    }

    pub(crate) fn user_username(&self) -> String {
        unescape(self.parsed.username(), Encoding::UserPassword).unwrap_or_default()
    }

    pub(crate) fn user_password(&self) -> Option<String> {
        self.parsed
            .password()
            .map(|password| unescape(password, Encoding::UserPassword).unwrap_or_else(|_| password.to_owned()))
    }

    pub(crate) fn user_string(&self) -> String {
        if self.parsed.username().is_empty() && self.parsed.password().is_none() {
            return String::new();
        }
        let username = self.user_username();
        match self.user_password() {
            Some(password) => escape(&format!("{username}:{password}"), Encoding::UserPassword),
            None => escape(&username, Encoding::UserPassword),
        }
    }

    pub(crate) fn host(&self) -> String {
        if let Some(host) = &self.host_override {
            return host.clone();
        }
        let Some(host) = self.parsed.host_str() else {
            return String::new();
        };
        let host = unescape(host, Encoding::Host).unwrap_or_else(|_| host.to_owned());
        match self.raw_port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }

    pub(crate) fn hostname(&self) -> String {
        split_host_port(&self.host()).0
    }

    pub(crate) fn port(&self) -> String {
        split_host_port(&self.host()).1
    }

    /// The port text of the raw authority, which the WHATWG view normalizes away.
    fn raw_port(&self) -> Option<String> {
        let rest = self.raw.get(self.parsed.scheme().len() + 1..)?;
        let rest = rest.strip_prefix("//")?;
        let authority = match rest.split_once(['/', '?', '#']) {
            Some((authority, _)) => authority,
            None => rest,
        };
        let host_port = match authority.rsplit_once('@') {
            Some((_, host_port)) => host_port,
            None => authority,
        };
        let (_, port) = host_port.rsplit_once(':')?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(port.to_owned())
    }
}

fn split_host_port(host_port: &str) -> (String, String) {
    let mut host = host_port;
    let mut port = "";
    if let Some((before, after)) = host_port.rsplit_once(':') {
        if after.bytes().all(|b| b.is_ascii_digit()) {
            host = before;
            port = after;
        }
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|host| host.strip_suffix(']')) {
        host = inner;
    }
    (host.to_owned(), port.to_owned())
}

pub(crate) fn handle_v_share_link(
    names: &mut HashMap<String, i32>,
    url: &Url,
    scheme: &str,
    proxy: &mut Map<String, Value>,
) -> anyhow::Result<()> {
    // Xray VMessAEAD / VLESS share link standard
    let query = url.query();
    proxy.insert("name".to_owned(), json!(unique_name(names, &url.fragment())));
    if url.hostname().is_empty() {
        return Err(anyhow::anyhow!("url.Hostname() is empty"));
    }
    if url.port().is_empty() {
        return Err(anyhow::anyhow!("url.Port() is empty"));
    }
    proxy.insert("type".to_owned(), json!(scheme));
    proxy.insert("server".to_owned(), json!(url.hostname()));
    proxy.insert("port".to_owned(), json!(url.port()));
    proxy.insert("uuid".to_owned(), json!(url.user_username()));
    proxy.insert("udp".to_owned(), json!(true));
    insert_tls_opts(&query, proxy);
    insert_packet_encoding_opts(&query, proxy);

    let network = v_share_network(&query);
    proxy.insert("network".to_owned(), Value::String(network.clone()));
    match network.as_str() {
        "http" => insert_http_opts(&query, proxy),
        "h2" => insert_h2_opts(&query, proxy),
        "ws" | "httpupgrade" => insert_ws_opts(&query, &network, proxy)?,
        "grpc" => insert_grpc_opts(&query, proxy),
        "xhttp" => insert_xhttp_opts(&query, proxy),
        _ => {}
    }

    Ok(())
}

/// The `security`, `sni` and `pbk` fields.
fn insert_tls_opts(query: &UrlValues, proxy: &mut Map<String, Value>) {
    let tls = query.get("security").to_lowercase();
    if tls.ends_with("tls") || tls == "reality" {
        proxy.insert("tls".to_owned(), json!(true));
        let fingerprint = query.get("fp");
        if fingerprint.is_empty() {
            proxy.insert("client-fingerprint".to_owned(), json!("chrome"));
        } else {
            proxy.insert("client-fingerprint".to_owned(), json!(fingerprint));
        }
        let alpn = query.get("alpn");
        if !alpn.is_empty() {
            proxy.insert("alpn".to_owned(), json!(alpn.split(',').collect::<Vec<_>>()));
        }
        let pcs = query.get("pcs");
        if !pcs.is_empty() {
            proxy.insert("fingerprint".to_owned(), json!(pcs));
        }
    }
    let sni = query.get("sni");
    if !sni.is_empty() {
        proxy.insert("servername".to_owned(), json!(sni));
    }
    insert_reality_opts(query, proxy);
}

/// The `pbk`/`sid`/`support-x25519mlkem768` reality fields.
fn insert_reality_opts(query: &UrlValues, proxy: &mut Map<String, Value>) {
    let reality_public_key = query.get("pbk");
    if reality_public_key.is_empty() {
        return;
    }
    let mut reality_opts = json!({ "public-key": reality_public_key, "short-id": query.get("sid") });
    let mlkem = query.get("support-x25519mlkem768");
    if !mlkem.is_empty() {
        if let Some(enabled) = parse_bool(&mlkem) {
            if let Some(opts) = reality_opts.as_object_mut() {
                opts.insert("support-x25519mlkem768".to_owned(), json!(enabled));
            }
        }
    }
    proxy.insert("reality-opts".to_owned(), reality_opts);
}

/// The `packetEncoding` field.
fn insert_packet_encoding_opts(query: &UrlValues, proxy: &mut Map<String, Value>) {
    match query.get("packetEncoding").as_str() {
        "none" => {}
        "packet" => {
            proxy.insert("packet-addr".to_owned(), json!(true));
        }
        _ => {
            proxy.insert("xudp".to_owned(), json!(true));
        }
    }
}

/// The `type`/`headerType` pair, where an `http` header type selects the h2 transport.
fn v_share_network(query: &UrlValues) -> String {
    let mut network = query.get("type").to_lowercase();
    if network.is_empty() {
        "tcp".clone_into(&mut network);
    }
    let fake_type = query.get("headerType").to_lowercase();
    if network == "tcp" && fake_type == "http" {
        "http".clone_into(&mut network);
    } else if network == "http" {
        "h2".clone_into(&mut network);
    }
    network
}

fn insert_http_opts(query: &UrlValues, proxy: &mut Map<String, Value>) {
    let mut headers = Map::new();
    let mut http_opts = Map::new();
    http_opts.insert("path".to_owned(), json!(["/"]));

    let host = query.get("host");
    if !host.is_empty() {
        headers.insert("Host".to_owned(), json!([host]));
    }

    let method = query.get("method");
    if !method.is_empty() {
        http_opts.insert("method".to_owned(), json!(method));
    }

    let path = query.get("path");
    if !path.is_empty() {
        http_opts.insert("path".to_owned(), json!([path]));
    }
    http_opts.insert("headers".to_owned(), Value::Object(headers));
    proxy.insert("http-opts".to_owned(), Value::Object(http_opts));
}

fn insert_h2_opts(query: &UrlValues, proxy: &mut Map<String, Value>) {
    let mut h2_opts = Map::new();
    h2_opts.insert("path".to_owned(), json!("/"));
    let path = query.get("path");
    if !path.is_empty() {
        h2_opts.insert("path".to_owned(), json!(path));
    }
    let host = query.get("host");
    if !host.is_empty() {
        h2_opts.insert("host".to_owned(), json!([host]));
    }
    proxy.insert("h2-opts".to_owned(), Value::Object(h2_opts));
}

/// The `ed`/`eh` early-data fields, whose `ed` value must parse as an `int32`.
fn insert_ws_opts(query: &UrlValues, network: &str, proxy: &mut Map<String, Value>) -> anyhow::Result<()> {
    let mut headers = Map::new();
    let mut ws_opts = Map::new();
    headers.insert("User-Agent".to_owned(), json!(rand_user_agent()));
    headers.insert("Host".to_owned(), json!(query.get("host")));
    ws_opts.insert("path".to_owned(), json!(query.get("path")));
    ws_opts.insert("headers".to_owned(), Value::Object(headers));

    let early_data = query.get("ed");
    if !early_data.is_empty() {
        let med = match early_data.parse::<i32>() {
            Ok(med) => med,
            Err(err) => {
                let reason = if matches!(
                    err.kind(),
                    std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow
                ) {
                    "value out of range"
                } else {
                    "invalid syntax"
                };
                return Err(anyhow::anyhow!("bad WebSocket max early data size: {early_data:?}: {reason}"));
            }
        };
        match network {
            "ws" => {
                ws_opts.insert("max-early-data".to_owned(), json!(med));
                ws_opts.insert("early-data-header-name".to_owned(), json!("Sec-WebSocket-Protocol"));
            }
            "httpupgrade" => {
                ws_opts.insert("v2ray-http-upgrade-fast-open".to_owned(), json!(true));
            }
            _ => {}
        }
    }
    let early_data_header = query.get("eh");
    if !early_data_header.is_empty() {
        ws_opts.insert("early-data-header-name".to_owned(), json!(early_data_header));
    }

    proxy.insert("ws-opts".to_owned(), Value::Object(ws_opts));
    Ok(())
}

fn insert_grpc_opts(query: &UrlValues, proxy: &mut Map<String, Value>) {
    let mut grpc_opts = Map::new();
    grpc_opts.insert("grpc-service-name".to_owned(), json!(query.get("serviceName")));
    proxy.insert("grpc-opts".to_owned(), Value::Object(grpc_opts));
}

fn insert_xhttp_opts(query: &UrlValues, proxy: &mut Map<String, Value>) {
    proxy.insert("network".to_owned(), json!("xhttp"));
    let mut xhttp_opts = Map::new();

    let path = query.get("path");
    if !path.is_empty() {
        xhttp_opts.insert("path".to_owned(), json!(path));
    }

    let host = query.get("host");
    if !host.is_empty() {
        xhttp_opts.insert("host".to_owned(), json!(host));
    }

    let mode = query.get("mode");
    if !mode.is_empty() {
        xhttp_opts.insert("mode".to_owned(), json!(mode));
    }

    let extra = query.get("extra");
    if !extra.is_empty() {
        if let Ok(Value::Object(extra_map)) = serde_json::from_str::<Value>(&extra) {
            parse_xhttp_extra(&extra_map, &mut xhttp_opts);
        }
    }

    proxy.insert("xhttp-opts".to_owned(), Value::Object(xhttp_opts));
}

/// Maps xray-core extra JSON fields to murmur xhttp-opts fields.
pub(crate) fn parse_xhttp_extra(extra: &Map<String, Value>, opts: &mut Map<String, Value>) {
    if matches!(extra.get("noGRPCHeader"), Some(Value::Bool(true))) {
        opts.insert("no-grpc-header".to_owned(), json!(true));
    }

    insert_extra_string(extra, opts, "xPaddingBytes", "x-padding-bytes");
    if let Some(v @ Value::Bool(_)) = extra.get("xPaddingObfsMode") {
        opts.insert("x-padding-obfs-mode".to_owned(), v.clone());
    }
    insert_extra_string(extra, opts, "xPaddingKey", "x-padding-key");
    insert_extra_string(extra, opts, "xPaddingHeader", "x-padding-header");
    insert_extra_string(extra, opts, "xPaddingPlacement", "x-padding-placement");
    insert_extra_string(extra, opts, "xPaddingMethod", "x-padding-method");
    insert_extra_string(extra, opts, "uplinkHTTPMethod", "uplink-http-method");
    insert_first_extra_string(extra, opts, ("sessionIDPlacement", "sessionPlacement"), "session-placement");
    insert_first_extra_string(extra, opts, ("sessionIDKey", "sessionKey"), "session-key");
    insert_extra_string(extra, opts, "sessionIDTable", "session-table");
    insert_extra_length(extra, opts);
    insert_extra_string(extra, opts, "seqPlacement", "seq-placement");
    insert_extra_string(extra, opts, "seqKey", "seq-key");
    insert_extra_string(extra, opts, "uplinkDataPlacement", "uplink-data-placement");
    insert_extra_string(extra, opts, "uplinkDataKey", "uplink-data-key");
    insert_extra_number(extra, opts, "uplinkChunkSize", "uplink-chunk-size");
    insert_extra_number(extra, opts, "scMaxEachPostBytes", "sc-max-each-post-bytes");
    insert_extra_number(extra, opts, "scMinPostsIntervalMs", "sc-min-posts-interval-ms");

    if let Some(Value::Object(xmux)) = extra.get("xmux") {
        insert_reuse_settings(xmux, opts);
    }
    if let Some(Value::Object(download_settings)) = extra.get("downloadSettings") {
        insert_download_settings(download_settings, opts);
    }
}

/// Inserts `dst` for the non-empty string `src`.
fn insert_extra_string(extra: &Map<String, Value>, opts: &mut Map<String, Value>, src: &str, dst: &str) {
    if let Some(text) = extra.get(src).and_then(Value::as_str) {
        if !text.is_empty() {
            opts.insert(dst.to_owned(), json!(text));
        }
    }
}

/// Inserts `dst` for the first of `keys` that holds a non-empty string.
fn insert_first_extra_string(extra: &Map<String, Value>, opts: &mut Map<String, Value>, keys: (&str, &str), dst: &str) {
    if let Some(text) = extra.get(keys.0).and_then(Value::as_str) {
        if !text.is_empty() {
            opts.insert(dst.to_owned(), json!(text));
        }
    } else if let Some(text) = extra.get(keys.1).and_then(Value::as_str) {
        if !text.is_empty() {
            opts.insert(dst.to_owned(), json!(text));
        }
    }
}

/// `sessionIDLength` carries either the length text or the length number.
fn insert_extra_length(extra: &Map<String, Value>, opts: &mut Map<String, Value>) {
    if let Some(text) = extra.get("sessionIDLength").and_then(Value::as_str) {
        if !text.is_empty() {
            opts.insert("session-length".to_owned(), json!(text));
        }
    } else if let Some(length) = extra.get("sessionIDLength").and_then(Value::as_f64) {
        opts.insert("session-length".to_owned(), json!(format!("{}", json_int(length))));
    }
}

/// Inserts `dst` for the number `src`.
fn insert_extra_number(extra: &Map<String, Value>, opts: &mut Map<String, Value>, src: &str, dst: &str) {
    if let Some(value) = extra.get(src).and_then(Value::as_f64) {
        opts.insert(dst.to_owned(), json!(json_int(value)));
    }
}

/// The whole-number reading of an `extra` field, which is carried as an `int64`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the extra fields hold whole-number counts, well inside the i64 range"
)]
fn json_int(value: f64) -> i64 {
    value as i64
}

/// Inserts `reuse-settings` when `xmux` maps to any setting.
fn insert_reuse_settings(xmux: &Map<String, Value>, opts: &mut Map<String, Value>) {
    let reuse = xmux_reuse_settings(xmux);
    if !reuse.is_empty() {
        opts.insert("reuse-settings".to_owned(), Value::Object(reuse));
    }
}

fn xmux_reuse_settings(xmux: &Map<String, Value>) -> Map<String, Value> {
    let mut reuse = Map::new();
    for (src, dst) in [
        ("maxConnections", "max-connections"),
        ("maxConcurrency", "max-concurrency"),
        ("cMaxReuseTimes", "c-max-reuse-times"),
        ("hMaxRequestTimes", "h-max-request-times"),
        ("hMaxReusableSecs", "h-max-reusable-secs"),
    ] {
        match xmux.get(src) {
            Some(Value::String(val)) => {
                if !val.is_empty() {
                    reuse.insert(dst.to_owned(), json!(val));
                }
            }
            Some(Value::Number(val)) => {
                if let Some(val) = val.as_f64() {
                    reuse.insert(dst.to_owned(), json!(format!("{}", json_int(val))));
                }
            }
            _ => {}
        }
    }
    if let Some(period) = xmux.get("hKeepAlivePeriod").and_then(Value::as_f64) {
        reuse.insert("h-keep-alive-period".to_owned(), json!(json_int(period)));
    }
    reuse
}

/// The `downloadSettings` object, which carries its own transport settings.
fn insert_download_settings(settings: &Map<String, Value>, opts: &mut Map<String, Value>) {
    let mut ds = Map::new();

    insert_extra_string(settings, &mut ds, "address", "server");
    insert_extra_number(settings, &mut ds, "port", "port");

    let sec = settings.get("security").and_then(Value::as_str).map_or_else(String::new, str::to_lowercase);
    if sec == "tls" || sec == "reality" {
        ds.insert("tls".to_owned(), json!(true));
        if let Some(Value::Object(tls_settings)) = settings.get("tlsSettings") {
            insert_download_tls_settings(tls_settings, &mut ds);
        }
    }

    if let Some(Value::Object(xhttp_settings)) = settings.get("xhttpSettings") {
        insert_download_xhttp_settings(xhttp_settings, &mut ds);
    }

    if !ds.is_empty() {
        opts.insert("download-settings".to_owned(), Value::Object(ds));
    }
}

/// The `downloadSettings.tlsSettings` object.
fn insert_download_tls_settings(tls_settings: &Map<String, Value>, ds: &mut Map<String, Value>) {
    insert_extra_string(tls_settings, ds, "serverName", "servername");
    insert_extra_string(tls_settings, ds, "fingerprint", "client-fingerprint");
    if let Some(Value::Array(alpn)) = tls_settings.get("alpn") {
        if !alpn.is_empty() {
            let alpn_list: Vec<Value> = alpn.iter().filter(|a| matches!(a, Value::String(_))).cloned().collect();
            if !alpn_list.is_empty() {
                ds.insert("alpn".to_owned(), Value::Array(alpn_list));
            }
        }
    }
    if matches!(tls_settings.get("allowInsecure"), Some(Value::Bool(true))) {
        ds.insert("skip-cert-verify".to_owned(), json!(true));
    }
}

/// The `downloadSettings.xhttpSettings` object.
fn insert_download_xhttp_settings(xhttp_settings: &Map<String, Value>, ds: &mut Map<String, Value>) {
    insert_extra_string(xhttp_settings, ds, "path", "path");
    insert_extra_string(xhttp_settings, ds, "host", "host");
    if let Some(Value::Object(headers)) = xhttp_settings.get("headers") {
        if !headers.is_empty() {
            ds.insert("headers".to_owned(), Value::Object(headers.clone()));
        }
    }
    if let Some(Value::Object(xhttp_extra)) = xhttp_settings.get("extra") {
        if let Some(Value::Object(xmux)) = xhttp_extra.get("xmux") {
            insert_reuse_settings(xmux, ds);
        }
    }
}

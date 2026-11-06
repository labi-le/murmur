//! Request-target parsing for the HTTP listener: absolute-form (`http://host/path?query`),
//! origin-form (`/path?query`) and, with `"http://"` prepended, CONNECT authority-form
//! (`host:port`) targets.
//!
//! The shapes are split out rather than run through a full URL parser: scheme extraction, the
//! query cut, authority/host parsing, and a path that passes the original bytes through unchanged
//! once their `%XX` escapes are known-valid (see [`escaped_path`]). A request line carries no
//! `#fragment` (see `hack.rs`), so there is no fragment handling here.

use std::fmt::Write as _;

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// The bytes accepted raw in a host: `unreserved` and `sub-delims` per RFC 3986 §3.2.2, plus
/// `:[]` (a host carries its own port and, for IPv6, its own brackets) and, beyond the RFC
/// grammar, the compatibility bytes `"`, `<`, `>`.
fn is_host_char_allowed(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'"'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'<'
                | b'='
                | b'>'
                | b':'
                | b'['
                | b']'
        )
}

/// The bytes left unescaped in a path: `unreserved`, plus the RFC 3986 §3.3 reserved characters
/// `: @ & = + $ / ; ,` — everything but `?`, which always separates the query.
fn should_escape_path(b: u8) -> bool {
    !(b.is_ascii_alphanumeric()
        || matches!(b, b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'@'))
}

/// Every byte accepted raw in the encoded path beyond what [`should_escape_path`] allows
/// unescaped — `!'()*[]%` — so the original bytes can go on the wire without re-escaping.
fn valid_encoded_path(s: &[u8]) -> bool {
    s.iter().all(|&b| {
        matches!(
            b,
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b',' | b';' | b'=' | b':' | b'@' | b'[' | b']' | b'%'
        ) || !should_escape_path(b)
    })
}

/// The three contexts percent-decoding behaves differently in: a host rejects a raw disallowed
/// byte outright, while a path or user-password only validates that `%XX` escapes are well-formed
/// and passes every other raw byte through.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EscMode {
    Host,
    Path,
    UserPassword,
}

/// Percent-decodes `%XX`, rejecting escapes for ASCII bytes below `0x80` other than the literal
/// `%25` exemption kept for IPv6 zone markers ([`EscMode::Host`] only); path and user-password
/// never reject a raw byte.
fn unescape(s: &str, mode: EscMode) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&current) = bytes.get(i) {
        match current {
            b'%' => {
                let Some([hi_byte, lo_byte]) = bytes.get(i + 1..).and_then(<[u8]>::first_chunk::<2>) else {
                    bail!("invalid URL escape");
                };
                if !hi_byte.is_ascii_hexdigit() || !lo_byte.is_ascii_hexdigit() {
                    bail!("invalid URL escape");
                }
                let hi = hex_val(*hi_byte);
                if mode == EscMode::Host && hi < 8 && bytes.get(i..i + 3) != Some(b"%25".as_slice()) {
                    bail!("invalid URL escape %{}{}", *hi_byte as char, *lo_byte as char);
                }
                out.push((hi << 4) | hex_val(*lo_byte));
                i += 3;
            }
            b if mode == EscMode::Host && b < 0x80 => {
                if !is_host_char_allowed(b) {
                    bail!("invalid character {:?} in host", b as char);
                }
                out.push(b);
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Empty, or `:` followed by ASCII digits only.
fn valid_optional_port(colon_port: &str) -> bool {
    let Some(digits) = colon_port.strip_prefix(':') else { return colon_port.is_empty() };
    digits.bytes().all(|b| b.is_ascii_digit())
}

/// The bytes allowed in a userinfo section.
fn valid_userinfo(s: &str) -> bool {
    s.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
                    | b'@'
            )
    })
}

/// Parses a combined `host[:port]`/`[ipv6]:port` string, without RFC 6874 IPv6 zone-id support:
/// this crate's dialer has no interface to bind a zone id to, so a zone-carrying literal is
/// unescaped as one opaque host string instead of being split into a hostname and zone part.
/// Returns host and port combined, matching what `hack::Request::authority` dials; CONNECT later
/// splits them through [`hostname_and_port`].
///
/// An ambiguous `host:mid:port` always takes the last colon: `a:b:443` is host `a:b` with port
/// `443`.
fn parse_host(host: &str) -> Result<String> {
    if let Some(rest) = host.strip_prefix('[') {
        let Some((hostname, colon_port)) = rest.split_once(']') else { bail!("missing ']' in host") };
        if !valid_optional_port(colon_port) {
            bail!("invalid port {colon_port:?} after host");
        }
        let hostname = unescape(hostname, EscMode::Host)?;
        let addr: std::net::IpAddr = hostname.parse().map_err(|_| anyhow!("invalid host: not an IP literal"))?;
        if addr.is_ipv4() {
            bail!("invalid IP-literal");
        }
        let colon_port = unescape(colon_port, EscMode::Host)?;
        return Ok(format!("[{hostname}]{colon_port}"));
    }
    if host.contains('[') {
        bail!("invalid IP-literal");
    }
    if let Some(last) = host.rfind(':') {
        let (_, colon_port) = host.split_at(last);
        if !valid_optional_port(colon_port) {
            bail!("invalid port {colon_port:?} after host");
        }
    }
    unescape(host, EscMode::Host)
}

/// Splits an already-[`parse_host`]-validated combined `host[:port]` string into a bracket-stripped
/// hostname and an optional numeric port.
fn hostname_and_port(host: &str) -> (String, Option<String>) {
    let mut hostname = host;
    let mut port = None;
    if let Some(colon) = host.rfind(':') {
        let (before, colon_port) = host.split_at(colon);
        if valid_optional_port(colon_port) {
            hostname = before;
            port = colon_port.strip_prefix(':').filter(|p| !p.is_empty()).map(str::to_owned);
        }
    }
    let hostname = hostname.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(hostname);
    (hostname.to_owned(), port)
}

/// Splits `userinfo@host` on the last `@`, validates and decodes the userinfo half, and runs the
/// host half through [`parse_host`].
fn parse_authority(authority: &str) -> Result<(Option<(String, String)>, String)> {
    let Some(at) = authority.rfind('@') else {
        return Ok((None, parse_host(authority)?));
    };
    let (userinfo, after_at) = authority.split_at(at);
    let host = after_at.strip_prefix('@').unwrap_or(after_at);
    if !valid_userinfo(userinfo) {
        bail!("invalid userinfo");
    }
    let user = if let Some((name, pass)) = userinfo.split_once(':') {
        (unescape(name, EscMode::UserPassword)?, unescape(pass, EscMode::UserPassword)?)
    } else {
        (unescape(userinfo, EscMode::UserPassword)?, String::new())
    };
    Ok((Some(user), parse_host(host)?))
}

/// `[a-zA-Z][a-zA-Z0-9+.-]*` up to a `:`, or no scheme at all (returning the input unchanged) the
/// moment a disqualifying byte is seen.
fn get_scheme(raw: &str) -> Result<(String, String)> {
    let bytes = raw.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if i > 0 => {}
            b':' if i > 0 => {
                let (scheme, colon_rest) = raw.split_at(i);
                return Ok((scheme.to_owned(), colon_rest.split_at(1).1.to_owned()));
            }
            b':' => bail!("missing protocol scheme"),
            _ => return Ok((String::new(), raw.to_owned())),
        }
    }
    Ok((String::new(), raw.to_owned()))
}

/// Returns the path bytes to put on the wire. As long as `raw_path`'s `%XX` escapes are
/// individually well-formed and every raw byte it contains is accepted unescaped
/// ([`valid_encoded_path`]), `raw_path` comes back byte-for-byte; only a raw byte that needs
/// escaping forces a rebuild from the decoded path.
fn escaped_path(raw_path: &str) -> Result<String> {
    let decoded = unescape(raw_path, EscMode::Path)?;
    if valid_encoded_path(raw_path.as_bytes()) {
        return Ok(raw_path.to_owned());
    }
    let mut out = String::with_capacity(decoded.len());
    for b in decoded.bytes() {
        if should_escape_path(b) {
            let _ = write!(out, "%{b:02X}");
        } else {
            out.push(b as char);
        }
    }
    Ok(out)
}

/// The result of parsing a request-target, restricted to the shapes a request-target has already
/// been checked to take.
///
/// Absolute-form (`scheme://[userinfo@]host[:port][/path][?query]`), origin-form
/// (`/path[?query]`), and — once the caller prefixes `"http://"` the way `hack::read_request` does
/// for CONNECT — authority-form. `#fragment`, `*` and opaque URLs have no caller in this package
/// (see the module doc).
#[derive(Debug)]
pub struct ParsedRequestUri {
    pub scheme: String,
    /// Empty for origin-form; the caller then falls back to the `Host` header.
    pub host: String,
    pub userinfo: Option<(String, String)>,
    /// The encoded path, plus (`?` + query if the target had a `?`), with `/` for an empty path.
    pub path_and_query: String,
}

pub fn parse_request_uri(raw_url: &str) -> Result<ParsedRequestUri> {
    if raw_url.is_empty() {
        bail!("empty url");
    }

    let (scheme, rest) = get_scheme(raw_url)?;
    let scheme = scheme.to_lowercase();

    let (rest, query) = match rest.split_once('?') {
        Some((before, after)) => (before, Some(after)),
        None => (rest.as_str(), None),
    };

    if !rest.starts_with('/') {
        if scheme.is_empty() {
            bail!("invalid URI for request");
        }
        let path_and_query = query.map_or_else(|| rest.to_owned(), |q| format!("{rest}?{q}"));
        return Ok(ParsedRequestUri { scheme, host: String::new(), userinfo: None, path_and_query });
    }

    let authority = if scheme.is_empty() { None } else { rest.strip_prefix("//") };
    let (host, userinfo, path) = match authority {
        Some(body) => {
            let (authority, remainder) = body.find('/').map_or((body, ""), |i| body.split_at(i));
            let (userinfo, host) = parse_authority(authority)?;
            (host, userinfo, remainder)
        }
        None => (String::new(), None, rest),
    };

    let escaped = escaped_path(path)?;
    let path = if escaped.is_empty() { "/".to_owned() } else { escaped };
    let path_and_query = query.map_or_else(|| path.clone(), |q| format!("{path}?{q}"));
    Ok(ParsedRequestUri { scheme, host, userinfo, path_and_query })
}

/// Parses a CONNECT authority-form target (`host:port`, no scheme, no path) by prepending
/// `"http://"` and running it through the same request-target parser, then splitting the host into
/// hostname and port — CONNECT dials them separately
/// (`adapter/inbound/util.rs::parse_http_addr`), where `hack::Request::authority` keeps them
/// combined for redialing.
pub(crate) fn parse_connect_authority(target: &str) -> Result<(String, Option<String>)> {
    let parsed = parse_request_uri(&format!("http://{target}"))?;
    Ok(hostname_and_port(&parsed.host))
}

/// Builds the Basic `Authorization` header from the URL userinfo when the caller supplied none.
///
/// There is no `Transport`/`Client` layer between parsing a request and forwarding it
/// (`client.rs`'s module doc), so the header is built here, at the one place both the forward path
/// (`proxy.rs::forward`) and the upgrade path (`upgrade.rs::write_request_head`) read
/// `Request::header` from.
#[must_use]
pub fn basic_auth_header(username: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{username}:{password}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each case pins one shape the authority/port split has to handle.

    #[test]
    fn plain_host_port() {
        assert_eq!(
            parse_connect_authority("www.example.com:443").unwrap(),
            ("www.example.com".to_owned(), Some("443".to_owned()))
        );
    }

    #[test]
    fn userinfo_stripped() {
        assert_eq!(parse_connect_authority("u@h:443").unwrap(), ("h".to_owned(), Some("443".to_owned())));
    }

    #[test]
    fn path_after_slash_ignored() {
        assert_eq!(parse_connect_authority("a/b:443").unwrap(), ("a".to_owned(), None));
    }

    #[test]
    fn hash_in_host_rejected() {
        assert!(parse_connect_authority("a#b:443").is_err());
    }

    #[test]
    fn non_numeric_port_rejected() {
        assert!(parse_connect_authority("a:b").is_err());
    }

    #[test]
    fn angle_bracket_accepted() {
        assert_eq!(parse_connect_authority("a<b:443").unwrap(), ("a<b".to_owned(), Some("443".to_owned())));
    }

    #[test]
    fn ipv6_literal() {
        assert_eq!(parse_connect_authority("[::1]:443").unwrap(), ("::1".to_owned(), Some("443".to_owned())));
    }

    #[test]
    fn ipv6_literal_rejects_ipv4() {
        assert!(parse_connect_authority("[127.0.0.1]:443").is_err());
    }

    #[test]
    fn ambiguous_colons_use_the_last_one() {
        assert_eq!(parse_connect_authority("a:b:443").unwrap(), ("a:b".to_owned(), Some("443".to_owned())));
    }

    #[test]
    fn ambiguous_colons_still_reject_a_non_numeric_final_segment() {
        assert!(parse_connect_authority("a:b:c").is_err());
    }

    #[test]
    fn case_preserved() {
        assert_eq!(
            parse_connect_authority("EXAMPLE.com:443").unwrap(),
            ("EXAMPLE.com".to_owned(), Some("443".to_owned()))
        );
    }

    #[test]
    fn host_without_port() {
        assert_eq!(parse_connect_authority("example.com").unwrap(), ("example.com".to_owned(), None));
    }

    // `parse_request_uri` cases, exercising the parser directly rather than through the CONNECT
    // `"http://"` prefix path above.

    #[test]
    fn origin_form_keeps_query() {
        let p = parse_request_uri("/?x=1").unwrap();
        assert_eq!(p.scheme, "");
        assert_eq!(p.host, "");
        assert_eq!(p.path_and_query, "/?x=1");
    }

    #[test]
    fn absolute_form_no_path_defaults_to_slash_and_keeps_query() {
        let p = parse_request_uri("http://B?x=1").unwrap();
        assert_eq!(p.host, "B");
        assert_eq!(p.path_and_query, "/?x=1");
    }

    #[test]
    fn query_marker_stops_authority_parsing() {
        let p = parse_request_uri("http://B?@evil.invalid/a").unwrap();
        assert_eq!(p.host, "B");
        assert_eq!(p.path_and_query, "/?@evil.invalid/a");
    }

    #[test]
    fn userinfo_extracted_and_stripped_from_host() {
        let p = parse_request_uri("http://user@B/a").unwrap();
        assert_eq!(p.host, "B");
        assert_eq!(p.userinfo, Some(("user".to_owned(), String::new())));
        assert_eq!(p.path_and_query, "/a");
    }

    #[test]
    fn scheme_is_lowercased() {
        assert_eq!(parse_request_uri("HTTP://B/a").unwrap().scheme, "http");
    }

    #[test]
    fn non_http_scheme_still_parses() {
        assert_eq!(parse_request_uri("ftp://B/a").unwrap().scheme, "ftp");
    }

    #[test]
    fn hash_in_authority_rejected() {
        assert!(parse_request_uri("http://a#b/x").is_err());
    }

    #[test]
    fn percent_escaped_host_validated() {
        assert!(parse_request_uri("http://%zz/a").is_err());
    }

    #[test]
    fn invalid_path_escape_rejected() {
        assert!(parse_request_uri("http://B/%zz").is_err());
    }

    #[test]
    fn valid_path_escape_round_trips() {
        assert_eq!(parse_request_uri("http://B/%41").unwrap().path_and_query, "/%41");
    }
}

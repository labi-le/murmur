use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use http::HeaderMap;

use super::hack::{split_host_port, Request};

/// Removes `Proxy-*` headers.
pub(crate) fn remove_proxy_headers(header: &mut HeaderMap) {
    header.remove("Proxy-Connection");
    header.remove("Proxy-Authenticate");
    header.remove("Proxy-Authorization");
}

/// Removes hop-by-hop headers.
///
/// Strip hop-by-hop headers based on RFC:
/// <http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.5.1>
/// <https://www.mnot.net/blog/2011/07/11/what_proxies_must_do>
pub(crate) fn remove_hop_by_hop_headers(header: &mut HeaderMap) {
    remove_proxy_headers(header);

    header.remove("TE");
    header.remove("Trailers");
    header.remove("Transfer-Encoding");
    header.remove("Upgrade");

    let connections = header.get("Connection").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
    header.remove("Connection");
    if connections.is_empty() {
        return;
    }
    for h in connections.split(',') {
        header.remove(h.trim());
    }
}

/// Removes an extra host port (`example.com:80` -> `example.com`). It resolves the behaviour of
/// some HTTP servers that do not handle a `host:80` suffix.
pub(crate) fn remove_extra_http_host_port(req: &mut Request) {
    let mut host = if req.host.is_empty() { req.authority.clone() } else { req.host.clone() };
    if let Some((p_host, port)) = split_host_port(&host) {
        if port == "80" {
            let mut new_host = p_host.to_owned();
            if let Ok(ip) = p_host.parse::<std::net::IpAddr>() {
                if matches!(ip, std::net::IpAddr::V6(_)) {
                    // RFC 2617 Sec 3.2.2, for IPv6 literal addresses the Host header needs to
                    // follow the RFC 2732 grammar for "host".
                    new_host = format!("[{new_host}]");
                }
            }
            host = new_host;
        }
    }

    req.host.clone_from(&host);
    req.authority = host;
}

/// Parses the `Proxy-Authorization` header and returns the base64-encoded credential.
pub(crate) fn parse_basic_proxy_authorization(header: &HeaderMap) -> String {
    /// The scheme `Proxy-Authorization` must carry before the credential.
    const PREFIX: &str = "Basic ";
    let value = header.get("Proxy-Authorization").and_then(|v| v.to_str().ok()).unwrap_or_default();
    // According to RFC7617, the scheme should be case-insensitive. In practice, some
    // implementations do use different case styles, causing authentication to fail.
    let scheme = value.get(..PREFIX.len()).unwrap_or_default();
    if !scheme.eq_ignore_ascii_case(PREFIX) {
        return String::new();
    }
    value.get(PREFIX.len()..).unwrap_or_default().to_owned()
}

/// Decodes the base64-encoded credential.
pub(crate) fn decode_basic_proxy_authorization(credential: &str) -> anyhow::Result<(String, String)> {
    let plain = STANDARD.decode(credential)?;
    let plain = String::from_utf8_lossy(&plain);
    match plain.split_once(':') {
        Some((user, pass)) => Ok((user.to_owned(), pass.to_owned())),
        None => Err(anyhow::anyhow!("invalid login")),
    }
}

use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use http_body_util::BodyExt;
use hyper::{header, Method, Response, StatusCode};
use tokio_util::sync::CancellationToken;

use murmur_component::resolver::relay::relay_dns_packet;
use murmur_component::resolver::resolver::{default_dns_timeout, default_resolver};

use super::common::{finish_response, full_body, plain_text, Req, RespBody};

/// The handler accepts every method and dispatches inside itself; [`route`] mirrors that by
/// matching any remaining path (the mount is at a single path, so only the empty segment list is
/// valid).
pub(crate) async fn route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    if !segs.is_empty() {
        return None;
    }
    Some(doh_handler(req).await)
}

/// The maximum size of a DNS message per RFC 8484.
const MAX_DNS_MESSAGE_SIZE: usize = 65535;

async fn doh_handler(req: Req) -> Response<RespBody> {
    if default_resolver().is_none() {
        return plain_text(StatusCode::INTERNAL_SERVER_ERROR, "DNS section is disabled");
    }

    let mut dns_data = match *req.method() {
        Method::GET => {
            let query = req.uri().query().unwrap_or("");
            let dns_param = query.split('&').find_map(|kv| kv.strip_prefix("dns=")).unwrap_or("");
            match URL_SAFE_NO_PAD.decode(dns_param) {
                Ok(data) => data,
                Err(err) => return plain_text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
            }
        }
        Method::POST => {
            let content_type = req.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
            if content_type != "application/dns-message" {
                return plain_text(StatusCode::INTERNAL_SERVER_ERROR, "invalid content-type");
            }
            match read_body_limited(req, MAX_DNS_MESSAGE_SIZE).await {
                Ok(data) => data,
                Err(err) => return plain_text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
            }
        }
        _ => return plain_text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    };

    let ctx = new_timeout_token(default_dns_timeout());
    let payload = dns_data.clone();
    let result = match relay_dns_packet(&ctx, &payload, &mut dns_data).await {
        Ok(data) => data.into_owned(),
        Err(err) => return plain_text(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    };

    let builder = Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, "application/dns-message");
    finish_response(builder, full_body(result))
}

/// A request-scoped DNS deadline. The timer that cancels the token is detached, matching a
/// cancellation that runs once the request completes; this token simply stops mattering once
/// `doh_handler` returns.
fn new_timeout_token(timeout: Duration) -> CancellationToken {
    let token = CancellationToken::new();
    let child = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        child.cancel();
    });
    token
}

/// Reads the body up to `limit` bytes without buffering the full body first.
async fn read_body_limited(req: Req, limit: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut body = req.into_body();
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(std::io::Error::other)?;
        if let Some(chunk) = frame.data_ref() {
            let remaining = limit.saturating_sub(buf.len());
            buf.extend(chunk.iter().copied().take(remaining));
            if buf.len() >= limit {
                break;
            }
        }
    }
    Ok(buf)
}

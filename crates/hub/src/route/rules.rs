use chrono::{DateTime, Utc};
use hyper::{Method, Response, StatusCode};
use serde::Serialize;

use murmur_constant::rule::RuleType;
use murmur_tunnel::tunnel;

use super::common::{json_response, status_only, Req, RespBody};
use super::errors::err_bad_request;
use super::server::embed_mode;

#[derive(Serialize)]
struct Rule {
    index: usize,
    #[serde(rename = "type")]
    type_: String,
    payload: String,
    proxy: String,
    size: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra: Option<RuleExtra>,
}

/// The per-rule counters; `hitAt`/`missAt` are written with the local zone's offset (UTC for the
/// zero time).
#[derive(Serialize)]
struct RuleExtra {
    disabled: bool,
    #[serde(rename = "hitCount")]
    hit_count: u64,
    #[serde(rename = "hitAt", with = "murmur_common::time_rfc3339")]
    hit_at: DateTime<Utc>,
    #[serde(rename = "missCount")]
    miss_count: u64,
    #[serde(rename = "missAt", with = "murmur_common::time_rfc3339")]
    miss_at: DateTime<Utc>,
}

pub(crate) async fn route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    match segs {
        [] => {
            if req.method() != Method::GET {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            Some(get_rules())
        }
        ["disable"] if !embed_mode() => {
            if req.method() != Method::PATCH {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            Some(disable_rules(req).await)
        }
        _ => None,
    }
}

/// A typed struct keeps the field order of the serialized rules; building the body through
/// `serde_json::Value` would sort the keys instead.
#[derive(Serialize)]
struct Rules {
    rules: Vec<Rule>,
}

fn get_rules() -> Response<RespBody> {
    let raw_rules = tunnel::rules();
    let mut rules = Vec::with_capacity(raw_rules.len());
    for (index, rule) in raw_rules.into_iter().enumerate() {
        let mut r = Rule {
            index,
            type_: rule.rule_type().string(),
            payload: rule.payload(),
            proxy: rule.adapter(),
            size: -1,
            extra: None,
        };

        let unwrapped = if let Some(wrapper) = rule.as_rule_wrapper() {
            r.extra = Some(RuleExtra {
                disabled: wrapper.is_disabled(),
                hit_count: wrapper.hit_count(),
                hit_at: wrapper.hit_at(),
                miss_count: wrapper.miss_count(),
                miss_at: wrapper.miss_at(),
            });
            wrapper.unwrap()
        } else {
            rule
        };

        if unwrapped.rule_type() == RuleType::GEOIP || unwrapped.rule_type() == RuleType::GEOSITE {
            r.size = unwrapped.as_rule_group().map_or(-1, murmur_constant::rule::RuleGroup::get_recode_size);
        }

        rules.push(r);
    }

    json_response(StatusCode::OK, &Rules { rules })
}

/// Disables or enables rules by their indexes.
async fn disable_rules(req: Req) -> Response<RespBody> {
    let Ok(payload) =
        super::common::decode_json_body::<Option<std::collections::HashMap<i64, bool>>, _>(req.into_body()).await
    else {
        return json_response(StatusCode::BAD_REQUEST, &err_bad_request());
    };
    let payload = payload.unwrap_or_default();

    if !payload.is_empty() {
        let rules = tunnel::rules();
        for (index, disabled) in payload {
            let Ok(index) = usize::try_from(index) else {
                continue;
            };
            let Some(rule) = rules.get(index) else {
                continue;
            };
            if let Some(wrapper) = rule.as_rule_wrapper() {
                wrapper.set_disabled(disabled);
            }
        }
    }

    super::common::no_content()
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    /// The declaration order of `Rule`/`RuleExtra` is part of the response; assembling the body
    /// through `serde_json::Value` would sort it.
    #[test]
    fn rules_body_keeps_the_declared_field_order() {
        let epoch = DateTime::from_timestamp(0, 0).expect("the epoch is representable");
        let rules = Rules {
            rules: vec![Rule {
                index: 7,
                type_: "RuleSet".to_owned(),
                payload: "payload".to_owned(),
                proxy: "PROXY".to_owned(),
                size: -1,
                extra: Some(RuleExtra { disabled: true, hit_count: 1, hit_at: epoch, miss_count: 2, miss_at: epoch }),
            }],
        };

        let body = String::from_utf8(crate::route::common::encode_json(&rules)).expect("JSON is UTF-8");
        assert_in_order(&body, &["index", "type", "payload", "proxy", "size", "extra"]);
        assert_in_order(&body, &["disabled", "hitCount", "hitAt", "missCount", "missAt"]);
        assert!(body.ends_with("}\n"), "{body}");
    }

    /// `hitAt`/`missAt` carry the local zone's offset.
    #[test]
    fn rule_timestamps_carry_the_local_offset() {
        let epoch = DateTime::from_timestamp(0, 0).expect("the epoch is representable");
        let rules = Rules {
            rules: vec![Rule {
                index: 0,
                type_: "Match".to_owned(),
                payload: String::new(),
                proxy: "DIRECT".to_owned(),
                size: -1,
                extra: Some(RuleExtra { disabled: false, hit_count: 0, hit_at: epoch, miss_count: 0, miss_at: epoch }),
            }],
        };

        let body = String::from_utf8(crate::route::common::encode_json(&rules)).expect("JSON is UTF-8");
        let expected = epoch.with_timezone(&chrono::Local).to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
        assert!(body.contains(&format!("\"hitAt\":\"{expected}\"")), "{body}");
        assert!(body.contains(&format!("\"missAt\":\"{expected}\"")), "{body}");
    }

    fn assert_in_order(body: &str, keys: &[&str]) {
        let mut previous = 0;
        for key in keys {
            let at = body.find(&format!("\"{key}\":")).unwrap_or_else(|| panic!("{key} missing from {body}"));
            assert!(at >= previous, "{key} out of order in {body}");
            previous = at;
        }
    }

    /// Drives `disable_rules` over a real HTTP/1.1 connection (not a hand-built `Req`, which
    /// `hyper::body::Incoming` cannot be) so the request body goes through hyper's own framing
    /// exactly like the live server, and returns the response status and raw JSON bytes.
    async fn patch_rules_disable(body: &[u8]) -> (StatusCode, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener has a local address");
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept loopback connection");
            let svc = service_fn(|req: Req| async move { Ok::<_, Infallible>(disable_rules(req).await) });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(conn), svc).await;
        });

        let mut stream = TcpStream::connect(addr).await.expect("connect to loopback listener");
        let request = format!(
            "PATCH /rules/disable HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.expect("write request head");
        stream.write_all(body).await.expect("write request body");

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");

        let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("response has a header/body split");
        let head = std::str::from_utf8(&raw[..head_end]).expect("response head is ascii");
        let status_str = head.split_whitespace().nth(1).expect("status line has a code");
        let status = StatusCode::from_bytes(status_str.as_bytes()).expect("valid status code");
        (status, raw[head_end + 4..].to_vec())
    }

    /// Only the first JSON value is decoded; bytes after it are not an
    /// error, and an empty `{}` payload never touches `tunnel::rules()`, so this needs no rule
    /// state set up.
    #[tokio::test]
    async fn trailing_garbage_after_the_payload_is_accepted() {
        let (status, body) = patch_rules_disable(b"{}TRAILING GARBAGE, NOT JSON").await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(body.is_empty());
    }

    /// A top-level `null` body decodes into `payload`'s zero value (an empty map), so it is a
    /// no-op: 204, not a decode error.
    #[tokio::test]
    async fn null_body_is_a_no_op() {
        let (status, body) = patch_rules_disable(b"null").await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(body.is_empty());
    }

    /// An empty body is a decode failure and answers 400 `Body invalid`.
    #[tokio::test]
    async fn empty_body_is_a_bad_request() {
        let (status, body) = patch_rules_disable(b"").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(&body[..], b"{\"message\":\"Body invalid\"}\n");
    }

    /// The body is drained on every path, including a failed
    /// decode, so the connection stays usable for the next pipelined request. If a decode error
    /// returned before draining, hyper would see unread request bytes once the handler returns
    /// and close the connection instead of serving the second request.
    #[tokio::test]
    async fn a_decode_error_still_drains_the_body_so_the_connection_stays_usable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener has a local address");
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept loopback connection");
            let svc = service_fn(|req: Req| async move { Ok::<_, Infallible>(disable_rules(req).await) });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(conn), svc).await;
        });
        let mut stream = TcpStream::connect(addr).await.expect("connect to loopback listener");

        let big_invalid: Vec<u8> = std::iter::once(b'n').chain(std::iter::repeat_n(b'x', 2 * 1024 * 1024)).collect();
        for (body, want) in [(&big_invalid[..], StatusCode::BAD_REQUEST), (&b"{}"[..], StatusCode::NO_CONTENT)] {
            let request =
                format!("PATCH /rules/disable HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\r\n", body.len());
            stream.write_all(request.as_bytes()).await.expect("write request head");
            stream.write_all(body).await.expect("write request body");
            assert_eq!(read_one_response(&mut stream).await, want, "second request on the same connection");
        }
    }

    /// Reads exactly one HTTP/1.1 response (status line, headers, `Content-Length` body) off a
    /// connection that stays open, so a second pipelined request/response can follow.
    async fn read_one_response(stream: &mut TcpStream) -> StatusCode {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = std::str::from_utf8(&buf[..head_end]).expect("response head is ascii");
                let status_str = head.split_whitespace().nth(1).expect("status line has a code");
                let status = StatusCode::from_bytes(status_str.as_bytes()).expect("valid status code");
                let content_length: usize = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split_once(':'))
                    .map(|(_, v)| v.trim().parse().expect("content-length is a number"))
                    .unwrap_or(0);
                let body_start = head_end + 4;
                while buf.len() < body_start + content_length {
                    let n = stream.read(&mut chunk).await.expect("read more body");
                    assert!(n > 0, "connection closed before the response body completed");
                    buf.extend_from_slice(&chunk[..n]);
                }
                return status;
            }
            let n = stream.read(&mut chunk).await.expect("read more head");
            assert!(n > 0, "connection closed before the response headers completed");
            buf.extend_from_slice(&chunk[..n]);
        }
    }
}

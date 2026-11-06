//! `hickory-proto` supplies the DNS message types.
//!
//! A record's RDATA text is read directly from `Record<RData>` (`record.data()`) rather than
//! recovered by trimming a header prefix off a combined `Display` string, which is both simpler
//! and immune to any header/rdata separator mismatch between the two libraries' `Display` formats.

use std::str::FromStr;
use std::time::Duration;

use hickory_proto::rr::{Name, Record};
use hyper::{Method, Response, StatusCode};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use murmur_component::resolver::resolver::{default_dns_timeout, default_resolver};
use murmur_dns::util::question;

use super::common::{json_response, status_only, Req, RespBody};
use super::errors::HttpError;
use super::server::query_param;

pub(crate) async fn route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    match segs {
        ["query"] => {
            if req.method() != Method::GET {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            Some(query_dns(&req).await)
        }
        _ => None,
    }
}

#[derive(Serialize)]
struct QuestionJson {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Qtype")]
    qtype: u16,
    #[serde(rename = "Qclass")]
    qclass: u16,
}

#[derive(Serialize)]
struct AnswerJson {
    name: String,
    #[serde(rename = "type")]
    type_: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

fn record_to_json(record: &Record) -> AnswerJson {
    AnswerJson {
        name: record.name.to_string(),
        type_: u16::from(record.record_type()),
        ttl: record.ttl,
        data: record.data.to_string(),
    }
}

async fn query_dns(req: &Req) -> Response<RespBody> {
    let Some(resolver) = default_resolver() else {
        return json_response(StatusCode::INTERNAL_SERVER_ERROR, &HttpError::new("DNS section is disabled"));
    };

    let query = req.uri().query().unwrap_or("");
    let name = query_param(query, "name").unwrap_or_default();
    let q_type_str = query_param(query, "type").unwrap_or_else(|| "A".to_owned());

    let Ok(q_type) = hickory_proto::rr::RecordType::from_str(&q_type_str) else {
        return json_response(StatusCode::BAD_REQUEST, &HttpError::new("invalid query type"));
    };

    let Ok(mut fqdn) = Name::from_utf8(&name) else {
        return json_response(StatusCode::BAD_REQUEST, &HttpError::new("invalid query name"));
    };
    fqdn.set_fqdn(true);

    let msg = question(fqdn, q_type);

    let ctx = new_timeout_token(default_dns_timeout());
    let resp = match resolver.exchange_context(&ctx, &msg).await {
        Ok(resp) => resp,
        Err(err) => return json_response(StatusCode::INTERNAL_SERVER_ERROR, &HttpError::new(err.to_string())),
    };

    let mut payload = serde_json::Map::new();
    payload.insert("Status".to_owned(), serde_json::json!(u16::from(resp.metadata.response_code)));
    payload.insert(
        "Question".to_owned(),
        serde_json::json!(resp
            .queries
            .iter()
            .map(|q| QuestionJson {
                name: q.name().to_string(),
                qtype: u16::from(q.query_type()),
                qclass: u16::from(q.query_class()),
            })
            .collect::<Vec<_>>()),
    );
    payload.insert("TC".to_owned(), serde_json::json!(resp.metadata.truncation));
    payload.insert("RD".to_owned(), serde_json::json!(resp.metadata.recursion_desired));
    payload.insert("RA".to_owned(), serde_json::json!(resp.metadata.recursion_available));
    payload.insert("AD".to_owned(), serde_json::json!(resp.metadata.authentic_data));
    payload.insert("CD".to_owned(), serde_json::json!(resp.metadata.checking_disabled));

    if !resp.answers.is_empty() {
        payload.insert(
            "Answer".to_owned(),
            serde_json::json!(resp.answers.iter().map(record_to_json).collect::<Vec<_>>()),
        );
    }
    if !resp.authorities.is_empty() {
        payload.insert(
            "Authority".to_owned(),
            serde_json::json!(resp.authorities.iter().map(record_to_json).collect::<Vec<_>>()),
        );
    }
    if !resp.additionals.is_empty() {
        payload.insert(
            "Additional".to_owned(),
            serde_json::json!(resp.additionals.iter().map(record_to_json).collect::<Vec<_>>()),
        );
    }

    json_response(StatusCode::OK, &payload)
}

/// A request-scoped DNS deadline plus its cancellation; see `doh.rs`'s identical helper for why
/// the timer is detached instead.
fn new_timeout_token(timeout: Duration) -> CancellationToken {
    let token = CancellationToken::new();
    let child = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        child.cancel();
    });
    token
}

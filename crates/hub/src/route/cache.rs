//! The `/cache` mount: flush endpoints for the fake-IP pool and the DNS cache.
//!
//! [`route`] receives the path segments left after the `/cache` prefix is stripped (see
//! `server.rs`'s module doc).

use hyper::{Method, Response, StatusCode};

use murmur_component::resolver::enhancer::flush_fake_ip;
use murmur_component::resolver::resolver::clear_cache;

use super::common::{no_content, status_only, Req, RespBody};
use super::errors::HttpError;

#[expect(
    clippy::unused_async,
    reason = "the mount entry point is awaited by the shared dispatcher in `server.rs`; every handler behind it is synchronous"
)]
pub(crate) async fn route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    match segs {
        ["fakeip", "flush"] => Some(flush_fake_ip_pool(&req)),
        ["dns", "flush"] => Some(flush_dns_cache(&req)),
        _ => None,
    }
}

fn flush_fake_ip_pool(req: &Req) -> Response<RespBody> {
    if req.method() != Method::POST {
        return status_only(StatusCode::METHOD_NOT_ALLOWED);
    }
    match flush_fake_ip() {
        Ok(()) => no_content(),
        Err(err) => super::common::json_response(StatusCode::BAD_REQUEST, &HttpError::new(err.to_string())),
    }
}

fn flush_dns_cache(req: &Req) -> Response<RespBody> {
    if req.method() != Method::POST {
        return status_only(StatusCode::METHOD_NOT_ALLOWED);
    }
    clear_cache();
    no_content()
}

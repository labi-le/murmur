use http_body_util::BodyExt;
use hyper::{header, Method, Response, StatusCode};

use super::common::{
    finish_response, full_body, get_escape_param, json_response, no_content, status_only, Req, RespBody,
};
use super::errors::{err_bad_request, HttpError};

pub(crate) async fn route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    match segs {
        [key] => {
            let key = get_escape_param(key);
            match *req.method() {
                Method::GET => Some(get_storage(&key)),
                Method::PUT => Some(set_storage(req, &key).await),
                Method::DELETE => Some(delete_storage(&key)),
                _ => Some(status_only(StatusCode::METHOD_NOT_ALLOWED)),
            }
        }
        _ => None,
    }
}

fn get_storage(key: &str) -> Response<RespBody> {
    let data = murmur_component_profile::cachefile::cache::cache().get_storage(key);
    let body = match data {
        Some(data) if !data.is_empty() => data,
        _ => b"null".to_vec(),
    };
    let builder = Response::builder().header(header::CONTENT_TYPE, "application/json");
    finish_response(builder, full_body(body))
}

async fn set_storage(req: Req, key: &str) -> Response<RespBody> {
    let data = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => return json_response(StatusCode::BAD_REQUEST, &HttpError::new(err.to_string())),
    };

    if serde_json::from_slice::<serde_json::Value>(&data).is_err() {
        return json_response(StatusCode::BAD_REQUEST, &err_bad_request());
    }
    if data.len() > 1024 * 1024 {
        return json_response(StatusCode::PAYLOAD_TOO_LARGE, &HttpError::new("payload exceeds 1MB limit"));
    }

    murmur_component_profile::cachefile::cache::cache().set_storage(key, &data);
    no_content()
}

fn delete_storage(key: &str) -> Response<RespBody> {
    murmur_component_profile::cachefile::cache::cache().delete_storage(key);
    no_content()
}

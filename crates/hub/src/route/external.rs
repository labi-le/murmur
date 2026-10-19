//! The external-router registry: other crates can mount permanent routes onto the API's route
//! table while it is being built.
//!
//! Each registered router receives one already-buffered request and returns `None` when it does not
//! want to handle it, which the caller turns into a 404.
//!
//! `Request<Incoming>` is not `Clone`, so the request is converted to an [`ExternalRequest`]
//! (its body already read into `Bytes`) once, and offered to each registered router in turn until
//! one claims it.

use std::sync::Arc;

use bytes::Bytes;
use futures::future::BoxFuture;
use http_body_util::BodyExt;
use hyper::{HeaderMap, Method, Response, Uri};
use parking_lot::RwLock;

use super::common::{Req, RespBody};

/// A cloneable snapshot of the request, since every registered router gets a chance to claim the
/// same one.
#[derive(Clone, Debug)]
pub struct ExternalRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
}

pub type ExternalRouter = Arc<dyn Fn(ExternalRequest) -> BoxFuture<'static, Option<Response<RespBody>>> + Send + Sync>;

static EXTERNAL_ROUTERS: RwLock<Vec<ExternalRouter>> = RwLock::new(Vec::new());

pub fn register(routes: Vec<ExternalRouter>) {
    EXTERNAL_ROUTERS.write().extend(routes);
}

/// Returns `None` if no registered router claimed the request, so the caller answers a 404.
pub(crate) async fn add_external_routers(req: Req) -> Option<Response<RespBody>> {
    let routers = EXTERNAL_ROUTERS.read().clone();
    if routers.is_empty() {
        return None;
    }

    let (parts, body) = req.into_parts();
    let body = body.collect().await.map(http_body_util::Collected::to_bytes).unwrap_or_default();
    let external_req = ExternalRequest { method: parts.method, uri: parts.uri, headers: parts.headers, body };

    for router in routers {
        if let Some(resp) = router(external_req.clone()).await {
            return Some(resp);
        }
    }
    None
}

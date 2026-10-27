//! The realm routes distinguish an unknown path (404) from a wrong method on a known path (405).
//!
//! [`route_for`] reproduces that split by matching the path's segments directly, the same
//! convention `hub::route::server` uses. The event-stream response goes through
//! [`ChannelBody`], the adapter `hub::route::common` and `transport::xhttp::server` already use
//! for the same purpose.
//!
//! DEVIATION: `connect` also selects on the request context's cancellation to return early when
//! the client gives up; hyper exposes no per-request cancellation signal here, so that branch is
//! dropped and a client that disconnects simply waits out `connect_response_timeout` on the
//! server side.

use std::convert::Infallible;
use std::error::Error as StdError;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::{Body, Frame};
use hyper::{header, Request, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::debugf;
use super::session::{PunchResponsePayload, RegisterOutcome, Server, Session, SessionEvent, SESSION_TTL};
use super::validate::{
    bearer, client_ip, error_body, validate_addresses, validate_hex_field, ERR_ATTEMPT_NOT_FOUND, ERR_BAD_REQUEST,
    ERR_INVALID_TOKEN, ERR_IP_LIMIT, ERR_NOT_FOUND, ERR_RATE_LIMITED, ERR_REALM_LIMIT, ERR_REALM_NOT_FOUND,
    ERR_REALM_TAKEN, NONCE_HEX_LENGTH, OBFS_HEX_LENGTH,
};

pub const MAX_REQUEST_BODY_BYTES: usize = 4 << 10;

/// The event-stream response body's backpressure limit.
const SSE_CHANNEL_CAPACITY: usize = 4;

pub type RespBody = BoxBody<Bytes, Infallible>;

#[derive(Debug, Serialize)]
struct PunchEvent {
    addresses: Vec<String>,
    nonce: String,
    obfs: String,
}

/// `register`'s request body.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AddressesReq {
    addresses: Option<Vec<String>>,
}

/// `connect`'s request body.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ConnectReq {
    addresses: Option<Vec<String>>,
    nonce: String,
    obfs: String,
}

/// `heartbeat`'s request body: `None` distinguishes an absent/null `addresses` from an explicitly
/// empty list, which is validated (and rejected) before the session is updated.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HeartbeatReq {
    addresses: Option<Vec<String>>,
}

fn check_realm_token<B>(server: &Server, req: &Request<B>) -> bool {
    !server.realm_token.is_empty() && bearer(&header_value(req, "authorization")) == server.realm_token
}

fn request_ip<B>(server: &Server, remote_addr: &str, req: &Request<B>) -> String {
    let value = if server.proxy_header.is_empty() { String::new() } else { header_value(req, &server.proxy_header) };
    client_ip(remote_addr, &server.proxy_header, &value)
}

/// The first header value for `name`, matched case-insensitively.
fn header_value<B>(req: &Request<B>, name: &str) -> String {
    req.headers()
        .iter()
        .find(|(k, _)| k.as_str().eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

enum Route {
    Register(String),
    Deregister(String),
    Events(String),
    Heartbeat(String),
    Connect(String),
    ConnectResponse(String, String),
    MethodNotAllowed,
    NotFound,
}

fn route_for(segments: &[&str], method: &str) -> Route {
    match segments {
        ["v1", id] if !id.is_empty() => match method {
            "POST" => Route::Register((*id).to_owned()),
            "DELETE" => Route::Deregister((*id).to_owned()),
            _ => Route::MethodNotAllowed,
        },
        ["v1", id, "events"] if !id.is_empty() => {
            if method == "GET" {
                Route::Events((*id).to_owned())
            } else {
                Route::MethodNotAllowed
            }
        }
        ["v1", id, "heartbeat"] if !id.is_empty() => {
            if method == "POST" {
                Route::Heartbeat((*id).to_owned())
            } else {
                Route::MethodNotAllowed
            }
        }
        ["v1", id, "connect"] if !id.is_empty() => {
            if method == "POST" {
                Route::Connect((*id).to_owned())
            } else {
                Route::MethodNotAllowed
            }
        }
        ["v1", id, "connects", nonce] if !id.is_empty() && !nonce.is_empty() => {
            if method == "POST" {
                Route::ConnectResponse((*id).to_owned(), (*nonce).to_owned())
            } else {
                Route::MethodNotAllowed
            }
        }
        _ => Route::NotFound,
    }
}

/// The route dispatch.
pub async fn serve<B>(server: Arc<Server>, remote_addr: String, req: Request<B>) -> Response<RespBody>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let segments: Vec<&str> = req.uri().path().strip_prefix('/').map(|p| p.split('/').collect()).unwrap_or_default();
    let method = req.method().as_str().to_owned();
    match route_for(&segments, &method) {
        Route::Register(id) => register(server, remote_addr, id, req).await,
        Route::Deregister(id) => deregister(server, remote_addr, id, req).await,
        Route::Events(id) => events(server, remote_addr, id, req).await,
        Route::Heartbeat(id) => heartbeat(server, remote_addr, id, req).await,
        Route::Connect(id) => connect(server, remote_addr, id, req).await,
        Route::ConnectResponse(id, nonce) => connect_response(server, remote_addr, id, nonce, req).await,
        Route::MethodNotAllowed => write_err(StatusCode::METHOD_NOT_ALLOWED, ERR_BAD_REQUEST, "method not allowed"),
        Route::NotFound => write_err(StatusCode::NOT_FOUND, ERR_NOT_FOUND, "unknown path"),
    }
}

async fn register<B>(server: Arc<Server>, remote_addr: String, id: String, req: Request<B>) -> Response<RespBody>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    if !server.realm_id_pattern.is_match(&id) {
        return write_err(StatusCode::BAD_REQUEST, ERR_BAD_REQUEST, "invalid realm name");
    }
    let remote = request_ip(&server, &remote_addr, &req);
    if !check_realm_token(&server, &req) {
        debugf(format!("register unauthorized realm={id} remote={remote}"));
        return write_err(StatusCode::UNAUTHORIZED, ERR_INVALID_TOKEN, "invalid realm token");
    }
    let addresses = match read_json::<B, AddressesReq>(req).await {
        JsonBody::Value(req) => req.addresses.unwrap_or_default(),
        JsonBody::Null => Vec::new(),
        JsonBody::Empty | JsonBody::Invalid => {
            return write_err(StatusCode::BAD_REQUEST, ERR_BAD_REQUEST, "invalid json")
        }
    };
    if let Err(err) = validate_addresses(&addresses) {
        return write_err(StatusCode::BAD_REQUEST, ERR_BAD_REQUEST, &err.to_string());
    }
    let address_count = addresses.len();
    match server.register(&id, addresses, remote.clone()) {
        RegisterOutcome::Registered(sess) => {
            debugf(format!("registered realm={id} session={} addresses={address_count} remote={remote}", sess.id));
            write_json(StatusCode::OK, &json!({ "session_id": sess.id, "ttl": SESSION_TTL.as_secs() }))
        }
        RegisterOutcome::Taken => {
            debugf(format!("register conflict realm={id} remote={remote}"));
            write_err(StatusCode::CONFLICT, ERR_REALM_TAKEN, "realm already registered")
        }
        RegisterOutcome::RealmLimit => {
            debugf(format!("register rejected (global limit) realm={id} remote={remote}"));
            write_err(StatusCode::TOO_MANY_REQUESTS, ERR_REALM_LIMIT, "global realm limit reached")
        }
        RegisterOutcome::IpLimit => {
            debugf(format!("register rejected (per-ip limit) realm={id} remote={remote}"));
            write_err(StatusCode::TOO_MANY_REQUESTS, ERR_IP_LIMIT, "per-ip realm limit reached")
        }
    }
}

#[expect(clippy::unused_async, reason = "every route handler is async so `serve` awaits them uniformly")]
async fn deregister<B>(server: Arc<Server>, remote_addr: String, id: String, req: Request<B>) -> Response<RespBody> {
    let remote = request_ip(&server, &remote_addr, &req);
    let token = bearer(&header_value(&req, "authorization"));
    let Some(sess) = server.get_session_by_token(&token).filter(|sess| sess.realm_id == id) else {
        debugf(format!("deregister unauthorized realm={id} remote={remote}"));
        return write_err(StatusCode::UNAUTHORIZED, ERR_INVALID_TOKEN, "invalid session token");
    };
    debugf(format!("deregistered realm={id} session={} remote={remote}", sess.id));
    server.remove_session(&sess);
    status_only(StatusCode::NO_CONTENT)
}

async fn heartbeat<B>(server: Arc<Server>, remote_addr: String, id: String, req: Request<B>) -> Response<RespBody>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let remote = request_ip(&server, &remote_addr, &req);
    let token = bearer(&header_value(&req, "authorization"));
    let Some(sess) = server.get_session_by_token(&token).filter(|sess| sess.realm_id == id) else {
        debugf(format!("heartbeat unauthorized realm={id} remote={remote}"));
        return write_err(StatusCode::UNAUTHORIZED, ERR_INVALID_TOKEN, "invalid session token");
    };
    let addresses = match read_json::<B, HeartbeatReq>(req).await {
        JsonBody::Value(req) => req.addresses,
        JsonBody::Null | JsonBody::Empty => None,
        JsonBody::Invalid => return write_err(StatusCode::BAD_REQUEST, ERR_BAD_REQUEST, "invalid json"),
    };
    if let Some(addresses) = &addresses {
        if let Err(err) = validate_addresses(addresses) {
            return write_err(StatusCode::BAD_REQUEST, ERR_BAD_REQUEST, &err.to_string());
        }
    }
    if sess.is_closed() {
        debugf(format!("heartbeat closed realm={id} session={} remote={remote}", sess.id));
        return write_err(StatusCode::UNAUTHORIZED, ERR_INVALID_TOKEN, "invalid session token");
    }
    sess.touch(SESSION_TTL);
    let addresses_updated = addresses.is_some();
    if let Some(addresses) = addresses {
        sess.set_addresses(addresses);
    }
    debugf(format!("heartbeat realm={id} session={} addressesUpdated={addresses_updated} remote={remote}", sess.id));
    let ttl = ttl_seconds();
    if !server.send_event(&sess, SessionEvent { kind: "heartbeat_ack".to_owned(), data: json!({ "ttl": ttl }) }) {
        debugf(format!("heartbeat ack dropped realm={id} session={} remote={remote}", sess.id));
    }
    write_json(StatusCode::OK, &json!({ "ttl": ttl }))
}

#[expect(clippy::unused_async, reason = "every route handler is async so `serve` awaits them uniformly")]
#[expect(
    clippy::significant_drop_tightening,
    reason = "the guard spans the spawned drain loop, so `tokio::select!`'s expansion cannot drop it earlier"
)]
async fn events<B>(server: Arc<Server>, remote_addr: String, id: String, req: Request<B>) -> Response<RespBody> {
    let remote = request_ip(&server, &remote_addr, &req);
    let token = bearer(&header_value(&req, "authorization"));
    let Some(sess) = server.get_session_by_token(&token).filter(|sess| sess.realm_id == id) else {
        debugf(format!("events unauthorized realm={id} remote={remote}"));
        return write_err(StatusCode::UNAUTHORIZED, ERR_INVALID_TOKEN, "invalid session token");
    };
    debugf(format!("events connected realm={id} session={} remote={remote}", sess.id));

    let (tx, body) = channel_body(SSE_CHANNEL_CAPACITY);
    let task_sess = Arc::clone(&sess);
    // cancel-safe: the task only drains an already-buffered event queue, so a drop just ends the SSE body.
    tokio::spawn(async move {
        let mut rx = task_sess.events_rx.lock().await;
        loop {
            tokio::select! {
                () = task_sess.done.cancelled() => {
                    debugf(format!("events closed realm={id} session={} remote={remote}", task_sess.id));
                    break;
                }
                () = tx.closed() => {
                    debugf(format!("events disconnected realm={id} session={} remote={remote}", task_sess.id));
                    break;
                }
                ev = rx.recv() => match ev {
                    Some(ev) => {
                        let data = serde_json::to_string(&ev.data).unwrap_or_else(|_| "null".to_owned());
                        if tx.send(Bytes::from(format!("event: {}\ndata: {data}\n\n", ev.kind))).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
            }
        }
    });

    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("text/event-stream"));
    headers.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-cache"));
    headers.insert(header::CONNECTION, header::HeaderValue::from_static("keep-alive"));
    response
}

// cancel-safe: `PendingGuard` removes the pending entry on drop, so a cancelled connect leaves no state behind.
async fn connect<B>(server: Arc<Server>, remote_addr: String, id: String, req: Request<B>) -> Response<RespBody>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let remote = request_ip(&server, &remote_addr, &req);
    if !check_realm_token(&server, &req) {
        debugf(format!("connect unauthorized realm={id} remote={remote}"));
        return write_err(StatusCode::UNAUTHORIZED, ERR_INVALID_TOKEN, "invalid realm token");
    }
    let body = match read_json::<B, ConnectReq>(req).await {
        JsonBody::Value(req) => req,
        JsonBody::Null => ConnectReq::default(),
        JsonBody::Empty | JsonBody::Invalid => {
            return write_err(StatusCode::BAD_REQUEST, ERR_BAD_REQUEST, "invalid json")
        }
    };
    let client_addresses = body.addresses.unwrap_or_default();
    if let Err(err) = validate_addresses(&client_addresses) {
        return write_err(StatusCode::BAD_REQUEST, ERR_BAD_REQUEST, &err.to_string());
    }
    if let Err(err) = validate_hex_field("nonce", &body.nonce, NONCE_HEX_LENGTH) {
        return write_err(StatusCode::BAD_REQUEST, ERR_BAD_REQUEST, &err.to_string());
    }
    if let Err(err) = validate_hex_field("obfs", &body.obfs, OBFS_HEX_LENGTH) {
        return write_err(StatusCode::BAD_REQUEST, ERR_BAD_REQUEST, &err.to_string());
    }

    let Some(sess) = server.realm_session(&id) else {
        debugf(format!("connect realm not found realm={id} remote={remote}"));
        return write_err(StatusCode::NOT_FOUND, ERR_REALM_NOT_FOUND, "realm not registered");
    };
    let mut server_addresses = sess.addresses();

    // The pending entry must exist before the punch event can be answered, so a fast hysteria
    // server can never deliver its addresses before the connect request is ready to receive them.
    let Some(rx) = server.register_pending(&sess, &body.nonce) else {
        debugf(format!("connect rate limited (pending) realm={id} session={} remote={remote}", sess.id));
        return write_err(StatusCode::SERVICE_UNAVAILABLE, ERR_RATE_LIMITED, "too many in-flight connect attempts");
    };
    let _pending = PendingGuard { server: Arc::clone(&server), sess: Arc::clone(&sess), nonce: body.nonce.clone() };

    let punch = PunchEvent { addresses: client_addresses.clone(), nonce: body.nonce.clone(), obfs: body.obfs.clone() };
    let data = serde_json::to_value(&punch).unwrap_or(Value::Null);
    if server.send_event(&sess, SessionEvent { kind: "punch".to_owned(), data }) {
        debugf(format!(
            "connect notified realm={id} session={} clientAddresses={} serverAddresses={} remote={remote}",
            sess.id,
            client_addresses.len(),
            server_addresses.len()
        ));
    } else {
        debugf(format!("connect rate limited realm={id} session={} remote={remote}", sess.id));
        return write_err(StatusCode::SERVICE_UNAVAILABLE, ERR_RATE_LIMITED, "server event buffer full");
    }

    tokio::select! {
        payload = rx => if let Ok(payload) = payload {
            if !payload.addresses.is_empty() {
                debugf(format!(
                    "connect fresh addresses realm={id} session={} addresses={} remote={remote}",
                    sess.id,
                    payload.addresses.len()
                ));
                server_addresses = payload.addresses;
            }
        } else {
            debugf(format!("connect canceled realm={id} session={} remote={remote}", sess.id));
            return write_err(StatusCode::NOT_FOUND, ERR_REALM_NOT_FOUND, "realm not registered");
        },
        () = tokio::time::sleep(server.connect_response_timeout) => {
            debugf(format!("connect response timed out realm={id} session={} remote={remote}", sess.id));
        }
        () = sess.done.cancelled() => {
            debugf(format!("connect canceled realm={id} session={} remote={remote}", sess.id));
            return write_err(StatusCode::NOT_FOUND, ERR_REALM_NOT_FOUND, "realm not registered");
        }
    }

    write_json(StatusCode::OK, &json!({ "addresses": server_addresses, "nonce": body.nonce, "obfs": body.obfs }))
}

async fn connect_response<B>(
    server: Arc<Server>,
    remote_addr: String,
    id: String,
    nonce: String,
    req: Request<B>,
) -> Response<RespBody>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let remote = request_ip(&server, &remote_addr, &req);
    if let Err(err) = validate_hex_field("nonce", &nonce, NONCE_HEX_LENGTH) {
        return write_err(StatusCode::BAD_REQUEST, ERR_BAD_REQUEST, &err.to_string());
    }
    let token = bearer(&header_value(&req, "authorization"));
    let Some(sess) = server.get_session_by_token(&token).filter(|sess| sess.realm_id == id) else {
        debugf(format!("connect-response unauthorized realm={id} remote={remote}"));
        return write_err(StatusCode::UNAUTHORIZED, ERR_INVALID_TOKEN, "invalid session token");
    };
    let addresses = match read_json::<B, AddressesReq>(req).await {
        JsonBody::Value(req) => req.addresses.unwrap_or_default(),
        JsonBody::Null => Vec::new(),
        JsonBody::Empty | JsonBody::Invalid => {
            return write_err(StatusCode::BAD_REQUEST, ERR_BAD_REQUEST, "invalid json")
        }
    };
    if let Err(err) = validate_addresses(&addresses) {
        return write_err(StatusCode::BAD_REQUEST, ERR_BAD_REQUEST, &err.to_string());
    }
    let address_count = addresses.len();
    if !server.deliver_pending(&sess, &nonce, PunchResponsePayload { addresses }) {
        debugf(format!("connect-response no pending realm={id} session={} nonce={nonce} remote={remote}", sess.id));
        return write_err(StatusCode::NOT_FOUND, ERR_ATTEMPT_NOT_FOUND, "no pending attempt for nonce");
    }
    debugf(format!(
        "connect-response delivered realm={id} session={} addresses={address_count} remote={remote}",
        sess.id
    ));
    status_only(StatusCode::NO_CONTENT)
}

struct PendingGuard {
    server: Arc<Server>,
    sess: Arc<Session>,
    nonce: String,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.server.cancel_pending(&self.sess, &self.nonce);
    }
}

enum JsonBody<T> {
    Value(T),
    /// Decoding a `null` body leaves the target untouched, which is not the same as the EOF an
    /// empty body produces.
    Null,
    Empty,
    Invalid,
}

/// The body limit is enforced on read, and only the first JSON value is consumed.
async fn read_json<B, T>(req: Request<B>) -> JsonBody<T>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    T: DeserializeOwned,
{
    match Limited::new(req.into_body(), MAX_REQUEST_BODY_BYTES).collect().await {
        Ok(collected) => decode_json(&collected.to_bytes()),
        Err(_) => JsonBody::Invalid,
    }
}

fn decode_json<T: DeserializeOwned>(bytes: &[u8]) -> JsonBody<T> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return JsonBody::Empty;
    }
    match Option::<T>::deserialize(&mut serde_json::Deserializer::from_slice(bytes)) {
        Ok(Some(value)) => JsonBody::Value(value),
        Ok(None) => JsonBody::Null,
        Err(_) => JsonBody::Invalid,
    }
}

fn ttl_seconds() -> u64 {
    SESSION_TTL.as_secs()
}

fn body_from(bytes: Bytes) -> RespBody {
    Full::new(bytes).boxed()
}

fn write_err(status: StatusCode, code: &str, message: &str) -> Response<RespBody> {
    json_response(status, &error_body(code, message))
}

fn write_json(status: StatusCode, value: &Value) -> Response<RespBody> {
    json_response(status, &value.to_string())
}

/// The encoded document terminates with a newline.
fn json_response(status: StatusCode, body: &str) -> Response<RespBody> {
    let mut response = Response::new(body_from(Bytes::from(format!("{body}\n"))));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
    response
}

fn status_only(status: StatusCode) -> Response<RespBody> {
    let mut response = Response::new(Empty::<Bytes>::new().boxed());
    *response.status_mut() = status;
    response
}

/// Stands in for `http_body_util::channel::Channel`, whose `channel` Cargo feature this dependency
/// set does not enable; see `hub::route::common`'s identical adapter.
struct ChannelBody {
    rx: mpsc::Receiver<Bytes>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.rx.poll_recv(cx).map(|chunk| chunk.map(|chunk| Ok(Frame::data(chunk))))
    }
}

fn channel_body(buffer: usize) -> (mpsc::Sender<Bytes>, RespBody) {
    let (tx, rx) = mpsc::channel(buffer);
    (tx, ChannelBody { rx }.boxed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hysteria2_realm::session::{new_server, ServerConfig, EVENTS_BUFFER_SIZE, MAX_PENDING_ATTEMPTS};
    use hyper::Method;

    const PEER: &str = "192.0.2.100:5555";
    const PEER2: &str = "192.0.2.101:5555";
    const TOKEN: &str = "realm-token";
    const NONCE: &str = "0102030405060708090a0b0c0d0e0f10";
    const OBFS: &str = "0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10";

    fn test_server(configure: impl FnOnce(&mut ServerConfig)) -> Arc<Server> {
        let mut cfg = ServerConfig { realm_token: TOKEN.to_owned(), ..Default::default() };
        configure(&mut cfg);
        Arc::new(new_server(cfg))
    }

    fn request(method: Method, path: &str, token: Option<&str>, body: &str) -> Request<Full<Bytes>> {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(Full::new(Bytes::copy_from_slice(body.as_bytes()))).expect("request")
    }

    async fn call(server: &Arc<Server>, peer: &str, req: Request<Full<Bytes>>) -> Response<RespBody> {
        serve(Arc::clone(server), peer.to_owned(), req).await
    }

    async fn body_bytes(resp: Response<RespBody>) -> Bytes {
        resp.into_body().collect().await.expect("body").to_bytes()
    }

    async fn body_json(resp: Response<RespBody>) -> Value {
        let bytes = body_bytes(resp).await;
        serde_json::from_slice(&bytes).unwrap_or_else(|err| panic!("json body {bytes:?}: {err}"))
    }

    async fn register_realm(server: &Arc<Server>, peer: &str, id: &str) -> String {
        let resp = call(
            server,
            peer,
            request(Method::POST, &format!("/v1/{id}"), Some(TOKEN), r#"{"addresses":["203.0.113.5:1000"]}"#),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        body_json(resp).await["session_id"].as_str().expect("session_id").to_owned()
    }

    #[tokio::test]
    async fn unknown_paths_and_wrong_methods_are_distinguished() {
        let server = test_server(|_| {});

        let not_found = call(&server, PEER, request(Method::GET, "/nope", None, "")).await;
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_json(not_found).await, json!({ "error": ERR_NOT_FOUND, "message": "unknown path" }));

        for (method, path) in [
            (Method::GET, "/v1/realm"),
            (Method::POST, "/v1/realm/events"),
            (Method::GET, "/v1/realm/heartbeat"),
            (Method::GET, "/v1/realm/connect"),
            (Method::GET, &format!("/v1/realm/connects/{NONCE}")),
        ] {
            let resp = call(&server, PEER, request(method.clone(), path, None, "")).await;
            assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
            assert_eq!(body_json(resp).await, json!({ "error": ERR_BAD_REQUEST, "message": "method not allowed" }));
        }

        // A path parameter needs at least one character, so a trailing slash is an unknown path
        // rather than a method mismatch.
        for path in ["/v1/", "/v1/realm/connects/"] {
            let resp = call(&server, PEER, request(Method::POST, path, None, "")).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
            assert_eq!(body_json(resp).await, json!({ "error": ERR_NOT_FOUND, "message": "unknown path" }));
        }
    }

    #[tokio::test]
    async fn register_validates_realm_name_token_and_body() {
        let server = test_server(|_| {});

        let bad_name = call(&server, PEER, request(Method::POST, "/v1/-bad!", Some(TOKEN), "{}")).await;
        assert_eq!(bad_name.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(bad_name).await["message"], "invalid realm name");

        let no_token = call(&server, PEER, request(Method::POST, "/v1/realm", None, "{}")).await;
        assert_eq!(no_token.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(no_token).await["error"], ERR_INVALID_TOKEN);

        let bad_json = call(&server, PEER, request(Method::POST, "/v1/realm", Some(TOKEN), "{")).await;
        assert_eq!(bad_json.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(bad_json).await["message"], "invalid json");

        let empty = call(&server, PEER, request(Method::POST, "/v1/realm", Some(TOKEN), "{}")).await;
        assert_eq!(body_json(empty).await["message"], "at least one address required");

        // the `Decode` leaves the target untouched for a `null` body, so this is the zero value
        // (no addresses) rather than the decode failure an empty body is.
        let null_body = call(&server, PEER, request(Method::POST, "/v1/realm", Some(TOKEN), "null")).await;
        assert_eq!(null_body.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(null_body).await["message"], "at least one address required");

        let oversized = call(
            &server,
            PEER,
            request(
                Method::POST,
                "/v1/realm",
                Some(TOKEN),
                &format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_REQUEST_BODY_BYTES)),
            ),
        )
        .await;
        assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(oversized).await["message"], "invalid json");

        let too_many = format!(
            r#"{{"addresses":[{}]}}"#,
            (0..9).map(|i| format!("\"203.0.113.5:{}\"", 1000 + i)).collect::<Vec<_>>().join(",")
        );
        let overflow = call(&server, PEER, request(Method::POST, "/v1/realm", Some(TOKEN), &too_many)).await;
        assert_eq!(body_json(overflow).await["message"], "too many addresses (max 8)");

        register_realm(&server, PEER, "realm").await;
        let taken = call(
            &server,
            PEER2,
            request(Method::POST, "/v1/realm", Some(TOKEN), r#"{"addresses":["203.0.113.5:1000"]}"#),
        )
        .await;
        assert_eq!(taken.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(taken).await["error"], ERR_REALM_TAKEN);
    }

    #[tokio::test]
    async fn register_enforces_global_and_per_ip_limits() {
        let server = test_server(|cfg| {
            cfg.max_realms = 2;
            cfg.max_realms_per_ip = 1;
        });
        register_realm(&server, PEER, "realm-a").await;

        let per_ip = call(
            &server,
            PEER,
            request(Method::POST, "/v1/realm-b", Some(TOKEN), r#"{"addresses":["203.0.113.5:1000"]}"#),
        )
        .await;
        assert_eq!(per_ip.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body_json(per_ip).await["error"], ERR_IP_LIMIT);

        register_realm(&server, PEER2, "realm-b").await;
        let global = call(
            &server,
            PEER2,
            request(Method::POST, "/v1/realm-c", Some(TOKEN), r#"{"addresses":["203.0.113.5:1000"]}"#),
        )
        .await;
        assert_eq!(global.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body_json(global).await["error"], ERR_REALM_LIMIT);
    }

    #[tokio::test]
    async fn connect_rejects_bad_credentials_arguments_and_unknown_realm() {
        let server = test_server(|_| {});
        let valid = r#"{"addresses":["203.0.113.5:1000"],"nonce":"0102030405060708090a0b0c0d0e0f10","obfs":"0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10"}"#;

        let unauthorized = call(&server, PEER, request(Method::POST, "/v1/realm/connect", None, valid)).await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let unknown = call(&server, PEER, request(Method::POST, "/v1/realm/connect", Some(TOKEN), valid)).await;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_json(unknown).await["error"], ERR_REALM_NOT_FOUND);

        register_realm(&server, PEER, "realm").await;
        for body in [
            r#"{"addresses":["203.0.113.5:1000"],"nonce":"00","obfs":"0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10"}"#,
            r#"{"addresses":["203.0.113.5:1000"],"nonce":"0102030405060708090a0b0c0d0e0f10","obfs":"00"}"#,
            r#"{"addresses":[],"nonce":"0102030405060708090a0b0c0d0e0f10","obfs":"0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10"}"#,
        ] {
            let resp = call(&server, PEER, request(Method::POST, "/v1/realm/connect", Some(TOKEN), body)).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{body}");
        }
    }

    #[tokio::test]
    async fn punch_flow_round_trips_through_events_and_connect_response() {
        let server = test_server(|_| {});
        let session_token = register_realm(&server, PEER, "realm").await;

        let stream = call(&server, PEER, request(Method::GET, "/v1/realm/events", Some(&session_token), "")).await;
        assert_eq!(stream.status(), StatusCode::OK);
        assert_eq!(stream.headers()[header::CONTENT_TYPE], "text/event-stream");
        let mut stream_body = stream.into_body();

        let connect_body = json!({
            "addresses": ["203.0.113.5:1000", "203.0.113.5:1001"],
            "nonce": NONCE,
            "obfs": OBFS,
        })
        .to_string();
        let connect_server = Arc::clone(&server);
        let responder_token = session_token.clone();
        let connect = tokio::spawn(async move {
            call(&connect_server, PEER, request(Method::POST, "/v1/realm/connect", Some(TOKEN), &connect_body)).await
        });

        let frame = stream_body.frame().await.expect("event frame").expect("event frame ok");
        let text = String::from_utf8(frame.into_data().expect("data frame").to_vec()).expect("utf8 frame");
        assert!(text.starts_with("event: punch\ndata: "), "{text:?}");
        let data = text.lines().find_map(|line| line.strip_prefix("data: ")).expect("data line");
        let punch: Value = serde_json::from_str(data).expect("punch json");
        assert_eq!(punch["nonce"], NONCE);
        assert_eq!(punch["obfs"], OBFS);
        assert_eq!(punch["addresses"], json!(["203.0.113.5:1000", "203.0.113.5:1001"]));

        let delivered = call(
            &server,
            PEER,
            request(
                Method::POST,
                &format!("/v1/realm/connects/{NONCE}"),
                Some(&responder_token),
                r#"{"addresses":["198.51.100.7:2000"]}"#,
            ),
        )
        .await;
        assert_eq!(delivered.status(), StatusCode::NO_CONTENT);

        let answered = connect.await.expect("connect task");
        assert_eq!(answered.status(), StatusCode::OK);
        let answer = body_json(answered).await;
        assert_eq!(answer["addresses"], json!(["198.51.100.7:2000"]));
        assert_eq!(answer["nonce"], NONCE);
        assert_eq!(answer["obfs"], OBFS);

        let duplicate = call(
            &server,
            PEER,
            request(
                Method::POST,
                &format!("/v1/realm/connects/{NONCE}"),
                Some(&session_token),
                r#"{"addresses":["198.51.100.7:2000"]}"#,
            ),
        )
        .await;
        assert_eq!(duplicate.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_json(duplicate).await["error"], ERR_ATTEMPT_NOT_FOUND);
    }

    #[tokio::test]
    async fn connect_falls_back_to_the_session_addresses_when_no_response_arrives() {
        let server = test_server(|cfg| cfg.connect_response_timeout = Some(std::time::Duration::from_millis(20)));
        let session_token = register_realm(&server, PEER, "realm").await;

        let heartbeat = call(
            &server,
            PEER,
            request(
                Method::POST,
                "/v1/realm/heartbeat",
                Some(&session_token),
                r#"{"addresses":["198.51.100.7:2000"]}"#,
            ),
        )
        .await;
        assert_eq!(heartbeat.status(), StatusCode::OK);
        assert_eq!(body_json(heartbeat).await["ttl"], SESSION_TTL.as_secs());

        let empty_list = call(
            &server,
            PEER,
            request(Method::POST, "/v1/realm/heartbeat", Some(&session_token), r#"{"addresses":[]}"#),
        )
        .await;
        assert_eq!(empty_list.status(), StatusCode::BAD_REQUEST);

        let no_body = call(&server, PEER, request(Method::POST, "/v1/realm/heartbeat", Some(&session_token), "")).await;
        assert_eq!(no_body.status(), StatusCode::OK);

        let null_body =
            call(&server, PEER, request(Method::POST, "/v1/realm/heartbeat", Some(&session_token), "null")).await;
        assert_eq!(null_body.status(), StatusCode::OK);

        let answered = call(
            &server,
            PEER,
            request(
                Method::POST,
                "/v1/realm/connect",
                Some(TOKEN),
                &json!({ "addresses": ["203.0.113.5:1000"], "nonce": NONCE, "obfs": OBFS }).to_string(),
            ),
        )
        .await;
        assert_eq!(answered.status(), StatusCode::OK);
        assert_eq!(body_json(answered).await["addresses"], json!(["198.51.100.7:2000"]));
    }

    #[tokio::test]
    async fn deregister_invalidates_the_session_token() {
        let server = test_server(|_| {});
        let session_token = register_realm(&server, PEER, "realm").await;

        let gone = call(&server, PEER, request(Method::DELETE, "/v1/realm", Some(&session_token), "")).await;
        assert_eq!(gone.status(), StatusCode::NO_CONTENT);

        let stale = call(&server, PEER, request(Method::POST, "/v1/realm/heartbeat", Some(&session_token), "{}")).await;
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(stale).await["error"], ERR_INVALID_TOKEN);
    }

    #[test]
    fn pending_attempt_limit_is_shared_with_the_event_buffer() {
        assert_eq!(MAX_PENDING_ATTEMPTS, EVENTS_BUFFER_SIZE);
    }
}

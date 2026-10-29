use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hyper::{Method, Response, StatusCode};
use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;

use murmur_common::utils::ranges::new_unsigned_ranges;
use murmur_component_profile::cachefile;
use murmur_constant::adapters::{AdapterType, Proxy as CProxy, ProxyAdapter as CProxyAdapter};
use murmur_tunnel::tunnel;

use super::common::{
    as_select_able, get_escape_param, json_response, marshal_json_response, proxy_json_response, status_only, Req,
    RespBody,
};
use super::errors::{err_bad_request, err_not_found, err_request_timeout, HttpError};
use super::server::query_param;

type SwitchProxiesCallback = Arc<dyn Fn(String, String) + Send + Sync>;

static SWITCH_PROXIES_CALLBACK: RwLock<Option<SwitchProxiesCallback>> = RwLock::new(None);

pub fn set_switch_proxies_callback(cb: SwitchProxiesCallback) {
    *SWITCH_PROXIES_CALLBACK.write() = Some(cb);
}

/// The `/proxies` mount. The shared name lookup runs for every path the mount matched, before the
/// route and its method resolve: an unknown name answers the API's JSON 404 whatever the method or
/// the leftover path is, a resolved one reaches the handler, and a leftover path no route matches
/// stays the router's plain 404 (`None`).
pub(crate) async fn route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    route_with(req, segs, |name| tunnel::proxies().get(name).cloned()).await
}

/// The body of the router; `lookup` is the name-lookup step, injectable so a test can drive every
/// path shape against a fixed map instead of the process-wide tunnel.
async fn route_with(
    req: Req,
    segs: &[&str],
    lookup: impl Fn(&str) -> Option<Arc<dyn CProxy>>,
) -> Option<Response<RespBody>> {
    let Some((name, rest)) = segs.split_first() else {
        if req.method() != Method::GET {
            return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
        }
        return Some(get_proxies());
    };

    let Some(proxy) = lookup(&get_escape_param(name)) else {
        return Some(json_response(StatusCode::NOT_FOUND, &err_not_found()));
    };

    match rest {
        [] => match *req.method() {
            Method::GET => Some(get_proxy(&proxy)),
            Method::PUT => Some(update_proxy(req, &proxy).await),
            Method::DELETE => Some(unfixed_proxy(&proxy)),
            _ => Some(status_only(StatusCode::METHOD_NOT_ALLOWED)),
        },
        ["delay"] => {
            if req.method() != Method::GET {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            Some(get_proxy_delay_for(&req, proxy).await)
        }
        _ => None,
    }
}

fn get_proxies() -> Response<RespBody> {
    proxies_response(&tunnel::proxies())
}

/// Split from the tunnel lookup so a test can drive it against a fixed map. The body is the sorted
/// names with each wrapper's own `marshal_json` bytes verbatim: a `serde_json::Value` round trip
/// would re-sort `history`/`extra` entries.
fn proxies_response(proxies: &HashMap<String, Arc<dyn CProxy>>) -> Response<RespBody> {
    let mut entries = Vec::with_capacity(proxies.len());
    for (name, proxy) in proxies {
        match CProxyAdapter::marshal_json(&**proxy) {
            Ok(bytes) => entries.push((name.as_str(), bytes)),
            Err(err) => return marshal_json_response(StatusCode::INTERNAL_SERVER_ERROR, Err(err)),
        }
    }
    entries.sort_by_key(|(name, _)| *name);

    let mut body = b"{\"proxies\":{".to_vec();
    for (index, (name, value)) in entries.iter().enumerate() {
        if index > 0 {
            body.push(b',');
        }
        serde_json::to_writer(&mut body, name).unwrap_or_default();
        body.push(b':');
        body.extend_from_slice(value);
    }
    body.extend_from_slice(b"}}");
    marshal_json_response(StatusCode::OK, Ok(body))
}

/// The proxy wrapper, not its inner adapter.
fn get_proxy(proxy: &Arc<dyn CProxy>) -> Response<RespBody> {
    proxy_json_response(StatusCode::OK, &**proxy)
}

async fn update_proxy(req: Req, proxy: &Arc<dyn CProxy>) -> Response<RespBody> {
    #[derive(serde::Deserialize, Default)]
    struct UpdateProxyRequest {
        #[serde(default)]
        name: String,
    }

    let Ok(update_req) = super::common::decode_json_body::<Option<UpdateProxyRequest>, _>(req.into_body()).await else {
        return json_response(StatusCode::BAD_REQUEST, &err_bad_request());
    };
    let update_req = update_req.unwrap_or_default();

    let adapter = proxy.adapter();
    let Some(selector) = as_select_able(&*adapter) else {
        return json_response(StatusCode::BAD_REQUEST, &HttpError::new("Must be a Selector"));
    };

    if let Err(err) = selector.set(&update_req.name).await {
        return json_response(StatusCode::BAD_REQUEST, &HttpError::new(format!("Selector update error: {err}")));
    }

    cachefile::cache::cache().set_selected(&proxy.name(), &update_req.name);
    let callback = SWITCH_PROXIES_CALLBACK.read().clone();
    if let Some(cb) = callback {
        let group_name = proxy.name();
        let proxy_name = update_req.name.clone();
        tokio::spawn(async move { cb(group_name, proxy_name) });
    }
    super::common::no_content()
}

/// `proxy` is already resolved: `provider.rs`'s provider-proxy mount reuses this same handler on
/// a proxy resolved from a specific provider instead of the global proxy map, and the same handler
/// is registered under both mounts.
pub(crate) async fn get_proxy_delay_for(
    req: &Req,
    proxy: Arc<dyn murmur_constant::adapters::Proxy>,
) -> Response<RespBody> {
    let query = req.uri().query().unwrap_or("");
    let url = query_param(query, "url").unwrap_or_default();
    let Some(timeout_str) = query_param(query, "timeout") else {
        return json_response(StatusCode::BAD_REQUEST, &err_bad_request());
    };
    // The parameter is a millisecond timeout, and `groups.rs` parses this same value as an `i32`;
    // an `i16` capped this route (and the provider healthcheck that delegates to it) at 32.767 s.
    let Ok(timeout_ms) = timeout_str.parse::<i32>() else {
        return json_response(StatusCode::BAD_REQUEST, &err_bad_request());
    };

    let Ok(expected_status) = new_unsigned_ranges::<u16>(&query_param(query, "expected").unwrap_or_default()) else {
        return json_response(StatusCode::BAD_REQUEST, &err_bad_request());
    };

    let (ctx, timed_out) = new_timeout_token(Duration::from_millis(u64::from(timeout_ms.max(0).cast_unsigned())));

    let result = proxy.url_test(&ctx, &url, expected_status).await;
    if timed_out.load(std::sync::atomic::Ordering::SeqCst) {
        return json_response(StatusCode::GATEWAY_TIMEOUT, &err_request_timeout());
    }

    // the error-and-delay branch is unreachable: every error return in the URL test
    // happens before the delay is assigned, so a failure and a zero delay answer the same 503.
    match result {
        Ok(delay) if delay != 0 => json_response(StatusCode::OK, &serde_json::json!({"delay": delay})),
        _ => json_response(StatusCode::SERVICE_UNAVAILABLE, &HttpError::new("An error occurred in the delay test")),
    }
}

/// The delay test checks for a deadline right after awaiting the URL test; `CancellationToken`
/// carries no deadline of its own, so the timeout is tracked in a flag the spawned timer sets when
/// it actually fires the cancellation.
fn new_timeout_token(timeout: Duration) -> (CancellationToken, Arc<std::sync::atomic::AtomicBool>) {
    let token = CancellationToken::new();
    let child = token.clone();
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fired_for_task = Arc::clone(&fired);
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        fired_for_task.store(true, std::sync::atomic::Ordering::SeqCst);
        child.cancel();
    });
    (token, fired)
}

fn unfixed_proxy(proxy: &Arc<dyn CProxy>) -> Response<RespBody> {
    if let Some(select_able) = as_select_able(&*proxy.adapter()) {
        if proxy.type_() != AdapterType::SELECTOR {
            select_able.force_set("");
            cachefile::cache::cache().set_selected(&proxy.name(), "");
            return super::common::no_content();
        }
    }
    json_response(StatusCode::BAD_REQUEST, &err_bad_request())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use http_body_util::BodyExt;
    use murmur_adapter::adapter::Proxy as ConcreteProxy;
    use murmur_adapter_outbound::direct::new_direct;
    use murmur_adapter_outboundgroup::parser::GroupCommonOption;
    use murmur_adapter_outboundgroup::selector::{Selector, SelectorOption};
    use murmur_common::utils::ranges::IntRanges;
    use murmur_constant::adapters::Proxy;
    use murmur_constant::provider::interface::{Provider, ProviderType, ProxyProvider, VehicleType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A `ProxyProvider` with a fixed, unchanging member list: just enough for `GroupBase` to
    /// have something to select from when constructing a group for a JSON-shape test.
    struct StaticProvider(Vec<Arc<dyn Proxy>>);

    #[async_trait]
    impl Provider for StaticProvider {
        fn name(&self) -> String {
            "static".to_owned()
        }
        fn vehicle_type(&self) -> VehicleType {
            VehicleType::COMPATIBLE
        }
        fn type_(&self) -> ProviderType {
            ProviderType::PROXY
        }
        async fn initial(&self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn update(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn marshal_json(&self) -> anyhow::Result<Vec<u8>> {
            Ok(b"{}".to_vec())
        }
    }

    #[async_trait]
    impl ProxyProvider for StaticProvider {
        fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
            self.0.clone()
        }
        fn count(&self) -> i32 {
            self.0.len() as i32
        }
        fn touch(&self) {}
        async fn health_check(&self) {}
        fn version(&self) -> u32 {
            0
        }
        fn register_health_check_task(
            &self,
            _url: &str,
            _expected_status: IntRanges<u16>,
            _filter: &str,
            _interval: u32,
        ) {
        }
        fn health_check_url(&self) -> String {
            String::new()
        }
    }

    /// The `type`/`id` keys of the base proxy JSON merged with the keys the adapter adds: every
    /// plain proxy entry under `/proxies` has exactly this key set, regardless of protocol.
    const EXPECTED_PROXY_ENTRY_KEYS: &[&str] = &[
        "type",
        "id",
        "history",
        "extra",
        "alive",
        "name",
        "udp",
        "uot",
        "xudp",
        "tfo",
        "mptcp",
        "smux",
        "interface",
        "routing-mark",
        "provider-name",
        "dialer-proxy",
    ];

    /// The wrapper's own serialized bytes, parsed: these tests compare key sets, and the byte
    /// order `history`/`extra` need is asserted by the listing tests instead.
    fn wrapper_value(proxy: &Arc<dyn Proxy>) -> serde_json::Value {
        serde_json::from_slice(&proxy.marshal_json().expect("the wrapper marshals")).expect("the wrapper wrote JSON")
    }

    #[test]
    fn plain_proxy_entry_key_set_is_stable() {
        let proxy: Arc<dyn Proxy> = ConcreteProxy::new(new_direct());
        let json = wrapper_value(&proxy);
        let object = json.as_object().expect("a plain proxy entry serializes to a JSON object");

        let mut actual: Vec<&str> = object.keys().map(String::as_str).collect();
        actual.sort_unstable();
        let mut expected = EXPECTED_PROXY_ENTRY_KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(actual, expected);
    }

    /// A group proxy adds `now`/`all`/`testUrl`/`hidden`/`icon`/`emptyFallback` on top of the
    /// base proxy wrapper every group type shares.
    #[test]
    fn selector_group_entry_key_set_is_stable() {
        let fallback = ConcreteProxy::new(new_direct());
        let member: Arc<dyn Proxy> = ConcreteProxy::new(new_direct());
        let provider: Arc<dyn ProxyProvider> = Arc::new(StaticProvider(vec![member]));
        let selector = Selector::new(GroupCommonOption::default(), SelectorOption::default(), fallback, vec![provider])
            .expect("a selector with one member proxy constructs");
        let proxy: Arc<dyn Proxy> = ConcreteProxy::new(selector);
        let json = wrapper_value(&proxy);
        let object = json.as_object().expect("a group proxy entry serializes to a JSON object");

        let mut actual: Vec<&str> = object.keys().map(String::as_str).collect();
        actual.sort_unstable();
        // Group types (Selector, URLTest, Fallback, LoadBalance) build their own base map
        // (`type`/`now`/`all`/`testUrl`/`hidden`/`icon`/`emptyFallback`) instead of the plain
        // proxy base, so unlike a plain proxy entry there is no `id` key here.
        let mut expected: Vec<&str> = EXPECTED_PROXY_ENTRY_KEYS.iter().copied().filter(|k| *k != "id").collect();
        expected.extend_from_slice(&["now", "all", "testUrl", "hidden", "icon", "emptyFallback"]);
        expected.sort_unstable();
        assert_eq!(actual, expected);

        assert!(object["all"].is_array());
        assert!(object["now"].is_string());
    }

    async fn response_json(response: Response<RespBody>) -> serde_json::Value {
        let bytes = response.into_body().collect().await.expect("a handler body collects").to_bytes();
        serde_json::from_slice(&bytes).expect("the handler wrote JSON")
    }

    async fn response_body(response: Response<RespBody>) -> Vec<u8> {
        response.into_body().collect().await.expect("a handler body collects").to_bytes().to_vec()
    }

    fn assert_wrapper_keys(object: &serde_json::Map<String, serde_json::Value>, what: &str) {
        let mut actual: Vec<&str> = object.keys().map(String::as_str).collect();
        actual.sort_unstable();
        let mut expected = EXPECTED_PROXY_ENTRY_KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(actual, expected, "{what} must render the C.Proxy wrapper, not proxy.Adapter()");
    }

    /// `/proxies` and `/proxies/{name}` render the proxy wrapper the tunnel holds, so a
    /// built-in entry carries the whole wrapper key set rather than the bare `{type,id}` adapter.
    #[tokio::test]
    async fn proxies_routes_render_the_wrapper_for_a_builtin() {
        let mut proxies: HashMap<String, Arc<dyn CProxy>> = HashMap::new();
        proxies.insert("DIRECT".to_owned(), ConcreteProxy::new(new_direct()));

        let body = response_json(proxies_response(&proxies)).await;
        let entry = body["proxies"]["DIRECT"].as_object().expect("each /proxies entry is an object");
        assert_wrapper_keys(entry, "/proxies' DIRECT entry");
        assert_eq!(entry["type"], "Direct");
        assert_eq!(entry["name"], "DIRECT");
        assert_eq!(entry["alive"], true);
        assert_eq!(entry["udp"], true);
        assert_eq!(entry["uot"], false);
        assert_eq!(entry["xudp"], false);
        assert_eq!(entry["tfo"], false);
        assert_eq!(entry["mptcp"], false);
        assert_eq!(entry["smux"], false);
        assert_eq!(entry["interface"], "");
        assert_eq!(entry["routing-mark"], 0);
        assert_eq!(entry["provider-name"], "");
        assert_eq!(entry["dialer-proxy"], "");
        assert!(entry["id"].is_string());
        assert!(entry["history"].as_array().expect("history is an array").is_empty());
        assert!(entry["extra"].as_object().expect("extra is an object").is_empty());

        let direct: Arc<dyn CProxy> = ConcreteProxy::new(new_direct());
        let single = response_json(get_proxy(&direct)).await;
        assert_wrapper_keys(single.as_object().expect("/proxies/DIRECT is an object"), "/proxies/DIRECT");
    }

    /// `history` records one entry per completed delay test and `extra` keys the per-URL state, both
    /// on the wrapper `URLTest` mutates; a built-in's first `/proxies` render must already show them.
    #[tokio::test]
    async fn wrapper_history_and_extra_after_a_delay_test() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a local test server binds");
        let url = format!("http://{}/", listener.local_addr().expect("a bound port"));
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        });

        let proxy: Arc<dyn CProxy> = ConcreteProxy::new(new_direct());
        let expected = new_unsigned_ranges::<u16>("200").expect("200 is a valid status range");
        let delay = proxy.url_test(&CancellationToken::new(), &url, expected).await.expect("the test server answers");

        let body = response_json(proxies_response(&HashMap::from([("DIRECT".to_owned(), Arc::clone(&proxy))]))).await;
        let raw = response_body(proxies_response(&HashMap::from([("DIRECT".to_owned(), proxy)]))).await;
        assert!(
            raw.windows(b"\"history\":[{\"time\":\"".len()).any(|window| window == b"\"history\":[{\"time\":\""),
            "the listing must embed the wrapper's own bytes, got {}",
            String::from_utf8_lossy(&raw)
        );
        let entry = &body["proxies"]["DIRECT"];
        assert_eq!(entry["alive"], true);

        let history = entry["history"].as_array().expect("history is an array");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0]["delay"], delay);
        let time = history[0]["time"].as_str().expect("time is a string");
        assert!(chrono::DateTime::parse_from_rfc3339(time).is_ok(), "time {time:?} is not an RFC 3339 timestamp");

        let extra = entry["extra"].as_object().expect("extra is an object");
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[url.as_str()]["alive"], true);
        assert_eq!(extra[url.as_str()]["history"][0]["delay"], delay);
    }

    /// A dashboard percent-encodes the proxy name in the path, and proxies are named with spaces
    /// and flags: the router must decode the segment before the lookup, or every such name is
    /// unreachable even though the map holds it.
    #[tokio::test]
    async fn the_proxy_name_is_percent_decoded_before_the_lookup() {
        let direct: Arc<dyn CProxy> = ConcreteProxy::new(new_direct());
        let name = "node with a space";
        let proxies = vec![(name.to_owned(), direct)];

        let target = "/proxies/node%20with%20a%20space";
        let (status, _) = request("GET", target, &["node%20with%20a%20space"], proxies).await;
        assert_eq!(status, StatusCode::OK, "the encoded name must resolve to the decoded key");
    }

    /// The JSON body of a not-found error, and the router's plain body of a `None` route
    /// (`server.rs`'s `not_found`), so a body assertion tells the two 404s apart.
    const NOT_FOUND_BODY: &[u8] = b"{\"message\":\"Resource not found\"}\n";
    const PLAIN_NOT_FOUND: &[u8] = b"404 page not found\n";

    /// Serves one request through the router over a real HTTP/1.1 connection: the handlers take
    /// `hyper::body::Incoming`, which no hand-built request can supply. `proxies` is the name map
    /// would have been resolved against, so no test here touches the tunnel global.
    async fn request(
        method: &str,
        target: &str,
        segs: &[&str],
        proxies: Vec<(String, Arc<dyn CProxy>)>,
    ) -> (StatusCode, Vec<u8>) {
        let segs: Vec<String> = segs.iter().map(|s| (*s).to_owned()).collect();
        let target = target.to_owned();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener has a local address");
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept loopback connection");
            let svc = hyper::service::service_fn(move |req: Req| {
                let segs = segs.clone();
                let proxies = proxies.clone();
                async move {
                    let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
                    let routed = route_with(req, &refs, |name| {
                        proxies.iter().find(|(key, _)| key == name).map(|(_, proxy)| Arc::clone(proxy))
                    })
                    .await;
                    let response = routed.unwrap_or_else(|| {
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(super::super::common::full_body(PLAIN_NOT_FOUND))
                            .expect("static response")
                    });
                    Ok::<_, std::convert::Infallible>(response)
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(conn), svc)
                .await;
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect to loopback listener");
        let head = format!("{method} {target} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
        stream.write_all(head.as_bytes()).await.expect("write request head");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");

        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("response has a header/body split");
        let head = std::str::from_utf8(&raw[..split]).expect("response head is ascii");
        let code = head.split_whitespace().nth(1).expect("status line has a code");
        (StatusCode::from_bytes(code.as_bytes()).expect("valid status code"), raw[split + 4..].to_vec())
    }

    /// The name lookup runs before the route and its method, so an unknown name is the API's JSON
    /// 404 on any method or leftover path, while a leftover path no route matches for a known name
    /// is the router's plain 404.
    #[tokio::test]
    async fn routing_resolves_the_name_before_the_method() {
        let direct: Arc<dyn CProxy> = ConcreteProxy::new(new_direct());
        let proxies = vec![("DIRECT".to_owned(), direct)];

        for method in ["GET", "PUT", "POST", "DELETE"] {
            for segs in [&["NOPE"][..], &["NOPE", "delay"][..], &["NOPE", "delay", ""][..], &[""][..]] {
                let (status, body) = request(method, "/", segs, proxies.clone()).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{method} {segs:?}");
                assert_eq!(body, NOT_FOUND_BODY, "{method} {segs:?}");
            }
        }

        assert_eq!(request("GET", "/", &["DIRECT"], proxies.clone()).await.0, StatusCode::OK);
        assert_eq!(request("PUT", "/", &["DIRECT"], proxies.clone()).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(request("DELETE", "/", &["DIRECT"], proxies.clone()).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(request("POST", "/", &["DIRECT"], proxies.clone()).await.0, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(request("POST", "/", &["DIRECT", "delay"], proxies.clone()).await.0, StatusCode::METHOD_NOT_ALLOWED);
        for method in ["GET", "POST"] {
            let (status, body) = request(method, "/", &["DIRECT", "delay", ""], proxies.clone()).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} leftover path");
            assert_eq!(body, PLAIN_NOT_FOUND, "{method} leftover path");
        }
    }

    /// A failed `URLTest` and a zero delay both answer 503 with the fixed message: the
    /// error-and-delay branch is unreachable, so the dial error never reaches the wire.
    #[tokio::test]
    async fn delay_endpoint_hides_the_url_test_error() {
        let direct: Arc<dyn CProxy> = ConcreteProxy::new(new_direct());
        let proxies = vec![("DIRECT".to_owned(), direct)];

        let target = "/proxies/DIRECT/delay?url=http://127.0.0.1:1/&timeout=2000&expected=";
        let (status, body) = request("GET", target, &["DIRECT", "delay"], proxies).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, b"{\"message\":\"An error occurred in the delay test\"}\n".to_vec());
    }

    /// The timeout is milliseconds, so a value above the `i16` range must reach the probe like it
    /// does on `/group/{name}/delay`; this route used to answer 400 for anything past 32.767 s.
    #[tokio::test]
    async fn delay_endpoint_accepts_a_timeout_above_the_i16_range() {
        let direct: Arc<dyn CProxy> = ConcreteProxy::new(new_direct());
        let proxies = vec![("DIRECT".to_owned(), direct)];

        let target = "/proxies/DIRECT/delay?url=http://127.0.0.1:1/&timeout=60000&expected=";
        let (status, body) = request("GET", target, &["DIRECT", "delay"], proxies).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the probe ran and failed on a closed port; body {}",
            String::from_utf8_lossy(&body)
        );
    }

    /// The URL query parameter is percent-decoded, and a dashboard encodes the value it sends: the
    /// recorded per-URL state must be keyed by the decoded URL.
    #[tokio::test]
    async fn delay_endpoint_decodes_the_url_parameter() {
        let direct: Arc<dyn CProxy> = ConcreteProxy::new(new_direct());
        let proxies = vec![("DIRECT".to_owned(), direct)];

        let url = "http://127.0.0.1:1/";
        let encoded = url.replace(':', "%3A").replace('/', "%2F");
        let target = format!("/proxies/DIRECT/delay?url={encoded}&timeout=2000&expected=200");
        let _ = request("GET", &target, &["DIRECT", "delay"], proxies.clone()).await;

        let body = response_json(proxies_response(&proxies.into_iter().collect())).await;
        let extra = body["proxies"]["DIRECT"]["extra"].as_object().expect("extra is an object");
        assert!(extra.contains_key(url), "extra is keyed by the decoded URL, got {extra:?}");
        assert_eq!(extra.len(), 1, "extra holds one entry per URL actually tested");
    }
}

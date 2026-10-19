use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hyper::{Method, Response, StatusCode};
use tokio_util::sync::CancellationToken;

use murmur_common::utils::ranges::new_unsigned_ranges;
use murmur_component_profile::cachefile;
use murmur_constant::adapters::{AdapterType, Proxy as CProxy, ProxyAdapter as CProxyAdapter};
use murmur_tunnel::tunnel;

use super::common::{
    as_proxy_group, as_select_able, get_escape_param, json_response, marshal_json_response, proxy_json_response,
    status_only, Req, RespBody,
};
use super::errors::{err_bad_request, err_not_found, HttpError};
use super::server::query_param;

/// The `/group` mount. As in `proxies.rs`, the shared name lookup runs before the route and its
/// method, so an unknown name is the API's JSON 404 for any method or leftover path, while an
/// unmatched leftover path for a known name is the router's plain 404 (`None`).
pub(crate) async fn route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    route_with(req, segs, |name| tunnel::proxies().get(name).cloned()).await
}

/// The body of the router; `lookup` is the shared name-lookup step, injectable so a test can drive
/// every path shape against a fixed map instead of the process-wide tunnel.
async fn route_with(
    req: Req,
    segs: &[&str],
    lookup: impl Fn(&str) -> Option<Arc<dyn CProxy>>,
) -> Option<Response<RespBody>> {
    let Some((name, rest)) = segs.split_first() else {
        if req.method() != Method::GET {
            return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
        }
        return Some(get_groups());
    };

    let Some(proxy) = lookup(&get_escape_param(name)) else {
        return Some(json_response(StatusCode::NOT_FOUND, &err_not_found()));
    };

    match rest {
        [] => {
            if req.method() != Method::GET {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            Some(get_group(&proxy))
        }
        ["delay"] => {
            if req.method() != Method::GET {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            Some(get_group_delay(&req, &proxy).await)
        }
        _ => None,
    }
}

fn get_groups() -> Response<RespBody> {
    groups_response(tunnel::proxies())
}

/// Split from the tunnel lookup so a test can drive it against a fixed map. Each entry is the
/// wrapper's own `marshal_json` bytes verbatim, and the body is `{"proxies":null}` rather than
/// `[]` when no group exists.
fn groups_response(proxies: HashMap<String, Arc<dyn CProxy>>) -> Response<RespBody> {
    let mut gs = Vec::new();
    for p in proxies.into_values() {
        if as_proxy_group(&*p.adapter()).is_some() {
            match CProxyAdapter::marshal_json(&*p) {
                Ok(bytes) => gs.push(bytes),
                Err(err) => return marshal_json_response(StatusCode::INTERNAL_SERVER_ERROR, Err(err)),
            }
        }
    }
    if gs.is_empty() {
        return marshal_json_response(StatusCode::OK, Ok(b"{\"proxies\":null}".to_vec()));
    }

    let mut body = b"{\"proxies\":[".to_vec();
    for (index, value) in gs.iter().enumerate() {
        if index > 0 {
            body.push(b',');
        }
        body.extend_from_slice(value);
    }
    body.extend_from_slice(b"]}");
    marshal_json_response(StatusCode::OK, Ok(body))
}

/// The proxy wrapper, or the 404 for a non-group.
fn get_group(proxy: &Arc<dyn CProxy>) -> Response<RespBody> {
    if as_proxy_group(&*proxy.adapter()).is_some() {
        return proxy_json_response(StatusCode::OK, &**proxy);
    }
    json_response(StatusCode::NOT_FOUND, &err_not_found())
}

async fn get_group_delay(req: &Req, proxy: &Arc<dyn CProxy>) -> Response<RespBody> {
    let adapter = proxy.adapter();
    let Some(group) = as_proxy_group(&*adapter) else {
        return json_response(StatusCode::NOT_FOUND, &err_not_found());
    };

    if let Some(select_able) = as_select_able(&*adapter) {
        if proxy.type_() != AdapterType::SELECTOR {
            select_able.force_set("");
            cachefile::cache::cache().set_selected(&proxy.name(), "");
        }
    }

    let query = req.uri().query().unwrap_or("");
    let url = query_param(query, "url").unwrap_or_default();
    let Some(timeout_str) = query_param(query, "timeout") else {
        return json_response(StatusCode::BAD_REQUEST, &err_bad_request());
    };
    // The same millisecond value and the same width `proxies.rs` parses this parameter with, so
    // one timeout works on both delay routes.
    let Ok(timeout_ms) = timeout_str.parse::<i32>() else {
        return json_response(StatusCode::BAD_REQUEST, &err_bad_request());
    };

    let Ok(expected_status) = new_unsigned_ranges::<u16>(&query_param(query, "expected").unwrap_or_default()) else {
        return json_response(StatusCode::BAD_REQUEST, &err_bad_request());
    };

    let ctx = new_timeout_token(Duration::from_millis(u64::from(timeout_ms.max(0).cast_unsigned())));

    match group.url_test(&ctx, &url, expected_status).await {
        Ok(dm) => json_response(StatusCode::OK, &dm),
        Err(err) => json_response(StatusCode::GATEWAY_TIMEOUT, &HttpError::new(err.to_string())),
    }
}

/// A request-scoped deadline plus its cancellation; see `doh.rs`'s identical helper for why the
/// timer is detached instead.
fn new_timeout_token(timeout: Duration) -> CancellationToken {
    let token = CancellationToken::new();
    let child = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        child.cancel();
    });
    token
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

    /// A `ProxyProvider` with a fixed member list: the group base falls back to the empty member
    /// (and the selector indexes it) only when a provider yields no proxy.
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

    /// The base wrapper keys plus the ones a selector adds.
    const EXPECTED_GROUP_ENTRY_KEYS: &[&str] = &[
        "type",
        "now",
        "all",
        "testUrl",
        "hidden",
        "icon",
        "emptyFallback",
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

    fn selector_wrapper() -> Arc<dyn CProxy> {
        let fallback = ConcreteProxy::new(new_direct());
        let member: Arc<dyn Proxy> = ConcreteProxy::new(new_direct());
        let provider: Arc<dyn ProxyProvider> = Arc::new(StaticProvider(vec![member]));
        let selector = Selector::new(GroupCommonOption::default(), SelectorOption::default(), fallback, vec![provider])
            .expect("a selector with one member proxy constructs");
        ConcreteProxy::new(selector)
    }

    async fn response_json(response: Response<RespBody>) -> serde_json::Value {
        let bytes = response.into_body().collect().await.expect("a handler body collects").to_bytes();
        serde_json::from_slice(&bytes).expect("the handler wrote JSON")
    }

    /// `/group` and `/group/{name}` render the proxy wrapper the tunnel holds, and a
    /// non-group or unknown name is the 404.
    #[tokio::test]
    async fn group_routes_render_the_wrapper() {
        let direct: Arc<dyn CProxy> = ConcreteProxy::new(new_direct());
        let group = selector_wrapper();
        let proxies: HashMap<String, Arc<dyn CProxy>> =
            HashMap::from([("DIRECT".to_owned(), Arc::clone(&direct)), ("GLOBAL".to_owned(), Arc::clone(&group))]);

        let body = response_json(groups_response(proxies)).await;
        let entries = body["proxies"].as_array().expect("getGroups writes an array");
        assert_eq!(entries.len(), 1, "only the group is listed");
        let object = entries[0].as_object().expect("a group entry is an object");
        let mut actual: Vec<&str> = object.keys().map(String::as_str).collect();
        actual.sort_unstable();
        let mut expected = EXPECTED_GROUP_ENTRY_KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(actual, expected, "getGroups must render the C.Proxy wrapper, not proxy.Adapter()");
        assert_eq!(object["type"], "Selector");
        assert!(object["all"].is_array());
        assert!(object["history"].as_array().expect("history is an array").is_empty());
        assert!(object["extra"].as_object().expect("extra is an object").is_empty());

        let single = response_json(get_group(&group)).await;
        let single = single.as_object().expect("/group/GLOBAL is an object");
        let mut single_keys: Vec<&str> = single.keys().map(String::as_str).collect();
        single_keys.sort_unstable();
        assert_eq!(single_keys, expected, "/group/GLOBAL must render the C.Proxy wrapper");
        assert_eq!(single["now"], "DIRECT");

        let not_a_group = get_group(&direct);
        assert_eq!(not_a_group.status(), StatusCode::NOT_FOUND);
        assert_eq!(response_json(not_a_group).await, serde_json::json!({"message": "Resource not found"}));

        assert_eq!(response_json(groups_response(HashMap::new())).await, serde_json::json!({"proxies": null}));
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

    /// `/group` shares the name lookup with `/proxies`, which resolves the name before the route
    /// and its method: an unknown name is the API's JSON 404, a known non-group is the group
    /// handler's, and a leftover path no route matches is the router's plain 404.
    #[tokio::test]
    async fn routing_resolves_the_name_before_the_method() {
        let direct: Arc<dyn CProxy> = ConcreteProxy::new(new_direct());
        let proxies = vec![("DIRECT".to_owned(), direct), ("PROXY".to_owned(), selector_wrapper())];

        for method in ["GET", "PUT", "POST", "DELETE"] {
            for segs in [&["NOPE"][..], &["NOPE", "delay"][..], &["NOPE", "delay", ""][..], &[""][..]] {
                let (status, body) = request(method, "/", segs, proxies.clone()).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{method} {segs:?}");
                assert_eq!(body, NOT_FOUND_BODY, "{method} {segs:?}");
            }
        }

        assert_eq!(request("GET", "/", &["PROXY"], proxies.clone()).await.0, StatusCode::OK);
        let (status, body) = request("GET", "/", &["DIRECT"], proxies.clone()).await;
        assert_eq!((status, body), (StatusCode::NOT_FOUND, NOT_FOUND_BODY.to_vec()));
        assert_eq!(request("GET", "/", &["DIRECT", "delay"], proxies.clone()).await.0, StatusCode::NOT_FOUND);
        assert_eq!(request("PUT", "/", &["PROXY"], proxies.clone()).await.0, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(request("POST", "/", &["PROXY", "delay"], proxies.clone()).await.0, StatusCode::METHOD_NOT_ALLOWED);
        for method in ["GET", "POST"] {
            let (status, body) = request(method, "/", &["PROXY", "delay", ""], proxies.clone()).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} leftover path");
            assert_eq!(body, PLAIN_NOT_FOUND, "{method} leftover path");
        }
    }

    /// The group route accepts a millisecond timeout past the `i16` range, which is the width
    /// `/proxies/{name}/delay` and a provider's `/healthcheck` now read the same value with.
    #[tokio::test]
    async fn group_delay_endpoint_accepts_a_timeout_above_the_i16_range() {
        let proxies = vec![("PROXY".to_owned(), selector_wrapper())];

        let target = "/group/PROXY/delay?url=http://127.0.0.1:1/&timeout=60000&expected=";
        let (status, body) = request("GET", target, &["PROXY", "delay"], proxies).await;
        assert_eq!(
            status,
            StatusCode::GATEWAY_TIMEOUT,
            "the probe ran and failed on a closed port; body {}",
            String::from_utf8_lossy(&body)
        );
    }
}

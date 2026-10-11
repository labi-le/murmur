use std::sync::Arc;

use hyper::{Method, Response, StatusCode};

use murmur_constant::adapters::Proxy;
use murmur_constant::provider::interface::{ProxyProvider, RuleProvider};
use murmur_tunnel::tunnel;

use super::common::{
    get_escape_param, json_response, marshal_json_response, proxy_json_response, proxy_provider_marshal_json,
    rule_provider_marshal_json, status_only, Req, RespBody,
};
use super::errors::{err_not_found, HttpError};

/// The providers mount, over both proxy providers and rule providers.
///
/// The name lookup runs before the method is resolved, so an unknown name answers 404 for every
/// method instead of 405, and a trailing empty segment reaches the lookup as an empty name rather
/// than being dropped.
pub(crate) async fn route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    let (provider_name, rest) = match segs {
        [] => {
            if req.method() != Method::GET {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            return Some(get_providers());
        }
        [provider_name, rest @ ..] => (get_escape_param(provider_name), mount_tail(rest)),
    };

    let Some(provider) = tunnel::providers().get(&provider_name).cloned() else {
        return Some(json_response(StatusCode::NOT_FOUND, &err_not_found()));
    };

    match rest {
        [] => match *req.method() {
            Method::GET => Some(get_provider(&provider)),
            Method::PUT => Some(update_provider(&provider).await),
            _ => Some(status_only(StatusCode::METHOD_NOT_ALLOWED)),
        },
        ["healthcheck"] if req.method() == Method::GET => Some(health_check_provider(&provider).await),
        [name, tail @ ..] => {
            let name = get_escape_param(name);
            let tail = mount_tail(tail);
            let Some(proxy) = find_provider_proxy(&provider, &name) else {
                return Some(json_response(StatusCode::NOT_FOUND, &err_not_found()));
            };
            match tail {
                [] => match *req.method() {
                    Method::GET => Some(get_proxy(&proxy)),
                    _ => Some(status_only(StatusCode::METHOD_NOT_ALLOWED)),
                },
                ["healthcheck"] => match *req.method() {
                    Method::GET => Some(get_proxy_delay(&req, proxy).await),
                    _ => Some(status_only(StatusCode::METHOD_NOT_ALLOWED)),
                },
                _ => None,
            }
        }
    }
}

/// A mount registers both `pattern` and `pattern/`, handing the sub-router `/` in both cases; an
/// empty segment that is the last one therefore belongs to the mount above, not to the route below
/// (`/providers/proxies/{provider}/` is the provider's own `/` route). Only one is consumed per
/// mount, which is why `/providers/proxies/{provider}//` still names an empty proxy.
fn mount_tail<'a, 'b>(segments: &'a [&'b str]) -> &'a [&'b str] {
    match segments {
        [""] => &[],
        other => other,
    }
}

pub(crate) async fn rule_route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    let (name, rest) = match segs {
        [] => {
            if req.method() != Method::GET {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            return Some(get_rule_providers());
        }
        [name, rest @ ..] => (get_escape_param(name), mount_tail(rest)),
    };

    let Some(provider) = tunnel::rule_providers().get(&name).cloned() else {
        return Some(json_response(StatusCode::NOT_FOUND, &err_not_found()));
    };

    match rest {
        [] => {
            if req.method() != Method::PUT {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            Some(update_rule_provider(&provider).await)
        }
        _ => None,
    }
}

fn get_providers() -> Response<RespBody> {
    providers_response(tunnel::providers().iter().map(|(name, p)| (name.clone(), proxy_provider_marshal_json(&**p))))
}

fn get_rule_providers() -> Response<RespBody> {
    providers_response(
        tunnel::rule_providers().iter().map(|(name, p)| (name.clone(), rule_provider_marshal_json(&**p))),
    )
}

/// The serialized provider map. Its keys are sorted, but each value keeps its own field order,
/// which is part of the response; building it through `serde_json::Value` would sort those inner
/// keys too, so the body is assembled from each provider's preset bytes instead.
fn providers_response(values: impl Iterator<Item = (String, anyhow::Result<Vec<u8>>)>) -> Response<RespBody> {
    let mut providers = Vec::new();
    for (name, value) in values {
        match value {
            Ok(bytes) => providers.push((name, bytes)),
            Err(err) => return marshal_json_response(StatusCode::INTERNAL_SERVER_ERROR, Err(err)),
        }
    }
    providers.sort_by(|(a, _), (b, _)| a.cmp(b));

    let mut body = b"{\"providers\":{".to_vec();
    for (index, (name, value)) in providers.iter().enumerate() {
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

fn get_provider(provider: &Arc<dyn ProxyProvider>) -> Response<RespBody> {
    marshal_json_response(StatusCode::OK, proxy_provider_marshal_json(&**provider))
}

async fn update_provider(provider: &Arc<dyn ProxyProvider>) -> Response<RespBody> {
    if let Err(err) = provider.update().await {
        return json_response(StatusCode::SERVICE_UNAVAILABLE, &HttpError::new(err.to_string()));
    }
    super::common::no_content()
}

/// `constant::provider::interface::ProxyProvider::health_check` is `async fn`; unlike the
/// fire-and-forget health check a caller might expect, awaiting it means the response is only sent
/// once every probe has actually completed.
async fn health_check_provider(provider: &Arc<dyn ProxyProvider>) -> Response<RespBody> {
    provider.health_check().await;
    super::common::no_content()
}

/// The provider's proxy lookup; the 404 for an absent name is built by the caller, so a found
/// proxy costs no response.
fn find_provider_proxy(provider: &Arc<dyn ProxyProvider>, name: &str) -> Option<Arc<dyn Proxy>> {
    provider.proxies().into_iter().find(|proxy| proxy.name() == name)
}

/// Mounted under the provider-proxy route.
fn get_proxy(proxy: &Arc<dyn Proxy>) -> Response<RespBody> {
    proxy_json_response(StatusCode::OK, &**proxy)
}

/// The delay probe for a provider proxy; the `/healthcheck` route reuses `proxies.rs`'s handler,
/// so this delegates to the same implementation.
async fn get_proxy_delay(req: &Req, proxy: Arc<dyn Proxy>) -> Response<RespBody> {
    super::proxies::get_proxy_delay_for(req, proxy).await
}

async fn update_rule_provider(provider: &Arc<dyn RuleProvider>) -> Response<RespBody> {
    if let Err(err) = provider.update().await {
        return json_response(StatusCode::SERVICE_UNAVAILABLE, &HttpError::new(err.to_string()));
    }
    super::common::no_content()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::Infallible;

    use async_trait::async_trait;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use murmur_common::utils::ranges::IntRanges;
    use murmur_component::cidr::ipcidr_set::IpCidrSet;
    use murmur_constant::metadata::Metadata;
    use murmur_constant::provider::interface::{Provider, ProviderType, RuleBehavior, VehicleType};
    use murmur_constant::rule::RuleMatchHelper;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    /// The name lookup runs before the method is resolved, so an absent provider or rule-provider
    /// name answers 404 rather than 405 — the distinction the two routers are easiest to get
    /// backwards.
    const NOT_FOUND_BODY: &[u8] = b"{\"message\":\"Resource not found\"}\n";

    #[derive(Clone, Copy)]
    enum Router {
        Proxy,
        Rule,
    }

    /// Serves one request through `route`/`rule_route` over a real HTTP/1.1 connection, because
    /// the handlers take `hyper::body::Incoming`, which no hand-built request can supply.
    async fn request(router: Router, method: &str, segs: &[&str]) -> (StatusCode, Vec<u8>) {
        let segs: Vec<String> = segs.iter().map(|s| (*s).to_owned()).collect();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener has a local address");
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept loopback connection");
            let svc = service_fn(move |req: Req| {
                let segs = segs.clone();
                async move {
                    let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
                    let routed = match router {
                        Router::Proxy => route(req, &refs).await,
                        Router::Rule => rule_route(req, &refs).await,
                    };
                    Ok::<_, Infallible>(routed.unwrap_or_else(|| status_only(StatusCode::NOT_FOUND)))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(conn), svc).await;
        });

        let mut stream = TcpStream::connect(addr).await.expect("connect to loopback listener");
        let request = format!("{method} / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.expect("write request head");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");

        let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("response has a header/body split");
        let head = std::str::from_utf8(&raw[..head_end]).expect("response head is ascii");
        let status_str = head.split_whitespace().nth(1).expect("status line has a code");
        let status = StatusCode::from_bytes(status_str.as_bytes()).expect("valid status code");
        (status, raw[head_end + 4..].to_vec())
    }

    struct StubProvider {
        name: &'static str,
        type_: ProviderType,
    }

    #[async_trait]
    impl Provider for StubProvider {
        fn name(&self) -> String {
            self.name.to_owned()
        }

        fn vehicle_type(&self) -> VehicleType {
            VehicleType::FILE
        }

        fn type_(&self) -> ProviderType {
            self.type_
        }

        async fn initial(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn update(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn marshal_json(&self) -> anyhow::Result<Vec<u8>> {
            // Reverse-alphabetical on purpose: `serde_json::Value` would reorder these, so a list
            // body that matches byte for byte proves the presets were embedded verbatim.
            Ok(b"{\"zzz-marker\":\"last\",\"aaa-marker\":\"first\"}".to_vec())
        }
    }

    #[async_trait]
    impl ProxyProvider for StubProvider {
        fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
            Vec::new()
        }

        fn count(&self) -> i32 {
            0
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

    #[async_trait]
    impl RuleProvider for StubProvider {
        fn behavior(&self) -> RuleBehavior {
            RuleBehavior::CLASSICAL
        }

        fn count(&self) -> i32 {
            0
        }

        fn match_(&self, _metadata: &mut Metadata, _helper: &RuleMatchHelper) -> bool {
            false
        }

        fn to_ip_cidr(&self) -> Option<IpCidrSet> {
            None
        }
    }

    fn install_stub_providers() {
        let mut providers: HashMap<String, Arc<dyn ProxyProvider>> = HashMap::new();
        providers.insert(
            STUB_PROXY_PROVIDER.to_owned(),
            Arc::new(StubProvider { name: STUB_PROXY_PROVIDER, type_: ProviderType::PROXY }),
        );
        let mut rule_providers: HashMap<String, Arc<dyn RuleProvider>> = HashMap::new();
        rule_providers.insert(
            STUB_RULE_PROVIDER.to_owned(),
            Arc::new(StubProvider { name: STUB_RULE_PROVIDER, type_: ProviderType::RULE }),
        );
        tunnel::update_proxies(HashMap::new(), providers);
        tunnel::update_rules(Vec::new(), HashMap::new(), rule_providers);
    }

    fn clear_stub_providers() {
        tunnel::update_proxies(HashMap::new(), HashMap::new());
        tunnel::update_rules(Vec::new(), HashMap::new(), HashMap::new());
    }

    const STUB_PROXY_PROVIDER: &str = "__stub_proxy_provider__";
    const STUB_RULE_PROVIDER: &str = "__stub_rule_provider__";

    /// The stateful test installs these two names, so the stateless one must not use them.
    const ABSENT_PROVIDER: &str = "__absent_provider__";

    /// Both tests read and write the process-wide tunnel, which `route`/`rule_route` look their
    /// providers up in, so they may not interleave.
    static TUNNEL_STATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// No provider state is installed, so every name below is genuinely absent: the name lookup
    /// 404s whatever the method is, where checking the method first would answer 405.
    #[tokio::test]
    async fn an_unknown_name_is_404_for_every_method() {
        let _guard = TUNNEL_STATE.lock().await;

        for method in ["GET", "PUT", "POST", "DELETE", "PATCH"] {
            for segs in [
                &[ABSENT_PROVIDER][..],
                &[ABSENT_PROVIDER, "healthcheck"][..],
                &[ABSENT_PROVIDER, "proxy"][..],
                &[ABSENT_PROVIDER, "proxy", "healthcheck"][..],
            ] {
                let (status, body) = request(Router::Proxy, method, segs).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "proxy {method} {segs:?}");
                assert_eq!(body, NOT_FOUND_BODY, "proxy {method} {segs:?}");
            }

            for segs in [&[ABSENT_PROVIDER][..], &[ABSENT_PROVIDER, "deeper"][..]] {
                let (status, body) = request(Router::Rule, method, segs).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "rule {method} {segs:?}");
                assert_eq!(body, NOT_FOUND_BODY, "rule {method} {segs:?}");
            }
        }
    }

    /// The wire responses for the proxy and rule provider subtrees across methods.
    #[tokio::test]
    async fn known_providers_reject_unknown_children_and_wrong_methods() {
        let _guard = TUNNEL_STATE.lock().await;
        install_stub_providers();

        let (status, body) = request(Router::Proxy, "GET", &[]).await;
        assert_eq!(status, StatusCode::OK, "provider list");
        // The map's keys are sorted but each provider's own `marshal_json` bytes are embedded
        // untouched.
        assert_eq!(
            &body[..],
            b"{\"providers\":{\"__stub_proxy_provider__\":{\"zzz-marker\":\"last\",\"aaa-marker\":\"first\"}}}\n"
        );
        let (status, body) = request(Router::Rule, "GET", &[]).await;
        assert_eq!(status, StatusCode::OK, "rule provider list");
        assert_eq!(
            &body[..],
            b"{\"providers\":{\"__stub_rule_provider__\":{\"zzz-marker\":\"last\",\"aaa-marker\":\"first\"}}}\n"
        );

        let (status, _) = request(Router::Proxy, "GET", &[STUB_PROXY_PROVIDER]).await;
        assert_eq!(status, StatusCode::OK, "provider detail");
        // The `/{providerName}` mount registers `/{providerName}/` too, and that one is the
        // provider's own `/` route, not an empty proxy name.
        let (status, _) = request(Router::Proxy, "GET", &[STUB_PROXY_PROVIDER, ""]).await;
        assert_eq!(status, StatusCode::OK, "provider detail, trailing slash");
        let (status, _) = request(Router::Rule, "PUT", &[STUB_RULE_PROVIDER, ""]).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "rule provider update, trailing slash");

        // The provider resolves, so the method check — not the name check — decides.
        let (status, _) = request(Router::Proxy, "POST", &[STUB_PROXY_PROVIDER]).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "provider wrong method");
        let (status, _) = request(Router::Proxy, "POST", &[STUB_PROXY_PROVIDER, ""]).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "provider wrong method, trailing slash");
        let (status, _) = request(Router::Rule, "GET", &[STUB_RULE_PROVIDER]).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "rule provider wrong method");

        // The provider resolves but the named proxy does not: the proxy lookup 404s before the
        // method check, so even a non-GET answers 404.
        for method in ["GET", "PUT", "POST", "DELETE"] {
            for segs in [
                &[STUB_PROXY_PROVIDER, "absent"][..],
                &[STUB_PROXY_PROVIDER, "absent", "healthcheck"][..],
                &[STUB_PROXY_PROVIDER, "absent", "deeper"][..],
            ] {
                let (status, body) = request(Router::Proxy, method, segs).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "unknown proxy {method} {segs:?}");
                assert_eq!(body, NOT_FOUND_BODY, "unknown proxy {method} {segs:?}");
            }
        }

        // Only one trailing empty segment is absorbed by a mount, so the next one is a name.
        let (status, body) = request(Router::Proxy, "GET", &[STUB_PROXY_PROVIDER, "", ""]).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "empty proxy name");
        assert_eq!(body, NOT_FOUND_BODY, "empty proxy name");
        let (status, body) = request(Router::Proxy, "GET", &[STUB_PROXY_PROVIDER, "", "healthcheck"]).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "empty proxy name, healthcheck");
        assert_eq!(body, NOT_FOUND_BODY, "empty proxy name, healthcheck");
        let (status, body) = request(Router::Proxy, "GET", &[STUB_PROXY_PROVIDER, "healthcheck", ""]).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "trailing slash after healthcheck");
        assert_eq!(body, NOT_FOUND_BODY, "trailing slash after healthcheck");

        // `/healthcheck` is a literal route only for GET; every other method takes it as a proxy
        // name, which answers 404 rather than 405.
        let (status, _) = request(Router::Proxy, "GET", &[STUB_PROXY_PROVIDER, "healthcheck"]).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "provider healthcheck");
        let (status, body) = request(Router::Proxy, "PUT", &[STUB_PROXY_PROVIDER, "healthcheck"]).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "provider healthcheck, wrong method");
        assert_eq!(body, NOT_FOUND_BODY, "provider healthcheck, wrong method");

        // A name that resolves to nothing is the proxy lookup's 404 even when more segments
        // follow; only a resolved proxy name falling through answers the router's own not-found
        // page.
        let (status, body) = request(Router::Proxy, "GET", &[STUB_PROXY_PROVIDER, "absent", "deeper", ""]).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "proxy subtree");
        assert_eq!(body, NOT_FOUND_BODY, "proxy subtree");
        let (status, body) = request(Router::Rule, "PUT", &[STUB_RULE_PROVIDER, "", ""]).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "rule provider subtree");
        assert!(body.is_empty(), "rule provider subtree body {body:?}");

        clear_stub_providers();
    }
}

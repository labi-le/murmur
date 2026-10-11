//! The `["providers", …]` mount's trailing-slash matrix, in its own process so the tunnel state
//! it installs cannot race the sibling route modules' unit tests.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::pedantic,
    clippy::nursery
)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use murmur_adapter::adapter::Proxy as ConcreteProxy;
use murmur_adapter_outbound::direct::new_direct;
use murmur_common::utils::ranges::IntRanges;
use murmur_constant::adapters::Proxy;
use murmur_constant::provider::interface::{Provider, ProviderType, ProxyProvider, VehicleType};
use murmur_hub::route::server::{re_create_server, Config};
use murmur_tunnel::tunnel;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

const PROVIDER: &str = "__matrix_provider__";
const PROXY: &str = "DIRECT";

struct MatrixProvider(Vec<Arc<dyn Proxy>>);

#[async_trait]
impl Provider for MatrixProvider {
    fn name(&self) -> String {
        PROVIDER.to_owned()
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
        Ok(b"{\"matrix-marker\":true}".to_vec())
    }
}

#[async_trait]
impl ProxyProvider for MatrixProvider {
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

    fn register_health_check_task(&self, _url: &str, _expected_status: IntRanges<u16>, _filter: &str, _interval: u32) {}

    fn health_check_url(&self) -> String {
        String::new()
    }
}

/// `None` until the accept loop answers, so the caller can poll for readiness.
async fn request(addr: &str, method: &str, path: &str) -> Option<(String, String)> {
    let mut stream = TcpStream::connect(addr).await.ok()?;
    let head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await.expect("write request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");

    let split = raw.windows(4).position(|window| window == b"\r\n\r\n").expect("response head is terminated");
    let head = std::str::from_utf8(&raw[..split]).expect("response head is utf-8");
    let code = head.split_whitespace().nth(1).expect("status line has a code").to_owned();
    Some((code, String::from_utf8_lossy(&raw[split + 4..]).into_owned()))
}

/// The observable families the matrix rows fall into, so a row pins behaviour rather than bytes
/// that legitimately vary between runs.
fn class(body: &str) -> &str {
    let body = body.trim_end_matches('\n');
    if body.is_empty() {
        "empty"
    } else if body == "404 page not found" {
        "go-404-page"
    } else if body.starts_with("{\"message\":") {
        "json-message"
    } else if body.starts_with("{\"providers\":") {
        "providers-json"
    } else if body.starts_with("{\"matrix-marker\"") {
        "provider-detail"
    } else if body.starts_with('{') {
        "proxy-json"
    } else {
        "unexpected"
    }
}

/// Every row is the expected API response: `provider.rs`'s `mount_tail` already consumes the
/// mount-boundary slash, so an arity at the call site absorbs it twice (`{p}//` 200).
#[tokio::test]
async fn providers_mount_keeps_the_trailing_slash_matrix() {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("probe a free loopback port");
    let addr = probe.local_addr().expect("probe local address").to_string();
    drop(probe);

    re_create_server(Arc::new(Config { addr: addr.clone(), ..Config::default() })).await;

    let mut providers: HashMap<String, Arc<dyn ProxyProvider>> = HashMap::new();
    providers.insert(PROVIDER.to_owned(), Arc::new(MatrixProvider(vec![ConcreteProxy::new(new_direct())])));
    tunnel::update_proxies(HashMap::new(), providers);

    let rows: [(&str, String, &str, &str); 27] = [
        ("GET", "/providers/proxies".to_owned(), "200", "providers-json"),
        ("GET", "/providers/proxies/".to_owned(), "200", "providers-json"),
        ("GET", "/providers/proxies//".to_owned(), "404", "json-message"),
        ("GET", "/providers/proxies///".to_owned(), "404", "json-message"),
        ("GET", format!("/providers/proxies/{PROVIDER}"), "200", "provider-detail"),
        ("GET", format!("/providers/proxies/{PROVIDER}/"), "200", "provider-detail"),
        ("GET", format!("/providers/proxies/{PROVIDER}//"), "404", "json-message"),
        ("GET", format!("/providers/proxies/{PROVIDER}///"), "404", "json-message"),
        ("GET", format!("/providers/proxies/{PROVIDER}/healthcheck"), "204", "empty"),
        ("GET", format!("/providers/proxies/{PROVIDER}/healthcheck/"), "404", "json-message"),
        ("GET", format!("/providers/proxies/{PROVIDER}/healthcheck//"), "404", "json-message"),
        ("PUT", format!("/providers/proxies/{PROVIDER}"), "204", "empty"),
        ("PUT", format!("/providers/proxies/{PROVIDER}/"), "204", "empty"),
        ("PUT", format!("/providers/proxies/{PROVIDER}//"), "404", "json-message"),
        ("GET", format!("/providers/proxies/{PROVIDER}/{PROXY}"), "200", "proxy-json"),
        ("GET", format!("/providers/proxies/{PROVIDER}/{PROXY}/"), "200", "proxy-json"),
        ("GET", format!("/providers/proxies/{PROVIDER}/{PROXY}//"), "404", "go-404-page"),
        ("GET", format!("/providers/proxies/{PROVIDER}/{PROXY}/healthcheck"), "400", "json-message"),
        ("GET", format!("/providers/proxies/{PROVIDER}/{PROXY}/healthcheck/"), "404", "go-404-page"),
        ("GET", format!("/providers/proxies/{PROVIDER}/{PROXY}/healthcheck//"), "404", "go-404-page"),
        ("GET", "/providers/proxies/absent/".to_owned(), "404", "json-message"),
        ("GET", "/providers/proxies/absent///".to_owned(), "404", "json-message"),
        ("GET", "/providers/proxies/absent/healthcheck/".to_owned(), "404", "json-message"),
        ("GET", "/providers/rules".to_owned(), "200", "providers-json"),
        ("GET", "/providers/rules/".to_owned(), "200", "providers-json"),
        ("GET", "/providers/rules//".to_owned(), "404", "json-message"),
        ("GET", "/providers/rules///".to_owned(), "404", "json-message"),
    ];

    for (method, path, expected_code, expected_class) in &rows {
        let mut last = None;
        for _ in 0..500 {
            match request(&addr, method, path).await {
                Some(response) => {
                    last = Some(response);
                    break;
                }
                None => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        }
        let (code, body) = last.unwrap_or_else(|| panic!("{method} {path}: no external controller answered"));
        assert_eq!(&code, expected_code, "{method} {path}: {body:?}");
        assert_eq!(class(&body), *expected_class, "{method} {path}: {body:?}");
    }
}

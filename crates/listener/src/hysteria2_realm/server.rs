//! DEVIATION: a listen failure returns early and leaks the listeners already opened; this crate
//! closes them first (see [`Listener::new`]).
//!
//! The TCP listener is wrapped in TLS only when a certificate is configured, and clients are
//! authenticated with the same helpers the sibling inbounds use. A header-read timeout is applied to
//! the HTTP/1 side of hyper's auto builder, which needs an explicit timer for the timeout to
//! fire.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio_util::sync::CancellationToken;

use crate::hysteria2_realm::api;
use crate::hysteria2_realm::session::{new_server, Server, ServerConfig};
use murmur_adapter_inbound::addition::Addition;
use murmur_common_net::io::Acceptor;
use murmur_component_ca::auth::{
    client_auth_type_from_string, NO_CLIENT_CERT, REQUIRE_AND_VERIFY_CLIENT_CERT, VERIFY_CLIENT_CERT_IF_GIVEN,
};
use murmur_component_ca::keypair::{load_certificates, new_tls_key_pair_loader};
use murmur_component_ech::load_ech_key;
use murmur_component_tls::utls::{self as tls_c, ClientHelloInfo, Config as TlsConfig};
use murmur_constant::listener::{InboundListenConfig, MultiAddrListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::hysteria2_realm::Hysteria2RealmServer;
use murmur_std_compat::net::{Addr, TcpAddr};

pub const DEFAULT_MAX_REALMS: i32 = 65536;
pub const DEFAULT_MAX_REALMS_PER_IP: i32 = 4;

const READ_HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[must_use]
pub fn default_alpn() -> Vec<String> {
    vec!["h2".to_owned(), "http/1.1".to_owned()]
}

/// An address stand-in for the address list; `murmur_std_compat::net::Addr` has no clone method.
#[derive(Debug)]
struct StaticAddr {
    network: String,
    address: String,
}

impl Addr for StaticAddr {
    fn network(&self) -> &str {
        &self.network
    }

    fn string(&self) -> String {
        self.address.clone()
    }
}

fn capture_addr(addr: &dyn Addr) -> Box<dyn Addr> {
    Box::new(StaticAddr { network: addr.network().to_owned(), address: addr.string() })
}

pub struct Listener {
    closed: Arc<AtomicBool>,
    config: Hysteria2RealmServer,
    listeners: Vec<Arc<dyn Acceptor>>,
    addrs: Vec<Box<dyn Addr>>,
    cancel: CancellationToken,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Listener")
            .field("closed", &self.closed)
            .field("config", &self.config)
            .field("addrs", &self.addrs)
            .field("cancel", &self.cancel)
            .finish_non_exhaustive()
    }
}

/// The TLS configuration, `None` when no certificate is configured — in which case the listener
/// is not wrapped in TLS.
fn build_tls_config(config: &Hysteria2RealmServer) -> Result<Option<Arc<TlsConfig>>> {
    let mut tls_config = crate::tls_server_config(Arc::new(murmur_ntp::time::now));
    let has_certificate = if !config.certificate.is_empty() && !config.private_key.is_empty() {
        let cert_loader = new_tls_key_pair_loader(&config.certificate, &config.private_key)?;
        tls_config.certificates = vec![cert_loader()?];
        tls_config.get_certificate = Some(Arc::new(move |_info: &ClientHelloInfo| cert_loader().map(Some)));
        if !config.ech_key.is_empty() {
            load_ech_key(&config.ech_key, &mut tls_config)?;
        }
        true
    } else {
        false
    };
    tls_config.client_auth = client_auth_type_from_string(&config.client_auth_type);
    if !config.client_auth_cert.is_empty() && tls_config.client_auth == NO_CLIENT_CERT {
        tls_config.client_auth = REQUIRE_AND_VERIFY_CLIENT_CERT;
    }
    if tls_config.client_auth == VERIFY_CLIENT_CERT_IF_GIVEN || tls_config.client_auth == REQUIRE_AND_VERIFY_CLIENT_CERT
    {
        tls_config.client_cas = Some(load_certificates(&config.client_auth_cert)?);
    }
    Ok(has_certificate.then(|| Arc::new(tls_config)))
}

/// One task accepts connections until the listener is closed, backing off on a retryable accept
/// error.
fn spawn_accept_loop(listener: Arc<dyn Acceptor>, server: Arc<Server>, closed: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let mut backoff = std::time::Duration::from_millis(5);
        loop {
            let conn = if let Ok(conn) = listener.accept().await {
                backoff = std::time::Duration::from_millis(5);
                conn
            } else {
                if closed.load(Ordering::SeqCst) {
                    break;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(1));
                continue;
            };
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let remote_addr = conn.peer_addr().map(|addr| addr.to_string()).unwrap_or_default();
                let io = TokioIo::new(conn);
                let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let server = Arc::clone(&server);
                    let remote_addr = remote_addr.clone();
                    async move { Ok::<_, std::convert::Infallible>(api::serve(server, remote_addr, req).await) }
                });
                let mut builder = auto::Builder::new(TokioExecutor::new());
                {
                    let mut http1 = builder.http1();
                    http1.timer(TokioTimer::new());
                    http1.header_read_timeout(Some(READ_HEADER_TIMEOUT));
                }
                let _ = builder.serve_connection_with_upgrades(io, service).await;
            });
        }
    });
}

impl Listener {
    pub async fn new(
        config: Hysteria2RealmServer,
        lc: Arc<dyn InboundListenConfig>,
        _tunnel: Arc<dyn Tunnel>,
        _additions: &[Addition],
    ) -> Result<Self> {
        let pattern = regex::Regex::new(&config.realm_name_pattern)
            .map_err(|err| anyhow::anyhow!("invalid realm name pattern {:?}: {err}", config.realm_name_pattern))?;
        let server = Arc::new(new_server(ServerConfig {
            realm_token: config.token.clone(),
            max_realms: config.max_realms,
            max_realms_per_ip: config.max_realms_per_ip,
            proxy_header: config.trusted_proxy_header.clone(),
            realm_id_pattern: Some(pattern),
            connect_response_timeout: None,
        }));
        let tls_config = build_tls_config(&config)?;

        let closed = Arc::new(AtomicBool::new(false));
        let mut listeners: Vec<Arc<dyn Acceptor>> = Vec::new();
        let mut addrs: Vec<Box<dyn Addr>> = Vec::new();
        for addr in config.listen.split(',') {
            let raw: Arc<dyn Acceptor> = match lc.listen(&CancellationToken::new(), "tcp", addr).await {
                Ok(listener) => Arc::from(listener),
                Err(err) => {
                    for listener in &listeners {
                        let _ = listener.close();
                    }
                    return Err(err);
                }
            };
            let listener: Arc<dyn Acceptor> = match &tls_config {
                Some(tls_config) => Arc::from(tls_c::new_listener(Arc::clone(&raw), Arc::clone(tls_config))),
                None => raw,
            };
            if let Ok(addr) = listener.addr() {
                addrs.push(capture_addr(&TcpAddr::from(addr)));
            }
            spawn_accept_loop(Arc::clone(&listener), Arc::clone(&server), Arc::clone(&closed));
            listeners.push(listener);
        }

        let cancel = CancellationToken::new();
        tokio::spawn(Arc::clone(&server).reaper(cancel.clone()));

        Ok(Self { closed, config, listeners, addrs, cancel })
    }
}

impl MultiAddrListener for Listener {
    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        let mut ret_err: Option<anyhow::Error> = None;
        for listener in &self.listeners {
            if let Err(err) = listener.close() {
                ret_err = Some(err.into());
            }
        }
        self.cancel.cancel();
        ret_err.map_or(Ok(()), Err)
    }

    fn config(&self) -> String {
        self.config.to_string()
    }

    fn addr_list(&self) -> Vec<Box<dyn Addr>> {
        self.addrs.iter().map(|addr| capture_addr(addr.as_ref())).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use bytes::Bytes;
    use http_body_util::{BodyExt as _, Full};
    use hyper::body::Incoming;
    use hyper::{Method, Request, StatusCode};
    use serde_json::{json, Value};
    use tokio::net::TcpStream;

    use super::*;
    use murmur_adapter_inbound::listen::new_listen_config;
    use murmur_testsupport::{tls_certificate, tls_private_key, HttpTestTunnel};
    use murmur_testsupport_probe::ensure_test_crypto_provider;

    const TOKEN: &str = "realm-token";
    const NONCE: &str = "0102030405060708090a0b0c0d0e0f10";
    const OBFS: &str = "0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10";
    const HANG_DEADLINE: Duration = Duration::from_secs(30);

    fn config(certificate: &str, private_key: &str) -> Hysteria2RealmServer {
        Hysteria2RealmServer {
            enable: true,
            listen: "127.0.0.1:0".to_owned(),
            token: TOKEN.to_owned(),
            max_realms: DEFAULT_MAX_REALMS,
            max_realms_per_ip: DEFAULT_MAX_REALMS_PER_IP,
            realm_name_pattern: crate::hysteria2_realm::session::DEFAULT_REALM_NAME_PATTERN.to_owned(),
            certificate: certificate.to_owned(),
            private_key: private_key.to_owned(),
            alpn: default_alpn(),
            ..Default::default()
        }
    }

    async fn start(certificate: &str, private_key: &str) -> (Listener, SocketAddr) {
        let lc: Arc<dyn InboundListenConfig> = Arc::from(new_listen_config());
        let listener = Listener::new(config(certificate, private_key), lc, HttpTestTunnel::new(), &[])
            .await
            .expect("realm listener");
        let addr = listener.addr_list()[0].string().parse().expect("bound address");
        (listener, addr)
    }

    fn request(method: Method, path: &str, token: Option<&str>, body: &str) -> Request<Full<Bytes>> {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            builder = builder.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(Full::new(Bytes::copy_from_slice(body.as_bytes()))).expect("request")
    }

    async fn round_trip<IO>(io: IO, req: Request<Full<Bytes>>) -> (StatusCode, Bytes)
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await.expect("handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = sender.send_request(req).await.expect("send request");
        let status = resp.status();
        let body = resp.into_body().collect().await.expect("response body").to_bytes();
        (status, body)
    }

    async fn plain_round_trip(addr: SocketAddr, req: Request<Full<Bytes>>) -> (StatusCode, Bytes) {
        let stream = TcpStream::connect(addr).await.expect("connect realm listener");
        round_trip(stream, req).await
    }

    async fn tls_round_trip(addr: SocketAddr, req: Request<Full<Bytes>>) -> (StatusCode, Bytes) {
        let stream = TcpStream::connect(addr).await.expect("connect realm listener");
        let tls_config = Arc::new(TlsConfig { insecure_skip_verify: true, ..Default::default() });
        let conn = tls_c::client(Box::new(stream), tls_config);
        conn.handshake().await.expect("client handshake");
        round_trip(conn, req).await
    }

    fn json_of(body: &Bytes) -> Value {
        serde_json::from_slice(body).unwrap_or_else(|err| panic!("json body {body:?}: {err}"))
    }

    /// Opens the SSE stream on its own connection and returns the body to read events from. The
    /// request handle must outlive the reads, hence the returned pair.
    async fn open_events(
        addr: SocketAddr,
        token: &str,
    ) -> (hyper::client::conn::http1::SendRequest<Full<Bytes>>, Incoming) {
        let stream = TcpStream::connect(addr).await.expect("connect realm listener");
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.expect("handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = sender
            .send_request(request(Method::GET, "/v1/realm/events", Some(token), ""))
            .await
            .expect("events request");
        assert_eq!(resp.status(), StatusCode::OK);
        (sender, resp.into_body())
    }

    /// A register/heartbeat/deregister cycle proves the listener answers over TLS; the relayed
    /// payload round trip itself is covered by the plain-HTTP case below and by `api`'s tests.
    #[tokio::test(flavor = "multi_thread")]
    async fn realm_listener_serves_the_api_over_tls() {
        ensure_test_crypto_provider();
        let (listener, addr) = start(tls_certificate(), tls_private_key()).await;

        let (status, body) = tls_round_trip(
            addr,
            request(Method::POST, "/v1/realm", Some(TOKEN), r#"{"addresses":["203.0.113.5:1000"]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let session = json_of(&body)["session_id"].as_str().expect("session_id").to_owned();
        assert_eq!(json_of(&body)["ttl"], 60);

        let (status, body) = tls_round_trip(
            addr,
            request(Method::POST, "/v1/realm/heartbeat", Some(&session), r#"{"addresses":["198.51.100.7:2000"]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_of(&body)["ttl"], 60);

        let (status, _) = tls_round_trip(addr, request(Method::DELETE, "/v1/realm", Some(&session), "")).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        listener.close().expect("realm listener close");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn realm_listener_relays_a_punch_payload_over_plain_http() {
        ensure_test_crypto_provider();
        let (listener, addr) = start("", "").await;

        let (status, body) = plain_round_trip(
            addr,
            request(Method::POST, "/v1/realm", Some(TOKEN), r#"{"addresses":["203.0.113.5:1000"]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let register = json_of(&body);
        let session = register["session_id"].as_str().expect("session_id").to_owned();
        assert_eq!(register["ttl"], 60);

        let (_events, mut events_body) = open_events(addr, &session).await;

        let connect_body = json!({ "addresses": ["203.0.113.5:1000"], "nonce": NONCE, "obfs": OBFS }).to_string();
        let connect = tokio::spawn(async move {
            plain_round_trip(addr, request(Method::POST, "/v1/realm/connect", Some(TOKEN), &connect_body)).await
        });

        let frame = tokio::time::timeout(HANG_DEADLINE, events_body.frame())
            .await
            .expect("punch event within the deadline")
            .expect("punch event frame")
            .expect("punch event frame ok");
        let text = String::from_utf8(frame.into_data().expect("data frame").to_vec()).expect("utf8");
        let data = text.lines().find_map(|line| line.strip_prefix("data: ")).expect("data line");
        let punch = json_of(&Bytes::copy_from_slice(data.as_bytes()));
        assert_eq!(punch["nonce"], NONCE);
        assert_eq!(punch["obfs"], OBFS);
        assert_eq!(punch["addresses"], json!(["203.0.113.5:1000"]));

        let (status, _) = plain_round_trip(
            addr,
            request(
                Method::POST,
                &format!("/v1/realm/connects/{NONCE}"),
                Some(&session),
                r#"{"addresses":["198.51.100.7:2000"]}"#,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, body) = tokio::time::timeout(HANG_DEADLINE, connect)
            .await
            .expect("connect within the deadline")
            .expect("connect task");
        assert_eq!(status, StatusCode::OK);
        let answer = json_of(&body);
        assert_eq!(answer["addresses"], json!(["198.51.100.7:2000"]));
        assert_eq!(answer["nonce"], NONCE);
        assert_eq!(answer["obfs"], OBFS);

        listener.close().expect("realm listener close");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn realm_listener_rejects_an_invalid_realm_name_pattern() {
        ensure_test_crypto_provider();
        let mut bad = config("", "");
        bad.realm_name_pattern = "(".to_owned();
        let lc: Arc<dyn InboundListenConfig> = Arc::from(new_listen_config());
        let Err(err) = Listener::new(bad, lc, HttpTestTunnel::new(), &[]).await else {
            panic!("an uncompilable realm name pattern must be rejected");
        };
        assert!(err.to_string().starts_with("invalid realm name pattern"), "{err}");
    }
}

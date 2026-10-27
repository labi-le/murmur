//! DEVIATION: the WebSocket-path/gRPC/XHTTP closures capture the still-under-construction listener.
//!
//! Closures built during construction would need to observe later mutations of the listener, but
//! Rust cannot mutate a struct after other code has captured a reference into
//! it. [`handle_conn`] is therefore a free function taking the pieces `Listener::handle_conn`
//! also needs (`service`, `decryption`); both the closures built during construction and the
//! finished `Listener::handle_conn` call the same function.
//!
//! DEVIATION: the connection is closed by the callee on every error path here, where an interface
//! value stays usable after being handed to a callee. `conn` is moved into
//! `ServerInstance::handshake`/`Service::new_connection`, so a callee that errors already owns
//! (and, on return, drops) it; dropping a `Box<dyn Conn>` closes the underlying socket the same
//! way an explicit `close()` would, so no separate `close()` call is made after those calls.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures::future::BoxFuture;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio_util::sync::CancellationToken;

use crate::jls::listener as jls;
use crate::shadowtls::listener as shadowtls_listener;
use murmur_adapter_inbound::addition::{with_in_name, with_special_rules, Addition};
use murmur_common_net::io::{Acceptor, OldConnAsStream, Stream, StreamAsOldConn};
use murmur_common_net::sing::ExtendedConn;
use murmur_common_net::{get_websocket_sec_accept, new_cached_conn};
use murmur_component_ca::auth::client_auth_type_from_string;
use murmur_component_ca::keypair::{load_certificates, new_tls_key_pair_loader};
use murmur_component_ech::load_ech_key;
use murmur_component_tls::utls::{
    new_listener as tls_new_listener, ClientAuthType, ClientHelloInfo, Config as TlsConfig,
};
use murmur_constant::listener::InboundListenConfig;
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::vless::VlessServer;
use murmur_listener_sing::context::{with_additions, SingContext};
use murmur_listener_sing::sing::{new_listener_handler, ListenerConfig as SingListenerConfig, SingMetadata};
use murmur_log::warnln;
use murmur_ntp as ntp;
use murmur_reality::RealityServerConfig;
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Addr, Conn as NetConn, TcpAddr};
use murmur_transport::gun::server as gun_server;
use murmur_transport_vless::encryption::factory::new_server as new_decryption_server;
use murmur_transport_vless::encryption::server::ServerInstance;
use murmur_transport_vmess::websocket::stream_upgraded_websocket_conn;
use murmur_transport_xhttp::config::Config as XhttpConfig;
use murmur_transport_xhttp::server as xhttp_server;

use super::service::Service;

type ResponseBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

pub struct Listener {
    closed: Arc<AtomicBool>,
    config: VlessServer,
    listeners: Vec<Arc<dyn Acceptor>>,
    service: Arc<Service<String>>,
    decryption: Option<Arc<ServerInstance>>,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Listener")
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("listeners", &self.listeners.len())
            .field("decryption", &self.decryption.is_some())
            .finish_non_exhaustive()
    }
}

/// A layer of the handler chain (WebSocket-path mux, gRPC, XHTTP); every layer
/// answers the same concrete response body, so one trait covers `WsRouter`,
/// `gun_server::GunServerHandler` and `xhttp_server::RequestHandler` uniformly.
#[async_trait]
trait HttpLayer: Send + Sync {
    async fn serve(&self, req: Request<Incoming>) -> Response<ResponseBody>;
}

struct GunLayer(Arc<gun_server::GunServerHandler>);

#[async_trait]
impl HttpLayer for GunLayer {
    async fn serve(&self, req: Request<Incoming>) -> Response<ResponseBody> {
        gun_server::Handler::serve(&*self.0, req).await
    }
}

struct XhttpLayer(Arc<xhttp_server::RequestHandler>);

#[async_trait]
impl HttpLayer for XhttpLayer {
    async fn serve(&self, req: Request<Incoming>) -> Response<ResponseBody> {
        xhttp_server::Handler::serve(&*self.0, req).await
    }
}

/// Bridges an `Arc<dyn HttpLayer>` fallback into gun's own `Handler` trait, for
/// `gun_server::ServerOption::http_handler`.
struct HttpLayerAsGun(Arc<dyn HttpLayer>);

#[async_trait]
impl gun_server::Handler for HttpLayerAsGun {
    async fn serve(&self, req: Request<Incoming>) -> Response<ResponseBody> {
        self.0.serve(req).await
    }
}

/// Bridges an `Arc<dyn HttpLayer>` fallback into xhttp's own `Handler` trait, for
/// `xhttp_server::ServerOption::http_handler`.
struct HttpLayerAsXhttp(Arc<dyn HttpLayer>);

#[async_trait]
impl xhttp_server::Handler for HttpLayerAsXhttp {
    async fn serve(&self, req: Request<Incoming>) -> Response<ResponseBody> {
        self.0.serve(req).await
    }
}

/// The handler registered at the configured WebSocket path.
struct WsRouter {
    ws_path: String,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
    service: Arc<Service<String>>,
    decryption: Option<Arc<ServerInstance>>,
}

#[async_trait]
impl HttpLayer for WsRouter {
    async fn serve(&self, req: Request<Incoming>) -> Response<ResponseBody> {
        if req.uri().path() != self.ws_path || !is_websocket_upgrade(&req) {
            return not_found_response();
        }

        let sec_key = header_str(&req, "sec-websocket-key");
        let sec_protocol = header_str(&req, "sec-websocket-protocol");
        let response = switching_protocols_response(sec_key.as_deref());

        let service = Arc::clone(&self.service);
        let decryption = self.decryption.clone();
        let tunnel = Arc::clone(&self.tunnel);
        let additions = self.additions.clone();
        tokio::spawn(async move {
            let Ok(upgraded) = hyper::upgrade::on(req).await else { return };
            let Ok(parts) = auto::upgrade::downcast::<TokioIo<Box<dyn Stream>>>(upgraded) else { return };
            let raw = parts.io.into_inner();
            let conn: Box<dyn Stream> =
                if parts.read_buf.is_empty() { raw } else { Box::new(new_cached_conn(raw, parts.read_buf.to_vec())) };
            // S11: remove with murmur-std-compat, once transport_vmess::websocket::stream_upgraded_websocket_conn
            // takes/returns Stream
            let old_conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(conn));
            let conn: Box<dyn Stream> = Box::new(OldConnAsStream(stream_upgraded_websocket_conn(
                old_conn,
                sec_key.as_deref(),
                sec_protocol.as_deref(),
            )));
            handle_conn(&service, decryption.as_ref(), conn, tunnel, &additions).await;
        });

        response
    }
}

fn header_str(req: &Request<Incoming>, name: &str) -> Option<String> {
    req.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
}

fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    header_str(req, "upgrade").unwrap_or_default().eq_ignore_ascii_case("websocket")
}

fn empty_body() -> ResponseBody {
    Empty::<Bytes>::new().boxed()
}

fn not_found_response() -> Response<ResponseBody> {
    let mut response = Response::new(empty_body());
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

fn switching_protocols_response(sec_key: Option<&str>) -> Response<ResponseBody> {
    let mut response = Response::new(empty_body());
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let headers = response.headers_mut();
    headers.insert(hyper::header::UPGRADE, hyper::header::HeaderValue::from_static("websocket"));
    headers.insert(hyper::header::CONNECTION, hyper::header::HeaderValue::from_static("Upgrade"));
    if let Some(sec_key) = sec_key {
        if let Ok(accept) = hyper::header::HeaderValue::from_str(&get_websocket_sec_accept(sec_key)) {
            headers.insert("Sec-WebSocket-Accept", accept);
        }
    }
    response
}

/// The connection handler captured by the WebSocket-path/gRPC/XHTTP handlers during construction; see the
/// module doc for why this is a free function.
async fn handle_conn(
    service: &Arc<Service<String>>,
    decryption: Option<&Arc<ServerInstance>>,
    mut conn: Box<dyn Stream>,
    tunnel: Arc<dyn Tunnel>,
    additions: &[Addition],
) {
    let _ = &tunnel;
    let ctx = with_additions(&SingContext::default(), additions.to_vec());
    if let Some(decryption) = decryption {
        conn = match decryption.handshake(conn, None).await {
            Ok(c) => Box::new(c),
            Err(_) => return,
        };
    }
    let source = conn.peer_addr().map(|addr| Socksaddr::from_ip(addr.ip(), addr.port())).unwrap_or_default();
    let metadata = SingMetadata { protocol: "vless".to_owned(), source, destination: Socksaddr::default() };
    let _ = service.new_connection(ctx, conn, metadata).await;
}

pub async fn new(
    config: VlessServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: &[Addition],
) -> Result<Listener> {
    let additions: Vec<Addition> = if additions.is_empty() {
        vec![with_in_name("DEFAULT-VLESS"), with_special_rules("")]
    } else {
        additions.to_vec()
    };

    let service = build_service(&config, &tunnel, &additions)?;
    let decryption = new_decryption_server(&config.decryption)?.map(Arc::new);
    let mut tls_config = build_tls_config(&config)?;
    validate_security_modes(&config, &tls_config)?;

    let shadowtls_builder = if config.shadow_tls.enable {
        Some(shadowtls_listener::new(&config.shadow_tls, Arc::clone(&tunnel))?)
    } else {
        None
    };
    let jls_builder =
        if config.jls_config.enable { Some(jls::new(&config.jls_config, Arc::clone(&tunnel))?) } else { None };
    let reality_server_config =
        config.reality_config.as_ref().map(|c| crate::reality::build_server_config(c, Arc::clone(&tunnel)));

    let ws_layer = build_ws_layer(&config, &service, decryption.as_ref(), &tunnel, &additions, &mut tls_config);
    let http_layer =
        build_grpc_layer(&config, &service, decryption.as_ref(), &tunnel, &additions, ws_layer, &mut tls_config);
    let http_layer =
        build_xhttp_layer(&config, &service, decryption.as_ref(), &tunnel, &additions, http_layer, &mut tls_config)?;

    let tls_config = Arc::new(tls_config);
    let closed = Arc::new(AtomicBool::new(false));
    let mut listeners: Vec<Arc<dyn Acceptor>> = Vec::new();
    for addr in config.listen.split(',') {
        let l = lc.listen(&CancellationToken::new(), "tcp", addr).await?;
        let l = wrap_listener(
            l,
            shadowtls_builder.as_ref(),
            jls_builder.as_ref(),
            &tls_config,
            &config,
            decryption.as_ref(),
            reality_server_config.as_ref(),
        )?;
        let l: Arc<dyn Acceptor> = Arc::from(l);
        spawn_conn_loop(
            Arc::clone(&l),
            http_layer.clone(),
            Arc::clone(&service),
            decryption.clone(),
            Arc::clone(&tunnel),
            additions.clone(),
            reality_server_config.clone(),
            Arc::clone(&closed),
        );
        listeners.push(l);
    }

    Ok(Listener { closed, config, listeners, service, decryption })
}

/// Builds the listener service with its user table.
fn build_service(
    config: &VlessServer,
    tunnel: &Arc<dyn Tunnel>,
    additions: &[Addition],
) -> Result<Arc<Service<String>>> {
    let h = new_listener_handler(SingListenerConfig {
        tunnel: Arc::clone(tunnel),
        type_: Type::VLESS,
        additions: additions.to_vec(),
        udp_timeout: std::time::Duration::default(),
        mux_option: config.mux_option.clone(),
    })?;

    let mut service: Service<String> = Service::new(Arc::new(h));
    let user_list: Vec<String> = config.users.iter().map(|it| it.username.clone()).collect();
    let user_uuid_list: Vec<String> = config.users.iter().map(|it| it.uuid.clone()).collect();
    let user_flow_list: Vec<String> = config.users.iter().map(|it| it.flow.clone()).collect();
    service.update_users(&user_list, &user_uuid_list, &user_flow_list);
    Ok(Arc::new(service))
}

/// Builds the server TLS config: certificate loader, ECH keys, client-auth policy.
fn build_tls_config(config: &VlessServer) -> Result<TlsConfig> {
    let mut tls_config = crate::tls_server_config(Arc::new(ntp::time::now));
    if !config.certificate.is_empty() && !config.private_key.is_empty() {
        let cert_loader = new_tls_key_pair_loader(&config.certificate, &config.private_key)?;
        tls_config.get_certificate = Some(Arc::new(move |_info: &ClientHelloInfo| cert_loader().map(Some)));

        if !config.ech_key.is_empty() {
            load_ech_key(&config.ech_key, &mut tls_config)?;
        }
    }
    tls_config.client_auth = client_auth_type_from_string(&config.client_auth_type);
    if !config.client_auth_cert.is_empty() && tls_config.client_auth == ClientAuthType::NO_CLIENT_CERT {
        tls_config.client_auth = ClientAuthType::REQUIRE_AND_VERIFY_CLIENT_CERT;
    }
    if tls_config.client_auth == ClientAuthType::VERIFY_CLIENT_CERT_IF_GIVEN
        || tls_config.client_auth == ClientAuthType::REQUIRE_AND_VERIFY_CLIENT_CERT
    {
        tls_config.client_cas = Some(load_certificates(&config.client_auth_cert)?);
    }
    if tls_config.client_auth != ClientAuthType::NO_CLIENT_CERT && tls_config.get_certificate.is_none() {
        return Err(anyhow!("client-auth requires certificate"));
    }
    Ok(tls_config)
}

/// Rejects security modes that are unsupported, or combined with each other.
fn validate_security_modes(config: &VlessServer, tls_config: &TlsConfig) -> Result<()> {
    let mut security_modes: Vec<&str> = Vec::with_capacity(5);
    if tls_config.get_certificate.is_some() {
        security_modes.push("certificate");
    }
    if config.shadow_tls.enable {
        security_modes.push("shadow-tls");
    }
    if config.res_tls.enable {
        return Err(anyhow!("res-tls is not supported: Restls has no Rust implementation (see README)"));
    }
    if config.jls_config.enable {
        security_modes.push("jls");
    }
    if config.reality_config.is_some() {
        security_modes.push("reality");
    }
    if security_modes.len() > 1 {
        return Err(anyhow!("security modes are mutually exclusive: {}", security_modes.join(", ")));
    }
    Ok(())
}

/// Builds the WebSocket-path layer, when the config registers a path.
fn build_ws_layer(
    config: &VlessServer,
    service: &Arc<Service<String>>,
    decryption: Option<&Arc<ServerInstance>>,
    tunnel: &Arc<dyn Tunnel>,
    additions: &[Addition],
    tls_config: &mut TlsConfig,
) -> Option<Arc<dyn HttpLayer>> {
    if config.ws_path.is_empty() {
        return None;
    }
    let router = WsRouter {
        ws_path: config.ws_path.clone(),
        tunnel: Arc::clone(tunnel),
        additions: additions.to_vec(),
        service: Arc::clone(service),
        decryption: decryption.cloned(),
    };
    if !tls_config.next_protos.iter().any(|p| p == "http/1.1") {
        tls_config.next_protos.push("http/1.1".to_owned());
    }
    Some(Arc::new(router))
}

/// Wraps `fallback` in the gRPC layer, when the config registers a service name.
fn build_grpc_layer(
    config: &VlessServer,
    service: &Arc<Service<String>>,
    decryption: Option<&Arc<ServerInstance>>,
    tunnel: &Arc<dyn Tunnel>,
    additions: &[Addition],
    fallback: Option<Arc<dyn HttpLayer>>,
    tls_config: &mut TlsConfig,
) -> Option<Arc<dyn HttpLayer>> {
    if config.grpc_service_name.is_empty() {
        return fallback;
    }
    let http_fallback: Option<Arc<dyn gun_server::Handler>> =
        fallback.map(|layer| -> Arc<dyn gun_server::Handler> { Arc::new(HttpLayerAsGun(layer)) });
    let conn_handler_service = Arc::clone(service);
    let conn_handler_decryption = decryption.cloned();
    let conn_handler_tunnel = Arc::clone(tunnel);
    let conn_handler_additions = additions.to_vec();
    let handler = Arc::new(gun_server::new_server_handler(gun_server::ServerOption {
        service_name: config.grpc_service_name.clone(),
        conn_handler: Arc::new(move |conn: Box<dyn ExtendedConn>| -> BoxFuture<'static, ()> {
            let conn: Box<dyn Stream> = conn;
            let service = Arc::clone(&conn_handler_service);
            let decryption = conn_handler_decryption.clone();
            let tunnel = Arc::clone(&conn_handler_tunnel);
            let additions = conn_handler_additions.clone();
            Box::pin(async move { handle_conn(&service, decryption.as_ref(), conn, tunnel, &additions).await })
        }),
        http_handler: http_fallback,
    }));
    if !tls_config.next_protos.iter().any(|p| p == "h2") {
        tls_config.next_protos.insert(0, "h2".to_owned());
    }
    Some(Arc::new(GunLayer(handler)))
}

/// Wraps `fallback` in the XHTTP layer, when the config registers a path, host or mode.
fn build_xhttp_layer(
    config: &VlessServer,
    service: &Arc<Service<String>>,
    decryption: Option<&Arc<ServerInstance>>,
    tunnel: &Arc<dyn Tunnel>,
    additions: &[Addition],
    fallback: Option<Arc<dyn HttpLayer>>,
    tls_config: &mut TlsConfig,
) -> Result<Option<Arc<dyn HttpLayer>>> {
    if config.xhttp_config.path.is_empty() && config.xhttp_config.host.is_empty() && config.xhttp_config.mode.is_empty()
    {
        return Ok(fallback);
    }
    if !config.xhttp_config.mode.is_empty() {
        match config.xhttp_config.mode.as_str() {
            "auto" | "stream-up" | "stream-one" | "packet-up" => {}
            _ => return Err(anyhow!("unsupported xhttp mode")),
        }
    }
    let http_fallback: Option<Arc<dyn xhttp_server::Handler>> =
        fallback.map(|layer| -> Arc<dyn xhttp_server::Handler> { Arc::new(HttpLayerAsXhttp(layer)) });
    let conn_handler_service = Arc::clone(service);
    let conn_handler_decryption = decryption.cloned();
    let conn_handler_tunnel = Arc::clone(tunnel);
    let conn_handler_additions = additions.to_vec();
    let handler = xhttp_server::RequestHandler::new(xhttp_server::ServerOption {
        config: xhttp_config(config),
        conn_handler: Some(Arc::new(move |conn: Box<dyn NetConn>| -> BoxFuture<'static, ()> {
            // S11: remove with murmur-std-compat, once transport_xhttp::server::ConnHandler takes Stream
            let conn: Box<dyn Stream> = Box::new(OldConnAsStream(conn));
            let service = Arc::clone(&conn_handler_service);
            let decryption = conn_handler_decryption.clone();
            let tunnel = Arc::clone(&conn_handler_tunnel);
            let additions = conn_handler_additions.clone();
            Box::pin(async move { handle_conn(&service, decryption.as_ref(), conn, tunnel, &additions).await })
        })),
        http_handler: http_fallback,
    })?;
    if !tls_config.next_protos.iter().any(|p| p == "http/1.1") {
        tls_config.next_protos.insert(0, "http/1.1".to_owned());
    }
    if !tls_config.next_protos.iter().any(|p| p == "h2") {
        tls_config.next_protos.insert(0, "h2".to_owned());
    }
    Ok(Some(Arc::new(XhttpLayer(handler))))
}

/// Rebuilds the transport `XhttpConfig` from the listener config, which spells out only a subset
/// of the transport's fields; the rest keep the transport defaults.
fn xhttp_config(config: &VlessServer) -> XhttpConfig {
    let XhttpConfig {
        headers,
        no_grpc_header,
        session_table,
        session_length,
        sc_min_posts_interval_ms,
        reuse_config,
        download_config,
        ..
    } = XhttpConfig::default();
    XhttpConfig {
        host: config.xhttp_config.host.clone(),
        path: config.xhttp_config.path.clone(),
        mode: config.xhttp_config.mode.clone(),
        headers,
        no_grpc_header,
        x_padding_bytes: config.xhttp_config.x_padding_bytes.clone(),
        x_padding_obfs_mode: config.xhttp_config.x_padding_obfs_mode,
        x_padding_key: config.xhttp_config.x_padding_key.clone(),
        x_padding_header: config.xhttp_config.x_padding_header.clone(),
        x_padding_placement: config.xhttp_config.x_padding_placement.clone(),
        x_padding_method: config.xhttp_config.x_padding_method.clone(),
        uplink_http_method: config.xhttp_config.uplink_http_method.clone(),
        session_placement: config.xhttp_config.session_placement.clone(),
        session_key: config.xhttp_config.session_key.clone(),
        session_table,
        session_length,
        seq_placement: config.xhttp_config.seq_placement.clone(),
        seq_key: config.xhttp_config.seq_key.clone(),
        uplink_data_placement: config.xhttp_config.uplink_data_placement.clone(),
        uplink_data_key: config.xhttp_config.uplink_data_key.clone(),
        uplink_chunk_size: config.xhttp_config.uplink_chunk_size.clone(),
        no_sse_header: config.xhttp_config.no_sse_header,
        sc_stream_up_server_secs: config.xhttp_config.sc_stream_up_server_secs.clone(),
        sc_max_buffered_posts: config.xhttp_config.sc_max_buffered_posts.clone(),
        sc_max_each_post_bytes: config.xhttp_config.sc_max_each_post_bytes.clone(),
        sc_min_posts_interval_ms,
        reuse_config,
        download_config,
    }
}

/// Wraps a freshly accepted listener in the security layer the config selects.
fn wrap_listener(
    l: Box<dyn Acceptor>,
    shadowtls_builder: Option<&shadowtls_listener::Builder>,
    jls_builder: Option<&jls::Builder>,
    tls_config: &Arc<TlsConfig>,
    config: &VlessServer,
    decryption: Option<&Arc<ServerInstance>>,
    reality_server_config: Option<&Arc<RealityServerConfig>>,
) -> Result<Box<dyn Acceptor>> {
    if let Some(builder) = shadowtls_builder {
        return Ok(builder.new_listener(l));
    }
    if let Some(builder) = jls_builder {
        return Ok(builder.new_listener(l));
    }
    if tls_config.get_certificate.is_some() {
        return Ok(tls_new_listener(Arc::from(l), Arc::clone(tls_config)));
    }
    if reality_server_config.is_none() && decryption.is_none() && !config.allow_insecure {
        return Err(anyhow!(
            "disallow using Vless without any certificates/shadow-tls/reality/decryption/allow-insecure config"
        ));
    }
    Ok(l)
}

/// Spawns one listener's accept loop; every accepted connection runs through reality (when
/// configured) and then either the HTTP layer chain or [`handle_conn`].
fn spawn_conn_loop(
    l: Arc<dyn Acceptor>,
    http_layer: Option<Arc<dyn HttpLayer>>,
    service: Arc<Service<String>>,
    decryption: Option<Arc<ServerInstance>>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
    reality_server_config: Option<Arc<RealityServerConfig>>,
    closed: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        loop {
            let Ok(conn) = l.accept().await else {
                if closed.load(Ordering::SeqCst) {
                    break;
                }
                continue;
            };
            let http_layer = http_layer.clone();
            let service = Arc::clone(&service);
            let decryption = decryption.clone();
            let tunnel = Arc::clone(&tunnel);
            let additions = additions.clone();
            crate::reality::spawn_conn(conn, reality_server_config.clone(), move |conn| async move {
                if let Some(http_layer) = http_layer {
                    let addrs = crate::conn_addr::ConnAddrs::capture(&*conn);
                    let io = TokioIo::new(conn);
                    let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
                        let http_layer = Arc::clone(&http_layer);
                        addrs.insert(&mut req);
                        async move { Ok::<_, Infallible>(http_layer.serve(req).await) }
                    });
                    let builder = auto::Builder::new(TokioExecutor::new());
                    if let Err(err) = builder.serve_connection_with_upgrades(io, svc).await {
                        warnln!("vless xhttp server connection failed: {err:?}");
                    }
                    return;
                }

                handle_conn(&service, decryption.as_ref(), conn, tunnel, &additions).await;
            });
        }
    });
}

impl Listener {
    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        let mut ret_err: Option<anyhow::Error> = None;
        for l in &self.listeners {
            if let Err(err) = l.close() {
                ret_err = Some(err.into());
            }
        }
        if let Some(decryption) = &self.decryption {
            decryption.close();
        }
        ret_err.map_or(Ok(()), Err)
    }

    #[must_use]
    pub fn config(&self) -> String {
        self.config.to_string()
    }

    #[must_use]
    pub fn addr_list(&self) -> Vec<Box<dyn Addr>> {
        self.listeners
            .iter()
            .filter_map(|l| l.addr().ok())
            .map(|a| -> Box<dyn Addr> { Box::new(TcpAddr::from(a)) })
            .collect()
    }

    pub async fn handle_conn(&self, conn: Box<dyn Stream>, tunnel: Arc<dyn Tunnel>, additions: &[Addition]) {
        handle_conn(&self.service, self.decryption.as_ref(), conn, tunnel, additions).await;
    }
}

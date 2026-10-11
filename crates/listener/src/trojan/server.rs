//! The HTTP server has no crate mirror.
//!
//! This listener drives `hyper-util`'s auto (h1/h2c) connection builder directly over each accepted
//! conn instead, reusing `transport::gun::server::Handler`/`GunServerHandler`
//! for the gRPC-tunnel path and `transport::vmess::websocket::stream_upgraded_websocket_conn` for
//! the WebSocket path (both accept the same request/response vocabulary this crate builds).
//! The idle timeout has no equivalent knob on `hyper_util::server::conn::auto::Builder`
//! and is not enforced here. `smux` is provided by `murmur-smux` and re-exported by
//! `transport-kcptun::common::smux`; the trojan-mux path drives that real implementation.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures::future::BoxFuture;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, CONNECTION, UPGRADE};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use parking_lot::Mutex;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::jls::listener as jls;
use crate::shadowtls;
use crate::trojan::packet::Packet as TrojanPacket;
use murmur_adapter_inbound::addition::{with_in_name, with_in_user, with_special_rules, Addition};
use murmur_common::utils::uuid::new_uuid_v4;
use murmur_common_net::io::{
    close_stream, udp_addr_from_socket_addr, Acceptor, Datagram, Stream as NetStream, StreamAsOldConn,
};
use murmur_common_net::new_cached_conn;
use murmur_common_net::packet::datagram::WaitReadFromDatagram;
use murmur_common_net::sing::ExtendedConn as SingExtendedConn;
use murmur_common_net::websocket::get_websocket_sec_accept;
use murmur_component_ca::auth::{
    client_auth_type_from_string, NO_CLIENT_CERT, REQUIRE_AND_VERIFY_CLIENT_CERT, VERIFY_CLIENT_CERT_IF_GIVEN,
};
use murmur_component_ca::keypair::{load_certificates, new_tls_key_pair_loader};
use murmur_component_ech::load_ech_key;
use murmur_component_tls::utls::{self as tls_c, ClientHelloInfo};
use murmur_constant::adapters::UDPPacket;
use murmur_constant::listener::{InboundListenConfig, MultiAddrListener};
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::trojan::TrojanServer;
use murmur_listener_sing::sing::{new_listener_handler, ListenerConfig as SingListenerConfig, ListenerHandler};
use murmur_ntp::time::now as ntp_now;
use murmur_std_compat::net::{Addr, Conn as NetConn};
use murmur_transport::gun::server::{
    new_server_handler as gun_new_server_handler, ConnHandler as GunConnHandler, Handler as GunHandler,
    ServerOption as GunServerOption,
};
use murmur_transport::socks5::socks5;
use murmur_transport::trojan::trojan::{self as trojan, KEY_LENGTH};
use murmur_transport_kcptun::common::smux::{
    accept as smux_accept, default_config as smux_default_config, server as smux_server,
};
use murmur_transport_shadowsocks::core::cipher::{pick_cipher, Cipher};
use murmur_transport_vmess::websocket::stream_upgraded_websocket_conn;

/// `gun::server::Handler`'s private response-body alias, redeclared locally: identical
/// underlying type, so implementing `Handler` here needs no access to the private name.
type ResponseBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn not_found() -> Response<ResponseBody> {
    let mut response = Response::new(Empty::<Bytes>::new().boxed());
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    req.headers().get(UPGRADE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// The handler registered for the configured WebSocket path.
struct WsMuxHandler {
    ws_path: String,
    sl: Arc<Listener>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
}

#[async_trait]
impl GunHandler for WsMuxHandler {
    async fn serve(&self, mut req: Request<Incoming>) -> Response<ResponseBody> {
        if req.uri().path() != self.ws_path || !is_websocket_upgrade(&req) {
            return not_found();
        }
        let Some(sec_key) = req.headers().get("sec-websocket-key").and_then(|v| v.to_str().ok()).map(str::to_owned)
        else {
            return not_found();
        };
        let sec_protocol = req.headers().get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).map(str::to_owned);
        let accept = get_websocket_sec_accept(&sec_key);

        let on_upgrade = hyper::upgrade::on(&mut req);
        let sl = Arc::clone(&self.sl);
        let tunnel = Arc::clone(&self.tunnel);
        let additions = self.additions.clone();
        tokio::spawn(async move {
            let Ok(upgraded) = on_upgrade.await else {
                return;
            };
            let Ok(parts) = auto::upgrade::downcast::<TokioIo<Box<dyn NetStream>>>(upgraded) else {
                return;
            };
            // S11: remove with murmur-std-compat, once stream_upgraded_websocket_conn (transport-vmess) takes
            // Stream.
            let mut old: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(parts.io.into_inner()));
            if !parts.read_buf.is_empty() {
                // S11: remove in U5, once stream_upgraded_websocket_conn takes Stream.
                old = Box::new(new_cached_conn(murmur_common_net::io::OldConnAsStream(old), parts.read_buf.to_vec()));
            }
            let old = stream_upgraded_websocket_conn(old, Some(&sec_key), sec_protocol.as_deref());
            let conn: Box<dyn NetStream> = Box::new(murmur_common_net::io::OldConnAsStream(old));
            sl.handle_conn(conn, tunnel, additions).await;
        });
        let mut response = Response::new(Empty::<Bytes>::new().boxed());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        let headers = response.headers_mut();
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        if let Ok(accept) = HeaderValue::from_str(&accept) {
            headers.insert("Sec-WebSocket-Accept", accept);
        }
        response
    }
}

async fn serve_http_conn(handler: Arc<dyn GunHandler>, conn: Box<dyn NetStream>) {
    let io = TokioIo::new(conn);
    let svc = service_fn(move |req: Request<Incoming>| {
        let handler = Arc::clone(&handler);
        async move { Ok::<_, Infallible>(handler.serve(req).await) }
    });
    let builder = auto::Builder::new(TokioExecutor::new());
    let _ = builder.serve_connection_with_upgrades(io, svc).await;
}

pub struct Listener {
    closed: AtomicBool,
    config: TrojanServer,
    listeners: Mutex<Vec<Arc<dyn Acceptor>>>,
    keys: dashmap::DashMap<[u8; KEY_LENGTH], String>,
    pick_cipher: Option<Box<dyn Cipher>>,
    handler: ListenerHandler,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Listener").field("closed", &self.closed).finish_non_exhaustive()
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear constructor: it wires TLS, the cipher and key selection and the listener loops"
)]
pub async fn new(
    config: TrojanServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<Listener>> {
    let additions =
        if additions.is_empty() { vec![with_in_name("DEFAULT-TROJAN"), with_special_rules("")] } else { additions };

    let h = new_listener_handler(SingListenerConfig {
        tunnel: Arc::clone(&tunnel),
        type_: Type::TROJAN,
        additions: additions.clone(),
        udp_timeout: std::time::Duration::default(),
        mux_option: config.mux_option.clone(),
    })?;

    let keys: dashmap::DashMap<[u8; KEY_LENGTH], String> = dashmap::DashMap::new();
    for user in &config.users {
        keys.insert(trojan::key(&user.password), user.username.clone());
    }

    let pick_cipher: Option<Box<dyn Cipher>> = if config.trojan_ss_option.enabled {
        if config.trojan_ss_option.password.is_empty() {
            return Err(anyhow!("empty password"));
        }
        let method = if config.trojan_ss_option.method.is_empty() {
            "AES-128-GCM".to_owned()
        } else {
            config.trojan_ss_option.method.clone()
        };
        Some(pick_cipher(&method, None, &config.trojan_ss_option.password)?)
    } else {
        None
    };

    // The listener is assigned here, before the TLS/handler setup below, so its config observes the
    // pre-default value and the WebSocket-path/gRPC closures can already capture the listener
    // by value; `listeners` fills in as each address is bound further down.
    let sl = Arc::new(Listener {
        closed: AtomicBool::new(false),
        config: config.clone(),
        listeners: Mutex::new(Vec::new()),
        keys,
        pick_cipher,
        handler: h,
    });

    let mut tls_config = crate::tls_server_config(Arc::new(ntp_now));

    if !config.certificate.is_empty() && !config.private_key.is_empty() {
        let cert_loader = new_tls_key_pair_loader(&config.certificate, &config.private_key)?;
        tls_config.get_certificate = Some(Arc::new(move |_info: &ClientHelloInfo| cert_loader().map(Some)));

        if !config.ech_key.is_empty() {
            load_ech_key(&config.ech_key, &mut tls_config)?;
        }
    }
    tls_config.client_auth = client_auth_type_from_string(&config.client_auth_type);
    if !config.client_auth_cert.is_empty() && tls_config.client_auth == NO_CLIENT_CERT {
        tls_config.client_auth = REQUIRE_AND_VERIFY_CLIENT_CERT;
    }
    if tls_config.client_auth == VERIFY_CLIENT_CERT_IF_GIVEN || tls_config.client_auth == REQUIRE_AND_VERIFY_CLIENT_CERT
    {
        tls_config.client_cas = Some(load_certificates(&config.client_auth_cert)?);
    }
    if tls_config.client_auth != NO_CLIENT_CERT && tls_config.get_certificate.is_none() {
        return Err(anyhow!("client-auth requires certificate"));
    }

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

    let shadow_tls_builder = if config.shadow_tls.enable {
        Some(shadowtls::listener::new(&config.shadow_tls, Arc::clone(&tunnel))?)
    } else {
        None
    };

    let jls_builder =
        if config.jls_config.enable { Some(jls::new(&config.jls_config, Arc::clone(&tunnel))?) } else { None };
    let reality_server_config =
        config.reality_config.as_ref().map(|c| crate::reality::build_server_config(c, Arc::clone(&tunnel)));

    let mut handler: Option<Arc<dyn GunHandler>> = None;

    if !config.ws_path.is_empty() {
        handler = Some(Arc::new(WsMuxHandler {
            ws_path: config.ws_path.clone(),
            sl: Arc::clone(&sl),
            tunnel: Arc::clone(&tunnel),
            additions: additions.clone(),
        }));
        tls_config.next_protos.push("http/1.1".to_owned());
    }
    if !config.grpc_service_name.is_empty() {
        let http_handler = handler.take();
        let sl_for_grpc = Arc::clone(&sl);
        let tunnel_for_grpc = Arc::clone(&tunnel);
        let additions_for_grpc = additions.clone();
        let conn_handler: GunConnHandler = Arc::new(move |conn: Box<dyn SingExtendedConn>| {
            let conn: Box<dyn NetStream> = conn;
            let sl = Arc::clone(&sl_for_grpc);
            let tunnel = Arc::clone(&tunnel_for_grpc);
            let additions = additions_for_grpc.clone();
            Box::pin(async move { sl.handle_conn(conn, tunnel, additions).await })
        });
        handler = Some(Arc::new(gun_new_server_handler(GunServerOption {
            service_name: config.grpc_service_name.clone(),
            conn_handler,
            http_handler,
        })));
        tls_config.next_protos.insert(0, "h2".to_owned());
    }

    for addr in config.listen.split(',') {
        let l = match lc.listen(&CancellationToken::new(), "tcp", addr).await {
            Ok(l) => l,
            Err(err) => return Err(err),
        };
        let mut l: Box<dyn Acceptor> = l;
        if let Some(builder) = &shadow_tls_builder {
            l = builder.new_listener(l);
        } else if let Some(builder) = &jls_builder {
            l = builder.new_listener(l);
        } else if tls_config.get_certificate.is_some() {
            let tls_config = Arc::new(tls_config.clone());
            l = tls_c::new_listener(Arc::from(l), tls_config);
        } else if reality_server_config.is_none() && !config.trojan_ss_option.enabled && !config.allow_insecure {
            return Err(anyhow!(
                "disallow using Trojan without any certificates/shadow-tls/reality/ss/allow-insecure config"
            ));
        }
        let l: Arc<dyn Acceptor> = Arc::from(l);
        sl.listeners.lock().push(Arc::clone(&l));
    }

    let bound: Vec<Arc<dyn Acceptor>> = sl.listeners.lock().iter().map(Arc::clone).collect();
    for l in bound {
        let sl = Arc::clone(&sl);
        let tunnel = Arc::clone(&tunnel);
        let additions = additions.clone();
        let handler = handler.clone();
        let reality_server_config = reality_server_config.clone();
        tokio::spawn(async move {
            if let Some(handler) = handler {
                loop {
                    let Ok(conn) = l.accept().await else {
                        if sl.closed.load(Ordering::SeqCst) {
                            break;
                        }
                        continue;
                    };
                    let handler = Arc::clone(&handler);
                    crate::reality::spawn_conn(conn, reality_server_config.clone(), move |conn| async move {
                        serve_http_conn(handler, conn).await;
                    });
                }
                return;
            }
            loop {
                let Ok(conn) = l.accept().await else {
                    if sl.closed.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                };
                let sl = Arc::clone(&sl);
                let tunnel = Arc::clone(&tunnel);
                let additions = additions.clone();
                crate::reality::spawn_conn(conn, reality_server_config.clone(), move |conn| async move {
                    sl.handle_conn(conn, tunnel, additions).await;
                });
            }
        });
    }

    Ok(sl)
}

impl MultiAddrListener for Listener {
    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        let mut ret_err: Option<anyhow::Error> = None;
        for lis in self.listeners.lock().iter() {
            if let Err(err) = lis.close() {
                ret_err = Some(err.into());
            }
        }
        ret_err.map_or(Ok(()), Err)
    }

    fn config(&self) -> String {
        self.config.to_string()
    }

    fn addr_list(&self) -> Vec<Box<dyn Addr>> {
        self.listeners
            .lock()
            .iter()
            .filter_map(|lis| lis.addr().ok())
            .map(|addr| -> Box<dyn Addr> { Box::new(murmur_std_compat::net::TcpAddr::from(addr)) })
            .collect()
    }
}

impl Listener {
    async fn handle_conn(self: Arc<Self>, conn: Box<dyn NetStream>, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) {
        let mut conn = conn;
        if let Some(cipher) = &self.pick_cipher {
            // S11: remove with murmur-std-compat — `Cipher::stream_conn` (transport-shadowsocks) is still
            // `murmur_std_compat::net::Conn`-typed.
            let old: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(conn));
            let Ok(old) = cipher.stream_conn(old) else {
                return;
            };
            conn = Box::new(murmur_common_net::io::OldConnAsStream(old));
        }

        let mut key = [0u8; KEY_LENGTH];
        if conn.read_exact(&mut key).await.is_err() {
            return;
        }

        let mut additions = additions;
        match self.keys.get(&key) {
            Some(user) => additions.push(with_in_user(user.value())),
            None => return,
        }

        let mut crlf = [0u8; 2];
        if conn.read_exact(&mut crlf).await.is_err() {
            return;
        }

        self.handle_conn_inner(false, conn, tunnel, additions).await;
    }

    fn handle_conn_inner(
        self: Arc<Self>,
        in_mux: bool,
        conn: Box<dyn NetStream>,
        tunnel: Arc<dyn Tunnel>,
        additions: Vec<Addition>,
    ) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let mut conn = conn;

            let Ok(command) = socks5::read_byte(&mut conn).await else {
                if in_mux {
                    let _ = close_stream(&*conn);
                }
                return;
            };

            match command {
                trojan::COMMAND_TCP | trojan::COMMAND_UDP | trojan::COMMAND_MUX => {}
                _ => {
                    if in_mux {
                        let _ = close_stream(&*conn);
                    }
                    return;
                }
            }

            let Ok(target) = socks5::read_addr0(&mut conn).await else {
                if in_mux {
                    let _ = close_stream(&*conn);
                }
                return;
            };

            if !in_mux {
                let mut crlf = [0u8; 2];
                if conn.read_exact(&mut crlf).await.is_err() {
                    return;
                }
            }

            match command {
                trojan::COMMAND_TCP => {
                    self.handler.handle_socket(&target, conn, &additions).await;
                }
                trojan::COMMAND_UDP => {
                    // S11: remove with murmur-std-compat — `trojan::new_packet_conn` (transport crate) still
                    // takes a `murmur_std_compat::net::Conn`-typed input; its `PacketConn` output already
                    // implements `Stream`/`Datagram` directly.
                    let pc = Arc::new(trojan::new_packet_conn(Box::new(StreamAsOldConn::new(conn))));
                    let Ok(remote_addr) = NetStream::peer_addr(&*pc) else { return };
                    // A fresh SNAT key per
                    // call to `handle_conn_inner` (real conn or one smux substream), so several
                    // substreams sharing one physical TCP conn's `remote_addr` still land in
                    // distinct NAT entries.
                    let nat_key = new_uuid_v4().to_string();

                    loop {
                        let (data, put, addr, err) = WaitReadFromDatagram::wait_read_from(&*pc).await;
                        if err.is_err() {
                            if let Some(put) = put {
                                put();
                            }
                            break;
                        }
                        let Some(addr) = addr else {
                            if let Some(put) = put {
                                put();
                            }
                            continue;
                        };
                        let udp_addr = udp_addr_from_socket_addr(addr);
                        let Some(target) = socks5::parse_addr_to_socks_addr(&udp_addr) else {
                            if let Some(put) = put {
                                put();
                            }
                            continue;
                        };

                        let pc_clone = Arc::clone(&pc);
                        let pc_dyn: Arc<dyn Datagram> = pc_clone;
                        let c_packet = Arc::new(TrojanPacket::new(pc_dyn, remote_addr, nat_key.clone(), data, put));
                        let c_packet_dyn: Arc<dyn UDPPacket> = c_packet;
                        let (packet, metadata) =
                            murmur_adapter_inbound::packet::new_packet(&target, c_packet_dyn, Type::TROJAN, &additions);
                        tunnel.handle_udp_packet(packet, metadata);
                    }
                }
                trojan::COMMAND_MUX => {
                    if in_mux {
                        return;
                    }
                    let mut smux_config = smux_default_config();
                    smux_config.keep_alive_disabled = true;
                    let Ok(session) = smux_server(conn, &smux_config) else { return };
                    loop {
                        let Ok(stream) = smux_accept(session.as_ref()).await else {
                            break;
                        };
                        let stream: Box<dyn NetStream> = stream;
                        let sl = Arc::clone(&self);
                        let tunnel = Arc::clone(&tunnel);
                        let additions = additions.clone();
                        tokio::spawn(sl.handle_conn_inner(true, stream, tunnel, additions));
                    }
                    let _ = session.close();
                }
                _ => {}
            }
        })
    }
}

//! The sing-shadowsocks service has no Rust mirror anywhere in this tree.
//!
//! That service both terminates the Shadowsocks wire protocol and re-dispatches into a listener
//! handler; this crate substitutes [`ServerCipher`], the classic
//! AEAD/`none` cipher via `transport::shadowsocks::core::cipher` (the same protocol that layer
//! already speaks) and the `2022-blake3-*` list via
//! `transport::shadowsocks::shadowaead_2022::server::Service` — plus
//! `listener::sing::sing::ListenerHandler::handle_socket` for dispatch, the same combination
//! `listener::shadowsocks::tcp`/`udp` already use for the sibling non-sing listener.
//!
//! DEVIATION: `ListenerHandler::handle_socket` reads the target address off the decrypted stream
//! itself (matching the service's own per-connection framing) and dispatches through
//! `Tunnel::handle_tcp_conn`/`is_special_fqdn`, but it does not thread a `SingContext`, so the
//! `sp.mux.sing-box.arpa`/`v1.mux.cool`/UDP-over-TCP special-fqdn destinations the
//! `ListenerHandler::new_connection` can reach through the real service are unreachable here,
//! the same limitation the sibling `listener::shadowsocks` module already accepts. UDP dispatch is
//! implemented the same way `listener::shadowsocks::udp` already does it
//! (`Tunnel::handle_udp_packet`), bypassing `ListenerHandler::new_packet_connection` entirely; the
//! packet handler performs no special-fqdn detection either, so this carries no
//! extra capability loss.
//!
//! DEVIATION: a deferred assignment would publish the still-mutating listener pointer
//! on every return path out of construction, including nulling the previous global on an early
//! listener-handler failure and publishing a partially populated listener on a later
//! construction error. Rust's ownership model has no equivalent to aliasing a not-yet-complete
//! shared value that way, so [`LISTENER`] is only ever published on the two outcomes
//! `handle_shadow_socks` actually relies on: full success, and the unsupported-cipher fallback (an
//! empty listener with `cipher`/`handler` both `None`, matching the service-present
//! guard), the same precedent `listener::shadowsocks::tcp` already sets for its sibling file.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::jls::listener as jls;
use crate::shadowsocks::utils::Packet;
use crate::shadowtls::listener as shadowtls;
use murmur_adapter_inbound::addition::{with_in_name, with_in_user, with_special_rules, Addition};
use murmur_adapter_inbound::packet::new_packet;
use murmur_common::sockopt::reuse_common::raw_conn_reuseaddr;
use murmur_common_net::io::{
    close_stream, Acceptor, Datagram, DatagramAsOldPacketConn, OldConnAsStream, Stream, StreamAsOldConn,
};
use murmur_common_net::packet::packet::EnhancePacketConn;
use murmur_common_net::packet_file::new_enhance_packet_conn;
use murmur_constant::listener::{InboundListenConfig, MultiAddrListener};
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::shadowsocks::ShadowsocksServer;
use murmur_listener_sing::sing::{
    new_listener_handler, ListenerConfig as SingListenerConfig, ListenerHandler, UDP_TIMEOUT,
};
use murmur_log::warnln;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn as NetPacketConn, TcpAddr};
use murmur_transport::socks5::socks5;
use murmur_transport_kcptun::server::{HandlerFn as KcptunHandlerFn, Server as KcptunServer};
use murmur_transport_shadowsocks::core::cipher::{pick_cipher, Cipher};
use murmur_transport_shadowsocks::shadowaead_2022::server as ss2022_server;
use murmur_transport_simple_obfs::http_server::new_http_obfs_server;
use murmur_transport_simple_obfs::tls_server::new_tls_obfs_server;

const METHOD_NONE: &str = "none";

const SHADOWAEAD_LIST: &[&str] = &[
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "chacha8-ietf-poly1305",
    "xchacha8-ietf-poly1305",
    "rabbit128-poly1305",
    "aes-128-ccm",
    "aes-192-ccm",
    "aes-256-ccm",
    "aes-128-gcm-siv",
    "aes-256-gcm-siv",
    "aegis-128l",
    "aegis-256",
    "aez-384",
    "deoxys-ii-256-128",
    "lea-128-gcm",
    "lea-192-gcm",
    "lea-256-gcm",
    "ascon128",
    "ascon128a",
];

const SHADOWAEAD_2022_LIST: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "2022-blake3-chacha8-poly1305",
    "2022-blake3-aes-128-ccm",
    "2022-blake3-aes-256-ccm",
];

static LISTENER: ArcSwapOption<Listener> = ArcSwapOption::const_empty();

pub struct Listener {
    closed: Arc<AtomicBool>,
    config: ShadowsocksServer,
    listeners: Vec<Arc<dyn Acceptor>>,
    udp_listeners: Vec<Arc<dyn Datagram>>,
    cipher: Option<Arc<ServerCipher>>,
    handler: Option<Arc<ListenerHandler>>,
    // S11: remove with murmur-std-compat, once transport_simple_obfs::{http_server,tls_server} return Stream
    simple_obfs: Option<fn(Box<dyn NetConn>) -> Box<dyn NetConn>>,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Listener").field("closed", &self.closed.load(Ordering::Relaxed)).finish_non_exhaustive()
    }
}

/// Dispatches between the classic-cipher path (`transport::shadowsocks::core::cipher::Cipher`)
/// and the `2022-blake3-*` path (`transport::shadowsocks::shadowaead_2022::server::Service`); see
/// the module-level DEVIATION note this replaces.
enum ServerCipher {
    Classic(Arc<dyn Cipher>),
    Aead2022(Arc<ss2022_server::Service>),
}

impl ServerCipher {
    fn packet_conn(&self, conn: Arc<dyn EnhancePacketConn>) -> Result<Arc<dyn EnhancePacketConn>> {
        match self {
            Self::Classic(cipher) => cipher.packet_conn(conn),
            Self::Aead2022(service) => Ok(service.packet_conn(conn)),
        }
    }
}

/// Shares one underlying socket between `udp_listeners`'s close/enhance-conn clones and the
/// kcptun serve task.
struct ArcDatagram(Arc<dyn Datagram>);

#[async_trait]
impl Datagram for ArcDatagram {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)> {
        self.0.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], addr: std::net::SocketAddr) -> std::io::Result<usize> {
        self.0.send_to(buf, addr).await
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.0.local_addr()
    }

    fn close(&self) -> std::io::Result<()> {
        self.0.close()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.0.as_socket()
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        self.0.as_any()
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear constructor: it wires the cipher, the obfuscation and security builders, then spawns a TCP accept loop and a UDP read loop per listen address"
)]
pub async fn new(
    config: ShadowsocksServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<dyn MultiAddrListener>> {
    let register_default = additions.is_empty();
    let additions =
        if register_default { vec![with_in_name("DEFAULT-SHADOWSOCKS"), with_special_rules("")] } else { additions };

    let handler = Arc::new(new_listener_handler(SingListenerConfig {
        tunnel: Arc::clone(&tunnel),
        type_: Type::SHADOWSOCKS,
        additions: additions.clone(),
        udp_timeout: std::time::Duration::default(),
        mux_option: config.mux_option.clone(),
    })?);

    let cipher: Arc<ServerCipher> = if config.cipher == METHOD_NONE {
        Arc::new(ServerCipher::Classic(Arc::from(pick_cipher("dummy", None, "")?)))
    } else if SHADOWAEAD_LIST.contains(&config.cipher.as_str()) {
        Arc::new(ServerCipher::Classic(Arc::from(pick_cipher(&config.cipher, None, &config.password)?)))
    } else if SHADOWAEAD_2022_LIST.contains(&config.cipher.as_str()) {
        Arc::new(ServerCipher::Aead2022(ss2022_server::Service::new(&config.cipher, &config.password, UDP_TIMEOUT)?))
    } else {
        let listener = Listener {
            closed: Arc::new(AtomicBool::new(false)),
            config: config.clone(),
            listeners: Vec::new(),
            udp_listeners: Vec::new(),
            cipher: None,
            handler: None,
            simple_obfs: None,
        };
        if register_default {
            LISTENER.store(Some(Arc::new(listener)));
        }
        return crate::shadowsocks::tcp::new(config, lc, tunnel, additions)
            .await
            .map(|l| -> Arc<dyn MultiAddrListener> { l });
    };

    let mut security_modes: Vec<&str> = Vec::with_capacity(3);
    if config.shadow_tls.enable {
        security_modes.push("shadow-tls");
    }
    if config.res_tls.enable {
        return Err(anyhow!("res-tls is not supported: Restls has no Rust implementation (see README)"));
    }
    if config.jls_config.enable {
        security_modes.push("jls");
    }
    if security_modes.len() > 1 {
        return Err(anyhow!("security modes are mutually exclusive: {}", security_modes.join(", ")));
    }

    let shadow_tls_builder =
        if config.shadow_tls.enable { Some(shadowtls::new(&config.shadow_tls, Arc::clone(&tunnel))?) } else { None };

    let jls_builder =
        if config.jls_config.enable { Some(jls::new(&config.jls_config, Arc::clone(&tunnel))?) } else { None };

    // S11: remove with murmur-std-compat, once transport_simple_obfs::{http_server,tls_server} return Box<dyn Stream>
    let simple_obfs: Option<fn(Box<dyn NetConn>) -> Box<dyn NetConn>> = if config.simple_obfs.enable {
        match config.simple_obfs.mode.as_str() {
            "http" => Some(new_http_obfs_server),
            "tls" => Some(new_tls_obfs_server),
            other => return Err(anyhow!("unsupported simple obfs mode: {other}")),
        }
    } else {
        None
    };

    let mut udp_enabled = config.udp;
    let kcptun_server: Option<Arc<KcptunServer>> = if config.kcp_tun.enable {
        udp_enabled = true;
        Some(Arc::new(KcptunServer::new(config.kcp_tun.config.clone())))
    } else {
        None
    };

    let closed = Arc::new(AtomicBool::new(false));
    let mut listeners: Vec<Arc<dyn Acceptor>> = Vec::new();
    let mut udp_listeners: Vec<Arc<dyn Datagram>> = Vec::new();

    for addr in config.listen.split(',') {
        if udp_enabled {
            let dg: Arc<dyn Datagram> = Arc::from(lc.listen_packet(&CancellationToken::new(), "udp", addr).await?);

            if let Some(socket) = dg.as_socket() {
                if let Err(err) = raw_conn_reuseaddr(&*socket) {
                    warnln!("Failed to Reuse UDP Address: {err}");
                }
            }

            udp_listeners.push(Arc::clone(&dg));

            if let Some(kcptun_server) = &kcptun_server {
                let kcptun_server = Arc::clone(kcptun_server);
                let cipher_task = Arc::clone(&cipher);
                let handler_task = Arc::clone(&handler);
                let additions_task = additions.clone();
                // S11: remove with murmur-std-compat, once transport_kcptun::server::Server::serve takes Box<dyn Datagram>
                let pc: Box<dyn NetPacketConn> = Box::new(DatagramAsOldPacketConn(ArcDatagram(Arc::clone(&dg))));
                tokio::spawn(async move {
                    let handler_fn: KcptunHandlerFn = Arc::new(move |c: Box<dyn NetConn>| {
                        let cipher = Arc::clone(&cipher_task);
                        let handler = Arc::clone(&handler_task);
                        let additions = additions_task.clone();
                        tokio::spawn(async move {
                            // S11: remove with murmur-std-compat, once transport_kcptun::server::HandlerFn carries Box<dyn Stream>
                            let c: Box<dyn Stream> = Box::new(OldConnAsStream(c));
                            handle_conn(&cipher, simple_obfs, &handler, c, &additions).await;
                        });
                    });
                    let _ = kcptun_server.serve(pc, handler_fn).await;
                });

                continue;
            }

            // S11: remove with murmur-std-compat, once transport_shadowsocks::core::cipher::PacketConnCipher takes Arc<dyn Datagram>
            let conn = cipher.packet_conn(new_enhance_packet_conn(Arc::new(DatagramAsOldPacketConn(ArcDatagram(
                Arc::clone(&dg),
            )))))?;
            let closed_task = Arc::clone(&closed);
            let tunnel_task = Arc::clone(&tunnel);
            let additions_task = additions.clone();
            tokio::spawn(async move {
                loop {
                    let (data, put, remote_addr, result) = conn.wait_read_from().await;
                    if result.is_err() {
                        if let Some(put) = put {
                            put();
                        }
                        if closed_task.load(Ordering::SeqCst) {
                            break;
                        }
                        continue;
                    }
                    let Some(remote_addr) = remote_addr else {
                        if let Some(put) = put {
                            put();
                        }
                        continue;
                    };
                    let Ok(remote_addr) = murmur_common_net::io::old_addr_to_socket_addr(remote_addr.as_ref()) else {
                        if let Some(put) = put {
                            put();
                        }
                        continue;
                    };
                    let conn_arc = Arc::clone(&conn);
                    let conn_dyn: Arc<dyn NetPacketConn> = conn_arc;
                    handle_socks_udp(conn_dyn, &tunnel_task, &data, put, remote_addr, &additions_task);
                }
            });
        }

        let l: Box<dyn Acceptor> = lc.listen(&CancellationToken::new(), "tcp", addr).await?;
        let l: Box<dyn Acceptor> = if let Some(builder) = &shadow_tls_builder {
            builder.new_listener(l)
        } else if let Some(builder) = &jls_builder {
            builder.new_listener(l)
        } else {
            l
        };
        let l: Arc<dyn Acceptor> = Arc::from(l);
        listeners.push(Arc::clone(&l));

        let closed_task = Arc::clone(&closed);
        let cipher_task = Arc::clone(&cipher);
        let handler_task = Arc::clone(&handler);
        let additions_task = additions.clone();
        tokio::spawn(async move {
            loop {
                let Ok(c) = l.accept().await else {
                    if closed_task.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                };
                let cipher = Arc::clone(&cipher_task);
                let handler = Arc::clone(&handler_task);
                let additions = additions_task.clone();
                tokio::spawn(async move {
                    handle_conn(&cipher, simple_obfs, &handler, c, &additions).await;
                });
            }
        });
    }

    let listener = Arc::new(Listener {
        closed,
        config,
        listeners,
        udp_listeners,
        cipher: Some(cipher),
        handler: Some(handler),
        simple_obfs,
    });
    if register_default {
        LISTENER.store(Some(Arc::clone(&listener)));
    }

    Ok(listener)
}

impl MultiAddrListener for Listener {
    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        let mut ret_err: Option<anyhow::Error> = None;
        for lis in &self.listeners {
            if let Err(err) = lis.close() {
                ret_err = Some(err.into());
            }
        }
        for lis in &self.udp_listeners {
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
        fn boxed_tcp_addr(addr: std::net::SocketAddr) -> Box<dyn Addr> {
            Box::new(TcpAddr::from(addr))
        }
        fn boxed_udp_addr(addr: std::net::SocketAddr) -> Box<dyn Addr> {
            Box::new(murmur_common_net::io::udp_addr_from_socket_addr(addr))
        }
        let mut addr_list: Vec<Box<dyn Addr>> =
            self.listeners.iter().filter_map(|lis| lis.addr().ok()).map(boxed_tcp_addr).collect();
        addr_list.extend(self.udp_listeners.iter().filter_map(|lis| lis.local_addr().ok()).map(boxed_udp_addr));
        addr_list
    }
}

impl Listener {
    pub async fn handle_conn(&self, conn: Box<dyn Stream>, additions: &[Addition]) {
        let (Some(cipher), Some(handler)) = (&self.cipher, &self.handler) else {
            let _ = close_stream(conn.as_ref());
            return;
        };
        handle_conn(cipher, self.simple_obfs, handler, conn, additions).await;
    }
}

/// Split out so the per-address accept/kcptun loops can call it
/// before the final `Listener` is published; see the module-level DEVIATION note.
async fn handle_conn(
    cipher: &ServerCipher,
    simple_obfs: Option<fn(Box<dyn NetConn>) -> Box<dyn NetConn>>,
    handler: &Arc<ListenerHandler>,
    mut conn: Box<dyn Stream>,
    additions: &[Addition],
) {
    let user = shadowtls_user_from_conn(conn.as_ref());

    if let Some(simple_obfs) = simple_obfs {
        // S11: remove with murmur-std-compat, once transport_simple_obfs::{http_server,tls_server} take/return Box<dyn Stream>
        let old: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(conn));
        conn = Box::new(OldConnAsStream(simple_obfs(old)));
    }

    let mut additions = additions.to_vec();
    if let Some(user) = user {
        additions.push(with_in_user(&user));
    }

    let (conn, target) = match cipher {
        ServerCipher::Classic(cipher) => {
            // S11: remove with murmur-std-compat, once transport_shadowsocks::core::cipher::StreamConnCipher takes/returns Box<dyn Stream>
            let old: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(conn));
            let mut conn: Box<dyn Stream> = match cipher.stream_conn(old) {
                Ok(conn) => Box::new(OldConnAsStream(conn)),
                Err(_) => return,
            };
            let Ok(target) = socks5::read_addr0(&mut conn).await else {
                let _ = close_stream(conn.as_ref());
                return;
            };
            (conn, target)
        }
        ServerCipher::Aead2022(service) => {
            let Ok((stream, destination)) = service.accept(conn).await else { return };
            let Some(target) = socks5::parse_addr(&destination.string()) else {
                let _ = close_stream(stream.as_ref());
                return;
            };
            (stream, target)
        }
    };
    handler.handle_socket(&target, conn, &additions).await;
}

/// See the module-level DEVIATION note: the crate carries no boundary to test an erased
/// `Box<dyn Stream>` for the shadow-tls user identity, matching
/// `listener::shadowsocks::tcp`'s equivalent stand-in.
fn shadowtls_user_from_conn(_conn: &dyn Stream) -> Option<String> {
    None
}

/// Implemented the same way `listener::shadowsocks::udp` does it; see the
/// module-level DEVIATION note.
// S11: remove with murmur-std-compat, once transport_shadowsocks::core::cipher::PacketConnCipher's
// the pooled read (see `cipher.packet_conn` above) takes Arc<dyn Datagram>.
fn handle_socks_udp(
    pc: Arc<dyn NetPacketConn>,
    tunnel: &Arc<dyn Tunnel>,
    buf: &[u8],
    put: Option<Box<dyn FnOnce() + Send>>,
    addr: std::net::SocketAddr,
    additions: &[Addition],
) {
    let Some(tgt_addr) = socks5::split_addr(buf) else {
        if let Some(put) = put {
            put();
        }
        return;
    };
    let payload = buf.get(tgt_addr.len()..).unwrap_or_default().to_vec();

    let packet = Arc::new(Packet::new(pc, addr, payload, put));
    let (packet, metadata) = new_packet(&tgt_addr, packet, Type::SHADOWSOCKS, additions);
    tunnel.handle_udp_packet(packet, metadata);
}

pub fn handle_shadow_socks(conn: Box<dyn Stream>, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) -> bool {
    if let Some(listener) = LISTENER.load_full() {
        if listener.cipher.is_some() && listener.handler.is_some() {
            tokio::spawn(async move { listener.handle_conn(conn, &additions).await });
            return true;
        }
    }
    crate::shadowsocks::tcp::handle_shadow_socks(conn, tunnel, additions)
}

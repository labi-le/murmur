//! The Shadowsocks inbound listener: per-address accept loops with their cipher and obfuscation
//! wiring.
//!
//! DEVIATION: the listener is published before its own listener/udp-listener lists are
//! populated, and mutates those lists on the same single task afterward; a published `Arc<Listener>`
//! cannot be mutated that way. The per-address TCP accept loop only ever needs `pick_cipher`,
//! `handler` and `simple_obfs`, so those are built as their own `Arc`s before the per-address
//! loop, shared directly with the spawned accept tasks, and folded into the final `Listener` (which
//! also collects the listener lists) only once the loop finishes and is then published.
//! NEEDED SHIM ITEM: `murmur_std_compat::net::Conn`/`murmur_std_compat::net::Listener::accept` carry no
//! `as_any`/`UpstreamNode` boundary, so `listener::shadowtls::listener::user_from_conn` cannot be
//! invoked on the generic `Box<dyn Conn>` `handle_conn` receives here; the shadow-tls user lookup is
//! stubbed to `None`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use arc_swap::ArcSwapOption;
use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::addition::{with_in_user, Addition};
use murmur_common_net::io::{close_stream, Acceptor, OldConnAsStream, Stream as NetStream, StreamAsOldConn};
use murmur_common_net::new_deadline_conn;
use murmur_constant::listener::{InboundListenConfig, MultiAddrListener};
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::shadowsocks::ShadowsocksServer;
use murmur_std_compat::net::{Addr, Conn as NetConn};

use crate::jls::listener as jls;
use crate::shadowtls::listener as shadowtls;
use murmur_listener_sing::sing::{new_listener_handler, ListenerConfig as SingListenerConfig, ListenerHandler};
use murmur_transport::socks5::socks5;
use murmur_transport_shadowsocks::core::cipher::{pick_cipher, Cipher};
use murmur_transport_simple_obfs::http_server::new_http_obfs_server;
use murmur_transport_simple_obfs::tls_server::new_tls_obfs_server;

use super::udp::{bind_udp, BoundUdp, UdpListener};

static LISTENER: ArcSwapOption<Listener> = ArcSwapOption::const_empty();

pub struct Listener {
    config: ShadowsocksServer,
    closed: Arc<AtomicBool>,
    listeners: Vec<Arc<dyn Acceptor>>,
    udp_listeners: Vec<Arc<UdpListener>>,
    pick_cipher: Arc<dyn Cipher>,
    handler: Arc<ListenerHandler>,
    simple_obfs: Option<fn(Box<dyn NetConn>) -> Box<dyn NetConn>>,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Listener").field("closed", &self.closed.load(Ordering::Relaxed)).finish_non_exhaustive()
    }
}

pub async fn new(
    config: ShadowsocksServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<Listener>> {
    let cipher: Arc<dyn Cipher> = Arc::from(pick_cipher(&config.cipher, None, &config.password)?);

    let handler = Arc::new(new_listener_handler(SingListenerConfig {
        tunnel: Arc::clone(&tunnel),
        type_: Type::SHADOWSOCKS,
        additions: additions.clone(),
        udp_timeout: std::time::Duration::default(),
        mux_option: config.mux_option.clone(),
    })?);

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

    let simple_obfs: Option<fn(Box<dyn NetConn>) -> Box<dyn NetConn>> = if config.simple_obfs.enable {
        match config.simple_obfs.mode.as_str() {
            "http" => Some(new_http_obfs_server),
            "tls" => Some(new_tls_obfs_server),
            other => return Err(anyhow!("unsupported simple obfs mode: {other}")),
        }
    } else {
        None
    };

    let closed = Arc::new(AtomicBool::new(false));
    let mut listeners: Vec<Arc<dyn Acceptor>> = Vec::new();
    let mut udp_listeners: Vec<Arc<UdpListener>> = Vec::new();
    let mut udp_servers: Vec<BoundUdp> = Vec::new();

    for addr in config.listen.split(',') {
        if config.udp {
            let bound = bind_udp(addr, &lc, cipher.as_ref(), &tunnel, &additions).await?;
            udp_listeners.push(bound.listener());
            udp_servers.push(bound);
        }

        let mut l: Box<dyn Acceptor> = lc.listen(&CancellationToken::new(), "tcp", addr).await?;
        if let Some(builder) = &shadow_tls_builder {
            l = builder.new_listener(l);
        } else if let Some(builder) = &jls_builder {
            l = builder.new_listener(l);
        }
        listeners.push(Arc::from(l));
    }

    for server in udp_servers {
        server.serve();
    }

    for l in &listeners {
        let l = Arc::clone(l);
        let closed_task = Arc::clone(&closed);
        let cipher_task = Arc::clone(&cipher);
        let handler_task = Arc::clone(&handler);
        let tunnel_task = Arc::clone(&tunnel);
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
                let tunnel = Arc::clone(&tunnel_task);
                let additions = additions_task.clone();
                tokio::spawn(async move {
                    handle_conn(&cipher, simple_obfs, &handler, c, &tunnel, &additions).await;
                });
            }
        });
    }

    let sl = Arc::new(Listener { config, closed, listeners, udp_listeners, pick_cipher: cipher, handler, simple_obfs });
    LISTENER.store(Some(Arc::clone(&sl)));

    Ok(sl)
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
                ret_err = Some(err);
            }
        }
        ret_err.map_or(Ok(()), Err)
    }

    fn config(&self) -> String {
        self.config.to_string()
    }

    fn addr_list(&self) -> Vec<Box<dyn Addr>> {
        let mut addr_list: Vec<Box<dyn Addr>> = self
            .listeners
            .iter()
            .filter_map(|lis| lis.addr().ok())
            .map(|addr| -> Box<dyn Addr> { Box::new(murmur_std_compat::net::TcpAddr::from(addr)) })
            .collect();
        addr_list.extend(self.udp_listeners.iter().filter_map(|lis| lis.local_addr().ok()));
        addr_list
    }
}

impl Listener {
    pub async fn handle_conn(&self, conn: Box<dyn NetStream>, tunnel: &Arc<dyn Tunnel>, additions: &[Addition]) {
        handle_conn(&self.pick_cipher, self.simple_obfs, &self.handler, conn, tunnel, additions).await;
    }
}

/// Split out so the per-address accept loop can call it before the
/// final `Listener` is published; see the module-level DEVIATION note.
async fn handle_conn(
    pick_cipher: &Arc<dyn Cipher>,
    simple_obfs: Option<fn(Box<dyn NetConn>) -> Box<dyn NetConn>>,
    handler: &Arc<ListenerHandler>,
    conn: Box<dyn NetStream>,
    _tunnel: &Arc<dyn Tunnel>,
    additions: &[Addition],
) {
    let user = shadowtls_user_from_conn(&*conn);
    let mut additions = additions.to_vec();
    if let Some(user) = user {
        additions.push(with_in_user(&user));
    }

    // S11: remove with murmur-std-compat — `simple_obfs`/`Cipher::stream_conn` (transport-simple-obfs,
    // transport-shadowsocks) are still `murmur_std_compat::net::Conn`-typed, so the bridge into
    // `new_deadline_conn` stays for now.
    let mut conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(conn));
    if let Some(simple_obfs) = simple_obfs {
        conn = simple_obfs(conn);
    }
    let Ok(conn) = pick_cipher.stream_conn(conn) else {
        return;
    };
    // S11: remove in U5, once Cipher::stream_conn returns Box<dyn Stream>.
    let mut conn: Box<dyn NetStream> = new_deadline_conn(OldConnAsStream(conn));

    let Ok(target) = socks5::read_addr0(&mut conn).await else {
        let _ = close_stream(&*conn);
        return;
    };
    handler.handle_socket(&target, conn, additions.as_slice()).await;
}

/// See the module-level NEEDED SHIM ITEM note: the crate carries no boundary to test an erased
/// `Box<dyn Conn>` for the shadow-tls user identity.
fn shadowtls_user_from_conn(_conn: &dyn NetStream) -> Option<String> {
    None
}

pub fn handle_shadow_socks(conn: Box<dyn NetStream>, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) -> bool {
    if let Some(listener) = LISTENER.load_full() {
        tokio::spawn(async move { listener.handle_conn(conn, &tunnel, &additions).await });
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every address binds before any accept loop starts, so a later bind failure leaves nothing
    /// serving on the addresses that did bind.
    #[tokio::test]
    async fn a_failed_second_bind_releases_the_address_that_did_bind() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("hold a port");
        let taken_port = taken.local_addr().expect("held address").port();
        let free = (1..taken_port)
            .rev()
            .find_map(|port| std::net::TcpListener::bind(("127.0.0.1", port)).ok())
            .expect("a free port below the held one");
        let free_port = free.local_addr().expect("free address").port();
        drop(free);

        let config = ShadowsocksServer {
            listen: format!("127.0.0.1:{free_port},127.0.0.1:{taken_port}"),
            cipher: "aes-128-gcm".to_owned(),
            password: "password".to_owned(),
            ..Default::default()
        };
        let lc: Arc<dyn InboundListenConfig> = Arc::new(murmur_adapter_inbound::listen::new_listen_config());
        let tunnel: Arc<dyn Tunnel> = murmur_testsupport::HttpTestTunnel::new();

        let err = new(config, lc, tunnel, Vec::new()).await.expect_err("the held port must fail the listener");
        assert!(err.to_string().contains("Address already in use"), "the failure names the reason: {err}");

        std::net::TcpListener::bind(("127.0.0.1", free_port))
            .expect("the address that did bind must be released on the failure path");
    }
}

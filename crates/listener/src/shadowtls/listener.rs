use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{Acceptor, AcceptorAsOldListener, OldListenerAsAcceptor};
use murmur_common_net::new_handle_context_listener;
use murmur_common_net::UpstreamNode;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::shadowtls::{ShadowTLS, ShadowTLSHandshakeOptions};
use murmur_listener_inner::tcp::handle_tcp;
use murmur_log::errorln;
use murmur_std_compat::net::{Conn as NetConn, Listener as NetListener};
use murmur_transport_shadowtls::server::{
    new_server_config, server, user_from_conn as transport_user_from_conn, HandshakeConfig, ServerConfig, User,
    WildcardSNI,
};

pub struct Builder {
    config: Arc<ServerConfig>,
}

impl std::fmt::Debug for Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder").finish_non_exhaustive()
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "signature is part of the listener construction contract shared by every inbound"
)]
pub fn new(config: &ShadowTLS, tunnel: Arc<dyn Tunnel>) -> Result<Builder> {
    let build_handshake = |handshake: &ShadowTLSHandshakeOptions| -> HandshakeConfig {
        let tunnel = Arc::clone(&tunnel);
        let proxy = handshake.proxy.clone();
        HandshakeConfig {
            server: handshake.dest.clone(),
            dial_context: Some(Arc::new(move |_ctx: CancellationToken, _network: String, address: String| {
                let tunnel = Arc::clone(&tunnel);
                let proxy = proxy.clone();
                Box::pin(async move { handle_tcp(Some(tunnel), &address, &proxy).await })
            })),
        }
    };

    let mut handshake_for_server_name: HashMap<String, HandshakeConfig> = HashMap::new();
    if config.version > 1 {
        for (server_name, server_options) in &config.handshake_for_server_name {
            handshake_for_server_name.insert(server_name.clone(), build_handshake(server_options));
        }
    }

    let users: Vec<User> =
        config.users.iter().map(|u| User { name: u.name.clone(), password: u.password.clone() }).collect();

    let wildcard_sni = match config.wildcard_sni.as_str() {
        "authed" => WildcardSNI::Authed,
        "all" => WildcardSNI::All,
        _ => WildcardSNI::Off,
    };
    let server_config = new_server_config(
        config.version,
        &config.password,
        &users,
        build_handshake(&config.handshake),
        &handshake_for_server_name,
        config.strict_mode,
        wildcard_sni,
    )?;

    Ok(Builder { config: Arc::new(server_config) })
}

impl Builder {
    #[must_use]
    pub fn new_listener(&self, listener: Box<dyn Acceptor>) -> Box<dyn Acceptor> {
        let config = Arc::clone(&self.config);
        // S11: remove with murmur-std-compat — `new_handle_context_listener` (common-net) and
        // `transport_shadowtls::server::server` are still `murmur_std_compat::net::{Listener,Conn}`-typed.
        let listener: Box<dyn NetListener> = Box::new(AcceptorAsOldListener(listener));
        Box::new(OldListenerAsAcceptor(new_handle_context_listener(
            &CancellationToken::new(),
            listener,
            Arc::new(move |ctx, conn: SharedConn| {
                let config = Arc::clone(&config);
                Box::pin(async move {
                    let inbound: Box<dyn NetConn> = Box::new(conn);
                    let server_conn = server(&ctx, inbound, Some(&config)).await?;
                    let server_conn: Box<dyn NetConn> = server_conn;
                    Ok(SharedConn::from_boxed(server_conn))
                })
            }),
            Arc::new(|payload| {
                let stack = std::backtrace::Backtrace::force_capture();
                errorln!("shadowtls server panic: {}\n{stack}", panic_message(payload));
            }),
        )))
    }
}

pub fn user_from_conn(conn: &dyn UpstreamNode) -> Option<String> {
    transport_user_from_conn(conn)
}

/// The rendering of the value recovered from a panic.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_owned()
    }
}

use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{Acceptor, AcceptorAsOldListener, OldListenerAsAcceptor};
use murmur_common_net::new_handle_context_listener;
use murmur_common_net::UpstreamNode;
use murmur_constant::tunnel::Tunnel;
use murmur_jls_tls::JlsUser;
use murmur_listener_config::jls::JLSConfig;
use murmur_listener_inner::tcp::handle_tcp;
use murmur_log::errorln;
use murmur_std_compat::net::{Conn as NetConn, Listener as NetListener};
use murmur_transport_jls::server::{
    new_server_config, server, user_from_conn as transport_user_from_conn, DialContextFn, ServerConfig,
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
pub fn new(config: &JLSConfig, tunnel: Arc<dyn Tunnel>) -> Result<Builder> {
    let users: Vec<JlsUser> = config
        .users
        .iter()
        .map(|user| JlsUser { username: user.username.clone(), password: user.password.clone() })
        .collect();
    let dial_tunnel = Arc::clone(&tunnel);
    let proxy = config.proxy.clone();
    let dial_context: DialContextFn = Arc::new(move |_ctx: CancellationToken, _network: String, address: String| {
        let dial_tunnel = Arc::clone(&dial_tunnel);
        let proxy = proxy.clone();
        Box::pin(async move { handle_tcp(Some(dial_tunnel), &address, &proxy).await })
    });
    let server_config =
        new_server_config(&config.sni, &config.dest, &users, config.alpn.as_deref(), config.rate_limit, dial_context)?;
    Ok(Builder { config: Arc::new(server_config) })
}

impl Builder {
    #[must_use]
    pub fn new_listener(&self, listener: Box<dyn Acceptor>) -> Box<dyn Acceptor> {
        let config = Arc::clone(&self.config);
        // S11: remove with murmur-std-compat — `new_handle_context_listener` (common-net) and
        // `transport_jls::server::server` are still `murmur_std_compat::net::{Listener,Conn}`-typed.
        let listener: Box<dyn NetListener> = Box::new(AcceptorAsOldListener(listener));
        Box::new(OldListenerAsAcceptor(new_handle_context_listener(
            &CancellationToken::new(),
            listener,
            Arc::new(move |ctx, conn: SharedConn| {
                let config = Arc::clone(&config);
                Box::pin(async move {
                    let inbound: Box<dyn NetConn> = Box::new(conn);
                    let server_conn = server(&ctx, inbound, &config).await?;
                    let server_conn: Box<dyn NetConn> = server_conn;
                    Ok(SharedConn::new(server_conn))
                })
            }),
            Arc::new(|payload| {
                let stack = std::backtrace::Backtrace::force_capture();
                errorln!("jls server panic: {}\n{stack}", panic_message(payload));
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

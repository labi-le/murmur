//! JLS client over the plain TLS handshake path.
//!
//! Only the plain TLS client path is implemented. The fingerprinted-client
//! path cannot be: JLS authenticates the literal bytes of the
//! `ClientHello` it sends, and of the `ServerHello` it receives, but
//! `component_tls::utls::UConn` sends neither. It builds the fingerprinted
//! hello into `handshake_state.hello.raw` and then hands the socket to
//! `tokio_rustls`, which writes a `ClientHello` of its own, and
//! `PubClientHandshakeState` has no `server_hello` for the `ServerHello`
//! check. Adding it needs those two hooks in `component-tls`, not a change
//! here; the client below is functionally correct but more
//! fingerprint-detectable.

pub use crate::server::MODE;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{OldConnAsStream, StreamAsOldConn};
use murmur_component_ca::config::get_cert_pool;
use murmur_jls_tls::{ClientConfig as EngineClientConfig, JlsStatus, JlsUser};
use murmur_ntp::time::now as ntp_now;
use murmur_std_compat::net::Conn as NetConn;

use crate::server::DEFAULT_ALPN;

/// The `ClientFingerprint` field, which only applies to the fingerprinted client, is absent; see
/// the module comment.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub server_name: String,
    pub user: JlsUser,
    /// the nullable `[]string`: `None` selects [`DEFAULT_ALPN`], an empty
    /// slice selects no ALPN at all.
    pub alpn: Option<Vec<String>>,
}

pub fn new_client_config(
    server_name: &str,
    username: &str,
    password: &str,
    alpn: Option<Vec<String>>,
) -> Result<ClientConfig> {
    if server_name.is_empty() {
        return Err(anyhow!("jls: server name is required"));
    }
    Ok(crate::new_config(username, password)?.client_config(server_name, alpn))
}

// NOT cancel-safe: the handshake consumes `conn`, so a dropped call loses the connection.
pub async fn new_client(
    ctx: &CancellationToken,
    conn: Box<dyn NetConn>,
    config: &ClientConfig,
) -> Result<Box<dyn NetConn>> {
    let alpn = match &config.alpn {
        Some(alpn) => alpn.clone(),
        None => DEFAULT_ALPN.iter().map(|proto| (*proto).to_owned()).collect(),
    };
    let engine_config = EngineClientConfig {
        server_name: config.server_name.clone(),
        alpn,
        user: config.user.clone(),
        root_certs: get_cert_pool(),
        time: Some(Arc::new(ntp_now)),
    };
    let stream = tokio::select! {
        () = ctx.cancelled() => return Err(anyhow!("jls: client handshake cancelled")),
        result = murmur_jls_tls::client_handshake(OldConnAsStream(conn), &engine_config) => result?,
    };
    if stream.state().status != JlsStatus::Authenticated {
        return Err(anyhow!("jls: jls authentication failed"));
    }
    Ok(Box::new(StreamAsOldConn::new(stream)))
}

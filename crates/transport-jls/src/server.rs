use std::any::Any;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{close_stream, OldConnAsStream, StreamAsOldConn};
use murmur_common_net::sing::UpstreamNode;
use murmur_common_net::{find_upstream, new_cached_conn, new_extended_conn, relay_context, ExtendedConn};
use murmur_jls_tls::{JlsStatus, JlsUser, ServerConfig as EngineServerConfig};
use murmur_log::debugln;
use murmur_std_compat::net::{Addr, Conn as NetConn, ExtendedConn as NetExtendedConn, TcpAddr};

use crate::ratelimit::new_rate_limited_conn;

pub const MODE: &str = "jls";

pub const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

/// Keeps both the I/O and the `UpstreamNode` reflection capability alive through the
/// erasure back to a plain connection, which has no `as_any`.
// Deliberate blanket impl (guideline section 7): the trait is a name for "connection that also
// exposes its `UpstreamNode`" so `Box<dyn ServerConn>` can be built from any such connection.
pub trait ServerConn: NetConn + UpstreamNode {}
impl<T: NetConn + UpstreamNode + ?Sized> ServerConn for T {}

#[derive(thiserror::Error, Debug)]
#[error("jls: jls authentication failed")]
pub struct JlsAuthFailed;

#[derive(thiserror::Error, Debug)]
#[error("jls: connection relayed to fallback")]
pub struct FallbackCompleted;

pub type DialContextFn = Arc<
    dyn Fn(CancellationToken, String, String) -> Pin<Box<dyn Future<Output = Result<Box<dyn NetConn>>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct ServerConfig {
    tls: Arc<EngineServerConfig>,
    dest: String,
    rate_limit: u64,
    dial_context: DialContextFn,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("users", &self.tls.users)
            .field("server_name", &self.tls.server_name)
            .field("alpn", &self.tls.alpn)
            .field("dest", &self.dest)
            .field("rate_limit", &self.rate_limit)
            .finish_non_exhaustive()
    }
}

/// `NewServerConfig`. `alpn` is the nullable `[]string`: `None` selects
/// [`DEFAULT_ALPN`], an empty slice selects no ALPN at all.
pub fn new_server_config(
    sni: &str,
    dest: &str,
    users: &[JlsUser],
    alpn: Option<&[String]>,
    rate_limit: u64,
    dial_context: DialContextFn,
) -> Result<ServerConfig> {
    if dest.is_empty() {
        return Err(anyhow!("jls: dest is required"));
    }
    let (dest_host, _dest_port) =
        murmur_common::net_addr::split_host_port(dest).map_err(|err| anyhow!("jls: invalid dest address: {err}"))?;
    let server_name = if sni.is_empty() { dest_host } else { sni.to_owned() };
    if users.is_empty() {
        return Err(anyhow!("jls: at least one user is required"));
    }
    for user in users {
        if user.username.is_empty() {
            return Err(anyhow!("jls: username is required"));
        }
        if user.password.is_empty() {
            return Err(anyhow!("jls: password is required"));
        }
    }
    let alpn: Vec<String> = match alpn {
        Some(alpn) => alpn.to_vec(),
        None => DEFAULT_ALPN.iter().map(|proto| (*proto).to_owned()).collect(),
    };

    // JLS authenticates the peer, so this generated certificate only carries the TLS handshake.
    let cert = crate::cert::new_self_signed_cert()?;
    let tls = EngineServerConfig { users: users.to_vec(), server_name, alpn, cert_der: cert.cert_der, key: cert.key };
    Ok(ServerConfig { tls: Arc::new(tls), dest: dest.to_owned(), rate_limit, dial_context })
}

pub async fn server(
    ctx: &CancellationToken,
    conn: Box<dyn NetConn>,
    config: &ServerConfig,
) -> Result<Box<dyn ServerConn>> {
    let inbound = SharedConn::new(conn);
    match murmur_jls_tls::server_handshake(OldConnAsStream(inbound.clone()), &config.tls).await {
        Ok(stream) => {
            // Defensively reject a successful TLS handshake if custom configuration bypassed JLS
            // authentication.
            if stream.state().status != JlsStatus::Authenticated {
                return Err(JlsAuthFailed.into());
            }
            let user = stream.state().user.clone();
            debugln!("[JLS] handshake finished, user: {user}");
            let stream: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(stream));
            Ok(Box::new(AuthenticatedConn::new(stream, user)))
        }
        // A partial or complete server flight may have been written before a later client message
        // or network error; forwarding would then mix two TLS handshakes, so only a failure with
        Err(err) => {
            let message = format!("{err}");
            match err.replayable_prefix() {
                Some(consumed) => Err(config.relay_fallback(ctx, inbound, consumed).await),
                None => Err(anyhow!("jls: {message}")),
            }
        }
    }
}

impl ServerConfig {
    async fn relay_fallback(&self, ctx: &CancellationToken, inbound: SharedConn, prefix: Vec<u8>) -> anyhow::Error {
        let upstream = match (self.dial_context)(ctx.clone(), "tcp".to_owned(), self.dest.clone()).await {
            Ok(upstream) => upstream,
            Err(err) => return anyhow!("jls: dial fallback destination: {err}"),
        };
        let mut inbound = new_cached_conn(OldConnAsStream(inbound), prefix);
        let mut upstream = new_rate_limited_conn(upstream, self.rate_limit);
        if let Err(err) = relay_context(ctx, &mut inbound, &mut *upstream).await {
            return err;
        }
        FallbackCompleted.into()
    }
}

/// Carries the authenticated username through the erasure back to a plain connection, so
/// `user_from_conn` can recover it by walking the connection chain.
struct AuthenticatedConn {
    conn: Box<dyn ExtendedConn>,
    user: String,
}

impl AuthenticatedConn {
    fn new(conn: Box<dyn NetConn>, user: String) -> Self {
        Self { conn: new_extended_conn(OldConnAsStream(conn)), user }
    }
}

impl AsyncRead for AuthenticatedConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for AuthenticatedConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_shutdown(cx)
    }
}

impl NetConn for AuthenticatedConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.conn.local_addr()?)))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.conn.peer_addr()?)))
    }

    fn close(&self) -> io::Result<()> {
        close_stream(&*self.conn)
    }

    fn close_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.old_conn().map_or(Ok(()), |inner| inner.set_deadline(deadline))
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.old_conn().map_or(Ok(()), |inner| inner.set_read_deadline(deadline))
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.old_conn().map_or(Ok(()), |inner| inner.set_write_deadline(deadline))
    }
}

impl NetExtendedConn for AuthenticatedConn {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(&self.conn)
    }
}

impl UpstreamNode for AuthenticatedConn {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&*self.conn)
    }
}

/// The connection parameter has no Rust equivalent that can be walked to an `UpstreamNode`.
/// Callers pass the richer `&dyn UpstreamNode` this crate's conns implement.
pub fn user_from_conn(conn: &dyn UpstreamNode) -> Option<String> {
    find_upstream::<AuthenticatedConn>(conn, None).map(|found| found.user.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// the `if alpn == nil` only fires for a nil slice, so a non-nil empty slice reaches
    /// `NextProtos` empty and the server offers no ALPN at all.
    #[test]
    fn new_server_config_defaults_only_a_nil_alpn() {
        let dial_context: DialContextFn = Arc::new(|_ctx, _network, _address| {
            let unused: Result<Box<dyn NetConn>> = Err(anyhow!("dial context unused in this test"));
            Box::pin(async move { unused })
        });
        let alpn_of = |alpn: Option<&[String]>| -> Vec<String> {
            let users = [JlsUser { username: "u".to_owned(), password: "p".to_owned() }];
            new_server_config("sni", "127.0.0.1:8443", &users, alpn, 0, Arc::clone(&dial_context))
                .unwrap()
                .tls
                .alpn
                .clone()
        };
        assert_eq!(alpn_of(None), DEFAULT_ALPN);
        assert_eq!(alpn_of(Some(&[])), Vec::<String>::new());
        assert_eq!(alpn_of(Some(&[String::from("h3")])), ["h3"]);
    }
}

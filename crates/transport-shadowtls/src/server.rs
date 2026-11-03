use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use hmac::Mac as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{close_stream, OldConnAsStream, Stream};
use murmur_common_net::sing::UpstreamNode;
use murmur_common_net::{find_upstream, new_cached_conn, new_extended_conn, relay_context, ExtendedConn};
use murmur_log::{debugln, warnln};
use murmur_std_compat::net::{Addr, Conn as NetConn, ExtendedConn as NetExtendedConn, TcpAddr};

use super::protocol::{
    copy_until_handshake_finished, extract_server_name, extract_server_random, is_server_hello_support_tls13,
    read_frame,
};
use super::v2::{copy_until_handshake_finished_v2, HashWriteConn, ShadowConn};
use super::v3::{
    copy_by_frame_until_hmac_matches, copy_by_frame_with_modification, new_verified_conn, verify_client_hello,
};

/// A package-local connection marker standing in as an untyped connection value, keeping full
/// runtime type info.
///
/// The connection trait deliberately has no `as_any`, so the user lookup needs a package-local
/// trait that keeps both the I/O and the `UpstreamNode` reflection capability alive through the
/// erasure back to a plain connection.
pub trait ServerConn: NetConn + UpstreamNode {}
impl<T: NetConn + UpstreamNode + ?Sized> ServerConn for T {}

#[derive(thiserror::Error, Debug)]
#[error("shadow-tls: connection relayed to fallback")]
pub struct FallbackCompleted;

pub type DialContextFn = Arc<
    dyn Fn(CancellationToken, String, String) -> Pin<Box<dyn Future<Output = Result<Box<dyn NetConn>>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct HandshakeConfig {
    pub server: String,
    pub dial_context: Option<DialContextFn>,
}

impl std::fmt::Debug for HandshakeConfig {
    /// Omits the dial closure, which has no meaningful representation.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeConfig")
            .field("server", &self.server)
            .field("dial_context", &self.dial_context.as_ref().map(|_| "<fn>"))
            .finish_non_exhaustive()
    }
}

impl HandshakeConfig {
    #[must_use]
    pub fn valid(&self) -> bool {
        !self.server.is_empty() && self.dial_context.is_some()
    }

    async fn dial(&self, ctx: &CancellationToken) -> Result<Box<dyn NetConn>> {
        if !self.valid() {
            return Err(anyhow!("shadow-tls: missing handshake information"));
        }
        let Some(dial_context) = self.dial_context.as_ref() else {
            return Err(anyhow!("shadow-tls: missing handshake information"));
        };
        let dial_context = Arc::clone(dial_context);
        dial_context(ctx.clone(), "tcp".to_owned(), self.server.clone()).await
    }
}

#[derive(Clone)]
pub struct User {
    pub name: String,
    pub password: String,
}

impl std::fmt::Debug for User {
    /// Redacts `password` so accidental `{:?}` logging cannot leak it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User").field("name", &self.name).field("password", &"<redacted>").finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum WildcardSNI {
    #[default]
    Off,
    Authed,
    All,
}

pub struct ServerConfig {
    version: i32,
    password: String,
    users: Vec<User>,
    handshake: HandshakeConfig,
    handshake_for_server_name: HashMap<String, HandshakeConfig>,
    strict_mode: bool,
    wildcard_sni: WildcardSNI,
}

impl std::fmt::Debug for ServerConfig {
    /// Redacts `password` so accidental `{:?}` logging cannot leak it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("version", &self.version)
            .field("password", &"<redacted>")
            .field("users", &self.users)
            .field("handshake", &self.handshake)
            .field("handshake_for_server_name", &self.handshake_for_server_name)
            .field("strict_mode", &self.strict_mode)
            .field("wildcard_sni", &self.wildcard_sni)
            .finish_non_exhaustive()
    }
}

/// Version validation on the server. Unlike `client::check_version`, it accepts version 3 (the
/// server never needs the client's `ClientHello` session-id hook), so it stays local.
fn check_version(version: i32) -> Result<()> {
    if !(1..=3).contains(&version) {
        return Err(anyhow!("shadow-tls: unknown protocol version: {version}"));
    }
    Ok(())
}

#[expect(
    clippy::implicit_hasher,
    reason = "public constructor takes a plain `HashMap`; generalizing over the hasher would change the public signature"
)]
pub fn new_server_config(
    version: i32,
    password: &str,
    users: &[User],
    handshake: HandshakeConfig,
    handshake_for_server_name: &HashMap<String, HandshakeConfig>,
    strict_mode: bool,
    wildcard_sni: WildcardSNI,
) -> Result<ServerConfig> {
    check_version(version)?;
    if version == 3 && users.is_empty() {
        return Err(anyhow!("shadow-tls: at least one user is required"));
    }
    if !handshake.valid() && wildcard_sni == WildcardSNI::Off {
        return Err(anyhow!("shadow-tls: missing default handshake information"));
    }
    if version < 3 && !handshake.valid() {
        return Err(anyhow!("shadow-tls: missing default handshake information"));
    }
    for (server_name, handshake_config) in handshake_for_server_name {
        if server_name.is_empty() || !handshake_config.valid() {
            return Err(anyhow!("shadow-tls: invalid handshake for server name {server_name:?}"));
        }
    }
    Ok(ServerConfig {
        version,
        password: password.to_owned(),
        users: users.to_vec(),
        handshake,
        handshake_for_server_name: handshake_for_server_name.clone(),
        strict_mode,
        wildcard_sni,
    })
}

/// The server entry point. The config arrives as an `Option`, mapping to `Option<&ServerConfig>`.
pub async fn server(
    ctx: &CancellationToken,
    conn: Box<dyn NetConn>,
    config: Option<&ServerConfig>,
) -> Result<Box<dyn ServerConn>> {
    let Some(config) = config else {
        return Err(anyhow!("shadow-tls: nil connection or server config"));
    };
    let version = config.version;
    let (server_conn, user) = match version {
        1 => config.server_v1(ctx, conn).await?,
        2 => config.server_v2(ctx, conn).await?,
        3 => config.server_v3(ctx, conn).await?,
        _ => return Err(anyhow!("shadow-tls: unknown protocol version: {version}")),
    };
    if user.is_empty() {
        return Ok(server_conn);
    }
    Ok(Box::new(AuthenticatedConn::new(server_conn, user)))
}

fn flatten_join<T>(result: std::result::Result<Result<T>, tokio::task::JoinError>) -> Result<T> {
    match result {
        Ok(inner) => inner,
        Err(join_err) => Err(anyhow!("shadow-tls: relay handshake task panicked: {join_err}")),
    }
}

impl ServerConfig {
    async fn server_v1(
        &self,
        ctx: &CancellationToken,
        conn: Box<dyn NetConn>,
    ) -> Result<(Box<dyn ServerConn>, String)> {
        let handshake_conn =
            self.handshake.dial(ctx).await.map_err(|err| anyhow!("shadow-tls: dial handshake server: {err}"))?;
        let client_shared = SharedConn::from_boxed(conn);
        let server_shared = SharedConn::from_boxed(handshake_conn);
        let result = relay_handshake(client_shared.clone(), server_shared.clone()).await;
        let _ = server_shared.close();
        result.map_err(|err| anyhow!("shadow-tls: relay handshake: {err}"))?;
        debugln!("[ShadowTLS] handshake finished");
        Ok((Box::new(client_shared), String::new()))
    }

    async fn server_v2(
        &self,
        ctx: &CancellationToken,
        conn: Box<dyn NetConn>,
    ) -> Result<(Box<dyn ServerConn>, String)> {
        let shared_conn = SharedConn::from_boxed(conn);
        let mut reader = shared_conn.clone();
        let client_hello =
            read_frame(&mut reader).await.map_err(|err| anyhow!("shadow-tls: read client handshake: {err}"))?;
        let handshake_config = self.select_handshake(&client_hello);
        let handshake_conn =
            handshake_config.dial(ctx).await.map_err(|err| anyhow!("shadow-tls: dial handshake server: {err}"))?;
        let handshake_shared = SharedConn::from_boxed(handshake_conn);
        let hash_conn = HashWriteConn::new(Box::new(shared_conn.clone()), &self.password);

        let mut copy_src = handshake_shared.clone();
        let mut copy_dst = hash_conn.clone();
        let server_copy_task: tokio::task::JoinHandle<io::Result<u64>> =
            tokio::spawn(async move { tokio::io::copy(&mut copy_src, &mut copy_dst).await });

        let mut cached_client = new_cached_conn(shared_conn.clone(), client_hello);
        let mut handshake_writer = handshake_shared.clone();
        let result = copy_until_handshake_finished_v2(&mut handshake_writer, &mut cached_client, &hash_conn, 2).await;

        match result {
            Ok(request) => {
                debugln!("[ShadowTLS] handshake finished");
                let _ = handshake_shared.close();
                let _ = server_copy_task.await;
                let shadow_conn = ShadowConn::new(Box::new(shared_conn));
                let final_conn = new_cached_conn(shadow_conn, request);
                Ok((Box::new(final_conn), String::new()))
            }
            Err(super::v2::HandshakeCopyError::FallbackRequired) => {
                warnln!("[ShadowTLS] fallback connection");
                hash_conn.fallback();
                let mut client_copy_src = shared_conn.clone();
                let mut client_copy_dst = handshake_shared.clone();
                let mut client_copy_task: tokio::task::JoinHandle<io::Result<u64>> =
                    tokio::spawn(async move { tokio::io::copy(&mut client_copy_src, &mut client_copy_dst).await });
                let mut server_copy_task = server_copy_task;

                let copy_errors = tokio::select! {
                    res = &mut client_copy_task => {
                        let client_copy_err = copy_task_err(res);
                        finish_copy_direction(&handshake_shared, &shared_conn, client_copy_err.as_ref());
                        let server_copy_err = copy_task_err(server_copy_task.await);
                        [client_copy_err, server_copy_err]
                    }
                    res = &mut server_copy_task => {
                        let server_copy_err = copy_task_err(res);
                        finish_copy_direction(&shared_conn, &handshake_shared, server_copy_err.as_ref());
                        let client_copy_err = copy_task_err(client_copy_task.await);
                        [client_copy_err, server_copy_err]
                    }
                };
                let _ = handshake_shared.close();
                if let Some(relay_err) = join_copy_errors(&copy_errors) {
                    return Err(relay_err);
                }
                Err(FallbackCompleted.into())
            }
            Err(err) => {
                let _ = handshake_shared.close();
                let _ = server_copy_task.await;
                Err(err.into())
            }
        }
    }

    fn select_handshake(&self, client_hello: &[u8]) -> HandshakeConfig {
        if let Ok(server_name) = extract_server_name(client_hello) {
            if let Some(custom) = self.handshake_for_server_name.get(&server_name) {
                return custom.clone();
            }
        }
        self.handshake.clone()
    }

    async fn server_v3(
        &self,
        ctx: &CancellationToken,
        conn: Box<dyn NetConn>,
    ) -> Result<(Box<dyn ServerConn>, String)> {
        let shared_conn = SharedConn::from_boxed(conn);
        let mut reader = shared_conn.clone();
        let client_hello =
            read_frame(&mut reader).await.map_err(|err| anyhow!("shadow-tls: read client handshake: {err}"))?;
        let server_name =
            extract_server_name(&client_hello).map_err(|err| anyhow!("shadow-tls: extract server name: {err}"))?;
        let verify_result = verify_client_hello(&client_hello, &self.users);
        let handshake_config = self.select_v3_handshake(&server_name, verify_result.is_ok());
        let user = match verify_result {
            Ok(user) => user.clone(),
            Err(err) => {
                warnln!("[ShadowTLS] client hello verify failed: {err}");
                return Err(self.relay_fallback(ctx, Box::new(shared_conn), client_hello, &handshake_config).await);
            }
        };
        debugln!("[ShadowTLS] client hello verify success");

        let handshake_conn =
            handshake_config.dial(ctx).await.map_err(|err| anyhow!("shadow-tls: dial handshake server: {err}"))?;
        let handshake_shared = SharedConn::from_boxed(handshake_conn);
        let handshake_writer = handshake_shared.clone();
        handshake_writer
            .write_all(&client_hello)
            .await
            .map_err(|err| anyhow!("shadow-tls: write client handshake: {err}"))?;
        let mut handshake_reader = handshake_shared.clone();
        let server_hello = read_frame(&mut handshake_reader)
            .await
            .map_err(|err| anyhow!("shadow-tls: read server handshake: {err}"))?;
        let client_writer = shared_conn.clone();
        client_writer
            .write_all(&server_hello)
            .await
            .map_err(|err| anyhow!("shadow-tls: write server handshake: {err}"))?;
        let Some(server_random) = extract_server_random(&server_hello) else {
            warnln!("[ShadowTLS] server random extract failed, will copy bidirectional");
            let mut left = shared_conn.clone();
            let mut right = handshake_shared.clone();
            relay_context(ctx, &mut left, &mut right).await?;
            return Err(FallbackCompleted.into());
        };
        if self.strict_mode && !is_server_hello_support_tls13(&server_hello) {
            warnln!("[ShadowTLS] TLS 1.3 is not supported, will copy bidirectional");
            let mut left = shared_conn.clone();
            let mut right = handshake_shared.clone();
            relay_context(ctx, &mut left, &mut right).await?;
            return Err(FallbackCompleted.into());
        }
        if murmur_log::level() == murmur_log::LogLevel::DEBUG {
            debugln!("[ShadowTLS] client authenticated, server random extracted: {}", hex::encode(&server_random));
        }

        let mut hmac_write = super::v2::new_hmac_sha1(&user.password);
        hmac_write.update(&server_random);
        let mut hmac_add = super::v2::new_hmac_sha1(&user.password);
        hmac_add.update(&server_random);
        hmac_add.update(b"S");
        let hmac_verify = super::v2::new_hmac_sha1(&user.password);

        let (request, hmac_verify) = relay_v3_handshake(
            &shared_conn,
            &handshake_shared,
            &user.password,
            &server_random,
            hmac_write,
            hmac_verify,
        )
        .await
        .map_err(|err| anyhow!("shadow-tls: relay handshake: {err}"))?;
        debugln!("[ShadowTLS] handshake relay finished");
        let verified = new_verified_conn(Box::new(shared_conn), hmac_add, hmac_verify, None);
        let final_conn = new_cached_conn(verified, request);
        Ok((Box::new(final_conn), user.name.clone()))
    }

    async fn relay_fallback(
        &self,
        ctx: &CancellationToken,
        conn: Box<dyn Stream>,
        prefix: Vec<u8>,
        handshake_config: &HandshakeConfig,
    ) -> anyhow::Error {
        let handshake_conn = match handshake_config.dial(ctx).await {
            Ok(conn) => conn,
            Err(err) => return anyhow!("shadow-tls: dial fallback server: {err}"),
        };
        let mut cached = new_cached_conn(conn, prefix);
        let mut handshake_conn = handshake_conn;
        if let Err(err) = relay_context(ctx, &mut cached, handshake_conn.as_mut()).await {
            return err;
        }
        FallbackCompleted.into()
    }

    fn select_v3_handshake(&self, server_name: &str, authenticated: bool) -> HandshakeConfig {
        if let Some(custom) = self.handshake_for_server_name.get(server_name) {
            return custom.clone();
        }
        let mut handshake_config = self.handshake.clone();
        if self.wildcard_sni == WildcardSNI::All || (authenticated && self.wildcard_sni == WildcardSNI::Authed) {
            handshake_config.server = murmur_component::dialer::bind::join_host_port(server_name, 443);
        }
        handshake_config
    }
}

async fn relay_v3_handshake(
    client_conn: &SharedConn,
    handshake_conn: &SharedConn,
    password: &str,
    server_random: &[u8],
    hmac_write: super::v2::HmacSha1,
    hmac_verify: super::v2::HmacSha1,
) -> Result<(Vec<u8>, super::v2::HmacSha1)> {
    enum First {
        Client(io::Result<(Vec<u8>, super::v2::HmacSha1)>),
        Modifier(io::Result<()>),
    }

    let mut a_conn = client_conn.clone();
    let mut a_handshake = handshake_conn.clone();
    let server_random_a = server_random.to_vec();
    let mut task_a: tokio::task::JoinHandle<io::Result<(Vec<u8>, super::v2::HmacSha1)>> = tokio::spawn(async move {
        copy_by_frame_until_hmac_matches(&mut a_conn, &mut a_handshake, hmac_verify, &server_random_a).await
    });

    let mut b_conn = handshake_conn.clone();
    let mut b_handshake = client_conn.clone();
    let password_b = password.to_owned();
    let server_random_b = server_random.to_vec();
    let mut task_b: tokio::task::JoinHandle<io::Result<()>> = tokio::spawn(async move {
        copy_by_frame_with_modification(&mut b_conn, &mut b_handshake, &password_b, &server_random_b, hmac_write).await
    });

    let first = tokio::select! {
        res = &mut task_a => First::Client(flatten_join_io(res)),
        res = &mut task_b => First::Modifier(flatten_join_io(res)),
    };

    match first {
        First::Client(Ok((request, hmac_verify))) => {
            let _ = handshake_conn.close();
            let _ = task_b.await;
            Ok((request, hmac_verify))
        }
        First::Client(Err(err)) => {
            let _ = handshake_conn.close();
            let _ = client_conn.set_deadline(Some(tokio::time::Instant::now()));
            let _ = task_b.await;
            Err(anyhow!("{err}"))
        }
        First::Modifier(modifier_result) => {
            let _ = handshake_conn.close();
            let _ = client_conn.set_deadline(Some(tokio::time::Instant::now()));
            let client_result = flatten_join_io(task_a.await);
            match modifier_result {
                Err(err) => Err(anyhow!("{err}")),
                Ok(()) => match client_result {
                    Err(err) => Err(anyhow!("{err}")),
                    Ok(_) => Err(anyhow!("shadow-tls: relay handshake: unexpected completion order")),
                },
            }
        }
    }
}

fn flatten_join_io<T>(result: std::result::Result<io::Result<T>, tokio::task::JoinError>) -> io::Result<T> {
    match result {
        Ok(inner) => inner,
        Err(join_err) => Err(io::Error::other(join_err.to_string())),
    }
}

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
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for AuthenticatedConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
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

/// A bare connection parameter cannot be walked for a wrapped-conn chain here;
/// callers pass the richer `&dyn UpstreamNode` this crate's conns implement.
pub fn user_from_conn(conn: &dyn UpstreamNode) -> Option<String> {
    find_upstream::<AuthenticatedConn>(conn, None).map(|found| found.user.clone())
}

fn copy_task_err(result: std::result::Result<io::Result<u64>, tokio::task::JoinError>) -> Option<io::Error> {
    match result {
        Ok(Ok(_)) => None,
        Ok(Err(err)) => Some(err),
        Err(join_err) => Some(io::Error::other(join_err.to_string())),
    }
}

fn finish_copy_direction(dst: &SharedConn, src: &SharedConn, err: Option<&io::Error>) {
    if err.is_none() {
        close_write(dst);
        return;
    }
    let _ = dst.close();
    let _ = src.close();
}

/// Half-closes the connection. `Conn::close_write` always exists (it defaults to a no-op), so
/// there is no fallback to a full close when half-close is unsupported.
fn close_write(conn: &SharedConn) {
    let _ = conn.close_write();
}

fn join_copy_errors(copy_errors: &[Option<io::Error>]) -> Option<anyhow::Error> {
    let mut messages = Vec::new();
    for err in copy_errors.iter().flatten() {
        if matches!(
            err.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::TimedOut
                | io::ErrorKind::NotConnected
                | io::ErrorKind::BrokenPipe
        ) {
            continue;
        }
        let text = err.to_string();
        if text.contains("use of closed network connection") {
            continue;
        }
        messages.push(text);
    }
    if messages.is_empty() {
        None
    } else {
        Some(anyhow!(messages.join("\n")))
    }
}

async fn relay_handshake(client_conn: SharedConn, server_conn: SharedConn) -> Result<()> {
    enum Which {
        A,
        B,
    }
    let mut a_dst = server_conn.clone();
    let mut a_src = client_conn.clone();
    let mut task_a: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
        copy_until_handshake_finished(&mut a_dst, &mut a_src).await.map_err(anyhow::Error::from)
    });
    let mut b_dst = client_conn.clone();
    let mut b_src = server_conn.clone();
    let mut task_b: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
        copy_until_handshake_finished(&mut b_dst, &mut b_src).await.map_err(anyhow::Error::from)
    });

    let (first_err, which) = tokio::select! {
        res = &mut task_a => (flatten_join(res).err(), Which::A),
        res = &mut task_b => (flatten_join(res).err(), Which::B),
    };
    if let Some(first_err) = first_err {
        let _ = client_conn.set_deadline(Some(tokio::time::Instant::now()));
        let _ = server_conn.close();
        match which {
            Which::A => {
                let _ = task_b.await;
            }
            Which::B => {
                let _ = task_a.await;
            }
        }
        return Err(first_err);
    }
    match which {
        Which::A => flatten_join(task_b.await)?,
        Which::B => flatten_join(task_a.await)?,
    }
    Ok(())
}

#[cfg(test)]
use crate::client::DEFAULT_ALPN;
#[cfg(test)]
use murmur_common_net::io::Acceptor;
#[cfg(test)]
use murmur_component_ca::keypair::{new_random_tls_key_pair, new_tls_key_pair_loader, KeyPairType};
#[cfg(test)]
use murmur_component_tls::utls;
#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
use tokio::net::TcpListener;

/// Starts a local camouflage TLS server, capped at TLS 1.2 when asked.
#[cfg(test)]
pub async fn start_camouflage_server(tls12_only: bool) -> String {
    let (certificate_pem, private_key_pem, _fingerprint) =
        new_random_tls_key_pair(KeyPairType::KEY_PAIR_TYPE_P256).expect("generate camouflage key pair");
    let loader = new_tls_key_pair_loader(&certificate_pem, &private_key_pem).expect("build key pair loader");
    let certificate = loader().expect("load camouflage certificate");

    let mut config = utls::Config {
        certificates: vec![certificate],
        next_protos: DEFAULT_ALPN.clone(),
        min_version: utls::VERSION_TLS12,
        ..Default::default()
    };
    if tls12_only {
        config.max_version = utls::VERSION_TLS12;
    }

    let raw_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind camouflage listener");
    let addr = raw_listener.local_addr().expect("camouflage listener addr").to_string();
    let listener: Arc<dyn Acceptor> = Arc::new(raw_listener);
    let tls_listener = utls::new_listener(listener, Arc::new(config));

    tokio::spawn(async move {
        loop {
            let conn = match tls_listener.accept().await {
                Ok(conn) => conn,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let (mut reader, mut writer) = tokio::io::split(conn);
                let _ = tokio::time::timeout(Duration::from_secs(10), tokio::io::copy(&mut reader, &mut writer)).await;
            });
        }
    });
    addr
}

#[cfg(test)]
fn set_test_deadline(conn: &dyn NetConn) {
    conn.set_deadline(Some(tokio::time::Instant::now() + Duration::from_secs(10))).expect("set deadline");
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::anyhow;
    use byteorder::{BigEndian, ByteOrder};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, oneshot};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::client::{new_shadow_tls, ShadowTLSOption, WS_ALPN};
    use crate::protocol::{
        APPLICATION_DATA, CLIENT_HELLO, HANDSHAKE, HMAC_SIZE, SERVER_HELLO, SESSION_ID_LENGTH_INDEX, TLS_HEADER_SIZE,
        TLS_SESSION_ID_SIZE,
    };
    use crate::v2::new_hmac_sha1;
    use crate::v3::hmac_sum4;
    use murmur_common_net::new_cached_conn_from_node;
    use murmur_component_tls::utls;

    const TEST_SERVER_NAME: &str = "shadowtls.example";
    const TEST_PASSWORD: &str = "shadowtls-test-password";

    struct RoundTripCase {
        name: &'static str,
        version: i32,
        fingerprint: &'static str,
        alpn: Vec<String>,
    }

    async fn run_round_trip_case(case: &RoundTripCase) {
        let camouflage_addr = start_camouflage_server(case.version == 1).await;
        let server_config = Arc::new(new_test_server_config(case.version, &camouflage_addr, &[], false));
        let (frontend_addr, result_rx) = start_server(server_config).await;

        let raw_client =
            TcpStream::connect(&frontend_addr).await.unwrap_or_else(|err| panic!("{}: dial: {err}", case.name));
        set_test_deadline(&raw_client);
        let option = ShadowTLSOption {
            password: TEST_PASSWORD.to_owned(),
            host: TEST_SERVER_NAME.to_owned(),
            client_fingerprint: case.fingerprint.to_owned(),
            skip_cert_verify: true,
            version: case.version,
            alpn: case.alpn.clone(),
            ..Default::default()
        };
        let ctx = CancellationToken::new();
        let mut client = new_shadow_tls(&ctx, Box::new(raw_client), Some(&option))
            .await
            .unwrap_or_else(|err| panic!("{}: client handshake: {err}", case.name));

        let client_payload = "client-payload-".repeat(3000).into_bytes();
        client.write_all(&client_payload).await.unwrap_or_else(|err| panic!("{}: client write: {err}", case.name));

        let server_result = receive_server_result(result_rx).await;
        if let Some(err) = server_result.err {
            panic!("{}: server handshake: {err}", case.name);
        }
        let mut server_conn =
            server_result.conn.unwrap_or_else(|| panic!("{}: server handshake produced no conn", case.name));
        set_test_deadline(server_conn.as_ref());
        assert!(server_result.user.is_none(), "{}: unexpected authenticated user", case.name);

        let mut got_client_payload = vec![0u8; client_payload.len()];
        server_conn
            .read_exact(&mut got_client_payload)
            .await
            .unwrap_or_else(|err| panic!("{}: server read: {err}", case.name));
        assert_eq!(got_client_payload, client_payload, "{}: corrupted client payload", case.name);

        let server_payload = "server-payload-".repeat(3000).into_bytes();
        server_conn.write_all(&server_payload).await.unwrap_or_else(|err| panic!("{}: server write: {err}", case.name));
        let mut got_server_payload = vec![0u8; server_payload.len()];
        client
            .read_exact(&mut got_server_payload)
            .await
            .unwrap_or_else(|err| panic!("{}: client read: {err}", case.name));
        assert_eq!(got_server_payload, server_payload, "{}: corrupted server payload", case.name);
    }

    /// Round-trips a client and server across the v1 and v2 cases.
    #[tokio::test]
    async fn server_round_trip() {
        let cases = vec![
            RoundTripCase { name: "v1", version: 1, fingerprint: "", alpn: Vec::new() },
            RoundTripCase { name: "v2", version: 2, fingerprint: "", alpn: Vec::new() },
            RoundTripCase { name: "v2-utls-websocket", version: 2, fingerprint: "chrome", alpn: WS_ALPN.clone() },
        ];
        for case in &cases {
            run_round_trip_case(case).await;
        }
    }

    #[tokio::test]
    async fn user_from_conn_through_wrappers() {
        let (left, _right) = murmur_common_net::pipe();
        let authenticated = AuthenticatedConn::new(Box::new(left), "test-user".to_owned());
        // S11: remove in U5, once AuthenticatedConn implements Stream.
        let cached = new_cached_conn_from_node(OldConnAsStream(authenticated), Vec::new());
        let conn = murmur_common_net::new_buffered_conn(Box::new(cached));

        let user = user_from_conn(&conn);
        assert_eq!(user.as_deref(), Some("test-user"));
    }

    #[tokio::test]
    async fn v2_interrupted_header_read() {
        let (client_side, server_side) = murmur_common_net::pipe();
        let (server_raw, mut started_rx) = ReadStartedConn::new(Box::new(server_side));
        let server_shared = SharedConn::from_boxed(Box::new(server_raw));
        let deadline_handle = server_shared.clone();
        let mut server = ShadowConn::new(Box::new(server_shared));

        let payload = b"payload after interrupted v2 header".to_vec();
        let mut frame = vec![0u8; TLS_HEADER_SIZE + payload.len()];
        frame[0] = APPLICATION_DATA;
        frame[1] = 3;
        frame[2] = 3;
        BigEndian::write_u16(&mut frame[3..TLS_HEADER_SIZE], payload.len() as u16);
        frame[TLS_HEADER_SIZE..].copy_from_slice(&payload);

        let buffer = vec![0u8; payload.len()];
        let (result_tx, result_rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut buffer = buffer;
            let read_result = server.read(&mut buffer).await;
            let _ = result_tx.send((server, buffer, read_result));
        });

        started_rx.recv().await.expect("read started signal");
        let mut client_side = client_side;
        client_side.write_all(&frame[..2]).await.expect("write partial header");
        started_rx.recv().await.expect("second read started signal");

        deadline_handle.set_read_deadline(Some(tokio::time::Instant::now())).expect("interrupt server read");
        let (mut server, mut buffer, read_result) = result_rx.await.expect("read task result");
        let err = read_result.expect_err("interrupted read must fail");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "server read error = {err:?}, want deadline exceeded");
        deadline_handle.set_read_deadline(None).expect("clear server read deadline");

        let (client_write_tx, client_write_rx) = oneshot::channel();
        tokio::spawn(async move {
            let write_result = client_side.write_all(&frame[2..]).await;
            let _ = client_write_tx.send(write_result);
        });
        server.read_exact(&mut buffer).await.expect("server read completed frame");
        assert_eq!(buffer, payload, "server payload mismatch");
        client_write_rx.await.expect("client write task result").expect("client write remaining frame");
    }

    struct ReadStartedConn {
        conn: Box<dyn NetConn>,
        started: mpsc::Sender<()>,
    }

    impl ReadStartedConn {
        fn new(conn: Box<dyn NetConn>) -> (Self, mpsc::Receiver<()>) {
            let (started, rx) = mpsc::channel(1);
            (Self { conn, started }, rx)
        }
    }

    impl AsyncRead for ReadStartedConn {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            let this = self.get_mut();
            let _ = this.started.try_send(());
            Pin::new(this.conn.as_mut()).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ReadStartedConn {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            Pin::new(self.get_mut().conn.as_mut()).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
            Pin::new(self.get_mut().conn.as_mut()).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
            Pin::new(self.get_mut().conn.as_mut()).poll_shutdown(cx)
        }
    }

    impl NetConn for ReadStartedConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            self.conn.local_addr()
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            self.conn.remote_addr()
        }

        fn close(&self) -> io::Result<()> {
            self.conn.close()
        }

        fn close_read(&self) -> io::Result<()> {
            self.conn.close_read()
        }

        fn close_write(&self) -> io::Result<()> {
            self.conn.close_write()
        }

        fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.conn.set_deadline(deadline)
        }

        fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.conn.set_read_deadline(deadline)
        }

        fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.conn.set_write_deadline(deadline)
        }
    }

    #[tokio::test]
    async fn handshake_selection_by_server_name() {
        let frame = capture_client_hello("mapped.example").await;
        let server_name = extract_server_name(&frame).expect("extract server name");
        assert_eq!(server_name, "mapped.example");

        let dial: DialContextFn =
            Arc::new(|_ctx, _network, _address| Box::pin(async { Err(anyhow!("dial not exercised by this test")) }));
        let mut handshake_for_server_name = HashMap::new();
        handshake_for_server_name.insert(
            "mapped.example".to_owned(),
            HandshakeConfig { server: "mapped.example:8443".to_owned(), dial_context: Some(Arc::clone(&dial)) },
        );
        let server_config = new_server_config(
            2,
            "",
            &[],
            HandshakeConfig { server: "default.example:443".to_owned(), dial_context: Some(dial) },
            &handshake_for_server_name,
            false,
            WildcardSNI::Off,
        )
        .expect("build server config");
        let selected = server_config.select_handshake(&frame);
        assert_eq!(selected.server, "mapped.example:8443");
    }

    #[test]
    fn v3_wildcard_sni_selection() {
        let default_handshake = HandshakeConfig { server: "default.example:443".to_owned(), dial_context: None };
        let custom_handshake = HandshakeConfig { server: "custom-upstream.example:443".to_owned(), dial_context: None };
        let cases: [(&str, WildcardSNI, &str, bool, &str); 5] = [
            ("off-authenticated", WildcardSNI::Off, "other.example", true, "default.example:443"),
            ("authed-authenticated", WildcardSNI::Authed, "other.example", true, "other.example:443"),
            ("authed-fallback", WildcardSNI::Authed, "other.example", false, "default.example:443"),
            ("all-fallback", WildcardSNI::All, "other.example", false, "other.example:443"),
            ("custom-fallback", WildcardSNI::Off, "custom.example", false, "custom-upstream.example:443"),
        ];
        for (case_name, mode, server_name, authenticated, want) in cases {
            let mut handshake_for_server_name = HashMap::new();
            handshake_for_server_name.insert("custom.example".to_owned(), custom_handshake.clone());
            let server_config = ServerConfig {
                version: 3,
                password: String::new(),
                users: Vec::new(),
                handshake: default_handshake.clone(),
                handshake_for_server_name,
                strict_mode: false,
                wildcard_sni: mode,
            };
            let got = server_config.select_v3_handshake(server_name, authenticated).server;
            assert_eq!(got, want, "{case_name}: selected server");
        }
    }

    /// The relaxed validation in the server-config constructor: an empty default handshake is accepted once
    /// `wildcardSNI != Off`, since the wildcard rewrite always produces a real target.
    #[test]
    fn new_server_config_accepts_empty_handshake_when_wildcard_sni_not_off() {
        let users = [User { name: "test".to_owned(), password: "secret".to_owned() }];
        let empty_handshake = HandshakeConfig { server: String::new(), dial_context: None };
        assert!(
            new_server_config(3, "", &users, empty_handshake.clone(), &HashMap::new(), false, WildcardSNI::All).is_ok(),
            "wildcard-sni: all must accept an empty default handshake"
        );
        assert!(
            new_server_config(3, "", &users, empty_handshake, &HashMap::new(), false, WildcardSNI::Off).is_err(),
            "wildcard-sni: off must still reject an empty default handshake"
        );
    }

    struct ServerTestResult {
        conn: Option<Box<dyn ServerConn>>,
        user: Option<String>,
        err: Option<anyhow::Error>,
    }

    fn new_test_server_config(version: i32, camouflage_addr: &str, users: &[User], strict_mode: bool) -> ServerConfig {
        let dial_context: DialContextFn = Arc::new(|_ctx: CancellationToken, network: String, address: String| {
            Box::pin(async move {
                if network != "tcp" {
                    return Err(anyhow!("shadow-tls test dialer: unsupported network {network}"));
                }
                let stream = TcpStream::connect(&address).await?;
                let conn: Box<dyn NetConn> = Box::new(stream);
                Ok(conn)
            })
        });
        new_server_config(
            version,
            TEST_PASSWORD,
            users,
            HandshakeConfig { server: camouflage_addr.to_owned(), dial_context: Some(dial_context) },
            &HashMap::new(),
            strict_mode,
            WildcardSNI::Off,
        )
        .expect("build test server config")
    }

    async fn start_server(server_config: Arc<ServerConfig>) -> (String, oneshot::Receiver<ServerTestResult>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr").to_string();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(err) => {
                    let _ = tx.send(ServerTestResult { conn: None, user: None, err: Some(err.into()) });
                    return;
                }
            };
            set_test_deadline(&stream);
            let ctx = CancellationToken::new();
            match server(&ctx, Box::new(stream), Some(&server_config)).await {
                Ok(conn) => {
                    let user = user_from_conn(conn.as_ref());
                    let _ = tx.send(ServerTestResult { conn: Some(conn), user, err: None });
                }
                Err(err) => {
                    let _ = tx.send(ServerTestResult { conn: None, user: None, err: Some(err) });
                }
            }
        });
        (addr, rx)
    }

    async fn capture_client_hello(server_name: &str) -> Vec<u8> {
        let (client_side, mut server_side) = murmur_common_net::pipe();
        let server_name = server_name.to_owned();
        let done = tokio::spawn(async move {
            let config = Arc::new(utls::Config { server_name, insecure_skip_verify: true, ..Default::default() });
            let client = utls::client(Box::new(OldConnAsStream(client_side)), config);
            let _ = client.handshake_context(&CancellationToken::new()).await;
        });
        let frame = read_frame(&mut server_side).await.expect("read captured ClientHello frame");
        let _ = server_side.close();
        let _ = done.await;
        frame
    }

    async fn receive_server_result(rx: oneshot::Receiver<ServerTestResult>) -> ServerTestResult {
        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => panic!("server task dropped without a result"),
            Err(_) => panic!("timed out waiting for ShadowTLS server"),
        }
    }

    #[tokio::test]
    async fn v3_unauthenticated_connection_falls_back() {
        let camouflage_addr = start_camouflage_server(false).await;
        let users = vec![User { name: "test-user".to_owned(), password: TEST_PASSWORD.to_owned() }];
        let server_config = Arc::new(new_test_server_config(3, &camouflage_addr, &users, false));
        let (frontend_addr, result_rx) = start_server(server_config).await;

        let raw_client = TcpStream::connect(&frontend_addr).await.expect("dial frontend");
        set_test_deadline(&raw_client);
        let config = Arc::new(utls::Config {
            server_name: TEST_SERVER_NAME.to_owned(),
            insecure_skip_verify: true,
            min_version: utls::VERSION_TLS12,
            ..Default::default()
        });
        let mut client = utls::client(Box::new(raw_client), config);
        client.handshake_context(&CancellationToken::new()).await.expect("fallback TLS handshake");

        let payload = b"ordinary TLS connection";
        client.write_all(payload).await.expect("fallback write");
        let mut response = vec![0u8; payload.len()];
        client.read_exact(&mut response).await.expect("fallback read");
        assert_eq!(response, payload, "fallback response mismatch");
        drop(client);

        let server_result = receive_server_result(result_rx).await;
        let err = server_result.err.expect("server must report an error for the fallback path");
        assert!(err.downcast_ref::<FallbackCompleted>().is_some(), "server error = {err}, want FallbackCompleted");
    }

    /// Builds a syntactically valid v3 ClientHello frame with a real SNI extension (so
    /// `extract_server_name` succeeds) whose embedded HMAC verifies against `password`, matching
    /// what a real v3 client produces.
    fn build_v3_client_hello(password: &str, sni: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xAAu8; 32]);
        body.push(TLS_SESSION_ID_SIZE as u8);
        body.extend_from_slice(&[0u8; TLS_SESSION_ID_SIZE]);
        body.extend_from_slice(&[0x00, 0x02]);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);

        let sni_bytes = sni.as_bytes();
        let mut sni_ext_body = Vec::new();
        sni_ext_body.extend_from_slice(&((3 + sni_bytes.len()) as u16).to_be_bytes());
        sni_ext_body.push(0x00);
        sni_ext_body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext_body.extend_from_slice(sni_bytes);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&(sni_ext_body.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext_body);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(CLIENT_HELLO);
        let body_len = body.len() as u32;
        handshake.extend_from_slice(&[(body_len >> 16) as u8, (body_len >> 8) as u8, body_len as u8]);
        handshake.extend_from_slice(&body);

        let mut frame = Vec::new();
        frame.push(HANDSHAKE);
        frame.extend_from_slice(&[0x03, 0x01]);
        frame.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        frame.extend_from_slice(&handshake);

        let hmac_index = SESSION_ID_LENGTH_INDEX + 1 + TLS_SESSION_ID_SIZE - HMAC_SIZE;
        let mut h = new_hmac_sha1(password);
        h.update(&frame[TLS_HEADER_SIZE..hmac_index]);
        h.update(&[0, 0, 0, 0]);
        h.update(&frame[hmac_index + HMAC_SIZE..]);
        let sum = hmac_sum4(&h);
        frame[hmac_index..hmac_index + HMAC_SIZE].copy_from_slice(&sum);
        frame
    }

    /// Builds a canned v3 ServerHello frame with no `supported_versions` extension, standing in
    /// for a camouflage backend that only negotiates TLS 1.2.
    fn build_tls12_server_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xBBu8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x00]);

        let mut handshake = Vec::new();
        handshake.push(SERVER_HELLO);
        let body_len = body.len() as u32;
        handshake.extend_from_slice(&[(body_len >> 16) as u8, (body_len >> 8) as u8, body_len as u8]);
        handshake.extend_from_slice(&body);

        let mut frame = Vec::new();
        frame.push(HANDSHAKE);
        frame.extend_from_slice(&[0x03, 0x03]);
        frame.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        frame.extend_from_slice(&handshake);
        frame
    }

    /// Fake camouflage backend that answers any connection with a TLS-1.2-only ServerHello,
    /// then relays whatever bytes follow until the peer closes.
    async fn start_fake_tls12_camouflage_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake camouflage listener");
        let addr = listener.local_addr().expect("listener addr").to_string();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            if stream.write_all(&build_tls12_server_hello()).await.is_err() {
                return;
            }
            let mut sink = [0u8; 1024];
            loop {
                match stream.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        addr
    }

    /// Proves the P1 strict-mode behaviour: an authenticated v3 client whose camouflage backend
    /// only negotiates TLS 1.2 must be relayed to fallback exactly like the unauthenticated case
    /// above (`FallbackCompleted`).
    #[tokio::test]
    async fn v3_strict_mode_rejects_tls12_camouflage() {
        let camouflage_addr = start_fake_tls12_camouflage_server().await;
        let users = vec![User { name: "test-user".to_owned(), password: TEST_PASSWORD.to_owned() }];
        let server_config = Arc::new(new_test_server_config(3, &camouflage_addr, &users, true));
        let (frontend_addr, result_rx) = start_server(server_config).await;

        let mut client = TcpStream::connect(&frontend_addr).await.expect("dial frontend");
        set_test_deadline(&client);
        let client_hello = build_v3_client_hello(TEST_PASSWORD, TEST_SERVER_NAME);
        client.write_all(&client_hello).await.expect("write client hello");

        let mut header = [0u8; TLS_HEADER_SIZE];
        client.read_exact(&mut header).await.expect("read server hello header");
        let len = usize::from(BigEndian::read_u16(&header[3..]));
        let mut rest = vec![0u8; len];
        client.read_exact(&mut rest).await.expect("read server hello body");
        drop(client);

        let server_result = receive_server_result(result_rx).await;
        let err = server_result.err.expect("strict-mode TLS 1.2 camouflage must fall back");
        assert!(err.downcast_ref::<FallbackCompleted>().is_some(), "server error = {err}, want FallbackCompleted");
    }
}

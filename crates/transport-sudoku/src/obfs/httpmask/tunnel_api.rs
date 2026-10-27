use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use murmur_common_net::io::Stream;
use murmur_component::dialer::options::NetDialer;

use super::early_handshake::{ClientEarlyHandshake, WrapConnFn};
use super::masker::{random_choice, ACCEPTS, ACCEPT_LANGUAGES, USER_AGENTS};
use super::tunnel_conn_poll::{dial_poll, dial_poll_with_client};
use super::tunnel_conn_stream::{dial_stream, dial_stream_with_client};
use super::tunnel_dial::{new_http_client, HttpClientTarget, TunnelHttpClient};
use super::tunnel_preconnect::with_timeout;
use super::tunnel_retry::close_idle_connections;
use super::tunnel_ws::dial_ws;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TunnelMode {
    Legacy,
    Stream,
    Poll,
    Auto,
    Ws,
}

impl TunnelMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Stream => "stream",
            Self::Poll => "poll",
            Self::Auto => "auto",
            Self::Ws => "ws",
        }
    }
}

pub(crate) fn normalize_tunnel_mode(mode: &str) -> TunnelMode {
    match mode.trim().to_lowercase().as_str() {
        "stream" => TunnelMode::Stream,
        "poll" => TunnelMode::Poll,
        "auto" => TunnelMode::Auto,
        "ws" => TunnelMode::Ws,
        _ => TunnelMode::Legacy,
    }
}

impl TunnelMode {
    /// Normalizes the tunnel mode as an associated function.
    pub(crate) fn normalize(mode: &str) -> Self {
        normalize_tunnel_mode(mode)
    }

    /// The normalized tunnel mode, compared against the known
    /// constants: unlike [`normalize_tunnel_mode`], an empty or unrecognized value has no
    /// "legacy" fallback.
    pub(crate) fn from_header(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "legacy" => Some(Self::Legacy),
            "stream" => Some(Self::Stream),
            "poll" => Some(Self::Poll),
            "auto" => Some(Self::Auto),
            "ws" => Some(Self::Ws),
            _ => None,
        }
    }
}

/// `HandleResult`. `StartTunnel` carries the user hash when the conn already completed a
/// full application-level handshake (httpmask early handshake); `server_handshake` uses it to
/// short-circuit, the same early-handshake user-hash check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HandleResult {
    PassThrough,
    StartTunnel(Option<String>),
    Done,
}

#[derive(Clone, Default)]
pub struct TunnelDialOptions {
    pub mode: String,
    pub tls_enabled: bool,
    pub host_override: String,
    pub path_root: String,
    /// `auth_key` is used only for WebSocket anti-probing authentication. Stream and poll use
    /// the authenticated Sudoku session token and upload sequence.
    pub auth_key: String,
    pub early_handshake: Option<ClientEarlyHandshake>,
    pub upgrade: Option<WrapConnFn>,
    /// `dial_context` is required so embedders can preserve their routing and proxy behavior.
    pub dial_context: Option<Arc<dyn NetDialer>>,
}

impl core::fmt::Debug for TunnelDialOptions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TunnelDialOptions")
            .field("mode", &self.mode)
            .field("tls_enabled", &self.tls_enabled)
            .field("host_override", &self.host_override)
            .field("path_root", &self.path_root)
            .field("auth_key", &"[redacted]")
            .field("has_early_handshake", &self.early_handshake.is_some())
            .field("has_upgrade", &self.upgrade.is_some())
            .field("has_dial_context", &self.dial_context.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct TunnelClientOptions {
    pub tls_enabled: bool,
    pub host_override: String,
    pub dial_context: Option<Arc<dyn NetDialer>>,
    pub max_idle_conns: i32,
}

impl core::fmt::Debug for TunnelClientOptions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TunnelClientOptions")
            .field("tls_enabled", &self.tls_enabled)
            .field("host_override", &self.host_override)
            .field("max_idle_conns", &self.max_idle_conns)
            .finish_non_exhaustive()
    }
}

pub struct TunnelClient {
    client: TunnelHttpClient,
    target: HttpClientTarget,
}

impl core::fmt::Debug for TunnelClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TunnelClient").finish_non_exhaustive()
    }
}

pub async fn new_tunnel_client(server_address: &str, opts: TunnelClientOptions) -> anyhow::Result<TunnelClient> {
    let max_idle = if opts.max_idle_conns <= 0 { 32 } else { opts.max_idle_conns };
    let (client, target) =
        new_http_client(server_address, opts.tls_enabled, &opts.host_override, opts.dial_context, max_idle).await?;
    Ok(TunnelClient { client, target })
}

impl TunnelClient {
    pub async fn close_idle_connections(&self) {
        close_idle_connections(&self.client.transport).await;
        self.client.transport.clear_idle();
    }

    pub async fn dial_tunnel(
        &self,
        ctx: &CancellationToken,
        opts: TunnelDialOptions,
    ) -> anyhow::Result<Box<dyn Stream>> {
        let mode = normalize_tunnel_mode(&opts.mode);
        if mode == TunnelMode::Legacy {
            return Err(anyhow::anyhow!("legacy mode does not use http tunnel"));
        }

        let transport = Arc::clone(&self.client.transport);
        match mode {
            TunnelMode::Stream => {
                dial_stream_with_client(ctx, Arc::clone(&transport), self.target.clone(), &opts).await
            }
            TunnelMode::Poll => dial_poll_with_client(ctx, Arc::clone(&transport), self.target.clone(), opts).await,
            TunnelMode::Auto => {
                let stream_ctx = auto_probe_context(ctx);
                let stream_result =
                    dial_stream_with_client(&stream_ctx, Arc::clone(&transport), self.target.clone(), &opts).await;
                match stream_result {
                    Ok(conn) => Ok(conn),
                    Err(stream_err) => {
                        match dial_poll_with_client(ctx, Arc::clone(&transport), self.target.clone(), opts).await {
                            Ok(conn) => Ok(conn),
                            Err(poll_err) => {
                                Err(anyhow::anyhow!("auto tunnel failed: stream: {stream_err}; poll: {poll_err}"))
                            }
                        }
                    }
                }
            }
            TunnelMode::Ws => Err(anyhow::anyhow!("ws mode does not support TunnelClient reuse")),
            TunnelMode::Legacy => Err(anyhow::anyhow!("legacy mode does not use http tunnel")),
        }
    }
}

/// `DialTunnel`: establishes a bidirectional raw Sudoku stream over `HTTPMask`.
pub(crate) async fn dial_tunnel(
    ctx: &CancellationToken,
    server_address: &str,
    opts: TunnelDialOptions,
) -> anyhow::Result<Box<dyn Stream>> {
    let mode = normalize_tunnel_mode(&opts.mode);
    if mode == TunnelMode::Legacy {
        return Err(anyhow::anyhow!("legacy mode does not use http tunnel"));
    }

    match mode {
        TunnelMode::Stream => dial_stream(ctx, server_address, &opts).await,
        TunnelMode::Poll => dial_poll(ctx, server_address, opts).await,
        TunnelMode::Ws => dial_ws(ctx, server_address, opts).await,
        TunnelMode::Auto => {
            let stream_ctx = auto_probe_context(ctx);
            let stream_result = dial_stream(&stream_ctx, server_address, &opts).await;
            match stream_result {
                Ok(conn) => Ok(conn),
                Err(stream_err) => match dial_poll(ctx, server_address, opts).await {
                    Ok(conn) => Ok(conn),
                    Err(poll_err) => Err(anyhow::anyhow!("auto tunnel failed: stream: {stream_err}; poll: {poll_err}")),
                },
            }
        }
        TunnelMode::Legacy => Err(anyhow::anyhow!("legacy mode does not use http tunnel")),
    }
}

pub(crate) const AUTO_PROBE_TIMEOUT: Duration = Duration::from_secs(20);

///
/// Deviation: `CancellationToken` carries no deadline to introspect the way a plain context
/// does, so `ctx`'s own deadline (if any) cannot be detected here; the timeout is always applied
/// as a child token, which is a strict subset of the behaviour (an extra, harmless timer when
/// the caller already had a shorter deadline).
pub(crate) fn auto_probe_context(ctx: &CancellationToken) -> CancellationToken {
    with_timeout(ctx, AUTO_PROBE_TIMEOUT)
}

pub(crate) fn apply_tunnel_headers(h: &mut http::HeaderMap, host: &str, mode: TunnelMode) {
    let mut r = rand::rng();
    let ua = random_choice(USER_AGENTS, &mut r);
    let accept = random_choice(ACCEPTS, &mut r);
    let lang = random_choice(ACCEPT_LANGUAGES, &mut r);

    set_header(h, http::header::USER_AGENT, ua);
    set_header(h, http::header::ACCEPT, accept);
    set_header(h, http::header::ACCEPT_LANGUAGE, lang);
    set_header(h, http::header::CACHE_CONTROL, "no-cache");
    set_header(h, http::header::PRAGMA, "no-cache");
    set_header(h, http::header::CONNECTION, "keep-alive");
    set_header(h, http::header::HOST, host);
    if let Ok(name) = http::header::HeaderName::from_bytes(b"x-sudoku-tunnel") {
        set_header(h, name, mode.as_str());
    }
}

fn set_header(h: &mut http::HeaderMap, name: http::header::HeaderName, value: &str) {
    if let Ok(value) = http::HeaderValue::from_str(value) {
        h.insert(name, value);
    }
}

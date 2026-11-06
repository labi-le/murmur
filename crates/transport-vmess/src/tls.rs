use std::any::Any;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{OldConnAsStream, Stream, StreamAsOldConn};
use murmur_component_ca as ca;
use murmur_component_ech as ech;
use murmur_component_tls::utls as tls_c;
use murmur_component_tls::utls::{ErasedTlsConn, TlsConn, TlsSessionCapability, VERSION_TLS13};
use murmur_reality::RealityConnAddrs;
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport_jls as jls;
use murmur_transport_shadowtls as shadowtls;
use murmur_transport_tlsmirror as tlsmirror;

/// The authenticated REALITY session as a [`TlsConn`]: the handshake completed, so it reports a
/// TLS 1.3 capability and can hand its buffered incoming plaintext to XTLS direct mode.
pub struct RealityTlsConn {
    inner: RealityConnAddrs<Box<dyn Stream>>,
}

impl RealityTlsConn {
    fn new(inner: RealityConnAddrs<Box<dyn Stream>>) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for RealityTlsConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityTlsConn").finish_non_exhaustive()
    }
}

impl AsyncRead for RealityTlsConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RealityTlsConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for RealityTlsConn {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    fn shutdown_read(&self) -> std::io::Result<()> {
        self.inner.shutdown_read()
    }

    fn shutdown_write(&self) -> std::io::Result<()> {
        self.inner.shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.inner.as_socket()
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        self.inner.old_conn()
    }
}

impl TlsConn for RealityTlsConn {
    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn tls_session_capability(&self) -> Option<TlsSessionCapability> {
        Some(TlsSessionCapability {
            handshake_complete: true,
            version: VERSION_TLS13,
            cipher_suite: self.inner.cipher_suite(),
        })
    }

    fn take_buffered_incoming(&mut self) -> Option<Vec<u8>> {
        Some(self.inner.take_buffered_incoming())
    }

    fn supports_raw_transport_handoff(&self) -> bool {
        true
    }
}

#[derive(Clone, Default)]
pub struct TlsConfig {
    pub host: String,
    pub skip_cert_verify: bool,
    pub name_cert_verify: String,
    pub finger_print: String,
    pub certificate: String,
    pub private_key: String,
    pub client_fingerprint: String,
    pub next_protos: Vec<String>,
    pub ech: Option<Arc<ech::Config>>,
    pub shadow_tls: Option<shadowtls::client::Config>,
    /// The Restls config. Restls replaces TLS entirely: the stream becomes the Restls
    /// channel and no other security mode applies.
    pub restls: Option<Arc<murmur_restls::Config>>,
    /// The JLS config. JLS wraps the dialled stream in its own authenticated TLS 1.3
    /// camouflage handshake, so the proxy protocol is only spoken once that succeeds.
    pub jls: Option<murmur_transport_jls::Config>,
    pub tls_mirror: Option<tlsmirror::config::Config>,
    pub tls_mirror_dialer: Option<tlsmirror::config::EnrollmentDialer>,
    /// The parsed Reality config lives here rather than on each protocol's own option struct,
    /// since every one of them reaches TLS through this type.
    pub reality: Option<Arc<murmur_reality::RealityClientConfig>>,
}

// Hand-written rather than derived: `certificate` and `private_key` hold PEM material.
impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConfig")
            .field("host", &self.host)
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("name_cert_verify", &self.name_cert_verify)
            .field("finger_print", &self.finger_print)
            .field("certificate", &"<redacted>")
            .field("private_key", &"<redacted>")
            .field("client_fingerprint", &self.client_fingerprint)
            .field("next_protos", &self.next_protos)
            .finish_non_exhaustive()
    }
}

/// Client-side [`tls_c::Config`] with every field spelled out, so a field added to the
/// mirrored TLS config cannot silently take its default on the dial path.
pub(crate) fn client_tls_config(
    server_name: String,
    insecure_skip_verify: bool,
    next_protos: Vec<String>,
) -> tls_c::Config {
    let tls_c::Config {
        rand,
        time,
        certificates,
        get_certificate,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        client_auth,
        client_cas,
        cipher_suites,
        session_tickets_disabled,
        min_version,
        max_version,
        curve_preferences,
        renegotiation,
        key_log_writer,
        encrypted_client_hello_config_list,
        encrypted_client_hello_rejection_verify,
        encrypted_client_hello_keys,
        get_encrypted_client_hello_keys,
        session_id_generator,
        ..
    } = tls_c::Config::default();
    tls_c::Config {
        rand,
        time,
        certificates,
        get_certificate,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        next_protos,
        server_name,
        client_auth,
        client_cas,
        insecure_skip_verify,
        cipher_suites,
        session_tickets_disabled,
        min_version,
        max_version,
        curve_preferences,
        renegotiation,
        key_log_writer,
        encrypted_client_hello_config_list,
        encrypted_client_hello_rejection_verify,
        encrypted_client_hello_keys,
        get_encrypted_client_hello_keys,
        session_id_generator,
    }
}

impl TlsConfig {
    pub fn to_std_config(&self) -> Result<tls_c::Config> {
        ca::config::get_tls_config(ca::config::Option {
            tls_config: Some(client_tls_config(self.host.clone(), self.skip_cert_verify, self.next_protos.clone())),
            fingerprint: self.finger_print.clone(),
            name_cert_verify: self.name_cert_verify.clone(),
            zero_trust: false,
            certificate: self.certificate.clone(),
            private_key: self.private_key.clone(),
        })
    }
}

/// Adapts `component::ech::Config` (which takes a `CancellationToken`) to
/// `tlsmirror::config::EchConfig` (which takes tlsmirror's own `DialCtx`).
struct TlsMirrorEch(Arc<ech::Config>);

#[async_trait::async_trait]
impl tlsmirror::config::EchConfig for TlsMirrorEch {
    async fn client_handle(&self, ctx: &tlsmirror::enrollment::DialCtx, config: &mut tls_c::Config) -> Result<()> {
        self.0.client_handle(ctx.token().clone(), config).await
    }

    async fn client_handle_utls(&self, ctx: &tlsmirror::enrollment::DialCtx, config: &mut tls_c::Config) -> Result<()> {
        self.0.client_handle_utls(ctx.token().clone(), config).await
    }
}

/// Runs the ECH client handle (or its uTLS variant), a no-op when `cfg` is unset.
async fn ech_client_handle(
    ech: Option<&Arc<ech::Config>>,
    ctx: &CancellationToken,
    tls_config: &mut tls_c::Config,
) -> Result<()> {
    match ech {
        Some(ech) => ech.client_handle(ctx.clone(), tls_config).await,
        None => Ok(()),
    }
}

async fn ech_client_handle_utls(
    ech: Option<&Arc<ech::Config>>,
    ctx: &CancellationToken,
    tls_config: &mut tls_c::Config,
) -> Result<()> {
    match ech {
        Some(ech) => ech.client_handle_utls(ctx.clone(), tls_config).await,
        None => Ok(()),
    }
}

pub async fn stream_tls_conn(
    ctx: &CancellationToken,
    conn: Box<dyn Stream>,
    cfg: &TlsConfig,
) -> Result<Box<dyn TlsConn>> {
    stream_tls_conn_impl(ctx, conn, cfg, false).await
}

/// [`stream_tls_conn`] with raw-transport handoff support for an XTLS Vision dial.
///
/// Without a client fingerprint, the plain-rustls branch uses a record-bounded reader so
/// Vision can switch to direct mode without stranding a record.
pub async fn stream_tls_conn_with_raw_handoff(
    ctx: &CancellationToken,
    conn: Box<dyn Stream>,
    cfg: &TlsConfig,
) -> Result<Box<dyn TlsConn>> {
    stream_tls_conn_impl(ctx, conn, cfg, true).await
}

// cancel-safe: `conn` is taken by value and the racing handshakes consume it, so a drop at any
// `.await` closes the stream and returns an error rather than leaving a half-negotiated conn
// reachable by a caller. No shared state is mutated before the handshake resolves.
async fn stream_tls_conn_impl(
    ctx: &CancellationToken,
    conn: Box<dyn Stream>,
    cfg: &TlsConfig,
    raw_handoff: bool,
) -> Result<Box<dyn TlsConn>> {
    if let Some(shadow) = &cfg.shadow_tls {
        let alpn =
            if cfg.next_protos.is_empty() { shadowtls::client::DEFAULT_ALPN.clone() } else { cfg.next_protos.clone() };
        let conn = shadowtls::client::new_shadow_tls(
            ctx,
            conn,
            Some(&shadowtls::client::ShadowTLSOption {
                password: shadow.password.clone(),
                host: cfg.host.clone(),
                fingerprint: cfg.finger_print.clone(),
                certificate: cfg.certificate.clone(),
                private_key: cfg.private_key.clone(),
                client_fingerprint: cfg.client_fingerprint.clone(),
                skip_cert_verify: cfg.skip_cert_verify,
                name_cert_verify: cfg.name_cert_verify.clone(),
                version: shadow.version,
                alpn,
            }),
        )
        .await?;
        return Ok(Box::new(ErasedTlsConn(conn)));
    }
    if let Some(restls) = &cfg.restls {
        let mut config = (**restls).clone();
        config.server_name = cfg.host.clone();
        config.next_protos = cfg.next_protos.clone();
        config.insecure_skip_verify = cfg.skip_cert_verify;
        if !cfg.finger_print.is_empty() {
            murmur_restls::config::set_fingerprint(&mut config, &cfg.finger_print, &cfg.name_cert_verify)?;
        } else if !cfg.name_cert_verify.is_empty() {
            murmur_restls::config::set_name_cert_verify(&mut config, &cfg.name_cert_verify);
        }
        let conn = tokio::select! {
            result = murmur_restls::new_restls(Box::new(StreamAsOldConn::new(conn)), &config) => result?,
            () = ctx.cancelled() => return Err(anyhow::anyhow!("Restls handshake cancelled")),
        };
        return Ok(Box::new(ErasedTlsConn(Box::new(OldConnAsStream(conn)))));
    }
    if let Some(jls_config) = &cfg.jls {
        // An unset `next_protos` selects JLS's default ALPN; an explicitly empty list cannot be
        // told apart from it here and is treated as unset too, the same way the ShadowTLS branch
        // above does.
        let alpn = (!cfg.next_protos.is_empty()).then(|| cfg.next_protos.clone());
        let client_config = jls_config.client_config(&cfg.host, alpn);
        let conn = jls::client::new_client(ctx, Box::new(StreamAsOldConn::new(conn)), &client_config).await?;
        return Ok(Box::new(ErasedTlsConn(Box::new(OldConnAsStream(conn)))));
    }
    if let Some(mirror_cfg) = &cfg.tls_mirror {
        let dial_ctx = tlsmirror::enrollment::dial_ctx_for(ctx);
        let client_config = tlsmirror::config::ClientConfig {
            config: mirror_cfg.clone(),
            server_name: cfg.host.clone(),
            skip_cert_verify: cfg.skip_cert_verify,
            name_cert_verify: cfg.name_cert_verify.clone(),
            alpn: cfg.next_protos.clone(),
            fingerprint: cfg.finger_print.clone(),
            certificate: cfg.certificate.clone(),
            private_key: cfg.private_key.clone(),
            client_fingerprint: cfg.client_fingerprint.clone(),
            forward_address_hint: cfg.host.clone(),
            ech: cfg.ech.clone().map(|ech| -> Arc<dyn tlsmirror::config::EchConfig> { Arc::new(TlsMirrorEch(ech)) }),
            enrollment_dialer: cfg.tls_mirror_dialer.clone(),
        };
        let conn = tlsmirror::client::dial(&dial_ctx, conn, client_config).await?;
        return Ok(Box::new(ErasedTlsConn(Box::new(conn))));
    }

    let tls_config = cfg.to_std_config()?;

    let (client_fingerprint, ok) = tls_c::get_fingerprint(&cfg.client_fingerprint);
    if ok {
        if let Some(reality_cfg) = &cfg.reality {
            let local_addr = conn.local_addr()?;
            let peer_addr = conn.peer_addr()?;
            let closer = murmur_reality::RealityCloser::capture(&*conn);
            let reality_stream = tokio::select! {
                result = murmur_reality::connect_reality_client(conn, &tls_config.server_name, reality_cfg) => result?,
                () = ctx.cancelled() => return Err(anyhow::anyhow!("REALITY handshake cancelled")),
            };
            let mut stream = reality_stream.with_addrs(local_addr, peer_addr);
            if let Some(closer) = closer {
                stream = stream.with_closer(closer);
            }
            return Ok(Box::new(RealityTlsConn::new(stream)));
        }
        let mut utls_config = tls_c::u_config(&tls_config);
        ech_client_handle_utls(cfg.ech.as_ref(), ctx, &mut utls_config).await?;
        let mut tls_conn = tls_c::uclient(conn, Arc::new(utls_config), client_fingerprint);
        tls_conn.handshake_context(ctx).await?;
        return Ok(Box::new(tls_conn));
    }
    if cfg.reality.is_some() {
        return Err(anyhow::anyhow!("REALITY is based on uTLS, please set a client-fingerprint"));
    }

    let mut tls_config = tls_config;
    ech_client_handle(cfg.ech.as_ref(), ctx, &mut tls_config).await?;

    let tls_conn = if raw_handoff {
        tls_c::client_with_raw_handoff(conn, Arc::new(tls_config))
    } else {
        tls_c::client(conn, Arc::new(tls_config))
    };
    tls_conn.handshake_context(ctx).await?;
    Ok(Box::new(tls_conn))
}

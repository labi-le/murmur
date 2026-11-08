//! v1 and v2 only: shadow-tls v3 needs a `ClientHello` `legacy_session_id` hook rustls does not
//! expose (rustls/rustls#1932).

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{OldConnAsStream, Stream, StreamAsOldConn};
use murmur_component_ca as ca;
use murmur_component_tls::utls;
use murmur_log::debugln;
use murmur_std_compat::net::Conn as NetConn;

use super::v2::{ClientConn, HashReadConn};

pub const MODE: &str = "shadow-tls";

pub static DEFAULT_ALPN: LazyLock<Vec<String>> = LazyLock::new(|| vec!["h2".to_owned(), "http/1.1".to_owned()]);
pub static WS_ALPN: LazyLock<Vec<String>> = LazyLock::new(|| vec!["http/1.1".to_owned()]);

pub type TlsSessionIdGeneratorFunc = Arc<dyn Fn(&[u8], &mut [u8]) -> Result<()> + Send + Sync>;

pub type TlsHandshakeFn = Arc<
    dyn Fn(
            CancellationToken,
            Box<dyn NetConn>,
            Option<TlsSessionIdGeneratorFunc>,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone, Debug, Default)]
pub struct ShadowTLSOption {
    pub password: String,
    pub host: String,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
    pub client_fingerprint: String,
    pub skip_cert_verify: bool,
    pub name_cert_verify: String,
    pub version: i32,
    pub alpn: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub password: String,
    pub version: i32,
}

/// Builds a client config.
///
/// Versions 1..=3 are accepted here; the client-side gate for the unimplemented version 3 belongs
/// to the dial path (`check_version`), because a dialer assembles its mutual-exclusion check only
/// after every mode has parsed.
pub fn new_config(password: &str, version: i32) -> Result<Config> {
    let version = if version == 0 { 2 } else { version };
    check_version_range(version)?;
    Ok(Config { password: password.to_owned(), version })
}

#[derive(Clone)]
pub struct ClientConfig {
    pub version: i32,
    pub password: String,
    pub tls_handshake: Option<TlsHandshakeFn>,
}

impl core::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("version", &self.version)
            .field("password", &"<redacted>")
            .field("tls_handshake", &self.tls_handshake.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct Client {
    version: i32,
    password: String,
    tls_handshake: Option<TlsHandshakeFn>,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("version", &self.version)
            .field("password", &"<redacted>")
            .field("tls_handshake", &self.tls_handshake.is_some())
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(config: ClientConfig) -> Result<Self> {
        check_version(config.version)?;
        Ok(Self { version: config.version, password: config.password, tls_handshake: config.tls_handshake })
    }

    pub fn set_handshake_func(&mut self, handshake_func: TlsHandshakeFn) {
        self.tls_handshake = Some(handshake_func);
    }

    pub async fn dial_context_conn(&self, ctx: &CancellationToken, conn: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let Some(tls_handshake) = self.tls_handshake.clone() else {
            return Err(anyhow!("shadow-tls: connection and TLS handshake are required"));
        };
        let shared = SharedConn::from_boxed(Box::new(StreamAsOldConn::new(conn)));
        match self.version {
            1 => {
                tls_handshake(ctx.clone(), Box::new(shared.clone()), None).await?;
                debugln!("[ShadowTLS] client handshake finished");
                Ok(Box::new(OldConnAsStream(shared)))
            }
            2 => {
                let hash_conn = HashReadConn::new(Box::new(shared), &self.password);
                let hash_conn_old: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(hash_conn.clone()));
                tls_handshake(ctx.clone(), hash_conn_old, None).await?;
                debugln!("[ShadowTLS] client handshake finished");
                Ok(Box::new(ClientConn::new(hash_conn)))
            }
            _ => Err(anyhow!("shadow-tls: unknown protocol version: {}", self.version)),
        }
    }
}

pub async fn new_shadow_tls(
    ctx: &CancellationToken,
    conn: Box<dyn Stream>,
    option: Option<&ShadowTLSOption>,
) -> Result<Box<dyn Stream>> {
    let Some(option) = option else {
        return Err(anyhow!("shadow-tls: nil client option"));
    };
    check_version(option.version)?;
    let mut tls_config = ca::config::get_tls_config(ca::config::Option {
        tls_config: Some(utls::Config {
            next_protos: option.alpn.clone(),
            min_version: utls::VERSION_TLS12,
            insecure_skip_verify: option.skip_cert_verify,
            server_name: option.host.clone(),
            ..Default::default()
        }),
        fingerprint: option.fingerprint.clone(),
        name_cert_verify: option.name_cert_verify.clone(),
        certificate: option.certificate.clone(),
        private_key: option.private_key.clone(),
        ..Default::default()
    })?;
    if option.version == 1 {
        tls_config.max_version = utls::VERSION_TLS12;
    }
    let client = Client::new(ClientConfig {
        version: option.version,
        password: option.password.clone(),
        tls_handshake: Some(u_tls_handshake_func(
            Arc::new(tls_config),
            option.client_fingerprint.clone(),
            option.version,
        )),
    })?;
    client.dial_context_conn(ctx, conn).await
}

fn u_tls_handshake_func(config: Arc<utls::Config>, client_fingerprint: String, version: i32) -> TlsHandshakeFn {
    Arc::new(
        move |ctx: CancellationToken,
              conn: Box<dyn NetConn>,
              session_id_generator: Option<TlsSessionIdGeneratorFunc>| {
            let config = Arc::clone(&config);
            let client_fingerprint = client_fingerprint.clone();
            Box::pin(async move {
                let mut tls_config = utls::u_config(&config);
                // The rustls-backed handshake has no hook for a caller-supplied session
                // ID (unlike the crate's from-scratch TLS implementation), so only the `uclient` branch
                // below actually reaches the ClientHello; this assignment still mirrors the
                // unconditional session-id generator assignment.
                tls_config.session_id_generator = session_id_generator.clone();
                if version == 1 {
                    tls_config.max_version = utls::VERSION_TLS12;
                    return utls::client(Box::new(OldConnAsStream(conn)), Arc::new(tls_config))
                        .handshake_context(&ctx)
                        .await;
                }
                let (fingerprint, ok) = utls::get_fingerprint(&client_fingerprint);
                if ok {
                    let next_protos = tls_config.next_protos.clone();
                    let mut tls_conn =
                        utls::uclient(Box::new(OldConnAsStream(conn)), Arc::new(tls_config), fingerprint);
                    if next_protos == *WS_ALPN {
                        utls::build_websocket_handshake_state(&mut tls_conn)?;
                    }
                    if version == 2 {
                        utls::build_removed_x25519_mlkem768_handshake_state(&mut tls_conn)?;
                    }
                    return tls_conn.handshake_context(&ctx).await;
                }
                utls::client(Box::new(OldConnAsStream(conn)), Arc::new(tls_config)).handshake_context(&ctx).await
            })
        },
    )
}

/// The version range accepted by a client config, without the client-side gate.
fn check_version_range(version: i32) -> Result<()> {
    if !(1..=3).contains(&version) {
        return Err(anyhow!("shadow-tls: unknown protocol version: {version}"));
    }
    Ok(())
}

/// The dial-time gate for shadow-tls v3, which has no Rust implementation: rustls exposes no hook
/// to set a `ClientHello`'s `legacy_session_id` (rustls/rustls#1932). Version 3 fails with a
/// message naming that reason; genuinely out-of-range versions keep the generic error.
pub(crate) fn check_version(version: i32) -> Result<()> {
    if version == 3 {
        return Err(anyhow!(
            "shadow-tls: protocol version 3 has no Rust implementation: rustls exposes no hook to set ClientHello legacy_session_id, see rust/README.md"
        ));
    }
    check_version_range(version)
}

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};

use crate::executor::executor as executor_mod;
use crate::route::server as route_server;
use murmur_config::config::Config;

/// Serialises a whole configuration operation.
///
/// Parsing is not side-effect free: `config::config::parse_raw_config` calls the general-update
/// hook, which writes the live general globals for the duration of the parse and rolls them back
/// through a `Drop` guard when it returns. An API update running inside that window (`PUT` and
/// `PATCH /configs` mutate the same globals and listeners) would be undone by the rollback, so
/// every entry point that parses or mutates the running configuration takes this lock for its whole
/// operation, parse and apply included.
static CONFIG_OPERATION: AsyncMutex<()> = AsyncMutex::const_new(());

/// Holds [`CONFIG_OPERATION`] for one parse-and-apply, or for one API update.
#[must_use]
pub async fn lock_config_operation() -> AsyncMutexGuard<'static, ()> {
    CONFIG_OPERATION.lock().await
}

/// A callback that mutates a [`Config`]. In this module std's `Option` is spelled in full.
pub type Option = Box<dyn Fn(&mut Config) + Send + Sync>;

#[must_use]
pub fn with_external_ui(external_ui: &str) -> Option {
    let external_ui = external_ui.to_owned();
    Box::new(move |cfg: &mut Config| {
        cfg.controller.external_ui.clone_from(&external_ui);
    })
}

#[must_use]
pub fn with_external_controller(external_controller: &str) -> Option {
    let external_controller = external_controller.to_owned();
    Box::new(move |cfg: &mut Config| {
        cfg.controller.external_controller.clone_from(&external_controller);
    })
}

#[must_use]
pub fn with_external_controller_tls(external_controller_tls: &str) -> Option {
    let external_controller_tls = external_controller_tls.to_owned();
    Box::new(move |cfg: &mut Config| {
        cfg.controller.external_controller_tls.clone_from(&external_controller_tls);
    })
}

#[must_use]
pub fn with_external_controller_unix(external_controller_unix: &str) -> Option {
    let external_controller_unix = external_controller_unix.to_owned();
    Box::new(move |cfg: &mut Config| {
        cfg.controller.external_controller_unix.clone_from(&external_controller_unix);
    })
}

#[must_use]
pub fn with_external_controller_pipe(external_controller_pipe: &str) -> Option {
    let external_controller_pipe = external_controller_pipe.to_owned();
    Box::new(move |cfg: &mut Config| {
        cfg.controller.external_controller_pipe.clone_from(&external_controller_pipe);
    })
}

#[must_use]
pub fn with_external_controller_routing_mark(external_controller_routing_mark: i32) -> Option {
    Box::new(move |cfg: &mut Config| {
        cfg.controller.external_controller_routing_mark = external_controller_routing_mark;
    })
}

#[must_use]
pub fn with_secret(secret: &str) -> Option {
    let secret = secret.to_owned();
    Box::new(move |cfg: &mut Config| {
        cfg.controller.secret.clone_from(&secret);
    })
}

/// Dispatches the configuration to all parts, including the external controller.
///
/// The caller holds [`CONFIG_OPERATION`] ([`parse`] takes it). A failure means the configuration
/// reached every part but at least one of them could not do what it asked, so the running state is
/// the partially applied one.
pub async fn apply_config(cfg: Config) -> Result<()> {
    let mut failures = Vec::new();
    if let Err(err) = apply_route(&cfg).await {
        failures.push(err);
    }
    if let Err(err) = executor_mod::apply_config(cfg, true).await {
        failures.push(err);
    }
    if failures.is_empty() {
        return Ok(());
    }
    let joined = failures.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ");
    Err(anyhow::anyhow!("{joined}"))
}

async fn apply_route(cfg: &Config) -> Result<()> {
    #[cfg(all(target_os = "android", feature = "cmfa"))]
    {
        static ANDROID_EMBED_INIT: std::sync::Once = std::sync::Once::new();
        ANDROID_EMBED_INIT.call_once(crate::route::patch_android::init);
    }

    route_server::re_create_server(Arc::new(route_server::Config {
        addr: cfg.controller.external_controller.clone(),
        tls_addr: cfg.controller.external_controller_tls.clone(),
        unix_addr: cfg.controller.external_controller_unix.clone(),
        pipe_addr: cfg.controller.external_controller_pipe.clone(),
        ui_path: cfg.controller.external_ui.clone(),
        routing_mark: cfg.controller.external_controller_routing_mark,
        secret: cfg.controller.secret.clone(),
        certificate: cfg.tls.certificate.clone(),
        private_key: cfg.tls.private_key.clone(),
        client_auth_type: cfg.tls.client_auth_type.clone(),
        client_auth_cert: cfg.tls.client_auth_cert.clone(),
        ech_key: cfg.tls.ech_key.clone(),
        doh_server: cfg.controller.external_doh_server.clone(),
        is_debug: cfg.general.log_level == murmur_log::LogLevel::DEBUG,
        cors: route_server::Cors {
            allow_origins: cfg.controller.cors.allow_origins.clone(),
            allow_private_network: cfg.controller.cors.allow_private_network,
        },
    }))
    .await
}

/// The stage at which a parse-and-apply failed.
///
/// The distinction is what a file watcher needs: a rejected read or parse leaves the running
/// configuration exactly as it was, while an apply that reported a failure may already have closed
/// or replaced listeners before it gave up.
#[derive(Debug)]
pub enum ReloadError {
    /// Reading or parsing failed: nothing was applied, so the running configuration is untouched.
    Rejected(anyhow::Error),
    /// The parse succeeded and the apply ran: at least one part of the running configuration could
    /// not be applied, so it may be the partially applied one.
    PartiallyApplied(anyhow::Error),
}

impl std::fmt::Display for ReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(err) | Self::PartiallyApplied(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for ReloadError {
    fn source(&self) -> std::option::Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected(err) | Self::PartiallyApplied(err) => err.source(),
        }
    }
}

/// Parses the configuration at startup, or again on a reload.
///
/// Holds [`CONFIG_OPERATION`] across the parse and the apply, so an API update cannot interleave
/// with the parse-time general update and be rolled back by it. The error names the stage that
/// failed (see [`ReloadError`]).
pub async fn parse(config_bytes: &[u8], options: &[Option]) -> Result<(), ReloadError> {
    let _operation = lock_config_operation().await;

    let mut cfg = match if config_bytes.is_empty() {
        executor_mod::parse().await
    } else {
        executor_mod::parse_with_bytes(config_bytes).await
    } {
        Ok(cfg) => cfg,
        Err(err) => return Err(ReloadError::Rejected(err)),
    };

    for option in options {
        option(&mut cfg);
    }

    // Boxed: the config-apply chain is by far the largest future awaited here.
    Box::pin(apply_config(cfg)).await.map_err(ReloadError::PartiallyApplied)
}

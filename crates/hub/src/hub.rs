use std::sync::Arc;

use anyhow::Result;

use crate::executor::executor as executor_mod;
use crate::route::server as route_server;
use murmur_config::config::Config;

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
pub async fn apply_config(cfg: Config) {
    apply_route(&cfg).await;
    executor_mod::apply_config(cfg, true).await;
}

async fn apply_route(cfg: &Config) {
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
    .await;
}

/// Parses the configuration at startup.
pub async fn parse(config_bytes: &[u8], options: &[Option]) -> Result<()> {
    let mut cfg = if config_bytes.is_empty() {
        executor_mod::parse().await?
    } else {
        executor_mod::parse_with_bytes(config_bytes).await?
    };

    for option in options {
        option(&mut cfg);
    }

    // Boxed: the config-apply chain is by far the largest future awaited here.
    Box::pin(apply_config(cfg)).await;
    Ok(())
}

use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use murmur_component_ca as ca;
use murmur_component_ech as ech;
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport_vmess::websocket::{stream_websocket_conn_public, WebsocketConfig};

use super::mux::{new_mux, MuxOption};

/// `Option`: options of the websocket obfs.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the struct mirrors the v2ray-plugin option set field for field, where every bool is an \
              independent switch"
)]
#[derive(Clone, Default)]
pub struct Option {
    pub host: String,
    pub port: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub tls: bool,
    pub ech_config: std::option::Option<Arc<ech::Config>>,
    pub skip_cert_verify: bool,
    pub name_cert_verify: String,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
    pub mux: bool,
    pub v2ray_http_upgrade: bool,
    pub v2ray_http_upgrade_fast_open: bool,
}

impl std::fmt::Debug for Option {
    // The header values, the certificate/key pair and the ECH config are withheld: they carry
    // credentials (a v2ray id, an `Authorization` token) and key material that must not reach a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Option")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("path", &self.path)
            .field("headers", &"<redacted>")
            .field("tls", &self.tls)
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("name_cert_verify", &self.name_cert_verify)
            .field("fingerprint", &self.fingerprint)
            .field("mux", &self.mux)
            .field("v2ray_http_upgrade", &self.v2ray_http_upgrade)
            .field("v2ray_http_upgrade_fast_open", &self.v2ray_http_upgrade_fast_open)
            .finish_non_exhaustive()
    }
}

/// Builds a v2ray obfuscated conn.
pub async fn new_v2ray_obfs(
    ctx: &CancellationToken,
    conn: Box<dyn NetConn>,
    option: &Option,
) -> Result<Box<dyn NetConn>> {
    let WebsocketConfig { tls, tls_config, max_early_data, early_data_header_name, client_fingerprint, .. } =
        WebsocketConfig::default();
    let mut config = WebsocketConfig {
        host: option.host.clone(),
        port: option.port.clone(),
        path: option.path.clone(),
        headers: option.headers.clone(),
        tls,
        tls_config,
        ech_config: option.ech_config.clone(),
        max_early_data,
        early_data_header_name,
        client_fingerprint,
        v2ray_http_upgrade: option.v2ray_http_upgrade,
        v2ray_http_upgrade_fast_open: option.v2ray_http_upgrade_fast_open,
    };

    if option.tls {
        config.tls = true;
        let tls_config = ca::config::get_tls_config(ca::config::Option {
            tls_config: Some(crate::websocket_tls::http_upgrade_tls_config(&option.host, option.skip_cert_verify)),
            fingerprint: option.fingerprint.clone(),
            name_cert_verify: option.name_cert_verify.clone(),
            zero_trust: false,
            certificate: option.certificate.clone(),
            private_key: option.private_key.clone(),
        })?;
        let mut tls_config = tls_config;

        if let Some(host) = config.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Host")).map(|(_, v)| v.clone())
        {
            if !host.is_empty() {
                tls_config.server_name = host;
            }
        }

        config.tls_config = Some(Arc::new(tls_config));
    }

    let mut conn = stream_websocket_conn_public(ctx, conn, config).await?;

    if option.mux {
        conn = Box::new(new_mux(
            conn,
            MuxOption { id: [0, 0], port: 0, host: "127.0.0.1".to_owned(), type_: String::new() },
        ));
    }
    Ok(conn)
}

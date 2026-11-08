use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use murmur_component_ech::ech::Config as EchConfig;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ECHOptions {
    #[serde(rename = "enable", default)]
    pub enable: bool,
    #[serde(rename = "config", default)]
    pub config: String,
    #[serde(rename = "query-server-name", default)]
    pub query_server_name: String,
}

impl ECHOptions {
    pub fn parse(&self) -> anyhow::Result<Option<EchConfig>> {
        if !self.enable {
            return Ok(None);
        }

        if !self.config.is_empty() {
            let list = STANDARD
                .decode(&self.config)
                .map_err(|err| anyhow::anyhow!("base64 decode ech config string failed: {err}"))?;
            return Ok(Some(EchConfig {
                get_encrypted_client_hello_config_list: Arc::new(move |_ctx, _server_name| {
                    let list = list.clone();
                    Box::pin(async move { Ok(list) })
                }),
            }));
        }

        let query_server_name = self.query_server_name.clone();
        Ok(Some(EchConfig {
            get_encrypted_client_hello_config_list: Arc::new(move |ctx, server_name| {
                let query_server_name = query_server_name.clone();
                Box::pin(async move {
                    let server_name = if query_server_name.is_empty() { server_name } else { query_server_name };
                    murmur_component::resolver::resolver::resolve_ech_with_resolver(
                        &ctx,
                        &server_name,
                        murmur_component::resolver::resolver::proxy_server_host_resolver().as_deref(),
                    )
                    .await
                })
            }),
        }))
    }
}

use serde::{Deserialize, Serialize};

use murmur_transport_shadowtls::client;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShadowTLSOptions {
    #[serde(rename = "password", default)]
    pub password: String,
    #[serde(rename = "version", default)]
    pub version: i32,
}

impl ShadowTLSOptions {
    pub fn parse(&self) -> anyhow::Result<Option<client::Config>> {
        if self.password.is_empty() && self.version == 0 {
            return Ok(None);
        }
        Ok(Some(client::new_config(&self.password, self.version)?))
    }
}

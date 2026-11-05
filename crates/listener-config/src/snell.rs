use serde::{Deserialize, Serialize};

use crate::jls::JLSConfig;
use crate::restls::ResTLS;
use crate::shadowtls::ShadowTLS;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SnellServer {
    #[serde(rename = "Listen")]
    pub listen: String,
    #[serde(rename = "Psk")]
    pub psk: String,
    #[serde(rename = "Version")]
    pub version: i32,
    #[serde(rename = "UDP")]
    pub udp: bool,
    #[serde(rename = "ObfsMode")]
    pub obfs_mode: String,
    #[serde(rename = "ObfsHost")]
    pub obfs_host: String,
    #[serde(rename = "shadow-tls")]
    pub shadow_tls: ShadowTLS,
    #[serde(rename = "res-tls")]
    pub res_tls: ResTLS,
    #[serde(rename = "jls-config")]
    pub jls_config: JLSConfig,
}

impl std::fmt::Display for SnellServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Ok(()),
        }
    }
}

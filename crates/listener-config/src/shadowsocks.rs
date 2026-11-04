use serde::{Deserialize, Serialize};

use crate::jls::JLSConfig;
use crate::kcptun::KcpTun;
use crate::restls::ResTLS;
use crate::shadowtls::ShadowTLS;
use murmur_listener_sing::sing::MuxOption;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShadowsocksServer {
    #[serde(rename = "Enable")]
    pub enable: bool,
    #[serde(rename = "Listen")]
    pub listen: String,
    #[serde(rename = "Password")]
    pub password: String,
    #[serde(rename = "Cipher")]
    pub cipher: String,
    #[serde(rename = "Udp")]
    pub udp: bool,
    #[serde(rename = "mux-option", default)]
    pub mux_option: MuxOption,
    #[serde(rename = "shadow-tls", default)]
    pub shadow_tls: ShadowTLS,
    #[serde(rename = "res-tls", default)]
    pub res_tls: ResTLS,
    #[serde(rename = "jls-config", default)]
    pub jls_config: JLSConfig,
    #[serde(rename = "kcp-tun", default)]
    pub kcp_tun: KcpTun,
    #[serde(rename = "simple-obfs", default)]
    pub simple_obfs: SimpleObfs,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SimpleObfs {
    #[serde(rename = "Enable")]
    pub enable: bool,
    #[serde(rename = "Mode")]
    pub mode: String,
}

impl std::fmt::Display for ShadowsocksServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Ok(()),
        }
    }
}

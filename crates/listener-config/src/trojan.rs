use serde::{Deserialize, Serialize};

use crate::jls::JLSConfig;
use crate::reality::RealityConfig;
use crate::restls::ResTLS;
use crate::shadowtls::ShadowTLS;
use murmur_listener_sing::sing::MuxOption;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrojanUser {
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "Password")]
    pub password: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrojanServer {
    #[serde(rename = "Enable")]
    pub enable: bool,
    #[serde(rename = "Listen")]
    pub listen: String,
    #[serde(rename = "Users")]
    pub users: Vec<TrojanUser>,
    #[serde(rename = "WsPath")]
    pub ws_path: String,
    #[serde(rename = "GrpcServiceName")]
    pub grpc_service_name: String,
    #[serde(rename = "Certificate")]
    pub certificate: String,
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    #[serde(rename = "ClientAuthType")]
    pub client_auth_type: String,
    #[serde(rename = "ClientAuthCert")]
    pub client_auth_cert: String,
    #[serde(rename = "EchKey")]
    pub ech_key: String,
    #[serde(rename = "AllowInsecure")]
    pub allow_insecure: bool,
    #[serde(rename = "shadow-tls")]
    pub shadow_tls: ShadowTLS,
    #[serde(rename = "res-tls")]
    pub res_tls: ResTLS,
    #[serde(rename = "jls-config")]
    pub jls_config: JLSConfig,
    #[serde(rename = "reality-config")]
    pub reality_config: Option<RealityConfig>,
    #[serde(rename = "MuxOption")]
    pub mux_option: MuxOption,
    #[serde(rename = "TrojanSSOption")]
    pub trojan_ss_option: TrojanSSOption,
}

/// The shadowsocks option carried by a Trojan server config.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrojanSSOption {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "Method")]
    pub method: String,
    #[serde(rename = "Password")]
    pub password: String,
}

impl std::fmt::Display for TrojanServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Ok(()),
        }
    }
}

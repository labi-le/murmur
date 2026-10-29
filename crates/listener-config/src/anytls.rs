use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::jls::JLSConfig;
use crate::restls::ResTLS;
use crate::shadowtls::ShadowTLS;

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the serde `skip_serializing_if` hook receives the field by reference"
)]
const fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AnyTLSServer {
    #[serde(rename = "enable")]
    pub enable: bool,
    #[serde(rename = "listen")]
    pub listen: String,
    #[serde(rename = "users", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub users: BTreeMap<String, String>,
    #[serde(rename = "certificate", default, skip_serializing_if = "String::is_empty")]
    pub certificate: String,
    #[serde(rename = "private-key", default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    #[serde(rename = "client-auth-type", default, skip_serializing_if = "String::is_empty")]
    pub client_auth_type: String,
    #[serde(rename = "client-auth-cert", default, skip_serializing_if = "String::is_empty")]
    pub client_auth_cert: String,
    #[serde(rename = "ech-key", default, skip_serializing_if = "String::is_empty")]
    pub ech_key: String,
    #[serde(rename = "shadow-tls", default)]
    pub shadow_tls: ShadowTLS,
    #[serde(rename = "res-tls", default)]
    pub res_tls: ResTLS,
    #[serde(rename = "jls-config", default)]
    pub jls_config: JLSConfig,
    #[serde(rename = "allow-insecure", default, skip_serializing_if = "is_false")]
    pub allow_insecure: bool,
    #[serde(rename = "padding-scheme", default, skip_serializing_if = "String::is_empty")]
    pub padding_scheme: String,
}

impl std::fmt::Display for AnyTLSServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Ok(()),
        }
    }
}

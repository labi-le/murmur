use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the serde `skip_serializing_if` hook receives the field by reference"
)]
const fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrustTunnelServer {
    #[serde(rename = "enable")]
    pub enable: bool,
    #[serde(rename = "listen")]
    pub listen: String,
    #[serde(rename = "users", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub users: BTreeMap<String, String>,
    #[serde(rename = "certificate")]
    pub certificate: String,
    #[serde(rename = "private-key")]
    pub private_key: String,
    #[serde(rename = "client-auth-type", default, skip_serializing_if = "String::is_empty")]
    pub client_auth_type: String,
    #[serde(rename = "client-auth-cert", default, skip_serializing_if = "String::is_empty")]
    pub client_auth_cert: String,
    #[serde(rename = "ech-key")]
    pub ech_key: String,
    #[serde(rename = "network", default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    #[serde(rename = "congestion-controller", default, skip_serializing_if = "String::is_empty")]
    pub congestion_controller: String,
    #[serde(rename = "cwnd", default, skip_serializing_if = "is_zero_i32")]
    pub cwnd: i32,
    #[serde(rename = "bbr-profile", default, skip_serializing_if = "String::is_empty")]
    pub bbr_profile: String,
}

impl std::fmt::Display for TrustTunnelServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Ok(()),
        }
    }
}

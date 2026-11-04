use serde::{Deserialize, Serialize};

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the serde `skip_serializing_if` hook receives the field by reference"
)]
const fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Hysteria2RealmServer {
    #[serde(rename = "enable")]
    pub enable: bool,
    #[serde(rename = "listen")]
    pub listen: String,
    #[serde(rename = "token")]
    pub token: String,
    #[serde(rename = "max-realms", default, skip_serializing_if = "is_zero_i32")]
    pub max_realms: i32,
    #[serde(rename = "max-realms-per-ip", default, skip_serializing_if = "is_zero_i32")]
    pub max_realms_per_ip: i32,
    #[serde(rename = "trusted-proxy-header", default, skip_serializing_if = "String::is_empty")]
    pub trusted_proxy_header: String,
    #[serde(rename = "realm-name-pattern", default, skip_serializing_if = "String::is_empty")]
    pub realm_name_pattern: String,
    #[serde(rename = "certificate")]
    pub certificate: String,
    #[serde(rename = "private-key")]
    pub private_key: String,
    #[serde(rename = "client-auth-type", default, skip_serializing_if = "String::is_empty")]
    pub client_auth_type: String,
    #[serde(rename = "client-auth-cert", default, skip_serializing_if = "String::is_empty")]
    pub client_auth_cert: String,
    #[serde(rename = "ech-key", default, skip_serializing_if = "String::is_empty")]
    pub ech_key: String,
    #[serde(rename = "alpn", default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
}

impl std::fmt::Display for Hysteria2RealmServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Ok(()),
        }
    }
}

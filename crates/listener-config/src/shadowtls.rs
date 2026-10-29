use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShadowTLS {
    #[serde(rename = "Enable")]
    pub enable: bool,
    #[serde(rename = "Version")]
    pub version: i32,
    #[serde(rename = "Password")]
    pub password: String,
    #[serde(rename = "Handshake")]
    pub handshake: ShadowTLSHandshakeOptions,
    #[serde(rename = "HandshakeForServerName")]
    pub handshake_for_server_name: BTreeMap<String, ShadowTLSHandshakeOptions>,
    #[serde(rename = "Users")]
    pub users: Vec<ShadowTLSUser>,
    #[serde(rename = "StrictMode")]
    pub strict_mode: bool,
    #[serde(rename = "WildcardSNI")]
    pub wildcard_sni: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShadowTLSUser {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Password")]
    pub password: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShadowTLSHandshakeOptions {
    #[serde(rename = "Dest")]
    pub dest: String,
    #[serde(rename = "Proxy")]
    pub proxy: String,
}

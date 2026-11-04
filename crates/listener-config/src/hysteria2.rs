use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use murmur_listener_sing::sing::MuxOption;

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the serde `skip_serializing_if` hook receives the field by reference"
)]
const fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the serde `skip_serializing_if` hook receives the field by reference"
)]
const fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Hysteria2Server {
    #[serde(rename = "enable")]
    pub enable: bool,
    #[serde(rename = "listen")]
    pub listen: String,
    #[serde(rename = "users", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub users: BTreeMap<String, String>,
    #[serde(rename = "obfs", default, skip_serializing_if = "String::is_empty")]
    pub obfs: String,
    #[serde(rename = "obfs-password", default, skip_serializing_if = "String::is_empty")]
    pub obfs_password: String,
    #[serde(rename = "obfs-min-packet-size", default, skip_serializing_if = "is_zero_i32")]
    pub obfs_min_packet_size: i32,
    #[serde(rename = "obfs-max-packet-size", default, skip_serializing_if = "is_zero_i32")]
    pub obfs_max_packet_size: i32,
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
    #[serde(rename = "max-idle-time", default, skip_serializing_if = "is_zero_i32")]
    pub max_idle_time: i32,
    #[serde(rename = "alpn", default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(rename = "up", default, skip_serializing_if = "String::is_empty")]
    pub up: String,
    #[serde(rename = "down", default, skip_serializing_if = "String::is_empty")]
    pub down: String,
    #[serde(rename = "ignore-client-bandwidth", default, skip_serializing_if = "std::ops::Not::not")]
    pub ignore_client_bandwidth: bool,
    #[serde(rename = "masquerade", default, skip_serializing_if = "String::is_empty")]
    pub masquerade: String,
    #[serde(rename = "cwnd", default, skip_serializing_if = "is_zero_i32")]
    pub cwnd: i32,
    #[serde(rename = "bbr-profile", default, skip_serializing_if = "String::is_empty")]
    pub bbr_profile: String,
    #[serde(rename = "udp-mtu", default, skip_serializing_if = "is_zero_i32")]
    pub udp_mtu: i32,
    #[serde(rename = "mux-option", default)]
    pub mux_option: MuxOption,
    #[serde(rename = "realm-opts", default)]
    pub realm_opts: Hysteria2RealmOption,
    #[serde(rename = "initial-stream-receive-window", default, skip_serializing_if = "is_zero_u64")]
    pub initial_stream_receive_window: u64,
    #[serde(rename = "max-stream-receive-window", default, skip_serializing_if = "is_zero_u64")]
    pub max_stream_receive_window: u64,
    #[serde(rename = "initial-connection-receive-window", default, skip_serializing_if = "is_zero_u64")]
    pub initial_connection_receive_window: u64,
    #[serde(rename = "max-connection-receive-window", default, skip_serializing_if = "is_zero_u64")]
    pub max_connection_receive_window: u64,
}

/// `Hysteria2RealmOption`, the `realm-opts` block of a `hysteria2` listener.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Hysteria2RealmOption {
    #[serde(rename = "enable")]
    pub enable: bool,
    #[serde(rename = "server-url", default, skip_serializing_if = "String::is_empty")]
    pub server_url: String,
    #[serde(rename = "token", default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    #[serde(rename = "realm-id", default, skip_serializing_if = "String::is_empty")]
    pub realm_id: String,
    #[serde(rename = "stun-servers", default, skip_serializing_if = "Vec::is_empty")]
    pub stun_servers: Vec<String>,
    #[serde(rename = "sni", default, skip_serializing_if = "String::is_empty")]
    pub sni: String,
    #[serde(rename = "skip-cert-verify", default, skip_serializing_if = "std::ops::Not::not")]
    pub skip_cert_verify: bool,
    #[serde(rename = "name-cert-verify", default, skip_serializing_if = "String::is_empty")]
    pub name_cert_verify: String,
    #[serde(rename = "fingerprint", default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    #[serde(rename = "certificate", default, skip_serializing_if = "String::is_empty")]
    pub certificate: String,
    #[serde(rename = "private-key", default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    #[serde(rename = "alpn", default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(rename = "proxy", default, skip_serializing_if = "String::is_empty")]
    pub proxy: String,
}

impl std::fmt::Display for Hysteria2Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Ok(()),
        }
    }
}

use serde::{Deserialize, Serialize};

use murmur_listener_sing::sing::MuxOption;

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the serde `skip_serializing_if` hook receives the field by reference"
)]
const fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShadowQuicUser {
    #[serde(rename = "username")]
    pub username: String,
    #[serde(rename = "password")]
    pub password: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShadowQuicJLSUpstream {
    #[serde(rename = "addr")]
    pub addr: String,
    #[serde(rename = "sni", default, skip_serializing_if = "String::is_empty")]
    pub sni: String,
    #[serde(rename = "proxy", default, skip_serializing_if = "String::is_empty")]
    pub proxy: String,
    #[serde(rename = "rate-limit", default, skip_serializing_if = "is_zero")]
    pub rate_limit: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[expect(clippy::struct_excessive_bools, reason = "the flags mirror the shadowquic config schema")]
pub struct ShadowQuicServer {
    #[serde(rename = "enable")]
    pub enable: bool,
    #[serde(rename = "listen")]
    pub listen: String,
    #[serde(rename = "users", default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<ShadowQuicUser>,
    #[serde(rename = "jls-upstream", default)]
    pub jls_upstream: ShadowQuicJLSUpstream,
    #[serde(rename = "alpn", default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(rename = "quic-versions", default, skip_serializing_if = "Vec::is_empty")]
    pub quic_versions: Vec<String>,
    #[serde(rename = "zero-rtt", default, skip_serializing_if = "is_false")]
    pub zero_rtt: bool,
    #[serde(rename = "congestion-controller", default, skip_serializing_if = "String::is_empty")]
    pub congestion_controller: String,
    #[serde(rename = "up", default, skip_serializing_if = "String::is_empty")]
    pub up: String,
    #[serde(rename = "down", default, skip_serializing_if = "String::is_empty")]
    pub down: String,
    #[serde(rename = "ignore-client-bandwidth", default, skip_serializing_if = "is_false")]
    pub ignore_client_bandwidth: bool,
    #[serde(rename = "max-idle-time", default, skip_serializing_if = "is_zero")]
    pub max_idle_time: i32,
    #[serde(rename = "max-datagram-frame-size", default, skip_serializing_if = "is_zero")]
    pub max_datagram_frame_size: i32,
    #[serde(rename = "recv-window-conn", default, skip_serializing_if = "is_zero")]
    pub receive_window_conn: i32,
    #[serde(rename = "recv-window", default, skip_serializing_if = "is_zero")]
    pub receive_window: i32,
    #[serde(rename = "disable-mtu-discovery", default, skip_serializing_if = "is_false")]
    pub disable_mtu_discovery: bool,
    #[serde(rename = "cwnd", default, skip_serializing_if = "is_zero")]
    pub cwnd: i32,
    #[serde(rename = "bbr-profile", default, skip_serializing_if = "String::is_empty")]
    pub bbr_profile: String,
    #[serde(rename = "mux-option", default)]
    pub mux_option: MuxOption,
}

impl std::fmt::Display for ShadowQuicServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Ok(()),
        }
    }
}

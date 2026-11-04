use serde::{Deserialize, Serialize};

use crate::jls::JLSConfig;
use crate::mekya::MekyaConfig;
use crate::mkcp::MKCPConfig;
use crate::reality::RealityConfig;
use crate::restls::ResTLS;
use crate::shadowtls::ShadowTLS;
use murmur_listener_sing::sing::MuxOption;
use murmur_transport_tlsmirror::config as tlsmirror;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VmessUser {
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "UUID")]
    pub uuid: String,
    #[serde(rename = "AlterID")]
    pub alter_id: i32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VmessServer {
    #[serde(rename = "Enable")]
    pub enable: bool,
    #[serde(rename = "Listen")]
    pub listen: String,
    #[serde(rename = "Users")]
    pub users: Vec<VmessUser>,
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
    #[serde(rename = "shadow-tls")]
    pub shadow_tls: ShadowTLS,
    #[serde(rename = "res-tls")]
    pub res_tls: ResTLS,
    #[serde(rename = "jls-config")]
    pub jls_config: JLSConfig,
    #[serde(rename = "reality-config")]
    pub reality_config: Option<RealityConfig>,
    #[serde(rename = "tlsmirror-config")]
    pub tls_mirror_config: TLSMirrorConfig,
    #[serde(rename = "mekya-config")]
    pub mekya_config: MekyaConfig,
    #[serde(rename = "mkcp-config")]
    pub mkcp_config: MKCPConfig,
    #[serde(rename = "mux-option")]
    pub mux_option: MuxOption,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TLSMirrorConfig {
    #[serde(rename = "primary-key", default, skip_serializing_if = "String::is_empty")]
    pub primary_key: String,
    #[serde(rename = "dest", default, skip_serializing_if = "String::is_empty")]
    pub dest: String,
    #[serde(rename = "proxy", default, skip_serializing_if = "String::is_empty")]
    pub proxy: String,
    #[serde(rename = "explicit-nonce-ciphersuites", default, skip_serializing_if = "Vec::is_empty")]
    pub explicit_nonce_cipher_suites: Vec<u16>,
    #[serde(rename = "defer-instance-derived-write-time", default)]
    pub defer_instance_derived_write_time: TLSMirrorTimeSpec,
    #[serde(rename = "transport-layer-padding", default)]
    pub transport_layer_padding: TLSMirrorTransportLayerPadding,
    #[serde(rename = "connection-enrolment", default, skip_serializing_if = "Option::is_none")]
    pub connection_enrolment: Option<TLSMirrorConnectionEnrolment>,
    #[serde(rename = "sequence-watermarking-enabled", default, skip_serializing_if = "std::ops::Not::not")]
    pub sequence_watermarking_enabled: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TLSMirrorConnectionEnrolment {
    #[serde(rename = "primary-ingress-outbound", default, skip_serializing_if = "String::is_empty")]
    pub primary_ingress_outbound: String,
    #[serde(rename = "primary-egress-outbound", default, skip_serializing_if = "String::is_empty")]
    pub primary_egress_outbound: String,
}

impl TLSMirrorConnectionEnrolment {
    #[must_use]
    pub fn build(this: Option<&Self>) -> Option<tlsmirror::ConnectionEnrolment> {
        let e = this?;
        Some(tlsmirror::ConnectionEnrolment {
            primary_ingress_outbound: e.primary_ingress_outbound.clone(),
            primary_egress_outbound: e.primary_egress_outbound.clone(),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct TLSMirrorTimeSpec {
    #[serde(rename = "base-nanoseconds", default, skip_serializing_if = "is_zero_u64")]
    pub base_nanoseconds: u64,
    #[serde(rename = "uniform-random-multiplier-nanoseconds", default, skip_serializing_if = "is_zero_u64")]
    pub uniform_random_multiplier_nanoseconds: u64,
}

impl TLSMirrorTimeSpec {
    #[must_use]
    pub const fn build(&self) -> tlsmirror::TimeSpec {
        tlsmirror::TimeSpec {
            base_nanoseconds: self.base_nanoseconds,
            uniform_random_multiplier_nanoseconds: self.uniform_random_multiplier_nanoseconds,
        }
    }
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the serde `skip_serializing_if` hook receives the field by reference"
)]
const fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct TLSMirrorTransportLayerPadding {
    #[serde(rename = "enabled", default, skip_serializing_if = "std::ops::Not::not")]
    pub enabled: bool,
}

impl TLSMirrorTransportLayerPadding {
    #[must_use]
    pub const fn build(&self) -> tlsmirror::TransportLayerPadding {
        tlsmirror::TransportLayerPadding { enabled: self.enabled }
    }
}

impl std::fmt::Display for VmessServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Ok(()),
        }
    }
}

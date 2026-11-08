use serde::{Deserialize, Serialize};

use crate::jls::JLSConfig;
use crate::reality::RealityConfig;
use crate::restls::ResTLS;
use crate::shadowtls::ShadowTLS;
use murmur_listener_sing::sing::MuxOption;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VlessUser {
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "UUID")]
    pub uuid: String,
    #[serde(rename = "Flow")]
    pub flow: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VlessServer {
    #[serde(rename = "Enable")]
    pub enable: bool,
    #[serde(rename = "Listen")]
    pub listen: String,
    #[serde(rename = "Users")]
    pub users: Vec<VlessUser>,
    #[serde(rename = "Decryption")]
    pub decryption: String,
    #[serde(rename = "WsPath")]
    pub ws_path: String,
    #[serde(rename = "XHTTPConfig")]
    pub xhttp_config: XHTTPConfig,
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
    #[serde(rename = "mux-option")]
    pub mux_option: MuxOption,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XHTTPConfig {
    #[serde(rename = "Path")]
    pub path: String,
    #[serde(rename = "Host")]
    pub host: String,
    #[serde(rename = "Mode")]
    pub mode: String,
    #[serde(rename = "XPaddingBytes")]
    pub x_padding_bytes: String,
    #[serde(rename = "XPaddingObfsMode")]
    pub x_padding_obfs_mode: bool,
    #[serde(rename = "XPaddingKey")]
    pub x_padding_key: String,
    #[serde(rename = "XPaddingHeader")]
    pub x_padding_header: String,
    #[serde(rename = "XPaddingPlacement")]
    pub x_padding_placement: String,
    #[serde(rename = "XPaddingMethod")]
    pub x_padding_method: String,
    #[serde(rename = "UplinkHTTPMethod")]
    pub uplink_http_method: String,
    #[serde(rename = "SessionPlacement")]
    pub session_placement: String,
    #[serde(rename = "SessionKey")]
    pub session_key: String,
    #[serde(rename = "SeqPlacement")]
    pub seq_placement: String,
    #[serde(rename = "SeqKey")]
    pub seq_key: String,
    #[serde(rename = "UplinkDataPlacement")]
    pub uplink_data_placement: String,
    #[serde(rename = "UplinkDataKey")]
    pub uplink_data_key: String,
    #[serde(rename = "UplinkChunkSize")]
    pub uplink_chunk_size: String,
    #[serde(rename = "NoSSEHeader")]
    pub no_sse_header: bool,
    #[serde(rename = "ScStreamUpServerSecs")]
    pub sc_stream_up_server_secs: String,
    #[serde(rename = "ScMaxBufferedPosts")]
    pub sc_max_buffered_posts: String,
    #[serde(rename = "ScMaxEachPostBytes")]
    pub sc_max_each_post_bytes: String,
}

impl std::fmt::Display for VlessServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Ok(()),
        }
    }
}

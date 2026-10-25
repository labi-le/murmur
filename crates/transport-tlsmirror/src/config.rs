//! `DialCtx` carries both cancellation and the per-dial key/value chain the enrollment loopback
//! checks read; there is no crate-wide context type, so this crate defines its own (deviation).

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use futures::future::BoxFuture;
use rand::Rng as _;

use murmur_component_tls::utls::Config as UtlsConfig;
use murmur_std_compat::net::Conn as NetConn;

use super::enrollment::DialCtx;

#[derive(Clone, Default)]
pub struct ClientConfig {
    pub config: Config,

    pub server_name: String,
    pub skip_cert_verify: bool,
    pub name_cert_verify: String,
    pub alpn: Vec<String>,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
    pub client_fingerprint: String,
    pub forward_address_hint: String,
    pub ech: Option<Arc<dyn EchConfig>>,
    pub enrollment_dialer: Option<EnrollmentDialer>,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The certificate and private key are credentials, and the ECH/dialer hooks are opaque.
        f.debug_struct("ClientConfig")
            .field("config", &self.config)
            .field("server_name", &self.server_name)
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("name_cert_verify", &self.name_cert_verify)
            .field("alpn", &self.alpn)
            .field("fingerprint", &self.fingerprint)
            .field("client_fingerprint", &self.client_fingerprint)
            .field("forward_address_hint", &self.forward_address_hint)
            .finish_non_exhaustive()
    }
}

pub type ServerConfig = Config;

/// The recommended TLS 1.2 cipher suite list for
/// explicit nonce carriers.
pub static RECOMMENDED_EXPLICIT_NONCE_CIPHER_SUITES: &[u16] = &[
    156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 49195, 49196, 49197,
    49198, 49199, 49200, 49201, 49202, 49290, 49291, 49293, 49316, 49317, 49318, 49319, 49320, 49321, 49322, 49323,
    49324, 49325, 49326, 49327, 52392, 52393, 52394, 52395, 52396, 52397, 52398,
];

#[derive(Clone, Default)]
pub struct Config {
    pub primary_key: String,
    pub explicit_nonce_cipher_suites: Vec<u16>,
    pub defer_instance_derived_write: TimeSpec,
    pub transport_layer_padding: TransportLayerPadding,
    pub connection_enrolment: Option<ConnectionEnrolment>,
    pub sequence_watermarking_enabled: bool,
    pub embedded_traffic_generator: Option<TrafficGenerator>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `primary_key` is the shared secret, so it is never printed.
        f.debug_struct("Config")
            .field("explicit_nonce_cipher_suites", &self.explicit_nonce_cipher_suites)
            .field("defer_instance_derived_write", &self.defer_instance_derived_write)
            .field("transport_layer_padding", &self.transport_layer_padding)
            .field("connection_enrolment", &self.connection_enrolment)
            .field("sequence_watermarking_enabled", &self.sequence_watermarking_enabled)
            .field("embedded_traffic_generator", &self.embedded_traffic_generator)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Debug)]
pub struct ConnectionEnrolment {
    pub primary_ingress_outbound: String,
    pub primary_egress_outbound: String,
}

pub type EnrollmentDialer =
    Arc<dyn Fn(DialCtx, &'static str, String) -> BoxFuture<'static, Result<Box<dyn NetConn>>> + Send + Sync>;

/// `ECHConfig`. The `*tls.Config` and `*tlsC.Config` are two distinct fork types;
///
/// This build mirrors both with the single `component::tls::utls::Config` (deviation, see the wave
/// report), so both methods take the same config type.
#[async_trait]
pub trait EchConfig: Send + Sync {
    async fn client_handle(&self, ctx: &DialCtx, config: &mut UtlsConfig) -> Result<()>;
    async fn client_handle_utls(&self, ctx: &DialCtx, config: &mut UtlsConfig) -> Result<()>;
}

#[derive(Clone, Default, Debug)]
pub struct TrafficGenerator {
    pub steps: Vec<TrafficStep>,
}

#[derive(Clone, Default, Debug)]
pub struct TrafficStep {
    pub name: String,
    pub host: String,
    pub path: String,
    pub method: String,
    pub headers: Vec<TrafficHeader>,
    pub next_step: Vec<TrafficTransferCandidate>,
    pub connection_ready: bool,
    pub connection_recall_exit: bool,
    pub wait_time: TimeSpec,
    pub h2_do_not_wait_for_download_finish: bool,
}

#[derive(Clone, Default, Debug)]
pub struct TrafficHeader {
    pub name: String,
    pub value: String,
    pub values: Vec<String>,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct TrafficTransferCandidate {
    pub weight: i32,
    pub goto_location: usize,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct TimeSpec {
    pub base_nanoseconds: u64,
    pub uniform_random_multiplier_nanoseconds: u64,
}

impl TimeSpec {
    pub fn duration(&self) -> Result<std::time::Duration> {
        let mut delay = self.base_nanoseconds;
        if self.uniform_random_multiplier_nanoseconds > 0 {
            let n = rand::rng().random_range(0..self.uniform_random_multiplier_nanoseconds);
            delay = delay.saturating_add(n);
        }
        Ok(std::time::Duration::from_nanos(delay))
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct TransportLayerPadding {
    pub enabled: bool,
}

#[must_use]
pub fn generate_primary_key() -> String {
    let mut key = [0u8; 32];
    rand::rng().fill(&mut key);
    STANDARD.encode(key)
}

pub fn decode_primary_key(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Err(anyhow::anyhow!("missing tlsmirror primary key"));
    }
    if let Ok(key) = STANDARD.decode(value) {
        if key.len() == 32 {
            return Ok(key);
        }
    }
    Err(anyhow::anyhow!("tlsmirror primary key must be standard base64 and decode to 32 bytes"))
}

use serde::{Deserialize, Serialize};

use murmur_transport_tlsmirror::config as tlsmirror;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TLSMirrorOptions {
    #[serde(rename = "primary-key", default)]
    pub primary_key: String,
    #[serde(rename = "explicit-nonce-ciphersuites", default)]
    pub explicit_nonce_cipher_suites: Vec<u16>,
    #[serde(rename = "defer-instance-derived-write-time", default)]
    pub defer_instance_derived_write_time: TLSMirrorTimeSpec,
    #[serde(rename = "transport-layer-padding", default)]
    pub transport_layer_padding: TLSMirrorTransportLayerPadding,
    #[serde(rename = "connection-enrolment", default)]
    pub connection_enrolment: Option<TLSMirrorConnectionEnrolment>,
    #[serde(rename = "embedded-traffic-generator", default)]
    pub embedded_traffic_generator: TLSMirrorTrafficGenerator,
    #[serde(rename = "sequence-watermarking-enabled", default)]
    pub sequence_watermarking_enabled: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TLSMirrorConnectionEnrolment {
    #[serde(rename = "primary-ingress-outbound", default)]
    pub primary_ingress_outbound: String,
    #[serde(rename = "primary-egress-outbound", default)]
    pub primary_egress_outbound: String,
}

impl TLSMirrorConnectionEnrolment {
    #[must_use]
    pub fn build(&self) -> tlsmirror::ConnectionEnrolment {
        tlsmirror::ConnectionEnrolment {
            primary_ingress_outbound: self.primary_ingress_outbound.clone(),
            primary_egress_outbound: self.primary_egress_outbound.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct TLSMirrorTimeSpec {
    #[serde(rename = "base-nanoseconds", default)]
    pub base_nanoseconds: u64,
    #[serde(rename = "uniform-random-multiplier-nanoseconds", default)]
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

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct TLSMirrorTransportLayerPadding {
    #[serde(rename = "enabled", default)]
    pub enabled: bool,
}

impl TLSMirrorTransportLayerPadding {
    #[must_use]
    pub const fn build(&self) -> tlsmirror::TransportLayerPadding {
        tlsmirror::TransportLayerPadding { enabled: self.enabled }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TLSMirrorTrafficGenerator {
    #[serde(rename = "steps", default)]
    pub steps: Vec<TLSMirrorTrafficStep>,
}

impl TLSMirrorTrafficGenerator {
    pub fn build(&self) -> Option<tlsmirror::TrafficGenerator> {
        if self.steps.is_empty() {
            return None;
        }
        let steps = self.steps.iter().map(TLSMirrorTrafficStep::build).collect();
        Some(tlsmirror::TrafficGenerator { steps })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TLSMirrorTrafficStep {
    #[serde(rename = "name", default)]
    pub name: String,
    #[serde(rename = "host", default)]
    pub host: String,
    #[serde(rename = "path", default)]
    pub path: String,
    #[serde(rename = "method", default)]
    pub method: String,
    #[serde(rename = "headers", default)]
    pub headers: Vec<TLSMirrorTrafficHeader>,
    #[serde(rename = "next-step", default)]
    pub next_step: Vec<TLSMirrorTrafficTransferCandidate>,
    #[serde(rename = "connection-ready", default)]
    pub connection_ready: bool,
    #[serde(rename = "connection-recall-exit", default)]
    pub connection_recall_exit: bool,
    #[serde(rename = "wait-time", default)]
    pub wait_time: TLSMirrorTimeSpec,
    #[serde(rename = "h2-do-not-wait-for-download-finish", default)]
    pub h2_do_not_wait_for_download_finish: bool,
}

impl TLSMirrorTrafficStep {
    pub fn build(&self) -> tlsmirror::TrafficStep {
        let headers = self.headers.iter().map(TLSMirrorTrafficHeader::build).collect();
        let next_step = self.next_step.iter().map(TLSMirrorTrafficTransferCandidate::build).collect();
        tlsmirror::TrafficStep {
            name: self.name.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            method: self.method.clone(),
            headers,
            next_step,
            connection_ready: self.connection_ready,
            connection_recall_exit: self.connection_recall_exit,
            wait_time: self.wait_time.build(),
            h2_do_not_wait_for_download_finish: self.h2_do_not_wait_for_download_finish,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TLSMirrorTrafficHeader {
    #[serde(rename = "name", default)]
    pub name: String,
    #[serde(rename = "value", default)]
    pub value: String,
    #[serde(rename = "values", default)]
    pub values: Vec<String>,
}

impl TLSMirrorTrafficHeader {
    #[must_use]
    pub fn build(&self) -> tlsmirror::TrafficHeader {
        tlsmirror::TrafficHeader { name: self.name.clone(), value: self.value.clone(), values: self.values.clone() }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct TLSMirrorTrafficTransferCandidate {
    #[serde(rename = "weight", default)]
    pub weight: i32,
    #[serde(rename = "goto-location", default)]
    pub goto_location: i32,
}

impl TLSMirrorTrafficTransferCandidate {
    #[must_use]
    #[expect(
        clippy::cast_sign_loss,
        reason = "goto_location is the protocol's 32-bit transfer target index, stored signed only \
                  because the wire field is; the cast preserves its bit pattern"
    )]
    pub const fn build(&self) -> tlsmirror::TrafficTransferCandidate {
        tlsmirror::TrafficTransferCandidate { weight: self.weight, goto_location: self.goto_location as usize }
    }
}

impl TLSMirrorOptions {
    pub fn build(&self) -> Option<tlsmirror::Config> {
        if self.primary_key.is_empty() {
            return None;
        }
        Some(tlsmirror::Config {
            primary_key: self.primary_key.clone(),
            explicit_nonce_cipher_suites: self.explicit_nonce_cipher_suites.clone(),
            defer_instance_derived_write: self.defer_instance_derived_write_time.build(),
            transport_layer_padding: self.transport_layer_padding.build(),
            connection_enrolment: self.connection_enrolment.as_ref().map(TLSMirrorConnectionEnrolment::build),
            sequence_watermarking_enabled: self.sequence_watermarking_enabled,
            embedded_traffic_generator: self.embedded_traffic_generator.build(),
        })
    }
}

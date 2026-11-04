use murmur_listener_config::vmess as lc_vmess;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TLSMirrorConfig {
    pub primary_key: String,
    pub dest: String,
    pub proxy: String,
    pub explicit_nonce_cipher_suites: Vec<u16>,
    pub defer_instance_derived_write_time: TLSMirrorTimeSpec,
    pub transport_layer_padding: TLSMirrorTransportLayerPadding,
    pub connection_enrolment: Option<TLSMirrorConnectionEnrolment>,
    pub sequence_watermarking_enabled: bool,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TLSMirrorConnectionEnrolment {
    pub primary_ingress_outbound: String,
    pub primary_egress_outbound: String,
}

impl TLSMirrorConnectionEnrolment {
    #[must_use]
    pub fn build(this: Option<&Self>) -> Option<lc_vmess::TLSMirrorConnectionEnrolment> {
        let e = this?;
        Some(lc_vmess::TLSMirrorConnectionEnrolment {
            primary_ingress_outbound: e.primary_ingress_outbound.clone(),
            primary_egress_outbound: e.primary_egress_outbound.clone(),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct TLSMirrorTimeSpec {
    pub base_nanoseconds: u64,
    pub uniform_random_multiplier_nanoseconds: u64,
}

impl TLSMirrorTimeSpec {
    #[must_use]
    pub const fn build(&self) -> lc_vmess::TLSMirrorTimeSpec {
        lc_vmess::TLSMirrorTimeSpec {
            base_nanoseconds: self.base_nanoseconds,
            uniform_random_multiplier_nanoseconds: self.uniform_random_multiplier_nanoseconds,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct TLSMirrorTransportLayerPadding {
    pub enabled: bool,
}

impl TLSMirrorTransportLayerPadding {
    #[must_use]
    pub const fn build(&self) -> lc_vmess::TLSMirrorTransportLayerPadding {
        lc_vmess::TLSMirrorTransportLayerPadding { enabled: self.enabled }
    }
}

impl TLSMirrorConfig {
    #[must_use]
    pub fn build(&self) -> lc_vmess::TLSMirrorConfig {
        lc_vmess::TLSMirrorConfig {
            primary_key: self.primary_key.clone(),
            dest: self.dest.clone(),
            proxy: self.proxy.clone(),
            explicit_nonce_cipher_suites: self.explicit_nonce_cipher_suites.clone(),
            defer_instance_derived_write_time: self.defer_instance_derived_write_time.build(),
            transport_layer_padding: self.transport_layer_padding.build(),
            connection_enrolment: TLSMirrorConnectionEnrolment::build(self.connection_enrolment.as_ref()),
            sequence_watermarking_enabled: self.sequence_watermarking_enabled,
        }
    }
}

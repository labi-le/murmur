//! Restls client and server configuration and the helpers that build them.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use rustls::RootCertStore;

use murmur_component_tls::utls::X509Certificate;
use murmur_ntp as ntp;

use crate::framing::derive_restls_secret;
use crate::script::{parse_record_script, Line, DEFAULT_RESTLS_SCRIPT};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionHint {
    Tls13,
    Tls12,
}

pub fn parse_version_hint(s: &str) -> Result<VersionHint> {
    match s.to_ascii_lowercase().as_str() {
        "tls13" => Ok(VersionHint::Tls13),
        "tls12" => Ok(VersionHint::Tls12),
        other => Err(anyhow!("invalid version hint: should be either tls12 or tls13, got {other:?}")),
    }
}

#[derive(Clone)]
pub struct Config {
    pub server_name: String,
    pub restls_secret: [u8; 32],
    pub version_hint: VersionHint,
    pub restls_script: Vec<Line>,
    /// Advertised in the ClientHello ALPN extension. The VMess/Trojan front-ends copy their
    /// `alpn` list straight onto the Restls config.
    pub next_protos: Vec<String>,
    /// Without it `set_name_cert_verify` falls back to the bare system roots and rejects a
    /// certificate signed only by a custom trust anchor.
    pub root_cas: Option<Arc<RootCertStore>>,
    pub insecure_skip_verify: bool,
    /// Overrides the default chain-trust check. Takes the full peer chain, leaf first.
    pub verify_connection: Option<Arc<dyn Fn(&[Arc<X509Certificate>]) -> Result<()> + Send + Sync>>,
    /// Whether session tickets are disabled. True unless `version_hint` is `Tls12`.
    pub session_tickets_disabled: bool,
}

impl core::fmt::Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("server_name", &self.server_name)
            .field("restls_secret", &"[redacted]")
            .field("version_hint", &self.version_hint)
            .field("restls_script", &self.restls_script)
            .field("next_protos", &self.next_protos)
            .field("root_cas", &self.root_cas)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("session_tickets_disabled", &self.session_tickets_disabled)
            .finish_non_exhaustive()
    }
}

pub fn new_restls_config(
    server_name: &str,
    password: &str,
    version_hint_str: &str,
    restls_script: &str,
) -> Result<Config> {
    let version_hint = parse_version_hint(version_hint_str)?;
    let restls_secret = derive_restls_secret(password.as_bytes());
    let script = if restls_script.is_empty() { DEFAULT_RESTLS_SCRIPT } else { restls_script };
    let parsed_script = parse_record_script(script)?;
    Ok(Config {
        server_name: server_name.to_owned(),
        restls_secret,
        version_hint,
        restls_script: parsed_script,
        next_protos: Vec::new(),
        root_cas: Some(murmur_component_ca::config::get_cert_pool()),
        insecure_skip_verify: false,
        verify_connection: None,
        session_tickets_disabled: version_hint != VersionHint::Tls12,
    })
}

pub fn set_fingerprint(config: &mut Config, fingerprint: &str, name_cert_verify: &str) -> Result<()> {
    let verifier =
        murmur_component_ca::fingerprint::new_fingerprint_verifier(fingerprint, Some(Arc::new(ntp::time::now)))?;
    let server_name = config.server_name.clone();
    let name_cert_verify = name_cert_verify.to_owned();
    config.insecure_skip_verify = true;
    config.verify_connection = Some(Arc::new(move |chain: &[Arc<X509Certificate>]| {
        let name = if name_cert_verify.is_empty() { server_name.clone() } else { name_cert_verify.clone() };
        verifier(chain, &name)
    }));
    Ok(())
}

pub fn set_name_cert_verify(config: &mut Config, dns_name: &str) {
    let verifier = murmur_component_ca::name_cert_verify::new_name_cert_verifier(
        dns_name,
        config.root_cas.clone(),
        Some(Arc::new(ntp::time::now)),
    );
    config.insecure_skip_verify = true;
    config.verify_connection = Some(Arc::new(move |chain: &[Arc<X509Certificate>]| verifier(chain)));
}

/// `dial` is supplied by the listener wiring (the tunnel routes the dial back through its own
/// dialer), so this crate stays transport-agnostic instead of opening raw TCP sockets itself.
#[derive(Clone)]
pub struct ServerConfig {
    pub server_hostname: String,
    pub password: String,
    pub restls_script: String,
    pub min_record_len: i32,
    pub rate_limit: u64,
    pub dial: crate::server::DialFn,
}

impl core::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("server_hostname", &self.server_hostname)
            .field("password", &"[redacted]")
            .field("restls_script", &self.restls_script)
            .field("min_record_len", &self.min_record_len)
            .field("rate_limit", &self.rate_limit)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use murmur_component_ca::config as ca_config;
    use murmur_component_ca::keypair::{new_random_tls_key_pair, x509_key_pair, KeyPairType};

    use super::*;

    #[test]
    fn name_cert_verify_trusts_custom_trust_certificates() {
        let (certificate_pem, private_key_pem, _) =
            new_random_tls_key_pair(KeyPairType::KEY_PAIR_TYPE_P256).expect("self-signed certificate");
        let leaf = x509_key_pair(certificate_pem.as_bytes(), private_key_pem.as_bytes())
            .expect("key pair")
            .leaf
            .expect("leaf certificate");

        ca_config::reset_certificate();
        ca_config::add_certificate(&certificate_pem).expect("add custom trust certificate");
        let mut config = new_restls_config("example.com", "password", "tls13", "").expect("Restls config");
        set_name_cert_verify(&mut config, "");
        let verified =
            config.verify_connection.as_ref().expect("SetNameCertVerify installs VerifyConnection")(&[leaf]).is_ok();
        ca_config::reset_certificate();

        assert!(verified, "tls.custom-trust-cert was ignored by the Restls name certificate verifier");
    }
}

//! Generates a P-256 key pair and its certificate: JLS
//! authenticates the peer itself, so the generated certificate only has to
//! carry the TLS handshake.

use anyhow::{anyhow, Result};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;

use murmur_component_ca::keypair::{new_random_tls_key_pair, KeyPairType};

pub struct SelfSignedCert {
    pub cert_der: Vec<u8>,
    pub key: SigningKey,
}

impl core::fmt::Debug for SelfSignedCert {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SelfSignedCert")
            .field("cert_der", &self.cert_der)
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

pub fn new_self_signed_cert() -> Result<SelfSignedCert> {
    let (certificate_pem, private_key_pem, _fingerprint) =
        new_random_tls_key_pair(KeyPairType::P256).map_err(|err| anyhow!("jls: generate TLS certificate: {err}"))?;
    let cert_der =
        pem_to_der(&certificate_pem, "CERTIFICATE").map_err(|err| anyhow!("jls: parse TLS certificate: {err}"))?;
    let key = SigningKey::from_pkcs8_der(&pem_to_der(&private_key_pem, "PRIVATE KEY")?)
        .map_err(|err| anyhow!("jls: parse TLS private key: {err}"))?;
    Ok(SelfSignedCert { cert_der, key })
}

fn pem_to_der(pem: &str, label: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;

    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = pem
        .strip_prefix(&begin)
        .and_then(|rest| rest.strip_suffix(&format!("\n{end}\n")))
        .ok_or_else(|| anyhow!("no {label} block in PEM"))?;
    // PEM bodies wrap at 64 columns, so the body still has its
    // line breaks in it.
    let unwrapped: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(unwrapped.as_bytes())
        .map_err(|err| anyhow!("base64 in {label} PEM: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use p256::pkcs8::EncodePrivateKey as _;

    #[test]
    fn generated_p256_key_pair_round_trips_through_pkcs8() {
        let cert = new_self_signed_cert().expect("generate a self-signed cert");
        assert!(!cert.cert_der.is_empty());
        let der = cert.key.to_pkcs8_der().expect("encode");
        let parsed = SigningKey::from_pkcs8_der(der.as_bytes()).expect("re-decode");
        assert_eq!(parsed.to_bytes(), cert.key.to_bytes());
    }

    #[test]
    fn pem_without_the_expected_block_is_rejected() {
        assert!(pem_to_der("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "PRIVATE KEY").is_err());
    }
}

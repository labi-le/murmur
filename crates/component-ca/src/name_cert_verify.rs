use std::sync::Arc;

use anyhow::{anyhow, Result};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;

use murmur_component_tls::utls::{TimeFn, X509Certificate};

use super::config::{
    current_time_of, server_name_of, signature_verification_algorithms, system_root_store, unix_time_of,
};

pub type NameCertVerifier = Arc<dyn Fn(&[Arc<X509Certificate>]) -> Result<()> + Send + Sync>;

/// Builds a verifier tied to `dns_name`. A `None` root pool falls back to the system roots.
#[must_use]
pub fn new_name_cert_verifier(
    dns_name: &str,
    roots: Option<Arc<RootCertStore>>,
    now: Option<TimeFn>,
) -> NameCertVerifier {
    let dns_name = dns_name.to_owned();
    Arc::new(move |certificates: &[Arc<X509Certificate>]| {
        let Some(leaf) = certificates.first() else {
            return Err(anyhow!("tls: no peer certificates"));
        };

        let roots = match &roots {
            Some(roots) => Arc::clone(roots),
            None => Arc::new(system_root_store()),
        };
        let intermediates: Vec<CertificateDer<'static>> = certificates
            .get(1..)
            .unwrap_or_default()
            .iter()
            .map(|certificate| CertificateDer::from(certificate.raw.clone()))
            .collect();
        let end_entity = CertificateDer::from(leaf.raw.clone());
        let parsed = rustls::server::ParsedCertificate::try_from(&end_entity)
            .map_err(|err| anyhow!("x509: cannot parse certificate: {err}"))?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &roots,
            &intermediates,
            unix_time_of(current_time_of(now.as_ref())),
            signature_verification_algorithms().all,
        )?;
        if !dns_name.is_empty() {
            rustls::client::verify_server_name(&parsed, &server_name_of(&dns_name)?)?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{DateTime, Utc};
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;

    use super::*;
    use crate::fingerprint::tests::{
        cert_time, certificate, GOOGLE_LEAF, GOOGLE_LEAF_WITH_INVALID_HASH, GTS_INTERMEDIATE, GTS_ROOT,
        LEAF_SERVER_NAME, SMIME_ROOT, WRONG_LEAF_SERVER_NAME,
    };

    fn roots_of(certs: &[&Arc<X509Certificate>]) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        for cert in certs {
            roots.add(CertificateDer::from(cert.raw.clone())).expect("trust anchor");
        }
        Arc::new(roots)
    }

    /// The expired case's clock: one second past the fixture leaf's `notAfter`.
    fn expired_cert_time() -> TimeFn {
        Arc::new(|| DateTime::<Utc>::from_timestamp(1679905159, 0).expect("valid timestamp"))
    }

    #[test]
    fn name_cert_verifier() {
        let leaf = certificate(GOOGLE_LEAF);
        let intermediate = certificate(GTS_INTERMEDIATE);
        let root = certificate(GTS_ROOT);
        let leaf_with_invalid_hash = certificate(GOOGLE_LEAF_WITH_INVALID_HASH);
        let smime_root = certificate(SMIME_ROOT);
        let roots = roots_of(&[&root]);
        let untrusted_roots = roots_of(&[&smime_root]);

        let cases: Vec<(&str, &str, Option<Arc<RootCertStore>>, Option<TimeFn>, Vec<Arc<X509Certificate>>, bool)> = vec![
            (
                "valid chain",
                LEAF_SERVER_NAME,
                Some(Arc::clone(&roots)),
                Some(cert_time()),
                vec![Arc::clone(&leaf), Arc::clone(&intermediate)],
                false,
            ),
            (
                "valid chain with root",
                LEAF_SERVER_NAME,
                Some(Arc::clone(&roots)),
                Some(cert_time()),
                vec![Arc::clone(&leaf), Arc::clone(&intermediate), root],
                false,
            ),
            (
                "wrong DNS name",
                WRONG_LEAF_SERVER_NAME,
                Some(Arc::clone(&roots)),
                Some(cert_time()),
                vec![Arc::clone(&leaf), Arc::clone(&intermediate)],
                true,
            ),
            ("no certificates", LEAF_SERVER_NAME, Some(Arc::clone(&roots)), Some(cert_time()), Vec::new(), true),
            (
                "missing intermediate",
                LEAF_SERVER_NAME,
                Some(Arc::clone(&roots)),
                Some(cert_time()),
                vec![Arc::clone(&leaf)],
                true,
            ),
            (
                "untrusted root",
                LEAF_SERVER_NAME,
                Some(untrusted_roots),
                Some(cert_time()),
                vec![Arc::clone(&leaf), Arc::clone(&intermediate)],
                true,
            ),
            (
                "expired certificate",
                LEAF_SERVER_NAME,
                Some(Arc::clone(&roots)),
                Some(expired_cert_time()),
                vec![leaf, Arc::clone(&intermediate)],
                true,
            ),
            (
                "invalid certificate signature",
                LEAF_SERVER_NAME,
                Some(roots),
                Some(cert_time()),
                vec![leaf_with_invalid_hash, intermediate],
                true,
            ),
        ];

        for (name, dns_name, roots, now, certificates, want_err) in cases {
            let verifier = new_name_cert_verifier(dns_name, roots, now);
            assert_eq!(want_err, verifier(&certificates).is_err(), "{name}");
        }
    }
}

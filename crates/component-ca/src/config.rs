use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::RootCertStore;

use murmur_common::once::oncefunc::once_value;
use murmur_component_tls::utls::{CertificateRequestInfo, Config, ConnectionState, TimeFn};
use murmur_ntp as ntp;

use super::fingerprint::new_fingerprint_verifier;
use super::keypair::new_tls_key_pair_loader;
use super::name_cert_verify::new_name_cert_verifier;

/// The embedded CA bundle. This bundle is empty in this tree, so the non-empty guards keep their
/// false branch (see `build_cert_pool` and `zero_trust_cert_pool` below). To embed a real bundle,
/// replace `ca-certificates.crt` in this directory with the PEM data; no code change is required.
pub(crate) static CA_CERTIFICATES: &[u8] = include_bytes!("ca-certificates.crt");

/// The process-wide certificate pool, guarded by a lock. A mutable in-place pool cannot be shared
/// as `Arc<RootCertStore>`, so a mutation replaces the arc: pools handed out before the mutation
/// keep the certificates they were built with.
static GLOBAL_CERT_POOL: LazyLock<RwLock<std::option::Option<Arc<RootCertStore>>>> =
    LazyLock::new(|| RwLock::new(None));

pub static DISABLE_EMBED_CA: LazyLock<bool> = LazyLock::new(|| env_flag("DISABLE_EMBED_CA"));

static DISABLE_SYSTEM_CA: LazyLock<bool> = LazyLock::new(|| env_flag("DISABLE_SYSTEM_CA"));
static SYSTEM_CA_DISABLED_BY_FIX: AtomicBool = AtomicBool::new(false);

/// Parses a boolean the way the environment flag expects; an unparsable value is `false`.
fn parse_bool(s: &str) -> bool {
    matches!(s, "1" | "t" | "T" | "TRUE" | "true" | "True")
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| parse_bool(&value))
}

/// Whether the system CA store is disabled, which `fix_windows`'s init may turn on.
pub fn disable_system_ca() -> bool {
    *DISABLE_SYSTEM_CA || SYSTEM_CA_DISABLED_BY_FIX.load(Ordering::SeqCst)
}

pub(crate) fn set_disable_system_ca() {
    SYSTEM_CA_DISABLED_BY_FIX.store(true, Ordering::SeqCst);
}

pub fn add_certificate(certificate: &str) -> Result<()> {
    if certificate.is_empty() {
        return Err(anyhow!("certificate is empty"));
    }

    let mut pool = clone_root_store(&get_cert_pool());
    if append_certs_from_pem(&mut pool, certificate.as_bytes()) {
        *GLOBAL_CERT_POOL.write() = Some(Arc::new(pool));
        return Ok(());
    }
    match parse_certificate(certificate.as_bytes()) {
        Some(cert) => {
            pool.add(cert).map_err(|err| anyhow!("add certificate failed: {err}"))?;
            *GLOBAL_CERT_POOL.write() = Some(Arc::new(pool));
            Ok(())
        }
        None => Err(anyhow!("add certificate failed")),
    }
}

pub(crate) fn initialize_cert_pool() {
    *GLOBAL_CERT_POOL.write() = Some(build_cert_pool());
}

fn build_cert_pool() -> Arc<RootCertStore> {
    super::fix_windows::init();
    let mut pool = if disable_system_ca() { RootCertStore::empty() } else { system_root_store() };
    if !*DISABLE_EMBED_CA {
        append_certs_from_pem(&mut pool, CA_CERTIFICATES);
    }
    Arc::new(pool)
}

pub fn reset_certificate() {
    initialize_cert_pool();
}

pub fn get_cert_pool() -> Arc<RootCertStore> {
    let mut guard = GLOBAL_CERT_POOL.write();
    if let Some(pool) = guard.as_ref() {
        return Arc::clone(pool);
    }
    let pool = build_cert_pool();
    *guard = Some(Arc::clone(&pool));
    pool
}

#[derive(Clone, Debug, Default)]
pub struct Option {
    pub tls_config: std::option::Option<Config>,
    pub fingerprint: String,
    pub name_cert_verify: String,
    pub zero_trust: bool,
    pub certificate: String,
    pub private_key: String,
}

/// The caller's config is cloned rather than mutated in place.
#[expect(
    clippy::needless_pass_by_value,
    reason = "public config entry point: callers hand over an owned `Option`, and widening the signature to a reference would change the public API"
)]
pub fn get_tls_config(opt: Option) -> Result<Config> {
    let mut tls_config = opt.tls_config.clone().unwrap_or_default();
    tls_config.time = Some(Arc::new(ntp::time::now));

    tls_config.root_cas = if opt.zero_trust { zero_trust_cert_pool() } else { Some(get_cert_pool()) };

    if !opt.fingerprint.is_empty() {
        let verifier = new_fingerprint_verifier(&opt.fingerprint, tls_config.time.clone())?;
        let name_cert_verify = opt.name_cert_verify.clone();
        tls_config.verify_connection = Some(Arc::new(move |state: &ConnectionState| {
            let mut server_name = state.server_name.clone();
            if !name_cert_verify.is_empty() {
                server_name.clone_from(&name_cert_verify);
            }
            verifier(&state.peer_certificates, &server_name)
        }));
        tls_config.insecure_skip_verify = true;
    } else if !opt.name_cert_verify.is_empty() {
        let verifier =
            new_name_cert_verifier(&opt.name_cert_verify, tls_config.root_cas.clone(), tls_config.time.clone());
        tls_config.verify_connection =
            Some(Arc::new(move |state: &ConnectionState| verifier(&state.peer_certificates)));
        tls_config.insecure_skip_verify = true;
    }

    if !opt.certificate.is_empty() || !opt.private_key.is_empty() {
        let cert_loader = new_tls_key_pair_loader(&opt.certificate, &opt.private_key)?;
        tls_config.get_client_certificate =
            Some(Arc::new(move |_info: &CertificateRequestInfo| cert_loader().map(Some)));
    }
    Ok(tls_config)
}

static ZERO_TRUST_CERT_POOL: LazyLock<Box<dyn Fn() -> std::option::Option<Arc<RootCertStore>> + Send + Sync>> =
    LazyLock::new(|| {
        Box::new(once_value(|| {
            if !CA_CERTIFICATES.is_empty() {
                let mut pool = RootCertStore::empty();
                if append_certs_from_pem(&mut pool, CA_CERTIFICATES) {
                    return Some(Arc::new(pool));
                }
            }
            None
        }))
    });

fn zero_trust_cert_pool() -> std::option::Option<Arc<RootCertStore>> {
    ZERO_TRUST_CERT_POOL()
}

/// Adds every certificate block in `pem` to `pool`, returning true when at least one was added.
pub(crate) fn append_certs_from_pem(pool: &mut RootCertStore, pem: &[u8]) -> bool {
    let mut ok = false;
    for (label, der, has_headers) in pem_sections(pem) {
        if label != "CERTIFICATE" || has_headers {
            continue;
        }
        if pool.add(CertificateDer::from(der)).is_ok() {
            ok = true;
        }
    }
    ok
}

/// The PEM blocks in `input`, each as a label, its DER bytes, and whether it carried headers.
#[must_use]
pub fn pem_sections(input: &[u8]) -> Vec<(String, Vec<u8>, bool)> {
    use base64::Engine as _;

    let text = String::from_utf8_lossy(input);
    let mut sections = Vec::new();
    let mut label: std::option::Option<String> = None;
    let mut body = String::new();
    let mut has_headers = false;
    let mut in_headers = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            if let Some(rest) = rest.strip_suffix("-----") {
                label = Some(rest.to_owned());
                body.clear();
                has_headers = false;
                in_headers = true;
                continue;
            }
        }
        if line.starts_with("-----END ") {
            if let Some(label) = label.take() {
                if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(body.as_bytes()) {
                    sections.push((label, der, has_headers));
                }
            }
            body.clear();
            in_headers = false;
            continue;
        }
        if label.is_none() {
            continue;
        }
        if in_headers {
            if line.is_empty() {
                in_headers = false;
            } else if line.contains(':') {
                has_headers = true;
                continue;
            } else {
                in_headers = false;
            }
        }
        body.push_str(line);
    }
    sections
}

pub(crate) fn parse_certificate(der: &[u8]) -> std::option::Option<CertificateDer<'static>> {
    let cert = CertificateDer::from(der.to_vec());
    rustls::server::ParsedCertificate::try_from(&cert).ok()?;
    Some(cert)
}

/// The certificates from the system CA store.
pub(crate) fn system_root_store() -> RootCertStore {
    let mut store = RootCertStore::empty();
    let result = rustls_native_certs::load_native_certs();
    store.add_parsable_certificates(result.certs);
    store
}

pub(crate) fn clone_root_store(pool: &RootCertStore) -> RootCertStore {
    RootCertStore { roots: pool.roots.clone() }
}

/// The provider rustls' verifiers were built with, shared with `component::tls::utls`.
pub(crate) fn signature_verification_algorithms() -> WebPkiSupportedAlgorithms {
    match CryptoProvider::get_default() {
        Some(provider) => provider.signature_verification_algorithms,
        None => rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
    }
}

pub(crate) fn server_name_of(name: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(name.to_owned()).map_err(|err| anyhow!("x509: invalid DNS name {name:?}: {err}"))
}

/// The instant to check the chain at; an unset time means the current time.
pub(crate) fn current_time_of(time: std::option::Option<&TimeFn>) -> DateTime<Utc> {
    match time {
        Some(time) => time(),
        None => Utc::now(),
    }
}

pub(crate) fn unix_time_of(time: DateTime<Utc>) -> UnixTime {
    let seconds = time.timestamp();
    let nanos = time.timestamp_subsec_nanos();
    if seconds <= 0 {
        return UnixTime::since_unix_epoch(Duration::ZERO);
    }
    UnixTime::since_unix_epoch(Duration::from_secs(seconds.cast_unsigned()) + Duration::from_nanos(u64::from(nanos)))
}

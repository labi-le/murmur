//! Server-certificate verification: the certificate-chain and hostname check
//! for a peer's leaf certificate.
//!
//! The other half, the skip for a JLS-authenticated peer, belongs to the
//! handshake that knows the JLS outcome: a JLS listener's certificate is
//! a freshly generated self-signed pair that chains to nothing, so that peer
//! is authenticated by the sealed `ServerHello.random` instead.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rustls::client::{verify_server_cert_signed_by_trust_anchor, verify_server_name};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::RootCertStore;

use crate::error::{Result, TlsError};

/// The time source used to check the peer's chain. `None` means the current time.
pub type TimeFn = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// Verifies the peer's chain against `roots`, the current time, `server_name` and the
/// intermediates, with the leaf taken from the peer's `Certificate` message and the rest of
/// that message as intermediates.
///
/// An empty `server_name` skips the name check.
pub(crate) fn verify_server_chain(
    chain: &[Vec<u8>],
    server_name: &str,
    roots: &RootCertStore,
    time: Option<&TimeFn>,
) -> Result<()> {
    let Some((leaf, intermediates)) = chain.split_first() else {
        return Err(TlsError::protocol("x509: server sent an empty certificate list"));
    };
    let end_entity = CertificateDer::from(leaf.as_slice());
    let parsed = ParsedCertificate::try_from(&end_entity)
        .map_err(|err| TlsError::protocol(format!("x509: cannot parse server certificate: {err}")))?;
    let intermediates: Vec<CertificateDer<'_>> =
        intermediates.iter().map(|der| CertificateDer::from(der.as_slice())).collect();
    verify_server_cert_signed_by_trust_anchor(
        &parsed,
        roots,
        &intermediates,
        unix_time_of(current_time_of(time)),
        signature_verification_algorithms().all,
    )
    .map_err(|err| TlsError::protocol(format!("x509: server certificate chain verification failed: {err}")))?;
    if !server_name.is_empty() {
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|err| TlsError::protocol(format!("x509: invalid server name {server_name:?}: {err}")))?;
        verify_server_name(&parsed, &name)
            .map_err(|err| TlsError::protocol(format!("x509: certificate not valid for {server_name:?}: {err}")))?;
    }
    Ok(())
}

fn current_time_of(time: Option<&TimeFn>) -> DateTime<Utc> {
    match time {
        Some(time) => time(),
        None => Utc::now(),
    }
}

fn unix_time_of(time: DateTime<Utc>) -> UnixTime {
    let seconds = time.timestamp();
    if seconds <= 0 {
        return UnixTime::since_unix_epoch(Duration::ZERO);
    }
    UnixTime::since_unix_epoch(
        Duration::from_secs(seconds.cast_unsigned()) + Duration::from_nanos(u64::from(time.timestamp_subsec_nanos())),
    )
}

/// The provider the rest of the tree builds its verifiers with, mirroring
/// `component/ca`'s `signature_verification_algorithms`.
fn signature_verification_algorithms() -> WebPkiSupportedAlgorithms {
    match CryptoProvider::get_default() {
        Some(provider) => provider.signature_verification_algorithms,
        None => rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
    }
}

//! RFC 8446 §4.4.3 `CertificateVerify` signature construction/verification, restricted to the
//! three schemes Restls's ClientHello advertises: `ecdsa_secp256r1_sha256`, `rsa_pss_rsae_sha256`
//! and `ed25519`.

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{Signature as EdSignature, Verifier as _, VerifyingKey as EdVerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey};
use rsa::signature::Verifier as _;
use rsa::RsaPublicKey;

use crate::consts::{SIG_ECDSA_SECP256R1_SHA256, SIG_ED25519, SIG_RSA_PSS_RSAE_SHA256};
use murmur_component_tls::utls::{CertificatePublicKeyBytes, Ed25519PublicKey};

/// The RFC 8446 §4.4.3 signed-message construction the server signs in a TLS 1.3 `CertificateVerify`.
#[must_use]
pub fn signed_message(transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64 + 33 + 1 + 32);
    msg.extend(std::iter::repeat_n(0x20u8, 64));
    msg.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    msg.push(0);
    msg.extend_from_slice(transcript_hash);
    msg
}

/// Verifies a server `CertificateVerify` signature against the leaf certificate's SPKI, as
/// parsed by `murmur_component_tls::utls::X509Certificate::parse`.
pub fn verify_certificate_verify(
    public_key: &(dyn std::any::Any + Send + Sync),
    scheme: u16,
    transcript_hash: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    let message = signed_message(transcript_hash);
    match scheme {
        SIG_ECDSA_SECP256R1_SHA256 => {
            let Some(CertificatePublicKeyBytes(raw)) = public_key.downcast_ref::<CertificatePublicKeyBytes>() else {
                bail!("restls: ecdsa_secp256r1_sha256 CertificateVerify with non-EC leaf key");
            };
            let verifying_key =
                P256VerifyingKey::from_sec1_bytes(raw).map_err(|err| anyhow!("restls: invalid P-256 SPKI: {err}"))?;
            let sig =
                P256Signature::from_der(signature).map_err(|err| anyhow!("restls: invalid ECDSA signature: {err}"))?;
            verifying_key.verify(&message, &sig).map_err(|err| anyhow!("restls: ECDSA CertificateVerify failed: {err}"))
        }
        SIG_RSA_PSS_RSAE_SHA256 => {
            let Some(CertificatePublicKeyBytes(raw)) = public_key.downcast_ref::<CertificatePublicKeyBytes>() else {
                bail!("restls: rsa_pss_rsae_sha256 CertificateVerify with non-RSA leaf key");
            };
            let rsa_key =
                RsaPublicKey::from_pkcs1_der(raw).map_err(|err| anyhow!("restls: invalid RSA SPKI: {err}"))?;
            let verifying_key = RsaPssVerifyingKey::<rsa::sha2::Sha256>::new(rsa_key);
            let sig = RsaPssSignature::try_from(signature)
                .map_err(|err| anyhow!("restls: invalid RSA-PSS signature: {err}"))?;
            verifying_key
                .verify(&message, &sig)
                .map_err(|err| anyhow!("restls: RSA-PSS CertificateVerify failed: {err}"))
        }
        SIG_ED25519 => {
            let Some(Ed25519PublicKey(raw)) = public_key.downcast_ref::<Ed25519PublicKey>() else {
                bail!("restls: ed25519 CertificateVerify with non-Ed25519 leaf key");
            };
            let verifying_key =
                EdVerifyingKey::from_bytes(raw).map_err(|err| anyhow!("restls: invalid Ed25519 SPKI: {err}"))?;
            let sig: EdSignature =
                signature.try_into().map_err(|_| anyhow!("restls: invalid Ed25519 signature length"))?;
            verifying_key
                .verify(&message, &sig)
                .map_err(|err| anyhow!("restls: Ed25519 CertificateVerify failed: {err}"))
        }
        other => bail!("restls: unsupported CertificateVerify signature scheme 0x{other:04x}"),
    }
}

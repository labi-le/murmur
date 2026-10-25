use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use notify::{RecursiveMode, Watcher};
use parking_lot::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use rustls::RootCertStore;
use sha2::{Digest, Sha256};

use murmur_component_tls::utls::{Certificate, X509Certificate};
use murmur_constant::path::PATH;

use super::config::{append_certs_from_pem, pem_sections};

/// A callback returning a certificate, matching the shape the TLS config expects.
pub type KeyPairLoader = Arc<dyn Fn() -> Result<Certificate> + Send + Sync>;

/// Builds a loader from a certificate and private key. With both arguments empty it generates a
/// random TLS RSA key pair.
pub fn new_tls_key_pair_loader(certificate: &str, private_key: &str) -> Result<KeyPairLoader> {
    let (certificate, private_key) = if certificate.is_empty() && private_key.is_empty() {
        let (certificate, private_key, _) = new_random_tls_key_pair(KeyPairType::KEY_PAIR_TYPE_RSA)?;
        (certificate, private_key)
    } else {
        (certificate.to_owned(), private_key.to_owned())
    };

    let plain_text_err = match x509_key_pair(certificate.as_bytes(), private_key.as_bytes()) {
        Ok(cert) => return Ok(Arc::new(move || Ok(cert.clone()))),
        Err(err) => err,
    };

    let certificate = PATH.resolve(&certificate);
    let private_key = PATH.resolve(&private_key);
    let cert = if !PATH.is_safe_path(&certificate) {
        Err(anyhow::Error::new(PATH.err_not_safe_path(&certificate)))
    } else if !PATH.is_safe_path(&private_key) {
        Err(anyhow::Error::new(PATH.err_not_safe_path(&private_key)))
    } else {
        load_x509_key_pair(&certificate, &private_key)
    };
    let cert = match cert {
        Ok(cert) => cert,
        Err(load_err) => {
            return Err(anyhow!(
                "parse certificate failed, maybe format error:{plain_text_err}, or path error: {load_err}"
            ));
        }
    };

    // The watcher is held in the returned closure so the watch lives exactly as long as the
    // loader does.
    let cert = Arc::new(RwLock::new(cert));
    let updated = Arc::clone(&cert);
    let watched_certificate = certificate.clone();
    let watched_private_key = private_key.clone();
    let watcher = notify::recommended_watcher(move |_event: notify::Result<notify::Event>| {
        let mut guard = updated.write();
        if let Ok(new_cert) = load_x509_key_pair(&watched_certificate, &watched_private_key) {
            *guard = new_cert;
        }
    })
    .ok()
    .and_then(|mut watcher| {
        for path in [certificate.as_str(), private_key.as_str()] {
            if watcher.watch(Path::new(path), RecursiveMode::NonRecursive).is_err() {
                return None;
            }
        }
        Some(watcher)
    });

    Ok(Arc::new(move || {
        let _keep_alive = &watcher;
        Ok(cert.read().clone())
    }))
}

fn load_x509_key_pair(cert_file: &str, key_file: &str) -> Result<Certificate> {
    let certificate_pem = std::fs::read(cert_file)?;
    let private_key_pem = std::fs::read(key_file)?;
    x509_key_pair(&certificate_pem, &private_key_pem)
}

/// The private key is not checked against the leaf's public key here; a mismatch is rejected by
/// the handshake instead.
pub fn x509_key_pair(certificate_pem: &[u8], private_key_pem: &[u8]) -> Result<Certificate> {
    let chain: Vec<CertificateDer<'static>> = pem_sections(certificate_pem)
        .into_iter()
        .filter(|(label, _, has_headers)| label == "CERTIFICATE" && !has_headers)
        .map(|(_, der, _)| CertificateDer::from(der))
        .collect();
    let Some(leaf) = chain.first() else {
        return Err(anyhow!("tls: failed to find any PEM data in certificate input"));
    };
    let Some(private_key) = pem_private_key(private_key_pem) else {
        return Err(anyhow!("tls: failed to find any PEM data in key input"));
    };
    Ok(Certificate {
        certificate: chain.iter().map(|cert| cert.as_ref().to_vec()).collect(),
        private_key: Some(private_key),
        leaf: X509Certificate::parse(leaf.as_ref()).ok().map(Arc::new),
        ..Certificate::default()
    })
}

fn pem_private_key(input: &[u8]) -> Option<PrivateKeyDer<'static>> {
    for (label, der, has_headers) in pem_sections(input) {
        if has_headers {
            continue;
        }
        match label.as_str() {
            "PRIVATE KEY" => return Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))),
            "RSA PRIVATE KEY" => return Some(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der))),
            "EC PRIVATE KEY" => return Some(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der))),
            _ => {}
        }
    }
    None
}

pub fn load_certificates(certificate: &str) -> Result<Arc<RootCertStore>> {
    let mut pool = RootCertStore::empty();
    if append_certs_from_pem(&mut pool, certificate.as_bytes()) {
        return Ok(Arc::new(pool));
    }
    let plain_text_err = format!("invalid certificate: {certificate}");

    let certificate = PATH.resolve(certificate);
    let mut load_err = None;
    if PATH.is_safe_path(&certificate) {
        match std::fs::read(&certificate) {
            Ok(cert_pem_block) => {
                if append_certs_from_pem(&mut pool, &cert_pem_block) {
                    return Ok(Arc::new(pool));
                }
            }
            Err(err) => load_err = Some(anyhow::Error::new(err)),
        }
    } else {
        load_err = Some(anyhow::Error::new(PATH.err_not_safe_path(&certificate)));
    }
    if let Some(load_err) = load_err {
        return Err(anyhow!(
            "parse certificate failed, maybe format error:{plain_text_err}, or path error: {load_err}"
        ));
    }
    Ok(Arc::new(pool))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyPairType {
    #[default]
    Rsa,
    P256,
    P384,
    Ed25519,
}

impl KeyPairType {
    pub const KEY_PAIR_TYPE_RSA: Self = Self::Rsa;
    pub const KEY_PAIR_TYPE_P256: Self = Self::P256;
    pub const KEY_PAIR_TYPE_P384: Self = Self::P384;
    pub const KEY_PAIR_TYPE_ED25519: Self = Self::Ed25519;
}

impl std::fmt::Display for KeyPairType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rsa => "rsa",
            Self::P256 => "p256",
            Self::P384 => "p384",
            Self::Ed25519 => "ed25519",
        })
    }
}

impl FromStr for KeyPairType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "rsa" => Ok(Self::Rsa),
            "p256" => Ok(Self::P256),
            "p384" => Ok(Self::P384),
            "ed25519" => Ok(Self::Ed25519),
            _ => Err(anyhow!("unknown key pair type: {s}")),
        }
    }
}

/// Generates a key pair, returning the certificate, its private key and the certificate's
/// SHA-256 fingerprint.
///
/// The P-384 arm needs a crate this build does not depend on.
pub fn new_random_tls_key_pair(key_pair_type: KeyPairType) -> Result<(String, String, String)> {
    let key = GeneratedKey::random(key_pair_type)?;
    let now = Utc::now();
    let tbs = der_sequence(&concat(&[
        der_explicit(0, &der_integer(2)),
        der_integer(1),
        key.signature_algorithm(),
        der_sequence(&[]),
        der_sequence(&concat(&[der_utc_time(now - Duration::days(365)), der_utc_time(now + Duration::days(365))])),
        der_sequence(&[]),
        key.subject_public_key_info()?,
    ]));
    let cert_der = der_sequence(&concat(&[tbs.clone(), key.signature_algorithm(), der_bit_string(&key.sign(&tbs)?)]));

    let fingerprint = super::fingerprint::calculate_fingerprint(&cert_der);
    Ok((pem_encode("CERTIFICATE", &cert_der), key.private_key_pem()?, fingerprint))
}

/// The signing key covering the key pair types this crate can generate.
enum GeneratedKey {
    P256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
    Rsa(Box<rsa::RsaPrivateKey>),
}

/// The RFC 8017 `DigestInfo` prefix that precedes the SHA-256 hash, everything up to but
/// excluding the 32 hash octets, byte by byte.
const PKCS1V15_SHA256_PREFIX: &[u8] =
    &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

impl GeneratedKey {
    fn random(key_pair_type: KeyPairType) -> Result<Self> {
        match key_pair_type {
            KeyPairType::P256 => {
                let mut seed = [0u8; 32];
                loop {
                    rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
                    if let Ok(secret_key) = p256::SecretKey::from_bytes(&seed.into()) {
                        return Ok(Self::P256(p256::ecdsa::SigningKey::from(&secret_key)));
                    }
                }
            }
            KeyPairType::Ed25519 => {
                let mut seed = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
                Ok(Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed)))
            }
            KeyPairType::Rsa => {
                let private_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
                    .map_err(|err| anyhow!("generate rsa key: {err}"))?;
                Ok(Self::Rsa(Box::new(private_key)))
            }
            KeyPairType::P384 => {
                Err(anyhow!("tls key pair type p384 needs the p384 crate, which this build does not depend on"))
            }
        }
    }

    fn spki_algorithm(&self) -> Vec<u8> {
        match self {
            Self::P256(_) => der_sequence(&concat(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_PRIME256V1)])),
            Self::Ed25519(_) => der_sequence(&concat(&[der_oid(OID_ED25519)])),
            Self::Rsa(_) => der_sequence(&concat(&[der_oid(OID_RSA_ENCRYPTION), der_null()])),
        }
    }

    fn signature_algorithm(&self) -> Vec<u8> {
        der_sequence(&match self {
            Self::P256(_) => concat(&[der_oid(OID_ECDSA_WITH_SHA256)]),
            Self::Ed25519(_) => concat(&[der_oid(OID_ED25519)]),
            Self::Rsa(_) => concat(&[der_oid(OID_SHA256_WITH_RSA_ENCRYPTION), der_null()]),
        })
    }

    fn public_key(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Self::P256(key) => key.verifying_key().to_sec1_point(false).as_ref().to_vec(),
            Self::Ed25519(key) => key.verifying_key().to_bytes().to_vec(),
            Self::Rsa(key) => {
                use rsa::pkcs1::EncodeRsaPublicKey as _;
                key.to_public_key().to_pkcs1_der()?.as_bytes().to_vec()
            }
        })
    }

    fn subject_public_key_info(&self) -> Result<Vec<u8>> {
        Ok(der_sequence(&concat(&[self.spki_algorithm(), der_bit_string(&self.public_key()?)])))
    }

    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::P256(key) => {
                use p256::ecdsa::signature::Signer as _;
                let signature: p256::ecdsa::Signature = key.sign(tbs);
                Ok(signature.to_der().as_bytes().to_vec())
            }
            Self::Ed25519(key) => {
                use ed25519_dalek::Signer as _;
                Ok(key.sign(tbs).to_bytes().to_vec())
            }
            Self::Rsa(key) => {
                let digest = Sha256::digest(tbs);
                let padding = rsa::pkcs1v15::Pkcs1v15Sign {
                    hash_len: Some(digest.len()),
                    prefix: PKCS1V15_SHA256_PREFIX.to_vec().into_boxed_slice(),
                };
                key.sign(padding, &digest).map_err(|err| anyhow!("sign with rsa key: {err}"))
            }
        }
    }

    fn private_key_pem(&self) -> Result<String> {
        match self {
            Self::P256(key) => {
                let secret = key.to_bytes();
                let ec_private_key = der_sequence(&concat(&[
                    der_integer(1),
                    der_octet_string(&secret),
                    der_explicit(0, &der_oid(OID_PRIME256V1)),
                    der_explicit(1, &der_bit_string(&self.public_key()?)),
                ]));
                let algorithm = concat(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_PRIME256V1)]);
                let pkcs8 = der_sequence(&concat(&[
                    der_integer(0),
                    der_sequence(&algorithm),
                    der_octet_string(&ec_private_key),
                ]));
                Ok(pem_encode("PRIVATE KEY", &pkcs8))
            }
            Self::Ed25519(key) => {
                let seed = key.to_bytes();
                let algorithm = der_oid(OID_ED25519);
                let key_octets = der_octet_string(&der_octet_string(&seed));
                let pkcs8 = der_sequence(&concat(&[der_integer(0), der_sequence(&algorithm), key_octets]));
                Ok(pem_encode("PRIVATE KEY", &pkcs8))
            }
            Self::Rsa(key) => {
                use rsa::pkcs8::EncodePrivateKey as _;
                let der = key.to_pkcs8_der()?;
                Ok(pem_encode("PRIVATE KEY", der.as_bytes()))
            }
        }
    }
}

pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
pub const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
pub const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_SHA256_WITH_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];

#[must_use]
pub fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flatten().copied().collect()
}

#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    reason = "DER length octets are one to three bytes wide by definition, and each arm's guard bounds the cast it truncates"
)]
pub fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(tag);
    match body.len() {
        len if len < 0x80 => out.push(len as u8),
        len if len <= 0xff => {
            out.push(0x81);
            out.push(len as u8);
        }
        len => {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
    }
    out.extend_from_slice(body);
    out
}

#[must_use]
pub fn der_sequence(body: &[u8]) -> Vec<u8> {
    der_tlv(0x30, body)
}

#[must_use]
pub fn der_oid(oid: &[u8]) -> Vec<u8> {
    der_tlv(0x06, oid)
}

fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    der_tlv(0x04, bytes)
}

#[must_use]
pub fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes.len() + 1);
    body.push(0x00);
    body.extend_from_slice(bytes);
    der_tlv(0x03, &body)
}

#[must_use]
pub fn der_integer(value: u8) -> Vec<u8> {
    der_tlv(0x02, &[value])
}

fn der_null() -> Vec<u8> {
    der_tlv(0x05, &[])
}

#[must_use]
pub fn der_explicit(tag: u8, body: &[u8]) -> Vec<u8> {
    der_tlv(0xa0 | tag, body)
}

#[must_use]
pub fn der_utc_time(time: DateTime<Utc>) -> Vec<u8> {
    der_tlv(0x17, time.format("%y%m%d%H%M%SZ").to_string().as_bytes())
}

/// Encodes DER as a PEM block with base64 wrapped at 64 characters.
#[expect(clippy::expect_used, reason = "base64 output is ASCII, so every 64-byte chunk is valid UTF-8")]
fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    use std::fmt::Write as _;

    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        let _ = writeln!(pem, "{}", std::str::from_utf8(chunk).expect("base64 is ascii"));
    }
    let _ = writeln!(pem, "-----END {label}-----");
    pem
}

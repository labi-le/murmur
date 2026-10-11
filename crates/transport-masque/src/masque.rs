//! Local mirrors of the protocol subsets this package uses.
//!
//! The connect-ip, HTTP/3 (including QUIC varints), URI-template, ECDSA and X.509 subsets are
//! mirrored in the `connectip`, `h3`, `quicvarint`, `uritemplate` and ECDSA modules below.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use http::HeaderMap;
use tokio_util::sync::CancellationToken;

pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";

pub const CONNECT_URI: &str = "https://cloudflareaccess.com";

const STATUS_OK: u16 = 200;

const CAPSULE_PROTOCOL_HEADER_VALUE: &str = "?1";

#[async_trait]
pub trait IpConn: Send + Sync {
    async fn read_packet(&mut self) -> anyhow::Result<Vec<u8>>;
    async fn write_packet(&mut self, b: &mut [u8]) -> anyhow::Result<Option<Vec<u8>>>;
    async fn close(&mut self) -> anyhow::Result<()>;
}

/// Mirror of the response fields this crate reads.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    /// The status, e.g. `200 OK`.
    pub status: String,
    pub header: HeaderMap,
}

impl HttpResponse {
    #[must_use]
    pub fn new(status_code: u16, header: HeaderMap) -> Self {
        let status = match http::StatusCode::from_u16(status_code).ok().and_then(|status| status.canonical_reason()) {
            Some(reason) => format!("{status_code} {reason}"),
            None => status_code.to_string(),
        };
        Self { status_code, status, header }
    }

    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.status_code == STATUS_OK
    }
}

#[must_use]
pub fn context_canceled() -> anyhow::Error {
    anyhow!("context canceled")
}

/// The TLS client fields this package sets. rustls takes the SNI at handshake time rather than
/// in the config, so it is carried next to it.
pub struct TlsConfig {
    pub config: rustls::ClientConfig,
    pub server_name: rustls::pki_types::ServerName<'static>,
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig").field("server_name", &self.server_name).finish_non_exhaustive()
    }
}

pub const NEXT_PROTO_H3: &[u8] = b"h3";

pub const ERR_UNSUPPORTED_ALGORITHM: &str = "x509: cannot verify signature: algorithm unimplemented";

/// No valid certificate chain could be built, which is what the pinning closure in
/// [`prepare_tls_config`] reports for a mismatched pinned key.
#[derive(Debug, Clone)]
pub struct CertificateInvalidError {
    pub detail: String,
}

impl fmt::Display for CertificateInvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "x509: no valid chains built: {}", self.detail)
    }
}

impl std::error::Error for CertificateInvalidError {}

/// An ECDSA private key kept as the DER the caller parsed, since no crate here
/// can do P-256 arithmetic.
#[derive(Debug, Clone)]
pub struct EcdsaPrivateKey {
    der: Vec<u8>,
}

impl EcdsaPrivateKey {
    ///
    /// Only the structure is validated; the curve and the point are not checked, which needs
    /// `p256`.
    pub fn parse_ec_private_key(der: &[u8]) -> anyhow::Result<Self> {
        let mut offset = 0;
        let (tag, body) =
            der_tlv(der, &mut offset).ok_or_else(|| anyhow!("x509: failed to parse EC private key: malformed DER"))?;
        if tag != DER_SEQUENCE || offset != der.len() {
            return Err(anyhow!("x509: failed to parse EC private key: malformed DER"));
        }
        let mut inner = 0;
        let (version_tag, version) =
            der_tlv(body, &mut inner).ok_or_else(|| anyhow!("x509: failed to parse EC private key: malformed DER"))?;
        if version_tag != DER_INTEGER || version != [1] {
            return Err(anyhow!("x509: failed to parse EC private key: unsupported version"));
        }
        let (key_tag, key) = der_tlv(body, &mut inner)
            .ok_or_else(|| anyhow!("x509: failed to parse EC private key: empty private key"))?;
        if key_tag != DER_OCTET_STRING || key.is_empty() {
            return Err(anyhow!("x509: failed to parse EC private key: malformed private key"));
        }
        Ok(Self { der: der.to_vec() })
    }

    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }
}

/// An ECDSA public key kept as the named curve and the encoded point, so equality is an exact
/// byte comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPublicKey {
    curve: Vec<u8>,
    point: Vec<u8>,
}

impl EcdsaPublicKey {
    pub fn parse_pkix_public_key(der: &[u8]) -> anyhow::Result<Self> {
        parse_spki(der).ok_or_else(|| anyhow!("x509: malformed public key"))
    }

    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        self == other
    }
}

const DER_SEQUENCE: u8 = 0x30;
const DER_INTEGER: u8 = 0x02;
const DER_BIT_STRING: u8 = 0x03;
const DER_OCTET_STRING: u8 = 0x04;
const DER_OBJECT_IDENTIFIER: u8 = 0x06;
/// `id-ecPublicKey`, 1.2.840.10045.2.1.
const OID_EC_PUBLIC_KEY: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// The named curves accepted here. P-224 is not accepted: no
/// crate validates that a P-224 point is on the curve (no `p224` crate is available the way
/// `p256`/`p384`/`p521` are), so a P-224 SPKI is rejected outright rather than admitted with an
/// unvalidated point — DEVIATION, tracked as a report item.
const OID_NAMED_CURVE_P256: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_NAMED_CURVE_P384: [u8; 5] = [0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_NAMED_CURVE_P521: [u8; 5] = [0x2b, 0x81, 0x04, 0x00, 0x23];

/// The uncompressed-point length for each curve: one prefix byte plus two field-element widths.
fn ec_point_len_for_curve(curve: &[u8]) -> Option<usize> {
    match curve {
        c if c == OID_NAMED_CURVE_P256 => Some(1 + 2 * 32),
        c if c == OID_NAMED_CURVE_P384 => Some(1 + 2 * 48),
        c if c == OID_NAMED_CURVE_P521 => Some(1 + 2 * 66),
        _ => None,
    }
}

/// Whether the point lies on the named curve.
fn ec_point_is_on_curve(curve: &[u8], point: &[u8]) -> bool {
    match curve {
        c if c == OID_NAMED_CURVE_P256 => p256::PublicKey::from_sec1_bytes(point).is_ok(),
        c if c == OID_NAMED_CURVE_P384 => p384::PublicKey::from_sec1_bytes(point).is_ok(),
        c if c == OID_NAMED_CURVE_P521 => p521::PublicKey::from_sec1_bytes(point).is_ok(),
        _ => false,
    }
}

/// DER encoding always writes zero unused bits, but a `BIT STRING`'s unused-bits byte may legally
/// be 1-7 on the wire as long as those trailing bits are themselves zero; the content is then
/// shifted right by that count so the returned bytes carry no padding, which is the form the
/// curve/point parsers take.
fn der_bit_string_right_align(unused_bits: u8, bytes: &[u8]) -> Vec<u8> {
    let shift = u32::from(unused_bits);
    if shift == 0 || bytes.is_empty() {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter().copied();
    let mut previous = iter.next().unwrap_or(0);
    out.push(previous >> shift);
    for byte in iter {
        out.push((previous << (8 - shift)) | (byte >> shift));
        previous = byte;
    }
    out
}

fn der_tlv<'a>(buf: &'a [u8], offset: &mut usize) -> Option<(u8, &'a [u8])> {
    let tag = *buf.get(*offset)?;
    *offset += 1;
    let first = *buf.get(*offset)?;
    *offset += 1;
    let length = if first & 0x80 == 0 {
        first as usize
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for _ in 0..count {
            length = (length << 8) | *buf.get(*offset)? as usize;
            *offset += 1;
        }
        length
    };
    let end = offset.checked_add(length)?;
    let body = buf.get(*offset..end)?;
    *offset = end;
    Some((tag, body))
}

fn parse_spki(der: &[u8]) -> Option<EcdsaPublicKey> {
    let mut offset = 0;
    let (tag, body) = der_tlv(der, &mut offset)?;
    if tag != DER_SEQUENCE || offset != der.len() {
        return None;
    }
    parse_spki_body(body)
}

fn parse_spki_body(body: &[u8]) -> Option<EcdsaPublicKey> {
    let mut inner = 0;
    let (algorithm_tag, algorithm) = der_tlv(body, &mut inner)?;
    if algorithm_tag != DER_SEQUENCE {
        return None;
    }
    let mut algorithm_offset = 0;
    let (oid_tag, oid) = der_tlv(algorithm, &mut algorithm_offset)?;
    if oid_tag != DER_OBJECT_IDENTIFIER || oid != OID_EC_PUBLIC_KEY {
        return None;
    }
    let (curve_tag, curve) = der_tlv(algorithm, &mut algorithm_offset)?;
    if curve_tag != DER_OBJECT_IDENTIFIER {
        return None;
    }
    let point_len = ec_point_len_for_curve(curve)?;
    let (key_tag, key) = der_tlv(body, &mut inner)?;
    if key_tag != DER_BIT_STRING {
        return None;
    }
    let (&unused_bits, raw) = key.split_first()?;
    if unused_bits > 7 || (raw.is_empty() && unused_bits > 0) {
        return None;
    }
    if unused_bits > 0 {
        let mask = (1u8 << unused_bits) - 1;
        if raw.last().is_some_and(|&last| last & mask != 0) {
            return None;
        }
    }
    let point = der_bit_string_right_align(unused_bits, raw);
    if point.len() != point_len || point.first() != Some(&0x04) {
        return None;
    }
    if !ec_point_is_on_curve(curve, &point) {
        return None;
    }
    Some(EcdsaPublicKey { curve: curve.to_vec(), point })
}

/// The public key for a peer certificate, taken from its `subjectPublicKeyInfo`; trailing bytes
/// after the certificate are rejected.
fn certificate_spki(cert: &[u8]) -> Option<EcdsaPublicKey> {
    let mut offset = 0;
    let (tag, body) = der_tlv(cert, &mut offset)?;
    if tag != DER_SEQUENCE || offset != cert.len() {
        return None;
    }
    let mut body_offset = 0;
    let (tbs_tag, tbs) = der_tlv(body, &mut body_offset)?;
    if tbs_tag != DER_SEQUENCE {
        return None;
    }
    let mut inner = 0;
    let (first_tag, _) = der_tlv(tbs, &mut inner)?;
    if first_tag != 0xa0 {
        inner = 0;
    }
    // serialNumber, signature, issuer, validity, subject, then subjectPublicKeyInfo.
    for _ in 0..5 {
        der_tlv(tbs, &mut inner)?;
    }
    let (spki_tag, spki) = der_tlv(tbs, &mut inner)?;
    if spki_tag != DER_SEQUENCE {
        return None;
    }
    parse_spki_body(spki)
}

fn verify_cert(cert: &[u8], peer_pub_key: &EcdsaPublicKey) -> anyhow::Result<()> {
    let Some(public_key) = certificate_spki(cert) else {
        return Err(anyhow!("{ERR_UNSUPPORTED_ALGORITHM}"));
    };
    if !public_key.equal(peer_pub_key) {
        return Err(CertificateInvalidError {
            detail: "remote endpoint has a different public key than what we trust".to_owned(),
        }
        .into());
    }
    Ok(())
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    if let Some(provider) = rustls::crypto::CryptoProvider::get_default() {
        return Arc::clone(provider);
    }
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    if let Err(installed) = rustls::crypto::CryptoProvider::install_default(provider.clone()) {
        return installed;
    }
    Arc::new(provider)
}

fn certificate_error(message: String) -> rustls::Error {
    #[derive(Debug)]
    struct Message(String);

    impl fmt::Display for Message {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for Message {}

    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(Arc::new(Message(message)))))
}

struct MasqueServerCertVerifier {
    peer_pub_key: EcdsaPublicKey,
    insecure: bool,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl fmt::Debug for MasqueServerCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueServerCertVerifier").field("insecure", &self.insecure).finish_non_exhaustive()
    }
}

impl rustls::client::danger::ServerCertVerifier for MasqueServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.insecure {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        let mut errors: Vec<String> = Vec::new();
        for cert in std::iter::once(end_entity).chain(intermediates.iter()) {
            if let Err(err) = verify_cert(cert.as_ref(), &self.peer_pub_key) {
                errors.push(err.to_string());
            }
        }
        if errors.is_empty() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(certificate_error(errors.join("\n")))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

///
/// Creates a TLS configuration using the provided certificate and SNI. It also verifies the peer's
/// public key against the provided public key.
pub fn prepare_tls_config(
    priv_key: &EcdsaPrivateKey,
    peer_pub_key: &EcdsaPublicKey,
    sni: &str,
    insecure: bool,
) -> anyhow::Result<TlsConfig> {
    let cert = generate_cert(priv_key).map_err(|err| anyhow!("failed to generate cert: {err}"))?;

    let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned())
        .map_err(|err| anyhow!("failed to parse server name: {err}"))?;

    let certificates: Vec<rustls::pki_types::CertificateDer<'static>> =
        cert.into_iter().map(rustls::pki_types::CertificateDer::from).collect();
    let key_der =
        rustls::pki_types::PrivateKeyDer::Sec1(rustls::pki_types::PrivateSec1KeyDer::from(priv_key.der().to_vec()));

    let provider = crypto_provider();
    let verifier = Arc::new(MasqueServerCertVerifier {
        peer_pub_key: peer_pub_key.clone(),
        insecure,
        algorithms: provider.signature_verification_algorithms,
    });

    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| anyhow!("failed to build TLS config: {err}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certificates, key_der)
        .map_err(|err| anyhow!("failed to build TLS config: {err}"))?;
    config.alpn_protocols = vec![NEXT_PROTO_H3.to_vec()];

    Ok(TlsConfig { config, server_name })
}

pub fn generate_cert(priv_key: &EcdsaPrivateKey) -> anyhow::Result<Vec<Vec<u8>>> {
    generate_cert_at(priv_key, chrono::Utc::now())
}

/// Generates a certificate, with `notBefore` supplied by the caller instead of read from the wall clock.
///
/// `generate_cert` is the production entry point; this exists so a test can pin the timestamp and
/// keep the certificate bytes reproducible from a seed.
pub fn generate_cert_at(
    priv_key: &EcdsaPrivateKey,
    not_before: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    use murmur_component_ca::keypair::{
        concat, der_bit_string, der_explicit, der_integer, der_oid, der_sequence, der_utc_time, OID_ECDSA_WITH_SHA256,
        OID_EC_PUBLIC_KEY, OID_PRIME256V1,
    };
    use p256::ecdsa::signature::Signer as _;

    let secret_key = p256::SecretKey::from_sec1_der(priv_key.der())
        .map_err(|err| anyhow!("x509: cannot create certificate: invalid ECDSA private key: {err}"))?;
    let signing_key = p256::ecdsa::SigningKey::from(&secret_key);
    let public_key_bytes = signing_key.verifying_key().to_sec1_point(false).as_ref().to_vec();

    let signature_algorithm = der_sequence(&concat(&[der_oid(OID_ECDSA_WITH_SHA256)]));
    let subject_public_key_info = der_sequence(&concat(&[
        der_sequence(&concat(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_PRIME256V1)])),
        der_bit_string(&public_key_bytes),
    ]));
    let empty_name = der_sequence(&[]);

    let not_after = not_before + chrono::Duration::days(1);
    let tbs = der_sequence(&concat(&[
        der_explicit(0, &der_integer(2)),
        der_integer(0),
        signature_algorithm.clone(),
        empty_name.clone(),
        der_sequence(&concat(&[der_utc_time(not_before), der_utc_time(not_after)])),
        empty_name,
        subject_public_key_info,
    ]));

    let signature: p256::ecdsa::Signature = signing_key.sign(&tbs);
    let cert_der = der_sequence(&concat(&[tbs, signature_algorithm, der_bit_string(signature.to_der().as_bytes())]));

    Ok(vec![cert_der])
}

/// The RFC 6570 template surface this package uses (`varnames` and `raw`).
pub mod uritemplate {
    #[derive(Debug, Clone)]
    pub struct Template {
        raw: String,
        varnames: Vec<String>,
    }

    impl Template {
        /// Builds a template, panicking on an invalid one.
        #[must_use]
        #[expect(clippy::panic, reason = "the contract is to abort on an invalid template")]
        pub fn must_new(raw: &str) -> Self {
            match Self::new(raw) {
                Ok(template) => template,
                Err(err) => panic!("uritemplate: {err}"),
            }
        }

        pub fn new(raw: &str) -> Result<Self, String> {
            let mut varnames: Vec<String> = Vec::new();
            let mut rest = raw;
            while let Some((_, after)) = rest.split_once('{') {
                let (expression, remaining) = after.split_once('}').ok_or("unclosed expression")?;
                parse_expression(expression, &mut varnames)?;
                rest = remaining;
            }
            if rest.contains('}') {
                return Err("unexpected closing brace".to_owned());
            }
            Ok(Self { raw: raw.to_owned(), varnames })
        }

        #[must_use]
        pub fn varnames(&self) -> &[String] {
            &self.varnames
        }

        #[must_use]
        pub fn raw(&self) -> &str {
            &self.raw
        }
    }

    fn parse_expression(expression: &str, varnames: &mut Vec<String>) -> Result<(), String> {
        if expression.is_empty() {
            return Err("empty expression".to_owned());
        }
        let mut vars = expression;
        if let Some(c) = expression.chars().next() {
            if !c.is_ascii_alphanumeric() && c != '_' && c != '%' {
                if !"+#./;?&=,!@|".contains(c) {
                    return Err(format!("invalid operator {c:?}"));
                }
                vars = expression.strip_prefix(c).unwrap_or(expression);
            }
        }
        if vars.is_empty() {
            return Err("empty variable list".to_owned());
        }
        for var in vars.split(',') {
            let name = var.split(':').next().unwrap_or_default();
            let name = name.strip_suffix('*').unwrap_or(name);
            if name.is_empty() {
                return Err("empty variable name".to_owned());
            }
            if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'%' || b == b'.') {
                return Err(format!("invalid variable name {name:?}"));
            }
            if !varnames.iter().any(|existing| existing == name) {
                varnames.push(name.to_owned());
            }
        }
        Ok(())
    }
}

/// RFC 9000 variable-length integers, including the [`Reader`] that values are read from.
pub mod quicvarint {
    use anyhow::anyhow;
    use async_trait::async_trait;
    use tokio::io::{AsyncRead, AsyncReadExt};

    pub const MAX: u64 = (1 << 62) - 1;

    /// The end-of-stream error a varint read returns.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    #[error("EOF")]
    pub struct Eof;

    /// A byte reader, the varint decoder's input.
    #[async_trait]
    pub trait Reader: Send {
        async fn read_byte(&mut self) -> anyhow::Result<u8>;
    }

    #[async_trait]
    impl<T: AsyncRead + Unpin + Send> Reader for tokio::io::ReadHalf<T> {
        async fn read_byte(&mut self) -> anyhow::Result<u8> {
            let mut buf = [0u8; 1];
            match AsyncReadExt::read_exact(self, &mut buf).await {
                Ok(_) => Ok(buf[0]),
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Err(Eof.into()),
                Err(err) => Err(err.into()),
            }
        }
    }

    #[must_use]
    pub const fn len(value: u64) -> usize {
        if value < 1 << 6 {
            1
        } else if value < 1 << 14 {
            2
        } else if value < 1 << 30 {
            4
        } else {
            8
        }
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "`len` picked the arm by the value's width, so no cast here truncates anything"
    )]
    pub fn append(buf: &mut Vec<u8>, value: u64) {
        match len(value) {
            1 => buf.push(value as u8),
            2 => buf.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
            4 => buf.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes()),
            _ => buf.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
        }
    }

    pub fn parse(buf: &[u8]) -> anyhow::Result<(u64, usize)> {
        let first = *buf.first().ok_or(Eof)?;
        let length = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for byte in buf.get(1..length).ok_or(Eof)? {
            value = (value << 8) | u64::from(*byte);
        }
        Ok((value, length))
    }

    pub async fn read<R: Reader + ?Sized>(reader: &mut R) -> anyhow::Result<u64> {
        let first = reader.read_byte().await?;
        let length = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for _ in 1..length {
            let byte =
                reader.read_byte().await.map_err(
                    |err| {
                        if err.is::<Eof>() {
                            anyhow!("unexpected EOF")
                        } else {
                            err
                        }
                    },
                )?;
            value = (value << 8) | u64::from(byte);
        }
        Ok(value)
    }
}

/// The connect-ip subset this package uses: the capsules, route advertisement and packet
/// handling.
pub mod connectip {
    use std::fmt;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use anyhow::anyhow;
    use async_trait::async_trait;
    use bytes::Bytes;
    use ipnet::{IpNet, Ipv4Net, Ipv6Net};
    use parking_lot::Mutex;
    use tokio::sync::{mpsc, oneshot};
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;

    use super::h3;
    use super::quicvarint::{self, Eof};

    const IP_PROTO_ICMP: u8 = 1;
    const IP_PROTO_ICMPV6: u8 = 58;

    const IPV4_HEADER_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;

    const CAPSULE_TYPE_ADDRESS_ASSIGN: u64 = 1;
    const CAPSULE_TYPE_ADDRESS_REQUEST: u64 = 2;
    const CAPSULE_TYPE_ROUTE_ADVERTISEMENT: u64 = 3;

    /// On IPv6 the minimum MTU of a link is 1280 bytes.
    pub const MIN_MTU: usize = 1280;

    /// The closed-connection error.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    #[error("use of closed network connection")]
    pub struct CloseError {
        pub remote: bool,
    }

    /// Reports a datagram too large, which makes the caller build an ICMP packet.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    #[error("datagram too large")]
    pub struct DatagramTooLargeError;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IpRoute {
        pub start_ip: IpAddr,
        pub end_ip: IpAddr,
        /// The Internet Protocol number allowed for this range, 0 for any.
        pub ip_protocol: u8,
    }

    impl IpRoute {
        fn len(&self) -> usize {
            1 + ip_bit_len(&self.start_ip) / 8 + ip_bit_len(&self.end_ip) / 8 + 1
        }
    }

    const fn ip_bit_len(ip: &IpAddr) -> usize {
        match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    fn ip_bytes(ip: &IpAddr) -> Vec<u8> {
        match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        }
    }

    #[derive(Debug, Clone)]
    struct AssignedAddress {
        ip_prefix: IpNet,
    }

    #[derive(Debug, Clone)]
    struct RouteAdvertisementCapsule {
        ip_address_ranges: Vec<IpRoute>,
    }

    impl RouteAdvertisementCapsule {
        fn append(&self, b: &mut Vec<u8>) {
            let total_len = self.ip_address_ranges.iter().map(IpRoute::len).sum::<usize>();
            quicvarint::append(b, CAPSULE_TYPE_ROUTE_ADVERTISEMENT);
            quicvarint::append(b, total_len as u64);
            for ip_range in &self.ip_address_ranges {
                b.push(if ip_range.start_ip.is_ipv4() { 4 } else { 6 });
                b.extend_from_slice(&ip_bytes(&ip_range.start_ip));
                b.extend_from_slice(&ip_bytes(&ip_range.end_ip));
                b.push(ip_range.ip_protocol);
            }
        }
    }

    /// The capsules this subset sends.
    enum Capsule {
        RouteAdvertisement(RouteAdvertisementCapsule),
    }

    impl Capsule {
        fn append(&self, b: &mut Vec<u8>) {
            match self {
                Self::RouteAdvertisement(capsule) => capsule.append(b),
            }
        }
    }

    struct WriteCapsule {
        capsule: Capsule,
        result: oneshot::Sender<anyhow::Result<()>>,
    }

    #[derive(Default)]
    struct ConnState {
        close_err: Option<CloseError>,
        /// IP prefixes that we assigned to the peer.
        peer_addresses: Option<Vec<IpNet>>,
        /// IP routes that we advertised to the peer.
        local_routes: Vec<IpRoute>,
        /// IP prefixes that the peer assigned to us.
        assigned_addresses: Vec<IpNet>,
        /// IP routes that the peer advertised to us.
        #[allow(
            dead_code,
            reason = "the advertised routes are parsed and stored but never consulted: only \
                      `assigned_addresses` and `local_routes` gate incoming datagrams, and no call \
                      site reads them."
        )]
        available_routes: Vec<IpRoute>,
    }

    /// `Conn`: a connection that proxies IP packets over HTTP/3.
    pub struct Conn {
        send: Arc<tokio::sync::Mutex<h3::StreamSend>>,
        state: Arc<Mutex<ConnState>>,
        writes: mpsc::Sender<WriteCapsule>,
        datagrams: h3::DatagramReceiver,
        close_notify: CancellationToken,
        hconn: Arc<h3::ClientConn>,
        stream_id: u64,
        tasks: Vec<JoinHandle<()>>,
    }

    impl fmt::Debug for Conn {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Conn").field("stream_id", &self.stream_id).finish_non_exhaustive()
        }
    }

    #[must_use]
    pub fn new_proxied_conn(str: h3::RequestStream) -> Conn {
        let hconn = Arc::clone(str.conn());
        let stream_id = str.stream_id();
        let (send, recv, datagrams) = str.split();
        let send = Arc::new(tokio::sync::Mutex::new(send));
        let state = Arc::new(Mutex::new(ConnState::default()));
        let close_notify = CancellationToken::new();
        let (writes, mut write_rx) = mpsc::channel(1);

        let read_send = Arc::clone(&send);
        let read_state = Arc::clone(&state);
        let read_close = close_notify.clone();
        let read_task = tokio::spawn(async move {
            let mut recv = recv;
            let mut locally_closed = false;
            let result = tokio::select! {
                result = read_from_stream(&mut recv, &read_state) => result,
                () = read_close.cancelled() => {
                    locally_closed = true;
                    Ok(())
                }
            };
            if locally_closed {
                // Dropping the receive half stops the stream, the equivalent of a read cancel.
                recv.stop(h3::H3_NO_ERROR);
            }
            let _ = read_send.lock().await.finish();
            if let Err(err) = result {
                murmur_log::debugln!("handling stream failed: {err}");
                let mut state = read_state.lock();
                if state.close_err.is_none() {
                    state.close_err = Some(CloseError { remote: true });
                    drop(state);
                    read_close.cancel();
                }
            }
        });

        let write_send = Arc::clone(&send);
        let write_state = Arc::clone(&state);
        let write_close = close_notify.clone();
        let write_task = tokio::spawn(async move {
            if let Err(err) = write_to_stream(write_send, &mut write_rx, &write_state, &write_close).await {
                murmur_log::debugln!("writing to stream failed: {err}");
                let mut state = write_state.lock();
                if state.close_err.is_none() {
                    state.close_err = Some(CloseError { remote: true });
                    drop(state);
                    write_close.cancel();
                }
            }
        });

        Conn { send, state, writes, datagrams, close_notify, hconn, stream_id, tasks: vec![read_task, write_task] }
    }

    impl Conn {
        ///
        /// The routes from the most recent call are the active ones.
        pub async fn advertise_route(
            &self,
            ctx: Option<&CancellationToken>,
            routes: Vec<IpRoute>,
        ) -> anyhow::Result<()> {
            for route in &routes {
                if route.start_ip > route.end_ip {
                    return Err(anyhow!(
                        "invalid route advertising start_ip: {} larger than {}",
                        route.start_ip,
                        route.end_ip
                    ));
                }
            }
            self.state.lock().local_routes.clone_from(&routes);
            self.send_capsule(ctx, Capsule::RouteAdvertisement(RouteAdvertisementCapsule { ip_address_ranges: routes }))
                .await
        }

        pub async fn read_packet(&mut self) -> anyhow::Result<Vec<u8>> {
            loop {
                let data = receive_datagram(&mut self.datagrams, None)
                    .await
                    .map_err(|err| self.close_err().map_or(err, anyhow::Error::from))?;
                let (context_id, n) =
                    quicvarint::parse(&data).map_err(|err| anyhow!("connect-ip: malformed datagram: {err}"))?;
                if context_id != 0 {
                    // Drop this datagram. We currently only support proxying of IP payloads.
                    continue;
                }
                let payload =
                    data.get(n..).ok_or_else(|| anyhow!("connect-ip: malformed datagram: truncated context id"))?;
                if let Err(err) = handle_incoming_proxied_packet(&self.state, payload) {
                    murmur_log::debugln!("dropping proxied packet: {err}");
                    continue;
                }
                return Ok(payload.to_vec());
            }
        }

        ///
        /// If sending the packet fails, it might return an ICMP packet; it is the caller's
        /// responsibility to send that packet to the sender.
        #[expect(
            clippy::unused_async,
            reason = "this inherent method backs the async `IpConn::write_packet` it implements"
        )]
        pub async fn write_packet(&mut self, b: &mut [u8]) -> anyhow::Result<Option<Vec<u8>>> {
            let data = match compose_datagram(b) {
                Ok(data) => data,
                Err(err) => {
                    murmur_log::debugln!("dropping proxied packet ({} bytes) that can't be proxied: {err}", b.len());
                    return Ok(None);
                }
            };
            if let Err(err) = self.hconn.send_datagram(self.stream_id, data.as_deref().unwrap_or(&[])) {
                if err.downcast_ref::<DatagramTooLargeError>().is_some() {
                    match compose_icmp_too_large_packet(b, MIN_MTU) {
                        Ok(packet) => return Ok(Some(packet)),
                        Err(err) => murmur_log::debugln!("failed to compose ICMP too large packet: {err}"),
                    }
                    return Ok(None);
                }
                return Err(self.close_err().map_or(err, anyhow::Error::from));
            }
            Ok(None)
        }

        pub async fn close(&mut self) -> anyhow::Result<()> {
            {
                let mut state = self.state.lock();
                if state.close_err.is_none() {
                    state.close_err = Some(CloseError { remote: false });
                }
            }
            self.close_notify.cancel();
            for task in self.tasks.drain(..) {
                task.abort();
            }
            self.send.lock().await.finish().map_err(|err| anyhow!("{err}"))
        }

        fn close_err(&self) -> Option<CloseError> {
            self.state.lock().close_err
        }

        async fn send_capsule(&self, ctx: Option<&CancellationToken>, capsule: Capsule) -> anyhow::Result<()> {
            let (result_tx, result_rx) = oneshot::channel();
            let request = WriteCapsule { capsule, result: result_tx };
            tokio::select! {
                sent = self.writes.send(request) => {
                    if sent.is_err() {
                        return Err(self.close_err().map_or_else(
                            || anyhow!("connect-ip: write loop closed"),
                            anyhow::Error::from,
                        ));
                    }
                    tokio::select! {
                        () = cancel(ctx) => Err(super::context_canceled()),
                        result = result_rx => match result {
                            Ok(result) => result,
                            Err(_) => Err(anyhow!("connect-ip: write loop closed")),
                        },
                    }
                }
                () = self.close_notify.cancelled() => Err(self.close_err().map_or_else(
                    || anyhow!("connect-ip: closed"),
                    anyhow::Error::from,
                )),
                () = cancel(ctx) => Err(super::context_canceled()),
            }
        }
    }

    /// Completion of an optional context, the select case the caller waits on.
    // cancel-safe: awaits only a token's `cancelled()` (or `pending()`) select case.
    async fn cancel(ctx: Option<&CancellationToken>) {
        match ctx {
            Some(ctx) => ctx.cancelled().await,
            None => std::future::pending().await,
        }
    }

    // NOT cancel-safe: a dropped read leaves the capsule framing half-consumed, so the caller
    // stops the stream instead of retrying the read.
    async fn read_from_stream(recv: &mut h3::StreamRecv, state: &Arc<Mutex<ConnState>>) -> anyhow::Result<()> {
        loop {
            let capsule_type = quicvarint::read(recv).await?;
            let payload_len = quicvarint::read(recv).await?;
            let mut reader = CapsuleReader::new(recv, payload_len);
            match capsule_type {
                CAPSULE_TYPE_ADDRESS_ASSIGN => {
                    let capsule = parse_address_assign_capsule(&mut reader).await?;
                    state.lock().assigned_addresses =
                        capsule.assigned_addresses.into_iter().map(|assigned| assigned.ip_prefix).collect();
                }
                CAPSULE_TYPE_ADDRESS_REQUEST => {
                    parse_address_request_capsule(&mut reader).await?;
                    return Err(anyhow!("connect-ip: address request not yet supported"));
                }
                CAPSULE_TYPE_ROUTE_ADVERTISEMENT => {
                    let capsule = parse_route_advertisement_capsule(&mut reader).await?;
                    state.lock().available_routes = capsule.ip_address_ranges;
                }
                _ => {}
            }
            reader.discard().await?;
        }
    }

    // NOT cancel-safe: the loop owns the capsule receiver, so a drop fails in-flight senders
    // rather than retrying them.
    async fn write_to_stream(
        send: Arc<tokio::sync::Mutex<h3::StreamSend>>,
        writes: &mut mpsc::Receiver<WriteCapsule>,
        state: &Arc<Mutex<ConnState>>,
        close_notify: &CancellationToken,
    ) -> anyhow::Result<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        loop {
            let request = tokio::select! {
                () = close_notify.cancelled() => {
                    let err = state.lock().close_err.unwrap_or(CloseError { remote: false });
                    return Err(err.into());
                }
                request = writes.recv() => match request {
                    Some(request) => request,
                    None => return Ok(()),
                },
            };
            buf.clear();
            request.capsule.append(&mut buf);
            let mut send = send.lock().await;
            match send.write(&buf).await {
                Ok(()) => {
                    let _ = request.result.send(Ok(()));
                }
                Err(err) => {
                    let message = err.to_string();
                    let _ = request.result.send(Err(err));
                    return Err(anyhow!("{message}"));
                }
            }
        }
    }

    /// Receives one datagram, fed by the connection's datagram dispatcher.
    // cancel-safe: awaits only a token's `cancelled()` (or `pending()`) and a `recv()` on a channel, both of which can be dropped and re-polled.
    async fn receive_datagram(
        datagrams: &mut h3::DatagramReceiver,
        ctx: Option<&CancellationToken>,
    ) -> anyhow::Result<Bytes> {
        let received = tokio::select! {
            () = cancel(ctx) => return Err(super::context_canceled()),
            received = datagrams.recv() => received,
        };
        match received {
            Some(data) => Ok(data),
            None => Err(anyhow!("http3: datagram stream closed")),
        }
    }

    /// The `N`-byte field at `start` of `data`, or `None` when `data` ends before it.
    fn field_at<const N: usize>(data: &[u8], start: usize) -> Option<[u8; N]> {
        let end = start.checked_add(N)?;
        data.get(start..end)?.try_into().ok()
    }

    /// The mutable `N`-byte header at the start of the packet `b`, or `None` when `b` is shorter
    /// than one.
    fn header_mut<const N: usize>(b: &mut [u8]) -> Option<&mut [u8; N]> {
        b.get_mut(..N)?.try_into().ok()
    }

    fn handle_incoming_proxied_packet(state: &Arc<Mutex<ConnState>>, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() {
            return Err(anyhow!("connect-ip: empty packet"));
        }
        let (src, dst, ip_proto) = match ip_version(data) {
            4 => {
                let (Some(src), Some(dst), Some(ip_proto)) =
                    (field_at::<4>(data, 12), field_at::<4>(data, 16), data.get(9).copied())
                else {
                    return Err(anyhow!("connect-ip: malformed datagram: too short"));
                };
                (IpAddr::V4(Ipv4Addr::from(src)), IpAddr::V4(Ipv4Addr::from(dst)), ip_proto)
            }
            6 => {
                let (Some(src), Some(dst), Some(ip_proto)) =
                    (field_at::<16>(data, 8), field_at::<16>(data, 24), data.get(6).copied())
                else {
                    return Err(anyhow!("connect-ip: malformed datagram: too short"));
                };
                (IpAddr::V6(Ipv6Addr::from(src)), IpAddr::V6(Ipv6Addr::from(dst)), ip_proto)
            }
            v => return Err(anyhow!("connect-ip: unknown IP versions: {v}")),
        };

        let (assigned_addresses, local_routes, peer_addresses) = {
            let state = state.lock();
            (state.assigned_addresses.clone(), state.local_routes.clone(), state.peer_addresses.clone())
        };

        // We don't necessarily assign any addresses to the peer. In the Remote Access VPN use case
        // (RFC 9484, section 8.1) the client accepts incoming traffic from all IPs.
        if let Some(peer_addresses) = &peer_addresses {
            if !peer_addresses.iter().any(|prefix| prefix.contains(&src)) {
                return Err(anyhow!("connect-ip: datagram source address not allowed: {src}"));
            }
        }

        // The destination IP address is valid if it is within one of the ranges assigned to us, or
        // within one of the ranges that we advertised to the peer.
        let mut is_allowed_dst =
            !assigned_addresses.is_empty() && assigned_addresses.iter().any(|prefix| prefix.contains(&dst));
        if !is_allowed_dst {
            is_allowed_dst = local_routes.iter().any(|route| {
                if route.start_ip > dst || dst > route.end_ip {
                    return false;
                }
                if (ip_version(data) == 4 && ip_proto == IP_PROTO_ICMP)
                    || (ip_version(data) == 6 && ip_proto == IP_PROTO_ICMPV6)
                {
                    return true;
                }
                route.ip_protocol == 0 || route.ip_protocol == ip_proto
            });
        }
        if !is_allowed_dst {
            return Err(anyhow!(
                "connect-ip: datagram destination address / protocol not allowed: {dst} (protocol: {ip_proto})"
            ));
        }
        Ok(())
    }

    /// `None` is the empty datagram for an empty packet.
    fn compose_datagram(b: &mut [u8]) -> anyhow::Result<Option<Vec<u8>>> {
        if b.is_empty() {
            return Ok(None);
        }
        match ip_version(b) {
            4 => {
                let header =
                    header_mut::<IPV4_HEADER_LEN>(b).ok_or_else(|| anyhow!("connect-ip: IPv4 packet too short"))?;
                let ttl = header[8];
                if ttl <= 1 {
                    return Err(anyhow!("connect-ip: datagram TTL too small: {ttl}"));
                }
                header[8] = ttl - 1;
                let checksum = calculate_ipv4_checksum(header);
                header[10..12].copy_from_slice(&checksum.to_be_bytes());
            }
            6 => {
                let header =
                    header_mut::<IPV6_HEADER_LEN>(b).ok_or_else(|| anyhow!("connect-ip: IPv6 packet too short"))?;
                let hop_limit = header[7];
                if hop_limit <= 1 {
                    return Err(anyhow!("connect-ip: datagram Hop Limit too small: {hop_limit}"));
                }
                header[7] = hop_limit - 1;
            }
            v => return Err(anyhow!("connect-ip: unknown IP versions: {v}")),
        }
        let mut data = Vec::with_capacity(1 + b.len());
        quicvarint::append(&mut data, 0);
        data.extend_from_slice(b);
        Ok(Some(data))
    }

    #[must_use]
    pub fn ip_version(b: &[u8]) -> u8 {
        b.first().map_or(0, |first| first >> 4)
    }

    #[must_use]
    pub fn calculate_ipv4_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
        let mut sum: u32 = 0;
        for (word_idx, word) in header.chunks_exact(2).enumerate() {
            // Word 5 of the header is the checksum field, which is excluded from its own sum.
            if word_idx == 5 {
                continue;
            }
            let [hi, lo] = word else { continue };
            sum += u32::from(u16::from_be_bytes([*hi, *lo]));
        }
        while (sum >> 16) > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the fold above leaves the sum below 0x10000, so its low half is the whole value"
        )]
        let folded = sum as u16;
        !folded
    }

    /// The ICMP checksum; its byte-wise fold is what the `ICMPv6` pseudo header expects.
    fn icmp_checksum(b: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut chunks = b.chunks_exact(2);
        for word in &mut chunks {
            let [first, second] = word else { continue };
            sum += u32::from(u16::from_le_bytes([*first, *second]));
        }
        if let [last] = chunks.remainder() {
            sum += u32::from(*last);
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += sum >> 16;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the fold above leaves the sum below 0x10000, so its low half is the whole value"
        )]
        let folded = sum as u16;
        !folded
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the body is a 1232-byte packet prefix plus a 4-byte MTU field, so no length here \
                  reaches the 32-bit ICMP or 16-bit IPv4/IPv6 length fields, and IPV4_HEADER_LEN \
                  is 20, i.e. 5 32-bit words in the IHL field"
    )]
    pub fn compose_icmp_too_large_packet(b: &[u8], mtu: usize) -> anyhow::Result<Vec<u8>> {
        if b.is_empty() {
            return Err(anyhow!("connect-ip: empty packet"));
        }
        let (message_type, code, original, pseudo_header) = match ip_version(b) {
            4 => (3u8, 4u8, b.get(..IPV4_HEADER_LEN + 8).unwrap_or(b).to_vec(), None),
            6 => {
                let (Some(dst), Some(src)) = (field_at::<16>(b, 24), field_at::<16>(b, 8)) else {
                    return Err(anyhow!("connect-ip: IPv6 packet too short"));
                };
                let original = b.get(..1232).unwrap_or(b).to_vec();
                let icmp_len = 8 + original.len();
                // RFC 4443's IPv6 pseudo header: the addresses, the ICMP message length, zeros and
                // the protocol.
                let mut pseudo_header = Vec::with_capacity(40);
                pseudo_header.extend_from_slice(&dst);
                pseudo_header.extend_from_slice(&src);
                pseudo_header.extend_from_slice(&(icmp_len as u32).to_be_bytes());
                pseudo_header.extend_from_slice(&[0, 0, 0, IP_PROTO_ICMPV6]);
                (2u8, 0u8, original, Some(pseudo_header))
            }
            v => return Err(anyhow!("connect-ip: unknown IP version: {v}")),
        };

        let mut body = Vec::with_capacity(4 + original.len());
        body.extend_from_slice(&(mtu as u32).to_be_bytes());
        body.extend_from_slice(&original);

        let mut message = pseudo_header.unwrap_or_default();
        let offset = message.len();
        message.extend_from_slice(&[message_type, code, 0, 0]);
        message.extend_from_slice(&body);
        let checksum = icmp_checksum(&message);
        let checksum_field =
            message.get_mut(offset + 2..offset + 4).ok_or_else(|| anyhow!("connect-ip: ICMP message too short"))?;
        checksum_field.copy_from_slice(&checksum.to_le_bytes());
        let message = message.get(offset..).ok_or_else(|| anyhow!("connect-ip: ICMP message too short"))?;

        if ip_version(b) == 4 {
            let (Some(src), Some(dst)) = (field_at::<4>(b, 12), field_at::<4>(b, 16)) else {
                return Err(anyhow!("connect-ip: IPv4 packet too short"));
            };
            let mut header = [0u8; IPV4_HEADER_LEN];
            header[0] = (4 << 4) | ((IPV4_HEADER_LEN as u8) >> 2);
            let ip_len = IPV4_HEADER_LEN + message.len();
            header[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
            header[8] = 64;
            header[9] = IP_PROTO_ICMP;
            header[12..16].copy_from_slice(&dst);
            header[16..20].copy_from_slice(&src);
            let checksum = calculate_ipv4_checksum(&header);
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
            let mut packet = header.to_vec();
            packet.extend_from_slice(message);
            return Ok(packet);
        }

        let (Some(dst), Some(src)) = (field_at::<16>(b, 24), field_at::<16>(b, 8)) else {
            return Err(anyhow!("connect-ip: IPv6 packet too short"));
        };
        let mut header = [0u8; IPV6_HEADER_LEN];
        header[0] = 6 << 4;
        header[4..6].copy_from_slice(&(message.len() as u16).to_be_bytes());
        header[6] = IP_PROTO_ICMPV6;
        header[7] = 64;
        header[8..24].copy_from_slice(&dst);
        header[24..40].copy_from_slice(&src);
        let mut packet = header.to_vec();
        packet.extend_from_slice(message);
        Ok(packet)
    }

    /// A capsule reader, bounded to one capsule.
    struct CapsuleReader<'a> {
        stream: &'a mut h3::StreamRecv,
        remaining: u64,
    }

    impl<'a> CapsuleReader<'a> {
        const fn new(stream: &'a mut h3::StreamRecv, remaining: u64) -> Self {
            Self { stream, remaining }
        }

        async fn read_byte(&mut self) -> anyhow::Result<u8> {
            if self.remaining == 0 {
                return Err(Eof.into());
            }
            let byte = self.stream.read_byte().await?;
            self.remaining -= 1;
            Ok(byte)
        }

        async fn read_varint(&mut self) -> anyhow::Result<u64> {
            let first = self.read_byte().await?;
            let length = 1usize << (first >> 6);
            let mut value = u64::from(first & 0x3f);
            for _ in 1..length {
                let byte =
                    self.read_byte().await.map_err(
                        |err| {
                            if err.is::<Eof>() {
                                anyhow!("unexpected EOF")
                            } else {
                                err
                            }
                        },
                    )?;
                value = (value << 8) | u64::from(byte);
            }
            Ok(value)
        }

        // NOT cancel-safe: `read_exact` consumes bytes from the stream as it fills the buffer, so a dropped call leaves the next read mid-field.
        async fn read_exact(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
            if self.remaining < buf.len() as u64 {
                return Err(anyhow!("unexpected EOF"));
            }
            self.stream.read_exact(buf).await?;
            self.remaining -= buf.len() as u64;
            Ok(())
        }

        async fn discard(&mut self) -> anyhow::Result<()> {
            let mut buf = [0u8; 1024];
            while self.remaining > 0 {
                let len = usize::try_from(self.remaining).unwrap_or(usize::MAX).min(buf.len());
                let (chunk, _rest) = buf.split_at_mut(len);
                self.stream.read_exact(chunk).await?;
                self.remaining -= len as u64;
            }
            Ok(())
        }
    }

    struct AddressAssignCapsule {
        assigned_addresses: Vec<AssignedAddress>,
    }

    async fn parse_address_assign_capsule(reader: &mut CapsuleReader<'_>) -> anyhow::Result<AddressAssignCapsule> {
        let mut assigned_addresses = Vec::new();
        while let Some((_request_id, ip_prefix)) = parse_address(reader).await? {
            assigned_addresses.push(AssignedAddress { ip_prefix });
        }
        Ok(AddressAssignCapsule { assigned_addresses })
    }

    async fn parse_address_request_capsule(reader: &mut CapsuleReader<'_>) -> anyhow::Result<()> {
        while let Some((_request_id, _ip_prefix)) = parse_address(reader).await? {}
        Ok(())
    }

    /// Parses one address; `None` stands for the end of a capsule's address list.
    async fn parse_address(reader: &mut CapsuleReader<'_>) -> anyhow::Result<Option<(u64, IpNet)>> {
        let request_id = match reader.read_varint().await {
            Ok(request_id) => request_id,
            Err(err) if err.is::<Eof>() => return Ok(None),
            Err(err) => return Err(err),
        };
        let ip_version = reader.read_byte().await?;
        let ip = match ip_version {
            4 => {
                let mut octets = [0u8; 4];
                reader.read_exact(&mut octets).await?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                let mut octets = [0u8; 16];
                reader.read_exact(&mut octets).await?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            ip_version => return Err(anyhow!("invalid IP version: {ip_version}")),
        };
        let prefix_len = reader.read_byte().await?;
        let bit_len = ip_bit_len(&ip);
        if prefix_len as usize > bit_len {
            return Err(anyhow!("prefix length {prefix_len} exceeds IP address length ({bit_len})"));
        }
        let prefix = match ip {
            IpAddr::V4(ip) => IpNet::V4(Ipv4Net::new(ip, prefix_len)?),
            IpAddr::V6(ip) => IpNet::V6(Ipv6Net::new(ip, prefix_len)?),
        };
        if prefix.trunc() != prefix {
            return Err(anyhow!("lower bits not covered by prefix length are not all zero"));
        }
        Ok(Some((request_id, prefix)))
    }

    async fn parse_route_advertisement_capsule(
        reader: &mut CapsuleReader<'_>,
    ) -> anyhow::Result<RouteAdvertisementCapsule> {
        let mut ip_address_ranges = Vec::new();
        while let Some(ip_range) = parse_ip_address_range(reader).await? {
            ip_address_ranges.push(ip_range);
        }
        Ok(RouteAdvertisementCapsule { ip_address_ranges })
    }

    /// `*connectip.Conn` satisfies the `IpConn` interface, which `*Conn` does here too.
    #[async_trait]
    impl super::IpConn for Conn {
        async fn read_packet(&mut self) -> anyhow::Result<Vec<u8>> {
            Self::read_packet(self).await
        }

        async fn write_packet(&mut self, b: &mut [u8]) -> anyhow::Result<Option<Vec<u8>>> {
            Self::write_packet(self, b).await
        }

        async fn close(&mut self) -> anyhow::Result<()> {
            Self::close(self).await
        }
    }

    /// Parses one address range; `None` stands for the end of the range list.
    async fn parse_ip_address_range(reader: &mut CapsuleReader<'_>) -> anyhow::Result<Option<IpRoute>> {
        let ip_version = match reader.read_byte().await {
            Ok(ip_version) => ip_version,
            Err(err) if err.is::<Eof>() => return Ok(None),
            Err(err) => return Err(err),
        };
        let (start_ip, end_ip) = match ip_version {
            4 => {
                let mut start = [0u8; 4];
                let mut end = [0u8; 4];
                reader.read_exact(&mut start).await?;
                reader.read_exact(&mut end).await?;
                (IpAddr::V4(Ipv4Addr::from(start)), IpAddr::V4(Ipv4Addr::from(end)))
            }
            6 => {
                let mut start = [0u8; 16];
                let mut end = [0u8; 16];
                reader.read_exact(&mut start).await?;
                reader.read_exact(&mut end).await?;
                (IpAddr::V6(Ipv6Addr::from(start)), IpAddr::V6(Ipv6Addr::from(end)))
            }
            ip_version => return Err(anyhow!("invalid IP version: {ip_version}")),
        };
        if start_ip > end_ip {
            return Err(anyhow!("start IP is greater than end IP"));
        }
        let ip_protocol = reader.read_byte().await?;
        Ok(Some(IpRoute { start_ip, end_ip, ip_protocol }))
    }

    #[cfg(test)]
    mod checksum_tests {
        use super::*;

        /// RFC 1071 §3's worked example.
        #[test]
        fn ipv4_checksum_known_answer() {
            let header: [u8; IPV4_HEADER_LEN] = [
                0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63, 0xac,
                0x10, 0x0a, 0x0c,
            ];
            assert_eq!(calculate_ipv4_checksum(&header), 0xb1e6);
        }

        #[test]
        fn icmp_checksum_even_length() {
            assert_eq!(icmp_checksum(&[0x01, 0x02, 0x03, 0x04]), 0xf9fb);
            assert_eq!(icmp_checksum(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a]), 0xf5fd);
        }

        #[test]
        fn icmp_checksum_odd_length() {
            assert_eq!(icmp_checksum(&[0x01, 0x02, 0x03, 0x04, 0x05]), 0xf9f6);
        }
    }
}

/// The HTTP/3 client surface this package uses: SETTINGS, the QPACK subset needed to encode
/// requests and decode responses, request streams and the RFC 9297 datagram framing.
pub mod h3 {
    use std::collections::HashMap;
    use std::fmt;
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use anyhow::anyhow;
    use async_trait::async_trait;
    use bytes::Bytes;
    use parking_lot::Mutex;
    use quinn::{RecvStream, SendStream, VarInt};
    use tokio::sync::{mpsc, Notify};
    use tokio_util::sync::CancellationToken;

    use super::quicvarint::{self, Eof};
    use super::HttpResponse;

    pub const H3_NO_ERROR: u32 = 0x100;
    pub const H3_GENERAL_PROTOCOL_ERROR: u32 = 0x101;
    pub const H3_INTERNAL_ERROR: u32 = 0x102;
    pub const H3_STREAM_CREATION_ERROR: u32 = 0x103;
    pub const H3_CLOSED_CRITICAL_STREAM: u32 = 0x104;
    pub const H3_FRAME_UNEXPECTED: u32 = 0x105;
    pub const H3_FRAME_ERROR: u32 = 0x106;
    pub const H3_EXCESSIVE_LOAD: u32 = 0x107;
    pub const H3_ID_ERROR: u32 = 0x108;
    pub const H3_SETTINGS_ERROR: u32 = 0x109;
    pub const H3_MISSING_SETTINGS: u32 = 0x10a;
    pub const H3_REQUEST_INCOMPLETE: u32 = 0x10d;
    pub const H3_MESSAGE_ERROR: u32 = 0x10e;
    pub const H3_DATAGRAM_ERROR: u32 = 0x33;
    pub const QPACK_DECOMPRESSION_FAILED: u32 = 0x200;

    /// The default user agent, sent when the request carries no `User-Agent`.
    pub const DEFAULT_USER_AGENT: &str = "quic-go HTTP/3";

    const FRAME_DATA: u64 = 0x0;
    const FRAME_HEADERS: u64 = 0x1;
    const FRAME_CANCEL_PUSH: u64 = 0x3;
    const FRAME_SETTINGS: u64 = 0x4;
    const FRAME_PUSH_PROMISE: u64 = 0x5;
    const FRAME_GOAWAY: u64 = 0x7;
    const FRAME_MAX_PUSH_ID: u64 = 0xd;

    const STREAM_TYPE_CONTROL: u64 = 0x0;
    const STREAM_TYPE_PUSH: u64 = 0x1;
    const STREAM_TYPE_QPACK_ENCODER: u64 = 0x2;
    const STREAM_TYPE_QPACK_DECODER: u64 = 0x3;

    const SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
    const SETTING_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
    const SETTING_QPACK_BLOCKED_STREAMS: u64 = 0x7;
    const SETTING_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;
    const SETTING_DATAGRAM: u64 = 0x33;

    const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 10 << 20;
    const MAX_QUARTER_STREAM_ID: u64 = (1 << 60) - 1;
    const STREAM_DATAGRAM_QUEUE_LEN: usize = 32;

    /// A SETTINGS frame is (identifier, value) varint pairs of at most ten bytes each, so 16 KiB is
    /// far above any real one, and the peer declares its length in two varint bytes.
    const MAX_SETTINGS_FRAME_LEN: u64 = 16 * 1024;

    /// The frames preceding the final response may not exceed the field-section size this client
    /// advertises, which bounds both the allocation and the loop.
    const MAX_RESPONSE_PREAMBLE_BYTES: u64 = DEFAULT_MAX_FIELD_SECTION_SIZE;

    /// Informational responses are the only reason to loop here, and RFC 9110 does not require
    /// handling more than one.
    const MAX_INTERIM_RESPONSES: u64 = 2;

    /// The hop-by-hop request headers dropped when encoding.
    const CONNECTION_SPECIFIC: [&str; 5] =
        ["connection", "proxy-connection", "transfer-encoding", "upgrade", "keep-alive"];

    const fn is_known_frame(frame_type: u64) -> bool {
        matches!(
            frame_type,
            FRAME_DATA
                | FRAME_HEADERS
                | FRAME_CANCEL_PUSH
                | FRAME_SETTINGS
                | FRAME_PUSH_PROMISE
                | FRAME_GOAWAY
                | FRAME_MAX_PUSH_ID
        )
    }

    async fn read_byte(recv: &mut RecvStream) -> anyhow::Result<u8> {
        let mut buf = [0u8; 1];
        match recv.read(&mut buf).await {
            Ok(Some(1)) => Ok(buf[0]),
            Ok(_) => Err(Eof.into()),
            Err(err) => Err(anyhow!("{err}")),
        }
    }

    async fn read_varint(recv: &mut RecvStream) -> anyhow::Result<u64> {
        let first = read_byte(recv).await?;
        let length = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for _ in 1..length {
            let byte =
                read_byte(recv).await.map_err(|err| if err.is::<Eof>() { anyhow!("unexpected EOF") } else { err })?;
            value = (value << 8) | u64::from(byte);
        }
        Ok(value)
    }

    async fn read_full(recv: &mut RecvStream, buf: &mut [u8]) -> anyhow::Result<()> {
        match recv.read_exact(buf).await {
            Ok(()) => Ok(()),
            Err(quinn::ReadExactError::FinishedEarly(_)) => Err(anyhow!("unexpected EOF")),
            Err(quinn::ReadExactError::ReadError(err)) => Err(anyhow!("{err}")),
        }
    }

    /// Reads one frame payload of the peer-declared `length`, which is bounded by `max_len` before
    /// anything is allocated for it.
    async fn read_payload_capped(recv: &mut RecvStream, length: u64, max_len: u64) -> anyhow::Result<Vec<u8>> {
        if length > max_len {
            return Err(anyhow!("http3: frame payload exceeds {max_len} bytes"));
        }
        let length = usize::try_from(length).map_err(|_err| anyhow!("http3: frame payload too large"))?;
        let mut payload = vec![0u8; length];
        read_full(recv, &mut payload).await?;
        Ok(payload)
    }

    async fn discard(recv: &mut RecvStream, length: u64) -> anyhow::Result<()> {
        let mut buf = [0u8; 1024];
        let mut remaining = length;
        while remaining > 0 {
            let len = usize::try_from(remaining).unwrap_or(usize::MAX).min(buf.len());
            let (chunk, _rest) = buf.split_at_mut(len);
            read_full(recv, chunk).await?;
            remaining -= len as u64;
        }
        Ok(())
    }

    async fn read_frame_header(recv: &mut RecvStream) -> anyhow::Result<(u64, u64)> {
        let frame_type = read_varint(recv).await?;
        let length = read_varint(recv).await?;
        Ok((frame_type, length))
    }

    /// Drops the routing entries whose receiver is gone, so a table entry cannot outlive the code
    /// that reads from it; returns how many were removed.
    fn prune_closed_datagram_streams(streams: &mut HashMap<u64, mpsc::Sender<Bytes>>) -> usize {
        let before = streams.len();
        streams.retain(|_stream_id, sender| !sender.is_closed());
        before - streams.len()
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Settings {
        pub enable_datagrams: bool,
        pub enable_extended_connect: bool,
        pub max_field_section_size: u64,
        pub qpack_max_table_capacity: u64,
        pub qpack_blocked_streams: u64,
        pub other: HashMap<u64, u64>,
    }

    fn append_settings(buf: &mut Vec<u8>, settings: &Settings, additional: &[(u64, u64)]) {
        let mut payload: Vec<u8> = Vec::new();
        if settings.max_field_section_size != 0 {
            quicvarint::append(&mut payload, SETTING_MAX_FIELD_SECTION_SIZE);
            quicvarint::append(&mut payload, settings.max_field_section_size);
        }
        if settings.enable_datagrams {
            quicvarint::append(&mut payload, SETTING_DATAGRAM);
            quicvarint::append(&mut payload, 1);
        }
        if settings.enable_extended_connect {
            quicvarint::append(&mut payload, SETTING_ENABLE_CONNECT_PROTOCOL);
            quicvarint::append(&mut payload, 1);
        }
        for (id, value) in additional {
            quicvarint::append(&mut payload, *id);
            quicvarint::append(&mut payload, *value);
        }
        quicvarint::append(buf, FRAME_SETTINGS);
        quicvarint::append(buf, payload.len() as u64);
        buf.extend_from_slice(&payload);
    }

    /// The SETTINGS parsing of the control stream.
    fn parse_settings(payload: &[u8]) -> anyhow::Result<Settings> {
        let mut settings = Settings::default();
        let mut offset = 0usize;
        while offset < payload.len() {
            let (id, n) = quicvarint::parse(payload.get(offset..).ok_or(Eof)?)?;
            offset += n;
            let (value, n) = quicvarint::parse(payload.get(offset..).ok_or(Eof)?)?;
            offset += n;
            match id {
                SETTING_QPACK_MAX_TABLE_CAPACITY => settings.qpack_max_table_capacity = value,
                SETTING_MAX_FIELD_SECTION_SIZE => settings.max_field_section_size = value,
                SETTING_QPACK_BLOCKED_STREAMS => settings.qpack_blocked_streams = value,
                SETTING_ENABLE_CONNECT_PROTOCOL => settings.enable_extended_connect = value != 0,
                SETTING_DATAGRAM => settings.enable_datagrams = value != 0,
                _ => {
                    settings.other.insert(id, value);
                }
            }
        }
        Ok(settings)
    }

    /// A local transport mirror, holding the options this crate sets.
    pub struct Transport {
        enable_datagrams: bool,
        additional_settings: Vec<(u64, u64)>,
        client_conns: Mutex<Vec<Arc<ClientConn>>>,
    }

    impl fmt::Debug for Transport {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Transport").field("enable_datagrams", &self.enable_datagrams).finish_non_exhaustive()
        }
    }

    impl Transport {
        #[must_use]
        pub const fn new(enable_datagrams: bool, additional_settings: Vec<(u64, u64)>) -> Self {
            Self { enable_datagrams, additional_settings, client_conns: Mutex::new(Vec::new()) }
        }

        pub async fn new_client_conn(&self, quic: quinn::Connection) -> anyhow::Result<Arc<ClientConn>> {
            let conn = ClientConn::new(quic, self.enable_datagrams, &self.additional_settings).await?;
            self.client_conns.lock().push(Arc::clone(&conn));
            Ok(conn)
        }

        pub fn close(&self) -> anyhow::Result<()> {
            let conns = std::mem::take(&mut *self.client_conns.lock());
            for conn in conns {
                conn.close_with_error(H3_NO_ERROR, "");
            }
            Ok(())
        }
    }

    /// One HTTP/3 connection.
    pub struct ClientConn {
        quic: quinn::Connection,
        settings: Mutex<Option<Settings>>,
        settings_notify: Notify,
        datagram_streams: Mutex<HashMap<u64, mpsc::Sender<Bytes>>>,
    }

    impl fmt::Debug for ClientConn {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ClientConn").field("settings", &self.settings.lock().is_some()).finish_non_exhaustive()
        }
    }

    impl ClientConn {
        pub async fn new(
            quic: quinn::Connection,
            enable_datagrams: bool,
            additional_settings: &[(u64, u64)],
        ) -> anyhow::Result<Arc<Self>> {
            let mut control = quic.open_uni().await.map_err(|err| anyhow!("{err}"))?;
            let settings = Settings {
                enable_datagrams,
                max_field_section_size: DEFAULT_MAX_FIELD_SECTION_SIZE,
                ..Settings::default()
            };
            let mut buf: Vec<u8> = Vec::new();
            quicvarint::append(&mut buf, STREAM_TYPE_CONTROL);
            append_settings(&mut buf, &settings, additional_settings);
            control.write_all(&buf).await.map_err(|err| anyhow!("{err}"))?;

            let conn = Arc::new(Self {
                quic,
                settings: Mutex::new(None),
                settings_notify: Notify::new(),
                datagram_streams: Mutex::new(HashMap::new()),
            });

            let streams = Arc::clone(&conn);
            tokio::spawn(async move {
                // The control stream must stay open for the connection's lifetime.
                let _control = control;
                streams.drive_uni_streams().await;
            });
            let datagrams = Arc::clone(&conn);
            tokio::spawn(async move { datagrams.drive_datagrams().await });

            Ok(conn)
        }

        async fn drive_uni_streams(self: Arc<Self>) {
            loop {
                match self.quic.accept_uni().await {
                    Ok(recv) => {
                        let conn = Arc::clone(&self);
                        tokio::spawn(async move {
                            let _ = conn.handle_uni_stream(recv).await;
                        });
                    }
                    Err(_) => return,
                }
            }
        }

        async fn handle_uni_stream(self: Arc<Self>, mut recv: RecvStream) -> anyhow::Result<()> {
            let Ok(stream_type) = read_varint(&mut recv).await else {
                return Ok(());
            };
            match stream_type {
                STREAM_TYPE_CONTROL => self.handle_control_stream(&mut recv).await,
                STREAM_TYPE_PUSH | STREAM_TYPE_QPACK_ENCODER | STREAM_TYPE_QPACK_DECODER => {
                    // No dynamic table is advertised and pushes are never enabled, so these
                    // streams carry nothing this client acts on; draining keeps flow control open.
                    let mut buf = [0u8; 1024];
                    while matches!(recv.read(&mut buf).await, Ok(Some(_))) {}
                    Ok(())
                }
                _ => {
                    self.close_with_error(H3_STREAM_CREATION_ERROR, "unknown stream type");
                    Err(anyhow!("http3: unknown stream type: {stream_type}"))
                }
            }
        }

        async fn handle_control_stream(self: &Arc<Self>, recv: &mut RecvStream) -> anyhow::Result<()> {
            let Ok((frame_type, length)) = read_frame_header(recv).await else {
                self.close_with_error(H3_MISSING_SETTINGS, "missing SETTINGS frame");
                return Err(anyhow!("http3: missing SETTINGS frame"));
            };
            if frame_type != FRAME_SETTINGS {
                self.close_with_error(H3_MISSING_SETTINGS, "missing SETTINGS frame");
                return Err(anyhow!("http3: missing SETTINGS frame"));
            }
            if length > MAX_SETTINGS_FRAME_LEN {
                self.close_with_error(H3_EXCESSIVE_LOAD, "SETTINGS frame too large");
                return Err(anyhow!("http3: SETTINGS frame exceeds {MAX_SETTINGS_FRAME_LEN} bytes"));
            }
            let payload = read_payload_capped(recv, length, MAX_SETTINGS_FRAME_LEN).await?;
            let settings = parse_settings(&payload).inspect_err(|_err| {
                self.close_with_error(H3_SETTINGS_ERROR, "invalid SETTINGS frame");
            })?;
            *self.settings.lock() = Some(settings);
            self.settings_notify.notify_waiters();

            loop {
                let (frame_type, length) = match read_frame_header(recv).await {
                    Ok(header) => header,
                    Err(err) => {
                        if err.is::<Eof>() {
                            self.close_with_error(H3_CLOSED_CRITICAL_STREAM, "control stream closed");
                        }
                        return Err(err);
                    }
                };
                if frame_type == FRAME_SETTINGS {
                    self.close_with_error(H3_FRAME_UNEXPECTED, "duplicate SETTINGS frame");
                    return Err(anyhow!("http3: duplicate SETTINGS frame"));
                }
                discard(recv, length).await?;
            }
        }

        async fn drive_datagrams(self: Arc<Self>) {
            loop {
                let Ok(datagram) = self.quic.read_datagram().await else {
                    return;
                };
                let Ok((quarter_stream_id, offset)) = quicvarint::parse(&datagram) else {
                    self.close_with_error(H3_DATAGRAM_ERROR, "could not read quarter stream id");
                    return;
                };
                if quarter_stream_id > MAX_QUARTER_STREAM_ID {
                    self.close_with_error(H3_DATAGRAM_ERROR, "invalid quarter stream id");
                    return;
                }
                let sender = self.datagram_streams.lock().get(&(quarter_stream_id * 4)).cloned();
                if let Some(sender) = sender {
                    // A full queue drops the datagram, like the per-stream queue.
                    let _ = sender.try_send(datagram.slice(offset..));
                }
            }
        }

        fn unregister_datagram_stream(&self, stream_id: u64) {
            self.datagram_streams.lock().remove(&stream_id);
        }

        fn register_datagram_stream(self: &Arc<Self>, stream_id: u64) -> DatagramReceiver {
            let (sender, receiver) = mpsc::channel(STREAM_DATAGRAM_QUEUE_LEN);
            let mut streams = self.datagram_streams.lock();
            prune_closed_datagram_streams(&mut streams);
            streams.insert(stream_id, sender);
            drop(streams);
            DatagramReceiver { conn: Arc::clone(self), stream_id, receiver }
        }

        /// Sends a datagram, prefixing the quarter stream ID.
        pub fn send_datagram(&self, stream_id: u64, data: &[u8]) -> anyhow::Result<()> {
            let mut buf: Vec<u8> = Vec::with_capacity(data.len() + 8);
            quicvarint::append(&mut buf, stream_id / 4);
            buf.extend_from_slice(data);
            match self.quic.send_datagram(Bytes::from(buf)) {
                Ok(()) => Ok(()),
                Err(quinn::SendDatagramError::TooLarge) => {
                    Err(anyhow::Error::new(super::connectip::DatagramTooLargeError))
                }
                Err(err) => Err(anyhow!("{err}")),
            }
        }

        pub fn close_with_error(&self, code: u32, reason: &str) {
            self.quic.close(VarInt::from_u32(code), reason.as_bytes());
        }

        pub fn settings(&self) -> Option<Settings> {
            self.settings.lock().clone()
        }

        /// Yields the peer's SETTINGS frame.
        // cancel-safe: the state is re-read before every await, so a dropped wait loses nothing.
        pub async fn received_settings(&self) -> Settings {
            loop {
                if let Some(settings) = self.settings() {
                    return settings;
                }
                let notified = self.settings_notify.notified();
                if let Some(settings) = self.settings() {
                    return settings;
                }
                notified.await;
            }
        }

        // cancel-safe: the closed-notification is a state quinn keeps, so a dropped wait loses
        // nothing.
        pub async fn context_done(&self) {
            let _ = self.quic.closed().await;
        }

        pub fn context_cause(&self) -> anyhow::Error {
            match self.quic.close_reason() {
                Some(err) => anyhow!("{err}"),
                None => super::context_canceled(),
            }
        }

        pub const fn quic_conn(&self) -> &quinn::Connection {
            &self.quic
        }

        pub async fn open_request_stream(
            self: &Arc<Self>,
            ctx: Option<&CancellationToken>,
        ) -> anyhow::Result<RequestStream> {
            let (send, recv) = tokio::select! {
                () = cancel(ctx) => return Err(super::context_canceled()),
                opened = self.quic.open_bi() => opened.map_err(|err| anyhow!("{err}"))?,
            };
            // Client-initiated bidirectional streams are numbered `index * 4`.
            let stream_id = send.id().index() << 2;
            let datagrams = self.register_datagram_stream(stream_id);
            Ok(RequestStream {
                send: StreamSend { conn: Arc::clone(self), stream_id, send, header: Vec::new(), payload_remaining: 0 },
                recv: StreamRecv {
                    conn: Arc::clone(self),
                    recv,
                    bytes_remaining_in_frame: 0,
                    parsed_trailer: false,
                    header: HeaderVarint::default(),
                    header_is_length: false,
                    frame_type: 0,
                    skip_remaining: 0,
                },
                datagrams,
            })
        }
    }

    /// Completion of an optional context, the select case the caller waits on.
    async fn cancel(ctx: Option<&CancellationToken>) {
        match ctx {
            Some(ctx) => ctx.cancelled().await,
            None => std::future::pending().await,
        }
    }

    /// The send side of a stream, which frames payloads in DATA frames.
    pub struct StreamSend {
        conn: Arc<ClientConn>,
        stream_id: u64,
        send: SendStream,
        /// Staged header of the DATA frame whose payload is still being written.
        header: Vec<u8>,
        payload_remaining: usize,
    }

    impl fmt::Debug for StreamSend {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("StreamSend").field("stream_id", &self.stream_id).finish_non_exhaustive()
        }
    }

    impl StreamSend {
        #[must_use]
        pub const fn stream_id(&self) -> u64 {
            self.stream_id
        }

        pub async fn write(&mut self, buf: &[u8]) -> anyhow::Result<()> {
            self.header.clear();
            self.payload_remaining = 0;
            let mut frame: Vec<u8> = Vec::with_capacity(buf.len() + 9);
            quicvarint::append(&mut frame, FRAME_DATA);
            quicvarint::append(&mut frame, buf.len() as u64);
            frame.extend_from_slice(buf);
            self.send.write_all(&frame).await.map_err(|err| anyhow!("{err}"))
        }

        /// The `AsyncWrite` side of the stream, framing `buf` in a DATA frame.
        pub fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            if self.payload_remaining == 0 {
                self.header.clear();
                quicvarint::append(&mut self.header, FRAME_DATA);
                quicvarint::append(&mut self.header, buf.len() as u64);
                self.payload_remaining = buf.len();
            }
            while !self.header.is_empty() {
                match Pin::new(&mut self.send).poll_write(cx, &self.header) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                    Poll::Ready(Ok(n)) => {
                        let remaining = self.header.len() - n;
                        self.header.copy_within(n.., 0);
                        self.header.truncate(remaining);
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(io::Error::other(err))),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            match Pin::new(&mut self.send).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => {
                    self.payload_remaining -= n;
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(io::Error::other(err))),
                Poll::Pending => Poll::Pending,
            }
        }

        /// Ends the send direction.
        pub fn finish(&mut self) -> anyhow::Result<()> {
            self.send.finish().map_err(|err| anyhow!("{err}"))
        }

        pub fn reset(&mut self, code: u32) {
            let _ = self.send.reset(VarInt::from_u32(code));
        }

        pub fn send_datagram(&self, data: &[u8]) -> anyhow::Result<()> {
            self.conn.send_datagram(self.stream_id, data)
        }
    }

    /// The frame-header varint currently being read, byte by byte.
    #[derive(Debug, Default, Clone, Copy)]
    struct HeaderVarint {
        value: u64,
        read: u8,
        total: u8,
    }

    impl HeaderVarint {
        fn reset(&mut self) {
            *self = Self::default();
        }

        /// Steps by one byte; `true` once the varint is complete.
        fn step(&mut self, byte: u8) -> bool {
            if self.read == 0 {
                self.total = 1 << (byte >> 6);
                self.value = u64::from(byte & 0x3f);
            } else {
                self.value = (self.value << 8) | u64::from(byte);
            }
            self.read += 1;
            self.read >= self.total
        }
    }

    /// The receive side of a stream, with the DATA framing of a request stream.
    pub struct StreamRecv {
        conn: Arc<ClientConn>,
        recv: RecvStream,
        bytes_remaining_in_frame: u64,
        parsed_trailer: bool,
        header: HeaderVarint,
        header_is_length: bool,
        frame_type: u64,
        skip_remaining: u64,
    }

    impl fmt::Debug for StreamRecv {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("StreamRecv").field("frame_type", &self.frame_type).finish_non_exhaustive()
        }
    }

    impl StreamRecv {
        #[must_use]
        pub fn stream_id(&self) -> u64 {
            self.recv.id().index() << 2
        }

        /// The `AsyncRead` side of the stream: the payloads of its DATA frames.
        pub fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
            loop {
                if self.bytes_remaining_in_frame > 0 {
                    let len = usize::try_from(self.bytes_remaining_in_frame).unwrap_or(usize::MAX).min(buf.len());
                    if len == 0 {
                        return Poll::Ready(Ok(0));
                    }
                    let (stage, _rest) = buf.split_at_mut(len);
                    return match self.recv.poll_read(cx, stage) {
                        Poll::Ready(Ok(0)) => Poll::Ready(Err(unexpected_eof())),
                        Poll::Ready(Ok(n)) => {
                            self.bytes_remaining_in_frame -= n as u64;
                            Poll::Ready(Ok(n))
                        }
                        Poll::Ready(Err(err)) => Poll::Ready(Err(io::Error::other(err))),
                        Poll::Pending => Poll::Pending,
                    };
                }
                if self.skip_remaining > 0 {
                    let mut scratch = [0u8; 1024];
                    let len = usize::try_from(self.skip_remaining).unwrap_or(usize::MAX).min(scratch.len());
                    let (stage, _rest) = scratch.split_at_mut(len);
                    match self.recv.poll_read(cx, stage) {
                        Poll::Ready(Ok(0)) => return Poll::Ready(Err(unexpected_eof())),
                        Poll::Ready(Ok(n)) => {
                            self.skip_remaining -= n as u64;
                            continue;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(io::Error::other(err))),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                let mut byte = [0u8; 1];
                match self.recv.poll_read(cx, &mut byte) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(io::Error::other(err))),
                    Poll::Pending => return Poll::Pending,
                }
                if !self.header.step(byte[0]) {
                    continue;
                }
                if !self.header_is_length {
                    self.frame_type = self.header.value;
                    self.header.reset();
                    self.header_is_length = true;
                    continue;
                }

                let length = self.header.value;
                self.header.reset();
                self.header_is_length = false;
                match self.frame_type {
                    FRAME_DATA => {
                        if self.parsed_trailer {
                            return Poll::Ready(Err(io::Error::other("DATA frame received after trailers")));
                        }
                        self.bytes_remaining_in_frame = length;
                    }
                    FRAME_HEADERS => {
                        if self.parsed_trailer {
                            return Poll::Ready(Err(io::Error::other(
                                "additional HEADERS frame received after trailers",
                            )));
                        }
                        self.parsed_trailer = true;
                        // Trailers are not surfaced, so the field section is skipped.
                        self.skip_remaining = length;
                    }
                    frame_type if is_known_frame(frame_type) => {
                        self.conn.close_with_error(H3_FRAME_UNEXPECTED, "unexpected frame");
                        return Poll::Ready(Err(io::Error::other(format!(
                            "peer sent an unexpected frame: type {frame_type}"
                        ))));
                    }
                    _ => self.skip_remaining = length,
                }
            }
        }

        /// Reads from the stream; a zero-length return stands for end of stream.
        pub async fn read(&mut self, buf: &mut [u8]) -> anyhow::Result<usize> {
            std::future::poll_fn(|cx| self.poll_read(cx, buf)).await.map_err(anyhow::Error::from)
        }

        /// Reads exactly the buffer's length from the stream's content.
        pub async fn read_exact(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
            let mut offset = 0;
            while offset < buf.len() {
                let (_, remaining) = buf.split_at_mut(offset);
                match self.read(remaining).await? {
                    0 => return Err(anyhow!("unexpected EOF")),
                    n => offset += n,
                }
            }
            Ok(())
        }

        pub async fn read_byte(&mut self) -> anyhow::Result<u8> {
            let mut buf = [0u8; 1];
            self.read_exact(&mut buf).await?;
            Ok(buf[0])
        }

        pub fn stop(&mut self, code: u32) {
            let _ = self.recv.stop(VarInt::from_u32(code));
        }

        /// The next frame header of the response body; `None` at a clean end of stream.
        async fn next_frame(&mut self) -> anyhow::Result<Option<(u64, u64)>> {
            match read_frame_header(&mut self.recv).await {
                Ok(header) => Ok(Some(header)),
                Err(err) if err.is::<Eof>() => Ok(None),
                Err(err) => Err(err),
            }
        }

        async fn read_payload(&mut self, length: u64) -> anyhow::Result<Vec<u8>> {
            read_payload_capped(&mut self.recv, length, DEFAULT_MAX_FIELD_SECTION_SIZE).await
        }
    }

    fn unexpected_eof() -> io::Error {
        io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
    }

    #[async_trait]
    impl quicvarint::Reader for StreamRecv {
        async fn read_byte(&mut self) -> anyhow::Result<u8> {
            Self::read_byte(self).await
        }
    }

    /// Local mirror of the request fields the HTTP/3 request writer consumes.
    #[derive(Debug, Clone)]
    pub struct RequestHead {
        pub method: http::Method,
        /// The protocol: for CONNECT this is the extended CONNECT `:protocol` value.
        pub proto: String,
        pub host: String,
        pub header: http::HeaderMap,
        pub url: http::Uri,
    }

    impl RequestHead {
        fn is_extended_connect(&self) -> bool {
            self.method == http::Method::CONNECT && !self.proto.is_empty() && self.proto != "HTTP/1.1"
        }

        /// The header list in the order it is written.
        fn encode_fields(&self) -> anyhow::Result<Vec<(String, String)>> {
            let mut host = self.host.clone();
            if host.is_empty() {
                host = self.url.authority().map(|authority| authority.as_str().to_owned()).unwrap_or_default();
            }
            let host = punycode_host_port(&host);
            if !valid_host_header(&host) {
                return Err(anyhow!("http3: invalid Host header"));
            }

            let is_extended_connect = self.is_extended_connect();
            if is_extended_connect && !valid_extended_connect_protocol(&self.proto) {
                return Err(anyhow!("invalid request :protocol {:?}", self.proto));
            }

            let mut path = String::new();
            if self.method != http::Method::CONNECT || is_extended_connect {
                path = self.url.path_and_query().map(|path| path.as_str().to_owned()).unwrap_or_default();
                if path.is_empty() {
                    "/".clone_into(&mut path);
                }
                if !valid_pseudo_path(&path) {
                    return Err(anyhow!("invalid request :path {path:?}"));
                }
            }

            for (name, value) in &self.header {
                let name = name.as_str();
                if !valid_header_field_name(name) {
                    return Err(anyhow!("invalid HTTP header name {name:?}"));
                }
                if !valid_header_field_value(value.to_str().unwrap_or_default()) {
                    return Err(anyhow!("invalid HTTP header value for header {name:?}"));
                }
            }

            let mut fields: Vec<(String, String)> = Vec::new();
            fields.push((":authority".to_owned(), host));
            fields.push((":method".to_owned(), self.method.as_str().to_owned()));
            if self.method != http::Method::CONNECT || is_extended_connect {
                fields.push((":path".to_owned(), path));
                fields.push((":scheme".to_owned(), self.url.scheme_str().unwrap_or("https").to_owned()));
            }
            if is_extended_connect {
                fields.push((":protocol".to_owned(), self.proto.clone()));
            }

            let mut did_user_agent = false;
            for (name, value) in &self.header {
                let name = name.as_str();
                if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
                    continue;
                }
                if CONNECTION_SPECIFIC.iter().any(|specific| name.eq_ignore_ascii_case(specific)) {
                    continue;
                }
                let value = value.to_str().unwrap_or_default();
                if name.eq_ignore_ascii_case("user-agent") {
                    // At most one User-Agent is emitted, and an empty one is dropped.
                    did_user_agent = true;
                    if value.is_empty() {
                        continue;
                    }
                }
                fields.push((name.to_ascii_lowercase(), value.to_owned()));
            }
            if !did_user_agent {
                fields.push(("user-agent".to_owned(), DEFAULT_USER_AGENT.to_owned()));
            }
            Ok(fields)
        }
    }

    /// Punycode host-port conversion needs an IDN implementation, which no pinned crate provides;
    /// hosts are passed through unchanged, which is exact for ASCII hosts.
    fn punycode_host_port(host: &str) -> String {
        host.to_owned()
    }

    fn valid_host_header(host: &str) -> bool {
        !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~%!$&'()*+,;=:[]@".contains(&b))
    }

    fn valid_pseudo_path(path: &str) -> bool {
        path.starts_with('/') && path.bytes().all(|b| b > 0x20 && b < 0x7f)
    }

    fn valid_header_field_name(name: &str) -> bool {
        !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    }

    fn valid_header_field_value(value: &str) -> bool {
        !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
    }

    fn valid_extended_connect_protocol(value: &str) -> bool {
        valid_header_field_name(value)
    }

    /// The receive half of a request stream's datagrams. It owns the connection's routing entry for
    /// the stream, so dropping it removes that entry and the table stays bounded by the streams
    /// that are still alive.
    pub struct DatagramReceiver {
        conn: Arc<ClientConn>,
        stream_id: u64,
        receiver: mpsc::Receiver<Bytes>,
    }

    impl fmt::Debug for DatagramReceiver {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("DatagramReceiver").field("stream_id", &self.stream_id).finish_non_exhaustive()
        }
    }

    impl DatagramReceiver {
        /// The next datagram of the stream; `None` once the connection's dispatcher is gone.
        // cancel-safe: a channel `recv` leaves the item queued, so a dropped call loses nothing.
        pub async fn recv(&mut self) -> Option<Bytes> {
            self.receiver.recv().await
        }
    }

    impl Drop for DatagramReceiver {
        fn drop(&mut self) {
            self.conn.unregister_datagram_stream(self.stream_id);
        }
    }

    /// A request stream, with the request head written by [`RequestStream::send_request_header`].
    pub struct RequestStream {
        send: StreamSend,
        recv: StreamRecv,
        datagrams: DatagramReceiver,
    }

    impl fmt::Debug for RequestStream {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("RequestStream").field("stream_id", &self.stream_id()).finish_non_exhaustive()
        }
    }

    impl RequestStream {
        #[must_use]
        pub fn stream_id(&self) -> u64 {
            self.send.stream_id()
        }

        #[must_use]
        pub const fn conn(&self) -> &Arc<ClientConn> {
            &self.send.conn
        }

        pub async fn send_request_header(&mut self, head: &RequestHead) -> anyhow::Result<()> {
            let fields = head.encode_fields()?;
            let block = qpack::encode_fields(&fields);
            let mut frame: Vec<u8> = Vec::with_capacity(block.len() + 9);
            quicvarint::append(&mut frame, FRAME_HEADERS);
            quicvarint::append(&mut frame, block.len() as u64);
            frame.extend_from_slice(&block);
            self.send.send.write_all(&frame).await.map_err(|err| anyhow!("{err}"))
        }

        pub async fn read_response(&mut self) -> anyhow::Result<HttpResponse> {
            let mut preamble_bytes: u64 = 0;
            let mut interim_responses: u64 = 0;
            loop {
                let Some((frame_type, length)) = self.recv.next_frame().await? else {
                    self.send.conn.close_with_error(H3_REQUEST_INCOMPLETE, "request stream closed before response");
                    return Err(anyhow!("http3: request stream closed before response"));
                };
                if frame_type == FRAME_HEADERS && length > DEFAULT_MAX_FIELD_SECTION_SIZE {
                    self.send.conn.close_with_error(H3_EXCESSIVE_LOAD, "response headers too large");
                    return Err(anyhow!("http3: response headers too large"));
                }
                preamble_bytes = preamble_bytes.saturating_add(length);
                if preamble_bytes > MAX_RESPONSE_PREAMBLE_BYTES {
                    self.send.conn.close_with_error(H3_EXCESSIVE_LOAD, "response preamble too large");
                    return Err(anyhow!("http3: response frames exceed {MAX_RESPONSE_PREAMBLE_BYTES} bytes"));
                }
                match frame_type {
                    FRAME_HEADERS => {
                        let block = self.recv.read_payload(length).await?;
                        let fields = qpack::decode_headers(&block).inspect_err(|_err| {
                            self.send
                                .conn
                                .close_with_error(QPACK_DECOMPRESSION_FAILED, "invalid response header block");
                        })?;
                        let status_code = status_from_fields(&fields)?;
                        if (100..200).contains(&status_code) {
                            interim_responses += 1;
                            if interim_responses > MAX_INTERIM_RESPONSES {
                                self.send.conn.close_with_error(H3_EXCESSIVE_LOAD, "too many informational responses");
                                return Err(anyhow!(
                                    "http3: more than {MAX_INTERIM_RESPONSES} informational responses before the final response"
                                ));
                            }
                            // Informational responses precede the final one.
                            continue;
                        }
                        let mut header = http::HeaderMap::new();
                        for (name, value) in &fields {
                            if name.starts_with(':') {
                                continue;
                            }
                            if let (Ok(name), Ok(value)) =
                                (http::HeaderName::try_from(name.as_str()), http::HeaderValue::try_from(value.as_str()))
                            {
                                header.append(name, value);
                            }
                        }
                        return Ok(HttpResponse::new(status_code, header));
                    }
                    FRAME_DATA => return Err(anyhow!("http3: DATA frame before the response headers")),
                    frame_type if is_known_frame(frame_type) => {
                        self.send.conn.close_with_error(H3_FRAME_UNEXPECTED, "unexpected frame");
                        return Err(anyhow!("peer sent an unexpected frame: type {frame_type}"));
                    }
                    _ => discard(&mut self.recv.recv, length).await?,
                }
            }
        }

        pub async fn read(&mut self, buf: &mut [u8]) -> anyhow::Result<usize> {
            self.recv.read(buf).await
        }

        pub async fn write(&mut self, buf: &[u8]) -> anyhow::Result<()> {
            self.send.write(buf).await
        }

        pub async fn receive_datagram(&mut self, ctx: Option<&CancellationToken>) -> anyhow::Result<Vec<u8>> {
            let received = tokio::select! {
                () = cancel(ctx) => return Err(super::context_canceled()),
                received = self.datagrams.recv() => received,
            };
            match received {
                Some(data) => Ok(data.to_vec()),
                None => Err(anyhow!("http3: datagram stream closed")),
            }
        }

        pub fn send_datagram(&self, data: &[u8]) -> anyhow::Result<()> {
            self.send.send_datagram(data)
        }

        pub fn cancel_read(&mut self, code: u32) {
            self.recv.stop(code);
        }

        pub fn cancel_write(&mut self, code: u32) {
            self.send.reset(code);
        }

        /// Closes only the send direction.
        pub fn close(&mut self) -> anyhow::Result<()> {
            self.send.finish()
        }

        #[must_use]
        pub fn split(self) -> (StreamSend, StreamRecv, DatagramReceiver) {
            (self.send, self.recv, self.datagrams)
        }
    }

    fn status_from_fields(fields: &[(String, String)]) -> anyhow::Result<u16> {
        for (name, value) in fields {
            if name == ":status" {
                return value.parse::<u16>().map_err(|_| anyhow!("http3: invalid :status {value:?}"));
            }
        }
        Err(anyhow!("http3: missing :status"))
    }

    /// The QPACK subset this client needs: static-table and literal representations only, so no
    /// dynamic table is used and none has to be advertised.
    mod qpack {
        use anyhow::anyhow;

        /// RFC 9204 Appendix A static table, in wire order.
        const STATIC_TABLE: [(&str, &str); 99] = [
            (":authority", ""),
            (":path", "/"),
            ("age", "0"),
            ("content-disposition", ""),
            ("content-length", "0"),
            ("cookie", ""),
            ("date", ""),
            ("etag", ""),
            ("if-modified-since", ""),
            ("if-none-match", ""),
            ("last-modified", ""),
            ("link", ""),
            ("location", ""),
            ("referer", ""),
            ("set-cookie", ""),
            (":method", "CONNECT"),
            (":method", "DELETE"),
            (":method", "GET"),
            (":method", "HEAD"),
            (":method", "OPTIONS"),
            (":method", "POST"),
            (":method", "PUT"),
            (":scheme", "http"),
            (":scheme", "https"),
            (":status", "103"),
            (":status", "200"),
            (":status", "304"),
            (":status", "404"),
            (":status", "503"),
            ("accept", "*/*"),
            ("accept", "application/dns-message"),
            ("accept-encoding", "gzip, deflate, br"),
            ("accept-ranges", "bytes"),
            ("access-control-allow-headers", "cache-control"),
            ("access-control-allow-headers", "content-type"),
            ("access-control-allow-origin", "*"),
            ("cache-control", "max-age=0"),
            ("cache-control", "max-age=2592000"),
            ("cache-control", "max-age=604800"),
            ("cache-control", "no-cache"),
            ("cache-control", "no-store"),
            ("cache-control", "public, max-age=31536000"),
            ("content-encoding", "br"),
            ("content-encoding", "gzip"),
            ("content-type", "application/dns-message"),
            ("content-type", "application/javascript"),
            ("content-type", "application/json"),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-type", "image/gif"),
            ("content-type", "image/jpeg"),
            ("content-type", "image/png"),
            ("content-type", "text/css"),
            ("content-type", "text/html; charset=utf-8"),
            ("content-type", "text/plain"),
            ("content-type", "text/plain;charset=utf-8"),
            ("range", "bytes=0-"),
            ("strict-transport-security", "max-age=31536000"),
            ("strict-transport-security", "max-age=31536000; includesubdomains"),
            ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
            ("vary", "accept-encoding"),
            ("vary", "origin"),
            ("x-content-type-options", "nosniff"),
            ("x-xss-protection", "1; mode=block"),
            (":status", "100"),
            (":status", "204"),
            (":status", "206"),
            (":status", "302"),
            (":status", "400"),
            (":status", "403"),
            (":status", "421"),
            (":status", "425"),
            (":status", "500"),
            ("accept-language", ""),
            ("access-control-allow-credentials", "FALSE"),
            ("access-control-allow-credentials", "TRUE"),
            ("access-control-allow-headers", "*"),
            ("access-control-allow-methods", "get"),
            ("access-control-allow-methods", "get, post, options"),
            ("access-control-allow-methods", "options"),
            ("access-control-expose-headers", "content-length"),
            ("access-control-request-headers", "content-type"),
            ("access-control-request-method", "get"),
            ("access-control-request-method", "post"),
            ("alt-svc", "clear"),
            ("authorization", ""),
            ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
            ("early-data", "1"),
            ("expect-ct", ""),
            ("forwarded", ""),
            ("if-range", ""),
            ("origin", ""),
            ("purpose", "prefetch"),
            ("server", ""),
            ("timing-allow-origin", "*"),
            ("upgrade-insecure-requests", "1"),
            ("user-agent", ""),
            ("x-forwarded-for", ""),
            ("x-frame-options", "deny"),
            ("x-frame-options", "sameorigin"),
        ];

        /// RFC 7541 Appendix B Huffman code, sorted by bit length then code; symbol 256 is EOS.
        const HUFFMAN_CODES: [(u8, u32, u16); 257] = [
            (5, 0x0, 48),
            (5, 0x1, 49),
            (5, 0x2, 50),
            (5, 0x3, 97),
            (5, 0x4, 99),
            (5, 0x5, 101),
            (5, 0x6, 105),
            (5, 0x7, 111),
            (5, 0x8, 115),
            (5, 0x9, 116),
            (6, 0x14, 32),
            (6, 0x15, 37),
            (6, 0x16, 45),
            (6, 0x17, 46),
            (6, 0x18, 47),
            (6, 0x19, 51),
            (6, 0x1a, 52),
            (6, 0x1b, 53),
            (6, 0x1c, 54),
            (6, 0x1d, 55),
            (6, 0x1e, 56),
            (6, 0x1f, 57),
            (6, 0x20, 61),
            (6, 0x21, 65),
            (6, 0x22, 95),
            (6, 0x23, 98),
            (6, 0x24, 100),
            (6, 0x25, 102),
            (6, 0x26, 103),
            (6, 0x27, 104),
            (6, 0x28, 108),
            (6, 0x29, 109),
            (6, 0x2a, 110),
            (6, 0x2b, 112),
            (6, 0x2c, 114),
            (6, 0x2d, 117),
            (7, 0x5c, 58),
            (7, 0x5d, 66),
            (7, 0x5e, 67),
            (7, 0x5f, 68),
            (7, 0x60, 69),
            (7, 0x61, 70),
            (7, 0x62, 71),
            (7, 0x63, 72),
            (7, 0x64, 73),
            (7, 0x65, 74),
            (7, 0x66, 75),
            (7, 0x67, 76),
            (7, 0x68, 77),
            (7, 0x69, 78),
            (7, 0x6a, 79),
            (7, 0x6b, 80),
            (7, 0x6c, 81),
            (7, 0x6d, 82),
            (7, 0x6e, 83),
            (7, 0x6f, 84),
            (7, 0x70, 85),
            (7, 0x71, 86),
            (7, 0x72, 87),
            (7, 0x73, 89),
            (7, 0x74, 106),
            (7, 0x75, 107),
            (7, 0x76, 113),
            (7, 0x77, 118),
            (7, 0x78, 119),
            (7, 0x79, 120),
            (7, 0x7a, 121),
            (7, 0x7b, 122),
            (8, 0xf8, 38),
            (8, 0xf9, 42),
            (8, 0xfa, 44),
            (8, 0xfb, 59),
            (8, 0xfc, 88),
            (8, 0xfd, 90),
            (10, 0x3f8, 33),
            (10, 0x3f9, 34),
            (10, 0x3fa, 40),
            (10, 0x3fb, 41),
            (10, 0x3fc, 63),
            (11, 0x7fa, 39),
            (11, 0x7fb, 43),
            (11, 0x7fc, 124),
            (12, 0xffa, 35),
            (12, 0xffb, 62),
            (13, 0x1ff8, 0),
            (13, 0x1ff9, 36),
            (13, 0x1ffa, 64),
            (13, 0x1ffb, 91),
            (13, 0x1ffc, 93),
            (13, 0x1ffd, 126),
            (14, 0x3ffc, 94),
            (14, 0x3ffd, 125),
            (15, 0x7ffc, 60),
            (15, 0x7ffd, 96),
            (15, 0x7ffe, 123),
            (19, 0x7fff0, 92),
            (19, 0x7fff1, 195),
            (19, 0x7fff2, 208),
            (20, 0xfffe6, 128),
            (20, 0xfffe7, 130),
            (20, 0xfffe8, 131),
            (20, 0xfffe9, 162),
            (20, 0xfffea, 184),
            (20, 0xfffeb, 194),
            (20, 0xfffec, 224),
            (20, 0xfffed, 226),
            (21, 0x1fffdc, 153),
            (21, 0x1fffdd, 161),
            (21, 0x1fffde, 167),
            (21, 0x1fffdf, 172),
            (21, 0x1fffe0, 176),
            (21, 0x1fffe1, 177),
            (21, 0x1fffe2, 179),
            (21, 0x1fffe3, 209),
            (21, 0x1fffe4, 216),
            (21, 0x1fffe5, 217),
            (21, 0x1fffe6, 227),
            (21, 0x1fffe7, 229),
            (21, 0x1fffe8, 230),
            (22, 0x3fffd2, 129),
            (22, 0x3fffd3, 132),
            (22, 0x3fffd4, 133),
            (22, 0x3fffd5, 134),
            (22, 0x3fffd6, 136),
            (22, 0x3fffd7, 146),
            (22, 0x3fffd8, 154),
            (22, 0x3fffd9, 156),
            (22, 0x3fffda, 160),
            (22, 0x3fffdb, 163),
            (22, 0x3fffdc, 164),
            (22, 0x3fffdd, 169),
            (22, 0x3fffde, 170),
            (22, 0x3fffdf, 173),
            (22, 0x3fffe0, 178),
            (22, 0x3fffe1, 181),
            (22, 0x3fffe2, 185),
            (22, 0x3fffe3, 186),
            (22, 0x3fffe4, 187),
            (22, 0x3fffe5, 189),
            (22, 0x3fffe6, 190),
            (22, 0x3fffe7, 196),
            (22, 0x3fffe8, 198),
            (22, 0x3fffe9, 228),
            (22, 0x3fffea, 232),
            (22, 0x3fffeb, 233),
            (23, 0x7fffd8, 1),
            (23, 0x7fffd9, 135),
            (23, 0x7fffda, 137),
            (23, 0x7fffdb, 138),
            (23, 0x7fffdc, 139),
            (23, 0x7fffdd, 140),
            (23, 0x7fffde, 141),
            (23, 0x7fffdf, 143),
            (23, 0x7fffe0, 147),
            (23, 0x7fffe1, 149),
            (23, 0x7fffe2, 150),
            (23, 0x7fffe3, 151),
            (23, 0x7fffe4, 152),
            (23, 0x7fffe5, 155),
            (23, 0x7fffe6, 157),
            (23, 0x7fffe7, 158),
            (23, 0x7fffe8, 165),
            (23, 0x7fffe9, 166),
            (23, 0x7fffea, 168),
            (23, 0x7fffeb, 174),
            (23, 0x7fffec, 175),
            (23, 0x7fffed, 180),
            (23, 0x7fffee, 182),
            (23, 0x7fffef, 183),
            (23, 0x7ffff0, 188),
            (23, 0x7ffff1, 191),
            (23, 0x7ffff2, 197),
            (23, 0x7ffff3, 231),
            (23, 0x7ffff4, 239),
            (24, 0xffffea, 9),
            (24, 0xffffeb, 142),
            (24, 0xffffec, 144),
            (24, 0xffffed, 145),
            (24, 0xffffee, 148),
            (24, 0xffffef, 159),
            (24, 0xfffff0, 171),
            (24, 0xfffff1, 206),
            (24, 0xfffff2, 215),
            (24, 0xfffff3, 225),
            (24, 0xfffff4, 236),
            (24, 0xfffff5, 237),
            (25, 0x1ffffec, 199),
            (25, 0x1ffffed, 207),
            (25, 0x1ffffee, 234),
            (25, 0x1ffffef, 235),
            (26, 0x3ffffe0, 192),
            (26, 0x3ffffe1, 193),
            (26, 0x3ffffe2, 200),
            (26, 0x3ffffe3, 201),
            (26, 0x3ffffe4, 202),
            (26, 0x3ffffe5, 205),
            (26, 0x3ffffe6, 210),
            (26, 0x3ffffe7, 213),
            (26, 0x3ffffe8, 218),
            (26, 0x3ffffe9, 219),
            (26, 0x3ffffea, 238),
            (26, 0x3ffffeb, 240),
            (26, 0x3ffffec, 242),
            (26, 0x3ffffed, 243),
            (26, 0x3ffffee, 255),
            (27, 0x7ffffde, 203),
            (27, 0x7ffffdf, 204),
            (27, 0x7ffffe0, 211),
            (27, 0x7ffffe1, 212),
            (27, 0x7ffffe2, 214),
            (27, 0x7ffffe3, 221),
            (27, 0x7ffffe4, 222),
            (27, 0x7ffffe5, 223),
            (27, 0x7ffffe6, 241),
            (27, 0x7ffffe7, 244),
            (27, 0x7ffffe8, 245),
            (27, 0x7ffffe9, 246),
            (27, 0x7ffffea, 247),
            (27, 0x7ffffeb, 248),
            (27, 0x7ffffec, 250),
            (27, 0x7ffffed, 251),
            (27, 0x7ffffee, 252),
            (27, 0x7ffffef, 253),
            (27, 0x7fffff0, 254),
            (28, 0xfffffe2, 2),
            (28, 0xfffffe3, 3),
            (28, 0xfffffe4, 4),
            (28, 0xfffffe5, 5),
            (28, 0xfffffe6, 6),
            (28, 0xfffffe7, 7),
            (28, 0xfffffe8, 8),
            (28, 0xfffffe9, 11),
            (28, 0xfffffea, 12),
            (28, 0xfffffeb, 14),
            (28, 0xfffffec, 15),
            (28, 0xfffffed, 16),
            (28, 0xfffffee, 17),
            (28, 0xfffffef, 18),
            (28, 0xffffff0, 19),
            (28, 0xffffff1, 20),
            (28, 0xffffff2, 21),
            (28, 0xffffff3, 23),
            (28, 0xffffff4, 24),
            (28, 0xffffff5, 25),
            (28, 0xffffff6, 26),
            (28, 0xffffff7, 27),
            (28, 0xffffff8, 28),
            (28, 0xffffff9, 29),
            (28, 0xffffffa, 30),
            (28, 0xffffffb, 31),
            (28, 0xffffffc, 127),
            (28, 0xffffffd, 220),
            (28, 0xffffffe, 249),
            (30, 0x3ffffffc, 10),
            (30, 0x3ffffffd, 13),
            (30, 0x3ffffffe, 22),
            (30, 0x3fffffff, 256),
        ];

        fn static_entry(index: u64) -> Option<(&'static str, &'static str)> {
            usize::try_from(index).ok().and_then(|index| STATIC_TABLE.get(index)).copied()
        }

        fn static_index_of_name(name: &str) -> Option<usize> {
            STATIC_TABLE.iter().position(|(candidate, _)| *candidate == name)
        }

        #[expect(
            clippy::cast_possible_truncation,
            reason = "the largest prefix mask is 7 bits, so a value below the mask and every \
                      continuation byte (masked to 7 bits) fit a `u8`"
        )]
        fn write_prefixed_int(out: &mut Vec<u8>, prefix_bits: u8, pattern: u8, value: u64) {
            let mask = (1u64 << prefix_bits) - 1;
            if value < mask {
                out.push(pattern | value as u8);
                return;
            }
            out.push(pattern | mask as u8);
            let mut rest = value - mask;
            while rest >= 128 {
                out.push((rest as u8 & 0x7f) | 0x80);
                rest >>= 7;
            }
            out.push(rest as u8);
        }

        /// Encodes one field, for the encodings this client emits.
        pub(super) fn encode_fields(fields: &[(String, String)]) -> Vec<u8> {
            let mut out: Vec<u8> = Vec::new();
            // Required Insert Count and Delta Base: no dynamic table, so both are zero.
            out.push(0);
            out.push(0);
            for (name, value) in fields {
                if let Some(index) = static_index_of_name(name) {
                    // Literal Field Line with Name Reference, static.
                    write_prefixed_int(&mut out, 4, 0b0101_0000, index as u64);
                } else {
                    // Literal Field Line with Literal Name, without Huffman coding.
                    write_prefixed_int(&mut out, 3, 0b0010_0000, name.len() as u64);
                    out.extend_from_slice(name.as_bytes());
                }
                write_prefixed_int(&mut out, 7, 0b0000_0000, value.len() as u64);
                out.extend_from_slice(value.as_bytes());
            }
            out
        }

        struct BlockReader<'a> {
            buf: &'a [u8],
            offset: usize,
        }

        impl<'a> BlockReader<'a> {
            const fn new(buf: &'a [u8]) -> Self {
                Self { buf, offset: 0 }
            }

            const fn is_empty(&self) -> bool {
                self.offset >= self.buf.len()
            }

            fn peek_byte(&self) -> anyhow::Result<u8> {
                self.buf.get(self.offset).copied().ok_or_else(|| anyhow!("qpack: truncated header block"))
            }

            fn byte(&mut self) -> anyhow::Result<u8> {
                let byte = self.peek_byte()?;
                self.offset += 1;
                Ok(byte)
            }

            fn take(&mut self, length: usize) -> anyhow::Result<&'a [u8]> {
                let end = self.offset.checked_add(length).ok_or_else(|| anyhow!("qpack: truncated header block"))?;
                let bytes = self.buf.get(self.offset..end).ok_or_else(|| anyhow!("qpack: truncated header block"))?;
                self.offset = end;
                Ok(bytes)
            }

            fn read_prefixed_int(&mut self, prefix_bits: u8) -> anyhow::Result<u64> {
                let first = self.byte()?;
                let mask = (1u64 << prefix_bits) - 1;
                self.read_int_tail(u64::from(first) & mask, mask)
            }

            fn read_int_tail(&mut self, value: u64, mask: u64) -> anyhow::Result<u64> {
                if value < mask {
                    return Ok(value);
                }
                let mut value = mask;
                let mut shift = 0u32;
                loop {
                    let byte = self.byte()?;
                    value = value
                        .checked_add(u64::from(byte & 0x7f) << shift)
                        .ok_or_else(|| anyhow!("qpack: integer overflow"))?;
                    if byte & 0x80 == 0 {
                        return Ok(value);
                    }
                    shift += 7;
                    if shift > 56 {
                        return Err(anyhow!("qpack: integer overflow"));
                    }
                }
            }

            fn read_string(&mut self) -> anyhow::Result<String> {
                let first = self.byte()?;
                let huffman = first & 0x80 != 0;
                let length = self.read_int_tail(u64::from(first & 0x7f), 0x7f)?;
                let length = usize::try_from(length).map_err(|_err| anyhow!("qpack: string too long"))?;
                let bytes = self.take(length)?;
                let decoded = if huffman { huffman_decode(bytes)? } else { bytes.to_vec() };
                String::from_utf8(decoded).map_err(|err| anyhow!("qpack: invalid header field value: {err}"))
            }

            fn read_name(&mut self, huffman: bool, length: u64) -> anyhow::Result<String> {
                let length = usize::try_from(length).map_err(|_err| anyhow!("qpack: string too long"))?;
                let bytes = self.take(length)?;
                let decoded = if huffman { huffman_decode(bytes)? } else { bytes.to_vec() };
                String::from_utf8(decoded).map_err(|err| anyhow!("qpack: invalid header field name: {err}"))
            }
        }

        /// Decodes a block without dynamic table references.
        pub(super) fn decode_headers(block: &[u8]) -> anyhow::Result<Vec<(String, String)>> {
            let mut reader = BlockReader::new(block);
            let required_insert_count = reader.read_prefixed_int(8)?;
            let _delta_base = reader.read_prefixed_int(7)?;
            if required_insert_count != 0 {
                return Err(anyhow!(
                    "qpack: dynamic table references are not supported (required insert count {required_insert_count})"
                ));
            }

            let mut fields: Vec<(String, String)> = Vec::new();
            while !reader.is_empty() {
                let first = reader.peek_byte()?;
                if first & 0x80 != 0 {
                    let static_reference = first & 0x40 != 0;
                    let index = reader.read_prefixed_int(6)?;
                    if !static_reference {
                        return Err(anyhow!("qpack: dynamic table reference {index}"));
                    }
                    let (name, value) =
                        static_entry(index).ok_or_else(|| anyhow!("qpack: invalid static index {index}"))?;
                    fields.push((name.to_owned(), value.to_owned()));
                } else if first & 0x40 != 0 {
                    let static_reference = first & 0x10 != 0;
                    let index = reader.read_prefixed_int(4)?;
                    if !static_reference {
                        return Err(anyhow!("qpack: dynamic table reference {index}"));
                    }
                    let (name, _) =
                        static_entry(index).ok_or_else(|| anyhow!("qpack: invalid static index {index}"))?;
                    let value = reader.read_string()?;
                    fields.push((name.to_owned(), value));
                } else if first & 0x20 != 0 {
                    let huffman = first & 0x08 != 0;
                    let name_length = reader.read_prefixed_int(3)?;
                    let name = reader.read_name(huffman, name_length)?;
                    let value = reader.read_string()?;
                    fields.push((name, value));
                } else if first & 0x10 != 0 {
                    return Err(anyhow!("qpack: post-base dynamic table references are not supported"));
                } else {
                    return Err(anyhow!("qpack: post-base dynamic table name references are not supported"));
                }
            }
            Ok(fields)
        }

        /// RFC 7541 section 5.2 Huffman decoding.
        pub(super) fn huffman_decode(input: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut out: Vec<u8> = Vec::with_capacity(input.len());
            let mut code: u32 = 0;
            let mut bits: u8 = 0;
            for byte in input {
                for shift in (0..8).rev() {
                    code = (code << 1) | u32::from((byte >> shift) & 1);
                    bits += 1;
                    let key = (bits, code);
                    if let Ok(index) = HUFFMAN_CODES.binary_search_by(|entry| (entry.0, entry.1).cmp(&key)) {
                        // 256, the EOS symbol, is the only symbol the table defines above `u8::MAX`.
                        let Some(byte) = HUFFMAN_CODES.get(index).and_then(|entry| u8::try_from(entry.2).ok()) else {
                            return Err(anyhow!("qpack: EOS symbol in Huffman-coded string"));
                        };
                        out.push(byte);
                        code = 0;
                        bits = 0;
                    }
                }
            }
            if bits > 7 {
                return Err(anyhow!("qpack: incomplete Huffman-coded string"));
            }
            if bits > 0 && code != (1u32 << bits) - 1 {
                return Err(anyhow!("qpack: invalid Huffman padding"));
            }
            Ok(out)
        }
    }

    #[cfg(test)]
    mod stream_tests {
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Duration;

        use bytes::Bytes;
        use quinn::{ConnectionError, Endpoint, SendStream, VarInt};
        use tokio::sync::mpsc;
        use tokio::time::timeout;

        use super::qpack;
        use super::*;
        use crate::masque::{generate_cert, prepare_tls_config, EcdsaPrivateKey, EcdsaPublicKey, NEXT_PROTO_H3};

        /// A loopback round trip takes milliseconds; this only has to be short enough that a missing
        /// frame bound fails the test instead of hanging the suite.
        const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

        struct TestPair {
            client: Arc<ClientConn>,
            server: quinn::Connection,
            _client_endpoint: Endpoint,
            _server_endpoint: Endpoint,
        }

        /// A P-256 key in the SEC1 DER the crate's certificate helpers take.
        fn private_key() -> EcdsaPrivateKey {
            loop {
                let mut seed = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
                if let Ok(secret) = p256::SecretKey::from_bytes(&seed.into()) {
                    let der = secret.to_sec1_der().expect("encode sec1 der");
                    return EcdsaPrivateKey::parse_ec_private_key(&der).expect("parse the key just generated");
                }
            }
        }

        fn public_key(private: &EcdsaPrivateKey) -> EcdsaPublicKey {
            use murmur_component_ca::keypair::OID_PRIME256V1;
            let secret = p256::SecretKey::from_sec1_der(private.der()).expect("sec1 private key");
            let signing = p256::ecdsa::SigningKey::from(&secret);
            EcdsaPublicKey {
                curve: OID_PRIME256V1.to_vec(),
                point: signing.verifying_key().to_sec1_point(false).as_ref().to_vec(),
            }
        }

        /// The client under test over a real QUIC connection, with the server side held by the test
        /// so it can write what a masque server would.
        async fn connect_pair() -> TestPair {
            murmur_testsupport_probe::ensure_test_crypto_provider();

            let server_key = private_key();
            let server_certs: Vec<rustls::pki_types::CertificateDer<'static>> = generate_cert(&server_key)
                .expect("server cert")
                .into_iter()
                .map(rustls::pki_types::CertificateDer::from)
                .collect();
            let server_private = rustls::pki_types::PrivateKeyDer::Sec1(rustls::pki_types::PrivateSec1KeyDer::from(
                server_key.der().to_vec(),
            ));
            let mut server_tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(server_certs, server_private)
                .expect("build the test server config");
            server_tls.alpn_protocols = vec![NEXT_PROTO_H3.to_vec()];
            let server_crypto =
                quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).expect("quinn accepts the server config");
            let server_endpoint = Endpoint::server(
                quinn::ServerConfig::with_crypto(Arc::new(server_crypto)),
                "127.0.0.1:0".parse().expect("loopback address"),
            )
            .expect("bind the server endpoint");
            let addr = server_endpoint.local_addr().expect("the server endpoint has an address");

            let client_key = private_key();
            let tls = prepare_tls_config(&client_key, &public_key(&server_key), "example.com", false)
                .expect("prepare the client tls config");
            let client_crypto =
                quinn::crypto::rustls::QuicClientConfig::try_from(tls.config).expect("quinn accepts the client config");
            let client_endpoint =
                Endpoint::client("127.0.0.1:0".parse().expect("loopback address")).expect("bind the client endpoint");
            let server_name = tls.server_name.to_str().into_owned();
            let connecting = client_endpoint
                .connect_with(quinn::ClientConfig::new(Arc::new(client_crypto)), addr, &server_name)
                .expect("dial the server");
            let accepting = async {
                server_endpoint
                    .accept()
                    .await
                    .expect("the server endpoint is still accepting")
                    .await
                    .expect("the server handshake completes")
            };
            let (client_conn, server_conn) = futures::join!(connecting, accepting);
            let client_conn = client_conn.expect("the client handshake completes");

            let client = Transport::new(true, Vec::new())
                .new_client_conn(client_conn)
                .await
                .expect("the client connection is created");
            TestPair {
                client,
                server: server_conn,
                _client_endpoint: client_endpoint,
                _server_endpoint: server_endpoint,
            }
        }

        /// Starts a server control stream and writes its stream type.
        async fn open_control_stream(pair: &TestPair) -> SendStream {
            let mut control = pair.server.open_uni().await.expect("open the server control stream");
            let mut stream_type: Vec<u8> = Vec::new();
            quicvarint::append(&mut stream_type, STREAM_TYPE_CONTROL);
            control.write_all(&stream_type).await.expect("write the control stream type");
            control
        }

        /// Writes one HTTP/3 frame header declaring `length`, with no payload.
        async fn write_frame_header(send: &mut SendStream, frame_type: u64, length: u64) {
            let mut header: Vec<u8> = Vec::new();
            quicvarint::append(&mut header, frame_type);
            quicvarint::append(&mut header, length);
            send.write_all(&header).await.expect("write the frame header");
        }

        async fn write_headers(send: &mut SendStream, status: &str) {
            let block = qpack::encode_fields(&[(":status".to_owned(), status.to_owned())]);
            let mut frame: Vec<u8> = Vec::new();
            quicvarint::append(&mut frame, FRAME_HEADERS);
            quicvarint::append(&mut frame, block.len() as u64);
            frame.extend_from_slice(&block);
            send.write_all(&frame).await.expect("write the HEADERS frame");
        }

        /// Opens a request stream and takes the server-side half a masque server would answer on.
        /// The request head has to be written first: a QUIC stream only exists for the peer once
        /// bytes arrive on it.
        async fn open_response_stream(pair: &TestPair) -> (RequestStream, SendStream) {
            let mut stream = pair.client.open_request_stream(None).await.expect("open a request stream");
            let head = RequestHead {
                method: http::Method::CONNECT,
                proto: String::new(),
                host: "example.com".to_owned(),
                header: http::HeaderMap::new(),
                url: http::Uri::from_static("https://example.com"),
            };
            stream.send_request_header(&head).await.expect("write the request head");
            let (send, _recv) = pair.server.accept_bi().await.expect("the server accepts the request stream");
            (stream, send)
        }

        fn datagram_stream_count(conn: &ClientConn) -> usize {
            conn.datagram_streams.lock().len()
        }

        #[tokio::test]
        async fn a_settings_frame_longer_than_the_cap_closes_the_connection_instead_of_allocating() {
            let pair = connect_pair().await;
            let mut control = open_control_stream(&pair).await;
            write_frame_header(&mut control, FRAME_SETTINGS, 1 << 30).await;

            let closed = timeout(FRAME_TIMEOUT, pair.server.closed())
                .await
                .expect("the client fails closed on a SETTINGS frame past the cap");
            match closed {
                ConnectionError::ApplicationClosed(app) => {
                    assert_eq!(app.error_code, VarInt::from_u32(H3_EXCESSIVE_LOAD));
                    assert_eq!(String::from_utf8_lossy(&app.reason), "SETTINGS frame too large");
                }
                err => panic!("expected an application close, got {err}"),
            }
        }

        #[tokio::test]
        async fn a_settings_frame_within_the_cap_is_parsed() {
            let pair = connect_pair().await;
            let mut control = open_control_stream(&pair).await;
            let mut payload: Vec<u8> = Vec::new();
            quicvarint::append(&mut payload, SETTING_MAX_FIELD_SECTION_SIZE);
            quicvarint::append(&mut payload, 4096);
            write_frame_header(&mut control, FRAME_SETTINGS, payload.len() as u64).await;
            control.write_all(&payload).await.expect("write the SETTINGS payload");

            let settings = timeout(FRAME_TIMEOUT, pair.client.received_settings())
                .await
                .expect("a SETTINGS frame within the cap is accepted");
            assert_eq!(settings.max_field_section_size, 4096);
        }

        #[tokio::test]
        async fn more_informational_responses_than_the_cap_fail_closed() {
            let pair = connect_pair().await;
            let (mut stream, mut server_send) = open_response_stream(&pair).await;
            for _ in 0..=MAX_INTERIM_RESPONSES {
                write_headers(&mut server_send, "103").await;
            }

            let result = timeout(FRAME_TIMEOUT, stream.read_response()).await.expect("the response loop is bounded");
            let err = result.expect_err("an unlimited run of informational responses is rejected");
            assert!(err.to_string().contains("informational responses"), "unexpected error: {err}");
        }

        #[tokio::test]
        async fn a_response_preamble_past_the_cap_fails_closed_without_reading_the_frames() {
            let pair = connect_pair().await;
            let (mut stream, mut server_send) = open_response_stream(&pair).await;
            write_headers(&mut server_send, "103").await;
            write_frame_header(&mut server_send, 0x21, MAX_RESPONSE_PREAMBLE_BYTES).await;

            let result = timeout(FRAME_TIMEOUT, stream.read_response()).await.expect("the response loop is bounded");
            let err = result.expect_err("a preamble past the byte cap is rejected");
            assert!(err.to_string().contains("exceed"), "unexpected error: {err}");
        }

        #[tokio::test]
        async fn informational_responses_up_to_the_cap_precede_the_final_response() {
            let pair = connect_pair().await;
            let (mut stream, mut server_send) = open_response_stream(&pair).await;
            for _ in 0..MAX_INTERIM_RESPONSES {
                write_headers(&mut server_send, "103").await;
            }
            write_headers(&mut server_send, "200").await;

            let response = timeout(FRAME_TIMEOUT, stream.read_response()).await.expect("the response arrives");
            assert_eq!(response.expect("a response within the caps").status_code, 200);
        }

        #[tokio::test]
        async fn a_closed_request_stream_releases_its_datagram_routing_entry() {
            let pair = connect_pair().await;
            for _ in 0..8 {
                let stream = pair.client.open_request_stream(None).await.expect("open a request stream");
                assert_eq!(datagram_stream_count(&pair.client), 1, "a live stream owns one routing entry");
                let (_send, _recv, datagrams) = stream.split();
                drop(datagrams);
            }

            assert_eq!(datagram_stream_count(&pair.client), 0, "every closed stream releases its routing entry");
        }

        #[tokio::test]
        async fn dropping_a_request_stream_releases_its_datagram_routing_entry() {
            let pair = connect_pair().await;
            let stream = pair.client.open_request_stream(None).await.expect("open a request stream");
            assert_eq!(datagram_stream_count(&pair.client), 1);

            drop(stream);
            assert_eq!(datagram_stream_count(&pair.client), 0);
        }

        #[test]
        fn pruning_drops_only_the_routing_entries_whose_receiver_is_gone() {
            let mut streams: HashMap<u64, mpsc::Sender<Bytes>> = HashMap::new();
            let (live, _live_receiver) = mpsc::channel::<Bytes>(1);
            let (dead, dead_receiver) = mpsc::channel::<Bytes>(1);
            drop(dead_receiver);
            streams.insert(4, live);
            streams.insert(8, dead);

            assert_eq!(prune_closed_datagram_streams(&mut streams), 1);
            assert_eq!(streams.len(), 1);
            assert!(streams.contains_key(&4));
        }
    }
}

/// The host with the port, if the URL has one.
pub(crate) fn url_host(url: &url::Url) -> String {
    match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_owned(),
        (None, _) => String::new(),
    }
}

/// Establishes a Connect-IP tunnel with the provided endpoint.
///
/// The endpoint address is what decides whether the authentication/connection succeeded.
pub async fn connect_tunnel(
    ctx: CancellationToken,
    quic_conn: quinn::Connection,
    connect_uri: &str,
) -> anyhow::Result<(h3::Transport, connectip::Conn)> {
    // The official client still sends the deprecated SETTINGS_H3_DATAGRAM_00 (0x276) as well.
    let tr = h3::Transport::new(true, vec![(0x276, 1)]);
    let hconn = tr.new_client_conn(quic_conn).await?;

    let mut additional_headers = HeaderMap::new();
    additional_headers.insert(http::header::USER_AGENT, http::HeaderValue::from_static(""));

    let template = uritemplate::Template::must_new(connect_uri);
    let (mut ip_conn, rsp) = match dial_ex(&ctx, &hconn, &template, "cf-connect-ip", &additional_headers, true).await {
        Ok(dialed) => dialed,
        Err(err) => {
            let _ = tr.close();
            if err.to_string() == "CRYPTO_ERROR 0x131 (remote): tls: access denied" {
                return Err(anyhow!(
                    "login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service"
                ));
            }
            return Err(anyhow!("failed to dial connect-ip: {err}"));
        }
    };

    let routes = vec![
        connectip::IpRoute {
            start_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            end_ip: IpAddr::V4(Ipv4Addr::BROADCAST),
            ip_protocol: 0,
        },
        connectip::IpRoute {
            start_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            end_ip: IpAddr::V6(Ipv6Addr::from([255u8; 16])),
            ip_protocol: 0,
        },
    ];
    if let Err(err) = ip_conn.advertise_route(Some(&ctx), routes).await {
        let _ = ip_conn.close().await;
        let _ = tr.close();
        return Err(err);
    }

    if !rsp.is_ok() {
        let _ = ip_conn.close().await;
        let _ = tr.close();
        return Err(anyhow!("failed to dial connect-ip: {}", rsp.status));
    }

    Ok((tr, ip_conn))
}

/// Dials a proxied connection to a target server.
pub async fn dial_ex(
    ctx: &CancellationToken,
    conn: &Arc<h3::ClientConn>,
    template: &uritemplate::Template,
    request_protocol: &str,
    additional_headers: &HeaderMap,
    ignore_extended_connect: bool,
) -> anyhow::Result<(connectip::Conn, HttpResponse)> {
    if !template.varnames().is_empty() {
        return Err(anyhow!("connect-ip: IP flow forwarding not supported"));
    }

    let url = url::Url::parse(template.raw()).map_err(|err| anyhow!("connect-ip: failed to parse URI: {err}"))?;

    let settings = tokio::select! {
        () = ctx.cancelled() => return Err(context_canceled()),
        () = conn.context_done() => return Err(conn.context_cause()),
        settings = conn.received_settings() => settings,
    };
    if !ignore_extended_connect && !settings.enable_extended_connect {
        return Err(anyhow!("connect-ip: server didn't enable Extended CONNECT"));
    }
    if !settings.enable_datagrams {
        return Err(anyhow!("connect-ip: server didn't enable datagrams"));
    }

    let mut headers = HeaderMap::new();
    headers.insert("capsule-protocol", http::HeaderValue::from_static(CAPSULE_PROTOCOL_HEADER_VALUE));
    for (name, value) in additional_headers {
        headers.insert(name, value.clone());
    }

    let mut rstr = conn
        .open_request_stream(Some(ctx))
        .await
        .map_err(|err| anyhow!("connect-ip: failed to open request stream: {err}"))?;

    let uri = http::Uri::try_from(url.as_str()).map_err(|err| anyhow!("connect-ip: failed to parse URI: {err}"))?;
    let head = h3::RequestHead {
        method: http::Method::CONNECT,
        proto: request_protocol.to_owned(),
        host: url_host(&url),
        header: headers,
        url: uri,
    };
    rstr.send_request_header(&head).await.map_err(|err| anyhow!("connect-ip: failed to send request: {err}"))?;

    let rsp = rstr.read_response().await.map_err(|err| anyhow!("connect-ip: failed to read response: {err}"))?;
    if rsp.status_code < 200 || rsp.status_code > 299 {
        return Err(anyhow!("connect-ip: server responded with {}", rsp.status_code));
    }
    Ok((connectip::new_proxied_conn(rstr), rsp))
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Verifier as _;

    use super::*;

    /// DER for `SEQUENCE { SEQUENCE { OID id-ecPublicKey, OID prime256v1 } }` plus the leading
    /// `BIT STRING` tag/length/unused-bits octet, i.e. every P-256 SubjectPublicKeyInfo's fixed
    /// prefix before its 65-byte uncompressed point: `3059301306072a8648ce3d020106082a8648ce3d
    /// 030107034200` with the outer `30 59` stripped (the caller compares against `der_tlv`'s
    /// extracted content, which excludes it).
    const P256_SPKI_PREFIX: &[u8] = &[
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];

    struct TestKeyPair {
        secret_key: p256::SecretKey,
        private_key_der: Vec<u8>,
        public_key_point: Vec<u8>,
    }

    fn random_secret_key() -> p256::SecretKey {
        let mut seed = [0u8; 32];
        loop {
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
            if let Ok(secret_key) = p256::SecretKey::from_bytes(&seed.into()) {
                return secret_key;
            }
        }
    }

    fn generate_test_key_pair() -> TestKeyPair {
        let secret_key = random_secret_key();
        let private_key_der = secret_key.to_sec1_der().expect("encode sec1 der").to_vec();
        let signing_key = p256::ecdsa::SigningKey::from(&secret_key);
        let public_key_point = signing_key.verifying_key().to_sec1_point(false).as_ref().to_vec();
        TestKeyPair { secret_key, private_key_der, public_key_point }
    }

    /// Builds the `EcdsaPublicKey` a peer would present for `key_pair`, the same shape
    /// `EcdsaPublicKey::parse_pkix_public_key` produces: the raw (tag/length-stripped) named-curve
    /// OID plus the uncompressed SEC1 point.
    fn ecdsa_public_key(key_pair: &TestKeyPair) -> EcdsaPublicKey {
        use murmur_component_ca::keypair::OID_PRIME256V1;
        EcdsaPublicKey { curve: OID_PRIME256V1.to_vec(), point: key_pair.public_key_point.clone() }
    }

    /// A DER UTCTime, e.g. `240101000000Z`, as the instant it names.
    fn parse_utc_time(bytes: &[u8]) -> chrono::DateTime<chrono::Utc> {
        chrono::NaiveDateTime::parse_from_str(std::str::from_utf8(bytes).expect("ascii"), "%y%m%d%H%M%SZ")
            .expect("parseable UTCTime")
            .and_utc()
    }

    /// Checks a TBS `validity`: two UTCTimes spanning exactly 24 hours and starting now.
    fn assert_validity_window(validity_body: &[u8]) {
        let mut cursor = 0;
        let (not_before_tag, not_before) = der_tlv(validity_body, &mut cursor).expect("notBefore");
        assert_eq!(not_before_tag, 0x17, "dates before 2050 encode as UTCTime");
        let (not_after_tag, not_after) = der_tlv(validity_body, &mut cursor).expect("notAfter");
        assert_eq!(not_after_tag, 0x17);
        assert_eq!(cursor, validity_body.len());

        let not_before_time = parse_utc_time(not_before);
        let not_after_time = parse_utc_time(not_after);
        assert_eq!(not_after_time - not_before_time, chrono::Duration::days(1), "NotAfter is NotBefore + 24h");
        let now = chrono::Utc::now();
        assert!(
            not_before_time <= now + chrono::Duration::seconds(1)
                && not_before_time >= now - chrono::Duration::minutes(1)
        );
    }

    /// Checks a `Name` the template leaves zero, which marshals to an empty `RDNSequence`.
    fn assert_empty_rdn_sequence(tag: u8, name: &[u8]) {
        assert_eq!(tag, DER_SEQUENCE);
        assert!(name.is_empty(), "the zero name marshals to an empty RDNSequence");
    }

    /// Checks a `subjectPublicKeyInfo` against the uncompressed SEC1 point it must carry.
    fn assert_spki_encodes_point(tag: u8, content: &[u8], point: &[u8]) {
        assert_eq!(tag, DER_SEQUENCE);
        let expected = [P256_SPKI_PREFIX, point].concat();
        assert_eq!(
            content,
            expected.as_slice(),
            "SPKI must encode the caller's public key as a standard P-256 SubjectPublicKeyInfo"
        );
    }

    /// The certificate written from an all-zero template (serial 0, empty subject/issuer, no
    /// extensions) and an empty parent: version 3 (encoded `2`), serial `0`, ECDSA-with-SHA256
    /// twice (TBS and outer), an empty issuer and subject, a validity of `NotBefore` to
    /// `NotBefore + 24h`, the caller's SubjectPublicKeyInfo, and no extensions field at all (a
    /// zero-length slice is dropped).
    #[test]
    fn generate_cert_writes_the_expected_certificate_fields() {
        let key_pair = generate_test_key_pair();
        let priv_key = EcdsaPrivateKey::parse_ec_private_key(&key_pair.private_key_der).expect("parse sec1 der");

        let cert = generate_cert(&priv_key).expect("generate cert");
        assert_eq!(cert.len(), 1, "the chain holds exactly one certificate");
        let cert_der = &cert[0];

        let mut offset = 0;
        let (tag, body) = der_tlv(cert_der, &mut offset).expect("certificate sequence");
        assert_eq!(tag, DER_SEQUENCE);
        assert_eq!(offset, cert_der.len(), "trailing bytes after certificate");

        let mut cursor = 0;
        let tbs_start = cursor;
        let (tbs_tag, tbs_body) = der_tlv(body, &mut cursor).expect("tbsCertificate sequence");
        assert_eq!(tbs_tag, DER_SEQUENCE);
        let tbs_der = &body[tbs_start..cursor];

        let (outer_sig_alg_tag, outer_signature_algorithm) = der_tlv(body, &mut cursor).expect("signatureAlgorithm");
        assert_eq!(outer_sig_alg_tag, DER_SEQUENCE);

        let (sig_tag, signature_bits) = der_tlv(body, &mut cursor).expect("signatureValue");
        assert_eq!(sig_tag, DER_BIT_STRING);
        assert_eq!(signature_bits[0], 0, "signature bit string has no unused bits");
        assert_eq!(cursor, body.len(), "trailing bytes after signatureValue");

        let mut tbs_cursor = 0;
        let (version_wrapper_tag, version_wrapper) = der_tlv(tbs_body, &mut tbs_cursor).expect("version");
        assert_eq!(version_wrapper_tag, 0xa0, "explicit [0] version");
        let mut version_cursor = 0;
        let (version_int_tag, version_int) = der_tlv(version_wrapper, &mut version_cursor).expect("version integer");
        assert_eq!(version_int_tag, DER_INTEGER);
        assert_eq!(version_int, [2], "the version is always v3, encoded as 2");

        let (serial_tag, serial) = der_tlv(tbs_body, &mut tbs_cursor).expect("serialNumber");
        assert_eq!(serial_tag, DER_INTEGER);
        assert_eq!(serial, [0], "the template's serial number is zero");

        let (tbs_sig_alg_tag, tbs_signature_algorithm) =
            der_tlv(tbs_body, &mut tbs_cursor).expect("tbs signature algorithm");
        assert_eq!(tbs_sig_alg_tag, DER_SEQUENCE);
        assert_eq!(
            tbs_signature_algorithm, outer_signature_algorithm,
            "the TBS and outer AlgorithmIdentifier are identical"
        );
        assert_eq!(tbs_signature_algorithm, OID_ECDSA_WITH_SHA256_CONTENT);

        let (issuer_tag, issuer) = der_tlv(tbs_body, &mut tbs_cursor).expect("issuer");
        assert_empty_rdn_sequence(issuer_tag, issuer);

        let (validity_tag, validity_body) = der_tlv(tbs_body, &mut tbs_cursor).expect("validity");
        assert_eq!(validity_tag, DER_SEQUENCE);
        assert_validity_window(validity_body);

        let (subject_tag, subject) = der_tlv(tbs_body, &mut tbs_cursor).expect("subject");
        assert_empty_rdn_sequence(subject_tag, subject);

        let (spki_tag, spki_content) = der_tlv(tbs_body, &mut tbs_cursor).expect("subjectPublicKeyInfo");
        assert_spki_encodes_point(spki_tag, spki_content, &key_pair.public_key_point);

        assert_eq!(tbs_cursor, tbs_body.len(), "no Extensions field is written for an all-zero template");

        let verifying_key = p256::ecdsa::SigningKey::from(&key_pair.secret_key).verifying_key().to_owned();
        let signature = p256::ecdsa::Signature::from_der(&signature_bits[1..]).expect("parseable ECDSA signature");
        verifying_key.verify(tbs_der, &signature).expect("certificate must verify against the supplied private key");
    }

    /// Content of `SEQUENCE { OBJECT IDENTIFIER ecdsa-with-SHA256 }` as `der_tlv` extracts it,
    /// without the outer tag/length: P-256 signing parameters carry no parameters field.
    const OID_ECDSA_WITH_SHA256_CONTENT: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

    #[test]
    fn generate_cert_rejects_a_malformed_private_key_instead_of_reporting_a_missing_crate() {
        let priv_key = EcdsaPrivateKey { der: vec![0x30, 0x03, 0x02, 0x01, 0x00] };
        let err = generate_cert(&priv_key).expect_err("malformed key cannot be turned into a p256 secret key");
        assert!(!err.to_string().contains("NEEDED CRATE"), "the p256 dependency is present: {err}");
    }

    /// Regression test for `certificate_spki` reusing the outer `offset` (already at
    /// `cert.len()` after the top-level `der_tlv` call) to index `body`: every `der_tlv(body,
    /// &mut offset)` call started out of bounds and failed, so `verify_cert` rejected every
    /// certificate with `ERR_UNSUPPORTED_ALGORITHM`, even one signed by the caller's own trusted
    /// key. Fails on the pre-fix code.
    #[test]
    fn verify_cert_accepts_a_generated_certificate_against_its_own_key() {
        let key_pair = generate_test_key_pair();
        let priv_key = EcdsaPrivateKey::parse_ec_private_key(&key_pair.private_key_der).expect("parse sec1 der");
        let cert = generate_cert(&priv_key).expect("generate cert");
        let pub_key = ecdsa_public_key(&key_pair);

        verify_cert(&cert[0], &pub_key).expect("verify_cert must accept the certificate's own public key");
    }

    /// End-to-end proof that `prepare_tls_config(insecure=false)` produces a client config that
    /// actually completes a handshake and pins the server's key, not just one that builds
    /// without error. Fails on the pre-fix code because the server's certificate can never pass
    /// `verify_cert` on the client side.
    #[tokio::test]
    async fn prepare_tls_config_completes_a_pinned_handshake_against_the_trusted_key() {
        use tokio::net::{TcpListener, TcpStream};

        murmur_testsupport_probe::ensure_test_crypto_provider();

        let server_key_pair = generate_test_key_pair();
        let server_priv_key =
            EcdsaPrivateKey::parse_ec_private_key(&server_key_pair.private_key_der).expect("parse sec1 der");
        let server_cert = generate_cert(&server_priv_key).expect("generate server cert");
        let server_cert_der: Vec<rustls::pki_types::CertificateDer<'static>> =
            server_cert.into_iter().map(rustls::pki_types::CertificateDer::from).collect();
        let server_key_der = rustls::pki_types::PrivateKeyDer::Sec1(rustls::pki_types::PrivateSec1KeyDer::from(
            server_priv_key.der().to_vec(),
        ));
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(server_cert_der, server_key_der)
                .expect("build test tls server config"),
        );

        let client_key_pair = generate_test_key_pair();
        let client_priv_key =
            EcdsaPrivateKey::parse_ec_private_key(&client_key_pair.private_key_der).expect("parse sec1 der");
        let server_pub_key = ecdsa_public_key(&server_key_pair);
        let tls_config =
            prepare_tls_config(&client_priv_key, &server_pub_key, "example.com", false).expect("prepare tls config");
        let server_name = tls_config.server_name.clone();
        let client_config = Arc::new(tls_config.config);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");

        let client_task = tokio::spawn(async move {
            let client_raw = TcpStream::connect(addr).await.expect("client connect");
            tokio_rustls::TlsConnector::from(client_config).connect(server_name, client_raw).await
        });

        let (server_raw, _) = listener.accept().await.expect("accept");
        let server_result = tokio_rustls::TlsAcceptor::from(server_config).accept(server_raw).await;
        let client_result = client_task.await.expect("client task panicked");

        server_result.expect("server handshake must complete against the pinned client");
        client_result.expect("client handshake must complete: prepare_tls_config's certificate must verify");
    }

    /// The pinning closure reports a mismatched pin as detail "remote endpoint has a different
    /// public key than what we trust", rendered as `"x509: no valid chains built: <detail>"`.
    /// Proves the negative path, not just that pinning accepts the right key: a certificate signed
    /// by key A must be rejected, with that exact text, when the caller pins key B.
    #[test]
    fn verify_cert_rejects_a_different_key_with_the_pin_mismatch_text() {
        let key_a = generate_test_key_pair();
        let key_b = generate_test_key_pair();
        let priv_key_a = EcdsaPrivateKey::parse_ec_private_key(&key_a.private_key_der).expect("parse sec1 der");
        let cert_a = generate_cert(&priv_key_a).expect("generate cert");
        let pub_key_b = ecdsa_public_key(&key_b);

        let err = verify_cert(&cert_a[0], &pub_key_b).expect_err("a different pinned key must be rejected");
        assert_eq!(
            err.to_string(),
            "x509: no valid chains built: remote endpoint has a different public key than what we trust",
            "verify_cert's pin-mismatch error must carry that text"
        );
    }

    /// Every strict prefix of a valid certificate is a different (truncated) byte string that
    /// must not verify. Guards against `certificate_spki`/`der_tlv` silently accepting a
    /// truncated `subjectPublicKeyInfo` that happens to still parse.
    #[test]
    fn verify_cert_rejects_every_truncation_of_a_valid_certificate() {
        let key_pair = generate_test_key_pair();
        let priv_key = EcdsaPrivateKey::parse_ec_private_key(&key_pair.private_key_der).expect("parse sec1 der");
        let cert = generate_cert(&priv_key).expect("generate cert");
        let cert_der = &cert[0];
        let pub_key = ecdsa_public_key(&key_pair);

        for n in 0..cert_der.len() {
            assert!(
                verify_cert(&cert_der[..n], &pub_key).is_err(),
                "a certificate truncated to {n} of {} bytes must not verify",
                cert_der.len()
            );
        }
    }

    /// The handshake counterpart of `verify_cert_rejects_a_different_key_with_the_pin_mismatch_text`:
    /// a server holding key A's certificate, dialed by a client that pinned key B through
    /// `prepare_tls_config`, must fail the handshake with the pin-mismatch text rather than
    /// complete or hang. Both sides are wrapped in a timeout so a regression that blocks instead
    /// of failing closed shows up as a test failure, not a hang.
    #[tokio::test]
    async fn prepare_tls_config_fails_closed_when_the_pinned_key_does_not_match_the_server() {
        use tokio::net::{TcpListener, TcpStream};

        murmur_testsupport_probe::ensure_test_crypto_provider();

        let server_key_pair = generate_test_key_pair();
        let server_priv_key =
            EcdsaPrivateKey::parse_ec_private_key(&server_key_pair.private_key_der).expect("parse sec1 der");
        let server_cert = generate_cert(&server_priv_key).expect("generate server cert");
        let server_cert_der: Vec<rustls::pki_types::CertificateDer<'static>> =
            server_cert.into_iter().map(rustls::pki_types::CertificateDer::from).collect();
        let server_key_der = rustls::pki_types::PrivateKeyDer::Sec1(rustls::pki_types::PrivateSec1KeyDer::from(
            server_priv_key.der().to_vec(),
        ));
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(server_cert_der, server_key_der)
                .expect("build test tls server config"),
        );

        let client_key_pair = generate_test_key_pair();
        let client_priv_key =
            EcdsaPrivateKey::parse_ec_private_key(&client_key_pair.private_key_der).expect("parse sec1 der");
        let wrong_key_pair = generate_test_key_pair();
        let wrong_pub_key = ecdsa_public_key(&wrong_key_pair);
        let tls_config =
            prepare_tls_config(&client_priv_key, &wrong_pub_key, "example.com", false).expect("prepare tls config");
        let server_name = tls_config.server_name.clone();
        let client_config = Arc::new(tls_config.config);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");

        let client_task = tokio::spawn(async move {
            let client_raw = TcpStream::connect(addr).await.expect("client connect");
            tokio_rustls::TlsConnector::from(client_config).connect(server_name, client_raw).await
        });

        let (server_raw, _) = listener.accept().await.expect("accept");
        let bound = std::time::Duration::from_secs(10);
        let server_result =
            tokio::time::timeout(bound, tokio_rustls::TlsAcceptor::from(server_config).accept(server_raw))
                .await
                .expect("server handshake must not hang");
        let client_result = tokio::time::timeout(bound, client_task)
            .await
            .expect("client handshake must not hang")
            .expect("client task panicked");

        assert!(server_result.is_err(), "server handshake must fail when the client rejects its certificate");
        let client_err = client_result.expect_err("client must reject the server's certificate: pinned key mismatch");
        assert!(
            client_err.to_string().contains("remote endpoint has a different public key than what we trust"),
            "client error must surface the pin-mismatch text: {client_err}"
        );
    }

    /// `certificate_spki` parses attacker-controlled bytes before `verify_cert` ever compares a
    /// public key; it must fail gracefully, never panic. Seeded so a CI panic reproduces locally;
    /// the certificate and its `notBefore` timestamp come from the same seeded, fixed inputs for
    /// the same reason (a wall-clock `notBefore` would change the certificate bytes, and so the
    /// whole mutation stream, every second).
    #[test]
    fn certificate_spki_never_panics_on_corrupted_or_truncated_certificates() {
        use rand::rngs::StdRng;
        use rand::{Rng, RngCore, SeedableRng};

        const SEED: u64 = 0x5eed_ba5e_c3a7_1234;
        let mut rng = StdRng::seed_from_u64(SEED);
        let secret_key = loop {
            let mut seed_bytes = [0u8; 32];
            rng.fill_bytes(&mut seed_bytes);
            if let Ok(secret_key) = p256::SecretKey::from_bytes(&seed_bytes.into()) {
                break secret_key;
            }
        };
        let private_key_der = secret_key.to_sec1_der().expect("encode sec1 der").to_vec();
        let priv_key = EcdsaPrivateKey::parse_ec_private_key(&private_key_der).expect("parse sec1 der");
        let not_before = "2024-01-01T00:00:00Z".parse::<chrono::DateTime<chrono::Utc>>().expect("parse fixed instant");
        let cert = generate_cert_at(&priv_key, not_before).expect("generate cert");
        let cert_der = cert[0].clone();

        for _ in 0..5000 {
            let mut mutated = cert_der.clone();
            let flips = rng.random_range(0..=8);
            for _ in 0..flips {
                if mutated.is_empty() {
                    break;
                }
                let idx = rng.random_range(0..mutated.len());
                mutated[idx] = rng.random();
            }
            let len = rng.random_range(0..=mutated.len());
            mutated.truncate(len);

            let _ = certificate_spki(&mutated);
        }
    }

    /// A `SubjectPublicKeyInfo` whose `BIT STRING` has zero length has no unused-bits octet, so
    /// `parse_spki_body`'s `key.split_first()?` must return `None` instead of indexing an empty
    /// slice. Random byte replacement reaches this shape too rarely (one specific byte at one
    /// specific offset) for the fuzz loop to cover it.
    #[test]
    fn certificate_spki_returns_none_for_a_zero_length_public_key_bit_string() {
        use murmur_component_ca::keypair::{
            concat, der_integer, der_oid, der_sequence, OID_EC_PUBLIC_KEY, OID_PRIME256V1,
        };

        let algorithm = der_sequence(&concat(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_PRIME256V1)]));
        let spki = der_sequence(&concat(&[algorithm, vec![0x03, 0x00]]));
        let filler = der_integer(0);
        let tbs =
            der_sequence(&concat(&[filler.clone(), filler.clone(), filler.clone(), filler.clone(), filler, spki]));
        let cert_der = der_sequence(&tbs);

        assert!(certificate_spki(&cert_der).is_none(), "a zero-length SPKI BIT STRING must not parse as a public key");
    }

    fn random_p384_secret_key() -> p384::SecretKey {
        let mut seed = [0u8; 48];
        loop {
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
            if let Ok(secret_key) = p384::SecretKey::from_bytes(&seed.into()) {
                return secret_key;
            }
        }
    }

    fn random_p521_secret_key() -> p521::SecretKey {
        let mut seed = [0u8; 66];
        loop {
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
            if let Ok(secret_key) = p521::SecretKey::from_bytes(&seed.into()) {
                return secret_key;
            }
        }
    }

    /// Round 2 review (agent://ReviewP3MuxMasque finding 1 on 2452f9b7): the on-curve check
    /// only ever covered P-256. Corpus cases for the other curves `ec_point_len_for_curve`
    /// admits: a genuine on-curve point is still accepted, and the same point with its last byte
    /// flipped (off the curve with overwhelming probability) is rejected, for both P-384 and
    /// P-521.
    #[test]
    fn parse_spki_rejects_off_curve_points_for_every_supported_curve() {
        use murmur_component_ca::keypair::{concat, der_bit_string, der_oid, der_sequence, OID_EC_PUBLIC_KEY};

        let p384_secret = random_p384_secret_key();
        let p384_point =
            p384::ecdsa::SigningKey::from(&p384_secret).verifying_key().to_sec1_point(false).as_ref().to_vec();
        let p521_secret = random_p521_secret_key();
        let p521_point =
            p521::ecdsa::SigningKey::from(&p521_secret).verifying_key().to_sec1_point(false).as_ref().to_vec();

        for (curve, point) in [(&OID_NAMED_CURVE_P384[..], p384_point), (&OID_NAMED_CURVE_P521[..], p521_point)] {
            let algorithm = der_sequence(&concat(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(curve)]));
            let valid = der_sequence(&concat(&[algorithm.clone(), der_bit_string(&point)]));
            assert!(parse_spki(&valid).is_some(), "a genuine on-curve point for curve {curve:?} must still parse");

            let mut off_curve = point.clone();
            *off_curve.last_mut().expect("point is non-empty") ^= 0x01;
            let invalid = der_sequence(&concat(&[algorithm, der_bit_string(&off_curve)]));
            assert!(parse_spki(&invalid).is_none(), "an off-curve point for curve {curve:?} must be rejected");
        }
    }

    /// P-224 has no on-curve crate available (see the DEVIATION note on `OID_NAMED_CURVE_P256`'s
    /// neighbourhood), so it must be rejected outright rather than admitted unvalidated.
    #[test]
    fn parse_spki_rejects_p224_outright() {
        use murmur_component_ca::keypair::{concat, der_bit_string, der_oid, der_sequence, OID_EC_PUBLIC_KEY};

        let oid_named_curve_p224 = [0x2b, 0x81, 0x04, 0x00, 0x21];
        let algorithm = der_sequence(&concat(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(&oid_named_curve_p224)]));
        let mut point = vec![0u8; 1 + 2 * 28];
        point[0] = 0x04;
        let spki = der_sequence(&concat(&[algorithm, der_bit_string(&point)]));
        assert!(parse_spki(&spki).is_none(), "P-224 must be rejected outright, not admitted with an unvalidated point");
    }

    /// Round 2 review finding 2 on 2452f9b7: trailing elements are accepted inside a `SEQUENCE`
    /// (an `AlgorithmIdentifier`, and the outer SPKI `SEQUENCE` after the `BIT STRING`); only the
    /// outermost DER (checked by `parse_spki` and `certificate_spki`) may not have trailing bytes.
    #[test]
    fn parse_spki_accepts_trailing_elements() {
        use murmur_component_ca::keypair::{
            concat, der_bit_string, der_oid, der_sequence, OID_EC_PUBLIC_KEY, OID_PRIME256V1,
        };

        let key_pair = generate_test_key_pair();
        let der_null = vec![0x05, 0x00];

        let algorithm_with_trailing =
            der_sequence(&concat(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_PRIME256V1), der_null.clone()]));
        let spki_algorithm_trailing =
            der_sequence(&concat(&[algorithm_with_trailing, der_bit_string(&key_pair.public_key_point)]));
        let parsed =
            parse_spki(&spki_algorithm_trailing).expect("a trailing element inside AlgorithmIdentifier is accepted");
        assert_eq!(parsed.point, key_pair.public_key_point);

        let algorithm = der_sequence(&concat(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_PRIME256V1)]));
        let spki_outer_trailing =
            der_sequence(&concat(&[algorithm, der_bit_string(&key_pair.public_key_point), der_null]));
        let parsed = parse_spki(&spki_outer_trailing).expect("a trailing element after the BIT STRING is accepted");
        assert_eq!(parsed.point, key_pair.public_key_point);
    }

    /// Round 2 review finding 0 on 488c68c8: hand-computed for the right-align definition
    /// (the shift is eight minus the bit length modulo eight, the bit length being the byte length
    /// times eight minus the unused bits, which reduces here to `unused_bits`, not `8 - unused_bits`).
    /// `unused_bits = 5`, raw content `0xD6 0xA0`
    /// (`0b1101_0110 0b1010_0000`, whose low 5 bits are already zero) right-aligns to `0x06 0xB5`.
    #[test]
    fn der_bit_string_right_align_shifts_by_the_unused_bits_count() {
        assert_eq!(der_bit_string_right_align(5, &[0xD6, 0xA0]), vec![0x06, 0xB5]);
        assert_eq!(der_bit_string_right_align(0, &[0xAB, 0xCD]), vec![0xAB, 0xCD]);
        assert_eq!(der_bit_string_right_align(3, &[]), Vec::<u8>::new());
    }

    /// Shifts `point` left by `unused_bits` bits within the same byte width — the inverse of
    /// `der_bit_string_right_align` — so a test can build a `BIT STRING` with a non-zero
    /// unused-bits count that legitimately right-aligns to a real EC point. Only exact for a
    /// `point` whose leading `unused_bits` bits are already zero, which holds for every
    /// uncompressed SEC1 point here (`0x04` leaves the top 5 bits zero).
    fn shift_left_for_bit_string(unused_bits: u8, point: &[u8]) -> Vec<u8> {
        let shift = u32::from(unused_bits);
        if shift == 0 {
            return point.to_vec();
        }
        let mut raw = vec![0u8; point.len()];
        for i in 0..point.len() {
            let hi = point[i] << shift;
            let lo = if i + 1 < point.len() { point[i + 1] >> (8 - shift) } else { 0 };
            raw[i] = hi | lo;
        }
        raw
    }

    /// Round 2 review finding 2 on 2452f9b7: a `BIT STRING` with a non-zero, but correctly
    /// zero-padded, unused-bits count is legal DER and right-aligns to a real point; this builds
    /// one that right-aligns to a genuine on-curve P-256 point and checks it still parses to that
    /// point.
    #[test]
    fn parse_spki_accepts_a_non_zero_unused_bits_count() {
        use murmur_component_ca::keypair::{concat, der_oid, der_sequence, OID_EC_PUBLIC_KEY, OID_PRIME256V1};

        let key_pair = generate_test_key_pair();
        let point = &key_pair.public_key_point;
        let unused_bits = 4u8;
        let raw = shift_left_for_bit_string(unused_bits, point);
        assert_eq!(
            der_bit_string_right_align(unused_bits, &raw),
            point.as_slice(),
            "test setup must round-trip through der_bit_string_right_align"
        );
        let bit_string_content: Vec<u8> = std::iter::once(unused_bits).chain(raw.iter().copied()).collect();
        let algorithm = der_sequence(&concat(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_PRIME256V1)]));
        let spki =
            der_sequence(&concat(&[algorithm, murmur_component_ca::keypair::der_tlv(0x03, &bit_string_content)]));

        let parsed = parse_spki(&spki).expect("a non-zero unused-bits count with zero padding bits must still parse");
        assert_eq!(parsed.point, point.as_slice());
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// P-256 `SubjectPublicKeyInfo`s taken from an external generator for unused-bits counts 1,
    /// 2, 3 and 5 (all legally zero-padded, all right-aligning to the same point below) plus 7
    /// (zero-padded but the resulting content is one byte short of a real point, so the on-curve
    /// check rejects it too). Covers the counts
    /// `parse_spki_accepts_a_non_zero_unused_bits_count`'s self-built vector (4) does not.
    #[test]
    fn parse_spki_accepts_unused_bits_spkis_from_external_generators() {
        let expected_point = hex_decode(
            "049eda859639d864d158792656a86db2d69f95a29d9941f2adb2747d7c975160a5201622b4eb5c850f234cc537b3aed3feaec2db95f75bf51da206ce526d48f29e",
        );
        let accepted = [
            (1u8, "3059301306072a8648ce3d020106082a8648ce3d030107034201093db50b2c73b0c9a2b0f24cad50db65ad3f2b453b3283e55b64e8faf92ea2c14a402c4569d6b90a1e46998a6f675da7fd5d85b72beeb7ea3b440d9ca4da91e53c"),
            (2u8, "3059301306072a8648ce3d020106082a8648ce3d030107034202127b6a1658e761934561e4995aa1b6cb5a7e568a766507cab6c9d1f5f25d45829480588ad3ad72143c8d3314decebb4ffabb0b6e57dd6fd476881b3949b523ca78"),
            (3u8, "3059301306072a8648ce3d020106082a8648ce3d03010703420324f6d42cb1cec3268ac3c932b5436d96b4fcad14ecca0f956d93a3ebe4ba8b052900b115a75ae428791a6629bd9d769ff57616dcafbadfa8ed103672936a4794f0"),
            (5u8, "3059301306072a8648ce3d020106082a8648ce3d03010703420593db50b2c73b0c9a2b0f24cad50db65ad3f2b453b3283e55b64e8faf92ea2c14a402c4569d6b90a1e46998a6f675da7fd5d85b72beeb7ea3b440d9ca4da91e53c0"),
        ];
        for (unused_bits, spki_hex) in accepted {
            let spki = hex_decode(spki_hex);
            let parsed = parse_spki(&spki).unwrap_or_else(|| panic!("unused_bits={unused_bits} must be accepted"));
            assert_eq!(parsed.point, expected_point, "unused_bits={unused_bits}");
        }

        let rejected_unused_bits_7 = hex_decode(
            "3059301306072a8648ce3d020106082a8648ce3d0301070342074f6d42cb1cec3268ac3c932b5436d96b4fcad14ecca0f956d93a3ebe4ba8b052900b115a75ae428791a6629bd9d769ff57616dcafbadfa8ed103672936a4794f00",
        );
        assert!(
            parse_spki(&rejected_unused_bits_7).is_none(),
            "unused_bits=7 is rejected here: the right-align shifts the 0x04 prefix out"
        );
    }
}

//! TLS 1.3 handshake message encode/decode (RFC 8446 §4), narrowed to exactly what REALITY's
//! `ClientHello`-splice trick and the minimal handshake around it need: `ClientHello`,
//! `ServerHello`, `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`. No
//! session resumption, 0-RTT, client certificates or HelloRetryRequest.

use anyhow::{anyhow, Result};

use crate::suite::CipherSuite;
use crate::wire::{handshake_message, Reader, Writer};

pub(crate) const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
pub(crate) const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
pub(crate) const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
pub(crate) const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
pub(crate) const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
pub(crate) const HANDSHAKE_TYPE_FINISHED: u8 = 20;

pub(crate) const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub(crate) const CONTENT_TYPE_ALERT: u8 = 21;
pub(crate) const CONTENT_TYPE_HANDSHAKE: u8 = 22;
pub(crate) const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

const LEGACY_VERSION_TLS12: u16 = 0x0303;
const SUPPORTED_VERSION_TLS13: u16 = 0x0304;

pub(crate) const GROUP_X25519: u16 = 0x001D;
const SIGNATURE_SCHEME_ED25519: u16 = 0x0807;

const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_KEY_SHARE: u16 = 51;

/// `ClientHello.random[..20]` is the HKDF salt for the REALITY `AuthKey`; `[20..]` is the AEAD
/// nonce for the `SessionId` splice.
pub(crate) struct ClientHello {
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub cipher_suites: Vec<CipherSuite>,
    pub server_name: String,
    /// `None` when the client offered no X25519 share. Authentication is skipped when there is
    /// none (the whole auth block is guarded on a real peer key), so absence must not collapse
    /// into a usable point -- an all-zero peer point would otherwise ECDH to the all-zero secret
    /// and authenticate anyone who can compute that HKDF.
    pub x25519_public: Option<[u8; 32]>,
    pub raw: Vec<u8>,
}

impl ClientHello {
    /// Builds the wire bytes with an all-zero `SessionId`; the caller (the REALITY splice step)
    /// overwrites `raw[session_id_offset()..][..32]` afterward and must keep [`Self::raw`] in
    /// sync so it can be resliced for the AEAD additional data.
    pub(crate) fn build(
        random: [u8; 32],
        cipher_suites: &[CipherSuite],
        server_name: &str,
        x25519_public: [u8; 32],
    ) -> Self {
        let mut body = Writer::new();
        body.u16(LEGACY_VERSION_TLS12);
        body.bytes(&random);
        body.vec_u8(&[0u8; 32]);

        let mut suites = Writer::new();
        for suite in cipher_suites {
            suites.u16(suite.id());
        }
        body.vec_u16(&suites.into_bytes());

        body.vec_u8(&[0u8]); // legacy_compression_methods: null only

        let mut exts = Writer::new();
        write_extension(&mut exts, EXT_SERVER_NAME, &server_name_extension(server_name));
        write_extension(&mut exts, EXT_SUPPORTED_GROUPS, &supported_groups_extension());
        write_extension(&mut exts, EXT_SIGNATURE_ALGORITHMS, &signature_algorithms_extension());
        write_extension(&mut exts, EXT_SUPPORTED_VERSIONS, &supported_versions_extension());
        write_extension(&mut exts, EXT_KEY_SHARE, &key_share_extension_client(GROUP_X25519, &x25519_public));
        body.vec_u16(&exts.into_bytes());

        let raw = handshake_message(HANDSHAKE_TYPE_CLIENT_HELLO, &body.into_bytes());
        Self {
            random,
            session_id: [0u8; 32],
            cipher_suites: cipher_suites.to_vec(),
            server_name: server_name.to_owned(),
            x25519_public: Some(x25519_public),
            raw,
        }
    }

    /// Offset of the 32-byte `SessionId` body inside [`Self::raw`]: 4 (handshake header) + 2
    /// (legacy_version) + 32 (random) + 1 (session_id length byte) = 39, per RFC 8446 §4.1.2.
    pub(crate) const SESSION_ID_OFFSET: usize = 39;

    pub(crate) fn splice_session_id(&mut self, session_id: [u8; 32]) {
        self.session_id = session_id;
        let (_, from_offset) = self.raw.split_at_mut(Self::SESSION_ID_OFFSET);
        let (field, _) = from_offset.split_at_mut(session_id.len());
        field.copy_from_slice(&session_id);
    }

    /// `raw` with the `SessionId` field zeroed, matching the state both sides use as AEAD
    /// additional data (client: before ever writing real content into it; server: reconstructed
    /// by re-zeroing the received ciphertext before `Open`).
    pub(crate) fn raw_with_zero_session_id(&self) -> Vec<u8> {
        let mut raw = self.raw.clone();
        let (_, from_offset) = raw.split_at_mut(Self::SESSION_ID_OFFSET);
        let (field, _) = from_offset.split_at_mut(self.session_id.len());
        field.fill(0);
        raw
    }

    pub(crate) fn parse(msg: &[u8]) -> Result<Self> {
        let mut r = Reader::new(msg);
        let msg_type = r.u8()?;
        if msg_type != HANDSHAKE_TYPE_CLIENT_HELLO {
            return Err(anyhow!("expected ClientHello, got handshake type {msg_type}"));
        }
        let len = r.u24()? as usize;
        let body = r.bytes(len)?;
        let mut b = Reader::new(body);
        let _legacy_version = b.u16()?;
        let random: [u8; 32] = b.bytes(32)?.try_into()?;
        let session_id_bytes = b.vec_u8()?;
        let mut session_id = [0u8; 32];
        if session_id_bytes.len() != 32 {
            return Err(anyhow!("REALITY requires a 32-byte ClientHello session id, got {}", session_id_bytes.len()));
        }
        session_id.copy_from_slice(session_id_bytes);

        let suites_bytes = b.vec_u16()?;
        let mut cipher_suites = Vec::new();
        let mut sr = Reader::new(suites_bytes);
        while sr.remaining() > 0 {
            if let Some(suite) = CipherSuite::from_id(sr.u16()?) {
                cipher_suites.push(suite);
            }
        }
        let _compression = b.vec_u8()?;

        let mut server_name = String::new();
        let mut x25519_public = None;
        let ext_bytes = b.vec_u16()?;
        let mut er = Reader::new(ext_bytes);
        while er.remaining() > 0 {
            let ext_type = er.u16()?;
            let ext_body = er.vec_u16()?;
            match ext_type {
                EXT_SERVER_NAME => server_name = parse_server_name_extension(ext_body)?,
                EXT_KEY_SHARE => {
                    if let Some(pubkey) = parse_key_share_client(ext_body, GROUP_X25519)? {
                        x25519_public = Some(pubkey);
                    }
                }
                _ => {}
            }
        }

        Ok(Self { random, session_id, cipher_suites, server_name, x25519_public, raw: msg.to_vec() })
    }
}

pub(crate) struct ServerHello {
    pub cipher_suite: CipherSuite,
    pub x25519_public: [u8; 32],
    pub raw: Vec<u8>,
}

impl ServerHello {
    pub(crate) fn build(
        random: [u8; 32],
        session_id_echo: &[u8; 32],
        cipher_suite: CipherSuite,
        x25519_public: [u8; 32],
    ) -> Self {
        let mut body = Writer::new();
        body.u16(LEGACY_VERSION_TLS12);
        body.bytes(&random);
        body.vec_u8(session_id_echo);
        body.u16(cipher_suite.id());
        body.u8(0); // legacy_compression_method: null

        let mut exts = Writer::new();
        write_extension(&mut exts, EXT_SUPPORTED_VERSIONS, &SUPPORTED_VERSION_TLS13.to_be_bytes());
        write_extension(&mut exts, EXT_KEY_SHARE, &key_share_entry(GROUP_X25519, &x25519_public));
        body.vec_u16(&exts.into_bytes());

        let raw = handshake_message(HANDSHAKE_TYPE_SERVER_HELLO, &body.into_bytes());
        Self { cipher_suite, x25519_public, raw }
    }

    pub(crate) fn parse(msg: &[u8]) -> Result<Self> {
        let mut r = Reader::new(msg);
        let msg_type = r.u8()?;
        if msg_type != HANDSHAKE_TYPE_SERVER_HELLO {
            return Err(anyhow!("expected ServerHello, got handshake type {msg_type}"));
        }
        let len = r.u24()? as usize;
        let body = r.bytes(len)?;
        let mut b = Reader::new(body);
        let _legacy_version = b.u16()?;
        let _random = b.bytes(32)?;
        let _session_id_echo = b.vec_u8()?;
        let cipher_suite =
            CipherSuite::from_id(b.u16()?).ok_or_else(|| anyhow!("ServerHello: unsupported cipher suite"))?;
        let _compression = b.u8()?;

        let mut supported_version_ok = false;
        let mut x25519_public = None;
        let ext_bytes = b.vec_u16()?;
        let mut er = Reader::new(ext_bytes);
        while er.remaining() > 0 {
            let ext_type = er.u16()?;
            let ext_body = er.vec_u16()?;
            match ext_type {
                EXT_SUPPORTED_VERSIONS => {
                    let version = <[u8; 2]>::try_from(ext_body).map(u16::from_be_bytes).unwrap_or_default();
                    if version == SUPPORTED_VERSION_TLS13 {
                        supported_version_ok = true;
                    }
                }
                EXT_KEY_SHARE => {
                    let mut kr = Reader::new(ext_body);
                    let group = kr.u16()?;
                    let data = kr.vec_u16()?;
                    if group == GROUP_X25519 && data.len() == 32 {
                        x25519_public = Some(<[u8; 32]>::try_from(data)?);
                    }
                }
                _ => {}
            }
        }
        if !supported_version_ok {
            return Err(anyhow!("ServerHello does not negotiate TLS 1.3"));
        }
        let x25519_public = x25519_public.ok_or_else(|| anyhow!("ServerHello: no usable X25519 key_share"))?;

        Ok(Self { cipher_suite, x25519_public, raw: msg.to_vec() })
    }
}

/// Always empty: the REALITY tunnel carries an inner proxy protocol, not HTTP, so ALPN and
/// friends are not needed.
pub(crate) fn build_encrypted_extensions() -> Vec<u8> {
    let mut body = Writer::new();
    body.vec_u16(&[]);
    handshake_message(HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, &body.into_bytes())
}

pub(crate) fn parse_encrypted_extensions(msg: &[u8]) -> Result<()> {
    let mut r = Reader::new(msg);
    let msg_type = r.u8()?;
    if msg_type != HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS {
        return Err(anyhow!("expected EncryptedExtensions, got handshake type {msg_type}"));
    }
    Ok(())
}

/// A single self-signed leaf, no chain, no extensions (RFC 8446 §4.4.2).
pub(crate) fn build_certificate(cert_der: &[u8]) -> Vec<u8> {
    let mut entry = Writer::new();
    entry.vec_u24(cert_der);
    entry.vec_u16(&[]); // certificate extensions: none

    let mut body = Writer::new();
    body.vec_u8(&[]); // certificate_request_context: empty (not a client cert)
    body.vec_u24(&entry.into_bytes());
    handshake_message(HANDSHAKE_TYPE_CERTIFICATE, &body.into_bytes())
}

pub(crate) fn parse_certificate(msg: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(msg);
    let msg_type = r.u8()?;
    if msg_type != HANDSHAKE_TYPE_CERTIFICATE {
        return Err(anyhow!("expected Certificate, got handshake type {msg_type}"));
    }
    let len = r.u24()? as usize;
    let body = r.bytes(len)?;
    let mut b = Reader::new(body);
    let _context = b.vec_u8()?;
    let list = b.vec_u24()?;
    let mut lr = Reader::new(list);
    let cert_der = lr.vec_u24()?;
    let _cert_extensions = lr.vec_u16()?;
    Ok(cert_der.to_vec())
}

/// RFC 8446 §4.4.3's signed content: 64 spaces, the context string, a zero byte, then the
/// transcript hash. REALITY always signs with Ed25519 (its fake leaf is always an Ed25519 key).
fn certificate_verify_signed_data(is_server: bool, transcript_digest: &[u8]) -> Vec<u8> {
    let context = if is_server { "TLS 1.3, server CertificateVerify" } else { "TLS 1.3, client CertificateVerify" };
    let mut data = vec![0x20u8; 64];
    data.extend_from_slice(context.as_bytes());
    data.push(0);
    data.extend_from_slice(transcript_digest);
    data
}

pub(crate) fn build_certificate_verify(signing_key: &ed25519_dalek::SigningKey, transcript_digest: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    let signed = certificate_verify_signed_data(true, transcript_digest);
    let signature = signing_key.sign(&signed).to_bytes();

    let mut body = Writer::new();
    body.u16(SIGNATURE_SCHEME_ED25519);
    body.vec_u16(&signature);
    handshake_message(HANDSHAKE_TYPE_CERTIFICATE_VERIFY, &body.into_bytes())
}

pub(crate) fn verify_certificate_verify(
    msg: &[u8],
    verifying_key: &ed25519_dalek::VerifyingKey,
    transcript_digest: &[u8],
) -> Result<()> {
    use ed25519_dalek::Verifier as _;
    let mut r = Reader::new(msg);
    let msg_type = r.u8()?;
    if msg_type != HANDSHAKE_TYPE_CERTIFICATE_VERIFY {
        return Err(anyhow!("expected CertificateVerify, got handshake type {msg_type}"));
    }
    let len = r.u24()? as usize;
    let body = r.bytes(len)?;
    let mut b = Reader::new(body);
    let scheme = b.u16()?;
    if scheme != SIGNATURE_SCHEME_ED25519 {
        return Err(anyhow!(
            "REALITY port only verifies Ed25519 CertificateVerify signatures, peer used scheme {scheme:#06x}"
        ));
    }
    let signature_bytes = b.vec_u16()?;
    let signature = ed25519_dalek::Signature::from_slice(signature_bytes)
        .map_err(|err| anyhow!("malformed Ed25519 signature: {err}"))?;
    let signed = certificate_verify_signed_data(true, transcript_digest);
    verifying_key.verify(&signed, &signature).map_err(|_| anyhow!("CertificateVerify signature does not match"))
}

pub(crate) fn build_finished(verify_data: &[u8]) -> Vec<u8> {
    handshake_message(HANDSHAKE_TYPE_FINISHED, verify_data)
}

pub(crate) fn parse_finished(msg: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(msg);
    let msg_type = r.u8()?;
    if msg_type != HANDSHAKE_TYPE_FINISHED {
        return Err(anyhow!("expected Finished, got handshake type {msg_type}"));
    }
    let len = r.u24()? as usize;
    Ok(r.bytes(len)?.to_vec())
}

fn write_extension(w: &mut Writer, ext_type: u16, body: &[u8]) {
    w.u16(ext_type);
    w.vec_u16(body);
}

fn server_name_extension(name: &str) -> Vec<u8> {
    let mut entry = Writer::new();
    entry.u8(0); // name_type: host_name
    entry.vec_u16(name.as_bytes());
    let mut list = Writer::new();
    list.vec_u16(&entry.into_bytes());
    list.into_bytes()
}

fn parse_server_name_extension(body: &[u8]) -> Result<String> {
    let mut r = Reader::new(body);
    let list = r.vec_u16()?;
    let mut lr = Reader::new(list);
    if lr.remaining() == 0 {
        return Ok(String::new());
    }
    let _name_type = lr.u8()?;
    let name = lr.vec_u16()?;
    Ok(String::from_utf8_lossy(name).into_owned())
}

fn supported_groups_extension() -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(GROUP_X25519);
    let mut out = Writer::new();
    out.vec_u16(&w.into_bytes());
    out.into_bytes()
}

fn signature_algorithms_extension() -> Vec<u8> {
    let mut w = Writer::new();
    for scheme in [SIGNATURE_SCHEME_ED25519, 0x0403u16, 0x0804u16, 0x0401u16] {
        w.u16(scheme);
    }
    let mut out = Writer::new();
    out.vec_u16(&w.into_bytes());
    out.into_bytes()
}

fn supported_versions_extension() -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(SUPPORTED_VERSION_TLS13);
    let mut out = Writer::new();
    out.vec_u8(&w.into_bytes());
    out.into_bytes()
}

/// RFC 8446 §4.2.8's single `KeyShareEntry`: a group plus a length-prefixed key.
fn key_share_entry(group: u16, public_key: &[u8; 32]) -> Vec<u8> {
    let mut entry = Writer::new();
    entry.u16(group);
    entry.vec_u16(public_key);
    entry.into_bytes()
}

/// RFC 8446 §4.2.8's `KeyShareClientHello` body is a `<2..2^16-1>`-length list of `KeyShareEntry`;
/// the server's is a bare entry, so the client form needs a list-length prefix
/// [`key_share_entry`] alone does not carry.
fn key_share_extension_client(group: u16, public_key: &[u8; 32]) -> Vec<u8> {
    let mut list = Writer::new();
    list.vec_u16(&key_share_entry(group, public_key));
    list.into_bytes()
}

/// Picks our entry out of a client that offers several groups; mirrors
/// [`key_share_extension_client`]'s list framing.
fn parse_key_share_client(body: &[u8], want_group: u16) -> Result<Option<[u8; 32]>> {
    let mut r = Reader::new(body);
    let list = r.vec_u16()?;
    let mut lr = Reader::new(list);
    while lr.remaining() > 0 {
        let group = lr.u16()?;
        let data = lr.vec_u16()?;
        if group == want_group && data.len() == 32 {
            return Ok(Some(<[u8; 32]>::try_from(data)?));
        }
    }
    Ok(None)
}

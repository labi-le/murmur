//! The client-side TLS 1.3 handshake behind [`UConn`](super::utls::UConn).
//!
//! `utls`'s whole point is that the `ClientHello` a caller configured reaches the wire unchanged.
//! `rustls` builds its own `ClientHello` and offers no hook to replace it, so this module drives
//! the handshake itself: it writes the `ClientHello`
//! [`UConn::build_handshake_state`](super::utls::UConn::build_handshake_state) assembled and then
//! runs RFC 8446 §4.1/§7 over the same primitives `rustls` would have used. Certificate-chain and
//! handshake-signature verification still go through the process-wide `rustls` provider, so the
//! trust decisions are identical to the plain [`Conn`](super::utls::Conn) path.
//!
//! Scope, stated up front because it is observable:
//!
//! * TLS 1.3 only. Every `ClientHelloId` in this crate's fingerprint table is a TLS 1.3
//!   browser fingerprint; a server that answers the fingerprinted hello with a TLS 1.2
//!   `ServerHello` is rejected rather than left to a handshake this module cannot run. A
//!   configuration that pins `max_version` below TLS 1.3 never reaches this module at all:
//!   [`UConn::handshake_context`](super::utls::UConn::handshake_context) hands such a connection
//!   to `rustls`, which keeps the plain TLS 1.2 path intact.
//! * `HelloRetryRequest` is answered with a second `ClientHello` (RFC 8446 §4.1.4/§4.4.1): the
//!   first `ClientHello` is replaced by `message_hash` in the transcript, the retry carries a
//!   fresh key share for the requested group and echoes any cookie, and a second retry is
//!   rejected. No 0-RTT, no session resumption. Post-handshake `NewSessionTicket` messages are
//!   accepted and ignored; `KeyUpdate` is honoured in both directions.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use anyhow::{anyhow, Result};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::SignatureScheme as RustlsSignatureScheme;
use sha2::{Digest, Sha256, Sha384};
use tokio::io::ReadBuf;

use murmur_common_net::io::Stream;
use murmur_log::debugln;

use super::utls::{
    verify_server_certificate, CertificateRequestInfo, Config, ConnectionState, CurveId, KeySharePrivateKeys,
    SignatureScheme, TlsSessionCapability, X509Certificate, VERSION_TLS13,
};

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;

const HANDSHAKE_SERVER_HELLO: u8 = 2;
const HANDSHAKE_NEW_SESSION_TICKET: u8 = 4;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 8;
const HANDSHAKE_CERTIFICATE: u8 = 11;
const HANDSHAKE_CERTIFICATE_REQUEST: u8 = 13;
const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 15;
const HANDSHAKE_FINISHED: u8 = 20;
const HANDSHAKE_KEY_UPDATE: u8 = 24;

const MAX_FRAGMENT_LEN: usize = 16384;
const MAX_RECORD_LEN: usize = MAX_FRAGMENT_LEN + 512;
const TAG_LEN: usize = 16;
const IV_LEN: usize = 12;
const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];

/// RFC 8446 §4.1.3's `HelloRetryRequest` sentinel replaces `ServerHello.random` to ask for a second
/// `ClientHello`. This crate cannot answer one, so it has to be recognised to produce a useful error
/// instead of a key-schedule failure.
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11,
    0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// RFC 8446 §4.4.3: a `CertificateVerify` signature covers 64 spaces, a context string, a zero byte
/// and the transcript hash.
const CERTIFICATE_VERIFY_PREFIX: [u8; 64] = [0x20; 64];
const SERVER_CERTIFICATE_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
const CLIENT_CERTIFICATE_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify";

/// The three RFC 8446 §B.4 cipher suites. `rustls`'s `AeadKey` constructor is crate-private, so the
/// record layer keeps its own AEAD rather than borrowing `rustls`'s.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tls13Suite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

impl Tls13Suite {
    pub(crate) const fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    pub(crate) const fn id(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::Chacha20Poly1305Sha256 => 0x1303,
        }
    }

    const fn hash_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => 32,
            Self::Aes256GcmSha384 => 48,
        }
    }

    const fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::Chacha20Poly1305Sha256 => 32,
        }
    }

    pub(crate) fn transcript_hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => Sha256::digest(data).to_vec(),
            Self::Aes256GcmSha384 => Sha384::digest(data).to_vec(),
        }
    }

    pub(crate) fn expand_label(self, secret: &[u8], label: &str, context: &[u8], out_len: usize) -> Result<Vec<u8>> {
        let full_label = format!("tls13 {label}");
        // DEVIATION: the label expansion would panic when the label or context does not fit the
        // one-byte length. The exporter label is caller-supplied, so fail closed instead.
        let label_len =
            u8::try_from(full_label.len()).map_err(|_| anyhow!("tls: HKDF-Expand-Label label or context too long"))?;
        let context_len =
            u8::try_from(context.len()).map_err(|_| anyhow!("tls: HKDF-Expand-Label label or context too long"))?;
        let mut info = Vec::with_capacity(3 + full_label.len() + context.len());
        info.extend_from_slice(&wire_u16(out_len));
        info.push(label_len);
        info.extend_from_slice(full_label.as_bytes());
        info.push(context_len);
        info.extend_from_slice(context);
        let mut out = vec![0u8; out_len];
        let expanded = match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => {
                let prk =
                    Hkdf::<Sha256>::from_prk(secret).map_err(|_| anyhow!("tls: HKDF PRK is shorter than HashLen"))?;
                prk.expand(&info, &mut out)
            }
            Self::Aes256GcmSha384 => {
                let prk =
                    Hkdf::<Sha384>::from_prk(secret).map_err(|_| anyhow!("tls: HKDF PRK is shorter than HashLen"))?;
                prk.expand(&info, &mut out)
            }
        };
        expanded.map_err(|_| anyhow!("tls: HKDF-Expand output length out of range"))?;
        Ok(out)
    }

    pub(crate) fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
            Self::Aes256GcmSha384 => Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec(),
        }
    }

    pub(crate) fn finished_mac(self, finished_key: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => {
                #[expect(
                    clippy::expect_used,
                    reason = "Hmac::new_from_slice accepts a key of any length, so the constructor cannot fail"
                )]
                let mut mac = Hmac::<Sha256>::new_from_slice(finished_key).expect("HMAC accepts any key length");
                mac.update(transcript_hash);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Aes256GcmSha384 => {
                #[expect(
                    clippy::expect_used,
                    reason = "Hmac::new_from_slice accepts a key of any length, so the constructor cannot fail"
                )]
                let mut mac = Hmac::<Sha384>::new_from_slice(finished_key).expect("HMAC accepts any key length");
                mac.update(transcript_hash);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    fn seal(self, key: &[u8], nonce: &[u8; IV_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let sealed = match self {
            Self::Aes128GcmSha256 => Aes128Gcm::new_from_slice(key)
                .map_err(|err| anyhow!("tls: aes-128-gcm key: {err}"))?
                .encrypt(nonce.into(), Payload { msg: plaintext, aad }),
            Self::Aes256GcmSha384 => Aes256Gcm::new_from_slice(key)
                .map_err(|err| anyhow!("tls: aes-256-gcm key: {err}"))?
                .encrypt(nonce.into(), Payload { msg: plaintext, aad }),
            Self::Chacha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|err| anyhow!("tls: chacha20poly1305 key: {err}"))?
                .encrypt(nonce.into(), Payload { msg: plaintext, aad }),
        };
        sealed.map_err(|_err| anyhow!("tls: record encryption failed"))
    }

    fn open(self, key: &[u8], nonce: &[u8; IV_LEN], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let opened = match self {
            Self::Aes128GcmSha256 => Aes128Gcm::new_from_slice(key)
                .map_err(|err| anyhow!("tls: aes-128-gcm key: {err}"))?
                .decrypt(nonce.into(), Payload { msg: ciphertext, aad }),
            Self::Aes256GcmSha384 => Aes256Gcm::new_from_slice(key)
                .map_err(|err| anyhow!("tls: aes-256-gcm key: {err}"))?
                .decrypt(nonce.into(), Payload { msg: ciphertext, aad }),
            Self::Chacha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|err| anyhow!("tls: chacha20poly1305 key: {err}"))?
                .decrypt(nonce.into(), Payload { msg: ciphertext, aad }),
        };
        opened.map_err(|_err| anyhow!("tls: record authentication failed"))
    }
}

fn record_nonce(iv: &[u8; IV_LEN], sequence: u64) -> [u8; IV_LEN] {
    let mut nonce = *iv;
    let (_, suffix) = nonce.split_at_mut(4);
    for (byte, mask) in suffix.iter_mut().zip(sequence.to_be_bytes()) {
        *byte ^= mask;
    }
    nonce
}

struct Reader<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let Some(rest) = self.buffer.get(self.offset..) else {
            return Err(anyhow!("tls: truncated handshake message"));
        };
        let Some((taken, _)) = rest.split_at_checked(length) else {
            return Err(anyhow!("tls: truncated handshake message"));
        };
        self.offset += length;
        Ok(taken)
    }

    fn u8(&mut self) -> Result<u8> {
        self.take(1)?.first().copied().ok_or_else(|| anyhow!("tls: truncated handshake message"))
    }

    fn u16(&mut self) -> Result<u16> {
        let (bytes, _) =
            self.take(2)?.split_first_chunk::<2>().ok_or_else(|| anyhow!("tls: truncated handshake message"))?;
        Ok(u16::from_be_bytes(*bytes))
    }

    fn u24(&mut self) -> Result<usize> {
        let (bytes, _) =
            self.take(3)?.split_first_chunk::<3>().ok_or_else(|| anyhow!("tls: truncated handshake message"))?;
        let [first, second, third] = *bytes;
        Ok((usize::from(first) << 16) | (usize::from(second) << 8) | usize::from(third))
    }

    fn vec8(&mut self) -> Result<&'a [u8]> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }

    fn vec16(&mut self) -> Result<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }

    fn vec24(&mut self) -> Result<&'a [u8]> {
        let length = self.u24()?;
        self.take(length)
    }
    fn remaining(&self) -> &'a [u8] {
        self.buffer.get(self.offset..).unwrap_or_default()
    }
}

/// The `ClientHello` handshake type, and the extension types a retry reply may carry.
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_MESSAGE_HASH: u8 = 254;
const EXTENSION_SUPPORTED_GROUPS: u16 = 10;
const EXTENSION_PADDING: u16 = 21;
const EXTENSION_SUPPORTED_VERSIONS: u16 = 43;
const EXTENSION_COOKIE: u16 = 44;
const EXTENSION_KEY_SHARE: u16 = 51;

struct ServerHelloFull {
    cipher_suite: u16,
    key_share_group: u16,
    key_share: Vec<u8>,
}

/// A `ServerHello` is either the real hello or a `HelloRetryRequest`, told apart by the random
/// sentinel before any key-share parsing, since a retry carries no key exchange.
enum ServerHello {
    Full(ServerHelloFull),
    Retry { selected_group: Option<CurveId>, cookie: Option<Vec<u8>>, suite: Tls13Suite },
}

/// The `ClientHello` facts a `ServerHello` or `HelloRetryRequest` has to be checked against.
struct OfferedClientHello {
    session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    supported_groups: Vec<u16>,
    key_share_groups: Vec<u16>,
}

impl OfferedClientHello {
    fn parse(raw: &[u8]) -> Result<Self> {
        let body = handshake_body(raw, HANDSHAKE_CLIENT_HELLO)?;
        let mut reader = Reader::new(body);
        reader.u16()?;
        reader.take(32)?;
        let session_id = reader.vec8()?.to_vec();
        let cipher_suites = {
            let mut list = Reader::new(reader.vec16()?);
            let mut suites = Vec::new();
            while !list.remaining().is_empty() {
                suites.push(list.u16()?);
            }
            suites
        };
        reader.vec8()?;
        let mut supported_groups = Vec::new();
        let mut key_share_groups = Vec::new();
        let mut reader = Reader::new(reader.vec16()?);
        while !reader.remaining().is_empty() {
            let extension_type = reader.u16()?;
            let data = reader.vec16()?;
            match extension_type {
                EXTENSION_SUPPORTED_GROUPS => {
                    let mut list = Reader::new(Reader::new(data).vec16()?);
                    while !list.remaining().is_empty() {
                        supported_groups.push(list.u16()?);
                    }
                }
                EXTENSION_KEY_SHARE => {
                    let mut list = Reader::new(Reader::new(data).vec16()?);
                    while !list.remaining().is_empty() {
                        key_share_groups.push(list.u16()?);
                        list.vec16()?;
                    }
                }
                _ => {}
            }
        }
        Ok(Self { session_id, cipher_suites, supported_groups, key_share_groups })
    }
}

/// The `ClientHello` fields a retry has to preserve: everything but the key share, the cookie and
/// the padding. Each extension is kept as its raw TLV body so an unmodified extension round-trips
/// byte for byte.
struct ClientHelloParts {
    legacy_version: u16,
    random: [u8; 32],
    session_id: Vec<u8>,
    cipher_suites: Vec<u8>,
    compression: Vec<u8>,
    extensions: Vec<(u16, Vec<u8>)>,
    had_padding: bool,
}

impl ClientHelloParts {
    fn parse(raw: &[u8]) -> Result<Self> {
        let body = handshake_body(raw, HANDSHAKE_CLIENT_HELLO)?;
        let mut reader = Reader::new(body);
        let legacy_version = reader.u16()?;
        let mut random = [0u8; 32];
        random.copy_from_slice(reader.take(32)?);
        let session_id = reader.vec8()?.to_vec();
        let cipher_suites = reader.vec16()?.to_vec();
        let compression = reader.vec8()?.to_vec();
        let mut extensions = Vec::new();
        let mut had_padding = false;
        let mut reader = Reader::new(reader.vec16()?);
        while !reader.remaining().is_empty() {
            let extension_type = reader.u16()?;
            let data = reader.vec16()?.to_vec();
            if extension_type == EXTENSION_PADDING {
                had_padding = true;
            }
            extensions.push((extension_type, data));
        }
        Ok(Self { legacy_version, random, session_id, cipher_suites, compression, extensions, had_padding })
    }

    fn marshal(&self, extensions: &[(u16, Vec<u8>)]) -> Result<Vec<u8>> {
        let mut extension_bytes = Vec::new();
        for (extension_type, body) in extensions {
            let length =
                u16::try_from(body.len()).map_err(|_| anyhow!("tls: extension {extension_type} is too long"))?;
            extension_bytes.extend_from_slice(&extension_type.to_be_bytes());
            extension_bytes.extend_from_slice(&length.to_be_bytes());
            extension_bytes.extend_from_slice(body);
        }
        let session_id_len = u8::try_from(self.session_id.len()).map_err(|_| anyhow!("tls: session id is too long"))?;
        let compression_len =
            u8::try_from(self.compression.len()).map_err(|_| anyhow!("tls: compression list is too long"))?;
        let cipher_suites_len =
            u16::try_from(self.cipher_suites.len()).map_err(|_| anyhow!("tls: cipher suite list is too long"))?;
        let extensions_len =
            u16::try_from(extension_bytes.len()).map_err(|_| anyhow!("tls: extension list is too long"))?;
        let mut body = Vec::new();
        body.extend_from_slice(&self.legacy_version.to_be_bytes());
        body.extend_from_slice(&self.random);
        body.push(session_id_len);
        body.extend_from_slice(&self.session_id);
        body.extend_from_slice(&cipher_suites_len.to_be_bytes());
        body.extend_from_slice(&self.cipher_suites);
        body.push(compression_len);
        body.extend_from_slice(&self.compression);
        body.extend_from_slice(&extensions_len.to_be_bytes());
        body.extend_from_slice(&extension_bytes);
        Ok(handshake_message(HANDSHAKE_CLIENT_HELLO, &body))
    }
}

/// RFC 8446 §4.4.1: the transcript replaces the first `ClientHello` with `message_hash` before
/// hashing anything after it.
fn message_hash(suite: Tls13Suite, client_hello: &[u8]) -> Vec<u8> {
    let digest = suite.transcript_hash(client_hello);
    let mut out = Vec::with_capacity(4 + digest.len());
    out.push(HANDSHAKE_MESSAGE_HASH);
    out.extend_from_slice(&wire_u24(digest.len()));
    out.extend_from_slice(&digest);
    out
}

/// The `key_share` extension body for a single fresh share.
fn key_share_body(group: u16, public: &[u8]) -> Result<Vec<u8>> {
    let public_len = u16::try_from(public.len()).map_err(|_| anyhow!("tls: key share is too long"))?;
    let mut entry = Vec::with_capacity(4 + public.len());
    entry.extend_from_slice(&group.to_be_bytes());
    entry.extend_from_slice(&public_len.to_be_bytes());
    entry.extend_from_slice(public);
    let entry_len = u16::try_from(entry.len()).map_err(|_| anyhow!("tls: key share list is too long"))?;
    let mut body = Vec::with_capacity(2 + entry.len());
    body.extend_from_slice(&entry_len.to_be_bytes());
    body.extend_from_slice(&entry);
    Ok(body)
}

/// Rebuilds the first `ClientHello` as the retry hello: the key share is replaced with one fresh
/// share for the requested group, the cookie is echoed, and the padding is resized so the retry
/// keeps the first hello's length.
fn build_retry_client_hello(
    client_hello: &[u8],
    selected_group: Option<CurveId>,
    cookie: Option<&[u8]>,
    key_shares: &mut KeySharePrivateKeys,
    provider: &CryptoProvider,
) -> Result<Vec<u8>> {
    let parts = ClientHelloParts::parse(client_hello)?;
    let original_len = client_hello.len();
    let mut fresh_share = match selected_group {
        Some(group) => Some(key_share_body(group.as_u16(), &key_shares.new_share_for(group, provider)?)?),
        None => None,
    };
    let mut extensions: Vec<(u16, Vec<u8>)> = Vec::with_capacity(parts.extensions.len() + 2);
    for (extension_type, body) in &parts.extensions {
        match *extension_type {
            EXTENSION_PADDING | EXTENSION_COOKIE => {}
            EXTENSION_KEY_SHARE => match fresh_share.take() {
                Some(fresh) => extensions.push((EXTENSION_KEY_SHARE, fresh)),
                None => extensions.push((EXTENSION_KEY_SHARE, body.clone())),
            },
            _ => extensions.push((*extension_type, body.clone())),
        }
    }
    if let Some(fresh) = fresh_share {
        extensions.push((EXTENSION_KEY_SHARE, fresh));
    }
    if let Some(cookie) = cookie {
        let length = u16::try_from(cookie.len()).map_err(|_| anyhow!("tls: retry cookie is too long"))?;
        let mut body = Vec::with_capacity(2 + cookie.len());
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(cookie);
        extensions.push((EXTENSION_COOKIE, body));
    }
    if parts.had_padding {
        let unpadded_len = parts.marshal(&extensions)?.len();
        if let Some(padding) = original_len.checked_sub(unpadded_len + 4).filter(|padding| *padding > 0) {
            extensions.push((EXTENSION_PADDING, vec![0u8; padding]));
        }
    }
    parts.marshal(&extensions)
}

fn parse_server_hello(body: &[u8], offered: &OfferedClientHello) -> Result<ServerHello> {
    let mut reader = Reader::new(body);
    let legacy_version = reader.u16()?;
    let mut random = [0u8; 32];
    random.copy_from_slice(reader.take(32)?);
    let session_id = reader.vec8()?.to_vec();
    let cipher_suite = reader.u16()?;
    reader.u8()?;
    let extensions = reader.vec16()?;

    if random == HELLO_RETRY_REQUEST_RANDOM {
        return parse_hello_retry_request(legacy_version, &session_id, cipher_suite, extensions, offered);
    }

    let mut selected_version = None;
    let mut key_share = None;
    let mut reader = Reader::new(extensions);
    while !reader.remaining().is_empty() {
        let extension_type = reader.u16()?;
        let data = reader.vec16()?;
        if extension_type == EXTENSION_SUPPORTED_VERSIONS {
            selected_version = Some(Reader::new(data).u16()?);
        } else if extension_type == EXTENSION_KEY_SHARE {
            let mut share = Reader::new(data);
            let group = share.u16()?;
            let key_exchange = share.vec16()?.to_vec();
            if !share.remaining().is_empty() {
                return Err(anyhow!("tls: server key_share has trailing bytes"));
            }
            key_share = Some((group, key_exchange));
        }
    }
    if selected_version != Some(VERSION_TLS13) {
        return Err(anyhow!("tls: server did not select TLS 1.3 (0x0304) for a fingerprinted ClientHello"));
    }
    let Some((key_share_group, key_share)) = key_share else {
        return Err(anyhow!("tls: server sent no key_share extension"));
    };
    Ok(ServerHello::Full(ServerHelloFull { cipher_suite, key_share_group, key_share }))
}

fn parse_hello_retry_request(
    legacy_version: u16,
    session_id: &[u8],
    cipher_suite: u16,
    extensions: &[u8],
    offered: &OfferedClientHello,
) -> Result<ServerHello> {
    if legacy_version != u16::from_be_bytes(LEGACY_RECORD_VERSION) {
        return Err(anyhow!("tls: HelloRetryRequest legacy_version 0x{legacy_version:04x} is not 0x0303"));
    }
    if session_id != offered.session_id.as_slice() {
        return Err(anyhow!("tls: HelloRetryRequest did not echo the ClientHello session id"));
    }
    let suite = Tls13Suite::from_id(cipher_suite)
        .ok_or_else(|| anyhow!("tls: HelloRetryRequest selected unsupported cipher suite 0x{cipher_suite:04x}"))?;
    if !offered.cipher_suites.contains(&cipher_suite) {
        return Err(anyhow!("tls: HelloRetryRequest selected a cipher suite the ClientHello did not offer"));
    }

    let mut selected_version = None;
    let mut selected_group = None;
    let mut cookie = None;
    let mut seen: Vec<u16> = Vec::new();
    let mut reader = Reader::new(extensions);
    while !reader.remaining().is_empty() {
        let extension_type = reader.u16()?;
        let data = reader.vec16()?;
        if seen.contains(&extension_type) {
            return Err(anyhow!("tls: HelloRetryRequest repeats extension {extension_type}"));
        }
        seen.push(extension_type);
        match extension_type {
            EXTENSION_SUPPORTED_VERSIONS => selected_version = Some(Reader::new(data).u16()?),
            EXTENSION_KEY_SHARE => {
                if data.len() != 2 {
                    return Err(anyhow!("tls: HelloRetryRequest key_share is {} bytes, want 2", data.len()));
                }
                let group = Reader::new(data).u16()?;
                if !offered.supported_groups.contains(&group) {
                    return Err(anyhow!(
                        "tls: HelloRetryRequest selected group 0x{group:04x} the ClientHello did not offer"
                    ));
                }
                if offered.key_share_groups.contains(&group) {
                    return Err(anyhow!(
                        "tls: HelloRetryRequest selected group 0x{group:04x} that already carries a key share"
                    ));
                }
                selected_group = Some(CurveId(group));
            }
            EXTENSION_COOKIE => {
                let mut cookie_reader = Reader::new(data);
                let value = cookie_reader.vec16()?.to_vec();
                if !cookie_reader.remaining().is_empty() {
                    return Err(anyhow!("tls: HelloRetryRequest cookie has trailing bytes"));
                }
                if value.is_empty() {
                    return Err(anyhow!("tls: HelloRetryRequest cookie is empty"));
                }
                cookie = Some(value);
            }
            other => return Err(anyhow!("tls: HelloRetryRequest carries unexpected extension {other}")),
        }
    }
    if selected_version != Some(VERSION_TLS13) {
        return Err(anyhow!("tls: HelloRetryRequest did not select TLS 1.3 (0x0304)"));
    }
    if selected_group.is_none() && cookie.is_none() {
        return Err(anyhow!("tls: HelloRetryRequest changes nothing"));
    }
    Ok(ServerHello::Retry { selected_group, cookie, suite })
}

fn encrypted_extensions_alpn(data: &[u8]) -> Result<Option<String>> {
    let mut reader = Reader::new(data);
    let mut alpn = None;
    let mut reader = Reader::new(reader.vec16()?);
    while !reader.remaining().is_empty() {
        let extension_type = reader.u16()?;
        let body = reader.vec16()?;
        if extension_type == 16 {
            let mut list = Reader::new(body);
            let mut protocols = Reader::new(list.vec16()?);
            if !protocols.remaining().is_empty() {
                alpn = Some(String::from_utf8_lossy(protocols.vec8()?).into_owned());
            }
        }
    }
    Ok(alpn)
}

/// The `Certificate` body opens with `certificate_request_context<0..2^8-1>`, which a server sends
/// empty outside post-handshake authentication, then the u24 `certificate_list`.
fn certificate_message(data: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = Reader::new(data);
    reader.vec8()?;
    let mut list = Reader::new(reader.vec24()?);
    let mut certificates = Vec::new();
    while !list.remaining().is_empty() {
        certificates.push(CertificateDer::from(list.vec24()?.to_vec()));
        list.vec16()?;
    }
    Ok(certificates)
}

struct CertificateVerify {
    scheme: u16,
    signature: Vec<u8>,
}

fn certificate_verify_message(data: &[u8]) -> Result<CertificateVerify> {
    let mut reader = Reader::new(data);
    let scheme = reader.u16()?;
    let signature = reader.vec16()?.to_vec();
    Ok(CertificateVerify { scheme, signature })
}

/// `CertificateRequest` carries the same `certificate_request_context<0..2^8-1>`, then an
/// `Extension extensions<2..2^16-1>` TLV list. The schemes live in `signature_algorithms` behind a
/// u16-length-prefixed `SignatureScheme` vector.
fn certificate_request_schemes(data: &[u8]) -> Result<Vec<u16>> {
    let mut reader = Reader::new(data);
    reader.vec8()?;
    let mut extensions = Reader::new(reader.vec16()?);
    let mut schemes = Vec::new();
    while !extensions.remaining().is_empty() {
        let extension_type = extensions.u16()?;
        let body = extensions.vec16()?;
        if extension_type == 13 {
            let mut list = Reader::new(body);
            let mut supported = Reader::new(list.vec16()?);
            while !supported.remaining().is_empty() {
                schemes.push(supported.u16()?);
            }
        }
    }
    Ok(schemes)
}

fn alert_message(alert: &[u8]) -> String {
    let name = match alert.get(1).copied() {
        Some(0) => "close_notify",
        Some(10) => "unexpected_message",
        Some(20) => "bad_record_mac",
        Some(21) => "decryption_failed",
        Some(22) => "record_overflow",
        Some(40) => "handshake_failure",
        Some(42) => "bad_certificate",
        Some(43) => "unsupported_certificate",
        Some(44) => "certificate_revoked",
        Some(45) => "certificate_expired",
        Some(46) => "certificate_unknown",
        Some(47) => "illegal_parameter",
        Some(48) => "unknown_ca",
        Some(49) => "access_denied",
        Some(50) => "decode_error",
        Some(51) => "decrypt_error",
        Some(60) => "export_restriction",
        Some(70) => "protocol_version",
        Some(71) => "insufficient_security",
        Some(80) => "internal_error",
        Some(86) => "inappropriate_fallback",
        Some(90) => "user_canceled",
        Some(109) => "missing_extension",
        Some(110) => "unsupported_extension",
        Some(112) => "unrecognized_name",
        Some(115) => "unknown_psk_identity",
        Some(116) => "certificate_required",
        Some(120) => "no_application_protocol",
        Some(description) => return format!("tls: peer sent alert {description}"),
        None => return "tls: peer sent a truncated alert".to_owned(),
    };
    format!("tls: peer sent alert {name}")
}

/// The low two bytes of `length`, big-endian: every 16-bit length field this module writes (record
/// length, handshake length, HKDF-Expand-Label output length) carries only those bytes.
fn wire_u16(length: usize) -> [u8; 2] {
    let [.., high, low] = length.to_be_bytes();
    [high, low]
}

/// The low three bytes of `length`, big-endian: the RFC 8446 u24 handshake-body length prefix.
fn wire_u24(length: usize) -> [u8; 3] {
    let [.., first, second, third] = length.to_be_bytes();
    [first, second, third]
}

fn write_plaintext_record(out: &mut Vec<u8>, content_type: u8, payload: &[u8]) {
    for fragment in payload.chunks(MAX_FRAGMENT_LEN) {
        out.push(content_type);
        out.extend_from_slice(&LEGACY_RECORD_VERSION);
        out.extend_from_slice(&wire_u16(fragment.len()));
        out.extend_from_slice(fragment);
    }
}

/// RFC 8446 §4: `msg_type(1) || length(3) || body`. The transcript hashes these exact bytes, so the
/// same buffer is both written and hashed.
fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(kind);
    message.extend_from_slice(&wire_u24(body.len()));
    message.extend_from_slice(body);
    message
}

/// The body of a handshake message read off the wire: everything past `msg_type(1) ||
/// length(3)`. The declared length must match, so a truncated or over-long message is rejected
/// before a parser reads past it.
fn handshake_body(raw: &[u8], kind: u8) -> Result<&[u8]> {
    let mut header = Reader::new(raw);
    if header.u8()? != kind {
        return Err(anyhow!("tls: expected handshake type {kind}"));
    }
    let length = header.u24()?;
    let body = raw.get(header.offset..).ok_or_else(|| anyhow!("tls: truncated handshake message"))?;
    if body.len() != length {
        return Err(anyhow!("tls: handshake message declares {length} bytes, carries {}", body.len()));
    }
    Ok(body)
}

fn traffic_key(suite: Tls13Suite, secret: &[u8]) -> Result<(Vec<u8>, [u8; IV_LEN])> {
    let key = suite.expand_label(secret, "key", &[], suite.key_len())?;
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&suite.expand_label(secret, "iv", &[], IV_LEN)?);
    Ok((key, iv))
}

fn verify_handshake_signature(
    provider: &CryptoProvider,
    raw: u16,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let scheme = RustlsSignatureScheme::from(raw);
    let algorithms = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(candidate, _)| *candidate == scheme)
        .map(|(_, algorithms)| *algorithms)
        .ok_or_else(|| anyhow!("tls: handshake signed with an unadvertised signature scheme 0x{raw:04x}"))?;
    for algorithm in algorithms {
        if algorithm.verify_signature(public_key, message, signature).is_ok() {
            return Ok(());
        }
    }
    Err(anyhow!("tls: server CertificateVerify signature is invalid"))
}

struct ServerFlight {
    certificates: Vec<CertificateDer<'static>>,
    transcript_before_certificate_verify: Vec<u8>,
    alpn: Option<String>,
    certificate_requested: bool,
    offered_schemes: Vec<u16>,
}

impl ServerFlight {
    const fn empty() -> Self {
        Self {
            certificates: Vec::new(),
            transcript_before_certificate_verify: Vec::new(),
            alpn: None,
            certificate_requested: false,
            offered_schemes: Vec::new(),
        }
    }
}

/// RFC 8446 §7.5 exporter over a TLS 1.3 `exporter_master_secret`: derive a per-label secret with
/// `Derive-Secret(exporter_master_secret, label, "")` and expand the literal label `"exporter"`
/// over `Hash(context)`, which is why the caller's `label` is used verbatim.
fn derive_exported_keying_material(
    suite: Tls13Suite,
    exporter_secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let derived = suite.expand_label(exporter_secret, label, &suite.transcript_hash(&[]), suite.hash_len())?;
    suite.expand_label(&derived, "exporter", &suite.transcript_hash(context), length)
}

/// Per-connection state of the fingerprinted client handshake. The transport itself stays in the
/// enclosing [`Conn`](super::utls::Conn) so `close`, the half-closes and the deadline hooks keep
/// reaching the socket; every method that touches the wire takes it as an argument.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the flags are independent parts of the stream state (write half closed, close_notify sent, peer closed, record body in progress), not one state machine"
)]
pub(crate) struct UtlsClient {
    config: Arc<Config>,
    provider: Arc<CryptoProvider>,
    client_hello: Vec<u8>,
    key_shares: KeySharePrivateKeys,
    suite: Option<Tls13Suite>,
    client_handshake_secret: Vec<u8>,
    server_handshake_secret: Vec<u8>,
    master_secret: Vec<u8>,
    client_key: Vec<u8>,
    client_iv: [u8; IV_LEN],
    client_sequence: u64,
    server_key: Vec<u8>,
    server_iv: [u8; IV_LEN],
    server_sequence: u64,
    client_application_secret: Vec<u8>,
    server_application_secret: Vec<u8>,
    exporter_secret: Vec<u8>,
    transcript: Vec<u8>,
    handshake_buffer: Vec<u8>,
    plain: Vec<u8>,
    plain_offset: usize,
    header: [u8; 5],
    header_filled: usize,
    body: Vec<u8>,
    body_filled: usize,
    body_started: bool,
    pending_record: Option<(u8, Vec<u8>)>,
    pending_out: Vec<u8>,
    pending_length: usize,
    close_notify_sent: bool,
    write_closed: bool,
    peer_closed: bool,
    state: ConnectionState,
}

impl UtlsClient {
    pub(crate) fn new(
        config: Arc<Config>,
        provider: Arc<CryptoProvider>,
        client_hello: Vec<u8>,
        key_shares: KeySharePrivateKeys,
    ) -> Self {
        Self {
            config,
            provider,
            client_hello,
            key_shares,
            suite: None,
            client_handshake_secret: Vec::new(),
            server_handshake_secret: Vec::new(),
            master_secret: Vec::new(),
            client_key: Vec::new(),
            client_iv: [0u8; IV_LEN],
            client_sequence: 0,
            server_key: Vec::new(),
            server_iv: [0u8; IV_LEN],
            server_sequence: 0,
            client_application_secret: Vec::new(),
            server_application_secret: Vec::new(),
            exporter_secret: Vec::new(),
            transcript: Vec::new(),
            handshake_buffer: Vec::new(),
            plain: Vec::new(),
            plain_offset: 0,
            header: [0u8; 5],
            header_filled: 0,
            body: Vec::new(),
            body_filled: 0,
            body_started: false,
            pending_record: None,
            pending_out: Vec::new(),
            pending_length: 0,
            close_notify_sent: false,
            write_closed: false,
            peer_closed: false,
            state: ConnectionState::default(),
        }
    }

    pub(crate) fn connection_state(&self) -> ConnectionState {
        self.state.clone()
    }

    pub(crate) fn export_keying_material(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        let Some(suite) = self.suite else {
            return Err(anyhow!("tls: handshake is not complete"));
        };
        derive_exported_keying_material(suite, &self.exporter_secret, label, context, length)
    }

    fn suite(&self) -> Result<Tls13Suite> {
        self.suite.ok_or_else(|| anyhow!("tls: handshake keys are not installed"))
    }

    // NOT cancel-safe: the handshake writes its preamble and messages to the socket before it completes, so a dropped call leaves the connection mid-exchange; the arms that await it drop it only when the connection is being torn down.
    pub(crate) async fn handshake(&mut self, stream: &mut dyn Stream) -> Result<()> {
        let mut out = Vec::new();
        write_plaintext_record(&mut out, CONTENT_HANDSHAKE, &self.client_hello);
        Self::write_bytes(stream, &out).await?;

        let offered = OfferedClientHello::parse(&self.client_hello)?;
        let first = self.read_handshake_message(stream).await?;
        if first.first() != Some(&HANDSHAKE_SERVER_HELLO) {
            return Err(anyhow!("tls: expected ServerHello, got handshake type {:?}", first.first()));
        }
        let parsed = parse_server_hello(handshake_body(&first, HANDSHAKE_SERVER_HELLO)?, &offered)?;
        let hello = match parsed {
            ServerHello::Full(hello) => {
                self.transcript.extend_from_slice(&self.client_hello);
                self.transcript.extend_from_slice(&first);
                hello
            }
            ServerHello::Retry { selected_group, cookie, suite } => {
                let retry_hello = build_retry_client_hello(
                    &self.client_hello,
                    selected_group,
                    cookie.as_deref(),
                    &mut self.key_shares,
                    &self.provider,
                )?;
                self.transcript = message_hash(suite, &self.client_hello);
                self.transcript.extend_from_slice(&first);
                self.transcript.extend_from_slice(&retry_hello);

                let mut out = Vec::new();
                write_plaintext_record(&mut out, CONTENT_HANDSHAKE, &retry_hello);
                Self::write_bytes(stream, &out).await?;

                let second = self.read_handshake_message(stream).await?;
                if second.first() != Some(&HANDSHAKE_SERVER_HELLO) {
                    return Err(anyhow!("tls: expected ServerHello after the retry, got {:?}", second.first()));
                }
                let retry_offered = OfferedClientHello::parse(&retry_hello)?;
                let second_body = handshake_body(&second, HANDSHAKE_SERVER_HELLO)?;
                let hello = match parse_server_hello(second_body, &retry_offered)? {
                    ServerHello::Full(hello) => hello,
                    ServerHello::Retry { .. } => {
                        return Err(anyhow!("tls: server sent a second HelloRetryRequest"));
                    }
                };
                if hello.cipher_suite != suite.id() {
                    return Err(anyhow!(
                        "tls: server changed the cipher suite from 0x{:04x} to 0x{:04x} after a HelloRetryRequest",
                        suite.id(),
                        hello.cipher_suite
                    ));
                }
                if let Some(group) = selected_group.filter(|group| hello.key_share_group != group.as_u16()) {
                    return Err(anyhow!(
                        "tls: server selected key share group 0x{:04x} after a HelloRetryRequest for group 0x{:04x}",
                        hello.key_share_group,
                        group.as_u16()
                    ));
                }
                self.transcript.extend_from_slice(&second);
                hello
            }
        };
        self.finish_server_hello(stream, hello).await
    }

    async fn finish_server_hello(&mut self, stream: &mut dyn Stream, hello: ServerHelloFull) -> Result<()> {
        let suite = Tls13Suite::from_id(hello.cipher_suite)
            .ok_or_else(|| anyhow!("tls: server selected unsupported cipher suite 0x{:04x}", hello.cipher_suite))?;
        let shared_secret = self.key_shares.complete(CurveId(hello.key_share_group), &hello.key_share)?;
        self.install_handshake_keys(suite, &shared_secret)?;

        let mut out = Vec::new();
        write_plaintext_record(&mut out, CONTENT_CHANGE_CIPHER_SPEC, &[0x01]);
        Self::write_bytes(stream, &out).await?;

        let mut flight = self.read_server_flight(stream).await?;
        self.state.peer_certificates = flight
            .certificates
            .iter()
            .map(|der| X509Certificate::parse(der.as_ref()))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(Arc::new)
            .collect();
        self.verify_peer()?;
        self.state.server_name.clone_from(&self.config.server_name);
        self.state.version = VERSION_TLS13;
        self.state.handshake_complete = true;
        self.state.cipher_suite = suite.id();
        self.state.negotiated_protocol_is_mutual = true;
        if let Some(protocol) = flight.alpn.take() {
            self.state.negotiated_protocol = protocol;
        }
        self.send_client_flight(stream, suite, &flight).await?;
        if let Some(verify_connection) = &self.config.verify_connection {
            verify_connection(&self.state)?;
        }
        debugln!("utls: {} ClientHello completed, cipher suite 0x{:04x}", self.config.server_name, suite.id());
        Ok(())
    }

    pub(crate) fn session_capability(&self) -> TlsSessionCapability {
        TlsSessionCapability {
            handshake_complete: self.state.handshake_complete,
            version: self.state.version,
            cipher_suite: self.state.cipher_suite,
        }
    }

    pub(crate) fn take_buffered_incoming(&mut self) -> Option<Vec<u8>> {
        // A partially read or already-decrypted record on the socket would be stranded once the
        // raw transport takes over, so refuse rather than lose ciphertext.
        if self.pending_record.is_some()
            || self.header_filled != 0
            || self.body_filled != 0
            || !self.handshake_buffer.is_empty()
        {
            return None;
        }
        let buffered =
            if self.plain_offset < self.plain.len() { self.plain.split_off(self.plain_offset) } else { Vec::new() };
        self.plain.clear();
        self.plain_offset = 0;
        Some(buffered)
    }

    fn install_handshake_keys(&mut self, suite: Tls13Suite, shared_secret: &[u8]) -> Result<()> {
        let hash_len = suite.hash_len();
        let zeros = vec![0u8; hash_len];
        let empty_hash = suite.transcript_hash(&[]);
        let early_secret = suite.extract(&zeros, &zeros);
        let handshake_ikm = suite.expand_label(&early_secret, "derived", &empty_hash, hash_len)?;
        let handshake_secret = suite.extract(&handshake_ikm, shared_secret);
        let digest = suite.transcript_hash(&self.transcript);
        let client_secret = suite.expand_label(&handshake_secret, "c hs traffic", &digest, hash_len)?;
        let server_secret = suite.expand_label(&handshake_secret, "s hs traffic", &digest, hash_len)?;
        let (client_key, client_iv) = traffic_key(suite, &client_secret)?;
        let (server_key, server_iv) = traffic_key(suite, &server_secret)?;
        let derived = suite.expand_label(&handshake_secret, "derived", &empty_hash, hash_len)?;
        self.master_secret = suite.extract(&derived, &zeros);
        self.client_handshake_secret = client_secret;
        self.server_handshake_secret = server_secret;
        self.client_key = client_key;
        self.client_iv = client_iv;
        self.server_key = server_key;
        self.server_iv = server_iv;
        self.suite = Some(suite);
        Ok(())
    }

    async fn read_server_flight(&mut self, stream: &mut dyn Stream) -> Result<ServerFlight> {
        let mut flight = ServerFlight::empty();
        loop {
            let suite = self.suite()?;
            let raw = self.read_handshake_message(stream).await?;
            let Some(&kind) = raw.first() else {
                return Err(anyhow!("tls: empty handshake message"));
            };
            let body = handshake_body(&raw, kind)?;
            match kind {
                HANDSHAKE_ENCRYPTED_EXTENSIONS => {
                    flight.alpn = encrypted_extensions_alpn(body)?;
                    self.transcript.extend_from_slice(&raw);
                }
                HANDSHAKE_CERTIFICATE_REQUEST => {
                    flight.certificate_requested = true;
                    flight.offered_schemes = certificate_request_schemes(body)?;
                    self.transcript.extend_from_slice(&raw);
                }
                HANDSHAKE_CERTIFICATE => {
                    flight.certificates = certificate_message(body)?;
                    self.transcript.extend_from_slice(&raw);
                    flight.transcript_before_certificate_verify = suite.transcript_hash(&self.transcript);
                }
                HANDSHAKE_CERTIFICATE_VERIFY => {
                    let signed = certificate_verify_message(body)?;
                    self.verify_server_certificate_verify(&signed, &flight)?;
                    self.transcript.extend_from_slice(&raw);
                }
                HANDSHAKE_FINISHED => {
                    let finished_key =
                        suite.expand_label(&self.server_handshake_secret, "finished", &[], suite.hash_len())?;
                    let expected = suite.finished_mac(&finished_key, &suite.transcript_hash(&self.transcript));
                    if body != expected.as_slice() {
                        return Err(anyhow!("tls: server Finished verify_data mismatch"));
                    }
                    self.transcript.extend_from_slice(&raw);
                    return Ok(flight);
                }
                _ => return Err(anyhow!("tls: unexpected handshake type {kind} in the server flight")),
            }
        }
    }

    fn verify_server_certificate_verify(&self, signed: &CertificateVerify, flight: &ServerFlight) -> Result<()> {
        let Some(end_entity) = flight.certificates.first() else {
            return Err(anyhow!("tls: server sent a CertificateVerify without a Certificate"));
        };
        let certificate = X509Certificate::parse(end_entity.as_ref())?;
        let public_key = certificate
            .subject_public_key()
            .ok_or_else(|| anyhow!("tls: server certificate has no usable public key"))?;
        let mut signed_bytes = Vec::new();
        signed_bytes.extend_from_slice(&CERTIFICATE_VERIFY_PREFIX);
        signed_bytes.extend_from_slice(SERVER_CERTIFICATE_VERIFY_CONTEXT);
        signed_bytes.push(0);
        signed_bytes.extend_from_slice(&flight.transcript_before_certificate_verify);
        verify_handshake_signature(&self.provider, signed.scheme, public_key, &signed_bytes, &signed.signature)
    }

    fn verify_peer(&self) -> Result<()> {
        let end_entity =
            self.state.peer_certificates.first().cloned().ok_or_else(|| anyhow!("tls: server sent no certificate"))?;
        let intermediates: Vec<CertificateDer<'static>> =
            self.state.peer_certificates.iter().skip(1).map(|cert| CertificateDer::from(cert.raw.clone())).collect();
        verify_server_certificate(
            &self.config,
            &self.provider,
            &CertificateDer::from(end_entity.raw.clone()),
            &intermediates,
        )?;
        if let Some(verify_peer_certificate) = &self.config.verify_peer_certificate {
            let raw_certificates: Vec<Vec<u8>> =
                self.state.peer_certificates.iter().map(|cert| cert.raw.clone()).collect();
            verify_peer_certificate(&raw_certificates, &[])?;
        }
        Ok(())
    }

    async fn send_client_flight(
        &mut self,
        stream: &mut dyn Stream,
        suite: Tls13Suite,
        flight: &ServerFlight,
    ) -> Result<()> {
        // TLS 1.3 client/server application traffic secrets use transcript through ServerHello/Finished,
        // before the client's authentication and Finished messages (RFC 8446 §7.1).
        let application_digest = suite.transcript_hash(&self.transcript);
        let mut out = Vec::new();
        if flight.certificate_requested {
            self.append_client_certificate(&mut out, flight)?;
        }
        let client_finished_key =
            suite.expand_label(&self.client_handshake_secret, "finished", &[], suite.hash_len())?;
        let verify_data = suite.finished_mac(&client_finished_key, &suite.transcript_hash(&self.transcript));
        let finished = handshake_message(HANDSHAKE_FINISHED, &verify_data);
        self.transcript.extend_from_slice(&finished);
        out.extend_from_slice(&self.seal_record(CONTENT_HANDSHAKE, &finished)?);

        let client_secret =
            suite.expand_label(&self.master_secret, "c ap traffic", &application_digest, suite.hash_len())?;
        let server_secret =
            suite.expand_label(&self.master_secret, "s ap traffic", &application_digest, suite.hash_len())?;
        self.exporter_secret =
            suite.expand_label(&self.master_secret, "exp master", &application_digest, suite.hash_len())?;
        self.client_application_secret = client_secret;
        self.server_application_secret = server_secret;
        (self.client_key, self.client_iv) = traffic_key(suite, &self.client_application_secret)?;
        (self.server_key, self.server_iv) = traffic_key(suite, &self.server_application_secret)?;
        self.client_sequence = 0;
        self.server_sequence = 0;

        Self::write_bytes(stream, &out).await
    }

    fn append_client_certificate(&mut self, out: &mut Vec<u8>, flight: &ServerFlight) -> Result<()> {
        let offered: Vec<RustlsSignatureScheme> =
            flight.offered_schemes.iter().map(|scheme| RustlsSignatureScheme::from(*scheme)).collect();
        let certificate = match &self.config.get_client_certificate {
            Some(get_client_certificate) => get_client_certificate(&CertificateRequestInfo {
                acceptable_cas: Vec::new(),
                signature_schemes: flight.offered_schemes.iter().copied().map(SignatureScheme).collect(),
                version: 0,
            })?,
            None => self
                .config
                .certificates
                .iter()
                .find(|certificate| !certificate.certificate.is_empty() && certificate.private_key.is_some())
                .cloned(),
        };
        let mut list = Vec::new();
        if let Some(certificate) = certificate.as_ref() {
            for der in &certificate.certificate {
                list.extend_from_slice(&wire_u24(der.len()));
                list.extend_from_slice(der);
                list.extend_from_slice(&[0u8, 0]);
            }
        }
        let mut body = vec![0u8];
        body.extend_from_slice(&wire_u24(list.len()));
        body.extend_from_slice(&list);
        let message = handshake_message(HANDSHAKE_CERTIFICATE, &body);
        self.transcript.extend_from_slice(&message);
        out.extend_from_slice(&self.seal_record(CONTENT_HANDSHAKE, &message)?);

        let Some(certificate) = certificate else {
            return Ok(());
        };
        let private_key = certificate.private_key.as_ref().map(PrivateKeyDer::clone_key);
        let Some(private_key) = private_key else {
            return Ok(());
        };
        let signing_key = self.provider.key_provider.load_private_key(private_key)?;
        let Some(signer) = signing_key.choose_scheme(&offered) else {
            return Err(anyhow!("tls: no usable client signature scheme for the server's CertificateRequest"));
        };
        let scheme = u16::from(signer.scheme());
        let mut signed_bytes = Vec::new();
        signed_bytes.extend_from_slice(&CERTIFICATE_VERIFY_PREFIX);
        signed_bytes.extend_from_slice(CLIENT_CERTIFICATE_VERIFY_CONTEXT);
        signed_bytes.push(0);
        signed_bytes.extend_from_slice(&self.suite()?.transcript_hash(&self.transcript));
        let signature = signer.sign(&signed_bytes)?;
        let mut body = Vec::with_capacity(4 + signature.len());
        body.extend_from_slice(&scheme.to_be_bytes());
        body.extend_from_slice(&wire_u16(signature.len()));
        body.extend_from_slice(&signature);
        let verify = handshake_message(HANDSHAKE_CERTIFICATE_VERIFY, &body);
        self.transcript.extend_from_slice(&verify);
        out.extend_from_slice(&self.seal_record(CONTENT_HANDSHAKE, &verify)?);
        Ok(())
    }

    fn seal_record(&mut self, content_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let suite = self.suite()?;
        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.extend_from_slice(payload);
        inner.push(content_type);
        let sealed_length = inner.len() + TAG_LEN;
        let mut header = [0u8; 5];
        header[..3].copy_from_slice(&[CONTENT_APPLICATION_DATA, LEGACY_RECORD_VERSION[0], LEGACY_RECORD_VERSION[1]]);
        header[3..].copy_from_slice(&wire_u16(sealed_length));
        let nonce = record_nonce(&self.client_iv, self.client_sequence);
        let sealed = suite.seal(&self.client_key, &nonce, &inner, &header)?;
        self.client_sequence += 1;
        let mut record = Vec::with_capacity(header.len() + sealed.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&sealed);
        Ok(record)
    }

    fn open_record(&mut self, record: (u8, Vec<u8>)) -> Result<(u8, Vec<u8>)> {
        let (content_type, body) = record;
        if content_type != CONTENT_APPLICATION_DATA {
            if content_type == CONTENT_CHANGE_CIPHER_SPEC || content_type == CONTENT_ALERT {
                return Ok((content_type, body));
            }
            return Err(anyhow!("tls: unexpected TLS record type {content_type} after the ServerHello"));
        }
        if body.len() < TAG_LEN {
            return Err(anyhow!("tls: short TLS 1.3 record"));
        }
        let suite = self.suite()?;
        let mut header = [0u8; 5];
        header[..3].copy_from_slice(&[CONTENT_APPLICATION_DATA, LEGACY_RECORD_VERSION[0], LEGACY_RECORD_VERSION[1]]);
        header[3..].copy_from_slice(&wire_u16(body.len()));
        let nonce = record_nonce(&self.server_iv, self.server_sequence);
        let inner = suite.open(&self.server_key, &nonce, &body, &header)?;
        self.server_sequence += 1;
        let Some(index) = inner.iter().rposition(|byte| *byte != 0) else {
            return Err(anyhow!("tls: TLSInnerPlaintext carries no content type"));
        };
        let (plaintext, rest) = inner.split_at(index);
        let (content_type, _) =
            rest.split_first().ok_or_else(|| anyhow!("tls: TLSInnerPlaintext carries no content type"))?;
        Ok((*content_type, plaintext.to_vec()))
    }

    async fn read_handshake_message(&mut self, stream: &mut dyn Stream) -> Result<Vec<u8>> {
        loop {
            let pending_length = self.handshake_buffer.first_chunk::<4>().map(|header| {
                let [_, second, third, fourth] = *header;
                (usize::from(second) << 16) | (usize::from(third) << 8) | usize::from(fourth)
            });
            if let Some(length) = pending_length {
                if self.handshake_buffer.len() >= 4 + length {
                    return Ok(self.handshake_buffer.drain(..4 + length).collect());
                }
            }
            let (content_type, payload) = self.next_record(stream).await?;
            if content_type == CONTENT_CHANGE_CIPHER_SPEC {
                continue;
            }
            let (content_type, payload) =
                if self.suite.is_some() { self.open_record((content_type, payload))? } else { (content_type, payload) };
            match content_type {
                CONTENT_HANDSHAKE => self.handshake_buffer.extend_from_slice(&payload),
                CONTENT_ALERT => return Err(anyhow!(alert_message(&payload))),
                _ => return Err(anyhow!("tls: unexpected TLS record type {content_type} during the handshake")),
            }
        }
    }

    async fn next_record(&mut self, stream: &mut dyn Stream) -> io::Result<(u8, Vec<u8>)> {
        if let Some(record) = self.pending_record.take() {
            return Ok(record);
        }
        std::future::poll_fn(|cx| self.poll_record(stream, cx)).await
    }

    fn poll_record(&mut self, stream: &mut dyn Stream, cx: &mut Context<'_>) -> Poll<io::Result<(u8, Vec<u8>)>> {
        loop {
            if self.header_filled < 5 {
                let (_, unwritten) = self.header.split_at_mut(self.header_filled);
                let mut buf = ReadBuf::new(unwritten);
                match Pin::new(&mut *stream).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(())) => {}
                }
                let filled = buf.filled().len();
                if filled == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        if self.header_filled == 0 {
                            "tls: peer closed the connection"
                        } else {
                            "tls: transport ended inside a record header"
                        },
                    )));
                }
                self.header_filled += filled;
                continue;
            }
            if !self.body_started {
                let length = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                if length > MAX_RECORD_LEN {
                    return Poll::Ready(Err(io::Error::other(format!("tls: oversized record of {length} bytes"))));
                }
                self.body = vec![0u8; length];
                self.body_filled = 0;
                self.body_started = true;
            }
            if self.body_filled < self.body.len() {
                let (_, unwritten) = self.body.split_at_mut(self.body_filled);
                let mut buf = ReadBuf::new(unwritten);
                match Pin::new(&mut *stream).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(())) => {}
                }
                let filled = buf.filled().len();
                if filled == 0 {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tls: truncated TLS record")));
                }
                self.body_filled += filled;
                continue;
            }
            let record = (self.header[0], std::mem::take(&mut self.body));
            self.header = [0u8; 5];
            self.header_filled = 0;
            self.body_filled = 0;
            self.body_started = false;
            return Poll::Ready(Ok(record));
        }
    }

    /// Writes `bytes` to the peer in full and flushes. Neither half of the connection is touched,
    /// so the helper needs no receiver.
    async fn write_bytes(stream: &mut dyn Stream, bytes: &[u8]) -> Result<()> {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let written = std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_write(cx, remaining)).await?;
            if written == 0 {
                return Err(anyhow!("tls: peer stopped accepting TLS records"));
            }
            remaining =
                remaining.get(written..).ok_or_else(|| anyhow!("tls: peer reported a write past the buffer"))?;
        }
        std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_flush(cx)).await?;
        Ok(())
    }

    fn poll_drain(&mut self, stream: &mut dyn Stream, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending_out.is_empty() {
            match Pin::new(&mut *stream).poll_write(cx, &self.pending_out) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tls: peer stopped accepting TLS records",
                    )))
                }
                Poll::Ready(Ok(written)) => drop(self.pending_out.drain(..written)),
            }
        }
        Poll::Ready(Ok(()))
    }

    pub(crate) fn poll_read(
        &mut self,
        stream: &mut dyn Stream,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.plain_offset < self.plain.len() {
                // `split_at` returns the head first: the bytes still to hand out are the tail.
                let (_, available) = self.plain.split_at(self.plain_offset);
                let take = available.len().min(buf.remaining());
                let (head, _) = available.split_at(take);
                buf.put_slice(head);
                self.plain_offset += take;
                return Poll::Ready(Ok(()));
            }
            if self.peer_closed {
                return Poll::Ready(Ok(()));
            }
            let record = match self.poll_next_plaintext(stream, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(record)) => record,
            };
            match record {
                Some((content_type, payload)) if content_type == CONTENT_APPLICATION_DATA => {
                    self.plain = payload;
                    self.plain_offset = 0;
                }
                None if self.peer_closed => return Poll::Ready(Ok(())),
                Some(_) | None => {}
            }
        }
    }

    /// `None` means "nothing to hand upwards this round": a post-handshake message that carries no
    /// application data, or a clean close.
    fn poll_next_plaintext(
        &mut self,
        stream: &mut dyn Stream,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<(u8, Vec<u8>)>>> {
        if let Some(record) = self.pending_record.take() {
            return Poll::Ready(self.consume_post_handshake(record));
        }
        match self.poll_record(stream, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(record)) => Poll::Ready(self.consume_post_handshake(record)),
        }
    }

    fn consume_post_handshake(&mut self, record: (u8, Vec<u8>)) -> io::Result<Option<(u8, Vec<u8>)>> {
        let (content_type, payload) = self.open_record(record).map_err(io::Error::other)?;
        if content_type == CONTENT_APPLICATION_DATA || content_type == CONTENT_CHANGE_CIPHER_SPEC {
            return Ok(Some((content_type, payload)));
        }
        if content_type == CONTENT_ALERT {
            self.peer_closed = true;
            if payload.get(1) == Some(&0) {
                return Ok(None);
            }
            return Err(io::Error::other(alert_message(&payload)));
        }
        if content_type != CONTENT_HANDSHAKE {
            return Err(io::Error::other(format!("tls: unexpected TLS record type {content_type}")));
        }
        match payload.first() {
            Some(&HANDSHAKE_NEW_SESSION_TICKET) => Ok(None),
            Some(&HANDSHAKE_KEY_UPDATE) => {
                self.update_traffic_keys(payload.get(1).copied() == Some(1)).map_err(io::Error::other)?;
                Ok(None)
            }
            _ => Err(io::Error::other("tls: unexpected post-handshake handshake message")),
        }
    }

    /// RFC 8446 §4.6.3. The sequence numbers deliberately keep running across an update.
    fn update_traffic_keys(&mut self, request_response_update: bool) -> Result<()> {
        let suite = self.suite()?;
        let hash_len = suite.hash_len();
        let server_secret = suite.expand_label(&self.server_application_secret, "traffic upd", &[], hash_len)?;
        self.server_application_secret.clone_from(&server_secret);
        (self.server_key, self.server_iv) = traffic_key(suite, &server_secret)?;
        if request_response_update {
            let client_secret = suite.expand_label(&self.client_application_secret, "traffic upd", &[], hash_len)?;
            self.client_application_secret.clone_from(&client_secret);
            (self.client_key, self.client_iv) = traffic_key(suite, &client_secret)?;
        }
        Ok(())
    }

    pub(crate) fn poll_write(
        &mut self,
        stream: &mut dyn Stream,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::other("tls: write half is closed")));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pending_out.is_empty() {
            let take = buf.len().min(MAX_FRAGMENT_LEN);
            let (head, _) = buf.split_at(take);
            self.pending_out = match self.seal_record(CONTENT_APPLICATION_DATA, head) {
                Ok(record) => record,
                Err(err) => return Poll::Ready(Err(io::Error::other(err))),
            };
            self.pending_length = take;
        }
        match self.poll_drain(stream, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {
                let taken = self.pending_length;
                self.pending_length = 0;
                Poll::Ready(Ok(taken))
            }
        }
    }

    pub(crate) fn poll_flush(&mut self, stream: &mut dyn Stream, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(Err(err)) = self.poll_drain(stream, cx) {
            return Poll::Ready(Err(err));
        }
        Pin::new(&mut *stream).poll_flush(cx)
    }

    pub(crate) fn poll_shutdown(&mut self, stream: &mut dyn Stream, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        if !self.close_notify_sent {
            self.pending_out = match self.seal_record(CONTENT_HANDSHAKE, &[0x01, 0x00]) {
                Ok(record) => record,
                Err(err) => return Poll::Ready(Err(io::Error::other(err))),
            };
            self.close_notify_sent = true;
        }
        match self.poll_drain(stream, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }
        self.write_closed = true;
        Pin::new(&mut *stream).poll_shutdown(cx)
    }

    pub(crate) fn mark_write_closed(&mut self) {
        self.write_closed = true;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::task::Waker;
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncWrite};

    use super::*;

    fn extension(extension_type: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&extension_type.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn handshake_message_frames_type_and_three_byte_length() {
        let message = handshake_message(HANDSHAKE_CERTIFICATE, &[0xaa, 0xbb]);
        assert_eq!(message, vec![HANDSHAKE_CERTIFICATE, 0, 0, 2, 0xaa, 0xbb]);
    }

    #[test]
    fn certificate_message_skips_the_context_and_reads_the_u24_list() {
        let leaf = vec![0x30, 0x82, 0x01, 0x02];
        let mut entry = Vec::new();
        entry.extend_from_slice(&(leaf.len() as u32).to_be_bytes()[1..]);
        entry.extend_from_slice(&leaf);
        entry.extend_from_slice(&[0, 0]);
        let mut body = vec![0u8];
        body.extend_from_slice(&(entry.len() as u32).to_be_bytes()[1..]);
        body.extend_from_slice(&entry);

        assert_eq!(certificate_message(&body).expect("certificate body"), vec![CertificateDer::from(leaf)]);
    }

    #[test]
    fn certificate_message_rejects_a_length_prefix_in_place_of_the_context() {
        let mut framed = vec![0u8, 0, 3];
        framed.extend_from_slice(&[0, 0, 0]);
        assert!(certificate_message(&framed).is_err());
    }

    #[test]
    fn certificate_request_schemes_reads_the_signature_algorithms_extension() {
        let mut supported = Vec::new();
        for scheme in [0x0403u16, 0x0804, 0x0805] {
            supported.extend_from_slice(&scheme.to_be_bytes());
        }
        let mut sigalgs = Vec::new();
        sigalgs.extend_from_slice(&(supported.len() as u16).to_be_bytes());
        sigalgs.extend_from_slice(&supported);

        let mut extensions = extension(13, &sigalgs);
        extensions.extend_from_slice(&extension(47, &[0xaa, 0xbb]));
        let mut body = vec![0u8];
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        assert_eq!(certificate_request_schemes(&body).expect("certificate request body"), vec![0x0403, 0x0804, 0x0805]);
    }

    #[test]
    fn certificate_request_without_signature_algorithms_offers_nothing() {
        let extensions = extension(47, &[0xaa]);
        let mut body = vec![0u8];
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        assert!(certificate_request_schemes(&body).expect("certificate request body").is_empty());
    }

    #[test]
    fn encrypted_extensions_alpn_reads_the_selected_protocol() {
        let protocols = [b"h2".as_slice(), b"http/1.1".as_slice()];
        let mut list = Vec::new();
        for protocol in protocols {
            list.push(protocol.len() as u8);
            list.extend_from_slice(protocol);
        }
        let mut alpn = Vec::new();
        alpn.extend_from_slice(&(list.len() as u16).to_be_bytes());
        alpn.extend_from_slice(&list);
        let extensions = extension(16, &alpn);
        let mut body = Vec::new();
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        assert_eq!(encrypted_extensions_alpn(&body).expect("encrypted extensions"), Some("h2".to_owned()));
    }

    #[test]
    fn parse_server_hello_reads_the_version_cipher_suite_and_key_share() {
        let share = vec![0x11, 0x22, 0x33, 0x44];
        let mut key_share = Vec::new();
        key_share.extend_from_slice(&0x001du16.to_be_bytes());
        key_share.extend_from_slice(&(share.len() as u16).to_be_bytes());
        key_share.extend_from_slice(&share);
        let mut extensions = extension(43, &VERSION_TLS13.to_be_bytes());
        extensions.extend_from_slice(&extension(51, &key_share));

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xabu8; 32]);
        body.push(0);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let parsed = parse_server_hello(
            &body,
            &OfferedClientHello {
                session_id: Vec::new(),
                cipher_suites: vec![0x1301],
                supported_groups: vec![0x001d],
                key_share_groups: vec![0x001d],
            },
        )
        .expect("server hello");
        let ServerHello::Full(parsed) = parsed else {
            panic!("expected a full server hello");
        };
        assert_eq!(parsed.cipher_suite, 0x1301);
        assert_eq!(parsed.key_share_group, 0x001d);
        assert_eq!(parsed.key_share, share);
    }

    #[test]
    fn server_flight_bodies_are_read_past_the_four_byte_header() {
        let certificate = vec![0x30, 0x82, 0x00, 0xff];
        let mut entry = Vec::new();
        entry.extend_from_slice(&(certificate.len() as u32).to_be_bytes()[1..]);
        entry.extend_from_slice(&certificate);
        entry.extend_from_slice(&[0, 0]);
        let mut body = vec![0u8];
        body.extend_from_slice(&(entry.len() as u32).to_be_bytes()[1..]);
        body.extend_from_slice(&entry);
        let framed = handshake_message(HANDSHAKE_CERTIFICATE, &body);

        let body = handshake_body(&framed, HANDSHAKE_CERTIFICATE).expect("certificate body");
        assert_eq!(certificate_message(body).expect("certificates"), vec![CertificateDer::from(certificate)]);
    }

    #[test]
    fn handshake_body_rejects_a_mismatched_length_or_type() {
        let framed = handshake_message(HANDSHAKE_FINISHED, &[0x11; 32]);
        assert_eq!(handshake_body(&framed, HANDSHAKE_FINISHED).expect("finished body"), &[0x11; 32][..]);
        assert!(handshake_body(&framed, HANDSHAKE_CERTIFICATE).is_err());

        let mut truncated = framed.clone();
        truncated[3] = 31;
        assert!(handshake_body(&truncated, HANDSHAKE_FINISHED).is_err());

        let mut wrong_type = framed;
        wrong_type[0] = HANDSHAKE_CERTIFICATE;
        assert!(handshake_body(&wrong_type, HANDSHAKE_FINISHED).is_err());
    }

    #[test]
    fn certificate_verify_message_reads_the_scheme_and_signature() {
        let signature = vec![0xde, 0xad, 0xbe, 0xef];
        let mut body = Vec::new();
        body.extend_from_slice(&0x0403u16.to_be_bytes());
        body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        body.extend_from_slice(&signature);

        let parsed = certificate_verify_message(&body).expect("certificate verify body");
        assert_eq!(parsed.scheme, 0x0403);
        assert_eq!(parsed.signature, signature);
    }

    #[test]
    fn exporter_matches_rfc8446_section_7_5_for_the_callers_label() {
        // The expected values were computed with an independent HKDF re-derivation; a
        // single-level `"exp master"` expansion, as this crate used to do, fails every one of
        // them.
        let exporter_secret =
            hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").expect("secret");
        let sha256 = |label: &str, context: &[u8], length: usize| {
            derive_exported_keying_material(Tls13Suite::Aes128GcmSha256, &exporter_secret, label, context, length)
        };
        assert_eq!(
            hex::encode(sha256("test", &[], 42).expect("exporter")),
            "842f4c6e6104b266bd13ddad7fa5a1adaeddfc2f735aa4d1e9b5395ba2245963a76e62c3e0004a6ed8a5"
        );
        assert_eq!(
            hex::encode(sha256("EXPORTER-test-label", b"context", 32).expect("exporter")),
            "cd4b120c61f88b9b84f7060454fc286e391f379adb6c73feb4c8fff2a3bbcae2"
        );
        assert_eq!(hex::encode(sha256("", &[0x00], 16).expect("exporter")), "bceb3a8fa6df7c6585e772a7c370f27e");
        assert_eq!(
            hex::encode(sha256("tuic", b"hunter2", 32).expect("exporter")),
            "e7a803801a463079278454b7ae27ebbe05cb58058ddadf4a607340c638e4f74e"
        );
        assert_eq!(
            hex::encode(
                derive_exported_keying_material(
                    Tls13Suite::Aes256GcmSha384,
                    &hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30")
                        .expect("secret"),
                    "EXPORTER-test-label",
                    b"context",
                    32,
                )
                .expect("exporter")
            ),
            "37d9f319eb482808faace6fd1845cb7262426a360aafafad2ee33df1de2a7b10"
        );
    }

    #[test]
    fn exporter_rejects_a_label_that_does_not_fit_the_one_byte_length() {
        let exporter_secret = vec![0u8; 32];
        let label = "x".repeat(250);
        assert!(
            derive_exported_keying_material(Tls13Suite::Aes128GcmSha256, &exporter_secret, &label, &[], 16).is_err()
        );
    }

    /// A peer that never answers: the buffered half of `poll_read` returns before it writes.
    struct IdleStream;

    impl Stream for IdleStream {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
        }
    }

    impl AsyncRead for IdleStream {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for IdleStream {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A peer that delivers `prefix` and then reports EOF forever. `spin_guard` bounds a reader
    /// that never yields to the runtime: after that many zero-byte reads the stream itself fails,
    /// so a spinning implementation fails the test instead of wedging it.
    struct TruncatedStream {
        prefix: Mutex<VecDeque<u8>>,
        zero_reads: AtomicUsize,
        spin_guard: usize,
    }

    impl Stream for TruncatedStream {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
        }
    }

    impl AsyncRead for TruncatedStream {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let mut prefix = this.prefix.lock().expect("truncated prefix");
            let take = prefix.len().min(buf.remaining());
            for _ in 0..take {
                if let Some(byte) = prefix.pop_front() {
                    buf.put_slice(&[byte]);
                }
            }
            drop(prefix);
            if take == 0 && this.zero_reads.fetch_add(1, Ordering::Relaxed) >= this.spin_guard {
                return Poll::Ready(Err(io::Error::other("test stream: the reader polled past EOF")));
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TruncatedStream {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A peer that stops after 1-4 bytes of a record header used to re-enter the read arm with
    /// nothing to read, spinning inside one `poll` instead of failing.
    #[tokio::test]
    async fn a_partial_record_header_before_eof_fails_instead_of_spinning() {
        let mut client = UtlsClient::new(
            Arc::new(Config::default()),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            Vec::new(),
            KeySharePrivateKeys::default(),
        );
        let mut stream = TruncatedStream {
            prefix: Mutex::new(VecDeque::from(vec![0x16, 0x03, 0x03])),
            zero_reads: AtomicUsize::new(0),
            spin_guard: 4,
        };

        let error = client.next_record(&mut stream).await.expect_err("a partial header before EOF must fail");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(error.to_string(), "tls: transport ended inside a record header");
    }

    /// The buffered half of `poll_read` must hand out the bytes at `plain_offset` on, not the
    /// already-delivered prefix.
    #[test]
    fn poll_read_hands_out_the_bytes_after_the_read_cursor() {
        let mut client = UtlsClient::new(
            Arc::new(Config::default()),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            Vec::new(),
            KeySharePrivateKeys::default(),
        );
        client.plain = b"0123456789".to_vec();
        client.plain_offset = 4;

        let mut stream = IdleStream;
        let mut out = [0u8; 4];
        let mut buf = ReadBuf::new(&mut out);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(client.poll_read(&mut stream, &mut cx, &mut buf), Poll::Ready(Ok(()))));
        assert_eq!(buf.filled(), b"4567".as_slice());
        assert_eq!(client.plain_offset, 8);
    }

    const HANDSHAKE_CLIENT_HELLO: u8 = 1;

    /// A `HelloRetryRequest` the test server synthesises once it has seen the first `ClientHello`,
    /// so the reply can echo the client's session id the way a real server must.
    struct RetryScript {
        group: Option<u16>,
        cookie: Option<Vec<u8>>,
        reply: RetryReply,
    }

    /// What the scripted peer sends after the retry `ClientHello`.
    enum RetryReply {
        /// Nothing, so the handshake fails after the retry `ClientHello` is written.
        Silent,
        /// A second `HelloRetryRequest`.
        SecondRetry,
        /// A full `ServerHello` with this cipher suite and key share group.
        ServerHello { suite: u16, group: u16 },
    }

    /// A peer whose reply is scripted and whose writes are captured, so the retry `ClientHello`
    /// can be inspected without a cooperating server.
    struct ScriptedStream {
        to_client: Mutex<VecDeque<u8>>,
        written: Arc<Mutex<Vec<u8>>>,
        one_byte_per_read: bool,
        script: Mutex<Option<RetryScript>>,
    }

    impl Stream for ScriptedStream {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
        }
    }

    impl AsyncRead for ScriptedStream {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let script = this.script.lock().expect("script slot").take();
            if let Some(script) = script {
                let written = this.written.lock().expect("scripted write capture");
                if written.is_empty() {
                    *this.script.lock().expect("script slot") = Some(script);
                } else {
                    let records = build_retry_records(&script, written.as_slice());
                    drop(written);
                    this.to_client.lock().expect("scripted read queue").extend(records);
                }
            }
            let mut queue = this.to_client.lock().expect("scripted read queue");
            let want = if this.one_byte_per_read { 1 } else { buf.remaining() };
            let n = want.min(queue.len()).min(buf.remaining());
            for _ in 0..n {
                if let Some(byte) = queue.pop_front() {
                    buf.put_slice(&[byte]);
                }
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedStream {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.get_mut().written.lock().expect("scripted write capture").extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A `HelloRetryRequest` `ServerHello`: the sentinel random, the session id echoed from the
    /// first `ClientHello`, an optional `key_share` selecting a group and an optional `cookie`,
    /// exactly as the wire carries them.
    fn hrr_record(selected_group: Option<u16>, cookie: Option<&[u8]>, session_id: &[u8]) -> Vec<u8> {
        let mut extensions = extension(43, &VERSION_TLS13.to_be_bytes());
        if let Some(group) = selected_group {
            extensions.extend_from_slice(&extension(51, &group.to_be_bytes()));
        }
        if let Some(cookie) = cookie {
            let mut body = Vec::new();
            body.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
            body.extend_from_slice(cookie);
            extensions.extend_from_slice(&extension(44, &body));
        }
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut record = Vec::new();
        write_plaintext_record(&mut record, CONTENT_HANDSHAKE, &handshake_message(HANDSHAKE_SERVER_HELLO, &body));
        record
    }

    /// A full TLS 1.3 `ServerHello` carrying `suite` and a key share for `group`, so a scripted
    /// peer can answer the retry with whatever the test needs to check.
    fn server_hello_record(suite: u16, group: u16, session_id: &[u8]) -> Vec<u8> {
        let mut key_share = group.to_be_bytes().to_vec();
        key_share.extend_from_slice(&32u16.to_be_bytes());
        key_share.extend_from_slice(&[0x5a; 32]);
        let mut extensions = extension(43, &VERSION_TLS13.to_be_bytes());
        extensions.extend_from_slice(&extension(51, &key_share));
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; 32]);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut record = Vec::new();
        write_plaintext_record(&mut record, CONTENT_HANDSHAKE, &handshake_message(HANDSHAKE_SERVER_HELLO, &body));
        record
    }

    fn build_retry_records(script: &RetryScript, written: &[u8]) -> Vec<u8> {
        let messages = handshake_messages(written);
        let client_hello = messages
            .iter()
            .find(|(kind, _)| *kind == HANDSHAKE_CLIENT_HELLO)
            .map(|(_, body)| body.as_slice())
            .expect("the client writes its ClientHello before reading");
        let session_id = client_hello_session_id(client_hello);
        let mut records = hrr_record(script.group, script.cookie.as_deref(), session_id);
        match &script.reply {
            RetryReply::Silent => {}
            RetryReply::SecondRetry => {
                records.extend_from_slice(&hrr_record(script.group, script.cookie.as_deref(), session_id));
            }
            RetryReply::ServerHello { suite, group } => {
                records.extend_from_slice(&server_hello_record(*suite, *group, session_id));
            }
        }
        records
    }

    /// Whether the client wrote a `ChangeCipherSpec`, which it only does once it has accepted the
    /// server's key share and installed handshake keys.
    fn has_change_cipher_spec(records: &[u8]) -> bool {
        let mut offset = 0;
        while offset + 5 <= records.len() {
            let content_type = records[offset];
            let length = usize::from(u16::from_be_bytes([records[offset + 3], records[offset + 4]]));
            if content_type == CONTENT_CHANGE_CIPHER_SPEC {
                return true;
            }
            offset += 5 + length;
        }
        false
    }

    fn handshake_messages(records: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut messages = Vec::new();
        let mut offset = 0;
        while offset + 5 <= records.len() {
            let content_type = records[offset];
            let length = usize::from(u16::from_be_bytes([records[offset + 3], records[offset + 4]]));
            let body = &records[offset + 5..offset + 5 + length];
            if content_type == CONTENT_HANDSHAKE {
                let mut inner = 0;
                while inner + 4 <= body.len() {
                    let kind = body[inner];
                    let length = (usize::from(body[inner + 1]) << 16)
                        | (usize::from(body[inner + 2]) << 8)
                        | usize::from(body[inner + 3]);
                    messages.push((kind, body[inner + 4..inner + 4 + length].to_vec()));
                    inner += 4 + length;
                }
            }
            offset += 5 + length;
        }
        messages
    }

    fn client_hellos(messages: &[(u8, Vec<u8>)]) -> Vec<&[u8]> {
        messages.iter().filter(|(kind, _)| *kind == HANDSHAKE_CLIENT_HELLO).map(|(_, body)| body.as_slice()).collect()
    }

    fn client_hello_random(body: &[u8]) -> &[u8] {
        &body[2..34]
    }

    fn client_hello_session_id(body: &[u8]) -> &[u8] {
        let length = usize::from(body[34]);
        &body[35..35 + length]
    }

    /// The body of one `ClientHello` extension, length prefix excluded.
    fn client_hello_extension(body: &[u8], wanted: u16) -> Option<Vec<u8>> {
        let extensions = {
            let mut reader = Reader::new(body);
            reader.u16().expect("legacy version");
            reader.take(32).expect("random");
            reader.vec8().expect("session id");
            reader.vec16().expect("cipher suites");
            reader.vec8().expect("compression methods");
            reader.vec16().expect("extensions")
        };
        let mut reader = Reader::new(extensions);
        while !reader.remaining().is_empty() {
            let extension_type = reader.u16().expect("extension type");
            let data = reader.vec16().expect("extension data");
            if extension_type == wanted {
                return Some(data.to_vec());
            }
        }
        None
    }

    fn client_hello_key_share_groups(body: &[u8]) -> Vec<u16> {
        let Some(data) = client_hello_extension(body, 51) else { return Vec::new() };
        let mut reader = Reader::new(&data);
        let mut shares = Reader::new(reader.vec16().expect("key share list"));
        let mut groups = Vec::new();
        while !shares.remaining().is_empty() {
            groups.push(shares.u16().expect("group"));
            shares.vec16().expect("key exchange");
        }
        groups
    }

    struct RetryOutcome {
        error: Option<anyhow::Error>,
        messages: Vec<(u8, Vec<u8>)>,
        written: Vec<u8>,
    }

    impl RetryOutcome {
        fn client_hellos(&self) -> Vec<&[u8]> {
            client_hellos(&self.messages)
        }
    }

    async fn run_fingerprinted_handshake(
        fingerprint: &str,
        script: RetryScript,
        one_byte_per_read: bool,
    ) -> RetryOutcome {
        let (fingerprint_id, known) = crate::utls::get_fingerprint(fingerprint);
        assert!(known, "unknown fingerprint {fingerprint}");
        let written = Arc::new(Mutex::new(Vec::new()));
        let stream = ScriptedStream {
            to_client: Mutex::new(VecDeque::new()),
            written: Arc::clone(&written),
            one_byte_per_read,
            script: Mutex::new(Some(script)),
        };
        let config = Arc::new(Config { server_name: "example.com".to_owned(), ..Config::default() });
        let mut conn = crate::utls::uclient(Box::new(stream), config, fingerprint_id);
        let ctx = tokio_util::sync::CancellationToken::new();
        let error = tokio::time::timeout(Duration::from_secs(5), conn.handshake_context(&ctx))
            .await
            .expect("handshake must not hang")
            .err();
        let captured = written.lock().expect("scripted write capture");
        RetryOutcome { error, messages: handshake_messages(captured.as_slice()), written: captured.to_vec() }
    }

    #[tokio::test]
    async fn edge_answers_a_retry_for_the_hybrid_group_with_a_second_client_hello() {
        let outcome = run_fingerprinted_handshake(
            "edge",
            RetryScript { group: Some(4588), cookie: None, reply: RetryReply::Silent },
            false,
        )
        .await;
        let hellos = outcome.client_hellos();
        assert_eq!(hellos.len(), 2, "the retry must be answered with a second ClientHello: {:?}", outcome.error);
        assert!(client_hello_key_share_groups(hellos[1]).contains(&4588));
    }

    #[tokio::test]
    async fn chrome_answers_a_retry_for_p256_with_a_second_client_hello() {
        let outcome = run_fingerprinted_handshake(
            "chrome",
            RetryScript { group: Some(23), cookie: None, reply: RetryReply::Silent },
            false,
        )
        .await;
        let hellos = outcome.client_hellos();
        assert_eq!(hellos.len(), 2, "the retry must be answered with a second ClientHello: {:?}", outcome.error);
        assert!(client_hello_key_share_groups(hellos[1]).contains(&23));
    }

    #[tokio::test]
    async fn a_retry_cookie_is_echoed_in_the_second_client_hello() {
        let cookie = b"retry-cookie".to_vec();
        let outcome = run_fingerprinted_handshake(
            "chrome",
            RetryScript { group: Some(23), cookie: Some(cookie.clone()), reply: RetryReply::Silent },
            false,
        )
        .await;
        let hellos = outcome.client_hellos();
        assert_eq!(hellos.len(), 2, "the retry must be answered with a second ClientHello: {:?}", outcome.error);
        let echoed = client_hello_extension(hellos[1], 44).expect("the retry must echo the cookie extension");
        assert_eq!(&echoed[2..], cookie);
    }

    #[tokio::test]
    async fn a_retry_for_an_unoffered_group_is_rejected_without_a_second_client_hello() {
        let outcome = run_fingerprinted_handshake(
            "chrome",
            RetryScript { group: Some(0x9999), cookie: None, reply: RetryReply::Silent },
            false,
        )
        .await;
        assert!(outcome.error.is_some(), "an unoffered retry group must fail the handshake");
        assert_eq!(outcome.client_hellos().len(), 1, "no retry may be sent for an unoffered group");
    }

    #[tokio::test]
    async fn a_second_retry_request_is_rejected_after_one_retry() {
        let outcome = run_fingerprinted_handshake(
            "chrome",
            RetryScript { group: Some(23), cookie: None, reply: RetryReply::SecondRetry },
            false,
        )
        .await;
        assert!(outcome.error.is_some(), "a second HelloRetryRequest must fail the handshake");
        assert_eq!(outcome.client_hellos().len(), 2, "exactly one retry ClientHello may be sent");
    }

    #[tokio::test]
    async fn a_group_retry_offers_only_the_requested_group() {
        let outcome = run_fingerprinted_handshake(
            "chrome",
            RetryScript { group: Some(23), cookie: None, reply: RetryReply::Silent },
            false,
        )
        .await;
        let hellos = outcome.client_hellos();
        assert_eq!(hellos.len(), 2, "{:?}", outcome.error);
        assert_eq!(client_hello_key_share_groups(hellos[1]), vec![23], "the retry must drop the first hello's shares");
    }

    #[tokio::test]
    async fn a_cookie_only_retry_keeps_the_offered_key_shares() {
        let outcome = run_fingerprinted_handshake(
            "chrome",
            RetryScript {
                group: None,
                cookie: Some(b"c".to_vec()),
                reply: RetryReply::ServerHello { suite: 0x1301, group: 29 },
            },
            false,
        )
        .await;
        let hellos = outcome.client_hellos();
        assert_eq!(hellos.len(), 2, "the cookie-only retry must be answered: {:?}", outcome.error);
        assert_eq!(
            client_hello_key_share_groups(hellos[1]),
            client_hello_key_share_groups(hellos[0]),
            "a cookie-only retry must keep the first hello's shares"
        );
        assert!(
            has_change_cipher_spec(&outcome.written),
            "a retained X25519 share must still complete the key exchange: {:?}",
            outcome.error
        );
    }

    #[tokio::test]
    async fn a_changed_cipher_suite_after_a_retry_is_rejected_before_key_installation() {
        let outcome = run_fingerprinted_handshake(
            "chrome",
            RetryScript { group: Some(23), cookie: None, reply: RetryReply::ServerHello { suite: 0x1303, group: 23 } },
            false,
        )
        .await;
        assert!(outcome.error.is_some(), "the second ServerHello must keep the HelloRetryRequest cipher suite");
        assert_eq!(outcome.client_hellos().len(), 2, "the retry ClientHello is still sent");
        assert!(!has_change_cipher_spec(&outcome.written), "no handshake keys may be installed for a changed suite");
    }

    #[tokio::test]
    async fn a_key_share_outside_the_retry_group_is_rejected_before_key_installation() {
        let outcome = run_fingerprinted_handshake(
            "chrome",
            RetryScript { group: Some(23), cookie: None, reply: RetryReply::ServerHello { suite: 0x1301, group: 29 } },
            false,
        )
        .await;
        assert!(outcome.error.is_some(), "the second ServerHello must use the HelloRetryRequest group");
        assert_eq!(outcome.client_hellos().len(), 2, "the retry ClientHello is still sent");
        assert!(!has_change_cipher_spec(&outcome.written), "a dropped first-hello share must never be used");
    }

    #[tokio::test]
    async fn a_retry_fragmented_across_reads_is_still_answered() {
        let outcome = run_fingerprinted_handshake(
            "chrome",
            RetryScript { group: Some(23), cookie: Some(b"c".to_vec()), reply: RetryReply::Silent },
            true,
        )
        .await;
        assert_eq!(outcome.client_hellos().len(), 2, "a byte-fragmented retry must still be answered");
    }

    #[tokio::test]
    async fn the_retry_client_hello_keeps_the_first_hello_random_and_session_id() {
        let outcome = run_fingerprinted_handshake(
            "chrome",
            RetryScript { group: Some(23), cookie: None, reply: RetryReply::Silent },
            false,
        )
        .await;
        let hellos = outcome.client_hellos();
        assert_eq!(hellos.len(), 2, "{:?}", outcome.error);
        assert_eq!(client_hello_random(hellos[0]), client_hello_random(hellos[1]));
        assert_eq!(client_hello_session_id(hellos[0]), client_hello_session_id(hellos[1]));
    }

    fn hello_retry_body(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
        body.push(0);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        body
    }

    #[test]
    fn a_cookie_only_retry_is_accepted_and_an_empty_retry_is_rejected() {
        let offered = OfferedClientHello {
            session_id: Vec::new(),
            cipher_suites: vec![0x1301],
            supported_groups: Vec::new(),
            key_share_groups: Vec::new(),
        };
        let mut cookie = Vec::new();
        cookie.extend_from_slice(&3u16.to_be_bytes());
        cookie.extend_from_slice(b"abc");
        let mut extensions = extension(43, &VERSION_TLS13.to_be_bytes());
        extensions.extend_from_slice(&extension(44, &cookie));
        let parsed = parse_server_hello(&hello_retry_body(&extensions), &offered).expect("cookie-only retry");
        assert!(matches!(parsed, ServerHello::Retry { selected_group: None, cookie: Some(_), .. }));

        let only_version = extension(43, &VERSION_TLS13.to_be_bytes());
        assert!(
            parse_server_hello(&hello_retry_body(&only_version), &offered).is_err(),
            "a retry that changes nothing must be rejected"
        );
    }
}

//! The Restls client: a hand-built TLS 1.2/1.3 handshake.
//!
//! The handshake carries the session-id auth token, detects when the server confirmed Restls
//! authentication, captures the first Finished record, and then promotes the connection to the
//! Restls application-record framing.

use rsa::pkcs1::DecodeRsaPublicKey as _;
use std::any::Any;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use anyhow::{anyhow, bail, Result};
use murmur_common::shared_conn::SharedConn;
// `subtle` is not a direct dependency of this crate; `p256` re-exports it.
use p256::elliptic_curve::subtle::ConstantTimeEq;
use parking_lot::Mutex;
use rand::Rng;
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_component_ca as ca;
use murmur_component_tls::utls::{generate_x25519, x25519_diffie_hellman, CertPool, VerifyOptions, X509Certificate};
use murmur_std_compat::net::{Addr, Conn as NetConn};

use crate::config::{Config, VersionHint};
use crate::consts::{
    CIPHER_SUITE_AES_128_GCM_SHA256, CIPHER_SUITE_CHACHA20_POLY1305_SHA256, GROUP_SECP256R1, GROUP_SECP384R1,
    GROUP_X25519, HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS,
    HANDSHAKE_TYPE_FINISHED, HANDSHAKE_TYPE_KEY_UPDATE, HANDSHAKE_TYPE_NEW_SESSION_TICKET,
    HANDSHAKE_TYPE_SERVER_HELLO_DONE, HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE, HELLO_RETRY_REQUEST_RANDOM, MAX_PLAINTEXT,
    RECORD_HEADER_LEN, RECORD_TYPE_ALERT, RECORD_TYPE_APPLICATION_DATA, RECORD_TYPE_CHANGE_CIPHER_SPEC,
    RECORD_TYPE_HANDSHAKE, RESTLS12_CLIENT_AUTH_LAYOUT3, RESTLS_APP_DATA_AUTH_HEADER_LEN, RESTLS_HANDSHAKE_MAC_LEN,
    SIG_ECDSA_SECP256R1_SHA256, SIG_ED25519, SIG_RSA_PSS_RSAE_SHA256, TLS12_GCM_CIPHER_SUITES, VERSION_TLS12,
    VERSION_TLS13,
};
use crate::crypto;
use crate::crypto::{
    derive_secret, derive_traffic_keys, empty_hash, finished_verify_data, hkdf_extract, pad_inner_plaintext,
    tls12_finished_verify_data, tls12_key_block, tls12_master_secret, unpad_inner_plaintext, CipherSuite,
    RecordProtection, Tls12CipherSuite, Tls12PrfHash, Tls12RecordProtection, Transcript,
};
use crate::framing;
use crate::messages::{
    first_handshake_message, marshal_client_key_exchange, marshal_finished, marshal_finished12, parse_certificate,
    parse_certificate_verify, parse_finished, parse_finished12, parse_server_hello, parse_server_key_exchange,
    ClientHelloBuilder, KeyShareEntry,
};
use crate::sigverify::verify_certificate_verify;
use crate::wire::{read_tls_record, record_header, record_payload, record_type, write_tls_record};

const RESTLS_CCS_RECORD: [u8; 6] = crate::consts::RESTLS_CCS_RECORD;

/// The filler padding when the target length is zero: 19 plus a random draw below 100.
const FILLER_RECORD_PADDING_MIN: usize = 19;
const FILLER_RECORD_PADDING_SPAN: usize = 100;

struct HandshakeMessageStream {
    buf: Vec<u8>,
}

impl HandshakeMessageStream {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    fn next_message(&mut self) -> Option<Vec<u8>> {
        let msg = first_handshake_message(&self.buf).ok()?.to_vec();
        self.buf.drain(..msg.len());
        Some(msg)
    }
}

/// Splits a complete handshake message into its `msg_type` and its body, without the 4-byte
/// `msg_type||u24 length` header.
fn handshake_message_parts(msg: &[u8]) -> Result<(u8, &[u8])> {
    let (msg_type, rest) = msg.split_first().ok_or_else(|| anyhow!("restls: empty handshake message"))?;
    let body = rest.get(3..).ok_or_else(|| anyhow!("restls: short handshake message"))?;
    Ok((*msg_type, body))
}

/// The big-endian `u16` at `bytes[offset..offset + 2]`, or `None` when `bytes` is too short.
fn be16_at(bytes: &[u8], offset: usize) -> Option<usize> {
    bytes.get(offset..offset + 2).and_then(|b| b.try_into().ok()).map(u16::from_be_bytes).map(usize::from)
}

/// The big-endian `u24` at `bytes[offset..offset + 3]`, or `None` when `bytes` is too short.
fn be24_at(bytes: &[u8], offset: usize) -> Option<usize> {
    bytes
        .get(offset..offset + 3)
        .and_then(|b| <[u8; 3]>::try_from(b).ok())
        .map(|[a, b, c]| (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c))
}

/// The client key material and marshalled `ClientHello` for one handshake attempt.
struct ClientHelloState {
    secret: x25519_dalek::StaticSecret,
    public: [u8; 32],
    random: [u8; 32],
    message: Vec<u8>,
}

fn prepare_client_hello(config: &Config, tls12: bool) -> Result<ClientHelloState> {
    let mut alpn_len = 0usize;
    for proto in &config.next_protos {
        if proto.is_empty() || proto.len() > 255 {
            bail!("restls: invalid NextProtos value");
        }
        alpn_len += 1 + proto.len();
    }
    if alpn_len > 0xffff {
        bail!("restls: NextProtos values too large");
    }

    let secret = generate_x25519()?;
    let public = x25519_dalek::PublicKey::from(&secret);
    let mut random = [0u8; 32];
    rand::rng().fill(&mut random);
    let mut session_id = [0u8; 32];
    let key_share = KeyShareEntry { group: GROUP_X25519, data: public.as_bytes().to_vec() };
    if tls12 {
        session_id = tls12_session_id(&config.restls_secret, public.as_bytes());
    } else {
        rand::rng().fill(&mut session_id[16..]);
        let auth_token = restls_session_id_auth_token(&config.restls_secret, std::slice::from_ref(&key_share), &[]);
        session_id[..RESTLS_HANDSHAKE_MAC_LEN].copy_from_slice(&auth_token);
    }

    let client_hello = ClientHelloBuilder {
        random,
        session_id,
        cipher_suites: if tls12 {
            TLS12_GCM_CIPHER_SUITES.to_vec()
        } else {
            vec![CIPHER_SUITE_AES_128_GCM_SHA256, CIPHER_SUITE_CHACHA20_POLY1305_SHA256]
        },
        server_name: config.server_name.clone(),
        supported_groups: if tls12 { vec![GROUP_X25519] } else { vec![GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1] },
        next_protos: config.next_protos.clone(),
        key_shares: vec![key_share],
        signature_algorithms: vec![SIG_ECDSA_SECP256R1_SHA256, SIG_RSA_PSS_RSAE_SHA256, SIG_ED25519],
        psk_identities: vec![],
        psk_binders: vec![],
        tls12_mode: tls12,
    };
    Ok(ClientHelloState { secret, public: *public.as_bytes(), random, message: client_hello.marshal() })
}

/// The TLS 1.3 key schedule and the record protections derived from it.
struct Tls13HandshakeKeys {
    suite: CipherSuite,
    client_hs_secret: [u8; crypto::HASH_LEN],
    server_hs_secret: [u8; crypto::HASH_LEN],
    master_secret: [u8; crypto::HASH_LEN],
    server_protection: RecordProtection,
    client_protection: RecordProtection,
}

impl Tls13HandshakeKeys {
    fn derive(
        server_hello: &crate::messages::ParsedServerHello,
        our_secret: &x25519_dalek::StaticSecret,
        transcript: &Transcript,
    ) -> Result<Self> {
        let suite = CipherSuite::from_id(server_hello.cipher_suite)
            .ok_or_else(|| anyhow!("restls: unsupported cipher suite 0x{:04x}", server_hello.cipher_suite))?;
        let Some(server_key_share) = server_hello.key_share.as_ref() else {
            bail!("restls: ServerHello is missing a key_share");
        };
        if server_key_share.group != GROUP_X25519 {
            bail!("restls: server selected an unsupported group 0x{:04x}", server_key_share.group);
        }
        let server_public: [u8; 32] = server_key_share
            .data
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("restls: malformed X25519 server key_share"))?;
        let shared_secret = x25519_diffie_hellman(our_secret, &x25519_dalek::PublicKey::from(server_public))?;

        let zero_hash = [0u8; crypto::HASH_LEN];
        let early_secret = hkdf_extract(&zero_hash, &zero_hash);
        let early_derived = derive_secret(&early_secret, "derived", &empty_hash());
        let handshake_secret = hkdf_extract(&early_derived, &shared_secret);
        let handshake_derived = derive_secret(&handshake_secret, "derived", &empty_hash());
        let master_secret = hkdf_extract(&handshake_derived, &zero_hash);
        let ch_sh_hash = transcript.hash();
        let client_hs_secret = derive_secret(&handshake_secret, "c hs traffic", &ch_sh_hash);
        let server_hs_secret = derive_secret(&handshake_secret, "s hs traffic", &ch_sh_hash);
        Ok(Self {
            suite,
            client_hs_secret,
            server_hs_secret,
            master_secret,
            server_protection: RecordProtection::new(suite, derive_traffic_keys(suite, &server_hs_secret)),
            client_protection: RecordProtection::new(suite, derive_traffic_keys(suite, &client_hs_secret)),
        })
    }

    /// Reads the first encrypted server record after the ChangeCipherSpec, checks the Restls auth
    /// mask on it, and returns its unpadded handshake content.
    async fn read_first_server_record(
        &mut self,
        stream: &mut Box<dyn NetConn>,
        config: &Config,
        server_random: &[u8; 32],
    ) -> Result<Vec<u8>> {
        write_tls_record(stream, RECORD_TYPE_CHANGE_CIPHER_SPEC, &[RESTLS_CCS_RECORD[5]]).await?;

        let record = loop {
            let record = read_tls_record(stream).await?;
            if record_type(&record)? == RECORD_TYPE_CHANGE_CIPHER_SPEC {
                continue;
            }
            break record;
        };
        if record_type(&record)? != RECORD_TYPE_APPLICATION_DATA {
            bail!("restls: expected first encrypted server record");
        }

        let mut trial = record.clone();
        framing::mask_server_auth(&config.restls_secret, server_random, &mut trial);
        let trial_header = record_header(&trial);
        let trial_open = self.server_protection.open(record_payload(&trial), &trial_header);
        let (restls_authed, plaintext) = if let Ok(pt) = trial_open {
            (true, pt)
        } else {
            let header = record_header(&record);
            let pt = self
                .server_protection
                .open(record_payload(&record), &header)
                .map_err(|_| anyhow!("restls: first server handshake record failed to decrypt"))?;
            (false, pt)
        };
        self.server_protection.advance();
        if !restls_authed {
            bail!("restls: server did not apply the Restls auth mask (not a Restls-aware peer)");
        }

        let (content_type, content) = unpad_inner_plaintext(plaintext)?;
        if content_type != RECORD_TYPE_HANDSHAKE {
            bail!("restls: expected handshake content in first encrypted server record");
        }
        Ok(content)
    }
}

/// Reads server records until the message stream yields one complete handshake message.
async fn next_handshake_message(
    stream: &mut Box<dyn NetConn>,
    protection: &mut RecordProtection,
    messages: &mut HandshakeMessageStream,
) -> Result<Vec<u8>> {
    loop {
        if let Some(msg) = messages.next_message() {
            return Ok(msg);
        }
        let record = loop {
            let record = read_tls_record(stream).await?;
            if record_type(&record)? == RECORD_TYPE_CHANGE_CIPHER_SPEC {
                continue;
            }
            break record;
        };
        if record_type(&record)? != RECORD_TYPE_APPLICATION_DATA {
            bail!("restls: expected encrypted server handshake record");
        }
        let header = record_header(&record);
        let pt = protection.open(record_payload(&record), &header)?;
        protection.advance();
        let (content_type, content) = unpad_inner_plaintext(pt)?;
        if content_type != RECORD_TYPE_HANDSHAKE {
            bail!("restls: expected handshake content in encrypted server record");
        }
        messages.feed(&content);
    }
}

/// RFC 8446 §4.4.4: the server's `Finished.verify_data` is exactly the value this transcript
/// derives, and byte equality is decided without early exit.
fn server_finished_matches(
    secret: &[u8; crypto::HASH_LEN],
    transcript_hash: &[u8; crypto::HASH_LEN],
    received: &[u8; 32],
) -> bool {
    bool::from(finished_verify_data(secret, transcript_hash).ct_eq(received.as_slice()))
}

/// Verifies the peer chain and the Finished from the server's TLS 1.3 flight, which starts with
/// the payload of the first encrypted record (`first_content`).
async fn tls13_server_handshake(
    stream: &mut Box<dyn NetConn>,
    config: &Config,
    keys: &mut Tls13HandshakeKeys,
    transcript: &mut Transcript,
    first_content: &[u8],
) -> Result<()> {
    let mut msg_stream = HandshakeMessageStream::new();
    msg_stream.feed(first_content);

    let mut leaf_cert: Option<X509Certificate> = None;
    let mut intermediate_certs: Vec<X509Certificate> = Vec::new();
    let mut cert_verified = false;
    let mut server_finished: Option<[u8; 32]> = None;

    while server_finished.is_none() {
        let msg = next_handshake_message(stream, &mut keys.server_protection, &mut msg_stream).await?;
        let (msg_type, body) = handshake_message_parts(&msg)?;
        match msg_type {
            HANDSHAKE_TYPE_NEW_SESSION_TICKET => {}
            HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS if leaf_cert.is_none() => {
                if body.len() < 2 || be16_at(body, 0) != Some(body.len() - 2) {
                    bail!("restls: malformed EncryptedExtensions");
                }
                transcript.update(&msg);
            }
            HANDSHAKE_TYPE_CERTIFICATE => {
                let parsed = parse_certificate(body)?;
                let (leaf, intermediates) = parsed
                    .entries
                    .split_first()
                    .ok_or_else(|| anyhow!("restls: server sent an empty Certificate message"))?;
                leaf_cert = Some(X509Certificate::parse(&leaf.cert_data)?);
                for entry in intermediates {
                    intermediate_certs.push(X509Certificate::parse(&entry.cert_data)?);
                }
                transcript.update(&msg);
            }
            HANDSHAKE_TYPE_CERTIFICATE_VERIFY => {
                let Some(leaf) = &leaf_cert else {
                    bail!("restls: CertificateVerify before Certificate");
                };
                let cv = parse_certificate_verify(body)?;
                let hash_before_cv = transcript.hash();
                let public_key = leaf
                    .public_key
                    .as_ref()
                    .ok_or_else(|| anyhow!("restls: leaf certificate has no parsed public key"))?;
                verify_certificate_verify(public_key.as_ref(), cv.scheme, &hash_before_cv, &cv.signature)?;
                verify_peer_chain(config, leaf, &intermediate_certs)?;
                cert_verified = true;
                transcript.update(&msg);
            }
            HANDSHAKE_TYPE_FINISHED => {
                let hash_before_finished = transcript.hash();
                let verify_data = parse_finished(&msg)?;
                if !server_finished_matches(&keys.server_hs_secret, &hash_before_finished, &verify_data) {
                    bail!("restls: server Finished verification failed");
                }
                server_finished = Some(verify_data);
                transcript.update(&msg);
            }
            other => bail!("restls: unexpected server handshake message type {other}"),
        }
    }

    if !cert_verified {
        bail!("restls: server sent no CertificateVerify");
    }
    Ok(())
}

/// Sends the TLS 1.3 client Finished and returns the raw record, which the first application
/// write must replay verbatim.
async fn send_tls13_client_finished(
    stream: &mut Box<dyn NetConn>,
    keys: &mut Tls13HandshakeKeys,
    transcript: &Transcript,
) -> Result<Vec<u8>> {
    let transcript_hash = transcript.hash();
    let client_finished_verify = finished_verify_data(&keys.client_hs_secret, &transcript_hash);
    let finished_msg = marshal_finished(&client_finished_verify);
    let inner = pad_inner_plaintext(&finished_msg, RECORD_TYPE_HANDSHAKE);
    let mut header = [RECORD_TYPE_APPLICATION_DATA, 0x03, 0x03, 0, 0];
    let ciphertext_len =
        u16::try_from(inner.len() + 16).map_err(|_| anyhow!("restls: Finished record exceeds the TLS record limit"))?;
    header[3..5].copy_from_slice(&ciphertext_len.to_be_bytes());
    let ciphertext = keys.client_protection.seal(&inner, &header);
    keys.client_protection.advance();

    let mut raw = Vec::with_capacity(RECORD_HEADER_LEN + ciphertext.len());
    raw.extend_from_slice(&header);
    raw.extend_from_slice(&ciphertext);
    write_all(stream, &raw).await?;
    Ok(raw)
}

fn tls13_conn(
    stream: Box<dyn NetConn>,
    config: &Config,
    server_random: [u8; 32],
    client_finished: Vec<u8>,
    suite: CipherSuite,
    server_app_secret: [u8; crypto::HASH_LEN],
) -> Box<dyn NetConn> {
    Box::new(RestlsConn {
        inner: SharedConn::from_boxed(stream),
        secret: config.restls_secret,
        server_random,
        to_server_counter: 0,
        to_client_counter: 0,
        client_finished: Some(client_finished),
        script: config.restls_script.clone(),
        tls12_gcm: false,
        parrot_gcm: false,
        relay: Some(RelayRead::Tls13 {
            suite,
            secret: server_app_secret,
            protection: RecordProtection::new(suite, derive_traffic_keys(suite, &server_app_secret)),
        }),
        peer_closed: false,
        read_buf: Vec::new(),
        pending_raw: Vec::new(),
        write_buf: Vec::new(),
        response_records: 0,
        write_waker: Mutex::new(None),
        read_waker: Mutex::new(None),
        pending_drain: Mutex::new(None),
        closed: AtomicBool::new(false),
        write_pos: 0,
    })
}

/// Performs the Restls client handshake over `stream` and returns a `Box<dyn NetConn>` that
/// carries the fully Restls-framed application channel.
// NOT cancel-safe: the handshake writes its preamble and messages to the socket before it completes, so a dropped call leaves the connection mid-exchange; the arms that await it drop it only when the connection is being torn down.
pub async fn new_restls(mut stream: Box<dyn NetConn>, config: &Config) -> Result<Box<dyn NetConn>> {
    let tls12 = config.version_hint == VersionHint::Tls12;
    let client = prepare_client_hello(config, tls12)?;

    let mut transcript = Transcript::new();
    transcript.update(&client.message);
    write_tls_record(&mut stream, RECORD_TYPE_HANDSHAKE, &client.message).await?;

    let sh_record = read_tls_record(&mut stream).await?;
    if record_type(&sh_record)? != RECORD_TYPE_HANDSHAKE {
        bail!("restls: expected ServerHello record");
    }
    let sh_msg = first_handshake_message(record_payload(&sh_record))?;
    let (_, sh_body) = handshake_message_parts(sh_msg)?;
    let server_hello = parse_server_hello(sh_body)?;
    if server_hello.random == HELLO_RETRY_REQUEST_RANDOM {
        bail!("restls: HelloRetryRequest is not supported");
    }
    if tls12 {
        if server_hello.supported_version != VERSION_TLS12 {
            bail!("restls: server did not negotiate TLS 1.2");
        }
        return handshake_tls12(
            stream,
            config,
            client.secret,
            client.public,
            client.random,
            &client.message,
            sh_msg.to_vec(),
            record_payload(&sh_record).get(sh_msg.len()..).unwrap_or_default().to_vec(),
            server_hello,
        )
        .await;
    }
    if server_hello.supported_version != VERSION_TLS13 {
        bail!("restls: server did not negotiate TLS 1.3");
    }
    transcript.update(sh_msg);
    let server_random = server_hello.random;

    let mut keys = Tls13HandshakeKeys::derive(&server_hello, &client.secret, &transcript)?;
    let first_content = keys.read_first_server_record(&mut stream, config, &server_random).await?;
    tls13_server_handshake(&mut stream, config, &mut keys, &mut transcript, &first_content).await?;

    let transcript_hash = transcript.hash();
    let server_app_secret = derive_secret(&keys.master_secret, "s ap traffic", &transcript_hash);
    let client_finished_raw = send_tls13_client_finished(&mut stream, &mut keys, &transcript).await?;
    Ok(tls13_conn(stream, config, server_random, client_finished_raw, keys.suite, server_app_secret))
}

// NOT cancel-safe: `AsyncWriteExt::write_all` writes into the socket as it goes, so a dropped call leaves a partial write.
async fn write_all(stream: &mut Box<dyn NetConn>, buf: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    stream.write_all(buf).await?;
    Ok(())
}

fn verify_peer_chain(config: &Config, leaf: &X509Certificate, intermediates: &[X509Certificate]) -> Result<()> {
    if let Some(verify_connection) = &config.verify_connection {
        let chain: Vec<std::sync::Arc<X509Certificate>> =
            std::iter::once(leaf.clone()).chain(intermediates.iter().cloned()).map(std::sync::Arc::new).collect();
        return verify_connection(&chain);
    }
    if config.insecure_skip_verify {
        return Ok(());
    }
    let roots = config.root_cas.clone().unwrap_or_else(ca::config::get_cert_pool);
    let mut pool = CertPool::new();
    for cert in intermediates {
        pool.add_cert(std::sync::Arc::new(cert.clone()));
    }
    leaf.verify(&VerifyOptions {
        dns_name: config.server_name.clone(),
        intermediates: pool,
        roots: Some(roots),
        ..Default::default()
    })
    .map(|_| ())
    .map_err(|err| anyhow!("restls: server certificate verification failed: {err}"))
}

fn tls12_session_id(secret: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let mut id = [0u8; 32];
    let layout = RESTLS12_CLIENT_AUTH_LAYOUT3;
    let digest = blake3::keyed_hash(secret, public_key);
    if let (Some(dst), Some(src)) = (id.get_mut(layout[0]..layout[1]), digest.as_bytes().get(..layout[1])) {
        dst.copy_from_slice(src);
    }
    id
}

fn tls12_hash(transcript: &[u8], hash: Tls12PrfHash) -> Vec<u8> {
    match hash {
        Tls12PrfHash::Sha256 => sha2::Sha256::digest(transcript).to_vec(),
        Tls12PrfHash::Sha384 => sha2::Sha384::digest(transcript).to_vec(),
    }
}

fn parse_tls12_certificate(body: &[u8]) -> Result<Vec<X509Certificate>> {
    let length = be24_at(body, 0).ok_or_else(|| anyhow!("restls: short TLS 1.2 Certificate"))?;
    if length != body.len() - 3 {
        bail!("restls: invalid TLS 1.2 Certificate list length");
    }
    let mut pos = 3;
    let mut certificates = Vec::new();
    while pos < body.len() {
        let len = be24_at(body, pos).ok_or_else(|| anyhow!("restls: truncated TLS 1.2 certificate"))?;
        pos += 3;
        let cert = body.get(pos..pos + len).ok_or_else(|| anyhow!("restls: truncated TLS 1.2 certificate"))?;
        certificates.push(X509Certificate::parse(cert)?);
        pos += len;
    }
    if certificates.is_empty() {
        bail!("restls: empty TLS 1.2 Certificate list");
    }
    Ok(certificates)
}

fn verify_tls12_server_key_exchange(
    public_key: &(dyn Any + Send + Sync),
    scheme: u16,
    signed: &[u8],
    signature: &[u8],
) -> Result<()> {
    use murmur_component_tls::utls::{CertificatePublicKeyBytes, Ed25519PublicKey};
    use p256::ecdsa::signature::Verifier as _;
    use rsa::signature::Verifier as _;
    match scheme {
        SIG_ECDSA_SECP256R1_SHA256 => {
            let raw = public_key
                .downcast_ref::<CertificatePublicKeyBytes>()
                .ok_or_else(|| anyhow!("restls: ECDSA key exchange with non-EC certificate"))?;
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw.0)?;
            let signature = p256::ecdsa::Signature::from_der(signature)?;
            key.verify(signed, &signature).map_err(|e| anyhow!("restls: invalid ServerKeyExchange signature: {e}"))
        }
        SIG_RSA_PSS_RSAE_SHA256 => {
            let raw = public_key
                .downcast_ref::<CertificatePublicKeyBytes>()
                .ok_or_else(|| anyhow!("restls: RSA key exchange with non-RSA certificate"))?;
            let key = rsa::RsaPublicKey::from_pkcs1_der(&raw.0)?;
            let verifier = rsa::pss::VerifyingKey::<rsa::sha2::Sha256>::new(key);
            let signature = rsa::pss::Signature::try_from(signature)?;
            verifier.verify(signed, &signature).map_err(|e| anyhow!("restls: invalid ServerKeyExchange signature: {e}"))
        }
        SIG_ED25519 => {
            let raw = public_key
                .downcast_ref::<Ed25519PublicKey>()
                .ok_or_else(|| anyhow!("restls: Ed25519 key exchange with non-Ed25519 certificate"))?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&raw.0)?;
            let signature = ed25519_dalek::Signature::try_from(signature)?;
            key.verify(signed, &signature).map_err(|e| anyhow!("restls: invalid ServerKeyExchange signature: {e}"))
        }
        _ => bail!("restls: unsupported TLS 1.2 server signature scheme 0x{scheme:04x}"),
    }
}

/// Reads the TLS 1.2 server flight until ServerHelloDone, accumulating the handshake transcript.
async fn tls12_read_server_flight(
    stream: &mut Box<dyn NetConn>,
    messages: &mut HandshakeMessageStream,
    transcript: &mut Vec<u8>,
) -> Result<(Vec<X509Certificate>, crate::messages::ParsedServerKeyExchange)> {
    let mut certificates: Option<Vec<X509Certificate>> = None;
    let mut key_exchange = None;
    loop {
        let message = loop {
            if let Some(message) = messages.next_message() {
                break message;
            }
            let record = read_tls_record(stream).await?;
            if record_type(&record)? != RECORD_TYPE_HANDSHAKE {
                bail!("restls: expected TLS 1.2 server handshake record");
            }
            messages.feed(record_payload(&record));
        };
        let (msg_type, body) = handshake_message_parts(&message)?;
        match msg_type {
            HANDSHAKE_TYPE_CERTIFICATE if certificates.is_none() => {
                certificates = Some(parse_tls12_certificate(body)?);
            }
            HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE if key_exchange.is_none() && certificates.is_some() => {
                key_exchange = Some(parse_server_key_exchange(body)?);
            }
            HANDSHAKE_TYPE_SERVER_HELLO_DONE if body.is_empty() && key_exchange.is_some() => {
                transcript.extend_from_slice(&message);
                break;
            }
            _ => bail!("restls: unexpected TLS 1.2 server handshake message"),
        }
        transcript.extend_from_slice(&message);
    }
    let certificates = certificates.ok_or_else(|| anyhow!("restls: missing TLS 1.2 server certificate"))?;
    let key_exchange = key_exchange.ok_or_else(|| anyhow!("restls: missing ServerKeyExchange"))?;
    Ok((certificates, key_exchange))
}

/// Sends the TLS 1.2 client Finished and appends its plaintext message to the transcript.
async fn send_tls12_client_finished(
    stream: &mut Box<dyn NetConn>,
    protection: &mut Tls12RecordProtection,
    master: &[u8; 48],
    transcript: &mut Vec<u8>,
    hash: Tls12PrfHash,
) -> Result<()> {
    let client_verify = tls12_finished_verify_data(master, b"client finished", &tls12_hash(transcript, hash), hash);
    let message = marshal_finished12(&client_verify);
    let encrypted = protection.seal(RECORD_TYPE_HANDSHAKE, &message);
    protection.advance();
    let length = u16::try_from(encrypted.len())
        .map_err(|_| anyhow!("restls: TLS 1.2 Finished record exceeds the TLS record limit"))?;
    let mut raw = Vec::with_capacity(RECORD_HEADER_LEN + encrypted.len());
    raw.extend_from_slice(&[RECORD_TYPE_HANDSHAKE, 3, 3]);
    raw.extend_from_slice(&length.to_be_bytes());
    raw.extend_from_slice(&encrypted);
    write_all(stream, &raw).await?;
    transcript.extend_from_slice(&message);
    Ok(())
}

/// Unmasks and decrypts the TLS 1.2 server Finished, reporting whether the record uses the
/// parrot GCM nonce layout.
fn open_tls12_server_finished(
    record: &mut [u8],
    config: &Config,
    server_random: &[u8; 32],
    protection: &mut Tls12RecordProtection,
) -> Result<(bool, Vec<u8>)> {
    let parrot_gcm = record_payload(record).get(..8) == Some(&[0; 8][..]);
    let original = record.to_vec();
    let mut mac = blake3::Hasher::new_keyed(&config.restls_secret);
    mac.update(server_random);
    let mask = mac.finalize();
    let offset = RECORD_HEADER_LEN + if parrot_gcm { 8 } else { 0 };
    let Some((_, masked)) = record.split_at_mut_checked(offset) else {
        bail!("restls: short TLS 1.2 server Finished record");
    };
    for (byte, mask_byte) in masked.iter_mut().zip(mask.as_bytes().get(..RESTLS_HANDSHAKE_MAC_LEN).unwrap_or_default())
    {
        *byte ^= mask_byte;
    }
    let Ok(finished) = protection.open(RECORD_TYPE_HANDSHAKE, record_payload(record)) else {
        protection
            .open(RECORD_TYPE_HANDSHAKE, record_payload(&original))
            .map_err(|_| anyhow!("restls: TLS 1.2 server Finished failed to decrypt"))?;
        bail!("restls: server did not apply the Restls auth mask");
    };
    protection.advance();
    Ok((parrot_gcm, finished))
}

fn tls12_conn(
    stream: Box<dyn NetConn>,
    config: &Config,
    server_random: [u8; 32],
    parrot_gcm: bool,
    protection: Tls12RecordProtection,
) -> Box<dyn NetConn> {
    Box::new(RestlsConn {
        inner: SharedConn::from_boxed(stream),
        secret: config.restls_secret,
        server_random,
        to_server_counter: 0,
        to_client_counter: 0,
        client_finished: None,
        script: config.restls_script.clone(),
        tls12_gcm: true,
        parrot_gcm,
        relay: Some(RelayRead::Tls12 { protection, real_record_counter: 0 }),
        peer_closed: false,
        read_buf: Vec::new(),
        pending_raw: Vec::new(),
        write_buf: Vec::new(),
        response_records: 0,
        write_waker: Mutex::new(None),
        read_waker: Mutex::new(None),
        pending_drain: Mutex::new(None),
        closed: AtomicBool::new(false),
        write_pos: 0,
    })
}

/// RFC 5246 §7.4.9: the server's TLS 1.2 `Finished.verify_data` is exactly the PRF output this
/// transcript derives, and byte equality is decided without early exit.
fn tls12_server_finished_matches(
    master: &[u8; 48],
    session_hash: &[u8],
    hash: Tls12PrfHash,
    received: &[u8; 12],
) -> bool {
    bool::from(tls12_finished_verify_data(master, b"server finished", session_hash, hash).ct_eq(received.as_slice()))
}

async fn handshake_tls12(
    mut stream: Box<dyn NetConn>,
    config: &Config,
    our_secret: x25519_dalek::StaticSecret,
    our_public: [u8; 32],
    client_random: [u8; 32],
    client_hello: &[u8],
    server_hello_message: Vec<u8>,
    server_hello_remainder: Vec<u8>,
    server_hello: crate::messages::ParsedServerHello,
) -> Result<Box<dyn NetConn>> {
    let suite = Tls12CipherSuite::from_id(server_hello.cipher_suite)
        .ok_or_else(|| anyhow!("restls: unsupported TLS 1.2 cipher suite 0x{:04x}", server_hello.cipher_suite))?;
    let server_random = server_hello.random;
    let mut transcript = Vec::new();
    transcript.extend_from_slice(client_hello);
    transcript.extend_from_slice(&server_hello_message);
    let mut messages = HandshakeMessageStream::new();
    messages.feed(&server_hello_remainder);
    let (certificates, key_exchange) = tls12_read_server_flight(&mut stream, &mut messages, &mut transcript).await?;

    let (leaf, intermediates) =
        certificates.split_first().ok_or_else(|| anyhow!("restls: missing TLS 1.2 server certificate"))?;
    verify_peer_chain(config, leaf, intermediates)?;
    if key_exchange.curve != GROUP_X25519 {
        bail!("restls: unsupported TLS 1.2 ECDHE group 0x{:04x}", key_exchange.curve);
    }
    let public_key =
        leaf.public_key.as_ref().ok_or_else(|| anyhow!("restls: TLS 1.2 certificate has no public key"))?;
    let mut signed = Vec::with_capacity(64 + key_exchange.params.len());
    signed.extend_from_slice(&client_random);
    signed.extend_from_slice(&server_random);
    signed.extend_from_slice(&key_exchange.params);
    verify_tls12_server_key_exchange(
        public_key.as_ref(),
        key_exchange.signature_scheme,
        &signed,
        &key_exchange.signature,
    )?;
    let server_public: [u8; 32] = key_exchange
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("restls: invalid TLS 1.2 X25519 server public key"))?;
    let shared_secret = x25519_diffie_hellman(&our_secret, &x25519_dalek::PublicKey::from(server_public))?;
    let ckx = marshal_client_key_exchange(&our_public);
    write_tls_record(&mut stream, RECORD_TYPE_HANDSHAKE, &ckx).await?;
    transcript.extend_from_slice(&ckx);

    let hash = suite.prf_hash();
    let master = tls12_master_secret(&shared_secret, &client_random, &server_random, hash);
    let keys = tls12_key_block(&master, &client_random, &server_random, suite);
    let mut client_protection = Tls12RecordProtection::new(suite, keys.client_write_key, keys.client_write_iv);
    let mut server_protection = Tls12RecordProtection::new(suite, keys.server_write_key, keys.server_write_iv);
    write_all(&mut stream, &RESTLS_CCS_RECORD).await?;
    send_tls12_client_finished(&mut stream, &mut client_protection, &master, &mut transcript, hash).await?;

    let ccs = read_tls_record(&mut stream).await?;
    if ccs != RESTLS_CCS_RECORD {
        bail!("restls: expected TLS 1.2 server ChangeCipherSpec");
    }
    let mut record = read_tls_record(&mut stream).await?;
    if record_type(&record)? != RECORD_TYPE_HANDSHAKE {
        bail!("restls: expected encrypted TLS 1.2 server Finished");
    }
    let (parrot_gcm, finished) =
        open_tls12_server_finished(&mut record, config, &server_random, &mut server_protection)?;
    let received = parse_finished12(&finished)?;
    if !tls12_server_finished_matches(&master, &tls12_hash(&transcript, hash), hash, &received) {
        bail!("restls: TLS 1.2 server Finished verification failed");
    }
    Ok(tls12_conn(stream, config, server_random, parrot_gcm, server_protection))
}

/// TLS 1.3 session-id restls auth token: the first 16 bytes of the keyed HMAC over every key
/// share's `be16(group)` and data, then every PSK identity label.
fn restls_session_id_auth_token(secret: &[u8; 32], key_shares: &[KeyShareEntry], psk_labels: &[&[u8]]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new_keyed(secret);
    for ks in key_shares {
        hasher.update(&ks.group.to_be_bytes());
        hasher.update(&ks.data);
    }
    for label in psk_labels {
        hasher.update(label);
    }
    let digest = hasher.finalize();
    digest.as_bytes().get(..RESTLS_HANDSHAKE_MAC_LEN).and_then(|bytes| bytes.try_into().ok()).unwrap_or_default()
}

/// The post-handshake Restls connection: a plain byte stream whose wire framing is the
/// HMAC-authenticated, mask-XORed application record scheme, used once the peer is authenticated
/// and the handshake is complete.
/// The relay keeps forwarding the disguise target's own records verbatim after the handshake, so
/// every server->client record counts towards `to_client_counter` and a record that fails Restls
/// authentication is decrypted with the negotiated application keys instead.
struct RestlsConn {
    inner: SharedConn,
    secret: [u8; 32],
    server_random: [u8; 32],
    to_server_counter: u64,
    to_client_counter: u64,
    /// Consumed by the very first client->server write.
    client_finished: Option<Vec<u8>>,
    script: Vec<crate::script::Line>,
    tls12_gcm: bool,
    parrot_gcm: bool,
    /// Application-traffic read keys, kept only to decrypt records the relay passes through
    /// unframed. `None` means any unframed record is fatal for this version.
    relay: Option<RelayRead>,
    /// Sticky clean EOF: set once a close_notify alert arrives, and never cleared.
    peer_closed: bool,

    /// Decoded plaintext not yet delivered to the caller's `poll_read` buffer.
    read_buf: Vec<u8>,
    /// Raw bytes read from `inner` for the TLS record currently being assembled.
    pending_raw: Vec<u8>,

    /// Framed record bytes queued for `inner`, not yet fully written.
    write_buf: Vec<u8>,
    write_pos: usize,
    response_records: u16,
    write_waker: Mutex<Option<std::task::Waker>>,
    read_waker: Mutex<Option<std::task::Waker>>,
    pending_drain: Mutex<Option<tokio::task::JoinHandle<io::Result<()>>>>,
    closed: AtomicBool,
}

/// Application-traffic receive state for records the relay forwards unframed.
enum RelayRead {
    Tls13 {
        suite: CipherSuite,
        secret: [u8; crypto::HASH_LEN],
        protection: RecordProtection,
    },
    Tls12 {
        protection: Tls12RecordProtection,
        /// The real to-client record counter. The relay overwrites a TLS 1.2 record's explicit
        /// nonce with its own Restls counter, so the real one has to be restored before the AEAD
        /// check; it is the target's record sequence number, which starts at one past the
        /// server Finished.
        real_record_counter: u64,
    },
}

enum RelayedRecord {
    /// Nothing to deliver: camouflage traffic, or a post-handshake message with no local effect.
    Consumed,
    /// The relay replayed the target's close_notify.
    Closed,
}

impl RestlsConn {
    fn wake_waiter(waiter: &Mutex<Option<std::task::Waker>>) {
        let waker = waiter.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// The payload this record carries, its total data+padding length, and its command. A script
    /// line whose target resolves to zero carries no payload and is padded to a random 19..=118
    /// bytes, so an empty filler record never looks undersized.
    fn next_record_shape(&self, data_len: usize) -> (usize, usize, crate::script::Command) {
        let (target, command) = match usize::try_from(self.to_server_counter).ok().and_then(|i| self.script.get(i)) {
            Some(line) => (line.target_len.len(), line.command),
            None => (data_len, crate::script::Command::Noop),
        };
        if target == 0 {
            let padding = FILLER_RECORD_PADDING_MIN + rand::rng().random_range(0..FILLER_RECORD_PADDING_SPAN);
            return (0, padding, command);
        }
        let target = target.min(MAX_PLAINTEXT - RESTLS_APP_DATA_AUTH_HEADER_LEN - if self.tls12_gcm { 8 } else { 0 });
        (data_len.min(target), target, command)
    }

    fn poll_send_responses(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.response_records > 0 {
            match self.poll_flush_write_buf(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
            let (_, target_len, command) = self.next_record_shape(0);
            self.write_buf = framing::write_record_with_nonce(
                &self.secret,
                &self.server_random,
                false,
                self.to_server_counter,
                self.client_finished.take().as_deref(),
                &[],
                target_len,
                command,
                self.tls12_gcm,
            );
            self.to_server_counter += 1;
            self.response_records -= 1;
        }
        self.poll_flush_write_buf(cx)
    }

    fn poll_fill_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.pending_raw.len() >= RECORD_HEADER_LEN {
                let payload_len = be16_at(&self.pending_raw, 3).unwrap_or_default();
                if self.pending_raw.len() >= RECORD_HEADER_LEN + payload_len {
                    return Poll::Ready(Ok(()));
                }
            }
            let mut scratch = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "restls: connection closed",
                        )));
                    }
                    self.pending_raw.extend_from_slice(read_buf.filled());
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut pending = self.pending_drain.lock();
        let had_pending = pending.is_some() || self.write_pos < self.write_buf.len();
        if let Some(drain) = pending.as_mut() {
            match Pin::new(drain).poll(cx) {
                Poll::Ready(result) => {
                    *pending = None;
                    Self::wake_waiter(&self.read_waker);
                    Self::wake_waiter(&self.write_waker);
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => return Poll::Ready(Err(err)),
                        Err(err) => return Poll::Ready(Err(io::Error::other(err))),
                    }
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        drop(pending);
        while self.write_pos < self.write_buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, self.write_buf.get(self.write_pos..).unwrap_or_default()) {
                Poll::Ready(Ok(0)) => {
                    Self::wake_waiter(&self.read_waker);
                    Self::wake_waiter(&self.write_waker);
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "restls: write returned 0")));
                }
                Poll::Ready(Ok(n)) => self.write_pos += n,
                Poll::Ready(Err(err)) => {
                    Self::wake_waiter(&self.read_waker);
                    Self::wake_waiter(&self.write_waker);
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Self::wake_waiter(&self.write_waker);
        if had_pending {
            Self::wake_waiter(&self.read_waker);
        }
        Poll::Ready(Ok(()))
    }
}

impl RestlsConn {
    /// The post-handshake fallback: a record that fails Restls authentication
    /// was forwarded verbatim from the disguise target, so it must still be authenticated with
    /// the negotiated application keys before anything is believed about it. Application data
    /// belongs to the camouflage session and is dropped rather than surfaced.
    fn read_relayed_record(&mut self, record: &mut [u8]) -> io::Result<RelayedRecord> {
        let Some(mut relay) = self.relay.take() else {
            return Err(relay_error(&anyhow!("restls: unframed record on a connection without relay keys")));
        };
        let outcome = read_relayed_record(&mut relay, record);
        self.relay = Some(relay);
        outcome
    }
}

fn relay_error(err: &anyhow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}

fn read_relayed_record(relay: &mut RelayRead, record: &mut [u8]) -> io::Result<RelayedRecord> {
    let RelayRead::Tls13 { suite, secret, protection } = relay else {
        let RelayRead::Tls12 { protection, real_record_counter } = relay else {
            return Err(relay_error(&anyhow!("restls: unframed record on a connection without relay keys")));
        };
        *real_record_counter += 1;
        if let Some(explicit_nonce) = record.get_mut(RECORD_HEADER_LEN..RECORD_HEADER_LEN + 8) {
            explicit_nonce.copy_from_slice(&real_record_counter.to_be_bytes());
        }
        let record_type = *record.first().ok_or_else(|| relay_error(&anyhow!("restls: empty record")))?;
        protection.open(record_type, record_payload(record)).map_err(|err| relay_error(&err))?;
        protection.advance();
        return match record_type {
            RECORD_TYPE_APPLICATION_DATA => Ok(RelayedRecord::Consumed),
            other => Err(relay_error(&anyhow!("restls: unexpected post-handshake record type {other}"))),
        };
    };
    let header = record_header(record);
    let plaintext = protection.open(record_payload(record), &header).map_err(|err| relay_error(&err))?;
    protection.advance();
    let (content_type, content) = unpad_inner_plaintext(plaintext).map_err(|err| relay_error(&err))?;
    match content_type {
        RECORD_TYPE_APPLICATION_DATA => Ok(RelayedRecord::Consumed),
        RECORD_TYPE_ALERT => Ok(RelayedRecord::Closed),
        RECORD_TYPE_HANDSHAKE => read_relayed_handshake(*suite, secret, protection, &content),
        other => Err(relay_error(&anyhow!("restls: unexpected post-handshake content type {other}"))),
    }
}

fn read_relayed_handshake(
    suite: CipherSuite,
    secret: &mut [u8; crypto::HASH_LEN],
    protection: &mut RecordProtection,
    content: &[u8],
) -> io::Result<RelayedRecord> {
    let msg = first_handshake_message(content).map_err(|err| relay_error(&err))?;
    let (msg_type, _) = handshake_message_parts(msg).map_err(|err| relay_error(&err))?;
    match msg_type {
        // Session tickets are never offered back by this crate, so a relayed one is inert.
        HANDSHAKE_TYPE_NEW_SESSION_TICKET => Ok(RelayedRecord::Consumed),
        HANDSHAKE_TYPE_KEY_UPDATE => {
            let expanded = crypto::hkdf_expand_label(secret, "traffic upd", &[], crypto::HASH_LEN);
            *secret = expanded
                .get(..crypto::HASH_LEN)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| relay_error(&anyhow!("restls: malformed traffic update secret")))?;
            *protection = RecordProtection::new(suite, derive_traffic_keys(suite, secret));
            Ok(RelayedRecord::Consumed)
        }
        other => Err(relay_error(&anyhow!("restls: unexpected post-handshake message type {other}"))),
    }
}

impl AsyncRead for RestlsConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        if this.peer_closed {
            return Poll::Ready(Ok(()));
        }
        loop {
            match this.poll_send_responses(cx) {
                Poll::Ready(Ok(())) => *this.read_waker.lock() = None,
                Poll::Ready(Err(err)) => {
                    *this.read_waker.lock() = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => {
                    *this.read_waker.lock() = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
            if !this.read_buf.is_empty() {
                let n = this.read_buf.len().min(buf.remaining());
                buf.put_slice(this.read_buf.get(..n).unwrap_or_default());
                this.read_buf.drain(..n);
                return Poll::Ready(Ok(()));
            }
            match this.poll_fill_record(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
            let payload_len = be16_at(&this.pending_raw, 3).unwrap_or_default();
            let mut record = this.pending_raw.get(..RECORD_HEADER_LEN + payload_len).unwrap_or_default().to_vec();
            this.pending_raw.drain(..RECORD_HEADER_LEN + payload_len);

            if record.first() == Some(&RECORD_TYPE_ALERT) {
                this.to_client_counter += 1;
                this.peer_closed = true;
                return Poll::Ready(Ok(()));
            }

            let decoded = framing::read_record_with_nonce(
                &this.secret,
                &this.server_random,
                true,
                this.to_client_counter,
                None,
                &mut record,
                this.parrot_gcm,
            );
            this.to_client_counter += 1;
            let Ok(result) = decoded else {
                match this.read_relayed_record(&mut record) {
                    Ok(RelayedRecord::Consumed) => continue,
                    Ok(RelayedRecord::Closed) => {
                        this.peer_closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    Err(err) => return Poll::Ready(Err(err)),
                }
            };
            let payload = record.get(result.data_offset..result.data_offset + result.data_len).unwrap_or_default();
            this.read_buf.extend_from_slice(payload);
            if let crate::script::Command::Response(n) = result.command {
                this.response_records += u16::from(n);
            }
        }
    }
}

impl AsyncWrite for RestlsConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        match this.poll_send_responses(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => {
                *this.write_waker.lock() = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            let (data_len, target_len, command) = this.next_record_shape(buf.len());
            let client_finished = this.client_finished.take();
            this.write_buf = framing::write_record_with_nonce(
                &this.secret,
                &this.server_random,
                false,
                this.to_server_counter,
                client_finished.as_deref(),
                buf.get(..data_len).unwrap_or_default(),
                target_len,
                command,
                this.tls12_gcm,
            );
            this.to_server_counter += 1;
            match this.poll_flush_write_buf(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending if data_len > 0 => {
                    let remaining = this.write_buf.split_off(this.write_pos);
                    this.write_buf.clear();
                    this.write_pos = 0;
                    let inner = this.inner.clone();
                    *this.pending_drain.lock() = Some(tokio::spawn(async move { inner.write_all(&remaining).await }));
                    return Poll::Ready(Ok(data_len));
                }
                Poll::Pending => {
                    *this.write_waker.lock() = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
            if data_len > 0 {
                return Poll::Ready(Ok(data_len));
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        match this.poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                *this.write_waker.lock() = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        match this.poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                *this.write_waker.lock() = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl NetConn for RestlsConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.remote_addr()
    }

    fn close(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        if self.write_pos == self.write_buf.len() && self.pending_drain.lock().is_none() {
            if !self.closed.swap(true, Ordering::AcqRel) {
                Self::wake_waiter(&self.read_waker);
                Self::wake_waiter(&self.write_waker);
                return self.inner.close();
            }
            return Ok(());
        }
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "restls: queued record requires async shutdown"))?;
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        Self::wake_waiter(&self.read_waker);
        Self::wake_waiter(&self.write_waker);
        let inner = self.inner.clone();
        let mut pending = self.pending_drain.lock().take();
        let remaining = self.write_buf.get(self.write_pos..).unwrap_or_default().to_vec();
        handle.spawn(async move {
            let result = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                if let Some(drain) = pending.as_mut() {
                    drain.await??;
                }
                inner.write_all(&remaining).await?;
                Ok::<(), io::Error>(())
            })
            .await;
            if result.is_err() {
                if let Some(drain) = pending {
                    drain.abort();
                }
            }
            let _ = inner.close();
        });
        Ok(())
    }
}

impl Drop for RestlsConn {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Acquire)
            && (self.write_pos < self.write_buf.len() || self.pending_drain.lock().is_some())
        {
            let _ = self.close();
        }
    }
}

#[cfg(test)]
mod tls12_client_tests {
    use super::*;

    struct TinySocket(tokio::io::DuplexStream);

    impl AsyncRead for TinySocket {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TinySocket {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl NetConn for TinySocket {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Err(io::ErrorKind::AddrNotAvailable.into())
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Err(io::ErrorKind::AddrNotAvailable.into())
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingWriteSocket {
        failure: std::sync::Arc<AtomicBool>,
        kind: io::ErrorKind,
    }

    impl AsyncRead for FailingWriteSocket {
        fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for FailingWriteSocket {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
            if !self.failure.load(Ordering::Acquire) {
                return Poll::Pending;
            }
            if self.kind == io::ErrorKind::WriteZero {
                Poll::Ready(Ok(0))
            } else {
                Poll::Ready(Err(self.kind.into()))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl NetConn for FailingWriteSocket {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Err(io::ErrorKind::AddrNotAvailable.into())
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Err(io::ErrorKind::AddrNotAvailable.into())
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    struct WakeCounter(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for WakeCounter {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn direct_write_failures_wake_split_readers_and_writers() {
        for kind in [io::ErrorKind::WriteZero, io::ErrorKind::BrokenPipe] {
            for shutdown in [false, true] {
                let failure = std::sync::Arc::new(AtomicBool::new(false));
                let conn = RestlsConn {
                    inner: SharedConn::from_boxed(Box::new(FailingWriteSocket {
                        failure: std::sync::Arc::clone(&failure),
                        kind,
                    })),
                    secret: [9; 32],
                    server_random: [7; 32],
                    to_server_counter: 0,
                    to_client_counter: 0,
                    client_finished: None,
                    script: crate::script::parse_record_script("0,250").unwrap(),
                    tls12_gcm: false,
                    parrot_gcm: false,
                    relay: None,
                    peer_closed: false,
                    read_buf: Vec::new(),
                    pending_raw: Vec::new(),
                    write_buf: Vec::new(),
                    response_records: 0,
                    write_waker: Mutex::new(None),
                    read_waker: Mutex::new(None),
                    pending_drain: Mutex::new(None),
                    closed: AtomicBool::new(false),
                    write_pos: 0,
                };
                let (mut reader, mut writer) = tokio::io::split(conn);
                let writer_wakes = std::sync::Arc::new(WakeCounter(std::sync::atomic::AtomicUsize::new(0)));
                let writer_waker = std::task::Waker::from(std::sync::Arc::clone(&writer_wakes));
                let mut writer_cx = Context::from_waker(&writer_waker);
                assert!(matches!(Pin::new(&mut writer).poll_write(&mut writer_cx, b"unaccepted"), Poll::Pending));

                let reader_wakes = std::sync::Arc::new(WakeCounter(std::sync::atomic::AtomicUsize::new(0)));
                let reader_waker = std::task::Waker::from(std::sync::Arc::clone(&reader_wakes));
                let mut reader_cx = Context::from_waker(&reader_waker);
                let mut byte = [0; 1];
                assert!(matches!(
                    Pin::new(&mut reader).poll_read(&mut reader_cx, &mut ReadBuf::new(&mut byte)),
                    Poll::Pending
                ));
                failure.store(true, Ordering::Release);
                let result = if shutdown {
                    Pin::new(&mut writer).poll_shutdown(&mut writer_cx)
                } else {
                    Pin::new(&mut writer).poll_flush(&mut writer_cx)
                };
                assert!(matches!(&result, Poll::Ready(Err(err)) if err.kind() == kind));
                assert!(reader_wakes.0.load(Ordering::SeqCst) > 0, "reader slept after {kind:?}");
                assert!(writer_wakes.0.load(Ordering::SeqCst) > 0, "writer slept after {kind:?}");
                let read_result = Pin::new(&mut reader).poll_read(&mut reader_cx, &mut ReadBuf::new(&mut byte));
                assert!(matches!(&read_result, Poll::Ready(Err(err)) if err.kind() == kind));
            }
        }
    }

    #[test]
    fn tls12_session_id_authenticates_x25519_public_key() {
        let secret = [0x42; 32];
        let public = [0x91; 32];
        let id = tls12_session_id(&secret, &public);
        let mac = blake3::keyed_hash(&secret, &public);
        assert_eq!(&id[..RESTLS12_CLIENT_AUTH_LAYOUT3[1]], &mac.as_bytes()[..RESTLS12_CLIENT_AUTH_LAYOUT3[1]]);
        assert_ne!(
            &id[..RESTLS12_CLIENT_AUTH_LAYOUT3[1]],
            &blake3::keyed_hash(&secret, &[0; 32]).as_bytes()[..RESTLS12_CLIENT_AUTH_LAYOUT3[1]]
        );
    }

    #[test]
    fn tls12_certificate_parser_rejects_truncated_der() {
        assert!(parse_tls12_certificate(&[0, 0, 3, 0, 0, 2]).is_err());
        assert!(parse_tls12_certificate(&[0, 0, 0]).is_err());
    }

    #[tokio::test]
    async fn close_wakes_parked_reader_and_flush_without_losing_accepted_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let (inner, mut peer) = tokio::io::duplex(1);
        let mut conn = std::sync::Arc::new(RestlsConn {
            inner: SharedConn::from_boxed(Box::new(TinySocket(inner))),
            secret: [9; 32],
            server_random: [7; 32],
            to_server_counter: 0,
            to_client_counter: 0,
            client_finished: None,
            script: Vec::new(),
            tls12_gcm: false,
            parrot_gcm: false,
            relay: None,
            peer_closed: false,
            read_buf: Vec::new(),
            pending_raw: Vec::new(),
            write_buf: Vec::new(),
            response_records: 0,
            write_waker: Mutex::new(None),
            read_waker: Mutex::new(None),
            pending_drain: Mutex::new(None),
            closed: AtomicBool::new(false),
            write_pos: 0,
        });
        let payload = vec![0x55; 300];
        std::sync::Arc::get_mut(&mut conn).unwrap().write_all(&payload).await.unwrap();
        assert!(conn.pending_drain.lock().is_some());

        let reader_wakes = std::sync::Arc::new(WakeCounter(std::sync::atomic::AtomicUsize::new(0)));
        let reader_waker = std::task::Waker::from(std::sync::Arc::clone(&reader_wakes));
        let mut reader_cx = Context::from_waker(&reader_waker);
        let writer_wakes = std::sync::Arc::new(WakeCounter(std::sync::atomic::AtomicUsize::new(0)));
        let writer_waker = std::task::Waker::from(std::sync::Arc::clone(&writer_wakes));
        let mut writer_cx = Context::from_waker(&writer_waker);
        let mut byte = [0; 1];
        let active = std::sync::Arc::get_mut(&mut conn).unwrap();
        assert!(matches!(
            Pin::new(&mut *active).poll_read(&mut reader_cx, &mut ReadBuf::new(&mut byte)),
            Poll::Pending
        ));
        assert!(matches!(Pin::new(&mut *active).poll_flush(&mut writer_cx), Poll::Pending));
        assert_eq!(reader_wakes.0.load(Ordering::SeqCst), 0);
        assert_eq!(writer_wakes.0.load(Ordering::SeqCst), 0);

        let closer = std::sync::Arc::clone(&conn);
        closer.close().unwrap();
        assert!(reader_wakes.0.load(Ordering::SeqCst) > 0, "parked reader was not woken");
        assert!(writer_wakes.0.load(Ordering::SeqCst) > 0, "parked flush was not woken");
        drop(closer);
        let active = std::sync::Arc::get_mut(&mut conn).unwrap();
        assert!(matches!(
            Pin::new(&mut *active).poll_read(&mut reader_cx, &mut ReadBuf::new(&mut byte)),
            Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::NotConnected
        ));
        assert!(matches!(
            Pin::new(&mut *active).poll_flush(&mut writer_cx),
            Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::NotConnected
        ));
        assert!(matches!(
            Pin::new(&mut *active).poll_write(&mut writer_cx, b"late"),
            Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::NotConnected
        ));

        let mut header = [0; 5];
        timeout(Duration::from_secs(2), peer.read_exact(&mut header)).await.unwrap().unwrap();
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut record = vec![0; 5 + len];
        record[..5].copy_from_slice(&header);
        timeout(Duration::from_secs(2), peer.read_exact(&mut record[5..])).await.unwrap().unwrap();
        let decoded = framing::read_record(&[9; 32], &[7; 32], false, 0, None, &mut record).unwrap();
        assert_eq!(&record[decoded.data_offset..decoded.data_offset + decoded.data_len], payload);
    }

    #[tokio::test]
    async fn close_rejects_io_without_replaying_backpressured_zero_target_record() {
        use tokio::io::AsyncReadExt;
        use tokio::time::{timeout, Duration};

        let (inner, mut peer) = tokio::io::duplex(1);
        let mut conn = RestlsConn {
            inner: SharedConn::from_boxed(Box::new(TinySocket(inner))),
            secret: [9; 32],
            server_random: [7; 32],
            to_server_counter: 0,
            to_client_counter: 0,
            client_finished: None,
            script: crate::script::parse_record_script("0,250").unwrap(),
            tls12_gcm: false,
            parrot_gcm: false,
            relay: None,
            peer_closed: false,
            read_buf: Vec::new(),
            pending_raw: Vec::new(),
            write_buf: Vec::new(),
            response_records: 0,
            write_waker: Mutex::new(None),
            read_waker: Mutex::new(None),
            pending_drain: Mutex::new(None),
            closed: AtomicBool::new(false),
            write_pos: 0,
        };
        std::future::poll_fn(|cx| {
            assert!(matches!(Pin::new(&mut conn).poll_write(cx, b"not accepted"), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        conn.close().unwrap();
        conn.close().unwrap();
        std::future::poll_fn(|cx| {
            let mut byte = [0; 1];
            let mut read_buf = ReadBuf::new(&mut byte);
            for result in [
                Pin::new(&mut conn).poll_read(cx, &mut read_buf),
                Pin::new(&mut conn).poll_write(cx, b"late").map(|result| result.map(|_| ())),
                Pin::new(&mut conn).poll_flush(cx),
                Pin::new(&mut conn).poll_shutdown(cx),
            ] {
                assert!(matches!(&result, Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::NotConnected));
            }
            Poll::Ready(())
        })
        .await;
        let mut header = [0; 5];
        timeout(Duration::from_secs(2), peer.read_exact(&mut header)).await.unwrap().unwrap();
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut record = vec![0; 5 + len];
        record[..5].copy_from_slice(&header);
        timeout(Duration::from_secs(2), peer.read_exact(&mut record[5..])).await.unwrap().unwrap();
        let decoded = framing::read_record(&[9; 32], &[7; 32], false, 0, None, &mut record).unwrap();
        assert_eq!(decoded.data_len, 0);
        tokio::task::yield_now().await;
        std::future::poll_fn(|cx| {
            let mut byte = [0; 1];
            assert!(matches!(Pin::new(&mut peer).poll_read(cx, &mut ReadBuf::new(&mut byte)), Poll::Pending));
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn close_rejects_new_write_without_interleaving_accepted_record() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let (inner, mut peer) = tokio::io::duplex(1);
        let mut conn = RestlsConn {
            inner: SharedConn::from_boxed(Box::new(TinySocket(inner))),
            secret: [9; 32],
            server_random: [7; 32],
            to_server_counter: 0,
            to_client_counter: 0,
            client_finished: None,
            script: Vec::new(),
            tls12_gcm: false,
            parrot_gcm: false,
            relay: None,
            peer_closed: false,
            read_buf: Vec::new(),
            pending_raw: Vec::new(),
            write_buf: Vec::new(),
            response_records: 0,
            write_waker: Mutex::new(None),
            read_waker: Mutex::new(None),
            pending_drain: Mutex::new(None),
            closed: AtomicBool::new(false),
            write_pos: 0,
        };
        let payload = vec![0x55; 300];
        conn.write_all(&payload).await.unwrap();
        conn.close().unwrap();
        conn.close().unwrap();
        std::future::poll_fn(|cx| {
            assert!(matches!(&Pin::new(&mut conn).poll_write(cx, b"late"), Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::NotConnected));
            Poll::Ready(())
        })
        .await;
        let mut header = [0; 5];
        timeout(Duration::from_secs(2), peer.read_exact(&mut header)).await.unwrap().unwrap();
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut record = vec![0; 5 + len];
        record[..5].copy_from_slice(&header);
        timeout(Duration::from_secs(2), peer.read_exact(&mut record[5..])).await.unwrap().unwrap();
        let decoded = framing::read_record(&[9; 32], &[7; 32], false, 0, None, &mut record).unwrap();
        assert_eq!(&record[decoded.data_offset..decoded.data_offset + decoded.data_len], payload);
        tokio::task::yield_now().await;
        std::future::poll_fn(|cx| {
            let mut byte = [0; 1];
            assert!(matches!(Pin::new(&mut peer).poll_read(cx, &mut ReadBuf::new(&mut byte)), Poll::Pending));
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn accepted_write_delivers_full_record_without_a_followup_flush() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let (inner, mut peer) = tokio::io::duplex(1);
        let mut conn = RestlsConn {
            inner: SharedConn::from_boxed(Box::new(TinySocket(inner))),
            secret: [9; 32],
            server_random: [7; 32],
            to_server_counter: 0,
            to_client_counter: 0,
            client_finished: None,
            script: Vec::new(),
            tls12_gcm: false,
            parrot_gcm: false,
            relay: None,
            peer_closed: false,
            read_buf: Vec::new(),
            pending_raw: Vec::new(),
            write_buf: Vec::new(),
            response_records: 0,
            write_waker: Mutex::new(None),
            read_waker: Mutex::new(None),
            pending_drain: Mutex::new(None),
            closed: AtomicBool::new(false),
            write_pos: 0,
        };
        let payload = vec![0x55; 8192];
        let (writer, reader) = timeout(Duration::from_secs(2), async {
            tokio::join!(async { conn.write_all(&payload).await }, async {
                let mut header = [0; 5];
                peer.read_exact(&mut header).await?;
                let len = u16::from_be_bytes([header[3], header[4]]) as usize;
                let mut record = vec![0; 5 + len];
                record[..5].copy_from_slice(&header);
                peer.read_exact(&mut record[5..]).await?;
                Ok::<_, io::Error>(record)
            })
        })
        .await
        .expect("accepted bytes stalled without a flush");
        writer.unwrap();
        let mut record = reader.unwrap();
        let decoded = framing::read_record(&[9; 32], &[7; 32], false, 0, None, &mut record).unwrap();
        assert_eq!(&record[decoded.data_offset..decoded.data_offset + decoded.data_len], payload);
    }

    #[tokio::test]
    async fn zero_target_filler_record_uses_the_reference_padding_range() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        async fn read_one(peer: &mut tokio::io::DuplexStream) -> io::Result<Vec<u8>> {
            let mut header = [0; RECORD_HEADER_LEN];
            peer.read_exact(&mut header).await?;
            let len = usize::from(header[3]) << 8 | usize::from(header[4]);
            let mut record = vec![0; RECORD_HEADER_LEN + len];
            record[..RECORD_HEADER_LEN].copy_from_slice(&header);
            peer.read_exact(&mut record[RECORD_HEADER_LEN..]).await?;
            Ok(record)
        }

        let (inner, mut peer) = tokio::io::duplex(1);
        let mut conn = RestlsConn {
            inner: SharedConn::from_boxed(Box::new(TinySocket(inner))),
            secret: [9; 32],
            server_random: [7; 32],
            to_server_counter: 0,
            to_client_counter: 0,
            client_finished: None,
            script: crate::script::parse_record_script("0,250").expect("record script"),
            tls12_gcm: false,
            parrot_gcm: false,
            relay: None,
            peer_closed: false,
            read_buf: Vec::new(),
            pending_raw: Vec::new(),
            write_buf: Vec::new(),
            response_records: 0,
            write_waker: Mutex::new(None),
            read_waker: Mutex::new(None),
            pending_drain: Mutex::new(None),
            closed: AtomicBool::new(false),
            write_pos: 0,
        };
        let payload = b"zero-target-filler-then-payload";

        let (written, records) = timeout(Duration::from_secs(2), async {
            tokio::join!(async { conn.write_all(payload).await }, async {
                let filler = read_one(&mut peer).await?;
                let carried = read_one(&mut peer).await?;
                Ok::<_, io::Error>((filler, carried))
            })
        })
        .await
        .expect("zero-target filler record stalled the writer");
        written.expect("write payload");
        let (mut filler, mut carried) = records.expect("read both records");

        let decoded = framing::read_record(&[9; 32], &[7; 32], false, 0, None, &mut filler).expect("filler record");
        assert_eq!(decoded.data_len, 0, "a zero script target must not carry payload");
        let padding = filler.len() - RECORD_HEADER_LEN - RESTLS_APP_DATA_AUTH_HEADER_LEN;
        assert!(
            (FILLER_RECORD_PADDING_MIN..FILLER_RECORD_PADDING_MIN + FILLER_RECORD_PADDING_SPAN).contains(&padding),
            "filler padding {padding} is outside the expected range"
        );

        let decoded = framing::read_record(&[9; 32], &[7; 32], false, 1, None, &mut carried).expect("payload record");
        assert_eq!(&carried[decoded.data_offset..decoded.data_offset + decoded.data_len], payload);
    }

    #[tokio::test]
    async fn closing_after_accepted_write_delivers_complete_record() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        for cleanup in 0..3 {
            let (inner, mut peer) = tokio::io::duplex(1);
            let mut conn = RestlsConn {
                inner: SharedConn::from_boxed(Box::new(TinySocket(inner))),
                secret: [9; 32],
                server_random: [7; 32],
                to_server_counter: 0,
                to_client_counter: 0,
                client_finished: None,
                script: Vec::new(),
                tls12_gcm: false,
                parrot_gcm: false,
                relay: None,
                peer_closed: false,
                read_buf: Vec::new(),
                pending_raw: Vec::new(),
                write_buf: Vec::new(),
                response_records: 0,
                write_waker: Mutex::new(None),
                read_waker: Mutex::new(None),
                pending_drain: Mutex::new(None),
                closed: AtomicBool::new(false),
                write_pos: 0,
            };
            let payload = vec![0x55; 300];
            conn.write_all(&payload).await.unwrap();
            match cleanup {
                0 => conn.close().unwrap(),
                1 => {
                    conn.close().unwrap();
                    drop(conn);
                }
                _ => drop(conn),
            }
            let mut record = timeout(Duration::from_secs(2), async {
                let mut header = [0; 5];
                peer.read_exact(&mut header).await?;
                let len = u16::from_be_bytes([header[3], header[4]]) as usize;
                let mut record = vec![0; 5 + len];
                record[..5].copy_from_slice(&header);
                peer.read_exact(&mut record[5..]).await?;
                Ok::<_, io::Error>(record)
            })
            .await
            .expect("close discarded accepted client bytes")
            .unwrap();
            let decoded = framing::read_record(&[9; 32], &[7; 32], false, 0, None, &mut record).unwrap();
            assert_eq!(&record[decoded.data_offset..decoded.data_offset + decoded.data_len], payload);
        }
    }

    #[tokio::test]
    async fn dropping_backpressured_client_stops_drain_after_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let (inner, mut peer) = tokio::io::duplex(1);
        let mut conn = RestlsConn {
            inner: SharedConn::from_boxed(Box::new(TinySocket(inner))),
            secret: [9; 32],
            server_random: [7; 32],
            to_server_counter: 0,
            to_client_counter: 0,
            client_finished: None,
            script: Vec::new(),
            tls12_gcm: false,
            parrot_gcm: false,
            relay: None,
            peer_closed: false,
            read_buf: Vec::new(),
            pending_raw: Vec::new(),
            write_buf: Vec::new(),
            response_records: 0,
            write_waker: Mutex::new(None),
            read_waker: Mutex::new(None),
            pending_drain: Mutex::new(None),
            closed: AtomicBool::new(false),
            write_pos: 0,
        };
        conn.write_all(&vec![0x55; 300]).await.unwrap();
        drop(conn);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let mut received = Vec::new();
        timeout(Duration::from_secs(2), peer.read_to_end(&mut received))
            .await
            .expect("backpressured drain was not cancelled")
            .unwrap();
        assert!(received.len() < 300, "timed-out drain kept sending accepted record");
    }

    #[tokio::test]
    async fn cancelled_pending_write_never_claims_or_drops_next_payload() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        for (abandoned, next) in [(vec![0x55; 300], vec![0x77]), (vec![0x55; 300], vec![0x55; 300])] {
            let (inner, mut peer) = tokio::io::duplex(1);
            let mut conn = RestlsConn {
                inner: SharedConn::from_boxed(Box::new(TinySocket(inner))),
                secret: [9; 32],
                server_random: [7; 32],
                to_server_counter: 0,
                to_client_counter: 0,
                client_finished: None,
                script: Vec::new(),
                tls12_gcm: false,
                parrot_gcm: false,
                relay: None,
                peer_closed: false,
                read_buf: Vec::new(),
                pending_raw: Vec::new(),
                write_buf: Vec::new(),
                response_records: 0,
                write_waker: Mutex::new(None),
                read_waker: Mutex::new(None),
                pending_drain: Mutex::new(None),
                closed: AtomicBool::new(false),
                write_pos: 0,
            };
            let first = vec![0x55; 8192];
            timeout(Duration::from_millis(100), conn.write_all(&first))
                .await
                .expect("write must accept before socket drains")
                .unwrap();
            std::future::poll_fn(|cx| {
                assert!(matches!(Pin::new(&mut conn).poll_write(cx, &abandoned), Poll::Pending));
                Poll::Ready(())
            })
            .await;
            let (written, received) = timeout(Duration::from_secs(2), async {
                tokio::join!(conn.write_all(&next), async {
                    let mut decoded = Vec::new();
                    for counter in 0..2 {
                        let mut header = [0; 5];
                        peer.read_exact(&mut header).await?;
                        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
                        let mut record = vec![0; 5 + len];
                        record[..5].copy_from_slice(&header);
                        peer.read_exact(&mut record[5..]).await?;
                        let result =
                            framing::read_record(&[9; 32], &[7; 32], false, counter, None, &mut record).unwrap();
                        decoded.push(record[result.data_offset..result.data_offset + result.data_len].to_vec());
                    }
                    Ok::<_, io::Error>(decoded)
                })
            })
            .await
            .expect("writer stalled after abandoned write");
            written.unwrap();
            assert_eq!(received.unwrap(), vec![first, next]);
        }
    }

    #[tokio::test]
    async fn split_read_draining_frame_wakes_parked_writer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let (inner, mut peer) = tokio::io::duplex(1);
        let mut conn = RestlsConn {
            inner: SharedConn::from_boxed(Box::new(TinySocket(inner))),
            secret: [9; 32],
            server_random: [7; 32],
            to_server_counter: 0,
            to_client_counter: 0,
            client_finished: None,
            script: Vec::new(),
            tls12_gcm: false,
            parrot_gcm: false,
            relay: None,
            peer_closed: false,
            read_buf: Vec::new(),
            pending_raw: Vec::new(),
            write_buf: Vec::new(),
            response_records: 0,
            write_waker: Mutex::new(None),
            read_waker: Mutex::new(None),
            pending_drain: Mutex::new(None),
            closed: AtomicBool::new(false),
            write_pos: 0,
        };
        let first = vec![0x42; 8192];
        timeout(Duration::from_millis(100), conn.write_all(&first)).await.unwrap().unwrap();
        let (mut reader, mut writer) = tokio::io::split(conn);
        let second = vec![0x43; 8192];
        std::future::poll_fn(|cx| {
            assert!(matches!(Pin::new(&mut writer).poll_write(cx, &second), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let read_task = tokio::spawn(async move {
            let mut scratch = [0; 1];
            let mut ready_tx = Some(ready_tx);
            std::future::poll_fn(|cx| {
                assert!(matches!(Pin::new(&mut reader).poll_read(cx, &mut ReadBuf::new(&mut scratch)), Poll::Pending));
                ready_tx.take().unwrap().send(()).unwrap();
                Poll::Ready(())
            })
            .await;
            reader.read(&mut scratch).await
        });
        ready_rx.await.unwrap();
        let (written, received) = timeout(Duration::from_secs(2), async {
            tokio::join!(writer.write_all(&second), async {
                let mut decoded = Vec::new();
                for counter in 0..2 {
                    let mut header = [0; 5];
                    peer.read_exact(&mut header).await?;
                    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
                    let mut record = vec![0; 5 + len];
                    record[..5].copy_from_slice(&header);
                    peer.read_exact(&mut record[5..]).await?;
                    let result = framing::read_record(&[9; 32], &[7; 32], false, counter, None, &mut record).unwrap();
                    decoded.push(record[result.data_offset..result.data_offset + result.data_len].to_vec());
                }
                Ok::<_, io::Error>(decoded)
            })
        })
        .await
        .expect("split reader displaced writer wakeup");
        written.unwrap();
        assert_eq!(received.unwrap(), vec![first, second]);
        read_task.abort();
    }

    #[tokio::test]
    async fn split_writer_finishing_drain_wakes_parked_reader() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let (inner, mut peer) = tokio::io::duplex(1);
        let mut conn = RestlsConn {
            inner: SharedConn::from_boxed(Box::new(TinySocket(inner))),
            secret: [9; 32],
            server_random: [7; 32],
            to_server_counter: 0,
            to_client_counter: 0,
            client_finished: None,
            script: Vec::new(),
            tls12_gcm: false,
            parrot_gcm: false,
            relay: None,
            peer_closed: false,
            read_buf: Vec::new(),
            pending_raw: Vec::new(),
            write_buf: Vec::new(),
            response_records: 0,
            write_waker: Mutex::new(None),
            read_waker: Mutex::new(None),
            pending_drain: Mutex::new(None),
            closed: AtomicBool::new(false),
            write_pos: 0,
        };
        conn.write_all(&vec![0x42; 8192]).await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(conn);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let read_task = tokio::spawn(async move {
            let mut byte = [0; 1];
            let mut ready_tx = Some(ready_tx);
            std::future::poll_fn(|cx| {
                assert!(matches!(Pin::new(&mut reader).poll_read(cx, &mut ReadBuf::new(&mut byte)), Poll::Pending));
                ready_tx.take().unwrap().send(()).unwrap();
                Poll::Ready(())
            })
            .await;
            reader.read_exact(&mut byte).await.unwrap();
            byte
        });
        ready_rx.await.unwrap();
        std::future::poll_fn(|cx| {
            assert!(matches!(Pin::new(&mut writer).poll_flush(cx), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        let peer_task = tokio::spawn(async move {
            let mut header = [0; 5];
            peer.read_exact(&mut header).await?;
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut record = vec![0; len];
            peer.read_exact(&mut record).await?;
            let reply = framing::write_record(&[9; 32], &[7; 32], true, 0, None, b"r", 1, crate::script::Command::Noop);
            peer.write_all(&reply).await
        });
        timeout(Duration::from_secs(2), writer.flush()).await.expect("writer did not flush pending drain").unwrap();
        assert_eq!(timeout(Duration::from_secs(2), read_task).await.expect("reader lost wakeup").unwrap(), [b'r']);
        timeout(Duration::from_secs(2), peer_task).await.expect("peer reply stalled").unwrap().unwrap();
    }

    fn relay_test_conn(inner: SharedConn, relay: Option<RelayRead>) -> RestlsConn {
        RestlsConn {
            inner,
            secret: [9; 32],
            server_random: [7; 32],
            to_server_counter: 0,
            to_client_counter: 0,
            client_finished: None,
            script: Vec::new(),
            tls12_gcm: false,
            parrot_gcm: false,
            relay,
            peer_closed: false,
            read_buf: Vec::new(),
            pending_raw: Vec::new(),
            write_buf: Vec::new(),
            response_records: 0,
            write_waker: Mutex::new(None),
            read_waker: Mutex::new(None),
            pending_drain: Mutex::new(None),
            closed: AtomicBool::new(false),
            write_pos: 0,
        }
    }

    #[tokio::test]
    async fn relayed_tls13_record_is_dropped_and_still_consumes_a_to_client_counter() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let suite = CipherSuite::Aes128GcmSha256;
        let app_secret = [5; crypto::HASH_LEN];
        let camouflage = {
            let sealer = RecordProtection::new(suite, derive_traffic_keys(suite, &app_secret));
            let plaintext = pad_inner_plaintext(&[b'x'; 64], RECORD_TYPE_APPLICATION_DATA);
            let mut header = [RECORD_TYPE_APPLICATION_DATA, 3, 3, 0, 0];
            header[3..5].copy_from_slice(&((plaintext.len() + 16) as u16).to_be_bytes());
            let mut record = header.to_vec();
            record.extend_from_slice(&sealer.seal(&plaintext, &header));
            record
        };

        let (inner, mut peer) = tokio::io::duplex(4096);
        let mut conn = relay_test_conn(
            SharedConn::from_boxed(Box::new(TinySocket(inner))),
            Some(RelayRead::Tls13 {
                suite,
                secret: app_secret,
                protection: RecordProtection::new(suite, derive_traffic_keys(suite, &app_secret)),
            }),
        );
        peer.write_all(&camouflage).await.unwrap();
        peer.write_all(&framing::write_record(
            &[9; 32],
            &[7; 32],
            true,
            1,
            None,
            b"restls-payload",
            14,
            crate::script::Command::Noop,
        ))
        .await
        .unwrap();

        let mut delivered = [0u8; 14];
        timeout(Duration::from_secs(2), conn.read_exact(&mut delivered)).await.unwrap().unwrap();
        assert_eq!(&delivered, b"restls-payload", "camouflage payload leaked into the Restls stream");
    }

    #[tokio::test]
    async fn relayed_encrypted_alert_ends_the_client_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let suite = CipherSuite::Aes128GcmSha256;
        let app_secret = [5; crypto::HASH_LEN];
        let close_notify = {
            let sealer = RecordProtection::new(suite, derive_traffic_keys(suite, &app_secret));
            let plaintext = pad_inner_plaintext(&[1, 0, RECORD_TYPE_ALERT], RECORD_TYPE_ALERT);
            let mut header = [RECORD_TYPE_APPLICATION_DATA, 3, 3, 0, 0];
            header[3..5].copy_from_slice(&((plaintext.len() + 16) as u16).to_be_bytes());
            let mut record = header.to_vec();
            record.extend_from_slice(&sealer.seal(&plaintext, &header));
            record
        };

        let (inner, mut peer) = tokio::io::duplex(4096);
        let mut conn = relay_test_conn(
            SharedConn::from_boxed(Box::new(TinySocket(inner))),
            Some(RelayRead::Tls13 {
                suite,
                secret: app_secret,
                protection: RecordProtection::new(suite, derive_traffic_keys(suite, &app_secret)),
            }),
        );
        peer.write_all(&close_notify).await.unwrap();
        let mut sink = [0u8; 8];
        let read = timeout(Duration::from_secs(2), conn.read(&mut sink)).await.unwrap().unwrap();
        assert_eq!(read, 0, "relayed close_notify must be a clean EOF");
        assert_eq!(conn.read(&mut sink).await.unwrap(), 0, "EOF must be sticky");
    }

    #[tokio::test]
    async fn plaintext_close_notify_is_a_clean_eof() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let (inner, mut peer) = tokio::io::duplex(64);
        let mut conn = relay_test_conn(SharedConn::from_boxed(Box::new(TinySocket(inner))), None);
        peer.write_all(&[RECORD_TYPE_ALERT, 3, 3, 0, 2, 1, 0]).await.unwrap();
        let mut sink = [0u8; 4];
        let read = timeout(Duration::from_secs(2), conn.read(&mut sink)).await.unwrap().unwrap();
        assert_eq!(read, 0, "a close_notify alert must not be reported as an error");
    }

    #[tokio::test]
    async fn unusable_alpn_entries_are_rejected_before_the_client_hello() {
        for protos in [vec![String::new()], vec!["x".repeat(256)]] {
            let (inner, _peer) = tokio::io::duplex(64);
            let mut config = crate::config::new_restls_config("restls-interop-target", "secret", "tls13", "").unwrap();
            config.next_protos = protos;
            let err = new_restls(Box::new(TinySocket(inner)), &config).await.err().expect("must reject");
            assert!(err.to_string().contains("NextProtos"), "unexpected error: {err}");
        }
    }

    /// The TLS 1.3 `Finished` check accepts exactly the value the transcript derives: a one-byte
    /// difference and another traffic secret are both rejected.
    #[test]
    fn the_tls13_server_finished_check_rejects_any_byte_difference() {
        let secret = [0x5au8; crypto::HASH_LEN];
        let transcript_hash = [0x27u8; crypto::HASH_LEN];
        let finished = finished_verify_data(&secret, &transcript_hash);
        assert!(server_finished_matches(&secret, &transcript_hash, &finished));

        let mut one_byte_off = finished;
        one_byte_off[crypto::HASH_LEN - 1] ^= 1;
        assert!(!server_finished_matches(&secret, &transcript_hash, &one_byte_off));

        let other_secret = [0x5bu8; crypto::HASH_LEN];
        assert!(!server_finished_matches(&other_secret, &transcript_hash, &finished), "another traffic secret");
    }

    /// The TLS 1.2 `Finished` check accepts exactly the value the transcript derives: a one-byte
    /// difference, another master secret and another PRF hash are all rejected.
    #[test]
    fn the_tls12_server_finished_check_rejects_any_byte_difference() {
        let master = [0x11u8; 48];
        let session_hash = [0x22u8; 32];
        let verify_data = tls12_finished_verify_data(&master, b"server finished", &session_hash, Tls12PrfHash::Sha256);
        assert!(tls12_server_finished_matches(&master, &session_hash, Tls12PrfHash::Sha256, &verify_data));

        let mut one_byte_off = verify_data;
        one_byte_off[11] ^= 0x80;
        assert!(!tls12_server_finished_matches(&master, &session_hash, Tls12PrfHash::Sha256, &one_byte_off));

        let other_master = [0x12u8; 48];
        assert!(
            !tls12_server_finished_matches(&other_master, &session_hash, Tls12PrfHash::Sha256, &verify_data),
            "another master secret"
        );
        assert!(
            !tls12_server_finished_matches(&master, &session_hash, Tls12PrfHash::Sha384, &verify_data),
            "another PRF hash"
        );
    }
}

//! The REALITY client: authentication and the fallback that fires on failure.
//!
//! Scope cut, stated up front: this client speaks the REALITY authentication protocol (the
//! `ClientHello` splice, `AuthKey` derivation, Ed25519 certificate HMAC check) over a hand-rolled
//! minimal TLS 1.3 handshake, not full browser-fingerprint mimicry (client-hello or JA3 spoofing).
//! A censor doing TLS fingerprinting could tell this apart from a real browser; REALITY's own core
//! trick -- proving identity via a self-signed certificate's forged signature field -- is
//! implemented faithfully and interoperates with a real REALITY server. The X25519MLKEM768 hybrid
//! is accepted but always treated as disabled: the hybrid group "does not work properly with the
//! old reality server", so classic X25519 is both the safer default and the only key-exchange
//! group this crate implements.

use anyhow::{anyhow, Result};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::cert;
use crate::handshake::{self, ClientHello, ServerHello};
use crate::record::RecordLayer;
use crate::stream::RealityStream;
use crate::suite::{CipherSuite, KeySchedule};

pub const MAX_SHORT_ID_LEN: usize = 8;

#[derive(Clone, Debug)]
pub struct RealityClientConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; MAX_SHORT_ID_LEN],
}

const OFFERED_SUITES: [CipherSuite; 3] =
    [CipherSuite::Aes128GcmSha256, CipherSuite::Aes256GcmSha384, CipherSuite::Chacha20Poly1305Sha256];

/// On authentication failure this fires the fallback masking traffic in the background and
/// returns an error; the caller must not reuse `stream` afterward either way.
// NOT cancel-safe: the handshake writes its preamble and messages to the socket before it completes, so a dropped call leaves the connection mid-exchange; the arms that await it drop it only when the connection is being torn down.
pub async fn connect_reality_client<S>(
    stream: S,
    server_name: &str,
    cfg: &RealityClientConfig,
) -> Result<RealityStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let mut record_layer = RecordLayer::new(stream);

    let mut random = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    let (client_private, client_public) = crate::suite::generate_x25519_keypair();

    let mut hello = ClientHello::build(random, &OFFERED_SUITES, server_name, client_public);

    let auth_key_shared = x25519_dalek::x25519(client_private, cfg.public_key);
    let auth_key = crate::suite::hkdf_sha256_reality(&auth_key_shared, &random[..20]);

    let now = crate::clock::now_unix_secs();
    let mut plaintext = [0u8; 16];
    plaintext[0] = 1;
    plaintext[1] = 8;
    plaintext[2] = 2;
    // The session-id block carries the low 32 bits of the Unix second, big-endian.
    plaintext[4..8].copy_from_slice(&now.to_be_bytes()[4..8]);
    plaintext[8..16].copy_from_slice(&cfg.short_id);

    let aad = hello.raw_with_zero_session_id();
    let nonce: [u8; 12] = random[20..32].try_into()?;
    let sealed = CipherSuite::Aes256GcmSha384.seal(&auth_key, &nonce, &plaintext, &aad)?;
    // ^ Suite here is a stand-in purely to pick AES-256-GCM: AES-256 is selected on the full
    // 32-byte HKDF output. It has no relation to the TLS cipher suite negotiated below.
    let session_id: [u8; 32] =
        sealed.try_into().map_err(|_| anyhow!("REALITY: unexpected session-id AEAD output length"))?;
    hello.splice_session_id(session_id);

    record_layer.write_plaintext_handshake(&hello.raw).await?;

    let server_hello_msg = record_layer.read_handshake_message().await?;
    let server_hello = ServerHello::parse(&server_hello_msg)?;
    let suite = server_hello.cipher_suite;

    let tls_shared = x25519_dalek::x25519(client_private, server_hello.x25519_public);

    let mut transcript = suite.transcript();
    transcript.update(&hello.raw);
    transcript.update(&server_hello_msg);
    let ch_sh_digest = transcript.digest();

    let schedule = KeySchedule::new(suite, &tls_shared, &ch_sh_digest);
    let (server_hs_key, server_hs_iv) = schedule.traffic_key_iv(&schedule.server_handshake_secret);
    let (client_hs_key, client_hs_iv) = schedule.traffic_key_iv(&schedule.client_handshake_secret);
    record_layer.set_read_keys(suite, server_hs_key, server_hs_iv);
    record_layer.set_write_keys(suite, client_hs_key, client_hs_iv);

    let ee_msg = record_layer.read_handshake_message().await?;
    handshake::parse_encrypted_extensions(&ee_msg)?;
    transcript.update(&ee_msg);

    let cert_msg = record_layer.read_handshake_message().await?;
    let cert_der = handshake::parse_certificate(&cert_msg)?;
    transcript.update(&cert_msg);
    let pre_cv_digest = transcript.digest();

    let cv_msg = record_layer.read_handshake_message().await?;
    let leaf = cert::parse_ed25519_leaf(&cert_der)?;
    let Some((leaf_public, leaf_signature)) = leaf else {
        return Err(anyhow!("REALITY: server certificate is not Ed25519"));
    };
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&leaf_public)
        .map_err(|err| anyhow!("REALITY: malformed Ed25519 leaf key: {err}"))?;
    handshake::verify_certificate_verify(&cv_msg, &verifying_key, &pre_cv_digest)?;
    transcript.update(&cv_msg);
    let pre_finished_digest = transcript.digest();

    let finished_msg = record_layer.read_handshake_message().await?;
    let server_verify_data = handshake::parse_finished(&finished_msg)?;
    let expected = schedule.finished_verify_data(&schedule.server_handshake_secret, &pre_finished_digest);
    if server_verify_data != expected {
        return Err(anyhow!("REALITY: server Finished does not verify"));
    }
    transcript.update(&finished_msg);
    let through_server_finished = transcript.digest();

    let (client_ap_secret, server_ap_secret) = schedule.application_secrets(&through_server_finished);

    let client_verify_data = schedule.finished_verify_data(&schedule.client_handshake_secret, &through_server_finished);
    let client_finished_msg = handshake::build_finished(&client_verify_data);
    record_layer.write_encrypted(handshake::CONTENT_TYPE_HANDSHAKE, &client_finished_msg).await?;

    let (client_ap_key, client_ap_iv) = schedule.traffic_key_iv(&client_ap_secret);
    let (server_ap_key, server_ap_iv) = schedule.traffic_key_iv(&server_ap_secret);
    record_layer.set_write_keys(suite, client_ap_key, client_ap_iv);
    record_layer.set_read_keys(suite, server_ap_key, server_ap_iv);

    let expected_hmac = cert::hmac_signature(&auth_key, &leaf_public);
    let verified = expected_hmac == leaf_signature;

    murmur_log::debugln!("REALITY authentication: {verified}, cipher suite: {:?}", suite);

    if !verified {
        tokio::spawn(reality_client_fallback(RealityStream::new(record_layer), server_name.to_owned()));
        return Err(anyhow!("REALITY authentication failed"));
    }

    Ok(RealityStream::new(record_layer).with_cipher_suite(suite.id()))
}

/// Once authentication has failed, the connection is real TLS to *some* server (just not our
/// REALITY one); send a plausible masking request over it and idle briefly before closing, rather
/// than dropping it the instant auth fails (which would itself be a distinguishing timing signal).
/// Best-effort: errors are swallowed.
async fn reality_client_fallback<S>(mut stream: RealityStream<S>, server_name: String)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let mut padding = vec![0u8; 30 + (rand::rng().next_u32() % 32) as usize];
    padding.fill(b'0');
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {server_name}\r\nUser-Agent: Mozilla/5.0\r\nCookie: padding={}\r\nConnection: close\r\n\r\n",
        String::from_utf8_lossy(&padding)
    );
    if stream.write_all(request.as_bytes()).await.is_err() {
        return;
    }
    let _ = stream.flush().await;
    let delay = std::time::Duration::from_secs(5 + u64::from(rand::rng().next_u32() % 10));
    let mut discard = [0u8; 4096];
    let _ = tokio::time::timeout(delay, async {
        loop {
            match tokio::io::AsyncReadExt::read(&mut stream, &mut discard).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
}

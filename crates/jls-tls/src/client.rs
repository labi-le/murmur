//! Client-side handshake driver: builds the plaintext `ClientHello` flight,
//! then drives the encrypted server flight through to application-data keys.

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::cursor::split_handshake_message;
use crate::error::TlsError;
use crate::jls::{self, RANDOM_SEED_LEN};
use crate::keys::{self, KeySchedule};
use crate::messages::{self, ClientHelloParams};
use crate::record::{DirectionKeys, RecordIo, LEGACY_VERSION_INITIAL};
use crate::stream::JlsStream;
use crate::transcript::Transcript;
use crate::x509;
use crate::{ClientConfig, JlsConnectionState, JlsStatus};
use murmur_common_net::io::Stream;

// NOT cancel-safe: the handshake consumes `stream` by value, so a dropped call cannot be resumed
// on that connection.
pub async fn client_handshake<S: Stream>(stream: S, config: &ClientConfig) -> anyhow::Result<JlsStream<S>> {
    let local_addr = stream.local_addr().ok();
    let peer_addr = stream.peer_addr().ok();
    let (read_half, write_half) = tokio::io::split(stream);
    let mut rio = RecordIo::from_halves(read_half, write_half);
    let mut transcript = Transcript::new();

    let client_secret_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        rand::rng().fill_bytes(&mut b);
        b
    };
    let client_secret = StaticSecret::from(client_secret_bytes);
    let client_public = PublicKey::from(&client_secret);

    let mut legacy_session_id = [0u8; 32];
    rand::rng().fill_bytes(&mut legacy_session_id);

    let mut random_seed = [0u8; RANDOM_SEED_LEN];
    rand::rng().fill_bytes(&mut random_seed);

    let client_hello = client_hello_flight(config, &legacy_session_id, client_public.as_bytes(), &random_seed)?;

    rio.write_plaintext_record(crate::record::CONTENT_HANDSHAKE, LEGACY_VERSION_INITIAL, &client_hello).await?;
    rio.write_change_cipher_spec().await?;
    transcript.update(&client_hello);

    let server_hello_raw = rio.read_handshake_message().await?;
    let (msg_type, server_hello_body) = split_handshake_message(&server_hello_raw)?;
    if msg_type != messages::MSG_SERVER_HELLO {
        return Err(TlsError::protocol("client: expected ServerHello").into());
    }
    let server_hello = messages::parse_server_hello(server_hello_body)?;
    if server_hello.legacy_session_id_echo != legacy_session_id {
        return Err(TlsError::protocol("client: server did not echo legacy_session_id").into());
    }

    let server_auth_data = jls::jls_server_hello_auth_data(&server_hello_raw)?;
    let jls_authenticated = jls::jls_check_fake_random(&config.user, &server_hello.random, &server_auth_data);

    transcript.update(&server_hello_raw);

    let shared_secret = client_secret.diffie_hellman(&PublicKey::from(server_hello.x25519_public));
    let mut ks = KeySchedule::new(None, shared_secret.as_bytes(), &transcript.hash())?;

    let (server_hs_key, server_hs_iv) = keys::traffic_key_iv(&ks.server_handshake_traffic_secret)?;
    let (client_hs_key, client_hs_iv) = keys::traffic_key_iv(&ks.client_handshake_traffic_secret)?;
    rio.set_read_keys(DirectionKeys::new(server_hs_key, server_hs_iv));
    rio.set_write_keys(DirectionKeys::new(client_hs_key, client_hs_iv));

    let ee_raw = rio.read_handshake_message().await?;
    let (msg_type, ee_body) = split_handshake_message(&ee_raw)?;
    if msg_type != messages::MSG_ENCRYPTED_EXTENSIONS {
        return Err(TlsError::protocol("client: expected EncryptedExtensions").into());
    }
    let ee = messages::parse_encrypted_extensions(ee_body)?;
    if ee.quic_transport_parameters.is_some() {
        return Err(TlsError::protocol("client: server sent an unexpected quic_transport_parameters extension").into());
    }
    check_alpn(&config.alpn, ee.alpn.as_deref(), false)?;
    let negotiated_alpn = ee.alpn;
    transcript.update(&ee_raw);

    read_server_certificate(&mut rio, &mut transcript, config, jls_authenticated).await?;

    let hash_through_server_finished = finish_handshake(&mut rio, &mut transcript, &ks).await?;
    ks.derive_application_secrets(&hash_through_server_finished)?;

    let (client_ap_key, client_ap_iv) = keys::traffic_key_iv(&ks.client_application_traffic_secret)?;
    let (server_ap_key, server_ap_iv) = keys::traffic_key_iv(&ks.server_application_traffic_secret)?;

    let status = if jls_authenticated { JlsStatus::Authenticated } else { JlsStatus::Unauthenticated };
    let state = JlsConnectionState { status, negotiated_alpn, user: config.user.username.clone() };

    let (read_half, _read_hs_keys, write_half, _write_hs_keys) = rio.into_halves();
    Ok(JlsStream::new(
        read_half,
        DirectionKeys::new(server_ap_key, server_ap_iv),
        write_half,
        DirectionKeys::new(client_ap_key, client_ap_iv),
        state,
        local_addr,
        peer_addr,
    ))
}

/// Builds the `ClientHello` this handshake sends: the message is built twice so
/// that the JLS `FakeRandom` is sealed into the random field of the hello that
/// actually goes out.
fn client_hello_flight(
    config: &ClientConfig,
    legacy_session_id: &[u8; 32],
    x25519_public: &[u8; 32],
    random_seed: &[u8; RANDOM_SEED_LEN],
) -> anyhow::Result<Vec<u8>> {
    let placeholder_random = [0u8; 32];
    let placeholder_params = ClientHelloParams {
        legacy_session_id,
        random: &placeholder_random,
        server_name: &config.server_name,
        alpn: &config.alpn,
        x25519_public,
        quic_transport_parameters: None,
        psk: None,
        early_data: false,
    };
    let placeholder_hello = messages::build_client_hello(&placeholder_params)?;
    let auth_data = jls::jls_client_hello_auth_data(&placeholder_hello)?;
    let fake_random = jls::jls_build_fake_random(&config.user, random_seed, &auth_data, &mut rand::rng())?;
    Ok(messages::build_client_hello(&ClientHelloParams { random: &fake_random, ..placeholder_params })?)
}

/// Reads the server's `Certificate` and `CertificateVerify`, chain-verifies a
/// peer that is not JLS-authenticated, and checks the signature over the
/// transcript hash through the certificate.
async fn read_server_certificate<R, W>(
    rio: &mut RecordIo<R, W>,
    transcript: &mut Transcript,
    config: &ClientConfig,
    jls_authenticated: bool,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let cert_raw = rio.read_handshake_message().await?;
    let (msg_type, cert_body) = split_handshake_message(&cert_raw)?;
    if msg_type != messages::MSG_CERTIFICATE {
        return Err(TlsError::protocol("client: expected Certificate").into());
    }
    let chain = messages::parse_certificate_chain(cert_body)?;
    // A JLS peer's camouflage certificate is self-signed by construction and is
    // authenticated by the `ServerHello` random instead, so the chain check skips it; any other
    // peer is a real TLS site.
    if !jls_authenticated {
        x509::verify_server_chain(&chain, &config.server_name, &config.root_certs, config.time.as_ref())?;
    }
    transcript.update(&cert_raw);
    let hash_through_certificate = transcript.hash();

    let cv_raw = rio.read_handshake_message().await?;
    let (msg_type, cv_body) = split_handshake_message(&cv_raw)?;
    if msg_type != messages::MSG_CERTIFICATE_VERIFY {
        return Err(TlsError::protocol("client: expected CertificateVerify").into());
    }
    let signature_der = messages::parse_certificate_verify(cv_body)?;
    transcript.update(&cv_raw);

    let leaf = chain.first().ok_or_else(|| TlsError::protocol("client: server sent an empty certificate list"))?;
    verify_certificate_signature(leaf, &signature_der, &hash_through_certificate)?;
    Ok(())
}

/// Verifies the server's `Finished` and answers with this client's own, over the
/// transcript hash through the server `Finished`.
async fn finish_handshake<R, W>(
    rio: &mut RecordIo<R, W>,
    transcript: &mut Transcript,
    ks: &KeySchedule,
) -> anyhow::Result<[u8; 32]>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let hash_before_server_finished = transcript.hash();
    let finished_raw = rio.read_handshake_message().await?;
    let (msg_type, finished_body) = split_handshake_message(&finished_raw)?;
    if msg_type != messages::MSG_FINISHED {
        return Err(TlsError::protocol("client: expected Finished").into());
    }
    let received_verify_data = messages::parse_finished(finished_body)?;
    if !keys::verify_finished(&ks.server_handshake_traffic_secret, &hash_before_server_finished, &received_verify_data)?
    {
        return Err(TlsError::protocol("client: server Finished verify_data mismatch").into());
    }
    transcript.update(&finished_raw);

    let hash_through_server_finished = transcript.hash();
    let client_verify_data =
        keys::compute_finished(&ks.client_handshake_traffic_secret, &hash_through_server_finished)?;
    let client_finished = messages::build_finished(&client_verify_data)?;
    rio.write_handshake_message(&client_finished).await?;
    Ok(hash_through_server_finished)
}

/// Enforces ALPN selection rules: a server may only select a protocol the client advertised,
/// and a client that advertised nothing must never be told one was selected.
pub(crate) fn check_alpn(
    client_protocols: &[String],
    server_protocol: Option<&str>,
    quic: bool,
) -> crate::error::Result<()> {
    let Some(server_protocol) = server_protocol else {
        if quic && !client_protocols.is_empty() {
            return Err(TlsError::protocol("server did not select an ALPN protocol"));
        }
        return Ok(());
    };
    if client_protocols.is_empty() {
        return Err(TlsError::protocol("server advertised unrequested ALPN extension"));
    }
    if !client_protocols.iter().any(|proto| proto == server_protocol) {
        return Err(TlsError::protocol("server selected unadvertised ALPN protocol"));
    }
    Ok(())
}

fn verify_certificate_signature(
    cert_der: &[u8],
    signature_der: &[u8],
    hash_through_certificate: &[u8; 32],
) -> crate::error::Result<()> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let point = crate::der::extract_p256_spki_point(cert_der)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&point)
        .map_err(|_| TlsError::protocol("client: invalid server certificate public key"))?;
    let signature = Signature::from_der(signature_der)
        .map_err(|_| TlsError::protocol("client: malformed CertificateVerify signature"))?;
    let content = messages::certificate_verify_signed_content(hash_through_certificate);
    verifying_key
        .verify(&content, &signature)
        .map_err(|_| TlsError::protocol("client: server CertificateVerify signature verification failed"))
}

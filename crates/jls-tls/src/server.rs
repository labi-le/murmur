//! Server-side handshake driver.
//!
//! Per the can-fallback invariant, no byte is written to the
//! stream until JLS authentication has succeeded: the `ClientHello` is fully
//! read and every configured user is checked before any response is built, and
//! every failure raised before the first byte goes out carries the client's
//! bytes back so the caller can relay them to a camouflage destination.

use std::marker::Unpin;

use p256::ecdsa::signature::Signer;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::cursor::split_handshake_message;
use crate::error::{ServerHandshakeError, TlsError};
use crate::jls::{self, RANDOM_SEED_LEN};
use crate::keys::{self, KeySchedule};
use crate::messages;
use crate::record::{DirectionKeys, RecordIo, CONTENT_HANDSHAKE, LEGACY_VERSION};
use crate::stream::JlsStream;
use crate::tee::TeeReader;
use crate::transcript::Transcript;
use crate::{JlsConnectionState, JlsStatus, JlsUser, ServerConfig};
use murmur_common_net::io::Stream;

/// The server's record layer, still wrapped in the [`TeeReader`] that keeps
/// the replayable prefix alive: it is only unwrapped once the flight exists,
/// so a flight that cannot be built can still hand back every byte read.
type ServerRecordIo<S> = RecordIo<TeeReader<ReadHalf<S>>, WriteHalf<S>>;

/// Reads and fully validates the `ClientHello`, deciding JLS authentication
/// before a single byte is written back. On failure, hands back every byte
/// read from the client so far; on success the capture stays live in the
/// returned record layer for the caller to fall back on.
async fn read_and_authenticate<S: Stream>(
    read_half: ReadHalf<S>,
    write_half: WriteHalf<S>,
    config: &ServerConfig,
) -> Result<(ServerRecordIo<S>, Transcript, AuthenticatedClientHello), ServerHandshakeError> {
    let mut rio = RecordIo::from_halves(TeeReader::new(read_half), write_half);

    let client_hello = match read_client_hello(&mut rio, config).await {
        Ok(client_hello) => client_hello,
        Err(rejection) => {
            let (mut tee_read_half, _r, _write_half, _w) = rio.into_halves();
            return Err(rejection.into_error(tee_read_half.stop_capture()));
        }
    };

    let mut transcript = Transcript::new();
    transcript.update(&client_hello.raw);

    Ok((rio, transcript, client_hello))
}

struct AuthenticatedClientHello {
    raw: Vec<u8>,
    legacy_session_id: Vec<u8>,
    user: JlsUser,
    client_x25519_public: [u8; 32],
    alpn: Vec<String>,
}

/// Why the `ClientHello` was turned away. Both shapes stay replayable to a
/// camouflage destination; they are kept apart so
/// [`ServerHandshakeError::AuthFailed`] stays specific to a JLS
/// authentication failure rather than also covering a framing error.
enum ClientHelloRejection {
    Authentication,
    Malformed(TlsError),
}

impl ClientHelloRejection {
    fn into_error(self, consumed: Vec<u8>) -> ServerHandshakeError {
        match self {
            Self::Authentication => ServerHandshakeError::AuthFailed { consumed },
            Self::Malformed(err) => ServerHandshakeError::Replayable { consumed, source: err.into() },
        }
    }
}

async fn read_client_hello<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    rio: &mut RecordIo<TeeReader<R>, W>,
    config: &ServerConfig,
) -> Result<AuthenticatedClientHello, ClientHelloRejection> {
    let raw = match rio.read_handshake_message().await {
        Ok(raw) => raw,
        Err(err) => return Err(ClientHelloRejection::Malformed(err)),
    };

    let (msg_type, body) = split_handshake_message(&raw).map_err(ClientHelloRejection::Malformed)?;
    if msg_type != messages::MSG_CLIENT_HELLO {
        return Err(ClientHelloRejection::Malformed(TlsError::protocol("server: expected ClientHello")));
    }
    let parsed = messages::parse_client_hello(body).map_err(|_| ClientHelloRejection::Authentication)?;
    let auth_data = jls::jls_client_hello_auth_data(&raw).map_err(|_| ClientHelloRejection::Authentication)?;
    if parsed.quic_transport_parameters.is_some() {
        return Err(ClientHelloRejection::Malformed(TlsError::protocol(
            "server: client sent an unexpected quic_transport_parameters extension",
        )));
    }
    let presented_sni = parsed.server_name.clone().unwrap_or_default();
    if !jls::check_server_name(&config.server_name, &presented_sni) {
        return Err(ClientHelloRejection::Authentication);
    }
    let user = config
        .users
        .iter()
        .find(|u| jls::jls_check_fake_random(u, &parsed.random, &auth_data))
        .cloned()
        .ok_or(ClientHelloRejection::Authentication)?;

    if !messages::offers_tls13(&parsed.supported_versions) {
        return Err(ClientHelloRejection::Malformed(TlsError::protocol(
            "server: client did not offer TLS 1.3 in supported_versions",
        )));
    }

    let client_x25519_public = match parsed.x25519_public {
        Some(key) if parsed.offers_tls13_aes128_gcm && parsed.offers_x25519 => key,
        _ => {
            return Err(ClientHelloRejection::Malformed(TlsError::protocol(
                "server: client did not offer TLS_AES_128_GCM_SHA256 / X25519",
            )));
        }
    };

    Ok(AuthenticatedClientHello {
        raw,
        legacy_session_id: parsed.legacy_session_id,
        user,
        client_x25519_public,
        alpn: parsed.alpn,
    })
}

/// The `ServerHello` with its JLS `FakeRandom` sealed in, built before the first
/// byte reaches the client so a failure here stays replayable to a fallback
/// destination. The handshake traffic keys cannot be derived yet: they are keyed
/// on a transcript that includes this very message.
pub(crate) struct ServerHelloFlight {
    server_hello: Vec<u8>,
    shared_secret: [u8; 32],
    encrypted_extensions: Vec<u8>,
}

fn prepare_server_flight(
    user: &JlsUser,
    legacy_session_id: &[u8],
    client_x25519_public: [u8; 32],
    negotiated_alpn: Option<&str>,
) -> crate::error::Result<ServerHelloFlight> {
    let mut server_secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut server_secret_bytes);
    let server_secret = StaticSecret::from(server_secret_bytes);
    let server_public = PublicKey::from(&server_secret);

    let mut random_seed = [0u8; RANDOM_SEED_LEN];
    rand::rng().fill_bytes(&mut random_seed);

    let placeholder_hello =
        messages::build_server_hello(legacy_session_id, &[0u8; 32], server_public.as_bytes(), None)?;
    let server_auth_data = jls::jls_server_hello_auth_data(&placeholder_hello)?;
    let fake_random = jls::jls_build_fake_random(user, &random_seed, &server_auth_data, &mut rand::rng())?;
    let server_hello = messages::build_server_hello(legacy_session_id, &fake_random, server_public.as_bytes(), None)?;

    let shared_secret = server_secret.diffie_hellman(&PublicKey::from(client_x25519_public));
    let encrypted_extensions = messages::build_encrypted_extensions(negotiated_alpn, None, false)?;
    Ok(ServerHelloFlight { server_hello, shared_secret: shared_secret.to_bytes(), encrypted_extensions })
}

/// Builds the server's first flight, or hands the failure back with the
/// whole replay prefix. Every byte read is replayed, not just the
/// `ClientHello` message, so a client that coalesced another handshake message
/// into the same record keeps those bytes too.
pub(crate) fn prepare_server_flight_or_replayable<R>(
    user: &JlsUser,
    legacy_session_id: &[u8],
    client_x25519_public: [u8; 32],
    negotiated_alpn: Option<&str>,
    tee: &mut TeeReader<R>,
) -> Result<ServerHelloFlight, ServerHandshakeError> {
    match prepare_server_flight(user, legacy_session_id, client_x25519_public, negotiated_alpn) {
        Ok(flight) => Ok(flight),
        Err(err) => Err(ServerHandshakeError::Replayable { consumed: tee.stop_capture(), source: err.into() }),
    }
}

/// The `h2`/`http/1.1` compatibility fallback applies in
/// both modes: protocol overlap is not enforced, and servers configured with
/// only `h2` are still expected to serve `http/1.1` clients. Only the
/// empty-list case is mode-sensitive — RFC 9001 §8.1 binds a QUIC server that
/// has protocols to offer, while over TCP an unrequested protocol is fine.
pub(crate) fn negotiate_alpn(
    server_protocols: &[String],
    client_protocols: &[String],
    quic: bool,
) -> crate::error::Result<Option<String>> {
    if server_protocols.is_empty() || client_protocols.is_empty() {
        if quic && !server_protocols.is_empty() {
            return Err(TlsError::protocol("client did not request an application protocol"));
        }
        return Ok(None);
    }
    let mut http11_fallback = false;
    for server_protocol in server_protocols {
        for client_protocol in client_protocols {
            if server_protocol == client_protocol {
                return Ok(Some(server_protocol.clone()));
            }
            if server_protocol == "h2" && client_protocol == "http/1.1" {
                http11_fallback = true;
            }
        }
    }
    if http11_fallback {
        return Ok(None);
    }
    Err(TlsError::protocol("client requested unsupported application protocols"))
}

pub async fn server_handshake<S: Stream>(
    stream: S,
    config: &ServerConfig,
) -> Result<JlsStream<S>, ServerHandshakeError> {
    let local_addr = stream.local_addr().ok();
    let peer_addr = stream.peer_addr().ok();
    let (read_half, write_half) = tokio::io::split(stream);

    let (rio, mut transcript, client_hello) = read_and_authenticate(read_half, write_half, config).await?;

    let negotiated_alpn = match negotiate_alpn(&config.alpn, &client_hello.alpn, false) {
        Ok(negotiated) => negotiated,
        // The ALPN negotiation failure precedes the first flight byte, so the
        // replay stays available to the camouflage relay.
        Err(err) => {
            let (mut tee, _read_keys, _write_half, _write_keys) = rio.into_halves();
            return Err(ServerHandshakeError::Replayable { consumed: tee.stop_capture(), source: err.into() });
        }
    };
    let (mut tee, _read_keys, write_half, _write_keys) = rio.into_halves();
    let ServerHelloFlight { server_hello, shared_secret, encrypted_extensions } = prepare_server_flight_or_replayable(
        &client_hello.user,
        &client_hello.legacy_session_id,
        client_hello.client_x25519_public,
        negotiated_alpn.as_deref(),
        &mut tee,
    )?;
    let mut rio = RecordIo::from_halves(tee.into_inner(), write_half);

    // From here on the client has seen TLS records: nothing may be replayed to
    // a fallback destination any more.
    rio.write_plaintext_record(CONTENT_HANDSHAKE, LEGACY_VERSION, &server_hello).await?;
    rio.write_change_cipher_spec().await?;
    transcript.update(&server_hello);

    let mut key_schedule = KeySchedule::new(None, &shared_secret, &transcript.hash())?;
    let (server_handshake_key, server_handshake_iv) =
        keys::traffic_key_iv(&key_schedule.server_handshake_traffic_secret)?;
    let (client_handshake_key, client_handshake_iv) =
        keys::traffic_key_iv(&key_schedule.client_handshake_traffic_secret)?;
    rio.set_write_keys(DirectionKeys::new(server_handshake_key, server_handshake_iv));
    rio.set_read_keys(DirectionKeys::new(client_handshake_key, client_handshake_iv));

    rio.write_handshake_message(&encrypted_extensions).await?;
    transcript.update(&encrypted_extensions);

    let cert_msg = messages::build_certificate(&config.cert_der)?;
    rio.write_handshake_message(&cert_msg).await?;
    transcript.update(&cert_msg);

    let sign_content = messages::certificate_verify_signed_content(&transcript.hash());
    let signature: p256::ecdsa::Signature = config.key.sign(&sign_content);
    let cert_verify_msg = messages::build_certificate_verify(signature.to_der().as_bytes())?;
    rio.write_handshake_message(&cert_verify_msg).await?;
    transcript.update(&cert_verify_msg);

    let hash_before_server_finished = transcript.hash();
    let server_verify_data =
        keys::compute_finished(&key_schedule.server_handshake_traffic_secret, &hash_before_server_finished)?;
    let server_finished = messages::build_finished(&server_verify_data)?;
    rio.write_handshake_message(&server_finished).await?;
    transcript.update(&server_finished);

    let hash_through_server_finished = transcript.hash();
    key_schedule.derive_application_secrets(&hash_through_server_finished)?;

    let client_finished_raw = rio.read_handshake_message().await?;
    let (msg_type, client_finished_body) = split_handshake_message(&client_finished_raw)?;
    if msg_type != messages::MSG_FINISHED {
        return Err(ServerHandshakeError::Irreversible(anyhow::anyhow!("server: expected client Finished")));
    }
    let received_verify_data = messages::parse_finished(client_finished_body)?;
    if !keys::verify_finished(
        &key_schedule.client_handshake_traffic_secret,
        &hash_through_server_finished,
        &received_verify_data,
    )? {
        return Err(ServerHandshakeError::Irreversible(anyhow::anyhow!(
            "server: client Finished verify_data mismatch"
        )));
    }
    transcript.update(&client_finished_raw);

    let (client_ap_key, client_ap_iv) = keys::traffic_key_iv(&key_schedule.client_application_traffic_secret)?;
    let (server_ap_key, server_ap_iv) = keys::traffic_key_iv(&key_schedule.server_application_traffic_secret)?;

    let state = JlsConnectionState {
        status: JlsStatus::Authenticated,
        negotiated_alpn,
        user: client_hello.user.username.clone(),
    };
    let (read_half, _r, write_half, _w) = rio.into_halves();
    Ok(JlsStream::new(
        read_half,
        DirectionKeys::new(client_ap_key, client_ap_iv),
        write_half,
        DirectionKeys::new(server_ap_key, server_ap_iv),
        state,
        local_addr,
        peer_addr,
    ))
}

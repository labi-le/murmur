use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use p256::ecdsa::{SigningKey, VerifyingKey};
use parking_lot::Mutex;
use rand::RngCore;
use rustls::RootCertStore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf};

use crate::client::check_alpn;
use crate::cursor::{build_handshake_message, split_handshake_message};
use crate::jls::{jls_build_fake_random, jls_check_fake_random, jls_client_hello_auth_data, JlsUser, RANDOM_SEED_LEN};
use crate::messages::{self, ClientHelloParams};
use crate::record::{self, RecordIo};
use crate::server::prepare_server_flight_or_replayable;
use crate::stream::ALERT_CLOSE_NOTIFY;
use crate::tee::TeeReader;
use crate::{
    client_handshake, server_handshake, ClientConfig, JlsStatus, JlsStream, ServerConfig, ServerHandshakeError,
};
use murmur_common_net::io::Stream;

struct TestStream(DuplexStream);

impl AsyncRead for TestStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl Stream for TestStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
    }
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        vec![0x81, len as u8]
    }
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(value.len()));
    out.extend_from_slice(value);
    out
}

/// Builds a structurally-valid-but-unsigned X.509 DER certificate wrapping
/// `verifying_key`'s uncompressed SEC1 point, sufficient for
/// [`crate::der::extract_p256_spki_point`] (which only walks structure, never
/// validates a CA chain or a self-signature).
fn build_test_cert_der(verifying_key: &VerifyingKey) -> Vec<u8> {
    let point = verifying_key.to_sec1_point(false);
    let bit_string = {
        let mut v = vec![0x00u8];
        v.extend_from_slice(point.as_ref());
        v
    };
    let spki_alg = der_tlv(0x30, &[]);
    let spki = der_tlv(0x30, &[spki_alg, der_tlv(0x03, &bit_string)].concat());

    let serial = der_tlv(0x02, &[0x01]);
    let sig_alg = der_tlv(0x30, &[]);
    let issuer = der_tlv(0x30, &[]);
    let validity = der_tlv(0x30, &[]);
    let subject = der_tlv(0x30, &[]);

    let tbs = der_tlv(0x30, &[serial, sig_alg.clone(), issuer, validity, subject, spki].concat());
    let sig_value = der_tlv(0x03, &[0x00]);
    der_tlv(0x30, &[tbs, sig_alg, sig_value].concat())
}

pub(crate) fn test_server_key_and_cert() -> (SigningKey, Vec<u8>) {
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let key =
        SigningKey::from_bytes((&seed).into()).expect("random 32 bytes are an all but certainly valid P-256 scalar");
    let cert_der = build_test_cert_der(key.verifying_key());
    (key, cert_der)
}

#[tokio::test]
async fn full_handshake_round_trip_and_data_transfer() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (key, cert_der) = test_server_key_and_cert();

    let client_config = ClientConfig {
        server_name: "example.com".to_owned(),
        alpn: vec!["h2".to_owned()],
        user: JlsUser { username: "alice".to_owned(), password: "s3cret".to_owned() },
        root_certs: Arc::new(RootCertStore::empty()),
        time: None,
    };
    let server_config = ServerConfig {
        users: vec![JlsUser { username: "alice".to_owned(), password: "s3cret".to_owned() }],
        server_name: String::new(),
        alpn: vec!["h2".to_owned()],
        cert_der,
        key,
    };

    let client_fut = client_handshake(TestStream(client_io), &client_config);
    let server_fut = server_handshake(TestStream(server_io), &server_config);
    let (client_result, server_result) = tokio::join!(client_fut, server_fut);

    let mut client_stream = client_result.expect("client handshake should succeed");
    let mut server_stream = server_result.expect("server handshake should succeed");

    assert_eq!(client_stream.state().status, JlsStatus::Authenticated);
    assert_eq!(server_stream.state().status, JlsStatus::Authenticated);
    assert_eq!(client_stream.state().user, "alice");
    assert_eq!(server_stream.state().user, "alice");
    assert_eq!(client_stream.state().negotiated_alpn.as_deref(), Some("h2"));
    assert_eq!(server_stream.state().negotiated_alpn.as_deref(), Some("h2"));

    let large_message = vec![0x42u8; 40_000];
    client_stream.write_all(&large_message).await.expect("client write");
    client_stream.flush().await.expect("client flush");
    let mut received = vec![0u8; large_message.len()];
    server_stream.read_exact(&mut received).await.expect("server read");
    assert_eq!(received, large_message);

    let reply = b"hello from server";
    server_stream.write_all(reply).await.expect("server write");
    server_stream.flush().await.expect("server flush");
    let mut reply_received = vec![0u8; reply.len()];
    client_stream.read_exact(&mut reply_received).await.expect("client read");
    assert_eq!(&reply_received, reply);
}

/// Runs a real client/server handshake pair over a duplex pair, so a test can
/// drive records through both ends of a finished connection.
async fn handshake_pair() -> (JlsStream<TestStream>, JlsStream<TestStream>) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (key, cert_der) = test_server_key_and_cert();
    let user = JlsUser { username: "alice".to_owned(), password: "s3cret".to_owned() };
    let client_config = ClientConfig {
        server_name: "example.com".to_owned(),
        alpn: vec![],
        user: user.clone(),
        root_certs: Arc::new(RootCertStore::empty()),
        time: None,
    };
    let server_config = ServerConfig { users: vec![user], server_name: String::new(), alpn: vec![], cert_der, key };

    let (client_result, server_result) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            client_handshake(TestStream(client_io), &client_config),
            server_handshake(TestStream(server_io), &server_config),
        )
    })
    .await
    .expect("the handshake pair must not hang");
    (client_result.expect("client handshake should succeed"), server_result.expect("server handshake should succeed"))
}

/// The ALPN negotiation and checking both key on what each side actually
/// offered, so a test has to be able to hand the two halves different lists.
async fn handshake_pair_with_alpn(
    client_alpn: &[&str],
    server_alpn: &[&str],
) -> (anyhow::Result<JlsStream<TestStream>>, Result<JlsStream<TestStream>, ServerHandshakeError>) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (key, cert_der) = test_server_key_and_cert();
    let user = JlsUser { username: "alice".to_owned(), password: "s3cret".to_owned() };
    let client_config = ClientConfig {
        server_name: "example.com".to_owned(),
        alpn: client_alpn.iter().map(|proto| (*proto).to_owned()).collect(),
        user: user.clone(),
        root_certs: Arc::new(RootCertStore::empty()),
        time: None,
    };
    let server_config = ServerConfig {
        users: vec![user],
        server_name: String::new(),
        alpn: server_alpn.iter().map(|proto| (*proto).to_owned()).collect(),
        cert_der,
        key,
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            client_handshake(TestStream(client_io), &client_config),
            server_handshake(TestStream(server_io), &server_config),
        )
    })
    .await
    .expect("the handshake pair must not hang")
}

/// ALPN negotiation refuses a client that requested a protocol the server
/// does not serve, and the refusal happens before the server flight, so the
/// replay path can still hand the client's bytes to the camouflage
/// destination. Silently completing without a protocol would instead hand a
/// real tunnel to a client the operator never intended to serve.
#[tokio::test]
async fn a_client_alpn_the_server_does_not_offer_falls_back_instead_of_tunnelling() {
    let (client_result, server_result) = handshake_pair_with_alpn(&["http/1.1"], &["h3"]).await;

    match server_result {
        Err(ServerHandshakeError::Replayable { consumed, source }) => {
            assert!(source.to_string().contains("unsupported application protocols"), "unexpected error: {source}");
            assert!(!consumed.is_empty(), "the fallback needs the client's bytes to relay");
        }
        Err(other) => panic!("a disjoint ALPN list must stay replayable, got {other:?}"),
        Ok(_) => panic!("a disjoint ALPN list must not produce a working tunnel"),
    }
    assert!(client_result.is_err(), "the client must not see a successful handshake");
}

/// The compatibility carve-out: a server configured with only `h2` still serves
/// an `http/1.1` client, just without selecting a protocol.
#[tokio::test]
async fn an_h2_only_server_still_serves_an_http_1_1_client() {
    let (client_result, server_result) = handshake_pair_with_alpn(&["http/1.1"], &["h2"]).await;

    let client = client_result.expect("the http/1.1 client must be served");
    let server = server_result.expect("the h2-only server must complete the handshake");
    assert_eq!(client.state().negotiated_alpn, None);
    assert_eq!(server.state().negotiated_alpn, None);
}

/// ALPN negotiation short-circuits on an empty client protocol list, so a server
/// that has protocols configured still selects none when the client advertised
/// none. The server must not fall back to its own preference in that case.
#[tokio::test]
async fn a_client_that_offered_nothing_is_served_without_a_protocol() {
    let (client_result, server_result) = handshake_pair_with_alpn(&[], &["h2"]).await;

    let client = client_result.expect("over TCP a server that selects nothing is not an ALPN failure");
    let server = server_result.expect("an empty client list must not fail the server");
    assert_eq!(client.state().negotiated_alpn, None);
    assert_eq!(server.state().negotiated_alpn, None);
}

/// A well-behaved peer never selects an unoffered protocol, so the
/// ALPN-check rejections are only reachable against a hostile or buggy
/// server — which is exactly the case they exist for.
#[test]
fn check_alpn_rejects_a_selection_the_client_never_offered() {
    let offered = ["h2".to_owned()];

    check_alpn(&offered, Some("h2"), false).expect("an offered protocol is a valid selection");
    check_alpn(&offered, None, false).expect("over TCP selecting nothing is not a failure");

    let unadvertised =
        check_alpn(&offered, Some("h3"), false).expect_err("a server may not select an unoffered protocol");
    assert!(unadvertised.to_string().contains("unadvertised"), "unexpected error: {unadvertised}");

    let unsolicited =
        check_alpn(&[], Some("h2"), false).expect_err("a client that offered nothing cannot be given a protocol");
    assert!(unsolicited.to_string().contains("unrequested"), "unexpected error: {unsolicited}");

    let quic_missing = check_alpn(&offered, None, true)
        .expect_err("RFC 9001 §8.1 requires a QUIC server that has protocols to select one");
    assert!(quic_missing.to_string().contains("did not select"), "unexpected error: {quic_missing}");
    check_alpn(&[], None, true).expect("a QUIC client that offered nothing may be given nothing");
}

/// The negotiation runs in server preference order, and both halves have to
/// agree on the single selected protocol.
#[tokio::test]
async fn alpn_is_selected_in_server_preference_order() {
    let (client_result, server_result) = handshake_pair_with_alpn(&["http/1.1", "h2"], &["h2", "http/1.1"]).await;

    let client = client_result.expect("the client must accept the selection");
    let server = server_result.expect("the server must complete the handshake");
    assert_eq!(client.state().negotiated_alpn.as_deref(), Some("h2"));
    assert_eq!(server.state().negotiated_alpn.as_deref(), Some("h2"));
}

/// A peer that half-closes politely sends `close_notify` (RFC 8446 §6.1);
/// reading it must yield a plain EOF, exactly like a socket half-close, and
/// keep yielding it instead of touching the transport again.
#[tokio::test]
async fn peer_close_notify_reads_as_eof() {
    let (mut client_stream, mut server_stream) = handshake_pair().await;

    client_stream.write_alert(&ALERT_CLOSE_NOTIFY).await.expect("client close_notify");

    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(5), server_stream.read(&mut buf))
        .await
        .expect("close_notify must be answered, not stall the reader")
        .expect("close_notify is a clean EOF, not an error");
    assert_eq!(n, 0, "close_notify must read as EOF");

    let n = tokio::time::timeout(Duration::from_secs(5), server_stream.read(&mut buf))
        .await
        .expect("the closed stream must not stall a later read")
        .expect("a closed stream keeps reading as EOF");
    assert_eq!(n, 0, "the terminal read state must stick");

    // Only the read side went terminal: the same stream still writes, and the
    // peer, whose read side never saw the alert, still receives the bytes.
    server_stream.write_all(b"after close_notify").await.expect("server write after close_notify");
    let mut received = [0u8; 18];
    tokio::time::timeout(Duration::from_secs(5), client_stream.read_exact(&mut received))
        .await
        .expect("the client must not stall reading the server's post-alert write")
        .expect("client read");
    assert_eq!(&received, b"after close_notify");
}

/// The EOF relaxation is bounded: every other alert is still an error.
#[tokio::test]
async fn peer_fatal_alert_still_reads_as_an_error() {
    let (mut client_stream, mut server_stream) = handshake_pair().await;

    // fatal(2) / handshake_failure(40)
    client_stream.write_alert(&[2, 40]).await.expect("client fatal alert");

    let mut buf = [0u8; 8];
    let err = tokio::time::timeout(Duration::from_secs(5), server_stream.read(&mut buf))
        .await
        .expect("a fatal alert must not stall the reader")
        .expect_err("a fatal alert is not a clean EOF");
    assert!(err.to_string().contains("alert"), "unexpected error: {err}");
}

#[tokio::test]
async fn wrong_password_fails_authentication_and_consumes_bytes() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (key, cert_der) = test_server_key_and_cert();

    let client_config = ClientConfig {
        server_name: "example.com".to_owned(),
        alpn: vec![],
        user: JlsUser { username: "alice".to_owned(), password: "wrong-password".to_owned() },
        root_certs: Arc::new(RootCertStore::empty()),
        time: None,
    };
    let server_config = ServerConfig {
        users: vec![JlsUser { username: "alice".to_owned(), password: "s3cret".to_owned() }],
        server_name: String::new(),
        alpn: vec![],
        cert_der,
        key,
    };

    let captured = Arc::new(Mutex::new(Vec::new()));
    let probe = ProbeWriteStream { inner: TestStream(client_io), captured: Arc::clone(&captured) };
    let client_task = tokio::spawn(async move { client_handshake(probe, &client_config).await });

    let server_result = server_handshake(TestStream(server_io), &server_config).await;
    let client_result = client_task.await.expect("client task should not panic");

    assert!(client_result.is_err(), "client handshake must fail when the server rejects authentication");

    match server_result {
        Err(ServerHandshakeError::AuthFailed { consumed }) => {
            let client_written = captured.lock().clone();
            assert!(
                client_written.starts_with(&consumed),
                "the reported bytes must be a prefix of what the client wrote"
            );
            assert_eq!(consumed[0], 0x16, "the first consumed record must be a handshake record");
            let record_len = 5 + usize::from(u16::from_be_bytes([consumed[3], consumed[4]]));
            assert_eq!(consumed.len(), record_len, "only the ClientHello record may be consumed before auth");
        }
        Err(other) => panic!("expected AuthFailed, got {other:?}"),
        Ok(_) => panic!("expected AuthFailed, got a successful server handshake"),
    }
}

/// A camouflage probe that is not a `ClientHello` at all must be reported with
/// the bytes read so far, so the caller can replay them to the fallback
/// destination untouched.
#[tokio::test]
async fn non_tls_probe_is_replayable_with_its_bytes() {
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (key, cert_der) = test_server_key_and_cert();
    let server_config = ServerConfig {
        users: vec![JlsUser { username: "alice".to_owned(), password: "s3cret".to_owned() }],
        server_name: String::new(),
        alpn: vec![],
        cert_der,
        key,
    };

    // A record header whose content type is not a handshake message: enough to
    // be a non-`ClientHello` probe that still terminates.
    let probe = b"GET\x00\x00";
    client_io.write_all(probe).await.expect("write probe");
    let server_result = server_handshake(TestStream(server_io), &server_config).await;

    let err = server_result.expect_err("a non-TLS probe must not complete a handshake");
    assert!(matches!(err, ServerHandshakeError::Replayable { .. }), "got {err:?}");
    assert_eq!(err.replayable_prefix().as_deref(), Some(probe.as_slice()));
}

/// The `ClientHello` a `client_handshake` client puts on the wire: the
/// placeholder hello fixes the JLS auth data, the real one carries the
/// `FakeRandom` sealed into that same auth data.
fn wire_client_hello(user: &JlsUser, legacy_session_id: &[u8; 32], x25519_public: &[u8; 32]) -> Vec<u8> {
    let placeholder = messages::build_client_hello(&ClientHelloParams {
        legacy_session_id,
        random: &[0u8; 32],
        server_name: "example.com",
        alpn: &[],
        x25519_public,
        quic_transport_parameters: None,
        psk: None,
        early_data: false,
    })
    .expect("placeholder ClientHello");
    let auth_data = jls_client_hello_auth_data(&placeholder).expect("client hello auth data");
    let mut seed = [0u8; RANDOM_SEED_LEN];
    rand::rng().fill_bytes(&mut seed);
    let random = jls_build_fake_random(user, &seed, &auth_data, &mut rand::rng()).expect("client fake random");
    let hello = messages::build_client_hello(&ClientHelloParams {
        legacy_session_id,
        random: &random,
        server_name: "example.com",
        alpn: &[],
        x25519_public,
        quic_transport_parameters: None,
        psk: None,
        early_data: false,
    })
    .expect("ClientHello");

    // Keep the fixture honest: it has to be a `ClientHello` a real server
    // accepts, not just one that parses.
    let (_, body) = split_handshake_message(&hello).expect("handshake message");
    let parsed = messages::parse_client_hello(body).expect("parse the built ClientHello");
    let hello_auth_data = jls_client_hello_auth_data(&hello).expect("client hello auth data");
    assert!(jls_check_fake_random(user, &parsed.random, &hello_auth_data), "the fixture must pass JLS authentication");
    hello
}

/// A single TLS record holding the `ClientHello` plus a second, complete
/// handshake message a client would not normally send in the same record, and
/// the exact bytes that go into the transport.
fn coalesced_client_hello_record(
    user: &JlsUser,
    legacy_session_id: &[u8; 32],
    x25519_public: &[u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    let client_hello = wire_client_hello(user, legacy_session_id, x25519_public);
    let trailer = build_handshake_message(messages::MSG_FINISHED, &[0u8; 32]).expect("coalesced handshake message");
    let len: u16 = (client_hello.len() + trailer.len()).try_into().expect("the record fits a u16 length");
    let mut wire = record::outer_header(record::CONTENT_HANDSHAKE, record::LEGACY_VERSION_INITIAL, len).to_vec();
    wire.extend_from_slice(&client_hello);
    wire.extend_from_slice(&trailer);
    (wire, client_hello)
}

/// Feeds `wire` to a server half through the real record layer and hands back
/// the still-capturing reader, now holding every byte read.
async fn tee_after_client_hello(wire: &[u8], client_hello: &[u8]) -> TeeReader<ReadHalf<TestStream>> {
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    client_io.write_all(wire).await.expect("write the coalesced ClientHello record");
    let (server_read, _server_write) = tokio::io::split(TestStream(server_io));
    let mut tee = TeeReader::new(server_read);
    {
        let mut sink = tokio::io::sink();
        let mut rio = RecordIo::from_halves(&mut tee, &mut sink);
        let raw = tokio::time::timeout(Duration::from_secs(5), rio.read_handshake_message())
            .await
            .expect("the ClientHello record must arrive")
            .expect("read the ClientHello message");
        assert_eq!(raw, client_hello, "the record layer hands back exactly the ClientHello message");
    }
    tee
}

/// A flight that cannot be built must hand back every byte read from the
/// client, not just the `ClientHello` message: the fallback relay has to see
/// the record framing and anything coalesced behind the message.
#[tokio::test]
async fn flight_failure_replays_the_whole_read_stream() {
    let user = JlsUser { username: "alice".to_owned(), password: "s3cret".to_owned() };
    let legacy_session_id = [0x11u8; 32];
    let x25519_public = [0x22u8; 32];
    let (wire, client_hello) = coalesced_client_hello_record(&user, &legacy_session_id, &x25519_public);
    let mut tee = tee_after_client_hello(&wire, &client_hello).await;

    // `prepare_server_flight` cannot fail for a `ClientHello` that
    // `parse_client_hello` accepted: the parser caps the session id and every
    // ALPN name at 255 bytes, exactly what the `vec8` writers allow. The
    // failure contract is therefore exercised at the helper's boundary, with
    // a session id the parser can never produce.
    let err = prepare_server_flight_or_replayable(&user, &[0u8; 300], x25519_public, None, &mut tee)
        .err()
        .expect("a 300-byte session id cannot be echoed in a ServerHello");
    assert_eq!(
        err.replayable_prefix().as_deref(),
        Some(wire.as_slice()),
        "the replay prefix is every byte read, not just the ClientHello message"
    );
}

/// Nothing is replayable once the flight exists, so the successful path must
/// leave the capture untouched.
#[tokio::test]
async fn flight_success_leaves_the_capture_intact() {
    let user = JlsUser { username: "alice".to_owned(), password: "s3cret".to_owned() };
    let legacy_session_id = [0x11u8; 32];
    let x25519_public = [0x22u8; 32];
    let (wire, client_hello) = coalesced_client_hello_record(&user, &legacy_session_id, &x25519_public);
    let mut tee = tee_after_client_hello(&wire, &client_hello).await;

    prepare_server_flight_or_replayable(&user, &legacy_session_id, x25519_public, None, &mut tee)
        .expect("a well-formed ClientHello builds the flight");
    assert_eq!(tee.stop_capture(), wire, "the successful path must not consume the capture");
}

struct ProbeWriteStream<S> {
    inner: S,
    captured: Arc<Mutex<Vec<u8>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for ProbeWriteStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ProbeWriteStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.captured.lock().extend_from_slice(&buf[..n]);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: Stream> Stream for ProbeWriteStream<S> {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
}

#[test]
fn jls_fake_random_round_trips() {
    let user = JlsUser { username: "alice".to_owned(), password: "s3cret".to_owned() };
    let auth_data = b"some-auth-data".to_vec();
    let mut seed = [0u8; RANDOM_SEED_LEN];
    rand::rng().fill_bytes(&mut seed);

    let fake_random = jls_build_fake_random(&user, &seed, &auth_data, &mut rand::rng()).expect("build fake random");
    assert!(jls_check_fake_random(&user, &fake_random, &auth_data));

    let wrong_user = JlsUser { username: "alice".to_owned(), password: "not-the-password".to_owned() };
    assert!(!jls_check_fake_random(&wrong_user, &fake_random, &auth_data));
}

/// Pinned vector for the AEAD construction: AES-256-GCM with a 32-byte nonce
/// sealing the 16-byte seed under a key and nonce derived as `sha256` of the
/// username/password and the auth data. The expected ciphertext below was
/// produced by that construction and keeps the nonce derivation honest.
#[test]
fn gcm_32_byte_nonce_matches_the_cross_check_vector() {
    let user = JlsUser { username: "alice".to_owned(), password: "s3cret".to_owned() };
    let auth_data = b"hello-auth-data-example".to_vec();
    let mut seed = [0u8; RANDOM_SEED_LEN];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8;
    }

    // Deterministic RNG stand-in: the vector's seed never lands on a
    // forbidden suffix, so `jls_build_fake_random` never redraws and the
    // supplied RNG is never actually consulted.
    struct NeverCalled;
    impl RngCore for NeverCalled {
        fn next_u32(&mut self) -> u32 {
            unreachable!("jls_build_fake_random should not redraw for this vector")
        }
        fn next_u64(&mut self) -> u64 {
            unreachable!("jls_build_fake_random should not redraw for this vector")
        }
        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            unreachable!("jls_build_fake_random should not redraw for this vector")
        }
    }

    let fake_random = jls_build_fake_random(&user, &seed, &auth_data, &mut NeverCalled).expect("build fake random");
    let expected = hex_decode("d31af4ecc0fec2bfbd34d838eb59a82a0e1de98f5cc293e58f333608a9f3f087");
    assert_eq!(fake_random.to_vec(), expected);
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex in test vector")).collect()
}

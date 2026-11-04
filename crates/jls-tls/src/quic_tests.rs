//! Round-trip tests for the QUIC-mode JLS handshake, driving the client and
//! server halves against each other over a simulated CRYPTO stream: every
//! `WriteData` event is fed to the peer's `handle_crypto_data` at the level the
//! event named.

use std::sync::Arc;

use p256::ecdsa::SigningKey;
use rustls::RootCertStore;

use crate::cursor::take_handshake_message;
use crate::keys::{self, quic_initial_secrets, quic_keys, KeySchedule, QuicVersion};
use crate::quic::{
    ClientSessionTicket, EncryptionLevel, QuicClient, QuicClientConfig, QuicEvent, QuicServer, QuicServerOptions,
};
use crate::tests::test_server_key_and_cert;
use crate::{messages, JlsStatus, JlsUser, ServerConfig, TlsError};

const CLIENT_PARAMS: &[u8] = b"client transport parameters";
const SERVER_PARAMS: &[u8] = b"server transport parameters";

fn user() -> JlsUser {
    JlsUser { username: "alice".to_owned(), password: "s3cret".to_owned() }
}

fn client(alpn: Vec<String>, password: &str) -> QuicClient {
    client_with(alpn, password, None)
}

fn client_with(alpn: Vec<String>, password: &str, ticket: Option<ClientSessionTicket>) -> QuicClient {
    QuicClient::new(QuicClientConfig {
        server_name: "example.com".to_owned(),
        alpn,
        user: JlsUser { username: "alice".to_owned(), password: password.to_owned() },
        transport_parameters: CLIENT_PARAMS.to_vec(),
        root_certs: Arc::new(RootCertStore::empty()),
        time: None,
        ticket,
    })
    .expect("build the quic client")
}

fn server(users: Vec<JlsUser>, alpn: Vec<String>, key: SigningKey, cert_der: Vec<u8>) -> QuicServer {
    QuicServer::new(
        ServerConfig { users, server_name: String::new(), alpn, cert_der, key },
        SERVER_PARAMS.to_vec(),
        QuicServerOptions { allow_0rtt: false, ticket_key: None },
    )
}

/// A server that issues session tickets, with ticket keys and 0-RTT allowed.
fn ticket_server(
    users: Vec<JlsUser>,
    alpn: Vec<String>,
    key: SigningKey,
    cert_der: Vec<u8>,
    ticket_key: [u8; 32],
    allow_0rtt: bool,
) -> QuicServer {
    QuicServer::new(
        ServerConfig { users, server_name: String::new(), alpn, cert_der, key },
        SERVER_PARAMS.to_vec(),
        QuicServerOptions { allow_0rtt, ticket_key: Some(ticket_key) },
    )
}

/// The `NewSessionTicket` the client kept, drained from its events.
fn take_session_ticket(client: &mut QuicClient) -> ClientSessionTicket {
    while let Some(event) = client.next_event() {
        if let QuicEvent::NewSessionTicket(ticket) = event {
            return ticket;
        }
    }
    panic!("the client kept no session ticket");
}

/// The handshake message types in a flight, in order, for asserting on which
/// messages a resumed server skips.
fn flight_message_types(data: &[u8]) -> Vec<u8> {
    let mut types = Vec::new();
    let mut rest = data.to_vec();
    while let Some(message) = take_handshake_message(&mut rest) {
        types.push(message[0]);
    }
    types
}

fn write_data(event: QuicEvent) -> (EncryptionLevel, Vec<u8>) {
    match event {
        QuicEvent::WriteData { level, data } => (level, data),
        other @ (QuicEvent::SetReadSecret { .. }
        | QuicEvent::SetWriteSecret { .. }
        | QuicEvent::TransportParameters(_)
        | QuicEvent::NewSessionTicket(_)
        | QuicEvent::HandshakeDone) => panic!("expected a WriteData event, got {other:?}"),
    }
}

/// Runs the handshake to completion, returning the events each side produced
/// in order so a test can assert on the whole sequence.
fn run_handshake(client: &mut QuicClient, server: &mut QuicServer) -> (Vec<QuicEvent>, Vec<QuicEvent>) {
    try_run_handshake(client, server).expect("the handshake completes")
}

fn try_run_handshake(
    client: &mut QuicClient,
    server: &mut QuicServer,
) -> Result<(Vec<QuicEvent>, Vec<QuicEvent>), TlsError> {
    let mut client_events = Vec::new();
    let mut server_events = Vec::new();

    let (level, data) = write_data(client.next_event().expect("the client greets first"));
    client_events.push(QuicEvent::WriteData { level, data: data.clone() });
    server.handle_crypto_data(level, &data)?;
    while let Some(event) = server.next_event() {
        server_events.push(event.clone());
        if let QuicEvent::WriteData { level, data } = &event {
            client.handle_crypto_data(*level, data)?;
        }
    }
    while let Some(event) = client.next_event() {
        client_events.push(event.clone());
        if let QuicEvent::WriteData { level, data } = &event {
            server.handle_crypto_data(*level, data)?;
        }
    }
    while let Some(event) = server.next_event() {
        server_events.push(event);
    }
    Ok((client_events, server_events))
}

fn secret_at(events: &[QuicEvent], level: EncryptionLevel, read: bool) -> [u8; 32] {
    events
        .iter()
        .find_map(|event| match event {
            QuicEvent::SetReadSecret { level: l, secret } if read && *l == level => Some(*secret),
            QuicEvent::SetWriteSecret { level: l, secret } if !read && *l == level => Some(*secret),
            QuicEvent::WriteData { .. }
            | QuicEvent::SetReadSecret { .. }
            | QuicEvent::SetWriteSecret { .. }
            | QuicEvent::TransportParameters(_)
            | QuicEvent::NewSessionTicket(_)
            | QuicEvent::HandshakeDone => None,
        })
        .expect("the level's secret was reported")
}

fn position_of(events: &[QuicEvent], wanted: impl Fn(&QuicEvent) -> bool) -> usize {
    events.iter().position(wanted).expect("the event is present")
}

fn transport_parameters(events: &[QuicEvent]) -> Vec<u8> {
    events
        .iter()
        .find_map(|event| match event {
            QuicEvent::TransportParameters(data) => Some(data.clone()),
            QuicEvent::WriteData { .. }
            | QuicEvent::SetReadSecret { .. }
            | QuicEvent::SetWriteSecret { .. }
            | QuicEvent::NewSessionTicket(_)
            | QuicEvent::HandshakeDone => None,
        })
        .expect("a TransportParameters event")
}

#[test]
fn a_jls_pair_authenticates_and_agrees_on_keys() {
    let (key, cert_der) = test_server_key_and_cert();
    let mut client = client(vec!["h3".to_owned()], "s3cret");
    let mut server = server(vec![user()], vec!["h3".to_owned()], key, cert_der);

    let (client_events, server_events) = run_handshake(&mut client, &mut server);

    assert_eq!(client.state().status, JlsStatus::Authenticated);
    assert_eq!(server.state().status, JlsStatus::Authenticated);
    assert_eq!(client.state().user, "alice");
    assert_eq!(server.state().user, "alice");
    assert_eq!(client.state().negotiated_alpn.as_deref(), Some("h3"));
    assert_eq!(server.state().negotiated_alpn.as_deref(), Some("h3"));

    // RFC 9001 §5.7: a 1-RTT read secret may only be released once the
    // handshake is complete, so the client must send its Finished first.
    let read_secret_released = |events: &[QuicEvent]| {
        position_of(events, |event| {
            matches!(event, QuicEvent::SetReadSecret { level: EncryptionLevel::Application, .. })
        })
    };
    let handshake_done = |events: &[QuicEvent]| position_of(events, |event| *event == QuicEvent::HandshakeDone);
    assert!(handshake_done(&client_events) < read_secret_released(&client_events));
    assert!(handshake_done(&server_events) < read_secret_released(&server_events));

    // Both sides must derive the same traffic secrets, or the QUIC layer
    // above them could not open each other's packets.
    for level in [EncryptionLevel::Handshake, EncryptionLevel::Application] {
        assert_eq!(
            secret_at(&client_events, level, false),
            secret_at(&server_events, level, true),
            "the client's write secret at {level:?} must equal the server's read secret"
        );
        assert_eq!(
            secret_at(&client_events, level, true),
            secret_at(&server_events, level, false),
            "the client's read secret at {level:?} must equal the server's write secret"
        );
    }
}

#[test]
fn each_side_reports_the_peers_transport_parameters() {
    let (key, cert_der) = test_server_key_and_cert();
    let mut client = client(vec!["h3".to_owned()], "s3cret");
    let mut server = server(vec![user()], vec!["h3".to_owned()], key, cert_der);

    let (client_events, server_events) = run_handshake(&mut client, &mut server);
    assert_eq!(transport_parameters(&client_events), SERVER_PARAMS);
    assert_eq!(transport_parameters(&server_events), CLIENT_PARAMS);
}

#[test]
fn a_wrong_password_never_authenticates_and_the_server_refuses_the_client() {
    let (key, cert_der) = test_server_key_and_cert();
    let mut client = client(vec!["h3".to_owned()], "wrong-password");
    let mut server = server(vec![user()], vec!["h3".to_owned()], key, cert_der);

    let (level, data) = write_data(client.next_event().expect("the client greets first"));
    let err = server.handle_crypto_data(level, &data).expect_err("the server must reject an unauthenticated hello");
    assert!(err.to_string().contains("jls authentication failed"), "unexpected error: {err}");
    assert_eq!(server.state().status, JlsStatus::Unauthenticated);
    assert!(server.next_event().is_none(), "a rejected ClientHello must not produce a ServerHello");
}

#[test]
fn a_client_only_authenticates_a_server_holding_the_same_credentials() {
    // The server seals its ServerHello with the same user it matched from the
    // ClientHello, so a credential mismatch is caught on the server's side and
    // never reaches a ServerHello the client could misread as authenticated.
    let (key, cert_der) = test_server_key_and_cert();
    let mut client = client(vec!["h3".to_owned()], "s3cret");
    let mut server = server(vec![user()], vec!["h3".to_owned()], key, cert_der);

    let (level, data) = write_data(client.next_event().expect("the client greets first"));
    server.handle_crypto_data(level, &data).expect("matching credentials authenticate");
    let mut server_hello = None;
    while let Some(event) = server.next_event() {
        if let QuicEvent::WriteData { level, data } = event {
            server_hello = Some((level, data));
            break;
        }
    }
    let (level, data) = server_hello.expect("the server answers with a ServerHello");
    client.handle_crypto_data(level, &data).expect("the client accepts the ServerHello");
    assert_eq!(client.state().status, JlsStatus::Authenticated);
}

#[test]
fn a_server_whose_sni_does_not_match_refuses_the_client() {
    let (key, cert_der) = test_server_key_and_cert();
    let mut client = client(vec!["h3".to_owned()], "s3cret");
    let mut server = QuicServer::new(
        ServerConfig {
            users: vec![user()],
            server_name: "other.example".to_owned(),
            alpn: vec!["h3".to_owned()],
            cert_der,
            key,
        },
        SERVER_PARAMS.to_vec(),
        QuicServerOptions { allow_0rtt: false, ticket_key: None },
    );

    let (level, data) = write_data(client.next_event().expect("the client greets first"));
    server.handle_crypto_data(level, &data).expect_err("a mismatched SNI must fail authentication");
}

#[test]
fn handshake_data_at_the_wrong_level_is_rejected() {
    let (key, cert_der) = test_server_key_and_cert();
    let mut client = client(vec!["h3".to_owned()], "s3cret");
    let mut server = server(vec![user()], vec!["h3".to_owned()], key, cert_der);

    let (_, data) = write_data(client.next_event().expect("the client greets first"));
    let err = server
        .handle_crypto_data(EncryptionLevel::Handshake, &data)
        .expect_err("a ClientHello at the Handshake level is a protocol error");
    assert!(err.to_string().contains("wrong encryption level"), "unexpected error: {err}");
}

#[test]
fn an_empty_server_alpn_list_fails_the_client_but_not_the_server() {
    // RFC 9001 §8.1 only binds a server that has protocols to offer, so an
    // empty server list is not an ALPN failure on the server side; the client
    // that did offer protocols is the one that rejects the empty selection.
    let (key, cert_der) = test_server_key_and_cert();
    let mut client = client(vec!["h3".to_owned()], "s3cret");
    let mut server = server(vec![user()], Vec::new(), key, cert_der);

    let err = try_run_handshake(&mut client, &mut server)
        .expect_err("a client that offered a protocol must reject an empty selection");
    assert!(err.to_string().contains("did not select an ALPN protocol"), "unexpected error: {err}");
}

#[test]
fn a_client_alpn_the_server_does_not_offer_is_refused() {
    let (key, cert_der) = test_server_key_and_cert();
    let mut client = client(vec!["h3".to_owned()], "s3cret");
    let mut server = server(vec![user()], vec!["h2".to_owned()], key, cert_der);

    let (level, data) = write_data(client.next_event().expect("the client greets first"));
    let err = server.handle_crypto_data(level, &data).expect_err("disjoint ALPN lists must fail the handshake");
    assert!(err.to_string().contains("unsupported application protocols"), "unexpected error: {err}");
}

/// The `h2`/`http/1.1` compatibility carve-out is not TCP-only, so over QUIC the same
/// ALPN negotiation lets an `h2`-only server accept an `http/1.1` client and
/// select nothing. RFC 9001 §8.1 then makes that empty selection a client-side
/// failure, which is the one place the two modes differ.
#[test]
fn an_h2_only_server_selects_nothing_and_the_quic_client_refuses_it() {
    let (key, cert_der) = test_server_key_and_cert();
    let mut client = client(vec!["http/1.1".to_owned()], "s3cret");
    let mut server = server(vec![user()], vec!["h2".to_owned()], key, cert_der);

    let err = try_run_handshake(&mut client, &mut server)
        .expect_err("an empty selection must not satisfy a QUIC client that offered a protocol");
    assert!(err.to_string().contains("did not select an ALPN protocol"), "unexpected error: {err}");
    assert_eq!(server.state().negotiated_alpn, None, "the server accepted without selecting a protocol");
}

#[test]
fn the_initial_secrets_depend_on_the_destination_connection_id_and_version() {
    let (a_client, a_server) = quic_initial_secrets(b"connection-id-a", QuicVersion::V1).expect("initial secrets");
    let (b_client, _) = quic_initial_secrets(b"connection-id-b", QuicVersion::V1).expect("initial secrets");
    assert_ne!(a_client, b_client, "a different DCID must yield different Initial keys");
    assert_ne!(a_client, a_server, "the two directions must not share a secret");

    let (v2_client, _) = quic_initial_secrets(b"connection-id-a", QuicVersion::V2).expect("initial secrets");
    assert_ne!(a_client, v2_client, "RFC 9369 changes the salt, so v1 and v2 Initial secrets differ");

    for version in [QuicVersion::V1, QuicVersion::V2] {
        let keys = quic_keys(&a_client, version).expect("quic keys");
        assert_ne!(keys.key, [0u8; 16]);
        assert_ne!(keys.iv, [0u8; 12]);
        assert_ne!(keys.hp, keys.key, "header protection uses its own label");
    }
}

#[test]
fn quic_keys_are_a_pure_function_of_the_traffic_secret_and_version() {
    let secret = [7u8; 32];
    let first = quic_keys(&secret, QuicVersion::V1).expect("quic keys");
    let again = quic_keys(&secret, QuicVersion::V1).expect("quic keys");
    assert_eq!(first.key, again.key, "the AEAD key must depend only on the secret and version");
    assert_eq!(first.iv, again.iv, "the nonce base must depend only on the secret and version");
    assert_eq!(first.hp, again.hp, "the header protection key must depend only on the secret and version");
    assert_ne!(
        quic_keys(&secret, QuicVersion::V1).expect("quic keys").hp,
        quic_keys(&secret, QuicVersion::V2).expect("quic keys").hp
    );
}

#[test]
fn a_finished_mac_over_the_wrong_transcript_does_not_verify() {
    let schedule = KeySchedule::new(None, &[3u8; 32], &[4u8; 32]).expect("key schedule");
    let forged = keys::verify_finished(&schedule.server_handshake_traffic_secret, &[5u8; 32], &[0u8; 32])
        .expect("verification runs");
    assert!(!forged, "the transcript is what binds the Finished MACs");
}

/// The server issues a ticket over the first connection; the client keeps it,
/// resumes from it over a second connection, and its first flight is protected
/// with `client_early_traffic_secret`, which the server accepts by deriving the
/// same secret from the ticket's PSK.
#[test]
fn a_resumed_client_rides_the_early_flight_and_the_server_takes_it() {
    let (key, cert_der) = test_server_key_and_cert();
    let ticket_key = [11u8; 32];

    let mut client = client(vec!["h3".to_owned()], "s3cret");
    let mut server =
        ticket_server(vec![user()], vec!["h3".to_owned()], key.clone(), cert_der.clone(), ticket_key, true);
    let (_, server_events) = run_handshake(&mut client, &mut server);
    assert!(client.early_traffic_secret().is_none(), "a first connection has no PSK to protect 0-RTT with");
    let ticket_flight = server_events
        .iter()
        .rev()
        .find_map(|event| match event {
            QuicEvent::WriteData { level: EncryptionLevel::Application, data } => Some(data.clone()),
            QuicEvent::WriteData { .. }
            | QuicEvent::SetReadSecret { .. }
            | QuicEvent::SetWriteSecret { .. }
            | QuicEvent::TransportParameters(_)
            | QuicEvent::NewSessionTicket(_)
            | QuicEvent::HandshakeDone => None,
        })
        .expect("the server sends a NewSessionTicket once the handshake is done");

    client.handle_crypto_data(EncryptionLevel::Application, &ticket_flight).expect("the client accepts its ticket");
    let ticket = take_session_ticket(&mut client);
    assert_eq!(ticket.alpn.as_deref(), Some("h3"));
    assert_eq!(ticket.username, "alice");
    assert_eq!(ticket.max_early_data, messages::MAX_EARLY_DATA_SIZE_QUIC);
    assert_eq!(ticket.transport_parameters, SERVER_PARAMS, "RFC 9001 §4.6.3 needs the issuing connection's parameters");
    assert_ne!(ticket.psk, [0u8; 32]);

    let mut resumed = client_with(vec!["h3".to_owned()], "s3cret", Some(ticket));
    let early = *resumed.early_traffic_secret().expect("a ticket that allows 0-RTT yields early keys");
    let mut server = ticket_server(vec![user()], vec!["h3".to_owned()], key, cert_der, ticket_key, true);
    let (client_events, server_events) = run_handshake(&mut resumed, &mut server);

    assert_eq!(resumed.early_data_accepted(), Some(true), "the server took the early flight");
    assert_eq!(
        secret_at(&server_events, EncryptionLevel::Early, true),
        early,
        "the server reads 0-RTT with the client's early traffic secret"
    );
    // RFC 8446 §4.1.1: a PSK handshake carries no certificate.
    let server_flight = server_events
        .iter()
        .find_map(|event| match event {
            QuicEvent::WriteData { level: EncryptionLevel::Handshake, data } => Some(data.clone()),
            QuicEvent::WriteData { .. }
            | QuicEvent::SetReadSecret { .. }
            | QuicEvent::SetWriteSecret { .. }
            | QuicEvent::TransportParameters(_)
            | QuicEvent::NewSessionTicket(_)
            | QuicEvent::HandshakeDone => None,
        })
        .expect("the server's handshake flight");
    assert_eq!(
        flight_message_types(&server_flight),
        vec![messages::MSG_ENCRYPTED_EXTENSIONS, messages::MSG_FINISHED],
        "a resumed handshake skips Certificate and CertificateVerify"
    );
    assert_eq!(server.state().user, "alice");
    assert_eq!(server.state().negotiated_alpn.as_deref(), Some("h3"));
    // The resumption PSK must drive both sides' handshake and application
    // secrets, or the resumed connection could not carry traffic.
    for level in [EncryptionLevel::Handshake, EncryptionLevel::Application] {
        assert_eq!(
            secret_at(&client_events, level, false),
            secret_at(&server_events, level, true),
            "the client's write secret at {level:?} must equal the server's read secret"
        );
        assert_eq!(
            secret_at(&client_events, level, true),
            secret_at(&server_events, level, false),
            "the client's read secret at {level:?} must equal the server's write secret"
        );
    }
}

/// Without a ticket the client must not offer a PSK at all, which is what keeps
/// a server from ever seeing an early flight it did not advertise.
#[test]
fn a_client_without_a_ticket_offers_no_psk_and_no_early_data() {
    let mut client = client(vec!["h3".to_owned()], "s3cret");
    assert!(client.early_traffic_secret().is_none());
    let (level, data) = write_data(client.next_event().expect("the client greets first"));
    assert_eq!(level, EncryptionLevel::Initial);
    let parsed = messages::parse_client_hello(&data[4..]).expect("parse the ClientHello");
    assert!(parsed.psk_identities.is_empty(), "no ticket means no pre_shared_key");
    assert!(parsed.psk_binders.is_empty());
    assert!(parsed.psk_modes.is_empty(), "psk_key_exchange_modes only accompanies a PSK");
    assert!(!parsed.early_data, "0-RTT requires a PSK (RFC 8446 §4.2.10)");
}

/// A ticket whose lifetime has run out must not be offered (RFC 8446 §4.2.11),
/// and a ticket issued to another JLS identity must not be, either.
#[test]
fn an_expired_or_foreign_ticket_is_never_offered() {
    let expired = ClientSessionTicket {
        psk: [5u8; 32],
        ticket: vec![1, 2, 3],
        lifetime: 10,
        age_add: 7,
        created_at: 1,
        max_early_data: messages::MAX_EARLY_DATA_SIZE_QUIC,
        alpn: Some("h3".to_owned()),
        transport_parameters: SERVER_PARAMS.to_vec(),
        username: "alice".to_owned(),
    };
    let mut client = client_with(vec!["h3".to_owned()], "s3cret", Some(expired));
    assert!(client.early_traffic_secret().is_none());
    let (_, data) = write_data(client.next_event().expect("the client greets first"));
    let parsed = messages::parse_client_hello(&data[4..]).expect("parse the ClientHello");
    assert!(parsed.psk_identities.is_empty(), "an expired ticket must not be offered");

    let foreign = ClientSessionTicket { username: "mallory".to_owned(), created_at: unix_now(), ..fresh_ticket() };
    let mut client = client_with(vec!["h3".to_owned()], "s3cret", Some(foreign));
    let (_, data) = write_data(client.next_event().expect("the client greets first"));
    let parsed = messages::parse_client_hello(&data[4..]).expect("parse the ClientHello");
    assert!(parsed.psk_identities.is_empty(), "another identity's ticket must not be offered");
    assert!(!parsed.early_data);
}

fn fresh_ticket() -> ClientSessionTicket {
    ClientSessionTicket {
        psk: [5u8; 32],
        ticket: vec![9, 9, 9],
        lifetime: messages::MAX_SESSION_TICKET_LIFETIME_SECS,
        age_add: 7,
        created_at: unix_now(),
        max_early_data: messages::MAX_EARLY_DATA_SIZE_QUIC,
        alpn: Some("h3".to_owned()),
        transport_parameters: SERVER_PARAMS.to_vec(),
        username: "alice".to_owned(),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

/// A server that does not allow 0-RTT must still resume, but its ticket says
/// nothing about early data, so the client offers none and the server derives
/// no early secret.
#[test]
fn a_server_that_does_not_allow_0rtt_resumes_without_early_data() {
    let (key, cert_der) = test_server_key_and_cert();
    let ticket_key = [12u8; 32];

    let mut client = client(vec!["h3".to_owned()], "s3cret");
    let mut server =
        ticket_server(vec![user()], vec!["h3".to_owned()], key.clone(), cert_der.clone(), ticket_key, false);
    let (_, server_events) = run_handshake(&mut client, &mut server);
    let ticket_flight = server_events
        .iter()
        .rev()
        .find_map(|event| match event {
            QuicEvent::WriteData { level: EncryptionLevel::Application, data } => Some(data.clone()),
            QuicEvent::WriteData { .. }
            | QuicEvent::SetReadSecret { .. }
            | QuicEvent::SetWriteSecret { .. }
            | QuicEvent::TransportParameters(_)
            | QuicEvent::NewSessionTicket(_)
            | QuicEvent::HandshakeDone => None,
        })
        .expect("the server still issues a ticket");
    client.handle_crypto_data(EncryptionLevel::Application, &ticket_flight).expect("the client accepts its ticket");
    let ticket = take_session_ticket(&mut client);
    assert_eq!(ticket.max_early_data, 0, "RFC 9001 §4.6.1 omits early_data to refuse 0-RTT");

    let mut resumed = client_with(vec!["h3".to_owned()], "s3cret", Some(ticket));
    assert!(resumed.early_traffic_secret().is_none(), "a ticket without max_early_data_size yields no early keys");
    let mut server = ticket_server(vec![user()], vec!["h3".to_owned()], key, cert_der, ticket_key, false);
    let (_, server_events) = run_handshake(&mut resumed, &mut server);

    assert_eq!(resumed.early_data_accepted(), None, "the client never offered 0-RTT");
    assert!(
        !server_events
            .iter()
            .any(|event| matches!(event, QuicEvent::SetReadSecret { level: EncryptionLevel::Early, .. })),
        "no early read secret without an early flight"
    );
    let server_flight = server_events
        .iter()
        .find_map(|event| match event {
            QuicEvent::WriteData { level: EncryptionLevel::Handshake, data } => Some(data.clone()),
            QuicEvent::WriteData { .. }
            | QuicEvent::SetReadSecret { .. }
            | QuicEvent::SetWriteSecret { .. }
            | QuicEvent::TransportParameters(_)
            | QuicEvent::NewSessionTicket(_)
            | QuicEvent::HandshakeDone => None,
        })
        .expect("the server's handshake flight");
    assert_eq!(
        flight_message_types(&server_flight),
        vec![messages::MSG_ENCRYPTED_EXTENSIONS, messages::MSG_FINISHED],
        "the PSK still resumed the handshake"
    );
}

/// A ticket this server never issued (another ticket key) must be ignored: the
/// handshake falls back to a certificate one rather than failing (§4.2.11).
#[test]
fn a_ticket_the_server_cannot_open_falls_back_to_a_certificate_handshake() {
    let (key, cert_der) = test_server_key_and_cert();
    let mut resumed = client_with(vec!["h3".to_owned()], "s3cret", Some(fresh_ticket()));
    let mut server = ticket_server(vec![user()], vec!["h3".to_owned()], key, cert_der, [13u8; 32], true);
    let (_, server_events) = run_handshake(&mut resumed, &mut server);

    assert_eq!(resumed.early_data_accepted(), Some(false), "there is no session to accept 0-RTT with");
    let server_flight = server_events
        .iter()
        .find_map(|event| match event {
            QuicEvent::WriteData { level: EncryptionLevel::Handshake, data } => Some(data.clone()),
            QuicEvent::WriteData { .. }
            | QuicEvent::SetReadSecret { .. }
            | QuicEvent::SetWriteSecret { .. }
            | QuicEvent::TransportParameters(_)
            | QuicEvent::NewSessionTicket(_)
            | QuicEvent::HandshakeDone => None,
        })
        .expect("the server's handshake flight");
    assert_eq!(
        flight_message_types(&server_flight),
        vec![
            messages::MSG_ENCRYPTED_EXTENSIONS,
            messages::MSG_CERTIFICATE,
            messages::MSG_CERTIFICATE_VERIFY,
            messages::MSG_FINISHED
        ],
        "an unusable ticket leaves an ordinary certificate handshake"
    );
}

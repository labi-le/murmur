//! QUIC-mode TLS 1.3 handshake carrying JLS authentication, with the
//! QUIC-specific branches of the TLS 1.3 client and server handshakes.
//!
//! The transport is the QUIC CRYPTO stream, not a byte stream: there is no
//! record layer and no `ChangeCipherSpec` (RFC 9001 §4.1.2), handshake bytes
//! are addressed by encryption level instead, and the QUIC layer owns packet
//! protection, taking the traffic secrets this module hands it. JLS itself is
//! unchanged from stream mode: the same credentials seal the `ClientHello`
//! random and the same credentials authenticate the `ServerHello` random.
//!
//! One behavioural difference from TCP mode follows from the transport: a JLS
//! fallback is never available in QUIC mode, so a failed JLS authentication is a
//! handshake error here rather than a relay to a fallback destination.

use std::collections::VecDeque;
use std::sync::Arc;

use p256::ecdsa::signature::Signer;
use rand::RngCore;
use rustls::RootCertStore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::client::check_alpn;
use crate::cursor::{split_handshake_message, take_handshake_message};
use crate::error::{Result, TlsError};
use crate::jls::{self, RANDOM_SEED_LEN};
use crate::keys::{self, KeySchedule};
use crate::messages::{self, ClientHelloParams, ClientHelloPsk};
use crate::server::negotiate_alpn;
use crate::ticket;
use crate::transcript::Transcript;
use crate::x509;
use crate::{JlsConnectionState, JlsStatus, JlsUser, ServerConfig, TimeFn};

/// A QUIC encryption level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionLevel {
    /// The 0-RTT level, whose keys come from
    /// the resumption PSK rather than from the handshake.
    Early,
    Initial,
    Handshake,
    Application,
}

/// A `NewSessionTicket` the client kept, in the shape a resume needs.
///
/// It carries the resumption PSK of RFC 8446 §4.6.1 plus every ticket field
/// §4.2.11 requires the client to echo, and the server's transport parameters
/// so `quinn` can evaluate the resumed connection (RFC 9001 §4.6.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSessionTicket {
    pub psk: [u8; 32],
    /// The ticket field, echoed as the PSK identity.
    pub ticket: Vec<u8>,
    pub lifetime: u32,
    pub age_add: u32,
    /// Seconds since the Unix epoch at which the client received the ticket,
    /// the start of the age in §4.2.11.
    pub created_at: u64,
    pub max_early_data: u32,
    pub alpn: Option<String>,
    pub transport_parameters: Vec<u8>,
    /// The JLS identity the ticket was issued to.
    pub username: String,
}

/// Client-side configuration for [`QuicClient`].
pub struct QuicClientConfig {
    pub server_name: String,
    pub alpn: Vec<String>,
    pub user: JlsUser,
    /// RFC 9000 transport parameters, sent in the mandatory
    /// `quic_transport_parameters` extension.
    pub transport_parameters: Vec<u8>,
    /// The trust anchors, as in [`crate::ClientConfig::root_certs`].
    pub root_certs: Arc<RootCertStore>,
    /// The time source, as in [`crate::ClientConfig::time`].
    pub time: Option<TimeFn>,
    /// The session a previous connection left, `Some` to attempt resumption.
    pub ticket: Option<ClientSessionTicket>,
}

impl core::fmt::Debug for QuicClientConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QuicClientConfig")
            .field("server_name", &self.server_name)
            .field("alpn", &self.alpn)
            .field("transport_parameters", &self.transport_parameters)
            .field("resuming", &self.ticket.is_some())
            .finish_non_exhaustive()
    }
}

/// What the QUIC layer is told to do next.
///
/// `SetReadSecret`/`SetWriteSecret` carry a TLS traffic secret, which the QUIC
/// layer expands into packet keys with [`crate::quic_keys`]. Initial secrets
/// are not reported because both peers derive them from the destination
/// connection ID independently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuicEvent {
    /// Handshake bytes to send in CRYPTO frames at `level`.
    WriteData {
        level: EncryptionLevel,
        data: Vec<u8>,
    },
    SetReadSecret {
        level: EncryptionLevel,
        secret: [u8; 32],
    },
    SetWriteSecret {
        level: EncryptionLevel,
        secret: [u8; 32],
    },
    /// The peer's RFC 9000 transport parameters.
    TransportParameters(Vec<u8>),
    /// A `NewSessionTicket` the client should keep for the next connection.
    NewSessionTicket(ClientSessionTicket),
    HandshakeDone,
}

enum ClientState {
    AwaitServerHello,
    AwaitEncryptedExtensions,
    AwaitCertificate,
    AwaitCertificateVerify,
    AwaitFinished,
    Done,
}

/// The client half of a JLS-authenticated QUIC TLS handshake.
pub struct QuicClient {
    config: QuicClientConfig,
    client_secret: StaticSecret,
    legacy_session_id: [u8; 32],
    transcript: Transcript,
    key_schedule: Option<KeySchedule>,
    peer_chain: Option<Vec<Vec<u8>>>,
    hash_through_certificate: Option<[u8; 32]>,
    read_level: EncryptionLevel,
    incoming: Vec<u8>,
    state: ClientState,
    events: VecDeque<QuicEvent>,
    jls_state: JlsConnectionState,
    /// The PSK offered in this `ClientHello`, if the config carried a usable
    /// ticket.
    psk: Option<[u8; 32]>,
    using_psk: bool,
    early_data_offered: bool,
    /// `None` until the server's `EncryptedExtensions` says whether it took
    /// the early flight.
    early_data_accepted: Option<bool>,
    /// The ALPN recorded with the ticket, which RFC 8446 §4.2.10 requires the
    /// resumed connection to keep for 0-RTT to be accepted.
    ticket_alpn: Option<String>,
    early_traffic_secret: Option<[u8; 32]>,
    server_transport_parameters: Vec<u8>,
}

impl core::fmt::Debug for QuicClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QuicClient")
            .field("config", &self.config)
            .field("read_level", &self.read_level)
            .field("jls_state", &self.jls_state)
            .field("using_psk", &self.using_psk)
            .field("early_data_offered", &self.early_data_offered)
            .field("queued_events", &self.events.len())
            .finish_non_exhaustive()
    }
}

impl QuicClient {
    /// Builds the `ClientHello` and queues it for the Initial encryption
    /// level. The JLS `FakeRandom` is sealed into the random field of exactly
    /// the hello that goes out, so the auth data is computed from a
    /// placeholder carrying a zeroed random.
    pub fn new(config: QuicClientConfig) -> Result<Self> {
        if config.server_name.is_empty() {
            return Err(TlsError::protocol("quic client: server name is required"));
        }
        let mut secret_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut secret_bytes);
        let client_secret = StaticSecret::from(secret_bytes);
        let client_public = PublicKey::from(&client_secret);

        let mut legacy_session_id = [0u8; 32];
        rand::rng().fill_bytes(&mut legacy_session_id);
        let mut random_seed = [0u8; RANDOM_SEED_LEN];
        rand::rng().fill_bytes(&mut random_seed);

        let now = unix_now();
        let ticket = config.ticket.clone().filter(|ticket| {
            // A session whose JLS identity is not this connection's is not
            // resumed.
            ticket.username == config.user.username
                && ticket.lifetime != 0
                && ticket.lifetime <= messages::MAX_SESSION_TICKET_LIFETIME_SECS
                && now < ticket.created_at + u64::from(ticket.lifetime)
        });
        let psk = ticket.as_ref().map(|ticket| ticket.psk);
        let early_data_offered = ticket.as_ref().is_some_and(|ticket| {
            ticket.max_early_data == messages::MAX_EARLY_DATA_SIZE_QUIC
                && ticket.alpn.as_ref().is_some_and(|alpn| config.alpn.contains(alpn))
        });
        let obfuscated_ticket_age = ticket.as_ref().map_or(0, |ticket| {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the wire field is 32 bits by definition: RFC 8446 §4.2.11.1 takes the age modulo 2^32"
            )]
            let age_ms = ((now - ticket.created_at) * 1000) as u32;
            age_ms + ticket.age_add
        });
        let psk_offer = ticket.as_ref().map(|ticket| ClientHelloPsk {
            identity: &ticket.ticket,
            obfuscated_ticket_age,
            binder: &[0u8; 32],
        });

        let client_hello = client_hello_flight(
            &config,
            &legacy_session_id,
            client_public.as_bytes(),
            &random_seed,
            psk,
            early_data_offered,
            psk_offer,
        )?;

        let mut transcript = Transcript::new();
        transcript.update(&client_hello);

        let mut events = VecDeque::new();
        events.push_back(QuicEvent::WriteData { level: EncryptionLevel::Initial, data: client_hello });
        let early_traffic_secret = match (&psk, early_data_offered) {
            (Some(psk), true) => {
                let secret = keys::client_early_traffic_secret(psk, &transcript.hash())?;
                events.push_back(QuicEvent::SetWriteSecret { level: EncryptionLevel::Early, secret });
                Some(secret)
            }
            _ => None,
        };

        Ok(Self {
            jls_state: JlsConnectionState {
                status: JlsStatus::Unauthenticated,
                negotiated_alpn: None,
                user: config.user.username.clone(),
            },
            ticket_alpn: ticket.as_ref().and_then(|ticket| ticket.alpn.clone()),
            config,
            client_secret,
            legacy_session_id,
            transcript,
            key_schedule: None,
            peer_chain: None,
            hash_through_certificate: None,
            read_level: EncryptionLevel::Initial,
            incoming: Vec::new(),
            state: ClientState::AwaitServerHello,
            events,
            psk,
            using_psk: false,
            early_data_offered,
            early_data_accepted: early_data_offered.then_some(false),
            early_traffic_secret,
            server_transport_parameters: Vec::new(),
        })
    }

    /// The secret the client's 0-RTT packets are protected with, once a ticket
    /// with `max_early_data_size` allowed one. `quinn` expands it into the
    /// early write keys before any handshake byte arrives.
    #[must_use]
    pub const fn early_traffic_secret(&self) -> Option<&[u8; 32]> {
        self.early_traffic_secret.as_ref()
    }

    /// Whether the server took the early flight, valid once the
    /// `EncryptedExtensions` arrived.
    #[must_use]
    pub const fn early_data_accepted(&self) -> Option<bool> {
        self.early_data_accepted
    }

    /// The transport parameters a resumed session must reuse for 0-RTT
    /// (RFC 9001 §4.6.3).
    #[must_use]
    pub fn ticket_transport_parameters(&self) -> Option<&[u8]> {
        self.config.ticket.as_ref().map(|ticket| ticket.transport_parameters.as_slice())
    }

    /// Drains the events queued so far; `None` once the handshake has
    /// completed and nothing is left to report.
    pub fn next_event(&mut self) -> Option<QuicEvent> {
        self.events.pop_front()
    }

    /// The JLS authentication outcome, valid once the handshake has completed.
    #[must_use]
    pub const fn state(&self) -> &JlsConnectionState {
        &self.jls_state
    }

    /// Feeds handshake bytes received from the peer's CRYPTO stream.
    pub fn handle_crypto_data(&mut self, level: EncryptionLevel, data: &[u8]) -> Result<()> {
        if level != self.read_level {
            return Err(TlsError::protocol("quic client: handshake data received at wrong encryption level"));
        }
        self.incoming.extend_from_slice(data);
        while let Some(raw) = take_handshake_message(&mut self.incoming) {
            match self.state {
                ClientState::AwaitServerHello => self.state = self.handle_server_hello(&raw)?,
                ClientState::AwaitEncryptedExtensions => self.state = self.handle_encrypted_extensions(&raw)?,
                ClientState::AwaitCertificate => self.state = self.handle_certificate(&raw)?,
                ClientState::AwaitCertificateVerify => self.state = self.handle_certificate_verify(&raw)?,
                ClientState::AwaitFinished => self.state = self.handle_server_finished(&raw)?,
                ClientState::Done => self.handle_post_handshake(&raw)?,
            }
        }
        Ok(())
    }

    fn handle_server_hello(&mut self, raw: &[u8]) -> Result<ClientState> {
        let (msg_type, body) = split_handshake_message(raw)?;
        if msg_type != messages::MSG_SERVER_HELLO {
            return Err(TlsError::protocol("quic client: expected ServerHello"));
        }
        let server_hello = messages::parse_server_hello(body)?;
        if server_hello.legacy_session_id_echo != self.legacy_session_id {
            return Err(TlsError::protocol("quic client: server did not echo legacy_session_id"));
        }
        // RFC 8446 §4.2.11: an accepted PSK must be one the client offered.
        self.using_psk = match server_hello.selected_identity {
            Some(index) if self.psk.is_some() && index == 0 => true,
            Some(_) => return Err(TlsError::protocol("quic client: server selected an invalid PSK")),
            None => false,
        };

        let server_auth_data = jls::jls_server_hello_auth_data(raw)?;
        self.jls_state.status =
            if jls::jls_check_fake_random(&self.config.user, &server_hello.random, &server_auth_data) {
                JlsStatus::Authenticated
            } else {
                JlsStatus::Unauthenticated
            };
        self.transcript.update(raw);

        let shared_secret = self.client_secret.diffie_hellman(&PublicKey::from(server_hello.x25519_public));
        let psk = if self.using_psk { self.psk } else { None };
        let schedule = KeySchedule::new(psk.as_ref(), shared_secret.as_bytes(), &self.transcript.hash())?;
        self.events.push_back(QuicEvent::SetWriteSecret {
            level: EncryptionLevel::Handshake,
            secret: schedule.client_handshake_traffic_secret,
        });
        self.events.push_back(QuicEvent::SetReadSecret {
            level: EncryptionLevel::Handshake,
            secret: schedule.server_handshake_traffic_secret,
        });
        self.key_schedule = Some(schedule);
        self.read_level = EncryptionLevel::Handshake;
        Ok(ClientState::AwaitEncryptedExtensions)
    }

    fn handle_encrypted_extensions(&mut self, raw: &[u8]) -> Result<ClientState> {
        let (msg_type, body) = split_handshake_message(raw)?;
        if msg_type != messages::MSG_ENCRYPTED_EXTENSIONS {
            return Err(TlsError::protocol("quic client: expected EncryptedExtensions"));
        }
        let ee = messages::parse_encrypted_extensions(body)?;
        check_alpn(&self.config.alpn, ee.alpn.as_deref(), true)?;
        self.jls_state.negotiated_alpn.clone_from(&ee.alpn);
        let Some(quic_params) = ee.quic_transport_parameters else {
            return Err(TlsError::protocol("quic client: server did not send a quic_transport_parameters extension"));
        };
        self.server_transport_parameters.clone_from(&quic_params);
        self.events.push_back(QuicEvent::TransportParameters(quic_params));
        // RFC 8446 §4.2.10: the server accepts 0-RTT by echoing the extension,
        // and only over the ALPN the ticket was issued for.
        if ee.early_data {
            if !self.early_data_offered {
                return Err(TlsError::protocol("quic client: server sent an unexpected early_data extension"));
            }
            if ee.alpn != self.ticket_alpn {
                return Err(TlsError::protocol("quic client: server accepted 0-RTT with the wrong ALPN"));
            }
            self.early_data_accepted = Some(true);
        } else if self.early_data_offered {
            self.early_data_accepted = Some(false);
        }
        self.transcript.update(raw);
        Ok(if self.using_psk { ClientState::AwaitFinished } else { ClientState::AwaitCertificate })
    }

    fn handle_certificate(&mut self, raw: &[u8]) -> Result<ClientState> {
        let (msg_type, body) = split_handshake_message(raw)?;
        if msg_type != messages::MSG_CERTIFICATE {
            return Err(TlsError::protocol("quic client: expected Certificate"));
        }
        self.peer_chain = Some(messages::parse_certificate_chain(body)?);
        self.transcript.update(raw);
        self.hash_through_certificate = Some(self.transcript.hash());
        Ok(ClientState::AwaitCertificateVerify)
    }

    fn handle_certificate_verify(&mut self, raw: &[u8]) -> Result<ClientState> {
        let (msg_type, body) = split_handshake_message(raw)?;
        if msg_type != messages::MSG_CERTIFICATE_VERIFY {
            return Err(TlsError::protocol("quic client: expected CertificateVerify"));
        }
        let signature_der = messages::parse_certificate_verify(body)?;
        let chain = self.peer_chain.as_deref().ok_or_else(|| TlsError::protocol("quic client: no Certificate seen"))?;
        let hash_through_certificate =
            self.hash_through_certificate.ok_or_else(|| TlsError::protocol("quic client: no Certificate seen"))?;
        // The camouflage certificate a JLS peer presents is self-signed by
        // construction, so only an unauthenticated peer is chain-verified.
        if self.jls_state.status != JlsStatus::Authenticated {
            x509::verify_server_chain(
                chain,
                &self.config.server_name,
                &self.config.root_certs,
                self.config.time.as_ref(),
            )?;
        }
        let leaf =
            chain.first().ok_or_else(|| TlsError::protocol("quic client: server sent an empty certificate list"))?;
        verify_certificate_signature(leaf, &signature_der, &hash_through_certificate)?;
        self.transcript.update(raw);
        Ok(ClientState::AwaitFinished)
    }

    fn handle_server_finished(&mut self, raw: &[u8]) -> Result<ClientState> {
        let (msg_type, body) = split_handshake_message(raw)?;
        if msg_type != messages::MSG_FINISHED {
            return Err(TlsError::protocol("quic client: expected Finished"));
        }
        let received = messages::parse_finished(body)?;
        let hash_before_finished = self.transcript.hash();
        let schedule = self.key_schedule.as_ref().ok_or_else(|| TlsError::protocol("quic client: no key schedule"))?;
        if !keys::verify_finished(&schedule.server_handshake_traffic_secret, &hash_before_finished, &received)? {
            return Err(TlsError::protocol("quic client: server Finished verify_data mismatch"));
        }
        self.transcript.update(raw);

        let schedule = self.key_schedule.as_mut().ok_or_else(|| TlsError::protocol("quic client: no key schedule"))?;
        schedule.derive_application_secrets(&self.transcript.hash())?;
        let client_verify_data =
            keys::compute_finished(&schedule.client_handshake_traffic_secret, &self.transcript.hash())?;
        let client_finished = messages::build_finished(&client_verify_data)?;
        self.transcript.update(&client_finished);
        schedule.derive_resumption_master_secret(&self.transcript.hash())?;

        self.events.push_back(QuicEvent::WriteData { level: EncryptionLevel::Handshake, data: client_finished });
        self.events.push_back(QuicEvent::SetWriteSecret {
            level: EncryptionLevel::Application,
            secret: schedule.client_application_traffic_secret,
        });
        self.events.push_back(QuicEvent::HandshakeDone);
        self.events.push_back(QuicEvent::SetReadSecret {
            level: EncryptionLevel::Application,
            secret: schedule.server_application_traffic_secret,
        });
        self.read_level = EncryptionLevel::Application;
        Ok(ClientState::Done)
    }

    /// RFC 8446 §4.6.1: `NewSessionTicket` arrives after the handshake, in
    /// application space, and is not part of the transcript (§4.4.1).
    fn handle_post_handshake(&mut self, raw: &[u8]) -> Result<()> {
        let (msg_type, body) = split_handshake_message(raw)?;
        if msg_type != messages::MSG_NEW_SESSION_TICKET {
            return Err(TlsError::protocol("quic client: unsupported post-handshake message"));
        }
        let ticket = messages::parse_new_session_ticket(body)?;
        if ticket.ticket.is_empty() || ticket.lifetime == 0 {
            return Err(TlsError::protocol("quic client: unusable session ticket"));
        }
        if ticket.lifetime > messages::MAX_SESSION_TICKET_LIFETIME_SECS {
            return Err(TlsError::protocol("quic client: session ticket lifetime too long"));
        }
        // RFC 9001 §4.6.1: over QUIC the parameter is a sentinel, so any other
        // non-zero value is a protocol violation.
        if ticket.max_early_data != 0 && ticket.max_early_data != messages::MAX_EARLY_DATA_SIZE_QUIC {
            return Err(TlsError::protocol("quic client: invalid max_early_data_size for QUIC"));
        }
        let schedule = self.key_schedule.as_ref().ok_or_else(|| TlsError::protocol("quic client: no key schedule"))?;
        let psk = keys::resumption_psk(&schedule.resumption_master_secret, &ticket.nonce)?;
        self.events.push_back(QuicEvent::NewSessionTicket(ClientSessionTicket {
            psk,
            ticket: ticket.ticket,
            lifetime: ticket.lifetime,
            age_add: ticket.age_add,
            created_at: unix_now(),
            max_early_data: ticket.max_early_data,
            alpn: self.jls_state.negotiated_alpn.clone(),
            transport_parameters: self.server_transport_parameters.clone(),
            username: self.config.user.username.clone(),
        }));
        Ok(())
    }
}

/// Builds the `ClientHello` a QUIC client connection sends. The JLS
/// `FakeRandom` is sealed into the random field of the hello that goes out, so
/// the auth data is computed from a placeholder carrying a zeroed random and
/// the PSK binder over the hello that carries the real one.
fn client_hello_flight(
    config: &QuicClientConfig,
    legacy_session_id: &[u8; 32],
    x25519_public: &[u8; 32],
    random_seed: &[u8; RANDOM_SEED_LEN],
    psk: Option<[u8; 32]>,
    early_data_offered: bool,
    psk_offer: Option<ClientHelloPsk<'_>>,
) -> Result<Vec<u8>> {
    let placeholder_params = ClientHelloParams {
        legacy_session_id,
        random: &[0u8; 32],
        server_name: &config.server_name,
        alpn: &config.alpn,
        x25519_public,
        quic_transport_parameters: Some(&config.transport_parameters),
        psk: psk_offer,
        early_data: early_data_offered,
    };
    let placeholder = messages::build_client_hello(&placeholder_params)?;
    let auth_data = jls::jls_client_hello_auth_data(&placeholder)?;
    let fake_random = jls::jls_build_fake_random(&config.user, random_seed, &auth_data, &mut rand::rng())?;

    let unsigned = messages::build_client_hello(&ClientHelloParams { random: &fake_random, ..placeholder_params })?;
    let binder = match &psk {
        Some(psk) => {
            let (_, unsigned_body) = split_handshake_message(&unsigned)?;
            let parsed = messages::parse_client_hello(unsigned_body)?;
            let truncated = messages::truncate_client_hello_binders(&unsigned, &parsed)
                .ok_or_else(|| TlsError::protocol("quic client: malformed pre_shared_key extension"))?;
            keys::compute_finished(&keys::resumption_binder_key(psk)?, &Sha256::digest(&truncated).into())?
        }
        None => [0u8; 32],
    };
    messages::build_client_hello(&ClientHelloParams {
        random: &fake_random,
        psk: psk_offer.map(|offer| ClientHelloPsk { binder: &binder, ..offer }),
        ..placeholder_params
    })
}

/// The ticket-age rules of RFC 8446 §4.2.11 are stated in real time, so this
/// engine reads the system clock where no explicit time source is threaded
/// through.
fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since_epoch| since_epoch.as_secs())
}

fn verify_certificate_signature(
    cert_der: &[u8],
    signature_der: &[u8],
    hash_through_certificate: &[u8; 32],
) -> Result<()> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let point = crate::der::extract_p256_spki_point(cert_der)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&point)
        .map_err(|_| TlsError::protocol("quic client: invalid server certificate public key"))?;
    let signature = Signature::from_der(signature_der)
        .map_err(|_| TlsError::protocol("quic client: malformed CertificateVerify signature"))?;
    let content = messages::certificate_verify_signed_content(hash_through_certificate);
    verifying_key
        .verify(&content, &signature)
        .map_err(|_| TlsError::protocol("quic client: server CertificateVerify signature verification failed"))
}

enum ServerState {
    AwaitClientHello,
    AwaitClientFinished,
    Done,
}

/// The PSK this server accepted from a `ClientHello`, and whether it also took
/// the client's early flight.
struct SelectedPsk {
    psk: [u8; 32],
    early_data: bool,
}

/// The knobs the QUIC-mode JLS server needs.
///
/// They come from this crate's own config: `allow_0rtt` decides both whether
/// tickets advertise 0-RTT and whether an early flight is accepted, and the AEAD
/// key the tickets are sealed under is [`Self::ticket_key`].
pub struct QuicServerOptions {
    pub allow_0rtt: bool,
    /// `None` disables session tickets.
    pub ticket_key: Option<[u8; 32]>,
}

impl core::fmt::Debug for QuicServerOptions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QuicServerOptions")
            .field("allow_0rtt", &self.allow_0rtt)
            .field("tickets_enabled", &self.ticket_key.is_some())
            .finish_non_exhaustive()
    }
}

/// The server half of a JLS-authenticated QUIC TLS handshake.
pub struct QuicServer {
    config: ServerConfig,
    transport_parameters: Vec<u8>,
    options: QuicServerOptions,
    transcript: Transcript,
    key_schedule: Option<KeySchedule>,
    read_level: EncryptionLevel,
    incoming: Vec<u8>,
    state: ServerState,
    events: VecDeque<QuicEvent>,
    jls_state: JlsConnectionState,
    /// The PSK of the resumed session this `ClientHello` selected.
    psk: Option<[u8; 32]>,
    using_psk: bool,
    /// The negotiated ALPN, which a 0-RTT resume must match.
    negotiated_alpn: Option<String>,
}

impl core::fmt::Debug for QuicServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QuicServer")
            .field("options", &self.options)
            .field("read_level", &self.read_level)
            .field("jls_state", &self.jls_state)
            .field("using_psk", &self.using_psk)
            .field("negotiated_alpn", &self.negotiated_alpn)
            .field("queued_events", &self.events.len())
            .finish_non_exhaustive()
    }
}

impl QuicServer {
    /// `transport_parameters` are this server's own RFC 9000 parameters, handed
    /// to the QUIC layer for the connection.
    #[must_use]
    pub fn new(config: ServerConfig, transport_parameters: Vec<u8>, options: QuicServerOptions) -> Self {
        Self {
            config,
            transport_parameters,
            options,
            transcript: Transcript::new(),
            key_schedule: None,
            read_level: EncryptionLevel::Initial,
            incoming: Vec::new(),
            state: ServerState::AwaitClientHello,
            events: VecDeque::new(),
            jls_state: JlsConnectionState {
                status: JlsStatus::Unauthenticated,
                negotiated_alpn: None,
                user: String::new(),
            },
            psk: None,
            using_psk: false,
            negotiated_alpn: None,
        }
    }

    pub fn next_event(&mut self) -> Option<QuicEvent> {
        self.events.pop_front()
    }

    /// The JLS authentication outcome, valid once the handshake has completed.
    #[must_use]
    pub const fn state(&self) -> &JlsConnectionState {
        &self.jls_state
    }

    pub fn handle_crypto_data(&mut self, level: EncryptionLevel, data: &[u8]) -> Result<()> {
        if matches!(self.state, ServerState::Done) {
            return Err(TlsError::protocol("quic server: post-handshake messages are not supported"));
        }
        if level != self.read_level {
            return Err(TlsError::protocol("quic server: handshake data received at wrong encryption level"));
        }
        self.incoming.extend_from_slice(data);
        while let Some(raw) = take_handshake_message(&mut self.incoming) {
            match self.state {
                ServerState::AwaitClientHello => self.state = self.handle_client_hello(&raw)?,
                ServerState::AwaitClientFinished => self.state = self.handle_client_finished(&raw)?,
                ServerState::Done => return Err(TlsError::protocol("quic server: unexpected message after handshake")),
            }
        }
        Ok(())
    }

    fn handle_client_hello(&mut self, raw: &[u8]) -> Result<ServerState> {
        let (msg_type, body) = split_handshake_message(raw)?;
        if msg_type != messages::MSG_CLIENT_HELLO {
            return Err(TlsError::protocol("quic server: expected ClientHello"));
        }
        let parsed = messages::parse_client_hello(body)?;

        let auth_data = jls::jls_client_hello_auth_data(raw)?;
        let presented_sni = parsed.server_name.clone().unwrap_or_default();
        if !jls::check_server_name(&self.config.server_name, &presented_sni) {
            return Err(TlsError::protocol("quic server: jls authentication failed"));
        }
        let user = self
            .config
            .users
            .iter()
            .find(|candidate| jls::jls_check_fake_random(candidate, &parsed.random, &auth_data))
            .cloned()
            .ok_or_else(|| TlsError::protocol("quic server: jls authentication failed"))?;

        let negotiated_alpn = negotiate_alpn(&self.config.alpn, &parsed.alpn, true)?;
        if !messages::offers_tls13(&parsed.supported_versions) {
            return Err(TlsError::protocol("quic server: client did not offer TLS 1.3 in supported_versions"));
        }
        let Some(quic_params) = parsed.quic_transport_parameters.clone() else {
            return Err(TlsError::protocol("quic server: client did not send a quic_transport_parameters extension"));
        };
        let client_x25519_public = match parsed.x25519_public {
            Some(key) if parsed.offers_tls13_aes128_gcm && parsed.offers_x25519 => key,
            _ => {
                return Err(TlsError::protocol("quic server: client did not offer TLS_AES_128_GCM_SHA256 / X25519"));
            }
        };
        // RFC 8446 §4.2.10: early data is only meaningful with a PSK; any other
        // client is rejected over QUIC.
        if parsed.early_data && parsed.psk_identities.is_empty() {
            return Err(TlsError::protocol("quic server: early_data without pre_shared_key"));
        }
        // RFC 8446 §4.2.9: psk_dhe_ke is the only mode this engine implements,
        // and a PSK offered without a mode it supports must not be used.
        if !parsed.psk_identities.is_empty() && !parsed.psk_modes.contains(&messages::PSK_MODE_PSK_DHE_KE) {
            return Err(TlsError::protocol("quic server: client offered a PSK without psk_dhe_ke"));
        }
        let resumed = self.select_psk(&parsed, raw, &user.username, negotiated_alpn.as_deref())?;
        let early_data = resumed.as_ref().is_some_and(|resumed| resumed.early_data);

        self.transcript.update(raw);
        self.events.push_back(QuicEvent::TransportParameters(quic_params));
        self.jls_state = JlsConnectionState {
            status: JlsStatus::Authenticated,
            negotiated_alpn: negotiated_alpn.clone(),
            user: user.username.clone(),
        };
        self.negotiated_alpn.clone_from(&negotiated_alpn);
        self.using_psk = resumed.is_some();
        self.psk = resumed.as_ref().map(|resumed| resumed.psk);
        if let Some(early) = resumed.as_ref().filter(|resumed| resumed.early_data) {
            let mut transcript = Transcript::new();
            transcript.update(raw);
            self.events.push_back(QuicEvent::SetReadSecret {
                level: EncryptionLevel::Early,
                secret: keys::client_early_traffic_secret(&early.psk, &transcript.hash())?,
            });
        }

        self.build_server_flight(&parsed, &user, client_x25519_public)?;
        self.finish_server_flight(negotiated_alpn.as_deref(), early_data)?;
        Ok(ServerState::AwaitClientFinished)
    }

    /// Queues the server's `EncryptedExtensions`, certificate flight (unless a
    /// PSK was selected) and `Finished`, deriving the application secrets on the
    /// way through.
    fn finish_server_flight(&mut self, negotiated_alpn: Option<&str>, early_data: bool) -> Result<()> {
        let encrypted_extensions =
            messages::build_encrypted_extensions(negotiated_alpn, Some(&self.transport_parameters), early_data)?;
        self.transcript.update(&encrypted_extensions);

        // RFC 8446 §4.1.1: a PSK handshake carries no certificate.
        let mut flight = encrypted_extensions;
        if !self.using_psk {
            let cert_msg = messages::build_certificate(&self.config.cert_der)?;
            self.transcript.update(&cert_msg);

            let sign_content = messages::certificate_verify_signed_content(&self.transcript.hash());
            let signature: p256::ecdsa::Signature = self.config.key.sign(&sign_content);
            let cert_verify_msg = messages::build_certificate_verify(signature.to_der().as_bytes())?;
            self.transcript.update(&cert_verify_msg);
            flight.extend_from_slice(&cert_msg);
            flight.extend_from_slice(&cert_verify_msg);
        }

        let hash_before_server_finished = self.transcript.hash();
        let schedule = self.key_schedule.as_ref().ok_or_else(|| TlsError::protocol("quic server: no key schedule"))?;
        let server_verify_data =
            keys::compute_finished(&schedule.server_handshake_traffic_secret, &hash_before_server_finished)?;
        let server_finished = messages::build_finished(&server_verify_data)?;
        self.transcript.update(&server_finished);

        let schedule = self.key_schedule.as_mut().ok_or_else(|| TlsError::protocol("quic server: no key schedule"))?;
        schedule.derive_application_secrets(&self.transcript.hash())?;
        flight.extend_from_slice(&server_finished);
        self.events.push_back(QuicEvent::WriteData { level: EncryptionLevel::Handshake, data: flight });
        self.events.push_back(QuicEvent::SetWriteSecret {
            level: EncryptionLevel::Application,
            secret: schedule.server_application_traffic_secret,
        });
        self.read_level = EncryptionLevel::Handshake;
        Ok(())
    }

    /// Builds and queues the `ServerHello`, sealing the JLS `FakeRandom` into
    /// its random field, and installs the handshake traffic secrets derived from
    /// the client's X25519 share.
    fn build_server_flight(
        &mut self,
        parsed: &messages::ParsedClientHello,
        user: &JlsUser,
        client_x25519_public: [u8; 32],
    ) -> Result<()> {
        let mut server_secret_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut server_secret_bytes);
        let server_secret = StaticSecret::from(server_secret_bytes);
        let server_public = PublicKey::from(&server_secret);

        let selected_identity = self.using_psk.then_some(0);
        let mut random_seed = [0u8; RANDOM_SEED_LEN];
        rand::rng().fill_bytes(&mut random_seed);
        let placeholder = messages::build_server_hello(
            &parsed.legacy_session_id,
            &[0u8; 32],
            server_public.as_bytes(),
            selected_identity,
        )?;
        let server_auth_data = jls::jls_server_hello_auth_data(&placeholder)?;
        let fake_random = jls::jls_build_fake_random(user, &random_seed, &server_auth_data, &mut rand::rng())?;
        let server_hello = messages::build_server_hello(
            &parsed.legacy_session_id,
            &fake_random,
            server_public.as_bytes(),
            selected_identity,
        )?;
        self.transcript.update(&server_hello);
        self.events.push_back(QuicEvent::WriteData { level: EncryptionLevel::Initial, data: server_hello });

        let shared_secret = server_secret.diffie_hellman(&PublicKey::from(client_x25519_public));
        let schedule = KeySchedule::new(self.psk.as_ref(), shared_secret.as_bytes(), &self.transcript.hash())?;
        self.events.push_back(QuicEvent::SetWriteSecret {
            level: EncryptionLevel::Handshake,
            secret: schedule.server_handshake_traffic_secret,
        });
        self.events.push_back(QuicEvent::SetReadSecret {
            level: EncryptionLevel::Handshake,
            secret: schedule.client_handshake_traffic_secret,
        });
        self.key_schedule = Some(schedule);
        Ok(())
    }

    /// RFC 8446 §4.2.11: the server selects at most one PSK, validates the
    /// binder that goes with it and otherwise ignores the offer. 0-RTT is only
    /// accepted when the ticket allowed it, the age is plausible (§4.2.10) and
    /// the resumed connection keeps the ticket's ALPN.
    fn select_psk(
        &self,
        parsed: &messages::ParsedClientHello,
        raw: &[u8],
        username: &str,
        negotiated_alpn: Option<&str>,
    ) -> Result<Option<SelectedPsk>> {
        let Some(key) = self.options.ticket_key.as_ref() else {
            return Ok(None);
        };
        if parsed.psk_identities.len() != 1 || parsed.psk_binders.len() != 1 {
            return Ok(None);
        }
        let Some(identity) = parsed.psk_identities.first() else {
            return Ok(None);
        };
        let Some(binder_bytes) = parsed.psk_binders.first() else {
            return Ok(None);
        };
        let Some(&obfuscated_ticket_age) = parsed.psk_obfuscated_ticket_ages.first() else {
            return Ok(None);
        };
        let Ok(state) = ticket::open(key, identity) else {
            return Ok(None);
        };
        let now = unix_now();
        if !ticket::is_valid(&state, now) || state.username != username {
            return Ok(None);
        }
        // A handshake whose selected PSK fails its binder is aborted rather than
        // fallen back from.
        let binder: [u8; 32] =
            binder_bytes.as_slice().try_into().map_err(|_| TlsError::protocol("quic server: PSK binder length"))?;
        let truncated = messages::truncate_client_hello_binders(raw, parsed)
            .ok_or_else(|| TlsError::protocol("quic server: malformed pre_shared_key extension"))?;
        let binder_key = keys::resumption_binder_key(&state.psk)?;
        if !keys::verify_finished(&binder_key, &Sha256::digest(&truncated).into(), &binder)? {
            return Err(TlsError::protocol("quic server: invalid PSK binder"));
        }
        let early_data = parsed.early_data
            && self.options.allow_0rtt
            && state.max_early_data == messages::MAX_EARLY_DATA_SIZE_QUIC
            && state.alpn.as_deref() == negotiated_alpn
            && ticket::age_is_plausible(&state, obfuscated_ticket_age, now);
        Ok(Some(SelectedPsk { psk: state.psk, early_data }))
    }

    fn handle_client_finished(&mut self, raw: &[u8]) -> Result<ServerState> {
        let (msg_type, body) = split_handshake_message(raw)?;
        if msg_type != messages::MSG_FINISHED {
            return Err(TlsError::protocol("quic server: expected client Finished"));
        }
        let received = messages::parse_finished(body)?;
        let hash_before = self.transcript.hash();
        let schedule = self.key_schedule.as_ref().ok_or_else(|| TlsError::protocol("quic server: no key schedule"))?;
        if !keys::verify_finished(&schedule.client_handshake_traffic_secret, &hash_before, &received)? {
            return Err(TlsError::protocol("quic server: client Finished verify_data mismatch"));
        }
        self.transcript.update(raw);
        let schedule = self.key_schedule.as_mut().ok_or_else(|| TlsError::protocol("quic server: no key schedule"))?;
        schedule.derive_resumption_master_secret(&self.transcript.hash())?;

        self.events.push_back(QuicEvent::HandshakeDone);
        self.events.push_back(QuicEvent::SetReadSecret {
            level: EncryptionLevel::Application,
            secret: schedule.client_application_traffic_secret,
        });
        self.read_level = EncryptionLevel::Application;

        // RFC 8446 §4.6.1: the ticket is sent after the handshake, and its PSK
        // is a one-way function of the resumption master secret. At most one is
        // sent per connection, with an empty ticket_nonce.
        let Some(key) = self.options.ticket_key else {
            return Ok(ServerState::Done);
        };
        let resumption_master_secret = schedule.resumption_master_secret;
        let psk = keys::resumption_psk(&resumption_master_secret, &[])?;
        let mut age_add_bytes = [0u8; 4];
        rand::rng().fill_bytes(&mut age_add_bytes);
        let state = ticket::TicketState {
            psk,
            created_at: unix_now(),
            lifetime: messages::MAX_SESSION_TICKET_LIFETIME_SECS,
            age_add: u32::from_le_bytes(age_add_bytes),
            max_early_data: if self.options.allow_0rtt { messages::MAX_EARLY_DATA_SIZE_QUIC } else { 0 },
            alpn: self.negotiated_alpn.clone(),
            username: self.jls_state.user.clone(),
        };
        let label = ticket::seal(&key, &state, &mut rand::rng())?;
        let message =
            messages::build_new_session_ticket(state.lifetime, state.age_add, &[], &label, state.max_early_data)?;
        self.events.push_back(QuicEvent::WriteData { level: EncryptionLevel::Application, data: message });
        Ok(ServerState::Done)
    }
}

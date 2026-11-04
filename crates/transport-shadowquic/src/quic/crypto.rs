//! The JLS QUIC-mode handshake as a `quinn` crypto plug-in, plus the RFC 9001 packet and
//! header protection for the key schedule that handshake produces.
//!
//! `quinn` owns the QUIC packet layer and drives a foreign TLS engine through
//! `quinn::crypto::Session`; `murmur_jls_tls`'s `QuicClient`/`QuicServer` are exactly such
//! an engine, so the JLS handshake runs unmodified over quinn's transport. The cipher suite is
//! `TLS_AES_128_GCM_SHA256` (the only one the JLS engine implements), so packet protection is
//! AES-128-GCM and header protection is AES-ECB per RFC 9001 §5.4 — both on `ring`, the same
//! backend quinn's own TLS plug-in uses.

use std::any::Any;
use std::collections::VecDeque;
use std::sync::Arc;

use bytes::BytesMut;
use hkdf::Hkdf;
use murmur_jls_tls::{
    quic_initial_secrets, quic_keys, ClientSessionTicket, EncryptionLevel, JlsConnectionState, JlsStatus, JlsUser,
    QuicClient, QuicClientConfig, QuicEvent, QuicKeys, QuicServer, QuicServerOptions, QuicVersion,
    ServerConfig as JlsServerConfig, TimeFn, TlsError,
};
use parking_lot::Mutex;
use quinn::crypto::{
    ClientConfig as CryptoClientConfig, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey,
    ServerConfig as CryptoServerConfig, Session, UnsupportedVersion,
};
use quinn::{ConnectError, ConnectionId, Side, TransportErrorCode};
use quinn_proto::{transport_parameters::TransportParameters, TransportError};
use ring::aead::quic::{HeaderProtectionKey, AES_128 as HP_AES_128};
use rustls::RootCertStore;
use sha2::Sha256;

const AEAD_TAG_LEN: usize = 16;
const LEVEL_COUNT: usize = 3;
const VERSION_1: u32 = 0x0000_0001;
const VERSION_2: u32 = 0x6b33_43cf;
/// TLS `alert_handshake_failure` (40). RFC 9001 §4.8 has no dedicated code for "the TLS handshake
/// failed", so the alert is carried in the CRYPTO_ERROR range instead.
const ALERT_HANDSHAKE_FAILURE: u8 = 40;

fn version_of(version: u32) -> Option<QuicVersion> {
    match version {
        VERSION_1 => Some(QuicVersion::V1),
        VERSION_2 => Some(QuicVersion::V2),
        _ => None,
    }
}

/// The handshake levels' slot in `JlsSession`'s per-level state. 0-RTT has no
/// slot of its own: quinn wants its single key pair before the handshake
/// starts, so the session keeps that secret beside the handshake levels.
fn level_index(level: EncryptionLevel) -> Option<usize> {
    match level {
        EncryptionLevel::Early => None,
        EncryptionLevel::Initial => Some(0),
        EncryptionLevel::Handshake => Some(1),
        EncryptionLevel::Application => Some(2),
    }
}

fn next_level(level: EncryptionLevel) -> Option<EncryptionLevel> {
    match level {
        // 0-RTT is not a step in the handshake's write sequence.
        EncryptionLevel::Early | EncryptionLevel::Application => None,
        EncryptionLevel::Initial => Some(EncryptionLevel::Handshake),
        EncryptionLevel::Handshake => Some(EncryptionLevel::Application),
    }
}

/// RFC 9001 §4.8: a handshake failure is a CRYPTO_ERROR whose code is the TLS alert.
fn transport_error(err: &TlsError) -> TransportError {
    let code = match err {
        TlsError::PeerAlert { description, .. } => TransportErrorCode::crypto(*description),
        TlsError::Io(_) | TlsError::Protocol(_) | TlsError::KeyUpdateUnsupported => {
            TransportErrorCode::crypto(ALERT_HANDSHAKE_FAILURE)
        }
    };
    TransportError { code, frame: None, reason: err.to_string() }
}

/// `HKDF-Expand-Label(secret, label, "", len)` per RFC 8446 §7.1, which RFC 9001 uses for the
/// `quic ku` key update.
fn expand_label(secret: &[u8; 32], label: &[u8], out: &mut [u8]) -> Option<()> {
    let length = u16::try_from(out.len()).ok()?;
    let label_len = u8::try_from(b"tls13 ".len() + label.len()).ok()?;
    let mut info = Vec::with_capacity(4 + label.len());
    info.extend_from_slice(&length.to_be_bytes());
    info.push(label_len);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    Hkdf::<Sha256>::from_prk(secret).ok()?.expand(&info, out).ok()
}

/// RFC 9001 §5.3: the nonce is the packet protection IV XOR the packet number, big-endian in its
/// low 8 bytes.
fn packet_nonce(iv: &[u8; 12], packet: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for (byte, pn) in nonce[4..].iter_mut().zip(packet.to_be_bytes()) {
        *byte ^= pn;
    }
    nonce
}

struct AesPacketKey {
    key: ring::aead::LessSafeKey,
    iv: [u8; 12],
}

impl AesPacketKey {
    fn new(keys: &QuicKeys) -> Self {
        #[expect(
            clippy::expect_used,
            reason = "`QuicKeys::key` is the fixed 16-byte AES-128 key, so the constructor cannot fail"
        )]
        let unbound =
            ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &keys.key).expect("an AES-128-GCM key is 16 bytes");
        Self { key: ring::aead::LessSafeKey::new(unbound), iv: keys.iv }
    }
}

impl PacketKey for AesPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, rest) = buf.split_at_mut(header_len);
        let (payload, tag) = rest.split_at_mut(rest.len() - AEAD_TAG_LEN);
        #[expect(
            clippy::expect_used,
            reason = "`PacketKey::encrypt` has no error channel; quinn sizes `buf` as header, payload and tag, so sealing cannot fail"
        )]
        let computed = self
            .key
            .seal_in_place_separate_tag(
                ring::aead::Nonce::assume_unique_for_key(packet_nonce(&self.iv, packet)),
                ring::aead::Aad::from(header),
                payload,
            )
            .expect("encrypting a QUIC payload cannot fail");
        tag.copy_from_slice(computed.as_ref());
    }

    fn decrypt(&self, packet: u64, header: &[u8], payload: &mut BytesMut) -> Result<(), CryptoError> {
        let len = payload.len();
        if len < AEAD_TAG_LEN {
            return Err(CryptoError);
        }
        // ring's `open_in_place` expects ciphertext||tag in one buffer and returns the plaintext
        // slice, so the received tag stays where the caller put it instead of being split off.
        let plaintext_len = self
            .key
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key(packet_nonce(&self.iv, packet)),
                ring::aead::Aad::from(header),
                payload.as_mut(),
            )
            .map_err(|_| CryptoError)?
            .len();
        payload.truncate(plaintext_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        AEAD_TAG_LEN
    }

    /// RFC 9001 §5.5: the confidentiality and integrity limits of AES-128-GCM.
    fn confidentiality_limit(&self) -> u64 {
        1 << 23
    }

    fn integrity_limit(&self) -> u64 {
        (1 << 36) - 64
    }
}

struct AesHeaderKey {
    key: HeaderProtectionKey,
}

impl AesHeaderKey {
    fn new(keys: &QuicKeys) -> Self {
        #[expect(
            clippy::expect_used,
            reason = "`QuicKeys::hp` is the fixed 16-byte AES-128 header protection key, so the constructor cannot fail"
        )]
        let key =
            HeaderProtectionKey::new(&HP_AES_128, &keys.hp).expect("an AES-128 header protection key is 16 bytes");
        Self { key }
    }

    /// RFC 9001 §5.4.3.
    ///
    /// `quinn` only calls this for a packet at least `pn_offset + 4 + sample_size` bytes long, so
    /// the early returns below are unreachable; a shorter packet is left untouched rather than
    /// panicking, since neither `HeaderKey` method has an error channel.
    fn apply(&self, pn_offset: usize, packet: &mut [u8], unmask: bool) {
        let Some(sample_start) = pn_offset.checked_add(4) else { return };
        let Some((header, sample)) = packet.split_at_mut_checked(sample_start) else { return };
        let Some((first, rest)) = header.split_first_mut() else { return };
        let Some(pn_start) = rest.len().checked_sub(4) else { return };
        let Some(pn_bytes) = rest.get_mut(pn_start..) else { return };
        let Some(mask) =
            sample.get(..self.key.algorithm().sample_len()).and_then(|sample| self.key.new_mask(sample).ok())
        else {
            return;
        };
        let Some((first_mask, pn_mask)) = mask.split_first() else { return };
        let bits = if *first & 0x80 == 0x80 { 0x0f } else { 0x1f };
        let first_plain = if unmask { *first ^ (first_mask & bits) } else { *first };
        let pn_len = usize::from(first_plain & 0x03) + 1;
        *first ^= first_mask & bits;
        for (byte, mask_byte) in pn_bytes.iter_mut().zip(pn_mask).take(pn_len) {
            *byte ^= *mask_byte;
        }
    }
}

impl HeaderKey for AesHeaderKey {
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(pn_offset, packet, false);
    }

    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(pn_offset, packet, true);
    }

    fn sample_size(&self) -> usize {
        self.key.algorithm().sample_len()
    }
}

/// One level's traffic secrets, kept in the form a key update re-derives them from.
///
/// Each half arrives with its own `SetWriteSecret`/`SetReadSecret` event, and a level becomes
/// usable only once both are present: the server derives its 1-RTT write secret while processing
/// the ClientHello but its 1-RTT *read* secret only once the client Finished arrives, so keying
/// on the write secret alone would install an all-zero peer key that quinn never recomputes.
#[derive(Clone, Copy)]
struct LevelSecrets {
    /// This peer's secret: encrypts what we send, decrypts what the peer sends.
    local: Option<[u8; 32]>,
    /// The peer's secret.
    remote: Option<[u8; 32]>,
}

impl LevelSecrets {
    fn complete(&self) -> Option<([u8; 32], [u8; 32])> {
        Some((self.local?, self.remote?))
    }
}

/// What a finished session publishes through `quinn`'s `handshake_data` hook, which the
/// connection wrapper reports as the connection state.
pub(crate) struct JlsHandshakeData {
    pub status: JlsStatus,
    pub user: String,
}

enum Engine {
    Client(Box<QuicClient>),
    Server(Box<QuicServer>),
}

impl Engine {
    fn next_event(&mut self) -> Option<QuicEvent> {
        match self {
            Self::Client(client) => client.next_event(),
            Self::Server(server) => server.next_event(),
        }
    }

    fn handle_crypto_data(&mut self, level: EncryptionLevel, data: &[u8]) -> Result<(), TlsError> {
        match self {
            Self::Client(client) => client.handle_crypto_data(level, data),
            Self::Server(server) => server.handle_crypto_data(level, data),
        }
    }

    fn state(&self) -> &JlsConnectionState {
        match self {
            Self::Client(client) => client.state(),
            Self::Server(server) => server.state(),
        }
    }
}

pub(crate) struct JlsSession {
    engine: Engine,
    version: QuicVersion,
    /// Which side of the connection this is, which decides how the peer's transport parameters
    /// are validated.
    side: Side,
    /// The level `quinn` currently writes CRYPTO frames at.
    write_level: EncryptionLevel,
    /// The level the peer's next CRYPTO data arrives at. `quinn` hands CRYPTO data over without
    /// naming the space it came from, and the JLS engine needs the level; the `SetReadSecret`
    /// events are what mark the transition, since a peer cannot send at a level whose keys the
    /// receiver has not derived yet.
    read_level: EncryptionLevel,
    /// Handshake bytes the engine produced that `quinn` has not sent yet, in order.
    outgoing: VecDeque<(EncryptionLevel, Vec<u8>)>,
    secrets: [Option<LevelSecrets>; LEVEL_COUNT],
    /// `client_early_traffic_secret`, the one secret behind both directions of 0-RTT.
    early_secret: Option<[u8; 32]>,
    /// Where a session ticket lands, shared with the client config so the next connection can
    /// offer it. `None` on the server.
    ticket_store: Option<Arc<Mutex<Option<ClientSessionTicket>>>>,
    /// The transport parameters stored with the ticket a resumed client is sending 0-RTT against.
    ticket_params: Option<TransportParameters>,
    handshake_done: bool,
    handshake_data_reported: bool,
    peer_params: Option<TransportParameters>,
}

impl JlsSession {
    fn new(
        engine: Engine,
        version: u32,
        side: Side,
        ticket_store: Option<Arc<Mutex<Option<ClientSessionTicket>>>>,
    ) -> Self {
        // Only the client knows its 0-RTT keys up front: quinn asks for them before the first
        // handshake byte, so the engine derived them while it built the ClientHello.
        let early_secret = match &engine {
            Engine::Client(client) => client.early_traffic_secret().copied(),
            Engine::Server(_) => None,
        };
        let ticket_params = match &engine {
            Engine::Client(client) => client.ticket_transport_parameters().and_then(parse_ticket_parameters),
            Engine::Server(_) => None,
        };
        #[expect(
            clippy::expect_used,
            reason = "quinn only starts a session for a version its own `initial_keys` accepted, and that path rejects every version `version_of` does not know"
        )]
        let version = version_of(version).expect("quinn only starts a session for a version initial_keys accepted");
        Self {
            engine,
            version,
            side,
            write_level: EncryptionLevel::Initial,
            read_level: EncryptionLevel::Initial,
            outgoing: VecDeque::new(),
            secrets: [None; LEVEL_COUNT],
            early_secret,
            ticket_store,
            ticket_params,
            handshake_done: false,
            handshake_data_reported: false,
            peer_params: None,
        }
    }

    fn record(&mut self, level: EncryptionLevel, local: Option<[u8; 32]>, remote: Option<[u8; 32]>) {
        let Some(index) = level_index(level) else {
            // RFC 9001 §4.6: one key pair protects the whole 0-RTT flight, so whichever side
            // reports the secret hands quinn the same keys.
            self.early_secret = local.or(remote);
            return;
        };
        let Some(entry) = self.secrets.get_mut(index) else { return };
        let entry = entry.get_or_insert(LevelSecrets { local: None, remote: None });
        if local.is_some() {
            entry.local = local;
        }
        if remote.is_some() {
            entry.remote = remote;
        }
    }

    fn drain(&mut self) -> Result<(), TransportError> {
        while let Some(event) = self.engine.next_event() {
            match event {
                QuicEvent::WriteData { level, data } => self.outgoing.push_back((level, data)),
                QuicEvent::SetWriteSecret { level, secret } => self.record(level, Some(secret), None),
                QuicEvent::SetReadSecret { level, secret } => {
                    self.record(level, None, Some(secret));
                    // 0-RTT is not part of the read sequence, and the read level is never 0-RTT,
                    // so both levels have a slot whenever the peer can send at a later one.
                    if let (Some(index), Some(read)) = (level_index(level), level_index(self.read_level)) {
                        if index > read {
                            self.read_level = level;
                        }
                    }
                }
                QuicEvent::TransportParameters(params) => {
                    let mut encoded = bytes::Bytes::copy_from_slice(&params);
                    self.peer_params = Some(TransportParameters::read(self.side, &mut encoded)?);
                }
                QuicEvent::NewSessionTicket(ticket) => {
                    if let Some(store) = &self.ticket_store {
                        *store.lock() = Some(ticket);
                    }
                }
                QuicEvent::HandshakeDone => self.handshake_done = true,
            }
        }
        Ok(())
    }

    /// Both traffic secrets for a level, once the engine has derived each of them.
    fn level_secrets(&self, level: EncryptionLevel) -> Option<([u8; 32], [u8; 32])> {
        self.secrets.get(level_index(level)?)?.as_ref()?.complete()
    }

    fn level_keys(&self, level: EncryptionLevel) -> Option<Keys> {
        let (local, remote) = self.level_secrets(level)?;
        let local = quic_keys(&local, self.version).ok()?;
        let remote = quic_keys(&remote, self.version).ok()?;
        Some(Keys {
            header: KeyPair {
                local: Box::new(AesHeaderKey::new(&local)),
                remote: Box::new(AesHeaderKey::new(&remote)),
            },
            packet: KeyPair {
                local: Box::new(AesPacketKey::new(&local)),
                remote: Box::new(AesPacketKey::new(&remote)),
            },
        })
    }
}

/// RFC 9001 §5.2: both peers derive the Initial secrets from the client's original destination
/// connection ID, before any handshake byte exists.
#[expect(
    clippy::expect_used,
    reason = "a 32-byte PRK and 16/12-byte keys cannot overflow the HKDF wire lengths, and `Session::initial_keys` has no error channel"
)]
fn initial_keys(version: QuicVersion, dst_cid: &ConnectionId, side: Side) -> Keys {
    let (client, server) = quic_initial_secrets(dst_cid.as_ref(), version).expect("fixed-size HKDF expansion");
    let (local, remote) = match side {
        Side::Client => (client, server),
        Side::Server => (server, client),
    };
    let local = quic_keys(&local, version).expect("fixed-size HKDF expansion");
    let remote = quic_keys(&remote, version).expect("fixed-size HKDF expansion");
    Keys {
        header: KeyPair { local: Box::new(AesHeaderKey::new(&local)), remote: Box::new(AesHeaderKey::new(&remote)) },
        packet: KeyPair { local: Box::new(AesPacketKey::new(&local)), remote: Box::new(AesPacketKey::new(&remote)) },
    }
}

impl Session for JlsSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.handshake_done {
            return None;
        }
        let state = self.engine.state();
        Some(Box::new(JlsHandshakeData { status: state.status, user: state.user.clone() }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        // RFC 9001 §4.6: the client writes 0-RTT and the server reads it under the same
        // `client_early_traffic_secret`, so one key pair is the whole 0-RTT level.
        let keys = quic_keys(&self.early_secret?, self.version).ok()?;
        Some((Box::new(AesHeaderKey::new(&keys)), Box::new(AesPacketKey::new(&keys))))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match &self.engine {
            Engine::Client(client) => client.early_data_accepted(),
            // Only a client can have data accepted, and quinn only asks when `early_crypto`
            // handed it 0-RTT keys.
            Engine::Server(_) => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        !self.handshake_done
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        // Post-handshake CRYPTO is a session ticket, which the client engine keeps so the
        // next connection can resume from it; the server defines no such messages.
        self.engine.handle_crypto_data(self.read_level, buf).map_err(|err| transport_error(&err))?;
        self.drain()?;
        if self.handshake_data_reported {
            return Ok(false);
        }
        self.handshake_data_reported = true;
        Ok(self.peer_params.is_some())
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        // Before the handshake supplies the peer's own parameters, quinn's `init_0rtt` needs the
        // ones stored with the ticket (RFC 9001 §4.6.3).
        if self.peer_params.is_some() {
            return Ok(self.peer_params);
        }
        Ok(self.ticket_params)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        self.drain().ok()?;
        if let Some((level, data)) = self.outgoing.front() {
            if *level == self.write_level {
                buf.extend_from_slice(data);
                self.outgoing.pop_front();
                return None;
            }
        }
        let next = next_level(self.write_level)?;
        self.level_secrets(next)?;
        self.write_level = next;
        self.level_keys(next)
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let secrets = self.secrets.get_mut(level_index(EncryptionLevel::Application)?)?.as_mut()?;
        let mut local = [0u8; 32];
        expand_label(&secrets.local?, b"quic ku", &mut local)?;
        let mut remote = [0u8; 32];
        expand_label(&secrets.remote?, b"quic ku", &mut remote)?;
        secrets.local = Some(local);
        secrets.remote = Some(remote);
        let local = quic_keys(&local, self.version).ok()?;
        let remote = quic_keys(&remote, self.version).ok()?;
        Some(KeyPair { local: Box::new(AesPacketKey::new(&local)), remote: Box::new(AesPacketKey::new(&remote)) })
    }

    fn is_valid_retry(&self, _orig_dst_cid: &ConnectionId, _header: &[u8], _payload: &[u8]) -> bool {
        // Neither side of this transport ever requests address validation, so a Retry packet is
        // never one this endpoint asked for.
        false
    }

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        // The JLS key schedule derives no exporter master secret to expand from, so keying
        // material export has no counterpart here.
        Err(ExportKeyingMaterialError)
    }
}

/// The JLS server credentials `quinn` turns into a crypto session per connection.
///
/// The credentials stay behind an [`Arc`] because `QuicServer` takes a [`JlsServerConfig`] by
/// value and that struct is not `Clone`, so one is rebuilt field by field for every connection.
pub(crate) struct JlsQuicServerConfig {
    credentials: Arc<JlsServerConfig>,
    /// Whether 0-RTT is allowed, which decides both whether tickets advertise 0-RTT and
    /// whether an early flight is taken.
    allow_0rtt: bool,
    /// The ticket keys: one key per endpoint, so every connection this listener
    /// serves can open the tickets another one issued.
    ticket_key: [u8; 32],
}

impl JlsQuicServerConfig {
    pub(crate) fn new(credentials: Arc<JlsServerConfig>, allow_0rtt: bool) -> Self {
        let mut ticket_key = [0u8; 32];
        #[expect(
            clippy::expect_used,
            reason = "`JlsQuicServerConfig::new` has no error channel to report an RNG failure with"
        )]
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut ticket_key).expect("the system RNG");
        Self { credentials, allow_0rtt, ticket_key }
    }

    fn session_credentials(&self) -> JlsServerConfig {
        let credentials = &*self.credentials;
        JlsServerConfig {
            users: credentials.users.clone(),
            server_name: credentials.server_name.clone(),
            alpn: credentials.alpn.clone(),
            cert_der: credentials.cert_der.clone(),
            key: credentials.key.clone(),
        }
    }
}

impl CryptoServerConfig for JlsQuicServerConfig {
    fn initial_keys(&self, version: u32, dst_cid: &ConnectionId) -> Result<Keys, UnsupportedVersion> {
        let version = version_of(version).ok_or(UnsupportedVersion)?;
        Ok(initial_keys(version, dst_cid, Side::Server))
    }

    #[expect(
        clippy::expect_used,
        reason = "`retry_tag` returns the tag itself, so it has no error channel; a 32-byte PRK and 16/12-byte keys cannot overflow the HKDF wire lengths"
    )]
    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; AEAD_TAG_LEN] {
        let Some(version) = version_of(version) else { return [0; AEAD_TAG_LEN] };
        let (client, _) = quic_initial_secrets(orig_dst_cid.as_ref(), version).expect("fixed-size HKDF expansion");
        let keys = quic_keys(&client, version).expect("fixed-size HKDF expansion");
        // RFC 9001 §5.8: the Retry Pseudo-Packet is the original destination connection ID
        // prefixed with its length, then the Retry packet. Sealing an empty payload with the
        // whole pseudo-packet as associated data under an all-zero nonce is exactly that
        // definition, and `encrypt` leaves the resulting tag in the pseudo-packet's own last 16
        // bytes.
        let cid = orig_dst_cid.as_ref();
        let pseudo_len = 1 + cid.len() + packet.len();
        let mut pseudo = Vec::with_capacity(pseudo_len + AEAD_TAG_LEN);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a QUIC connection ID is at most 20 bytes and RFC 9001 §5.8 gives its length a one-byte field"
        )]
        pseudo.push(cid.len() as u8);
        pseudo.extend_from_slice(cid);
        pseudo.extend_from_slice(packet);
        pseudo.resize(pseudo_len + AEAD_TAG_LEN, 0);
        AesPacketKey::new(&keys).encrypt(0, &mut pseudo, pseudo_len);
        let mut tag = [0u8; AEAD_TAG_LEN];
        tag.copy_from_slice(&pseudo.split_off(pseudo_len));
        tag
    }

    fn start_session(self: Arc<Self>, version: u32, params: &TransportParameters) -> Box<dyn Session> {
        let mut transport_parameters = Vec::new();
        params.write(&mut transport_parameters);
        let options = QuicServerOptions { allow_0rtt: self.allow_0rtt, ticket_key: Some(self.ticket_key) };
        let engine = QuicServer::new(self.session_credentials(), transport_parameters, options);
        Box::new(JlsSession::new(Engine::Server(Box::new(engine)), version, Side::Server, None))
    }
}

/// The JLS client credentials `quinn` turns into a crypto session per connection.
pub(crate) struct JlsQuicClientConfig {
    alpn: Vec<String>,
    user: JlsUser,
    root_certs: Arc<RootCertStore>,
    time: Option<TimeFn>,
    /// A single-entry client session cache, which
    /// `adapter-outbound`'s `zero-rtt` option installs: the ticket the last connection stored,
    /// offered by the next one. It lives as long as this config, so one outbound keeps it across
    /// dials.
    session_store: Arc<Mutex<Option<ClientSessionTicket>>>,
}

impl JlsQuicClientConfig {
    pub(crate) fn new(alpn: Vec<String>, user: JlsUser, root_certs: Arc<RootCertStore>, time: Option<TimeFn>) -> Self {
        Self { alpn, user, root_certs, time, session_store: Arc::new(Mutex::new(None)) }
    }

    /// The ticket the last connection stored, which the next one offers. Only a test can observe
    /// it: `quinn` learns about it by `start_session` offering it.
    #[cfg(test)]
    pub(crate) fn stored_session(&self) -> Option<ClientSessionTicket> {
        self.session_store.lock().clone()
    }
}

impl CryptoClientConfig for JlsQuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        let mut transport_parameters = Vec::new();
        params.write(&mut transport_parameters);
        let ticket = self.session_store.lock().clone();
        let client = QuicClient::new(QuicClientConfig {
            server_name: server_name.to_owned(),
            alpn: self.alpn.clone(),
            user: self.user.clone(),
            transport_parameters,
            root_certs: Arc::clone(&self.root_certs),
            time: self.time.clone(),
            ticket,
        })
        // Every failure `QuicClient::new` reports comes from the ClientHello it builds, which is
        // built out of the server name and the ALPN list, so this is the closest fit available.
        .map_err(|err| ConnectError::InvalidServerName(err.to_string()))?;
        Ok(Box::new(JlsSession::new(
            Engine::Client(Box::new(client)),
            version,
            Side::Client,
            Some(Arc::clone(&self.session_store)),
        )))
    }
}

/// The transport parameters a ticket carries: the server's own, as the client recorded them
/// (RFC 9001 §4.6.3). A ticket whose parameters cannot be parsed is not usable for 0-RTT, which
/// `None` reports.
fn parse_ticket_parameters(encoded: &[u8]) -> Option<TransportParameters> {
    let mut bytes = bytes::Bytes::copy_from_slice(encoded);
    TransportParameters::read(Side::Client, &mut bytes).ok()
}

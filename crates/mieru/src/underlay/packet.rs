use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, Mutex as AsyncMutex};

use crate::cipher::{self, BlockCipher};
use crate::io::{ClientDialer, DialedPacket, PacketIo};
use crate::session::{ReadEnd, SegmentSink, Session, SessionError, SessionMeta, SessionPeer, Transport};
use crate::wire::{self, DataAckStruct, ProtocolType, SessionStruct};

use super::{discover, fragment_size, Result, ServerUsers, DEFAULT_MTU};

use crate::padding::{self, AsciiPaddingOpts, PaddingOpts, PaddingPosition};
use crate::trafficpattern::Config;

const SESSION_ACCEPT_CAPACITY: usize = 64;
const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
const DATAGRAM_HEADER_LEN: usize = cipher::DEFAULT_NONCE_SIZE + wire::METADATA_LENGTH + cipher::DEFAULT_OVERHEAD;

struct SessionEntry {
    session: Arc<Session>,
    cipher: Arc<BlockCipher>,
    peer_addr: SocketAddr,
}

struct Inner {
    socket: Arc<dyn PacketIo>,
    is_client: bool,
    client_cipher: Option<Arc<BlockCipher>>,
    client_server_addr: Option<SocketAddr>,
    sessions: AsyncMutex<HashMap<u32, SessionEntry>>,
    users: Option<ServerUsers>,
    mtu: usize,
    closed: AtomicBool,
    local_addr: Option<SocketAddr>,
    /// The name this side authenticated as: the configured one client-side, the one
    /// `Registry::discover` matched server-side.
    user_name: Option<String>,
    /// The `traffic-pattern` this underlay was built with, if any. Drives nonce shaping and
    /// datagram padding; absent means mieru's unpadded default.
    traffic_pattern: Option<Config>,
}

struct ClientSink {
    socket: Arc<dyn PacketIo>,
    cipher: Arc<BlockCipher>,
    peer_addr: SocketAddr,
    traffic_pattern: Option<Config>,
    mtu: usize,
}

#[async_trait::async_trait]
impl SegmentSink for ClientSink {
    async fn send_segment(&self, meta: [u8; wire::METADATA_LENGTH], payload: &[u8]) -> std::io::Result<()> {
        send_datagram(
            &self.socket,
            &self.cipher,
            self.peer_addr,
            meta,
            payload,
            self.traffic_pattern.as_ref(),
            self.mtu,
        )
        .await
    }
}

struct ServerSink {
    inner: Arc<Inner>,
    session_id: u32,
}

#[async_trait::async_trait]
impl SegmentSink for ServerSink {
    async fn send_segment(&self, meta: [u8; wire::METADATA_LENGTH], payload: &[u8]) -> std::io::Result<()> {
        let (cipher, peer_addr) = {
            let sessions = self.inner.sessions.lock().await;
            let Some(entry) = sessions.get(&self.session_id) else {
                return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "session no longer registered"));
            };
            let looked_up = (Arc::clone(&entry.cipher), entry.peer_addr);
            drop(sessions);
            looked_up
        };
        send_datagram(
            &self.inner.socket,
            &cipher,
            peer_addr,
            meta,
            payload,
            self.inner.traffic_pattern.as_ref(),
            self.inner.mtu,
        )
        .await
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "padding is capped at MAX_PADDING_LEN (255); the wire length field is one byte"
)]
fn padding_byte_len(len: usize) -> u8 {
    len as u8
}

/// Writes one segment: padding lengths live in the datagram's own metadata, so it is re-marshaled
/// with them filled in before encryption. A session-struct datagram gets end padding only; a
/// data-ack datagram also gets middle padding, between the metadata and the payload.
#[allow(clippy::too_many_arguments)]
async fn send_datagram(
    socket: &dyn PacketIo,
    cipher: &BlockCipher,
    peer: SocketAddr,
    meta: [u8; wire::METADATA_LENGTH],
    payload: &[u8],
    traffic_pattern: Option<&Config>,
    mtu: usize,
) -> std::io::Result<()> {
    let Some(protocol) = ProtocolType::from_byte(meta[0]).ok() else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "unknown segment protocol"));
    };
    let max_padding = |fragment_size: usize, existing: usize, position| {
        padding::max_padding_size_with_traffic_pattern(
            traffic_pattern,
            Transport::Packet,
            mtu,
            fragment_size,
            existing,
            position,
        )
    };
    let strategy_source = cipher.user_name().unwrap_or_default();
    let (meta, prefix, suffix) = if protocol.is_session_struct() {
        let mut session = SessionStruct::unmarshal(&meta).map_err(wire_io_err)?;
        let pad = padding::new_padding(&PaddingOpts::recommended(
            max_padding(session.payload_len as usize, 0, PaddingPosition::End),
            padding::PACKET_OVERHEAD + session.payload_len as usize,
            &strategy_source,
        ));
        session.suffix_len = padding_byte_len(pad.len());
        (session.marshal(), Vec::new(), pad)
    } else {
        let mut data_ack = DataAckStruct::unmarshal(&meta).map_err(wire_io_err)?;
        let prefix = padding::new_padding(&PaddingOpts {
            max_len: max_padding(data_ack.payload_len as usize, 0, PaddingPosition::Middle),
            ascii: Some(AsciiPaddingOpts::default()),
            entropy: None,
        });
        let suffix = padding::new_padding(&PaddingOpts {
            max_len: max_padding(data_ack.payload_len as usize, prefix.len(), PaddingPosition::End),
            ascii: Some(AsciiPaddingOpts::default()),
            entropy: None,
        });
        data_ack.prefix_len = padding_byte_len(prefix.len());
        data_ack.suffix_len = padding_byte_len(suffix.len());
        (data_ack.marshal(), prefix, suffix)
    };

    let encrypted_meta = cipher.encrypt(&meta).map_err(cipher_io_err)?;
    let nonce = nonce_prefix(&encrypted_meta)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "nonce prefix"))?;
    let mut datagram = Vec::with_capacity(
        encrypted_meta.len() + payload.len() + prefix.len() + suffix.len() + cipher::DEFAULT_OVERHEAD,
    );
    datagram.extend_from_slice(&encrypted_meta);
    // The wire order is metadata, then middle padding, then the payload, then end padding; the
    // receiver slices the payload out using the two lengths the metadata carries.
    datagram.extend_from_slice(&prefix);
    if !payload.is_empty() {
        let encrypted_payload = cipher.encrypt_with_nonce(&nonce, payload).map_err(cipher_io_err)?;
        datagram.extend_from_slice(&encrypted_payload);
    }
    datagram.extend_from_slice(&suffix);
    socket.send_to(&datagram, peer).await?;
    Ok(())
}

/// The nonce prefix a datagram — or the encrypted metadata blob at its head — starts with.
fn nonce_prefix(buf: &[u8]) -> Option<[u8; cipher::DEFAULT_NONCE_SIZE]> {
    let prefix = buf.get(..cipher::DEFAULT_NONCE_SIZE)?;
    prefix.try_into().ok()
}

fn wire_io_err(e: wire::WireError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}

fn cipher_io_err(e: cipher::CipherError) -> std::io::Error {
    std::io::Error::other(e)
}

/// One shared `UdpSocket` carrying many [`Session`]s, told apart by session id (and, server-side,
/// by which cached per-session cipher first decrypts a datagram).
pub struct PacketUnderlay {
    inner: Arc<Inner>,
    accept_rx: AsyncMutex<mpsc::Receiver<Arc<Session>>>,
}

impl std::fmt::Debug for PacketUnderlay {
    /// Redacting: the inner state holds ciphers and session entries that must not be logged.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketUnderlay").finish_non_exhaustive()
    }
}

impl PacketUnderlay {
    pub async fn connect(
        dialer: &dyn ClientDialer,
        ctx: &tokio_util::sync::CancellationToken,
        host: &str,
        port: u16,
        password: &[u8],
        username: &str,
        traffic_pattern: Option<Config>,
    ) -> Result<Self> {
        let packet = dialer.dial_packet(ctx, host, port).await?;
        Self::from_dialed(packet, password, username, traffic_pattern)
    }

    pub fn from_dialed(
        dialed: DialedPacket,
        password: &[u8],
        username: &str,
        traffic_pattern: Option<Config>,
    ) -> Result<Self> {
        let block =
            cipher::block_cipher_from_password(password, true).map_err(|_| super::UnderlayError::NoMatchingUser)?;
        block.set_user_name(Some(username.to_owned()));
        block.set_nonce_pattern(traffic_pattern.as_ref().and_then(Config::nonce_pattern));
        let inner = Arc::new(Inner {
            socket: dialed.socket,
            is_client: true,
            client_cipher: Some(Arc::new(block)),
            client_server_addr: Some(dialed.peer_addr),
            sessions: AsyncMutex::new(HashMap::new()),
            users: None,
            mtu: DEFAULT_MTU,
            closed: AtomicBool::new(false),
            local_addr: dialed.local_addr.ok(),
            user_name: Some(username.to_owned()),
            traffic_pattern,
        });

        let (accept_tx, accept_rx) = mpsc::channel(SESSION_ACCEPT_CAPACITY);
        tokio::spawn(run_read_loop(Arc::clone(&inner), accept_tx));
        spawn_idle_sweep(Arc::clone(&inner));
        Ok(Self { inner, accept_rx: AsyncMutex::new(accept_rx) })
    }

    pub fn bound(socket: Arc<dyn PacketIo>, users: ServerUsers, traffic_pattern: Option<Config>) -> Self {
        let local_addr = socket.local_addr().ok();
        let inner = Arc::new(Inner {
            socket,
            is_client: false,
            client_cipher: None,
            client_server_addr: None,
            sessions: AsyncMutex::new(HashMap::new()),
            users: Some(users),
            mtu: DEFAULT_MTU,
            closed: AtomicBool::new(false),
            local_addr,
            user_name: None,
            traffic_pattern,
        });

        let (accept_tx, accept_rx) = mpsc::channel(SESSION_ACCEPT_CAPACITY);
        tokio::spawn(run_read_loop(Arc::clone(&inner), accept_tx));
        spawn_idle_sweep(Arc::clone(&inner));
        Self { inner, accept_rx: AsyncMutex::new(accept_rx) }
    }

    pub async fn dial_session(&self, id: u32) -> Arc<Session> {
        #[expect(
            clippy::expect_used,
            reason = "dial_session is only reachable after from_dialed, which always sets the client cipher"
        )]
        let cipher = self.inner.client_cipher.clone().expect("client cipher");
        #[expect(
            clippy::expect_used,
            reason = "dial_session is only reachable after from_dialed, which always sets the server address"
        )]
        let peer_addr = self.inner.client_server_addr.expect("client peer addr");
        let sink: Arc<dyn SegmentSink> = Arc::new(ClientSink {
            socket: Arc::clone(&self.inner.socket),
            cipher: Arc::clone(&cipher),
            peer_addr,
            traffic_pattern: self.inner.traffic_pattern.clone(),
            mtu: self.inner.mtu,
        });
        let frag = fragment_size(Transport::Packet, self.inner.mtu);
        let session = Arc::new(Session::new(id, true, Transport::Packet, frag, sink, self.client_peer(peer_addr)));
        self.inner.sessions.lock().await.insert(id, SessionEntry { session: Arc::clone(&session), cipher, peer_addr });
        session
    }

    pub async fn accept_session(&self) -> Option<Arc<Session>> {
        self.accept_rx.lock().await.recv().await
    }

    pub async fn session_count(&self) -> usize {
        self.inner.sessions.lock().await.len()
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.socket.local_addr()
    }

    fn client_peer(&self, peer_addr: SocketAddr) -> SessionPeer {
        SessionPeer {
            local_addr: self.inner.local_addr,
            peer_addr: Some(peer_addr),
            user_name: self.inner.user_name.clone(),
        }
    }

    pub async fn close(&self) {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut sessions = self.inner.sessions.lock().await;
        for (_, entry) in sessions.drain() {
            entry.session.force_close();
        }
    }
}

fn spawn_idle_sweep(inner: Arc<Inner>) {
    tokio::spawn(async move {
        // the first tick must land one interval out; `tokio::time::interval` fires at once.
        let mut interval =
            tokio::time::interval_at(tokio::time::Instant::now() + SESSION_SWEEP_INTERVAL, SESSION_SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            if inner.closed.load(Ordering::Acquire) {
                return;
            }
            let mut sessions = inner.sessions.lock().await;
            sessions.retain(|_, entry| {
                let idle = entry.session.is_idle(crate::session::IDLE_SESSION_TIMEOUT);
                if idle {
                    entry.session.force_close();
                }
                !idle
            });
        }
    });
}

/// The metadata blob at the head of one datagram, after decryption, and the user `discover`
/// matched when no cached session cipher opened it.
struct DecryptedMeta {
    cipher: Arc<BlockCipher>,
    plaintext: Vec<u8>,
    discovered_user: Option<String>,
}

/// One incoming segment: the metadata it carried, the payload it described, and the cipher that
/// decrypted it.
struct IncomingSegment {
    cipher: Arc<BlockCipher>,
    protocol: ProtocolType,
    meta: SessionMeta,
    payload: Bytes,
    discovered_user: Option<String>,
}

impl Inner {
    /// Opens one datagram's metadata with the client cipher, the cipher cached for the peer, or
    /// user discovery, in that order.
    async fn decrypt_meta(&self, encrypted_meta: &[u8], peer: SocketAddr) -> Option<DecryptedMeta> {
        if self.is_client {
            let cipher = self.client_cipher.as_ref()?;
            let plaintext = cipher.decrypt(encrypted_meta).ok()?;
            return Some(DecryptedMeta { cipher: Arc::clone(cipher), plaintext, discovered_user: None });
        }
        let cached = {
            let sessions = self.sessions.lock().await;
            sessions.values().find_map(|entry| {
                if entry.peer_addr == peer {
                    entry.cipher.decrypt(encrypted_meta).ok().map(|pt| (Arc::clone(&entry.cipher), pt))
                } else {
                    None
                }
            })
        };
        if let Some((cipher, plaintext)) = cached {
            return Some(DecryptedMeta { cipher, plaintext, discovered_user: None });
        }
        let users = self.users.as_ref()?;
        let (name, block, plaintext) = discover(encrypted_meta, users, true)?;
        block.set_nonce_pattern(self.traffic_pattern.as_ref().and_then(Config::nonce_pattern));
        Some(DecryptedMeta { cipher: Arc::new(block), plaintext, discovered_user: Some(name) })
    }
}

/// Validates the decrypted metadata and decrypts the payload it describes; the nonce prefix sits
/// in the datagram because the metadata and the payload are separate AEAD blobs.
fn decode_segment(encrypted_meta: &[u8], rest: &[u8], decrypted: DecryptedMeta) -> Option<IncomingSegment> {
    if decrypted.plaintext.len() != wire::METADATA_LENGTH {
        return None;
    }
    let protocol_byte = *decrypted.plaintext.first()?;
    let protocol = ProtocolType::from_byte(protocol_byte).ok()?;
    let nonce = nonce_prefix(encrypted_meta)?;
    let (meta, payload) = if protocol.is_session_struct() {
        let meta = SessionStruct::unmarshal(&decrypted.plaintext).ok()?;
        if wire::validate_timestamp(meta.timestamp).is_err() {
            return None;
        }
        let payload = extract_payload(rest, &decrypted.cipher, &nonce, 0, meta.payload_len, meta.suffix_len)?;
        (SessionMeta::Session(meta), payload)
    } else {
        let meta = DataAckStruct::unmarshal(&decrypted.plaintext).ok()?;
        if wire::validate_timestamp(meta.timestamp).is_err() {
            return None;
        }
        let payload =
            extract_payload(rest, &decrypted.cipher, &nonce, meta.prefix_len, meta.payload_len, meta.suffix_len)?;
        (SessionMeta::DataAck(meta), payload)
    };
    Some(IncomingSegment {
        cipher: decrypted.cipher,
        protocol,
        meta,
        payload,
        discovered_user: decrypted.discovered_user,
    })
}

/// Dispatch is on the session protocol first: an open request creates its session, a repeated id
/// is dropped, and only a data segment for an unknown session asks the peer to close it.
async fn route_segment(
    inner: &Arc<Inner>,
    accept_tx: &mpsc::Sender<Arc<Session>>,
    peer: SocketAddr,
    segment: IncomingSegment,
) {
    let IncomingSegment { cipher, protocol, meta, payload, discovered_user } = segment;
    let session_id = match &meta {
        SessionMeta::Session(s) => s.session_id,
        SessionMeta::DataAck(d) => d.session_id,
    };

    let existing = inner.sessions.lock().await.get(&session_id).map(|e| Arc::clone(&e.session));
    if protocol == ProtocolType::OpenSessionRequest && !inner.is_client {
        if existing.is_some() {
            return;
        }
        let sink: Arc<dyn SegmentSink> = Arc::new(ServerSink { inner: Arc::clone(inner), session_id });
        let frag = fragment_size(Transport::Packet, inner.mtu);
        let session_peer =
            SessionPeer { local_addr: inner.local_addr, peer_addr: Some(peer), user_name: discovered_user };
        let session = Arc::new(Session::new(session_id, false, Transport::Packet, frag, sink, session_peer));
        inner
            .sessions
            .lock()
            .await
            .insert(session_id, SessionEntry { session: Arc::clone(&session), cipher, peer_addr: peer });
        let _ = session.handle_incoming(protocol, meta, payload).await;
        let _ = accept_tx.send(session).await;
        return;
    }

    match existing {
        Some(session) => {
            if matches!(session.handle_incoming(protocol, meta, payload).await, Err(SessionError::ProtocolDirection)) {
                send_close_reply(&inner.socket, &cipher, peer, session_id, inner.traffic_pattern.as_ref(), inner.mtu)
                    .await;
            }
        }
        None if protocol.is_session_struct() => {}
        None => {
            send_close_reply(&inner.socket, &cipher, peer, session_id, inner.traffic_pattern.as_ref(), inner.mtu).await;
        }
    }
}

async fn run_read_loop(inner: Arc<Inner>, accept_tx: mpsc::Sender<Arc<Session>>) {
    let mut buf = vec![0u8; 65535];
    loop {
        let Ok((n, peer)) = inner.socket.recv_from(&mut buf).await else { break };
        let Some(datagram) = buf.get(..n) else { continue };
        if datagram.len() < DATAGRAM_HEADER_LEN {
            continue;
        }
        let (encrypted_meta, rest) = datagram.split_at(DATAGRAM_HEADER_LEN);

        // Discovery and the session cache only ever get the encrypted metadata, never the payload.
        let Some(decrypted) = inner.decrypt_meta(encrypted_meta, peer).await else { continue };
        let Some(segment) = decode_segment(encrypted_meta, rest, decrypted) else { continue };

        route_segment(&inner, &accept_tx, peer, segment).await;
    }

    // A packet underlay whose event loop returns is closed: its sessions are torn down, so a
    // reader parked on one of them is woken rather than left waiting for datagrams.
    inner.closed.store(true, Ordering::Release);
    let mut sessions = inner.sessions.lock().await;
    for (_, entry) in sessions.drain() {
        entry.session.force_close_with_error(ReadEnd::UnderlayLost);
    }
}

fn extract_payload(
    rest: &[u8],
    cipher: &BlockCipher,
    nonce: &[u8; cipher::DEFAULT_NONCE_SIZE],
    prefix_len: u8,
    payload_len: u16,
    suffix_len: u8,
) -> Option<Bytes> {
    let mut offset = prefix_len as usize;
    let payload = if payload_len > 0 {
        let end = offset.checked_add(payload_len as usize + cipher::DEFAULT_OVERHEAD)?;
        let ciphertext = rest.get(offset..end)?;
        let plaintext = cipher.decrypt_with_nonce(nonce, ciphertext).ok()?;
        offset = end;
        Bytes::from(plaintext)
    } else {
        Bytes::new()
    };
    offset = offset.checked_add(suffix_len as usize)?;
    let _ = rest.get(..offset)?;
    Some(payload)
}

async fn send_close_reply(
    socket: &dyn PacketIo,
    cipher: &BlockCipher,
    peer: SocketAddr,
    session_id: u32,
    traffic_pattern: Option<&Config>,
    mtu: usize,
) {
    let meta = SessionStruct {
        protocol: ProtocolType::CloseSessionRequest as u8,
        timestamp: wire::now_minutes(),
        session_id,
        seq: 0,
        status_code: wire::STATUS_OK,
        payload_len: 0,
        suffix_len: 0,
    };
    let _ = send_datagram(socket, cipher, peer, meta.marshal(), &[], traffic_pattern, mtu).await;
}

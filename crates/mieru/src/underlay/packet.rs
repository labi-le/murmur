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

/// Sessions keyed by id, plus the peer index the server uses to find the ciphers that may open a
/// datagram before session-id routing. The index has no independent lifetime: insert, retain and
/// drain update both maps together, so an evicted session cannot leave a candidate behind.
#[derive(Default)]
struct SessionTable {
    entries: HashMap<u32, SessionEntry>,
    session_ids_by_peer: HashMap<SocketAddr, Vec<u32>>,
}

impl SessionTable {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&self, id: u32) -> Option<&SessionEntry> {
        self.entries.get(&id)
    }

    fn insert(&mut self, id: u32, entry: SessionEntry) {
        let peer_addr = entry.peer_addr;
        if let Some(previous) = self.entries.insert(id, entry) {
            self.unindex(previous.peer_addr, id);
        }
        self.session_ids_by_peer.entry(peer_addr).or_default().push(id);
    }

    fn retain(&mut self, mut keep: impl FnMut(u32, &SessionEntry) -> bool) {
        let before = self.entries.len();
        self.entries.retain(|id, entry| keep(*id, entry));
        if self.entries.len() == before {
            return;
        }
        // One pass over the index, not one linear search per removed id: many idle sessions on
        // one endpoint must not turn the sweep quadratic while the sessions mutex is held.
        let entries = &self.entries;
        self.session_ids_by_peer.retain(|_, ids| {
            ids.retain(|id| entries.contains_key(id));
            !ids.is_empty()
        });
    }

    fn drain(&mut self) -> impl Iterator<Item = (u32, SessionEntry)> + '_ {
        self.session_ids_by_peer.clear();
        self.entries.drain()
    }

    /// Every session owned by `peer_addr`, in insertion order. One datagram is offered to each
    /// cached cipher until one opens it; discovery is the caller's fallback.
    fn candidates(&self, peer_addr: SocketAddr) -> impl Iterator<Item = &SessionEntry> {
        self.session_ids_by_peer.get(&peer_addr).into_iter().flatten().filter_map(|id| self.entries.get(id))
    }

    fn unindex(&mut self, peer_addr: SocketAddr, id: u32) {
        let Some(ids) = self.session_ids_by_peer.get_mut(&peer_addr) else { return };
        if let Some(position) = ids.iter().position(|candidate| *candidate == id) {
            ids.swap_remove(position);
        }
        if ids.is_empty() {
            self.session_ids_by_peer.remove(&peer_addr);
        }
    }
}

struct Inner {
    socket: Arc<dyn PacketIo>,
    is_client: bool,
    client_cipher: Option<Arc<BlockCipher>>,
    client_server_addr: Option<SocketAddr>,
    sessions: AsyncMutex<SessionTable>,
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
            let Some(entry) = sessions.get(self.session_id) else {
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
    let mut datagram = Vec::with_capacity(
        encrypted_meta.len()
            + prefix.len()
            + payload.len()
            + cipher::DEFAULT_NONCE_SIZE
            + cipher::DEFAULT_OVERHEAD
            + suffix.len(),
    );
    datagram.extend_from_slice(&encrypted_meta);
    // The wire order is metadata, then middle padding, then the payload, then end padding; the
    // receiver slices the payload out using the two lengths the metadata carries.
    datagram.extend_from_slice(&prefix);
    if !payload.is_empty() {
        // A payload sealed under the metadata's nonce would reuse that keystream and Poly1305 key.
        let encrypted_payload = cipher.encrypt(payload).map_err(cipher_io_err)?;
        datagram.extend_from_slice(&encrypted_payload);
    }
    datagram.extend_from_slice(&suffix);
    socket.send_to(&datagram, peer).await?;
    Ok(())
}

fn wire_io_err(e: wire::WireError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}

fn cipher_io_err(e: cipher::CipherError) -> std::io::Error {
    std::io::Error::other(e)
}

/// One shared `UdpSocket` carrying many [`Session`]s.
///
/// Server-side, the session table also indexes session ids by peer address, so an incoming
/// datagram is offered only the ciphers cached for its source endpoint before user discovery;
/// routing then uses the decrypted session id.
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
            sessions: AsyncMutex::new(SessionTable::default()),
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
            sessions: AsyncMutex::new(SessionTable::default()),
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
    /// Opens one datagram's metadata with the client cipher, the ciphers indexed for the peer, or
    /// user discovery, in that order.
    async fn decrypt_meta(&self, encrypted_meta: &[u8], peer: SocketAddr) -> Option<DecryptedMeta> {
        if self.is_client {
            let cipher = self.client_cipher.as_ref()?;
            let plaintext = cipher.decrypt(encrypted_meta).ok()?;
            return Some(DecryptedMeta { cipher: Arc::clone(cipher), plaintext, discovered_user: None });
        }
        let cached = {
            let sessions = self.sessions.lock().await;
            let opened = sessions
                .candidates(peer)
                .find_map(|entry| entry.cipher.decrypt(encrypted_meta).ok().map(|pt| (Arc::clone(&entry.cipher), pt)));
            opened
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
fn decode_segment(rest: &[u8], decrypted: DecryptedMeta) -> Option<IncomingSegment> {
    if decrypted.plaintext.len() != wire::METADATA_LENGTH {
        return None;
    }
    let protocol_byte = *decrypted.plaintext.first()?;
    let protocol = ProtocolType::from_byte(protocol_byte).ok()?;
    let (meta, payload) = if protocol.is_session_struct() {
        let meta = SessionStruct::unmarshal(&decrypted.plaintext).ok()?;
        if wire::validate_timestamp(meta.timestamp).is_err() {
            return None;
        }
        let payload = extract_payload(rest, &decrypted.cipher, 0, meta.payload_len, meta.suffix_len)?;
        (SessionMeta::Session(meta), payload)
    } else {
        let meta = DataAckStruct::unmarshal(&decrypted.plaintext).ok()?;
        if wire::validate_timestamp(meta.timestamp).is_err() {
            return None;
        }
        let payload = extract_payload(rest, &decrypted.cipher, meta.prefix_len, meta.payload_len, meta.suffix_len)?;
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

    let existing = inner.sessions.lock().await.get(session_id).map(|e| Arc::clone(&e.session));
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
        let Some(segment) = decode_segment(rest, decrypted) else { continue };

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
    prefix_len: u8,
    payload_len: u16,
    suffix_len: u8,
) -> Option<Bytes> {
    let mut offset = prefix_len as usize;
    let payload = if payload_len > 0 {
        let end = offset.checked_add(payload_len as usize + cipher::DEFAULT_NONCE_SIZE + cipher::DEFAULT_OVERHEAD)?;
        let ciphertext = rest.get(offset..end)?;
        let plaintext = cipher.decrypt(ciphertext).ok()?;
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;

    use tokio::io::AsyncReadExt;

    use crate::session::SessionStream;

    use super::*;

    #[derive(Default)]
    struct RecordingSocket(StdMutex<Vec<u8>>);

    #[async_trait::async_trait]
    impl PacketIo for RecordingSocket {
        async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }

        async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> std::io::Result<usize> {
            self.0.lock().expect("recording socket lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(SocketAddr::from(([192, 0, 2, 1], 9)))
        }
    }

    /// A datagram's metadata and payload must be sealed under distinct nonces: one nonce for both
    /// reuses the keystream and the Poly1305 one-time key across two messages.
    #[tokio::test]
    async fn a_datagrams_metadata_and_payload_carry_separate_nonces() {
        let socket = RecordingSocket::default();
        let cipher = cipher::block_cipher_from_password(b"pw", true).expect("derive");
        cipher.set_user_name(Some("bob".to_owned()));
        let ack = DataAckStruct {
            protocol: ProtocolType::DataClientToServer as u8,
            timestamp: wire::now_minutes(),
            payload_len: 7,
            ..DataAckStruct::default()
        };
        let peer: SocketAddr = "192.0.2.1:9".parse().expect("peer addr");
        send_datagram(&socket, &cipher, peer, ack.marshal(), b"payload", None, DEFAULT_MTU).await.expect("send");

        let datagram = socket.0.lock().expect("recording socket lock").clone();
        let (encrypted_meta, rest) = datagram.split_at(DATAGRAM_HEADER_LEN);
        let plaintext = cipher.decrypt(encrypted_meta).expect("metadata opens");
        let meta = DataAckStruct::unmarshal(&plaintext).expect("metadata");
        let start = meta.prefix_len as usize;
        let end = start + meta.payload_len as usize + cipher::DEFAULT_NONCE_SIZE + cipher::DEFAULT_OVERHEAD;
        let payload_blob = rest.get(start..end).expect("payload blob with its own nonce prefix");

        assert_ne!(
            payload_blob.get(..cipher::DEFAULT_NONCE_SIZE).expect("payload nonce"),
            encrypted_meta.get(..cipher::DEFAULT_NONCE_SIZE).expect("metadata nonce"),
            "the payload must not be sealed under the metadata's nonce"
        );
        assert_eq!(cipher.decrypt(payload_blob).expect("payload opens under its own nonce"), b"payload");

        let segment =
            decode_segment(rest, DecryptedMeta { cipher: Arc::new(cipher), plaintext, discovered_user: None })
                .expect("segment decodes");
        assert_eq!(segment.payload, Bytes::from_static(b"payload"));
    }

    struct NullSink;

    #[async_trait::async_trait]
    impl SegmentSink for NullSink {
        async fn send_segment(&self, _meta: [u8; wire::METADATA_LENGTH], _payload: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn test_inner(sessions: SessionTable) -> Inner {
        Inner {
            socket: Arc::new(RecordingSocket::default()),
            is_client: false,
            client_cipher: None,
            client_server_addr: None,
            sessions: AsyncMutex::new(sessions),
            users: None,
            mtu: DEFAULT_MTU,
            closed: AtomicBool::new(false),
            local_addr: None,
            user_name: None,
            traffic_pattern: None,
        }
    }

    fn test_entry(id: u32, cipher: Arc<BlockCipher>, peer: SocketAddr) -> SessionEntry {
        let session = Arc::new(Session::new(
            id,
            false,
            Transport::Stream,
            1024,
            Arc::new(NullSink),
            SessionPeer { peer_addr: Some(peer), ..SessionPeer::default() },
        ));
        SessionEntry { session, cipher, peer_addr: peer }
    }

    #[tokio::test]
    #[ignore = "peer-index benchmark; run with --ignored --nocapture"]
    async fn benchmark_decrypt_meta_peer_lookup() {
        let cipher = Arc::new(cipher::block_cipher_from_password(b"bench-pw", true).expect("cipher"));
        let meta = SessionStruct {
            protocol: ProtocolType::OpenSessionRequest as u8,
            timestamp: wire::now_minutes(),
            session_id: 1,
            seq: 0,
            status_code: wire::STATUS_OK,
            payload_len: 0,
            suffix_len: 0,
        };
        let encrypted = cipher.encrypt(&meta.marshal()).expect("metadata");
        let missing: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 65000));

        for peers in [1usize, 32, 256, 4096] {
            let mut sessions = SessionTable::default();
            let mut addresses = Vec::with_capacity(peers);
            for i in 0..peers {
                let peer = SocketAddr::from(([127, 0, 0, 1], 10000 + i as u16));
                addresses.push(peer);
                sessions.insert(i as u32 + 1, test_entry(i as u32 + 1, Arc::clone(&cipher), peer));
            }
            let inner = test_inner(sessions);
            for peer in &addresses {
                assert!(inner.decrypt_meta(&encrypted, *peer).await.is_some());
            }
            let rounds = 20_000usize;
            let started = std::time::Instant::now();
            for i in 0..rounds {
                assert!(inner.decrypt_meta(&encrypted, addresses[i % peers]).await.is_some());
            }
            let hit = started.elapsed() / u32::try_from(rounds).expect("rounds fit");
            let started = std::time::Instant::now();
            for _ in 0..rounds {
                assert!(inner.decrypt_meta(&encrypted, missing).await.is_none());
            }
            let miss = started.elapsed() / u32::try_from(rounds).expect("rounds fit");
            println!("peers={peers} hit={}ns miss={}ns", hit.as_nanos(), miss.as_nanos());
        }

        for sessions_per_peer in [1usize, 32, 256, 4096] {
            let peer = SocketAddr::from(([127, 0, 0, 1], 10000));
            let mut sessions = SessionTable::default();
            for i in 0..sessions_per_peer {
                let key = format!("bench-pw-{i}");
                let entry_cipher = Arc::new(cipher::block_cipher_from_password(key.as_bytes(), true).expect("cipher"));
                sessions.insert(i as u32 + 1, test_entry(i as u32 + 1, entry_cipher, peer));
            }
            let target = Arc::clone(
                &sessions.get(u32::try_from(sessions_per_peer).expect("fits")).expect("last session").cipher,
            );
            let encrypted = target.encrypt(&meta.marshal()).expect("metadata");
            let inner = test_inner(sessions);
            let rounds = 200usize;
            let started = std::time::Instant::now();
            for _ in 0..rounds {
                assert!(inner.decrypt_meta(&encrypted, peer).await.is_some());
            }
            let hit = started.elapsed() / u32::try_from(rounds).expect("rounds fit");
            println!("same_peer_sessions={sessions_per_peer} hit={}ns", hit.as_nanos());
        }
    }

    /// A peer may present metadata under any cipher it has used on this underlay. The indexed
    /// candidates keep every session's cipher, so a later one still opens its own datagram.
    #[tokio::test]
    async fn a_later_cipher_for_the_same_peer_still_opens_metadata() {
        let peer: SocketAddr = "192.0.2.7:4321".parse().expect("peer");
        let first = Arc::new(cipher::block_cipher_from_password(b"first-key", true).expect("first cipher"));
        let second = Arc::new(cipher::block_cipher_from_password(b"second-key", true).expect("second cipher"));
        let inner = test_inner(SessionTable::default());
        {
            let mut sessions = inner.sessions.lock().await;
            sessions.insert(1, test_entry(1, Arc::clone(&first), peer));
            sessions.insert(2, test_entry(2, Arc::clone(&second), peer));
        }
        let meta = SessionStruct {
            protocol: ProtocolType::OpenSessionRequest as u8,
            timestamp: wire::now_minutes(),
            session_id: 2,
            seq: 0,
            status_code: wire::STATUS_OK,
            payload_len: 0,
            suffix_len: 0,
        };
        let encrypted = second.encrypt(&meta.marshal()).expect("metadata");
        let decrypted = inner.decrypt_meta(&encrypted, peer).await.expect("the later candidate opens it");
        assert_eq!(decrypted.plaintext, meta.marshal());
    }

    /// A rotated credential on an endpoint that already owns a session must still reach discovery:
    /// the peer candidates are tried first, and a miss does not close the path.
    #[tokio::test]
    async fn a_rotated_cipher_falls_through_peer_candidates_to_discovery() {
        let (users, current) = server_cipher("bob", "rotated-secret");
        let peer: SocketAddr = "192.0.2.7:4321".parse().expect("peer");
        let old = Arc::new(cipher::block_cipher_from_password(b"old-key", true).expect("old cipher"));
        let mut sessions = SessionTable::default();
        sessions.insert(1, test_entry(1, old, peer));
        let inner = Inner { users: Some(users), ..test_inner(sessions) };
        let meta = SessionStruct {
            protocol: ProtocolType::OpenSessionRequest as u8,
            timestamp: wire::now_minutes(),
            session_id: 2,
            seq: 0,
            status_code: wire::STATUS_OK,
            payload_len: 0,
            suffix_len: 0,
        };
        let encrypted = current.encrypt(&meta.marshal()).expect("metadata");

        let decrypted = inner.decrypt_meta(&encrypted, peer).await.expect("discovery opens the rotated key");
        assert_eq!(decrypted.discovered_user.as_deref(), Some("bob"));
        assert_eq!(decrypted.plaintext, meta.marshal());
    }

    /// Eviction is the sweep's retain: dropping an entry must drop its peer candidate too, and an
    /// empty peer bucket must not survive.
    #[tokio::test]
    async fn evicting_a_session_removes_its_peer_candidates() {
        let first_peer: SocketAddr = "192.0.2.7:4321".parse().expect("peer");
        let second_peer: SocketAddr = "192.0.2.8:4321".parse().expect("peer");
        let cipher = Arc::new(cipher::block_cipher_from_password(b"key", true).expect("cipher"));
        let mut sessions = SessionTable::default();
        sessions.insert(1, test_entry(1, Arc::clone(&cipher), first_peer));
        sessions.insert(2, test_entry(2, Arc::clone(&cipher), first_peer));
        sessions.insert(3, test_entry(3, cipher, second_peer));

        sessions.retain(|id, _| id != 1);
        let kept: Vec<u32> = sessions.candidates(first_peer).map(|entry| entry.session.id()).collect();
        assert_eq!(kept, vec![2]);

        sessions.retain(|_, _| false);
        assert_eq!(sessions.len(), 0);
        assert!(sessions.candidates(first_peer).next().is_none());
        assert!(sessions.candidates(second_peer).next().is_none());
        assert!(sessions.session_ids_by_peer.is_empty());
    }

    /// A sweep that drops many sessions from one endpoint must leave a consistent index without a
    /// per-removal walk of the same peer bucket.
    #[tokio::test]
    async fn evicting_many_same_peer_sessions_leaves_a_consistent_index() {
        let peer: SocketAddr = "192.0.2.7:4321".parse().expect("peer");
        let cipher = Arc::new(cipher::block_cipher_from_password(b"key", true).expect("cipher"));
        let mut sessions = SessionTable::default();
        for id in 1..=4096 {
            sessions.insert(id, test_entry(id, Arc::clone(&cipher), peer));
        }

        sessions.retain(|id, _| id % 2 == 0);

        assert_eq!(sessions.len(), 2048);
        let kept: Vec<u32> = sessions.candidates(peer).map(|entry| entry.session.id()).collect();
        assert_eq!(kept.len(), 2048);
        assert!(kept.iter().all(|id| id % 2 == 0));
    }

    /// Closing the underlay drains every session and the peer buckets along with it.
    #[tokio::test]
    async fn closing_an_underlay_drops_sessions_and_peer_candidates() {
        let socket = Arc::new(RecordingSocket::default());
        let underlay = PacketUnderlay::bound(socket, ServerUsers::new(&HashMap::new(), false), None);
        let peer: SocketAddr = "192.0.2.7:4321".parse().expect("peer");
        let cipher = Arc::new(cipher::block_cipher_from_password(b"key", true).expect("cipher"));
        {
            let mut sessions = underlay.inner.sessions.lock().await;
            sessions.insert(1, test_entry(1, Arc::clone(&cipher), peer));
            sessions.insert(2, test_entry(2, cipher, peer));
        }
        assert_eq!(underlay.session_count().await, 2);

        underlay.close().await;

        assert_eq!(underlay.session_count().await, 0);
        assert!(underlay.inner.sessions.lock().await.session_ids_by_peer.is_empty());
    }

    #[derive(Default)]
    struct QueueSocket {
        incoming: AsyncMutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        outgoing: AsyncMutex<Vec<(Vec<u8>, SocketAddr)>>,
        notify: tokio::sync::Notify,
    }

    impl QueueSocket {
        async fn push(&self, datagram: Vec<u8>, peer: SocketAddr) {
            self.incoming.lock().await.push_back((datagram, peer));
            self.notify.notify_one();
        }
    }

    #[async_trait::async_trait]
    impl PacketIo for QueueSocket {
        async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            loop {
                let notified = self.notify.notified();
                {
                    let mut incoming = self.incoming.lock().await;
                    if let Some((datagram, peer)) = incoming.pop_front() {
                        let len = datagram.len().min(buf.len());
                        buf.get_mut(..len).expect("bounds").copy_from_slice(datagram.get(..len).expect("bounds"));
                        return Ok((len, peer));
                    }
                }
                notified.await;
            }
        }

        async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
            self.outgoing.lock().await.push((buf.to_vec(), target));
            Ok(buf.len())
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(SocketAddr::from(([192, 0, 2, 1], 9)))
        }
    }

    fn server_cipher(user: &str, password: &str) -> (ServerUsers, Arc<BlockCipher>) {
        let users = HashMap::from([(user.to_owned(), password.to_owned())]);
        let users = ServerUsers::new(&users, false);
        let credential = cipher::hash_password(password.as_bytes(), user.as_bytes());
        let cipher = cipher::block_cipher_from_password(&credential, true).expect("client cipher");
        (users, Arc::new(cipher))
    }

    fn open_datagram(cipher: &BlockCipher, session_id: u32) -> Vec<u8> {
        let meta = SessionStruct {
            protocol: ProtocolType::OpenSessionRequest as u8,
            timestamp: wire::now_minutes(),
            session_id,
            seq: 0,
            status_code: wire::STATUS_OK,
            payload_len: 0,
            suffix_len: 0,
        };
        cipher.encrypt(&meta.marshal()).expect("metadata")
    }

    fn data_datagram(cipher: &BlockCipher, session_id: u32, seq: u32, payload: &[u8]) -> Vec<u8> {
        let meta = DataAckStruct {
            protocol: ProtocolType::DataClientToServer as u8,
            timestamp: wire::now_minutes(),
            session_id,
            seq,
            payload_len: u16::try_from(payload.len()).expect("payload fits"),
            ..DataAckStruct::default()
        };
        let mut datagram = cipher.encrypt(&meta.marshal()).expect("metadata");
        datagram.extend_from_slice(&cipher.encrypt(payload).expect("payload"));
        datagram
    }

    /// The read loop resolves each datagram through the peer index, accepts two authenticated
    /// sessions, delivers payload on one, and leaves a wrong-key open request without a session.
    #[tokio::test]
    async fn a_bound_underlay_authenticates_multiple_sessions_and_rejects_a_wrong_key() {
        let (users, cipher) = server_cipher("bob", "another-secret");
        let (_, wrong_cipher) = server_cipher("mallory", "not-configured");
        let socket = Arc::new(QueueSocket::default());
        let packet_io = Arc::clone(&socket);
        let packet_io: Arc<dyn PacketIo> = packet_io;
        let underlay = PacketUnderlay::bound(packet_io, users, None);
        let first_peer: SocketAddr = "198.51.100.10:40000".parse().expect("peer");
        let second_peer: SocketAddr = "198.51.100.11:40000".parse().expect("peer");
        let wrong_peer: SocketAddr = "198.51.100.12:40000".parse().expect("peer");
        let timeout = Duration::from_secs(2);

        socket.push(open_datagram(&cipher, 7), first_peer).await;
        let first = tokio::time::timeout(timeout, underlay.accept_session())
            .await
            .expect("first session accepted")
            .expect("session");
        assert_eq!(first.id(), 7);
        assert_eq!(first.user_name(), Some("bob"));

        socket.push(open_datagram(&cipher, 8), second_peer).await;
        let second = tokio::time::timeout(timeout, underlay.accept_session())
            .await
            .expect("second session accepted")
            .expect("session");
        assert_eq!(second.id(), 8);

        let mut stream = SessionStream::new(Arc::clone(&first));
        socket.push(data_datagram(&cipher, 7, 1, b"hello"), first_peer).await;
        let mut payload = [0u8; 5];
        tokio::time::timeout(timeout, stream.read_exact(&mut payload)).await.expect("payload read").expect("payload");
        assert_eq!(&payload, b"hello");

        socket.push(open_datagram(&wrong_cipher, 9), wrong_peer).await;
        socket.push(open_datagram(&cipher, 10), second_peer).await;
        let third = tokio::time::timeout(timeout, underlay.accept_session())
            .await
            .expect("third session accepted")
            .expect("session");
        assert_eq!(third.id(), 10, "the wrong-key open request must not create a session");
        assert_eq!(underlay.session_count().await, 3);

        underlay.close().await;
        assert_eq!(underlay.session_count().await, 0);
    }
}

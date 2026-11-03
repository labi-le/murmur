use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

use crate::cipher::{self, BlockCipher};
use crate::io::{ClientDialer, DialedStream, Stream};
use crate::padding::{self, AsciiPaddingOpts, PaddingOpts, PaddingPosition};
use crate::session::{ReadEnd, SegmentSink, Session, SessionMeta, SessionPeer, SessionState, Transport};
use crate::trafficpattern::{self, Config};
use crate::wire::{self, DataAckStruct, ProtocolType, SessionStruct};

use super::{discover, fragment_size, Result, ServerUsers, UnderlayError, DEFAULT_MTU};

const SESSION_ACCEPT_CAPACITY: usize = 64;
const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
/// `streamOverhead = MetadataLength + cipher.DefaultOverhead*2`, the random data the recommended
/// padding strategy measures its entropy against.
const STREAM_OVERHEAD: usize = wire::METADATA_LENGTH + cipher::DEFAULT_OVERHEAD * 2;

/// The write side of the socket together with the send cipher, which mieru creates on the first
/// segment (lazily initialized) and keeps for the life of the connection. One lock covers
/// both, so segments cannot interleave and desynchronize the implicit nonce sequence.
struct Writer {
    half: WriteHalf<Stream>,
    cipher: Option<BlockCipher>,
}

struct Inner {
    read_half: AsyncMutex<ReadHalf<Stream>>,
    writer: AsyncMutex<Writer>,
    is_client: bool,
    /// The client's key template, cloned into the send cipher and into the recv
    /// cipher the first segment needs.
    client_block: Option<BlockCipher>,
    users: Option<ServerUsers>,
    sessions: AsyncMutex<HashMap<u32, Arc<Session>>>,
    /// Set once the first segment has been opened. A `None` here is what
    /// makes the next read expect the 24-byte nonce on the wire.
    recv: AsyncMutex<Option<BlockCipher>>,
    closed: AtomicBool,
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
    /// The name this side authenticated as: the configured one client-side, the one
    /// `Registry::discover` matched server-side.
    user_name: Option<String>,
    /// The `traffic-pattern` this underlay was built with, if any. Drives nonce shaping, segment
    /// padding and TCP write fragmentation; absent means mieru's unpadded default.
    traffic_pattern: Option<Config>,
    mtu: usize,
}

impl Inner {
    /// Initializes the send block cipher lazily. A client sends under a fresh clone of its own key; a server
    /// answers under a clone of the cipher the first segment established, with the implicit nonce
    /// cleared so the two directions run independent nonce sequences.
    async fn init_send_cipher(&self) -> Result<BlockCipher> {
        if let Some(block) = &self.client_block {
            return Ok(block.clone_full());
        }
        let send = self.recv.lock().await.as_ref().ok_or(UnderlayError::Closed)?.clone_full();
        send.set_implicit_nonce_mode(false);
        send.set_implicit_nonce_mode(true);
        Ok(send)
    }

    /// The fragmentation switch: off unless the effective pattern enables it.
    fn traffic_fragment(&self) -> Option<i32> {
        self.traffic_pattern
            .as_ref()
            .and_then(Config::tcp_fragment)
            .filter(|(enabled, _)| *enabled)
            .map(|(_, max_sleep_ms)| max_sleep_ms)
    }

    fn max_padding(&self, fragment_size: usize, existing: usize, position: PaddingPosition) -> usize {
        padding::max_padding_size_with_traffic_pattern(
            self.traffic_pattern.as_ref(),
            Transport::Stream,
            self.mtu,
            fragment_size,
            existing,
            position,
        )
    }

    fn peer_facts(&self, user_name: Option<String>) -> SessionPeer {
        SessionPeer { local_addr: self.local_addr, peer_addr: self.peer_addr, user_name }
    }
}

/// One multiplexed `TcpStream` shared by many [`Session`]s.
pub struct StreamUnderlay {
    inner: Arc<Inner>,
    accept_rx: AsyncMutex<mpsc::Receiver<Arc<Session>>>,
}

impl core::fmt::Debug for StreamUnderlay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The socket halves and the ciphers are not printable.
        f.debug_struct("StreamUnderlay")
            .field("is_client", &self.inner.is_client)
            .field("local_addr", &self.inner.local_addr)
            .field("peer_addr", &self.inner.peer_addr)
            .finish_non_exhaustive()
    }
}

impl StreamUnderlay {
    pub async fn connect(
        dialer: &dyn ClientDialer,
        ctx: &tokio_util::sync::CancellationToken,
        host: &str,
        port: u16,
        password: &[u8],
        username: &str,
        traffic_pattern: Option<Config>,
    ) -> Result<Self> {
        let connection = dialer.dial_stream(ctx, host, port).await?;
        Self::from_dialed(connection, true, None, Some((password, username)), traffic_pattern)
    }

    pub fn from_accepted(
        accepted: crate::io::AcceptedStream,
        users: ServerUsers,
        traffic_pattern: Option<Config>,
    ) -> Result<Self> {
        if users.is_empty() {
            return Err(UnderlayError::NoMatchingUser);
        }
        Self::from_parts(accepted, false, Some(users), None, traffic_pattern)
    }

    pub fn from_dialed(
        dialed: DialedStream,
        is_client: bool,
        users: Option<ServerUsers>,
        client_secret: Option<(&[u8], &str)>,
        traffic_pattern: Option<Config>,
    ) -> Result<Self> {
        Self::from_parts(
            crate::io::AcceptedStream {
                stream: dialed.stream,
                local_addr: dialed.local_addr,
                peer_addr: dialed.peer_addr,
            },
            is_client,
            users,
            client_secret,
            traffic_pattern,
        )
    }

    fn from_parts(
        accepted: crate::io::AcceptedStream,
        is_client: bool,
        users: Option<ServerUsers>,
        client_secret: Option<(&[u8], &str)>,
        traffic_pattern: Option<Config>,
    ) -> Result<Self> {
        let template = client_secret
            .map(|(password, username)| -> Result<BlockCipher> {
                let block =
                    cipher::block_cipher_from_password(password, false).map_err(|_| UnderlayError::NoMatchingUser)?;
                block.set_user_name(Some(username.to_owned()));
                Ok(block)
            })
            .transpose()?;
        if let (Some(block), Some(config)) = (template.as_ref(), traffic_pattern.as_ref()) {
            block.set_nonce_pattern(config.nonce_pattern());
        }

        let crate::io::AcceptedStream { stream, local_addr, peer_addr } = accepted;
        let (read_half, write_half) = tokio::io::split(stream);
        let inner = Arc::new(Inner {
            read_half: AsyncMutex::new(read_half),
            writer: AsyncMutex::new(Writer { half: write_half, cipher: None }),
            is_client,
            user_name: template.as_ref().and_then(BlockCipher::user_name),
            client_block: template,
            users,
            sessions: AsyncMutex::new(HashMap::new()),
            recv: AsyncMutex::new(None),
            closed: AtomicBool::new(false),
            local_addr: local_addr.ok(),
            peer_addr: peer_addr.ok(),
            traffic_pattern,
            mtu: DEFAULT_MTU,
        });

        let (accept_tx, accept_rx) = mpsc::channel(SESSION_ACCEPT_CAPACITY);
        tokio::spawn(run_read_loop(Arc::clone(&inner), accept_tx));
        spawn_session_sweep(Arc::clone(&inner));
        Ok(Self { inner, accept_rx: AsyncMutex::new(accept_rx) })
    }

    pub async fn dial_session(&self, id: u32) -> Arc<Session> {
        let sink = Arc::clone(&self.inner);
        let sink: Arc<dyn SegmentSink> = sink;
        let session = Arc::new(Session::new(
            id,
            true,
            Transport::Stream,
            fragment_size(Transport::Stream, self.inner.mtu),
            sink,
            self.inner.peer_facts(self.inner.user_name.clone()),
        ));
        self.inner.sessions.lock().await.insert(id, Arc::clone(&session));
        session
    }

    pub async fn accept_session(&self) -> Option<Arc<Session>> {
        self.accept_rx.lock().await.recv().await
    }

    pub async fn session_count(&self) -> usize {
        self.inner.sessions.lock().await.len()
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr
    }

    pub async fn close(&self) {
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        // A close shuts the write side down, which is what lets the peer's read loop return.
        let _ = self.inner.writer.lock().await.half.shutdown().await;
        let mut sessions = self.inner.sessions.lock().await;
        for (_, session) in sessions.drain() {
            session.force_close();
        }
    }
}

/// One decoded incoming segment, still to be demultiplexed onto a session.
struct Incoming {
    protocol: ProtocolType,
    meta: SessionMeta,
    payload: Bytes,
    /// The user the first segment authenticated as, which only the server learns by trying keys.
    user_name: Option<String>,
}

fn spawn_session_sweep(inner: Arc<Inner>) {
    tokio::spawn(async move {
        // the first tick must land one interval out; `tokio::time::interval` fires at once.
        let mut interval =
            tokio::time::interval_at(tokio::time::Instant::now() + SESSION_SWEEP_INTERVAL, SESSION_SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            if inner.closed.load(Ordering::Acquire) {
                return;
            }
            inner.sessions.lock().await.retain(|_, session| session.state() != SessionState::Closed);
        }
    });
}

async fn run_read_loop(inner: Arc<Inner>, accept_tx: mpsc::Sender<Arc<Session>>) {
    loop {
        let Ok(incoming) = read_one_segment(&inner).await else { break };
        dispatch(&inner, &accept_tx, incoming).await;
    }
    // The event loop returns with the connection already closed: the sessions it owned go
    // with it, so a reader parked on one of them is woken rather than left waiting forever.
    inner.closed.store(true, Ordering::Release);
    let mut sessions = inner.sessions.lock().await;
    for (_, session) in sessions.drain() {
        session.force_close_with_error(ReadEnd::UnderlayLost);
    }
}

/// Reads one segment: metadata, then the payload and the padding the metadata's two length fields
/// describe. A protocol error ends the connection.
#[expect(
    clippy::significant_drop_tightening,
    reason = "one segment is read under a single lock: splitting the guard per read would let another reader interleave the metadata, payload and padding"
)]
async fn read_one_segment(inner: &Inner) -> Result<Incoming> {
    let first_read = inner.recv.lock().await.is_none();
    let mut read_half = inner.read_half.lock().await;

    let mut metadata =
        vec![
            0u8;
            wire::METADATA_LENGTH + cipher::DEFAULT_OVERHEAD + if first_read { cipher::DEFAULT_NONCE_SIZE } else { 0 }
        ];
    read_half.read_exact(&mut metadata).await.map_err(|_| UnderlayError::Closed)?;

    let mut slot = inner.recv.lock().await;
    let mut discovered_user = None;
    let plaintext = if slot.is_none() {
        let (name, block) = match (inner.users.as_ref(), inner.client_block.as_ref()) {
            (Some(users), _) => {
                let (name, block, _) = discover(&metadata, users, true).ok_or(UnderlayError::NoMatchingUser)?;
                (name, block)
            }
            (None, Some(template)) => (inner.user_name.clone().unwrap_or_default(), template.clone_full()),
            (None, None) => return Err(UnderlayError::NoMatchingUser),
        };
        block.set_nonce_pattern(inner.traffic_pattern.as_ref().and_then(Config::nonce_pattern));
        // The discovered block is stateless, so re-opening the first segment under implicit-nonce
        // mode is what captures the peer's nonce; every later segment then carries only its tag.
        block.set_implicit_nonce_mode(true);
        let plaintext = block.decrypt(&metadata).map_err(cipher_err)?;
        *slot = Some(block);
        discovered_user = Some(name);
        plaintext
    } else {
        slot.as_ref().ok_or(UnderlayError::Closed)?.decrypt(&metadata).map_err(cipher_err)?
    };

    if plaintext.len() != wire::METADATA_LENGTH {
        return Err(UnderlayError::Io(std::io::Error::other("decrypted metadata has the wrong size")));
    }
    let protocol = ProtocolType::from_byte(*plaintext.first().ok_or(UnderlayError::Closed)?)?;

    let (meta, prefix_len, payload_len, suffix_len) = if protocol.is_session_struct() {
        let session = SessionStruct::unmarshal(&plaintext)?;
        wire::validate_timestamp(session.timestamp)?;
        (SessionMeta::Session(session), 0usize, session.payload_len as usize, session.suffix_len as usize)
    } else {
        let data_ack = DataAckStruct::unmarshal(&plaintext)?;
        wire::validate_timestamp(data_ack.timestamp)?;
        (
            SessionMeta::DataAck(data_ack),
            data_ack.prefix_len as usize,
            data_ack.payload_len as usize,
            data_ack.suffix_len as usize,
        )
    };

    let mut scratch = [0u8; trafficpattern::MAX_PADDING_LEN as usize];
    if prefix_len > 0 {
        let Some(dst) = scratch.get_mut(..prefix_len) else {
            return Err(UnderlayError::Closed);
        };
        read_half.read_exact(dst).await.map_err(|_| UnderlayError::Closed)?;
    }
    let payload = if payload_len > 0 {
        let mut sealed = vec![0u8; payload_len + cipher::DEFAULT_OVERHEAD];
        read_half.read_exact(&mut sealed).await.map_err(|_| UnderlayError::Closed)?;
        Bytes::from(slot.as_ref().ok_or(UnderlayError::Closed)?.decrypt(&sealed).map_err(cipher_err)?)
    } else {
        Bytes::new()
    };
    if suffix_len > 0 {
        let Some(dst) = scratch.get_mut(..suffix_len) else {
            return Err(UnderlayError::Closed);
        };
        read_half.read_exact(dst).await.map_err(|_| UnderlayError::Closed)?;
    }

    Ok(Incoming { protocol, meta, payload, user_name: discovered_user })
}

/// `RunEventLoop`'s dispatch: a session protocol creates, answers or closes a session; a data
/// segment for a session this underlay does not have asks the peer to close it.
async fn dispatch(inner: &Arc<Inner>, accept_tx: &mpsc::Sender<Arc<Session>>, incoming: Incoming) {
    let Incoming { protocol, meta, payload, user_name } = incoming;
    let (session_id, un_ack_seq) = match meta {
        SessionMeta::Session(session) => (session.session_id, 0),
        SessionMeta::DataAck(data_ack) => (data_ack.session_id, data_ack.un_ack_seq),
    };

    if protocol.is_session_struct() {
        if protocol == ProtocolType::OpenSessionRequest {
            if inner.is_client || session_id == 0 {
                return;
            }
            if inner.sessions.lock().await.contains_key(&session_id) {
                return;
            }
            let sink = Arc::clone(inner);
            let sink: Arc<dyn SegmentSink> = sink;
            let session = Arc::new(Session::new(
                session_id,
                false,
                Transport::Stream,
                fragment_size(Transport::Stream, inner.mtu),
                sink,
                inner.peer_facts(user_name),
            ));
            inner.sessions.lock().await.insert(session_id, Arc::clone(&session));
            let _ = session.handle_incoming(protocol, meta, payload).await;
            let _ = accept_tx.send(session).await;
            return;
        }
        let existing = inner.sessions.lock().await.get(&session_id).cloned();
        if let Some(session) = existing {
            let _ = session.handle_incoming(protocol, meta, payload).await;
        }
        return;
    }

    let existing = inner.sessions.lock().await.get(&session_id).cloned();
    if let Some(session) = existing {
        let _ = session.handle_incoming(protocol, meta, payload).await;
    } else {
        let close = SessionStruct {
            protocol: ProtocolType::CloseSessionRequest as u8,
            timestamp: wire::now_minutes(),
            session_id,
            seq: un_ack_seq,
            status_code: wire::STATUS_OK,
            payload_len: 0,
            suffix_len: 0,
        };
        let _ = write_segment(inner, close.marshal(), &[]).await;
    }
}

/// Writes one segment. The padding lengths live in the segment's own metadata, so it is re-marshaled
/// with them filled in before encryption. A session-struct segment gets end padding only; a
/// data-ack segment also gets middle padding, between the metadata and the payload.
async fn write_segment(inner: &Inner, meta: [u8; wire::METADATA_LENGTH], payload: &[u8]) -> std::io::Result<()> {
    let mut writer = inner.writer.lock().await;
    if writer.cipher.is_none() {
        writer.cipher = Some(inner.init_send_cipher().await.map_err(std::io::Error::other)?);
    }
    let Some(send) = writer.cipher.as_ref() else {
        return Err(std::io::Error::other(UnderlayError::Closed));
    };

    let protocol = ProtocolType::from_byte(meta[0]).map_err(wire_io_err)?;
    let strategy_source = send.user_name().unwrap_or_default();
    let (meta, prefix, suffix, fragmentable) = if protocol.is_session_struct() {
        let mut session = SessionStruct::unmarshal(&meta).map_err(wire_io_err)?;
        let pad = padding::new_padding(&PaddingOpts::recommended(
            inner.max_padding(session.payload_len as usize, 0, PaddingPosition::End),
            STREAM_OVERHEAD + session.payload_len as usize,
            &strategy_source,
        ));
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a stream transport caps padding at MAX_PADDING_LEN (255); the wire length field is one byte"
        )]
        let suffix_len = pad.len() as u8;
        session.suffix_len = suffix_len;
        (session.marshal(), Vec::new(), pad, true)
    } else {
        let mut data_ack = DataAckStruct::unmarshal(&meta).map_err(wire_io_err)?;
        let prefix = padding::new_padding(&PaddingOpts {
            max_len: inner.max_padding(data_ack.payload_len as usize, 0, PaddingPosition::Middle),
            ascii: Some(AsciiPaddingOpts::default()),
            entropy: None,
        });
        let suffix = padding::new_padding(&PaddingOpts {
            max_len: inner.max_padding(data_ack.payload_len as usize, prefix.len(), PaddingPosition::End),
            ascii: Some(AsciiPaddingOpts::default()),
            entropy: None,
        });
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a stream transport caps padding at MAX_PADDING_LEN (255); the wire length field is one byte"
        )]
        let prefix_len = prefix.len() as u8;
        data_ack.prefix_len = prefix_len;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a stream transport caps padding at MAX_PADDING_LEN (255); the wire length field is one byte"
        )]
        let suffix_len = suffix.len() as u8;
        data_ack.suffix_len = suffix_len;
        (data_ack.marshal(), prefix, suffix, false)
    };

    let encrypted_meta = send.encrypt(&meta).map_err(cipher_io_err)?;
    let mut segment = Vec::with_capacity(
        encrypted_meta.len() + prefix.len() + payload.len() + suffix.len() + cipher::DEFAULT_OVERHEAD,
    );
    segment.extend_from_slice(&encrypted_meta);
    // The wire order is metadata, then middle padding, then the payload, then end padding; the
    // receiver slices the payload out using the two lengths the metadata carries.
    segment.extend_from_slice(&prefix);
    if !payload.is_empty() {
        segment.extend_from_slice(&send.encrypt(payload).map_err(cipher_io_err)?);
    }
    segment.extend_from_slice(&suffix);

    if fragmentable {
        write_with_possible_fragment(&mut writer.half, &segment, inner.traffic_fragment()).await
    } else {
        writer.half.write_all(&segment).await
    }
}

/// Writes with possible fragmentation: with fragmentation on, one segment leaves as several writes of
/// geometrically-sized chunks, optionally spaced out, so a large segment does not read as one
/// large write on the wire. Off, it is a single write.
async fn write_with_possible_fragment(
    half: &mut WriteHalf<Stream>,
    data: &[u8],
    max_sleep_ms: Option<i32>,
) -> std::io::Result<()> {
    let Some(max_sleep_ms) = max_sleep_ms else {
        return half.write_all(data).await;
    };
    let mut remaining = data;
    while !remaining.is_empty() {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            clippy::cast_sign_loss,
            reason = "`data` is one segment, bounded by MAX_PDU plus its framing, so its length is exact in f64 and the square root is a small non-negative integer"
        )]
        let min_len = (data.len() as f64).sqrt() as usize + 1;
        let max_len = min_len.max(data.len() / 2);
        let len_to_send = rand::rng().random_range(min_len..=max_len).min(remaining.len());
        let (chunk, rest) = remaining.split_at(len_to_send);
        half.write_all(chunk).await?;
        if max_sleep_ms > 0 {
            #[expect(
                clippy::cast_sign_loss,
                reason = "the enclosing `> 0` guard rules out a negative sleep, so the widening to u64 is exact"
            )]
            let sleep_ms = rand::rng().random_range(0..=max_sleep_ms as u64);
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        }
        remaining = rest;
    }
    Ok(())
}

fn wire_io_err(e: wire::WireError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}

fn cipher_io_err(e: cipher::CipherError) -> std::io::Error {
    std::io::Error::other(e)
}

fn cipher_err(e: cipher::CipherError) -> UnderlayError {
    UnderlayError::Io(std::io::Error::other(e))
}

#[async_trait::async_trait]
impl SegmentSink for Inner {
    async fn send_segment(&self, meta: [u8; wire::METADATA_LENGTH], payload: &[u8]) -> std::io::Result<()> {
        write_segment(self, meta, payload).await
    }
}

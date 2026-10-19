//! The server half of the AEAD-2022 ciphers.
//!
//! Restricted to the single-PSK path `listener::sing_shadowsocks::server` calls; the multi-user
//! server is not implemented.
//!
//! `Service::udp_sessions`/`udp_sessions_by_addr` expire idle entries the way an age- and
//! access-updating LRU cache does: `open_packet` touches a session's `last_seen` on every packet
//! and evicts sessions idle past `udp_timeout` from both maps.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use super::protocol::{
    check_timestamp, decode_socksaddr, encode_socksaddr, err_bad_header_type, err_packet_id_not_unique,
    err_packet_too_short, err_salt_not_unique, err_short_read, key, now_unix, session_key, system_time_fn,
    AesBlockCipher, ChunkCipher, CipherKind, KeyedXof, TimeFn, AES_BLOCK_SIZE, HEADER_TYPE_CLIENT, HEADER_TYPE_SERVER,
    MAX_CHUNK_SIZE, MAX_PADDING_LENGTH, OVERHEAD, PACKET_LENGTH_BUFFER_SIZE, PACKET_MINIMAL_HEADER_SIZE,
    PACKET_NONCE_SIZE, REQUEST_HEADER_FIXED_CHUNK_LENGTH,
};
use super::sliding_window::SlidingWindow;
use crate::shadowaead::cipher::Aead;
use murmur_common_net::io::Stream as NetStream;
use murmur_common_net::{EnhancePacketConn, WaitReadFrom};
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Addr, PacketConn};

fn to_io_error(err: anyhow::Error) -> io::Error {
    io::Error::other(err)
}

/// Truncated datagrams are a clean `Err`, never a panic: the length is attacker-controlled.
fn split_packet(buf: &[u8], mid: usize) -> Result<(&[u8], &[u8])> {
    buf.split_at_checked(mid).ok_or_else(err_packet_too_short)
}

fn aes_block_at(buf: &[u8], offset: usize) -> Result<[u8; AES_BLOCK_SIZE]> {
    let bytes = buf.get(offset..offset + AES_BLOCK_SIZE).ok_or_else(err_packet_too_short)?;
    bytes.try_into().map_err(|_| err_packet_too_short())
}

fn be_u64_at(buf: &[u8], offset: usize) -> Result<u64> {
    let bytes = buf.get(offset..offset + 8).ok_or_else(|| err_short_read(buf.len()))?;
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| err_short_read(buf.len()))?;
    Ok(u64::from_be_bytes(bytes))
}

fn be_u16_at(buf: &[u8], offset: usize) -> Result<u16> {
    let bytes = buf.get(offset..offset + 2).ok_or_else(|| err_short_read(buf.len()))?;
    let bytes: [u8; 2] = bytes.try_into().map_err(|_| err_short_read(buf.len()))?;
    Ok(u16::from_be_bytes(bytes))
}

/// Rejects a TCP request salt seen again within the last 60 seconds. The whole map is swept only
/// when more than the timeout has passed since the last sweep; otherwise a single lookup also
/// checks age. Sweeping every call would be O(60 * connections/sec) work under the shared service
/// lock.
struct SaltFilter {
    seen: HashMap<Vec<u8>, Instant>,
    last_clean: Instant,
}

const SALT_FILTER_WINDOW_SECS: u64 = 60;

impl SaltFilter {
    fn new() -> Self {
        Self { seen: HashMap::new(), last_clean: Instant::now() }
    }

    fn check(&mut self, salt: &[u8]) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_clean).as_secs() > SALT_FILTER_WINDOW_SECS {
            self.seen.retain(|_, seen_at| now.duration_since(*seen_at).as_secs() < SALT_FILTER_WINDOW_SECS);
            self.last_clean = now;
        }
        if let Some(seen_at) = self.seen.get(salt) {
            if now.duration_since(*seen_at).as_secs() < SALT_FILTER_WINDOW_SECS {
                return false;
            }
        }
        self.seen.insert(salt.to_vec(), now);
        true
    }
}

pub struct Service {
    kind: CipherKind,
    key_salt_length: usize,
    psk: Vec<u8>,
    udp_cipher: Option<Box<dyn Aead>>,
    udp_block_cipher: Option<AesBlockCipher>,
    replay_filter: Mutex<SaltFilter>,
    udp_sessions: Mutex<HashMap<u64, Arc<Mutex<ServerUdpSession>>>>,
    udp_sessions_by_addr: Mutex<HashMap<SocketAddr, Arc<Mutex<ServerUdpSession>>>>,
    udp_timeout: Duration,
    last_udp_sweep: Mutex<Instant>,
    time_fn: TimeFn,
}

/// Redacted: `psk` and the derived ciphers are key material.
impl fmt::Debug for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Service")
            .field("kind", &self.kind)
            .field("key_salt_length", &self.key_salt_length)
            .field("udp_timeout", &self.udp_timeout)
            .finish_non_exhaustive()
    }
}

impl Service {
    /// Builds a `Service` using the default `murmur_ntp::time::now` clock.
    pub fn new(cipher_name: &str, password: &str, udp_timeout: Duration) -> Result<Arc<Self>> {
        Self::new_with_time_fn(cipher_name, password, udp_timeout, system_time_fn())
    }

    /// The time source, exposed so tests can substitute a fixed or skewed clock
    /// instead of mutating the process-wide `murmur_ntp::time` offset.
    fn new_with_time_fn(
        cipher_name: &str,
        password: &str,
        udp_timeout: Duration,
        time_fn: TimeFn,
    ) -> Result<Arc<Self>> {
        let kind = CipherKind::parse(cipher_name)
            .ok_or_else(|| anyhow!("shadowsocks 2022: unsupported method: {cipher_name}"))?;
        let key_salt_length = kind.key_salt_length();
        if password.is_empty() {
            return Err(anyhow!("missing psk"));
        }
        let mut psk = STANDARD.decode(password).map_err(|err| anyhow!("decode psk: {err}"))?;
        if psk.len() < key_salt_length {
            return Err(anyhow!("bad key"));
        } else if psk.len() > key_salt_length {
            psk = key(&psk, key_salt_length);
        }

        let (udp_cipher, udp_block_cipher) = if kind.is_aes() {
            (None, Some(AesBlockCipher::new(&psk)?))
        } else {
            let cipher = kind.make_udp_aead(&psk)?;
            (Some(cipher), None)
        };

        Ok(Arc::new(Self {
            kind,
            key_salt_length,
            psk,
            udp_cipher,
            udp_block_cipher,
            replay_filter: Mutex::new(SaltFilter::new()),
            udp_sessions: Mutex::new(HashMap::new()),
            udp_sessions_by_addr: Mutex::new(HashMap::new()),
            udp_timeout,
            last_udp_sweep: Mutex::new(Instant::now()),
            time_fn,
        }))
    }

    /// Reads and validates the whole TCP request, returning a
    /// conn positioned at the payload (the `ListenerHandler`/`socks5::read_addr0` boundary the
    /// classic-cipher path uses does not apply here, since the destination and padding sit inside
    /// this protocol's own encrypted framing) plus the destination.
    // NOT cancel-safe: the accepted connection has already been read from (framing or an authentication header), so a dropped call loses it mid-exchange.
    pub async fn accept(&self, mut conn: Box<dyn NetStream>) -> Result<(Box<dyn NetStream>, Socksaddr)> {
        let mut salt = vec![0u8; self.key_salt_length];
        read_exact_async(&mut conn, &mut salt).await?;

        if !self.replay_filter.lock().check(&salt) {
            return Err(err_salt_not_unique());
        }

        let key = session_key(&self.psk, &salt, self.key_salt_length);
        let aead = self.kind.make_aead(&key)?;
        let mut cipher = ChunkCipher::new(aead);

        let mut fixed = vec![0u8; REQUEST_HEADER_FIXED_CHUNK_LENGTH + OVERHEAD];
        read_exact_async(&mut conn, &mut fixed).await?;
        let plain = cipher.open(&fixed)?;
        let header_type = *plain.first().ok_or_else(|| err_short_read(plain.len()))?;
        if header_type != HEADER_TYPE_CLIENT {
            return Err(err_bad_header_type(HEADER_TYPE_CLIENT, header_type));
        }
        let epoch = be_u64_at(&plain, 1)?;
        check_timestamp(epoch, (self.time_fn)())?;
        let var_len = usize::from(be_u16_at(&plain, 9)?);

        let mut var = vec![0u8; var_len + OVERHEAD];
        read_exact_async(&mut conn, &mut var).await?;
        let plain = cipher.open(&var)?;

        let (destination, consumed) = decode_socksaddr(&plain)?;
        if plain.len() < consumed + 2 {
            return Err(anyhow!("bad request: missing payload or padding"));
        }
        let padding_len = usize::from(be_u16_at(&plain, consumed)?);
        let remaining = plain.len() - consumed - 2;
        if remaining < padding_len {
            return Err(anyhow!("bad request: missing payload or padding"));
        }
        if padding_len == 0 && remaining == 0 {
            return Err(anyhow!("bad request: missing payload or padding"));
        }
        let payload = plain.get(consumed + 2 + padding_len..).unwrap_or_default().to_vec();

        let conn = ServerConn::new(
            conn,
            cipher,
            self.kind,
            self.psk.clone(),
            self.key_salt_length,
            salt,
            payload,
            Arc::clone(&self.time_fn),
        );
        Ok((Box::new(conn), destination.unwrap()))
    }

    /// The `PacketConnCipher::packet_conn` shape, wrapping `conn`.
    pub fn packet_conn(self: &Arc<Self>, conn: Arc<dyn EnhancePacketConn>) -> Arc<dyn EnhancePacketConn> {
        Arc::new(ServicePacketConn { service: Arc::clone(self), inner: conn })
    }

    /// The age- and access-based eviction, applied to both UDP session maps: evicts
    /// entries idle past `udp_timeout`, throttled to run at most every quarter of `udp_timeout`
    /// so a busy inbound does not pay an `O(sessions)` sweep on every packet. `udp_sessions_by_addr`
    /// is swept independently of `udp_sessions`, by each entry's own session idle time, because a
    /// session can have more than one live `by_addr` entry (NAT rebinding, a client's source
    /// address changing mid-session): removing only the most-recently-seen address would leave
    /// every earlier address's entry, and its `Arc<Mutex<ServerUdpSession>>`, alive forever.
    fn sweep_udp_sessions_if_due(&self) {
        let now = Instant::now();
        {
            let mut last_sweep = self.last_udp_sweep.lock();
            if now.duration_since(*last_sweep) < self.udp_timeout / 4 {
                return;
            }
            *last_sweep = now;
        }

        let is_idle =
            |session: &Arc<Mutex<ServerUdpSession>>| now.duration_since(session.lock().last_seen) > self.udp_timeout;
        self.udp_sessions.lock().retain(|_, session| !is_idle(session));
        self.udp_sessions_by_addr.lock().retain(|_, session| !is_idle(session));
    }
}

async fn read_exact_async(conn: &mut Box<dyn NetStream>, buf: &mut [u8]) -> Result<()> {
    use tokio::io::AsyncReadExt;
    conn.read_exact(buf).await.map_err(|err| anyhow!("read header: {err}"))?;
    Ok(())
}

enum WritePhase {
    NeedResponse { request_salt: Vec<u8> },
    Ready(ChunkCipher),
}

struct ServerConn {
    inner: Box<dyn NetStream>,
    read_cipher: ChunkCipher,
    key_salt_length: usize,
    kind: CipherKind,
    psk: Vec<u8>,
    time_fn: TimeFn,
    write: WritePhase,
    pending_write: Vec<u8>,
    pending_write_sent: usize,
    pending_plain_len: usize,
    /// The exact caller-visible plaintext `pending_write` was sealed from; see
    /// `VerifiedConn::write_state`'s twin field in `transport-shadowtls/src/v3.rs`.
    pending_plain: Vec<u8>,
    /// See `ClientConn::torn` in `client.rs`.
    torn: bool,
    read_pending: Vec<u8>,
    read_len_acc: Vec<u8>,
    read_data_acc: Vec<u8>,
    read_pending_len: Option<usize>,
}

impl ServerConn {
    #[allow(clippy::too_many_arguments)]
    fn new(
        inner: Box<dyn NetStream>,
        read_cipher: ChunkCipher,
        kind: CipherKind,
        psk: Vec<u8>,
        key_salt_length: usize,
        request_salt: Vec<u8>,
        initial_payload: Vec<u8>,
        time_fn: TimeFn,
    ) -> Self {
        Self {
            inner,
            read_cipher,
            key_salt_length,
            kind,
            psk,
            time_fn,
            write: WritePhase::NeedResponse { request_salt },
            pending_write: Vec::new(),
            pending_write_sent: 0,
            pending_plain_len: 0,
            pending_plain: Vec::new(),
            torn: false,
            read_pending: initial_payload,
            read_len_acc: Vec::new(),
            read_data_acc: Vec::new(),
            read_pending_len: None,
        }
    }
}

fn server_torn_err() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "shadowsocks: conn torn by an abandoned mid-frame write")
}

fn poll_write_record(
    inner: &mut dyn NetStream,
    cx: &mut Context<'_>,
    record: &[u8],
    sent: &mut usize,
) -> Poll<io::Result<()>> {
    while *sent < record.len() {
        let (_, rest) = record.split_at(*sent);
        let n = match Pin::new(&mut *inner).poll_write(cx, rest) {
            Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };
        *sent += n;
    }
    Poll::Ready(Ok(()))
}

fn poll_read_exact(
    inner: &mut dyn NetStream,
    cx: &mut Context<'_>,
    acc: &mut Vec<u8>,
    want: usize,
) -> Poll<io::Result<()>> {
    while acc.len() < want {
        let mut chunk = [0u8; 4096];
        let take = chunk.len().min(want - acc.len());
        let (head, _) = chunk.split_at_mut(take);
        let mut read_buf = ReadBuf::new(head);
        ready!(Pin::new(&mut *inner).poll_read(cx, &mut read_buf))?;
        let n = read_buf.filled().len();
        if n == 0 {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        acc.extend_from_slice(read_buf.filled());
    }
    Poll::Ready(Ok(()))
}

impl AsyncWrite for ServerConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.torn {
            return Poll::Ready(Err(server_torn_err()));
        }
        loop {
            if !this.pending_write.is_empty() {
                if this.pending_plain_len > 0 && !buf.starts_with(&this.pending_plain) {
                    this.pending_write.clear();
                    this.pending_write_sent = 0;
                    this.pending_plain_len = 0;
                    this.pending_plain.clear();
                    this.torn = true;
                    return Poll::Ready(Err(server_torn_err()));
                }
                match poll_write_record(&mut *this.inner, cx, &this.pending_write, &mut this.pending_write_sent) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => {
                        // The pending write is only ever populated already sealed (see
                        // `ClientConn::poll_write` in `client.rs` for the identical reasoning):
                        // dropping a sealed frame here, even with zero bytes of it on the wire
                        // yet, leaves the peer's crypto state permanently desynchronized the
                        // moment the *next* frame is sealed with the advanced nonce
                        // (`agent://ReviewBridge2` P2), so every failure while a sealed frame is
                        // pending must tear the whole conn, matching the own contract that a
                        // mid-frame write failure leaves the conn broken.
                        this.pending_write.clear();
                        this.pending_write_sent = 0;
                        this.pending_plain_len = 0;
                        this.pending_plain.clear();
                        this.torn = true;
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Ok(())) => {}
                }
                this.pending_write.clear();
                this.pending_write_sent = 0;
                this.pending_plain.clear();
                if this.pending_plain_len > 0 {
                    let n = this.pending_plain_len;
                    this.pending_plain_len = 0;
                    return Poll::Ready(Ok(n));
                }
                if buf.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                continue;
            }

            if let WritePhase::NeedResponse { request_salt } = &this.write {
                let mut salt = vec![0u8; this.key_salt_length];
                rand::rng().fill_bytes(&mut salt);
                let mut wire = salt.clone();

                let key = session_key(&this.psk, &salt, this.key_salt_length);
                let aead = this.kind.make_aead(&key).map_err(to_io_error)?;
                let mut writer = ChunkCipher::new(aead);

                let take = buf.len().min(MAX_CHUNK_SIZE);
                let (chunk, _) = buf.split_at(take);
                let mut fixed = Vec::with_capacity(1 + 8 + this.key_salt_length + 2);
                fixed.push(HEADER_TYPE_SERVER);
                fixed.extend_from_slice(&now_unix((this.time_fn)()).to_be_bytes());
                fixed.extend_from_slice(request_salt);
                fixed.extend_from_slice(&u16::try_from(take).unwrap_or(u16::MAX).to_be_bytes());
                writer.seal_into(&mut wire, &fixed).map_err(to_io_error)?;
                writer.seal_into(&mut wire, chunk).map_err(to_io_error)?;

                this.write = WritePhase::Ready(writer);
                this.pending_write = wire;
                this.pending_plain_len = take;
                this.pending_plain = chunk.to_vec();
                continue;
            }

            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let WritePhase::Ready(writer) = &mut this.write else {
                return Poll::Ready(Err(io::Error::other("shadowsocks: write phase not advanced")));
            };
            let (chunk, _) = buf.split_at(buf.len().min(MAX_CHUNK_SIZE));
            let sealed = writer.seal_chunk(chunk).map_err(to_io_error)?;
            this.pending_write = sealed;
            this.pending_plain_len = chunk.len();
            this.pending_plain = chunk.to_vec();
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncRead for ServerConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.torn {
            return Poll::Ready(Err(server_torn_err()));
        }
        loop {
            if !this.read_pending.is_empty() {
                let n = buf.remaining().min(this.read_pending.len());
                let (head, _) = this.read_pending.split_at(n);
                buf.put_slice(head);
                this.read_pending.drain(..n);
                return Poll::Ready(Ok(()));
            }

            if let Some(want) = this.read_pending_len {
                ready!(poll_read_exact(&mut *this.inner, cx, &mut this.read_data_acc, want + OVERHEAD))?;
                let plain = this.read_cipher.open(&this.read_data_acc).map_err(to_io_error)?;
                this.read_data_acc.clear();
                this.read_pending_len = None;
                this.read_pending = plain;
                continue;
            }

            let want = PACKET_LENGTH_BUFFER_SIZE + OVERHEAD;
            ready!(poll_read_exact(&mut *this.inner, cx, &mut this.read_len_acc, want))?;
            let len = this.read_cipher.open_length(&this.read_len_acc).map_err(to_io_error)?;
            this.read_len_acc.clear();
            this.read_pending_len = Some(len);
        }
    }
}

impl NetStream for ServerConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.inner.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.inner.shutdown_write()
    }
    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.inner.old_conn()
    }
}

struct ServerUdpSession {
    session_id: u64,
    packet_id: u64,
    cipher: Option<Box<dyn Aead>>,
    rng: Option<KeyedXof>,
    remote_session_id: u64,
    remote_cipher: Option<Box<dyn Aead>>,
    window: SlidingWindow,
    /// Refreshed on every packet this session handles.
    last_seen: Instant,
}

impl ServerUdpSession {
    #[expect(
        clippy::expect_used,
        reason = "`Service` validates the psk length before any session is built, so `make_aead` cannot fail here"
    )]
    fn new(service: &Service) -> Self {
        let (session_id, rng) = if service.udp_cipher.is_some() {
            let mut rng = KeyedXof::new();
            (rng.read_u64(), Some(rng))
        } else {
            (rand::rng().random::<u64>(), None)
        };
        let cipher = if service.udp_cipher.is_none() {
            let sid = session_id.to_be_bytes();
            let key = session_key(&service.psk, &sid, service.key_salt_length);
            Some(service.kind.make_aead(&key).expect("psk already length-validated"))
        } else {
            None
        };
        Self {
            session_id,
            packet_id: 0,
            cipher,
            rng,
            remote_session_id: 0,
            remote_cipher: None,
            window: SlidingWindow::default(),
            last_seen: Instant::now(),
        }
    }

    fn next_packet_id(&mut self) -> u64 {
        self.packet_id += 1;
        self.packet_id
    }
}

struct ServicePacketConn {
    service: Arc<Service>,
    inner: Arc<dyn EnhancePacketConn>,
}

const MAX_UDP_PACKET: usize = 64 * 1024;

impl ServicePacketConn {
    /// Returns the decrypted `[addr][payload]` bytes (matching the classic-cipher UDP wire shape
    /// `listener::sing_shadowsocks::server::handle_socks_udp` already parses) plus the sender's
    /// socket address, used as the session lookup key for the reply direction.
    fn open_packet(&self, buf: &[u8], from: SocketAddr) -> Result<Vec<u8>> {
        let service = &self.service;
        service.sweep_udp_sessions_if_due();

        let (header16, ciphertext) = decrypt_udp_header(service, buf)?;
        let now = Instant::now();
        let plain = if let Some(header) = header16 {
            open_udp_packet_with_block_header(service, &header, &ciphertext, from, now)?
        } else {
            open_udp_packet_with_aead_header(service, &ciphertext, from, now)?
        };

        let header_type = *plain.first().ok_or_else(|| anyhow!("decrypt packet: EOF"))?;
        if header_type != HEADER_TYPE_CLIENT {
            return Err(err_bad_header_type(HEADER_TYPE_CLIENT, header_type));
        }
        if plain.len() < 9 {
            return Err(err_short_read(plain.len() - 1));
        }
        let epoch = be_u64_at(&plain, 1)?;
        check_timestamp(epoch, (service.time_fn)())?;

        if plain.len() < 11 {
            return Err(anyhow!("read padding length: {}", err_short_read(plain.len() - 9)));
        }
        let padding_len = usize::from(be_u16_at(&plain, 9)?);
        let rest = plain.get((11 + padding_len).min(plain.len())..).unwrap_or_default();
        if rest.is_empty() {
            // A padding length past the end clamps silently, leaving an empty buffer and a bare
            // "EOF" error from the address read.
            return Err(anyhow!("EOF"));
        }
        let (destination, consumed) = decode_socksaddr(rest)?;
        let payload = rest.get(consumed..).unwrap_or_default();

        let mut out = encode_socksaddr(&destination.unwrap())?;
        out.extend_from_slice(payload);
        Ok(out)
    }

    fn seal_packet(&self, session: &Arc<Mutex<ServerUdpSession>>, payload: &[u8]) -> Result<Vec<u8>> {
        let service = &self.service;
        let mut s = session.lock();

        let mut header = Vec::with_capacity(AES_BLOCK_SIZE);
        if let Some(rng) = s.rng.as_mut() {
            let mut nonce = [0u8; PACKET_NONCE_SIZE];
            rng.read(&mut nonce);
            header.extend_from_slice(&nonce);
        }
        header.extend_from_slice(&s.session_id.to_be_bytes());
        let packet_id = s.next_packet_id();
        header.extend_from_slice(&packet_id.to_be_bytes());

        let (destination, appended) = decode_socksaddr(payload)?;
        let destination = destination.unwrap();
        let reply_payload = payload.get(appended..).unwrap_or_default();
        let padding_len = if destination.port == 53 && reply_payload.len() < MAX_PADDING_LENGTH {
            rand::rng().random_range(1..=(MAX_PADDING_LENGTH - reply_payload.len()))
        } else {
            0usize
        };

        let mut body = Vec::new();
        body.push(HEADER_TYPE_SERVER);
        body.extend_from_slice(&now_unix((service.time_fn)()).to_be_bytes());
        body.extend_from_slice(&s.remote_session_id.to_be_bytes());
        body.extend_from_slice(&u16::try_from(padding_len).unwrap_or(u16::MAX).to_be_bytes());
        body.resize(body.len() + padding_len, 0);
        body.extend_from_slice(&encode_socksaddr(&destination)?);
        body.extend_from_slice(reply_payload);

        let mut out;
        if let Some(udp_cipher) = &service.udp_cipher {
            drop(s);
            let (nonce, head) = split_packet(&header, PACKET_NONCE_SIZE)?;
            let mut plaintext = head.to_vec();
            plaintext.extend_from_slice(&body);
            out = nonce.to_vec();
            udp_cipher.seal(&mut out, nonce, &plaintext, &[])?;
        } else {
            out = header.clone();
            let (_, nonce) = split_packet(&header, AES_BLOCK_SIZE - 12)?;
            let cipher = s.cipher.as_ref().ok_or_else(|| anyhow!("shadowsocks 2022: session cipher missing"))?;
            cipher.seal(&mut out, nonce, &body, &[])?;
            drop(s);
            let mut block = aes_block_at(&header, 0)?;
            service
                .udp_block_cipher
                .as_ref()
                .ok_or_else(|| anyhow!("shadowsocks 2022: aes block cipher missing"))?
                .encrypt_block(&mut block);
            out.get_mut(..AES_BLOCK_SIZE).ok_or_else(err_packet_too_short)?.copy_from_slice(&block);
        }
        Ok(out)
    }
}

/// Splits a datagram into its header -- a decrypted AES block for the AES ciphers, otherwise the
/// authenticated 2022 header -- and the ciphertext after it.
fn decrypt_udp_header(service: &Service, buf: &[u8]) -> Result<(Option<[u8; AES_BLOCK_SIZE]>, Vec<u8>)> {
    let Some(udp_cipher) = service.udp_cipher.as_ref() else {
        if buf.len() < PACKET_MINIMAL_HEADER_SIZE {
            return Err(err_packet_too_short());
        }
        let mut header = aes_block_at(buf, 0)?;
        service
            .udp_block_cipher
            .as_ref()
            .ok_or_else(|| anyhow!("shadowsocks 2022: aes block cipher missing"))?
            .decrypt_block(&mut header);
        return Ok((Some(header), buf.get(AES_BLOCK_SIZE..).unwrap_or_default().to_vec()));
    };

    if buf.len() < PACKET_NONCE_SIZE + PACKET_MINIMAL_HEADER_SIZE {
        return Err(err_packet_too_short());
    }
    let (nonce, ct) = split_packet(buf, PACKET_NONCE_SIZE)?;
    let plain = udp_cipher.open(nonce, ct, &[]).map_err(|e| anyhow!("decrypt packet header: {e}"))?;
    Ok((None, plain))
}

/// Opens a packet of an AES cipher, whose undecrypted block header leads with the session and
/// packet ids the session state is keyed by.
fn open_udp_packet_with_block_header(
    service: &Service,
    header: &[u8; AES_BLOCK_SIZE],
    ciphertext: &[u8],
    from: SocketAddr,
    now: Instant,
) -> Result<Vec<u8>> {
    let session_id = be_u64_at(header, 0)?;
    let packet_id = be_u64_at(header, 8)?;

    let sessions = service.udp_sessions.lock();
    let existing = sessions.get(&session_id).cloned();
    drop(sessions);

    let (session, is_new) = match existing {
        Some(s) => (s, false),
        None => (Arc::new(Mutex::new(ServerUdpSession::new(service))), true),
    };

    {
        let mut s = session.lock();
        if !s.window.check(packet_id) {
            return Err(err_packet_id_not_unique());
        }
        s.last_seen = now;
        if is_new {
            s.remote_session_id = session_id;
            let key = session_key(&service.psk, header.get(..8).unwrap_or_default(), service.key_salt_length);
            s.remote_cipher = Some(service.kind.make_aead(&key)?);
        }
    }

    let nonce = header.get(4..16).unwrap_or_default();
    let opened = {
        let s = session.lock();
        s.remote_cipher
            .as_ref()
            .ok_or_else(|| anyhow!("shadowsocks 2022: missing remote cipher"))?
            .open(nonce, ciphertext, &[])
            .map_err(|e| anyhow!("decrypt packet: {e}"))?
    };
    session.lock().window.add(packet_id);

    if is_new {
        service.udp_sessions.lock().insert(session_id, Arc::clone(&session));
    }
    service.udp_sessions_by_addr.lock().insert(from, session);

    Ok(opened)
}

/// Opens a packet of a 2022 cipher: the decrypted header leads with the session and packet ids,
/// and the payload follows after the AEAD nonce.
fn open_udp_packet_with_aead_header(
    service: &Service,
    ciphertext: &[u8],
    from: SocketAddr,
    now: Instant,
) -> Result<Vec<u8>> {
    if ciphertext.len() < AES_BLOCK_SIZE {
        return Err(err_packet_too_short());
    }
    let session_id = be_u64_at(ciphertext, 0)?;
    let packet_id = be_u64_at(ciphertext, 8)?;

    let sessions = service.udp_sessions.lock();
    let existing = sessions.get(&session_id).cloned();
    drop(sessions);
    let (session, is_new) = match existing {
        Some(s) => (s, false),
        None => (Arc::new(Mutex::new(ServerUdpSession::new(service))), true),
    };
    {
        let mut s = session.lock();
        if !s.window.check(packet_id) {
            return Err(err_packet_id_not_unique());
        }
        s.window.add(packet_id);
        s.last_seen = now;
        if is_new {
            s.remote_session_id = session_id;
        }
    }
    if is_new {
        service.udp_sessions.lock().insert(session_id, Arc::clone(&session));
    }
    service.udp_sessions_by_addr.lock().insert(from, session);
    Ok(ciphertext.get(AES_BLOCK_SIZE..).unwrap_or_default().to_vec())
}

fn socket_addr_of(addr: &dyn Addr) -> Option<SocketAddr> {
    let addr_port = addr.addr_port()?;
    Some(SocketAddr::new(addr_port.ip?, addr_port.port))
}

#[async_trait]
impl PacketConn for ServicePacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut scratch = vec![0u8; MAX_UDP_PACKET];
        let (n, from) = self.inner.read_from(&mut scratch).await?;
        scratch.truncate(n);
        let Some(from_socket) = socket_addr_of(from.as_ref()) else {
            return Err(io::Error::other("shadowsocks 2022: udp source has no socket address"));
        };
        let out = self.open_packet(&scratch, from_socket).map_err(to_io_error)?;
        let n = out.len().min(buf.len());
        let (head, _) = buf.split_at_mut(n);
        head.copy_from_slice(out.get(..n).unwrap_or_default());
        Ok((n, from))
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let Some(to) = socket_addr_of(addr) else {
            return Err(io::Error::other("shadowsocks 2022: udp destination has no socket address"));
        };
        let Some(session) = self.service.udp_sessions_by_addr.lock().get(&to).cloned() else {
            return Err(io::Error::other("shadowsocks 2022: no udp session for reply destination"));
        };
        let sealed = self.seal_packet(&session, buf).map_err(to_io_error)?;
        self.inner.write_to(&sealed, addr).await?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.inner.close()
    }
}

#[async_trait]
impl WaitReadFrom for ServicePacketConn {
    // NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let (data, put, from, result) = self.inner.wait_read_from().await;
        if result.is_err() {
            return (data, put, from, result);
        }
        let Some(from) = from else {
            return (Vec::new(), put, None, Err(io::Error::other("shadowsocks 2022: udp source missing")));
        };
        let Some(from_socket) = socket_addr_of(from.as_ref()) else {
            return (
                Vec::new(),
                put,
                None,
                Err(io::Error::other("shadowsocks 2022: udp source has no socket address")),
            );
        };
        match self.open_packet(&data, from_socket) {
            Ok(out) => (out, put, Some(from), Ok(())),
            Err(err) => (Vec::new(), put, None, Err(to_io_error(err))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::task::{Context, Poll};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadBuf};
    use tokio::sync::mpsc;

    use super::*;
    use crate::shadowaead_2022::client::ClientMethod;
    use murmur_std_compat::net::UdpAddr;

    const CIPHERS: &[(&str, usize)] = &[
        ("2022-blake3-aes-128-gcm", 16),
        ("2022-blake3-aes-256-gcm", 32),
        ("2022-blake3-chacha20-poly1305", 32),
        ("2022-blake3-chacha8-poly1305", 32),
        ("2022-blake3-aes-128-ccm", 16),
        ("2022-blake3-aes-256-ccm", 32),
    ];

    /// A generous default so ordinary round-trip and KAT tests never evict a session mid test;
    /// `udp_idle_session_is_evicted` uses its own short timeout instead.
    const TEST_UDP_TIMEOUT: Duration = Duration::from_secs(300);

    fn password(len: usize) -> String {
        STANDARD.encode(vec![0x42u8; len])
    }

    struct PipeConn(DuplexStream);

    impl AsyncRead for PipeConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PipeConn {
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

    impl NetStream for PipeConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    fn pipe_pair() -> (Box<dyn NetStream>, Box<dyn NetStream>) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (Box::new(PipeConn(a)), Box::new(PipeConn(b)))
    }

    #[tokio::test]
    async fn tcp_round_trip_all_ciphers() {
        for &(name, key_len) in CIPHERS {
            let psk = password(key_len);
            let client = ClientMethod::new(name, &psk).expect("client method");
            let service = Service::new(name, &psk, TEST_UDP_TIMEOUT).expect("service");

            let (client_conn, server_conn) = pipe_pair();
            let destination = Socksaddr::fqdn("example.com", 443);

            let client_task = tokio::spawn(async move {
                let mut conn = client.dial_conn(client_conn, destination).await.expect("dial conn");
                conn.write_all(b"hello from client").await.expect("write request payload");
                let mut buf = [0u8; 64];
                let n = conn.read(&mut buf).await.expect("read response");
                assert_eq!(&buf[..n], b"hello from server");
                conn
            });

            let (mut server_conn, dest) = service.accept(server_conn).await.expect("accept");
            assert_eq!(dest.fqdn, "example.com");
            assert_eq!(dest.port, 443);
            let mut buf = [0u8; 64];
            let n = server_conn.read(&mut buf).await.expect("read request payload");
            assert_eq!(&buf[..n], b"hello from client");
            server_conn.write_all(b"hello from server").await.expect("write response payload");

            client_task.await.expect("client task");
        }
    }
    #[tokio::test]
    async fn tcp_close_through_stream_as_old_conn_reaches_the_real_socket() {
        use tokio::io::AsyncReadExt;

        let (name, key_len) = CIPHERS[0];
        let psk = password(key_len);
        let client_method = ClientMethod::new(name, &psk).expect("client method");
        let service = Service::new(name, &psk, TEST_UDP_TIMEOUT).expect("service");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let server_task = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
        let client_tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let server_tcp = server_task.await.expect("server task");

        let destination = Socksaddr::fqdn("example.com", 443);
        let client_conn = client_method.dial_conn(Box::new(client_tcp), destination).await.expect("dial conn");
        let old_client: Box<dyn murmur_std_compat::net::Conn> =
            Box::new(murmur_common_net::io::StreamAsOldConn::new(client_conn));

        let (server_conn, _dest) = service.accept(Box::new(server_tcp)).await.expect("accept");
        let mut old_server = murmur_common_net::io::StreamAsOldConn::new(server_conn);

        old_client.close().expect("close");

        let mut buf = [0u8; 1];
        match old_server.read(&mut buf).await {
            Ok(n) => assert_eq!(n, 0, "closing the client bridge must shut down the real socket"),
            Err(err) => assert_eq!(
                err.kind(),
                io::ErrorKind::UnexpectedEof,
                "the only expected failure is the chunk framing seeing a real socket EOF mid-record: {err}"
            ),
        }
    }

    #[tokio::test]
    async fn tcp_salt_replay_is_rejected() {
        let (name, key_len) = CIPHERS[0];
        let psk = password(key_len);
        let service = Service::new(name, &psk, TEST_UDP_TIMEOUT).expect("service");

        // Craft two independent client requests sharing one fixed salt by racing the client's
        // own randomness would be flaky, so drive the replay filter directly instead: the same
        // salt bytes accepted once must be rejected on a second `accept`.
        let salt = vec![0x11u8; key_len];
        assert!(service.replay_filter.lock().check(&salt));
        assert!(!service.replay_filter.lock().check(&salt));
    }

    /// `SaltFilter::check` must sweep the whole map only when the window has elapsed since the
    /// last sweep, not on every call: a stale entry survives one call before the window elapses
    /// and is gone on the first call after it does.
    #[test]
    fn salt_filter_sweeps_only_once_per_window_not_every_check() {
        let mut filter = SaltFilter::new();
        filter.last_clean = Instant::now();
        filter.seen.insert(vec![0xAA], Instant::now() - Duration::from_secs(61));

        assert!(filter.check(&[0xBB]));
        assert_eq!(filter.seen.len(), 2, "stale entry must not be swept before the window elapses");

        filter.last_clean = Instant::now() - Duration::from_secs(61);
        assert!(filter.check(&[0xCC]));
        assert_eq!(filter.seen.len(), 2, "sweep must drop the stale entry once the window elapses");
    }

    #[tokio::test]
    async fn tcp_bad_timestamp_is_rejected_with_the_documented_error_text() {
        let (name, key_len) = CIPHERS[0];
        let psk = password(key_len);
        let client = ClientMethod::new(name, &psk).expect("client method");
        // Skews only this service's clock by an hour, independent of any other test's clock,
        // so the request's embedded timestamp lands far outside the 30s window.
        let service = Service::new_with_time_fn(
            name,
            &psk,
            TEST_UDP_TIMEOUT,
            Arc::new(|| murmur_ntp::time::now().timestamp() + 3_600),
        )
        .expect("service");

        let (client_conn, server_conn) = pipe_pair();
        let destination = Socksaddr::fqdn("example.com", 443);
        let _client_conn = client.dial_conn(client_conn, destination).await.expect("dial conn");
        let err = match service.accept(server_conn).await {
            Ok(_) => panic!("stale timestamp must be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().starts_with("bad timestamp: received "), "unexpected error: {err}");
    }

    struct ChannelPacketConn {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        peer_port: u16,
    }

    fn channel_pair(port_a: u16, port_b: u16) -> (Arc<ChannelPacketConn>, Arc<ChannelPacketConn>) {
        let (tx_a, rx_b) = mpsc::unbounded_channel();
        let (tx_b, rx_a) = mpsc::unbounded_channel();
        (
            Arc::new(ChannelPacketConn { tx: tx_a, rx: tokio::sync::Mutex::new(rx_a), peer_port: port_b }),
            Arc::new(ChannelPacketConn { tx: tx_b, rx: tokio::sync::Mutex::new(rx_b), peer_port: port_a }),
        )
    }

    #[async_trait]
    impl PacketConn for ChannelPacketConn {
        async fn read_from(&self, _buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
            unreachable!("tests only drive wait_read_from")
        }
        async fn write_to(&self, buf: &[u8], _addr: &dyn Addr) -> io::Result<usize> {
            self.tx.send(buf.to_vec()).map_err(|_| io::Error::other("peer closed"))?;
            Ok(buf.len())
        }
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(UdpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.peer_port)))
        }
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl WaitReadFrom for ChannelPacketConn {
        async fn wait_read_from(
            &self,
        ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
            let mut rx = self.rx.lock().await;
            match rx.recv().await {
                Some(data) => {
                    let addr: Box<dyn Addr> = Box::new(UdpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.peer_port));
                    (data, None, Some(addr), Ok(()))
                }
                None => (Vec::new(), None, None, Err(io::Error::other("channel closed"))),
            }
        }
    }

    static NEXT_PORT: AtomicU16 = AtomicU16::new(30000);

    #[tokio::test]
    async fn udp_round_trip_all_ciphers() {
        for &(name, key_len) in CIPHERS {
            let psk = password(key_len);
            let client_method = ClientMethod::new(name, &psk).expect("client method");
            let service = Service::new(name, &psk, TEST_UDP_TIMEOUT).expect("service");

            let port_a = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
            let port_b = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
            let (raw_client, raw_server) = channel_pair(port_a, port_b);

            let client_pc = client_method.dial_packet_conn(raw_client);
            let server_pc = service.packet_conn(raw_server);

            let dest_addr: Box<dyn Addr> = Box::new(UdpAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
            client_pc.write_to(b"dns query", dest_addr.as_ref()).await.expect("client write");

            let (data, put, from, result) = server_pc.wait_read_from().await;
            result.expect("server decrypt");
            let addr_len = match data[0] {
                1 => 7,
                4 => 19,
                _ => unreachable!(),
            };
            assert_eq!(&data[addr_len..], b"dns query");
            if let Some(put) = put {
                put();
            }
            let from = from.expect("server sees client udp addr");

            server_pc.write_to(b"\x01\x08\x08\x08\x08\x00\x35dns reply", from.as_ref()).await.expect("server write");
            let (data, put, _from, result) = client_pc.wait_read_from().await;
            result.expect("client decrypt");
            assert_eq!(data, b"dns reply");
            if let Some(put) = put {
                put();
            }
        }
    }

    /// A reply to port 53 is padded with 1..900 random bytes when the payload is shorter than
    /// `MAX_PADDING_LENGTH`, so a DNS response does not leave the server at its true,
    /// traffic-analysis-revealing length; a reply to any other port is never padded. Compares raw
    /// wire sizes (before the client's own decrypt) for two equal-length payloads differing only
    /// in the reply's destination port.
    #[tokio::test]
    async fn udp_server_pads_port_53_replies() {
        let (name, key_len) = CIPHERS[0];
        let psk = password(key_len);
        let client_method = ClientMethod::new(name, &psk).expect("client method");
        let service = Service::new(name, &psk, TEST_UDP_TIMEOUT).expect("service");

        let port_a = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let port_b = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let (raw_client, raw_server) = channel_pair(port_a, port_b);
        let raw_client_peek = Arc::clone(&raw_client);

        let client_pc = client_method.dial_packet_conn(raw_client);
        let server_pc = service.packet_conn(raw_server);

        let dest_addr: Box<dyn Addr> = Box::new(UdpAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
        client_pc.write_to(b"dns query", dest_addr.as_ref()).await.expect("client write");
        let (_data, put, from, result) = server_pc.wait_read_from().await;
        result.expect("server decrypt");
        if let Some(put) = put {
            put();
        }
        let from = from.expect("server sees client udp addr");

        server_pc.write_to(b"\x01\x08\x08\x08\x08\x00\x35short", from.as_ref()).await.expect("server write dns reply");
        let (dns_wire, _put, _peer, result) = raw_client_peek.wait_read_from().await;
        result.expect("raw recv dns reply");

        server_pc
            .write_to(b"\x01\x08\x08\x08\x08\x1f\x90short", from.as_ref())
            .await
            .expect("server write other reply");
        let (other_wire, _put, _peer, result) = raw_client_peek.wait_read_from().await;
        result.expect("raw recv other reply");

        assert!(
            dns_wire.len() > other_wire.len(),
            "a reply to port 53 must be padded like the serverPacketWriter, dns={} other={}",
            dns_wire.len(),
            other_wire.len()
        );
    }

    #[tokio::test]
    async fn udp_packet_id_replay_is_dropped() {
        let (name, key_len) = CIPHERS[0];
        let psk = password(key_len);
        let service = Service::new(name, &psk, TEST_UDP_TIMEOUT).expect("service");
        let mut session = ServerUdpSession::new(&service);
        assert!(session.window.check(1));
        session.window.add(1);
        assert!(!session.window.check(1));
    }

    /// The age- and access-based eviction: a session that receives no packet for
    /// longer than `udp_timeout` is dropped from both `udp_sessions` and
    /// `udp_sessions_by_addr`, not kept forever.
    #[tokio::test]
    async fn udp_idle_session_is_evicted() {
        let (name, key_len) = CIPHERS[0];
        let psk = password(key_len);
        let client_method = ClientMethod::new(name, &psk).expect("client method");
        let service = Service::new(name, &psk, Duration::from_millis(50)).expect("service");

        let port_a = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let port_b = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let (raw_client, raw_server) = channel_pair(port_a, port_b);
        let client_pc = client_method.dial_packet_conn(raw_client);
        let server_pc = service.packet_conn(raw_server);

        let dest_addr: Box<dyn Addr> = Box::new(UdpAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
        client_pc.write_to(b"hello", dest_addr.as_ref()).await.expect("client write");
        let (_data, put, _from, result) = server_pc.wait_read_from().await;
        result.expect("server decrypt");
        if let Some(put) = put {
            put();
        }

        assert_eq!(service.udp_sessions.lock().len(), 1, "session recorded");
        assert_eq!(service.udp_sessions_by_addr.lock().len(), 1, "by-addr entry recorded");

        tokio::time::sleep(Duration::from_millis(250)).await;
        service.sweep_udp_sessions_if_due();

        assert!(service.udp_sessions.lock().is_empty(), "idle session must be evicted");
        assert!(service.udp_sessions_by_addr.lock().is_empty(), "by-addr mapping must be evicted too");
    }

    /// Regression test: a session's `udp_sessions_by_addr` entries must not outlive the session
    /// just because the client's source address changed mid-session (NAT rebinding, or a source
    /// port change). One session (id 5) sends first from `127.0.0.1:40001`, then again from
    /// `127.0.0.1:40002`; once the session goes idle, both `by_addr` entries must be gone, not
    /// only the most recently seen address.
    #[tokio::test]
    async fn udp_idle_session_evicts_every_by_addr_entry_after_address_change() {
        let (name, key_len) = CIPHERS[0];
        let psk = password(key_len);
        let service = Service::new(name, &psk, Duration::from_millis(50)).expect("service");
        let port_a = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let port_b = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let (_raw_client, raw_server) = channel_pair(port_a, port_b);
        let spc = ServicePacketConn { service: Arc::clone(&service), inner: raw_server };

        let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40001);
        let addr_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40002);

        let now = murmur_ntp::time::now().timestamp() as u64;
        let mut body = Vec::new();
        body.push(HEADER_TYPE_CLIENT);
        body.extend_from_slice(&now.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&encode_socksaddr(&Socksaddr::fqdn("example.com", 443)).expect("encode dest"));
        body.extend_from_slice(b"payload");

        let packet_a = build_aes_udp_packet(&service, 5, 1, &body);
        spc.open_packet(&packet_a, addr_a).expect("first packet from address A");
        let packet_b = build_aes_udp_packet(&service, 5, 2, &body);
        spc.open_packet(&packet_b, addr_b).expect("second packet from address B");

        assert_eq!(service.udp_sessions.lock().len(), 1, "one session recorded");
        assert_eq!(service.udp_sessions_by_addr.lock().len(), 2, "both addresses recorded before sweep");

        tokio::time::sleep(Duration::from_millis(250)).await;
        service.sweep_udp_sessions_if_due();

        assert!(service.udp_sessions.lock().is_empty(), "idle session must be evicted");
        assert!(
            service.udp_sessions_by_addr.lock().is_empty(),
            "every by_addr entry for the idle session must be evicted, not just the most recent address"
        );
    }

    /// Builds a valid AES-cipher UDP packet directly (bypassing `ClientPacketConn::seal_packet`,
    /// which never emits a malformed one) so `open_packet` can be fed a `plaintext_body` short
    /// enough, or a `padding_len` large enough, to have panicked before the bounds checks below.
    fn build_aes_udp_packet(service: &Service, session_id: u64, packet_id: u64, plaintext_body: &[u8]) -> Vec<u8> {
        let mut header = Vec::with_capacity(AES_BLOCK_SIZE);
        header.extend_from_slice(&session_id.to_be_bytes());
        header.extend_from_slice(&packet_id.to_be_bytes());
        let key = session_key(&service.psk, &header[..8], service.key_salt_length);
        let aead = service.kind.make_aead(&key).expect("aead");
        let nonce = &header[4..16];
        let mut sealed = Vec::new();
        aead.seal(&mut sealed, nonce, plaintext_body, &[]).expect("seal");
        let mut wire_header: [u8; AES_BLOCK_SIZE] = header[..AES_BLOCK_SIZE].try_into().unwrap();
        service.udp_block_cipher.as_ref().unwrap().encrypt_block(&mut wire_header);
        let mut packet = wire_header.to_vec();
        packet.extend_from_slice(&sealed);
        packet
    }

    /// Reproduces the panics from a real crash report: a 1-byte decrypted body used to panic at
    /// `plain[1..9]` with "range end index 9 out of range for slice of length 1", and a header
    /// with `padding_len = 0xFFFF` used to panic at `plain[11 + padding_len..]` with "range
    /// start index 65546 out of range for slice of length 11". Both must now be a clean `Err`
    /// from `open_packet` instead of taking down the listener task, with the own error text for
    /// each case: a short epoch read is a bare `EOF`, and an oversized `padding_len` is not
    /// itself an error — the length is clamped past the end, so the downstream address read
    /// reports a bare `EOF` again.
    #[tokio::test]
    async fn udp_malformed_packets_are_rejected_not_panicked() {
        let (name, key_len) = CIPHERS[0];
        let psk = password(key_len);
        let service = Service::new(name, &psk, TEST_UDP_TIMEOUT).expect("service");
        let port_a = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let port_b = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let (_raw_client, raw_server) = channel_pair(port_a, port_b);
        let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_a);
        let spc = ServicePacketConn { service: Arc::clone(&service), inner: raw_server };

        let short_body = build_aes_udp_packet(&service, 1, 1, &[0u8]);
        let err = spc.open_packet(&short_body, from).expect_err("truncated body must be rejected, not panic");
        assert_eq!(err.to_string(), "EOF", "unexpected error: {err}");

        let now = murmur_ntp::time::now().timestamp() as u64;
        let mut oversized_padding_body = Vec::new();
        oversized_padding_body.push(HEADER_TYPE_CLIENT);
        oversized_padding_body.extend_from_slice(&now.to_be_bytes());
        oversized_padding_body.extend_from_slice(&0xFFFFu16.to_be_bytes());
        let padding_packet = build_aes_udp_packet(&service, 2, 1, &oversized_padding_body);
        let err =
            spc.open_packet(&padding_packet, from).expect_err("oversized padding_len must be rejected, not panic");
        assert_eq!(err.to_string(), "EOF", "unexpected error: {err}");
    }

    /// Known-answer test: TCP requests captured from a client (a deterministic RNG override and
    /// a clock pinned to epoch 1700000000), one per cipher,
    /// dialing destination `example.com:443` with payload `ping-payload`. Proves the
    /// AEAD/CCM/chacha8 chunk framing decodes captured ciphertext byte for byte, not just this
    /// crate's own round-trip.
    #[tokio::test]
    async fn kat_tcp_request_decodes_captured_client_frames() {
        let vectors: &[(&str, &str, &str)] = &[
        ("2022-blake3-aes-128-gcm", "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "000102030405060708090a0b0c0d0e0ffab7dea34cfd4e24ec8fa13deb801e542225135bc7c80ced8e879584c99c9693c4dc8ab21e518483dd5709175f82f2ea34897169f4239008af8d90f95198dc0a58159bda80744b67d34f812d151d33aacc7c4f2b249d2519b5a6e2903c098ee12f255784a351fed78336d12f0a2deeb0ae7c19cfd7586f72c1e0284afa32de6ce3b4c635f64b75898f6ee51b12d7e44f19bc70ccb7eb4917271e8dad6548cb70b11b7433ac75d4f7dd26b511a237db49c5ad667f05725059aa7c88ee9d3c870feead98403c1a1641f2d73ba2d858a78ea3e3bb880ef0787d7ccc5b919dfd"),
        ("2022-blake3-aes-256-gcm", "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f9ad0bc425fd2cf2f21fec5d2cc3a8ff2dc98787e168f4a0425ceb8647ee179ed5c83ed4615d262c21a920c1cb725d957ce0a8a90b99b386a59cb2235010f2f70c07a61096d8f74f0c23694161b791c60cc1309a27807f2121f18cd3f92e8f61b830cde7983cedd28c30c257adc771a7ee0112137a186504fb741ebd965977d82a1ff7c107e34f3879d47bab1346bb441e97d91c2cd5744566d0b63ed9249013b98235667416e0ed5dc748f5c89f02df1b43077e7c68fba4589d3ebe7de58e3d0e1a6965ddfd0a189290bfc90149e8c5e41665f7d7805c1e8dfa3ae1d6120d05d0218e14057d2ca2d4f8c77c612098c6b594e0e5d79d06d98577217f195da04909db5456e771b2cd9876390bd996c6f00825c85cc4963df577da2b296582ae1cd7bc6f144048b4e208ac528b334fa1bec064ccba73860a42274140de073f324c0a674ac2ca201a0575b20efb8ea03c59b4c0000478b0cb1bdcaba1b26bd3d7b69ffa3ca994fd03cee27bb71f036234861d0120e8e8438e69547af63e1c5b2354bcefd754af6ebb43dded642ed8d068e60dc897e1a20ace590255852656853ff9ad3bb5a0428b33f7132d6c26ea7d9a3e28c5425b245bdeeb50c585d27a627b6d20957f07dec66714add12dcd20e9bd03a9dec62e3b86a06152a71e5755b7997d480d0caf3761132c4f1d514e72236940cf7d3120c0cc2d03d848dde2924d82c9347383596df2d5df1cce5f2cba4ce087422d16b94f432a61dc533ccd370b8f63d9bd1f82a24616e4cdb58a77129f518c353f7db614c95e82ae1d56b70908038f070caae4635be2a4ebd9618b20cbe75e15a41b5315a4fed8ea9fef6041ec00b5a1cc93d137d333539895d875608579c9e5821904a14012e61e625ff36805c93f4f171897f67446e74ffaec58fcc92919f810c4ed6a4f98c2293578d23176f94c4a8b7d364eddec02d71c9d838ab19a521cbad080307def38e14a3c4b60eeb72edc6003d1f2a7f86b209127ae99c2bab10ec4e643b82ab032724b726a8ec93ba378e4c0f75ab72941c10986a4945273adc4ef0ed0d1ffd4abcdfba5384f0ecea2109e75bcaac92a522f63b1da975a0c832b395b64d6d718a0a2c546a915edaec"),
        ("2022-blake3-chacha20-poly1305", "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fcf3074c682c8bb1bb18d310b62bbb58a10f0c96791acffdcb61044d282bd919be408c0af121ebf471da50e07f83fd368f10348ab051c92de59600e435bec298c8c743bea977e316ef64b7270f351b623c9513c5713cf4fb34a1b352d9b67f597e2da08bc184917b6af97830a884f0b4faf68d5441a882db7ef51d41b46c9c8401b0d2ce4ee70b73b893c0950d41108fb9861856dbd6acd4e98d59007a41767eae71dcddcb847417678adfae535c8f090cdf5497383050e0632e888051f537e8bc8f10ee3a3025397cfdc1cf99819c94f02b42a4289012b80e140fc8c45985a8c94cf3d1ace6f7c59bfd6c5805a8f6114b299efa54e12930e237009db73cf96e9795b3a6099d87cf62ab158e09b5a3ca1aab66263989609dcf01c37a0024f41502599acab88f05d08017f368d2a70cf26c342ac7f002589168363fc708211ec9dafff0d0e44944e5da65473d2041720a238bcb5994d5bd8766efbd88eb7568caac79bdcb4a3f3355935e928fd6a3fe27aefb2791162b9e61aae47381af06fd22cf3a78df5779b8eb2bc9fead903641170a7fa738eb64640cfaf9e691ba393e9a436907cedff00b1ab8d2887415c436839e02cf9c98adc7e616e3aa8451750747aca3fd1af698f73742ff2ffa78a396cc55cfc736e9ed578b0219c9421a43166898469c73e542b77fc42d425a8789464fdeaa761456862f8ff7b11e36794d645f6c6e6da04e0dd69f81593689b2e5e307258cd19535e6416f099fad3145675cb4955d28ff8b3829a0d269f4e6e2bd994a561400cd9c226c682ce317f4773d2a2ee6f39fd59831d7e895fa02fed2f3d0d1f4afcb534c8c42b630ec31890c28d12d30ac59349994db7809ce9e4fb5418ce1e1800ee42164c0d6b2ebb14b4cdbc180c212f7c17bc2337990b3f1f72eb4f0d714402b10b231d1b872648873ea31154bda76c2684139761fbf9b25f04fb0dc69d25136b7221ad4dcf27b13bb3b72822ff21120efc5e579dbb993c6bdf8a27413e326f3fc7972c59b0d69084126f6568f53d7e02cfdc0b5a69bda236bebcbe822d14ebf9b3633d79f28d127f82d0044d414b5ec2890f20800043962fb58b582d2023d09ddcfc6b46ac2e9e02fa79a2efa3f8198301adae7211bf736f674b3f80af774d0aa46ff8bcee18d60d7373a1810dbda377fc863e32786ee3a4ff0ff42e60dd63bfb6e060c91f9ef375dca6c18956bd4dc84ad49b5d85176df7168e8477d64c60ceff64c4c2801ded738d8e2d48a571ae2a1c3fcc841c1444d8309e0665dde733ae09b14daa1ee298b7f69ea2bd3b9dba8b0d578a0d7519e07b4640828fe76f9e6dbb6676936690aa23468ddae412aba0f883"),
        ("2022-blake3-chacha8-poly1305", "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fe2c631a6db53f3074b14ce4d741e63397d2603466486cf4549ca86aba3f4e44bf26bc091208d669554212bc5924baea03cb15c396e7828195f76a49488aaebfcc9c3abedb395c2f67f338a9b46b342b1459ec843a1497a941e2f7eb6e7d5c3a4103a9488977f2487be22fca5fc92fc5a2212d8a753e2205b2a9b2095373784e8b2c08a5174a91c2aed705a60592f5afb8b48e9299aa745381cd90a628173e14da24c6011dc4d2970a10b5274dbc93fb3d55c2a9d6a994bced75ac5081a4a5cf73379f15d91aa9a243d80032ecd8aaec68bab37832b66d6f24f04e2c68df9008e180a8c3892bd621d18f8171ec00e955ed50765dcc3ef3d73d803c98cf5c9544f1a50cecca8c4f3159bbe889a6192a7bc57c0722ce09e8c644309a5eefca3a937ff253cfa66608af00404ebf29e2b31171839a96e7e0ba41850d59c70bff7016663064336201aa5bb19a45390ad8ba1a8284e9aca1c7d931d9b720b7c95ebf836d83c7248f44557393c92986f484b4747536f18c6f6b626f12afdedd9d84f62546e8e871129beb90296f33e03821d77799287cf4158e5bb3f6456de8dedc13079ca0c20f24ffdbb52999d98d7b77a71f3d668c86a2b6ca68f8550974f79731988c9e0a65d8c875c12d4f605aeec2347854c90f769d63c06f42ece84458a1064505d669d7605d244ad9b9d349039659ca01f99f8cdecf9c2711ec30749a4561887cb66abb8af6e7da8aaac7037f2626c9416e476d3202b0ac85c28459085f7d784a6d0887e4097fe2c6bada03f3e26698739d8db37f45fde4aee1c5df5ef290956a3746fb6508cbeba054d281a5645659ed37f670a174f5bdf7aedc9cebfead368f1cb21402aaf578c7b3c724135783aed51753a8e339e7bf046a803a352f63135e0b4fa00260bd05166ed638ff0f79b1334dfdb9e24c13098f5322db6dd1c409623a767f3c12f1022c49f40fd556c591daef2541218b7f0c8dedb90a22cca44f8c0a8c6d8e5a2d726ceea53eab6bab527bfe5"),
        ("2022-blake3-aes-128-ccm", "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "000102030405060708090a0b0c0d0e0f7ba4ff832f45ed6b95a9b7eced9f2821e87d243f098f44e0958cfc1682a7f133a28f19c4ddffe0580991cb0ed1b42ddceb92d6e787d7dca9a01790baf8365e4b223230deed7dc67f58d46b9b554c21bd687893c6968507681a92c06293c38d148612b773ad73630d3473123662e0e807ad0b98a55488901597daeb18af83a1dc29aed8698ed1de9b84548d833f3fec2773ff4891df0ef6eb25ea72ea9ae187b877ce54e7f6a12151acf5944e409f987de4c5ca0edeb21097193de5923a9e24e3e86c0e5a890234e71186f71f0a965abf91b86d3217429fe661615864dc8ee3f5cfbb68b9ac5525a56948698f8beafc4e3d7e418ae88cb27ec2d9a5392450bf44ecab8cc9aabcad739b8f8da354cc8c0d04cb538b6d24dc0d76860ed13d3651f4116bb513904a86307c884e9a5cf2438f9db6b33207f28563682c1ab352caa7fd763b19a0d2635fc14d270a0a9049edb0d325688aa4843bb2fe7372d4ec9810e3e2c1c5fb8b8199202dcdb7af295222fceef5a2ffc13048c05600386c70b220b338ec562fdf55c998352d8df521a3528756222f2cedd840e8ea687be8c73316fff7848cefc0322032f67a7d202acd60aabfcd885fab0ef78d363642c398a3c56c0f06f662375c457e692b684450525a1e58601e87cb2a193755aa78b18875e6b1cc473f1f100428d87bcc3f31de26884aa07c271c63cbb4776977d2da5322226271e4bc0603a8fc8ca377f8d1dec4fe"),
        ("2022-blake3-aes-256-ccm", "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f147c7cb8e38e52b5f035cbe3a04620c1d71c955813ed93a87de29e8e15958764f300617c8c676cf43779d561439a75af4022e8dc9208d043fbe31cc34a7c44726c1a6793ae85a5c2e5ebac2bb791201b561ad32a32b4a1a426037813bcf1dd59f6696fda1df068da3c0db5691604660b0acb903c6d2f46c9e20aa6d81b20d9f351fda6ea802a15d28efba151d90173dd58a67ae032caa57b53e276d6c6f57227f832c16779e1ecdcef0a1541f2f2e7f29517dc1d169ca9229e52a806381e877f13d026569566f6be170f5d18ad8fff85bc1633ec38ec3bc60b83f3702e1ba186999ba26434b949bcc4a39c1c99fad7e3cfeda12d1502d7731877ff47ee6645c233d21d7bd129fd2267716af1c0a7d4027737d3847ed901fded7c297168131dec738d83a7f7a843acc11a2842d8f8ec54b642f841f6e25d3132d3abccc5d88b2f9feb1357a1cac815d93a3812d94c3e0623bce9279a5e91de2fa5dacd78c40d44ac457c44b6432ec111aa2c53d96e8bd9ae3be9a5e126897f1f522228a8cba142cce177fe736841a8f4ca57a1cb2ca2b6a08d3fa7f0d951ae5e53fdb13b2aad85deac73e7c736a3b34f8d52110e4571a9706bb01c5bed954cec850ff86f38135c2608be67086401297c938623953a4098b54609e5e2d9a93822f8d4578fc392c57879f6e987775e49ea8b4c172e251e1f9a9b748f2476a24bed9e92a54c1e518e9aeaabfd9c2a8b54b1063a59972385c7df"),
        ];
        for &(name, psk_hex, request_hex) in vectors {
            let psk = hex::decode(psk_hex).expect("valid psk hex");
            let request = hex::decode(request_hex).expect("valid request hex");
            let service = Service::new_with_time_fn(
                name,
                &STANDARD.encode(&psk),
                TEST_UDP_TIMEOUT,
                Arc::new(|| 1_700_000_000i64),
            )
            .expect("service");

            let (client_conn, server_conn) = pipe_pair();
            let writer = tokio::spawn(async move {
                let mut client_conn = client_conn;
                client_conn.write_all(&request).await.expect("feed golden request");
            });

            let accepted = service.accept(server_conn).await;
            let (mut conn, dest) = accepted.unwrap_or_else(|err| panic!("{name}: accept golden request: {err}"));
            assert_eq!(dest.fqdn, "example.com", "{name}: destination host");
            assert_eq!(dest.port, 443, "{name}: destination port");
            let mut buf = [0u8; 64];
            let n = conn.read(&mut buf).await.expect("read golden payload");
            assert_eq!(&buf[..n], b"ping-payload", "{name}: payload");
            writer.await.expect("writer task");
        }
    }

    /// Known-answer test: UDP packets captured the same way as
    /// `kat_tcp_request_decodes_captured_client_frames`, one per cipher, addressed to
    /// `203.0.113.1:443` with payload `udp-ping-payload`.
    #[tokio::test]
    async fn kat_udp_packet_decodes_captured_client_datagram() {
        let vectors: &[(&str, &str, &str)] = &[
        ("2022-blake3-aes-128-gcm", "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "5615c0f165a697f4973d20969de19e6740fb3c5629d7c8cdd852d5d8229ae8a1ecf7fc19c91c20cf895f9a71c530c1d2a814d04b26d548d5eff455e8168a7d8330b4"),
        ("2022-blake3-aes-256-gcm", "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "1fbc16c893185995342cdb0bd663cac360a1b3fd9642113cc1c8a4c54b11ea75830034d72765f40d7607e62006b8496126c8e5ea755571b5a1b7f82359c51e2ac131"),
        ("2022-blake3-chacha20-poly1305", "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "b1e9d74decc09809eb732f1b00bc95c27cb15f9dd4d6478f10c4f7e05b15f3c5ad80d6a65b956bea45666014ad5ecaf549db52fbbe0af944b9a69a3ba4f2f0ae926e236db94c1ca6278f23f834e62d685b202929117655b3ed26"),
        ("2022-blake3-chacha8-poly1305", "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "b1e9d74decc09809eb732f1b00bc95c27cb15f9dd4d6478fdf0628d0427e683b513e7388dca6ceff0cabd46be8f5cc1040c66e9575252379c93e61d98615874f85bda6a4c8115a37e0a6acbf3aa6d3e010a32dc8b0d6ab31adb5"),
        ("2022-blake3-aes-128-ccm", "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "5615c0f165a697f4973d20969de19e67b61a7c18d58ca2384178350331c6d96dc42c415d229551fcb60f8866a679875e19c3f4eb73d798006aa5c38c75f6709f3d9a"),
        ("2022-blake3-aes-256-ccm", "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "1fbc16c893185995342cdb0bd663cac3c646cb44f22ae75e523b714d72098d8d6ec3fdc04f9a0f4a04d77667d12a2dec0e98e316d49c5f4b675b3048892e857b5ce4"),
        ];
        for &(name, psk_hex, packet_hex) in vectors {
            let psk = hex::decode(psk_hex).expect("valid psk hex");
            let packet = hex::decode(packet_hex).expect("valid packet hex");
            let service = Service::new_with_time_fn(
                name,
                &STANDARD.encode(&psk),
                TEST_UDP_TIMEOUT,
                Arc::new(|| 1_700_000_000i64),
            )
            .expect("service");

            let port_a = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
            let port_b = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
            let (raw_client, raw_server) = channel_pair(port_a, port_b);
            raw_client.tx.send(packet).expect("feed golden packet");
            let server_pc = service.packet_conn(raw_server);

            let (data, put, _from, result) = server_pc.wait_read_from().await;
            result.unwrap_or_else(|err| panic!("{name}: decode golden packet: {err}"));

            // `203.0.113.1:443` is IPv4 (ATYP 1): 1 type byte + 4 address bytes + 2 port bytes.
            assert_eq!(data[0], 1, "{name}: destination atyp");
            assert_eq!(&data[1..7], &[203, 0, 113, 1, 1, 187], "{name}: destination addr:port");
            assert_eq!(&data[7..], b"udp-ping-payload", "{name}: payload");
            if let Some(put) = put {
                put();
            }
        }
    }

    struct SealBeforeSendFlakyConn {
        calls: usize,
    }
    impl AsyncRead for SealBeforeSendFlakyConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for SealBeforeSendFlakyConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.calls += 1;
            match this.calls {
                // Response header + chunk 1: delivered whole.
                1 => Poll::Ready(Ok(buf.len())),
                // Chunk 2's first inner write attempt: park before a single byte goes out.
                2 => Poll::Pending,
                // Chunk 2's resumed write: fails with zero bytes of *this* chunk ever sent.
                3 => Poll::Ready(Err(io::Error::from(io::ErrorKind::TimedOut))),
                // Every call after that would otherwise succeed outright.
                _ => Poll::Ready(Ok(buf.len())),
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl NetStream for SealBeforeSendFlakyConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1))
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2))
        }
    }

    /// Regression for `agent://ReviewBridge2` P2: mirrors
    /// `client::tests::client_conn_write_tears_down_when_a_sealed_chunk_fails_before_any_byte_is_sent`
    /// for `ServerConn`. `seal_chunk`/`seal_into` advance the AEAD nonce the moment a chunk is
    /// sealed into `pending_write`, before a single byte of it is written, so a chunk that fails
    /// on its very first inner write attempt must tear the conn even though zero bytes of it
    /// were ever sent.
    #[test]
    fn server_conn_write_tears_down_when_a_sealed_chunk_fails_before_any_byte_is_sent() {
        let psk = vec![0u8; CipherKind::Aes128Gcm.key_salt_length()];
        let key_salt_length = CipherKind::Aes128Gcm.key_salt_length();
        let read_aead = CipherKind::Aes128Gcm.make_aead(&[0u8; 16]).expect("aead builds");
        let read_cipher = ChunkCipher::new(read_aead);
        let time_fn: TimeFn = Arc::new(|| 0);
        let mut conn = ServerConn::new(
            Box::new(SealBeforeSendFlakyConn { calls: 0 }),
            read_cipher,
            CipherKind::Aes128Gcm,
            psk,
            key_salt_length,
            vec![0u8; key_salt_length],
            Vec::new(),
            time_fn,
        );

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let chunk1 = vec![0xAAu8; 64];
        match Pin::new(&mut conn).poll_write(&mut cx, &chunk1) {
            Poll::Ready(Ok(n)) => assert_eq!(n, chunk1.len(), "response header + chunk 1 must be delivered whole"),
            other @ Poll::Ready(_) | other @ Poll::Pending => {
                panic!("expected the first write to succeed outright, got {other:?}")
            }
        }

        let chunk2 = vec![0xBBu8; 64];
        match Pin::new(&mut conn).poll_write(&mut cx, &chunk2) {
            Poll::Pending => {}
            other @ Poll::Ready(_) => {
                panic!("expected chunk 2's first inner write to park, got {other:?}")
            }
        }
        let err = match Pin::new(&mut conn).poll_write(&mut cx, &chunk2) {
            Poll::Ready(Err(err)) => err,
            other @ Poll::Pending | other @ Poll::Ready(_) => {
                panic!("expected the resumed chunk 2 write to hit the mock's scheduled failure, got {other:?}")
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        let chunk3 = vec![0xCCu8; 64];
        let err = match Pin::new(&mut conn).poll_write(&mut cx, &chunk3) {
            Poll::Ready(Err(err)) => err,
            other @ Poll::Pending | other @ Poll::Ready(_) => {
                panic!("a write after a sealed-but-undelivered chunk's failure must fail closed, got {other:?}")
            }
        };
        assert_eq!(
            err.kind(),
            io::ErrorKind::BrokenPipe,
            "the conn must tear down the moment a sealed chunk is dropped, even with zero bytes sent"
        );
    }
}

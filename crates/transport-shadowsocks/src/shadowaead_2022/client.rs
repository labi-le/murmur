//! The client-only half of the AEAD-2022 ciphers.
//! See the module doc for scope.
//!
//! Multi-PSK EIH is implemented for both the TCP request (`build_request`) and the AES UDP path
//! (`ClientPacketConn::seal_packet`): `adapter::outbound::shadowsocks` can dial a multi-user
//! server with a colon-joined password over either transport. UDP EIH for the chacha ciphers is
//! unsupported because the UDP write path refuses that combination; the single-PSK UDP path is
//! otherwise complete for every cipher (session id, packet id, sliding window replay, timestamp
//! check).

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::protocol::{
    check_timestamp, decode_socksaddr, encode_socksaddr, err_bad_client_session_id, err_bad_header_type,
    err_bad_request_salt, err_no_eih, err_packet_id_not_unique, err_packet_too_short, err_too_many_server_sessions,
    identity_subkey, now_unix, psk_hash_blocks, session_key, system_time_fn, AesBlockCipher, ChunkCipher, CipherKind,
    KeyedXof, TimeFn, AES_BLOCK_SIZE, HEADER_TYPE_CLIENT, HEADER_TYPE_SERVER, MAX_CHUNK_SIZE, MAX_PADDING_LENGTH,
    OVERHEAD, PACKET_LENGTH_BUFFER_SIZE, PACKET_MINIMAL_HEADER_SIZE, PACKET_NONCE_SIZE,
    REQUEST_HEADER_FIXED_CHUNK_LENGTH,
};
use super::sliding_window::SlidingWindow;
use crate::shadowaead::cipher::Aead;
use murmur_common_net::io::Stream as NetStream;
use murmur_common_net::{EnhancePacketConn, WaitReadFrom};
use murmur_common_pool as pool;
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Addr, PacketConn, TcpAddr, UdpAddr};

fn to_io_error(err: anyhow::Error) -> io::Error {
    io::Error::other(err)
}

fn socksaddr_to_addr(dest: &Socksaddr) -> Box<dyn Addr> {
    match dest.addr {
        Some(ip) => Box::new(UdpAddr::new(ip, dest.port)),
        None => Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), dest.port)),
    }
}

/// `err_packet_too_short` stands in for the truncation panic a checked frame would otherwise take.
fn read_u64_at(buf: &[u8], offset: usize) -> Result<u64> {
    let bytes: [u8; 8] = buf
        .get(offset..)
        .and_then(|tail| tail.get(..8))
        .and_then(|head| head.try_into().ok())
        .ok_or_else(err_packet_too_short)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_u16_at(buf: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = buf
        .get(offset..)
        .and_then(|tail| tail.get(..2))
        .and_then(|head| head.try_into().ok())
        .ok_or_else(err_packet_too_short)?;
    Ok(u16::from_be_bytes(bytes))
}

/// The request header's `var_len`/`padding_len` fields are `uint16`; both are bounded by
/// `MAX_PADDING_LENGTH` plus one socksaddr, so the conversion never actually saturates.
fn wire_len(len: usize) -> u16 {
    u16::try_from(len).unwrap_or(u16::MAX)
}

pub struct ClientMethod {
    kind: CipherKind,
    key_salt_length: usize,
    psk_list: Vec<Vec<u8>>,
    psk_hash: Option<Vec<u8>>,
    /// The UDP AEAD, only set for `2022-blake3-chacha20-poly1305` (XChaCha20-Poly1305).
    udp_cipher: Option<Box<dyn Aead>>,
    /// The UDP block encrypt/decrypt ciphers, only set for the AES ciphers.
    udp_block_encrypt: Option<AesBlockCipher>,
    udp_block_decrypt: Option<AesBlockCipher>,
    time_fn: TimeFn,
}

impl std::fmt::Debug for ClientMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted: the PSKs and every cipher derived from them are key material.
        f.debug_struct("ClientMethod")
            .field("kind", &self.kind)
            .field("key_salt_length", &self.key_salt_length)
            .field("psk_count", &self.psk_list.len())
            .field("has_psk_hash", &self.psk_hash.is_some())
            .field("udp_cipher", &self.udp_cipher.is_some())
            .field("udp_block_encrypt", &self.udp_block_encrypt.is_some())
            .field("udp_block_decrypt", &self.udp_block_decrypt.is_some())
            .finish_non_exhaustive()
    }
}

impl ClientMethod {
    /// Builds a `ClientMethod` using the default `murmur_ntp::time::now` clock.
    pub fn new(cipher_name: &str, password: &str) -> Result<Arc<Self>> {
        Self::new_with_time_fn(cipher_name, password, system_time_fn())
    }

    /// The clock function, exposed so tests can substitute a fixed or skewed clock
    /// instead of mutating the process-wide `murmur_ntp::time` offset.
    pub(crate) fn new_with_time_fn(cipher_name: &str, password: &str, time_fn: TimeFn) -> Result<Arc<Self>> {
        let kind = CipherKind::parse(cipher_name)
            .ok_or_else(|| anyhow!("shadowsocks 2022: unsupported method: {cipher_name}"))?;
        let key_salt_length = kind.key_salt_length();

        if password.is_empty() {
            return Err(anyhow!("missing password"));
        }
        let mut psk_list = Vec::new();
        for part in password.split(':') {
            let decoded = STANDARD.decode(part).map_err(|err| anyhow!("decode key: {err}"))?;
            psk_list.push(decoded);
        }
        if !kind.is_aes() && psk_list.len() > 1 {
            return Err(err_no_eih());
        }
        for k in &psk_list {
            if k.len() != key_salt_length {
                return Err(anyhow!("bad key length, required {key_salt_length}, got {}", k.len()));
            }
        }
        let psk_hash = psk_hash_blocks(&psk_list);

        let (udp_cipher, udp_block_encrypt, udp_block_decrypt) = if kind.is_aes() {
            let encrypt = AesBlockCipher::new(psk_list.first().ok_or_else(|| anyhow!("missing password"))?)?;
            let decrypt = AesBlockCipher::new(psk_list.last().ok_or_else(|| anyhow!("missing password"))?)?;
            (None, Some(encrypt), Some(decrypt))
        } else {
            let cipher = kind.make_udp_aead(psk_list.first().ok_or_else(|| anyhow!("missing password"))?)?;
            (Some(cipher), None, None)
        };

        Ok(Arc::new(Self {
            kind,
            key_salt_length,
            psk_list,
            psk_hash,
            udp_cipher,
            udp_block_encrypt,
            udp_block_decrypt,
            time_fn,
        }))
    }

    fn last_psk(&self) -> &[u8] {
        self.psk_list.last().map_or(&[][..], Vec::as_slice)
    }

    /// Builds the request, minus the "stuff the first write's payload into the request's
    /// variable chunk" optimization: the request always carries an empty payload here, and a
    /// real caller's first write after connecting goes through the ordinary chunk writer. This
    /// changes chunk boundaries but not wire framing: any AEAD-2022 reader decodes chunk by
    /// chunk regardless of where a boundary falls.
    fn build_request(&self, destination: &Socksaddr) -> Result<(Vec<u8>, ChunkCipher, Vec<u8>)> {
        let mut salt = vec![0u8; self.key_salt_length];
        rand::rng().fill_bytes(&mut salt);
        let mut wire = salt.clone();

        if let Some(psk_hash) = &self.psk_hash {
            let n = self.psk_list.len();
            for (i, (psk, hash_block)) in self.psk_list.iter().zip(psk_hash.chunks_exact(AES_BLOCK_SIZE)).enumerate() {
                let subkey = identity_subkey(psk, &salt, self.key_salt_length);
                let block_cipher = AesBlockCipher::new(&subkey)?;
                let mut block = [0u8; AES_BLOCK_SIZE];
                block.copy_from_slice(hash_block);
                block_cipher.encrypt_block(&mut block);
                wire.extend_from_slice(&block);
                if i == n - 2 {
                    break;
                }
            }
        }

        let session_key = session_key(self.last_psk(), &salt, self.key_salt_length);
        let aead = self.kind.make_aead(&session_key)?;
        let mut writer = ChunkCipher::new(aead);

        let addr_bytes = encode_socksaddr(destination)?;
        let padding_len = rand::rng().random_range(1..=MAX_PADDING_LENGTH);
        let var_len = addr_bytes.len() + 2 + padding_len;

        let mut fixed = Vec::with_capacity(REQUEST_HEADER_FIXED_CHUNK_LENGTH);
        fixed.push(HEADER_TYPE_CLIENT);
        fixed.extend_from_slice(&now_unix((self.time_fn)()).to_be_bytes());
        fixed.extend_from_slice(&wire_len(var_len).to_be_bytes());
        writer.seal_into(&mut wire, &fixed)?;

        let mut var = Vec::with_capacity(var_len);
        var.extend_from_slice(&addr_bytes);
        var.extend_from_slice(&wire_len(padding_len).to_be_bytes());
        var.resize(var.len() + padding_len, 0);
        writer.seal_into(&mut wire, &var)?;

        Ok((wire, writer, salt))
    }

    /// Writes the request eagerly.
    pub async fn dial_conn(
        self: &Arc<Self>,
        mut conn: Box<dyn NetStream>,
        destination: Socksaddr,
    ) -> Result<Box<dyn NetStream>> {
        let (wire, writer, request_salt) = self.build_request(&destination)?;
        conn.write_all(&wire).await?;
        Ok(Box::new(ClientConn::new(conn, Arc::clone(self), writer, request_salt)))
    }

    #[must_use]
    pub fn dial_early_conn(self: &Arc<Self>, conn: Box<dyn NetStream>, destination: Socksaddr) -> Box<dyn NetStream> {
        Box::new(ClientConn::new_early(conn, Arc::clone(self), destination))
    }

    pub fn dial_packet_conn(self: &Arc<Self>, conn: Arc<dyn EnhancePacketConn>) -> Arc<dyn EnhancePacketConn> {
        Arc::new(ClientPacketConn {
            session: Mutex::new(ClientUdpSession::new(self)),
            method: Arc::clone(self),
            inner: conn,
        })
    }
}

enum WritePhase {
    NeedRequest { destination: Socksaddr },
    Ready(ChunkCipher),
}

#[allow(clippy::enum_variant_names)]
enum ReadPhase {
    NeedSalt,
    NeedFixedChunk { salt: Vec<u8> },
    NeedVarChunk { cipher: ChunkCipher, want: usize },
    NeedChunkLen { cipher: ChunkCipher },
    NeedChunkData { cipher: ChunkCipher, want: usize },
}

struct ClientConn {
    inner: Box<dyn NetStream>,
    method: Arc<ClientMethod>,
    write: WritePhase,
    pending_write: Vec<u8>,
    pending_write_sent: usize,
    pending_plain_len: usize,
    /// The exact caller-visible plaintext `pending_write` was sealed from; see
    /// `VerifiedConn::write_state`'s twin field in `transport-shadowtls/src/v3.rs` for why a
    /// mismatch on resumption means the caller that started this chunk gave up on it.
    pending_plain: Vec<u8>,
    /// Set once a resumed write is found to carry different plaintext than the chunk already
    /// mid-flight: every later read/write fails with `BrokenPipe` instead of risking the stale
    /// chunk's remaining bytes reaching the peer under a new caller's name, or misreporting this
    /// call's byte count — the own contract that a mid-frame write failure leaves the conn
    /// broken, never silently resumable.
    torn: bool,
    request_salt: Vec<u8>,
    read: ReadPhase,
    read_acc: Vec<u8>,
    read_pending: Vec<u8>,
}

impl ClientConn {
    fn new(inner: Box<dyn NetStream>, method: Arc<ClientMethod>, writer: ChunkCipher, request_salt: Vec<u8>) -> Self {
        Self {
            inner,
            method,
            write: WritePhase::Ready(writer),
            pending_write: Vec::new(),
            pending_write_sent: 0,
            pending_plain_len: 0,
            pending_plain: Vec::new(),
            torn: false,
            request_salt,
            read: ReadPhase::NeedSalt,
            read_acc: Vec::new(),
            read_pending: Vec::new(),
        }
    }

    fn new_early(inner: Box<dyn NetStream>, method: Arc<ClientMethod>, destination: Socksaddr) -> Self {
        Self {
            inner,
            method,
            write: WritePhase::NeedRequest { destination },
            pending_write: Vec::new(),
            pending_write_sent: 0,
            pending_plain_len: 0,
            pending_plain: Vec::new(),
            torn: false,
            request_salt: Vec::new(),
            read: ReadPhase::NeedSalt,
            read_acc: Vec::new(),
            read_pending: Vec::new(),
        }
    }
}

fn client_torn_err() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "shadowsocks: conn torn by an abandoned mid-frame write")
}

/// The read driver selects a phase arm from `&self.read` before moving the phase out, so the
/// moved value always matches; a mismatch is reported rather than panicked on.
fn client_read_phase_err() -> io::Error {
    io::Error::other("shadowsocks: client read phase out of sync")
}

fn poll_write_record(
    inner: &mut dyn NetStream,
    cx: &mut Context<'_>,
    record: &[u8],
    sent: &mut usize,
) -> Poll<io::Result<()>> {
    while *sent < record.len() {
        let Some(rest) = record.get(*sent..) else {
            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
        };
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
        let Some(dst) = chunk.get_mut(..take) else {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        };
        let mut read_buf = ReadBuf::new(dst);
        ready!(Pin::new(&mut *inner).poll_read(cx, &mut read_buf))?;
        if read_buf.filled().is_empty() {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        acc.extend_from_slice(read_buf.filled());
    }
    Poll::Ready(Ok(()))
}

impl AsyncWrite for ClientConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.torn {
            return Poll::Ready(Err(client_torn_err()));
        }
        loop {
            if !this.pending_write.is_empty() {
                if this.pending_plain_len > 0 && !buf.starts_with(&this.pending_plain) {
                    this.pending_write.clear();
                    this.pending_write_sent = 0;
                    this.pending_plain_len = 0;
                    this.pending_plain.clear();
                    this.torn = true;
                    return Poll::Ready(Err(client_torn_err()));
                }
                match poll_write_record(&mut *this.inner, cx, &this.pending_write, &mut this.pending_write_sent) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => {
                        // The pending write is only ever populated already sealed — either
                        // `seal_chunk` (which advances the AEAD nonce) or `build_request` (whose
                        // wire already commits the session's request salt) run before this arm
                        // can be reached. Dropping a sealed frame here, even with zero bytes of
                        // it on the wire yet, leaves the peer's crypto state permanently
                        // desynchronized the moment the *next* frame is sealed with the advanced
                        // nonce (`agent://ReviewBridge2` P2), so every failure while a sealed
                        // frame is pending must tear the whole conn, matching the own contract
                        // that a mid-frame write failure leaves the conn broken.
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

            if let WritePhase::NeedRequest { destination } = &this.write {
                let (wire, writer, salt) = this.method.build_request(destination).map_err(to_io_error)?;
                this.request_salt = salt;
                this.write = WritePhase::Ready(writer);
                this.pending_write = wire;
                continue;
            }

            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let WritePhase::Ready(writer) = &mut this.write else {
                // The `NeedRequest` arm above always moves the phase to `Ready` before looping.
                continue;
            };
            let n = buf.len().min(MAX_CHUNK_SIZE);
            let (plain, _) = buf.split_at(n);
            let sealed = writer.seal_chunk(plain).map_err(to_io_error)?;
            this.pending_write = sealed;
            this.pending_plain_len = n;
            this.pending_plain = plain.to_vec();
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncRead for ClientConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.torn {
            return Poll::Ready(Err(client_torn_err()));
        }
        loop {
            if !this.read_pending.is_empty() {
                let n = buf.remaining().min(this.read_pending.len());
                let (pending, _) = this.read_pending.split_at(n);
                buf.put_slice(pending);
                this.read_pending.drain(..n);
                return Poll::Ready(Ok(()));
            }

            match &this.read {
                ReadPhase::NeedSalt => {
                    let want = this.method.key_salt_length;
                    ready!(poll_read_exact(&mut *this.inner, cx, &mut this.read_acc, want))?;
                    let salt = std::mem::take(&mut this.read_acc);
                    this.read = ReadPhase::NeedFixedChunk { salt };
                }
                ReadPhase::NeedFixedChunk { .. } => {
                    let want = 1 + 8 + this.method.key_salt_length + 2 + OVERHEAD;
                    ready!(poll_read_exact(&mut *this.inner, cx, &mut this.read_acc, want))?;
                    let ReadPhase::NeedFixedChunk { salt } = std::mem::replace(&mut this.read, ReadPhase::NeedSalt)
                    else {
                        return Poll::Ready(Err(client_read_phase_err()));
                    };
                    let key = session_key(this.method.last_psk(), &salt, this.method.key_salt_length);
                    let aead = this.method.kind.make_aead(&key).map_err(to_io_error)?;
                    let mut cipher = ChunkCipher::new(aead);
                    let plain = cipher.open(&this.read_acc).map_err(to_io_error)?;
                    this.read_acc.clear();
                    let (header_type, rest) =
                        plain.split_first().ok_or_else(err_packet_too_short).map_err(to_io_error)?;
                    if *header_type != HEADER_TYPE_SERVER {
                        return Poll::Ready(Err(to_io_error(err_bad_header_type(HEADER_TYPE_SERVER, *header_type))));
                    }
                    let epoch = read_u64_at(rest, 0).map_err(to_io_error)?;
                    check_timestamp(epoch, (this.method.time_fn)()).map_err(to_io_error)?;
                    let var_start = 8 + this.method.key_salt_length;
                    let response_salt = rest.get(8..var_start).ok_or_else(err_packet_too_short).map_err(to_io_error)?;
                    if response_salt != this.request_salt.as_slice() {
                        return Poll::Ready(Err(to_io_error(err_bad_request_salt())));
                    }
                    let var_len = usize::from(read_u16_at(rest, var_start).map_err(to_io_error)?);
                    this.read = ReadPhase::NeedVarChunk { cipher, want: var_len + OVERHEAD };
                }
                ReadPhase::NeedVarChunk { want, .. } => {
                    let want = *want;
                    ready!(poll_read_exact(&mut *this.inner, cx, &mut this.read_acc, want))?;
                    let ReadPhase::NeedVarChunk { mut cipher, .. } =
                        std::mem::replace(&mut this.read, ReadPhase::NeedSalt)
                    else {
                        return Poll::Ready(Err(client_read_phase_err()));
                    };
                    let plain = cipher.open(&this.read_acc).map_err(to_io_error)?;
                    this.read_acc.clear();
                    this.read = ReadPhase::NeedChunkLen { cipher };
                    this.read_pending = plain;
                }
                ReadPhase::NeedChunkLen { .. } => {
                    let want = PACKET_LENGTH_BUFFER_SIZE + OVERHEAD;
                    ready!(poll_read_exact(&mut *this.inner, cx, &mut this.read_acc, want))?;
                    let ReadPhase::NeedChunkLen { mut cipher } = std::mem::replace(&mut this.read, ReadPhase::NeedSalt)
                    else {
                        return Poll::Ready(Err(client_read_phase_err()));
                    };
                    let len = cipher.open_length(&this.read_acc).map_err(to_io_error)?;
                    this.read_acc.clear();
                    this.read = ReadPhase::NeedChunkData { cipher, want: len + OVERHEAD };
                }
                ReadPhase::NeedChunkData { want, .. } => {
                    let want = *want;
                    ready!(poll_read_exact(&mut *this.inner, cx, &mut this.read_acc, want))?;
                    let ReadPhase::NeedChunkData { mut cipher, .. } =
                        std::mem::replace(&mut this.read, ReadPhase::NeedSalt)
                    else {
                        return Poll::Ready(Err(client_read_phase_err()));
                    };
                    let plain = cipher.open(&this.read_acc).map_err(to_io_error)?;
                    this.read_acc.clear();
                    this.read = ReadPhase::NeedChunkLen { cipher };
                    this.read_pending = plain;
                }
            }
        }
    }
}

impl NetStream for ClientConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
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

struct ClientUdpSession {
    session_id: u64,
    packet_id: u64,
    /// The AES-path session-keyed AEAD for this client's own outgoing
    /// packets. `None` for the chacha path, which reuses `ClientMethod::udp_cipher` directly.
    cipher: Option<Box<dyn Aead>>,
    rng: Option<KeyedXof>,
    remote_session_id: u64,
    remote_cipher: Option<Box<dyn Aead>>,
    last_remote_session_id: u64,
    last_remote_cipher: Option<Box<dyn Aead>>,
    last_remote_seen: i64,
    /// Freshly derived remote cipher, staged in `open_packet` while the session-id/packet-id
    /// bookkeeping is still validating a not-yet-seen session, then adopted on success.
    pending_remote_cipher: Option<Box<dyn Aead>>,
    window: SlidingWindow,
    last_window: SlidingWindow,
}

impl ClientUdpSession {
    #[expect(
        clippy::expect_used,
        reason = "ClientMethod already rejected every PSK whose length does not match the cipher"
    )]
    fn new(method: &ClientMethod) -> Self {
        let (session_id, rng) = if method.udp_cipher.is_some() {
            let mut rng = KeyedXof::new();
            (rng.read_u64(), Some(rng))
        } else {
            (rand::rng().random::<u64>(), None)
        };
        let cipher = if method.udp_cipher.is_none() {
            let sid = session_id.to_be_bytes();
            let key = session_key(method.last_psk(), &sid, method.key_salt_length);
            Some(method.kind.make_aead(&key).expect("valid psk length already validated"))
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
            last_remote_session_id: 0,
            last_remote_cipher: None,
            last_remote_seen: 0,
            pending_remote_cipher: None,
            window: SlidingWindow::default(),
            last_window: SlidingWindow::default(),
        }
    }

    fn next_packet_id(&mut self) -> u64 {
        self.packet_id += 1;
        self.packet_id
    }

    fn check_packet_id_unique(&self, session_id: u64, packet_id: u64) -> Result<()> {
        if session_id == self.remote_session_id {
            if !self.window.check(packet_id) {
                return Err(err_packet_id_not_unique());
            }
        } else if session_id == self.last_remote_session_id && !self.last_window.check(packet_id) {
            return Err(err_packet_id_not_unique());
        }
        Ok(())
    }

    /// Books a freshly seen remote session or advances the window of a known one, then checks the
    /// packet echoes this client's own session id.
    fn accept_remote_packet(&mut self, session_id: u64, packet_id: u64, now: i64, plain: &[u8]) -> Result<()> {
        if session_id == self.remote_session_id {
            self.window.add(packet_id);
        } else if session_id == self.last_remote_session_id {
            self.last_window.add(packet_id);
            self.last_remote_seen = now;
        } else {
            let new_cipher = self.pending_remote_cipher.take();
            if self.remote_session_id != 0 {
                if now - self.last_remote_seen < 60 {
                    return Err(err_too_many_server_sessions());
                }
                self.last_remote_session_id = self.remote_session_id;
                self.last_window = std::mem::take(&mut self.window);
                self.last_remote_seen = now;
                self.last_remote_cipher = self.remote_cipher.take();
            }
            self.remote_session_id = session_id;
            self.remote_cipher = new_cipher;
            self.window.add(packet_id);
        }

        if plain.len() < 19 {
            return Err(err_packet_too_short());
        }
        if read_u64_at(plain, 9)? != self.session_id {
            return Err(err_bad_client_session_id());
        }
        Ok(())
    }
}

struct ClientPacketConn {
    method: Arc<ClientMethod>,
    inner: Arc<dyn EnhancePacketConn>,
    session: Mutex<ClientUdpSession>,
}

const MAX_UDP_PACKET: usize = 64 * 1024;

impl ClientPacketConn {
    #[expect(
        clippy::expect_used,
        reason = "the AES branch is reachable only when ClientMethod built both the session cipher \
                  and the block cipher, which it does for every AES kind"
    )]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the session lock must span the seal so the packet id and the outgoing cipher advance together"
    )]
    fn seal_packet(&self, destination: &Socksaddr, payload: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock();

        let mut header = Vec::with_capacity(AES_BLOCK_SIZE);
        if let Some(rng) = session.rng.as_mut() {
            let mut nonce = [0u8; PACKET_NONCE_SIZE];
            rng.read(&mut nonce);
            header.extend_from_slice(&nonce);
        }
        header.extend_from_slice(&session.session_id.to_be_bytes());
        let packet_id = session.next_packet_id();
        header.extend_from_slice(&packet_id.to_be_bytes());

        let mut body = Vec::new();
        body.push(HEADER_TYPE_CLIENT);
        body.extend_from_slice(&now_unix((self.method.time_fn)()).to_be_bytes());
        let padding_len = if destination.port == 53 && payload.len() < MAX_PADDING_LENGTH {
            rand::rng().random_range(1..=(MAX_PADDING_LENGTH - payload.len()))
        } else {
            0
        };
        body.extend_from_slice(&wire_len(padding_len).to_be_bytes());
        body.resize(body.len() + padding_len, 0);
        body.extend_from_slice(&encode_socksaddr(destination)?);
        body.extend_from_slice(payload);

        let mut out;
        if let Some(udp_cipher) = &self.method.udp_cipher {
            let (nonce, rest) = header.split_at(PACKET_NONCE_SIZE);
            let mut plaintext = rest.to_vec();
            plaintext.extend_from_slice(&body);
            out = nonce.to_vec();
            udp_cipher.seal(&mut out, nonce, &plaintext, &[])?;
        } else {
            out = header.clone();
            if let Some(psk_hash) = &self.method.psk_hash {
                let (header_bytes, _) = header.split_at(AES_BLOCK_SIZE);
                let header_block: &[u8; AES_BLOCK_SIZE] =
                    header_bytes.try_into().map_err(|_| err_packet_too_short())?;
                let n = self.method.psk_list.len();
                for (i, (psk, hash_block)) in
                    self.method.psk_list.iter().zip(psk_hash.chunks_exact(AES_BLOCK_SIZE)).enumerate()
                {
                    let mut identity = [0u8; AES_BLOCK_SIZE];
                    for (dst, (h, p)) in identity.iter_mut().zip(hash_block.iter().zip(header_block.iter())) {
                        *dst = h ^ p;
                    }
                    AesBlockCipher::new(psk)?.encrypt_block(&mut identity);
                    out.extend_from_slice(&identity);
                    if i == n - 2 {
                        break;
                    }
                }
            }
            let nonce = header.get(AES_BLOCK_SIZE - 12..AES_BLOCK_SIZE).ok_or_else(err_packet_too_short)?;
            let cipher = session.cipher.as_ref().expect("session cipher present for aes ciphers");
            cipher.seal(&mut out, nonce, &body, &[])?;
            let mut block: [u8; AES_BLOCK_SIZE] =
                header.get(..AES_BLOCK_SIZE).and_then(|head| head.try_into().ok()).ok_or_else(err_packet_too_short)?;
            self.method
                .udp_block_encrypt
                .as_ref()
                .expect("aes cipher method builds an encrypt block cipher")
                .encrypt_block(&mut block);
            let (out_head, _) = out.split_at_mut(AES_BLOCK_SIZE);
            out_head.copy_from_slice(&block);
        }

        Ok(out)
    }

    fn open_packet(&self, buf: &[u8]) -> Result<(Socksaddr, Vec<u8>)> {
        let (header_block, payload) = self.split_packet(buf)?;

        let plain = {
            let mut session = self.session.lock();

            let (session_id, packet_id, plain) = self.decrypt_payload(&mut session, header_block, &payload)?;

            let header_type = *plain.first().ok_or_else(err_packet_too_short)?;
            if header_type != HEADER_TYPE_SERVER {
                return Err(err_bad_header_type(HEADER_TYPE_SERVER, header_type));
            }
            let epoch = read_u64_at(&plain, 1)?;
            let now = (self.method.time_fn)();
            check_timestamp(epoch, now)?;

            session.accept_remote_packet(session_id, packet_id, now, &plain)?;
            plain
        };

        let padding_len = usize::from(read_u16_at(&plain, 17)?);
        let body = plain.get(19 + padding_len..).ok_or_else(err_packet_too_short)?;
        let (destination, consumed) = decode_socksaddr(body)?;
        let payload = body.get(consumed..).ok_or_else(err_packet_too_short)?;
        Ok((destination.unwrap(), payload.to_vec()))
    }

    /// Splits a datagram into its outer header and payload: the chacha path has no header block
    /// and returns the already-decrypted payload, the AES path returns the decrypted block and
    /// leaves the body sealed.
    #[expect(
        clippy::expect_used,
        reason = "the AES branch is reachable only when ClientMethod built the decrypt block cipher"
    )]
    fn split_packet(&self, buf: &[u8]) -> Result<(Option<[u8; AES_BLOCK_SIZE]>, Vec<u8>)> {
        if let Some(udp_cipher) = self.method.udp_cipher.as_ref() {
            if buf.len() < PACKET_NONCE_SIZE + PACKET_MINIMAL_HEADER_SIZE {
                return Err(err_packet_too_short());
            }
            let (nonce, ciphertext) = buf.split_at(PACKET_NONCE_SIZE);
            let plain = udp_cipher.open(nonce, ciphertext, &[]).map_err(|e| anyhow!("decrypt packet: {e}"))?;
            Ok((None, plain))
        } else {
            if buf.len() < PACKET_MINIMAL_HEADER_SIZE {
                return Err(err_packet_too_short());
            }
            let (header_bytes, body) = buf.split_at(AES_BLOCK_SIZE);
            let mut header: [u8; AES_BLOCK_SIZE] = header_bytes.try_into().map_err(|_| err_packet_too_short())?;
            self.method
                .udp_block_decrypt
                .as_ref()
                .expect("aes cipher method builds a decrypt block cipher")
                .decrypt_block(&mut header);
            Ok((Some(header), body.to_vec()))
        }
    }

    /// Resolves the packet's session and packet ids and unseals the inner header, rejecting a
    /// replay against a remote session this client already knows.
    #[expect(
        clippy::expect_used,
        reason = "each staged remote cipher is derived for the session id it is stored beside"
    )]
    fn decrypt_payload(
        &self,
        session: &mut ClientUdpSession,
        header_block: Option<[u8; AES_BLOCK_SIZE]>,
        payload: &[u8],
    ) -> Result<(u64, u64, Vec<u8>)> {
        let Some(header) = header_block else {
            if payload.len() < 16 {
                return Err(err_packet_too_short());
            }
            let session_id = read_u64_at(payload, 0)?;
            let packet_id = read_u64_at(payload, 8)?;
            session.check_packet_id_unique(session_id, packet_id)?;
            let plain = payload.get(16..).ok_or_else(err_packet_too_short)?.to_vec();
            return Ok((session_id, packet_id, plain));
        };

        let session_id = read_u64_at(&header, 0)?;
        let packet_id = read_u64_at(&header, 8)?;
        session.check_packet_id_unique(session_id, packet_id)?;
        let nonce = header.get(4..16).ok_or_else(err_packet_too_short)?;
        let plain = if session_id == session.remote_session_id {
            session
                .remote_cipher
                .as_ref()
                .expect("remote cipher set with matching session id")
                .open(nonce, payload, &[])
                .map_err(|e| anyhow!("decrypt packet: {e}"))?
        } else if session_id == session.last_remote_session_id {
            session
                .last_remote_cipher
                .as_ref()
                .expect("last remote cipher set with matching session id")
                .open(nonce, payload, &[])
                .map_err(|e| anyhow!("decrypt packet: {e}"))?
        } else {
            let sid = header.get(..8).ok_or_else(err_packet_too_short)?;
            let key = session_key(self.method.last_psk(), sid, self.method.key_salt_length);
            let aead = self.method.kind.make_aead(&key)?;
            let opened = aead.open(nonce, payload, &[]).map_err(|e| anyhow!("decrypt packet: {e}"))?;
            session.pending_remote_cipher = Some(aead);
            opened
        };
        Ok((session_id, packet_id, plain))
    }
}

#[async_trait]
impl PacketConn for ClientPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut scratch = vec![0u8; MAX_UDP_PACKET];
        let (n, _from) = self.inner.read_from(&mut scratch).await?;
        scratch.truncate(n);
        let (destination, payload) = self.open_packet(&scratch).map_err(to_io_error)?;
        let n = payload.len().min(buf.len());
        let (dst, _) = buf.split_at_mut(n);
        let (src, _) = payload.split_at(n);
        dst.copy_from_slice(src);
        Ok((n, socksaddr_to_addr(&destination)))
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let destination = murmur_sing::metadata::socksaddr_from_net(Some(addr));
        let sealed = self.seal_packet(&destination, buf).map_err(to_io_error)?;
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
impl WaitReadFrom for ClientPacketConn {
    // NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let (data, put, _addr, result) = self.inner.wait_read_from().await;
        if result.is_err() {
            if put.is_some() {
                return (data, put, None, result);
            }
            let _ = pool::put(data);
            return (Vec::new(), None, None, result);
        }
        match self.open_packet(&data) {
            Ok((destination, payload)) => {
                // `payload` is a fresh Vec: the transferred pooled block is no longer needed.
                if put.is_none() {
                    let _ = pool::put(data);
                }
                (payload, put, Some(socksaddr_to_addr(&destination)), Ok(()))
            }
            Err(err) => {
                if let Some(put) = put {
                    put();
                } else {
                    let _ = pool::put(data);
                }
                (Vec::new(), None, None, Err(to_io_error(err)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty password builds an empty PSK list and reports "missing password"; without this
    /// check `"".split(':')` would decode one empty key and fail later with a misleading length
    /// error.
    #[test]
    fn new_with_empty_password_returns_missing_password_text() {
        let result = ClientMethod::new("2022-blake3-aes-128-gcm", "");
        let Err(err) = result else {
            panic!("expected an error for an empty password");
        };
        assert_eq!(err.to_string(), "missing password");
    }

    struct DxConn(tokio::io::DuplexStream);
    impl AsyncRead for DxConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for DxConn {
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
    impl NetStream for DxConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }
    }

    /// Deterministic regression, forced without any deadline or timing: fill the duplex so a
    /// chunk write genuinely parks mid-frame (`pending_write` holds the sealed bytes and how many
    /// have gone out), stop polling that specific write — exactly what an outer bridge abandoning
    /// a poll looks like from `ClientConn`'s point of view — and call `poll_write` again with a
    /// *different* buffer. `ClientConn` must refuse to resume the stale chunk under the new
    /// buffer's name; it must tear the whole conn down instead of reporting the old chunk's
    /// length for the new buffer (which tokio's `write_all` would otherwise index out of bounds
    /// on, or which would silently misreport a successful write of the wrong bytes).
    #[test]
    fn client_conn_write_tears_down_instead_of_resuming_a_different_buffer() {
        let method = ClientMethod::new("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==").expect("valid method");
        let aead = CipherKind::Aes128Gcm.make_aead(&[0u8; 16]).expect("aead builds");
        let writer = ChunkCipher::new(aead);
        let (dx_writer, _dx_reader) = tokio::io::duplex(16);
        let mut conn = ClientConn::new(Box::new(DxConn(dx_writer)), method, writer, vec![0u8; 8]);

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let first = vec![0xAAu8; 256];
        match Pin::new(&mut conn).poll_write(&mut cx, &first) {
            Poll::Pending => {}
            other => panic!("expected the first write to park behind the full duplex buffer, got {other:?}"),
        }

        let second = b"different buffer";
        let err = match Pin::new(&mut conn).poll_write(&mut cx, second) {
            Poll::Ready(Err(err)) => err,
            other @ Poll::Ready(Ok(_)) | other @ Poll::Pending => {
                panic!("resuming the stale chunk under a different buffer must fail cleanly, got {other:?}")
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        let mut buf = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut buf);
        match Pin::new(&mut conn).poll_read(&mut cx, &mut read_buf) {
            Poll::Ready(Err(err)) => assert_eq!(err.kind(), io::ErrorKind::BrokenPipe),
            other @ Poll::Ready(Ok(_)) | other @ Poll::Pending => {
                panic!("a torn conn must fail every subsequent read too, got {other:?}")
            }
        }
    }

    struct FlakyConn {
        calls: usize,
    }
    impl AsyncRead for FlakyConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for FlakyConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.calls += 1;
            match this.calls {
                1 => Poll::Ready(Ok(buf.len().min(10))),
                2 => Poll::Pending,
                3 => Poll::Ready(Err(io::Error::other("simulated transport failure"))),
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
    impl NetStream for FlakyConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }
    }

    /// Regression for `agent://ReviewBridge2` P2 (2): a chunk write that fails after some of its
    /// bytes already reached the peer must tear the whole conn down, not just clear the pending
    /// chunk and leave the conn writable for a fresh, unrelated chunk to land right after the
    /// partial one. `FlakyConn` accepts a partial chunk, then parks, then fails exactly once, and
    /// would otherwise accept every write after that — proving the conn stays torn because
    /// `ClientConn` itself refuses, not because the mock is unusable.
    #[test]
    fn client_conn_write_tears_down_after_a_partial_frame_write_fails() {
        let method = ClientMethod::new("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==").expect("valid method");
        let aead = CipherKind::Aes128Gcm.make_aead(&[0u8; 16]).expect("aead builds");
        let writer = ChunkCipher::new(aead);
        let mut conn = ClientConn::new(Box::new(FlakyConn { calls: 0 }), method, writer, vec![0u8; 8]);

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let payload = vec![0xAAu8; 256];
        match Pin::new(&mut conn).poll_write(&mut cx, &payload) {
            Poll::Pending => {}
            other => panic!("expected the write to park after a partial inner accept, got {other:?}"),
        }
        assert!(conn.pending_write_sent > 0, "FlakyConn's first call must have accepted some bytes before parking");

        let err = match Pin::new(&mut conn).poll_write(&mut cx, &payload) {
            Poll::Ready(Err(err)) => err,
            other @ Poll::Ready(Ok(_)) | other @ Poll::Pending => {
                panic!("expected the resumed write to hit the mock's one scheduled failure, got {other:?}")
            }
        };
        assert_eq!(err.to_string(), "simulated transport failure");

        let err = match Pin::new(&mut conn).poll_write(&mut cx, b"fresh, unrelated write") {
            Poll::Ready(Err(err)) => err,
            other @ Poll::Ready(Ok(_)) | other @ Poll::Pending => {
                panic!("a write after a partial-frame failure must fail closed, got {other:?}")
            }
        };
        assert_eq!(
            err.kind(),
            io::ErrorKind::BrokenPipe,
            "the conn must stay torn so no later write ever puts a fresh chunk after the partial one"
        );
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
                // Chunk 1: delivered whole.
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
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }
    }

    /// Regression for `agent://ReviewBridge2` P2: `seal_chunk` advances the AEAD nonce the
    /// moment a chunk is sealed into `pending_write`, before a single byte of it is written. The
    /// old tear condition (`pending_write_sent > 0`) only fired once bytes had gone out, so a
    /// chunk that fails on its very first inner write attempt — sealed but wholly undelivered —
    /// used to leave the conn writable, and the next chunk would be sealed against a nonce the
    /// peer's decryptor never advanced past. `SealBeforeSendFlakyConn` delivers chunk 1, then
    /// fails chunk 2 before any of its bytes reach the mock (`TimedOut`, matching a real deadline
    /// mid-chunk), and would otherwise accept chunk 3 outright: proving `ClientConn` now refuses
    /// chunk 3 on its own.
    #[test]
    fn client_conn_write_tears_down_when_a_sealed_chunk_fails_before_any_byte_is_sent() {
        let method = ClientMethod::new("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==").expect("valid method");
        let aead = CipherKind::Aes128Gcm.make_aead(&[0u8; 16]).expect("aead builds");
        let writer = ChunkCipher::new(aead);
        let mut conn = ClientConn::new(Box::new(SealBeforeSendFlakyConn { calls: 0 }), method, writer, vec![0u8; 8]);

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let chunk1 = vec![0xAAu8; 64];
        match Pin::new(&mut conn).poll_write(&mut cx, &chunk1) {
            Poll::Ready(Ok(n)) => assert_eq!(n, chunk1.len(), "chunk 1 must be delivered whole"),
            other @ Poll::Ready(Err(_)) | other @ Poll::Pending => {
                panic!("expected chunk 1 to succeed outright, got {other:?}")
            }
        }

        let chunk2 = vec![0xBBu8; 64];
        match Pin::new(&mut conn).poll_write(&mut cx, &chunk2) {
            Poll::Pending => {}
            other => panic!("expected chunk 2's first inner write to park, got {other:?}"),
        }
        let err = match Pin::new(&mut conn).poll_write(&mut cx, &chunk2) {
            Poll::Ready(Err(err)) => err,
            other @ Poll::Ready(Ok(_)) | other @ Poll::Pending => {
                panic!("expected the resumed chunk 2 write to hit the mock's scheduled failure, got {other:?}")
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        let chunk3 = vec![0xCCu8; 64];
        let err = match Pin::new(&mut conn).poll_write(&mut cx, &chunk3) {
            Poll::Ready(Err(err)) => err,
            other @ Poll::Ready(Ok(_)) | other @ Poll::Pending => {
                panic!("a write after a sealed-but-undelivered chunk's failure must fail closed, got {other:?}")
            }
        };
        assert_eq!(
            err.kind(),
            io::ErrorKind::BrokenPipe,
            "the conn must tear down the moment a sealed chunk is dropped, even with zero bytes sent"
        );
    }

    /// Regression for `agent://ReviewBridge2` P2 (1): the resume check used to require the
    /// resumed `buf` to equal the pending chunk's plaintext exactly. `AsyncWrite`'s own contract
    /// lets a caller resume a `Pending` poll with a buffer that has grown since (`tokio::io::copy`,
    /// `BufWriter`), and that must not tear the conn as long as the new buffer still starts with
    /// the exact bytes already sealed. ss2022 already used a prefix check before this unit, so
    /// this documents the existing, correct behavior against a regression.
    #[test]
    fn client_conn_write_accepts_a_resumed_buffer_that_grew_since_the_last_poll() {
        let method = ClientMethod::new("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==").expect("valid method");
        let aead = CipherKind::Aes128Gcm.make_aead(&[0u8; 16]).expect("aead builds");
        let writer = ChunkCipher::new(aead);
        let (dx_writer, _dx_reader) = tokio::io::duplex(16);
        let mut conn = ClientConn::new(Box::new(DxConn(dx_writer)), method, writer, vec![0u8; 8]);

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let first = vec![0xAAu8; 256];
        match Pin::new(&mut conn).poll_write(&mut cx, &first) {
            Poll::Pending => {}
            other => panic!("expected the first write to park behind the full duplex buffer, got {other:?}"),
        }

        let mut grown = first.clone();
        grown.extend_from_slice(&[0xBBu8; 64]);
        match Pin::new(&mut conn).poll_write(&mut cx, &grown) {
            Poll::Pending => {}
            other => panic!(
                "a resumed poll with a buffer that grew but still starts with the sealed chunk's bytes \
                 must not tear the conn, got {other:?}"
            ),
        }
    }
}

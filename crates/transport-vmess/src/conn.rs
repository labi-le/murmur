//! `Conn` drives its reader and writer halves (each backed by the same conn) with plain synchronous
//! reads and writes, including the multi-step AEAD handshake response read.
//!
//! A Rust `AsyncRead`/`AsyncWrite` impl only holds `Pin<&mut Self>` for the
//! duration of one `poll_*` call, so the multi-`await` body runs inside a boxed future stored
//! between polls and driven under an `Arc<tokio::sync::Mutex<Inner>>` — the same pattern
//! `transport/sudoku/obfs/httpmask/ws_stream_conn.rs`'s `WsStreamConn` uses for the same reason.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes::cipher::{KeyInit, KeyIvInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes128Gcm;
use bytes::{BufMut, BytesMut};
use cfb_mode::{Decryptor, Encryptor};
use chacha20poly1305::ChaCha20Poly1305;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use md5::{Digest as _, Md5};
use parking_lot::Mutex as SyncMutex;
use rand::{Rng, RngCore};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;

use murmur_common::shared_conn::SharedConn as VmessSharedConn;
use murmur_common_net::io::Stream;
use murmur_std_compat::net::Conn as NetConn;

use super::aead::{AeadCipher, AeadReader, AeadWriter};
use super::chunk::{ChunkReader, ChunkWriter};
use super::header;
use super::user::Id;
use super::vmess::{
    DstAddr, Security, COMMAND_TCP, COMMAND_UDP, OPTION_CHUNK_STREAM, SECURITY_AES128GCM, SECURITY_CHACHA20POLY1305,
};

#[allow(
    clippy::large_enum_variant,
    reason = "AeadReader embeds the AeadCipher key material directly (see aead.rs); ChunkReader is a plain buffer/offset pair, so the size gap reflects real state, not layout neglect"
)]
enum Reader {
    Chunk(ChunkReader),
    Aead(AeadReader),
}

impl Reader {
    async fn read(&mut self, conn: &mut dyn Stream, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Chunk(r) => r.read(conn, b).await,
            Self::Aead(r) => r.read(conn, b).await,
        }
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "AeadWriter embeds the AeadCipher key material directly (see aead.rs); ChunkWriter is a unit struct, so the size gap reflects real state, not layout neglect"
)]
enum Writer {
    Chunk(ChunkWriter),
    Aead(AeadWriter),
}

impl Writer {
    async fn write(&mut self, conn: &mut dyn Stream, b: &[u8]) -> io::Result<usize> {
        match self {
            Self::Chunk(w) => w.write(conn, b).await,
            Self::Aead(w) => w.write(conn, b).await,
        }
    }
}

struct Inner {
    conn: Box<dyn Stream>,
    reader: Reader,
    writer: Writer,
    dst: DstAddr,
    id: Id,
    req_body_iv: Vec<u8>,
    req_body_key: Vec<u8>,
    resp_body_iv: Vec<u8>,
    resp_body_key: Vec<u8>,
    resp_v: u8,
    security: Security,
    is_aead: bool,
    received: bool,
}

impl Inner {
    // NOT cancel-safe: the request borrows a locked send half and has already started writing, so a dropped call abandons the request on a connection that cannot be reused safely; the arms that await it drop it only while the connection is being torn down.
    async fn send_request(&mut self) -> io::Result<()> {
        let timestamp = Utc::now();
        let mut mbuf = Vec::new();

        if !self.is_aead {
            let mut mac = Hmac::<Md5>::new_from_slice(self.id.uuid.as_bytes()).map_err(io::Error::other)?;
            mac.update(&timestamp.timestamp().cast_unsigned().to_be_bytes());
            mbuf.extend_from_slice(&mac.finalize().into_bytes());
        }

        let mut buf = BytesMut::new();
        buf.put_u8(super::vmess::VERSION);
        buf.extend_from_slice(&self.req_body_iv);
        buf.extend_from_slice(&self.req_body_key);
        buf.put_u8(self.resp_v);
        buf.put_u8(OPTION_CHUNK_STREAM);

        let p = rand::rng().random_range(0..16u8);
        buf.put_u8((p << 4) | self.security);
        buf.put_u8(0);
        buf.put_u8(if self.dst.udp { COMMAND_UDP } else { COMMAND_TCP });

        buf.put_u16(u16::try_from(self.dst.port).map_err(|_| io::Error::other("destination port exceeds 65535"))?);
        buf.put_u8(self.dst.addr_type);
        buf.extend_from_slice(&self.dst.addr);

        if p > 0 {
            let mut padding = vec![0u8; usize::from(p)];
            rand::rng().fill_bytes(&mut padding);
            buf.extend_from_slice(&padding);
        }

        let checksum = fnv1a32(&buf);
        buf.extend_from_slice(&checksum.to_be_bytes());

        if !self.is_aead {
            let iv = hash_timestamp(timestamp);
            let stream = Encryptor::<Aes128>::new_from_slices(&self.id.cmd_key, &iv).map_err(io::Error::other)?;
            stream.encrypt(&mut buf);
            mbuf.extend_from_slice(&buf);
            self.conn.write_all(&mbuf).await?;
            self.conn.flush().await?;
            return Ok(());
        }

        let mut fixed_length_cmd_key = [0u8; 16];
        let n = self.id.cmd_key.len().min(16);
        let (dst, _) = fixed_length_cmd_key.split_at_mut(n);
        let (src, _) = self.id.cmd_key.split_at(n);
        dst.copy_from_slice(src);
        let vmessout = header::seal_vmess_aead_header(fixed_length_cmd_key, &buf, timestamp);
        self.conn.write_all(&vmessout).await?;
        self.conn.flush().await?;
        Ok(())
    }

    async fn recv_response(&mut self) -> io::Result<()> {
        let buf: Vec<u8>;

        if self.is_aead {
            let aead_response_header_length_encryption_key =
                header::kdf(&self.resp_body_key, &[header::KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY])[..16].to_vec();
            let aead_response_header_length_encryption_iv =
                header::kdf(&self.resp_body_iv, &[header::KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV])[..12].to_vec();

            let aead_response_header_length_encryption_aead =
                Aes128Gcm::new_from_slice(&aead_response_header_length_encryption_key).map_err(io::Error::other)?;

            let mut aead_encrypted_response_header_length = [0u8; 18];
            self.conn.read_exact(&mut aead_encrypted_response_header_length).await?;

            let decrypted_response_header_length_binary_buffer = aead_response_header_length_encryption_aead
                .decrypt(
                    (&aead_response_header_length_encryption_iv[..])
                        .try_into()
                        .map_err(|_| io::Error::other("12-byte GCM nonce"))?,
                    Payload { msg: &aead_encrypted_response_header_length, aad: &[] },
                )
                .map_err(|_| io::Error::other("cipher: message authentication failed"))?;

            let decrypted_response_header_length = u16::from_be_bytes(
                decrypted_response_header_length_binary_buffer
                    .try_into()
                    .map_err(|_| io::Error::other("2-byte header length"))?,
            );

            let aead_response_header_payload_encryption_key =
                header::kdf(&self.resp_body_key, &[header::KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY])[..16].to_vec();
            let aead_response_header_payload_encryption_iv =
                header::kdf(&self.resp_body_iv, &[header::KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV])[..12].to_vec();
            let aead_response_header_payload_encryption_aead =
                Aes128Gcm::new_from_slice(&aead_response_header_payload_encryption_key).map_err(io::Error::other)?;

            let mut encrypted_response_header_buffer = vec![0u8; decrypted_response_header_length as usize + 16];
            self.conn.read_exact(&mut encrypted_response_header_buffer).await?;

            buf = aead_response_header_payload_encryption_aead
                .decrypt(
                    (&aead_response_header_payload_encryption_iv[..])
                        .try_into()
                        .map_err(|_| io::Error::other("12-byte GCM nonce"))?,
                    Payload { msg: &encrypted_response_header_buffer, aad: &[] },
                )
                .map_err(|_| io::Error::other("cipher: message authentication failed"))?;

            if buf.len() < 4 {
                return Err(io::Error::other("unexpected buffer length"));
            }
        } else {
            let stream = Decryptor::<Aes128>::new_from_slices(&self.resp_body_key, &self.resp_body_iv)
                .map_err(io::Error::other)?;
            let mut raw = [0u8; 4];
            self.conn.read_exact(&mut raw).await?;
            stream.decrypt(&mut raw);
            buf = raw.to_vec();
        }

        if buf.first().copied() != Some(self.resp_v) {
            return Err(io::Error::other("unexpected response header"));
        }
        if buf.get(2).copied() != Some(0) {
            return Err(io::Error::other("dynamic port is not supported now"));
        }
        Ok(())
    }

    async fn do_read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if !self.received {
            self.recv_response().await?;
            self.received = true;
        }
        self.reader.read(&mut *self.conn, b).await
    }

    async fn do_write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.writer.write(&mut *self.conn, b).await
    }
}

fn fnv1a32(data: &[u8]) -> u32 {
    const OFFSET_BASIS: u32 = 2_166_136_261;
    const PRIME: u32 = 16_777_619;
    let mut hash = OFFSET_BASIS;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn hash_timestamp(t: DateTime<Utc>) -> [u8; 16] {
    let ts = t.timestamp().cast_unsigned().to_be_bytes();
    let mut hash = Md5::new();
    hash.update(ts);
    hash.update(ts);
    hash.update(ts);
    hash.update(ts);
    hash.finalize().into()
}

type ReadFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;
type WriteFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;
type FlushFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'static>>;

pub struct Conn {
    inner: Arc<AsyncMutex<Inner>>,
    /// The real close/deadline capability, kept outside `inner`'s async mutex (whose guard cannot
    /// outlive an `old_conn()` call) so [`Stream::old_conn`] can hand out a stable reference; see
    /// `sing::conn_driver::Driven`'s `close_handle` for the identical reasoning.
    close_handle: VmessSharedConn,
    read: SyncMutex<Option<ReadFuture>>,
    write: SyncMutex<Option<WriteFuture>>,
    flush: SyncMutex<Option<FlushFuture>>,
    read_buf: SyncMutex<Vec<u8>>,
    write_buf: SyncMutex<Vec<u8>>,
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut read = this.read.lock();
        if read.is_none() {
            let inner = Arc::clone(&this.inner);
            let mut tmp = std::mem::take(&mut *this.read_buf.lock());
            tmp.clear();
            tmp.resize(buf.remaining(), 0);
            *read = Some(Box::pin(async move {
                let mut guard = inner.lock().await;
                let result = guard.do_read(&mut tmp).await;
                drop(guard);
                (tmp, result)
            }));
        }
        let Some(future) = read.as_mut() else {
            return Poll::Ready(Err(io::Error::other("read future was just installed")));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready((tmp, result)) => {
                *read = None;
                drop(read);
                match result {
                    Ok(n) => {
                        let (chunk, _) = tmp.split_at(n);
                        buf.put_slice(chunk);
                        *this.read_buf.lock() = tmp;
                        Poll::Ready(Ok(()))
                    }
                    Err(err) => {
                        *this.read_buf.lock() = tmp;
                        Poll::Ready(Err(err))
                    }
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut write = this.write.lock();
        if write.is_none() {
            let inner = Arc::clone(&this.inner);
            let mut data = std::mem::take(&mut *this.write_buf.lock());
            data.clear();
            data.extend_from_slice(buf);
            *write = Some(Box::pin(async move {
                let mut guard = inner.lock().await;
                let result = guard.do_write(&data).await;
                drop(guard);
                (data, result)
            }));
        }
        let Some(future) = write.as_mut() else {
            return Poll::Ready(Err(io::Error::other("write future was just installed")));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready((data, result)) => {
                *write = None;
                drop(write);
                *this.write_buf.lock() = data;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// The inner conn is flushed explicitly: the TLS layer above buffers ciphertext rather than
    /// sending each write straight through, so nothing else would push it out.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut flush = this.flush.lock();
        if flush.is_none() {
            let inner = Arc::clone(&this.inner);
            *flush = Some(Box::pin(async move {
                let mut guard = inner.lock().await;
                guard.conn.flush().await
            }));
        }
        let Some(future) = flush.as_mut() else {
            return Poll::Ready(Err(io::Error::other("flush future was just installed")));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                *flush = None;
                drop(flush);
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl Stream for Conn {
    /// The embedded conn's local and peer addresses are promoted directly.
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self.inner.try_lock() {
            Ok(guard) => guard.conn.local_addr(),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "vmess conn busy")),
        }
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self.inner.try_lock() {
            Ok(guard) => guard.conn.peer_addr(),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "vmess conn busy")),
        }
    }

    /// `shutdown_read`/`shutdown_write` are never overridden (inherited no-op
    /// defaults); `close()`'s real forwarding lives on [`Stream::old_conn`] instead, via
    /// `close_handle`, so these stay no-ops rather than reaching through to the dialed conn.
    fn shutdown_read(&self) -> io::Result<()> {
        Ok(())
    }

    fn shutdown_write(&self) -> io::Result<()> {
        Ok(())
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(&self.close_handle)
    }
}

fn build_reader_writer(
    security: Security,
    req_body_iv: &[u8],
    req_body_key: &[u8],
    resp_body_iv: &[u8],
    resp_body_key: &[u8],
) -> io::Result<(Reader, Writer)> {
    match security {
        SECURITY_AES128GCM => {
            let write_aead =
                Aes128Gcm::new_from_slice(req_body_key).map_err(io::Error::other).map(AeadCipher::Aes128Gcm)?;
            let read_aead =
                Aes128Gcm::new_from_slice(resp_body_key).map_err(io::Error::other).map(AeadCipher::Aes128Gcm)?;
            Ok((
                Reader::Aead(AeadReader::new(read_aead, resp_body_iv.to_vec())),
                Writer::Aead(AeadWriter::new(write_aead, req_body_iv.to_vec())),
            ))
        }
        SECURITY_CHACHA20POLY1305 => {
            let write_key = chacha_key(req_body_key);
            let read_key = chacha_key(resp_body_key);
            let write_aead = ChaCha20Poly1305::new_from_slice(&write_key).map_err(io::Error::other)?;
            let read_aead = ChaCha20Poly1305::new_from_slice(&read_key).map_err(io::Error::other)?;
            Ok((
                Reader::Aead(AeadReader::new(AeadCipher::ChaCha20Poly1305(read_aead), resp_body_iv.to_vec())),
                Writer::Aead(AeadWriter::new(AeadCipher::ChaCha20Poly1305(write_aead), req_body_iv.to_vec())),
            ))
        }
        // `SECURITY_NONE` and any unrecognized cipher id take the plain chunk codec here.
        _ => Ok((Reader::Chunk(ChunkReader::new()), Writer::Chunk(ChunkWriter::new()))),
    }
}

/// The ChaCha20-Poly1305 key derivation: `md5(md5(body_key) || md5(md5(body_key)))`.
fn chacha_key(body_key: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let t = Md5::digest(body_key);
    key[..16].copy_from_slice(&t);
    let t2 = Md5::digest(&key[..16]);
    key[16..].copy_from_slice(&t2);
    key
}

pub(crate) async fn new_conn(
    conn: Box<dyn Stream>,
    close_handle: VmessSharedConn,
    id: Id,
    dst: DstAddr,
    security: Security,
    is_aead: bool,
) -> anyhow::Result<Box<dyn Stream>> {
    let mut rand_bytes = [0u8; 33];
    rand::rng().fill_bytes(&mut rand_bytes);
    let req_body_iv = rand_bytes[..16].to_vec();
    let req_body_key = rand_bytes[16..32].to_vec();
    let resp_v = rand_bytes[32];

    let (resp_body_key, resp_body_iv) = if is_aead {
        let body_key = sha256(&req_body_key);
        let body_iv = sha256(&req_body_iv);
        (body_key[..16].to_vec(), body_iv[..16].to_vec())
    } else {
        (Md5::digest(&req_body_key).to_vec(), Md5::digest(&req_body_iv).to_vec())
    };

    let (reader, writer) = build_reader_writer(security, &req_body_iv, &req_body_key, &resp_body_iv, &resp_body_key)?;

    let inner = Inner {
        conn,
        reader,
        writer,
        dst,
        id,
        req_body_iv,
        req_body_key,
        resp_body_iv,
        resp_body_key,
        resp_v,
        security,
        is_aead,
        received: false,
    };

    let inner = Arc::new(AsyncMutex::new(inner));
    inner.lock().await.send_request().await?;

    Ok(Box::new(Conn {
        inner,
        close_handle,
        read: SyncMutex::new(None),
        write: SyncMutex::new(None),
        flush: SyncMutex::new(None),
        read_buf: SyncMutex::new(Vec::new()),
        write_buf: SyncMutex::new(Vec::new()),
    }))
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    Sha256::digest(data).into()
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn").finish_non_exhaustive()
    }
}

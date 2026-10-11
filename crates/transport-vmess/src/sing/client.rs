//! `security = aes-128-cfb` (the legacy CFB body framing) is out of scope — see the module report.
//!
//! `alterId > 0` is not: such a client sends the legacy HMAC-MD5/CFB request header and reads the
//! legacy CFB response header, while the body keeps the configured AEAD framing.
//!
//! The client conn drives a lazily-installed reader and writer; this build keeps the
//! same boxed-future-per-`poll_*`-call shape as `transport::vmess::conn::Conn`, but with
//! independent read/write locks: sharing one lock would let a pending
//! `read_response`/`read_chunk` (parked on the peer) starve out the write that would unblock it —
//! exactly what hyper's H1 client does by polling read before write on every connection.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use aes::cipher::KeyIvInit as _;
use aes::Aes128;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use anyhow::{anyhow, bail, Result};
use cfb_mode::{Decryptor, Encryptor};
use chrono::{DateTime, Utc};
use parking_lot::Mutex as SyncMutex;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use super::addr;
use super::chunk::{
    auth_len_key, new_shake, AeadBodyReader, AeadBodyWriter, AeadChunkReader, AeadChunkWriter, Cipher, SharedShake,
    StreamChunkReader, StreamChunkWriter,
};
use crate::header::{
    kdf, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
    KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
};
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Addr, Conn as NetConn};

pub(crate) const VERSION: u8 = 1;

const OPTION_CHUNK_STREAM: u8 = 1;
const OPTION_CHUNK_MASKING: u8 = 4;
const OPTION_GLOBAL_PADDING: u8 = 8;
const OPTION_AUTHENTICATED_LENGTH: u8 = 16;

pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 2;
pub(crate) const COMMAND_MUX: u8 = 3;

const CIPHER_OVERHEAD: usize = 16;

/// `Security`, narrowed to the AEAD-2 ciphers this build implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    None,
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl Security {
    /// The security-string switch, minus `"aes-128-cfb"` (the legacy CFB body framing, which
    /// this crate does not implement) and the `"auto"` runtime arch check, matched instead
    /// against `std::env::consts::ARCH` the same way `transport::vmess::vmess::new_client` does.
    pub fn parse(security: &str) -> Result<Self> {
        match security {
            "auto" => Ok(match std::env::consts::ARCH {
                "x86_64" | "s390x" | "aarch64" => Self::Aes128Gcm,
                _ => Self::ChaCha20Poly1305,
            }),
            "none" | "zero" => Ok(Self::None),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            "aes-128-cfb" => {
                bail!("vmess: unsupported security type: {security} (the legacy CFB body framing is not implemented)")
            }
            other => bail!("vmess: unsupported security type: {other}"),
        }
    }

    pub(crate) fn byte(self) -> u8 {
        match self {
            Self::None => 5,
            Self::Aes128Gcm => 3,
            Self::ChaCha20Poly1305 => 4,
        }
    }

    /// The security byte: only the three AEAD-2 byte values this crate supports resolve; any
    /// other byte (including `1`=legacy, `2`=auto — auto is resolved client-side and never sent on
    /// the wire) is rejected.
    pub(crate) fn from_byte(b: u8) -> Option<Self> {
        match b {
            5 => Some(Self::None),
            3 => Some(Self::Aes128Gcm),
            4 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct Client {
    key: [u8; 16],
    security: Security,
    alter_id: i32,
    alter_key: Option<[u8; 16]>,
    global_padding: bool,
    authenticated_length: bool,
    time_func: fn() -> DateTime<Utc>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("security", &self.security)
            .field("alter_id", &self.alter_id)
            .field("global_padding", &self.global_padding)
            .field("authenticated_length", &self.authenticated_length)
            .finish_non_exhaustive()
    }
}

pub(crate) fn key_from_uuid(uuid: Uuid) -> [u8; 16] {
    use md5::{Digest as _, Md5};
    let mut h = Md5::new();
    h.update(uuid.as_bytes());
    h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    h.finalize().into()
}

impl Client {
    pub fn new(
        uuid: Uuid,
        security: &str,
        alter_id: i32,
        global_padding: bool,
        authenticated_length: bool,
        time_func: fn() -> DateTime<Utc>,
    ) -> Result<Self> {
        let security = Security::parse(security)?;
        let alter_key = (alter_id > 0).then(|| crate::user::next_id(&uuid).into_bytes());
        Ok(Self {
            key: key_from_uuid(uuid),
            security,
            alter_id,
            alter_key,
            global_padding,
            authenticated_length,
            time_func,
        })
    }

    fn option_byte(&self, command: u8) -> u8 {
        match self.security {
            Security::None => {
                if command == COMMAND_UDP {
                    OPTION_CHUNK_STREAM
                } else {
                    0
                }
            }
            Security::Aes128Gcm | Security::ChaCha20Poly1305 => {
                let mut option = OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING;
                if self.global_padding {
                    option |= OPTION_GLOBAL_PADDING;
                }
                if self.authenticated_length {
                    option |= OPTION_AUTHENTICATED_LENGTH;
                }
                option
            }
        }
    }

    /// Writes the handshake immediately.
    pub async fn dial_conn(&self, upstream: Box<dyn NetConn>, destination: Socksaddr) -> Result<Box<dyn NetConn>> {
        let conn = self.dial_raw(upstream, COMMAND_TCP, destination);
        conn.write_handshake_now().await?;
        Ok(Box::new(conn))
    }

    /// The handshake is deferred to the first write.
    #[must_use]
    pub fn dial_early_conn(&self, upstream: Box<dyn NetConn>, destination: Socksaddr) -> Box<dyn NetConn> {
        Box::new(self.dial_raw(upstream, COMMAND_TCP, destination))
    }

    pub async fn dial_packet_conn(
        &self,
        upstream: Box<dyn NetConn>,
        destination: Socksaddr,
    ) -> Result<Box<dyn NetConn>> {
        let conn = self.dial_raw(upstream, COMMAND_UDP, destination);
        conn.write_handshake_now().await?;
        Ok(Box::new(conn))
    }

    #[must_use]
    pub fn dial_early_packet_conn(&self, upstream: Box<dyn NetConn>, destination: Socksaddr) -> Box<dyn NetConn> {
        Box::new(self.dial_raw(upstream, COMMAND_UDP, destination))
    }

    /// Dials in mux mode, carrying only `XudpPacketConn` traffic.
    pub async fn dial_mux_conn(&self, upstream: Box<dyn NetConn>, destination: Socksaddr) -> Result<Conn> {
        let conn = self.dial_raw(upstream, COMMAND_MUX, destination);
        conn.write_handshake_now().await?;
        Ok(conn)
    }

    #[must_use]
    pub fn dial_early_mux_conn(&self, upstream: Box<dyn NetConn>, destination: Socksaddr) -> Conn {
        self.dial_raw(upstream, COMMAND_MUX, destination)
    }

    fn dial_raw(&self, upstream: Box<dyn NetConn>, command: u8, destination: Socksaddr) -> Conn {
        let mut request_key = [0u8; 16];
        let mut request_nonce = [0u8; 16];
        rand::rng().fill_bytes(&mut request_key);
        rand::rng().fill_bytes(&mut request_nonce);
        let option = self.option_byte(command);
        // `security = none` TCP builds `FrameReader::Raw` (see `build_codec`), which reads a
        // stream slice rather than one whole chunk; buffering the remainder is required so a
        // caller's shorter read doesn't see `InvalidInput`, matching the plain-stream passthrough.
        let read_buffer = (option & OPTION_CHUNK_STREAM != 0 && command == COMMAND_TCP)
            || command == COMMAND_MUX
            || (self.security == Security::None && command == COMMAND_TCP);

        let shared = Arc::new(SharedConn { upstream: SyncMutex::new(upstream), response_header: AtomicU8::new(0) });

        let read_state = ReadState {
            client: self.clone(),
            command,
            request_key,
            request_nonce,
            read_buffer,
            conn: ConnHandle(Arc::clone(&shared)),
            reader: None,
            pending: Vec::new(),
            pending_offset: 0,
        };
        let write_state = WriteState {
            client: self.clone(),
            command,
            destination,
            request_key,
            request_nonce,
            conn: ConnHandle(Arc::clone(&shared)),
            writer: None,
        };

        Conn {
            shared,
            read_state: Arc::new(AsyncMutex::new(read_state)),
            write_state: Arc::new(AsyncMutex::new(write_state)),
            read: SyncMutex::new(None),
            write: SyncMutex::new(None),
            read_buf: SyncMutex::new(Vec::new()),
            write_buf: SyncMutex::new(Vec::new()),
        }
    }
}

fn aes_gcm_seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(io::Error::other)?;
    let nonce = <&Nonce<_>>::try_from(nonce).map_err(|_| io::Error::other("cipher: bad nonce"))?;
    cipher.encrypt(nonce, Payload { msg: plaintext, aad }).map_err(|_| io::Error::other("vmess: aead seal failed"))
}

fn aes_gcm_open(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(io::Error::other)?;
    let nonce = <&Nonce<_>>::try_from(nonce).map_err(|_| io::Error::other("cipher: bad nonce"))?;
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| io::Error::other("cipher: message authentication failed"))
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

fn md5_16(data: &[u8]) -> [u8; 16] {
    use md5::{Digest as _, Md5};
    Md5::digest(data).into()
}

fn hmac_md5(key: &[u8], msg: &[u8]) -> io::Result<[u8; 16]> {
    use hmac::{Hmac, Mac as _};
    let mut mac = Hmac::<md5::Md5>::new_from_slice(key).map_err(io::Error::other)?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().into())
}

fn legacy_time_hash(timestamp: u64) -> [u8; 16] {
    use md5::{Digest as _, Md5};
    let be = timestamp.to_be_bytes();
    let mut hash = Md5::new();
    for _ in 0..4 {
        hash.update(be);
    }
    hash.finalize().into()
}

fn cfb_encrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> io::Result<()> {
    Encryptor::<Aes128>::new_from_slices(key, iv).map_err(io::Error::other)?.encrypt(data);
    Ok(())
}

fn cfb_decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> io::Result<()> {
    Decryptor::<Aes128>::new_from_slices(key, iv).map_err(io::Error::other)?.decrypt(data);
    Ok(())
}

/// One of [`StreamChunkReader`]/[`StreamChunkWriter`] (default) or [`AeadChunkReader`]/
/// [`AeadChunkWriter`] (`authenticated-length`), paired with the AEAD body cipher.
enum FrameReader {
    Stream(StreamChunkReader),
    AuthLen(Box<AeadChunkReader>),
    /// `security = none`, `command != UDP`: no framing at all (the reader returns the conn
    /// verbatim when `option == 0`).
    Raw,
}

enum FrameWriter {
    Stream(StreamChunkWriter),
    AuthLen(Box<AeadChunkWriter>),
    Raw,
}

pub(crate) struct Codec {
    body_reader: Option<AeadBodyReader>,
    body_writer: Option<AeadBodyWriter>,
    frame_reader: FrameReader,
    frame_writer: FrameWriter,
}

pub(crate) fn build_codec(
    security: Security,
    option: u8,
    request_key: &[u8; 16],
    request_nonce: &[u8; 16],
    resp_key: &[u8],
    resp_iv: &[u8],
) -> io::Result<Codec> {
    let global_padding: Option<SharedShake> =
        if option & OPTION_GLOBAL_PADDING != 0 { Some(new_shake(resp_iv)) } else { None };
    let chunk_masking: Option<SharedShake> = if option & OPTION_CHUNK_MASKING != 0 {
        Some(global_padding.clone().unwrap_or_else(|| new_shake(resp_iv)))
    } else {
        None
    };

    match security {
        Security::None => {
            if option & OPTION_CHUNK_STREAM == 0 {
                return Ok(Codec {
                    body_reader: None,
                    body_writer: None,
                    frame_reader: FrameReader::Raw,
                    frame_writer: FrameWriter::Raw,
                });
            }
            Ok(Codec {
                body_reader: None,
                body_writer: None,
                frame_reader: FrameReader::Stream(StreamChunkReader::new(
                    chunk_masking.clone(),
                    global_padding.clone(),
                    0, // `security = none`: an empty body really is empty on the wire
                )),
                frame_writer: FrameWriter::Stream(StreamChunkWriter::new(chunk_masking, global_padding)),
            })
        }
        Security::Aes128Gcm | Security::ChaCha20Poly1305 => {
            // The body cipher always uses the `key, nonce` params (`resp_key, resp_iv` here);
            // `request_key, request_nonce` feeds only the
            // authenticated-length chunk framing below. Client-writes-its-own-request and
            // server-reads-that-request pass the same key for both slots, but server-writes-its-
            // response and client-reads-that-response do not — using `request_key` here would
            // decrypt/encrypt the body under the wrong key for those two directions.
            let (write_cipher, read_cipher) = match security {
                Security::Aes128Gcm => (Cipher::new_aes_128_gcm(resp_key)?, Cipher::new_aes_128_gcm(resp_key)?),
                Security::None | Security::ChaCha20Poly1305 => {
                    (Cipher::new_chacha20_poly1305(resp_key)?, Cipher::new_chacha20_poly1305(resp_key)?)
                }
            };
            let body_writer = AeadBodyWriter::new(write_cipher, resp_iv);
            let body_reader = AeadBodyReader::new(read_cipher, resp_iv);

            if option & OPTION_AUTHENTICATED_LENGTH != 0 {
                // The length cipher is keyed with `request_key, request_nonce` on both directions
                // (client read, client write, server read, server write), never
                // `resp_key`/`resp_iv`.
                let (write_len_cipher, read_len_cipher) = match security {
                    Security::Aes128Gcm => (
                        Cipher::new_aes_128_gcm(&auth_len_key(request_key))?,
                        Cipher::new_aes_128_gcm(&auth_len_key(request_key))?,
                    ),
                    Security::None | Security::ChaCha20Poly1305 => (
                        Cipher::new_chacha20_poly1305(&auth_len_key(request_key))?,
                        Cipher::new_chacha20_poly1305(&auth_len_key(request_key))?,
                    ),
                };
                Ok(Codec {
                    body_reader: Some(body_reader),
                    body_writer: Some(body_writer),
                    frame_reader: FrameReader::AuthLen(Box::new(AeadChunkReader::new(
                        read_len_cipher,
                        request_nonce,
                        global_padding.clone(),
                    ))),
                    frame_writer: FrameWriter::AuthLen(Box::new(AeadChunkWriter::new(
                        write_len_cipher,
                        request_nonce,
                        global_padding,
                    ))),
                })
            } else {
                Ok(Codec {
                    body_reader: Some(body_reader),
                    body_writer: Some(body_writer),
                    frame_reader: FrameReader::Stream(StreamChunkReader::new(
                        chunk_masking.clone(),
                        global_padding.clone(),
                        CIPHER_OVERHEAD,
                    )),
                    frame_writer: FrameWriter::Stream(StreamChunkWriter::new(chunk_masking, global_padding)),
                })
            }
        }
    }
}

impl Codec {
    pub(crate) async fn write_chunk<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        w: &mut W,
        plaintext: &[u8],
    ) -> io::Result<()> {
        let sealed = match &mut self.body_writer {
            Some(body) => body.seal(plaintext),
            None => plaintext.to_vec(),
        };
        match &mut self.frame_writer {
            FrameWriter::Stream(fw) => fw.write(w, &sealed).await,
            FrameWriter::AuthLen(fw) => fw.write(w, &sealed).await,
            FrameWriter::Raw => w.write_all(&sealed).await,
        }
    }

    /// Returns `Ok(None)` on protocol EOF (a zero-length terminal chunk).
    pub(crate) async fn read_chunk<R: AsyncRead + Unpin + ?Sized>(&mut self, r: &mut R) -> io::Result<Option<Vec<u8>>> {
        let sealed = match &mut self.frame_reader {
            FrameReader::Stream(fr) => match fr.read(r).await? {
                Some(b) => b,
                None => return Ok(None),
            },
            FrameReader::AuthLen(fr) => match fr.read(r).await? {
                Some(b) => b,
                None => return Ok(None),
            },
            FrameReader::Raw => {
                let mut buf = vec![0u8; 16384];
                let n = r.read(&mut buf).await?;
                if n == 0 {
                    return Ok(None);
                }
                buf.truncate(n);
                return Ok(Some(buf));
            }
        };
        match &mut self.body_reader {
            Some(body) => Ok(Some(body.open(&sealed)?)),
            None => Ok(Some(sealed)),
        }
    }
}

/// The dialed conn behind a lock held only for one `poll_read`/`poll_write`/admin call at a
/// time — the same pattern `adapter::outbound::base::ConnWrapper` uses — so [`ReadState`] and
/// [`WriteState`] below can each run their own multi-`.await` state machine independently.
struct SharedConn {
    upstream: SyncMutex<Box<dyn NetConn>>,
    response_header: AtomicU8,
}

#[derive(Clone)]
struct ConnHandle(Arc<SharedConn>);

impl AsyncRead for ConnHandle {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.0.upstream.lock();
        Pin::new(&mut **guard).poll_read(cx, buf)
    }
}

impl AsyncWrite for ConnHandle {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut guard = self.0.upstream.lock();
        Pin::new(&mut **guard).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.0.upstream.lock();
        Pin::new(&mut **guard).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.0.upstream.lock();
        Pin::new(&mut **guard).poll_shutdown(cx)
    }
}

/// The write-direction fields of `Conn`'s raw and client halves.
struct WriteState {
    client: Client,
    command: u8,
    destination: Socksaddr,
    request_key: [u8; 16],
    request_nonce: [u8; 16],
    conn: ConnHandle,
    writer: Option<Codec>,
}

/// The read-direction fields of `Conn`'s raw and client halves.
struct ReadState {
    client: Client,
    command: u8,
    request_key: [u8; 16],
    request_nonce: [u8; 16],
    read_buffer: bool,
    conn: ConnHandle,
    reader: Option<Codec>,
    pending: Vec<u8>,
    pending_offset: usize,
}

impl WriteState {
    async fn write_handshake(&mut self, payload: &[u8]) -> io::Result<()> {
        let padding_len = rand::rng().random_range(0u8..16);
        let mut header_len = 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1;
        if self.command != COMMAND_MUX {
            header_len += addr::addr_port_len(&self.destination);
        }
        header_len += usize::from(padding_len);
        header_len += 4;

        let option = self.client.option_byte(self.command);
        let response_header = rand::rng().random::<u8>();
        self.conn.0.response_header.store(response_header, Ordering::SeqCst);
        let security_byte = self.client.security.byte();

        let legacy = if let Some(alter_key) = self.client.alter_key.as_ref() {
            let timestamp = (self.client.time_func)().timestamp().cast_unsigned();
            Some((hmac_md5(alter_key, &timestamp.to_be_bytes())?, legacy_time_hash(timestamp)))
        } else {
            None
        };
        let prefix_len = if legacy.is_some() { 16 } else { 0 };
        let mut header = Vec::with_capacity(prefix_len + header_len);
        if let Some((auth_id, _)) = legacy.as_ref() {
            header.extend_from_slice(auth_id);
        }
        header.push(VERSION);
        header.extend_from_slice(&self.request_nonce);
        header.extend_from_slice(&self.request_key);
        header.push(response_header);
        header.push(option);
        header.push((padding_len << 4) | security_byte);
        header.push(0);
        header.push(self.command);
        if self.command != COMMAND_MUX {
            addr::write_addr_port(&mut header, &self.destination).map_err(io::Error::other)?;
        }
        header.resize(header.len() + usize::from(padding_len), 0);
        let checksum =
            fnv1a32(header.get(prefix_len..).ok_or_else(|| io::Error::other("vmess: missing request header"))?);
        header.extend_from_slice(&checksum.to_be_bytes());
        debug_assert_eq!(header.len(), prefix_len + header_len);

        if let Some((_, time_hash)) = legacy {
            let body = header.get_mut(prefix_len..).ok_or_else(|| io::Error::other("vmess: missing request header"))?;
            cfb_encrypt(&self.client.key, &time_hash, body)?;
            self.conn.write_all(&header).await?;
        } else {
            let time = (self.client.time_func)();
            let auth_id = crate::header::create_auth_id(&self.client.key, time.timestamp());
            let mut connection_nonce = [0u8; 8];
            rand::rng().fill_bytes(&mut connection_nonce);

            let length_key = kdf(
                &self.client.key,
                &[KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, &auth_id, &connection_nonce],
            );
            let length_nonce = kdf(
                &self.client.key,
                &[KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, &auth_id, &connection_nonce],
            );
            let header_len_u16 =
                u16::try_from(header_len).map_err(|_| io::Error::other("vmess: header length overflows u16"))?;
            let sealed_len =
                aes_gcm_seal(&length_key[..16], &length_nonce[..12], &header_len_u16.to_be_bytes(), &auth_id)?;

            let header_key =
                kdf(&self.client.key, &[KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY, &auth_id, &connection_nonce]);
            let header_nonce =
                kdf(&self.client.key, &[KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, &auth_id, &connection_nonce]);
            let sealed_header = aes_gcm_seal(&header_key[..16], &header_nonce[..12], &header, &auth_id)?;

            let mut request = Vec::with_capacity(16 + sealed_len.len() + 8 + sealed_header.len());
            request.extend_from_slice(&auth_id);
            request.extend_from_slice(&sealed_len);
            request.extend_from_slice(&connection_nonce);
            request.extend_from_slice(&sealed_header);
            self.conn.write_all(&request).await?;
        }

        self.writer = Some(
            build_codec(
                self.client.security,
                option,
                &self.request_key,
                &self.request_nonce,
                &self.request_key,
                &self.request_nonce,
            )
            .map_err(io::Error::other)?,
        );

        if !payload.is_empty() {
            let mut codec = self.writer.take().ok_or_else(|| io::Error::other("vmess: writer not installed"))?;
            let result = write_payload(&mut codec, &mut self.conn, payload).await;
            self.writer = Some(codec);
            result?;
        }
        Ok(())
    }

    async fn do_write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.writer.is_none() {
            self.write_handshake(b).await?;
            return Ok(b.len());
        }
        let mut codec = self.writer.take().ok_or_else(|| io::Error::other("vmess: writer not installed"))?;
        let result = write_payload(&mut codec, &mut self.conn, b).await;
        self.writer = Some(codec);
        result?;
        Ok(b.len())
    }
}

impl ReadState {
    async fn read_response(&mut self) -> io::Result<()> {
        let (response_key, response_nonce) = if self.client.alter_key.is_some() {
            let response_key = md5_16(&self.request_key);
            let response_nonce = md5_16(&self.request_nonce);
            let mut raw = [0u8; 4];
            self.conn.read_exact(&mut raw).await?;
            cfb_decrypt(&response_key, &response_nonce, &mut raw)?;
            let [echo, _, _, cmd_len] = raw;
            if echo != self.conn.0.response_header.load(Ordering::SeqCst) {
                return Err(io::Error::other("vmess: bad response header"));
            }
            // The command bytes are discarded from the raw conn, leaving the CFB stream at four bytes.
            if cmd_len > 0 {
                let mut scratch = [0u8; 256];
                let discard = scratch
                    .get_mut(..usize::from(cmd_len))
                    .ok_or_else(|| io::Error::other("vmess: bad response command length"))?;
                self.conn.read_exact(discard).await?;
            }
            (response_key, response_nonce)
        } else {
            let response_key = digest16(&Sha256::digest(self.request_key))?;
            let response_nonce = digest16(&Sha256::digest(self.request_nonce))?;

            let header_len_key = kdf(&response_key, &[KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY]);
            let header_len_nonce = kdf(&response_nonce, &[KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV]);
            let mut sealed_len = [0u8; 2 + CIPHER_OVERHEAD];
            self.conn.read_exact(&mut sealed_len).await?;
            let opened_len = aes_gcm_open(&header_len_key[..16], &header_len_nonce[..12], &sealed_len, &[])?;
            let (len_bytes, _) = opened_len
                .split_first_chunk::<2>()
                .ok_or_else(|| io::Error::other("vmess: response header length is truncated"))?;
            let header_len = usize::from(u16::from_be_bytes(*len_bytes));

            let header_key = kdf(&response_key, &[KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY]);
            let header_nonce = kdf(&response_nonce, &[KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV]);
            let mut sealed_header = vec![0u8; header_len + CIPHER_OVERHEAD];
            self.conn.read_exact(&mut sealed_header).await?;
            let _opened_header = aes_gcm_open(&header_key[..16], &header_nonce[..12], &sealed_header, &[])?;

            (response_key, response_nonce)
        };

        let option = self.client.option_byte(self.command);
        self.reader = Some(
            build_codec(
                self.client.security,
                option,
                &self.request_key,
                &self.request_nonce,
                &response_key,
                &response_nonce,
            )
            .map_err(io::Error::other)?,
        );
        Ok(())
    }

    async fn do_read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if self.pending_offset < self.pending.len() {
            let rest = self
                .pending
                .get(self.pending_offset..)
                .ok_or_else(|| io::Error::other("vmess: pending offset past end of buffer"))?;
            let n = copy_out(b, rest);
            self.pending_offset += n;
            return Ok(n);
        }
        if self.reader.is_none() {
            self.read_response().await?;
        }
        let mut codec = self.reader.take().ok_or_else(|| io::Error::other("vmess: reader not installed"))?;
        let result = codec.read_chunk(&mut self.conn).await;
        self.reader = Some(codec);
        let chunk = match result? {
            Some(chunk) => chunk,
            None if self.command == COMMAND_UDP => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "vmess: udp session ended"))
            }
            None => return Ok(0),
        };

        if !self.read_buffer && chunk.len() > b.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "buffer is shorter than a chunk"));
        }
        let n = copy_out(b, &chunk);
        if n < chunk.len() {
            self.pending = chunk;
            self.pending_offset = n;
        } else {
            self.pending.clear();
            self.pending_offset = 0;
        }
        Ok(n)
    }
}

pub(crate) async fn write_payload<W: AsyncWrite + Unpin + ?Sized>(
    codec: &mut Codec,
    conn: &mut W,
    payload: &[u8],
) -> io::Result<()> {
    for chunk in payload.chunks(super::chunk::WRITE_CHUNK_SIZE) {
        codec.write_chunk(conn, chunk).await?;
    }
    Ok(())
}

fn copy_out(dst: &mut [u8], src: &[u8]) -> usize {
    let n = dst.len().min(src.len());
    let (dst_head, _) = dst.split_at_mut(n);
    let (src_head, _) = src.split_at(n);
    dst_head.copy_from_slice(src_head);
    n
}

fn digest16(digest: &[u8]) -> io::Result<[u8; 16]> {
    digest
        .split_first_chunk::<16>()
        .map(|(head, _)| *head)
        .ok_or_else(|| io::Error::other("vmess: sha256 digest shorter than 16 bytes"))
}

type ReadFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;
type WriteFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;

/// The client conn: the read and write directions share one stream, so a packet boundary is
/// the chunk boundary and no separate packet type is needed — see the module report.
pub struct Conn {
    shared: Arc<SharedConn>,
    read_state: Arc<AsyncMutex<ReadState>>,
    write_state: Arc<AsyncMutex<WriteState>>,
    read: SyncMutex<Option<ReadFuture>>,
    write: SyncMutex<Option<WriteFuture>>,
    read_buf: SyncMutex<Vec<u8>>,
    write_buf: SyncMutex<Vec<u8>>,
}

impl Conn {
    async fn write_handshake_now(&self) -> Result<()> {
        let mut guard = self.write_state.lock().await;
        guard.write_handshake(&[]).await.map_err(|e| anyhow!(e))
    }
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut read = this.read.lock();
        if read.is_none() {
            let state = Arc::clone(&this.read_state);
            let mut tmp = std::mem::take(&mut *this.read_buf.lock());
            tmp.clear();
            tmp.resize(buf.remaining(), 0);
            *read = Some(Box::pin(async move {
                let mut guard = state.lock().await;
                let result = guard.do_read(&mut tmp).await;
                drop(guard);
                (tmp, result)
            }));
        }
        let Some(future) = read.as_mut() else {
            return Poll::Ready(Err(io::Error::other("vmess: read future not installed")));
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
            let state = Arc::clone(&this.write_state);
            let mut data = std::mem::take(&mut *this.write_buf.lock());
            data.clear();
            data.extend_from_slice(buf);
            *write = Some(Box::pin(async move {
                let mut guard = state.lock().await;
                let result = guard.do_write(&data).await;
                drop(guard);
                (data, result)
            }));
        }
        let Some(future) = write.as_mut() else {
            return Poll::Ready(Err(io::Error::other("vmess: write future not installed")));
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

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut guard = this.shared.upstream.lock();
        Pin::new(&mut **guard).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut guard = this.shared.upstream.lock();
        Pin::new(&mut **guard).poll_shutdown(cx)
    }
}

impl NetConn for Conn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        match self.shared.upstream.try_lock() {
            Some(guard) => guard.local_addr(),
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "vmess conn busy")),
        }
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        match self.shared.upstream.try_lock() {
            Some(guard) => guard.remote_addr(),
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "vmess conn busy")),
        }
    }

    fn close(&self) -> io::Result<()> {
        match self.shared.upstream.try_lock() {
            Some(guard) => guard.close(),
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "vmess conn busy")),
        }
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self.shared.upstream.try_lock() {
            Some(guard) => guard.set_deadline(deadline),
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "vmess conn busy")),
        }
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self.shared.upstream.try_lock() {
            Some(guard) => guard.set_read_deadline(deadline),
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "vmess conn busy")),
        }
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self.shared.upstream.try_lock() {
            Some(guard) => guard.set_write_deadline(deadline),
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "vmess conn busy")),
        }
    }
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("sing::Conn").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::TimeZone;

    use super::*;
    use murmur_std_compat::net::TcpAddr;

    fn fixed_time() -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000, 0).single().expect("valid timestamp")
    }

    struct TestDuplexConn(tokio::io::DuplexStream);

    impl AsyncRead for TestDuplexConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestDuplexConn {
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

    impl NetConn for TestDuplexConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// `ReviewSingVmess` finding 7: `alterId > 0` must load (via `Client::new`), matching the
    /// refactor contract's frozen YAML-acceptance surface. Fails on 3cfb750b, which rejects
    /// construction outright.
    #[test]
    fn alter_id_gt_zero_accepted_at_construction() {
        let client = Client::new(Uuid::nil(), "aes-128-gcm", 64, false, false, fixed_time);
        assert!(client.is_ok(), "alterId > 0 must load, not fail construction");
    }

    /// `ReviewSingVmess` finding 10: `security = none` TCP is a plain passthrough
    /// (`option == 0` builds `FrameReader::Raw`/`FrameWriter::Raw`), so a caller reading with a
    /// buffer smaller than the underlying `read()` must not see `InvalidInput`, and a clean close
    /// must report `Ok(0)`. Fails on 3cfb750b (`InvalidInput "buffer is shorter than a chunk"` on
    /// the first short read, `UnexpectedEof` on close).
    #[tokio::test]
    async fn security_none_tcp_raw_reader_buffers_short_reads_and_reports_clean_eof() {
        let (server_io, mut client_io) = tokio::io::duplex(65536);
        let client = Client::new(Uuid::nil(), "none", 0, false, false, fixed_time).expect("valid client");

        let shared = Arc::new(SharedConn {
            upstream: SyncMutex::new(Box::new(TestDuplexConn(server_io))),
            response_header: AtomicU8::new(0),
        });
        let codec =
            build_codec(Security::None, 0, &[0u8; 16], &[0u8; 16], &[0u8; 16], &[0u8; 16]).expect("valid codec");
        let mut read_state = ReadState {
            client,
            command: COMMAND_TCP,
            request_key: [0u8; 16],
            request_nonce: [0u8; 16],
            read_buffer: true,
            conn: ConnHandle(shared),
            reader: Some(codec),
            pending: Vec::new(),
            pending_offset: 0,
        };

        let payload = vec![0xABu8; 40000];
        client_io.write_all(&payload).await.expect("write payload");

        let mut got = Vec::new();
        let mut small = [0u8; 1024];
        while got.len() < payload.len() {
            let n = read_state.do_read(&mut small).await.expect("read succeeds with a smaller-than-chunk buffer");
            assert!(n > 0, "read must make progress");
            got.extend_from_slice(&small[..n]);
        }
        assert_eq!(got, payload);

        client_io.shutdown().await.expect("shutdown client half");
        let n = read_state.do_read(&mut small).await.expect("clean close reports Ok(0), not UnexpectedEof");
        assert_eq!(n, 0);
    }

    /// `ReviewSvCore` finding 0: a clean close at a chunk boundary is `Ok(None)` from the codec
    /// (finding 6 of the previous round), which TCP conns correctly surface as `Ok(0)`. On a
    /// `COMMAND_UDP` conn, though, `network::PacketConn`/XUDP callers treat `Ok(0)` as a
    /// real empty datagram, so the session never ends and the NAT entry never gets dropped (a
    /// clean end of stream, which the client packet-conn read turns into an error). Fails on
    /// 60e1ae45, which returns `Ok(0)` for both TCP and UDP alike.
    #[tokio::test]
    async fn udp_read_after_peer_close_returns_err_not_ok_zero() {
        let (server_io, mut client_io) = tokio::io::duplex(65536);
        let client = Client::new(Uuid::nil(), "none", 0, false, false, fixed_time).expect("valid client");

        let shared = Arc::new(SharedConn {
            upstream: SyncMutex::new(Box::new(TestDuplexConn(server_io))),
            response_header: AtomicU8::new(0),
        });
        let codec = build_codec(Security::None, OPTION_CHUNK_STREAM, &[0u8; 16], &[0u8; 16], &[0u8; 16], &[0u8; 16])
            .expect("valid codec");
        let mut read_state = ReadState {
            client,
            command: COMMAND_UDP,
            request_key: [0u8; 16],
            request_nonce: [0u8; 16],
            read_buffer: true,
            conn: ConnHandle(shared),
            reader: Some(codec),
            pending: Vec::new(),
            pending_offset: 0,
        };

        let mut writer =
            build_codec(Security::None, OPTION_CHUNK_STREAM, &[0u8; 16], &[0u8; 16], &[0u8; 16], &[0u8; 16])
                .expect("valid codec");
        writer.write_chunk(&mut client_io, b"hello").await.expect("write one udp datagram chunk");

        let mut buf = [0u8; 64];
        let n = read_state.do_read(&mut buf).await.expect("first read delivers the datagram");
        assert_eq!(&buf[..n], b"hello");

        client_io.shutdown().await.expect("shutdown client half");
        read_state.do_read(&mut buf).await.expect_err(
            "a clean close on a UDP conn must be an error, not Ok(0) (indistinguishable from an empty datagram)",
        );
    }
}

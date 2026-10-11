//! The server half of VMess. Only the AEAD-2 request branch is implemented.
//!
//! `alter_id != 0` is accepted at [`Service::update_users`] time and never rejected in
//! [`Service::accept`] either: an AEAD AuthID is matched against every user regardless of that
//! user's `alter_id` (only the separate legacy alter-id-map lookup this crate doesn't implement
//! cares about it). Header protection is always disabled, matching how
//! `listener::sing_vmess::server` constructs the service, so the header read always uses
//! `read_at_least_from` (a robust multi-read loop) rather than the single-read probe-detection path.
//!
//! The bloom-filter-backed replay cache has no crate mirror; this
//! uses a plain time-windowed `HashSet` guarded by a `parking_lot::Mutex` instead, pruned on
//! every check. It rejects a replayed AuthID exactly as the filter does; only the false-positive
//! rate under extreme memory pressure differs, which is not wire-visible.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes::cipher::{BlockCipherDecrypt, KeyInit as _};
use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
use parking_lot::Mutex as SyncMutex;
use sha2::Digest as _;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use super::addr;
use super::chunk::CIPHER_OVERHEAD;
use super::client::{
    build_codec, key_from_uuid, write_payload, Codec, Security, COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, VERSION,
};
use crate::header::{
    kdf, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
    KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
    KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY, KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY, KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
};
use murmur_common::shared_conn::SharedConn as VmessSharedConn;
use murmur_common_net::io::{OldConnAsStream, StreamAsOldConn};
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::Conn as NetConn;

const HEADER_LEN_BUFFER_LEN: usize = 2 + CIPHER_OVERHEAD;
const NONCE_INDEX: usize = 16 + HEADER_LEN_BUFFER_LEN;
const HEADER_INDEX: usize = NONCE_INDEX + 8;
const AEAD_MIN_HEADER_LEN: usize = 16 + HEADER_LEN_BUFFER_LEN + 8 + CIPHER_OVERHEAD + 42;

struct UserEntry {
    username: String,
    cmd_key: [u8; 16],
}

impl core::fmt::Debug for UserEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserEntry").field("username", &self.username).field("cmd_key", &"<redacted>").finish()
    }
}

/// The service's replay-relevant state, minus the legacy alter-id maps (see
/// the module doc) and the mux/handler dispatch, which the caller (`listener::sing_vmess`) owns.
#[derive(Debug)]
pub struct Service {
    users: SyncMutex<Vec<UserEntry>>,
    time_func: fn() -> DateTime<Utc>,
    replay: SyncMutex<HashMap<[u8; 16], Instant>>,
}

/// The outcome of a successful accept: the caller dispatches on `command`.
pub struct Accepted {
    pub username: String,
    pub command: u8,
    pub destination: Socksaddr,
    pub conn: Box<dyn NetConn>,
}

impl core::fmt::Debug for Accepted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Accepted")
            .field("username", &self.username)
            .field("command", &self.command)
            .field("destination", &self.destination)
            .finish_non_exhaustive()
    }
}

impl Service {
    pub fn new(time_func: fn() -> DateTime<Utc>) -> Self {
        Self { users: SyncMutex::new(Vec::new()), time_func, replay: SyncMutex::new(HashMap::new()) }
    }

    pub fn update_users(&self, usernames: &[String], uuids: &[String], alter_ids: &[i32]) -> Result<()> {
        if usernames.len() != uuids.len() || usernames.len() != alter_ids.len() {
            bail!("vmess: mismatched user list lengths");
        }
        let mut entries = Vec::with_capacity(uuids.len());
        for ((username, uuid_str), _alter_id) in usernames.iter().zip(uuids).zip(alter_ids) {
            let uuid = Uuid::parse_str(uuid_str).map_err(|err| anyhow!("invalid uuid {uuid_str}: {err}"))?;
            entries.push(UserEntry { username: username.clone(), cmd_key: key_from_uuid(uuid) });
        }
        *self.users.lock() = entries;
        Ok(())
    }

    fn check_replay(&self, decoded_id: &[u8; 16]) -> bool {
        let mut seen = self.replay.lock();
        let now = Instant::now();
        seen.retain(|_, t| now.duration_since(*t) < Duration::from_secs(120));
        if seen.contains_key(decoded_id) {
            return false;
        }
        seen.insert(*decoded_id, now);
        true
    }

    /// Accepts a connection (AEAD-2 branch only).
    // NOT cancel-safe: the accepted connection has already been read from (framing or an authentication header), so a dropped call loses it mid-exchange.
    pub async fn accept(&self, mut conn: Box<dyn NetConn>) -> Result<Accepted> {
        let mut request = vec![0u8; AEAD_MIN_HEADER_LEN];
        conn.read_exact(&mut request).await?;

        let auth_id = array_at::<16>(&request, 0)?;
        let (username, cmd_key) = self.select_user(&auth_id)?;
        let (header, consumed) = read_header(&mut conn, &mut request, &auth_id, &cmd_key).await?;
        let RequestHeader {
            command,
            security,
            option,
            response_header,
            request_body_key,
            request_body_nonce,
            destination,
        } = parse_request_header(&header)?;

        let leftover = request.get(consumed..).unwrap_or_default().to_vec();
        // S11: remove in U5, once this module's own `conn` field takes Stream.
        let conn: Box<dyn NetConn> = if leftover.is_empty() {
            conn
        } else {
            Box::new(murmur_common_net::new_cached_conn(OldConnAsStream(conn), leftover))
        };

        let reader = build_codec(
            security,
            option,
            &request_body_key,
            &request_body_nonce,
            &request_body_key,
            &request_body_nonce,
        )
        .map_err(|err| anyhow!(err))?;
        // `security = none` TCP builds `FrameReader::Raw` (see `client::build_codec`), which
        // reads a stream slice rather than one whole chunk; buffering the remainder is required
        // so a caller's shorter read doesn't see `InvalidInput`.
        let read_buffer = (option & 1 != 0 && command == COMMAND_TCP)
            || command == COMMAND_MUX
            || (security == Security::None && command == COMMAND_TCP);

        let close_handle = VmessSharedConn::from_boxed(conn);
        let shared = super::conn_driver::SharedConn::new(Box::new(OldConnAsStream(close_handle.clone())));
        let read_state = ReadState {
            conn: Arc::clone(&shared).into(),
            reader: Some(reader),
            read_buffer,
            command,
            pending: Vec::new(),
            pending_offset: 0,
        };
        let write_state = WriteState {
            conn: Arc::clone(&shared).into(),
            request_body_key,
            request_body_nonce,
            response_header,
            option,
            security,
            writer: None,
        };

        Ok(Accepted {
            username,
            command,
            destination,
            conn: Box::new(StreamAsOldConn::new(super::conn_driver::Driven::new(
                shared,
                close_handle,
                read_state,
                write_state,
            ))),
        })
    }

    /// Decodes the AEAD AuthID block and matches it against every registered user.
    fn select_user(&self, auth_id: &[u8; 16]) -> Result<(String, [u8; 16])> {
        let now = (self.time_func)().timestamp();
        for user in self.users.lock().iter() {
            let aes_key = &kdf(&user.cmd_key, &[KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY])[..16];
            let aes_block = aes::Aes128::new_from_slice(aes_key).map_err(|err| anyhow!("{err}"))?;
            let mut decoded_block = aes::Block::from(*auth_id);
            aes_block.decrypt_block(&mut decoded_block);
            let decoded: [u8; 16] = decoded_block.into();

            let checksum = crc32fast::hash(&decoded[..12]);
            if checksum != u32::from_be_bytes(array_at(&decoded, 12)?) {
                continue;
            }
            let timestamp = i64::from_be_bytes(array_at(&decoded, 0)?);
            if (timestamp - now).abs() > 120 {
                bail!("vmess: bad timestamp");
            }
            if !self.check_replay(&decoded) {
                bail!("vmess: replayed request");
            }
            return Ok((user.username.clone(), user.cmd_key));
        }
        bail!("vmess: bad request (no matching user)");
    }
}

/// The fields read out of the opened AEAD header.
struct RequestHeader {
    command: u8,
    security: Security,
    option: u8,
    response_header: u8,
    request_body_key: [u8; 16],
    request_body_nonce: [u8; 16],
    destination: Socksaddr,
}

/// Copies the `N`-byte window at `offset`, so a short buffer is an error rather than a panic.
fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .and_then(|window| <[u8; N]>::try_from(window).ok())
        .ok_or_else(|| anyhow!("vmess: truncated header"))
}

fn byte_at(bytes: &[u8], offset: usize) -> Result<u8> {
    bytes.get(offset).copied().ok_or_else(|| anyhow!("vmess: truncated header"))
}

/// Opens the sealed length, pulls the remaining header bytes off `conn`, then opens the header.
async fn read_header(
    conn: &mut dyn NetConn,
    request: &mut Vec<u8>,
    auth_id: &[u8; 16],
    cmd_key: &[u8; 16],
) -> Result<(Vec<u8>, usize)> {
    let connection_nonce = array_at::<8>(request, NONCE_INDEX)?;

    let length_key = kdf(cmd_key, &[KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, auth_id, &connection_nonce]);
    let length_nonce = kdf(cmd_key, &[KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, auth_id, &connection_nonce]);
    let sealed_length = request.get(16..NONCE_INDEX).ok_or_else(|| anyhow!("vmess: truncated header"))?;
    let opened_length = aes_gcm_open(&length_key[..16], &length_nonce[..12], sealed_length, auth_id)?;
    let header_length = usize::from(u16::from_be_bytes(array_at(&opened_length, 0)?));

    let consumed = HEADER_INDEX + header_length + CIPHER_OVERHEAD;
    if consumed > request.len() {
        let mut more = vec![0u8; consumed - request.len()];
        conn.read_exact(&mut more).await?;
        request.extend_from_slice(&more);
    }

    let header_key = kdf(cmd_key, &[KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY, auth_id, &connection_nonce]);
    let header_nonce = kdf(cmd_key, &[KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, auth_id, &connection_nonce]);
    let sealed_header = request.get(HEADER_INDEX..consumed).ok_or_else(|| anyhow!("vmess: truncated header"))?;
    let header = aes_gcm_open(&header_key[..16], &header_nonce[..12], sealed_header, auth_id)?;
    Ok((header, consumed))
}

fn parse_request_header(header: &[u8]) -> Result<RequestHeader> {
    if header.len() <= 38 {
        bail!("vmess: bad header (short)");
    }
    let version = byte_at(header, 0)?;
    if version != VERSION {
        bail!("vmess: bad version {version}");
    }
    let request_body_nonce = array_at::<16>(header, 1)?;
    let request_body_key = array_at::<16>(header, 17)?;
    let response_header = byte_at(header, 33)?;
    let option = byte_at(header, 34)?;
    let flags = byte_at(header, 35)?;
    let padding_len = usize::from(flags >> 4);
    let security_byte = flags & 0x0F;
    let command = byte_at(header, 37)?;
    if !matches!(command, COMMAND_TCP | COMMAND_UDP | COMMAND_MUX) {
        bail!("vmess: unknown command {command}");
    }
    if command == COMMAND_UDP && option == 0 {
        bail!("vmess: bad packet connection");
    }
    let security = Security::from_byte(security_byte).ok_or_else(|| anyhow!("vmess: unsupported security type"))?;

    let mut cursor: &[u8] = header.get(38..).ok_or_else(|| anyhow!("vmess: bad header (short)"))?;
    let destination = if command == COMMAND_MUX {
        Socksaddr::default()
    } else {
        addr::read_addr_port(&mut cursor).map_err(|err| anyhow!("bad destination address: {err}"))?
    };
    if padding_len > 0 {
        cursor = cursor.get(padding_len..).ok_or_else(|| anyhow!("vmess: bad padding"))?;
    }
    if cursor.len() < 4 {
        bail!("vmess: bad header (missing checksum)");
    }
    Ok(RequestHeader { command, security, option, response_header, request_body_key, request_body_nonce, destination })
}

fn aes_gcm_open(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes128Gcm, KeyInit};
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|err| anyhow!("{err}"))?;
    let nonce = <&aes_gcm::Nonce<_>>::try_from(nonce).map_err(|_| anyhow!("cipher: bad nonce"))?;
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| anyhow!("cipher: message authentication failed"))
}

fn aes_gcm_seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes128Gcm, KeyInit};
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|err| anyhow!("{err}"))?;
    let nonce = <&aes_gcm::Nonce<_>>::try_from(nonce).map_err(|_| anyhow!("cipher: bad nonce"))?;
    cipher.encrypt(nonce, Payload { msg: plaintext, aad }).map_err(|_| anyhow!("cipher: seal failed"))
}

/// The first 16 bytes of `Sha256::digest(input)`: the AEAD-2 response key/nonce derivation.
fn sha256_first16(input: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    if let Some(first) = sha2::Sha256::digest(input).get(..out.len()) {
        out.copy_from_slice(first);
    }
    out
}

/// The write-direction fields of the server conn when `legacyProtocol == false`.
struct WriteState {
    conn: super::conn_driver::ConnHandle,
    request_body_key: [u8; 16],
    request_body_nonce: [u8; 16],
    response_header: u8,
    option: u8,
    security: Security,
    writer: Option<Codec>,
}

/// Read-direction fields.
struct ReadState {
    conn: super::conn_driver::ConnHandle,
    reader: Option<Codec>,
    read_buffer: bool,
    command: u8,
    pending: Vec<u8>,
    pending_offset: usize,
}

impl WriteState {
    /// Writes the response header (AEAD-2 branch).
    async fn write_response(&mut self) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let response_key = sha256_first16(self.request_body_key);
        let response_nonce = sha256_first16(self.request_body_nonce);

        let header_len_key = kdf(&response_key, &[KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY]);
        let header_len_nonce = kdf(&response_nonce, &[KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV]);
        let sealed_len = aes_gcm_seal(&header_len_key[..16], &header_len_nonce[..12], &4u16.to_be_bytes(), &[])
            .map_err(std::io::Error::other)?;

        let header_key = kdf(&response_key, &[KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY]);
        let header_nonce = kdf(&response_nonce, &[KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV]);
        let plain_header = [self.response_header, self.option, 0, 0];
        let sealed_header =
            aes_gcm_seal(&header_key[..16], &header_nonce[..12], &plain_header, &[]).map_err(std::io::Error::other)?;

        let mut response = Vec::with_capacity(sealed_len.len() + sealed_header.len());
        response.extend_from_slice(&sealed_len);
        response.extend_from_slice(&sealed_header);
        self.conn.write_all(&response).await?;

        self.writer = Some(
            build_codec(
                self.security,
                self.option,
                &self.request_body_key,
                &self.request_body_nonce,
                &response_key,
                &response_nonce,
            )
            .map_err(std::io::Error::other)?,
        );
        Ok(())
    }

    async fn do_write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.writer.is_none() {
            self.write_response().await?;
        }
        let Some(mut codec) = self.writer.take() else {
            return Err(std::io::Error::other("vmess: write codec missing"));
        };
        let result = write_payload(&mut codec, &mut self.conn, b).await;
        self.writer = Some(codec);
        result?;
        Ok(b.len())
    }
}

impl ReadState {
    async fn do_read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        if self.pending_offset < self.pending.len() {
            let (_, pending) = self.pending.split_at(self.pending_offset);
            let n = copy_out(b, pending);
            self.pending_offset += n;
            return Ok(n);
        }
        let Some(mut codec) = self.reader.take() else {
            return Err(std::io::Error::other("vmess: read codec missing"));
        };
        let result = codec.read_chunk(&mut self.conn).await;
        self.reader = Some(codec);
        let chunk = match result? {
            Some(chunk) => chunk,
            None if self.command == COMMAND_UDP => {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "vmess: udp session ended"))
            }
            None => return Ok(0),
        };
        if !self.read_buffer && chunk.len() > b.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "buffer is shorter than a chunk"));
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

fn copy_out(dst: &mut [u8], src: &[u8]) -> usize {
    let n = dst.len().min(src.len());
    if let (Some(dst), Some(src)) = (dst.get_mut(..n), src.get(..n)) {
        dst.copy_from_slice(src);
    }
    n
}

impl super::conn_driver::DriveRead for ReadState {
    fn read<'a>(&'a mut self, b: &'a mut [u8]) -> Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'a>> {
        Box::pin(self.do_read(b))
    }
}

impl super::conn_driver::DriveWrite for WriteState {
    fn write<'a>(&'a mut self, b: &'a [u8]) -> Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'a>> {
        Box::pin(self.do_write(b))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin as StdPin;
    use std::task::{Context as StdContext, Poll as StdPoll};

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;
    use crate::sing::client::Client;
    use murmur_std_compat::net::{Addr, TcpAddr};

    struct TestDuplexConn(tokio::io::DuplexStream);

    impl AsyncRead for TestDuplexConn {
        fn poll_read(
            self: StdPin<&mut Self>,
            cx: &mut StdContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> StdPoll<std::io::Result<()>> {
            StdPin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestDuplexConn {
        fn poll_write(self: StdPin<&mut Self>, cx: &mut StdContext<'_>, buf: &[u8]) -> StdPoll<std::io::Result<usize>> {
            StdPin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: StdPin<&mut Self>, cx: &mut StdContext<'_>) -> StdPoll<std::io::Result<()>> {
            StdPin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: StdPin<&mut Self>, cx: &mut StdContext<'_>) -> StdPoll<std::io::Result<()>> {
            StdPin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl NetConn for TestDuplexConn {
        fn local_addr(&self) -> std::io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        }

        fn remote_addr(&self) -> std::io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        }

        fn close(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// `ReviewSingVmess` finding 7: `alter_id > 0` must load (via `update_users`), matching the
    /// refactor contract's frozen YAML-acceptance surface. Fails on
    /// 3cfb750b, which rejects the whole user list outright.
    #[test]
    fn alter_id_gt_zero_accepted_by_update_users() {
        let service = Service::new(Utc::now);
        let uuid = Uuid::new_v4().to_string();
        let result = service.update_users(&["alice".to_owned()], &[uuid], &[64]);
        assert!(
            result.is_ok(),
            "alterId > 0 must load, not fail UpdateUsers: {result:?}"
        );
    }

    /// Companion to the above: accept matches AEAD AuthIDs across all users
    /// regardless of `alter_id` — a nonzero `alter_id` only adds the extra legacy alter-id-map
    /// path, which this crate doesn't implement, but never gates the AEAD-2 handshake itself.
    /// `listener::re_create_vmess` registers the top-level `vmess-config` listener's user with
    /// `alter_id: 1`, so this must keep working.
    #[tokio::test]
    async fn alter_id_gt_zero_still_accepts_aead_client_at_accept() {
        let uuid = Uuid::new_v4();
        let service = Service::new(Utc::now);
        service.update_users(&["alice".to_owned()], &[uuid.to_string()], &[1]).expect("update_users accepts alterId>0");

        let client = Client::new(uuid, "aes-128-gcm", 0, false, false, Utc::now).expect("valid client");
        let (client_io, server_io) = tokio::io::duplex(65536);
        let client_conn: Box<dyn NetConn> = Box::new(TestDuplexConn(client_io));
        let destination = Socksaddr { fqdn: "example.com".to_owned(), addr: None, port: 80 };
        tokio::spawn(async move {
            let _ = client.dial_conn(client_conn, destination).await;
        });

        let server_conn: Box<dyn NetConn> = Box::new(TestDuplexConn(server_io));
        let accepted = service.accept(server_conn).await.expect("AEAD client must be accepted despite alterId > 0");
        assert_eq!(accepted.username, "alice");
    }

    /// `ReviewSvCore` finding 0: a clean close at a chunk boundary is `Ok(None)` from the codec,
    /// which TCP conns correctly surface as `Ok(0)`. On a `COMMAND_UDP` conn, though,
    /// `VmessServerPacketConn`/XUDP callers treat `Ok(0)` as a real empty datagram, so the
    /// session never ends and the NAT entry never gets dropped (a clean end of stream, which
    /// the server packet-conn read turns into an error). Fails on 60e1ae45, which returns
    /// `Ok(0)` for both TCP and UDP alike.
    #[tokio::test]
    async fn udp_read_after_peer_close_returns_err_not_ok_zero() {
        let uuid = Uuid::new_v4();
        let service = Service::new(Utc::now);
        service.update_users(&["alice".to_owned()], &[uuid.to_string()], &[0]).expect("valid users");

        let client = Client::new(uuid, "none", 0, false, false, Utc::now).expect("valid client");
        let (client_io, server_io) = tokio::io::duplex(65536);
        let client_conn: Box<dyn NetConn> = Box::new(TestDuplexConn(client_io));
        let destination = Socksaddr { fqdn: "example.com".to_owned(), addr: None, port: 80 };
        let mut client_pc = client.dial_early_packet_conn(client_conn, destination);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client_pc.write_all(b"hello").await.expect("write one udp datagram");
            client_pc.shutdown().await.expect("shutdown client half");
        });

        let server_conn: Box<dyn NetConn> = Box::new(TestDuplexConn(server_io));
        let mut accepted = service.accept(server_conn).await.expect("valid udp accept");
        assert_eq!(accepted.command, COMMAND_UDP);

        let mut buf = [0u8; 64];
        use tokio::io::AsyncReadExt;
        let n = accepted.conn.read(&mut buf).await.expect("first read delivers the datagram");
        assert_eq!(&buf[..n], b"hello");

        accepted.conn.read(&mut buf).await.expect_err(
            "a clean close on a UDP conn must be an error, not Ok(0) (indistinguishable from an empty datagram)",
        );
    }
}

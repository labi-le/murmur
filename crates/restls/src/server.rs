//! The Restls server: relays the TLS 1.2/1.3 handshake verbatim between the inbound client and a
//! real dialed `target`.
//!
//! The client is authenticated purely from public wire bytes (no TLS decryption is ever needed
//! server-side), after which the inbound socket runs the Restls application-record framing for
//! the life of the connection.
//!
//! Both the TLS 1.3 and TLS 1.2 handshake paths are relayed (see `handshake_tls13`/
//! `handshake_tls12`). Any other negotiated version, or a target that answers with a
//! HelloRetryRequest / an unparseable ClientHello / ServerHello, falls back to `relay_raw`: the
//! raw bytes are shoveled between the two sockets until either side closes, and no connection is
//! ever produced for that case. `ServerConfig.rate_limit` is accepted but not enforced: the
//! fallback path would wrap the raw relay in a token-bucket rate limiter, but neither this crate
//! nor its `common-net` dependency has a rate-limiter primitive, and it only ever gates the
//! abandoned raw-relay fallback path (never the authenticated Restls traffic).
//!
//! The disguise `target` connection is dropped once the handshake finishes, so the target's own
//! post-handshake records are never forwarded to the client and its cached `close_notify` is
//! never replayed on close. Record counters stay consistent either way, because a peer only
//! counts records it actually receives; what is lost is camouflage fidelity and the target's
//! clean-close notification, not interoperability.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use anyhow::{anyhow, bail, Result};
use parking_lot::Mutex;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common::shared_conn::SharedConn;
use murmur_std_compat::net::{Addr, Conn as NetConn};

use crate::config::ServerConfig;
use crate::consts::{
    tls12_curve_index, EXT_KEY_SHARE, EXT_PRE_SHARED_KEY, EXT_SESSION_TICKET, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
    HANDSHAKE_TYPE_SERVER_HELLO_DONE, HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE, HELLO_RETRY_REQUEST_RANDOM, MAX_PLAINTEXT,
    RECORD_HEADER_LEN, RECORD_TYPE_ALERT, RECORD_TYPE_APPLICATION_DATA, RECORD_TYPE_CHANGE_CIPHER_SPEC,
    RECORD_TYPE_HANDSHAKE, RESTLS12_CLIENT_AUTH_LAYOUT3, RESTLS12_CLIENT_AUTH_LAYOUT4, RESTLS_APP_DATA_AUTH_HEADER_LEN,
    RESTLS_CCS_RECORD, RESTLS_HANDSHAKE_MAC_LEN, TLS12_GCM_CIPHER_SUITES, VERSION_TLS12, VERSION_TLS13,
};
use crate::framing;
use crate::script::Command;
use crate::wire::{read_tls_record, read_tls_record_preserving, record_payload, record_type};

pub type DialFn = Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<Box<dyn NetConn>>> + Send>> + Send + Sync>;

/// The shared error for a handshake that fell back to the raw relay and saw it close.
const RAW_RELAY_CLOSED: &str = "restls: raw relay closed without restls connection";

fn restls_host_port(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:443")
    } else if host.contains(':') {
        host.to_owned()
    } else {
        format!("{host}:443")
    }
}

pub async fn restls_server(inbound: Box<dyn NetConn>, config: &ServerConfig) -> Result<Box<dyn NetConn>> {
    let min_record_len =
        if config.min_record_len <= 0 { 15 } else { usize::try_from(config.min_record_len).unwrap_or(15) };
    let target_addr = restls_host_port(&config.server_hostname);
    let target = (config.dial)(target_addr).await?;
    let inbound = SharedConn::from_boxed(inbound);
    let target = SharedConn::from_boxed(target);

    let secret = framing::derive_restls_secret(config.password.as_bytes());
    let script = if config.restls_script.is_empty() {
        crate::script::parse_record_script(crate::script::DEFAULT_RESTLS_SCRIPT)?
    } else {
        crate::script::parse_record_script(&config.restls_script)?
    };

    let mut inbound_rw = inbound.clone();
    let mut target_rw = target.clone();

    let ch_record = read_record_forwarding_prefix(&mut inbound_rw, &mut target_rw, &inbound, &target).await?;
    let Ok(ch_msg) = parse_client_hello_record(&ch_record) else {
        write_all(&mut target_rw, &ch_record).await?;
        return raw_relay_abort(&inbound, &target, RAW_RELAY_CLOSED).await;
    };
    write_all(&mut target_rw, &ch_record).await?;

    let sh_record = read_record_forwarding_prefix(&mut target_rw, &mut inbound_rw, &inbound, &target).await?;
    let Ok(server_hello) = parse_server_hello_record(&sh_record) else {
        write_all(&mut inbound_rw, &sh_record).await?;
        return raw_relay_abort(&inbound, &target, RAW_RELAY_CLOSED).await;
    };
    if server_hello.random == HELLO_RETRY_REQUEST_RANDOM {
        write_all(&mut inbound_rw, &sh_record).await?;
        return raw_relay_abort(&inbound, &target, "restls: hello retry request, relayed raw and connection closed")
            .await;
    }
    write_all(&mut inbound_rw, &sh_record).await?;

    let server_random = server_hello.random;

    if server_hello.supported_version == VERSION_TLS13 {
        return tls13_connection(inbound, target, secret, server_random, &ch_msg, script, min_record_len).await;
    }

    if server_hello.supported_version == VERSION_TLS12 {
        return tls12_connection(
            inbound,
            target,
            secret,
            server_random,
            &ch_msg,
            &server_hello,
            sh_record,
            script,
            min_record_len,
        )
        .await;
    }

    bail!("restls: target negotiated an unsupported TLS version");
}

/// Reads one TLS record from `reader`, forwarding bytes the failed read had already buffered to
/// `writer`; only a failure that read nothing at all is propagated as-is.
async fn read_record_forwarding_prefix(
    reader: &mut SharedConn,
    writer: &mut SharedConn,
    inbound: &SharedConn,
    target: &SharedConn,
) -> Result<Vec<u8>> {
    match read_tls_record_preserving(reader).await {
        Ok(record) => Ok(record),
        Err((prefix, err)) => {
            if prefix.is_empty() {
                return Err(err);
            }
            write_all(writer, &prefix).await?;
            relay_raw(inbound.clone(), target.clone()).await?;
            bail!("{RAW_RELAY_CLOSED}");
        }
    }
}

/// Relays the rest of the connection raw and reports `message` instead of a Restls connection.
async fn raw_relay_abort(inbound: &SharedConn, target: &SharedConn, message: &str) -> Result<Box<dyn NetConn>> {
    relay_raw(inbound.clone(), target.clone()).await?;
    bail!("{message}")
}

async fn tls13_connection(
    inbound: SharedConn,
    target: SharedConn,
    secret: [u8; 32],
    server_random: [u8; 32],
    ch_msg: &[u8],
    script: Vec<crate::script::Line>,
    min_record_len: usize,
) -> Result<Box<dyn NetConn>> {
    if check_tls13_client_auth(&secret, ch_msg).is_err() {
        return raw_relay_abort(&inbound, &target, "restls: unauthenticated TLS 1.3 connection relayed raw and closed")
            .await;
    }
    let (client_finished_raw, pending_record, early_server_records) =
        handshake_tls13(secret, server_random, inbound.clone(), target.clone()).await?;
    Ok(Box::new(RestlsConn::new(
        inbound,
        secret,
        server_random,
        Some(client_finished_raw),
        script,
        min_record_len,
        false,
        false,
        pending_record,
        early_server_records,
    )))
}

async fn tls12_connection(
    inbound: SharedConn,
    target: SharedConn,
    secret: [u8; 32],
    server_random: [u8; 32],
    ch_msg: &[u8],
    server_hello: &crate::messages::ParsedServerHello,
    sh_record: Vec<u8>,
    script: Vec<crate::script::Line>,
    min_record_len: usize,
) -> Result<Box<dyn NetConn>> {
    let Ok((session_id, session_ticket)) = parse_client_hello_session_fields(ch_msg) else {
        return raw_relay_abort(&inbound, &target, RAW_RELAY_CLOSED).await;
    };
    let is_tls12_gcm = TLS12_GCM_CIPHER_SUITES.contains(&server_hello.cipher_suite);
    let tls12_authenticated = AtomicBool::new(false);
    let parrot_gcm = AtomicBool::new(false);
    let handshake_result = handshake_tls12(
        secret,
        server_random,
        is_tls12_gcm,
        session_id,
        session_ticket,
        inbound.clone(),
        target.clone(),
        sh_record,
        &tls12_authenticated,
        &parrot_gcm,
    )
    .await;
    let client_finished_raw = match handshake_result {
        Ok(cf) => cf,
        Err(err) => {
            if tls12_authenticated.load(Ordering::SeqCst) {
                return Err(err);
            }
            return raw_relay_abort(&inbound, &target, RAW_RELAY_CLOSED).await;
        }
    };
    Ok(Box::new(RestlsConn::new(
        inbound,
        secret,
        server_random,
        client_finished_raw,
        script,
        min_record_len,
        is_tls12_gcm,
        parrot_gcm.load(Ordering::SeqCst),
        Vec::new(),
        0,
    )))
}

// NOT cancel-safe: `AsyncWriteExt::write_all` writes into the socket as it goes, so a dropped call leaves a partial write.
async fn write_all<W: AsyncWrite + Unpin>(conn: &mut W, buf: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    conn.write_all(buf).await?;
    Ok(())
}

fn parse_client_hello_record(record: &[u8]) -> Result<Vec<u8>> {
    if record_type(record)? != RECORD_TYPE_HANDSHAKE {
        bail!("restls: expected ClientHello record");
    }
    Ok(crate::messages::first_handshake_message(record_payload(record))?.to_vec())
}

fn parse_server_hello_record(record: &[u8]) -> Result<crate::messages::ParsedServerHello> {
    if record_type(record)? != RECORD_TYPE_HANDSHAKE {
        bail!("restls: target did not answer with a ServerHello");
    }
    let msg = crate::messages::first_handshake_message(record_payload(record))?;
    crate::messages::parse_server_hello(msg.get(4..).ok_or_else(|| anyhow!("restls: short ServerHello"))?)
}

/// The raw relay without the rate limiter (see module doc): shovels bytes between `inbound` and
/// `target` until either side closes, then closes both. Returns `Ok(())` on a clean close (the
/// caller always turns that into `RAW_RELAY_CLOSED`) or the first I/O error either direction hit.
async fn relay_raw(mut inbound: SharedConn, mut target: SharedConn) -> Result<()> {
    let result = tokio::io::copy_bidirectional(&mut inbound, &mut target).await;
    let _ = inbound.close();
    let _ = target.close();
    result?;
    Ok(())
}

/// The ClientHello body byte at `pos`, or the shared short-message error.
fn hello_byte(body: &[u8], pos: usize) -> Result<u8> {
    body.get(pos).copied().ok_or_else(|| anyhow!("restls: short ClientHello"))
}

/// The big-endian `u16` at `pos` of a ClientHello body, or the shared short-message error.
fn hello_u16(body: &[u8], pos: usize) -> Result<u16> {
    let Some([hi, lo]) = body.get(pos..pos + 2) else {
        bail!("restls: short ClientHello");
    };
    Ok(u16::from_be_bytes([*hi, *lo]))
}

/// purely a check over the plaintext ClientHello
/// bytes the relay already forwarded, no decryption involved.
fn check_tls13_client_auth(secret: &[u8; 32], ch_msg: &[u8]) -> Result<()> {
    let body = ch_msg.get(4..).ok_or_else(|| anyhow!("restls: short ClientHello"))?;
    let mut pos = 2 + 32;
    if body.len() < pos + 1 {
        bail!("restls: short ClientHello");
    }
    let session_id_len = usize::from(hello_byte(body, pos)?);
    pos += 1;
    if session_id_len != 32 || body.len() < pos + 32 {
        bail!("restls: TLS 1.3 session id must be 32 bytes");
    }
    let session_id = body.get(pos..pos + 32).ok_or_else(|| anyhow!("restls: TLS 1.3 session id must be 32 bytes"))?;
    pos += 32;

    if body.len() < pos + 2 {
        bail!("restls: short ClientHello");
    }
    let cs_len = usize::from(hello_u16(body, pos)?);
    pos += 2;
    if body.len() < pos + cs_len + 1 {
        bail!("restls: short ClientHello cipher suites");
    }
    pos += cs_len;
    if body.len() < pos + 1 {
        bail!("restls: short ClientHello");
    }
    let comp_len = usize::from(hello_byte(body, pos)?);
    pos += 1;
    if body.len() < pos + comp_len + 2 {
        bail!("restls: short ClientHello compression methods");
    }
    pos += comp_len;
    if body.len() < pos + 2 {
        bail!("restls: short ClientHello");
    }
    let ext_len = usize::from(hello_u16(body, pos)?);
    pos += 2;
    if body.len() < pos + ext_len {
        bail!("restls: short ClientHello extensions");
    }
    let ext_block = body.get(pos..pos + ext_len).ok_or_else(|| anyhow!("restls: short ClientHello extensions"))?;

    let mut hasher = blake3::Hasher::new_keyed(secret);
    let mut ep = 0usize;
    while ep + 4 <= ext_block.len() {
        let id = hello_u16(ext_block, ep)?;
        let len = usize::from(hello_u16(ext_block, ep + 2)?);
        if ext_block.len() < ep + 4 + len {
            bail!("restls: short ClientHello extension");
        }
        let data = ext_block.get(ep + 4..ep + 4 + len).ok_or_else(|| anyhow!("restls: short ClientHello extension"))?;
        ep += 4 + len;
        if id == EXT_KEY_SHARE {
            if data.len() < 2 {
                bail!("restls: short key_share extension");
            }
            let mut dp = 2;
            while dp + 4 <= data.len() {
                let group = hello_u16(data, dp)?;
                let klen = usize::from(hello_u16(data, dp + 2)?);
                if data.len() < dp + 4 + klen {
                    bail!("restls: short key_share entry");
                }
                hasher.update(&group.to_be_bytes());
                hasher.update(data.get(dp + 4..dp + 4 + klen).ok_or_else(|| anyhow!("restls: short key_share entry"))?);
                dp += 4 + klen;
            }
        } else if id == EXT_PRE_SHARED_KEY {
            if data.len() < 2 {
                bail!("restls: short pre_shared_key extension");
            }
            let ids_len = usize::from(hello_u16(data, 0)?);
            let mut dp = 2;
            let end = 2 + ids_len;
            while dp + 2 <= end {
                let label_len = usize::from(hello_u16(data, dp)?);
                if data.len() < dp + 2 + label_len + 4 || dp + 2 + label_len + 4 > end {
                    bail!("restls: short pre_shared_key identity");
                }
                hasher.update(
                    data.get(dp + 2..dp + 2 + label_len)
                        .ok_or_else(|| anyhow!("restls: short pre_shared_key identity"))?,
                );
                dp += 2 + label_len + 4;
            }
        }
    }
    let expect = hasher.finalize();
    if expect.as_bytes().get(..RESTLS_HANDSHAKE_MAC_LEN) != session_id.get(..RESTLS_HANDSHAKE_MAC_LEN) {
        bail!("restls: bad TLS 1.3 client auth");
    }
    Ok(())
}

/// Extracts the 32-byte session id and, when present, the `session_ticket` extension body (ext
/// id 35, RFC 5077) out of a raw ClientHello handshake message, used by the TLS 1.2 auth checks
/// below. Walks the same fields as `check_tls13_client_auth` above, just extracting a different
/// extension.
fn parse_client_hello_session_fields(ch_msg: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    let body = ch_msg.get(4..).ok_or_else(|| anyhow!("restls: short ClientHello"))?;
    let mut pos = 2 + 32;
    if body.len() < pos + 1 {
        bail!("restls: short ClientHello");
    }
    let session_id_len = usize::from(hello_byte(body, pos)?);
    pos += 1;
    if session_id_len != 32 || body.len() < pos + 32 {
        bail!("restls: TLS 1.2 session id must be 32 bytes");
    }
    let session_id: [u8; 32] = body
        .get(pos..pos + 32)
        .ok_or_else(|| anyhow!("restls: TLS 1.2 session id must be 32 bytes"))?
        .try_into()
        .map_err(|_| anyhow!("restls: TLS 1.2 session id must be 32 bytes"))?;
    pos += 32;

    if body.len() < pos + 2 {
        bail!("restls: short ClientHello");
    }
    let cs_len = usize::from(hello_u16(body, pos)?);
    pos += 2;
    if body.len() < pos + cs_len + 1 {
        bail!("restls: short ClientHello cipher suites");
    }
    pos += cs_len;
    if body.len() < pos + 1 {
        bail!("restls: short ClientHello");
    }
    let comp_len = usize::from(hello_byte(body, pos)?);
    pos += 1;
    if body.len() < pos + comp_len + 2 {
        bail!("restls: short ClientHello compression methods");
    }
    pos += comp_len;
    if body.len() < pos + 2 {
        bail!("restls: short ClientHello");
    }
    let ext_len = usize::from(hello_u16(body, pos)?);
    pos += 2;
    if body.len() < pos + ext_len {
        bail!("restls: short ClientHello extensions");
    }
    let ext_block = body.get(pos..pos + ext_len).ok_or_else(|| anyhow!("restls: short ClientHello extensions"))?;

    let mut session_ticket = Vec::new();
    let mut ep = 0usize;
    while ep + 4 <= ext_block.len() {
        let id = hello_u16(ext_block, ep)?;
        let len = usize::from(hello_u16(ext_block, ep + 2)?);
        if ext_block.len() < ep + 4 + len {
            bail!("restls: short ClientHello extension");
        }
        let data = ext_block.get(ep + 4..ep + 4 + len).ok_or_else(|| anyhow!("restls: short ClientHello extension"))?;
        ep += 4 + len;
        if id == EXT_SESSION_TICKET {
            session_ticket = data.to_vec();
        }
    }
    Ok((session_id, session_ticket))
}

/// Relays the TLS 1.3 handshake. `inbound`/`target` are owned `SharedConn` clones so the
/// concurrent `select!` below can hold a persistent read future on one clone and write
/// through another, matching the two-sided relay without risking the borrow conflict a
/// single `&mut` handle would hit: a pending read future would otherwise hold `inbound`/`target`
/// borrowed across its whole lifetime, blocking the sibling branch's writes to the same
/// connection.
async fn handshake_tls13(
    secret: [u8; 32],
    server_random: [u8; 32],
    inbound: SharedConn,
    target: SharedConn,
) -> Result<(Vec<u8>, Vec<u8>, u64)> {
    let mut inbound_w = inbound.clone();
    let mut target_w = target.clone();
    let mut target_r = target.clone();

    let mut seen_server_ccs = false;
    loop {
        let record = read_tls_record(&mut target_r).await?;
        match record_type(&record)? {
            RECORD_TYPE_CHANGE_CIPHER_SPEC => {
                if seen_server_ccs {
                    bail!("restls: duplicate TLS 1.3 server CCS");
                }
                seen_server_ccs = true;
                write_all(&mut inbound_w, &record).await?;
            }
            RECORD_TYPE_APPLICATION_DATA => {
                if !seen_server_ccs {
                    bail!("restls: TLS 1.3 encrypted server flight before CCS");
                }
                let mut record = record;
                framing::mask_server_auth(&secret, &server_random, &mut record);
                write_all(&mut inbound_w, &record).await?;
                break;
            }
            other => bail!("restls: unexpected TLS 1.3 server record type {other}"),
        }
    }

    let mut seen_client_ccs = false;
    let mut previous_client_record: Option<Vec<u8>> = None;
    let mut server_flight_records = 0u64;
    let mut client_handshake_records = 0u64;
    let mut target_read = Box::pin(read_tls_record_owned(target_r));
    let mut client_read = Box::pin(read_tls_record_owned(inbound.clone()));
    loop {
        tokio::select! {
            result = &mut target_read => {
                let record = result?;
                match record_type(&record)? {
                    RECORD_TYPE_APPLICATION_DATA => write_all(&mut inbound_w, &record).await?,
                    other => bail!("restls: unexpected TLS 1.3 server flight record type {other}"),
                }
                server_flight_records += 1;
                target_read = Box::pin(read_tls_record_owned(target.clone()));
            }
            result = &mut client_read => {
                let record = result?;
                match record_type(&record)? {
                    RECORD_TYPE_CHANGE_CIPHER_SPEC => {
                        if seen_client_ccs {
                            bail!("restls: duplicate TLS 1.3 client CCS");
                        }
                        if record != RESTLS_CCS_RECORD {
                            bail!("restls: incorrect TLS 1.3 client CCS");
                        }
                        seen_client_ccs = true;
                        write_all(&mut target_w, &record).await?;
                    }
                    RECORD_TYPE_APPLICATION_DATA => {
                        if let Some(prev) = &previous_client_record {
                            if is_first_restls_client_record(&secret, &server_random, &record, prev) {
                                let expected: u64 = if client_handshake_records > 1 { 4 } else { 3 };
                                return Ok((prev.clone(), record, server_flight_records.saturating_sub(expected)));
                            }
                        }
                        write_all(&mut target_w, &record).await?;
                        previous_client_record = Some(record);
                        client_handshake_records += 1;
                    }
                    other => bail!("restls: unexpected TLS 1.3 client record type {other}"),
                }
                client_read = Box::pin(read_tls_record_owned(inbound.clone()));
            }
        }
    }
}

fn is_first_restls_client_record(
    secret: &[u8; 32],
    server_random: &[u8; 32],
    record: &[u8],
    client_finished: &[u8],
) -> bool {
    let mut record = record.to_vec();
    framing::read_record(secret, server_random, false, 0, Some(client_finished), &mut record).is_ok()
}

/// `read_tls_record` needs `&mut R`; the `select!` loop above reassigns each future from a fresh
/// `SharedConn::clone()` every iteration, so the connection must be owned by the future itself
/// rather than borrowed from a local that would need to outlive it.
async fn read_tls_record_owned(mut conn: SharedConn) -> Result<Vec<u8>> {
    read_tls_record(&mut conn).await
}

/// Reassembles TLS handshake messages that may span multiple records (or share one record) back
/// into whole `msg_type||u24 len||body` messages.
#[derive(Default)]
struct HandshakeMessageReader {
    pending: Vec<u8>,
}

const MAX_HANDSHAKE: usize = 65536;

impl HandshakeMessageReader {
    /// `f` returns `false` to stop consuming further reassembled messages from this record (the
    /// callback return value).
    fn add_record(&mut self, record: &[u8], mut f: impl FnMut(&[u8]) -> bool) -> Result<()> {
        if record.first() != Some(&RECORD_TYPE_HANDSHAKE) || record.len() < RECORD_HEADER_LEN {
            bail!("restls: expected TLS handshake record");
        }
        let Some(payload) = record.get(RECORD_HEADER_LEN..) else {
            bail!("restls: expected TLS handshake record");
        };
        self.pending.extend_from_slice(payload);
        while self.pending.len() >= 4 {
            let Some([b1, b2, b3]) = self.pending.get(1..4) else {
                return Ok(());
            };
            let n = (usize::from(*b1) << 16) | (usize::from(*b2) << 8) | usize::from(*b3);
            if n > MAX_HANDSHAKE {
                bail!("restls: TLS handshake message length {n} exceeds maximum {MAX_HANDSHAKE}");
            }
            if self.pending.len() < 4 + n {
                return Ok(());
            }
            let msg: Vec<u8> = self.pending.drain(..4 + n).collect();
            if !f(&msg) {
                return Ok(());
            }
        }
        Ok(())
    }
}

fn process_handshake_record(
    messages: &mut HandshakeMessageReader,
    selected_curve: &mut u16,
    server_hello_done: &mut bool,
    record: &[u8],
) -> Result<()> {
    messages.add_record(record, |msg| {
        if let Some([msg_type, _, _, _, major, hi, lo]) = msg.get(..7) {
            if *msg_type == HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE && *major == 3 {
                *selected_curve = u16::from_be_bytes([*hi, *lo]);
            }
        }
        if msg.first() == Some(&HANDSHAKE_TYPE_SERVER_HELLO_DONE) {
            *server_hello_done = true;
            return false;
        }
        true
    })
}

fn mask_server_auth_tls12(secret: &[u8; 32], server_random: &[u8; 32], record: &mut [u8], is_tls12_gcm: bool) -> bool {
    let mut hasher = blake3::Hasher::new_keyed(secret);
    hasher.update(server_random);
    let mac = hasher.finalize();
    let mac = &mac.as_bytes()[..RESTLS_HANDSHAKE_MAC_LEN];

    let mut offset = RECORD_HEADER_LEN;
    let mut parrot_gcm = false;
    if is_tls12_gcm {
        if let Some(nonce) = u64_at(record, RECORD_HEADER_LEN) {
            if nonce == 0 {
                offset += 8;
                parrot_gcm = true;
            }
        }
    }
    if let Some(tail) = record.get_mut(offset..) {
        for (b, mask_byte) in tail.iter_mut().zip(mac) {
            *b ^= mask_byte;
        }
    }
    parrot_gcm
}

/// The big-endian `u64` at `pos`, or `None` when `data` is too short for one.
fn u64_at(data: &[u8], pos: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(pos..pos + 8)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// The TLS record payload length from its header, or `None` while the header is incomplete.
fn record_payload_len(raw: &[u8]) -> Option<usize> {
    let [hi, lo] = raw.get(RECORD_HEADER_LEN - 2..RECORD_HEADER_LEN)? else {
        return None;
    };
    Some((usize::from(*hi) << 8) | usize::from(*lo))
}

/// The `[start, end)` window that `layout[index..index + 1]` names inside the 32-byte session id.
fn layout_window(layout: &[usize], index: usize) -> Option<(usize, usize)> {
    Some((*layout.get(index)?, *layout.get(index + 1)?))
}

fn check_tls12_client_key_exchange(
    secret: &[u8; 32],
    session_id: &[u8; 32],
    has_session_ticket: bool,
    curve: u16,
    ckx_msg: &[u8],
) -> Result<()> {
    let curve_index = tls12_curve_index(curve).ok_or_else(|| anyhow!("restls: unsupported TLS 1.2 curve {curve}"))?;
    let ciphertext = ckx_msg.get(4..).ok_or_else(|| anyhow!("restls: malformed TLS 1.2 ClientKeyExchange"))?;
    let Some((&first, rest)) = ciphertext.split_first() else {
        bail!("restls: malformed TLS 1.2 ClientKeyExchange");
    };
    if usize::from(first) != rest.len() {
        bail!("restls: malformed TLS 1.2 ClientKeyExchange");
    }
    let layout: &[usize] =
        if has_session_ticket { &RESTLS12_CLIENT_AUTH_LAYOUT4 } else { &RESTLS12_CLIENT_AUTH_LAYOUT3 };
    let (start, end) = layout_window(layout, curve_index).ok_or_else(|| anyhow!("restls: bad TLS 1.2 client auth"))?;
    let actual = session_id.get(start..end).ok_or_else(|| anyhow!("restls: bad TLS 1.2 client auth"))?;

    let mut hasher = blake3::Hasher::new_keyed(secret);
    hasher.update(rest);
    let expect = hasher.finalize();
    if expect.as_bytes().get(..actual.len()) != Some(actual) {
        bail!("restls: bad TLS 1.2 client auth");
    }
    Ok(())
}

fn check_tls12_session_ticket(secret: &[u8; 32], session_id: &[u8; 32], session_ticket: &[u8]) -> Result<()> {
    if session_ticket.is_empty() {
        bail!("restls: TLS 1.2 resumption requires a session ticket");
    }
    let (start, end) = layout_window(&RESTLS12_CLIENT_AUTH_LAYOUT4, 3)
        .ok_or_else(|| anyhow!("restls: bad TLS 1.2 session ticket auth"))?;
    let actual = session_id.get(start..end).ok_or_else(|| anyhow!("restls: bad TLS 1.2 session ticket auth"))?;

    let mut hasher = blake3::Hasher::new_keyed(secret);
    hasher.update(session_ticket);
    let expect = hasher.finalize();
    if expect.as_bytes().get(..actual.len()) != Some(actual) {
        bail!("restls: bad TLS 1.2 session ticket auth");
    }
    Ok(())
}

/// Unlike the TLS 1.3 path, the TLS 1.2 client and server flights never overlap (the client only
/// sends its flight after the server's `ServerHelloDone`), so this whole family reads
/// sequentially — no `select!` or background reader is needed.
#[allow(clippy::too_many_arguments)]
async fn handshake_tls12(
    secret: [u8; 32],
    server_random: [u8; 32],
    is_tls12_gcm: bool,
    session_id: [u8; 32],
    session_ticket: Vec<u8>,
    inbound: SharedConn,
    target: SharedConn,
    first_server_record: Vec<u8>,
    tls12_authenticated: &AtomicBool,
    parrot_gcm: &AtomicBool,
) -> Result<Option<Vec<u8>>> {
    let has_ticket = !session_ticket.is_empty();
    let mut inbound_w = inbound.clone();
    let mut target_r = target.clone();

    let mut messages = HandshakeMessageReader::default();
    let mut selected_curve: u16 = 0;
    let mut server_hello_done = false;
    process_handshake_record(&mut messages, &mut selected_curve, &mut server_hello_done, &first_server_record)?;

    if server_hello_done {
        return finish_tls12_full_handshake(
            secret,
            server_random,
            is_tls12_gcm,
            session_id,
            has_ticket,
            inbound,
            target,
            selected_curve,
            tls12_authenticated,
            parrot_gcm,
        )
        .await;
    }

    loop {
        let record = read_tls_record(&mut target_r).await?;
        match record_type(&record)? {
            RECORD_TYPE_HANDSHAKE => {
                write_all(&mut inbound_w, &record).await?;
                process_handshake_record(&mut messages, &mut selected_curve, &mut server_hello_done, &record)?;
                if server_hello_done {
                    return finish_tls12_full_handshake(
                        secret,
                        server_random,
                        is_tls12_gcm,
                        session_id,
                        has_ticket,
                        inbound,
                        target,
                        selected_curve,
                        tls12_authenticated,
                        parrot_gcm,
                    )
                    .await;
                }
            }
            RECORD_TYPE_CHANGE_CIPHER_SPEC => {
                write_all(&mut inbound_w, &record).await?;
                check_tls12_session_ticket(&secret, &session_id, &session_ticket)?;
                tls12_authenticated.store(true, Ordering::SeqCst);
                return finish_tls12_resumed_handshake(
                    secret,
                    server_random,
                    is_tls12_gcm,
                    inbound,
                    target,
                    parrot_gcm,
                )
                .await;
            }
            other => {
                write_all(&mut inbound_w, &record).await?;
                bail!("restls: unexpected TLS 1.2 server record type before client flight: {other}");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_tls12_full_handshake(
    secret: [u8; 32],
    server_random: [u8; 32],
    is_tls12_gcm: bool,
    session_id: [u8; 32],
    has_session_ticket: bool,
    inbound: SharedConn,
    target: SharedConn,
    selected_curve: u16,
    tls12_authenticated: &AtomicBool,
    parrot_gcm: &AtomicBool,
) -> Result<Option<Vec<u8>>> {
    let mut inbound_r = inbound.clone();
    let mut target_w = target.clone();

    let mut seen_client_ccs = false;
    let mut messages = HandshakeMessageReader::default();
    loop {
        let record = read_tls_record(&mut inbound_r).await?;
        let rt = record_type(&record)?;

        let mut authentication_err: Option<anyhow::Error> = None;
        if rt == RECORD_TYPE_HANDSHAKE
            && !seen_client_ccs
            && !tls12_authenticated.load(Ordering::SeqCst)
            && selected_curve != 0
        {
            let parse_result = messages.add_record(&record, |msg| {
                if msg.first() != Some(&HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE) {
                    return true;
                }
                match check_tls12_client_key_exchange(&secret, &session_id, has_session_ticket, selected_curve, msg) {
                    Ok(()) => tls12_authenticated.store(true, Ordering::SeqCst),
                    Err(err) => authentication_err = Some(err),
                }
                false
            });
            if let Err(err) = parse_result {
                authentication_err = Some(err);
            }
        }

        let mut record_err: Option<anyhow::Error> = None;
        if rt == RECORD_TYPE_CHANGE_CIPHER_SPEC {
            if seen_client_ccs {
                record_err = Some(anyhow!("restls: duplicate TLS 1.2 client CCS"));
            } else if record != RESTLS_CCS_RECORD {
                record_err = Some(anyhow!("restls: incorrect TLS 1.2 client CCS"));
            } else {
                seen_client_ccs = true;
            }
        }

        write_all(&mut target_w, &record).await?;

        if let Some(err) = authentication_err {
            return Err(err);
        }
        if let Some(err) = record_err {
            return Err(err);
        }
        if seen_client_ccs && rt != RECORD_TYPE_CHANGE_CIPHER_SPEC {
            break;
        }
    }
    if !tls12_authenticated.load(Ordering::SeqCst) {
        bail!("restls: TLS 1.2 ClientKeyExchange was not authenticated");
    }

    let mut inbound_w = inbound.clone();
    let mut target_r = target.clone();
    loop {
        let record = read_tls_record(&mut target_r).await?;
        if record_type(&record)? == RECORD_TYPE_CHANGE_CIPHER_SPEC {
            write_all(&mut inbound_w, &record).await?;
            break;
        }
        if record_type(&record)? != RECORD_TYPE_HANDSHAKE {
            bail!("restls: expected TLS 1.2 server CCS");
        }
        write_all(&mut inbound_w, &record).await?;
    }

    let mut record = read_tls_record(&mut target_r).await?;
    if record_type(&record)? != RECORD_TYPE_HANDSHAKE {
        bail!("restls: expected TLS 1.2 ServerFinished");
    }
    parrot_gcm.store(mask_server_auth_tls12(&secret, &server_random, &mut record, is_tls12_gcm), Ordering::SeqCst);
    write_all(&mut inbound_w, &record).await?;
    Ok(None)
}

/// Completes the resumed TLS 1.2 handshake.
async fn finish_tls12_resumed_handshake(
    secret: [u8; 32],
    server_random: [u8; 32],
    is_tls12_gcm: bool,
    inbound: SharedConn,
    target: SharedConn,
    parrot_gcm: &AtomicBool,
) -> Result<Option<Vec<u8>>> {
    let mut target_r = target.clone();
    let mut inbound_w = inbound.clone();
    let mut record = read_tls_record(&mut target_r).await?;
    if record_type(&record)? != RECORD_TYPE_HANDSHAKE {
        bail!("restls: expected TLS 1.2 resumed ServerFinished");
    }
    parrot_gcm.store(mask_server_auth_tls12(&secret, &server_random, &mut record, is_tls12_gcm), Ordering::SeqCst);
    write_all(&mut inbound_w, &record).await?;

    let mut inbound_r = inbound.clone();
    let mut target_w = target.clone();
    let mut seen_client_ccs = false;
    loop {
        let record = read_tls_record(&mut inbound_r).await?;
        match record_type(&record)? {
            RECORD_TYPE_CHANGE_CIPHER_SPEC => {
                if seen_client_ccs {
                    bail!("restls: duplicate TLS 1.2 client CCS");
                }
                if record != RESTLS_CCS_RECORD {
                    bail!("restls: incorrect TLS 1.2 client CCS");
                }
                seen_client_ccs = true;
                write_all(&mut target_w, &record).await?;
            }
            RECORD_TYPE_HANDSHAKE => {
                if !seen_client_ccs {
                    bail!("restls: TLS 1.2 client Finished before CCS");
                }
                write_all(&mut target_w, &record).await?;
                return Ok(Some(record));
            }
            other => bail!("restls: unexpected TLS 1.2 client record type {other}"),
        }
    }
}

struct RestlsConn {
    inbound: SharedConn,
    secret: [u8; 32],
    server_random: [u8; 32],
    to_server_counter: u64,
    to_client_counter: u64,
    client_finished: Option<Vec<u8>>,
    script: Vec<crate::script::Line>,
    min_record_len: usize,
    is_tls12_gcm: bool,
    parrot_gcm: bool,

    read_buf: Vec<u8>,
    /// Delivery cursor into `read_buf`: bytes below it have already been handed to the caller.
    /// Small reads advance this instead of draining (and shifting) the unread suffix.
    read_offset: usize,
    pending_raw: Vec<u8>,

    write_buf: Vec<u8>,
    write_pos: usize,
    pending_drain: Mutex<Option<tokio::task::JoinHandle<io::Result<()>>>>,

    /// Set when the last record written to the client carried a scripted "answer with n bytes"
    /// command, cleared by the next client record the read path decodes. While set, `poll_write`
    /// parks instead of sending the next record.
    awaiting_client_record: bool,
    write_waker: Mutex<Option<Waker>>,
    drain_waker: Mutex<Option<Waker>>,
    read_drain_waker: Mutex<Option<Waker>>,
    closed: AtomicBool,

    /// The number of fake/filler records still owed to the client before the just-decrypted
    /// `pending_read_payload` may be handed to the `AsyncRead` caller.
    pending_fake_count: u32,
    pending_read_payload: Vec<u8>,
}

impl RestlsConn {
    #[allow(clippy::too_many_arguments)]
    fn new(
        inbound: SharedConn,
        secret: [u8; 32],
        server_random: [u8; 32],
        client_finished: Option<Vec<u8>>,
        script: Vec<crate::script::Line>,
        min_record_len: usize,
        is_tls12_gcm: bool,
        parrot_gcm: bool,
        pending_raw: Vec<u8>,
        to_client_counter: u64,
    ) -> Self {
        Self {
            inbound,
            secret,
            server_random,
            to_server_counter: 0,
            to_client_counter,
            client_finished,
            script,
            min_record_len,
            is_tls12_gcm,
            parrot_gcm,
            read_buf: Vec::new(),
            read_offset: 0,
            pending_raw,
            write_buf: Vec::new(),
            write_pos: 0,
            pending_drain: Mutex::new(None),
            awaiting_client_record: false,
            write_waker: Mutex::new(None),
            drain_waker: Mutex::new(None),
            read_drain_waker: Mutex::new(None),
            closed: AtomicBool::new(false),
            pending_fake_count: 0,
            pending_read_payload: Vec::new(),
        }
    }

    fn next_to_client_target(&self, data_len: usize) -> (usize, Command) {
        if let Some(line) = usize::try_from(self.to_client_counter).ok().and_then(|i| self.script.get(i)) {
            return (line.target_len.len(), line.command);
        }
        let floor = self.min_record_len + rand::rng().random_range(0..100);
        if data_len < floor {
            (floor, Command::Noop)
        } else {
            (data_len, Command::Noop)
        }
    }

    /// The sizing rule applied to `fake` (data-less keep-alive) records: pads up to
    /// `min_record_len` instead of the script's/jitter's (possibly near-zero) `target_len` so
    /// filler records aren't conspicuously tiny.
    fn build_fake_record(&mut self) -> Vec<u8> {
        let (raw_target, command) = self.next_to_client_target(0);
        let max_target_len = MAX_PLAINTEXT - RESTLS_APP_DATA_AUTH_HEADER_LEN - if self.parrot_gcm { 8 } else { 0 };
        let target_len = raw_target.min(max_target_len);
        let padding_len = if target_len < RESTLS_APP_DATA_AUTH_HEADER_LEN + self.min_record_len {
            self.min_record_len.min(max_target_len)
        } else {
            target_len
        };
        let record = framing::write_record_with_nonce(
            &self.secret,
            &self.server_random,
            true,
            self.to_client_counter,
            None,
            &[],
            padding_len,
            command,
            self.parrot_gcm,
        );
        self.to_client_counter += 1;
        record
    }

    fn poll_fill_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(payload_len) = record_payload_len(&self.pending_raw) {
                if self.pending_raw.len() >= RECORD_HEADER_LEN + payload_len {
                    return Poll::Ready(Ok(()));
                }
            }
            let mut scratch = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inbound).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "restls: connection closed",
                        )));
                    }
                    self.pending_raw.extend_from_slice(read_buf.filled());
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_pending_drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
        while self.write_pos < self.write_buf.len() {
            let tail = self.write_buf.get(self.write_pos..).unwrap_or_default();
            match Pin::new(&mut self.inbound).poll_write(cx, tail) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "restls: write returned 0")));
                }
                Poll::Ready(Ok(n)) => self.write_pos += n,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Drives the background drain a previous `poll_write` spawned after stopping mid-record:
    /// `Ready(Ok)` once it has finished (or when none was queued), `Pending` while it still runs.
    fn poll_pending_drain(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut pending = self.pending_drain.lock();
        let Some(drain) = pending.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(drain).poll(cx) {
            Poll::Ready(result) => {
                *pending = None;
                drop(pending);
                match result {
                    Ok(Ok(())) => Poll::Ready(Ok(())),
                    Ok(Err(err)) => Poll::Ready(Err(err)),
                    Err(err) => Poll::Ready(Err(io::Error::other(err))),
                }
            }
            Poll::Pending => {
                drop(pending);
                Poll::Pending
            }
        }
    }

    /// Wakes a writer parked in `poll_write` because the client-facing drain it waited on made
    /// progress.
    fn wake_drain_waker(&self) {
        let pending_waker = self.drain_waker.lock().take();
        if let Some(waker) = pending_waker {
            waker.wake();
        }
    }

    /// Flushes a record still queued to the client before a read is served, parking the read on
    /// `read_drain_waker` while that drain is in flight.
    fn poll_read_prelude(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_buf.is_empty() || self.pending_fake_count != 0 {
            return Poll::Ready(Ok(()));
        }
        match self.poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => {
                self.wake_drain_waker();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                self.wake_drain_waker();
                Poll::Ready(Err(err))
            }
            Poll::Pending => {
                *self.read_drain_waker.lock() = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// Sends the next owed filler record to the client.
    fn poll_emit_fake_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_buf.is_empty() {
            let record = self.build_fake_record();
            self.write_buf = record;
            self.write_pos = 0;
            self.pending_fake_count -= 1;
        }
        match self.poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => {
                self.wake_drain_waker();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                self.wake_drain_waker();
                Poll::Ready(Err(err))
            }
            Poll::Pending => {
                *self.read_drain_waker.lock() = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// Reads and decodes one Restls record from the client. `Ok(None)` is a `close_notify`
    /// alert: a clean end of stream, not a framing failure.
    fn poll_take_client_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<(Vec<u8>, Command)>>> {
        match self.poll_fill_record(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
        let Some(payload_len) = record_payload_len(&self.pending_raw) else {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "restls: incomplete record header")));
        };
        let end = RECORD_HEADER_LEN + payload_len;
        let Some(mut record) = self.pending_raw.get(..end).map(<[u8]>::to_vec) else {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "restls: incomplete record")));
        };
        self.pending_raw.drain(..end);

        if record.first() == Some(&RECORD_TYPE_ALERT) {
            return Poll::Ready(Ok(None));
        }

        let client_finished = self.client_finished.take();
        let result = framing::read_record_with_nonce(
            &self.secret,
            &self.server_random,
            false,
            self.to_server_counter,
            client_finished.as_deref(),
            &mut record,
            self.is_tls12_gcm,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        self.to_server_counter += 1;

        if self.awaiting_client_record {
            self.awaiting_client_record = false;
            let pending_waker = self.write_waker.lock().take();
            if let Some(waker) = pending_waker {
                waker.wake();
            }
        }

        let payload = record.get(result.data_offset..).unwrap_or_default();
        let data = payload.get(..result.data_len).unwrap_or_default().to_vec();
        Poll::Ready(Ok(Some((data, result.command))))
    }
}

impl RestlsConn {
    fn deliver_read_buf(&mut self, buf: &mut ReadBuf<'_>) {
        let unread = self.read_buf.len().saturating_sub(self.read_offset);
        let n = unread.min(buf.remaining());
        let end = self.read_offset + n;
        if let Some(bytes) = self.read_buf.get(self.read_offset..end) {
            buf.put_slice(bytes);
        }
        self.read_offset = end;
        if self.read_offset >= self.read_buf.len() {
            self.read_buf.clear();
            self.read_offset = 0;
        }
    }

    /// Drops already-delivered bytes before another payload is appended. The read loop always
    /// drains `read_buf` before decoding the next record or moving `pending_read_payload`, so
    /// this normally finds no prefix; it keeps the cursor a plain offset if a future caller
    /// appends while a payload is partly consumed.
    fn compact_read_buf(&mut self) {
        if self.read_offset == 0 {
            return;
        }
        if self.read_offset >= self.read_buf.len() {
            self.read_buf.clear();
        } else {
            self.read_buf.drain(..self.read_offset);
        }
        self.read_offset = 0;
    }
}

impl AsyncRead for RestlsConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        match this.poll_read_prelude(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
        loop {
            if this.read_offset < this.read_buf.len() {
                this.deliver_read_buf(buf);
                return Poll::Ready(Ok(()));
            }

            if this.pending_fake_count > 0 {
                match this.poll_emit_fake_record(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if !this.pending_read_payload.is_empty() {
                this.compact_read_buf();
                this.read_buf.append(&mut this.pending_read_payload);
                continue;
            }

            match this.poll_take_client_record(cx) {
                Poll::Ready(Ok(Some((data, command)))) => {
                    if let Command::Response(n) = command {
                        if n > 0 {
                            this.pending_fake_count = u32::from(n);
                            this.pending_read_payload = data;
                            continue;
                        }
                    }
                    this.compact_read_buf();
                    this.read_buf.extend_from_slice(&data);
                }
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for RestlsConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        match this.poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => {
                let pending_waker = this.read_drain_waker.lock().take();
                if let Some(waker) = pending_waker {
                    waker.wake();
                }
            }
            Poll::Ready(Err(err)) => {
                let pending_waker = this.read_drain_waker.lock().take();
                if let Some(waker) = pending_waker {
                    waker.wake();
                }
                return Poll::Ready(Err(err));
            }
            Poll::Pending => {
                *this.drain_waker.lock() = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.awaiting_client_record {
            *this.write_waker.lock() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let max_target_len = MAX_PLAINTEXT - RESTLS_APP_DATA_AUTH_HEADER_LEN - if this.parrot_gcm { 8 } else { 0 };
        let mut target = this.next_to_client_target(buf.len());
        while target.0 == 0 {
            let record = framing::write_record_with_nonce(
                &this.secret,
                &this.server_random,
                true,
                this.to_client_counter,
                None,
                &[],
                0,
                target.1,
                this.parrot_gcm,
            );
            this.to_client_counter += 1;
            if target.1.needs_interrupt() {
                this.awaiting_client_record = true;
            }
            this.write_buf = record;
            this.write_pos = 0;
            match this.poll_flush_write_buf(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    *this.drain_waker.lock() = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
            if this.awaiting_client_record {
                *this.write_waker.lock() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            target = this.next_to_client_target(buf.len());
        }
        let (target_len, command) = target;
        let target_len = target_len.min(max_target_len);
        let data_len = buf.len().min(target_len);
        let record = framing::write_record_with_nonce(
            &this.secret,
            &this.server_random,
            true,
            this.to_client_counter,
            None,
            buf.get(..data_len).unwrap_or_default(),
            target_len,
            command,
            this.parrot_gcm,
        );
        this.to_client_counter += 1;
        if command.needs_interrupt() {
            this.awaiting_client_record = true;
        }
        this.write_buf = record;
        this.write_pos = 0;
        match this.poll_flush_write_buf(cx) {
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(data_len)),
            Poll::Pending => {
                let remaining = this.write_buf.split_off(this.write_pos);
                this.write_buf.clear();
                this.write_pos = 0;
                let conn = this.inbound.clone();
                *this.pending_drain.lock() = Some(tokio::spawn(async move { conn.write_all(&remaining).await }));
                Poll::Ready(Ok(data_len))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        let result = this.poll_flush_write_buf(cx);
        if result.is_ready() {
            let pending_waker = this.read_drain_waker.lock().take();
            if let Some(waker) = pending_waker {
                waker.wake();
            }
        }
        match result {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inbound).poll_flush(cx),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                *this.drain_waker.lock() = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        let result = this.poll_flush_write_buf(cx);
        if result.is_ready() {
            let pending_waker = this.read_drain_waker.lock().take();
            if let Some(waker) = pending_waker {
                waker.wake();
            }
        }
        match result {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inbound).poll_shutdown(cx),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                *this.drain_waker.lock() = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl NetConn for RestlsConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inbound.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inbound.remote_addr()
    }

    fn close(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        if self.write_pos == self.write_buf.len() && self.pending_drain.lock().is_none() {
            if !self.closed.swap(true, Ordering::AcqRel) {
                let pending_waker = self.write_waker.lock().take();
                if let Some(waker) = pending_waker {
                    waker.wake();
                }
                let pending_waker = self.drain_waker.lock().take();
                if let Some(waker) = pending_waker {
                    waker.wake();
                }
                let pending_waker = self.read_drain_waker.lock().take();
                if let Some(waker) = pending_waker {
                    waker.wake();
                }
                return self.inbound.close();
            }
            return Ok(());
        }
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "restls: queued record requires async shutdown"))?;
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let pending_waker = self.write_waker.lock().take();
        if let Some(waker) = pending_waker {
            waker.wake();
        }
        let pending_waker = self.drain_waker.lock().take();
        if let Some(waker) = pending_waker {
            waker.wake();
        }
        let pending_waker = self.read_drain_waker.lock().take();
        if let Some(waker) = pending_waker {
            waker.wake();
        }
        let conn = self.inbound.clone();
        let pending = self.pending_drain.lock().take();
        let remaining = self.write_buf.get(self.write_pos..).unwrap_or_default().to_vec();
        handle.spawn(async move {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                if let Some(drain) = pending {
                    drain.await??;
                }
                conn.write_all(&remaining).await?;
                Ok::<(), io::Error>(())
            })
            .await;
            let _ = conn.close();
        });
        Ok(())
    }
}

impl Drop for RestlsConn {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Acquire)
            && (self.write_pos < self.write_buf.len() || self.pending_drain.lock().is_some())
        {
            let _ = self.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::HANDSHAKE_TYPE_CLIENT_HELLO;

    #[test]
    fn malformed_client_hello_extensions_return_error_without_panicking() {
        let mut hello = vec![HANDSHAKE_TYPE_CLIENT_HELLO, 0, 0, 0];
        hello.extend_from_slice(&[3, 3]);
        hello.extend_from_slice(&[0; 32]);
        hello.push(32);
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0, 2, 0x13, 1, 1, 0, 0, 5]);
        hello.extend_from_slice(&[0, 51, 0, 8, 0]);
        assert!(parse_client_hello_session_fields(&hello).is_err());
        assert!(check_tls13_client_auth(&[0; 32], &hello).is_err());
    }

    #[test]
    fn tls12_gcm_server_mask_preserves_explicit_nonce() {
        let secret = [13; 32];
        let random = [17; 32];
        let mut finished = vec![RECORD_TYPE_HANDSHAKE, 3, 3, 0, 40];
        finished.extend_from_slice(&[0; 8]);
        finished.extend_from_slice(&[21; 32]);
        let original = finished.clone();
        assert!(mask_server_auth_tls12(&secret, &random, &mut finished, true));
        assert_eq!(&finished[5..13], &[0; 8]);
        assert_ne!(&finished[13..], &original[13..]);
        assert_eq!(&finished[29..], &original[29..]);
        assert!(mask_server_auth_tls12(&secret, &random, &mut finished, true));
        assert_eq!(finished, original);
    }

    struct TinySocket(tokio::io::DuplexStream);

    impl AsyncRead for TinySocket {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TinySocket {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl NetConn for TinySocket {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Err(io::ErrorKind::AddrNotAvailable.into())
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Err(io::ErrorKind::AddrNotAvailable.into())
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingSocket {
        inner: TinySocket,
        failure: Arc<std::sync::atomic::AtomicU8>,
    }

    impl AsyncRead for FailingSocket {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for FailingSocket {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            match self.failure.load(Ordering::SeqCst) {
                1 => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                2 => Poll::Ready(Ok(0)),
                _ => Pin::new(&mut self.inner).poll_write(cx, buf),
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl NetConn for FailingSocket {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            self.inner.local_addr()
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            self.inner.remote_addr()
        }

        fn close(&self) -> io::Result<()> {
            self.inner.close()
        }
    }

    fn failing_connection(script: &str) -> (RestlsConn, tokio::io::DuplexStream, Arc<std::sync::atomic::AtomicU8>) {
        let (inner, peer) = tokio::io::duplex(1);
        let failure = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let conn = RestlsConn::new(
            SharedConn::from_boxed(Box::new(FailingSocket { inner: TinySocket(inner), failure: Arc::clone(&failure) })),
            [7; 32],
            [9; 32],
            None,
            crate::script::parse_record_script(script).unwrap(),
            15,
            false,
            false,
            Vec::new(),
            0,
        );
        (conn, peer, failure)
    }

    fn tiny_connection(script: &str) -> (RestlsConn, tokio::io::DuplexStream) {
        let (inner, peer) = tokio::io::duplex(1);
        let conn = RestlsConn::new(
            SharedConn::from_boxed(Box::new(TinySocket(inner))),
            [7; 32],
            [9; 32],
            None,
            crate::script::parse_record_script(script).unwrap(),
            15,
            false,
            false,
            Vec::new(),
            0,
        );
        (conn, peer)
    }

    /// A connection whose peer can queue a whole record before the read side is polled.
    fn delivery_connection() -> (RestlsConn, tokio::io::DuplexStream) {
        let (inner, peer) = tokio::io::duplex(16 * 1024);
        let conn = RestlsConn::new(
            SharedConn::from_boxed(Box::new(TinySocket(inner))),
            [7; 32],
            [9; 32],
            None,
            Vec::new(),
            15,
            false,
            false,
            Vec::new(),
            0,
        );
        (conn, peer)
    }

    async fn connection(script: &str, parrot_gcm: bool) -> (RestlsConn, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let conn = RestlsConn::new(
            SharedConn::from_boxed(Box::new(server)),
            [7; 32],
            [9; 32],
            None,
            crate::script::parse_record_script(script).unwrap(),
            15,
            parrot_gcm,
            parrot_gcm,
            Vec::new(),
            0,
        );
        (conn, client)
    }

    async fn next_record<R: AsyncRead + Unpin>(peer: &mut R, counter: u64, nonce: bool) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut header = [0; RECORD_HEADER_LEN];
        peer.read_exact(&mut header).await.unwrap();
        let size = u16::from_be_bytes([header[3], header[4]]) as usize;
        assert!(size <= MAX_PLAINTEXT, "oversized TLS record: {size}");
        let mut record = vec![0; RECORD_HEADER_LEN + size];
        record[..RECORD_HEADER_LEN].copy_from_slice(&header);
        peer.read_exact(&mut record[RECORD_HEADER_LEN..]).await.unwrap();
        let decoded =
            framing::read_record_with_nonce(&[7; 32], &[9; 32], true, counter, None, &mut record, nonce).unwrap();
        record[decoded.data_offset..decoded.data_offset + decoded.data_len].to_vec()
    }

    #[tokio::test]
    async fn large_server_write_splits_into_bounded_records_including_nonce() {
        use tokio::io::AsyncWriteExt;
        let (mut conn, mut peer) = connection("1", true).await;
        let payload = vec![42; 34_000];
        let sender = tokio::spawn(async move { conn.write_all(&payload).await.unwrap() });
        let mut received = Vec::new();
        let mut counter = 0;
        while received.len() < 34_000 {
            received.extend(next_record(&mut peer, counter, true).await);
            counter += 1;
        }
        assert_eq!(received, vec![42; 34_000]);
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn zero_target_record_does_not_drop_first_application_byte() {
        use tokio::io::AsyncWriteExt;
        let (mut conn, mut peer) = connection("0,250", false).await;
        let sender = tokio::spawn(async move { conn.write_all(b"hello").await.unwrap() });
        assert!(next_record(&mut peer, 0, false).await.is_empty());
        assert_eq!(next_record(&mut peer, 1, false).await, b"hello");
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn server_write_completes_under_backpressure_without_caller_flush() {
        use tokio::io::AsyncWriteExt;
        use tokio::time::{timeout, Duration};
        let (mut conn, mut peer) = tiny_connection("");
        let payload = vec![37; 300];
        let (written, received) = timeout(Duration::from_secs(2), async {
            tokio::join!(conn.write_all(&payload), next_record(&mut peer, 0, false))
        })
        .await
        .expect("writer stalled under backpressure");
        written.unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn close_drains_a_queued_partial_record() {
        use tokio::time::{timeout, Duration};
        let (mut conn, mut peer) = tiny_connection("");
        let payload = vec![77; 300];
        std::future::poll_fn(|cx| {
            assert!(matches!(Pin::new(&mut conn).poll_write(cx, &payload), Poll::Ready(Ok(300))));
            Poll::Ready(())
        })
        .await;
        conn.close().unwrap();
        let received = timeout(Duration::from_secs(2), next_record(&mut peer, 0, false))
            .await
            .expect("close truncated queued record");
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn zero_target_response_waits_for_client_record_without_consuming_payload() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let (conn, mut peer) = connection("0<1,250", false).await;
        let (mut reader, mut writer) = tokio::io::split(conn);
        let writing = tokio::spawn(async move { writer.write_all(b"hello").await.unwrap() });
        let mut header = [0; RECORD_HEADER_LEN];
        timeout(Duration::from_secs(2), peer.read_exact(&mut header)).await.unwrap().unwrap();
        let size = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut record = vec![0; RECORD_HEADER_LEN + size];
        record[..RECORD_HEADER_LEN].copy_from_slice(&header);
        peer.read_exact(&mut record[RECORD_HEADER_LEN..]).await.unwrap();
        let first = framing::read_record(&[7; 32], &[9; 32], true, 0, None, &mut record).unwrap();
        assert_eq!(first.data_len, 0);
        assert_eq!(first.command, Command::Response(1));
        assert!(!writing.is_finished());

        let reading = tokio::spawn(async move {
            let mut response = [0; 3];
            reader.read_exact(&mut response).await.unwrap();
            response
        });
        let response = framing::write_record(&[7; 32], &[9; 32], false, 0, None, b"ack", 3, Command::Noop);
        peer.write_all(&response).await.unwrap();
        assert_eq!(timeout(Duration::from_secs(2), reading).await.unwrap().unwrap(), *b"ack");
        assert_eq!(timeout(Duration::from_secs(2), next_record(&mut peer, 1, false)).await.unwrap(), b"hello");
        timeout(Duration::from_secs(2), writing).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn read_drains_pending_zero_target_response_under_backpressure() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};
        let (mut conn, mut peer) = tiny_connection("0<1");
        std::future::poll_fn(|cx| {
            assert!(matches!(Pin::new(&mut conn).poll_write(cx, b"hello"), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        let reader = tokio::spawn(async move {
            let mut payload = [0; 3];
            conn.read_exact(&mut payload).await.unwrap();
            payload
        });
        let mut header = [0; RECORD_HEADER_LEN];
        timeout(Duration::from_secs(2), peer.read_exact(&mut header))
            .await
            .expect("pending zero-target frame stalled")
            .unwrap();
        let size = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut record = vec![0; RECORD_HEADER_LEN + size];
        record[..RECORD_HEADER_LEN].copy_from_slice(&header);
        peer.read_exact(&mut record[RECORD_HEADER_LEN..]).await.unwrap();
        let first = framing::read_record(&[7; 32], &[9; 32], true, 0, None, &mut record).unwrap();
        assert_eq!(first.data_len, 0);
        assert_eq!(first.command, Command::Response(1));
        peer.write_all(&framing::write_record(&[7; 32], &[9; 32], false, 0, None, b"ack", 3, Command::Noop))
            .await
            .unwrap();
        assert_eq!(timeout(Duration::from_secs(2), reader).await.unwrap().unwrap(), *b"ack");
    }
    #[test]
    fn bare_ipv6_target_uses_default_tls_port() {
        assert_eq!(restls_host_port("::1"), "[::1]:443");
        assert_eq!(restls_host_port("[::1]:8443"), "[::1]:8443");
    }

    #[tokio::test]
    async fn cancelled_backpressured_write_accepts_each_subsequent_buffer_once() {
        use tokio::io::AsyncWriteExt;
        use tokio::time::{timeout, Duration};
        for next in [vec![37; 300], b"z".to_vec()] {
            let (mut conn, mut peer) = tiny_connection("");
            let first = vec![37; 300];
            let abandoned = vec![38; 300];
            assert_eq!(conn.write(&first).await.unwrap(), first.len());
            std::future::poll_fn(|cx| {
                assert!(matches!(Pin::new(&mut conn).poll_write(cx, &abandoned), Poll::Pending));
                Poll::Ready(())
            })
            .await;
            let expected = next.clone();
            let writer = tokio::spawn(async move {
                conn.write_all(&next).await.unwrap();
                conn.flush().await.unwrap();
            });
            assert_eq!(timeout(Duration::from_secs(2), next_record(&mut peer, 0, false)).await.unwrap(), first);
            let transmitted = timeout(Duration::from_secs(2), next_record(&mut peer, 1, false)).await.unwrap();
            assert_eq!(transmitted, expected);
            timeout(Duration::from_secs(2), writer).await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn reader_draining_frame_wakes_blocked_writer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};
        let (mut conn, mut peer) = tiny_connection("");
        let first = vec![39; 300];
        assert_eq!(conn.write(&first).await.unwrap(), first.len());
        let (mut reader, mut writer) = tokio::io::split(conn);
        let writing = tokio::spawn(async move { writer.write_all(b"next").await.unwrap() });
        let reading = tokio::spawn(async move {
            let mut incoming = [0; 1];
            reader.read_exact(&mut incoming).await
        });
        assert_eq!(timeout(Duration::from_secs(2), next_record(&mut peer, 0, false)).await.unwrap(), first);
        assert_eq!(timeout(Duration::from_secs(2), next_record(&mut peer, 1, false)).await.unwrap(), b"next");
        timeout(Duration::from_secs(2), writing).await.unwrap().unwrap();
        reading.abort();
    }

    #[tokio::test]
    async fn reader_draining_zero_target_record_wakes_original_writer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};
        let (conn, mut peer) = tiny_connection("0,250");
        let (mut reader, mut writer) = tokio::io::split(conn);
        let (first_poll, seen) = tokio::sync::oneshot::channel();
        let writing = tokio::spawn(async move {
            let mut first_poll = Some(first_poll);
            let written = std::future::poll_fn(|cx| {
                let result = Pin::new(&mut writer).poll_write(cx, b"hello");
                if let Some(signal) = first_poll.take() {
                    assert!(matches!(result, Poll::Pending));
                    signal.send(()).unwrap();
                }
                result
            })
            .await
            .unwrap();
            assert_eq!(written, 5);
            writer.flush().await.unwrap();
        });
        timeout(Duration::from_secs(2), seen).await.unwrap().unwrap();
        let (reader_polled, reader_seen) = tokio::sync::oneshot::channel();
        let reading = tokio::spawn(async move {
            let mut incoming = [0; 1];
            let mut reader_polled = Some(reader_polled);
            std::future::poll_fn(|cx| {
                let mut buffer = ReadBuf::new(&mut incoming);
                let result = Pin::new(&mut reader).poll_read(cx, &mut buffer);
                if let Some(signal) = reader_polled.take() {
                    assert!(matches!(result, Poll::Pending));
                    signal.send(()).unwrap();
                }
                result
            })
            .await?;
            reader.read_exact(&mut incoming).await
        });
        timeout(Duration::from_secs(2), reader_seen).await.unwrap().unwrap();
        assert!(timeout(Duration::from_secs(2), next_record(&mut peer, 0, false)).await.unwrap().is_empty());
        assert_eq!(timeout(Duration::from_secs(2), next_record(&mut peer, 1, false)).await.unwrap(), b"hello");
        timeout(Duration::from_secs(2), writing).await.unwrap().unwrap();
        reading.abort();
    }

    #[tokio::test]
    async fn flush_or_shutdown_wakes_reader_parked_on_shared_record() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};
        for shutdown in [false, true] {
            let (conn, mut peer) = tiny_connection("0,250");
            let (mut reader, mut writer) = tokio::io::split(conn);
            std::future::poll_fn(|cx| {
                assert!(matches!(Pin::new(&mut writer).poll_write(cx, b"hello"), Poll::Pending));
                Poll::Ready(())
            })
            .await;
            let (polled, seen) = tokio::sync::oneshot::channel();
            let reading = tokio::spawn(async move {
                let mut payload = [0; 3];
                let mut polled = Some(polled);
                let mut read = Box::pin(reader.read_exact(&mut payload));
                std::future::poll_fn(|cx| {
                    let result = read.as_mut().poll(cx);
                    if let Some(signal) = polled.take() {
                        assert!(matches!(result, Poll::Pending));
                        signal.send(()).unwrap();
                    }
                    result
                })
                .await
                .unwrap();
                payload
            });
            timeout(Duration::from_secs(2), seen).await.unwrap().unwrap();
            let (flushing, flushed) = tokio::sync::oneshot::channel();
            let draining = tokio::spawn(async move {
                let mut flushing = Some(flushing);
                std::future::poll_fn(|cx| {
                    let result = if shutdown {
                        Pin::new(&mut writer).poll_shutdown(cx)
                    } else {
                        Pin::new(&mut writer).poll_flush(cx)
                    };
                    if let Some(signal) = flushing.take() {
                        assert!(matches!(result, Poll::Pending));
                        signal.send(()).unwrap();
                    }
                    result
                })
                .await
                .unwrap();
            });
            timeout(Duration::from_secs(2), flushed).await.unwrap().unwrap();
            assert!(timeout(Duration::from_secs(2), next_record(&mut peer, 0, false)).await.unwrap().is_empty());
            timeout(Duration::from_secs(2), draining).await.unwrap().unwrap();
            peer.write_all(&framing::write_record(&[7; 32], &[9; 32], false, 0, None, b"ack", 3, Command::Noop))
                .await
                .unwrap();
            assert_eq!(
                timeout(Duration::from_secs(2), reading).await.expect("reader missed shared-drain wake").unwrap(),
                *b"ack"
            );
        }
    }

    async fn reader_draining_frame_wakes_parked_drain(shutdown: bool) {
        use tokio::time::{timeout, Duration};

        let (conn, mut peer) = tiny_connection("0,250");
        let (mut reader, mut writer) = tokio::io::split(conn);
        std::future::poll_fn(|cx| {
            assert!(matches!(Pin::new(&mut writer).poll_write(cx, b"hello"), Poll::Pending));
            Poll::Ready(())
        })
        .await;

        let (writer_polled, writer_seen) = tokio::sync::oneshot::channel();
        let draining = tokio::spawn(async move {
            let mut writer_polled = Some(writer_polled);
            std::future::poll_fn(|cx| {
                let result = if shutdown {
                    Pin::new(&mut writer).poll_shutdown(cx)
                } else {
                    Pin::new(&mut writer).poll_flush(cx)
                };
                if let Some(signal) = writer_polled.take() {
                    assert!(matches!(result, Poll::Pending));
                    signal.send(()).unwrap();
                }
                result
            })
            .await
            .unwrap();
        });
        timeout(Duration::from_secs(2), writer_seen).await.unwrap().unwrap();

        let (reader_polled, reader_seen) = tokio::sync::oneshot::channel();
        let reading = tokio::spawn(async move {
            let mut reader_polled = Some(reader_polled);
            std::future::poll_fn(|cx| {
                let mut byte = [0];
                let mut buffer = ReadBuf::new(&mut byte);
                let result = Pin::new(&mut reader).poll_read(cx, &mut buffer);
                if let Some(signal) = reader_polled.take() {
                    assert!(matches!(result, Poll::Pending));
                    signal.send(()).unwrap();
                }
                result
            })
            .await
        });
        timeout(Duration::from_secs(2), reader_seen).await.unwrap().unwrap();
        assert!(timeout(Duration::from_secs(2), next_record(&mut peer, 0, false)).await.unwrap().is_empty());
        timeout(Duration::from_secs(2), draining)
            .await
            .expect("reader drained frame but flush/shutdown task remained parked")
            .unwrap();
        reading.abort();
    }

    #[tokio::test]
    async fn reader_write_error_wakes_parked_flush_or_shutdown() {
        use tokio::time::{timeout, Duration};

        for shutdown in [false, true] {
            for failure_kind in [1, 2] {
                let (conn, _peer, failure) = failing_connection("0,250");
                let (mut reader, mut writer) = tokio::io::split(conn);
                std::future::poll_fn(|cx| {
                    assert!(matches!(Pin::new(&mut writer).poll_write(cx, b"hello"), Poll::Pending));
                    Poll::Ready(())
                })
                .await;

                let (writer_polled, writer_seen) = tokio::sync::oneshot::channel();
                let draining = tokio::spawn(async move {
                    let mut writer_polled = Some(writer_polled);
                    std::future::poll_fn(|cx| {
                        let result = if shutdown {
                            Pin::new(&mut writer).poll_shutdown(cx)
                        } else {
                            Pin::new(&mut writer).poll_flush(cx)
                        };
                        if let Some(signal) = writer_polled.take() {
                            assert!(matches!(result, Poll::Pending));
                            signal.send(()).unwrap();
                        }
                        result
                    })
                    .await
                    .unwrap_err()
                    .kind()
                });
                timeout(Duration::from_secs(2), writer_seen).await.unwrap().unwrap();
                failure.store(failure_kind, Ordering::SeqCst);

                let reader_error = std::future::poll_fn(|cx| {
                    let mut byte = [0];
                    let mut buffer = ReadBuf::new(&mut byte);
                    Pin::new(&mut reader).poll_read(cx, &mut buffer)
                })
                .await
                .unwrap_err();
                let expected = if failure_kind == 1 { io::ErrorKind::BrokenPipe } else { io::ErrorKind::WriteZero };
                assert_eq!(reader_error.kind(), expected);
                assert_eq!(
                    timeout(Duration::from_secs(2), draining).await.expect("reader error left writer parked").unwrap(),
                    expected
                );
            }
        }
    }

    #[tokio::test]
    async fn reader_draining_frame_wakes_parked_flush() {
        reader_draining_frame_wakes_parked_drain(false).await;
    }

    #[tokio::test]
    async fn reader_draining_frame_wakes_parked_shutdown() {
        reader_draining_frame_wakes_parked_drain(true).await;
    }

    #[tokio::test]
    async fn writer_flush_does_not_duplicate_backpressured_fake_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};
        let (conn, mut peer) = tiny_connection("250");
        let (mut reader, mut writer) = tokio::io::split(conn);
        let (polled, seen) = tokio::sync::oneshot::channel();
        let reading = tokio::spawn(async move {
            let mut payload = [0; 3];
            let mut polled = Some(polled);
            let mut read = Box::pin(reader.read_exact(&mut payload));
            std::future::poll_fn(|cx| {
                let result = read.as_mut().poll(cx);
                if let Some(signal) = polled.take() {
                    assert!(matches!(result, Poll::Pending));
                    signal.send(()).unwrap();
                }
                result
            })
            .await
            .unwrap();
            payload
        });
        peer.write_all(&framing::write_record(&[7; 32], &[9; 32], false, 0, None, b"ack", 3, Command::Response(1)))
            .await
            .unwrap();
        timeout(Duration::from_secs(2), seen).await.unwrap().unwrap();
        let draining = tokio::spawn(async move { writer.flush().await.unwrap() });
        assert!(timeout(Duration::from_secs(2), next_record(&mut peer, 0, false)).await.unwrap().is_empty());
        timeout(Duration::from_secs(2), draining).await.unwrap().unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), reading).await.expect("duplicate fake record blocked payload").unwrap(),
            *b"ack"
        );
    }

    #[tokio::test]
    async fn failed_background_drain_does_not_panic_on_subsequent_flush_or_close() {
        use tokio::io::AsyncWriteExt;
        use tokio::time::{timeout, Duration};

        let (mut conn, peer) = tiny_connection("");
        assert_eq!(conn.write(&vec![57; 300]).await.unwrap(), 300);
        drop(peer);
        timeout(Duration::from_secs(2), async {
            while !conn.pending_drain.lock().as_ref().unwrap().is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background drain did not fail after peer closed");
        assert!(conn.flush().await.is_err());
        timeout(Duration::from_secs(2), conn.flush()).await.expect("second flush stalled after failed drain").unwrap();
        conn.close().unwrap();
    }

    #[tokio::test]
    async fn cancelled_background_drain_does_not_panic_on_subsequent_flush() {
        use tokio::io::AsyncWriteExt;
        use tokio::time::{timeout, Duration};

        let (mut conn, _peer) = tiny_connection("");
        let drain = tokio::spawn(std::future::pending::<io::Result<()>>());
        drain.abort();
        *conn.pending_drain.lock() = Some(drain);
        assert!(timeout(Duration::from_secs(2), conn.flush()).await.unwrap().is_err());
        timeout(Duration::from_secs(2), conn.flush())
            .await
            .expect("second flush stalled after cancelled drain")
            .unwrap();
    }

    #[tokio::test]
    async fn close_wakes_write_waiting_for_scripted_client_response() {
        use tokio::io::AsyncWriteExt;
        use tokio::time::{timeout, Duration};

        let (conn, mut peer) = connection("1<1,1", false).await;
        let conn = SharedConn::from_boxed(Box::new(conn));
        let mut writer = conn.clone();
        assert_eq!(writer.write(b"a").await.unwrap(), 1);
        assert_eq!(timeout(Duration::from_secs(2), next_record(&mut peer, 0, false)).await.unwrap(), b"a");

        let (polled, seen) = tokio::sync::oneshot::channel();
        let writing = tokio::spawn(async move {
            let mut polled = Some(polled);
            std::future::poll_fn(|cx| {
                let result = Pin::new(&mut writer).poll_write(cx, b"b");
                if let Some(signal) = polled.take() {
                    assert!(matches!(result, Poll::Pending));
                    signal.send(()).unwrap();
                }
                result
            })
            .await
            .unwrap_err()
            .kind()
        });
        timeout(Duration::from_secs(2), seen).await.unwrap().unwrap();
        conn.close().unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), writing).await.expect("close left scripted writer parked").unwrap(),
            io::ErrorKind::NotConnected
        );
    }

    #[tokio::test]
    async fn close_wakes_split_drain_waiters_when_clone_steals_pending_drain() {
        use tokio::io::AsyncWriteExt;
        use tokio::time::{timeout, Duration};

        for operation in 0..3 {
            let (mut conn, _peer) = tiny_connection("");
            assert_eq!(conn.write(&vec![57; 300]).await.unwrap(), 300);
            conn.pending_fake_count = 1;
            let conn = SharedConn::from_boxed(Box::new(conn));
            let closer = conn.clone();
            let (mut reader, mut writer) = tokio::io::split(conn);

            let (writer_polled, writer_seen) = tokio::sync::oneshot::channel();
            let draining = tokio::spawn(async move {
                let mut writer_polled = Some(writer_polled);
                std::future::poll_fn(|cx| {
                    let result = match operation {
                        0 => Pin::new(&mut writer).poll_write(cx, b"more").map(|result| result.map(|_| ())),
                        1 => Pin::new(&mut writer).poll_flush(cx),
                        _ => Pin::new(&mut writer).poll_shutdown(cx),
                    };
                    if let Some(signal) = writer_polled.take() {
                        assert!(matches!(result, Poll::Pending));
                        signal.send(()).unwrap();
                    }
                    result
                })
                .await
                .unwrap_err()
                .kind()
            });
            timeout(Duration::from_secs(2), writer_seen).await.unwrap().unwrap();

            let (reader_polled, reader_seen) = tokio::sync::oneshot::channel();
            let reading = tokio::spawn(async move {
                let mut reader_polled = Some(reader_polled);
                std::future::poll_fn(|cx| {
                    let mut byte = [0];
                    let mut buffer = ReadBuf::new(&mut byte);
                    let result = Pin::new(&mut reader).poll_read(cx, &mut buffer);
                    if let Some(signal) = reader_polled.take() {
                        assert!(matches!(result, Poll::Pending));
                        signal.send(()).unwrap();
                    }
                    result
                })
                .await
                .unwrap_err()
                .kind()
            });
            timeout(Duration::from_secs(2), reader_seen).await.unwrap().unwrap();
            closer.close().unwrap();
            closer.close().unwrap();
            assert_eq!(
                timeout(Duration::from_secs(2), draining)
                    .await
                    .expect("close left split write/flush/shutdown parked")
                    .unwrap(),
                io::ErrorKind::NotConnected
            );
            assert_eq!(
                timeout(Duration::from_secs(2), reading).await.expect("close left split reader parked").unwrap(),
                io::ErrorKind::NotConnected
            );
        }
    }

    #[tokio::test]
    async fn close_does_not_replay_queued_record() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};
        let (mut conn, mut peer) = connection("", false).await;
        let payload = vec![71; 300];
        conn.write_buf = framing::write_record(&[7; 32], &[9; 32], true, 0, None, &payload, 300, Command::Noop);
        conn.close().unwrap();
        conn.close().unwrap();
        assert!(Pin::new(&mut conn).write(b"unexpected").await.is_err());
        let mut rest = vec![0; conn.write_buf.len()];
        timeout(Duration::from_secs(2), peer.read_exact(&mut rest)).await.unwrap().unwrap();
        let mut extra = [0; 1];
        assert_eq!(timeout(Duration::from_secs(2), peer.read(&mut extra)).await.unwrap().unwrap(), 0);
    }
    #[tokio::test]
    async fn close_under_socket_backpressure_finishes_within_bound() {
        use tokio::io::AsyncReadExt;
        use tokio::time::{timeout, Duration};
        let (mut conn, mut peer) = connection("", false).await;
        let filler = [27; 16384];
        let filled = std::future::poll_fn(|cx| {
            for _ in 0..2048 {
                match Pin::new(&mut conn.inbound).poll_write(cx, &filler) {
                    Poll::Ready(Ok(0)) => panic!("socket closed while filling send buffer"),
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(err)) => panic!("socket fill failed: {err}"),
                    Poll::Pending => return Poll::Ready(true),
                }
            }
            Poll::Ready(false)
        })
        .await;
        assert!(filled, "socket did not reach backpressure");
        conn.write_buf = framing::write_record(&[7; 32], &[9; 32], true, 0, None, b"last", 20, Command::Noop);
        conn.close().unwrap();
        conn.close().unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let mut received = Vec::new();
        timeout(Duration::from_secs(3), peer.read_to_end(&mut received))
            .await
            .expect("close left the socket open after bounded drain")
            .unwrap();
        assert!(!received.is_empty());
    }
    #[tokio::test]
    async fn malformed_target_initial_response_is_relayed_verbatim() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let incoming = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let config = ServerConfig {
            server_hostname: "example.org".to_owned(),
            password: "test".to_owned(),
            restls_script: "1".to_owned(),
            min_record_len: 15,
            rate_limit: 0,
            dial: Arc::new(move |_| {
                Box::pin(async move {
                    let conn: Box<dyn NetConn> = Box::new(tokio::net::TcpStream::connect(target_addr).await?);
                    Ok(conn)
                })
            }),
        };
        let mut client = tokio::net::TcpStream::connect(incoming.local_addr().unwrap()).await.unwrap();
        let (inbound, _) = incoming.accept().await.unwrap();
        let server = tokio::spawn(async move { restls_server(Box::new(inbound), &config).await });
        let (mut disguise, _) = target.accept().await.unwrap();

        let mut body = vec![3, 3];
        body.extend_from_slice(&[1; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, 0]);
        let mut hello = vec![1, 0, 0, body.len() as u8];
        hello.extend_from_slice(&body);
        let mut record = vec![22, 3, 3, 0, hello.len() as u8];
        record.extend_from_slice(&hello);
        client.write_all(&record).await.unwrap();
        let mut received = vec![0; record.len()];
        disguise.read_exact(&mut received).await.unwrap();
        assert_eq!(received, record);

        disguise.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await.unwrap();
        let mut response = vec![0; 28];
        timeout(Duration::from_secs(2), client.read_exact(&mut response)).await.unwrap().unwrap();
        assert_eq!(&response, b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        drop(disguise);
        drop(client);
        assert!(timeout(Duration::from_secs(2), server).await.unwrap().unwrap().is_err());
    }

    #[tokio::test]
    async fn unsupported_tls_version_relays_probe_and_disguise_response_without_payload() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let incoming = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let config = ServerConfig {
            server_hostname: "example.org".to_owned(),
            password: "test".to_owned(),
            restls_script: "1".to_owned(),
            min_record_len: 15,
            rate_limit: 0,
            dial: Arc::new(move |_| {
                Box::pin(async move {
                    let conn: Box<dyn NetConn> = Box::new(tokio::net::TcpStream::connect(target_addr).await?);
                    Ok(conn)
                })
            }),
        };
        let mut client = tokio::net::TcpStream::connect(incoming.local_addr().unwrap()).await.unwrap();
        let (inbound, _) = incoming.accept().await.unwrap();
        let server = tokio::spawn(async move { restls_server(Box::new(inbound), &config).await });
        let (mut disguise, _) = timeout(Duration::from_secs(2), target.accept()).await.unwrap().unwrap();

        let probe = [0x16, 0xff, 0xff, 0, 100];
        client.write_all(&probe).await.unwrap();
        let mut forwarded = [0; 5];
        timeout(Duration::from_secs(2), disguise.read_exact(&mut forwarded))
            .await
            .expect("invalid TLS version stalled before forwarding header")
            .unwrap();
        assert_eq!(forwarded, probe);

        disguise.write_all(b"rejected").await.unwrap();
        let mut response = [0; 8];
        timeout(Duration::from_secs(2), client.read_exact(&mut response)).await.unwrap().unwrap();
        assert_eq!(&response, b"rejected");
        drop(disguise);
        drop(client);
        assert!(timeout(Duration::from_secs(2), server).await.unwrap().unwrap().is_err());
    }

    /// Small caller reads must deliver each record's payload exactly once, in order, with the
    /// next record starting at its own payload.
    #[tokio::test]
    async fn small_reads_deliver_records_in_order() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for chunk in [1usize, 64, 1024] {
            let first: Vec<u8> = (0..4 * 1024).map(|i| (i % 251) as u8).collect();
            let second: Vec<u8> = (0..3 * 1024).map(|i| (i % 239) as u8).collect();
            let (mut conn, mut peer) = delivery_connection();
            peer.write_all(&framing::write_record(
                &[7; 32],
                &[9; 32],
                false,
                0,
                None,
                &first,
                first.len(),
                Command::Noop,
            ))
            .await
            .unwrap();
            peer.write_all(&framing::write_record(
                &[7; 32],
                &[9; 32],
                false,
                1,
                None,
                &second,
                second.len(),
                Command::Noop,
            ))
            .await
            .unwrap();

            let mut out = vec![0u8; chunk];
            let mut got = Vec::with_capacity(first.len() + second.len());
            while got.len() < first.len() + second.len() {
                let n = conn.read(&mut out).await.expect("small read must deliver payload");
                assert!(n > 0, "delivery stalled at {} bytes with chunk {chunk}", got.len());
                got.extend_from_slice(&out[..n]);
            }
            let mut expected = first;
            expected.extend_from_slice(&second);
            assert_eq!(got, expected, "chunk size {chunk}");
        }
    }

    /// The record MAC is checked before anything is queued for delivery: a corrupted record is
    /// an error, never plaintext.
    #[tokio::test]
    async fn a_record_with_a_bad_mac_delivers_no_plaintext() {
        use tokio::io::AsyncWriteExt;

        let (mut conn, mut peer) = delivery_connection();
        let mut record = framing::write_record(&[7; 32], &[9; 32], false, 0, None, b"authentic", 9, Command::Noop);
        if let Some(last) = record.last_mut() {
            *last ^= 1;
        }
        peer.write_all(&record).await.unwrap();

        let mut out = [0u8; 32];
        let mut read_buf = ReadBuf::new(&mut out);
        let result = std::future::poll_fn(|cx| Pin::new(&mut conn).poll_read(cx, &mut read_buf)).await;
        let err = result.expect_err("a corrupted record must fail the read");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(read_buf.filled().is_empty(), "a rejected record exposed plaintext");
    }

    /// Compaction must keep only the undelivered suffix, so an append after a partial read
    /// cannot replay already-delivered bytes.
    #[tokio::test]
    async fn compacting_a_partially_consumed_payload_keeps_the_unread_suffix() {
        let (mut conn, _peer) = delivery_connection();
        conn.read_buf = vec![1, 2, 3, 4];
        conn.read_offset = 2;
        conn.compact_read_buf();
        assert_eq!(conn.read_buf, [3, 4]);
        assert_eq!(conn.read_offset, 0);
    }
}

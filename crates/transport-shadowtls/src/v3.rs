//! Server side only. The client's TLS-library session-id hook has no rustls equivalent
//! (rustls/rustls#1932), so the client stays gated at `check_version` in `client.rs` and neither
//! type is present here.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use hmac::digest::Reset;
use hmac::Mac as _;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use murmur_common_net::io::{old_addr_to_socket_addr, ExtendedStream, Stream as NetStream};
use murmur_std_compat::net::Conn as NetConn;

use super::protocol::{
    read_frame, ALERT, APPLICATION_DATA, CLIENT_HELLO, HANDSHAKE, HMAC_SIZE, MAX_TLS_PLAINTEXT,
    SESSION_ID_LENGTH_INDEX, TLS_HEADER_SIZE, TLS_HMAC_HEADER_SIZE, TLS_RANDOM_SIZE, TLS_SESSION_ID_SIZE,
};
use super::server::User;
use super::v2::{new_hmac_sha1, HmacSha1};

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[expect(
    clippy::indexing_slicing,
    reason = "SHA-1's digest is always 20 bytes, so its first `HMAC_SIZE` (4) bytes are always present"
)]
pub(crate) fn hmac_sum4(mac: &HmacSha1) -> [u8; HMAC_SIZE] {
    let full = mac.clone().finalize().into_bytes();
    let mut out = [0u8; HMAC_SIZE];
    out.copy_from_slice(&full[..HMAC_SIZE]);
    out
}

pub(crate) fn hmac_reset(mac: &mut HmacSha1, server_random: &[u8], side: u8) {
    Reset::reset(mac);
    mac.update(server_random);
    mac.update(&[side]);
}

pub(crate) fn kdf(password: &str, server_random: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(server_random);
    hasher.finalize().into()
}

pub(crate) fn xor_slice(data: &mut [u8], key: &[u8]) {
    for (byte, key_byte) in data.iter_mut().zip(key.iter().cycle()) {
        *byte ^= *key_byte;
    }
}

fn verify_application_data(frame: &[u8], h: &mut HmacSha1, update: bool) -> bool {
    let [APPLICATION_DATA, 3, 3, ..] = *frame else {
        return false;
    };
    if frame.len() < TLS_HMAC_HEADER_SIZE {
        return false;
    }
    let Some(payload) = frame.get(TLS_HMAC_HEADER_SIZE..) else {
        return false;
    };
    let Some(mac) = frame.get(TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE) else {
        return false;
    };
    h.update(payload);
    let sum = hmac_sum4(h);
    if update {
        h.update(&sum);
    }
    constant_time_eq(mac, &sum)
}

/// Verifies a ClientHello. Iterates `users` in configuration order and returns the first whose
/// password's HMAC matches the zeroed-session-id digest embedded by the client.
pub(crate) fn verify_client_hello<'a>(frame: &[u8], users: &'a [User]) -> Result<&'a User> {
    const HMAC_INDEX: usize = SESSION_ID_LENGTH_INDEX + 1 + TLS_SESSION_ID_SIZE - HMAC_SIZE;
    const MIN_LENGTH: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE + 1 + TLS_SESSION_ID_SIZE;
    if frame.len() < MIN_LENGTH {
        return Err(anyhow!("unexpected EOF"));
    }
    if frame.first() != Some(&HANDSHAKE) || frame.get(TLS_HEADER_SIZE) != Some(&CLIENT_HELLO) {
        return Err(anyhow!("shadow-tls: unexpected ClientHello record"));
    }
    let Some(&session_id_length) = frame.get(SESSION_ID_LENGTH_INDEX) else {
        return Err(anyhow!("shadow-tls: unexpected session ID length"));
    };
    if usize::from(session_id_length) != TLS_SESSION_ID_SIZE {
        return Err(anyhow!("shadow-tls: unexpected session ID length"));
    }
    let Some(prefix) = frame.get(TLS_HEADER_SIZE..HMAC_INDEX) else {
        return Err(anyhow!("unexpected EOF"));
    };
    let Some(suffix) = frame.get(HMAC_INDEX + HMAC_SIZE..) else {
        return Err(anyhow!("unexpected EOF"));
    };
    let Some(mac) = frame.get(HMAC_INDEX..HMAC_INDEX + HMAC_SIZE) else {
        return Err(anyhow!("unexpected EOF"));
    };
    for user in users {
        let mut h = new_hmac_sha1(&user.password);
        h.update(prefix);
        h.update(&[0, 0, 0, 0]);
        h.update(suffix);
        let sum = hmac_sum4(&h);
        if constant_time_eq(mac, &sum) {
            return Ok(user);
        }
    }
    Err(anyhow!("shadow-tls: ClientHello HMAC mismatch"))
}

/// Forwards handshake records read from `conn` to
/// `handshake_conn` unmodified until an application-data record's HMAC matches `hmac_verify`
/// (reset to `serverRandom`+`'C'` before each attempt); that record's payload is the client's
/// leftover proxied request and ends the relay.
pub(crate) async fn copy_by_frame_until_hmac_matches<R, W>(
    conn: &mut R,
    handshake_conn: &mut W,
    mut hmac_verify: HmacSha1,
    server_random: &[u8],
) -> io::Result<(Vec<u8>, HmacSha1)>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    loop {
        let frame = read_frame(conn)
            .await
            .map_err(|err| io::Error::new(err.kind(), format!("shadow-tls: read client record: {err}")))?;
        if frame.len() > TLS_HMAC_HEADER_SIZE && frame.first() == Some(&APPLICATION_DATA) {
            let (header, payload) = frame.split_at(TLS_HMAC_HEADER_SIZE);
            let (_, mac) = header.split_at(TLS_HEADER_SIZE);
            hmac_reset(&mut hmac_verify, server_random, b'C');
            hmac_verify.update(payload);
            let sum = hmac_sum4(&hmac_verify);
            if constant_time_eq(&sum, mac) {
                hmac_reset(&mut hmac_verify, server_random, b'C');
                hmac_verify.update(payload);
                hmac_verify.update(mac);
                return Ok((payload.to_vec(), hmac_verify));
            }
        }
        handshake_conn
            .write_all(&frame)
            .await
            .map_err(|err| io::Error::new(err.kind(), format!("shadow-tls: write client record: {err}")))?;
    }
}

/// Forwards non-application-data records from `conn` to
/// `handshake_conn` unmodified; application-data records are XORed with `kdf(password,
/// server_random)` and tagged with a running HMAC, obfuscating the real backend's post-ServerHello
/// traffic on its way to the shadow-tls-aware client.
pub(crate) async fn copy_by_frame_with_modification<R, W>(
    conn: &mut R,
    handshake_conn: &mut W,
    password: &str,
    server_random: &[u8],
    mut hmac_write: HmacSha1,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let write_key = kdf(password, server_random);
    loop {
        let mut frame = read_frame(conn)
            .await
            .map_err(|err| io::Error::new(err.kind(), format!("shadow-tls: read server record: {err}")))?;
        if frame.first() != Some(&APPLICATION_DATA) {
            handshake_conn
                .write_all(&frame)
                .await
                .map_err(|err| io::Error::new(err.kind(), format!("shadow-tls: write server record: {err}")))?;
            continue;
        }
        let (tls_header, payload) = frame.split_at_mut(TLS_HEADER_SIZE);
        xor_slice(payload, &write_key);
        hmac_write.update(payload);
        let Ok(new_len) = u16::try_from(payload.len() + HMAC_SIZE) else {
            return Err(io::Error::other(format!(
                "shadow-tls: record payload of {} bytes overflows the TLS record length",
                payload.len()
            )));
        };
        let (_, length_field) = tls_header.split_at_mut(3);
        BigEndian::write_u16(length_field, new_len);
        let hmac_hash = hmac_sum4(&hmac_write);
        let mut out = Vec::with_capacity(TLS_HMAC_HEADER_SIZE + payload.len());
        out.extend_from_slice(tls_header);
        out.extend_from_slice(&hmac_hash);
        out.extend_from_slice(payload);
        handshake_conn
            .write_all(&out)
            .await
            .map_err(|err| io::Error::new(err.kind(), format!("shadow-tls: write modified server record: {err}")))?;
    }
}

struct WriteRecordState {
    buf: Vec<u8>,
    offset: usize,
    written_len: usize,
}

pub(crate) struct VerifiedConn {
    conn: Box<dyn NetConn>,
    hmac_add: HmacSha1,
    hmac_verify: HmacSha1,
    hmac_ignore: Option<HmacSha1>,
    pending: Vec<u8>,
    read_buf: Vec<u8>,
    read_offset: usize,
    read_length_known: bool,
    write_state: Option<WriteRecordState>,
    /// Set once a resumed write is found to carry a different payload than the record already
    /// mid-flight (see [`WriteRecordState::payload`]): every later read/write fails with
    /// `BrokenPipe` instead of risking the stale record's remaining bytes reaching the peer under
    /// a new caller's name, or misreporting this call's byte count — the contract that a
    /// mid-frame write failure leaves the conn broken, never silently resumable.
    torn: bool,
}

pub(crate) fn new_verified_conn(
    conn: Box<dyn NetConn>,
    hmac_add: HmacSha1,
    hmac_verify: HmacSha1,
    hmac_ignore: Option<HmacSha1>,
) -> VerifiedConn {
    VerifiedConn {
        conn,
        hmac_add,
        hmac_verify,
        hmac_ignore,
        pending: Vec::new(),
        read_buf: vec![0u8; TLS_HEADER_SIZE],
        read_offset: 0,
        read_length_known: false,
        write_state: None,
        torn: false,
    }
}

impl VerifiedConn {
    fn deliver_pending(&mut self, buf: &mut ReadBuf<'_>) {
        let n = self.pending.len().min(buf.remaining());
        let (head, _) = self.pending.split_at(n);
        buf.put_slice(head);
        self.pending.drain(..n);
    }

    /// Sends a TLS alert. Best-effort: a single non-blocking write attempt, errors ignored,
    /// matching the synchronous fire-and-forget write.
    fn send_alert(&mut self, cx: &mut Context<'_>) {
        const RECORD_SIZE: usize = 31;
        let mut record = [0u8; RECORD_SIZE];
        record[0] = ALERT;
        record[1] = 3;
        record[2] = 3;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "RECORD_SIZE is 31, so the alert record's length field (26) always fits a u8"
        )]
        let alert_body_len = (RECORD_SIZE - TLS_HEADER_SIZE) as u8;
        record[4] = alert_body_len;
        rand::Rng::fill(&mut rand::rng(), &mut record[TLS_HEADER_SIZE..]);
        let _ = Pin::new(self.conn.as_mut()).poll_write(cx, &record);
    }

    /// Reads one record. Persists a partially-read record across polls so a read
    /// deadline only interrupts the current `Read`.
    fn poll_read_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Vec<u8>>> {
        loop {
            if self.read_offset < self.read_buf.len() {
                let Some(unread) = self.read_buf.get_mut(self.read_offset..) else {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                };
                let mut header_buf = ReadBuf::new(unread);
                match Pin::new(self.conn.as_mut()).poll_read(cx, &mut header_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(())) => {
                        let n = header_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                        }
                        self.read_offset += n;
                    }
                }
                continue;
            }
            if !self.read_length_known {
                let Some(length_bytes) = self.read_buf.get(3..TLS_HEADER_SIZE) else {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                };
                let length = usize::from(BigEndian::read_u16(length_bytes));
                self.read_buf.resize(TLS_HEADER_SIZE + length, 0);
                self.read_length_known = true;
                continue;
            }
            break;
        }
        let frame = std::mem::replace(&mut self.read_buf, vec![0u8; TLS_HEADER_SIZE]);
        self.read_offset = 0;
        self.read_length_known = false;
        Poll::Ready(Ok(frame))
    }

    fn poll_write_record(&mut self, cx: &mut Context<'_>, payload: &[u8]) -> Poll<io::Result<usize>> {
        if self.torn {
            return Poll::Ready(Err(torn_err()));
        }
        if let Some(state) = self.write_state.as_ref() {
            // `AsyncWrite`'s own contract lets a caller resume a `Pending` poll with a buffer
            // that has grown since (`tokio::io::copy` and `BufWriter` both do this), so only a
            // buffer that does **not** start with the exact bytes already sealed into this
            // record is a genuine mismatch — the caller that started this record gave up on it
            // (e.g. an outer deadline bridge that abandoned the poll) and this call is for a
            // different, unrelated write.
            let sealed_tail = state.buf.get(TLS_HMAC_HEADER_SIZE..);
            if !sealed_tail.is_some_and(|sealed| payload.starts_with(sealed)) {
                self.write_state = None;
                self.torn = true;
                return Poll::Ready(Err(torn_err()));
            }
        }
        if self.write_state.is_none() {
            let Ok(record_len) = u16::try_from(HMAC_SIZE + payload.len()) else {
                return Poll::Ready(Err(io::Error::other(format!(
                    "shadow-tls: record payload of {} bytes overflows the TLS record length",
                    payload.len()
                ))));
            };
            self.hmac_add.update(payload);
            let hmac_hash = hmac_sum4(&self.hmac_add);
            self.hmac_add.update(&hmac_hash);
            let mut buf = Vec::with_capacity(TLS_HMAC_HEADER_SIZE + payload.len());
            buf.push(APPLICATION_DATA);
            buf.push(3);
            buf.push(3);
            let mut length_bytes = [0u8; 2];
            BigEndian::write_u16(&mut length_bytes, record_len);
            buf.extend_from_slice(&length_bytes);
            buf.extend_from_slice(&hmac_hash);
            buf.extend_from_slice(payload);
            self.write_state = Some(WriteRecordState { buf, offset: 0, written_len: payload.len() });
        }
        loop {
            let Some(state) = self.write_state.as_mut() else {
                self.torn = true;
                return Poll::Ready(Err(torn_err()));
            };
            if state.offset >= state.buf.len() {
                let n = state.written_len;
                self.write_state = None;
                return Poll::Ready(Ok(n));
            }
            let offset = state.offset;
            let (_, unwritten) = state.buf.split_at(offset);
            match Pin::new(self.conn.as_mut()).poll_write(cx, unwritten) {
                Poll::Ready(Ok(0)) => {
                    self.write_state = None;
                    self.torn = true;
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => state.offset += n,
                Poll::Ready(Err(err)) => {
                    // The frame was already sealed (its bytes and HMAC hash were computed and
                    // `self.hmac_add` was already advanced) before this loop started, whether or
                    // not any byte of it has reached `self.conn` yet. A dropped sealed frame
                    // leaves the peer's HMAC chain permanently desynchronized with ours the
                    // moment we seal the *next* frame, so any failure here — even with
                    // `state.offset == 0` — must tear the whole conn (`agent://ReviewBridge2` P2),
                    // matching the contract that a mid-frame write failure leaves the conn
                    // broken.
                    self.write_state = None;
                    self.torn = true;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncRead for VerifiedConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.torn {
            return Poll::Ready(Err(torn_err()));
        }
        if !this.pending.is_empty() {
            this.deliver_pending(buf);
            return Poll::Ready(Ok(()));
        }
        loop {
            let frame = match this.poll_read_record(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(frame)) => frame,
                Poll::Ready(Err(err)) => {
                    if err.kind() != io::ErrorKind::TimedOut {
                        this.send_alert(cx);
                    }
                    return Poll::Ready(Err(err));
                }
            };
            match frame.first() {
                Some(&ALERT) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "shadow-tls: remote alert: use of closed network connection",
                    )));
                }
                Some(&APPLICATION_DATA) => {
                    if let Some(ignore) = this.hmac_ignore.as_mut() {
                        if verify_application_data(&frame, ignore, false) {
                            continue;
                        }
                        this.hmac_ignore = None;
                    }
                    if !verify_application_data(&frame, &mut this.hmac_verify, true) {
                        this.send_alert(cx);
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "shadow-tls: application data verification failed",
                        )));
                    }
                    let Some(payload) = frame.get(TLS_HMAC_HEADER_SIZE..) else {
                        this.send_alert(cx);
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                    };
                    this.pending = payload.to_vec();
                    if this.pending.is_empty() {
                        continue;
                    }
                    this.deliver_pending(buf);
                    return Poll::Ready(Ok(()));
                }
                Some(&other) => {
                    this.send_alert(cx);
                    return Poll::Ready(Err(io::Error::other(format!(
                        "shadow-tls: unexpected TLS record type: {other}"
                    ))));
                }
                None => {
                    this.send_alert(cx);
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                }
            }
        }
    }
}

impl AsyncWrite for VerifiedConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let length = buf.len().min(MAX_TLS_PLAINTEXT);
        let (head, _) = buf.split_at(length);
        this.poll_write_record(cx, head)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().conn.as_mut()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().conn.as_mut()).poll_shutdown(cx)
    }
}

fn torn_err() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "shadow-tls: conn torn by an abandoned mid-frame write")
}

impl NetStream for VerifiedConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.conn.local_addr()?.as_ref())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.conn.remote_addr()?.as_ref())
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.close_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.close_write()
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(self.conn.as_ref())
    }
}

impl ExtendedStream for VerifiedConn {}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use parking_lot::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{mpsc, oneshot};

    use super::*;
    use murmur_common::shared_conn::SharedConn;
    use murmur_std_compat::net::Addr;

    const TEST_PASSWORD: &str = "shadowtls-v3-test-password";

    fn user(name: &str, password: &str) -> User {
        User { name: name.to_owned(), password: password.to_owned() }
    }

    /// Builds a syntactically valid ClientHello frame whose embedded HMAC verifies against
    /// `password`, matching what a real v3 client produces.
    pub(crate) fn make_v3_client_hello(password: &str, filler: u8) -> Vec<u8> {
        const HMAC_INDEX: usize = SESSION_ID_LENGTH_INDEX + 1 + TLS_SESSION_ID_SIZE - HMAC_SIZE;
        const FRAME_LEN: usize = HMAC_INDEX + HMAC_SIZE + 16;
        let mut frame = vec![filler; FRAME_LEN];
        frame[0] = HANDSHAKE;
        frame[TLS_HEADER_SIZE] = CLIENT_HELLO;
        frame[SESSION_ID_LENGTH_INDEX] = TLS_SESSION_ID_SIZE as u8;
        let mut h = new_hmac_sha1(password);
        h.update(&frame[TLS_HEADER_SIZE..HMAC_INDEX]);
        h.update(&[0, 0, 0, 0]);
        h.update(&frame[HMAC_INDEX + HMAC_SIZE..]);
        let sum = hmac_sum4(&h);
        frame[HMAC_INDEX..HMAC_INDEX + HMAC_SIZE].copy_from_slice(&sum);
        frame
    }

    /// New coverage for the multi-user selection: `users` are iterated in configuration order and
    /// the first HMAC match is returned, regardless of position.
    #[test]
    fn verify_client_hello_selects_any_configured_user() {
        let users = vec![user("alice", "alice-password"), user("bob", "bob-password")];

        let frame_for_alice = make_v3_client_hello("alice-password", 0xAA);
        let matched = verify_client_hello(&frame_for_alice, &users).expect("alice's password verifies");
        assert_eq!(matched.name, "alice");

        let frame_for_bob = make_v3_client_hello("bob-password", 0xBB);
        let matched = verify_client_hello(&frame_for_bob, &users).expect("bob's password verifies");
        assert_eq!(matched.name, "bob");
    }

    #[test]
    fn verify_client_hello_rejects_wrong_password() {
        let users = vec![user("alice", "alice-password"), user("bob", "bob-password")];
        let frame = make_v3_client_hello("not-a-configured-password", 0xCC);
        let err = verify_client_hello(&frame, &users).expect_err("wrong password must not verify");
        assert_eq!(err.to_string(), "shadow-tls: ClientHello HMAC mismatch");
    }

    #[derive(Clone, Default)]
    struct WriteSpy(Arc<Mutex<WriteSpyState>>);

    #[derive(Default)]
    struct WriteSpyState {
        writes: usize,
        data: Vec<u8>,
    }

    impl WriteSpy {
        fn writes(&self) -> usize {
            self.0.lock().writes
        }

        fn take_frame(&self) -> Vec<u8> {
            std::mem::take(&mut self.0.lock().data)
        }
    }

    struct WriteSpyConn(WriteSpy);

    impl AsyncRead for WriteSpyConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for WriteSpyConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let mut state = self.0 .0.lock();
            state.writes += 1;
            state.data.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl NetConn for WriteSpyConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Err(io::Error::other("write spy has no address"))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Err(io::Error::other("write spy has no address"))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn verified_conn_zero_length_write() {
        let spy = WriteSpy::default();
        let mut verified = new_verified_conn(
            Box::new(WriteSpyConn(spy.clone())),
            new_hmac_sha1(TEST_PASSWORD),
            new_hmac_sha1(TEST_PASSWORD),
            None,
        );

        let n = verified.write(&[]).await.expect("zero-length write succeeds");
        assert_eq!(n, 0, "Write(nil) = {n}, want 0");
        assert_eq!(spy.writes(), 0, "underlying writes = {}, want 0", spy.writes());

        let payload = b"after a zero-length write";
        verified.write_all(payload).await.expect("payload write succeeds");
        let recorded = spy.take_frame();
        let mut expected_hmac = new_hmac_sha1(TEST_PASSWORD);
        expected_hmac.update(payload);
        let expected_tag = hmac_sum4(&expected_hmac);
        assert_eq!(
            &recorded[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE],
            &expected_tag,
            "Write(nil) advanced the HMAC state"
        );
    }

    /// Feeds a fixed byte sequence to the reader side of a `VerifiedConn` under test, one
    /// `poll_read` call at a time.
    struct CursorConn {
        data: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for CursorConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let remaining = &this.data[this.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for CursorConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl NetConn for CursorConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Err(io::Error::other("cursor conn has no address"))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Err(io::Error::other("cursor conn has no address"))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Builds a verified application-data record the same way `VerifiedConn::poll_write_record`
    /// does, so a zero-length record can be constructed directly without going through `Write`
    /// (which is a no-op for an empty payload, per `verified_conn_zero_length_write` above).
    fn build_verified_record(hmac: &mut HmacSha1, payload: &[u8]) -> Vec<u8> {
        hmac.update(payload);
        let hmac_hash = hmac_sum4(hmac);
        hmac.update(&hmac_hash);
        let mut buf = Vec::with_capacity(TLS_HMAC_HEADER_SIZE + payload.len());
        buf.push(APPLICATION_DATA);
        buf.push(3);
        buf.push(3);
        let mut length_bytes = [0u8; 2];
        BigEndian::write_u16(&mut length_bytes, (HMAC_SIZE + payload.len()) as u16);
        buf.extend_from_slice(&length_bytes);
        buf.extend_from_slice(&hmac_hash);
        buf.extend_from_slice(payload);
        buf
    }

    /// A verified zero-length application-data record (reachable from a zero-length write, unlike
    /// this crate's own `Write(&[])`) must not surface as
    /// EOF: `poll_read` has to skip it and keep reading until real payload arrives.
    #[tokio::test]
    async fn verified_conn_read_skips_zero_length_record() {
        let mut hmac_state = new_hmac_sha1(TEST_PASSWORD);
        let mut wire = build_verified_record(&mut hmac_state, &[]);
        let payload = b"second record payload";
        wire.extend_from_slice(&build_verified_record(&mut hmac_state, payload));

        let mut verified = new_verified_conn(
            Box::new(CursorConn { data: wire, pos: 0 }),
            new_hmac_sha1(TEST_PASSWORD),
            new_hmac_sha1(TEST_PASSWORD),
            None,
        );

        let mut out = vec![0u8; payload.len()];
        verified.read_exact(&mut out).await.expect("read must skip the zero-length record and deliver the next one");
        assert_eq!(&out, payload);
    }

    struct ReadStartedConn {
        conn: Box<dyn NetConn>,
        started: mpsc::Sender<()>,
    }

    impl ReadStartedConn {
        fn new(conn: Box<dyn NetConn>) -> (Self, mpsc::Receiver<()>) {
            let (started, rx) = mpsc::channel(1);
            (Self { conn, started }, rx)
        }
    }

    impl AsyncRead for ReadStartedConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let _ = this.started.try_send(());
            Pin::new(this.conn.as_mut()).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ReadStartedConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(self.get_mut().conn.as_mut()).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(self.get_mut().conn.as_mut()).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(self.get_mut().conn.as_mut()).poll_shutdown(cx)
        }
    }

    impl NetConn for ReadStartedConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            self.conn.local_addr()
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            self.conn.remote_addr()
        }

        fn close(&self) -> io::Result<()> {
            self.conn.close()
        }

        fn close_read(&self) -> io::Result<()> {
            self.conn.close_read()
        }

        fn close_write(&self) -> io::Result<()> {
            self.conn.close_write()
        }

        fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.conn.set_deadline(deadline)
        }

        fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.conn.set_read_deadline(deadline)
        }

        fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.conn.set_write_deadline(deadline)
        }
    }

    /// A read deadline that fires mid-record must surface as a timeout to the caller without the
    /// connection sending a TLS alert (which
    /// would otherwise poison the stream for the retry that follows).
    #[tokio::test]
    async fn v3_interrupted_read_does_not_send_alert() {
        let (client_side, server_side) = murmur_common_net::pipe();
        let client_shared = SharedConn::from_boxed(Box::new(client_side));
        let client_write_handle = client_shared.clone();
        let (server_raw, mut started_rx) = ReadStartedConn::new(Box::new(server_side));
        let server_shared = SharedConn::from_boxed(Box::new(server_raw));
        let deadline_handle = server_shared.clone();

        let server_random = [1u8; TLS_RANDOM_SIZE];
        let mut client_add = new_hmac_sha1(TEST_PASSWORD);
        hmac_reset(&mut client_add, &server_random, b'C');
        let mut client_verify = new_hmac_sha1(TEST_PASSWORD);
        hmac_reset(&mut client_verify, &server_random, b'S');
        let mut server_add = new_hmac_sha1(TEST_PASSWORD);
        hmac_reset(&mut server_add, &server_random, b'S');
        let mut server_verify = new_hmac_sha1(TEST_PASSWORD);
        hmac_reset(&mut server_verify, &server_random, b'C');
        // Independent of `client_add`: the request frame below is written straight to
        // `client_write_handle` (a raw write), never through
        // `client`'s own `Write`, so its HMAC chain lives here rather than inside `client`.
        let mut frame_hmac = new_hmac_sha1(TEST_PASSWORD);
        hmac_reset(&mut frame_hmac, &server_random, b'C');
        let mut client = new_verified_conn(Box::new(client_shared), client_add, client_verify, None);
        let mut server = new_verified_conn(Box::new(server_shared), server_add, server_verify, None);

        let response = b"response after interrupted idle read".to_vec();
        let (client_read_tx, client_read_rx) = oneshot::channel();
        let response_len = response.len();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; response_len];
            let result = client.read_exact(&mut buffer).await;
            let _ = client_read_tx.send((buffer, result));
        });

        let (server_read_tx, server_read_rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut buffer = [0u8; 1];
            let result = server.read(&mut buffer).await;
            let _ = server_read_tx.send((server, result));
        });

        started_rx.recv().await.expect("read started signal");
        deadline_handle.set_read_deadline(Some(tokio::time::Instant::now())).expect("interrupt server read");
        let (mut server, read_result) = server_read_rx.await.expect("server read task result");
        let err = read_result.expect_err("interrupted read must fail");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "server read error = {err:?}, want deadline exceeded");
        deadline_handle.set_read_deadline(None).expect("clear server read deadline");

        let mut client_read_rx = client_read_rx;
        assert!(client_read_rx.try_recv().is_err(), "client received data before response");

        let request = b"request after interrupted partial read".to_vec();
        let frame = build_verified_record(&mut frame_hmac, &request);
        let mut buffer = vec![0u8; request.len()];
        let (server_read_tx, server_read_rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = server.read_exact(&mut buffer).await;
            let _ = server_read_tx.send((server, buffer, result));
        });

        started_rx.recv().await.expect("read started signal");
        client_write_handle.write_all(&frame[..TLS_HEADER_SIZE]).await.expect("write partial request");
        started_rx.recv().await.expect("second read started signal");

        deadline_handle.set_read_deadline(Some(tokio::time::Instant::now())).expect("interrupt partial server read");
        let (mut server, mut buffer, read_result) = server_read_rx.await.expect("server read task result");
        let err = read_result.expect_err("interrupted partial read must fail");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "partial server read error = {err:?}, want deadline exceeded");
        deadline_handle.set_read_deadline(None).expect("clear partial server read deadline");

        assert!(client_read_rx.try_recv().is_err(), "client received data after interrupted partial read");

        let (client_write_tx, client_write_rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = client_write_handle.write_all(&frame[TLS_HEADER_SIZE..]).await;
            let _ = client_write_tx.send(result);
        });
        server.read_exact(&mut buffer).await.expect("server read request");
        assert_eq!(buffer, request, "server request mismatch");
        client_write_rx.await.expect("client write task result").expect("client write request");

        let (server_write_tx, server_write_rx) = oneshot::channel();
        let response_for_write = response.clone();
        tokio::spawn(async move {
            let result = server.write_all(&response_for_write).await;
            let _ = server_write_tx.send(result);
        });
        let (data, result) = client_read_rx.await.expect("client read task result");
        result.expect("client read response");
        assert_eq!(data, response, "client response mismatch");
        server_write_rx.await.expect("server write task result").expect("server write response");
    }

    /// Real duplex-backed `Stream`, wrapped in `StreamAsOldConn` to give `VerifiedConn`'s
    /// `old_conn()` (which answers `Some(self.conn.as_ref())`) a genuinely deadline-enforcing
    /// inner conn, exactly like production's bottom-of-stack raw `TcpStream` — not a hand-rolled
    /// `Conn` whose `set_write_deadline` would be the trait's no-op default.
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
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }
    }

    /// Regression for `ReviewTlsWave3` P2 and `agent://ReviewBridge2` P2: through the outer
    /// `StreamAsOldConn` every `VerifiedConn` is wrapped in (`server.rs`'s `server_v3`/`client.rs`'s
    /// `check_version`), a write deadline that fires while `poll_write_record` is mid-frame, after
    /// some bytes of the sealed record already reached the peer, must tear the whole conn down —
    /// the contract that a mid-frame write failure leaves the conn broken. Earlier revisions
    /// of this fix cleared the frame and left the conn writable instead, so a later, unrelated
    /// write put a fresh record right after the stale partial one on the wire.
    #[tokio::test]
    async fn stream_as_old_conn_write_after_deadline_cleared_does_not_resume_a_stale_frame() {
        let (dx_writer, mut dx_reader) = tokio::io::duplex(64);
        let inner: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(DxConn(dx_writer)));
        let verified = new_verified_conn(inner, new_hmac_sha1(TEST_PASSWORD), new_hmac_sha1(TEST_PASSWORD), None);
        let mut bridged = murmur_common_net::io::StreamAsOldConn::new(verified);

        NetConn::set_write_deadline(&bridged, Some(tokio::time::Instant::now() + Duration::from_millis(30)))
            .expect("arm write deadline");
        let stale_payload = vec![0xAAu8; 512];
        let err = tokio::time::timeout(Duration::from_secs(2), bridged.write_all(&stale_payload))
            .await
            .expect("the stalled write must time out, not hang forever")
            .expect_err("a write past a full duplex buffer, under a short deadline, must fail");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        NetConn::set_write_deadline(&bridged, None).expect("clear write deadline");

        let tail = b"tailbytes!";
        let drain = async {
            let mut scratch = [0u8; 128];
            loop {
                match tokio::time::timeout(Duration::from_millis(80), dx_reader.read(&mut scratch)).await {
                    Ok(Ok(n)) if n > 0 => continue,
                    _ => break,
                }
            }
        };
        let (write_result, ()) =
            tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(bridged.write_all(tail), drain) })
                .await
                .expect("tail write must not hang forever draining the stale frame's leftover bytes");
        let err = write_result.expect_err(
            "the timed-out write already put part of the stale frame on the wire, so the conn must be \
             permanently torn: a later write must never put a fresh record after that partial one",
        );
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    /// Deterministic regression for the same class of bug as the probe above, forced without any
    /// deadline or timing at all: fill the duplex so a record write genuinely parks mid-frame
    /// (`write_state` holds the sealed bytes and how many have gone out), stop polling that
    /// specific write (exactly what an outer bridge abandoning a poll looks like from
    /// `VerifiedConn`'s point of view, timing race or not), and call `poll_write` again with a
    /// *different* buffer. `VerifiedConn` must refuse to resume the stale record under the new
    /// buffer's name; it must tear the whole conn down instead.
    #[tokio::test]
    async fn verified_conn_write_tears_down_instead_of_resuming_a_different_buffer() {
        let (dx_writer, _dx_reader) = tokio::io::duplex(16);
        let inner: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(DxConn(dx_writer)));
        let mut verified = new_verified_conn(inner, new_hmac_sha1(TEST_PASSWORD), new_hmac_sha1(TEST_PASSWORD), None);

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let first = vec![0xAAu8; 256];
        match Pin::new(&mut verified).poll_write(&mut cx, &first) {
            Poll::Pending => {}
            other => panic!("expected the first write to park behind the full duplex buffer, got {other:?}"),
        }

        // Never poll the first write again — as if an outer bridge had already returned an error
        // for it to some other caller — and issue a completely different write instead.
        let second = b"different buffer";
        let err = match Pin::new(&mut verified).poll_write(&mut cx, second) {
            Poll::Ready(Err(err)) => err,
            other @ Poll::Ready(_) | other @ Poll::Pending => {
                panic!("resuming the stale record under a different buffer must fail cleanly, got {other:?}")
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        // Torn is permanent: even a read must now fail instead of ever touching the peer again.
        let mut buf = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut buf);
        match Pin::new(&mut verified).poll_read(&mut cx, &mut read_buf) {
            Poll::Ready(Err(err)) => assert_eq!(err.kind(), io::ErrorKind::BrokenPipe),
            other @ Poll::Ready(_) | other @ Poll::Pending => {
                panic!("a torn conn must fail every subsequent read too, got {other:?}")
            }
        }
    }

    /// Regression for `agent://ReviewBridge2` P2 (1): the resume check used to require the
    /// resumed `payload` to equal the in-flight record's payload exactly. `AsyncWrite`'s own
    /// contract lets a caller resume a `Pending` poll with a buffer that has grown since —
    /// `tokio::io::copy`'s `CopyBuffer` and a `BufWriter` both do this — and that must not tear
    /// the conn as long as the new buffer still starts with the exact bytes already sealed.
    #[tokio::test]
    async fn verified_conn_write_accepts_a_resumed_buffer_that_grew_since_the_last_poll() {
        let (dx_writer, _dx_reader) = tokio::io::duplex(16);
        let inner: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(DxConn(dx_writer)));
        let mut verified = new_verified_conn(inner, new_hmac_sha1(TEST_PASSWORD), new_hmac_sha1(TEST_PASSWORD), None);

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let first = vec![0xAAu8; 256];
        match Pin::new(&mut verified).poll_write(&mut cx, &first) {
            Poll::Pending => {}
            other => panic!("expected the first write to park behind the full duplex buffer, got {other:?}"),
        }

        let mut grown = first.clone();
        grown.extend_from_slice(&[0xBBu8; 64]);
        match Pin::new(&mut verified).poll_write(&mut cx, &grown) {
            Poll::Pending => {}
            other => panic!(
                "a resumed poll with a buffer that grew but still starts with the sealed record's \
                 bytes must not tear the conn, got {other:?}"
            ),
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
                // First call: accept only part of the record, so `state.offset` becomes nonzero.
                1 => Poll::Ready(Ok(buf.len().min(10))),
                // Second call (same outer `poll_write_record` invocation, `state.offset` still
                // short of `state.buf.len()`): park, so the manual poll below observes `Pending`
                // with partial progress already recorded.
                2 => Poll::Pending,
                // Third call (the resumed write): fail, simulating a mid-frame deadline or a
                // transient send error after part of the record already reached the peer.
                3 => Poll::Ready(Err(io::Error::other("simulated transport failure"))),
                // Every call after that would otherwise succeed outright — proving that a torn
                // conn refuses on its own, not because the transport is still broken.
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
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }
    }

    /// Regression for `agent://ReviewBridge2` P2 (2): a record write that fails after some of its
    /// bytes already reached the peer used to just clear `write_state` and leave the conn
    /// writable, so the next write put a fresh record right after the partial one — the peer's
    /// byte stream then fails TLS-record parsing. `FlakyConn` accepts a partial chunk, then parks,
    /// then fails exactly once, and would otherwise accept every write after that — proving the
    /// conn stays torn because `VerifiedConn` itself refuses, not because the mock is unusable.
    #[tokio::test]
    async fn verified_conn_write_tears_down_after_a_partial_frame_write_fails() {
        let inner: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(FlakyConn { calls: 0 }));
        let mut verified = new_verified_conn(inner, new_hmac_sha1(TEST_PASSWORD), new_hmac_sha1(TEST_PASSWORD), None);

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let payload = vec![0xAAu8; 256];
        match Pin::new(&mut verified).poll_write(&mut cx, &payload) {
            Poll::Pending => {}
            other => panic!("expected the write to park after a partial inner accept, got {other:?}"),
        }
        assert!(
            verified.write_state.as_ref().is_some_and(|state| state.offset > 0),
            "FlakyConn's first call must have accepted some of the sealed record before parking"
        );

        let err = match Pin::new(&mut verified).poll_write(&mut cx, &payload) {
            Poll::Ready(Err(err)) => err,
            other @ Poll::Ready(_) | other @ Poll::Pending => {
                panic!("expected the resumed write to hit the mock's one scheduled failure, got {other:?}")
            }
        };
        assert_eq!(err.to_string(), "simulated transport failure");

        // Even though the mock would now accept every further write, the conn must refuse.
        let err = match Pin::new(&mut verified).poll_write(&mut cx, b"fresh, unrelated write") {
            Poll::Ready(Err(err)) => err,
            other @ Poll::Ready(_) | other @ Poll::Pending => {
                panic!("a write after a partial-frame failure must fail closed, got {other:?}")
            }
        };
        assert_eq!(
            err.kind(),
            io::ErrorKind::BrokenPipe,
            "the conn must stay torn so no later write ever puts a fresh record after the partial one"
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
                // Record 1: delivered whole.
                1 => Poll::Ready(Ok(buf.len())),
                // Record 2's first inner write attempt: park before a single byte goes out.
                2 => Poll::Pending,
                // Record 2's resumed write: fails with zero bytes of *this* record ever sent —
                // the old `state.offset > 0` gate would have let this slide.
                3 => Poll::Ready(Err(io::Error::from(io::ErrorKind::TimedOut))),
                // Every call after that would otherwise succeed outright — proving record 3
                // never reaches here because `VerifiedConn` itself refuses first.
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
            Ok("127.0.0.1:1".parse().unwrap())
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }
    }

    /// Regression for `agent://ReviewBridge2` P2: `hmac_add` advances the moment a record is
    /// *sealed* (`v3.rs:300`), before a single byte of it is written. The old tear condition
    /// (`state.offset > 0`) only fired once bytes had gone out, so a record that fails on its
    /// very first inner write attempt — sealed but wholly undelivered — used to leave the conn
    /// writable, and the next record would be sealed against an HMAC chain the peer never
    /// verified. `SealBeforeSendFlakyConn` delivers record 1, then fails record 2 before any of
    /// its bytes reach the mock (with a `TimedOut` matching a real deadline mid-record), and
    /// would otherwise accept record 3 outright: proving `VerifiedConn` now refuses record 3 on
    /// its own, because a sealed-but-dropped record must tear the conn regardless of delivery.
    #[tokio::test]
    async fn verified_conn_write_tears_down_when_a_sealed_record_fails_before_any_byte_is_sent() {
        let inner: Box<dyn NetConn> =
            Box::new(murmur_common_net::io::StreamAsOldConn::new(SealBeforeSendFlakyConn { calls: 0 }));
        let mut verified = new_verified_conn(inner, new_hmac_sha1(TEST_PASSWORD), new_hmac_sha1(TEST_PASSWORD), None);

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let record1 = vec![0xAAu8; 64];
        match Pin::new(&mut verified).poll_write(&mut cx, &record1) {
            Poll::Ready(Ok(n)) => assert_eq!(n, record1.len(), "record 1 must be delivered whole"),
            other @ Poll::Ready(_) | other @ Poll::Pending => {
                panic!("expected record 1 to succeed outright, got {other:?}")
            }
        }

        let record2 = vec![0xBBu8; 64];
        match Pin::new(&mut verified).poll_write(&mut cx, &record2) {
            Poll::Pending => {}
            other => panic!("expected record 2's first inner write to park, got {other:?}"),
        }
        let err = match Pin::new(&mut verified).poll_write(&mut cx, &record2) {
            Poll::Ready(Err(err)) => err,
            other @ Poll::Ready(_) | other @ Poll::Pending => {
                panic!("expected the resumed record 2 write to hit the mock's scheduled failure, got {other:?}")
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        // Record 2 was sealed (its HMAC hash computed and `hmac_add` advanced) but never put a
        // single byte on the wire. The mock would now accept anything, but a record 3 must never
        // reach it: the sealed-and-dropped record 2 already broke the HMAC chain.
        let record3 = vec![0xCCu8; 64];
        let err = match Pin::new(&mut verified).poll_write(&mut cx, &record3) {
            Poll::Ready(Err(err)) => err,
            other @ Poll::Ready(_) | other @ Poll::Pending => {
                panic!("a write after a sealed-but-undelivered record's failure must fail closed, got {other:?}")
            }
        };
        assert_eq!(
            err.kind(),
            io::ErrorKind::BrokenPipe,
            "the conn must tear down the moment a sealed record is dropped, even with zero bytes sent"
        );
    }
}

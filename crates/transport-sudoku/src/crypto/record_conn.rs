use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use anyhow::{anyhow, Result};
use bytes::BytesMut;
use hmac::{Hmac, KeyInit as _, Mac as _};
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::aead::{poll_read_exact, poll_write_frame, Aead, Aes128GcmAead, ChaCha20Poly1305Aead};
use murmur_common_net::io::Stream;

/// `KeyUpdateAfterBytes` controls automatic key rotation based on plaintext bytes.
/// It is a package var (not config) to enable targeted tests with smaller thresholds.
pub static KEY_UPDATE_AFTER_BYTES: AtomicI64 = AtomicI64::new(32 << 20);

/// epoch(uint32) + seq(uint64) - also used as nonce+AAD.
const RECORD_HEADER_SIZE: usize = 12;
const MAX_FRAME_BODY_SIZE: usize = 65535;

struct RecordKeys {
    base_send: Vec<u8>,
    base_recv: Vec<u8>,
}

/// `RecordConn` is a framed AEAD connection with:
///   - deterministic per-record nonce (epoch+seq)
///   - per-direction key rotation (epoch), driven by plaintext byte counters
///   - replay/out-of-order protection within the connection (strict seq check)
///
/// Wire format per record:
///   - uint16 bodyLen
///   - `header[12]` = epoch(uint32 BE) || seq(uint64 BE)  (plaintext)
///   - ciphertext = AEAD(header as nonce, plaintext, header as AAD)
pub struct RecordConn {
    conn: Box<dyn Stream>,
    method: String,

    keys: RecordKeys,

    send_aead: Option<Arc<dyn Aead>>,
    send_aead_epoch: u32,

    recv_aead: Option<Arc<dyn Aead>>,
    recv_aead_epoch: u32,

    send_epoch: u32,
    send_seq: u64,
    send_bytes: i64,
    send_epoch_updates: u32,

    recv_epoch: u32,
    recv_seq: u64,
    recv_initialized: bool,

    read_buf: BytesMut,

    write_frame: Vec<u8>,
    write_frame_sent: usize,
    write_frame_plain_len: usize,

    recv_len_buf: [u8; 2],
    recv_len_filled: usize,
    recv_body: Vec<u8>,
    recv_body_filled: usize,
}

impl core::fmt::Debug for RecordConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecordConn")
            .field("method", &self.method)
            .field("send_epoch", &self.send_epoch)
            .field("recv_epoch", &self.recv_epoch)
            .finish_non_exhaustive()
    }
}

pub fn new_record_conn(conn: Box<dyn Stream>, method: &str, base_send: &[u8], base_recv: &[u8]) -> Result<RecordConn> {
    let method = normalize_aead_method(method);
    if method != "none" {
        validate_base_key(base_send).map_err(|err| anyhow!("invalid send base key: {err}"))?;
        validate_base_key(base_recv).map_err(|err| anyhow!("invalid recv base key: {err}"))?;
    }
    let mut rc = RecordConn {
        conn,
        method,
        keys: RecordKeys { base_send: clone_bytes(base_send), base_recv: clone_bytes(base_recv) },
        send_aead: None,
        send_aead_epoch: 0,
        recv_aead: None,
        recv_aead_epoch: 0,
        send_epoch: 0,
        send_seq: 0,
        send_bytes: 0,
        send_epoch_updates: 0,
        recv_epoch: 0,
        recv_seq: 0,
        recv_initialized: false,
        read_buf: BytesMut::new(),
        write_frame: Vec::new(),
        write_frame_sent: 0,
        write_frame_plain_len: 0,
        recv_len_buf: [0u8; 2],
        recv_len_filled: 0,
        recv_body: Vec::new(),
        recv_body_filled: 0,
    };
    rc.reset_traffic_state()?;
    Ok(rc)
}

impl RecordConn {
    pub fn rekey(&mut self, base_send: &[u8], base_recv: &[u8]) -> Result<()> {
        if self.method != "none" {
            validate_base_key(base_send).map_err(|err| anyhow!("invalid send base key: {err}"))?;
            validate_base_key(base_recv).map_err(|err| anyhow!("invalid recv base key: {err}"))?;
        }

        self.keys = RecordKeys { base_send: clone_bytes(base_send), base_recv: clone_bytes(base_recv) };
        self.reset_traffic_state()?;
        self.read_buf.clear();
        self.reset_recv_frame();

        self.send_aead = None;
        self.recv_aead = None;
        self.send_aead_epoch = 0;
        self.recv_aead_epoch = 0;
        Ok(())
    }

    fn reset_traffic_state(&mut self) -> Result<()> {
        let (send_epoch, send_seq) =
            random_record_counters().map_err(|err| anyhow!("initialize record counters: {err}"))?;
        self.send_epoch = send_epoch;
        self.send_seq = send_seq;
        self.send_bytes = 0;
        self.send_epoch_updates = 0;
        self.recv_epoch = 0;
        self.recv_seq = 0;
        self.recv_initialized = false;
        Ok(())
    }

    fn reset_recv_frame(&mut self) {
        self.recv_len_filled = 0;
        self.recv_body.clear();
        self.recv_body_filled = 0;
    }

    fn new_aead_for(&self, base: &[u8], epoch: u32) -> Result<Option<Arc<dyn Aead>>> {
        if self.method == "none" {
            return Ok(None);
        }
        let key = derive_epoch_key(base, epoch, &self.method)?;
        let aead: Arc<dyn Aead> = match self.method.as_str() {
            "aes-128-gcm" => {
                let a = Aes128GcmAead::new(&key[..16])?;
                if a.nonce_size() != RECORD_HEADER_SIZE {
                    return Err(anyhow!("unexpected gcm nonce size: {}", a.nonce_size()));
                }
                Arc::new(a)
            }
            "chacha20-poly1305" => {
                let a = ChaCha20Poly1305Aead::new(&key[..32])?;
                if a.nonce_size() != RECORD_HEADER_SIZE {
                    return Err(anyhow!("unexpected chacha nonce size: {}", a.nonce_size()));
                }
                Arc::new(a)
            }
            _ => return Err(anyhow!("unsupported cipher: {}", self.method)),
        };
        Ok(Some(aead))
    }

    fn maybe_bump_send_epoch(&mut self, added_plain: usize) -> Result<()> {
        let ku = KEY_UPDATE_AFTER_BYTES.load(Ordering::SeqCst);
        if ku <= 0 || self.method == "none" {
            return Ok(());
        }
        self.send_bytes += i64::try_from(added_plain).map_err(|err| anyhow!("record byte counter: {err}"))?;
        let threshold = ku * i64::from(self.send_epoch_updates + 1);
        if self.send_bytes < threshold {
            return Ok(());
        }
        self.send_epoch = self.send_epoch.wrapping_add(1);
        self.send_epoch_updates = self.send_epoch_updates.wrapping_add(1);
        let next_seq = random_non_zero_uint64().map_err(|err| anyhow!("rotate record seq: {err}"))?;
        self.send_seq = next_seq;
        Ok(())
    }

    fn validate_recv_position(&self, epoch: u32, seq: u64) -> Result<()> {
        if !self.recv_initialized {
            return Ok(());
        }
        if epoch < self.recv_epoch {
            return Err(anyhow!("replayed epoch: got {} want >={}", epoch, self.recv_epoch));
        }
        if epoch == self.recv_epoch && seq != self.recv_seq {
            return Err(anyhow!("out of order: epoch={} got={} want={}", epoch, seq, self.recv_seq));
        }
        if epoch > self.recv_epoch {
            const MAX_JUMP: u32 = 8;
            if epoch - self.recv_epoch > MAX_JUMP {
                return Err(anyhow!("epoch jump too large: got={} want<={}", epoch - self.recv_epoch, MAX_JUMP));
            }
        }
        Ok(())
    }

    const fn mark_recv_position(&mut self, epoch: u32, seq: u64) {
        self.recv_epoch = epoch;
        self.recv_seq = seq.wrapping_add(1);
        self.recv_initialized = true;
    }
}

fn normalize_aead_method(method: &str) -> String {
    match method {
        "" | "chacha20-poly1305" => "chacha20-poly1305".to_owned(),
        _ => method.to_owned(),
    }
}

fn validate_base_key(b: &[u8]) -> Result<()> {
    if b.len() < 32 {
        return Err(anyhow!("need at least 32 bytes, got {}", b.len()));
    }
    Ok(())
}

fn clone_bytes(b: &[u8]) -> Vec<u8> {
    b.to_vec()
}

fn random_record_counters() -> Result<(u32, u64)> {
    let epoch = random_non_zero_uint32()?;
    let seq = random_non_zero_uint64()?;
    Ok((epoch, seq))
}

fn random_non_zero_uint32() -> Result<u32> {
    loop {
        let mut b = [0u8; 4];
        OsRng.try_fill_bytes(&mut b)?;
        let v = u32::from_be_bytes(b);
        if v != 0 && v != u32::MAX {
            return Ok(v);
        }
    }
}

fn random_non_zero_uint64() -> Result<u64> {
    loop {
        let mut b = [0u8; 8];
        OsRng.try_fill_bytes(&mut b)?;
        let v = u64::from_be_bytes(b);
        if v != 0 && v != u64::MAX {
            return Ok(v);
        }
    }
}

fn derive_epoch_key(base: &[u8], epoch: u32, method: &str) -> Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(base).map_err(|err| anyhow!("hmac key: {err}"))?;
    mac.update(b"sudoku-record:");
    mac.update(method.as_bytes());
    mac.update(&epoch.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(out.as_slice());
    Ok(key)
}

impl AsyncWrite for RecordConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.method == "none" {
            return Pin::new(&mut this.conn).poll_write(cx, buf);
        }

        let mut total = 0usize;
        let mut off = 0usize;

        if !this.write_frame.is_empty() {
            ready!(poll_write_frame(&mut this.conn, cx, &this.write_frame, &mut this.write_frame_sent,))?;
            let plain_len = this.write_frame_plain_len;
            total = plain_len;
            off = plain_len;
            this.write_frame.clear();
            this.write_frame_sent = 0;
            this.write_frame_plain_len = 0;
            if let Err(err) = this.maybe_bump_send_epoch(plain_len) {
                return Poll::Ready(Err(io::Error::other(err)));
            }
        }

        while off < buf.len() {
            if this.send_aead.is_none() || this.send_aead_epoch != this.send_epoch {
                match this.new_aead_for(&this.keys.base_send, this.send_epoch) {
                    Ok(aead) => {
                        this.send_aead = aead;
                        this.send_aead_epoch = this.send_epoch;
                    }
                    Err(err) => return Poll::Ready(Err(io::Error::other(err))),
                }
            }
            let Some(aead) = this.send_aead.clone() else {
                return Poll::Ready(Err(io::Error::other("send aead unavailable")));
            };

            let max_plain = MAX_FRAME_BODY_SIZE.saturating_sub(RECORD_HEADER_SIZE + aead.overhead());
            if max_plain == 0 {
                return Poll::Ready(Err(io::Error::other("frame size too small")));
            }
            let n = std::cmp::min(buf.len() - off, max_plain);
            let (_, rest) = buf.split_at(off);
            let (chunk, _) = rest.split_at(n);

            let mut header = [0u8; RECORD_HEADER_SIZE];
            header[..4].copy_from_slice(&this.send_epoch.to_be_bytes());
            header[4..].copy_from_slice(&this.send_seq.to_be_bytes());
            this.send_seq = this.send_seq.wrapping_add(1);

            let cipher_len = n + aead.overhead();
            let Ok(body_len) = u16::try_from(RECORD_HEADER_SIZE + cipher_len) else {
                return Poll::Ready(Err(io::Error::other("frame too large")));
            };

            this.write_frame.clear();
            this.write_frame.extend_from_slice(&body_len.to_be_bytes());
            this.write_frame.extend_from_slice(&header);
            if let Err(err) = aead.seal(&mut this.write_frame, &header, chunk, &header) {
                return Poll::Ready(Err(io::Error::other(err)));
            }
            this.write_frame_sent = 0;
            this.write_frame_plain_len = n;

            match poll_write_frame(&mut this.conn, cx, &this.write_frame, &mut this.write_frame_sent) {
                Poll::Ready(Ok(())) => {
                    total += n;
                    off += n;
                    this.write_frame.clear();
                    this.write_frame_sent = 0;
                    this.write_frame_plain_len = 0;
                    if let Err(err) = this.maybe_bump_send_epoch(n) {
                        return Poll::Ready(Err(io::Error::other(err)));
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    if total == 0 {
                        return Poll::Pending;
                    }
                    return Poll::Ready(Ok(total));
                }
            }
        }
        Poll::Ready(Ok(total))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.conn).poll_shutdown(cx)
    }
}

impl AsyncRead for RecordConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.method == "none" {
            return Pin::new(&mut this.conn).poll_read(cx, buf);
        }

        if !this.read_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), this.read_buf.len());
            if n == 0 {
                return Poll::Ready(Ok(()));
            }
            buf.put_slice(&this.read_buf.split_to(n));
            return Poll::Ready(Ok(()));
        }

        if this.recv_body.is_empty() {
            match poll_read_exact(&mut this.conn, cx, &mut this.recv_len_buf, &mut this.recv_len_filled) {
                Poll::Ready(Ok(true)) => {
                    let body_len = u16::from_be_bytes(this.recv_len_buf) as usize;
                    this.recv_len_filled = 0;
                    if body_len < RECORD_HEADER_SIZE {
                        return Poll::Ready(Err(io::Error::other("frame too short")));
                    }
                    if body_len > MAX_FRAME_BODY_SIZE {
                        return Poll::Ready(Err(io::Error::other("frame too large")));
                    }
                    this.recv_body = vec![0u8; body_len];
                    this.recv_body_filled = 0;
                }
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        match poll_read_exact(&mut this.conn, cx, &mut this.recv_body, &mut this.recv_body_filled) {
            Poll::Ready(Ok(true)) => {}
            Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let mut body = std::mem::take(&mut this.recv_body);
        this.recv_body_filled = 0;
        let mut header = [0u8; RECORD_HEADER_SIZE];
        let (header_bytes, payload) = body.split_at_mut(RECORD_HEADER_SIZE);
        header.copy_from_slice(header_bytes);

        let epoch = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let seq = u64::from_be_bytes([
            header[4], header[5], header[6], header[7], header[8], header[9], header[10], header[11],
        ]);

        if let Err(err) = this.validate_recv_position(epoch, seq) {
            return Poll::Ready(Err(io::Error::other(err)));
        }

        if this.recv_aead.is_none() || this.recv_aead_epoch != epoch {
            match this.new_aead_for(&this.keys.base_recv, epoch) {
                Ok(aead) => {
                    this.recv_aead = aead;
                    this.recv_aead_epoch = epoch;
                }
                Err(err) => return Poll::Ready(Err(io::Error::other(err))),
            }
        }
        let Some(aead) = this.recv_aead.clone() else {
            return Poll::Ready(Err(io::Error::other("recv aead unavailable")));
        };

        let plaintext = match aead.open_in_place(&header, payload, &header) {
            Ok(plaintext) => plaintext,
            Err(err) => {
                return Poll::Ready(Err(io::Error::other(anyhow!(
                    "decryption failed: epoch={epoch} seq={seq}: {err}"
                ))));
            }
        };
        this.mark_recv_position(epoch, seq);

        this.read_buf.extend_from_slice(plaintext);
        let n = std::cmp::min(buf.remaining(), this.read_buf.len());
        if n > 0 {
            buf.put_slice(&this.read_buf.split_to(n));
        }
        Poll::Ready(Ok(()))
    }
}

impl Stream for RecordConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn.old_conn()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use parking_lot::Mutex;
    use sha2::Digest as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[derive(Clone)]
    struct CaptureConn {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl CaptureConn {
        fn new() -> Self {
            Self { buf: Arc::new(Mutex::new(Vec::new())) }
        }
    }

    impl AsyncRead for CaptureConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for CaptureConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.buf.lock().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Clone)]
    struct ReplayConn {
        reader: Arc<Mutex<io::Cursor<Vec<u8>>>>,
    }

    impl ReplayConn {
        fn new(data: Vec<u8>) -> Self {
            Self { reader: Arc::new(Mutex::new(io::Cursor::new(data))) }
        }
    }

    impl AsyncRead for ReplayConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let n = io::Read::read(&mut *self.reader.lock(), buf.initialize_unfilled())?;
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ReplayConn {
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

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }

    impl Stream for CaptureConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(test_addr())
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(test_addr())
        }
    }

    impl Stream for ReplayConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(test_addr())
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(test_addr())
        }
    }

    #[tokio::test]
    async fn record_conn_first_frame_uses_randomized_counters() {
        let psk_send = Sha256::digest(b"record-send");
        let psk_recv = Sha256::digest(b"record-recv");

        let raw = Arc::new(CaptureConn::new());
        let mut writer =
            new_record_conn(Box::new((*raw).clone()), "chacha20-poly1305", &psk_send, &psk_recv).expect("new writer");

        assert!(
            writer.send_epoch != 0 && writer.send_seq != 0,
            "expected non-zero randomized counters, got epoch={} seq={}",
            writer.send_epoch,
            writer.send_seq
        );

        let want = b"record prefix camouflage";
        writer.write_all(want).await.expect("write");

        let wire = raw.buf.lock().clone();
        assert!(wire.len() >= 2 + RECORD_HEADER_SIZE, "short frame: {}", wire.len());

        let body_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
        assert_eq!(body_len, wire.len() - 2, "body len mismatch");

        let mut epoch_bytes = [0u8; 4];
        epoch_bytes.copy_from_slice(&wire[2..6]);
        let epoch = u32::from_be_bytes(epoch_bytes);
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&wire[6..14]);
        let seq = u64::from_be_bytes(seq_bytes);
        assert!(epoch != 0 && seq != 0, "wire header still starts from zero: epoch={epoch} seq={seq}");

        let mut reader = new_record_conn(Box::new(ReplayConn::new(wire)), "chacha20-poly1305", &psk_recv, &psk_send)
            .expect("new reader");

        let mut got = vec![0u8; want.len()];
        reader.read_exact(&mut got).await.expect("read");
        assert_eq!(got, want.to_vec(), "plaintext mismatch");
    }
}

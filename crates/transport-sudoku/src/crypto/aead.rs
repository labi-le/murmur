use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use aes_gcm::aead::{AeadInOut, Key, Nonce, Tag};
use aes_gcm::{Aes128Gcm, KeyInit as _};
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use chacha20poly1305::ChaCha20Poly1305;
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common_net::io::Stream;

pub trait Aead: Send + Sync + std::fmt::Debug {
    fn nonce_size(&self) -> usize;

    fn overhead(&self) -> usize;

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> Result<()>;

    /// Decrypts `buf` in place and returns the plaintext prefix (the tag is stripped).
    fn open_in_place<'a>(&self, nonce: &[u8], buf: &'a mut [u8], additional_data: &[u8]) -> Result<&'a mut [u8]>;
}

#[derive(Debug)]
pub(crate) struct Aes128GcmAead {
    cipher: Aes128Gcm,
}

impl Aes128GcmAead {
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        let key =
            Key::<Aes128Gcm>::try_from(key).map_err(|_| anyhow!("invalid aes-128-gcm key length: {}", key.len()))?;
        Ok(Self { cipher: Aes128Gcm::new(&key) })
    }
}

impl Aead for Aes128GcmAead {
    fn nonce_size(&self) -> usize {
        12
    }

    fn overhead(&self) -> usize {
        16
    }

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> Result<()> {
        let nonce =
            Nonce::<Aes128Gcm>::try_from(nonce).map_err(|_| anyhow!("unexpected gcm nonce size: {}", nonce.len()))?;
        let start = dst.len();
        dst.extend_from_slice(plaintext);
        let (_, out) = dst.split_at_mut(start);
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce, additional_data, out.into())
            .map_err(|_| anyhow!("gcm seal failed"))?;
        dst.extend_from_slice(&tag);
        Ok(())
    }

    fn open_in_place<'a>(&self, nonce: &[u8], buf: &'a mut [u8], additional_data: &[u8]) -> Result<&'a mut [u8]> {
        let nonce =
            Nonce::<Aes128Gcm>::try_from(nonce).map_err(|_| anyhow!("unexpected gcm nonce size: {}", nonce.len()))?;
        if buf.len() < 16 {
            return Err(anyhow!("message authentication failed"));
        }
        let plain_len = buf.len() - 16;
        let (ciphertext, tag_bytes) = buf.split_at_mut(plain_len);
        let tag = Tag::<Aes128Gcm>::try_from(&tag_bytes[..]).map_err(|_| anyhow!("message authentication failed"))?;
        self.cipher
            .decrypt_inout_detached(&nonce, additional_data, (&mut *ciphertext).into(), &tag)
            .map_err(|_| anyhow!("message authentication failed"))?;
        Ok(ciphertext)
    }
}

#[derive(Debug)]
pub(crate) struct ChaCha20Poly1305Aead {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Aead {
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        let key = chacha20poly1305::Key::try_from(key)
            .map_err(|_| anyhow!("invalid chacha20-poly1305 key length: {}", key.len()))?;
        Ok(Self { cipher: ChaCha20Poly1305::new(&key) })
    }
}

impl Aead for ChaCha20Poly1305Aead {
    fn nonce_size(&self) -> usize {
        12
    }

    fn overhead(&self) -> usize {
        16
    }

    fn seal(&self, dst: &mut Vec<u8>, nonce: &[u8], plaintext: &[u8], additional_data: &[u8]) -> Result<()> {
        let nonce = chacha20poly1305::Nonce::try_from(nonce)
            .map_err(|_| anyhow!("unexpected chacha nonce size: {}", nonce.len()))?;
        let start = dst.len();
        dst.extend_from_slice(plaintext);
        let (_, out) = dst.split_at_mut(start);
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce, additional_data, out.into())
            .map_err(|_| anyhow!("chacha seal failed"))?;
        dst.extend_from_slice(&tag);
        Ok(())
    }

    fn open_in_place<'a>(&self, nonce: &[u8], buf: &'a mut [u8], additional_data: &[u8]) -> Result<&'a mut [u8]> {
        let nonce = chacha20poly1305::Nonce::try_from(nonce)
            .map_err(|_| anyhow!("unexpected chacha nonce size: {}", nonce.len()))?;
        if buf.len() < 16 {
            return Err(anyhow!("message authentication failed"));
        }
        let plain_len = buf.len() - 16;
        let (ciphertext, tag_bytes) = buf.split_at_mut(plain_len);
        let tag =
            chacha20poly1305::Tag::try_from(&tag_bytes[..]).map_err(|_| anyhow!("message authentication failed"))?;
        self.cipher
            .decrypt_inout_detached(&nonce, additional_data, (&mut *ciphertext).into(), &tag)
            .map_err(|_| anyhow!("message authentication failed"))?;
        Ok(ciphertext)
    }
}

/// The per-frame cap is `65535` minus the nonce size and the AEAD overhead.
const MAX_FRAME_BODY_SIZE: usize = 65535;

pub struct AEADConn {
    conn: Box<dyn Stream>,
    aead: Option<Arc<dyn Aead>>,
    read_buf: BytesMut,
    nonce_size: usize,

    write_frame: Vec<u8>,
    write_frame_sent: usize,
    write_frame_plain_len: usize,

    recv_header: [u8; 2],
    recv_header_filled: usize,
    recv_body: Vec<u8>,
    recv_body_filled: usize,
}

impl core::fmt::Debug for AEADConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AEADConn")
            .field("nonce_size", &self.nonce_size)
            .field("cipher", &self.aead.is_some())
            .finish_non_exhaustive()
    }
}

pub(crate) fn poll_write_frame(
    conn: &mut Box<dyn Stream>,
    cx: &mut Context<'_>,
    frame: &[u8],
    sent: &mut usize,
) -> Poll<std::io::Result<()>> {
    while *sent < frame.len() {
        let (_, pending) = frame.split_at(*sent);
        match Pin::new(&mut **conn).poll_write(cx, pending) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "write zero")));
            }
            Poll::Ready(Ok(n)) => *sent += n,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

pub(crate) fn poll_read_exact(
    conn: &mut Box<dyn Stream>,
    cx: &mut Context<'_>,
    dst: &mut [u8],
    filled: &mut usize,
) -> Poll<std::io::Result<bool>> {
    while *filled < dst.len() {
        let (_, rest) = dst.split_at_mut(*filled);
        let mut read_buf = ReadBuf::new(rest);
        ready!(Pin::new(&mut **conn).poll_read(cx, &mut read_buf))?;
        let n = read_buf.filled().len();
        if n == 0 {
            // 0 bytes read is a clean EOF; a partial frame is an unexpected EOF.
            if *filled == 0 {
                return Poll::Ready(Ok(false));
            }
            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "unexpected EOF")));
        }
        *filled += n;
    }
    Poll::Ready(Ok(true))
}

pub fn new_aead_conn(conn: Box<dyn Stream>, key: &str, method: &str) -> Result<AEADConn> {
    if method == "none" {
        return Ok(AEADConn {
            conn,
            aead: None,
            read_buf: BytesMut::new(),
            nonce_size: 0,
            write_frame: Vec::new(),
            write_frame_sent: 0,
            write_frame_plain_len: 0,
            recv_header: [0u8; 2],
            recv_header_filled: 0,
            recv_body: Vec::new(),
            recv_body_filled: 0,
        });
    }

    let mut h = Sha256::new();
    h.update(key.as_bytes());
    let key_bytes = h.finalize();

    let aead: Arc<dyn Aead> = match method {
        "aes-128-gcm" => {
            let key =
                key_bytes.get(..16).ok_or_else(|| anyhow!("invalid aes-128-gcm key length: {}", key_bytes.len()))?;
            Arc::new(Aes128GcmAead::new(key)?)
        }
        "chacha20-poly1305" => Arc::new(ChaCha20Poly1305Aead::new(&key_bytes)?),
        _ => return Err(anyhow!("unsupported cipher: {method}")),
    };

    let nonce_size = aead.nonce_size();
    Ok(AEADConn {
        conn,
        aead: Some(aead),
        read_buf: BytesMut::new(),
        nonce_size,
        write_frame: Vec::new(),
        write_frame_sent: 0,
        write_frame_plain_len: 0,
        recv_header: [0u8; 2],
        recv_header_filled: 0,
        recv_body: Vec::new(),
        recv_body_filled: 0,
    })
}

impl AsyncWrite for AEADConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let Some(aead) = this.aead.clone() else {
            return Pin::new(&mut this.conn).poll_write(cx, buf);
        };

        let max_payload = MAX_FRAME_BODY_SIZE - this.nonce_size - aead.overhead();
        let mut total = 0usize;
        let mut off = 0usize;

        if !this.write_frame.is_empty() {
            ready!(poll_write_frame(&mut this.conn, cx, &this.write_frame, &mut this.write_frame_sent,))?;
            total = this.write_frame_plain_len;
            off = total;
            this.write_frame.clear();
            this.write_frame_sent = 0;
            this.write_frame_plain_len = 0;
        }

        while off < buf.len() {
            let chunk_size = std::cmp::min(buf.len() - off, max_payload);
            let (_, rest) = buf.split_at(off);
            let (chunk, _) = rest.split_at(chunk_size);

            let mut nonce = vec![0u8; this.nonce_size];
            OsRng.try_fill_bytes(&mut nonce).map_err(std::io::Error::other)?;

            let frame_len = this.nonce_size + aead.overhead() + chunk_size;
            this.write_frame.clear();
            #[expect(clippy::cast_possible_truncation, reason = "frame_len never exceeds MAX_FRAME_BODY_SIZE")]
            this.write_frame.extend_from_slice(&(frame_len as u16).to_be_bytes());
            this.write_frame.extend_from_slice(&nonce);
            if let Err(err) = aead.seal(&mut this.write_frame, &nonce, chunk, &[]) {
                return Poll::Ready(Err(std::io::Error::other(err)));
            }
            this.write_frame_sent = 0;
            this.write_frame_plain_len = chunk_size;

            match poll_write_frame(&mut this.conn, cx, &this.write_frame, &mut this.write_frame_sent) {
                Poll::Ready(Ok(())) => {
                    total += chunk_size;
                    off += chunk_size;
                    this.write_frame.clear();
                    this.write_frame_sent = 0;
                    this.write_frame_plain_len = 0;
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

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.conn).poll_shutdown(cx)
    }
}

impl AsyncRead for AEADConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let Some(aead) = this.aead.clone() else {
            return Pin::new(&mut this.conn).poll_read(cx, buf);
        };

        if !this.read_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), this.read_buf.len());
            if n == 0 {
                return Poll::Ready(Ok(()));
            }
            buf.put_slice(&this.read_buf.split_to(n));
            return Poll::Ready(Ok(()));
        }

        if this.recv_body.is_empty() {
            match poll_read_exact(&mut this.conn, cx, &mut this.recv_header, &mut this.recv_header_filled) {
                Poll::Ready(Ok(true)) => {
                    let frame_len = u16::from_be_bytes(this.recv_header) as usize;
                    this.recv_header_filled = 0;
                    this.recv_body = vec![0u8; frame_len];
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
        if body.len() < this.nonce_size {
            return Poll::Ready(Err(std::io::Error::other("frame too short")));
        }
        if this.nonce_size != 12 {
            return Poll::Ready(Err(std::io::Error::other("unsupported aead nonce size")));
        }
        let (nonce_bytes, payload) = body.split_at_mut(12);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_bytes);
        let Ok(plaintext) = aead.open_in_place(&nonce, payload, &[]) else {
            return Poll::Ready(Err(std::io::Error::other("decryption failed")));
        };

        this.read_buf.extend_from_slice(plaintext);

        let n = std::cmp::min(buf.remaining(), this.read_buf.len());
        if n > 0 {
            buf.put_slice(&this.read_buf.split_to(n));
        }
        Poll::Ready(Ok(()))
    }
}

impl Stream for AEADConn {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.conn.peer_addr()
    }

    fn shutdown_read(&self) -> std::io::Result<()> {
        self.conn.shutdown_read()
    }

    fn shutdown_write(&self) -> std::io::Result<()> {
        self.conn.shutdown_write()
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn.old_conn()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    struct PipeConn(tokio::io::DuplexStream);

    impl AsyncRead for PipeConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PipeConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl Stream for PipeConn {
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }

        fn peer_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    /// The payload spans several frames, so framing, the reusable frame buffer and
    /// partial reads are all exercised.
    async fn round_trip(method: &str) {
        let (client_end, server_end) = tokio::io::duplex(64 * 1024);
        let mut client = new_aead_conn(Box::new(PipeConn(client_end)), "shared-secret", method).expect("client conn");
        let mut server = new_aead_conn(Box::new(PipeConn(server_end)), "shared-secret", method).expect("server conn");

        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let writer = tokio::spawn(async move { client.write_all(&payload).await });

        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = server.read(&mut chunk).await.expect("read");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
        }
        writer.await.expect("write task").expect("write payload");

        assert_eq!(got.len(), expected.len(), "round trip length for {method}");
        assert_eq!(got, expected, "round trip payload for {method}");
    }

    #[tokio::test]
    async fn aead_conn_round_trips_framed_payloads() {
        for method in ["chacha20-poly1305", "aes-128-gcm", "none"] {
            round_trip(method).await;
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
    }

    /// NIST GCM spec (McGrew & Viega), Appendix B, Test Case 2: AES-128-GCM, all-zero 16-byte
    /// key, all-zero 12-byte IV, 16 zero plaintext bytes, no AAD.
    #[test]
    fn aes128gcm_seal_and_open_in_place_match_nist_test_case_2() {
        let key = hex(&"0".repeat(32));
        let nonce = hex(&"0".repeat(24));
        let plaintext = hex(&"0".repeat(32));
        let want_ciphertext = hex("0388dace60b6a392f328c2b971b2fe78");
        let want_tag = hex("ab6e47d42cec13bdf53a67b21257bddf");

        let aead = Aes128GcmAead::new(&key).expect("aes-128-gcm key");

        let mut sealed = Vec::new();
        aead.seal(&mut sealed, &nonce, &plaintext, &[]).expect("seal");
        assert_eq!(&sealed[..want_ciphertext.len()], &want_ciphertext[..], "ciphertext must match NIST vector");
        assert_eq!(&sealed[want_ciphertext.len()..], &want_tag[..], "tag must match NIST vector");

        let mut buf = sealed.clone();
        let opened = aead.open_in_place(&nonce, &mut buf, &[]).expect("open_in_place").to_vec();
        assert_eq!(opened, plaintext, "open_in_place must recover the exact plaintext");
    }

    /// RFC 8439 section 2.8.2: AEAD_CHACHA20_POLY1305 example and test vector.
    #[test]
    fn chacha20poly1305_seal_and_open_in_place_match_rfc8439() {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex("070000004041424344454647");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        let want_ciphertext = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let want_tag = hex("1ae10b594f09e26a7e902ecbd0600691");

        let aead = ChaCha20Poly1305Aead::new(&key).expect("chacha20-poly1305 key");

        let mut sealed = Vec::new();
        aead.seal(&mut sealed, &nonce, &plaintext, &aad).expect("seal");
        assert_eq!(&sealed[..want_ciphertext.len()], &want_ciphertext[..], "ciphertext must match RFC 8439 vector");
        assert_eq!(&sealed[want_ciphertext.len()..], &want_tag[..], "tag must match RFC 8439 vector");

        let mut buf = sealed.clone();
        let opened = aead.open_in_place(&nonce, &mut buf, &aad).expect("open_in_place").to_vec();
        assert_eq!(opened, plaintext, "open_in_place must recover the exact plaintext");
    }
}

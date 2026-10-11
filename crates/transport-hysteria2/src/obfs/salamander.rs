//! The salamander packet-conn obfuscator: every packet gains a random 8-byte salt and is XORed with `blake2b-256(password || salt)`,
//! repeating the 32-byte key across the payload.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use blake2::Digest as _;
use parking_lot::Mutex;
use rand::RngCore;

use murmur_std_compat::net::{Addr, PacketConn};

pub const SALAMANDER_SALT_LEN: usize = 8;

pub const OBFUS_TYPE_SALAMANDER: &str = "salamander";

const KEY_LEN: usize = 32;

fn key_of(password: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let mut hasher = blake2::Blake2b256::new();
    hasher.update(password);
    hasher.update(salt);
    hasher.finalize().into()
}

fn apply(key: &[u8; KEY_LEN], data: &mut [u8]) {
    for (byte, mask) in data.iter_mut().zip(key.iter().cycle()) {
        *byte ^= *mask;
    }
}

///
/// the transform is stateless per packet, so only the outgoing buffer needs a lock; several
/// writers may hold it in turn without their frames interleaving.
pub struct SalamanderPacketConn {
    inner: Arc<dyn PacketConn>,
    password: Arc<[u8]>,
    write_buf: Mutex<Vec<u8>>,
}

impl std::fmt::Debug for SalamanderPacketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SalamanderPacketConn").finish_non_exhaustive()
    }
}

impl SalamanderPacketConn {
    pub fn new(inner: Arc<dyn PacketConn>, password: Arc<[u8]>) -> Self {
        Self { inner, password, write_buf: Mutex::new(Vec::new()) }
    }

    /// Decryption goes into the front of the caller's buffer, so
    /// the salt is consumed instead of left in front of the payload.
    pub fn decode(&self, buf: &mut [u8], len: usize) -> usize {
        if len <= SALAMANDER_SALT_LEN {
            return len;
        }
        let key = {
            let (salt, _) = buf.split_at_mut(SALAMANDER_SALT_LEN);
            key_of(&self.password, salt)
        };
        let body_len = len - SALAMANDER_SALT_LEN;
        buf.copy_within(SALAMANDER_SALT_LEN..len, 0);
        let (body, _) = buf.split_at_mut(body_len);
        apply(&key, body);
        body.len()
    }

    /// The write-side framing.
    pub fn encode_into(&self, buf: &mut Vec<u8>, payload: &[u8]) {
        buf.clear();
        buf.resize(SALAMANDER_SALT_LEN + payload.len(), 0);
        let (salt, body) = buf.split_at_mut(SALAMANDER_SALT_LEN);
        rand::rng().fill_bytes(salt);
        body.copy_from_slice(payload);
        let key = key_of(&self.password, salt);
        apply(&key, body);
    }
}

#[async_trait]
impl PacketConn for SalamanderPacketConn {
    /// A packet no longer than the salt carries no ciphertext; it is handed back undecoded and
    /// the QUIC layer above treats it as noise and drops it.
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let (len, addr) = self.inner.read_from(buf).await?;
        Ok((self.decode(buf, len), addr))
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let encoded = {
            let mut out = self.write_buf.lock();
            self.encode_into(&mut out, buf);
            out.clone()
        };
        self.inner.write_to(&encoded, addr).await?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.inner.close()
    }

    fn into_std_udp(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        // An obfuscating wrapper is not a bare UDP socket, matching the trait's own rule.
        Err(io::Error::new(io::ErrorKind::Unsupported, "obfuscated conn is not a raw UDP socket"))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use murmur_std_compat::net::UdpAddr;

    async fn dead_socket() -> Arc<dyn PacketConn> {
        Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    /// A writer and a reader wrapped with the same password, plus the address the writer targets.
    async fn pair(password: &[u8]) -> (SalamanderPacketConn, SalamanderPacketConn, UdpAddr) {
        let writer = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let reader = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = UdpAddr::from(reader.local_addr().unwrap());
        let client = SalamanderPacketConn::new(Arc::<tokio::net::UdpSocket>::clone(&writer), Arc::from(password));
        let server = SalamanderPacketConn::new(Arc::<tokio::net::UdpSocket>::clone(&reader), Arc::from(password));
        (client, server, target)
    }

    #[tokio::test]
    async fn payload_round_trips_through_the_transform() {
        let (client, server, target) = pair(b"pw").await;
        client.write_to(b"the quick brown fox", &target).await.unwrap();
        let mut buf = [0u8; 64];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), server.read_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..len], b"the quick brown fox");
    }

    #[tokio::test]
    async fn a_second_packet_round_trips_on_the_same_pair() {
        let (client, server, target) = pair(b"pw").await;
        client.write_to(b"first", &target).await.unwrap();
        client.write_to(b"second", &target).await.unwrap();
        let mut buf = [0u8; 64];
        for expected in [&b"first"[..], b"second"] {
            let (len, _) =
                tokio::time::timeout(Duration::from_secs(5), server.read_from(&mut buf)).await.unwrap().unwrap();
            assert_eq!(&buf[..len], expected);
        }
    }

    #[tokio::test]
    async fn an_empty_payload_travels_as_a_salt_only_packet() {
        let (client, server, target) = pair(b"pw").await;
        client.write_to(&[], &target).await.unwrap();
        let mut buf = [0u8; 64];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), server.read_from(&mut buf)).await.unwrap().unwrap();
        // The short-salt early return hands the salt back undecoded.
        assert_eq!(len, SALAMANDER_SALT_LEN);
    }

    #[tokio::test]
    async fn a_payload_longer_than_the_key_still_repeats_it() {
        let (client, server, target) = pair(b"pw").await;
        let payload: Vec<u8> = (0..100u8).collect();
        client.write_to(&payload, &target).await.unwrap();
        let mut buf = [0u8; 256];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), server.read_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..len], &payload[..]);
    }

    #[tokio::test]
    async fn wrong_password_does_not_recover_the_payload() {
        let (client, server, target) = pair(b"pw").await;
        let wrong = SalamanderPacketConn::new(Arc::clone(&server.inner), Arc::from(&b"other"[..]));
        client.write_to(b"secret", &target).await.unwrap();
        let mut buf = [0u8; 64];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), wrong.read_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(len, b"secret".len());
        assert_ne!(&buf[..len], b"secret");
    }

    #[tokio::test]
    async fn wire_form_is_salt_plus_ciphertext_of_the_same_length() {
        let conn = SalamanderPacketConn::new(dead_socket().await, Arc::from(&b"pw"[..]));
        let payload = [7u8; 40];
        let mut out = Vec::new();
        conn.encode_into(&mut out, &payload);
        assert_eq!(out.len(), SALAMANDER_SALT_LEN + payload.len());

        let mut decoded = out.clone();
        let wire_len = decoded.len();
        assert_eq!(conn.decode(&mut decoded, wire_len), payload.len());
        assert_eq!(&decoded[..payload.len()], &payload);
    }

    #[tokio::test]
    async fn key_is_blake2b_of_password_concatenated_with_salt() {
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut hasher = blake2::Blake2b256::new();
        hasher.update(b"pw");
        hasher.update(salt);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(key_of(b"pw", &salt), expected);
    }

    #[tokio::test]
    async fn packet_at_or_below_the_salt_length_is_returned_unchanged() {
        let conn = SalamanderPacketConn::new(dead_socket().await, Arc::from(&b"pw"[..]));
        let mut short = [0xAAu8; SALAMANDER_SALT_LEN];
        assert_eq!(conn.decode(&mut short, SALAMANDER_SALT_LEN), SALAMANDER_SALT_LEN);
        assert_eq!(short, [0xAAu8; SALAMANDER_SALT_LEN]);
    }
}

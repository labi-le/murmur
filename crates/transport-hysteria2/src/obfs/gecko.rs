//! The gecko packet-conn obfuscator.
//!
//! Gecko sits on top of salamander: a packet whose first byte carries the fragment flag is split
//! into 2..=8 padded chunks that the receiver reassembles before handing the payload up.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use rand::{Rng, RngCore};

use murmur_std_compat::net::{Addr, PacketConn};

use super::salamander::{SalamanderPacketConn, SALAMANDER_SALT_LEN};

pub const OBFUS_TYPE_GECKO: &str = "gecko";

const FRAGMENT_FLAG: u8 = 0x80;
const HEADER_LEN: usize = 5;
const MIN_CHUNKS: u8 = 2;
const MAX_CHUNKS: u8 = 8;
pub const MAX_ON_WIRE_SIZE: usize = 2048;
pub const DEFAULT_MIN_PACKET_SIZE: usize = 512;
pub const DEFAULT_MAX_PACKET_SIZE: usize = 1200;

const REASSEMBLY_TTL: Duration = Duration::from_secs(8);
const MAX_REASSEMBLY: usize = 4096;
const MAX_PER_SOURCE: usize = 8;

/// The 5-byte chunk header: fragment flag, message id, chunk index and count, pad length.
fn chunk_header(msg_id: u8, index: u8, chunks: u8, pad_len: usize) -> io::Result<[u8; HEADER_LEN]> {
    let Ok(pad_len) = u16::try_from(pad_len) else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "hysteria2: padding does not fit the frame header"));
    };
    let [pad_hi, pad_lo] = pad_len.to_be_bytes();
    Ok([FRAGMENT_FLAG, msg_id, (index << 4) | (chunks & 0x0f), pad_hi, pad_lo])
}

#[derive(Debug)]
struct ReassemblyEntry {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    deadline: Instant,
}

#[derive(Debug, Default)]
struct Reassembly {
    entries: HashMap<(String, u8), ReassemblyEntry>,
    per_source: HashMap<String, usize>,
    last_sweep: Option<Instant>,
}

impl Reassembly {
    fn drop_entry(&mut self, key: &(String, u8)) {
        if self.entries.remove(key).is_some() {
            if let Some(count) = self.per_source.get_mut(&key.0) {
                *count -= 1;
                if *count == 0 {
                    self.per_source.remove(&key.0);
                }
            }
        }
    }

    fn sweep_expired(&mut self, now: Instant) {
        let expired: Vec<(String, u8)> =
            self.entries.iter().filter(|(_, entry)| now > entry.deadline).map(|(key, _)| key.clone()).collect();
        for key in expired {
            self.drop_entry(&key);
        }
        self.last_sweep = Some(now);
    }

    fn evict_oldest(&mut self) {
        let oldest = self.entries.iter().min_by_key(|(_, entry)| entry.deadline).map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            self.drop_entry(&key);
        }
    }

    fn packets_insert(&mut self, key: (String, u8), messages: Vec<Option<Vec<u8>>>) {
        let now = Instant::now();
        self.entries.insert(key, ReassemblyEntry { chunks: messages, received: 1, deadline: now + REASSEMBLY_TTL });
    }

    fn accept(&mut self, source: &str, msg_id: u8, chunk_idx: u8, total: u8, payload: &[u8]) -> Option<Vec<u8>> {
        let now = Instant::now();
        if self.last_sweep.is_none_or(|last| now.duration_since(last) >= REASSEMBLY_TTL / 2) {
            self.sweep_expired(now);
        }

        let key = (source.to_owned(), msg_id);
        if let Some(entry) = self.entries.get_mut(&key) {
            if entry.chunks.len() != usize::from(total) {
                return None;
            }
            let slot = entry.chunks.get_mut(usize::from(chunk_idx))?;
            if slot.is_some() {
                return None;
            }
            *slot = Some(payload.to_vec());
            entry.received += 1;
            if entry.received < entry.chunks.len() {
                entry.deadline = now + REASSEMBLY_TTL;
                return None;
            }
        } else {
            if self.per_source.get(source).copied().unwrap_or(0) >= MAX_PER_SOURCE {
                return None;
            }
            if self.entries.len() >= MAX_REASSEMBLY {
                self.evict_oldest();
            }
            *self.per_source.entry(source.to_owned()).or_insert(0) += 1;
            let mut messages = vec![None; usize::from(total)];
            let slot = messages.get_mut(usize::from(chunk_idx))?;
            *slot = Some(payload.to_vec());
            self.packets_insert(key.clone(), messages);
            return None;
        }

        let entry = self.entries.remove(&key)?;
        if let Some(count) = self.per_source.get_mut(source) {
            *count -= 1;
            if *count == 0 {
                self.per_source.remove(source);
            }
        }
        let mut out = Vec::with_capacity(entry.chunks.iter().map(|chunk| chunk.as_ref().map_or(0, Vec::len)).sum());
        for chunk in entry.chunks.into_iter().flatten() {
            out.extend_from_slice(&chunk);
        }
        Some(out)
    }
}

#[derive(Debug)]
pub struct GeckoPacketConn {
    /// Gecko always wraps salamander, so the inner conn is held directly rather than as another
    /// `Arc<dyn PacketConn>`.
    inner: Arc<SalamanderPacketConn>,
    min_packet_size: usize,
    max_packet_size: usize,
    msg_id: Mutex<u8>,
    reassembly: Mutex<Reassembly>,
    write_buf: Mutex<Vec<u8>>,
}

impl GeckoPacketConn {
    pub fn new(
        inner: Arc<dyn PacketConn>,
        password: Arc<[u8]>,
        min_packet_size: usize,
        max_packet_size: usize,
    ) -> Self {
        Self {
            inner: Arc::new(SalamanderPacketConn::new(inner, password)),
            min_packet_size,
            max_packet_size,
            msg_id: Mutex::new(0),
            reassembly: Mutex::new(Reassembly::default()),
            write_buf: Mutex::new(Vec::new()),
        }
    }

    /// The default min/max packet sizes applied to an unset range, plus the `invalid packet size
    /// range` check the client and service perform.
    pub fn resolve_packet_sizes(
        min_packet_size: usize,
        max_packet_size: usize,
    ) -> Result<(usize, usize), &'static str> {
        let min_packet_size = if min_packet_size == 0 { DEFAULT_MIN_PACKET_SIZE } else { min_packet_size };
        let max_packet_size = if max_packet_size == 0 { DEFAULT_MAX_PACKET_SIZE } else { max_packet_size };
        if min_packet_size == 0 || min_packet_size > max_packet_size || max_packet_size > MAX_ON_WIRE_SIZE {
            return Err("gecko: invalid packet size range");
        }
        Ok((min_packet_size, max_packet_size))
    }

    fn random_pad_len(&self, chunk_len: usize) -> usize {
        let base = SALAMANDER_SALT_LEN + HEADER_LEN + chunk_len;
        let low = self.min_packet_size.max(base);
        if low > self.max_packet_size {
            return 0;
        }
        low - base + rand::rng().random_range(0..=(self.max_packet_size - low))
    }

    async fn write_fragmented(&self, payload: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let chunks = MIN_CHUNKS + rand::rng().random_range(0..=(MAX_CHUNKS - MIN_CHUNKS));
        let chunk_size = payload.len() / usize::from(chunks);
        let msg_id = {
            let mut counter = self.msg_id.lock();
            *counter = counter.wrapping_add(1);
            *counter
        };

        for index in 0..chunks {
            let frame = {
                let mut buf = self.write_buf.lock();
                let start = usize::from(index) * chunk_size;
                let end = if index + 1 < chunks { start + chunk_size } else { payload.len() };
                let (_, tail) = payload.split_at(start);
                let (chunk, _) = tail.split_at(end - start);
                let pad_len = self.random_pad_len(chunk.len());
                let header = chunk_header(msg_id, index, chunks, pad_len)?;

                buf.clear();
                buf.resize(HEADER_LEN + pad_len + chunk.len(), 0);
                let (head, body) = buf.split_at_mut(HEADER_LEN);
                head.copy_from_slice(&header);
                let (pad, data) = body.split_at_mut(pad_len);
                rand::rng().fill_bytes(pad);
                data.copy_from_slice(chunk);
                buf.clone()
            };
            self.inner.write_to(&frame, addr).await?;
        }
        Ok(payload.len())
    }

    /// Returns the reassembled payload once every chunk has arrived.
    fn accept_chunk(
        &self,
        addr: &dyn Addr,
        msg_id: u8,
        chunk_idx: u8,
        total_chunks: u8,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let source = addr.string();
        self.reassembly.lock().accept(&source, msg_id, chunk_idx, total_chunks, payload)
    }
}

#[async_trait]
impl PacketConn for GeckoPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        loop {
            let (len, addr) = self.inner.read_from(buf).await?;
            let (valid, _) = buf.split_at_mut(len);
            let Some(&first) = valid.first() else {
                continue;
            };
            if first & FRAGMENT_FLAG == 0 {
                return Ok((len, addr));
            }
            let Some((header, body)) = valid.split_at_checked(HEADER_LEN) else {
                continue;
            };
            let &[_, msg_id, flags, pad_hi, pad_lo] = header else {
                continue;
            };
            let chunk_idx = flags >> 4;
            let total_chunks = flags & 0x0f;
            let pad_len = usize::from(u16::from_be_bytes([pad_hi, pad_lo]));
            if !(MIN_CHUNKS..=MAX_CHUNKS).contains(&total_chunks) || chunk_idx >= total_chunks {
                continue;
            }
            let Some(body) = body.get(pad_len..) else {
                continue;
            };
            let Some(payload) = self.accept_chunk(addr.as_ref(), msg_id, chunk_idx, total_chunks, body) else {
                continue;
            };
            let written = payload.len().min(buf.len());
            let (target, _) = buf.split_at_mut(written);
            let (source, _) = payload.split_at(written);
            target.copy_from_slice(source);
            return Ok((written, addr));
        }
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let Some(&first) = buf.first() else {
            return Ok(0);
        };
        if first & FRAGMENT_FLAG == 0 {
            return self.inner.write_to(buf, addr).await;
        }
        self.write_fragmented(buf, addr).await
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

impl GeckoPacketConn {
    /// The chunk frames `write_fragmented` would emit, without sending them. Test-only seam for
    /// exercising the reassembler's out-of-order and duplicate paths.
    #[cfg(test)]
    fn frames(&self, payload: &[u8]) -> Vec<Vec<u8>> {
        let chunks = usize::from(MIN_CHUNKS) + rand::rng().random_range(0..=usize::from(MAX_CHUNKS - MIN_CHUNKS));
        let chunk_size = payload.len() / chunks;
        let msg_id = {
            let mut counter = self.msg_id.lock();
            *counter = counter.wrapping_add(1);
            *counter
        };
        let mut frames = Vec::with_capacity(chunks);
        for index in 0..chunks {
            let start = index * chunk_size;
            let end = if index + 1 < chunks { start + chunk_size } else { payload.len() };
            let chunk = &payload[start..end];
            let pad_len = self.random_pad_len(chunk.len());
            let mut frame = vec![0u8; HEADER_LEN + pad_len + chunk.len()];
            frame[0] = FRAGMENT_FLAG;
            frame[1] = msg_id;
            frame[2] = (index as u8) << 4 | chunks as u8 & 0x0f;
            frame[3..5].copy_from_slice(&(pad_len as u16).to_be_bytes());
            rand::rng().fill_bytes(&mut frame[HEADER_LEN..HEADER_LEN + pad_len]);
            frame[HEADER_LEN + pad_len..].copy_from_slice(chunk);
            frames.push(frame);
        }
        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use murmur_std_compat::net::UdpAddr;

    async fn sockets() -> (Arc<tokio::net::UdpSocket>, Arc<tokio::net::UdpSocket>, UdpAddr) {
        let writer = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let reader = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let target = UdpAddr::from(reader.local_addr().unwrap());
        (writer, reader, target)
    }

    fn gecko(conn: Arc<dyn PacketConn>, min: usize, max: usize) -> GeckoPacketConn {
        let (min, max) = GeckoPacketConn::resolve_packet_sizes(min, max).unwrap();
        GeckoPacketConn::new(conn, Arc::from(&b"pw"[..]), min, max)
    }

    async fn recv(conn: &GeckoPacketConn, expect_len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; 65535];
        let (len, _) = tokio::time::timeout(Duration::from_secs(10), conn.read_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(len, expect_len);
        buf[..len].to_vec()
    }

    /// A payload whose first byte carries the fragment flag, forcing the chunked path.
    fn flagged(len: usize) -> Vec<u8> {
        let mut payload = vec![0u8; len];
        payload[0] = FRAGMENT_FLAG;
        for (index, byte) in payload.iter_mut().enumerate().skip(1) {
            *byte = index as u8;
        }
        payload
    }

    #[test]
    fn packet_size_defaults_match_the_reference_constants() {
        assert_eq!(GeckoPacketConn::resolve_packet_sizes(0, 0).unwrap(), (512, 1200));
        assert_eq!(GeckoPacketConn::resolve_packet_sizes(600, 1400).unwrap(), (600, 1400));
    }

    #[test]
    fn packet_size_range_rejects_impossible_combinations() {
        assert!(GeckoPacketConn::resolve_packet_sizes(1400, 600).is_err());
        assert!(GeckoPacketConn::resolve_packet_sizes(512, MAX_ON_WIRE_SIZE + 1).is_err());
    }

    #[tokio::test]
    async fn unflagged_payload_passes_straight_through() {
        let (writer, reader, target) = sockets().await;
        let client = gecko(Arc::<tokio::net::UdpSocket>::clone(&writer), 0, 0);
        let server = gecko(Arc::<tokio::net::UdpSocket>::clone(&reader), 0, 0);
        let payload = b"plain salamander payload";
        client.write_to(payload, &target).await.unwrap();
        assert_eq!(recv(&server, payload.len()).await, payload);
    }

    #[tokio::test]
    async fn fragmented_payload_is_reassembled_in_order() {
        let (writer, reader, target) = sockets().await;
        let client = gecko(Arc::<tokio::net::UdpSocket>::clone(&writer), 0, 0);
        let server = gecko(Arc::<tokio::net::UdpSocket>::clone(&reader), 0, 0);
        let payload = flagged(900);
        client.write_to(&payload, &target).await.unwrap();
        assert_eq!(recv(&server, payload.len()).await, payload);
    }

    #[tokio::test]
    async fn chunks_arriving_out_of_order_still_reassemble() {
        let (writer, reader, target) = sockets().await;
        let client = gecko(Arc::<tokio::net::UdpSocket>::clone(&writer), 0, 0);
        let server = gecko(Arc::<tokio::net::UdpSocket>::clone(&reader), 0, 0);
        let payload = flagged(700);

        let mut frames = client.frames(&payload);
        assert!(frames.len() >= 2);
        let last = frames.pop().expect("at least two chunks");
        for frame in &frames {
            client.inner.write_to(frame, &target).await.unwrap();
        }
        client.inner.write_to(&last, &target).await.unwrap();
        assert_eq!(recv(&server, payload.len()).await, payload);
    }

    #[tokio::test]
    async fn two_fragmented_messages_in_a_row_do_not_cross() {
        let (writer, reader, target) = sockets().await;
        let client = gecko(Arc::<tokio::net::UdpSocket>::clone(&writer), 0, 0);
        let server = gecko(Arc::<tokio::net::UdpSocket>::clone(&reader), 0, 0);
        let first = flagged(800);
        let second = flagged(600);
        client.write_to(&first, &target).await.unwrap();
        client.write_to(&second, &target).await.unwrap();
        assert_eq!(recv(&server, first.len()).await, first);
        assert_eq!(recv(&server, second.len()).await, second);
    }

    #[tokio::test]
    async fn empty_payload_writes_nothing() {
        let (writer, reader, target) = sockets().await;
        let client = gecko(Arc::<tokio::net::UdpSocket>::clone(&writer), 0, 0);
        let _server = gecko(Arc::<tokio::net::UdpSocket>::clone(&reader), 0, 0);
        assert_eq!(client.write_to(&[], &target).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn short_flagged_packet_is_discarded_and_the_next_one_read() {
        let (writer, reader, target) = sockets().await;
        let client = gecko(Arc::<tokio::net::UdpSocket>::clone(&writer), 0, 0);
        let server = gecko(Arc::<tokio::net::UdpSocket>::clone(&reader), 0, 0);
        let mut truncated = client.frames(&flagged(600));
        let short = truncated.pop().expect("chunks produced");
        client.inner.write_to(&short[..2], &target).await.unwrap();
        let payload = b"survivor";
        client.write_to(payload, &target).await.unwrap();
        assert_eq!(recv(&server, payload.len()).await, payload);
    }

    #[test]
    fn reassembly_refills_a_dropped_chunk_id() {
        let mut reassembly = Reassembly::default();
        assert!(reassembly.accept("a", 1, 0, 2, b"aa").is_none());
        assert!(reassembly.accept("a", 1, 0, 2, b"bb").is_none());
        assert_eq!(reassembly.accept("a", 1, 1, 2, b"cc"), Some(b"aacc".to_vec()));
        assert!(reassembly.entries.is_empty());
    }

    #[test]
    fn reassembly_rejects_a_message_whose_total_changed() {
        let mut reassembly = Reassembly::default();
        assert!(reassembly.accept("a", 1, 0, 2, b"aa").is_none());
        assert!(reassembly.accept("a", 1, 0, 3, b"bb").is_none());
    }

    #[test]
    fn reassembly_bounds_the_messages_tracked_per_source() {
        let mut reassembly = Reassembly::default();
        for msg_id in 0..(MAX_PER_SOURCE as u8) {
            assert!(reassembly.accept("a", msg_id, 0, 2, b"aa").is_none());
        }
        assert!(reassembly.accept("a", 200, 0, 2, b"aa").is_none());
        assert_eq!(reassembly.accept("b", 1, 0, 2, b"aa").map(|out| out.len()), None);
    }

    #[tokio::test]
    async fn random_padding_keeps_a_chunk_inside_the_configured_packet_size_window() {
        let conn = gecko(dead_packet_conn().await, 1200, 1400);
        for chunk_len in [0usize, 10, 600, 1180] {
            let base = SALAMANDER_SALT_LEN + HEADER_LEN + chunk_len;
            let pad = conn.random_pad_len(chunk_len);
            assert!(pad <= 1400 - base, "chunk {chunk_len} padded past the maximum");
            if base < 1200 {
                assert!(base + pad >= 1200, "chunk {chunk_len} padded below the minimum");
            }
        }
    }

    #[tokio::test]
    async fn random_padding_is_zero_once_the_chunk_alone_exceeds_the_maximum() {
        let conn = gecko(dead_packet_conn().await, 512, 1200);
        assert_eq!(conn.random_pad_len(1200), 0);
    }

    async fn dead_packet_conn() -> Arc<dyn PacketConn> {
        Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }
}

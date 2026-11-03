//! The QUIC-datagram UDP relay that both the client's packet listener and the server's datagram
//! handler hand out.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Mutex as AsyncMutex;

use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};

use crate::protocol::{self, UdpMessage, MAX_UDP_SIZE};

/// The defragger LRU keeps an entry for ten seconds, refreshed on every hit.
const DEFRAG_AGE: Duration = Duration::from_secs(10);

/// The depth of the queue holding a session's received datagrams.
const DATA_QUEUE_DEPTH: usize = 64;

/// Reports the largest payload the peer will accept, which is what re-fragmentation sizes itself
/// against.
#[derive(Debug, thiserror::Error)]
#[error("DATAGRAM frame too large (maximum: {max_datagram_payload_size} bytes)")]
pub struct DatagramTooLarge {
    pub max_datagram_payload_size: usize,
}

/// Everything `send_datagram` can report back to the fragmentation decision.
#[derive(Debug, thiserror::Error)]
pub enum DatagramError {
    #[error(transparent)]
    TooLarge(#[from] DatagramTooLarge),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl DatagramError {
    #[must_use]
    pub fn too_large(&self) -> Option<usize> {
        match self {
            Self::TooLarge(DatagramTooLarge { max_datagram_payload_size }) => Some(*max_datagram_payload_size),
            Self::Io(_) => None,
        }
    }
}

/// The datagram surface of a QUIC connection, which is all this relay needs from it.
#[async_trait::async_trait]
pub trait QuicDatagrams: Send + Sync {
    fn send_datagram(&self, data: &[u8]) -> Result<(), DatagramError>;
    async fn receive_datagram(&self) -> io::Result<Vec<u8>>;
}

/// A budget computed as the packet size less the address can go negative once the address alone
/// exceeds it, so the packet is refused instead.
fn fragment(message: &UdpMessage, max_packet_size: usize) -> Result<Vec<UdpMessage>, DatagramError> {
    let budget = max_packet_size.checked_sub(message.header_size()).filter(|budget| *budget > 0).ok_or_else(|| {
        DatagramError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hysteria2: address does not fit the datagram budget",
        ))
    })?;
    if message.data.len() <= budget {
        return Ok(vec![message.clone()]);
    }
    let chunks: Vec<&[u8]> = message.data.chunks(budget).collect();
    let frag_count = u8::try_from(chunks.len()).map_err(|_| too_many_fragments())?;
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            Ok(UdpMessage {
                session_id: message.session_id,
                packet_id: message.packet_id,
                frag_id: u8::try_from(index).map_err(|_| too_many_fragments())?,
                frag_count,
                // The receiver reads the address off the first fragment; clearing it on later
                // fragments does not work.
                addr: message.addr.clone(),
                data: chunk.to_vec(),
            })
        })
        .collect()
}

fn too_many_fragments() -> DatagramError {
    DatagramError::Io(io::Error::new(io::ErrorKind::InvalidInput, "hysteria2: too many fragments"))
}

#[derive(Debug)]
struct PacketItem {
    messages: Vec<Option<UdpMessage>>,
    count: usize,
    deadline: Instant,
}

#[derive(Debug, Default)]
pub struct Defragger {
    packets: HashMap<u16, PacketItem>,
}

impl Defragger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `udpDefragger.feed`, returning the reassembled message once every fragment landed.
    pub fn feed(&mut self, message: UdpMessage) -> Option<UdpMessage> {
        if message.frag_count <= 1 {
            return Some(message);
        }
        if message.frag_id >= message.frag_count {
            return None;
        }
        let now = Instant::now();
        self.packets.retain(|_, item| item.deadline > now);

        let same_shape = self
            .packets
            .get(&message.packet_id)
            .is_some_and(|item| item.messages.len() == usize::from(message.frag_count));
        if !same_shape {
            let mut messages = vec![None; usize::from(message.frag_count)];
            let slot = messages.get_mut(usize::from(message.frag_id))?;
            *slot = Some(message.clone());
            self.packets.insert(message.packet_id, PacketItem { messages, count: 1, deadline: now + DEFRAG_AGE });
            return None;
        }

        let item = self.packets.get_mut(&message.packet_id)?;
        item.deadline = now + DEFRAG_AGE;
        let slot = item.messages.get_mut(usize::from(message.frag_id))?;
        if slot.is_some() {
            return None;
        }
        *slot = Some(message.clone());
        item.count += 1;
        if item.count != item.messages.len() {
            return None;
        }

        let item = self.packets.remove(&message.packet_id)?;
        let destination = item.messages.first()?.as_ref()?.addr.clone();
        let mut data = Vec::new();
        for message in item.messages.into_iter().flatten() {
            data.extend_from_slice(&message.data);
        }
        Some(UdpMessage {
            session_id: message.session_id,
            packet_id: message.packet_id,
            frag_id: 0,
            frag_count: 1,
            addr: destination,
            data,
        })
    }
}

pub struct UdpPacketConn {
    session_id: u32,
    udp_mtu: usize,
    quic: Arc<dyn QuicDatagrams>,
    next_packet_id: Mutex<u16>,
    defragger: Mutex<Defragger>,
    sender: tokio::sync::mpsc::Sender<UdpMessage>,
    receiver: AsyncMutex<tokio::sync::mpsc::Receiver<UdpMessage>>,
    on_destroy: Mutex<Option<Box<dyn FnOnce() + Send + Sync>>>,
}

impl std::fmt::Debug for UdpPacketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacketConn")
            .field("session_id", &self.session_id)
            .field("udp_mtu", &self.udp_mtu)
            .finish_non_exhaustive()
    }
}

impl UdpPacketConn {
    pub fn new(
        session_id: u32,
        quic: Arc<dyn QuicDatagrams>,
        udp_mtu: usize,
        on_destroy: Box<dyn FnOnce() + Send + Sync>,
    ) -> Arc<Self> {
        let (sender, receiver) = tokio::sync::mpsc::channel(DATA_QUEUE_DEPTH);
        Arc::new(Self {
            session_id,
            udp_mtu,
            defragger: Mutex::new(Defragger::new()),
            quic,
            next_packet_id: Mutex::new(0),
            sender,
            receiver: AsyncMutex::new(receiver),
            on_destroy: Mutex::new(Some(on_destroy)),
        })
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    pub fn write_packet(&self, data: &[u8], destination: &str) -> io::Result<()> {
        if data.len() > MAX_UDP_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("DATAGRAM frame too large (maximum: {MAX_UDP_SIZE} bytes)"),
            ));
        }
        let packet_id = {
            let mut next = self.next_packet_id.lock();
            *next = (*next).wrapping_add(1) % u16::MAX;
            *next
        };
        let message = UdpMessage {
            session_id: self.session_id,
            packet_id,
            frag_id: 0,
            frag_count: 1,
            addr: destination.to_owned(),
            data: data.to_vec(),
        };
        self.write_message(&message).map_err(|err| match err {
            DatagramError::Io(err) => err,
            DatagramError::TooLarge(err) => io::Error::new(io::ErrorKind::InvalidInput, err),
        })
    }

    /// Try the whole datagram first, and re-fragment against whatever budget the peer reported
    /// when it turned out to be too large.
    fn write_message(&self, message: &UdpMessage) -> Result<(), DatagramError> {
        let mut budget = self.udp_mtu;
        if message.data.len() <= budget.saturating_sub(message.header_size()) {
            match self.quic.send_datagram(&message.serialize()) {
                Ok(()) => return Ok(()),
                Err(err) => match err.too_large() {
                    Some(reported) => budget = reported,
                    None => return Err(err),
                },
            }
        }
        match self.send_fragments(message, budget) {
            Ok(()) => Ok(()),
            Err(err) => err.too_large().map_or(Err(err), |reported| self.send_fragments(message, reported)),
        }
    }

    fn send_fragments(&self, message: &UdpMessage, budget: usize) -> Result<(), DatagramError> {
        for fragment in fragment(message, budget)? {
            self.quic.send_datagram(&fragment.serialize())?;
        }
        Ok(())
    }

    /// Reassembles first, then enqueues; a full queue drops the
    /// packet instead of stalling the QUIC read loop that feeds it.
    pub fn input_packet(&self, message: UdpMessage) {
        let reassembled = self.defragger.lock().feed(message);
        let Some(message) = reassembled else {
            return;
        };
        let _ = self.sender.try_send(message);
    }

    /// Decodes one datagram and feeds it to the session, for the server's datagram read loop.
    pub fn input_datagram(&self, raw: &[u8]) -> anyhow::Result<()> {
        self.input_packet(protocol::parse_udp_message(raw)?);
        Ok(())
    }

    /// Detaches this session from its connection, which the connection
    /// itself outlives.
    pub fn close(&self) {
        let on_destroy = self.on_destroy.lock().take();
        if let Some(on_destroy) = on_destroy {
            on_destroy();
        }
    }
}

#[async_trait::async_trait]
impl PacketConn for UdpPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let message = {
            let mut receiver = self.receiver.lock().await;
            receiver.recv().await.ok_or_else(closed)?
        };
        let addr = parse_destination(&message.addr)?;
        let len = message.data.len().min(buf.len());
        let (target, _) = buf.split_at_mut(len);
        let (source, _) = message.data.split_at(len);
        target.copy_from_slice(source);
        Ok((len, Box::new(UdpAddr::from(addr))))
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.write_packet(buf, &addr.string())?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2 udp session has no local address"))
    }

    fn close(&self) -> io::Result<()> {
        Self::close(self);
        Ok(())
    }
}

/// Parsing a socks address, whose FQDN case has no `net.Addr` equivalent: it reaches
/// the handler as a `M.Socksaddr`.
pub fn parse_destination(address: &str) -> io::Result<std::net::SocketAddr> {
    murmur_sing::metadata::parse_socksaddr(address)
        .unwrap()
        .addr_port()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid destination {address}")))
}

/// The MTU a session reads and writes at.
#[must_use]
pub const fn reader_mtu() -> usize {
    MAX_UDP_SIZE
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "use of closed network connection")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(addr: &str, data: &[u8]) -> UdpMessage {
        UdpMessage {
            session_id: 3,
            packet_id: 9,
            frag_id: 0,
            frag_count: 1,
            addr: addr.to_owned(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn a_small_message_is_not_fragmented() {
        let message = message("1.2.3.4:5", &[1, 2, 3]);
        assert_eq!(fragment(&message, 1200).unwrap(), vec![message]);
    }

    #[test]
    fn a_large_message_is_split_into_ordered_numbered_fragments() {
        // "1.2.3.4:5" costs an 18-byte header, so a 1200-byte budget leaves 1182 bytes per fragment.
        let payload: Vec<u8> = (0..2000u32).map(|value| value as u8).collect();
        let message = message("1.2.3.4:5", &payload);
        let fragments = fragment(&message, 1200).unwrap();
        assert_eq!(fragments.len(), 2);
        assert!(fragments.iter().all(|fragment| fragment.frag_count == 2));
        assert_eq!(fragments[0].frag_id, 0);
        assert_eq!(fragments[1].frag_id, 1);
        assert!(fragments.iter().all(|fragment| fragment.session_id == 3 && fragment.packet_id == 9));
        assert!(fragments.iter().all(|fragment| fragment.addr == "1.2.3.4:5"));
        let joined: Vec<u8> = fragments.iter().flat_map(|fragment| fragment.data.clone()).collect();
        assert_eq!(joined, payload);
    }

    #[test]
    fn fragments_reassemble_to_the_original_message() {
        let payload: Vec<u8> = (0..5000u32).map(|value| value as u8).collect();
        let original = message("1.2.3.4:5", &payload);
        let fragments = fragment(&original, 1200).unwrap();
        assert!(fragments.len() > 2);

        let mut defragger = Defragger::new();
        let reassembled = fragments
            .into_iter()
            .filter_map(|fragment| defragger.feed(fragment))
            .next_back()
            .expect("every fragment arrived");
        assert_eq!(reassembled.addr, "1.2.3.4:5");
        assert_eq!(reassembled.data, payload);
        assert_eq!(reassembled.frag_count, 1);
        assert_eq!(reassembled.session_id, 3);
        assert_eq!(reassembled.packet_id, 9);
    }

    #[test]
    fn an_unfragmented_message_passes_straight_through_the_defragger() {
        let mut defragger = Defragger::new();
        let message = message("1.2.3.4:5", b"payload");
        assert_eq!(defragger.feed(message.clone()), Some(message));
    }

    #[test]
    fn a_duplicate_fragment_is_dropped_without_counting() {
        let original = message("1.2.3.4:5", &vec![0u8; 3000]);
        let fragments = fragment(&original, 1200).unwrap();
        assert_eq!(fragments.len(), 3);

        let mut defragger = Defragger::new();
        assert!(defragger.feed(fragments[0].clone()).is_none());
        assert!(defragger.feed(fragments[0].clone()).is_none());
        assert_eq!(defragger.packets[&9].count, 1);
        assert!(defragger.feed(fragments[1].clone()).is_none());
        let reassembled = defragger.feed(fragments[2].clone()).expect("every fragment id landed");
        assert_eq!(reassembled.data, original.data);
        assert!(defragger.packets.is_empty());
    }

    #[test]
    fn a_fragment_id_past_the_total_is_dropped() {
        let mut defragger = Defragger::new();
        let mut bad = message("1.2.3.4:5", b"x");
        bad.frag_id = 5;
        bad.frag_count = 2;
        assert!(defragger.feed(bad).is_none());
        assert!(defragger.packets.is_empty());
    }

    #[test]
    fn a_changed_fragment_total_restarts_the_message() {
        let mut defragger = Defragger::new();
        let mut first = message("1.2.3.4:5", b"x");
        first.frag_id = 0;
        first.frag_count = 2;
        let mut second = message("1.2.3.4:5", b"y");
        second.frag_id = 0;
        second.frag_count = 3;
        assert!(defragger.feed(first).is_none());
        assert!(defragger.feed(second).is_none());
        let stored = &defragger.packets[&9];
        assert_eq!(stored.messages.len(), 3);
        assert_eq!(stored.count, 1);
    }

    #[test]
    fn an_expired_partial_message_is_forgotten() {
        let mut defragger = Defragger::new();
        let mut first = message("1.2.3.4:5", b"x");
        first.frag_id = 0;
        first.frag_count = 2;
        assert!(defragger.feed(first).is_none());
        defragger.packets.get_mut(&9).expect("pending").deadline = Instant::now() - Duration::from_secs(1);

        let mut second = message("1.2.3.4:5", b"y");
        second.frag_id = 0;
        second.frag_count = 2;
        assert!(defragger.feed(second).is_none());
        assert_eq!(defragger.packets[&9].count, 1);
    }

    #[test]
    fn an_address_that_cannot_fit_is_rejected_rather_than_looping() {
        let long = "a".repeat(protocol::MAX_ADDRESS_LENGTH as usize);
        let message = message(&format!("{long}:80"), b"x");
        assert!(fragment(&message, 1200).is_err());
    }

    #[test]
    fn destination_parsing_round_trips_for_ip_targets() {
        assert_eq!(parse_destination("1.2.3.4:53").unwrap().to_string(), "1.2.3.4:53");
        assert_eq!(parse_destination("[::1]:53").unwrap().to_string(), "[::1]:53");
        assert!(parse_destination("example.com:80").is_err());
    }

    #[test]
    fn datagram_error_reports_only_the_size_limit() {
        assert_eq!(DatagramError::from(DatagramTooLarge { max_datagram_payload_size: 900 }).too_large(), Some(900));
        assert_eq!(DatagramError::Io(closed()).too_large(), None);
    }

    struct FakeQuic {
        sent: Mutex<Vec<Vec<u8>>>,
        limit: usize,
    }

    #[async_trait::async_trait]
    impl QuicDatagrams for FakeQuic {
        fn send_datagram(&self, data: &[u8]) -> Result<(), DatagramError> {
            if data.len() > self.limit {
                return Err(DatagramTooLarge { max_datagram_payload_size: self.limit }.into());
            }
            self.sent.lock().push(data.to_vec());
            Ok(())
        }

        async fn receive_datagram(&self) -> io::Result<Vec<u8>> {
            Err(closed())
        }
    }

    fn fake(limit: usize) -> Arc<FakeQuic> {
        Arc::new(FakeQuic { sent: Mutex::new(Vec::new()), limit })
    }

    fn conn(quic: &Arc<FakeQuic>, session_id: u32, udp_mtu: usize) -> Arc<UdpPacketConn> {
        UdpPacketConn::new(session_id, Arc::<FakeQuic>::clone(quic), udp_mtu, Box::new(|| {}))
    }

    fn sent_messages(quic: &Arc<FakeQuic>) -> Vec<UdpMessage> {
        quic.sent.lock().iter().map(|raw| protocol::parse_udp_message(raw).unwrap()).collect()
    }

    #[tokio::test]
    async fn a_small_write_reaches_the_peer_whole() {
        let quic = fake(4096);
        conn(&quic, 1, 1200).write_packet(b"hello", "1.2.3.4:53").unwrap();
        let sent = sent_messages(&quic);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].data, b"hello");
        assert_eq!(sent[0].addr, "1.2.3.4:53");
        assert_eq!(sent[0].session_id, 1);
    }

    #[tokio::test]
    async fn an_oversized_write_is_fragmented_and_rejoins() {
        let quic = fake(4096);
        let payload = vec![0xABu8; 3000];
        conn(&quic, 7, 1200).write_packet(&payload, "1.2.3.4:53").unwrap();

        let sent = sent_messages(&quic);
        assert!(sent.len() > 1, "expected fragments, got {}", sent.len());
        let mut defragger = Defragger::new();
        let reassembled = sent.into_iter().filter_map(|message| defragger.feed(message)).next_back().expect("complete");
        assert_eq!(reassembled.data, payload);
        assert_eq!(reassembled.session_id, 7);
    }

    #[tokio::test]
    async fn a_peer_reporting_a_smaller_budget_re_sizes_the_fragments() {
        let quic = fake(700);
        let payload = vec![1u8; 2000];
        conn(&quic, 1, 1200).write_packet(&payload, "1.2.3.4:53").unwrap();
        let sent = sent_messages(&quic);
        assert!(sent.len() > 1);
        assert!(quic.sent.lock().iter().all(|raw| raw.len() <= 700));
        let mut defragger = Defragger::new();
        let reassembled = sent.into_iter().filter_map(|message| defragger.feed(message)).next_back().expect("complete");
        assert_eq!(reassembled.data, payload);
    }

    #[tokio::test]
    async fn a_payload_above_the_protocol_maximum_is_refused_outright() {
        let quic = fake(65535);
        let payload = vec![0u8; MAX_UDP_SIZE + 1];
        assert!(conn(&quic, 1, 65535).write_packet(&payload, "1.2.3.4:53").is_err());
        assert!(quic.sent.lock().is_empty());
    }

    #[tokio::test]
    async fn packet_ids_advance_and_never_repeat_zero() {
        let quic = fake(4096);
        let conn = conn(&quic, 1, 1200);
        for _ in 0..5 {
            conn.write_packet(b"x", "1.2.3.4:53").unwrap();
        }
        let ids: Vec<u16> = sent_messages(&quic).into_iter().map(|message| message.packet_id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn a_read_returns_the_reassembled_payload_and_its_destination() {
        let quic = fake(4096);
        let conn = conn(&quic, 1, 1200);
        conn.input_packet(message("1.2.3.4:53", b"reply"));
        let mut buf = [0u8; 64];
        let (len, addr) = conn.read_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"reply");
        assert_eq!(addr.string(), "1.2.3.4:53");
    }

    #[tokio::test]
    async fn a_short_read_buffer_truncates_rather_than_overruns() {
        let quic = fake(4096);
        let conn = conn(&quic, 1, 1200);
        conn.input_packet(message("1.2.3.4:53", b"0123456789"));
        let mut buf = [0u8; 4];
        let (len, _) = conn.read_from(&mut buf).await.unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf, b"0123");
    }

    #[tokio::test]
    async fn closing_detaches_the_session_exactly_once() {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&counter);
        let quic = fake(4096);
        let conn = UdpPacketConn::new(
            1,
            Arc::<FakeQuic>::clone(&quic),
            1200,
            Box::new(move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
        );
        conn.close();
        conn.close();
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

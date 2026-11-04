use std::sync::{Arc, LazyLock, OnceLock};

use bytes::BytesMut;
use parking_lot::Mutex;

use crate::quic::Conn as QuicConn;
use murmur_common::lru::{self, LruCache};

use super::protocol::{Address, Packet, ATYP_NONE, PACKET_OVER_HEAD};

/// A safe UDP relay packet size.
///
/// The QUIC max datagram frame size is left alone because tuicv5 fragments UDP itself;
/// `1200` is the default max datagram size and `-3` the per-frame header overhead.
pub static MAX_FRAG_SIZE: LazyLock<usize> = LazyLock::new(|| 1200 - *PACKET_OVER_HEAD - 3);

/// A datagram that cannot be fragmented into something the v5 `PACKET` command can carry.
///
/// `frag_total` and `frag_id` are single wire bytes, so a zero fragment capacity (nothing to
/// divide the payload into) and a count above 255 (which would be written as a wrapped
/// `frag_total` and then overflow `frag_id`) are unrepresentable. Both fail closed here instead
/// of sending a header the peer would read as a different message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FragmentCapacityError {
    #[error("tuic v5: fragment capacity is zero, so a {payload_size} byte payload cannot be fragmented")]
    ZeroCapacity { payload_size: usize },
    #[error(
        "tuic v5: a {payload_size} byte payload at capacity {frag_size} needs {fragment_count} fragments, above the 255 the wire fields hold"
    )]
    CountOverflow { payload_size: usize, frag_size: usize, fragment_count: usize },
}

pub(crate) async fn frag_write_native(
    quic_conn: &dyn QuicConn,
    mut packet: Packet,
    buf: &mut BytesMut,
    frag_size: usize,
) -> anyhow::Result<()> {
    let full_payload = packet.data.clone();
    if frag_size == 0 {
        return Err(FragmentCapacityError::ZeroCapacity { payload_size: full_payload.len() }.into());
    }
    let frag_count = full_payload.len().div_ceil(frag_size);
    // `frag_id` counts up once per fragment, so a count the single-byte wire fields hold is what
    // keeps both `frag_total` and the final `frag_id += 1` representable.
    let Ok(frag_total) = u8::try_from(frag_count) else {
        return Err(FragmentCapacityError::CountOverflow {
            payload_size: full_payload.len(),
            frag_size,
            fragment_count: frag_count,
        }
        .into());
    };
    let mut off = 0usize;
    let mut frag_id = 0u8;
    packet.frag_total = frag_total;
    while off < full_payload.len() {
        let mut payload_size = full_payload.len() - off;
        if payload_size > frag_size {
            payload_size = frag_size;
        }
        packet.frag_id = frag_id;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the fragment payload is capped at `frag_size`, a datagram payload bound that fits the 16-bit wire field"
        )]
        let frag_len = payload_size as u16;
        packet.size = frag_len;
        packet.data = full_payload.slice(off..off + payload_size);
        off += payload_size;
        frag_id += 1;
        buf.clear();
        packet.write_to(buf);
        quic_conn.send_datagram(&buf[..])?;
        // The address is sent once: `Address::write_to` returns before reading `addr` for
        // `ATYP_NONE`, so it is dropped here rather than deep-copied for every later fragment.
        packet.addr = Address { type_: ATYP_NONE, addr: Vec::new(), port: 0 };
    }
    Ok(())
}

/// Concurrent incomplete messages held per association. An age window alone bounds nothing when
/// the peer picks `frag_total`, and a peer relaying datagrams has only a few messages in flight.
const FRAGMENT_BAG_LIMIT: usize = 1024;

/// The largest payload one message may reassemble to, the bound the 16-bit wire `size` field can
/// describe and the bound `send_to` accepts. A bag that would exceed it is dropped before the
/// bytes are retained, so the cache holds at most one fragment of slack per bag rather than a
/// count-limited number of unaccounted payloads.
const MAX_REASSEMBLED_PAYLOAD: usize = 65_535;

/// The bag's fields, held under one lock.
#[derive(Default)]
struct PacketBagState {
    /// The fragments received so far, at most one per `frag_id`, so a bag is sized by what the
    /// peer actually sent rather than by the `frag_total` it declared.
    frags: Vec<Packet>,
    /// The payload bytes those fragments hold, summed as they arrive so a message is refused
    /// before it can outgrow [`MAX_REASSEMBLED_PAYLOAD`].
    held_bytes: usize,
    /// The `frag_total` the message in flight declared; a different one starts a new message.
    frag_total: u8,
}

#[derive(Default)]
pub(crate) struct PacketBag {
    state: Mutex<PacketBagState>,
}

/// The defragger. The lazy LRU init collapses into one `OnceLock`.
#[derive(Default)]
pub(crate) struct DeFragger {
    lru: OnceLock<LruCache<u16, Arc<PacketBag>>>,
}

impl DeFragger {
    /// The lazily initialized LRU cache.
    fn lru(&self) -> &LruCache<u16, Arc<PacketBag>> {
        self.lru.get_or_init(|| {
            lru::new(vec![lru::with_age(10), lru::with_size(FRAGMENT_BAG_LIMIT), lru::with_update_age_on_get()])
        })
    }

    pub(crate) fn feed(&self, m: Packet) -> Option<Packet> {
        if m.frag_total <= 1 {
            return Some(m);
        }
        let frag_id = m.frag_id;
        if frag_id >= m.frag_total {
            // wtf is this?
            return None;
        }
        let pkt_id = m.pkt_id;
        let lru = self.lru();
        let (bag, _) = lru.get_or_store(pkt_id, || Arc::new(PacketBag::default()));
        let mut state = bag.state.lock();
        if state.frag_total != m.frag_total {
            state.frags.clear();
            state.held_bytes = 0;
            state.frag_total = m.frag_total;
        }
        if state.frags.iter().any(|frag| frag.frag_id == frag_id) {
            return None;
        }
        let held_bytes = state.held_bytes.saturating_add(m.data.len());
        if held_bytes > MAX_REASSEMBLED_PAYLOAD {
            // The peer is past the size a single udp datagram can carry: drop what this message
            // retained instead of adding to it, and let a fresh message start on this `pkt_id`.
            drop(state);
            lru.delete(pkt_id);
            return None;
        }
        state.held_bytes = held_bytes;
        state.frags.push(m);
        if state.frags.len() != usize::from(state.frag_total) {
            return None;
        }

        // all fragments received, assemble
        let mut frags = std::mem::take(&mut state.frags);
        drop(state);
        frags.sort_unstable_by_key(|frag| frag.frag_id);
        let mut data = Vec::new();
        for frag in &frags {
            data.extend_from_slice(&frag.data);
        }
        let mut p = frags.into_iter().next()?;
        // `held_bytes` bounded every fragment as it arrived, so this holds; a checked conversion
        // keeps the size consistent with the payload even if that bound is ever loosened.
        let reassembled_len = u16::try_from(data.len()).ok()?;
        p.size = reassembled_len;
        p.data = bytes::Bytes::from(data);
        p.frag_id = 0;
        p.frag_total = 1;
        lru.delete(pkt_id);
        Some(p)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::v5::protocol;

    fn packet(pkt_id: u16, frag_total: u8, frag_id: u8, data: &[u8]) -> Packet {
        let addr = protocol::new_address_addr_port(SocketAddr::from(([192, 0, 2, 1], 9)));
        let size = u16::try_from(data.len()).expect("the test payloads fit the wire field");
        protocol::new_packet(1, pkt_id, frag_total, frag_id, size, addr, bytes::Bytes::copy_from_slice(data))
    }

    fn held_fragments(defragger: &DeFragger, pkt_id: u16) -> usize {
        let (bag, _) = defragger.lru().get_or_store(pkt_id, || Arc::new(PacketBag::default()));
        let held = bag.state.lock().frags.len();
        held
    }

    /// The payload bytes a bag retains right now, the value the aggregate bound caps.
    fn bag_held_bytes(defragger: &DeFragger, pkt_id: u16) -> usize {
        let (bag, _) = defragger.lru().get_or_store(pkt_id, || Arc::new(PacketBag::default()));
        let held = bag.state.lock().held_bytes;
        held
    }

    #[test]
    fn a_fragment_bag_holds_only_the_fragments_that_arrived() {
        let defragger = DeFragger::default();
        assert!(defragger.feed(packet(7, 255, 0, b"")).is_none());
        assert_eq!(held_fragments(&defragger, 7), 1, "a 13 byte fragment must not hold a slot per declared fragment");
    }

    #[test]
    fn fragment_bags_are_evicted_once_the_cache_limit_is_reached() {
        let defragger = DeFragger::default();
        for pkt_id in 0..10_000u16 {
            assert!(defragger.feed(packet(pkt_id, 255, 0, b"")).is_none());
        }
        let lru = defragger.lru();
        let held = (0..10_000u16).filter(|pkt_id| lru.exist(*pkt_id)).count();
        assert_eq!(held, FRAGMENT_BAG_LIMIT, "10 000 pkt_ids must not outgrow the cache's size limit");
    }

    #[test]
    fn fragments_arriving_out_of_order_are_joined_in_order_under_the_first_fragments_address() {
        let defragger = DeFragger::default();
        let addr = protocol::new_address_addr_port(SocketAddr::from(([192, 0, 2, 1], 9)));
        let none = Address { type_: ATYP_NONE, addr: Vec::new(), port: 0 };
        let first = protocol::new_packet(1, 9, 2, 0, 2, addr.clone(), bytes::Bytes::from_static(b"ab"));
        let second = protocol::new_packet(1, 9, 2, 1, 2, none, bytes::Bytes::from_static(b"cd"));

        assert!(defragger.feed(second).is_none());
        let assembled = defragger.feed(first).expect("the second fragment completes the message");
        assert_eq!(&assembled.data[..], b"abcd");
        assert_eq!(assembled.size, 4);
        assert_eq!(assembled.frag_id, 0);
        assert_eq!(assembled.frag_total, 1);
        assert_eq!(assembled.addr.string(), addr.string());
    }

    #[test]
    fn two_maximum_size_fragments_never_assemble_past_the_size_a_datagram_carries() {
        let defragger = DeFragger::default();
        let big = vec![0u8; 40_000];
        assert!(defragger.feed(packet(11, 2, 0, &big)).is_none());
        assert!(
            defragger.feed(packet(11, 2, 1, &big)).is_none(),
            "80 000 retained bytes must not be returned against a 14464-byte `size` field"
        );
        assert_eq!(held_fragments(&defragger, 11), 0, "the refused message must not stay in the cache");
        assert!(defragger.feed(packet(11, 2, 0, b"ab")).is_none());
        assert!(defragger.feed(packet(11, 2, 1, b"cd")).is_some(), "a fresh message must reassemble");
    }

    #[test]
    fn a_message_is_refused_before_its_fragments_outgrow_one_udp_datagram() {
        let defragger = DeFragger::default();
        let fragment = vec![0u8; 1_200];
        let mut completed = Vec::new();
        let mut peak_retained = 0usize;
        for frag_id in 0..200u8 {
            if defragger.feed(packet(4, 200, frag_id, &fragment)).is_some() {
                completed.push(frag_id);
            }
            peak_retained = peak_retained.max(bag_held_bytes(&defragger, 4));
        }
        assert!(completed.is_empty(), "an incomplete message past the udp bound must never complete: {completed:?}");
        assert_eq!(peak_retained, 64_800, "a bag must stop retaining fragments at the udp bound");
    }

    #[test]
    fn a_message_that_lands_below_the_udp_bound_still_reassembles() {
        let defragger = DeFragger::default();
        let half = vec![0u8; 30_000];
        assert!(defragger.feed(packet(6, 2, 0, &half)).is_none());
        let assembled = defragger.feed(packet(6, 2, 1, &half)).expect("60 000 bytes fit one udp datagram");
        assert_eq!(assembled.data.len(), 60_000);
        assert_eq!(usize::from(assembled.size), 60_000);
    }

    #[test]
    fn a_repeated_fragment_does_not_complete_the_message() {
        let defragger = DeFragger::default();
        assert!(defragger.feed(packet(3, 2, 1, b"cd")).is_none());
        assert!(defragger.feed(packet(3, 2, 1, b"cd")).is_none());
        assert!(defragger.feed(packet(3, 2, 0, b"ab")).is_some());
    }

    #[test]
    fn a_different_frag_total_starts_a_new_message_on_the_same_packet_id() {
        let defragger = DeFragger::default();
        assert!(defragger.feed(packet(5, 2, 0, b"ab")).is_none());
        assert!(defragger.feed(packet(5, 4, 0, b"ab")).is_none());
        assert_eq!(held_fragments(&defragger, 5), 1);
        assert!(defragger.feed(packet(5, 2, 1, b"cd")).is_none());
    }

    #[derive(Default)]
    struct RecordingConn(Mutex<Vec<Vec<u8>>>);

    #[async_trait::async_trait]
    impl QuicConn for RecordingConn {
        fn local_addr(&self) -> Box<dyn murmur_std_compat::net::Addr> {
            unimplemented!("the fragment writer never reads the local address")
        }

        fn remote_addr(&self) -> Box<dyn murmur_std_compat::net::Addr> {
            unimplemented!("the fragment writer never reads the remote address")
        }

        fn close_with_error(&self, _code: u64, _reason: &str) -> anyhow::Result<()> {
            anyhow::bail!("the fragment writer never closes the connection")
        }

        fn config(&self) -> murmur_quic::Config {
            unimplemented!("the fragment writer never reads the config")
        }

        fn connection_stats(&self) -> murmur_quic::ConnectionStats {
            unimplemented!("the fragment writer never reads the stats")
        }

        fn connection_state(&self) -> murmur_quic::ConnectionState {
            unimplemented!("the fragment writer never reads the connection state")
        }

        fn context(&self) -> tokio_util::sync::CancellationToken {
            unimplemented!("the fragment writer never reads the context")
        }

        async fn handshake_complete(&self) {}

        fn export_keying_material(&self, _label: &[u8], _context: &[u8], _length: usize) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("the fragment writer never exports keying material")
        }

        async fn open_stream(
            &self,
            _ctx: &tokio_util::sync::CancellationToken,
        ) -> anyhow::Result<Box<dyn murmur_quic::Stream>> {
            anyhow::bail!("the fragment writer never opens a stream")
        }

        async fn open_uni_stream(
            &self,
            _ctx: &tokio_util::sync::CancellationToken,
        ) -> anyhow::Result<Box<dyn murmur_quic::SendStream>> {
            anyhow::bail!("the fragment writer never opens a uni stream")
        }

        async fn accept_stream(
            &self,
            _ctx: &tokio_util::sync::CancellationToken,
        ) -> anyhow::Result<Box<dyn murmur_quic::Stream>> {
            anyhow::bail!("the fragment writer never accepts a stream")
        }

        async fn accept_uni_stream(
            &self,
            _ctx: &tokio_util::sync::CancellationToken,
        ) -> anyhow::Result<Box<dyn murmur_quic::ReceiveStream>> {
            anyhow::bail!("the fragment writer never accepts a uni stream")
        }

        fn send_datagram(&self, data: &[u8]) -> anyhow::Result<()> {
            self.0.lock().push(data.to_vec());
            Ok(())
        }

        async fn receive_datagram(&self, _ctx: &tokio_util::sync::CancellationToken) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("the fragment writer never receives a datagram")
        }
    }

    /// Pins the frames a fragmented datagram is sent as: the address is written once, every later
    /// fragment carries `ATYP_NONE`, and each payload is the slice of the original it claims.
    #[tokio::test]
    async fn every_fragment_after_the_first_is_sent_without_an_address() {
        let conn = RecordingConn::default();
        let addr = protocol::new_address_addr_port(SocketAddr::from(([192, 0, 2, 1], 9)));
        let packet = protocol::new_packet(1, 4, 1, 0, 12, addr.clone(), bytes::Bytes::from_static(b"abcdefghijkl"));
        let mut buf = BytesMut::new();

        frag_write_native(&conn, packet, &mut buf, 5).await.expect("the fragments are sent");

        let sent = conn.0.lock().clone();
        assert_eq!(sent.len(), 3);
        let mut payloads = Vec::new();
        for (index, frame) in sent.iter().enumerate() {
            let mut cursor = std::io::Cursor::new(&frame[..]);
            let parsed = protocol::read_packet(&mut cursor).await.expect("the frame parses");
            assert_eq!(parsed.frag_total, 3);
            assert_eq!(usize::from(parsed.frag_id), index);
            assert_eq!(usize::from(parsed.size), parsed.data.len());
            if index == 0 {
                assert_eq!(parsed.addr.string(), addr.string());
            } else {
                assert_eq!(parsed.addr.type_, ATYP_NONE);
            }
            payloads.extend_from_slice(&parsed.data);
        }
        assert_eq!(payloads, b"abcdefghijkl");
    }

    /// A zero capacity has nothing to divide the payload into, so it must be rejected before any
    /// fragment is written rather than panicking inside `div_ceil`.
    #[tokio::test]
    async fn a_zero_fragment_capacity_is_rejected_before_any_fragment_is_sent() {
        let conn = RecordingConn::default();
        let addr = protocol::new_address_addr_port(SocketAddr::from(([192, 0, 2, 1], 9)));
        let packet = protocol::new_packet(1, 4, 1, 0, 4, addr, bytes::Bytes::from_static(b"abcd"));
        let mut buf = BytesMut::new();

        let err = frag_write_native(&conn, packet, &mut buf, 0).await.expect_err("a zero capacity must fail closed");

        assert!(
            matches!(err.downcast_ref::<FragmentCapacityError>(), Some(FragmentCapacityError::ZeroCapacity { .. })),
            "the error must name the unrepresentable capacity, got: {err}"
        );
        assert!(conn.0.lock().is_empty(), "a zero capacity must not write a fragment");
    }

    /// `frag_total` is one wire byte: a payload needing 256 fragments must be rejected instead of
    /// being written with `frag_total = 0` and, on the last fragment, overflowing `frag_id`.
    #[tokio::test]
    async fn a_payload_needing_more_than_two_hundred_and_fifty_five_fragments_is_rejected_without_a_partial_send() {
        let conn = RecordingConn::default();
        let addr = protocol::new_address_addr_port(SocketAddr::from(([192, 0, 2, 1], 9)));
        let payload = bytes::Bytes::from(vec![7u8; usize::from(u16::MAX)]);
        let packet = protocol::new_packet(1, 4, 1, 0, u16::MAX, addr, payload);
        let mut buf = BytesMut::new();

        let err =
            frag_write_native(&conn, packet, &mut buf, 256).await.expect_err("256 fragments do not fit the wire field");

        assert!(
            matches!(
                err.downcast_ref::<FragmentCapacityError>(),
                Some(FragmentCapacityError::CountOverflow { fragment_count: 256, .. })
            ),
            "the error must name the fragment count, got: {err}"
        );
        assert!(conn.0.lock().is_empty(), "a count above 255 must not write a partial fragment run");
    }

    /// The other side of the boundary: 255 fragments is the largest count the wire fields hold and
    /// must still be sent intact.
    #[tokio::test]
    async fn a_payload_needing_exactly_two_hundred_and_fifty_five_fragments_is_sent() {
        let conn = RecordingConn::default();
        let addr = protocol::new_address_addr_port(SocketAddr::from(([192, 0, 2, 1], 9)));
        let payload = vec![7u8; 255 * 256];
        let packet = protocol::new_packet(1, 4, 1, 0, u16::MAX, addr, bytes::Bytes::from(payload.clone()));
        let mut buf = BytesMut::new();

        frag_write_native(&conn, packet, &mut buf, 256).await.expect("255 fragments fit the wire fields");

        let sent = conn.0.lock().clone();
        assert_eq!(sent.len(), 255);
        let mut reassembled = Vec::new();
        for (index, frame) in sent.iter().enumerate() {
            let mut cursor = std::io::Cursor::new(&frame[..]);
            let parsed = protocol::read_packet(&mut cursor).await.expect("the frame parses");
            assert_eq!(parsed.frag_total, 255);
            assert_eq!(usize::from(parsed.frag_id), index);
            reassembled.extend_from_slice(&parsed.data);
        }
        assert_eq!(reassembled, payload);
    }
}

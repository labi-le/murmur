use std::sync::{Arc, LazyLock, OnceLock};

use bytes::BytesMut;
use parking_lot::Mutex;

use crate::quic::Conn as QuicConn;
use murmur_common::lru::{self, LruCache};

use super::protocol::{Packet, ATYP_NONE, PACKET_OVER_HEAD};

/// A safe UDP relay packet size.
///
/// The QUIC max datagram frame size is left alone because tuicv5 fragments UDP itself;
/// `1200` is the default max datagram size and `-3` the per-frame header overhead.
pub static MAX_FRAG_SIZE: LazyLock<usize> = LazyLock::new(|| 1200 - *PACKET_OVER_HEAD - 3);

pub(crate) async fn frag_write_native(
    quic_conn: &dyn QuicConn,
    mut packet: Packet,
    buf: &mut BytesMut,
    frag_size: usize,
) -> anyhow::Result<()> {
    let full_payload = packet.data.clone();
    let mut off = 0usize;
    let mut frag_id = 0u8;
    let frag_count = full_payload.len().div_ceil(frag_size);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the fragment count is bounded by the udp relay payload limit divided by the fragment size, which fits the single-byte wire field"
    )]
    let frag_total = frag_count as u8;
    packet.frag_total = frag_total;
    while off < full_payload.len() {
        let mut payload_size = full_payload.len() - off;
        if payload_size > frag_size {
            payload_size = frag_size;
        }
        let mut frag = packet.clone();
        frag.frag_id = frag_id;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the fragment payload is capped at `frag_size`, a datagram payload bound that fits the 16-bit wire field"
        )]
        let frag_len = payload_size as u16;
        frag.size = frag_len;
        frag.data = full_payload.slice(off..off + payload_size);
        off += payload_size;
        frag_id += 1;
        buf.clear();
        frag.write_to(buf);
        quic_conn.send_datagram(&buf[..])?;
        packet.addr.type_ = ATYP_NONE; // avoid "fragment 2/2: address in non-first fragment"
    }
    Ok(())
}

/// The bag's fields, held under one lock.
#[derive(Default)]
struct PacketBagState {
    frags: Vec<Option<Packet>>,
    count: u8,
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
        self.lru.get_or_init(|| lru::new(vec![lru::with_age(10), lru::with_update_age_on_get()]))
    }

    pub(crate) fn feed(&self, m: Packet) -> Option<Packet> {
        if m.frag_total <= 1 {
            return Some(m);
        }
        if m.frag_id >= m.frag_total {
            // wtf is this?
            return None;
        }
        let lru = self.lru();
        let (bag, _) = lru.get_or_store(m.pkt_id, || Arc::new(PacketBag::default()));
        let mut state = bag.state.lock();
        let frag_id = m.frag_id as usize;
        if usize::from(m.frag_total) != state.frags.len() {
            // new message, clear previous state
            state.frags = vec![None; m.frag_total as usize];
            state.count = 1;
            let slot = state.frags.get_mut(frag_id)?;
            *slot = Some(m);
            return None;
        }
        let pkt_id = m.pkt_id;
        let slot = state.frags.get_mut(frag_id)?;
        if slot.is_some() {
            return None;
        }
        *slot = Some(m);
        state.count += 1;
        if usize::from(state.count) != state.frags.len() {
            return None;
        }

        // all fragments received, assemble
        let mut data = Vec::new();
        for frag in state.frags.iter().flatten() {
            data.extend_from_slice(&frag.data);
        }
        let mut p = state.frags.first().cloned().flatten()?;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the reassembled payload is bounded by the original udp datagram size, which fits the 16-bit wire field"
        )]
        let reassembled_len = data.len() as u16;
        p.size = reassembled_len;
        p.data = bytes::Bytes::from(data);
        p.frag_id = 0;
        p.frag_total = 1;
        state.frags = Vec::new();
        drop(state);
        lru.delete(pkt_id);
        Some(p)
    }
}

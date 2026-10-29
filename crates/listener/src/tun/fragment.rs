//! IPv4 and IPv6 fragment reassembly for the TUN reader.
//!
//! A TUN device delivers one IP packet per read, so a datagram larger than the path MTU arrives as
//! several fragments. The transport parse has no fragment handling: a non-first fragment would be
//! read as if its payload began with a transport header, and its arbitrary port bytes would be
//! forwarded as a real flow. This cache collects fragments, refuses conflicting overlap, and hands
//! the reader one whole IP packet.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::packet::checksum;

/// Concurrent reassemblies. Each holds at most one 65,535-byte datagram, so this bounds the cache
/// at roughly 4 MiB while leaving ample room for the handful of fragmented flows a router sees.
const MAX_REASSEMBLIES: usize = 64;

/// A datagram whose fragments take longer than this is discarded, as RFC 791 requires of a
/// reassembly that cannot complete.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest payload an IP datagram can carry.
const MAX_DATAGRAM: usize = 65_535;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const IPV6_FRAGMENT_HEADER_LEN: usize = 8;
const IPPROTO_FRAGMENT: u8 = 44;

/// What the reader should do with one packet from the device.
#[derive(Debug)]
pub enum FragmentOutcome {
    /// A whole packet, which the caller parses as before.
    NotFragmented,
    /// A fragment was stored; nothing to forward yet.
    Pending,
    /// The last missing fragment arrived and this is the reassembled IP packet.
    Complete(Vec<u8>),
    /// A fragment was refused; the reason names the shape that was rejected.
    Dropped(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Key {
    V4 { src: Ipv4Addr, dst: Ipv4Addr, id: u16, protocol: u8 },
    V6 { src: Ipv6Addr, dst: Ipv6Addr, id: u32, next_header: u8 },
}

#[derive(Debug)]
struct Entry {
    buffer: Vec<u8>,
    /// Non-overlapping, sorted, merged `[start, end)` byte ranges present in `buffer`.
    covered: Vec<(usize, usize)>,
    /// The value of the last fragment's end offset, once that fragment has arrived.
    total: Option<usize>,
    /// The IPv4 header (including options) or the IPv6 base header of the first fragment.
    header: Vec<u8>,
    deadline: Instant,
}

impl Entry {
    fn new(header: Vec<u8>, deadline: Instant) -> Self {
        Self { buffer: Vec::new(), covered: Vec::new(), total: None, header, deadline }
    }

    /// Stores `data` at `offset`, refusing a differing overlap and merging adjacent ranges.
    fn insert(&mut self, offset: usize, data: &[u8]) -> Result<(), &'static str> {
        let end = offset.checked_add(data.len()).ok_or("fragment offset overflow")?;
        if end > MAX_DATAGRAM {
            return Err("fragment past the maximum datagram size");
        }
        for &(start, covered_end) in &self.covered {
            if start < end && offset < covered_end {
                let from = start.max(offset);
                let to = covered_end.min(end);
                if self.buffer.get(from..to) != data.get(from - offset..to - offset) {
                    return Err("conflicting fragment overlap");
                }
            }
        }
        if self.buffer.len() < end {
            self.buffer.resize(end, 0);
        }
        self.buffer.get_mut(offset..end).ok_or("fragment offset outside the buffer")?.copy_from_slice(data);

        let mut merged = Vec::with_capacity(self.covered.len() + 1);
        let mut start = offset;
        let mut finish = end;
        for &(covered_start, covered_end) in &self.covered {
            if covered_end < start || covered_start > finish {
                merged.push((covered_start, covered_end));
            } else {
                start = start.min(covered_start);
                finish = finish.max(covered_end);
            }
        }
        merged.push((start, finish));
        merged.sort_unstable();
        self.covered = merged;
        Ok(())
    }

    /// Adds one fragment and reports the completed payload once the last one is present.
    fn absorb(&mut self, offset: usize, body: &[u8], more_fragments: bool) -> Result<Option<Vec<u8>>, &'static str> {
        self.insert(offset, body)?;
        if !more_fragments {
            if self.total.is_some_and(|existing| existing != offset + body.len()) {
                return Err("conflicting fragment total length");
            }
            self.total = Some(offset + body.len());
        }
        if self.total.is_some() {
            Ok(self.complete().map(<[u8]>::to_vec))
        } else {
            Ok(None)
        }
    }

    /// Whether every byte from zero through the declared total is present.
    fn complete(&self) -> Option<&[u8]> {
        let total = self.total?;
        if total == 0 || total > MAX_DATAGRAM {
            return None;
        }
        match self.covered.as_slice() {
            [(0, end)] if *end == total => self.buffer.get(..total),
            _ => None,
        }
    }
}

/// Fragments seen so far, keyed by the RFC 791/8200 identity of their datagram.
#[derive(Debug)]
pub struct FragmentCache {
    entries: HashMap<Key, Entry>,
}

impl Default for FragmentCache {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentCache {
    #[must_use]
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Feeds one packet read from the device. `now` is passed in so the timeout policy is
    /// testable without sleeping.
    pub fn feed(&mut self, packet: &[u8], now: Instant) -> FragmentOutcome {
        self.expire(now);
        match packet.first().map(|byte| byte >> 4) {
            Some(4) => self.feed_ipv4(packet, now),
            Some(6) => self.feed_ipv6(packet, now),
            _ => FragmentOutcome::NotFragmented,
        }
    }

    fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, entry| entry.deadline > now);
    }

    fn feed_ipv4(&mut self, packet: &[u8], now: Instant) -> FragmentOutcome {
        let Some(header) = packet.first_chunk::<IPV4_HEADER_LEN>() else {
            return FragmentOutcome::NotFragmented;
        };
        let header_len = usize::from(header[0] & 0x0f) * 4;
        if header_len < IPV4_HEADER_LEN || header_len > packet.len() {
            return FragmentOutcome::NotFragmented;
        }
        let total_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if total_len < header_len || total_len > packet.len() {
            return FragmentOutcome::NotFragmented;
        }
        let flags_offset = u16::from_be_bytes([header[6], header[7]]);
        let more_fragments = flags_offset & 0x2000 != 0;
        let offset = usize::from(flags_offset & 0x1fff) * 8;
        if !more_fragments && offset == 0 {
            return FragmentOutcome::NotFragmented;
        }
        let src = Ipv4Addr::new(header[12], header[13], header[14], header[15]);
        let dst = Ipv4Addr::new(header[16], header[17], header[18], header[19]);
        let key = Key::V4 { src, dst, id: u16::from_be_bytes([header[4], header[5]]), protocol: header[9] };
        let body = packet.get(header_len..total_len).unwrap_or_default();
        let stored = {
            let Some(entry) = self.entry(key, || header.to_vec(), now) else {
                return FragmentOutcome::Dropped("fragment cache is full");
            };
            entry.absorb(offset, body, more_fragments)
        };
        match stored {
            Err(reason) => {
                self.entries.remove(&key);
                FragmentOutcome::Dropped(reason)
            }
            Ok(None) => FragmentOutcome::Pending,
            Ok(Some(payload)) => match self.entries.remove(&key) {
                Some(entry) => build_ipv4(&entry.header, &payload),
                None => FragmentOutcome::Dropped("fragment entry vanished"),
            },
        }
    }

    fn feed_ipv6(&mut self, packet: &[u8], now: Instant) -> FragmentOutcome {
        let Some(header) = packet.first_chunk::<IPV6_HEADER_LEN>() else {
            return FragmentOutcome::NotFragmented;
        };
        if header[6] != IPPROTO_FRAGMENT {
            return FragmentOutcome::NotFragmented;
        }
        let payload_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
        let total_len = IPV6_HEADER_LEN + payload_len;
        if total_len > packet.len() || payload_len < IPV6_FRAGMENT_HEADER_LEN {
            return FragmentOutcome::NotFragmented;
        }
        let Some(fragment) = packet.get(IPV6_HEADER_LEN..total_len) else {
            return FragmentOutcome::NotFragmented;
        };
        let Some(fragment_header) = fragment.first_chunk::<IPV6_FRAGMENT_HEADER_LEN>() else {
            return FragmentOutcome::NotFragmented;
        };
        let next_header = fragment_header[0];
        let offset_field = u16::from_be_bytes([fragment_header[2], fragment_header[3]]);
        let more_fragments = offset_field & 1 != 0;
        let offset = usize::from((offset_field >> 3) & 0x1fff) * 8;
        if !more_fragments && offset == 0 {
            let body = fragment.get(IPV6_FRAGMENT_HEADER_LEN..).unwrap_or_default();
            return build_ipv6(header, body, next_header);
        }
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&header[8..24]);
        dst.copy_from_slice(&header[24..40]);
        let id = u32::from_be_bytes([fragment_header[4], fragment_header[5], fragment_header[6], fragment_header[7]]);
        let key = Key::V6 { src: Ipv6Addr::from(src), dst: Ipv6Addr::from(dst), id, next_header };
        let body = fragment.get(IPV6_FRAGMENT_HEADER_LEN..).unwrap_or_default();
        let stored = {
            let Some(entry) = self.entry(key, || header.to_vec(), now) else {
                return FragmentOutcome::Dropped("fragment cache is full");
            };
            entry.absorb(offset, body, more_fragments)
        };
        match stored {
            Err(reason) => {
                self.entries.remove(&key);
                FragmentOutcome::Dropped(reason)
            }
            Ok(None) => FragmentOutcome::Pending,
            Ok(Some(payload)) => match self.entries.remove(&key) {
                Some(entry) => build_ipv6(&entry.header, &payload, next_header),
                None => FragmentOutcome::Dropped("fragment entry vanished"),
            },
        }
    }

    fn entry(&mut self, key: Key, header: impl FnOnce() -> Vec<u8>, now: Instant) -> Option<&mut Entry> {
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_REASSEMBLIES {
            return None;
        }
        Some(self.entries.entry(key).or_insert_with(|| Entry::new(header(), now + REASSEMBLY_TIMEOUT)))
    }
}

fn put(header: &mut [u8], at: std::ops::Range<usize>, value: &[u8]) -> bool {
    header.get_mut(at).is_some_and(|field| {
        field.copy_from_slice(value);
        true
    })
}

fn build_ipv4(header: &[u8], payload: &[u8]) -> FragmentOutcome {
    let Some(mut header) = header.get(..IPV4_HEADER_LEN).map(<[u8]>::to_vec) else {
        return FragmentOutcome::Dropped("missing IPv4 header");
    };
    let Some(total_len) = header.len().checked_add(payload.len()).and_then(|len| u16::try_from(len).ok()) else {
        return FragmentOutcome::Dropped("reassembled datagram exceeds the IPv4 size");
    };
    let mut packet = Vec::with_capacity(usize::from(total_len));
    let Some(version_ihl) = header.get_mut(0) else {
        return FragmentOutcome::Dropped("truncated IPv4 header");
    };
    // The reassembled packet carries no options, so its header length is the fixed five words.
    *version_ihl = (*version_ihl & 0xf0) | 5;
    if !put(&mut header, 2..4, &total_len.to_be_bytes())
        || !put(&mut header, 6..8, &[0, 0])
        || !put(&mut header, 10..12, &[0, 0])
    {
        return FragmentOutcome::Dropped("truncated IPv4 header");
    }
    let sum = checksum(&[&header]);
    if !put(&mut header, 10..12, &sum.to_be_bytes()) {
        return FragmentOutcome::Dropped("truncated IPv4 header");
    }
    packet.extend_from_slice(&header);
    packet.extend_from_slice(payload);
    FragmentOutcome::Complete(packet)
}

fn build_ipv6(header: &[u8], payload: &[u8], next_header: u8) -> FragmentOutcome {
    let Some(mut header) = header.get(..IPV6_HEADER_LEN).map(<[u8]>::to_vec) else {
        return FragmentOutcome::Dropped("missing IPv6 header");
    };
    let Ok(payload_len) = u16::try_from(payload.len()) else {
        return FragmentOutcome::Dropped("reassembled datagram exceeds the IPv6 payload size");
    };
    let Some(next) = header.get_mut(6) else {
        return FragmentOutcome::Dropped("truncated IPv6 header");
    };
    *next = next_header;
    if !put(&mut header, 4..6, &payload_len.to_be_bytes()) {
        return FragmentOutcome::Dropped("truncated IPv6 header");
    }
    let mut packet = Vec::with_capacity(header.len() + payload.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(payload);
    FragmentOutcome::Complete(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &[u8] = b"the quick brown fox jumps over the lazy dog, twice over for a fragment boundary";

    fn ipv4_fragment(offset: usize, more: bool, id: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; IPV4_HEADER_LEN];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((IPV4_HEADER_LEN + payload.len()) as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        let mut flags = ((offset / 8) as u16) & 0x1fff;
        if more {
            flags |= 0x2000;
        }
        packet[6..8].copy_from_slice(&flags.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 2]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet.extend_from_slice(payload);
        packet
    }

    fn ipv6_fragment(offset: usize, more: bool, id: u32, next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; IPV6_HEADER_LEN];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((IPV6_FRAGMENT_HEADER_LEN + payload.len()) as u16).to_be_bytes());
        packet[6] = IPPROTO_FRAGMENT;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        let flags = (((offset / 8) as u16) & 0x1fff) << 3 | u16::from(more);
        packet.extend_from_slice(&[next_header, 0]);
        packet.extend_from_slice(&flags.to_be_bytes());
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn ipv4_fragments_reassemble_out_of_order() {
        let now = Instant::now();
        let mut cache = FragmentCache::new();
        let first = &PAYLOAD[..24];
        let second = &PAYLOAD[24..];
        assert!(matches!(cache.feed(&ipv4_fragment(24, false, 7, second), now), FragmentOutcome::Pending));
        let FragmentOutcome::Complete(packet) = cache.feed(&ipv4_fragment(0, true, 7, first), now) else {
            panic!("the datagram should complete");
        };
        assert_eq!(packet[9], 17);
        assert_eq!(&packet[IPV4_HEADER_LEN..], PAYLOAD);
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), (IPV4_HEADER_LEN + PAYLOAD.len()) as u16);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0);
        assert_eq!(checksum(&[&packet[..IPV4_HEADER_LEN]]), 0);
    }

    #[test]
    fn conflicting_overlap_discards_the_datagram() {
        let now = Instant::now();
        let mut cache = FragmentCache::new();
        assert!(matches!(cache.feed(&ipv4_fragment(0, true, 9, &PAYLOAD[..24]), now), FragmentOutcome::Pending));
        let mut different = PAYLOAD[16..].to_vec();
        different[0] ^= 0xff;
        assert!(matches!(cache.feed(&ipv4_fragment(16, false, 9, &different), now), FragmentOutcome::Dropped(_)));
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn a_reassembly_times_out() {
        let now = Instant::now();
        let mut cache = FragmentCache::new();
        assert!(matches!(cache.feed(&ipv4_fragment(0, true, 11, &PAYLOAD[..24]), now), FragmentOutcome::Pending));
        assert!(matches!(
            cache.feed(&ipv4_fragment(0, false, 12, PAYLOAD), now + REASSEMBLY_TIMEOUT),
            FragmentOutcome::NotFragmented
        ));
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn ipv6_fragments_reassemble_and_strip_the_fragment_header() {
        let now = Instant::now();
        let mut cache = FragmentCache::new();
        let first = &PAYLOAD[..32];
        let second = &PAYLOAD[32..];
        assert!(matches!(cache.feed(&ipv6_fragment(0, true, 21, 17, first), now), FragmentOutcome::Pending));
        let FragmentOutcome::Complete(packet) = cache.feed(&ipv6_fragment(32, false, 21, 17, second), now) else {
            panic!("the datagram should complete");
        };
        assert_eq!(packet[6], 17);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]) as usize, PAYLOAD.len());
        assert_eq!(&packet[IPV6_HEADER_LEN..], PAYLOAD);
    }

    #[test]
    fn ipv4_fragments_with_options_are_rebuilt_with_a_fixed_header() {
        fn fragment_with_options(offset: usize, more: bool, payload: &[u8]) -> Vec<u8> {
            let mut packet = vec![0u8; IPV4_HEADER_LEN + 4];
            packet[0] = 0x46;
            packet[2..4].copy_from_slice(&((IPV4_HEADER_LEN + 4 + payload.len()) as u16).to_be_bytes());
            packet[4..6].copy_from_slice(&77u16.to_be_bytes());
            let mut flags = ((offset / 8) as u16) & 0x1fff;
            if more {
                flags |= 0x2000;
            }
            packet[6..8].copy_from_slice(&flags.to_be_bytes());
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&[192, 0, 2, 2]);
            packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
            packet[20..24].copy_from_slice(&[1, 1, 1, 0]);
            packet.extend_from_slice(payload);
            packet
        }

        let now = Instant::now();
        let mut cache = FragmentCache::new();
        assert!(matches!(cache.feed(&fragment_with_options(0, true, &PAYLOAD[..24]), now), FragmentOutcome::Pending));
        let FragmentOutcome::Complete(packet) = cache.feed(&fragment_with_options(24, false, &PAYLOAD[24..]), now)
        else {
            panic!("the datagram should complete");
        };
        assert_eq!(packet[0], 0x45, "the reassembled header must not advertise options");
        assert_eq!(&packet[IPV4_HEADER_LEN..], PAYLOAD);
        assert_eq!(checksum(&[&packet[..IPV4_HEADER_LEN]]), 0);
    }

    #[test]
    fn a_whole_packet_is_left_to_the_normal_parser() {
        let now = Instant::now();
        let mut cache = FragmentCache::new();
        assert!(matches!(cache.feed(&ipv4_fragment(0, false, 31, PAYLOAD), now), FragmentOutcome::NotFragmented));
        let mut whole = vec![0u8; IPV6_HEADER_LEN];
        whole[0] = 0x60;
        whole[4..6].copy_from_slice(&(PAYLOAD.len() as u16).to_be_bytes());
        whole[6] = 17;
        whole[7] = 64;
        whole[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        whole[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        whole.extend_from_slice(PAYLOAD);
        assert!(matches!(cache.feed(&whole, now), FragmentOutcome::NotFragmented));
    }

    #[test]
    fn an_ipv6_atomic_fragment_is_completed_without_the_fragment_header() {
        let now = Instant::now();
        let mut cache = FragmentCache::new();
        let FragmentOutcome::Complete(packet) = cache.feed(&ipv6_fragment(0, false, 33, 17, PAYLOAD), now) else {
            panic!("the atomic fragment should complete");
        };
        assert_eq!(packet[6], 17);
        assert_eq!(&packet[IPV6_HEADER_LEN..], PAYLOAD);
    }
}

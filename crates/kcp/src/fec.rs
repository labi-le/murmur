//! The FEC packet framing: seqid/flag headers, shard-set bookkeeping and the out-of-order/loss
//! recovery window.
//!
//! The GF(256) erasure coding itself is delegated to `reed_solomon_turbo::ReedSolomon` rather than
//! a hand-rolled Cauchy matrix. Its parity codewords are byte-identical to the standard encoder's,
//! so a parity shard generated here reconstructs a lost shard on any peer of the same family. With
//! no loss FEC is wire-transparent: parity shards are extra UDP packets a data-only receiver
//! ignores.

use std::collections::HashMap;

use reed_solomon_turbo::ReedSolomon;

use crate::autotune::AutoTune;

pub const FEC_HEADER_SIZE: usize = 6;
pub const FEC_HEADER_SIZE_PLUS2: usize = FEC_HEADER_SIZE + 2;
pub const TYPE_DATA: u16 = 0xf1;
pub const TYPE_PARITY: u16 = 0xf2;
pub const TYPE_OOB: u16 = 0xf3;
const MAX_SHARD_SETS: u32 = 3;

fn itimediff(later: u32, earlier: u32) -> i32 {
    later.wrapping_sub(earlier).cast_signed()
}

/// A shard group's width as the `u32` the sequence arithmetic divides by. Both constructors take
/// shard counts of at least 1 and at most `i32::MAX`, so their sum always fits a `u32`.
fn shard_size_u32(shard_size: usize) -> u32 {
    u32::try_from(shard_size).unwrap_or(u32::MAX)
}

/// The `(data, parity)` split an autotuned FEC period implies: `None` when either count is
/// non-positive, when the pair exceeds the 256-shard ceiling, or when nothing changed.
fn autotuned_split(
    auto_data: i32,
    auto_parity: i32,
    data_shards: usize,
    parity_shards: usize,
) -> Option<(usize, usize)> {
    let auto_data = usize::try_from(auto_data).ok()?;
    let auto_parity = usize::try_from(auto_parity).ok()?;
    if auto_data == 0 || auto_parity == 0 || auto_data + auto_parity >= 256 {
        return None;
    }
    if auto_data == data_shards && auto_parity == parity_shards {
        return None;
    }
    Some((auto_data, auto_parity))
}

/// The 2-byte little-endian FEC length prefix of a payload.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the FEC frame carries the payload length in a 16-bit field by definition"
)]
fn fec_length_prefix(len: usize) -> [u8; 2] {
    (len as u16).to_le_bytes()
}

/// A decoded FEC packet view (`seqid` u32 LE, `flag` u16 LE, then payload).
#[derive(Clone)]
pub(crate) struct FecPacket(pub Vec<u8>);

impl FecPacket {
    fn seqid(&self) -> u32 {
        self.0.get(..4).and_then(|seqid| seqid.try_into().ok()).map_or(0, u32::from_le_bytes)
    }
    fn flag(&self) -> u16 {
        self.0.get(4..6).and_then(|flag| flag.try_into().ok()).map_or(0, u16::from_le_bytes)
    }
    fn data(&self) -> &[u8] {
        self.0.get(FEC_HEADER_SIZE..).unwrap_or_default()
    }
}

/// The shard heap, keyed the same way as `core::SegmentHeap`: a small unordered `Vec` plus a
/// `marks` set for duplicate detection (the shard count per set is bounded by
/// `dataShards+parityShards`, at most 256).
#[derive(Default)]
struct ShardHeap {
    elements: Vec<FecPacket>,
}

impl ShardHeap {
    fn has(&self, sn: u32) -> bool {
        self.elements.iter().any(|p| p.seqid() == sn)
    }
    fn len(&self) -> usize {
        self.elements.len()
    }
}

pub struct FecDecoder {
    data_shards: usize,
    parity_shards: usize,
    shard_size: usize,
    shard_set: HashMap<u32, ShardHeap>,
    paws: u32,
    newest_shard_id: u32,
    codec: ReedSolomon,
    auto_tune: AutoTune,
    should_tune: bool,
}

impl core::fmt::Debug for FecDecoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FecDecoder")
            .field("data_shards", &self.data_shards)
            .field("parity_shards", &self.parity_shards)
            .field("shard_size", &self.shard_size)
            .field("shard_sets", &self.shard_set.len())
            .finish_non_exhaustive()
    }
}

impl FecDecoder {
    /// Returns `None` when FEC is disabled (either shard count is zero) or the requested split
    /// is invalid.
    #[must_use]
    pub fn new(data_shards: i32, parity_shards: i32) -> Option<Self> {
        if data_shards <= 0 || parity_shards <= 0 || data_shards + parity_shards > 256 {
            return None;
        }
        let (data_shards, parity_shards) = (usize::try_from(data_shards).ok()?, usize::try_from(parity_shards).ok()?);
        let shard_size = data_shards + parity_shards;
        let codec = ReedSolomon::new(data_shards, parity_shards).ok()?;
        let width = shard_size_u32(shard_size);
        Some(Self {
            data_shards,
            parity_shards,
            shard_size,
            shard_set: HashMap::new(),
            paws: u32::MAX / width * width,
            newest_shard_id: 0,
            codec,
            auto_tune: AutoTune::default(),
            should_tune: false,
        })
    }

    fn get_shard_id(&self, seqid: u32) -> u32 {
        seqid / shard_size_u32(self.shard_size)
    }

    fn discard_shards(&mut self) {
        let newest = self.newest_shard_id;
        let shard_size = shard_size_u32(self.shard_size);
        self.shard_set.retain(|shard_id, _| {
            itimediff(newest * shard_size, shard_id * shard_size) <= (MAX_SHARD_SETS * shard_size).cast_signed()
        });
    }

    /// Decodes a packet: returns recovered data-shard payloads (already stripped of the
    /// FEC header, via the 2-byte length-prefix convention downstream).
    pub fn decode(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        let inp = FecPacket(packet.to_vec());
        self.auto_tune.sample(inp.flag() == TYPE_DATA, inp.seqid());

        if inp.seqid() >= self.paws {
            return Vec::new();
        }

        let shard_size = shard_size_u32(self.shard_size);
        if ((inp.seqid() % shard_size) as usize) < self.data_shards {
            if inp.flag() != TYPE_DATA {
                self.should_tune = true;
            }
        } else if inp.flag() != TYPE_PARITY {
            self.should_tune = true;
        }

        if self.should_tune {
            let auto_data = self.auto_tune.find_period(true);
            let auto_parity = self.auto_tune.find_period(false);
            if let Some((data_shards, parity_shards)) =
                autotuned_split(auto_data, auto_parity, self.data_shards, self.parity_shards)
            {
                if let Ok(codec) = ReedSolomon::new(data_shards, parity_shards) {
                    self.data_shards = data_shards;
                    self.parity_shards = parity_shards;
                    self.shard_size = data_shards + parity_shards;
                    self.shard_set.clear();
                    self.codec = codec;
                    let width = shard_size_u32(self.shard_size);
                    self.paws = u32::MAX / width * width;
                    self.should_tune = false;
                }
            }
            return Vec::new();
        }

        let shard_id = self.get_shard_id(inp.seqid());
        let shard = self.shard_set.entry(shard_id).or_default();

        if shard.has(inp.seqid()) {
            return Vec::new();
        }
        shard.elements.push(inp);

        let mut recovered = Vec::new();
        if shard.len() >= self.data_shards {
            let pkts: Vec<FecPacket> = self.shard_set.remove(&shard_id).unwrap_or_default().elements;

            let mut shards: Vec<Option<Vec<u8>>> = vec![None; self.shard_size];
            let mut present = vec![false; self.shard_size];
            let mut num_data_shard = 0;
            let mut maxlen = 0usize;
            for pkt in &pkts {
                let idx = (pkt.seqid() % shard_size) as usize;
                if let Some(shard) = shards.get_mut(idx) {
                    *shard = Some(pkt.data().to_vec());
                }
                if let Some(seen) = present.get_mut(idx) {
                    *seen = true;
                }
                if pkt.flag() == TYPE_DATA {
                    num_data_shard += 1;
                }
                maxlen = maxlen.max(pkt.data().len());
            }

            if num_data_shard != self.data_shards {
                let mut have: Vec<(Vec<u8>, bool)> = shards
                    .into_iter()
                    .zip(present.iter().copied())
                    .map(|(shard, seen)| {
                        let mut buf = shard.unwrap_or_default();
                        buf.resize(maxlen, 0);
                        (buf, seen)
                    })
                    .collect();
                if self.codec.reconstruct_data(&mut have).is_ok() {
                    for ((data, _), seen) in have.iter().take(self.data_shards).zip(&present) {
                        if !seen {
                            recovered.push(data.clone());
                        }
                    }
                }
            }
        }

        if itimediff(shard_id * shard_size, self.newest_shard_id * shard_size) > 0 {
            self.newest_shard_id = shard_id;
        }
        self.discard_shards();

        recovered
    }
}

pub struct FecEncoder {
    data_shards: usize,
    parity_shards: usize,
    paws: u32,
    next: u32,

    shard_count: usize,
    max_size: usize,

    header_offset: usize,
    payload_offset: usize,

    shard_cache: Vec<Vec<u8>>,
    ts_latest_packet: i64,

    codec: ReedSolomon,
}

impl core::fmt::Debug for FecEncoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FecEncoder")
            .field("data_shards", &self.data_shards)
            .field("parity_shards", &self.parity_shards)
            .field("shard_count", &self.shard_count)
            .field("max_size", &self.max_size)
            .finish_non_exhaustive()
    }
}

impl FecEncoder {
    #[must_use]
    pub fn new(data_shards: i32, parity_shards: i32, offset: usize) -> Option<Self> {
        if data_shards <= 0 || parity_shards <= 0 {
            return None;
        }
        let (data_shards, parity_shards) = (usize::try_from(data_shards).ok()?, usize::try_from(parity_shards).ok()?);
        let shard_size = data_shards + parity_shards;
        let codec = ReedSolomon::new(data_shards, parity_shards).ok()?;
        let width = shard_size_u32(shard_size);
        Some(Self {
            data_shards,
            parity_shards,
            paws: u32::MAX / width * width,
            next: 0,
            shard_count: 0,
            max_size: 0,
            header_offset: offset,
            payload_offset: offset + FEC_HEADER_SIZE,
            shard_cache: (0..shard_size).map(|_| vec![0u8; crate::crypt::MTU_LIMIT]).collect(),
            ts_latest_packet: 0,
            codec,
        })
    }

    fn seal_data(&mut self, data: &mut [u8]) {
        let Some(header) = data.first_chunk_mut::<FEC_HEADER_SIZE>() else {
            return;
        };
        let (seqid, flag) = header.split_at_mut(4);
        seqid.copy_from_slice(&self.next.to_le_bytes());
        flag.copy_from_slice(&TYPE_DATA.to_le_bytes());
        self.next = (self.next + 1) % self.paws;
    }

    fn skip_parity(&mut self) {
        self.next = (self.next + shard_size_u32(self.parity_shards)) % self.paws;
    }

    /// Encodes a shard: `b` is the buffer with `header_offset` bytes reserved at the
    /// front for the FEC header (already written by the caller with zeroed placeholder bytes).
    /// `rto` is in milliseconds. Returns parity shard buffers to send alongside `b`, if this
    /// call completed a full data-shard group.
    pub fn encode(&mut self, b: &mut [u8], rto: u32) -> Vec<Vec<u8>> {
        let Some(fec_header) = b.get_mut(self.header_offset..) else {
            return Vec::new();
        };
        self.seal_data(fec_header);
        let len = b.len() - self.payload_offset;
        if let Some(prefix) = b.get_mut(self.payload_offset..self.payload_offset + 2) {
            prefix.copy_from_slice(&fec_length_prefix(len));
        }

        let sz = b.len();
        let Some(slot) = self.shard_cache.get_mut(self.shard_count) else {
            return Vec::new();
        };
        slot.resize(sz, 0);
        if let (Some(dst), Some(src)) = (slot.get_mut(self.payload_offset..), b.get(self.payload_offset..)) {
            dst.copy_from_slice(src);
        }
        self.shard_count += 1;
        self.max_size = self.max_size.max(sz);

        let now = now_millis();
        let mut ps = Vec::new();
        if self.shard_count == self.data_shards {
            if now - self.ts_latest_packet < i64::from(rto) {
                for shard in self.shard_cache.iter_mut().take(self.data_shards) {
                    shard.resize(self.max_size, 0);
                }

                let mut cache: Vec<Vec<u8>> = self
                    .shard_cache
                    .iter()
                    .map(|s| s.get(self.payload_offset..self.max_size).unwrap_or_default().to_vec())
                    .collect();

                if self.codec.encode(&mut cache).is_ok() {
                    for k in 0..self.parity_shards {
                        let shard_idx = self.data_shards + k;
                        let (Some(src), Some(dst)) = (cache.get(shard_idx), self.shard_cache.get_mut(shard_idx)) else {
                            continue;
                        };
                        dst.resize(self.max_size, 0);
                        if let Some(dst_payload) = dst.get_mut(self.payload_offset..) {
                            dst_payload.copy_from_slice(src);
                        }
                        let mut parity_header = [0u8; FEC_HEADER_SIZE];
                        let (seqid, flag) = parity_header.split_at_mut(4);
                        seqid.copy_from_slice(&self.next.to_le_bytes());
                        flag.copy_from_slice(&TYPE_PARITY.to_le_bytes());
                        if let Some(dst_header) = dst.get_mut(self.header_offset..self.header_offset + FEC_HEADER_SIZE)
                        {
                            dst_header.copy_from_slice(&parity_header);
                        }
                        self.next = (self.next + 1) % self.paws;
                        if let Some(shard) = dst.get(..self.max_size) {
                            ps.push(shard.to_vec());
                        }
                    }
                } else {
                    self.skip_parity();
                }
            } else {
                self.skip_parity();
            }

            self.shard_count = 0;
            self.max_size = 0;
        }

        self.ts_latest_packet = now;
        ps
    }
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

//! The sync ARQ core. Window sizes, RTO calculation, fast-resend, congestion window and NODELAY
//! modes are wire-compatible byte-for-byte with a real KCP peer.
//!
//! Buffer-pool recycling is intentionally not implemented: it is a pure allocator optimization
//! with no wire effect, and a `Vec<u8>` per segment is simpler and just as correct.

use std::collections::{HashSet, VecDeque};

pub const IKCP_RTO_NDL: u32 = 30;
pub const IKCP_RTO_MIN: u32 = 100;
pub const IKCP_RTO_DEF: u32 = 200;
pub const IKCP_RTO_MAX: u32 = 60000;
pub const IKCP_CMD_PUSH: u8 = 81;
pub const IKCP_CMD_ACK: u8 = 82;
pub const IKCP_CMD_WASK: u8 = 83;
pub const IKCP_CMD_WINS: u8 = 84;
pub const IKCP_ASK_SEND: u32 = 1;
pub const IKCP_ASK_TELL: u32 = 2;
pub const IKCP_WND_SND: u32 = 32;
pub const IKCP_WND_RCV: u32 = 32;
pub const IKCP_MTU_DEF: u32 = 1400;
pub const IKCP_OVERHEAD: u32 = 24;
pub const IKCP_DEADLINK: u32 = 20;
pub const IKCP_THRESH_INIT: u32 = 2;
pub const IKCP_THRESH_MIN: u32 = 2;
pub const IKCP_PROBE_INIT: u32 = 500;
pub const IKCP_PROBE_LIMIT: u32 = 120_000;
pub const IKCP_SN_OFFSET: usize = 12;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PacketType {
    Regular,
    Fec,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FlushType {
    AckOnly,
    Full,
}

fn itimediff(later: u32, earlier: u32) -> i32 {
    later.wrapping_sub(earlier).cast_signed()
}

fn ibound(lower: u32, middle: u32, upper: u32) -> u32 {
    lower.max(middle).min(upper)
}

/// Writes `segment`'s encoded header at `pos` in `buffer`, if it fits.
fn encode_segment_at(buffer: &mut [u8], pos: usize, segment: &Segment) {
    if let Some(slot) = buffer.get_mut(pos..pos + IKCP_OVERHEAD as usize) {
        segment.encode(slot);
    }
}

#[derive(Clone, Default)]
pub(crate) struct Segment {
    pub conv: u32,
    pub cmd: u8,
    pub frg: u8,
    pub wnd: u16,
    pub ts: u32,
    pub sn: u32,
    pub una: u32,
    pub rto: u32,
    pub xmit: u32,
    pub resendts: u32,
    pub fastack: u32,
    pub acked: bool,
    pub data: Vec<u8>,
}

impl Segment {
    fn new(size: usize) -> Self {
        Self {
            conv: 0,
            cmd: 0,
            frg: 0,
            wnd: 0,
            ts: 0,
            sn: 0,
            una: 0,
            rto: 0,
            xmit: 0,
            resendts: 0,
            fastack: 0,
            acked: false,
            data: vec![0u8; size],
        }
    }

    /// Writes the 24-byte KCP header into `out[..24]`.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a segment payload is bounded by the MTU, so its length always fits the 32-bit length field"
    )]
    fn encode(&self, out: &mut [u8]) {
        let Some(out) = out.first_chunk_mut::<24>() else {
            return;
        };
        out[0..4].copy_from_slice(&self.conv.to_le_bytes());
        out[4] = self.cmd;
        out[5] = self.frg;
        out[6..8].copy_from_slice(&self.wnd.to_le_bytes());
        out[8..12].copy_from_slice(&self.ts.to_le_bytes());
        out[12..16].copy_from_slice(&self.sn.to_le_bytes());
        out[16..20].copy_from_slice(&self.una.to_le_bytes());
        out[20..24].copy_from_slice(&(self.data.len() as u32).to_le_bytes());
    }
}

/// A min-heap of segments ordered by wrap-safe `sn` distance, used for
/// out-of-order receive reassembly. Implemented as a plain `Vec` with linear-scan
/// min-extraction: the window is small (a couple hundred segments at most), so this is simpler
/// than replicating a heap's sift while remaining behaviourally identical (same pop
/// order, same duplicate detection via `marks`).
#[derive(Default)]
pub(crate) struct SegmentHeap {
    items: Vec<Segment>,
    marks: HashSet<u32>,
}

impl SegmentHeap {
    fn push(&mut self, seg: Segment) {
        self.marks.insert(seg.sn);
        self.items.push(seg);
    }

    /// Pops the segment whose `sn` is smallest under wrap-safe `itimediff` ordering.
    fn pop_min(&mut self) -> Option<Segment> {
        let first = self.items.first()?;
        let mut min_idx = 0;
        let mut min_sn = first.sn;
        for (i, item) in self.items.iter().enumerate().skip(1) {
            if itimediff(item.sn, min_sn) < 0 {
                min_idx = i;
                min_sn = item.sn;
            }
        }
        let seg = self.items.swap_remove(min_idx);
        self.marks.remove(&seg.sn);
        Some(seg)
    }

    fn peek_min_sn(&self) -> Option<u32> {
        self.items.iter().map(|s| s.sn).reduce(|a, b| if itimediff(b, a) < 0 { b } else { a })
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    fn has(&self, sn: u32) -> bool {
        self.marks.contains(&sn)
    }
}

#[derive(Clone, Copy)]
struct AckItem {
    sn: u32,
    ts: u32,
}

/// `KCP`. `output` receives each flushed wire buffer (a whole KCP segment run, up to `mtu`
/// bytes) in place of a closure capturing the session's conn.
pub struct Kcp {
    pub conv: u32,
    pub mtu: u32,
    pub mss: u32,
    state: u32,
    pub snd_una: u32,
    pub snd_nxt: u32,
    rcv_nxt: u32,
    ssthresh: u32,
    rx_rttvar: i32,
    rx_srtt: i32,
    rx_rto: u32,
    rx_minrto: u32,
    pub snd_wnd: u32,
    pub rcv_wnd: u32,
    rmt_wnd: u32,
    cwnd: u32,
    probe: u32,
    interval: u32,
    ts_flush: u32,
    nodelay: u32,
    updated: bool,
    ts_probe: u32,
    probe_wait: u32,
    dead_link: u32,
    incr: u32,
    fastresend: i32,
    nocwnd: bool,
    pub stream: bool,

    snd_queue: VecDeque<Segment>,
    rcv_queue: VecDeque<Segment>,
    snd_buf: VecDeque<Segment>,
    rcv_buf: SegmentHeap,

    acklist: Vec<AckItem>,

    buffer: Vec<u8>,
    output: Box<dyn FnMut(&[u8]) + Send>,
}

impl core::fmt::Debug for Kcp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Kcp")
            .field("conv", &self.conv)
            .field("state", &self.state)
            .field("mtu", &self.mtu)
            .field("mss", &self.mss)
            .field("snd_una", &self.snd_una)
            .field("snd_nxt", &self.snd_nxt)
            .field("rcv_nxt", &self.rcv_nxt)
            .field("snd_wnd", &self.snd_wnd)
            .field("rcv_wnd", &self.rcv_wnd)
            .field("rmt_wnd", &self.rmt_wnd)
            .field("cwnd", &self.cwnd)
            .field("rx_rto", &self.rx_rto)
            .field("snd_queue", &self.snd_queue.len())
            .field("rcv_queue", &self.rcv_queue.len())
            .field("snd_buf", &self.snd_buf.len())
            .field("rcv_buf", &self.rcv_buf.len())
            .finish_non_exhaustive()
    }
}

impl Kcp {
    #[must_use]
    pub fn new(conv: u32, output: Box<dyn FnMut(&[u8]) + Send>) -> Self {
        let mtu = IKCP_MTU_DEF;
        Self {
            conv,
            mtu,
            mss: mtu - IKCP_OVERHEAD,
            state: 0,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ssthresh: IKCP_THRESH_INIT,
            rx_rttvar: 0,
            rx_srtt: 0,
            rx_rto: IKCP_RTO_DEF,
            rx_minrto: IKCP_RTO_MIN,
            snd_wnd: IKCP_WND_SND,
            rcv_wnd: IKCP_WND_RCV,
            rmt_wnd: IKCP_WND_RCV,
            cwnd: 0,
            probe: 0,
            interval: 100,
            ts_flush: 100,
            nodelay: 0,
            updated: false,
            ts_probe: 0,
            probe_wait: 0,
            dead_link: IKCP_DEADLINK,
            incr: 0,
            fastresend: 0,
            nocwnd: false,
            stream: false,
            snd_queue: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            snd_buf: VecDeque::new(),
            rcv_buf: SegmentHeap::default(),
            acklist: Vec::new(),
            buffer: vec![0u8; mtu as usize],
            output,
        }
    }

    fn ack_push(&mut self, sn: u32, ts: u32) {
        self.acklist.push(AckItem { sn, ts });
    }

    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "a segment payload is bounded by the MTU, and a reassembled datagram by the receive window, so both fit an `i32`"
    )]
    #[must_use]
    pub fn peek_size(&self) -> i32 {
        let Some(seg) = self.rcv_queue.front() else {
            return -1;
        };
        if seg.frg == 0 {
            return seg.data.len() as i32;
        }
        if self.rcv_queue.len() < seg.frg as usize + 1 {
            return -1;
        }
        let mut length = 0i32;
        for seg in &self.rcv_queue {
            length += seg.data.len() as i32;
            if seg.frg == 0 {
                break;
            }
        }
        length
    }

    /// `Recv`. Returns `-1` (no data), `-2` (buffer too small) or the number of bytes copied.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "the reassembled datagram is bounded by the receive window, so the byte count fits an `i32`"
    )]
    pub fn recv(&mut self, buffer: &mut [u8]) -> i32 {
        let peeksize = self.peek_size();
        let Ok(peek_len) = usize::try_from(peeksize) else {
            return -1;
        };
        if peek_len > buffer.len() {
            return -2;
        }

        let fast_recover = self.rcv_queue.len() >= self.rcv_wnd as usize;

        let mut n = 0usize;
        while let Some(seg) = self.rcv_queue.pop_front() {
            if let Some(dst) = buffer.get_mut(n..n + seg.data.len()) {
                dst.copy_from_slice(&seg.data);
            }
            n += seg.data.len();
            let frg = seg.frg;
            if frg == 0 {
                break;
            }
        }

        while self.rcv_buf.len() > 0 {
            let Some(sn) = self.rcv_buf.peek_min_sn() else { break };
            if sn == self.rcv_nxt && self.rcv_queue.len() < self.rcv_wnd as usize {
                let Some(seg) = self.rcv_buf.pop_min() else { break };
                self.rcv_queue.push_back(seg);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            } else {
                break;
            }
        }

        if self.rcv_queue.len() < self.rcv_wnd as usize && fast_recover {
            self.probe |= IKCP_ASK_TELL;
        }

        n as i32
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "`count` is capped at 255 above, so `count - i - 1` always fits the fragment id `u8`"
    )]
    pub fn send(&mut self, mut buffer: &[u8]) -> i32 {
        if buffer.is_empty() {
            return -1;
        }

        if self.stream {
            if !self.snd_queue.is_empty() {
                if let Some(seg) = self.snd_queue.back_mut() {
                    if seg.data.len() < self.mss as usize {
                        let capacity = self.mss as usize - seg.data.len();
                        let extend = buffer.len().min(capacity);
                        if let Some(head) = buffer.get(..extend) {
                            seg.data.extend_from_slice(head);
                        }
                        buffer = buffer.get(extend..).unwrap_or_default();
                    }
                }
            }
            if buffer.is_empty() {
                return 0;
            }
        }

        let count = if buffer.len() <= self.mss as usize { 1 } else { buffer.len().div_ceil(self.mss as usize) };

        if count > 255 {
            return -2;
        }
        let count = count.max(1);

        for i in 0..count {
            let size = buffer.len().min(self.mss as usize);
            let mut seg = Segment::new(size);
            if let Some(head) = buffer.get(..size) {
                seg.data.copy_from_slice(head);
            }
            seg.frg = if self.stream { 0 } else { (count - i - 1) as u8 };
            self.snd_queue.push_back(seg);
            buffer = buffer.get(size..).unwrap_or_default();
        }
        0
    }

    fn update_ack(&mut self, rtt: i32) {
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttvar = rtt >> 1;
        } else {
            let mut delta = rtt - self.rx_srtt;
            self.rx_srtt += delta >> 3;
            if delta < 0 {
                delta = -delta;
            }
            if rtt < self.rx_srtt - self.rx_rttvar {
                self.rx_rttvar += (delta - self.rx_rttvar) >> 5;
            } else {
                self.rx_rttvar += (delta - self.rx_rttvar) >> 2;
            }
        }
        let rto = self.rx_srtt.cast_unsigned().wrapping_add(self.interval.max(self.rx_rttvar.cast_unsigned() << 2));
        self.rx_rto = ibound(self.rx_minrto, rto, IKCP_RTO_MAX);
    }

    fn shrink_buf(&mut self) {
        self.snd_una = self.snd_buf.front().map_or(self.snd_nxt, |s| s.sn);
    }

    fn parse_ack(&mut self, sn: u32) {
        if itimediff(sn, self.snd_una) < 0 || itimediff(sn, self.snd_nxt) >= 0 {
            return;
        }
        for seg in &mut self.snd_buf {
            if sn == seg.sn {
                seg.acked = true;
                break;
            }
            if itimediff(sn, seg.sn) < 0 {
                break;
            }
        }
    }

    fn parse_fastack(&mut self, sn: u32, ts: u32) -> i32 {
        if itimediff(sn, self.snd_una) < 0 || itimediff(sn, self.snd_nxt) >= 0 {
            return 0;
        }
        let mut should_fastack = 0;
        for seg in &mut self.snd_buf {
            if itimediff(sn, seg.sn) < 0 {
                break;
            }
            if sn != seg.sn && itimediff(seg.ts, ts) <= 0 && seg.fastack != 0xFFFF_FFFF {
                seg.fastack += 1;
                if seg.fastack >= self.fastresend.cast_unsigned() {
                    should_fastack = 1;
                }
            }
        }
        should_fastack
    }

    fn parse_una(&mut self, una: u32) -> i32 {
        let mut count = 0;
        while let Some(seg) = self.snd_buf.front() {
            if itimediff(una, seg.sn) > 0 {
                self.snd_buf.pop_front();
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    /// `parse_data`: returns true if the segment is a duplicate.
    fn parse_data(&mut self, newseg: Segment) -> bool {
        let sn = newseg.sn;
        if itimediff(sn, self.rcv_nxt.wrapping_add(self.rcv_wnd)) >= 0 || itimediff(sn, self.rcv_nxt) < 0 {
            return true;
        }

        let repeat = self.rcv_buf.has(sn);
        if !repeat {
            self.rcv_buf.push(newseg);
        }

        while self.rcv_buf.len() > 0 {
            let Some(min_sn) = self.rcv_buf.peek_min_sn() else { break };
            if min_sn == self.rcv_nxt && self.rcv_queue.len() < self.rcv_wnd as usize {
                let Some(seg) = self.rcv_buf.pop_min() else { break };
                self.rcv_queue.push_back(seg);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            } else {
                break;
            }
        }

        repeat
    }

    /// `Input`. `data` is one or more concatenated encoded KCP segments (already stripped of
    /// any FEC/crypto framing). `pkt_type` distinguishes FEC-recovered input from regular input
    /// (only regular input updates `rmt_wnd`/RTT).
    pub fn input(&mut self, mut data: &[u8], pkt_type: PacketType, ack_no_delay: bool) -> i32 {
        let snd_una = self.snd_una;
        if data.len() < IKCP_OVERHEAD as usize {
            return -1;
        }

        let mut latest = 0u32;
        let mut update_rtt = false;
        let mut flush_segments = 0i32;

        while data.len() >= IKCP_OVERHEAD as usize {
            let Some((header, rest)) = data.split_first_chunk::<24>() else {
                break;
            };

            let conv = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            if conv != self.conv {
                return -1;
            }
            let cmd = header[4];
            let frg = header[5];
            let wnd = u16::from_le_bytes([header[6], header[7]]);
            let ts = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
            let sn = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
            let una = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
            let length = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);
            data = rest;

            if data.len() < length as usize {
                return -2;
            }
            let Some(payload) = data.get(..length as usize) else {
                return -2;
            };

            if cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK && cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS {
                return -3;
            }

            if pkt_type == PacketType::Regular {
                self.rmt_wnd = u32::from(wnd);
            }
            if self.parse_una(una) > 0 {
                flush_segments |= 1;
            }
            self.shrink_buf();

            if cmd == IKCP_CMD_ACK {
                self.parse_ack(sn);
                flush_segments |= self.parse_fastack(sn, ts);
                update_rtt = true;
                latest = ts;
            } else if cmd == IKCP_CMD_PUSH {
                if itimediff(sn, self.rcv_nxt.wrapping_add(self.rcv_wnd)) < 0 {
                    self.ack_push(sn, ts);
                    if itimediff(sn, self.rcv_nxt) >= 0 {
                        let seg = Segment {
                            conv,
                            cmd,
                            frg,
                            wnd,
                            ts,
                            sn,
                            una,
                            rto: 0,
                            xmit: 0,
                            resendts: 0,
                            fastack: 0,
                            acked: false,
                            data: payload.to_vec(),
                        };
                        self.parse_data(seg);
                    }
                }
            } else if cmd == IKCP_CMD_WASK {
                self.probe |= IKCP_ASK_TELL;
            } else if cmd == IKCP_CMD_WINS {
                // no-op, just a keepalive/window-tell notification.
            }

            data = data.get(length as usize..).unwrap_or_default();
        }

        if update_rtt && pkt_type == PacketType::Regular {
            let current = current_ms();
            if itimediff(current, latest) >= 0 {
                self.update_ack(itimediff(current, latest));
            }
        }

        self.grow_cwnd(snd_una);

        if flush_segments != 0 {
            self.flush(FlushType::Full);
        } else if self.acklist.len() >= (self.mtu / IKCP_OVERHEAD) as usize
            || (ack_no_delay && !self.acklist.is_empty())
        {
            self.flush(FlushType::AckOnly);
        }
        0
    }

    /// Congestion growth after an ack advanced `snd_una`: one segment per ack below `ssthresh`,
    /// additive increase in `incr` units above it.
    fn grow_cwnd(&mut self, snd_una: u32) {
        if self.nocwnd || itimediff(self.snd_una, snd_una) <= 0 || self.cwnd >= self.rmt_wnd {
            return;
        }
        let mss = self.mss;
        if self.cwnd < self.ssthresh {
            self.cwnd += 1;
            self.incr += mss;
        } else {
            if self.incr < mss {
                self.incr = mss;
            }
            self.incr += (mss * mss) / self.incr + (mss / 16);
            if (self.cwnd + 1) * mss <= self.incr {
                // The divisor `mss` is never zero: `set_mtu` rejects `mtu < 50`.
                self.cwnd = self.incr.div_ceil(mss);
            }
        }
        if self.cwnd > self.rmt_wnd {
            self.cwnd = self.rmt_wnd;
            self.incr = self.rmt_wnd * mss;
        }
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the wire `wnd` field is 16 bits by definition, so the advertised window is masked to it"
    )]
    fn wnd_unused(&self) -> u16 {
        if self.rcv_queue.len() < self.rcv_wnd as usize {
            (self.rcv_wnd as usize - self.rcv_queue.len()) as u16
        } else {
            0
        }
    }

    /// `flush`. Returns the millisecond delay until the next flush should be scheduled.
    #[expect(
        clippy::too_many_lines,
        clippy::cognitive_complexity,
        reason = "the congestion-control routine is byte-exact; its stages share the window, probe and output buffer state, so splitting it would break that correspondence"
    )]
    pub fn flush(&mut self, flush_type: FlushType) -> u32 {
        let mut seg = Segment {
            conv: self.conv,
            cmd: IKCP_CMD_ACK,
            frg: 0,
            wnd: self.wnd_unused(),
            ts: 0,
            sn: 0,
            una: self.rcv_nxt,
            rto: 0,
            xmit: 0,
            resendts: 0,
            fastack: 0,
            acked: false,
            data: Vec::new(),
        };

        let mtu = self.mtu as usize;
        if self.buffer.len() != mtu {
            self.buffer = vec![0u8; mtu];
        }
        let mut pos = 0usize;
        let output = &mut self.output;

        macro_rules! make_space {
            ($space:expr) => {
                if pos + $space > mtu {
                    output(self.buffer.get(..pos).unwrap_or_default());
                    pos = 0;
                }
            };
        }

        if matches!(flush_type, FlushType::AckOnly | FlushType::Full) {
            let n = self.acklist.len();
            for (i, ack) in self.acklist.clone().into_iter().enumerate() {
                make_space!(IKCP_OVERHEAD as usize);
                if itimediff(ack.sn, self.rcv_nxt) >= 0 || n - 1 == i {
                    seg.sn = ack.sn;
                    seg.ts = ack.ts;
                    encode_segment_at(&mut self.buffer, pos, &seg);
                    pos += 24;
                }
            }
            self.acklist.clear();
        }

        if self.rmt_wnd == 0 {
            let current = current_ms();
            if self.probe_wait == 0 {
                self.probe_wait = IKCP_PROBE_INIT;
                self.ts_probe = current.wrapping_add(self.probe_wait);
            } else if itimediff(current, self.ts_probe) >= 0 {
                if self.probe_wait < IKCP_PROBE_INIT {
                    self.probe_wait = IKCP_PROBE_INIT;
                }
                self.probe_wait += self.probe_wait / 2;
                if self.probe_wait > IKCP_PROBE_LIMIT {
                    self.probe_wait = IKCP_PROBE_LIMIT;
                }
                self.ts_probe = current.wrapping_add(self.probe_wait);
                self.probe |= IKCP_ASK_SEND;
            }
        } else {
            self.ts_probe = 0;
            self.probe_wait = 0;
        }

        if self.probe & IKCP_ASK_SEND != 0 {
            seg.cmd = IKCP_CMD_WASK;
            make_space!(IKCP_OVERHEAD as usize);
            encode_segment_at(&mut self.buffer, pos, &seg);
            pos += 24;
        }
        if self.probe & IKCP_ASK_TELL != 0 {
            seg.cmd = IKCP_CMD_WINS;
            make_space!(IKCP_OVERHEAD as usize);
            encode_segment_at(&mut self.buffer, pos, &seg);
            pos += 24;
        }
        self.probe = 0;

        let mut cwnd = self.snd_wnd.min(self.rmt_wnd);
        if !self.nocwnd {
            cwnd = self.cwnd.min(cwnd);
        }

        let mut new_segs_count = 0;
        while itimediff(self.snd_nxt, self.snd_una.wrapping_add(cwnd)) < 0 {
            let Some(mut newseg) = self.snd_queue.pop_front() else { break };
            newseg.conv = self.conv;
            newseg.cmd = IKCP_CMD_PUSH;
            newseg.sn = self.snd_nxt;
            self.snd_buf.push_back(newseg);
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            new_segs_count += 1;
        }

        let resent = if self.fastresend > 0 { self.fastresend.cast_unsigned() } else { 0xFFFF_FFFF };

        let mut current = current_ms();
        let mut change = 0u32;
        let mut lost_segs = 0u32;
        let mut next_update = self.interval;

        if matches!(flush_type, FlushType::Full) {
            for segment in &mut self.snd_buf {
                if segment.acked {
                    continue;
                }
                let mut needsend = false;
                if segment.xmit == 0 {
                    needsend = true;
                    segment.rto = self.rx_rto;
                    segment.resendts = current.wrapping_add(segment.rto);
                } else if segment.fastack != 0xFFFF_FFFF
                    && (segment.fastack >= resent || (segment.fastack > 0 && new_segs_count == 0))
                {
                    // "Fast retransmit" (`fastack >= fastresend`) and "early retransmit"
                    // (`fastack > 0 && no new segments`) differ only in a counter, so they share
                    // one body here.
                    needsend = true;
                    segment.fastack = 0xFFFF_FFFF;
                    segment.rto = self.rx_rto;
                    segment.resendts = current.wrapping_add(segment.rto);
                    change += 1;
                } else if itimediff(current, segment.resendts) >= 0 {
                    needsend = true;
                    if self.nodelay == 0 {
                        segment.rto = segment.rto.wrapping_add(self.rx_rto);
                    } else {
                        segment.rto = segment.rto.wrapping_add(self.rx_rto / 2);
                    }
                    segment.fastack = 0;
                    segment.resendts = current.wrapping_add(segment.rto);
                    lost_segs += 1;
                }

                if needsend {
                    current = current_ms();
                    segment.xmit += 1;
                    segment.ts = current;
                    segment.wnd = seg.wnd;
                    segment.una = seg.una;

                    let need = IKCP_OVERHEAD as usize + segment.data.len();
                    if pos + need > mtu {
                        output(self.buffer.get(..pos).unwrap_or_default());
                        pos = 0;
                    }
                    encode_segment_at(&mut self.buffer, pos, segment);
                    pos += 24;
                    if let Some(dst) = self.buffer.get_mut(pos..pos + segment.data.len()) {
                        dst.copy_from_slice(&segment.data);
                    }
                    pos += segment.data.len();

                    if segment.xmit >= self.dead_link {
                        self.state = 0xFFFF_FFFF;
                    }
                }

                let rto = itimediff(segment.resendts, current);
                if rto > 0 && rto.cast_unsigned() < next_update {
                    next_update = rto.cast_unsigned();
                }
            }
        }

        if !self.nocwnd {
            if change > 0 {
                let inflight = self.snd_nxt.wrapping_sub(self.snd_una);
                self.ssthresh = (inflight / 2).max(IKCP_THRESH_MIN);
                self.cwnd = self.ssthresh + resent;
                self.incr = self.cwnd * self.mss;
            }
            if lost_segs > 0 {
                self.ssthresh = (cwnd / 2).max(IKCP_THRESH_MIN);
                self.cwnd = 1;
                self.incr = self.mss;
            }
            if self.cwnd < 1 {
                self.cwnd = 1;
                self.incr = self.mss;
            }
        }

        if pos > 0 {
            output(self.buffer.get(..pos).unwrap_or_default());
        }

        next_update
    }

    /// Updates the session state (deprecated, kept for parity with the public surface).
    pub fn update(&mut self) {
        let current = current_ms();
        if !self.updated {
            self.updated = true;
            self.ts_flush = current;
        }
        let mut slap = itimediff(current, self.ts_flush);
        if !(-10000..10000).contains(&slap) {
            self.ts_flush = current;
            slap = 0;
        }
        if slap >= 0 {
            self.ts_flush = self.ts_flush.wrapping_add(self.interval);
            if itimediff(current, self.ts_flush) >= 0 {
                self.ts_flush = current.wrapping_add(self.interval);
            }
            self.flush(FlushType::Full);
        }
    }

    #[must_use]
    pub fn check(&self) -> u32 {
        let current = current_ms();
        let mut ts_flush = self.ts_flush;
        if !self.updated {
            return current;
        }
        if !(-10000..10000).contains(&itimediff(current, ts_flush)) {
            ts_flush = current;
        }
        if itimediff(current, ts_flush) >= 0 {
            return current;
        }
        let flush_wait = itimediff(ts_flush, current);

        let mut tm_packet = i32::MAX;
        for seg in &self.snd_buf {
            let diff = itimediff(seg.resendts, current);
            if diff <= 0 {
                return current;
            }
            if diff < tm_packet {
                tm_packet = diff;
            }
        }

        let mut minimal = tm_packet.min(flush_wait).cast_unsigned();
        if minimal >= self.interval {
            minimal = self.interval;
        }
        current.wrapping_add(minimal)
    }

    pub fn set_mtu(&mut self, mtu: i32) -> i32 {
        if mtu < 50 || mtu.cast_unsigned() < IKCP_OVERHEAD {
            return -1;
        }
        self.mtu = mtu.cast_unsigned();
        self.mss = self.mtu - IKCP_OVERHEAD;
        self.buffer = vec![0u8; self.mtu as usize];
        0
    }

    pub fn no_delay(&mut self, nodelay: i32, interval: i32, resend: i32, nc: i32) {
        if nodelay >= 0 {
            self.nodelay = nodelay.cast_unsigned();
            self.rx_minrto = if nodelay != 0 { IKCP_RTO_NDL } else { IKCP_RTO_MIN };
        }
        if interval >= 0 {
            let interval = interval.clamp(10, 5000);
            self.interval = interval.cast_unsigned();
        }
        if resend >= 0 {
            self.fastresend = resend;
        }
        if nc >= 0 {
            self.nocwnd = nc != 0;
        }
    }

    pub fn wnd_size(&mut self, sndwnd: i32, rcvwnd: i32) {
        if sndwnd > 0 {
            self.snd_wnd = sndwnd.cast_unsigned();
        }
        if rcvwnd > 0 {
            self.rcv_wnd = rcvwnd.cast_unsigned();
        }
    }

    #[must_use]
    pub fn wait_snd(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
    }
}

use std::sync::LazyLock;
use std::time::Instant;

static REF_TIME: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Elapsed monotonic milliseconds since first use. The epoch is arbitrary and only ever observed
/// through 32-bit differences, so its origin does not affect wraparound.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the millisecond clock is a 32-bit counter that wraps by design; timestamps are only ever compared through `itimediff`"
)]
pub(crate) fn current_ms() -> u32 {
    REF_TIME.elapsed().as_millis() as u32
}

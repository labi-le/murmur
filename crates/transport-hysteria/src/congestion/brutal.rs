use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use murmur_quic::congestion::{
    AckedPacketInfo, ByteCount, CongestionControl, CongestionControlEx, LostPacketInfo, PacketNumber, RttStatsProvider,
};
use murmur_quic::monotime;

use super::pacer::{new_pacer, Pacer};

pub(crate) const INIT_MAX_DATAGRAM_SIZE: ByteCount = 1252;

const PKT_INFO_SLOT_COUNT: usize = 5; // slot index is based on seconds, so this is basically how many seconds we sample
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;

pub struct BrutalSender {
    rtt_stats: Option<Arc<dyn RttStatsProvider>>,
    bps: ByteCount,
    max_datagram_size: ByteCount,
    pacer: Pacer,

    pkt_info_slots: [PktInfo; PKT_INFO_SLOT_COUNT],
    /// The pacer closure would read the ack rate directly; here the rate is shared with that closure as
    /// the bit pattern of the `f64`.
    ack_rate: Arc<AtomicU64>,
}

#[derive(Clone, Copy, Debug, Default)]
struct PktInfo {
    timestamp: i64,
    ack_count: u64,
    loss_count: u64,
}

#[must_use]
pub fn new_brutal_sender(bps: ByteCount) -> BrutalSender {
    let ack_rate = Arc::new(AtomicU64::new(1.0f64.to_bits()));
    let pacer_ack_rate = Arc::clone(&ack_rate);
    let pacer = new_pacer(Box::new(move || paced_bandwidth(bps, pacer_ack_rate.load(Ordering::Relaxed))));
    BrutalSender {
        rtt_stats: None,
        bps,
        max_datagram_size: INIT_MAX_DATAGRAM_SIZE,
        pacer,
        pkt_info_slots: [PktInfo::default(); PKT_INFO_SLOT_COUNT],
        ack_rate,
    }
}

impl fmt::Debug for BrutalSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrutalSender")
            .field("bps", &self.bps)
            .field("max_datagram_size", &self.max_datagram_size)
            .field("pacer", &self.pacer)
            .field("pkt_info_slots", &self.pkt_info_slots)
            .field("ack_rate", &self.get_ack_rate())
            .finish_non_exhaustive()
    }
}

impl BrutalSender {
    pub fn set_rtt_stats_provider(&mut self, rtt_stats: Arc<dyn RttStatsProvider>) {
        self.rtt_stats = Some(rtt_stats);
    }

    #[must_use]
    pub fn time_until_send(&self, _bytes_in_flight: ByteCount) -> monotime::Time {
        self.pacer.time_until_send()
    }

    #[must_use]
    pub fn has_pacing_budget(&self, now: monotime::Time) -> bool {
        self.pacer.budget(now) >= self.max_datagram_size
    }

    #[must_use]
    pub fn can_send(&self, bytes_in_flight: ByteCount) -> bool {
        bytes_in_flight < self.get_congestion_window()
    }

    #[must_use]
    pub fn get_congestion_window(&self) -> ByteCount {
        #[expect(clippy::expect_used, reason = "the dial path installs the RTT provider before any packet is sent")]
        let rtt_stats = self.rtt_stats.as_ref().expect("RTT stats provider is set before sending");
        let rtt = max_duration(rtt_stats.latest_rtt(), rtt_stats.smoothed_rtt());
        if rtt.is_zero() {
            return 10240;
        }
        congestion_window(self.bps, rtt.as_secs_f64(), self.get_ack_rate())
    }

    pub fn on_packet_sent(
        &mut self,
        sent_time: monotime::Time,
        _bytes_in_flight: ByteCount,
        _packet_number: PacketNumber,
        bytes: ByteCount,
        _is_retransmittable: bool,
    ) {
        self.pacer.sent_packet(sent_time, bytes);
    }

    pub const fn on_packet_acked(
        &mut self,
        _number: PacketNumber,
        _acked_bytes: ByteCount,
        _prior_in_flight: ByteCount,
        _event_time: monotime::Time,
    ) {
        // Stub
    }

    pub const fn on_congestion_event(
        &mut self,
        _number: PacketNumber,
        _lost_bytes: ByteCount,
        _prior_in_flight: ByteCount,
    ) {
        // Stub
    }

    pub fn on_congestion_event_ex(
        &mut self,
        _prior_in_flight: ByteCount,
        event_time: monotime::Time,
        acked_packets: &[AckedPacketInfo],
        lost_packets: &[LostPacketInfo],
    ) {
        let current_timestamp = monotonic_seconds(event_time);
        let Some(slot) = slot_index(current_timestamp) else {
            return;
        };
        let Some(info) = self.pkt_info_slots.get_mut(slot) else {
            return;
        };
        if info.timestamp == current_timestamp {
            info.loss_count += lost_packets.len() as u64;
            info.ack_count += acked_packets.len() as u64;
        } else {
            // uninitialized slot or too old, reset
            info.timestamp = current_timestamp;
            info.ack_count = acked_packets.len() as u64;
            info.loss_count = lost_packets.len() as u64;
        }
        self.update_ack_rate(current_timestamp);
    }

    pub fn set_max_datagram_size(&mut self, size: ByteCount) {
        self.max_datagram_size = size;
        self.pacer.set_max_datagram_size(size);
    }

    #[must_use]
    pub const fn in_slow_start(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn in_recovery(&self) -> bool {
        false
    }

    pub const fn maybe_exit_slow_start(&mut self) {}

    pub const fn on_retransmission_timeout(&mut self, _packets_retransmitted: bool) {}

    fn update_ack_rate(&self, current_timestamp: i64) {
        let min_timestamp = current_timestamp - slot_count();
        let mut ack_count = 0u64;
        let mut loss_count = 0u64;
        for info in &self.pkt_info_slots {
            if info.timestamp < min_timestamp {
                continue;
            }
            ack_count += info.ack_count;
            loss_count += info.loss_count;
        }
        if ack_count + loss_count < MIN_SAMPLE_COUNT {
            self.set_ack_rate(1.0);
            return;
        }
        let rate = ack_rate_ratio(ack_count, ack_count + loss_count);
        if rate < MIN_ACK_RATE {
            self.set_ack_rate(MIN_ACK_RATE);
            return;
        }
        self.set_ack_rate(rate);
    }

    fn get_ack_rate(&self) -> f64 {
        f64::from_bits(self.ack_rate.load(Ordering::Relaxed))
    }

    fn set_ack_rate(&self, ack_rate: f64) {
        self.ack_rate.store(ack_rate.to_bits(), Ordering::Relaxed);
    }
}

impl CongestionControl for BrutalSender {
    fn set_rtt_stats_provider(&mut self, provider: Arc<dyn RttStatsProvider>) {
        Self::set_rtt_stats_provider(self, provider);
    }

    fn time_until_send(&self, bytes_in_flight: ByteCount) -> monotime::Time {
        Self::time_until_send(self, bytes_in_flight)
    }

    fn has_pacing_budget(&self, now: monotime::Time) -> bool {
        Self::has_pacing_budget(self, now)
    }

    fn on_packet_sent(
        &mut self,
        sent_time: monotime::Time,
        bytes_in_flight: ByteCount,
        packet_number: PacketNumber,
        bytes: ByteCount,
        is_retransmittable: bool,
    ) {
        Self::on_packet_sent(self, sent_time, bytes_in_flight, packet_number, bytes, is_retransmittable);
    }

    fn can_send(&self, bytes_in_flight: ByteCount) -> bool {
        Self::can_send(self, bytes_in_flight)
    }

    fn maybe_exit_slow_start(&mut self) {
        Self::maybe_exit_slow_start(self);
    }

    fn on_packet_acked(
        &mut self,
        number: PacketNumber,
        acked_bytes: ByteCount,
        prior_in_flight: ByteCount,
        event_time: monotime::Time,
    ) {
        Self::on_packet_acked(self, number, acked_bytes, prior_in_flight, event_time);
    }

    fn on_congestion_event(&mut self, number: PacketNumber, lost_bytes: ByteCount, prior_in_flight: ByteCount) {
        Self::on_congestion_event(self, number, lost_bytes, prior_in_flight);
    }

    fn on_retransmission_timeout(&mut self, packets_retransmitted: bool) {
        Self::on_retransmission_timeout(self, packets_retransmitted);
    }

    fn set_max_datagram_size(&mut self, size: ByteCount) {
        Self::set_max_datagram_size(self, size);
    }

    fn in_slow_start(&self) -> bool {
        Self::in_slow_start(self)
    }

    fn in_recovery(&self) -> bool {
        Self::in_recovery(self)
    }

    fn get_congestion_window(&self) -> ByteCount {
        Self::get_congestion_window(self)
    }
}

impl CongestionControlEx for BrutalSender {
    fn on_congestion_event_ex(
        &mut self,
        prior_in_flight: ByteCount,
        event_time: monotime::Time,
        acked_packets: &[AckedPacketInfo],
        lost_packets: &[LostPacketInfo],
    ) {
        Self::on_congestion_event_ex(self, prior_in_flight, event_time, acked_packets, lost_packets);
    }
}

const _: fn() = || {
    const fn assert_impl<T: CongestionControlEx>() {}
    assert_impl::<BrutalSender>();
};

pub(crate) fn max_duration(a: Duration, b: Duration) -> Duration {
    if a > b {
        a
    } else {
        b
    }
}

/// The sampling table's slot count expressed in the `i64` second domain; the table holds five
/// slots, so this conversion cannot fail.
fn slot_count() -> i64 {
    i64::try_from(PKT_INFO_SLOT_COUNT).unwrap_or(1)
}

/// The sampling slot `timestamp` falls in, `None` before the lazily sampled monotonic origin.
fn slot_index(timestamp: i64) -> Option<usize> {
    usize::try_from(timestamp.rem_euclid(slot_count())).ok()
}

/// `bps` scaled by the ack rate the pacer closure shares with the sender.
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "the paced rate is computed in f64 from the integer bit/sec field and truncated back to that field"
)]
fn paced_bandwidth(bps: ByteCount, ack_rate_bits: u64) -> ByteCount {
    (bps as f64 / f64::from_bits(ack_rate_bits)) as ByteCount
}

/// The window `bps * rtt * 1.5 / ack_rate` the sender paces against.
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "the window is computed in f64 from the integer bit/sec field and truncated back to that field"
)]
fn congestion_window(bps: ByteCount, rtt_secs: f64, ack_rate: f64) -> ByteCount {
    (bps as f64 * rtt_secs * 1.5 / ack_rate) as ByteCount
}

/// The acked share of the sampled packets.
#[expect(clippy::cast_precision_loss, reason = "the ack rate is a f64 ratio of integer packet counters")]
fn ack_rate_ratio(acked: u64, sampled: u64) -> f64 {
    acked as f64 / sampled as f64
}

/// The monotonic clock exposes only differences between instants, so seconds are counted from the
/// first congestion event this module saw.
fn monotonic_seconds(t: monotime::Time) -> i64 {
    static ORIGIN: LazyLock<monotime::Time> = LazyLock::new(monotime::now);
    t.sub(&ORIGIN).as_secs().cast_signed()
}

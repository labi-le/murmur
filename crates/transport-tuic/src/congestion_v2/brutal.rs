use std::sync::Arc;

use murmur_quic::congestion::{
    AckedPacketInfo, ByteCount, CongestionControl, CongestionControlEx, LostPacketInfo, PacketNumber, RttStatsProvider,
    INITIAL_PACKET_SIZE,
};
use murmur_quic::monotime;

use super::pacer::Pacer;

const BRUTAL_PACKET_INFO_SLOT_COUNT: i64 = 5; // slot index is based on seconds, so this samples the recent 5 seconds.
const BRUTAL_MIN_SAMPLE_COUNT: u64 = 50;
const BRUTAL_MIN_ACK_RATE: f64 = 0.8;
const BRUTAL_CONGESTION_WINDOW_FACTOR: f64 = 2.0;
const BRUTAL_INITIAL_CONGESTION_WINDOW: ByteCount = 10240;

#[expect(clippy::cast_possible_truncation, reason = "the slot count is the integer constant 5, which fits a usize")]
pub struct BrutalSender {
    rtt_stats: Option<Arc<dyn RttStatsProvider>>,
    bps: ByteCount,
    max_datagram_size: ByteCount,
    pacer: Pacer,

    packet_info_slots: [BrutalPacketInfo; BRUTAL_PACKET_INFO_SLOT_COUNT as usize],
    ack_rate: f64,

    /// The slot index and its expiry are derived from `monotime` nanoseconds
    /// since the process origin, which the monotime type does not expose; the
    /// sender's creation time serves as the origin instead.
    epoch: monotime::Time,
}

impl core::fmt::Debug for BrutalSender {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BrutalSender")
            .field("bps", &self.bps)
            .field("max_datagram_size", &self.max_datagram_size)
            .field("pacer", &self.pacer)
            .field("packet_info_slots", &self.packet_info_slots)
            .field("ack_rate", &self.ack_rate)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BrutalPacketInfo {
    timestamp: i64,
    ack_count: u64,
    loss_count: u64,
}

#[expect(clippy::cast_possible_truncation, reason = "the slot count is the integer constant 5, which fits a usize")]
#[must_use]
pub fn new_brutal_sender(bps: u64) -> BrutalSender {
    BrutalSender {
        rtt_stats: None,
        bps: bps.cast_signed(),
        max_datagram_size: INITIAL_PACKET_SIZE,
        pacer: Pacer::new_pacer(),
        packet_info_slots: [BrutalPacketInfo::default(); BRUTAL_PACKET_INFO_SLOT_COUNT as usize],
        ack_rate: 1.0,
        epoch: monotime::now(),
    }
}

impl BrutalSender {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        reason = "the bandwidth is scaled in f64 and truncated toward zero"
    )]
    pub(crate) fn bandwidth_for_pacer(&self) -> ByteCount {
        (self.bps as f64 / self.ack_rate) as ByteCount
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "packet counts over five seconds are far below 2^52 and exact in f64"
    )]
    pub(crate) fn update_ack_rate(&mut self, current_timestamp: i64) {
        let min_timestamp = current_timestamp - BRUTAL_PACKET_INFO_SLOT_COUNT;
        let mut ack_count = 0u64;
        let mut loss_count = 0u64;
        for info in &self.packet_info_slots {
            if info.timestamp < min_timestamp {
                continue;
            }
            ack_count += info.ack_count;
            loss_count += info.loss_count;
        }
        if ack_count + loss_count < BRUTAL_MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
            return;
        }
        let rate = ack_count as f64 / (ack_count + loss_count) as f64;
        if rate < BRUTAL_MIN_ACK_RATE {
            self.ack_rate = BRUTAL_MIN_ACK_RATE;
            return;
        }
        self.ack_rate = rate;
    }
}

impl CongestionControl for BrutalSender {
    fn set_rtt_stats_provider(&mut self, rtt_stats: Arc<dyn RttStatsProvider>) {
        self.rtt_stats = Some(rtt_stats);
    }

    fn time_until_send(&self, _bytes_in_flight: ByteCount) -> monotime::Time {
        self.pacer.time_until_send(self.bandwidth_for_pacer())
    }

    fn has_pacing_budget(&self, now: monotime::Time) -> bool {
        self.pacer.budget(now, self.bandwidth_for_pacer()) >= self.max_datagram_size
    }

    fn can_send(&self, bytes_in_flight: ByteCount) -> bool {
        bytes_in_flight <= self.get_congestion_window()
    }

    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        reason = "the bandwidth-delay product is computed in f64 and truncated toward zero"
    )]
    fn get_congestion_window(&self) -> ByteCount {
        let Some(rtt_stats) = &self.rtt_stats else {
            return BRUTAL_INITIAL_CONGESTION_WINDOW;
        };
        let rtt = rtt_stats.smoothed_rtt();
        if rtt.is_zero() {
            return BRUTAL_INITIAL_CONGESTION_WINDOW;
        }
        let mut cwnd =
            (self.bps as f64 * rtt.as_secs_f64() * BRUTAL_CONGESTION_WINDOW_FACTOR / self.ack_rate) as ByteCount;
        if cwnd < self.max_datagram_size {
            cwnd = self.max_datagram_size;
        }
        cwnd
    }

    fn on_packet_sent(
        &mut self,
        sent_time: monotime::Time,
        _bytes_in_flight: ByteCount,
        _packet_number: PacketNumber,
        bytes: ByteCount,
        _is_retransmittable: bool,
    ) {
        let get_bandwidth = self.bandwidth_for_pacer();
        self.pacer.sent_packet(sent_time, bytes, get_bandwidth);
    }

    /// The ack rate is updated from acked and lost packet counts.
    fn on_packet_acked(
        &mut self,
        _number: PacketNumber,
        _acked_bytes: ByteCount,
        _prior_in_flight: ByteCount,
        _event_time: monotime::Time,
    ) {
    }

    /// The ack rate is updated from acked and lost packet counts.
    fn on_congestion_event(&mut self, _number: PacketNumber, _lost_bytes: ByteCount, _prior_in_flight: ByteCount) {}

    fn on_retransmission_timeout(&mut self, _packets_retransmitted: bool) {}

    fn set_max_datagram_size(&mut self, size: ByteCount) {
        self.max_datagram_size = size;
        self.pacer.set_max_datagram_size(size);
    }

    fn in_slow_start(&self) -> bool {
        false
    }

    fn in_recovery(&self) -> bool {
        false
    }

    fn maybe_exit_slow_start(&mut self) {}
}

impl CongestionControlEx for BrutalSender {
    fn on_congestion_event_ex(
        &mut self,
        _prior_in_flight: ByteCount,
        event_time: monotime::Time,
        acked_packets: &[AckedPacketInfo],
        lost_packets: &[LostPacketInfo],
    ) {
        let current_timestamp = event_time.sub(&self.epoch).as_secs().cast_signed();
        let slot = usize::try_from(current_timestamp % BRUTAL_PACKET_INFO_SLOT_COUNT).unwrap_or_default();
        if let Some(info) = self.packet_info_slots.get_mut(slot) {
            if info.timestamp == current_timestamp {
                info.loss_count += lost_packets.len() as u64;
                info.ack_count += acked_packets.len() as u64;
            } else {
                *info = BrutalPacketInfo {
                    timestamp: current_timestamp,
                    ack_count: acked_packets.len() as u64,
                    loss_count: lost_packets.len() as u64,
                };
            }
        }
        self.update_ack_rate(current_timestamp);
    }
}

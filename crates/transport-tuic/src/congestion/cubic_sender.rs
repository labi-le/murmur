use std::sync::Arc;
use std::time::Duration;

use murmur_quic::congestion;
use murmur_quic::congestion::CongestionControl as _;
use murmur_quic::monotime;

use super::bandwidth::{bandwidth_from_delta, Bandwidth, INF_BANDWIDTH};
use super::cubic::{new_cubic, Cubic};
use super::hybrid_slow_start::HybridSlowStart;
use super::minmax::{max, min};
use super::pacer::{new_pacer, Pacer};

const MAX_BURST_PACKETS: congestion::ByteCount = 3;
/// Reno backoff factor.
const RENO_BETA: f64 = 0.7;
const MIN_CONGESTION_WINDOW_PACKETS: congestion::ByteCount = 2;
const INITIAL_CONGESTION_WINDOW: congestion::ByteCount = 32;

pub const INVALID_PACKET_NUMBER: congestion::PacketNumber = -1;
pub const MAX_CONGESTION_WINDOW_PACKETS: congestion::ByteCount = 20000;
pub const MAX_BYTE_COUNT: congestion::ByteCount = (1 << 62) - 1;

pub struct CubicSender {
    hybrid_slow_start: HybridSlowStart,
    rtt_stats: Option<Arc<dyn congestion::RttStatsProvider>>,
    cubic: Cubic,
    pacer: Pacer,

    reno: bool,

    /// Track the largest packet that has been sent.
    largest_sent_packet_number: congestion::PacketNumber,

    /// Track the largest packet that has been acked.
    largest_acked_packet_number: congestion::PacketNumber,

    /// Track the largest packet number outstanding when a CWND cutback occurs.
    largest_sent_at_last_cutback: congestion::PacketNumber,

    /// Congestion window in bytes.
    congestion_window: congestion::ByteCount,

    /// Slow start congestion window in bytes, aka ssthresh.
    slow_start_threshold: congestion::ByteCount,

    /// ACK counter for the Reno implementation.
    num_acked_packets: u64,
    max_datagram_size: congestion::ByteCount,
}

impl core::fmt::Debug for CubicSender {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CubicSender")
            .field("hybrid_slow_start", &self.hybrid_slow_start)
            .field("cubic", &self.cubic)
            .field("reno", &self.reno)
            .field("largest_sent_packet_number", &self.largest_sent_packet_number)
            .field("largest_acked_packet_number", &self.largest_acked_packet_number)
            .field("largest_sent_at_last_cutback", &self.largest_sent_at_last_cutback)
            .field("congestion_window", &self.congestion_window)
            .field("slow_start_threshold", &self.slow_start_threshold)
            .field("num_acked_packets", &self.num_acked_packets)
            .field("max_datagram_size", &self.max_datagram_size)
            .finish_non_exhaustive()
    }
}

/// Creates a new cubic sender.
#[allow(
    private_interfaces,
    reason = "the sender type and its constructor are public, but the field types stay crate-internal, matching the unexported struct fields"
)]
#[must_use]
pub fn new_cubic_sender(initial_max_datagram_size: congestion::ByteCount, reno: bool) -> CubicSender {
    new_cubic_sender_with_windows(
        reno,
        initial_max_datagram_size,
        INITIAL_CONGESTION_WINDOW * initial_max_datagram_size,
    )
}

fn new_cubic_sender_with_windows(
    reno: bool,
    initial_max_datagram_size: congestion::ByteCount,
    initial_congestion_window: congestion::ByteCount,
) -> CubicSender {
    CubicSender {
        hybrid_slow_start: HybridSlowStart::default(),
        rtt_stats: None,
        cubic: new_cubic(),
        pacer: new_pacer(INF_BANDWIDTH),
        reno,
        largest_sent_packet_number: INVALID_PACKET_NUMBER,
        largest_acked_packet_number: INVALID_PACKET_NUMBER,
        largest_sent_at_last_cutback: INVALID_PACKET_NUMBER,
        congestion_window: initial_congestion_window,
        slow_start_threshold: MAX_BYTE_COUNT,
        num_acked_packets: 0,
        max_datagram_size: initial_max_datagram_size,
    }
}

impl CubicSender {
    const fn max_congestion_window(&self) -> congestion::ByteCount {
        self.max_datagram_size * MAX_CONGESTION_WINDOW_PACKETS
    }

    const fn min_congestion_window(&self) -> congestion::ByteCount {
        self.max_datagram_size * MIN_CONGESTION_WINDOW_PACKETS
    }

    /// Called when we receive an ack. Normal TCP tracks how many packets one ack
    /// represents, but quic has a separate ack for each packet.
    fn maybe_increase_cwnd(
        &mut self,
        _packet_number: congestion::PacketNumber,
        acked_bytes: congestion::ByteCount,
        prior_in_flight: congestion::ByteCount,
        event_time: monotime::Time,
    ) {
        // Do not increase the congestion window unless the sender is close to using
        // the current window.
        if !self.is_cwnd_limited(prior_in_flight) {
            self.cubic.on_application_limited();
            return;
        }
        if self.congestion_window >= self.max_congestion_window() {
            return;
        }
        if self.in_slow_start() {
            // TCP slow start, exponential growth, increase by one for each ACK.
            self.congestion_window = self.congestion_window.wrapping_add(self.max_datagram_size);
            return;
        }
        // Congestion avoidance
        if self.reno {
            // Classic Reno congestion avoidance.
            self.num_acked_packets += 1;
            let reno_ack_threshold = (self.congestion_window / self.max_datagram_size).cast_unsigned();
            if self.num_acked_packets >= reno_ack_threshold {
                self.congestion_window = self.congestion_window.wrapping_add(self.max_datagram_size);
                self.num_acked_packets = 0;
            }
        } else {
            let Some(rtt_stats) = self.rtt_stats.as_ref() else {
                return;
            };
            let min_rtt = rtt_stats.min_rtt();
            self.congestion_window = min(
                self.max_congestion_window(),
                self.cubic.congestion_window_after_ack(acked_bytes, self.congestion_window, min_rtt, event_time),
            );
        }
    }

    fn is_cwnd_limited(&self, bytes_in_flight: congestion::ByteCount) -> bool {
        let congestion_window = self.get_congestion_window();
        if bytes_in_flight >= congestion_window {
            return true;
        }
        let available_bytes = congestion_window - bytes_in_flight;
        let slow_start_limited = self.in_slow_start() && bytes_in_flight > congestion_window / 2;
        slow_start_limited || available_bytes <= MAX_BURST_PACKETS * self.max_datagram_size
    }

    /// The current bandwidth estimate.
    #[must_use]
    pub fn bandwidth_estimate(&self) -> Bandwidth {
        let Some(rtt_stats) = self.rtt_stats.as_ref() else {
            return INF_BANDWIDTH;
        };
        let srtt = rtt_stats.smoothed_rtt();
        if srtt == Duration::ZERO {
            // If we haven't measured an rtt, the bandwidth estimate is unknown.
            return INF_BANDWIDTH;
        }
        bandwidth_from_delta(self.congestion_window, srtt)
    }
}

impl congestion::CongestionControl for CubicSender {
    fn set_rtt_stats_provider(&mut self, provider: Arc<dyn congestion::RttStatsProvider>) {
        self.rtt_stats = Some(provider);
    }

    /// When the next packet should be sent.
    fn time_until_send(&self, _bytes_in_flight: congestion::ByteCount) -> monotime::Time {
        self.pacer.time_until_send(self.bandwidth_estimate())
    }

    fn has_pacing_budget(&self, now: monotime::Time) -> bool {
        self.pacer.budget(now, self.bandwidth_estimate()) >= self.max_datagram_size
    }

    fn on_packet_sent(
        &mut self,
        sent_time: monotime::Time,
        _bytes_in_flight: congestion::ByteCount,
        packet_number: congestion::PacketNumber,
        bytes: congestion::ByteCount,
        is_retransmittable: bool,
    ) {
        let bandwidth = self.bandwidth_estimate();
        self.pacer.sent_packet(sent_time, bytes, bandwidth);
        if !is_retransmittable {
            return;
        }
        self.largest_sent_packet_number = packet_number;
        self.hybrid_slow_start.on_packet_sent(packet_number);
    }

    fn can_send(&self, bytes_in_flight: congestion::ByteCount) -> bool {
        bytes_in_flight < self.get_congestion_window()
    }

    fn maybe_exit_slow_start(&mut self) {
        if !self.in_slow_start() {
            return;
        }
        let Some(rtt_stats) = self.rtt_stats.as_ref() else {
            return;
        };
        let latest_rtt = rtt_stats.latest_rtt();
        let min_rtt = rtt_stats.min_rtt();
        let congestion_window = self.get_congestion_window();
        if self.hybrid_slow_start.should_exit_slow_start(
            latest_rtt,
            min_rtt,
            congestion_window / self.max_datagram_size,
        ) {
            // exit slow start
            self.slow_start_threshold = self.congestion_window;
        }
    }

    fn on_packet_acked(
        &mut self,
        acked_packet_number: congestion::PacketNumber,
        acked_bytes: congestion::ByteCount,
        prior_in_flight: congestion::ByteCount,
        event_time: monotime::Time,
    ) {
        self.largest_acked_packet_number = max(acked_packet_number, self.largest_acked_packet_number);
        if self.in_recovery() {
            return;
        }
        self.maybe_increase_cwnd(acked_packet_number, acked_bytes, prior_in_flight, event_time);
        if self.in_slow_start() {
            self.hybrid_slow_start.on_packet_acked(acked_packet_number);
        }
    }

    fn on_congestion_event(
        &mut self,
        packet_number: congestion::PacketNumber,
        _lost_bytes: congestion::ByteCount,
        _prior_in_flight: congestion::ByteCount,
    ) {
        // TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
        // already sent should be treated as a single loss event, since it's expected.
        if packet_number <= self.largest_sent_at_last_cutback {
            return;
        }

        if self.reno {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_precision_loss,
                reason = "the Reno backoff scales the congestion window by the fractional `RENO_BETA` and truncates the result back to a byte count, which is the algorithm's own cut"
            )]
            let reno_window = (self.congestion_window as f64 * RENO_BETA) as congestion::ByteCount;
            self.congestion_window = reno_window;
        } else {
            self.congestion_window = self.cubic.congestion_window_after_packet_loss(self.congestion_window);
        }
        let min_cwnd = self.min_congestion_window();
        if self.congestion_window < min_cwnd {
            self.congestion_window = min_cwnd;
        }
        self.slow_start_threshold = self.congestion_window;
        self.largest_sent_at_last_cutback = self.largest_sent_packet_number;
        // reset packet count from congestion avoidance mode. We start
        // counting again when we're out of recovery.
        self.num_acked_packets = 0;
    }

    /// Called on a retransmission timeout.
    fn on_retransmission_timeout(&mut self, packets_retransmitted: bool) {
        self.largest_sent_at_last_cutback = INVALID_PACKET_NUMBER;
        if !packets_retransmitted {
            return;
        }
        self.hybrid_slow_start.restart();
        self.cubic.reset();
        self.slow_start_threshold = self.congestion_window / 2;
        self.congestion_window = self.min_congestion_window();
    }

    fn set_max_datagram_size(&mut self, size: congestion::ByteCount) {
        assert!(
            size >= self.max_datagram_size,
            "congestion BUG: decreased max datagram size from {} to {}",
            self.max_datagram_size,
            size
        );
        let cwnd_is_min_cwnd = self.congestion_window == self.min_congestion_window();
        self.max_datagram_size = size;
        if cwnd_is_min_cwnd {
            self.congestion_window = self.min_congestion_window();
        }
        self.pacer.set_max_datagram_size(size);
    }

    fn in_slow_start(&self) -> bool {
        self.get_congestion_window() < self.slow_start_threshold
    }

    fn in_recovery(&self) -> bool {
        self.largest_acked_packet_number != INVALID_PACKET_NUMBER
            && self.largest_acked_packet_number <= self.largest_sent_at_last_cutback
    }

    fn get_congestion_window(&self) -> congestion::ByteCount {
        self.congestion_window
    }
}

impl congestion::CongestionControlEx for CubicSender {
    fn on_congestion_event_ex(
        &mut self,
        _prior_in_flight: congestion::ByteCount,
        _event_time: monotime::Time,
        _acked_packets: &[congestion::AckedPacketInfo],
        _lost_packets: &[congestion::LostPacketInfo],
    ) {
        // Stub
    }
}

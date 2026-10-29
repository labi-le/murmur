use std::time::Duration;

use murmur_common::time::{duration_to_nanos, MICROSECOND};
use murmur_quic::congestion;

use super::minmax::{max, min};

// The magic clamping numbers come from the original code in tcp_cubic.c.
const HYBRID_START_LOW_WINDOW: congestion::ByteCount = 16;

/// Number of delay samples for detecting the increase of delay.
const HYBRID_START_MIN_SAMPLES: u32 = 8;

/// Exit slow start if the min rtt has increased by more than 1/8th.
const HYBRID_START_DELAY_FACTOR_EXP: u32 = 3;
const HYBRID_START_DELAY_MIN_THRESHOLD_US: i64 = 4000;
const HYBRID_START_DELAY_MAX_THRESHOLD_US: i64 = 16000;

/// `HybridSlowStart` implements the TCP hybrid slow start algorithm
#[derive(Debug, Default)]
pub struct HybridSlowStart {
    end_packet_number: congestion::PacketNumber,
    last_sent_packet_number: congestion::PacketNumber,
    started: bool,
    current_min_rtt: Duration,
    rtt_sample_count: u32,
    hystart_found: bool,
}

impl HybridSlowStart {
    /// Called for the start of each receive round (burst) in the slow start phase.
    pub const fn start_receive_round(&mut self, last_sent: congestion::PacketNumber) {
        self.end_packet_number = last_sent;
        self.current_min_rtt = Duration::ZERO;
        self.rtt_sample_count = 0;
        self.started = true;
    }

    /// True if this ack is the last packet number of the current slow start round.
    #[must_use]
    pub const fn is_end_of_round(&self, ack: congestion::PacketNumber) -> bool {
        self.end_packet_number < ack
    }

    /// Called on every new ack frame, since a new
    /// RTT measurement can be made then.
    /// rtt: the RTT for this ack packet.
    /// minRTT: is the lowest delay (RTT) we have seen during the session.
    /// congestionWindow: the congestion window in packets.
    pub fn should_exit_slow_start(
        &mut self,
        latest_rtt: Duration,
        min_rtt: Duration,
        congestion_window: congestion::ByteCount,
    ) -> bool {
        if !self.started {
            let last_sent = self.last_sent_packet_number;
            self.start_receive_round(last_sent);
        }
        if self.hystart_found {
            return true;
        }
        // Second detection parameter - delay increase detection: the minimum delay of the
        // current burst is compared against the minimum delay of the session, over the first
        // few packets of each burst only.
        self.rtt_sample_count += 1;
        if self.rtt_sample_count <= HYBRID_START_MIN_SAMPLES
            && (self.current_min_rtt.is_zero() || self.current_min_rtt > latest_rtt)
        {
            self.current_min_rtt = latest_rtt;
        }
        // We only need to check this once per round.
        if self.rtt_sample_count == HYBRID_START_MIN_SAMPLES {
            // Divide minRTT by 8 to get a rtt increase threshold for exiting.
            let min_rtt_increase_threshold_us =
                (duration_to_nanos(min_rtt) / MICROSECOND) >> HYBRID_START_DELAY_FACTOR_EXP;
            // Ensure the rtt threshold is never less than 2ms or more than 16ms.
            let min_rtt_increase_threshold_us = min(min_rtt_increase_threshold_us, HYBRID_START_DELAY_MAX_THRESHOLD_US);
            let min_rtt_increase_threshold_us = max(min_rtt_increase_threshold_us, HYBRID_START_DELAY_MIN_THRESHOLD_US);
            let min_rtt_increase_threshold = Duration::from_micros(min_rtt_increase_threshold_us.cast_unsigned());

            if self.current_min_rtt > min_rtt + min_rtt_increase_threshold {
                self.hystart_found = true;
            }
        }
        // Exit from slow start if the cwnd is greater than 16 and
        // increasing delay is found.
        congestion_window >= HYBRID_START_LOW_WINDOW && self.hystart_found
    }

    /// Called when a packet was sent.
    pub const fn on_packet_sent(&mut self, packet_number: congestion::PacketNumber) {
        self.last_sent_packet_number = packet_number;
    }

    /// Invoked after `should_exit_slow_start`, so it is best to end
    /// the round when the final packet of the burst is received and start it on
    /// the next incoming ack.
    pub fn on_packet_acked(&mut self, acked_packet_number: congestion::PacketNumber) {
        if self.is_end_of_round(acked_packet_number) {
            self.started = false;
        }
    }

    /// Started returns true if started
    #[must_use]
    pub const fn started(&self) -> bool {
        self.started
    }

    /// Restart the slow start phase
    pub const fn restart(&mut self) {
        self.started = false;
        self.hystart_found = false;
    }
}

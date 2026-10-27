//!
//! src from <https://quiche.googlesource.com/quiche.git/+/66dea072431f94095dfc3dd2743cb94ef365f7ef/quic/core/congestion_control/bbr_sender.cc>

use portable_atomic::AtomicI64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use murmur_common::time::duration_to_nanos;
use murmur_quic::congestion;
use murmur_quic::congestion::CongestionControl as _;
use murmur_quic::monotime;

use super::bandwidth::{bandwidth_from_delta, Bandwidth, INF_BANDWIDTH};
use super::bandwidth_sampler::{new_bandwidth_sampler, BandwidthSampler};
use super::pacer::{new_pacer, Pacer};
use super::windowed_filter::{max_filter, new_windowed_filter, WindowedFilter};

/// The default maximum packet size used in QUIC for congestion window computations in bytes.
pub const INITIAL_MAX_DATAGRAM_SIZE: congestion::ByteCount = 1280;
pub const INITIAL_PACKET_SIZE: congestion::ByteCount = 1280;
pub const INITIAL_CONGESTION_WINDOW: congestion::ByteCount = 32;
pub const DEFAULT_BBR_MAX_CONGESTION_WINDOW: congestion::ByteCount = 10000;

#[must_use]
pub fn get_initial_packet_size(initial_packet_size: u16) -> congestion::ByteCount {
    congestion::ByteCount::from(initial_packet_size)
}

/// Default initial rtt used before any samples are received.
pub const INITIAL_RTT: Duration = Duration::from_millis(100);

/// The gain used for the STARTUP, equal to  4*ln(2).
pub const DEFAULT_HIGH_GAIN: f64 = 2.77;

/// The gain used in STARTUP after loss has been detected.
/// 1.5 is enough to allow for 25% exogenous loss and still observe a 25% growth
/// in measured bandwidth.
pub const STARTUP_AFTER_LOSS_GAIN: f64 = 1.5;

/// The cycle of gains used during the PROBE_BW stage.
pub const PACING_GAIN: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

/// The length of the gain cycle.
pub const GAIN_CYCLE_LENGTH: usize = PACING_GAIN.len();

/// The size of the bandwidth filter window, in round-trips.
pub const BANDWIDTH_WINDOW_SIZE: usize = GAIN_CYCLE_LENGTH + 2;

/// The time after which the current `min_rtt` value expires.
pub const MIN_RTT_EXPIRY: Duration = Duration::from_secs(10);

/// The minimum time the connection can spend in PROBE_RTT mode.
pub const PROBE_RTT_TIME: Duration = Duration::from_millis(200);

/// If the bandwidth does not increase by the factor of `STARTUP_GROWTH_TARGET`
/// within `ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP` rounds, the connection
/// will exit the STARTUP mode.
pub const STARTUP_GROWTH_TARGET: f64 = 1.25;
pub const ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP: i64 = 3;

/// Coefficient of target congestion window to use when basing PROBE_RTT on BDP.
pub const MODERATE_PROBE_RTT_MULTIPLIER: f64 = 0.75;

/// Coefficient to determine if a new RTT is sufficiently similar to `min_rtt` that
/// we don't need to enter PROBE_RTT.
pub const SIMILAR_MIN_RTT_THRESHOLD: f64 = 1.125;

/// Congestion window gain for QUIC BBR during PROBE_BW phase.
pub const DEFAULT_CONGESTION_WINDOW_GAIN_CONST: f64 = 2.0;

pub const INFINITE_RTT: Duration = Duration::from_nanos(i64::MAX as u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BbrMode {
    /// Startup phase of the connection.
    Startup,
    /// After achieving the highest possible bandwidth during the startup, lower
    /// the pacing rate in order to drain the queue.
    Drain,
    /// Cruising mode.
    ProbeBw,
    /// Temporarily slow down sending in order to empty the buffer and measure
    /// the real minimum RTT.
    ProbeRtt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BbrRecoveryState {
    /// Do not limit.
    NotInRecovery,

    /// Allow an extra outstanding byte for each byte acknowledged.
    Conservation,

    /// Allow two extra outstanding bytes for each byte acknowledged (slow
    /// start).
    Growth,
}

#[expect(clippy::struct_excessive_bools, reason = "the flags mirror the sender's named conditions one-to-one")]
pub struct BbrSender {
    mode: BbrMode,
    rtt_stats: Option<Arc<dyn congestion::RttStatsProvider>>,
    /// Total bytes of unacked packets; the send-decision helpers take it by `&self`.
    bytes_in_flight: AtomicI64,
    /// Bandwidth sampler provides BBR with the bandwidth measurements at
    /// individual points.
    sampler: BandwidthSampler,
    /// The number of the round trips that have occurred during the connection.
    round_trip_count: i64,
    /// The packet number of the most recently sent packet.
    last_send_packet: congestion::PacketNumber,
    /// Acknowledgement of any packet after the current round-trip end will cause
    /// the round trip counter to advance.
    current_round_trip_end: congestion::PacketNumber,
    /// The filter that tracks the maximum bandwidth over the multiple recent
    /// round-trips.
    max_bandwidth: WindowedFilter,
    /// Tracks the maximum number of bytes acked faster than the sending rate.
    max_ack_height: WindowedFilter,
    /// The time this aggregation started and the number of bytes acked during it.
    aggregation_epoch_start_time: monotime::Time,
    aggregation_epoch_bytes: congestion::ByteCount,
    /// Minimum RTT estimate.  Automatically expires within 10 seconds (and
    /// triggers `PROBE_RTT` mode) if no new value is sampled during that period.
    min_rtt: Duration,
    /// The time at which the current value of `min_rtt` was assigned.
    min_rtt_timestamp: monotime::Time,
    /// The maximum allowed number of bytes in flight.
    congestion_window: congestion::ByteCount,
    /// The initial value of the |`congestion_window`_|.
    initial_congestion_window: congestion::ByteCount,
    /// The pacing gain applied during the STARTUP phase.
    high_gain: f64,
    /// The CWND gain applied during the STARTUP phase.
    high_cwnd_gain: f64,
    /// The pacing gain applied during the DRAIN phase.
    drain_gain: f64,
    /// The current pacing rate of the connection.
    pacing_rate: Bandwidth,
    /// The gain currently applied to the pacing rate.
    pacing_gain: f64,
    /// The gain currently applied to the congestion window.
    congestion_window_gain: f64,
    /// The gain used for the congestion window during PROBE_BW.  Latched from
    /// the congestion-window-gain setting.
    congestion_window_gain_const: f64,
    /// The number of RTTs to stay in STARTUP mode.  Defaults to 3.
    num_startup_rtts: i64,
    /// If true, exit startup if 1RTT has passed with no bandwidth increase and
    /// the connection is in recovery.
    exit_startup_on_loss: bool,
    /// Number of round-trips in PROBE_BW mode, used for determining the current
    /// pacing gain cycle.
    cycle_current_offset: usize,
    /// The time at which the last pacing gain cycle was started.
    last_cycle_start: monotime::Time,
    /// Indicates whether the connection has reached the full bandwidth mode.
    is_at_full_bandwidth: bool,
    /// Number of rounds during which there was no significant bandwidth increase.
    rounds_without_bandwidth_gain: i64,
    /// The bandwidth compared to which the increase is measured.
    bandwidth_at_last_round: Bandwidth,
    /// Set to true upon exiting quiescence.
    exiting_quiescence: bool,
    /// Time at which PROBE_RTT has to be exited.  Setting it to zero indicates
    /// that the time is yet unknown as the number of packets in flight has not
    /// reached the required value.
    exit_probe_rtt_at: monotime::Time,
    /// Indicates whether a round-trip has passed since PROBE_RTT became active.
    probe_rtt_round_passed: bool,
    /// Indicates whether the most recent bandwidth sample was marked as
    /// app-limited.
    last_sample_is_app_limited: bool,
    /// Indicates whether any non app-limited samples have been recorded.
    has_no_app_limited_sample: bool,
    /// Current state of recovery.
    recovery_state: BbrRecoveryState,
    /// Receiving acknowledgement of a packet after |`end_recovery_at`_| will cause
    /// BBR to exit the recovery mode.  A value above zero indicates at least one
    /// loss has been detected, so it must not be set back to zero.
    end_recovery_at: congestion::PacketNumber,
    /// A window used to limit the number of bytes in flight during loss recovery.
    recovery_window: congestion::ByteCount,
    /// If true, consider all samples in recovery app-limited.
    is_app_limited_recovery: bool,
    /// When true, pace at 1.5x and disable packet conservation in STARTUP.
    slower_startup: bool,
    /// When true, disables packet conservation in STARTUP.
    rate_based_startup: bool,
    /// When non-zero, decreases the rate in STARTUP by the total number of bytes
    /// lost in STARTUP divided by CWND.
    startup_rate_reduction_multiplier: i64,
    /// Sum of bytes lost in STARTUP.
    startup_bytes_lost: congestion::ByteCount,
    /// When true, add the most recent ack aggregation measurement during STARTUP.
    enable_ack_aggregation_during_startup: bool,
    /// When true, expire the windowed ack aggregation values in STARTUP when
    /// bandwidth increases more than 25%.
    expire_ack_aggregation_in_startup: bool,
    /// If true, will not exit low gain mode until `bytes_in_flight` drops below BDP
    /// or it's time for high gain mode.
    drain_to_target: bool,
    /// If true, use a CWND of 0.75*BDP during PROBE_RTT instead of 4 packets.
    probe_rtt_based_on_bdp: bool,
    /// If true, skip PROBE_RTT and update the timestamp of the existing `min_rtt` to
    /// now if `min_rtt` over the last cycle is within 12.5% of the current `min_rtt`.
    probe_rtt_skipped_if_similar_rtt: bool,
    /// If true, disable PROBE_RTT entirely as long as the connection was recently
    /// app limited.
    probe_rtt_disabled_if_app_limited: bool,
    app_limited_since_last_probe_rtt: bool,
    min_rtt_since_last_probe_rtt: Duration,
    /// Latched value of the always-sample-when-acked setting.
    always_get_bw_sample_when_acked: bool,

    pacer: Pacer,

    max_datagram_size: congestion::ByteCount,
}

impl core::fmt::Debug for BbrSender {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BbrSender")
            .field("mode", &self.mode)
            .field("recovery_state", &self.recovery_state)
            .field("round_trip_count", &self.round_trip_count)
            .field("congestion_window", &self.congestion_window)
            .field("pacing_rate", &self.pacing_rate)
            .field("bytes_in_flight", &self.bytes_in_flight)
            .finish_non_exhaustive()
    }
}

/// Creates a new BBR sender.
#[allow(
    private_interfaces,
    reason = "the sender type and its constructor are public, but the field types stay crate-internal, matching the unexported struct fields"
)]
pub fn new_bbr_sender(
    initial_max_datagram_size: congestion::ByteCount,
    initial_congestion_window: congestion::ByteCount,
    initial_max_congestion_window: congestion::ByteCount,
) -> BbrSender {
    BbrSender {
        mode: BbrMode::Startup,
        rtt_stats: None,
        bytes_in_flight: AtomicI64::new(0),
        sampler: new_bandwidth_sampler(),
        round_trip_count: 0,
        last_send_packet: 0,
        current_round_trip_end: 0,
        max_bandwidth: new_windowed_filter(bandwidth_window_size_i64(), max_filter),
        max_ack_height: new_windowed_filter(bandwidth_window_size_i64(), max_filter),
        aggregation_epoch_start_time: monotime::Time::default(),
        aggregation_epoch_bytes: 0,
        min_rtt: Duration::ZERO,
        min_rtt_timestamp: monotime::Time::default(),
        congestion_window: initial_congestion_window,
        initial_congestion_window,
        high_gain: DEFAULT_HIGH_GAIN,
        high_cwnd_gain: DEFAULT_HIGH_GAIN,
        drain_gain: 1.0 / DEFAULT_HIGH_GAIN,
        pacing_rate: 0,
        pacing_gain: 1.0,
        congestion_window_gain: 1.0,
        congestion_window_gain_const: DEFAULT_CONGESTION_WINDOW_GAIN_CONST,
        num_startup_rtts: ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP,
        exit_startup_on_loss: false,
        cycle_current_offset: 0,
        last_cycle_start: monotime::Time::default(),
        is_at_full_bandwidth: false,
        rounds_without_bandwidth_gain: 0,
        bandwidth_at_last_round: 0,
        exiting_quiescence: false,
        exit_probe_rtt_at: monotime::Time::default(),
        probe_rtt_round_passed: false,
        last_sample_is_app_limited: false,
        has_no_app_limited_sample: false,
        recovery_state: BbrRecoveryState::NotInRecovery,
        end_recovery_at: 0,
        recovery_window: initial_max_congestion_window,
        is_app_limited_recovery: false,
        slower_startup: false,
        rate_based_startup: false,
        startup_rate_reduction_multiplier: 0,
        startup_bytes_lost: 0,
        enable_ack_aggregation_during_startup: false,
        expire_ack_aggregation_in_startup: false,
        drain_to_target: false,
        probe_rtt_based_on_bdp: false,
        probe_rtt_skipped_if_similar_rtt: false,
        probe_rtt_disabled_if_app_limited: false,
        app_limited_since_last_probe_rtt: false,
        min_rtt_since_last_probe_rtt: INFINITE_RTT,
        always_get_bw_sample_when_acked: false,
        pacer: new_pacer(INF_BANDWIDTH),
        max_datagram_size: initial_max_datagram_size,
    }
}

impl BbrSender {
    const fn max_congestion_window(&self) -> congestion::ByteCount {
        self.max_datagram_size * DEFAULT_BBR_MAX_CONGESTION_WINDOW
    }

    const fn min_congestion_window(&self) -> congestion::ByteCount {
        self.max_datagram_size * self.initial_congestion_window
    }

    pub fn get_bytes_in_flight(&self) -> congestion::ByteCount {
        self.bytes_in_flight.load(Ordering::Relaxed)
    }

    /// True when the round trip counter advanced.
    pub const fn update_round_trip_counter(&mut self, last_acked_packet: congestion::PacketNumber) -> bool {
        if self.current_round_trip_end == 0 || last_acked_packet > self.current_round_trip_end {
            self.current_round_trip_end = last_acked_packet;
            self.round_trip_count += 1;
            return true;
        }
        false
    }

    pub fn update_bandwidth_and_min_rtt(
        &mut self,
        now: monotime::Time,
        acked_packets: &[congestion::AckedPacketInfo],
    ) -> bool {
        let mut sample_min_rtt = INFINITE_RTT;

        for packet in acked_packets {
            if !self.always_get_bw_sample_when_acked && packet.bytes_acked == 0 {
                // Skip acked packets with 0 in flight bytes when updating bandwidth.
                return false;
            }
            let bandwidth_sample = self.sampler.on_packet_acked(now, packet.packet_number);
            if self.always_get_bw_sample_when_acked && !bandwidth_sample.state_at_send.is_valid {
                // From the sampler's perspective, the packet has never been sent, or the
                // packet has been acked or marked as lost previously.
                return false;
            }
            self.last_sample_is_app_limited = bandwidth_sample.state_at_send.is_app_limited;
            if !bandwidth_sample.state_at_send.is_app_limited {
                self.has_no_app_limited_sample = true;
            }
            if bandwidth_sample.rtt > Duration::ZERO {
                sample_min_rtt = min_rtt(sample_min_rtt, bandwidth_sample.rtt);
            }
            if !bandwidth_sample.state_at_send.is_app_limited || bandwidth_sample.bandwidth > self.bandwidth_estimate()
            {
                self.max_bandwidth.update(bandwidth_sample.bandwidth.cast_signed(), self.round_trip_count);
            }
        }

        // If none of the RTT samples are valid, return immediately.
        if sample_min_rtt == INFINITE_RTT {
            return false;
        }

        self.min_rtt_since_last_probe_rtt = min_rtt(self.min_rtt_since_last_probe_rtt, sample_min_rtt);
        // Do not expire min_rtt if none was ever available.
        let mut min_rtt_expired = self.min_rtt > Duration::ZERO && now > self.min_rtt_timestamp.add(MIN_RTT_EXPIRY);
        if min_rtt_expired || sample_min_rtt < self.min_rtt || self.min_rtt == Duration::ZERO {
            if min_rtt_expired && self.should_extend_min_rtt_expiry() {
                min_rtt_expired = false;
            } else {
                self.min_rtt = sample_min_rtt;
            }
            self.min_rtt_timestamp = now;
            // Reset since_last_probe_rtt fields.
            self.min_rtt_since_last_probe_rtt = INFINITE_RTT;
            self.app_limited_since_last_probe_rtt = false;
        }

        min_rtt_expired
    }

    pub fn should_extend_min_rtt_expiry(&self) -> bool {
        if self.probe_rtt_disabled_if_app_limited && self.app_limited_since_last_probe_rtt {
            // Extend the current min_rtt if we've been app limited recently.
            return true;
        }

        #[expect(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "the 12.5% min-RTT margin is an f64 computation, truncated to whole non-negative nanoseconds"
        )]
        let min_rtt_increased_since_last_probe = self.min_rtt_since_last_probe_rtt
            > Duration::from_nanos((self.min_rtt.as_nanos() as f64 * SIMILAR_MIN_RTT_THRESHOLD) as u64);
        if self.probe_rtt_skipped_if_similar_rtt
            && self.app_limited_since_last_probe_rtt
            && !min_rtt_increased_since_last_probe
        {
            // Extend the current min_rtt if we've been app limited recently and an rtt
            // has been measured in that time that's less than 12.5% more than the
            // current min_rtt.
            return true;
        }

        false
    }

    pub fn discard_lost_packets(&mut self, lost_packets: &[congestion::LostPacketInfo]) {
        for packet in lost_packets {
            self.sampler.on_congestion_event(packet.packet_number);
            if self.mode == BbrMode::Startup && self.startup_rate_reduction_multiplier != 0 {
                self.startup_bytes_lost = self.startup_bytes_lost.wrapping_add(packet.bytes_lost);
            }
        }
    }

    pub fn update_recovery_state(&mut self, has_losses: bool, is_round_start: bool) {
        // Exit recovery when there are no losses for a round.
        if !has_losses {
            self.end_recovery_at = self.last_send_packet;
        }
        match self.recovery_state {
            BbrRecoveryState::NotInRecovery => {
                // Enter conservation on the first loss.
                if has_losses {
                    self.recovery_state = BbrRecoveryState::Conservation;
                    // This will cause the |recovery_window_| to be set to the correct
                    // value in CalculateRecoveryWindow().
                    self.recovery_window = 0;
                    // Since the conservation phase is meant to be lasting for a whole
                    // round, extend the current round as if it were started right now.
                    self.current_round_trip_end = self.last_send_packet;
                    // The guard short-circuits on a `false &&` over the app-limited sample, so this stays off.
                    let app_limited_recovery_enabled = false;
                    if app_limited_recovery_enabled && self.last_sample_is_app_limited {
                        self.is_app_limited_recovery = true;
                    }
                }
            }
            BbrRecoveryState::Conservation => {
                if is_round_start {
                    self.recovery_state = BbrRecoveryState::Growth;
                }
                // Falls through into the GROWTH case.
                if !has_losses && self.last_send_packet > self.end_recovery_at {
                    self.recovery_state = BbrRecoveryState::NotInRecovery;
                    self.is_app_limited_recovery = false;
                }
            }
            BbrRecoveryState::Growth => {
                // Exit recovery if appropriate.
                if !has_losses && self.last_send_packet > self.end_recovery_at {
                    self.recovery_state = BbrRecoveryState::NotInRecovery;
                    self.is_app_limited_recovery = false;
                }
            }
        }

        if self.recovery_state != BbrRecoveryState::NotInRecovery && self.is_app_limited_recovery {
            self.sampler.on_app_limited();
        }
    }

    pub fn update_ack_aggregation_bytes(
        &mut self,
        ack_time: monotime::Time,
        acked_bytes: congestion::ByteCount,
    ) -> congestion::ByteCount {
        // Compute how many bytes are expected to be delivered, assuming max bandwidth
        // is correct.
        let expected_acked_bytes = self
            .max_bandwidth
            .get_best()
            .wrapping_mul(duration_to_nanos(ack_time.sub(&self.aggregation_epoch_start_time)));
        // Reset the current aggregation epoch as soon as the ack arrival rate is less
        // than or equal to the max bandwidth.
        if self.aggregation_epoch_bytes <= expected_acked_bytes {
            // Reset to start measuring a new aggregation epoch.
            self.aggregation_epoch_bytes = acked_bytes;
            self.aggregation_epoch_start_time = ack_time;
            return 0;
        }
        // Compute how many extra bytes were delivered vs max bandwidth.
        // Include the bytes most recently acknowledged to account for stretch acks.
        self.aggregation_epoch_bytes = self.aggregation_epoch_bytes.wrapping_add(acked_bytes);
        self.max_ack_height.update(self.aggregation_epoch_bytes - expected_acked_bytes, self.round_trip_count);
        self.aggregation_epoch_bytes - expected_acked_bytes
    }

    pub fn update_gain_cycle_phase(
        &mut self,
        now: monotime::Time,
        prior_in_flight: congestion::ByteCount,
        has_losses: bool,
    ) {
        let bytes_in_flight = self.get_bytes_in_flight();
        // In most cases, the cycle is advanced after an RTT passes.
        let since_last_cycle_start = now.sub(&self.last_cycle_start);
        let advance_after_rtt = since_last_cycle_start > self.get_min_rtt();

        // If the pacing gain is above 1.0, the connection is trying to probe the
        // bandwidth by increasing the number of bytes in flight to at least
        // pacing_gain * BDP.  Make sure that it actually reaches the target, as long
        // as there are no losses suggesting that the buffers are not able to hold
        // that much.
        let probing_bandwidth = self.pacing_gain > 1.0
            && !has_losses
            && prior_in_flight < self.get_target_congestion_window(self.pacing_gain);
        // If pacing gain is below 1.0, the connection is trying to drain the extra
        // queue which could have been incurred by probing prior to it.  If the number
        // of bytes in flight falls down to the estimated BDP value earlier, conclude
        // that the queue has been successfully drained and exit this cycle early.
        let draining_early = self.pacing_gain < 1.0 && bytes_in_flight <= self.get_target_congestion_window(1.0);
        // A drained queue exits the cycle early; an unfinished probe holds it back.
        let should_advance_gain_cycling = draining_early || (advance_after_rtt && !probing_bandwidth);

        if should_advance_gain_cycling {
            self.cycle_current_offset = (self.cycle_current_offset + 1) % GAIN_CYCLE_LENGTH;
            self.last_cycle_start = now;
            let Some(gain) = PACING_GAIN.get(self.cycle_current_offset).copied() else {
                return;
            };
            // The gain table holds literal `1.0` entries, so the bit comparison is exact.
            let is_neutral_gain = gain.to_bits() == 1.0_f64.to_bits();
            // Stay in low gain mode until the target BDP is hit.
            // Low gain mode will be exited immediately when the target BDP is achieved.
            if self.drain_to_target
                && self.pacing_gain < 1.0
                && is_neutral_gain
                && bytes_in_flight > self.get_target_congestion_window(1.0)
            {
                return;
            }
            self.pacing_gain = gain;
        }
    }

    pub fn get_target_congestion_window(&self, gain: f64) -> congestion::ByteCount {
        let bdp = duration_to_nanos(self.get_min_rtt()).wrapping_mul(self.bandwidth_estimate().cast_signed());
        let mut congestion_window = scaled_bytes(gain * bytes_to_f64(bdp));

        // BDP estimate will be zero if no bandwidth samples are available yet.
        if congestion_window == 0 {
            congestion_window = scaled_bytes(gain * bytes_to_f64(self.initial_congestion_window));
        }

        max_byte_count(congestion_window, self.min_congestion_window())
    }

    pub fn check_if_full_bandwidth_reached(&mut self) {
        if self.last_sample_is_app_limited {
            return;
        }

        let target = scaled_bandwidth(bandwidth_to_f64(self.bandwidth_at_last_round) * STARTUP_GROWTH_TARGET);
        if self.bandwidth_estimate() >= target {
            self.bandwidth_at_last_round = self.bandwidth_estimate();
            self.rounds_without_bandwidth_gain = 0;
            if self.expire_ack_aggregation_in_startup {
                // Expire old excess delivery measurements now that bandwidth increased.
                self.max_ack_height.reset(0, self.round_trip_count);
            }
            return;
        }
        self.rounds_without_bandwidth_gain += 1;
        if self.rounds_without_bandwidth_gain >= self.num_startup_rtts
            || (self.exit_startup_on_loss && self.in_recovery())
        {
            self.is_at_full_bandwidth = true;
        }
    }

    pub fn maybe_exit_startup_or_drain(&mut self, now: monotime::Time) {
        if self.mode == BbrMode::Startup && self.is_at_full_bandwidth {
            self.on_exit_startup(now);
            self.mode = BbrMode::Drain;
            self.pacing_gain = self.drain_gain;
            self.congestion_window_gain = self.high_cwnd_gain;
        }
        if self.mode == BbrMode::Drain && self.get_bytes_in_flight() <= self.get_target_congestion_window(1.0) {
            self.enter_probe_bandwidth_mode(now);
        }
    }

    pub fn enter_probe_bandwidth_mode(&mut self, now: monotime::Time) {
        self.mode = BbrMode::ProbeBw;
        self.congestion_window_gain = self.congestion_window_gain_const;

        // Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
        // excluded because in that case increased gain and decreased gain would not
        // follow each other.
        let random = rand::random::<u64>() >> 1;
        self.cycle_current_offset = (random % (GAIN_CYCLE_LENGTH - 1) as u64) as usize;
        if self.cycle_current_offset >= 1 {
            self.cycle_current_offset += 1;
        }

        self.last_cycle_start = now;
        let Some(gain) = PACING_GAIN.get(self.cycle_current_offset).copied() else {
            return;
        };
        self.pacing_gain = gain;
    }

    pub fn maybe_enter_or_exit_probe_rtt(&mut self, now: monotime::Time, is_round_start: bool, min_rtt_expired: bool) {
        if min_rtt_expired && !self.exiting_quiescence && self.mode != BbrMode::ProbeRtt {
            if self.in_slow_start() {
                self.on_exit_startup(now);
            }
            self.mode = BbrMode::ProbeRtt;
            self.pacing_gain = 1.0;
            // Do not decide on the time to exit PROBE_RTT until bytes in flight
            // are at the target small value.
            self.exit_probe_rtt_at = monotime::Time::default();
        }

        if self.mode == BbrMode::ProbeRtt {
            self.sampler.on_app_limited();
            if self.exit_probe_rtt_at.is_zero() {
                // If the window has reached the appropriate size, schedule exiting
                // PROBE_RTT.  The CWND during PROBE_RTT is the minimum congestion window, but
                // we allow an extra packet since QUIC checks CWND before sending a
                // packet.
                if self.get_bytes_in_flight() < self.probe_rtt_congestion_window() + self.max_datagram_size {
                    self.exit_probe_rtt_at = now.add(PROBE_RTT_TIME);
                    self.probe_rtt_round_passed = false;
                }
            } else {
                if is_round_start {
                    self.probe_rtt_round_passed = true;
                }
                if now >= self.exit_probe_rtt_at && self.probe_rtt_round_passed {
                    self.min_rtt_timestamp = now;
                    if self.is_at_full_bandwidth {
                        self.enter_probe_bandwidth_mode(now);
                    } else {
                        self.enter_startup_mode(now);
                    }
                }
            }
        }
        self.exiting_quiescence = false;
    }

    pub fn probe_rtt_congestion_window(&self) -> congestion::ByteCount {
        if self.probe_rtt_based_on_bdp {
            self.get_target_congestion_window(MODERATE_PROBE_RTT_MULTIPLIER)
        } else {
            self.min_congestion_window()
        }
    }

    pub const fn enter_startup_mode(&mut self, _now: monotime::Time) {
        self.mode = BbrMode::Startup;
        self.pacing_gain = self.high_gain;
        self.congestion_window_gain = self.high_cwnd_gain;
    }

    /// Nothing to update: the startup-exit check only inspects the RTT stats, and the
    /// slow-start statistics it would then adjust are not implemented.
    pub const fn on_exit_startup(&self, _now: monotime::Time) {}

    pub fn calculate_pacing_rate(&mut self) {
        if self.bandwidth_estimate() == 0 {
            return;
        }

        let target_rate = scaled_bandwidth(self.pacing_gain * bandwidth_to_f64(self.bandwidth_estimate()));
        if self.is_at_full_bandwidth {
            self.pacing_rate = target_rate;
            return;
        }

        // Pace at the rate of initial_window / RTT as soon as RTT measurements are
        // available.
        if self.pacing_rate == 0 {
            let Some(rtt_stats) = self.rtt_stats.as_ref() else {
                return;
            };
            let min_rtt = rtt_stats.min_rtt();
            if min_rtt > Duration::ZERO {
                self.pacing_rate = bandwidth_from_delta(self.initial_congestion_window, min_rtt);
                return;
            }
        }
        // Slow the pacing rate in STARTUP once loss has ever been detected.
        let has_ever_detected_loss = self.end_recovery_at > 0;
        if self.slower_startup && has_ever_detected_loss && self.has_no_app_limited_sample {
            self.pacing_rate = scaled_bandwidth(STARTUP_AFTER_LOSS_GAIN * bandwidth_to_f64(self.bandwidth_estimate()));
            return;
        }

        // Slow the pacing rate in STARTUP by the bytes_lost / CWND.
        if self.startup_rate_reduction_multiplier != 0 && has_ever_detected_loss && self.has_no_app_limited_sample {
            self.pacing_rate = scaled_bandwidth(
                (1.0 - (bytes_to_f64(self.startup_bytes_lost) * bytes_to_f64(self.startup_rate_reduction_multiplier)
                    / bytes_to_f64(self.congestion_window)))
                    * bandwidth_to_f64(target_rate),
            );
            // Ensure the pacing rate doesn't drop below the startup growth target times
            // the bandwidth estimate.
            self.pacing_rate = max_bandwidth(
                self.pacing_rate,
                scaled_bandwidth(STARTUP_GROWTH_TARGET * bandwidth_to_f64(self.bandwidth_estimate())),
            );
            return;
        }

        // Do not decrease the pacing rate during startup.
        self.pacing_rate = max_bandwidth(self.pacing_rate, target_rate);
    }

    pub fn calculate_congestion_window(
        &mut self,
        acked_bytes: congestion::ByteCount,
        excess_acked: congestion::ByteCount,
    ) {
        if self.mode == BbrMode::ProbeRtt {
            return;
        }

        let mut target_window = self.get_target_congestion_window(self.congestion_window_gain);
        if self.is_at_full_bandwidth {
            // Add the max recently measured ack aggregation to CWND.
            target_window = target_window.wrapping_add(self.max_ack_height.get_best());
        } else if self.enable_ack_aggregation_during_startup {
            // Add the most recent excess acked.  Because CWND never decreases in
            // STARTUP, this will automatically create a very localized max filter.
            target_window = target_window.wrapping_add(excess_acked);
        }

        // Instead of immediately setting the target CWND as the new one, BBR grows
        // the CWND towards |target_window| by only increasing it |bytes_acked| at a
        // time.
        // The expression short-circuits with `true || !in_recovery()`, so this is always true.
        let add_bytes_acked = true;
        if self.is_at_full_bandwidth {
            self.congestion_window = min_byte_count(target_window, self.congestion_window + acked_bytes);
        } else if add_bytes_acked
            && (self.congestion_window < target_window
                || self.sampler.total_bytes_acked < self.initial_congestion_window)
        {
            // If the connection is not yet out of startup phase, do not decrease the
            // window.
            self.congestion_window += acked_bytes;
        }

        // Enforce the limits on the congestion window.
        self.congestion_window = max_byte_count(self.congestion_window, self.min_congestion_window());
        self.congestion_window = min_byte_count(self.congestion_window, self.max_congestion_window());
    }

    pub fn calculate_recovery_window(&mut self, acked_bytes: congestion::ByteCount, lost_bytes: congestion::ByteCount) {
        if self.rate_based_startup && self.mode == BbrMode::Startup {
            return;
        }

        if self.recovery_state == BbrRecoveryState::NotInRecovery {
            return;
        }

        // Set up the initial recovery window.
        if self.recovery_window == 0 {
            self.recovery_window =
                max_byte_count(self.get_bytes_in_flight() + acked_bytes, self.min_congestion_window());
            return;
        }

        // Remove losses from the recovery window, while accounting for a potential
        // integer underflow.
        if self.recovery_window >= lost_bytes {
            self.recovery_window -= lost_bytes;
        } else {
            self.recovery_window = self.max_datagram_size;
        }
        // In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
        // release additional |bytes_acked| to achieve a slow-start-like behavior.
        if self.recovery_state == BbrRecoveryState::Growth {
            self.recovery_window += acked_bytes;
        }
        // Sanity checks.  Ensure that we always allow to send at least an MSS or
        // |bytes_acked| in response, whichever is larger.
        self.recovery_window = max_byte_count(self.recovery_window, self.get_bytes_in_flight() + acked_bytes);
        self.recovery_window = max_byte_count(self.recovery_window, self.min_congestion_window());
    }

    /// The minimum RTT, or the default initial RTT if none was sampled.
    pub fn get_min_rtt(&self) -> Duration {
        if self.min_rtt > Duration::ZERO {
            self.min_rtt
        } else {
            INITIAL_RTT
        }
    }

    /// The current bandwidth estimate.
    pub fn bandwidth_estimate(&self) -> Bandwidth {
        let Some(rtt_stats) = self.rtt_stats.as_ref() else {
            return INF_BANDWIDTH;
        };
        let srtt = rtt_stats.smoothed_rtt();
        if srtt == Duration::ZERO {
            // If we haven't measured an rtt, the bandwidth estimate is unknown.
            return INF_BANDWIDTH;
        }
        bandwidth_from_delta(self.get_congestion_window(), srtt)
    }
}

impl congestion::CongestionControl for BbrSender {
    fn set_rtt_stats_provider(&mut self, provider: Arc<dyn congestion::RttStatsProvider>) {
        self.rtt_stats = Some(provider);
    }

    fn get_congestion_window(&self) -> congestion::ByteCount {
        if self.mode == BbrMode::ProbeRtt {
            return self.probe_rtt_congestion_window();
        }

        if self.in_recovery() && !(self.rate_based_startup && self.mode == BbrMode::Startup) {
            return min_byte_count(self.congestion_window, self.recovery_window);
        }

        self.congestion_window
    }

    fn maybe_exit_slow_start(&mut self) {}

    fn on_packet_acked(
        &mut self,
        _number: congestion::PacketNumber,
        _acked_bytes: congestion::ByteCount,
        _prior_in_flight: congestion::ByteCount,
        _event_time: monotime::Time,
    ) {
        // Stub
    }

    fn on_congestion_event(
        &mut self,
        _number: congestion::PacketNumber,
        _lost_bytes: congestion::ByteCount,
        _prior_in_flight: congestion::ByteCount,
    ) {
        // Stub
    }

    /// When the next packet should be sent.
    fn time_until_send(&self, bytes_in_flight: congestion::ByteCount) -> monotime::Time {
        self.bytes_in_flight.store(bytes_in_flight, Ordering::Relaxed);
        self.pacer.time_until_send(self.bandwidth_estimate())
    }

    fn has_pacing_budget(&self, now: monotime::Time) -> bool {
        self.pacer.budget(now, self.bandwidth_estimate()) >= self.max_datagram_size
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

    fn on_packet_sent(
        &mut self,
        sent_time: monotime::Time,
        bytes_in_flight: congestion::ByteCount,
        packet_number: congestion::PacketNumber,
        bytes: congestion::ByteCount,
        is_retransmittable: bool,
    ) {
        let bandwidth = self.bandwidth_estimate();
        self.pacer.sent_packet(sent_time, bytes, bandwidth);

        self.last_send_packet = packet_number;

        self.bytes_in_flight.store(bytes_in_flight, Ordering::Relaxed);
        if bytes_in_flight == 0 && self.sampler.is_app_limited {
            self.exiting_quiescence = true;
        }

        if self.aggregation_epoch_start_time.is_zero() {
            self.aggregation_epoch_start_time = sent_time;
        }

        self.sampler.on_packet_sent(sent_time, packet_number, bytes, bytes_in_flight, is_retransmittable);
    }

    fn can_send(&self, bytes_in_flight: congestion::ByteCount) -> bool {
        self.bytes_in_flight.store(bytes_in_flight, Ordering::Relaxed);
        bytes_in_flight < self.get_congestion_window()
    }

    fn on_retransmission_timeout(&mut self, _packets_retransmitted: bool) {}

    fn in_slow_start(&self) -> bool {
        self.mode == BbrMode::Startup
    }

    fn in_recovery(&self) -> bool {
        self.recovery_state != BbrRecoveryState::NotInRecovery
    }
}

impl congestion::CongestionControlEx for BbrSender {
    fn on_congestion_event_ex(
        &mut self,
        prior_in_flight: congestion::ByteCount,
        event_time: monotime::Time,
        acked_packets: &[congestion::AckedPacketInfo],
        lost_packets: &[congestion::LostPacketInfo],
    ) {
        let total_bytes_acked_before = self.sampler.total_bytes_acked;
        let mut is_round_start = false;
        let mut min_rtt_expired = false;

        if !lost_packets.is_empty() {
            self.discard_lost_packets(lost_packets);
        }

        // Input the new data into the BBR model of the connection.
        let excess_acked: congestion::ByteCount = if let Some(last_acked) = acked_packets.last() {
            is_round_start = self.update_round_trip_counter(last_acked.packet_number);
            min_rtt_expired = self.update_bandwidth_and_min_rtt(event_time, acked_packets);
            self.update_recovery_state(!lost_packets.is_empty(), is_round_start);
            let bytes_acked = self.sampler.total_bytes_acked - total_bytes_acked_before;
            self.update_ack_aggregation_bytes(event_time, bytes_acked)
        } else {
            0
        };

        // Handle logic specific to PROBE_BW mode.
        if self.mode == BbrMode::ProbeBw {
            self.update_gain_cycle_phase(event_time, prior_in_flight, !lost_packets.is_empty());
        }

        // Handle logic specific to STARTUP and DRAIN modes.
        if is_round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bandwidth_reached();
        }
        self.maybe_exit_startup_or_drain(event_time);

        // Handle logic specific to PROBE_RTT.
        self.maybe_enter_or_exit_probe_rtt(event_time, is_round_start, min_rtt_expired);

        // Calculate number of packets acked and lost.
        let bytes_acked = self.sampler.total_bytes_acked - total_bytes_acked_before;
        let mut bytes_lost: congestion::ByteCount = 0;
        for packet in lost_packets {
            bytes_lost += packet.bytes_lost;
        }

        // After the model is updated, recalculate the pacing rate and congestion
        // window.
        self.calculate_pacing_rate();
        self.calculate_congestion_window(bytes_acked, excess_acked);
        self.calculate_recovery_window(bytes_acked, bytes_lost);
    }
}

fn min_rtt(a: Duration, b: Duration) -> Duration {
    if a < b {
        a
    } else {
        b
    }
}

pub(crate) const fn min_bandwidth(a: Bandwidth, b: Bandwidth) -> Bandwidth {
    if a < b {
        a
    } else {
        b
    }
}

const fn max_bandwidth(a: Bandwidth, b: Bandwidth) -> Bandwidth {
    if a > b {
        a
    } else {
        b
    }
}

const fn max_byte_count(a: congestion::ByteCount, b: congestion::ByteCount) -> congestion::ByteCount {
    if a > b {
        a
    } else {
        b
    }
}

const fn min_byte_count(a: congestion::ByteCount, b: congestion::ByteCount) -> congestion::ByteCount {
    if a < b {
        a
    } else {
        b
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts are bounded, well inside the exactly representable f64 range"
)]
fn bytes_to_f64(bytes: congestion::ByteCount) -> f64 {
    bytes as f64
}

#[expect(
    clippy::cast_precision_loss,
    reason = "link rates are bounded, well inside the exactly representable f64 range"
)]
fn bandwidth_to_f64(bandwidth: Bandwidth) -> f64 {
    bandwidth as f64
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the gained window is bounded by max_congestion_window, so the truncation is bounded"
)]
fn scaled_bytes(value: f64) -> congestion::ByteCount {
    value as congestion::ByteCount
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the gained rate is bounded by max_congestion_window, so the truncation is bounded"
)]
#[expect(clippy::cast_sign_loss, reason = "the gained rate is non-negative by construction")]
fn scaled_bandwidth(value: f64) -> Bandwidth {
    value as Bandwidth
}

/// The bandwidth filter window, in round-trips, as the `i64` the windowed filter stores.
fn bandwidth_window_size_i64() -> i64 {
    i64::try_from(BANDWIDTH_WINDOW_SIZE).unwrap_or(i64::MAX)
}

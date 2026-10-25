//!
//! src from <https://github.com/google/quiche/blob/e7872fc9e12bb1d46a118949c3d4da36de58aa44/quiche/quic/core/congestion_control/bbr_sender.cc>

use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;

use murmur_quic::congestion::{
    AckedPacketInfo, ByteCount, CongestionControl, CongestionControlEx, LostPacketInfo, PacketNumber, RttStatsProvider,
    MAX_CONGESTION_WINDOW_PACKETS, MAX_PACKET_BUFFER_SIZE, PACKETS_PER_CONNECTION_ID,
};
use murmur_quic::monotime;

use super::bandwidth::{bandwidth_from_delta, Bandwidth, BYTES_PER_SECOND, INF_BANDWIDTH};
use super::bandwidth_sampler::{
    new_bandwidth_sampler, BandwidthSampler, CongestionEventSample, RoundTripCount, SendTimeState, INF_RTT,
};
use super::minmax::{max, min};
use super::pacer::Pacer;
use super::windowed_filter::{max_filter, new_windowed_filter, WindowedFilter};

pub(crate) const MIN_BPS: ByteCount = 65536; // 64 KB/s

pub(crate) const INVALID_PACKET_NUMBER: PacketNumber = -1;
pub(crate) const MIN_CONGESTION_WINDOW_PACKETS: ByteCount = 4;

// Constants based on TCP defaults.
// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
// Does not inflate the pacing rate.
// The gain used for the STARTUP, equal to 2/ln(2).
pub(crate) const DEFAULT_HIGH_GAIN: f64 = 2.885;
// The newly derived CWND gain for STARTUP, 2.
pub(crate) const DERIVED_HIGH_CWND_GAIN: f64 = 2.0;

// The cycle of gains used during the PROBE_BW stage.
pub(crate) const PACING_GAIN: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

// The length of the gain cycle.
pub(crate) const GAIN_CYCLE_LENGTH: usize = PACING_GAIN.len();
// The size of the bandwidth filter window, in round-trips.
pub(crate) const BANDWIDTH_WINDOW_SIZE: usize = GAIN_CYCLE_LENGTH + 2;

// The time after which the current min_rtt value expires.
pub(crate) const MIN_RTT_EXPIRY: Duration = Duration::from_secs(10);
// The minimum time the connection can spend in PROBE_RTT mode.
pub(crate) const PROBE_RTT_TIME: Duration = Duration::from_millis(200);
// If the bandwidth does not increase by the factor of `STARTUP_GROWTH_TARGET`
// within `ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP` rounds, the connection
// will exit the STARTUP mode.
pub(crate) const STARTUP_GROWTH_TARGET: f64 = 1.25;
pub(crate) const ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP: i64 = 3;

// Flag.
pub(crate) const DEFAULT_STARTUP_FULL_LOSS_COUNT: u64 = 8;
pub(crate) const QUIC_BBR2_DEFAULT_LOSS_THRESHOLD: f64 = 0.02;

/// the `type bbrMode int`, the phase of the connection.
pub(crate) type BbrMode = i32;

// Startup phase of the connection.
pub(crate) const BBR_MODE_STARTUP: BbrMode = 0;
// After achieving the highest possible bandwidth during the startup, lower
// the pacing rate in order to drain the queue.
pub(crate) const BBR_MODE_DRAIN: BbrMode = 1;
// Cruising mode.
pub(crate) const BBR_MODE_PROBE_BW: BbrMode = 2;
// Temporarily slow down sending in order to empty the buffer and measure
// the real minimum RTT.
pub(crate) const BBR_MODE_PROBE_RTT: BbrMode = 3;

/// the `type bbrRecoveryState int`: how the congestion control limits the
/// amount of bytes in flight.
pub(crate) type BbrRecoveryState = i32;

// Do not limit.
pub(crate) const BBR_RECOVERY_STATE_NOT_IN_RECOVERY: BbrRecoveryState = 0;
// Allow an extra outstanding byte for each byte acknowledged.
pub(crate) const BBR_RECOVERY_STATE_CONSERVATION: BbrRecoveryState = 1;
// Allow two extra outstanding bytes for each byte acknowledged (slow
// start).
pub(crate) const BBR_RECOVERY_STATE_GROWTH: BbrRecoveryState = 2;

pub const PROFILE_CONSERVATIVE: &str = "conservative";
pub const PROFILE_STANDARD: &str = "standard";
pub const PROFILE_AGGRESSIVE: &str = "aggressive";

/// the `type Profile string`, the parameter set the sender runs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    ProfileConservative,
    ProfileStandard,
    ProfileAggressive,
}

/// The profile default: anything but `conservative`/`aggressive` runs `standard`.
impl Default for Profile {
    fn default() -> Self {
        Self::ProfileStandard
    }
}

impl Profile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProfileConservative => PROFILE_CONSERVATIVE,
            Self::ProfileStandard => PROFILE_STANDARD,
            Self::ProfileAggressive => PROFILE_AGGRESSIVE,
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Any string converts to a `Profile`; an unknown one behaves as the
/// standard profile, which is also the default.
impl From<&str> for Profile {
    fn from(profile: &str) -> Self {
        match profile {
            PROFILE_CONSERVATIVE => Self::ProfileConservative,
            PROFILE_AGGRESSIVE => Self::ProfileAggressive,
            _ => Self::ProfileStandard,
        }
    }
}

impl FromStr for Profile {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Infallible> {
        Ok(Self::from(s))
    }
}

#[expect(clippy::struct_excessive_bools, reason = "the flags mirror the profile parameter set one-to-one")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProfileConfig {
    high_gain: f64,
    high_cwnd_gain: f64,
    congestion_window_gain_constant: f64,
    num_startup_rtts: i64,
    drain_to_target: bool,
    detect_overshooting: bool,
    bytes_lost_multiplier: u8,
    enable_ack_aggregation_startup: bool,
    expire_ack_aggregation_startup: bool,
    enable_overestimate_avoidance: bool,
    reduce_extra_acked_on_bandwidth_increase: bool,
}

pub(crate) fn config_for_profile(profile: Profile) -> ProfileConfig {
    match profile {
        Profile::ProfileConservative => ProfileConfig {
            high_gain: 2.25,
            high_cwnd_gain: 1.75,
            congestion_window_gain_constant: 1.75,
            num_startup_rtts: 2,
            drain_to_target: true,
            detect_overshooting: true,
            bytes_lost_multiplier: 1,
            enable_ack_aggregation_startup: false,
            expire_ack_aggregation_startup: false,
            enable_overestimate_avoidance: true,
            reduce_extra_acked_on_bandwidth_increase: true,
        },
        Profile::ProfileAggressive => ProfileConfig {
            high_gain: 3.0,
            high_cwnd_gain: 2.25,
            congestion_window_gain_constant: 2.5,
            num_startup_rtts: 4,
            drain_to_target: false,
            detect_overshooting: false,
            bytes_lost_multiplier: 2,
            enable_ack_aggregation_startup: true,
            expire_ack_aggregation_startup: true,
            enable_overestimate_avoidance: false,
            reduce_extra_acked_on_bandwidth_increase: false,
        },
        Profile::ProfileStandard => ProfileConfig {
            high_gain: DEFAULT_HIGH_GAIN,
            high_cwnd_gain: DERIVED_HIGH_CWND_GAIN,
            congestion_window_gain_constant: 2.0,
            num_startup_rtts: ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP,
            drain_to_target: false,
            detect_overshooting: false,
            bytes_lost_multiplier: 2,
            enable_ack_aggregation_startup: false,
            expire_ack_aggregation_startup: false,
            enable_overestimate_avoidance: false,
            reduce_extra_acked_on_bandwidth_increase: false,
        },
    }
}

#[expect(clippy::struct_excessive_bools, reason = "the flags mirror the sender's named conditions one-to-one")]
pub struct BbrSender {
    rtt_stats: Option<Arc<dyn RttStatsProvider>>,
    pacer: Pacer,

    mode: BbrMode,

    // Bandwidth sampler provides BBR with the bandwidth measurements at
    // individual points.
    sampler: BandwidthSampler,

    // The number of the round trips that have occurred during the connection.
    round_trip_count: RoundTripCount,

    // The packet number of the most recently sent packet.
    last_sent_packet: PacketNumber,
    // Acknowledgement of any packet after |current_round_trip_end_| will cause
    // the round trip counter to advance.
    current_round_trip_end: PacketNumber,

    // Number of congestion events with some losses, in the current round.
    num_loss_events_in_round: u64,

    // Number of total bytes lost in the current round.
    bytes_lost_in_round: ByteCount,

    // The filter that tracks the maximum bandwidth over the multiple recent
    // round-trips.
    max_bandwidth: WindowedFilter<Bandwidth, RoundTripCount>,

    // Minimum RTT estimate.  Automatically expires within 10 seconds (and
    // triggers PROBE_RTT mode) if no new value is sampled during that period.
    min_rtt: Duration,
    // The time at which the current value of |min_rtt_| was assigned.
    min_rtt_timestamp: Option<monotime::Time>,

    // The maximum allowed number of bytes in flight.
    congestion_window: ByteCount,

    // The initial value of the |congestion_window_|.
    initial_congestion_window: ByteCount,

    // The largest value the |congestion_window_| can achieve.
    max_congestion_window: ByteCount,

    // The smallest value the |congestion_window_| can achieve.
    min_congestion_window: ByteCount,

    // The BBR profile used by the sender.
    profile: Profile,

    // The pacing gain applied during the STARTUP phase.
    high_gain: f64,

    // The CWND gain applied during the STARTUP phase.
    high_cwnd_gain: f64,

    // The pacing gain applied during the DRAIN phase.
    drain_gain: f64,

    // The current pacing rate of the connection.
    pacing_rate: Bandwidth,

    // The gain currently applied to the pacing rate.
    pacing_gain: f64,
    // The gain currently applied to the congestion window.
    congestion_window_gain: f64,

    // The gain used for the congestion window during PROBE_BW.  Latched from
    // the congestion-window-gain setting.
    congestion_window_gain_constant: f64,
    // The number of RTTs to stay in STARTUP mode.  Defaults to 3.
    num_startup_rtts: i64,

    // Number of round-trips in PROBE_BW mode, used for determining the current
    // pacing gain cycle.
    cycle_current_offset: i32,
    // The time at which the last pacing gain cycle was started.
    last_cycle_start: Option<monotime::Time>,

    // Indicates whether the connection has reached the full bandwidth mode.
    is_at_full_bandwidth: bool,
    // Number of rounds during which there was no significant bandwidth increase.
    rounds_without_bandwidth_gain: i64,
    // The bandwidth compared to which the increase is measured.
    bandwidth_at_last_round: Bandwidth,

    // Set to true upon exiting quiescence.
    exiting_quiescence: bool,

    // Time at which PROBE_RTT has to be exited.  Setting it to zero indicates
    // that the time is yet unknown as the number of packets in flight has not
    // reached the required value.
    exit_probe_rtt_at: Option<monotime::Time>,
    // Indicates whether a round-trip has passed since PROBE_RTT became active.
    probe_rtt_round_passed: bool,

    // Indicates whether the most recent bandwidth sample was marked as
    // app-limited.
    last_sample_is_app_limited: bool,
    // Indicates whether any non app-limited samples have been recorded.
    has_no_app_limited_sample: bool,

    // Current state of recovery.
    recovery_state: BbrRecoveryState,
    // Receiving acknowledgement of a packet after |end_recovery_at_| will cause
    // BBR to exit the recovery mode.  A value above zero indicates at least one
    // loss has been detected, so it must not be set back to zero.
    end_recovery_at: PacketNumber,
    // A window used to limit the number of bytes in flight during loss recovery.
    recovery_window: ByteCount,

    // When true, add the most recent ack aggregation measurement during STARTUP.
    enable_ack_aggregation_during_startup: bool,
    // When true, expire the windowed ack aggregation values in STARTUP when
    // bandwidth increases more than 25%.
    expire_ack_aggregation_in_startup: bool,

    // If true, will not exit low gain mode until bytes_in_flight drops below BDP
    // or it's time for high gain mode.
    drain_to_target: bool,

    // If true, slow down pacing rate in STARTUP when overshooting is detected.
    detect_overshooting: bool,
    // Bytes lost while detect_overshooting_ is true.
    bytes_lost_while_detecting_overshooting: ByteCount,
    // Slow down pacing rate if
    // bytes_lost_while_detecting_overshooting_ *
    // bytes_lost_multiplier_while_detecting_overshooting_ > IW.
    bytes_lost_multiplier_while_detecting_overshooting: u8,
    // When overshooting is detected, do not drop pacing_rate_ below this value /
    // min_rtt.
    cwnd_to_calculate_min_pacing_rate: ByteCount,

    // Max congestion window when adjusting network parameters.
    max_congestion_window_with_network_parameters_adjusted: ByteCount, // not used

    // Params.
    max_datagram_size: ByteCount,
    // Recorded on packet sent. equivalent |unacked_packets_->bytes_in_flight()|
    bytes_in_flight: ByteCount,
}

impl fmt::Debug for BbrSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BbrSender")
            .field("mode", &self.mode)
            .field("round_trip_count", &self.round_trip_count)
            .field("congestion_window", &self.congestion_window)
            .field("pacing_rate", &self.pacing_rate)
            .field("bytes_in_flight", &self.bytes_in_flight)
            .field("min_rtt", &self.min_rtt)
            .field("recovery_state", &self.recovery_state)
            .finish_non_exhaustive()
    }
}

#[allow(
    private_interfaces,
    reason = "the sender type and its constructor are public, but the field types stay crate-internal, matching the unexported struct fields"
)]
#[must_use]
pub fn new_bbr_sender(
    initial_max_datagram_size: ByteCount,
    initial_congestion_window_packets: ByteCount,
    profile: Profile,
) -> BbrSender {
    new_bbr_sender_with_windows(
        initial_max_datagram_size,
        initial_congestion_window_packets * initial_max_datagram_size,
        MAX_CONGESTION_WINDOW_PACKETS * initial_max_datagram_size,
        profile,
    )
}

/// The window-taking constructor, told apart from the exported one by the casing
/// rules rather than by its name.
pub(crate) fn new_bbr_sender_with_windows(
    initial_max_datagram_size: ByteCount,
    initial_congestion_window: ByteCount,
    initial_max_congestion_window: ByteCount,
    profile: Profile,
) -> BbrSender {
    let mut b = BbrSender {
        rtt_stats: None,
        pacer: Pacer::new_pacer(),
        mode: BBR_MODE_STARTUP,
        sampler: new_bandwidth_sampler(BANDWIDTH_WINDOW_SIZE as RoundTripCount),
        round_trip_count: 0,
        last_sent_packet: INVALID_PACKET_NUMBER,
        current_round_trip_end: INVALID_PACKET_NUMBER,
        num_loss_events_in_round: 0,
        bytes_lost_in_round: 0,
        max_bandwidth: new_windowed_filter(BANDWIDTH_WINDOW_SIZE as RoundTripCount, max_filter::<Bandwidth>),
        min_rtt: Duration::ZERO,
        min_rtt_timestamp: None,
        congestion_window: initial_congestion_window,
        initial_congestion_window,
        max_congestion_window: initial_max_congestion_window,
        min_congestion_window: min_congestion_window_for_max_datagram_size(initial_max_datagram_size),
        profile: Profile::ProfileStandard,
        high_gain: DEFAULT_HIGH_GAIN,
        high_cwnd_gain: DERIVED_HIGH_CWND_GAIN,
        drain_gain: 1.0 / DEFAULT_HIGH_GAIN,
        pacing_rate: 0,
        pacing_gain: 1.0,
        congestion_window_gain: 1.0,
        congestion_window_gain_constant: 2.0,
        num_startup_rtts: ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP,
        cycle_current_offset: 0,
        last_cycle_start: None,
        is_at_full_bandwidth: false,
        rounds_without_bandwidth_gain: 0,
        bandwidth_at_last_round: 0,
        exiting_quiescence: false,
        exit_probe_rtt_at: None,
        probe_rtt_round_passed: false,
        last_sample_is_app_limited: false,
        has_no_app_limited_sample: false,
        recovery_state: BBR_RECOVERY_STATE_NOT_IN_RECOVERY,
        end_recovery_at: INVALID_PACKET_NUMBER,
        recovery_window: initial_max_congestion_window,
        enable_ack_aggregation_during_startup: false,
        expire_ack_aggregation_in_startup: false,
        drain_to_target: false,
        detect_overshooting: false,
        bytes_lost_while_detecting_overshooting: 0,
        bytes_lost_multiplier_while_detecting_overshooting: 2,
        cwnd_to_calculate_min_pacing_rate: initial_congestion_window,
        max_congestion_window_with_network_parameters_adjusted: initial_max_congestion_window,
        max_datagram_size: initial_max_datagram_size,
        bytes_in_flight: 0,
    };

    b.apply_profile(profile);

    b.enter_startup_mode();

    b
}

impl BbrSender {
    pub(crate) fn apply_profile(&mut self, profile: Profile) {
        let cfg = config_for_profile(profile);
        self.profile = profile;
        self.high_gain = cfg.high_gain;
        self.high_cwnd_gain = cfg.high_cwnd_gain;
        self.drain_gain = 1.0 / cfg.high_gain;
        self.congestion_window_gain_constant = cfg.congestion_window_gain_constant;
        self.num_startup_rtts = cfg.num_startup_rtts;
        self.drain_to_target = cfg.drain_to_target;
        self.detect_overshooting = cfg.detect_overshooting;
        self.bytes_lost_multiplier_while_detecting_overshooting = cfg.bytes_lost_multiplier;
        self.enable_ack_aggregation_during_startup = cfg.enable_ack_aggregation_startup;
        self.expire_ack_aggregation_in_startup = cfg.expire_ack_aggregation_startup;
        if cfg.enable_overestimate_avoidance {
            self.sampler.enable_overestimate_avoidance();
        }
        self.sampler.set_reduce_extra_acked_on_bandwidth_increase(cfg.reduce_extra_acked_on_bandwidth_increase);
    }

    pub(crate) fn rescale_packet_sized_windows(&mut self, max_datagram_size: ByteCount) {
        let old_max_datagram_size = self.max_datagram_size;
        self.max_datagram_size = max_datagram_size;
        self.initial_congestion_window = scale_byte_window_for_datagram_size(
            self.initial_congestion_window,
            old_max_datagram_size,
            max_datagram_size,
        );
        self.max_congestion_window =
            scale_byte_window_for_datagram_size(self.max_congestion_window, old_max_datagram_size, max_datagram_size);
        self.min_congestion_window = min_congestion_window_for_max_datagram_size(max_datagram_size);
        self.cwnd_to_calculate_min_pacing_rate = scale_byte_window_for_datagram_size(
            self.cwnd_to_calculate_min_pacing_rate,
            old_max_datagram_size,
            max_datagram_size,
        );
        self.max_congestion_window_with_network_parameters_adjusted = scale_byte_window_for_datagram_size(
            self.max_congestion_window_with_network_parameters_adjusted,
            old_max_datagram_size,
            max_datagram_size,
        );
    }

    /// Returns the current estimate of the RTT of the connection.  Outside of
    /// the edge cases, this is minimum RTT.
    pub(crate) fn get_min_rtt(&self) -> Duration {
        if !self.min_rtt.is_zero() {
            return self.min_rtt;
        }
        // min_rtt could be available if the handshake packet gets neutered then
        // gets acknowledged. This could only happen for QUIC crypto where we do not
        // drop keys.
        let Some(rtt_stats) = self.rtt_stats.as_ref() else {
            return Duration::from_millis(100);
        };
        let min_rtt = rtt_stats.min_rtt();
        if min_rtt.is_zero() {
            Duration::from_millis(100)
        } else {
            min_rtt
        }
    }

    /// Computes the target congestion window using the specified gain.
    pub(crate) fn get_target_congestion_window(&self, gain: f64) -> ByteCount {
        let bdp = bdp_from_rtt_and_bandwidth(self.get_min_rtt(), self.bandwidth_estimate());
        let mut congestion_window = scaled_bytes(gain * bytes_to_f64(bdp));

        // BDP estimate will be zero if no bandwidth samples are available yet.
        if congestion_window == 0 {
            congestion_window = scaled_bytes(gain * bytes_to_f64(self.initial_congestion_window));
        }

        max(congestion_window, self.min_congestion_window)
    }

    /// The target congestion window during PROBE_RTT.
    pub(crate) const fn probe_rtt_congestion_window(&self) -> ByteCount {
        self.min_congestion_window
    }

    pub(crate) fn maybe_update_min_rtt(&mut self, now: monotime::Time, sample_min_rtt: Duration) -> bool {
        // Do not expire min_rtt if none was ever available.
        let min_rtt_expired = self.min_rtt != Duration::ZERO
            && self.min_rtt_timestamp.is_some_and(|min_rtt_timestamp| now > min_rtt_timestamp.add(MIN_RTT_EXPIRY));
        if min_rtt_expired || sample_min_rtt < self.min_rtt || self.min_rtt == Duration::ZERO {
            self.min_rtt = sample_min_rtt;
            self.min_rtt_timestamp = Some(now);
        }

        min_rtt_expired
    }

    /// Enters the STARTUP mode.
    pub(crate) const fn enter_startup_mode(&mut self) {
        self.mode = BBR_MODE_STARTUP;
        self.pacing_gain = self.high_gain;
        self.congestion_window_gain = self.high_cwnd_gain;
    }

    /// Enters the PROBE_BW mode.
    pub(crate) fn enter_probe_bandwidth_mode(&mut self, now: monotime::Time) {
        self.mode = BBR_MODE_PROBE_BW;
        self.congestion_window_gain = self.congestion_window_gain_constant;

        // Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
        // excluded because in that case increased gain and decreased gain would not
        // follow each other.
        let packet_numbers = i32::try_from(PACKETS_PER_CONNECTION_ID).unwrap_or(i32::MAX);
        self.cycle_current_offset = rand::rng().random_range(0..packet_numbers) % (gain_cycle_len_i32() - 1);
        if self.cycle_current_offset >= 1 {
            self.cycle_current_offset += 1;
        }

        self.last_cycle_start = Some(now);
        self.pacing_gain = self.current_pacing_gain();
    }

    /// Updates the round-trip counter if a round-trip has passed.  Returns true if
    /// the counter has been advanced.
    pub(crate) const fn update_round_trip_counter(&mut self, last_acked_packet: PacketNumber) -> bool {
        if self.current_round_trip_end == INVALID_PACKET_NUMBER || last_acked_packet > self.current_round_trip_end {
            self.round_trip_count += 1;
            self.current_round_trip_end = self.last_sent_packet;
            return true;
        }
        false
    }

    /// Updates the current gain used in PROBE_BW mode.
    pub(crate) fn update_gain_cycle_phase(
        &mut self,
        now: monotime::Time,
        prior_in_flight: ByteCount,
        has_losses: bool,
    ) {
        // In most cases, the cycle is advanced after an RTT passes.
        //
        // If the pacing gain is above 1.0, the connection is trying to probe the
        // bandwidth by increasing the number of bytes in flight to at least
        // pacing_gain * BDP.  Make sure that it actually reaches the target, as long
        // as there are no losses suggesting that the buffers are not able to hold
        // that much.
        let probes_bandwidth = self.pacing_gain > 1.0
            && !has_losses
            && prior_in_flight < self.get_target_congestion_window(self.pacing_gain);
        let cycle_ready = !probes_bandwidth
            && match self.last_cycle_start {
                Some(last_cycle_start) => now > last_cycle_start.add(self.get_min_rtt()),
                None => true,
            };

        // If pacing gain is below 1.0, the connection is trying to drain the extra
        // queue which could have been incurred by probing prior to it.  If the number
        // of bytes in flight falls down to the estimated BDP value earlier, conclude
        // that the queue has been successfully drained and exit this cycle early.
        let drain_exits_cycle =
            self.pacing_gain < 1.0 && self.bytes_in_flight <= self.get_target_congestion_window(1.0);

        if cycle_ready || drain_exits_cycle {
            self.cycle_current_offset = (self.cycle_current_offset + 1) % gain_cycle_len_i32();
            self.last_cycle_start = Some(now);
            // Stay in low gain mode until the target BDP is hit.
            // Low gain mode will be exited immediately when the target BDP is achieved.
            if self.drain_to_target
                && self.pacing_gain < 1.0
                && self.current_pacing_gain().total_cmp(&1.0).is_eq()
                && self.bytes_in_flight > self.get_target_congestion_window(1.0)
            {
                return;
            }
            self.pacing_gain = self.current_pacing_gain();
        }
    }

    /// Tracks for how many round-trips the bandwidth has not increased
    /// significantly.
    pub(crate) fn check_if_full_bandwidth_reached(&mut self, last_packet_send_state: &SendTimeState) {
        if self.last_sample_is_app_limited {
            return;
        }

        let target = scaled_bandwidth(bandwidth_to_f64(self.bandwidth_at_last_round) * STARTUP_GROWTH_TARGET);
        if self.bandwidth_estimate() >= target {
            self.bandwidth_at_last_round = self.bandwidth_estimate();
            self.rounds_without_bandwidth_gain = 0;
            if self.expire_ack_aggregation_in_startup {
                // Expire old excess delivery measurements now that bandwidth increased.
                let round_trip_count = self.round_trip_count;
                self.sampler.reset_max_ack_height_tracker(0, round_trip_count);
            }
            return;
        }

        self.rounds_without_bandwidth_gain += 1;
        if self.rounds_without_bandwidth_gain >= self.num_startup_rtts
            || self.should_exit_startup_due_to_loss(last_packet_send_state)
        {
            self.is_at_full_bandwidth = true;
        }
    }

    pub(crate) fn maybe_app_limited(&mut self, bytes_in_flight: ByteCount) {
        if bytes_in_flight < self.get_target_congestion_window(1.0) {
            self.sampler.on_app_limited();
        }
    }

    /// Transitions from STARTUP to DRAIN and from DRAIN to PROBE_BW if
    /// appropriate.
    pub(crate) fn maybe_exit_startup_or_drain(&mut self, now: monotime::Time) {
        if self.mode == BBR_MODE_STARTUP && self.is_at_full_bandwidth {
            self.mode = BBR_MODE_DRAIN;
            self.pacing_gain = self.drain_gain;
            self.congestion_window_gain = self.high_cwnd_gain;
        }
        if self.mode == BBR_MODE_DRAIN && self.bytes_in_flight <= self.get_target_congestion_window(1.0) {
            self.enter_probe_bandwidth_mode(now);
        }
    }

    /// Decides whether to enter or exit PROBE_RTT.
    pub(crate) fn maybe_enter_or_exit_probe_rtt(
        &mut self,
        now: monotime::Time,
        is_round_start: bool,
        min_rtt_expired: bool,
    ) {
        if min_rtt_expired && !self.exiting_quiescence && self.mode != BBR_MODE_PROBE_RTT {
            self.mode = BBR_MODE_PROBE_RTT;
            self.pacing_gain = 1.0;
            // Do not decide on the time to exit PROBE_RTT until bytes in flight
            // are at the target small value.
            self.exit_probe_rtt_at = None;
        }

        if self.mode == BBR_MODE_PROBE_RTT {
            self.sampler.on_app_limited();

            match self.exit_probe_rtt_at {
                None => {
                    // If the window has reached the appropriate size, schedule exiting
                    // PROBE_RTT.  The CWND during PROBE_RTT is the minimum congestion window, but
                    // we allow an extra packet since QUIC checks CWND before sending a
                    // packet.
                    if self.bytes_in_flight < self.probe_rtt_congestion_window() + MAX_PACKET_BUFFER_SIZE {
                        self.exit_probe_rtt_at = Some(now.add(PROBE_RTT_TIME));
                        self.probe_rtt_round_passed = false;
                    }
                }
                Some(exit_probe_rtt_at) => {
                    if is_round_start {
                        self.probe_rtt_round_passed = true;
                    }
                    if now >= exit_probe_rtt_at && self.probe_rtt_round_passed {
                        self.min_rtt_timestamp = Some(now);
                        if self.is_at_full_bandwidth {
                            self.enter_probe_bandwidth_mode(now);
                        } else {
                            self.enter_startup_mode();
                        }
                    }
                }
            }
        }

        self.exiting_quiescence = false;
    }

    /// Determines whether BBR needs to enter, exit or advance state of the
    /// recovery.
    pub(crate) const fn update_recovery_state(
        &mut self,
        last_acked_packet: PacketNumber,
        has_losses: bool,
        is_round_start: bool,
    ) {
        // Disable recovery in startup, if loss-based exit is enabled.
        if !self.is_at_full_bandwidth {
            return;
        }

        // Exit recovery when there are no losses for a round.
        if has_losses {
            self.end_recovery_at = self.last_sent_packet;
        }

        if self.recovery_state == BBR_RECOVERY_STATE_NOT_IN_RECOVERY {
            if has_losses {
                self.recovery_state = BBR_RECOVERY_STATE_CONSERVATION;
                // This will cause the |recovery_window_| to be set to the correct
                // value in CalculateRecoveryWindow().
                self.recovery_window = 0;
                // Since the conservation phase is meant to be lasting for a whole
                // round, extend the current round as if it were started right now.
                self.current_round_trip_end = self.last_sent_packet;
            }
            return;
        }
        if self.recovery_state == BBR_RECOVERY_STATE_CONSERVATION && is_round_start {
            self.recovery_state = BBR_RECOVERY_STATE_GROWTH;
        }
        // the switch falls through from CONSERVATION into the GROWTH case.
        if self.recovery_state == BBR_RECOVERY_STATE_GROWTH {
            // Exit recovery if appropriate.
            if !has_losses && last_acked_packet > self.end_recovery_at {
                self.recovery_state = BBR_RECOVERY_STATE_NOT_IN_RECOVERY;
            }
        }
    }

    /// Determines the appropriate pacing rate for the connection.
    pub(crate) fn calculate_pacing_rate(&mut self, bytes_lost: ByteCount) {
        if self.bandwidth_estimate() == 0 {
            return;
        }

        let target_rate = scaled_bandwidth(self.pacing_gain * bandwidth_to_f64(self.bandwidth_estimate()));
        if self.is_at_full_bandwidth {
            self.pacing_rate = target_rate;
            return;
        }

        let Some(rtt_stats) = self.rtt_stats.as_ref() else {
            // Without RTT statistics there is nothing to pace against; the pacer keeps its rate.
            return;
        };
        // Pace at the rate of initial_window / RTT as soon as RTT measurements are
        // available.
        if self.pacing_rate == 0 && !rtt_stats.min_rtt().is_zero() {
            self.pacing_rate = bandwidth_from_delta(self.initial_congestion_window, rtt_stats.min_rtt());
            return;
        }

        if self.detect_overshooting {
            self.bytes_lost_while_detecting_overshooting += bytes_lost;
            // Check for overshooting with network parameters adjusted when pacing rate
            // > target_rate and loss has been detected.
            if self.pacing_rate > target_rate
                && self.bytes_lost_while_detecting_overshooting > 0
                && (self.has_no_app_limited_sample
                    || self.bytes_lost_while_detecting_overshooting
                        * ByteCount::from(self.bytes_lost_multiplier_while_detecting_overshooting)
                        > self.initial_congestion_window)
            {
                // We are fairly sure overshoot happens if 1) there is at least one
                // non app-limited bw sample or 2) half of IW gets lost. Slow pacing
                // rate.
                self.pacing_rate =
                    max(target_rate, bandwidth_from_delta(self.cwnd_to_calculate_min_pacing_rate, rtt_stats.min_rtt()));
                self.bytes_lost_while_detecting_overshooting = 0;
                self.detect_overshooting = false;
            }
        }

        // Do not decrease the pacing rate during startup.
        self.pacing_rate = max(self.pacing_rate, target_rate);
    }

    /// Determines the appropriate congestion window for the connection.
    pub(crate) fn calculate_congestion_window(&mut self, bytes_acked: ByteCount, excess_acked: ByteCount) {
        if self.mode == BBR_MODE_PROBE_RTT {
            return;
        }

        let mut target_window = self.get_target_congestion_window(self.congestion_window_gain);
        if self.is_at_full_bandwidth {
            // Add the max recently measured ack aggregation to CWND.
            target_window += self.sampler.max_ack_height();
        } else if self.enable_ack_aggregation_during_startup {
            // Add the most recent excess acked.  Because CWND never decreases in
            // STARTUP, this will automatically create a very localized max filter.
            target_window += excess_acked;
        }

        // Instead of immediately setting the target CWND as the new one, BBR grows
        // the CWND towards |target_window| by only increasing it |bytes_acked| at a
        // time.
        if self.is_at_full_bandwidth {
            self.congestion_window = min(target_window, self.congestion_window + bytes_acked);
        } else if self.congestion_window < target_window
            || self.sampler.total_bytes_acked() < self.initial_congestion_window
        {
            // If the connection is not yet out of startup phase, do not decrease the
            // window.
            self.congestion_window += bytes_acked;
        }

        // Enforce the limits on the congestion window.
        self.congestion_window = max(self.congestion_window, self.min_congestion_window);
        self.congestion_window = min(self.congestion_window, self.max_congestion_window);
    }

    /// Determines the appropriate window that constrains the in-flight during recovery.
    pub(crate) fn calculate_recovery_window(&mut self, bytes_acked: ByteCount, bytes_lost: ByteCount) {
        if self.recovery_state == BBR_RECOVERY_STATE_NOT_IN_RECOVERY {
            return;
        }

        // Set up the initial recovery window.
        if self.recovery_window == 0 {
            self.recovery_window = self.bytes_in_flight + bytes_acked;
            self.recovery_window = max(self.min_congestion_window, self.recovery_window);
            return;
        }

        // Remove losses from the recovery window, while accounting for a potential
        // integer underflow.
        if self.recovery_window >= bytes_lost {
            self.recovery_window -= bytes_lost;
        } else {
            self.recovery_window = self.max_datagram_size;
        }

        // In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
        // release additional |bytes_acked| to achieve a slow-start-like behavior.
        if self.recovery_state == BBR_RECOVERY_STATE_GROWTH {
            self.recovery_window += bytes_acked;
        }

        // Always allow sending at least |bytes_acked| in response.
        self.recovery_window = max(self.recovery_window, self.bytes_in_flight + bytes_acked);
        self.recovery_window = max(self.min_congestion_window, self.recovery_window);
    }

    /// Return whether we should exit STARTUP due to excessive loss.
    pub(crate) fn should_exit_startup_due_to_loss(&self, last_packet_send_state: &SendTimeState) -> bool {
        if self.num_loss_events_in_round < DEFAULT_STARTUP_FULL_LOSS_COUNT || !last_packet_send_state.is_valid {
            return false;
        }

        let inflight_at_send = last_packet_send_state.bytes_in_flight;

        if inflight_at_send > 0 && self.bytes_lost_in_round > 0 {
            if self.bytes_lost_in_round
                > scaled_bytes(bytes_to_f64(inflight_at_send) * QUIC_BBR2_DEFAULT_LOSS_THRESHOLD)
            {
                return true;
            }
            return false;
        }
        false
    }

    /// The pacing gain at the current position in the gain cycle, or the neutral gain if the
    /// offset ever leaves the cycle.
    fn current_pacing_gain(&self) -> f64 {
        usize::try_from(self.cycle_current_offset)
            .ok()
            .and_then(|offset| PACING_GAIN.get(offset).copied())
            .unwrap_or(1.0)
    }

    /// Get the current bandwidth estimate. Note that Bandwidth is in bits per second.
    pub(crate) fn bandwidth_estimate(&self) -> Bandwidth {
        self.max_bandwidth.get_best()
    }

    #[must_use]
    pub fn pacing_rate(&self) -> Bandwidth {
        if self.pacing_rate == 0 {
            let bdp = bandwidth_from_delta(self.initial_congestion_window, self.get_min_rtt());
            return scaled_bandwidth(self.high_gain * bandwidth_to_f64(bdp));
        }

        self.pacing_rate
    }

    pub(crate) fn bandwidth_for_pacer(&self) -> ByteCount {
        let bps = scaled_bytes(bandwidth_to_f64(self.pacing_rate()) / bandwidth_to_f64(BYTES_PER_SECOND));
        if bps < MIN_BPS {
            // We need to make sure that the bandwidth value for pacer is never zero,
            // otherwise it will go into an edge case where the pacing-budget check is false
            // but the send time is in the past, causing the send loop to get stuck.
            return MIN_BPS;
        }
        bps
    }
}

impl CongestionControl for BbrSender {
    fn set_rtt_stats_provider(&mut self, rtt_stats: Arc<dyn RttStatsProvider>) {
        self.rtt_stats = Some(rtt_stats);
    }

    /// Part of the `CongestionControl` surface.
    fn time_until_send(&self, _bytes_in_flight: ByteCount) -> monotime::Time {
        let get_bandwidth = self.bandwidth_for_pacer();
        self.pacer.time_until_send(get_bandwidth)
    }

    /// Part of the `CongestionControl` surface.
    fn has_pacing_budget(&self, now: monotime::Time) -> bool {
        let get_bandwidth = self.bandwidth_for_pacer();
        self.pacer.budget(now, get_bandwidth) >= self.max_datagram_size
    }

    /// Part of the `CongestionControl` surface.
    fn on_packet_sent(
        &mut self,
        sent_time: monotime::Time,
        bytes_in_flight: ByteCount,
        packet_number: PacketNumber,
        bytes: ByteCount,
        is_retransmittable: bool,
    ) {
        let get_bandwidth = self.bandwidth_for_pacer();
        self.pacer.sent_packet(sent_time, bytes, get_bandwidth);

        self.last_sent_packet = packet_number;
        self.bytes_in_flight = bytes_in_flight;

        if bytes_in_flight == 0 {
            self.exiting_quiescence = true;
        }

        self.sampler.on_packet_sent(sent_time, packet_number, bytes, bytes_in_flight, is_retransmittable);
    }

    /// Part of the `CongestionControl` surface.
    fn can_send(&self, bytes_in_flight: ByteCount) -> bool {
        bytes_in_flight < self.get_congestion_window()
    }

    /// Part of the `CongestionControl` surface.
    fn maybe_exit_slow_start(&mut self) {
        // Do nothing
    }

    /// Part of the `CongestionControl` surface.
    fn on_packet_acked(
        &mut self,
        _number: PacketNumber,
        _acked_bytes: ByteCount,
        _prior_in_flight: ByteCount,
        _event_time: monotime::Time,
    ) {
        // Do nothing.
    }

    /// Part of the `CongestionControl` surface.
    fn on_congestion_event(&mut self, _number: PacketNumber, _lost_bytes: ByteCount, _prior_in_flight: ByteCount) {
        // Do nothing.
    }

    /// Part of the `CongestionControl` surface.
    fn on_retransmission_timeout(&mut self, _packets_retransmitted: bool) {
        // Do nothing.
    }

    /// Part of the `CongestionControl` surface.
    fn set_max_datagram_size(&mut self, s: ByteCount) {
        assert!(
            s >= self.max_datagram_size,
            "congestion BUG: decreased max datagram size from {} to {}",
            self.max_datagram_size,
            s
        );
        let old_min_congestion_window = self.min_congestion_window;
        let old_initial_congestion_window = self.initial_congestion_window;
        self.rescale_packet_sized_windows(s);
        if self.congestion_window == old_min_congestion_window {
            self.congestion_window = self.min_congestion_window;
        } else if self.congestion_window == old_initial_congestion_window {
            self.congestion_window = self.initial_congestion_window;
        } else {
            self.congestion_window =
                min(self.max_congestion_window, max(self.congestion_window, self.min_congestion_window));
        }
        self.recovery_window = min(self.max_congestion_window, max(self.recovery_window, self.min_congestion_window));
        self.pacer.set_max_datagram_size(s);
    }

    /// Part of the `CongestionControl` surface.
    fn in_slow_start(&self) -> bool {
        self.mode == BBR_MODE_STARTUP
    }

    /// Part of the `CongestionControl` surface.
    fn in_recovery(&self) -> bool {
        self.recovery_state != BBR_RECOVERY_STATE_NOT_IN_RECOVERY
    }

    /// Part of the `CongestionControl` surface.
    fn get_congestion_window(&self) -> ByteCount {
        if self.mode == BBR_MODE_PROBE_RTT {
            return self.probe_rtt_congestion_window();
        }

        if self.in_recovery() {
            return min(self.congestion_window, self.recovery_window);
        }

        self.congestion_window
    }
}

impl CongestionControlEx for BbrSender {
    fn on_congestion_event_ex(
        &mut self,
        prior_in_flight: ByteCount,
        event_time: monotime::Time,
        acked_packets: &[AckedPacketInfo],
        lost_packets: &[LostPacketInfo],
    ) {
        let total_bytes_acked_before = self.sampler.total_bytes_acked();
        let total_bytes_lost_before = self.sampler.total_bytes_lost();

        let mut is_round_start = false;
        let mut min_rtt_expired = false;

        self.maybe_app_limited(prior_in_flight);

        // Update bytesInFlight
        self.bytes_in_flight = prior_in_flight;
        for p in acked_packets {
            self.bytes_in_flight -= p.bytes_acked;
        }
        for p in lost_packets {
            self.bytes_in_flight -= p.bytes_lost;
        }

        if let Some(last_acked) = acked_packets.last() {
            let last_acked_packet = last_acked.packet_number;
            is_round_start = self.update_round_trip_counter(last_acked_packet);
            self.update_recovery_state(last_acked_packet, !lost_packets.is_empty(), is_round_start);
        }

        let best_bandwidth = self.max_bandwidth.get_best();
        let sample: CongestionEventSample = self.sampler.on_congestion_event(
            event_time,
            acked_packets,
            lost_packets,
            best_bandwidth,
            INF_BANDWIDTH,
            self.round_trip_count,
        );
        if sample.last_packet_send_state.is_valid {
            self.last_sample_is_app_limited = sample.last_packet_send_state.is_app_limited;
            self.has_no_app_limited_sample = self.has_no_app_limited_sample || !self.last_sample_is_app_limited;
        }
        // Avoid updating |max_bandwidth_| if a) this is a loss-only event, or b) all
        // packets in |acked_packets| did not generate valid samples. (e.g. ack of
        // ack-only packets). In both cases, sampler_.total_bytes_acked() will not
        // change.
        if total_bytes_acked_before != self.sampler.total_bytes_acked()
            && (!sample.sample_is_app_limited || sample.sample_max_bandwidth > self.max_bandwidth.get_best())
        {
            self.max_bandwidth.update(sample.sample_max_bandwidth, self.round_trip_count);
        }

        if sample.sample_rtt != INF_RTT {
            min_rtt_expired = self.maybe_update_min_rtt(event_time, sample.sample_rtt);
        }
        let bytes_lost = self.sampler.total_bytes_lost() - total_bytes_lost_before;

        let excess_acked = sample.extra_acked;
        // The send state of the largest packet in acked_packets, unless it is
        // empty. If acked_packets is empty, it's the send state of the largest
        // packet in lost_packets.
        let last_packet_send_state = sample.last_packet_send_state;

        if !lost_packets.is_empty() {
            self.num_loss_events_in_round += 1;
            self.bytes_lost_in_round += bytes_lost;
        }

        // Handle logic specific to PROBE_BW mode.
        if self.mode == BBR_MODE_PROBE_BW {
            self.update_gain_cycle_phase(event_time, prior_in_flight, !lost_packets.is_empty());
        }

        // Handle logic specific to STARTUP and DRAIN modes.
        if is_round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bandwidth_reached(&last_packet_send_state);
        }

        self.maybe_exit_startup_or_drain(event_time);

        // Handle logic specific to PROBE_RTT.
        self.maybe_enter_or_exit_probe_rtt(event_time, is_round_start, min_rtt_expired);

        // Calculate number of packets acked and lost.
        let bytes_acked = self.sampler.total_bytes_acked() - total_bytes_acked_before;

        // After the model is updated, recalculate the pacing rate and congestion
        // window.
        self.calculate_pacing_rate(bytes_lost);
        self.calculate_congestion_window(bytes_acked, excess_acked);
        self.calculate_recovery_window(bytes_acked, bytes_lost);

        // Cleanup internal state.
        // This is where we clean up obsolete (acked or lost) packets from the bandwidth sampler.
        // The "least unacked" should actually be FirstOutstanding, but since we are not passing
        // that through the congestion-event hook, we will only do an estimate using acked/lost packets
        // for now. Because of fast retransmission, they should differ by no more than 2 packets.
        // (this is controlled by the packet threshold in the sent-packet handler)
        let least_unacked = if let Some(last_acked) = acked_packets.last() {
            last_acked.packet_number - 2
        } else if let Some(last_lost) = lost_packets.last() {
            last_lost.packet_number + 1
        } else {
            INVALID_PACKET_NUMBER
        };
        self.sampler.remove_obsolete_packets(least_unacked);

        if is_round_start {
            self.num_loss_events_in_round = 0;
            self.bytes_lost_in_round = 0;
        }
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts are bounded, well inside the exactly representable f64 range"
)]
fn bytes_to_f64(bytes: ByteCount) -> f64 {
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
fn scaled_bytes(value: f64) -> ByteCount {
    value as ByteCount
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the gained rate is bounded by max_congestion_window, so the truncation is bounded"
)]
#[expect(clippy::cast_sign_loss, reason = "the gained rate is non-negative by construction")]
fn scaled_bandwidth(value: f64) -> Bandwidth {
    value as Bandwidth
}

/// The gain cycle length as the `i32` the offset arithmetic uses.
fn gain_cycle_len_i32() -> i32 {
    i32::try_from(GAIN_CYCLE_LENGTH).unwrap_or(i32::MAX)
}

pub(crate) const fn min_congestion_window_for_max_datagram_size(max_datagram_size: ByteCount) -> ByteCount {
    MIN_CONGESTION_WINDOW_PACKETS * max_datagram_size
}

pub(crate) const fn scale_byte_window_for_datagram_size(
    window: ByteCount,
    old_max_datagram_size: ByteCount,
    new_max_datagram_size: ByteCount,
) -> ByteCount {
    if old_max_datagram_size == new_max_datagram_size {
        return window;
    }
    let scaled = window.cast_unsigned() * new_max_datagram_size.cast_unsigned() / old_max_datagram_size.cast_unsigned();
    scaled.cast_signed()
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "a nanosecond count since process start and one second both fit in i64"
)]
pub(crate) const fn bdp_from_rtt_and_bandwidth(rtt: Duration, bandwidth: Bandwidth) -> ByteCount {
    (rtt.as_nanos() as ByteCount).wrapping_mul(bandwidth.cast_signed())
        / BYTES_PER_SECOND.cast_signed()
        / (Duration::from_secs(1).as_nanos() as ByteCount)
}

/// The initial packet size of a QUIC connection, the only part of the connection API this
/// module reads; the connection mirror implements it.
pub trait InitialPacketSizeProvider {
    fn initial_packet_size(&self) -> ByteCount;
}

pub fn get_initial_packet_size<C: InitialPacketSizeProvider + ?Sized>(quic_conn: &C) -> ByteCount {
    quic_conn.initial_packet_size()
}

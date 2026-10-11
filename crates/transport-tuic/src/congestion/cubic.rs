//!
//! This cubic implementation is based on the one found in Chromiums's QUIC
//! implementation, in the files `net/quic/congestion_control/cubic.{hh,cc`}.

use std::time::Duration;

use murmur_common::time::{duration_to_nanos, MICROSECOND};
use murmur_quic::{congestion, monotime};

use super::bbr_sender::INITIAL_PACKET_SIZE;
use super::minmax::min;

// Constants based on TCP defaults. The following constants are in 2^10 fractions of a second
// instead of ms to allow a 10 shift right to divide.

// 1024*1024^3 (first 1024 is from 0.100^3)
// where 0.100 is 100 ms which is the scaling round trip time.
const CUBE_SCALE: i64 = 40;
const CUBE_CONGESTION_WINDOW_SCALE: i64 = 410;
const CUBE_FACTOR: congestion::ByteCount = (1i64 << CUBE_SCALE) / CUBE_CONGESTION_WINDOW_SCALE / MAX_DATAGRAM_SIZE;
const MAX_DATAGRAM_SIZE: congestion::ByteCount = INITIAL_PACKET_SIZE;

const DEFAULT_NUM_CONNECTIONS: usize = 1;

/// Default Cubic backoff factor
const BETA: f32 = 0.7;

/// Additional backoff factor when loss occurs in the concave part of the Cubic
/// curve. This additional backoff factor is expected to give up bandwidth to
/// new concurrent flows and speed up convergence.
const BETA_LAST_MAX: f32 = 0.85;

/// Cubic implements the cubic algorithm from TCP
#[derive(Debug)]
pub struct Cubic {
    /// Number of connections to simulate.
    num_connections: usize,

    /// Time when this cycle started, after last loss event.
    epoch: monotime::Time,

    /// Max congestion window used just before last loss event.
    /// Note: to improve fairness to other streams an additional back off is
    /// applied to this value if the new value is below our latest value.
    last_max_congestion_window: congestion::ByteCount,

    /// Number of acked bytes since the cycle started (epoch).
    acked_bytes_count: congestion::ByteCount,

    /// TCP Reno equivalent congestion window in packets.
    estimated_tcp_congestion_window: congestion::ByteCount,

    /// Origin point of cubic function.
    origin_point_congestion_window: congestion::ByteCount,

    /// Time to origin point of cubic function in 2^10 fractions of a second.
    time_to_origin_point: u32,

    /// Last congestion window in packets computed by cubic function.
    last_target_congestion_window: congestion::ByteCount,
}

/// Creates a new Cubic instance.
#[must_use]
pub fn new_cubic() -> Cubic {
    let mut c = Cubic {
        num_connections: DEFAULT_NUM_CONNECTIONS,
        epoch: monotime::Time::default(),
        last_max_congestion_window: 0,
        acked_bytes_count: 0,
        estimated_tcp_congestion_window: 0,
        origin_point_congestion_window: 0,
        time_to_origin_point: 0,
        last_target_congestion_window: 0,
    };
    c.reset();
    c
}

impl Cubic {
    /// Reset is called after a timeout to reset the cubic state
    pub fn reset(&mut self) {
        self.epoch = monotime::Time::default();
        self.last_max_congestion_window = 0;
        self.acked_bytes_count = 0;
        self.estimated_tcp_congestion_window = 0;
        self.origin_point_congestion_window = 0;
        self.time_to_origin_point = 0;
        self.last_target_congestion_window = 0;
    }

    #[expect(clippy::cast_precision_loss, reason = "num_connections is a small count that is exact in f32")]
    fn alpha(&self) -> f32 {
        // TCPFriendly alpha is described in Section 3.3 of the CUBIC paper. Note that
        // beta here is a cwnd multiplier, and is equal to 1-beta from the paper.
        let b = self.beta();
        3.0 * self.num_connections as f32 * self.num_connections as f32 * (1.0 - b) / (1.0 + b)
    }

    #[expect(clippy::cast_precision_loss, reason = "num_connections is a small count that is exact in f32")]
    fn beta(&self) -> f32 {
        // kNConnectionBeta is the backoff factor after loss for our N-connection
        // emulation, which emulates the effective backoff of an ensemble of N
        // TCP-Reno connections on a single loss event.
        (self.num_connections as f32 - 1.0 + BETA) / self.num_connections as f32
    }

    #[expect(clippy::cast_precision_loss, reason = "num_connections is a small count that is exact in f32")]
    fn beta_last_max(&self) -> f32 {
        // betaLastMax is the additional backoff factor after loss for our
        // N-connection emulation, which emulates the additional backoff of
        // an ensemble of N TCP-Reno connections on a single loss event.
        (self.num_connections as f32 - 1.0 + BETA_LAST_MAX) / self.num_connections as f32
    }

    /// Called on ack arrival when the sender is unable to use
    /// the available congestion window. Resets Cubic state during quiescence.
    pub fn on_application_limited(&mut self) {
        // When sender is not using the available congestion window, the window does
        // not grow. But to be RTT-independent, Cubic assumes that the sender has been
        // using the entire window during the time since the beginning of the current
        // "epoch" (the end of the last loss recovery period), so application-limited
        // periods break that assumption and reset the epoch.
        self.epoch = monotime::Time::default();
    }

    /// Computes a new congestion window to use after
    /// a loss event. Returns the new congestion window in packets. The new
    /// congestion window is a multiplicative decrease of our current window.
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        reason = "the cubic math scales the window in f32 and truncates toward zero"
    )]
    pub fn congestion_window_after_packet_loss(
        &mut self,
        current_congestion_window: congestion::ByteCount,
    ) -> congestion::ByteCount {
        if current_congestion_window.wrapping_add(MAX_DATAGRAM_SIZE) < self.last_max_congestion_window {
            // We never reached the old max, so assume we are competing with another
            // flow. Use our extra back off factor to allow the other flow to go up.
            self.last_max_congestion_window =
                (self.beta_last_max() * current_congestion_window as f32) as congestion::ByteCount;
        } else {
            self.last_max_congestion_window = current_congestion_window;
        }
        self.epoch = monotime::Time::default(); // Reset time.
        (current_congestion_window as f32 * self.beta()) as congestion::ByteCount
    }

    /// Computes a new congestion window to use after a received ACK.
    /// Returns the new congestion window in packets. The new congestion window
    /// follows a cubic function that depends on the time passed since last
    /// packet loss.
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the cubic math uses f32/f64 here and truncates toward zero"
    )]
    pub fn congestion_window_after_ack(
        &mut self,
        acked_bytes: congestion::ByteCount,
        current_congestion_window: congestion::ByteCount,
        delay_min: Duration,
        event_time: monotime::Time,
    ) -> congestion::ByteCount {
        self.acked_bytes_count = self.acked_bytes_count.wrapping_add(acked_bytes);

        if self.epoch.is_zero() {
            // First ACK after a loss event.
            self.epoch = event_time; // Start of epoch.
            self.acked_bytes_count = acked_bytes; // Reset count.
                                                  // Reset estimated_tcp_congestion_window_ to be in sync with cubic.
            self.estimated_tcp_congestion_window = current_congestion_window;
            if self.last_max_congestion_window <= current_congestion_window {
                self.time_to_origin_point = 0;
                self.origin_point_congestion_window = current_congestion_window;
            } else {
                self.time_to_origin_point =
                    (CUBE_FACTOR.wrapping_mul(self.last_max_congestion_window - current_congestion_window) as f64)
                        .cbrt() as u32;
                self.origin_point_congestion_window = self.last_max_congestion_window;
            }
        }

        // Change the time unit from microseconds to 2^10 fractions per second. Take
        // the round trip time in account. This is done to allow us to use shift as a
        // divide operator.
        let elapsed_time =
            ((duration_to_nanos(event_time.add(delay_min).sub(&self.epoch)) / MICROSECOND) << 10) / (1000 * 1000);

        // Right-shifts of negative, signed numbers have implementation-dependent
        // behavior, so force the offset to be positive, as is done in the kernel.
        let mut offset = i64::from(self.time_to_origin_point) - elapsed_time;
        if offset < 0 {
            offset = -offset;
        }

        let delta_congestion_window =
            (CUBE_CONGESTION_WINDOW_SCALE.wrapping_mul(offset).wrapping_mul(offset).wrapping_mul(offset))
                .wrapping_mul(MAX_DATAGRAM_SIZE)
                >> CUBE_SCALE;
        let mut target_congestion_window = if elapsed_time > i64::from(self.time_to_origin_point) {
            self.origin_point_congestion_window.wrapping_add(delta_congestion_window)
        } else {
            self.origin_point_congestion_window.wrapping_sub(delta_congestion_window)
        };
        // Limit the CWND increase to half the acked bytes.
        target_congestion_window =
            min(target_congestion_window, current_congestion_window.wrapping_add(self.acked_bytes_count / 2));

        // Increase the window by approximately Alpha * 1 MSS of bytes every
        // time we ack an estimated tcp window of bytes.  For small
        // congestion windows (less than 25), the formula below will
        // increase slightly slower than linearly per estimated tcp window
        // of bytes.
        self.estimated_tcp_congestion_window = self.estimated_tcp_congestion_window.wrapping_add(
            (self.acked_bytes_count as f32 * self.alpha() * MAX_DATAGRAM_SIZE as f32
                / self.estimated_tcp_congestion_window as f32) as congestion::ByteCount,
        );
        self.acked_bytes_count = 0;

        // We have a new cubic congestion window.
        self.last_target_congestion_window = target_congestion_window;

        // Compute target congestion_window based on cubic target and estimated TCP
        // congestion_window, use highest (fastest).
        if target_congestion_window < self.estimated_tcp_congestion_window {
            target_congestion_window = self.estimated_tcp_congestion_window;
        }
        target_congestion_window
    }

    /// Sets the number of emulated connections.
    pub const fn set_num_connections(&mut self, n: usize) {
        self.num_connections = n;
    }
}

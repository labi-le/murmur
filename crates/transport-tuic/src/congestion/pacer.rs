use std::time::Duration;

use murmur_common::time::{duration_from_nanos, duration_to_nanos};
use murmur_quic::{congestion, monotime};

use super::bandwidth::{Bandwidth, BYTES_PER_SECOND};
use super::minmax::{max, min};

pub(crate) const INITIAL_MAX_DATAGRAM_SIZE: congestion::ByteCount = 1252;
pub const MIN_PACING_DELAY: Duration = Duration::from_millis(1);
pub const TIMER_GRANULARITY: Duration = Duration::from_millis(1);
pub(crate) const MAX_BURST_SIZE_PACKETS: congestion::ByteCount = 10;

/// The pacer implements a token bucket pacing algorithm.
///
/// The pacer holds an adjusted-bandwidth closure over the sender that owns it, so the
/// port passes the sender's current estimate to every call instead.
pub(crate) struct Pacer {
    budget_at_last_sent: congestion::ByteCount,
    max_datagram_size: congestion::ByteCount,
    last_sent_time: monotime::Time,
}

pub(crate) fn new_pacer(initial_bandwidth: Bandwidth) -> Pacer {
    let mut p = Pacer {
        budget_at_last_sent: 0,
        max_datagram_size: INITIAL_MAX_DATAGRAM_SIZE,
        last_sent_time: monotime::Time::default(),
    };
    p.budget_at_last_sent = p.max_burst_size(initial_bandwidth);
    p
}

impl Pacer {
    pub(crate) fn sent_packet(&mut self, send_time: monotime::Time, size: congestion::ByteCount, bandwidth: Bandwidth) {
        let budget = self.budget(send_time, bandwidth);
        if size > budget {
            self.budget_at_last_sent = 0;
        } else {
            self.budget_at_last_sent = budget - size;
        }
        self.last_sent_time = send_time;
    }

    pub(crate) fn budget(&self, now: monotime::Time, bandwidth: Bandwidth) -> congestion::ByteCount {
        if self.last_sent_time.is_zero() {
            return self.max_burst_size(bandwidth);
        }
        let budget = self.budget_at_last_sent.wrapping_add(
            adjusted_bandwidth(bandwidth).cast_signed().wrapping_mul(duration_to_nanos(now.sub(&self.last_sent_time)))
                / 1_000_000_000,
        );
        min(self.max_burst_size(bandwidth), budget)
    }

    fn max_burst_size(&self, bandwidth: Bandwidth) -> congestion::ByteCount {
        max(
            duration_to_nanos(MIN_PACING_DELAY + TIMER_GRANULARITY)
                .cast_unsigned()
                .wrapping_mul(adjusted_bandwidth(bandwidth))
                .cast_signed()
                / 1_000_000_000,
            MAX_BURST_SIZE_PACKETS * self.max_datagram_size,
        )
    }

    /// When the next packet should be sent.
    /// It returns the zero value of monotime.Time if a packet can be sent immediately.
    #[expect(
        clippy::cast_precision_loss,
        reason = "the pacing delay is derived in f64; only the rounded-up nanosecond quotient is used"
    )]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the quotient was rounded up to an integer above, so this cast truncates nothing"
    )]
    pub(crate) fn time_until_send(&self, bandwidth: Bandwidth) -> monotime::Time {
        if self.budget_at_last_sent >= self.max_datagram_size {
            return monotime::Time::default();
        }
        let delay = duration_from_nanos(
            (((self.max_datagram_size - self.budget_at_last_sent) as f64) * 1e9 / adjusted_bandwidth(bandwidth) as f64)
                .ceil() as i64,
        );
        self.last_sent_time.add(max(MIN_PACING_DELAY, delay))
    }

    pub(crate) const fn set_max_datagram_size(&mut self, s: congestion::ByteCount) {
        self.max_datagram_size = s;
    }
}

/// The adjusted-bandwidth closure of the pacer: bandwidth is in bits/s, the token
/// bucket works in bytes/s, slightly above the measured value.
const fn adjusted_bandwidth(bandwidth: Bandwidth) -> u64 {
    let bw = bandwidth / BYTES_PER_SECOND;
    bw.wrapping_mul(5) / 4
}

use std::time::Duration;

use murmur_quic::congestion::{ByteCount, INITIAL_PACKET_SIZE, MIN_PACING_DELAY};
use murmur_quic::monotime;

use super::minmax::{max, min};

const MAX_BURST_PACKETS: ByteCount = 10;
const MAX_BURST_PACING_DELAY_MULTIPLIER: u32 = 4;

/// Pacer implements a token bucket pacing algorithm.
///
/// A callback that
/// borrows the sender owning its pacer can't be stored, so every method reading the
/// bandwidth takes it as an argument instead.
#[derive(Debug)]
pub struct Pacer {
    budget_at_last_sent: ByteCount,
    max_datagram_size: ByteCount,
    last_sent_time: Option<monotime::Time>,
}

impl Pacer {
    #[must_use]
    pub const fn new_pacer() -> Self {
        Self {
            budget_at_last_sent: MAX_BURST_PACKETS * INITIAL_PACKET_SIZE,
            max_datagram_size: INITIAL_PACKET_SIZE,
            last_sent_time: None,
        }
    }

    pub fn sent_packet(&mut self, send_time: monotime::Time, size: ByteCount, get_bandwidth: ByteCount) {
        let budget = self.budget(send_time, get_bandwidth);
        if size > budget {
            self.budget_at_last_sent = 0;
        } else {
            self.budget_at_last_sent = budget - size;
        }
        self.last_sent_time = Some(send_time);
    }

    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the elapsed monotonic time is a nanosecond count well inside the byte-budget's range"
    )]
    pub fn budget(&self, now: monotime::Time, get_bandwidth: ByteCount) -> ByteCount {
        let Some(last_sent_time) = self.last_sent_time else {
            return self.max_burst_size(get_bandwidth);
        };
        let elapsed = now.sub(&last_sent_time).as_nanos() as ByteCount;
        // the signed arithmetic wraps around, and the overflow guard below
        // relies on that.
        let mut budget = self.budget_at_last_sent.wrapping_add(get_bandwidth.wrapping_mul(elapsed) / 1_000_000_000);
        if budget < 0 {
            // protect against overflows
            budget = (1 << 62) - 1;
        }
        min(self.max_burst_size(get_bandwidth), budget)
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the constant pacing delay in nanoseconds is far below the byte count's range"
    )]
    pub(crate) fn max_burst_size(&self, get_bandwidth: ByteCount) -> ByteCount {
        let pacing_delay = MIN_PACING_DELAY * MAX_BURST_PACING_DELAY_MULTIPLIER;
        max(
            (pacing_delay.as_nanos() as ByteCount) * get_bandwidth / 1_000_000_000,
            MAX_BURST_PACKETS * self.max_datagram_size,
        )
    }

    /// When the next packet should be sent.
    /// It returns the zero value if a packet can be sent immediately.
    #[must_use]
    pub fn time_until_send(&self, get_bandwidth: ByteCount) -> monotime::Time {
        if self.budget_at_last_sent >= self.max_datagram_size {
            // the zero time is in the past, which callers read as "send now".
            return monotime::now();
        }
        let diff = 1_000_000_000u64 * (self.max_datagram_size - self.budget_at_last_sent).cast_unsigned();
        let bw = get_bandwidth.cast_unsigned();
        // We might need to round up this value.
        // Otherwise, we might have a budget (slightly) smaller than the datagram size when the timer expires.
        let mut d = diff / bw;
        // this is effectively a ceiling, but using only integer math
        if !diff.is_multiple_of(bw) {
            d += 1;
        }
        let Some(last_sent_time) = self.last_sent_time else {
            return monotime::now();
        };
        last_sent_time.add(max(MIN_PACING_DELAY, Duration::from_nanos(d)))
    }

    pub const fn set_max_datagram_size(&mut self, s: ByteCount) {
        self.max_datagram_size = s;
    }
}

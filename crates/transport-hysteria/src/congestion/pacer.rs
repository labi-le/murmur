use std::fmt;
use std::time::Duration;

use murmur_quic::congestion::ByteCount;
use murmur_quic::monotime;

use super::brutal::{max_duration, INIT_MAX_DATAGRAM_SIZE};

const MAX_BURST_PACKETS: ByteCount = 10;
const MIN_PACING_DELAY: Duration = Duration::from_millis(1);

/// The pacer implements a token bucket pacing algorithm.
pub(crate) struct Pacer {
    budget_at_last_sent: ByteCount,
    max_datagram_size: ByteCount,
    /// A zero monotonic instant marks "nothing sent yet"; this clock cannot build a zero instant,
    /// so the unsent state is carried as `None`.
    last_sent_time: Option<monotime::Time>,
    get_bandwidth: Box<dyn Fn() -> ByteCount + Send + Sync>, // in bytes/s
}

pub(crate) fn new_pacer(get_bandwidth: Box<dyn Fn() -> ByteCount + Send + Sync>) -> Pacer {
    Pacer {
        budget_at_last_sent: MAX_BURST_PACKETS * INIT_MAX_DATAGRAM_SIZE,
        max_datagram_size: INIT_MAX_DATAGRAM_SIZE,
        last_sent_time: None,
        get_bandwidth,
    }
}

impl fmt::Debug for Pacer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pacer")
            .field("budget_at_last_sent", &self.budget_at_last_sent)
            .field("max_datagram_size", &self.max_datagram_size)
            .field("last_sent_time", &self.last_sent_time)
            .finish_non_exhaustive()
    }
}

impl Pacer {
    pub(crate) fn sent_packet(&mut self, send_time: monotime::Time, size: ByteCount) {
        let budget = self.budget(send_time);
        if size > budget {
            self.budget_at_last_sent = 0;
        } else {
            self.budget_at_last_sent = budget - size;
        }
        self.last_sent_time = Some(send_time);
    }

    pub(crate) fn budget(&self, now: monotime::Time) -> ByteCount {
        let Some(last_sent_time) = self.last_sent_time else {
            return self.max_burst_size();
        };
        let elapsed = nanos_to_byte_count(now.sub(&last_sent_time).as_nanos());
        let budget = self.budget_at_last_sent + (self.get_bandwidth)() * elapsed / 1_000_000_000;
        min_byte_count(self.max_burst_size(), budget)
    }

    fn max_burst_size(&self) -> ByteCount {
        max_byte_count(
            nanos_to_byte_count((MIN_PACING_DELAY + Duration::from_millis(1)).as_nanos()) * (self.get_bandwidth)()
                / 1_000_000_000,
            MAX_BURST_PACKETS * self.max_datagram_size,
        )
    }

    /// Returns when the next packet should be sent.
    /// It returns the zero value of monotime.Time if a packet can be sent immediately.
    ///
    /// The zero value is the instant [`monotime::now`] stands for here: waiting until it elapses no
    /// time at all, which is what a caller of the zero value does.
    pub(crate) fn time_until_send(&self) -> monotime::Time {
        if self.budget_at_last_sent >= self.max_datagram_size {
            return monotime::now();
        }
        let Some(last_sent_time) = self.last_sent_time else {
            // nothing has been sent yet, so there is no send to space the next one from
            return monotime::now();
        };
        last_sent_time.add(max_duration(
            MIN_PACING_DELAY,
            Duration::from_nanos(delay_nanos(
                self.max_datagram_size - self.budget_at_last_sent,
                (self.get_bandwidth)(),
            )),
        ))
    }

    pub(crate) const fn set_max_datagram_size(&mut self, s: ByteCount) {
        self.max_datagram_size = s;
    }
}

/// A monotonic duration as the byte count the token bucket works in; no reachable elapsed time is
/// close to `i64::MAX` nanoseconds.
fn nanos_to_byte_count(nanos: u128) -> ByteCount {
    ByteCount::try_from(nanos).unwrap_or(ByteCount::MAX)
}

/// The nanoseconds a deficit of `bytes` takes at `bandwidth` bytes per second, rounded up.
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the pacing delay is computed in f64 from the byte counts and rounded to a non-negative nanosecond count"
)]
fn delay_nanos(bytes: ByteCount, bandwidth: ByteCount) -> u64 {
    ((bytes as f64) * 1e9 / (bandwidth as f64)).ceil() as u64
}

const fn max_byte_count(a: ByteCount, b: ByteCount) -> ByteCount {
    if a < b {
        b
    } else {
        a
    }
}

const fn min_byte_count(a: ByteCount, b: ByteCount) -> ByteCount {
    if a < b {
        a
    } else {
        b
    }
}

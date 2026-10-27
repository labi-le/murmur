//! Token buckets for the ShadowQuic-to-JLS camouflage relay.
//!
//! A ShadowQuic listener that forwards unauthenticated traffic to a JLS
//! destination must not be usable to amplify traffic against it, so
//! every relayed packet passes one of these first. Two shapes exist: a
//! byte-rate token bucket for packet data, and a count-based token bucket for
//! the forwarder-state transitions (tentative forwards, persistent fallback
//! sockets, authenticating connections).

use std::time::Duration;

use parking_lot::Mutex;

const BURST_PERIOD: Duration = Duration::from_millis(10);

/// The burst floor: a rate too low to cover one 1452-byte packet in the burst
/// period still admits that packet.
const MIN_BURST_BYTES: f64 = 1452.0;

const BITS_PER_BYTE: f64 = 8.0;

/// A token bucket over bytes.
pub struct PacketRateLimiter {
    inner: Mutex<Option<Bucket>>,
}

impl core::fmt::Debug for PacketRateLimiter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketRateLimiter").finish_non_exhaustive()
    }
}

struct Bucket {
    rate_bytes_per_second: f64,
    burst: f64,
    available: f64,
    last: tokio::time::Instant,
}

impl PacketRateLimiter {
    /// A `rate_bps` of zero disables limiting entirely, modelled as an
    /// `unlimited` flag rather than an infinitely large bucket.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "the bucket keeps its rate as f64; precision above 2^53 bit/s cannot change admission"
    )]
    pub fn new(rate_bps: u64) -> Self {
        let inner = if rate_bps == 0 {
            None
        } else {
            let rate_bytes_per_second = rate_bps as f64 / BITS_PER_BYTE;
            let burst = (rate_bytes_per_second * BURST_PERIOD.as_secs_f64()).max(MIN_BURST_BYTES);
            Some(Bucket { rate_bytes_per_second, burst, available: burst, last: tokio::time::Instant::now() })
        };
        Self { inner: Mutex::new(inner) }
    }

    pub fn allow(&self, n: usize) -> bool {
        self.allow_at(n, tokio::time::Instant::now())
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "`n` is a single relayed packet, far inside the 2^53 bytes an f64 represents exactly"
    )]
    pub fn allow_at(&self, n: usize, now: tokio::time::Instant) -> bool {
        let mut guard = self.inner.lock();
        let Some(bucket) = guard.as_mut() else {
            return true;
        };
        let elapsed = now.saturating_duration_since(bucket.last);
        bucket.available =
            elapsed.as_secs_f64().mul_add(bucket.rate_bytes_per_second, bucket.available).min(bucket.burst);
        bucket.last = now;
        if n as f64 > bucket.available {
            return false;
        }
        bucket.available -= n as f64;
        drop(guard);
        true
    }
}

/// A token bucket over counts, refilled to `burst` at `rate` tokens per second.
pub struct CountRateLimiter {
    state: Mutex<CountBucket>,
}

impl core::fmt::Debug for CountRateLimiter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CountRateLimiter").finish_non_exhaustive()
    }
}

struct CountBucket {
    tokens: f64,
    updated: tokio::time::Instant,
}

impl CountRateLimiter {
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "the burst is a handful of concurrency slots, exactly representable in f64"
    )]
    pub fn new(burst: usize) -> Self {
        Self { state: Mutex::new(CountBucket { tokens: burst as f64, updated: tokio::time::Instant::now() }) }
    }

    /// Refills the bucket. `burst` is passed per call because one limiter is
    /// refilled against different rate/burst pairs at different call sites.
    #[expect(
        clippy::cast_precision_loss,
        reason = "rate and burst are concurrency counts in the tens, exactly representable in f64"
    )]
    pub fn refill(&self, now: tokio::time::Instant, rate: usize, burst: usize) {
        let mut bucket = self.state.lock();
        let elapsed = now.saturating_duration_since(bucket.updated);
        bucket.tokens = elapsed.as_secs_f64().mul_add(rate as f64, bucket.tokens).min(burst as f64);
        bucket.updated = now;
    }

    /// The `tokens < 1` check followed by a decrement, which the forwarder
    /// inlines at every call site after its own `refill`.
    pub fn take(&self) -> bool {
        let mut bucket = self.state.lock();
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}

/// The tentative-forward concurrency cap, and the unit every other count-based
/// limit is derived from.
pub const MAX_TENTATIVE_FORWARDS: usize = 64;
/// Persistent fallback sockets are far more expensive than tentative probes,
/// so this is a multiple of the tentative cap.
pub const MAX_FORWARD_CONNS: usize = 4 * MAX_TENTATIVE_FORWARDS;
pub const MAX_AUTHENTICATING_CONNS: usize = MAX_FORWARD_CONNS;
pub const MAX_TENTATIVE_CLIENTS: usize = 1024;
/// The per-client cap: a single source address gets a quarter of the
/// server-wide budget.
pub const MAX_PER_CLIENT: usize = MAX_TENTATIVE_FORWARDS / 4;
pub const MAX_CAPTURE_BYTES: i64 = 10 << 20;
pub const MAX_CAPTURE_BYTES_PER_CLIENT: i64 = 2 * MAX_CAPTURE_BYTES;
pub const MAX_CAPTURE_BYTES_PER_SERVER: i64 = 100 << 20;

/// The per-client slice of the forwarder's budget.
///
/// A single source address must not be able to consume the server-wide
/// fallback capacity, so every counter here has both a per-client and a
/// server-wide limit.
pub struct ClientBudget {
    pub forwards: usize,
    pub fallbacks: usize,
    pub authenticating: usize,
    pub captured_bytes: i64,
    fallback_rate: CountRateLimiter,
    authentication_rate: CountRateLimiter,
}

impl core::fmt::Debug for ClientBudget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientBudget")
            .field("forwards", &self.forwards)
            .field("fallbacks", &self.fallbacks)
            .field("authenticating", &self.authenticating)
            .field("captured_bytes", &self.captured_bytes)
            .finish_non_exhaustive()
    }
}

impl ClientBudget {
    /// Builds a client budget. The constructor also stamps the last-seen time, but that
    /// lives in the forwarder's own map entry here.
    #[must_use]
    pub fn new() -> Self {
        Self {
            forwards: 0,
            fallbacks: 0,
            authenticating: 0,
            captured_bytes: 0,
            fallback_rate: CountRateLimiter::new(MAX_PER_CLIENT),
            authentication_rate: CountRateLimiter::new(MAX_PER_CLIENT),
        }
    }
}

impl Default for ClientBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBudget {
    /// Refreshes the per-client token buckets against the per-client rate and
    /// burst, refreshing all three limiters at each reservation.
    pub fn refill(&self, now: tokio::time::Instant) {
        self.fallback_rate.refill(now, MAX_PER_CLIENT, MAX_PER_CLIENT);
        self.authentication_rate.refill(now, MAX_PER_CLIENT, MAX_PER_CLIENT);
    }

    /// the `tokens < 1` check on the fallback limiter.
    pub fn take_fallback(&self) -> bool {
        self.fallback_rate.take()
    }

    /// the `tokens < 1` check on the authentication limiter.
    pub fn take_authentication(&self) -> bool {
        self.authentication_rate.take()
    }

    pub fn has_authentication_capacity(&self) -> bool {
        self.authenticating < MAX_PER_CLIENT
    }

    /// the `candidate.forwards != 0 || candidate.fallbacks != 0 ||
    /// candidate.authenticating != 0 || candidate.capturedBytes != 0` guard in
    /// the idle-client eviction scan: a client still holding any resource is
    /// not evictable, so it is skipped when the map is full.
    pub fn holds_no_resources(&self) -> bool {
        self.forwards == 0 && self.fallbacks == 0 && self.authenticating == 0 && self.captured_bytes == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_rate_never_limits() {
        let limiter = PacketRateLimiter::new(0);
        assert!(limiter.allow(usize::MAX));
    }

    #[test]
    fn the_burst_floor_admits_one_maximum_packet() {
        // 1 bit/s is far below one 1452-byte packet per burst period, so the
        // floor is what admits it; the second packet must then be refused.
        let limiter = PacketRateLimiter::new(1);
        let now = tokio::time::Instant::now();
        assert!(limiter.allow_at(1452, now));
        assert!(!limiter.allow_at(1452, now));
    }

    #[test]
    fn tokens_refill_at_the_configured_rate() {
        // 8 kbit/s is 1000 B/s, whose 10 ms burst of 10 B is floored to the
        // 1452 B packet-size floor, so 1000 B leaves 452 B.
        let limiter = PacketRateLimiter::new(8 * 1000);
        let now = tokio::time::Instant::now();
        assert!(limiter.allow_at(1000, now));
        assert!(!limiter.allow_at(1000, now), "no refill within the same instant");
        // 200 ms at 1000 B/s restores 200 B: 452 + 200 = 652, still short of 1000.
        assert!(!limiter.allow_at(1000, now + Duration::from_millis(200)));
        // A further 800 ms reaches the 1452 B burst cap exactly, so a packet fits.
        assert!(limiter.allow_at(1000, now + Duration::from_secs(1)));
    }

    #[test]
    fn a_count_limiter_hands_out_exactly_its_burst() {
        let limiter = CountRateLimiter::new(3);
        assert!(limiter.take());
        assert!(limiter.take());
        assert!(limiter.take());
        assert!(!limiter.take());
        limiter.refill(tokio::time::Instant::now() + Duration::from_secs(1), 1, 3);
        assert!(limiter.take());
    }

    #[test]
    fn a_client_budget_hands_out_exactly_the_per_client_share() {
        let budget = ClientBudget::new();
        for _ in 0..MAX_PER_CLIENT {
            assert!(budget.take_fallback());
        }
        assert!(!budget.take_fallback(), "one client must not exceed its quarter of the budget");

        budget.refill(tokio::time::Instant::now() + Duration::from_secs(1));
        assert!(budget.take_fallback());
    }

    #[test]
    fn a_client_holding_any_resource_is_not_evictable() {
        let mut budget = ClientBudget::new();
        assert!(budget.holds_no_resources(), "a fresh client holds nothing");

        budget.forwards = 1;
        assert!(!budget.holds_no_resources());
        budget.forwards = 0;

        budget.fallbacks = 1;
        assert!(!budget.holds_no_resources());
        budget.fallbacks = 0;

        budget.authenticating = 1;
        assert!(!budget.holds_no_resources());
        budget.authenticating = 0;

        budget.captured_bytes = 1;
        assert!(!budget.holds_no_resources());
    }

    #[test]
    fn a_client_cannot_authenticate_past_its_per_client_cap() {
        let mut budget = ClientBudget::new();
        for held in 0..MAX_PER_CLIENT {
            budget.authenticating = held;
            assert!(budget.has_authentication_capacity());
        }
        budget.authenticating = MAX_PER_CLIENT;
        assert!(!budget.has_authentication_capacity());
    }
}

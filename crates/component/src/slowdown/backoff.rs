use portable_atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// The `i64::MAX - 512` bound that keeps the float-to-nanosecond conversion from overflowing an
/// `i64`.
const MAX_INT64: f64 = 9_223_372_036_854_775_295.0;

/// A duration counter starting at `min`. After every call the current timing is multiplied by
/// `factor`, but it never exceeds `max`.
///
/// Backoff is not generally concurrent-safe, but `for_attempt` can be used concurrently.
#[derive(Debug, Default)]
pub struct Backoff {
    pub attempt: AtomicU64,
    /// Factor is the multiplying factor for each increment step
    pub factor: f64,
    /// Jitter eases contention by randomizing backoff steps
    pub jitter: bool,
    /// Min and Max are the minimum and maximum values of the counter
    pub min: Duration,
    pub max: Duration,
}

impl Backoff {
    /// Duration returns the duration for the current attempt before incrementing
    /// the attempt counter. See `for_attempt`.
    pub fn duration(&self) -> Duration {
        let attempt = self.attempt.fetch_add(1, Ordering::SeqCst);
        #[expect(
            clippy::cast_precision_loss,
            reason = "the attempt counter is a float exponent; precision beyond 2^53 attempts is irrelevant"
        )]
        let attempt = attempt as f64;
        self.for_attempt(attempt)
    }

    /// Returns the duration for a specific attempt; the first attempt is 0.
    ///
    /// This is useful for a large number of independent backoffs that should not each store the
    /// Backoff parameters. `for_attempt` is concurrent-safe.
    pub fn for_attempt(&self, attempt: f64) -> Duration {
        // Zero-values are nonsensical, so we use
        // them to apply defaults
        let min = if self.min > Duration::ZERO { self.min } else { Duration::from_millis(100) };
        let max = if self.max > Duration::ZERO { self.max } else { Duration::from_secs(10) };
        if min >= max {
            // short-circuit
            return max;
        }
        let factor = if self.factor > 0.0 { self.factor } else { 2.0 };
        // calculate this duration
        #[expect(
            clippy::cast_precision_loss,
            reason = "the delay is a float exponent; nanosecond precision beyond 2^53 is meaningless"
        )]
        let minf = min.as_nanos() as f64;
        let mut durf = minf * factor.powf(attempt);
        if self.jitter {
            durf = rand::random::<f64>().mul_add(durf - minf, minf);
        }
        // keep the float from overflowing the i64 bound
        if durf > MAX_INT64 {
            return max;
        }
        #[expect(clippy::cast_possible_truncation, reason = "the check above bounds the value to the i64 range")]
        let dur = durf as i64;
        let min_ns = i64::try_from(min.as_nanos()).unwrap_or(i64::MAX);
        let max_ns = i64::try_from(max.as_nanos()).unwrap_or(i64::MAX);
        // keep within bounds
        if dur < min_ns {
            return min;
        }
        if dur > max_ns {
            return max;
        }
        Duration::from_nanos(dur.unsigned_abs())
    }

    /// Reset restarts the current attempt counter at zero.
    pub fn reset(&self) {
        self.attempt.store(0, Ordering::SeqCst);
    }

    /// Attempt returns the current attempt counter value.
    #[must_use]
    pub fn attempt(&self) -> f64 {
        #[expect(
            clippy::cast_precision_loss,
            reason = "the counter is reported as a float exponent; precision beyond 2^53 is irrelevant"
        )]
        let attempt = self.attempt.load(Ordering::SeqCst) as f64;
        attempt
    }

    /// Adds one to the attempt counter.
    pub fn add_attempt(&self) {
        self.attempt.fetch_add(1, Ordering::SeqCst);
    }

    /// Copy returns a backoff with equals constraints as the original
    #[must_use]
    pub fn copy(&self) -> Self {
        Self { attempt: AtomicU64::default(), factor: self.factor, jitter: self.jitter, min: self.min, max: self.max }
    }
}

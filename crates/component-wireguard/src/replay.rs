//! The 64-packet sliding window that rejects a re-sent counter.

/// A window of the 64 counters below the largest one seen; bit `i` stands for
/// `largest - i`, so bit 0 is always set.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReplayFilter {
    largest: u64,
    window: u64,
}

impl ReplayFilter {
    pub fn reset(&mut self) {
        self.largest = 0;
        self.window = 0;
    }

    /// Validates a counter, without the counter ceiling, which the caller applies
    /// against its own reject-after-messages limit.
    pub fn validate_counter(&mut self, counter: u64) -> bool {
        if counter > self.largest {
            let advance = counter - self.largest;
            self.window = if advance >= u64::from(u64::BITS) { 0 } else { self.window << advance };
            self.window |= 1;
            self.largest = counter;
            return true;
        }
        let age = self.largest - counter;
        if age >= u64::from(u64::BITS) {
            return false;
        }
        let bit = 1u64 << age;
        if self.window & bit != 0 {
            return false;
        }
        self.window |= bit;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_replays_and_anything_older_than_the_window() {
        let mut filter = ReplayFilter::default();
        for counter in 0..64 {
            assert!(filter.validate_counter(counter), "counter {counter}");
        }
        assert!(!filter.validate_counter(0));
        assert!(!filter.validate_counter(63));
        assert!(filter.validate_counter(64));
        assert!(!filter.validate_counter(0));
        assert!(filter.validate_counter(1000));
        assert!(filter.validate_counter(999));
        assert!(!filter.validate_counter(999));
        assert!(!filter.validate_counter(936));
    }

    #[test]
    fn a_gap_in_the_counter_sequence_is_filled_once() {
        let mut filter = ReplayFilter::default();
        assert!(filter.validate_counter(10));
        assert!(filter.validate_counter(12));
        assert!(filter.validate_counter(11));
        assert!(!filter.validate_counter(11));
    }

    #[test]
    fn reset_reopens_the_window() {
        let mut filter = ReplayFilter::default();
        assert!(filter.validate_counter(5));
        filter.reset();
        assert!(filter.validate_counter(5));
    }
}

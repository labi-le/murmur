use std::ops::{Div, Sub};

// Both traits are type sets the sender bounds are written against, so they stay open; the crate is
// `publish = false`, so a downstream `impl` cannot come into coherence conflict with them.
/// the `WindowedFilterValue` type set: any value.
pub trait WindowedFilterValue {}

impl<V> WindowedFilterValue for V {}

/// the `WindowedFilterTime` type set: integers and floats.
pub trait WindowedFilterTime: Copy + PartialOrd + Sub<Output = Self> + Div<Output = Self> + From<u8> {}

impl<T> WindowedFilterTime for T where T: Copy + PartialOrd + Sub<Output = Self> + Div<Output = Self> + From<u8> {}

/// Tracks the minimum (or maximum) sample estimate over a fixed time interval.
///
/// Implements Kathleen Nichols' algorithm: for instance, the minimum RTT over the
/// past five minutes. It keeps track of the best, second best, and third best min
/// (or max) estimates, maintaining an invariant that the measurement time of the
/// n'th best >= n-1'th best.
///
/// The algorithm works as follows. On a reset, all three estimates are set to
/// the same sample. The second best estimate is then recorded in the second
/// quarter of the window, and a third best estimate is recorded in the second
/// half of the window, bounding the worst case error when the true min is
/// monotonically increasing (or true max is monotonically decreasing) over the
/// window.
///
/// A new best sample replaces all three estimates, since the new best is lower
/// (or higher) than everything else in the window and it is the most recent.
/// The window thus effectively gets reset on every new min. The same property
/// holds true for second best and third best estimates. Specifically, when a
/// sample arrives that is better than the second best but not better than the
/// best, it replaces the second and third best estimates but not the best
/// estimate. Similarly, a sample that is better than the third best estimate
/// but not the other estimates replaces only the third best estimate.
///
/// Finally, when the best expires, it is replaced by the second best, which in
/// turn is replaced by the third best. The newest sample replaces the third
/// best.
#[derive(Debug)]
pub struct WindowedFilter<V, T> {
    // Time length of window.
    window_length: T,
    estimates: [Entry<V, T>; 3],
    comparator: fn(V, V) -> i32,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Entry<V, T> {
    pub(crate) sample: V,
    pub(crate) time: T,
}

/// Compares two values and returns true if the first is greater than or equal
/// to the second.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the signature matches the `fn(V, V) -> i32` comparator stored in `WindowedFilter`"
)]
pub fn max_filter<O: PartialOrd>(a: O, b: O) -> i32 {
    if a > b {
        1
    } else if a < b {
        -1
    } else {
        0
    }
}

/// Compares two values and returns true if the first is less than or equal
/// to the second.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the signature matches the `fn(V, V) -> i32` comparator stored in `WindowedFilter`"
)]
pub fn min_filter<O: PartialOrd>(a: O, b: O) -> i32 {
    if a < b {
        1
    } else if a > b {
        -1
    } else {
        0
    }
}

pub fn new_windowed_filter<V, T>(window_length: T, comparator: fn(V, V) -> i32) -> WindowedFilter<V, T>
where
    V: WindowedFilterValue + Copy + Default,
    T: WindowedFilterTime + Default,
{
    WindowedFilter { window_length, estimates: [Entry::default(); 3], comparator }
}

impl<V, T> WindowedFilter<V, T>
where
    V: WindowedFilterValue + Copy + Default,
    T: WindowedFilterTime + Default,
{
    /// Changes the window length.  Does not update any current samples.
    pub const fn set_window_length(&mut self, window_length: T) {
        self.window_length = window_length;
    }

    pub const fn get_best(&self) -> V {
        self.estimates[0].sample
    }

    pub const fn get_second_best(&self) -> V {
        self.estimates[1].sample
    }

    pub const fn get_third_best(&self) -> V {
        self.estimates[2].sample
    }

    /// Updates best estimates with |sample|, and expires and updates best
    /// estimates as necessary.
    pub fn update(&mut self, new_sample: V, new_time: T) {
        // Reset all estimates if they have not yet been initialized, if new sample
        // is a new best, or if the newest recorded estimate is too old.
        if (self.comparator)(self.estimates[0].sample, V::default()) == 0
            || (self.comparator)(new_sample, self.estimates[0].sample) >= 0
            || new_time - self.estimates[2].time > self.window_length
        {
            self.reset(new_sample, new_time);
            return;
        }

        if (self.comparator)(new_sample, self.estimates[1].sample) >= 0 {
            self.estimates[1] = Entry { sample: new_sample, time: new_time };
            self.estimates[2] = self.estimates[1];
        } else if (self.comparator)(new_sample, self.estimates[2].sample) >= 0 {
            self.estimates[2] = Entry { sample: new_sample, time: new_time };
        }

        // Expire and update estimates as necessary.
        if new_time - self.estimates[0].time > self.window_length {
            // The best estimate hasn't been updated for an entire window, so promote
            // second and third best estimates.
            self.estimates[0] = self.estimates[1];
            self.estimates[1] = self.estimates[2];
            self.estimates[2] = Entry { sample: new_sample, time: new_time };
            // Need to iterate one more time. Check if the new best estimate is
            // outside the window as well, since it may also have been recorded a
            // long time ago. Don't need to iterate once more since we cover that
            // case at the beginning of the method.
            if new_time - self.estimates[0].time > self.window_length {
                self.estimates[0] = self.estimates[1];
                self.estimates[1] = self.estimates[2];
            }
            return;
        }
        if (self.comparator)(self.estimates[1].sample, self.estimates[0].sample) == 0
            && new_time - self.estimates[1].time > self.window_length / T::from(4u8)
        {
            // A quarter of the window has passed without a better sample, so the
            // second-best estimate is taken from the second quarter of the window.
            self.estimates[1] = Entry { sample: new_sample, time: new_time };
            self.estimates[2] = self.estimates[1];
            return;
        }

        if (self.comparator)(self.estimates[2].sample, self.estimates[1].sample) == 0
            && new_time - self.estimates[2].time > self.window_length / T::from(2u8)
        {
            // We've passed a half of the window without a better estimate, so take
            // a third-best estimate from the second half of the window.
            self.estimates[2] = Entry { sample: new_sample, time: new_time };
        }
    }

    /// Resets all estimates to new sample.
    pub const fn reset(&mut self, new_sample: V, new_time: T) {
        self.estimates[2] = Entry { sample: new_sample, time: new_time };
        self.estimates[1] = self.estimates[2];
        self.estimates[0] = self.estimates[1];
    }

    pub fn clear(&mut self) {
        self.estimates = [Entry::default(); 3];
    }
}

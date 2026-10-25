/// Kathleen Nichols' windowed filter: three estimates are kept so that the best one never
/// outlives the window by more than one update.
#[derive(Debug)]
pub struct WindowedFilter {
    /// Time length of window.
    window_length: i64,
    estimates: [Sample; 3],
    comparator: fn(i64, i64) -> bool,
}

/// A measurement and the time unit it was recorded at.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sample {
    pub(crate) sample: i64,
    pub(crate) time: i64,
}

/// Compares two values and returns true if the first is greater than or equal
/// to the second.
#[must_use]
pub const fn max_filter(a: i64, b: i64) -> bool {
    a >= b
}

/// Compares two values and returns true if the first is less than or equal
/// to the second.
#[must_use]
pub const fn min_filter(a: i64, b: i64) -> bool {
    a <= b
}

pub fn new_windowed_filter(window_length: i64, comparator: fn(i64, i64) -> bool) -> WindowedFilter {
    WindowedFilter { window_length, estimates: [Sample::default(); 3], comparator }
}

impl WindowedFilter {
    /// Changes the window length.  Does not update any current samples.
    pub const fn set_window_length(&mut self, window_length: i64) {
        self.window_length = window_length;
    }

    #[must_use]
    pub const fn get_best(&self) -> i64 {
        self.estimates[0].sample
    }

    #[must_use]
    pub const fn get_second_best(&self) -> i64 {
        self.estimates[1].sample
    }

    #[must_use]
    pub const fn get_third_best(&self) -> i64 {
        self.estimates[2].sample
    }

    pub fn update(&mut self, sample: i64, time: i64) {
        if self.estimates[0].time == 0
            || (self.comparator)(sample, self.estimates[0].sample)
            || (time - self.estimates[2].time) > self.window_length
        {
            self.reset(sample, time);
            return;
        }

        if (self.comparator)(sample, self.estimates[1].sample) {
            self.estimates[1].sample = sample;
            self.estimates[1].time = time;
            self.estimates[2].sample = sample;
            self.estimates[2].time = time;
        } else if (self.comparator)(sample, self.estimates[2].sample) {
            self.estimates[2].sample = sample;
            self.estimates[2].time = time;
        }

        // Expire and update estimates as necessary.
        if time - self.estimates[0].time > self.window_length {
            // The best estimate hasn't been updated for an entire window, so promote
            // second and third best estimates.
            self.estimates[0] = self.estimates[1];
            self.estimates[1] = self.estimates[2];
            self.estimates[2] = Sample { sample, time };
            // Check whether the new best estimate is outside the window as well, since it
            // may also have been recorded a long time ago; the case of a still older
            // estimate is covered at the beginning of the method.
            if time - self.estimates[0].time > self.window_length {
                self.estimates[0] = self.estimates[1];
                self.estimates[1] = self.estimates[2];
            }
            return;
        }
        if self.estimates[1].sample == self.estimates[0].sample
            && time - self.estimates[1].time > self.window_length >> 2
        {
            // A quarter of the window has passed without a better sample, so the
            // second-best estimate is taken from the second quarter of the window.
            self.estimates[1].sample = sample;
            self.estimates[1].time = time;
            self.estimates[2].sample = sample;
            self.estimates[2].time = time;
            return;
        }

        if self.estimates[2].sample == self.estimates[1].sample
            && time - self.estimates[2].time > self.window_length >> 1
        {
            // We've passed a half of the window without a better estimate, so take
            // a third-best estimate from the second half of the window.
            self.estimates[2].sample = sample;
            self.estimates[2].time = time;
        }
    }

    pub const fn reset(&mut self, new_sample: i64, new_time: i64) {
        self.estimates[0].sample = new_sample;
        self.estimates[0].time = new_time;
        self.estimates[1].sample = new_sample;
        self.estimates[1].time = new_time;
        self.estimates[2].sample = new_sample;
        self.estimates[2].time = new_time;
    }
}

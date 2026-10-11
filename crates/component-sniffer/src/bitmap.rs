#[derive(Debug, Default, Clone)]
pub(crate) struct Bitmap {
    words: Vec<u64>,
}

impl Bitmap {
    /// Sets every bit in the half-open interval `[start, end)`. Panics if `start` is negative or
    /// `end` is less than `start`.
    pub(crate) fn set_range(&mut self, start: isize, end: isize) {
        assert!(start >= 0 && end >= start, "invalid bitmap range");
        if start == end {
            return;
        }
        let start = start.cast_unsigned();
        let end = end.cast_unsigned();

        let word_count = (end - 1) / 64 + 1;
        if word_count > self.words.len() {
            let bit_len = usize::BITS - (word_count - 1).leading_zeros();
            let mut new_word_count = 1usize << bit_len;
            if new_word_count > usize::MAX >> 1 {
                new_word_count = word_count;
            }
            let mut words = vec![0u64; new_word_count];
            if let Some(head) = words.get_mut(..self.words.len()) {
                head.copy_from_slice(&self.words);
            }
            self.words = words;
        }

        let first_word = start / 64;
        let last_word = (end - 1) / 64;
        let first_mask = !0u64 << (start % 64);
        let end_bit = end % 64;
        let last_mask = if end_bit != 0 { (1u64 << end_bit) - 1 } else { !0u64 };

        let Some(window) = self.words.get_mut(first_word..=last_word) else {
            return;
        };
        if first_word == last_word {
            for word in window {
                *word |= first_mask & last_mask;
            }
            return;
        }
        if let [first, middle @ .., last] = window {
            *first |= first_mask;
            middle.fill(!0u64);
            *last |= last_mask;
        }
    }

    /// Returns the first unset bit in `[start, end)`, or `end` if all bits in the interval are
    /// set. Panics if `start` is negative or `end` is less than `start`.
    pub(crate) fn first_unset(&self, start: isize, end: isize) -> isize {
        assert!(start >= 0 && end >= start, "invalid bitmap range");
        if start == end {
            return end;
        }
        let ustart = start.cast_unsigned();
        let uend = end.cast_unsigned();

        let mut word_index = ustart / 64;
        let Some(&first_word) = self.words.get(word_index) else {
            return start;
        };
        let mut word = first_word | ((1u64 << (ustart % 64)) - 1);
        loop {
            if word != !0u64 {
                let unset = word_index * 64 + (!word).trailing_zeros() as usize;
                return if unset < uend { unset.cast_signed() } else { end };
            }

            word_index += 1;
            if word_index * 64 >= uend {
                return end;
            }
            let Some(&next) = self.words.get(word_index) else {
                return (word_index * 64).cast_signed();
            };
            word = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Bitmap;

    #[test]
    fn zero_value() {
        let coverage = Bitmap::default();
        assert_eq!(0, coverage.first_unset(0, 128));
        assert_eq!(0, coverage.first_unset(0, 0));
    }

    #[test]
    fn single_word() {
        let mut coverage = Bitmap::default();
        coverage.set_range(1, 5);
        assert_eq!(0, coverage.first_unset(0, 5));
        assert_eq!(5, coverage.first_unset(1, 5));
        assert_eq!(5, coverage.first_unset(1, 6));
    }

    #[test]
    fn cross_word() {
        let mut coverage = Bitmap::default();
        coverage.set_range(1, 130);
        assert_eq!(130, coverage.first_unset(1, 130));
        assert_eq!(130, coverage.first_unset(1, 131));
    }

    #[test]
    fn one_bit_gap() {
        let mut coverage = Bitmap::default();
        coverage.set_range(0, 64);
        coverage.set_range(65, 130);
        assert_eq!(64, coverage.first_unset(0, 130));
    }

    #[test]
    fn overlap_survives_growth() {
        let mut coverage = Bitmap::default();
        coverage.set_range(0, 10);
        coverage.set_range(64, 70);
        coverage.set_range(8, 65);
        assert_eq!(70, coverage.first_unset(0, 71));
    }

    #[test]
    fn invalid_range() {
        let coverage = Bitmap::default();
        assert!(std::panic::catch_unwind(|| coverage.clone().set_range(-1, 0)).is_err());
        assert!(std::panic::catch_unwind(|| coverage.clone().set_range(1, 0)).is_err());
        assert!(std::panic::catch_unwind(|| coverage.first_unset(-1, 0)).is_err());
        assert!(std::panic::catch_unwind(|| coverage.first_unset(1, 0)).is_err());
    }
}

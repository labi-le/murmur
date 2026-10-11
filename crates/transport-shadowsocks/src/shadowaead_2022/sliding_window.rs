const BLOCK_BIT_LOG: u32 = 6;
const RING_BLOCKS: u64 = 1 << 7;
const BLOCK_MASK: u64 = RING_BLOCKS - 1;
const BIT_MASK: u64 = (1 << BLOCK_BIT_LOG) - 1;
const SIZE: u64 = (RING_BLOCKS - 1) << BLOCK_BIT_LOG;

#[expect(
    clippy::cast_possible_truncation,
    reason = "RING_BLOCKS is 128, exactly representable in usize on every supported target"
)]
const RING_BLOCKS_USIZE: usize = RING_BLOCKS as usize;

/// The `ring` slot for a block index the caller has already masked with `BLOCK_MASK`; the
/// `Option` is `None` only for an index outside `RING_BLOCKS`, which the mask cannot produce.
fn ring_slot(masked_block_index: u64) -> Option<usize> {
    usize::try_from(masked_block_index).ok()
}

#[derive(Debug, Clone)]
pub struct SlidingWindow {
    last: u64,
    ring: [u64; RING_BLOCKS_USIZE],
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self { last: 0, ring: [0u64; RING_BLOCKS_USIZE] }
    }
}

impl SlidingWindow {
    #[must_use]
    pub fn check(&self, counter: u64) -> bool {
        if counter > self.last {
            return true;
        }
        if self.last - counter > SIZE {
            return false;
        }
        let block_index = (counter >> BLOCK_BIT_LOG) & BLOCK_MASK;
        let bit_index = counter & BIT_MASK;
        let word = ring_slot(block_index).and_then(|slot| self.ring.get(slot)).copied().unwrap_or(0);
        (word >> bit_index) & 1 == 0
    }

    pub fn add(&mut self, counter: u64) {
        let mut block_index = counter >> BLOCK_BIT_LOG;

        if counter > self.last {
            let last_block_index = self.last >> BLOCK_BIT_LOG;
            let diff = (block_index - last_block_index).min(RING_BLOCKS);
            let mut last_block_index = last_block_index;
            for _ in 0..diff {
                last_block_index = (last_block_index + 1) & BLOCK_MASK;
                if let Some(word) = ring_slot(last_block_index).and_then(|slot| self.ring.get_mut(slot)) {
                    *word = 0;
                }
            }
            self.last = counter;
        }

        block_index &= BLOCK_MASK;
        let bit_index = counter & BIT_MASK;
        if let Some(word) = ring_slot(block_index).and_then(|slot| self.ring.get_mut(slot)) {
            *word |= 1 << bit_index;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_monotonic_counters() {
        let mut w = SlidingWindow::default();
        for i in 0..1000u64 {
            assert!(w.check(i));
            w.add(i);
        }
    }

    #[test]
    fn rejects_replayed_counter() {
        let mut w = SlidingWindow::default();
        assert!(w.check(5));
        w.add(5);
        assert!(!w.check(5));
    }

    #[test]
    fn accepts_reordered_within_window() {
        let mut w = SlidingWindow::default();
        w.add(100);
        assert!(w.check(90));
        w.add(90);
        assert!(!w.check(90));
        assert!(!w.check(100));
    }

    #[test]
    fn rejects_counter_behind_window() {
        let mut w = SlidingWindow::default();
        w.add(SIZE + 1000);
        assert!(!w.check(5));
    }
}

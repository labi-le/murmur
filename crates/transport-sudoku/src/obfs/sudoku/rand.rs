use rand::TryRngCore as _;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub(crate) struct SudokuRand {
    state: u64,
    cached: u32,
    have_cached: bool,
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the nanosecond clock only seeds the PRNG, so its low 64 bits are taken as-is"
)]
pub(crate) fn new_seeded_rand() -> SudokuRand {
    let mut seed = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0i64, |d| d.as_nanos() as i64);
    let mut seed_bytes = [0u8; 8];
    if rand::rngs::OsRng.try_fill_bytes(&mut seed_bytes).is_ok() {
        seed = i64::from_be_bytes(seed_bytes);
    }
    new_sudoku_rand(seed)
}

pub(crate) const fn new_sudoku_rand(seed: i64) -> SudokuRand {
    let mut state = seed.cast_unsigned();
    if state == 0 {
        state = 0x9e37_79b9_7f4a_7c15;
    }
    SudokuRand { state, cached: 0, have_cached: false }
}

impl SudokuRand {
    pub(crate) const fn uint64(&mut self) -> u64 {
        self.have_cached = false;
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub(crate) fn uint32(&mut self) -> u32 {
        if self.have_cached {
            self.have_cached = false;
            return self.cached;
        }
        let v = self.uint64();
        let [low0, low1, low2, low3, ..] = v.to_le_bytes();
        self.cached = u32::from_le_bytes([low0, low1, low2, low3]);
        self.have_cached = true;
        (v >> 32) as u32
    }

    pub(crate) fn intn(&mut self, n: usize) -> usize {
        if n <= 1 {
            return 0;
        }
        fast_intn_from_uint32(self.uint32(), n)
    }
}

pub(crate) fn fast_intn_from_uint32(u: u32, n: usize) -> usize {
    ((u64::from(u) * n as u64) >> 32) as usize
}

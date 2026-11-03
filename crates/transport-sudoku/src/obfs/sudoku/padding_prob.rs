use super::rand::SudokuRand;

pub(crate) const PROB_ONE: u64 = 1u64 << 32;

pub(crate) fn pick_padding_threshold(r: Option<&mut SudokuRand>, p_min: i32, p_max: i32) -> u64 {
    let Some(r) = r else {
        return 0;
    };
    let mut p_min = p_min;
    let mut p_max = p_max;
    if p_min < 0 {
        p_min = 0;
    }
    if p_max < p_min {
        p_max = p_min;
    }
    if p_max > 100 {
        p_max = 100;
    }
    if p_min > 100 {
        p_min = 100;
    }

    let min = u64::from(p_min.cast_unsigned()) * PROB_ONE / 100;
    let max = u64::from(p_max.cast_unsigned()) * PROB_ONE / 100;
    if max <= min {
        return min;
    }
    let u = u64::from(r.uint32());
    min + ((u.wrapping_mul(max - min)) >> 32)
}

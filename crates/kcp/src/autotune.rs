//! FEC bandwidth autotuning: detects the peer's actual data/parity shard period.
//!
//! The period is inferred from the stream of incoming FEC flags, so a decoder configured with
//! the wrong `(dataShards, parityShards)` can resynchronize.

fn itimediff(later: u32, earlier: u32) -> i32 {
    later.wrapping_sub(earlier).cast_signed()
}

const MAX_AUTO_TUNE_SAMPLES: usize = 258;

/// `pulse`: a 0/1 signal sample with its wire sequence number.
#[derive(Clone, Copy)]
struct Pulse {
    bit: bool,
    seq: u32,
}

/// The auto-tune state. Kept as a plain `Vec` (bounded at [`MAX_AUTO_TUNE_SAMPLES`]) rather than a
/// heap container: the eviction rule is "drop the sample with smallest wrap-safe seq", which a
/// linear scan finds directly over this small, bounded collection.
#[derive(Default)]
pub(crate) struct AutoTune {
    pulses: Vec<Pulse>,
}

impl AutoTune {
    pub(crate) fn sample(&mut self, bit: bool, seq: u32) {
        self.pulses.push(Pulse { bit, seq });
        if self.pulses.len() > MAX_AUTO_TUNE_SAMPLES {
            let mut min_idx = 0;
            let mut min_seq = self.pulses.first().map_or(0, |p| p.seq);
            for (i, pulse) in self.pulses.iter().enumerate().skip(1) {
                if itimediff(pulse.seq, min_seq) < 0 {
                    min_idx = i;
                    min_seq = pulse.seq;
                }
            }
            self.pulses.swap_remove(min_idx);
        }
    }

    /// Finds the period; returns `-1` if none is found.
    pub(crate) fn find_period(&self, bit: bool) -> i32 {
        if self.pulses.len() < 3 {
            return -1;
        }

        let mut sorted = self.pulses.clone();
        sorted.sort_by(|a, b| itimediff(a.seq, b.seq).cmp(&0));

        let mut left_edge = None;
        for (i, (prev, cur)) in sorted.iter().zip(sorted.iter().skip(1)).enumerate() {
            if prev.seq.wrapping_add(1) != cur.seq {
                return -1;
            }
            if prev.bit != bit && cur.bit == bit {
                left_edge = Some(i + 1);
                break;
            }
        }
        let Some(left_edge) = left_edge else {
            return -1;
        };

        let mut right_edge = None;
        for (i, (prev, cur)) in sorted.iter().zip(sorted.iter().skip(1)).enumerate().skip(left_edge) {
            if prev.seq.wrapping_add(1) != cur.seq {
                return -1;
            }
            if prev.bit == bit && cur.bit != bit {
                right_edge = Some(i + 1);
                break;
            }
        }
        let Some(right_edge) = right_edge else {
            return -1;
        };

        i32::try_from(right_edge - left_edge).unwrap_or(-1)
    }
}

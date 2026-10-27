//! Padding size caps and the padding bytes themselves.
//!
//! [`max_padding_size`] is the hard cap a segment's transport allows; the traffic pattern then
//! lowers it to whatever the pattern's `padding` fields allow. [`new_padding`] draws the actual
//! bytes, either printable-ASCII or entropy-balanced, and the caller splices them into the segment
//! around the encrypted payload.

use rand::Rng;

use crate::rng;
use crate::trafficpattern::{Config, MAX_PADDING_LEN};

/// `packetOverhead = NonceSize*2 + MetadataLength + Overhead*2`, one nonce and one tag per AEAD
/// blob (the metadata and the payload).
pub const PACKET_OVERHEAD: usize =
    crate::cipher::DEFAULT_NONCE_SIZE * 2 + crate::wire::METADATA_LENGTH + 2 * crate::cipher::DEFAULT_OVERHEAD;

/// Where padding goes, which is what picks the traffic-pattern field that caps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaddingPosition {
    Middle,
    End,
}

/// The maximum padding size: the transport's own ceiling, before any traffic pattern narrows it. A stream
/// segment has no MTU to respect, so it gets the full padding-length field.
#[must_use]
pub fn max_padding_size(
    transport: crate::session::Transport,
    mtu: usize,
    fragment_size: usize,
    existing: usize,
) -> usize {
    match transport {
        crate::session::Transport::Stream => MAX_PADDING_LEN as usize,
        crate::session::Transport::Packet => {
            #[expect(
                clippy::cast_possible_wrap,
                reason = "mtu, fragment_size and existing come from the transport MTU and a segment length, far below i64::MAX"
            )]
            let (available, existing_i64) =
                (mtu as i64 - PACKET_OVERHEAD as i64 - fragment_size as i64, existing as i64);
            if available <= existing_i64 {
                return 0;
            }
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "available > existing_i64 here and the min clamps the value into 0..=MAX_PADDING_LEN"
            )]
            let capped = (available - existing_i64).min(i64::from(MAX_PADDING_LEN)) as usize;
            capped
        }
    }
}

/// The maximum padding size with a traffic pattern: the transport ceiling, narrowed by the pattern.
///
/// The middle and end padding caps do the narrowing; a pattern that does not configure the
/// position leaves the transport ceiling in place.
pub fn max_padding_size_with_traffic_pattern(
    config: Option<&Config>,
    transport: crate::session::Transport,
    mtu: usize,
    fragment_size: usize,
    existing: usize,
    position: PaddingPosition,
) -> usize {
    let ceiling = max_padding_size(transport, mtu, fragment_size, existing);
    let Some(configured) = config.and_then(Config::padding_pattern).and_then(|padding| match position {
        PaddingPosition::Middle => padding.max_middle_padding_len,
        PaddingPosition::End => padding.max_end_padding_len,
    }) else {
        return ceiling;
    };
    let Ok(configured) = usize::try_from(configured) else {
        // A negative configured length disables this position's padding.
        return 0;
    };
    ceiling.min(configured)
}

/// The ASCII strategy: at least `min_consecutive_ascii_len` adjacent bytes are made printable.
#[derive(Clone, Copy, Debug, Default)]
pub struct AsciiPaddingOpts {
    pub min_consecutive_ascii_len: usize,
}

/// The entropy strategy: pad until the scarcer bit of `existing_data` is rare enough overall.
#[derive(Clone, Debug)]
pub struct EntropyPaddingOpts {
    pub existing_data: Vec<u8>,
    /// The target share of the scarcer bit across existing data plus padding, in `(0.0, 0.5]`.
    pub target_probability: f64,
}

/// Padding options.
#[derive(Clone, Debug)]
pub struct PaddingOpts {
    pub max_len: usize,
    pub ascii: Option<AsciiPaddingOpts>,
    pub entropy: Option<EntropyPaddingOpts>,
}

impl PaddingOpts {
    /// Builds the recommended padding options: mieru picks one of its two strategies per source name, so a
    /// given user name always pads the same way.
    #[must_use]
    pub fn recommended(max_len: usize, random_data_len: usize, strategy_source: &str) -> Self {
        if rng::fixed_int_v(2, strategy_source) == 0 {
            return Self {
                max_len,
                ascii: Some(AsciiPaddingOpts {
                    min_consecutive_ascii_len: max_len.min(recommended_consecutive_ascii_len()),
                }),
                entropy: None,
            };
        }
        let mut existing_data = vec![0u8; random_data_len];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut existing_data);
        Self {
            max_len,
            ascii: None,
            entropy: Some(EntropyPaddingOpts { existing_data, target_probability: RECOMMENDED_TARGET_PROBABILITY }),
        }
    }
}

/// The recommended target probability.
const RECOMMENDED_TARGET_PROBABILITY: f64 = 0.325;

fn recommended_consecutive_ascii_len() -> usize {
    #[expect(clippy::cast_sign_loss, reason = "rng::fixed_int_vh returns a non-negative range")]
    let extra = rng::fixed_int_vh(17) as usize;
    24 + extra
}

/// Builds padding. Returns an empty buffer when the cap is zero, which is how a pattern turns
/// padding off.
#[must_use]
pub fn new_padding(opts: &PaddingOpts) -> Vec<u8> {
    if let Some(ascii) = opts.ascii {
        return new_ascii_padding(opts.max_len, ascii.min_consecutive_ascii_len);
    }
    if let Some(entropy) = &opts.entropy {
        return new_entropy_padding(opts.max_len, entropy);
    }
    Vec::new()
}

fn new_ascii_padding(max_len: usize, min_consecutive_ascii_len: usize) -> Vec<u8> {
    let min_consecutive_ascii_len = min_consecutive_ascii_len.min(max_len);
    if max_len == 0 {
        return Vec::new();
    }
    let length = rng::intn(max_len - min_consecutive_ascii_len + 1) + min_consecutive_ascii_len;
    let mut padding = random_bytes(length);
    // The printable run is placed at a random offset, so a fixed start would make the ASCII
    // padding just as fingerprintable as none at all.
    let begin = if length > min_consecutive_ascii_len {
        rand::rng().random_range(0..length - min_consecutive_ascii_len)
    } else {
        0
    };
    to_printable_char(&mut padding, begin, begin + min_consecutive_ascii_len);
    padding
}

fn new_entropy_padding(max_len: usize, opts: &EntropyPaddingOpts) -> Vec<u8> {
    if max_len == 0 {
        return Vec::new();
    }
    let distribution = to_bit_distribution(&opts.existing_data);
    let (lower_bit, lower_bit_count) = if distribution.bit1 < distribution.bit0 {
        (1u8, distribution.bit1_count)
    } else {
        (0u8, distribution.bit0_count)
    };

    // With x = lowerBitCount, t = targetProbability, e = existing bits and p = padding bits the
    // goal is x = t * (e + p), so p = x / t - e.
    let target = opts.target_probability.clamp(f64::MIN_POSITIVE, 0.5);
    let existing_bits = opts.existing_data.len() * 8;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        reason = "bit counts are bounded by the payload length, which is bounded by MAX_PDU"
    )]
    let min_padding_bits = ((lower_bit_count as f64 / target) - existing_bits as f64).max(0.0) as usize;
    let min_padding_bytes = min_padding_bits.div_ceil(8);

    let length = if min_padding_bytes >= max_len {
        max_len
    } else {
        rng::intn(max_len - min_padding_bytes + 1) + min_padding_bytes
    };
    let mut padding = vec![0u8; length];

    // Only as many padding bits as the target still needs may differ from the uniform fill.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "bit counts and the padding length are bounded by the payload, which is bounded by MAX_PDU"
    )]
    let flip = (((existing_bits + length * 8) as f64 * target) as i64 - lower_bit_count as i64)
        .clamp(0, length as i64 * 8) as usize;
    let mut rng = rand::rng();
    if lower_bit == 0 {
        padding.fill(0xFF);
        for _ in 0..flip {
            let j = rng.random_range(0..length * 8);
            // j < length * 8 and padding.len() == length, so the byte index exists.
            if let Some(byte) = padding.get_mut(j / 8) {
                *byte &= !(1 << (j % 8));
            }
        }
    } else {
        for _ in 0..flip {
            let j = rng.random_range(0..length * 8);
            if let Some(byte) = padding.get_mut(j / 8) {
                *byte |= 1 << (j % 8);
            }
        }
    }
    padding
}

fn random_bytes(length: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; length];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut buffer);
    buffer
}

/// The low end of the printable ASCII range.
pub const PRINTABLE_CHAR_SUB: u8 = 0x20;
/// The high end of the printable ASCII range.
pub const PRINTABLE_CHAR_SUP: u8 = 0x7E;
const PRINTABLE_CHAR_LEN: u32 = (PRINTABLE_CHAR_SUP - PRINTABLE_CHAR_SUB + 1) as u32;
/// The largest multiple of the printable range that fits in a `u16`; draws above it are rejected
/// so the modulo below introduces no bias.
const PRINTABLE_UINT16_LIMIT: u32 = (1u32 << 16) - ((1u32 << 16) % PRINTABLE_CHAR_LEN);
/// The 64-character alphabet used for low-entropy text.
pub const COMMON64_SET: &[u8; 64] = b"CCOzB3KKr9NDAgVnJcCn9ib37T1JH6vRSVx8YaNnXbfo6yFU1EHPy2r3D5LM1Qi4";

/// Rewrites `b[begin..end]` so every byte is printable ASCII, keeping
/// the bytes that already are.
pub fn to_printable_char(b: &mut [u8], begin: usize, end: usize) {
    let mut pending = Vec::new();
    for (i, slot) in b.iter_mut().enumerate().take(end).skip(begin) {
        if *slot < PRINTABLE_CHAR_SUB || *slot > PRINTABLE_CHAR_SUP {
            if *slot & 0x80 > 0 {
                let low_bits = *slot & 0x7F;
                if (PRINTABLE_CHAR_SUB..=PRINTABLE_CHAR_SUP).contains(&low_bits) {
                    *slot = low_bits;
                    continue;
                }
            }
            pending.push(i);
        }
    }
    let mut rng = rand::rng();
    for i in pending {
        // The index came from the enumeration above, so the byte exists.
        let Some(slot) = b.get_mut(i) else {
            continue;
        };
        // Rejection sampling keeps the printable range uniform; a plain modulo would favour the
        // low characters, which is exactly the bias the range is drawn from.
        loop {
            let draw: u32 = rng.random();
            if draw < PRINTABLE_UINT16_LIMIT {
                *slot = (draw % PRINTABLE_CHAR_LEN) as u8 + PRINTABLE_CHAR_SUB;
                break;
            }
        }
    }
}

/// Maps each byte through the low six bits of mieru's 64-character table,
/// so the result looks like base64-ish text drawn from a small, fixed alphabet.
pub fn to_common64_set(b: &mut [u8], begin: usize, end: usize) {
    for slot in b.iter_mut().take(end).skip(begin) {
        // The mask keeps the index below the table's 64 entries.
        let Some(mapped) = COMMON64_SET.get(usize::from(*slot & 0x3F)) else {
            continue;
        };
        *slot = *mapped;
    }
}

/// The bit distribution of a payload.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BitDistribution {
    pub bit0: f64,
    pub bit1: f64,
    pub bit0_count: usize,
    pub bit1_count: usize,
}

/// Computes the bit distribution. An empty input is a perfect split, which is what makes the entropy
/// strategy's "no data yet" case symmetric.
#[must_use]
pub fn to_bit_distribution(data: &[u8]) -> BitDistribution {
    if data.is_empty() {
        return BitDistribution { bit0: 0.5, bit1: 0.5, bit0_count: 0, bit1_count: 0 };
    }
    let mut bit0_count = 0usize;
    let mut bit1_count = 0usize;
    for byte in data {
        for i in 0..8 {
            if (byte >> i) & 1 == 0 {
                bit0_count += 1;
            } else {
                bit1_count += 1;
            }
        }
    }
    #[expect(clippy::cast_precision_loss, reason = "the bit counts of a payload bounded by MAX_PDU fit exactly in f64")]
    let total = (data.len() * 8) as f64;
    #[expect(clippy::cast_precision_loss, reason = "the bit counts fit exactly in f64")]
    let (bit0, bit1) = (bit0_count as f64 / total, bit1_count as f64 / total);
    BitDistribution { bit0, bit1, bit0_count, bit1_count }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trafficpattern::{Config, PaddingPattern, TrafficPattern};

    fn ascii_opts(max_len: usize, min_consecutive: usize) -> PaddingOpts {
        PaddingOpts {
            max_len,
            ascii: Some(AsciiPaddingOpts { min_consecutive_ascii_len: min_consecutive }),
            entropy: None,
        }
    }

    #[test]
    fn a_zero_cap_produces_no_padding() {
        assert!(new_padding(&ascii_opts(0, 0)).is_empty());
        assert!(new_padding(&PaddingOpts {
            max_len: 0,
            ascii: None,
            entropy: Some(EntropyPaddingOpts { existing_data: vec![1, 2, 3], target_probability: 0.3 }),
        })
        .is_empty());
    }

    #[test]
    fn ascii_padding_never_exceeds_its_cap() {
        for max_len in 1..=64usize {
            let padding = new_padding(&ascii_opts(max_len, max_len));
            assert!(padding.len() <= max_len, "max_len {max_len} produced {}", padding.len());
        }
    }

    /// A run of printable ASCII is what the ASCII strategy exists to produce, so it has to be
    /// observable in the output rather than merely possible.
    #[test]
    fn ascii_padding_carries_a_printable_run_of_at_least_the_minimum() {
        for max_len in 32..=255usize {
            let min_consecutive = max_len.min(recommended_consecutive_ascii_len());
            let padding = new_padding(&ascii_opts(max_len, min_consecutive));
            assert!(max_consecutive_printable_length(&padding) >= min_consecutive, "max_len {max_len}");
        }
    }

    /// The longest run of printable bytes.
    fn max_consecutive_printable_length(b: &[u8]) -> usize {
        let mut best = 0;
        let mut current = 0;
        for &byte in b {
            if (PRINTABLE_CHAR_SUB..=PRINTABLE_CHAR_SUP).contains(&byte) {
                current += 1;
                best = best.max(current);
            } else {
                current = 0;
            }
        }
        best
    }

    #[test]
    fn entropy_padding_balances_the_scarcer_bit_towards_the_target() {
        let existing_data: Vec<u8> = (0..200u16).map(|i| (i % 251) as u8).collect();
        let target = 0.325;
        let opts = EntropyPaddingOpts { existing_data, target_probability: target };
        let padding = new_entropy_padding(255, &opts);
        assert!(!padding.is_empty());
        let combined = [opts.existing_data.as_slice(), padding.as_slice()].concat();
        let distribution = to_bit_distribution(&combined);
        let scarcer = distribution.bit0.min(distribution.bit1);
        assert!(scarcer <= target + 0.05, "scarcer bit share {scarcer} overshot target {target}");
    }

    #[test]
    fn entropy_padding_respects_a_zero_cap() {
        let opts = EntropyPaddingOpts { existing_data: vec![0u8; 32], target_probability: 0.3 };
        assert!(new_entropy_padding(0, &opts).is_empty());
    }

    #[test]
    fn to_printable_char_rewrites_only_non_printable_bytes() {
        let mut data: Vec<u8> = (0..=255u8).collect();
        let already_printable =
            data.iter().copied().filter(|b| (PRINTABLE_CHAR_SUB..=PRINTABLE_CHAR_SUP).contains(b)).count();
        let len = data.len();
        to_printable_char(&mut data, 0, len);
        assert!(data.iter().all(|b| (PRINTABLE_CHAR_SUB..=PRINTABLE_CHAR_SUP).contains(b)));
        for (index, byte) in data.iter().enumerate() {
            let original = index as u8;
            if (PRINTABLE_CHAR_SUB..=PRINTABLE_CHAR_SUP).contains(&original) {
                assert_eq!(*byte, original, "printable byte at {index} was rewritten");
            }
        }
        assert_eq!(already_printable, 95);
    }

    /// A byte whose high bit is set but whose low seven bits already spell a printable character
    /// is recovered by clearing the high bit rather than redrawn. `0xFF` does not qualify: its low
    /// bits are `0x7F`, one past the last printable character, so it is redrawn.
    #[test]
    fn to_printable_char_recovers_a_byte_by_clearing_its_high_bit() {
        let mut data = vec![0xA5u8, 0x41, 0x00];
        let len = data.len();
        to_printable_char(&mut data, 0, len);
        assert_eq!(data[0], 0x25, "0xA5's low bits already spell a printable character");
        assert_eq!(data[1], 0x41, "an already printable byte is kept");
        assert!((PRINTABLE_CHAR_SUB..=PRINTABLE_CHAR_SUP).contains(&data[2]), "0x00 has to be redrawn");
    }

    #[test]
    fn to_printable_char_leaves_bytes_outside_the_range_alone() {
        let mut data = vec![0x00u8; 8];
        to_printable_char(&mut data, 2, 5);
        assert_eq!(&data[..2], &[0x00, 0x00], "bytes before the range must not be touched");
        assert!(
            data[2..5].iter().all(|b| (PRINTABLE_CHAR_SUB..=PRINTABLE_CHAR_SUP).contains(b)),
            "bytes inside the range must be rewritten"
        );
        assert_eq!(&data[5..], &[0x00, 0x00, 0x00], "bytes after the range must not be touched");
    }

    #[test]
    fn to_common64_set_draws_from_the_fixed_alphabet() {
        let mut data: Vec<u8> = (0..=255u8).collect();
        let len = data.len();
        to_common64_set(&mut data, 0, len);
        assert!(data.iter().all(|b| COMMON64_SET.contains(b)));
    }

    #[test]
    fn bit_distribution_counts_and_ratios_agree() {
        assert_eq!(to_bit_distribution(&[]), BitDistribution { bit0: 0.5, bit1: 0.5, bit0_count: 0, bit1_count: 0 });
        let distribution = to_bit_distribution(&[0x00, 0xFF]);
        assert_eq!(distribution.bit0_count + distribution.bit1_count, 16);
        assert_eq!(distribution.bit0_count, 8);
        assert!((distribution.bit0 - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn the_transport_ceiling_ignores_the_pattern() {
        assert_eq!(max_padding_size(crate::session::Transport::Stream, 1400, 100, 0), 255);
        // 1400 - 112 overhead - 200 fragment - 10 already used = 1078, capped at 255.
        assert_eq!(max_padding_size(crate::session::Transport::Packet, 1400, 200, 10), 255);
        assert_eq!(max_padding_size(crate::session::Transport::Packet, 400, 200, 10), 78);
        assert_eq!(max_padding_size(crate::session::Transport::Packet, 200, 200, 10), 0);
    }

    #[test]
    fn the_pattern_lowers_the_ceiling_to_its_configured_maximum() {
        let config = |middle: Option<i32>, end: Option<i32>| {
            Config::new(Some(TrafficPattern {
                padding: Some(PaddingPattern { max_middle_padding_len: middle, max_end_padding_len: end }),
                ..Default::default()
            }))
            .expect("config")
        };
        let capped = config(Some(64), Some(32));
        assert_eq!(
            max_padding_size_with_traffic_pattern(
                Some(&capped),
                crate::session::Transport::Stream,
                1400,
                0,
                0,
                PaddingPosition::Middle
            ),
            64
        );
        assert_eq!(
            max_padding_size_with_traffic_pattern(
                Some(&capped),
                crate::session::Transport::Stream,
                1400,
                0,
                0,
                PaddingPosition::End
            ),
            32
        );
        assert_eq!(
            max_padding_size_with_traffic_pattern(
                Some(&capped),
                crate::session::Transport::Packet,
                1400,
                200,
                10,
                PaddingPosition::End
            ),
            32,
            "the pattern's cap is still bounded by the transport ceiling"
        );
    }

    #[test]
    fn a_pattern_without_the_position_leaves_the_ceiling_alone() {
        let config = Config::new(Some(TrafficPattern {
            padding: Some(PaddingPattern { max_middle_padding_len: Some(0), max_end_padding_len: None }),
            ..Default::default()
        }))
        .expect("config");
        // The effective pattern always fills both fields, so drive the unset path through a
        // pattern whose padding block the caller never saw.
        assert!(Config::new(None).expect("config").padding_pattern().is_some());
        assert_eq!(
            max_padding_size_with_traffic_pattern(
                None,
                crate::session::Transport::Stream,
                1400,
                0,
                0,
                PaddingPosition::Middle
            ),
            255
        );
        assert_eq!(
            max_padding_size_with_traffic_pattern(
                Some(&config),
                crate::session::Transport::Stream,
                1400,
                0,
                0,
                PaddingPosition::Middle
            ),
            0,
            "an explicit zero disables middle padding"
        );
    }
}

//! The `traffic-pattern` option is a base64 protobuf `TrafficPattern` message.
//!
//! [`Config`] is the
//! two-layer view kept here: `original` is what the user wrote, `effective` is the same message
//! with every unset field generated from the pattern's seed, so a partially-specified pattern
//! still pins down a complete one.
//!
//! The three behaviours the effective pattern drives live alongside it: nonce shaping in
//! [`crate::cipher`], segment padding in [`crate::padding`], and TCP write fragmentation in
//! [`crate::underlay`]. Low-entropy payload coding is a fourth knob in the same message; it is
//! decoded and validated for round-trip parity but not applied, and
//! [`Config::low_entropy_enabled`] reports it so a caller can refuse the pattern rather than
//! silently send un-camouflaged traffic.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use prost::Message;

use crate::rng;

/// The maximum padding length: the widest padding the wire's one-byte length fields can describe.
pub const MAX_PADDING_LEN: i32 = 255;

#[derive(thiserror::Error, Debug)]
pub enum PatternError {
    #[error("decode base64 string failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("proto.Unmarshal() failed: malformed protobuf traffic pattern")]
    Protobuf,
    #[error("TrafficPattern is invalid: {0}")]
    Invalid(String),
}

/// How the nonce bytes are chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum NonceType {
    Random = 0,
    Printable = 1,
    PrintableSubset = 2,
    Fixed = 3,
}

impl NonceType {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Random),
            1 => Some(Self::Printable),
            2 => Some(Self::PrintableSubset),
            3 => Some(Self::Fixed),
            _ => None,
        }
    }
}

/// The `Off` low-entropy mode, the only one that leaves low entropy disabled.
pub const LOW_ENTROPY_MODE_OFF: i32 = 0;
/// The number of low-entropy mode values, from which an implicit mode is drawn.
pub const LOW_ENTROPY_MODE_COUNT: usize = 5;

/// The number of `LowEntropyMaskRotation` enum values: no rotation, 15 right rotations and 15
/// left rotations.
pub const LOW_ENTROPY_MASK_ROTATION_COUNT: usize = 31;

#[derive(Clone, PartialEq, Eq, Message)]
pub struct TcpFragment {
    #[prost(bool, optional, tag = "1")]
    pub enable: Option<bool>,
    #[prost(int32, optional, tag = "2")]
    pub max_sleep_ms: Option<i32>,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct NoncePatternProto {
    #[prost(int32, optional, tag = "1")]
    pub nonce_type: Option<i32>,
    #[prost(bool, optional, tag = "2")]
    pub apply_to_all_udp_packet: Option<bool>,
    #[prost(int32, optional, tag = "3")]
    pub min_len: Option<i32>,
    #[prost(int32, optional, tag = "4")]
    pub max_len: Option<i32>,
    #[prost(string, repeated, tag = "5")]
    pub custom_hex_strings: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct PaddingPattern {
    #[prost(int32, optional, tag = "1")]
    pub max_middle_padding_len: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    pub max_end_padding_len: Option<i32>,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct LowEntropyPattern {
    #[prost(int32, optional, tag = "1")]
    pub mode: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    pub mask_rotation: Option<i32>,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct TrafficPattern {
    #[prost(int32, optional, tag = "1")]
    pub seed: Option<i32>,
    #[prost(bool, optional, tag = "2")]
    pub unlock_all: Option<bool>,
    #[prost(message, optional, tag = "3")]
    pub tcp_fragment: Option<TcpFragment>,
    #[prost(message, optional, tag = "4")]
    pub nonce: Option<NoncePatternProto>,
    #[prost(message, optional, tag = "5")]
    pub padding: Option<PaddingPattern>,
    #[prost(message, optional, tag = "6")]
    pub low_entropy: Option<LowEntropyPattern>,
}

/// The nonce shape applied to every generated nonce, once the effective pattern has filled in
/// the gaps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoncePattern {
    pub nonce_type: NonceType,
    pub apply_to_all_udp_packet: bool,
    pub min_len: i32,
    pub max_len: i32,
    pub custom_hex_strings: Vec<String>,
}

/// A validated traffic pattern plus the effective pattern generated from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    original: TrafficPattern,
    effective: TrafficPattern,
}

/// `Encode`: the base64 form of the protobuf message, the exact inverse of [`decode`].
#[must_use]
pub fn encode(pattern: &TrafficPattern) -> String {
    STANDARD.encode(pattern.encode_to_vec())
}

/// `Decode`.
pub fn decode(encoded: &str) -> Result<TrafficPattern, PatternError> {
    let bytes = STANDARD.decode(encoded)?;
    TrafficPattern::decode(bytes.as_slice()).map_err(|_| PatternError::Protobuf)
}

/// Validates a pattern. A pattern that is not set at all is valid.
pub fn validate(pattern: Option<&TrafficPattern>) -> Result<(), PatternError> {
    let Some(pattern) = pattern else { return Ok(()) };
    if let Some(fragment) = &pattern.tcp_fragment {
        if let Some(max_sleep_ms) = fragment.max_sleep_ms {
            if max_sleep_ms < 0 {
                return Err(PatternError::Invalid(format!("TCPFragment maxSleepMs {max_sleep_ms} is negative")));
            }
            if max_sleep_ms > 100 {
                return Err(PatternError::Invalid(format!(
                    "TCPFragment maxSleepMs {max_sleep_ms} exceeds maximum value 100"
                )));
            }
        }
    }
    if let Some(nonce) = &pattern.nonce {
        if let Some(min_len) = nonce.min_len {
            if min_len < 0 {
                return Err(PatternError::Invalid(format!("NoncePattern minLen {min_len} is negative")));
            }
            if min_len > 12 {
                return Err(PatternError::Invalid(format!("NoncePattern minLen {min_len} exceeds maximum value 12")));
            }
        }
        if let Some(max_len) = nonce.max_len {
            if max_len < 0 {
                return Err(PatternError::Invalid(format!("NoncePattern maxLen {max_len} is negative")));
            }
            if max_len > 12 {
                return Err(PatternError::Invalid(format!("NoncePattern maxLen {max_len} exceeds maximum value 12")));
            }
        }
        if let (Some(min_len), Some(max_len)) = (nonce.min_len, nonce.max_len) {
            if min_len > max_len {
                return Err(PatternError::Invalid(format!(
                    "NoncePattern minLen {min_len} is greater than maxLen {max_len}"
                )));
            }
        }
        for (i, hex_str) in nonce.custom_hex_strings.iter().enumerate() {
            let decoded = decode_hex(hex_str).ok_or_else(|| {
                PatternError::Invalid(format!(
                    "NoncePattern customHexStrings[{i}] {hex_str:?} is not a valid hex string"
                ))
            })?;
            if decoded.len() > 12 {
                return Err(PatternError::Invalid(format!(
                    "NoncePattern customHexStrings[{i}] decoded length {} exceeds maximum 12 bytes",
                    decoded.len()
                )));
            }
        }
    }
    if let Some(padding) = &pattern.padding {
        if let Some(max_middle) = padding.max_middle_padding_len {
            if max_middle < 0 {
                return Err(PatternError::Invalid(format!(
                    "PaddingPattern maxMiddlePaddingLen {max_middle} is negative"
                )));
            }
            if max_middle > MAX_PADDING_LEN {
                return Err(PatternError::Invalid(format!(
                    "PaddingPattern maxMiddlePaddingLen {max_middle} exceeds maximum value {MAX_PADDING_LEN}"
                )));
            }
        }
        if let Some(max_end) = padding.max_end_padding_len {
            if max_end < 0 {
                return Err(PatternError::Invalid(format!("PaddingPattern maxEndPaddingLen {max_end} is negative")));
            }
            if max_end > MAX_PADDING_LEN {
                return Err(PatternError::Invalid(format!(
                    "PaddingPattern maxEndPaddingLen {max_end} exceeds maximum value {MAX_PADDING_LEN}"
                )));
            }
        }
    }
    if let Some(low_entropy) = &pattern.low_entropy {
        if let Some(mode) = low_entropy.mode {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_possible_wrap,
                reason = "LOW_ENTROPY_MODE_COUNT is 5, which fits in i32"
            )]
            let last_mode = LOW_ENTROPY_MODE_OFF + LOW_ENTROPY_MODE_COUNT as i32 - 1;
            if !(LOW_ENTROPY_MODE_OFF..=last_mode).contains(&mode) {
                return Err(PatternError::Invalid(format!("LowEntropyPattern mode {mode} is invalid")));
            }
        }
        if let Some(rotation) = low_entropy.mask_rotation {
            if !is_valid_mask_rotation(rotation) {
                return Err(PatternError::Invalid(format!("LowEntropyPattern maskRotation {rotation} is invalid")));
            }
        }
    }
    Ok(())
}

/// Whether a low-entropy rotation is valid: no rotation, a right rotation of 1..=15 bits, or a left rotation
/// encoded as a multiple of 16 up to 240.
#[must_use]
pub fn is_valid_mask_rotation(rotation: i32) -> bool {
    (0..=15).contains(&rotation) || (16..=240).contains(&rotation) && rotation % 16 == 0
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let [hi, lo] = pair else {
                return None;
            };
            let hi = (*hi as char).to_digit(16)?;
            let lo = (*lo as char).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

impl Config {
    /// Validates `original`, then generates every field it left unset. `None` stands
    /// for the unset pattern, which becomes the empty one.
    pub fn new(original: Option<TrafficPattern>) -> Result<Self, PatternError> {
        validate(original.as_ref())?;
        let original = original.unwrap_or_default();
        let mut effective = original.clone();
        generate_implicit_traffic_pattern(&original, &mut effective);
        Ok(Self { original, effective })
    }

    #[must_use]
    pub fn original(&self) -> &TrafficPattern {
        &self.original
    }

    #[must_use]
    pub fn effective(&self) -> &TrafficPattern {
        &self.effective
    }

    /// The nonce shape to hand a cipher block. The *effective* pattern's nonce is used here, so
    /// an unconfigured nonce still gets the generated type and lengths.
    pub fn nonce_pattern(&self) -> Option<NoncePattern> {
        let nonce = self.effective.nonce.as_ref()?;
        Some(NoncePattern {
            nonce_type: nonce.nonce_type.and_then(NonceType::from_i32).unwrap_or(NonceType::Random),
            apply_to_all_udp_packet: nonce.apply_to_all_udp_packet.unwrap_or_default(),
            min_len: nonce.min_len.unwrap_or_default(),
            max_len: nonce.max_len.unwrap_or_default(),
            custom_hex_strings: nonce.custom_hex_strings.clone(),
        })
    }

    /// The effective padding caps, i.e. the pattern's configured bounds.
    #[must_use]
    pub fn padding_pattern(&self) -> Option<&PaddingPattern> {
        self.effective.padding.as_ref()
    }

    /// TCP write fragmentation, i.e. the fragmentation switch.
    #[must_use]
    pub fn tcp_fragment(&self) -> Option<(bool, i32)> {
        let fragment = self.effective.tcp_fragment.as_ref()?;
        Some((fragment.enable.unwrap_or_default(), fragment.max_sleep_ms.unwrap_or_default()))
    }

    /// Whether the effective pattern asks for low-entropy payload coding. Nothing in this crate
    /// applies it, so a caller that cannot honour it must refuse the pattern.
    #[must_use]
    pub fn low_entropy_enabled(&self) -> bool {
        self.effective
            .low_entropy
            .as_ref()
            .and_then(|low_entropy| low_entropy.mode)
            .is_some_and(|mode| mode != LOW_ENTROPY_MODE_OFF)
    }
}

/// Generates an implicit traffic pattern: the seed every unset field's generator keys off, and
/// whether the generators may reach for options the user did not name.
struct ImplicitContext {
    seed: i32,
    unlock_all: bool,
}

impl ImplicitContext {
    fn fixed(&self, n: i32, field: &str) -> i32 {
        rng::fixed_int(n, &format!("{}:{}", self.seed, field))
    }
}

fn generate_implicit_traffic_pattern(original: &TrafficPattern, effective: &mut TrafficPattern) {
    let context = ImplicitContext {
        seed: original.seed.unwrap_or_else(|| rng::fixed_int(i32::MAX, &rng::host_hint())),
        unlock_all: original.unlock_all.unwrap_or_default(),
    };
    generate_tcp_fragment(original, effective, &context);
    generate_nonce_pattern(original, effective, &context);
    generate_padding_pattern(original, effective, &context);
    generate_low_entropy_pattern(original, effective, &context);
}

fn generate_tcp_fragment(original: &TrafficPattern, effective: &mut TrafficPattern, context: &ImplicitContext) {
    let source = original.tcp_fragment.clone().unwrap_or_default();
    let enable = source.enable.unwrap_or_else(|| context.unlock_all && context.fixed(2, "tcpFragment.enable") == 1);
    let max_sleep_ms = source.max_sleep_ms.unwrap_or_else(|| {
        if context.unlock_all {
            context.fixed(100, "tcpFragment.maxSleepMs") + 1
        } else {
            0
        }
    });
    effective.tcp_fragment = Some(TcpFragment { enable: Some(enable), max_sleep_ms: Some(max_sleep_ms) });
}

fn generate_nonce_pattern(original: &TrafficPattern, effective: &mut TrafficPattern, context: &ImplicitContext) {
    let source = original.nonce.clone().unwrap_or_default();
    // NONCE_TYPE_FIXED is never generated: it needs custom hex strings, which a generated
    // pattern has no way to fill in meaningfully.
    let nonce_type = source.nonce_type.unwrap_or_else(|| {
        if context.unlock_all {
            context.fixed(NonceType::Random as i32, "nonce.type")
        } else {
            context.fixed(NonceType::Printable as i32, "nonce.type") + 1
        }
    });
    let apply_to_all_udp_packet =
        source.apply_to_all_udp_packet.unwrap_or_else(|| context.fixed(2, "nonce.applyToAllUDPPacket") == 1);
    let min_len = source.min_len.unwrap_or_else(|| {
        if context.unlock_all {
            context.fixed(13, "nonce.minLen")
        } else {
            context.fixed(7, "nonce.minLen") + 6
        }
    });
    let max_len = source.max_len.unwrap_or_else(|| context.fixed(13 - min_len, "nonce.maxLen") + min_len);
    effective.nonce = Some(NoncePatternProto {
        nonce_type: Some(nonce_type),
        apply_to_all_udp_packet: Some(apply_to_all_udp_packet),
        min_len: Some(min_len),
        max_len: Some(max_len),
        custom_hex_strings: source.custom_hex_strings,
    });
}

fn generate_padding_pattern(original: &TrafficPattern, effective: &mut TrafficPattern, context: &ImplicitContext) {
    let source = original.padding.clone().unwrap_or_default();
    let max_middle_padding_len = source
        .max_middle_padding_len
        .unwrap_or_else(|| (context.fixed(MAX_PADDING_LEN + 1, "padding.maxMiddlePaddingLen") - 128).max(0));
    let max_end_padding_len = source.max_end_padding_len.unwrap_or_else(|| {
        if context.unlock_all {
            context.fixed(MAX_PADDING_LEN + 1, "padding.maxEndPaddingLen")
        } else {
            MAX_PADDING_LEN
        }
    });
    effective.padding = Some(PaddingPattern {
        max_middle_padding_len: Some(max_middle_padding_len),
        max_end_padding_len: Some(max_end_padding_len),
    });
}

fn generate_low_entropy_pattern(original: &TrafficPattern, effective: &mut TrafficPattern, context: &ImplicitContext) {
    let source = original.low_entropy.clone().unwrap_or_default();
    let mode = source.mode.unwrap_or_else(|| {
        if context.unlock_all {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_possible_wrap,
                reason = "LOW_ENTROPY_MODE_COUNT is 5, which fits in i32"
            )]
            let mode_count = LOW_ENTROPY_MODE_COUNT as i32;
            context.fixed(mode_count, "lowEntropy.mode")
        } else {
            LOW_ENTROPY_MODE_OFF
        }
    });
    let mask_rotation = source.mask_rotation.unwrap_or_else(|| {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_possible_wrap,
            reason = "LOW_ENTROPY_MASK_ROTATION_COUNT is 31, which fits in i32"
        )]
        let rotation_count = LOW_ENTROPY_MASK_ROTATION_COUNT as i32;
        let index = context.fixed(rotation_count, "lowEntropy.maskRotation");
        if index <= 15 {
            index
        } else {
            (index - 15) * 16
        }
    });
    effective.low_entropy = Some(LowEntropyPattern { mode: Some(mode), mask_rotation: Some(mask_rotation) });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(base64: &str) -> TrafficPattern {
        decode(base64).expect("decode")
    }

    #[test]
    fn round_trips_through_base64() {
        // A traffic-pattern test vector: a tcpFragment block and nothing
        // else, so every other field stays unset and generation has to fill it in.
        let decoded = pattern("GgQIARAK");
        let tcp_fragment = decoded.tcp_fragment.as_ref().expect("tcp fragment");
        assert_eq!(tcp_fragment.enable, Some(true));
        assert_eq!(tcp_fragment.max_sleep_ms, Some(10));
        assert!(decoded.nonce.is_none(), "the vector sets no nonce pattern");
        assert_eq!(encode(&decoded), "GgQIARAK");
    }

    #[test]
    fn decodes_the_empty_string_to_an_empty_pattern() {
        assert_eq!(decode("").expect("decode empty"), TrafficPattern::default());
    }

    #[test]
    fn rejects_a_truncated_base64_payload() {
        assert!(matches!(decode("not base64!"), Err(PatternError::Base64(_))));
    }

    /// Generation only fills what the user left unset, so every field the pattern names has to
    /// come back unchanged while the rest are filled in.
    #[test]
    fn generation_preserves_every_explicitly_set_field() {
        let original = pattern("CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3");
        let effective = Config::new(Some(original.clone())).expect("config").effective().clone();
        assert_eq!(effective.seed, original.seed);
        assert_eq!(effective.unlock_all, original.unlock_all);
        assert_eq!(effective.tcp_fragment, original.tcp_fragment);
        let nonce_type = effective.nonce.as_ref().and_then(|n| n.nonce_type).expect("nonce type");
        assert_eq!(nonce_type, NonceType::Fixed as i32, "the vector's hex prefixes imply NONCE_TYPE_FIXED");
        assert_eq!(effective.nonce.as_ref().and_then(|n| n.apply_to_all_udp_packet), Some(true));
        let hex_strings = effective.nonce.as_ref().expect("nonce").custom_hex_strings.clone();
        assert_eq!(hex_strings, ["00010203".to_owned(), "04050607".to_owned()]);
        assert!(original.padding.is_none(), "the vector names no padding block");
        let padding = effective.padding.as_ref().expect("generated padding");
        assert!((0..=MAX_PADDING_LEN).contains(&padding.max_middle_padding_len.expect("middle")));
        assert!((0..=MAX_PADDING_LEN).contains(&padding.max_end_padding_len.expect("end")));
        // The vector sets unlockAll, so the generated low entropy mode is a draw over the whole
        // enum rather than the "off" the non-unlockAll path picks.
        let low_entropy_mode = effective.low_entropy.and_then(|l| l.mode).expect("low entropy mode");
        assert!(
            (LOW_ENTROPY_MODE_OFF..LOW_ENTROPY_MODE_OFF + LOW_ENTROPY_MODE_COUNT as i32).contains(&low_entropy_mode),
            "generated mode {low_entropy_mode} is outside the enum"
        );
    }

    /// The generated pattern must be a function of the seed alone: two configs built from the
    /// same message agree on every field, and different seeds can disagree.
    #[test]
    fn generation_is_deterministic_in_the_seed() {
        let effective = |seed| {
            let mut original = TrafficPattern { seed: Some(seed), ..Default::default() };
            original.unlock_all = Some(true);
            Config::new(Some(original)).expect("config").effective().clone()
        };
        assert_eq!(effective(42), effective(42));
        let differing = (0..64).any(|seed| effective(seed) != effective(seed + 1));
        assert!(differing, "64 consecutive seeds all produced the same pattern");
    }

    #[test]
    fn a_pattern_without_unlock_all_stays_in_the_safe_subset() {
        let effective = Config::new(Some(TrafficPattern::default())).expect("config").effective().clone();
        let tcp_fragment = effective.tcp_fragment.expect("tcp fragment");
        assert_eq!(tcp_fragment.enable, Some(false));
        assert_eq!(tcp_fragment.max_sleep_ms, Some(0));
        let nonce = effective.nonce.expect("nonce");
        assert!(matches!(nonce.nonce_type, Some(1 | 2)), "generated type {nonce:?}");
        let padding = effective.padding.expect("padding");
        assert_eq!(padding.max_end_padding_len, Some(MAX_PADDING_LEN));
        assert_eq!(effective.low_entropy.expect("low entropy").mode, Some(LOW_ENTROPY_MODE_OFF));
    }

    /// Every seed has to produce a nonce length pair the wire can carry, which is what the
    /// `min_len <= max_len <= 12` invariant that validation promises but the generator must honour.
    #[test]
    fn generated_nonce_lengths_stay_within_the_valid_range() {
        for seed in 0..200 {
            for unlock_all in [false, true] {
                let original = TrafficPattern { seed: Some(seed), unlock_all: Some(unlock_all), ..Default::default() };
                let effective = Config::new(Some(original)).expect("config").effective().clone();
                let nonce = effective.nonce.expect("nonce");
                let (min_len, max_len) = (nonce.min_len.expect("min len"), nonce.max_len.expect("max len"));
                assert!(
                    (0..=12).contains(&min_len) && (min_len..=12).contains(&max_len),
                    "seed {seed} unlockAll {unlock_all}: minLen {min_len} maxLen {max_len}"
                );
            }
        }
    }

    #[test]
    fn a_partially_specified_pattern_keeps_what_it_names() {
        let original = TrafficPattern {
            seed: Some(42),
            tcp_fragment: Some(TcpFragment { enable: Some(true), max_sleep_ms: None }),
            ..Default::default()
        };
        let config = Config::new(Some(original)).expect("config");
        let tcp_fragment = config.effective().tcp_fragment.as_ref().expect("tcp fragment");
        assert_eq!(tcp_fragment.enable, Some(true), "an explicit enable must not be regenerated");
        assert!(tcp_fragment.max_sleep_ms.is_some(), "an unset maxSleepMs must be generated");
        let nonce = config.effective().nonce.as_ref().expect("nonce");
        assert!(nonce.min_len.is_some() && nonce.max_len.is_some(), "an absent nonce must be generated whole");
    }

    #[test]
    fn a_fixed_nonce_pattern_survives_and_reports_its_prefixes() {
        let original = TrafficPattern {
            nonce: Some(NoncePatternProto {
                nonce_type: Some(NonceType::Fixed as i32),
                custom_hex_strings: vec!["00010203".to_owned(), "aabbccdd".to_owned()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let config = Config::new(Some(original)).expect("config");
        let pattern = config.nonce_pattern().expect("nonce pattern");
        assert_eq!(pattern.nonce_type, NonceType::Fixed);
        assert_eq!(pattern.custom_hex_strings, ["00010203", "aabbccdd"]);
    }

    #[test]
    fn low_entropy_is_reported_rather_than_silently_dropped() {
        let mut original = TrafficPattern::default();
        assert!(!Config::new(Some(original.clone())).expect("config").low_entropy_enabled());
        original.low_entropy = Some(LowEntropyPattern { mode: Some(3), mask_rotation: Some(0) });
        assert!(Config::new(Some(original)).expect("config").low_entropy_enabled());
    }

    #[test]
    fn validate_accepts_every_documented_bound() {
        for base64 in ["", "GgQIARAK", "CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3"] {
            validate(Some(&pattern(base64))).expect(base64);
        }
    }

    #[test]
    fn validate_rejects_each_out_of_range_field() {
        let cases: [(&str, Box<dyn Fn(&mut TrafficPattern)>); 12] = [
            (
                "maxSleepMs 101 exceeds maximum value 100",
                Box::new(|p: &mut TrafficPattern| {
                    p.tcp_fragment = Some(TcpFragment { enable: Some(true), max_sleep_ms: Some(101) });
                }),
            ),
            (
                "maxSleepMs -1 is negative",
                Box::new(|p: &mut TrafficPattern| {
                    p.tcp_fragment = Some(TcpFragment { enable: Some(true), max_sleep_ms: Some(-1) });
                }),
            ),
            (
                "maxLen 13 exceeds maximum value 12",
                Box::new(|p: &mut TrafficPattern| {
                    p.nonce = Some(NoncePatternProto { max_len: Some(13), ..Default::default() });
                }),
            ),
            (
                "minLen 13 exceeds maximum value 12",
                Box::new(|p: &mut TrafficPattern| {
                    p.nonce = Some(NoncePatternProto { min_len: Some(13), ..Default::default() });
                }),
            ),
            (
                "maxLen -1 is negative",
                Box::new(|p: &mut TrafficPattern| {
                    p.nonce = Some(NoncePatternProto { max_len: Some(-1), ..Default::default() });
                }),
            ),
            (
                "minLen -1 is negative",
                Box::new(|p: &mut TrafficPattern| {
                    p.nonce = Some(NoncePatternProto { min_len: Some(-1), ..Default::default() });
                }),
            ),
            (
                "minLen 8 is greater than maxLen 4",
                Box::new(|p: &mut TrafficPattern| {
                    p.nonce = Some(NoncePatternProto { min_len: Some(8), max_len: Some(4), ..Default::default() });
                }),
            ),
            (
                "exceeds maximum 12 bytes",
                Box::new(|p: &mut TrafficPattern| {
                    p.nonce = Some(NoncePatternProto {
                        custom_hex_strings: vec!["000102030405060708090a0b0c".to_owned()],
                        ..Default::default()
                    });
                }),
            ),
            (
                "is not a valid hex string",
                Box::new(|p: &mut TrafficPattern| {
                    p.nonce = Some(NoncePatternProto {
                        custom_hex_strings: vec!["not_valid_hex".to_owned()],
                        ..Default::default()
                    });
                }),
            ),
            (
                "maxMiddlePaddingLen 256 exceeds maximum value 255",
                Box::new(|p: &mut TrafficPattern| {
                    p.padding = Some(PaddingPattern { max_middle_padding_len: Some(256), ..Default::default() });
                }),
            ),
            (
                "mode 5 is invalid",
                Box::new(|p: &mut TrafficPattern| {
                    p.low_entropy = Some(LowEntropyPattern { mode: Some(5), mask_rotation: Some(0) });
                }),
            ),
            (
                "maskRotation 17 is invalid",
                Box::new(|p: &mut TrafficPattern| {
                    p.low_entropy = Some(LowEntropyPattern { mode: Some(0), mask_rotation: Some(17) });
                }),
            ),
        ];
        for (expected, mutate) in cases {
            let mut candidate = TrafficPattern::default();
            mutate(&mut candidate);
            let err = validate(Some(&candidate)).expect_err(expected);
            assert!(err.to_string().contains(expected), "got {err}");
        }
    }
}

//!
//! Reflection over `dst` and struct tags at run time has no Rust counterpart, so a target struct
//! describes itself through `serde` attributes instead. The tag is spelled out on the
//! field, `omitempty` becomes an `Option` field or `#[serde(default)]`, an anonymous embedded
//! struct and a `,remain` field both become `#[serde(flatten)]`, and `"-"` becomes `#[serde(skip)]`:
//!
//! ```text
//! #[derive(Deserialize)]
//! struct Proxy {
//!     #[serde(rename = "name")] name: String,
//!     #[serde(rename = "port")] port: u16,
//!     #[serde(rename = "udp", default)] udp: bool,
//! }
//! ```
//!
//! A field decoded through a text unmarshaller implements `Deserialize` with
//! [`TEXT_UNMARSHALER`] as its newtype name; the decoder converts the value to a string first, so
//! weak typing applies to it as well.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::LazyLock;

use serde::de::DeserializeOwned;
use serde_yaml::{Mapping, Value};

/// The newtype-struct name a type passes to `Deserializer::deserialize_newtype_struct` to be
/// decoded through the text-unmarshaller path.
pub const TEXT_UNMARSHALER: &str = "TextUnmarshaler";

/// One module's contribution to [`REQUIRED_FIELDS`]: `(struct identifier, required tag names)`
/// pairs for every decoded struct that has at least one field the tag leaves without
/// `omitempty`.
pub type RequiredFieldsTable = &'static [(&'static str, &'static [&'static str])];

/// Required (non-`omitempty`) tag names per decoded struct, aggregated from
/// `crate::structure::registry::ALL` and keyed by the struct's bare Rust identifier —
/// the same string `#[derive(Deserialize)]` passes as `deserialize_struct`'s `name` argument, and
/// what [`short_type_name`] extracts from `std::any::type_name`. Mirrors
/// the check that rejects a decoded struct left with an unset required field.
static REQUIRED_FIELDS: LazyLock<HashMap<&'static str, &'static [&'static str]>> = LazyLock::new(|| {
    let pairs: Vec<_> = super::registry::ALL.iter().flat_map(|table| table.iter().copied()).collect();
    let map: HashMap<_, _> = pairs.iter().copied().collect();
    debug_assert_eq!(
        map.len(),
        pairs.len(),
        "two required-fields tables registered the same bare struct identifier; rename one or key by module path"
    );
    map
});

fn required_fields_for(name: &str) -> &'static [&'static str] {
    REQUIRED_FIELDS.get(name).copied().unwrap_or(&[])
}

/// Matches the identifier `#[derive(Deserialize)]` passes as `deserialize_struct`'s `name`
/// argument: `std::any::type_name::<T>()` includes the module path and, for a generic type, its
/// parameters; both are stripped here.
fn short_type_name<T: ?Sized>() -> &'static str {
    let full = std::any::type_name::<T>();
    let base = full.split('<').next().unwrap_or(full);
    base.rsplit("::").next().unwrap_or(base)
}

/// Replaces the option's key names; the longest pattern wins at each position.
#[derive(Debug, Clone, Default)]
pub struct KeyReplacer {
    pairs: Vec<(String, String)>,
}

impl KeyReplacer {
    #[must_use]
    pub fn new(oldnew: &[&str]) -> Self {
        let mut pairs: Vec<(String, String)> = Vec::with_capacity(oldnew.len() / 2);
        let mut rest = oldnew;
        while let [old, new, tail @ ..] = rest {
            pairs.push((String::from(*old), String::from(*new)));
            rest = tail;
        }
        pairs.sort_by_key(|pair| Reverse(pair.0.len()));
        Self { pairs }
    }

    #[must_use]
    pub fn replace(&self, text: &str) -> String {
        if self.pairs.is_empty() {
            return text.to_owned();
        }
        let mut replaced = String::with_capacity(text.len());
        let mut index = 0;
        'scan: while index < text.len() {
            let Some(remaining) = text.get(index..) else {
                break;
            };
            for (old, new) in &self.pairs {
                if remaining.starts_with(old.as_str()) {
                    replaced.push_str(new);
                    index += old.len();
                    continue 'scan;
                }
            }
            let Some(character) = remaining.chars().next() else {
                break;
            };
            replaced.push(character);
            index += character.len_utf8();
        }
        replaced
    }
}

/// Replaces `_` with `-`.
pub static DEFAULT_KEY_REPLACER: LazyLock<KeyReplacer> = LazyLock::new(|| KeyReplacer::new(&["_", "-"]));

/// `Option` is the configuration that is used to create a new decoder.
///
/// The name is the and shadows the prelude's `Option` in this module, which is why `key_replacer`
/// spells out `std::option::Option`.
#[derive(Debug, Clone, Default)]
pub struct Option {
    pub tag_name: String,
    pub weakly_typed_input: bool,
    pub key_replacer: std::option::Option<KeyReplacer>,
}

/// `Decoder` is the core of structure.
#[derive(Debug, Clone)]
pub struct Decoder {
    pub(crate) option: Option,
}

/// `new_decoder` returns a `Decoder` by `Option`.
#[must_use]
pub fn new_decoder(option: Option) -> Decoder {
    let mut option = option;
    if option.tag_name.is_empty() {
        "structure".clone_into(&mut option.tag_name);
    }
    Decoder { option }
}

impl Decoder {
    /// `decode` transforms a mapping into a struct.
    ///
    /// A run-time check that `dst` is a pointer is unnecessary here; the decoded value is returned.
    pub fn decode<T: DeserializeOwned>(&self, src: &Mapping) -> anyhow::Result<T> {
        self.decode_source(de::Source::Mapping(src))
    }

    /// `decode_value` is `decode` for a source that is already a `serde_yaml::Value`.
    pub fn decode_value<T: DeserializeOwned>(&self, src: &Value) -> anyhow::Result<T> {
        self.decode_source(de::Source::Value(src))
    }

    fn decode_source<T: DeserializeOwned>(&self, source: de::Source<'_>) -> anyhow::Result<T> {
        if let Err(message) = de::check_required::<T>(&self.option, source) {
            return Err(anyhow::anyhow!(message));
        }
        de::decode(&self.option, source)
    }
}

/// Drops the null-valued keys a `#[serde(flatten)]` target would otherwise be handed as map entries.
///
/// Every field is read through `Decoder::decode`, which returns at once on a null value, so a
/// null field leaves the target at its zero value. A Rust target carrying `#[serde(flatten)]`
/// never reaches `deserialize_struct`: `serde` routes it through `Deserializer::deserialize_map`,
/// which carries the *map* rule that rejects a null value, applied to the target's own fields too.
///
/// This applies only when the target's flattened field is the anonymous embed. A `,remain` map is
/// a real map there, so a null key has to stay a rejected map entry.
#[must_use]
pub fn drop_null_fields(mapping: &Mapping) -> Mapping {
    let mut dropped = Mapping::new();
    for (key, value) in mapping {
        if !value.is_null() {
            dropped.insert(key.clone(), value.clone());
        }
    }
    dropped
}

mod de {
    use std::fmt;

    use serde::de::value::BorrowedStrDeserializer;
    use serde::de::{self, DeserializeOwned, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess, Visitor};
    use serde_yaml::{Mapping, Number, Value};

    #[derive(Debug)]
    pub(super) struct Error(String);

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for Error {}

    impl de::Error for Error {
        fn custom<T: fmt::Display>(msg: T) -> Self {
            Self(msg.to_string())
        }
    }

    fn untagged(value: &Value) -> &Value {
        let mut value = value;
        while let Value::Tagged(tagged) = value {
            value = &tagged.value;
        }
        value
    }

    fn kind_name(value: &Value) -> &'static str {
        match untagged(value) {
            Value::Null => "nil",
            Value::Bool(_) => "bool",
            Value::Number(number) => match number_kind(number) {
                NumKind::Int(_) => "int",
                NumKind::Uint(_) => "uint",
                NumKind::Float(_) => "float64",
            },
            Value::String(_) => "string",
            Value::Sequence(_) => "[]interface {}",
            Value::Mapping(_) => "map[string]interface {}",
            Value::Tagged(_) => "tagged",
        }
    }

    /// The kind of a YAML number: a positive value reports as an `int`, and only the decoder's
    /// weak typing lets a `uint` or a `float64` reach an `int` target.
    enum NumKind {
        Int(i64),
        Uint(u64),
        Float(f64),
    }

    fn number_kind(number: &Number) -> NumKind {
        if number.is_i64() {
            if let Some(value) = number.as_i64() {
                return NumKind::Int(value);
            }
        }
        if number.is_u64() {
            if let Some(value) = number.as_u64() {
                return NumKind::Uint(value);
            }
        }
        NumKind::Float(number.as_f64().unwrap_or(0.0))
    }

    fn join_path(parent: &str, field: &str) -> String {
        if parent.is_empty() {
            field.to_owned()
        } else {
            format!("{parent}.{field}")
        }
    }

    fn object_path(parent: &str, key: &Value) -> String {
        let key = match key {
            Value::String(text) => text.clone(),
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::Sequence(_)
            | Value::Mapping(_)
            | Value::Tagged(_) => format!("{key:?}"),
        };
        format!("{parent}[{key}]")
    }

    fn equal_fold(left: &str, right: &str) -> bool {
        left.eq_ignore_ascii_case(right) || left.to_lowercase() == right.to_lowercase()
    }

    pub(super) fn decode<T: DeserializeOwned>(option: &super::Option, source: Source<'_>) -> anyhow::Result<T> {
        T::deserialize(ValueDeserializer::new(source, String::new(), option)).map_err(anyhow::Error::new)
    }

    /// Validates a top-level decode target's own required fields before `decode` runs.
    ///
    /// `deserialize_struct` performs the equivalent check for every struct it is invoked for, but
    /// a target with a `#[serde(flatten)]` field (the squashed embedded struct) never reaches
    /// `deserialize_struct`: serde routes it through `deserialize_map` instead, which carries
    /// neither the target's name nor its field list. This is the only place that can still enforce
    /// requiredness for such a target, so it is checked here, against the same registry, keyed by
    /// `T`'s own bare identifier via [`super::short_type_name`].
    pub(super) fn check_required<T: ?Sized>(option: &super::Option, source: Source<'_>) -> Result<(), String> {
        let required = super::required_fields_for(super::short_type_name::<T>());
        if required.is_empty() {
            return Ok(());
        }
        let Some(mapping) = source.mapping() else {
            return Ok(());
        };
        let mut missing: Vec<&str> =
            required.iter().copied().filter(|field| lookup_field(mapping, field, option).is_none()).collect();
        if missing.is_empty() {
            return Ok(());
        }
        missing.sort_unstable();
        Err(format!("'' has unset fields: {}", missing.join(", ")))
    }

    /// The value being decoded. The decoder is entered either with a bare `Mapping` or with a
    /// `Value` that already owns one; every nested value is a `Value`.
    #[derive(Clone, Copy)]
    pub(super) enum Source<'de> {
        Value(&'de Value),
        Mapping(&'de Mapping),
    }

    impl<'de> Source<'de> {
        fn mapping(&self) -> Option<&'de Mapping> {
            match *self {
                Self::Mapping(mapping) => Some(mapping),
                Self::Value(value) => match untagged(value) {
                    Value::Mapping(mapping) => Some(mapping),
                    Value::Null
                    | Value::Bool(_)
                    | Value::Number(_)
                    | Value::String(_)
                    | Value::Sequence(_)
                    | Value::Tagged(_) => None,
                },
            }
        }

        fn sequence(&self) -> Option<&'de [Value]> {
            match *self {
                Self::Mapping(_) => None,
                Self::Value(value) => match untagged(value) {
                    Value::Sequence(values) => Some(values.as_slice()),
                    Value::Null
                    | Value::Bool(_)
                    | Value::Number(_)
                    | Value::String(_)
                    | Value::Tagged(_)
                    | Value::Mapping(_) => None,
                },
            }
        }

        fn string(&self) -> Option<&'de str> {
            match *self {
                Self::Mapping(_) => None,
                Self::Value(value) => match untagged(value) {
                    Value::String(text) => Some(text.as_str()),
                    Value::Null
                    | Value::Bool(_)
                    | Value::Number(_)
                    | Value::Sequence(_)
                    | Value::Tagged(_)
                    | Value::Mapping(_) => None,
                },
            }
        }

        fn number(&self) -> Option<&'de Number> {
            match *self {
                Self::Mapping(_) => None,
                Self::Value(value) => match untagged(value) {
                    Value::Number(number) => Some(number),
                    Value::Null
                    | Value::Bool(_)
                    | Value::String(_)
                    | Value::Sequence(_)
                    | Value::Tagged(_)
                    | Value::Mapping(_) => None,
                },
            }
        }

        fn boolean(&self) -> Option<bool> {
            match *self {
                Self::Mapping(_) => None,
                Self::Value(value) => match untagged(value) {
                    Value::Bool(boolean) => Some(*boolean),
                    Value::Null
                    | Value::Number(_)
                    | Value::String(_)
                    | Value::Sequence(_)
                    | Value::Tagged(_)
                    | Value::Mapping(_) => None,
                },
            }
        }

        fn is_null(&self) -> bool {
            matches!(*self, Self::Value(value) if untagged(value).is_null())
        }

        fn kind(&self) -> &'static str {
            match *self {
                Self::Mapping(_) => "map[string]interface {}",
                Self::Value(value) => kind_name(value),
            }
        }
    }

    pub(super) struct ValueDeserializer<'de> {
        source: Source<'de>,
        path: String,
        parent: &'de super::Option,
    }

    impl<'de> ValueDeserializer<'de> {
        pub(super) const fn new(source: Source<'de>, path: String, parent: &'de super::Option) -> Self {
            Self { source, path, parent }
        }

        const fn weak(&self) -> bool {
            self.parent.weakly_typed_input
        }

        fn unconvertible(&self, expected: &str) -> Error {
            Error(format!(
                "'{}' expected type '{expected}', got unconvertible type '{}'",
                self.path,
                self.source.kind()
            ))
        }

        fn null_error(&self) -> Error {
            Error(format!("'{}' can not be null", self.path))
        }

        #[expect(
            clippy::cast_possible_truncation,
            reason = "a weakly typed float truncates toward zero, as this conversion does"
        )]
        fn int_value(&self) -> Result<i64, Error> {
            match self.source.number() {
                Some(number) => match number_kind(number) {
                    NumKind::Int(value) => Ok(value),
                    NumKind::Uint(value) if self.weak() => Ok(value.cast_signed()),
                    NumKind::Float(value) if self.weak() => Ok(value as i64),
                    NumKind::Uint(_) | NumKind::Float(_) => Err(self.unconvertible("int64")),
                },
                None => match self.source.string() {
                    Some(text) if self.weak() => {
                        parse_int(text, 64).map_err(|err| Error(format!("cannot parse '{}' as int: {err}", self.path)))
                    }
                    None | Some(_) => Err(self.unconvertible("int64")),
                },
            }
        }

        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a weakly typed float truncates toward zero and drops its sign, as this conversion does"
        )]
        fn uint_value(&self) -> Result<u64, Error> {
            match self.source.number() {
                Some(number) => match number_kind(number) {
                    NumKind::Uint(value) => Ok(value),
                    NumKind::Int(value) if self.weak() => Ok(value.cast_unsigned()),
                    NumKind::Float(value) if self.weak() => Ok(value as u64),
                    NumKind::Int(_) | NumKind::Float(_) => Err(self.unconvertible("uint64")),
                },
                None => match self.source.string() {
                    Some(text) if self.weak() => {
                        parse_uint(text, 64).map_err(|err| Error(format!("cannot parse '{}' as int: {err}", self.path)))
                    }
                    None | Some(_) => Err(self.unconvertible("uint64")),
                },
            }
        }

        #[expect(
            clippy::cast_precision_loss,
            reason = "the conversion widens a 64-bit integer to a float, which rounds"
        )]
        fn float_value(&self) -> Result<f64, Error> {
            match self.source.number() {
                Some(number) => match number_kind(number) {
                    NumKind::Float(value) => Ok(value),
                    // A uint converts to a float even without weak typing.
                    NumKind::Uint(value) => Ok(value as f64),
                    NumKind::Int(value) if self.weak() => Ok(value as f64),
                    NumKind::Int(_) => Err(self.unconvertible("float64")),
                },
                None => match self.source.string() {
                    Some(text) if self.weak() => {
                        text.parse::<f64>().map_err(|err| Error(format!("cannot parse '{}' as int: {err}", self.path)))
                    }
                    None | Some(_) => Err(self.unconvertible("float64")),
                },
            }
        }

        fn bool_value(&self) -> Result<bool, Error> {
            if let Some(value) = self.source.boolean() {
                return Ok(value);
            }
            if self.weak() {
                match self.source.number().map(number_kind) {
                    Some(NumKind::Int(value)) => return Ok(value != 0),
                    Some(NumKind::Uint(value)) => return Ok(value != 0),
                    Some(NumKind::Float(_)) | None => {}
                }
            }
            Err(self.unconvertible("bool"))
        }

        fn string_value(&self) -> Result<String, Error> {
            if let Some(text) = self.source.string() {
                return Ok(text.to_owned());
            }
            if self.weak() {
                if let Some(number) = self.source.number() {
                    return Ok(match number_kind(number) {
                        NumKind::Int(value) => value.to_string(),
                        NumKind::Uint(value) => value.to_string(),
                        NumKind::Float(value) => format_float_e(value),
                    });
                }
            }
            Err(self.unconvertible("string"))
        }

        fn base64_bytes(&self) -> Result<Vec<u8>, Error> {
            use base64::Engine as _;

            let text = self.source.string().unwrap_or_default();
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .map_err(|err| Error(format!("try decode '{}' by base64 error: {err}", self.path)))
        }

        fn zero_sequence<V: Visitor<'de>>(&self, visitor: V) -> Result<V::Value, Error> {
            let empty: &[Value] = &[];
            visitor.visit_seq(SeqValues { iter: empty.iter(), path: self.path.clone(), parent: self.parent, index: 0 })
        }

        fn zero_mapping<V: Visitor<'de>>(&self, visitor: V) -> Result<V::Value, Error> {
            visitor.visit_map(MappingAccess {
                iter: None,
                pending: None,
                path: self.path.clone(),
                parent: self.parent,
                reject_null: false,
            })
        }
    }

    /// Parses a signed integer of `bits` bits, base prefixes included.
    fn parse_int(text: &str, bits: u32) -> Result<i64, String> {
        let (negative, magnitude) = parse_magnitude(text)?;
        let limit = if negative {
            if bits >= 64 {
                1u64 << 63
            } else {
                1u64 << (bits - 1)
            }
        } else if bits >= 64 {
            i64::MAX.cast_unsigned()
        } else {
            (1u64 << (bits - 1)) - 1
        };
        if magnitude > limit {
            return Err("value out of range".to_owned());
        }
        Ok(if negative { magnitude.cast_signed().wrapping_neg() } else { magnitude.cast_signed() })
    }

    /// Parses an unsigned integer of `bits` bits, base prefixes included.
    fn parse_uint(text: &str, bits: u32) -> Result<u64, String> {
        let (negative, magnitude) = parse_magnitude(text)?;
        if negative {
            return Err("invalid syntax".to_owned());
        }
        let limit = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        if magnitude > limit {
            return Err("value out of range".to_owned());
        }
        Ok(magnitude)
    }

    fn parse_magnitude(text: &str) -> Result<(bool, u64), String> {
        let mut rest = text;
        let mut negative = false;
        if let Some(stripped) = rest.strip_prefix('+') {
            rest = stripped;
        } else if let Some(stripped) = rest.strip_prefix('-') {
            negative = true;
            rest = stripped;
        }

        let (radix, digits) = if let Some(stripped) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            (16, stripped)
        } else if let Some(stripped) = rest.strip_prefix("0o").or_else(|| rest.strip_prefix("0O")) {
            (8, stripped)
        } else if let Some(stripped) = rest.strip_prefix("0b").or_else(|| rest.strip_prefix("0B")) {
            (2, stripped)
        } else if rest.len() > 1 && rest.starts_with('0') {
            (8, rest.get(1..).unwrap_or_default())
        } else {
            (10, rest)
        };
        if digits.is_empty() {
            return Err("invalid syntax".to_owned());
        }

        let mut magnitude = 0u64;
        let mut digit_before = false;
        for character in digits.chars() {
            if character == '_' {
                if !digit_before {
                    return Err("invalid syntax".to_owned());
                }
                digit_before = false;
                continue;
            }
            let Some(digit) = character.to_digit(radix) else {
                return Err("invalid syntax".to_owned());
            };
            magnitude = magnitude
                .checked_mul(u64::from(radix))
                .and_then(|value| value.checked_add(u64::from(digit)))
                .ok_or_else(|| "value out of range".to_owned())?;
            digit_before = true;
        }
        if !digit_before {
            return Err("invalid syntax".to_owned());
        }
        Ok((negative, magnitude))
    }

    /// Formats a float in scientific notation, whose exponent is signed and at least two digits
    /// wide.
    fn format_float_e(value: f64) -> String {
        let formatted = format!("{value:E}");
        let Some((mantissa, exponent)) = formatted.split_once('E') else {
            return formatted;
        };
        let (sign, digits) = match exponent.strip_prefix('-') {
            Some(digits) => ('-', digits),
            None => ('+', exponent),
        };
        format!("{mantissa}E{sign}{digits:0>2}")
    }

    struct SeqValues<'de> {
        iter: std::slice::Iter<'de, Value>,
        path: String,
        parent: &'de super::Option,
        index: usize,
    }

    impl<'de> SeqAccess<'de> for SeqValues<'de> {
        type Error = Error;

        fn next_element_seed<E: DeserializeSeed<'de>>(&mut self, seed: E) -> Result<Option<E::Value>, Error> {
            let Some(value) = self.iter.next() else {
                return Ok(None);
            };
            let path = format!("{}[{}]", self.path, self.index);
            self.index += 1;
            seed.deserialize(ValueDeserializer::new(Source::Value(value), path, self.parent)).map(Some)
        }
    }

    /// Elements of a base64 decoded byte array.
    struct ByteValues {
        bytes: Vec<u8>,
        index: usize,
    }

    impl<'de> SeqAccess<'de> for ByteValues {
        type Error = Error;

        fn next_element_seed<E: DeserializeSeed<'de>>(&mut self, seed: E) -> Result<Option<E::Value>, Error> {
            let Some(byte) = self.bytes.get(self.index).copied() else {
                return Ok(None);
            };
            self.index += 1;
            seed.deserialize(byte.into_deserializer()).map(Some)
        }
    }

    struct MappingAccess<'de> {
        iter: Option<serde_yaml::mapping::Iter<'de>>,
        pending: Option<(&'de Value, String)>,
        path: String,
        parent: &'de super::Option,
        reject_null: bool,
    }

    impl<'de> MapAccess<'de> for MappingAccess<'de> {
        type Error = Error;

        fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, Error> {
            let Some(iter) = self.iter.as_mut() else {
                return Ok(None);
            };
            let Some((key, value)) = iter.next() else {
                return Ok(None);
            };
            let path = object_path(&self.path, key);
            self.pending = Some((value, path.clone()));
            seed.deserialize(ValueDeserializer::new(Source::Value(key), path, self.parent)).map(Some)
        }

        fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
            let Some((value, path)) = self.pending.take() else {
                return Err(Error("map value requested without a key".to_owned()));
            };
            if self.reject_null && value.is_null() {
                return Err(Error(format!("filed {path} invalid")));
            }
            seed.deserialize(ValueDeserializer::new(Source::Value(value), path, self.parent))
        }
    }

    struct FieldsAccess<'de> {
        entries: Vec<(&'static str, &'de Value)>,
        index: usize,
        path: String,
        parent: &'de super::Option,
    }

    impl<'de> MapAccess<'de> for FieldsAccess<'de> {
        type Error = Error;

        fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, Error> {
            let Some((field, _)) = self.entries.get(self.index) else {
                return Ok(None);
            };
            self.index += 1;
            seed.deserialize(BorrowedStrDeserializer::<Error>::new(field)).map(Some)
        }

        fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
            let Some((field, value)) = self.entries.get(self.index - 1) else {
                return Err(Error("struct value requested without a field".to_owned()));
            };
            let path = join_path(&self.path, field);
            seed.deserialize(ValueDeserializer::new(Source::Value(value), path, self.parent))
        }
    }

    /// Looks a field up by its exact name first and then falls back to a
    /// case-insensitive search over the replaced key names.
    fn lookup_field<'de>(mapping: &'de Mapping, field: &str, option: &super::Option) -> Option<&'de Value> {
        if let Some(value) = mapping.get(field) {
            return Some(value);
        }
        let field_name = match &option.key_replacer {
            Some(replacer) => replacer.replace(field),
            None => field.to_owned(),
        };
        for (key, value) in mapping {
            let Some(key) = key.as_str() else {
                continue;
            };
            let key = match &option.key_replacer {
                Some(replacer) => replacer.replace(key),
                None => key.to_owned(),
            };
            if equal_fold(&key, &field_name) {
                return Some(value);
            }
        }
        None
    }

    impl<'de> de::Deserializer<'de> for ValueDeserializer<'de> {
        type Error = Error;

        fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_unit() } else { Err(self.null_error()) };
            }
            if let Some(text) = self.source.string() {
                return visitor.visit_str(text);
            }
            if let Some(boolean) = self.source.boolean() {
                return visitor.visit_bool(boolean);
            }
            if let Some(number) = self.source.number() {
                return match number_kind(number) {
                    NumKind::Int(value) => visitor.visit_i64(value),
                    NumKind::Uint(value) => visitor.visit_u64(value),
                    NumKind::Float(value) => visitor.visit_f64(value),
                };
            }
            if let Some(values) = self.source.sequence() {
                return visitor.visit_seq(SeqValues {
                    iter: values.iter(),
                    path: self.path,
                    parent: self.parent,
                    index: 0,
                });
            }
            match self.source.mapping() {
                Some(mapping) => visitor.visit_map(MappingAccess {
                    iter: Some(mapping.iter()),
                    pending: None,
                    path: self.path,
                    parent: self.parent,
                    reject_null: false,
                }),
                None => Err(self.unconvertible("any")),
            }
        }

        fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_bool(false) } else { Err(self.null_error()) };
            }
            let value = self.bool_value()?;
            visitor.visit_bool(value)
        }

        fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_i8(0) } else { Err(self.null_error()) };
            }
            let value = i8::try_from(self.int_value()?).map_err(|_| self.unconvertible("int8"))?;
            visitor.visit_i8(value)
        }

        fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_i16(0) } else { Err(self.null_error()) };
            }
            let value = i16::try_from(self.int_value()?).map_err(|_| self.unconvertible("int16"))?;
            visitor.visit_i16(value)
        }

        fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_i32(0) } else { Err(self.null_error()) };
            }
            let value = i32::try_from(self.int_value()?).map_err(|_| self.unconvertible("int32"))?;
            visitor.visit_i32(value)
        }

        fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_i64(0) } else { Err(self.null_error()) };
            }
            let value = self.int_value()?;
            visitor.visit_i64(value)
        }

        fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_u8(0) } else { Err(self.null_error()) };
            }
            let value = u8::try_from(self.uint_value()?).map_err(|_| self.unconvertible("uint8"))?;
            visitor.visit_u8(value)
        }

        fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_u16(0) } else { Err(self.null_error()) };
            }
            let value = u16::try_from(self.uint_value()?).map_err(|_| self.unconvertible("uint16"))?;
            visitor.visit_u16(value)
        }

        fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_u32(0) } else { Err(self.null_error()) };
            }
            let value = u32::try_from(self.uint_value()?).map_err(|_| self.unconvertible("uint32"))?;
            visitor.visit_u32(value)
        }

        fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_u64(0) } else { Err(self.null_error()) };
            }
            let value = self.uint_value()?;
            visitor.visit_u64(value)
        }

        #[expect(
            clippy::cast_possible_truncation,
            reason = "the decoded target is `f32`, so the value narrows by definition"
        )]
        fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_f32(0.0) } else { Err(self.null_error()) };
            }
            let value = self.float_value()?;
            visitor.visit_f32(value as f32)
        }

        fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_f64(0.0) } else { Err(self.null_error()) };
            }
            let value = self.float_value()?;
            visitor.visit_f64(value)
        }

        fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_char('\0') } else { Err(self.null_error()) };
            }
            let text = self.string_value()?;
            let mut characters = text.chars();
            let Some(character) = characters.next() else {
                return Err(self.unconvertible("char"));
            };
            if characters.next().is_some() {
                return Err(self.unconvertible("char"));
            }
            visitor.visit_char(character)
        }

        fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_str("") } else { Err(self.null_error()) };
            }
            let value = self.string_value()?;
            visitor.visit_str(&value)
        }

        fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_string(String::new()) } else { Err(self.null_error()) };
            }
            let value = self.string_value()?;
            visitor.visit_string(value)
        }

        fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_bytes(&[]) } else { Err(self.null_error()) };
            }
            if self.source.string().is_some() {
                let bytes = self.base64_bytes()?;
                return visitor.visit_bytes(&bytes);
            }
            self.deserialize_seq(visitor)
        }

        fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_byte_buf(Vec::new()) } else { Err(self.null_error()) };
            }
            if self.source.string().is_some() {
                let bytes = self.base64_bytes()?;
                return visitor.visit_byte_buf(bytes);
            }
            self.deserialize_seq(visitor)
        }

        fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return visitor.visit_none();
            }
            visitor.visit_some(self)
        }

        fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return visitor.visit_unit();
            }
            self.deserialize_any(visitor)
        }

        fn deserialize_unit_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V) -> Result<V::Value, Error> {
            self.deserialize_unit(visitor)
        }

        fn deserialize_newtype_struct<V: Visitor<'de>>(
            self,
            name: &'static str,
            visitor: V,
        ) -> Result<V::Value, Error> {
            if name == super::TEXT_UNMARSHALER {
                if self.source.is_null() {
                    return if self.weak() { visitor.visit_str("") } else { Err(self.null_error()) };
                }
                let text = self.string_value()?;
                return visitor
                    .visit_str::<Error>(&text)
                    .map_err(|err| Error(format!("cannot parse '{}' as text: {err}", self.path)));
            }
            visitor.visit_newtype_struct(self)
        }

        fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return self.zero_sequence(visitor);
            }
            if self.source.string().is_some() {
                // A byte array arrives base64 encoded from a string.
                let bytes = self.base64_bytes()?;
                return visitor.visit_seq(ByteValues { bytes, index: 0 });
            }
            let Some(values) = self.source.sequence() else {
                return Err(Error(format!("'{}' is not a slice", self.path)));
            };
            visitor.visit_seq(SeqValues { iter: values.iter(), path: self.path, parent: self.parent, index: 0 })
        }

        fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, Error> {
            self.deserialize_seq(visitor)
        }

        fn deserialize_tuple_struct<V: Visitor<'de>>(
            self,
            _name: &'static str,
            _len: usize,
            visitor: V,
        ) -> Result<V::Value, Error> {
            self.deserialize_seq(visitor)
        }

        fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return self.zero_mapping(visitor);
            }
            let Some(mapping) = self.source.mapping() else {
                return Err(Error(format!("'{}' expected a map, got '{}'", self.path, self.source.kind())));
            };
            visitor.visit_map(MappingAccess {
                iter: Some(mapping.iter()),
                pending: None,
                path: self.path,
                parent: self.parent,
                reject_null: true,
            })
        }

        fn deserialize_struct<V: Visitor<'de>>(
            self,
            name: &'static str,
            fields: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { self.zero_mapping(visitor) } else { Err(self.null_error()) };
            }
            let Some(mapping) = self.source.mapping() else {
                return Err(Error(format!("'{}' expected a map, got '{}'", self.path, self.source.kind())));
            };

            let required = super::required_fields_for(name);
            let mut entries = Vec::with_capacity(fields.len());
            let mut unset: Vec<&'static str> = Vec::new();
            for field in fields {
                match lookup_field(mapping, field, self.parent) {
                    Some(value) => {
                        // A null value leaves the target field untouched, so the Rust field keeps its
                        // default; the key's presence still counts as "set" either way.
                        if !value.is_null() {
                            entries.push((*field, value));
                        }
                    }
                    None => {
                        if required.contains(field) {
                            unset.push(field);
                        }
                    }
                }
            }

            if unset.is_empty() {
                return visitor.visit_map(FieldsAccess { entries, index: 0, path: self.path, parent: self.parent });
            }
            let path = self.path.clone();
            let decoded = visitor.visit_map(FieldsAccess { entries, index: 0, path: self.path, parent: self.parent });
            unset.sort_unstable();
            let unset_error = format!("'{path}' has unset fields: {}", unset.join(", "));
            match decoded {
                Ok(_) => Err(Error(unset_error)),
                Err(err) => Err(Error(format!("{err},{unset_error}"))),
            }
        }

        fn deserialize_enum<V: Visitor<'de>>(
            self,
            _name: &'static str,
            _variants: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, Error> {
            if self.source.is_null() {
                return if self.weak() { visitor.visit_str("") } else { Err(self.null_error()) };
            }
            let Some(variant) = self.source.string() else {
                return Err(self.unconvertible("string"));
            };
            let access: UnitEnumAccess<'de, Error> = UnitEnumAccess { variant, _error: std::marker::PhantomData };
            visitor.visit_enum(access)
        }

        fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            self.deserialize_any(visitor)
        }

        fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            visitor.visit_unit()
        }
    }

    /// A string decodes into a named string type directly; a Rust enum takes unit variants from
    /// a string the same way.
    struct UnitEnumAccess<'de, E> {
        variant: &'de str,
        _error: std::marker::PhantomData<E>,
    }

    impl<'de, E: de::Error> de::EnumAccess<'de> for UnitEnumAccess<'de, E> {
        type Error = E;
        type Variant = UnitVariantAccess<E>;

        fn variant_seed<K: DeserializeSeed<'de>>(self, seed: K) -> Result<(K::Value, Self::Variant), E> {
            let variant = seed.deserialize(BorrowedStrDeserializer::<E>::new(self.variant))?;
            Ok((variant, UnitVariantAccess { _error: std::marker::PhantomData }))
        }
    }

    struct UnitVariantAccess<E> {
        _error: std::marker::PhantomData<E>,
    }

    impl<'de, E: de::Error> de::VariantAccess<'de> for UnitVariantAccess<E> {
        type Error = E;

        fn unit_variant(self) -> Result<(), E> {
            Ok(())
        }

        fn newtype_variant_seed<K: DeserializeSeed<'de>>(self, _seed: K) -> Result<K::Value, E> {
            Err(de::Error::invalid_type(de::Unexpected::UnitVariant, &"newtype variant"))
        }

        fn tuple_variant<V: Visitor<'de>>(self, _len: usize, _visitor: V) -> Result<V::Value, E> {
            Err(de::Error::invalid_type(de::Unexpected::UnitVariant, &"tuple variant"))
        }

        fn struct_variant<V: Visitor<'de>>(self, _fields: &'static [&'static str], _visitor: V) -> Result<V::Value, E> {
            Err(de::Error::invalid_type(de::Unexpected::UnitVariant, &"struct variant"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fmt;

    use serde::Deserialize;
    use serde_yaml::Number;

    use super::*;
    // `super::*` brings the decoder's `Option` into scope, so the prelude one is named explicitly.
    use std::option::Option;

    fn int(value: i64) -> Value {
        Value::Number(Number::from(value))
    }

    fn text(value: &str) -> Value {
        Value::String(value.to_owned())
    }

    fn mapping(entries: Vec<(&str, Value)>) -> Mapping {
        let mut mapping = Mapping::new();
        for (key, value) in entries {
            mapping.insert(text(key), value);
        }
        mapping
    }

    fn sequence(values: Vec<Value>) -> Value {
        Value::Sequence(values)
    }

    fn decoder() -> Decoder {
        new_decoder(super::Option { tag_name: "test".to_owned(), ..Default::default() })
    }

    fn weak_decoder() -> Decoder {
        new_decoder(super::Option { tag_name: "test".to_owned(), weakly_typed_input: true, ..Default::default() })
    }

    fn replacing_decoder() -> Decoder {
        new_decoder(super::Option {
            tag_name: "test".to_owned(),
            weakly_typed_input: true,
            key_replacer: Some(KeyReplacer::new(&["_", "-"])),
        })
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Baz {
        #[serde(rename = "foo")]
        foo: i32,
        #[serde(rename = "bar")]
        bar: String,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct BazSlice {
        #[serde(rename = "foo")]
        foo: i32,
        #[serde(rename = "bar")]
        bar: Vec<String>,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct BazOptional {
        #[serde(rename = "foo")]
        foo: i32,
        #[serde(rename = "bar", default)]
        bar: String,
    }

    #[test]
    fn basic() {
        let raw = mapping(vec![("foo", int(1)), ("bar", text("test")), ("extra", Value::Bool(false))]);
        let decoded: Baz = decoder().decode(&raw).expect("decode");
        assert_eq!(Baz { foo: 1, bar: "test".to_owned() }, decoded);
    }

    #[test]
    fn slice() {
        let raw = mapping(vec![("foo", int(1)), ("bar", sequence(vec![text("one"), text("two")]))]);
        let decoded: BazSlice = decoder().decode(&raw).expect("decode");
        assert_eq!(BazSlice { foo: 1, bar: vec!["one".to_owned(), "two".to_owned()] }, decoded);
    }

    #[test]
    fn optional() {
        let raw = mapping(vec![("foo", int(1))]);
        let decoded: BazOptional = decoder().decode(&raw).expect("decode");
        assert_eq!(BazOptional { foo: 1, bar: String::new() }, decoded);
    }

    #[test]
    fn missing_key() {
        let raw = mapping(vec![("foo", int(1))]);
        let decoded: Result<Baz, _> = decoder().decode(&raw);
        assert!(decoded.is_err(), "should throw error");
    }

    #[test]
    fn slice_type_error() {
        let raw = mapping(vec![("foo", int(1)), ("bar", sequence(vec![int(1), int(2)]))]);
        let decoded: Result<BazSlice, _> = decoder().decode(&raw);
        assert!(decoded.is_err(), "should throw error");
    }

    #[test]
    fn weak_type() {
        let raw = mapping(vec![("foo", text("1")), ("bar", sequence(vec![int(1)]))]);
        let decoded: BazSlice = weak_decoder().decode(&raw).expect("decode");
        assert_eq!(BazSlice { foo: 1, bar: vec!["1".to_owned()] }, decoded);
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct DashedKeys {
        #[serde(rename = "skip-cert-verify", default)]
        skip_cert_verify: bool,
    }

    #[test]
    fn key_replacer() {
        let raw = mapping(vec![("skip_cert_verify", Value::Bool(true))]);
        let decoded: DashedKeys = replacing_decoder().decode(&raw).expect("decode");
        assert!(decoded.skip_cert_verify);

        let raw = mapping(vec![("FOO", int(1)), ("Bar", text("test"))]);
        let decoded: Baz = replacing_decoder().decode(&raw).expect("decode");
        assert_eq!(Baz { foo: 1, bar: "test".to_owned() }, decoded);
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Nest {
        #[serde(flatten)]
        baz_optional: BazOptional,
    }

    #[test]
    fn nest() {
        let raw = mapping(vec![("foo", int(1))]);
        let decoded: Nest = decoder().decode(&raw).expect("decode");
        assert_eq!(BazOptional { foo: 1, bar: String::new() }, decoded.baz_optional);
    }

    #[test]
    fn a_nil_field_of_a_flattened_target_is_dropped_before_the_decode() {
        let raw = mapping(vec![("foo", int(1)), ("bar", Value::Null)]);

        let err = decoder().decode::<Nest>(&raw).unwrap_err();
        assert!(err.to_string().contains("bar"), "{err}");

        let decoded: Nest = decoder().decode(&drop_null_fields(&raw)).expect("decode");
        assert_eq!(BazOptional { foo: 1, bar: String::new() }, decoded.baz_optional);
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Inner {
        #[serde(flatten)]
        baz_optional: BazOptional,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct DoubleNest {
        #[serde(rename = "bar")]
        bar: Inner,
    }

    #[test]
    fn double_nest() {
        let raw = mapping(vec![("bar", Value::Mapping(mapping(vec![("foo", int(1))])))]);
        let decoded: DoubleNest = decoder().decode(&raw).expect("decode");
        assert_eq!(BazOptional { foo: 1, bar: String::new() }, decoded.bar.baz_optional);
    }

    #[derive(Debug, Deserialize)]
    struct Remain {
        #[serde(rename = "foo")]
        foo: i32,
        #[serde(rename = "bar")]
        bar: String,
        #[serde(flatten)]
        remain: HashMap<String, Value>,
    }

    #[test]
    fn remain() {
        let raw = mapping(vec![("foo", int(1)), ("bar", text("test")), ("extra", Value::Bool(false))]);
        let decoded: Remain = decoder().decode(&raw).expect("decode");
        assert_eq!(1, decoded.foo);
        assert_eq!("test", decoded.bar);
        assert_eq!(1, decoded.remain.len());
        assert_eq!(Some(&Value::Bool(false)), decoded.remain.get("extra"));
    }

    #[test]
    fn slice_nil_value() {
        let raw = mapping(vec![("foo", int(1)), ("bar", sequence(vec![text("bar"), Value::Null]))]);

        let decoded: BazSlice = weak_decoder().decode(&raw).expect("decode");
        assert_eq!(vec!["bar".to_owned(), String::new()], decoded.bar);

        let decoded: Result<BazSlice, _> = decoder().decode(&raw);
        assert!(decoded.is_err(), "should throw error");
    }

    #[derive(Debug, Deserialize)]
    struct MapSlice {
        #[serde(rename = "bar")]
        bar: Vec<HashMap<String, Value>>,
    }

    #[derive(Debug, Deserialize)]
    struct BazSliceStruct {
        #[serde(rename = "bar")]
        _bar: Vec<Baz>,
    }

    #[test]
    fn slice_nil_value_complex() {
        let raw =
            mapping(vec![("bar", sequence(vec![Value::Mapping(mapping(vec![("bar", text("foo"))])), Value::Null]))]);

        let decoded: MapSlice = decoder().decode(&raw).expect("decode");
        assert_eq!(2, decoded.bar.len());
        assert_eq!(Some(&text("foo")), decoded.bar[0].get("bar"));
        // The null element becomes an empty map here; a null map has no Rust counterpart.
        assert!(decoded.bar[1].is_empty());

        let decoded: Result<BazSliceStruct, _> = decoder().decode(&raw);
        assert!(decoded.is_err(), "should throw error");
    }

    #[derive(Debug, Deserialize)]
    struct SliceCap {
        #[serde(rename = "foo")]
        foo: Option<Vec<String>>,
        #[serde(rename = "bar")]
        bar: Option<Vec<String>>,
    }

    #[test]
    fn slice_cap() {
        let raw = mapping(vec![("foo", sequence(Vec::new()))]);
        let decoded: SliceCap = decoder().decode(&raw).expect("decode");
        // Decoding ensures the value is not null when the input holds an empty array; a
        // missing key stays null.
        assert_eq!(Some(Vec::new()), decoded.foo);
        assert_eq!(None, decoded.bar);
    }

    #[derive(Debug, Deserialize)]
    struct ByteField {
        #[serde(rename = "foo")]
        foo: Vec<u8>,
    }

    #[test]
    fn base64() {
        let raw = mapping(vec![("foo", text("AQID"))]);
        let decoded: ByteField = decoder().decode(&raw).expect("decode");
        assert_eq!(vec![1, 2, 3], decoded.foo);
    }

    #[derive(Debug, Deserialize)]
    struct Pointers {
        #[serde(rename = "foo")]
        foo: Option<String>,
        #[serde(rename = "bar")]
        bar: Option<String>,
    }

    #[test]
    fn pointer() {
        let raw = mapping(vec![("foo", text("foo"))]);
        let decoded: Pointers = decoder().decode(&raw).expect("decode");
        assert_eq!(Some("foo".to_owned()), decoded.foo);
        assert_eq!(None, decoded.bar);
    }

    #[derive(Debug, Deserialize)]
    struct PointerStructs {
        #[serde(rename = "foo")]
        foo: Option<String>,
        #[serde(rename = "bar")]
        bar: Option<Baz>,
    }

    #[test]
    fn pointer_struct() {
        let raw = mapping(vec![("foo", text("foo"))]);
        let decoded: PointerStructs = decoder().decode(&raw).expect("decode");
        assert_eq!(Some("foo".to_owned()), decoded.foo);
        assert_eq!(None, decoded.bar);
    }

    /// A numeric type decoded through a text unmarshaller.
    #[derive(Debug, PartialEq)]
    struct Num {
        a: i32,
    }

    impl<'de> Deserialize<'de> for Num {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct NumVisitor;

            impl<'de> serde::de::Visitor<'de> for NumVisitor {
                type Value = Num;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("a number written as text")
                }

                fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Num, E> {
                    text.parse::<i32>().map(|a| Num { a }).map_err(E::custom)
                }
            }

            deserializer.deserialize_newtype_struct(TEXT_UNMARSHALER, NumVisitor)
        }
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct NumFields {
        #[serde(rename = "num")]
        num: Num,
        #[serde(rename = "num_p")]
        num_p: Option<Num>,
        #[serde(rename = "num_arr")]
        num_arr: Vec<Num>,
    }

    #[test]
    fn text_unmarshaller() {
        let mut raw = mapping(vec![
            ("num", text("255")),
            ("num_p", text("127")),
            ("num_arr", sequence(vec![text("1"), text("2"), text("3")])),
        ]);

        let decoded: NumFields = decoder().decode(&raw).expect("decode");
        assert_eq!(255, decoded.num.a);
        assert_eq!(Some(Num { a: 127 }), decoded.num_p);
        assert_eq!(vec![Num { a: 1 }, Num { a: 2 }, Num { a: 3 }], decoded.num_arr);

        raw.insert(text("num"), int(256));
        let decoded: Result<NumFields, _> = decoder().decode(&raw);
        assert!(decoded.is_err(), "should throw error");

        let decoded: NumFields = weak_decoder().decode(&raw).expect("decode");
        assert_eq!(256, decoded.num.a);

        raw.insert(text("num_p"), text("abc"));
        let decoded: Result<NumFields, _> = decoder().decode(&raw);
        assert!(decoded.is_err(), "should throw error");
    }

    #[derive(Debug, Deserialize)]
    struct OptInner {
        #[serde(rename = "bar", default)]
        bar: String,
    }

    #[derive(Debug, Deserialize)]
    struct WithOpt {
        #[serde(rename = "opt")]
        opt: OptInner,
    }

    #[test]
    fn null() {
        let raw = mapping(vec![("opt", Value::Mapping(mapping(vec![("bar", Value::Null)])))]);
        let decoded: WithOpt = decoder().decode(&raw).expect("decode");
        assert_eq!("", decoded.opt.bar);
    }

    #[derive(Debug, Deserialize)]
    struct HeaderMap {
        #[serde(rename = "headers")]
        _headers: HashMap<String, String>,
    }

    #[test]
    fn a_nil_map_entry_is_rejected() {
        let raw = mapping(vec![("headers", Value::Mapping(mapping(vec![("X-Token", Value::Null)])))]);
        let err = decoder().decode::<HeaderMap>(&raw).unwrap_err();
        assert!(err.to_string().contains("X-Token"), "{err}");
    }

    #[derive(Debug, Deserialize)]
    struct Ignore {
        #[serde(skip)]
        must_ignore: String,
    }

    #[test]
    fn ignore() {
        // Decoding into an existing struct would leave the old value in place on a skipped key; this
        // builds a fresh value, which is why only the default can be observed.
        let raw = mapping(vec![("-", text("newData"))]);
        let decoded: Ignore = decoder().decode(&raw).expect("decode");
        assert_eq!("", decoded.must_ignore);

        let raw = mapping(Vec::new());
        let decoded: Ignore = decoder().decode(&raw).expect("decode");
        assert_eq!("", decoded.must_ignore);
    }

    #[derive(Debug, Deserialize)]
    struct Tp {
        #[serde(skip)]
        must_ignore: String,
    }

    #[derive(Debug, Deserialize)]
    struct IgnoreInNest {
        #[serde(flatten)]
        tp: Tp,
    }

    #[test]
    fn ignore_in_nest() {
        let raw = mapping(vec![("-", text("newData"))]);
        let decoded: IgnoreInNest = decoder().decode(&raw).expect("decode");
        assert_eq!("", decoded.tp.must_ignore);

        let raw = mapping(Vec::new());
        let decoded: IgnoreInNest = decoder().decode(&raw).expect("decode");
        assert_eq!("", decoded.tp.must_ignore);
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct RequiredDemo {
        #[serde(rename = "certificate", default)]
        certificate: String,
        #[serde(rename = "nickname", default)]
        nickname: String,
    }

    #[test]
    fn required_field_present_decodes() {
        let raw = mapping(vec![("certificate", text("a")), ("nickname", text("b"))]);
        let decoded: RequiredDemo = decoder().decode(&raw).expect("decode");
        assert_eq!(RequiredDemo { certificate: "a".to_owned(), nickname: "b".to_owned() }, decoded);
    }

    #[test]
    fn required_field_missing_message() {
        let raw = mapping(vec![("nickname", text("b"))]);
        let err = decoder().decode::<RequiredDemo>(&raw).expect_err("should fail");
        assert_eq!("'' has unset fields: certificate", err.to_string());
    }

    #[test]
    fn omitempty_field_missing_decodes() {
        let raw = mapping(vec![("certificate", text("a"))]);
        let decoded: RequiredDemo = decoder().decode(&raw).expect("decode");
        assert_eq!(RequiredDemo { certificate: "a".to_owned(), nickname: String::new() }, decoded);
    }

    #[derive(Debug, Deserialize)]
    #[allow(
        dead_code,
        reason = "fields populated only via decode(); tests assert on the resulting error, not the fields"
    )]
    struct RequiredDemoParent {
        #[serde(rename = "inner", default)]
        inner: Option<RequiredDemo>,
    }

    #[test]
    fn required_field_missing_in_nested_struct_reports_the_field_path() {
        let raw = mapping(vec![("inner", Value::Mapping(mapping(vec![("nickname", text("b"))])))]);
        let err = decoder().decode::<RequiredDemoParent>(&raw).expect_err("should fail");
        assert_eq!("'inner' has unset fields: certificate", err.to_string());
    }

    #[derive(Debug, Deserialize)]
    #[allow(
        dead_code,
        reason = "fields populated only via decode(); tests assert on the resulting error, not the fields"
    )]
    struct RequiredDemoFlatten {
        #[serde(flatten)]
        inner: RequiredDemo,
    }

    #[test]
    fn required_field_missing_on_a_flattened_target_message() {
        let raw = mapping(vec![("nickname", text("b"))]);
        let err = decoder().decode::<RequiredDemoFlatten>(&raw).expect_err("should fail");
        assert_eq!("'' has unset fields: certificate", err.to_string());
    }
}

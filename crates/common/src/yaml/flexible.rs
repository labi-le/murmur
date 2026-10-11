//! Decoding of scalars into strings in permissive fields.
//!
//! `serde_with`-style helpers giving a YAML reader's scalar-to-string decoding: any
//! scalar node decoded into a `string` field takes the node's raw source text verbatim
//! (the string case), regardless of the scalar's resolved YAML type. So a
//! `string` field accepts an unquoted `true`, `80`, or `1.5` exactly as it accepts a quoted one.
//! `serde`'s derived `String`/`Vec<String>` decoding only accepts YAML string scalars, so a
//! `Vec<String>` field whose example configs mix bare numbers with strings needs this to match
//! the input domain, as in a sniffer port list mixing a single port with a range.

use serde::de::{Deserialize, Deserializer};
use serde_yaml::Value;

fn scalar_to_string<'de, D: Deserializer<'de>>(value: Value) -> Result<String, D::Error> {
    use serde::de::Error;
    match value {
        Value::String(s) => Ok(s),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        other @ (Value::Null | Value::Sequence(_) | Value::Mapping(_) | Value::Tagged(_)) => {
            Err(D::Error::custom(format!("expected a scalar, got {other:?}")))
        }
    }
}

/// `#[serde(deserialize_with = "flexible::string_vec")]` for a `Vec<String>` field.
pub fn string_vec<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    Vec::<Value>::deserialize(deserializer)?.into_iter().map(|v| scalar_to_string::<D>(v)).collect()
}

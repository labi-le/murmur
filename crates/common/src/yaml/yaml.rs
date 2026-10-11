//!
//! The decoder fills the value it is given, so mappings merge into
//! `out` instead of replacing it, which keeps the caller's
//! pre-populated defaults for keys the document does not mention.

use anyhow::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_yaml::Value;

pub fn unmarshal<T: DeserializeOwned + Serialize>(input: &[u8], out: &mut T) -> Result<()> {
    let overlay: Value = serde_yaml::from_slice(input)?;
    if overlay.is_null() {
        return Ok(());
    }
    let mut base = serde_yaml::to_value(&*out)?;
    merge(&mut base, overlay);
    *out = serde_yaml::from_value(base)?;
    Ok(())
}

pub fn marshal<T: Serialize>(input: &T) -> Result<Vec<u8>> {
    Ok(serde_yaml::to_string(input)?.into_bytes())
}

/// Mappings merge recursively; every other kind replaces the target. The merge is a
/// no-op when the source node is null and the destination is a non-pointer struct (there is
/// nothing to assign a null to), so a null overlay onto a mapping base — a bare `tun:`, `dns:`,
/// `sniffer:`, ... — leaves that section's pre-populated defaults untouched instead of wiping
/// them; a null overlay onto anything else (a sequence, a scalar, a `HashMap` field) still
/// replaces the target, matching the sequence/pointer/map fields going to null on an explicit null.
fn merge(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Mapping(base_map), Value::Mapping(overlay_map)) => {
            for (key, value) in overlay_map {
                match base_map.get_mut(&key) {
                    Some(base_value) => merge(base_value, value),
                    None => {
                        base_map.insert(key, value);
                    }
                }
            }
        }
        (Value::Mapping(_), Value::Null) => {}
        (base, overlay) => *base = overlay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    struct Nested {
        a: u16,
        b: u16,
    }

    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    struct Config {
        name: String,
        port: u16,
        tags: Vec<String>,
        nested: Nested,
    }

    fn defaults() -> Config {
        Config { name: "default".to_owned(), port: 7890, tags: vec!["x".to_owned()], nested: Nested { a: 1, b: 2 } }
    }

    #[test]
    fn test_unmarshal_merges_into_existing_value() {
        let mut config = defaults();
        unmarshal(b"port: 9090\nnested:\n  b: 3\n", &mut config).unwrap();
        assert_eq!(
            config,
            Config {
                name: "default".to_owned(),
                port: 9090,
                tags: vec!["x".to_owned()],
                nested: Nested { a: 1, b: 3 },
            }
        );
    }

    #[test]
    fn test_unmarshal_replaces_sequences_and_ignores_empty_documents() {
        let mut config = defaults();
        unmarshal(b"tags:\n  - y\n", &mut config).unwrap();
        assert_eq!(config.tags, vec!["y".to_owned()]);

        let mut config = defaults();
        unmarshal(b"# only a comment\n", &mut config).unwrap();
        assert_eq!(config, defaults());
    }

    #[test]
    fn test_marshal() {
        let text = String::from_utf8(marshal(&defaults()).unwrap()).unwrap();
        assert!(text.contains("name: default"));
        let mut config = Config::default();
        unmarshal(text.as_bytes(), &mut config).unwrap();
        assert_eq!(config, defaults());
    }
}

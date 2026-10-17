//!
//! The decoder fills the value it is given, so mappings merge into
//! `out` instead of replacing it, which keeps the caller's
//! pre-populated defaults for keys the document does not mention.

use anyhow::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;
use yaml_serde::Value;

pub fn unmarshal<T: DeserializeOwned + Serialize>(input: &[u8], out: &mut T) -> Result<()> {
    let overlay: Value = yaml_serde::from_slice(input)?;
    if overlay.is_null() {
        return Ok(());
    }
    let mut base = yaml_serde::to_value(&*out)?;
    merge(&mut base, overlay);
    *out = yaml_serde::from_value(base)?;
    Ok(())
}

pub fn marshal<T: Serialize>(input: &T) -> Result<Vec<u8>> {
    Ok(yaml_serde::to_string(input)?.into_bytes())
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

    #[test]
    fn unmarshal_resolves_aliases_before_merging_defaults() {
        let mut config = defaults();
        unmarshal(b"name: &name example\ntags: [*name]\n", &mut config).unwrap();
        assert_eq!(config.name, "example");
        assert_eq!(config.tags, ["example"]);
        assert_eq!(config.nested, Nested { a: 1, b: 2 });
    }

    #[test]
    fn unmarshal_rejects_duplicate_keys_without_mutating_defaults() {
        let mut config = defaults();
        assert!(unmarshal(b"port: 8080\nport: 9090\n", &mut config).is_err());
        assert_eq!(config, defaults());
    }

    #[test]
    fn marshal_preserves_tagged_values_and_explicit_merge_keys() {
        let mut value = Value::Null;
        unmarshal(b"tagged: !custom example\nmap:\n  <<: {port: 8080}\n", &mut value).unwrap();
        let mapping = value.as_mapping().unwrap();
        let tagged = mapping.get("tagged").unwrap();
        assert!(matches!(tagged, Value::Tagged(_)));
        let nested = mapping.get("map").unwrap().as_mapping().unwrap();
        assert!(nested.contains_key("<<"));
        assert!(!nested.contains_key("port"));
        let mut decoded = Value::Null;
        unmarshal(&marshal(&value).unwrap(), &mut decoded).unwrap();
        assert_eq!(decoded, value);
    }
}

use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_yaml::Value;

pub fn filter<T: PartialEq + Clone>(t_slice: &[T], filter: impl Fn(&T) -> bool) -> Vec<T> {
    t_slice.iter().filter(|t| filter(t)).cloned().collect()
}

/// A `None` input yields `None`.
pub fn map<T, N>(arr: Option<&[T]>, mut block: impl FnMut(&T) -> N) -> Option<Vec<N>> {
    let arr = arr?;
    Some(arr.iter().map(&mut block).collect())
}

pub fn to_string_slice<T: Serialize>(value: &T) -> Result<Vec<String>> {
    match serde_yaml::to_value(value)? {
        Value::Sequence(seq) => Ok(seq.iter().map(value_string).collect()),
        Value::String(s) => Ok(vec![s]),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Mapping(_) | Value::Tagged(_) => {
            Err(anyhow!("value format error, must be string or array"))
        }
    }
}

/// The string form of the kinds YAML values can hold.
fn value_string(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Sequence(seq) => {
            let items: Vec<String> = seq.iter().map(value_string).collect();
            format!("[{}]", items.join(" "))
        }
        Value::Mapping(mapping) => {
            let mut entries: Vec<(String, String)> =
                mapping.iter().map(|(k, v)| (value_string(k), value_string(v))).collect();
            entries.sort();
            let items: Vec<String> = entries.iter().map(|(k, v)| format!("{k}:{v}")).collect();
            format!("map[{}]", items.join(" "))
        }
        Value::Tagged(tagged) => value_string(&tagged.value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_and_map() {
        let values = [1, 2, 3, 4];
        assert_eq!(filter(&values, |value| value % 2 == 0), vec![2, 4]);
        assert_eq!(map(Some(&values[..]), |value| value * 2), Some(vec![2, 4, 6, 8]));
        assert_eq!(map::<u16, u16>(None, |value| *value), None);
    }

    #[test]
    fn test_to_string_slice() {
        assert_eq!(to_string_slice(&"example.com").unwrap(), vec!["example.com"]);
        assert_eq!(to_string_slice(&vec!["a", "b"]).unwrap(), vec!["a", "b"]);
        assert_eq!(
            to_string_slice(&serde_json::json!(["192.0.2.1", 80, true])).unwrap(),
            vec!["192.0.2.1", "80", "true"]
        );
        assert!(to_string_slice(&1u16).is_err());
    }
}

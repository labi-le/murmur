use std::collections::HashMap;

/// A string-to-string map. Neither iteration order nor the byte order of `to_bytes` is
/// specified.
pub type StringMap = HashMap<String, String>;

#[must_use]
pub fn to_bytes(s: &StringMap) -> Vec<u8> {
    let mut lines: Vec<String> = Vec::new();
    for (k, v) in s {
        lines.push(format!("{k}={v}"));
    }
    lines.join("\n").into_bytes()
}

/// Parses a `StringMap` from bytes. A line without `=` is skipped, and the key may be empty.
///
/// Keys and values that are not valid UTF-8 are converted lossily.
#[must_use]
pub fn string_map_from_bytes(b: &[u8]) -> StringMap {
    let mut m = StringMap::new();
    let text = String::from_utf8_lossy(b);
    for line in text.split('\n') {
        if let Some((key, value)) = line.split_once('=') {
            m.insert(key.to_owned(), value.to_owned());
        }
    }
    m
}

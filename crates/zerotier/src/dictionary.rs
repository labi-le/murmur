//! ZeroTier's escaped newline-delimited key-value dictionary form, which
//! carries controller network configurations and protocol metadata.

use std::collections::HashMap;

/// Reports malformed ZeroTier dictionary encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ZeroTier dictionary")]
pub struct InvalidDictionary;

/// The decoded entries of one dictionary, keeping the first of duplicate keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dictionary(HashMap<String, Vec<u8>>);

impl Dictionary {
    /// A raw entry value, absent when the key was not sent.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.0.get(key).map(Vec::as_slice)
    }

    /// A hexadecimal integer entry, or `fallback` when absent or invalid.
    #[must_use]
    pub fn uint(&self, key: &str, fallback: u64) -> u64 {
        let Some(value) = self.0.get(key).filter(|value| !value.is_empty()) else {
            return fallback;
        };
        parse_hex_uint(value).unwrap_or(fallback)
    }

    /// A Boolean entry, or `fallback` when absent or empty.
    #[must_use]
    pub fn bool(&self, key: &str, fallback: bool) -> bool {
        match self.0.get(key).filter(|value| !value.is_empty()) {
            Some(value) => value.first().is_some_and(|byte| matches!(byte, b'1' | b't' | b'T')),
            None => fallback,
        }
    }

    /// An entry as text, or the empty string when absent.
    #[must_use]
    pub fn string(&self, key: &str) -> String {
        String::from_utf8_lossy(self.get(key).unwrap_or_default()).into_owned()
    }
}

/// Decodes ZeroTier's escaped newline-delimited key-value form.
pub fn parse_dictionary(data: &[u8]) -> Result<Dictionary, InvalidDictionary> {
    let data = match data.iter().position(|byte| *byte == 0) {
        Some(nul) => data.get(..nul).ok_or(InvalidDictionary)?,
        None => data,
    };
    let mut entries = HashMap::new();
    for line in data.split(|byte| *byte == b'\r' || *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let equals = line.iter().position(|byte| *byte == b'=').ok_or(InvalidDictionary)?;
        if equals == 0 {
            return Err(InvalidDictionary);
        }
        let key = String::from_utf8_lossy(line.get(..equals).ok_or(InvalidDictionary)?).into_owned();
        if let std::collections::hash_map::Entry::Vacant(slot) = entries.entry(key) {
            slot.insert(unescape_dictionary_value(line.get(equals + 1..).ok_or(InvalidDictionary)?)?);
        }
    }
    Ok(Dictionary(entries))
}

/// Decodes the backslash escape sequences a dictionary value may carry.
fn unescape_dictionary_value(value: &[u8]) -> Result<Vec<u8>, InvalidDictionary> {
    let mut result = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        let byte = *value.get(index).ok_or(InvalidDictionary)?;
        if byte != b'\\' {
            result.push(byte);
            index += 1;
            continue;
        }
        index += 1;
        let escaped = *value.get(index).ok_or(InvalidDictionary)?;
        result.push(match escaped {
            b'0' => 0,
            b'r' => b'\r',
            b'n' => b'\n',
            b'e' => b'=',
            other => other,
        });
        index += 1;
    }
    Ok(result)
}

/// Appends one escaped key-value entry to `dst`.
pub fn append_dictionary_entry(mut dst: Vec<u8>, key: &str, value: &[u8]) -> Result<Vec<u8>, InvalidDictionary> {
    if key.is_empty() || key.bytes().any(|byte| matches!(byte, b'=' | b'\r' | b'\n' | 0)) {
        return Err(InvalidDictionary);
    }
    if !dst.is_empty() {
        dst.push(b'\n');
    }
    dst.extend_from_slice(key.as_bytes());
    dst.push(b'=');
    for byte in value {
        match byte {
            0 => dst.extend_from_slice(b"\\0"),
            b'\r' => dst.extend_from_slice(b"\\r"),
            b'\n' => dst.extend_from_slice(b"\\n"),
            b'\\' => dst.extend_from_slice(b"\\\\"),
            b'=' => dst.extend_from_slice(b"\\e"),
            other => dst.push(*other),
        }
    }
    Ok(dst)
}

/// Appends `value` as a fixed-width hexadecimal entry.
pub fn append_dictionary_uint(dst: Vec<u8>, key: &str, value: u64) -> Result<Vec<u8>, InvalidDictionary> {
    append_dictionary_entry(dst, key, format!("{value:016x}").as_bytes())
}

/// Parses a 64-bit hexadecimal integer, rejecting signs, underscores and
/// overflow.
fn parse_hex_uint(value: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(value).ok()?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(text, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_escaped_entries_and_keeps_the_first_duplicate() {
        let dictionary = parse_dictionary(b"a=1\nb=2\ncopy=x=y\na=3\n").unwrap();
        assert_eq!(dictionary.get("a"), Some(&b"1"[..]));
        assert_eq!(dictionary.get("b"), Some(&b"2"[..]));
        assert_eq!(dictionary.get("copy"), Some(&b"x=y"[..]));
        assert_eq!(dictionary.get("absent"), None);
    }

    #[test]
    fn decodes_every_escape_sequence() {
        let dictionary = parse_dictionary(b"k=\\0\\r\\n\\e\\\\\\q").unwrap();
        assert_eq!(dictionary.get("k"), Some(&[0, b'\r', b'\n', b'=', b'\\', b'q'][..]));
    }

    #[test]
    fn stops_at_the_first_nul_and_splits_on_both_line_endings() {
        let dictionary = parse_dictionary(b"a=1\r\nb=2\r\nc=3\x00d=4").unwrap();
        assert_eq!(dictionary.get("a"), Some(&b"1"[..]));
        assert_eq!(dictionary.get("b"), Some(&b"2"[..]));
        assert_eq!(dictionary.get("c"), Some(&b"3"[..]));
        assert_eq!(dictionary.get("d"), None);
    }

    #[test]
    fn rejects_lines_without_a_key_or_a_dangling_escape() {
        assert_eq!(parse_dictionary(b"novalue"), Err(InvalidDictionary));
        assert_eq!(parse_dictionary(b"=1"), Err(InvalidDictionary));
        assert_eq!(parse_dictionary(b"k=trailing\\"), Err(InvalidDictionary));
    }

    #[test]
    fn entries_round_trip_through_the_escaping() {
        let raw = append_dictionary_entry(Vec::new(), "k", &[0, b'\r', b'\n', b'=', b'\\', b'q']).unwrap();
        let raw = append_dictionary_entry(raw, "second", b"v").unwrap();
        let dictionary = parse_dictionary(&raw).unwrap();
        assert_eq!(dictionary.get("k"), Some(&[0, b'\r', b'\n', b'=', b'\\', b'q'][..]));
        assert_eq!(dictionary.get("second"), Some(&b"v"[..]));
    }

    #[test]
    fn appends_fixed_width_hexadecimal_integers() {
        let raw = append_dictionary_uint(Vec::new(), "v", 7).unwrap();
        assert_eq!(raw, b"v=0000000000000007");
        assert_eq!(parse_dictionary(&raw).unwrap().uint("v", 0), 7);
    }

    #[test]
    fn reads_typed_entries_with_fallbacks() {
        let dictionary = parse_dictionary(b"v=1f\nflag=1\nempty=\nbad=zzz\ntext=hello").unwrap();
        assert_eq!(dictionary.uint("v", 0), 0x1f);
        assert_eq!(dictionary.uint("empty", 9), 9);
        assert_eq!(dictionary.uint("bad", 9), 9);
        assert_eq!(dictionary.uint("absent", 9), 9);
        assert!(dictionary.bool("flag", false));
        assert!(!dictionary.bool("empty", false));
        assert!(dictionary.bool("absent", true));
        assert_eq!(dictionary.string("text"), "hello");
        assert_eq!(dictionary.string("absent"), "");
    }

    #[test]
    fn rejects_keys_the_encoding_cannot_carry() {
        assert_eq!(append_dictionary_entry(Vec::new(), "", b"v"), Err(InvalidDictionary));
        assert_eq!(append_dictionary_entry(Vec::new(), "a=b", b"v"), Err(InvalidDictionary));
        assert_eq!(append_dictionary_entry(Vec::new(), "a\nb", b"v"), Err(InvalidDictionary));
    }
}

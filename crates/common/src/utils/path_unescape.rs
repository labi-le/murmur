//! Percent-decoding: decodes `%XX` escapes, leaving `+` untouched (unlike
//! query-string unescaping, which treats `+` as a space).
//!
//! Three call sites (`component::easytier::toml`, `hub::route::common`,
//! `common::convert::v`, the last since deleted as dead) reimplemented this independently and
//! drifted: one converted the decoded bytes with `String::from_utf8_lossy`, silently replacing
//! any byte sequence that was not valid UTF-8 with U+FFFD instead of failing; this
//! implementation errors instead, matching this crate's "no silent degradation" convention
//! and the stricter of the two prior behaviours (the other independent copy already treated a
//! non-UTF-8 result as a hard failure via `Option::None`).
use anyhow::{anyhow, Result};

pub fn path_unescape(value: &str) -> Result<String> {
    if !value.contains('%') {
        return Ok(value.to_owned());
    }
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte != b'%' {
            out.push(byte);
            index += 1;
            continue;
        }
        let hi = bytes.get(index + 1).copied().and_then(hex_digit);
        let lo = bytes.get(index + 2).copied().and_then(hex_digit);
        let (Some(hi), Some(lo)) = (hi, lo) else {
            let end = (index + 3).min(bytes.len());
            let escape = String::from_utf8_lossy(bytes.get(index..end).unwrap_or_default());
            return Err(anyhow!("invalid URL escape \"{escape}\""));
        };
        out.push((hi << 4) | lo);
        index += 3;
    }
    String::from_utf8(out).map_err(|_| anyhow!("invalid UTF-8 after unescaping {value:?}"))
}

fn hex_digit(byte: u8) -> Option<u8> {
    char::from(byte).to_digit(16).and_then(|digit| u8::try_from(digit).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_through_when_no_escape_present() {
        assert_eq!(path_unescape("plain").unwrap(), "plain");
    }

    #[test]
    fn decodes_percent_escapes_and_keeps_plus() {
        assert_eq!(path_unescape("CC%2BCC/CC=").unwrap(), "CC+CC/CC=");
    }

    #[test]
    fn rejects_truncated_escape() {
        assert!(path_unescape("abc%4").is_err());
    }

    #[test]
    fn rejects_non_hex_escape() {
        assert!(path_unescape("abc%4g").is_err());
    }

    #[test]
    fn rejects_invalid_utf8_after_decoding() {
        assert!(path_unescape("%ff%fe").is_err());
    }
}

//! Wildcard matching:
//!
//! ```text
//! `*` matches zero or more characters
//! `?` matches exactly one character
//! ```
//!
//! `.` is a valid delimiter in domain name matching and is not a wildcard here, so the earlier
//! `.`-for-exactly-one / `?`-for-zero-or-one convention has been replaced: `.` became `?`, and
//! the zero-or-one case was dropped.
//!
//! Copied and modified from <https://github.com/IGLOU-EU/go-wildcard/tree/ce22b7af48e487517a492d3727d9386492043e21>
//! which is licensed under OpenBSD's ISC-style license.
//! Copyright (c) 2023 Iglou.eu contact@example.com Copyright (c) 2023 Adrien Kara adrien@example.com

#[must_use]
pub fn match_(pattern: &str, s: &str) -> bool {
    if pattern.is_empty() {
        return s.is_empty();
    }
    if pattern == "*" || s == pattern {
        return true;
    }

    match_by_string(pattern, s)
}

fn match_by_string(pattern: &str, s: &str) -> bool {
    let pattern = pattern.as_bytes();
    let s = s.as_bytes();
    let mut pattern_index: usize = 0;
    let mut s_index: usize = 0;
    let mut last_star: usize = 0;
    let mut star: Option<usize> = None;

    while let Some(&s_byte) = s.get(s_index) {
        let Some(&c) = pattern.get(pattern_index) else {
            if let Some(star) = star {
                pattern_index = star + 1;
                last_star += 1;
                s_index = last_star;
                continue;
            }
            return false;
        };
        match c {
            b'?' => {
                // It matches any single character. So, we don't need to check anything.
            }
            b'*' => {
                // '*' matches zero or more characters. Store its position and increment the pattern index.
                star = Some(pattern_index);
                last_star = s_index;
                pattern_index += 1;
                continue;
            }
            c => {
                // If the characters don't match, check if there was a previous '*' to backtrack.
                if c != s_byte {
                    if let Some(star) = star {
                        pattern_index = star + 1;
                        last_star += 1;
                        s_index = last_star;
                        continue;
                    }

                    return false;
                }
            }
        }

        pattern_index += 1;
        s_index += 1;
    }

    // Check if the remaining pattern characters are '*', which can match the end of the string.
    while pattern.get(pattern_index) == Some(&b'*') {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    // TestMatch validates the logic of wild card matching,
    // it needs to support '*', '?' and only validates byte comparison
    // over strings, not rune or grapheme cluster
    #[test]
    fn test_match() {
        let cases: &[(&str, &str, bool)] = &[
            ("", "", true),
            ("", "*", true),
            ("", "**", true),
            ("", "?", false),
            ("", "?*", false),
            ("", "*?", false),
            ("a", "", false),
            ("a", "a", true),
            ("a", "*", true),
            ("a", "**", true),
            ("a", "?", true),
            ("a", "?*", true),
            ("a", "*?", true),
            ("match the exact string", "match the exact string", true),
            ("do not match a different string", "this is a different string", false),
            ("Match The Exact String WITH DIFFERENT CASE", "Match The Exact String WITH DIFFERENT CASE", true),
            (
                "do not match a different string WITH DIFFERENT CASE",
                "this is a different string WITH DIFFERENT CASE",
                false,
            ),
            (
                "Do Not Match The Exact String With Different Case",
                "do not match the exact string with different case",
                false,
            ),
            ("match an emoji 😃", "match an emoji 😃", true),
            ("do not match because of different emoji 😃", "do not match because of different emoji 😄", false),
            (
                "🌅☕️📰👨‍💼👩‍💼🏢🖥️💼💻📊📈📉👨‍👩‍👧‍👦🍝🕰️💪🏋️‍♂️🏋️‍♀️🏋️‍♂️💼🚴‍♂️🚴‍♀️🚴‍♂️🛀💤🌃",
                "🌅☕️📰👨‍💼👩‍💼🏢🖥️💼💻📊📈📉👨‍👩‍👧‍👦🍝🕰️💪🏋️‍♂️🏋️‍♀️🏋️‍♂️💼🚴‍♂️🚴‍♀️🚴‍♂️🛀💤🌃",
                true,
            ),
            (
                "🌅☕️📰👨‍💼👩‍💼🏢🖥️💼💻📊📈📉👨‍👩‍👧‍👦🍝🕰️💪🏋️‍♂️🏋️‍♀️🏋️‍♂️💼🚴‍♂️🚴‍♀️🚴‍♂️🛀💤🌃",
                "🦌🐇🦡🐿️🌲🌳🏰🌳🌲🌞🌧️❄️🌬️⛈️🔥🎄🎅🎁🎉🎊🥳👨‍👩‍👧‍👦💏👪💖👩‍💼🛀",
                false,
            ),
            ("match a string with a *", "match a string *", true),
            ("match a string with a * at the beginning", "* at the beginning", true),
            ("match a string with two *", "match * with *", true),
            ("do not match a string with extra and a *", "do not match a string * with more", false),
            ("match a string with a ?", "match ? string with a ?", true),
            ("match a string with a ? at the beginning", "?atch a string with a ? at the beginning", true),
            ("match a string with two ?", "match a ??ring with two ?", true),
            ("do not match a string with extra ?", "do not match a string with extra ??", false),
            ("abc.edf.hjg", "abc.edf.hjg", true),
            ("abc.edf.hjg", "ab.cedf.hjg", false),
            ("abc.edf.hjg", "abc.edfh.jg", false),
            ("abc.edf.hjg", "abc.edf.hjq", false),
            ("abc.edf.hjg", "abc.*.hjg", true),
            ("abc.edf.hjg", "abc.*.hjq", false),
            ("abc.edf.hjg", "abc*hjg", true),
            ("abc.edf.hjg", "abc*hjq", false),
            ("abc.edf.hjg", "a*g", true),
            ("abc.edf.hjg", "a*q", false),
            ("abc.edf.hjg", "ab?.edf.hjg", true),
            ("abc.edf.hjg", "?b?.edf.hjg", true),
            ("abc.edf.hjg", "??c.edf.hjg", true),
            ("abc.edf.hjg", "a??.edf.hjg", true),
            ("abc.edf.hjg", "ab??.edf.hjg", false),
            ("abc.edf.hjg", "??.edf.hjg", false),
        ];

        for (i, (s, pattern, result)) in cases.iter().enumerate() {
            let matched = match_(pattern, s);
            assert_eq!(
                *result,
                matched,
                "Test {}: Expected `{}`, found `{}`; With Pattern: `{}` and String: `{}`",
                i + 1,
                result,
                matched,
                pattern,
                s
            );
        }
    }

    // A reference matcher following https://research.swtch.com/glob, kept as the oracle the
    // needle matcher is fuzzed against.
    fn reference_match(pattern: &str, name: &str) -> bool {
        let pattern = pattern.as_bytes();
        let name = name.as_bytes();
        let mut px = 0;
        let mut nx = 0;
        let mut next_px = 0;
        let mut next_nx = 0;
        while px < pattern.len() || nx < name.len() {
            if px < pattern.len() {
                let c = pattern[px];
                match c {
                    // single-character wildcard
                    b'?' => {
                        if nx < name.len() {
                            px += 1;
                            nx += 1;
                            continue;
                        }
                    }
                    // zero-or-more-character wildcard
                    b'*' => {
                        // Try to match at nx.
                        // If that doesn't work out,
                        // restart at nx+1 next.
                        next_px = px;
                        next_nx = nx + 1;
                        px += 1;
                        continue;
                    }
                    // ordinary character
                    _ => {
                        if nx < name.len() && name[nx] == c {
                            px += 1;
                            nx += 1;
                            continue;
                        }
                    }
                }
            }
            // Mismatch. Maybe restart.
            if 0 < next_nx && next_nx <= name.len() {
                px = next_px;
                nx = next_nx;
                continue;
            }
            return false;
        }
        // Matched all of pattern to all of name. Success.
        true
    }

    fn strings_over(alphabet: &[u8], max_len: usize) -> Vec<String> {
        let mut out = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in &frontier {
                for ch in alphabet {
                    let mut s = prefix.clone();
                    s.push(char::from(*ch));
                    next.push(s);
                }
            }
            out.extend(next.iter().cloned());
            frontier = next;
        }
        out
    }

    // the test compares against an independent implementation, enumerating every pattern and
    // name over a small alphabet instead of fuzzing.
    #[test]
    fn test_match_against_reference_matcher() {
        let patterns = strings_over(b"ab*?", 4);
        let names = strings_over(b"ab", 4);
        for pattern in &patterns {
            for name in &names {
                assert_eq!(
                    match_(pattern, name),
                    reference_match(pattern, name),
                    "Match failed for pattern `{pattern}` and name `{name}`"
                );
            }
        }
    }
}

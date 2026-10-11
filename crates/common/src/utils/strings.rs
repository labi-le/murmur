#[must_use]
pub fn reverse(s: &str) -> String {
    s.chars().rev().collect()
}

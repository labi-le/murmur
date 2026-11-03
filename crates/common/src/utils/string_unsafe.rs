/// A borrowed view of `s` as bytes, without a heap-allocated copy. This is only
/// valid when the returned slice is never mutated.
#[must_use]
pub const fn immutable_bytes_from_string(s: &str) -> &[u8] {
    s.as_bytes()
}

/// A borrowed view of `bs` as a string, without a heap-allocated copy, valid when
/// `bs` is UTF-8.
///
/// Returns `None` otherwise; `bs` must not be mutated while the borrow is live.
#[must_use]
pub fn string_from_immutable_bytes(bs: &[u8]) -> Option<&str> {
    std::str::from_utf8(bs).ok()
}

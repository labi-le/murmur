//! No pool is needed here: neither `session.rs` nor `stream.rs` depends on a size-class
//! boundary for correctness (unlike `MaxStreamBuffer`, which does gate protocol behaviour), and
//! Rust's allocator plus `Vec` drop already absorbs the buffer churn a pool would avoid.
pub(crate) fn get_buffer(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

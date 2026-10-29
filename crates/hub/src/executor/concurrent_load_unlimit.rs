//! See `concurrent_load_limit.rs`'s doc comment for why this maps to `target_arch` in
//! `{"x86", "x86_64", "aarch64"}`.
//!
//! `usize::MAX` becomes the concurrency limit: `executor::load_provider`'s `for_each_concurrent`
//! treats that as "no concurrency cap" rather than a real semaphore size.

pub(crate) const CONCURRENT_COUNT: usize = usize::MAX;

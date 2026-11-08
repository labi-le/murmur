//! `target_arch` does not split by endianness, so `"aarch64"` already covers the
//! `arm64`/`arm64be` and `"mips"` already covers the `mips`/`mipsle`; the negation below is gated
//! the same way in `hub/executor.rs`'s `pub mod` line.

pub(crate) const CONCURRENT_COUNT: usize = 5;

//!
//! The max/min wrappers are re-exports of the builtin `max`/`min`. An older hand-written fallback is
//! superseded by this module and was dropped along with its `pub mod` line.

pub use std::cmp::{max, min};

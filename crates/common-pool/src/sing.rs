//!
//! The default allocator used by the sing buffer implementation.
//!
//! There is no cross-crate init hook to point every sing buffer allocation at this crate's
//! allocator, so `murmur_compat::sing_buf` takes its allocator from here.

use super::alloc::{Allocator, DEFAULT_ALLOCATOR};

/// The default allocator that sing buffers use.
#[must_use]
pub fn default_allocator() -> &'static dyn Allocator {
    &*DEFAULT_ALLOCATOR
}

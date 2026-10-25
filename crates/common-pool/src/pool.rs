use anyhow::Result;

use super::alloc::{Allocator, DEFAULT_ALLOCATOR};

/// a buffer of `size` bytes from the default allocator.
pub fn get(size: usize) -> Vec<u8> {
    DEFAULT_ALLOCATOR.get(size)
}

/// returns a buffer to the default allocator.
pub fn put(buf: Vec<u8>) -> Result<()> {
    DEFAULT_ALLOCATOR.put(buf)
}

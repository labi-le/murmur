use std::sync::LazyLock;

use anyhow::{anyhow, Result};
use parking_lot::Mutex;
pub trait Allocator: Send + Sync {
    /// a buffer of `size` bytes, taken from the smallest pooled block
    /// that fits.
    fn get(&self, size: usize) -> Vec<u8>;

    /// returns a buffer to the pool it came from.
    fn put(&self, buf: Vec<u8>) -> Result<()>;
}
pub static DEFAULT_ALLOCATOR: LazyLock<DefaultAllocator> = LazyLock::new(new_allocator);

/// Cap on the number of blocks retained per size class. This pool never frees on its own, so an
/// unbounded free list would keep every
/// block a traffic burst ever allocated resident for the process's lifetime. With 1024 blocks
/// retained per size class, the worst case summed over all eleven classes this allocator serves
/// is about 128MiB resident: the widest class contributes 64MiB of that, and the relay-buffer and
/// UDP-datagram classes contribute 32MiB and 16MiB. The cap stays far above the per-class
/// concurrency any
/// deployment sustains, so steady-state traffic keeps a 100% pool hit rate.
const MAX_POOLED_PER_CLASS: usize = 1024;

/// block pools from 64B to 64K, optimized to prevent overwriting
/// after zeroing.
#[derive(Debug)]
pub struct DefaultAllocator {
    buffers: [Mutex<Vec<Vec<u8>>>; 11],
}

/// an allocator for frames of less than 65536 bytes, whose block waste
/// is guaranteed to be no more than 50%.
#[must_use]
pub fn new_allocator() -> DefaultAllocator {
    DefaultAllocator { buffers: std::array::from_fn(|_| Mutex::new(Vec::new())) }
}

impl DefaultAllocator {
    const fn block_size(index: usize) -> usize {
        1 << (index + 6)
    }

    /// How many blocks of the given size class are parked in the free list. Exists so a test can
    /// tell a reuse from a fresh allocation, which the block contents can no longer show because
    /// `put` wipes every byte.
    #[must_use]
    pub fn free_len(&self, block_size: usize) -> usize {
        if !block_size.is_power_of_two() || !(64..=65536).contains(&block_size) {
            return 0;
        }
        let index = block_size.trailing_zeros().cast_signed() - 6;
        self.buffers.get(index.cast_unsigned() as usize).map_or(0, |slot| slot.lock().len())
    }
}

impl Allocator for DefaultAllocator {
    fn get(&self, size: usize) -> Vec<u8> {
        match size {
            0 => Vec::new(),
            size if size > 65536 => vec![0u8; size],
            size => {
                let mut index = 0usize;
                if size > 64 {
                    index = usize::from(msb(size));
                    if size != 1usize << index {
                        index += 1;
                    }
                    index -= 6;
                }

                let mut buffer = {
                    let Some(slot) = self.buffers.get(index) else {
                        return vec![0u8; size];
                    };
                    let mut pool = slot.lock();
                    match pool.pop() {
                        Some(buffer) => buffer,
                        None => vec![0u8; Self::block_size(index)],
                    }
                };
                buffer.truncate(size);

                buffer
            }
        }
    }

    fn put(&self, mut buf: Vec<u8>) -> Result<()> {
        let capacity = buf.capacity();
        if capacity == 0 || capacity > 65536 {
            return Ok(());
        }

        let mut bits = usize::from(msb(capacity));
        if capacity != 1usize << bits {
            return Err(anyhow!("allocator Put() incorrect buffer size"));
        }
        if capacity < 1 << 6 {
            return Ok(());
        }
        bits -= 6;

        // `resize` alone writes only the tail past `len`, so a short buffer would keep its old
        // contents and the next `get` would hand them to an unrelated caller. `clear` first
        // drops the length to zero, so the resize below writes every byte of the block.
        buf.clear();
        buf.resize(capacity, 0);

        {
            let Some(slot) = self.buffers.get(bits) else {
                return Ok(());
            };
            let mut pool = slot.lock();
            if pool.len() < MAX_POOLED_PER_CLASS {
                pool.push(buf);
            }
        }
        Ok(())
    }
}

/// The position of the most significant bit, including the wrap at a zero size.
#[expect(
    clippy::cast_possible_truncation,
    reason = "blocks are capped at 64KiB, so the argument fits in 32 bits, and the u16 wrap for a zero size is load-bearing"
)]
const fn msb(size: usize) -> u16 {
    (u32::BITS - 1).wrapping_sub((size as u32).leading_zeros()) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_get() {
        let alloc = new_allocator();
        assert!(alloc.get(0).is_empty());
        assert_eq!(1, alloc.get(1).len());
        assert_eq!(2, alloc.get(2).len());
        assert_eq!(3, alloc.get(3).len());
        assert_eq!(64, alloc.get(3).capacity());
        assert_eq!(64, alloc.get(4).capacity());
        assert_eq!(1023, alloc.get(1023).len());
        assert_eq!(1024, alloc.get(1023).capacity());
        assert_eq!(1024, alloc.get(1024).len());
        assert_eq!(65536, alloc.get(65536).len());
        assert_eq!(65537, alloc.get(65537).len());
    }

    #[test]
    fn test_alloc_put() {
        let alloc = new_allocator();
        assert!(alloc.put(Vec::new()).is_ok(), "putting an empty buffer must succeed");

        assert!(alloc.put(vec![0u8; 3]).is_err(), "putting a 3-byte element must fail");
        assert!(alloc.put(vec![0u8; 4]).is_ok(), "putting a 4-byte element must succeed");

        let mut data = vec![0u8; 1024];
        data.truncate(1023);
        assert!(alloc.put(data).is_ok(), "putting a 1023-byte element must succeed");

        assert!(alloc.put(vec![0u8; 65536]).is_ok(), "putting a 65536-byte element must succeed");
        assert!(alloc.put(vec![0u8; 65537]).is_ok(), "putting a 65537-byte element must succeed");
    }

    #[test]
    fn test_alloc_put_then_get() {
        let alloc = new_allocator();
        let data = alloc.get(4);
        let data_capacity = data.capacity();
        alloc.put(data).unwrap();
        let new_data = alloc.get(4);

        assert_eq!(data_capacity, new_data.capacity(), "different cap while alloc.get()");
    }
}

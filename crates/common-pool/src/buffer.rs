use std::sync::LazyLock;

use bytes::BytesMut;
use parking_lot::Mutex;

/// Cap on the idle buffers kept, instead of holding every buffer handed back.
#[cfg(not(feature = "with_low_memory"))]
const MAX_POOLED_BUFFERS: usize = 64;
#[cfg(feature = "with_low_memory")]
const MAX_POOLED_BUFFERS: usize = 16;
const MAX_IDLE_CAPACITY: usize = 64 * 1024;

#[derive(Default)]
struct BufferPool {
    buffers: Mutex<Vec<BytesMut>>,
}

impl BufferPool {
    fn get(&self) -> BytesMut {
        self.buffers.lock().pop().unwrap_or_default()
    }

    fn put(&self, mut buf: BytesMut) {
        if buf.capacity() > MAX_IDLE_CAPACITY {
            return;
        }

        let mut pool = self.buffers.lock();
        if pool.len() < MAX_POOLED_BUFFERS {
            buf.clear();
            pool.push(buf);
        }
    }
}

static BUFFER_POOL: LazyLock<BufferPool> = LazyLock::new(BufferPool::default);

pub fn get_buffer() -> BytesMut {
    BUFFER_POOL.get()
}

/// resets the buffer and returns it to the pool.
pub fn put_buffer(buf: BytesMut) {
    BUFFER_POOL.put(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varied_size_burst_bounds_idle_bytes() {
        let pool = BufferPool::default();
        let burst: Vec<_> = (0..128)
            .map(|index| {
                let mut buf = BytesMut::with_capacity([32768, 49152, 65536][index % 3]);
                buf.resize(buf.capacity(), 0xA5);
                buf
            })
            .collect();
        for buf in burst {
            pool.put(buf);
        }

        let retained = pool.buffers.lock();
        let retained_bytes: usize = retained.iter().map(BytesMut::capacity).sum();
        let budget = if cfg!(feature = "with_low_memory") { 1024 * 1024 } else { 4 * 1024 * 1024 };
        assert!(retained_bytes <= budget, "retained {retained_bytes} bytes after burst");
        assert!(!retained.is_empty(), "the pool must still retain reusable buffers");
    }

    #[test]
    fn reused_buffer_exposes_no_previous_contents() {
        let pool = BufferPool::default();
        let mut buf = BytesMut::with_capacity(8192);
        buf.resize(8192, 0xA5);
        let allocation = buf.as_ptr();
        pool.put(buf);

        let mut reused = pool.get();
        assert_eq!(reused.as_ptr(), allocation);
        assert!(reused.is_empty());
        reused.resize(8192, 0);
        assert!(reused.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn oversized_release_preserves_reusable_buffer() {
        let pool = BufferPool::default();
        let reusable = BytesMut::with_capacity(8192);
        let allocation = reusable.as_ptr();
        pool.put(reusable);
        pool.put(BytesMut::with_capacity(65537));

        assert_eq!(pool.get().as_ptr(), allocation);
        assert_eq!(pool.get().capacity(), 0);
    }
}

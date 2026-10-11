use std::sync::LazyLock;

use bytes::BytesMut;
use parking_lot::Mutex;

/// Cap on the idle buffers kept, instead of holding every buffer handed back.
const MAX_POOLED_BUFFERS: usize = 64;
const MAX_IDLE_CAPACITY: usize = 64 * 1024;

static BUFFER_POOL: LazyLock<Mutex<Vec<BytesMut>>> = LazyLock::new(|| Mutex::new(Vec::new()));
pub fn get_buffer() -> BytesMut {
    BUFFER_POOL.lock().pop().unwrap_or_default()
}

/// resets the buffer and returns it to the pool.
pub fn put_buffer(mut buf: BytesMut) {
    buf.clear();

    if buf.capacity() > MAX_IDLE_CAPACITY {
        return;
    }

    let mut pool = BUFFER_POOL.lock();
    if pool.len() < MAX_POOLED_BUFFERS {
        pool.push(buf);
    }
}

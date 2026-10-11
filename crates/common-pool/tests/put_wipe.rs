use murmur_common_pool::alloc::{new_allocator, Allocator};

#[test]
fn put_wipes_short_len_block() {
    let alloc = new_allocator();
    let mut buf = vec![0xAAu8; 1024];
    buf.truncate(1023);
    assert!(alloc.put(buf).is_ok());
    let got = alloc.get(1023);
    assert_eq!(1023, got.len());
    assert!(got.iter().all(|&byte| byte == 0), "put left stale bytes in the pooled block");
}

#[test]
fn put_wipes_bytes_beyond_len() {
    let alloc = new_allocator();
    let mut buf = vec![0xFFu8; 4096];
    buf.truncate(1);
    assert!(alloc.put(buf).is_ok());
    let got = alloc.get(1);
    assert_eq!(1, got.len());
    assert!(got.iter().all(|&byte| byte == 0), "put left stale bytes in the pooled block");

    let mut buf = vec![0xFFu8; 4096];
    buf.truncate(1);
    assert!(alloc.put(buf).is_ok());
    let got = alloc.get(1);
    assert!(got.iter().all(|&byte| byte == 0), "put left stale bytes in the pooled block");
}

#[test]
fn put_wipes_every_size_class() {
    let alloc = new_allocator();
    for block in [64usize, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536] {
        let mut buf = vec![0xA5u8; block];
        buf.truncate(block - 1);
        assert!(alloc.put(buf).is_ok());
        let got = alloc.get(block - 1);
        assert_eq!(block - 1, got.len());
        assert!(got.iter().all(|&byte| byte == 0), "class {block} left stale bytes in the pooled block");
    }
}

#[test]
fn put_wipes_full_len_block() {
    let alloc = new_allocator();
    assert!(alloc.put(vec![0x5Au8; 1024]).is_ok());
    let got = alloc.get(1024);
    assert_eq!(1024, got.len());
    assert!(got.iter().all(|&byte| byte == 0), "put left stale bytes in the pooled block");
}

/// A block whose length is not a power of two still returns to the pool and is handed back out
/// again. This is the regression the `InnerUdpPacket` drop used to guard: a payload of 200 bytes
/// rides a 256-byte block, and a `put` that rejected anything but an exact-size block would have
/// freed it instead of reusing it. The sentinel a caller can no longer use to detect reuse, since
/// `put` wipes the block, so the free list is observed directly.
#[test]
fn a_short_len_block_returns_to_the_free_list() {
    let alloc = new_allocator();
    assert_eq!(0, alloc.free_len(256), "the class starts empty");

    let mut buf = vec![0xCDu8; 256];
    buf.truncate(200);
    assert!(alloc.put(buf).is_ok());
    assert_eq!(1, alloc.free_len(256), "the block must reach the free list rather than be dropped");

    let reused = alloc.get(200);
    assert_eq!(256, reused.capacity(), "the pooled block is handed back, not a fresh allocation");
    assert_eq!(0, alloc.free_len(256), "the block left the free list");
}

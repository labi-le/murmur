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

#[cfg(feature = "with_low_memory")]
#[test]
fn varied_size_burst_retains_at_most_four_mib() {
    let alloc = new_allocator();
    let blocks = [64usize, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];
    let burst: Vec<_> = blocks
        .iter()
        .flat_map(|&block| (0..65).map(move |_| block))
        .map(|size| {
            let mut buf = alloc.get(size - 1);
            buf.fill(0xA5);
            buf
        })
        .collect();
    for buf in burst {
        assert!(alloc.put(buf).is_ok());
    }

    let retained_bytes: usize = blocks.iter().map(|&block| block * alloc.free_len(block)).sum();
    assert!(retained_bytes <= 4 * 1024 * 1024, "retained {retained_bytes} bytes after burst");
    for block in blocks {
        assert!(alloc.free_len(block) > 0, "class {block} should still support reuse");
        let buf = alloc.get(block);
        assert_eq!(buf.len(), block);
        assert!(buf.iter().all(|&byte| byte == 0));
    }
}

#[test]
fn reused_block_is_zeroed_across_its_entire_capacity() {
    let alloc = new_allocator();
    let mut buf = alloc.get(65536);
    let allocation = buf.as_ptr();
    buf.fill(0xA5);
    buf.truncate(1);
    assert!(alloc.put(buf).is_ok());

    let reused = alloc.get(65536);
    assert_eq!(reused.as_ptr(), allocation, "reuse must not allocate a replacement");
    assert_eq!(reused.len(), 65536);
    assert!(reused.iter().all(|&byte| byte == 0));
}

#[test]
fn oversized_release_does_not_enter_a_smaller_pool() {
    let alloc = new_allocator();
    let mut oversized = alloc.get(65537);
    assert_eq!(oversized.len(), 65537);
    oversized.fill(0xA5);
    oversized.truncate(1);
    assert!(alloc.put(oversized).is_ok());

    for block in [64usize, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536] {
        assert_eq!(alloc.free_len(block), 0);
    }
    let next = alloc.get(65537);
    assert_eq!(next.len(), 65537);
    assert!(next.iter().all(|&byte| byte == 0));
}

#[test]
fn overflowing_a_size_class_keeps_retained_blocks_reusable() {
    let alloc = new_allocator();
    let burst: Vec<_> = (0..1025)
        .map(|_| {
            let mut buf = alloc.get(63);
            buf.fill(0xA5);
            buf
        })
        .collect();
    for buf in burst {
        assert!(alloc.put(buf).is_ok());
    }

    assert_eq!(alloc.free_len(64), 1024);
    for _ in 0..1024 {
        let reused = alloc.get(64);
        assert_eq!(reused.len(), 64);
        assert!(reused.iter().all(|&byte| byte == 0));
    }
    assert_eq!(alloc.free_len(64), 0);
}

use base64::Engine as _;
use sha1::{Digest as _, Sha1};

/// The WebSocket masking algorithm of RFC 6455 section 5.3, returning the rotated key a
/// continuation call would need. One pass per 8-byte chunk xors the same bytes a byte-by-byte pass
/// would.
#[expect(
    clippy::expect_used,
    reason = "`split_at_mut` with a constant yields exactly that many bytes, so the conversion cannot fail"
)]
pub fn mask_websocket(key: u32, mut b: &mut [u8]) -> u32 {
    let mut key = key;

    if b.len() >= 8 {
        let key64: u64 = (u64::from(key) << 32) | u64::from(key);

        while b.len() >= 8 {
            let (head, tail) = b.split_at_mut(8);
            let v = u64::from_le_bytes(head.try_into().expect("eight bytes"));
            head.copy_from_slice(&(v ^ key64).to_le_bytes());
            b = tail;
        }
    }

    while b.len() >= 4 {
        let (head, tail) = b.split_at_mut(4);
        let v = u32::from_le_bytes(head.try_into().expect("four bytes"));
        head.copy_from_slice(&(v ^ key).to_le_bytes());
        b = tail;
    }

    for byte in b.iter_mut() {
        let [low, ..] = key.to_le_bytes();
        *byte ^= low;
        key = key.rotate_right(8);
    }

    key
}

#[must_use]
pub fn get_websocket_sec_accept(sec_key: &str) -> String {
    const MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const NONCE_SIZE: usize = 24;

    let mut p = vec![0u8; NONCE_SIZE + MAGIC.len()];
    let sec_key = sec_key.as_bytes();
    let n = core::cmp::min(NONCE_SIZE, sec_key.len());
    if let (Some(dst), Some(src)) = (p.get_mut(..n), sec_key.get(..n)) {
        dst.copy_from_slice(src);
    }
    if let Some(dst) = p.get_mut(NONCE_SIZE..) {
        dst.copy_from_slice(MAGIC.as_bytes());
    }
    let sum = Sha1::digest(&p);
    base64::engine::general_purpose::STANDARD.encode(sum)
}

//!
//! A byte-at-a-time reader keeps calling `read` on an empty, error-free result, then treats a
//! trailing one-byte read followed by EOF as success.
//!
//! `tokio::io::AsyncRead`'s `read()` never returns that
//! `(n>0, error)` pairing (a short read and an error are mutually exclusive) and signals EOF with
//! a plain `Ok(0)`, so the loop's only reachable outcomes collapse to: got a byte, or hit EOF.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Reads a single byte: an erased reader cannot be probed for a byte-at-a-time capability, so this
/// always reads one byte rather than handing the reader back unchanged.
pub(crate) async fn read_byte<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<u8> {
    let mut b = [0u8; 1];
    let n = reader.read(&mut b).await?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
    }
    Ok(b[0])
}

/// Reads a uvarint, bounded to its 10-byte maximum.
pub async fn read_u_variant<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<u64> {
    const MAX_VARINT_LEN_64: usize = 10;
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for i in 0..MAX_VARINT_LEN_64 {
        let b = read_byte(reader).await?;
        if b < 0x80 {
            if i == MAX_VARINT_LEN_64 - 1 && b > 1 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "binary: varint overflows a 64-bit integer"));
            }
            return Ok(x | (u64::from(b) << s));
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "binary: varint overflows a 64-bit integer"))
}

#[must_use]
pub const fn u_varint_len(x: u64) -> usize {
    match () {
        () if x < 1 << 7 => 1,
        () if x < 1 << (7 * 2) => 2,
        () if x < 1 << (7 * 3) => 3,
        () if x < 1 << (7 * 4) => 4,
        () if x < 1 << (7 * 5) => 5,
        () if x < 1 << (7 * 6) => 6,
        () if x < 1 << (7 * 7) => 7,
        () if x < 1 << (7 * 8) => 8,
        () if x < 1 << (7 * 9) => 9,
        () => 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_u_variant_round_trips_uvarint_len() {
        for &x in &[0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            let mut v = x;
            loop {
                if v < 0x80 {
                    buf.push(v as u8);
                    break;
                }
                buf.push((v as u8 & 0x7f) | 0x80);
                v >>= 7;
            }
            assert_eq!(buf.len(), u_varint_len(x));
            let mut cursor = io::Cursor::new(buf);
            let got = read_u_variant(&mut cursor).await.unwrap();
            assert_eq!(got, x);
        }
    }
}

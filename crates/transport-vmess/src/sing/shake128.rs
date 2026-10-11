//! SHAKE128, as used for chunk-length masking and global padding: absorb once, then squeeze an
//! unbounded stream. The same FIPS 202 SHAKE128 the `sha3` crate implements; `kat_tests` pins the
//! squeeze order against fixed output.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128Reader};

/// One SHAKE128 stream shared by the masking and padding roles, read as big-endian `u16`s in
/// order.
pub(crate) struct Shake128Stream {
    reader: Shake128Reader,
}

impl Shake128Stream {
    pub(crate) fn new(seed: &[u8]) -> Self {
        Self { reader: Shake128::default().chain(seed).finalize_xof() }
    }

    pub(crate) fn next_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.reader.read(&mut buf);
        u16::from_be_bytes(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::Shake128Stream;

    #[test]
    fn matches_hashlib_shake_128_stream() {
        let seed: Vec<u8> = (0xc0u8..=0xcf).collect();
        let mut s = Shake128Stream::new(&seed);
        let got: Vec<u16> = (0..10).map(|_| s.next_u16()).collect();
        assert_eq!(got, vec![16324, 25672, 42329, 17904, 34238, 15079, 39927, 24556, 51299, 14838]);
    }

    #[test]
    fn matches_hashlib_shake_128_empty_seed() {
        let mut s = Shake128Stream::new(b"");
        let got: Vec<u16> = (0..8).map(|_| s.next_u16()).collect();
        assert_eq!(got, vec![32668, 11172, 59535, 33405, 24928, 17744, 30213, 34110]);
    }
}

use super::murmur::{Bmixer, Digest};

const C1_32: u32 = 0xcc9e2d51;
const C2_32: u32 = 0x1b873593;

/// The rolling hash the mixer owns, held separately from the struct that
/// embeds the digest.
#[derive(Debug)]
pub(crate) struct Mixer32 {
    h1: u32,
}

impl Bmixer for Mixer32 {
    fn bmix(&mut self, p: &[u8]) -> usize {
        let mut h1 = self.h1;
        let (blocks, tail) = p.as_chunks::<4>();
        for block in blocks {
            // The block is loaded with an unaligned native-endian read.
            let mut k1 = u32::from_ne_bytes(*block);

            k1 = k1.wrapping_mul(C1_32);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(C2_32);

            h1 ^= k1;
            h1 = h1.rotate_left(13);
            h1 = h1.wrapping_mul(4).wrapping_add(h1).wrapping_add(0xe6546b64);
        }
        self.h1 = h1;
        p.len() - tail.len()
    }

    fn size(&self) -> usize {
        4
    }

    fn reset(&mut self, seed: u32) {
        self.h1 = seed;
    }
}

#[derive(Debug)]
pub struct Digest32 {
    pub(crate) digest: Digest<Mixer32>,
}

impl Digest32 {
    #[must_use]
    pub fn size(&self) -> usize {
        self.digest.mixer.size()
    }

    #[must_use]
    pub fn sum(&self, mut b: Vec<u8>) -> Vec<u8> {
        let h = self.sum32();
        b.extend_from_slice(&h.to_be_bytes());
        b
    }

    #[must_use]
    pub fn sum32(&self) -> u32 {
        let mut h1 = self.digest.mixer.h1;

        let tail = &self.digest.tail;
        let mut k1: u32 = 0;
        // the switch falls through: case 3 runs 3, 2 and 1, case 2 runs 2 and 1, which is
        // the little-endian fold below.
        let rem = tail.len() & 3;
        if rem != 0 {
            for byte in tail.iter().rev() {
                k1 = (k1 << 8) | u32::from(*byte);
            }
            k1 = k1.wrapping_mul(C1_32);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(C2_32);
            h1 ^= k1;
        }

        #[expect(clippy::cast_possible_truncation, reason = "a 32-bit digest mixes the low 32 bits of the length")]
        let clen = self.digest.clen as u32;
        h1 ^= clen;

        h1 ^= h1 >> 16;
        h1 = h1.wrapping_mul(0x85ebca6b);
        h1 ^= h1 >> 13;
        h1 = h1.wrapping_mul(0xc2b2ae35);
        h1 ^= h1 >> 16;

        h1
    }

    /// Writes into the embedded digest.
    pub fn write(&mut self, p: &[u8]) -> usize {
        self.digest.write(p)
    }

    /// Resets the embedded digest.
    pub fn reset(&mut self) {
        self.digest.reset();
    }

    /// The block size of the embedded digest.
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.digest.block_size()
    }
}

#[must_use]
pub fn new32() -> Digest32 {
    new32_with_seed(0)
}

#[must_use]
pub fn new32_with_seed(seed: u32) -> Digest32 {
    let mut d = Digest32 { digest: Digest { clen: 0, tail: Vec::new(), seed, mixer: Mixer32 { h1: 0 } } };
    d.reset();
    d
}

#[must_use]
pub fn sum32(data: &[u8]) -> u32 {
    sum32_with_seed(data, 0)
}

#[must_use]
pub fn sum32_with_seed(data: &[u8], seed: u32) -> u32 {
    let mut h1 = seed;

    let (blocks, tail) = data.as_chunks::<4>();
    for block in blocks {
        let mut k1 = u32::from_ne_bytes(*block);

        k1 = k1.wrapping_mul(C1_32);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2_32);

        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(4).wrapping_add(h1).wrapping_add(0xe6546b64);
    }

    let mut k1: u32 = 0;
    let rem = tail.len() & 3;
    if rem != 0 {
        for byte in tail.iter().rev() {
            k1 = (k1 << 8) | u32::from(*byte);
        }
        k1 = k1.wrapping_mul(C1_32);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2_32);
        h1 ^= k1;
    }

    // A 32-bit digest mixes the low 32 bits of the input length.
    #[expect(clippy::cast_possible_truncation, reason = "a 32-bit digest mixes the low 32 bits of the length")]
    let len32 = data.len() as u32;
    h1 ^= len32;

    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85ebca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2ae35);
    h1 ^= h1 >> 16;

    h1
}

/// `XorShift128Plus` - a pseudorandom number generator.
#[derive(Clone, Debug, Default)]
pub struct XorShift128Plus {
    s: [u64; 2],
}

/// The two seed words: the first 16 bytes of `bin`, little-endian, zero-filled when `bin` is
/// shorter.
fn seed_words(bin: &[u8]) -> [u64; 2] {
    let mut bytes = [0u8; 16];
    for (dst, src) in bytes.iter_mut().zip(bin) {
        *dst = *src;
    }
    let mut words = [0u64; 2];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap_or_default());
    }
    words
}

/// The seed's length prefix is the low 16 bits of the buffer length.
fn low_u16(length: usize) -> u16 {
    let [b0, b1, ..] = length.to_le_bytes();
    u16::from_le_bytes([b0, b1])
}

impl XorShift128Plus {
    pub const fn next_u64(&mut self) -> u64 {
        let mut x = self.s[0];
        let y = self.s[1];
        self.s[0] = y;
        x ^= x << 23;
        x ^= y ^ (x >> 17) ^ (y >> 26);
        self.s[1] = x;
        x.wrapping_add(y)
    }

    pub fn init_from_bin(&mut self, bin: &[u8]) {
        self.s = seed_words(bin);
    }

    pub fn init_from_bin_and_length(&mut self, bin: &mut [u8], length: usize) {
        if let Some(head) = bin.get_mut(..2) {
            head.copy_from_slice(&low_u16(length).to_le_bytes());
        }
        self.s = seed_words(bin);
        for _ in 0..4 {
            self.next_u64();
        }
    }
}

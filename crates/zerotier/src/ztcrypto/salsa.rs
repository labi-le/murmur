//! Salsa20 core used for ZeroTier's memory-hard identity hash and its
//! reduced-round packet stream.
//!
//! The identity hash needs the standard 20-round construction with a full
//! 16-byte input state, while packet protection uses 12 rounds with the stream
//! counter starting at zero. Both share the block function below.

const SIGMA: [u32; 4] = [
    u32::from_le_bytes(*b"expa"),
    u32::from_le_bytes(*b"nd 3"),
    u32::from_le_bytes(*b"2-by"),
    u32::from_le_bytes(*b"te k"),
];

/// ZeroTier's packet stream: 12 rounds, an 8-byte nonce and a 64-bit block
/// counter starting at zero.
pub fn salsa20_12_xor_key_stream(dst: &mut [u8], src: &[u8], nonce: &[u8; 8], key: &[u8; 32]) {
    let mut state = [0u8; 16];
    state[..8].copy_from_slice(nonce);
    xor_key_stream(dst, src, &state, key, 12);
}

/// Standard Salsa20 over a 16-byte input state (an 8-byte nonce followed by an
/// 8-byte block counter). `rounds` must be even.
pub fn xor_key_stream(dst: &mut [u8], src: &[u8], state: &[u8; 16], key: &[u8; 32], rounds: usize) {
    assert!(dst.len() >= src.len());
    let mut state = *state;
    for (ciphertext, plaintext) in dst.chunks_mut(64).zip(src.chunks(64)) {
        let mut block = [0u8; 64];
        salsa_core(&mut block, &state, key, rounds);
        for (byte, (plain, mask)) in ciphertext.iter_mut().zip(plaintext.iter().zip(block.iter())) {
            *byte = *plain ^ *mask;
        }
        increment_counter(&mut state);
    }
}

/// [`xor_key_stream`] for a destination that is also the source, which Rust's
/// borrow checker cannot express as two arguments to one call.
pub fn xor_key_stream_in_place(buf: &mut [u8], state: &[u8; 16], key: &[u8; 32], rounds: usize) {
    let mut state = *state;
    for chunk in buf.chunks_mut(64) {
        let mut block = [0u8; 64];
        salsa_core(&mut block, &state, key, rounds);
        for (byte, mask) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= *mask;
        }
        increment_counter(&mut state);
    }
}

fn increment_counter(state: &mut [u8; 16]) {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&state[8..16]);
    let counter = u64::from_le_bytes(raw).wrapping_add(1);
    state[8..16].copy_from_slice(&counter.to_le_bytes());
}

#[inline]
fn rotate(value: u32, count: u32) -> u32 {
    value.rotate_left(count)
}

/// Reads `N` little-endian 32-bit words from the head of `bytes`.
fn le_words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    let mut result = [0u32; N];
    for (slot, chunk) in result.iter_mut().zip(bytes.chunks_exact(4)) {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(chunk);
        *slot = u32::from_le_bytes(raw);
    }
    result
}

fn salsa_core(out: &mut [u8; 64], input: &[u8; 16], key: &[u8; 32], rounds: usize) {
    let key_words = le_words::<8>(key);
    let input_words = le_words::<4>(input);
    let j = [
        SIGMA[0],
        key_words[0],
        key_words[1],
        key_words[2],
        key_words[3],
        SIGMA[1],
        input_words[0],
        input_words[1],
        input_words[2],
        input_words[3],
        SIGMA[2],
        key_words[4],
        key_words[5],
        key_words[6],
        key_words[7],
        SIGMA[3],
    ];

    let mut x = j;
    for _ in 0..rounds / 2 {
        x[4] ^= rotate(x[0].wrapping_add(x[12]), 7);
        x[8] ^= rotate(x[4].wrapping_add(x[0]), 9);
        x[12] ^= rotate(x[8].wrapping_add(x[4]), 13);
        x[0] ^= rotate(x[12].wrapping_add(x[8]), 18);
        x[9] ^= rotate(x[5].wrapping_add(x[1]), 7);
        x[13] ^= rotate(x[9].wrapping_add(x[5]), 9);
        x[1] ^= rotate(x[13].wrapping_add(x[9]), 13);
        x[5] ^= rotate(x[1].wrapping_add(x[13]), 18);
        x[14] ^= rotate(x[10].wrapping_add(x[6]), 7);
        x[2] ^= rotate(x[14].wrapping_add(x[10]), 9);
        x[6] ^= rotate(x[2].wrapping_add(x[14]), 13);
        x[10] ^= rotate(x[6].wrapping_add(x[2]), 18);
        x[3] ^= rotate(x[15].wrapping_add(x[11]), 7);
        x[7] ^= rotate(x[3].wrapping_add(x[15]), 9);
        x[11] ^= rotate(x[7].wrapping_add(x[3]), 13);
        x[15] ^= rotate(x[11].wrapping_add(x[7]), 18);

        x[1] ^= rotate(x[0].wrapping_add(x[3]), 7);
        x[2] ^= rotate(x[1].wrapping_add(x[0]), 9);
        x[3] ^= rotate(x[2].wrapping_add(x[1]), 13);
        x[0] ^= rotate(x[3].wrapping_add(x[2]), 18);
        x[6] ^= rotate(x[5].wrapping_add(x[4]), 7);
        x[7] ^= rotate(x[6].wrapping_add(x[5]), 9);
        x[4] ^= rotate(x[7].wrapping_add(x[6]), 13);
        x[5] ^= rotate(x[4].wrapping_add(x[7]), 18);
        x[11] ^= rotate(x[10].wrapping_add(x[9]), 7);
        x[8] ^= rotate(x[11].wrapping_add(x[10]), 9);
        x[9] ^= rotate(x[8].wrapping_add(x[11]), 13);
        x[10] ^= rotate(x[9].wrapping_add(x[8]), 18);
        x[12] ^= rotate(x[15].wrapping_add(x[14]), 7);
        x[13] ^= rotate(x[12].wrapping_add(x[15]), 9);
        x[14] ^= rotate(x[13].wrapping_add(x[12]), 13);
        x[15] ^= rotate(x[14].wrapping_add(x[13]), 18);
    }

    for (chunk, (value, base)) in out.chunks_exact_mut(4).zip(x.iter().zip(j.iter())) {
        chunk.copy_from_slice(&value.wrapping_add(*base).to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(data: &str) -> Vec<u8> {
        hex::decode(data).unwrap()
    }

    #[test]
    fn matches_official_salsa20_12_vector() {
        let key: [u8; 32] = hex("0f62b5085bae0154a7fa4da0f34699ec3f92e5388bde3184d72a7dd02376c91c").try_into().unwrap();
        let nonce: [u8; 8] = hex("288ff65dc42b92f9").try_into().unwrap();
        let want = hex(concat!(
            "99db33ad11ce0ccb3bfdbf8d0c18160452d014cde989b4c411a559ff7c20a169e6",
            "dc9909d816becedc4063ce07cea828f44bf9b6c9a0a0b200e1b52af41859c5",
        ));

        let mut got = vec![0u8; 64];
        salsa20_12_xor_key_stream(&mut got, &[0u8; 64], &nonce, &key);
        assert_eq!(got, want);
    }

    #[test]
    fn in_place_matches_two_buffer_stream() {
        let key = [7u8; 32];
        let state = [9u8; 16];
        let input: Vec<u8> = (0..200u32).map(|value| value as u8).collect();

        let mut split = vec![0u8; input.len()];
        xor_key_stream(&mut split, &input, &state, &key, 20);

        let mut in_place = input.clone();
        xor_key_stream_in_place(&mut in_place, &state, &key, 20);

        assert_eq!(split, in_place);
    }

    #[test]
    fn block_counter_advances_within_one_call() {
        let key = [7u8; 32];
        let state: [u8; 16] = [[9u8; 8], [0u8; 8]].concat().try_into().unwrap();
        let input: Vec<u8> = (0..200u32).map(|value| value as u8).collect();

        let mut whole = vec![0u8; input.len()];
        xor_key_stream(&mut whole, &input, &state, &key, 20);

        let mut per_block = vec![0u8; input.len()];
        for (index, chunk) in input.chunks(64).enumerate() {
            let mut block_state = state;
            block_state[8..16].copy_from_slice(&(index as u64).to_le_bytes());
            let start = index * 64;
            xor_key_stream(&mut per_block[start..start + chunk.len()], chunk, &block_state, &key, 20);
        }

        assert_eq!(whole, per_block);
    }

    #[test]
    fn twelve_round_wrapper_starts_each_call_at_counter_zero() {
        let key = [7u8; 32];
        let nonce = [9u8; 8];
        let input: Vec<u8> = (0..200u32).map(|value| value as u8).collect();

        let mut first = vec![0u8; input.len()];
        let mut second = vec![0u8; input.len()];
        salsa20_12_xor_key_stream(&mut first, &input, &nonce, &key);
        salsa20_12_xor_key_stream(&mut second, &input, &nonce, &key);

        assert_eq!(first, second);
        assert_ne!(first[..64], input[..64]);
    }
}

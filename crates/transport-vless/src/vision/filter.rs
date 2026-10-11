use std::collections::HashMap;
use std::sync::LazyLock;

use murmur_log::debugln;

use super::conn::Conn;

pub(crate) static TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
pub(crate) static TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
pub(crate) static TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
pub(crate) static TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];

static TLS13_CIPHER_SUITE_MAP: LazyLock<HashMap<u16, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        (0x1301, "TLS_AES_128_GCM_SHA256"),
        (0x1302, "TLS_AES_256_GCM_SHA384"),
        (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
        (0x1304, "TLS_AES_128_CCM_SHA256"),
        (0x1305, "TLS_AES_128_CCM_8_SHA256"),
    ])
});

pub(crate) const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
pub(crate) const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

pub(crate) fn index_of(haystack: &[u8], needle: &[u8]) -> i32 {
    if needle.len() > haystack.len() {
        return -1;
    }
    let Some(&first) = needle.first() else {
        return 0;
    };
    let found =
        memchr::memchr_iter(first, haystack).find(|&index| haystack.get(index..index + needle.len()) == Some(needle));
    match found {
        Some(index) => i32::try_from(index).unwrap_or(-1),
        None => -1,
    }
}

/// The last `needle` in `haystack`, or `-1` when there is none.
pub(crate) fn rindex_of(haystack: &[u8], needle: &[u8]) -> i32 {
    if needle.len() > haystack.len() {
        return -1;
    }
    match memchr::memmem::rfind(haystack, needle) {
        Some(index) => i32::try_from(index).unwrap_or(-1),
        None => -1,
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    index_of(haystack, needle) != -1
}

impl Conn {
    pub(crate) fn filter_tls(&mut self, buffer: &[u8]) -> i32 {
        if self.packets_to_filter <= 0 {
            return 0;
        }
        let len_p = buffer.len();
        self.packets_to_filter -= 1;
        let mut index = index_of(buffer, &TLS_SERVER_HANDSHAKE_START);
        if index == -1 {
            index = index_of(buffer, &TLS_CLIENT_HANDSHAKE_START);
            if usize::try_from(index)
                .is_ok_and(|pos| len_p > pos + 5 && buffer.get(pos + 5) == Some(&TLS_HANDSHAKE_TYPE_CLIENT_HELLO))
            {
                self.is_tls = true;
            }
        } else if let Ok(index_pos) = usize::try_from(index) {
            self.parse_server_hello(buffer, index_pos);
        }

        if self.remaining_server_hello > 0 {
            let mut end = usize::from(self.remaining_server_hello);
            let i = usize::try_from(index).unwrap_or(0);
            if i + end > len_p {
                end = len_p;
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "`i + end > len_p` with `end <= u16::MAX` keeps `len_p - i` below `u16::MAX`"
                )]
                let consumed = (len_p - i) as u16;
                self.remaining_server_hello = self.remaining_server_hello.wrapping_sub(consumed);
            } else {
                // `end` is the remaining count itself, so the wrapped subtraction is zero.
                self.remaining_server_hello = 0;
                end += i;
            }
            if buffer.get(i..end).is_some_and(|segment| contains(segment, &TLS13_SUPPORTED_VERSIONS)) {
                let cs = TLS13_CIPHER_SUITE_MAP.get(&self.cipher).copied().unwrap_or("");
                if !cs.is_empty() && cs != "TLS_AES_128_CCM_8_SHA256" {
                    self.enable_xtls = true;
                }
                debugln!("XTLS Vision found TLS 1.3, packetLength={}， CipherSuite={}", len_p, cs);
                self.packets_to_filter = 0;
                return index;
            } else if self.remaining_server_hello == 0 {
                debugln!("XTLS Vision found TLS 1.2, packetLength={}", len_p);
                self.packets_to_filter = 0;
                return index;
            }
            debugln!(
                "XTLS Vision found inconclusive server hello, packetLength={}, remainingServerHelloBytes={}",
                len_p,
                self.remaining_server_hello
            );
        }
        if self.packets_to_filter <= 0 {
            debugln!("XTLS Vision stop filtering");
        }
        index
    }

    /// Parses the TLS ServerHello record header at `index`, recording the Vision-relevant fields.
    fn parse_server_hello(&mut self, buffer: &[u8], index: usize) {
        let len_p = buffer.len();
        let looks_like_record =
            len_p > index + 5 && buffer.first() == Some(&22) && buffer.get(1) == Some(&3) && buffer.get(2) == Some(&3);
        if !looks_like_record {
            return;
        }
        self.is_tls = true;
        if buffer.get(5) != Some(&TLS_HANDSHAKE_TYPE_SERVER_HELLO) {
            return;
        }
        let (Some(&hi), Some(&lo)) = (buffer.get(index + 3), buffer.get(index + 4)) else {
            return;
        };
        self.remaining_server_hello = u16::from_be_bytes([hi, lo]).wrapping_add(5);
        self.is_tls12orabove = true;
        if len_p - index >= 79 && self.remaining_server_hello >= 79 {
            let session_id_len = usize::from(buffer.get(index + 43).copied().unwrap_or(0));
            let cipher_offset = index + 43 + session_id_len + 1;
            if let (Some(&hi), Some(&lo)) = (buffer.get(cipher_offset), buffer.get(cipher_offset + 1)) {
                self.cipher = u16::from_be_bytes([hi, lo]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{index_of, rindex_of};

    /// The caller-visible boundaries: absent, overlapping, last index, flush with the end, whole buffer, over-long needle.
    #[test]
    fn byte_search_boundaries() {
        const NEEDLE: &[u8] = &[0x17, 0x03, 0x03];
        let cases: &[(&[u8], &[u8], i32, i32)] = &[
            (b"aaaa", b"aa", 0, 2),
            (b"ababab", b"ab", 0, 4),
            (b"abc", b"abc", 0, 0),
            (b"..\x17\x03\x03", NEEDLE, 2, 2),
            (b"..\x17\x03\x03..", NEEDLE, 2, 2),
            (b"\x17\x17\x03\x03.\x17", NEEDLE, 1, 1),
            (b"\x17\x03\x17\x03\x03\x17\x03", NEEDLE, 2, 2),
            (b"\x17\x03\x03..\x17\x03", NEEDLE, 0, 0),
            (&[0x41u8; 32], NEEDLE, -1, -1),
            (b"abc", b"z", -1, -1),
            (b"xy", b"xyz", -1, -1),
        ];
        for &(haystack, needle, first, last) in cases {
            assert_eq!(index_of(haystack, needle), first, "index_of({haystack:?}, {needle:?})");
            assert_eq!(rindex_of(haystack, needle), last, "rindex_of({haystack:?}, {needle:?})");
        }
    }
}

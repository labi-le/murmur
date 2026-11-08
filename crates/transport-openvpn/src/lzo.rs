//! LZO1X compression and decompression, plus the OpenVPN compression framing bytes.

use anyhow::Result;

pub const LZO_COMPRESS_NONE: u8 = 0xFA;
pub const LZO_COMPRESS_LZO: u8 = 0x66;

#[derive(Debug, thiserror::Error)]
#[error("lzo decompression failed")]
pub struct ErrLZODecompress;

/// Handles `OpenVPN` comp-lzo data packets: the first byte is the compression
/// header, followed by the payload.
pub fn lzo1x_decompress_safe(src: &[u8]) -> Result<Vec<u8>> {
    let Some((&header, payload)) = src.split_first() else {
        return Err(anyhow::Error::new(ErrLZODecompress));
    };

    match header {
        LZO_COMPRESS_NONE => {
            if payload.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(payload.to_vec())
            }
        }
        LZO_COMPRESS_LZO => {
            if payload.is_empty() {
                return Ok(Vec::new());
            }
            decompress1x(payload).map_err(|_| anyhow::Error::new(ErrLZODecompress))
        }
        _ => Err(anyhow::Error::new(ErrLZODecompress)),
    }
}

/// Handles `OpenVPN` comp-lzo data packets. Prepends the comp-lzo header
/// (0xfa = not compressed) to satisfy servers expecting the framing.
pub fn lzo1x_compress_safe(src: &[u8]) -> Result<Vec<u8>> {
    let mut lzo_packet = Vec::with_capacity(1 + src.len());
    lzo_packet.push(LZO_COMPRESS_NONE);
    lzo_packet.extend_from_slice(src);
    Ok(lzo_packet)
}

/// The decompressor's error surface. Both variants reach `lzo1x_decompress_safe` as
/// `ErrLZODecompress`, whose bounds failures are recovered as an end-of-input error.
#[derive(Debug)]
enum LzoError {
    LookBehindUnderrun,
    Eof,
}

const M2_MAX_OFFSET: usize = 0x0800;

/// The input reader. It consumes the whole slice, so the sliding 4096-byte window only has to
/// report an end-of-input once it is exhausted.
struct LzoReader<'a> {
    data: &'a [u8],
    pos: usize,
    err: Option<LzoError>,
}

impl<'a> LzoReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        let mut reader = Self { data, pos: 0, err: None };
        reader.rebuffer();
        reader
    }

    const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn rebuffer(&mut self) {
        if self.remaining() == 0 && self.err.is_none() {
            self.err = Some(LzoError::Eof);
        }
    }

    fn read_append(&mut self, out: &mut Vec<u8>, n: usize) {
        let take = self.remaining().min(n);
        if let Some(chunk) = self.data.get(self.pos..self.pos + take) {
            out.extend_from_slice(chunk);
        }
        self.pos += take;
        if take < n {
            self.err = Some(LzoError::Eof);
        }
    }

    fn read_u8(&mut self) -> std::result::Result<u8, LzoError> {
        let Some(&byte) = self.data.get(self.pos) else {
            return Err(LzoError::Eof);
        };
        self.pos += 1;
        Ok(byte)
    }

    fn read_u16(&mut self) -> std::result::Result<usize, LzoError> {
        let Some(&[low, high, ..]) = self.data.get(self.pos..) else {
            return Err(LzoError::Eof);
        };
        self.pos += 2;
        Ok(usize::from(u16::from_le_bytes([low, high])))
    }

    fn read_multi(&mut self, base: usize) -> std::result::Result<usize, LzoError> {
        let mut total = 0usize;
        while let Some(&value) = self.data.get(self.pos) {
            self.pos += 1;
            if value == 0 {
                total += 255;
                continue;
            }
            return Ok(total + usize::from(value) + base);
        }
        self.err = Some(LzoError::Eof);
        Err(LzoError::Eof)
    }
}

fn copy_match(out: &mut Vec<u8>, m_pos: usize, n: usize) -> std::result::Result<(), LzoError> {
    if m_pos >= out.len() {
        return Err(LzoError::LookBehindUnderrun);
    }
    if m_pos + n > out.len() {
        for index in 0..n {
            let Some(&byte) = out.get(m_pos + index) else {
                return Err(LzoError::LookBehindUnderrun);
            };
            out.push(byte);
        }
    } else {
        out.extend_from_within(m_pos..m_pos + n);
    }
    Ok(())
}

/// Where the next match copies from and how long it is, or the stream terminator.
enum MatchHeader {
    /// Continue at `CopyMatch`: copy `len + 2` bytes from `m_pos`.
    Copy { m_pos: isize, len: usize, last2: u8 },
    /// The 2-byte copy is already done; continue at `MatchDone`.
    ShortCopy { m_pos: isize, last2: u8 },
    /// The stream terminator ended the input.
    End,
}

/// Decodes the `Match` state's offset/length header. The offsets reach back from the current
/// output end, so negative values are look-behind underruns.
fn decode_match_header(
    reader: &mut LzoReader<'_>,
    out: &mut Vec<u8>,
    ip: u8,
) -> std::result::Result<MatchHeader, LzoError> {
    let t = usize::from(ip);
    let out_len = out.len();
    if t >= 64 {
        let mut m_pos = out_len.cast_signed() - 1;
        m_pos -= ((t >> 2) & 7).cast_signed();
        let next = reader.read_u8()?;
        m_pos -= isize::from(next) << 3;
        return Ok(MatchHeader::Copy { m_pos, len: (t >> 5) - 1, last2: ip });
    }
    if t >= 32 {
        let mut len = t & 31;
        if len == 0 {
            len = reader.read_multi(31)?;
        }
        let mut m_pos = out_len.cast_signed() - 1;
        let v16 = reader.read_u16()?;
        m_pos -= (v16 >> 2).cast_signed();
        let [last2, ..] = v16.to_le_bytes();
        return Ok(MatchHeader::Copy { m_pos, len, last2 });
    }
    if t >= 16 {
        let mut m_pos = out_len.cast_signed();
        m_pos -= ((t & 8) << 11).cast_signed();
        let mut len = t & 7;
        if len == 0 {
            len = reader.read_multi(7)?;
        }
        let v16 = reader.read_u16()?;
        m_pos -= (v16 >> 2).cast_signed();
        if m_pos == out_len.cast_signed() {
            return Ok(MatchHeader::End);
        }
        m_pos -= 0x4000;
        let [last2, ..] = v16.to_le_bytes();
        return Ok(MatchHeader::Copy { m_pos, len, last2 });
    }
    let mut m_pos = out_len.cast_signed() - 1;
    m_pos -= (t >> 2).cast_signed();
    let next = reader.read_u8()?;
    m_pos -= isize::from(next) << 2;
    if m_pos < 0 {
        return Err(LzoError::LookBehindUnderrun);
    }
    copy_match(out, m_pos.cast_unsigned(), 2)?;
    Ok(MatchHeader::ShortCopy { m_pos, last2: ip })
}

/// The jump targets of the LZO1X decompressor.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    BeginLoop,
    FirstLiteralRun,
    Match,
    CopyMatch,
    MatchDone,
    MatchNext,
    MatchEnd,
}

/// LZO1X decompression. The algorithm's jump graph is kept as an explicit state
/// machine so every jump keeps its exact target. The stream terminator ends decompression.
fn decompress1x(input: &[u8]) -> std::result::Result<Vec<u8>, LzoError> {
    let mut reader = LzoReader::new(input);
    let mut out: Vec<u8> = Vec::new();
    let mut t: usize = 0;
    let mut m_pos: isize = 0;
    let mut last2: u8 = 0;

    let mut ip = reader.read_u8()?;
    let mut state = if usize::from(ip) > 17 {
        t = usize::from(ip) - 17;
        if t < 4 {
            State::MatchNext
        } else {
            reader.read_append(&mut out, t);
            State::FirstLiteralRun
        }
    } else {
        State::BeginLoop
    };

    loop {
        match state {
            State::BeginLoop => {
                t = usize::from(ip);
                if t >= 16 {
                    state = State::Match;
                    continue;
                }
                if t == 0 {
                    t = reader.read_multi(15)?;
                }
                reader.read_append(&mut out, t + 3);
                state = State::FirstLiteralRun;
            }
            State::FirstLiteralRun => {
                ip = reader.read_u8()?;
                last2 = ip;
                t = usize::from(ip);
                if t >= 16 {
                    state = State::Match;
                    continue;
                }
                m_pos = out.len().cast_signed() - (1 + M2_MAX_OFFSET.cast_signed());
                m_pos -= (t >> 2).cast_signed();
                ip = reader.read_u8()?;
                m_pos -= isize::from(ip) << 2;
                if m_pos < 0 {
                    return Err(LzoError::LookBehindUnderrun);
                }
                copy_match(&mut out, m_pos.cast_unsigned(), 3)?;
                state = State::MatchDone;
            }
            State::Match => {
                reader.rebuffer();
                if let Some(err) = reader.err {
                    return Err(err);
                }
                state = match decode_match_header(&mut reader, &mut out, ip)? {
                    MatchHeader::Copy { m_pos: pos, len, last2: byte } => {
                        m_pos = pos;
                        t = len;
                        last2 = byte;
                        State::CopyMatch
                    }
                    MatchHeader::ShortCopy { m_pos: pos, last2: byte } => {
                        m_pos = pos;
                        last2 = byte;
                        State::MatchDone
                    }
                    MatchHeader::End => return Ok(out),
                };
            }
            State::CopyMatch => {
                if m_pos < 0 {
                    return Err(LzoError::LookBehindUnderrun);
                }
                copy_match(&mut out, m_pos.cast_unsigned(), t + 2)?;
                state = State::MatchDone;
            }
            State::MatchDone => {
                t = usize::from(last2 & 3);
                state = if t == 0 { State::MatchEnd } else { State::MatchNext };
            }
            State::MatchNext => {
                reader.read_append(&mut out, t);
                ip = reader.read_u8()?;
                state = State::Match;
            }
            State::MatchEnd => {
                ip = reader.read_u8()?;
                state = State::BeginLoop;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn assert_known_answer(input: &[u8], compressed_hex: &str) {
        let mut wire = vec![LZO_COMPRESS_LZO];
        wire.extend(hex_decode(compressed_hex));
        let decompressed = lzo1x_decompress_safe(&wire).expect("decompress known-answer vector");
        assert_eq!(decompressed, input);
    }

    /// A known-answer round trip over random data.
    #[test]
    fn lzo1x_safe_round_trip() {
        let mut data = vec![0u8; 1024];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut data);
        let compressed = lzo1x_compress_safe(&data).unwrap();
        let decompressed = lzo1x_decompress_safe(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    /// Known-answer vector for `b"hello world"`.
    #[test]
    fn lzo1x_known_answer_short() {
        assert_known_answer(b"hello world", "1c68656c6c6f20776f726c64110000");
    }

    /// Known-answer vector: `compressed_hex` is the LZO1X compression of 200 repeats of `b"AB"`.
    #[test]
    fn lzo1x_known_answer_repetitive() {
        let input = b"AB".repeat(200);
        assert_known_answer(&input, "0341424142414220006a0400110000");
    }

    /// Known-answer vector: `compressed_hex` is the LZO1X compression of 300 random bytes.
    #[test]
    fn lzo1x_known_answer_incompressible() {
        let input = hex_decode("e3cc3311e67f7e23d15af8befcb4021269faf5dc46c934f8b9ae65ee95b536463d6eb7abd845e3805a725b7bc6f6cd05e4249dcad5f566e61bfccd2d69855a4b762001e4c5d6d581925e74be758b8077cb90dc18d00904c78fc5de222ab4f2a4016d2843b6771d04a02b2befbc034ef4af7a4fc05ef0336ed2a6566916534627cad8cd6c3ddd86bd9b310e4fd1bd3ac2a776d738483ae4b7e764b72062c919cf9f791b1d320a4b615be4fbd90b2a1fe33f88cd7f7abc616d2d2f006c569c6a2b4134a7464ce44431d2ccdb1b000f4d126dfb5ee39754d838cad6987836e4c4c63bba3ccadddbe67a8671d406329bc2cf3a791748579006f50e2830bf91ac8f57789cbd1243dba506c5eaf440bb1b44e72a8de8fac4e29c3e48ec20c3a8bc796aafdf10fd1314d450d0e7d69a");
        assert_known_answer(
            &input,
            "00001be3cc3311e67f7e23d15af8befcb4021269faf5dc46c934f8b9ae65ee95b536463d6eb7abd845e3805a725b7bc6f6cd05e4249dcad5f566e61bfccd2d69855a4b762001e4c5d6d581925e74be758b8077cb90dc18d00904c78fc5de222ab4f2a4016d2843b6771d04a02b2befbc034ef4af7a4fc05ef0336ed2a6566916534627cad8cd6c3ddd86bd9b310e4fd1bd3ac2a776d738483ae4b7e764b72062c919cf9f791b1d320a4b615be4fbd90b2a1fe33f88cd7f7abc616d2d2f006c569c6a2b4134a7464ce44431d2ccdb1b000f4d126dfb5ee39754d838cad6987836e4c4c63bba3ccadddbe67a8671d406329bc2cf3a791748579006f50e2830bf91ac8f57789cbd1243dba506c5eaf440bb1b44e72a8de8fac4e29c3e48ec20c3a8bc796aafdf10fd1314d450d0e7d69a110000",
        );
    }

    /// Known-answer vector: `compressed_hex` is the LZO1X compression of 112 repeats of a 45-byte
    /// sentence. It exercises a long-length M3 match (distance 45) whose zero-length
    /// extension spans multiple bytes through `read_multi`.
    #[test]
    fn lzo1x_known_answer_long_match() {
        let pattern = b"The quick brown fox jumps over the lazy dog. ";
        let mut input = Vec::new();
        while input.len() < 5000 {
            input.extend_from_slice(pattern);
        }
        assert_known_answer(
            &input,
            "002054686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e205468652071200000000000000000000000000000000000000070b000110000",
        );
    }
}

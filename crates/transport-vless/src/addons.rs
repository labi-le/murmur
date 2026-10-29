use std::io;

use anyhow::{anyhow, Result};

use super::config_pb::Addons;

/// A byte reader over the input, as a varint decoder needs.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    const fn len(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_byte(&mut self) -> io::Result<u8> {
        match self.data.get(self.pos) {
            Some(byte) => {
                self.pos += 1;
                Ok(*byte)
            }
            None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")),
        }
    }

    fn read_full(&mut self, dst: &mut [u8]) -> io::Result<()> {
        if self.len() < dst.len() {
            let err = if self.len() == 0 {
                io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
            } else {
                io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
            };
            return Err(err);
        }
        let (_, rest) = self.data.split_at(self.pos);
        let (src, _tail) = rest.split_at(dst.len());
        dst.copy_from_slice(src);
        self.pos += dst.len();
        Ok(())
    }
}

const MAX_VARINT_LEN64: usize = 10;

fn varint_overflow() -> io::Error {
    io::Error::other("binary: varint overflows a 64-bit integer")
}

fn read_uvarint(reader: &mut Reader<'_>) -> io::Result<u64> {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for i in 0..MAX_VARINT_LEN64 {
        let b = match reader.read_byte() {
            Ok(b) => b,
            Err(err) => {
                if i == MAX_VARINT_LEN64 - 1 && err.kind() == io::ErrorKind::UnexpectedEof {
                    return Err(varint_overflow());
                }
                return Err(err);
            }
        };
        if b < 0x80 {
            if i == MAX_VARINT_LEN64 - 1 && b > 1 {
                return Err(varint_overflow());
            }
            return Ok(x | u64::from(b) << s);
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
    }
    Err(varint_overflow())
}

pub fn read_addons(data: &[u8]) -> Result<Addons> {
    let mut reader = Reader::new(data);
    let mut addons = Addons::default();
    while reader.len() > 0 {
        let tag = read_uvarint(&mut reader)?;
        let number = tag >> 3;
        let typ = (tag & 7) as u8;
        match typ {
            // VARINT
            0 => {
                read_uvarint(&mut reader)?;
            }
            // I32
            5 => {
                let mut i32_bytes = [0u8; 4];
                reader.read_full(&mut i32_bytes)?;
            }
            // I64
            1 => {
                let mut i64_bytes = [0u8; 8];
                reader.read_full(&mut i64_bytes)?;
            }
            // LEN
            2 => {
                let bytes_len = usize::try_from(read_uvarint(&mut reader)?)?;
                let mut bytes_data = vec![0u8; bytes_len];
                reader.read_full(&mut bytes_data)?;
                match number {
                    1 => addons.flow = String::from_utf8_lossy(&bytes_data).into_owned(),
                    2 => addons.seed = bytes_data,
                    _ => {}
                }
            }
            // group (3,4) has been deprecated we unneeded support
            _ => return Err(anyhow!("unknown protobuf message tag: {tag}")),
        }
    }
    Ok(addons)
}

#[must_use]
pub fn write_addons(addons: &Addons) -> Vec<u8> {
    let mut writer = Vec::new();
    if !addons.flow.is_empty() {
        write_uvarint(&mut writer, (1 << 3) | 2); // (field << 3) bit-or wire_type encoded as uint32 varint
        write_uvarint(&mut writer, addons.flow.len() as u64);
        writer.extend_from_slice(addons.flow.as_bytes());
    }
    if !addons.seed.is_empty() {
        write_uvarint(&mut writer, (2 << 3) | 2); // (field << 3) bit-or wire_type encoded as uint32 varint
        write_uvarint(&mut writer, addons.seed.len() as u64);
        writer.extend_from_slice(&addons.seed);
    }
    writer
}

pub fn write_uvarint(writer: &mut Vec<u8>, mut x: u64) {
    while x >= 0x80 {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the group written is the low 7 bits of `x`; bit 7 is the continuation flag set here"
        )]
        writer.push(x as u8 | 0x80);
        x >>= 7;
    }
    #[expect(clippy::cast_possible_truncation, reason = "the loop above exits only once `x < 0x80`")]
    writer.push(x as u8);
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use crate::vless::{XRS, XRV};

    use super::*;

    #[test]
    fn test_addons() {
        let tests: [(&str, Vec<u8>); 4] =
            [(XRV, Vec::new()), (XRS, vec![1, 2, 3]), ("", vec![1, 2, 3]), ("", Vec::new())];

        for (i, (flow, seed)) in tests.iter().enumerate() {
            // proto->handwritten
            {
                let addons = Addons { flow: (*flow).to_owned(), seed: seed.clone() };

                let addons_bytes = addons.encode_to_vec();
                let addons = match read_addons(&addons_bytes) {
                    Ok(addons) => addons,
                    Err(err) => panic!("test {i}: error reading addons: {err}"),
                };

                assert_eq!(&addons.flow, flow, "test {i}");
                assert_eq!(&addons.seed, seed, "test {i}");
            }

            // handwritten->proto
            {
                let addons = Addons { flow: (*flow).to_owned(), seed: seed.clone() };

                let addons_bytes = write_addons(&addons);
                let addons = match Addons::decode(&mut &addons_bytes[..]) {
                    Ok(addons) => addons,
                    Err(err) => panic!("test {i}: error reading addons: {err}"),
                };

                assert_eq!(&addons.flow, flow, "test {i}");
                assert_eq!(&addons.seed, seed, "test {i}");
            }

            // handwritten->handwritten
            {
                let addons = Addons { flow: (*flow).to_owned(), seed: seed.clone() };

                let addons_bytes = write_addons(&addons);
                let addons = match read_addons(&addons_bytes) {
                    Ok(addons) => addons,
                    Err(err) => panic!("test {i}: error reading addons: {err}"),
                };

                assert_eq!(&addons.flow, flow, "test {i}");
                assert_eq!(&addons.seed, seed, "test {i}");
            }
        }
    }
}

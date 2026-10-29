use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

use thiserror::Error;

/// The decode errors, matched on by variant in `cache.rs`.
/// `OpenFailed` is the bare file-open failure, which `cache.rs` never matches on — it falls to that
/// function's default "give up" arm.
#[derive(Error, Debug)]
pub(crate) enum DecodeError {
    #[error("failed to read bytes")]
    FailedToReadBytes,
    #[error("failed to read expected length of bytes")]
    FailedToReadExpectedLenBytes,
    #[error("invalid geodata file")]
    InvalidGeodataFile,
    #[error("invalid geodata varint length")]
    InvalidGeodataVarintLength,
    #[error("code not found")]
    CodeNotFound,
    #[error("failed to open file: {filename}, base error: {source}")]
    OpenFailed { filename: String, source: std::io::Error },
}

use DecodeError::{
    CodeNotFound, FailedToReadBytes, FailedToReadExpectedLenBytes, InvalidGeodataFile, InvalidGeodataVarintLength,
};

/// Folded into a single-byte read: end of stream maps to `CodeNotFound`, any other
/// error to `FailedToReadBytes` (an unexpected-EOF error cannot occur on a 1-byte read).
fn read_byte<R: Read>(reader: &mut R) -> Result<u8, DecodeError> {
    let mut b = [0u8; 1];
    match reader.read(&mut b) {
        Ok(0) => Err(CodeNotFound),
        Ok(_) => Ok(b[0]),
        Err(_) => Err(FailedToReadBytes),
    }
}

/// A full read of `buf`: zero bytes read is `CodeNotFound`, a short read is
/// `FailedToReadExpectedLenBytes`, any other I/O error is `FailedToReadBytes`.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), DecodeError> {
    let mut total = 0usize;
    while total < buf.len() {
        let Some(rest) = buf.get_mut(total..) else {
            return Err(FailedToReadBytes);
        };
        match reader.read(rest) {
            Ok(0) => return Err(if total == 0 { CodeNotFound } else { FailedToReadExpectedLenBytes }),
            Ok(n) => total += n,
            Err(_) => return Err(FailedToReadBytes),
        }
    }
    Ok(())
}

/// Consumes a varint, restricted to the already-delimited byte sequence `read_length` builds (its
/// last byte always has the continuation bit clear).
fn consume_varint(buf: &[u8]) -> Option<u64> {
    let mut value: u64 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i >= 10 {
            return None;
        }
        value |= u64::from(b & 0x7f) << (7 * i);
        if b < 0x80 {
            return Some(value);
        }
    }
    None
}

fn read_length<R: Read>(reader: &mut R, length_bytes: &mut Vec<u8>) -> Result<u64, DecodeError> {
    length_bytes.clear();
    loop {
        let b = read_byte(reader)?;
        length_bytes.push(b);
        if b < 128 {
            return consume_varint(length_bytes).ok_or(InvalidGeodataVarintLength);
        }
    }
}

fn remaining_bytes<F: Read + Seek>(reader: &mut BufReader<F>, file_len: u64) -> Result<u64, DecodeError> {
    let position = reader.stream_position().map_err(|_| FailedToReadBytes)?;
    Ok(file_len.saturating_sub(position))
}

/// `reader.seek_relative` handles the buffered discard or bare seek this needs.
#[expect(
    clippy::indexing_slicing,
    reason = "`length >= prefix_length` is checked before the header is written, so every write \
              stays inside the `length`-byte buffer"
)]
fn emit_bytes<F: Read + Seek>(mut f: F, code: &str) -> Result<Vec<u8>, DecodeError> {
    let file_len = f.seek(SeekFrom::End(0)).map_err(|_| FailedToReadBytes)?;
    f.seek(SeekFrom::Start(0)).map_err(|_| FailedToReadBytes)?;
    let mut reader = BufReader::with_capacity(16 * 1024, f);
    let mut length_bytes: Vec<u8> = Vec::new();

    loop {
        let b = read_byte(&mut reader)?;
        if b != 10 {
            return Err(InvalidGeodataFile);
        }
        let length = read_length(&mut reader, &mut length_bytes)?;

        let b = read_byte(&mut reader)?;
        if b != 10 {
            return Err(InvalidGeodataFile);
        }
        let code_length = read_length(&mut reader, &mut length_bytes)?;

        // A declared length larger than the file cannot be a real record, and must not reach an
        // allocation that aborts on it.
        if code_length > remaining_bytes(&mut reader, file_len)? {
            return Err(FailedToReadExpectedLenBytes);
        }
        let name_length = usize::try_from(code_length).map_err(|_| FailedToReadExpectedLenBytes)?;
        let mut name = vec![0u8; name_length];
        read_full(&mut reader, &mut name)?;

        let prefix_length = 1 + length_bytes.len() as u64 + code_length;
        if length < prefix_length || length - prefix_length > remaining_bytes(&mut reader, file_len)? {
            return Err(FailedToReadExpectedLenBytes);
        }
        if String::from_utf8_lossy(&name).eq_ignore_ascii_case(code) {
            let result_length = usize::try_from(length).map_err(|_| FailedToReadExpectedLenBytes)?;
            let mut result = vec![0u8; result_length];
            let mut n = 0;
            result[n] = 10;
            n += 1;
            result[n..n + length_bytes.len()].copy_from_slice(&length_bytes);
            n += length_bytes.len();
            result[n..n + name.len()].copy_from_slice(&name);
            n += name.len();
            read_full(&mut reader, &mut result[n..]).map_err(|err| {
                if matches!(err, CodeNotFound) {
                    FailedToReadExpectedLenBytes
                } else {
                    err
                }
            })?;
            return Ok(result);
        }

        let offset = i64::try_from(length - prefix_length).map_err(|_| FailedToReadExpectedLenBytes)?;
        reader.seek_relative(offset).map_err(|_| FailedToReadBytes)?;
    }
}

pub(crate) fn decode(filename: &str, code: &str) -> Result<Vec<u8>, DecodeError> {
    let f = File::open(filename).map_err(|source| DecodeError::OpenFailed { filename: filename.to_owned(), source })?;
    emit_bytes(f, code)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn a_code_length_past_the_end_of_the_file_is_rejected_not_allocated() {
        // Outer `0A`, a zero-length record, inner `0A`, then a code-length varint of `u64::MAX`
        // over a 13-byte file.
        let file = vec![0x0A, 0x00, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        let err = emit_bytes(Cursor::new(file), "cn").unwrap_err();
        assert!(matches!(err, FailedToReadExpectedLenBytes), "got {err}");
    }

    #[test]
    fn a_record_length_past_the_end_of_the_file_is_rejected_not_allocated() {
        let mut file = vec![0x0A];
        file.extend([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]);
        file.extend([0x0A, 0x02, b'c', b'n']);
        let err = emit_bytes(Cursor::new(file), "cn").unwrap_err();
        assert!(matches!(err, FailedToReadExpectedLenBytes), "got {err}");
    }

    #[test]
    fn a_record_shorter_than_its_reencoded_header_is_rejected_not_indexed() {
        // Record length 3 with code length 2: the re-encoded header alone is 4 bytes.
        let file = vec![0x0A, 0x03, 0x0A, 0x02, b'c', b'n'];
        let err = emit_bytes(Cursor::new(file), "cn").unwrap_err();
        assert!(matches!(err, FailedToReadExpectedLenBytes), "got {err}");
    }

    #[test]
    fn a_well_formed_record_still_decodes_to_its_reencoded_entry() {
        let file = vec![0x0A, 0x06, 0x0A, 0x02, b'c', b'n', 0x12, 0x00];
        let decoded = emit_bytes(Cursor::new(file), "cn").unwrap();
        assert_eq!(decoded, vec![0x0A, 0x02, b'c', b'n', 0x12, 0x00]);
    }

    #[test]
    fn a_non_matching_record_shorter_than_its_header_is_rejected_on_the_skip_path() {
        // Record length 0 with code name `xy`: a skip must not walk backwards into the record.
        let file = vec![0x0A, 0x00, 0x0A, 0x02, b'x', b'y'];
        let err = emit_bytes(Cursor::new(file), "cn").unwrap_err();
        assert!(matches!(err, FailedToReadExpectedLenBytes), "got {err}");
    }

    #[test]
    fn a_non_matching_record_with_an_overflowing_length_is_rejected_on_the_skip_path() {
        // A `u64::MAX` length whose signed subtraction would go negative.
        let mut file = vec![0x0A];
        file.extend([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]);
        file.extend([0x0A, 0x02, b'x', b'y']);
        let err = emit_bytes(Cursor::new(file), "cn").unwrap_err();
        assert!(matches!(err, FailedToReadExpectedLenBytes), "got {err}");
    }
}

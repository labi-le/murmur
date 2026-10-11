use std::fs::File;
use std::io::{BufReader, Read, Seek};

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

/// `reader.seek_relative` handles the buffered discard or bare seek this needs.
#[expect(
    clippy::indexing_slicing,
    reason = "the record header is written at a running cursor; a declared length below the header \
              size is malformed and must fail loudly instead of being silently clamped"
)]
fn emit_bytes<F: Read + Seek>(f: F, code: &str) -> Result<Vec<u8>, DecodeError> {
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

        let mut name = vec![0u8; usize::try_from(code_length).unwrap_or(usize::MAX)];
        read_full(&mut reader, &mut name)?;

        let prefix_length = 1 + length_bytes.len() as u64 + code_length;
        if String::from_utf8_lossy(&name).eq_ignore_ascii_case(code) {
            let mut result = vec![0u8; usize::try_from(length).unwrap_or(usize::MAX)];
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

        let offset = length.cast_signed() - prefix_length.cast_signed();
        reader.seek_relative(offset).map_err(|_| FailedToReadBytes)?;
    }
}

pub(crate) fn decode(filename: &str, code: &str) -> Result<Vec<u8>, DecodeError> {
    let f = File::open(filename).map_err(|source| DecodeError::OpenFailed { filename: filename.to_owned(), source })?;
    emit_bytes(f, code)
}

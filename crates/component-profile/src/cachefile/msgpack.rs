//! Minimal MessagePack codec for the two values the cachefile stores.
//!
//! A struct is a map keyed by field name, the hash type goes through its binary marshaler, and a
//! timestamp is the timestamp extension with type id -1.

use std::mem::size_of;

use anyhow::anyhow;
use chrono::{DateTime, Utc};

use super::etag::EtagWithHash;
use super::storage::StorageData;
use murmur_common::time::zero_time;
use murmur_common::utils::hash::HashType;

const NIL: u8 = 0xc0;
const BIN8: u8 = 0xc4;
const BIN16: u8 = 0xc5;
const BIN32: u8 = 0xc6;
const EXT8: u8 = 0xc7;
const EXT16: u8 = 0xc8;
const EXT32: u8 = 0xc9;
const FIXEXT1: u8 = 0xd4;
const FIXEXT2: u8 = 0xd5;
const FIXEXT4: u8 = 0xd6;
const FIXEXT8: u8 = 0xd7;
const FIXEXT16: u8 = 0xd8;
const STR8: u8 = 0xd9;
const STR16: u8 = 0xda;
const STR32: u8 = 0xdb;
const ARRAY16: u8 = 0xdc;
const ARRAY32: u8 = 0xdd;
const MAP16: u8 = 0xde;
const MAP32: u8 = 0xdf;
const TIME_EXT_ID: u8 = 0xff;

#[must_use]
pub fn encode_etag_with_hash(value: &EtagWithHash) -> Vec<u8> {
    let mut out = Vec::new();
    encode_map_len(&mut out, 3);
    encode_str(&mut out, "Hash");
    encode_bin(&mut out, value.hash.bytes());
    encode_str(&mut out, "ETag");
    encode_str(&mut out, &value.etag);
    encode_str(&mut out, "Time");
    encode_time(&mut out, &value.time);
    out
}

pub fn decode_etag_with_hash(data: &[u8]) -> anyhow::Result<EtagWithHash> {
    let mut value = EtagWithHash::default();
    let mut reader = Reader { data, offset: 0 };
    for _ in 0..read_map_len(&mut reader)? {
        let key = read_str(&mut reader)?;
        match key.as_str() {
            "Hash" => {
                let mut hash = HashType::default();
                hash.unmarshal_binary(&read_bin(&mut reader)?)?;
                value.hash = hash;
            }
            "ETag" => value.etag = read_str(&mut reader)?,
            "Time" => value.time = read_time(&mut reader)?,
            _ => skip_value(&mut reader)?,
        }
    }
    Ok(value)
}

/// Encodes the storage-data map form.
///
/// Takes the payload by borrow so a large value is not copied before it reaches the encoder.
#[must_use]
pub fn encode_storage_data(data: &[u8], time: &DateTime<Utc>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_map_len(&mut out, 2);
    encode_str(&mut out, "Data");
    encode_bin(&mut out, data);
    encode_str(&mut out, "Time");
    encode_time(&mut out, time);
    out
}

pub fn decode_storage_data(data: &[u8]) -> anyhow::Result<StorageData> {
    let mut value = StorageData::default();
    let mut reader = Reader { data, offset: 0 };
    for _ in 0..read_map_len(&mut reader)? {
        let key = read_str(&mut reader)?;
        match key.as_str() {
            "Data" => value.data = read_bin(&mut reader)?,
            "Time" => value.time = read_time(&mut reader)?,
            _ => skip_value(&mut reader)?,
        }
    }
    Ok(value)
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> anyhow::Result<u8> {
        let byte = *self.data.get(self.offset).ok_or_else(|| anyhow!("msgpack: unexpected end of input"))?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, len: usize) -> anyhow::Result<&[u8]> {
        let end = self.offset.checked_add(len).ok_or_else(|| anyhow!("msgpack: invalid length"))?;
        let bytes = self.data.get(self.offset..end).ok_or_else(|| anyhow!("msgpack: unexpected end of input"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> anyhow::Result<u16> {
        let bytes: [u8; 2] = self.take(size_of::<u16>())?.try_into().map_err(corrupt)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> anyhow::Result<u32> {
        let bytes: [u8; 4] = self.take(size_of::<u32>())?.try_into().map_err(corrupt)?;
        Ok(u32::from_be_bytes(bytes))
    }
}

fn read_map_len(reader: &mut Reader<'_>) -> anyhow::Result<u32> {
    let code = reader.u8()?;
    match code {
        // the array form of a struct is accepted as well as the map form.
        0x80..=0x9f => Ok(u32::from(code & 0x0f)),
        MAP16 | ARRAY16 => Ok(u32::from(reader.u16()?)),
        MAP32 | ARRAY32 => reader.u32(),
        _ => Err(anyhow!("msgpack: expected a map, got code {code:#x}")),
    }
}

fn read_str(reader: &mut Reader<'_>) -> anyhow::Result<String> {
    let code = reader.u8()?;
    let len = match code {
        0xa0..=0xbf => u32::from(code & 0x1f),
        STR8 => u32::from(reader.u8()?),
        STR16 => u32::from(reader.u16()?),
        STR32 => reader.u32()?,
        _ => return Err(anyhow!("msgpack: expected a string, got code {code:#x}")),
    };
    let bytes = reader.take(len as usize)?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn read_bin(reader: &mut Reader<'_>) -> anyhow::Result<Vec<u8>> {
    let code = reader.u8()?;
    if code == NIL {
        return Ok(Vec::new());
    }
    let len = match code {
        BIN8 => u32::from(reader.u8()?),
        BIN16 => u32::from(reader.u16()?),
        BIN32 => reader.u32()?,
        _ => return Err(anyhow!("msgpack: expected binary, got code {code:#x}")),
    };
    Ok(reader.take(len as usize)?.to_vec())
}

fn read_time(reader: &mut Reader<'_>) -> anyhow::Result<DateTime<Utc>> {
    let code = reader.u8()?;
    if code == NIL {
        return Ok(zero_time());
    }

    let (seconds, nanos) = match code {
        FIXEXT4 | FIXEXT8 => {
            if reader.u8()? != TIME_EXT_ID {
                return Err(anyhow!("msgpack: unsupported extension decoding time"));
            }
            if code == FIXEXT4 {
                (i64::from(u32::from_be_bytes(reader.take(size_of::<u32>())?.try_into().map_err(corrupt)?)), 0)
            } else {
                let data = u64::from_be_bytes(reader.take(size_of::<u64>())?.try_into().map_err(corrupt)?);
                ((data & 0x0000_0003_ffff_ffff).cast_signed(), (data >> 34) as u32)
            }
        }
        EXT8 | EXT16 | EXT32 => {
            let len = read_ext_len(reader, code)?;
            if reader.u8()? != TIME_EXT_ID {
                return Err(anyhow!("msgpack: unsupported extension decoding time"));
            }
            if len != 12 {
                return Err(anyhow!("msgpack: invalid ext len={len} decoding time"));
            }
            let nanos = u32::from_be_bytes(reader.take(size_of::<u32>())?.try_into().map_err(corrupt)?);
            let seconds = i64::from_be_bytes(reader.take(size_of::<u64>())?.try_into().map_err(corrupt)?);
            (seconds, nanos)
        }
        _ => return Err(anyhow!("msgpack: expected a timestamp, got code {code:#x}")),
    };

    DateTime::from_timestamp(seconds, nanos).ok_or_else(|| anyhow!("msgpack: time out of range"))
}

fn read_ext_len(reader: &mut Reader<'_>, code: u8) -> anyhow::Result<u32> {
    match code {
        EXT8 => Ok(u32::from(reader.u8()?)),
        EXT16 => Ok(u32::from(reader.u16()?)),
        EXT32 => reader.u32(),
        _ => Err(anyhow!("msgpack: expected an extension, got code {code:#x}")),
    }
}

fn corrupt(_: std::array::TryFromSliceError) -> anyhow::Error {
    anyhow!("msgpack: truncated value")
}

fn skip_value(reader: &mut Reader<'_>) -> anyhow::Result<()> {
    let code = reader.u8()?;
    match code {
        // null, never-used, false, true, positive and negative fixint
        0x00..=0x7f | 0xc0..=0xc3 | 0xe0..=0xff => Ok(()),
        0xa0..=0xbf => take_count(reader, u32::from(code & 0x1f)),
        0x90..=0x9f => skip_count(reader, u32::from(code & 0x0f), false),
        0x80..=0x8f => skip_count(reader, u32::from(code & 0x0f), true),
        BIN8 | STR8 => {
            let len = u32::from(reader.u8()?);
            take_count(reader, len)
        }
        BIN16 | STR16 => {
            let len = u32::from(reader.u16()?);
            take_count(reader, len)
        }
        BIN32 | STR32 => {
            let len = reader.u32()?;
            take_count(reader, len)
        }
        ARRAY16 => {
            let len = u32::from(reader.u16()?);
            skip_count(reader, len, false)
        }
        ARRAY32 => {
            let len = reader.u32()?;
            skip_count(reader, len, false)
        }
        MAP16 => {
            let len = u32::from(reader.u16()?);
            skip_count(reader, len, true)
        }
        MAP32 => {
            let len = reader.u32()?;
            skip_count(reader, len, true)
        }
        0xca | 0xce | 0xd2 => take_count(reader, 4),
        0xcb | 0xcf | 0xd3 => take_count(reader, 8),
        0xcc | 0xd0 => take_count(reader, 1),
        0xcd | 0xd1 | FIXEXT1 => take_count(reader, 2),
        FIXEXT2 => take_count(reader, 3),
        FIXEXT4 => take_count(reader, 5),
        FIXEXT8 => take_count(reader, 9),
        FIXEXT16 => take_count(reader, 17),
        EXT8 | EXT16 | EXT32 => {
            let len = read_ext_len(reader, code)?;
            take_count(reader, len + 1)
        }
    }
}

fn take_count(reader: &mut Reader<'_>, len: u32) -> anyhow::Result<()> {
    reader.take(len as usize)?;
    Ok(())
}

fn skip_count(reader: &mut Reader<'_>, len: u32, pairs: bool) -> anyhow::Result<()> {
    for _ in 0..len {
        skip_value(reader)?;
        if pairs {
            skip_value(reader)?;
        }
    }
    Ok(())
}

/// The low four bytes of `len`, the width of the widest MessagePack length form.
fn low_u32(len: usize) -> u32 {
    u32::try_from(len & 0xffff_ffff).unwrap_or_default()
}

fn encode_map_len(out: &mut Vec<u8>, len: usize) {
    if len < 16 {
        out.push(0x80 | u8::try_from(len).unwrap_or_default());
    } else if let Ok(len) = u16::try_from(len) {
        out.push(MAP16);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        out.push(MAP32);
        out.extend_from_slice(&low_u32(len).to_be_bytes());
    }
}

fn encode_str(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = bytes.len();
    if len < 32 {
        out.push(0xa0 | u8::try_from(len).unwrap_or_default());
    } else if let Ok(len) = u8::try_from(len) {
        out.push(STR8);
        out.push(len);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(STR16);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        out.push(STR32);
        out.extend_from_slice(&low_u32(len).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

fn encode_bin(out: &mut Vec<u8>, value: &[u8]) {
    let len = value.len();
    if let Ok(len) = u8::try_from(len) {
        out.push(BIN8);
        out.push(len);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(BIN16);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        out.push(BIN32);
        out.extend_from_slice(&low_u32(len).to_be_bytes());
    }
    out.extend_from_slice(value);
}

fn encode_time(out: &mut Vec<u8>, value: &DateTime<Utc>) {
    let seconds = value.timestamp().cast_unsigned();
    let nanos = value.timestamp_subsec_nanos();

    if seconds >> 34 == 0 {
        let data = (u64::from(nanos) << 34) | seconds;
        if let Ok(data) = u32::try_from(data) {
            out.push(FIXEXT4);
            out.push(TIME_EXT_ID);
            out.extend_from_slice(&data.to_be_bytes());
        } else {
            out.push(FIXEXT8);
            out.push(TIME_EXT_ID);
            out.extend_from_slice(&data.to_be_bytes());
        }
    } else {
        out.push(EXT8);
        out.push(12);
        out.push(TIME_EXT_ID);
        out.extend_from_slice(&nanos.to_be_bytes());
        out.extend_from_slice(&seconds.to_be_bytes());
    }
}

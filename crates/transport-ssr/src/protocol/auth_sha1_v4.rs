use std::sync::Arc;

use anyhow::Result;
use bytes::{Buf as _, BufMut as _, BytesMut};

use crate::tools::buf_pool::append_rand_bytes;
use crate::tools::crypto::hmac_sha1;
use murmur_common_net::io::Stream;
use murmur_common_net::EnhancePacketConn;
use murmur_common_pool as pool;

use super::base::{AuthData, Base};
use super::protocol::{
    err_auth_sha1_v4_adler32_error, err_auth_sha1_v4_crc32_error, err_auth_sha1_v4_length_error, get_data_length,
    register, Protocol, ProtocolList,
};
use super::stream::Conn as ProtocolConn;

/// the `init` registering `auth_sha1_v4`.
pub(crate) fn init(list: &mut ProtocolList) {
    register(list, "auth_sha1_v4", new_auth_sha1_v4, 7);
}
pub(crate) struct AuthSHA1V4 {
    base: Base,
    auth_data: AuthData,
    iv: Vec<u8>,
    has_sent_header: bool,
    raw_trans: bool,
}

pub(crate) fn new_auth_sha1_v4(b: &Base) -> Box<dyn Protocol> {
    Box::new(AuthSHA1V4 {
        base: b.clone(),
        auth_data: AuthData::default(),
        iv: Vec::new(),
        has_sent_header: false,
        raw_trans: false,
    })
}

impl Protocol for AuthSHA1V4 {
    fn stream_conn(&self, c: Box<dyn Stream>, iv: &[u8]) -> Box<dyn Stream> {
        let p = Self {
            base: self.base.clone(),
            auth_data: self.auth_data.next(),
            iv: iv.to_vec(),
            has_sent_header: false,
            raw_trans: false,
        };
        Box::new(ProtocolConn::new(c, Box::new(p)))
    }

    /// Returns the conn unchanged.
    fn packet_conn(&self, c: Arc<dyn EnhancePacketConn>) -> Arc<dyn EnhancePacketConn> {
        c
    }

    fn decode(&mut self, dst: &mut BytesMut, src: &mut BytesMut) -> Result<()> {
        if self.raw_trans {
            dst.extend_from_slice(&src.copy_to_bytes(src.remaining()));
            return Ok(());
        }
        while src.len() > 4 {
            let Some(&[b0, b1, b2, b3, ..]) = src.get(..4) else {
                break;
            };
            if (crc32fast::hash(&[b0, b1]) & 0xffff) as u16 != u16::from_le_bytes([b2, b3]) {
                src.clear();
                return Err(err_auth_sha1_v4_crc32_error());
            }

            let length = usize::from(u16::from_be_bytes([b0, b1]));
            if !(7..8192).contains(&length) {
                self.raw_trans = true;
                src.clear();
                return Err(err_auth_sha1_v4_length_error());
            }
            if length > src.len() {
                break;
            }

            let Some(adler_bytes) = src.get(length - 4..length) else {
                break;
            };
            let adler = u32::from_le_bytes(adler_bytes.try_into().unwrap_or_default());
            if adler32_checksum(src.get(..length - 4).unwrap_or_default()) != adler {
                self.raw_trans = true;
                src.clear();
                return Err(err_auth_sha1_v4_adler32_error());
            }

            let Some(&[marker, pos_hi, pos_lo, ..]) = src.get(4..) else {
                break;
            };
            let mut pos = usize::from(marker);
            if pos < 255 {
                pos += 4;
            } else {
                pos = usize::from(u16::from_be_bytes([pos_hi, pos_lo])) + 4;
            }
            // DEVIATION: a frame whose body starts past `length - 4` is rejected as a length error
            // instead of slicing out of bounds.
            if pos > length - 4 {
                self.raw_trans = true;
                src.clear();
                return Err(err_auth_sha1_v4_length_error());
            }
            dst.extend_from_slice(src.get(pos..length - 4).unwrap_or_default());
            let _ = src.split_to(length);
        }
        Ok(())
    }

    fn encode(&mut self, buf: &mut BytesMut, b: &[u8]) -> Result<()> {
        let mut b = b;
        if !self.has_sent_header {
            let data_length = usize::try_from(get_data_length(b)).map_err(|_| err_auth_sha1_v4_length_error())?;
            let (auth_data, rest) = b.split_at(data_length);
            self.pack_auth_data(buf, auth_data);
            b = rest;

            self.has_sent_header = true;
        }
        while b.len() > 8100 {
            let (chunk, rest) = b.split_at(8100);
            pack_data(buf, chunk);
            b = rest;
        }
        if !b.is_empty() {
            pack_data(buf, b);
        }

        Ok(())
    }

    fn decode_packet(&mut self, b: &[u8]) -> Result<Vec<u8>> {
        Ok(b.to_vec())
    }

    fn encode_packet(&mut self, buf: &mut BytesMut, b: &[u8]) -> Result<()> {
        buf.extend_from_slice(b);
        Ok(())
    }
}

impl AuthSHA1V4 {
    fn pack_auth_data(&self, pool_buf: &mut BytesMut, data: &[u8]) {
        let data_length = data.len();
        let rand_data_length = get_rand_data_length(12 + data_length);
        /*
            2:	uint16 BigEndian packedAuthDataLength
            4:	uint32 LittleEndian crc32Data
            3:	maxRandDataLengthPrefix (min: 1)
            12:	authDataLength
            10:	hmacSHA1DataLength
        */
        let mut packed_auth_data_length = 2 + 4 + 3 + rand_data_length + 12 + data_length + 10;
        if rand_data_length < 128 {
            packed_auth_data_length -= 2;
        }
        let packed_auth_data_length = low_u16(packed_auth_data_length);

        let salt = b"auth_sha1_v4";
        let mut crc_data = pool::get(salt.len() + self.base.key.len() + 2);
        let (length_field, rest) = crc_data.split_at_mut(2);
        length_field.copy_from_slice(&packed_auth_data_length.to_be_bytes());
        let (salt_field, key_field) = rest.split_at_mut(salt.len());
        salt_field.copy_from_slice(salt);
        key_field.copy_from_slice(&self.base.key);

        let mut key = pool::get(self.iv.len() + self.base.key.len());
        let (iv_field, key_field) = key.split_at_mut(self.iv.len());
        iv_field.copy_from_slice(&self.iv);
        key_field.copy_from_slice(&self.base.key);

        let frame_start = pool_buf.len();
        pool_buf.extend_from_slice(&packed_auth_data_length.to_be_bytes());
        pool_buf.put_u32_le(crc32fast::hash(&crc_data));
        pack_rand_data(pool_buf, rand_data_length);
        self.auth_data.put_auth_data(pool_buf);
        pool_buf.extend_from_slice(data);
        let hmac = hmac_sha1(&key, pool_buf.get(frame_start..).unwrap_or_default());
        let (hmac_prefix, _) = hmac.split_at(10);
        pool_buf.extend_from_slice(hmac_prefix);

        pool::put(crc_data).ok();
        pool::put(key).ok();
    }
}

/// The low 8 bits of `value`, the width of the protocol's one-byte rand-data length prefix.
fn low_u8(value: usize) -> u8 {
    let [b0, ..] = value.to_le_bytes();
    b0
}

/// The low 16 bits of `value`, the width of the protocol's length fields.
fn low_u16(value: usize) -> u16 {
    let [b0, b1, ..] = value.to_le_bytes();
    u16::from_le_bytes([b0, b1])
}

fn pack_data(pool_buf: &mut BytesMut, data: &[u8]) {
    let data_length = data.len();
    let rand_data_length = get_rand_data_length(data_length);
    /*
        2:	uint16 BigEndian packedDataLength
        2:	uint16 LittleEndian crc32Data & 0xffff
        3:	maxRandDataLengthPrefix (min:1)
        4:	adler32Data
    */
    let mut packed_data_length = 2 + 2 + 3 + rand_data_length + data_length + 4;
    if rand_data_length < 128 {
        packed_data_length -= 2;
    }

    let frame_start = pool_buf.len();
    let packed_data_length = low_u16(packed_data_length);
    pool_buf.put_u16(packed_data_length);
    let crc32 = (crc32fast::hash(&packed_data_length.to_be_bytes()) & 0xffff) as u16;
    pool_buf.put_u16_le(crc32);
    pack_rand_data(pool_buf, rand_data_length);
    pool_buf.extend_from_slice(data);
    pool_buf.put_u32_le(adler32_checksum(pool_buf.get(frame_start..).unwrap_or_default()));
}

fn pack_rand_data(pool_buf: &mut BytesMut, size: usize) {
    if size < 128 {
        pool_buf.put_u8(low_u8(size + 1));
        append_rand_bytes(pool_buf, size);
        return;
    }
    pool_buf.put_u8(255);
    pool_buf.put_u16(low_u16(size + 3));
    append_rand_bytes(pool_buf, size);
}

fn get_rand_data_length(size: usize) -> usize {
    if size > 1200 {
        return 0;
    }
    if size > 400 {
        return rand::random_range(0..256);
    }
    rand::random_range(0..512)
}

fn adler32_checksum(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::super::protocol::{get_head_size, Protocol as _};
    use super::*;
    use crate::tools::random::XorShift128Plus;

    fn key16(b: u8) -> Vec<u8> {
        (0..16u8).map(|i| b + i).collect()
    }

    fn data_of(n: usize, v: u8) -> Vec<u8> {
        vec![v; n]
    }

    fn digest(b: &[u8]) -> String {
        use md5::{Digest as _, Md5};
        use sha1::Sha1;
        let m = Md5::digest(b);
        let s = Sha1::digest(b);
        format!("len={} md5={} sha1={}", b.len(), hex::encode(m.as_slice()), hex::encode(s.as_slice()))
    }

    fn new_proto(key: &[u8], iv: &[u8]) -> AuthSHA1V4 {
        AuthSHA1V4 {
            base: Base { key: key.to_vec(), overhead: 0, param: String::new() },
            auth_data: AuthData::default(),
            iv: iv.to_vec(),
            has_sent_header: false,
            raw_trans: false,
        }
    }

    #[test]
    fn pack_data_v1_matches_known_vector() {
        let mut buf = BytesMut::new();
        pack_data(&mut buf, &data_of(8100, 0x5a));
        assert_eq!(
            "len=8109 md5=fb9fbc5b313e1ec0aebc4a854e6ef02b sha1=bdb2c5a14c97817f19ff75c98f3109c6fe4ff597",
            digest(&buf)
        );
    }

    #[test]
    fn v1_decode_recovers_payload() {
        let mut buf = BytesMut::new();
        pack_data(&mut buf, &data_of(8100, 0x5a));

        let mut s = new_proto(&key16(11), &key16(12));
        let mut dst = BytesMut::new();
        let mut src = buf.clone();
        s.decode(&mut dst, &mut src).unwrap();
        assert_eq!(data_of(8100, 0x5a), &dst[..]);
        assert!(src.is_empty(), "the whole packet is consumed");
    }

    #[test]
    fn decode_rejects_frame_whose_payload_offset_exceeds_its_length() {
        // Only an unkeyed CRC-32 and Adler-32 gate this decoder, so a malicious SSR server can
        // forge a frame whose `pos` byte lands past `length - 4` without any key material.
        let mut a = new_proto(&key16(11), &key16(12));
        let mut src = BytesMut::from(&[0u8, 8, 205, 154, 112, 1, 80, 2][..]);
        let mut dst = BytesMut::new();
        let err = a.decode(&mut dst, &mut src).unwrap_err();
        assert!(err.to_string().contains("length"), "expected a length error, got {err}");
    }

    #[test]
    fn adler32_matches_known_vector() {
        assert_eq!(300_286_872, adler32_checksum(b"Wikipedia"));
        assert_eq!(1, adler32_checksum(&[]));
    }

    #[test]
    fn get_head_size_table() {
        assert_eq!(30, get_head_size(&[], 30));
        assert_eq!(30, get_head_size(&[0x01], 30));
        assert_eq!(7, get_head_size(&[0x01, 0x00], 30));
        assert_eq!(19, get_head_size(&[0x04, 0x00], 30));
        assert_eq!(9, get_head_size(&[0x03, 0x05], 30));
        assert_eq!(30, get_head_size(&[0x02, 0x00], 30));
        assert_eq!(13, get_head_size(&[0x0b, 0x09], 30));
    }

    #[test]
    fn get_data_length_bounds() {
        let b = data_of(64, 0x02);
        let n = get_data_length(&b);
        assert!((30..=61).contains(&n), "{n}");
        assert_eq!(10, get_data_length(&data_of(10, 0x02)));
    }

    #[test]
    fn xorshift128_plus_matches_known_vector() {
        let mut r = XorShift128Plus::default();
        r.init_from_bin(&key16(1));
        let mut got = Vec::new();
        for _ in 0..8 {
            got.push(r.next_u64());
        }
        assert_eq!(
            vec![
                3069514155717595923,
                2777903849066675630,
                9029865344244674215,
                17360054589986511017,
                15795691717983355365,
                21792535218811883,
                3308991197650913735,
                1774032466174672517
            ],
            got
        );
    }

    #[test]
    fn a1_auth_header_structure() {
        let key = key16(11);
        let iv = key16(12);
        let data = data_of(40, 0x5a);
        let a = new_proto(&key, &iv);
        let mut buf = BytesMut::new();
        a.pack_auth_data(&mut buf, &data);

        assert_eq!(buf.len(), u16::from_be_bytes([buf[0], buf[1]]) as usize, "packedAuthDataLength");
        let mut crc_data = Vec::new();
        crc_data.extend_from_slice(&buf[..2]);
        crc_data.extend_from_slice(b"auth_sha1_v4");
        crc_data.extend_from_slice(&key);
        assert_eq!(crc32fast::hash(&crc_data), u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]));

        let mut hmac_key = iv.clone();
        hmac_key.extend_from_slice(&key);
        assert_eq!(&hmac_sha1(&hmac_key, &buf[..buf.len() - 10])[..10], &buf[buf.len() - 10..]);

        let (prefix, rand_len) = if buf[6] == 255 {
            (3usize, u16::from_be_bytes([buf[7], buf[8]]) as usize - 3)
        } else {
            (1usize, buf[6] as usize - 1)
        };
        assert!(rand_len < 512, "{rand_len}");
        let auth_at = 6 + prefix + rand_len;
        assert_eq!(vec![0u8; 8], buf[auth_at + 4..auth_at + 12].to_vec(), "zero authData for a fresh instance");
        assert_eq!(data, buf[auth_at + 12..buf.len() - 10].to_vec(), "payload follows the authData");
    }
}

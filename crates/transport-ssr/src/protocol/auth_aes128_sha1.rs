use std::sync::Arc;

use anyhow::Result;
use bytes::{Buf as _, BufMut as _, BytesMut};
use rand::rngs::OsRng;
use rand::TryRngCore as _;

use crate::tools::buf_pool::append_rand_bytes;
use crate::tools::crypto::{hmac_sha1, sha1_sum};
use murmur_common_net::io::Stream;
use murmur_common_net::EnhancePacketConn;
use murmur_common_pool as pool;
use murmur_log::warnln;

use super::base::{AuthData, Base, UserData};
use super::protocol::{
    err_auth_aes128_chksum_error, err_auth_aes128_length_error, err_auth_aes128_mac_error, get_data_length, register,
    Protocol, ProtocolList,
};
use super::stream::Conn as ProtocolConn;

pub(crate) type HmacMethod = fn(&[u8], &[u8]) -> Vec<u8>;

pub(crate) type HashDigestMethod = fn(&[u8]) -> Vec<u8>;

/// The low 8 bits of `value`, the width of the protocol's short random-length prefix.
fn low_u8(value: i32) -> u8 {
    let [b0, ..] = value.to_le_bytes();
    b0
}

/// The low 16 bits of `value`, the width of the protocol's length fields.
fn low_u16(value: i32) -> u16 {
    let [b0, b1, ..] = value.to_le_bytes();
    u16::from_le_bytes([b0, b1])
}

fn len_usize(value: i32) -> usize {
    usize::try_from(value).unwrap_or_default()
}

/// the `init` registering `auth_aes128_sha1`.
pub(crate) fn init(list: &mut ProtocolList) {
    register(list, "auth_aes128_sha1", new_auth_aes128_sha1, 9);
}
pub(crate) struct AuthAES128Function {
    pub(crate) salt: &'static str,
    pub(crate) hmac: HmacMethod,
    pub(crate) hash_digest: HashDigestMethod,
}
pub(crate) struct AuthAES128 {
    base: Base,
    auth_data: AuthData,
    auth_aes128_function: Arc<AuthAES128Function>,
    user_data: UserData,
    iv: Vec<u8>,
    has_sent_header: bool,
    raw_trans: bool,
    pack_id: u32,
    recv_id: u32,
}

/// Builds an auth-AES128 instance: the struct literal plus the user-data init both variants make.
pub(crate) fn new_auth_aes128(
    b: &Base,
    auth_data: AuthData,
    auth_aes128_function: Arc<AuthAES128Function>,
    user_data: UserData,
) -> AuthAES128 {
    let mut a = AuthAES128 {
        base: b.clone(),
        auth_data,
        auth_aes128_function,
        user_data,
        iv: Vec::new(),
        has_sent_header: false,
        raw_trans: false,
        pack_id: 0,
        recv_id: 0,
    };
    a.init_user_data();
    a
}

pub(crate) fn new_auth_aes128_sha1(b: &Base) -> Box<dyn Protocol> {
    Box::new(new_auth_aes128(
        b,
        AuthData::default(),
        Arc::new(AuthAES128Function { salt: "auth_aes128_sha1", hmac: hmac_sha1, hash_digest: sha1_sum }),
        UserData::default(),
    ))
}

impl AuthAES128 {
    fn init_user_data(&mut self) {
        let mut params = self.base.param.split(':');
        if let (Some(user_id_str), Some(user_key_str)) = (params.next(), params.next()) {
            if let Ok(user_id) = user_id_str.parse::<u32>() {
                self.user_data.user_id.copy_from_slice(&user_id.to_le_bytes());
                self.user_data.user_key = (self.auth_aes128_function.hash_digest)(user_key_str.as_bytes());
            } else {
                warnln!(
                    "Wrong protocol-param for {}, only digits are expected before ':'",
                    self.auth_aes128_function.salt
                );
            }
        }
        if self.user_data.user_key.is_empty() {
            self.user_data.user_key = self.base.key.clone();
            let _ = OsRng.try_fill_bytes(&mut self.user_data.user_id);
        }
    }
}

impl Protocol for AuthAES128 {
    fn stream_conn(&self, c: Box<dyn Stream>, iv: &[u8]) -> Box<dyn Stream> {
        let p = Self {
            base: self.base.clone(),
            auth_data: self.auth_data.next(),
            auth_aes128_function: Arc::clone(&self.auth_aes128_function),
            user_data: self.user_data.clone(),
            iv: iv.to_vec(),
            has_sent_header: false,
            raw_trans: false,
            pack_id: 1,
            recv_id: 1,
        };
        Box::new(ProtocolConn::new(c, Box::new(p)))
    }

    fn packet_conn(&self, c: Arc<dyn EnhancePacketConn>) -> Arc<dyn EnhancePacketConn> {
        let p = Self {
            base: self.base.clone(),
            auth_data: AuthData::default(),
            auth_aes128_function: Arc::clone(&self.auth_aes128_function),
            user_data: self.user_data.clone(),
            iv: Vec::new(),
            has_sent_header: false,
            raw_trans: false,
            pack_id: 0,
            recv_id: 0,
        };
        Arc::new(super::packet::PacketConn::new(c, Box::new(p)))
    }

    fn decode(&mut self, dst: &mut BytesMut, src: &mut BytesMut) -> Result<()> {
        if self.raw_trans {
            dst.extend_from_slice(&src.copy_to_bytes(src.remaining()));
            return Ok(());
        }
        while src.len() > 4 {
            let mut mac_key = pool::get(self.user_data.user_key.len() + 4);
            let (key_part, id_part) = mac_key.split_at_mut(self.user_data.user_key.len());
            key_part.copy_from_slice(&self.user_data.user_key);
            id_part.copy_from_slice(&self.recv_id.to_le_bytes());

            let (head, _) = src.split_at(4);
            let (len_field, frame_mac) = head.split_at(2);
            let [b0, b1] = len_field else { break };
            let length = usize::from(u16::from_le_bytes([*b0, *b1]));
            let mac = (self.auth_aes128_function.hmac)(&mac_key, len_field);
            if !mac.starts_with(frame_mac) {
                src.clear();
                pool::put(mac_key).ok();
                return Err(err_auth_aes128_mac_error());
            }

            if !(7..8192).contains(&length) {
                self.raw_trans = true;
                src.clear();
                pool::put(mac_key).ok();
                return Err(err_auth_aes128_length_error());
            }
            if length > src.len() {
                pool::put(mac_key).ok();
                break;
            }

            let (header, _) = src.split_at(7);
            let (_, pos_field) = header.split_at(4);
            let [pos_byte, pos_lo, pos_hi] = pos_field else { break };
            let mut pos = usize::from(*pos_byte);
            if pos < 255 {
                pos += 4;
            } else {
                pos = usize::from(u16::from_le_bytes([*pos_lo, *pos_hi])) + 4;
            }

            let (mac_input, tail) = src.split_at(length - 4);
            let (checksum, _) = tail.split_at(4);
            let mac = (self.auth_aes128_function.hmac)(&mac_key, mac_input);
            if !mac.starts_with(checksum) {
                self.raw_trans = true;
                src.clear();
                pool::put(mac_key).ok();
                return Err(err_auth_aes128_chksum_error());
            }

            self.recv_id += 1;

            // DEVIATION: a frame whose body starts past `length - 4` is rejected as a length error
            // instead of slicing out of bounds.
            if pos > length - 4 {
                self.raw_trans = true;
                src.clear();
                pool::put(mac_key).ok();
                return Err(err_auth_aes128_length_error());
            }
            let (_, from_pos) = src.split_at(pos);
            let (payload, _) = from_pos.split_at(length - 4 - pos);
            dst.extend_from_slice(payload);
            let _ = src.split_to(length);
            pool::put(mac_key).ok();
        }
        Ok(())
    }

    fn encode(&mut self, buf: &mut BytesMut, b: &[u8]) -> Result<()> {
        let full_data_length = i32::try_from(b.len()).unwrap_or(i32::MAX);
        let mut b = b;
        if !self.has_sent_header {
            let (auth_data, rest) = b.split_at(len_usize(get_data_length(b)));
            self.pack_auth_data(buf, auth_data);
            b = rest;
            self.has_sent_header = true;
        }
        while b.len() > 8100 {
            let (chunk, rest) = b.split_at(8100);
            self.pack_data(buf, chunk, full_data_length);
            b = rest;
        }
        if !b.is_empty() {
            self.pack_data(buf, b, full_data_length);
        }
        Ok(())
    }

    fn decode_packet(&mut self, b: &[u8]) -> Result<Vec<u8>> {
        if b.len() < 4 {
            return Err(err_auth_aes128_length_error());
        }
        let (body, frame_mac) = b.split_at(b.len() - 4);
        let mac = (self.auth_aes128_function.hmac)(&self.base.key, body);
        if !mac.starts_with(frame_mac) {
            return Err(err_auth_aes128_chksum_error());
        }
        Ok(body.to_vec())
    }

    fn encode_packet(&mut self, buf: &mut BytesMut, b: &[u8]) -> Result<()> {
        buf.extend_from_slice(b);
        buf.extend_from_slice(&self.user_data.user_id);
        let hmac = (self.auth_aes128_function.hmac)(&self.user_data.user_key, buf);
        buf.extend_from_slice(hmac.get(..4).unwrap_or_default());
        Ok(())
    }
}

impl AuthAES128 {
    fn pack_data(&mut self, pool_buf: &mut BytesMut, data: &[u8], full_data_length: i32) {
        let data_length = i32::try_from(data.len()).unwrap_or(i32::MAX);
        let rand_data_length = self.get_rand_data_length_for_pack_data(data_length, full_data_length);
        /*
            2:	uint16 LittleEndian packedDataLength
            2:	hmac of packedDataLength
            3:	maxRandDataLengthPrefix (min:1)
            4:	hmac of packedData except the last 4 bytes
        */
        let mut packed_data_length = 2 + 2 + 3 + rand_data_length + data_length + 4;
        if rand_data_length < 128 {
            packed_data_length -= 2;
        }

        let mut mac_key = pool::get(self.user_data.user_key.len() + 4);
        let (key_part, id_part) = mac_key.split_at_mut(self.user_data.user_key.len());
        key_part.copy_from_slice(&self.user_data.user_key);
        id_part.copy_from_slice(&self.pack_id.to_le_bytes());
        self.pack_id += 1;

        let packed_length = low_u16(packed_data_length);
        pool_buf.put_u16_le(packed_length);
        let mac = (self.auth_aes128_function.hmac)(&mac_key, &packed_length.to_le_bytes());
        pool_buf.extend_from_slice(mac.get(..2).unwrap_or_default());
        self.pack_rand_data(pool_buf, rand_data_length);
        pool_buf.extend_from_slice(data);
        let mac_start = pool_buf.len() + 4 - len_usize(packed_data_length);
        let (_, mac_input) = pool_buf.split_at(mac_start);
        let mac = (self.auth_aes128_function.hmac)(&mac_key, mac_input);
        pool_buf.extend_from_slice(mac.get(..4).unwrap_or_default());
        pool::put(mac_key).ok();
    }

    fn get_rand_data_length_for_pack_data(&self, data_length: i32, full_data_length: i32) -> i32 {
        if full_data_length >= 32 * 1024 - self.base.overhead {
            return 0;
        }
        // 1460: tcp_mss
        let rev_length = 1460 - data_length - 9;
        if rev_length == 0 {
            return 0;
        }
        if rev_length < 0 {
            if rev_length > -1460 {
                return trapezoid_random(rev_length + 1460, -0.3);
            }
            return rand::random_range(0..32);
        }
        if data_length > 900 {
            return rand::random_range(0..rev_length);
        }
        trapezoid_random(rev_length, -0.3)
    }

    fn pack_auth_data(&self, pool_buf: &mut BytesMut, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let data_length = i32::try_from(data.len()).unwrap_or(i32::MAX);
        let rand_data_length = Self::get_rand_data_length_for_pack_auth_data(data_length);
        /*
            7:	checkHead(1) and hmac of checkHead(6)
            4:	userID
            16:	encrypted data of authdata(12), uint16 BigEndian packedDataLength(2) and uint16 BigEndian randDataLength(2)
            4:	hmac of userID and encrypted data
            4:	hmac of packedAuthData except the last 4 bytes
        */
        let packed_auth_data_length = 7 + 4 + 16 + 4 + rand_data_length + data_length + 4;

        let mut mac_key = pool::get(self.iv.len() + self.base.key.len());
        let (iv_part, key_part) = mac_key.split_at_mut(self.iv.len());
        iv_part.copy_from_slice(&self.iv);
        key_part.copy_from_slice(&self.base.key);

        pool_buf.put_u8(rand::random_range(0..=255u8));
        let mac = (self.auth_aes128_function.hmac)(&mac_key, pool_buf);
        pool_buf.extend_from_slice(mac.get(..6).unwrap_or_default());
        pool_buf.extend_from_slice(&self.user_data.user_id);
        if self
            .auth_data
            .put_encrypted_data(
                pool_buf,
                &self.user_data.user_key,
                [packed_auth_data_length, rand_data_length],
                self.auth_aes128_function.salt,
            )
            .is_err()
        {
            pool_buf.clear();
            pool::put(mac_key).ok();
            return;
        }
        let (_, auth_mac_input) = pool_buf.split_at(7);
        let mac = (self.auth_aes128_function.hmac)(&mac_key, auth_mac_input);
        pool_buf.extend_from_slice(mac.get(..4).unwrap_or_default());
        append_rand_bytes(pool_buf, len_usize(rand_data_length));
        pool_buf.extend_from_slice(data);
        let mac = (self.auth_aes128_function.hmac)(&self.user_data.user_key, pool_buf);
        pool_buf.extend_from_slice(mac.get(..4).unwrap_or_default());
        pool::put(mac_key).ok();
    }

    fn get_rand_data_length_for_pack_auth_data(size: i32) -> i32 {
        if size > 400 {
            return rand::random_range(0..512);
        }
        rand::random_range(0..1024)
    }

    #[expect(clippy::unused_self, reason = "the unit tests below drive this helper as a method")]
    fn pack_rand_data(&self, pool_buf: &mut BytesMut, size: i32) {
        let size_usize = len_usize(size);
        if size < 128 {
            pool_buf.put_u8(low_u8(size + 1));
            append_rand_bytes(pool_buf, size_usize);
            return;
        }
        pool_buf.put_u8(255);
        pool_buf.put_u16_le(low_u16(size + 3));
        append_rand_bytes(pool_buf, size_usize);
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the sampled float is truncated toward zero into the protocol's int length"
)]
fn trapezoid_random(max: i32, d: f64) -> i32 {
    let mut base = rand::random::<f64>();
    if d - 0.0 > 1e-6 {
        let a = 1.0 - d;
        base = ((4.0 * d).mul_add(base, a * a).sqrt() - a) / (2.0 * d);
    }
    (base * f64::from(max)) as i32
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aes::Aes128;
    use bytes::BytesMut;

    use super::super::base::{AuthData, UserData};
    use super::super::protocol::Protocol as _;
    use super::*;
    use crate::tools::crypto::{hmac_md5, hmac_sha1, md5_sum, sha1_sum};

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

    fn new_proto(salt: &'static str, hmac: HmacMethod, hash_digest: HashDigestMethod) -> AuthAES128 {
        AuthAES128 {
            base: Base { key: key16(11), overhead: 9, param: String::new() },
            auth_data: AuthData::default(),
            auth_aes128_function: Arc::new(AuthAES128Function { salt, hmac, hash_digest }),
            user_data: UserData { user_key: key16(21), user_id: [5, 6, 7, 8] },
            iv: Vec::new(),
            has_sent_header: false,
            raw_trans: false,
            pack_id: 7,
            recv_id: 7,
        }
    }

    #[test]
    fn pack_data_v3_sha1_matches_known_vector() {
        let mut x = new_proto("auth_aes128_sha1", hmac_sha1, sha1_sum);
        let mut buf = BytesMut::new();
        x.pack_data(&mut buf, &data_of(8100, 0x5a), 32768);
        assert_eq!(
            "len=8109 md5=60773dbaab63c15ca5e036dca39f571e sha1=7823e96d02e908cfcd2c662ad88f796afdc732ea",
            digest(&buf)
        );

        let mut s = new_proto("auth_aes128_sha1", hmac_sha1, sha1_sum);
        let mut dst = BytesMut::new();
        let mut src = buf.clone();
        s.decode(&mut dst, &mut src).unwrap();
        assert_eq!(data_of(8100, 0x5a), &dst[..]);
        assert!(src.is_empty());
        assert!(!s.raw_trans);
    }

    #[test]
    fn decode_rejects_frame_whose_payload_offset_exceeds_its_length() {
        let mut x = new_proto("auth_aes128_sha1", hmac_sha1, sha1_sum);
        // Built by computing the two real HMACs `decode` checks (over `src[..2]` and
        // `src[..length-4]`, both keyed with `user_key || recv_id`) so this frame passes both
        // checksum checks, and its declared `pos` byte (4) still lands past `length - 4` (4)
        // once added to the 4-byte header, matching the own `pos:length-4` slice.
        let mut src = BytesMut::from(&[8u8, 0, 40, 143, 120, 110, 253, 216][..]);
        let mut dst = BytesMut::new();
        let err = x.decode(&mut dst, &mut src).unwrap_err();
        assert!(err.to_string().contains("length"), "expected a length error, got {err}");
    }

    #[test]
    fn pack_data_v4_md5_matches_known_vector() {
        let mut x = new_proto("auth_aes128_md5", hmac_md5, md5_sum);
        let mut buf = BytesMut::new();
        x.pack_data(&mut buf, &data_of(8100, 0x5a), 32768);
        assert_eq!(
            "len=8109 md5=4fb469238c009052103023194eada141 sha1=54563c4ee7b18a00bb339936678577e2d72af052",
            digest(&buf)
        );

        let mut s = new_proto("auth_aes128_md5", hmac_md5, md5_sum);
        let mut dst = BytesMut::new();
        let mut src = buf.clone();
        s.decode(&mut dst, &mut src).unwrap();
        assert_eq!(data_of(8100, 0x5a), &dst[..]);
        assert!(src.is_empty());
        assert!(!s.raw_trans);
    }

    #[test]
    fn pack_rand_data_prefixes() {
        let x = new_proto("auth_aes128_sha1", hmac_sha1, sha1_sum);
        let mut buf = BytesMut::new();
        x.pack_rand_data(&mut buf, 0);
        assert_eq!(1, buf[0]);
        assert_eq!(1, buf.len());
        let mut buf = BytesMut::new();
        x.pack_rand_data(&mut buf, 200);
        assert_eq!(255, buf[0]);
        assert_eq!(203, u16::from_le_bytes([buf[1], buf[2]]));
        assert_eq!(203, buf.len());
    }

    #[test]
    fn trapezoid_random_bounds() {
        for _ in 0..64 {
            let v = trapezoid_random(1460, -0.3);
            assert!((0..1460).contains(&v), "{v}");
        }
    }

    fn check_auth_header(salt: &'static str, hmac: HmacMethod, hash_digest: HashDigestMethod) {
        use aes::cipher::{BlockCipherDecrypt as _, KeyInit as _};
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        use murmur_transport_shadowsocks::core::cipher::kdf;

        let key = key16(11);
        let iv = key16(12);
        let ukey = key16(21);
        let data = data_of(40, 0x5a);
        let mut x = new_proto(salt, hmac, hash_digest);
        x.iv = iv.clone();
        let mut buf = BytesMut::new();
        x.pack_auth_data(&mut buf, &data);

        let mut mac_key = iv;
        mac_key.extend_from_slice(&key);
        assert_eq!(&hmac(&mac_key, &buf[..1])[..6], &buf[1..7], "checkHead hmac");
        assert_eq!(&[5u8, 6, 7, 8], &buf[7..11], "userID");
        assert_eq!(&hmac(&mac_key, &buf[7..27])[..4], &buf[27..31], "authData hmac");
        assert_eq!(&hmac(&ukey, &buf[..buf.len() - 4])[..4], &buf[buf.len() - 4..], "packet hmac");

        let rand_len = buf.len() - 31 - data.len() - 4;
        let cipher_key = kdf(&format!("{}{salt}", STANDARD.encode(&ukey)), 16);
        let cipher = Aes128::new_from_slice(&cipher_key).unwrap();
        let mut block = aes::Block::from(<[u8; 16]>::try_from(&buf[11..27]).unwrap());
        cipher.decrypt_block(&mut block);
        let plain = block.as_slice();
        assert_eq!(buf.len() as u16, u16::from_le_bytes([plain[12], plain[13]]), "packedAuthDataLength");
        assert_eq!(rand_len as u16, u16::from_le_bytes([plain[14], plain[15]]), "randDataLength");
        assert_eq!(0, u32::from_le_bytes([plain[4], plain[5], plain[6], plain[7]]), "clientID");
        assert_eq!(0, u32::from_le_bytes([plain[8], plain[9], plain[10], plain[11]]), "connectionID");
    }

    #[test]
    fn auth_headers_match_known_vectors() {
        check_auth_header("auth_aes128_sha1", hmac_sha1, sha1_sum);
        check_auth_header("auth_aes128_md5", hmac_md5, md5_sum);
    }
}

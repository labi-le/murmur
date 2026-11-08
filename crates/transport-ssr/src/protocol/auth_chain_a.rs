use std::sync::Arc;

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::{Buf as _, BufMut as _, BytesMut};
use cipher::{InOutBuf, StreamCipher, StreamCipherError};
use rand::rngs::OsRng;
use rand::TryRngCore as _;

use crate::tools::buf_pool::append_rand_bytes;
use crate::tools::crypto::hmac_md5;
use crate::tools::random::XorShift128Plus;
use murmur_common_net::io::Stream as NetStream;
use murmur_common_net::EnhancePacketConn;
use murmur_common_pool as pool;
use murmur_log::warnln;
use murmur_transport_shadowsocks::core::cipher::kdf;

use super::base::{AuthData, Base, UserData};
use super::protocol::{
    err_auth_chain_chksum_error, err_auth_chain_length_error, err_ssr_crashing_blocked, get_data_length, register,
    Protocol, ProtocolList,
};
use super::stream::Conn as ProtocolConn;

/// the `init` registering `auth_chain_a`.
pub(crate) fn init(list: &mut ProtocolList) {
    register(list, "auth_chain_a", new_auth_chain_a, 4);
}

/// The per-stream random-data-length function: a boxed closure, which is how `auth_chain_b`
/// carries its size lists into the call.
pub(crate) type RandDataLengthMethod = Box<dyn Fn(i32, &mut [u8], &mut XorShift128Plus) -> i32 + Send + Sync>;
pub(crate) struct AuthChainA {
    pub(crate) base: Base,
    pub(crate) auth_data: AuthData,
    pub(crate) user_data: UserData,
    pub(crate) iv: Vec<u8>,
    pub(crate) salt: &'static str,
    pub(crate) has_sent_header: bool,
    pub(crate) raw_trans: bool,
    pub(crate) last_client_hash: Vec<u8>,
    pub(crate) last_server_hash: Vec<u8>,
    pub(crate) encrypter: Option<Box<dyn StreamCipher + Send + Sync>>,
    pub(crate) decrypter: Option<Box<dyn StreamCipher + Send + Sync>>,
    pub(crate) random_client: XorShift128Plus,
    pub(crate) random_server: XorShift128Plus,
    pub(crate) rand_data_length: Option<RandDataLengthMethod>,
    pub(crate) pack_id: u32,
    pub(crate) recv_id: u32,
}

pub(crate) fn new_auth_chain_a(b: &Base) -> Box<dyn Protocol> {
    Box::new(new_auth_chain_a_inner(b, AuthData::default(), "auth_chain_a"))
}

/// Builds an auth-chain-A instance: the struct literal plus the user-data init both chain prototypes make.
pub(crate) fn new_auth_chain_a_inner(b: &Base, auth_data: AuthData, salt: &'static str) -> AuthChainA {
    let mut a = new_auth_chain_a_literal(b, auth_data, UserData::default(), salt);
    a.init_user_data();
    a
}

/// The struct literal on its own: the copies the stream and packet conns build reuse the
/// prototype's user data and never run user-data init.
pub(crate) fn new_auth_chain_a_literal(
    b: &Base,
    auth_data: AuthData,
    user_data: UserData,
    salt: &'static str,
) -> AuthChainA {
    AuthChainA {
        base: b.clone(),
        auth_data,
        user_data,
        iv: Vec::new(),
        salt,
        has_sent_header: false,
        raw_trans: false,
        last_client_hash: Vec::new(),
        last_server_hash: Vec::new(),
        encrypter: None,
        decrypter: None,
        random_client: XorShift128Plus::default(),
        random_server: XorShift128Plus::default(),
        rand_data_length: None,
        pack_id: 0,
        recv_id: 0,
    }
}

/// The low 8 bits of `value`, the width of one RC4 state byte.
fn low_u8(value: usize) -> u8 {
    let [b0, ..] = value.to_le_bytes();
    b0
}

/// The low 16 bits of `value`, the width of the protocol's little-endian length field.
fn low_u16(value: usize) -> u16 {
    let [b0, b1, ..] = value.to_le_bytes();
    u16::from_le_bytes([b0, b1])
}

/// The low 32 bits of `value`, the width of the protocol's little-endian length fields.
fn low_i32(value: usize) -> i32 {
    let [b0, b1, b2, b3, ..] = value.to_le_bytes();
    i32::from_le_bytes([b0, b1, b2, b3])
}

/// The first `N` bytes of `hash`, the digest prefixes the wire format reads at fixed offsets.
fn digest_head<const N: usize>(hash: &[u8]) -> [u8; N] {
    let mut head = [0u8; N];
    if let Some(prefix) = hash.get(..N) {
        head.copy_from_slice(prefix);
    }
    head
}

impl AuthChainA {
    fn init_user_data(&mut self) {
        let params: Vec<&str> = self.base.param.split(':').collect();
        if let [first, second, ..] = params.as_slice() {
            if let Ok(user_id) = first.parse::<u32>() {
                self.user_data.user_id.copy_from_slice(&user_id.to_le_bytes());
                self.user_data.user_key = second.as_bytes().to_vec();
            } else {
                warnln!("Wrong protocol-param for {}, only digits are expected before ':'", self.salt);
            }
        }
        if self.user_data.user_key.is_empty() {
            self.user_data.user_key = self.base.key.clone();
            let _ = OsRng.try_fill_bytes(&mut self.user_data.user_id);
        }
    }

    ///
    /// `XORKeyStream` encrypts the caller's slice in place; a `&[u8]` cannot be mutated, so a copy
    /// is encrypted instead. No caller observes the difference: a write reports the
    /// pre-encryption length and never looks at its argument again.
    fn pack_data(&mut self, pool_buf: &mut BytesMut, data: &[u8]) {
        let mut data = data.to_vec();
        let Some(encrypter) = self.encrypter.as_mut() else {
            return;
        };
        encrypter.apply_keystream(&mut data);

        let mut mac_key = pool::get(self.user_data.user_key.len() + 4);
        let (key_part, id_part) = mac_key.split_at_mut(self.user_data.user_key.len());
        key_part.copy_from_slice(&self.user_data.user_key);
        id_part.copy_from_slice(&self.pack_id.to_le_bytes());
        self.pack_id += 1;

        let digest = digest_head::<16>(&self.last_client_hash);
        let length = low_u16(data.len()) ^ u16::from_le_bytes([digest[14], digest[15]]);

        let original_length = pool_buf.len();
        pool_buf.put_u16_le(length);
        self.put_mixed_rand_data_and_data(pool_buf, &data);
        let Some(mac_data) = pool_buf.get(original_length..) else {
            pool::put(mac_key).ok();
            return;
        };
        self.last_client_hash = hmac_md5(&mac_key, mac_data);
        pool_buf.extend_from_slice(&digest_head::<2>(&self.last_client_hash));
        pool::put(mac_key).ok();
    }

    fn put_mixed_rand_data_and_data(&mut self, pool_buf: &mut BytesMut, data: &[u8]) {
        let Some(method) = self.rand_data_length.as_ref() else {
            pool_buf.extend_from_slice(data);
            return;
        };
        let rand_data_length = method(low_i32(data.len()), &mut self.last_client_hash, &mut self.random_client);
        if data.is_empty() {
            append_rand_bytes(pool_buf, usize::try_from(rand_data_length).unwrap_or_default());
            return;
        }
        if rand_data_length > 0 {
            let start_pos = get_rand_start_pos(rand_data_length, &mut self.random_client);
            append_rand_bytes(pool_buf, usize::try_from(start_pos).unwrap_or_default());
            pool_buf.extend_from_slice(data);
            append_rand_bytes(pool_buf, usize::try_from(rand_data_length - start_pos).unwrap_or_default());
            return;
        }
        pool_buf.extend_from_slice(data);
    }

    /// Initializes the RC4 cipher; the cipher error is discarded, since a 16-byte key cannot
    /// hit it.
    fn init_rc4_cipher(&mut self) {
        let key = kdf(
            &format!("{}{}", STANDARD.encode(&self.user_data.user_key), STANDARD.encode(&self.last_client_hash)),
            16,
        );
        self.encrypter = Some(Box::new(Rc4::new(&key)));
        self.decrypter = Some(Box::new(Rc4::new(&key)));
    }

    fn pack_auth_data(&mut self, pool_buf: &mut BytesMut, data: &[u8]) {
        /*
            12:	four check-header bytes and an eight-byte hmac over them
            4:	uint32 LittleEndian uid, the user id XOR the last client hash
            16:	encrypted authdata of twelve bytes, a uint16 LittleEndian overhead and a uint16 LittleEndian zero
            4:	a four-byte last server hash
        */

        let mut mac_key = pool::get(self.iv.len() + self.base.key.len());
        let (iv_part, key_part) = mac_key.split_at_mut(self.iv.len());
        iv_part.copy_from_slice(&self.iv);
        key_part.copy_from_slice(&self.base.key);

        // check head
        append_rand_bytes(pool_buf, 4);
        self.last_client_hash = hmac_md5(&mac_key, pool_buf);
        self.init_rc4_cipher();
        pool_buf.extend_from_slice(&digest_head::<8>(&self.last_client_hash));
        // uid
        let digest = digest_head::<16>(&self.last_client_hash);
        let uid = u32::from_le_bytes(self.user_data.user_id)
            ^ u32::from_le_bytes([digest[8], digest[9], digest[10], digest[11]]);
        pool_buf.put_u32_le(uid);
        // encrypted data
        if self
            .auth_data
            .put_encrypted_data(pool_buf, &self.user_data.user_key, [self.base.overhead, 0], self.salt)
            .is_err()
        {
            pool_buf.clear();
            pool::put(mac_key).ok();
            return;
        }
        // last server hash
        let Some(server_hash_data) = pool_buf.get(12..) else {
            pool::put(mac_key).ok();
            return;
        };
        self.last_server_hash = hmac_md5(&self.user_data.user_key, server_hash_data);
        pool_buf.extend_from_slice(&digest_head::<4>(&self.last_server_hash));
        // packed data
        self.pack_data(pool_buf, data);
        pool::put(mac_key).ok();
    }
}

pub(crate) fn get_rand_start_pos(length: i32, random: &mut XorShift128Plus) -> i32 {
    if length == 0 {
        return 0;
    }
    let start_pos = (random.next_u64() % 8589934609).cast_signed() % i64::from(length);
    i32::try_from(start_pos).unwrap_or_default()
}

pub(crate) fn get_rand_length(length: i32, last_hash: &mut [u8], random: &mut XorShift128Plus) -> i32 {
    if length > 1440 {
        return 0;
    }
    random.init_from_bin_and_length(last_hash, usize::try_from(length).unwrap_or_default());
    if length > 1300 {
        return (random.next_u64() % 31) as i32;
    }
    if length > 900 {
        return (random.next_u64() % 127) as i32;
    }
    if length > 400 {
        return (random.next_u64() % 521) as i32;
    }
    (random.next_u64() % 1021) as i32
}

fn udp_get_rand_length(last_hash: &[u8], random: &mut XorShift128Plus) -> i32 {
    random.init_from_bin(last_hash);
    (random.next_u64() % 127) as i32
}

/// An RC4 cipher, hand-written because no RC4 crate is pinned. The shadowstream module keeps
/// its own private copy of the same cipher; this one is local to `auth_chain_a`, which needs a
/// stream-cipher implementation of its own.
struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// The `Kdf` output is always 16, so the key-length assert cannot fire.
    fn new(key: &[u8]) -> Self {
        let k = key.len();
        assert!((1..=256).contains(&k), "invalid RC4 key size {k}");
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = low_u8(i);
        }
        let mut j: u8 = 0;
        for (i, byte) in key.iter().cycle().take(256).enumerate() {
            j = j.wrapping_add(s.get(i).copied().unwrap_or_default()).wrapping_add(*byte);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    /// The state byte at `index`; a `u8` can only address the 256-byte state.
    fn state(&self, index: u8) -> u8 {
        self.s.get(usize::from(index)).copied().unwrap_or_default()
    }
}

impl StreamCipher for Rc4 {
    fn check_remaining(&self, _data_len: usize) -> Result<(), StreamCipherError> {
        Ok(())
    }

    fn unchecked_apply_keystream_inout(&mut self, buf: InOutBuf<'_, '_, u8>) {
        for v in buf.into_out_with_copied_in() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state(self.i));
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let k = self.state(self.i).wrapping_add(self.state(self.j));
            *v ^= self.state(k);
        }
    }

    fn unchecked_write_keystream(&mut self, buf: &mut [u8]) {
        buf.fill(0);
        self.unchecked_apply_keystream(buf);
    }
}

impl Protocol for AuthChainA {
    fn stream_conn(&self, c: Box<dyn NetStream>, iv: &[u8]) -> Box<dyn NetStream> {
        let mut p = new_auth_chain_a_literal(&self.base, self.auth_data.next(), self.user_data.clone(), self.salt);
        p.iv = iv.to_vec();
        p.pack_id = 1;
        p.recv_id = 1;
        p.rand_data_length = Some(Box::new(get_rand_length));
        Box::new(ProtocolConn::new(c, Box::new(p)))
    }

    fn packet_conn(&self, c: Arc<dyn EnhancePacketConn>) -> Arc<dyn EnhancePacketConn> {
        let p = new_auth_chain_a_literal(&self.base, AuthData::default(), self.user_data.clone(), self.salt);
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

            let digest = digest_head::<16>(&self.last_server_hash);
            let data_length = i32::from(
                u16::from_le_bytes(digest_head::<2>(src.as_ref())) ^ u16::from_le_bytes([digest[14], digest[15]]),
            );
            let Some(method) = self.rand_data_length.as_ref() else {
                pool::put(mac_key).ok();
                return Err(err_ssr_crashing_blocked());
            };
            let rand_data_length = method(data_length, &mut self.last_server_hash, &mut self.random_server);
            let length = data_length + rand_data_length;
            // A negative length would make the slices below run backwards, so reject the frame.
            if data_length < 0 || rand_data_length < 0 || length < 0 {
                pool::put(mac_key).ok();
                return Err(err_ssr_crashing_blocked());
            }
            // One conversion past the guard replaces a cast on every bound and slice below.
            let Ok(frame_length) = usize::try_from(length) else {
                pool::put(mac_key).ok();
                return Err(err_ssr_crashing_blocked());
            };

            if frame_length >= 4096 {
                self.raw_trans = true;
                src.clear();
                pool::put(mac_key).ok();
                return Err(err_auth_chain_length_error());
            }

            if frame_length + 4 > src.len() {
                pool::put(mac_key).ok();
                break;
            }

            let Some(mac_data) = src.get(..frame_length + 2) else {
                pool::put(mac_key).ok();
                break;
            };
            let server_hash = hmac_md5(&mac_key, mac_data);
            let Some(checksum) = src.get(frame_length + 2..frame_length + 4) else {
                pool::put(mac_key).ok();
                break;
            };
            if !server_hash.starts_with(checksum) {
                self.raw_trans = true;
                src.clear();
                pool::put(mac_key).ok();
                return Err(err_auth_chain_chksum_error());
            }
            self.last_server_hash = server_hash;

            let mut pos = 2;
            if data_length > 0 && rand_data_length > 0 {
                pos += get_rand_start_pos(rand_data_length, &mut self.random_server);
            }
            // DEVIATION: also rejects `recv_id == 1` frames with `data_length < 2`, which the
            // `wantedData[2:]` slice below would otherwise panic on.
            if pos < 0 || pos + data_length < 0 || data_length < 0 || (self.recv_id == 1 && data_length < 2) {
                pool::put(mac_key).ok();
                return Err(err_ssr_crashing_blocked());
            }

            let (Ok(pos), Ok(data_length)) = (usize::try_from(pos), usize::try_from(data_length)) else {
                pool::put(mac_key).ok();
                return Err(err_ssr_crashing_blocked());
            };
            let Some(decrypter) = self.decrypter.as_mut() else {
                pool::put(mac_key).ok();
                return Err(err_ssr_crashing_blocked());
            };
            let Some(encrypted) = src.get_mut(pos..pos + data_length) else {
                pool::put(mac_key).ok();
                break;
            };
            decrypter.apply_keystream(encrypted);
            let (from, to) = if self.recv_id == 1 { (pos + 2, pos + data_length) } else { (pos, pos + data_length) };
            let Some(plain) = src.get(from..to) else {
                pool::put(mac_key).ok();
                break;
            };
            dst.extend_from_slice(plain);
            self.recv_id += 1;
            let _ = src.split_to(frame_length + 4);
            pool::put(mac_key).ok();
        }
        Ok(())
    }

    fn encode(&mut self, buf: &mut BytesMut, b: &[u8]) -> Result<()> {
        let mut b = b;
        if !self.has_sent_header {
            let data_length = get_data_length(b);
            let (header, rest) = b.split_at(usize::try_from(data_length).unwrap_or_default());
            self.pack_auth_data(buf, header);
            b = rest;
            self.has_sent_header = true;
        }
        while b.len() > 2800 {
            let (block, rest) = b.split_at(2800);
            self.pack_data(buf, block);
            b = rest;
        }
        if !b.is_empty() {
            self.pack_data(buf, b);
        }
        Ok(())
    }

    fn decode_packet(&mut self, b: &[u8]) -> Result<Vec<u8>> {
        if b.len() < 9 {
            return Err(err_auth_chain_length_error());
        }
        let (body, mac) = b.split_at(b.len() - 1);
        if digest_head::<1>(&hmac_md5(&self.user_data.user_key, body)) != digest_head::<1>(mac) {
            return Err(err_auth_chain_chksum_error());
        }
        let Some(md5_input) = body.get(body.len() - 7..) else {
            return Err(err_auth_chain_length_error());
        };
        let md5_data = hmac_md5(&self.base.key, md5_input);

        let rand_data_length = udp_get_rand_length(&md5_data, &mut self.random_server);
        let Ok(rand_data_length) = usize::try_from(rand_data_length) else {
            return Err(err_auth_chain_length_error());
        };
        // DEVIATION: a frame shorter than `8 + randDataLength` is rejected as a length error
        // instead of slicing out of bounds.
        if b.len() < 8 + rand_data_length {
            return Err(err_auth_chain_length_error());
        }

        let key = kdf(&format!("{}{}", STANDARD.encode(&self.user_data.user_key), STANDARD.encode(&md5_data)), 16);
        let mut rc4_cipher = Rc4::new(&key);
        let Some(plain) = b.get(..b.len() - 8 - rand_data_length) else {
            return Err(err_auth_chain_length_error());
        };
        let mut wanted_data = plain.to_vec();
        rc4_cipher.apply_keystream(&mut wanted_data);
        Ok(wanted_data)
    }

    fn encode_packet(&mut self, buf: &mut BytesMut, b: &[u8]) -> Result<()> {
        let mut auth_data = pool::get(3);
        let _ = OsRng.try_fill_bytes(&mut auth_data);

        let md5_data = hmac_md5(&self.base.key, &auth_data);

        let rand_data_length = udp_get_rand_length(&md5_data, &mut self.random_client);
        let Ok(rand_data_length) = usize::try_from(rand_data_length) else {
            return Err(err_auth_chain_length_error());
        };

        let key = kdf(&format!("{}{}", STANDARD.encode(&self.user_data.user_key), STANDARD.encode(&md5_data)), 16);
        let mut rc4_cipher = Rc4::new(&key);
        let mut b = b.to_vec();
        rc4_cipher.apply_keystream(&mut b);

        buf.extend_from_slice(&b);
        append_rand_bytes(buf, rand_data_length);
        buf.extend_from_slice(&auth_data);
        let digest = digest_head::<16>(&md5_data);
        let uid = u32::from_le_bytes(self.user_data.user_id)
            ^ u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        buf.put_u32_le(uid);
        let mac = hmac_md5(&self.user_data.user_key, buf);
        buf.extend_from_slice(&digest_head::<1>(&mac));
        pool::put(auth_data).ok();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::super::base::{AuthData, UserData};
    use super::super::protocol::Protocol as _;
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

    fn new_proto() -> AuthChainA {
        AuthChainA {
            base: Base { key: key16(11), overhead: 4, param: String::new() },
            auth_data: AuthData::default(),
            user_data: UserData { user_key: key16(21), user_id: [1, 2, 3, 4] },
            iv: Vec::new(),
            salt: "auth_chain_a",
            has_sent_header: false,
            raw_trans: false,
            last_client_hash: Vec::new(),
            last_server_hash: Vec::new(),
            encrypter: None,
            decrypter: None,
            random_client: XorShift128Plus::default(),
            random_server: XorShift128Plus::default(),
            rand_data_length: None,
            pack_id: 0,
            recv_id: 0,
        }
    }

    #[test]
    fn pack_data_v2_matches_known_vector() {
        let mut c = new_proto();
        c.pack_id = 7;
        c.last_client_hash = key16(5);
        c.init_rc4_cipher();
        c.rand_data_length = Some(Box::new(get_rand_length));
        let mut buf = BytesMut::new();
        c.pack_data(&mut buf, &data_of(2000, 0x5a));
        assert_eq!(
            "len=2004 md5=2b5dc05d3c844d4e5356744024e33f05 sha1=36dd82e8ac9f2fdd66435bbeeb527b2419c8a01c",
            digest(&buf)
        );
    }

    #[test]
    fn v2_decode_recovers_payload() {
        let mut c = new_proto();
        c.pack_id = 7;
        c.last_client_hash = key16(5);
        c.init_rc4_cipher();
        c.rand_data_length = Some(Box::new(get_rand_length));
        let mut buf = BytesMut::new();
        c.pack_data(&mut buf, &data_of(2000, 0x5a));

        let mut s = new_proto();
        s.recv_id = 7;
        s.last_client_hash = key16(5);
        s.last_server_hash = key16(5);
        s.init_rc4_cipher();
        s.rand_data_length = Some(Box::new(get_rand_length));
        let mut dst = BytesMut::new();
        let mut src = buf.clone();
        s.decode(&mut dst, &mut src).unwrap();
        assert_eq!(data_of(2000, 0x5a), &dst[..]);
        assert!(src.is_empty());
    }

    #[test]
    fn decode_packet_rejects_forged_short_frame() {
        let base_key = key16(31);
        let user_key = key16(21);
        let mut c = new_proto();
        c.base.key = base_key.clone();
        c.user_data.user_key = user_key.clone();

        let mut b = vec![0u8; 9];
        let mut found_rand_data_length = None;
        for first in 0u8..=255 {
            b[0] = first;
            let md5_data = hmac_md5(&base_key, &b[1..8]);
            let rand_data_length = udp_get_rand_length(&md5_data, &mut XorShift128Plus::default());
            if rand_data_length >= 2 {
                found_rand_data_length = Some(rand_data_length);
                break;
            }
        }
        assert!(found_rand_data_length.is_some(), "expected some byte to push rand_data_length >= 2");

        b[8] = hmac_md5(&user_key, &b[..8])[0];

        let err = c.decode_packet(&b).unwrap_err();
        assert!(err.to_string().contains("length"), "expected a length error, got {err}");
    }

    #[test]
    fn decode_rejects_recv_id_one_frame_with_data_length_under_two() {
        let mut c = new_proto();
        c.pack_id = 1;
        c.last_client_hash = key16(5);
        c.init_rc4_cipher();
        c.rand_data_length = Some(Box::new(get_rand_length));
        let mut buf = BytesMut::new();
        c.pack_data(&mut buf, &data_of(1, 0x5a));

        let mut s = new_proto();
        s.recv_id = 1;
        s.last_client_hash = key16(5);
        s.last_server_hash = key16(5);
        s.init_rc4_cipher();
        s.rand_data_length = Some(Box::new(get_rand_length));
        let mut dst = BytesMut::new();
        let mut src = buf;
        let err = s.decode(&mut dst, &mut src).unwrap_err();
        assert!(err.to_string().contains("crashing"), "expected the crashing-blocked error, got {err}");
    }

    #[test]
    fn rc4_canonical_vector() {
        let mut c = Rc4::new(b"Key");
        let mut data = b"Plaintext".to_vec();
        c.apply_keystream(&mut data);
        assert_eq!("bbf316e8d940af0ad3", hex::encode(&data));
    }

    #[test]
    fn get_rand_start_pos_matches_known_vector() {
        let mut r = XorShift128Plus::default();
        r.init_from_bin(&key16(2));
        let mut got = Vec::new();
        for l in [0, 1, 7, 100, 1440] {
            got.push(get_rand_start_pos(l, &mut r));
        }
        assert_eq!(vec![0, 0, 1, 78, 620], got);
    }

    #[test]
    fn get_rand_length_matches_known_vector() {
        let mut r = XorShift128Plus::default();
        r.init_from_bin(&key16(4));
        let mut got = Vec::new();
        for l in [1500, 1440, 1400, 1000, 500, 100, 0] {
            let mut hash = key16(5);
            got.push((get_rand_length(l, &mut hash, &mut r), hash[0], hash[1]));
        }
        assert_eq!(
            vec![(0, 5, 6), (12, 160, 5), (27, 120, 5), (13, 232, 3), (190, 244, 1), (384, 100, 0), (73, 0, 0)],
            got
        );
    }

    #[test]
    fn udp_get_rand_length_matches_known_vector() {
        let mut r = XorShift128Plus::default();
        assert_eq!(115, udp_get_rand_length(&key16(6), &mut r));
    }
}

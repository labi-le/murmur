use std::sync::Arc;

use anyhow::Result;
use bytes::BytesMut;

use crate::tools::random::XorShift128Plus;
use murmur_common_net::io::Stream;
use murmur_common_net::EnhancePacketConn;

use super::auth_chain_a::{new_auth_chain_a_inner, new_auth_chain_a_literal, AuthChainA};
use super::base::{AuthData, Base};
use super::protocol::{register, Protocol, ProtocolList};
use super::stream::Conn as ProtocolConn;

/// the `init` registering `auth_chain_b`.
pub(crate) fn init(list: &mut ProtocolList) {
    register(list, "auth_chain_b", new_auth_chain_b, 4);
}
pub(crate) struct AuthChainB {
    pub(crate) auth_chain_a: AuthChainA,
    pub(crate) data_size_list: Vec<i32>,
    pub(crate) data_size_list2: Vec<i32>,
}

pub(crate) fn new_auth_chain_b(b: &Base) -> Box<dyn Protocol> {
    Box::new(AuthChainB {
        auth_chain_a: new_auth_chain_a_inner(b, AuthData::default(), "auth_chain_b"),
        data_size_list: Vec::new(),
        data_size_list2: Vec::new(),
    })
}

pub(crate) fn init_data_size(key: &[u8], random_server: &mut XorShift128Plus) -> (Vec<i32>, Vec<i32>) {
    let mut data_size_list = Vec::new();
    let mut data_size_list2 = Vec::new();

    random_server.init_from_bin(key);
    for _ in 0..random_server.next_u64() % 8 + 4 {
        data_size_list.push((random_server.next_u64() % 2340 % 2040 % 1440) as i32);
    }
    data_size_list.sort_unstable();

    for _ in 0..random_server.next_u64() % 16 + 8 {
        data_size_list2.push((random_server.next_u64() % 2340 % 2040 % 1440) as i32);
    }
    data_size_list2.sort_unstable();

    (data_size_list, data_size_list2)
}

/// `next_u64() % bound`, narrowed to `usize`: the remainder is always below `bound`.
#[expect(clippy::cast_possible_truncation, reason = "a remainder of `% bound` is below `bound`")]
fn next_below(random: &mut XorShift128Plus, bound: usize) -> usize {
    (random.next_u64() % bound as u64) as usize
}

///
/// The size lists are handed to the stream's random-data-length closure, which is the only caller.
fn get_rand_length_b(
    data_size_list: &[i32],
    data_size_list2: &[i32],
    overhead: i32,
    length: i32,
    last_hash: &mut [u8],
    random: &mut XorShift128Plus,
) -> i32 {
    if length >= 1440 {
        return 0;
    }
    #[expect(
        clippy::cast_sign_loss,
        reason = "the seed consumes only the low 16 bits of `length`, so a negative value wraps exactly as the protocol's own `uint16(length)` cast"
    )]
    let length_seed = length as usize;
    random.init_from_bin_and_length(last_hash, length_seed);
    let mut pos = data_size_list.partition_point(|&size| size < length + overhead);
    let mut final_pos = pos + next_below(random, data_size_list.len());
    if let Some(&size) = data_size_list.get(final_pos) {
        return size - length - overhead;
    }

    pos = data_size_list2.partition_point(|&size| size < length + overhead);
    final_pos = pos + next_below(random, data_size_list2.len());
    if let Some(&size) = data_size_list2.get(final_pos) {
        return size - length - overhead;
    }
    if final_pos < pos + data_size_list2.len() - 1 {
        return 0;
    }
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

impl Protocol for AuthChainB {
    fn stream_conn(&self, c: Box<dyn Stream>, iv: &[u8]) -> Box<dyn Stream> {
        let mut p = Self {
            auth_chain_a: new_auth_chain_a_literal(
                &self.auth_chain_a.base,
                self.auth_chain_a.auth_data.next(),
                self.auth_chain_a.user_data.clone(),
                self.auth_chain_a.salt,
            ),
            data_size_list: Vec::new(),
            data_size_list2: Vec::new(),
        };
        p.auth_chain_a.iv = iv.to_vec();
        p.auth_chain_a.pack_id = 1;
        p.auth_chain_a.recv_id = 1;
        let (data_size_list, data_size_list2) =
            init_data_size(&p.auth_chain_a.base.key, &mut p.auth_chain_a.random_server);
        let overhead = p.auth_chain_a.base.overhead;
        p.data_size_list.clone_from(&data_size_list);
        p.data_size_list2.clone_from(&data_size_list2);
        p.auth_chain_a.rand_data_length = Some(Box::new(move |length, last_hash, random| {
            get_rand_length_b(&data_size_list, &data_size_list2, overhead, length, last_hash, random)
        }));
        Box::new(ProtocolConn::new(c, Box::new(p)))
    }

    /// Wraps the conn, inherited from the embedded auth chain A.
    fn packet_conn(&self, c: Arc<dyn EnhancePacketConn>) -> Arc<dyn EnhancePacketConn> {
        self.auth_chain_a.packet_conn(c)
    }

    fn decode(&mut self, dst: &mut BytesMut, src: &mut BytesMut) -> Result<()> {
        self.auth_chain_a.decode(dst, src)
    }

    fn encode(&mut self, buf: &mut BytesMut, b: &[u8]) -> Result<()> {
        self.auth_chain_a.encode(buf, b)
    }

    fn decode_packet(&mut self, b: &[u8]) -> Result<Vec<u8>> {
        self.auth_chain_a.decode_packet(b)
    }

    fn encode_packet(&mut self, buf: &mut BytesMut, b: &[u8]) -> Result<()> {
        self.auth_chain_a.encode_packet(buf, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::random::XorShift128Plus;

    fn key16(b: u8) -> Vec<u8> {
        (0..16u8).map(|i| b + i).collect()
    }

    #[test]
    fn init_data_size_matches_known_vector() {
        let mut r = XorShift128Plus::default();
        let (list, list2) = init_data_size(&key16(7), &mut r);
        assert_eq!(vec![42, 134, 165, 206, 424, 429, 482, 549, 781, 909, 1376], list);
        assert_eq!(
            vec![
                35, 56, 145, 156, 195, 206, 212, 282, 362, 385, 419, 477, 518, 547, 562, 728, 776, 1077, 1204, 1237,
                1290, 1429
            ],
            list2
        );
    }

    #[test]
    fn get_rand_length_b_matches_known_vector() {
        let mut seed = XorShift128Plus::default();
        let (list, list2) = init_data_size(&key16(7), &mut seed);
        let mut r = XorShift128Plus::default();
        r.init_from_bin(&key16(8));
        let mut got = Vec::new();
        for l in [1439, 1400, 1000, 500, 100, 0] {
            let mut hash = key16(9);
            got.push((get_rand_length_b(&list, &list2, 4, l, &mut hash, &mut r), hash[0], hash[1]));
        }
        assert_eq!(vec![(0, 159, 5), (0, 120, 5), (372, 232, 3), (45, 244, 1), (805, 100, 0), (420, 0, 0)], got);
    }
}

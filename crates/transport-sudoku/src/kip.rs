use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use super::write_chunks::write_all_chunks;
use crate::obfs::sudoku::table::Table;

const KIP_MAGIC: &[u8; 3] = b"kip";

pub(crate) const KIP_TYPE_CLIENT_HELLO: u8 = 0x01;
pub(crate) const KIP_TYPE_SERVER_HELLO: u8 = 0x02;

pub const KIP_TYPE_OPEN_TCP: u8 = 0x10;
pub(crate) const KIP_TYPE_START_MUX: u8 = 0x11;
pub const KIP_TYPE_START_UOT: u8 = 0x12;
pub(crate) const KIP_TYPE_KEEP_ALIVE: u8 = 0x14;

/// KIP feature bits are advisory capability flags negotiated during the handshake.
/// They represent control-plane message families.
pub(crate) const KIP_FEAT_OPEN_TCP: u32 = 1 << 0;
pub(crate) const KIP_FEAT_MUX: u32 = 1 << 1;
pub(crate) const KIP_FEAT_UOT: u32 = 1 << 2;
pub(crate) const KIP_FEAT_KEEP_ALIVE: u32 = 1 << 4;

pub(crate) const KIP_FEAT_ALL: u32 = KIP_FEAT_OPEN_TCP | KIP_FEAT_MUX | KIP_FEAT_UOT | KIP_FEAT_KEEP_ALIVE;

pub(crate) const KIP_HELLO_USER_HASH_SIZE: usize = 8;
pub(crate) const KIP_HELLO_NONCE_SIZE: usize = 16;
pub(crate) const KIP_HELLO_PUB_SIZE: usize = 32;

const KIP_CLIENT_HELLO_TABLE_HINT_SIZE: usize = 4;

fn err_kip(msg: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("kip protocol error: {msg}")
}

pub(crate) struct KipMessage {
    pub(crate) typ: u8,
    pub(crate) payload: Vec<u8>,
}

pub async fn write_kip_message<W: AsyncWrite + Unpin + ?Sized>(w: &mut W, typ: u8, payload: &[u8]) -> Result<()> {
    let Ok(payload_len) = u16::try_from(payload.len()) else {
        return Err(err_kip(format!("payload too large: {}", payload.len())));
    };

    let mut hdr = [0u8; 3 + 1 + 2];
    hdr[..3].copy_from_slice(KIP_MAGIC);
    hdr[3] = typ;
    BigEndian::write_u16(&mut hdr[4..], payload_len);

    write_all_chunks(w, &[&hdr[..], payload]).await.map_err(Into::into)
}

pub(crate) async fn read_kip_message<R: AsyncRead + Unpin + ?Sized>(r: &mut R) -> Result<KipMessage> {
    let mut hdr = [0u8; 3 + 1 + 2];
    r.read_exact(&mut hdr).await?;
    if &hdr[..3] != KIP_MAGIC {
        return Err(err_kip("bad magic"));
    }
    let typ = hdr[3];
    let n = usize::from(BigEndian::read_u16(&hdr[4..]));
    let mut payload = vec![0u8; n];
    if n > 0 {
        r.read_exact(&mut payload).await?;
    }
    Ok(KipMessage { typ, payload })
}

pub(crate) struct KipClientHello {
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) user_hash: [u8; KIP_HELLO_USER_HASH_SIZE],
    pub(crate) nonce: [u8; KIP_HELLO_NONCE_SIZE],
    pub(crate) client_pub: [u8; KIP_HELLO_PUB_SIZE],
    pub(crate) features: u32,
    pub(crate) table_hint: u32,
    pub(crate) has_table_hint: bool,
}

pub(crate) struct KipServerHello {
    pub(crate) nonce: [u8; KIP_HELLO_NONCE_SIZE],
    pub(crate) server_pub: [u8; KIP_HELLO_PUB_SIZE],
    pub(crate) selected_feats: u32,
}

pub(crate) fn new_kip_client_hello(
    user_hash: [u8; KIP_HELLO_USER_HASH_SIZE],
    nonce: [u8; KIP_HELLO_NONCE_SIZE],
    client_pub: [u8; KIP_HELLO_PUB_SIZE],
    feats: u32,
    table_hint: u32,
    has_table_hint: bool,
) -> KipClientHello {
    KipClientHello { timestamp: Utc::now(), user_hash, nonce, client_pub, features: feats, table_hint, has_table_hint }
}

pub(crate) fn kip_user_hash_from_key(psk: &str) -> [u8; KIP_HELLO_USER_HASH_SIZE] {
    let mut out = [0u8; KIP_HELLO_USER_HASH_SIZE];
    let psk = psk.trim();
    if psk.is_empty() {
        return out;
    }

    if let Ok(key_bytes) = hex::decode(psk) {
        if !key_bytes.is_empty() {
            let sum = Sha256::digest(&key_bytes);
            out.copy_from_slice(sum.split_at(KIP_HELLO_USER_HASH_SIZE).0);
            return out;
        }
    }

    let sum = Sha256::digest(psk.as_bytes());
    out.copy_from_slice(sum.split_at(KIP_HELLO_USER_HASH_SIZE).0);
    out
}

impl KipClientHello {
    pub(crate) fn encode_payload(&self) -> Vec<u8> {
        let mut b = Vec::new();
        let mut tmp = [0u8; 8];
        BigEndian::write_u64(&mut tmp, self.timestamp.timestamp().cast_unsigned());
        b.extend_from_slice(&tmp);
        b.extend_from_slice(&self.user_hash);
        b.extend_from_slice(&self.nonce);
        b.extend_from_slice(&self.client_pub);
        let mut f = [0u8; 4];
        BigEndian::write_u32(&mut f, self.features);
        b.extend_from_slice(&f);
        if self.has_table_hint {
            let mut hint = [0u8; KIP_CLIENT_HELLO_TABLE_HINT_SIZE];
            BigEndian::write_u32(&mut hint, self.table_hint);
            b.extend_from_slice(&hint);
        }
        b
    }
}

pub(crate) fn decode_kip_client_hello_payload(payload: &[u8]) -> Result<KipClientHello> {
    const MIN_LEN: usize = 8 + KIP_HELLO_USER_HASH_SIZE + KIP_HELLO_NONCE_SIZE + KIP_HELLO_PUB_SIZE + 4;
    if payload.len() < MIN_LEN {
        return Err(err_kip("client hello too short"));
    }
    let (ts_bytes, payload) = payload.split_at(8);
    let ts = BigEndian::read_u64(ts_bytes).cast_signed();
    let timestamp = DateTime::<Utc>::from_timestamp(ts, 0).ok_or_else(|| err_kip("invalid timestamp"))?;
    let mut user_hash = [0u8; KIP_HELLO_USER_HASH_SIZE];
    let (user_hash_bytes, payload) = payload.split_at(KIP_HELLO_USER_HASH_SIZE);
    user_hash.copy_from_slice(user_hash_bytes);
    let mut nonce = [0u8; KIP_HELLO_NONCE_SIZE];
    let (nonce_bytes, payload) = payload.split_at(KIP_HELLO_NONCE_SIZE);
    nonce.copy_from_slice(nonce_bytes);
    let mut client_pub = [0u8; KIP_HELLO_PUB_SIZE];
    let (client_pub_bytes, payload) = payload.split_at(KIP_HELLO_PUB_SIZE);
    client_pub.copy_from_slice(client_pub_bytes);
    let (features_bytes, payload) = payload.split_at(4);
    let features = BigEndian::read_u32(features_bytes);
    let hint_bytes = payload.get(..KIP_CLIENT_HELLO_TABLE_HINT_SIZE);
    let has_table_hint = hint_bytes.is_some();
    let table_hint = hint_bytes.map_or(0, BigEndian::read_u32);
    Ok(KipClientHello { timestamp, user_hash, nonce, client_pub, features, table_hint, has_table_hint })
}

pub(crate) fn resolve_client_hello_table(
    selected: &std::sync::Arc<Table>,
    candidates: &[std::sync::Arc<Table>],
    hello: &KipClientHello,
) -> Result<std::sync::Arc<Table>> {
    if !hello.has_table_hint {
        return Ok(std::sync::Arc::clone(selected));
    }
    if selected.hint() == hello.table_hint {
        return Ok(std::sync::Arc::clone(selected));
    }
    if candidates.is_empty() {
        return Err(anyhow!("no table candidates"));
    }

    let hinted = candidates.iter().find(|candidate| candidate.hint() == hello.table_hint);
    let Some(hinted) = hinted else {
        return Err(anyhow!("unknown table hint: {}", hello.table_hint));
    };
    if !std::sync::Arc::ptr_eq(hinted, selected) && (!hinted.is_ascii || !selected.is_ascii) {
        return Err(anyhow!("table hint {} mismatches probed uplink table", hello.table_hint));
    }
    Ok(std::sync::Arc::clone(hinted))
}

impl KipServerHello {
    pub(crate) fn encode_payload(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.nonce);
        b.extend_from_slice(&self.server_pub);
        let mut f = [0u8; 4];
        BigEndian::write_u32(&mut f, self.selected_feats);
        b.extend_from_slice(&f);
        b
    }
}

pub(crate) fn decode_kip_server_hello_payload(payload: &[u8]) -> Result<KipServerHello> {
    const WANT: usize = KIP_HELLO_NONCE_SIZE + KIP_HELLO_PUB_SIZE + 4;
    if payload.len() != WANT {
        return Err(err_kip(format!("server hello bad len: {}", payload.len())));
    }
    let (nonce_bytes, payload) = payload.split_at(KIP_HELLO_NONCE_SIZE);
    let mut nonce = [0u8; KIP_HELLO_NONCE_SIZE];
    nonce.copy_from_slice(nonce_bytes);
    let (server_pub_bytes, payload) = payload.split_at(KIP_HELLO_PUB_SIZE);
    let mut server_pub = [0u8; KIP_HELLO_PUB_SIZE];
    server_pub.copy_from_slice(server_pub_bytes);
    let selected_feats = BigEndian::read_u32(payload);
    Ok(KipServerHello { nonce, server_pub, selected_feats })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obfs::sudoku::table::new_table_with_custom;
    use crate::tables::new_client_tables_with_custom_patterns;

    #[test]
    fn kip_client_hello_table_hint_round_trip() {
        let hello = KipClientHello {
            timestamp: Utc::now(),
            user_hash: [0u8; KIP_HELLO_USER_HASH_SIZE],
            nonce: [0u8; KIP_HELLO_NONCE_SIZE],
            client_pub: [0u8; KIP_HELLO_PUB_SIZE],
            features: KIP_FEAT_ALL,
            table_hint: 0x1234_5678,
            has_table_hint: true,
        };
        let decoded = decode_kip_client_hello_payload(&hello.encode_payload()).expect("decode client hello");
        assert!(decoded.has_table_hint, "expected decoded hello to carry table hint");
        assert_eq!(decoded.table_hint, hello.table_hint);
    }

    #[test]
    fn resolve_client_hello_table_allows_directional_ascii_rotation() {
        let tables = new_client_tables_with_custom_patterns(
            "seed",
            "up_ascii_down_entropy",
            "",
            &["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()],
        )
        .expect("build tables");
        assert_eq!(tables.len(), 2);

        let hello = KipClientHello {
            timestamp: Utc::now(),
            user_hash: [0u8; KIP_HELLO_USER_HASH_SIZE],
            nonce: [0u8; KIP_HELLO_NONCE_SIZE],
            client_pub: [0u8; KIP_HELLO_PUB_SIZE],
            features: 0,
            table_hint: tables[1].hint(),
            has_table_hint: true,
        };
        let selected = resolve_client_hello_table(&tables[0], &tables, &hello).expect("resolve client hello table");
        assert!(std::sync::Arc::ptr_eq(&selected, &tables[1]), "resolved table mismatch");
    }

    #[test]
    fn resolve_client_hello_table_rejects_entropy_mismatch() {
        let a = new_table_with_custom("seed", "prefer_entropy", "xpxvvpvv").expect("table a");
        let b = new_table_with_custom("seed", "prefer_entropy", "vxpvxvvp").expect("table b");

        let hello = KipClientHello {
            timestamp: Utc::now(),
            user_hash: [0u8; KIP_HELLO_USER_HASH_SIZE],
            nonce: [0u8; KIP_HELLO_NONCE_SIZE],
            client_pub: [0u8; KIP_HELLO_PUB_SIZE],
            features: 0,
            table_hint: b.hint(),
            has_table_hint: true,
        };
        assert!(
            resolve_client_hello_table(&a, &[std::sync::Arc::clone(&a), b], &hello).is_err(),
            "expected entropy-table mismatch to fail"
        );
    }

    #[tokio::test]
    async fn write_kip_message_encodes_the_length_field_at_its_width_and_refuses_one_past_it() {
        for len in [usize::from(u16::MAX) - 1, usize::from(u16::MAX)] {
            let mut sink = Vec::new();
            let payload = vec![0x5au8; len];
            write_kip_message(&mut sink, KIP_TYPE_OPEN_TCP, &payload)
                .await
                .unwrap_or_else(|err| panic!("a {len}-byte payload must be encodable: {err}"));

            let declared = usize::from(u16::from_be_bytes([sink[4], sink[5]]));
            assert_eq!(declared, len, "declared length for a {len}-byte payload");
            assert_eq!(sink.len(), 6 + len, "frame size for a {len}-byte payload");
        }

        let mut sink = Vec::new();
        let oversized = vec![0x5au8; usize::from(u16::MAX) + 1];
        let err = write_kip_message(&mut sink, KIP_TYPE_OPEN_TCP, &oversized)
            .await
            .expect_err("a payload one byte past the 16-bit length field must be refused");

        assert_eq!(err.to_string(), "kip protocol error: payload too large: 65536");
        assert!(sink.is_empty(), "a refused payload must write no bytes");
    }

    #[tokio::test]
    async fn read_kip_message_reads_the_widest_frame_the_length_field_can_declare() {
        let payload: Vec<u8> = (0..usize::from(u16::MAX)).map(|i| (i % 251) as u8).collect();
        let mut frame = Vec::new();
        write_kip_message(&mut frame, KIP_TYPE_OPEN_TCP, &payload).await.expect("encode widest frame");

        let decoded = read_kip_message(&mut frame.as_slice()).await.expect("decode widest frame");
        assert_eq!(decoded.typ, KIP_TYPE_OPEN_TCP);
        assert_eq!(decoded.payload, payload, "widest frame payload round trip");
    }
}

use std::sync::LazyLock;

use anyhow::{anyhow, Result};
use chrono::TimeDelta;
use rand::rngs::OsRng;
use rand::TryRngCore;
use tokio::io::AsyncWriteExt;

use super::kip::{
    decode_kip_server_hello_payload, new_kip_client_hello, read_kip_message, write_kip_message, KIP_HELLO_NONCE_SIZE,
    KIP_HELLO_PUB_SIZE, KIP_TYPE_CLIENT_HELLO, KIP_TYPE_SERVER_HELLO,
};
use super::session_keys::{derive_session_directional_bases, generate_x25519_ephemeral, x25519_shared_secret};
use crate::crypto::record_conn::RecordConn;
use x25519_dalek::PublicKey;

pub(crate) static KIP_HANDSHAKE_SKEW: LazyLock<TimeDelta> = LazyLock::new(|| TimeDelta::seconds(60));

pub(crate) async fn kip_handshake_client(
    rc: &mut RecordConn,
    seed: &str,
    user_hash: [u8; super::kip::KIP_HELLO_USER_HASH_SIZE],
    feats: u32,
    table_hint: u32,
    has_table_hint: bool,
) -> Result<u32> {
    let ephemeral = generate_x25519_ephemeral().map_err(|err| anyhow!("ecdh generate failed: {err}"))?;

    let mut nonce = [0u8; KIP_HELLO_NONCE_SIZE];
    OsRng.try_fill_bytes(&mut nonce).map_err(|err| anyhow!("nonce generate failed: {err}"))?;

    let mut client_pub = [0u8; KIP_HELLO_PUB_SIZE];
    client_pub.copy_from_slice(PublicKey::from(&ephemeral).as_bytes());

    let ch = new_kip_client_hello(user_hash, nonce, client_pub, feats, table_hint, has_table_hint);
    write_kip_message(rc, KIP_TYPE_CLIENT_HELLO, &ch.encode_payload())
        .await
        .map_err(|err| anyhow!("write client hello failed: {err}"))?;
    rc.flush().await.map_err(|err| anyhow!("flush client hello failed: {err}"))?;

    let msg = read_kip_message(rc).await.map_err(|err| anyhow!("read server hello failed: {err}"))?;
    if msg.typ != KIP_TYPE_SERVER_HELLO {
        return Err(anyhow!("unexpected handshake message: {}", msg.typ));
    }
    let sh =
        decode_kip_server_hello_payload(&msg.payload).map_err(|err| anyhow!("decode server hello failed: {err}"))?;
    if sh.nonce != nonce {
        return Err(anyhow!("handshake nonce mismatch"));
    }

    let shared = x25519_shared_secret(&ephemeral, &sh.server_pub).map_err(|err| anyhow!("ecdh failed: {err}"))?;
    let (sess_c2s, sess_s2c) = derive_session_directional_bases(seed, &shared, &nonce)
        .map_err(|err| anyhow!("derive session keys failed: {err}"))?;
    rc.rekey(&sess_c2s, &sess_s2c).map_err(|err| anyhow!("rekey failed: {err}"))?;

    Ok(sh.selected_feats)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    use super::*;
    use crate::address::encode_address;
    use crate::config::default_config;
    use crate::crypto::record_conn::new_record_conn;
    use crate::handshake::{build_client_obfs_conn, read_server_session, server_handshake, SessionType};
    use crate::init::client_aead_seed;
    use crate::kip::{kip_user_hash_from_key, write_kip_message, KIP_FEAT_ALL, KIP_TYPE_OPEN_TCP};
    use crate::obfs::sudoku::table::new_table_with_custom;
    use crate::session_keys::derive_psk_directional_bases;
    use crate::tables::new_server_tables_with_custom_patterns;
    use murmur_common_net::io::Stream;

    struct PipeConn(DuplexStream);

    impl AsyncRead for PipeConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PipeConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl Stream for PipeConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }

        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    fn pipe_pair() -> (Box<dyn Stream>, Box<dyn Stream>) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (Box::new(PipeConn(a)), Box::new(PipeConn(b)))
    }

    #[tokio::test]
    async fn directional_custom_table_rotation_hint_round_trip() {
        let key = "directional-rotate-key";
        let target = "8.8.8.8:53";

        let server_tables = new_server_tables_with_custom_patterns(
            &client_aead_seed(key),
            "up_ascii_down_entropy",
            "",
            &["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()],
        )
        .expect("server tables");
        assert_eq!(server_tables.len(), 2, "expected 2 server tables");

        let client_table =
            new_table_with_custom(&client_aead_seed(key), "up_ascii_down_entropy", "vxpvxvvp").expect("client table");

        let mut server_cfg = default_config();
        server_cfg.key = key.to_owned();
        server_cfg.aead_method = "chacha20-poly1305".to_owned();
        server_cfg.tables = server_tables;
        server_cfg.padding_min = 0;
        server_cfg.padding_max = 0;
        server_cfg.enable_pure_downlink = true;
        server_cfg.handshake_timeout_seconds = 5;
        server_cfg.disable_http_mask = true;

        let mut client_cfg = server_cfg.clone();
        client_cfg.server_address = "example.com:443".to_owned();

        let (server_conn, client_conn) = pipe_pair();

        let target_task = target.to_owned();
        let server_task = tokio::spawn(async move {
            let (c, meta) = server_handshake(server_conn, &server_cfg, None).await?;
            let session = read_server_session(c, Some(&meta)).await?;
            if session.typ != SessionType::Tcp || session.target != target_task {
                return Err(anyhow!("unexpected session"));
            }
            let mut conn = session.conn;
            let want = b"client-payload";
            let mut got = vec![0u8; want.len()];
            conn.read_exact(&mut got).await?;
            if got != want {
                return Err(anyhow!("unexpected payload: {got:?}"));
            }
            conn.write_all(b"server-reply").await?;
            Ok::<(), anyhow::Error>(())
        });

        let seed = client_aead_seed(&client_cfg.key);
        let obfs_conn = build_client_obfs_conn(
            client_conn,
            &client_table,
            client_cfg.padding_min,
            client_cfg.padding_max,
            client_cfg.enable_pure_downlink,
        );
        let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
        let mut c_conn = new_record_conn(obfs_conn, &client_cfg.aead_method, &psk_c2s, &psk_s2c).expect("setup crypto");

        kip_handshake_client(
            &mut c_conn,
            &seed,
            kip_user_hash_from_key(&client_cfg.key),
            KIP_FEAT_ALL,
            client_table.hint(),
            true,
        )
        .await
        .expect("client handshake");

        let addr_buf = encode_address(target).expect("encode target");
        write_kip_message(&mut c_conn, KIP_TYPE_OPEN_TCP, &addr_buf).await.expect("write target");
        c_conn.write_all(b"client-payload").await.expect("write payload");

        let mut reply = vec![0u8; b"server-reply".len()];
        c_conn.read_exact(&mut reply).await.expect("read reply");
        assert_eq!(reply, b"server-reply", "unexpected reply");

        server_task.await.expect("server task join").expect("server");
    }
}

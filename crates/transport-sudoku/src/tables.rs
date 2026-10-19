use std::sync::Arc;

use anyhow::Result;

use super::init::new_table_with_custom;
use crate::obfs::sudoku::ascii_mode::parse_ascii_mode;
use crate::obfs::sudoku::table::Table;

pub(crate) fn normalize_custom_patterns(custom_table: &str, custom_tables: &[String]) -> Vec<String> {
    let mut patterns = custom_tables.to_vec();
    if patterns.is_empty() && !custom_table.trim().is_empty() {
        patterns = vec![custom_table.to_owned()];
    }
    if patterns.is_empty() {
        patterns = vec![String::new()];
    }
    patterns
}

pub(crate) fn normalize_table_patterns(
    table_type: &str,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<Vec<String>> {
    let patterns = normalize_custom_patterns(custom_table, custom_tables);
    parse_ascii_mode(table_type)?;
    Ok(patterns)
}

///
/// Deprecated-ish: prefer [`new_client_tables_with_custom_patterns`] / [`new_server_tables_with_custom_patterns`].
pub(crate) fn new_tables_with_custom_patterns(
    key: &str,
    table_type: &str,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<Vec<Arc<Table>>> {
    let patterns = normalize_table_patterns(table_type, custom_table, custom_tables)?;
    let mut tables = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        let pattern = pattern.trim();
        let t = new_table_with_custom(key, table_type, pattern)?;
        tables.push(t);
    }
    Ok(tables)
}

pub fn new_client_tables_with_custom_patterns(
    key: &str,
    table_type: &str,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<Vec<Arc<Table>>> {
    new_tables_with_custom_patterns(key, table_type, custom_table, custom_tables)
}

/// `NewServerTablesWithCustomPatterns`: when probeable custom table rotation is enabled, also
/// accept the default table to avoid forcing clients to update in lockstep.
pub fn new_server_tables_with_custom_patterns(
    key: &str,
    table_type: &str,
    custom_table: &str,
    custom_tables: &[String],
) -> Result<Vec<Arc<Table>>> {
    let mut patterns = normalize_table_patterns(table_type, custom_table, custom_tables)?;
    let ascii_mode = parse_ascii_mode(table_type)?;
    if ascii_mode.uplink == "entropy" && patterns.first().is_some_and(|p| !p.trim().is_empty()) {
        patterns.insert(0, String::new());
    }
    new_tables_with_custom_patterns(key, table_type, "", &patterns)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::address::encode_address;
    use crate::config::default_config;
    use crate::handshake::{client_handshake, read_server_session, server_handshake, SessionType};
    use crate::init::client_aead_seed;
    use crate::kip::{write_kip_message, KIP_TYPE_OPEN_TCP};
    use crate::obfs::sudoku::table::new_table_with_custom;
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
    async fn directional_traffic_round_trip() {
        struct Case {
            name: &'static str,
            mode: &'static str,
            pure: bool,
        }
        let cases = [
            Case { name: "UpASCII_DownEntropy_Pure", mode: "up_ascii_down_entropy", pure: true },
            Case { name: "UpASCII_DownEntropy_Packed", mode: "up_ascii_down_entropy", pure: false },
            Case { name: "UpEntropy_DownASCII_Pure", mode: "up_entropy_down_ascii", pure: true },
            Case { name: "UpEntropy_DownASCII_Packed", mode: "up_entropy_down_ascii", pure: false },
        ];

        for case in cases {
            let key = format!("directional-test-key-{}", case.name);
            let target = "8.8.8.8:53".to_owned();

            let table = new_table_with_custom(&client_aead_seed(&key), case.mode, "xpxvvpvv").expect("table");

            let mut server_cfg = default_config();
            server_cfg.key = key.clone();
            server_cfg.aead_method = "chacha20-poly1305".to_owned();
            server_cfg.table = Some(table);
            server_cfg.padding_min = 0;
            server_cfg.padding_max = 0;
            server_cfg.enable_pure_downlink = case.pure;
            server_cfg.handshake_timeout_seconds = 5;
            server_cfg.disable_http_mask = true;

            let mut client_cfg = server_cfg.clone();
            client_cfg.server_address = "example.com:443".to_owned();

            let (server_conn, client_conn) = pipe_pair();

            let target_task = target.clone();
            let server_task = tokio::spawn(async move {
                let (c, meta) = server_handshake(server_conn, &server_cfg, None).await?;
                let session = read_server_session(c, Some(&meta)).await?;
                if session.typ != SessionType::Tcp {
                    return Err(anyhow::anyhow!("expected TCP session"));
                }
                if session.target != target_task {
                    return Err(anyhow::anyhow!("unexpected session target: {}", session.target));
                }
                let mut conn = session.conn;
                let want = b"client-payload";
                let mut got = vec![0u8; want.len()];
                conn.read_exact(&mut got).await?;
                if got != want {
                    return Err(anyhow::anyhow!("unexpected payload: {got:?}"));
                }
                conn.write_all(b"server-reply").await?;
                Ok::<(), anyhow::Error>(())
            });

            let mut c_conn = client_handshake(client_conn, &client_cfg).await.expect("client handshake");

            let addr_buf = encode_address(&target).expect("encode target");
            write_kip_message(&mut c_conn, KIP_TYPE_OPEN_TCP, &addr_buf).await.expect("write target");
            c_conn.write_all(b"client-payload").await.expect("write payload");

            let mut reply = vec![0u8; b"server-reply".len()];
            c_conn.read_exact(&mut reply).await.expect("read reply");
            assert_eq!(reply, b"server-reply", "unexpected reply for {}", case.name);

            server_task.await.expect("server task join").expect("server");
        }
    }

    #[tokio::test]
    async fn directional_traffic_round_trip_tcp() {
        struct Case {
            name: &'static str,
            mode: &'static str,
            pure: bool,
        }
        let cases = [
            Case { name: "UpASCII_DownEntropy_Pure_TCP", mode: "up_ascii_down_entropy", pure: true },
            Case { name: "UpEntropy_DownASCII_Packed_TCP", mode: "up_entropy_down_ascii", pure: false },
        ];

        for case in cases {
            let key = format!("directional-tcp-test-key-{}", case.name);

            let table = new_table_with_custom(&client_aead_seed(&key), case.mode, "xpxvvpvv").expect("table");

            let mut server_cfg = default_config();
            server_cfg.key = key.clone();
            server_cfg.aead_method = "chacha20-poly1305".to_owned();
            server_cfg.table = Some(table);
            server_cfg.padding_min = 0;
            server_cfg.padding_max = 0;
            server_cfg.enable_pure_downlink = case.pure;
            server_cfg.handshake_timeout_seconds = 5;
            server_cfg.disable_http_mask = true;

            let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
            let addr = listener.local_addr().expect("listener addr");
            let target = addr.to_string();

            let target_task = target.clone();
            let server_cfg_task = server_cfg.clone();
            let server_task = tokio::spawn(async move {
                let (raw, _) = listener.accept().await?;
                let (c, meta) = server_handshake(Box::new(raw), &server_cfg_task, None).await?;
                let session = read_server_session(c, Some(&meta)).await?;
                if session.typ != SessionType::Tcp || session.target != target_task {
                    return Err(anyhow::anyhow!("unexpected session"));
                }
                let mut conn = session.conn;
                let want = b"client-payload";
                let mut got = vec![0u8; want.len()];
                conn.read_exact(&mut got).await?;
                if got != want {
                    return Err(anyhow::anyhow!("unexpected payload: {got:?}"));
                }
                conn.write_all(b"server-reply").await?;
                Ok::<(), anyhow::Error>(())
            });

            let mut client_cfg = server_cfg.clone();
            client_cfg.server_address = target.clone();

            let raw = TcpStream::connect(&target).await.expect("dial");
            let mut c_conn = client_handshake(Box::new(raw), &client_cfg).await.expect("client handshake");

            let addr_buf = encode_address(&target).expect("encode target");
            write_kip_message(&mut c_conn, KIP_TYPE_OPEN_TCP, &addr_buf).await.expect("write target");
            c_conn.write_all(b"client-payload").await.expect("write payload");

            let mut reply = vec![0u8; b"server-reply".len()];
            c_conn.read_exact(&mut reply).await.expect("read reply");
            assert_eq!(reply, b"server-reply", "unexpected reply for {}", case.name);

            server_task.await.expect("server task join").expect("server");
        }
    }

    #[test]
    fn directional_custom_table_rotation_collapse() {
        let patterns = ["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()];

        let client_tables = new_client_tables_with_custom_patterns("seed", "up_ascii_down_entropy", "", &patterns)
            .expect("client tables");
        assert_eq!(client_tables.len(), 2, "expected ascii-uplink directional rotation to keep 2 tables");
        assert_ne!(
            client_tables[0].hint(),
            client_tables[1].hint(),
            "expected directional custom tables to carry distinct hints"
        );
        assert_eq!(
            client_tables[0].encode_table[0][0], client_tables[1].encode_table[0][0],
            "expected directional ascii uplink tables to share the same probe layout"
        );
        assert_ne!(
            client_tables[0].opposite_direction().encode_table[0][0],
            client_tables[1].opposite_direction().encode_table[0][0],
            "expected directional downlink custom layouts to differ"
        );

        let client_tables = new_client_tables_with_custom_patterns("seed", "up_entropy_down_ascii", "", &patterns)
            .expect("client tables entropy uplink");
        assert_eq!(client_tables.len(), 2, "expected entropy-uplink rotation to keep 2 tables");

        let server_tables = new_server_tables_with_custom_patterns("seed", "up_ascii_down_entropy", "", &patterns)
            .expect("server tables");
        assert_eq!(server_tables.len(), 2, "expected ascii-uplink server directional table set to keep 2 tables");

        let client_tables = new_client_tables_with_custom_patterns("seed", "up_ascii_down_entropy", &patterns[0], &[])
            .expect("client table with single custom pattern");
        assert_eq!(
            server_tables[0].opposite_direction().encode_table[0][0],
            client_tables[0].opposite_direction().encode_table[0][0],
            "expected server directional downlink table to preserve custom pattern"
        );
    }
}

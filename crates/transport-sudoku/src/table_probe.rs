use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use rand::TryRngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader, ReadBuf};

use super::config::ProtocolConfig;
use super::handshake_kip::KIP_HANDSHAKE_SKEW;
use super::init::server_aead_seed;
use super::kip::{decode_kip_client_hello_payload, read_kip_message, KIP_TYPE_CLIENT_HELLO};
use super::session_keys::derive_psk_directional_bases;
use crate::crypto::record_conn::new_record_conn;
use crate::obfs::sudoku::conn::new_conn;
use crate::obfs::sudoku::table::Table;
use murmur_common_net::io::Stream;

pub(crate) struct ClientTableChoice {
    pub(crate) table: Arc<Table>,
    pub(crate) hint: u32,
    pub(crate) has_hint: bool,
}

pub(crate) fn pick_client_table(cfg: &ProtocolConfig) -> Result<ClientTableChoice> {
    let candidates = cfg.table_candidates();
    if candidates.is_empty() {
        return Err(anyhow!("no table configured"));
    }
    if let [table] = candidates.as_slice() {
        let table = Arc::clone(table);
        let hint = table.hint();
        return Ok(ClientTableChoice { table, hint, has_hint: false });
    }
    let mut b = [0u8; 1];
    OsRng.try_fill_bytes(&mut b).map_err(|err| anyhow!("random table pick failed: {err}"))?;
    let idx = usize::from(b[0]) % candidates.len();
    let table = candidates.get(idx).cloned().ok_or_else(|| anyhow!("no table configured"))?;
    let hint = table.hint();
    Ok(ClientTableChoice { table, hint, has_hint: true })
}

struct ReadOnlyConn {
    data: io::Cursor<Vec<u8>>,
}
impl AsyncRead for ReadOnlyConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().data).poll_read(cx, buf)
    }
}
impl AsyncWrite for ReadOnlyConn {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl Stream for ReadOnlyConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Err(io::Error::new(io::ErrorKind::NotConnected, "no local address"))
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        Err(io::Error::new(io::ErrorKind::NotConnected, "no remote address"))
    }
}

/// Drains the buffered bytes: reads exactly the bytes already buffered by `r`, causing no additional I/O.
async fn drain_buffered(r: &mut BufReader<Box<dyn Stream>>) -> Result<Vec<u8>> {
    let n = r.buffer().len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut out = vec![0u8; n];
    r.read_exact(&mut out).await?;
    Ok(out)
}

async fn probe_handshake_bytes(probe: &[u8], cfg: &ProtocolConfig, table: &Arc<Table>) -> Result<()> {
    let rc: Box<dyn Stream> = Box::new(ReadOnlyConn { data: io::Cursor::new(probe.to_vec()) });
    let obfs_conn = new_conn(rc, Some(Arc::clone(table)), cfg.padding_min, cfg.padding_max, false);
    let seed = server_aead_seed(&cfg.key);
    let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
    let mut c_conn = new_record_conn(Box::new(obfs_conn), &cfg.aead_method, &psk_s2c, &psk_c2s)?;

    let msg = read_kip_message(&mut c_conn).await?;
    if msg.typ != KIP_TYPE_CLIENT_HELLO {
        return Err(anyhow!("unexpected handshake message: {}", msg.typ));
    }
    let ch = decode_kip_client_hello_payload(&msg.payload)?;
    if (chrono::Utc::now().timestamp() - ch.timestamp.timestamp()).abs() > KIP_HANDSHAKE_SKEW.num_seconds() {
        return Err(anyhow!("time skew/replay"));
    }

    Ok(())
}

/// Selects a table by probe. Ownership of `r` threads through both branches: success returns the
/// reader alongside the resolved table and probe bytes; failure returns it alongside the error so
/// the caller (`server_handshake`) can still reclaim the raw conn for a fallback relay.
pub(crate) async fn select_table_by_probe(
    mut r: BufReader<Box<dyn Stream>>,
    cfg: &ProtocolConfig,
    tables: &[Arc<Table>],
) -> std::result::Result<
    (BufReader<Box<dyn Stream>>, Arc<Table>, Vec<u8>),
    (BufReader<Box<dyn Stream>>, anyhow::Error, Vec<u8>),
> {
    const MAX_PROBE_BYTES: usize = 64 * 1024;
    const READ_CHUNK: usize = 4 * 1024;

    if tables.is_empty() {
        return Err((r, anyhow!("no table candidates"), Vec::new()));
    }
    if tables.len() > 255 {
        return Err((r, anyhow!("too many table candidates: {}", tables.len()), Vec::new()));
    }

    let mut candidates: Vec<Arc<Table>> = tables.to_vec();

    let mut probe = match drain_buffered(&mut r).await {
        Ok(p) => p,
        Err(err) => return Err((r, anyhow!("drain buffered bytes failed: {err}"), Vec::new())),
    };

    loop {
        if let [table] = candidates.as_slice() {
            let tail = match drain_buffered(&mut r).await {
                Ok(t) => t,
                Err(err) => return Err((r, anyhow!("drain buffered bytes failed: {err}"), probe)),
            };
            probe.extend_from_slice(&tail);
            return Ok((r, Arc::clone(table), probe));
        }

        let mut need_more = false;
        let mut next = Vec::with_capacity(candidates.len());
        let mut matched: Option<Arc<Table>> = None;
        for table in &candidates {
            match probe_handshake_bytes(&probe, cfg, table).await {
                Ok(()) => {
                    matched = Some(Arc::clone(table));
                    break;
                }
                Err(err) => {
                    if is_eof_like(&err) {
                        need_more = true;
                        next.push(Arc::clone(table));
                    }
                }
            }
        }
        if let Some(table) = matched {
            let tail = match drain_buffered(&mut r).await {
                Ok(t) => t,
                Err(err) => return Err((r, anyhow!("drain buffered bytes failed: {err}"), probe)),
            };
            probe.extend_from_slice(&tail);
            return Ok((r, table, probe));
        }
        candidates = next;

        if candidates.is_empty() || !need_more {
            return Err((r, anyhow!("handshake table selection failed"), probe));
        }
        if probe.len() >= MAX_PROBE_BYTES {
            return Err((r, anyhow!("handshake probe exceeded {MAX_PROBE_BYTES} bytes"), probe));
        }

        let mut tmp = vec![0u8; READ_CHUNK];
        match r.read(&mut tmp).await {
            Ok(n) => {
                probe.extend_from_slice(tmp.split_at(n).0);
                if n == 0 {
                    return Err((r, anyhow!("handshake probe read failed: unexpected EOF"), probe));
                }
            }
            Err(err) => return Err((r, anyhow!("handshake probe read failed: {err}"), probe)),
        }
    }
}

/// Whether `err` looks like a short/incomplete read (a clean or unexpected EOF), i.e. the
/// probe needs more bytes rather than being a
/// definitive mismatch.
fn is_eof_like(err: &anyhow::Error) -> bool {
    if let Some(io_err) = err.downcast_ref::<io::Error>() {
        return io_err.kind() == io::ErrorKind::UnexpectedEof;
    }
    let msg = err.to_string();
    msg.contains("early eof") || msg.contains("unexpected end of file") || msg.contains("UnexpectedEof")
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    use crate::config::default_config;
    use crate::handshake::{client_handshake, read_server_session, server_handshake, SessionType};
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
    async fn custom_tables_rotation_probed_by_server() {
        let key = "rotate-test-key";
        let target = "8.8.8.8:53";

        let t1 = new_table_with_custom("rotate-seed", "prefer_entropy", "xpxvvpvv").expect("t1");
        let t2 = new_table_with_custom("rotate-seed", "prefer_entropy", "vxpvxvvp").expect("t2");

        let mut server_cfg = default_config();
        server_cfg.key = key.to_owned();
        server_cfg.aead_method = "chacha20-poly1305".to_owned();
        server_cfg.tables = vec![t1, t2];
        server_cfg.padding_min = 0;
        server_cfg.padding_max = 0;
        server_cfg.enable_pure_downlink = true;
        server_cfg.handshake_timeout_seconds = 5;
        server_cfg.disable_http_mask = true;

        let mut client_cfg = server_cfg.clone();
        client_cfg.server_address = "example.com:443".to_owned();

        for _ in 0..10 {
            let (server_conn, client_conn) = pipe_pair();

            let server_cfg_task = server_cfg.clone();
            let target_task = target.to_owned();
            let server_task = tokio::spawn(async move {
                let (c, meta) = server_handshake(server_conn, &server_cfg_task, None).await?;
                let session = read_server_session(c, Some(&meta)).await?;
                if session.typ != SessionType::Tcp {
                    return Err(anyhow::anyhow!("expected TCP session"));
                }
                if session.target != target_task {
                    return Err(anyhow::anyhow!("unexpected session target: {}", session.target));
                }
                let mut conn = session.conn;
                conn.write_all(&[0xaa, 0xbb, 0xcc]).await?;
                Ok::<(), anyhow::Error>(())
            });

            let mut c_conn = client_handshake(client_conn, &client_cfg).await.expect("client handshake");

            let addr_buf = crate::address::encode_address(target).expect("encode addr");
            crate::kip::write_kip_message(&mut c_conn, crate::kip::KIP_TYPE_OPEN_TCP, &addr_buf)
                .await
                .expect("write addr");

            let mut buf = [0u8; 3];
            c_conn.read_exact(&mut buf).await.expect("read payload");
            assert_eq!(buf, [0xaa, 0xbb, 0xcc], "payload mismatch");
            drop(c_conn);

            server_task.await.expect("server task join").expect("server");
        }
    }
}

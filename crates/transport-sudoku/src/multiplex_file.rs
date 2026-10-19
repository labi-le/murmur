use anyhow::{anyhow, Result};

use super::address::{decode_address, encode_address};
use super::kip::{write_kip_message, KIP_TYPE_START_MUX};
use crate::multiplex::session::Session;
use murmur_common_net::io::Stream;

/// Upgrades an already-handshaked Sudoku tunnel into a multiplex
/// session.
///
/// Deviation: the tunnel-ready check type-asserts `conn` against an internal
/// ready-conn interface, a no-op for any conn that isn't one (the common case here — `conn`
/// arrives from an arbitrary caller-supplied dialer already type-erased into a stream, same as
/// this crate's `Box<dyn Stream>`). This crate never had a reachable way to make that downcast
/// succeed here either (the boxed stream type deliberately carries no `Any`,
/// and `conn` has already lost its concrete type at the dialer boundary); the equivalent
/// downcast-based wrapper (`httpmask::tunnel_ready`) was removed as dead code once that was
/// confirmed, so the call is simply dropped here, matching its no-op outcome for every conn
/// that was never HTTPMask-tunnel wrapped in the first place.
pub(crate) async fn start_multiplex_client(
    _ctx: &tokio_util::sync::CancellationToken,
    conn: Box<dyn Stream>,
) -> Result<MultiplexClient> {
    let mut conn = conn;
    write_kip_message(&mut conn, KIP_TYPE_START_MUX, &[])
        .await
        .map_err(|err| anyhow!("write mux start failed: {err}"))?;

    let sess = Session::client(conn);

    Ok(MultiplexClient { sess })
}

pub(crate) struct MultiplexClient {
    sess: std::sync::Arc<Session>,
}

impl MultiplexClient {
    /// Opens a new logical stream, writes the target address, and
    /// returns the stream as a connection.
    pub(crate) async fn dial(
        &self,
        ctx: &tokio_util::sync::CancellationToken,
        target_address: &str,
    ) -> Result<Box<dyn Stream>> {
        if self.sess.is_closed() {
            return Err(anyhow!("multiplex session is closed"));
        }
        if target_address.trim().is_empty() {
            return Err(anyhow!("target address cannot be empty"));
        }

        let addr_buf = encode_address(target_address).map_err(|err| anyhow!("encode target address failed: {err}"))?;

        if ctx.is_cancelled() {
            return Err(anyhow!("context canceled"));
        }

        let stream = self.sess.open_stream(&addr_buf).await?;
        Ok(Box::new(stream))
    }

    pub(crate) fn close(&self) {
        self.sess.close();
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.sess.is_closed()
    }

    pub(crate) fn done(&self) -> tokio_util::sync::CancellationToken {
        self.sess.done()
    }
}

/// `AcceptMultiplexServer`: upgrades a server-side, already-handshaked Sudoku connection into a
/// multiplex session.
pub fn accept_multiplex_server(conn: Box<dyn Stream>) -> Result<MultiplexServer> {
    let sess = Session::server(conn);
    Ok(MultiplexServer { sess })
}

/// `MultiplexServer`: wraps a multiplex session created from a handshaked Sudoku tunnel
/// connection.
#[derive(Debug)]
pub struct MultiplexServer {
    sess: std::sync::Arc<Session>,
}

impl MultiplexServer {
    /// Accepts a multiplex stream and returns the target
    /// address declared in the open frame.
    pub async fn accept_tcp(&self) -> Result<(Box<dyn Stream>, String)> {
        let (stream, payload) = self.sess.accept_stream().await?;

        let target = match decode_address(&mut &payload[..]).await {
            Ok(target) => target,
            Err(err) => {
                let _ = murmur_common_net::io::close_stream(&stream);
                return Err(err);
            }
        };

        Ok((Box::new(stream), target))
    }

    pub fn close(&self) {
        self.sess.close();
    }

    #[allow(dead_code, reason = "mirrors MultiplexServer::is_closed; has no caller")]
    pub(crate) fn is_closed(&self) -> bool {
        self.sess.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::config::default_config;
    use crate::handshake::{client_handshake, read_server_session, server_handshake, SessionType};
    use crate::obfs::sudoku::table::new_table;

    #[tokio::test]
    async fn multiplex_tcp_echo() {
        let table = new_table("seed", "prefer_ascii");
        let key = "test-key-mux";
        let target = "example.com:80";

        let mut server_cfg = default_config();
        server_cfg.key = key.to_owned();
        server_cfg.aead_method = "chacha20-poly1305".to_owned();
        server_cfg.table = Some(table);
        server_cfg.padding_min = 0;
        server_cfg.padding_max = 0;
        server_cfg.enable_pure_downlink = true;
        server_cfg.handshake_timeout_seconds = 5;
        server_cfg.disable_http_mask = true;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let addr = listener.local_addr().expect("listener addr").to_string();

        let handshakes = std::sync::Arc::new(AtomicI64::new(0));
        let streams = std::sync::Arc::new(AtomicI64::new(0));
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let server_cfg_accept = server_cfg.clone();
        let handshakes_server = std::sync::Arc::clone(&handshakes);
        let streams_server = std::sync::Arc::clone(&streams);
        let target_server = target.to_owned();
        tokio::spawn(async move {
            let _done_tx = done_tx;
            let Ok((raw, _)) = listener.accept().await else {
                return;
            };

            let Ok((c, meta)) = server_handshake(Box::new(raw), &server_cfg_accept, None).await else {
                return;
            };
            handshakes_server.fetch_add(1, Ordering::SeqCst);

            let Ok(session) = read_server_session(c, Some(&meta)).await else {
                return;
            };
            if session.typ != SessionType::Multiplex {
                let _ = murmur_common_net::io::close_stream(&*session.conn);
                return;
            }

            let Ok(mux) = accept_multiplex_server(session.conn) else {
                return;
            };

            loop {
                let Ok((stream, dst)) = mux.accept_tcp().await else {
                    return;
                };
                if dst != target_server {
                    let _ = murmur_common_net::io::close_stream(&*stream);
                    return;
                }
                streams_server.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut stream = stream;
                    let (mut r, mut w) = tokio::io::split(&mut stream);
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        let mut client_cfg = server_cfg.clone();
        client_cfg.server_address = addr.clone();

        let raw = TcpStream::connect(&addr).await.expect("dial");
        let c_conn = client_handshake(Box::new(raw), &client_cfg).await.expect("client handshake");

        let ctx = tokio_util::sync::CancellationToken::new();
        let mux = start_multiplex_client(&ctx, c_conn).await.expect("start mux");

        for i in 0..6 {
            let mut s = mux.dial(&ctx, target).await.unwrap_or_else(|err| panic!("dial stream {i}: {err}"));

            let msg = b"hello-mux";
            s.write_all(msg).await.unwrap_or_else(|err| panic!("write: {err}"));
            let mut buf = vec![0u8; msg.len()];
            s.read_exact(&mut buf).await.unwrap_or_else(|err| panic!("read: {err}"));
            let _ = murmur_common_net::io::close_stream(&*s);
            assert_eq!(buf, msg, "echo mismatch: got {buf:?}");
        }

        mux.close();
        tokio::time::timeout(Duration::from_secs(5), done_rx).await.expect("server did not exit").ok();

        assert_eq!(handshakes.load(Ordering::SeqCst), 1, "unexpected handshake count");
        assert!(streams.load(Ordering::SeqCst) >= 6, "unexpected stream count");
    }
}

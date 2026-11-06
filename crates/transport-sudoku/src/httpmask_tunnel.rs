use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio_util::sync::CancellationToken;

use super::config::ProtocolConfig;
use super::early_handshake::{
    new_http_mask_client_early_handshake, new_http_mask_server_early_handshake, EarlyCodecConfig,
};
use super::init::{client_aead_seed, server_aead_seed};
use super::kip::{kip_user_hash_from_key, KIP_FEAT_ALL};
use super::replay::GLOBAL_HANDSHAKE_REPLAY;
use super::table_probe::pick_client_table;
use crate::obfs::httpmask::early_handshake::{ClientEarlyHandshake, WrapConnFn};
use crate::obfs::httpmask::tunnel_api::{dial_tunnel, HandleResult, TunnelDialOptions};
use crate::obfs::httpmask::tunnel_server::{new_tunnel_server, TunnelServer, TunnelServerOptions};
use murmur_common_net::io::Stream;

pub struct HttpMaskTunnelServer {
    cfg: Option<ProtocolConfig>,
    ts: Option<Arc<TunnelServer>>,
}

impl core::fmt::Debug for HttpMaskTunnelServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpMaskTunnelServer")
            .field("has_cfg", &self.cfg.is_some())
            .field("has_tunnel_server", &self.ts.is_some())
            .finish()
    }
}

fn new_http_mask_early_codec_config(cfg: &ProtocolConfig, psk: String) -> EarlyCodecConfig {
    EarlyCodecConfig {
        psk,
        aead: cfg.aead_method.clone(),
        enable_pure_downlink: cfg.enable_pure_downlink,
        padding_min: cfg.padding_min,
        padding_max: cfg.padding_max,
    }
}

async fn new_client_http_mask_early_handshake(cfg: &ProtocolConfig) -> Result<ClientEarlyHandshake> {
    let choice = pick_client_table(cfg)?;

    new_http_mask_client_early_handshake(
        new_http_mask_early_codec_config(cfg, client_aead_seed(&cfg.key)),
        choice.table,
        choice.hint,
        choice.has_hint,
        kip_user_hash_from_key(&cfg.key),
        KIP_FEAT_ALL,
    )
    .await
}

#[must_use]
pub fn new_http_mask_tunnel_server(cfg: ProtocolConfig) -> HttpMaskTunnelServer {
    new_http_mask_tunnel_server_impl(cfg, false)
}

#[must_use]
pub fn new_http_mask_tunnel_server_with_fallback(cfg: ProtocolConfig) -> HttpMaskTunnelServer {
    new_http_mask_tunnel_server_impl(cfg, true)
}

fn new_http_mask_tunnel_server_impl(cfg: ProtocolConfig, pass_through_on_reject: bool) -> HttpMaskTunnelServer {
    let mut ts = None;
    if !cfg.disable_http_mask {
        match cfg.http_mask_mode.trim().to_lowercase().as_str() {
            "stream" | "poll" | "auto" | "ws" => {
                ts = Some(new_tunnel_server(TunnelServerOptions {
                    mode: cfg.http_mask_mode.clone(),
                    path_root: cfg.http_mask_path_root.clone(),
                    auth_key: server_aead_seed(&cfg.key),
                    auth_skew: std::time::Duration::ZERO,
                    pass_through_on_reject,
                    pull_read_timeout: std::time::Duration::ZERO,
                    session_ttl: std::time::Duration::ZERO,
                    early_handshake: Some(new_http_mask_server_early_handshake(
                        new_http_mask_early_codec_config(&cfg, server_aead_seed(&cfg.key)),
                        cfg.table_candidates(),
                        Arc::new(|user_hash: &str, nonce, now| GLOBAL_HANDSHAKE_REPLAY.allow(user_hash, nonce, now)),
                    )),
                }));
            }
            _ => {}
        }
    }
    HttpMaskTunnelServer { cfg: Some(cfg), ts }
}

/// HTTPMask tunnel modes (stream/poll/auto/ws) add extra round trips before the first
/// handshake bytes can reach ServerHandshake, especially under high concurrency, so tunneled
/// conns get a higher handshake timeout than raw TCP.
const MIN_TUNNELED_HANDSHAKE_TIMEOUT_SECONDS: i32 = 15;

impl HttpMaskTunnelServer {
    /// Inspects an accepted TCP connection and upgrades it
    /// to an HTTP tunnel stream when needed.
    ///
    /// Returns:
    ///   - `done=true`: this TCP connection has been fully handled (e.g., stream/poll control
    ///     request), caller should return
    ///   - `done=false`: `handshake_conn`+`cfg` are ready for `server_handshake`, together with the
    ///     early-handshake user hash when the conn already completed a full application-level
    ///     handshake (httpmask early handshake); pass it straight to `server_handshake` so it can
    ///     short-circuit like the early-handshake user-hash check
    pub async fn wrap_conn(
        &self,
        raw_conn: Box<dyn Stream>,
    ) -> Result<(Option<Box<dyn Stream>>, Option<ProtocolConfig>, bool, Option<String>)> {
        let Some(ts) = &self.ts else {
            return Ok((Some(raw_conn), self.cfg.clone(), false, None));
        };

        let (res, c) = ts.handle_conn(raw_conn).await?;

        match res {
            HandleResult::Done => Ok((None, None, true, None)),
            HandleResult::PassThrough => Ok((c, self.cfg.clone(), false, None)),
            HandleResult::StartTunnel(early_user_hash) => {
                let mut inner = self.cfg.clone().ok_or_else(|| anyhow!("config is required"))?;
                inner.disable_http_mask = true;
                if inner.handshake_timeout_seconds <= 0
                    || inner.handshake_timeout_seconds < MIN_TUNNELED_HANDSHAKE_TIMEOUT_SECONDS
                {
                    inner.handshake_timeout_seconds = MIN_TUNNELED_HANDSHAKE_TIMEOUT_SECONDS;
                }
                Ok((c, Some(inner), false, early_user_hash))
            }
        }
    }
}

pub type TunnelDialer = Arc<
    dyn Fn(CancellationToken, String, String) -> futures::future::BoxFuture<'static, Result<Box<dyn Stream>>>
        + Send
        + Sync,
>;

/// `DialHTTPMaskTunnel`: dials a CDN-capable HTTP tunnel (stream/poll/auto/ws) and returns a
/// stream carrying raw Sudoku bytes.
pub async fn dial_http_mask_tunnel(
    ctx: &CancellationToken,
    server_address: &str,
    cfg: &ProtocolConfig,
    dial: Option<TunnelDialer>,
    upgrade: Option<WrapConnFn>,
) -> Result<Box<dyn Stream>> {
    if cfg.disable_http_mask {
        return Err(anyhow!("http mask is disabled"));
    }
    match cfg.http_mask_mode.trim().to_lowercase().as_str() {
        "stream" | "poll" | "auto" | "ws" => {}
        other => return Err(anyhow!("http-mask-mode={other:?} does not use http tunnel")),
    }

    let early_handshake = if upgrade.is_some() { Some(new_client_http_mask_early_handshake(cfg).await?) } else { None };

    let dial_context = dial.map(|dial| -> Arc<dyn murmur_component::dialer::options::NetDialer> {
        Arc::new(murmur_component::dialer::options::NetDialerFunc::new(move |ctx, host, port| dial(ctx, host, port)))
    });

    dial_tunnel(
        ctx,
        server_address,
        TunnelDialOptions {
            mode: cfg.http_mask_mode.clone(),
            tls_enabled: cfg.http_mask_tls_enabled,
            host_override: cfg.http_mask_host.clone(),
            path_root: cfg.http_mask_path_root.clone(),
            auth_key: client_aead_seed(&cfg.key),
            early_handshake,
            upgrade,
            dial_context,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::future::BoxFuture;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::task::JoinSet;

    use super::*;
    use crate::address::encode_address;
    use crate::config::default_config;
    use crate::handshake::{client_handshake, read_server_session, server_handshake, ServerSession, SessionType};
    use crate::init::new_table;
    use crate::kip::{write_kip_message, KIP_TYPE_OPEN_TCP, KIP_TYPE_START_UOT};
    use crate::tables::new_tables_with_custom_patterns;
    use crate::uot::{read_datagram, write_datagram};

    type SessionHandler = Arc<dyn Fn(ServerSession) -> BoxFuture<'static, Result<()>> + Send + Sync>;

    struct TunnelTestServer {
        addr: String,
        cancel: CancellationToken,
        accept_task: tokio::task::JoinHandle<()>,
        err_rx: mpsc::Receiver<anyhow::Error>,
    }

    impl TunnelTestServer {
        async fn stop(self) -> Vec<anyhow::Error> {
            self.cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), self.accept_task).await;
            let mut err_rx = self.err_rx;
            err_rx.close();
            let mut errs = Vec::new();
            while let Ok(err) = err_rx.try_recv() {
                errs.push(err);
            }
            errs
        }
    }

    async fn start_tunnel_server(cfg: ProtocolConfig, handle: SessionHandler) -> TunnelTestServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let addr = listener.local_addr().expect("listener addr").to_string();

        let (err_tx, err_rx) = mpsc::channel(128);
        let cancel = CancellationToken::new();
        let loop_cancel = cancel.clone();
        let tunnel_srv = Arc::new(new_http_mask_tunnel_server(cfg));

        let accept_task = tokio::spawn(async move {
            let mut join_set = JoinSet::new();
            loop {
                tokio::select! {
                    () = loop_cancel.cancelled() => break,
                    accept_res = listener.accept() => {
                        let (stream, _) = match accept_res {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        let tunnel_srv = Arc::clone(&tunnel_srv);
                        let handle = Arc::clone(&handle);
                        let err_tx = err_tx.clone();
                        join_set.spawn(async move {
                            let conn: Box<dyn Stream> = Box::new(stream);
                            let (handshake_conn, handshake_cfg, handled, early_user_hash) =
                                match tunnel_srv.wrap_conn(conn).await {
                                    Ok(v) => v,
                                    Err(err) => {
                                        let skip = err
                                            .downcast_ref::<std::io::Error>()
                                            .is_some_and(|io_err| {
                                                matches!(
                                                    io_err.kind(),
                                                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::UnexpectedEof
                                                )
                                            });
                                        if !skip {
                                            let _ = err_tx.send(err).await;
                                        }
                                        return;
                                    }
                                };
                            if handled {
                                return;
                            }
                            let (Some(handshake_conn), Some(handshake_cfg)) = (handshake_conn, handshake_cfg) else {
                                let _ = err_tx.send(anyhow!("wrap conn returned nil")).await;
                                return;
                            };

                            let (c_conn, meta) =
                                match server_handshake(handshake_conn, &handshake_cfg, early_user_hash.as_deref())
                                    .await
                                {
                                Ok(v) => v,
                                Err(err) => {
                                    let _ = err_tx.send(err).await;
                                    return;
                                }
                            };

                            let session = match read_server_session(c_conn, Some(&meta)).await {
                                Ok(v) => v,
                                Err(err) => {
                                    let _ = err_tx.send(err).await;
                                    return;
                                }
                            };
                            if let Err(err) = handle(session).await {
                                let _ = err_tx.send(err).await;
                            }
                        });
                    }
                }
            }
            while join_set.join_next().await.is_some() {}
        });

        TunnelTestServer { addr, cancel, accept_task, err_rx }
    }

    fn new_tunnel_test_table(key: &str) -> ProtocolConfig {
        let tables =
            new_tables_with_custom_patterns(&client_aead_seed(key), "prefer_ascii", "", &[]).expect("build tables");
        assert_eq!(tables.len(), 1, "unexpected tables: {}", tables.len());

        let mut cfg = default_config();
        cfg.key = key.to_owned();
        cfg.aead_method = "chacha20-poly1305".to_owned();
        cfg.table = Some(Arc::clone(&tables[0]));
        cfg.padding_min = 0;
        cfg.padding_max = 0;
        cfg.handshake_timeout_seconds = 5;
        cfg.enable_pure_downlink = true;
        cfg.disable_http_mask = false;
        cfg
    }

    /// A dialer as used by the tests.
    fn test_dialer() -> TunnelDialer {
        Arc::new(
            |_ctx: CancellationToken,
             _network: String,
             address: String|
             -> BoxFuture<'static, Result<Box<dyn Stream>>> {
                Box::pin(async move {
                    let stream = TcpStream::connect(&address).await?;
                    let conn: Box<dyn Stream> = Box::new(stream);
                    Ok(conn)
                })
            },
        )
    }

    #[tokio::test]
    async fn http_mask_tunnel_stream_tcp_round_trip() {
        let key = "tunnel-stream-key";
        let target = "1.1.1.1:80";

        let mut server_cfg = new_tunnel_test_table(key);
        server_cfg.http_mask_mode = "stream".to_owned();

        let handler: SessionHandler = Arc::new(move |mut s: ServerSession| {
            Box::pin(async move {
                if s.typ != SessionType::Tcp {
                    return Err(anyhow!("unexpected session type: {:?}", s.typ));
                }
                if s.target != target {
                    return Err(anyhow!("target mismatch: {}", s.target));
                }
                let _ = s.conn.write_all(b"ok").await;
                Ok(())
            })
        });

        let server = start_tunnel_server(server_cfg.clone(), handler).await;

        let ctx = CancellationToken::new();

        let mut client_cfg = server_cfg.clone();
        client_cfg.server_address = server.addr.clone();
        client_cfg.http_mask_host = "example.com".to_owned();

        let tunnel_conn =
            dial_http_mask_tunnel(&ctx, &client_cfg.server_address, &client_cfg, Some(test_dialer()), None)
                .await
                .expect("dial tunnel");

        let mut handshake_cfg = client_cfg.clone();
        handshake_cfg.disable_http_mask = true;
        let mut c_conn = client_handshake(tunnel_conn, &handshake_cfg).await.expect("client handshake");

        let addr_buf = encode_address(target).expect("encode addr");
        write_kip_message(&mut c_conn, KIP_TYPE_OPEN_TCP, &addr_buf).await.expect("write addr");

        let mut buf = [0u8; 2];
        c_conn.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ok", "unexpected payload: {buf:?}");

        let errs = server.stop().await;
        assert!(errs.is_empty(), "server error: {:?}", errs.first());
    }

    #[tokio::test]
    async fn http_mask_tunnel_poll_uot_round_trip() {
        let key = "tunnel-poll-key";
        let target = "8.8.8.8:53";
        let payload = [0xaa_u8, 0xbb, 0xcc, 0xdd];

        let mut server_cfg = new_tunnel_test_table(key);
        server_cfg.http_mask_mode = "poll".to_owned();

        let handler: SessionHandler = Arc::new(move |mut s: ServerSession| {
            Box::pin(async move {
                if s.typ != SessionType::UoT {
                    return Err(anyhow!("unexpected session type: {:?}", s.typ));
                }
                let (got_addr, got_payload) =
                    read_datagram(&mut s.conn).await.map_err(|err| anyhow!("server read datagram: {err}"))?;
                if got_addr != target {
                    return Err(anyhow!("uot target mismatch: {got_addr}"));
                }
                if got_payload != payload {
                    return Err(anyhow!("uot payload mismatch: {got_payload:x?}"));
                }
                write_datagram(&mut s.conn, &got_addr, &got_payload)
                    .await
                    .map_err(|err| anyhow!("server write datagram: {err}"))?;
                Ok(())
            })
        });

        let server = start_tunnel_server(server_cfg.clone(), handler).await;

        let ctx = CancellationToken::new();

        let mut client_cfg = server_cfg.clone();
        client_cfg.server_address = server.addr.clone();

        let tunnel_conn =
            dial_http_mask_tunnel(&ctx, &client_cfg.server_address, &client_cfg, Some(test_dialer()), None)
                .await
                .expect("dial tunnel");

        let mut handshake_cfg = client_cfg.clone();
        handshake_cfg.disable_http_mask = true;
        let mut c_conn = client_handshake(tunnel_conn, &handshake_cfg).await.expect("client handshake");

        write_kip_message(&mut c_conn, KIP_TYPE_START_UOT, &[]).await.expect("start uot");
        write_datagram(&mut c_conn, target, &payload).await.expect("write datagram");
        let (got_addr, got_payload) = read_datagram(&mut c_conn).await.expect("read datagram");
        assert_eq!(got_addr, target, "uot target mismatch: {got_addr}");
        assert_eq!(got_payload, payload, "uot payload mismatch: {got_payload:x?}");

        let errs = server.stop().await;
        assert!(errs.is_empty(), "server error: {:?}", errs.first());
    }

    #[tokio::test]
    async fn http_mask_tunnel_auto_tcp_round_trip() {
        let key = "tunnel-auto-key";
        let target = "9.9.9.9:443";

        let mut server_cfg = new_tunnel_test_table(key);
        server_cfg.http_mask_mode = "auto".to_owned();

        let handler: SessionHandler = Arc::new(move |mut s: ServerSession| {
            Box::pin(async move {
                if s.typ != SessionType::Tcp {
                    return Err(anyhow!("unexpected session type: {:?}", s.typ));
                }
                if s.target != target {
                    return Err(anyhow!("target mismatch: {}", s.target));
                }
                let _ = s.conn.write_all(b"ok").await;
                Ok(())
            })
        });

        let server = start_tunnel_server(server_cfg.clone(), handler).await;

        let ctx = CancellationToken::new();

        let mut client_cfg = server_cfg.clone();
        client_cfg.server_address = server.addr.clone();

        let tunnel_conn =
            dial_http_mask_tunnel(&ctx, &client_cfg.server_address, &client_cfg, Some(test_dialer()), None)
                .await
                .expect("dial tunnel");

        let mut handshake_cfg = client_cfg.clone();
        handshake_cfg.disable_http_mask = true;
        let mut c_conn = client_handshake(tunnel_conn, &handshake_cfg).await.expect("client handshake");

        let addr_buf = encode_address(target).expect("encode addr");
        write_kip_message(&mut c_conn, KIP_TYPE_OPEN_TCP, &addr_buf).await.expect("write addr");

        let mut buf = [0u8; 2];
        c_conn.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ok", "unexpected payload: {buf:?}");

        let errs = server.stop().await;
        assert!(errs.is_empty(), "server error: {:?}", errs.first());
    }

    #[tokio::test]
    async fn http_mask_tunnel_ws_tcp_round_trip() {
        let key = "tunnel-ws-key";
        let target = "1.1.1.1:80";

        let mut server_cfg = new_tunnel_test_table(key);
        server_cfg.http_mask_mode = "ws".to_owned();

        let handler: SessionHandler = Arc::new(move |mut s: ServerSession| {
            Box::pin(async move {
                if s.typ != SessionType::Tcp {
                    return Err(anyhow!("unexpected session type: {:?}", s.typ));
                }
                if s.target != target {
                    return Err(anyhow!("target mismatch: {}", s.target));
                }
                let _ = s.conn.write_all(b"ok").await;
                Ok(())
            })
        });

        let server = start_tunnel_server(server_cfg.clone(), handler).await;

        let ctx = CancellationToken::new();

        let mut client_cfg = server_cfg.clone();
        client_cfg.server_address = server.addr.clone();

        let tunnel_conn =
            dial_http_mask_tunnel(&ctx, &client_cfg.server_address, &client_cfg, Some(test_dialer()), None)
                .await
                .expect("dial tunnel");

        let mut handshake_cfg = client_cfg.clone();
        handshake_cfg.disable_http_mask = true;
        let mut c_conn = client_handshake(tunnel_conn, &handshake_cfg).await.expect("client handshake");

        let addr_buf = encode_address(target).expect("encode addr");
        write_kip_message(&mut c_conn, KIP_TYPE_OPEN_TCP, &addr_buf).await.expect("write addr");

        let mut buf = [0u8; 2];
        c_conn.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ok", "unexpected payload: {buf:?}");

        let errs = server.stop().await;
        assert!(errs.is_empty(), "server error: {:?}", errs.first());
    }

    #[tokio::test]
    async fn http_mask_tunnel_early_handshake_tcp_round_trip() {
        for mode in ["stream", "poll", "ws"] {
            let key = format!("tunnel-early-{mode}");
            let target = "1.1.1.1:80";

            let mut server_cfg = new_tunnel_test_table(&key);
            server_cfg.http_mask_mode = mode.to_owned();

            let handler: SessionHandler = Arc::new(move |mut s: ServerSession| {
                Box::pin(async move {
                    if s.typ != SessionType::Tcp {
                        return Err(anyhow!("unexpected session type: {:?}", s.typ));
                    }
                    if s.target != target {
                        return Err(anyhow!("target mismatch: {}", s.target));
                    }
                    let _ = s.conn.write_all(b"ok").await;
                    Ok(())
                })
            });

            let server = start_tunnel_server(server_cfg.clone(), handler).await;

            let ctx = CancellationToken::new();

            let mut client_cfg = server_cfg.clone();
            client_cfg.server_address = server.addr.clone();

            let mut handshake_cfg = client_cfg.clone();
            handshake_cfg.disable_http_mask = true;
            let upgrade: WrapConnFn = Arc::new(move |raw: Box<dyn Stream>| {
                let handshake_cfg = handshake_cfg.clone();
                Box::pin(async move { client_handshake(raw, &handshake_cfg).await })
            });

            let mut tunnel_conn = tokio::time::timeout(
                Duration::from_secs(10),
                dial_http_mask_tunnel(
                    &ctx,
                    &client_cfg.server_address,
                    &client_cfg,
                    Some(test_dialer()),
                    Some(upgrade),
                ),
            )
            .await
            .expect("dial tunnel timed out")
            .expect("dial tunnel");

            let addr_buf = encode_address(target).expect("encode addr");
            write_kip_message(&mut tunnel_conn, KIP_TYPE_OPEN_TCP, &addr_buf).await.expect("write addr");

            let mut buf = [0u8; 2];
            tunnel_conn.read_exact(&mut buf).await.expect("read");
            assert_eq!(&buf, b"ok", "unexpected payload: {buf:?}");

            let errs = server.stop().await;
            assert!(errs.is_empty(), "server error: {:?}", errs.first());
        }
    }

    #[tokio::test]
    async fn http_mask_tunnel_early_handshake_auto_path_root_tcp_round_trip() {
        let key = "tunnel-early-auto-pathroot";
        let target = "1.1.1.1:80";

        let mut server_cfg = new_tunnel_test_table(key);
        server_cfg.http_mask_mode = "auto".to_owned();
        server_cfg.http_mask_path_root = "httpmaskpath".to_owned();

        let handler: SessionHandler = Arc::new(move |mut s: ServerSession| {
            Box::pin(async move {
                if s.typ != SessionType::Tcp {
                    return Err(anyhow!("unexpected session type: {:?}", s.typ));
                }
                if s.target != target {
                    return Err(anyhow!("target mismatch: {}", s.target));
                }
                let _ = s.conn.write_all(b"ok").await;
                Ok(())
            })
        });

        let server = start_tunnel_server(server_cfg.clone(), handler).await;

        let ctx = CancellationToken::new();

        let mut client_cfg = server_cfg.clone();
        client_cfg.server_address = server.addr.clone();

        let mut handshake_cfg = client_cfg.clone();
        handshake_cfg.disable_http_mask = true;
        let upgrade: WrapConnFn = Arc::new(move |raw: Box<dyn Stream>| {
            let handshake_cfg = handshake_cfg.clone();
            Box::pin(async move { client_handshake(raw, &handshake_cfg).await })
        });

        let mut tunnel_conn = tokio::time::timeout(
            Duration::from_secs(10),
            dial_http_mask_tunnel(&ctx, &client_cfg.server_address, &client_cfg, Some(test_dialer()), Some(upgrade)),
        )
        .await
        .expect("dial tunnel timed out")
        .expect("dial tunnel");

        let addr_buf = encode_address(target).expect("encode addr");
        write_kip_message(&mut tunnel_conn, KIP_TYPE_OPEN_TCP, &addr_buf).await.expect("write addr");

        let mut buf = [0u8; 2];
        tunnel_conn.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ok", "unexpected payload: {buf:?}");

        let errs = server.stop().await;
        assert!(errs.is_empty(), "server error: {:?}", errs.first());
    }

    #[tokio::test]
    async fn http_mask_tunnel_validation() {
        let mut cfg = default_config();
        cfg.key = "k".to_owned();
        cfg.table = Some(new_table("seed", "prefer_ascii"));
        cfg.server_address = "127.0.0.1:1".to_owned();

        let ctx = CancellationToken::new();

        cfg.disable_http_mask = true;
        cfg.http_mask_mode = "stream".to_owned();
        assert!(
            dial_http_mask_tunnel(&ctx, &cfg.server_address, &cfg, None, None).await.is_err(),
            "expected error for disabled http mask"
        );

        cfg.disable_http_mask = false;
        cfg.http_mask_mode = "legacy".to_owned();
        assert!(
            dial_http_mask_tunnel(&ctx, &cfg.server_address, &cfg, None, None).await.is_err(),
            "expected error for legacy mode"
        );
    }

    #[tokio::test]
    async fn http_mask_tunnel_soak_concurrent() {
        let key = "tunnel-soak-key";
        let target = "1.0.0.1:80";

        let mut server_cfg = new_tunnel_test_table(key);
        server_cfg.http_mask_mode = "stream".to_owned();
        server_cfg.enable_pure_downlink = false;

        const SESSIONS: usize = 8;
        const PAYLOAD_LEN: usize = 64 * 1024;

        let handler: SessionHandler = Arc::new(move |mut s: ServerSession| {
            Box::pin(async move {
                if s.typ != SessionType::Tcp {
                    return Err(anyhow!("unexpected session type: {:?}", s.typ));
                }
                if s.target != target {
                    return Err(anyhow!("target mismatch: {}", s.target));
                }
                let mut buf = vec![0u8; PAYLOAD_LEN];
                s.conn.read_exact(&mut buf).await.map_err(|err| anyhow!("server read payload: {err}"))?;
                s.conn.write_all(&buf).await.map_err(|err| anyhow!("{err}"))?;
                Ok(())
            })
        });

        let server = start_tunnel_server(server_cfg.clone(), handler).await;

        let ctx = CancellationToken::new();

        let mut tasks = Vec::new();
        for id in 0..SESSIONS {
            let server_cfg = server_cfg.clone();
            let addr = server.addr.clone();
            let ctx = ctx.clone();
            tasks.push(tokio::spawn(async move {
                let mut client_cfg = server_cfg.clone();
                client_cfg.server_address = addr;
                client_cfg.http_mask_host = client_cfg.http_mask_host.trim().to_owned();

                let tunnel_conn =
                    dial_http_mask_tunnel(&ctx, &client_cfg.server_address, &client_cfg, Some(test_dialer()), None)
                        .await
                        .map_err(|err| anyhow!("dial: {err}"))?;

                let mut handshake_cfg = client_cfg.clone();
                handshake_cfg.disable_http_mask = true;
                let mut c_conn =
                    client_handshake(tunnel_conn, &handshake_cfg).await.map_err(|err| anyhow!("handshake: {err}"))?;

                let addr_buf = encode_address(target).map_err(|err| anyhow!("encode addr: {err}"))?;
                write_kip_message(&mut c_conn, KIP_TYPE_OPEN_TCP, &addr_buf)
                    .await
                    .map_err(|err| anyhow!("write addr: {err}"))?;

                let payload = vec![id as u8; PAYLOAD_LEN];
                c_conn.write_all(&payload).await.map_err(|err| anyhow!("write payload: {err}"))?;

                let mut echo = vec![0u8; PAYLOAD_LEN];
                c_conn.read_exact(&mut echo).await.map_err(|err| anyhow!("read echo: {err}"))?;

                if echo != payload {
                    return Err(anyhow!("echo mismatch"));
                }
                Ok::<(), anyhow::Error>(())
            }));
        }

        for task in tasks {
            task.await.expect("join soak task").expect("soak");
        }

        let errs = server.stop().await;
        assert!(errs.is_empty(), "server error: {:?}", errs.first());
    }
}

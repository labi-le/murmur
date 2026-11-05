use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};
use tokio_util::sync::CancellationToken;

use murmur_common_net::deadline::pipe_sing::pipe;
use murmur_common_net::io::{close_stream, OldConnAsStream, Stream, StreamAsOldConn};
use murmur_component_ca as ca;
use murmur_component_tls::utls;
use murmur_std_compat::net::Conn as NetConn;

use super::config::{decode_primary_key, ClientConfig};
use super::conn::{new_hidden_conn, Conn, ERR_CARRIER_HANDSHAKE};
use super::enrollment::{
    derive_enrollment_server_identifier, is_connection_enrollment_bypassed, is_loopback_protection_enabled,
    verify_connection_enrollment, DialCtx,
};
use super::mirror::{hrtb_hook, new_mirror_conn, FnHook, MessageHook, SharedConn};
use super::record::Record;
use super::traffic::{run_traffic_generator, traffic_generator_waits_for_ready, SharedConn as TrafficSharedConn};

// NOT cancel-safe: a dropped future leaves the mirror and its carrier tasks running; only the
// cancellation arms close the hidden conn.
pub async fn dial(ctx: &DialCtx, raw_conn: Box<dyn Stream>, cfg: ClientConfig) -> Result<Conn> {
    let key = decode_primary_key(&cfg.config.primary_key)?;
    if cfg.config.connection_enrolment.is_some() {
        let server_id = derive_enrollment_server_identifier(&key)?;
        if is_loopback_protection_enabled(ctx, &server_id) {
            let _ = close_stream(raw_conn.as_ref());
            return Err(anyhow!("tlsmirror: loopback protection refused dialing to self"));
        }
    }

    let mut server_name = cfg.server_name.clone();
    if server_name.is_empty() {
        server_name = cfg.forward_address_hint.clone();
    }
    if server_name.is_empty() && !cfg.skip_cert_verify {
        return Err(anyhow!("tlsmirror: server-name is required when certificate verification is enabled"));
    }

    let (tls_side, mirror_side) = pipe();
    let lifetime_ctx = CancellationToken::new();

    let hidden_cell: Arc<OnceLock<Conn>> = Arc::new(OnceLock::new());
    let inbound_hook: Arc<dyn MessageHook> = {
        let cell = Arc::clone(&hidden_cell);
        Arc::new(FnHook(hrtb_hook(move |rec: &mut Record| {
            let cell = Arc::clone(&cell);
            Box::pin(async move {
                let Some(hidden) = cell.get().cloned() else {
                    return Err(anyhow!("tlsmirror: hidden conn is not set"));
                };
                hidden.handle_inbound_record(rec).await
            })
        })))
    };

    let mirror = new_mirror_conn(
        &lifetime_ctx,
        SharedConn::new(Box::new(mirror_side)),
        SharedConn::new(Box::new(StreamAsOldConn::new(raw_conn))),
        &cfg.config,
        None,
        Some(inbound_hook),
        None,
        None,
    );
    let hidden = match new_hidden_conn(&lifetime_ctx, Arc::clone(&mirror), key, false, cfg.config.clone()) {
        Ok(hidden) => hidden,
        Err(err) => {
            let _ = mirror.close();
            return Err(err);
        }
    };
    hidden_cell.set(hidden.clone()).ok();
    mirror.set_on_c2s_message_tx(hidden.as_outbound_tx_hook());
    mirror.start();

    let tls_config = match new_tls_config(&cfg, &server_name) {
        Ok(tls_config) => tls_config,
        Err(err) => {
            let _ = hidden.close();
            return Err(err);
        }
    };

    let tls_side: Box<dyn Stream> = Box::new(OldConnAsStream(tls_side));
    let (carrier_tls, carrier_alpn) = handshake_carrier(ctx, tls_side, tls_config, &cfg, &hidden).await?;

    run_carrier_traffic(ctx, &hidden, carrier_tls, carrier_alpn, &cfg).await?;

    if cfg.config.connection_enrolment.is_some() && !is_connection_enrollment_bypassed(ctx) {
        if let Err(err) = verify_connection_enrollment(&hidden, ctx, &cfg).await {
            let _ = hidden.close();
            return Err(err);
        }
    }
    Ok(hidden)
}

fn new_tls_config(cfg: &ClientConfig, server_name: &str) -> Result<utls::Config> {
    let utls::Config {
        rand,
        time,
        certificates,
        get_certificate,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        client_auth,
        client_cas,
        cipher_suites,
        session_tickets_disabled,
        min_version,
        max_version,
        curve_preferences,
        renegotiation,
        key_log_writer,
        encrypted_client_hello_config_list,
        encrypted_client_hello_rejection_verify,
        encrypted_client_hello_keys,
        get_encrypted_client_hello_keys,
        session_id_generator,
        ..
    } = utls::Config::default();
    let ca::config::Option { zero_trust, .. } = ca::config::Option::default();
    ca::config::get_tls_config(ca::config::Option {
        tls_config: Some(utls::Config {
            server_name: server_name.to_owned(),
            insecure_skip_verify: cfg.skip_cert_verify,
            next_protos: cfg.alpn.clone(),
            rand,
            time,
            certificates,
            get_certificate,
            get_client_certificate,
            verify_peer_certificate,
            verify_connection,
            root_cas,
            client_auth,
            client_cas,
            cipher_suites,
            session_tickets_disabled,
            min_version,
            max_version,
            curve_preferences,
            renegotiation,
            key_log_writer,
            encrypted_client_hello_config_list,
            encrypted_client_hello_rejection_verify,
            encrypted_client_hello_keys,
            get_encrypted_client_hello_keys,
            session_id_generator,
        }),
        fingerprint: cfg.fingerprint.clone(),
        name_cert_verify: cfg.name_cert_verify.clone(),
        zero_trust,
        certificate: cfg.certificate.clone(),
        private_key: cfg.private_key.clone(),
    })
}

async fn handshake_carrier(
    ctx: &DialCtx,
    tls_side: Box<dyn Stream>,
    tls_config: utls::Config,
    cfg: &ClientConfig,
    hidden: &Conn,
) -> Result<(Box<dyn NetConn>, String)> {
    let (fingerprint, ok) = utls::get_fingerprint(&cfg.client_fingerprint);
    if ok {
        let mut tls_config = tls_config;
        if let Some(ech) = &cfg.ech {
            if let Err(err) = ech.client_handle_utls(ctx, &mut tls_config).await {
                let _ = hidden.close();
                return Err(err);
            }
        }
        let mut u_conn = utls::uclient(tls_side, Arc::new(tls_config), fingerprint);
        if let Err(err) = u_conn.handshake_context(ctx.token()).await {
            let _ = hidden.close();
            return Err(anyhow!("{ERR_CARRIER_HANDSHAKE}: {err}"));
        }
        let alpn = utls::get_tls_connection_state(&u_conn).negotiated_protocol;
        Ok((Box::new(StreamAsOldConn::new(u_conn)), alpn))
    } else {
        let mut tls_config = tls_config;
        if let Some(ech) = &cfg.ech {
            if let Err(err) = ech.client_handle(ctx, &mut tls_config).await {
                let _ = hidden.close();
                return Err(err);
            }
        }
        let tls_conn = utls::client(tls_side, Arc::new(tls_config));
        if let Err(err) = tls_conn.handshake_context(ctx.token()).await {
            let _ = hidden.close();
            return Err(anyhow!("{ERR_CARRIER_HANDSHAKE}: {err}"));
        }
        let alpn = utls::get_tls_connection_state(&tls_conn).negotiated_protocol;
        Ok((Box::new(StreamAsOldConn::new(tls_conn)), alpn))
    }
}

async fn run_carrier_traffic(
    ctx: &DialCtx,
    hidden: &Conn,
    carrier_tls: Box<dyn NetConn>,
    carrier_alpn: String,
    cfg: &ClientConfig,
) -> Result<()> {
    let recall = CancellationToken::new();
    let recall_once = Arc::new(std::sync::Once::new());
    {
        let recall = recall.clone();
        let recall_once = Arc::clone(&recall_once);
        hidden.set_recall_traffic_generator(Arc::new(move || {
            recall_once.call_once(|| recall.cancel());
        }));
    }

    let ready = CancellationToken::new();
    let done = CancellationToken::new();
    {
        let hidden_ctx = hidden.ctx().clone();
        let ready = ready.clone();
        let done = done.clone();
        let cfg_traffic = cfg.config.embedded_traffic_generator.clone();
        let carrier_conn = TrafficSharedConn::new(carrier_tls);
        tokio::spawn(async move {
            run_traffic_generator(
                &hidden_ctx,
                carrier_conn,
                cfg_traffic.as_ref(),
                &carrier_alpn,
                move || ready.cancel(),
                &recall,
            )
            .await;
            done.cancel();
        });
    }

    if !traffic_generator_waits_for_ready(cfg.config.embedded_traffic_generator.as_ref()) {
        return Ok(());
    }
    tokio::select! {
        () = ready.cancelled() => Ok(()),
        () = done.cancelled() => {
            let _ = hidden.close();
            Err(anyhow!("tlsmirror: carrier traffic generator exited before ready"))
        }
        () = hidden.ctx().cancelled() => Err(anyhow!("context canceled")),
        () = ctx.cancelled() => {
            let _ = hidden.close();
            Err(anyhow!("context canceled"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use http_body_util::StreamBody;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    use crate::config::{
        generate_primary_key, Config, TimeSpec, TrafficGenerator, TrafficHeader, TrafficStep, TrafficTransferCandidate,
        TransportLayerPadding,
    };
    use crate::server::serve_conn_ready;
    use murmur_component_ca::keypair::{new_random_tls_key_pair, x509_key_pair, KeyPairType};

    use super::*;

    async fn start_test_forward_tls(configure: Option<fn(&mut utls::Config)>) -> String {
        let (cert_pem, key_pem, _fingerprint) =
            new_random_tls_key_pair(KeyPairType::P256).expect("generate forward TLS key pair");
        let certificate =
            x509_key_pair(cert_pem.as_bytes(), key_pem.as_bytes()).expect("parse forward TLS certificate");
        let mut config =
            utls::Config { certificates: vec![certificate], min_version: utls::VERSION_TLS13, ..Default::default() };
        if let Some(configure) = configure {
            configure(&mut config);
        }
        let config = Arc::new(config);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind forward listener");
        let addr = listener.local_addr().expect("forward listener addr").to_string();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    let mut conn = utls::server(Box::new(stream), config);
                    if conn.handshake().await.is_err() {
                        return;
                    }
                    let _ = tokio::io::copy(&mut conn, &mut tokio::io::sink()).await;
                });
            }
        });
        addr
    }

    async fn start_test_forward_https(requests: Arc<AtomicI32>) -> String {
        let (cert_pem, key_pem, _fingerprint) =
            new_random_tls_key_pair(KeyPairType::P256).expect("generate forward TLS key pair");
        let certificate =
            x509_key_pair(cert_pem.as_bytes(), key_pem.as_bytes()).expect("parse forward TLS certificate");
        let config = Arc::new(utls::Config {
            certificates: vec![certificate],
            min_version: utls::VERSION_TLS13,
            ..Default::default()
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind forward listener");
        let addr = listener.local_addr().expect("forward listener addr").to_string();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let config = Arc::clone(&config);
                let requests = Arc::clone(&requests);
                tokio::spawn(async move {
                    let conn = utls::server(Box::new(stream), config);
                    if conn.handshake().await.is_err() {
                        return;
                    }
                    let mut reader = BufReader::new(conn);
                    loop {
                        let mut line = String::new();
                        match reader.read_line(&mut line).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                        if line == "\r\n" {
                            break;
                        }
                    }
                    requests.fetch_add(1, Ordering::SeqCst);
                    let response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
                    if reader.get_mut().write_all(response).await.is_err() {
                        return;
                    }
                    let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
                });
            }
        });
        addr
    }

    async fn start_test_forward_http2(requests: Arc<AtomicI32>) -> String {
        let (cert_pem, key_pem, _fingerprint) =
            new_random_tls_key_pair(KeyPairType::P256).expect("generate forward TLS key pair");
        let certificate =
            x509_key_pair(cert_pem.as_bytes(), key_pem.as_bytes()).expect("parse forward TLS certificate");
        let config = Arc::new(utls::Config {
            certificates: vec![certificate],
            min_version: utls::VERSION_TLS13,
            next_protos: vec!["h2".to_owned()],
            ..Default::default()
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind forward listener");
        let addr = listener.local_addr().expect("forward listener addr").to_string();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let config = Arc::clone(&config);
                let requests = Arc::clone(&requests);
                tokio::spawn(async move {
                    let conn = utls::server(Box::new(stream), config);
                    if conn.handshake().await.is_err() {
                        return;
                    }
                    let io = hyper_util::rt::TokioIo::new(conn);
                    let service = hyper::service::service_fn(move |_req: hyper::Request<hyper::body::Incoming>| {
                        let requests = Arc::clone(&requests);
                        async move {
                            requests.fetch_add(1, Ordering::SeqCst);
                            let body_stream = futures::stream::once(async {
                                tokio::time::sleep(Duration::from_millis(200)).await;
                                Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(Bytes::from_static(b"ok")))
                            });
                            let body = StreamBody::new(body_stream);
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder().status(200).body(body).expect("build h2 response"),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(io, service)
                        .await;
                });
            }
        });
        addr
    }

    async fn test_tls_mirror_round_trip(
        mut cfg: Config,
        first_write_delay_at_least: Option<Duration>,
        configure_forward_tls: Option<fn(&mut utls::Config)>,
    ) {
        cfg.primary_key = generate_primary_key();

        let forward_addr = start_test_forward_tls(configure_forward_tls).await;
        let server_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server listener");
        let server_addr = server_listener.local_addr().expect("server listener addr").to_string();

        let ctx = CancellationToken::new();
        let server_cfg = cfg.clone();
        let server_ctx = ctx.clone();
        let (server_done_tx, server_done_rx) = oneshot::channel::<Result<()>>();
        tokio::spawn(async move {
            let result: Result<()> = async {
                let (carrier, _) = server_listener.accept().await?;
                let forward = TcpStream::connect(&forward_addr).await?;
                let mut conn = serve_conn_ready(&server_ctx, Box::new(carrier), Box::new(forward), server_cfg).await?;
                for i in 0u8..8 {
                    let size = 4 + usize::from(i) * 8192;
                    let mut buf = vec![0u8; size];
                    conn.read_exact(&mut buf).await?;
                    if buf != vec![i; size] {
                        return Err(anyhow!("server received mismatched payload for size {size}"));
                    }
                    conn.write_all(&vec![255u8 - i; size]).await?;
                }
                Ok(())
            }
            .await;
            let _ = server_done_tx.send(result);
        });

        let raw = TcpStream::connect(&server_addr).await.expect("dial server");
        let dial_ctx = DialCtx::new(ctx.clone());
        let mut client = tokio::time::timeout(
            Duration::from_secs(10),
            dial(
                &dial_ctx,
                Box::new(raw),
                ClientConfig {
                    config: cfg,
                    server_name: "localhost".to_owned(),
                    skip_cert_verify: true,
                    ..Default::default()
                },
            ),
        )
        .await
        .expect("client dial timed out")
        .expect("client dial");

        for i in 0u8..8 {
            let size = 4 + usize::from(i) * 8192;
            let start = std::time::Instant::now();
            tokio::time::timeout(Duration::from_secs(10), client.write_all(&vec![i; size]))
                .await
                .unwrap_or_else(|_| panic!("client write {i} timed out"))
                .expect("client write");
            if i == 0 {
                if let Some(min_delay) = first_write_delay_at_least {
                    let elapsed = start.elapsed();
                    assert!(elapsed >= min_delay, "first write returned too soon: {elapsed:?}");
                }
            }
            let mut buf = vec![0u8; size];
            tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("client read {i} timed out"))
                .expect("client read");
            assert_eq!(buf, vec![255u8 - i; size]);
        }

        match tokio::time::timeout(Duration::from_secs(1), server_done_rx).await {
            Ok(Ok(result)) => result.expect("server handler failed"),
            Ok(Err(_)) => panic!("server task dropped without a result"),
            Err(_) => panic!("server handler timeout"),
        }
    }

    #[tokio::test]
    async fn round_trip_default() {
        test_tls_mirror_round_trip(Config::default(), None, None).await;
    }

    #[tokio::test]
    async fn round_trip_transport_layer_padding() {
        let cfg = Config { transport_layer_padding: TransportLayerPadding { enabled: true }, ..Default::default() };
        test_tls_mirror_round_trip(cfg, None, None).await;
    }

    #[tokio::test]
    async fn round_trip_sequence_watermark() {
        let cfg = Config { sequence_watermarking_enabled: true, ..Default::default() };
        test_tls_mirror_round_trip(cfg, None, None).await;
    }

    #[tokio::test]
    async fn round_trip_first_write_delay() {
        let cfg = Config {
            defer_instance_derived_write: TimeSpec {
                base_nanoseconds: Duration::from_millis(50).as_nanos() as u64,
                ..Default::default()
            },
            ..Default::default()
        };
        test_tls_mirror_round_trip(cfg, Some(Duration::from_millis(40)), None).await;
    }

    #[tokio::test]
    async fn round_trip_tls12_explicit_nonce() {
        fn configure_forward_tls12(config: &mut utls::Config) {
            config.min_version = utls::VERSION_TLS12;
            config.max_version = utls::VERSION_TLS12;
            config.cipher_suites = Some(vec![0xc02b]);
        }

        let cfg = Config {
            explicit_nonce_cipher_suites: crate::config::RECOMMENDED_EXPLICIT_NONCE_CIPHER_SUITES.to_vec(),
            ..Default::default()
        };
        test_tls_mirror_round_trip(cfg, None, Some(configure_forward_tls12)).await;
    }

    async fn test_tls_mirror_round_trip_with_embedded_traffic_generator(
        forward_addr: String,
        requests: Arc<AtomicI32>,
        alpn: Vec<String>,
        h2_do_not_wait_for_download_finish: bool,
    ) {
        let server_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server listener");
        let server_addr = server_listener.local_addr().expect("server listener addr").to_string();
        let ctx = CancellationToken::new();
        let primary_key = generate_primary_key();

        let server_ctx = ctx.clone();
        let server_primary_key = primary_key.clone();
        let (server_done_tx, server_done_rx) = oneshot::channel::<Result<()>>();
        tokio::spawn(async move {
            let result: Result<()> = async {
                let (carrier, _) = server_listener.accept().await?;
                let forward = TcpStream::connect(&forward_addr).await?;
                let mut conn = serve_conn_ready(
                    &server_ctx,
                    Box::new(carrier),
                    Box::new(forward),
                    Config { primary_key: server_primary_key, ..Default::default() },
                )
                .await?;
                let mut buf = vec![0u8; 1024];
                conn.read_exact(&mut buf).await?;
                conn.write_all(&buf).await?;
                Ok(())
            }
            .await;
            let _ = server_done_tx.send(result);
        });

        let raw = TcpStream::connect(&server_addr).await.expect("dial server");
        let dial_ctx = DialCtx::new(ctx.clone());
        let mut client = dial(
            &dial_ctx,
            Box::new(raw),
            ClientConfig {
                config: Config {
                    primary_key,
                    embedded_traffic_generator: Some(TrafficGenerator {
                        steps: vec![TrafficStep {
                            host: "localhost".to_owned(),
                            path: "/carrier".to_owned(),
                            method: "GET".to_owned(),
                            connection_ready: true,
                            connection_recall_exit: true,
                            wait_time: TimeSpec {
                                base_nanoseconds: Duration::from_millis(10).as_nanos() as u64,
                                ..Default::default()
                            },
                            next_step: vec![TrafficTransferCandidate { weight: 1, goto_location: 0 }],
                            headers: vec![TrafficHeader {
                                name: "User-Agent".to_owned(),
                                value: "tlsmirror-test".to_owned(),
                                ..Default::default()
                            }],
                            h2_do_not_wait_for_download_finish,
                            ..Default::default()
                        }],
                    }),
                    ..Default::default()
                },
                server_name: "localhost".to_owned(),
                skip_cert_verify: true,
                alpn,
                ..Default::default()
            },
        )
        .await
        .expect("client dial");
        assert!(requests.load(Ordering::SeqCst) >= 1);

        let payload = vec![7u8; 1024];
        client.write_all(&payload).await.expect("client write");
        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.expect("client read");
        assert_eq!(got, payload);

        match tokio::time::timeout(Duration::from_secs(1), server_done_rx).await {
            Ok(Ok(result)) => result.expect("server handler failed"),
            Ok(Err(_)) => panic!("server task dropped without a result"),
            Err(_) => panic!("server handler timeout"),
        }
    }

    #[tokio::test]
    async fn round_trip_with_embedded_traffic_generator_http1() {
        let requests = Arc::new(AtomicI32::new(0));
        let forward_addr = start_test_forward_https(Arc::clone(&requests)).await;
        test_tls_mirror_round_trip_with_embedded_traffic_generator(forward_addr, requests, Vec::new(), false).await;
    }

    #[tokio::test]
    async fn round_trip_with_embedded_traffic_generator_h2() {
        let requests = Arc::new(AtomicI32::new(0));
        let forward_addr = start_test_forward_http2(Arc::clone(&requests)).await;
        test_tls_mirror_round_trip_with_embedded_traffic_generator(forward_addr, requests, vec!["h2".to_owned()], true)
            .await;
    }
}

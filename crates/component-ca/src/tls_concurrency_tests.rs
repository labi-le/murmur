//! Relocated from `component::tls::utls`'s own test module (crate split: this crate already
//! depends on `component::tls` normally, so the integration tests that generate a real
//! certificate through `component::ca::keypair` and drive it through
//! `component::tls::utls::{client, server}` moved here instead of `component::tls` gaining a
//! dev-only dependency back on this crate).

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use crate::keypair::{new_random_tls_key_pair, new_tls_key_pair_loader, KeyPairType};
    use murmur_component_tls::utls::{client, server, Config};

    /// Hang detection, not a latency budget: high enough that only a task that stopped making
    /// progress trips it, even on an oversubscribed host. Trips here first mean check
    /// `--test-threads` against `available_parallelism`, not the code under test.
    const HANG_DEADLINE: Duration = Duration::from_secs(60);

    /// Concurrent connection count scaled to the host: enough over `available_parallelism` to
    /// force real queueing, with a floor so a low-core host still exercises genuine concurrency.
    fn concurrency_width() -> usize {
        std::thread::available_parallelism().map(std::num::NonZeroUsize::get).unwrap_or(1).saturating_mul(8).max(16)
    }

    #[tokio::test]
    async fn concurrent_hyper_auto_over_tls_never_hangs() {
        use bytes::Bytes;
        use http_body_util::{BodyExt, Full};
        use hyper::service::service_fn;
        use hyper::{Request, Response};
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto;
        use std::convert::Infallible;
        use tokio::net::{TcpListener, TcpStream};

        let (cert_pem, key_pem, _fp) = new_random_tls_key_pair(KeyPairType::P256).expect("key generation");
        let loader = new_tls_key_pair_loader(&cert_pem, &key_pem).expect("valid cert");
        let cert_for_server = loader().expect("cert loads");

        let server_config = Arc::new(Config {
            certificates: vec![cert_for_server],
            next_protos: vec!["http/1.1".to_owned()],
            ..Default::default()
        });
        let client_config = Arc::new(Config {
            insecure_skip_verify: true,
            next_protos: vec!["http/1.1".to_owned()],
            ..Default::default()
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");

        let n = concurrency_width();

        let mut client_tasks = Vec::with_capacity(n);
        for _ in 0..n {
            let client_config = Arc::clone(&client_config);
            client_tasks.push(tokio::spawn(async move {
                let raw = TcpStream::connect(addr).await.expect("client connect");
                let tls_conn = client(Box::new(raw), client_config);
                tls_conn.handshake().await.expect("client handshake");
                let io = TokioIo::new(tls_conn);
                let (mut sender, conn) =
                    tokio::time::timeout(HANG_DEADLINE, hyper::client::conn::http1::handshake(io))
                        .await
                        .expect("client http1 handshake did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect")
                        .expect("client http1 handshake failed");
                tokio::spawn(conn);
                let req = Request::get("/").body(Full::<Bytes>::default()).expect("valid request");
                let response = tokio::time::timeout(HANG_DEADLINE, sender.send_request(req))
                    .await
                    .expect("client request did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect")
                    .expect("client request failed");
                assert_eq!(response.status(), hyper::StatusCode::OK);
                let body = response.into_body().collect().await.expect("body collect").to_bytes();
                assert_eq!(&body[..], b"ok");
            }));
        }

        let mut server_tasks = Vec::with_capacity(n);
        for _ in 0..n {
            let (raw, _) = listener.accept().await.expect("accept");
            let server_config = Arc::clone(&server_config);
            server_tasks.push(tokio::spawn(async move {
                let tls_conn = server(Box::new(raw), server_config);
                let io = TokioIo::new(tls_conn);
                let svc = service_fn(|_req: Request<hyper::body::Incoming>| async move {
                    Ok::<_, Infallible>(Response::new(Full::<Bytes>::from(&b"ok"[..])))
                });
                let builder = auto::Builder::new(TokioExecutor::new());
                tokio::time::timeout(HANG_DEADLINE, builder.serve_connection_with_upgrades(io, svc))
                    .await
                    .expect("server serve_connection did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect")
                    .expect("server serve_connection failed");
            }));
        }

        for task in client_tasks {
            task.await.expect("client task panicked");
        }
        for task in server_tasks {
            task.await.expect("server task panicked");
        }
    }

    #[tokio::test]
    async fn concurrent_raw_http_roundtrip_then_echo_over_tls_baseline() {
        run_raw_http_roundtrip_then_echo(false).await;
    }

    #[tokio::test]
    async fn concurrent_raw_http_roundtrip_then_echo_over_tls_repro() {
        run_raw_http_roundtrip_then_echo(true).await;
    }

    async fn run_raw_http_roundtrip_then_echo(do_http_roundtrip: bool) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let (cert_pem, key_pem, _fp) = new_random_tls_key_pair(KeyPairType::P256).expect("key generation");
        let loader = new_tls_key_pair_loader(&cert_pem, &key_pem).expect("valid cert");
        let cert_for_server = loader().expect("cert loads");

        let server_config = Arc::new(Config {
            certificates: vec![cert_for_server],
            next_protos: vec!["http/1.1".to_owned()],
            ..Default::default()
        });
        let client_config = Arc::new(Config {
            insecure_skip_verify: true,
            next_protos: vec!["http/1.1".to_owned()],
            ..Default::default()
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");

        let n = concurrency_width();

        let mut client_tasks = Vec::with_capacity(n);
        for i in 0..n {
            let client_config = Arc::clone(&client_config);
            client_tasks.push(tokio::spawn(async move {
                tokio::time::timeout(HANG_DEADLINE, async move {
                    let raw = TcpStream::connect(addr).await.expect("client connect");
                    let mut tls_conn = client(Box::new(raw), client_config);
                    tls_conn.handshake().await.expect("client handshake");

                    if do_http_roundtrip {
                        tls_conn
                            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                            .await
                            .expect("client http request write");
                        let mut buf = [0u8; 4096];
                        let mut total = 0usize;
                        loop {
                            let n = tls_conn.read(&mut buf[total..]).await.expect("client http response read");
                            assert!(n > 0, "server closed before sending http response");
                            total += n;
                            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }

                    tls_conn.write_all(b"PING").await.expect("client ping write");
                    let mut pong = [0u8; 4];
                    tls_conn.read_exact(&mut pong).await.expect("client pong read");
                    assert_eq!(&pong, b"PONG", "task {i} got unexpected echo reply");
                })
                .await
                .unwrap_or_else(|_| panic!("task {i} did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect"));
            }));
        }

        let mut server_tasks = Vec::with_capacity(n);
        for i in 0..n {
            let (raw, _) = listener.accept().await.expect("accept");
            let server_config = Arc::clone(&server_config);
            server_tasks.push(tokio::spawn(async move {
                tokio::time::timeout(HANG_DEADLINE, async move {
                    let mut tls_conn = server(Box::new(raw), server_config);
                    tls_conn.handshake().await.expect("server handshake");

                    if do_http_roundtrip {
                        let mut buf = [0u8; 4096];
                        let mut total = 0usize;
                        loop {
                            let n = tls_conn.read(&mut buf[total..]).await.expect("server http request read");
                            assert!(n > 0, "client closed before sending http request");
                            total += n;
                            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        tls_conn
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .expect("server http response write");
                    }

                    let mut ping = [0u8; 4];
                    tls_conn.read_exact(&mut ping).await.expect("server ping read");
                    assert_eq!(&ping, b"PING", "task {i} server got unexpected ping");
                    tls_conn.write_all(b"PONG").await.expect("server pong write");
                })
                .await
                .unwrap_or_else(|_| panic!("task {i} did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect"));
            }));
        }

        for task in client_tasks {
            task.await.expect("client task panicked");
        }
        for task in server_tasks {
            task.await.expect("server task panicked");
        }
    }

    #[tokio::test]
    async fn concurrent_hyper_upgrade_then_echo_over_tls_repro() {
        use bytes::Bytes;
        use http_body_util::{BodyExt, Empty};
        use hyper::header::{CONNECTION, UPGRADE};
        use hyper::service::service_fn;
        use hyper::{Request, Response, StatusCode};
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let (cert_pem, key_pem, _fp) = new_random_tls_key_pair(KeyPairType::P256).expect("key generation");
        let loader = new_tls_key_pair_loader(&cert_pem, &key_pem).expect("valid cert");
        let cert_for_server = loader().expect("cert loads");

        let server_config = Arc::new(Config {
            certificates: vec![cert_for_server],
            next_protos: vec!["http/1.1".to_owned()],
            ..Default::default()
        });
        let client_config = Arc::new(Config {
            insecure_skip_verify: true,
            next_protos: vec!["http/1.1".to_owned()],
            ..Default::default()
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");

        let n = concurrency_width();

        let mut client_tasks = Vec::with_capacity(n);
        for i in 0..n {
            let client_config = Arc::clone(&client_config);
            client_tasks.push(tokio::spawn(async move {
                tokio::time::timeout(HANG_DEADLINE, async move {
                    let raw = TcpStream::connect(addr).await.expect("client connect");
                    let tls_conn = client(Box::new(raw), client_config);
                    tls_conn.handshake().await.expect("client handshake");
                    let io = TokioIo::new(tls_conn);
                    let (mut sender, conn) =
                        hyper::client::conn::http1::handshake(io).await.expect("client http1 handshake");
                    tokio::spawn(conn.with_upgrades());
                    let req = Request::get("/upgrade")
                        .header(UPGRADE, "raw")
                        .header(CONNECTION, "Upgrade")
                        .body(Empty::<Bytes>::new())
                        .expect("valid request");
                    let response = sender.send_request(req).await.expect("client request failed");
                    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
                    let mut upgraded = TokioIo::new(hyper::upgrade::on(response).await.expect("client upgrade"));
                    upgraded.write_all(b"PING").await.expect("client ping write");
                    let mut pong = [0u8; 4];
                    upgraded.read_exact(&mut pong).await.expect("client pong read");
                    assert_eq!(&pong, b"PONG", "task {i} got unexpected echo reply");
                })
                .await
                .unwrap_or_else(|_| panic!("task {i} did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect"));
            }));
        }

        let mut server_tasks = Vec::with_capacity(n);
        for i in 0..n {
            let (raw, _) = listener.accept().await.expect("accept");
            let server_config = Arc::clone(&server_config);
            server_tasks.push(tokio::spawn(async move {
                tokio::time::timeout(HANG_DEADLINE, async move {
                    let tls_conn = server(Box::new(raw), server_config);
                    let io = TokioIo::new(tls_conn);
                    let svc = service_fn(move |mut req: Request<hyper::body::Incoming>| async move {
                        let on_upgrade = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            let upgraded = on_upgrade.await.expect("server upgrade");
                            let mut upgraded = TokioIo::new(upgraded);
                            let mut ping = [0u8; 4];
                            upgraded.read_exact(&mut ping).await.expect("server ping read");
                            assert_eq!(&ping, b"PING", "task {i} server got unexpected ping");
                            upgraded.write_all(b"PONG").await.expect("server pong write");
                        });
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::SWITCHING_PROTOCOLS)
                                .header(UPGRADE, "raw")
                                .header(CONNECTION, "Upgrade")
                                .body(Empty::<Bytes>::new().boxed())
                                .expect("static response is valid"),
                        )
                    });
                    let builder = auto::Builder::new(TokioExecutor::new());
                    builder.serve_connection_with_upgrades(io, svc).await.expect("server serve_connection failed");
                })
                .await
                .unwrap_or_else(|_| panic!("task {i} did not complete within the hang-detection deadline; check for test-suite oversubscription before suspecting a scheduling defect"));
            }));
        }

        for task in client_tasks {
            task.await.expect("client task panicked");
        }
        for task in server_tasks {
            task.await.expect("server task panicked");
        }
    }
}

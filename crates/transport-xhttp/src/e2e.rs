//! End-to-end coverage for the streaming upload/response modes, driven over real loopback TCP
//! against a real `hyper` HTTP/1.1 server: sustained multi-megabyte transfers (large enough that
//! every buffer between the tunnel and the socket is cycled many times, so flow control is
//! genuinely exercised) plus both close directions and the request framing on the wire.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use murmur_std_compat::net::Conn as NetConn;

use super::client::{new_transport, Client, DialQuicFunc, DialRawFunc, TransportMaker, WrapTlsFunc};
use super::config::{Config, Request, RequestBody, RoundTripper};
use super::server::{ConnHandler, Handler, RequestHandler, ServerOption};

const HOST: &str = "example.com";
const PATH: &str = "/xhttp";
/// Comfortably past the client's 64 KiB upload pipe, the server's 32-frame response channel and
/// the kernel socket buffers, so a completed transfer proves backpressure was applied and
/// released at every hop instead of being absorbed by buffering somewhere.
const SUSTAINED_BYTES: usize = 2 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(20);

/// The three modes the client accepts.
const MODES: [&str; 3] = ["stream-one", "stream-up", "packet-up"];

/// The subset whose upload leg is a live request body, so closing the client ends that body and
/// the server's tunnel reader unwinds. `packet-up`'s tunnel instead reads an upload queue that
/// only a POST can advance, and the always-on connection reader — which surfaces the
/// peer's disconnect through `r.Context().Done()` — has no `hyper` equivalent: its HTTP/1.1
/// server issues no read while a bodyless request's response is still streaming. So a silent
/// client is invisible to a `packet-up` tunnel until it writes: a carrier limitation, not a bug.
const MODES_WITH_PROPAGATED_CLOSE: [&str; 2] = ["stream-one", "stream-up"];

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn passthrough_wrap_tls() -> WrapTlsFunc {
    Arc::new(|_ctx, conn, _is_h2| Box::pin(async move { Ok(conn) }))
}

fn unused_dial_quic() -> DialQuicFunc {
    Arc::new(|_ctx, _cfg| Box::pin(async { Err(anyhow::anyhow!("no QUIC transport in these tests")) }))
}

fn loopback_dial_raw(addr: SocketAddr) -> DialRawFunc {
    Arc::new(move |_ctx| {
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            let conn: Box<dyn NetConn> = Box::new(stream);
            Ok(conn)
        })
    })
}

fn loopback_transport(addr: SocketAddr) -> Arc<dyn RoundTripper> {
    new_transport(
        loopback_dial_raw(addr),
        passthrough_wrap_tls(),
        unused_dial_quic(),
        &["http/1.1".to_owned()],
        Duration::ZERO,
    )
}

/// Connections are real loopback TCP sockets, so request and response framing actually crosses a
/// socket instead of an in-memory duplex.
fn loopback_transport_maker(addr: SocketAddr) -> TransportMaker {
    Arc::new(move || loopback_transport(addr))
}

fn mode_config(mode: &str) -> Config {
    Config { host: HOST.to_owned(), path: PATH.to_owned(), mode: mode.to_owned(), ..Config::default() }
}

async fn spawn_server(config: Config, conn_handler: ConnHandler) -> SocketAddr {
    let handler = RequestHandler::new(ServerOption { config, conn_handler: Some(conn_handler), http_handler: None })
        .expect("valid xhttp server config");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener local addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(move |req| {
                    let handler = Arc::clone(&handler);
                    async move { Ok::<_, std::convert::Infallible>(handler.serve(req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

async fn dial(config: Arc<Config>, server_addr: SocketAddr) -> Box<dyn NetConn> {
    let client = Client::new(config, loopback_transport_maker(server_addr), None, false).expect("client construction");
    tokio::time::timeout(IO_TIMEOUT, client.dial(CancellationToken::new()))
        .await
        .expect("dial completed")
        .expect("dial succeeded")
}

async fn within<T>(what: &str, fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(IO_TIMEOUT, fut).await.unwrap_or_else(|_| panic!("{what} never completed"))
}

/// Uploads `sent` while concurrently draining the echoed response, then asserts the tunnel
/// returned the exact bytes. The two directions have to overlap: a write-only phase would fill
/// the server's response channel and stall the echo, deadlocking the transfer instead of
/// exercising flow control.
async fn sustained_round_trip(label: &str, conn: Box<dyn NetConn>, sent: &[u8]) {
    let expected = sent.to_vec();
    let (mut reader, mut writer) = tokio::io::split(conn);
    let (upload, download) = tokio::join!(
        async {
            within(&format!("{label} upload"), writer.write_all(sent)).await.expect("upload");
            within(&format!("{label} upload flush"), writer.flush()).await.expect("upload flush");
        },
        async {
            let mut echoed = vec![0u8; expected.len()];
            within(&format!("{label} download"), reader.read_exact(&mut echoed)).await.expect("download");
            echoed
        }
    );
    let () = upload;
    assert_eq!(download, expected, "{label}: echoed payload differs from what was sent");
}

fn echoing_handler(exit: mpsc::UnboundedSender<()>, stop_after: Option<usize>) -> ConnHandler {
    Arc::new(move |mut conn: Box<dyn NetConn>| {
        let exit = exit.clone();
        Box::pin(async move {
            let mut buf = vec![0u8; 16 * 1024];
            let mut seen = 0usize;
            loop {
                let n = match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if conn.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                seen += n;
                if stop_after.is_some_and(|limit| seen >= limit) {
                    break;
                }
            }
            let _ = conn.close();
            let _ = exit.send(());
        })
    })
}

fn packet_request(config: &Config, seq: &str, data: &[u8]) -> Request {
    let mut req = Request {
        method: config.normalized_uplink_http_method(),
        url: url::Url::parse(&format!("https://{HOST}{}", config.normalized_path())).expect("packet url"),
        host: HOST.to_owned(),
        ..Request::default()
    };
    config.fill_packet_request(&mut req, "session", seq, data).expect("fill packet request");
    req
}

fn head_value<'head>(head: &'head str, name: &str) -> Option<&'head str> {
    head.lines().find_map(|line| line.strip_prefix(name)?.split_once(':').map(|(_, value)| value.trim()))
}

/// Consumes the request body the head declares. Answering before the body arrives would reset
/// the connection while the client is still writing it, a stub artefact rather than anything
/// about the framing under test. `pending` holds body bytes the head read already pulled in.
async fn drain_declared_body(stream: &mut tokio::net::TcpStream, head: &str, mut pending: Vec<u8>) {
    let mut buf = vec![0u8; 16 * 1024];
    if let Some(len) = head_value(head, "content-length").and_then(|value| value.parse::<usize>().ok()) {
        let mut remaining = len.saturating_sub(pending.len());
        while remaining > 0 {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => remaining = remaining.saturating_sub(n),
            }
        }
    } else if head.contains("transfer-encoding: chunked") {
        while !pending.windows(5).any(|window| window == b"0\r\n\r\n") {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => pending.extend_from_slice(&buf[..n]),
            }
        }
    }
}

/// Runs `req` against a bare TCP listener that records the request head and answers `200`.
async fn capture_request_head(req: Request) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener local addr");
    let head: Arc<tokio::sync::Mutex<String>> = Arc::new(tokio::sync::Mutex::new(String::new()));
    let sink = Arc::clone(&head);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut seen: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => seen.extend_from_slice(&buf[..n]),
            }
        }
        let split = seen.windows(4).position(|window| window == b"\r\n\r\n").map_or(seen.len(), |at| at + 4);
        let (raw_head, pending) = seen.split_at(split);
        let received = String::from_utf8_lossy(raw_head).to_ascii_lowercase();
        sink.lock().await.push_str(&received);
        drain_declared_body(&mut stream, &received, pending.to_vec()).await;
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    });

    let transport = loopback_transport(addr);
    transport.ensure_connected(CancellationToken::new()).await.expect("connect");
    within("round trip", transport.round_trip(req)).await.expect("round trip succeeded");
    let captured = head.lock().await.to_ascii_lowercase();
    captured
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sustained_multimegabyte_round_trip_in_every_mode() {
    let sent = payload(SUSTAINED_BYTES);
    for mode in MODES {
        let (exit, _exits) = mpsc::unbounded_channel();
        let server_addr = spawn_server(mode_config(mode), echoing_handler(exit, None)).await;
        let conn = dial(Arc::new(mode_config(mode)), server_addr).await;
        sustained_round_trip(mode, conn, &sent).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_client_ends_the_server_tunnel() {
    let probe = payload(64);
    for mode in MODES_WITH_PROPAGATED_CLOSE {
        let (exit, mut exits) = mpsc::unbounded_channel();
        let server_addr = spawn_server(mode_config(mode), echoing_handler(exit, None)).await;
        let mut conn = dial(Arc::new(mode_config(mode)), server_addr).await;

        within(&format!("{mode} upload"), conn.write_all(&probe)).await.expect("upload");
        let mut echoed = vec![0u8; probe.len()];
        within(&format!("{mode} download"), conn.read_exact(&mut echoed)).await.expect("download");
        assert_eq!(echoed, probe, "{mode}: echo differs");

        conn.close().expect("close");
        drop(conn);

        assert!(
            tokio::time::timeout(TEARDOWN_TIMEOUT, exits.recv()).await.is_ok(),
            "{mode}: the server tunnel kept running after the client closed the session, so the \
             upload side never learns its peer is gone"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_server_ending_the_tunnel_ends_the_client_read() {
    let sent = payload(4096);
    for mode in MODES {
        let (exit, mut exits) = mpsc::unbounded_channel();
        let server_addr = spawn_server(mode_config(mode), echoing_handler(exit, Some(sent.len()))).await;
        let mut conn = dial(Arc::new(mode_config(mode)), server_addr).await;

        within(&format!("{mode} upload"), conn.write_all(&sent)).await.expect("upload");
        let mut echoed = vec![0u8; sent.len()];
        within(&format!("{mode} download"), conn.read_exact(&mut echoed)).await.expect("download");
        assert_eq!(echoed, sent, "{mode}: echo differs");

        let mut trailing = [0u8; 1];
        let end = within(&format!("{mode} trailing read"), conn.read(&mut trailing)).await;
        assert!(
            matches!(end, Ok(0) | Err(_)),
            "{mode}: the client read must reach end of stream after the server closed the tunnel, got {end:?}"
        );
        assert!(
            tokio::time::timeout(TEARDOWN_TIMEOUT, exits.recv()).await.is_ok(),
            "{mode}: the server tunnel never returned"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packet_up_reassembles_a_sustained_upload_split_across_bounded_posts() {
    let sent = payload(SUSTAINED_BYTES);
    let config = Config {
        sc_max_each_post_bytes: "65536".to_owned(),
        sc_min_posts_interval_ms: "1".to_owned(),
        sc_max_buffered_posts: "4".to_owned(),
        ..mode_config("packet-up")
    };
    let (exit, _exits) = mpsc::unbounded_channel();
    let server_addr = spawn_server(config.clone(), echoing_handler(exit, None)).await;
    let conn = dial(Arc::new(config), server_addr).await;
    sustained_round_trip("packet-up", conn, &sent).await;
}

/// One of four framings is picked for a packet's
/// payload and the server reassembles each differently, so every placement has to survive a
/// multi-post round trip with the payload split into several base64 chunks per POST.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packet_up_round_trips_through_every_uplink_data_placement() {
    let sent = payload(256 * 1024);
    for placement in ["body", "header", "cookie", "auto"] {
        let config = Config {
            uplink_data_placement: placement.to_owned(),
            uplink_data_key: "x".to_owned(),
            uplink_chunk_size: "8192".to_owned(),
            sc_max_each_post_bytes: "65536".to_owned(),
            sc_min_posts_interval_ms: "1".to_owned(),
            ..mode_config("packet-up")
        };
        let (exit, _exits) = mpsc::unbounded_channel();
        let server_addr = spawn_server(config.clone(), echoing_handler(exit, None)).await;
        let conn = dial(Arc::new(config), server_addr).await;
        sustained_round_trip(&format!("packet-up/{placement}"), conn, &sent).await;
    }
}

/// the packet request builder knows the exact payload length, so the POST is framed with
/// `Content-Length`; the streaming uploads have a pipe body of unknown length and go out
/// chunked instead. Middleboxes treat the two differently, so the distinction is pinned here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packet_posts_carry_a_content_length_and_stream_uploads_stay_chunked() {
    let packet = mode_config("packet-up");
    let packet_head = capture_request_head(packet_request(&packet, "0", b"payload")).await;
    assert!(
        packet_head.contains(&format!("content-length: {}", "payload".len())),
        "a packet POST must be framed with Content-Length, got:\n{packet_head}"
    );

    let stream = mode_config("stream-one");
    let (mut body_writer, body_reader) = tokio::io::duplex(64);
    let body = payload(1024);
    tokio::spawn(async move {
        let _ = body_writer.write_all(&body).await;
    });
    let mut stream_req = Request {
        method: stream.normalized_uplink_http_method(),
        url: url::Url::parse(&format!("https://{HOST}{}", stream.normalized_path())).expect("stream url"),
        host: HOST.to_owned(),
        body: Some(RequestBody::Stream(Box::pin(body_reader))),
        ..Request::default()
    };
    stream.fill_stream_request(&mut stream_req, "").expect("fill stream request");
    let stream_head = capture_request_head(stream_req).await;
    assert!(
        stream_head.contains("transfer-encoding: chunked"),
        "a streaming upload of unknown length must be chunked, got:\n{stream_head}"
    );
    assert!(
        !stream_head.contains("content-length:"),
        "a streaming upload of unknown length must not claim a length, got:\n{stream_head}"
    );
}

/// A packet POST with no payload is indistinguishable from any other bodyless request to an
/// intermediary, so it is the one packet response that opts out of caching; a POST that carries
/// data keeps the default.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_bodyless_packet_posts_opt_out_of_caching() {
    let packet = mode_config("packet-up");
    let (exit, _exits) = mpsc::unbounded_channel();
    let server_addr = spawn_server(packet.clone(), echoing_handler(exit, None)).await;
    let transport = loopback_transport(server_addr);
    transport.ensure_connected(CancellationToken::new()).await.expect("connect");

    let empty = transport.round_trip(packet_request(&packet, "0", b"")).await.expect("empty post");
    assert_eq!(empty.status_code, 200);
    assert_eq!(
        empty.header.get(http::header::CACHE_CONTROL).map(http::HeaderValue::as_bytes),
        Some(b"no-store".as_slice()),
        "a bodyless packet POST must be marked no-store"
    );

    let filled = transport.round_trip(packet_request(&packet, "1", b"payload")).await.expect("filled post");
    assert_eq!(filled.status_code, 200);
    assert!(
        filled.header.get(http::header::CACHE_CONTROL).is_none(),
        "a packet POST that carries data must keep the default caching headers, got {:?}",
        filled.header.get(http::header::CACHE_CONTROL)
    );
}

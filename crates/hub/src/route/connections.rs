use std::time::Duration;

use hyper::{Method, Response, StatusCode};

use murmur_tunnel::statistic::manager::DEFAULT_MANAGER;

use super::common::{
    encode_json, get_escape_param, json_response, method_not_allowed, stream_response, Req, RespBody, StreamSink,
};
use super::server::query_param;

#[expect(
    clippy::unused_async,
    reason = "the mount entry point is awaited by the shared dispatcher in `server.rs`; every handler behind it is synchronous"
)]
pub(crate) async fn route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    match segs {
        [] => match *req.method() {
            Method::GET => Some(get_connections(req)),
            Method::DELETE => Some(close_all_connections()),
            _ => Some(method_not_allowed(&["GET", "DELETE"])),
        },
        [id] => {
            let id = get_escape_param(id);
            if req.method() != Method::DELETE {
                return Some(method_not_allowed(&["DELETE"]));
            }
            Some(close_connection(&id))
        }
        _ => None,
    }
}

fn get_connections(req: Req) -> Response<RespBody> {
    if req.headers().get("upgrade").and_then(|v| v.to_str().ok()) != Some("websocket") {
        return json_response(StatusCode::OK, &DEFAULT_MANAGER.snapshot());
    }

    let query = req.uri().query().unwrap_or("").to_owned();
    let interval_str = query_param(&query, "interval").unwrap_or_default();
    let interval = if interval_str.is_empty() { Some(1000) } else { interval_str.parse::<i64>().ok() };

    stream_response(req, move |mut sink: StreamSink| async move {
        // Both cases render into the writer of the just-upgraded connection, where the bytes are
        // dropped: the client sees the handshake and then nothing.
        let Some(interval) = interval else {
            sink.idle_until_peer_closes().await;
            return;
        };

        if !send_snapshot(&mut sink).await {
            return;
        }

        // A zero-period ticker would panic after that first frame, and the panic is recovered
        // without closing the upgraded connection.
        let Ok(interval_ms) = u64::try_from(interval) else {
            sink.idle_until_peer_closes().await;
            return;
        };
        if interval_ms == 0 {
            sink.idle_until_peer_closes().await;
            return;
        }

        let mut tick = tokio::time::interval(Duration::from_millis(interval_ms));
        tick.tick().await;
        loop {
            tick.tick().await;
            if !send_snapshot(&mut sink).await {
                break;
            }
        }
    })
}

/// One JSON-formatted snapshot frame per call.
async fn send_snapshot(sink: &mut StreamSink) -> bool {
    sink.write_text(&encode_json(&DEFAULT_MANAGER.snapshot())).await
}

fn close_connection(id: &str) -> Response<RespBody> {
    if let Some(c) = DEFAULT_MANAGER.get(id) {
        let _ = c.close();
    }
    super::common::no_content()
}

fn close_all_connections() -> Response<RespBody> {
    DEFAULT_MANAGER.range(|c| {
        let _ = c.close();
        true
    });
    super::common::no_content()
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::time::Duration;

    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn handshake(interval: &str) -> String {
        format!(
            "GET /connections?interval={interval} HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
    }

    /// Serves `route` on a real connection and returns the socket once the response head has
    /// arrived; a websocket upgrade cannot go through hyper's client.
    async fn open(request: &str) -> (TcpStream, String, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener has a local address");
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept loopback connection");
            let service =
                service_fn(|req: Req| async move { Ok::<_, Infallible>(route(req, &[]).await.expect("route")) });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(conn), service)
                .with_upgrades()
                .await;
        });

        let mut stream = TcpStream::connect(addr).await.expect("connect to loopback listener");
        stream.write_all(request.as_bytes()).await.expect("write request");
        let mut buffer = Vec::new();
        let head_end = loop {
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk).await.expect("read response head");
            assert!(read > 0, "server closed before the response head: {:?}", String::from_utf8_lossy(&buffer));
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
        (stream, head, buffer[head_end..].to_vec())
    }

    /// Everything the server sends within `window`, and whether it closed the socket.
    async fn drain(stream: &mut TcpStream, rest: Vec<u8>, window: Duration) -> (Vec<u8>, bool) {
        let deadline = tokio::time::Instant::now() + window;
        let mut buffer = rest;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return (buffer, false);
            }
            let mut chunk = [0u8; 4096];
            match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
                Err(_) => return (buffer, false),
                Ok(Ok(0)) | Ok(Err(_)) => return (buffer, true),
                Ok(Ok(read)) => buffer.extend_from_slice(&chunk[..read]),
            }
        }
    }

    fn text_frames(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut i = 0;
        while i + 2 <= bytes.len() {
            let opcode = bytes[i] & 0x0F;
            let (length, start) = match bytes[i + 1] & 0x7F {
                126 => (u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize, i + 4),
                other => (other as usize, i + 2),
            };
            assert!(start + length <= bytes.len(), "partial websocket frame");
            if opcode == 0x1 {
                frames.push(bytes[start..start + length].to_vec());
            }
            i = start + length;
        }
        frames
    }

    /// A bad `interval` is only noticed after the upgrade: the peer sees the handshake, no frames,
    /// and an open socket.
    #[tokio::test]
    async fn a_bad_interval_upgrades_and_then_stays_silent() {
        let (mut stream, head, rest) = open(&handshake("abc")).await;
        assert!(head.starts_with("HTTP/1.1 101 Switching Protocols"), "{head}");

        let (bytes, closed) = drain(&mut stream, rest, Duration::from_millis(400)).await;
        assert!(bytes.is_empty(), "no frame may follow the handshake: {bytes:?}");
        assert!(!closed, "the socket must stay open");
    }

    /// A zero-interval ticker panics after the immediate snapshot; the panic is recovered
    /// without closing the hijacked connection, so exactly one frame arrives.
    #[tokio::test]
    async fn a_zero_interval_sends_one_snapshot_and_leaves_the_socket_open() {
        let (mut stream, head, rest) = open(&handshake("0")).await;
        assert!(head.starts_with("HTTP/1.1 101 Switching Protocols"), "{head}");

        let (bytes, closed) = drain(&mut stream, rest, Duration::from_millis(400)).await;
        assert!(!closed, "the socket must stay open");
        let frames = text_frames(&bytes);
        assert_eq!(frames.len(), 1, "exactly the immediate snapshot: {frames:?}");
        assert!(frames[0].ends_with(b"}\n"), "entry-terminated frame: {:?}", frames[0]);
        assert!(frames[0].starts_with(b"{\"downloadTotal\":0,\"uploadTotal\":0,\"connections\":null,"));
    }

    /// The `interval` query value is percent-decoded, so a client that encodes the value still
    /// gets the interval it asked for rather than the bad-interval path.
    #[tokio::test]
    async fn a_percent_encoded_interval_is_decoded() {
        let (mut stream, head, rest) = open(&handshake("%30")).await;
        assert!(head.starts_with("HTTP/1.1 101 Switching Protocols"), "{head}");
        let (bytes, closed) = drain(&mut stream, rest, Duration::from_millis(400)).await;
        assert!(!closed, "the socket must stay open");
        assert_eq!(text_frames(&bytes).len(), 1, "`%30` is interval=0: the immediate snapshot only");

        let (mut stream, head, rest) = open(&handshake("%32%35%30")).await;
        assert!(head.starts_with("HTTP/1.1 101 Switching Protocols"), "{head}");
        let (bytes, _closed) = drain(&mut stream, rest, Duration::from_millis(700)).await;
        assert!(text_frames(&bytes).len() >= 2, "`%32%35%30` is interval=250, not the 1000 default");
    }
}

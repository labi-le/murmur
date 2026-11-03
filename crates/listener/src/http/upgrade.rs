//! The TLS branch is unreachable: the request reader never populates a TLS field, and this
//! crate's reader (`hack.rs`) bypasses the accept loop that would.
//!
//! A server's own accept loop would set that field for a TLS-wrapped connection before invoking a
//! handler, and it is not filled in by the request parser, which is the lower layer this crate
//! sits at. Only the buffered-conn branch is implemented, so the TLS branch has no reachable
//! caller to preserve.
//!
//! The wire (de)serializers have no crate equivalent here either, so this crate writes the
//! outgoing request's head with the same header-writer style `proxy.rs::write_response` uses for
//! responses, then streams the request body straight into the backend connection with
//! `hack::pump_body`, never buffering it, unlike an earlier version which read the whole (normally
//! bodyless, but attacker-sized if declared) body into memory before ever writing a byte of the
//! request. The response head is parsed with the same `httparse`-based, bare-LF-tolerant approach
//! `hack.rs` uses for requests.

use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use tokio::io::AsyncWriteExt as _;

use murmur_adapter_inbound::addition::Addition;
use murmur_adapter_inbound::http::new_http;
use murmur_common_net::bufconn::BufferedConn;
use murmur_common_net::{new_buffered_conn, new_extended_conn, pipe, relay};
use murmur_constant::tunnel::Tunnel;
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport::socks5::socks5;

use super::hack::{
    is_chunked, join_host_port, parse_content_length, pump_body, read_body, read_header_block, split_host_port,
    BodySink, Request,
};
use super::proxy::{write_response, RawResponse, ResponseBody};
use super::utils::{remove_extra_http_host_port, remove_proxy_headers};

const MAX_HEADERS: usize = 128;

pub(crate) fn is_upgrade_request(header: &HeaderMap) -> bool {
    header
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|elm| elm.trim().eq_ignore_ascii_case("Upgrade"))
}

pub(crate) async fn handle_upgrade(
    mut conn: BufferedConn,
    mut request: Request,
    tunnel: Arc<dyn Tunnel>,
    additions: &[Addition],
) {
    remove_proxy_headers(&mut request.header);
    remove_extra_http_host_port(&mut request);

    let mut address = request.host.clone();
    if split_host_port(&address).is_none() {
        address = join_host_port(&address, "80");
    }

    let Some(dst_addr) = socks5::parse_addr(&address) else {
        let _ = conn.close();
        return;
    };

    let (left, right) = pipe();
    let (https_conn, metadata) = new_http(&dst_addr, &conn, Box::new(right), additions);
    tokio::spawn(async move {
        tunnel.handle_tcp_conn(Box::new(murmur_common_net::io::OldConnAsStream(https_conn)), metadata).await;
    });

    // S11: remove in U8, when the final std-compat bridge is deleted.
    let mut buffered_left = new_buffered_conn(new_extended_conn(murmur_common_net::io::OldConnAsStream(left)));

    if write_request_head(&mut buffered_left, &request).await.is_err() {
        let _ = buffered_left.close();
        let _ = conn.close();
        return;
    }
    if request.chunked {
        let mut sink = ChunkedRequestSink { inner: &mut buffered_left };
        if pump_body(&mut conn, &mut sink, request.content_length, request.chunked).await.is_err() {
            let _ = buffered_left.close();
            let _ = conn.close();
            return;
        }
        if buffered_left.write_all(b"0\r\n\r\n").await.is_err() {
            let _ = buffered_left.close();
            let _ = conn.close();
            return;
        }
    } else if pump_body(&mut conn, &mut buffered_left, request.content_length, request.chunked).await.is_err() {
        let _ = buffered_left.close();
        let _ = conn.close();
        return;
    }

    let Ok(mut response) = read_response(&mut buffered_left).await else {
        let _ = buffered_left.close();
        let _ = conn.close();
        return;
    };

    remove_proxy_headers(&mut response.headers);

    if write_response(&mut conn, request.proto_major, request.proto_minor, &request.method, &mut response)
        .await
        .is_err()
    {
        let _ = buffered_left.close();
        let _ = conn.close();
        return;
    }

    if response.status == StatusCode::SWITCHING_PROTOCOLS {
        relay(&mut buffered_left, &mut conn).await;
    }

    let _ = buffered_left.close();
    let _ = conn.close();
}

/// A [`BodySink`] that re-chunks whatever `pump_body` forwards it:
/// each call becomes one `"{len:x}\r\n<data>\r\n"` chunk on the wire, skipping zero-length writes
/// since a zero-length chunk on the wire means end-of-body. `handle_upgrade` writes the terminating
/// `"0\r\n\r\n"` itself once the pump finishes, and this type never sees that call, since `pump_body`
/// only ever calls `write_chunk`.
struct ChunkedRequestSink<'a> {
    inner: &'a mut BufferedConn,
}

#[async_trait::async_trait]
impl BodySink for ChunkedRequestSink<'_> {
    async fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut out = Vec::with_capacity(data.len() + 16);
        out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
        self.inner.write_all(&out).await.map_err(|err| anyhow!("{err}"))
    }

    async fn flush(&mut self) -> Result<()> {
        tokio::io::AsyncWriteExt::flush(self.inner).await.map_err(|err| anyhow!("{err}"))
    }
}

/// The outgoing request head: the request line and headers, with the body's
/// framing rebuilt from the parsed [`Request`](Request) exactly like `proxy.rs::forward` does
/// (see its module doc) rather than from `request.body.len()`. This function no longer receives
/// a materialized body to measure, since `handle_upgrade` streams it separately with `pump_body`.
/// `Content-Length` is written at most once: `fix_length` already left a deduplicated line in
/// `request.header` when the request declared one, so this skips that map entry and emits its own
/// line only for a positive length, or `POST`/`PUT`/`PATCH` regardless
/// of length (the only branches this crate's upgrade requests can plausibly hit; a `GET`/`HEAD`
/// upgrade with a zero length sends neither line here).
async fn write_request_head(conn: &mut BufferedConn, request: &Request) -> Result<()> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("{} {} HTTP/1.1\r\n", request.method, request.path_and_query).as_bytes());
    if !request.header.contains_key(http::header::HOST) && !request.host.is_empty() {
        out.extend_from_slice(format!("Host: {}\r\n", request.host).as_bytes());
    }
    for (name, value) in &request.header {
        if *name == http::header::CONTENT_LENGTH {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if request.chunked {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    } else {
        let send_content_length = match request.content_length {
            Some(n) if n > 0 => true,
            _ => matches!(request.method, http::Method::POST | http::Method::PUT | http::Method::PATCH),
        };
        if send_content_length {
            out.extend_from_slice(format!("Content-Length: {}\r\n", request.content_length.unwrap_or(0)).as_bytes());
        }
    }
    out.extend_from_slice(b"\r\n");
    conn.write_all(&out).await?;
    tokio::io::AsyncWriteExt::flush(conn).await?;
    Ok(())
}

async fn read_response(conn: &mut BufferedConn) -> Result<RawResponse> {
    let raw = read_header_block(conn, |b| {
        let mut headers_buf = [httparse::EMPTY_HEADER; MAX_HEADERS];
        httparse::Response::new(&mut headers_buf).parse(b)
    })
    .await?;

    let mut headers_buf = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Response::new(&mut headers_buf);
    match parsed.parse(&raw).map_err(|err| anyhow!("malformed response: {err}"))? {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => bail!("malformed response: truncated headers"),
    }

    let code = parsed.code.ok_or_else(|| anyhow!("malformed response: missing status code"))?;
    let status = StatusCode::from_u16(code).map_err(|err| anyhow!("malformed response: {err}"))?;

    let mut headers = HeaderMap::new();
    for h in parsed.headers.iter() {
        if h.name.is_empty() {
            continue;
        }
        let name =
            http::HeaderName::from_bytes(h.name.as_bytes()).map_err(|err| anyhow!("malformed header name: {err}"))?;
        let value = HeaderValue::from_bytes(h.value).map_err(|err| anyhow!("malformed header value: {err}"))?;
        headers.append(name, value);
    }

    // A `101 Switching Protocols` response has no body; everything after the header block is the
    // now-upgraded stream this function's caller relays instead.
    let body = if status == StatusCode::SWITCHING_PROTOCOLS {
        Bytes::new()
    } else {
        let content_length = parse_content_length(&headers)?;
        let chunked = is_chunked(&headers);
        read_body(conn, content_length, chunked).await?
    };

    Ok(RawResponse { status, headers, body: ResponseBody::Buffered(body), close: false })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Mutex;

    use crate::auth::auth::NIL;
    use murmur_component_nat::table::Table;
    use murmur_constant::adapters::{NatTable, UDPPacket};
    use murmur_constant::metadata::Metadata;
    use murmur_constant::tunnel::Tunnel;

    use super::super::proxy::handle_conn;

    const HANG_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

    /// Reads the backend's raw request head, then exactly `body_len` more bytes of body, then
    /// replies `101`, recording the raw body bytes it saw on the wire for the test to inspect.
    struct RecordingUpgradeTunnel {
        body_len: usize,
        observed_body: Arc<Mutex<Vec<u8>>>,
        observed_head: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl Tunnel for RecordingUpgradeTunnel {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn murmur_common_net::io::Stream>, _metadata: Metadata) {
            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                if conn.read_exact(&mut byte).await.is_err() {
                    return;
                }
                header.push(byte[0]);
                if header.len() >= 4 && header[header.len() - 4..] == *b"\r\n\r\n" {
                    break;
                }
            }
            *self.observed_head.lock().await = header;

            let mut body = vec![0u8; self.body_len];
            if conn.read_exact(&mut body).await.is_err() {
                return;
            }
            *self.observed_body.lock().await = body;

            let _ = conn.write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n").await;
        }

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {
            unreachable!("this test never sends UDP");
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    async fn run_upgrade(request: &[u8], tunnel: Arc<dyn Tunnel>) -> Vec<u8> {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy listener local addr");

        let server_task = tokio::spawn(async move {
            let (conn, _) = tokio::time::timeout(HANG_DEADLINE, proxy_listener.accept())
                .await
                .expect("accept did not complete within the hang-detection deadline")
                .expect("accept");
            tokio::time::timeout(HANG_DEADLINE, handle_conn(Box::new(conn), tunnel, NIL.clone(), &[]))
                .await
                .expect("server handling did not complete within the hang-detection deadline");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("client connect");
        client.write_all(request).await.expect("client request write");

        let mut response = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let n = tokio::time::timeout(HANG_DEADLINE, client.read(&mut buf))
                .await
                .expect("client response read did not complete within the hang-detection deadline")
                .expect("client response read");
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
            if response.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        drop(client);
        server_task.await.expect("server task panicked");
        response
    }

    // Covers re-chunking the upgrade request body instead of sending decoded bytes: the outgoing
    // request re-chunks a chunked body, but an earlier version
    // routed it through `pump_chunked_body`, which decodes chunking and writes the raw bytes,
    // even though `write_request_head` had already announced `Transfer-Encoding: chunked`.
    #[tokio::test]
    async fn upgrade_chunked_body_is_rechunked_on_the_wire() {
        let expected_wire_body = b"5\r\nhello\r\n0\r\n\r\n";
        let observed_body = Arc::new(Mutex::new(Vec::new()));
        let observed_head = Arc::new(Mutex::new(Vec::new()));
        let tunnel: Arc<dyn Tunnel> = Arc::new(RecordingUpgradeTunnel {
            body_len: expected_wire_body.len(),
            observed_body: Arc::clone(&observed_body),
            observed_head: Arc::clone(&observed_head),
        });

        let request = b"GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
            Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let response = run_upgrade(request, tunnel).await;

        assert!(String::from_utf8_lossy(&response).contains("101"), "expected a 101 response, got {response:?}");
        assert_eq!(
            observed_body.lock().await.as_slice(),
            expected_wire_body,
            "backend must see the body re-chunked, not the decoded bytes"
        );
    }

    // Finding: "Send exactly one Content-Length on the upgrade request". `fix_length` already
    // leaves a deduplicated `Content-Length` in `request.header`; an earlier version appended its
    // own line on top instead of skipping the copied one, sending the header twice.
    #[tokio::test]
    async fn upgrade_content_length_sent_exactly_once() {
        let observed_body = Arc::new(Mutex::new(Vec::new()));
        let observed_head = Arc::new(Mutex::new(Vec::new()));
        let tunnel: Arc<dyn Tunnel> = Arc::new(RecordingUpgradeTunnel {
            body_len: 5,
            observed_body: Arc::clone(&observed_body),
            observed_head: Arc::clone(&observed_head),
        });

        let request = b"GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
            Content-Length: 5\r\n\r\nhello";
        let response = run_upgrade(request, tunnel).await;
        assert!(String::from_utf8_lossy(&response).contains("101"), "expected a 101 response, got {response:?}");

        let head = observed_head.lock().await.clone();
        let head_text = String::from_utf8_lossy(&head).to_lowercase();
        let occurrences = head_text.matches("content-length:").count();
        assert_eq!(occurrences, 1, "expected exactly one Content-Length line, got {head_text:?}");
        assert!(head_text.contains("content-length: 5"), "expected Content-Length: 5, got {head_text:?}");
        assert_eq!(observed_body.lock().await.as_slice(), b"hello");
    }

    #[tokio::test]
    async fn upgrade_content_length_sent_exactly_once_absolute_form() {
        let observed_body = Arc::new(Mutex::new(Vec::new()));
        let observed_head = Arc::new(Mutex::new(Vec::new()));
        let tunnel: Arc<dyn Tunnel> = Arc::new(RecordingUpgradeTunnel {
            body_len: 5,
            observed_body: Arc::clone(&observed_body),
            observed_head: Arc::clone(&observed_head),
        });

        let request = b"GET http://h/ws101 HTTP/1.1\r\nHost: h\r\nProxy-Connection: keep-alive\r\n\
            Connection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 5\r\n\r\nhello";
        let response = run_upgrade(request, tunnel).await;
        assert!(String::from_utf8_lossy(&response).contains("101"), "expected a 101 response, got {response:?}");

        let head = observed_head.lock().await.clone();
        let head_text = String::from_utf8_lossy(&head).to_lowercase();
        let occurrences = head_text.matches("content-length:").count();
        assert_eq!(occurrences, 1, "expected exactly one Content-Length line, got {head_text:?}");
        assert_eq!(observed_body.lock().await.as_slice(), b"hello");
    }
}

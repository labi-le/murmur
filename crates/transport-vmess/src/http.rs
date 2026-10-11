//! The upgrade request is emitted as a normalized HTTP/1.1 request line, `Host`, `User-Agent`
//! (unless overridden), `Content-Length`, then the caller's remaining headers sorted by name.
//!
//! The result is functionally identical to any RFC 7230-compliant peer, though not necessarily
//! byte-identical to that peer's header order.
//!
//! `HttpConn` polls its underlying `conn` directly from `poll_read`/`poll_write` (no shared
//! `Arc<Mutex<..>>`-guarded async state): the relay loop in `tunnel/tunnel.rs` polls the read half
//! and the write half of the same connection from a single task in sequence, and a version of this
//! type that boxed each direction's work as a future holding one shared `tokio::sync::Mutex`
//! deadlocked — the read half's first poll locked the mutex and blocked inside it waiting for the
//! server's response, which the server only sends after receiving the request the write half was
//! waiting on the same mutex to send.

use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_std_compat::net::{Addr, Conn as NetConn};

#[derive(Clone, Debug, Default)]
pub struct HttpConfig {
    pub method: String,
    pub host: String,
    pub path: Vec<String>,
    pub headers: BTreeMap<String, Vec<String>>,
}

/// Canonicalizes a header name to its `Content-Type` shape, limited to the ASCII case this
/// crate needs.
fn canonical_header_key(name: &str) -> String {
    name.split('-')
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + &chars.as_str().to_ascii_lowercase(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

#[expect(
    clippy::indexing_slicing,
    reason = "every caller rejects an empty list before choosing, so the drawn index is always in bounds"
)]
fn random_choice(list: &[String]) -> &str {
    &list[rand::rng().random_range(0..list.len())]
}

fn write_request(cfg: &HttpConfig, body: &[u8]) -> Vec<u8> {
    let path = if cfg.path.is_empty() { "/" } else { random_choice(&cfg.path) };
    let host =
        cfg.headers.get("Host").filter(|list| !list.is_empty()).map_or(cfg.host.as_str(), |list| random_choice(list));
    let method = if cfg.method.is_empty() { "GET" } else { cfg.method.as_str() };

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for (key, list) in &cfg.headers {
        if list.is_empty() {
            continue;
        }
        headers.insert(canonical_header_key(key), random_choice(list).to_owned());
    }
    headers.remove("Host");

    let mut out = Vec::with_capacity(256 + body.len());
    out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
    if let Some(user_agent) = headers.remove("User-Agent") {
        if !user_agent.is_empty() {
            out.extend_from_slice(format!("User-Agent: {user_agent}\r\n").as_bytes());
        }
    } else {
        out.extend_from_slice(format!("User-Agent: {}\r\n", murmur_constant::version::USER_AGENT).as_bytes());
    }
    headers.remove("Content-Length");
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    for (key, value) in &headers {
        out.extend_from_slice(format!("{key}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// Finds the `\r\n\r\n` that ends the header block.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|pos| pos + 4)
}

pub struct HttpConn {
    conn: Box<dyn NetConn>,
    cfg: HttpConfig,
    whandshake: bool,
    pending_write: Option<Vec<u8>>,
    pending_written: usize,
    header_consumed: bool,
    header_buf: Vec<u8>,
    read_chunk: Vec<u8>,
    leftover: Vec<u8>,
    leftover_offset: usize,
}

impl AsyncRead for HttpConn {
    /// Drains the bytes read past the response header once, then reads the underlying conn
    /// directly, holding no buffered-reader state between calls.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.header_consumed {
            loop {
                if let Some(pos) = find_header_end(&this.header_buf) {
                    this.leftover = this.header_buf.split_off(pos);
                    this.leftover_offset = 0;
                    this.header_consumed = true;
                    break;
                }

                let mut read_buf = ReadBuf::new(&mut this.read_chunk);
                match Pin::new(&mut *this.conn).poll_read(cx, &mut read_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                        }
                        let filled = read_buf.filled().to_vec();
                        this.header_buf.extend_from_slice(&filled);
                    }
                }
            }
        }

        if this.leftover_offset < this.leftover.len() {
            let n = std::cmp::min(buf.remaining(), this.leftover.len() - this.leftover_offset);
            let (_, unsent) = this.leftover.split_at(this.leftover_offset);
            let (chunk, _) = unsent.split_at(n);
            buf.put_slice(chunk);
            this.leftover_offset += n;
            if this.leftover_offset == this.leftover.len() {
                this.leftover = Vec::new();
                this.leftover_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut *this.conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.whandshake {
            return Pin::new(&mut *this.conn).poll_write(cx, buf);
        }

        if this.pending_write.is_none() {
            this.pending_write = Some(write_request(&this.cfg, buf));
            this.pending_written = 0;
        }

        loop {
            let Some(pending) = this.pending_write.as_ref() else {
                return Poll::Ready(Err(io::Error::other("pending write was just installed")));
            };
            if this.pending_written >= pending.len() {
                break;
            }
            let (_, unsent) = pending.split_at(this.pending_written);
            match Pin::new(&mut *this.conn).poll_write(cx, unsent) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    this.pending_write = None;
                    this.pending_written = 0;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => this.pending_written += n,
                Poll::Ready(Err(err)) => {
                    this.pending_write = None;
                    this.pending_written = 0;
                    return Poll::Ready(Err(err));
                }
            }
        }

        this.pending_write = None;
        this.pending_written = 0;
        this.whandshake = true;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl NetConn for HttpConn {
    /// The embedded conn's local and peer addresses are promoted directly.
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.remote_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.conn.close()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_write_deadline(deadline)
    }
}

impl std::fmt::Debug for HttpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpConn").finish_non_exhaustive()
    }
}

#[must_use]
pub fn stream_http_conn(conn: Box<dyn NetConn>, cfg: HttpConfig) -> Box<dyn NetConn> {
    Box::new(HttpConn {
        conn,
        cfg,
        whandshake: false,
        pending_write: None,
        pending_written: 0,
        header_consumed: false,
        header_buf: Vec::with_capacity(512),
        read_chunk: vec![0u8; 512],
        leftover: Vec::new(),
        leftover_offset: 0,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use murmur_std_compat::net::{Addr, TcpAddr};

    /// Byte-exact against a captured request for the default, unrandomized config
    /// vless's `network: http` builds (no method, host `example.com`, path `/`).
    #[test]
    fn write_request_emits_reference_bytes() {
        let cfg = HttpConfig {
            method: String::new(),
            host: "example.com".to_owned(),
            path: vec!["/".to_owned()],
            headers: BTreeMap::new(),
        };
        let body = b"VLESS-HANDSHAKE-PAYLOAD-BYTES";

        let got = write_request(&cfg, body);

        let want = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: {}\r\nContent-Length: 29\r\n\r\nVLESS-HANDSHAKE-PAYLOAD-BYTES",
            murmur_constant::version::USER_AGENT
        );
        assert_eq!(want.as_bytes(), got.as_slice());
    }

    struct PipeConn(tokio::io::DuplexStream);

    impl AsyncRead for PipeConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PipeConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl NetConn for PipeConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Regression covering the deadlock this build had: `common::net::sing::RelayDirection` polls the
    /// read half of a connection before the write half on every tick (`right_to_left` before
    /// `left_to_right`), and a real TCP+HTTP-disguise server does not send its response until it
    /// has read the full request. Driving `poll_read` then `poll_write` in that exact order, from
    /// one hand-rolled `poll_fn` tick, reproduces the ordering the relay uses. With the old
    /// `Arc<tokio::sync::Mutex<Inner>>` design this hung forever: the first `poll_read` locked the
    /// mutex and stayed pending awaiting the server's reply, starving `poll_write` of the same
    /// lock it needed to send the request the server was waiting for.
    #[tokio::test]
    async fn read_polled_before_write_does_not_deadlock() {
        let (client_side, server_side) = tokio::io::duplex(1 << 16);
        let cfg = HttpConfig {
            method: String::new(),
            host: "example.com".to_owned(),
            path: vec!["/".to_owned()],
            headers: BTreeMap::new(),
        };
        let mut client = stream_http_conn(Box::new(PipeConn(client_side)), cfg);

        let server = tokio::spawn(async move {
            let mut server_side = server_side;
            let mut request = vec![0u8; 4096];
            let mut filled = 0;
            loop {
                let n = server_side.read(&mut request[filled..]).await.expect("server read");
                assert_ne!(n, 0, "client closed before sending the full request");
                filled += n;
                if find_header_end(&request[..filled]).is_some() {
                    break;
                }
            }
            server_side.write_all(b"HTTP/1.1 200 OK\r\n\r\nBODY").await.expect("server write response");
        });

        let request = b"handshake".to_vec();
        let mut read_buf = [0u8; 4];
        let mut read_done = false;
        let mut write_done = false;

        let drive = std::future::poll_fn(|cx| {
            if !read_done {
                let mut rb = ReadBuf::new(&mut read_buf);
                match Pin::new(&mut *client).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        assert_eq!(b"BODY", &read_buf);
                        read_done = true;
                    }
                    Poll::Ready(Err(err)) => panic!("client read failed: {err}"),
                    Poll::Pending => {}
                }
            }
            if !write_done {
                match Pin::new(&mut *client).poll_write(cx, &request) {
                    Poll::Ready(Ok(_)) => write_done = true,
                    Poll::Ready(Err(err)) => panic!("client write failed: {err}"),
                    Poll::Pending => {}
                }
            }
            if read_done && write_done {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), drive)
            .await
            .expect("polling read before write must not deadlock the connection");
        server.await.expect("server task");
    }
}

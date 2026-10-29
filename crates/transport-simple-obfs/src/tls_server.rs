use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use chrono::Utc;
use rand::Rng as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common_net::io::{OldConnAsStream, Stream, StreamAsOldConn};
use murmur_std_compat::net::Conn;

use super::tls::{frame_record, poll_read_full, RemainAdjust, TlsReadOp, TlsWriteOp};

/// The TLS simple-obfs server.
pub struct TLSObfsServer {
    conn: Box<dyn Stream>,
    remain: i64,
    first_request: bool,
    session_ticket_done: bool,
    first_response: bool,
    read_op: Option<TlsReadOp>,
    write_op: Option<TlsWriteOp>,
    /// Which of the read operations the in-flight `read_op` belongs to, so a resuming poll knows how
    /// to finish it: `Read` hands the bytes to the caller, the skip operations discard them.
    op_phase: OpPhase,
    exts: [u8; 4 * 16 + 2],
    exts_filled: usize,
}

impl core::fmt::Debug for TLSObfsServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TLSObfsServer")
            .field("remain", &self.remain)
            .field("first_request", &self.first_request)
            .field("session_ticket_done", &self.session_ticket_done)
            .field("first_response", &self.first_response)
            .field("op_phase", &self.op_phase)
            .field("exts_filled", &self.exts_filled)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OpPhase {
    Idle,
    /// Reads and discards the extension block.
    Read,
    /// The SNI read at the head of the extension block.
    SkipSni,
    /// The trailing read of the extension block.
    SkipExts,
}

impl TLSObfsServer {
    fn poll_op_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let Some(op) = self.read_op.as_mut() else {
            self.op_phase = OpPhase::Idle;
            return Poll::Ready(Ok(()));
        };
        let data = match op.poll(&mut *self.conn, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(data)) => data,
            Poll::Ready(Err(err)) => {
                self.read_op = None;
                self.op_phase = OpPhase::Idle;
                return Poll::Ready(Err(err));
            }
        };
        match op.remain_adjust() {
            Some(RemainAdjust::Set(remain)) => self.remain = remain,
            Some(RemainAdjust::Sub(n)) => self.remain -= n,
            None => {}
        }
        self.read_op = None;
        self.op_phase = OpPhase::Idle;
        buf.put_slice(data.get(..std::cmp::min(data.len(), buf.remaining())).unwrap_or_default());
        Poll::Ready(Ok(()))
    }

    /// Skips the SNI and the other TLS extensions.
    fn poll_skip_other_exts_sni(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(op) = self.read_op.as_mut() else {
            self.op_phase = OpPhase::Idle;
            return Poll::Ready(Ok(()));
        };
        match op.poll(&mut *self.conn, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(_)) => {
                self.read_op = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                self.read_op = None;
                Poll::Ready(Err(err))
            }
        }
    }

    fn poll_skip_other_exts_tail(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A clean EOF here is the end of the stream, which the caller reports as such.
        match poll_read_full(&mut *self.conn, cx, &mut self.exts, &mut self.exts_filled) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    fn poll_write_op(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let Some(op) = self.write_op.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        let mut first_response = self.first_response;
        let result = op.poll(&mut *self.conn, cx, buf, |chunk| {
            if first_response {
                first_response = false;
                make_server_hello(chunk)
            } else {
                frame_record(chunk)
            }
        });
        self.first_response = first_response;
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(written)) => {
                self.write_op = None;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(err)) => {
                self.write_op = None;
                Poll::Ready(Err(err))
            }
        }
    }
}

impl AsyncRead for TLSObfsServer {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.op_phase {
                // Finish whatever operation an earlier poll started before choosing the next step.
                OpPhase::Idle => {}
                OpPhase::Read => return this.poll_op_read(cx, buf),
                OpPhase::SkipSni => match this.poll_skip_other_exts_sni(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(())) => {
                        this.op_phase = OpPhase::SkipExts;
                        continue;
                    }
                },
                OpPhase::SkipExts => match this.poll_skip_other_exts_tail(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(())) => {
                        this.op_phase = OpPhase::Idle;
                        continue;
                    }
                },
            }

            if this.remain > 0 {
                let length = usize::try_from(this.remain).unwrap_or(usize::MAX);
                this.read_op = Some(TlsReadOp::remain(std::cmp::min(length, buf.remaining()), buf.remaining()));
                this.op_phase = OpPhase::Read;
                continue;
            }

            if this.first_request {
                this.first_request = false;
                this.read_op = Some(TlsReadOp::framed(9 * 16 - 4, buf.remaining()));
                this.op_phase = OpPhase::Read;
                continue;
            }

            if !this.session_ticket_done {
                this.session_ticket_done = true;
                // SNI first
                this.read_op = Some(TlsReadOp::framed(7, 256));
                this.op_phase = OpPhase::SkipSni;
                continue;
            }

            this.read_op = Some(TlsReadOp::framed(3, buf.remaining()));
            this.op_phase = OpPhase::Read;
        }
    }
}

impl AsyncWrite for TLSObfsServer {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.write_op.is_none() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            this.write_op = Some(TlsWriteOp::new());
        }
        this.poll_write_op(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_shutdown(cx)
    }
}

impl Stream for TLSObfsServer {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.conn.as_socket()
    }

    fn old_conn(&self) -> Option<&dyn Conn> {
        self.conn.old_conn()
    }
}

/// Creates a TLS simple-obfs server.
#[must_use]
pub fn new_tls_obfs_server(conn: Box<dyn Conn>) -> Box<dyn Conn> {
    let conn: Box<dyn Stream> = Box::new(OldConnAsStream(conn));
    Box::new(StreamAsOldConn::new(TLSObfsServer {
        conn,
        remain: 0,
        first_request: true,
        session_ticket_done: false,
        first_response: true,
        read_op: None,
        write_op: None,
        op_phase: OpPhase::Idle,
        exts: [0; 4 * 16 + 2],
        exts_filled: 0,
    }))
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the server-hello length field is 16 bits and its timestamp field 32 bits by definition, so the low bits are the wire value"
)]
fn make_server_hello(data: &[u8]) -> Vec<u8> {
    let mut rand_bytes = vec![0u8; 28];
    let mut session_id = vec![0u8; 32];
    rand::rng().fill(&mut rand_bytes[..]);
    rand::rng().fill(&mut session_id[..]);

    let mut buf = Vec::with_capacity(128 + data.len());

    buf.push(0x16);
    buf.extend_from_slice(&0x0301u16.to_be_bytes());
    buf.extend_from_slice(&91u16.to_be_bytes());
    buf.extend_from_slice(&[2, 0, 0, 87, 0x03, 0x03]);
    buf.extend_from_slice(&(Utc::now().timestamp() as u32).to_be_bytes());
    buf.extend_from_slice(&rand_bytes);
    buf.push(32);
    buf.extend_from_slice(&session_id);

    buf.extend_from_slice(&[0xcc, 0xa8]);
    buf.push(0);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
    buf.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
    buf.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);

    buf.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

    buf.extend_from_slice(&[0x16, 0x03, 0x03]);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);

    buf
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, ReadBuf};

    use super::*;
    use murmur_std_compat::net::{Addr, TcpAddr};

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

    impl Conn for PipeConn {
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

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// The client's hello/framing and the server's discard/skip arithmetic must stay in step in both
    /// directions and across chunk boundaries, reading in pieces small enough to hit the `remain` path.
    #[tokio::test]
    async fn round_trip() {
        let (client_side, server_side) = tokio::io::duplex(1 << 20);
        let mut client = super::super::tls::new_tls_obfs(Box::new(PipeConn(client_side)), "example.com".to_owned());
        let mut server = new_tls_obfs_server(Box::new(PipeConn(server_side)));

        let sent = payload(100_000);
        let expected = sent.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&sent).await.expect("client write");
            client
        });
        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        while got.len() < expected.len() {
            let n = server.read(&mut chunk).await.expect("server read");
            assert!(n > 0, "unexpected eof after {} bytes", got.len());
            got.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(got, expected);
        let mut client = writer.await.expect("writer");

        let response = payload(100_000);
        let expected = response.clone();
        let writer = tokio::spawn(async move {
            server.write_all(&response).await.expect("server write");
        });
        let mut got = Vec::new();
        while got.len() < expected.len() {
            let n = client.read(&mut chunk).await.expect("client read");
            assert!(n > 0, "unexpected eof after {} bytes", got.len());
            got.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(got, expected);
        writer.await.expect("writer");
    }

    #[tokio::test]
    async fn round_trip_small_payloads() {
        let (client_side, server_side) = tokio::io::duplex(1 << 16);
        let mut client = super::super::tls::new_tls_obfs(Box::new(PipeConn(client_side)), "a.example".to_owned());
        let mut server = new_tls_obfs_server(Box::new(PipeConn(server_side)));

        for length in [1usize, 16, 100] {
            let sent = payload(length);
            client.write_all(&sent).await.expect("client write");
            let mut got = vec![0u8; length];
            server.read_exact(&mut got).await.expect("server read");
            assert_eq!(got, sent, "length {length}");
        }
    }

    struct FlagConn {
        inner: tokio::io::DuplexStream,
        closes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl AsyncRead for FlagConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for FlagConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }
    impl Conn for FlagConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn close(&self) -> io::Result<()> {
            self.closes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// Regression for `agent://ReviewS9Obfs`'s finding: `close()` through
    /// `StreamAsOldConn(TLSObfsServer{conn: OldConnAsStream(inner)})` used to reach only
    /// `shutdown_read`/`shutdown_write`, never the dialed conn's own `close()`.
    #[tokio::test]
    async fn close_reaches_the_dialed_conn() {
        let (_client, server) = tokio::io::duplex(64);
        let closes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flag = FlagConn { inner: server, closes: std::sync::Arc::clone(&closes) };
        let obfs = new_tls_obfs_server(Box::new(flag));
        obfs.close().expect("close");
        assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

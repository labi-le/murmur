use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::socks5;
use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{
    old_addr_to_socket_addr, socket_addr_from_udp_addr, udp_addr_from_socket_addr, Datagram, Stream as NetStream,
};
use murmur_common_net::packet::datagram::WaitReadFromDatagram;
use murmur_common_pool as pool;
use murmur_std_compat::net::{Conn, UdpAddr};

pub(crate) const MAX_LENGTH: usize = 8192;

pub static DEFAULT_ALPN: &[&str] = &["h2", "http/1.1"];

pub static DEFAULT_WEBSOCKET_ALPN: &[&str] = &["http/1.1"];

pub(crate) static CRLF: [u8; 2] = *b"\r\n";

/// `Command`, an alias of `byte`.
pub type Command = u8;

pub const COMMAND_TCP: Command = 1;
pub const COMMAND_UDP: Command = 3;
pub const COMMAND_MUX: Command = 0x7f;

pub const KEY_LENGTH: usize = 56;

fn err_text(message: &'static str) -> io::Error {
    io::Error::other(message)
}

async fn read_full<R>(r: &mut R, buf: &mut [u8]) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut n = 0;
    let mut rest: &mut [u8] = buf;
    while !rest.is_empty() {
        let read = r.read(rest).await?;
        if read == 0 {
            return Err(if n == 0 {
                io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
            } else {
                io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
            });
        }
        // A reader that claims more bytes than it was handed is treated as a short stream.
        let Some(tail) = rest.get_mut(read..) else {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
        };
        rest = tail;
        n += read;
    }
    Ok(())
}

pub async fn write_header<W>(
    w: &mut W,
    hex_password: &[u8; KEY_LENGTH],
    command: Command,
    socks5_addr: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = pool::get_buffer();

    buf.extend_from_slice(hex_password);
    buf.extend_from_slice(&CRLF);

    buf.extend_from_slice(&[command]);
    buf.extend_from_slice(socks5_addr);
    buf.extend_from_slice(&CRLF);

    let result = w.write_all(&buf).await;
    pool::put_buffer(buf);
    result
}

async fn write_packet<W>(w: &mut W, socks5_addr: &[u8], payload: &[u8]) -> io::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = pool::get_buffer();

    buf.extend_from_slice(socks5_addr);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "`write_packet_split` is the only caller and hands over at most `MAX_LENGTH` bytes, so the length prefix always fits a `u16`"
    )]
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(&CRLF);
    buf.extend_from_slice(payload);

    let result = w.write_all(&buf).await;
    pool::put_buffer(buf);
    result?;
    Ok(payload.len())
}

pub async fn write_packet_split<W>(w: &mut W, socks5_addr: &[u8], payload: &[u8]) -> io::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() <= MAX_LENGTH {
        return write_packet(w, socks5_addr, payload).await;
    }

    let total = payload.len();
    for chunk in payload.chunks(MAX_LENGTH) {
        write_packet(w, socks5_addr, chunk).await?;
    }

    Ok(total)
}

pub async fn read_packet<R>(r: &mut R, payload: &mut [u8]) -> io::Result<(UdpAddr, usize, usize)>
where
    R: AsyncRead + Unpin,
{
    let addr = socks5::socks5::read_addr(r, payload).await.map_err(|_| err_text("read addr error"))?;
    let Some(u_addr) = addr.udp_addr() else {
        return Err(err_text("parse addr error"));
    };

    let Some(length_buf) = payload.first_chunk_mut::<2>() else {
        return Err(err_text("read length error"));
    };
    if read_full(r, length_buf).await.is_err() {
        return Err(err_text("read length error"));
    }

    let total = usize::from(u16::from_be_bytes(*length_buf));
    if total > MAX_LENGTH {
        return Err(err_text("packet invalid"));
    }

    let Some(crlf_buf) = payload.first_chunk_mut::<2>() else {
        return Err(err_text("read crlf error"));
    };
    if read_full(r, crlf_buf).await.is_err() {
        return Err(err_text("read crlf error"));
    }

    let length = total.min(payload.len());

    let Some(body) = payload.get_mut(..length) else {
        return Err(err_text("read packet error"));
    };
    if read_full(r, body).await.is_err() {
        return Err(err_text("read packet error"));
    }

    Ok((u_addr, length, total - length))
}

/// A `PacketConn`, which embeds a stream conn.
pub struct PacketConn {
    conn: SharedConn,
    state: tokio::sync::Mutex<PacketConnState>,
}

impl std::fmt::Debug for PacketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketConn").finish_non_exhaustive()
    }
}

struct PacketConnState {
    remain: usize,
    r_addr: Option<UdpAddr>,
}

#[must_use]
pub fn new_packet_conn(conn: Box<dyn Conn>) -> PacketConn {
    PacketConn {
        conn: SharedConn::from_boxed(conn),
        state: tokio::sync::Mutex::new(PacketConnState { remain: 0, r_addr: None }),
    }
}

impl AsyncRead for PacketConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for PacketConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl PacketConn {
    async fn recv_from_udp(&self, b: &mut [u8]) -> io::Result<(usize, UdpAddr)> {
        let mut state = self.state.lock().await;
        if state.remain != 0 {
            let length = state.remain.min(b.len());

            let conn = self.conn.clone();
            let (chunk, _) = b.split_at_mut(length);
            let n = conn.read(chunk).await?;

            state.remain -= n;
            let addr = state.r_addr.clone().ok_or_else(|| err_text("missing remote address"))?;
            if state.remain == 0 {
                state.r_addr = None;
            }

            drop(state);
            return Ok((n, addr));
        }

        let mut conn = self.conn.clone();
        let (addr, n, remain) = read_packet(&mut conn, b).await?;

        if remain != 0 {
            state.remain = remain;
            state.r_addr = Some(addr.clone());
        }

        drop(state);
        Ok((n, addr))
    }

    async fn send_to_addr(&self, b: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let udp_addr = udp_addr_from_socket_addr(addr);
        let socks5_addr = socks5::socks5::parse_addr_to_socks_addr(&udp_addr).map(|addr| addr.0).unwrap_or_default();
        let mut conn = self.conn.clone();
        write_packet_split(&mut conn, &socks5_addr, b).await
    }
}

impl NetStream for PacketConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.conn.local_addr()?.as_ref())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.conn.remote_addr()?.as_ref())
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.close_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.close_write()
    }

    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(&self.conn)
    }
}

#[async_trait]
impl Datagram for PacketConn {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, addr) = self.recv_from_udp(buf).await?;
        Ok((n, socket_addr_from_udp_addr(&addr)))
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.send_to_addr(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.conn.local_addr()?.as_ref())
    }

    fn close(&self) -> io::Result<()> {
        self.conn.close()
    }
}

#[async_trait]
impl WaitReadFromDatagram for PacketConn {
    // NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
    async fn wait_read_from(&self) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<SocketAddr>, io::Result<()>) {
        let _state = self.state.lock().await;

        let mut conn = self.conn.clone();
        let destination = match socks5::socks5::read_addr0(&mut conn).await {
            Ok(destination) => destination,
            Err(err) => return (Vec::new(), None, None, Err(io::Error::other(err.to_string()))),
        };
        let Some(udp_addr) = destination.udp_addr() else {
            return (Vec::new(), None, None, Err(err_text("parse addr error")));
        };
        let addr = socket_addr_from_udp_addr(&udp_addr);

        let mut data = pool::get(pool::UDP_BUFFER_SIZE);

        let mut header = [0u8; 2 + 2];
        if let Err(err) = read_full(&mut conn, &mut header).await {
            let _ = pool::put(data);
            return (Vec::new(), None, None, Err(err));
        }
        let [hi, lo, ..] = header;
        let length = usize::from(u16::from_be_bytes([hi, lo]));
        if length > MAX_LENGTH {
            let _ = pool::put(data);
            return (Vec::new(), None, None, Err(err_text("packet invalid")));
        }

        let Some(body) = data.get_mut(..length) else {
            let _ = pool::put(data);
            return (Vec::new(), None, None, Err(err_text("packet invalid")));
        };

        if length > 0 {
            if let Err(err) = read_full(&mut conn, body).await {
                let _ = pool::put(data);
                return (Vec::new(), None, None, Err(err));
            }
        } else {
            let _ = pool::put(data);
            return (Vec::new(), None, Some(addr), Ok(()));
        }

        let payload = body.to_vec();
        let put: Box<dyn FnOnce() + Send> = Box::new(move || {
            let _ = pool::put(data);
        });
        (payload, Some(put), Some(addr), Ok(()))
    }
}

#[must_use]
pub fn key(password: &str) -> [u8; KEY_LENGTH] {
    let hash = Sha224::digest(password.as_bytes());
    let encoded = hex::encode(hash);
    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(encoded.as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use std::time::Duration;
    use tokio::io::AsyncWrite;

    use super::*;

    #[derive(Default)]
    struct RecordingWriter {
        buf: Vec<u8>,
    }

    impl AsyncWrite for RecordingWriter {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.get_mut().buf.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// `key` is the lowercase hex of the SHA-224 digest of the password.
    #[test]
    fn key_is_lowercase_hex_sha224() {
        let got = key("test-password");
        assert_eq!(&got, b"b42338ef718bb33b88d3c2bf0cb6130499a1dc05e5c101b3722b09c7");
    }

    /// Pins `write_header` wire bytes for a TCP command to `example.com:443`.
    #[tokio::test]
    async fn write_header_tcp_wire_bytes() {
        let hex_password = key("test-password");
        let socks5_addr = socks5::socks5::parse_addr("example.com:443").expect("valid socks5 addr");

        let mut w = RecordingWriter::default();
        write_header(&mut w, &hex_password, COMMAND_TCP, &socks5_addr).await.expect("write_header");

        let want = hex::decode(
            "62343233333865663731386262333362383864336332626630636236313330343939613164633035653563313031623337323262303963370d0a01030b6578616d706c652e636f6d01bb0d0a",
        )
        .expect("valid hex vector");
        assert_eq!(w.buf, want, "write_header does not match the pinned bytes");
    }

    /// Pins `write_packet_split` wire bytes for a UDP payload to `198.51.100.7:5353`.
    #[tokio::test]
    async fn write_packet_udp_wire_bytes() {
        let socks5_addr = socks5::socks5::parse_addr("198.51.100.7:5353").expect("valid socks5 addr");
        let payload = b"udp-payload";

        let mut w = RecordingWriter::default();
        let n = write_packet_split(&mut w, &socks5_addr, payload).await.expect("write_packet_split");

        let want = hex::decode("01c633640714e9000b0d0a7564702d7061796c6f6164").expect("valid hex vector");
        assert_eq!(n, payload.len());
        assert_eq!(w.buf, want, "write_packet does not match the pinned bytes");
    }

    #[tokio::test]
    async fn datagram_recv_from_reassembles_a_split_packet_via_pooled_state() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (client, (mut server, _)) =
            tokio::try_join!(tokio::net::TcpStream::connect(addr), listener.accept()).expect("pair");

        let pc = new_packet_conn(Box::new(client));
        let socks5_addr = socks5::socks5::parse_addr("198.51.100.7:5353").expect("valid socks5 addr");
        // `read_packet` rejects any first-call buffer shorter than `socks5::MAX_ADDR_LEN` (it
        // doubles as scratch space for the socks5 address header), so the payload must be
        // longer than that to exercise the partial-packet ("remain") pooled-read path at all.
        let payload: Vec<u8> = (0..socks5::socks5::MAX_ADDR_LEN + 20).map(|i| i as u8).collect();
        write_packet_split(&mut server, &socks5_addr, &payload).await.expect("write_packet_split");

        let mut first = vec![0u8; socks5::socks5::MAX_ADDR_LEN];
        let (n1, from1) = Datagram::recv_from(&pc, &mut first).await.expect("first recv_from");
        assert_eq!(n1, first.len());
        assert_eq!(first[..n1], payload[..n1]);
        assert_eq!(from1, "198.51.100.7:5353".parse::<SocketAddr>().unwrap());

        let mut rest = vec![0u8; payload.len() - n1];
        let (n2, from2) = Datagram::recv_from(&pc, &mut rest).await.expect("second recv_from");
        assert_eq!(n2, rest.len());
        assert_eq!(rest[..n2], payload[n1..]);
        assert_eq!(from2, from1, "the pooled partial-packet state must keep reporting the same source address");
    }

    #[tokio::test]
    async fn datagram_send_to_matches_the_old_write_to_wire_format() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (mut client, (server, _)) =
            tokio::try_join!(tokio::net::TcpStream::connect(addr), listener.accept()).expect("pair");

        let pc = new_packet_conn(Box::new(server));
        let dest: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let payload = b"udp-payload";
        let n = Datagram::send_to(&pc, payload, dest).await.expect("send_to");
        assert_eq!(n, payload.len());

        let mut buf = vec![0u8; MAX_LENGTH];
        let (got_addr, got_n, remain) = read_packet(&mut client, &mut buf).await.expect("read_packet");
        assert_eq!(remain, 0);
        assert_eq!(&buf[..got_n], payload);
        assert_eq!(SocketAddr::try_from(&got_addr).unwrap(), dest);
    }

    /// Regression guard for the `Stream::shutdown_write` bridge: a caller that only holds
    /// `PacketConn` as a `Stream` must still be able to half-close the underlying TCP socket, the
    /// same as the old `Conn::close_write` forward it replaces.
    #[tokio::test]
    async fn stream_impl_reports_socket_addresses_and_half_closes_on_shutdown_write() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (client, (mut server, _)) =
            tokio::try_join!(tokio::net::TcpStream::connect(addr), listener.accept()).expect("pair");
        let client_addr = client.local_addr().expect("client addr");

        let pc = new_packet_conn(Box::new(client));
        assert_eq!(NetStream::local_addr(&pc).expect("local_addr"), client_addr);
        assert_eq!(NetStream::peer_addr(&pc).expect("peer_addr"), addr);

        NetStream::shutdown_write(&pc).expect("shutdown_write");

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), server.read(&mut buf))
            .await
            .expect("shutdown_write must not leave the peer read hanging")
            .expect("server read after client half-close");
        assert_eq!(n, 0, "shutdown_write must half-close the socket, matching the old close_write");
    }

    /// Regression guard for the `Stream::shutdown_read` bridge: mirrors
    /// `stream_impl_reports_socket_addresses_and_half_closes_on_shutdown_write`, but for the read
    /// side. The server never writes, so a genuine `shutdown_read` reports local `Ok(0)`
    /// immediately; a no-op `shutdown_read` leaves the client parked forever.
    #[tokio::test]
    async fn stream_impl_half_closes_the_read_side_on_shutdown_read() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (client, (_server, _)) =
            tokio::try_join!(tokio::net::TcpStream::connect(addr), listener.accept()).expect("pair");

        let mut pc = new_packet_conn(Box::new(client));
        NetStream::shutdown_read(&pc).expect("shutdown_read");

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), AsyncReadExt::read(&mut pc, &mut buf))
            .await
            .expect("shutdown_read must not leave the client read hanging")
            .expect("client read after shutdown_read");
        assert_eq!(n, 0, "shutdown_read must half-close the read side locally");
    }
}

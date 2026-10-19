use std::any::Any;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{close_stream, ExtendedStream, Stream as NetStream};
use murmur_common_net::sing::{new_extended_conn, EarlyConn, ExtendedConn as CommonExtendedConn, UpstreamNode};
use murmur_compat::sing_buf::{self as buf, Buffer};
use murmur_component_tls::utls::TlsBufferedIncoming;
use murmur_std_compat::net::{sock_addr_of, Addr, Conn as NetConn, ExtendedConn as NetExtendedConn, TcpAddr};

use super::config_pb::Addons;
use super::vision::conn::Conn as VisionConn;
use super::vision::vision;
use super::vless::{Client, DstAddr, COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, VERSION, XRV};

/// Recovers a socket-backed `SocketAddr` from a [`Addr`]. This crate's own conns only ever hand
/// back `TcpAddr`/`UdpAddr` (the `as_sock_addr` case), so unlike `common_net::io`'s private helper
/// of the same purpose this does not also try `addr_port`/`Display` fallbacks.
pub(crate) fn old_addr_to_socket_addr(addr: &dyn Addr) -> io::Result<SocketAddr> {
    sock_addr_of(addr)
        .and_then(|sock_addr| SocketAddr::try_from(&sock_addr).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "address is not socket-backed"))
}

/// The scratch buffer used to discard the response's addon data.
const RECV_SCRATCH_SIZE: usize = 32 * 1024;

/// The read-full contract: `Ok(false)` is a clean EOF, a short read is `UnexpectedEof`.
fn poll_read_full<R>(reader: &mut R, cx: &mut Context<'_>, dst: &mut [u8], filled: &mut usize) -> Poll<io::Result<bool>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let Some(mut rest) = dst.get_mut(*filled..) else {
        return Poll::Ready(Ok(true));
    };
    while !rest.is_empty() {
        let mut read_buf = ReadBuf::new(rest);
        ready!(Pin::new(&mut *reader).poll_read(cx, &mut read_buf))?;
        let n = read_buf.filled().len();
        if n == 0 {
            if *filled == 0 {
                return Poll::Ready(Ok(false));
            }
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")));
        }
        let (_, tail) = rest.split_at_mut(n);
        rest = tail;
        *filled += n;
    }
    Poll::Ready(Ok(true))
}

fn eof_error() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

/// Which half of the blocking `recv_response` is due.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RecvStage {
    Head,
    Discard,
}

pub struct Conn {
    inner: Box<dyn CommonExtendedConn>,
    dst: DstAddr,
    id: Uuid,
    addons: Option<Addons>,
    received: bool,
    sent: bool,
    recv_stage: RecvStage,
    recv_buffer: [u8; 2],
    recv_filled: usize,
    recv_remaining: usize,
    recv_scratch: Vec<u8>,
    recv_scratch_filled: usize,
    send_data: Option<Vec<u8>>,
    send_data_sent: usize,
}

impl core::fmt::Debug for Conn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Conn")
            .field("dst", &self.dst)
            .field("id", &"<redacted>")
            .field("received", &self.received)
            .field("sent", &self.sent)
            .finish_non_exhaustive()
    }
}

impl Conn {
    pub(crate) async fn recv_response(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_recv_response(cx)).await
    }

    fn poll_recv_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.recv_stage {
                RecvStage::Head => {
                    if !ready!(poll_read_full(&mut self.inner, cx, &mut self.recv_buffer, &mut self.recv_filled))? {
                        return Poll::Ready(Err(eof_error()));
                    }

                    if self.recv_buffer[0] != VERSION {
                        return Poll::Ready(Err(io::Error::other("unexpected response version")));
                    }

                    let length = usize::from(self.recv_buffer[1]);
                    self.recv_stage = RecvStage::Discard;
                    if length == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    self.recv_remaining = length;
                    self.recv_scratch = vec![0u8; length.min(RECV_SCRATCH_SIZE)];
                    self.recv_scratch_filled = 0;
                }
                RecvStage::Discard => {
                    // Discard the response's addon bytes; a read error ends the discard early.
                    while self.recv_remaining > 0 {
                        let want = self.recv_remaining.min(self.recv_scratch.len());
                        let (chunk, _tail) = self.recv_scratch.split_at_mut(want);
                        match poll_read_full(&mut self.inner, cx, chunk, &mut self.recv_scratch_filled) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Ok(true)) => {
                                self.recv_remaining -= want;
                                self.recv_scratch_filled = 0;
                            }
                            Poll::Ready(Ok(false) | Err(_)) => break,
                        }
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    /// Builds the request body up to the conn write.
    fn build_request(&self, p: &[u8]) -> Vec<u8> {
        let addons_bytes = match &self.addons {
            Some(addons) => addons.encode_to_vec(),
            None => Vec::new(),
        };

        let mut request_len = 1; // protocol version
        request_len += 16; // UUID
        request_len += 1; // addons length
        request_len += addons_bytes.len();
        request_len += 1; // command
        if !self.dst.mux {
            request_len += 2; // port
            request_len += 1; // addr type
            request_len += self.dst.addr.len();
        }
        request_len += p.len();

        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_possible_wrap,
            reason = "`buf::new_size` is `i32`-sized, and a request frame is a small fixed header, the addons and one payload"
        )]
        let mut buffer = buf::new_size(request_len as i32);

        #[expect(
            clippy::cast_possible_truncation,
            reason = "the addons blob is length-prefixed by a single byte on the wire, which is what is written here"
        )]
        buf::must(vec![
            buffer.write_byte(VERSION).err(),             // protocol version
            buffer.write_bytes(self.id.as_bytes()).err(), // 16 bytes of uuid
            buffer.write_byte(addons_bytes.len() as u8).err(),
            buffer.write_bytes(&addons_bytes).err(),
        ]);

        if self.dst.mux {
            buf::must(vec![buffer.write_byte(COMMAND_MUX).err()]);
        } else {
            if self.dst.udp {
                buf::must(vec![buffer.write_byte(COMMAND_UDP).err()]);
            } else {
                buf::must(vec![buffer.write_byte(COMMAND_TCP).err()]);
            }

            buffer.extend(2).copy_from_slice(&self.dst.port.to_be_bytes());
            buf::must(vec![buffer.write_byte(self.dst.addr_type).err(), buffer.write_bytes(&self.dst.addr).err()]);
        }

        buf::must(vec![buffer.write_bytes(p).err()]);

        let bytes = buffer.bytes().to_vec();
        buffer.release();
        bytes
    }

    // cancel-safe: polls `self`'s own state machine through `poll_fn`, so dropping the future only stops polling and the handshake resumes where it left off on the next call.
    pub(crate) async fn send_request(&mut self, p: &[u8]) -> io::Result<()> {
        poll_fn(|cx| self.poll_send_request(cx, p)).await
    }

    /// The wrapped conn's write is documented to write the whole buffer or fail, so it would never
    /// short-write. `poll_write` on an `AsyncWrite` carries no such guarantee — the underlying
    /// `tokio::io::duplex` that xhttp uses caps a single write at its fixed channel capacity, so a
    /// combined header+payload buffer larger than that capacity is legitimately short-written and
    /// must be resumed, not treated as fully sent.
    fn poll_send_request(&mut self, cx: &mut Context<'_>, p: &[u8]) -> Poll<io::Result<()>> {
        if self.send_data.is_none() {
            self.send_data = Some(self.build_request(p));
            self.send_data_sent = 0;
        }
        loop {
            let Some(data) = self.send_data.as_ref() else {
                return Poll::Ready(Err(io::Error::other("vless: request buffer missing")));
            };
            if self.send_data_sent >= data.len() {
                break;
            }
            let (_, unsent) = data.split_at(self.send_data_sent);
            match Pin::new(&mut self.inner).poll_write(cx, unsent) {
                Poll::Ready(Ok(0)) => {
                    self.send_data = None;
                    self.send_data_sent = 0;
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "vless: write zero")));
                }
                Poll::Ready(Ok(n)) => self.send_data_sent += n,
                Poll::Ready(Err(err)) => {
                    self.send_data = None;
                    self.send_data_sent = 0;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        self.send_data = None;
        self.send_data_sent = 0;
        Poll::Ready(Ok(()))
    }

    #[must_use]
    pub const fn reader_replaceable(&self) -> bool {
        self.received
    }

    #[must_use]
    pub const fn writer_replaceable(&self) -> bool {
        self.sent
    }

    #[must_use]
    pub const fn need_handshake(&self) -> bool {
        !self.sent
    }
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.received {
            ready!(this.poll_recv_response(cx))?;
            this.received = true;
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.sent {
            ready!(this.poll_send_request(cx, buf))?;
            this.sent = true;
            return Poll::Ready(Ok(buf.len()));
        }

        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl NetConn for Conn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.inner.local_addr()?)))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.inner.peer_addr()?)))
    }

    fn close(&self) -> io::Result<()> {
        close_stream(&*self.inner)
    }

    fn close_read(&self) -> io::Result<()> {
        self.inner.shutdown_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.old_conn().map_or(Ok(()), |inner| inner.set_deadline(deadline))
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.old_conn().map_or(Ok(()), |inner| inner.set_read_deadline(deadline))
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.old_conn().map_or(Ok(()), |inner| inner.set_write_deadline(deadline))
    }
}

impl NetExtendedConn for Conn {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(&self.inner)
    }

    fn reader_replaceable(&self) -> bool {
        Self::reader_replaceable(self)
    }

    fn writer_replaceable(&self) -> bool {
        Self::writer_replaceable(self)
    }
}

impl UpstreamNode for Conn {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&*self.inner)
    }

    fn reader_replaceable(&self) -> Option<bool> {
        Some(Self::reader_replaceable(self))
    }

    fn writer_replaceable(&self) -> Option<bool> {
        Some(Self::writer_replaceable(self))
    }

    fn early_conn(&self) -> Option<&dyn EarlyConn> {
        Some(self)
    }
}

impl EarlyConn for Conn {
    fn need_handshake(&self) -> bool {
        Self::need_handshake(self)
    }
}

impl NetStream for Conn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(NetConn::local_addr(self)?.as_ref())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(NetConn::remote_addr(self)?.as_ref())
    }

    fn shutdown_read(&self) -> io::Result<()> {
        NetConn::close_read(self)
    }

    fn shutdown_write(&self) -> io::Result<()> {
        NetConn::close_write(self)
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.inner.as_socket()
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(self)
    }
}

impl ExtendedStream for Conn {
    fn reader_replaceable(&self) -> bool {
        NetExtendedConn::reader_replaceable(self)
    }

    fn writer_replaceable(&self) -> bool {
        NetExtendedConn::writer_replaceable(self)
    }
}

#[async_trait]
impl CommonExtendedConn for Conn {
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        if !self.received {
            self.recv_response().await?;
            self.received = true;
        }
        self.inner.read_buffer(buffer).await
    }

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        if !self.sent {
            self.send_request(buffer.bytes()).await?;
            self.sent = true;
            return Ok(());
        }

        self.inner.write_buffer(buffer).await
    }
}

pub fn new_conn(
    conn: Box<dyn NetStream>,
    tls_check: vision::TlsConnCheck,
    direct_net: Option<SharedConn>,
    buffered_incoming: Option<Arc<dyn TlsBufferedIncoming>>,
    client: &Client,
    dst: &DstAddr,
) -> anyhow::Result<Box<dyn ExtendedStream>> {
    let id = client.uuid;
    let c = Conn {
        inner: new_extended_conn(conn),
        id,
        addons: client.addons.clone(),
        dst: dst.clone(),
        received: false,
        sent: false,
        recv_stage: RecvStage::Head,
        recv_buffer: [0; 2],
        recv_filled: 0,
        recv_remaining: 0,
        recv_scratch: Vec::new(),
        recv_scratch_filled: 0,
        send_data: None,
        send_data_sent: 0,
    };

    let vision_flow = client.addons.as_ref().is_some_and(|addons| addons.flow == XRV);
    if vision_flow {
        let vision_conn: VisionConn =
            vision::new_conn(SharedConn::from_boxed(Box::new(c)), tls_check, direct_net, buffered_incoming, id)?;
        return Ok(Box::new(vision_conn));
    }

    Ok(Box::new(c))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::vless::{new_client, ATYP_DOMAIN_NAME, ATYP_IPV4, ATYP_IPV6};
    use murmur_common_net::deadline::pipe_sing::pipe;
    use murmur_common_net::io::OldConnAsStream;

    const UUID_STR: &str = "11111111-1111-1111-1111-111111111111";

    /// Pins the request bytes the client writes for a no-addons client and the given
    /// [`DstAddr`] to the documented wire format: a single `write_all(b"hi")` follows the header.
    /// VLESS numbers ATYP 1/2/3 as IPv4/domain/IPv6, unlike SOCKS's 1/3/4.
    async fn assert_request_wire_bytes(dst: DstAddr, want_hex: &str) {
        let client = new_client(UUID_STR, None).expect("vless client");
        let (pipe_conn, mut peer) = pipe();
        let mut conn = client
            .stream_conn(Box::new(OldConnAsStream(pipe_conn)), vision::TlsConnCheck::Unsupported, None, None, &dst)
            .expect("stream_conn");

        let want = hex::decode(want_hex).expect("valid hex vector");
        let write_task = tokio::spawn(async move {
            conn.write_all(b"hi").await.expect("write_all");
        });

        let mut got = vec![0u8; want.len()];
        peer.read_exact(&mut got).await.expect("read exact request length");

        assert_eq!(got, want, "sendRequest diverges from the vless.Conn.sendRequest");

        let mut rest = Vec::new();
        if let Err(err) = peer.read_to_end(&mut rest).await {
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "drain: {err}");
        }
        assert!(rest.is_empty(), "trailing bytes after the frame");

        write_task.await.expect("writer task");
    }

    #[tokio::test]
    async fn send_request_ipv4_wire_bytes() {
        let dst = DstAddr { udp: false, addr_type: ATYP_IPV4, addr: vec![192, 0, 2, 1], port: 443, mux: false };
        assert_request_wire_bytes(dst, "0011111111111111111111111111111111000101bb01c00002016869").await;
    }

    #[tokio::test]
    async fn send_request_domain_wire_bytes() {
        let mut addr = vec![b"example.com".len() as u8];
        addr.extend_from_slice(b"example.com");
        let dst = DstAddr { udp: false, addr_type: ATYP_DOMAIN_NAME, addr, port: 80, mux: false };
        assert_request_wire_bytes(dst, "001111111111111111111111111111111100010050020b6578616d706c652e636f6d6869")
            .await;
    }

    #[tokio::test]
    async fn send_request_ipv6_wire_bytes() {
        let addr = "2001:db8::1".parse::<std::net::Ipv6Addr>().expect("valid ipv6").octets().to_vec();
        let dst = DstAddr { udp: false, addr_type: ATYP_IPV6, addr, port: 8443, mux: false };
        assert_request_wire_bytes(
            dst,
            "0011111111111111111111111111111111000120fb0320010db80000000000000000000000016869",
        )
        .await;
    }

    /// Pins the addons-length-prefixed protobuf blob for a non-vision flow in the request.
    #[tokio::test]
    async fn send_request_with_addons_flow_wire_bytes() {
        let addons = Addons { flow: "some-custom-flow".to_owned(), seed: Vec::new() };
        let client = new_client(UUID_STR, Some(addons)).expect("vless client");
        let mut addr = vec![b"example.com".len() as u8];
        addr.extend_from_slice(b"example.com");
        let dst = DstAddr { udp: false, addr_type: ATYP_DOMAIN_NAME, addr, port: 80, mux: false };

        let (pipe_conn, mut peer) = pipe();
        let mut conn = client
            .stream_conn(Box::new(OldConnAsStream(pipe_conn)), vision::TlsConnCheck::Unsupported, None, None, &dst)
            .expect("stream_conn");

        let want = hex::decode(
            "0011111111111111111111111111111111120a10736f6d652d637573746f6d2d666c6f77010050020b6578616d706c652e636f6d6869",
        )
        .expect("valid hex vector");
        let write_task = tokio::spawn(async move {
            conn.write_all(b"hi").await.expect("write_all");
        });

        let mut got = vec![0u8; want.len()];
        peer.read_exact(&mut got).await.expect("read exact request length");

        assert_eq!(got, want, "sendRequest with addons diverges from the vless.Conn.sendRequest");

        let mut rest = Vec::new();
        if let Err(err) = peer.read_to_end(&mut rest).await {
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "drain: {err}");
        }
        assert!(rest.is_empty(), "trailing bytes after the frame");

        write_task.await.expect("writer task");
    }

    #[tokio::test]
    async fn silent_tcp_peer_respects_vless_read_deadline() -> io::Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let client_socket = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
        let (_silent_peer, _) = listener.accept().await?;
        let client = new_client(UUID_STR, None).expect("vless client");
        let dst = DstAddr { udp: false, addr_type: ATYP_IPV4, addr: vec![192, 0, 2, 1], port: 443, mux: false };
        let mut conn = client
            .stream_conn(Box::new(client_socket), vision::TlsConnCheck::Unsupported, None, None, &dst)
            .expect("vless stream");
        conn.old_conn()
            .expect("vless must preserve its deadline interface")
            .set_read_deadline(Some(tokio::time::Instant::now() + std::time::Duration::from_millis(40)))?;
        let mut byte = [0u8; 1];
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), conn.read(&mut byte))
            .await
            .expect("vless read must finish");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        Ok(())
    }
}

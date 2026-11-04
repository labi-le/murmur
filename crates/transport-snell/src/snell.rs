//! The Snell client and server sessions: the command handshake and the obfuscated stream wrapper.

use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use murmur_common_net::io::{close_stream, OldConnAsStream, Stream};
use murmur_common_pool as pool;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn as NetPacketConn, TcpAddr};
use murmur_transport::socks5::socks5;
use murmur_transport_shadowsocks::shadowaead;

use super::cipher::{new_aes128gcm, new_chacha20poly1305};
use super::v4::{new_v4_conn, V4Conn, V4ReadHalf, V4WriteHalf};

pub const VERSION1: i32 = 1;
pub const VERSION2: i32 = 2;
pub const VERSION3: i32 = 3;
pub const VERSION4: i32 = 4;
pub const VERSION5: i32 = 5;
pub const DEFAULT_SNELL_VERSION: i32 = VERSION1;

/// max packet length
pub(crate) const MAX_LENGTH: usize = 0x3FFF;

pub const COMMAND_PING: u8 = 0;
pub const COMMAND_CONNECT: u8 = 1;
pub const COMMAND_CONNECT_V2: u8 = 5;
pub const COMMAND_UDP: u8 = 6;
pub const COMMOND_UDP_FORWARD: u8 = 1;

pub const COMMAND_TUNNEL: u8 = 0;
pub const COMMAND_PONG: u8 = 1;
pub const COMMAND_ERROR: u8 = 2;

pub const VERSION: u8 = 1;

pub(crate) const END_SIGNAL: &[u8] = &[];

/// The EOF error reported when the read got nothing.
pub(crate) fn eof_error() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

pub(crate) fn unexpected_eof_error() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

pub(crate) fn to_io_error(err: anyhow::Error) -> io::Error {
    io::Error::other(err)
}

pub(crate) fn is_zero_chunk(err: &io::Error) -> bool {
    err.get_ref().and_then(|err| err.downcast_ref::<shadowaead::stream::ErrZeroChunk>()).is_some()
}

/// The read-full contract: `Ok(false)` is a clean EOF, a short read is `UnexpectedEof`.
pub(crate) fn poll_read_full<R>(
    reader: &mut R,
    cx: &mut Context<'_>,
    dst: &mut [u8],
    filled: &mut usize,
) -> Poll<io::Result<bool>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    while *filled < dst.len() {
        let (_, pending) = dst.split_at_mut(*filled);
        let mut read_buf = ReadBuf::new(pending);
        ready!(Pin::new(&mut *reader).poll_read(cx, &mut read_buf))?;
        let n = read_buf.filled().len();
        if n == 0 {
            if *filled == 0 {
                return Poll::Ready(Ok(false));
            }
            return Poll::Ready(Err(unexpected_eof_error()));
        }
        *filled += n;
    }
    Poll::Ready(Ok(true))
}

/// The write: a socket write always writes fully or errors.
///
/// `poll_write` may report a short write (e.g. `ShadowConn::poll_write` capping at
/// `MAX_TLS_PLAINTEXT`); this loops over `offset` (persisted by the caller across polls) until
/// `record` is fully written.
pub(crate) fn poll_write_once<W>(
    writer: &mut W,
    cx: &mut Context<'_>,
    record: &[u8],
    offset: &mut usize,
) -> Poll<io::Result<()>>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    while *offset < record.len() {
        let (_, pending) = record.split_at(*offset);
        match Pin::new(&mut *writer).poll_write(cx, pending) {
            Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero))),
            Poll::Ready(Ok(n)) => *offset += n,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
    *offset = 0;
    Poll::Ready(Ok(()))
}

#[async_trait]
pub trait PacketFrameWriter: Send + Sync {
    /// The write fallback.
    async fn write(&mut self, b: &[u8]) -> io::Result<usize>;

    async fn write_packet_frame(&mut self, b: &[u8]) -> io::Result<usize> {
        self.write(b).await
    }
}

/// The conn a session writes through: the plain stream or the packet-framing v4 conn.
///
/// Variant selection stands in for the assertion a caller would otherwise make on the wrapped
/// conn, since `murmur_std_compat::net::Conn` has no `as_any`.
pub enum SnellConn {
    Plain(Box<dyn Stream>),
    V4(Box<V4Conn>),
}

impl fmt::Debug for SnellConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(_) => f.debug_tuple("Plain").finish_non_exhaustive(),
            Self::V4(_) => f.debug_tuple("V4").finish_non_exhaustive(),
        }
    }
}

impl AsyncRead for SnellConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(conn) => Pin::new(&mut **conn).poll_read(cx, buf),
            Self::V4(conn) => Pin::new(&mut **conn).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SnellConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(conn) => Pin::new(&mut **conn).poll_write(cx, buf),
            Self::V4(conn) => Pin::new(&mut **conn).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(conn) => Pin::new(&mut **conn).poll_flush(cx),
            Self::V4(conn) => Pin::new(&mut **conn).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(conn) => Pin::new(&mut **conn).poll_shutdown(cx),
            Self::V4(conn) => Pin::new(&mut **conn).poll_shutdown(cx),
        }
    }
}

impl Stream for SnellConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Plain(conn) => conn.local_addr(),
            Self::V4(conn) => conn.local_addr(),
        }
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Plain(conn) => conn.peer_addr(),
            Self::V4(conn) => conn.peer_addr(),
        }
    }

    fn shutdown_read(&self) -> io::Result<()> {
        match self {
            Self::Plain(conn) => conn.shutdown_read(),
            Self::V4(conn) => conn.shutdown_read(),
        }
    }

    fn shutdown_write(&self) -> io::Result<()> {
        match self {
            Self::Plain(conn) => conn.shutdown_write(),
            Self::V4(conn) => conn.shutdown_write(),
        }
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        match self {
            Self::Plain(conn) => conn.old_conn(),
            Self::V4(conn) => conn.old_conn(),
        }
    }
}

/// The reply progress. A blocking read as one call becomes a resumable poll here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplyStage {
    Head,
    Code,
    Length,
    Message,
}

pub struct Snell {
    conn: SnellConn,
    buffer: [u8; 1],
    pub(crate) reply: bool,
    reply_stage: ReplyStage,
    reply_filled: usize,
    reply_code: u8,
    reply_msg: Vec<u8>,
}

impl fmt::Debug for Snell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snell")
            .field("reply", &self.reply)
            .field("reply_stage", &self.reply_stage)
            .field("reply_code", &self.reply_code)
            .finish_non_exhaustive()
    }
}

impl Snell {
    pub(crate) const fn new(conn: SnellConn) -> Self {
        Self {
            conn,
            buffer: [0],
            reply: false,
            reply_stage: ReplyStage::Head,
            reply_filled: 0,
            reply_code: 0,
            reply_msg: Vec::new(),
        }
    }

    pub async fn read_reply(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_reply(cx)).await
    }

    fn poll_reply(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.reply {
            return Poll::Ready(Ok(()));
        }

        loop {
            match self.reply_stage {
                ReplyStage::Head => {
                    if !ready!(poll_read_full(&mut self.conn, cx, &mut self.buffer, &mut self.reply_filled))? {
                        return Poll::Ready(Err(eof_error()));
                    }
                    self.reply = true;
                    self.reply_filled = 0;

                    if self.buffer[0] == COMMAND_TUNNEL {
                        return Poll::Ready(Ok(()));
                    } else if self.buffer[0] != COMMAND_ERROR {
                        return Poll::Ready(Err(io::Error::other("command not support")));
                    }
                    self.reply_stage = ReplyStage::Code;
                }
                ReplyStage::Code => {
                    if !ready!(poll_read_full(&mut self.conn, cx, &mut self.buffer, &mut self.reply_filled))? {
                        return Poll::Ready(Err(eof_error()));
                    }
                    self.reply_code = self.buffer[0];
                    self.reply_filled = 0;
                    self.reply_stage = ReplyStage::Length;
                }
                ReplyStage::Length => {
                    if !ready!(poll_read_full(&mut self.conn, cx, &mut self.buffer, &mut self.reply_filled))? {
                        return Poll::Ready(Err(eof_error()));
                    }
                    let length = usize::from(self.buffer[0]);
                    self.reply_msg = vec![0u8; length];
                    self.reply_filled = 0;
                    self.reply_stage = ReplyStage::Message;
                }
                ReplyStage::Message => {
                    if !ready!(poll_read_full(&mut self.conn, cx, &mut self.reply_msg, &mut self.reply_filled))? {
                        return Poll::Ready(Err(eof_error()));
                    }
                    return Poll::Ready(Err(io::Error::other(format!(
                        "server reported code: {}, message: {}",
                        self.reply_code,
                        String::from_utf8_lossy(&self.reply_msg)
                    ))));
                }
            }
        }
    }
}

impl AsyncRead for Snell {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_reply(cx))?;
        Pin::new(&mut this.conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for Snell {
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

impl NetConn for Snell {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.local_addr().map(|a| -> Box<dyn Addr> { Box::new(TcpAddr::from(a)) })
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.peer_addr().map(|a| -> Box<dyn Addr> { Box::new(TcpAddr::from(a)) })
    }

    fn close(&self) -> io::Result<()> {
        close_stream(&self.conn)
    }

    fn close_read(&self) -> io::Result<()> {
        match self.conn.old_conn() {
            Some(inner) => inner.close_read(),
            None => self.conn.shutdown_read(),
        }
    }

    fn close_write(&self) -> io::Result<()> {
        match self.conn.old_conn() {
            Some(inner) => inner.close_write(),
            None => self.conn.shutdown_write(),
        }
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.old_conn().map_or(Ok(()), |inner| inner.set_deadline(deadline))
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.old_conn().map_or(Ok(()), |inner| inner.set_read_deadline(deadline))
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.old_conn().map_or(Ok(()), |inner| inner.set_write_deadline(deadline))
    }
}

#[async_trait]
impl PacketFrameWriter for Snell {
    /// The write fallback.
    async fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.conn.write(b).await
    }

    async fn write_packet_frame(&mut self, b: &[u8]) -> io::Result<usize> {
        match &mut self.conn {
            SnellConn::V4(conn) => conn.write_packet_frame(b).await,
            SnellConn::Plain(conn) => conn.write(b).await,
        }
    }
}

pub async fn write_header<W>(conn: &mut W, host: &str, port: u32, version: i32) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    write_header_with_reuse(conn, host, port, version, false).await
}

pub async fn write_header_with_reuse<W>(
    conn: &mut W,
    host: &str,
    port: u32,
    version: i32,
    reuse: bool,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let host_len = u8::try_from(host.len()).map_err(|_| anyhow::anyhow!("snell host too long"))?;
    let port = u16::try_from(port).map_err(|_| anyhow::anyhow!("snell port out of range"))?;

    let mut buf = pool::get_buffer();
    buf.put_u8(VERSION);
    if version == VERSION2 || reuse {
        buf.put_u8(COMMAND_CONNECT_V2);
    } else {
        buf.put_u8(COMMAND_CONNECT);
    }

    // clientID length & id
    buf.put_u8(0);

    // host & port
    buf.put_u8(host_len);
    buf.put_slice(host.as_bytes());
    buf.put_u16(port);

    let result = conn.write_all(&buf).await;
    pool::put_buffer(buf);

    Ok(result?)
}

pub async fn write_udp_header<W>(conn: &mut W, version: i32) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if version < VERSION3 {
        return Err(anyhow::anyhow!("unsupport UDP version"));
    }

    // version, command, clientID length
    conn.write_all(&[VERSION, COMMAND_UDP, 0x00]).await?;
    conn.flush().await?;
    Ok(())
}

/// The end-of-stream frame written through `poll_write` directly.
///
/// `AsyncWriteExt::write`/`write_all` short-circuit a zero-length buffer and never poll the
/// writer, so the frame the blocking write produces has to be driven through `poll_write`,
/// as `pool.rs`'s close already does.
pub async fn write_zero_chunk<W>(conn: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    poll_fn(|cx| Pin::new(&mut *conn).poll_write(cx, END_SIGNAL).map(|result| result.map(|_| ()))).await
}

/// Half-closes the write side, taking the `&mut Snell` receiver.
pub async fn half_close(conn: &mut Snell) -> io::Result<()> {
    write_zero_chunk(&mut conn.conn).await?;
    conn.reply = false;
    Ok(())
}

#[must_use]
pub fn stream_conn(conn: Box<dyn NetConn>, psk: &[u8], version: i32) -> Snell {
    let conn: Box<dyn Stream> = Box::new(OldConnAsStream(conn));
    if version >= VERSION4 {
        return Snell::new(SnellConn::V4(Box::new(new_v4_conn(conn, psk))));
    }

    let cipher: Box<dyn shadowaead::cipher::Cipher> =
        if version == VERSION1 { new_chacha20poly1305(psk) } else { new_aes128gcm(psk) };
    Snell::new(SnellConn::Plain(Box::new(shadowaead::stream::new_conn(conn, cipher))))
}

#[must_use]
pub fn server_stream_conn(conn: Box<dyn NetConn>, psk: &[u8], version: i32) -> Snell {
    let mut stream = stream_conn(conn, psk, version);
    stream.reply = true;
    stream
}

#[must_use]
pub fn packet_conn(conn: PacketConnConn) -> Box<dyn NetPacketConn> {
    let local_addr = match &conn {
        PacketConnConn::Snell(conn) => conn.local_addr(),
        PacketConnConn::Plain(conn) => conn.local_addr(),
    }
    .ok()
    .and_then(|addr| murmur_std_compat::net::sock_addr_of(&*addr))
    .and_then(|addr| SocketAddr::try_from(&addr).ok());
    let (read, write) = match conn {
        PacketConnConn::Snell(snell) => snell.split(),
        PacketConnConn::Plain(conn) => {
            let stream: Box<dyn Stream> = Box::new(OldConnAsStream(conn));
            let (read, write) = tokio::io::split(stream);
            (SnellReadHalf::plain(read), SnellWriteHalf::plain(write))
        }
    };
    Box::new(PacketConn {
        read: tokio::sync::Mutex::new(read),
        write: Arc::new(tokio::sync::Mutex::new(write)),
        local_addr,
    })
}

async fn write_packet_datagram<W>(w: &mut W, socks5_addr: &[u8], payload: &[u8]) -> anyhow::Result<usize>
where
    W: PacketFrameWriter + ?Sized,
{
    let mut buf = pool::get_buffer();
    let result = async {
        // Compose the snell UDP address format, a different framing from the socks5 address
        // format.
        buf.put_u8(COMMOND_UDP_FORWARD);
        let Some(&atype) = socks5_addr.first() else {
            return Err(anyhow::anyhow!("snell UDP address invalid"));
        };
        match atype {
            socks5::ATYP_DOMAIN_NAME => {
                let Some(&host_len) = socks5_addr.get(1) else {
                    return Err(anyhow::anyhow!("snell UDP address invalid"));
                };
                let Some(addr) = socks5_addr.get(1..1 + 1 + usize::from(host_len) + 2) else {
                    return Err(anyhow::anyhow!("snell UDP address invalid"));
                };
                buf.put_slice(addr);
            }
            socks5::ATYP_IPV4 => {
                let Some(addr) = socks5_addr.get(1..1 + 4 + 2) else {
                    return Err(anyhow::anyhow!("snell UDP address invalid"));
                };
                buf.put_slice(&[0x00, 0x04]);
                buf.put_slice(addr);
            }
            socks5::ATYP_IPV6 => {
                let Some(addr) = socks5_addr.get(1..1 + 16 + 2) else {
                    return Err(anyhow::anyhow!("snell UDP address invalid"));
                };
                buf.put_slice(&[0x00, 0x06]);
                buf.put_slice(addr);
            }
            _ => return Err(anyhow::anyhow!("snell UDP address invalid")),
        }

        buf.put_slice(payload);
        w.write_packet_frame(&buf).await?;
        Ok(payload.len())
    }
    .await;
    pool::put_buffer(buf);
    result
}

pub async fn write_packet<W>(w: &mut W, socks5_addr: &[u8], payload: &[u8]) -> anyhow::Result<usize>
where
    W: PacketFrameWriter + ?Sized,
{
    let header_length = udp_request_header_length(socks5_addr);
    if header_length >= MAX_LENGTH {
        return Err(anyhow::anyhow!("snell UDP address too large"));
    }
    if payload.len() <= MAX_LENGTH - header_length {
        return write_packet_datagram(w, socks5_addr, payload).await;
    }
    Err(anyhow::anyhow!("snell UDP payload too large"))
}

pub async fn write_packet_response<W>(w: &mut W, addr: &dyn Addr, payload: &[u8]) -> anyhow::Result<usize>
where
    W: PacketFrameWriter + ?Sized,
{
    let mut buf = pool::get_buffer();
    let result = async {
        let Some(socks5_addr) = socks5::parse_addr_to_socks_addr(addr) else {
            return Err(anyhow::anyhow!("snell UDP response address invalid"));
        };
        let socks5_addr = socks5_addr.0;
        let Some(&atype) = socks5_addr.first() else {
            return Err(anyhow::anyhow!("snell UDP response address invalid"));
        };
        match atype {
            socks5::ATYP_IPV4 => {
                let Some(addr) = socks5_addr.get(1..1 + 4 + 2) else {
                    return Err(anyhow::anyhow!("snell UDP response address invalid"));
                };
                buf.put_u8(0x04);
                buf.put_slice(addr);
            }
            socks5::ATYP_IPV6 => {
                let Some(addr) = socks5_addr.get(1..1 + 16 + 2) else {
                    return Err(anyhow::anyhow!("snell UDP response address invalid"));
                };
                buf.put_u8(0x06);
                buf.put_slice(addr);
            }
            _ => return Err(anyhow::anyhow!("snell UDP response address invalid")),
        }
        buf.put_slice(payload);

        w.write_packet_frame(&buf).await?;
        Ok(payload.len())
    }
    .await;
    pool::put_buffer(buf);
    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UDPRequest {
    pub host: String,
    /// The IP address; `None` means unspecified.
    pub ip: Option<std::net::IpAddr>,
    pub port: u16,
    pub payload: Vec<u8>,
}

/// The two-byte big-endian port and the payload that follow the address at `offset`.
fn udp_port_and_payload(packet: &[u8], offset: usize, error: &str) -> anyhow::Result<(u16, Vec<u8>)> {
    let port = packet.get(offset..offset + 2).ok_or_else(|| anyhow::anyhow!("{error}"))?;
    let payload = packet.get(offset + 2..).ok_or_else(|| anyhow::anyhow!("{error}"))?;
    let port = u16::from_be_bytes(port.try_into().map_err(|_| anyhow::anyhow!("{error}"))?);
    Ok((port, payload.to_vec()))
}

pub fn parse_udp_request(packet: &[u8]) -> anyhow::Result<UDPRequest> {
    if packet.len() < 2 || packet.first() != Some(&COMMOND_UDP_FORWARD) {
        return Err(anyhow::anyhow!("snell invalid UDP request"));
    }
    let Some(&host_len) = packet.get(1) else {
        return Err(anyhow::anyhow!("snell invalid UDP request"));
    };
    let host_len = usize::from(host_len);
    if host_len != 0 {
        if packet.len() <= 2 + host_len + 2 {
            return Err(anyhow::anyhow!("snell invalid UDP domain request"));
        }
        let offset = 2 + host_len;
        let host = packet.get(2..offset).ok_or_else(|| anyhow::anyhow!("snell invalid UDP domain request"))?;
        let (port, payload) = udp_port_and_payload(packet, offset, "snell invalid UDP domain request")?;
        return Ok(UDPRequest { host: String::from_utf8_lossy(host).into_owned(), ip: None, port, payload });
    }
    if packet.len() < 3 {
        return Err(anyhow::anyhow!("snell invalid UDP IP request"));
    }
    let Some(&address_type) = packet.get(2) else {
        return Err(anyhow::anyhow!("snell invalid UDP IP request"));
    };
    match address_type {
        0x04 => {
            if packet.len() < 3 + 4 + 2 {
                return Err(anyhow::anyhow!("snell invalid UDP IPv4 request"));
            }
            let octets = packet
                .get(3..7)
                .and_then(|octets| octets.first_chunk::<4>())
                .ok_or_else(|| anyhow::anyhow!("snell invalid UDP IPv4 request"))?;
            let (port, payload) = udp_port_and_payload(packet, 7, "snell invalid UDP IPv4 request")?;
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(*octets));
            Ok(UDPRequest { host: String::new(), ip: Some(unmap_ip(ip)), port, payload })
        }
        0x06 => {
            if packet.len() < 3 + 16 + 2 {
                return Err(anyhow::anyhow!("snell invalid UDP IPv6 request"));
            }
            let octets = packet
                .get(3..19)
                .and_then(|octets| octets.first_chunk::<16>())
                .ok_or_else(|| anyhow::anyhow!("snell invalid UDP IPv6 request"))?;
            let (port, payload) = udp_port_and_payload(packet, 19, "snell invalid UDP IPv6 request")?;
            let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(*octets));
            Ok(UDPRequest { host: String::new(), ip: Some(unmap_ip(ip)), port, payload })
        }
        _ => Err(anyhow::anyhow!("snell invalid UDP address type")),
    }
}

const fn unmap_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => std::net::IpAddr::V6(v6),
        },
        v4 @ std::net::IpAddr::V4(_) => v4,
    }
}

#[must_use]
pub fn udp_request_header_length(socks5_addr: &[u8]) -> usize {
    let Some(&address_type) = socks5_addr.first() else {
        return MAX_LENGTH + 1;
    };
    match address_type {
        socks5::ATYP_DOMAIN_NAME => {
            let Some(&host_len) = socks5_addr.get(1) else {
                return MAX_LENGTH + 1;
            };
            1 + 1 + usize::from(host_len) + 2
        }
        socks5::ATYP_IPV4 => 1 + 2 + 4 + 2,
        socks5::ATYP_IPV6 => 1 + 2 + 16 + 2,
        _ => MAX_LENGTH + 1,
    }
}

pub async fn read_packet<R>(r: &mut R, payload: &mut [u8]) -> anyhow::Result<(Box<dyn Addr>, usize)>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buf = pool::get(pool::UDP_BUFFER_SIZE);
    let result = async {
        let mut head_len = 1usize;
        let n = tokio::io::AsyncReadExt::read(r, &mut buf[..]).await?;
        if n < head_len {
            return Err(anyhow::anyhow!("insufficient UDP length"));
        }

        // parse snell UDP response address format
        let mut err: Option<anyhow::Error> = None;
        match buf.first().copied() {
            Some(0x04) => {
                head_len += 4 + 2;
                if n < head_len {
                    err = Some(anyhow::anyhow!("insufficient UDP length"));
                } else if let Some(first) = buf.first_mut() {
                    *first = socks5::ATYP_IPV4;
                }
            }
            Some(0x06) => {
                head_len += 16 + 2;
                if n < head_len {
                    err = Some(anyhow::anyhow!("insufficient UDP length"));
                } else if let Some(first) = buf.first_mut() {
                    *first = socks5::ATYP_IPV6;
                }
            }
            _ => err = Some(anyhow::anyhow!("ip version invalid")),
        }

        if let Some(err) = err {
            return Err(err);
        }

        let Some(addr) = socks5::split_addr(&buf) else {
            return Err(anyhow::anyhow!("remote address invalid"));
        };
        let Some(u_addr) = addr.udp_addr() else {
            return Err(anyhow::anyhow!("parse addr error"));
        };

        let mut length = payload.len();
        if n - head_len < length {
            length = n - head_len;
        }
        let Some(target) = payload.get_mut(..length) else {
            return Err(anyhow::anyhow!("insufficient UDP length"));
        };
        let Some(source) = buf.get(head_len..head_len + length) else {
            return Err(anyhow::anyhow!("insufficient UDP length"));
        };
        target.copy_from_slice(source);

        let addr: Box<dyn Addr> = Box::new(u_addr);
        Ok((addr, length))
    }
    .await;
    let _ = pool::put(buf);
    result
}

impl Snell {
    /// Splits the session into independently pollable read and write halves. A packet conn needs
    /// both directions live at once: the tunnel parks a receive while the next datagram may be
    /// written, and one mutex around the whole session deadlocks that pattern.
    pub(crate) fn split(self) -> (SnellReadHalf, SnellWriteHalf) {
        let Self { conn, buffer, reply, reply_stage, reply_filled, reply_code, reply_msg } = self;
        let (read, write) = match conn {
            SnellConn::Plain(conn) => {
                let (read, write) = tokio::io::split(conn);
                (SnellReadConn::Plain(read), SnellWriteConn::Plain(write))
            }
            SnellConn::V4(conn) => {
                let (read, write) = conn.split();
                (SnellReadConn::V4(read), SnellWriteConn::V4(Box::new(write)))
            }
        };
        (
            SnellReadHalf { conn: read, buffer, reply, reply_stage, reply_filled, reply_code, reply_msg },
            SnellWriteHalf { conn: write },
        )
    }
}

pub(crate) enum SnellReadConn {
    Plain(tokio::io::ReadHalf<Box<dyn Stream>>),
    V4(V4ReadHalf),
}

impl AsyncRead for SnellReadConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(conn) => Pin::new(conn).poll_read(cx, buf),
            Self::V4(conn) => Pin::new(conn).poll_read(cx, buf),
        }
    }
}

pub(crate) enum SnellWriteConn {
    Plain(tokio::io::WriteHalf<Box<dyn Stream>>),
    V4(Box<V4WriteHalf>),
}

impl AsyncWrite for SnellWriteConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(conn) => Pin::new(conn).poll_write(cx, buf),
            Self::V4(conn) => Pin::new(conn.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(conn) => Pin::new(conn).poll_flush(cx),
            Self::V4(conn) => Pin::new(conn.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(conn) => Pin::new(conn).poll_shutdown(cx),
            Self::V4(conn) => Pin::new(conn.as_mut()).poll_shutdown(cx),
        }
    }
}

/// The read half of a Snell session, including the reply state the first read consumes.
pub(crate) struct SnellReadHalf {
    conn: SnellReadConn,
    buffer: [u8; 1],
    reply: bool,
    reply_stage: ReplyStage,
    reply_filled: usize,
    reply_code: u8,
    reply_msg: Vec<u8>,
}

impl SnellReadHalf {
    fn plain(conn: tokio::io::ReadHalf<Box<dyn Stream>>) -> Self {
        Self {
            conn: SnellReadConn::Plain(conn),
            buffer: [0],
            reply: true,
            reply_stage: ReplyStage::Head,
            reply_filled: 0,
            reply_code: 0,
            reply_msg: Vec::new(),
        }
    }

    fn poll_reply(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.reply {
            return Poll::Ready(Ok(()));
        }

        loop {
            match self.reply_stage {
                ReplyStage::Head => {
                    if !ready!(poll_read_full(&mut self.conn, cx, &mut self.buffer, &mut self.reply_filled))? {
                        return Poll::Ready(Err(eof_error()));
                    }
                    self.reply = true;
                    self.reply_filled = 0;

                    if self.buffer[0] == COMMAND_TUNNEL {
                        return Poll::Ready(Ok(()));
                    } else if self.buffer[0] != COMMAND_ERROR {
                        return Poll::Ready(Err(io::Error::other("command not support")));
                    }
                    self.reply_stage = ReplyStage::Code;
                }
                ReplyStage::Code => {
                    if !ready!(poll_read_full(&mut self.conn, cx, &mut self.buffer, &mut self.reply_filled))? {
                        return Poll::Ready(Err(eof_error()));
                    }
                    self.reply_code = self.buffer[0];
                    self.reply_filled = 0;
                    self.reply_stage = ReplyStage::Length;
                }
                ReplyStage::Length => {
                    if !ready!(poll_read_full(&mut self.conn, cx, &mut self.buffer, &mut self.reply_filled))? {
                        return Poll::Ready(Err(eof_error()));
                    }
                    let length = usize::from(self.buffer[0]);
                    self.reply_msg = vec![0u8; length];
                    self.reply_filled = 0;
                    self.reply_stage = ReplyStage::Message;
                }
                ReplyStage::Message => {
                    if !ready!(poll_read_full(&mut self.conn, cx, &mut self.reply_msg, &mut self.reply_filled))? {
                        return Poll::Ready(Err(eof_error()));
                    }
                    return Poll::Ready(Err(io::Error::other(format!(
                        "server reported code: {}, message: {}",
                        self.reply_code,
                        String::from_utf8_lossy(&self.reply_msg)
                    ))));
                }
            }
        }
    }
}

impl AsyncRead for SnellReadHalf {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_reply(cx))?;
        Pin::new(&mut this.conn).poll_read(cx, buf)
    }
}

/// The write half of a Snell session.
pub(crate) struct SnellWriteHalf {
    conn: SnellWriteConn,
}

impl SnellWriteHalf {
    fn plain(conn: tokio::io::WriteHalf<Box<dyn Stream>>) -> Self {
        Self { conn: SnellWriteConn::Plain(conn) }
    }
}

impl AsyncWrite for SnellWriteHalf {
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

#[async_trait]
impl PacketFrameWriter for SnellWriteHalf {
    async fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        AsyncWriteExt::write(self, b).await
    }

    async fn write_packet_frame(&mut self, b: &[u8]) -> io::Result<usize> {
        match &mut self.conn {
            SnellWriteConn::V4(conn) => conn.write_packet_frame(b).await,
            SnellWriteConn::Plain(conn) => AsyncWriteExt::write(conn, b).await,
        }
    }
}

/// The packet conn keeps its read and write halves behind separate locks; a parked receive must
/// not block the next datagram from being written.
pub struct PacketConn {
    read: tokio::sync::Mutex<SnellReadHalf>,
    write: Arc<tokio::sync::Mutex<SnellWriteHalf>>,
    local_addr: Option<SocketAddr>,
}

impl fmt::Debug for PacketConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketConn").finish_non_exhaustive()
    }
}

/// The packet conn's underlying conn; as with [`SnellConn`], a runtime check picks a variant.
pub enum PacketConnConn {
    Snell(Snell),
    Plain(Box<dyn NetConn>),
}

impl fmt::Debug for PacketConnConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Snell(conn) => f.debug_tuple("Snell").field(conn).finish(),
            Self::Plain(_) => f.debug_tuple("Plain").finish_non_exhaustive(),
        }
    }
}

impl AsyncRead for PacketConnConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Snell(conn) => Pin::new(conn).poll_read(cx, buf),
            Self::Plain(conn) => Pin::new(&mut **conn).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PacketConnConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Snell(conn) => Pin::new(conn).poll_write(cx, buf),
            Self::Plain(conn) => Pin::new(&mut **conn).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Snell(conn) => Pin::new(conn).poll_flush(cx),
            Self::Plain(conn) => Pin::new(&mut **conn).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Snell(conn) => Pin::new(conn).poll_shutdown(cx),
            Self::Plain(conn) => Pin::new(&mut **conn).poll_shutdown(cx),
        }
    }
}

#[async_trait]
impl PacketFrameWriter for PacketConnConn {
    async fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Self::Snell(conn) => AsyncWriteExt::write(conn, b).await,
            Self::Plain(conn) => AsyncWriteExt::write(conn, b).await,
        }
    }

    async fn write_packet_frame(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Self::Snell(conn) => conn.write_packet_frame(b).await,
            Self::Plain(conn) => conn.write(b).await,
        }
    }
}

#[async_trait]
impl NetPacketConn for PacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut read = self.read.lock().await;
        let (addr, n) = read_packet(&mut *read, buf).await.map_err(to_io_error)?;
        drop(read);
        Ok((n, addr))
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let socks5_addr = socks5::parse_addr_to_socks_addr(addr).map(|addr| addr.0).unwrap_or_default();
        let mut write = self.write.lock().await;
        write_packet(&mut *write, &socks5_addr, buf).await.map_err(to_io_error)
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.local_addr
            .map(|addr| -> Box<dyn Addr> { Box::new(TcpAddr::from(addr)) })
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "snell: packet conn has no local address"))
    }

    fn close(&self) -> io::Result<()> {
        // `PacketConn::close` is synchronous; shutdown runs on the runtime. The read half drops
        // with this value and the two halves release the stream once both are gone.
        let write = Arc::clone(&self.write);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let mut write = write.lock().await;
                let _ = AsyncWriteExt::shutdown(&mut *write).await;
                drop(write);
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, DuplexStream, ReadBuf};

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

    /// Pins the full header bytes (not just the command byte) to the documented wire format of a
    /// reuse-aware request. The argon2 KDF the
    /// encrypted v4 frame layer needs is out of scope here: this header is written in the clear
    /// before any AEAD wrapping applies.
    #[tokio::test]
    async fn write_header_with_reuse_wire_format() {
        let cases = [
            ("v1", VERSION1, false, "0101000b6578616d706c652e636f6d01bb"),
            ("v2", VERSION2, false, "0105000b6578616d706c652e636f6d01bb"),
            ("v3", VERSION3, false, "0101000b6578616d706c652e636f6d01bb"),
            ("v4 no reuse", VERSION4, false, "0101000b6578616d706c652e636f6d01bb"),
            ("v4 reuse", VERSION4, true, "0105000b6578616d706c652e636f6d01bb"),
        ];

        for (name, version, reuse, want_hex) in cases {
            let mut w = RecordingWriter::default();
            write_header_with_reuse(&mut w, "example.com", 443, version, reuse).await.expect(name);
            let want = hex::decode(want_hex).expect("valid hex vector");
            assert_eq!(w.buf, want, "{name}: header diverges from the snell.WriteHeaderWithReuse");
        }
    }

    /// `SnellConn::Plain` bridges the dialed old `Conn` through `OldConnAsStream` and a
    /// `shadowaead::stream::Conn`; `Snell::close` must still reach the dialed conn's own
    /// `close()` (mirrors `transport-simple-obfs`'s `close_reaches_the_dialed_conn`).
    struct FlagConn {
        inner: DuplexStream,
        closes: Arc<AtomicUsize>,
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

    impl NetConn for FlagConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)))
        }

        fn close(&self) -> io::Result<()> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn close_reaches_the_dialed_conn_aead() {
        let (_client, server) = tokio::io::duplex(64);
        let closes = Arc::new(AtomicUsize::new(0));
        let flag = FlagConn { inner: server, closes: Arc::clone(&closes) };
        let snell = stream_conn(Box::new(flag), b"password", VERSION1);

        snell.close().expect("close");

        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn close_reaches_the_dialed_conn_v4() {
        let (_client, server) = tokio::io::duplex(64);
        let closes = Arc::new(AtomicUsize::new(0));
        let flag = FlagConn { inner: server, closes: Arc::clone(&closes) };
        let snell = stream_conn(Box::new(flag), b"password", VERSION4);

        snell.close().expect("close");

        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }

    /// The half-close writes the end signal as a zero-length `Write`, which only becomes the
    /// end-of-stream frame once it reaches the framing layer; `write`/`write_all` short-circuit an
    /// empty buffer, so the peer waited for an end of stream that never arrived.
    #[tokio::test]
    async fn half_close_frames_the_end_signal_the_peer_waits_for() {
        for version in [VERSION1, VERSION4] {
            let (client_raw, server_raw) = tokio::io::duplex(64);
            let client = FlagConn { inner: client_raw, closes: Arc::new(AtomicUsize::new(0)) };
            let server = FlagConn { inner: server_raw, closes: Arc::new(AtomicUsize::new(0)) };
            let mut client = stream_conn(Box::new(client), b"password", version);
            let mut server = stream_conn(Box::new(server), b"password", version);

            let half_close = tokio::spawn(async move { half_close(&mut client).await });
            let read = tokio::time::timeout(Duration::from_secs(5), server.read(&mut [0u8; 1])).await;
            match read {
                Ok(Err(err)) if is_zero_chunk(&err) => {}
                other => panic!("v{version}: half close must end the stream with a zero-length frame, got {other:?}"),
            }
            assert!(half_close.await.expect("half close task").is_ok());
        }
    }
}

#[cfg(test)]
mod packet_conn_concurrency_tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    struct TestConn(tokio::io::DuplexStream);

    impl AsyncRead for TestConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestConn {
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

    impl NetConn for TestConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1)))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 2)))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x04, 127, 0, 0, 1];
        frame.extend_from_slice(&9u16.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// The tunnel's read loop re-enters `read_from` immediately after handing a response back. A
    /// packet conn that serializes both directions on one lock then holds that lock while waiting,
    /// so the next `write_to` can never deliver the request the response depends on.
    #[tokio::test]
    async fn a_pending_receive_does_not_block_the_next_send() {
        let (client, mut server) = tokio::io::duplex(128);
        let packet = packet_conn(PacketConnConn::Plain(Box::new(TestConn(client))));
        let address: Box<dyn Addr> = Box::new(TcpAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9));

        let reader = async {
            let mut buf = [0u8; 128];
            let (n, _) = packet.read_from(&mut buf).await.expect("first response");
            assert_eq!(&buf[..n], b"one-response");
            let (n, _) = packet.read_from(&mut buf).await.expect("second response");
            assert_eq!(&buf[..n], b"two-response");
        };
        let sender = async {
            packet.write_to(b"one", &*address).await.expect("first request");
            // Let the reader consume the first response and re-enter `read_from`.
            tokio::time::sleep(Duration::from_millis(100)).await;
            packet.write_to(b"two", &*address).await.expect("second request");
        };
        let server_task = async {
            let mut buf = [0u8; 256];
            let n = server.read(&mut buf).await.expect("first request");
            assert!(n > 0);
            server.write_all(&framed(b"one-response")).await.expect("first response");
            let n = server.read(&mut buf).await.expect("second request");
            assert!(n > 0);
            server.write_all(&framed(b"two-response")).await.expect("second response");
        };

        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(reader, sender, server_task);
        })
        .await
        .expect("a pending receive must not block the next send");
    }
}

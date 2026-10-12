//! DEVIATION: the vision conn walks the accepted stream's concrete type through reflection to
//! reach the underlying TLS conn.
//!
//! `vision::vision::TlsConnCheck::evaluate` needs the TLS conn as `&dyn Any` to do the same check
//! without reflection, but at this crate's generic `Service::new_connection` boundary the conn is
//! erased to `Box<dyn common_net::io::Stream>`.
//! `Stream::as_any` exists, but nothing between it and the accepted socket — `SharedConn`,
//! `CancellableStream` — forwards it, so `TlsConnCheck::Unsupported` is passed below and the
//! vision handshake always fails the same way it would for a non-TLS conn (`NEEDED SHIM ITEM:
//! as_any forwarding along the `SharedConn` chain).
//!
//! DEVIATION: the request context carries the resolved user so the additions can tag the inbound
//! with the in-user name. `listener::sing::context::SingContext` has the `user` field for exactly
//! this and `murmur_listener_sing::context::with_user` provides the setter (used by
//! `sing_vmess/server.rs`), but this file still skips the attachment: the resolved user is looked
//! up and flow-checked, only the context tagging is missing.
//!
//! DEVIATION: the packet-writer interface takes `buffer: &Buffer`, while the wire encoder mutates
//! the buffer in place (extending it with a two-byte header) before a single write.
//! [`ServerPacketConn::write_packet`] instead concatenates the length prefix
//! and payload into a scratch `Vec<u8>` and writes that frame as one unit; the bytes on the wire
//! are identical.

use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use uuid::Uuid;

use murmur_common::shared_conn::SharedConn;
use murmur_common::utils::uuid::uuid_map;
use murmur_common_net::io::{close_stream, CancellableStream, DeadlineToken, ExtendedStream, Stream};
use murmur_common_net::packet::packet_sing::udp_addr;
use murmur_common_net::sing::{new_extended_conn, ExtendedConn as CommonExtendedConn, UpstreamNode};
use murmur_compat::sing_buf::Buffer;
use murmur_component::dialer::tfo::NeedAdditionalReadDeadline;
use murmur_listener_sing::context::SingContext;
use murmur_listener_sing::sing::{ListenerHandler, SingMetadata};
use murmur_sing::metadata::Socksaddr;
use murmur_sing::network::{
    self, NetPacketReader, NetPacketWriter, PacketReadWaiter, PacketReader, PacketWriter, ReadWaitOptions, ReadWaitable,
};
use murmur_std_compat::net::{Addr, Conn as NetConn, TcpAddr};
use murmur_transport_vless::config_pb::Addons;
use murmur_transport_vless::vision::vision as vision_conn;
use murmur_transport_vless::vless;

/// The listener handler trait, combining the TCP and UDP connection handlers plus the exception
/// handler, not mirrored elsewhere in the crate.
#[async_trait]
pub trait Handler: Send + Sync {
    async fn new_connection(&self, ctx: SingContext, conn: Box<dyn Stream>, metadata: SingMetadata) -> Result<()>;

    async fn new_packet_connection(
        &self,
        ctx: SingContext,
        conn: Box<dyn network::PacketConn>,
        metadata: SingMetadata,
    ) -> Result<()>;

    fn new_error(&self, ctx: &SingContext, err: &anyhow::Error);
}

/// `listener::sing::sing::new_listener_handler` builds exactly this shape (the implicit interface
/// satisfaction).
#[async_trait]
impl Handler for ListenerHandler {
    async fn new_connection(&self, ctx: SingContext, conn: Box<dyn Stream>, metadata: SingMetadata) -> Result<()> {
        Self::new_connection(self, ctx, conn, metadata).await
    }

    async fn new_packet_connection(
        &self,
        ctx: SingContext,
        conn: Box<dyn network::PacketConn>,
        metadata: SingMetadata,
    ) -> Result<()> {
        Self::new_packet_connection(self, ctx, conn, metadata).await
    }

    fn new_error(&self, ctx: &SingContext, err: &anyhow::Error) {
        Self::new_error(self, ctx, err);
    }
}

pub struct Service<T> {
    user_map: std::collections::HashMap<[u8; 16], T>,
    user_flow: std::collections::HashMap<T, String>,
    handler: Arc<dyn Handler>,
}

/// Redacts the user identifiers the maps are keyed by, reporting only how many are configured.
impl<T> core::fmt::Debug for Service<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Service")
            .field("users", &self.user_map.len())
            .field("flows", &self.user_flow.len())
            .finish_non_exhaustive()
    }
}

impl<T> Service<T> {
    pub fn new(handler: Arc<dyn Handler>) -> Self {
        Self { user_map: std::collections::HashMap::new(), user_flow: std::collections::HashMap::new(), handler }
    }
}

impl<T> Service<T>
where
    T: Eq + std::hash::Hash + Clone + Send + Sync + 'static,
{
    pub fn update_users(&mut self, user_list: &[T], user_uuid_list: &[String], user_flow_list: &[String]) {
        let mut user_map = std::collections::HashMap::new();
        let mut user_flow_map = std::collections::HashMap::new();
        for ((user_name, user_uuid), user_flow) in user_list.iter().zip(user_uuid_list).zip(user_flow_list) {
            let user_id = uuid_map(user_uuid).into_bytes();
            user_map.insert(user_id, user_name.clone());
            user_flow_map.insert(user_name.clone(), user_flow.clone());
        }
        self.user_map = user_map;
        self.user_flow = user_flow_map;
    }

    pub async fn new_connection(
        &self,
        ctx: SingContext,
        mut conn: Box<dyn Stream>,
        mut metadata: SingMetadata,
    ) -> Result<()> {
        let version = conn.read_u8().await?;
        if version != vless::VERSION {
            return Err(anyhow!("unknown version: {version}"));
        }

        let mut request_uuid = [0u8; 16];
        conn.read_exact(&mut request_uuid).await?;

        let addons_len = conn.read_u8().await?;
        let addons = if addons_len > 0 {
            let mut addons_bytes = vec![0u8; addons_len as usize];
            conn.read_exact(&mut addons_bytes).await?;
            Addons::decode(&addons_bytes[..])?
        } else {
            Addons::default()
        };

        let command = conn.read_u8().await?;

        let destination =
            if command == vless::COMMAND_MUX { Socksaddr::default() } else { read_addr_port(&mut *conn).await? };

        let Some(user) = self.user_map.get(&request_uuid).cloned() else {
            return Err(anyhow!("unknown UUID: {}", Uuid::from_bytes(request_uuid)));
        };
        metadata.destination = destination.clone();

        let user_flow = self.user_flow.get(&user).cloned().unwrap_or_default();
        let request_flow = addons.flow.clone();
        if request_flow != user_flow && !request_flow.is_empty() {
            return Err(anyhow!(
                "flow mismatch: expected {}, but got {}",
                flow_name(&user_flow),
                flow_name(&request_flow)
            ));
        }

        let response_conn = ServerConn::new(new_extended_conn(conn));

        let dispatch_conn = match request_flow.as_str() {
            vless::XRV => {
                let shared = SharedConn::new(CancellableStream::new(response_conn));
                let vision = vision_conn::new_conn(
                    shared,
                    vision_conn::TlsConnCheck::Unsupported,
                    None,
                    None,
                    Uuid::from_bytes(request_uuid),
                )
                .map_err(|err| anyhow!("initialize vision: {err}"))?;
                DispatchConn::Vision(vision)
            }
            "" => DispatchConn::Plain(response_conn),
            other => return Err(anyhow!("unknown flow: {other}")),
        };

        match command {
            vless::COMMAND_TCP => self.handler.new_connection(ctx, dispatch_conn.into_stream(), metadata).await,
            vless::COMMAND_UDP => {
                if request_flow == vless::XRV {
                    return Err(anyhow!("{} flow does not support UDP", vless::XRV));
                }
                let DispatchConn::Plain(response_conn) = dispatch_conn else {
                    return Err(anyhow!("{} flow does not support UDP", vless::XRV));
                };
                let packet_conn = ServerPacketConn::new(Box::new(response_conn), destination);
                self.handler.new_packet_connection(ctx, Box::new(packet_conn), metadata).await
            }
            vless::COMMAND_MUX => handle_mux_connection(dispatch_conn.into_stream(), &metadata),
            other => Err(anyhow!("unknown command: {other}")),
        }
    }
}

/// The result of applying the request flow to `responseConn`, kept concrete until the command
/// switch decides whether it is handed off as a plain conn (`ServerPacketConn` also needs the
/// concrete [`ServerConn`] to reuse its "response header written once" state) or boxed as
/// `Box<dyn Stream>`.
#[expect(
    clippy::large_enum_variant,
    reason = "Vision inlines the full XTLS filter/read-state machine while Plain wraps an extended conn, so the size gap is the real state difference"
)]
enum DispatchConn {
    Plain(ServerConn),
    Vision(murmur_transport_vless::vision::conn::Conn),
}

impl DispatchConn {
    fn into_stream(self) -> Box<dyn Stream> {
        match self {
            Self::Plain(conn) => Box::new(conn),
            Self::Vision(conn) => Box::new(conn),
        }
    }
}

/// The mux-connection handler, standing in for the sing-vmess mux; see
/// `listener::sing::sing::handle_vmess_mux_connection` for the identical unimplemented dependency.
fn handle_mux_connection(_conn: Box<dyn Stream>, _metadata: &SingMetadata) -> Result<()> {
    Err(anyhow!("sing-vmess mux protocol not implemented (NEEDED CRATE: sing-vmess)"))
}

const fn flow_name(value: &str) -> &str {
    if value.is_empty() {
        "none"
    } else {
        value
    }
}

/// The address-and-port reader, not mirrored elsewhere in the crate. The wire format is fixed by
/// the serializer's family bytes and port-then-address order: port first, then the family byte,
/// then the address, so it is implemented locally (`NEEDED SHIM ITEM:
/// murmur_sing::metadata::Serializer::read_addr_port`).
async fn read_addr_port(conn: &mut dyn Stream) -> Result<Socksaddr> {
    let port = conn.read_u16().await?;
    let family = conn.read_u8().await?;
    match family {
        0x01 => {
            let mut addr = [0u8; 4];
            conn.read_exact(&mut addr).await?;
            Ok(Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::from(addr)), port))
        }
        0x03 => {
            let mut addr = [0u8; 16];
            conn.read_exact(&mut addr).await?;
            Ok(Socksaddr::from_ip(IpAddr::V6(Ipv6Addr::from(addr)), port))
        }
        0x02 => {
            let len = conn.read_u8().await?;
            let mut fqdn = vec![0u8; len as usize];
            conn.read_exact(&mut fqdn).await?;
            Ok(Socksaddr::fqdn(String::from_utf8_lossy(&fqdn).into_owned(), port))
        }
        other => Err(anyhow!("unknown address family: {other}")),
    }
}

pub struct ServerConn {
    extended_conn: Box<dyn CommonExtendedConn>,
    response_written: bool,
    write_pending: Option<Vec<u8>>,
}

/// The wrapped conn is not printable, so it is skipped and only the response state is reported.
impl core::fmt::Debug for ServerConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerConn")
            .field("response_written", &self.response_written)
            .field("write_pending", &self.write_pending.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

impl ServerConn {
    fn new(extended_conn: Box<dyn CommonExtendedConn>) -> Self {
        Self { extended_conn, response_written: false, write_pending: None }
    }

    /// The buffered-response half of the server conn's write path.
    fn poll_write_response(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.write_pending.is_none() {
            let mut data = Vec::with_capacity(2 + buf.len());
            data.push(vless::VERSION);
            data.push(0);
            data.extend_from_slice(buf);
            self.write_pending = Some(data);
        }
        let Some(data) = self.write_pending.as_deref() else {
            return Poll::Ready(Err(io::Error::other("vless: response header buffer missing")));
        };
        let result = match Pin::new(&mut self.extended_conn).poll_write(cx, data) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };
        self.write_pending = None;
        result
    }
}

impl AsyncRead for ServerConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().extended_conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for ServerConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.response_written {
            let result = this.poll_write_response(cx, buf);
            if let Poll::Ready(Ok(_)) = &result {
                this.response_written = true;
            }
            return result;
        }
        Pin::new(&mut this.extended_conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().extended_conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().extended_conn).poll_shutdown(cx)
    }
}

impl Stream for ServerConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.extended_conn.local_addr()
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.extended_conn.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.extended_conn.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.extended_conn.shutdown_write()
    }
    fn old_conn(&self) -> Option<&dyn NetConn> {
        self.extended_conn.old_conn()
    }

    fn need_additional_read_deadline(&self) -> bool {
        true
    }
}

impl ExtendedStream for ServerConn {
    fn reader_replaceable(&self) -> bool {
        true
    }
    fn writer_replaceable(&self) -> bool {
        self.response_written
    }
}

impl UpstreamNode for ServerConn {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&*self.extended_conn)
    }

    fn reader_replaceable(&self) -> Option<bool> {
        Some(true)
    }

    fn writer_replaceable(&self) -> Option<bool> {
        Some(self.response_written)
    }

    fn front_headroom(&self) -> Option<i32> {
        Some(if self.response_written { 0 } else { 2 })
    }
}

#[async_trait]
impl CommonExtendedConn for ServerConn {
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        self.extended_conn.read_buffer(buffer).await
    }

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        if !self.response_written {
            let [version, reserved] = buffer.extend_header(2) else {
                return Err(io::Error::other("vless: reserved response header is not two bytes"));
            };
            *version = vless::VERSION;
            *reserved = 0;
            self.response_written = true;
        }
        self.extended_conn.write_buffer(buffer).await
    }
}

impl NeedAdditionalReadDeadline for ServerConn {
    fn need_additional_read_deadline(&self) -> bool {
        true
    }
}

/// DEVIATION: an extended conn would promote
/// `Read`/`Write`/`LocalAddr`/`SetDeadline` onto the struct.
///
/// Nothing in this crate's `network::PacketConn` pipeline (the surface
/// `Handler::new_packet_connection` actually needs) ever calls that byte-stream half of a
/// packet-mode conn, so it is not exposed; only the packet-oriented surface below is. The wrapped
/// conn needs `&mut` access from `&self`-receiver trait methods (sing interfaces carry no
/// mutability), so it is shared behind an `Arc<parking_lot::Mutex>`.
///
/// The guard is taken per poll and dropped before the task can suspend, never held for the whole
/// network wait (the discipline `common::shared_conn::SharedConn` and
/// `snell::server::read_udp_datagram` follow). Holding it across the read would let a reader parked
/// on the next client datagram starve the upstream response write, `close` and the read-deadline
/// update that all need the one conn — the stall this lock discipline exists to avoid.
pub struct ServerPacketConn {
    extended_conn: Arc<parking_lot::Mutex<Box<dyn CommonExtendedConn>>>,
    destination: Socksaddr,
    read_wait_options: parking_lot::Mutex<ReadWaitOptions>,
    /// The read/write deadlines this type enforces itself.
    ///
    /// The wrapped conn is an `ExtendedConnWrapper`, whose `old_conn` is `None`, so forwarding a
    /// deadline to it alone would be a no-op; racing the token on every poll is what makes a
    /// deadline that arrives while a read is already parked still end that read.
    read_deadline: DeadlineToken,
    write_deadline: DeadlineToken,
}

/// The mutex-held conn is not printable, so it is skipped and only the destination is reported.
impl core::fmt::Debug for ServerPacketConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerPacketConn").field("destination", &self.destination).finish_non_exhaustive()
    }
}

/// The error `Buffer::read_full_from` reports when a frame does not fit the packet buffer, matching
/// the allocator's own `short_buffer`.
fn short_buffer() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "short buffer")
}

/// The error the byte-stream readers report when a frame ends before its declared length and no
/// byte was read, matching `Buffer::read_full_from`'s empty read.
fn unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

/// The error an expired read/write deadline reports, matching
/// `murmur_common_net::deadline::conn::err_deadline_exceeded`.
fn deadline_exceeded() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

/// Reads exactly `buf.len()` bytes from the shared conn, taking the lock fresh for each poll and
/// dropping it before returning `Pending`, so a parked read never holds the conn a concurrent
/// write, `close` or deadline update needs.
///
/// The read is raced against `deadline`, so a deadline armed after this read parked still ends it.
///
/// NOT cancel-safe: `filled` is local to this call, so a drop mid-read loses the offset.
async fn read_bytes_exact(
    conn: &parking_lot::Mutex<Box<dyn CommonExtendedConn>>,
    buf: &mut [u8],
    deadline: &DeadlineToken,
) -> io::Result<()> {
    let token = deadline.token();
    tokio::select! {
        result = read_bytes_poll(conn, buf) => result,
        () = token.cancelled() => Err(deadline_exceeded()),
    }
}

/// The poll half of [`read_bytes_exact`], without the deadline race.
async fn read_bytes_poll(conn: &parking_lot::Mutex<Box<dyn CommonExtendedConn>>, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    poll_fn(|cx| {
        while filled < buf.len() {
            let mut guard = conn.lock();
            let Some(rest) = buf.get_mut(filled..) else {
                return Poll::Ready(Err(short_buffer()));
            };
            let mut read_buf = ReadBuf::new(rest);
            match Pin::new(&mut *guard).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(unexpected_eof()));
                    }
                    filled += n;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    })
    .await
}

/// Reads exactly `size` more bytes into `buffer`'s free space.
///
/// NOT cancel-safe: `truncate` commits only after the whole block, so a drop mid-read loses bytes.
async fn read_frame_exact(
    conn: &parking_lot::Mutex<Box<dyn CommonExtendedConn>>,
    buffer: &mut Buffer,
    size: usize,
    deadline: &DeadlineToken,
) -> io::Result<()> {
    if buffer.free_len() < size {
        return Err(short_buffer());
    }
    let Some(free) = buffer.free_bytes().get_mut(..size) else {
        return Err(short_buffer());
    };
    read_bytes_exact(conn, free, deadline).await?;
    buffer.truncate(size);
    Ok(())
}

/// Writes one length-prefixed frame, taking the conn lock fresh for each poll so a concurrently
/// parked read does not hold it. Prefix and payload stay one `framed` unit, so a frame cannot
/// interleave into another frame's payload.
///
/// The write is raced against `deadline`, so a deadline armed after this write parked still ends
/// it. NOT cancel-safe: `written` is local to this call.
async fn write_frame(
    conn: &parking_lot::Mutex<Box<dyn CommonExtendedConn>>,
    framed: &[u8],
    deadline: &DeadlineToken,
) -> io::Result<()> {
    let token = deadline.token();
    tokio::select! {
        result = write_frame_poll(conn, framed) => result,
        () = token.cancelled() => Err(deadline_exceeded()),
    }
}

/// The poll half of [`write_frame`], without the deadline race.
async fn write_frame_poll(conn: &parking_lot::Mutex<Box<dyn CommonExtendedConn>>, framed: &[u8]) -> io::Result<()> {
    let mut written = 0;
    poll_fn(|cx| {
        while written < framed.len() {
            let Some(rest) = framed.get(written..) else {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            };
            let mut guard = conn.lock();
            match Pin::new(&mut *guard).poll_write(cx, rest) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => written += n,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    })
    .await
}

/// Reads the `u16` big-endian length prefix of the next frame.
async fn read_packet_len(
    conn: &parking_lot::Mutex<Box<dyn CommonExtendedConn>>,
    deadline: &DeadlineToken,
) -> io::Result<usize> {
    let mut len = [0u8; 2];
    read_bytes_exact(conn, &mut len, deadline).await?;
    Ok(u16::from_be_bytes(len) as usize)
}

impl ServerPacketConn {
    fn new(extended_conn: Box<dyn CommonExtendedConn>, destination: Socksaddr) -> Self {
        Self {
            extended_conn: Arc::new(parking_lot::Mutex::new(extended_conn)),
            destination,
            read_wait_options: parking_lot::Mutex::new(ReadWaitOptions::default()),
            read_deadline: DeadlineToken::new(),
            write_deadline: DeadlineToken::new(),
        }
    }
}

impl ReadWaitable for ServerPacketConn {
    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        *self.read_wait_options.lock() = options;
        false
    }
}

#[async_trait]
impl PacketReadWaiter for ServerPacketConn {
    async fn wait_read_packet(&self) -> io::Result<(Buffer, Socksaddr)> {
        let options = *self.read_wait_options.lock();
        let packet_len = read_packet_len(&self.extended_conn, &self.read_deadline).await?;

        let mut buffer = options.new_packet_buffer();
        if let Err(err) = read_frame_exact(&self.extended_conn, &mut buffer, packet_len, &self.read_deadline).await {
            buffer.release();
            return Err(err);
        }
        options.post_return(&mut buffer);

        Ok((buffer, self.destination.clone()))
    }
}

#[async_trait]
impl PacketReader for ServerPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        let packet_len = read_packet_len(&self.extended_conn, &self.read_deadline).await?;
        read_frame_exact(&self.extended_conn, buffer, packet_len, &self.read_deadline).await?;
        Ok(self.destination.clone())
    }
}

#[async_trait]
impl NetPacketReader for ServerPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let packet_len = read_packet_len(&self.extended_conn, &self.read_deadline).await?;
        let Some(dst) = p.get_mut(..packet_len) else {
            return Err(io::Error::other("short buffer"));
        };
        read_bytes_exact(&self.extended_conn, dst, &self.read_deadline).await?;

        let addr: Box<dyn Addr> = if self.destination.is_fqdn() {
            Box::new(self.destination.clone())
        } else {
            Box::new(udp_addr(&self.destination))
        };
        Ok((packet_len, addr))
    }
}

#[async_trait]
impl PacketWriter for ServerPacketConn {
    /// The packet-write path; see the module doc for the buffer-mutation
    /// deviation.
    async fn write_packet(&self, buffer: &Buffer, _destination: &Socksaddr) -> io::Result<()> {
        let Ok(len) = u16::try_from(buffer.len()) else {
            return Err(io::Error::other("vless: packet exceeds the u16 length prefix"));
        };
        let mut framed = Vec::with_capacity(2 + buffer.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(buffer.bytes());
        write_frame(&self.extended_conn, &framed, &self.write_deadline).await
    }
}

#[async_trait]
impl NetPacketWriter for ServerPacketConn {
    async fn write_to(&self, p: &[u8], _addr: &dyn Addr) -> io::Result<usize> {
        let Ok(len) = u16::try_from(p.len()) else {
            return Err(io::Error::other("vless: packet exceeds the u16 length prefix"));
        };
        let mut framed = Vec::with_capacity(2 + p.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(p);
        write_frame(&self.extended_conn, &framed, &self.write_deadline).await?;
        Ok(p.len())
    }
}

#[async_trait]
impl network::PacketConn for ServerPacketConn {
    async fn close(&self) -> io::Result<()> {
        close_stream(&**self.extended_conn.lock())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.extended_conn.lock().local_addr()?)))
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.read_deadline.set(deadline);
        self.extended_conn.lock().old_conn().map_or(Ok(()), |inner| inner.set_read_deadline(deadline))
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.write_deadline.set(deadline);
        self.extended_conn.lock().old_conn().map_or(Ok(()), |inner| inner.set_write_deadline(deadline))
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.read_deadline.set(deadline);
        self.write_deadline.set(deadline);
        self.extended_conn.lock().old_conn().map_or(Ok(()), |inner| inner.set_deadline(deadline))
    }
}

impl NeedAdditionalReadDeadline for ServerPacketConn {
    fn need_additional_read_deadline(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::Instant;

    use murmur_common_net::sing::new_deadline_conn;
    use murmur_sing::network::PacketConn as _;

    use super::*;

    /// A real TCP pair whose server half is the conn the packet conn wraps, so a read parked on
    /// the client's silence is the same `Pending` a live VLESS UDP session reaches. The deadline
    /// layer is the one a real accepted stream carries, so `set_read_deadline` reaches the conn
    /// that races the parked read.
    async fn packet_conn_carrying() -> (ServerPacketConn, tokio::net::TcpStream) {
        let listener =
            tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("an ephemeral port is free");
        let addr = listener.local_addr().expect("the probe is bound");
        let client = tokio::net::TcpStream::connect(addr).await.expect("the client connects");
        let (server, _) = listener.accept().await.expect("the probe accepts");
        let conn = ServerPacketConn::new(new_deadline_conn(server), Socksaddr::default());
        (conn, client)
    }

    /// A parked read that holds the duplex lock is the reported stall: the upstream response
    /// write never reaches the peer the client is waiting on.
    #[tokio::test]
    async fn a_parked_read_does_not_block_a_concurrent_write_to_the_peer() {
        let (conn, mut client) = packet_conn_carrying().await;
        let conn = Arc::new(conn);

        let reader = tokio::spawn({
            let conn = Arc::clone(&conn);
            async move { conn.read_packet(&mut Buffer::default()).await }
        });
        // Let the reader reach its read and park there.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        let written =
            tokio::time::timeout(Duration::from_millis(300), conn.write_to(b"response", &udp_addr(&conn.destination)))
                .await
                .expect("write_to must not wait for the parked read");
        written.expect("the response is written");

        let mut framed = [0u8; 10];
        client.read_exact(&mut framed).await.expect("the peer receives the complete frame");
        assert_eq!(framed, [0x00, 0x08, b'r', b'e', b's', b'p', b'o', b'n', b's', b'e']);

        reader.abort();
        let _ = reader.await;
    }

    /// `close` waits for the same mutex today, so it cannot end a read already parked on it.
    #[tokio::test]
    async fn close_ends_a_parked_read() {
        let (conn, _client) = packet_conn_carrying().await;
        let conn = Arc::new(conn);

        let reader = tokio::spawn({
            let conn = Arc::clone(&conn);
            async move { conn.read_packet(&mut Buffer::default()).await }
        });
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        tokio::time::timeout(Duration::from_millis(300), conn.close())
            .await
            .expect("close must not wait for the parked read")
            .expect("close succeeds");

        let ended = tokio::time::timeout(Duration::from_millis(300), reader)
            .await
            .expect("the parked read ends once the conn is closed");
        assert!(ended.is_ok(), "a closed conn's read returns, it does not panic");
    }

    /// The read-deadline setter used to report success while silently skipping the update whenever
    /// the conn was busy, so a deadline that arrived while a read was parked never reached that
    /// read.
    #[tokio::test]
    async fn a_read_deadline_update_ends_the_parked_read() {
        let (conn, _client) = packet_conn_carrying().await;
        let conn = Arc::new(conn);

        let reader = tokio::spawn({
            let conn = Arc::clone(&conn);
            async move { conn.read_packet(&mut Buffer::default()).await }
        });
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        conn.set_read_deadline(Some(Instant::now() + Duration::from_millis(50)))
            .expect("the read deadline is accepted while the read is parked");

        let ended = tokio::time::timeout(Duration::from_millis(400), reader)
            .await
            .expect("the deadline must terminate the parked read");
        let err = ended.expect("the read task does not panic").expect_err("the deadline ends the read");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    async fn conn_carrying(frame: &[u8]) -> (Box<dyn Stream>, tokio::net::TcpStream) {
        let listener =
            tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("an ephemeral port is free");
        let addr = listener.local_addr().expect("the probe is bound");
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("the client connects");
        let (server, _) = listener.accept().await.expect("the probe accepts");
        client.write_all(frame).await.expect("the frame is written");
        (Box::new(server), client)
    }

    /// The frame is the wire port, then the family byte; every other reader of this field in the
    /// tree refuses a family it does not define, so an unknown one must not become a destination.
    #[tokio::test]
    async fn an_unknown_address_family_is_refused_instead_of_becoming_an_empty_destination() {
        let (mut server, _client) = conn_carrying(&[0x00, 0x50, 0x09]).await;

        let err = read_addr_port(&mut *server).await.expect_err("family 0x09 names no address family");

        assert_eq!(err.to_string(), "unknown address family: 9");
    }

    #[tokio::test]
    async fn the_defined_address_families_still_parse_with_the_port_the_frame_carries() {
        let (mut server, _client) = conn_carrying(&[0x01, 0xbb, 0x01, 127, 0, 0, 1]).await;
        assert_eq!(
            read_addr_port(&mut *server).await.expect("0x01 is ipv4"),
            Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)
        );

        let (mut server, _client) = conn_carrying(&[0x00, 0x35, 0x02, 3, b'a', b'.', b'b']).await;
        assert_eq!(read_addr_port(&mut *server).await.expect("0x02 is fqdn"), Socksaddr::fqdn("a.b", 53));

        let (mut server, _client) =
            conn_carrying(&[0x00, 0x35, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).await;
        assert_eq!(
            read_addr_port(&mut *server).await.expect("0x03 is ipv6"),
            Socksaddr::from_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 53)
        );
    }
}

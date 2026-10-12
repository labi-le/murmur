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
//! and payload into a scratch `Vec<u8>` and issues one `write_all`; the bytes on the wire are
//! identical.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use uuid::Uuid;

use murmur_common::shared_conn::SharedConn;
use murmur_common::utils::uuid::uuid_map;
use murmur_common_net::io::{close_stream, CancellableStream, ExtendedStream, Stream};
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

/// The response header prepended to the first application write: the version byte, then the
/// reserved/addon-length byte.
const RESPONSE_HEADER: [u8; 2] = [vless::VERSION, 0];

pub struct ServerConn {
    extended_conn: Box<dyn CommonExtendedConn>,
    response_written: bool,
    /// How many of the fixed header bytes have reached the wire. Only the header is ever retained,
    /// so no application byte outlives the call that supplied it.
    response_sent: usize,
}

/// The wrapped conn is not printable, so it is skipped and only the response state is reported.
impl core::fmt::Debug for ServerConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerConn")
            .field("response_written", &self.response_written)
            .field("response_sent", &self.response_sent)
            .finish_non_exhaustive()
    }
}

impl ServerConn {
    fn new(extended_conn: Box<dyn CommonExtendedConn>) -> Self {
        Self { extended_conn, response_written: false, response_sent: 0 }
    }

    /// The buffered-response half of the server conn's write path.
    ///
    /// One `poll_write` on the wrapped conn may accept only part of what it is handed — a socket
    /// whose send buffer has little room, a `tokio::io::duplex` carrier capped at its channel
    /// capacity — so the fixed header is resumed from `response_sent` across polls. Only the header
    /// is buffered: the payload is written from the caller's own `buf` once the header is on the
    /// wire, so a `Pending` never retains application bytes from a call the caller may abandon, and
    /// a resumed write reports bytes of the buffer it was actually handed. The offset is wire
    /// state, not call state: it survives a failed poll, so a retry after a cleared write deadline
    /// resumes the header instead of repeating the bytes already sent.
    fn poll_write_response(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        while self.response_sent < RESPONSE_HEADER.len() {
            let (_, unsent) = RESPONSE_HEADER.split_at(self.response_sent);
            match Pin::new(&mut self.extended_conn).poll_write(cx, unsent) {
                // The offset is the wire's own progress and outlives a failed poll: a caller that
                // clears a fired write deadline and writes again must resume the header, not repeat
                // the bytes already on the wire.
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "vless: response write zero")));
                }
                Poll::Ready(Ok(sent)) => self.response_sent += sent,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.response_sent = 0;
        self.response_written = true;
        Pin::new(&mut self.extended_conn).poll_write(cx, buf)
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
            // The header transition is owned by `poll_write_response`, which sets
            // `response_written` once the header is on the wire.
            return this.poll_write_response(cx, buf);
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
/// mutability), so it is held behind a `tokio::sync::Mutex`, mirroring
/// `listener::sing::sing::UotConn`.
pub struct ServerPacketConn {
    extended_conn: tokio::sync::Mutex<Box<dyn CommonExtendedConn>>,
    destination: Socksaddr,
    read_wait_options: parking_lot::Mutex<ReadWaitOptions>,
}

/// The mutex-held conn is not printable, so it is skipped and only the destination is reported.
impl core::fmt::Debug for ServerPacketConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerPacketConn").field("destination", &self.destination).finish_non_exhaustive()
    }
}

impl ServerPacketConn {
    fn new(extended_conn: Box<dyn CommonExtendedConn>, destination: Socksaddr) -> Self {
        Self {
            extended_conn: tokio::sync::Mutex::new(extended_conn),
            destination,
            read_wait_options: parking_lot::Mutex::new(ReadWaitOptions::default()),
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
        let mut conn = self.extended_conn.lock().await;
        let mut packet_len = [0u8; 2];
        conn.read_exact(&mut packet_len).await?;
        let packet_len = u16::from_be_bytes(packet_len) as usize;

        let mut buffer = options.new_packet_buffer();
        if let Err(err) = buffer.read_full_from(&mut *conn, packet_len).await {
            buffer.release();
            return Err(err);
        }
        drop(conn);
        options.post_return(&mut buffer);

        Ok((buffer, self.destination.clone()))
    }
}

#[async_trait]
impl PacketReader for ServerPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        let mut conn = self.extended_conn.lock().await;
        let mut packet_len = [0u8; 2];
        conn.read_exact(&mut packet_len).await?;
        let packet_len = u16::from_be_bytes(packet_len) as usize;
        buffer.read_full_from(&mut *conn, packet_len).await?;
        drop(conn);
        Ok(self.destination.clone())
    }
}

/// Reads and drops `len` payload bytes the caller's slice could not hold. The length prefix is
/// already off the stream when a read rejects a datagram, so the payload has to leave it too;
/// otherwise the next read decodes payload bytes as a length prefix. A conn that breaks mid-drain
/// reports its own error rather than the short-buffer one, which would look recoverable on a
/// stream that is gone.
// NOT cancel-safe: a dropped drain has already taken part of the rejected datagram off the stream,
// so the stream stays mid-frame and a caller that cancels the read must tear the connection down
// rather than read again.
async fn discard_payload<R>(conn: &mut R, len: usize) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut scratch = [0u8; 512];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(scratch.len());
        let Some(dst) = scratch.get_mut(..chunk) else {
            return Err(io::Error::other("vless: discard window exceeds the scratch block"));
        };
        conn.read_exact(dst).await?;
        remaining -= chunk;
    }
    Ok(())
}

#[async_trait]
impl NetPacketReader for ServerPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut conn = self.extended_conn.lock().await;
        let mut packet_len = [0u8; 2];
        conn.read_exact(&mut packet_len).await?;
        let packet_len = u16::from_be_bytes(packet_len) as usize;
        let Some(dst) = p.get_mut(..packet_len) else {
            discard_payload(&mut *conn, packet_len).await?;
            return Err(io::Error::other("short buffer"));
        };
        conn.read_exact(dst).await?;
        drop(conn);

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
        let mut conn = self.extended_conn.lock().await;
        let mut framed = Vec::with_capacity(2 + buffer.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(buffer.bytes());
        conn.write_all(&framed).await
    }
}

#[async_trait]
impl NetPacketWriter for ServerPacketConn {
    async fn write_to(&self, p: &[u8], _addr: &dyn Addr) -> io::Result<usize> {
        let Ok(len) = u16::try_from(p.len()) else {
            return Err(io::Error::other("vless: packet exceeds the u16 length prefix"));
        };
        let mut conn = self.extended_conn.lock().await;
        conn.write_u16(len).await?;
        conn.write_all(p).await?;
        drop(conn);
        Ok(p.len())
    }
}

#[async_trait]
impl network::PacketConn for ServerPacketConn {
    async fn close(&self) -> io::Result<()> {
        close_stream(&*self.extended_conn.lock().await)
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        match self.extended_conn.try_lock() {
            Ok(conn) => Ok(Box::new(TcpAddr::from(conn.local_addr()?))),
            Err(_) => Err(io::Error::other("vless: local address unavailable while conn is busy")),
        }
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self.extended_conn.try_lock() {
            Ok(conn) => conn.old_conn().map_or(Ok(()), |inner| inner.set_read_deadline(deadline)),
            Err(_) => Ok(()),
        }
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self.extended_conn.try_lock() {
            Ok(conn) => conn.old_conn().map_or(Ok(()), |inner| inner.set_write_deadline(deadline)),
            Err(_) => Ok(()),
        }
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self.extended_conn.try_lock() {
            Ok(conn) => conn.old_conn().map_or(Ok(()), |inner| inner.set_deadline(deadline)),
            Err(_) => Ok(()),
        }
    }
}

impl NeedAdditionalReadDeadline for ServerPacketConn {
    fn need_additional_read_deadline(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use tokio::io::AsyncWriteExt;

    use super::*;

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

    /// A server packet conn over a fresh accepted loopback socket carrying `frame`.
    async fn packet_conn_carrying(frame: &[u8]) -> (ServerPacketConn, tokio::net::TcpStream) {
        let listener =
            tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("an ephemeral port is free");
        let addr = listener.local_addr().expect("the probe is bound");
        let mut peer = tokio::net::TcpStream::connect(addr).await.expect("the peer connects");
        let (server, _) = listener.accept().await.expect("the probe accepts");
        peer.write_all(frame).await.expect("the frame is written");
        let destination = Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
        (ServerPacketConn::new(new_extended_conn(server), destination), peer)
    }

    /// The stream from the report: `00 04 | 00 01 41 42` then `00 02 | 43 44`. A two-byte slice
    /// rejects the first datagram; the read after it must start at the second length prefix
    /// instead of decoding `00 01` as a header.
    #[tokio::test]
    async fn a_short_buffer_does_not_leave_the_read_between_datagram_boundaries() {
        let (conn, _peer) = packet_conn_carrying(&[0x00, 0x04, 0x00, 0x01, 0x41, 0x42, 0x00, 0x02, 0x43, 0x44]).await;

        let mut small = [0u8; 2];
        let err = NetPacketReader::read_from(&conn, &mut small)
            .await
            .expect_err("four payload bytes do not fit a two-byte slice");
        assert_eq!(err.to_string(), "short buffer");

        let mut larger = [0u8; 8];
        let (n, _addr) = NetPacketReader::read_from(&conn, &mut larger)
            .await
            .expect("the read after a short buffer must start at the second length prefix");
        assert_eq!(&larger[..n], b"CD", "the second datagram must survive the rejected first one");
    }

    /// The drain spans more than one read, so a payload larger than a single drain chunk must
    /// still leave the stream aligned on the next datagram.
    #[tokio::test]
    async fn a_short_buffer_drains_a_payload_larger_than_one_chunk() {
        let payload = [0xABu8; 4096];
        let mut frame = Vec::new();
        frame.extend_from_slice(&u16::try_from(payload.len()).expect("4096 fits a u16").to_be_bytes());
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&[0x00, 0x02, 0x43, 0x44]);
        let (conn, _peer) = packet_conn_carrying(&frame).await;

        let mut small = [0u8; 16];
        NetPacketReader::read_from(&conn, &mut small).await.expect_err("4096 payload bytes do not fit a 16-byte slice");

        let mut larger = [0u8; 8];
        let (n, _addr) = NetPacketReader::read_from(&conn, &mut larger)
            .await
            .expect("the datagram behind the drained one must be readable");
        assert_eq!(&larger[..n], b"CD");
    }

    /// A slice that holds the payload exactly is a fit, not a short buffer, and the read after it
    /// must still find the next length prefix.
    #[tokio::test]
    async fn a_payload_exactly_filling_the_slice_is_returned_intact() {
        let (conn, _peer) = packet_conn_carrying(&[0x00, 0x02, 0x43, 0x44, 0x00, 0x02, 0x45, 0x46]).await;

        let mut exact = [0u8; 2];
        let (n, _addr) =
            NetPacketReader::read_from(&conn, &mut exact).await.expect("an exact fit is not a short buffer");
        assert_eq!(&exact[..n], b"CD");

        let (n, _addr) = NetPacketReader::read_from(&conn, &mut exact).await.expect("the second exact fit reads too");
        assert_eq!(&exact[..n], b"EF");
    }

    /// A conn that accepts at most `per_write` bytes per `poll_write` and stops accepting after
    /// `budget` bytes, standing in for a socket whose send buffer has only a little room. Every
    /// accepted byte is recorded, so what actually reached the wire is observable. `park_on` names
    /// the poll that returns `Pending` (waking immediately) instead of accepting anything.
    #[derive(Debug)]
    struct TrickleStream {
        wire: Arc<Mutex<Vec<u8>>>,
        per_write: usize,
        budget: usize,
        park_on: Option<usize>,
        /// What `per_write` becomes once `park_on` has passed, so a test can model a send buffer
        /// that was full during the parked call and has room again on the next one.
        per_write_after_park: usize,
        /// The poll that fails with a recoverable `TimedOut` instead of accepting anything.
        timed_out_on: Option<usize>,
        calls: usize,
    }

    impl TrickleStream {
        fn new(per_write: usize, budget: usize) -> (Self, Arc<Mutex<Vec<u8>>>) {
            let wire = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    wire: Arc::clone(&wire),
                    per_write,
                    budget,
                    park_on: None,
                    per_write_after_park: per_write,
                    timed_out_on: None,
                    calls: 0,
                },
                wire,
            )
        }
    }

    impl AsyncRead for TrickleStream {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TrickleStream {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let call = this.calls;
            this.calls += 1;
            if this.park_on == Some(call) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if this.timed_out_on == Some(call) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "the write deadline fired")));
            }
            // Calls after the park see a wider send buffer, the way a socket that refused the whole
            // frame while full accepts all of it once the peer has drained.
            let per_write = if this.park_on.is_some_and(|parked| call > parked) {
                this.per_write_after_park
            } else {
                this.per_write
            };
            let accepted = buf.len().min(per_write).min(this.budget);
            this.budget -= accepted;
            this.wire.lock().expect("the wire is not poisoned").extend_from_slice(&buf[..accepted]);
            Poll::Ready(Ok(accepted))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for TrickleStream {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        }
    }

    fn conn_over_trickle_writer(per_write: usize, budget: usize) -> (ServerConn, Arc<Mutex<Vec<u8>>>) {
        let (stream, wire) = TrickleStream::new(per_write, budget);
        (ServerConn::new(new_extended_conn(stream)), wire)
    }

    /// A writer that accepts one byte per call must still carry the whole response frame; the
    /// single-poll path wrote the first byte and reported the entire payload as sent.
    #[tokio::test]
    async fn a_writer_accepting_one_byte_per_call_receives_the_whole_response_frame() {
        let (mut conn, wire) = conn_over_trickle_writer(1, usize::MAX);

        conn.write_all(&[0xA1, 0xB2]).await.expect("the payload is written");

        assert_eq!(*wire.lock().expect("the wire is not poisoned"), vec![vless::VERSION, 0, 0xA1, 0xB2]);
    }

    /// The byte a short write left unsent must be resumed from the caller's buffer, never replayed
    /// from the buffered copy of an earlier one.
    #[tokio::test]
    async fn a_payload_interrupted_by_a_short_write_is_resumed_without_duplicating_bytes() {
        let (mut conn, wire) = conn_over_trickle_writer(3, usize::MAX);

        conn.write_all(&[0xA1, 0xB2, 0xC3, 0xD4]).await.expect("the payload is written");

        assert_eq!(*wire.lock().expect("the wire is not poisoned"), vec![vless::VERSION, 0, 0xA1, 0xB2, 0xC3, 0xD4]);
    }

    /// A park between two bytes of the frame is not the end of the write: the offset survives it and
    /// the caller is told nothing was accepted, so the header still lands exactly once.
    #[tokio::test]
    async fn a_frame_interrupted_by_a_park_resumes_where_it_left_off() {
        let (stream, wire) = TrickleStream::new(1, usize::MAX);
        let mut conn = ServerConn::new(new_extended_conn(TrickleStream { park_on: Some(1), ..stream }));

        conn.write_all(&[0xA1, 0xB2]).await.expect("the payload is written");

        assert_eq!(*wire.lock().expect("the wire is not poisoned"), vec![vless::VERSION, 0, 0xA1, 0xB2]);
    }

    /// An application write abandoned after a `Pending` may be replaced by a different buffer. Only
    /// the fixed header survives the abandoned call, so the resumed write reports bytes of the
    /// buffer it was handed and never transmits the abandoned one.
    #[tokio::test]
    async fn an_abandoned_buffer_is_never_transmitted_by_a_resumed_write() {
        let (stream, wire) = TrickleStream::new(1, usize::MAX);
        let stream = TrickleStream { park_on: Some(1), per_write_after_park: usize::MAX, ..stream };
        let mut conn = ServerConn::new(new_extended_conn(stream));
        let mut cx = Context::from_waker(std::task::Waker::noop());

        let abandoned = [b'A'; 4];
        assert!(Pin::new(&mut conn).poll_write(&mut cx, &abandoned).is_pending(), "the writer parks");

        let replacement = [b'B'; 3];
        let accepted = match Pin::new(&mut conn).poll_write(&mut cx, &replacement) {
            Poll::Ready(Ok(accepted)) => accepted,
            Poll::Ready(Err(err)) => panic!("the resumed write failed: {err}"),
            Poll::Pending => panic!("the resumed write must report bytes, not park again"),
        };
        assert!(
            accepted <= replacement.len(),
            "a resumed write reported {accepted} bytes of a {} byte buffer",
            replacement.len()
        );
        assert_eq!(*wire.lock().expect("the wire is not poisoned"), vec![vless::VERSION, 0, b'B', b'B', b'B']);
    }

    /// A recoverable write error must not lose the header bytes already on the wire: the retry
    /// resumes from the offset instead of emitting `VERSION` a second time.
    #[tokio::test]
    async fn a_retry_after_a_recoverable_error_does_not_repeat_the_header() {
        let (stream, wire) = TrickleStream::new(1, usize::MAX);
        let stream = TrickleStream { timed_out_on: Some(1), ..stream };
        let mut conn = ServerConn::new(new_extended_conn(stream));
        let mut cx = Context::from_waker(std::task::Waker::noop());

        let payload = [0xA1, 0xB2];
        match Pin::new(&mut conn).poll_write(&mut cx, &payload) {
            Poll::Ready(Err(err)) => assert_eq!(err.kind(), io::ErrorKind::TimedOut),
            Poll::Ready(Ok(accepted)) => panic!("the failed write reported {accepted} bytes"),
            Poll::Pending => panic!("a fired deadline is an error, not a park"),
        }
        assert_eq!(*wire.lock().expect("the wire is not poisoned"), vec![vless::VERSION]);

        conn.write_all(&payload).await.expect("the retry writes the payload");

        assert_eq!(*wire.lock().expect("the wire is not poisoned"), vec![vless::VERSION, 0, 0xA1, 0xB2]);
    }

    /// The header is framing, not caller data: a writer that takes the two header bytes and then
    /// stops must fail the write instead of reporting the payload as sent.
    #[tokio::test]
    async fn a_payload_refused_after_the_header_is_not_reported_as_success() {
        let (mut conn, wire) = conn_over_trickle_writer(usize::MAX, 2);

        let err = conn.write_all(&[0xA1, 0xB2, 0xC3]).await.expect_err("the payload never reaches the wire");

        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        assert_eq!(*wire.lock().expect("the wire is not poisoned"), vec![vless::VERSION, 0]);
    }

    /// `Ready(Ok(0))` on the first byte is a refusal, not a fully buffered write.
    #[tokio::test]
    async fn a_writer_refusing_the_first_byte_is_not_reported_as_success() {
        let (mut conn, wire) = conn_over_trickle_writer(1, 0);

        let err = conn.write_all(&[0xA1]).await.expect_err("no byte reaches the wire");

        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        assert!(wire.lock().expect("the wire is not poisoned").is_empty());
    }
}

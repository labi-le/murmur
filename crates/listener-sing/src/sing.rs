//! `sp.mux.sing-box.arpa` carriers are multiplexed by `murmur_sing_mux`.
//!
//! VMess COMMAND_MUX and `v1.mux.cool` are dispatched by the VMess listener. Packetaddr's magic
//! destination rewrites each datagram's embedded address.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use uuid::Uuid;

use murmur_adapter_inbound::addition::{apply_additions, with_dst_addr, with_in_addr, with_src_addr, Addition};
use murmur_common::utils::uuid::new_uuid_v4;
use murmur_common_net::io::{Stream, StreamAsOldConn};
use murmur_common_net::new_deadline_conn;
use murmur_common_net::packet::packet_sing::udp_addr;
use murmur_compat::sing_buf::Buffer;
use murmur_constant::adapters::{UDPPacket, WriteBack};
use murmur_constant::metadata::{Metadata, NetWork, Type};
use murmur_constant::tunnel::Tunnel;
use murmur_log::warnln;
use murmur_sing::bufio::new_net_packet_writer;
use murmur_sing::metadata::{parse_socksaddr_host_port, socksaddr_from, Socksaddr};
use murmur_sing::network::{self, NetPacketWriter, PacketWriter, ReadWaitOptions};
use murmur_sing::uot;
use murmur_sing_mux::brutal::raw_socket;
use murmur_sing_mux::client::BrutalOptions as MuxBrutalOptions;
use murmur_sing_mux::server::{
    new_service as new_mux_service, Metadata as MuxMetadata, Service as MuxServiceImpl,
    ServiceHandler as MuxServiceHandler, ServiceOptions as MuxServiceOptions,
};
use murmur_sing_mux::session::MuxConn;
use murmur_std_compat::net::{Addr, TcpAddr};

use super::context::{get_additions, get_in_addr, SingContext};

pub const UDP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);
pub const ICMP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

const MUX_DESTINATION_FQDN: &str = "sp.mux.sing-box.arpa";
const VMESS_MUX_DESTINATION_FQDN: &str = "v1.mux.cool";
const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
const UOT_LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";
const PACKETADDR_SEQ_PACKET_MAGIC_ADDRESS: &str = "sp.packet-addr.v2fly.arpa";

/// The `Metadata` type of this listener, re-exported as `SingMetadata` from the crate that owns
/// the metadata vocabulary.
pub use murmur_sing::metadata::Metadata as SingMetadata;

#[derive(Clone)]
pub struct ListenerConfig {
    pub tunnel: Arc<dyn Tunnel>,
    pub type_: Type,
    pub additions: Vec<Addition>,
    pub udp_timeout: std::time::Duration,
    pub mux_option: MuxOption,
}

impl core::fmt::Debug for ListenerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `tunnel` and `additions` are erased trait objects without a `Debug` bound.
        let Self { type_, additions, udp_timeout, mux_option, .. } = self;
        f.debug_struct("ListenerConfig")
            .field("type_", type_)
            .field("additions", &additions.len())
            .field("udp_timeout", udp_timeout)
            .field("mux_option", mux_option)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct MuxOption {
    #[serde(rename = "padding", default, skip_serializing_if = "std::ops::Not::not")]
    pub padding: bool,
    #[serde(rename = "brutal", default)]
    pub brutal: BrutalOptions,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BrutalOptions {
    #[serde(rename = "enabled")]
    pub enabled: bool,
    #[serde(rename = "up", default, skip_serializing_if = "String::is_empty")]
    pub up: String,
    #[serde(rename = "down", default, skip_serializing_if = "String::is_empty")]
    pub down: String,
}

/// The mux service contract, behind a local trait so `ListenerHandler` does not name the mux
/// crate's concrete type. `handler`/`ctx` are passed per call instead of stored, because this
/// tree's `ListenerHandler` owners hold it by value rather than behind `Arc`, and the mux
/// service's `new_connection` already takes the handler by reference.
#[async_trait]
trait MuxService: Send + Sync {
    async fn new_connection(
        &self,
        handler: &ListenerHandler,
        ctx: SingContext,
        conn: Box<dyn Stream>,
        metadata: SingMetadata,
    ) -> Result<()>;
}

struct RealMuxService(MuxServiceImpl);

/// Bridges `Box<dyn Stream>` (`murmur_common_net`) into `Box<dyn MuxConn>`
/// (`murmur_sing_mux`) — same bounds (`AsyncRead + AsyncWrite + Send + Sync + Unpin`),
/// different trait objects, so a thin forwarding wrapper is all that's needed.
struct StreamAsMuxConn(Box<dyn Stream>);

impl tokio::io::AsyncRead for StreamAsMuxConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for StreamAsMuxConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// Bridges the mux service's handler contract back onto the real `ListenerHandler` for the
/// lifetime of one mux carrier connection's [`RealMuxService::new_connection`] call.
struct ListenerHandlerBridge<'a> {
    handler: &'a ListenerHandler,
    ctx: SingContext,
}

#[async_trait]
impl MuxServiceHandler for ListenerHandlerBridge<'_> {
    /// The connection entry point, reached through the mux service's handler trait.
    async fn new_connection(&self, conn: Box<dyn MuxConn>, metadata: MuxMetadata) -> Result<()> {
        self.handler.new_connection(self.ctx.clone(), Box::new(MuxConnAsStream(conn)), metadata).await
    }

    /// The packet-connection entry point, reached through the mux service's handler trait.
    async fn new_packet_connection(&self, conn: Box<dyn network::PacketConn>, metadata: MuxMetadata) -> Result<()> {
        self.handler.new_packet_connection(self.ctx.clone(), conn, metadata).await
    }
}

/// Bridges the mux crate's `Box<dyn MuxStream>` (an already-open multiplexed stream, itself a
/// `MuxConn`) back into `Box<dyn Stream>` for `ListenerHandler::new_connection`.
struct MuxConnAsStream(Box<dyn MuxConn>);

impl tokio::io::AsyncRead for MuxConnAsStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for MuxConnAsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl Stream for MuxConnAsStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "sing-mux stream has no local addr"))
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "sing-mux stream has no peer addr"))
    }
}

#[async_trait]
impl MuxService for RealMuxService {
    async fn new_connection(
        &self,
        handler: &ListenerHandler,
        ctx: SingContext,
        conn: Box<dyn Stream>,
        metadata: SingMetadata,
    ) -> Result<()> {
        let bridge = ListenerHandlerBridge { handler, ctx };
        let socket = raw_socket(conn.as_socket());
        self.0
            .new_connection(&bridge, Box::new(StreamAsMuxConn(conn)), socket, metadata)
            .await
            .map_err(|err| anyhow!("{err}"))
    }
}

fn handle_vmess_mux_connection(_conn: Box<dyn Stream>, _metadata: &SingMetadata) -> Result<()> {
    Err(anyhow!("VMess mux destination requires the VMess listener"))
}

struct PacketAddrConn {
    inner: Box<dyn network::PacketConn>,
}

/// `Buffer::read_bytes` already rejects a short read, so this error is unreachable: it keeps the
/// conversion fallible instead of panicking.
fn invalid_address_length() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "packetaddr: truncated address")
}

#[async_trait]
impl network::PacketReader for PacketAddrConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        self.inner.read_packet(buffer).await?;
        let family = buffer.read_byte()?;
        let ip = match family {
            1 => {
                let octets: [u8; 4] = buffer.read_bytes(4)?.try_into().map_err(|_| invalid_address_length())?;
                IpAddr::from(octets)
            }
            2 => {
                let octets: [u8; 16] = buffer.read_bytes(16)?.try_into().map_err(|_| invalid_address_length())?;
                IpAddr::from(octets)
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "packetaddr: invalid address family")),
        };
        let port = u16::from_be_bytes(buffer.read_bytes(2)?.try_into().map_err(|_| invalid_address_length())?);
        Ok(Socksaddr::from_ip(ip, port))
    }
}

#[async_trait]
impl PacketWriter for PacketAddrConn {
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        if !destination.fqdn.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "packetaddr: fqdn unsupported"));
        }
        let mut wire = Vec::with_capacity(buffer.len() + 19);
        match destination.addr {
            Some(IpAddr::V4(ip)) => {
                wire.push(1);
                wire.extend_from_slice(&ip.octets());
            }
            Some(IpAddr::V6(ip)) => {
                wire.push(2);
                wire.extend_from_slice(&ip.octets());
            }
            None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "packetaddr: fqdn unsupported")),
        }
        wire.extend_from_slice(&destination.port.to_be_bytes());
        wire.extend_from_slice(buffer.bytes());
        let framed = murmur_compat::sing_buf::as_(wire);
        self.inner.write_packet(&framed, &Socksaddr::default()).await
    }
}

#[async_trait]
impl network::PacketConn for PacketAddrConn {
    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.local_addr()
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.set_write_deadline(deadline)
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.set_deadline(deadline)
    }
}

#[derive(Clone)]
pub struct ListenerHandler {
    pub config: ListenerConfig,
    handler_id: Uuid,
    mux_service: Arc<dyn MuxService>,
}

impl core::fmt::Debug for ListenerHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `mux_service` is an erased trait object without a `Debug` bound.
        let Self { config, handler_id, .. } = self;
        f.debug_struct("ListenerHandler")
            .field("config", config)
            .field("handler_id", handler_id)
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn upstream_metadata(metadata: &SingMetadata) -> SingMetadata {
    SingMetadata { protocol: String::new(), source: metadata.source.clone(), destination: metadata.destination.clone() }
}

#[must_use]
pub fn convert_metadata(metadata: &Metadata) -> SingMetadata {
    SingMetadata {
        protocol: metadata.type_.string(),
        source: socksaddr_from(metadata.src_ip, metadata.src_port),
        destination: parse_socksaddr_host_port(&metadata.string(), metadata.dst_port),
    }
}

pub fn new_listener_handler(lc: ListenerConfig) -> Result<ListenerHandler> {
    let handler_id = new_uuid_v4();
    let send_bps = murmur_common::utils::mbps::string_to_bps(&lc.mux_option.brutal.up);
    let receive_bps = murmur_common::utils::mbps::string_to_bps(&lc.mux_option.brutal.down);
    let mux_service = new_mux_service(MuxServiceOptions {
        padding: lc.mux_option.padding,
        brutal: MuxBrutalOptions { enabled: lc.mux_option.brutal.enabled, send_bps, receive_bps },
    })
    .map_err(|err| anyhow!("{err}"))?;
    Ok(ListenerHandler { config: lc, handler_id, mux_service: Arc::new(RealMuxService(mux_service)) })
}

impl ListenerHandler {
    #[must_use]
    pub fn is_special_fqdn(&self, fqdn: &str) -> bool {
        matches!(fqdn, MUX_DESTINATION_FQDN | VMESS_MUX_DESTINATION_FQDN | UOT_MAGIC_ADDRESS | UOT_LEGACY_MAGIC_ADDRESS)
    }

    pub async fn parse_special_fqdn(
        &self,
        ctx: SingContext,
        mut conn: Box<dyn Stream>,
        metadata: SingMetadata,
    ) -> Result<()> {
        match metadata.destination.fqdn.as_str() {
            MUX_DESTINATION_FQDN => {
                self.mux_service.new_connection(self, ctx, conn, upstream_metadata(&metadata)).await
            }
            VMESS_MUX_DESTINATION_FQDN => handle_vmess_mux_connection(conn, &metadata),
            UOT_MAGIC_ADDRESS => {
                let request =
                    uot::read_request(conn.as_mut()).await.map_err(|err| anyhow!("read UoT request: {err}"))?;
                let mut metadata = metadata;
                metadata.destination = request.destination.clone();
                // S11: remove once `uot::new_conn` takes `Box<dyn Stream>`.
                let uot_conn: Arc<dyn network::PacketConn> =
                    Arc::new(uot::new_conn(Box::new(StreamAsOldConn::new(conn)), request));
                self.new_packet_connection_conn(&ctx, uot_conn, metadata).await
            }
            UOT_LEGACY_MAGIC_ADDRESS => {
                let mut metadata = metadata;
                metadata.destination =
                    Socksaddr { fqdn: String::new(), addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), port: 0 };
                let request = uot::Request { is_connect: false, destination: Socksaddr::default() };
                // S11: remove once `uot::new_conn` takes `Box<dyn Stream>`.
                let uot_conn: Arc<dyn network::PacketConn> =
                    Arc::new(uot::new_conn(Box::new(StreamAsOldConn::new(conn)), request));
                self.new_packet_connection_conn(&ctx, uot_conn, metadata).await
            }
            _ => Err(anyhow!("not special fqdn")),
        }
    }

    pub async fn new_connection(&self, ctx: SingContext, conn: Box<dyn Stream>, metadata: SingMetadata) -> Result<()> {
        if self.is_special_fqdn(&metadata.destination.fqdn) {
            return self.parse_special_fqdn(ctx, conn, metadata).await;
        }

        // A `need_additional_read_deadline` probe answered by the conn
        // itself, so plain TCP/TLS and mux streams keep answering `false`.
        let conn: Box<dyn Stream> =
            if need_additional_read_deadline(conn.as_ref()) { new_deadline_conn(conn) } else { conn };

        let mut c_metadata = Metadata { network: NetWork::TCP, type_: self.config.type_, ..Metadata::default() };
        if metadata.source.is_ip() && metadata.source.fqdn.is_empty() {
            c_metadata.raw_src_addr = metadata.source.tcp_addr().map(|a| -> Arc<dyn Addr> { Arc::new(a) });
        }
        if metadata.destination.is_ip() && metadata.destination.fqdn.is_empty() {
            c_metadata.raw_dst_addr = metadata.destination.tcp_addr().map(|a| -> Arc<dyn Addr> { Arc::new(a) });
        }
        apply_additions(
            &mut c_metadata,
            &[
                with_dst_addr(Some(Box::new(metadata.destination.clone()))),
                with_src_addr(Some(Box::new(metadata.source.clone()))),
                with_in_addr(conn.local_addr().ok().map(|addr| -> Box<dyn Addr> { Box::new(TcpAddr::from(addr)) })),
            ],
        );
        apply_additions(&mut c_metadata, &self.config.additions);
        apply_additions(&mut c_metadata, &get_additions(&ctx));

        self.config.tunnel.handle_tcp_conn(conn, c_metadata).await;
        Ok(())
    }

    pub async fn new_packet_connection(
        &self,
        ctx: SingContext,
        conn: Box<dyn network::PacketConn>,
        metadata: SingMetadata,
    ) -> Result<()> {
        let conn: Box<dyn network::PacketConn> = if metadata.destination.fqdn == PACKETADDR_SEQ_PACKET_MAGIC_ADDRESS {
            Box::new(PacketAddrConn { inner: conn })
        } else {
            conn
        };
        self.new_packet_connection_conn(&ctx, Arc::from(conn), metadata).await
    }

    async fn new_packet_connection_conn(
        &self,
        ctx: &SingContext,
        conn: Arc<dyn network::PacketConn>,
        metadata: SingMetadata,
    ) -> Result<()> {
        // `PacketConn: PacketWriter`: the wide connection coerces to its write half, but only
        // on a concretely typed binding; `Arc::clone`'s return type would unify with the
        // narrower one and reject its argument.
        let conn_arc: Arc<dyn network::PacketConn> = Arc::clone(&conn);
        let conn_writer: Arc<dyn PacketWriter> = conn_arc;
        let writer: Arc<Mutex<Option<Arc<dyn NetPacketWriter>>>> =
            Arc::new(Mutex::new(Some(new_net_packet_writer(conn_writer))));
        // One fresh SNAT key for
        // this whole packet connection's lifetime, shared by every packet it reads.
        let nat_key = new_uuid_v4().to_string();

        let rw_options = ReadWaitOptions::default();
        let conn_arc: Arc<dyn network::PacketConn> = Arc::clone(&conn);
        let conn_reader: Arc<dyn network::PacketReader> = conn_arc;
        let read_waiter = network::create_packet_read_waiter(conn_reader);
        let is_read_waiter = true;
        read_waiter.initialize_read_waiter(rw_options);

        let result: Result<()> = loop {
            let (buff, dest, err): (Option<Buffer>, Socksaddr, Option<io::Error>) = if is_read_waiter {
                match read_waiter.wait_read_packet().await {
                    Ok((buff, dest)) => (Some(buff), dest, None),
                    Err(err) => (None, Socksaddr::default(), Some(err)),
                }
            } else {
                let mut buff = rw_options.new_packet_buffer();
                let result = conn.read_packet(&mut buff).await;
                rw_options.post_return(&mut buff);
                match result {
                    Ok(dest) => (Some(buff), dest, None),
                    Err(err) => (Some(buff), Socksaddr::default(), Some(err)),
                }
            };
            if let Some(err) = err {
                if let Some(mut buff) = buff {
                    buff.release();
                }
                if should_ignore_packet_error(&err) {
                    break Ok(());
                }
                break Err(err.into());
            }
            let Some(buff) = buff else { break Ok(()) };

            let r_addr: SocketAddr = SocketAddr::new(
                metadata.source.addr.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                metadata.source.port,
            );
            let l_addr: Option<Arc<dyn Addr>> = match get_in_addr(ctx) {
                Some(addr) => Some(addr),
                None => conn.local_addr().ok().map(Arc::from),
            };
            let l_addr: Option<SocketAddr> =
                match l_addr.map(|addr| murmur_common_net::io::old_addr_to_socket_addr(addr.as_ref())).transpose() {
                    Ok(l_addr) => l_addr,
                    Err(err) => {
                        let mut buff = buff;
                        buff.release();
                        break Err(err.into());
                    }
                };

            let c_packet = Arc::new(Packet {
                writer: Arc::clone(&writer),
                r_addr,
                l_addr,
                nat_key: nat_key.clone(),
                data: buff.bytes().to_vec(),
                buff: Mutex::new(Some(buff)),
            });
            self.handle_packet(ctx, c_packet, metadata.source.clone(), dest);
        };

        *writer.lock() = None;
        let _ = conn.close().await;
        result
    }

    #[expect(
        clippy::unused_async,
        reason = "published listener entry point whose callers await it; the async signature is part of that interface"
    )]
    pub async fn new_packet(
        &self,
        ctx: &SingContext,
        key: SocketAddr,
        buffer: Buffer,
        metadata: SingMetadata,
        init: Arc<dyn Fn(Option<Arc<dyn network::PacketConn>>) -> Arc<dyn PacketWriter> + Send + Sync>,
    ) {
        let writer = new_net_packet_writer(init(None));
        let writer = Arc::new(Mutex::new(Some(writer)));

        let r_addr: SocketAddr =
            SocketAddr::new(metadata.source.addr.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), metadata.source.port);
        // A downcast to the writer's local address is not expressible on the erased writer this
        // port has no vocabulary for (`NEEDED SHIM ITEM: network::NetPacketWriter::local_addr`);
        // `l_addr` is left unset here, matching the TUN listener path where the cast also fails.
        let l_addr: Option<SocketAddr> = None;
        // The connID is the handler-scoped key, except for TUN — which this codebase has no
        // listener type for, so the handler-scoped key always applies:
        // sessions multiplexed over one client connection (h2/grpc/xhttp) share `r_addr`, but each
        // gets its own `key` (per-stream), so this stays unique per session.
        let nat_key = format!("{}:{key}", self.handler_id);

        let c_packet = Arc::new(Packet {
            writer,
            r_addr,
            l_addr,
            nat_key,
            data: buffer.bytes().to_vec(),
            buff: Mutex::new(Some(buffer)),
        });
        self.handle_packet(ctx, c_packet, metadata.source, metadata.destination);
    }

    fn handle_packet(&self, ctx: &SingContext, c_packet: Arc<Packet>, source: Socksaddr, destination: Socksaddr) {
        let mut c_metadata = Metadata { network: NetWork::UDP, type_: self.config.type_, ..Metadata::default() };
        if source.is_ip() && source.fqdn.is_empty() {
            c_metadata.raw_src_addr = Some(Arc::new(udp_addr(&source)));
        }
        if destination.is_ip() && destination.fqdn.is_empty() {
            c_metadata.raw_dst_addr = Some(Arc::new(udp_addr(&destination)));
        }
        apply_additions(
            &mut c_metadata,
            &[
                with_dst_addr(Some(Box::new(destination))),
                with_src_addr(Some(Box::new(source))),
                with_in_addr(Some(Box::new(murmur_common_net::io::udp_addr_from_socket_addr(
                    c_packet.in_addr().unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
                )))),
            ],
        );
        apply_additions(&mut c_metadata, &self.config.additions);
        apply_additions(&mut c_metadata, &get_additions(ctx));

        self.config.tunnel.handle_udp_packet(c_packet, c_metadata);
    }

    pub fn new_error(&self, _ctx: &SingContext, err: &anyhow::Error) {
        warnln!("{} listener get error: {err:?}", self.config.type_.string());
    }

    #[must_use]
    pub fn type_mutation(&self, typ: Type) -> Self {
        Self {
            config: ListenerConfig { type_: typ, ..self.config.clone() },
            handler_id: self.handler_id,
            mux_service: Arc::clone(&self.mux_service),
        }
    }
}

fn need_additional_read_deadline(conn: &dyn Stream) -> bool {
    conn.need_additional_read_deadline()
}

fn should_ignore_packet_error(err: &io::Error) -> bool {
    is_timeout(err) || is_closed(err) || is_canceled(err)
}

fn is_timeout(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::TimedOut
}

fn is_closed(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
    )
}

fn is_canceled(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}

struct Packet {
    writer: Arc<Mutex<Option<Arc<dyn NetPacketWriter>>>>,
    r_addr: SocketAddr,
    l_addr: Option<SocketAddr>,
    /// The per-connection
    /// (or per-handler-and-socket) SNAT key, kept apart from `r_addr` (the real source address,
    /// which every packet on one client connection shares) so the tunnel's NAT table sees
    /// distinct entries per connection/handler rather than merging them by shared source.
    nat_key: String,
    data: Vec<u8>,
    buff: Mutex<Option<Buffer>>,
}

#[async_trait]
impl WriteBack for Packet {
    /// Writes a UDP packet with source (ip, port) = `addr`.
    async fn write_back(&self, b: &[u8], addr: Option<SocketAddr>) -> Result<usize> {
        let Some(addr) = addr else {
            return Err(anyhow!("address is invalid"));
        };
        let addr = murmur_common_net::io::udp_addr_from_socket_addr(addr);
        let writer = self.writer.lock().clone();
        let Some(writer) = writer else {
            return Err(anyhow!("writeBack to closed connection"));
        };
        Ok(writer.write_to(b, &addr).await?)
    }
}

impl UDPPacket for Packet {
    fn data(&self) -> &[u8] {
        &self.data
    }

    fn drop_(&self) {
        let buff = self.buff.lock().take();
        if let Some(mut buff) = buff {
            buff.release();
        }
    }

    /// The source IP/port of the UDP packet.
    fn local_addr(&self) -> SocketAddr {
        self.r_addr
    }

    fn in_addr(&self) -> Option<SocketAddr> {
        Some(self.l_addr.unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
    }

    /// The remote address string, see the `nat_key` field doc.
    fn nat_key(&self) -> String {
        self.nat_key.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use murmur_constant::adapters::NatTable;
    use murmur_std_compat::net::UdpAddr;

    use super::*;

    #[derive(Default)]
    struct CapturingTunnel {
        packets: Mutex<Vec<Arc<dyn UDPPacket>>>,
        destinations: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Tunnel for CapturingTunnel {
        async fn handle_tcp_conn(&self, _conn: Box<dyn Stream>, _metadata: Metadata) {
            unimplemented!("not exercised by this test")
        }

        fn handle_udp_packet(&self, packet: Arc<dyn UDPPacket>, metadata: Metadata) {
            self.destinations.lock().push(metadata.remote_address());
            self.packets.lock().push(packet);
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            unimplemented!("not exercised by this test")
        }
    }

    struct FakePacketConn {
        local: SocketAddr,
        incoming: Mutex<VecDeque<(Vec<u8>, Socksaddr)>>,
        outgoing: Arc<Mutex<Vec<(Vec<u8>, Socksaddr)>>>,
        deadlines: Arc<Mutex<Vec<&'static str>>>,
    }

    impl FakePacketConn {
        fn new(local: SocketAddr, incoming: Vec<(Vec<u8>, Socksaddr)>) -> Self {
            Self {
                local,
                incoming: Mutex::new(VecDeque::from(incoming)),
                outgoing: Arc::default(),
                deadlines: Arc::default(),
            }
        }
    }

    #[async_trait]
    impl network::PacketReader for FakePacketConn {
        async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
            match self.incoming.lock().pop_front() {
                Some((data, dest)) => {
                    buffer.write_bytes(&data)?;
                    Ok(dest)
                }
                None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "fake conn exhausted")),
            }
        }
    }

    #[async_trait]
    impl PacketWriter for FakePacketConn {
        async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
            self.outgoing.lock().push((buffer.bytes().to_vec(), destination.clone()));
            Ok(())
        }
    }

    #[async_trait]
    impl network::PacketConn for FakePacketConn {
        async fn close(&self) -> io::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(UdpAddr::new(self.local.ip(), self.local.port())))
        }

        fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.deadlines.lock().push("read");
            Ok(())
        }

        fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.deadlines.lock().push("write");
            Ok(())
        }

        fn set_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.deadlines.lock().push("both");
            Ok(())
        }
    }

    fn test_handler(tunnel: Arc<dyn Tunnel>) -> ListenerHandler {
        new_listener_handler(ListenerConfig {
            tunnel,
            type_: Type::SOCKS5,
            additions: vec![],
            udp_timeout: UDP_TIMEOUT,
            mux_option: MuxOption::default(),
        })
        .unwrap()
    }

    fn peer_source() -> Socksaddr {
        Socksaddr { fqdn: String::new(), addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), port: 40000 }
    }

    #[tokio::test]
    async fn new_packet_connection_conn_nat_keys_two_connections_over_one_peer_differently() {
        let tunnel = Arc::new(CapturingTunnel::default());
        let handler_tunnel = Arc::clone(&tunnel);
        let handler = test_handler(handler_tunnel);
        let source = peer_source();
        let metadata =
            SingMetadata { protocol: String::new(), source: source.clone(), destination: Socksaddr::default() };
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5353);

        let conn1: Arc<dyn network::PacketConn> = Arc::new(FakePacketConn::new(
            local,
            vec![(b"one".to_vec(), source.clone()), (b"two".to_vec(), source.clone())],
        ));
        let _ = handler.new_packet_connection_conn(&SingContext::default(), conn1, metadata.clone()).await;

        let conn2: Arc<dyn network::PacketConn> =
            Arc::new(FakePacketConn::new(local, vec![(b"three".to_vec(), source.clone())]));
        let _ = handler.new_packet_connection_conn(&SingContext::default(), conn2, metadata).await;

        let packets = tunnel.packets.lock();
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].local_addr(), packets[2].local_addr(), "both connections share one peer source");
        assert_eq!(packets[0].nat_key(), packets[1].nat_key(), "packets read on the same connection share one nat_key");
        assert_ne!(
            packets[0].nat_key(),
            packets[2].nat_key(),
            "two connections sharing one peer source must land in distinct NAT entries"
        );
    }

    #[tokio::test]
    async fn packetaddr_magic_routes_each_embedded_destination_without_header() {
        let tunnel = Arc::new(CapturingTunnel::default());
        let handler_tunnel = Arc::clone(&tunnel);
        let handler = test_handler(handler_tunnel);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353);
        let mut ipv6_packet = vec![2];
        ipv6_packet.extend_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        ipv6_packet.extend_from_slice(&[1, 187, 0xbb, 0xcc]);
        let incoming = vec![(vec![1, 203, 0, 113, 7, 0, 53, 0xaa], peer_source()), (ipv6_packet, peer_source())];
        let metadata = SingMetadata {
            source: peer_source(),
            destination: Socksaddr::fqdn(PACKETADDR_SEQ_PACKET_MAGIC_ADDRESS, 443),
            ..SingMetadata::default()
        };
        handler
            .new_packet_connection(SingContext::default(), Box::new(FakePacketConn::new(local, incoming)), metadata)
            .await
            .unwrap();
        let packets = tunnel.packets.lock();
        assert_eq!(packets[0].data(), &[0xaa]);
        assert_eq!(packets[1].data(), &[0xbb, 0xcc]);
        assert_eq!(tunnel.destinations.lock().as_slice(), ["203.0.113.7:53", "[2001:db8::1]:443"]);
    }

    #[tokio::test]
    async fn packetaddr_other_fqdn_and_ip_destination_keep_original_packet() {
        for destination in
            [Socksaddr::fqdn("example.com", 443), Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 53)]
        {
            let tunnel = Arc::new(CapturingTunnel::default());
            let handler_tunnel = Arc::clone(&tunnel);
            let handler = test_handler(handler_tunnel);
            let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353);
            let incoming = vec![(vec![1, 203, 0, 113, 7, 0, 53, 0xaa], peer_source())];
            let metadata = SingMetadata { source: peer_source(), destination, ..SingMetadata::default() };
            handler
                .new_packet_connection(SingContext::default(), Box::new(FakePacketConn::new(local, incoming)), metadata)
                .await
                .unwrap();
            assert_eq!(tunnel.packets.lock()[0].data(), &[1, 203, 0, 113, 7, 0, 53, 0xaa]);
            assert_eq!(tunnel.destinations.lock().as_slice(), ["10.0.0.1:40000"]);
        }
    }

    #[tokio::test]
    async fn packetaddr_replies_encode_the_reply_destination_not_the_magic_address() {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353);
        let inner = FakePacketConn::new(local, vec![]);
        let outgoing = Arc::clone(&inner.outgoing);
        let conn = PacketAddrConn { inner: Box::new(inner) };
        let ipv4 = Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)), 53);
        let ipv6 = Socksaddr::from_ip(IpAddr::V6("2001:db8::1".parse().unwrap()), 443);
        conn.write_packet(&murmur_compat::sing_buf::as_(b"one".to_vec()), &ipv4).await.unwrap();
        conn.write_packet(&murmur_compat::sing_buf::as_(b"two".to_vec()), &ipv6).await.unwrap();
        let mut expected_ipv6 = vec![2];
        expected_ipv6.extend_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        expected_ipv6.extend_from_slice(&[1, 187, b't', b'w', b'o']);
        assert_eq!(
            outgoing.lock().as_slice(),
            [
                (vec![1, 198, 51, 100, 8, 0, 53, b'o', b'n', b'e'], Socksaddr::default()),
                (expected_ipv6, Socksaddr::default()),
            ]
        );
        let err = conn
            .write_packet(&murmur_compat::sing_buf::as_(b"x".to_vec()), &Socksaddr::fqdn("example.com", 53))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = conn
            .write_packet(
                &murmur_compat::sing_buf::as_(b"x".to_vec()),
                &Socksaddr { fqdn: "example.com".into(), addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), port: 53 },
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(outgoing.lock().len(), 2);
    }

    #[tokio::test]
    async fn packetaddr_delegates_connection_deadlines() {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353);
        let inner = FakePacketConn::new(local, vec![]);
        let deadlines = Arc::clone(&inner.deadlines);
        let conn = PacketAddrConn { inner: Box::new(inner) };
        let instant = tokio::time::Instant::now();
        network::PacketConn::set_read_deadline(&conn, Some(instant)).unwrap();
        network::PacketConn::set_write_deadline(&conn, Some(instant)).unwrap();
        network::PacketConn::set_deadline(&conn, Some(instant)).unwrap();
        assert_eq!(deadlines.lock().as_slice(), ["read", "write", "both"]);
    }

    #[tokio::test]
    async fn new_packet_keys_two_streams_over_one_peer_differently() {
        let tunnel = Arc::new(CapturingTunnel::default());
        let handler_tunnel = Arc::clone(&tunnel);
        let handler = test_handler(handler_tunnel);
        let source = peer_source();
        let metadata =
            SingMetadata { protocol: String::new(), source: source.clone(), destination: Socksaddr::default() };
        let ctx = SingContext::default();
        let init: Arc<dyn Fn(Option<Arc<dyn network::PacketConn>>) -> Arc<dyn PacketWriter> + Send + Sync> =
            Arc::new(|_| -> Arc<dyn PacketWriter> {
                Arc::new(FakePacketConn::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0), vec![]))
            });

        let key_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 1111);
        let key_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 2222);
        handler
            .new_packet(&ctx, key_a, murmur_compat::sing_buf::as_(b"a".to_vec()), metadata.clone(), Arc::clone(&init))
            .await;
        handler.new_packet(&ctx, key_b, murmur_compat::sing_buf::as_(b"b".to_vec()), metadata, init).await;

        let packets = tunnel.packets.lock();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].local_addr(), packets[1].local_addr(), "both streams share one peer source");
        assert_ne!(
            packets[0].nat_key(),
            packets[1].nat_key(),
            "two multiplexed streams over one peer must land in distinct NAT entries"
        );
    }
}

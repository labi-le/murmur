//! VMess AEAD-2 service dispatches TCP, UDP, and VMess mux sessions. The
//! separate sing-mux protocol (`sp.mux.sing-box.arpa`) remains unsupported.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, CONNECTION, UPGRADE};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Mutex as TokioMutex, Notify};
use tokio_util::sync::CancellationToken;

use crate::jls::listener as jls;
use crate::shadowsocks::utils::percent_decode;
use crate::shadowtls;
use crate::tlsmirror;
use murmur_adapter_inbound::addition::{with_in_name, with_special_rules, Addition};
use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{Acceptor, OldConnAsStream, Stream, StreamAsOldConn};
use murmur_common_net::new_cached_conn;
use murmur_common_net::sing::ExtendedConn as SingExtendedConn;
use murmur_common_net::websocket::get_websocket_sec_accept;
use murmur_compat::sing_buf::Buffer as SingBuffer;
use murmur_component_ca::auth::{
    client_auth_type_from_string, NO_CLIENT_CERT, REQUIRE_AND_VERIFY_CLIENT_CERT, VERIFY_CLIENT_CERT_IF_GIVEN,
};
use murmur_component_ca::keypair::{load_certificates, new_tls_key_pair_loader};
use murmur_component_ech::load_ech_key;
use murmur_component_tls::utls::{self as tls_c, ClientHelloInfo, Config as TlsConfig};
use murmur_constant::listener::{InboundListenConfig, MultiAddrListener};
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::vmess::{TLSMirrorConnectionEnrolment, VmessServer};
use murmur_listener_sing::context::SingContext;
use murmur_listener_sing::sing::{
    new_listener_handler, ListenerConfig as SingListenerConfig, ListenerHandler, SingMetadata,
};
use murmur_ntp::time::now as ntp_now;
use murmur_sing::network::{
    self, PacketConn as SingPacketConnTrait, PacketReader as SingPacketReader, PacketWriter as SingPacketWriter,
};
use murmur_std_compat::net::{Addr, Conn as NetConn, Listener as NetListener, TcpAddr};
use murmur_transport::gun::server::{
    new_server_handler as gun_new_server_handler, ConnHandler as GunConnHandler, Handler as GunHandler,
    ServerOption as GunServerOption,
};
use murmur_transport_mekya as mekya;
use murmur_transport_mkcp as mkcp;
use murmur_transport_vmess::sing::client::{COMMAND_TCP, COMMAND_UDP};
use murmur_transport_vmess::sing::service::Service as VmessSingService;
use murmur_transport_vmess::websocket::stream_upgraded_websocket_conn;

const VMESS_MUX_FQDN: &str = "v1.mux.cool";

/// `gun::server::Handler`'s private response-body alias, redeclared locally: identical
/// underlying type, so implementing `Handler` here needs no access to the private name.
type ResponseBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn not_found() -> Response<ResponseBody> {
    let mut response = Response::new(Empty::<Bytes>::new().boxed());
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    req.headers().get(UPGRADE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// The handler registered for the configured WebSocket path.
struct WsMuxHandler {
    ws_path: String,
    sl: Arc<Listener>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
}

#[async_trait]
impl GunHandler for WsMuxHandler {
    async fn serve(&self, mut req: Request<Incoming>) -> Response<ResponseBody> {
        if req.uri().path() != self.ws_path || !is_websocket_upgrade(&req) {
            return not_found();
        }
        let sec_key = req.headers().get("sec-websocket-key").and_then(|v| v.to_str().ok()).map(str::to_owned);
        let sec_protocol = req.headers().get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).map(str::to_owned);
        let accept = sec_key.as_deref().map(get_websocket_sec_accept);

        let on_upgrade = hyper::upgrade::on(&mut req);
        let sl = Arc::clone(&self.sl);
        let tunnel = Arc::clone(&self.tunnel);
        let additions = self.additions.clone();
        tokio::spawn(async move {
            let Ok(upgraded) = on_upgrade.await else { return };
            let Ok(parts) = auto::upgrade::downcast::<TokioIo<Box<dyn Stream>>>(upgraded) else { return };
            // S11: remove with murmur-std-compat, once
            // murmur_transport_vmess::websocket::stream_upgraded_websocket_conn takes Stream.
            let mut conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(parts.io.into_inner()));
            if !parts.read_buf.is_empty() {
                // S11: remove in U5, once stream_upgraded_websocket_conn takes Stream.
                conn = Box::new(new_cached_conn(OldConnAsStream(conn), parts.read_buf.to_vec()));
            }
            let conn = stream_upgraded_websocket_conn(conn, sec_key.as_deref(), sec_protocol.as_deref());
            let conn: Box<dyn Stream> = Box::new(OldConnAsStream(conn));
            sl.handle_conn(conn, tunnel, additions).await;
        });

        let mut response = Response::new(Empty::<Bytes>::new().boxed());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        let headers = response.headers_mut();
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        if let Some(accept) = accept.and_then(|accept| HeaderValue::from_str(&accept).ok()) {
            headers.insert("Sec-WebSocket-Accept", accept);
        }
        response
    }
}

async fn serve_http_conn(handler: Arc<dyn GunHandler>, conn: Box<dyn Stream>) {
    let io = TokioIo::new(conn);
    let svc = service_fn(move |req: Request<Incoming>| {
        let handler = Arc::clone(&handler);
        async move { Ok::<_, Infallible>(handler.serve(req).await) }
    });
    let builder = auto::Builder::new(TokioExecutor::new());
    let _ = builder.serve_connection_with_upgrades(io, svc).await;
}

/// Wraps a [`murmur_transport_vmess::sing::service::Accepted`] stream conn (each `read`/`write`
/// call already is one vmess chunk = one packet) as a `network::PacketConn`, the shape
/// `ListenerHandler::new_packet_connection` needs. Mirrors
/// `listener::sing_vless::service::ServerPacketConn`'s role but adds no length-prefix framing of
/// its own — the vmess AEAD-2 chunk framing already is that framing.
struct VmessServerPacketConn {
    read: TokioMutex<ReadHalf<Box<dyn Stream>>>,
    write: TokioMutex<WriteHalf<Box<dyn Stream>>>,
    local_addr: Option<Arc<dyn Addr>>,
    destination: murmur_sing::metadata::Socksaddr,
}

/// A repeatedly handed out address for the split-conn halves, matching
/// `transport::openvpn::packetio::PhysicalConn`'s identical `SharedAddr`.
#[derive(Debug)]
struct SharedAddr(Arc<dyn Addr>);

impl Addr for SharedAddr {
    fn network(&self) -> &str {
        self.0.network()
    }

    fn string(&self) -> String {
        self.0.string()
    }

    fn addr_port(&self) -> Option<murmur_std_compat::net::AddrPort> {
        self.0.addr_port()
    }

    fn raw_addr(&self) -> Option<&dyn Addr> {
        self.0.raw_addr()
    }

    fn as_iface_prefix(&self) -> Option<ipnet::IpNet> {
        self.0.as_iface_prefix()
    }

    fn as_sock_addr(&self) -> Option<murmur_std_compat::net::SockAddr> {
        self.0.as_sock_addr()
    }
}

impl VmessServerPacketConn {
    fn new(conn: Box<dyn Stream>, destination: murmur_sing::metadata::Socksaddr) -> Self {
        fn arc_addr(addr: std::net::SocketAddr) -> Arc<dyn Addr> {
            Arc::new(TcpAddr::from(addr))
        }
        let local_addr = conn.local_addr().ok().map(arc_addr);
        let (read, write) = tokio::io::split(conn);
        Self { read: TokioMutex::new(read), write: TokioMutex::new(write), local_addr, destination }
    }
}

#[async_trait]
impl SingPacketReader for VmessServerPacketConn {
    async fn read_packet(&self, buffer: &mut SingBuffer) -> std::io::Result<murmur_sing::metadata::Socksaddr> {
        let mut half = self.read.lock().await;
        buffer.read_once_from(&mut *half).await?;
        drop(half);
        Ok(self.destination.clone())
    }
}

#[async_trait]
impl SingPacketWriter for VmessServerPacketConn {
    async fn write_packet(
        &self,
        buffer: &SingBuffer,
        _destination: &murmur_sing::metadata::Socksaddr,
    ) -> std::io::Result<()> {
        let mut half = self.write.lock().await;
        half.write_all(buffer.bytes()).await
    }
}

#[async_trait]
impl SingPacketConnTrait for VmessServerPacketConn {
    async fn close(&self) -> std::io::Result<()> {
        let mut half = self.write.lock().await;
        half.shutdown().await
    }

    fn local_addr(&self) -> std::io::Result<Box<dyn Addr>> {
        match self.local_addr.clone() {
            Some(addr) => Ok(Box::new(SharedAddr(addr))),
            None => Err(std::io::Error::other("vmess: local address unavailable")),
        }
    }
}
struct MuxFrame {
    id: u16,
    status: u8,
    option: u8,
    network: u8,
    destination: murmur_sing::metadata::Socksaddr,
    payload: Vec<u8>,
}

struct MuxFrameReader {
    conn: ReadHalf<Box<dyn Stream>>,
}

impl MuxFrameReader {
    async fn read_frame(&mut self) -> std::io::Result<MuxFrame> {
        use std::io::{Error, ErrorKind};
        let mut size = [0; 2];
        self.conn.read_exact(&mut size).await?;
        let mut header = vec![0; u16::from_be_bytes(size) as usize];
        self.conn.read_exact(&mut header).await?;
        let [id_hi, id_lo, status, option, rest @ ..] = header.as_slice() else {
            return Err(Error::new(ErrorKind::InvalidData, "vmess mux: short frame"));
        };
        let id = u16::from_be_bytes([*id_hi, *id_lo]);
        let (network, destination) = if let [network, addr @ ..] = rest {
            let mut cursor = addr;
            (*network, mux_read_addr(&mut cursor)?)
        } else {
            (0, murmur_sing::metadata::Socksaddr::default())
        };
        let payload = if *option & 1 != 0 {
            let mut payload_size = [0; 2];
            self.conn.read_exact(&mut payload_size).await?;
            let mut payload = vec![0; u16::from_be_bytes(payload_size) as usize];
            self.conn.read_exact(&mut payload).await?;
            payload
        } else {
            Vec::new()
        };
        Ok(MuxFrame { id, status: *status, option: *option, network, destination, payload })
    }
}

fn mux_read_addr(cursor: &mut &[u8]) -> std::io::Result<murmur_sing::metadata::Socksaddr> {
    use std::io::{Error, ErrorKind};
    fn take<'a>(cursor: &mut &'a [u8], n: usize) -> std::io::Result<&'a [u8]> {
        if cursor.len() < n {
            return Err(Error::from(ErrorKind::UnexpectedEof));
        }
        let (bytes, rest) = cursor.split_at(n);
        *cursor = rest;
        Ok(bytes)
    }
    fn take_array<const N: usize>(cursor: &mut &[u8]) -> std::io::Result<[u8; N]> {
        take(cursor, N)?.try_into().map_err(|_| Error::from(ErrorKind::UnexpectedEof))
    }
    let [port_hi, port_lo] = take_array::<2>(cursor)?;
    let port = u16::from_be_bytes([port_hi, port_lo]);
    let [family] = take_array::<1>(cursor)?;
    let addr = match family {
        1 => {
            let octets = take_array::<4>(cursor)?;
            murmur_sing::metadata::Socksaddr::from_ip(std::net::IpAddr::from(octets), port)
        }
        3 => {
            let octets = take_array::<16>(cursor)?;
            murmur_sing::metadata::Socksaddr::from_ip(std::net::IpAddr::from(octets), port)
        }
        2 => {
            let [length] = take_array::<1>(cursor)?;
            murmur_sing::metadata::Socksaddr::fqdn(
                String::from_utf8(take(cursor, length as usize)?.to_vec())
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))?,
                port,
            )
        }
        _ => return Err(Error::new(ErrorKind::InvalidData, "vmess mux: invalid address family")),
    };
    Ok(addr)
}

fn mux_write_addr(wire: &mut Vec<u8>, addr: &murmur_sing::metadata::Socksaddr) -> std::io::Result<()> {
    wire.extend_from_slice(&addr.port.to_be_bytes());
    if let Some(ip) = addr.addr {
        match ip {
            std::net::IpAddr::V4(ip) => {
                wire.push(1);
                wire.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                wire.push(3);
                wire.extend_from_slice(&ip.octets());
            }
        }
    } else if !addr.fqdn.is_empty() {
        let length = u8::try_from(addr.fqdn.len())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "vmess mux: invalid destination"))?;
        wire.extend_from_slice(&[2, length]);
        wire.extend_from_slice(addr.fqdn.as_bytes());
    } else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "vmess mux: invalid destination"));
    }
    Ok(())
}

struct MuxTcpConn {
    io: tokio::io::DuplexStream,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
}

impl AsyncRead for MuxTcpConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxTcpConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl Stream for MuxTcpConn {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Ok(self.local)
    }
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Ok(self.peer)
    }
}

struct MuxUdpConn {
    id: u16,
    incoming: TokioMutex<mpsc::Receiver<(Vec<u8>, murmur_sing::metadata::Socksaddr)>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    active: Arc<TokioMutex<bool>>,
    local: std::net::SocketAddr,
}

#[async_trait]
impl SingPacketReader for MuxUdpConn {
    async fn read_packet(&self, buffer: &mut SingBuffer) -> std::io::Result<murmur_sing::metadata::Socksaddr> {
        let (payload, destination) = self
            .incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        if payload.len() > buffer.free_len() {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        buffer.write_bytes(&payload)?;
        Ok(destination)
    }
}

#[async_trait]
impl SingPacketWriter for MuxUdpConn {
    async fn write_packet(
        &self,
        buffer: &SingBuffer,
        destination: &murmur_sing::metadata::Socksaddr,
    ) -> std::io::Result<()> {
        let mut header = Vec::with_capacity(32);
        header.extend_from_slice(&self.id.to_be_bytes());
        header.extend_from_slice(&[2, 1]);
        if destination.is_valid() {
            header.push(2);
            mux_write_addr(&mut header, destination)?;
        }
        let wire = mux_data_frame(&header, buffer.bytes())?;
        let permit = self.outgoing.reserve().await.map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        let active = *self.active.lock().await;
        if !active {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        permit.send(wire);
        Ok(())
    }
}

#[async_trait]
impl SingPacketConnTrait for MuxUdpConn {
    async fn close(&self) -> std::io::Result<()> {
        *self.active.lock().await = false;
        Ok(())
    }
    fn local_addr(&self) -> std::io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::from(self.local)))
    }
}

fn mux_data_frame(header: &[u8], payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let length = u16::try_from(header.len()).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let payload_length =
        u16::try_from(payload.len()).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut wire = Vec::with_capacity(4 + header.len() + payload.len());
    wire.extend_from_slice(&length.to_be_bytes());
    wire.extend_from_slice(header);
    wire.extend_from_slice(&payload_length.to_be_bytes());
    wire.extend_from_slice(payload);
    Ok(wire)
}

async fn mux_send_data(outgoing: &mpsc::Sender<Vec<u8>>, header: &[u8], payload: &[u8]) -> std::io::Result<()> {
    outgoing
        .send(mux_data_frame(header, payload)?)
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
}

/// The sync-close path writes the `End` from a task of its own, so a full queue
/// backpressures that task instead of the receive loop. Nothing else observes those
/// tasks, so a writer that only watches the queue would read it as drained and close the
/// carrier while one still holds a frame.
#[derive(Clone, Default)]
struct MuxEndQueue {
    pending: Arc<AtomicUsize>,
    settled: Arc<Notify>,
}

impl MuxEndQueue {
    fn track(&self) {
        self.pending.fetch_add(1, Ordering::SeqCst);
    }

    fn settle(&self) {
        self.pending.fetch_sub(1, Ordering::SeqCst);
        self.settled.notify_waiters();
    }

    /// Arms the waiter before re-reading the count, so a frame settling in between is
    /// not missed.
    async fn wait_drained(&self) {
        loop {
            let mut settled = std::pin::pin!(self.settled.notified());
            settled.as_mut().enable();
            if self.pending.load(Ordering::SeqCst) == 0 {
                return;
            }
            settled.await;
        }
    }
}

/// The sync-close path. A full queue means the writer is backpressured by a
/// peer that stopped reading, not that the carrier broke, so the frame waits for capacity
/// on its own task and is counted until it lands.
fn mux_send_end(outgoing: &mpsc::Sender<Vec<u8>>, ends: &MuxEndQueue, id: u16) -> std::io::Result<()> {
    let mut frame = vec![0, 4];
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(&[3, 0]);
    match outgoing.try_send(frame) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(frame)) => {
            let outgoing = outgoing.clone();
            let ends = ends.clone();
            ends.track();
            tokio::spawn(async move {
                outgoing.send(frame).await.ok();
                ends.settle();
            });
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
    }
}

enum MuxStream {
    Tcp(WriteHalf<tokio::io::DuplexStream>),
    Udp {
        incoming: Option<mpsc::Sender<(Vec<u8>, murmur_sing::metadata::Socksaddr)>>,
        active: Arc<TokioMutex<bool>>,
        destination: murmur_sing::metadata::Socksaddr,
    },
}

struct MuxEntry {
    generation: u64,
    stream: MuxStream,
    handler: tokio::task::JoinHandle<()>,
    relay: Option<tokio::task::JoinHandle<()>>,
    ended: bool,
}

impl MuxEntry {
    /// The local-close path for a peer's `StatusEnd`: the request direction is
    /// half-closed so the handler reads EOF, while the response direction keeps draining
    /// until the handler returns.
    async fn half_close(&mut self) {
        if self.ended {
            return;
        }
        self.ended = true;
        match &mut self.stream {
            MuxStream::Tcp(write) => {
                let _ = write.shutdown().await;
            }
            MuxStream::Udp { incoming, .. } => *incoming = None,
        }
    }

    /// the `StatusNew` overwrites the map entry and leaves the replaced handler running,
    /// so a TCP session's response still reaches the peer under the id it just reused.
    /// Aborting the handler would discard those bytes, so only the handles are dropped and
    /// the relay runs on to the handler's EOF. A UDP session has no such drain — its
    /// retained writer must stop, or it would answer the peer's new session.
    async fn retire(mut self) {
        self.half_close().await;
        if let MuxStream::Udp { active, .. } = &self.stream {
            *active.lock().await = false;
            Self::stop_task(self.handler).await;
        }
    }

    /// The cleanup path for a session still running when the carrier goes away.
    async fn finish(mut self) {
        self.half_close().await;
        match &self.stream {
            MuxStream::Tcp(_) => Self::stop_relay(&mut self.relay).await,
            MuxStream::Udp { active, .. } => {
                *active.lock().await = false;
                // The handler owns the `MuxUdpConn` and with it the session's `outgoing`
                // clone. The handler ends by closing its pipe; a handler that never
                // returns would keep the frame queue, and the carrier's FIN, open.
                Self::stop_task(self.handler).await;
                Self::stop_relay(&mut self.relay).await;
            }
        }
    }

    /// the session is done, so stop the handler and the relay.
    async fn close(mut self) {
        self.half_close().await;
        match &self.stream {
            // No await: this runs on the receive loop and the handler holds no sender.
            MuxStream::Tcp(_) => self.handler.abort(),
            MuxStream::Udp { active, .. } => {
                *active.lock().await = false;
                Self::stop_task(self.handler).await;
            }
        }
        Self::stop_relay(&mut self.relay).await;
    }

    /// The relay owns the session's `outgoing` clone, and `abort` is asynchronous: the task
    /// is dropped — clone released — only once the handle is awaited.
    async fn stop_relay(relay: &mut Option<tokio::task::JoinHandle<()>>) {
        if let Some(relay) = relay.take() {
            Self::stop_task(relay).await;
        }
    }

    async fn stop_task(task: tokio::task::JoinHandle<()>) {
        task.abort();
        let _ = task.await;
    }
}

/// Ends in the carrier's only graceful FIN, which runs after the last queued frame, so the
/// queue is drained first. `closing` is the teardown's end-of-queue signal for the senders
/// this task cannot own: a `MuxUdpConn` a tunnel kept alive past its session holds one, and
/// nothing else would end the queue.
// NOT cancel-safe: a drop mid-write leaves a partial frame on the carrier, so the only caller that aborts it is the non-graceful teardown that discards that carrier.
async fn mux_write_frames<W: AsyncWrite + Unpin>(
    mut write: W,
    mut receiver: mpsc::Receiver<Vec<u8>>,
    closing: CancellationToken,
    ends: MuxEndQueue,
) -> std::io::Result<()> {
    let mut draining = false;
    loop {
        let frame = if draining {
            // `try_recv` keeps a sender this task does not own from holding it open, but
            // it cannot see a deferred `End` still waiting for capacity. The queue reads
            // empty first, so wait for the outstanding ones rather than closing the
            // carrier in front of them.
            match receiver.try_recv() {
                Ok(frame) => Some(frame),
                Err(_) if ends.pending.load(Ordering::SeqCst) > 0 => {
                    ends.wait_drained().await;
                    continue;
                }
                Err(_) => None,
            }
        } else {
            tokio::select! {
                frame = receiver.recv() => frame,
                () = closing.cancelled() => {
                    draining = true;
                    continue;
                }
            }
        };
        let Some(frame) = frame else { break };
        write.write_all(&frame).await?;
        write.flush().await?;
    }
    write.shutdown().await
}

/// The cleanup path, reached from the task the mux-connection handler starts on cancellation and
/// from the receive loop returning. Frames are written inline under the write lock, so closing the conn is
/// the whole teardown; here a task owns the write half, so the order is
/// load-bearing and the writer is handed back rather than waited on — the writes to the conn
/// are no more tied to the mux-connection handler returning, and a peer that stopped reading must
/// not hold the teardown up.
async fn mux_teardown(
    reader: tokio::task::JoinHandle<()>,
    mut writer: tokio::task::JoinHandle<std::io::Result<()>>,
    closing: CancellationToken,
    outgoing: mpsc::Sender<Vec<u8>>,
    mut streams: std::collections::HashMap<u16, MuxEntry>,
    graceful: bool,
) -> tokio::task::JoinHandle<std::io::Result<()>> {
    reader.abort();
    drop(outgoing);
    for (_, entry) in streams.drain() {
        if graceful {
            entry.finish().await;
        } else {
            entry.close().await;
        }
    }
    if graceful {
        closing.cancel();
        return writer;
    }
    writer.abort();
    let _ = std::pin::Pin::new(&mut writer).await;
    writer
}

// cancel-safe: the task owns nothing outside itself, so aborting it only drops the handler's pipe, which is the teardown its callers ask for.
async fn handle_vmess_mux_connection(
    handler: &ListenerHandler,
    ctx: SingContext,
    conn: Box<dyn Stream>,
    metadata: SingMetadata,
) -> Result<()> {
    use std::collections::HashMap;
    let local = conn.local_addr()?;
    let peer = conn.peer_addr()?;
    let (read, write) = tokio::io::split(conn);
    let (outgoing, receiver) = mpsc::channel::<Vec<u8>>(32);
    let closing = CancellationToken::new();
    let ends = MuxEndQueue::default();
    let writer = tokio::spawn(mux_write_frames(write, receiver, closing.clone(), ends.clone()));
    let (reader, mut frames) = spawn_mux_frame_reader(read);
    let (finished, mut completed) = mpsc::unbounded_channel::<(u16, u64)>();
    let sessions = MuxSessionContext {
        handler,
        ctx: &ctx,
        metadata: &metadata,
        local,
        peer,
        outgoing: &outgoing,
        finished: &finished,
    };
    let mut streams = HashMap::<u16, MuxEntry>::new();
    let mut generation = 0u64;
    let result: Result<()> = loop {
        let frame = tokio::select! {
            event = completed.recv() => {
                if let Some((id, version)) = event {
                    if streams.get(&id).is_some_and(|entry| entry.generation == version) {
                        if let Some(entry) = streams.remove(&id) { entry.close().await; }
                        if let Err(err) = mux_send_end(&outgoing, &ends, id) { break Err(err.into()); }
                    }
                }
                continue;
            }
            frame = frames.recv() => match frame {
                Some(Ok(frame)) => frame,
                Some(Err(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => break Ok(()),
                Some(Err(err)) => break Err(err.into()),
                None => break Ok(()),
            }
        };
        match frame.status {
            1 => {
                if streams.get(&frame.id).is_some_and(|entry| !entry.ended) {
                    break Err(anyhow!("vmess mux: duplicate session id"));
                }
                // The map entry is overwritten while the old handler keeps running, so an ended
                // session's response still reaches the peer under the reused id.
                if let Some(entry) = streams.remove(&frame.id) {
                    entry.retire().await;
                }
                generation = generation.wrapping_add(1);
                let entry = match sessions.build(&frame, generation) {
                    Ok(entry) => entry,
                    Err(err) => break Err(err),
                };
                streams.insert(frame.id, entry);
            }
            2 => {
                // The map entry is deleted on local close, so a Keep arriving after an End finds
                // nothing and is answered with a synchronised close for that id.
                if streams.get(&frame.id).is_none_or(|entry| entry.ended) {
                    if let Err(err) = mux_send_end(&outgoing, &ends, frame.id) {
                        break Err(err.into());
                    }
                    continue;
                }
            }
            3 => {
                if let Some(entry) = streams.get_mut(&frame.id) {
                    entry.half_close().await;
                }
                continue;
            }
            4 => continue,
            other => break Err(anyhow!("vmess mux: bad session status {other}")),
        }
        if frame.option & 1 != 0 && !frame.payload.is_empty() {
            if let Err(err) = deliver_mux_payload(&mut streams, frame, &outgoing, &ends).await {
                break Err(err.into());
            }
        }
    };
    mux_teardown(reader, writer, closing, outgoing, streams, result.is_ok()).await;
    result
}

/// Spawns the frame reader and hands back its task handle and the channel the frames arrive
/// on. The task ends the channel on the first read error, and a drop loses at most the frame
/// in flight on a carrier that is going away.
fn spawn_mux_frame_reader(
    conn: ReadHalf<Box<dyn Stream>>,
) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<std::io::Result<MuxFrame>>) {
    let (frames_tx, frames) = mpsc::channel(32);
    let task = tokio::spawn(async move {
        let mut reader = MuxFrameReader { conn };
        loop {
            let frame = reader.read_frame().await;
            let end = frame.is_err();
            if frames_tx.send(frame).await.is_err() || end {
                break;
            }
        }
    });
    (task, frames)
}

/// Delivers a payload frame to the session it names and tears that session down when the
/// delivery fails; the `End` answering a failed delivery is the caller's to send.
async fn deliver_mux_payload(
    streams: &mut std::collections::HashMap<u16, MuxEntry>,
    frame: MuxFrame,
    outgoing: &mpsc::Sender<Vec<u8>>,
    ends: &MuxEndQueue,
) -> std::io::Result<()> {
    let MuxFrame { id, destination, payload, .. } = frame;
    let failed = match streams.get_mut(&id) {
        // The missing-stream branch: payload for a session the receive loop does
        // not own is read off the wire and discarded.
        None => false,
        Some(entry) => match &mut entry.stream {
            MuxStream::Tcp(write) => write.write_all(&payload).await.is_err(),
            MuxStream::Udp { incoming, destination: session_destination, .. } => {
                let target = if destination.is_valid() { destination } else { session_destination.clone() };
                match incoming {
                    Some(incoming) => incoming.send((payload, target)).await.is_err(),
                    None => false,
                }
            }
        },
    };
    if !failed {
        return Ok(());
    }
    if let Some(entry) = streams.remove(&id) {
        entry.close().await;
    }
    mux_send_end(outgoing, ends, id)
}

/// The per-connection state a NEW frame's entry needs: the handler and request context it
/// runs under, and the queue its tasks write into.
struct MuxSessionContext<'a> {
    handler: &'a ListenerHandler,
    ctx: &'a SingContext,
    metadata: &'a SingMetadata,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    outgoing: &'a mpsc::Sender<Vec<u8>>,
    finished: &'a mpsc::UnboundedSender<(u16, u64)>,
}

impl MuxSessionContext<'_> {
    /// Spawns the session's TCP relay or UDP packet conn and returns its map entry.
    fn build(&self, frame: &MuxFrame, version: u64) -> Result<MuxEntry> {
        let id = frame.id;
        let stream_metadata = SingMetadata { destination: frame.destination.clone(), ..self.metadata.clone() };
        match frame.network {
            1 => {
                let (server, bridge) = tokio::io::duplex(65536);
                let (mut bridge_read, bridge_write) = tokio::io::split(bridge);
                let sender = self.outgoing.clone();
                let closed = self.finished.clone();
                let relay = tokio::spawn(async move {
                    let mut payload = [0u8; 15000];
                    while let Ok(n) = bridge_read.read(&mut payload).await {
                        if n == 0 {
                            break;
                        }
                        let id_bytes = id.to_be_bytes();
                        let header = [id_bytes[0], id_bytes[1], 2, 1];
                        let Some(chunk) = payload.get(..n) else { break };
                        if mux_send_data(&sender, &header, chunk).await.is_err() {
                            break;
                        }
                    }
                    let _ = closed.send((id, version));
                });
                let handler = self.handler.clone();
                let stream: Box<dyn Stream> = Box::new(MuxTcpConn { io: server, local: self.local, peer: self.peer });
                let ctx = self.ctx.clone();
                let worker = tokio::spawn(async move {
                    let _ = handler.new_connection(ctx, stream, stream_metadata).await;
                });
                Ok(MuxEntry {
                    generation: version,
                    stream: MuxStream::Tcp(bridge_write),
                    handler: worker,
                    relay: Some(relay),
                    ended: false,
                })
            }
            2 => {
                let (incoming_tx, incoming_rx) = mpsc::channel(32);
                let active = Arc::new(TokioMutex::new(true));
                let packet: Box<dyn network::PacketConn> = Box::new(MuxUdpConn {
                    id,
                    incoming: TokioMutex::new(incoming_rx),
                    outgoing: self.outgoing.clone(),
                    local: self.local,
                    active: Arc::clone(&active),
                });
                let handler = self.handler.clone();
                let ctx = self.ctx.clone();
                let closed = self.finished.clone();
                let worker = tokio::spawn(async move {
                    let _ = handler.new_packet_connection(ctx, packet, stream_metadata).await;
                    let _ = closed.send((id, version));
                });
                Ok(MuxEntry {
                    generation: version,
                    stream: MuxStream::Udp {
                        incoming: Some(incoming_tx),
                        destination: frame.destination.clone(),
                        active,
                    },
                    handler: worker,
                    relay: None,
                    ended: false,
                })
            }
            other => Err(anyhow!("vmess mux: bad network {other}")),
        }
    }
}

/// Wraps the sing-vmess service.
struct VmessService {
    handler: ListenerHandler,
    inner: VmessSingService,
}

impl VmessService {
    fn update_users(&self, usernames: &[String], uuids: &[String], alter_ids: &[i32]) -> Result<()> {
        self.inner.update_users(usernames, uuids, alter_ids)
    }

    const fn start() {}

    const fn close() {}

    async fn new_connection(&self, ctx: SingContext, conn: Box<dyn Stream>, mut metadata: SingMetadata) -> Result<()> {
        // S11: remove with murmur-std-compat, once murmur_transport_vmess::sing::service::Service::accept
        // takes/returns Stream.
        let old_conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(conn));
        let accepted = self.inner.accept(old_conn).await?;
        metadata.destination = accepted.destination.clone();
        let ctx = murmur_listener_sing::context::with_user(&ctx, accepted.username.clone());
        let conn: Box<dyn Stream> = Box::new(OldConnAsStream(accepted.conn));
        match accepted.command {
            COMMAND_TCP if metadata.destination.fqdn == VMESS_MUX_FQDN => {
                handle_vmess_mux_connection(&self.handler, ctx, conn, metadata).await
            }
            COMMAND_TCP => self.handler.new_connection(ctx, conn, metadata).await,
            COMMAND_UDP => {
                let pc: Box<dyn network::PacketConn> =
                    Box::new(VmessServerPacketConn::new(conn, metadata.destination.clone()));
                self.handler.new_packet_connection(ctx, pc, metadata).await
            }
            3 => handle_vmess_mux_connection(&self.handler, ctx, conn, metadata).await,
            other => Err(anyhow!("sing-vmess: unknown command {other}")),
        }
    }
}

pub struct Listener {
    closed: AtomicBool,
    config: VmessServer,
    listeners: Mutex<Vec<Arc<dyn Acceptor>>>,
    service: Arc<VmessService>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

/// the package-level `var _listener *Listener`.
static LAST_DEFAULT_LISTENER: Mutex<Option<Arc<Listener>>> = Mutex::new(None);

pub async fn new(
    config: VmessServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<Listener>> {
    let use_default = additions.is_empty();
    let result = new_inner(config, lc, tunnel, additions).await;
    if use_default {
        *LAST_DEFAULT_LISTENER.lock() = result.as_ref().ok().cloned();
    }
    result
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear constructor: it wires TLS, the transport layers and the users, then starts the listener loops"
)]
async fn new_inner(
    config: VmessServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<Listener>> {
    let additions =
        if additions.is_empty() { vec![with_in_name("DEFAULT-VMESS"), with_special_rules("")] } else { additions };

    let mut tls_mirror_builder = None;
    let mut handler_tunnel = Arc::clone(&tunnel);
    if !config.tls_mirror_config.primary_key.is_empty() {
        let tls_mirror_config = tlsmirror::tlsmirror::Config {
            primary_key: config.tls_mirror_config.primary_key.clone(),
            dest: config.tls_mirror_config.dest.clone(),
            proxy: config.tls_mirror_config.proxy.clone(),
            explicit_nonce_cipher_suites: config.tls_mirror_config.explicit_nonce_cipher_suites.clone(),
            defer_instance_derived_write_time: config.tls_mirror_config.defer_instance_derived_write_time.build(),
            transport_layer_padding: config.tls_mirror_config.transport_layer_padding.build(),
            connection_enrolment: TLSMirrorConnectionEnrolment::build(
                config.tls_mirror_config.connection_enrolment.as_ref(),
            ),
            sequence_watermarking_enabled: config.tls_mirror_config.sequence_watermarking_enabled,
        };
        let builder = tls_mirror_config.build(Arc::clone(&tunnel));
        handler_tunnel = builder.wrap_tunnel(Arc::clone(&tunnel));
        tls_mirror_builder = Some(builder);
    }

    let h = new_listener_handler(SingListenerConfig {
        tunnel: handler_tunnel,
        type_: Type::VMESS,
        additions: additions.clone(),
        udp_timeout: std::time::Duration::default(),
        mux_option: config.mux_option.clone(),
    })?;

    validate_mekya_transport(&config)?;

    let service = Arc::new(VmessService { handler: h, inner: VmessSingService::new(ntp_now) });
    service.update_users(
        &config.users.iter().map(|u| u.username.clone()).collect::<Vec<_>>(),
        &config.users.iter().map(|u| u.uuid.clone()).collect::<Vec<_>>(),
        &config.users.iter().map(|u| u.alter_id).collect::<Vec<_>>(),
    )?;
    VmessService::start();

    // The listener is assigned here, before the TLS/handler setup below, so the
    // WebSocket-path/gRPC closures can already capture it by value; `listeners` fills in as
    // each address is bound further down.
    let sl = Arc::new(Listener {
        closed: AtomicBool::new(false),
        config: config.clone(),
        listeners: Mutex::new(Vec::new()),
        service,
    });

    let mut tls_config = build_tls_config(&config)?;
    validate_security_modes(&config, tls_config.get_certificate.is_some())?;

    let shadow_tls_builder = if config.shadow_tls.enable {
        Some(shadowtls::listener::new(&config.shadow_tls, Arc::clone(&tunnel))?)
    } else {
        None
    };

    let jls_builder =
        if config.jls_config.enable { Some(jls::new(&config.jls_config, Arc::clone(&tunnel))?) } else { None };
    let reality_server_config =
        config.reality_config.as_ref().map(|c| crate::reality::build_server_config(c, Arc::clone(&tunnel)));

    let handler = build_gun_handler(&config, &sl, &tunnel, &additions, &mut tls_config);

    for addr in config.listen.split(',') {
        let l: Box<dyn Acceptor> = if config.mkcp_config.enable {
            let pc: Box<dyn murmur_std_compat::net::PacketConn> =
                Box::new(murmur_common_net::io::DatagramAsOldPacketConn(
                    lc.listen_packet(&CancellationToken::new(), "udp", addr).await?,
                ));
            // The packet conn is closed here on an error path; `mkcp::listener::listen` takes it by value,
            // so a failed call already drops it, and the underlying socket's own
            // `Drop` releases its fd the same way an explicit close would.
            let old_l = mkcp::listener::listen(&CancellationToken::new(), pc, config.mkcp_config.build()).await?;
            Box::new(murmur_common_net::io::OldListenerAsAcceptor(old_l))
        } else {
            lc.listen(&CancellationToken::new(), "tcp", addr).await?
        };

        let l = if let Some(builder) = &shadow_tls_builder {
            builder.new_listener(l)
        } else if let Some(builder) = &jls_builder {
            builder.new_listener(l)
        } else if let Some(builder) = &tls_mirror_builder {
            builder.new_listener(l)
        } else if tls_config.get_certificate.is_some() {
            let tls_config = Arc::new(tls_config.clone());
            tls_c::new_listener(Arc::from(l), tls_config)
        } else {
            l
        };

        let l: Box<dyn Acceptor> = if config.mekya_config.enable {
            let old_l: Box<dyn NetListener> = Box::new(murmur_common_net::io::AcceptorAsOldListener(l));
            let mekya_l = mekya::server::listen(&CancellationToken::new(), old_l, config.mekya_config.build()).await?;
            Box::new(murmur_common_net::io::OldListenerAsAcceptor(mekya_l))
        } else {
            l
        };

        let l: Arc<dyn Acceptor> = Arc::from(l);
        sl.listeners.lock().push(Arc::clone(&l));
    }

    let bound: Vec<Arc<dyn Acceptor>> = sl.listeners.lock().iter().map(Arc::clone).collect();
    for l in bound {
        let sl = Arc::clone(&sl);
        let tunnel = Arc::clone(&tunnel);
        let _additions = additions.clone();
        let handler = handler.clone();
        let reality_server_config = reality_server_config.clone();
        tokio::spawn(async move {
            if let Some(handler) = handler {
                loop {
                    let Ok(conn) = l.accept().await else {
                        if sl.closed.load(Ordering::SeqCst) {
                            break;
                        }
                        continue;
                    };
                    let handler = Arc::clone(&handler);
                    crate::reality::spawn_conn(conn, reality_server_config.clone(), move |conn| async move {
                        serve_http_conn(handler, conn).await;
                    });
                }
                return;
            }
            loop {
                let Ok(conn) = l.accept().await else {
                    if sl.closed.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                };
                let sl = Arc::clone(&sl);
                let tunnel = Arc::clone(&tunnel);
                crate::reality::spawn_conn(conn, reality_server_config.clone(), move |conn| async move {
                    sl.handle_conn(conn, tunnel, Vec::new()).await;
                });
            }
        });
    }

    Ok(sl)
}

/// Builds the server TLS config: the certificate/key pair, the optional ECH key, and the
/// client-auth policy the handlers verify against.
fn build_tls_config(config: &VmessServer) -> Result<TlsConfig> {
    let mut tls_config = crate::tls_server_config(Arc::new(ntp_now));

    if !config.certificate.is_empty() && !config.private_key.is_empty() {
        let cert_loader = new_tls_key_pair_loader(&config.certificate, &config.private_key)?;
        tls_config.get_certificate = Some(Arc::new(move |_info: &ClientHelloInfo| cert_loader().map(Some)));

        if !config.ech_key.is_empty() {
            load_ech_key(&config.ech_key, &mut tls_config)?;
        }
    }
    tls_config.client_auth = client_auth_type_from_string(&config.client_auth_type);
    if !config.client_auth_cert.is_empty() && tls_config.client_auth == NO_CLIENT_CERT {
        tls_config.client_auth = REQUIRE_AND_VERIFY_CLIENT_CERT;
    }
    if tls_config.client_auth == VERIFY_CLIENT_CERT_IF_GIVEN || tls_config.client_auth == REQUIRE_AND_VERIFY_CLIENT_CERT
    {
        tls_config.client_cas = Some(load_certificates(&config.client_auth_cert)?);
    }
    if tls_config.client_auth != NO_CLIENT_CERT && tls_config.get_certificate.is_none() {
        return Err(anyhow!("client-auth requires certificate"));
    }
    Ok(tls_config)
}

/// Rejects the security modes that cannot be combined, or that the configured transport
/// cannot carry.
fn validate_security_modes(config: &VmessServer, has_certificate: bool) -> Result<()> {
    let mut security_modes: Vec<&str> = Vec::with_capacity(6);
    if has_certificate {
        security_modes.push("certificate");
    }
    if config.reality_config.is_some() {
        security_modes.push("reality");
    }
    if !config.tls_mirror_config.primary_key.is_empty() {
        security_modes.push("tlsmirror");
    }
    if config.shadow_tls.enable {
        security_modes.push("shadow-tls");
    }
    if config.res_tls.enable {
        return Err(anyhow!("res-tls is not supported: Restls has no Rust implementation (see README)"));
    }
    if config.jls_config.enable {
        security_modes.push("jls");
    }
    if security_modes.len() > 1 {
        return Err(anyhow!("security modes are mutually exclusive: {}", security_modes.join(", ")));
    }
    let tcp_only_security_mode = if config.jls_config.enable {
        "JLS"
    } else if config.shadow_tls.enable {
        "ShadowTLS"
    } else {
        ""
    };
    if config.mkcp_config.enable && !tcp_only_security_mode.is_empty() {
        return Err(anyhow!("{tcp_only_security_mode} only supports TCP transports"));
    }
    Ok(())
}

/// Mekya carries neither the mkcp transport nor the HTTP front-ends.
fn validate_mekya_transport(config: &VmessServer) -> Result<()> {
    if !config.mekya_config.enable {
        return Ok(());
    }
    if config.mkcp_config.enable {
        return Err(anyhow!("mkcp-config is unavailable in mekya"));
    }
    if !config.ws_path.is_empty() || !config.grpc_service_name.is_empty() {
        return Err(anyhow!("ws and grpc are unavailable in mekya"));
    }
    Ok(())
}

/// Builds the WebSocket/gRPC front-end handler and records the ALPN protocols it needs on
/// `tls_config`.
fn build_gun_handler(
    config: &VmessServer,
    sl: &Arc<Listener>,
    tunnel: &Arc<dyn Tunnel>,
    additions: &[Addition],
    tls_config: &mut TlsConfig,
) -> Option<Arc<dyn GunHandler>> {
    let mut handler: Option<Arc<dyn GunHandler>> = None;
    if !config.ws_path.is_empty() {
        handler = Some(Arc::new(WsMuxHandler {
            ws_path: config.ws_path.clone(),
            sl: Arc::clone(sl),
            tunnel: Arc::clone(tunnel),
            additions: additions.to_vec(),
        }));
        tls_config.next_protos.push("http/1.1".to_owned());
    }
    if !config.grpc_service_name.is_empty() {
        let http_handler = handler.take();
        let sl_for_grpc = Arc::clone(sl);
        let tunnel_for_grpc = Arc::clone(tunnel);
        let additions_for_grpc = additions.to_vec();
        let conn_handler: GunConnHandler = Arc::new(move |conn: Box<dyn SingExtendedConn>| {
            let conn: Box<dyn Stream> = conn;
            let sl = Arc::clone(&sl_for_grpc);
            let tunnel = Arc::clone(&tunnel_for_grpc);
            let additions = additions_for_grpc.clone();
            Box::pin(async move { sl.handle_conn(conn, tunnel, additions).await })
        });
        handler = Some(Arc::new(gun_new_server_handler(GunServerOption {
            service_name: config.grpc_service_name.clone(),
            conn_handler,
            http_handler,
        })));
        tls_config.next_protos.insert(0, "h2".to_owned());
    }
    if config.mekya_config.enable {
        if !tls_config.next_protos.iter().any(|p| p == "http/1.1") {
            tls_config.next_protos.insert(0, "http/1.1".to_owned());
        }
        if !tls_config.next_protos.iter().any(|p| p == "h2") {
            tls_config.next_protos.insert(0, "h2".to_owned());
        }
    }
    handler
}

impl MultiAddrListener for Listener {
    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        let mut ret_err: Option<anyhow::Error> = None;
        for lis in self.listeners.lock().iter() {
            if let Err(err) = lis.close() {
                ret_err = Some(err.into());
            }
        }
        VmessService::close();
        ret_err.map_or(Ok(()), Err)
    }

    fn config(&self) -> String {
        self.config.to_string()
    }

    fn addr_list(&self) -> Vec<Box<dyn Addr>> {
        fn boxed_addr(addr: std::net::SocketAddr) -> Box<dyn Addr> {
            Box::new(TcpAddr::from(addr))
        }
        self.listeners.lock().iter().filter_map(|lis| lis.addr().ok()).map(boxed_addr).collect()
    }
}

impl Listener {
    async fn handle_conn(&self, conn: Box<dyn Stream>, _tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) {
        let ctx = murmur_listener_sing::context::with_additions(&SingContext::default(), additions);
        let metadata = SingMetadata {
            protocol: "vmess".to_owned(),
            source: sing_socksaddr_from_net(conn.peer_addr().ok()),
            destination: murmur_sing::metadata::Socksaddr::default(),
        };
        new_connection_closing_on_error(&self.service, ctx, conn, metadata).await;
    }
}

/// The connection handler still holds the conn after the service returns (passing an interface
/// value copies an interface header), so it can close the conn when the service fails. Here the
/// service takes the conn by value, so the caller keeps a [`SharedConn`] clone instead; it answers
/// `Stream::old_conn` with itself, so the service's own close/deadline surface is unchanged.
async fn new_connection_closing_on_error(
    service: &VmessService,
    ctx: SingContext,
    conn: Box<dyn Stream>,
    metadata: SingMetadata,
) {
    let conn = SharedConn::new(StreamAsOldConn::new(conn));
    let closer = conn.clone();
    if service.new_connection(ctx, Box::new(conn), metadata).await.is_err() {
        let _ = closer.close();
    }
}

/// A SOCKS address built from a socket address, narrowed to what the connection handler needs.
fn sing_socksaddr_from_net(addr: Option<std::net::SocketAddr>) -> murmur_sing::metadata::Socksaddr {
    use murmur_sing::metadata::Socksaddr;
    match addr {
        Some(addr) => Socksaddr { fqdn: String::new(), addr: Some(addr.ip()), port: addr.port() },
        None => Socksaddr::default(),
    }
}

pub fn handle_vmess(conn: Box<dyn Stream>, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) -> bool {
    let listener = LAST_DEFAULT_LISTENER.lock().clone();
    if let Some(sl) = listener {
        tokio::spawn(async move { sl.handle_conn(conn, tunnel, additions).await });
        return true;
    }
    false
}

/// The `vmess://` URL parser.
///
/// A multi-host-capable fork of the standard parser is needed
/// because the standard parser and the `url` crate both reject a comma-separated host such as
/// `vmess://user:pass@host1,host2,host3`; this is a small purpose-built
/// scheme/userinfo/host splitter (the same stand-in as
/// `listener::shadowsocks::utils::parse_ss_url`) rather than a full RFC 3986 URL parser.
pub fn parse_vmess_url(s: &str) -> Result<(String, String, String)> {
    let (_, rest) = s.split_once("://").ok_or_else(|| anyhow!("missing protocol scheme"))?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, _) = rest.split_at(authority_end);

    let (userinfo, host_part) = match authority.rfind('@') {
        Some(i) => {
            let (userinfo, host_part) = authority.split_at(i);
            (Some(userinfo), host_part.strip_prefix('@').unwrap_or(host_part))
        }
        None => (None, authority),
    };

    let addr = host_part.to_owned();

    let (username, password) = match userinfo {
        Some(info) => match info.split_once(':') {
            Some((user, pass)) => (percent_decode(user)?, percent_decode(pass)?),
            None => (percent_decode(info)?, String::new()),
        },
        None => (String::new(), String::new()),
    };

    Ok((addr, username, password))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

    use super::*;

    #[test]
    fn shadow_tls_and_jls_are_mutually_exclusive() {
        let config = VmessServer {
            shadow_tls: murmur_listener_config::shadowtls::ShadowTLS { enable: true, ..Default::default() },
            jls_config: murmur_listener_config::jls::JLSConfig { enable: true, ..Default::default() },
            ..VmessServer::default()
        };
        let err = validate_security_modes(&config, false).expect_err("both tcp-only modes must be rejected");
        assert_eq!(err.to_string(), "security modes are mutually exclusive: shadow-tls, jls");
    }

    #[tokio::test]
    async fn mux_writer_flushes_final_frame_while_session_remains_open() {
        let (server, mut client) = tokio::io::duplex(4096);
        let (tx, rx) = mpsc::channel(1);
        let writer = tokio::spawn(mux_write_frames(
            tokio::io::BufWriter::new(server),
            rx,
            CancellationToken::new(),
            MuxEndQueue::default(),
        ));
        tx.send(b"reply".to_vec()).await.unwrap();
        let mut reply = [0; 5];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply)).await.unwrap().unwrap();
        assert_eq!(&reply, b"reply");
        drop(tx);
        tokio::time::timeout(Duration::from_secs(2), writer).await.unwrap().unwrap().unwrap();
    }

    #[tokio::test]
    async fn mux_udp_session_close_is_not_blocked_by_backpressured_reply() {
        let (outgoing, mut receiver) = mpsc::channel(1);
        outgoing.send(vec![1]).await.unwrap();
        let (incoming, received) = mpsc::channel(1);
        let active = Arc::new(TokioMutex::new(true));
        let conn = MuxUdpConn {
            id: 7,
            incoming: TokioMutex::new(received),
            outgoing,
            local: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            active: Arc::clone(&active),
        };
        let mut blocked = tokio::spawn(async move {
            conn.write_packet(
                &murmur_compat::sing_buf::as_(b"reply".to_vec()),
                &murmur_sing::metadata::Socksaddr::default(),
            )
            .await
        });
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut blocked).await.is_err());
        let entry = MuxEntry {
            generation: 1,
            stream: MuxStream::Udp {
                incoming: Some(incoming),
                destination: murmur_sing::metadata::Socksaddr::default(),
                active,
            },
            handler: tokio::spawn(async {}),
            relay: None,
            ended: false,
        };
        tokio::time::timeout(Duration::from_secs(2), entry.close()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), receiver.recv()).await.unwrap().unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(2), blocked).await.unwrap().unwrap().is_err());
    }

    #[tokio::test]
    async fn mux_teardown_flushes_queued_frames_before_the_carrier_fin() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (mut read, write) = tokio::io::split(server);
        let (outgoing, receiver) = mpsc::channel::<Vec<u8>>(32);
        let closing = CancellationToken::new();
        let ends = MuxEndQueue::default();
        let writer = tokio::spawn(mux_write_frames(write, receiver, closing.clone(), ends.clone()));
        let reader = tokio::spawn(async move {
            let mut inbound = Vec::new();
            let _ = read.read_to_end(&mut inbound).await;
        });
        // A session's reply and the `End` behind it are both still queued when the peer
        // half-closes, and both have to reach it ahead of the EOF.
        mux_send_data(&outgoing, &[0, 9, 2, 1], b"foo").await.unwrap();
        mux_send_end(&outgoing, &ends, 9).unwrap();
        let expected = [
            0, 4, 0, 9, 2, 1, 0, 3, b'f', b'o', b'o', // the reply
            0, 4, 0, 9, 3, 0, // the End behind it
        ];

        let writer = mux_teardown(reader, writer, closing, outgoing, std::collections::HashMap::new(), true).await;
        tokio::time::timeout(Duration::from_secs(2), writer).await.unwrap().unwrap().unwrap();

        let mut written = vec![0; expected.len()];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut written)).await.unwrap().unwrap();
        assert_eq!(written, expected);
        let mut rest = [0; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut rest)).await.unwrap().unwrap();
        assert_eq!(read, 0, "the carrier must end in the writer's shutdown");
    }

    /// A deferred `End` waits on a task of its own, invisible to the writer. Without the
    /// count, the writer reads the momentarily empty queue as drained and closes the
    /// carrier, so the peer never learns the session ended.
    #[tokio::test]
    async fn mux_teardown_flushes_a_deferred_end_frame_before_the_carrier_fin() {
        let (server, mut client) = tokio::io::duplex(1);
        let (outgoing, receiver) = mpsc::channel::<Vec<u8>>(1);
        let closing = CancellationToken::new();
        let ends = MuxEndQueue::default();
        // A one-byte carrier: the filler parks the writer inside `write_all` until the
        // client reads, so the queue is provably still full when the `End` is deferred.
        let writer = tokio::spawn(mux_write_frames(server, receiver, closing.clone(), ends.clone()));

        outgoing.send(vec![0]).await.unwrap();
        mux_send_end(&outgoing, &ends, 9).unwrap();
        assert!(ends.pending.load(Ordering::SeqCst) > 0, "the End must be deferred, not inline");

        let drained = tokio::spawn({
            let ends = ends.clone();
            async move { ends.wait_drained().await }
        });
        closing.cancel();
        let mut filler = [0; 1];
        client.read_exact(&mut filler).await.unwrap();
        let mut end = [0; 6];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut end)).await.unwrap().unwrap();
        assert_eq!(end, [0, 4, 0, 9, 3, 0], "the deferred End must reach the peer ahead of the FIN");
        tokio::time::timeout(Duration::from_secs(2), drained).await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(2), writer).await.unwrap().unwrap().unwrap();

        let mut rest = [0; 1];
        assert_eq!(client.read(&mut rest).await.unwrap(), 0, "the carrier must end in the writer's shutdown");
    }

    struct DuplexConn(tokio::io::DuplexStream);

    impl AsyncRead for DuplexConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DuplexConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl Stream for DuplexConn {
        fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }

        fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }
    }

    #[test]
    fn test_parse_vmess_url() {
        let cases = [
            ("username", "password", ":1000,:2000,:3000"),
            ("username", "password", "127.0.0.1:1000,127.0.0.1:2000,127.0.0.1:3000"),
            ("username", "password", "[::1]:1000,[::1]:2000,[::1]:3000"),
        ];
        for (username, passwd, hosts) in cases {
            let url = format!("vmess://{username}:{passwd}@{hosts}");
            let (addr, got_username, got_password) = parse_vmess_url(&url).expect("parse succeeds");
            assert_eq!(addr, hosts);
            assert_eq!(got_username, username);
            assert_eq!(got_password, passwd);
        }
    }

    /// Review finding 5: `read_packet` held its lock across the read await, so a
    /// reply from `write_packet` stalled behind a pending read from a silent peer.
    #[tokio::test]
    async fn test_write_packet_not_blocked_by_pending_read_packet() {
        let (server_io, mut client_io) = tokio::io::duplex(4096);
        let server_conn: Box<dyn Stream> = Box::new(DuplexConn(server_io));
        let destination = murmur_sing::metadata::Socksaddr::default();
        let pc = Arc::new(VmessServerPacketConn::new(server_conn, destination.clone()));

        let reader = Arc::clone(&pc);
        let read_task = tokio::spawn(async move {
            let mut buffer = murmur_compat::sing_buf::new_size(murmur_compat::sing_buf::UDP_BUFFER_SIZE);
            let _ = reader.read_packet(&mut buffer).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!read_task.is_finished(), "read_packet must still be pending on a silent peer");

        let write_buffer = murmur_compat::sing_buf::as_(b"hello".to_vec());
        let write_result =
            tokio::time::timeout(Duration::from_secs(2), pc.write_packet(&write_buffer, &destination)).await;
        write_result.expect("write_packet must not block behind a pending read_packet").expect("write succeeds");

        let mut got = [0u8; 5];
        client_io.read_exact(&mut got).await.expect("client receives the write");
        assert_eq!(&got, b"hello");

        read_task.abort();
    }

    #[tokio::test]
    async fn mux_reads_udp_new_and_keep_frames_with_distinct_destinations() {
        let (server, mut peer) = tokio::io::duplex(4096);
        let sender = tokio::spawn(async move {
            peer.write_all(&[
                0, 12, 0, 7, 1, 1, 2, 0, 53, 1, 192, 0, 2, 1, 0, 3, b'o', b'n', b'e', 0, 12, 0, 7, 2, 1, 2, 0, 54, 1,
                192, 0, 2, 2, 0, 3, b't', b'w', b'o',
            ])
            .await
            .unwrap();
        });
        let conn: Box<dyn Stream> = Box::new(DuplexConn(server));
        let (reader, _) = tokio::io::split(conn);
        let mut receiver = MuxFrameReader { conn: reader };
        let first = tokio::time::timeout(Duration::from_secs(2), receiver.read_frame()).await.unwrap().unwrap();
        let second = tokio::time::timeout(Duration::from_secs(2), receiver.read_frame()).await.unwrap().unwrap();
        assert_eq!((first.id, first.status, first.network), (7, 1, 2));
        assert_eq!(
            first.destination,
            murmur_sing::metadata::Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53)
        );
        assert_eq!(first.payload, b"one");
        assert_eq!(
            second.destination,
            murmur_sing::metadata::Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 54)
        );
        assert_eq!(second.payload, b"two");
        sender.await.unwrap();
    }

    struct MuxCapture(mpsc::UnboundedSender<(Vec<u8>, String)>);

    #[async_trait]
    impl Tunnel for MuxCapture {
        async fn handle_tcp_conn(&self, _conn: Box<dyn Stream>, _metadata: murmur_constant::metadata::Metadata) {
            panic!("unexpected TCP stream");
        }

        fn handle_udp_packet(
            &self,
            packet: Arc<dyn murmur_constant::adapters::UDPPacket>,
            metadata: murmur_constant::metadata::Metadata,
        ) {
            self.0.send((packet.data().to_vec(), metadata.remote_address())).unwrap();
        }

        fn nat_table(&self) -> Arc<dyn murmur_constant::adapters::NatTable> {
            panic!("NAT not used");
        }
    }

    #[tokio::test]
    async fn mux_udp_loopback_dispatches_packets_and_preserves_destinations() {
        let (sent, mut received) = mpsc::unbounded_channel();
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(MuxCapture(sent)),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(async move {
            handle_vmess_mux_connection(&handler, SingContext::default(), Box::new(server), SingMetadata::default())
                .await
        });
        client
            .write_all(&[
                0, 12, 0, 7, 1, 1, 2, 0, 53, 1, 192, 0, 2, 1, 0, 3, b'o', b'n', b'e', 0, 12, 0, 7, 2, 1, 2, 0, 54, 1,
                192, 0, 2, 2, 0, 3, b't', b'w', b'o',
            ])
            .await
            .unwrap();
        let first = tokio::time::timeout(Duration::from_secs(2), received.recv()).await.unwrap().unwrap();
        let second = tokio::time::timeout(Duration::from_secs(2), received.recv()).await.unwrap().unwrap();
        assert_eq!(first, (b"one".to_vec(), "192.0.2.1:53".into()));
        assert_eq!(second, (b"two".to_vec(), "192.0.2.2:54".into()));
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap().unwrap();
    }

    #[tokio::test]
    async fn mux_aead_client_xudp_loopback_reaches_inbound_udp_handler() {
        let (sent, mut received) = mpsc::unbounded_channel();
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(MuxCapture(sent)),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let uuid = uuid::Uuid::new_v4();
        let service = VmessService { handler, inner: VmessSingService::new(ntp_now) };
        service.update_users(&["loopback".into()], &[uuid.to_string()], &[0]).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let raw_client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let server_task = tokio::spawn(async move {
            service.new_connection(SingContext::default(), Box::new(server), SingMetadata::default()).await
        });
        let client =
            murmur_transport_vmess::sing::client::Client::new(uuid, "aes-128-gcm", 0, false, false, ntp_now).unwrap();
        let carrier = client
            .dial_mux_conn(
                Box::new(StreamAsOldConn::new(Box::new(raw_client))),
                murmur_sing::metadata::Socksaddr::default(),
            )
            .await
            .unwrap();
        let destination = murmur_sing::metadata::Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53);
        let mut xudp = murmur_transport_vmess::sing::xudp::new_xudp_conn(Box::new(carrier), [0; 8], destination);
        tokio::time::timeout(Duration::from_secs(2), xudp.write_all(b"ping")).await.unwrap().unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(2), received.recv()).await.unwrap().unwrap();
        assert_eq!(packet, (b"ping".to_vec(), "192.0.2.1:53".into()));
        server_task.abort();
    }

    #[tokio::test]
    async fn mux_tcp_magic_destination_dispatches_without_command_mux() {
        let (sent, mut received) = mpsc::unbounded_channel();
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(MuxCapture(sent)),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let uuid = uuid::Uuid::new_v4();
        let service = VmessService { handler, inner: VmessSingService::new(ntp_now) };
        service.update_users(&["loopback".into()], &[uuid.to_string()], &[0]).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let raw_client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let server_task = tokio::spawn(async move {
            service.new_connection(SingContext::default(), Box::new(server), SingMetadata::default()).await
        });
        let client =
            murmur_transport_vmess::sing::client::Client::new(uuid, "aes-128-gcm", 0, false, false, ntp_now).unwrap();
        let mut carrier = client
            .dial_conn(
                Box::new(StreamAsOldConn::new(Box::new(raw_client))),
                murmur_sing::metadata::Socksaddr::fqdn(VMESS_MUX_FQDN.to_owned(), 666),
            )
            .await
            .unwrap();
        carrier.write_all(&[0, 12, 0, 1, 1, 1, 2, 0, 53, 1, 192, 0, 2, 1, 0, 3, b'o', b'n', b'e']).await.unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(2), received.recv()).await.unwrap().unwrap();
        assert_eq!(packet, (b"one".to_vec(), "192.0.2.1:53".into()));
        server_task.abort();
    }

    #[tokio::test]
    async fn mux_unknown_keep_backpressure_does_not_stall_carrier_teardown() {
        let (sent, _received) = mpsc::unbounded_channel();
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(MuxCapture(sent)),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let (server, mut client) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            handle_vmess_mux_connection(
                &handler,
                SingContext::default(),
                Box::new(DuplexConn(server)),
                SingMetadata::default(),
            )
            .await
        });
        let sender = tokio::spawn(async move {
            for _ in 0..500 {
                if client.write_all(&[0, 4, 0, 9, 2, 0]).await.is_err() {
                    break;
                }
            }
            let _ = client.shutdown().await;
        });
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(2), sender).await.unwrap().unwrap();
    }

    struct TcpDrain(mpsc::UnboundedSender<Vec<u8>>, bool);

    #[async_trait]
    impl Tunnel for TcpDrain {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, _metadata: murmur_constant::metadata::Metadata) {
            if self.1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let mut payload = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), conn.read_to_end(&mut payload)).await.unwrap().unwrap();
            self.0.send(payload).unwrap();
        }

        fn handle_udp_packet(
            &self,
            _packet: Arc<dyn murmur_constant::adapters::UDPPacket>,
            _metadata: murmur_constant::metadata::Metadata,
        ) {
            panic!("unexpected UDP packet");
        }

        fn nat_table(&self) -> Arc<dyn murmur_constant::adapters::NatTable> {
            panic!("NAT not used");
        }
    }

    #[tokio::test]
    async fn mux_tcp_end_preserves_preceding_payload_for_tunnel() {
        let (sent, mut received) = mpsc::unbounded_channel();
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(TcpDrain(sent, false)),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(async move {
            handle_vmess_mux_connection(&handler, SingContext::default(), Box::new(server), SingMetadata::default())
                .await
        });
        client
            .write_all(&[0, 12, 0, 9, 1, 1, 1, 0, 80, 1, 192, 0, 2, 10, 0, 3, b'f', b'o', b'o', 0, 4, 0, 9, 3, 0])
            .await
            .unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), received.recv()).await.unwrap().unwrap(), b"foo");
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn mux_carrier_eof_preserves_buffered_tcp_payload() {
        let (sent, mut received) = mpsc::unbounded_channel();
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(TcpDrain(sent, true)),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(async move {
            handle_vmess_mux_connection(&handler, SingContext::default(), Box::new(server), SingMetadata::default())
                .await
        });
        client.write_all(&[0, 12, 0, 9, 1, 1, 1, 0, 80, 1, 192, 0, 2, 10, 0, 3, b'f', b'o', b'o']).await.unwrap();
        client.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap().unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), received.recv()).await.unwrap().unwrap(), b"foo");
    }

    struct MuxEcho;

    #[async_trait]
    impl Tunnel for MuxEcho {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, metadata: murmur_constant::metadata::Metadata) {
            assert_eq!(metadata.remote_address(), "192.0.2.10:80");
            let mut input = [0; 3];
            conn.read_exact(&mut input).await.unwrap();
            conn.write_all(&input).await.unwrap();
        }

        fn handle_udp_packet(
            &self,
            _packet: Arc<dyn murmur_constant::adapters::UDPPacket>,
            _metadata: murmur_constant::metadata::Metadata,
        ) {
            panic!("unexpected UDP packet");
        }

        fn nat_table(&self) -> Arc<dyn murmur_constant::adapters::NatTable> {
            panic!("NAT not used");
        }
    }

    #[tokio::test]
    async fn mux_tcp_loopback_dispatches_and_returns_stream_data() {
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(MuxEcho),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(async move {
            handle_vmess_mux_connection(&handler, SingContext::default(), Box::new(server), SingMetadata::default())
                .await
        });
        client.write_all(&[0, 12, 0, 9, 1, 1, 1, 0, 80, 1, 192, 0, 2, 10, 0, 3, b'f', b'o', b'o']).await.unwrap();
        let mut reply = [0; 11];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply)).await.unwrap().unwrap();
        assert_eq!(&reply, &[0, 4, 0, 9, 2, 1, 0, 3, b'f', b'o', b'o']);
        let mut end = [0; 6];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut end)).await.unwrap().unwrap();
        assert_eq!(end, [0, 4, 0, 9, 3, 0]);
        client.write_all(&[0, 12, 0, 9, 1, 1, 1, 0, 80, 1, 192, 0, 2, 10, 0, 3, b'b', b'a', b'r']).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply)).await.unwrap().unwrap();
        assert_eq!(&reply, &[0, 4, 0, 9, 2, 1, 0, 3, b'b', b'a', b'r']);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    }

    struct PacketAddrEcho;

    #[async_trait]
    impl Tunnel for PacketAddrEcho {
        async fn handle_tcp_conn(&self, _conn: Box<dyn Stream>, _metadata: murmur_constant::metadata::Metadata) {
            panic!("unexpected TCP stream");
        }

        fn handle_udp_packet(
            &self,
            packet: Arc<dyn murmur_constant::adapters::UDPPacket>,
            metadata: murmur_constant::metadata::Metadata,
        ) {
            assert_eq!(metadata.remote_address(), "192.0.2.1:53");
            assert_eq!(packet.data(), b"ping");
            tokio::spawn(async move {
                packet.write_back(b"pong", Some(std::net::SocketAddr::from(([192, 0, 2, 1], 53)))).await.unwrap();
            });
        }

        fn nat_table(&self) -> Arc<dyn murmur_constant::adapters::NatTable> {
            panic!("NAT not used");
        }
    }

    #[tokio::test]
    async fn mux_packetaddr_loopback_rewrites_reply_inside_payload() {
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(PacketAddrEcho),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(async move {
            handle_vmess_mux_connection(&handler, SingContext::default(), Box::new(server), SingMetadata::default())
                .await
        });
        let domain = b"sp.packet-addr.v2fly.arpa";
        let mut request = vec![0, (9 + domain.len()) as u8, 0, 11, 1, 1, 2, 0, 0, 2, domain.len() as u8];
        request.extend_from_slice(domain);
        request.extend_from_slice(&[0, 11, 1, 192, 0, 2, 1, 0, 53, b'p', b'i', b'n', b'g']);
        client.write_all(&request).await.unwrap();
        let mut reply = [0; 19];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply)).await.unwrap().unwrap();
        assert_eq!(reply, [0, 4, 0, 11, 2, 1, 0, 11, 1, 192, 0, 2, 1, 0, 53, b'p', b'o', b'n', b'g']);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    }

    struct RetainPackets(mpsc::UnboundedSender<Arc<dyn murmur_constant::adapters::UDPPacket>>);

    #[async_trait]
    impl Tunnel for RetainPackets {
        async fn handle_tcp_conn(&self, _conn: Box<dyn Stream>, _metadata: murmur_constant::metadata::Metadata) {
            panic!("unexpected TCP stream");
        }

        fn handle_udp_packet(
            &self,
            packet: Arc<dyn murmur_constant::adapters::UDPPacket>,
            _metadata: murmur_constant::metadata::Metadata,
        ) {
            self.0.send(packet).unwrap();
        }

        fn nat_table(&self) -> Arc<dyn murmur_constant::adapters::NatTable> {
            panic!("NAT not used");
        }
    }

    #[tokio::test]
    async fn mux_reused_udp_id_rejects_retained_old_reply_writer() {
        let (sent, mut packets) = mpsc::unbounded_channel();
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(RetainPackets(sent)),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(async move {
            handle_vmess_mux_connection(&handler, SingContext::default(), Box::new(server), SingMetadata::default())
                .await
        });
        let request = [0, 12, 0, 7, 1, 1, 2, 0, 53, 1, 192, 0, 2, 1, 0, 3, b'o', b'n', b'e'];
        client.write_all(&request).await.unwrap();
        let old = tokio::time::timeout(Duration::from_secs(2), packets.recv()).await.unwrap().unwrap();
        client.write_all(&[0, 4, 0, 7, 3, 0]).await.unwrap();
        client.write_all(&request).await.unwrap();
        let new = tokio::time::timeout(Duration::from_secs(2), packets.recv()).await.unwrap().unwrap();
        let remote = Some(std::net::SocketAddr::from(([192, 0, 2, 1], 53)));
        assert!(old.write_back(b"stale", remote).await.is_err());
        new.write_back(b"fresh", remote).await.unwrap();
        let mut reply = [0; 21];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply)).await.unwrap().unwrap();
        assert_eq!(reply, [0, 12, 0, 7, 2, 1, 2, 0, 53, 1, 192, 0, 2, 1, 0, 5, b'f', b'r', b'e', b's', b'h']);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    }

    struct DelayedReply(mpsc::UnboundedSender<Vec<u8>>);

    #[async_trait]
    impl Tunnel for DelayedReply {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, _metadata: murmur_constant::metadata::Metadata) {
            let mut request = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), conn.read_to_end(&mut request)).await.unwrap().unwrap();
            self.0.send(request).unwrap();
            // The reply lands after the peer's `StatusEnd`, once this task is running.
            tokio::time::sleep(Duration::from_millis(50)).await;
            conn.write_all(b"pong").await.unwrap();
        }

        fn handle_udp_packet(
            &self,
            _packet: Arc<dyn murmur_constant::adapters::UDPPacket>,
            _metadata: murmur_constant::metadata::Metadata,
        ) {
            panic!("unexpected UDP packet");
        }

        fn nat_table(&self) -> Arc<dyn murmur_constant::adapters::NatTable> {
            panic!("NAT not used");
        }
    }

    /// Replies with the request echoed behind a marker, so a test can tell two sessions
    /// sharing an id apart by which reply it is waiting for.
    struct EchoRequest(mpsc::UnboundedSender<Vec<u8>>);

    #[async_trait]
    impl Tunnel for EchoRequest {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, _metadata: murmur_constant::metadata::Metadata) {
            let mut request = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), conn.read_to_end(&mut request)).await.unwrap().unwrap();
            self.0.send(request.clone()).unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            conn.write_all(&request).await.unwrap();
        }

        fn handle_udp_packet(
            &self,
            _packet: Arc<dyn murmur_constant::adapters::UDPPacket>,
            _metadata: murmur_constant::metadata::Metadata,
        ) {
            panic!("unexpected UDP packet");
        }

        fn nat_table(&self) -> Arc<dyn murmur_constant::adapters::NatTable> {
            panic!("NatTable not used");
        }
    }

    #[tokio::test]
    async fn mux_tcp_reply_after_status_end_reaches_peer() {
        let (sent, mut received) = mpsc::unbounded_channel();
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(DelayedReply(sent)),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(async move {
            handle_vmess_mux_connection(&handler, SingContext::default(), Box::new(server), SingMetadata::default())
                .await
        });
        client
            .write_all(&[0, 12, 0, 9, 1, 1, 1, 0, 80, 1, 192, 0, 2, 10, 0, 3, b'f', b'o', b'o', 0, 4, 0, 9, 3, 0])
            .await
            .unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), received.recv()).await.unwrap().unwrap(), b"foo");
        let mut reply = [0; 12];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply)).await.unwrap().unwrap();
        assert_eq!(reply, [0, 4, 0, 9, 2, 1, 0, 4, b'p', b'o', b'n', b'g']);
        let mut end = [0; 6];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut end)).await.unwrap().unwrap();
        assert_eq!(end, [0, 4, 0, 9, 3, 0]);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    }

    /// the `StatusNew` overwrites the map entry and leaves the replaced handler running,
    /// so a session the peer already half-closed still gets its response out under the
    /// reused id. Aborting it on reuse drops the reply the peer is still waiting for.
    #[tokio::test]
    async fn mux_reused_id_drains_the_ended_sessions_response() {
        let (sent, mut received) = mpsc::unbounded_channel();
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(EchoRequest(sent)),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(async move {
            handle_vmess_mux_connection(&handler, SingContext::default(), Box::new(server), SingMetadata::default())
                .await
        });
        // Open the session, half-close it, then immediately reuse the id. `EchoRequest`
        // only writes its reply after the read side reports EOF, so the reuse lands while
        // the first session's response is still pending.
        client
            .write_all(&[
                0, 12, 0, 9, 1, 1, 1, 0, 80, 1, 192, 0, 2, 10, 0, 3, b'f', b'o', b'o', 0, 4, 0, 9, 3, 0, 0, 12, 0, 9,
                1, 1, 1, 0, 80, 1, 192, 0, 2, 10, 0, 3, b'b', b'a', b'r',
            ])
            .await
            .unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), received.recv()).await.unwrap().unwrap(), b"foo");

        // Only the retired session's own echo proves the drain: both share id 9, so the
        // second session's reply would otherwise satisfy the wait.
        let mut seen = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !seen.windows(11).any(|window| window == b"\x00\x04\x00\x09\x02\x01\x00\x03foo") {
            let mut chunk = [0u8; 1024];
            let read = tokio::time::timeout_at(deadline, client.read(&mut chunk)).await.unwrap().unwrap();
            assert_ne!(read, 0, "carrier closed before the ended session's reply was flushed");
            seen.extend_from_slice(&chunk[..read]);
        }
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn mux_keep_after_status_end_gets_end_reply() {
        let (sent, mut received) = mpsc::unbounded_channel();
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(DelayedReply(sent)),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(async move {
            handle_vmess_mux_connection(&handler, SingContext::default(), Box::new(server), SingMetadata::default())
                .await
        });
        client
            .write_all(&[0, 12, 0, 9, 1, 1, 1, 0, 80, 1, 192, 0, 2, 10, 0, 3, b'f', b'o', b'o', 0, 4, 0, 9, 3, 0])
            .await
            .unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), received.recv()).await.unwrap().unwrap(), b"foo");
        // The local close removed the id, so this Keep is unowned and gets an End back.
        client.write_all(&[0, 4, 0, 9, 2, 1, 0, 1, b'x']).await.unwrap();
        let mut end = [0; 6];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut end)).await.unwrap().unwrap();
        assert_eq!(end, [0, 4, 0, 9, 3, 0]);
        let mut reply = [0; 12];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply)).await.unwrap().unwrap();
        assert_eq!(reply, [0, 4, 0, 9, 2, 1, 0, 4, b'p', b'o', b'n', b'g']);
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    }

    struct WriteGate {
        open: AtomicBool,
        waker: Mutex<Option<std::task::Waker>>,
    }

    impl WriteGate {
        fn release(&self) {
            self.open.store(true, Ordering::SeqCst);
            if let Some(waker) = self.waker.lock().take() {
                waker.wake();
            }
        }
    }

    /// Parks every write until the gate opens, so the frame queue fills without relying on
    /// how fast the peer drains the carrier.
    struct GatedConn {
        io: tokio::io::DuplexStream,
        gate: Arc<WriteGate>,
    }

    impl AsyncRead for GatedConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for GatedConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if !this.gate.open.load(Ordering::SeqCst) {
                *this.gate.waker.lock() = Some(cx.waker().clone());
                if !this.gate.open.load(Ordering::SeqCst) {
                    return Poll::Pending;
                }
            }
            Pin::new(&mut this.io).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
        }
    }

    impl Stream for GatedConn {
        fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }

        fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        }
    }

    #[tokio::test]
    async fn mux_end_frame_backpressure_keeps_serving_new_sessions() {
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(MuxEcho),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let gate = Arc::new(WriteGate { open: AtomicBool::new(false), waker: Mutex::new(None) });
        let (server, mut client) = tokio::io::duplex(4096);
        let task = tokio::spawn({
            let gate = Arc::clone(&gate);
            async move {
                handle_vmess_mux_connection(
                    &handler,
                    SingContext::default(),
                    Box::new(GatedConn { io: server, gate }),
                    SingMetadata::default(),
                )
                .await
            }
        });
        // Twice the frame-queue depth, so the surplus End frames hit a full queue.
        for _ in 0..64 {
            client.write_all(&[0, 4, 0, 9, 2, 0]).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!task.is_finished(), "End-frame backpressure must not tear the carrier down");
        gate.release();
        client.write_all(&[0, 12, 0, 1, 1, 1, 1, 0, 80, 1, 192, 0, 2, 10, 0, 3, b'f', b'o', b'o']).await.unwrap();
        let mut seen = Vec::new();
        let mut chunk = [0u8; 1024];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !seen.windows(11).any(|window| window == b"\x00\x04\x00\x01\x02\x01\x00\x03foo") {
            let read = tokio::time::timeout_at(deadline, client.read(&mut chunk)).await.unwrap().unwrap();
            assert_ne!(read, 0, "carrier closed before the new session's reply was flushed");
            seen.extend_from_slice(&chunk[..read]);
        }
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    }

    /// Reads as an immediate EOF and has a `Drop` that closes nothing, so the flag below is set
    /// only by the explicit close the connection handler performs on a service error.
    struct CloseRecordingConn(Arc<AtomicBool>);

    impl AsyncRead for CloseRecordingConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for CloseRecordingConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for CloseRecordingConn {
        fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        }

        fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        }

        fn shutdown_read(&self) -> std::io::Result<()> {
            self.0.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn shutdown_write(&self) -> std::io::Result<()> {
            self.0.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn service_error_closes_the_conn_instead_of_only_dropping_it() {
        let (sent, _received) = mpsc::unbounded_channel();
        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::new(MuxCapture(sent)),
            type_: Type::VMESS,
            additions: vec![],
            udp_timeout: murmur_listener_sing::sing::UDP_TIMEOUT,
            mux_option: Default::default(),
        })
        .unwrap();
        let uuid = uuid::Uuid::new_v4();
        let service = VmessService { handler, inner: VmessSingService::new(ntp_now) };
        service.update_users(&["loopback".into()], &[uuid.to_string()], &[0]).unwrap();

        let closed = Arc::new(AtomicBool::new(false));
        new_connection_closing_on_error(
            &service,
            SingContext::default(),
            Box::new(CloseRecordingConn(Arc::clone(&closed))),
            SingMetadata::default(),
        )
        .await;
        assert!(closed.load(Ordering::SeqCst), "a rejected VMess connection must be closed, not just dropped");
    }
}

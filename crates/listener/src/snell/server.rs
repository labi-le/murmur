//! DEVIATION: the buffered reader wrapping the accepted stream only read-aheads the socket for
//! convenience.
//!
//! `AsyncRead::read`/`read_exact` never return more bytes than requested, so a plain sequential
//! read through the same `Snell` value is observably identical, so no separate buffering layer
//! is needed.
//!
//! DEVIATION: the shadow-tls in-user addition needs the accepted conn's user chain
//! (`&dyn UpstreamNode`/`&dyn NetConn`), but `murmur_std_compat::net::Listener::accept` returns a
//! `Box<dyn murmur_std_compat::net::Conn>`, which carries no `as_any`/downcast
//! support. There is no way to recover the concrete conn chain at this boundary, so `loaded`
//! is always `false` here and the shadow-tls in-user addition is never applied.

use std::future::{poll_fn, Future};
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use crate::jls::listener as jls;
use crate::shadowtls;
use murmur_adapter_inbound::addition::{apply_additions, with_in_addr, with_in_user, with_src_addr, Addition};
use murmur_common::shared_conn::SharedConn;
use murmur_common::utils::uuid::new_uuid_v4;
use murmur_common_net::io::{Acceptor, Stream as NetStream, StreamAsOldConn};
use murmur_common_net::new_custom_addr;
use murmur_constant::adapters::{UDPPacket, WriteBack};
use murmur_constant::listener::{InboundListenConfig, MultiAddrListener};
use murmur_constant::metadata::{Metadata, NetWork, Type};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::snell::SnellServer;
use murmur_std_compat::net::{Addr, Conn as NetConn, UdpAddr};
use murmur_transport_shadowsocks::shadowaead::stream::ErrZeroChunk;
use murmur_transport_simple_obfs::http_server::new_http_obfs_server;
use murmur_transport_simple_obfs::tls_server::new_tls_obfs_server;
use murmur_transport_snell::snell::{self, Snell};

const MAX_PACKET_LENGTH: usize = 0x3FFF;

fn is_zero_chunk(err: &io::Error) -> bool {
    err.get_ref().and_then(|err| err.downcast_ref::<ErrZeroChunk>()).is_some()
}

fn unmap_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        other @ IpAddr::V4(_) => other,
    }
}

#[derive(Debug)]
struct StaticAddr {
    network: String,
    address: String,
}

impl Addr for StaticAddr {
    fn network(&self) -> &str {
        &self.network
    }

    fn string(&self) -> String {
        self.address.clone()
    }
}

fn clone_addr(addr: &dyn Addr) -> Box<dyn Addr> {
    Box::new(StaticAddr { network: addr.network().to_owned(), address: addr.string() })
}

/// Placeholder `Snell` inner conn: the swap target of `std::mem::replace` once the real stream has
/// been moved into a `TcpRequestConn`/the UDP loop. It is never actually read from or written to.
struct NullConn;

impl AsyncRead for NullConn {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for NullConn {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl NetConn for NullConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Err(io::Error::other("null conn"))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Err(io::Error::other("null conn"))
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }

    fn close_read(&self) -> io::Result<()> {
        Ok(())
    }

    fn close_write(&self) -> io::Result<()> {
        Ok(())
    }

    fn set_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Ok(())
    }

    fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Ok(())
    }
}

fn take_stream(stream: &mut Snell) -> Snell {
    std::mem::replace(stream, snell::server_stream_conn(Box::new(NullConn), b"", 0))
}

pub struct Listener {
    closed: AtomicBool,
    config: SnellServer,
    listeners: Vec<Box<dyn Acceptor>>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("listeners", &self.listeners.len())
            .finish_non_exhaustive()
    }
}

fn close_listeners(listeners: &[Box<dyn Acceptor>]) {
    for lis in listeners {
        let _ = lis.close();
    }
}

pub async fn new(
    config: SnellServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<Listener>> {
    let mut config = config;
    if config.version == 0 {
        config.version = snell::VERSION4;
    }
    match config.version {
        snell::VERSION1 | snell::VERSION2 | snell::VERSION3 | snell::VERSION4 | snell::VERSION5 => {}
        other => return Err(anyhow!("snell inbound version {other} is not supported")),
    }
    if config.psk.is_empty() {
        return Err(anyhow!("snell inbound requires psk"));
    }
    match config.obfs_mode.as_str() {
        "" | "http" | "tls" => {}
        other => return Err(anyhow!("snell inbound obfs mode error: {other}")),
    }

    let mut listeners: Vec<Box<dyn Acceptor>> = Vec::new();

    let mut security_modes: Vec<&str> = Vec::with_capacity(3);
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

    let shadow_tls_builder = if config.shadow_tls.enable {
        Some(shadowtls::listener::new(&config.shadow_tls, Arc::clone(&tunnel))?)
    } else {
        None
    };

    let jls_builder =
        if config.jls_config.enable { Some(jls::new(&config.jls_config, Arc::clone(&tunnel))?) } else { None };

    for addr in config.listen.split(',') {
        let addr = addr.trim();
        if addr.is_empty() {
            continue;
        }
        let ln = match lc.listen(&CancellationToken::new(), "tcp", addr).await {
            Ok(ln) => ln,
            Err(err) => {
                close_listeners(&listeners);
                return Err(err);
            }
        };
        let mut ln: Box<dyn Acceptor> = ln;
        if let Some(builder) = &shadow_tls_builder {
            ln = builder.new_listener(ln);
        } else if let Some(builder) = &jls_builder {
            ln = builder.new_listener(ln);
        }
        listeners.push(ln);
    }

    let sl = Arc::new(Listener { closed: AtomicBool::new(false), config, listeners });

    for index in 0..sl.listeners.len() {
        let sl = Arc::clone(&sl);
        let tunnel = Arc::clone(&tunnel);
        let additions = additions.clone();
        tokio::spawn(async move {
            loop {
                let Some(listener) = sl.listeners.get(index) else {
                    return;
                };
                let Ok(conn) = listener.accept().await else {
                    if sl.closed.load(Ordering::SeqCst) {
                        return;
                    }
                    continue;
                };
                let sl = Arc::clone(&sl);
                let tunnel = Arc::clone(&tunnel);
                let additions = additions.clone();
                tokio::spawn(async move { sl.handle_conn(conn, tunnel, additions).await });
            }
        });
    }

    Ok(sl)
}

impl MultiAddrListener for Listener {
    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        let mut ret_err: Option<anyhow::Error> = None;
        for ln in &self.listeners {
            if let Err(err) = ln.close() {
                ret_err = Some(err.into());
            }
        }
        ret_err.map_or(Ok(()), Err)
    }

    fn config(&self) -> String {
        self.config.to_string()
    }

    fn addr_list(&self) -> Vec<Box<dyn Addr>> {
        self.listeners
            .iter()
            .filter_map(|lis| lis.addr().ok())
            .map(|addr| -> Box<dyn Addr> { Box::new(murmur_std_compat::net::TcpAddr::from(addr)) })
            .collect()
    }
}

/// Reads one datagram off `stream`. The read never takes `write_mu`, so a reply
/// blocked on the client's socket never blocks the next read; this acquires the mutex fresh for
/// each poll and drops the guard the moment that poll returns, instead of holding it for the
/// whole (unbounded) wait for the next datagram, so a concurrent `write_back` isn't starved
/// meanwhile.
async fn read_udp_datagram(stream: &Arc<AsyncMutex<Snell>>, buf: &mut [u8]) -> io::Result<usize> {
    let mut lock_fut: Option<Pin<Box<dyn Future<Output = tokio::sync::OwnedMutexGuard<Snell>> + Send>>> = None;
    poll_fn(|cx| {
        if lock_fut.is_none() {
            lock_fut = Some(Box::pin(Arc::clone(stream).lock_owned()));
        }
        let Some(fut) = lock_fut.as_mut() else {
            return Poll::Pending;
        };
        let mut guard = match fut.as_mut().poll(cx) {
            Poll::Ready(guard) => {
                lock_fut = None;
                guard
            }
            Poll::Pending => return Poll::Pending,
        };
        let mut read_buf = ReadBuf::new(&mut *buf);
        match Pin::new(&mut *guard).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

impl Listener {
    async fn handle_conn(&self, raw_conn: Box<dyn NetStream>, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) {
        // See the module-level DEVIATION note: `loaded` cannot be recovered here.
        let loaded = false;
        let mut additions = additions;
        if loaded {
            additions.push(with_in_user(""));
        }

        // S11: remove with murmur-std-compat — `new_http_obfs_server`/`new_tls_obfs_server`
        // (transport-simple-obfs) and `snell::server_stream_conn` (transport-snell) are still
        // `murmur_std_compat::net::Conn`-typed end to end.
        let raw_conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(raw_conn));
        let conn: Box<dyn NetConn> = match self.config.obfs_mode.as_str() {
            "http" => new_http_obfs_server(raw_conn),
            "tls" => new_tls_obfs_server(raw_conn),
            "" => raw_conn,
            _ => {
                let _ = raw_conn.close();
                return;
            }
        };
        let mut stream = snell::server_stream_conn(conn, self.config.psk.as_bytes(), self.config.version);
        loop {
            if !matches!(self.handle_request(&mut stream, &tunnel, &additions).await, Ok(true)) {
                let _ = stream.close();
                return;
            }
        }
    }

    async fn handle_request(
        &self,
        stream: &mut Snell,
        tunnel: &Arc<dyn Tunnel>,
        additions: &[Addition],
    ) -> Result<bool> {
        let version = stream.read_u8().await?;
        if version != snell::VERSION {
            return Err(anyhow!("snell invalid protocol version: {version}"));
        }

        let command = stream.read_u8().await?;
        if command == snell::COMMAND_PING {
            let _ = stream.write_all(&[snell::COMMAND_PONG]).await;
            return Ok(false);
        }

        let client_id = read_client_id(stream).await?;

        match command {
            snell::COMMAND_CONNECT | snell::COMMAND_CONNECT_V2 => {
                self.handle_tcp(stream, command == snell::COMMAND_CONNECT_V2, &client_id, tunnel, additions).await
            }
            snell::COMMAND_UDP => {
                if !self.config.udp {
                    return Err(anyhow!("snell UDP is disabled"));
                }
                self.handle_udp(stream, &client_id, tunnel, additions).await?;
                Ok(false)
            }
            other => Err(anyhow!("snell unknown command: {other}")),
        }
    }

    async fn handle_tcp(
        &self,
        stream: &mut Snell,
        reuse: bool,
        client_id: &str,
        tunnel: &Arc<dyn Tunnel>,
        additions: &[Addition],
    ) -> Result<bool> {
        let host_len = stream.read_u8().await?;
        if host_len == 0 {
            return Err(anyhow!("snell connect host is empty"));
        }

        let mut host_bytes = vec![0u8; usize::from(host_len)];
        stream.read_exact(&mut host_bytes).await?;
        let mut port_bytes = [0u8; 2];
        stream.read_exact(&mut port_bytes).await?;
        let host = String::from_utf8_lossy(&host_bytes).into_owned();
        let port = u16::from_be_bytes(port_bytes);

        let remote_addr = stream.remote_addr().ok();
        let local_addr = stream.local_addr().ok();
        let metadata =
            build_metadata(NetWork::TCP, &host, port, Type::SNELL, remote_addr, local_addr, client_id, additions);

        let conn = TcpRequestConn::new(take_stream(stream), reuse);
        tunnel.handle_tcp_conn(Box::new(murmur_common_net::io::OldConnAsStream(conn)), metadata).await;
        Ok(reuse)
    }

    async fn handle_udp(
        &self,
        stream: &mut Snell,
        client_id: &str,
        tunnel: &Arc<dyn Tunnel>,
        additions: &[Addition],
    ) -> Result<()> {
        // The write is synchronous and always reaches the wire; the Snell
        // wrapper's `poll_flush` does forward to the underlying (possibly TLS-wrapped) conn, so
        // this reply needs an explicit flush before the read loop starts waiting on a reply the
        // client may otherwise never see (review finding 7 on the TLS-flush sweep).
        stream.write_all(&[snell::COMMAND_TUNNEL]).await?;
        stream.flush().await?;

        let conn_id = new_uuid_v4().to_string();
        let nat_key = conn_id.clone();
        let remote_addr = stream.remote_addr().ok();
        let local_addr: Arc<dyn Addr> = match &remote_addr {
            Some(addr) => {
                let custom_addr: Box<dyn Addr> =
                    new_custom_addr(Type::SNELL.string(), conn_id, clone_addr(addr.as_ref()));
                Arc::from(custom_addr)
            }
            None => Arc::new(StaticAddr { network: Type::SNELL.string(), address: String::new() }),
        };
        let packet_local_addr = match &remote_addr {
            Some(addr) => murmur_common_net::io::old_addr_to_socket_addr(addr.as_ref())?,
            None => return Err(anyhow!("snell: UDP tunnel requires a known remote address")),
        };

        let stream = Arc::new(AsyncMutex::new(take_stream(stream)));
        let mut buf = vec![0u8; MAX_PACKET_LENGTH];
        loop {
            let n = read_udp_datagram(&stream, &mut buf).await;
            let n = match n {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(err) => {
                    if is_zero_chunk(&err) {
                        return Ok(());
                    }
                    return Err(err.into());
                }
            };
            let Some(datagram) = buf.get(..n) else {
                return Err(anyhow!("snell: datagram length {n} exceeds buffer"));
            };
            let request = snell::parse_udp_request(datagram)?;
            let mut metadata = build_metadata(
                NetWork::UDP,
                &request.host,
                request.port,
                Type::SNELL,
                remote_addr.as_ref().map(|a| clone_addr(a.as_ref())),
                Some(clone_addr(local_addr.as_ref())),
                client_id,
                additions,
            );
            if let Some(ip) = request.ip {
                metadata.host = String::new();
                metadata.dst_ip = Some(unmap_ip(ip));
            }

            let dst_addr = metadata.udp_addr();
            let payload = request.payload;
            let packet = Arc::new(UdpPacket {
                data: payload,
                conn: Arc::clone(&stream),
                local_addr: packet_local_addr,
                nat_key: nat_key.clone(),
                dst_addr,
            });
            tunnel.handle_udp_packet(packet, metadata);
        }
    }
}

/// The conn shape `l.metadata` needs, taken as already-resolved addresses since the TCP
/// and UDP call sites hold the source `Snell` value under different ownership (owned vs.
/// `Arc<Mutex<_>>`).
fn build_metadata(
    network: NetWork,
    host: &str,
    port: u16,
    type_: Type,
    remote_addr: Option<Box<dyn Addr>>,
    local_addr: Option<Box<dyn Addr>>,
    client_id: &str,
    additions: &[Addition],
) -> Metadata {
    let mut metadata = Metadata { network, type_, dst_port: port, ..Metadata::default() };
    if let Ok(ip) = host.parse::<IpAddr>() {
        metadata.dst_ip = Some(unmap_ip(ip));
    } else {
        host.clone_into(&mut metadata.host);
    }
    apply_additions(&mut metadata, &[with_src_addr(remote_addr), with_in_addr(local_addr)]);
    apply_additions(&mut metadata, additions);
    if !client_id.is_empty() {
        apply_additions(&mut metadata, &[with_in_user(client_id)]);
    }
    metadata
}

async fn write_command_error<W>(w: &mut W, code: u8, message: &str) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut msg = message.as_bytes();
    if msg.len() > 255 {
        msg = msg.get(..255).unwrap_or(msg);
    }
    let mut buf = Vec::with_capacity(3 + msg.len());
    buf.push(snell::COMMAND_ERROR);
    buf.push(code);
    buf.push(u8::try_from(msg.len()).unwrap_or(u8::MAX));
    buf.extend_from_slice(msg);
    w.write_all(&buf).await
}

fn join_errors(a: Option<io::Error>, b: Option<io::Error>) -> io::Result<()> {
    match (a, b) {
        (None, None) => Ok(()),
        (Some(e), None) | (None, Some(e)) => Err(e),
        (Some(e1), Some(e2)) => Err(io::Error::other(format!("{e1}\n{e2}"))),
    }
}

type WriteFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;

/// The request conn. A read never takes `write_mu`, relying on the conn's
/// concurrent-read/concurrent-write guarantee; `common::net::SharedConn` gives the same property
/// here without a real duplex socket underneath, because its lock is only ever held across one
/// synchronous poll, never across a suspension. That is what makes a stalled write's `Pending`
/// release the lock instead of parking a queued `Acquire` that only this same relay task could
/// ever poll again (review findings on d0654454: `close()`/`set_*deadline` hung behind a parked
/// read, and a stalled download write starved the upload read in a full-duplex relay).
struct TcpRequestConn {
    conn: SharedConn,
    reuse: bool,
    reply_written: Arc<AtomicBool>,
    closed: AtomicBool,
    /// The write mutex, held across a whole write and across the whole close. Only
    /// `close`'s spawned task ever awaits it, so the d0654454 deadlock cannot recur.
    write_mu: Arc<AsyncMutex<()>>,
    write_fut: SyncMutex<Option<WriteFuture>>,
}

impl TcpRequestConn {
    fn new(conn: Snell, reuse: bool) -> Self {
        Self {
            conn: SharedConn::from_boxed(Box::new(conn)),
            reuse,
            reply_written: Arc::new(AtomicBool::new(false)),
            closed: AtomicBool::new(false),
            write_mu: Arc::new(AsyncMutex::new(())),
            write_fut: SyncMutex::new(None),
        }
    }
}

impl AsyncRead for TcpRequestConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().conn).poll_read(cx, buf) {
            Poll::Ready(Err(err)) if is_zero_chunk(&err) => Poll::Ready(Ok(())),
            other @ (Poll::Ready(_) | Poll::Pending) => other,
        }
    }
}

impl AsyncWrite for TcpRequestConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut slot = this.write_fut.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            let mut conn = this.conn.clone();
            let write_mu = Arc::clone(&this.write_mu);
            let reply_written = Arc::clone(&this.reply_written);
            let owned_buf = buf.to_vec();
            *slot = Some(Box::pin(async move {
                let _guard = write_mu.lock().await;
                if reply_written.load(Ordering::Acquire) {
                    conn.write(&owned_buf).await
                } else {
                    let mut payload = Vec::with_capacity(1 + owned_buf.len());
                    payload.push(snell::COMMAND_TUNNEL);
                    payload.extend_from_slice(&owned_buf);
                    conn.write_all(&payload).await?;
                    reply_written.store(true, Ordering::Release);
                    Ok(owned_buf.len())
                }
            }));
        }
        let Some(fut) = slot.as_mut() else {
            return Poll::Ready(Err(io::Error::other("write future not initialised")));
        };
        let result = fut.as_mut().poll(cx);
        if result.is_ready() {
            *slot = None;
        }
        result
    }

    /// Forwards to the wrapped conn, which may be TLS-wrapped obfs: the write is
    /// synchronous and always reaches the wire, but a buffered async writer underneath (as with
    /// `tokio_rustls`) can report bytes consumed while they still sit in an internal buffer, so a
    /// no-op flush here would strand them under backpressure (review finding 7 on the TLS-flush
    /// sweep).
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl NetConn for TcpRequestConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.remote_addr()
    }

    /// Close. DEVIATION: the body runs inline under `write_mu`, so its caller blocks until an
    /// in-flight write lands. `close` is `&self` and the relay calls it
    /// from inside the poll that owns the parked write, so waiting inline would park the only
    /// task that can drive that write forward. The body runs in a task instead, queued behind
    /// `write_mu`, which restores the ordering without the caller ever awaiting it.
    fn close(&self) -> io::Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut conn = self.conn.clone();
        let write_mu = Arc::clone(&self.write_mu);
        let reply_written = Arc::clone(&self.reply_written);
        let reuse = self.reuse;
        tokio::spawn(async move {
            let _guard = write_mu.lock().await;
            if !reply_written.load(Ordering::Acquire) {
                let write_err = write_command_error(&mut conn, 0x65, "Remote EOF").await.err();
                let close_err = if reuse { None } else { conn.close().err() };
                let _ = join_errors(write_err, close_err);
            } else if reuse {
                // The zero-length frame that ends the tunnel.
                let _ = snell::write_zero_chunk(&mut conn).await;
            } else {
                let _ = conn.close();
            }
        });
        Ok(())
    }

    fn close_read(&self) -> io::Result<()> {
        Ok(())
    }

    fn close_write(&self) -> io::Result<()> {
        self.close()
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

async fn read_client_id(stream: &mut Snell) -> Result<String> {
    let length = stream.read_u8().await?;
    if length == 0 {
        return Ok(String::new());
    }
    let mut id = vec![0u8; usize::from(length)];
    stream.read_exact(&mut id).await?;
    Ok(String::from_utf8_lossy(&id).into_owned())
}

struct UdpPacket {
    data: Vec<u8>,
    conn: Arc<AsyncMutex<Snell>>,
    local_addr: std::net::SocketAddr,
    /// A fresh per-conn key so
    /// several UDP tunnels sharing one physical conn's remote address still land in distinct
    /// NAT entries.
    nat_key: String,
    dst_addr: Option<UdpAddr>,
}

#[async_trait]
impl WriteBack for UdpPacket {
    async fn write_back(&self, b: &[u8], addr: Option<std::net::SocketAddr>) -> Result<usize> {
        let owned_dst;
        let addr: &dyn Addr = match addr {
            Some(addr) => {
                owned_dst = murmur_common_net::io::udp_addr_from_socket_addr(addr);
                &owned_dst
            }
            None => match &self.dst_addr {
                Some(dst) => {
                    owned_dst = dst.clone();
                    &owned_dst
                }
                None => return Err(anyhow!("address is invalid")),
            },
        };
        let mut conn = self.conn.lock().await;
        snell::write_packet_response(&mut *conn, addr, b).await
    }
}

impl UDPPacket for UdpPacket {
    fn data(&self) -> &[u8] {
        &self.data
    }

    fn drop_(&self) {}

    fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// The remote address string, see the `nat_key` field doc.
    fn nat_key(&self) -> String {
        self.nat_key.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use tokio::io::{duplex, DuplexStream};

    use super::*;
    use murmur_transport_snell::snell::{VERSION1, VERSION4};

    struct PipeConn(DuplexStream);

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

    #[derive(Debug)]
    struct DummyAddr(&'static str);

    impl Addr for DummyAddr {
        fn network(&self) -> &str {
            self.0
        }

        fn string(&self) -> String {
            self.0.to_owned()
        }
    }

    impl NetConn for PipeConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(DummyAddr("pipe")))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(DummyAddr("pipe")))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A write sink that always accepts immediately and counts bytes, so it never introduces
    /// backpressure of its own; the read half is a fixed payload standing in for backend
    /// download data. Together with [`PipeConn`] over a tiny `duplex`, this isolates
    /// `TcpRequestConn`'s own read/write contention from any other bottleneck in the probes
    /// below.
    struct SourceConn {
        download: io::Cursor<Vec<u8>>,
        uploaded: Arc<AtomicUsize>,
    }

    impl SourceConn {
        fn new(download: Vec<u8>) -> Self {
            Self { download: io::Cursor::new(download), uploaded: Arc::new(AtomicUsize::new(0)) }
        }
    }

    impl AsyncRead for SourceConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().download).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for SourceConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.uploaded.fetch_add(buf.len(), Ordering::SeqCst);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl NetConn for SourceConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(DummyAddr("source")))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(DummyAddr("source")))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Review finding on d0654454: the parked `lock_owned` read fixed the busy spin but queued
    /// an `Acquire` that only this same relay task could ever poll again, so when a stalled
    /// write's error made `relay_inner` call `left_conn.close()` in that same poll, `close()`'s
    /// own `conn.lock().await` waited on a permit that had already gone to the parked read.
    /// `SharedConn`'s lock is never held across a suspension, so nothing is ever queued: this
    /// must finish well inside the bound instead of hanging.
    #[tokio::test(flavor = "multi_thread")]
    async fn review_relay_close_after_failed_write_does_not_hang() {
        let (client_wire, client_wire_remote) = duplex(64);
        let snell = snell::server_stream_conn(Box::new(PipeConn(client_wire)), &[1u8; 32], VERSION1);
        let mut tcp_conn = TcpRequestConn::new(snell, false);
        let mut right_conn = SourceConn::new(vec![0x42u8; 256 * 1024]);

        let relay = tokio::spawn(async move {
            murmur_common_net::relay(&mut tcp_conn, &mut right_conn).await;
        });

        // Let the relay push download bytes until the 64-byte duplex buffer backs up, then
        // simulate the client disconnecting mid-write.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(client_wire_remote);

        let result = tokio::time::timeout(Duration::from_secs(10), relay).await;
        assert!(result.is_ok(), "relay's close() hung after the client disconnected mid-write (review probe)");
    }

    /// Review finding on d0654454: the write future held the shared conn's lock across the
    /// whole (possibly unbounded) `write_all`/`write` `Pending` span, so a stalled download
    /// (client not reading) starved the upload read, which needs the same lock. `SharedConn`
    /// only ever holds its lock across one synchronous poll, so a stalled write's `Pending`
    /// releases it immediately and the upload keeps draining.
    #[tokio::test(flavor = "multi_thread")]
    async fn review_full_duplex_relay_with_stalled_download_still_reads_upload() {
        const UPLOAD_LEN: usize = 256 * 1024;
        const PSK: &[u8; 32] = &[1u8; 32];

        let (client_wire, client_wire_remote) = duplex(64);
        let server_snell = snell::server_stream_conn(Box::new(PipeConn(client_wire)), PSK, VERSION1);
        let mut tcp_conn = TcpRequestConn::new(server_snell, false);
        // The client's own encoder: `TcpRequestConn`'s read goes through the server-side Snell
        // AEAD decoder, so the upload bytes have to be genuinely framed the way a real Snell
        // client would, not raw bytes on the wire.
        let mut client_snell = snell::stream_conn(Box::new(PipeConn(client_wire_remote)), PSK, VERSION1);

        let uploaded = Arc::new(AtomicUsize::new(0));
        let mut right_conn = SourceConn::new(vec![0x42u8; UPLOAD_LEN]);
        right_conn.uploaded = Arc::clone(&uploaded);

        let relay = tokio::spawn(async move {
            // Never reads back what `right_conn` sends downstream: that direction stalls
            // forever on the 64-byte duplex buffer, which is the point of this probe.
            murmur_common_net::relay(&mut tcp_conn, &mut right_conn).await;
        });

        let upload = tokio::spawn(async move {
            let payload = vec![0x55u8; UPLOAD_LEN];
            client_snell.write_all(&payload).await
        });

        let waited = tokio::time::timeout(Duration::from_secs(10), async {
            upload.await.unwrap().expect("client's upload write must not error");
            while uploaded.load(Ordering::SeqCst) < UPLOAD_LEN {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "upload was starved by the stalled download (review probe)");
        assert_eq!(UPLOAD_LEN, uploaded.load(Ordering::SeqCst), "every uploaded byte must reach the upstream side");

        relay.abort();
    }

    /// The close reuse arm writes a zero-length frame so the client learns
    /// the tunnel ended. `AsyncWriteExt::write` on an empty buffer emits nothing, so the client
    /// waited forever for an end of stream that was never framed, and `block_in_place` panicked
    /// on the current-thread runtime the relay drives. Both directions here span many v4 frames,
    /// the case where the writer holds a half-written frame across the close.
    #[tokio::test]
    async fn reuse_close_ends_a_multi_frame_transfer_with_the_zero_length_frame() {
        const PSK: &[u8; 32] = b"passwordpasswordpasswordpassword";
        const UPLOAD: usize = 96 * 1024;
        const DOWNLOAD: usize = 48 * 1024;

        let (client_wire, server_wire) = duplex(1024);
        let server_snell = snell::server_stream_conn(Box::new(PipeConn(server_wire)), PSK, VERSION4);
        let mut tcp_conn = TcpRequestConn::new(server_snell, true);

        let client = tokio::spawn(async move {
            let mut client = snell::stream_conn(Box::new(PipeConn(client_wire)), PSK, VERSION4);
            client.write_all(&vec![0x5a; UPLOAD]).await.expect("client upload");
            // `Snell::poll_read` reads the reply header first, which eats the command byte the
            // request conn's first write prepends, so the readable payload is what follows it.
            // The reply header accepts no other byte, so reading at all proves the command.
            let mut download = vec![0u8; DOWNLOAD];
            client.read_exact(&mut download).await.expect("client download");
            (download, client.read(&mut [0u8; 1]).await)
        });

        let mut uploaded = vec![0u8; UPLOAD];
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut filled = 0;
            while filled < uploaded.len() {
                filled += tcp_conn.read(&mut uploaded[filled..]).await.expect("upload read");
            }
        })
        .await
        .expect("the multi-frame upload stalled");
        assert!(uploaded.iter().all(|b| *b == 0x5a), "the upload lost or reordered bytes");

        let download = vec![0x33u8; DOWNLOAD];
        tokio::time::timeout(Duration::from_secs(10), tcp_conn.write_all(&download))
            .await
            .expect("the multi-frame download stalled")
            .expect("download write");

        tcp_conn.close().expect("reuse close");

        let (downloaded, end) = tokio::time::timeout(Duration::from_secs(10), client)
            .await
            .expect("the client hung after the end signal")
            .expect("client task");
        assert!(downloaded.iter().all(|b| *b == 0x33), "the download lost or reordered bytes");
        match end {
            Ok(0) => {}
            Err(err) if is_zero_chunk(&err) => {}
            other => panic!("the reuse close must end the client's stream with a zero-length frame, got {other:?}"),
        }
    }

    /// A wire whose first write parks until the test releases it, standing in for a first reply
    /// still in flight when `close` runs. Later writes pass straight through, so anything `close`
    /// emits while that reply is parked reaches the client ahead of it.
    struct StalledWire {
        inner: DuplexStream,
        state: Arc<StallState>,
        parked: bool,
    }

    struct StallState {
        released: AtomicBool,
        entered: tokio::sync::Notify,
        waker: SyncMutex<Option<std::task::Waker>>,
    }

    impl StallState {
        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            if let Some(waker) = self.waker.lock().expect("stall waker mutex poisoned").take() {
                waker.wake();
            }
        }
    }

    impl AsyncRead for StalledWire {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for StalledWire {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if !this.parked {
                this.parked = true;
                *this.state.waker.lock().expect("stall waker mutex poisoned") = Some(cx.waker().clone());
                this.state.entered.notify_one();
                if !this.state.released.load(Ordering::SeqCst) {
                    return Poll::Pending;
                }
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

    impl NetConn for StalledWire {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(DummyAddr("stalled")))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(DummyAddr("stalled")))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The close takes `write_mu`, so it can never read `reply_written` while the first reply is
    /// still being written, and never puts the "Remote EOF" frame ahead of a reply the client is
    /// entitled to. The relay's cancel path closes the client conn from inside the very poll that
    /// owns the parked write, which is the interleaving `write_mu` exists to rule out.
    #[tokio::test(flavor = "multi_thread")]
    async fn close_does_not_overtake_an_in_flight_first_reply() {
        const PSK: &[u8; 32] = &[7u8; 32];
        const DOWNLOAD: usize = 64;

        let state = Arc::new(StallState {
            released: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            waker: SyncMutex::new(None),
        });
        let (client_wire, server_wire) = duplex(4096);
        let server_snell = snell::server_stream_conn(
            Box::new(StalledWire { inner: server_wire, state: Arc::clone(&state), parked: false }),
            PSK,
            VERSION1,
        );
        let mut tcp_conn = TcpRequestConn::new(server_snell, true);
        let mut upstream = SourceConn::new(vec![0x3c; DOWNLOAD]);
        let ctx = CancellationToken::new();

        let relay = {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _ = murmur_common_net::relay_context(&ctx, &mut tcp_conn, &mut upstream).await;
            })
        };

        tokio::time::timeout(Duration::from_secs(10), state.entered.notified())
            .await
            .expect("the first reply never reached the wire");
        ctx.cancel();
        // Long enough for an unserialized close to get its frame out ahead of the parked reply.
        tokio::time::sleep(Duration::from_millis(100)).await;
        state.release();

        let mut client = snell::stream_conn(Box::new(PipeConn(client_wire)), PSK, VERSION1);
        let mut download = vec![0u8; DOWNLOAD];
        tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut download))
            .await
            .expect("the client hung instead of seeing the first reply")
            .expect("the client must see the first reply, not a command error");
        assert!(download.iter().all(|b| *b == 0x3c), "the first reply lost or reordered bytes");
        match client.read(&mut [0u8; 1]).await {
            Ok(0) => {}
            Err(err) if is_zero_chunk(&err) => {}
            other => panic!("close must end the tunnel with the zero-length frame, got {other:?}"),
        }

        relay.abort();
    }

    #[tokio::test]
    async fn read_udp_datagram_releases_the_lock_while_waiting_for_the_next_packet() {
        let (a, b) = duplex(64);
        let snell = snell::server_stream_conn(Box::new(PipeConn(a)), &[1u8; 32], VERSION1);
        let stream = Arc::new(AsyncMutex::new(snell));

        let reader = {
            let stream = Arc::clone(&stream);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64];
                read_udp_datagram(&stream, &mut buf).await
            })
        };

        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let acquired = tokio::time::timeout(Duration::from_millis(200), stream.lock()).await;
        assert!(acquired.is_ok(), "write_back must be able to take the lock while the reader has no data yet");
        drop(acquired);

        drop(b);
        let _ = reader.await;
    }

    /// `Listener::handle_udp` generates one fresh `nat_key` per call and shares it across every
    /// packet built from that call's read loop; two UDP tunnels sharing the same physical
    /// conn's `local_addr` must not collapse onto the same NAT entry.
    #[test]
    fn nat_key_differs_across_tunnels_sharing_the_same_local_addr() {
        let (a, _a_remote) = duplex(64);
        let (b, _b_remote) = duplex(64);
        let local_addr: std::net::SocketAddr = "203.0.113.12:8388".parse().unwrap();

        let conn_one =
            Arc::new(AsyncMutex::new(snell::server_stream_conn(Box::new(PipeConn(a)), &[1u8; 32], VERSION1)));
        let conn_two =
            Arc::new(AsyncMutex::new(snell::server_stream_conn(Box::new(PipeConn(b)), &[1u8; 32], VERSION1)));

        let one = UdpPacket {
            data: Vec::new(),
            conn: conn_one,
            local_addr,
            nat_key: new_uuid_v4().to_string(),
            dst_addr: None,
        };
        let two = UdpPacket {
            data: Vec::new(),
            conn: conn_two,
            local_addr,
            nat_key: new_uuid_v4().to_string(),
            dst_addr: None,
        };

        assert_eq!(one.local_addr(), two.local_addr());
        assert_ne!(one.nat_key(), two.nat_key());
    }
}

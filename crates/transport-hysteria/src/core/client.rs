use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use parking_lot::{Mutex as SyncMutex, RwLock};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex as TokioMutex};

use crate::obfs::obfs::Obfuscator;
use crate::pmtud_fix::DISABLE_PATH_MTU_DISCOVERY;
use crate::transport::client::ClientTransport;
use crate::transport::quic::{Config, TlsConfig};
use crate::utils::misc::{self, PacketDialer};
use murmur_common_net::io::{old_addr_to_socket_addr, Stream, StreamAsOldConn};
use murmur_quic::hysteria::Conn as RawQuicConn;
use murmur_quic::DatagramTooLargeError;
use murmur_std_compat::net::{Addr, Conn as NetConn};

use super::frag::{self, Defragger};
use super::protocol::{self, ClientHello, ClientRequest, UdpMessage};
use super::stream::WrappedQuicStream;

#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("closed")]
pub struct ErrClosed;

/// Bridges this package's [`RawQuicConn`] to `ClientTransport::quic_dial`'s `Arc<dyn TransportConn>`
/// return type. Whoever implements a concrete `transport::hysteria::transport::quic::Transport`
/// for hysteria is expected to hand back the `Arc<dyn TransportConn>` through [`wrap_quic_conn`],
/// so [`unwrap_quic_conn`]'s `as_any` downcast finds this adapter.
struct ConnAdapter(Arc<dyn RawQuicConn>);

impl crate::transport::quic::Conn for ConnAdapter {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// See [`ConnAdapter`].
pub fn wrap_quic_conn(inner: Arc<dyn RawQuicConn>) -> Arc<dyn crate::transport::quic::Conn> {
    Arc::new(ConnAdapter(inner))
}

/// See [`ConnAdapter`]; the inverse of [`wrap_quic_conn`].
pub fn unwrap_quic_conn(conn: &Arc<dyn crate::transport::quic::Conn>) -> Option<Arc<dyn RawQuicConn>> {
    conn.as_any().downcast_ref::<ConnAdapter>().map(|adapter| Arc::clone(&adapter.0))
}

pub type CongestionFactory = Arc<dyn Fn(u64) -> Box<dyn murmur_quic::congestion::CongestionControlEx> + Send + Sync>;

/// A `Box<dyn Addr>` handed out over a shared `Arc<dyn Addr>`; `local_addr`/`remote_addr` (called
/// repeatedly, each needing an owned `Box<dyn Addr>`) share the pseudo addr captured once at dial
/// time this way.
struct SharedAddr(Arc<dyn Addr>);

impl std::fmt::Debug for SharedAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

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

fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

struct ClientState {
    quic_session: Option<Arc<dyn RawQuicConn>>,
    closed: bool,
}

pub struct Client {
    transport: Arc<ClientTransport>,
    server_addr: String,
    server_ports: String,
    protocol: String,
    send_bps: u64,
    recv_bps: u64,
    auth: Vec<u8>,
    congestion_factory: Option<CongestionFactory>,
    obfuscator: Option<Arc<dyn Obfuscator>>,

    tls_config: Arc<dyn TlsConfig>,
    quic_config: Config,

    /// Guards the QUIC session and `closed` together; every touch of either field happens while
    /// this mutex is held.
    state: TokioMutex<ClientState>,

    udp_session_mutex: RwLock<HashMap<u32, mpsc::Sender<UdpMessage>>>,
    udp_defragger: SyncMutex<Defragger>,
    hop_interval: Duration,
    fast_open: bool,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("server_addr", &self.server_addr)
            .field("server_ports", &self.server_ports)
            .field("protocol", &self.protocol)
            .field("fast_open", &self.fast_open)
            .finish_non_exhaustive()
    }
}

impl Client {
    #[expect(clippy::too_many_arguments, reason = "the constructor takes the client's configuration field for field")]
    pub fn new_client(
        server_addr: String,
        server_ports: String,
        protocol: String,
        auth: Vec<u8>,
        tls_config: Arc<dyn TlsConfig>,
        mut quic_config: Config,
        transport: Arc<ClientTransport>,
        send_bps: u64,
        recv_bps: u64,
        congestion_factory: Option<CongestionFactory>,
        obfuscator: Option<Arc<dyn Obfuscator>>,
        hop_interval: Duration,
        fast_open: bool,
    ) -> anyhow::Result<Arc<Self>> {
        quic_config.disable_path_mtu_discovery = quic_config.disable_path_mtu_discovery || DISABLE_PATH_MTU_DISCOVERY;
        Ok(Arc::new(Self {
            transport,
            server_addr,
            server_ports,
            protocol,
            send_bps,
            recv_bps,
            auth,
            congestion_factory,
            obfuscator,
            tls_config,
            quic_config,
            state: TokioMutex::new(ClientState { quic_session: None, closed: false }),
            udp_session_mutex: RwLock::new(HashMap::new()),
            udp_defragger: SyncMutex::new(Defragger::default()),
            hop_interval,
            fast_open,
        }))
    }

    // cancel-safe: the QUIC session it opens is owned by this future and is published to the client state
    // only once the control stream is authenticated.
    async fn connect_to_server(
        self: &Arc<Self>,
        state: &mut ClientState,
        dialer: &Arc<dyn PacketDialer>,
    ) -> anyhow::Result<()> {
        let qs = self
            .transport
            .quic_dial(
                &self.protocol,
                &self.server_addr,
                &self.server_ports,
                &*self.tls_config,
                &self.quic_config,
                self.obfuscator.clone(),
                self.hop_interval,
                Arc::clone(dialer),
            )
            .await?;
        let qs = unwrap_quic_conn(&qs)
            .ok_or_else(|| anyhow!("hysteria: quic transport did not return a wrapped connection"))?;

        // Control stream.
        let stream = match tokio::time::timeout(protocol::PROTOCOL_TIMEOUT, qs.open_stream_sync()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                let _ = qs.close_with_error(protocol::CLOSE_ERROR_CODE_PROTOCOL, "protocol error");
                return Err(err);
            }
            Err(_) => {
                let _ = qs.close_with_error(protocol::CLOSE_ERROR_CODE_PROTOCOL, "protocol error");
                return Err(anyhow!("context deadline exceeded"));
            }
        };
        let mut stream = WrappedQuicStream::new(stream);

        let (ok, msg) = match self.handle_control_stream(&qs, &mut stream).await {
            Ok(result) => result,
            Err(err) => {
                let _ = qs.close_with_error(protocol::CLOSE_ERROR_CODE_PROTOCOL, "protocol error");
                return Err(err);
            }
        };
        if !ok {
            let _ = qs.close_with_error(protocol::CLOSE_ERROR_CODE_AUTH, "auth error");
            return Err(anyhow!("auth error: {msg}"));
        }

        // All good.
        *self.udp_session_mutex.write() = HashMap::new();
        tokio::spawn({
            let client = Arc::clone(self);
            let qs = Arc::clone(&qs);
            async move { client.handle_message(qs).await }
        });
        state.quic_session = Some(qs);
        Ok(())
    }

    async fn handle_control_stream(
        &self,
        qs: &Arc<dyn RawQuicConn>,
        stream: &mut WrappedQuicStream,
    ) -> anyhow::Result<(bool, String)> {
        // Send client hello.
        protocol::write_client_hello(
            stream,
            &ClientHello { send_bps: self.send_bps, recv_bps: self.recv_bps, auth: self.auth.clone() },
        )
        .await?;
        // Receive server hello.
        let sh = protocol::read_server_hello(stream).await?;
        // Set the congestion accordingly.
        if sh.ok {
            if let Some(factory) = &self.congestion_factory {
                qs.set_congestion_control(factory(sh.recv_bps));
            }
        }
        Ok((sh.ok, sh.message))
    }

    async fn handle_message(self: Arc<Self>, qs: Arc<dyn RawQuicConn>) {
        loop {
            let Ok(msg) = qs.receive_datagram().await else { break };
            let Ok(udp_msg) = UdpMessage::unpack(&msg) else { continue };
            let Some(df_msg) = self.udp_defragger.lock().feed(udp_msg) else { continue };
            let map = self.udp_session_mutex.read();
            if let Some(sender) = map.get(&df_msg.session_id) {
                // Silently drop the message when the channel is full.
                let _ = sender.try_send(df_msg);
            }
        }
    }

    async fn open_stream_with_reconnect(
        self: &Arc<Self>,
        dialer: &Arc<dyn PacketDialer>,
    ) -> anyhow::Result<(Arc<dyn RawQuicConn>, WrappedQuicStream)> {
        let mut state = self.state.lock().await;
        if state.closed {
            return Err(ErrClosed.into());
        }
        if state.quic_session.is_none() {
            // Still error, oops.
            self.connect_to_server(&mut state, dialer).await?;
        }
        let qs = state
            .quic_session
            .clone()
            .ok_or_else(|| anyhow!("hysteria: connect_to_server returned without a quic session"))?;
        match qs.open_stream() {
            Ok(stream) => return Ok((qs, WrappedQuicStream::new(stream))),
            Err(_err) => {
                // A temporary stream-open error returns without reconnecting. No error type in
                // this seam marks itself temporary, so every failure falls through to the
                // reconnect below.
            }
        }
        // Permanent error, need to reconnect.
        self.connect_to_server(&mut state, dialer).await?;
        // We are not going to try again even if it still fails the second time.
        let qs = state
            .quic_session
            .clone()
            .ok_or_else(|| anyhow!("hysteria: connect_to_server returned without a quic session"))?;
        // Nothing below touches `state`, so let go of the lock before opening a stream that may
        // block a concurrent dial.
        drop(state);
        let stream = qs.open_stream()?;
        Ok((qs, WrappedQuicStream::new(stream)))
    }

    pub async fn dial_tcp(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        dialer: Arc<dyn PacketDialer>,
    ) -> anyhow::Result<Box<dyn NetConn>> {
        let (session, mut stream) = self.open_stream_with_reconnect(&dialer).await?;

        // Send request.
        if let Err(err) =
            protocol::write_client_request(&mut stream, &ClientRequest { udp: false, host: host.to_owned(), port })
                .await
        {
            let _ = stream.close();
            return Err(err);
        }

        // If fast open is enabled, we return the stream immediately and defer the response
        // handling to the first Read() call.
        let established = if self.fast_open {
            false
        } else {
            match protocol::read_server_response(&mut stream).await {
                Ok(sr) if sr.ok => true,
                Ok(sr) => {
                    let _ = stream.close();
                    return Err(anyhow!("connection rejected: {}", sr.message));
                }
                Err(err) => {
                    let _ = stream.close();
                    return Err(err);
                }
            }
        };

        let pseudo_local_addr: Arc<dyn Addr> = Arc::from(session.local_addr());
        let pseudo_remote_addr: Arc<dyn Addr> = Arc::from(session.remote_addr());
        let conn = QuicConn {
            close_view: QuicConnCloseView {
                orig: stream.clone(),
                pseudo_local_addr: Arc::clone(&pseudo_local_addr),
                pseudo_remote_addr: Arc::clone(&pseudo_remote_addr),
            },
            orig: stream,
            pseudo_local_addr,
            pseudo_remote_addr,
            established: AtomicBool::new(established),
            establish: SyncMutex::new(None),
        };
        Ok(Box::new(StreamAsOldConn::new(conn)))
    }

    pub async fn dial_udp(self: &Arc<Self>, dialer: Arc<dyn PacketDialer>) -> anyhow::Result<Box<dyn UdpConn>> {
        let (session, mut stream) = self.open_stream_with_reconnect(&dialer).await?;

        // Send request.
        if let Err(err) =
            protocol::write_client_request(&mut stream, &ClientRequest { udp: true, host: String::new(), port: 0 })
                .await
        {
            let _ = stream.close();
            return Err(err);
        }
        // Read response.
        let sr = match protocol::read_server_response(&mut stream).await {
            Ok(sr) => sr,
            Err(err) => {
                let _ = stream.close();
                return Err(err);
            }
        };
        if !sr.ok {
            let _ = stream.close();
            return Err(anyhow!("connection rejected: {}", sr.message));
        }

        // Create a session in the map.
        let (tx, rx) = mpsc::channel(1024);
        self.udp_session_mutex.write().insert(sr.udp_session_id, tx);

        let pkt_conn = Arc::new(QuicPktConn {
            session,
            stream,
            udp_session_id: sr.udp_session_id,
            msg_rx: TokioMutex::new(rx),
            client: Arc::clone(self),
        });
        tokio::spawn(Arc::clone(&pkt_conn).hold());
        Ok(Box::new(pkt_conn))
    }

    pub async fn close(self: &Arc<Self>) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        let result = match &state.quic_session {
            Some(qs) => qs.close_with_error(protocol::CLOSE_ERROR_CODE_GENERIC, ""),
            None => Ok(()),
        };
        state.closed = true;
        result
    }
}

type EstablishFuture = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;

struct QuicConn {
    orig: WrappedQuicStream,
    pseudo_local_addr: Arc<dyn Addr>,
    pseudo_remote_addr: Arc<dyn Addr>,
    established: AtomicBool,
    establish: SyncMutex<Option<EstablishFuture>>,
    close_view: QuicConnCloseView,
}

impl QuicConn {
    fn close_impl(&self) -> io::Result<()> {
        self.orig.close()
    }
}

impl AsyncRead for QuicConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.established.load(Ordering::SeqCst) {
            let mut guard = this.establish.lock();
            if guard.is_none() {
                let mut reader = this.orig.clone();
                *guard = Some(Box::pin(async move {
                    let sr = protocol::read_server_response(&mut reader).await?;
                    if !sr.ok {
                        return Err(anyhow!("connection rejected: {}", sr.message));
                    }
                    Ok(())
                }));
            }
            let Some(fut) = guard.as_mut() else {
                return Poll::Ready(Err(io::Error::other("establish future was just installed")));
            };
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {
                    *guard = None;
                    drop(guard);
                    this.established.store(true, Ordering::SeqCst);
                }
                Poll::Ready(Err(err)) => {
                    *guard = None;
                    drop(guard);
                    let _ = this.close_impl();
                    return Poll::Ready(Err(io::Error::other(err)));
                }
            }
        }
        Pin::new(&mut this.orig).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().orig).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().orig).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().orig).poll_shutdown(cx)
    }
}

impl Stream for QuicConn {
    /// The pseudo QUIC-session address is not socket-backed, so this goes through the same
    /// conversion the old-`Conn`/`Stream` bridges use.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.pseudo_local_addr.as_ref())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.pseudo_remote_addr.as_ref())
    }

    /// There is no separate read/write close on the QUIC conn, so `shutdown_read`/`shutdown_write`
    /// stay the inherited no-op defaults; the real close (cancel-read then close the QUIC stream)
    /// lives on `old_conn` instead.
    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(&self.close_view)
    }
}

/// Close-only old-`Conn` view for [`QuicConn`], reached only through [`Stream::old_conn`] so
/// `close()` on the still-old-API caller (via `StreamAsOldConn`) reaches the real one-shot QUIC
/// stream reset ([`WrappedQuicStream::close`]).
struct QuicConnCloseView {
    orig: WrappedQuicStream,
    pseudo_local_addr: Arc<dyn Addr>,
    pseudo_remote_addr: Arc<dyn Addr>,
}

/// Never polled; `Conn` requires `AsyncRead + AsyncWrite`, so this forwards to the same
/// [`WrappedQuicStream`] [`QuicConn`] itself reads and writes through.
impl AsyncRead for QuicConnCloseView {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().orig).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicConnCloseView {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().orig).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().orig).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().orig).poll_shutdown(cx)
    }
}

impl NetConn for QuicConnCloseView {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(SharedAddr(Arc::clone(&self.pseudo_local_addr))))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(SharedAddr(Arc::clone(&self.pseudo_remote_addr))))
    }

    fn close(&self) -> io::Result<()> {
        self.orig.close()
    }
}

#[async_trait]
pub trait UdpConn: Send + Sync {
    async fn read_from(&self) -> anyhow::Result<(Vec<u8>, String)>;
    async fn write_to(&self, p: &[u8], addr: &str) -> anyhow::Result<()>;
    fn close(&self) -> anyhow::Result<()>;
    fn local_addr(&self) -> Box<dyn Addr>;
    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
}

struct QuicPktConn {
    session: Arc<dyn RawQuicConn>,
    stream: WrappedQuicStream,
    udp_session_id: u32,
    msg_rx: TokioMutex<mpsc::Receiver<UdpMessage>>,
    client: Arc<Client>,
}

impl QuicPktConn {
    /// Holds the stream until it is closed.
    async fn hold(self: Arc<Self>) {
        let mut buf = [0u8; 1024];
        let mut reader = self.stream.clone();
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = self.close_impl();
    }

    fn close_impl(&self) -> io::Result<()> {
        // Removes the session so that reconnecting will reassign the map, and dropping the sender
        // makes subsequent `recv()` calls observe the channel as closed.
        self.client.udp_session_mutex.write().remove(&self.udp_session_id);
        self.stream.close()
    }
}

#[async_trait]
impl UdpConn for Arc<QuicPktConn> {
    async fn read_from(&self) -> anyhow::Result<(Vec<u8>, String)> {
        let mut rx = self.msg_rx.lock().await;
        match rx.recv().await {
            Some(msg) => Ok((msg.data, join_host_port(&msg.host, msg.port))),
            None => Err(ErrClosed.into()),
        }
    }

    async fn write_to(&self, p: &[u8], addr: &str) -> anyhow::Result<()> {
        let (host, port) = misc::split_host_port(addr)?;
        let mut msg = UdpMessage {
            session_id: self.udp_session_id,
            host,
            port,
            msg_id: 0,
            frag_id: 0,
            frag_count: 1,
            data: p.to_vec(),
        };
        // Try no frag first.
        match self.session.send_datagram(&msg.pack()) {
            Ok(()) => Ok(()),
            Err(err) => {
                if let Some(size_err) = err.downcast_ref::<DatagramTooLargeError>() {
                    // Need to frag. `msg_id` must be > 0 when `frag_count` > 1.
                    msg.msg_id = rand::rng().random_range(0..0xFFFFu16) + 1;
                    let max_payload = usize::try_from(size_err.max_datagram_payload_size.max(0)).unwrap_or(0);
                    for frag_msg in frag::frag_udp_message(&msg, max_payload) {
                        self.session.send_datagram(&frag_msg.pack())?;
                    }
                    Ok(())
                } else {
                    // Some other error.
                    Err(err)
                }
            }
        }
    }

    fn close(&self) -> anyhow::Result<()> {
        self.close_impl().map_err(Into::into)
    }

    fn local_addr(&self) -> Box<dyn Addr> {
        self.session.local_addr()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.stream.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.stream.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.stream.set_write_deadline(deadline)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio_util::sync::CancellationToken;

    use super::*;

    #[derive(Debug)]
    struct FakeAddr;

    impl Addr for FakeAddr {
        fn network(&self) -> &str {
            "fake"
        }
        fn string(&self) -> String {
            "127.0.0.1:0".to_owned()
        }
    }

    #[derive(Default)]
    struct FakeQuicStream {
        cancel_read_called: AtomicBool,
        closed: AtomicBool,
    }

    impl murmur_quic::hysteria::Stream for FakeQuicStream {
        fn stream_id(&self) -> murmur_quic::StreamId {
            0
        }
        fn poll_read(&self, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_write(&self, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn cancel_read(&self, _code: murmur_quic::StreamErrorCode) {
            self.cancel_read_called.store(true, Ordering::SeqCst);
        }
        fn cancel_write(&self, _code: murmur_quic::StreamErrorCode) {}
        fn close(&self) -> io::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            Ok(())
        }
        fn set_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            Ok(())
        }
        fn context(&self) -> CancellationToken {
            CancellationToken::new()
        }
    }

    /// Regression for the `Conn`->`Stream` conversion: `QuicConn` does not wrap an old-style
    /// conn (its inner value is a QUIC stream from a different crate), so the real one-shot close
    /// (cancel-read then close) has to reach through `QuicConnCloseView` instead. Without it,
    /// `StreamAsOldConn::close` would only mark the bridge closed and cancel its own deadline
    /// tokens, never touching the QUIC stream.
    #[tokio::test]
    async fn close_through_stream_as_old_conn_reaches_the_real_quic_stream() {
        let fake = Arc::new(FakeQuicStream::default());
        let stream = WrappedQuicStream::new(Arc::<FakeQuicStream>::clone(&fake));
        let pseudo_addr: Arc<dyn Addr> = Arc::new(FakeAddr);
        let conn = QuicConn {
            close_view: QuicConnCloseView {
                orig: stream.clone(),
                pseudo_local_addr: Arc::clone(&pseudo_addr),
                pseudo_remote_addr: Arc::clone(&pseudo_addr),
            },
            orig: stream,
            pseudo_local_addr: Arc::clone(&pseudo_addr),
            pseudo_remote_addr: pseudo_addr,
            established: AtomicBool::new(true),
            establish: SyncMutex::new(None),
        };
        let old_conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(conn));

        old_conn.close().expect("close");

        assert!(fake.cancel_read_called.load(Ordering::SeqCst), "close must cancel-read the QUIC stream");
        assert!(fake.closed.load(Ordering::SeqCst), "close must reach the real QUIC stream close");
    }
}

//! The client.
//!
//! The client keeps one authenticated QUIC connection and multiplexes every TCP stream and UDP
//! session over it.
//!
//! Two QUIC behaviours have no `quinn` equivalent and are reported rather than faked:
//!
//! * Retargeting a live connection's port for the hop loop. `quinn::Connection` has no such call
//!   and the endpoint owns the path, so `server-ports` picks the port per *connection* but a live
//!   connection never re-hops.
//! * Setting the congestion control to a Brutal sender. The rate only arrives in the auth
//!   response, after quinn has bound its controller, so [`CongestionOption`] is applied when the
//!   connection is built.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{bail, Result};
use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Conn, PacketConn};

use crate::obfs::Obfs;
use crate::packet::{QuicDatagrams, UdpPacketConn};
use crate::protocol::{self, AuthRequest, UdpMessage};
use crate::quic::{
    poll_write_header, transport_config, CongestionOption, PacketConnSocket, QuicConfig, QuicConn, QuicStream,
};

const MIN_HOP_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);

pub struct ClientOptions {
    pub password: String,
    pub server_address: Socksaddr,
    /// A random entry is picked per connection when non-empty.
    pub server_ports: Vec<u16>,
    pub hop_interval: Duration,
    pub hop_interval_max: Duration,
    pub send_bps: u64,
    pub receive_bps: u64,
    pub obfs: Option<Obfs>,
    /// The name quinn verifies and sends, which the adapter resolves
    /// from the `sni` option or else the server host. Never the dialled address.
    pub server_name: String,
    pub tls: Arc<rustls::ClientConfig>,
    pub quic: QuicConfig,
    pub udp_disabled: bool,
    pub udp_mtu: usize,
    pub congestion: CongestionOption,
    pub handshake_timeout: Duration,
    /// The proxy-aware packet conn the QUIC session runs over, before obfuscation.
    pub packet_conn: Arc<dyn PacketConn>,
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions")
            .field("server_address", &self.server_address)
            .field("server_ports", &self.server_ports)
            .field("hop_interval", &self.hop_interval)
            .field("hop_interval_max", &self.hop_interval_max)
            .field("send_bps", &self.send_bps)
            .field("receive_bps", &self.receive_bps)
            .field("server_name", &self.server_name)
            .field("quic", &self.quic)
            .field("udp_disabled", &self.udp_disabled)
            .field("udp_mtu", &self.udp_mtu)
            .field("congestion", &self.congestion)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

impl ClientOptions {
    /// The default UDP MTU: the QUIC max datagram size (1200) less the datagram-frame overhead,
    /// the largest payload hysteria2 ever emits whole.
    pub const DEFAULT_UDP_MTU: usize = 1200 - 3;

    #[must_use]
    pub fn resolved_udp_mtu(&self) -> usize {
        if self.udp_mtu == 0 {
            Self::DEFAULT_UDP_MTU
        } else {
            self.udp_mtu
        }
    }

    /// the `start`/`end` clamping of the configured `hop-interval`.
    #[must_use]
    pub fn resolved_hop_intervals(&self) -> (Duration, Duration) {
        let mut start = self.hop_interval;
        if start.is_zero() {
            start = DEFAULT_HOP_INTERVAL;
        } else if start < MIN_HOP_INTERVAL {
            start = MIN_HOP_INTERVAL;
        }
        let end = if self.hop_interval_max < start { start } else { self.hop_interval_max };
        (start, end)
    }
}

#[derive(Clone)]
pub struct Client(Arc<ClientInner>);

struct ClientInner {
    options: ClientOptions,
    /// The lifetime a connection attempt hangs off, so a request that gives up
    /// never tears down a dial that a later request will reuse.
    lifetime: CancellationToken,
    conn: tokio::sync::Mutex<Option<Arc<ClientConn>>>,
    closed: Mutex<bool>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("closed", &*self.0.closed.lock()).finish()
    }
}

impl Client {
    pub fn new(options: ClientOptions) -> Result<Self> {
        if options.server_address.port == 0 && options.server_ports.is_empty() {
            bail!("invalid port");
        }
        if options.server_ports.contains(&0) {
            bail!("invalid port");
        }
        let quic = options.quic.clone().with_defaults();
        let options = ClientOptions { quic, ..options };
        Ok(Self(Arc::new(ClientInner {
            options,
            lifetime: CancellationToken::new(),
            conn: tokio::sync::Mutex::new(None),
            closed: Mutex::new(false),
        })))
    }

    pub async fn dial_conn(&self, ctx: &CancellationToken, destination: Socksaddr) -> io::Result<Box<dyn Conn>> {
        let conn = self.0.offer(ctx).await?;
        let stream = conn.quic.open_stream().await?;
        Ok(Box::new(ClientStream::new(stream, destination.string())))
    }

    pub async fn listen_packet(&self, ctx: &CancellationToken) -> io::Result<Box<dyn PacketConn>> {
        if self.0.options.udp_disabled {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2: UDP disabled"));
        }
        let conn = self.0.offer(ctx).await?;
        if conn.udp_disabled {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2: UDP disabled by server"));
        }
        let session = conn.new_udp_session();
        Ok(Box::new(SessionPacketConn(session)))
    }

    pub fn close_with_error(&self, reason: &str) -> io::Result<()> {
        let already_closed = std::mem::replace(&mut *self.0.closed.lock(), true);
        if already_closed {
            return Ok(());
        }
        self.0.lifetime.cancel();
        if let Ok(guard) = self.0.conn.try_lock() {
            if let Some(conn) = guard.clone() {
                conn.close_with_error(reason);
            }
        }
        Ok(())
    }
}

impl ClientInner {
    /// one shared connection, established at most once at a time.
    async fn offer(&self, ctx: &CancellationToken) -> io::Result<Arc<ClientConn>> {
        if *self.closed.lock() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "hysteria2: client closed"));
        }
        let lock = self.conn.lock();
        let mut guard = tokio::select! {
            biased;
            () = ctx.cancelled() => return Err(cancelled()),
            guard = lock => guard,
        };
        if let Some(conn) = guard.as_ref() {
            if conn.active() {
                return Ok(Arc::clone(conn));
            }
        }
        let conn = self.authenticate_and_wrap().await?;
        *guard = Some(Arc::clone(&conn));
        drop(guard);
        Ok(conn)
    }

    /// Dials a server and authenticates on it, without the realm negotiation.
    async fn authenticate_and_wrap(&self) -> io::Result<Arc<ClientConn>> {
        let server = self.next_server_address();
        let server_addr: SocketAddr = server
            .addr_port()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hysteria2: server address has no IP"))?;
        let conn = tokio::time::timeout(self.options.handshake_timeout, self.connect(server_addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "hysteria2: handshake timeout"))??;
        self.authenticate(conn).await
    }

    /// Picks a random port from `server_ports` when one is configured.
    fn next_server_address(&self) -> Socksaddr {
        let mut server = self.options.server_address.clone();
        if !self.options.server_ports.is_empty() {
            let pick = rand::rng().random_range(0..self.options.server_ports.len());
            if let Some(&port) = self.options.server_ports.get(pick) {
                server.port = port;
            }
        }
        server
    }

    /// Dials the address, with the name in the TLS ClientHello taken from
    /// `ClientOptions::server_name`.
    async fn connect(&self, server_addr: SocketAddr) -> io::Result<Arc<QuicConn>> {
        let packet_conn = match &self.options.obfs {
            Some(obfs) => obfs.wrap(Arc::clone(&self.options.packet_conn)),
            None => Arc::clone(&self.options.packet_conn),
        };
        let socket = PacketConnSocket::new(packet_conn)?;
        let runtime = quinn::default_runtime().ok_or_else(|| io::Error::other("quinn has no async runtime"))?;
        let mut endpoint =
            quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), None, socket, runtime)
                .map_err(io::Error::other)?;

        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from((*self.options.tls).clone()).map_err(io::Error::other)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(transport_config(&self.options.quic, &self.options.congestion)));
        endpoint.set_default_client_config(client_config);

        let mut connecting = endpoint
            .connect(server_addr, &self.options.server_name)
            .map_err(|err| io::Error::other(format!("hysteria2: {err}")))?;
        let connection = tokio::select! {
            biased;
            () = self.lifetime.cancelled() => return Err(cancelled()),
            result = &mut connecting => result.map_err(io::Error::other)?,
        };
        Ok(QuicConn::with_endpoint(connection, endpoint))
    }

    /// The authentication exchange: a `POST` to the auth endpoint over HTTP/3.
    async fn authenticate(&self, conn: Arc<QuicConn>) -> io::Result<Arc<ClientConn>> {
        let h3_conn = h3_quinn::Connection::new(conn.connection.clone());
        let (mut driver, mut send_request) = h3::client::new(h3_conn).await.map_err(io::Error::other)?;
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let url = format!("https://{}{}", protocol::URL_HOST, protocol::URL_PATH);
        let mut request = http::Request::post(url).body(()).map_err(io::Error::other)?;
        *request.headers_mut() = protocol::auth_request_to_header(&AuthRequest {
            auth: self.options.password.clone(),
            rx: self.options.receive_bps,
        });

        let mut stream = send_request.send_request(request).await.map_err(io::Error::other)?;
        stream.finish().await.map_err(io::Error::other)?;
        let response = stream.recv_response().await.map_err(io::Error::other)?;
        let status = response.status().as_u16();
        if status != protocol::STATUS_AUTH_OK {
            let _ = conn.close_with_error(0, "");
            return Err(io::Error::other(format!("hysteria2: authentication failed, status code: {status}")));
        }
        let auth = protocol::auth_response_from_header(response.headers());

        let actual_tx = if auth.rx == 0 || auth.rx > self.options.send_bps { self.options.send_bps } else { auth.rx };
        murmur_log::debugln!("hysteria2: authenticated, server rx {}, tx in use {actual_tx}", auth.rx);

        let conn = Arc::new(ClientConn {
            quic: conn,
            udp_disabled: self.options.udp_disabled || !auth.udp_enabled,
            udp_mtu: self.options.resolved_udp_mtu(),
            sessions: Mutex::new(SessionTable::default()),
            done: CancellationToken::new(),
            send_request,
        });
        if !conn.udp_disabled {
            tokio::spawn(Arc::clone(&conn).loop_messages());
        }
        Ok(conn)
    }
}

pub struct ClientConn {
    pub quic: Arc<QuicConn>,
    udp_disabled: bool,
    udp_mtu: usize,
    sessions: Mutex<SessionTable>,
    done: CancellationToken,
    /// h3's session handle, held for the connection's lifetime only: `h3` counts `SendRequest`
    /// instances and closes the QUIC connection with `HTTP_NO_ERROR` when the last one drops, while
    /// the HTTP/3 transport stays in the connection pool. Never used after authentication.
    #[allow(dead_code)]
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
}

#[derive(Default)]
struct SessionTable {
    next_session_id: u32,
    sessions: std::collections::HashMap<u32, Arc<UdpPacketConn>>,
}

impl std::fmt::Debug for ClientConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConn")
            .field("quic", &self.quic)
            .field("udp_disabled", &self.udp_disabled)
            .field("udp_mtu", &self.udp_mtu)
            .finish_non_exhaustive()
    }
}

impl ClientConn {
    fn active(&self) -> bool {
        !self.done.is_cancelled() && self.quic.connection.close_reason().is_none()
    }

    /// Registers a new UDP session and returns its handle.
    fn new_udp_session(self: &Arc<Self>) -> Arc<UdpPacketConn> {
        let session_id = {
            let mut table = self.sessions.lock();
            let session_id = table.next_session_id;
            table.next_session_id = table.next_session_id.wrapping_add(1);
            session_id
        };
        let owner = Arc::clone(self);
        let session = UdpPacketConn::new(
            session_id,
            Arc::<QuicConn>::clone(&self.quic),
            self.udp_mtu,
            Box::new(move || {
                owner.sessions.lock().sessions.remove(&session_id);
            }),
        );
        self.sessions.lock().sessions.insert(session_id, Arc::clone(&session));
        session
    }

    /// route each datagram to the session it names.
    async fn loop_messages(self: Arc<Self>) {
        loop {
            let raw = tokio::select! {
                biased;
                () = self.done.cancelled() => return,
                result = self.quic.receive_datagram() => match result {
                    Ok(raw) => raw,
                    Err(err) => {
                        murmur_log::debugln!("hysteria2: receive message: {err}");
                        self.close_with_error(&err.to_string());
                        return;
                    }
                },
            };
            let message = match protocol::parse_udp_message(&raw) {
                Ok(message) => message,
                Err(err) => {
                    murmur_log::debugln!("hysteria2: decode UDP message: {err}");
                    self.close_with_error(&err.to_string());
                    return;
                }
            };
            self.dispatch(message);
        }
    }

    /// Routes a datagram to the session it names; the server routes its own datagrams the same
    /// way, and one naming no live session is dropped.
    pub fn dispatch(self: &Arc<Self>, message: UdpMessage) {
        let session = self.sessions.lock().sessions.get(&message.session_id).cloned();
        if let Some(session) = session {
            session.input_packet(message);
        }
    }

    pub fn close_with_error(&self, reason: &str) {
        self.done.cancel();
        let sessions: Vec<Arc<UdpPacketConn>> = {
            let mut table = self.sessions.lock();
            table.sessions.drain().map(|(_, session)| session).collect()
        };
        for session in sessions {
            session.close();
        }
        let _ = self.quic.close_with_error(0, reason);
    }
}

#[must_use]
pub fn next_hop_interval(start: Duration, max: Duration) -> Duration {
    if start >= max {
        return start;
    }
    let span = u64::try_from(max.saturating_sub(start).as_millis().max(1)).unwrap_or(u64::MAX);
    start + Duration::from_millis(rand::rng().random_range(0..=span))
}

/// A QUIC stream that writes its destination ahead of the first payload and
/// withholds the payload until the peer's verdict has been read.
#[derive(Debug)]
pub struct ClientStream {
    stream: QuicStream,
    destination: String,
    /// The request header while any of it is still on its way to the peer; `None` before the first
    /// write builds it and after the send half has taken every byte of it.
    request_header: Option<BytesMut>,
    request_written: bool,
    response_read: bool,
    prefix: Vec<u8>,
}

impl ClientStream {
    fn new(stream: QuicStream, destination: String) -> Self {
        Self {
            stream,
            destination,
            request_header: None,
            request_written: false,
            response_read: false,
            prefix: Vec::new(),
        }
    }

    /// Hands whatever is left of the request header to the send half, keeping the tail a short
    /// accept left over for the poll that follows. Nothing is built here: an absent header means the
    /// first write has not been polled yet, so a flush or a shutdown before it still sends nothing.
    fn poll_request_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(header) = self.request_header.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match poll_write_header(&mut self.stream.send, cx, header) {
            Poll::Ready(Ok(())) => {
                self.request_written = true;
                self.request_header = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Consumes the response header out of `prefix`, growing it from the stream until it parses.
    /// The parse runs against an in-memory cursor, so it never yields `Pending` itself and a
    /// re-poll after a short read resumes exactly where the previous one stopped.
    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let (outcome, consumed) = {
                let mut cursor = io::Cursor::new(self.prefix.as_slice());
                let outcome =
                    futures::executor::block_on(protocol::read_tcp_response(&mut cursor)).map_err(io::Error::other);
                (outcome, usize::try_from(cursor.position()).unwrap_or(self.prefix.len()))
            };
            match outcome {
                Ok((true, _)) => {
                    self.prefix.drain(..consumed);
                    self.response_read = true;
                    return Poll::Ready(Ok(()));
                }
                Ok((false, message)) => {
                    return Poll::Ready(Err(io::Error::other(format!("hysteria2: remote error: {message}"))))
                }
                Err(_) => {
                    let mut scratch = [0u8; 512];
                    let mut read_buf = ReadBuf::new(&mut scratch);
                    match AsyncRead::poll_read(Pin::new(&mut self.stream.recv), cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            let filled = read_buf.filled();
                            if filled.is_empty() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "hysteria2: stream ended before the response header",
                                )));
                            }
                            self.prefix.extend_from_slice(filled);
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl AsyncRead for ClientStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if !self.response_read {
            match self.poll_response(cx) {
                Poll::Ready(result) => result?,
                Poll::Pending => return Poll::Pending,
            }
        }
        if !self.prefix.is_empty() {
            let len = self.prefix.len().min(buf.remaining());
            let (head, _) = self.prefix.split_at(len);
            buf.put_slice(head);
            self.prefix.drain(..len);
            return Poll::Ready(Ok(()));
        }
        AsyncRead::poll_read(Pin::new(&mut self.stream.recv), cx, buf)
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if !this.request_written {
            if this.request_header.is_none() {
                this.request_header = Some(protocol::write_tcp_request_header(&this.destination));
            }
            // The header goes out whole before any payload byte can follow it; a window too small for
            // it leaves the tail here for the next poll instead of failing the write.
            match this.poll_request_header(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        AsyncWrite::poll_write(Pin::new(&mut this.stream.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        // A flush cannot report success while a header the send half only partly took is still here.
        match this.poll_request_header(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
        AsyncWrite::poll_flush(Pin::new(&mut this.stream.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        // The FIN may only follow a complete header, never a truncated one.
        match this.poll_request_header(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
        AsyncWrite::poll_shutdown(Pin::new(&mut this.stream.send), cx)
    }
}

/// The session conn behind the boxed [`PacketConn`] a caller receives; `murmur_std_compat::net`
/// has no blanket impl for `Arc<P>`, and the session is shared with the connection's datagram loop.
#[derive(Debug)]
pub struct SessionPacketConn(Arc<UdpPacketConn>);

#[async_trait::async_trait]
impl PacketConn for SessionPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn murmur_std_compat::net::Addr>)> {
        self.0.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn murmur_std_compat::net::Addr) -> io::Result<usize> {
        self.0.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        self.0.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        UdpPacketConn::close(&self.0);
        Ok(())
    }
}

impl Conn for ClientStream {
    fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2 proxy conn has no address"))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2 proxy conn has no address"))
    }

    fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2 proxy conn has no deadline"))
    }

    fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2 proxy conn has no deadline"))
    }

    fn close(&self) -> io::Result<()> {
        self.stream.send_stop();
        Ok(())
    }
}

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "hysteria2: operation cancelled")
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use murmur_component_ca::keypair::{new_random_tls_key_pair, KeyPairType};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::AsyncWriteExt;

    use super::*;

    async fn base() -> ClientOptions {
        ClientOptions {
            password: "pw".to_owned(),
            server_address: Socksaddr::from_ip("192.0.2.1".parse().unwrap(), 443),
            server_ports: Vec::new(),
            hop_interval: Duration::ZERO,
            hop_interval_max: Duration::ZERO,
            send_bps: 0,
            receive_bps: 0,
            obfs: None,
            server_name: "server.example.com".to_owned(),
            tls: Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .expect("tls 1.3 only")
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth(),
            ),
            quic: QuicConfig::default(),
            udp_disabled: false,
            udp_mtu: 0,
            congestion: CongestionOption::default(),
            handshake_timeout: Duration::from_secs(10),
            packet_conn: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()),
        }
    }

    #[tokio::test]
    async fn a_server_without_any_port_is_rejected() {
        let mut options = base().await;
        options.server_address = Socksaddr::from_ip("192.0.2.1".parse().unwrap(), 0);
        assert_eq!(Client::new(options).unwrap_err().to_string(), "invalid port");
    }

    #[tokio::test]
    async fn a_port_hopping_list_alone_is_enough() {
        let mut options = base().await;
        options.server_address = Socksaddr::from_ip("192.0.2.1".parse().unwrap(), 0);
        options.server_ports = vec![200, 300];
        assert!(Client::new(options).is_ok());
    }

    #[tokio::test]
    async fn a_zero_port_inside_the_hopping_list_is_rejected() {
        let mut options = base().await;
        options.server_ports = vec![200, 0];
        assert_eq!(Client::new(options).unwrap_err().to_string(), "invalid port");
    }

    #[tokio::test]
    async fn the_udp_mtu_default_is_the_reference_value() {
        assert_eq!(base().await.resolved_udp_mtu(), 1197);
        let mut options = base().await;
        options.udp_mtu = 1000;
        assert_eq!(options.resolved_udp_mtu(), 1000);
    }

    #[tokio::test]
    async fn hop_intervals_clamp_to_the_bounds() {
        let mut options = base().await;
        assert_eq!(options.resolved_hop_intervals(), (DEFAULT_HOP_INTERVAL, DEFAULT_HOP_INTERVAL));

        options.hop_interval = Duration::from_secs(1);
        options.hop_interval_max = Duration::from_secs(2);
        assert_eq!(options.resolved_hop_intervals(), (MIN_HOP_INTERVAL, MIN_HOP_INTERVAL));

        options.hop_interval = Duration::from_secs(30);
        options.hop_interval_max = Duration::from_secs(10);
        assert_eq!(options.resolved_hop_intervals(), (Duration::from_secs(30), Duration::from_secs(30)));
    }

    #[test]
    fn hop_interval_stays_inside_the_configured_window() {
        let start = Duration::from_secs(10);
        let max = Duration::from_secs(20);
        for _ in 0..200 {
            let next = next_hop_interval(start, max);
            assert!(next >= start && next <= max, "{next:?}");
        }
        assert_eq!(next_hop_interval(Duration::from_secs(20), Duration::from_secs(10)), Duration::from_secs(20));
    }

    #[tokio::test]
    async fn hopping_picks_only_configured_ports() {
        let mut options = base().await;
        options.server_ports = vec![200, 300];
        let client = Client::new(options).unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(client.0.next_server_address().port);
        }
        assert_eq!(seen, [200, 300].into_iter().collect());
    }

    #[tokio::test]
    async fn without_hopping_the_configured_port_is_used() {
        let mut options = base().await;
        options.server_address = Socksaddr::from_ip("192.0.2.1".parse().unwrap(), 8443);
        let client = Client::new(options).unwrap();
        assert_eq!(client.0.next_server_address().port, 8443);
    }

    #[tokio::test]
    async fn the_quic_config_takes_the_defaults_at_construction() {
        let client = Client::new(base().await).unwrap();
        assert_eq!(client.0.options.quic.max_idle_timeout, crate::quic::DEFAULT_MAX_IDLE_TIMEOUT);
        assert_eq!(client.0.options.quic.max_connection_receive_window, crate::quic::DEFAULT_CONN_RECEIVE_WINDOW);
    }

    #[tokio::test]
    async fn the_quinn_server_name_is_the_configured_name_and_never_the_dialled_address() {
        // The adapter resolves the name before the client is built: the `sni` option when set,
        // else the server.
        fn adapter_server_name(sni: &str, server: &str) -> String {
            if sni.is_empty() {
                server.to_owned()
            } else {
                sni.to_owned()
            }
        }

        let mut options = base().await;
        options.server_name = adapter_server_name("sni.example.com", "server.example.com");
        let with_sni = Client::new(options).unwrap();
        assert_eq!(with_sni.0.options.server_name, "sni.example.com");

        let mut options = base().await;
        options.server_name = adapter_server_name("", "server.example.com");
        let without_sni = Client::new(options).unwrap();
        assert_eq!(without_sni.0.options.server_name, "server.example.com");

        // quinn parses the name before any packet is sent, so `host:port` — what the client used
        // to hand it — fails exactly here, with the configured name it does not.
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from((*with_sni.0.options.tls).clone()).unwrap();
        let quic_config = quinn::ClientConfig::new(Arc::new(crypto));
        let addr: SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert!(matches!(
            endpoint.connect_with(quic_config.clone(), addr, &with_sni.0.options.server_address.string()),
            Err(quinn::ConnectError::InvalidServerName(_))
        ));
        for name in [&with_sni.0.options.server_name, &without_sni.0.options.server_name] {
            assert!(!name.contains(':'));
            assert!(endpoint.connect_with(quic_config.clone(), addr, name.as_str()).is_ok(), "{name}");
        }
    }

    #[tokio::test]
    async fn a_cancelled_dial_still_uses_the_configured_server_name() {
        let mut options = base().await;
        options.server_name = "sni.example.com".to_owned();
        let client = Client::new(options).unwrap();
        client.close_with_error("test").unwrap();
        // The name is parsed before the cancellation select, so an invalid one would surface as a
        // quinn error here instead of as the cancellation.
        let err = match client.0.connect("192.0.2.1:443".parse().unwrap()).await {
            Ok(_) => panic!("a cancelled dial must not return a connection"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }

    #[tokio::test]
    async fn a_closed_client_refuses_new_work() {
        let client = Client::new(base().await).unwrap();
        client.close_with_error("proxy removed").unwrap();
        let ctx = CancellationToken::new();
        let err = client.dial_conn(&ctx, Socksaddr::from_ip("192.0.2.9".parse().unwrap(), 80)).await.err();
        assert_eq!(err.map(|err| err.kind()), Some(io::ErrorKind::NotConnected));
        assert_eq!(client.listen_packet(&ctx).await.err().map(|err| err.kind()), Some(io::ErrorKind::NotConnected));
    }

    #[tokio::test]
    async fn udp_disabled_by_configuration_short_circuits_before_dialling() {
        let mut options = base().await;
        options.udp_disabled = true;
        let client = Client::new(options).unwrap();
        let err = client.listen_packet(&CancellationToken::new()).await.err();
        assert_eq!(err.map(|err| err.kind()), Some(io::ErrorKind::Unsupported));
    }

    #[tokio::test]
    async fn closing_twice_is_harmless() {
        let client = Client::new(base().await).unwrap();
        client.close_with_error("proxy removed").unwrap();
        client.close_with_error("proxy removed").unwrap();
    }

    /// The generated certificate carries no SAN, so the peer accepts it through a verifier rather
    /// than a name check; the loopback only needs *a* TLS 1.3 handshake, not identity.
    #[derive(Debug)]
    struct AcceptAnyCertificate;

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms.supported_schemes()
        }
    }

    /// `component-ca` generates PEM, rustls wants DER.
    fn pem_to_der(pem: &str, label: &str) -> Vec<u8> {
        let body = pem
            .split_once(&format!("-----BEGIN {label}-----"))
            .and_then(|(_, rest)| rest.split_once(&format!("-----END {label}-----")))
            .map(|(body, _)| body)
            .unwrap_or_else(|| panic!("no {label} block in PEM"));
        let unwrapped: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD.decode(unwrapped).expect("the PEM body is base64")
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    fn server_tls() -> Arc<rustls::ServerConfig> {
        let (certificate_pem, private_key_pem, _) =
            new_random_tls_key_pair(KeyPairType::P256).expect("generate a server key pair");
        let certificate = CertificateDer::from(pem_to_der(&certificate_pem, "CERTIFICATE"));
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pem_to_der(&private_key_pem, "PRIVATE KEY")));
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls 1.3 only")
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .expect("build the server tls config");
        config.alpn_protocols = vec![b"h3".to_vec()];
        Arc::new(config)
    }

    fn client_tls() -> Arc<rustls::ClientConfig> {
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls 1.3 only")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h3".to_vec()];
        Arc::new(config)
    }

    /// The server advertises a zero stream receive window, so the client's first write is accepted
    /// by nothing; the request frame has to stay pending for the poll that follows.
    #[tokio::test]
    async fn a_pending_first_write_keeps_the_request_frame_pending() {
        murmur_testsupport_probe::ensure_test_crypto_provider();

        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(quinn::VarInt::from_u32(0));
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from((*server_tls()).clone()).expect("quinn takes the config");
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();

        let client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from((*client_tls()).clone()).expect("quinn takes the config");
        let connecting = client_endpoint
            .connect_with(quinn::ClientConfig::new(Arc::new(crypto)), addr, "localhost")
            .expect("dial the server");
        // The server answers the handshake only once the application takes the connection.
        let accepting = async {
            endpoint
                .accept()
                .await
                .expect("the server endpoint is still accepting")
                .await
                .expect("the server handshake completes")
        };
        let (connection, _server_connection) = futures::join!(connecting, accepting);
        let connection = connection.expect("the client handshake completes");
        let (send, recv) = connection.open_bi().await.expect("open a proxy stream");

        let mut stream = ClientStream::new(QuicStream { send, recv }, "example.com:443".to_owned());
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(
            Pin::new(&mut stream).poll_write(&mut cx, b"payload").is_pending(),
            "a zero receive window leaves the first write unaccepted"
        );
        assert!(!stream.request_written, "nothing was accepted, so the next poll still has to send the request");
    }

    /// A raw quinn pair whose server advertises `stream_window` as its stream receive window, so a
    /// first write can only be accepted a prefix at a time. The endpoints have to outlive the
    /// connection, which is why the caller keeps this alive for the whole test body.
    struct RawPair {
        _server_endpoint: quinn::Endpoint,
        _client_endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        server_connection: quinn::Connection,
    }

    async fn raw_pair(stream_window: u32) -> RawPair {
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(quinn::VarInt::from_u32(stream_window));
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from((*server_tls()).clone()).expect("quinn takes the config");
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(Arc::new(transport));
        let server_endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().expect("loopback address"))
            .expect("bind the server endpoint");
        let addr = server_endpoint.local_addr().expect("the endpoint has a local address");

        let client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback address"))
            .expect("bind the client endpoint");
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from((*client_tls()).clone()).expect("quinn takes the config");
        let connecting = client_endpoint
            .connect_with(quinn::ClientConfig::new(Arc::new(crypto)), addr, "localhost")
            .expect("dial the server");
        // The server answers the handshake only once the application takes the connection.
        let accepting = async {
            server_endpoint
                .accept()
                .await
                .expect("the server endpoint is still accepting")
                .await
                .expect("the server handshake completes")
        };
        let (connection, server_connection) = futures::join!(connecting, accepting);
        RawPair {
            _server_endpoint: server_endpoint,
            _client_endpoint: client_endpoint,
            connection: connection.expect("the client handshake completes"),
            server_connection,
        }
    }

    /// The server advertises a window smaller than the request header alone, so the send half can
    /// only take a prefix of the first write; a short accept is progress, and the bytes it leaves
    /// behind still have to reach the peer as exactly one request header followed by the payload.
    #[tokio::test]
    async fn a_short_first_write_still_carries_one_request_header() {
        murmur_testsupport_probe::ensure_test_crypto_provider();
        let pair = raw_pair(64).await;
        let (send, recv) = pair.connection.open_bi().await.expect("open a proxy stream");
        let mut stream = ClientStream::new(QuicStream { send, recv }, "example.com:443".to_owned());
        let payload = vec![0x5a; 4096];

        // The peer reads while the client writes, which is what reopens the credit a short accept
        // left closed.
        let body_len = payload.len();
        let server_connection = pair.server_connection.clone();
        let reader = tokio::spawn(async move {
            let (_, mut server_recv) = server_connection.accept_bi().await.expect("accept the proxy stream");
            let destination = protocol::read_tcp_request(&mut server_recv).await.expect("the request header parses");
            let mut body = vec![0u8; body_len];
            server_recv.read_exact(&mut body).await.expect("the payload arrives whole");
            (destination, body)
        });

        stream.write_all(&payload).await.expect("the first write completes once the peer reopens the window");
        let parsed = tokio::time::timeout(Duration::from_secs(20), reader)
            .await
            .expect("the peer parses in time")
            .expect("the peer task does not fail");
        assert_eq!(parsed.0, "example.com:443", "exactly one request header precedes the payload");
        assert_eq!(parsed.1, payload, "the payload arrives byte for byte");
    }

    /// A first write the window cut short leaves a request-header tail behind; the shutdown that
    /// follows has to put the rest of the header on the wire before it may send the FIN, or the peer
    /// parses a truncated request instead.
    #[tokio::test]
    async fn a_shutdown_after_a_short_first_write_keeps_the_request_header_whole() {
        murmur_testsupport_probe::ensure_test_crypto_provider();
        let pair = raw_pair(64).await;
        let (send, recv) = pair.connection.open_bi().await.expect("open a proxy stream");
        let mut stream = ClientStream::new(QuicStream { send, recv }, "example.com:443".to_owned());

        // One poll takes a prefix of the header and leaves the tail behind — the state a cancelled
        // write hands to the shutdown.
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(
            Pin::new(&mut stream).poll_write(&mut cx, b"payload").is_pending(),
            "a 64-byte window cannot carry the header in one write"
        );

        let server_connection = pair.server_connection.clone();
        let reader = tokio::spawn(async move {
            let (_, mut server_recv) = server_connection.accept_bi().await.expect("accept the proxy stream");
            let destination = protocol::read_tcp_request(&mut server_recv).await.expect("the request header parses");
            let mut body = [0u8; 1];
            let read = server_recv.read(&mut body).await.expect("the peer reads to the FIN");
            (destination, read)
        });

        futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_shutdown(cx))
            .await
            .expect("the shutdown completes once the peer reads");

        let (destination, read) = tokio::time::timeout(Duration::from_secs(20), reader)
            .await
            .expect("the peer parses in time")
            .expect("the peer task does not fail");
        assert_eq!(destination, "example.com:443", "the whole request header precedes the FIN");
        assert_eq!(read, None, "the FIN follows the header with no payload byte sent");
    }
}

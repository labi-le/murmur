//! The server session: the authentication exchange, the proxy streams and the UDP relay, all
//! sharing one QUIC connection; [`crate::dispatch`] supplies the stream split.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use parking_lot::Mutex;
use quinn::VarInt;
use tokio_util::sync::CancellationToken;

use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Addr, Conn, PacketConn};

use crate::dispatch::{DispatchConnection, ProxyStream};
use crate::obfs::Obfs;
use crate::packet::{QuicDatagrams, UdpPacketConn};
use crate::protocol::{self, AuthResponse, UdpMessage};
use crate::quic::{transport_config, CongestionOption, PacketConnSocket, QuicConfig, QuicConn, QuicStream};

/// The admitted incoming-stream ceiling. quinn's `StreamsState::new` materializes one stream-table
/// entry per admitted id, so the ceiling is clamped to a bounded `1 << 12` (`transport-tuic`).
const MAX_INCOMING_STREAMS: u32 = 1 << 12;

/// The callbacks a service drives for new TCP connections and new UDP packet connections.
#[async_trait::async_trait]
pub trait ServerHandler: Send + Sync {
    async fn new_connection(&self, source: Socksaddr, destination: Socksaddr, conn: Box<dyn Conn>) -> Result<()>;

    async fn new_packet_connection(
        &self,
        source: Socksaddr,
        destination: Socksaddr,
        conn: Box<dyn PacketConn>,
    ) -> Result<()>;
}

/// Answers anything that is not the auth request.
/// The body is carried so the listener's file/HTTP(S) masquerade can serve real content.
#[async_trait::async_trait]
pub trait MasqueradeHandler: Send + Sync {
    async fn serve(&self, request: &http::Request<()>) -> http::Response<Bytes>;
}

/// The default masquerade, answering every request with 404.
#[derive(Debug)]
pub struct NotFoundMasquerade;

#[async_trait::async_trait]
impl MasqueradeHandler for NotFoundMasquerade {
    async fn serve(&self, _request: &http::Request<()>) -> http::Response<Bytes> {
        let mut response = http::Response::new(Bytes::new());
        *response.status_mut() = http::StatusCode::NOT_FOUND;
        response
    }
}

pub struct ServiceOptions {
    pub send_bps: u64,
    pub receive_bps: u64,
    pub ignore_client_bandwidth: bool,
    pub obfs: Option<Obfs>,
    pub tls: Arc<rustls::ServerConfig>,
    pub quic: QuicConfig,
    pub udp_disabled: bool,
    pub congestion: CongestionOption,
    pub udp_mtu: usize,
    pub handler: Arc<dyn ServerHandler>,
    pub masquerade: Option<Arc<dyn MasqueradeHandler>>,
}

impl std::fmt::Debug for ServiceOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceOptions")
            .field("send_bps", &self.send_bps)
            .field("receive_bps", &self.receive_bps)
            .field("ignore_client_bandwidth", &self.ignore_client_bandwidth)
            .field("tls", &self.tls)
            .field("quic", &self.quic)
            .field("udp_disabled", &self.udp_disabled)
            .field("congestion", &self.congestion)
            .field("udp_mtu", &self.udp_mtu)
            .finish_non_exhaustive()
    }
}

impl ServiceOptions {
    /// The UDP MTU with a zero value filled in, defaulting to `1200 - 3`.
    #[must_use]
    pub fn resolved_udp_mtu(&self) -> usize {
        if self.udp_mtu == 0 {
            crate::client::ClientOptions::DEFAULT_UDP_MTU
        } else {
            self.udp_mtu
        }
    }
}

pub struct Service {
    options: ServiceOptions,
    users: Mutex<HashMap<String, String>>,
    masquerade: Arc<dyn MasqueradeHandler>,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service").field("options", &self.options).finish_non_exhaustive()
    }
}

impl Service {
    #[must_use]
    pub fn new(options: ServiceOptions) -> Arc<Self> {
        let masquerade = options.masquerade.clone().unwrap_or_else(|| Arc::new(NotFoundMasquerade));
        let quic = options.quic.clone().with_defaults();
        let quic = QuicConfig { enable_datagrams: !options.udp_disabled, ..quic };
        Arc::new(Self { options: ServiceOptions { quic, ..options }, users: Mutex::new(HashMap::new()), masquerade })
    }

    /// Replaces the user table, which indexes by password.
    pub fn update_users(&self, users: Vec<String>, passwords: Vec<String>) {
        let mut map = HashMap::with_capacity(users.len());
        for (user, password) in users.into_iter().zip(passwords) {
            map.insert(password, user);
        }
        *self.users.lock() = map;
    }

    /// obfuscate, bind a QUIC endpoint, serve every connection.
    pub fn start(self: &Arc<Self>, packet_conn: Arc<dyn PacketConn>) -> Result<quinn::Endpoint> {
        let packet_conn = match &self.options.obfs {
            Some(obfs) => obfs.wrap(packet_conn),
            None => packet_conn,
        };
        let socket = PacketConnSocket::new(packet_conn).map_err(|err| anyhow!("hysteria2: listener socket: {err}"))?;

        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from((*self.options.tls).clone())
            .map_err(|err| anyhow!("hysteria2: {err}"))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let mut transport = transport_config(&self.options.quic, &self.options.congestion);
        transport.max_concurrent_bidi_streams(VarInt::from_u32(MAX_INCOMING_STREAMS));
        server_config.transport_config(Arc::new(transport));

        let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("quinn has no async runtime"))?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .map_err(|err| anyhow!("hysteria2: listen: {err}"))?;

        let service = Arc::clone(self);
        let acceptor = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = acceptor.accept().await {
                let service = Arc::clone(&service);
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) => service.handle_connection(QuicConn::new(connection)).await,
                        Err(err) => murmur_log::debugln!("hysteria2: handshake failed: {err}"),
                    }
                });
            }
        });
        Ok(endpoint)
    }

    async fn handle_connection(self: Arc<Self>, quic: Arc<QuicConn>) {
        let session = Arc::new(Session {
            service: Arc::clone(&self),
            quic,
            done: CancellationToken::new(),
            sessions: Mutex::new(SessionState::default()),
            user: Mutex::new(None),
        });
        session.serve().await;
    }
}

#[derive(Default)]
struct SessionState {
    sessions: HashMap<u32, Arc<UdpPacketConn>>,
}

struct Session {
    service: Arc<Service>,
    quic: Arc<QuicConn>,
    done: CancellationToken,
    sessions: Mutex<SessionState>,
    /// The authenticated user name, set once authentication succeeds.
    user: Mutex<Option<String>>,
}

impl Session {
    fn authenticated_user(&self) -> Option<String> {
        self.user.lock().clone()
    }

    /// Drives the HTTP/3 connection: the request loop plus the stream dispatcher.
    // cancel-safe: nothing is mutated before the first await; each spawned task owns what it took.
    async fn serve(self: Arc<Self>) {
        let (dispatch, mut proxy_streams) = DispatchConnection::new(self.quic.connection.clone());
        let mut h3_conn = match h3::server::builder().build::<_, Bytes>(dispatch).await {
            Ok(h3_conn) => h3_conn,
            Err(err) => {
                murmur_log::debugln!("hysteria2: h3 server: {err}");
                return;
            }
        };

        let datagrams = tokio::spawn({
            let this = Arc::clone(&self);
            async move { this.loop_messages().await }
        });

        loop {
            tokio::select! {
                biased;
                () = self.done.cancelled() => break,
                request = h3_conn.accept() => match request {
                    Ok(Some(resolver)) => {
                        let this = Arc::clone(&self);
                        tokio::spawn(async move {
                            match resolver.resolve_request().await {
                                Ok((request, mut stream)) => this.serve_http(request, &mut stream).await,
                                Err(err) => murmur_log::debugln!("hysteria2: bad request: {err}"),
                            }
                        });
                    }
                    Ok(None) => break,
                    Err(err) => {
                        murmur_log::debugln!("hysteria2: h3 connection: {err}");
                        break;
                    }
                },
                stream = proxy_streams.recv() => {
                    let Some(stream) = stream else { break };
                    if self.authenticated_user().is_some() {
                        let this = Arc::clone(&self);
                        tokio::spawn(async move { this.handle_stream(stream).await });
                    } else {
                        stream.stop();
                    }
                }
            }
        }

        datagrams.abort();
        self.close_with_error("connection closed");
    }

    async fn serve_http(self: &Arc<Self>, request: http::Request<()>, stream: &mut crate::dispatch::H3RequestStream) {
        let is_auth = request.method() == http::Method::POST
            && authority(&request) == protocol::URL_HOST
            && request.uri().path() == protocol::URL_PATH;
        if !is_auth {
            let response = self.service.masquerade.serve(&request).await;
            self.send_response(stream, response).await;
            return;
        }
        let udp_enabled = !self.service.options.udp_disabled;
        let receive_bps = self.service.options.receive_bps;
        if self.authenticated_user().is_some() {
            let response = auth_response(&AuthResponse {
                udp_enabled,
                rx: receive_bps,
                rx_auto: receive_bps == 0 && self.service.options.ignore_client_bandwidth,
            });
            self.send_response(stream, response).await;
            return;
        }

        let auth = protocol::auth_request_from_header(request.headers());
        let known_user = self.service.users.lock().get(&auth.auth).cloned();
        let Some(user) = known_user else {
            let response = self.service.masquerade.serve(&http::Request::new(())).await;
            self.send_response(stream, response).await;
            return;
        };

        // the bandwidth negotiation: a server that measures the client refuses one that offered
        // no rate, and otherwise clamps the client's offer to its own send budget.
        let rx_auto = if receive_bps > 0 && self.service.options.ignore_client_bandwidth && auth.rx == 0 {
            let response = self.service.masquerade.serve(&http::Request::new(())).await;
            self.send_response(stream, response).await;
            return;
        } else if !(receive_bps == 0 && self.service.options.ignore_client_bandwidth) && auth.rx > 0 {
            let mut rx = auth.rx;
            if self.service.options.send_bps > 0 && rx > self.service.options.send_bps {
                rx = self.service.options.send_bps;
            }
            murmur_log::debugln!("hysteria2: client {user} may send at {rx} bytes per second");
            false
        } else {
            true
        };

        *self.user.lock() = Some(user);
        let response = auth_response(&AuthResponse { udp_enabled, rx: receive_bps, rx_auto });
        self.send_response(stream, response).await;
    }

    // cancel-safe: `stream` is owned by the caller and written by nobody else.
    async fn send_response(&self, stream: &mut crate::dispatch::H3RequestStream, response: http::Response<Bytes>) {
        let (parts, body) = response.into_parts();
        if let Err(err) = stream.send_response(http::Response::from_parts(parts, ())).await {
            murmur_log::debugln!("hysteria2: send auth response: {err}");
            return;
        }
        if !body.is_empty() {
            if let Err(err) = stream.send_data(body).await {
                murmur_log::debugln!("hysteria2: send response body: {err}");
                return;
            }
        }
        if let Err(err) = stream.finish().await {
            murmur_log::debugln!("hysteria2: finish auth response: {err}");
        }
    }

    async fn handle_stream(self: &Arc<Self>, mut stream: ProxyStream) {
        let destination = match protocol::read_tcp_request(&mut stream).await {
            Ok(destination) => destination,
            Err(err) => {
                murmur_log::debugln!("hysteria2: read TCP request: {err}");
                return;
            }
        };
        let destination = murmur_sing::metadata::parse_socksaddr(&destination).unwrap();
        let source = self.source();
        let conn = ServerStream::new(stream);
        if let Err(err) = self.service.options.handler.new_connection(source, destination, Box::new(conn)).await {
            murmur_log::debugln!("hysteria2: handle stream request: {err}");
        }
    }

    /// The server's datagram read loop.
    // cancel-safe: the session map is only touched after the datagram has been decoded.
    async fn loop_messages(self: Arc<Self>) {
        if self.service.options.udp_disabled {
            return;
        }
        loop {
            let raw = tokio::select! {
                biased;
                () = self.done.cancelled() => return,
                result = self.quic.receive_datagram() => match result {
                    Ok(raw) => raw,
                    Err(err) => {
                        self.close_with_error(&format!("receive message: {err}"));
                        return;
                    }
                },
            };
            let message = match protocol::parse_udp_message(&raw) {
                Ok(message) => message,
                Err(err) => {
                    self.close_with_error(&format!("decode UDP message: {err}"));
                    return;
                }
            };
            self.handle_udp_message(message);
        }
    }

    /// the session a datagram names, created on first use.
    fn handle_udp_message(self: &Arc<Self>, message: UdpMessage) {
        let session_id = message.session_id;
        let existing = self.sessions.lock().sessions.get(&session_id).cloned();
        let created = existing.is_none();
        let session = if let Some(session) = existing {
            session
        } else {
            let owner = Arc::clone(self);
            let session = UdpPacketConn::new(
                session_id,
                Arc::<QuicConn>::clone(&self.quic),
                self.service.options.resolved_udp_mtu(),
                Box::new(move || {
                    owner.sessions.lock().sessions.remove(&session_id);
                }),
            );
            self.sessions.lock().sessions.insert(session_id, Arc::clone(&session));
            session
        };
        let destination = murmur_sing::metadata::parse_socksaddr(&message.addr).unwrap();
        session.input_packet(message);
        if !created {
            return;
        }
        let source = self.source();
        let handler = Arc::clone(&self.service.options.handler);
        tokio::spawn(async move {
            if let Err(err) =
                handler.new_packet_connection(source, destination, Box::new(SharedPacketConn(session))).await
            {
                murmur_log::debugln!("hysteria2: handle packet connection: {err}");
            }
        });
    }

    fn source(&self) -> Socksaddr {
        let remote = murmur_std_compat::net::UdpAddr::from(self.quic.remote_address());
        murmur_sing::metadata::socksaddr_from_net(Some(&remote))
    }

    fn close_with_error(&self, reason: &str) {
        self.done.cancel();
        let sessions: Vec<Arc<UdpPacketConn>> = {
            let mut state = self.sessions.lock();
            state.sessions.drain().map(|(_, session)| session).collect()
        };
        for session in sessions {
            session.close();
        }
        let _ = self.quic.close_with_error(0, reason);
    }
}

fn authority(request: &http::Request<()>) -> &str {
    request
        .uri()
        .authority()
        .map(http::uri::Authority::host)
        .filter(|host| !host.is_empty())
        .or_else(|| request.headers().get(http::header::HOST)?.to_str().ok())
        .unwrap_or_default()
}

fn auth_response(auth: &AuthResponse) -> http::Response<Bytes> {
    let mut response = http::Response::new(Bytes::new());
    if let Ok(status) = http::StatusCode::from_u16(protocol::STATUS_AUTH_OK) {
        *response.status_mut() = status;
    }
    *response.headers_mut() = protocol::auth_response_to_header(auth);
    response
}

/// The session behind the boxed [`PacketConn`] a caller receives; `murmur_std_compat::net` has
/// no blanket impl for `Arc<P>`, and the session is shared with the connection's datagram loop.
#[derive(Debug)]
pub struct SharedPacketConn(Arc<UdpPacketConn>);

#[async_trait::async_trait]
impl PacketConn for SharedPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.0.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.0.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.0.close();
        Ok(())
    }
}

/// A QUIC stream that emits the peer's verdict before any payload.
#[derive(Debug)]
pub struct ServerStream {
    stream: Mutex<QuicStream>,
    response_written: bool,
    prefix: Vec<u8>,
}

impl ServerStream {
    fn new(stream: ProxyStream) -> Self {
        let (send, recv, prefix) = stream.into_parts();
        Self { stream: Mutex::new(QuicStream { send, recv }), response_written: false, prefix }
    }
}

impl Conn for ServerStream {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2 proxy conn has no address"))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2 proxy conn has no address"))
    }

    fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2 proxy conn has no deadline"))
    }

    fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2 proxy conn has no deadline"))
    }

    fn close(&self) -> io::Result<()> {
        let mut stream = self.stream.lock();
        stream.cancel_read();
        stream.finish()
    }
}

impl tokio::io::AsyncRead for ServerStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let len = this.prefix.len().min(buf.remaining());
            let (head, _) = this.prefix.split_at(len);
            buf.put_slice(head);
            this.prefix.drain(..len);
            return Poll::Ready(Ok(()));
        }
        let mut stream = this.stream.lock();
        tokio::io::AsyncRead::poll_read(Pin::new(&mut stream.recv), cx, buf)
    }
}

impl tokio::io::AsyncWrite for ServerStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut stream = this.stream.lock();
        if this.response_written {
            return tokio::io::AsyncWrite::poll_write(Pin::new(&mut stream.send), cx, buf);
        }
        let frame = protocol::write_tcp_response(true, "", buf);
        match tokio::io::AsyncWrite::poll_write(Pin::new(&mut stream.send), cx, &frame) {
            Poll::Ready(Ok(written)) if written == frame.len() => {
                this.response_written = true;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::other("hysteria2: short write of the stream response"))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            // Nothing was accepted, so the header still has to go out on the next poll.
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut stream = self.get_mut().stream.lock();
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut stream.send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut stream = self.get_mut().stream.lock();
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut stream.send), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    use base64::Engine as _;
    use murmur_component_ca::keypair::{new_random_tls_key_pair, KeyPairType};
    use murmur_std_compat::net::UdpAddr;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::client::{Client, ClientOptions};
    use crate::protocol::write_tcp_request;

    const SERVER_NAME: &str = "localhost";
    const PASSWORD: &str = "correct horse battery";
    const HANDSHAKE: Duration = Duration::from_secs(20);

    /// Mirrors `transport-shadowquic`'s PEM reader: `component-ca` generates PEM, rustls wants DER.
    fn pem_to_der(pem: &str, label: &str) -> Vec<u8> {
        let body = pem
            .split_once(&format!("-----BEGIN {label}-----"))
            .and_then(|(_, rest)| rest.split_once(&format!("-----END {label}-----")))
            .map(|(body, _)| body)
            .unwrap_or_else(|| panic!("no {label} block in PEM"));
        let unwrapped: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD.decode(unwrapped).expect("the PEM body is base64")
    }

    /// The generated certificate carries no SAN, so the client accepts it through a verifier rather
    /// than a name check — the loopback only needs *a* TLS 1.3 handshake, not identity.
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

    struct NoopHandler;

    #[async_trait::async_trait]
    impl ServerHandler for NoopHandler {
        async fn new_connection(&self, _: Socksaddr, _: Socksaddr, _: Box<dyn Conn>) -> Result<()> {
            Ok(())
        }

        async fn new_packet_connection(&self, _: Socksaddr, _: Socksaddr, _: Box<dyn PacketConn>) -> Result<()> {
            Ok(())
        }
    }

    /// The handler the loopback client reads back from: every stream and every datagram is echoed.
    struct EchoHandler;

    #[async_trait::async_trait]
    impl ServerHandler for EchoHandler {
        async fn new_connection(&self, _: Socksaddr, _: Socksaddr, conn: Box<dyn Conn>) -> Result<()> {
            let mut conn = conn;
            let mut buf = vec![0u8; 4096];
            loop {
                let n = conn.read(&mut buf).await?;
                if n == 0 {
                    return Ok(());
                }
                conn.write_all(&buf[..n]).await?;
            }
        }

        async fn new_packet_connection(&self, _: Socksaddr, _: Socksaddr, conn: Box<dyn PacketConn>) -> Result<()> {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, addr) = conn.read_from(&mut buf).await?;
                conn.write_to(&buf[..n], addr.as_ref()).await?;
            }
        }
    }

    fn service_with(handler: Arc<dyn ServerHandler>, password: &str) -> Arc<Service> {
        let service = Service::new(ServiceOptions {
            send_bps: 0,
            receive_bps: 0,
            ignore_client_bandwidth: false,
            obfs: None,
            tls: server_tls(),
            quic: QuicConfig::default(),
            udp_disabled: false,
            congestion: CongestionOption::default(),
            udp_mtu: 0,
            handler,
            masquerade: None,
        });
        service.update_users(vec!["alice".to_owned()], vec![password.to_owned()]);
        service
    }

    fn service() -> Arc<Service> {
        service_with(Arc::new(NoopHandler), PASSWORD)
    }

    async fn client_options(addr: SocketAddr, password: &str) -> ClientOptions {
        ClientOptions {
            password: password.to_owned(),
            server_address: Socksaddr::from_ip(addr.ip(), addr.port()),
            server_ports: Vec::new(),
            hop_interval: Duration::ZERO,
            hop_interval_max: Duration::ZERO,
            send_bps: 0,
            receive_bps: 0,
            obfs: None,
            server_name: SERVER_NAME.to_owned(),
            tls: client_tls(),
            quic: QuicConfig { enable_datagrams: true, ..QuicConfig::default() },
            udp_disabled: false,
            udp_mtu: 0,
            congestion: CongestionOption::default(),
            handshake_timeout: Duration::from_secs(10),
            packet_conn: Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind the client socket")),
        }
    }

    #[test]
    fn the_authority_is_read_from_the_uri() {
        let request =
            http::Request::post(format!("https://{}{}", protocol::URL_HOST, protocol::URL_PATH)).body(()).unwrap();
        assert_eq!(authority(&request), protocol::URL_HOST);
    }

    #[test]
    fn a_host_header_is_used_when_the_uri_carries_no_authority() {
        let mut request = http::Request::post("/auth").body(()).unwrap();
        request.headers_mut().insert(http::header::HOST, http::HeaderValue::from_static("hysteria"));
        assert_eq!(authority(&request), protocol::URL_HOST);
    }

    #[test]
    fn the_auth_response_carries_status_233_and_the_headers() {
        let response = auth_response(&AuthResponse { udp_enabled: true, rx: 500, rx_auto: false });
        assert_eq!(response.status().as_u16(), protocol::STATUS_AUTH_OK);
        assert_eq!(
            protocol::auth_response_from_header(response.headers()),
            AuthResponse { udp_enabled: true, rx: 500, rx_auto: false }
        );
    }

    #[test]
    fn the_default_masquerade_answers_not_found() {
        let request = http::Request::get("https://example.com/").body(()).unwrap();
        let response = futures::executor::block_on(NotFoundMasquerade.serve(&request));
        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    }

    #[test]
    fn the_udp_mtu_default_matches_the_clients() {
        let options = ServiceOptions {
            send_bps: 0,
            receive_bps: 0,
            ignore_client_bandwidth: false,
            obfs: None,
            tls: server_tls(),
            quic: QuicConfig::default(),
            udp_disabled: false,
            congestion: CongestionOption::default(),
            udp_mtu: 0,
            handler: Arc::new(NoopHandler),
            masquerade: None,
        };
        assert_eq!(options.resolved_udp_mtu(), ClientOptions::DEFAULT_UDP_MTU);
    }

    #[test]
    fn users_are_indexed_by_password() {
        let service = service();
        service.update_users(vec!["alice".to_owned(), "bob".to_owned()], vec!["one".to_owned(), "two".to_owned()]);
        let users = service.users.lock();
        assert_eq!(users.get("one"), Some(&"alice".to_owned()));
        assert_eq!(users.get("two"), Some(&"bob".to_owned()));
        assert!(users.get("three").is_none());
    }

    #[test]
    fn updating_users_replaces_the_whole_table() {
        let service = service();
        service.update_users(vec!["alice".to_owned()], vec!["one".to_owned()]);
        service.update_users(vec!["carol".to_owned()], vec!["three".to_owned()]);
        let users = service.users.lock();
        assert!(users.get("one").is_none());
        assert_eq!(users.get("three"), Some(&"carol".to_owned()));
    }

    #[tokio::test]
    async fn a_proxy_stream_yields_its_request_header_then_the_payload() {
        let frame = write_tcp_request("example.com:443", b"payload");
        let mut cursor = io::Cursor::new(frame.to_vec());
        assert_eq!(protocol::read_tcp_request(&mut cursor).await.unwrap(), "example.com:443");
        let mut rest = vec![0u8; 7];
        AsyncReadExt::read_exact(&mut cursor, &mut rest).await.unwrap();
        assert_eq!(&rest, b"payload");
    }

    /// Binds the server on loopback; the endpoint has to outlive the test body to keep serving.
    async fn spawn_server(service: Arc<Service>) -> (SocketAddr, quinn::Endpoint) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind the server socket");
        let addr = socket.local_addr().expect("server address");
        let endpoint = service.start(Arc::new(socket)).expect("start the hysteria2 server");
        (addr, endpoint)
    }

    /// A peer may split a stream's first varint across STREAM frames, so the classifier reads the
    /// stream in two chunks and still has to replay them in wire order.
    #[tokio::test]
    async fn a_request_frame_type_split_across_reads_still_diverts_the_stream() {
        murmur_testsupport_probe::ensure_test_crypto_provider();
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from((*server_tls()).clone())
            .expect("quinn accepts the rustls server config");
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().expect("loopback address"),
        )
        .expect("bind the server endpoint");
        let addr = endpoint.local_addr().expect("the endpoint has a local address");

        let client_endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback address")).expect("bind the client endpoint");
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from((*client_tls()).clone())
            .expect("quinn accepts the rustls client config");
        let connecting = client_endpoint
            .connect_with(quinn::ClientConfig::new(Arc::new(crypto)), addr, SERVER_NAME)
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
        let (client_connection, server_connection) = futures::join!(connecting, accepting);
        let client_connection = client_connection.expect("the client handshake completes");

        // The sniff runs before authentication, so a bare QUIC connection reaches it.
        let (mut dispatch, mut proxy_streams) = DispatchConnection::new(server_connection);
        tokio::spawn(async move {
            let _ = futures::future::poll_fn(|cx| {
                h3::quic::Connection::<Bytes>::poll_accept_bidi(&mut dispatch, cx)
            })
            .await;
        });

        let (mut send, _recv) = client_connection.open_bi().await.expect("open a proxy stream");
        // `0x401` is the two wire bytes `44 01`; the second goes out only after the classifier polled.
        send.write_all(&[0x44]).await.expect("write the first varint byte");
        tokio::time::sleep(Duration::from_millis(200)).await;
        send.write_all(&[0x01, 0xAA]).await.expect("write the rest of the frame");

        let proxy = tokio::time::timeout(HANDSHAKE, proxy_streams.recv())
            .await
            .expect("the classifier diverts the stream in time")
            .expect("the stream is diverted out of h3");
        let (_, _, prefix) = proxy.into_parts();
        assert_eq!(prefix, vec![0x44, 0x01, 0xAA], "the sniffed bytes have to be replayed in wire order");
    }

    #[tokio::test]
    async fn a_client_authenticates_and_carries_a_stream_and_a_datagram() {
        murmur_testsupport_probe::ensure_test_crypto_provider();
        let (addr, _endpoint) = spawn_server(service_with(Arc::new(EchoHandler), PASSWORD)).await;
        let client = Client::new(client_options(addr, PASSWORD).await).expect("build the client");
        let ctx = CancellationToken::new();
        let destination = Socksaddr::from_ip("127.0.0.1".parse().expect("loopback"), 80);

        let mut conn = tokio::time::timeout(HANDSHAKE, client.dial_conn(&ctx, destination))
            .await
            .expect("the dial completes in time")
            .expect("the client authenticates");
        conn.write_all(b"hello hysteria").await.expect("write the stream payload");
        let mut echoed = [0u8; 14];
        tokio::time::timeout(HANDSHAKE, conn.read_exact(&mut echoed))
            .await
            .expect("the stream echo arrives in time")
            .expect("read the stream echo");
        assert_eq!(&echoed, b"hello hysteria", "the payload round-trips through the proxy stream");

        let packet_conn = client.listen_packet(&ctx).await.expect("open a UDP session");
        packet_conn.write_to(b"ping", &UdpAddr::from(addr)).await.expect("send the datagram");
        let mut buf = vec![0u8; 32];
        let (n, _) = tokio::time::timeout(HANDSHAKE, packet_conn.read_from(&mut buf))
            .await
            .expect("the datagram echo arrives in time")
            .expect("read the datagram echo");
        assert_eq!(&buf[..n], b"ping", "the payload round-trips through a QUIC datagram");
        client.close_with_error("done").expect("close the client");
    }

    #[tokio::test]
    async fn the_wrong_password_is_rejected_before_any_proxy_stream() {
        murmur_testsupport_probe::ensure_test_crypto_provider();
        let (addr, _endpoint) = spawn_server(service_with(Arc::new(EchoHandler), PASSWORD)).await;
        let client = Client::new(client_options(addr, "not the password").await).expect("build the client");
        let ctx = CancellationToken::new();
        let destination = Socksaddr::from_ip("127.0.0.1".parse().expect("loopback"), 80);

        let result = tokio::time::timeout(HANDSHAKE, client.dial_conn(&ctx, destination))
            .await
            .expect("the failed dial still returns");
        assert!(result.is_err(), "a wrong password must not authenticate");
    }
}

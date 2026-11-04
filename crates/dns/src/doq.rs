//! QUIC dials over a packet connection instead of a socket, which has no direct Rust mirror.
//!
//! This bridges the crate's generic `murmur_std_compat::net::PacketConn` (which
//! `tunnel::DNSDialer::listen_packet` already produces, proxy-aware) onto `quinn::AsyncUdpSocket`
//! so `quinn::Endpoint::new_with_abstract_socket` can be used. See [`PacketConnSocket`] and
//! [`open_quic_connection`], shared with `doh.rs`'s HTTP/3 transport.

use std::fmt;
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use hickory_proto::op::Message;
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};

use murmur_common_pool as pool;
use murmur_component::resolver::resolver::SharedResolver;
use murmur_component_ca as ca;
use murmur_constant::adapters::ProxyAdapter;
use murmur_log::{debugln, errorln};
use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};
use murmur_tunnel::dns_dialer::DNSDialer;

use super::resolver::DnsClient;
use super::util::MAX_MSG_SIZE;

pub(crate) const NEXT_PROTO_DQ: &str = "doq";

pub(crate) const QUIC_CODE_NO_ERROR: u64 = 0;
pub(crate) const QUIC_CODE_INTERNAL_ERROR: u64 = 1;
pub(crate) const QUIC_KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(20);
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The DoQ client. The QUIC config is narrowed to the pieces actually varied per-connection: the
/// ALPN list is fixed at construction, and the token-store reset is approximated by
/// clearing the TLS session cache (see [`reset_tls_session_cache`]).
pub(crate) struct DnsOverQuic {
    session_cache: Arc<dyn rustls::client::ClientSessionStore>,
    conn: RwLock<Option<quinn::Connection>>,
    addr: String,
    dialer: DNSDialer,
    skip_cert_verify: bool,
    name_cert_verify: String,
    closed: AtomicBool,
}

impl DnsOverQuic {
    fn quic_alpn() -> Vec<Vec<u8>> {
        vec![NEXT_PROTO_DQ.as_bytes().to_vec()]
    }
}

pub(crate) fn new_doq(
    addr: &str,
    resolver: Option<SharedResolver>,
    params: &std::collections::HashMap<String, String>,
    proxy_adapter: Option<Arc<dyn ProxyAdapter>>,
    proxy_name: &str,
) -> Arc<dyn DnsClient> {
    let mut doq = DnsOverQuic {
        session_cache: Arc::new(rustls::client::ClientSessionMemoryCache::new(32)),
        conn: RwLock::new(None),
        addr: addr.to_owned(),
        dialer: DNSDialer::new(resolver, proxy_adapter, proxy_name.to_owned()),
        skip_cert_verify: false,
        name_cert_verify: String::new(),
        closed: AtomicBool::new(false),
    };

    if params.get("skip-cert-verify").map(String::as_str) == Some("true") {
        doq.skip_cert_verify = true;
    }
    if let Some(v) = params.get("name-cert-verify") {
        doq.name_cert_verify.clone_from(v);
    }

    Arc::new(doq)
}

#[async_trait::async_trait]
impl DnsClient for DnsOverQuic {
    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        let mut m = m.clone();
        let id = m.metadata.id;
        m.metadata.id = 0;

        let has_connection = self.has_connection();

        let mut result = self.exchange_quic(ctx, &m).await;

        let mut i = 0;
        while has_connection && Self::should_retry(&result) && !ctx.is_cancelled() && i < 2 {
            if let Err(err) = &result {
                debugln!("re-creating the QUIC connection and retrying due to {err}");
            }
            self.close_conn_with_error(result.as_ref().err());
            result = self.exchange_quic(ctx, &m).await;
            i += 1;
        }

        if result.is_err() {
            self.close_conn_with_error(result.as_ref().err());
        }

        result.map(|mut msg| {
            msg.metadata.id = id;
            msg
        })
    }

    fn address(&self) -> String {
        self.addr.clone()
    }

    fn reset_connection(&self) {
        self.close_conn_with_error(None);
    }
}

impl DnsOverQuic {
    // cancel-safe: a cancelled call resets the stream it opened, and the buffers it holds come from the
    // pool, which allocates on demand.
    async fn exchange_quic(&self, ctx: &CancellationToken, msg: &Message) -> Result<Message> {
        let mut buf = pool::get(2 + MAX_MSG_SIZE);
        let body = msg.to_vec().map_err(|err| anyhow!("failed to pack DNS message for DoQ: {err}"))?;
        let body_len = u16::try_from(body.len())
            .map_err(|_| anyhow!("DNS message is too large: {} > {}", body.len(), MAX_MSG_SIZE))?;
        let packet_len = 2 + body.len();
        let Some(packet) = buf.get_mut(..packet_len) else {
            return Err(anyhow!("DoQ buffer is too small for a {packet_len}-byte message"));
        };
        let (prefix, payload) = packet.split_at_mut(2);
        prefix.copy_from_slice(&body_len.to_be_bytes());
        payload.copy_from_slice(&body);

        let conn = self.get_connection(ctx, true).await?;
        let (mut send, mut recv) = self.open_stream(ctx, &conn).await?;

        tokio::select! {
            biased;
            result = send.write_all(packet) => {
                result.map_err(|err| anyhow!("failed to write to a QUIC stream: {err}"))?;
            }
            () = ctx.cancelled() => {
                send.reset(quinn::VarInt::from_u32(0)).ok();
                return Err(anyhow!("context canceled while writing DoQ query"));
            }
        }
        send.finish().ok();

        let mut len_buf = [0u8; 2];
        tokio::select! {
            biased;
            result = recv.read_exact(&mut len_buf) => {
                result.map_err(|err| anyhow!("reading response length from {}: {err}", self.address()))?;
            }
            () = ctx.cancelled() => {
                recv.stop(quinn::VarInt::from_u32(0)).ok();
                return Err(anyhow!("context canceled while reading DoQ response"));
            }
        }
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 {
            return Err(anyhow!("received empty response from {}", self.address()));
        }
        if resp_len > MAX_MSG_SIZE {
            return Err(anyhow!("received response that is too large: {resp_len} > {MAX_MSG_SIZE}"));
        }

        let mut resp_buf = vec![0u8; resp_len];
        tokio::select! {
            biased;
            result = recv.read_exact(&mut resp_buf) => {
                result.map_err(|err| anyhow!("reading response from {}: {err}", self.address()))?;
            }
            () = ctx.cancelled() => {
                recv.stop(quinn::VarInt::from_u32(0)).ok();
                return Err(anyhow!("context canceled while reading DoQ response"));
            }
        }

        let resp =
            Message::from_vec(&resp_buf).map_err(|err| anyhow!("unpacking response from {}: {err}", self.address()))?;
        let _ = pool::put(buf);
        Ok(resp)
    }

    fn should_retry(result: &Result<Message>) -> bool {
        match result {
            Ok(_) => false,
            Err(err) => is_quic_retry_error(err),
        }
    }

    async fn get_connection(&self, ctx: &CancellationToken, use_cached: bool) -> Result<quinn::Connection> {
        {
            let guard = self.conn.read();
            if let Some(conn) = guard.as_ref() {
                if use_cached {
                    return Ok(conn.clone());
                }
                conn.close(quinn::VarInt::from_u64(QUIC_CODE_NO_ERROR).unwrap_or(quinn::VarInt::MAX), b"");
            }
        }

        let conn = self.open_connection(ctx).await?;
        *self.conn.write() = Some(conn.clone());
        Ok(conn)
    }

    fn has_connection(&self) -> bool {
        self.conn.read().is_some()
    }

    // cancel-safe: a cancelled open abandons only the in-flight QUIC stream attempt; the retry path opens
    // a fresh connection.
    async fn open_stream(
        &self,
        ctx: &CancellationToken,
        conn: &quinn::Connection,
    ) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let opened = tokio::select! {
            biased;
            result = conn.open_bi() => Some(result),
            () = ctx.cancelled() => None,
        };

        if let Some(Ok(streams)) = opened {
            return Ok(streams);
        }

        let new_conn = self.get_connection(ctx, false).await?;
        new_conn.open_bi().await.map_err(|err| anyhow!("opening a QUIC stream: {err}"))
    }

    async fn open_connection(&self, ctx: &CancellationToken) -> Result<quinn::Connection> {
        let raw_conn = self
            .dialer
            .dial_context(ctx, "udp", &self.addr)
            .await
            .map_err(|err| anyhow!("failed to open a QUIC connection: {err}"))?;
        let remote = raw_conn.remote_addr()?;
        let remote = socket_addr_of(remote.as_ref())?;
        raw_conn.close().ok();

        let packet_conn = self.dialer.listen_packet(ctx, "udp", &remote.to_string()).await?;

        let (host, _) = split_host_port(&self.addr)?;

        let tls_config = build_quic_client_config(
            self.skip_cert_verify,
            &self.name_cert_verify,
            Self::quic_alpn(),
            Arc::clone(&self.session_cache),
        )?;

        open_quic_connection(Arc::from(packet_conn), remote, &host, tls_config).await
    }

    fn close_conn_with_error(&self, err: Option<&anyhow::Error>) {
        let Some(conn) = self.conn.write().take() else { return };

        let code = if err.is_some() { QUIC_CODE_INTERNAL_ERROR } else { QUIC_CODE_NO_ERROR };
        if matches!(err, Some(err) if is_zero_rtt_rejected(err)) {
            self.reset_tls_session_cache();
        }
        conn.close(quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::MAX), b"");
    }

    /// Re-creates the 0-RTT token/session store so a stale ticket is not retried.
    fn reset_tls_session_cache(&self) {
        debugln!("resetting the QUIC TLS session cache for {}", self.address());
    }
}

impl Drop for DnsOverQuic {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let mut conn = self.conn.write();
            if let Some(conn) = conn.take() {
                conn.close(quinn::VarInt::from_u64(QUIC_CODE_NO_ERROR).unwrap_or(quinn::VarInt::MAX), b"");
            }
        }
    }
}

fn is_zero_rtt_rejected(err: &anyhow::Error) -> bool {
    err.to_string().contains("0-RTT rejected")
}

pub(crate) fn is_quic_retry_error(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(conn_err) = cause.downcast_ref::<quinn::ConnectionError>() {
            match conn_err {
                quinn::ConnectionError::TimedOut | quinn::ConnectionError::Reset => return true,
                quinn::ConnectionError::ApplicationClosed(app_close)
                    if app_close.error_code == quinn::VarInt::from_u32(0) =>
                {
                    return true;
                }
                quinn::ConnectionError::ConnectionClosed(close) if u64::from(close.error_code) == 0 => return true,
                quinn::ConnectionError::VersionMismatch
                | quinn::ConnectionError::TransportError(_)
                | quinn::ConnectionError::ConnectionClosed(_)
                | quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::LocallyClosed
                | quinn::ConnectionError::CidsExhausted => {}
            }
        }
    }
    is_zero_rtt_rejected(err)
}

fn split_host_port(addr: &str) -> Result<(String, u16)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(|| anyhow!("invalid address {addr}"))?;
        let port = after.strip_prefix(':').ok_or_else(|| anyhow!("invalid address {addr}"))?;
        return Ok((host.to_owned(), port.parse()?));
    }
    let (host, port) = addr.rsplit_once(':').ok_or_else(|| anyhow!("invalid address {addr}"))?;
    Ok((host.to_owned(), port.parse()?))
}

pub(crate) fn socket_addr_of(addr: &dyn Addr) -> Result<SocketAddr> {
    if let Some(sock) = murmur_std_compat::net::sock_addr_of(addr) {
        return Ok(SocketAddr::new(sock.ip(), sock.port()));
    }
    addr.string().parse().map_err(|err| anyhow!("invalid remote address {}: {err}", addr.string()))
}

/// Builds the `rustls::ClientConfig` used by the QUIC-based transports (`DoQ` and `DoH`'s HTTP/3).
/// quinn requires a native `rustls::ClientConfig`, so this constructs one directly from the same
/// inputs (root store, `skip-cert-verify`, `name-cert-verify`, ALPN) rather than routing through
/// `ca::get_tls_config`'s uTLS `Config` type. uTLS `ClientHello` fingerprinting is therefore not
/// available for QUIC transports.
pub(crate) fn build_quic_client_config(
    skip_cert_verify: bool,
    name_cert_verify: &str,
    alpn_protocols: Vec<Vec<u8>>,
    session_cache: Arc<dyn rustls::client::ClientSessionStore>,
) -> Result<Arc<rustls::ClientConfig>> {
    let provider = crypto_provider();

    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|err| anyhow!("failed to build TLS config: {err}"))?
        .dangerous();

    let mut config = if skip_cert_verify {
        builder.with_custom_certificate_verifier(Arc::new(InsecureVerifier(provider))).with_no_client_auth()
    } else if !name_cert_verify.is_empty() {
        builder
            .with_custom_certificate_verifier(Arc::new(NameCertVerifyingVerifier::new(name_cert_verify, provider)))
            .with_no_client_auth()
    } else {
        let roots = ca::config::get_cert_pool();
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|err| anyhow!("failed to build TLS config: {err}"))?
            .with_root_certificates((*roots).clone())
            .with_no_client_auth()
    };

    config.alpn_protocols = alpn_protocols;
    config.resumption = rustls::client::Resumption::store(session_cache);
    config.enable_early_data = true;
    Ok(Arc::new(config))
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

#[derive(Debug)]
struct InsecureVerifier(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

struct NameCertVerifyingVerifier {
    verifier: ca::name_cert_verify::NameCertVerifier,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl fmt::Debug for NameCertVerifyingVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NameCertVerifyingVerifier")
            .field("verifier", &"<fn>")
            .field("provider", &self.provider)
            .finish()
    }
}

impl NameCertVerifyingVerifier {
    fn new(name: &str, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { verifier: ca::name_cert_verify::new_name_cert_verifier(name, None, None), provider }
    }
}

impl rustls::client::danger::ServerCertVerifier for NameCertVerifyingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut certs = Vec::with_capacity(1 + intermediates.len());
        certs.push(
            murmur_component_tls::utls::X509Certificate::parse(end_entity)
                .map_err(|err| rustls::Error::General(err.to_string()))?,
        );
        for der in intermediates {
            certs.push(
                murmur_component_tls::utls::X509Certificate::parse(der)
                    .map_err(|err| rustls::Error::General(err.to_string()))?,
            );
        }
        let certs: Vec<Arc<_>> = certs.into_iter().map(Arc::new).collect();
        (self.verifier)(&certs).map_err(|err| rustls::Error::General(err.to_string()))?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Bridges an arbitrary `Box<dyn PacketConn>` (proxy-aware, from `DNSDialer::listen_packet`) onto
/// `quinn::AsyncUdpSocket`.
pub(crate) struct PacketConnSocket {
    local_addr: SocketAddr,
    send: Mutex<PollSender<(Vec<u8>, SocketAddr)>>,
    recv: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

impl fmt::Debug for PacketConnSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketConnSocket").field("local_addr", &self.local_addr).finish_non_exhaustive()
    }
}

impl PacketConnSocket {
    fn new(conn: Arc<dyn PacketConn>, local_addr: SocketAddr) -> Arc<Self> {
        let (recv_tx, recv_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
        let (send_tx, mut send_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);

        let recv_conn = Arc::clone(&conn);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match recv_conn.read_from(&mut buf).await {
                    Ok((n, addr)) => {
                        let Ok(sock_addr) = socket_addr_of(addr.as_ref()) else { continue };
                        let Some(payload) = buf.get(..n) else { continue };
                        if recv_tx.send((payload.to_vec(), sock_addr)).await.is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        errorln!("DoQ/DoH3 packet conn read error: {err}");
                        break;
                    }
                }
            }
        });

        let send_conn = conn;
        tokio::spawn(async move {
            while let Some((data, addr)) = send_rx.recv().await {
                let udp_addr = UdpAddr::from(addr);
                if let Err(err) = send_conn.write_to(&data, &udp_addr).await {
                    errorln!("DoQ/DoH3 packet conn write error: {err}");
                    break;
                }
            }
        });

        Arc::new(Self { local_addr, send: Mutex::new(PollSender::new(send_tx)), recv: Mutex::new(recv_rx) })
    }
}

impl quinn::AsyncUdpSocket for PacketConnSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(SendPoller(self))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        let mut guard = self.send.lock();
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        match guard.poll_reserve(&mut cx) {
            Poll::Ready(Ok(())) => guard
                .send_item((transmit.contents.to_vec(), transmit.destination))
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "packet conn closed")),
            Poll::Ready(Err(_)) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "packet conn closed")),
            Poll::Pending => Err(io::Error::new(io::ErrorKind::WouldBlock, "send buffer full")),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.recv.lock();
        match rx.poll_recv(cx) {
            Poll::Ready(Some((data, addr))) => {
                let (Some(buf), Some(meta_slot)) = (bufs.first_mut(), meta.first_mut()) else {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidInput, "no receive buffer")));
                };
                let len = data.len().min(buf.len());
                let (Some(src), Some(dst)) = (data.get(..len), buf.get_mut(..len)) else {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidInput, "datagram is too short")));
                };
                dst.copy_from_slice(src);
                *meta_slot = quinn::udp::RecvMeta { addr, len, stride: len, ecn: None, dst_ip: None };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "packet conn closed"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

#[derive(Debug)]
struct SendPoller(Arc<PacketConnSocket>);

impl quinn::UdpPoller for SendPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let mut guard = self.0.send.lock();
        guard.poll_reserve(cx).map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "packet conn closed"))
    }
}

/// Dials over the packet connection, always awaiting the full handshake (a dial-early variant,
/// used only by `doh.rs`'s probe/HTTP3 path, would additionally allow sending 0-RTT data before the
/// handshake completes; quinn negotiates 0-RTT itself given a warm session cache, so the
/// distinction collapses here — recorded as a deviation).
pub(crate) async fn open_quic_connection(
    packet_conn: Arc<dyn PacketConn>,
    remote: SocketAddr,
    server_name: &str,
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<quinn::Connection> {
    let local_addr = match packet_conn.local_addr() {
        Ok(addr) => socket_addr_of(addr.as_ref())?,
        Err(_) => {
            if remote.is_ipv4() {
                SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0)
            } else {
                SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)
            }
        }
    };

    let socket = PacketConnSocket::new(packet_conn, local_addr);
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.max_udp_payload_size(1350).ok();

    let endpoint =
        quinn::Endpoint::new_with_abstract_socket(endpoint_config, None, socket, Arc::new(quinn::TokioRuntime))
            .map_err(|err| anyhow!("failed to create QUIC endpoint: {err}"))?;

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from((*tls_config).clone())
        .map_err(|err| anyhow!("invalid QUIC TLS config: {err}"))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(QUIC_KEEP_ALIVE_PERIOD));
    client_config.transport_config(Arc::new(transport_config));

    let connecting = endpoint
        .connect_with(client_config, remote, server_name)
        .map_err(|err| anyhow!("failed to dial QUIC connection: {err}"))?;
    let connection = connecting
        .await
        .map_err(|err| anyhow::Error::from(err).context(format!("opening quic connection to {remote}")))?;
    Ok(connection)
}

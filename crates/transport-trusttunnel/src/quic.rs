//! QUIC client and server for the trusttunnel transport, driving `quinn` + `h3`/`h3-quinn`
//! directly and binding its own UDP endpoint.
//!
//! A richer QUIC mirror and its concrete `quinn` backend now exist (`murmur_transport_tuic::quic`'s
//! `Conn`/`EarlyListener` with `dial`/`listen_early`, `ClientTls`/`ServerTls` and
//! `congestion_factory`, over the `murmur_std_compat::net::PacketConn` a dialer produces), but this
//! file is not wired to them. The QUIC transport therefore does not go through
//! the client dialer — only its host is resolved through `murmur`'s resolver — and
//! uTLS fingerprinting or ECH are not applied to it (only ALPN and `skip_cert_verify` carry over
//! from [`murmur_transport_vmess::tls::TlsConfig`]). The congestion-control name is mapped locally
//! to `quinn`'s own `congestion::{CubicConfig, NewRenoConfig, BbrConfig}` (see
//! [`congestion_controller_factory`]) instead of through `murmur_transport_tuic::quic`'s
//! `congestion_factory`.
//!
//! NEEDED SHIM ITEM: route this file's client and server through `murmur_transport_tuic::quic`'s
//! `dial`/`listen_early` instead of the endpoints built here.
//!
//! 0-RTT is kept asymmetric:
//!
//! * Server: early data is enabled through rustls's `max_early_data_size = u32::MAX` in
//!   [`build_server_rustls_config`]; `QuicServerConfig::try_from` copies the field through
//!   untouched, and rustls sends the session tickets carrying the `early_data` extension with its
//!   default `send_tls13_tickets = 2`.
//! * Client: early data is never offered — [`H3RoundTripper::connect`] uses plain
//!   `quinn::Endpoint::connect` (never `Connecting::into_0rtt`) and [`build_client_rustls_config`]
//!   pins rustls's `enable_early_data = false`, so no ticket is cached and no early data is sent.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use murmur_common_httputils::addr::{set_addr_from_request, LocalAddrContextKey, RemoteAddr};
use murmur_component::resolver::resolver::{lookup_ip_with_resolver, proxy_server_host_resolver, sortation_addr};
use murmur_component_ca::fingerprint::{new_fingerprint_verifier, FingerprintVerifier as FingerprintVerifierFn};
use murmur_component_ca::keypair::new_tls_key_pair_loader;
use murmur_component_tls::utls::X509Certificate;
use murmur_std_compat::net::PacketConn as StdPacketConn;
use murmur_transport_vmess as vmess;

use super::client::TunnelRoundTripper;
use super::protocol::{BodyReader, BodyWriter, DEFAULT_QUIC_MAX_IDLE_TIMEOUT, DEFAULT_QUIC_STREAM_RECEIVE_WINDOW};
use super::service::Service;

fn congestion_controller_factory(name: &str, cwnd: i32) -> Arc<dyn ControllerFactory + Send + Sync> {
    let initial_window = u64::try_from(cwnd).ok().filter(|w| *w > 0).map(|w| w * 1200);
    match name {
        "cubic" | "new_reno" if name == "new_reno" => {
            let mut cfg = NewRenoConfig::default();
            if let Some(w) = initial_window {
                cfg.initial_window(w);
            }
            Arc::new(cfg)
        }
        "bbr_meta_v1" | "bbr_meta_v2" | "bbr" => {
            let mut cfg = BbrConfig::default();
            if let Some(w) = initial_window {
                cfg.initial_window(w);
            }
            Arc::new(cfg)
        }
        _ => {
            let mut cfg = CubicConfig::default();
            if let Some(w) = initial_window {
                cfg.initial_window(w);
            }
            Arc::new(cfg)
        }
    }
}

fn transport_config(name: &str, cwnd: i32) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the stream receive window constant is 128 KiB, well under u32"
    )]
    let receive_window = quinn::VarInt::from_u32(DEFAULT_QUIC_STREAM_RECEIVE_WINDOW as u32);
    transport
        .max_idle_timeout(quinn::IdleTimeout::try_from(DEFAULT_QUIC_MAX_IDLE_TIMEOUT).ok())
        .stream_receive_window(receive_window)
        .congestion_controller_factory(congestion_controller_factory(name, cwnd));
    transport
}

/// The h3 server's incoming-stream limit. Every CONNECT tunnel takes one bidirectional stream.
/// quinn's `StreamsState::new` materializes a stream-table entry per admitted stream ID, so a huge
/// limit cannot reach quinn unchanged; `1 << 12` still clears quinn's default of 100 by 40x, which
/// is the limit that would queue a client's concurrent tunnels, at a bounded table size.
const MAX_INCOMING_STREAMS: u32 = 1 << 12;

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
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
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

struct FingerprintVerifier(FingerprintVerifierFn);

impl std::fmt::Debug for FingerprintVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FingerprintVerifier").finish_non_exhaustive()
    }
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut certs = Vec::with_capacity(1 + intermediates.len());
        for der in std::iter::once(end_entity).chain(intermediates) {
            let cert = X509Certificate::parse(der.as_ref()).map_err(|err| rustls::Error::General(err.to_string()))?;
            certs.push(Arc::new(cert));
        }
        let name = server_name.to_str().into_owned();
        (self.0)(&certs, &name).map_err(|err| rustls::Error::General(err.to_string()))?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

fn build_client_rustls_config(tls_config: &vmess::tls::TlsConfig) -> Result<Arc<rustls::ClientConfig>> {
    let builder = rustls::ClientConfig::builder();
    let builder = if tls_config.skip_cert_verify {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify))
    } else if !tls_config.finger_print.is_empty() {
        let verifier = new_fingerprint_verifier(&tls_config.finger_print, Some(Arc::new(murmur_ntp::time::now)))?;
        builder.dangerous().with_custom_certificate_verifier(Arc::new(FingerprintVerifier(verifier)))
    } else {
        builder.with_root_certificates((*murmur_component_ca::config::get_cert_pool()).clone())
    };

    let mut config = if !tls_config.certificate.is_empty() && !tls_config.private_key.is_empty() {
        let cert_loader = new_tls_key_pair_loader(&tls_config.certificate, &tls_config.private_key)?;
        let certificate = cert_loader()?;
        let chain: Vec<rustls::pki_types::CertificateDer<'static>> =
            certificate.certificate.into_iter().map(rustls::pki_types::CertificateDer::from).collect();
        let key = certificate.private_key.ok_or_else(|| anyhow!("client certificate has no private key"))?;
        builder.with_client_auth_cert(chain, key)?
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = tls_config.next_protos.iter().map(|p| p.as_bytes().to_vec()).collect();
    // The client never caches a session ticket and never opts into `into_0rtt`, keeping it off
    // 0-RTT. rustls's default is already false.
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

#[expect(clippy::unnecessary_wraps, reason = "the fallible shape of this constructor is its pub(crate) signature")]
pub(crate) fn quic_round_tripper(
    tls_config: &vmess::tls::TlsConfig,
    congestion_control_name: &str,
    cwnd: i32,
    bbr_profile: &str,
    server: &str,
) -> Result<Arc<dyn TunnelRoundTripper>> {
    Ok(Arc::new(H3RoundTripper {
        server: server.to_owned(),
        tls_config: tls_config.clone(),
        congestion_control_name: congestion_control_name.to_owned(),
        cwnd,
        bbr_profile: bbr_profile.to_owned(),
        connection: AsyncMutex::new(None),
    }))
}

/// Resolves the server through `murmur`'s own resolver, never the OS resolver; IPv4 leads like the
/// default dual-stack primary.
async fn resolve_quic_server(server: &str) -> Result<SocketAddr> {
    let (host, port, has_port) = murmur_common_net::split_host_port(server)?;
    if !has_port {
        return Err(anyhow!("address {server}: missing port in address"));
    }
    let port: u16 = port.parse().map_err(|_| anyhow!("address {server}: unknown port {port}"))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // `open` carries no request context to borrow (the `Dial` gets the request's).
    let ctx = CancellationToken::new();
    let ips = lookup_ip_with_resolver(&ctx, &host, proxy_server_host_resolver().as_deref()).await?;
    let (ipv4s, ipv6s) = sortation_addr(&ips);
    ipv4s
        .first()
        .or_else(|| ipv6s.first())
        .map(|ip| SocketAddr::new(*ip, port))
        .ok_or_else(|| anyhow!("could not resolve {server}"))
}

struct H3State {
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver: tokio::task::JoinHandle<()>,
    endpoint: quinn::Endpoint,
}

impl H3State {
    /// Dropping the `JoinHandle` only detaches the driver, so the h3 connection (and with it the
    /// quinn one) would outlive the client that owns it. Aborting the driver and closing the
    /// endpoint releases the socket and every stream still open on it.
    fn close(self) {
        self.driver.abort();
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
    }
}

pub(crate) struct H3RoundTripper {
    server: String,
    tls_config: vmess::tls::TlsConfig,
    congestion_control_name: String,
    cwnd: i32,
    bbr_profile: String,
    connection: AsyncMutex<Option<H3State>>,
}

impl H3RoundTripper {
    async fn connect(&self) -> Result<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>> {
        let mut guard = self.connection.lock().await;
        if let Some(state) = guard.as_ref() {
            return Ok(state.send_request.clone());
        }
        let _ = &self.bbr_profile;

        let addr = resolve_quic_server(&self.server).await?;
        let bind_addr: SocketAddr = if addr.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
        let socket = murmur_component::dialer::control::bind_quic_client_socket(bind_addr)?;
        let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime found"))?;
        let mut endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;

        let rustls_config = build_client_rustls_config(&self.tls_config)?;
        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from((*rustls_config).clone())?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport_config(&self.congestion_control_name, self.cwnd)));
        endpoint.set_default_client_config(client_config);

        let server_name =
            if self.tls_config.host.is_empty() { addr.ip().to_string() } else { self.tls_config.host.clone() };
        let quinn_conn = endpoint.connect(addr, &server_name)?.await?;
        let h3_conn = h3_quinn::Connection::new(quinn_conn);
        let (mut connection, send_request) = h3::client::new(h3_conn).await?;
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| connection.poll_close(cx)).await;
        });
        *guard = Some(H3State { send_request: send_request.clone(), driver, endpoint });
        drop(guard);
        Ok(send_request)
    }
}

impl murmur_common_httputils::force_close::RoundTripper for H3RoundTripper {
    fn close_idle_connections(&self) {}

    fn close_http2_connections(&self) {
        if let Ok(mut guard) = self.connection.try_lock() {
            if let Some(state) = guard.take() {
                state.close();
            }
        }
    }

    fn close(&self) {
        self.close_http2_connections();
    }
}

enum H3WriteCommand {
    Data(Bytes, tokio::sync::oneshot::Sender<std::io::Result<()>>),
    Finish(tokio::sync::oneshot::Sender<std::io::Result<()>>),
}

fn broken_h3_stream() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "h3 stream already failed a write")
}

/// `h3-quinn::SendStream::poll_ready` (`h3-quinn-0.0.10/src/lib.rs:464-476`) leaves its `writing`
/// slot populated whenever the wrapped `quinn::SendStream::poll_write` returns *any* real error,
/// including the routine `Stopped` a peer sends once it has read all the response it wants (a
/// concurrent CONNECT tunnel closing early is exactly this): the `?` on that `poll_write` call
/// returns before the line that clears `writing`. `h3::RequestStream::finish()` then
/// unconditionally tries to write one grease frame first (`h3-0.0.8/src/connection.rs:1101-1114`,
/// once per stream) before actually finishing; on an already-poisoned stream that grease write's
/// own `send_data` sees `writing` still `Some` and reports h3-quinn's misuse guard —
/// `ConnectionErrorIncoming::InternalError("internal error in the http stack")` — which h3
/// promotes to a fatal `H3_INTERNAL_ERROR` that tears down the *whole* connection, aborting every
/// other concurrent stream. Confirmed live: instrumenting every `send_data`/`finish` call showed a
/// stream's ordinary `Stopped`-caused `send_data` error immediately followed, on the very next
/// call to that same stream's `finish()`, by exactly this connection-ending error. A single task
/// owns the stream for its whole lifetime, both so a caller cancelling `write_flush`/`close` can
/// never abandon a write mid-poll, and — the fix for the actual failure — so it can remember that
/// the stream already failed a write and skip `finish()`'s grease frame instead of ever touching
/// the poisoned stream again.
struct H3BodyWriter(tokio::sync::mpsc::UnboundedSender<H3WriteCommand>);

impl H3BodyWriter {
    fn new(mut stream: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<H3WriteCommand>();
        tokio::spawn(async move {
            let mut poisoned = false;
            while let Some(command) = rx.recv().await {
                match command {
                    H3WriteCommand::Data(data, ack) => {
                        let result = if poisoned {
                            Err(broken_h3_stream())
                        } else {
                            let result = stream.send_data(data).await.map_err(std::io::Error::other);
                            poisoned = result.is_err();
                            result
                        };
                        let _ = ack.send(result);
                    }
                    H3WriteCommand::Finish(ack) => {
                        let result = if poisoned {
                            Err(broken_h3_stream())
                        } else {
                            stream.finish().await.map_err(std::io::Error::other)
                        };
                        let _ = ack.send(result);
                        return;
                    }
                }
            }
            // The writer went away without a `Finish` (the relay's half close drops it once it is
            // done writing): the peer's read side would wait for an EOF that never comes.
            if !poisoned {
                let _ = stream.finish().await;
            }
        });
        Self(tx)
    }
}

#[async_trait::async_trait]
impl BodyWriter for H3BodyWriter {
    async fn write_flush(&self, p: &[u8]) -> std::io::Result<usize> {
        let (ack, done) = tokio::sync::oneshot::channel();
        self.0
            .send(H3WriteCommand::Data(Bytes::copy_from_slice(p), ack))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "h3 stream writer task exited"))?;
        done.await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "h3 stream writer task exited"))??;
        Ok(p.len())
    }

    fn close(&self) {
        let (ack, _done) = tokio::sync::oneshot::channel();
        let _ = self.0.send(H3WriteCommand::Finish(ack));
    }
}

/// Split from the combined `h3::client::RequestStream` at [`H3RoundTripper::open`] so the reader
/// and the writer never contend for the same lock: sharing one mutex across both directions
/// deadlocked the relay whenever a write needed to happen while a read was blocked awaiting more
/// data from the peer (`recv_data` holds its stream borrow for the whole wait).
struct H3BodyReader {
    stream: Arc<AsyncMutex<h3::client::RequestStream<h3_quinn::RecvStream, Bytes>>>,
    pending: parking_lot::Mutex<Option<std::pin::Pin<Box<dyn Future<Output = std::io::Result<Option<Bytes>>> + Send>>>>,
    leftover: parking_lot::Mutex<Option<Bytes>>,
}

impl H3BodyReader {
    fn new(stream: Arc<AsyncMutex<h3::client::RequestStream<h3_quinn::RecvStream, Bytes>>>) -> Self {
        Self { stream, pending: parking_lot::Mutex::new(None), leftover: parking_lot::Mutex::new(None) }
    }
}

/// Reads an h3 request body. `h3::client::RequestStream::recv_data` is an `async
/// fn`; a naive `poll_read` that boxes a fresh call to it on every poll and drops that future on
/// `Poll::Pending` (the original shape) is not cancel-safe — dropping a `recv_data` call
/// mid-flight discards bytes it already pulled off the QUIC stream without delivering them,
/// desynchronizing every h3 DATA frame boundary after the first short read. `pending` persists the
/// same future across polls instead (the pattern `TcpConn::poll_read` already uses), and
/// `leftover` holds back bytes from a chunk larger than the caller's buffer instead of dropping
/// them, since `recv_data` has no smaller-buffer form.
impl tokio::io::AsyncRead for H3BodyReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        {
            let mut leftover = this.leftover.lock();
            if let Some(bytes) = leftover.as_mut() {
                let n = bytes.len().min(buf.remaining());
                buf.put_slice(bytes.get(..n).unwrap_or_default());
                bytes::Buf::advance(bytes, n);
                if bytes.is_empty() {
                    *leftover = None;
                }
                drop(leftover);
                return std::task::Poll::Ready(Ok(()));
            }
        }
        let mut pending = this.pending.lock();
        let future = pending.get_or_insert_with(|| {
            let inner = Arc::clone(&this.stream);
            Box::pin(async move {
                let mut stream = inner.lock().await;
                match stream.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        let n = bytes::Buf::remaining(&chunk);
                        Ok(Some(bytes::Buf::copy_to_bytes(&mut chunk, n)))
                    }
                    Ok(None) => Ok(None),
                    Err(err) => Err(std::io::Error::other(err)),
                }
            })
        });
        match future.as_mut().poll(cx) {
            std::task::Poll::Ready(result) => {
                *pending = None;
                drop(pending);
                match result {
                    Ok(Some(bytes)) => {
                        let n = bytes.len().min(buf.remaining());
                        buf.put_slice(bytes.get(..n).unwrap_or_default());
                        if n < bytes.len() {
                            *this.leftover.lock() = Some(bytes.slice(n..));
                        }
                        std::task::Poll::Ready(Ok(()))
                    }
                    Ok(None) => std::task::Poll::Ready(Ok(())),
                    Err(err) => std::task::Poll::Ready(Err(err)),
                }
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[async_trait::async_trait]
impl TunnelRoundTripper for H3RoundTripper {
    async fn open(
        &self,
        host: &str,
        user_agent: &str,
        auth: &str,
    ) -> Result<(Arc<dyn BodyWriter>, futures::future::BoxFuture<'static, Result<BodyReader>>)> {
        let mut send_request = self.connect().await?;
        let request = hyper::Request::builder()
            .method("CONNECT")
            .uri(host)
            .header("User-Agent", user_agent)
            .header("Proxy-Authorization", auth)
            .body(())?;
        let stream = send_request.send_request(request).await?;
        let (send_stream, mut recv_stream) = stream.split();
        let writer: Arc<dyn BodyWriter> = Arc::new(H3BodyWriter::new(send_stream));
        let pending = Box::pin(async move {
            let status = recv_stream.recv_response().await?.status();
            if status != hyper::StatusCode::OK {
                return Err(anyhow!("unexpected status code: {}", status.as_u16()));
            }
            let body: BodyReader = Box::pin(H3BodyReader::new(Arc::new(AsyncMutex::new(recv_stream))));
            Ok(body)
        });
        Ok((writer, pending))
    }

    async fn health_check_round_trip(&self, host: &str, user_agent: &str, auth: &str) -> Result<()> {
        let mut send_request = self.connect().await?;
        let request = hyper::Request::builder()
            .method("CONNECT")
            .uri(host)
            .header("User-Agent", user_agent)
            .header("Proxy-Authorization", auth)
            .body(())?;
        let mut stream = send_request.send_request(request).await?;
        stream.finish().await?;
        let response = stream.recv_response().await?;
        if response.status() != hyper::StatusCode::OK {
            return Err(anyhow!("unexpected status code: {}", response.status().as_u16()));
        }
        Ok(())
    }
}

pub(crate) fn config_http3_server(
    service: &Arc<Service>,
    tls_config: Option<Arc<murmur_component_tls::utls::Config>>,
    udp_conn: Box<dyn StdPacketConn>,
) -> Result<()> {
    let Some(tls_config) = tls_config else {
        return Err(anyhow!("HTTP3 server requires a TLS config"));
    };

    let server_rustls_config = build_server_rustls_config(&tls_config)?;
    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_rustls_config)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    let mut transport = transport_config(&service.quic_congestion_control, service.quic_cwnd);
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_INCOMING_STREAMS));
    server_config.transport_config(Arc::new(transport));

    let std_socket = udp_conn.into_std_udp()?;
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime found for quinn"))?;
    let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(server_config), std_socket, runtime)?;

    let http3_server = Arc::new(Http3Server { endpoint: endpoint.clone(), closed: AtomicBool::new(false) });
    *service.h3_server.lock() = Some(Arc::clone(&http3_server));

    let service = Arc::clone(service);
    // quinn 0.11 exposes only the peer's address on `Connection`, so the listener's own is taken
    // from the endpoint every accepted connection shares.
    let local_addr = endpoint.local_addr().ok();
    tokio::spawn(async move {
        loop {
            let Some(connecting) = endpoint.accept().await else { break };
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                let Ok(quinn_conn) = connecting.await else { return };
                let remote_addr = quinn_conn.remote_address();
                let h3_conn = h3_quinn::Connection::new(quinn_conn);
                let Ok(mut h3_conn) = h3::server::builder().build::<_, Bytes>(h3_conn).await else { return };
                while let Ok(Some(resolver)) = h3_conn.accept().await {
                    let service = Arc::clone(&service);
                    tokio::spawn(async move {
                        let Ok((request, stream)) = resolver.resolve_request().await else { return };
                        serve_h3(&service, request, stream, local_addr, remote_addr).await;
                    });
                }
            });
        }
    });
    Ok(())
}

/// The h3 server uses the listener's own TLS material, so client-certificate authentication and
/// the certificate hook carry over too; only the ALPN addition is h3-specific. ECH is the one thing
/// that cannot carry over: `rustls` implements no ECH server, and `quinn` only speaks `rustls`, so
/// the h3 listener's ClientHellos are always in the clear and saying so beats serving silently.
fn build_server_rustls_config(tls_config: &murmur_component_tls::utls::Config) -> Result<rustls::ServerConfig> {
    if tls_config.certificates.is_empty() && tls_config.get_certificate.is_none() {
        return Err(anyhow!("HTTP3 server requires a certificate"));
    }
    if !tls_config.encrypted_client_hello_keys.is_empty() {
        log::warn!("trusttunnel: the configured ECH key is not used for h3; rustls has no ECH server");
    }
    let mut server_config = murmur_component_tls::utls::server_rustls_config(tls_config)?;
    server_config.alpn_protocols = vec![b"h3".to_vec()];
    // quinn-proto's `TryFrom` does not touch `max_early_data_size`, so without this quinn's server
    // silently rejects every 0-RTT flight.
    server_config.max_early_data_size = u32::MAX;
    Ok(server_config)
}

/// Holds the `quinn::Endpoint` directly rather than an h3 server type, since the h3 server driver
/// loop owns the request dispatch itself (see [`config_http3_server`]).
pub(crate) struct Http3Server {
    endpoint: quinn::Endpoint,
    closed: AtomicBool,
}

impl Http3Server {
    pub(crate) fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
    }
}

/// See [`H3BodyWriter`] for why the stream is owned by a dedicated task rather than written to
/// directly from `write_flush`/`close`.
struct H3ServerBodyWriter(tokio::sync::mpsc::UnboundedSender<H3WriteCommand>);

impl H3ServerBodyWriter {
    fn new(mut stream: h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<H3WriteCommand>();
        tokio::spawn(async move {
            let mut poisoned = false;
            while let Some(command) = rx.recv().await {
                match command {
                    H3WriteCommand::Data(data, ack) => {
                        let result = if poisoned {
                            Err(broken_h3_stream())
                        } else {
                            let result = stream.send_data(data).await.map_err(std::io::Error::other);
                            poisoned = result.is_err();
                            result
                        };
                        let _ = ack.send(result);
                    }
                    H3WriteCommand::Finish(ack) => {
                        let result = if poisoned {
                            Err(broken_h3_stream())
                        } else {
                            stream.finish().await.map_err(std::io::Error::other)
                        };
                        let _ = ack.send(result);
                        return;
                    }
                }
            }
            if !poisoned {
                let _ = stream.finish().await;
            }
        });
        Self(tx)
    }
}

#[async_trait::async_trait]
impl BodyWriter for H3ServerBodyWriter {
    async fn write_flush(&self, p: &[u8]) -> std::io::Result<usize> {
        let (ack, done) = tokio::sync::oneshot::channel();
        self.0
            .send(H3WriteCommand::Data(Bytes::copy_from_slice(p), ack))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "h3 stream writer task exited"))?;
        done.await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "h3 stream writer task exited"))??;
        Ok(p.len())
    }

    fn close(&self) {
        let (ack, _done) = tokio::sync::oneshot::channel();
        let _ = self.0.send(H3WriteCommand::Finish(ack));
    }
}

/// Split from the combined `h3::server::RequestStream` in [`serve_h3`]; see [`H3BodyReader`] for
/// why sharing one mutex across both directions deadlocked the relay.
struct H3ServerBodyReader {
    stream: Arc<AsyncMutex<h3::server::RequestStream<h3_quinn::RecvStream, Bytes>>>,
    pending: parking_lot::Mutex<Option<std::pin::Pin<Box<dyn Future<Output = std::io::Result<Option<Bytes>>> + Send>>>>,
    leftover: parking_lot::Mutex<Option<Bytes>>,
}

impl H3ServerBodyReader {
    fn new(stream: Arc<AsyncMutex<h3::server::RequestStream<h3_quinn::RecvStream, Bytes>>>) -> Self {
        Self { stream, pending: parking_lot::Mutex::new(None), leftover: parking_lot::Mutex::new(None) }
    }
}

/// See [`H3BodyReader`]: the same cancel-safety and partial-read fix, mirrored for the server
/// side's `h3::server::RequestStream`.
impl tokio::io::AsyncRead for H3ServerBodyReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        {
            let mut leftover = this.leftover.lock();
            if let Some(bytes) = leftover.as_mut() {
                let n = bytes.len().min(buf.remaining());
                buf.put_slice(bytes.get(..n).unwrap_or_default());
                bytes::Buf::advance(bytes, n);
                if bytes.is_empty() {
                    *leftover = None;
                }
                drop(leftover);
                return std::task::Poll::Ready(Ok(()));
            }
        }
        let mut pending = this.pending.lock();
        let future = pending.get_or_insert_with(|| {
            let inner = Arc::clone(&this.stream);
            Box::pin(async move {
                let mut stream = inner.lock().await;
                match stream.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        let n = bytes::Buf::remaining(&chunk);
                        Ok(Some(bytes::Buf::copy_to_bytes(&mut chunk, n)))
                    }
                    Ok(None) => Ok(None),
                    Err(err) => Err(std::io::Error::other(err)),
                }
            })
        });
        match future.as_mut().poll(cx) {
            std::task::Poll::Ready(result) => {
                *pending = None;
                drop(pending);
                match result {
                    Ok(Some(bytes)) => {
                        let n = bytes.len().min(buf.remaining());
                        buf.put_slice(bytes.get(..n).unwrap_or_default());
                        if n < bytes.len() {
                            *this.leftover.lock() = Some(bytes.slice(n..));
                        }
                        std::task::Poll::Ready(Ok(()))
                    }
                    Ok(None) => std::task::Poll::Ready(Ok(())),
                    Err(err) => std::task::Poll::Ready(Err(err)),
                }
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

fn empty_response(status: http::StatusCode) -> http::Response<()> {
    let mut response = http::Response::new(());
    *response.status_mut() = status;
    response
}

/// The h3 half of request serving: the h1/h2 listener shares one transport-agnostic handler, but
/// `h3`'s server API has no such shared abstraction, so this drives [`Service::dispatch`] directly
/// once the h3 response headers are flushed for the magic-address branches.
async fn serve_h3(
    service: &Arc<Service>,
    mut request: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    local_addr: Option<SocketAddr>,
    remote_addr: SocketAddr,
) {
    let authorization =
        request.headers().get("Proxy-Authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
    let Some(username) = service.verify(&authorization) else {
        let _ = stream.send_response(empty_response(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED)).await;
        service.bad_request("", "authorization failed");
        return;
    };
    if request.method() != http::Method::CONNECT {
        let _ = stream.send_response(empty_response(http::StatusCode::METHOD_NOT_ALLOWED)).await;
        service.bad_request("", &format!("unexpected HTTP method {}", request.method()));
        return;
    }
    let host = request.uri().authority().map(ToString::to_string).unwrap_or_default();
    log::debug!("[{username}] request to {host}");

    if host == super::protocol::HEALTH_CHECK_MAGIC_ADDRESS {
        if stream.send_response(empty_response(http::StatusCode::OK)).await.is_ok() {
            let _ = stream.finish().await;
        }
        return;
    }

    if stream.send_response(empty_response(http::StatusCode::OK)).await.is_err() {
        return;
    }
    let (send_stream, recv_stream) = stream.split();
    let writer: Arc<dyn BodyWriter> = Arc::new(H3ServerBodyWriter::new(send_stream));
    let http_conn = super::protocol::HttpConn::new(writer);
    // `h3` carries no per-request remote address, so the connection's own address supplies what the
    // request would otherwise provide. Without it the tunneled conn reports no local or peer address
    // and the relay's `metadata.source` comes out empty.
    request.extensions_mut().insert(RemoteAddr(remote_addr.to_string()));
    if let Some(local_addr) = local_addr {
        request
            .extensions_mut()
            .insert(LocalAddrContextKey(Arc::new(murmur_std_compat::net::TcpAddr::from(local_addr))));
    }
    set_addr_from_request(&http_conn.net_addr, &request);
    http_conn.setup(Some(Box::pin(H3ServerBodyReader::new(Arc::new(AsyncMutex::new(recv_stream))))), None);
    service.dispatch(http_conn, &remote_addr.to_string(), &host).await;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Result;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;
    use tokio_util::sync::CancellationToken;

    use murmur_common_net::sing::ExtendedConn as SingExtendedConn;
    use murmur_compat::sing_buf;
    use murmur_component_ca::keypair::new_tls_key_pair_loader;
    use murmur_component_tls::utls as tls_c;
    use murmur_sing::network::PacketConn as SingPacketConn;
    use murmur_std_compat::net::{PacketConn as StdPacketConn, UdpAddr};
    use murmur_testsupport::{tls_certificate, tls_private_key, TestDialer};
    use murmur_testsupport_probe::ensure_test_crypto_provider;
    use murmur_transport_vmess::tls::TlsConfig;

    use super::super::client::{Client, ClientOptions};
    use super::super::service::{Handler, Service, ServiceOptions, SingMetadata};

    /// Hands the tunnel's far side to the test through a duplex so the test drives a real
    /// full-duplex relay with backpressure in both directions.
    struct EchoHandler {
        peer: tokio::sync::mpsc::UnboundedSender<tokio::io::DuplexStream>,
    }

    #[async_trait::async_trait]
    impl Handler for EchoHandler {
        async fn new_connection(
            &self,
            _ctx: &CancellationToken,
            mut conn: Box<dyn SingExtendedConn>,
            _metadata: SingMetadata,
        ) -> Result<()> {
            let (mut tunnel_side, peer_side) = tokio::io::duplex(8 * 1024);
            self.peer.send(peer_side).expect("test holds the receiver");
            let _ = tokio::io::copy_bidirectional(&mut conn, &mut tunnel_side).await;
            Ok(())
        }

        async fn new_packet_connection(
            &self,
            _ctx: &CancellationToken,
            _conn: Arc<dyn SingPacketConn>,
            _metadata: SingMetadata,
        ) -> Result<()> {
            Ok(())
        }
    }

    fn quic_pair() -> (Arc<tls_c::Config>, TlsConfig) {
        let mut tls_config = tls_c::Config { time: Some(Arc::new(murmur_ntp::time::now)), ..Default::default() };
        let cert_loader = new_tls_key_pair_loader(tls_certificate(), tls_private_key()).expect("cert loader");
        tls_config.certificates = vec![cert_loader().expect("certificate")];
        tls_config.get_certificate = Some(Arc::new(move |_info: &tls_c::ClientHelloInfo| cert_loader().map(Some)));
        let client = TlsConfig { host: "127.0.0.1".to_owned(), skip_cert_verify: true, ..Default::default() };
        (Arc::new(tls_config), client)
    }

    fn client_options(server: std::net::SocketAddr, tls_config: TlsConfig) -> ClientOptions {
        ClientOptions {
            dialer: Arc::new(TestDialer::new(CancellationToken::new())),
            dial_options: None,
            server: server.to_string(),
            username: "test".to_owned(),
            password: "password".to_owned(),
            tls_config: Arc::new(tls_config),
            quic: true,
            quic_congestion_control: "bbr".to_owned(),
            quic_cwnd: 0,
            quic_bbr_profile: String::new(),
            health_check: false,
            max_connections: 0,
            min_streams: 0,
            max_streams: 0,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_tunnel_over_quic_round_trips_both_directions() {
        ensure_test_crypto_provider();
        let (tls_config, client_tls_config) = quic_pair();

        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let addr = socket.local_addr().expect("local addr");
        let service = Service::new(ServiceOptions {
            ctx: CancellationToken::new(),
            handler: Arc::new(EchoHandler { peer: peer_tx }),
            icmp_handler: None,
            quic_congestion_control: "bbr".to_owned(),
            quic_cwnd: 0,
            quic_bbr_profile: String::new(),
        });
        service.update_users(std::iter::once(("test".to_owned(), "password".to_owned())).collect());
        let udp_conn: Box<dyn StdPacketConn> = Box::new(socket);
        service.start(None, Some(udp_conn), Some(tls_config)).await.expect("service start");

        let client =
            Client::new(CancellationToken::new(), client_options(addr, client_tls_config)).await.expect("client");
        let conn = client.dial("example.com:443").await.expect("dial through the tunnel");
        let mut peer = tokio::time::timeout(Duration::from_secs(10), peer_rx.recv())
            .await
            .expect("handler never received the tunnel")
            .expect("handler received the tunnel");

        let payload: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
        let (mut tunnel_reader, mut tunnel_writer) = tokio::io::split(conn);
        let upload = {
            let payload = payload.clone();
            tokio::spawn(async move {
                tunnel_writer.write_all(&payload).await.expect("upload");
                tunnel_writer.shutdown().await.expect("half close");
            })
        };

        let mut uploaded = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(20), peer.read_exact(&mut uploaded))
            .await
            .expect("upload stalled in the relay")
            .expect("peer read");
        assert_eq!(uploaded, payload);

        // The echo runs concurrently with the read: a payload larger than the h3 stream's
        // receive window only drains if the reader keeps consuming while the writer fills it.
        let echo = tokio::spawn(async move {
            peer.write_all(&uploaded).await.expect("peer echo");
            peer.shutdown().await.expect("peer half close");
        });

        let mut received = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(20), tunnel_reader.read_exact(&mut received))
            .await
            .expect("download stalled in the relay")
            .expect("download");
        assert_eq!(received, payload);

        // Both halves closed, so the relay must close the h3 stream rather than leave the peer
        // waiting for an EOF that only a finished stream produces.
        let mut trailing = Vec::new();
        tokio::time::timeout(Duration::from_secs(20), tunnel_reader.read_to_end(&mut trailing))
            .await
            .expect("the relay never finished the h3 stream")
            .expect("tunnel drain");
        assert!(trailing.is_empty());
        upload.await.expect("upload task joins");
        echo.await.expect("echo task joins");
        let _ = client.close();
        let _ = service.close().await;
    }

    /// The listener-level inbound test drives its concurrent phase as 128 simultaneous CONNECT
    /// tunnels on one h3 connection, so the connection has to survive many streams finishing at
    /// once: a single poisoned stream used to escalate into `H3_INTERNAL_ERROR` and abort them all.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_connect_tunnels_over_quic_all_complete() {
        ensure_test_crypto_provider();
        let (tls_config, client_tls_config) = quic_pair();

        struct SizedEcho(usize);

        #[async_trait::async_trait]
        impl Handler for SizedEcho {
            async fn new_connection(
                &self,
                _ctx: &CancellationToken,
                mut conn: Box<dyn SingExtendedConn>,
                _metadata: SingMetadata,
            ) -> Result<()> {
                let mut buf = vec![0u8; self.0];
                let _ = AsyncReadExt::read_exact(&mut conn, &mut buf).await;
                let _ = AsyncWriteExt::write_all(&mut conn, &buf).await;
                let _ = AsyncWriteExt::shutdown(&mut conn).await;
                Ok(())
            }

            async fn new_packet_connection(
                &self,
                _ctx: &CancellationToken,
                _conn: Arc<dyn SingPacketConn>,
                _metadata: SingMetadata,
            ) -> Result<()> {
                Ok(())
            }
        }

        const TUNNELS: usize = 128;
        const SIZE: usize = 64 * 1024;

        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let addr = socket.local_addr().expect("local addr");
        let service = Service::new(ServiceOptions {
            ctx: CancellationToken::new(),
            handler: Arc::new(SizedEcho(SIZE)),
            icmp_handler: None,
            quic_congestion_control: "bbr".to_owned(),
            quic_cwnd: 0,
            quic_bbr_profile: String::new(),
        });
        service.update_users(std::iter::once(("test".to_owned(), "password".to_owned())).collect());
        let udp_conn: Box<dyn StdPacketConn> = Box::new(socket);
        service.start(None, Some(udp_conn), Some(tls_config)).await.expect("service start");

        let client = Client::new(
            CancellationToken::new(),
            ClientOptions { health_check: true, ..client_options(addr, client_tls_config) },
        )
        .await
        .expect("client");

        let payload: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
        let one = || {
            let client = Arc::clone(&client);
            let payload = payload.clone();
            async move {
                let conn = client.dial("example.com:443").await.expect("dial");
                let (mut reader, mut writer) = tokio::io::split(conn);
                let upload = {
                    let payload = payload.clone();
                    tokio::spawn(async move {
                        writer.write_all(&payload).await.expect("upload");
                        writer.shutdown().await.expect("half close");
                    })
                };
                let mut received = vec![0u8; payload.len()];
                tokio::time::timeout(Duration::from_secs(30), reader.read_exact(&mut received))
                    .await
                    .expect("download stalled")
                    .expect("download");
                upload.await.expect("upload joins");
                assert_eq!(received, payload);
            }
        };
        let (tunnels, checks) = tokio::join!(
            futures::future::join_all((0..TUNNELS).map(|_| one())),
            futures::future::join_all((0..8).map(|_| client.health_check()))
        );
        assert_eq!(tunnels.len(), TUNNELS);
        for check in checks {
            check.expect("health check on a busy connection");
        }

        let _ = client.close();
        let _ = service.close().await;
    }

    /// the h3 server sets its incoming-stream limit to `1 << 60` so a client's tunnels never queue behind
    /// a per-connection stream limit, and every CONNECT tunnel is one bidirectional stream. The
    /// barrier is what makes that observable: those tunnels are only all open at once if the
    /// server admits more streams than quinn's default of 100, since a client cannot open the
    /// 101st until an earlier one closes.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_tunnels_past_quinns_default_stream_limit_all_stay_open() {
        ensure_test_crypto_provider();
        let (tls_config, client_tls_config) = quic_pair();

        const TUNNELS: usize = 128;

        struct HeldEcho {
            opened: Arc<std::sync::atomic::AtomicUsize>,
            all_open: Arc<tokio::sync::Barrier>,
        }

        #[async_trait::async_trait]
        impl Handler for HeldEcho {
            async fn new_connection(
                &self,
                _ctx: &CancellationToken,
                mut conn: Box<dyn SingExtendedConn>,
                _metadata: SingMetadata,
            ) -> Result<()> {
                self.opened.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::time::timeout(Duration::from_secs(20), self.all_open.wait())
                    .await
                    .expect("a tunnel never received stream credit");
                let mut byte = [0u8; 1];
                let _ = AsyncReadExt::read_exact(&mut conn, &mut byte).await;
                let _ = AsyncWriteExt::write_all(&mut conn, &byte).await;
                Ok(())
            }

            async fn new_packet_connection(
                &self,
                _ctx: &CancellationToken,
                _conn: Arc<dyn SingPacketConn>,
                _metadata: SingMetadata,
            ) -> Result<()> {
                Ok(())
            }
        }

        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let addr = socket.local_addr().expect("local addr");
        let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = Service::new(ServiceOptions {
            ctx: CancellationToken::new(),
            handler: Arc::new(HeldEcho {
                opened: Arc::clone(&opened),
                all_open: Arc::new(tokio::sync::Barrier::new(TUNNELS)),
            }),
            icmp_handler: None,
            quic_congestion_control: "bbr".to_owned(),
            quic_cwnd: 0,
            quic_bbr_profile: String::new(),
        });
        service.update_users(std::iter::once(("test".to_owned(), "password".to_owned())).collect());
        let udp_conn: Box<dyn StdPacketConn> = Box::new(socket);
        service.start(None, Some(udp_conn), Some(tls_config)).await.expect("service start");

        let client =
            Client::new(CancellationToken::new(), client_options(addr, client_tls_config)).await.expect("client");

        let one = || {
            let client = Arc::clone(&client);
            async move {
                let conn = tokio::time::timeout(Duration::from_secs(20), client.dial("example.com:443"))
                    .await
                    .expect("dial waited for stream credit")
                    .expect("dial");
                let (mut reader, mut writer) = tokio::io::split(conn);
                writer.write_all(b"x").await.expect("upload");
                let mut echoed = [0u8; 1];
                tokio::time::timeout(Duration::from_secs(20), reader.read_exact(&mut echoed))
                    .await
                    .expect("echo stalled")
                    .expect("echo");
                assert_eq!(echoed, *b"x");
            }
        };
        let _ = futures::future::join_all((0..TUNNELS).map(|_| one())).await;
        assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), TUNNELS);

        let _ = client.close();
        let _ = service.close().await;
    }

    struct UdpEcho;

    #[async_trait::async_trait]
    impl Handler for UdpEcho {
        async fn new_connection(
            &self,
            _ctx: &CancellationToken,
            _conn: Box<dyn SingExtendedConn>,
            _metadata: SingMetadata,
        ) -> Result<()> {
            Ok(())
        }

        async fn new_packet_connection(
            &self,
            _ctx: &CancellationToken,
            conn: Arc<dyn SingPacketConn>,
            _metadata: SingMetadata,
        ) -> Result<()> {
            loop {
                let mut buffer = sing_buf::new_packet();
                let Ok(destination) = conn.read_packet(&mut buffer).await else { return Ok(()) };
                let echoed = conn.write_packet(&buffer, &destination).await;
                buffer.release();
                echoed?;
            }
        }
    }

    /// The `_udp2` magic address over h3: the packet relay shares the CONNECT stream with the TCP
    /// tunnel, so a header/body read that loses stream framing shows up here as a wrong round trip.
    #[tokio::test(flavor = "multi_thread")]
    async fn udp_tunnel_over_quic_round_trips_packets() {
        ensure_test_crypto_provider();
        let (tls_config, client_tls_config) = quic_pair();

        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let addr = socket.local_addr().expect("local addr");
        let service = Service::new(ServiceOptions {
            ctx: CancellationToken::new(),
            handler: Arc::new(UdpEcho),
            icmp_handler: None,
            quic_congestion_control: "bbr".to_owned(),
            quic_cwnd: 0,
            quic_bbr_profile: String::new(),
        });
        service.update_users(std::iter::once(("test".to_owned(), "password".to_owned())).collect());
        let udp_conn: Box<dyn StdPacketConn> = Box::new(socket);
        service.start(None, Some(udp_conn), Some(tls_config)).await.expect("service start");

        let client =
            Client::new(CancellationToken::new(), client_options(addr, client_tls_config)).await.expect("client");
        let pc = client.listen_packet().await.expect("listen packet");

        let ip: std::net::IpAddr = "1.2.3.4".parse().expect("ip");
        let destination: Box<dyn murmur_std_compat::net::Addr> = Box::new(UdpAddr::new(ip, 53));
        for round in 0..5u8 {
            let payload = vec![round; 64];
            pc.write_to(&payload, destination.as_ref()).await.expect("packet write");
            let mut buf = vec![0u8; 128];
            let (n, _from) = tokio::time::timeout(Duration::from_secs(10), pc.read_from(&mut buf))
                .await
                .expect("packet read did not time out")
                .expect("packet read");
            assert_eq!(&buf[..n], payload.as_slice());
        }

        let _ = client.close();
        let _ = service.close().await;
    }

    /// A quinn endpoint serving `server_rustls` (the h3 listener's own config, minus the h3
    /// dispatch) on a bound UDP socket, so a test can speak raw quinn to it.
    fn quinn_server(server_rustls: rustls::ServerConfig) -> (quinn::Endpoint, std::net::SocketAddr) {
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_rustls).expect("quic server config");
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(Arc::new(super::transport_config("bbr", 0)));
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let addr = socket.local_addr().expect("local addr");
        let runtime = quinn::default_runtime().expect("runtime");
        let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(server_config), socket, runtime)
            .expect("endpoint");
        (endpoint, addr)
    }

    /// Echoes each uni stream on a fresh server uni stream and reports every payload, so a caller
    /// can wait for "the server read my data" (which also proves the server's post-handshake
    /// flight, session tickets included, has landed).
    fn spawn_quinn_server(endpoint: quinn::Endpoint) -> tokio::sync::mpsc::UnboundedReceiver<Vec<u8>> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(connecting) = incoming.accept() else { continue };
                let Ok((conn, _)) = connecting.into_0rtt() else { continue };
                let tx = tx.clone();
                tokio::spawn(async move {
                    while let Ok(mut recv) = conn.accept_uni().await {
                        let Ok(payload) = recv.read_to_end(64).await else { break };
                        if let Ok(mut send) = conn.open_uni().await {
                            let _ = send.write_all(&payload).await;
                            let _ = send.finish();
                        }
                        let _ = tx.send(payload);
                    }
                });
            }
        });
        rx
    }

    fn quinn_client(rustls_config: rustls::ClientConfig) -> quinn::Endpoint {
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config).expect("client config");
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(super::transport_config("bbr", 0)));
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let runtime = quinn::default_runtime().expect("runtime");
        let mut endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime).expect("endpoint");
        endpoint.set_default_client_config(client_config);
        endpoint
    }

    /// A quinn client that opts into 0-RTT (`enable_early_data`) and offers the listener's own
    /// ALPN, which QUIC requires (RFC 9001 §8.1).
    fn early_data_client() -> quinn::Endpoint {
        let mut config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(super::NoVerify))
            .with_no_client_auth();
        config.enable_early_data = true;
        config.alpn_protocols = vec![b"h3".to_vec()];
        quinn_client(config)
    }

    /// One full handshake plus a 1-RTT round trip, so the server's NewSessionTicket is processed
    /// before the caller tries to resume.
    async fn prime_session(endpoint: &quinn::Endpoint, addr: std::net::SocketAddr) -> quinn::Connection {
        let conn = endpoint.connect(addr, "localhost").expect("connect").await.expect("handshake");
        let mut send = conn.open_uni().await.expect("open stream");
        send.write_all(b"one").await.expect("write");
        send.finish().expect("finish");
        let mut recv = conn.accept_uni().await.expect("server echo");
        assert_eq!(recv.read_to_end(64).await.expect("read echo"), b"one");
        conn
    }

    /// The server must advertise 0-RTT and accept the early-data flight: without
    /// `max_early_data_size` the ticket carries no early data, quinn's `into_0rtt` has no keys, and
    /// this test fails at `expect`.
    #[tokio::test(flavor = "multi_thread")]
    async fn h3_server_accepts_an_early_data_flight() {
        ensure_test_crypto_provider();
        let (tls_config, _) = quic_pair();
        let server_rustls = super::build_server_rustls_config(&tls_config).expect("server rustls config");
        let (server, addr) = quinn_server(server_rustls);
        let mut received = spawn_quinn_server(server);
        let client = early_data_client();

        let primed = prime_session(&client, addr).await;
        let (resumed, accepted) =
            client.connect(addr, "localhost").expect("connect").into_0rtt().expect("client was handed 0-RTT keys");
        let mut early = resumed.open_uni().await.expect("0-RTT stream");
        early.write_all(b"zero").await.expect("0-RTT write");
        early.finish().expect("finish");
        assert!(accepted.await, "the server rejected the 0-RTT flight");

        let mut payloads = Vec::new();
        for _ in 0..2 {
            payloads.push(
                tokio::time::timeout(Duration::from_secs(10), received.recv())
                    .await
                    .expect("server received nothing")
                    .expect("server received nothing"),
            );
        }
        assert_eq!(payloads, vec![b"one".to_vec(), b"zero".to_vec()]);

        primed.close(quinn::VarInt::from_u32(0), b"");
        resumed.close(quinn::VarInt::from_u32(0), b"");
        client.close(quinn::VarInt::from_u32(0), b"");
    }

    /// The control for the test above: the advertisement is a rustls field, not a quinn default.
    /// The identical listener config minus `max_early_data_size` hands out tickets with no early
    /// data, so the same client is never given keys.
    #[tokio::test(flavor = "multi_thread")]
    async fn h3_server_without_the_advertisement_refuses_early_data() {
        ensure_test_crypto_provider();
        let (tls_config, _) = quic_pair();
        let mut server_rustls = murmur_component_tls::utls::server_rustls_config(&tls_config).expect("rustls config");
        server_rustls.alpn_protocols = vec![b"h3".to_vec()];
        let (server, addr) = quinn_server(server_rustls);
        let _received = spawn_quinn_server(server);
        let client = early_data_client();

        let primed = prime_session(&client, addr).await;
        assert!(
            client.connect(addr, "localhost").expect("connect").into_0rtt().is_err(),
            "a server that never set max_early_data_size handed out 0-RTT keys"
        );

        primed.close(quinn::VarInt::from_u32(0), b"");
        client.close(quinn::VarInt::from_u32(0), b"");
    }

    /// The client config built here must stay off 0-RTT even against a server that advertises it:
    /// no session cache is configured, so no ticket is stored.
    #[tokio::test(flavor = "multi_thread")]
    async fn h3_client_never_attempts_0rtt() {
        ensure_test_crypto_provider();
        let (tls_config, mut client_tls_config) = quic_pair();
        client_tls_config.next_protos = vec!["h3".to_owned()];
        let server_rustls = super::build_server_rustls_config(&tls_config).expect("server rustls config");
        let (server, addr) = quinn_server(server_rustls);
        let _received = spawn_quinn_server(server);

        let rustls_client = super::build_client_rustls_config(&client_tls_config).expect("client rustls config");
        let client = quinn_client((*rustls_client).clone());

        let primed = prime_session(&client, addr).await;
        assert!(
            client.connect(addr, "localhost").expect("connect").into_0rtt().is_err(),
            "the client offered 0-RTT data"
        );

        primed.close(quinn::VarInt::from_u32(0), b"");
        client.close(quinn::VarInt::from_u32(0), b"");
    }
}

#[cfg(test)]
mod resolve_quic_server_tests {
    use std::time::Duration;

    use async_trait::async_trait;
    use hickory_proto::op::Message;
    use murmur_testsupport_probe::ensure_test_crypto_provider;
    use murmur_transport_vmess::tls::TlsConfig;

    use super::*;
    use murmur_component::resolver::resolver::{set_proxy_server_host_resolver, Resolver, SharedResolver};

    /// Answers one canned address and records every host it was asked for.
    struct RecordingResolver {
        answer: IpAddr,
        asked: parking_lot::Mutex<Vec<String>>,
        asked_notify: tokio::sync::Notify,
    }

    impl RecordingResolver {
        fn new(answer: IpAddr) -> Self {
            Self { answer, asked: parking_lot::Mutex::new(Vec::new()), asked_notify: tokio::sync::Notify::new() }
        }

        fn answer(&self, host: &str) -> Result<Vec<IpAddr>> {
            self.asked.lock().push(host.to_owned());
            self.asked_notify.notify_waiters();
            Ok(vec![self.answer])
        }
    }

    /// The installed proxy-server-host resolver is process-wide, so the tests that swap it hold
    /// this lock and restore the previous value on drop, including when an assertion panics.
    static RESOLVER_GLOBAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct InstalledResolver {
        _lock: std::sync::MutexGuard<'static, ()>,
        previous: Option<SharedResolver>,
    }

    impl InstalledResolver {
        fn install(resolver: SharedResolver) -> Self {
            let lock = RESOLVER_GLOBAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = proxy_server_host_resolver();
            set_proxy_server_host_resolver(Some(resolver));
            Self { _lock: lock, previous }
        }
    }

    impl Drop for InstalledResolver {
        fn drop(&mut self) {
            set_proxy_server_host_resolver(self.previous.take());
        }
    }

    #[async_trait]
    impl Resolver for RecordingResolver {
        async fn lookup_ip(&self, _ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
            self.answer(host)
        }

        async fn lookup_ipv4(&self, _ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
            self.answer(host)
        }

        async fn lookup_ipv6(&self, _ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
            self.answer(host)
        }

        async fn resolve_ech(&self, _ctx: &CancellationToken, _host: &str) -> Result<Vec<u8>> {
            panic!("the recording resolver only resolves addresses")
        }

        async fn exchange_context(&self, _ctx: &CancellationToken, _m: &Message) -> Result<Message> {
            panic!("the recording resolver only resolves addresses")
        }

        fn invalid(&self) -> bool {
            true
        }

        fn clear_cache(&self) {}

        fn reset_connection(&self) {}
    }

    #[tokio::test]
    async fn names_resolve_through_the_port_resolver_and_literals_do_not() {
        let resolver = Arc::new(RecordingResolver::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7))));
        let _installed = InstalledResolver::install(Arc::<RecordingResolver>::clone(&resolver));

        let target = resolve_quic_server("example.com:443").await.expect("resolve");
        assert_eq!(SocketAddr::from(([192, 0, 2, 7], 443)), target);
        assert_eq!(vec!["example.com".to_owned()], *resolver.asked.lock());

        let literal: SocketAddr = "192.0.2.9:8443".parse().unwrap();
        assert_eq!(literal, resolve_quic_server(&literal.to_string()).await.expect("literal"));
        assert_eq!(vec!["example.com".to_owned()], *resolver.asked.lock(), "a literal must not reach the resolver");
    }

    /// `H3RoundTripper::connect` is the only caller, and the address it resolves to is TEST-NET-1,
    /// so the handshake never completes: the resolver query is what the test observes.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_round_tripper_resolves_its_server_through_the_port_resolver() {
        ensure_test_crypto_provider();
        let resolver = Arc::new(RecordingResolver::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7))));
        let _installed = InstalledResolver::install(Arc::<RecordingResolver>::clone(&resolver));

        let tls_config = TlsConfig { host: "example.com".to_owned(), skip_cert_verify: true, ..Default::default() };
        let round_tripper =
            quic_round_tripper(&tls_config, "bbr", 0, "", "tunnel.example:8443").expect("round tripper");
        let open = tokio::spawn(async move { round_tripper.open("example.com:443", "ua", "auth").await.map(|_| ()) });

        // Wait for the query itself rather than polling a fixed budget: the resolver notifies on
        // every lookup, so the timeout below is only a hang guard, not a timing assumption.
        let asked = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let notified = resolver.asked_notify.notified();
                if !resolver.asked.lock().is_empty() {
                    break;
                }
                notified.await;
            }
        })
        .await;
        open.abort();
        assert!(asked.is_ok(), "the round tripper never resolved its server");
        assert!(resolver.asked.lock().iter().all(|host| host == "tunnel.example"));
    }
}

//! Fingerprinted TLS handshakes over `rustls`.

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use ml_kem::{Decapsulate, DecapsulationKey, KeyExport, MlKem768, Seed};
use parking_lot::Mutex;
use rand::distr::weighted::WeightedIndex;
use rand::distr::Distribution;
use rand::Rng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{ActiveKeyExchange, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, NamedGroup, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;
use x25519_dalek::{PublicKey, StaticSecret};

use murmur_common::utils::slice::map;
use murmur_common_net::io::{close_stream, Acceptor, Stream};
use murmur_log::{debugln, warnln};
use murmur_std_compat::net::{Addr, Conn as NetConn, TcpAddr};

use crate::utls_client::UtlsClient;

pub const VERSION_TLS12: u16 = 0x0303;
pub const VERSION_TLS13: u16 = 0x0304;

const SSLV3_HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDHELLO_RANDOM_LEN: usize = 32;
const CLIENT_SESSION_ID_LEN: usize = 32;
const PRNG_SEED_LENGTH: usize = 32;
const X25519_KEY_LEN: usize = 32;

/// DER-encoded OID `1.3.101.112` (Ed25519).
const ED25519_ALGORITHM_OID: &[u8] = &[0x2b, 0x65, 0x70];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct CurveId(pub u16);

impl CurveId {
    pub const CURVE_P256: Self = Self(23);
    pub const CURVE_P384: Self = Self(24);
    pub const CURVE_P521: Self = Self(25);
    pub const X25519: Self = Self(29);
    pub const X25519_MLKEM768: Self = Self(4588);

    /// The wire value of the group.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignatureScheme(pub u16);

impl SignatureScheme {
    pub const PKCS1_WITH_SHA1: Self = Self(0x0201);
    pub const ECDSA_WITH_SHA1: Self = Self(0x0203);
    pub const PKCS1_WITH_SHA256: Self = Self(0x0401);
    pub const ECDSA_WITH_P256_AND_SHA256: Self = Self(0x0403);
    pub const PKCS1_WITH_SHA384: Self = Self(0x0501);
    pub const ECDSA_WITH_P384_AND_SHA384: Self = Self(0x0503);
    pub const PKCS1_WITH_SHA512: Self = Self(0x0601);
    pub const ECDSA_WITH_P521_AND_SHA512: Self = Self(0x0603);
    pub const PSS_WITH_SHA256: Self = Self(0x0804);
    pub const PSS_WITH_SHA384: Self = Self(0x0805);
    pub const PSS_WITH_SHA512: Self = Self(0x0806);
    pub const ED25519: Self = Self(0x0807);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientAuthType(pub i32);

impl ClientAuthType {
    pub const NO_CLIENT_CERT: Self = Self(0);
    pub const REQUEST_CLIENT_CERT: Self = Self(1);
    pub const REQUIRE_ANY_CLIENT_CERT: Self = Self(2);
    pub const VERIFY_CLIENT_CERT_IF_GIVEN: Self = Self(3);
    pub const REQUIRE_AND_VERIFY_CLIENT_CERT: Self = Self(4);
}

impl Default for ClientAuthType {
    fn default() -> Self {
        Self::NO_CLIENT_CERT
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenegotiationSupport(pub i32);

impl RenegotiationSupport {
    pub const RENEGOTIATE_NEVER: Self = Self(0);
    pub const RENEGOTIATE_ONCE_AS_CLIENT: Self = Self(1);
    pub const RENEGOTIATE_FREELY_AS_CLIENT: Self = Self(2);
}

impl Default for RenegotiationSupport {
    fn default() -> Self {
        Self::RENEGOTIATE_NEVER
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClientHelloId {
    pub client: String,
    pub version: String,
    pub seed: Option<PrngSeed>,
    pub weights: Option<Weights>,
}

/// Alias of [`ClientHelloId`].
pub type UClientHelloID = ClientHelloId;

pub type PrngSeed = [u8; PRNG_SEED_LENGTH];

#[must_use]
pub fn new_prng_seed() -> PrngSeed {
    let mut seed = [0u8; PRNG_SEED_LENGTH];
    rand::rng().fill(&mut seed);
    seed
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Weights {
    pub extensions_append_alpn: f64,
    pub tls_vers_max_set_version_tls13: f64,
    pub cipher_suites_remove_random_ciphers: f64,
    pub sig_and_hash_algos_append_ecdsa_with_sha1: f64,
    pub sig_and_hash_algos_append_ecdsa_with_p521_and_sha512: f64,
    pub sig_and_hash_algos_append_pss_with_sha256: f64,
    pub sig_and_hash_algos_append_pss_with_sha384_pss_with_sha512: f64,
    pub curve_i_ds_append_x25519: f64,
    pub curve_i_ds_append_curve_p521: f64,
    pub extensions_append_padding: f64,
    pub extensions_append_status: f64,
    pub extensions_append_sct: f64,
    pub extensions_append_reneg: f64,
    pub extensions_append_ems: f64,
    pub first_key_share_set_curve_p256: f64,
    pub key_share_append_random_groups: f64,
    pub extensions_append_alps: f64,
}

#[must_use]
pub const fn default_weights() -> Weights {
    Weights {
        extensions_append_alpn: 0.7,
        tls_vers_max_set_version_tls13: 0.4,
        cipher_suites_remove_random_ciphers: 0.4,
        sig_and_hash_algos_append_ecdsa_with_sha1: 0.63,
        sig_and_hash_algos_append_ecdsa_with_p521_and_sha512: 0.59,
        sig_and_hash_algos_append_pss_with_sha256: 0.51,
        sig_and_hash_algos_append_pss_with_sha384_pss_with_sha512: 0.9,
        curve_i_ds_append_x25519: 0.71,
        curve_i_ds_append_curve_p521: 0.46,
        extensions_append_padding: 0.62,
        extensions_append_status: 0.74,
        extensions_append_sct: 0.46,
        extensions_append_reneg: 0.75,
        extensions_append_ems: 0.77,
        first_key_share_set_curve_p256: 0.00,
        key_share_append_random_groups: 0.50,
        extensions_append_alps: 0.33,
    }
}

const HELLO_DEFAULT: &str = "Default";
const HELLO_CUSTOM: &str = "Custom";

fn client_hello_id(client: &str, version: &str) -> UClientHelloID {
    UClientHelloID { client: client.to_owned(), version: version.to_owned(), seed: None, weights: None }
}

#[must_use]
pub fn hello_default() -> UClientHelloID {
    client_hello_id(HELLO_DEFAULT, "0")
}

#[must_use]
pub fn hello_custom() -> UClientHelloID {
    client_hello_id(HELLO_CUSTOM, "0")
}

#[must_use]
pub fn hello_randomized() -> UClientHelloID {
    client_hello_id("Randomized", "0")
}

#[must_use]
pub fn hello_randomized_alpn() -> UClientHelloID {
    client_hello_id("Randomized-ALPN", "0")
}

#[must_use]
pub fn hello_randomized_no_alpn() -> UClientHelloID {
    client_hello_id("Randomized-NoALPN", "0")
}

#[must_use]
pub fn hello_firefox_auto() -> UClientHelloID {
    hello_firefox_120()
}

#[must_use]
pub fn hello_firefox_120() -> UClientHelloID {
    client_hello_id("Firefox", "120")
}

#[must_use]
pub fn hello_chrome_auto() -> UClientHelloID {
    hello_chrome_133()
}

#[must_use]
pub fn hello_chrome_100_psk() -> UClientHelloID {
    client_hello_id("Chrome", "100_PSK")
}

#[must_use]
pub fn hello_chrome_106_shuffle() -> UClientHelloID {
    client_hello_id("Chrome", "106")
}

#[must_use]
pub fn hello_chrome_114_padding_psk_shuf() -> UClientHelloID {
    client_hello_id("Chrome", "114_PSK")
}

#[must_use]
pub fn hello_chrome_115_pq() -> UClientHelloID {
    client_hello_id("Chrome", "115_PQ")
}

#[must_use]
pub fn hello_chrome_115_pq_psk() -> UClientHelloID {
    client_hello_id("Chrome", "115_PQ_PSK")
}

#[must_use]
pub fn hello_chrome_120() -> UClientHelloID {
    client_hello_id("Chrome", "120")
}

#[must_use]
pub fn hello_chrome_133() -> UClientHelloID {
    client_hello_id("Chrome", "133")
}

#[must_use]
pub fn hello_ios_auto() -> UClientHelloID {
    hello_ios_14()
}

#[must_use]
pub fn hello_ios_14() -> UClientHelloID {
    client_hello_id("iOS", "14")
}

#[must_use]
pub fn hello_android_11_ok_http() -> UClientHelloID {
    client_hello_id("Android", "11")
}

#[must_use]
pub fn hello_edge_auto() -> UClientHelloID {
    hello_edge_85()
}

#[must_use]
pub fn hello_edge_85() -> UClientHelloID {
    client_hello_id("Edge", "85")
}

#[must_use]
pub fn hello_safari_auto() -> UClientHelloID {
    hello_safari_16_0()
}

#[must_use]
pub fn hello_safari_16_0() -> UClientHelloID {
    client_hello_id("Safari", "16.0")
}

#[must_use]
pub fn hello_360_auto() -> UClientHelloID {
    hello_360_7_5()
}

#[must_use]
pub fn hello_360_7_5() -> UClientHelloID {
    client_hello_id("360Browser", "7.5")
}

#[must_use]
pub fn hello_qq_auto() -> UClientHelloID {
    hello_qq_11_1()
}

#[must_use]
pub fn hello_qq_11_1() -> UClientHelloID {
    client_hello_id("QQBrowser", "11.1")
}

/// A TLS connection over the shared transport state.
pub struct Conn {
    shared: Arc<TlsShared>,
    close_view: TlsCloseView,
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn")
            .field("is_client", &self.shared.is_client)
            .field("server_name", &self.shared.server_name)
            .finish_non_exhaustive()
    }
}

struct TlsShared {
    is_client: bool,
    config: Arc<Config>,
    server_name: String,
    state: Mutex<ConnState>,
    local_addr: Option<std::net::SocketAddr>,
    remote_addr: Option<std::net::SocketAddr>,
    next_protos_override: Mutex<Option<Vec<String>>>,
    write_closed: AtomicBool,
    /// Set once a [`UConn`] has handed the raw transport to its own handshake. The transport stays
    /// reachable through `state` so `close` and the deadline hooks keep working, but a `rustls`
    /// handshake starting now would write a second, foreign `ClientHello` into it.
    fingerprinted: AtomicBool,
    runtime: Mutex<Option<tokio::runtime::Handle>>,
    /// Set when the transport is a [`RecordBoundaryStream`], which is what makes the raw handoff
    /// provable; `None` keeps the engine's own reads unbounded.
    raw_boundary: Option<Arc<RawBoundaryProbe>>,
}

struct TlsCloseView(Arc<TlsShared>);

enum ConnState {
    Raw(Box<dyn Stream>),
    Handshaking(Pin<Box<dyn Future<Output = io::Result<TlsIo>> + Send>>),
    ClosingWrite { io: Box<TlsIo>, wakers: Vec<std::task::Waker>, close_after_write: bool },
    Ready(Box<TlsIo>),
    Failed(String),
    Closed,
}

enum TlsIo {
    Client(tokio_rustls::client::TlsStream<Box<dyn Stream>>),
    Server(tokio_rustls::server::TlsStream<Box<dyn Stream>>),
}

impl TlsIo {
    fn poll_read_io(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Client(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Server(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }

    fn poll_write_io(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self {
            Self::Client(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Server(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Client(stream) => Pin::new(stream).poll_flush(cx),
            Self::Server(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Client(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Server(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }

    fn inner_mut(&mut self) -> &mut Box<dyn Stream> {
        match self {
            Self::Client(stream) => stream.get_mut().0,
            Self::Server(stream) => stream.get_mut().0,
        }
    }

    /// Moves the decrypted-but-undelivered plaintext out of the engine, so an XTLS direct-mode
    /// read can serve it before the raw transport's bytes.
    fn take_plaintext(&mut self) -> Vec<u8> {
        match self {
            Self::Client(stream) => drain_plaintext(&mut **stream.get_mut().1),
            Self::Server(stream) => drain_plaintext(&mut **stream.get_mut().1),
        }
    }

    fn common_state(&self) -> CommonStateRef<'_> {
        match self {
            Self::Client(stream) => CommonStateRef {
                common: stream.get_ref().1,
                ech_accepted: stream.get_ref().1.ech_status() == rustls::client::EchStatus::Accepted,
            },
            Self::Server(stream) => CommonStateRef { common: stream.get_ref().1, ech_accepted: false },
        }
    }

    fn export_keying_material(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        let output = match self {
            Self::Client(stream) => {
                stream.get_ref().1.export_keying_material(vec![0u8; length], label.as_bytes(), Some(context))
            }
            Self::Server(stream) => {
                stream.get_ref().1.export_keying_material(vec![0u8; length], label.as_bytes(), Some(context))
            }
        }
        .map_err(|err| anyhow!("tls: export keying material failed: {err}"))?;
        Ok(output)
    }
}

fn drain_plaintext<SD: rustls::SideData>(conn: &mut rustls::ConnectionCommon<SD>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut reader = conn.reader();
    loop {
        let length = {
            let Ok(chunk) = io::BufRead::fill_buf(&mut reader) else { break };
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(chunk);
            chunk.len()
        };
        io::BufRead::consume(&mut reader, length);
    }
    out
}

impl TlsShared {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.local_addr.ok_or_else(|| io::Error::other("tls: no local address"))
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.remote_addr.ok_or_else(|| io::Error::other("tls: no remote address"))
    }

    fn poll_write_shutdown(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.state.lock();
        let ConnState::ClosingWrite { io, .. } = &mut *state else {
            return Poll::Ready(Ok(()));
        };
        let Poll::Ready(result) = io.poll_shutdown_io(cx) else {
            return Poll::Pending;
        };
        let ConnState::ClosingWrite { mut io, wakers, close_after_write } =
            std::mem::replace(&mut *state, ConnState::Closed)
        else {
            return Poll::Ready(Err(io::Error::other("tls: write shutdown state changed")));
        };
        if close_after_write || result.is_err() {
            let _ = close_stream(&**io.inner_mut());
        }
        if !close_after_write {
            match &result {
                Ok(()) => *state = ConnState::Ready(io),
                Err(err) => *state = ConnState::Failed(err.to_string()),
            }
        }
        drop(state);
        for waker in wakers {
            waker.wake();
        }
        Poll::Ready(result)
    }
}

/// The record boundary a [`RecordBoundaryStream`] shares with the [`Conn`] it feeds. Direct mode
/// may only take the transport over when this reads true: a byte read for the following record
/// would otherwise be lost to the raw stream.
struct RawBoundaryProbe {
    at_boundary: AtomicBool,
}

impl RawBoundaryProbe {
    const fn new() -> Self {
        Self { at_boundary: AtomicBool::new(true) }
    }

    fn enter_record(&self) {
        self.at_boundary.store(false, Ordering::Release);
    }

    fn leave_record(&self) {
        self.at_boundary.store(true, Ordering::Release);
    }

    fn at_boundary(&self) -> bool {
        self.at_boundary.load(Ordering::Acquire)
    }
}

const RECORD_HEADER_LEN: usize = 5;

/// Feeds the engine above it exactly one TLS record at a time.
///
/// `tokio-rustls`' `poll_read` keeps filling its plaintext buffer while the caller's buffer has
/// room, so on its own it would read the transport past the record carrying the peer's DIRECT
/// frame and swallow the raw bytes that follow. This reader bounds every read to the record in
/// flight and, after a complete record, returns `Pending` for exactly one poll (self-waking, so
/// the caller is not parked) before starting the next one.
struct RecordBoundaryStream {
    inner: Box<dyn Stream>,
    probe: Arc<RawBoundaryProbe>,
    header: [u8; RECORD_HEADER_LEN],
    header_filled: usize,
    header_delivered: usize,
    body_remaining: usize,
    pause_next: bool,
}

impl RecordBoundaryStream {
    /// Reads until the record header is complete; `false` is a clean EOF before any record byte.
    fn read_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        while self.header_filled < RECORD_HEADER_LEN {
            let (_, pending) = self.header.split_at_mut(self.header_filled);
            let mut read_buf = ReadBuf::new(pending);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        if self.header_filled == 0 {
                            return Poll::Ready(Ok(false));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "tls: transport ended inside a record header",
                        )));
                    }
                    self.header_filled += n;
                    self.probe.enter_record();
                }
            }
        }
        Poll::Ready(Ok(true))
    }

    fn finish_record(&mut self) {
        self.header_filled = 0;
        self.header_delivered = 0;
        self.body_remaining = 0;
        self.pause_next = true;
        self.probe.leave_record();
    }
}

impl AsyncRead for RecordBoundaryStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.pause_next {
                this.pause_next = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if this.header_delivered < RECORD_HEADER_LEN {
                match this.read_header(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                    Poll::Ready(Ok(true)) => {}
                }
                let n = (RECORD_HEADER_LEN - this.header_delivered).min(buf.remaining());
                let (_, pending) = this.header.split_at(this.header_delivered);
                let (head, _) = pending.split_at(n);
                buf.put_slice(head);
                this.header_delivered += n;
                if this.header_delivered == RECORD_HEADER_LEN {
                    this.body_remaining = usize::from(u16::from_be_bytes([this.header[3], this.header[4]]));
                }
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }
            if this.body_remaining > 0 {
                let n = this.body_remaining.min(buf.remaining());
                let filled = {
                    let (head, _) = buf.initialize_unfilled().split_at_mut(n);
                    let mut read_buf = ReadBuf::new(head);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Ready(Ok(())) => read_buf.filled().len(),
                    }
                };
                if filled == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tls: transport ended inside a record body",
                    )));
                }
                buf.advance(filled);
                this.body_remaining -= filled;
                if this.body_remaining == 0 {
                    this.finish_record();
                }
                return Poll::Ready(Ok(()));
            }
            this.finish_record();
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for RecordBoundaryStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for RecordBoundaryStream {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.inner.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.inner.as_socket()
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        self.inner.old_conn()
    }
}

struct CommonStateRef<'a> {
    common: &'a rustls::CommonState,
    ech_accepted: bool,
}

impl Conn {
    fn new(
        is_client: bool,
        config: Arc<Config>,
        server_name: String,
        inner: Box<dyn Stream>,
        next_protos_override: Option<Vec<String>>,
    ) -> Self {
        Self::new_inner(is_client, config, server_name, inner, next_protos_override, None)
    }

    fn new_inner(
        is_client: bool,
        config: Arc<Config>,
        server_name: String,
        inner: Box<dyn Stream>,
        next_protos_override: Option<Vec<String>>,
        raw_boundary: Option<Arc<RawBoundaryProbe>>,
    ) -> Self {
        let local_addr = inner.local_addr().ok();
        let remote_addr = inner.peer_addr().ok();
        let shared = Arc::new(TlsShared {
            is_client,
            config,
            server_name,
            state: Mutex::new(ConnState::Raw(inner)),
            local_addr,
            remote_addr,
            next_protos_override: Mutex::new(next_protos_override),
            write_closed: AtomicBool::new(false),
            fingerprinted: AtomicBool::new(false),
            runtime: Mutex::new(tokio::runtime::Handle::try_current().ok()),
            raw_boundary,
        });
        Self { close_view: TlsCloseView(Arc::clone(&shared)), shared }
    }

    /// The plaintext the engine has decrypted but not delivered, taken when XTLS direct mode
    /// switches the read direction. `None` refuses the switch: the transport is not at a record
    /// boundary, so taking it over would strand ciphertext.
    #[must_use]
    pub fn take_buffered_incoming(&self) -> Option<Vec<u8>> {
        let probe = self.shared.raw_boundary.as_ref()?;
        if !probe.at_boundary() {
            return None;
        }
        let mut state = self.shared.state.lock();
        match &mut *state {
            ConnState::Ready(io) | ConnState::ClosingWrite { io, .. } => Some(io.take_plaintext()),
            ConnState::Raw(_) | ConnState::Handshaking(_) | ConnState::Failed(_) | ConnState::Closed => None,
        }
    }

    // cancel-safe: polls `self`'s own state machine through `poll_fn`, so dropping the future only stops polling and the handshake resumes where it left off on the next call.
    pub async fn handshake(&self) -> Result<()> {
        std::future::poll_fn(|cx| self.poll_handshake(cx)).await.map_err(|err| anyhow!("{err}"))
    }

    pub async fn handshake_context(&self, ctx: &CancellationToken) -> Result<()> {
        tokio::select! {
            result = self.handshake() => result,
            () = ctx.cancelled() => Err(anyhow!("context canceled")),
        }
    }

    fn poll_handshake(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared.state.lock();
        match &mut *state {
            ConnState::Ready(_) | ConnState::Closed => return Poll::Ready(Ok(())),
            ConnState::Failed(message) => {
                return Poll::Ready(Err(io::Error::other(message.clone())));
            }
            ConnState::Raw(_) => {
                let ConnState::Raw(raw) = std::mem::replace(&mut *state, ConnState::Closed) else {
                    return Poll::Ready(Err(io::Error::other("tls: connection state changed during handshake")));
                };
                let future = match self.new_handshake_future(raw) {
                    Ok(future) => future,
                    Err(err) => {
                        let message = err.to_string();
                        *state = ConnState::Failed(message.clone());
                        return Poll::Ready(Err(io::Error::other(message)));
                    }
                };
                *state = ConnState::Handshaking(future);
            }
            ConnState::Handshaking(_) | ConnState::ClosingWrite { .. } => {}
        }
        if let ConnState::ClosingWrite { wakers, .. } = &mut *state {
            if !wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
                wakers.push(cx.waker().clone());
            }
            return Poll::Pending;
        }
        let ConnState::Handshaking(future) = &mut *state else {
            return Poll::Ready(Err(io::Error::other("tls: handshake is not complete")));
        };
        let poll_result = future.as_mut().poll(cx);
        let result = match poll_result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                let message = err.to_string();
                *state = ConnState::Failed(message.clone());
                Poll::Ready(Err(io::Error::other(message)))
            }
            Poll::Ready(Ok(io)) => match self.finish_handshake(&io) {
                Ok(()) => {
                    *state = ConnState::Ready(Box::new(io));
                    Poll::Ready(Ok(()))
                }
                Err(err) => {
                    let message = err.to_string();
                    *state = ConnState::Failed(message.clone());
                    Poll::Ready(Err(io::Error::other(message)))
                }
            },
        };
        drop(state);
        result
    }

    fn new_handshake_future(
        &self,
        raw: Box<dyn Stream>,
    ) -> Result<Pin<Box<dyn Future<Output = io::Result<TlsIo>> + Send>>> {
        if self.shared.fingerprinted.load(Ordering::Acquire) {
            return Err(anyhow!("tls: the fingerprinted handshake already owns this connection"));
        }
        let mut runtime = self.shared.runtime.lock();
        if runtime.is_none() {
            *runtime = tokio::runtime::Handle::try_current().ok();
        }
        drop(runtime);
        if self.shared.is_client {
            let tls_config = self.client_rustls_config()?;
            let server_name = if self.shared.server_name.is_empty() {
                server_name_of(&self.shared.config)?
            } else {
                ServerName::try_from(self.shared.server_name.clone())
                    .map_err(|err| anyhow!("tls: invalid server name {:?}: {err}", self.shared.server_name))?
            };
            let connect = tokio_rustls::TlsConnector::from(tls_config).connect(server_name, raw);
            return Ok(Box::pin(async move { Ok(TlsIo::Client(connect.await?)) }));
        }
        let tls_config = self.server_rustls_config()?;
        let accept = tokio_rustls::TlsAcceptor::from(tls_config).accept(raw);
        Ok(Box::pin(async move { Ok(TlsIo::Server(accept.await?)) }))
    }

    fn finish_handshake(&self, io: &TlsIo) -> Result<()> {
        let state = self.state_from_io(io);
        if let Some(verify_peer_certificate) = &self.shared.config.verify_peer_certificate {
            let raw_certificates: Vec<Vec<u8>> = state.peer_certificates.iter().map(|cert| cert.raw.clone()).collect();
            verify_peer_certificate(&raw_certificates, &state.verified_chains)?;
        }
        if let Some(verify_connection) = &self.shared.config.verify_connection {
            verify_connection(&state)?;
        }
        Ok(())
    }

    fn state_from_io(&self, io: &TlsIo) -> ConnectionState {
        let CommonStateRef { common, ech_accepted } = io.common_state();
        let peer_certificates: Vec<Arc<X509Certificate>> = common
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .filter_map(|cert| X509Certificate::parse(cert.as_ref()).ok().map(Arc::new))
            .collect();
        let curve_id =
            common.negotiated_key_exchange_group().map_or(CurveId(0), |group| curve_id_of_name(group.name()));
        ConnectionState {
            version: common.protocol_version().map_or(0, u16::from),
            handshake_complete: !common.is_handshaking(),
            did_resume: common.handshake_kind() == Some(rustls::HandshakeKind::Resumed),
            cipher_suite: common.negotiated_cipher_suite().map_or(0, |suite| u16::from(suite.suite())),
            negotiated_protocol: common
                .alpn_protocol()
                .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
                .unwrap_or_default(),
            negotiated_protocol_is_mutual: true,
            server_name: self.shared.server_name.clone(),
            peer_certificates,
            verified_chains: Vec::new(),
            signed_certificate_timestamps: Vec::new(),
            ocsp_response: Vec::new(),
            tls_unique: Vec::new(),
            ech_accepted,
            testing_only_curve_id: curve_id,
        }
    }

    #[must_use]
    pub fn connection_state(&self) -> ConnectionState {
        let state = self.shared.state.lock();
        match &*state {
            ConnState::Ready(io) | ConnState::ClosingWrite { io, .. } => self.state_from_io(io),
            ConnState::Raw(_) | ConnState::Handshaking(_) | ConnState::Failed(_) | ConnState::Closed => {
                ConnectionState::default()
            }
        }
    }

    #[must_use]
    pub fn session_capability(&self) -> Option<TlsSessionCapability> {
        let state = self.shared.state.lock();
        match &*state {
            ConnState::Ready(io) | ConnState::ClosingWrite { io, .. } => {
                let CommonStateRef { common, .. } = io.common_state();
                Some(TlsSessionCapability {
                    handshake_complete: !common.is_handshaking(),
                    version: common.protocol_version().map_or(0, u16::from),
                    cipher_suite: common.negotiated_cipher_suite().map_or(0, |suite| u16::from(suite.suite())),
                })
            }
            ConnState::Raw(_) | ConnState::Handshaking(_) | ConnState::Failed(_) | ConnState::Closed => None,
        }
    }

    pub fn verify_hostname(&self, host: &str) -> Result<()> {
        let state = self.connection_state();
        match state.peer_certificates.first() {
            Some(cert) => {
                let options = VerifyOptions {
                    dns_name: host.to_owned(),
                    intermediates: CertPool::from_certificates(state.peer_certificates.iter().skip(1).cloned()),
                    roots: self.shared.config.root_cas.clone(),
                    current_time: self.shared.config.time_now(),
                };
                cert.verify(&options)?;
                Ok(())
            }
            None => Err(anyhow!("tls: no certificate available")),
        }
    }

    pub fn export_keying_material(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        let state = self.shared.state.lock();
        match &*state {
            ConnState::Ready(io) | ConnState::ClosingWrite { io, .. } => {
                io.export_keying_material(label, context, length)
            }
            ConnState::Raw(_) | ConnState::Handshaking(_) | ConnState::Failed(_) | ConnState::Closed => {
                Err(anyhow!("tls: handshake is not complete"))
            }
        }
    }

    fn client_rustls_config(&self) -> Result<Arc<rustls::ClientConfig>> {
        let mut tls_config = client_rustls_config(&self.shared.config)?;
        if let Some(next_protos) = self.shared.next_protos_override.lock().as_ref() {
            tls_config.alpn_protocols = encode_protocols(next_protos);
        }
        Ok(Arc::new(tls_config))
    }

    fn server_rustls_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        server_rustls_config(&self.shared.config).map(Arc::new)
    }
}

/// Builds a `rustls::ClientConfig` from a [`Config`].
///
/// For callers that run the handshake through a TLS engine they do not own: `quinn`/`h3-quinn`
/// terminate the handshake themselves and can only be handed a `rustls` config, so the
/// fingerprinted [`Conn`] path above does not reach them. Nothing may be dropped here — the
/// certificate verifier, the TLS 1.2 crypto provider, client authentication, resumption and the
/// key log all carry security meaning.
pub fn client_rustls_config(config: &Config) -> Result<rustls::ClientConfig> {
    let provider = build_provider(config);
    let versions = protocol_versions(config.min_version, config.max_version)?;
    let builder =
        rustls::ClientConfig::builder_with_provider(Arc::clone(&provider)).with_protocol_versions(&versions)?;
    let verifier = Arc::new(ConfigServerCertVerifier::new(
        config.insecure_skip_verify,
        config.root_cas.clone(),
        Arc::clone(&provider),
    )?);
    let builder = builder.dangerous().with_custom_certificate_verifier(verifier);
    let builder = if let Some(resolver) = &config.get_client_certificate {
        builder.with_client_cert_resolver(Arc::new(ConfigClientCertResolver {
            get_client_certificate: Some(Arc::clone(resolver)),
            certificates: config.certificates.clone(),
            provider: Arc::clone(&provider),
        }))
    } else if let Some(certificate) = config.certificates.first() {
        match certificate.client_auth_pair(&provider)? {
            Some((chain, key)) => builder.with_client_auth_cert(chain, key)?,
            None => builder.with_no_client_auth(),
        }
    } else {
        builder.with_no_client_auth()
    };
    let mut tls_config = builder;
    tls_config.alpn_protocols = encode_protocols(&config.next_protos);
    tls_config.enable_sni = !config.server_name.is_empty();
    if config.session_tickets_disabled {
        tls_config.resumption = rustls::client::Resumption::disabled();
    }
    if let Some(writer) = &config.key_log_writer {
        tls_config.key_log = Arc::new(ConfigKeyLog { writer: Arc::clone(writer) });
    }
    Ok(tls_config)
}

/// Builds a `rustls::ServerConfig` from a [`Config`].
///
/// `rustls` serves the trusttunnel h3 listener directly (it has no fingerprinting to apply to
/// a server), which must not silently drop the parts of the config that carry security meaning:
/// client-certificate authentication and the certificate-selection hook.
pub fn server_rustls_config(config: &Config) -> Result<rustls::ServerConfig> {
    let provider = build_provider(config);
    let versions = protocol_versions(config.min_version, config.max_version)?;
    let builder =
        rustls::ServerConfig::builder_with_provider(Arc::clone(&provider)).with_protocol_versions(&versions)?;
    let builder = match config.client_auth {
        ClientAuthType::NO_CLIENT_CERT => builder.with_no_client_auth(),
        ClientAuthType::REQUEST_CLIENT_CERT | ClientAuthType::REQUIRE_ANY_CLIENT_CERT => {
            let verifier = client_cert_verifier(config, &provider).allow_unauthenticated().build()?;
            builder.with_client_cert_verifier(verifier)
        }
        _ => {
            let verifier = client_cert_verifier(config, &provider).build()?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let resolver = Arc::new(ConfigCertResolver {
        get_certificate: config.get_certificate.clone(),
        certificates: config.certificates.clone(),
        provider,
    });
    let mut tls_config = builder.with_cert_resolver(resolver);
    if config.session_tickets_disabled {
        tls_config.send_tls13_tickets = 0;
    }
    tls_config.alpn_protocols = encode_protocols(&config.next_protos);
    if let Some(writer) = &config.key_log_writer {
        tls_config.key_log = Arc::new(ConfigKeyLog { writer: Arc::clone(writer) });
    }
    Ok(tls_config)
}

fn client_cert_verifier(config: &Config, provider: &Arc<CryptoProvider>) -> rustls::server::ClientCertVerifierBuilder {
    let roots = match &config.client_cas {
        Some(roots) => Arc::clone(roots),
        None => Arc::new(system_root_store()),
    };
    WebPkiClientVerifier::builder_with_provider(roots, Arc::clone(provider))
}

fn encode_protocols(protocols: &[String]) -> Vec<Vec<u8>> {
    protocols.iter().map(|protocol| protocol.as_bytes().to_vec()).collect()
}

fn protocol_versions(min_version: u16, max_version: u16) -> Result<Vec<&'static rustls::SupportedProtocolVersion>> {
    let min = if min_version == 0 { VERSION_TLS12 } else { min_version };
    let max = if max_version == 0 { VERSION_TLS13 } else { max_version };
    if min > max {
        return Err(anyhow!("tls: MinVersion must be <= MaxVersion"));
    }
    let mut versions = Vec::with_capacity(2);
    if max >= VERSION_TLS13 && min <= VERSION_TLS13 {
        versions.push(&rustls::version::TLS13);
    }
    if max > VERSION_TLS13 || (max >= VERSION_TLS12 && min <= VERSION_TLS12) {
        versions.push(&rustls::version::TLS12);
    }
    if versions.is_empty() {
        return Err(anyhow!("tls: no supported versions satisfy MinVersion and MaxVersion"));
    }
    Ok(versions)
}

/// An unset `max_version` means TLS 1.3, so it must be read the same way
/// before the fingerprinted handshake decides whether it can run at all.
pub(crate) fn effective_max_version(config: &Config) -> u16 {
    if config.max_version == 0 {
        VERSION_TLS13
    } else {
        config.max_version
    }
}

/// Server-name resolution shared by the `rustls` client and the fingerprinted one.
pub(crate) fn server_name_of(config: &Config) -> Result<ServerName<'static>> {
    if config.server_name.is_empty() {
        if !config.insecure_skip_verify {
            return Err(anyhow!("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config"));
        }
        return Ok(ServerName::from(std::net::Ipv4Addr::LOCALHOST));
    }
    ServerName::try_from(config.server_name.clone())
        .map_err(|err| anyhow!("tls: invalid server name {:?}: {err}", config.server_name))
}

/// Server-certificate verification, reused by the fingerprinted handshake so both paths honour
/// `insecure_skip_verify` and `root_cas` identically.
pub(crate) fn verify_server_certificate(
    config: &Config,
    provider: &Arc<CryptoProvider>,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Result<()> {
    let verifier =
        ConfigServerCertVerifier::new(config.insecure_skip_verify, config.root_cas.clone(), Arc::clone(provider))?;
    verifier.verify_server_cert(
        end_entity,
        intermediates,
        &server_name_of(config)?,
        &[],
        unix_time_of(config.time_now()),
    )?;
    Ok(())
}

fn crypto_provider() -> Arc<CryptoProvider> {
    match CryptoProvider::get_default() {
        Some(provider) => Arc::clone(provider),
        None => Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    }
}

#[must_use]
pub fn build_provider(config: &Config) -> Arc<CryptoProvider> {
    let mut provider = super::tls12_sequence_nonce::tls12_sequence_nonce_provider();
    if let Some(cipher_suites) = &config.cipher_suites {
        if !cipher_suites.is_empty() {
            provider.cipher_suites.retain(|suite| {
                matches!(suite, rustls::SupportedCipherSuite::Tls13(_))
                    || cipher_suites.contains(&u16::from(suite.suite()))
            });
        }
    }
    if let Some(curve_preferences) = &config.curve_preferences {
        if !curve_preferences.is_empty() {
            let wanted: Vec<NamedGroup> =
                curve_preferences.iter().filter_map(|curve| named_group_of_curve(*curve)).collect();
            let filtered: Vec<&'static dyn rustls::crypto::SupportedKxGroup> =
                provider.kx_groups.iter().filter(|group| wanted.contains(&group.name())).copied().collect();
            if !filtered.is_empty() {
                provider.kx_groups = filtered;
            }
        }
    }
    Arc::new(provider)
}

const fn named_group_of_curve(curve: CurveId) -> Option<NamedGroup> {
    match curve {
        CurveId::CURVE_P256 => Some(NamedGroup::secp256r1),
        CurveId::CURVE_P384 => Some(NamedGroup::secp384r1),
        CurveId::CURVE_P521 => Some(NamedGroup::secp521r1),
        CurveId::X25519 => Some(NamedGroup::X25519),
        CurveId::X25519_MLKEM768 => Some(NamedGroup::X25519MLKEM768),
        _ => None,
    }
}

const fn curve_id_of_name(group: NamedGroup) -> CurveId {
    match group {
        NamedGroup::secp256r1 => CurveId::CURVE_P256,
        NamedGroup::secp384r1 => CurveId::CURVE_P384,
        NamedGroup::secp521r1 => CurveId::CURVE_P521,
        NamedGroup::X25519 => CurveId::X25519,
        NamedGroup::X25519MLKEM768 => CurveId::X25519_MLKEM768,
        NamedGroup::X448
        | NamedGroup::FFDHE2048
        | NamedGroup::FFDHE3072
        | NamedGroup::FFDHE4096
        | NamedGroup::FFDHE6144
        | NamedGroup::FFDHE8192
        | NamedGroup::MLKEM512
        | NamedGroup::MLKEM768
        | NamedGroup::MLKEM1024
        | NamedGroup::secp256r1MLKEM768
        | NamedGroup::Unknown(_)
        | _ => CurveId(0),
    }
}

fn system_root_store() -> RootCertStore {
    let mut store = RootCertStore::empty();
    let result = rustls_native_certs::load_native_certs();
    store.add_parsable_certificates(result.certs);
    store
}

struct ConfigKeyLog {
    writer: Arc<Mutex<dyn io::Write + Send + Sync>>,
}

impl fmt::Debug for ConfigKeyLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigKeyLog").finish()
    }
}

impl rustls::KeyLog for ConfigKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let _ = writeln!(self.writer.lock(), "{label} {} {}", hex::encode(client_random), hex::encode(secret));
    }
}

#[derive(Debug)]
struct ConfigServerCertVerifier {
    insecure_skip_verify: bool,
    inner: Arc<WebPkiServerVerifier>,
}

impl ConfigServerCertVerifier {
    fn new(
        insecure_skip_verify: bool,
        root_cas: Option<Arc<RootCertStore>>,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self> {
        let roots = match root_cas {
            Some(roots) => roots,
            None => Arc::new(system_root_store()),
        };
        let inner = WebPkiServerVerifier::builder_with_provider(roots, provider).build()?;
        Ok(Self { insecure_skip_verify, inner })
    }
}

impl ServerCertVerifier for ConfigServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.insecure_skip_verify {
            return Ok(ServerCertVerified::assertion());
        }
        self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

struct ConfigCertResolver {
    get_certificate: Option<GetCertificateFn>,
    certificates: Vec<Certificate>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for ConfigCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigCertResolver")
            .field("get_certificate", &self.get_certificate.is_some())
            .field("certificates", &self.certificates.len())
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for ConfigCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let certificate = match &self.get_certificate {
            Some(get_certificate) => {
                let info = ClientHelloInfo {
                    cipher_suites: client_hello.cipher_suites().iter().map(|suite| u16::from(*suite)).collect(),
                    server_name: client_hello.server_name().unwrap_or_default().to_owned(),
                    supported_curves: Vec::new(),
                    supported_points: Vec::new(),
                    signature_schemes: client_hello
                        .signature_schemes()
                        .iter()
                        .map(|scheme| SignatureScheme(u16::from(*scheme)))
                        .collect(),
                    supported_protos: client_hello
                        .alpn()
                        .map(|protocols| {
                            protocols.map(|protocol| String::from_utf8_lossy(protocol).into_owned()).collect()
                        })
                        .unwrap_or_default(),
                    supported_versions: Vec::new(),
                    extensions: Vec::new(),
                };
                get_certificate(&info).ok().flatten()
            }
            None => self.certificates.first().cloned(),
        };
        certificate?.to_certified_key(&self.provider).ok()
    }
}

struct ConfigClientCertResolver {
    get_client_certificate: Option<GetClientCertificateFn>,
    certificates: Vec<Certificate>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for ConfigClientCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigClientCertResolver")
            .field("certificates", &self.certificates.len())
            .finish_non_exhaustive()
    }
}

impl rustls::client::ResolvesClientCert for ConfigClientCertResolver {
    fn resolve(
        &self,
        acceptable_issuers: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let info = CertificateRequestInfo {
            acceptable_cas: acceptable_issuers.iter().map(|ca| ca.to_vec()).collect(),
            signature_schemes: sigschemes.iter().map(|scheme| SignatureScheme(u16::from(*scheme))).collect(),
            version: 0,
        };
        let certificate = match &self.get_client_certificate {
            Some(get_client_certificate) => (get_client_certificate)(&info).ok().flatten(),
            None => self.certificates.first().cloned(),
        };
        certificate?.to_certified_key(&self.provider).ok()
    }

    fn has_certs(&self) -> bool {
        !self.certificates.is_empty() || self.get_client_certificate.is_some()
    }
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        {
            let mut state = this.shared.state.lock();
            match &mut *state {
                ConnState::ClosingWrite { io, close_after_write: false, .. } => return io.poll_read_io(cx, buf),
                ConnState::ClosingWrite { close_after_write: true, .. } => return Poll::Ready(Ok(())),
                ConnState::Raw(_)
                | ConnState::Handshaking(_)
                | ConnState::Ready(_)
                | ConnState::Failed(_)
                | ConnState::Closed => {}
            }
        }
        match this.poll_handshake(cx) {
            Poll::Pending => {
                return Poll::Pending;
            }
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        }
        let mut state = this.shared.state.lock();
        match &mut *state {
            ConnState::Ready(io) | ConnState::ClosingWrite { io, close_after_write: false, .. } => {
                io.poll_read_io(cx, buf)
            }
            ConnState::Closed | ConnState::ClosingWrite { close_after_write: true, .. } => Poll::Ready(Ok(())),
            ConnState::Failed(message) => Poll::Ready(Err(io::Error::other(message.clone()))),
            ConnState::Raw(_) | ConnState::Handshaking(_) => {
                Poll::Ready(Err(io::Error::other("tls: handshake is not complete")))
            }
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shared.write_closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::other("tls: write half is closed")));
        }
        match this.poll_handshake(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        }
        let mut state = this.shared.state.lock();
        if this.shared.write_closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::other("tls: write half is closed")));
        }
        match &mut *state {
            ConnState::Ready(io) => io.poll_write_io(cx, buf),
            ConnState::Closed => Poll::Ready(Err(io::Error::other("tls: conn is closed"))),
            ConnState::Failed(message) => Poll::Ready(Err(io::Error::other(message.clone()))),
            ConnState::Raw(_) | ConnState::Handshaking(_) | ConnState::ClosingWrite { .. } => {
                Poll::Ready(Err(io::Error::other("tls: handshake is not complete")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_handshake(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        }
        let mut state = this.shared.state.lock();
        match &mut *state {
            ConnState::Ready(io) => io.poll_flush_io(cx),
            ConnState::Closed => Poll::Ready(Ok(())),
            ConnState::Failed(message) => Poll::Ready(Err(io::Error::other(message.clone()))),
            ConnState::Raw(_) | ConnState::Handshaking(_) | ConnState::ClosingWrite { .. } => {
                Poll::Ready(Err(io::Error::other("tls: handshake is not complete")))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(&*this.shared.state.lock(), ConnState::ClosingWrite { .. }) {
            match this.poll_handshake(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if this.shared.write_closed.load(Ordering::Acquire) {
            if let ConnState::Failed(message) = &*this.shared.state.lock() {
                return Poll::Ready(Err(io::Error::other(message.clone())));
            }
            return Poll::Ready(Ok(()));
        }
        let mut state = this.shared.state.lock();
        match &mut *state {
            ConnState::Ready(io) => {
                let result = io.poll_shutdown_io(cx);
                if matches!(result, Poll::Ready(Ok(()))) {
                    this.shared.write_closed.store(true, Ordering::Release);
                }
                result
            }
            ConnState::Closed | ConnState::Raw(_) | ConnState::Handshaking(_) | ConnState::ClosingWrite { .. } => {
                Poll::Ready(Ok(()))
            }
            ConnState::Failed(message) => Poll::Ready(Err(io::Error::other(message.clone()))),
        }
    }
}

impl Conn {
    pub fn close(&self) -> io::Result<()> {
        let handle = tokio::runtime::Handle::try_current().ok().or_else(|| self.shared.runtime.lock().clone());
        let mut state = self.shared.state.lock();
        if handle.is_none() && matches!(&*state, ConnState::Ready(_) | ConnState::ClosingWrite { .. }) {
            return Err(io::Error::other("tls: closing an active session requires a runtime"));
        }
        if let ConnState::ClosingWrite { close_after_write, .. } = &mut *state {
            *close_after_write = true;
            return Ok(());
        }
        let previous = std::mem::replace(&mut *state, ConnState::Closed);
        drop(state);
        match previous {
            ConnState::Raw(raw) => close_stream(&*raw),
            ConnState::Ready(mut io) => {
                // rustls can still hold ciphertext after a successful write; drain before closing the transport.
                let handle =
                    handle.ok_or_else(|| io::Error::other("tls: closing an active session requires a runtime"))?;
                handle.spawn(async move {
                    let _ = std::future::poll_fn(|cx| io.poll_shutdown_io(cx)).await;
                    let _ = close_stream(&**io.inner_mut());
                });
                Ok(())
            }
            ConnState::ClosingWrite { .. } => Err(io::Error::other("tls: closing write state after replacement")),
            ConnState::Handshaking(_) | ConnState::Failed(_) | ConnState::Closed => Ok(()),
        }
    }

    pub fn shutdown_read(&self) -> io::Result<()> {
        let mut state = self.shared.state.lock();
        match &mut *state {
            ConnState::Raw(raw) => raw.shutdown_read(),
            ConnState::Ready(io) | ConnState::ClosingWrite { io, .. } => io.inner_mut().shutdown_read(),
            ConnState::Handshaking(_) | ConnState::Failed(_) | ConnState::Closed => Ok(()),
        }
    }

    pub fn shutdown_write(&self) -> io::Result<()> {
        let mut state = self.shared.state.lock();
        match &mut *state {
            ConnState::Raw(raw) => {
                raw.shutdown_write()?;
                self.shared.write_closed.store(true, Ordering::Release);
                Ok(())
            }
            ConnState::Ready(_) => {
                let handle = tokio::runtime::Handle::try_current()
                    .ok()
                    .or_else(|| self.shared.runtime.lock().clone())
                    .ok_or_else(|| io::Error::other("tls: shutdown_write requires a runtime"))?;
                let ConnState::Ready(io) = std::mem::replace(&mut *state, ConnState::Closed) else {
                    return Err(io::Error::other("tls: ready state changed during shutdown_write"));
                };
                *state = ConnState::ClosingWrite { io, wakers: Vec::new(), close_after_write: false };
                drop(state);
                self.shared.write_closed.store(true, Ordering::Release);
                let shared = Arc::clone(&self.shared);
                handle.spawn(async move {
                    let _ = std::future::poll_fn(|cx| shared.poll_write_shutdown(cx)).await;
                });
                Ok(())
            }
            ConnState::ClosingWrite { .. } | ConnState::Closed | ConnState::Handshaking(_) => Ok(()),
            ConnState::Failed(message) => Err(io::Error::other(message.clone())),
        }
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let mut state = self.shared.state.lock();
        match &mut *state {
            ConnState::Raw(raw) => raw.old_conn().map_or(Ok(()), |conn| conn.set_deadline(deadline)),
            ConnState::Ready(io) | ConnState::ClosingWrite { io, .. } => {
                io.inner_mut().old_conn().map_or(Ok(()), |conn| conn.set_deadline(deadline))
            }
            ConnState::Handshaking(_) | ConnState::Failed(_) | ConnState::Closed => Ok(()),
        }
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let mut state = self.shared.state.lock();
        match &mut *state {
            ConnState::Raw(raw) => raw.old_conn().map_or(Ok(()), |conn| conn.set_read_deadline(deadline)),
            ConnState::Ready(io) | ConnState::ClosingWrite { io, .. } => {
                io.inner_mut().old_conn().map_or(Ok(()), |conn| conn.set_read_deadline(deadline))
            }
            ConnState::Handshaking(_) | ConnState::Failed(_) | ConnState::Closed => Ok(()),
        }
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let mut state = self.shared.state.lock();
        match &mut *state {
            ConnState::Raw(raw) => raw.old_conn().map_or(Ok(()), |conn| conn.set_write_deadline(deadline)),
            ConnState::Ready(io) | ConnState::ClosingWrite { io, .. } => {
                io.inner_mut().old_conn().map_or(Ok(()), |conn| conn.set_write_deadline(deadline))
            }
            ConnState::Handshaking(_) | ConnState::Failed(_) | ConnState::Closed => Ok(()),
        }
    }
}

impl Stream for Conn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.shared.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.shared.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        Self::shutdown_read(self)
    }

    fn shutdown_write(&self) -> io::Result<()> {
        Self::shutdown_write(self)
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(&self.close_view)
    }
}

impl ConcreteConn for Conn {}

impl TlsCloseView {
    fn conn(&self) -> Conn {
        Conn { shared: Arc::clone(&self.0), close_view: Self(Arc::clone(&self.0)) }
    }
}

impl AsyncRead for TlsCloseView {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn()).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsCloseView {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().conn()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn()).poll_shutdown(cx)
    }
}

impl NetConn for TlsCloseView {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr().map(|addr| -> Box<dyn Addr> { Box::new(TcpAddr::new(addr.ip(), addr.port())) })
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.peer_addr().map(|addr| -> Box<dyn Addr> { Box::new(TcpAddr::new(addr.ip(), addr.port())) })
    }

    fn close(&self) -> io::Result<()> {
        self.conn().close()
    }

    fn close_read(&self) -> io::Result<()> {
        self.conn().shutdown_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.conn().shutdown_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn().set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn().set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn().set_write_deadline(deadline)
    }
}

#[derive(Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the field set is fixed by the public API this type mirrors, so the flat bool flags cannot be grouped"
)]
pub struct ConnectionState {
    pub version: u16,
    pub handshake_complete: bool,
    pub did_resume: bool,
    pub cipher_suite: u16,
    pub negotiated_protocol: String,
    pub negotiated_protocol_is_mutual: bool,
    pub server_name: String,
    pub peer_certificates: Vec<Arc<X509Certificate>>,
    pub verified_chains: Vec<Vec<Arc<X509Certificate>>>,
    pub signed_certificate_timestamps: Vec<Vec<u8>>,
    pub ocsp_response: Vec<u8>,
    pub tls_unique: Vec<u8>,
    pub ech_accepted: bool,
    pub testing_only_curve_id: CurveId,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            version: 0,
            handshake_complete: false,
            did_resume: false,
            cipher_suite: 0,
            negotiated_protocol: String::new(),
            negotiated_protocol_is_mutual: false,
            server_name: String::new(),
            peer_certificates: Vec::new(),
            verified_chains: Vec::new(),
            signed_certificate_timestamps: Vec::new(),
            ocsp_response: Vec::new(),
            tls_unique: Vec::new(),
            ech_accepted: false,
            testing_only_curve_id: CurveId(0),
        }
    }
}

impl fmt::Debug for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionState")
            .field("version", &self.version)
            .field("handshake_complete", &self.handshake_complete)
            .field("did_resume", &self.did_resume)
            .field("cipher_suite", &self.cipher_suite)
            .field("negotiated_protocol", &self.negotiated_protocol)
            .field("negotiated_protocol_is_mutual", &self.negotiated_protocol_is_mutual)
            .field("server_name", &self.server_name)
            .field("peer_certificates", &self.peer_certificates.len())
            .field("verified_chains", &self.verified_chains.len())
            .field("signed_certificate_timestamps", &self.signed_certificate_timestamps.len())
            .field("ocsp_response", &self.ocsp_response.len())
            .field("tls_unique", &self.tls_unique.len())
            .field("ech_accepted", &self.ech_accepted)
            .field("testing_only_curve_id", &self.testing_only_curve_id)
            .finish()
    }
}

#[derive(Default)]
pub struct Certificate {
    pub certificate: Vec<Vec<u8>>,
    pub private_key: Option<PrivateKeyDer<'static>>,
    pub supported_signature_algorithms: Option<Vec<SignatureScheme>>,
    pub ocsp_staple: Vec<u8>,
    pub signed_certificate_timestamps: Vec<Vec<u8>>,
    pub leaf: Option<Arc<X509Certificate>>,
}

impl Clone for Certificate {
    fn clone(&self) -> Self {
        Self {
            certificate: self.certificate.clone(),
            private_key: self.private_key.as_ref().map(PrivateKeyDer::clone_key),
            supported_signature_algorithms: self.supported_signature_algorithms.clone(),
            ocsp_staple: self.ocsp_staple.clone(),
            signed_certificate_timestamps: self.signed_certificate_timestamps.clone(),
            leaf: self.leaf.clone(),
        }
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("certificate", &self.certificate.len())
            .field("private_key", &self.private_key.is_some())
            .field("supported_signature_algorithms", &self.supported_signature_algorithms.as_ref().map(Vec::len))
            .field("ocsp_staple", &self.ocsp_staple.len())
            .field("signed_certificate_timestamps", &self.signed_certificate_timestamps.len())
            .field("leaf", &self.leaf)
            .finish()
    }
}

impl Certificate {
    fn chain(&self) -> Vec<CertificateDer<'static>> {
        self.certificate.iter().cloned().map(CertificateDer::from).collect()
    }

    fn client_auth_pair(
        &self,
        provider: &CryptoProvider,
    ) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
        if self.certificate.is_empty() {
            return Ok(None);
        }
        let Some(key) = self.private_key.as_ref().map(PrivateKeyDer::clone_key) else {
            return Ok(None);
        };
        provider.key_provider.load_private_key(key.clone_key())?;
        Ok(Some((self.chain(), key)))
    }

    fn to_certified_key(&self, provider: &CryptoProvider) -> Result<Arc<CertifiedKey>> {
        let chain = self.chain();
        if chain.is_empty() {
            return Err(anyhow!("tls: certificate chain is empty"));
        }
        let private_key = self
            .private_key
            .as_ref()
            .map(PrivateKeyDer::clone_key)
            .ok_or_else(|| anyhow!("tls: certificate has no private key"))?;
        let signing_key = provider.key_provider.load_private_key(private_key)?;
        let mut certified_key = CertifiedKey::new(chain, signing_key);
        if !self.ocsp_staple.is_empty() {
            certified_key.ocsp = Some(self.ocsp_staple.clone());
        }
        Ok(Arc::new(certified_key))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EncryptedClientHelloKey {
    pub config: Vec<u8>,
    pub private_key: Vec<u8>,
    pub send_as_retry: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ClientHelloInfo {
    pub cipher_suites: Vec<u16>,
    pub server_name: String,
    pub supported_curves: Vec<CurveId>,
    pub supported_points: Vec<u8>,
    pub signature_schemes: Vec<SignatureScheme>,
    pub supported_protos: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub extensions: Vec<u16>,
}

#[derive(Clone, Debug, Default)]
pub struct CertificateRequestInfo {
    pub acceptable_cas: Vec<Vec<u8>>,
    pub signature_schemes: Vec<SignatureScheme>,
    pub version: u16,
}

pub type GetCertificateFn = Arc<dyn Fn(&ClientHelloInfo) -> Result<Option<Certificate>> + Send + Sync>;

pub type GetClientCertificateFn = Arc<dyn Fn(&CertificateRequestInfo) -> Result<Option<Certificate>> + Send + Sync>;

pub type VerifyPeerCertificateFn = Arc<dyn Fn(&[Vec<u8>], &[Vec<Arc<X509Certificate>>]) -> Result<()> + Send + Sync>;

pub type VerifyConnectionFn = Arc<dyn Fn(&ConnectionState) -> Result<()> + Send + Sync>;

/// The ECH key lookup hook.
///
/// The fingerprinted handshake and the plain [`Conn`] path share a single [`Config`] type, so the
/// field lives here even though the fingerprinted handshake never carries it forward.
pub type GetEncryptedClientHelloKeysFn =
    Arc<dyn Fn(&ClientHelloInfo) -> Result<Vec<EncryptedClientHelloKey>> + Send + Sync>;

pub type SessionIdGeneratorFn = Arc<dyn Fn(&[u8], &mut [u8]) -> Result<()> + Send + Sync>;

#[derive(Clone)]
pub struct Config {
    pub rand: Option<Arc<Mutex<dyn io::Read + Send + Sync>>>,
    pub time: Option<TimeFn>,
    pub certificates: Vec<Certificate>,
    pub get_certificate: Option<GetCertificateFn>,
    pub get_client_certificate: Option<GetClientCertificateFn>,
    pub verify_peer_certificate: Option<VerifyPeerCertificateFn>,
    pub verify_connection: Option<VerifyConnectionFn>,
    pub root_cas: Option<Arc<RootCertStore>>,
    pub next_protos: Vec<String>,
    pub server_name: String,
    pub client_auth: ClientAuthType,
    pub client_cas: Option<Arc<RootCertStore>>,
    pub insecure_skip_verify: bool,
    pub cipher_suites: Option<Vec<u16>>,
    pub session_tickets_disabled: bool,
    pub min_version: u16,
    pub max_version: u16,
    pub curve_preferences: Option<Vec<CurveId>>,
    pub renegotiation: RenegotiationSupport,
    pub key_log_writer: Option<Arc<Mutex<dyn io::Write + Send + Sync>>>,
    pub encrypted_client_hello_config_list: Vec<u8>,
    pub encrypted_client_hello_rejection_verify: Option<VerifyConnectionFn>,
    pub encrypted_client_hello_keys: Vec<EncryptedClientHelloKey>,
    pub get_encrypted_client_hello_keys: Option<GetEncryptedClientHelloKeysFn>,
    pub session_id_generator: Option<SessionIdGeneratorFn>,
}
impl Default for Config {
    /// Every field at its zero value. Written out rather than derived so that adding a
    /// field to `Config` cannot default silently: this impl stops compiling until the new field is
    /// named here (RUST_GUIDELINES.md section 3, functional-update struct literals).
    fn default() -> Self {
        Self {
            rand: <Option<Arc<Mutex<dyn io::Read + Send + Sync>>> as Default>::default(),
            time: <Option<TimeFn> as Default>::default(),
            certificates: <Vec<Certificate> as Default>::default(),
            get_certificate: <Option<GetCertificateFn> as Default>::default(),
            get_client_certificate: <Option<GetClientCertificateFn> as Default>::default(),
            verify_peer_certificate: <Option<VerifyPeerCertificateFn> as Default>::default(),
            verify_connection: <Option<VerifyConnectionFn> as Default>::default(),
            root_cas: <Option<Arc<RootCertStore>> as Default>::default(),
            next_protos: <Vec<String> as Default>::default(),
            server_name: <String as Default>::default(),
            client_auth: <ClientAuthType as Default>::default(),
            client_cas: <Option<Arc<RootCertStore>> as Default>::default(),
            insecure_skip_verify: <bool as Default>::default(),
            cipher_suites: <Option<Vec<u16>> as Default>::default(),
            session_tickets_disabled: <bool as Default>::default(),
            min_version: <u16 as Default>::default(),
            max_version: <u16 as Default>::default(),
            curve_preferences: <Option<Vec<CurveId>> as Default>::default(),
            renegotiation: <RenegotiationSupport as Default>::default(),
            key_log_writer: <Option<Arc<Mutex<dyn io::Write + Send + Sync>>> as Default>::default(),
            encrypted_client_hello_config_list: <Vec<u8> as Default>::default(),
            encrypted_client_hello_rejection_verify: <Option<VerifyConnectionFn> as Default>::default(),
            encrypted_client_hello_keys: <Vec<EncryptedClientHelloKey> as Default>::default(),
            get_encrypted_client_hello_keys: <Option<GetEncryptedClientHelloKeysFn> as Default>::default(),
            session_id_generator: <Option<SessionIdGeneratorFn> as Default>::default(),
        }
    }
}

pub type TimeFn = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("server_name", &self.server_name)
            .field("next_protos", &self.next_protos)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("min_version", &self.min_version)
            .field("max_version", &self.max_version)
            .field("client_auth", &self.client_auth)
            .field("certificates", &self.certificates.len())
            .finish_non_exhaustive()
    }
}

impl Config {
    /// The current time when `time` is unset.
    #[must_use]
    pub fn time_now(&self) -> DateTime<Utc> {
        match &self.time {
            Some(time) => time(),
            None => Utc::now(),
        }
    }
}

#[must_use]
pub fn client(c: Box<dyn Stream>, config: Arc<Config>) -> Conn {
    let server_name = config.server_name.clone();
    Conn::new(true, config, server_name, c, None)
}

/// [`client`] for a dial that may hand its raw transport to XTLS direct mode: the transport is
/// read one TLS record at a time, so the switch can prove it is at a record boundary.
#[must_use]
pub fn client_with_raw_handoff(c: Box<dyn Stream>, config: Arc<Config>) -> Conn {
    let server_name = config.server_name.clone();
    let boundary = Arc::new(RawBoundaryProbe::new());
    let inner = Box::new(RecordBoundaryStream {
        inner: c,
        probe: Arc::clone(&boundary),
        header: [0; RECORD_HEADER_LEN],
        header_filled: 0,
        header_delivered: 0,
        body_remaining: 0,
        pause_next: false,
    });
    Conn::new_inner(true, config, server_name, inner, None, Some(boundary))
}

#[must_use]
pub fn server(c: Box<dyn Stream>, config: Arc<Config>) -> Conn {
    Conn::new(false, config, String::new(), c, None)
}

pub fn new_listener(inner: Arc<dyn Acceptor>, config: Arc<Config>) -> Box<dyn Acceptor> {
    Box::new(TlsListener { inner, config })
}

struct TlsListener {
    inner: Arc<dyn Acceptor>,
    config: Arc<Config>,
}

#[async_trait::async_trait]
impl Acceptor for TlsListener {
    // cancel-safe: forwards to the wrapped acceptor's `accept` and only boxes the result, so a dropped call leaves the listener exactly as it was.
    async fn accept(&self) -> io::Result<Box<dyn Stream>> {
        let conn = self.inner.accept().await?;
        Ok(Box::new(server(conn, Arc::clone(&self.config))))
    }

    fn close(&self) -> io::Result<()> {
        self.inner.close()
    }

    fn addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.addr()
    }
}

pub struct UConn {
    pub conn: Conn,
    pub extensions: Vec<Box<dyn TlsExtension>>,
    pub client_hello_id: ClientHelloId,
    pub handshake_state: PubClientHandshakeState,
    client_hello_build_status: ClientHelloBuildStatus,
    padding: Option<PaddingPlan>,
    /// `Some` once [`Self::handshake_context`] has driven the fingerprinted handshake. Until
    /// then every read and write still goes to the embedded [`Conn`], so a caller that never
    /// handshakes behaves exactly as before.
    engine: Mutex<Option<Box<UtlsClient>>>,
}

impl fmt::Debug for UConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UConn")
            .field("client_hello_id", &self.client_hello_id)
            .field("handshake_state", &self.handshake_state)
            .field("client_hello_build_status", &self.client_hello_build_status)
            .finish_non_exhaustive()
    }
}

impl UConn {
    pub fn connection_state(&self) -> ConnectionState {
        match &*self.engine.lock() {
            Some(engine) => engine.connection_state(),
            None => self.conn.connection_state(),
        }
    }

    pub fn export_keying_material(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        match &*self.engine.lock() {
            Some(engine) => engine.export_keying_material(label, context, length),
            None => self.conn.export_keying_material(label, context, length),
        }
    }

    #[must_use]
    pub fn session_capability(&self) -> Option<TlsSessionCapability> {
        match &*self.engine.lock() {
            Some(engine) => Some(engine.session_capability()),
            None => self.conn.session_capability(),
        }
    }

    pub fn take_buffered_incoming(&mut self) -> Option<Vec<u8>> {
        let engine = self.engine.get_mut().as_deref_mut()?;
        let at_record_boundary = {
            let state = self.conn.shared.state.lock();
            matches!(&*state, ConnState::Raw(_))
        };
        if !at_record_boundary {
            return None;
        }
        engine.take_buffered_incoming()
    }
}

impl AsyncRead for UConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(engine) = this.engine.get_mut().as_deref_mut() else {
            return Pin::new(&mut this.conn).poll_read(cx, buf);
        };
        let mut state = this.conn.shared.state.lock();
        match &mut *state {
            ConnState::Raw(raw) => engine.poll_read(&mut **raw, cx, buf),
            ConnState::Handshaking(_)
            | ConnState::ClosingWrite { .. }
            | ConnState::Ready(_)
            | ConnState::Failed(_)
            | ConnState::Closed => Poll::Ready(Err(io::Error::other("tls: handshake is not complete"))),
        }
    }
}

impl AsyncWrite for UConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(engine) = this.engine.get_mut().as_deref_mut() else {
            return Pin::new(&mut this.conn).poll_write(cx, buf);
        };
        let mut state = this.conn.shared.state.lock();
        match &mut *state {
            ConnState::Raw(raw) => engine.poll_write(&mut **raw, cx, buf),
            ConnState::Handshaking(_)
            | ConnState::ClosingWrite { .. }
            | ConnState::Ready(_)
            | ConnState::Failed(_)
            | ConnState::Closed => Poll::Ready(Err(io::Error::other("tls: handshake is not complete"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(engine) = this.engine.get_mut().as_deref_mut() else {
            return Pin::new(&mut this.conn).poll_flush(cx);
        };
        let mut state = this.conn.shared.state.lock();
        match &mut *state {
            ConnState::Raw(raw) => engine.poll_flush(&mut **raw, cx),
            ConnState::Handshaking(_)
            | ConnState::ClosingWrite { .. }
            | ConnState::Ready(_)
            | ConnState::Failed(_)
            | ConnState::Closed => Poll::Ready(Err(io::Error::other("tls: handshake is not complete"))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(engine) = this.engine.get_mut().as_deref_mut() else {
            return Pin::new(&mut this.conn).poll_shutdown(cx);
        };
        let mut state = this.conn.shared.state.lock();
        match &mut *state {
            ConnState::Raw(raw) => engine.poll_shutdown(&mut **raw, cx),
            ConnState::Handshaking(_)
            | ConnState::ClosingWrite { .. }
            | ConnState::Ready(_)
            | ConnState::Failed(_)
            | ConnState::Closed => Poll::Ready(Ok(())),
        }
    }
}

impl Stream for UConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }

    /// The TLS `close_notify` is written by the graceful [`AsyncWrite::poll_shutdown`] path; this
    /// hard half-close goes straight to the transport, as it does for a socket that is being torn
    /// down rather than politely ended.
    fn shutdown_write(&self) -> io::Result<()> {
        let mut engine = self.engine.lock();
        if let Some(engine) = engine.as_deref_mut() {
            engine.mark_write_closed();
            let state = self.conn.shared.state.lock();
            return match &*state {
                ConnState::Raw(raw) => raw.shutdown_write(),
                ConnState::Handshaking(_)
                | ConnState::ClosingWrite { .. }
                | ConnState::Ready(_)
                | ConnState::Failed(_)
                | ConnState::Closed => Ok(()),
            };
        }
        drop(engine);
        self.conn.shutdown_write()
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        self.conn.old_conn()
    }
}

impl ConcreteConn for UConn {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientHelloBuildStatus {
    NotBuilt,
    BuildByUtls,
    BuildByDefault,
}

#[derive(Debug, Default)]
pub struct PubClientHandshakeState {
    pub hello: PubClientHelloMsg,
    pub state13: Tls13OnlyState,
}

#[derive(Debug, Default)]
pub struct Tls13OnlyState {
    pub key_share_keys: Option<KeySharePrivateKeys>,
}

/// One entry per offered `key_share`, so the handshake can answer
/// whichever group the server picks.
#[derive(Debug, Default)]
pub struct KeySharePrivateKeys {
    pub shares: Vec<ShareKeys>,
}

/// The private half of one `key_share` entry.
///
/// `ecdhe` is the X25519 scalar; `mlkem` is present only for the X25519MLKEM768 hybrid, whose
/// shared secret is the ML-KEM key followed by the X25519 one. `kx` carries a provider-backed
/// exchange for the groups this module does not hand-roll (the NIST curves), used on retry.
pub struct ShareKeys {
    pub curve_id: CurveId,
    pub ecdhe: Option<StaticSecret>,
    pub mlkem: Option<DecapsulationKey<MlKem768>>,
    pub kx: Option<Box<dyn ActiveKeyExchange>>,
}

impl fmt::Debug for ShareKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareKeys")
            .field("curve_id", &self.curve_id)
            .field("ecdhe", &self.ecdhe.is_some())
            .field("mlkem", &self.mlkem.is_some())
            .field("kx", &self.kx.is_some())
            .finish()
    }
}

impl KeySharePrivateKeys {
    #[must_use]
    pub fn share(&self, curve_id: CurveId) -> Option<&ShareKeys> {
        self.shares.iter().find(|share| share.curve_id == curve_id)
    }

    /// The key exchange for the group the server chose, or an error naming the group when the
    /// `ClientHello` never offered it.
    pub fn complete(&mut self, curve_id: CurveId, peer: &[u8]) -> Result<Vec<u8>> {
        let share = self.shares.iter_mut().find(|share| share.curve_id == curve_id).ok_or_else(|| {
            anyhow!(
                "tls: server chose key share group 0x{:04x}, which this ClientHello did not offer",
                curve_id.as_u16()
            )
        })?;
        if let Some(kx) = share.kx.take() {
            let secret =
                kx.complete(peer).map_err(|err| anyhow!("tls: key share 0x{:04x}: {err}", curve_id.as_u16()))?;
            return Ok(secret.secret_bytes().to_vec());
        }
        let ecdhe = share
            .ecdhe
            .as_ref()
            .ok_or_else(|| anyhow!("tls: key share 0x{:04x} carries no ECDHE scalar", curve_id.as_u16()))?;
        let Some(mlkem) = share.mlkem.as_ref() else {
            return x25519_diffie_hellman(ecdhe, &x25519_public_key(peer)?);
        };
        let (mlkem_share, ecdhe_share) = peer.split_at(peer.len().saturating_sub(X25519_KEY_LEN));
        let mut shared = mlkem
            .decapsulate_slice(mlkem_share)
            .map_err(|_| anyhow!("tls: ML-KEM key share is not a valid ciphertext"))?
            .as_slice()
            .to_vec();
        shared.extend_from_slice(&x25519_diffie_hellman(ecdhe, &x25519_public_key(ecdhe_share)?)?);
        Ok(shared)
    }

    /// Replaces every share with fresh material for `curve_id`, returning the public key bytes to
    /// carry in the retry `ClientHello`. The retry offers only this group, so the first
    /// `ClientHello`'s shares are discarded rather than left for `complete` to answer.
    pub fn new_share_for(&mut self, curve_id: CurveId, provider: &CryptoProvider) -> Result<Vec<u8>> {
        let name = named_group_of_curve(curve_id)
            .ok_or_else(|| anyhow!("tls: no key exchange group 0x{:04x}", curve_id.as_u16()))?;
        let group = provider
            .kx_groups
            .iter()
            .find(|group| group.name() == name)
            .ok_or_else(|| anyhow!("tls: key exchange group 0x{:04x} is not enabled", curve_id.as_u16()))?;
        let kx = group.start().map_err(|err| anyhow!("tls: key exchange group 0x{:04x}: {err}", curve_id.as_u16()))?;
        let public = kx.pub_key().to_vec();
        self.shares.clear();
        self.shares.push(ShareKeys { curve_id, ecdhe: None, mlkem: None, kx: Some(kx) });
        Ok(public)
    }
}

fn x25519_public_key(bytes: &[u8]) -> Result<PublicKey> {
    let bytes: [u8; X25519_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| anyhow!("tls: X25519 key share is {} bytes, want {X25519_KEY_LEN}", bytes.len()))?;
    Ok(PublicKey::from(bytes))
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the field set is fixed by the public API this type mirrors, so the bool flags cannot be grouped"
)]
pub struct PubClientHelloMsg {
    pub raw: Vec<u8>,
    pub vers: u16,
    pub random: Vec<u8>,
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub next_proto_neg: bool,
    pub server_name: String,
    pub ocsp_stapling: bool,
    pub scts: bool,
    pub ems: bool,
    pub supported_curves: Vec<CurveId>,
    pub supported_points: Vec<u8>,
    pub ticket_supported: bool,
    pub session_ticket: Vec<u8>,
    pub supported_signature_algorithms: Vec<SignatureScheme>,
    pub secure_renegotiation: Vec<u8>,
    pub secure_renegotiation_supported: bool,
    pub alpn_protocols: Vec<String>,
    pub supported_signature_algorithms_cert: Vec<SignatureScheme>,
    pub supported_versions: Vec<u16>,
    pub cookie: Vec<u8>,
    pub key_shares: Vec<KeyShare>,
    pub early_data: bool,
    pub psk_modes: Vec<u8>,
    pub psk_identities: Vec<PskIdentity>,
    pub psk_binders: Vec<Vec<u8>>,
    pub quic_transport_parameters: Vec<u8>,
}
impl Default for PubClientHelloMsg {
    /// Every field at its zero value. Written out rather than derived so that adding a
    /// field to `PubClientHelloMsg` cannot default silently: this impl stops compiling until the new field is
    /// named here (RUST_GUIDELINES.md section 3, functional-update struct literals).
    fn default() -> Self {
        Self {
            raw: <Vec<u8> as Default>::default(),
            vers: <u16 as Default>::default(),
            random: <Vec<u8> as Default>::default(),
            session_id: <Vec<u8> as Default>::default(),
            cipher_suites: <Vec<u16> as Default>::default(),
            compression_methods: <Vec<u8> as Default>::default(),
            next_proto_neg: <bool as Default>::default(),
            server_name: <String as Default>::default(),
            ocsp_stapling: <bool as Default>::default(),
            scts: <bool as Default>::default(),
            ems: <bool as Default>::default(),
            supported_curves: <Vec<CurveId> as Default>::default(),
            supported_points: <Vec<u8> as Default>::default(),
            ticket_supported: <bool as Default>::default(),
            session_ticket: <Vec<u8> as Default>::default(),
            supported_signature_algorithms: <Vec<SignatureScheme> as Default>::default(),
            secure_renegotiation: <Vec<u8> as Default>::default(),
            secure_renegotiation_supported: <bool as Default>::default(),
            alpn_protocols: <Vec<String> as Default>::default(),
            supported_signature_algorithms_cert: <Vec<SignatureScheme> as Default>::default(),
            supported_versions: <Vec<u16> as Default>::default(),
            cookie: <Vec<u8> as Default>::default(),
            key_shares: <Vec<KeyShare> as Default>::default(),
            early_data: <bool as Default>::default(),
            psk_modes: <Vec<u8> as Default>::default(),
            psk_identities: <Vec<PskIdentity> as Default>::default(),
            psk_binders: <Vec<Vec<u8>> as Default>::default(),
            quic_transport_parameters: <Vec<u8> as Default>::default(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PskIdentity {
    pub identity: Vec<u8>,
    pub obfuscated_ticket_age: u32,
}

pub trait TlsExtension: Send + Sync {
    fn write_to_uconn(&self, uconn: &mut UConn) -> Result<()>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read(&self, b: &mut [u8]) -> io::Result<usize>;

    /// Overridden by [`PaddingExtension`]: `apply_padding` sizes the padding extension from the
    /// finished `ClientHello`, and a second `build_handshake_state` must not add another one.
    fn is_padding(&self) -> bool {
        false
    }

    /// Overridden by [`KeyShareExtension`]: `generate_key_shares` fills in the post-quantum and
    /// ECDHE key-share bytes after the extension list is built, and
    /// `build_removed_x25519_mlkem768_handshake_state` prunes the MLKEM768 entry back out.
    fn as_key_share_mut(&mut self) -> Option<&mut KeyShareExtension> {
        None
    }

    fn as_key_share(&self) -> Option<&KeyShareExtension> {
        None
    }

    /// Overridden by [`AlpnExtension`]: `build_websocket_handshake_state` rewrites or inserts the
    /// negotiated protocol list.
    fn as_alpn_mut(&mut self) -> Option<&mut AlpnExtension> {
        None
    }

    fn as_alpn(&self) -> Option<&AlpnExtension> {
        None
    }

    /// Overridden by [`SupportedCurvesExtension`]: `build_removed_x25519_mlkem768_handshake_state`
    /// prunes the MLKEM768 curve back out.
    fn as_supported_curves_mut(&mut self) -> Option<&mut SupportedCurvesExtension> {
        None
    }

    fn as_supported_curves(&self) -> Option<&SupportedCurvesExtension> {
        None
    }
}
fn boxed_extension<T: TlsExtension + 'static>(extension: T) -> Box<dyn TlsExtension> {
    Box::new(extension)
}

fn read_into(b: &mut [u8], contents: &[u8]) -> io::Result<usize> {
    let Some(target) = b.get_mut(..contents.len()) else {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short buffer"));
    };
    target.copy_from_slice(contents);
    Ok(contents.len())
}

#[derive(Clone, Debug, Default)]
pub struct SniExtension {
    pub server_name: String,
}

fn hostname_in_sni(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    let mut host = name;
    if host.starts_with('[') && host.ends_with(']') && host.len() > 1 {
        if let Some(bracketed) = host.strip_prefix('[').and_then(|inner| inner.strip_suffix(']')) {
            host = bracketed;
        }
    }
    if let Some(index) = host.rfind('%') {
        if index > 0 {
            host = host.split_at(index).0;
        }
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return String::new();
    }
    let mut name = name;
    while let Some(stripped) = name.strip_suffix('.') {
        name = stripped;
    }
    name.to_owned()
}

impl TlsExtension for SniExtension {
    fn write_to_uconn(&self, uconn: &mut UConn) -> Result<()> {
        uconn.handshake_state.hello.server_name.clone_from(&self.server_name);
        Ok(())
    }

    fn len(&self) -> usize {
        let host_name = hostname_in_sni(&self.server_name);
        if host_name.is_empty() {
            return 0;
        }
        4 + 2 + 1 + 2 + host_name.len()
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the `ServerNameList` list and name lengths are 16-bit TLS wire fields"
    )]
    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let host_name = hostname_in_sni(&self.server_name);
        if host_name.is_empty() {
            return Ok(0);
        }
        let mut contents = Vec::with_capacity(self.len());
        contents.extend_from_slice(&[0x00, 0x00]);
        contents.extend_from_slice(&((2 + 1 + 2 + host_name.len()) as u16).to_be_bytes());
        contents.extend_from_slice(&((1 + 2 + host_name.len()) as u16).to_be_bytes());
        contents.push(0);
        contents.extend_from_slice(&(host_name.len() as u16).to_be_bytes());
        contents.extend_from_slice(host_name.as_bytes());
        read_into(b, &contents)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SupportedCurvesExtension {
    pub curves: Vec<CurveId>,
}

impl TlsExtension for SupportedCurvesExtension {
    fn write_to_uconn(&self, uconn: &mut UConn) -> Result<()> {
        uconn.handshake_state.hello.supported_curves.clone_from(&self.curves);
        Ok(())
    }

    fn len(&self) -> usize {
        6 + 2 * self.curves.len()
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the `SupportedGroups` list and byte-length fields are 16-bit TLS wire fields"
    )]
    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let mut contents = Vec::with_capacity(self.len());
        contents.extend_from_slice(&10u16.to_be_bytes());
        contents.extend_from_slice(&((2 + 2 * self.curves.len()) as u16).to_be_bytes());
        contents.extend_from_slice(&((2 * self.curves.len()) as u16).to_be_bytes());
        for curve in &self.curves {
            contents.extend_from_slice(&curve.as_u16().to_be_bytes());
        }
        read_into(b, &contents)
    }

    fn as_supported_curves_mut(&mut self) -> Option<&mut Self> {
        Some(self)
    }

    fn as_supported_curves(&self) -> Option<&Self> {
        Some(self)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyShare {
    pub group: CurveId,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct KeyShareExtension {
    pub key_shares: Vec<KeyShare>,
}

impl KeyShareExtension {
    fn key_shares_len(&self) -> usize {
        self.key_shares.iter().map(|share| 4 + share.data.len()).sum()
    }
}

impl TlsExtension for KeyShareExtension {
    fn write_to_uconn(&self, uconn: &mut UConn) -> Result<()> {
        uconn.handshake_state.hello.key_shares.clone_from(&self.key_shares);
        Ok(())
    }

    fn len(&self) -> usize {
        4 + 2 + self.key_shares_len()
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the `KeyShare` list and entry lengths are 16-bit TLS wire fields"
    )]
    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let key_shares_len = self.key_shares_len();
        let mut contents = Vec::with_capacity(self.len());
        contents.extend_from_slice(&51u16.to_be_bytes());
        contents.extend_from_slice(&((key_shares_len + 2) as u16).to_be_bytes());
        contents.extend_from_slice(&(key_shares_len as u16).to_be_bytes());
        for share in &self.key_shares {
            contents.extend_from_slice(&share.group.as_u16().to_be_bytes());
            contents.extend_from_slice(&(share.data.len() as u16).to_be_bytes());
            contents.extend_from_slice(&share.data);
        }
        read_into(b, &contents)
    }

    fn as_key_share_mut(&mut self) -> Option<&mut Self> {
        Some(self)
    }

    fn as_key_share(&self) -> Option<&Self> {
        Some(self)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SupportedVersionsExtension {
    pub versions: Vec<u16>,
}

impl TlsExtension for SupportedVersionsExtension {
    fn write_to_uconn(&self, uconn: &mut UConn) -> Result<()> {
        uconn.handshake_state.hello.supported_versions.clone_from(&self.versions);
        Ok(())
    }

    fn len(&self) -> usize {
        5 + 2 * self.versions.len()
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the version list is an 8-bit `SupportedVersions` list inside a 16-bit extension body"
    )]
    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let mut contents = Vec::with_capacity(self.len());
        contents.extend_from_slice(&43u16.to_be_bytes());
        contents.extend_from_slice(&((1 + 2 * self.versions.len()) as u16).to_be_bytes());
        contents.push((2 * self.versions.len()) as u8);
        for version in &self.versions {
            contents.extend_from_slice(&version.to_be_bytes());
        }
        read_into(b, &contents)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SignatureAlgorithmsExtension {
    pub supported_signature_algorithms: Vec<SignatureScheme>,
}

impl TlsExtension for SignatureAlgorithmsExtension {
    fn write_to_uconn(&self, uconn: &mut UConn) -> Result<()> {
        uconn.handshake_state.hello.supported_signature_algorithms.clone_from(&self.supported_signature_algorithms);
        Ok(())
    }

    fn len(&self) -> usize {
        6 + 2 * self.supported_signature_algorithms.len()
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the `SignatureSchemeList` and byte-length fields are 16-bit TLS wire fields"
    )]
    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let mut contents = Vec::with_capacity(self.len());
        contents.extend_from_slice(&13u16.to_be_bytes());
        contents.extend_from_slice(&((2 + 2 * self.supported_signature_algorithms.len()) as u16).to_be_bytes());
        contents.extend_from_slice(&((2 * self.supported_signature_algorithms.len()) as u16).to_be_bytes());
        for scheme in &self.supported_signature_algorithms {
            contents.extend_from_slice(&scheme.0.to_be_bytes());
        }
        read_into(b, &contents)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SignatureAlgorithmsCertExtension {
    pub supported_signature_algorithms: Vec<SignatureScheme>,
}

impl TlsExtension for SignatureAlgorithmsCertExtension {
    fn write_to_uconn(&self, uconn: &mut UConn) -> Result<()> {
        uconn
            .handshake_state
            .hello
            .supported_signature_algorithms_cert
            .clone_from(&self.supported_signature_algorithms);
        Ok(())
    }

    fn len(&self) -> usize {
        6 + 2 * self.supported_signature_algorithms.len()
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the `SignatureSchemeList` and byte-length fields are 16-bit TLS wire fields"
    )]
    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let mut contents = Vec::with_capacity(self.len());
        contents.extend_from_slice(&50u16.to_be_bytes());
        contents.extend_from_slice(&((2 + 2 * self.supported_signature_algorithms.len()) as u16).to_be_bytes());
        contents.extend_from_slice(&((2 * self.supported_signature_algorithms.len()) as u16).to_be_bytes());
        for scheme in &self.supported_signature_algorithms {
            contents.extend_from_slice(&scheme.0.to_be_bytes());
        }
        read_into(b, &contents)
    }
}

#[derive(Clone, Debug, Default)]
pub struct PskKeyExchangeModesExtension {
    pub modes: Vec<u8>,
}

impl TlsExtension for PskKeyExchangeModesExtension {
    fn write_to_uconn(&self, uconn: &mut UConn) -> Result<()> {
        uconn.handshake_state.hello.psk_modes.clone_from(&self.modes);
        Ok(())
    }

    fn len(&self) -> usize {
        5 + self.modes.len()
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the `PskKeyExchangeModes` list is an 8-bit count inside a 16-bit extension body"
    )]
    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let mut contents = Vec::with_capacity(self.len());
        contents.extend_from_slice(&45u16.to_be_bytes());
        contents.extend_from_slice(&((1 + self.modes.len()) as u16).to_be_bytes());
        contents.push(self.modes.len() as u8);
        contents.extend_from_slice(&self.modes);
        read_into(b, &contents)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SessionTicketExtension {
    pub session: Vec<u8>,
    pub initialized: bool,
}

impl TlsExtension for SessionTicketExtension {
    fn write_to_uconn(&self, uconn: &mut UConn) -> Result<()> {
        uconn.handshake_state.hello.ticket_supported = true;
        uconn.handshake_state.hello.session_ticket.clone_from(&self.session);
        Ok(())
    }

    fn len(&self) -> usize {
        4 + self.session.len()
    }

    #[expect(clippy::cast_possible_truncation, reason = "the session ticket length field is 16 bits by definition")]
    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let mut contents = Vec::with_capacity(self.len());
        contents.extend_from_slice(&35u16.to_be_bytes());
        contents.extend_from_slice(&(self.session.len() as u16).to_be_bytes());
        contents.extend_from_slice(&self.session);
        read_into(b, &contents)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExtendedMasterSecretExtension;

impl TlsExtension for ExtendedMasterSecretExtension {
    fn write_to_uconn(&self, uconn: &mut UConn) -> Result<()> {
        uconn.handshake_state.hello.ems = true;
        Ok(())
    }

    fn len(&self) -> usize {
        4
    }

    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let mut contents = Vec::with_capacity(self.len());
        contents.extend_from_slice(&23u16.to_be_bytes());
        contents.extend_from_slice(&0u16.to_be_bytes());
        read_into(b, &contents)
    }
}

#[derive(Clone, Debug, Default)]
pub struct AlpnExtension {
    pub alpn_protocols: Vec<String>,
}

impl TlsExtension for AlpnExtension {
    fn write_to_uconn(&self, uconn: &mut UConn) -> Result<()> {
        if uconn.conn.shared.config.encrypted_client_hello_config_list.is_empty() {
            *uconn.conn.shared.next_protos_override.lock() = Some(self.alpn_protocols.clone());
            uconn.handshake_state.hello.alpn_protocols.clone_from(&self.alpn_protocols);
        }
        Ok(())
    }

    fn len(&self) -> usize {
        let mut b_len = 2 + 2 + 2;
        for protocol in &self.alpn_protocols {
            b_len += 1 + protocol.len();
        }
        b_len
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the ALPN protocol list uses an 8-bit name length and 16-bit list lengths"
    )]
    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let mut list = Vec::new();
        for protocol in &self.alpn_protocols {
            list.push(protocol.len() as u8);
            list.extend_from_slice(protocol.as_bytes());
        }
        let mut contents = Vec::with_capacity(self.len());
        contents.extend_from_slice(&16u16.to_be_bytes());
        contents.extend_from_slice(&((2 + list.len()) as u16).to_be_bytes());
        contents.extend_from_slice(&(list.len() as u16).to_be_bytes());
        contents.extend_from_slice(&list);
        read_into(b, &contents)
    }

    fn as_alpn_mut(&mut self) -> Option<&mut Self> {
        Some(self)
    }

    fn as_alpn(&self) -> Option<&Self> {
        Some(self)
    }
}

#[derive(Clone, Debug, Default)]
pub struct GenericExtension {
    pub id: u16,
    pub data: Vec<u8>,
}

impl TlsExtension for GenericExtension {
    fn write_to_uconn(&self, _uconn: &mut UConn) -> Result<()> {
        Ok(())
    }

    fn len(&self) -> usize {
        4 + self.data.len()
    }

    #[expect(clippy::cast_possible_truncation, reason = "the extension data length field is 16 bits by definition")]
    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let mut contents = Vec::with_capacity(self.len());
        contents.extend_from_slice(&self.id.to_be_bytes());
        contents.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        contents.extend_from_slice(&self.data);
        read_into(b, &contents)
    }
}

impl UConn {
    fn new(conn: Conn, client_hello_id: ClientHelloId) -> Self {
        Self {
            conn,
            extensions: Vec::new(),
            client_hello_id,
            handshake_state: PubClientHandshakeState::default(),
            client_hello_build_status: ClientHelloBuildStatus::NotBuilt,
            padding: None,
            engine: Mutex::new(None),
        }
    }

    pub fn build_handshake_state(&mut self) -> Result<()> {
        if self.client_hello_id.client == HELLO_DEFAULT {
            if self.client_hello_build_status == ClientHelloBuildStatus::BuildByDefault {
                return Ok(());
            }
            self.new_client_hello();
            // the standard extension set lives in `hello_plan`'s non-browser arm, so a default
            // hello without it goes out bare.
            self.apply_preset_by_id();
            self.generate_key_shares()?;
            self.apply_config()?;
            self.marshal_client_hello()?;
            self.apply_session_id_generator()?;
            self.client_hello_build_status = ClientHelloBuildStatus::BuildByDefault;
            return Ok(());
        }
        if self.client_hello_build_status == ClientHelloBuildStatus::NotBuilt {
            self.new_client_hello();
            self.apply_preset_by_id();
            self.generate_key_shares()?;
        }
        self.apply_config()?;
        self.apply_padding()?;
        self.marshal_client_hello()?;
        self.apply_session_id_generator()?;
        self.client_hello_build_status = ClientHelloBuildStatus::BuildByUtls;
        Ok(())
    }

    pub fn build_handshake_state_without_session(&mut self) -> Result<()> {
        self.build_handshake_state()
    }

    fn new_client_hello(&mut self) {
        let mut rng = rand::rng();
        let mut random = vec![0u8; HANDHELLO_RANDOM_LEN];
        rng.fill(&mut random[..]);
        let mut session_id = vec![0u8; CLIENT_SESSION_ID_LEN];
        rng.fill(&mut session_id[..]);
        self.handshake_state.hello = PubClientHelloMsg {
            vers: VERSION_TLS12,
            random,
            session_id,
            cipher_suites: default_cipher_suites(),
            compression_methods: vec![0],
            ..Default::default()
        };
    }

    fn apply_preset_by_id(&mut self) {
        if self.client_hello_id.client == HELLO_CUSTOM {
            return;
        }
        let plan = hello_plan(&self.client_hello_id, &self.conn.shared.config);
        self.extensions = plan.extensions;
        self.handshake_state.hello.cipher_suites = plan.cipher_suites;
        self.padding = plan.padding;
    }

    /// The Boring padding style: a `ClientHello` whose
    /// length is over 0xff and under [`BORING_PADDING_TARGET`] grows to that target. The length is
    /// only known once every other extension is in place, so this runs between `apply_config` and
    /// the final marshal.
    fn apply_padding(&mut self) -> Result<()> {
        let Some(padding) = self.padding.as_ref() else {
            return Ok(());
        };
        if self.extensions.iter().any(|extension| extension.is_padding()) {
            return Ok(());
        }
        let probe = serialize_client_hello(&self.handshake_state.hello, &self.extensions)?;
        if probe.len() <= 0xff || probe.len() >= padding.target {
            return Ok(());
        }
        let shortfall = padding.target - probe.len();
        let length = u16::try_from(if shortfall >= 5 { shortfall - 4 } else { 1 })
            .map_err(|_| anyhow!("tls: padding shortfall {shortfall} does not fit an extension"))?;
        let index = padding.index.min(self.extensions.len());
        self.extensions.insert(index, Box::new(PaddingExtension { length }));
        Ok(())
    }

    fn apply_config(&mut self) -> Result<()> {
        let extensions = std::mem::take(&mut self.extensions);
        for extension in &extensions {
            extension.write_to_uconn(self)?;
        }
        self.extensions = extensions;
        Ok(())
    }

    fn generate_key_shares(&mut self) -> Result<()> {
        let mut keys = KeySharePrivateKeys::default();
        for extension in &mut self.extensions {
            let Some(key_share_extension) = extension.as_key_share_mut() else {
                continue;
            };
            for key_share in &mut key_share_extension.key_shares {
                if key_share.data.len() > 1 {
                    continue;
                }
                let curve_id = key_share.group;
                if is_grease(curve_id.as_u16()) {
                    key_share.data = vec![0];
                    continue;
                }
                if curve_id == CurveId::X25519_MLKEM768 {
                    let ecdhe_key = generate_x25519()?;
                    let mlkem_key = generate_mlkem_key();
                    let mut data = mlkem_key.encapsulation_key().to_bytes().to_vec();
                    data.extend_from_slice(PublicKey::from(&ecdhe_key).as_bytes());
                    key_share.data = data;
                    keys.shares.push(ShareKeys { curve_id, ecdhe: Some(ecdhe_key), mlkem: Some(mlkem_key), kx: None });
                } else {
                    let ecdhe_key = generate_x25519_for_curve(curve_id)?;
                    key_share.data = PublicKey::from(&ecdhe_key).to_bytes().to_vec();
                    keys.shares.push(ShareKeys { curve_id, ecdhe: Some(ecdhe_key), mlkem: None, kx: None });
                }
            }
        }
        self.handshake_state.state13.key_share_keys = Some(keys);
        Ok(())
    }

    fn marshal_client_hello(&mut self) -> Result<()> {
        self.handshake_state.hello.raw = serialize_client_hello(&self.handshake_state.hello, &self.extensions)?;
        Ok(())
    }

    /// Applies the configured session-id generator.
    fn apply_session_id_generator(&mut self) -> Result<()> {
        let Some(generator) = self.conn.shared.config.session_id_generator.clone() else {
            return Ok(());
        };
        self.handshake_state.hello.session_id = vec![0u8; CLIENT_SESSION_ID_LEN];
        self.marshal_client_hello()?;
        let mut session_id = vec![0u8; CLIENT_SESSION_ID_LEN];
        generator(&self.handshake_state.hello.raw, &mut session_id)
            .map_err(|err| anyhow!("tls: generate session id failed: {err}"))?;
        self.handshake_state.hello.session_id = session_id;
        self.marshal_client_hello()
    }

    /// Builds the handshake state, then sends exactly that
    /// `ClientHello` and finishes the handshake itself. A configuration capped below TLS 1.3 is
    /// left to `rustls`, which still speaks TLS 1.2.
    pub async fn handshake_context(&mut self, ctx: &CancellationToken) -> Result<()> {
        self.build_handshake_state()?;
        let config = Arc::clone(&self.conn.shared.config);
        if effective_max_version(&config) < VERSION_TLS13 {
            return self.conn.handshake_context(ctx).await;
        }
        let mut client = UtlsClient::new(
            config,
            build_provider(&self.conn.shared.config),
            self.handshake_state.hello.raw.clone(),
            self.handshake_state.state13.key_share_keys.take().unwrap_or_default(),
        );
        let mut raw = {
            let mut state = self.conn.shared.state.lock();
            match std::mem::replace(&mut *state, ConnState::Closed) {
                ConnState::Raw(raw) => raw,
                previous @ (ConnState::Handshaking(_)
                | ConnState::ClosingWrite { .. }
                | ConnState::Ready(_)
                | ConnState::Failed(_)
                | ConnState::Closed) => {
                    *state = previous;
                    drop(state);
                    return Err(anyhow!("tls: connection is no longer waiting for a handshake"));
                }
            }
        };
        self.conn.shared.fingerprinted.store(true, Ordering::Release);
        let result = {
            let handshake = client.handshake(&mut *raw);
            tokio::pin!(handshake);
            tokio::select! {
                result = &mut handshake => result,
                () = ctx.cancelled() => Err(anyhow!("context canceled")),
            }
        };
        match result {
            Ok(()) => {
                *self.conn.shared.state.lock() = ConnState::Raw(raw);
                *self.engine.lock() = Some(Box::new(client));
                Ok(())
            }
            Err(err) => {
                let _ = close_stream(&*raw);
                Err(err)
            }
        }
    }
}

/// Extension types the browser shapes below spell out as literal bodies because this crate has no
/// dedicated extension type for them.
const EXTENSION_STATUS_REQUEST: u16 = 5;
const EXTENSION_EC_POINT_FORMATS: u16 = 11;
const EXTENSION_SCT: u16 = 18;
const EXTENSION_PADDING: u16 = 21;
const EXTENSION_RECORD_SIZE_LIMIT: u16 = 28;
const EXTENSION_RENEGOTIATION_INFO: u16 = 0xff01;
const EXTENSION_APPLICATION_SETTINGS: u16 = 17513;
const EXTENSION_APPLICATION_SETTINGS_NEW: u16 = 17613;

/// The Boring padding style's target `ClientHello` length.
const BORING_PADDING_TARGET: usize = 0x200;

/// `status_request` for a responder that offers neither OCSP staples nor SCTs: the `responder_id`
/// list and the `request_extensions` list are both empty.
const STATUS_REQUEST_BODY: [u8; 5] = [1, 0, 0, 0, 0];
const X25519_GROUP: u16 = CurveId::X25519.0;
const X25519MLKEM768_GROUP: u16 = 4588;

const CHROME_CIPHER_SUITES: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
    0x0035,
];
const CHROME_GROUPS: &[u16] = &[X25519MLKEM768_GROUP, X25519_GROUP, 23, 24];
const CHROME_KEY_SHARES: &[u16] = &[X25519MLKEM768_GROUP, X25519_GROUP];
const CHROME_SIGNATURE_ALGORITHMS: &[u16] =
    &[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0806, 0x0603, 0x0601, 0x0807, 0x0203];

/// The default cipher suite list: the preference order minus the disabled, RSA-key-exchange and
/// 3DES entries. The TLS 1.3 suites are appended after it, since the list is reset only on a
/// TLS 1.3-only client.
const BUILTIN_CIPHER_SUITES: &[u16] = &[0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014];
const BUILTIN_TLS13_CIPHER_SUITES: &[u16] = &[0x1301, 0x1302, 0x1303];
const BUILTIN_GROUPS: &[u16] = &[X25519MLKEM768_GROUP, X25519_GROUP, 23, 24, 25];
const BUILTIN_KEY_SHARES: &[u16] = &[X25519MLKEM768_GROUP, X25519_GROUP];
const BUILTIN_SIGNATURE_ALGORITHMS: &[u16] =
    &[0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203];

const FIREFOX_CIPHER_SUITES: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00c, 0xc013, 0xc014, 0x009c, 0x009d,
    0x002f, 0x0035,
];
const FIREFOX_GROUPS: &[u16] = &[X25519MLKEM768_GROUP, X25519_GROUP, 23, 24, 25, 256];
const FIREFOX_KEY_SHARES: &[u16] = &[X25519MLKEM768_GROUP, X25519_GROUP];
const FIREFOX_SIGNATURE_ALGORITHMS: &[u16] =
    &[0x0503, 0x0501, 0x0403, 0x0401, 0x0805, 0x0804, 0x0806, 0x0501, 0x0601, 0x0603, 0x0807, 0x0203];

const SAFARI_CIPHER_SUITES: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
    0x0035,
];
const SAFARI_GROUPS: &[u16] = &[X25519_GROUP, 23, 24, 25];
const SAFARI_SIGNATURE_ALGORITHMS: &[u16] =
    &[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0806, 0x0603, 0x0601, 0x0807, 0x0203, 0x0201];

const ANDROID_CIPHER_SUITES: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
    0x0035,
];
const ANDROID_GROUPS: &[u16] = &[X25519_GROUP, 23, 24, 25, 256];
const ANDROID_SIGNATURE_ALGORITHMS: &[u16] =
    &[0x0804, 0x0805, 0x0806, 0x0403, 0x0401, 0x0503, 0x0501, 0x0603, 0x0601, 0x0203, 0x0201];

/// The browser families this crate gives a distinct `ClientHello` shape. A `ClientHelloId` outside
/// this list (`Default`) keeps the shared default list instead of guessing a browser.
///
/// DEVIATION: these shapes are this crate's own reconstruction of the browser hellos rather than a
/// translation of them. What each family does model is pinned by the preset tests below; what it
/// does not:
/// - no shape carries `signature_algorithms_cert` (`SignatureAlgorithmsCertExtension` is used
///   nowhere, and none of the hellos below have it),
///   nor `compress_certificate`, ECH, `delegated_credentials`, NPN or `channel_id`.
/// - `Chrome` renders every Chrome version with one shape, where the shuffling variant
///   shuffles the whole extension list from Chrome 106 on, and the PQ variant
///   is keyed on X25519Kyber768Draft00 instead of X25519MLKEM768.
/// - the Android OkHttp shape is TLS 1.2-only, so this crate's TLS 1.3
///   extensions (`key_share`/`psk_key_exchange_modes`/`supported_versions`) are extra.
/// - the 360 7.5 shape is a TLS 1.2 hello with NPN, `channel_id_old` and an `spdy` ALPN list.
///   this crate gives `360Browser` and `QQBrowser` the Edge shape, so
///   `QQBrowser` also loses the ALPS extension the Edge shape keeps.
/// - every shape advertises `Config::next_protos`, where a preset whose spec carries an
///   `AlpnExtension` overwrites the config with the preset's own list; this crate keeps the caller's
///   list so consumers can still route on the negotiated protocol.
/// - `HELLO_CUSTOM` has no spec-injection equivalent, so it always marshals an
///   extension-less `ClientHello`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Browser {
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Edge,
    Chinese360,
    ChineseQq,
}

fn browser_of(id: &ClientHelloId) -> Option<Browser> {
    match id.client.as_str() {
        "Chrome" => Some(Browser::Chrome),
        "Firefox" => Some(Browser::Firefox),
        "Safari" => Some(Browser::Safari),
        "iOS" => Some(Browser::Ios),
        "Android" => Some(Browser::Android),
        "Edge" => Some(Browser::Edge),
        "360Browser" => Some(Browser::Chinese360),
        "QQBrowser" => Some(Browser::ChineseQq),
        _ => None,
    }
}

struct PaddingPlan {
    target: usize,
    index: usize,
}

struct HelloPlan {
    extensions: Vec<Box<dyn TlsExtension>>,
    cipher_suites: Vec<u16>,
    padding: Option<PaddingPlan>,
}

/// The extension list a family builder produces, plus where its padding extension belongs.
type Shape = (Vec<Box<dyn TlsExtension>>, Option<PaddingPlan>);

/// A random GREASE value of the form `0xωaωa`, with `0 ≤ ω < 16`, so
/// browsers keep a parser's unknown-value path exercised.
fn random_grease() -> u16 {
    let value = (rand::rng().random::<u8>() & 0xf0) | 0x0a;
    u16::from_be_bytes([value, value])
}

fn with_grease(grease: Option<u16>, values: &[u16]) -> Vec<u16> {
    let Some(grease) = grease else {
        return values.to_vec();
    };
    let mut out = Vec::with_capacity(values.len() + 1);
    out.push(grease);
    out.extend_from_slice(values);
    out
}

fn curves(values: &[u16]) -> Vec<CurveId> {
    values.iter().map(|value| CurveId(*value)).collect()
}

fn key_shares(grease: Option<u16>, values: &[u16]) -> Vec<KeyShare> {
    with_grease(grease, values).into_iter().map(|group| KeyShare { group: CurveId(group), data: Vec::new() }).collect()
}

/// True when both bytes are identical and the low nibble is `0xa`.
fn is_grease(group: u16) -> bool {
    let [high, low] = group.to_be_bytes();
    high == low && low & 0x0f == 0x0a
}

fn schemes(values: &[u16]) -> Vec<SignatureScheme> {
    values.iter().map(|value| SignatureScheme(*value)).collect()
}

/// The ALPS extension data is the u16-length-prefixed
/// `ProtocolNameList`, matching ALPN's own encoding.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the ALPS `ProtocolNameList` uses ALPN's 8-bit name length and 16-bit list length"
)]
fn application_settings(protocols: &[String]) -> Vec<u8> {
    let mut list = Vec::new();
    for protocol in protocols {
        list.push(protocol.len() as u8);
        list.extend_from_slice(protocol.as_bytes());
    }
    let mut body = Vec::with_capacity(2 + list.len());
    body.extend_from_slice(&(list.len() as u16).to_be_bytes());
    body.extend_from_slice(&list);
    body
}

/// RFC 7301 forbids an empty `ProtocolNameList`, so the extension appears only when the config
/// offers at least one protocol.
fn alpn_extension(config: &Config) -> Option<Box<dyn TlsExtension>> {
    (!config.next_protos.is_empty()).then(|| {
        let extension: Box<dyn TlsExtension> = Box::new(AlpnExtension { alpn_protocols: config.next_protos.clone() });
        extension
    })
}

/// All three randomized ids are generated the same way; the id only picks the ALPN policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RandomizedAlpn {
    Coin,
    Always,
    Never,
}

fn randomized_alpn(id: &ClientHelloId) -> Option<RandomizedAlpn> {
    match id.client.as_str() {
        "Randomized" => Some(RandomizedAlpn::Coin),
        "Randomized-ALPN" => Some(RandomizedAlpn::Always),
        "Randomized-NoALPN" => Some(RandomizedAlpn::Never),
        _ => None,
    }
}

fn hello_plan(id: &ClientHelloId, config: &Config) -> HelloPlan {
    if let Some(alpn) = randomized_alpn(id) {
        return randomized_plan(id, config, alpn);
    }
    let Some(browser) = browser_of(id) else {
        return HelloPlan {
            extensions: default_extensions(config),
            cipher_suites: builtin_cipher_suites(),
            padding: None,
        };
    };
    // Edge, 360 and QQ are Chromium stacks, so they keep Chromium's GREASE but not its
    // post-quantum key share or its ALPS tail.
    let grease = matches!(browser, Browser::Chrome | Browser::Edge | Browser::Chinese360 | Browser::ChineseQq)
        .then(random_grease);
    let (extensions, padding) = match browser {
        Browser::Chrome => chrome_extensions(config, grease, true, alps_code_point(&id.version)),
        Browser::Edge | Browser::Chinese360 | Browser::ChineseQq => {
            chrome_extensions(config, grease, false, EXTENSION_APPLICATION_SETTINGS)
        }
        Browser::Firefox => firefox_extensions(config),
        Browser::Safari | Browser::Ios => (safari_extensions(config), None),
        Browser::Android => (android_extensions(config), None),
    };
    HelloPlan { extensions, cipher_suites: cipher_suites_of(browser, grease), padding }
}

fn cipher_suites_of(browser: Browser, grease: Option<u16>) -> Vec<u16> {
    let base = match browser {
        Browser::Firefox => FIREFOX_CIPHER_SUITES,
        Browser::Safari | Browser::Ios => SAFARI_CIPHER_SUITES,
        Browser::Android => ANDROID_CIPHER_SUITES,
        Browser::Chrome | Browser::Edge | Browser::Chinese360 | Browser::ChineseQq => CHROME_CIPHER_SUITES,
    };
    with_grease(grease, base)
}

/// Chrome 131 on advertises ALPS under `EXTENSION_APPLICATION_SETTINGS_NEW` instead of
/// `EXTENSION_APPLICATION_SETTINGS`.
fn alps_code_point(version: &str) -> u16 {
    match version {
        "131" | "133" => EXTENSION_APPLICATION_SETTINGS_NEW,
        _ => EXTENSION_APPLICATION_SETTINGS,
    }
}

/// Chromium's extension order. `modern` distinguishes the two shapes this crate models: current
/// Chrome sends a post-quantum key share and the ALPS tail, while the earlier Chromium shape Edge,
/// 360 and QQ present sends neither.
fn chrome_extensions(config: &Config, grease: Option<u16>, modern: bool, alps: u16) -> Shape {
    let shares = if modern { CHROME_KEY_SHARES } else { &[X25519_GROUP][..] };
    let mut extensions: Vec<Box<dyn TlsExtension>> = vec![
        Box::new(SniExtension { server_name: config.server_name.clone() }),
        Box::new(ExtendedMasterSecretExtension),
        Box::new(GenericExtension { id: EXTENSION_RENEGOTIATION_INFO, data: vec![0] }),
        Box::new(SupportedCurvesExtension { curves: curves(&with_grease(grease, CHROME_GROUPS)) }),
        Box::new(SessionTicketExtension::default()),
    ];
    extensions.extend(alpn_extension(config));
    extensions.extend([
        boxed_extension(GenericExtension { id: EXTENSION_STATUS_REQUEST, data: STATUS_REQUEST_BODY.to_vec() }),
        boxed_extension(SignatureAlgorithmsExtension {
            supported_signature_algorithms: schemes(&with_grease(grease, CHROME_SIGNATURE_ALGORITHMS)),
        }),
        boxed_extension(KeyShareExtension { key_shares: key_shares(grease, shares) }),
        boxed_extension(PskKeyExchangeModesExtension { modes: vec![1] }),
        boxed_extension(SupportedVersionsExtension { versions: with_grease(grease, &[VERSION_TLS13, VERSION_TLS12]) }),
    ]);
    if let Some(grease) = grease {
        extensions.push(Box::new(GenericExtension { id: grease, data: vec![0] }));
    }
    let padding_index = extensions.len();
    if modern && !config.next_protos.is_empty() {
        extensions.push(Box::new(GenericExtension { id: alps, data: application_settings(&config.next_protos) }));
    }
    (extensions, Some(PaddingPlan { target: BORING_PADDING_TARGET, index: padding_index }))
}

/// Firefox: no GREASE and an `ec_point_formats`/`record_size_limit` tail.
fn firefox_extensions(config: &Config) -> Shape {
    let mut extensions: Vec<Box<dyn TlsExtension>> = vec![
        Box::new(SniExtension { server_name: config.server_name.clone() }),
        Box::new(ExtendedMasterSecretExtension),
        Box::new(SupportedCurvesExtension { curves: curves(FIREFOX_GROUPS) }),
        Box::new(KeyShareExtension { key_shares: key_shares(None, FIREFOX_KEY_SHARES) }),
        Box::new(SignatureAlgorithmsExtension {
            supported_signature_algorithms: schemes(FIREFOX_SIGNATURE_ALGORITHMS),
        }),
        Box::new(SupportedVersionsExtension { versions: vec![VERSION_TLS13, VERSION_TLS12] }),
        Box::new(PskKeyExchangeModesExtension { modes: vec![1] }),
        Box::new(SessionTicketExtension::default()),
    ];
    extensions.extend(alpn_extension(config));
    extensions.extend([
        boxed_extension(GenericExtension { id: EXTENSION_STATUS_REQUEST, data: STATUS_REQUEST_BODY.to_vec() }),
        boxed_extension(GenericExtension { id: EXTENSION_RENEGOTIATION_INFO, data: vec![0] }),
        boxed_extension(GenericExtension { id: EXTENSION_EC_POINT_FORMATS, data: vec![1, 0] }),
        boxed_extension(GenericExtension { id: EXTENSION_RECORD_SIZE_LIMIT, data: vec![0x00, 0x01, 0x00] }),
    ]);
    let padding_index = extensions.len();
    (extensions, Some(PaddingPlan { target: BORING_PADDING_TARGET, index: padding_index }))
}

/// Safari and iOS share WebKit's extension set. Neither pads explicitly, so both return no
/// [`PaddingPlan`].
fn safari_extensions(config: &Config) -> Vec<Box<dyn TlsExtension>> {
    let schemes = schemes(SAFARI_SIGNATURE_ALGORITHMS);
    let mut extensions: Vec<Box<dyn TlsExtension>> = vec![
        Box::new(SniExtension { server_name: config.server_name.clone() }),
        Box::new(ExtendedMasterSecretExtension),
        Box::new(SupportedCurvesExtension { curves: curves(SAFARI_GROUPS) }),
        Box::new(GenericExtension { id: EXTENSION_EC_POINT_FORMATS, data: vec![1, 0] }),
    ];
    extensions.extend(alpn_extension(config));
    extensions.extend([
        boxed_extension(GenericExtension { id: EXTENSION_STATUS_REQUEST, data: STATUS_REQUEST_BODY.to_vec() }),
        boxed_extension(SignatureAlgorithmsExtension { supported_signature_algorithms: schemes }),
        boxed_extension(KeyShareExtension { key_shares: key_shares(None, &[X25519_GROUP]) }),
        boxed_extension(PskKeyExchangeModesExtension { modes: vec![1] }),
        boxed_extension(SupportedVersionsExtension { versions: vec![VERSION_TLS13, VERSION_TLS12] }),
    ]);
    extensions
}

/// OkHttp's shape: the same WebKit-style core without ALPS and with no `session_ticket`.
fn android_extensions(config: &Config) -> Vec<Box<dyn TlsExtension>> {
    let schemes = schemes(ANDROID_SIGNATURE_ALGORITHMS);
    let mut extensions: Vec<Box<dyn TlsExtension>> = vec![
        Box::new(SniExtension { server_name: config.server_name.clone() }),
        Box::new(ExtendedMasterSecretExtension),
    ];
    extensions.extend(alpn_extension(config));
    extensions.extend([
        boxed_extension(GenericExtension { id: EXTENSION_STATUS_REQUEST, data: STATUS_REQUEST_BODY.to_vec() }),
        boxed_extension(SupportedCurvesExtension { curves: curves(ANDROID_GROUPS) }),
        boxed_extension(SignatureAlgorithmsExtension { supported_signature_algorithms: schemes }),
        boxed_extension(KeyShareExtension { key_shares: key_shares(None, &[X25519_GROUP]) }),
        boxed_extension(SupportedVersionsExtension { versions: vec![VERSION_TLS13, VERSION_TLS12] }),
        boxed_extension(PskKeyExchangeModesExtension { modes: vec![1] }),
        boxed_extension(SessionTicketExtension::default()),
    ]);
    extensions
}

/// The default extension set in the order the default hello marshals it. `session_ticket` and
/// `psk_key_exchange_modes` are missing on purpose: a session cache would only add them when the
/// config carries one, which this crate has no equivalent of.
fn default_extensions(config: &Config) -> Vec<Box<dyn TlsExtension>> {
    let mut extensions: Vec<Box<dyn TlsExtension>> = vec![
        Box::new(SniExtension { server_name: config.server_name.clone() }),
        boxed_extension(GenericExtension { id: EXTENSION_EC_POINT_FORMATS, data: vec![1, 0] }),
        boxed_extension(GenericExtension { id: EXTENSION_RENEGOTIATION_INFO, data: vec![0] }),
        Box::new(ExtendedMasterSecretExtension),
        boxed_extension(GenericExtension { id: EXTENSION_SCT, data: Vec::new() }),
        boxed_extension(GenericExtension { id: EXTENSION_STATUS_REQUEST, data: STATUS_REQUEST_BODY.to_vec() }),
        boxed_extension(SupportedCurvesExtension { curves: curves(BUILTIN_GROUPS) }),
        boxed_extension(SignatureAlgorithmsExtension {
            supported_signature_algorithms: schemes(BUILTIN_SIGNATURE_ALGORITHMS),
        }),
    ];
    extensions.extend(alpn_extension(config));
    extensions.extend([
        boxed_extension(SupportedVersionsExtension { versions: vec![VERSION_TLS13, VERSION_TLS12] }),
        boxed_extension(KeyShareExtension { key_shares: key_shares(None, BUILTIN_KEY_SHARES) }),
    ]);
    extensions
}

fn default_cipher_suites() -> Vec<u16> {
    CHROME_CIPHER_SUITES.to_vec()
}

/// The default arm's cipher list: the TLS 1.2 preference order
/// followed by the TLS 1.3 suites.
fn builtin_cipher_suites() -> Vec<u16> {
    let mut suites = BUILTIN_CIPHER_SUITES.to_vec();
    suites.extend_from_slice(BUILTIN_TLS13_CIPHER_SUITES);
    suites
}

/// A SplitMix64 stream seeded from the [`ClientHelloId`] seed, so a randomized hello is
/// reproducible across connections.
struct SeededRng {
    state: u64,
}

impl SeededRng {
    fn new(seed: PrngSeed) -> Self {
        let mut state = 0u64;
        for byte in seed {
            state = (state << 8) | u64::from(byte);
        }
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "the draw is shifted into the low 53 bits and divided by 2^53, so both operands are exactly representable in `f64`"
    )]
    fn chance(&mut self, probability: f64) -> bool {
        let draw = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        draw < probability
    }
}

/// A randomized hello: every decision the `Weights` struct describes is drawn from the seeded
/// stream, so the same configured seed always produces the same randomized shape. The id only
/// picks the ALPN policy, forcing it on, off, or leaving it to the stream.
fn randomized_plan(id: &ClientHelloId, config: &Config, alpn: RandomizedAlpn) -> HelloPlan {
    let weights = id.weights.unwrap_or_else(default_weights);
    let mut rng = SeededRng::new(id.seed.unwrap_or([0u8; PRNG_SEED_LENGTH]));

    let mut cipher_suites = default_cipher_suites();
    if rng.chance(weights.cipher_suites_remove_random_ciphers) {
        cipher_suites.retain(|suite| !matches!(*suite, 0x009c | 0x009d | 0x002f | 0x0035));
    }

    let mut groups = vec![X25519MLKEM768_GROUP, X25519_GROUP];
    if rng.chance(weights.curve_i_ds_append_x25519) {
        groups.push(X25519_GROUP);
    }
    if rng.chance(weights.curve_i_ds_append_curve_p521) {
        groups.push(25);
    }
    groups.push(23);
    groups.push(24);
    groups.dedup();

    let mut algorithms = vec![0x0403u16, 0x0401, 0x0503, 0x0501, 0x0201, 0x0601];
    if rng.chance(weights.sig_and_hash_algos_append_ecdsa_with_sha1) {
        algorithms.push(0x0203);
    }
    if rng.chance(weights.sig_and_hash_algos_append_ecdsa_with_p521_and_sha512) {
        algorithms.push(0x0603);
    }
    if rng.chance(weights.sig_and_hash_algos_append_pss_with_sha256) {
        algorithms.push(0x0804);
    }
    if rng.chance(weights.sig_and_hash_algos_append_pss_with_sha384_pss_with_sha512) {
        algorithms.push(0x0805);
        algorithms.push(0x0806);
    }

    let shares = if rng.chance(weights.key_share_append_random_groups) {
        vec![X25519MLKEM768_GROUP, X25519_GROUP]
    } else {
        vec![X25519MLKEM768_GROUP]
    };

    let with_alpn = match alpn {
        RandomizedAlpn::Always => true,
        RandomizedAlpn::Never => false,
        RandomizedAlpn::Coin => rng.chance(weights.extensions_append_alpn),
    };
    // An ALPN-forced hello with none configured substitutes a popular list; an empty
    // `ProtocolNameList` is not encodable.
    let alpn_protocols = if config.next_protos.is_empty() {
        vec!["h2".to_owned(), "http/1.1".to_owned()]
    } else {
        config.next_protos.clone()
    };

    let mut extensions: Vec<Box<dyn TlsExtension>> = vec![
        Box::new(SniExtension { server_name: config.server_name.clone() }),
        Box::new(SupportedCurvesExtension { curves: curves(&groups) }),
    ];
    if rng.chance(weights.extensions_append_ems) {
        extensions.push(Box::new(ExtendedMasterSecretExtension));
    }
    if rng.chance(weights.extensions_append_reneg) {
        extensions.push(Box::new(GenericExtension { id: EXTENSION_RENEGOTIATION_INFO, data: vec![0] }));
    }
    if with_alpn {
        extensions.push(Box::new(AlpnExtension { alpn_protocols: alpn_protocols.clone() }));
    }
    if rng.chance(weights.extensions_append_status) {
        extensions
            .push(Box::new(GenericExtension { id: EXTENSION_STATUS_REQUEST, data: STATUS_REQUEST_BODY.to_vec() }));
    }
    if rng.chance(weights.extensions_append_sct) {
        extensions.push(Box::new(GenericExtension { id: EXTENSION_SCT, data: Vec::new() }));
    }
    extensions.extend([
        boxed_extension(GenericExtension { id: EXTENSION_EC_POINT_FORMATS, data: vec![1, 0] }),
        boxed_extension(SignatureAlgorithmsExtension { supported_signature_algorithms: schemes(&algorithms) }),
        boxed_extension(KeyShareExtension { key_shares: key_shares(None, &shares) }),
        boxed_extension(PskKeyExchangeModesExtension { modes: vec![1] }),
        boxed_extension(SupportedVersionsExtension { versions: vec![VERSION_TLS13, VERSION_TLS12] }),
    ]);
    if with_alpn && rng.chance(weights.extensions_append_alps) {
        extensions.push(Box::new(GenericExtension {
            id: EXTENSION_APPLICATION_SETTINGS,
            data: application_settings(&alpn_protocols),
        }));
    }
    let padding = rng
        .chance(weights.extensions_append_padding)
        .then_some(PaddingPlan { target: BORING_PADDING_TARGET, index: extensions.len() });
    HelloPlan { extensions, cipher_suites, padding }
}

/// A padding extension. `length` is the body size; the four-byte extension header is
/// counted separately by [`Self::len`].
#[derive(Clone, Debug)]
pub struct PaddingExtension {
    pub length: u16,
}

impl TlsExtension for PaddingExtension {
    fn write_to_uconn(&self, _uconn: &mut UConn) -> Result<()> {
        Ok(())
    }

    fn len(&self) -> usize {
        4 + usize::from(self.length)
    }

    fn is_padding(&self) -> bool {
        true
    }

    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let mut contents = Vec::with_capacity(self.len());
        contents.extend_from_slice(&EXTENSION_PADDING.to_be_bytes());
        contents.extend_from_slice(&self.length.to_be_bytes());
        contents.resize(self.len(), 0);
        read_into(b, &contents)
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "every length field of the `ClientHello` handshake is the format's own 8-, 16- or 24-bit width"
)]
fn serialize_client_hello(hello: &PubClientHelloMsg, extensions: &[Box<dyn TlsExtension>]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&hello.vers.to_be_bytes());
    body.extend_from_slice(&hello.random);
    body.push(hello.session_id.len() as u8);
    body.extend_from_slice(&hello.session_id);
    body.extend_from_slice(&((hello.cipher_suites.len() * 2) as u16).to_be_bytes());
    for cipher_suite in &hello.cipher_suites {
        body.extend_from_slice(&cipher_suite.to_be_bytes());
    }
    body.push(hello.compression_methods.len() as u8);
    body.extend_from_slice(&hello.compression_methods);
    let mut extension_bytes = Vec::new();
    for extension in extensions {
        let mut buffer = vec![0u8; extension.len()];
        let written = extension.read(&mut buffer)?;
        let Some(payload) = buffer.get(..written) else {
            return Err(anyhow!("tls: extension wrote {written} bytes into a {} byte buffer", buffer.len()));
        };
        extension_bytes.extend_from_slice(payload);
    }
    body.extend_from_slice(&(extension_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&extension_bytes);

    let mut raw = Vec::with_capacity(4 + body.len());
    raw.push(SSLV3_HANDSHAKE_CLIENT_HELLO);
    let length = body.len() as u32;
    raw.extend_from_slice(&length.to_be_bytes()[1..]);
    raw.extend_from_slice(&body);
    Ok(raw)
}

#[must_use]
pub fn uclient(c: Box<dyn Stream>, config: Arc<Config>, fingerprint: UClientHelloID) -> UConn {
    let server_name = config.server_name.clone();
    let conn = Conn::new(true, config, server_name, c, None);
    UConn::new(conn, fingerprint)
}

#[must_use]
pub fn get_fingerprint(client_fingerprint: &str) -> (UClientHelloID, bool) {
    if client_fingerprint.is_empty() || client_fingerprint == "none" {
        return (UClientHelloID::default(), false);
    }

    if client_fingerprint == "random" {
        let fingerprint = random_fingerprint();
        debugln!("use initial random HelloID:{}", fingerprint.client);
        return (fingerprint, true);
    }

    if let Some(fingerprint) = fingerprints().get(client_fingerprint) {
        debugln!("use specified fingerprint:{}", fingerprint.client);
        (fingerprint.clone(), true)
    } else {
        warnln!("wrong clientFingerprint:{}", client_fingerprint);
        (UClientHelloID::default(), false)
    }
}

static RANDOM_FINGERPRINT: LazyLock<UClientHelloID> = LazyLock::new(|| {
    let Ok(chooser) = WeightedIndex::new([6u32, 3, 2, 1]) else {
        return UClientHelloID::default();
    };
    let names = ["chrome", "safari", "ios", "firefox"];
    let Some(&init_client) = names.get(chooser.sample(&mut rand::rng())) else {
        return UClientHelloID::default();
    };
    debugln!("initial random HelloID:{}", init_client);
    let Some(fingerprint) = fingerprints().get(init_client) else {
        warnln!("error in initial random HelloID:{}", init_client);
        return UClientHelloID::default();
    };
    fingerprint.clone()
});

fn random_fingerprint() -> UClientHelloID {
    RANDOM_FINGERPRINT.clone()
}

static FINGERPRINTS: LazyLock<HashMap<&'static str, UClientHelloID>> = LazyLock::new(|| {
    let mut fingerprints = HashMap::from([
        ("chrome", hello_chrome_auto()),
        ("firefox", hello_firefox_auto()),
        ("safari", hello_safari_auto()),
        ("ios", hello_ios_auto()),
        ("android", hello_android_11_ok_http()),
        ("edge", hello_edge_auto()),
        ("360", hello_360_auto()),
        ("qq", hello_qq_auto()),
        ("random", UClientHelloID::default()),
        ("chrome120", hello_chrome_120()),
        ("firefox120", hello_firefox_120()),
        ("safari16", hello_safari_16_0()),
        ("chrome_psk", hello_chrome_100_psk()),
        ("chrome_psk_shuffle", hello_chrome_106_shuffle()),
        ("chrome_padding_psk_shuffle", hello_chrome_114_padding_psk_shuf()),
        ("chrome_pq", hello_chrome_115_pq()),
        ("chrome_pq_psk", hello_chrome_115_pq_psk()),
        ("randomized", hello_randomized()),
    ]);
    init(&mut fingerprints);
    fingerprints
});

fn fingerprints() -> &'static HashMap<&'static str, UClientHelloID> {
    &FINGERPRINTS
}

fn init(fingerprints: &mut HashMap<&'static str, UClientHelloID>) {
    let mut weights = default_weights();
    weights.tls_vers_max_set_version_tls13 = 1.0;
    weights.first_key_share_set_curve_p256 = 0.0;
    let mut randomized = hello_randomized();
    randomized.seed = Some(new_prng_seed());
    randomized.weights = Some(weights);
    fingerprints.insert("randomized", randomized);
}

pub fn u_certificate(it: &Certificate) -> Certificate {
    Certificate {
        certificate: it.certificate.clone(),
        private_key: it.private_key.as_ref().map(PrivateKeyDer::clone_key),
        supported_signature_algorithms: map(it.supported_signature_algorithms.as_deref(), |scheme| {
            SignatureScheme(scheme.0)
        }),
        ocsp_staple: it.ocsp_staple.clone(),
        signed_certificate_timestamps: it.signed_certificate_timestamps.clone(),
        leaf: it.leaf.clone(),
    }
}

#[must_use]
pub fn u_encrypted_client_hello_key(it: &EncryptedClientHelloKey) -> EncryptedClientHelloKey {
    EncryptedClientHelloKey {
        config: it.config.clone(),
        private_key: it.private_key.clone(),
        send_as_retry: it.send_as_retry,
    }
}

#[must_use]
pub fn tls_connection_state(state: &ConnectionState) -> ConnectionState {
    ConnectionState {
        version: state.version,
        handshake_complete: state.handshake_complete,
        did_resume: state.did_resume,
        cipher_suite: state.cipher_suite,
        negotiated_protocol: state.negotiated_protocol.clone(),
        negotiated_protocol_is_mutual: state.negotiated_protocol_is_mutual,
        server_name: state.server_name.clone(),
        peer_certificates: state.peer_certificates.clone(),
        verified_chains: state.verified_chains.clone(),
        signed_certificate_timestamps: state.signed_certificate_timestamps.clone(),
        ocsp_response: state.ocsp_response.clone(),
        tls_unique: state.tls_unique.clone(),
        ech_accepted: state.ech_accepted,
        testing_only_curve_id: state.testing_only_curve_id,
    }
}

pub fn u_config(config: &Config) -> Config {
    Config {
        rand: config.rand.clone(),
        time: config.time.clone(),
        certificates: map(Some(config.certificates.as_slice()), u_certificate).unwrap_or_default(),
        get_client_certificate: config.get_client_certificate.clone(),
        verify_peer_certificate: config.verify_peer_certificate.clone(),
        root_cas: config.root_cas.clone(),
        next_protos: config.next_protos.clone(),
        server_name: config.server_name.clone(),
        client_auth: config.client_auth,
        client_cas: config.client_cas.clone(),
        insecure_skip_verify: config.insecure_skip_verify,
        cipher_suites: config.cipher_suites.clone(),
        min_version: config.min_version,
        max_version: config.max_version,
        curve_preferences: config.curve_preferences.clone(),
        session_tickets_disabled: config.session_tickets_disabled,
        renegotiation: config.renegotiation,
        key_log_writer: config.key_log_writer.clone(),
        get_certificate: config.get_certificate.clone(),
        verify_connection: config.verify_connection.clone(),
        encrypted_client_hello_config_list: Vec::new(),
        encrypted_client_hello_rejection_verify: config.encrypted_client_hello_rejection_verify.clone(),
        encrypted_client_hello_keys: map(
            Some(config.encrypted_client_hello_keys.as_slice()),
            u_encrypted_client_hello_key,
        )
        .unwrap_or_default(),
        get_encrypted_client_hello_keys: None,
        session_id_generator: None,
    }
}

pub fn build_websocket_handshake_state(c: &mut UConn) -> Result<()> {
    c.build_handshake_state()?;
    let mut has_alpn_extension = false;
    for extension in &mut c.extensions {
        if let Some(alpn) = extension.as_alpn_mut() {
            has_alpn_extension = true;
            alpn.alpn_protocols = vec!["http/1.1".to_owned()];
            break;
        }
    }
    if !has_alpn_extension {
        c.extensions.push(Box::new(AlpnExtension { alpn_protocols: vec!["http/1.1".to_owned()] }));
    }
    c.build_handshake_state()?;
    Ok(())
}

pub fn build_removed_x25519_mlkem768_handshake_state(c: &mut UConn) -> Result<()> {
    c.build_handshake_state()?;
    for extension in &mut c.extensions {
        if let Some(curves) = extension.as_supported_curves_mut() {
            curves.curves.retain(|curve| *curve != CurveId::X25519_MLKEM768);
        }
        if let Some(key_shares) = extension.as_key_share_mut() {
            key_shares.key_shares.retain(|share| share.group != CurveId::X25519_MLKEM768);
        }
    }
    c.build_handshake_state()?;
    Ok(())
}

pub fn get_tls_connection_state(conn: &dyn Any) -> ConnectionState {
    if let Some(conn) = conn.downcast_ref::<UConn>() {
        return conn.connection_state();
    }
    if let Some(conn) = conn.downcast_ref::<Conn>() {
        return conn.connection_state();
    }
    ConnectionState::default()
}

/// No `Box` implementation: erased trait objects must retain their inner `as_any` identity.
pub trait ConcreteConn: Stream {}

/// The scalar facts XTLS Vision needs from a completed TLS session, read without cloning the
/// certificate chain or the negotiated ALPN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsSessionCapability {
    pub handshake_complete: bool,
    pub version: u16,
    pub cipher_suite: u16,
}

/// Incoming plaintext buffered by TLS, drained at the XTLS read-direction switch.
///
/// `None` means the conn cannot prove a record boundary: switching would strand ciphertext
/// and must be refused.
pub trait TlsBufferedIncoming: Send + Sync {
    fn take_buffered_incoming(&self) -> Option<Vec<u8>>;
}

pub trait TlsConn: Stream {
    fn as_any(&self) -> &(dyn Any + Send + Sync);

    fn tls_connection_state(&self) -> ConnectionState {
        get_tls_connection_state(TlsConn::as_any(self))
    }

    fn tls_session_capability(&self) -> Option<TlsSessionCapability> {
        None
    }

    fn take_buffered_incoming(&mut self) -> Option<Vec<u8>> {
        None
    }

    /// Whether the raw transport under this session can be handed to XTLS direct mode. `false`
    /// keeps Vision from emitting `COMMAND_PADDING_DIRECT`.
    fn supports_raw_transport_handoff(&self) -> bool {
        false
    }
}

impl TlsConn for Conn {
    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn tls_session_capability(&self) -> Option<TlsSessionCapability> {
        self.session_capability()
    }

    fn take_buffered_incoming(&mut self) -> Option<Vec<u8>> {
        Self::take_buffered_incoming(self)
    }

    fn supports_raw_transport_handoff(&self) -> bool {
        self.shared.raw_boundary.is_some()
    }
}

impl TlsConn for UConn {
    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn tls_session_capability(&self) -> Option<TlsSessionCapability> {
        self.session_capability()
    }

    fn take_buffered_incoming(&mut self) -> Option<Vec<u8>> {
        self.take_buffered_incoming()
    }

    fn supports_raw_transport_handoff(&self) -> bool {
        true
    }
}

/// A cloneable handle over one [`TlsConn`]: the outbound chain polls it while XTLS Vision keeps a
/// second handle to drain the incoming plaintext buffered at the direct-mode switch.
pub struct SharedTlsConn {
    conn: Arc<Mutex<Box<dyn TlsConn>>>,
}

impl SharedTlsConn {
    #[must_use]
    pub fn new(conn: Box<dyn TlsConn>) -> Self {
        Self { conn: Arc::new(Mutex::new(conn)) }
    }
}

impl Clone for SharedTlsConn {
    fn clone(&self) -> Self {
        Self { conn: Arc::clone(&self.conn) }
    }
}

impl fmt::Debug for SharedTlsConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedTlsConn").finish_non_exhaustive()
    }
}

impl AsyncRead for SharedTlsConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self.conn.lock()).poll_read(cx, buf)
    }
}

impl AsyncWrite for SharedTlsConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut **self.conn.lock()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self.conn.lock()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self.conn.lock()).poll_shutdown(cx)
    }
}

impl Stream for SharedTlsConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.lock().local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.lock().peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.lock().shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.lock().shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        None
    }
}

impl TlsConn for SharedTlsConn {
    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn tls_connection_state(&self) -> ConnectionState {
        self.conn.lock().tls_connection_state()
    }

    fn tls_session_capability(&self) -> Option<TlsSessionCapability> {
        self.conn.lock().tls_session_capability()
    }

    fn take_buffered_incoming(&mut self) -> Option<Vec<u8>> {
        self.conn.lock().take_buffered_incoming()
    }

    fn supports_raw_transport_handoff(&self) -> bool {
        self.conn.lock().supports_raw_transport_handoff()
    }
}

impl TlsBufferedIncoming for SharedTlsConn {
    fn take_buffered_incoming(&self) -> Option<Vec<u8>> {
        self.conn.lock().take_buffered_incoming()
    }
}

pub struct ErasedTlsConn(pub Box<dyn Stream>);

impl fmt::Debug for ErasedTlsConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ErasedTlsConn").finish_non_exhaustive()
    }
}

impl AsyncRead for ErasedTlsConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for ErasedTlsConn {
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

impl Stream for ErasedTlsConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.0.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.0.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.0.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.0.shutdown_write()
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        self.0.old_conn()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.0.as_socket()
    }
}

impl ConcreteConn for ErasedTlsConn {}

impl TlsConn for ErasedTlsConn {
    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

pub fn generate_x25519() -> Result<StaticSecret> {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    Ok(StaticSecret::from(bytes))
}

/// Generates the ECDHE key of `curve_id`; only X25519 is supported.
pub fn generate_x25519_for_curve(curve_id: CurveId) -> Result<StaticSecret> {
    if curve_id != CurveId::X25519 {
        return Err(anyhow!(
            "unsupported Curve in KeyShareExtension: {}.To mimic it, fill the Data(key) field manually",
            curve_id.as_u16()
        ));
    }
    generate_x25519()
}

pub fn x25519_diffie_hellman(secret: &StaticSecret, public: &PublicKey) -> Result<Vec<u8>> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(anyhow!("bad X25519 remote ECDH input: low order point"));
    }
    Ok(shared.to_bytes().to_vec())
}

fn generate_mlkem_key() -> DecapsulationKey<MlKem768> {
    let mut seed = [0u8; 64];
    rand::rng().fill(&mut seed);
    DecapsulationKey::<MlKem768>::from_seed(Seed::from(seed))
}

/// A parsed X.509 certificate, reduced to the fields this crate reads.
#[derive(Clone)]
pub struct X509Certificate {
    pub raw: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Option<Arc<dyn Any + Send + Sync>>,
}

impl fmt::Debug for X509Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509Certificate")
            .field("raw", &self.raw.len())
            .field("signature", &self.signature.len())
            .field("public_key", &self.public_key.is_some())
            .finish()
    }
}

impl X509Certificate {
    /// Parses a certificate, limited to the SPKI public key and signature.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut certificate = DerReader::new(raw);
        let certificate_contents = certificate.read_any()?;
        let mut certificate = DerReader::new(certificate_contents);
        let tbs_certificate = certificate.read_any()?;
        certificate.read_any()?;
        let signature = certificate.read_bit_string()?;

        let mut tbs = DerReader::new(tbs_certificate);
        if tbs.peek_tag() == Some(0xa0) {
            tbs.read_any()?;
        }
        tbs.read_any()?;
        tbs.read_any()?;
        tbs.read_any()?;
        tbs.read_any()?;
        tbs.read_any()?;
        let subject_public_key_info = tbs.read_any()?;

        let mut spki = DerReader::new(subject_public_key_info);
        let algorithm = spki.read_any()?;
        let subject_public_key = spki.read_bit_string()?;
        let mut algorithm = DerReader::new(algorithm);
        let algorithm_oid = algorithm.read_any()?;

        let public_key: Arc<dyn Any + Send + Sync> = if algorithm_oid == ED25519_ALGORITHM_OID {
            Arc::new(Ed25519PublicKey::new(&subject_public_key)?)
        } else {
            Arc::new(CertificatePublicKeyBytes(subject_public_key))
        };
        Ok(Self { raw: raw.to_vec(), signature, public_key: Some(public_key) })
    }

    pub fn verify(&self, options: &VerifyOptions) -> Result<Vec<Vec<Arc<Self>>>> {
        let roots = match &options.roots {
            Some(roots) => Arc::clone(roots),
            None => Arc::new(system_root_store()),
        };
        let provider = crypto_provider();
        let verifier = WebPkiServerVerifier::builder_with_provider(roots, provider).build()?;
        let end_entity = CertificateDer::from(self.raw.clone());
        let intermediates: Vec<CertificateDer<'static>> =
            options.intermediates.certs.iter().map(|cert| CertificateDer::from(cert.raw.clone())).collect();
        let server_name = ServerName::try_from(options.dns_name.clone())
            .map_err(|err| anyhow!("x509: invalid DNS name {:?}: {err}", options.dns_name))?;
        let now = unix_time_of(options.current_time);
        verifier.verify_server_cert(&end_entity, &intermediates, &server_name, &[], now)?;
        let mut chain = vec![Arc::new(self.clone())];
        chain.extend(options.intermediates.certs.iter().cloned());
        Ok(vec![chain])
    }

    /// The public-key bits of the certificate's SPKI, the form a
    /// [`SignatureVerificationAlgorithm`](rustls::pki_types::SignatureVerificationAlgorithm) takes.
    pub(crate) fn subject_public_key(&self) -> Option<&[u8]> {
        let key = self.public_key.as_ref()?;
        if let Some(key) = key.downcast_ref::<Ed25519PublicKey>() {
            return Some(&key.0);
        }
        key.downcast_ref::<CertificatePublicKeyBytes>().map(|key| key.0.as_slice())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey(pub [u8; 32]);

impl Ed25519PublicKey {
    fn new(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.try_into().map_err(|_| anyhow!("x509: invalid Ed25519 public key"))?))
    }
}

/// The raw public-key bytes of the algorithms this crate does not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificatePublicKeyBytes(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct VerifyOptions {
    pub dns_name: String,
    pub intermediates: CertPool,
    pub roots: Option<Arc<RootCertStore>>,
    pub current_time: DateTime<Utc>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self { dns_name: String::new(), intermediates: CertPool::default(), roots: None, current_time: Utc::now() }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CertPool {
    pub certs: Vec<Arc<X509Certificate>>,
}

impl CertPool {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_cert(&mut self, cert: Arc<X509Certificate>) {
        self.certs.push(cert);
    }

    fn from_certificates(certs: impl IntoIterator<Item = Arc<X509Certificate>>) -> Self {
        Self { certs: certs.into_iter().collect() }
    }
}

fn unix_time_of(time: DateTime<Utc>) -> UnixTime {
    let seconds = time.timestamp();
    let nanos = time.timestamp_subsec_nanos();
    if seconds <= 0 {
        return UnixTime::since_unix_epoch(Duration::ZERO);
    }
    let duration = Duration::from_secs(seconds.cast_unsigned()) + Duration::from_nanos(u64::from(nanos));
    UnixTime::since_unix_epoch(duration)
}

struct DerReader<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    const fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    fn peek_tag(&self) -> Option<u8> {
        self.buffer.get(self.offset).copied()
    }

    fn read_any(&mut self) -> Result<&'a [u8]> {
        self.buffer.get(self.offset).ok_or_else(|| anyhow!("x509: truncated certificate"))?;
        self.offset += 1;
        let first = *self.buffer.get(self.offset).ok_or_else(|| anyhow!("x509: truncated certificate"))?;
        self.offset += 1;
        let length = if first & 0x80 == 0 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            let mut length = 0usize;
            for _ in 0..count {
                let byte = *self.buffer.get(self.offset).ok_or_else(|| anyhow!("x509: truncated certificate"))?;
                self.offset += 1;
                length = (length << 8) | usize::from(byte);
            }
            length
        };
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.buffer.len())
            .ok_or_else(|| anyhow!("x509: truncated certificate"))?;
        let contents = self.buffer.get(self.offset..end).ok_or_else(|| anyhow!("x509: truncated certificate"))?;
        self.offset = end;
        Ok(contents)
    }

    fn read_bit_string(&mut self) -> Result<Vec<u8>> {
        let contents = self.read_any()?;
        let (unused_bits, bits) = contents.split_first().ok_or_else(|| anyhow!("x509: truncated bit string"))?;
        if *unused_bits != 0 {
            return Err(anyhow!("x509: unsupported bit string padding"));
        }
        Ok(bits.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicUsize;
    use std::task::Waker;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use murmur_common::shared_conn::SharedConn;
    use murmur_common_net::io::OldConnAsStream;

    struct MockConn;

    impl AsyncRead for MockConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockConn {
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

    impl Stream for MockConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443))
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443))
        }
    }

    #[derive(Default)]
    struct WriteGate {
        paused: AtomicBool,
        waker: Mutex<Option<Waker>>,
    }

    impl WriteGate {
        fn resume(&self) {
            self.paused.store(false, Ordering::Release);
            let pending_waker = self.waker.lock().take();
            if let Some(waker) = pending_waker {
                waker.wake();
            }
        }
    }

    struct GatedSocket {
        socket: tokio::net::TcpStream,
        gate: Arc<WriteGate>,
    }

    impl AsyncRead for GatedSocket {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().socket).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for GatedSocket {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.gate.paused.load(Ordering::Acquire) {
                *this.gate.waker.lock() = Some(cx.waker().clone());
                if this.gate.paused.load(Ordering::Acquire) {
                    return Poll::Pending;
                }
            }
            Pin::new(&mut this.socket).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().socket).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().socket).poll_shutdown(cx)
        }
    }

    impl Stream for GatedSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.socket.local_addr()
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.socket.peer_addr()
        }

        fn shutdown_read(&self) -> io::Result<()> {
            Stream::shutdown_read(&self.socket)
        }

        fn shutdown_write(&self) -> io::Result<()> {
            Stream::shutdown_write(&self.socket)
        }
    }

    fn mock_config() -> Arc<Config> {
        Arc::new(Config { server_name: "example.com".to_owned(), ..Default::default() })
    }

    fn mock_uconn() -> UConn {
        uclient(Box::new(MockConn), mock_config(), hello_chrome_auto())
    }

    #[test]
    fn fingerprint_lookup_rejects_unknown_ids() {
        assert_eq!(get_fingerprint(""), (UClientHelloID::default(), false));
        assert_eq!(get_fingerprint("none"), (UClientHelloID::default(), false));
        assert_eq!(get_fingerprint("missing"), (UClientHelloID::default(), false));
    }

    #[test]
    fn fingerprint_lookup_returns_known_ids() {
        let (fingerprint, ok) = get_fingerprint("chrome");
        assert!(ok);
        assert_eq!(fingerprint.client, "Chrome");
        assert_eq!(fingerprint.version, "133");
        let (fingerprint, ok) = get_fingerprint("random");
        assert!(ok);
        let known = [hello_chrome_auto(), hello_safari_auto(), hello_ios_auto(), hello_firefox_auto()];
        assert!(known.contains(&fingerprint), "unexpected random fingerprint: {fingerprint:?}");
    }

    #[test]
    fn init_seeds_the_randomized_fingerprint() {
        let (fingerprint, ok) = get_fingerprint("randomized");
        assert!(ok);
        assert_eq!(fingerprint.client, "Randomized");
        assert!(fingerprint.seed.is_some());
        let weights = fingerprint.weights.expect("weights");
        assert_eq!(weights.tls_vers_max_set_version_tls13, 1.0);
        assert_eq!(weights.first_key_share_set_curve_p256, 0.0);
    }

    #[test]
    fn build_handshake_state_writes_the_session_id_at_offset_39() {
        let mut conn = mock_uconn();
        conn.build_handshake_state().expect("build handshake state");
        let hello = &conn.handshake_state.hello;
        assert_eq!(hello.session_id.len(), CLIENT_SESSION_ID_LEN);
        assert_eq!(hello.raw[0], SSLV3_HANDSHAKE_CLIENT_HELLO);
        assert_eq!(&hello.raw[39..39 + CLIENT_SESSION_ID_LEN], hello.session_id.as_slice());
        assert_eq!(hello.server_name, "example.com");
        assert_eq!(hello.supported_versions.len(), 3, "Chrome leads supported_versions with a GREASE version");

        let keys = conn.handshake_state.state13.key_share_keys.as_ref().expect("key share keys");
        let hybrid = keys.share(CurveId::X25519_MLKEM768).expect("hybrid share");
        assert!(hybrid.ecdhe.is_some());
        assert!(hybrid.mlkem.is_some());
        assert!(keys.share(CurveId::X25519).expect("x25519 share").ecdhe.is_some());

        let key_shares =
            conn.extensions.iter().find_map(|extension| extension.as_key_share()).expect("key share extension");
        let hybrid =
            key_shares.key_shares.iter().find(|share| share.group == CurveId::X25519_MLKEM768).expect("hybrid share");
        assert_eq!(hybrid.data.len(), 1184 + 32);
        let x25519 = key_shares.key_shares.iter().find(|share| share.group == CurveId::X25519).expect("x25519 share");
        assert_eq!(x25519.data.len(), 32);
        let grease = key_shares.key_shares.iter().find(|share| is_grease(share.group.as_u16())).expect("grease share");
        assert_eq!(grease.data, vec![0u8]);
    }

    #[test]
    fn build_handshake_state_applies_session_id_generator() {
        let seen = Arc::new(Mutex::new(0usize));
        let seen_clone = Arc::clone(&seen);
        let generator: SessionIdGeneratorFn = Arc::new(move |client_hello, session_id| {
            assert_eq!(&client_hello[39..39 + CLIENT_SESSION_ID_LEN], &[0u8; CLIENT_SESSION_ID_LEN][..]);
            session_id.fill(0xab);
            *seen_clone.lock() += 1;
            Ok(())
        });
        let config = Arc::new(Config {
            server_name: "example.com".to_owned(),
            session_id_generator: Some(generator),
            ..Default::default()
        });
        let mut conn = uclient(Box::new(MockConn), config, hello_chrome_auto());
        conn.build_handshake_state().expect("build handshake state");
        assert_eq!(conn.handshake_state.hello.session_id, vec![0xabu8; CLIENT_SESSION_ID_LEN]);
        assert_eq!(
            &conn.handshake_state.hello.raw[39..39 + CLIENT_SESSION_ID_LEN],
            &[0xabu8; CLIENT_SESSION_ID_LEN][..]
        );
        assert_eq!(*seen.lock(), 1);
    }

    #[test]
    fn build_websocket_handshake_state_forces_http11_alpn() {
        let config = Arc::new(Config {
            server_name: "example.com".to_owned(),
            next_protos: vec!["h2".to_owned()],
            ..Default::default()
        });
        let mut conn = uclient(Box::new(MockConn), config, hello_chrome_auto());
        build_websocket_handshake_state(&mut conn).expect("build websocket handshake state");
        let alpn = conn.extensions.iter().find_map(|extension| extension.as_alpn()).expect("alpn extension");
        assert_eq!(alpn.alpn_protocols, vec!["http/1.1".to_owned()]);
        assert_eq!(conn.handshake_state.hello.alpn_protocols, vec!["http/1.1".to_owned()]);
        assert_eq!(*conn.conn.shared.next_protos_override.lock(), Some(vec!["http/1.1".to_owned()]));
    }

    #[test]
    fn build_removed_mlkem_handshake_state_drops_the_hybrid_share() {
        let mut conn = mock_uconn();
        build_removed_x25519_mlkem768_handshake_state(&mut conn).expect("remove mlkem");
        let curves = conn
            .extensions
            .iter()
            .find_map(|extension| extension.as_supported_curves())
            .expect("supported curves extension");
        assert!(!curves.curves.contains(&CurveId::X25519_MLKEM768));
        let key_shares =
            conn.extensions.iter().find_map(|extension| extension.as_key_share()).expect("key share extension");
        let groups: Vec<CurveId> =
            key_shares.key_shares.iter().map(|share| share.group).filter(|group| !is_grease(group.as_u16())).collect();
        assert_eq!(groups, vec![CurveId::X25519]);
        let keys = conn.handshake_state.state13.key_share_keys.as_ref().expect("key share keys");
        assert!(keys.share(CurveId::X25519).expect("x25519 share").ecdhe.is_some());
    }

    #[test]
    fn u_config_copies_the_shared_fields() {
        let config = Config {
            server_name: "example.com".to_owned(),
            insecure_skip_verify: true,
            next_protos: vec!["h2".to_owned()],
            min_version: VERSION_TLS13,
            max_version: VERSION_TLS13,
            session_tickets_disabled: true,
            cipher_suites: Some(vec![0x1301]),
            curve_preferences: Some(vec![CurveId::X25519]),
            encrypted_client_hello_config_list: vec![1, 2, 3],
            get_encrypted_client_hello_keys: Some(Arc::new(|_: &ClientHelloInfo| Ok(Vec::new()))),
            ..Default::default()
        };
        let converted = u_config(&config);
        assert_eq!(converted.server_name, "example.com");
        assert!(converted.insecure_skip_verify);
        assert_eq!(converted.next_protos, vec!["h2".to_owned()]);
        assert_eq!(converted.min_version, VERSION_TLS13);
        assert!(converted.session_tickets_disabled);
        assert!(converted.encrypted_client_hello_config_list.is_empty());
        assert!(converted.get_encrypted_client_hello_keys.is_none());
        let certificates = vec![Certificate::default()];
        assert_eq!(u_config(&Config { certificates, ..Default::default() }).certificates.len(), 1);
    }

    #[test]
    fn client_hello_serialization_places_the_session_id_at_offset_39() {
        let hello = PubClientHelloMsg {
            vers: VERSION_TLS12,
            random: vec![7u8; HANDHELLO_RANDOM_LEN],
            session_id: vec![9u8; CLIENT_SESSION_ID_LEN],
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            ..Default::default()
        };
        let raw = serialize_client_hello(&hello, &[]).expect("serialize");
        assert_eq!(raw[0], SSLV3_HANDSHAKE_CLIENT_HELLO);
        assert_eq!(&raw[39..39 + CLIENT_SESSION_ID_LEN], &[9u8; CLIENT_SESSION_ID_LEN]);
        assert_eq!(raw.len(), 4 + 2 + 32 + 1 + 32 + 2 + 2 + 1 + 1 + 2);
    }

    #[test]
    fn sni_extension_omits_ip_names_and_strips_trailing_dots() {
        assert_eq!(hostname_in_sni("example.com"), "example.com");
        assert_eq!(hostname_in_sni("192.0.2.1"), "");
        assert_eq!(hostname_in_sni("example.com."), "example.com");
        assert_eq!(hostname_in_sni("[2001:db8::1]"), "");
    }

    #[test]
    fn ecdh_agrees_on_the_shared_secret() {
        let alice = generate_x25519().expect("alice key");
        let bob = generate_x25519().expect("bob key");
        assert_eq!(
            x25519_diffie_hellman(&alice, &PublicKey::from(&bob)).expect("alice shared"),
            x25519_diffie_hellman(&bob, &PublicKey::from(&alice)).expect("bob shared")
        );
    }

    #[test]
    fn x25519_matches_rfc_7748_test_vectors() {
        // RFC 7748 §5.2, X25519 test vector #1.
        let scalar: [u8; 32] = hex::decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes");
        let u: [u8; 32] = hex::decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes");
        let expected =
            hex::decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552").expect("valid hex");
        let secret = StaticSecret::from(scalar);
        let shared = secret.diffie_hellman(&PublicKey::from(u));
        assert_eq!(shared.to_bytes().to_vec(), expected);

        // RFC 7748 §5.2, X25519 test vector #2.
        let scalar2: [u8; 32] = hex::decode("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes");
        let u2: [u8; 32] = hex::decode("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes");
        let expected2 =
            hex::decode("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957").expect("valid hex");
        let secret2 = StaticSecret::from(scalar2);
        let shared2 = secret2.diffie_hellman(&PublicKey::from(u2));
        assert_eq!(shared2.to_bytes().to_vec(), expected2);
    }

    #[test]
    fn tls_conn_as_any_reaches_the_boxed_conn_not_the_box() {
        let boxed: Box<dyn TlsConn> = Box::new(mock_uconn());
        assert!(TlsConn::as_any(&*boxed).downcast_ref::<UConn>().is_some(), "expected UConn, got the box");
        let boxed: Box<dyn TlsConn> = Box::new(client(Box::new(MockConn), mock_config()));
        assert!(TlsConn::as_any(&*boxed).downcast_ref::<Conn>().is_some(), "expected Conn, got the box");
        let boxed: Box<dyn TlsConn> = Box::new(ErasedTlsConn(Box::new(MockConn)));
        assert!(
            TlsConn::as_any(&*boxed).downcast_ref::<ErasedTlsConn>().is_some(),
            "expected ErasedTlsConn, got the box"
        );
    }

    #[tokio::test]
    async fn close_write_reaches_the_wrapped_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client_task = tokio::spawn(tokio::net::TcpStream::connect(addr));
        let (server_stream, _) = listener.accept().await.expect("accept");
        let mut client_stream = client_task.await.expect("join").expect("connect");

        let conn = server(Box::new(server_stream), mock_config());
        conn.shutdown_write().expect("shutdown_write");

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), client_stream.read(&mut buf))
            .await
            .expect("bounded read")
            .expect("read after peer half-close");
        assert_eq!(n, 0, "expected EOF after write-side shutdown");
    }

    fn tls_server_config() -> Arc<Config> {
        use rustls::pki_types::pem::PemObject;

        let cert = CertificateDer::from_pem_slice(include_bytes!("../../common-net/src/testdata/stutter_tls_cert.pem"))
            .expect("fixture certificate");
        let key = PrivateKeyDer::from_pem_slice(include_bytes!("../../common-net/src/testdata/stutter_tls_key.pem"))
            .expect("fixture key");
        Arc::new(Config {
            certificates: vec![Certificate {
                certificate: vec![cert.as_ref().to_vec()],
                private_key: Some(key),
                ..Default::default()
            }],
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn shutdown_read_keeps_tls_write_half_open() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut conn = server(Box::new(socket), tls_server_config());
            conn.handshake().await.expect("server handshake");
            conn.shutdown_read().expect("shutdown read half");
            conn.write_all(b"write half remains open").await.expect("server write");
            conn.close().expect("close tls");
        });
        let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut peer = client(
            Box::new(socket),
            Arc::new(Config { server_name: "localhost".into(), insecure_skip_verify: true, ..Default::default() }),
        );
        tokio::time::timeout(Duration::from_secs(2), peer.handshake())
            .await
            .expect("bounded handshake")
            .expect("client handshake");
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut received))
            .await
            .expect("bounded tls read")
            .expect("tls read");
        assert_eq!(received, b"write half remains open");
        tokio::time::timeout(Duration::from_secs(2), server_task).await.expect("bounded server").expect("server task");
    }

    #[tokio::test]
    async fn close_stream_drains_tls_ciphertext_outside_runtime() {
        let config = tls_server_config();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut conn = server(Box::new(socket), config);
            conn.handshake().await.expect("server handshake");
            conn.write_all(b"ciphertext must drain").await.expect("server write");
            std::thread::spawn(move || close_stream(&conn))
                .join()
                .expect("close thread")
                .expect("close tls through private view");
        });
        let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut client = client(
            Box::new(socket),
            Arc::new(Config { server_name: "localhost".into(), insecure_skip_verify: true, ..Default::default() }),
        );
        tokio::time::timeout(Duration::from_secs(2), client.handshake())
            .await
            .expect("bounded handshake")
            .expect("client handshake");
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut received))
            .await
            .expect("bounded tls read")
            .expect("tls read");
        assert_eq!(received, b"ciphertext must drain");
        tokio::time::timeout(Duration::from_secs(2), server_task).await.expect("bounded server").expect("server task");
    }

    #[tokio::test]
    async fn shutdown_write_drains_tls_and_keeps_read_half_open() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut conn = server(Box::new(socket), tls_server_config());
            conn.handshake().await.expect("server handshake");
            conn.write_all(b"one-way message").await.expect("server write");
            conn.shutdown_write().expect("shutdown write half");
            assert!(conn.write_all(b"not delivered").await.is_err(), "write after half-close must fail");
            let mut reply = [0u8; 5];
            tokio::time::timeout(Duration::from_secs(2), conn.read_exact(&mut reply))
                .await
                .expect("bounded server read")
                .expect("server read");
            assert_eq!(&reply, b"reply");
            conn.close().expect("close tls");
        });
        let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut peer = client(
            Box::new(socket),
            Arc::new(Config { server_name: "localhost".into(), insecure_skip_verify: true, ..Default::default() }),
        );
        tokio::time::timeout(Duration::from_secs(2), peer.handshake())
            .await
            .expect("bounded handshake")
            .expect("client handshake");
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut received))
            .await
            .expect("bounded tls read")
            .expect("tls read");
        assert_eq!(received, b"one-way message");
        peer.write_all(b"reply").await.expect("client reply");
        tokio::time::timeout(Duration::from_secs(2), server_task).await.expect("bounded server").expect("server task");
    }

    #[tokio::test]
    async fn shutdown_write_reads_reply_while_ciphertext_is_backpressured() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let gate = Arc::new(WriteGate::default());
        let server_gate = Arc::clone(&gate);
        let (read_reply, received_reply) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut conn =
                server(Box::new(GatedSocket { socket, gate: Arc::clone(&server_gate) }), tls_server_config());
            conn.handshake().await.expect("server handshake");
            server_gate.paused.store(true, Ordering::Release);
            conn.write_all(b"request body").await.expect("write buffered TLS plaintext");
            conn.shutdown_write().expect("shutdown write half");
            let mut reply = [0u8; 5];
            tokio::time::timeout(Duration::from_secs(2), conn.read_exact(&mut reply))
                .await
                .expect("read reply before ciphertext drains")
                .expect("read reply");
            assert_eq!(&reply, b"reply");
            read_reply.send(()).expect("send reply observation");
            conn.close().expect("close tls");
        });
        let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut peer = client(
            Box::new(socket),
            Arc::new(Config { server_name: "localhost".into(), insecure_skip_verify: true, ..Default::default() }),
        );
        tokio::time::timeout(Duration::from_secs(2), peer.handshake())
            .await
            .expect("bounded handshake")
            .expect("client handshake");
        peer.write_all(b"reply").await.expect("write reply before reading response");
        tokio::time::timeout(Duration::from_secs(2), received_reply)
            .await
            .expect("server must read reply before gate opens")
            .expect("server reply observation");
        gate.resume();
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut received))
            .await
            .expect("bounded TLS read")
            .expect("TLS read");
        assert_eq!(received, b"request body");
        tokio::time::timeout(Duration::from_secs(2), server_task).await.expect("bounded server").expect("server task");
    }

    #[tokio::test]
    async fn set_read_deadline_reaches_the_wrapped_conn() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client_stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (server_stream, _) = listener.accept().await.expect("accept");

        let extended = murmur_common_net::new_extended_conn(server_stream);
        let deadline_conn = murmur_common_net::deadline::conn::new_conn(extended);
        let conn = server(Box::new(OldConnAsStream(deadline_conn)), mock_config());
        conn.old_conn()
            .expect("close view")
            .set_read_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(50)))
            .expect("set read deadline");

        let result = tokio::time::timeout(Duration::from_secs(2), conn.handshake()).await;
        drop(client_stream);
        assert!(result.is_ok(), "handshake must observe the wrapped conn's read deadline instead of hanging");
        assert!(result.unwrap().is_err(), "handshake must fail once the wrapped conn's read deadline fires");
    }

    #[test]
    fn alpn_extension_is_emitted_only_when_protocols_are_configured() {
        let configured = alpn_extension(&Config { next_protos: vec!["h2".to_owned()], ..Default::default() })
            .expect("alpn extension");
        assert_eq!(configured.len(), 4 + 2 + 1 + 2);
        assert!(alpn_extension(&Config::default()).is_none());
    }

    #[test]
    fn alpn_extension_carries_a_non_empty_protocol_name_list() {
        let extension = alpn_extension(&Config { next_protos: vec!["h2".to_owned()], ..Default::default() })
            .expect("alpn extension");
        let mut bytes = vec![0u8; extension.len()];
        extension.read(&mut bytes).expect("read extension");

        assert_eq!(bytes, vec![0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2']);
    }

    #[test]
    fn configured_alpn_reaches_the_client_hello() {
        let config = Arc::new(Config {
            server_name: "example.com".to_owned(),
            next_protos: vec!["h2".to_owned()],
            ..Default::default()
        });
        let mut conn = uclient(Box::new(MockConn), config, hello_chrome_auto());
        conn.build_handshake_state().expect("build handshake state");

        assert_eq!(conn.handshake_state.hello.alpn_protocols, vec!["h2".to_owned()]);
        assert_eq!(*conn.conn.shared.next_protos_override.lock(), Some(vec!["h2".to_owned()]));
        let raw = &conn.handshake_state.hello.raw;
        assert!(raw.windows(3).any(|window| window == [0x00, 0x10, 0x00]), "the ALPN extension must be on the wire");
    }

    /// The extension ids in wire order. Every preset test compares against the extension list the
    /// id models.
    fn client_hello_extension_ids(raw: &[u8]) -> Vec<u16> {
        let mut offset = 4 + 2 + HANDHELLO_RANDOM_LEN;
        offset += 1 + usize::from(raw[offset]);
        let cipher_suites_len = usize::from(u16::from_be_bytes([raw[offset], raw[offset + 1]]));
        offset += 2 + cipher_suites_len;
        offset += 1 + usize::from(raw[offset]);
        let extensions_len = usize::from(u16::from_be_bytes([raw[offset], raw[offset + 1]]));
        offset += 2;
        let end = offset + extensions_len;
        let mut ids = Vec::new();
        while offset + 4 <= end {
            ids.push(u16::from_be_bytes([raw[offset], raw[offset + 1]]));
            let body = usize::from(u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]));
            offset += 4 + body;
        }
        ids
    }

    /// The body of the first `id` extension, so an extension's encoding can be pinned, not just its
    /// presence.
    fn client_hello_extension_body(raw: &[u8], id: u16) -> Option<Vec<u8>> {
        let mut offset = 4 + 2 + HANDHELLO_RANDOM_LEN;
        offset += 1 + usize::from(raw[offset]);
        let cipher_suites_len = usize::from(u16::from_be_bytes([raw[offset], raw[offset + 1]]));
        offset += 2 + cipher_suites_len;
        offset += 1 + usize::from(raw[offset]);
        let extensions_len = usize::from(u16::from_be_bytes([raw[offset], raw[offset + 1]]));
        offset += 2;
        let end = offset + extensions_len;
        while offset + 4 <= end {
            let extension_id = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
            let body = usize::from(u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]));
            if extension_id == id {
                return Some(raw[offset + 4..offset + 4 + body].to_vec());
            }
            offset += 4 + body;
        }
        None
    }

    fn built_extension_ids(fingerprint: UClientHelloID) -> Vec<u16> {
        let config = Arc::new(Config {
            server_name: "example.com".to_owned(),
            next_protos: vec!["h2".to_owned(), "http/1.1".to_owned()],
            ..Default::default()
        });
        let mut conn = uclient(Box::new(MockConn), config, fingerprint);
        conn.build_handshake_state().expect("build handshake state");
        client_hello_extension_ids(&conn.handshake_state.hello.raw)
    }

    /// GREASE values and the `padding` extension are deliberately heap-placed, so a shape is
    /// compared without them.
    fn significant_extension_ids(ids: &[u16]) -> Vec<u16> {
        ids.iter().copied().filter(|id| !is_grease(*id) && *id != EXTENSION_PADDING).collect()
    }

    /// The default hello, built over an in-memory pipe with a session-cache-less
    /// config: `server_name`, `ec_point_formats`, `renegotiation_info`, `extended_master_secret`,
    /// SCT, `status_request`, `supported_groups`, `signature_algorithms`, ALPN,
    /// `supported_versions`, `key_share`.
    #[test]
    fn default_client_hello_matches_the_default_extension_order() {
        let config = Arc::new(Config {
            server_name: "example.com".to_owned(),
            next_protos: vec!["h2".to_owned(), "http/1.1".to_owned()],
            ..Default::default()
        });
        let mut conn = uclient(Box::new(MockConn), config, hello_default());
        conn.build_handshake_state().expect("build handshake state");

        assert_eq!(
            client_hello_extension_ids(&conn.handshake_state.hello.raw),
            vec![0, 11, 0xff01, 23, 18, 5, 10, 13, 16, 43, 51]
        );
        assert_eq!(
            conn.handshake_state.hello.cipher_suites,
            vec![
                0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x1301, 0x1302, 0x1303
            ]
        );
        let curves =
            conn.extensions.iter().find_map(|extension| extension.as_supported_curves()).expect("supported curves");
        assert_eq!(
            curves.curves,
            vec![CurveId::X25519_MLKEM768, CurveId::X25519, CurveId(23), CurveId(24), CurveId(25)]
        );
        assert_eq!(conn.handshake_state.hello.supported_versions, vec![VERSION_TLS13, VERSION_TLS12]);
        assert_eq!(
            client_hello_extension_body(&conn.handshake_state.hello.raw, EXTENSION_EC_POINT_FORMATS).as_deref(),
            Some([1u8, 0].as_slice()),
            "ec_point_formats is a length-prefixed list, not a bare point"
        );
    }

    /// The default hello keeps `BUILTIN_SIGNATURE_ALGORITHMS`, which the Chrome shapes
    /// do not share.
    #[test]
    fn default_client_hello_offers_the_default_signature_algorithms() {
        let config = Arc::new(Config { server_name: "example.com".to_owned(), ..Default::default() });
        let mut conn = uclient(Box::new(MockConn), config, hello_default());
        conn.build_handshake_state().expect("build handshake state");

        assert_eq!(
            conn.handshake_state
                .hello
                .supported_signature_algorithms
                .iter()
                .map(|scheme| scheme.0)
                .collect::<Vec<u16>>(),
            vec![0x0804, 0x0403, 0x0807, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0503, 0x0603, 0x0201, 0x0203]
        );
    }

    /// The three randomized ids only differ by their ALPN policy: `always` advertises ALPN,
    /// `never` never does, and `coin` flips the `extensions_append_alpn` weight.
    #[test]
    fn randomized_alpn_follows_the_id_not_the_stream() {
        fn fingerprint(client: &str, alpn: f64) -> UClientHelloID {
            let mut weights = default_weights();
            weights.extensions_append_alpn = alpn;
            weights.extensions_append_alps = 1.0;
            UClientHelloID {
                client: client.to_owned(),
                version: "0".to_owned(),
                seed: Some([7u8; PRNG_SEED_LENGTH]),
                weights: Some(weights),
            }
        }
        fn has_alpn(client: &str, alpn: f64) -> bool {
            built_extension_ids(fingerprint(client, alpn)).contains(&16)
        }

        assert!(has_alpn("Randomized-ALPN", 0.0), "an ALPN-forced id ignores the weight");
        assert!(!has_alpn("Randomized-NoALPN", 1.0), "an ALPN-less id ignores the weight");
        assert!(!has_alpn("Randomized", 0.0), "the coin decides for HelloRandomized");
        assert!(has_alpn("Randomized", 1.0), "the coin decides for HelloRandomized");
        assert!(built_extension_ids(fingerprint("Randomized-NoALPN", 1.0)).contains(&10));
        assert!(
            !built_extension_ids(fingerprint("Randomized-NoALPN", 1.0)).contains(&EXTENSION_APPLICATION_SETTINGS),
            "ALPS is TLS 1.3 + ALPN only"
        );
    }

    #[test]
    fn browser_preset_extension_shapes_are_pinned() {
        let cases: &[(&str, UClientHelloID, &[u16])] = &[
            ("default", hello_default(), &[0, 11, 0xff01, 23, 18, 5, 10, 13, 16, 43, 51]),
            ("chrome", hello_chrome_133(), &[0, 23, 0xff01, 10, 35, 16, 5, 13, 51, 45, 43, 17613]),
            ("chrome120", hello_chrome_120(), &[0, 23, 0xff01, 10, 35, 16, 5, 13, 51, 45, 43, 17513]),
            ("firefox", hello_firefox_120(), &[0, 23, 10, 51, 13, 43, 45, 35, 16, 5, 0xff01, 11, 28]),
            ("safari", hello_safari_16_0(), &[0, 23, 10, 11, 16, 5, 13, 51, 45, 43]),
            ("ios", hello_ios_14(), &[0, 23, 10, 11, 16, 5, 13, 51, 45, 43]),
            ("android", hello_android_11_ok_http(), &[0, 23, 16, 5, 10, 13, 51, 43, 45, 35]),
            ("edge", hello_edge_85(), &[0, 23, 0xff01, 10, 35, 16, 5, 13, 51, 45, 43]),
            ("360", hello_360_7_5(), &[0, 23, 0xff01, 10, 35, 16, 5, 13, 51, 45, 43]),
            ("qq", hello_qq_11_1(), &[0, 23, 0xff01, 10, 35, 16, 5, 13, 51, 45, 43]),
            ("custom", hello_custom(), &[]),
        ];
        for (name, fingerprint, expected) in cases {
            let ids = built_extension_ids(fingerprint.clone());
            assert_eq!(significant_extension_ids(&ids), *expected, "{name}");
            assert!(!ids.contains(&50), "{name} must not invent signature_algorithms_cert");
        }
    }

    /// ALPS is a Chromium extension: only the modern Chrome shape carries it, and a preset without
    /// ALPN must not advertise it either.
    #[test]
    fn alps_belongs_to_the_chrome_shape_only() {
        let ids = built_extension_ids(hello_chrome_133());
        assert!(ids.contains(&EXTENSION_APPLICATION_SETTINGS_NEW), "chrome 133 uses the new ALPS code point");
        let ids = built_extension_ids(hello_chrome_120());
        assert!(ids.contains(&EXTENSION_APPLICATION_SETTINGS), "chrome 120 uses the old ALPS code point");
        for fingerprint in
            [hello_firefox_120(), hello_safari_16_0(), hello_ios_14(), hello_android_11_ok_http(), hello_edge_85()]
        {
            let ids = built_extension_ids(fingerprint);
            assert!(
                !ids.contains(&EXTENSION_APPLICATION_SETTINGS) && !ids.contains(&EXTENSION_APPLICATION_SETTINGS_NEW)
            );
        }
    }

    #[test]
    fn padding_follows_boring_padding_style() {
        fn padded(cipher_suites: usize) -> Vec<u8> {
            let mut conn = mock_uconn();
            conn.handshake_state.hello = PubClientHelloMsg {
                vers: VERSION_TLS12,
                random: vec![0u8; HANDHELLO_RANDOM_LEN],
                session_id: vec![0u8; CLIENT_SESSION_ID_LEN],
                cipher_suites: vec![0x1301; cipher_suites],
                compression_methods: vec![0],
                ..Default::default()
            };
            conn.extensions = vec![Box::new(SniExtension { server_name: "example.com".to_owned() })];
            conn.padding = Some(PaddingPlan { target: BORING_PADDING_TARGET, index: 1 });
            conn.apply_padding().expect("padding");
            serialize_client_hello(&conn.handshake_state.hello, &conn.extensions).expect("serialize")
        }

        let short = padded(102);
        assert_eq!(client_hello_extension_ids(&short), vec![0, EXTENSION_PADDING]);
        assert_eq!(short.len(), BORING_PADDING_TARGET);

        let long = padded(210);
        assert_eq!(client_hello_extension_ids(&long), vec![0], "a hello over the target is left alone");

        let tiny = padded(1);
        assert_eq!(client_hello_extension_ids(&tiny), vec![0], "a hello of at most 0xff is left alone");
    }

    #[test]
    fn default_client_hello_carries_default_extensions() {
        let config = Arc::new(Config {
            server_name: "example.com".to_owned(),
            next_protos: vec!["h2".to_owned()],
            ..Default::default()
        });
        let mut conn = uclient(Box::new(MockConn), config, hello_default());
        conn.build_handshake_state().expect("build handshake state");

        assert!(conn.extensions.iter().any(|extension| extension.as_alpn().is_some()), "ALPN must be offered");
        assert!(
            conn.extensions.iter().any(|extension| extension.as_key_share().is_some()),
            "a key share must be offered"
        );
        assert!(
            conn.extensions.iter().any(|extension| extension.as_supported_curves().is_some()),
            "the supported curves must be offered"
        );
        assert!(
            conn.handshake_state.state13.key_share_keys.as_ref().is_some_and(|keys| !keys.shares.is_empty()),
            "the offered key share must carry its private keys"
        );
        assert!(
            conn.handshake_state.hello.raw.windows(3).any(|window| window == [0x00, 0x10, 0x00]),
            "the ALPN extension must be on the wire"
        );
    }

    #[test]
    fn alps_body_is_a_uint16_length_prefixed_protocol_name_list() {
        let body = application_settings(&["h2".to_owned(), "http/1.1".to_owned()]);

        assert_eq!(body, vec![0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']);
    }

    #[tokio::test]
    async fn fingerprinted_handshake_completes_and_carries_alpn() {
        use rustls::pki_types::pem::PemObject;

        let cert = CertificateDer::from_pem_slice(include_bytes!("../../common-net/src/testdata/stutter_tls_cert.pem"))
            .expect("fixture certificate");
        let key = PrivateKeyDer::from_pem_slice(include_bytes!("../../common-net/src/testdata/stutter_tls_key.pem"))
            .expect("fixture key");
        let server_config =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("server config");
        let mut server_config = server_config;
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut stream = acceptor.accept(socket).await.expect("server handshake");
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            let mut received = [0u8; 5];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
                .await
                .expect("server read timeout")
                .expect("server read");
            assert_eq!(&received, b"hello");
        });

        let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let config = Arc::new(Config {
            server_name: "localhost".to_owned(),
            next_protos: vec!["h2".to_owned()],
            insecure_skip_verify: true,
            ..Default::default()
        });
        let mut conn = uclient(Box::new(socket), config, hello_chrome_auto());
        tokio::time::timeout(Duration::from_secs(5), conn.handshake_context(&CancellationToken::new()))
            .await
            .expect("bounded fingerprinted handshake")
            .expect("fingerprinted handshake");
        tokio::time::timeout(Duration::from_secs(5), conn.write_all(b"hello"))
            .await
            .expect("client write timeout")
            .expect("client write");

        assert_eq!(conn.connection_state().negotiated_protocol, "h2");
        assert!(conn.connection_state().negotiated_protocol_is_mutual);

        tokio::time::timeout(Duration::from_secs(5), server_task).await.expect("bounded server").expect("server task");
    }

    struct ScriptedStream {
        bytes: Vec<u8>,
        read: Arc<AtomicUsize>,
    }

    impl AsyncRead for ScriptedStream {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let start = this.read.load(Ordering::Acquire);
            let n = (this.bytes.len() - start).min(buf.remaining());
            buf.put_slice(&this.bytes[start..start + n]);
            this.read.store(start + n, Ordering::Release);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedStream {
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

    impl Stream for ScriptedStream {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443))
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443))
        }
    }

    fn wire_record(body: &[u8]) -> Vec<u8> {
        let mut record = vec![0x17, 0x03, 0x03];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(body);
        record
    }

    fn boundary_stream(inner: Box<dyn Stream>, probe: &Arc<RawBoundaryProbe>) -> RecordBoundaryStream {
        RecordBoundaryStream {
            inner,
            probe: Arc::clone(probe),
            header: [0; RECORD_HEADER_LEN],
            header_filled: 0,
            header_delivered: 0,
            body_remaining: 0,
            pause_next: false,
        }
    }

    /// The reader must hand the engine the record it is delivering and nothing after it, so the
    /// bytes a direct-mode switch takes over are still unread on the transport.
    #[test]
    fn record_boundary_reader_stops_at_the_record_before_a_handoff() {
        let consumed = Arc::new(AtomicUsize::new(0));
        let mut wire = wire_record(&[0xAA, 0xBB]);
        wire.extend_from_slice(b"RAW!");
        let probe = Arc::new(RawBoundaryProbe::new());
        let inner = Box::new(ScriptedStream { bytes: wire, read: Arc::clone(&consumed) });
        let mut stream = boundary_stream(inner, &probe);

        let mut cx = Context::from_waker(Waker::noop());
        let mut buf = [0u8; 64];
        let mut read_buf = ReadBuf::new(&mut buf);
        assert!(Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf).is_ready());
        assert_eq!(read_buf.filled(), [0x17, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB].as_slice());
        assert_eq!(consumed.load(Ordering::Acquire), 7, "no byte after the record may be read");
        assert!(probe.at_boundary(), "a delivered record leaves the reader at a boundary");
    }

    /// One record per poll: the poll after a complete record must not start the next one.
    #[test]
    fn record_boundary_reader_pauses_once_between_records() {
        let consumed = Arc::new(AtomicUsize::new(0));
        let mut wire = wire_record(&[0xAA]);
        wire.extend_from_slice(&wire_record(&[0xBB]));
        let probe = Arc::new(RawBoundaryProbe::new());
        let inner = Box::new(ScriptedStream { bytes: wire, read: Arc::clone(&consumed) });
        let mut stream = boundary_stream(inner, &probe);
        let mut cx = Context::from_waker(Waker::noop());

        let mut first_buf = [0u8; 64];
        let mut first = ReadBuf::new(&mut first_buf);
        assert!(Pin::new(&mut stream).poll_read(&mut cx, &mut first).is_ready());
        assert_eq!(first.filled(), [0x17, 0x03, 0x03, 0x00, 0x01, 0xAA].as_slice());

        let mut paused_buf = [0u8; 64];
        let mut paused = ReadBuf::new(&mut paused_buf);
        assert!(Pin::new(&mut stream).poll_read(&mut cx, &mut paused).is_pending());
        assert!(paused.filled().is_empty());
        assert_eq!(consumed.load(Ordering::Acquire), 6, "the pause must not read the next record");
        assert!(probe.at_boundary());

        let mut second_buf = [0u8; 64];
        let mut second = ReadBuf::new(&mut second_buf);
        assert!(Pin::new(&mut stream).poll_read(&mut cx, &mut second).is_ready());
        assert_eq!(second.filled(), [0x17, 0x03, 0x03, 0x00, 0x01, 0xBB].as_slice());
        assert_eq!(consumed.load(Ordering::Acquire), 12);
    }

    /// With a real `rustls` session, the plaintext the engine has not delivered is drained for the
    /// switch while the raw bytes written after the last record stay on the socket.
    #[tokio::test]
    async fn raw_handoff_rustls_client_keeps_the_suffixed_raw_bytes_for_the_switch() {
        use rustls::pki_types::pem::PemObject;

        let cert = CertificateDer::from_pem_slice(include_bytes!("../../common-net/src/testdata/stutter_tls_cert.pem"))
            .expect("fixture certificate");
        let key = PrivateKeyDer::from_pem_slice(include_bytes!("../../common-net/src/testdata/stutter_tls_key.pem"))
            .expect("fixture key");
        let server_config =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut stream = acceptor.accept(socket).await.expect("server handshake");
            stream.write_all(b"hello").await.expect("server write");
            stream.flush().await.expect("server flush");
            stream.get_mut().0.write_all(b"RAW!").await.expect("raw suffix");
            stream.get_mut().0.flush().await.expect("raw flush");
        });

        let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let raw = SharedConn::from_boxed(Box::new(socket));
        let config =
            Arc::new(Config { server_name: "localhost".to_owned(), insecure_skip_verify: true, ..Default::default() });
        let mut conn = client_with_raw_handoff(Box::new(raw.clone()), config);
        tokio::time::timeout(Duration::from_secs(5), conn.handshake_context(&CancellationToken::new()))
            .await
            .expect("bounded handshake")
            .expect("handshake");

        let mut hello = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut hello))
            .await
            .expect("bounded read")
            .expect("read");
        assert_eq!(&hello, b"he");

        assert!(conn.supports_raw_transport_handoff(), "the record-bounded transport can switch");
        assert_eq!(conn.take_buffered_incoming().expect("a proven record boundary"), b"llo");

        let mut suffix = Vec::new();
        while suffix.len() < 4 {
            let mut chunk = [0u8; 4];
            let n = tokio::time::timeout(Duration::from_secs(5), raw.read(&mut chunk))
                .await
                .expect("bounded raw read")
                .expect("raw read");
            if n == 0 {
                break;
            }
            suffix.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(suffix, b"RAW!");

        tokio::time::timeout(Duration::from_secs(5), server).await.expect("bounded server").expect("server");
    }
}

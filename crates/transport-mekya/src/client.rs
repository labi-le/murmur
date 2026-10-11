//! This crate's client drives `hyper`'s client connection builders directly.
//!
//! It keeps up to [`MAX_IDLE_CONNS_PER_HOST`] idle HTTP/1.1 connections per address and one shared
//! HTTP/2 connection per `H2Transport` (both published to hyper via
//! `hyper::client::conn::{http1,http2}::handshake`), and implements the ALPN-aware round tripper's
//! pending-connection ALPN detection itself. No dial hook exposes the addresses of the connection
//! a round trip actually used, so the local `RoundTripper` trait returns the dialed conn's
//! addresses alongside the response.

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use futures::future::BoxFuture;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as HttpBody, Frame, Incoming};
use hyper::client::conn::{http1, http2};
use hyper::{Method, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::{Mutex, RwLock};
use rand::rngs::OsRng;
use rand::TryRngCore as _;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::io::StreamReader;
use tokio_util::sync::CancellationToken;

use murmur_common_httputils::force_close;
use murmur_common_net::io::{close_stream, Stream};
use murmur_component_tls::utls::get_tls_connection_state;
use murmur_std_compat::net::{Addr, Conn as NetConn, TcpAddr};
use murmur_transport_mkcp as mkcp;

use super::bundle;
use super::config::Config;
use super::deadline::{new_pipe_deadlines, PipeDeadlines};

const HTTP2_NEXT_PROTO_TLS: &str = "h2";

/// Registered at concrete dialed stream types, so `as_any` preserves the TLS connection identity.
pub trait DialedConn: Stream {}

/// Lets the ALPN-aware round tripper inspect the underlying TLS connection.
pub trait AnyConn: Stream + Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T: DialedConn + 'static> AnyConn for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub type DialFunc =
    Arc<dyn Fn(CancellationToken) -> BoxFuture<'static, anyhow::Result<Box<dyn AnyConn>>> + Send + Sync>;

type DialTlsFn =
    Arc<dyn Fn(CancellationToken, String) -> BoxFuture<'static, anyhow::Result<Box<dyn AnyConn>>> + Send + Sync>;

fn err_context_canceled() -> io::Error {
    io::Error::other("context canceled")
}

fn err_deadline_exceeded() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

fn err_net_closed() -> anyhow::Error {
    anyhow!(io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection"))
}

fn zero_addr() -> Box<dyn Addr> {
    Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
}

/// The ALPN-mismatch error kinds.
#[derive(Debug, Error)]
enum MekyaError {
    #[error("mekya: incorrect ALPN negotiated, try again")]
    UnexpectedAlpn,
    #[error("mekya: incorrect ALPN negotiated")]
    UnexpectedAlpnTooMany,
}

/// The addresses of the connection the round trip actually used, captured by the sub-transport.
struct RoundTripResult {
    response: Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>>,
    local_addr: Option<Arc<dyn Addr>>,
    remote_addr: Option<Arc<dyn Addr>>,
}

impl std::fmt::Debug for RoundTripResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoundTripResult")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .finish_non_exhaustive()
    }
}

/// The round-trip contract shared by the HTTP/1.1 and HTTP/2 sub-transports.
#[async_trait]
trait RoundTripper: force_close::RoundTripper {
    async fn round_trip(&self, ctx: CancellationToken, req: Request<Full<Bytes>>) -> anyhow::Result<RoundTripResult>;
}

fn round_trip_addr(uri: &hyper::Uri) -> String {
    let host = uri.host().unwrap_or_default();
    let port = uri.port_u16().unwrap_or(443);
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn clone_request(req: &Request<Full<Bytes>>) -> Request<Full<Bytes>> {
    req.clone()
}

/// Keeps up to [`MAX_IDLE_CONNS_PER_HOST`] idle connections per address instead of dialing fresh
/// for every request.
struct H1Transport {
    dial_tls: DialTlsFn,
    idle: Arc<Mutex<HashMap<String, Vec<PooledH1Conn>>>>,
    /// Set when idle connections are closed and honoured by the idle-put path
    /// until the next successful dial resets it, so a response body that
    /// finishes after the transport was told to close idle conns does not repopulate the pool.
    close_idle: Arc<AtomicBool>,
}

type H1Sender = http1::SendRequest<Full<Bytes>>;

struct PooledH1Conn {
    sender: H1Sender,
    local_addr: Option<Arc<dyn Addr>>,
    remote_addr: Option<Arc<dyn Addr>>,
}

const MAX_IDLE_CONNS_PER_HOST: usize = 2;

fn put_idle_h1(
    idle: &Mutex<HashMap<String, Vec<PooledH1Conn>>>,
    close_idle: &AtomicBool,
    addr: String,
    conn: PooledH1Conn,
) {
    let mut idle = idle.lock();
    if close_idle.load(Ordering::SeqCst) {
        return;
    }
    let conns = idle.entry(addr).or_default();
    conns.retain(|conn| !conn.sender.is_closed());
    if conns.len() < MAX_IDLE_CONNS_PER_HOST {
        conns.push(conn);
    }
    drop(idle);
}

impl H1Transport {
    fn take_idle(&self, addr: &str) -> Option<PooledH1Conn> {
        let mut idle = self.idle.lock();
        self.close_idle.store(false, Ordering::SeqCst);
        let conns = idle.get_mut(addr)?;
        while let Some(conn) = conns.pop() {
            if !conn.sender.is_closed() {
                return Some(conn);
            }
        }
        drop(idle);
        None
    }
}

impl force_close::RoundTripper for H1Transport {
    fn close_idle_connections(&self) {
        let mut idle = self.idle.lock();
        self.close_idle.store(true, Ordering::SeqCst);
        idle.clear();
    }
}

/// Wraps an HTTP/1.1 response body so [`PooledH1Conn`] only rejoins [`H1Transport::idle`] once
/// the body reaches a clean EOF — hyper's http1 dispatcher only accepts a new message once the
/// previous response is fully read, so returning the sender as soon as headers
/// arrive (the mekya server writes headers lazily and can hold the body open for
/// `max_write_duration_ms`) would queue the next poll's upload behind this response's body. A
/// body that errors or is dropped before EOF drops the sender instead, matching the
/// discarding a connection that cannot cleanly return to the idle pool.
struct H1IdleGuardBody {
    inner: Incoming,
    idle: Arc<Mutex<HashMap<String, Vec<PooledH1Conn>>>>,
    close_idle: Arc<AtomicBool>,
    addr: String,
    conn: Option<PooledH1Conn>,
}

impl HttpBody for H1IdleGuardBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_frame(cx);
        match &poll {
            Poll::Ready(None) => {
                if let Some(conn) = this.conn.take() {
                    put_idle_h1(&this.idle, &this.close_idle, std::mem::take(&mut this.addr), conn);
                }
            }
            Poll::Ready(Some(Err(_))) => {
                this.conn = None;
            }
            Poll::Ready(Some(Ok(_))) | Poll::Pending => {}
        }
        poll
    }
}

#[async_trait]
impl RoundTripper for H1Transport {
    // NOT cancel-safe: the request borrows a locked send half and has already started writing, so a dropped call abandons the request on a connection that cannot be reused safely; the arms that await it drop it only while the connection is being torn down.
    async fn round_trip(&self, ctx: CancellationToken, req: Request<Full<Bytes>>) -> anyhow::Result<RoundTripResult> {
        let addr = round_trip_addr(req.uri());
        if let Some(mut pooled) = self.take_idle(&addr) {
            if pooled.sender.ready().await.is_ok() {
                if let Ok(response) = pooled.sender.send_request(clone_request(&req)).await {
                    let (local_addr, remote_addr) = (pooled.local_addr.clone(), pooled.remote_addr.clone());
                    let response = response.map(|body| {
                        BodyExt::boxed(H1IdleGuardBody {
                            inner: body,
                            idle: Arc::clone(&self.idle),
                            close_idle: Arc::clone(&self.close_idle),
                            addr: addr.clone(),
                            conn: Some(pooled),
                        })
                    });
                    return Ok(RoundTripResult { response, local_addr, remote_addr });
                }
            }
        }
        let conn = (self.dial_tls)(ctx, addr.clone()).await?;
        let local_addr: Option<Arc<dyn Addr>> =
            conn.local_addr().ok().map(|addr| -> Arc<dyn Addr> { Arc::new(TcpAddr::from(addr)) });
        let remote_addr: Option<Arc<dyn Addr>> =
            conn.peer_addr().ok().map(|addr| -> Arc<dyn Addr> { Arc::new(TcpAddr::from(addr)) });
        let io = TokioIo::new(conn);
        let (mut send_request, connection) = http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = send_request.send_request(req).await?;
        let pooled =
            PooledH1Conn { sender: send_request, local_addr: local_addr.clone(), remote_addr: remote_addr.clone() };
        let response = response.map(|body| {
            BodyExt::boxed(H1IdleGuardBody {
                inner: body,
                idle: Arc::clone(&self.idle),
                close_idle: Arc::clone(&self.close_idle),
                addr,
                conn: Some(pooled),
            })
        });
        Ok(RoundTripResult { response, local_addr, remote_addr })
    }
}

/// The dialed connection is spoken to as HTTP/2 with no further ALPN negotiation, since the dial
/// already performed it. `http2::SendRequest` multiplexes, so a single dialed connection is reused
/// for every request until it stops accepting new streams. Once the peer's
/// concurrent-stream limit is reached this does not dial an additional connection (hyper
/// does not expose that count on `SendRequest`): a pooled connection at its stream limit queues
/// extra requests in hyper rather than falling back to a fresh dial.
struct H2Transport {
    dial_tls: DialTlsFn,
    conn: Mutex<Option<PooledH2Conn>>,
    generation: std::sync::atomic::AtomicU64,
}

type H2Sender = http2::SendRequest<Full<Bytes>>;

#[derive(Clone)]
struct PooledH2Conn {
    sender: H2Sender,
    local_addr: Option<Arc<dyn Addr>>,
    remote_addr: Option<Arc<dyn Addr>>,
    generation: u64,
}

impl force_close::RoundTripper for H2Transport {
    fn close_http2_connections(&self) {
        self.conn.lock().take();
    }
}

/// `hyper::Error::source` carries the underlying `h2::Error` for an HTTP/2 stream or connection
/// failure; this recovers it so `H2Transport::round_trip` can tell a stream-level failure
/// (retry) apart from a `GOAWAY` (evict and redial).
fn h2_error(err: &hyper::Error) -> Option<&h2::Error> {
    std::error::Error::source(err).and_then(|src| src.downcast_ref::<h2::Error>())
}

#[async_trait]
impl RoundTripper for H2Transport {
    // NOT cancel-safe: the request borrows a locked send half and has already started writing, so a dropped call abandons the request on a connection that cannot be reused safely; the arms that await it drop it only while the connection is being torn down.
    async fn round_trip(&self, ctx: CancellationToken, req: Request<Full<Bytes>>) -> anyhow::Result<RoundTripResult> {
        let addr = round_trip_addr(req.uri());
        let existing = self.conn.lock().clone();
        if let Some(mut pooled) = existing {
            if pooled.sender.ready().await.is_ok() {
                match pooled.sender.send_request(clone_request(&req)).await {
                    Ok(response) => {
                        let response = response.map(BodyExt::boxed);
                        return Ok(RoundTripResult {
                            response,
                            local_addr: pooled.local_addr,
                            remote_addr: pooled.remote_addr,
                        });
                    }
                    Err(err) if h2_error(&err).is_some_and(|e| e.reason() == Some(h2::Reason::REFUSED_STREAM)) => {
                        // A REFUSED_STREAM is retried on the same connection instead of being
                        // treated as a dead connection.
                        match pooled.sender.send_request(clone_request(&req)).await {
                            Ok(response) => {
                                let response = response.map(BodyExt::boxed);
                                return Ok(RoundTripResult {
                                    response,
                                    local_addr: pooled.local_addr,
                                    remote_addr: pooled.remote_addr,
                                });
                            }
                            Err(err) => return Err(err.into()),
                        }
                    }
                    Err(err) => {
                        // Only two stream failures are retried on a fresh connection: an
                        // unprocessed-stream `GOAWAY` and a peer `RST_STREAM(PROTOCOL_ERROR)`.
                        // Every other stream failure - including one that happens to race with
                        // `sender.is_closed()` flipping true, e.g. a processed-then-closed
                        // `GOAWAY` or a dead connection discovered by this very request - must
                        // surface to the caller rather than silently redialing.
                        let should_evict = h2_error(&err).is_some_and(|e| {
                            (e.is_go_away() && e.is_remote())
                                || (e.is_reset() && e.is_remote() && e.reason() == Some(h2::Reason::PROTOCOL_ERROR))
                        });
                        if !should_evict {
                            return Err(err.into());
                        }
                    }
                }
            }
            let mut guard = self.conn.lock();
            if guard.as_ref().is_some_and(|current| current.generation == pooled.generation) {
                guard.take();
            }
        }
        let conn = (self.dial_tls)(ctx, addr).await?;
        let local_addr: Option<Arc<dyn Addr>> =
            conn.local_addr().ok().map(|addr| -> Arc<dyn Addr> { Arc::new(TcpAddr::from(addr)) });
        let remote_addr: Option<Arc<dyn Addr>> =
            conn.peer_addr().ok().map(|addr| -> Arc<dyn Addr> { Arc::new(TcpAddr::from(addr)) });
        let io = TokioIo::new(conn);
        let (mut send_request, connection) = http2::handshake(TokioExecutor::new(), io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self.conn.lock() = Some(PooledH2Conn {
            sender: send_request.clone(),
            local_addr: local_addr.clone(),
            remote_addr: remote_addr.clone(),
            generation,
        });
        let response = send_request.send_request(req).await?;
        let response = response.map(BodyExt::boxed);
        Ok(RoundTripResult { response, local_addr, remote_addr })
    }
}

struct RoundTripperPool {
    round_trippers: Vec<Arc<dyn RoundTripper>>,
    next: Mutex<usize>,
}

#[async_trait]
impl RoundTripper for RoundTripperPool {
    // NOT cancel-safe: the request borrows a locked send half and has already started writing, so a dropped call abandons the request on a connection that cannot be reused safely; the arms that await it drop it only while the connection is being torn down.
    async fn round_trip(&self, ctx: CancellationToken, req: Request<Full<Bytes>>) -> anyhow::Result<RoundTripResult> {
        let rt = {
            let mut next = self.next.lock();
            let rt = Arc::clone(&self.round_trippers[*next]);
            *next = (*next + 1) % self.round_trippers.len();
            rt
        };
        rt.round_trip(ctx, req).await
    }
}

impl force_close::RoundTripper for RoundTripperPool {
    fn close(&self) {
        for rt in &self.round_trippers {
            force_close::close_transport(rt.as_ref());
        }
    }
}

fn new_h2_round_tripper(h2_pool_size: i64, dial_tls: DialTlsFn) -> Arc<dyn RoundTripper> {
    if h2_pool_size >= 2 {
        let round_trippers: Vec<Arc<dyn RoundTripper>> = (0..h2_pool_size)
            .map(|_| -> Arc<dyn RoundTripper> {
                Arc::new(H2Transport {
                    dial_tls: Arc::clone(&dial_tls),
                    conn: Mutex::new(None),
                    generation: std::sync::atomic::AtomicU64::new(0),
                })
            })
            .collect();
        Arc::new(RoundTripperPool { round_trippers, next: Mutex::new(0) })
    } else {
        Arc::new(H2Transport { dial_tls, conn: Mutex::new(None), generation: std::sync::atomic::AtomicU64::new(0) })
    }
}

struct PendingConn {
    state: Mutex<Option<Box<dyn AnyConn>>>,
    timer: JoinHandle<()>,
}

fn new_pending_conn(conn: Box<dyn AnyConn>) -> Arc<PendingConn> {
    Arc::new_cyclic(|weak: &Weak<PendingConn>| {
        let weak = Weak::clone(weak);
        let timer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            if let Some(pending) = weak.upgrade() {
                pending.close();
            }
        });
        PendingConn { state: Mutex::new(Some(conn)), timer }
    })
}

impl PendingConn {
    fn claim(&self) -> Option<Box<dyn AnyConn>> {
        let conn = self.state.lock().take();
        if conn.is_some() {
            self.timer.abort();
        }
        conn
    }

    fn close(&self) {
        let conn = self.state.lock().take();
        if let Some(conn) = conn {
            self.timer.abort();
            let _ = close_stream(conn.as_ref());
        }
    }
}

struct AlpnAwareRoundTripperState {
    connect_with_h1: HashMap<String, bool>,
    pending_conn: Option<HashMap<(String, bool), Arc<PendingConn>>>,
}

/// The ALPN-aware round tripper. `mu` is `parking_lot::Mutex` rather than `tokio::sync::Mutex` so that
/// `force_close::RoundTripper::close`, a synchronous method on a trait this crate does not own,
/// can take the same lock.
///
/// DEVIATION: the documented behaviour holds the lock across the external `dial` call inside
/// the dial, fully serializing dials; here the lock is released before
/// dialing, so dials may overlap.
struct AlpnAwareRoundTripper {
    state: Mutex<AlpnAwareRoundTripperState>,
    dial: DialFunc,
    h1: Arc<dyn RoundTripper>,
    h2: Arc<dyn RoundTripper>,
}

fn make_dial_tls(rt: Weak<AlpnAwareRoundTripper>, expected_h2: bool) -> DialTlsFn {
    Arc::new(move |ctx, addr| {
        let rt = Weak::clone(&rt);
        Box::pin(async move {
            let rt = rt.upgrade().ok_or_else(err_net_closed)?;
            rt.dial_or_get_tls_with_expected_alpn(ctx, addr, expected_h2).await
        })
    })
}

fn new_round_tripper(dial: DialFunc, h2_pool_size: i64) -> Arc<AlpnAwareRoundTripper> {
    Arc::new_cyclic(|weak: &Weak<AlpnAwareRoundTripper>| {
        let h1: Arc<dyn RoundTripper> = Arc::new(H1Transport {
            dial_tls: make_dial_tls(Weak::clone(weak), false),
            idle: Arc::new(Mutex::new(HashMap::new())),
            close_idle: Arc::new(AtomicBool::new(false)),
        });
        let h2 = new_h2_round_tripper(h2_pool_size, make_dial_tls(Weak::clone(weak), true));
        AlpnAwareRoundTripper {
            state: Mutex::new(AlpnAwareRoundTripperState {
                connect_with_h1: HashMap::new(),
                pending_conn: Some(HashMap::new()),
            }),
            dial,
            h1,
            h2,
        }
    })
}

fn get_pending_conn_locked(state: &mut AlpnAwareRoundTripperState, addr: &str, h2: bool) -> Option<Box<dyn AnyConn>> {
    let sessions = state.pending_conn.as_mut()?;
    let pending = sessions.remove(&(addr.to_owned(), h2))?;
    pending.claim()
}

fn put_pending_conn_locked(state: &mut AlpnAwareRoundTripperState, addr: String, h2: bool, conn: Box<dyn AnyConn>) {
    let Some(sessions) = state.pending_conn.as_mut() else {
        let _ = close_stream(conn.as_ref());
        return;
    };
    let key = (addr, h2);
    if let Some(old) = sessions.get(&key) {
        old.close();
    }
    sessions.insert(key, new_pending_conn(conn));
}

impl AlpnAwareRoundTripper {
    fn should_connect_with_h1(&self, addr: &str) -> bool {
        self.state.lock().connect_with_h1.get(addr).copied().unwrap_or(false)
    }

    async fn dial_or_get_tls_with_expected_alpn(
        &self,
        ctx: CancellationToken,
        addr: String,
        expected_h2: bool,
    ) -> anyhow::Result<Box<dyn AnyConn>> {
        // The guard's scope has to end before the dial below: a `parking_lot` guard is
        // not `Send`, so holding one across the await would make this future non-`Send`.
        {
            let mut state = self.state.lock();
            if state.pending_conn.is_none() {
                return Err(err_net_closed());
            }
            if state.connect_with_h1.get(&addr).copied().unwrap_or(false) == expected_h2 {
                return Err(MekyaError::UnexpectedAlpn.into());
            }
            if let Some(conn) = get_pending_conn_locked(&mut state, &addr, expected_h2) {
                return Ok(conn);
            }
            drop(state);
        }

        let conn = (self.dial)(ctx).await?;
        let tls_state = get_tls_connection_state(AnyConn::as_any(conn.as_ref()));
        let protocol_is_h2 = tls_state.negotiated_protocol == HTTP2_NEXT_PROTO_TLS;
        if !tls_state.handshake_complete || protocol_is_h2 == expected_h2 {
            return Ok(conn);
        }

        let mut state = self.state.lock();
        put_pending_conn_locked(&mut state, addr.clone(), protocol_is_h2, conn);
        state.connect_with_h1.insert(addr, !protocol_is_h2);
        drop(state);
        Err(MekyaError::UnexpectedAlpn.into())
    }
}

#[async_trait]
impl RoundTripper for AlpnAwareRoundTripper {
    // NOT cancel-safe: the request borrows a locked send half and has already started writing, so a dropped call abandons the request on a connection that cannot be reused safely; the arms that await it drop it only while the connection is being torn down.
    async fn round_trip(&self, ctx: CancellationToken, req: Request<Full<Bytes>>) -> anyhow::Result<RoundTripResult> {
        if req.uri().scheme_str() != Some("https") {
            return Err(anyhow!("mekya: unsupported url scheme {:?}", req.uri().scheme_str().unwrap_or_default()));
        }
        let addr = round_trip_addr(req.uri());
        for _ in 0..5 {
            let rt: Arc<dyn RoundTripper> =
                if self.should_connect_with_h1(&addr) { Arc::clone(&self.h1) } else { Arc::clone(&self.h2) };
            match rt.round_trip(ctx.clone(), clone_request(&req)).await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    if matches!(err.downcast_ref::<MekyaError>(), Some(MekyaError::UnexpectedAlpn)) {
                        continue;
                    }
                    return Err(err);
                }
            }
        }
        Err(MekyaError::UnexpectedAlpnTooMany.into())
    }
}

impl force_close::RoundTripper for AlpnAwareRoundTripper {
    fn close(&self) {
        let pending = self.state.lock().pending_conn.take();
        if let Some(pending) = pending {
            for conn in pending.into_values() {
                conn.close();
            }
        }
        force_close::close_transport(self.h1.as_ref());
        force_close::close_transport(self.h2.as_ref());
    }
}

/// Normalizes a URL. `url::Url::parse` rejects a scheme-less input outright instead of leaving the
/// scheme empty, so a missing scheme is retried with `https://` prefixed before the default-scheme
/// check.
fn normalize_url(raw: &str) -> anyhow::Result<String> {
    if raw.is_empty() {
        return Err(anyhow!("mekya: empty url"));
    }
    let parsed = match url::Url::parse(raw) {
        Ok(url) => url,
        Err(url::ParseError::RelativeUrlWithoutBase) => url::Url::parse(&format!("https://{raw}"))?,
        Err(err) => return Err(err.into()),
    };
    if parsed.scheme() != "https" {
        return Err(anyhow!("mekya: unsupported url scheme {:?}", parsed.scheme()));
    }
    if parsed.host_str().unwrap_or_default().is_empty() {
        return Err(anyhow!("mekya: empty url host"));
    }
    Ok(parsed.to_string())
}

struct AddrState {
    local: Option<Arc<dyn Addr>>,
    remote: Option<Arc<dyn Addr>>,
}

type ReadFuture = Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>>;
type WriteFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;

struct RequestClientSession {
    ctx: CancellationToken,
    session_id: Vec<u8>,
    rt: Arc<dyn RoundTripper>,
    url: String,
    current_polling_interval: i64,
    max_request_size: i64,
    max_write_delay: i64,
    writer_tx: mpsc::Sender<Vec<u8>>,
    reader_tx: mpsc::Sender<Vec<u8>>,
    reader_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    deadlines: PipeDeadlines,
    addr: RwLock<AddrState>,
    read_future: Mutex<Option<ReadFuture>>,
    write_future: Mutex<Option<WriteFuture>>,
}

impl RequestClientSession {
    fn local_addr(&self) -> Option<Arc<dyn Addr>> {
        self.addr.read().local.clone()
    }

    fn remote_addr(&self) -> Option<Arc<dyn Addr>> {
        self.addr.read().remote.clone()
    }

    fn set_underlying_addr(&self, local: Arc<dyn Addr>, remote: Arc<dyn Addr>) {
        let mut state = self.addr.write();
        state.local = Some(local);
        state.remote = Some(remote);
    }

    fn close(&self) {
        self.ctx.cancel();
    }

    async fn read(&self) -> io::Result<Vec<u8>> {
        let mut reader_rx = self.reader_rx.lock().await;
        let read_deadline = self.deadlines.read.wait();
        let result = tokio::select! {
            () = self.ctx.cancelled() => Err(err_context_canceled()),
            () = read_deadline.wait() => Err(err_deadline_exceeded()),
            packet = reader_rx.recv() => packet.ok_or_else(err_context_canceled),
        };
        drop(reader_rx);
        result
    }

    async fn write(&self, packet: Vec<u8>) -> io::Result<usize> {
        let len = packet.len();
        let write_deadline = self.deadlines.write.wait();
        tokio::select! {
            () = self.ctx.cancelled() => Err(err_context_canceled()),
            () = write_deadline.wait() => Err(err_deadline_exceeded()),
            result = self.writer_tx.send(packet) => result.map(|()| len).map_err(|_| err_context_canceled()),
        }
    }
}

/// The request client session, shared between the caller's `Conn` use
/// and the background keep-running task.
fn new_request_client_session(
    ctx: &CancellationToken,
    url: String,
    current_polling_interval: i64,
    max_request_size: i64,
    max_write_delay: i64,
    rt: Arc<dyn RoundTripper>,
) -> anyhow::Result<Arc<RequestClientSession>> {
    let mut session_id = vec![0u8; 16];
    OsRng.try_fill_bytes(&mut session_id).map_err(|err| anyhow!("{err}"))?;
    let (writer_tx, writer_rx) = mpsc::channel(256);
    let (reader_tx, reader_rx) = mpsc::channel(256);
    let session = Arc::new(RequestClientSession {
        ctx: ctx.child_token(),
        session_id,
        rt,
        url,
        current_polling_interval,
        max_request_size,
        max_write_delay,
        writer_tx,
        reader_tx,
        reader_rx: tokio::sync::Mutex::new(reader_rx),
        deadlines: new_pipe_deadlines(),
        addr: RwLock::new(AddrState { local: None, remote: None }),
        read_future: Mutex::new(None),
        write_future: Mutex::new(None),
    });
    tokio::spawn(keep_running(Arc::clone(&session), writer_rx));
    Ok(session)
}

async fn keep_running(session: Arc<RequestClientSession>, mut writer_rx: mpsc::Receiver<Vec<u8>>) {
    let mut next_write: Option<Vec<u8>> = None;
    while !session.ctx.is_cancelled() {
        run_once(&session, &mut writer_rx, &mut next_write).await;
    }
}

fn write_packet(
    request_body: &mut Vec<u8>,
    max_request_size: i64,
    next_write: &mut Option<Vec<u8>>,
    packet: &[u8],
) -> bool {
    let size_offset = bundle::PACKET_BUNDLE_OVERHEAD + packet.len();
    let body_len = i64::try_from(request_body.len() + size_offset).unwrap_or(i64::MAX);
    if max_request_size > 0 && body_len > max_request_size {
        *next_write = Some(packet.to_vec());
        return false;
    }
    bundle::write_packet_bundle(request_body, packet).is_ok()
}

async fn run_once(
    session: &Arc<RequestClientSession>,
    writer_rx: &mut mpsc::Receiver<Vec<u8>>,
    next_write: &mut Option<Vec<u8>>,
) {
    let mut request_body = Vec::new();
    let mut seen_packet = false;
    let polling_interval = Duration::from_millis(session.current_polling_interval.max(0).cast_unsigned());
    let write_delay = Duration::from_millis(session.max_write_delay.max(0).cast_unsigned());
    let sleep = tokio::time::sleep(polling_interval);
    tokio::pin!(sleep);

    if let Some(packet) = next_write.take() {
        seen_packet = true;
        sleep.as_mut().reset(tokio::time::Instant::now() + write_delay);
        if !write_packet(&mut request_body, session.max_request_size, next_write, &packet) {
            return;
        }
    }

    loop {
        tokio::select! {
            () = session.ctx.cancelled() => return,
            () = &mut sleep => break,
            packet = writer_rx.recv() => {
                let Some(packet) = packet else { break };
                if !seen_packet {
                    seen_packet = true;
                    sleep.as_mut().reset(tokio::time::Instant::now() + write_delay);
                }
                if !write_packet(&mut request_body, session.max_request_size, next_write, &packet) {
                    break;
                }
            }
        }
    }

    let session = Arc::clone(session);
    tokio::spawn(async move { session_round_trip(&session, request_body).await });
}

async fn session_round_trip(session: &Arc<RequestClientSession>, body: Vec<u8>) {
    let Ok(uri) = session.url.parse::<hyper::Uri>() else { return };
    let Some(authority) = uri.authority().cloned() else { return };
    let Ok(req) = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(hyper::header::HOST, authority.as_str())
        .header("X-Session-ID", URL_SAFE_NO_PAD.encode(&session.session_id))
        .body(Full::new(Bytes::from(body)))
    else {
        return;
    };
    let result = tokio::select! {
        () = session.ctx.cancelled() => return,
        result = session.rt.round_trip(session.ctx.clone(), req) => result,
    };
    let Ok(result) = result else { return };
    if let (Some(local), Some(remote)) = (result.local_addr, result.remote_addr) {
        session.set_underlying_addr(local, remote);
    }

    let stream = result.response.into_body().into_data_stream().map_err(io::Error::other);
    let mut reader = StreamReader::new(stream);
    loop {
        let packet = tokio::select! {
            () = session.ctx.cancelled() => return,
            result = bundle::read_packet_bundle(&mut reader) => {
                let Ok(packet) = result else { return };
                packet
            }
        };
        tokio::select! {
            () = session.ctx.cancelled() => return,
            result = session.reader_tx.send(packet) => {
                if result.is_err() {
                    return;
                }
            }
        }
    }
}

/// `Box<dyn Addr>` bridge for a shared [`Addr`], returning the same address value from
/// `LocalAddr`/`RemoteAddr` on every call.
#[derive(Debug)]
struct AddrRef(Arc<dyn Addr>);

impl Addr for AddrRef {
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

/// Local newtype so `Arc<RequestClientSession>` can satisfy the foreign `Conn` trait (Rust's orphan
/// rule forbids implementing a foreign trait for `Arc<LocalType>` directly), letting the same
/// session pointer be handed to the transport as a `Conn` while the client keeps its own reference.
pub(crate) struct SharedRequestClientSession(Arc<RequestClientSession>);

impl AsyncRead for SharedRequestClientSession {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut read_future = this.0.read_future.lock();
        let fut = read_future.get_or_insert_with(|| {
            let session = Arc::clone(&this.0);
            Box::pin(async move { session.read().await })
        });
        let poll = match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                *read_future = None;
                match result {
                    Ok(packet) => {
                        let n = buf.remaining().min(packet.len());
                        let (payload, _) = packet.split_at(n);
                        buf.put_slice(payload);
                        Poll::Ready(Ok(()))
                    }
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
        };
        drop(read_future);
        poll
    }
}

impl AsyncWrite for SharedRequestClientSession {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut write_future = this.0.write_future.lock();
        let fut = write_future.get_or_insert_with(|| {
            let session = Arc::clone(&this.0);
            let packet = buf.to_vec();
            Box::pin(async move { session.write(packet).await })
        });
        let poll = match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                *write_future = None;
                Poll::Ready(result)
            }
        };
        drop(write_future);
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().0.close();
        Poll::Ready(Ok(()))
    }
}

impl NetConn for SharedRequestClientSession {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(match self.0.local_addr() {
            Some(addr) => Box::new(AddrRef(addr)),
            None => zero_addr(),
        })
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(match self.0.remote_addr() {
            Some(addr) => Box::new(AddrRef(addr)),
            None => zero_addr(),
        })
    }

    fn close(&self) -> io::Result<()> {
        self.0.close();
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.deadlines.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.deadlines.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.deadlines.set_write_deadline(deadline)
    }
}

pub(crate) struct ClientConn {
    conn: murmur_common_net::io::StreamAsOldConn<mkcp::conn::Conn>,
    raw: Arc<RequestClientSession>,
    closed: AtomicBool,
}

impl AsyncRead for ClientConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for ClientConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl NetConn for ClientConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        if let Some(addr) = self.raw.local_addr() {
            return Ok(Box::new(AddrRef(addr)));
        }
        self.conn.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        if let Some(addr) = self.raw.remote_addr() {
            return Ok(Box::new(AddrRef(addr)));
        }
        self.conn.remote_addr()
    }

    fn close(&self) -> io::Result<()> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.raw.close();
        }
        self.conn.close()
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

pub struct Client {
    ctx: CancellationToken,
    cfg: Config,
    url: String,
    rt: Arc<dyn RoundTripper>,
    closed: AtomicBool,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("url", &self.url).field("closed", &self.closed).finish_non_exhaustive()
    }
}

pub fn new_client(ctx: &CancellationToken, dial: DialFunc, cfg: Config) -> anyhow::Result<Client> {
    let child = ctx.child_token();
    let round_trip_url = match normalize_url(&cfg.url) {
        Ok(url) => url,
        Err(err) => {
            child.cancel();
            return Err(err);
        }
    };
    let rt: Arc<dyn RoundTripper> = new_round_tripper(dial, cfg.h2_pool_size);
    Ok(Client { ctx: child, cfg, url: round_trip_url, rt, closed: AtomicBool::new(false) })
}

impl Client {
    fn new_session(&self) -> anyhow::Result<Arc<RequestClientSession>> {
        new_request_client_session(
            &self.ctx,
            self.url.clone(),
            self.cfg.polling_interval_initial,
            self.cfg.max_request_size,
            self.cfg.max_write_delay,
            Arc::clone(&self.rt),
        )
    }

    pub async fn dial(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn NetConn>> {
        if self.ctx.is_cancelled() {
            return Err(err_context_canceled().into());
        }
        if ctx.is_cancelled() {
            return Err(err_context_canceled().into());
        }
        let raw = self.new_session()?;
        let raw_conn: Box<dyn NetConn> = Box::new(SharedRequestClientSession(Arc::clone(&raw)));
        let conn = match mkcp::conn::dial(raw_conn, self.cfg.kcp.clone()).await {
            Ok(conn) => conn,
            Err(err) => {
                raw.close();
                return Err(err);
            }
        };
        Ok(Box::new(ClientConn { conn, raw, closed: AtomicBool::new(false) }))
    }

    pub fn close(&self) -> anyhow::Result<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.ctx.cancel();
        force_close::close_transport(self.rt.as_ref());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::atomic::AtomicUsize;

    use http::Version;
    use hyper::service::service_fn;
    use hyper_util::server::conn::auto;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::Duration;

    use murmur_component_ca as ca;
    use murmur_component_tls::utls;
    use murmur_std_compat::net::Listener as NetListener;

    use super::*;

    impl DialedConn for TcpStream {}
    impl DialedConn for utls::UConn {}

    fn test_config() -> Config {
        Config {
            kcp: mkcp::config::Config { tti: 15, ..Default::default() },
            url: "https://example.invalid/mekya".to_owned(),
            h2_pool_size: 2,
            max_write_delay: 20,
            max_request_size: 96000,
            polling_interval_initial: 20,
            max_write_size: 1 << 20,
            max_write_duration_ms: 100,
            max_simultaneous_write_connection: 16,
            packet_writing_buffer: 1024,
        }
    }

    async fn echo(mut conn: impl AsyncRead + AsyncWrite + Unpin) -> io::Result<()> {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            conn.write_all(&buf[..n]).await?;
        }
    }

    #[tokio::test]
    async fn round_trip() {
        let ctx = CancellationToken::new();
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let cfg = test_config();
        let server = crate::server::listen(&ctx, Box::new(tcp_listener), cfg.clone()).await.expect("listen");
        let server_addr = server.addr().expect("server addr").string();

        tokio::spawn(async move {
            if let Ok(conn) = server.accept().await {
                let _ = echo(conn).await;
            }
        });

        let dial: DialFunc = Arc::new(move |_ctx| {
            let addr = server_addr.clone();
            Box::pin(async move {
                let stream = TcpStream::connect(&addr).await?;
                let conn: Box<dyn AnyConn> = Box::new(stream);
                Ok(conn)
            })
        });

        let client = new_client(&ctx, dial, cfg).expect("new client");
        let mut conn = client.dial(&ctx).await.expect("dial");

        let payload = vec![b'm'; 64 * 1024];
        conn.write_all(&payload).await.expect("write");
        let mut got = vec![0u8; payload.len()];
        conn.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload);
        assert!(conn.local_addr().is_ok());
        assert!(conn.remote_addr().is_ok());
        conn.close().expect("close");
    }

    /// [`MAX_IDLE_CONNS_PER_HOST`] (2) bounds how many idle HTTP/1.1 connections per address
    /// `H1Transport` keeps; sequential round trips to the same address must reuse a pooled
    /// connection instead of dialing fresh every time.
    #[tokio::test]
    async fn h1_transport_reuses_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_srv = Arc::clone(&accept_count);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                accept_count_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(|_req: Request<Incoming>| async move {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
                    });
                    let _ = auto::Builder::new(TokioExecutor::new()).serve_connection(io, svc).await;
                });
            }
        });

        let dial_addr = addr.to_string();
        let transport = H1Transport {
            dial_tls: Arc::new(move |_ctx, _addr| {
                let dial_addr = dial_addr.clone();
                Box::pin(async move {
                    let stream = TcpStream::connect(&dial_addr).await?;
                    let conn: Box<dyn AnyConn> = Box::new(stream);
                    Ok(conn)
                })
            }),
            idle: Arc::new(Mutex::new(HashMap::new())),
            close_idle: Arc::new(AtomicBool::new(false)),
        };

        let uri: hyper::Uri = format!("https://{addr}/").parse().expect("uri");
        for _ in 0..10 {
            let req = Request::get(uri.clone()).body(Full::new(Bytes::new())).expect("req");
            let result = transport.round_trip(CancellationToken::new(), req).await.expect("round trip");
            result.response.into_body().collect().await.expect("drain body");
        }

        let accepted = accept_count.load(Ordering::SeqCst);
        assert!(accepted <= 2, "expected at most 2 TCP connections (the default MaxIdleConnsPerHost), got {accepted}");
    }

    /// The read loop removes a broken conn from the idle map, and the idle-put path keeps
    /// popping past broken entries (review finding 0 on c6359372): `take_idle` must skip a dead
    /// entry instead of handing it back, and `put_idle_h1` must prune dead entries before
    /// checking [`MAX_IDLE_CONNS_PER_HOST`] so they cannot starve a live conn out of the pool.
    #[tokio::test]
    async fn h1_idle_pool_prunes_dead_conns_on_take_and_put() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(|_req: Request<Incoming>| async move {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
                    });
                    let _ = auto::Builder::new(TokioExecutor::new()).serve_connection(io, svc).await;
                });
            }
        });

        async fn live_sender(addr: std::net::SocketAddr) -> H1Sender {
            let stream = TcpStream::connect(addr).await.expect("connect");
            let io = TokioIo::new(stream);
            let (send_request, connection) = http1::handshake::<_, Full<Bytes>>(io).await.expect("handshake");
            tokio::spawn(async move {
                let _ = connection.await;
            });
            send_request
        }

        async fn dead_sender() -> H1Sender {
            let (client, server) = tokio::io::duplex(64);
            drop(server);
            let io = TokioIo::new(client);
            let (send_request, connection) = http1::handshake::<_, Full<Bytes>>(io).await.expect("handshake");
            let _ = connection.await;
            assert!(send_request.is_closed(), "sender must report closed once its connection driver exits");
            send_request
        }

        let transport = H1Transport {
            dial_tls: Arc::new(|_ctx, _addr| Box::pin(async { Err(anyhow!("not used")) })),
            idle: Arc::new(Mutex::new(HashMap::new())),
            close_idle: Arc::new(AtomicBool::new(false)),
        };
        let key = "test".to_owned();

        let live = PooledH1Conn { sender: live_sender(addr).await, local_addr: None, remote_addr: None };
        let dead = PooledH1Conn { sender: dead_sender().await, local_addr: None, remote_addr: None };
        {
            let mut idle = transport.idle.lock();
            let entry = idle.entry(key.clone()).or_default();
            entry.push(live);
            entry.push(dead);
        }
        let popped = transport.take_idle(&key).expect("take_idle must return the live entry, not None");
        assert!(!popped.sender.is_closed(), "take_idle returned the dead entry instead of skipping it");
        assert!(
            transport.idle.lock().get(&key).is_none_or(Vec::is_empty),
            "both the dead and the live entry must be consumed from the pool"
        );

        let dead1 = PooledH1Conn { sender: dead_sender().await, local_addr: None, remote_addr: None };
        let dead2 = PooledH1Conn { sender: dead_sender().await, local_addr: None, remote_addr: None };
        {
            let mut idle = transport.idle.lock();
            let entry = idle.entry(key.clone()).or_default();
            entry.push(dead1);
            entry.push(dead2);
        }
        assert_eq!(transport.idle.lock().get(&key).map(Vec::len), Some(2));
        let live2 = PooledH1Conn { sender: live_sender(addr).await, local_addr: None, remote_addr: None };
        put_idle_h1(&transport.idle, &transport.close_idle, key.clone(), live2);
        let idle = transport.idle.lock();
        let conns = idle.get(&key).expect("entry must still exist");
        assert_eq!(conns.len(), 1, "the two dead entries must be pruned to make room for the live one");
        assert!(!conns[0].sender.is_closed());
    }

    /// The close-idle flag (review finding 1 on c6359372): closing idle connections must
    /// keep dropping conns that go idle later, until the next `take_idle` resets the flag for
    /// the following dial.
    #[tokio::test]
    async fn h1_close_idle_flag_drops_conns_until_next_take() {
        async fn any_sender() -> H1Sender {
            let (client, server) = tokio::io::duplex(64);
            drop(server);
            let io = TokioIo::new(client);
            let (send_request, connection) = http1::handshake::<_, Full<Bytes>>(io).await.expect("handshake");
            let _ = connection.await;
            send_request
        }

        let transport = H1Transport {
            dial_tls: Arc::new(|_ctx, _addr| Box::pin(async { Err(anyhow!("not used")) })),
            idle: Arc::new(Mutex::new(HashMap::new())),
            close_idle: Arc::new(AtomicBool::new(false)),
        };
        let key = "test".to_owned();

        force_close::RoundTripper::close_idle_connections(&transport);
        assert!(transport.close_idle.load(Ordering::SeqCst));

        let conn = PooledH1Conn { sender: any_sender().await, local_addr: None, remote_addr: None };
        put_idle_h1(&transport.idle, &transport.close_idle, key.clone(), conn);
        assert!(
            transport.idle.lock().get(&key).is_none_or(Vec::is_empty),
            "put_idle_h1 must drop the conn while close_idle is set"
        );

        assert!(transport.take_idle(&key).is_none());
        assert!(!transport.close_idle.load(Ordering::SeqCst), "take_idle must reset close_idle for the next dial");

        let conn = PooledH1Conn { sender: any_sender().await, local_addr: None, remote_addr: None };
        put_idle_h1(&transport.idle, &transport.close_idle, key.clone(), conn);
        assert_eq!(
            transport.idle.lock().get(&key).map(Vec::len),
            Some(1),
            "pooling must work normally again once close_idle has been reset"
        );
    }

    /// `H2Transport` multiplexes every round trip over the one connection it dials per address.
    #[tokio::test]
    async fn h2_transport_reuses_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_srv = Arc::clone(&accept_count);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                accept_count_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(|_req: Request<Incoming>| async move {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
                    });
                    let _ = auto::Builder::new(TokioExecutor::new()).serve_connection(io, svc).await;
                });
            }
        });

        let dial_addr = addr.to_string();
        let transport = H2Transport {
            dial_tls: Arc::new(move |_ctx, _addr| {
                let dial_addr = dial_addr.clone();
                Box::pin(async move {
                    let stream = TcpStream::connect(&dial_addr).await?;
                    let conn: Box<dyn AnyConn> = Box::new(stream);
                    Ok(conn)
                })
            }),
            conn: Mutex::new(None),
            generation: std::sync::atomic::AtomicU64::new(0),
        };

        let uri: hyper::Uri = format!("https://{addr}/").parse().expect("uri");
        for _ in 0..10 {
            let req = Request::get(uri.clone()).body(Full::new(Bytes::new())).expect("req");
            let result = transport.round_trip(CancellationToken::new(), req).await.expect("round trip");
            result.response.into_body().collect().await.expect("drain body");
        }

        let accepted = accept_count.load(Ordering::SeqCst);
        assert_eq!(accepted, 1, "expected exactly 1 TCP connection reused for every round trip, got {accepted}");
    }

    /// A stream-level failure (`RST_STREAM(REFUSED_STREAM)`) is retried on the same connection
    /// rather than tearing it down (review finding 3 on c6359372): `H2Transport::round_trip` must
    /// evict the pooled sender only when the sender itself reports closed, not on every failed
    /// `send_request`.
    #[tokio::test]
    async fn h2_transport_keeps_pooled_conn_after_a_stream_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_srv = Arc::clone(&accept_count);
        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_srv = Arc::clone(&request_count);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                accept_count_srv.fetch_add(1, Ordering::SeqCst);
                let request_count = Arc::clone(&request_count_srv);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |_req: Request<Incoming>| {
                        let request_count = Arc::clone(&request_count);
                        async move {
                            if request_count.fetch_add(1, Ordering::SeqCst) == 1 {
                                return Err(io::Error::other("forced stream error"));
                            }
                            Ok::<_, io::Error>(Response::new(Full::new(Bytes::new())))
                        }
                    });
                    let _ = auto::Builder::new(TokioExecutor::new()).serve_connection(io, svc).await;
                });
            }
        });

        let dial_addr = addr.to_string();
        let transport = H2Transport {
            dial_tls: Arc::new(move |_ctx, _addr| {
                let dial_addr = dial_addr.clone();
                Box::pin(async move {
                    let stream = TcpStream::connect(&dial_addr).await?;
                    let conn: Box<dyn AnyConn> = Box::new(stream);
                    Ok(conn)
                })
            }),
            conn: Mutex::new(None),
            generation: std::sync::atomic::AtomicU64::new(0),
        };

        let uri: hyper::Uri = format!("https://{addr}/").parse().expect("uri");
        let req = || Request::get(uri.clone()).body(Full::new(Bytes::new())).expect("req");

        transport.round_trip(CancellationToken::new(), req()).await.expect("round trip 1 warms the pool");
        let generation_after_first = transport.conn.lock().as_ref().expect("pooled conn").generation;

        let second = transport.round_trip(CancellationToken::new(), req()).await;
        assert!(second.is_err(), "the forced stream error must surface to the caller");
        let generation_after_error = transport.conn.lock().as_ref().map(|pooled| pooled.generation);
        assert_eq!(
            generation_after_error,
            Some(generation_after_first),
            "a stream-level error on a still-open sender must not evict the pooled conn"
        );

        let result = transport.round_trip(CancellationToken::new(), req()).await.expect("round trip 3");
        result.response.into_body().collect().await.expect("drain body");
        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            1,
            "the pooled conn must be reused after the stream error, not redialed"
        );
    }

    /// Round 2 review (agent://ReviewP3MuxMasque P2 finding on 2452f9b7):
    /// `RST_STREAM(REFUSED_STREAM)` is retried on the same connection instead of treating it as a
    /// dead connection. Drives a raw `h2` server directly (not hyper's) so a stream can be
    /// refused deliberately: the server answers request 1 (priming `H2Transport`'s pool, the
    /// same way `h2_transport_reuses_connections` does), refuses request 2, then answers request
    /// 3 (the retry) normally, all on the one TCP connection.
    #[tokio::test]
    async fn h2_transport_retries_refused_stream_on_the_same_conn() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_srv = Arc::clone(&accept_count);
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else { return };
            accept_count_srv.fetch_add(1, Ordering::SeqCst);
            let mut conn = h2::server::handshake(stream).await.expect("h2 server handshake");
            if let Some(Ok((_, mut respond))) = conn.accept().await {
                let response = Response::builder().status(200).body(()).expect("response");
                let _ = respond.send_response(response, true);
            }
            if let Some(Ok((_, mut respond))) = conn.accept().await {
                respond.send_reset(h2::Reason::REFUSED_STREAM);
            }
            if let Some(Ok((_, mut respond))) = conn.accept().await {
                let response = Response::builder().status(200).body(()).expect("response");
                let _ = respond.send_response(response, true);
            }
            while conn.accept().await.is_some() {}
        });

        let dial_addr = addr.to_string();
        let transport = H2Transport {
            dial_tls: Arc::new(move |_ctx, _addr| {
                let dial_addr = dial_addr.clone();
                Box::pin(async move {
                    let stream = TcpStream::connect(&dial_addr).await?;
                    let conn: Box<dyn AnyConn> = Box::new(stream);
                    Ok(conn)
                })
            }),
            conn: Mutex::new(None),
            generation: std::sync::atomic::AtomicU64::new(0),
        };

        let uri: hyper::Uri = format!("https://{addr}/").parse().expect("uri");
        let req = || Request::get(uri.clone()).body(Full::new(Bytes::new())).expect("req");

        transport.round_trip(CancellationToken::new(), req()).await.expect("round trip 1 primes the pool");

        let result = transport
            .round_trip(CancellationToken::new(), req())
            .await
            .expect("REFUSED_STREAM must be retried on the same conn and succeed");
        result.response.into_body().collect().await.expect("drain body");

        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            1,
            "REFUSED_STREAM must not cause a redial, only a retry on the same conn"
        );
    }

    /// Round 2 review (agent://ReviewMuxMasqueR2 P2 finding on 488c68c8): the previous version of
    /// this test called `conn.abrupt_shutdown(NO_ERROR)` after the `h2` server crate had already
    /// accepted stream 3, so the `GOAWAY` it sent carried `last_stream_id=3` — the stream the
    /// client was waiting on counts as processed, `h2` surfaces a plain `BrokenPipe` for it
    /// instead of `Error::GoAway`, and the retry went through the pre-existing `is_closed()` path
    /// instead of the new `is_go_away` branch. This drives a hand-rolled HTTP/2 frame server
    /// instead: it responds to stream 1 normally (priming the pool), then, on seeing stream 3's
    /// `HEADERS`, writes a raw `GOAWAY(last_stream_id=1, NO_ERROR)` frame and keeps the socket
    /// open rather than closing it (an unprocessed-stream `GOAWAY`, retried on a fresh
    /// connection). A second, ordinary connection then answers the retry.
    #[tokio::test]
    async fn h2_transport_evicts_and_redials_after_goaway() {
        async fn serve_one(mut stream: TcpStream) {
            let mut preface = [0u8; 24];
            if stream.read_exact(&mut preface).await.is_err() {
                return;
            }
            if stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.is_err() {
                return;
            }
            loop {
                let mut header = [0u8; 9];
                if stream.read_exact(&mut header).await.is_err() {
                    return;
                }
                let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
                let mut payload = vec![0u8; len];
                if stream.read_exact(&mut payload).await.is_err() {
                    return;
                }
                let frame_type = header[3];
                let flags = header[4];
                let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
                if frame_type == 4 && flags & 1 == 0 {
                    if stream.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await.is_err() {
                        return;
                    }
                } else if frame_type == 1 && stream_id == 1 {
                    // HEADERS, END_HEADERS|END_STREAM, HPACK static index 8 (":status: 200").
                    if stream.write_all(&[0, 0, 1, 1, 5, 0, 0, 0, 1, 0x88]).await.is_err() {
                        return;
                    }
                } else if frame_type == 1 && stream_id == 3 {
                    // GOAWAY, last_stream_id=1, error=NO_ERROR; the connection stays open.
                    let _ = stream.write_all(&[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]).await;
                }
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_srv = Arc::clone(&accept_count);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                accept_count_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve_one(stream));
            }
        });

        let dial_addr = addr.to_string();
        let transport = H2Transport {
            dial_tls: Arc::new(move |_ctx, _addr| {
                let dial_addr = dial_addr.clone();
                Box::pin(async move {
                    let stream = TcpStream::connect(&dial_addr).await?;
                    let conn: Box<dyn AnyConn> = Box::new(stream);
                    Ok(conn)
                })
            }),
            conn: Mutex::new(None),
            generation: std::sync::atomic::AtomicU64::new(0),
        };

        let uri: hyper::Uri = format!("https://{addr}/").parse().expect("uri");
        let req = || Request::get(uri.clone()).body(Full::new(Bytes::new())).expect("req");

        let first = transport.round_trip(CancellationToken::new(), req()).await.expect("round trip 1 primes the pool");
        first.response.into_body().collect().await.expect("drain body 1");

        let result = transport
            .round_trip(CancellationToken::new(), req())
            .await
            .expect("GOAWAY(last_stream_id below the stream) must evict the pooled conn and redial instead of failing");
        result.response.into_body().collect().await.expect("drain body 2");

        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            2,
            "GOAWAY must evict the pooled generation and dial a fresh connection"
        );
    }
    /// Round 2 review (agent://ReviewMuxMasqueR2 P3 finding on 488c68c8): a peer
    /// `RST_STREAM(PROTOCOL_ERROR)` is also retried on a fresh connection rather than surfaced,
    /// the same as an unprocessed-stream `GOAWAY`. Drives a raw `h2` server:
    /// the first connection answers request 1 (priming the pool), resets request 2 with
    /// `PROTOCOL_ERROR`; a second connection then answers the retried request normally.
    #[tokio::test]
    async fn h2_transport_evicts_and_redials_after_peer_protocol_error_reset() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_srv = Arc::clone(&accept_count);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                accept_count_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut conn = h2::server::handshake(stream).await.expect("h2 server handshake");
                    if let Some(Ok((_, mut respond))) = conn.accept().await {
                        let response = Response::builder().status(200).body(()).expect("response");
                        let _ = respond.send_response(response, true);
                    }
                    if let Some(Ok((_, mut respond))) = conn.accept().await {
                        respond.send_reset(h2::Reason::PROTOCOL_ERROR);
                    }
                    while conn.accept().await.is_some() {}
                });
            }
        });

        let dial_addr = addr.to_string();
        let transport = H2Transport {
            dial_tls: Arc::new(move |_ctx, _addr| {
                let dial_addr = dial_addr.clone();
                Box::pin(async move {
                    let stream = TcpStream::connect(&dial_addr).await?;
                    let conn: Box<dyn AnyConn> = Box::new(stream);
                    Ok(conn)
                })
            }),
            conn: Mutex::new(None),
            generation: std::sync::atomic::AtomicU64::new(0),
        };

        let uri: hyper::Uri = format!("https://{addr}/").parse().expect("uri");
        let req = || Request::get(uri.clone()).body(Full::new(Bytes::new())).expect("req");

        transport.round_trip(CancellationToken::new(), req()).await.expect("round trip 1 primes the pool");

        let result = transport
            .round_trip(CancellationToken::new(), req())
            .await
            .expect("RST_STREAM(PROTOCOL_ERROR) must evict the pooled conn and redial instead of failing");
        result.response.into_body().collect().await.expect("drain body");

        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            2,
            "RST_STREAM(PROTOCOL_ERROR) must evict the pooled generation and dial a fresh connection"
        );
    }
    /// A `GOAWAY` whose `last_stream_id` already covers the pending stream counts as processed:
    /// `h2` surfaces a plain `Io` error for it, not `Error::GoAway`, and this crate errors it
    /// rather than redialing. The pre-fix `!pooled.sender.is_closed()` check raced this 55-90% of
    /// the time into a silent redial instead. Drives a raw HTTP/2 frame server like
    /// `h2_transport_evicts_and_redials_after_goaway`, but with `last_stream_id=3` (covering the
    /// pending stream) and the socket closed right after, instead of kept open.
    #[tokio::test]
    async fn h2_transport_does_not_redial_after_a_processed_goaway_then_close() {
        async fn serve_one(mut stream: TcpStream) {
            let mut preface = [0u8; 24];
            if stream.read_exact(&mut preface).await.is_err() {
                return;
            }
            if stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.is_err() {
                return;
            }
            loop {
                let mut header = [0u8; 9];
                if stream.read_exact(&mut header).await.is_err() {
                    return;
                }
                let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
                let mut payload = vec![0u8; len];
                if stream.read_exact(&mut payload).await.is_err() {
                    return;
                }
                let frame_type = header[3];
                let flags = header[4];
                let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
                if frame_type == 4 && flags & 1 == 0 {
                    if stream.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await.is_err() {
                        return;
                    }
                } else if frame_type == 1 && stream_id == 1 {
                    if stream.write_all(&[0, 0, 1, 1, 5, 0, 0, 0, 1, 0x88]).await.is_err() {
                        return;
                    }
                } else if frame_type == 1 && stream_id == 3 {
                    // GOAWAY, last_stream_id=3 (this stream counts as processed), error=NO_ERROR,
                    // then close instead of keeping the connection open.
                    let _ = stream.write_all(&[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0]).await;
                    let _ = stream.flush().await;
                    return;
                }
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_srv = Arc::clone(&accept_count);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                accept_count_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve_one(stream));
            }
        });

        let dial_addr = addr.to_string();
        let transport = H2Transport {
            dial_tls: Arc::new(move |_ctx, _addr| {
                let dial_addr = dial_addr.clone();
                Box::pin(async move {
                    let stream = TcpStream::connect(&dial_addr).await?;
                    let conn: Box<dyn AnyConn> = Box::new(stream);
                    Ok(conn)
                })
            }),
            conn: Mutex::new(None),
            generation: std::sync::atomic::AtomicU64::new(0),
        };

        let uri: hyper::Uri = format!("https://{addr}/").parse().expect("uri");
        let req = || Request::get(uri.clone()).body(Full::new(Bytes::new())).expect("req");

        let first = transport.round_trip(CancellationToken::new(), req()).await.expect("round trip 1 primes the pool");
        first.response.into_body().collect().await.expect("drain body 1");

        let result = transport.round_trip(CancellationToken::new(), req()).await;
        assert!(result.is_err(), "a processed-then-closed GOAWAY must surface as an error rather than redial");

        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            1,
            "a processed-then-closed GOAWAY must not evict the pooled generation and dial a fresh connection"
        );
    }

    /// `should_evict` used to fire on any `is_go_away()`,
    /// including one `h2` raises itself (`Initiator::Library`) after noticing the peer violated
    /// the protocol -- not just a peer-sent (`Initiator::Remote`) `GOAWAY`. This case is never
    /// retried: a self-detected protocol violation means the peer is broken, not that the stream
    /// was merely unprocessed. Drives a raw HTTP/2 frame server like
    /// `h2_transport_evicts_and_redials_after_goaway`, but answers stream 3's `HEADERS` with a
    /// `DATA` frame on stream 0 -- an invalid stream ID for `DATA`, which `h2` rejects while
    /// decoding and turns into its own library-raised `GOAWAY(PROTOCOL_ERROR)` before the peer
    /// sends anything back.
    #[tokio::test]
    async fn h2_transport_errors_on_a_library_raised_goaway_without_redialing() {
        async fn serve_one(mut stream: TcpStream) {
            let mut preface = [0u8; 24];
            if stream.read_exact(&mut preface).await.is_err() {
                return;
            }
            if stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.is_err() {
                return;
            }
            loop {
                let mut header = [0u8; 9];
                if stream.read_exact(&mut header).await.is_err() {
                    return;
                }
                let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
                let mut payload = vec![0u8; len];
                if stream.read_exact(&mut payload).await.is_err() {
                    return;
                }
                let frame_type = header[3];
                let flags = header[4];
                let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
                if frame_type == 4 && flags & 1 == 0 {
                    if stream.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await.is_err() {
                        return;
                    }
                } else if frame_type == 1 && stream_id == 1 {
                    if stream.write_all(&[0, 0, 1, 1, 5, 0, 0, 0, 1, 0x88]).await.is_err() {
                        return;
                    }
                } else if frame_type == 1 && stream_id == 3 {
                    // DATA frame on stream 0: invalid, so h2 raises its own GOAWAY instead of
                    // waiting for anything more from the peer.
                    let _ = stream.write_all(&[0, 0, 0, 0, 0, 0, 0, 0, 0]).await;
                    let _ = stream.flush().await;
                }
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_srv = Arc::clone(&accept_count);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                accept_count_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve_one(stream));
            }
        });

        let dial_addr = addr.to_string();
        let transport = H2Transport {
            dial_tls: Arc::new(move |_ctx, _addr| {
                let dial_addr = dial_addr.clone();
                Box::pin(async move {
                    let stream = TcpStream::connect(&dial_addr).await?;
                    let conn: Box<dyn AnyConn> = Box::new(stream);
                    Ok(conn)
                })
            }),
            conn: Mutex::new(None),
            generation: std::sync::atomic::AtomicU64::new(0),
        };

        let uri: hyper::Uri = format!("https://{addr}/").parse().expect("uri");
        let req = || Request::get(uri.clone()).body(Full::new(Bytes::new())).expect("req");

        let first = transport.round_trip(CancellationToken::new(), req()).await.expect("round trip 1 primes the pool");
        first.response.into_body().collect().await.expect("drain body 1");

        let result = transport.round_trip(CancellationToken::new(), req()).await;
        assert!(
            result.is_err(),
            "a library-raised GOAWAY (the client's own protocol-violation detection) must surface as an error \
             rather than redial"
        );

        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            1,
            "a library-raised GOAWAY must not evict the pooled generation and dial a fresh connection"
        );
    }

    /// A response body that never completes and a server that never closes the connection stand
    /// in for the real mekya server holding a response open for `max_write_duration_ms`.
    /// `session_round_trip`'s body read must still return
    /// promptly once `session.ctx` is cancelled instead of blocking until the peer gives up.
    #[tokio::test]
    async fn session_round_trip_body_read_exits_on_session_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let mut buf = vec![0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
            let _ = stream.flush().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let ctx = CancellationToken::new();
        let dial_tls: DialTlsFn = Arc::new(move |_ctx, _addr| {
            Box::pin(async move {
                let stream = TcpStream::connect(addr).await?;
                let conn: Box<dyn AnyConn> = Box::new(stream);
                Ok(conn)
            })
        });
        let rt: Arc<dyn RoundTripper> = Arc::new(H1Transport {
            dial_tls,
            idle: Arc::new(Mutex::new(HashMap::new())),
            close_idle: Arc::new(AtomicBool::new(false)),
        });
        let (writer_tx, _writer_rx) = mpsc::channel(1);
        let (reader_tx, reader_rx) = mpsc::channel(1);
        let session = Arc::new(RequestClientSession {
            ctx: ctx.child_token(),
            session_id: vec![0u8; 16],
            rt,
            url: format!("https://{addr}/mekya"),
            current_polling_interval: 20,
            max_request_size: 96000,
            max_write_delay: 20,
            writer_tx,
            reader_tx,
            reader_rx: tokio::sync::Mutex::new(reader_rx),
            deadlines: new_pipe_deadlines(),
            addr: RwLock::new(AddrState { local: None, remote: None }),
            read_future: Mutex::new(None),
            write_future: Mutex::new(None),
        });

        let handle = tokio::spawn({
            let session = Arc::clone(&session);
            async move { session_round_trip(&session, Vec::new()).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        session.close();

        tokio::time::timeout(Duration::from_millis(300), handle)
            .await
            .expect("body read must exit promptly once session.ctx is cancelled")
            .expect("task must not panic");
    }

    /// Same shape as `session_round_trip_body_read_exits_on_session_close`, but the peer never
    /// writes the response headers (the mekya server writes headers lazily, only on its first
    /// packet flush or `max_write_duration_ms`). Per
    /// `session_round_trip`'s wait for headers at `round_trip(...).await`
    /// must also race `session.ctx`, not just the body read that follows it.
    #[tokio::test]
    async fn session_round_trip_header_wait_exits_on_session_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let mut buf = vec![0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let ctx = CancellationToken::new();
        let dial_tls: DialTlsFn = Arc::new(move |_ctx, _addr| {
            Box::pin(async move {
                let stream = TcpStream::connect(addr).await?;
                let conn: Box<dyn AnyConn> = Box::new(stream);
                Ok(conn)
            })
        });
        let rt: Arc<dyn RoundTripper> = Arc::new(H1Transport {
            dial_tls,
            idle: Arc::new(Mutex::new(HashMap::new())),
            close_idle: Arc::new(AtomicBool::new(false)),
        });
        let (writer_tx, _writer_rx) = mpsc::channel(1);
        let (reader_tx, reader_rx) = mpsc::channel(1);
        let session = Arc::new(RequestClientSession {
            ctx: ctx.child_token(),
            session_id: vec![0u8; 16],
            rt,
            url: format!("https://{addr}/mekya"),
            current_polling_interval: 20,
            max_request_size: 96000,
            max_write_delay: 20,
            writer_tx,
            reader_tx,
            reader_rx: tokio::sync::Mutex::new(reader_rx),
            deadlines: new_pipe_deadlines(),
            addr: RwLock::new(AddrState { local: None, remote: None }),
            read_future: Mutex::new(None),
            write_future: Mutex::new(None),
        });

        let handle = tokio::spawn({
            let session = Arc::clone(&session);
            async move { session_round_trip(&session, Vec::new()).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        session.close();

        tokio::time::timeout(Duration::from_millis(300), handle)
            .await
            .expect("header wait must exit promptly once session.ctx is cancelled")
            .expect("task must not panic");
    }

    fn version_string(version: Version) -> String {
        match version {
            Version::HTTP_09 => "HTTP/0.9".to_owned(),
            Version::HTTP_10 => "HTTP/1.0".to_owned(),
            Version::HTTP_11 => "HTTP/1.1".to_owned(),
            Version::HTTP_2 => "HTTP/2.0".to_owned(),
            Version::HTTP_3 => "HTTP/3.0".to_owned(),
            other => format!("{other:?}"),
        }
    }

    async fn start_alpn_test_http_server(next_protos: &[&str]) -> (String, mpsc::Receiver<String>) {
        let protos: Vec<String> = if next_protos.is_empty() {
            vec![HTTP2_NEXT_PROTO_TLS.to_owned(), "http/1.1".to_owned()]
        } else {
            next_protos.iter().map(|p| (*p).to_owned()).collect()
        };

        let loader = ca::keypair::new_tls_key_pair_loader("", "").expect("cert loader");
        let certificate = loader().expect("cert value");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let (tx, rx) = mpsc::channel(4);

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                let tx = tx.clone();
                let certificate = certificate.clone();
                let protos = protos.clone();
                tokio::spawn(async move {
                    let tls_config =
                        utls::Config { certificates: vec![certificate], next_protos: protos, ..Default::default() };
                    let conn = utls::server(Box::new(stream), Arc::new(tls_config));
                    let handshake_ctx = CancellationToken::new();
                    if conn.handshake_context(&handshake_ctx).await.is_err() {
                        return;
                    }
                    let io = TokioIo::new(Box::new(conn));
                    let tx = tx.clone();
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let tx = tx.clone();
                        async move {
                            let _ = tx.send(version_string(req.version())).await;
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                        }
                    });
                    let builder = auto::Builder::new(TokioExecutor::new());
                    let _ = builder.serve_connection(io, svc).await;
                });
            }
        });

        (addr, rx)
    }

    /// This crate has a single `component::tls::utls` port, so the two
    /// variants here differ only by the client-hello fingerprint used.
    type ConnFactory = fn(String, Vec<String>, String) -> BoxFuture<'static, anyhow::Result<Box<dyn AnyConn>>>;

    async fn new_alpn_test_conn(
        addr: &str,
        protocols: &[String],
        negotiated: &str,
        fingerprint: utls::UClientHelloID,
    ) -> anyhow::Result<Box<dyn AnyConn>> {
        let stream = TcpStream::connect(addr).await?;
        let config = utls::Config { insecure_skip_verify: true, next_protos: protocols.to_vec(), ..Default::default() };
        let mut conn = utls::uclient(Box::new(stream), Arc::new(config), fingerprint);
        let handshake_ctx = CancellationToken::new();
        conn.handshake_context(&handshake_ctx).await?;
        let state = get_tls_connection_state(&conn);
        if state.negotiated_protocol != negotiated {
            let _ = close_stream(&conn);
            return Err(anyhow!("negotiated ALPN {:?}, want {:?}", state.negotiated_protocol, negotiated));
        }
        Ok(Box::new(conn))
    }

    fn new_default_test_conn(
        addr: String,
        protocols: Vec<String>,
        negotiated: String,
    ) -> BoxFuture<'static, anyhow::Result<Box<dyn AnyConn>>> {
        Box::pin(async move { new_alpn_test_conn(&addr, &protocols, &negotiated, utls::hello_default()).await })
    }

    fn new_browser_test_conn(
        addr: String,
        protocols: Vec<String>,
        negotiated: String,
    ) -> BoxFuture<'static, anyhow::Result<Box<dyn AnyConn>>> {
        Box::pin(async move { new_alpn_test_conn(&addr, &protocols, &negotiated, utls::hello_chrome_auto()).await })
    }

    fn new_alpn_test_dialer(
        new_conn: ConnFactory,
        addr: String,
        protocols: Vec<&'static str>,
    ) -> (DialFunc, Arc<AtomicUsize>) {
        let dial_count = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&dial_count);
        let protocols: Vec<String> = protocols.into_iter().map(str::to_owned).collect();
        let dial: DialFunc = Arc::new(move |ctx: CancellationToken| {
            let addr = addr.clone();
            let protocols = protocols.clone();
            let dial_count = Arc::clone(&dial_count);
            Box::pin(async move {
                if ctx.is_cancelled() {
                    return Err(err_context_canceled().into());
                }
                let index = dial_count.fetch_add(1, Ordering::SeqCst);
                let Some(protocol) = protocols.get(index) else {
                    return Err(anyhow!("unexpected ALPN test dial {}", index + 1));
                };
                let client_protocols = if protocol.is_empty() { Vec::new() } else { vec![protocol.clone()] };
                new_conn(addr, client_protocols, protocol.clone()).await
            })
        });
        (dial, count)
    }

    fn new_alpn_test_dialer_with_client_protocols(
        new_conn: ConnFactory,
        addr: String,
        client_protocols: Vec<&'static str>,
        negotiated_protocols: Vec<&'static str>,
    ) -> (DialFunc, Arc<AtomicUsize>) {
        let dial_count = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&dial_count);
        let client_protocols: Vec<String> = client_protocols.into_iter().map(str::to_owned).collect();
        let negotiated_protocols: Vec<String> = negotiated_protocols.into_iter().map(str::to_owned).collect();
        let dial: DialFunc = Arc::new(move |ctx: CancellationToken| {
            let addr = addr.clone();
            let client_protocols = client_protocols.clone();
            let negotiated_protocols = negotiated_protocols.clone();
            let dial_count = Arc::clone(&dial_count);
            Box::pin(async move {
                if ctx.is_cancelled() {
                    return Err(err_context_canceled().into());
                }
                let index = dial_count.fetch_add(1, Ordering::SeqCst);
                let Some(negotiated) = negotiated_protocols.get(index) else {
                    return Err(anyhow!("unexpected ALPN test dial {}", index + 1));
                };
                new_conn(addr, client_protocols.clone(), negotiated.clone()).await
            })
        });
        (dial, count)
    }

    fn test_request(url: &str) -> Request<Full<Bytes>> {
        let uri: hyper::Uri = url.parse().expect("valid test uri");
        let authority = uri.authority().expect("test uri has an authority").clone();
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(hyper::header::HOST, authority.as_str())
            .body(Full::new(Bytes::new()))
            .expect("request")
    }

    async fn require_alpn_round_trip(
        rt: &dyn RoundTripper,
        url: &str,
        seen_proto: &mut mpsc::Receiver<String>,
        expected_proto: &str,
    ) {
        let ctx = CancellationToken::new();
        let req = test_request(url);
        let result = rt.round_trip(ctx, req).await.expect("round trip");
        let _ = result.response.into_body().collect().await.expect("body").to_bytes();

        match tokio::time::timeout(Duration::from_secs(1), seen_proto.recv()).await {
            Ok(Some(proto)) => assert_eq!(proto, expected_proto),
            _ => panic!("timed out waiting for ALPN test request"),
        }
    }

    async fn require_alpn_round_trip_error(rt: &dyn RoundTripper, url: &str) {
        let ctx = CancellationToken::new();
        let req = test_request(url);
        let err = rt.round_trip(ctx, req).await.expect_err("expected error");
        assert!(matches!(err.downcast_ref::<MekyaError>(), Some(MekyaError::UnexpectedAlpn)));
    }

    fn require_no_alpn_request(seen_proto: &mut mpsc::Receiver<String>) {
        assert!(seen_proto.try_recv().is_err());
    }

    async fn alpn_round_trip_case(
        new_conn: ConnFactory,
        addr: &str,
        seen_proto: &mut mpsc::Receiver<String>,
        server_protos: Vec<&'static str>,
        expected_proto: &str,
        expected_h1: bool,
    ) {
        let url = format!("https://{addr}/mekya");
        let (dial, dial_count) = new_alpn_test_dialer(new_conn, addr.to_owned(), server_protos);
        let rt = new_round_tripper(dial, 0);
        require_alpn_round_trip(rt.as_ref(), &url, seen_proto, expected_proto).await;
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);
        assert_eq!(rt.should_connect_with_h1(addr), expected_h1);
        force_close::close_transport(rt.as_ref());
    }

    /// Scoped to the core ALPN state-transition cases (h2
    /// direct, http1/empty-ALPN fallback, each transport rejecting the other's ALPN, and the
    /// remembered-h1 cache both persisting and being replaced) rather than every server-address
    /// permutation, since those exercise the identical dial path
    /// code path against a differently-restricted test server.
    async fn alpn_routing_cases(new_conn: ConnFactory) {
        let (addr, mut seen_proto) = start_alpn_test_http_server(&[]).await;
        let url = format!("https://{addr}/mekya");

        alpn_round_trip_case(new_conn, &addr, &mut seen_proto, vec![HTTP2_NEXT_PROTO_TLS], "HTTP/2.0", false).await;
        alpn_round_trip_case(new_conn, &addr, &mut seen_proto, vec!["http/1.1"], "HTTP/1.1", true).await;
        alpn_round_trip_case(new_conn, &addr, &mut seen_proto, vec![""], "HTTP/1.1", true).await;

        {
            let (dial, dial_count) = new_alpn_test_dialer(new_conn, addr.clone(), vec![HTTP2_NEXT_PROTO_TLS]);
            let rt = new_round_tripper(dial, 0);
            rt.state.lock().connect_with_h1.insert(addr.clone(), true);
            require_alpn_round_trip_error(rt.h1.as_ref(), &url).await;
            assert_eq!(dial_count.load(Ordering::SeqCst), 1);
            assert!(!rt.should_connect_with_h1(&addr));
            force_close::close_transport(rt.as_ref());
        }

        {
            let (dial, dial_count) = new_alpn_test_dialer(new_conn, addr.clone(), vec!["http/1.1"]);
            let rt = new_round_tripper(dial, 0);
            require_alpn_round_trip_error(rt.h2.as_ref(), &url).await;
            assert_eq!(dial_count.load(Ordering::SeqCst), 1);
            assert!(rt.should_connect_with_h1(&addr));
            force_close::close_transport(rt.as_ref());
        }

        {
            let (dial, dial_count) = new_alpn_test_dialer(new_conn, addr.clone(), vec!["http/1.1", "http/1.1"]);
            let rt = new_round_tripper(dial, 0);
            require_alpn_round_trip(rt.as_ref(), &url, &mut seen_proto, "HTTP/1.1").await;
            assert!(rt.should_connect_with_h1(&addr));
            force_close::close_transport(rt.h1.as_ref());

            require_alpn_round_trip(rt.as_ref(), &url, &mut seen_proto, "HTTP/1.1").await;
            assert_eq!(dial_count.load(Ordering::SeqCst), 2);
            assert!(rt.should_connect_with_h1(&addr));
            force_close::close_transport(rt.as_ref());
        }

        {
            let (dial, dial_count) =
                new_alpn_test_dialer(new_conn, addr.clone(), vec!["http/1.1", HTTP2_NEXT_PROTO_TLS]);
            let rt = new_round_tripper(dial, 0);
            require_alpn_round_trip(rt.as_ref(), &url, &mut seen_proto, "HTTP/1.1").await;
            assert!(rt.should_connect_with_h1(&addr));
            force_close::close_transport(rt.h1.as_ref());

            require_alpn_round_trip(rt.as_ref(), &url, &mut seen_proto, "HTTP/2.0").await;
            assert_eq!(dial_count.load(Ordering::SeqCst), 2);
            assert!(!rt.should_connect_with_h1(&addr));
            force_close::close_transport(rt.as_ref());
        }

        let _ = require_no_alpn_request;
        let _ = new_alpn_test_dialer_with_client_protocols;
    }

    #[tokio::test]
    async fn alpn_routing_default_hello() {
        alpn_routing_cases(new_default_test_conn).await;
    }

    #[tokio::test]
    async fn alpn_routing_browser() {
        alpn_routing_cases(new_browser_test_conn).await;
    }

    #[tokio::test]
    async fn any_conn_as_any_reaches_the_boxed_conn_not_the_box() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = TcpStream::connect(addr).await.expect("connect");
        let boxed: Box<dyn AnyConn> = Box::new(stream);
        assert!(
            AnyConn::as_any(boxed.as_ref()).downcast_ref::<TcpStream>().is_some(),
            "expected the boxed TcpStream, got the box"
        );
    }
}

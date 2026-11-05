//! Server side of the protocol, with the response body returned as a stream.
//!
//! The blocking handler model (the request handler blocks on a select
//! over the request context's done channel and the connection's wait channel before returning,
//! keeping the response open) has no
//! async equivalent that also streams the response body; this crate returns the streamed
//! `hyper::Response` immediately, backed by an `http_body_util::channel` body, and relies on that
//! channel and the incoming request body naturally failing once either side disconnects, since
//! [`Handler::serve`] does not own the surrounding connection's accept loop.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use dashmap::{mapref::entry::Entry, DashMap};
use futures::future::BoxFuture;
use futures::stream::StreamExt;
use http::StatusCode;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::Incoming;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::{watch, Mutex as AsyncMutex};
use tokio_util::io::StreamReader;

use murmur_common_httputils::addr::{set_addr_from_request, NetAddr};
use murmur_common_net::io::StreamAsOldConn;
use murmur_std_compat::net::Conn as NetConn;

use super::config::{Config, Request, PLACEMENT_AUTO, PLACEMENT_BODY, PLACEMENT_COOKIE, PLACEMENT_HEADER};
use super::conn::{Conn as XConn, ReadCloser, WriteCloser};
use super::upload_queue::{Packet, UploadQueue, UploadQueueHandle};
use super::xpadding::{PaddingMethod, XPaddingConfig, XPaddingPlacement};

/// The response body channel's buffer, in frames: a response writer has no equivalent
/// bound (every `Write` is flushed immediately), so this is a generous, arbitrary backpressure
/// limit rather than a behaviour-preserving constant.
const RESPONSE_CHANNEL_CAPACITY: usize = 32;

type ResponseBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;
type ChannelSender = tokio::sync::mpsc::Sender<Bytes>;

/// Stands in for `http_body_util::channel::Channel` (its `channel` Cargo feature is not enabled
/// for this crate; see `transport/mekya/server.rs`'s identical adapter): a `hyper::body::Body`
/// that yields whatever `Bytes` chunks arrive on an `mpsc` channel, ending the body when the
/// sender drops.
struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
}

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, std::convert::Infallible>>> {
        self.rx.poll_recv(cx).map(|chunk| chunk.map(|chunk| Ok(hyper::body::Frame::data(chunk))))
    }
}

fn channel_body(buffer: usize) -> (ChannelSender, ChannelBody) {
    let (tx, rx) = tokio::sync::mpsc::channel(buffer);
    (tx, ChannelBody { rx })
}

fn text_response(status: StatusCode, message: &str) -> hyper::Response<ResponseBody> {
    let body = Full::new(Bytes::from(format!("{message}\n"))).boxed();
    let mut response = hyper::Response::new(body);
    *response.status_mut() = status;
    response
}

fn empty_response(status: StatusCode) -> hyper::Response<ResponseBody> {
    let body = Empty::new().boxed();
    let mut response = hyper::Response::new(body);
    *response.status_mut() = status;
    response
}

/// `ConnHandler`, adapted to return a future.
///
/// The tunnel handlers here are async (mirroring the `futures::future::BoxFuture` convention
/// used by other transports' dial/handler callbacks in this crate).
pub type ConnHandler = Arc<dyn Fn(Box<dyn NetConn>) -> BoxFuture<'static, ()> + Send + Sync>;

/// A handler, narrowed to the one method this crate's request handling needs.
#[async_trait]
pub trait Handler: Send + Sync {
    async fn serve(&self, req: hyper::Request<Incoming>) -> hyper::Response<ResponseBody>;
}

pub struct ServerOption {
    pub config: Config,
    pub conn_handler: Option<ConnHandler>,
    pub http_handler: Option<Arc<dyn Handler>>,
}

impl std::fmt::Debug for ServerOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerOption")
            .field("config", &self.config)
            .field("conn_handler", &self.conn_handler.is_some())
            .field("http_handler", &self.http_handler.is_some())
            .finish_non_exhaustive()
    }
}

/// The server-side connection, minus the wait channel this crate does not need (see the module doc
/// comment).
struct HttpServerConn {
    reader: AsyncMutex<Pin<Box<dyn AsyncRead + Send>>>,
    tx: AsyncMutex<Option<ChannelSender>>,
    closed: AtomicBool,
}

impl HttpServerConn {
    fn new(reader: Pin<Box<dyn AsyncRead + Send>>, tx: ChannelSender) -> Arc<Self> {
        Arc::new(Self {
            reader: AsyncMutex::new(reader),
            tx: AsyncMutex::new(Some(tx)),
            closed: AtomicBool::new(false),
        })
    }

    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        let mut reader = self.reader.lock().await;
        reader.read(buf).await
    }

    // `significant_drop_tightening` resolves its level from the enclosing item, so the expectation
    // has to sit on the function rather than on the `lock` statement.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the sender is borrowed out of the locked slot, so the guard has to span the send"
    )]
    async fn write(&self, data: &[u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        let mut guard = self.tx.lock().await;
        let Some(sender) = guard.as_mut() else {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        };
        match sender.send(Bytes::copy_from_slice(data)).await {
            Ok(()) => Ok(data.len()),
            Err(_) => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

struct HttpServerConnReader {
    conn: Arc<HttpServerConn>,
    pending: Option<Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>>>,
    /// A direct read would go into the caller's `b`, so it could never return
    /// more than `len(b)` bytes. This instead reads into an internally sized buffer across
    /// possibly-`Pending` polls, so a completed read can carry more bytes than a later poll's
    /// (smaller) `buf` has room for; those spill here and are drained on the next call instead of
    /// overflowing `buf`.
    carry: Vec<u8>,
}

impl AsyncRead for HttpServerConnReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.carry.is_empty() {
            let n = this.carry.len().min(buf.remaining());
            buf.put_slice(this.carry.get(..n).unwrap_or_default());
            this.carry.drain(..n);
            return Poll::Ready(Ok(()));
        }
        let want = buf.remaining();
        let pending = this.pending.get_or_insert_with(|| {
            let conn = Arc::clone(&this.conn);
            Box::pin(async move {
                let mut tmp = vec![0u8; want];
                let n = conn.read(&mut tmp).await?;
                tmp.truncate(n);
                Ok(tmp)
            })
        });
        match pending.as_mut().poll(cx) {
            Poll::Ready(Ok(mut data)) => {
                this.pending = None;
                let n = data.len().min(buf.remaining());
                buf.put_slice(data.get(..n).unwrap_or_default());
                if n < data.len() {
                    this.carry = data.split_off(n);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                this.pending = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl ReadCloser for HttpServerConnReader {
    fn close(&self) -> io::Result<()> {
        self.conn.close();
        Ok(())
    }
}

struct HttpServerConnWriter {
    conn: Arc<HttpServerConn>,
    pending: Option<Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>>,
}

impl AsyncWrite for HttpServerConnWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let pending = this.pending.get_or_insert_with(|| {
            let data = buf.to_vec();
            let conn = Arc::clone(&this.conn);
            Box::pin(async move { conn.write(&data).await })
        });
        match pending.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.pending = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl WriteCloser for HttpServerConnWriter {
    fn close(&self) -> io::Result<()> {
        self.conn.close();
        Ok(())
    }
}

/// The HTTP session. `connected` is a `tokio::sync::watch` rather than a channel closed once,
/// since the reaper task below must also observe a session that is already connected by the time
/// it starts waiting, which `tokio::sync::Notify` cannot express.
struct HttpSession {
    upload_queue: Arc<UploadQueue>,
    connected_tx: watch::Sender<bool>,
    connected_rx: watch::Receiver<bool>,
}

impl HttpSession {
    fn new(max_packets: i64) -> Arc<Self> {
        let (connected_tx, connected_rx) = watch::channel(false);
        Arc::new(Self { upload_queue: UploadQueue::new(max_packets), connected_tx, connected_rx })
    }

    fn mark_connected(&self) {
        let _ = self.connected_tx.send(true);
    }
}

pub struct RequestHandler {
    config: Config,
    conn_handler: Option<ConnHandler>,
    http_handler: Option<Arc<dyn Handler>>,

    x_padding_bytes: super::config::Range,
    sc_max_each_post_bytes: super::config::Range,
    sc_stream_up_server_secs: super::config::Range,
    sc_max_buffered_posts: super::config::Range,

    sessions: DashMap<String, Arc<HttpSession>>,
    self_weak: Weak<Self>,
}

impl std::fmt::Debug for RequestHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestHandler")
            .field("config", &self.config)
            .field("sessions", &self.sessions.len())
            .field("conn_handler", &self.conn_handler.is_some())
            .field("http_handler", &self.http_handler.is_some())
            .finish_non_exhaustive()
    }
}

impl RequestHandler {
    pub fn new(opt: ServerOption) -> anyhow::Result<Arc<Self>> {
        let x_padding_bytes = opt.config.normalized_x_padding_bytes()?;
        let sc_max_each_post_bytes = opt.config.normalized_sc_max_each_post_bytes()?;
        let sc_stream_up_server_secs = opt.config.normalized_sc_stream_up_server_secs()?;
        let sc_max_buffered_posts = opt.config.normalized_sc_max_buffered_posts()?;
        Ok(Arc::new_cyclic(|weak| Self {
            config: opt.config,
            conn_handler: opt.conn_handler,
            http_handler: opt.http_handler,
            x_padding_bytes,
            sc_max_each_post_bytes,
            sc_stream_up_server_secs,
            sc_max_buffered_posts,
            sessions: DashMap::new(),
            self_weak: Weak::clone(weak),
        }))
    }

    /// Inserts or returns a session. `DashMap::entry` holds that key's shard lock across the
    /// lookup and the insert, so two concurrent first-arrivals for one session id cannot both
    /// create and insert.
    fn upsert_session(&self, session_id: &str) -> Arc<HttpSession> {
        match self.sessions.entry(session_id.to_owned()) {
            Entry::Occupied(entry) => Arc::clone(entry.get()),
            Entry::Vacant(entry) => {
                let session = HttpSession::new(self.sc_max_buffered_posts.max);
                entry.insert(Arc::clone(&session));

                let session_id = session_id.to_owned();
                let mut connected_rx = session.connected_rx.clone();
                let reaped_session = Arc::clone(&session);
                if let Some(this) = self.self_weak.upgrade() {
                    tokio::spawn(async move {
                        tokio::select! {
                            () = tokio::time::sleep(Duration::from_secs(30)) => {
                                this.reap_session(&session_id, &reaped_session);
                            }
                            _ = connected_rx.wait_for(|connected| *connected) => {}
                        }
                    });
                }

                session
            }
        }
    }

    /// Removes `session_id` only while it still maps to `session`. Deliberate divergence: a
    /// reaper that deleted unconditionally by id would have no check that the stored session is
    /// still the one it was started for. If S1 is deleted (its connection closes, or a caller
    /// calls `delete_session` directly) and a fresh S2 is created under the same `session_id`
    /// before S1's 30-second timer fires, an unconditional reaper would delete S2 and close its
    /// upload queue, killing a live connection that has nothing to do with the timed-out S1. The
    /// `Arc::ptr_eq` check here keeps S2 alive by only removing the entry if it is still literally
    /// the `Arc` this reaper was spawned for (`rust/README.md`'s "Known divergences" section lists
    /// this).
    fn reap_session(&self, session_id: &str, session: &Arc<HttpSession>) {
        if let Some((_, removed)) = self.sessions.remove_if(session_id, |_, v| Arc::ptr_eq(v, session)) {
            let _ = removed.upload_queue.close();
        }
    }

    fn delete_session(&self, session_id: &str) {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            let _ = session.upload_queue.close();
        }
    }

    #[allow(dead_code, reason = "no caller")]
    fn session(&self, session_id: &str) -> Option<Arc<HttpSession>> {
        self.sessions.get(session_id).map(|entry| entry.clone())
    }

    fn normalized_mode(&self) -> &str {
        if self.config.mode.is_empty() {
            "auto"
        } else {
            &self.config.mode
        }
    }

    fn allow_stream_one(&self) -> bool {
        matches!(self.normalized_mode(), "auto" | "stream-one" | "stream-up")
    }

    fn allow_session_download(&self) -> bool {
        matches!(self.normalized_mode(), "auto" | "stream-up" | "packet-up")
    }

    fn allow_stream_up_upload(&self) -> bool {
        matches!(self.normalized_mode(), "auto" | "stream-up")
    }

    fn allow_packet_up_upload(&self) -> bool {
        matches!(self.normalized_mode(), "auto" | "packet-up")
    }
}

/// A request, narrowed to the fields `Config`'s extraction methods read, built once per
/// request from the real `hyper::Request<Incoming>` headers/URI.
fn extraction_request(req: &hyper::Request<Incoming>) -> Request {
    let path_and_query = req.uri().path_and_query().map_or("/", http::uri::PathAndQuery::as_str);
    let url = url::Url::parse(&format!("http://placeholder{path_and_query}")).unwrap_or_else(|_| placeholder_url());
    Request {
        method: req.method().to_string(),
        url,
        host: String::new(),
        header: req.headers().clone(),
        body: None,
        content_length: 0,
    }
}

#[expect(clippy::expect_used, reason = "the placeholder URL is a constant that always parses")]
fn placeholder_url() -> url::Url {
    url::Url::parse("http://placeholder/").expect("static URL")
}

fn request_host(req: &hyper::Request<Incoming>) -> String {
    req.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("").to_owned()
}

#[allow(dead_code, reason = "no caller")]
pub(crate) fn split_non_empty(s: &str) -> Vec<&str> {
    s.split('/').filter(|part| !part.is_empty()).collect()
}

pub(crate) fn equal_host(a: &str, b: &str) -> bool {
    let a = a.to_lowercase();
    let b = b.to_lowercase();
    let a = a.rsplit_once(':').map_or(a.as_str(), |(host, _)| host);
    let b = b.rsplit_once(':').map_or(b.as_str(), |(host, _)| host);
    a == b
}

fn read_header_payload(req: &hyper::Request<Incoming>, uplink_data_key: &str) -> Result<Vec<u8>, ()> {
    let mut chunks = Vec::new();
    let mut i = 0usize;
    loop {
        let key = format!("{uplink_data_key}-{i}");
        let Some(value) = req.headers().get(&key).and_then(|v| v.to_str().ok()) else {
            break;
        };
        chunks.push(value.to_owned());
        i += 1;
    }
    URL_SAFE_NO_PAD.decode(chunks.join("")).map_err(|_| ())
}

fn read_cookie_payload(extraction_req: &Request, uplink_data_key: &str) -> Result<Vec<u8>, ()> {
    let mut chunks = Vec::new();
    let mut i = 0usize;
    loop {
        let name = format!("{uplink_data_key}_{i}");
        let Some(cookie) = extraction_req.cookie(&name) else {
            break;
        };
        chunks.push(cookie.value);
        i += 1;
    }
    URL_SAFE_NO_PAD.decode(chunks.join("")).map_err(|_| ())
}

#[async_trait]
impl Handler for RequestHandler {
    async fn serve(&self, req: hyper::Request<Incoming>) -> hyper::Response<ResponseBody> {
        Self::serve_http(self, req).await
    }
}

impl RequestHandler {
    async fn serve_http(&self, req: hyper::Request<Incoming>) -> hyper::Response<ResponseBody> {
        let path = self.config.normalized_path();

        if let Some(http_handler) = &self.http_handler {
            if !req.uri().path().starts_with(&path) {
                return http_handler.serve(req).await;
            }
        }

        if !self.config.host.is_empty() && !equal_host(&request_host(&req), &self.config.host) {
            return empty_response(StatusCode::NOT_FOUND);
        }

        if !req.uri().path().starts_with(&path) {
            return empty_response(StatusCode::NOT_FOUND);
        }

        let extraction_req = extraction_request(&req);

        let mut response_header = http::HeaderMap::new();
        self.config.write_response_header(&mut response_header, req.method().as_str(), req.headers());
        self.config.apply_x_padding_to_response(&mut response_header, &self.padding_config());

        if req.method() == http::Method::OPTIONS {
            let mut resp = empty_response(StatusCode::OK);
            *resp.headers_mut() = response_header;
            return resp;
        }

        let (padding_value, _) =
            self.config.extract_x_padding_from_request(&extraction_req, self.config.x_padding_obfs_mode);
        if !self.config.is_padding_valid(
            &padding_value,
            self.x_padding_bytes.min,
            self.x_padding_bytes.max,
            &PaddingMethod(self.config.x_padding_method.clone()),
        ) {
            let mut resp = text_response(StatusCode::BAD_REQUEST, "invalid xpadding");
            resp.headers_mut().extend(response_header);
            return resp;
        }
        let obfs_padding_accepted = self.config.x_padding_obfs_mode && !padding_value.is_empty();
        let (session_id, seq_str) = self.config.extract_meta_from_request(&extraction_req, &path);

        if !session_id.is_empty() {
            let session = self.upsert_session(&session_id);
            // stream-up upload: POST /path/{session}
            if req.method() != http::Method::GET && seq_str.is_empty() && self.allow_stream_up_upload() {
                return self.serve_stream_up_upload(req, session, response_header, obfs_padding_accepted).await;
            }
            // packet-up upload: POST /path/{session}/{seq}
            if req.method() != http::Method::GET && !seq_str.is_empty() && self.allow_packet_up_upload() {
                return self.serve_packet_up_upload(req, extraction_req, &seq_str, session, response_header).await;
            }
            // stream-up/packet-up download: GET /path/{session}
            if req.method() == http::Method::GET && seq_str.is_empty() && self.allow_session_download() {
                return self.serve_session_download(req, &session_id, &session, response_header);
            }
        }

        // stream-one: POST /path
        if req.method() != http::Method::GET && session_id.is_empty() && seq_str.is_empty() && self.allow_stream_one() {
            return self.serve_stream_one(req, response_header);
        }

        empty_response(StatusCode::NOT_FOUND)
    }

    /// `XPaddingConfig` for this response: the configured obfuscation placement and method when
    /// `x-padding-obfs-mode` is on, the fixed `X-Padding` header placement otherwise.
    fn padding_config(&self) -> XPaddingConfig {
        let length = self.x_padding_bytes.rand();
        let mut x_padding_config =
            XPaddingConfig { length, placement: XPaddingPlacement::default(), method: PaddingMethod::default() };
        if self.config.x_padding_obfs_mode {
            x_padding_config.placement = XPaddingPlacement {
                placement: self.config.x_padding_placement.clone(),
                key: self.config.x_padding_key.clone(),
                header: self.config.x_padding_header.clone(),
                raw_url: String::new(),
            };
            x_padding_config.method = PaddingMethod(self.config.x_padding_method.clone());
        } else {
            x_padding_config.placement = XPaddingPlacement {
                placement: PLACEMENT_HEADER.to_owned(),
                header: "X-Padding".to_owned(),
                key: String::new(),
                raw_url: String::new(),
            };
        }
        x_padding_config
    }

    /// stream-up upload: POST /path/{session}
    async fn serve_stream_up_upload(
        &self,
        req: hyper::Request<Incoming>,
        session: Arc<HttpSession>,
        response_header: http::HeaderMap,
        obfs_padding_accepted: bool,
    ) -> hyper::Response<ResponseBody> {
        let mut response_header = response_header;
        let has_legacy_referer_compat_marker = req.headers().get(http::header::REFERER).is_some();
        let (tx, body) = channel_body(RESPONSE_CHANNEL_CAPACITY);
        let incoming_stream = req.into_body().into_data_stream().map(|res| res.map_err(io::Error::other));
        let body_reader = Box::pin(StreamReader::new(incoming_stream));
        let http_sc = HttpServerConn::new(body_reader, tx);

        let push_result = session
            .upload_queue
            .push(Packet {
                seq: 0,
                payload: Vec::new(),
                reader: Some(Box::pin(HttpServerConnReader {
                    conn: Arc::clone(&http_sc),
                    pending: None,
                    carry: Vec::new(),
                })),
            })
            .await;
        if let Err(err) = push_result {
            return finish_with(text_response(StatusCode::CONFLICT, &err.to_string()), response_header);
        }

        response_header.insert("X-Accel-Buffering", http::HeaderValue::from_static("no"));
        response_header.insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
        if !self.config.no_sse_header {
            response_header.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/event-stream"));
        }

        if (has_legacy_referer_compat_marker || obfs_padding_accepted) && self.sc_stream_up_server_secs.max > 0 {
            let x_padding_bytes = self.x_padding_bytes;
            let sc_stream_up_server_secs = self.sc_stream_up_server_secs;
            tokio::spawn(async move {
                loop {
                    let padding = vec![b'X'; byte_size(x_padding_bytes.rand())];
                    if http_sc.write(&padding).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(sc_stream_up_server_secs.rand().max(0).cast_unsigned()))
                        .await;
                }
            });
        }

        ok_response(body, response_header)
    }

    /// packet-up upload: POST /path/{session}/{seq}
    async fn serve_packet_up_upload(
        &self,
        req: hyper::Request<Incoming>,
        extraction_req: Request,
        seq_str: &str,
        session: Arc<HttpSession>,
        response_header: http::HeaderMap,
    ) -> hyper::Response<ResponseBody> {
        let mut response_header = response_header;
        let max_each_post_bytes = byte_size(self.sc_max_each_post_bytes.max);
        let payload = match self.read_packet_up_payload(req, extraction_req).await {
            Ok(payload) => payload,
            Err(resp) => return finish_with(resp, response_header),
        };

        if payload.len() > max_each_post_bytes {
            return finish_with(text_response(StatusCode::PAYLOAD_TOO_LARGE, "body too large"), response_header);
        }

        // A POST carrying no payload looks bodyless, and therefore cacheable, to every
        // intermediary; it is the one case answered with an explicit no-store.
        if payload.is_empty() {
            response_header.insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
        }

        let Ok(seq) = seq_str.parse::<u64>() else {
            return finish_with(text_response(StatusCode::BAD_REQUEST, "invalid xhttp seq"), response_header);
        };

        if let Err(err) = session.upload_queue.push(Packet { seq, payload, reader: None }).await {
            return finish_with(text_response(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()), response_header);
        }

        let mut resp = empty_response(StatusCode::OK);
        *resp.headers_mut() = response_header;
        resp
    }

    /// Reads the packet-up POST payload from whichever of the header, cookie and body placements
    /// the configured uplink data placement selects.
    async fn read_packet_up_payload(
        &self,
        req: hyper::Request<Incoming>,
        extraction_req: Request,
    ) -> Result<Vec<u8>, hyper::Response<ResponseBody>> {
        let data_placement = self.config.normalized_uplink_data_placement();
        let uplink_data_key = &self.config.uplink_data_key;

        let mut header_payload = Vec::new();
        if data_placement == PLACEMENT_AUTO || data_placement == PLACEMENT_HEADER {
            match read_header_payload(&req, uplink_data_key) {
                Ok(payload) => header_payload = payload,
                Err(()) => {
                    return Err(text_response(StatusCode::BAD_REQUEST, "invalid base64 in header's payload"));
                }
            }
        }

        let mut cookie_payload = Vec::new();
        if data_placement == PLACEMENT_AUTO || data_placement == PLACEMENT_COOKIE {
            match read_cookie_payload(&extraction_req, uplink_data_key) {
                Ok(payload) => cookie_payload = payload,
                Err(()) => {
                    return Err(text_response(StatusCode::BAD_REQUEST, "invalid base64 in cookies' payload"));
                }
            }
        }

        let mut body_payload = Vec::new();
        if data_placement == PLACEMENT_AUTO || data_placement == PLACEMENT_BODY {
            let content_length = req
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<i64>().ok());
            if content_length.is_some_and(|len| len > self.sc_max_each_post_bytes.max) {
                return Err(text_response(StatusCode::PAYLOAD_TOO_LARGE, "body too large"));
            }
            let limit = byte_size(self.sc_max_each_post_bytes.max).saturating_add(1);
            match Limited::new(req.into_body(), limit).collect().await {
                Ok(collected) => body_payload = collected.to_bytes().to_vec(),
                Err(_) => return Err(text_response(StatusCode::BAD_REQUEST, "failed to read body")),
            }
        }

        Ok(match data_placement.as_str() {
            PLACEMENT_HEADER => header_payload,
            PLACEMENT_COOKIE => cookie_payload,
            PLACEMENT_BODY => body_payload,
            PLACEMENT_AUTO => {
                let mut combined = header_payload;
                combined.extend(cookie_payload);
                combined.extend(body_payload);
                combined
            }
            _ => Vec::new(),
        })
    }

    /// stream-up/packet-up download: GET /path/{session}
    fn serve_session_download(
        &self,
        req: hyper::Request<Incoming>,
        session_id: &str,
        session: &HttpSession,
        response_header: http::HeaderMap,
    ) -> hyper::Response<ResponseBody> {
        let mut response_header = response_header;
        session.mark_connected();

        response_header.insert("X-Accel-Buffering", http::HeaderValue::from_static("no"));
        response_header.insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
        if !self.config.no_sse_header {
            response_header.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/event-stream"));
        }

        let net_addr = Arc::new(NetAddr::default());
        set_addr_from_request(&net_addr, &req);
        let (tx, body) = channel_body(RESPONSE_CHANNEL_CAPACITY);
        let incoming_stream = req.into_body().into_data_stream().map(|res| res.map_err(io::Error::other));
        let body_reader = Box::pin(StreamReader::new(incoming_stream));
        let http_sc = HttpServerConn::new(body_reader, tx);

        let session_id_close = session_id.to_owned();
        let this = Weak::clone(&self.self_weak);
        let conn = XConn::new(
            Box::pin(HttpServerConnWriter { conn: http_sc, pending: None }),
            Box::pin(UploadQueueHandle(Arc::clone(&session.upload_queue))),
            net_addr,
        );
        conn.set_on_close(Box::new(move || {
            if let Some(this) = this.upgrade() {
                this.delete_session(&session_id_close);
            }
        }));

        if let Some(conn_handler) = &self.conn_handler {
            let handler = Arc::clone(conn_handler);
            let net_conn: Box<dyn NetConn> =
                Box::new(StreamAsOldConn::new(murmur_common_net::sing::new_deadline_conn(conn)));
            tokio::spawn(handler(net_conn));
        }

        ok_response(body, response_header)
    }

    /// stream-one: POST /path
    fn serve_stream_one(
        &self,
        req: hyper::Request<Incoming>,
        response_header: http::HeaderMap,
    ) -> hyper::Response<ResponseBody> {
        let mut response_header = response_header;
        response_header.insert("X-Accel-Buffering", http::HeaderValue::from_static("no"));
        response_header.insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-store"));

        let net_addr = Arc::new(NetAddr::default());
        set_addr_from_request(&net_addr, &req);
        let (tx, body) = channel_body(RESPONSE_CHANNEL_CAPACITY);
        let incoming_stream = req.into_body().into_data_stream().map(|res| res.map_err(io::Error::other));
        let body_reader = Box::pin(StreamReader::new(incoming_stream));
        let http_sc = HttpServerConn::new(body_reader, tx);

        let conn = XConn::new(
            Box::pin(HttpServerConnWriter { conn: Arc::clone(&http_sc), pending: None }),
            Box::pin(HttpServerConnReader { conn: http_sc, pending: None, carry: Vec::new() }),
            net_addr,
        );

        if let Some(conn_handler) = &self.conn_handler {
            let handler = Arc::clone(conn_handler);
            let net_conn: Box<dyn NetConn> =
                Box::new(StreamAsOldConn::new(murmur_common_net::sing::new_deadline_conn(conn)));
            tokio::spawn(handler(net_conn));
        }

        ok_response(body, response_header)
    }
}

fn finish_with(
    mut resp: hyper::Response<ResponseBody>,
    extra_headers: http::HeaderMap,
) -> hyper::Response<ResponseBody> {
    resp.headers_mut().extend(extra_headers);
    resp
}

/// A `200 OK` response streaming `body`, carrying the headers the padding config produced.
fn ok_response(body: ChannelBody, headers: http::HeaderMap) -> hyper::Response<ResponseBody> {
    let mut resp = hyper::Response::new(body.boxed());
    *resp.status_mut() = StatusCode::OK;
    *resp.headers_mut() = headers;
    resp
}

/// Narrows a configured `i64` size to `usize`. `parse_range` rejects only a zero upper bound, so a
/// negative range clamps to zero here rather than wrapping into a huge allocation.
fn byte_size(value: i64) -> usize {
    usize::try_from(value.max(0)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn_handler_close() -> ConnHandler {
        Arc::new(|conn: Box<dyn NetConn>| {
            Box::pin(async move {
                let _ = conn.close();
            })
        })
    }

    async fn run_case(mode: &str, method: http::Method, path: &str, want_status: u16) {
        let config = Config { path: "/xhttp".to_owned(), mode: mode.to_owned(), ..Config::default() };
        let handler = RequestHandler::new(ServerOption {
            config: config.clone(),
            conn_handler: Some(conn_handler_close()),
            http_handler: None,
        })
        .expect("valid config");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener local addr");
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(move |req| {
                    let handler = Arc::clone(&handler);
                    async move { Ok::<_, std::convert::Infallible>(handler.serve(req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await;
            }
        });

        let mut req = Request {
            method: method.to_string(),
            url: url::Url::parse(&format!("http://example.com{path}")).expect("static URL"),
            host: "example.com".to_owned(),
            ..Request::default()
        };
        config.fill_stream_request(&mut req, "").expect("fill stream request");
        req.host = "example.com".to_owned();
        let hyper_req = super::super::client::build_hyper_request(req).expect("build hyper request");

        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect loopback");
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut send_request, connection) = hyper::client::conn::http1::handshake(io).await.expect("client handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let resp = send_request.send_request(hyper_req).await.expect("send request");
        assert_eq!(resp.status().as_u16(), want_status, "mode={mode} method={method} path={path}");
    }

    #[tokio::test]
    async fn test_server_handler_mode_restrictions() {
        run_case("stream-one", http::Method::POST, "/xhttp/", 200).await;
        run_case("stream-one", http::Method::GET, "/xhttp/session", 404).await;
        run_case("stream-up", http::Method::POST, "/xhttp/", 200).await;
        run_case("stream-up", http::Method::GET, "/xhttp/session", 200).await;
        run_case("stream-up", http::Method::POST, "/xhttp/session/0", 404).await;
        run_case("packet-up", http::Method::GET, "/xhttp/session", 200).await;
        run_case("packet-up", http::Method::POST, "/xhttp/", 404).await;
        run_case("packet-up", http::Method::POST, "/xhttp/session", 404).await;
    }

    /// Regresses the non-atomic `get`-then-`insert` race in `upsert_session` (the entry API holds
    /// the key's shard lock across both steps). Many tasks racing on the same fresh session id
    /// must all observe one session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_upsert_session_concurrent_same_id_is_atomic() {
        const RACERS: usize = 8;
        let config = Config { path: "/xhttp".to_owned(), mode: "packet-up".to_owned(), ..Config::default() };
        let handler =
            RequestHandler::new(ServerOption { config, conn_handler: None, http_handler: None }).expect("valid config");

        for trial in 0..500 {
            let session_id = format!("race-{trial}");
            let barrier = Arc::new(tokio::sync::Barrier::new(RACERS));
            let mut tasks = Vec::with_capacity(RACERS);
            for _ in 0..RACERS {
                let handler = Arc::clone(&handler);
                let barrier = Arc::clone(&barrier);
                let session_id = session_id.clone();
                tasks.push(tokio::spawn(async move {
                    barrier.wait().await;
                    handler.upsert_session(&session_id)
                }));
            }
            let mut sessions = Vec::with_capacity(RACERS);
            for task in tasks {
                sessions.push(task.await.expect("upsert_session task"));
            }
            let first = &sessions[0];
            for other in &sessions[1..] {
                assert!(
                    Arc::ptr_eq(first, other),
                    "trial {trial}: upsert_session returned distinct sessions for the same id under concurrency"
                );
            }
        }
    }

    /// Reproduces the sequence `reap_session`'s doc comment describes: S1 is deleted (its
    /// connection closed) and S2 is created under the same id before S1's stale reaper fires.
    /// An unconditional delete-by-id would remove S2, closing its upload queue and killing a live
    /// connection; the `Arc::ptr_eq` guard here must leave S2 in place.
    #[tokio::test]
    async fn test_reap_session_does_not_delete_a_replacement_session_with_the_same_id() {
        let config = Config { path: "/xhttp".to_owned(), mode: "packet-up".to_owned(), ..Config::default() };
        let handler =
            RequestHandler::new(ServerOption { config, conn_handler: None, http_handler: None }).expect("valid config");

        let session_id = "reused-id";
        let s1 = handler.upsert_session(session_id);
        handler.delete_session(session_id);
        let s2 = handler.upsert_session(session_id);
        assert!(!Arc::ptr_eq(&s1, &s2), "test setup: s2 must be a distinct session from s1");

        handler.reap_session(session_id, &s1);

        let stored = handler.session(session_id).expect("s2 must still be present after the stale reaper fires");
        assert!(Arc::ptr_eq(&stored, &s2), "the stale reaper for s1 must not delete the live replacement s2");
    }

    #[test]
    fn test_equal_host_strips_port_and_case() {
        assert!(equal_host("Example.com:443", "example.com"));
        assert!(!equal_host("example.com", "example.org"));
    }

    /// A reader whose first `poll_read` is `Pending` (after registering the waker) and whose
    /// second delivers `data` in full, so a caller of [`HttpServerConnReader::poll_read`] is
    /// forced through the pending-then-retry path with a smaller retry buffer than the one that
    /// started the read.
    struct FlakyBodyReader {
        pending_once: bool,
        data: Vec<u8>,
    }

    impl AsyncRead for FlakyBodyReader {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.pending_once {
                this.pending_once = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = this.data.len().min(buf.remaining());
            buf.put_slice(&this.data[..n]);
            this.data.drain(..n);
            Poll::Ready(Ok(()))
        }
    }

    /// A direct read can never return more than `len(b)` because it reads into the caller's slice;
    /// this instead reads into an internally sized buffer while a
    /// poll is pending, so a retry with a smaller `buf` than the one that started the read must
    /// not overflow that `buf` or lose bytes.
    #[test]
    fn poll_read_does_not_overflow_a_smaller_retry_buffer() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let inner = FlakyBodyReader { pending_once: true, data: vec![0x42u8; 463] };
        let conn = HttpServerConn::new(Box::pin(inner), tx);
        let mut reader = HttpServerConnReader { conn, pending: None, carry: Vec::new() };

        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut big = vec![0u8; 463];
        let mut big_buf = ReadBuf::new(&mut big);
        let first = Pin::new(&mut reader).poll_read(&mut cx, &mut big_buf);
        assert!(matches!(first, Poll::Pending));

        let mut small = [0u8; 5];
        let mut small_buf = ReadBuf::new(&mut small);
        let second = Pin::new(&mut reader).poll_read(&mut cx, &mut small_buf);
        assert!(matches!(second, Poll::Ready(Ok(()))));
        assert_eq!(small_buf.filled(), &[0x42u8; 5]);

        let mut rest = vec![0u8; 458];
        let mut rest_buf = ReadBuf::new(&mut rest);
        let third = Pin::new(&mut reader).poll_read(&mut cx, &mut rest_buf);
        assert!(matches!(third, Poll::Ready(Ok(()))));
        assert_eq!(rest_buf.filled().len(), 458, "no bytes may be dropped across the shrinking retry");
        assert!(rest_buf.filled().iter().all(|&b| b == 0x42), "carried-over bytes must reach the caller intact");
    }
}

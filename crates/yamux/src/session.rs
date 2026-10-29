use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot, Notify, Semaphore};
use tokio::task::JoinHandle;

use crate::config::{verify_config, Config};
use crate::error::{
    err_connection_write_timeout, err_duplicate_stream, err_keepalive_timeout, err_session_shutdown,
    err_streams_exhausted, err_timeout, go_away_error, ErrInfo,
};
use crate::frame::{
    Header, FLAG_ACK, FLAG_RST, FLAG_SYN, HEADER_SIZE, TYPE_DATA, TYPE_GO_AWAY, TYPE_PING, TYPE_WINDOW_UPDATE,
};
use crate::stream::{Stream, StreamShared};

#[derive(Clone, Debug)]
enum ShutdownReason {
    Normal,
    GoAway { code: u32, remote: bool },
    Err(ErrInfo),
}

impl ShutdownReason {
    fn to_io(&self) -> std::io::Error {
        match self {
            Self::Normal => err_session_shutdown(),
            Self::GoAway { code, remote } => go_away_error(*code, *remote),
            Self::Err(info) => info.to_io(),
        }
    }
}

#[derive(Debug)]
pub struct SessionCore {
    is_client: bool,
    pub config: Config,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    streams: Mutex<HashMap<u32, Arc<StreamShared>>>,
    next_stream_id: AtomicU32,
    num_incoming_streams: AtomicU32,
    open_semaphore: Arc<Semaphore>,
    accept_tx: mpsc::Sender<Arc<StreamShared>>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<Arc<StreamShared>>>,
    active_ping: Mutex<Option<(u32, oneshot::Sender<()>)>>,
    next_ping_id: AtomicU32,
    closed: AtomicBool,
    shutdown_reason: Mutex<Option<ShutdownReason>>,
    shutdown_notify: Notify,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl SessionCore {
    fn current_err(&self) -> std::io::Error {
        self.shutdown_reason.lock().as_ref().map_or_else(err_session_shutdown, ShutdownReason::to_io)
    }

    /// Resolves once the session is shut down. `notify_waiters` is edge-triggered, so a waiter
    /// that parks after a shutdown would otherwise wait forever; registering the waiter before
    /// re-reading `closed` closes that window, and `Notify::notify_one` additionally leaves a
    /// stored permit for anyone who has not registered yet.
    // cancel-safe: waits on a level-triggered notification and re-checks the state before parking, so a dropped wait misses nothing -- the next call re-reads the same state.
    async fn shutdown_signal(&self) {
        let notified = self.shutdown_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }

    pub fn send_frame(&self, frame: Vec<u8>) -> std::io::Result<()> {
        self.out_tx.send(frame).map_err(|_| self.current_err())
    }

    /// Closes a stream, releasing the bookkeeping this crate tracks via [`StreamShared`]'s own
    /// `open_permit`.
    pub fn close_stream(&self, id: u32) {
        let removed = self.streams.lock().remove(&id).is_some();
        if removed && self.is_client == id.is_multiple_of(2) {
            // A map entry proves the matching `fetch_add` in `incoming_stream` already ran, so the
            // count is at least 1 and a plain `fetch_sub` cannot wrap.
            self.num_incoming_streams.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn trigger_shutdown(&self, reason: ShutdownReason) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        *self.shutdown_reason.lock() = Some(reason);
        self.shutdown_notify.notify_waiters();
        self.shutdown_notify.notify_one();
        let err = self.current_err();
        let drained: Vec<_> = self.streams.lock().drain().map(|(_, v)| v).collect();
        for s in drained {
            s.force_close(&err);
        }
    }

    fn incoming_stream(self: &Arc<Self>, id: u32) -> std::io::Result<()> {
        if self.is_client != id.is_multiple_of(2) {
            return Err(std::io::Error::other("both yamux endpoints are clients"));
        }

        let mut streams = self.streams.lock();
        if streams.contains_key(&id) {
            drop(streams);
            let _ = self.send_frame(Header::encode(TYPE_GO_AWAY, 0, 0, crate::frame::GO_AWAY_PROTO_ERR).to_vec());
            return Err(err_duplicate_stream());
        }
        if self.num_incoming_streams.load(Ordering::Acquire) >= self.config.max_incoming_streams {
            drop(streams);
            let hdr = Header::encode(TYPE_WINDOW_UPDATE, FLAG_RST, id, 0);
            return self.send_frame(hdr.to_vec());
        }

        let shared = StreamShared::new_incoming(id, Arc::clone(self));
        streams.insert(id, Arc::clone(&shared));
        self.num_incoming_streams.fetch_add(1, Ordering::AcqRel);
        drop(streams);

        if self.accept_tx.try_send(shared).is_err() {
            self.close_stream(id);
            let hdr = Header::encode(TYPE_WINDOW_UPDATE, FLAG_RST, id, 0);
            return self.send_frame(hdr.to_vec());
        }
        Ok(())
    }

    fn handle_ping(&self, hdr: &Header) {
        let ping_id = hdr.length;
        if hdr.flags & FLAG_SYN != 0 {
            let pong = Header::encode(TYPE_PING, FLAG_ACK, 0, ping_id);
            let _ = self.send_frame(pong.to_vec());
            return;
        }
        let mut active = self.active_ping.lock();
        if active.as_ref().is_some_and(|(id, _)| *id == ping_id) {
            if let Some((_, tx)) = active.take() {
                let _ = tx.send(());
            }
        }
    }
}

#[derive(Debug)]
pub struct Session {
    core: Arc<SessionCore>,
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self { core: Arc::clone(&self.core) }
    }
}

impl Session {
    pub async fn open_stream(&self) -> std::io::Result<Stream> {
        let core = &self.core;
        if core.closed.load(Ordering::Acquire) {
            return Err(core.current_err());
        }
        let permit = tokio::select! {
            biased;
            () = core.shutdown_signal() => return Err(core.current_err()),
            res = Arc::clone(&core.open_semaphore).acquire_owned() => res.map_err(|_| core.current_err())?,
        };

        let id = core.next_stream_id.fetch_add(2, Ordering::AcqRel);
        if id >= u32::MAX - 1 {
            return Err(err_streams_exhausted());
        }

        let shared = StreamShared::new_outgoing(id, Arc::clone(core), permit);
        core.streams.lock().insert(id, Arc::clone(&shared));
        if let Err(e) = shared.send_window_update() {
            core.streams.lock().remove(&id);
            return Err(e);
        }
        Ok(Stream::new(shared))
    }

    pub async fn accept_stream(&self) -> std::io::Result<Stream> {
        let core = &self.core;
        loop {
            let item = {
                let mut rx = core.accept_rx.lock().await;
                tokio::select! {
                    biased;
                    () = core.shutdown_signal() => return Err(core.current_err()),
                    item = rx.recv() => item,
                }
            };
            let Some(shared) = item else {
                return Err(core.current_err());
            };
            if shared.send_window_update().is_err() {
                continue;
            }
            return Ok(Stream::new(shared));
        }
    }

    #[must_use]
    pub fn num_streams(&self) -> usize {
        self.core.streams.lock().len()
    }

    pub async fn close(&self) -> std::io::Result<()> {
        self.core.trigger_shutdown(ShutdownReason::Normal);
        let handles = std::mem::take(&mut *self.core.tasks.lock());
        for h in handles {
            let _ = h.await;
        }
        Ok(())
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.core.closed.load(Ordering::Acquire)
    }
}

pub async fn client<S>(conn: S, config: Config) -> std::io::Result<Session>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    new_session(conn, config, true).await
}

pub async fn server<S>(conn: S, config: Config) -> std::io::Result<Session>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    new_session(conn, config, false).await
}

#[allow(
    clippy::unused_async,
    reason = "no await point to insert: the send/recv/keepalive loops are spawned, and \
              client/server keep the async shape their callers already await on"
)]
async fn new_session<S>(conn: S, config: Config, is_client: bool) -> std::io::Result<Session>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    verify_config(&config)?;

    let (read_half, write_half) = tokio::io::split(conn);
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (accept_tx, accept_rx) = mpsc::channel(config.accept_backlog);

    let core = Arc::new(SessionCore {
        is_client,
        next_stream_id: AtomicU32::new(if is_client { 1 } else { 2 }),
        open_semaphore: Arc::new(Semaphore::new(config.accept_backlog)),
        accept_tx,
        accept_rx: tokio::sync::Mutex::new(accept_rx),
        out_tx,
        config,
        streams: Mutex::new(HashMap::new()),
        num_incoming_streams: AtomicU32::new(0),
        active_ping: Mutex::new(None),
        next_ping_id: AtomicU32::new(0),
        closed: AtomicBool::new(false),
        shutdown_reason: Mutex::new(None),
        shutdown_notify: Notify::new(),
        tasks: Mutex::new(Vec::new()),
    });

    let recv_core = Arc::clone(&core);
    let recv_handle = tokio::spawn(recv_loop(recv_core, read_half));
    let send_core = Arc::clone(&core);
    let send_handle = tokio::spawn(send_loop(send_core, write_half, out_rx));
    let mut handles = vec![recv_handle, send_handle];
    if core.config.enable_keepalive {
        let ka_core = Arc::clone(&core);
        handles.push(tokio::spawn(keepalive_loop(ka_core)));
    }
    *core.tasks.lock() = handles;

    Ok(Session { core })
}

/// The receive loop.
async fn recv_loop<S>(core: Arc<SessionCore>, mut read_half: ReadHalf<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let reason = recv_body(&core, &mut read_half).await;
    core.trigger_shutdown(reason);
}

async fn recv_body<S>(core: &Arc<SessionCore>, read_half: &mut ReadHalf<S>) -> ShutdownReason
where
    S: tokio::io::AsyncRead + Send + Unpin,
{
    let mut hdr_buf = [0u8; HEADER_SIZE];
    loop {
        let read_res = tokio::select! {
            biased;
            () = core.shutdown_signal() => return ShutdownReason::Normal,
            res = read_half.read_exact(&mut hdr_buf) => res,
        };
        if let Err(e) = read_res {
            return ShutdownReason::Err(ErrInfo::from_io(&e));
        }
        let hdr = match Header::decode(&hdr_buf) {
            Ok(h) => h,
            Err(e) => return ShutdownReason::Err(ErrInfo::from_io(&e)),
        };
        match hdr.msg_type {
            TYPE_DATA | TYPE_WINDOW_UPDATE => {
                if let Err(e) = handle_stream_message(core, hdr, read_half).await {
                    return ShutdownReason::Err(ErrInfo::from_io(&e));
                }
            }
            TYPE_PING => core.handle_ping(&hdr),
            TYPE_GO_AWAY => return ShutdownReason::GoAway { code: hdr.length, remote: true },
            // `Header::decode` rejects any `msg_type` above `TYPE_GO_AWAY`, so this arm is
            // unreachable in practice; surfacing the decoder's own error keeps the recv loop
            // from panicking a worker thread if that invariant ever breaks.
            _ => {
                let err = crate::error::err_invalid_msg_type();
                return ShutdownReason::Err(ErrInfo::from_io(&err));
            }
        }
    }
}

async fn handle_stream_message<S>(
    core: &Arc<SessionCore>,
    hdr: Header,
    read_half: &mut ReadHalf<S>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + Send + Unpin,
{
    let id = hdr.stream_id;
    let flags = hdr.flags;
    if flags & FLAG_SYN != 0 {
        core.incoming_stream(id)?;
    }

    let Some(stream) = ({
        let streams = core.streams.lock();
        streams.get(&id).cloned()
    }) else {
        if hdr.msg_type == TYPE_DATA && hdr.length > 0 {
            let mut remaining = usize::try_from(hdr.length).unwrap_or(usize::MAX);
            let mut scratch = [0u8; 4096];
            while remaining > 0 {
                let want = remaining.min(scratch.len());
                let (chunk, _) = scratch.split_at_mut(want);
                read_half.read_exact(chunk).await?;
                remaining -= want;
            }
        }
        return Ok(());
    };

    if hdr.msg_type == TYPE_WINDOW_UPDATE {
        stream.incr_send_window(&hdr, flags);
        return Ok(());
    }

    if let Err(e) = stream.begin_data(&hdr, flags, hdr.length) {
        let _ = core.send_frame(Header::encode(TYPE_GO_AWAY, 0, 0, crate::frame::GO_AWAY_PROTO_ERR).to_vec());
        return Err(e);
    }
    if hdr.length == 0 {
        return Ok(());
    }
    let mut data = BytesMut::zeroed(usize::try_from(hdr.length).unwrap_or(usize::MAX));
    read_half.read_exact(&mut data).await?;
    stream.commit_data(data.freeze());
    drop(stream);
    Ok(())
}

/// The send loop.
async fn send_loop<S>(
    core: Arc<SessionCore>,
    mut write_half: WriteHalf<S>,
    mut out_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let reason: ShutdownReason = loop {
        let frame = tokio::select! {
            biased;
            () = core.shutdown_signal() => break ShutdownReason::Normal,
            frame = out_rx.recv() => frame,
        };
        let Some(frame) = frame else {
            break ShutdownReason::Normal;
        };
        match tokio::time::timeout(core.config.connection_write_timeout, write_half.write_all(&frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => break ShutdownReason::Err(ErrInfo::from_io(&e)),
            Err(_elapsed) => break ShutdownReason::Err(ErrInfo::from_io(&err_connection_write_timeout())),
        }
    };
    core.trigger_shutdown(reason);
}

/// The keepalive loop, collapsed into one since this crate has no
/// standalone RTT-measurement consumer (see `stream.rs`'s note on the omitted adaptive window
/// growth) or public ping API to multiplex against.
async fn keepalive_loop(core: Arc<SessionCore>) {
    loop {
        tokio::select! {
            biased;
            () = core.shutdown_signal() => return,
            () = tokio::time::sleep(core.config.keep_alive_interval) => {}
        }
        if core.closed.load(Ordering::Acquire) {
            return;
        }
        if do_ping(&core, core.config.connection_write_timeout).await.is_err() {
            core.trigger_shutdown(ShutdownReason::Err(ErrInfo::from_io(&err_keepalive_timeout())));
            return;
        }
    }
}

async fn do_ping(core: &Arc<SessionCore>, timeout: Duration) -> std::io::Result<()> {
    let id = core.next_ping_id.fetch_add(1, Ordering::AcqRel);
    let (tx, rx) = oneshot::channel();
    *core.active_ping.lock() = Some((id, tx));
    let hdr = Header::encode(TYPE_PING, FLAG_SYN, 0, id);
    core.send_frame(hdr.to_vec())?;
    tokio::select! {
        biased;
        () = core.shutdown_signal() => Err(core.current_err()),
        res = rx => res.map_err(|_| core.current_err()),
        () = tokio::time::sleep(timeout) => Err(err_timeout()),
    }
}

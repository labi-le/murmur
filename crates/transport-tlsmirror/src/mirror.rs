use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use murmur_common_net::deadline::pipe::CloseSignal;
use murmur_std_compat::net::{Addr, Conn as NetConn};

use super::config::Config;
use super::crypto::ExplicitNonceGenerator;
use super::record::{
    duplicate_record, has_zero_explicit_nonce, parse_client_random, parse_server_hello, read_record, write_record,
    Record, MAX_TLS_RECORD_PAYLOAD, RECORD_TYPE_ALERT, RECORD_TYPE_APPLICATION_DATA, RECORD_TYPE_CHANGE_CIPHER_SPEC,
    RECORD_TYPE_HANDSHAKE,
};

#[async_trait]
pub(crate) trait MessageHook: Send + Sync {
    async fn call(&self, rec: &mut Record) -> Result<bool>;
}

/// Adapts a boxed async closure to [`MessageHook`], for the inline hooks built around the
/// not-yet-constructed `*Conn` (the forward-declared `var hidden *Conn`).
pub(crate) struct FnHook<F>(pub F);

#[async_trait]
impl<F> MessageHook for FnHook<F>
where
    F: for<'r> Fn(&'r mut Record) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'r>> + Send + Sync,
{
    async fn call(&self, rec: &mut Record) -> Result<bool> {
        (self.0)(rec).await
    }
}

/// Coerces a closure literal into the higher-ranked `Fn` bound [`FnHook`] requires: an explicit
/// per-call return-type annotation on the closure itself does not establish the `for<'r>` bound,
/// so callers infer it through this identity function instead.
pub(crate) const fn hrtb_hook<F>(f: F) -> F
where
    F: for<'r> Fn(&'r mut Record) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'r>> + Send + Sync,
{
    f
}

/// A shared `NetConn`, so it can be closed from a task that does not own the read/write half.
#[derive(Clone)]
pub(crate) struct SharedConn(Arc<Mutex<Box<dyn NetConn>>>);

impl SharedConn {
    pub(crate) fn new(conn: Box<dyn NetConn>) -> Self {
        Self(Arc::new(Mutex::new(conn)))
    }

    pub(crate) fn close(&self) {
        let _ = self.0.lock().close();
    }
}

impl AsyncRead for SharedConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().0.lock();
        Pin::new(&mut **conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for SharedConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut conn = self.get_mut().0.lock();
        Pin::new(&mut **conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().0.lock();
        Pin::new(&mut **conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().0.lock();
        Pin::new(&mut **conn).poll_shutdown(cx)
    }
}

impl NetConn for SharedConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.lock().local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.lock().remote_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.0.lock().close()
    }
}

/// A reader that first drains `prefix` (the captured records' remaining bytes), then reads from
/// `inner`.
pub(crate) struct PrefixedReader {
    prefix: Vec<u8>,
    pos: usize,
    inner: SharedConn,
}

impl PrefixedReader {
    const fn new(prefix: Vec<u8>, inner: SharedConn) -> Self {
        Self { prefix, pos: 0, inner }
    }
}

impl AsyncRead for PrefixedReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            // `pos` and `n` are both bounded above, so the splits cannot panic.
            let (_, pending) = this.prefix.split_at(this.pos);
            let n = buf.remaining().min(pending.len());
            let (chunk, _) = pending.split_at(n);
            buf.put_slice(chunk);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

/// The buffered reader over the captured-record fallback chain.
pub(crate) type FallbackReader = BufReader<PrefixedReader>;

/// A write task, extended with `ack`: a oneshot the sender can use to learn when this task —
/// and every task queued ahead of it — has actually been written and flushed to the wire, since
/// `WriteTask::rec`/`raw` reaching the channel only means the write is queued, not delivered.
pub(crate) struct WriteTask {
    pub(crate) rec: Option<Record>,
    pub(crate) raw: Vec<u8>,
    pub(crate) fallback: Option<FallbackReader>,
    pub(crate) ack: Option<tokio::sync::oneshot::Sender<()>>,
}

#[derive(Default)]
struct HandshakeRandom {
    client_random: [u8; 32],
    server_random: [u8; 32],
    client_random_ready: bool,
    server_random_ready: bool,
    tls12_explicit: bool,
}

pub(crate) struct MirrorConn {
    ctx: CancellationToken,

    pub(crate) client_conn: SharedConn,
    pub(crate) server_conn: SharedConn,

    on_c2s_message: Option<Arc<dyn MessageHook>>,
    on_s2c_message: Option<Arc<dyn MessageHook>>,
    pub(crate) on_c2s_message_tx: Mutex<Option<Arc<dyn MessageHook>>>,
    pub(crate) on_s2c_message_tx: Mutex<Option<Arc<dyn MessageHook>>>,

    c2s_insert_tx: mpsc::Sender<WriteTask>,
    c2s_insert_rx: Mutex<Option<mpsc::Receiver<WriteTask>>>,
    s2c_insert_tx: mpsc::Sender<WriteTask>,
    s2c_insert_rx: Mutex<Option<mpsc::Receiver<WriteTask>>>,
    pub(crate) c2s_ready: CloseSignal,
    pub(crate) s2c_ready: CloseSignal,
    pub(crate) on_close: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,

    random: RwLock<HandshakeRandom>,
    explicit_ready: CloseSignal,
    explicit_suites: HashSet<u16>,
    c2s_explicit_nonce: Mutex<ExplicitNonceGenerator>,
    s2c_explicit_nonce: Mutex<ExplicitNonceGenerator>,
}

pub(crate) fn new_mirror_conn(
    parent_ctx: &CancellationToken,
    client_conn: SharedConn,
    server_conn: SharedConn,
    cfg: &Config,
    on_c2s_message: Option<Arc<dyn MessageHook>>,
    on_s2c_message: Option<Arc<dyn MessageHook>>,
    on_c2s_message_tx: Option<Arc<dyn MessageHook>>,
    on_s2c_message_tx: Option<Arc<dyn MessageHook>>,
) -> Arc<MirrorConn> {
    let explicit_suites: HashSet<u16> = cfg.explicit_nonce_cipher_suites.iter().copied().collect();
    let (c2s_tx, c2s_rx) = mpsc::channel(100);
    let (s2c_tx, s2c_rx) = mpsc::channel(100);
    Arc::new(MirrorConn {
        ctx: parent_ctx.child_token(),
        client_conn,
        server_conn,
        on_c2s_message,
        on_s2c_message,
        on_c2s_message_tx: Mutex::new(on_c2s_message_tx),
        on_s2c_message_tx: Mutex::new(on_s2c_message_tx),
        c2s_insert_tx: c2s_tx,
        c2s_insert_rx: Mutex::new(Some(c2s_rx)),
        s2c_insert_tx: s2c_tx,
        s2c_insert_rx: Mutex::new(Some(s2c_rx)),
        c2s_ready: CloseSignal::default(),
        s2c_ready: CloseSignal::default(),
        on_close: Mutex::new(None),
        random: RwLock::new(HandshakeRandom::default()),
        explicit_ready: CloseSignal::default(),
        explicit_suites,
        c2s_explicit_nonce: Mutex::new(ExplicitNonceGenerator::default()),
        s2c_explicit_nonce: Mutex::new(ExplicitNonceGenerator::default()),
    })
}

fn context_canceled_error() -> anyhow::Error {
    anyhow!("context canceled")
}

impl MirrorConn {
    /// `c.mirror.ctx`.
    pub(crate) const fn ctx(&self) -> &CancellationToken {
        &self.ctx
    }

    /// The client-to-server insert queue, reached from the conn's insert path.
    pub(crate) fn c2s_insert_tx(&self) -> mpsc::Sender<WriteTask> {
        self.c2s_insert_tx.clone()
    }

    /// The server-to-client insert queue, reached from the conn's insert path.
    pub(crate) fn s2c_insert_tx(&self) -> mpsc::Sender<WriteTask> {
        self.s2c_insert_tx.clone()
    }

    /// `mirror.onClose = ...` field assignment after construction.
    pub(crate) fn set_on_close(&self, f: Arc<dyn Fn() + Send + Sync>) {
        *self.on_close.lock() = Some(f);
    }

    /// `mirror.onC2SMessageTx = ...` field assignment after construction.
    pub(crate) fn set_on_c2s_message_tx(&self, hook: Arc<dyn MessageHook>) {
        *self.on_c2s_message_tx.lock() = Some(hook);
    }

    /// `mirror.onS2CMessageTx = ...` field assignment after construction.
    pub(crate) fn set_on_s2c_message_tx(&self, hook: Arc<dyn MessageHook>) {
        *self.on_s2c_message_tx.lock() = Some(hook);
    }

    pub(crate) fn start(self: &Arc<Self>) {
        let c2s = Arc::clone(self);
        tokio::spawn(async move { c2s.c2s_worker().await });
        let s2c = Arc::clone(self);
        tokio::spawn(async move { s2c.s2c_worker().await });
        let closer = Arc::clone(self);
        tokio::spawn(async move {
            closer.ctx.cancelled().await;
            let on_close = closer.on_close.lock().clone();
            if let Some(on_close) = on_close {
                (*on_close)();
            }
            closer.client_conn.close();
            closer.server_conn.close();
        });
    }

    #[expect(clippy::unnecessary_wraps, reason = "kept `Result`-returning to match the NetConn-style close contract")]
    pub(crate) fn close(&self) -> Result<()> {
        self.ctx.cancel();
        Ok(())
    }

    pub(crate) fn handshake_random(&self) -> Result<([u8; 32], [u8; 32])> {
        let random = self.random.read();
        if !random.client_random_ready || !random.server_random_ready {
            return Err(anyhow!("tlsmirror: handshake random is not ready"));
        }
        Ok((random.client_random, random.server_random))
    }

    // cancel-safe: it only waits for the mirror's own readiness signal.
    pub(crate) async fn explicit_nonce_overhead(&self) -> usize {
        tokio::select! {
            () = self.explicit_ready.wait() => {}
            () = self.ctx.cancelled() => return 0,
        }
        if self.random.read().tls12_explicit {
            8
        } else {
            0
        }
    }

    // cancel-safe: it only waits for a readiness signal that stays set for later callers.
    pub(crate) async fn wait_c2s_ready(&self, ctx: &CancellationToken) -> Result<()> {
        tokio::select! {
            () = self.c2s_ready.wait() => Ok(()),
            () = self.ctx.cancelled() => Err(context_canceled_error()),
            () = ctx.cancelled() => Err(context_canceled_error()),
        }
    }

    // cancel-safe: as `wait_c2s_ready`.
    pub(crate) async fn wait_s2c_ready(&self, ctx: &CancellationToken) -> Result<()> {
        tokio::select! {
            () = self.s2c_ready.wait() => Ok(()),
            () = self.ctx.cancelled() => Err(context_canceled_error()),
            () = ctx.cancelled() => Err(context_canceled_error()),
        }
    }

    // cancel-safe: an `mpsc` send is atomic, so the task is either queued whole or not at all.
    pub(crate) async fn insert_c2s(&self, rec: &Record) -> Result<()> {
        let task = WriteTask { rec: Some(duplicate_record(rec)), raw: Vec::new(), fallback: None, ack: None };
        tokio::select! {
            () = self.ctx.cancelled() => Err(context_canceled_error()),
            result = self.c2s_insert_tx.send(task) => result.map_err(|_| anyhow!("tlsmirror: mirror is closed")),
        }
    }

    // cancel-safe: as `insert_c2s`.
    pub(crate) async fn insert_s2c(&self, rec: &Record) -> Result<()> {
        let task = WriteTask { rec: Some(duplicate_record(rec)), raw: Vec::new(), fallback: None, ack: None };
        tokio::select! {
            () = self.ctx.cancelled() => Err(context_canceled_error()),
            result = self.s2c_insert_tx.send(task) => result.map_err(|_| anyhow!("tlsmirror: mirror is closed")),
        }
    }

    async fn c2s_worker(self: Arc<Self>) {
        let mut server_writer = BufWriter::with_capacity(65536, self.server_conn.clone());

        let Ok((first, mut client_reader, first_raw)) =
            self.capture_first_handshake_record(self.client_conn.clone(), &mut server_writer).await
        else {
            return;
        };
        let Ok(client_random) = parse_client_random(&first.fragment) else {
            self.fallback_direct_copy(&mut server_writer, &mut client_reader, &first_raw).await;
            return;
        };
        {
            let mut random = self.random.write();
            random.client_random = client_random;
            random.client_random_ready = true;
        }
        if write_raw_flush(&mut server_writer, &first_raw).await.is_err() {
            self.ctx.cancel();
            return;
        }

        let hook = self.on_c2s_message_tx.lock().clone();
        #[expect(clippy::expect_used, reason = "the c2s worker takes this receiver exactly once")]
        let rx = self.c2s_insert_rx.lock().take().expect("the c2s receiver is taken exactly once");
        let writer_mirror = Arc::clone(&self);
        tokio::spawn(async move { writer_mirror.record_writer(server_writer, rx, hook, true).await });

        let mut explicit_pending = false;
        while !self.ctx.is_cancelled() {
            let (rec, raw, result) = read_record(&mut client_reader).await;
            let Some(mut rec) = rec else {
                let _ = result;
                self.fallback_queued_copy(&self.c2s_insert_tx, client_reader, None, raw).await;
                return;
            };
            if rec.record_type == RECORD_TYPE_HANDSHAKE && explicit_pending && !has_zero_explicit_nonce(&rec.fragment) {
                self.fallback_queued_copy(&self.c2s_insert_tx, client_reader, Some(rec), Vec::new()).await;
                return;
            }
            if rec.record_type == RECORD_TYPE_CHANGE_CIPHER_SPEC && !self.explicit_ready.is_closed() {
                self.fallback_queued_copy(&self.c2s_insert_tx, client_reader, Some(rec), Vec::new()).await;
                return;
            }
            if let Some(hook) = &self.on_c2s_message {
                match hook.call(&mut rec).await {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(_) => {
                        self.fallback_queued_copy(&self.c2s_insert_tx, client_reader, Some(rec), Vec::new()).await;
                        return;
                    }
                }
            }
            if self.insert_c2s(&rec).await.is_err() {
                self.ctx.cancel();
                return;
            }
            if rec.record_type == RECORD_TYPE_CHANGE_CIPHER_SPEC && self.random.read().tls12_explicit {
                explicit_pending = true;
                continue;
            }
            if rec.record_type == RECORD_TYPE_APPLICATION_DATA
                || (rec.record_type == RECORD_TYPE_HANDSHAKE && explicit_pending)
            {
                self.c2s_ready.close();
            }
            explicit_pending = false;
        }
    }

    async fn s2c_worker(self: Arc<Self>) {
        let mut client_writer = BufWriter::with_capacity(65536, self.client_conn.clone());

        let Ok((mut first, mut server_reader, first_raw)) =
            self.capture_first_handshake_record(self.server_conn.clone(), &mut client_writer).await
        else {
            return;
        };
        let Ok((server_random, cipher_suite)) = parse_server_hello(&first.fragment) else {
            self.fallback_direct_copy(&mut client_writer, &mut server_reader, &first_raw).await;
            return;
        };
        {
            let mut random = self.random.write();
            random.server_random = server_random;
            random.server_random_ready = true;
            random.tls12_explicit = self.explicit_suites.contains(&cipher_suite);
        }
        self.explicit_ready.close();
        if let Some(hook) = &self.on_s2c_message {
            if hook.call(&mut first).await.is_err() {
                self.fallback_direct_copy(&mut client_writer, &mut server_reader, &first_raw).await;
                return;
            }
        }
        if write_raw_flush(&mut client_writer, &first_raw).await.is_err() {
            self.ctx.cancel();
            return;
        }

        let hook = self.on_s2c_message_tx.lock().clone();
        #[expect(clippy::expect_used, reason = "the s2c worker takes this receiver exactly once")]
        let rx = self.s2c_insert_rx.lock().take().expect("the s2c receiver is taken exactly once");
        let writer_mirror = Arc::clone(&self);
        tokio::spawn(async move { writer_mirror.record_writer(client_writer, rx, hook, false).await });

        let mut explicit_pending = false;
        while !self.ctx.is_cancelled() {
            let (rec, raw, result) = read_record(&mut server_reader).await;
            let Some(mut rec) = rec else {
                let _ = result;
                self.fallback_queued_copy(&self.s2c_insert_tx, server_reader, None, raw).await;
                return;
            };
            if rec.record_type == RECORD_TYPE_HANDSHAKE && explicit_pending && !has_zero_explicit_nonce(&rec.fragment) {
                self.fallback_queued_copy(&self.s2c_insert_tx, server_reader, Some(rec), Vec::new()).await;
                return;
            }
            if let Some(hook) = &self.on_s2c_message {
                match hook.call(&mut rec).await {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(_) => {
                        self.fallback_queued_copy(&self.s2c_insert_tx, server_reader, Some(rec), Vec::new()).await;
                        return;
                    }
                }
            }
            if self.insert_s2c(&rec).await.is_err() {
                self.ctx.cancel();
                return;
            }
            if rec.record_type == RECORD_TYPE_CHANGE_CIPHER_SPEC && self.random.read().tls12_explicit {
                explicit_pending = true;
                continue;
            }
            if rec.record_type == RECORD_TYPE_APPLICATION_DATA
                || (rec.record_type == RECORD_TYPE_HANDSHAKE && explicit_pending)
            {
                self.s2c_ready.close();
            }
            explicit_pending = false;
        }
    }

    async fn fallback_direct_copy(&self, writer: &mut BufWriter<SharedConn>, src: &mut FallbackReader, raw: &[u8]) {
        if write_raw_flush(writer, raw).await.is_err() {
            self.ctx.cancel();
            return;
        }
        let _ = copy_flush(writer, src).await;
        self.ctx.cancel();
    }

    async fn capture_first_handshake_record(
        &self,
        src: SharedConn,
        dst: &mut BufWriter<SharedConn>,
    ) -> Result<(Record, FallbackReader, Vec<u8>)> {
        let mut read_buffer = vec![0u8; 65536];
        let mut copied = 0usize;
        let mut src_reader = src.clone();
        loop {
            if self.ctx.is_cancelled() {
                return Err(context_canceled_error());
            }
            let read = {
                let (_, spare) = read_buffer.split_at_mut(copied);
                src_reader.read(spare).await
            };
            let n = match read {
                Ok(0) => {
                    self.ctx.cancel();
                    return Err(anyhow!("EOF"));
                }
                Ok(n) => n,
                Err(err) => {
                    self.ctx.cancel();
                    return Err(err.into());
                }
            };
            let buffer_end = copied + n;
            let (captured, _) = read_buffer.split_at(buffer_end);
            match peek_first_handshake_record(captured) {
                Ok(PeekOutcome::NeedMore) => {
                    let (_, fresh) = captured.split_at(copied);
                    if dst.write_all(fresh).await.is_err() {
                        self.ctx.cancel();
                        return Err(anyhow!("tlsmirror: failed to forward captured bytes"));
                    }
                    if dst.flush().await.is_err() {
                        self.ctx.cancel();
                        return Err(anyhow!("tlsmirror: failed to flush captured bytes"));
                    }
                    copied = buffer_end;
                }
                Ok(PeekOutcome::Ready(rec, processed)) => {
                    let (_, tail) = captured.split_at(copied);
                    let (raw, rest) = tail.split_at(processed - copied);
                    let raw = raw.to_vec();
                    let rest = rest.to_vec();
                    let fallback = BufReader::with_capacity(65536, PrefixedReader::new(rest, src));
                    return Ok((rec, fallback, raw));
                }
                Err(err) => {
                    let _ = dst.write_all(captured).await;
                    let _ = dst.flush().await;
                    let _ = copy_flush(dst, &mut src_reader).await;
                    self.ctx.cancel();
                    return Err(err);
                }
            }
        }
    }

    // cancel-safe: an `mpsc` send is atomic, so the fallback task is either queued whole or dropped.
    async fn fallback_queued_copy(
        &self,
        tx: &mpsc::Sender<WriteTask>,
        src: FallbackReader,
        first: Option<Record>,
        raw: Vec<u8>,
    ) {
        let rec = first.as_ref().map(duplicate_record);
        let task = WriteTask { rec, raw, fallback: Some(src), ack: None };
        tokio::select! {
            () = self.ctx.cancelled() => {}
            _ = tx.send(task) => {}
        }
    }

    // NOT cancel-safe: a drop between taking a task off the queue and finishing its record leaves
    // the carrier stream cut mid-record.
    async fn record_writer(
        self: Arc<Self>,
        mut writer: BufWriter<SharedConn>,
        mut rx: mpsc::Receiver<WriteTask>,
        hook: Option<Arc<dyn MessageHook>>,
        c2s: bool,
    ) {
        loop {
            let task = tokio::select! {
                () = self.ctx.cancelled() => return,
                task = rx.recv() => task,
            };
            let Some(mut task) = task else { return };
            if let Some(mut rec) = task.rec.take() {
                self.fill_explicit_nonce(&mut rec, c2s);
                if let Some(hook) = &hook {
                    match hook.call(&mut rec).await {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(_) => {
                            self.ctx.cancel();
                            return;
                        }
                    }
                }
                if write_record(&mut writer, &rec).await.is_err() {
                    self.ctx.cancel();
                    return;
                }
                if rec.record_type == RECORD_TYPE_ALERT {
                    self.ctx.cancel();
                    return;
                }
            }
            if !task.raw.is_empty() {
                if writer.write_all(&task.raw).await.is_err() {
                    self.ctx.cancel();
                    return;
                }
                if writer.flush().await.is_err() {
                    self.ctx.cancel();
                    return;
                }
            }
            if let Some(mut fallback) = task.fallback.take() {
                let _ = copy_flush(&mut writer, &mut fallback).await;
                self.ctx.cancel();
                return;
            }
            // Every write ahead of this task (including one carried by this same task) has now
            // been written and flushed, so a flush barrier queued at or before this point can be
            // acknowledged: see `Conn::poll_flush` (conn.rs), which is what queues `ack`.
            if let Some(ack) = task.ack.take() {
                let _ = ack.send(());
            }
        }
    }

    fn fill_explicit_nonce(&self, rec: &mut Record, c2s: bool) {
        if !rec.inserted {
            return;
        }
        let Some(nonce_bytes) = rec.fragment.get_mut(..8) else {
            return;
        };
        if !self.explicit_ready.is_closed() {
            return;
        }
        if !self.random.read().tls12_explicit {
            return;
        }
        if rec.record_type != RECORD_TYPE_APPLICATION_DATA && rec.record_type != RECORD_TYPE_ALERT {
            return;
        }
        let nonce = if c2s { self.c2s_explicit_nonce.lock().next() } else { self.s2c_explicit_nonce.lock().next() };
        nonce_bytes.copy_from_slice(&nonce);
    }
}

async fn copy_flush<R, W>(writer: &mut W, src: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        let Some(chunk) = buf.get(..n) else {
            return Ok(());
        };
        writer.write_all(chunk).await?;
        writer.flush().await?;
    }
}

async fn write_raw_flush<W: AsyncWrite + Unpin>(writer: &mut W, raw: &[u8]) -> Result<()> {
    if raw.is_empty() {
        return Ok(());
    }
    writer.write_all(raw).await?;
    writer.flush().await?;
    Ok(())
}

enum PeekOutcome {
    NeedMore,
    Ready(Record, usize),
}

fn peek_first_handshake_record(buffer: &[u8]) -> Result<PeekOutcome> {
    let Some(header) = buffer.first_chunk::<5>() else {
        return Ok(PeekOutcome::NeedMore);
    };
    let [record_type, major, minor, length_hi, length_lo] = *header;
    if record_type != RECORD_TYPE_HANDSHAKE {
        return Err(anyhow!("tlsmirror: unexpected first tls record type"));
    }
    match major {
        0x01 | 0x02 => {}
        0x03 => {
            if minor > 0x03 {
                return Err(anyhow!("tlsmirror: unexpected first tls record version"));
            }
        }
        _ => return Err(anyhow!("tlsmirror: unexpected first tls record version")),
    }
    let length = (usize::from(length_hi) << 8) | usize::from(length_lo);
    if length > MAX_TLS_RECORD_PAYLOAD {
        return Err(anyhow!("tlsmirror: tls record is too large"));
    }
    let processed = 5 + length;
    if buffer.len() < processed {
        return Ok(PeekOutcome::NeedMore);
    }
    let (captured, _) = buffer.split_at(processed);
    let (_, fragment) = captured.split_at(5);
    let rec = Record { record_type, version: [major, minor], fragment: fragment.to_vec(), inserted: false };
    Ok(PeekOutcome::Ready(rec, processed))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::oneshot;

    use murmur_common_net::deadline::pipe_sing::pipe;

    use super::*;

    fn test_client_hello_fragment() -> Vec<u8> {
        let mut fragment = vec![0u8; 38];
        fragment[0] = 1;
        for (i, byte) in fragment.iter_mut().enumerate().skip(6) {
            *byte = i as u8;
        }
        fragment
    }

    fn test_server_hello_fragment() -> Vec<u8> {
        let mut fragment = vec![0u8; 41];
        fragment[0] = 2;
        for (i, byte) in fragment.iter_mut().enumerate().take(38).skip(6) {
            *byte = (0x80 + i) as u8;
        }
        fragment[38] = 0;
        fragment[39] = 0x13;
        fragment[40] = 0x01;
        fragment
    }

    fn encode_test_record(record_type: u8, version: [u8; 2], fragment: &[u8]) -> Vec<u8> {
        let mut record = vec![0u8; 5 + fragment.len()];
        record[0] = record_type;
        record[1] = version[0];
        record[2] = version[1];
        let len = fragment.len() as u16;
        record[3] = (len >> 8) as u8;
        record[4] = len as u8;
        record[5..].copy_from_slice(fragment);
        record
    }

    struct FallbackPipe {
        client: SharedConn,
        forward: SharedConn,
        write_err_tx: mpsc::Sender<io::Result<()>>,
        write_err_rx: mpsc::Receiver<io::Result<()>>,
    }

    fn new_pipe(c2s_hook: Option<Arc<dyn MessageHook>>) -> FallbackPipe {
        let ctx = CancellationToken::new();
        let (client_raw, mirror_client_raw) = pipe();
        let (mirror_server_raw, forward_raw) = pipe();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        client_raw.set_deadline(Some(deadline)).expect("set client deadline");
        forward_raw.set_deadline(Some(deadline)).expect("set forward deadline");

        let mirror = new_mirror_conn(
            &ctx,
            SharedConn::new(Box::new(mirror_client_raw)),
            SharedConn::new(Box::new(mirror_server_raw)),
            &Config::default(),
            c2s_hook,
            None,
            None,
            None,
        );
        mirror.start();

        let (write_err_tx, write_err_rx) = mpsc::channel(4);
        FallbackPipe {
            client: SharedConn::new(Box::new(client_raw)),
            forward: SharedConn::new(Box::new(forward_raw)),
            write_err_tx,
            write_err_rx,
        }
    }

    fn write_async(tx: &mpsc::Sender<io::Result<()>>, mut conn: SharedConn, payload: Vec<u8>) {
        let tx = tx.clone();
        tokio::spawn(async move {
            let result = conn.write_all(&payload).await;
            let _ = tx.send(result).await;
        });
    }

    async fn expect_read(conn: &mut SharedConn, want: &[u8]) {
        let mut got = vec![0u8; want.len()];
        conn.read_exact(&mut got).await.expect("expected bytes were not forwarded");
        assert_eq!(got, want);
    }

    async fn expect_read_error(conn: &mut SharedConn) {
        let mut buf = [0u8; 1];
        let result = conn.read(&mut buf).await;
        assert!(result.is_err(), "expected a read error");
    }

    async fn forward_client_hello(p: &mut FallbackPipe) {
        let client_hello = encode_test_record(RECORD_TYPE_HANDSHAKE, [0x03, 0x03], &test_client_hello_fragment());
        write_async(&p.write_err_tx, p.client.clone(), client_hello.clone());
        expect_read(&mut p.forward, &client_hello).await;
        p.write_err_rx.recv().await.expect("write result").expect("client hello write failed");
    }

    async fn forward_server_hello(p: &mut FallbackPipe) {
        let server_hello = encode_test_record(RECORD_TYPE_HANDSHAKE, [0x03, 0x03], &test_server_hello_fragment());
        write_async(&p.write_err_tx, p.forward.clone(), server_hello.clone());
        expect_read(&mut p.client, &server_hello).await;
        p.write_err_rx.recv().await.expect("write result").expect("server hello write failed");
    }

    #[tokio::test]
    async fn fallback_non_tls() {
        let mut p = new_pipe(None);
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        write_async(&p.write_err_tx, p.client.clone(), request.clone());
        expect_read(&mut p.forward, &request).await;
        p.write_err_rx.recv().await.expect("write result").expect("request write failed");

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec();
        write_async(&p.write_err_tx, p.forward.clone(), response.clone());
        expect_read(&mut p.client, &response).await;
        p.write_err_rx.recv().await.expect("write result").expect("response write failed");
    }

    #[tokio::test]
    async fn fallback_closes_after_malformed_first_client_hello() {
        let mut p = new_pipe(None);
        let malformed_client_hello = encode_test_record(RECORD_TYPE_HANDSHAKE, [0x03, 0x03], &[1]);
        write_async(&p.write_err_tx, p.client.clone(), malformed_client_hello.clone());
        expect_read(&mut p.forward, &malformed_client_hello).await;
        expect_read_error(&mut p.forward).await;
        let _ = p.write_err_rx.recv().await;
    }

    #[tokio::test]
    async fn fallback_after_c2s_hook_error() {
        let hook: Arc<dyn MessageHook> = Arc::new(FnHook(hrtb_hook(|rec: &mut Record| {
            Box::pin(async move {
                if rec.record_type == RECORD_TYPE_APPLICATION_DATA {
                    Err(anyhow!("probe fallback"))
                } else {
                    Ok(false)
                }
            })
        })));
        let mut p = new_pipe(Some(hook));
        forward_client_hello(&mut p).await;
        forward_server_hello(&mut p).await;

        let application_data =
            encode_test_record(RECORD_TYPE_APPLICATION_DATA, [0x03, 0x03], b"probe-application-data");
        let raw_tail = b"raw-tail-after-fallback".to_vec();
        let mut payload = application_data.clone();
        payload.extend_from_slice(&raw_tail);
        write_async(&p.write_err_tx, p.client.clone(), payload);
        expect_read(&mut p.forward, &application_data).await;
        expect_read(&mut p.forward, &raw_tail).await;
        p.write_err_rx.recv().await.expect("write result").expect("payload write failed");
    }

    #[tokio::test]
    async fn fallback_keeps_invalid_record_header() {
        let mut p = new_pipe(None);
        forward_client_hello(&mut p).await;
        forward_server_hello(&mut p).await;

        let invalid_header = vec![RECORD_TYPE_APPLICATION_DATA, 0x03, 0x03, 0x40, 0x01];
        let raw_tail = b"tail-after-invalid-header".to_vec();
        let mut payload = invalid_header.clone();
        payload.extend_from_slice(&raw_tail);
        write_async(&p.write_err_tx, p.client.clone(), payload);
        expect_read(&mut p.forward, &invalid_header).await;
        expect_read(&mut p.forward, &raw_tail).await;
        p.write_err_rx.recv().await.expect("write result").expect("payload write failed");
    }

    #[tokio::test]
    async fn fallback_c2s_change_cipher_spec_before_server_hello() {
        let mut p = new_pipe(None);
        forward_client_hello(&mut p).await;

        let change_cipher_spec = encode_test_record(RECORD_TYPE_CHANGE_CIPHER_SPEC, [0x03, 0x03], &[1]);
        let raw_tail = b"raw-tail-after-early-ccs".to_vec();
        let mut payload = change_cipher_spec.clone();
        payload.extend_from_slice(&raw_tail);
        write_async(&p.write_err_tx, p.client.clone(), payload);
        expect_read(&mut p.forward, &change_cipher_spec).await;
        expect_read(&mut p.forward, &raw_tail).await;
        p.write_err_rx.recv().await.expect("write result").expect("payload write failed");
    }

    #[tokio::test]
    async fn fallback_forwards_alert_before_close() {
        let mut p = new_pipe(None);
        forward_client_hello(&mut p).await;
        forward_server_hello(&mut p).await;

        let alert = encode_test_record(RECORD_TYPE_ALERT, [0x03, 0x03], &[1, 0]);
        write_async(&p.write_err_tx, p.client.clone(), alert.clone());
        expect_read(&mut p.forward, &alert).await;
        p.write_err_rx.recv().await.expect("write result").expect("alert write failed");
    }

    #[tokio::test]
    async fn capture_first_handshake_record_forwards_fragments() {
        let ctx = CancellationToken::new();
        let (src_raw, src_writer_raw) = pipe();
        let (dst_reader_raw, dst_raw) = pipe();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        src_raw.set_deadline(Some(deadline)).expect("set src deadline");
        src_writer_raw.set_deadline(Some(deadline)).expect("set src writer deadline");
        dst_reader_raw.set_deadline(Some(deadline)).expect("set dst reader deadline");
        dst_raw.set_deadline(Some(deadline)).expect("set dst deadline");

        let src = SharedConn::new(Box::new(src_raw));
        let mut dst_reader = SharedConn::new(Box::new(dst_reader_raw));
        let dst = SharedConn::new(Box::new(dst_raw));
        let src_writer = SharedConn::new(Box::new(src_writer_raw));

        let mirror = new_mirror_conn(&ctx, src.clone(), dst.clone(), &Config::default(), None, None, None, None);

        let (captured_tx, captured_rx) = oneshot::channel();
        {
            let mirror = Arc::clone(&mirror);
            let src = src.clone();
            let dst = dst.clone();
            tokio::spawn(async move {
                let mut writer = BufWriter::with_capacity(65536, dst);
                let result = mirror.capture_first_handshake_record(src, &mut writer).await;
                let _ = captured_tx.send(result);
            });
        }

        let client_hello = encode_test_record(RECORD_TYPE_HANDSHAKE, [0x03, 0x03], &test_client_hello_fragment());
        let first_part = client_hello[..8].to_vec();
        let rest_part = client_hello[8..].to_vec();
        let next_record = encode_test_record(RECORD_TYPE_APPLICATION_DATA, [0x03, 0x03], b"coalesced-next-record");

        let (write_err_tx, mut write_err_rx) = mpsc::channel::<io::Result<()>>(2);
        {
            let tx = write_err_tx.clone();
            let mut src_writer = src_writer.clone();
            let first_part = first_part.clone();
            tokio::spawn(async move {
                let result = src_writer.write_all(&first_part).await;
                let _ = tx.send(result).await;
            });
        }
        let mut got_first_part = vec![0u8; first_part.len()];
        dst_reader.read_exact(&mut got_first_part).await.expect("read first part");
        assert_eq!(got_first_part, first_part);
        write_err_rx.recv().await.expect("write result").expect("first part write failed");

        {
            let tx = write_err_tx.clone();
            let mut src_writer = src_writer.clone();
            let mut payload = rest_part.clone();
            payload.extend_from_slice(&next_record);
            tokio::spawn(async move {
                let result = src_writer.write_all(&payload).await;
                let _ = tx.send(result).await;
            });
        }
        write_err_rx.recv().await.expect("write result").expect("rest part write failed");

        let result = captured_rx.await.expect("capture task result");
        let (rec, mut reader, raw) = result.expect("captureFirstHandshakeRecord failed");
        assert_eq!(rec.record_type, RECORD_TYPE_HANDSHAKE);
        assert_eq!(rec.fragment, test_client_hello_fragment());
        assert_eq!(raw, rest_part);

        {
            let tx = write_err_tx.clone();
            let raw = raw.clone();
            let mut writer = BufWriter::with_capacity(65536, dst.clone());
            tokio::spawn(async move {
                let result = write_raw_flush(&mut writer, &raw).await.map_err(io::Error::other);
                let _ = tx.send(result).await;
            });
        }
        let mut got_rest_part = vec![0u8; rest_part.len()];
        dst_reader.read_exact(&mut got_rest_part).await.expect("read rest part");
        assert_eq!(got_rest_part, rest_part);
        write_err_rx.recv().await.expect("write result").expect("rest part flush failed");

        let (rec, raw, result) = read_record(&mut reader).await;
        result.expect("read coalesced record");
        let rec = rec.expect("coalesced record parsed");
        assert_eq!(rec.record_type, RECORD_TYPE_APPLICATION_DATA);
        assert_eq!(rec.fragment, b"coalesced-next-record");
        assert_eq!(raw, next_record);
    }
}

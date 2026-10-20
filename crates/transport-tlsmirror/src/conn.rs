use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use chacha20::cipher::StreamCipher;
use chacha20::XChaCha20;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use murmur_common_net::deadline::conn::err_deadline_exceeded;
use murmur_common_net::io::{old_addr_to_socket_addr, DeadlineToken, Stream as NetStream};
use murmur_std_compat::net::{Addr, Conn as NetConn};

use super::config::Config;
use super::crypto::{
    derive_encryption_key, new_decryptor, new_encryptor, new_sequence_watermark, Decryptor, Encryptor,
};
use super::mirror::{hrtb_hook, FnHook, MessageHook, MirrorConn, SharedConn, WriteTask};
use super::padding::{pack_padding, unpack_padding};
use super::record::{
    duplicate_record, Record, MAX_TLS_RECORD_PAYLOAD, RECORD_TYPE_ALERT, RECORD_TYPE_APPLICATION_DATA,
};

pub(crate) const ERR_CARRIER_HANDSHAKE: &str = "tlsmirror: carrier handshake failed";

fn context_canceled_io() -> io::Error {
    io::Error::other("context canceled")
}

fn io_err(err: anyhow::Error) -> io::Error {
    io::Error::other(err)
}

struct CryptoState {
    encryptor: Option<Arc<Mutex<Encryptor>>>,
    decryptor: Option<Arc<Mutex<Decryptor>>>,
    protocol_version: [u8; 2],
}

struct EnrollmentState {
    remove: Option<Box<dyn FnOnce() + Send>>,
    removed: bool,
}

struct ReadState {
    buffer: Option<Bytes>,
    /// The read-deadline generation (see [`murmur_common_net::io::DeadlineToken::token_with_generation`])
    /// in force when `future` was created. `poll_read` discards a stale `future` instead of
    /// resuming it when this no longer matches the current generation: the bridge's own fallback
    /// timer can abandon a poll of this future without `Conn` itself ever being told (see
    /// `agent://ReviewBridge`'s P2), leaving `future` alive holding a clone of a token that is
    /// now permanently cancelled — resuming it would spuriously fail every read forever, even
    /// past a later `set_read_deadline(None)`. Discarding is lossless for a read: the underlying
    /// `read_rx` channel keeps no state of its own tied to this particular future.
    generation: u64,
    future: Option<Pin<Box<dyn Future<Output = io::Result<Bytes>> + Send>>>,
}

struct WriteState {
    /// The exact caller-visible buffer this in-flight write was started from. Unlike a read, a
    /// write cannot be safely discarded and silently retried when a resumed poll carries
    /// different bytes: the abandoned future may still be in flight and could still enqueue the
    /// *old* buffer's bytes at an unpredictable later time, and `AsyncWrite`'s own contract
    /// requires a resumed poll to carry the identical buffer anyway. So a mismatch here (as
    /// opposed to a mere deadline reset, which does not change the buffer and must not tear
    /// anything down) tears the whole `Conn` down (`ConnInner::torn`) instead of resuming or
    /// discarding — matching the own contract that a mid-frame write failure leaves the conn
    /// broken, never silently resumable.
    payload: Bytes,
    future: Option<Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>>,
}

struct FlushState {
    future: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
}

struct ConnInner {
    ctx: CancellationToken,

    mirror: Arc<MirrorConn>,

    primary_key: Vec<u8>,
    is_server: bool,
    config: Config,

    crypto: Mutex<CryptoState>,
    watermark_tx: Mutex<Option<XChaCha20>>,
    watermark_rx: Mutex<Option<XChaCha20>>,

    first_write: AtomicBool,
    first_write_delay: std::time::Duration,

    read_tx: mpsc::Sender<Bytes>,
    read_rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    read_state: Mutex<ReadState>,
    write_state: Mutex<WriteState>,
    flush_state: Mutex<FlushState>,

    recall_traffic_generator: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    enrollment: Mutex<EnrollmentState>,
    read_deadline: DeadlineToken,
    write_deadline: DeadlineToken,
    /// Set once a resumed write is found to carry different bytes than the frame already
    /// mid-flight (see [`WriteState::payload`]), or once any byte of a frame has already reached
    /// the peer and the write that carried it then fails: every subsequent read/write/flush fails
    /// with `BrokenPipe` instead of risking a torn frame's stale bytes reaching the peer later.
    torn: AtomicBool,
    /// Set to `true` the moment `write_once` inserts its first fragment onto the mirror's queue
    /// for the write currently in flight, and reset to `false` when a new write begins; consulted
    /// by `poll_write`'s error arm to tell a write that failed after some bytes already reached
    /// the peer (must tear the conn down) from one that failed before any byte went out (safe to
    /// simply report the error and let the caller retry with a fresh write).
    write_progress: AtomicBool,
}

/// A cheap `Arc` handle: hooks captured by the mirror conn and the handle returned to
/// callers alias the same connection, which this mirrors with `Arc` sharing.
#[derive(Clone)]
pub struct Conn(Arc<ConnInner>);

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The inner state carries the shared secret and the live crypto state.
        f.debug_struct("Conn").finish_non_exhaustive()
    }
}

pub(crate) fn new_hidden_conn(
    parent_ctx: &CancellationToken,
    mirror: Arc<MirrorConn>,
    primary_key: Vec<u8>,
    is_server: bool,
    cfg: Config,
) -> Result<Conn> {
    let ctx = parent_ctx.child_token();
    let first_write_delay = cfg.defer_instance_derived_write.duration().inspect_err(|_| ctx.cancel())?;
    let (read_tx, read_rx) = mpsc::channel(32);
    Ok(Conn(Arc::new(ConnInner {
        ctx,
        mirror,
        primary_key,
        is_server,
        config: cfg,
        crypto: Mutex::new(CryptoState { encryptor: None, decryptor: None, protocol_version: [0, 0] }),
        watermark_tx: Mutex::new(None),
        watermark_rx: Mutex::new(None),
        first_write: AtomicBool::new(true),
        first_write_delay,
        read_tx,
        read_rx: tokio::sync::Mutex::new(read_rx),
        read_state: Mutex::new(ReadState { buffer: None, generation: 0, future: None }),
        write_state: Mutex::new(WriteState { payload: Bytes::new(), future: None }),
        flush_state: Mutex::new(FlushState { future: None }),
        recall_traffic_generator: Mutex::new(None),
        enrollment: Mutex::new(EnrollmentState { remove: None, removed: false }),
        read_deadline: DeadlineToken::new(),
        write_deadline: DeadlineToken::new(),
        torn: AtomicBool::new(false),
        write_progress: AtomicBool::new(false),
    })))
}

impl ConnInner {
    fn ensure_crypto_locked(
        &self,
        crypto: &mut CryptoState,
        version: [u8; 2],
    ) -> Result<(Arc<Mutex<Encryptor>>, Arc<Mutex<Decryptor>>)> {
        if let (Some(encryptor), Some(decryptor)) = (&crypto.encryptor, &crypto.decryptor) {
            return Ok((Arc::clone(encryptor), Arc::clone(decryptor)));
        }
        let (client_random, server_random) = self.mirror.handshake_random()?;

        let (encrypt_tag, decrypt_tag) = if self.is_server { (":s2c", ":c2s") } else { (":c2s", ":s2c") };

        let (enc_key, enc_mask) = derive_encryption_key(&self.primary_key, client_random, server_random, encrypt_tag)?;
        let (dec_key, dec_mask) = derive_encryption_key(&self.primary_key, client_random, server_random, decrypt_tag)?;
        let encryptor = Arc::new(Mutex::new(new_encryptor(&enc_key, &enc_mask)?));
        let decryptor = Arc::new(Mutex::new(new_decryptor(&dec_key, &dec_mask)?));
        crypto.encryptor = Some(Arc::clone(&encryptor));
        crypto.decryptor = Some(Arc::clone(&decryptor));
        crypto.protocol_version = if version == [0, 0] { [0x03, 0x03] } else { version };
        Ok((encryptor, decryptor))
    }

    // NOT cancel-safe: the record is consumed and its watermark applied before the payload reaches
    // the reader, so a drop here loses the plaintext record.
    pub(crate) async fn handle_inbound_record(&self, rec: &mut Record) -> Result<bool> {
        self.apply_sequence_watermark_rx(rec);
        if rec.record_type != RECORD_TYPE_APPLICATION_DATA {
            return Ok(false);
        }
        let decryptor = {
            let mut crypto = self.crypto.lock();
            let version = rec.version;
            let Ok((_, decryptor)) = self.ensure_crypto_locked(&mut crypto, version) else {
                return Ok(false);
            };
            decryptor
        };
        let overhead = self.mirror.explicit_nonce_overhead().await;
        let nonce_size = decryptor.lock().nonce_size();
        if rec.fragment.len() < overhead + nonce_size {
            return Ok(false);
        }
        let payload = {
            let mut d = decryptor.lock();
            let Some(fragment) = rec.fragment.get(overhead..) else {
                return Ok(false);
            };
            match d.open(fragment) {
                Ok(payload) => payload,
                Err(_) => return Ok(false),
            }
        };
        self.init_sequence_watermark_rx();
        let payload = if self.config.transport_layer_padding.enabled {
            match unpack_padding(&payload) {
                (Some(payload), _) => payload.to_vec(),
                (None, _) => return Ok(true),
            }
        } else {
            payload
        };
        tokio::select! {
            () = self.ctx.cancelled() => Err(anyhow!("context canceled")),
            result = self.read_tx.send(Bytes::from(payload)) => {
                result.map_err(|_| anyhow!("tlsmirror: conn closed"))?;
                Ok(true)
            }
        }
    }

    fn apply_sequence_watermark_rx(&self, rec: &mut Record) {
        if !self.config.sequence_watermarking_enabled {
            return;
        }
        if rec.record_type != RECORD_TYPE_APPLICATION_DATA && rec.record_type != RECORD_TYPE_ALERT {
            return;
        }
        let Some(offset) = rec.fragment.len().checked_sub(16) else { return };
        let Some(watermark) = rec.fragment.get_mut(offset..) else { return };
        let mut guard = self.watermark_rx.lock();
        let Some(stream) = guard.as_mut() else { return };
        stream.apply_keystream(watermark);
        drop(guard);
    }

    #[expect(clippy::unused_async, reason = "the hook wrapper awaits this alongside `handle_inbound_record`")]
    pub(crate) async fn handle_outbound_record_tx(&self, rec: &mut Record) -> Result<bool> {
        if !self.config.sequence_watermarking_enabled {
            return Ok(false);
        }
        let is_watermarked_tail = (rec.record_type == RECORD_TYPE_APPLICATION_DATA
            || rec.record_type == RECORD_TYPE_ALERT)
            && rec.fragment.len() >= 16;
        if is_watermarked_tail {
            let len = rec.fragment.len();
            let mut guard = self.watermark_tx.lock();
            if let (Some(stream), Some(watermark)) = (guard.as_mut(), rec.fragment.get_mut(len - 16..)) {
                stream.apply_keystream(watermark);
            }
        }
        let has_watermark_tx = self.watermark_tx.lock().is_some();
        if rec.inserted && !has_watermark_tx && self.init_sequence_watermark_tx().is_err() {
            return Ok(true);
        }
        Ok(false)
    }

    fn init_sequence_watermark_tx(&self) -> Result<()> {
        let (client_random, server_random) = self.mirror.handshake_random()?;
        let tag = if self.is_server { ":s2c" } else { ":c2s" };
        let stream = new_sequence_watermark(&self.primary_key, client_random, server_random, tag)?;
        *self.watermark_tx.lock() = Some(stream);
        Ok(())
    }

    fn init_sequence_watermark_rx(&self) {
        if !self.config.sequence_watermarking_enabled || self.watermark_rx.lock().is_some() {
            return;
        }
        let Ok((client_random, server_random)) = self.mirror.handshake_random() else { return };
        let tag = if self.is_server { ":c2s" } else { ":s2c" };
        if let Ok(stream) = new_sequence_watermark(&self.primary_key, client_random, server_random, tag) {
            *self.watermark_rx.lock() = Some(stream);
        }
    }

    /// One iteration of the conn read's inner select.
    // cancel-safe: a cancelled receive leaves the queued record for the next call, and the future
    // is replaced only after it reports `Ready`.
    async fn read_once(&self) -> io::Result<Bytes> {
        let cancel_token = self.read_deadline.token();
        let mut rx = self.read_rx.lock().await;
        let outcome = tokio::select! {
            () = self.ctx.cancelled() => Err(context_canceled_io()),
            () = self.mirror.ctx().cancelled() => Err(context_canceled_io()),
            () = cancel_token.cancelled() => Err(err_deadline_exceeded()),
            data = rx.recv() => data.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "tlsmirror: read channel closed")),
        };
        drop(rx);
        outcome
    }

    // cancel-safe: it only waits for the mirror's own readiness signal.
    async fn wait_write_ready(&self, deadline: &CancellationToken) -> io::Result<()> {
        let ready: Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> = if self.is_server {
            Box::pin(self.mirror.wait_s2c_ready(&self.ctx))
        } else {
            Box::pin(self.mirror.wait_c2s_ready(&self.ctx))
        };
        tokio::select! {
            outcome = ready => outcome.map_err(io_err),
            () = deadline.cancelled() => Err(err_deadline_exceeded()),
        }
    }

    // cancel-safe: an `mpsc` send is atomic, so the task is either queued whole or not at all.
    async fn insert_c2s(&self, rec: &Record, deadline: &CancellationToken) -> io::Result<()> {
        let task = WriteTask { rec: Some(duplicate_record(rec)), raw: Vec::new(), fallback: None, ack: None };
        let tx = self.mirror.c2s_insert_tx();
        tokio::select! {
            () = self.ctx.cancelled() => Err(context_canceled_io()),
            () = self.mirror.ctx().cancelled() => Err(context_canceled_io()),
            () = deadline.cancelled() => Err(err_deadline_exceeded()),
            result = tx.send(task) => result.map_err(|_| io::Error::other("tlsmirror: mirror is closed")),
        }
    }

    // cancel-safe: as `insert_c2s`.
    async fn insert_s2c(&self, rec: &Record, deadline: &CancellationToken) -> io::Result<()> {
        let task = WriteTask { rec: Some(duplicate_record(rec)), raw: Vec::new(), fallback: None, ack: None };
        let tx = self.mirror.s2c_insert_tx();
        tokio::select! {
            () = self.ctx.cancelled() => Err(context_canceled_io()),
            () = self.mirror.ctx().cancelled() => Err(context_canceled_io()),
            () = deadline.cancelled() => Err(err_deadline_exceeded()),
            result = tx.send(task) => result.map_err(|_| io::Error::other("tlsmirror: mirror is closed")),
        }
    }

    /// Queues a flush-barrier `WriteTask` on the same queue `insert_c2s`/`insert_s2c` write
    /// records to, so it is only acknowledged once every record queued before it has actually
    /// been written and flushed by `record_writer` (see `mirror.rs`) — unlike the previous bare
    /// `Poll::Ready(Ok(()))`, which returned before a queued write had necessarily reached the
    /// wire at all.
    // NOT cancel-safe: a cancelled ack wait abandons a barrier that stays queued, so the flush
    // still runs while the caller sees the cancellation error.
    async fn flush_once(self: Arc<Self>) -> io::Result<()> {
        let tx = if self.is_server { self.mirror.s2c_insert_tx() } else { self.mirror.c2s_insert_tx() };
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        let task = WriteTask { rec: None, raw: Vec::new(), fallback: None, ack: Some(ack_tx) };
        let cancel_token = self.write_deadline.token();
        let sent = tokio::select! {
            () = self.ctx.cancelled() => return Err(context_canceled_io()),
            () = self.mirror.ctx().cancelled() => return Err(context_canceled_io()),
            () = cancel_token.cancelled() => return Err(err_deadline_exceeded()),
            result = tx.send(task) => result,
        };
        if sent.is_err() {
            return Ok(());
        }
        tokio::select! {
            () = self.ctx.cancelled() => Err(context_canceled_io()),
            () = self.mirror.ctx().cancelled() => Err(context_canceled_io()),
            () = cancel_token.cancelled() => Err(err_deadline_exceeded()),
            _ = ack_rx => Ok(()),
        }
    }

    // NOT cancel-safe: the first-write flag is cleared before the delay is awaited, and a mid-frame
    // drop leaves part of the write on the mirror's queue.
    async fn write_once(self: Arc<Self>, data: Bytes) -> io::Result<usize> {
        let cancel_token = self.write_deadline.token();
        self.wait_write_ready(&cancel_token).await?;

        if self.first_write.swap(false, Ordering::SeqCst) && !self.first_write_delay.is_zero() {
            tokio::select! {
                () = self.ctx.cancelled() => return Err(context_canceled_io()),
                () = self.mirror.ctx().cancelled() => return Err(context_canceled_io()),
                () = cancel_token.cancelled() => return Err(err_deadline_exceeded()),
                () = tokio::time::sleep(self.first_write_delay) => {}
            }
        }

        let payload_size = data.len();
        let (encryptor, version) = {
            let mut crypto = self.crypto.lock();
            let version = crypto.protocol_version;
            let (encryptor, _) = self.ensure_crypto_locked(&mut crypto, version).map_err(io_err)?;
            (encryptor, crypto.protocol_version)
        };

        let overhead = self.mirror.explicit_nonce_overhead().await;
        let mut max_plaintext = MAX_TLS_RECORD_PAYLOAD
            .checked_sub(overhead)
            .and_then(|room| room.checked_sub(encryptor.lock().overhead()))
            .ok_or_else(|| io_err(anyhow!("tlsmirror: invalid tls record overhead")))?;
        if self.config.transport_layer_padding.enabled {
            max_plaintext = max_plaintext
                .checked_sub(4)
                .ok_or_else(|| io_err(anyhow!("tlsmirror: invalid tls record overhead")))?;
        }
        if max_plaintext == 0 {
            return Err(io_err(anyhow!("tlsmirror: invalid tls record overhead")));
        }

        let mut written = 0usize;
        while written < data.len() {
            let end = (written + max_plaintext).min(data.len());
            let Some(chunk) = data.get(written..end) else {
                return Err(io_err(anyhow!("tlsmirror: invalid tls record overhead")));
            };
            let mut fragment = vec![0u8; overhead];
            // Sealing advances the encryptor's nonce counter; anything that fails from this
            // point on (including the `insert_*` call below, e.g. a deadline hitting a full
            // queue) leaves the peer's decryptor permanently desynchronized the moment the
            // *next* fragment is sealed, so `poll_write`'s caller must tear the conn even if the
            // failing insert never queued a single byte (`agent://ReviewBridge2` P2).
            self.write_progress.store(true, Ordering::SeqCst);
            // `chunk` borrows the `data: Bytes` owned by this future and is not used after the
            // seal, so the unpadded path seals it in place. Padding is the only case that needs
            // a new buffer, and it is built once and borrowed rather than copied into `plain`
            // first.
            if self.config.transport_layer_padding.enabled {
                let padded = pack_padding(chunk, 0);
                encryptor.lock().seal(&mut fragment, &padded).map_err(io_err)?;
            } else {
                encryptor.lock().seal(&mut fragment, chunk).map_err(io_err)?;
            }
            let rec = Record { record_type: RECORD_TYPE_APPLICATION_DATA, version, fragment, inserted: true };
            let result = if self.is_server {
                self.insert_s2c(&rec, &cancel_token).await
            } else {
                self.insert_c2s(&rec, &cancel_token).await
            };
            result?;
            written = end;
        }
        Ok(payload_size)
    }

    fn remove_enrollment(&self) {
        let mut state = self.enrollment.lock();
        if state.removed {
            return;
        }
        state.removed = true;
        let remove = state.remove.take();
        drop(state);
        if let Some(remove) = remove {
            remove();
        }
    }

    fn set_enrollment_remove(&self, remove: Box<dyn FnOnce() + Send>) {
        let mut state = self.enrollment.lock();
        if state.removed {
            drop(state);
            remove();
            return;
        }
        state.remove = Some(remove);
    }

    fn addr_conn(&self) -> &SharedConn {
        if self.is_server {
            &self.mirror.client_conn
        } else {
            &self.mirror.server_conn
        }
    }
}

/// `Stream::old_conn` view: reached only through `StreamAsOldConn` by callers not yet migrated
/// off the std-compat `Conn` trait. `AsyncRead`/`AsyncWrite` here are never polled — `StreamAsOldConn`
/// reads/writes through `Conn`'s own `AsyncRead`/`AsyncWrite` impl below, not through this view.
impl AsyncRead for ConnInner {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("tlsmirror: close-view is never polled")))
    }
}

impl AsyncWrite for ConnInner {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other("tlsmirror: close-view is never polled")))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl NetConn for ConnInner {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.addr_conn().local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.addr_conn().remote_addr()
    }

    fn close(&self) -> io::Result<()> {
        let recall = self.recall_traffic_generator.lock().clone();
        if let Some(recall) = recall {
            (*recall)();
        }
        self.remove_enrollment();
        self.ctx.cancel();
        self.mirror.close().map_err(io_err)
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.set_read_deadline(deadline)?;
        self.set_write_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.read_deadline.set(deadline);
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.write_deadline.set(deadline);
        Ok(())
    }
}

impl Conn {
    /// The outbound-record hook, as a hook value.
    pub(crate) fn as_outbound_tx_hook(&self) -> Arc<dyn MessageHook> {
        let inner = Arc::clone(&self.0);
        Arc::new(FnHook(hrtb_hook(move |rec: &mut Record| {
            let inner = Arc::clone(&inner);
            Box::pin(async move { inner.handle_outbound_record_tx(rec).await })
        })))
    }

    pub(crate) fn ctx(&self) -> &CancellationToken {
        &self.0.ctx
    }

    pub(crate) fn mirror(&self) -> &Arc<MirrorConn> {
        &self.0.mirror
    }

    /// `hidden.handleInboundRecord`: the forward-declared hook's entry point.
    pub(crate) async fn handle_inbound_record(&self, rec: &mut Record) -> Result<bool> {
        self.0.handle_inbound_record(rec).await
    }

    /// `hidden.removeEnrollment`, assigned as `mirror.onClose`.
    pub(crate) fn remove_enrollment(&self) {
        self.0.remove_enrollment();
    }

    pub(crate) fn primary_key(&self) -> &[u8] {
        &self.0.primary_key
    }

    pub(crate) fn set_recall_traffic_generator(&self, f: Arc<dyn Fn() + Send + Sync>) {
        *self.0.recall_traffic_generator.lock() = Some(f);
    }

    pub(crate) fn set_enrollment_remove(&self, remove: Box<dyn FnOnce() + Send>) {
        self.0.set_enrollment_remove(remove);
    }

    pub fn close(&self) -> io::Result<()> {
        NetConn::close(self.0.as_ref())
    }

    pub fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        NetConn::set_deadline(self.0.as_ref(), deadline)
    }

    pub fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        NetConn::set_read_deadline(self.0.as_ref(), deadline)
    }

    pub fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        NetConn::set_write_deadline(self.0.as_ref(), deadline)
    }
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.0.torn.load(Ordering::SeqCst) {
            return Poll::Ready(Err(torn_err()));
        }
        let mut state = this.0.read_state.lock();
        loop {
            if let Some(data) = state.buffer.as_mut() {
                if !data.is_empty() {
                    let n = buf.remaining().min(data.len());
                    let head = data.split_to(n);
                    buf.put_slice(&head);
                    return Poll::Ready(Ok(()));
                }
                state.buffer = None;
            }
            let (_, generation) = this.0.read_deadline.token_with_generation();
            if state.future.is_some() && state.generation != generation {
                state.future = None;
            }
            if state.future.is_none() {
                let inner = Arc::clone(&this.0);
                state.generation = generation;
                state.future = Some(Box::pin(async move { inner.read_once().await }));
            }
            let Some(future) = state.future.as_mut() else {
                return Poll::Ready(Err(poll_future_missing()));
            };
            match future.as_mut().poll(cx) {
                Poll::Pending => {
                    drop(state);
                    return Poll::Pending;
                }
                Poll::Ready(Ok(data)) => {
                    state.future = None;
                    state.buffer = Some(data);
                }
                Poll::Ready(Err(err)) => {
                    state.future = None;
                    drop(state);
                    return Poll::Ready(Err(err));
                }
            }
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.0.torn.load(Ordering::SeqCst) {
            return Poll::Ready(Err(torn_err()));
        }
        let mut state = this.0.write_state.lock();
        if state.future.is_some() && !buf.starts_with(&state.payload) {
            // The bridge abandoned a poll of this same future (a spurious deadline race, e.g.
            // `agent://ReviewBridge`'s P2), and this call carries bytes that are not even a
            // continuation of the frame already mid-flight: the caller that issued the abandoned
            // write already observed a failure for it, and `buf` here is a fresh, unrelated
            // write. `AsyncWrite`'s own contract lets a caller resume a `Pending` poll with a
            // buffer that has grown (`tokio::io::copy` and `BufWriter` both do this), so only a
            // buffer that does **not** start with the bytes already in flight is a genuine
            // mismatch; a mere deadline reset while this same write is still legitimately in
            // flight must not trip this. The old future may still be in flight and could still
            // enqueue its stale bytes later, so resuming or silently discarding it are both
            // unsafe once mismatched — tear the whole conn down instead, matching the own
            // contract that a mid-frame write failure leaves the conn broken.
            state.future = None;
            drop(state);
            this.0.torn.store(true, Ordering::SeqCst);
            return Poll::Ready(Err(torn_err()));
        }
        if state.future.is_none() {
            let inner = Arc::clone(&this.0);
            let data = Bytes::copy_from_slice(buf);
            state.payload = data.clone();
            this.0.write_progress.store(false, Ordering::SeqCst);
            state.future = Some(Box::pin(async move { inner.write_once(data).await }));
        }
        let Some(future) = state.future.as_mut() else {
            return Poll::Ready(Err(poll_future_missing()));
        };
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                state.future = None;
                if result.is_ok() {
                    // A later write completing behind a barrier already stored in
                    // `flush_state` would let the next poll_flush complete on that stale
                    // barrier before this write reaches the peer. Drop the lock on
                    // write_state first, then clear flush_state.
                    drop(state);
                    this.0.flush_state.lock().future = None;
                    return Poll::Ready(result);
                }
                drop(state);
                if this.0.write_progress.load(Ordering::SeqCst) {
                    // At least one fragment of this write was already sealed (or reached the
                    // mirror's queue) before the rest of it failed (e.g. a deadline mid-frame):
                    // the peer's crypto state or byte stream is now permanently desynchronized,
                    // so the whole conn must tear. But the `Write` and this bridge's other
                    // implementations (v2, v3, ss2022) return the write's own error on the call
                    // that discovers the failure, not a synthesized one — a caller checking for
                    // e.g. `TimedOut` on this exact call must still see it
                    // (`agent://ReviewBridge2` P3); only later calls see `torn_err()`.
                    this.0.torn.store(true, Ordering::SeqCst);
                    return Poll::Ready(result);
                }
                Poll::Ready(result)
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.0.torn.load(Ordering::SeqCst) {
            return Poll::Ready(Err(torn_err()));
        }
        let mut state = this.0.flush_state.lock();
        if state.future.is_none() {
            let inner = Arc::clone(&this.0);
            state.future = Some(Box::pin(async move { inner.flush_once().await }));
        }
        let Some(future) = state.future.as_mut() else {
            return Poll::Ready(Err(poll_future_missing()));
        };
        let outcome = match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                state.future = None;
                Poll::Ready(result)
            }
        };
        drop(state);
        outcome
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn torn_err() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "tlsmirror: conn torn by an abandoned mid-frame write")
}

/// Reports the poll state machine losing its future slot, which no reachable path produces.
fn poll_future_missing() -> io::Error {
    io::Error::other("tlsmirror: poll state lost its future")
}

impl NetStream for Conn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.0.addr_conn().local_addr()?.as_ref())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.0.addr_conn().remote_addr()?.as_ref())
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(self.0.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use murmur_common_net::deadline::pipe_sing::pipe;

    use super::*;

    #[tokio::test]
    async fn conn_deadline_read() {
        let ctx = CancellationToken::new();
        let (client, server) = pipe();
        let mirror = super::super::mirror::new_mirror_conn(
            &ctx,
            SharedConn::new(Box::new(client)),
            SharedConn::new(Box::new(server)),
            &Config::default(),
            None,
            None,
            None,
            None,
        );
        let mut conn = new_hidden_conn(&ctx, mirror, vec![0u8; 32], false, Config::default()).unwrap();
        conn.set_read_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(10))).unwrap();

        let mut buf = [0u8; 1];
        let err = conn.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn conn_deadline_write() {
        let ctx = CancellationToken::new();
        let (client, server) = pipe();
        let mirror = super::super::mirror::new_mirror_conn(
            &ctx,
            SharedConn::new(Box::new(client)),
            SharedConn::new(Box::new(server)),
            &Config::default(),
            None,
            None,
            None,
            None,
        );
        let mut conn = new_hidden_conn(&ctx, mirror, vec![0u8; 32], false, Config::default()).unwrap();
        conn.set_write_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(10))).unwrap();

        let err = conn.write(&[1u8]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// Regression for `ReviewTlsWave3` P1: through `StreamAsOldConn` (the bridge every hidden
    /// conn is wrapped in — see `listener/src/tlsmirror/tlsmirror.rs`, `transport-vmess/src/tls.rs`),
    /// a deadline used to be raced twice: once by the bridge's own `CancellableStream` token,
    /// once by `Conn`'s own internal token (forwarded via `set_read_deadline`). The bridge's own
    /// token fired first and returned `TimedOut` without ever polling `Conn::poll_read` again, so
    /// `read_state.future` was abandoned mid-flight holding a clone of the now-permanently-fired
    /// token. Clearing the deadline reset the bridge's and `Conn`'s own tokens, but not that
    /// stale clone, so the very next read resumed the abandoned future and got one more spurious
    /// `TimedOut` instead of the peer's bytes — exactly the sniffer's peek-deadline-then-clear
    /// pattern (`component-sniffer/src/dispatcher.rs`).
    #[tokio::test]
    async fn conn_read_after_deadline_cleared_resumes_instead_of_timing_out_again() {
        let ctx = CancellationToken::new();
        let (client, server) = pipe();
        let mirror = super::super::mirror::new_mirror_conn(
            &ctx,
            SharedConn::new(Box::new(client)),
            SharedConn::new(Box::new(server)),
            &Config::default(),
            None,
            None,
            None,
            None,
        );
        let conn = new_hidden_conn(&ctx, mirror, vec![0u8; 32], false, Config::default()).unwrap();
        let read_tx = conn.0.read_tx.clone();
        let mut bridged = murmur_common_net::io::StreamAsOldConn::new(conn);

        NetConn::set_read_deadline(&bridged, Some(tokio::time::Instant::now() + Duration::from_millis(20))).unwrap();
        let mut buf = [0u8; 8];
        let err = bridged.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        NetConn::set_read_deadline(&bridged, None).unwrap();
        read_tx.send(Bytes::from_static(b"12345678")).await.unwrap();

        let n = tokio::time::timeout(Duration::from_secs(2), bridged.read(&mut buf))
            .await
            .expect("a read after clearing the deadline must not hang")
            .expect("a read after clearing the deadline must resume normally, not fail again on the abandoned future");
        assert_eq!(&buf[..n], b"12345678");
    }

    /// Deterministic regression for the P2 finding in `agent://ReviewBridge`: the bridge's own
    /// fallback `DeadlineToken` and `Conn`'s own internal one raced two independent timers, so on
    /// a multi-thread runtime the bridge's could fire first and abandon `Conn::poll_read` without
    /// `Conn` itself ever observing its own token's cancellation — leaving `read_state.future`
    /// alive, still pinned to that now-permanently-cancelled token. This reproduces the exact
    /// same abandonment `Conn`-side, with no `StreamAsOldConn`, no bridge, and no multi-thread
    /// timing at all: poll a read to `Pending` once, let its own deadline genuinely fire, then
    /// drop the outer future (as a racing caller that got `TimedOut` from elsewhere would) without
    /// ever polling `Conn` again, and clear-and-rearm the deadline before the next read. On
    /// unfixed code this is 100% reproducible, not 1-in-400: `read_state.future` has no way to
    /// know its captured token is stale.
    #[tokio::test]
    async fn conn_read_discards_a_future_abandoned_across_a_deadline_generation_change() {
        let ctx = CancellationToken::new();
        let (client, server) = pipe();
        let mirror = super::super::mirror::new_mirror_conn(
            &ctx,
            SharedConn::new(Box::new(client)),
            SharedConn::new(Box::new(server)),
            &Config::default(),
            None,
            None,
            None,
            None,
        );
        let mut conn = new_hidden_conn(&ctx, mirror, vec![0u8; 32], false, Config::default()).unwrap();
        let read_tx = conn.0.read_tx.clone();

        conn.set_read_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(5))).unwrap();
        let mut buf = [0u8; 8];
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        {
            let mut read_fut = std::pin::pin!(conn.read(&mut buf));
            assert!(read_fut.as_mut().poll(&mut cx).is_pending(), "nothing queued yet: the read must park");
            // Let this specific deadline's own timer genuinely fire and cancel its own token —
            // no bridge, no fallback, just `Conn`'s native `set_read_deadline` — then drop the
            // outer future without ever polling `Conn` again, exactly like a caller who received
            // `TimedOut` from elsewhere and gave up on this read.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        conn.set_read_deadline(None).unwrap();
        read_tx.send(Bytes::from_static(b"12345678")).await.unwrap();

        let n = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut buf))
            .await
            .expect("a fresh read must not hang")
            .expect(
                "a fresh read must see the queued bytes, not resume a future pinned to an \
                 already-fired, discarded deadline generation",
            );
        assert_eq!(&buf[..n], b"12345678");
    }

    /// Write-side twin of the read regression above: `write_state.future` is abandoned the same
    /// way, so a write issued after clearing the deadline resumed that abandoned future and got
    /// an immediate, spurious `TimedOut` instead of genuinely parking on the next write's own
    /// readiness wait.
    #[tokio::test]
    async fn conn_write_after_deadline_cleared_parks_instead_of_failing_again() {
        let ctx = CancellationToken::new();
        let (client, server) = pipe();
        let mirror = super::super::mirror::new_mirror_conn(
            &ctx,
            SharedConn::new(Box::new(client)),
            SharedConn::new(Box::new(server)),
            &Config::default(),
            None,
            None,
            None,
            None,
        );
        let conn = new_hidden_conn(&ctx, mirror, vec![0u8; 32], false, Config::default()).unwrap();
        let mut bridged = murmur_common_net::io::StreamAsOldConn::new(conn);

        NetConn::set_write_deadline(&bridged, Some(tokio::time::Instant::now() + Duration::from_millis(20))).unwrap();
        let err = bridged.write(&[1u8]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        NetConn::set_write_deadline(&bridged, None).unwrap();
        let second = tokio::time::timeout(Duration::from_millis(100), bridged.write(&[2u8])).await;
        assert!(
            second.is_err(),
            "a write after clearing the deadline must park waiting for readiness again, not immediately fail with a stale timeout"
        );
    }

    /// Regression for `agent://ReviewBridge2` P2 (1): `poll_write`'s resume check used to require
    /// the resumed `buf` to equal the in-flight frame's payload exactly. `AsyncWrite`'s own
    /// contract lets a caller resume a `Pending` poll with a buffer that has grown since —
    /// `tokio::io::copy` reads more source data while the writer is `Pending` and
    /// then polls with the extended slice, and so does a `BufWriter` whose caller appends more
    /// bytes between flushes. Neither must tear the conn, as long as the new buffer still starts
    /// with the exact bytes already sealed into the in-flight frame.
    #[tokio::test]
    async fn conn_write_accepts_a_resumed_buffer_that_grew_since_the_last_poll() {
        let ctx = CancellationToken::new();
        let (client, server) = pipe();
        let mirror = super::super::mirror::new_mirror_conn(
            &ctx,
            SharedConn::new(Box::new(client)),
            SharedConn::new(Box::new(server)),
            &Config::default(),
            None,
            None,
            None,
            None,
        );
        let mut conn = new_hidden_conn(&ctx, mirror, vec![0u8; 32], false, Config::default()).unwrap();

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let first = vec![0xAAu8; 50];
        // Nothing drives the handshake capture in this test, so `wait_write_ready` never
        // resolves and the write parks forever — the same baseline `conn_deadline_write` above
        // relies on, just without a deadline racing it here.
        match Pin::new(&mut conn).poll_write(&mut cx, &first) {
            Poll::Pending => {}
            other => panic!("expected the write to park on write-readiness, got {other:?}"),
        }

        let mut grown = first.clone();
        grown.extend_from_slice(&[0xBBu8; 50]);
        match Pin::new(&mut conn).poll_write(&mut cx, &grown) {
            Poll::Pending => {}
            other => panic!(
                "a resumed poll with a buffer that grew but still starts with the in-flight frame's \
                 bytes must not tear the conn, got {other:?}"
            ),
        }
    }

    /// Regression test for the ReviewFlush2b hang: `flush_once` used to wait forever on an ack
    /// from `record_writer`, which is never spawned once the conn is already closed.
    #[tokio::test]
    async fn conn_flush_after_close_returns_context_canceled() {
        let ctx = CancellationToken::new();
        let (client, server) = pipe();
        let mirror = super::super::mirror::new_mirror_conn(
            &ctx,
            SharedConn::new(Box::new(client)),
            SharedConn::new(Box::new(server)),
            &Config::default(),
            None,
            None,
            None,
            None,
        );
        let mut conn = new_hidden_conn(&ctx, mirror, vec![0u8; 32], false, Config::default()).unwrap();
        conn.close().unwrap();

        let err = tokio::time::timeout(Duration::from_secs(2), conn.flush())
            .await
            .expect("flush after close must not hang")
            .unwrap_err();
        assert_eq!(err.to_string(), "context canceled");
    }

    /// Companion to `conn_flush_after_close_returns_context_canceled`: a flush polled past an
    /// already-expired write deadline must not hang on the same unspawned ack either.
    #[tokio::test]
    async fn conn_flush_past_write_deadline_times_out() {
        let ctx = CancellationToken::new();
        let (client, server) = pipe();
        let mirror = super::super::mirror::new_mirror_conn(
            &ctx,
            SharedConn::new(Box::new(client)),
            SharedConn::new(Box::new(server)),
            &Config::default(),
            None,
            None,
            None,
            None,
        );
        let mut conn = new_hidden_conn(&ctx, mirror, vec![0u8; 32], false, Config::default()).unwrap();
        conn.set_write_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(10))).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let err = tokio::time::timeout(Duration::from_secs(2), conn.flush())
            .await
            .expect("flush past the write deadline must not hang")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(err.to_string(), "i/o timeout");
    }

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

    async fn read_one_record(conn: &mut SharedConn) -> Vec<u8> {
        let mut header = [0u8; 5];
        conn.read_exact(&mut header).await.expect("record header");
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; len];
        conn.read_exact(&mut body).await.expect("record body");
        let mut full = header.to_vec();
        full.extend_from_slice(&body);
        full
    }

    /// Drives the crypto-established path a real client/server TLS 1.3 handshake would reach:
    /// forwards a client hello and a server hello through the mirror (so both handshake randoms
    /// and `explicit_ready` are set), then a marker application-data record (so `c2s_ready`
    /// closes and `Conn::write_once` no longer blocks on it).
    async fn setup_ready_c2s_conn(
        hook: Option<Arc<dyn MessageHook>>,
    ) -> (Conn, SharedConn, SharedConn, CancellationToken) {
        let ctx = CancellationToken::new();
        let (client_raw, mirror_client_raw) = pipe();
        let (mirror_server_raw, forward_raw) = pipe();

        let mirror = super::super::mirror::new_mirror_conn(
            &ctx,
            SharedConn::new(Box::new(mirror_client_raw)),
            SharedConn::new(Box::new(mirror_server_raw)),
            &Config::default(),
            None,
            None,
            hook,
            None,
        );
        mirror.start();

        let mut client = SharedConn::new(Box::new(client_raw));
        let mut forward = SharedConn::new(Box::new(forward_raw));

        let client_hello = encode_test_record(
            super::super::record::RECORD_TYPE_HANDSHAKE,
            [0x03, 0x03],
            &test_client_hello_fragment(),
        );
        client.write_all(&client_hello).await.expect("write client hello");
        assert_eq!(read_one_record(&mut forward).await, client_hello);

        let server_hello = encode_test_record(
            super::super::record::RECORD_TYPE_HANDSHAKE,
            [0x03, 0x03],
            &test_server_hello_fragment(),
        );
        forward.write_all(&server_hello).await.expect("write server hello");
        assert_eq!(read_one_record(&mut client).await, server_hello);

        let marker = encode_test_record(RECORD_TYPE_APPLICATION_DATA, [0x03, 0x03], &[0x99u8; 16]);
        client.write_all(&marker).await.expect("write readiness marker");
        assert_eq!(read_one_record(&mut forward).await, marker);

        let conn = new_hidden_conn(&ctx, mirror, vec![0u8; 32], false, Config::default()).expect("new_hidden_conn");
        (conn, client, forward, ctx)
    }

    /// The mirror's `record_writer` (see `mirror.rs`) processes `c2s_insert_tx` strictly in
    /// FIFO order, and `Conn::poll_flush` queues a barrier on that same queue: a barrier only
    /// means "everything queued before it has reached the wire" for the specific queue position
    /// it was sent at. If `poll_write` does not drop a stale, still-pending barrier before
    /// queuing a new write, a caller that polls flush, writes again, then polls flush a second
    /// time (exactly what `common::net::sing::relay_inner`'s `RelayDirection` does) gets back
    /// the first barrier's answer — which never accounted for the second write.
    #[tokio::test]
    async fn conn_poll_flush_waits_for_write_queued_after_a_pending_flush() {
        let gate = Arc::new(tokio::sync::Notify::new());
        let inserted_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hook: Arc<dyn MessageHook> = {
            let gate = Arc::clone(&gate);
            let inserted_calls = Arc::clone(&inserted_calls);
            Arc::new(FnHook(hrtb_hook(move |rec: &mut Record| {
                let gate = Arc::clone(&gate);
                let inserted_calls = Arc::clone(&inserted_calls);
                Box::pin(async move {
                    if rec.inserted {
                        let n = inserted_calls.fetch_add(1, Ordering::SeqCst);
                        if n == 1 {
                            gate.notified().await;
                        }
                    }
                    Ok(false)
                })
            })))
        };

        let (mut conn, _client, mut forward, _ctx) = setup_ready_c2s_conn(Some(hook)).await;

        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(Pin::new(&mut conn).poll_write(&mut cx, b"A"), Poll::Ready(Ok(1))));
        assert!(
            matches!(Pin::new(&mut conn).poll_flush(&mut cx), Poll::Pending),
            "first flush poll must be pending on the async ack"
        );
        assert!(matches!(Pin::new(&mut conn).poll_write(&mut cx, b"B"), Poll::Ready(Ok(1))));

        // `pipe()` is the synchronous in-memory pipe: `record_writer`'s write of A's record only
        // completes once a peer read rendezvous with it, so this also exercises that rendezvous
        // while proving the barrier itself stays pending.
        let (flushed, record_a) = tokio::join!(
            tokio::time::timeout(
                Duration::from_millis(200),
                std::future::poll_fn(|cx| Pin::new(&mut conn).poll_flush(cx)),
            ),
            read_one_record(&mut forward),
        );
        assert!(flushed.is_err(), "stale flush returned Ok(Ok(())) while write B was unwritten");
        assert!(!record_a.is_empty());

        let record_b_not_yet = tokio::time::timeout(Duration::from_millis(100), read_one_record(&mut forward)).await;
        assert!(record_b_not_yet.is_err(), "write B must not have reached the wire while its record hook is blocked");

        gate.notify_one();

        let (flushed, record_b) = tokio::join!(
            tokio::time::timeout(
                Duration::from_millis(2000),
                std::future::poll_fn(|cx| Pin::new(&mut conn).poll_flush(cx)),
            ),
            read_one_record(&mut forward),
        );
        flushed.expect("flush must complete once write B has been written").unwrap();
        assert!(!record_b.is_empty());
    }
}

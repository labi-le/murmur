//! The OpenVPN client: the control-channel handshake, key negotiation and the data-channel
//! pump.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::anyhow;
use arc_swap::ArcSwapOption;
use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{watch, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use murmur_common::errors::error_is;
use murmur_common::time::{duration_from_nanos, TimeDuration};

use super::config::{cipher_key_length, normalize_cipher, ClientConfig, COMP_LZO_YES, PROTO_UDP};
use super::control::{CancelContext, Cause, ContextError, ControlChannel, ControlConn};
use super::data::{self, DataChannel};
use super::keymethod::{
    derive_client_key_material, install_script_options_string, install_script_peer_info, new_client_key_method2_record,
    parse_server_key_method2_record_consumed, record_complete, KeyMethod2Record,
};
use super::lzo::{lzo1x_compress_safe, lzo1x_decompress_safe};
use super::mux::{ErrControlRetransmitStopped, PacketMux};
use super::packet::{new_session_id, parse_opcode_key_id, ControlCryptor, ControlPacket, KEY_ID_MASK};
use super::packetio::{is_packet_dropped, PacketIO};
use super::push::{new_push_reply, parse_push_reply_inner, PushReply, PUSH_REQUEST};

pub const CONTROL_RETRANSMIT_DELAY: Duration = Duration::from_secs(1);

pub(crate) const RENEGOTIATE_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) const TRANSITION_WINDOW: Duration = Duration::from_secs(3600);

pub(crate) const AUTH_DEFERRED_EXPIRE: Duration = Duration::from_secs(60);

pub(crate) const AUTH_PENDING_MAX_TIMEOUT: Duration = Duration::from_secs(30 * 60);

pub(crate) const TOKEN_PUSH_READ_TIMEOUT: Duration = Duration::from_millis(300);

pub(crate) const MAX_TLS_CONTROL_BUFFER: usize = 1 << 20;

static START: LazyLock<Instant> =
    LazyLock::new(|| Instant::now().checked_sub(Duration::from_secs(3600)).unwrap_or_else(Instant::now));

fn start() -> Instant {
    *START
}

/// Elapsed nanoseconds since `START`, which is anchored an hour before process start.
fn elapsed_nanos() -> i64 {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "elapsed nanoseconds since the start anchor stay far below i64::MAX"
    )]
    let nanos = start().elapsed().as_nanos() as i64;
    nanos
}

/// Wraps a cause: anyhow renders only the outermost message, so the cause is
/// folded into the text while staying reachable through `source()`.
#[derive(Debug)]
pub(crate) struct ContextErrorWithCause {
    message: String,
    source: anyhow::Error,
}

impl fmt::Display for ContextErrorWithCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ContextErrorWithCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let source: &(dyn std::error::Error + 'static) = self.source.as_ref();
        Some(source)
    }
}

pub(crate) fn wrap_error(context: &str, err: anyhow::Error) -> anyhow::Error {
    let message = format!("{context}: {err}");
    anyhow::Error::new(ContextErrorWithCause { message, source: err })
}

pub(crate) fn err_net_closed() -> io::Error {
    super::control::closed_error()
}

#[must_use]
pub fn is_err_net_closed(err: &anyhow::Error) -> bool {
    error_is::<super::control::ErrClosed>(err)
        || err.chain().any(|cause| match cause.downcast_ref::<io::Error>() {
            Some(err) => err.kind() == io::ErrorKind::NotConnected,
            None => false,
        })
}

pub(crate) fn is_context_deadline_exceeded(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(cause.downcast_ref::<ContextError>(), Some(ContextError::DeadlineExceeded))
            || cause.downcast_ref::<io::Error>().is_some_and(|err| err.kind() == io::ErrorKind::TimedOut)
            || cause.to_string() == "context deadline exceeded"
    })
}

fn cause_from_error(err: anyhow::Error) -> Cause {
    let boxed: Box<dyn std::error::Error + Send + Sync> = err.into();
    Cause::from_arc(Arc::from(boxed))
}

fn operation_context_error(ctx: &CancelContext, fallback: anyhow::Error) -> anyhow::Error {
    ctx.cause().map_or(fallback, anyhow::Error::new)
}

pub struct Client {
    config: Arc<ClientConfig>,
    mux: PacketMux,

    control: Arc<ControlChannel>,
    control_conn: SharedControlConn,
    /// The active TLS session, swapped on each rekey and read by the control path.
    tls_conn: ArcSwapOption<TlsConn>,
    /// Written and read only by the handshake/control task.
    state: Mutex<ControlState>,
    rekey_handshake_timeout: AtomicU64,
    data: RwLock<DataState>,

    run_ctx: CancelContext,

    write_sem: Arc<Semaphore>,

    last_send_nano: AtomicI64,
    last_receive_nano: AtomicI64,
    /// Written by the control task, read by the packet reader.
    rekey_error: ArcSwapOption<Cause>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

struct ControlState {
    control_established_at: Option<Instant>,
    leftover_tls: Vec<u8>,
    push_pending: Option<PushReply>,
    push_continuation_pending: bool,
    push: Option<PushReply>,
    auth_user: String,
    auth_pass: String,
    negotiated_cipher: String,
}

struct DataState {
    data: Option<Arc<DataChannel>>,
    outbound_key: Option<Arc<DataChannel>>,
    /// The zero instant starts in the past, so `None` means "expired".
    outbound_start: Option<Instant>,
    deferred_until: Option<Instant>,
    pending_deferred_until: Option<Instant>,
    pending_deferred_key_id: u8,
    pending_deferred_set: bool,
    retiring: Option<Arc<DataChannel>>,
    retiring_expiry: Option<Instant>,
    pending_retiring_expiry: Option<Instant>,
    pending_outbound_start: Option<Instant>,
    data_by_key: HashMap<u8, Arc<DataChannel>>,
    data_changed: watch::Sender<u64>,
}

impl DataState {
    fn new() -> Self {
        let (data_changed, _receiver) = watch::channel(0u64);
        Self {
            data: None,
            outbound_key: None,
            outbound_start: None,
            deferred_until: None,
            pending_deferred_until: None,
            pending_deferred_key_id: 0,
            pending_deferred_set: false,
            retiring: None,
            retiring_expiry: None,
            pending_retiring_expiry: None,
            pending_outbound_start: None,
            data_by_key: HashMap::new(),
            data_changed,
        }
    }
}

/// the locked epoch selection in `write_data_packet`, resolved before any await.
enum EpochSelection {
    /// Ordinary data writes pause until `install_data_channel` publishes a usable epoch.
    Pause(watch::Receiver<u64>),
    Write {
        outbound: Arc<DataChannel>,
        need_promote: bool,
    },
}

/// the locked revalidation and encryption in `write_data_packet`, resolved before any await.
enum EpochEncryption {
    /// The selected epoch was retired between selection and encryption.
    Reselect,
    /// Pauses ordinary data writes until `install_data_channel` publishes a usable epoch.
    Pause(watch::Receiver<u64>),
    /// The packet encrypted while the epoch lock was held.
    Packet(Vec<u8>),
}

impl Client {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the public constructor gives the client its own config handle, and callers pass a fresh Arc"
    )]
    pub fn new(config: Arc<ClientConfig>, io: Arc<dyn PacketIO>) -> anyhow::Result<Arc<Self>> {
        let crypt: Option<Arc<dyn ControlCryptor>> =
            if !config.tls_crypt_v2_key.is_empty() || !config.tls_crypt_v2_wrapped_key.is_empty() {
                Some(Arc::new(super::tlscrypt_v2::new_tls_crypt_v2(
                    &config.tls_crypt_v2_key,
                    &config.tls_crypt_v2_wrapped_key,
                )?))
            } else if !config.tls_crypt_key.is_empty() {
                Some(Arc::new(super::tlscrypt::new_tls_crypt(&config.tls_crypt_key, true)?))
            } else if !config.tls_auth_key.is_empty() {
                Some(Arc::new(super::tlsauth::new_tls_auth(&config.tls_auth_key, &config.key_direction, &config.auth)?))
            } else {
                None
            };
        let local = new_session_id()?;
        let run_ctx = CancelContext::background();
        let mux = PacketMux::new(io);
        tokio::spawn({
            let mux = mux.clone();
            async move { mux.run().await }
        });
        let control = Arc::new(ControlChannel::new(Arc::new(mux.clone()), crypt, local));
        let control_conn = SharedControlConn::new(ControlConn::new(Arc::clone(&control)));
        let client = Arc::new(Self {
            config: Arc::clone(&config),
            mux,
            control,
            control_conn,
            tls_conn: ArcSwapOption::default(),
            state: Mutex::new(ControlState {
                control_established_at: None,
                leftover_tls: Vec::new(),
                push_pending: None,
                push_continuation_pending: false,
                push: None,
                auth_user: config.username.trim().to_owned(),
                auth_pass: config.password.clone(),
                negotiated_cipher: String::new(),
            }),
            #[expect(
                clippy::cast_possible_truncation,
                reason = "RENEGOTIATE_TIMEOUT is 30s, so its nanosecond count fits in u64"
            )]
            rekey_handshake_timeout: AtomicU64::new(RENEGOTIATE_TIMEOUT.as_nanos() as u64),
            data: RwLock::new(DataState::new()),
            run_ctx,
            write_sem: Arc::new(Semaphore::new(1)),
            last_send_nano: AtomicI64::new(0),
            last_receive_nano: AtomicI64::new(0),
            rekey_error: ArcSwapOption::default(),
        });
        client.mark_send();
        client.mark_receive();
        tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.flush_control_acks().await }
        });
        Ok(client)
    }

    // cancel-safe: the loop only waits on the ACK wake and the run context, so a dropped wait re-arms on
    // the next ACK.
    async fn flush_control_acks(self: &Arc<Self>) {
        loop {
            tokio::select! {
                () = self.control.wait_ack_wake() => {
                    while self.control.pending_acks() > 0 {
                        if let Err(err) = self.control.send_ack(&self.run_ctx).await {
                            if !self.run_ctx.is_done() {
                                self.fail_control(wrap_error("send openvpn control ACK", err));
                            }
                            return;
                        }
                    }
                }
                () = self.run_ctx.done() => return,
            }
        }
    }

    pub async fn handshake(self: &Arc<Self>, ctx: &CancellationToken) -> anyhow::Result<PushReply> {
        let caller_ctx = CancelContext::from_token(ctx.clone());
        self.control.send_reset(&caller_ctx).await.map_err(|err| wrap_error("send hard reset", err))?;
        self.wait_server_reset(&caller_ctx).await?;
        let handshake_ctx = caller_ctx.with_cancel_cause();
        let mut interrupt: Option<InterruptGuard> = None;
        let mut retransmit = if self.config.proto == PROTO_UDP {
            Some(self.retransmit_control(&handshake_ctx, Some(handshake_ctx.clone())))
        } else {
            None
        };
        let outcome = async {
            interrupt = Some(
                self.start_tls_epoch(&handshake_ctx)
                    .await
                    .map_err(|err| operation_context_error(&handshake_ctx, err))?,
            );
            let push = self
                .do_key_exchange(&handshake_ctx)
                .await
                .map_err(|err| operation_context_error(&handshake_ctx, err))?;
            if let Some(stop) = retransmit.as_mut() {
                stop.stop();
            }
            retransmit = None;
            if let Some(guard) = interrupt.as_mut() {
                guard.interrupt().await;
            }
            interrupt = None;
            self.control_operation_error(&handshake_ctx)?;
            let _ = self.control_conn.set_deadline(None);
            let client = Arc::clone(self);
            tokio::spawn(async move { client.watch_control().await });
            Ok(push)
        }
        .await;
        if let Some(stop) = retransmit.as_mut() {
            stop.stop();
        }
        if let Some(guard) = interrupt.as_mut() {
            guard.interrupt().await;
        }
        handshake_ctx.cancel(None);
        outcome
    }

    fn tls_config(&self) -> anyhow::Result<Arc<rustls::ClientConfig>> {
        tls_config(&self.config)
    }

    async fn start_tls_epoch(&self, ctx: &CancelContext) -> anyhow::Result<InterruptGuard> {
        let tls_config = self.tls_config()?;
        if self.tls_conn.load_full().is_some() {
            // Drop the old epoch without writing close_notify, which would go out on the new
            // control epoch.
            self.tls_conn.store(None);
        }
        self.control_conn.reset();
        {
            let mut state = self.state.lock();
            state.control_established_at = None;
            state.leftover_tls = Vec::new();
        }
        let mut interrupt = interrupt_control_conn_on_done(ctx, self.control_conn.clone());
        let conn = match TlsConn::connect(self.control_conn.clone(), tls_config).await {
            Ok(conn) => conn,
            Err(err) => {
                interrupt.interrupt().await;
                return Err(wrap_error("openvpn tls handshake", err.into()));
            }
        };
        self.tls_conn.store(Some(Arc::new(conn)));
        // Control packets that arrived on the new epoch while the handshake was reading must stay
        // reachable through the active TLS session.
        self.consume_queued_control();
        Ok(interrupt)
    }

    fn consume_queued_control(&self) {
        for pkt in self.control.read_all() {
            if pkt.opcode != super::packet::P_CONTROL_V1 || pkt.payload.is_empty() {
                continue;
            }
            self.control_conn.unsafe_feed(&pkt.payload);
        }
    }

    async fn do_key_exchange(self: &Arc<Self>, ctx: &CancelContext) -> anyhow::Result<PushReply> {
        let primary_cipher = self
            .config
            .data_ciphers
            .first()
            .map_or_else(|| self.config.cipher.clone(), |cipher| normalize_cipher(cipher));
        let (auth_user, auth_pass) = {
            let state = self.state.lock();
            (state.auth_user.clone(), state.auth_pass.clone())
        };
        let client_record = new_client_key_method2_record(
            &install_script_options_string(
                &self.config.proto,
                &primary_cipher,
                &self.config.auth,
                &self.config.comp_lzo,
            ),
            &install_script_peer_info(
                &primary_cipher,
                &self.config.data_ciphers,
                &self.config.comp_lzo,
                &self.config.peer_info,
            ),
            &auth_user,
            &auth_pass,
        )?;
        let client_bytes = client_record.marshal_client()?;
        self.tls_write(&client_bytes).await.map_err(|err| wrap_error("write key method 2 client record", err))?;
        let server_record = self.read_server_key_method(ctx).await?;

        // Keys are derived at the maximum cipher key length and sliced once the push reply
        // settles the cipher.
        let mut sources = client_record.sources;
        sources.server = server_record.sources.server;
        let mut keys =
            derive_client_key_material(sources, self.control.local_session_id(), self.control.remote_session_id(), 32)
                .map_err(|err| wrap_error("derive data channel keys", err))?;
        self.state.lock().control_established_at = Some(Instant::now());

        if self.state.lock().push.is_some() {
            self.consume_rekey_push().await.map_err(|err| wrap_error("consume rekey push", err))?;
            let push = self.state.lock().push.clone().unwrap_or_default();
            let negotiated_cipher = self
                .config
                .negotiate_cipher(&push.data_ciphers, &push.cipher)
                .map_err(|err| wrap_error("negotiate data cipher", err))?;
            self.state.lock().negotiated_cipher.clone_from(&negotiated_cipher);
            let key_len = cipher_key_length(&negotiated_cipher);
            keys.send_cipher_key.truncate(key_len);
            keys.recv_cipher_key.truncate(key_len);
            let key_id = self.control.key_id();
            let new_data = DataChannel::new(&keys, &negotiated_cipher, &self.config.auth, push.peer_id, key_id)?;
            self.install_data_channel(Arc::new(new_data));
            self.mark_send();
            self.mark_receive();
            return Ok(push);
        }

        self.tls_write(format!("{PUSH_REQUEST}\x00").as_bytes())
            .await
            .map_err(|err| wrap_error("write push request", err))?;
        let reply = self.read_push_reply(ctx).await?;
        let push = merge_push_reply(self.state.lock().push.clone(), Some(reply)).unwrap_or_default();
        if push.prefixes.is_empty() {
            return Err(anyhow!("openvpn push reply missing ifconfig address"));
        }
        self.state.lock().push = Some(push.clone());

        let negotiated_cipher = self
            .config
            .negotiate_cipher(&push.data_ciphers, &push.cipher)
            .map_err(|err| wrap_error("negotiate data cipher", err))?;
        self.state.lock().negotiated_cipher.clone_from(&negotiated_cipher);

        let key_len = cipher_key_length(&negotiated_cipher);
        keys.send_cipher_key.truncate(key_len);
        keys.recv_cipher_key.truncate(key_len);

        let key_id = self.control.key_id();
        let new_data = DataChannel::new(&keys, &negotiated_cipher, &self.config.auth, push.peer_id, key_id)?;
        self.install_data_channel(Arc::new(new_data));
        self.capture_auth_token(&push);
        self.mark_send();
        self.mark_receive();
        Ok(push)
    }

    async fn tls_write(&self, data: &[u8]) -> anyhow::Result<()> {
        let conn = self.tls_conn.load_full().ok_or_else(|| anyhow!("openvpn tls connection is not established"))?;
        conn.write_all(data).await?;
        Ok(())
    }

    async fn consume_rekey_push(&self) -> anyhow::Result<()> {
        let conn = self.tls_conn.load_full();
        let conn: Option<&dyn PushReadConn> = match &conn {
            Some(conn) => Some(&**conn),
            None => None,
        };
        self.consume_rekey_push_from(conn, &ReadTokenPushReply).await
    }

    async fn consume_rekey_push_from(
        &self,
        conn: Option<&dyn PushReadConn>,
        read_final: &dyn TokenPushReader,
    ) -> anyhow::Result<()> {
        let outcome = self.consume_rekey_push_inner(conn, read_final).await;
        let _ = self.control_conn.set_deadline(None);
        outcome
    }

    // cancel-safe: every shared field it touches is read or written under a short-lived lock, and the
    // timeouts only bound the reads they wrap.
    async fn consume_rekey_push_inner(
        &self,
        conn: Option<&dyn PushReadConn>,
        read_final: &dyn TokenPushReader,
    ) -> anyhow::Result<()> {
        let base =
            self.state.lock().push.clone().ok_or_else(|| anyhow!("openvpn rekey push without a cached push reply"))?;
        let rekey = new_push_reply(String::new(), base.peer_id, false);
        let mut push = merge_push_reply(Some(base), Some(rekey)).unwrap_or_default();
        let mut complete = false;
        let mut attempted_final_read = false;

        // Terminal control messages have priority over coalesced push data.
        {
            let state = self.state.lock();
            control_message_error(&state.leftover_tls)?;
        }

        let (reply, ok) = {
            let mut state = self.state.lock();
            let (reply, rest, ok) = take_push_reply(&state.leftover_tls);
            state.leftover_tls = rest;
            drop(state);
            (reply, ok)
        };
        if let Some(reply) = reply {
            let pending = self.state.lock().push_pending.take();
            let mut merged = merge_push_reply(pending, Some(reply)).unwrap_or_default();
            self.apply_auth_pending_timeout(&mut merged);
            if merged.push_continuation == 2 {
                self.state.lock().push_continuation_pending = true;
            }
            self.state.lock().push_pending = Some(merged);
        }
        if ok {
            complete = true;
            self.state.lock().push_continuation_pending = false;
        }
        {
            let state = self.state.lock();
            control_message_error(&state.leftover_tls)?;
        }

        if !complete && conn.is_some() {
            attempted_final_read = true;
            let continuation_limit = self.rekey_wait_deadline(Instant::now());
            let deadline = if self.state.lock().push_continuation_pending { Some(continuation_limit) } else { None };
            let leftover = self.state.lock().leftover_tls.clone();
            let established = self.state.lock().control_established_at;
            let extended = [deadline, established, Some(continuation_limit)];
            let (more, new_rest) = read_final.read_final(read_conn(conn)?, &leftover, &extended).await?;
            self.state.lock().leftover_tls = new_rest;
            if let Some(more) = more {
                let pending = self.state.lock().push_pending.take();
                let mut merged = merge_push_reply(pending, Some(more)).unwrap_or_default();
                self.apply_auth_pending_timeout(&mut merged);
                complete = merged.has_push_reply && merged.push_continuation != 2;
                if merged.has_push_reply {
                    self.state.lock().push_continuation_pending = merged.push_continuation == 2;
                }
                self.state.lock().push_pending = Some(merged);
            }
        }

        if attempted_final_read && self.state.lock().push_continuation_pending {
            return Err(anyhow!("openvpn continued push reply incomplete"));
        }
        {
            let mut state = self.state.lock();
            // A standalone AUTH_PENDING is metadata, not the first half of a push, so an
            // unfinished accumulator is discarded while the cached push is kept.
            if !complete && state.push_pending.as_ref().is_some_and(|pending| !pending.has_push_reply) {
                state.push_pending = None;
            }
        }
        if complete {
            let pending = self.state.lock().push_pending.take();
            if pending.is_some() {
                push = merge_push_reply(Some(push), pending).unwrap_or_default();
            }
        }
        self.state.lock().push = Some(push.clone());
        self.capture_auth_token(&push);
        Ok(())
    }

    async fn consume_parked_rekey_push(&self) -> anyhow::Result<()> {
        self.consume_queued_control();
        if self.state.lock().push.is_some() {
            return self.consume_rekey_push().await;
        }
        let _ = self.control_conn.set_deadline(None);
        Ok(())
    }

    fn apply_auth_pending_timeout(&self, reply: &mut PushReply) {
        if !push_has_auth_pending(Some(reply)) {
            return;
        }
        let established = self.state.lock().control_established_at;
        anchor_auth_pending_deadline(reply, established);
        let deadline = reply.auth_pending_until;
        let key_id = self.control.key_id();
        {
            let mut state = self.data.write();
            // AUTH_PENDING replaces the timeout of this authentication session, shorter deadlines
            // included.
            if state.data.as_ref().is_some_and(|data| data.key_id == key_id) {
                state.deferred_until = deadline;
            } else {
                state.pending_deferred_key_id = key_id;
                state.pending_deferred_until = deadline;
                state.pending_deferred_set = true;
            }
        }
        let _ = self.control_conn.set_deadline(deadline);
    }

    fn auth_pending_deadline(&self) -> Option<Instant> {
        let key_id = self.control.key_id();
        let state = self.data.read();
        let deferred = state.deferred_until;
        let data_matches = state.data.as_ref().is_some_and(|data| data.key_id == key_id);
        let pending = state.pending_deferred_until;
        let pending_matches = state.pending_deferred_set && state.pending_deferred_key_id == key_id;
        drop(state);
        if pending_matches {
            return pending;
        }
        if data_matches && deferred.is_some() {
            return deferred;
        }
        None
    }

    fn transition_window(&self) -> Duration {
        if self.config.transition_window_set || self.config.transition_window > 0 {
            duration_from_nanos(self.config.transition_window)
        } else {
            TRANSITION_WINDOW
        }
    }

    fn retiring_window_deadline(&self, reset: Option<&ControlPacket>) -> Instant {
        let accepted_at = reset.and_then(|reset| reset.received_at).unwrap_or_else(Instant::now);
        accepted_at + self.transition_window()
    }

    fn stage_retiring_window(&self, deadline: Option<Instant>) {
        let Some(deadline) = deadline else {
            return;
        };
        let mut state = self.data.write();
        state.pending_retiring_expiry = Some(deadline);
        state.pending_outbound_start = Some(retiring_outbound_start(deadline, self.transition_window()));
    }

    fn signal_data_changed_locked(state: &DataState) {
        state.data_changed.send_modify(|version| *version = version.wrapping_add(1));
    }

    /// The outbound key deliberately stays on the previous epoch until the peer proves it has
    /// activated the new one, mirroring `OpenVPN`'s deferred auth key selection.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the write guard is held for every field swap and the change signal, so no earlier drop exists"
    )]
    fn install_data_channel(&self, new_data: Arc<DataChannel>) {
        let mut state = self.data.write();
        let new_key_id = new_data.key_id;
        let old = state.data.take();
        state.retiring.clone_from(&old);
        state.data = Some(Arc::clone(&new_data));
        state.outbound_key = Some(match &old {
            Some(old) => Arc::clone(old),
            None => Arc::clone(&new_data),
        });
        state.outbound_start = Some(Instant::now());
        if old.is_some() {
            if let Some(pending) = state.pending_outbound_start.take() {
                state.outbound_start = Some(pending);
            }
        }
        state.pending_outbound_start = None;
        state.deferred_until = None;
        if state.pending_deferred_set && state.pending_deferred_key_id == new_key_id {
            state.deferred_until = state.pending_deferred_until;
        }
        state.pending_deferred_until = None;
        state.pending_deferred_key_id = 0;
        state.pending_deferred_set = false;
        if let Some(old) = &old {
            if old.key_id != new_key_id {
                state.data_by_key.insert(old.key_id, Arc::clone(old));
            }
        }
        state.data_by_key.insert(new_key_id, new_data);
        if let Some(_old) = &old {
            match state.pending_retiring_expiry.take() {
                Some(pending) => state.retiring_expiry = Some(pending),
                None => state.retiring_expiry = Some(Instant::now() + self.transition_window()),
            }
        } else {
            state.retiring_expiry = None;
        }
        state.pending_retiring_expiry = None;
        let old_key_id = old.as_ref().map(|old| old.key_id);
        state.data_by_key.retain(|id, _| *id == new_key_id || Some(*id) == old_key_id);
        Self::signal_data_changed_locked(&state);
    }

    fn capture_auth_token(&self, push: &PushReply) {
        let Some((user, pass)) = push.auth_token() else {
            return;
        };
        let mut state = self.state.lock();
        if !user.is_empty() {
            state.auth_user = user;
        }
        state.auth_pass = pass;
    }

    pub async fn write_ip_packet(&self, ctx: &CancellationToken, packet: &[u8]) -> anyhow::Result<()> {
        self.write_data_packet(ctx, packet, true).await
    }

    pub async fn write_ping(&self, ctx: &CancellationToken) -> anyhow::Result<()> {
        self.write_data_packet(ctx, &data::OPEN_VPN_PING_PACKET, false).await
    }

    /// the pause select, lifted out of `write_data_packet` so no guard is held across its await.
    // cancel-safe: it holds no guard across the select, which is why it is lifted out of the write path.
    async fn wait_epoch_change(
        &self,
        ctx: &CancellationToken,
        changed: &mut watch::Receiver<u64>,
    ) -> anyhow::Result<()> {
        tokio::select! {
            _ = changed.changed() => Ok(()),
            () = ctx.cancelled() => Err(ContextError::Canceled.into()),
            () = self.run_ctx.done() => Err(err_net_closed().into()),
        }
    }

    // cancel-safe: the semaphore permit is taken only by the arm that resolves, and a dropped write
    // releases it with the future.
    async fn write_data_packet(&self, ctx: &CancellationToken, packet: &[u8], compress: bool) -> anyhow::Result<()> {
        let data_ctx = CancelContext::from_token(ctx.clone());
        let _permit = tokio::select! {
            permit = self.write_sem.acquire() => permit.map_err(|_| anyhow!("openvpn write semaphore is closed"))?,
            () = ctx.cancelled() => return Err(ContextError::Canceled.into()),
        };
        let compressed;
        let packet: &[u8] = if compress && self.config.comp_lzo == COMP_LZO_YES {
            compressed = lzo1x_compress_safe(packet)?;
            &compressed
        } else {
            packet
        };

        loop {
            // Select under the state lock, upgrading only when promotion is due.
            let selection = {
                let state = self.data.read();
                let Some(data) = state.data.clone() else {
                    return Err(anyhow!("openvpn data channel is not ready"));
                };
                if state.pending_retiring_expiry.is_some_and(|deadline| Instant::now() > deadline) {
                    EpochSelection::Pause(state.data_changed.subscribe())
                } else {
                    let outbound = state.outbound_key.clone().unwrap_or_else(|| Arc::clone(&data));
                    let need_promote = !Arc::ptr_eq(&outbound, &data)
                        && (data.peer_active() || selection_expired(&state) || retiring_expired(&state));
                    drop(state);
                    EpochSelection::Write { outbound, need_promote }
                }
            };
            let (outbound, need_promote) = match selection {
                EpochSelection::Pause(mut changed) => {
                    // Fail closed without tearing down the tunnel: ordinary data writes pause until
                    // install_data_channel publishes the new usable epoch.
                    self.wait_epoch_change(ctx, &mut changed).await?;
                    continue;
                }
                EpochSelection::Write { outbound, need_promote } => (outbound, need_promote),
            };
            if need_promote {
                let mut state = self.data.write();
                let current = state.data.clone().ok_or_else(|| anyhow!("openvpn data channel is not ready"))?;
                if !state.outbound_key.as_ref().is_some_and(|key| Arc::ptr_eq(key, &current))
                    && state.outbound_key.is_some()
                    && (current.peer_active() || selection_expired(&state) || retiring_expired(&state))
                {
                    state.outbound_key = Some(current);
                    state.outbound_start = Some(Instant::now());
                }
                drop(state);
                continue;
            }

            // Revalidate the selection, then keep the lock through encryption so
            // install_data_channel cannot retire this epoch while crypto is in flight.
            let encryption = {
                let state = self.data.read();
                let encryption = if state.pending_retiring_expiry.is_some_and(|deadline| Instant::now() > deadline) {
                    EpochEncryption::Pause(state.data_changed.subscribe())
                } else {
                    let data_now = state.data.as_ref().ok_or_else(|| anyhow!("openvpn data channel is not ready"))?;
                    let valid =
                        state.data_by_key.get(&outbound.key_id).is_some_and(|entry| Arc::ptr_eq(entry, &outbound))
                            && (Arc::ptr_eq(&outbound, data_now)
                                || opt_ptr_eq(Some(&outbound), state.retiring.as_ref())
                                || opt_ptr_eq(Some(&outbound), state.outbound_key.as_ref()));
                    #[expect(
                        clippy::if_same_then_else,
                        reason = "both arms reselect the epoch, mirroring the two separate continue checks in writeDataPacket"
                    )]
                    if !valid {
                        EpochEncryption::Reselect
                    } else if !Arc::ptr_eq(&outbound, data_now)
                        && (data_now.peer_active() || selection_expired(&state) || retiring_expired(&state))
                    {
                        EpochEncryption::Reselect
                    } else {
                        EpochEncryption::Packet(outbound.encrypt(packet)?)
                    }
                };
                drop(state);
                encryption
            };
            let encrypted = match encryption {
                EpochEncryption::Reselect => continue,
                EpochEncryption::Pause(mut changed) => {
                    self.wait_epoch_change(ctx, &mut changed).await?;
                    continue;
                }
                EpochEncryption::Packet(encrypted) => encrypted,
            };
            // The packet is an in-flight datagram now: release state before transport I/O so a
            // blocked socket cannot stall a concurrent rekey install.
            match self.mux.write_data_packet(&data_ctx, &encrypted).await {
                Ok(()) => {
                    self.mark_send();
                    return Ok(());
                }
                Err(err) => {
                    if is_packet_dropped(&err) {
                        return Ok(());
                    }
                    return Err(err);
                }
            }
        }
    }

    pub fn last_rekey_error(&self) -> Option<anyhow::Error> {
        self.rekey_error.load_full().map(|cause| anyhow::Error::new((*cause).clone()))
    }

    pub async fn read_ip_packet(&self, ctx: &CancellationToken) -> anyhow::Result<Vec<u8>> {
        let data_ctx = CancelContext::from_token(ctx.clone());
        loop {
            let packet = match self.mux.read_data_packet(&data_ctx).await {
                Ok(packet) => packet,
                Err(err) => {
                    // Only surface the rekey failure while the transport is being torn down.
                    if is_err_net_closed(&err) {
                        if let Some(rekey_err) = self.last_rekey_error() {
                            return Err(anyhow!("{err}: {rekey_err}"));
                        }
                    }
                    return Err(err);
                }
            };
            let Ok(plain) = self.decrypt_data_packet(&packet) else {
                continue;
            };
            self.mark_receive();
            if data::is_ping_packet(&plain) {
                continue;
            }
            if self.config.comp_lzo == COMP_LZO_YES && !plain.is_empty() {
                return lzo1x_decompress_safe(&plain);
            }
            return Ok(plain);
        }
    }

    fn decrypt_data_packet(&self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        let Some(&first) = packet.first() else {
            return Err(anyhow!("empty openvpn data packet"));
        };
        let (_, key_id) = parse_opcode_key_id(first);
        let state = self.data.read();
        if state.pending_retiring_expiry.is_some_and(|deadline| Instant::now() > deadline) {
            return Err(anyhow!("openvpn data packet after retiring deadline while rekey is in progress"));
        }
        // The retiring epoch is rejected once the transition window elapsed even though it still
        // has a data_by_key entry.
        if state.retiring.as_ref().is_some_and(|retiring| retiring.key_id == key_id)
            && state.retiring_expiry.is_some_and(|deadline| Instant::now() > deadline)
        {
            return Err(anyhow!("openvpn data packet from expired retiring epoch"));
        }
        // Route strictly by key ID: the CBC HMAC excludes the opcode/key-ID header, so decrypting
        // with the wrong key would still authenticate.
        let Some(entry) = state.data_by_key.get(&key_id).cloned() else {
            return Err(anyhow!("openvpn data packet with unknown key id"));
        };
        let is_newest = state.data.as_ref().is_some_and(|data| Arc::ptr_eq(data, &entry));
        let plain = entry.decrypt(packet);
        drop(state);
        let plain = plain?;
        if is_newest {
            entry.mark_peer_active();
        }
        Ok(plain)
    }

    pub fn since_send(&self) -> TimeDuration {
        elapsed_nanos() - self.last_send_nano.load(Ordering::SeqCst)
    }

    pub fn since_receive(&self) -> TimeDuration {
        elapsed_nanos() - self.last_receive_nano.load(Ordering::SeqCst)
    }

    fn mark_send(&self) {
        self.last_send_nano.store(elapsed_nanos(), Ordering::SeqCst);
    }

    fn mark_receive(&self) {
        self.last_receive_nano.store(elapsed_nanos(), Ordering::SeqCst);
    }
}

/// The retiring window start: `deadline - window`, or the deadline itself when that would
/// underflow, which is the only comparison made against this bound.
fn retiring_outbound_start(deadline: Instant, window: Duration) -> Instant {
    deadline.checked_sub(window).unwrap_or(deadline)
}

fn opt_ptr_eq(a: Option<&Arc<DataChannel>>, b: Option<&Arc<DataChannel>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

fn selection_expired(state: &DataState) -> bool {
    state.outbound_start.is_none_or(|start| Instant::now() > start + AUTH_DEFERRED_EXPIRE)
}

fn retiring_expired(state: &DataState) -> bool {
    state.retiring.is_some()
        && opt_ptr_eq(state.outbound_key.as_ref(), state.retiring.as_ref())
        && state.retiring_expiry.is_some_and(|deadline| Instant::now() > deadline)
}

impl Client {
    async fn watch_control(self: &Arc<Self>) {
        loop {
            let packet = match self.control.wait_for_soft_reset(&self.run_ctx).await {
                Ok(packet) => packet,
                Err(err) => {
                    if self.run_ctx.is_done() {
                        return;
                    }
                    if super::control::is_parked_tls(&err) {
                        // A same-epoch payload was parked: consume it now so a deferred
                        // authentication failure surfaces instead of waiting for a soft reset that
                        // may never come.
                        if let Err(consume_err) = self.consume_parked_rekey_push().await {
                            if !self.run_ctx.is_done() {
                                self.fail_control(wrap_error("consume parked rekey push", consume_err));
                            }
                            return;
                        }
                        continue;
                    }
                    self.fail_control(wrap_error("wait for soft reset", err));
                    return;
                }
            };
            // The retiring key lifetime starts when the soft reset is accepted, before the token
            // probe may consume its timeout.
            let retiring_expiry = self.retiring_window_deadline(Some(&packet));
            self.stage_retiring_window(Some(retiring_expiry));
            self.consume_queued_control();
            if self.state.lock().push.is_some() {
                if let Err(err) = self.consume_rekey_push().await {
                    if !self.run_ctx.is_done() {
                        self.fail_control(wrap_error("consume queued rekey push", err));
                    }
                    return;
                }
            }
            if let Err(err) = self.renegotiate(Some(&packet), Some(retiring_expiry)).await {
                if !self.run_ctx.is_done() {
                    // A soft reset already advanced the reliable control epoch, so rolling back is
                    // not safe: keep carrying data on the retiring key until the advertised
                    // deadlines, then fail closed.
                    self.fail_control(wrap_error("renegotiate", err));
                }
                return;
            }
        }
    }

    fn fail_control(&self, err: anyhow::Error) {
        self.rekey_error.compare_and_swap(&None::<Arc<Cause>>, Some(Arc::new(cause_from_error(err))));
        self.run_ctx.cancel(None);
        let _ = self.mux.close();
    }

    async fn renegotiate(
        self: &Arc<Self>,
        server_reset: Option<&ControlPacket>,
        retiring_expiry: Option<Instant>,
    ) -> anyhow::Result<()> {
        let reneg_ctx = self.run_ctx.with_cancel_cause();
        let mut interrupt: Option<InterruptGuard> = None;
        let mut retransmit: Option<RetransmitStop> = None;
        let _ = self.control_conn.set_deadline(Some(Instant::now() + self.rekey_timeout()));

        if let Some(retiring_expiry) = retiring_expiry {
            let mut state = self.data.write();
            state.pending_retiring_expiry = Some(retiring_expiry);
            state.pending_outbound_start = Some(retiring_outbound_start(retiring_expiry, self.transition_window()));
        }

        let key_id = if let Some(reset) = server_reset {
            reset.key_id & KEY_ID_MASK
        } else {
            super::control::next_key_id(self.control.key_id())
        };
        // Adopt before sending so the ACK lands on the new epoch; adopt_key_id clears the ACKs.
        self.control.adopt_key_id(key_id);
        if let Some(reset) = server_reset {
            self.control.mark_received(reset.message_id);
            self.control.queue_ack(reset.message_id);
        }

        let outcome = async {
            self.control.send_soft_reset(&reneg_ctx).await.map_err(|err| wrap_error("send soft reset", err))?;
            if self.config.proto == PROTO_UDP {
                retransmit = Some(self.retransmit_control(&reneg_ctx, Some(reneg_ctx.clone())));
            }
            interrupt = Some(
                self.start_tls_epoch(&reneg_ctx)
                    .await
                    .map_err(|err| operation_context_error(&reneg_ctx, wrap_error("tls epoch handshake", err)))?,
            );
            self.do_key_exchange(&reneg_ctx)
                .await
                .map_err(|err| operation_context_error(&reneg_ctx, wrap_error("rekey exchange", err)))?;
            if let Some(stop) = retransmit.as_mut() {
                stop.stop();
            }
            retransmit = None;
            if let Some(guard) = interrupt.as_mut() {
                guard.interrupt().await;
            }
            interrupt = None;
            self.control_operation_error(&reneg_ctx)
        }
        .await;
        if let Some(stop) = retransmit.as_mut() {
            stop.stop();
        }
        if let Some(guard) = interrupt.as_mut() {
            guard.interrupt().await;
        }
        let _ = self.control_conn.set_deadline(None);
        reneg_ctx.cancel(None);
        outcome
    }

    fn control_operation_error(&self, ctx: &CancelContext) -> anyhow::Result<()> {
        if let Some(cause) = ctx.cause() {
            return Err(anyhow::Error::new(cause));
        }
        if let Some(err) = self.mux.current_error() {
            return Err(wrap_error("openvpn transport terminated", err));
        }
        Ok(())
    }

    fn retransmit_control(self: &Arc<Self>, ctx: &CancelContext, fail: Option<CancelContext>) -> RetransmitStop {
        let loop_ctx = ctx.with_cancel_cause();
        let stop_ctx = loop_ctx.clone();
        let client = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval_at(Instant::now() + CONTROL_RETRANSMIT_DELAY, CONTROL_RETRANSMIT_DELAY);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(err) = client.control.retransmit_pending(&loop_ctx).await {
                            if loop_ctx.is_done() {
                                if loop_ctx
                                    .cause()
                                    .is_some_and(|cause| cause.is::<ErrControlRetransmitStopped>())
                                {
                                    if let Some(transport_err) = client.mux.current_error() {
                                        if let Some(fail) = &fail {
                                            fail.cancel(Some(cause_from_error(wrap_error(
                                                "retransmit openvpn control packet",
                                                transport_err,
                                            ))));
                                        }
                                    }
                                }
                                return;
                            }
                            if let Some(fail) = &fail {
                                fail.cancel(Some(cause_from_error(
                                    wrap_error("retransmit openvpn control packet", err),
                                )));
                            }
                            return;
                        }
                    }
                    () = loop_ctx.done() => return,
                }
            }
        });
        RetransmitStop::new(move || stop_ctx.cancel(Some(Cause::from_error(ErrControlRetransmitStopped))))
    }

    fn rekey_timeout(&self) -> Duration {
        let nanos = self.rekey_handshake_timeout.load(Ordering::Relaxed);
        if nanos != 0 {
            Duration::from_nanos(nanos)
        } else {
            RENEGOTIATE_TIMEOUT
        }
    }

    #[cfg(test)]
    pub(crate) fn set_rekey_handshake_timeout_for_test(&self, d: Duration) {
        self.rekey_handshake_timeout.store(d.as_nanos() as u64, Ordering::Relaxed);
    }

    fn rekey_wait_deadline(&self, now: Instant) -> Instant {
        let mut deadline = now + self.rekey_timeout();
        let retiring_expiry = self.data.read().pending_retiring_expiry;
        if let Some(retiring_expiry) = retiring_expiry {
            if retiring_expiry > deadline {
                deadline = retiring_expiry;
            }
        }
        deadline
    }

    #[expect(clippy::unused_async, reason = "callers await every client lifecycle method, so close stays async")]
    pub async fn close(&self) -> anyhow::Result<()> {
        self.run_ctx.cancel(None);
        self.mux.close()
    }

    async fn wait_server_reset(&self, ctx: &CancelContext) -> anyhow::Result<()> {
        let mut retransmits = 0u32;
        loop {
            let read_ctx = if self.config.proto == PROTO_UDP {
                ctx.with_deadline(Instant::now() + CONTROL_RETRANSMIT_DELAY)
            } else {
                ctx.clone()
            };
            let result = self.control.read(&read_ctx).await;
            if self.config.proto == PROTO_UDP {
                read_ctx.cancel(None);
            }
            let packet = match result {
                Ok(packet) => packet,
                Err(err) => {
                    if self.config.proto == PROTO_UDP && is_context_deadline_exceeded(&err) && !ctx.is_done() {
                        self.control
                            .retransmit_pending(ctx)
                            .await
                            .map_err(|err| wrap_error("retransmit hard reset", err))?;
                        retransmits += 1;
                        continue;
                    }
                    return Err(anyhow!("read hard reset response after {retransmits} retransmits: {err}"));
                }
            };
            match packet.opcode {
                super::packet::P_CONTROL_HARD_RESET_SERVER_V2 => return Ok(()),
                super::packet::P_CONTROL_HARD_RESET_SERVER_V1 => {
                    return Err(anyhow!("openvpn server replied with unsupported key method 1 reset"));
                }
                _ => {}
            }
        }
    }

    async fn read_server_key_method(&self, ctx: &CancelContext) -> anyhow::Result<KeyMethod2Record> {
        let conn = self.tls_conn.load_full();
        let conn: Option<&dyn PushReadConn> = match &conn {
            Some(conn) => Some(&**conn),
            None => None,
        };
        self.read_server_key_method_from(ctx, conn).await
    }

    async fn read_server_key_method_from(
        &self,
        ctx: &CancelContext,
        conn: Option<&dyn PushReadConn>,
    ) -> anyhow::Result<KeyMethod2Record> {
        let mut buf = {
            let mut state = self.state.lock();
            std::mem::take(&mut state.leftover_tls)
        };
        if buf.len() > MAX_TLS_CONTROL_BUFFER {
            return Err(anyhow!("openvpn TLS control buffer exceeds {MAX_TLS_CONTROL_BUFFER} bytes"));
        }
        let mut tmp = [0u8; 4096];
        let mut read_err: Option<io::Error> = None;
        loop {
            // A record counts as complete only with all four strings present, so a fragment split
            // across TLS reads cannot be accepted early.
            if record_complete(&buf).0 {
                let (record, consumed) = parse_server_key_method2_record_consumed(&buf)?;
                self.state.lock().leftover_tls = buf.get(consumed..).unwrap_or_default().to_vec();
                return Ok(record);
            }
            // A shortened 2.6 record may end right after the options when the following
            // PUSH_REPLY/AUTH_FAILED is already visible; only truncation means "read more".
            match parse_server_key_method2_record_consumed(&buf) {
                Ok((record, consumed)) => {
                    self.state.lock().leftover_tls = buf.get(consumed..).unwrap_or_default().to_vec();
                    return Ok(record);
                }
                Err(parse_err) => {
                    if !is_key_method_packet_too_short(&parse_err) && !is_io_string_eof(&parse_err) {
                        return Err(parse_err);
                    }
                }
            }
            if let Some(err) = read_err.take() {
                return Err(wrap_error("read key method 2 server record", anyhow::Error::new(err)));
            }
            if let Some(err) = ctx.err() {
                return Err(err);
            }
            let conn = read_conn(conn)?;
            let (n, err) = read_once(conn, &mut tmp).await;
            if n > 0 {
                buf = append_tls_control(&buf, tmp.get(..n).unwrap_or_default())?;
            }
            read_err = err;
        }
    }

    async fn read_push_reply(&self, ctx: &CancelContext) -> anyhow::Result<PushReply> {
        let conn = self.tls_conn.load_full();
        let conn: Option<&dyn PushReadConn> = match &conn {
            Some(conn) => Some(&**conn),
            None => None,
        };
        self.read_push_reply_from(ctx, conn).await
    }

    async fn read_push_reply_from(
        &self,
        ctx: &CancelContext,
        conn: Option<&dyn PushReadConn>,
    ) -> anyhow::Result<PushReply> {
        let mut buf = {
            let mut state = self.state.lock();
            std::mem::take(&mut state.leftover_tls)
        };
        if buf.len() > MAX_TLS_CONTROL_BUFFER {
            return Err(anyhow!("openvpn TLS control buffer exceeds {MAX_TLS_CONTROL_BUFFER} bytes"));
        }
        let mut tmp = [0u8; 4096];
        let mut read_err: Option<io::Error> = None;
        let mut continuation_deadline: Option<Instant> = None;
        loop {
            control_message_error(&buf)?;
            let (reply, rest, ok) = take_push_reply(&buf);
            if ok {
                self.state.lock().leftover_tls = rest;
                let pending = self.state.lock().push_pending.take();
                let mut reply = match pending {
                    Some(pending) => merge_push_reply(Some(pending), reply).unwrap_or_default(),
                    None => reply.unwrap_or_default(),
                };
                self.apply_auth_pending_timeout(&mut reply);
                return Ok(reply);
            }
            if let Some(reply) = reply {
                // Intermediate continuation segments and AUTH_PENDING accumulate until the final
                // PUSH_REPLY segment arrives.
                buf = rest;
                let pending = self.state.lock().push_pending.take();
                let mut merged = merge_push_reply(pending, Some(reply)).unwrap_or_default();
                self.apply_auth_pending_timeout(&mut merged);
                if merged.push_continuation == 2 && continuation_deadline.is_none() {
                    continuation_deadline = Some(self.rekey_wait_deadline(Instant::now()));
                }
                self.state.lock().push_pending = Some(merged);
            }
            if let Some(err) = read_err.take() {
                return Err(wrap_error("read push reply", anyhow::Error::new(err)));
            }
            let mut deadline = self.auth_pending_deadline();
            if let Some(continuation) = continuation_deadline {
                if deadline.is_none_or(|deadline| continuation < deadline) {
                    deadline = Some(continuation);
                }
            }
            if let Some(deadline) = deadline {
                if let Some(conn) = conn {
                    let _ = conn.set_deadline(Some(deadline));
                }
            }
            if let Some(err) = ctx.err() {
                return Err(err);
            }
            let conn = read_conn(conn)?;
            let (n, err) = read_once(conn, &mut tmp).await;
            if n > 0 {
                buf = append_tls_control(&buf, tmp.get(..n).unwrap_or_default())?;
            }
            read_err = err;
        }
    }
}

fn read_conn(conn: Option<&dyn PushReadConn>) -> anyhow::Result<&dyn PushReadConn> {
    conn.ok_or_else(|| anyhow!("openvpn tls connection is not established"))
}

/// A reader may report bytes and a terminal error together; `Ok(0)` is that EOF.
async fn read_once(conn: &dyn PushReadConn, buf: &mut [u8]) -> (usize, Option<io::Error>) {
    match conn.read(buf).await {
        Ok(0) => (0, Some(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))),
        Ok(n) => (n, None),
        Err(err) => (0, Some(err)),
    }
}

fn append_tls_control(buf: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.len() > MAX_TLS_CONTROL_BUFFER - buf.len() {
        return Err(anyhow!("openvpn TLS control buffer exceeds {MAX_TLS_CONTROL_BUFFER} bytes"));
    }
    let mut out = Vec::with_capacity(buf.len() + data.len());
    out.extend_from_slice(buf);
    out.extend_from_slice(data);
    Ok(out)
}

fn interrupt_control_conn_on_done(ctx: &CancelContext, conn: SharedControlConn) -> InterruptGuard {
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let stop = murmur_common::contextutils::after_func(ctx.token(), move || {
        let _ = conn.close();
        let _ = done_tx.send(());
    });
    InterruptGuard { stop: Some(Box::new(stop)), done: Some(done_rx) }
}

pub(crate) struct InterruptGuard {
    stop: Option<Box<dyn Fn() -> bool + Send + Sync>>,
    done: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl InterruptGuard {
    /// Mirrors the stop function: it also waits for a callback that already started, which makes
    /// this the boundary after which cancellation can no longer close a later epoch.
    pub(crate) async fn interrupt(&mut self) {
        if let Some(stop) = self.stop.take() {
            if !stop() {
                if let Some(done) = self.done.take() {
                    let _ = done.await;
                }
            }
        }
    }
}

pub(crate) struct RetransmitStop {
    cancel: Option<Box<dyn FnOnce() + Send>>,
}

impl RetransmitStop {
    fn new<F: FnOnce() + Send + 'static>(cancel: F) -> Self {
        Self { cancel: Some(Box::new(cancel)) }
    }

    pub(crate) fn stop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel();
        }
    }
}

impl Drop for RetransmitStop {
    fn drop(&mut self) {
        self.stop();
    }
}

#[async_trait::async_trait]
pub(crate) trait PushReadConn: Send + Sync {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()>;
    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()>;
}

#[async_trait::async_trait]
pub(crate) trait TokenPushReader: Send + Sync {
    async fn read_final(
        &self,
        conn: &dyn PushReadConn,
        leftover: &[u8],
        extended: &[Option<Instant>],
    ) -> anyhow::Result<(Option<PushReply>, Vec<u8>)>;
}

pub(crate) struct ReadTokenPushReply;

#[async_trait::async_trait]
impl TokenPushReader for ReadTokenPushReply {
    async fn read_final(
        &self,
        conn: &dyn PushReadConn,
        leftover: &[u8],
        extended: &[Option<Instant>],
    ) -> anyhow::Result<(Option<PushReply>, Vec<u8>)> {
        read_token_push_reply(conn, leftover, extended).await
    }
}

pub(crate) async fn read_token_push_reply(
    conn: &dyn PushReadConn,
    leftover: &[u8],
    extended: &[Option<Instant>],
) -> anyhow::Result<(Option<PushReply>, Vec<u8>)> {
    let mut buf = leftover.to_vec();
    if buf.len() > MAX_TLS_CONTROL_BUFFER {
        return Err(anyhow!("openvpn TLS control buffer exceeds {MAX_TLS_CONTROL_BUFFER} bytes"));
    }
    let mut tmp = [0u8; 4096];
    let mut acc: Option<PushReply> = None;
    let mut wait_until = extended.first().copied().flatten();
    let mut continuation_until = extended.first().copied().flatten();
    let established_at = extended.get(1).copied().flatten();
    let continuation_limit = extended.get(2).copied().flatten();
    let mut auth_pending_until: Option<Instant> = None;

    // The buffered bytes are parsed first: the reply may be complete already.
    control_message_error(&buf)?;
    let (reply, rest, ok) = take_push_reply(&buf);
    if ok {
        return Ok((merge_push_reply(acc, reply), rest));
    }
    if let Some(reply) = reply {
        let mut merged = merge_push_reply(acc, Some(reply)).unwrap_or_default();
        promote_token_wait_policy(
            conn,
            &mut merged,
            established_at,
            &mut wait_until,
            &mut continuation_until,
            &mut auth_pending_until,
            continuation_limit,
        );
        acc = Some(merged);
        buf = rest;
    }
    control_message_error(&buf)?;

    let outcome = probe_token_push(
        conn,
        buf,
        &mut tmp,
        acc,
        wait_until,
        continuation_until,
        auth_pending_until,
        established_at,
        continuation_limit,
    )
    .await;
    let _ = conn.set_read_deadline(None);
    outcome
}

fn promote_token_wait_policy(
    conn: &dyn PushReadConn,
    reply: &mut PushReply,
    established_at: Option<Instant>,
    wait_until: &mut Option<Instant>,
    continuation_until: &mut Option<Instant>,
    auth_pending_until: &mut Option<Instant>,
    continuation_limit: Option<Instant>,
) {
    let now = Instant::now();
    if push_has_auth_pending(Some(reply)) {
        anchor_auth_pending_deadline(reply, established_at);
        let deadline = reply.auth_pending_until;
        *auth_pending_until = deadline;
        if continuation_until.is_some() {
            *wait_until = *continuation_until;
            if auth_pending_until.is_some_and(|pending| wait_until.is_some_and(|wait| pending < wait)) {
                *wait_until = *auth_pending_until;
            }
        }
        let _ = conn.set_deadline(deadline);
    }
    if reply.push_continuation == 2 && continuation_until.is_none() {
        *continuation_until = continuation_limit;
        if continuation_until.is_none() {
            *continuation_until = Some(now + RENEGOTIATE_TIMEOUT);
        }
        *wait_until = *continuation_until;
        if auth_pending_until.is_some_and(|pending| wait_until.is_some_and(|wait| pending < wait)) {
            *wait_until = *auth_pending_until;
        }
        let _ = conn.set_deadline(*wait_until);
    }
}

async fn probe_token_push(
    conn: &dyn PushReadConn,
    mut buf: Vec<u8>,
    tmp: &mut [u8],
    mut acc: Option<PushReply>,
    wait_until: Option<Instant>,
    continuation_until: Option<Instant>,
    auth_pending_until: Option<Instant>,
    established_at: Option<Instant>,
    continuation_limit: Option<Instant>,
) -> anyhow::Result<(Option<PushReply>, Vec<u8>)> {
    let mut wait_until = wait_until;
    let mut continuation_until = continuation_until;
    let mut auth_pending_until = auth_pending_until;
    let mut attempt = 0usize;
    loop {
        let mut read_deadline = Instant::now() + TOKEN_PUSH_READ_TIMEOUT;
        if let Some(wait) = wait_until {
            if wait < read_deadline {
                read_deadline = wait;
            }
        }
        let _ = conn.set_read_deadline(Some(read_deadline));
        let (n, err) = read_once(conn, tmp).await;
        if n > 0 {
            buf = append_tls_control(&buf, tmp.get(..n).unwrap_or_default())?;
        }
        control_message_error(&buf)?;
        let (reply, rest, ok) = take_push_reply(&buf);
        if ok {
            if let Some(reply) = reply {
                let mut merged = merge_push_reply(acc, Some(reply)).unwrap_or_default();
                promote_token_wait_policy(
                    conn,
                    &mut merged,
                    established_at,
                    &mut wait_until,
                    &mut continuation_until,
                    &mut auth_pending_until,
                    continuation_limit,
                );
                acc = Some(merged);
            }
            return Ok((acc, rest));
        }
        if let Some(reply) = reply {
            let mut merged = merge_push_reply(acc, Some(reply)).unwrap_or_default();
            promote_token_wait_policy(
                conn,
                &mut merged,
                established_at,
                &mut wait_until,
                &mut continuation_until,
                &mut auth_pending_until,
                continuation_limit,
            );
            acc = Some(merged);
            buf = rest;
        }
        if let Some(err) = err {
            let err: anyhow::Error = err.into();
            if is_timeout(&err) {
                if continuation_until.is_some() && wait_until.is_some_and(|wait| Instant::now() < wait) {
                    continue;
                }
                return Ok((acc, buf));
            }
            return Err(err);
        }
        // A token refresh, standalone AUTH_PENDING included, is a short probe; only an unfinished
        // continuation waits for the extended deadline.
        if continuation_until.is_none() && attempt + 1 >= 2 {
            return Ok((acc, buf));
        }
        if continuation_until.is_some() && wait_until.is_none_or(|wait| Instant::now() >= wait) {
            return Ok((acc, buf));
        }
        attempt += 1;
    }
}

fn is_timeout(err: &anyhow::Error) -> bool {
    is_context_deadline_exceeded(err)
        || err
            .downcast_ref::<io::Error>()
            .is_some_and(|err| matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock))
}

/// The auth-failed and control-terminated errors, kept as matchable types behind the
/// message-carrying error so `error_is::<T>` still finds them.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("openvpn authentication failed")]
pub(crate) struct ErrAuthFailed;

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("openvpn server terminated the control session")]
pub(crate) struct ErrControlTerminated;

#[derive(Debug, thiserror::Error)]
#[error("{}: {}", .sentinel, .message)]
pub(crate) struct AuthFailedMessage {
    #[source]
    sentinel: ErrAuthFailed,
    message: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{}: {}", .sentinel, .message)]
pub(crate) struct ControlTerminatedMessage {
    #[source]
    sentinel: ErrControlTerminated,
    message: String,
}

pub(crate) fn err_auth_failed() -> anyhow::Error {
    anyhow::Error::new(ErrAuthFailed)
}

fn auth_failed_message(message: String) -> anyhow::Error {
    anyhow::Error::new(AuthFailedMessage { sentinel: ErrAuthFailed, message })
}

fn control_terminated_message(message: String) -> anyhow::Error {
    anyhow::Error::new(ControlTerminatedMessage { sentinel: ErrControlTerminated, message })
}

pub(crate) fn auth_failed_msg(buf: &[u8]) -> bool {
    let (msgs, _) = split_control_messages(buf);
    msgs.iter().any(|msg| msg.starts_with(b"AUTH_FAILED"))
}

pub(crate) fn auth_failed_error(buf: &[u8]) -> anyhow::Error {
    let (msgs, _) = split_control_messages(buf);
    for msg in msgs {
        if msg.starts_with(b"AUTH_FAILED") {
            return auth_failed_message(String::from_utf8_lossy(msg).trim().to_owned());
        }
    }
    err_auth_failed()
}

pub(crate) fn control_message_error(buf: &[u8]) -> anyhow::Result<()> {
    if auth_failed_msg(buf) {
        return Err(auth_failed_error(buf));
    }
    let (msgs, _) = split_control_messages(buf);
    for msg in msgs {
        for prefix in ["RESTART", "HALT", "EXIT"] {
            if msg.starts_with(prefix.as_bytes()) {
                return Err(control_terminated_message(String::from_utf8_lossy(msg).trim().to_owned()));
            }
        }
        if msg.starts_with(b"PUSH_REPLY") {
            if let Err(err) = parse_push_reply_inner(&String::from_utf8_lossy(msg)) {
                return Err(wrap_error("invalid openvpn push reply", err));
            }
        }
    }
    Ok(())
}

pub(crate) fn push_has_auth_pending(reply: Option<&PushReply>) -> bool {
    reply.is_some_and(|reply| reply.has_auth_pending || !reply.auth_pending_timeout.is_zero())
}

pub(crate) fn anchor_auth_pending_deadline(reply: &mut PushReply, established_at: Option<Instant>) {
    if !push_has_auth_pending(Some(reply)) || reply.auth_pending_until.is_some() {
        return;
    }
    let established_at = established_at.unwrap_or_else(Instant::now);
    reply.auth_pending_until = Some(established_at + reply.auth_pending_timeout);
}

pub(crate) fn take_push_reply(buf: &[u8]) -> (Option<PushReply>, Vec<u8>, bool) {
    // One caller handles the happy path (PUSH_REPLY), the failure path (AUTH_FAILED) and the
    // deferred-auth signal (AUTH_PENDING,timeout N), so complete NUL-delimited messages are walked
    // in order rather than assuming PUSH_REPLY comes first.
    let (msgs, rest) = split_control_messages(buf);
    if msgs.is_empty() {
        return (None, rest.to_vec(), false);
    }
    let mut auth_failed: Option<&[u8]> = None;
    let mut reply: Option<PushReply> = None;
    let mut parsed = false;
    let mut continuation_pending = false;
    for msg in msgs {
        if msg.starts_with(b"AUTH_FAILED") {
            auth_failed = Some(msg);
            continue;
        }
        if msg.starts_with(b"AUTH_PENDING") {
            // AUTH_PENDING alone is not a complete push reply.
            if let Ok(pending) = parse_auth_pending_timeout(&String::from_utf8_lossy(msg)) {
                reply = merge_push_reply(reply, Some(pending));
            }
        }
        if msg.starts_with(b"PUSH_REPLY") {
            if let Ok(parsed_reply) = parse_push_reply_inner(&String::from_utf8_lossy(msg)) {
                continuation_pending = parsed_reply.push_continuation == 2;
                reply = merge_push_reply(reply, Some(parsed_reply));
                parsed = true;
            }
        }
        // Other complete control messages are deliberately consumed.
    }
    if auth_failed.is_some() {
        return (None, rest.to_vec(), false);
    }
    if !parsed || continuation_pending {
        return (reply, rest.to_vec(), false);
    }
    (reply, rest.to_vec(), true)
}

pub(crate) fn parse_auth_pending_timeout(msg: &str) -> anyhow::Result<PushReply> {
    let PushReply {
        raw,
        prefixes,
        routes,
        dns,
        redirect,
        block_ipv6,
        data_ciphers,
        cipher,
        auth_token_user,
        auth_token_pass,
        push_continuation,
        has_push_reply,
        auth_pending_until,
        ..
    } = PushReply::default();
    let mut reply = PushReply {
        raw,
        prefixes,
        routes,
        dns,
        peer_id: data::PEER_ID_UNSET,
        redirect,
        block_ipv6,
        data_ciphers,
        cipher,
        auth_token_user,
        auth_token_pass,
        push_continuation,
        has_push_reply,
        auth_pending_timeout: AUTH_DEFERRED_EXPIRE,
        auth_pending_until,
        has_auth_pending: true,
    };
    if !msg.starts_with("AUTH_PENDING") {
        return Err(anyhow!("not an auth pending message"));
    }
    let rest = msg.strip_prefix("AUTH_PENDING").unwrap_or(msg);
    let rest = rest.strip_prefix(',').unwrap_or(rest);
    for part in rest.split(',') {
        let fields: Vec<&str> = part.split_whitespace().collect();
        let Ok([key, value]) = <[&str; 2]>::try_from(fields.as_slice()) else {
            continue;
        };
        if key != "timeout" {
            continue;
        }
        let max_seconds = AUTH_PENDING_MAX_TIMEOUT.as_secs();
        match value.parse::<u64>() {
            Ok(seconds) => {
                reply.auth_pending_timeout = Duration::from_secs(seconds.min(max_seconds));
            }
            Err(err) if *err.kind() == std::num::IntErrorKind::PosOverflow => {
                reply.auth_pending_timeout = AUTH_PENDING_MAX_TIMEOUT;
            }
            Err(_) => {}
        }
    }
    Ok(reply)
}

pub(crate) fn split_control_messages(buf: &[u8]) -> (Vec<&[u8]>, &[u8]) {
    if buf.is_empty() {
        return (Vec::new(), buf);
    }
    let mut msgs = Vec::new();
    let mut rest = buf;
    while let Some(idx) = rest.iter().position(|&b| b == 0) {
        let (msg, tail) = rest.split_at(idx);
        msgs.push(msg);
        rest = tail.get(1..).unwrap_or_default();
    }
    (msgs, rest)
}

pub(crate) fn merge_push_reply(prev: Option<PushReply>, next: Option<PushReply>) -> Option<PushReply> {
    let Some(mut next) = next else {
        return prev;
    };
    let Some(prev) = prev else {
        return Some(next);
    };
    next.prefixes = append_unique_prefixes(&prev.prefixes, next.prefixes);
    next.routes = append_unique_prefixes(&prev.routes, next.routes);
    next.dns = append_unique_addrs(&prev.dns, next.dns);
    let next_has_push_reply = next.has_push_reply;
    next.data_ciphers = append_unique_strings(&prev.data_ciphers, next.data_ciphers);
    if next.peer_id == data::PEER_ID_UNSET {
        next.peer_id = prev.peer_id;
    }
    if next.cipher.is_empty() {
        next.cipher = prev.cipher;
    }
    if !next.redirect {
        next.redirect = prev.redirect;
    }
    if !next.block_ipv6 {
        next.block_ipv6 = prev.block_ipv6;
    }
    if next.auth_token_pass.is_empty() {
        next.auth_token_pass = prev.auth_token_pass;
    }
    if next.auth_token_user.is_empty() {
        next.auth_token_user = prev.auth_token_user;
    }
    // A deferred-auth timeout survives merging into a later non-pending PUSH_REPLY, carrying its
    // observation-anchored deadline.
    if !push_has_auth_pending(Some(&next)) {
        next.auth_pending_timeout = prev.auth_pending_timeout;
        next.auth_pending_until = prev.auth_pending_until;
        next.has_auth_pending = prev.has_auth_pending;
    }
    if !next_has_push_reply {
        next.push_continuation = prev.push_continuation;
    }
    next.has_push_reply = next.has_push_reply || prev.has_push_reply;
    Some(next)
}

pub(crate) fn append_unique_prefixes(prev: &[ipnet::IpNet], next: Vec<ipnet::IpNet>) -> Vec<ipnet::IpNet> {
    if prev.is_empty() {
        return next;
    }
    let mut out = prev.to_vec();
    for prefix in next {
        if !contains_prefix(&out, &prefix) {
            out.push(prefix);
        }
    }
    out
}

pub(crate) fn contains_prefix(list: &[ipnet::IpNet], prefix: &ipnet::IpNet) -> bool {
    list.iter().any(|candidate| candidate == prefix)
}

pub(crate) fn append_unique_addrs(prev: &[std::net::IpAddr], next: Vec<std::net::IpAddr>) -> Vec<std::net::IpAddr> {
    if prev.is_empty() {
        return next;
    }
    let mut out = prev.to_vec();
    for addr in next {
        if !contains_addr(&out, &addr) {
            out.push(addr);
        }
    }
    out
}

pub(crate) fn contains_addr(list: &[std::net::IpAddr], addr: &std::net::IpAddr) -> bool {
    list.iter().any(|candidate| candidate == addr)
}

pub(crate) fn append_unique_strings(prev: &[String], next: Vec<String>) -> Vec<String> {
    if prev.is_empty() {
        return next;
    }
    let mut out = prev.to_vec();
    for item in next {
        if !contains_string(&out, &item) {
            out.push(item);
        }
    }
    out
}

pub(crate) fn contains_string(list: &[String], item: &str) -> bool {
    list.iter().any(|candidate| candidate == item)
}

fn is_key_method_packet_too_short(err: &anyhow::Error) -> bool {
    err.chain().any(<dyn std::error::Error + 'static>::is::<super::keymethod::ErrKeyMethodPacketTooShort>)
}

fn is_io_string_eof(err: &anyhow::Error) -> bool {
    err.chain().any(<dyn std::error::Error + 'static>::is::<super::keymethod::IoStringEOF>)
}

fn trim_ascii_space(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(data.len());
    let end = data.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |idx| idx + 1);
    data.get(start..end).unwrap_or_default()
}

/// `rustls-pemfile` is not a pinned dependency, so PEM sections are decoded with the pinned
/// base64 engine instead.
fn pem_sections(input: &[u8]) -> Vec<(String, Vec<u8>)> {
    use base64::Engine as _;

    let text = String::from_utf8_lossy(input);
    let mut sections = Vec::new();
    let mut label: Option<String> = None;
    let mut body = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            if let Some(rest) = rest.strip_suffix("-----") {
                label = Some(rest.to_owned());
                body.clear();
                continue;
            }
        }
        if line.starts_with("-----END ") {
            if let Some(label) = label.take() {
                if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(body.as_bytes()) {
                    sections.push((label, der));
                }
            }
            body.clear();
            continue;
        }
        if label.is_some() {
            body.push_str(line);
        }
    }
    sections
}

fn pem_certificates(pem: &[u8]) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    pem_sections(pem)
        .into_iter()
        .filter(|(label, _)| label == "CERTIFICATE")
        .map(|(_, der)| rustls::pki_types::CertificateDer::from(der))
        .collect()
}

fn pem_private_key(pem: &[u8]) -> Option<rustls::pki_types::PrivateKeyDer<'static>> {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

    for (label, der) in pem_sections(pem) {
        match label.as_str() {
            "PRIVATE KEY" => return Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))),
            "RSA PRIVATE KEY" => return Some(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der))),
            "EC PRIVATE KEY" => return Some(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der))),
            _ => {}
        }
    }
    None
}

fn tls_config(config: &ClientConfig) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let ca = pem_certificates(&config.ca);
    if ca.is_empty() {
        return Err(anyhow!("parse openvpn ca certificate"));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(ca);
    let verifier = verify::OpenVpnServerCertVerifier::new(Arc::new(roots))?;
    let builder =
        rustls::ClientConfig::builder_with_provider(Arc::new(murmur_component_tls::tls12_sequence_nonce_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|err| wrap_error("rustls default protocol versions", anyhow::Error::new(err)))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier));
    let cert_pem = trim_ascii_space(&config.cert);
    let key_pem = trim_ascii_space(&config.key);
    let client_config = if !cert_pem.is_empty() && !key_pem.is_empty() {
        let cert_chain = pem_certificates(&config.cert);
        let private_key = pem_private_key(&config.key)
            .ok_or_else(|| wrap_error("parse client certificate/key", anyhow!("no private key found")))?;
        builder
            .with_client_auth_cert(cert_chain, private_key)
            .map_err(|err| wrap_error("parse client certificate/key", anyhow::Error::new(err)))?
    } else {
        builder.with_no_client_auth()
    };
    // rustls has no renegotiation; every rekey here starts a fresh TLS session anyway.
    Ok(Arc::new(client_config))
}

mod verify {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    /// the `VerifyConnection` closure verifies the chain against the configured CA and ignores
    /// the server name, which webpki reports as `NotValidForName`.
    #[derive(Debug)]
    pub(super) struct OpenVpnServerCertVerifier {
        inner: Arc<WebPkiServerVerifier>,
    }

    impl OpenVpnServerCertVerifier {
        pub(super) fn new(roots: Arc<rustls::RootCertStore>) -> anyhow::Result<Self> {
            let inner = WebPkiServerVerifier::builder(roots)
                .build()
                .map_err(|err| super::wrap_error("parse openvpn ca certificate", anyhow::Error::new(err)))?;
            Ok(Self { inner })
        }
    }

    impl ServerCertVerifier for OpenVpnServerCertVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            match self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now) {
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::NotValidForName | rustls::CertificateError::NotValidForNameContext { .. },
                )) => Ok(ServerCertVerified::assertion()),
                other => other,
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }
}

/// The TLS session drives the control channel through this shared handle, which also keeps the
/// deadline operations and the cancellation close reachable.
#[derive(Clone)]
pub(crate) struct SharedControlConn(ControlConn);

impl SharedControlConn {
    pub(crate) const fn new(conn: ControlConn) -> Self {
        Self(conn)
    }

    pub(crate) fn reset(&self) {
        self.0.reset();
    }

    pub(crate) fn unsafe_feed(&self, payload: &[u8]) {
        self.0.unsafe_feed(payload);
    }

    pub(crate) fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.0.set_deadline(deadline)
    }

    pub(crate) fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.0.set_read_deadline(deadline)
    }

    pub(crate) fn close(&self) -> io::Result<()> {
        self.0.close()
    }

    #[allow(dead_code, reason = "exercised only by #[cfg(test)] tests that read the readBuf field directly")]
    pub(crate) fn read_buf(&self) -> Vec<u8> {
        self.0.read_buf()
    }
}

impl AsyncRead for SharedControlConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.0.poll_read_shared(cx, buf)
    }
}

impl AsyncWrite for SharedControlConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.0.poll_write_shared(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

pub(crate) struct TlsConn {
    stream: tokio::sync::Mutex<tokio_rustls::client::TlsStream<SharedControlConn>>,
    conn: SharedControlConn,
}

impl TlsConn {
    async fn connect(conn: SharedControlConn, config: Arc<rustls::ClientConfig>) -> io::Result<Self> {
        // No ServerName is set, so the handshake sends no SNI; an IP server name keeps that.
        let server_name =
            rustls::pki_types::ServerName::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED).into());
        let stream = tokio_rustls::TlsConnector::from(config).connect(server_name, conn.clone()).await?;
        Ok(Self { stream: tokio::sync::Mutex::new(stream), conn })
    }

    async fn write_all(&self, data: &[u8]) -> io::Result<()> {
        let mut stream = self.stream.lock().await;
        stream.write_all(data).await
    }
}

#[async_trait::async_trait]
impl PushReadConn for TlsConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut stream = self.stream.lock().await;
        stream.read(buf).await
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.conn.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.conn.set_read_deadline(deadline)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::{mpsc, oneshot};
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    use murmur_common_net::io::Stream;

    use super::*;
    use crate::{config, control, data, keymethod, packet, packetio, push, tlsauth, tlscrypt};
    use murmur_testsupport_probe::ensure_test_crypto_provider;

    // ---- rekey tests (a) ----
    struct BarePacketIo;

    #[async_trait::async_trait]
    impl PacketIO for BarePacketIo {
        async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>) {
            std::future::pending::<(Option<Vec<u8>>, Option<anyhow::Error>)>().await
        }

        async fn write_packet(&self, _packet: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }

        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            None
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    fn new_bare_control_client() -> Arc<Client> {
        Client::new(Arc::new(ClientConfig::default()), Arc::new(BarePacketIo)).expect("bare control client")
    }

    #[derive(Default)]
    struct ChunkConn {
        data: Vec<Vec<u8>>,
        errs: Vec<Option<io::Error>>,
        idx: Mutex<usize>,
        pending_err: Mutex<Option<io::Error>>,
        last_deadline: Mutex<Option<tokio::time::Instant>>,
        last_write_deadline: Mutex<Option<tokio::time::Instant>>,
        operation_deadlines: Mutex<Vec<Option<tokio::time::Instant>>>,
    }

    #[async_trait::async_trait]
    impl PushReadConn for ChunkConn {
        async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some(err) = self.pending_err.lock().take() {
                return Err(err);
            }
            let mut idx = self.idx.lock();
            if *idx >= self.data.len() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout"));
            }
            let n = buf.len().min(self.data[*idx].len());
            buf[..n].copy_from_slice(&self.data[*idx][..n]);
            let err =
                self.errs.get(*idx).and_then(Option::as_ref).map(|err| io::Error::new(err.kind(), err.to_string()));
            *idx += 1;
            match err {
                // the Read yields bytes and a terminal error together; the bytes go out now and the
                // error on the next call, which is what the reader's n-before-err order observes.
                Some(err) if n > 0 => {
                    *self.pending_err.lock() = Some(err);
                    Ok(n)
                }
                Some(err) => Err(err),
                None => Ok(n),
            }
        }

        fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            *self.last_deadline.lock() = deadline;
            *self.last_write_deadline.lock() = deadline;
            self.operation_deadlines.lock().push(deadline);
            Ok(())
        }

        fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            *self.last_deadline.lock() = deadline;
            Ok(())
        }
    }

    struct ControlConnPushReader(ControlConn);

    #[async_trait::async_trait]
    impl PushReadConn for ControlConnPushReader {
        async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf).await
        }

        fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.0.set_deadline(deadline)
        }

        fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            self.0.set_read_deadline(deadline)
        }
    }

    struct ContinuationDiscoveredReader {
        expected: Arc<ChunkConn>,
    }

    #[async_trait::async_trait]
    impl TokenPushReader for ContinuationDiscoveredReader {
        async fn read_final(
            &self,
            conn: &dyn PushReadConn,
            leftover: &[u8],
            _extended: &[Option<tokio::time::Instant>],
        ) -> anyhow::Result<(Option<PushReply>, Vec<u8>)> {
            assert!(std::ptr::eq(conn, &*self.expected), "reader received wrong connection");
            assert!(leftover.is_empty(), "unexpected initial leftover: {leftover:?}");
            Ok((
                Some(PushReply {
                    peer_id: data::PEER_ID_UNSET,
                    has_push_reply: true,
                    push_continuation: 2,
                    routes: vec!["10.9.0.0/16".parse().expect("test prefix")],
                    ..Default::default()
                }),
                Vec::new(),
            ))
        }
    }

    struct AuthPendingReader {
        expected: Arc<ChunkConn>,
        pending: PushReply,
    }

    #[async_trait::async_trait]
    impl TokenPushReader for AuthPendingReader {
        async fn read_final(
            &self,
            conn: &dyn PushReadConn,
            leftover: &[u8],
            _extended: &[Option<tokio::time::Instant>],
        ) -> anyhow::Result<(Option<PushReply>, Vec<u8>)> {
            assert!(std::ptr::eq(conn, &*self.expected), "reader received wrong connection");
            assert!(leftover.is_empty(), "unexpected initial leftover: {leftover:?}");
            Ok((Some(self.pending.clone()), Vec::new()))
        }
    }

    #[derive(Default)]
    struct RetransmitTestPacketIo {
        writes: Mutex<usize>,
        first: Mutex<Option<anyhow::Error>>,
        second: Mutex<Option<anyhow::Error>>,
        retried: Option<Arc<tokio::sync::Notify>>,
    }

    #[async_trait::async_trait]
    impl PacketIO for RetransmitTestPacketIo {
        async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>) {
            std::future::pending::<(Option<Vec<u8>>, Option<anyhow::Error>)>().await
        }

        async fn write_packet(&self, _packet: &[u8]) -> anyhow::Result<()> {
            let writes = {
                let mut writes = self.writes.lock();
                *writes += 1;
                *writes
            };
            if writes == 1 {
                if let Some(err) = self.first.lock().take() {
                    return Err(err);
                }
            }
            if writes == 2 {
                if let Some(err) = self.second.lock().take() {
                    return Err(err);
                }
            }
            if writes >= 3 {
                if let Some(retried) = &self.retried {
                    retried.notify_one();
                }
            }
            Ok(())
        }

        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            None
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    #[derive(Default)]
    struct BlockingPermanentPacketIo {
        writes: Mutex<usize>,
        entered: Option<Arc<tokio::sync::Notify>>,
        release: Option<Arc<tokio::sync::Notify>>,
        write_err: Mutex<Option<anyhow::Error>>,
    }

    #[async_trait::async_trait]
    impl PacketIO for BlockingPermanentPacketIo {
        async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>) {
            std::future::pending::<(Option<Vec<u8>>, Option<anyhow::Error>)>().await
        }

        async fn write_packet(&self, _packet: &[u8]) -> anyhow::Result<()> {
            let writes = {
                let mut writes = self.writes.lock();
                *writes += 1;
                *writes
            };
            if writes == 2 {
                if let Some(entered) = &self.entered {
                    entered.notify_one();
                }
                if let Some(release) = &self.release {
                    release.notified().await;
                }
                if let Some(err) = self.write_err.lock().take() {
                    return Err(err);
                }
            }
            Ok(())
        }

        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            None
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    fn marshal_open_vpn_string(out: &mut Vec<u8>, s: &str) {
        if s.is_empty() {
            out.extend_from_slice(&0u16.to_be_bytes());
            return;
        }
        let bytes = s.as_bytes();
        let len = u16::try_from(bytes.len()).expect("openvpn string length fits u16");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
    }

    fn key_method_string_complete(packet: &[u8], offset: usize) -> bool {
        if offset + 2 > packet.len() {
            return false;
        }
        let size = usize::from(u16::from_be_bytes([packet[offset], packet[offset + 1]]));
        size == 0 || offset + 2 + size <= packet.len()
    }

    fn client_key_method_complete(packet: &[u8]) -> bool {
        const FIXED: usize = 4 + 1 + 48 + 32 * 2;
        if packet.len() < FIXED {
            return false;
        }
        let mut offset = FIXED;
        for _ in 0..4 {
            if !key_method_string_complete(packet, offset) {
                return false;
            }
            offset += 2 + usize::from(u16::from_be_bytes([packet[offset], packet[offset + 1]]));
        }
        true
    }

    fn marshal_test_server_key_method() -> Vec<u8> {
        let random1: [u8; 32] = rand::random();
        let random2: [u8; 32] = rand::random();
        let mut out = Vec::with_capacity(4 + 1 + 32 * 2 + 16);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.push(keymethod::KEY_METHOD_2);
        out.extend_from_slice(&random1);
        out.extend_from_slice(&random2);
        marshal_open_vpn_string(
            &mut out,
            &install_script_options_string(PROTO_UDP, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, ""),
        );
        marshal_open_vpn_string(&mut out, "");
        marshal_open_vpn_string(&mut out, "");
        marshal_open_vpn_string(&mut out, "");
        out
    }

    async fn read_test_client_key_method(conn: &dyn PushReadConn) -> anyhow::Result<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let mut tmp = [0u8; 1024];
        while !client_key_method_complete(&buf) {
            let n = conn.read(&mut tmp).await?;
            if n > 0 {
                buf.extend_from_slice(&tmp[..n]);
            }
        }
        Ok(())
    }

    fn rekey_test_key_material() -> keymethod::KeyMaterial {
        keymethod::KeyMaterial {
            send_cipher_key: vec![0x11; 16],
            send_hmac_key: vec![0x22; 64],
            recv_cipher_key: vec![0x11; 16],
            recv_hmac_key: vec![0x22; 64],
        }
    }

    fn rekey_test_key_material_filled(fill: u8) -> keymethod::KeyMaterial {
        keymethod::KeyMaterial {
            send_cipher_key: vec![fill; 16],
            send_hmac_key: vec![fill + 1; 64],
            recv_cipher_key: vec![fill; 16],
            recv_hmac_key: vec![fill + 1; 64],
        }
    }

    fn generate_test_tls_server_certificate(
    ) -> (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>, Vec<u8>) {
        let (cert_pem, key_pem, _fingerprint) =
            murmur_component_ca::keypair::new_random_tls_key_pair(murmur_component_ca::keypair::KeyPairType::P256)
                .expect("generate test tls server certificate");
        let cert_der =
            pem_certificates(cert_pem.as_bytes()).into_iter().next().expect("parse test tls server certificate");
        let key_der = pem_private_key(key_pem.as_bytes()).expect("parse test tls server certificate key");
        (cert_der, key_der, cert_pem.into_bytes())
    }

    fn test_server_tls_acceptor() -> (tokio_rustls::TlsAcceptor, Vec<u8>) {
        let (cert_der, key_der, ca_pem) = generate_test_tls_server_certificate();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("build test tls server config");
        (tokio_rustls::TlsAcceptor::from(Arc::new(server_config)), ca_pem)
    }

    struct ServerTlsPushConn(tokio::sync::Mutex<tokio_rustls::server::TlsStream<ControlConn>>);

    #[async_trait::async_trait]
    impl PushReadConn for ServerTlsPushConn {
        async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.lock().await.read(buf).await
        }

        fn set_deadline(&self, _deadline: Option<Instant>) -> io::Result<()> {
            Ok(())
        }

        fn set_read_deadline(&self, _deadline: Option<Instant>) -> io::Result<()> {
            Ok(())
        }
    }

    // The blocked close parks a runtime worker, so the test needs a second one to drive `interrupt`.
    #[expect(
        clippy::await_holding_lock,
        reason = "holding `held` across the awaits is the point: it makes ControlConn::close block on interrupt_write's state.lock()"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_interrupt_control_conn_stop_waits_for_running_close() {
        let ctx = CancelContext::background();
        let token = ctx.token().clone();
        let channel = Arc::new(ControlChannel::default());
        let conn = SharedControlConn::new(ControlConn::new(Arc::clone(&channel)));
        let mut interrupt = interrupt_control_conn_on_done(&ctx, conn);
        let held = channel.state().lock();
        token.cancel();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut stopped = tokio::spawn(async move { interrupt.interrupt().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut stopped).await.is_err(),
            "stop returned while control connection close was still running"
        );
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), &mut stopped)
            .await
            .expect("stop did not return after control connection close completed")
            .expect("stop task joined");
    }

    #[tokio::test]
    async fn test_initial_handshake_context_deadline_remains_hard_limit() {
        ensure_test_crypto_provider();
        let (client_io, server_io) = new_memory_packet_pair();
        let (acceptor, ca_pem) = test_server_tls_acceptor();
        let client = new_test_client(
            &Arc::new(ClientConfig {
                proto: PROTO_UDP.to_owned(),
                ca: ca_pem,
                cipher: config::CIPHER_AES_128_GCM.to_owned(),
                auth: config::AUTH_SHA256.to_owned(),
                username: "test".to_owned(),
                remote_host: "server".to_owned(),
                remote_port: 1194,
                ..Default::default()
            }),
            control_io_packet_adapter(client_io),
        )
        .expect("test client");

        let guard_ctx = CancelContext::background().with_deadline(Instant::now() + Duration::from_secs(5));
        let handshake_deadline = Instant::now() + Duration::from_millis(750);
        let handshake_cc = CancelContext::background().with_deadline(handshake_deadline);
        let handshake_token = handshake_cc.token().clone();

        let mut handshake_task = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.handshake(&handshake_token).await }
        });

        let reset_raw = server_io.read_packet(&guard_ctx).await.expect("read client reset");
        let (reset, _, _) = packet::decode_control_packet(None, &reset_raw).expect("decode client reset");
        let server =
            ControlChannel::new(Arc::<MemoryPacketIO>::clone(&server_io), None, packet::SessionID(*b"server01"));
        server.set_remote_session_id(reset.local_session);
        server.mark_received(reset.message_id);
        server.queue_ack(reset.message_id);
        server.send(&guard_ctx, packet::P_CONTROL_HARD_RESET_SERVER_V2, &[]).await.expect("send server reset");

        let server_conn = ControlConn::new(Arc::new(server));
        let server_tls = acceptor.accept(server_conn).await.expect("server tls handshake");
        let push_conn = ServerTlsPushConn(tokio::sync::Mutex::new(server_tls));
        read_test_client_key_method(&push_conn).await.expect("read client key method 2");

        {
            let state = client.control.state().lock();
            assert!(
                state.read_deadline.is_none() && state.write_deadline.is_none(),
                "caller deadline was copied into control channel: read={:?} write={:?}",
                state.read_deadline,
                state.write_deadline
            );
        }

        {
            let mut server_tls = push_conn.0.lock().await;
            server_tls.write_all(&marshal_test_server_key_method()).await.expect("write server key method 2");
        }

        let mut push_request = Vec::new();
        let mut read_buf = [0u8; 128];
        while !push_request.contains(&0u8) {
            let n = {
                let mut server_tls = push_conn.0.lock().await;
                server_tls.read(&mut read_buf).await.expect("read push request")
            };
            push_request.extend_from_slice(&read_buf[..n]);
        }
        let nul = push_request.iter().position(|&b| b == 0).expect("push request nul terminator");
        assert_eq!(&push_request[..nul], PUSH_REQUEST.as_bytes(), "push request payload");

        {
            let mut server_tls = push_conn.0.lock().await;
            server_tls.write_all(b"AUTH_PENDING,timeout 60\x00").await.expect("write auth pending");
        }

        let poll_deadline = Instant::now() + Duration::from_secs(5);
        let auth_deadline = loop {
            let staged = client.data.read().pending_deferred_until;
            if let Some(deadline) = staged {
                break deadline;
            }
            if handshake_task.is_finished() {
                let result = (&mut handshake_task).await.expect("handshake task joined");
                panic!("handshake ended before AUTH_PENDING was applied: {result:?}");
            }
            assert!(Instant::now() < poll_deadline, "guard timeout waiting for AUTH_PENDING deadline");
            tokio::time::sleep(Duration::from_millis(1)).await;
        };
        assert!(
            auth_deadline > handshake_deadline,
            "AUTH_PENDING deadline = {auth_deadline:?}, want later than caller deadline {handshake_deadline:?}"
        );

        let handshake_result = tokio::time::timeout(Duration::from_secs(5), handshake_task)
            .await
            .expect("guard timeout waiting for handshake to finish")
            .expect("handshake task joined");
        let err = handshake_result.expect_err("handshake unexpectedly succeeded");
        assert!(is_context_deadline_exceeded(&err), "handshake returned {err}");

        let state = client.control.state().lock();
        assert_eq!(
            state.read_deadline,
            Some(auth_deadline),
            "context cancellation rewrote protocol deadline: read={:?} write={:?} want={:?}",
            state.read_deadline,
            state.write_deadline,
            auth_deadline
        );
        assert_eq!(
            state.write_deadline,
            Some(auth_deadline),
            "context cancellation rewrote protocol deadline: read={:?} write={:?} want={:?}",
            state.read_deadline,
            state.write_deadline,
            auth_deadline
        );
    }

    #[tokio::test]
    async fn test_client_propagates_data_packet_id_exhaustion() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = new_test_client(&Arc::new(ClientConfig::default()), control_io_packet_adapter(client_io))
            .expect("test client");
        let keys = keymethod::KeyMaterial {
            send_cipher_key: vec![0x11; 16],
            send_hmac_key: vec![0x22; 64],
            recv_cipher_key: vec![0x33; 16],
            recv_hmac_key: vec![0x44; 64],
        };
        let data =
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 0, 0).expect("data channel");
        data.set_send_packet_id(data::DATA_PACKET_ID_REKEY_THRESHOLD);
        client.install_data_channel(Arc::new(data));

        let ctx = CancellationToken::new();
        let err = client.write_ip_packet(&ctx, &[0x45, 0, 0, 20]).await.expect_err("exhausted packet wrote");
        assert!(error_is::<data::ErrDataPacketIDExhausted>(&err), "exhausted packet returned {err}");

        let read_ctx =
            CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_millis(20));
        let leaked = server_io.read_packet(&read_ctx).await;
        assert!(leaked.is_err(), "exhausted packet reached transport: {:?}", leaked.ok());
    }

    #[tokio::test]
    async fn test_send_soft_reset_rotates_key_id() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), true).expect("client tls-crypt"));
        let client = ControlChannel::new(client_io, Some(client_crypt), packet::SessionID(*b"client01"));
        client.set_remote_session_id(packet::SessionID(*b"server01"));
        client.set_clock(Arc::new(|| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(1_714_567_890, 0).expect("fixed clock timestamp")
        }));

        let ctx = CancelContext::background();
        client.send(&ctx, packet::P_CONTROL_V1, b"msg1").await.expect("send msg1");
        client.send(&ctx, packet::P_CONTROL_V1, b"msg2").await.expect("send msg2");
        assert_eq!(client.key_id(), 0, "expected initial keyID=0");
        assert_eq!(client.state().lock().send_message, 2, "expected sendMessage=2");
        assert_eq!(client.pending_messages(), 2, "expected 2 pending messages");

        let _ = client.rotate_key_id();
        client.send_soft_reset(&ctx).await.expect("send soft reset");
        assert_eq!(client.key_id(), 1, "expected keyID=1 after soft reset");
        assert_eq!(client.state().lock().send_message, 1, "expected sendMessage=1 after soft reset");
        assert_eq!(client.state().lock().recv_message, 0, "expected recvMessage=0 after soft reset");
        assert_eq!(client.pending_messages(), 1, "expected 1 pending message (soft reset)");

        for i in 0..3 {
            server_io.read_packet(&ctx).await.unwrap_or_else(|err| panic!("failed to drain packet {i}: {err}"));
        }
    }

    #[tokio::test]
    async fn test_classify_watch_accepts_next_epoch_soft_reset() {
        let server_id = packet::SessionID(*b"server01");
        let (client_io, _server_io) = new_memory_packet_pair();
        let client_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), true).expect("client tls-crypt"));
        let client = ControlChannel::new(client_io, Some(client_crypt), packet::SessionID(*b"client01"));
        client.set_remote_session_id(server_id);

        let pkt_next = ControlPacket {
            opcode: packet::P_CONTROL_SOFT_RESET_V1,
            key_id: 1,
            local_session: server_id,
            ..Default::default()
        };
        let (soft_reset, valid) = client.classify_watch_packet_locked(&pkt_next);
        assert!(soft_reset && valid, "expected next-epoch soft reset keyID=1 to be accepted when current keyID=0");

        let pkt_same = ControlPacket {
            opcode: packet::P_CONTROL_SOFT_RESET_V1,
            key_id: 0,
            local_session: server_id,
            ..Default::default()
        };
        let (soft_reset, valid) = client.classify_watch_packet_locked(&pkt_same);
        assert!(!soft_reset && !valid, "expected soft reset with same keyID=0 to be rejected when current keyID=0");

        client.adopt_key_id(1);
        let pkt_stale = ControlPacket {
            opcode: packet::P_CONTROL_SOFT_RESET_V1,
            key_id: 0,
            local_session: server_id,
            ..Default::default()
        };
        let (soft_reset, valid) = client.classify_watch_packet_locked(&pkt_stale);
        assert!(!soft_reset && !valid, "expected stale soft reset keyID=0 to be rejected when current keyID=1");

        let pkt_next2 = ControlPacket {
            opcode: packet::P_CONTROL_SOFT_RESET_V1,
            key_id: 2,
            local_session: server_id,
            ..Default::default()
        };
        let (soft_reset, valid) = client.classify_watch_packet_locked(&pkt_next2);
        assert!(soft_reset && valid, "expected next-epoch soft reset keyID=2 to be accepted when current keyID=1");

        let pkt_bad_msg = ControlPacket {
            opcode: packet::P_CONTROL_SOFT_RESET_V1,
            key_id: 2,
            message_id: 5,
            local_session: server_id,
            ..Default::default()
        };
        let (soft_reset, valid) = client.classify_watch_packet_locked(&pkt_bad_msg);
        assert!(!soft_reset && !valid, "expected soft reset with message id 5 to be rejected");
    }

    #[tokio::test]
    async fn test_data_lock_protects_data_channel_swap() {
        let mut config = ClientConfig {
            remote_host: "1.2.3.4".to_owned(),
            remote_port: 1194,
            ca: TEST_CERT.as_bytes().to_vec(),
            cipher: config::CIPHER_AES_128_GCM.to_owned(),
            auth: config::AUTH_SHA256.to_owned(),
            username: "testuser".to_owned(),
            password: "testpass".to_owned(),
            ..Default::default()
        };
        config.prepare().expect("prepare config");
        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(&Arc::new(config), control_io_packet_adapter(client_io)).expect("test client");

        let ctx = CancellationToken::new();
        let cancel_ctx = ctx.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel_ctx.cancel();
        });
        let _err =
            client.read_ip_packet(&ctx).await.expect_err("expected error from ReadIPPacket when data channel is nil");
        cancel_task.await.expect("cancel task joined");
    }

    #[tokio::test]
    async fn test_next_key_id_follows_open_vpn_sequence() {
        let mut got = 0u8;
        for (i, want) in [1u8, 2, 3, 4, 5, 6, 7, 1, 2].into_iter().enumerate() {
            got = control::next_key_id(got);
            assert_eq!(got, want, "step {}", i + 1);
        }
    }

    #[tokio::test]
    async fn test_soft_reset_advances_open_vpn_key_id() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), true).expect("client tls-crypt"));
        let client = ControlChannel::new(client_io, Some(client_crypt), packet::SessionID(*b"client01"));

        assert_eq!(client.key_id(), 0, "initial key ID");
        let _ = client.rotate_key_id();
        assert_eq!(client.key_id(), 1, "first soft reset key ID");
        let _ = client.rotate_key_id();
        assert_eq!(client.key_id(), 2, "second soft reset key ID");
    }

    #[tokio::test]
    async fn test_rekey_keeps_old_outbound_even_if_never_sent() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { username: "u".to_owned(), password: "p".to_owned(), ..Default::default() }),
            control_io_packet_adapter(client_io),
        )
        .expect("test client");

        let keys = rekey_test_key_material();
        let initial = Arc::new(
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 0)
                .expect("initial data channel"),
        );
        let rekeyed = Arc::new(
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 1)
                .expect("rekeyed data channel"),
        );
        client.install_data_channel(Arc::clone(&initial));
        client.install_data_channel(Arc::clone(&rekeyed));

        let ctx = CancellationToken::new();
        client.write_data_packet(&ctx, &[0x45, 0, 0, 20], false).await.expect("write data packet");
        let pkt = server_io.read_packet(&CancelContext::background()).await.expect("data packet");
        let (_, key_id) = parse_opcode_key_id(pkt[0]);
        assert_eq!(key_id, 0, "outbound key ID after quiet rekey want 0 (old key kept)");
    }

    #[tokio::test]
    async fn test_failed_decrypt_does_not_promote() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { username: "u".to_owned(), password: "p".to_owned(), ..Default::default() }),
            control_io_packet_adapter(client_io),
        )
        .expect("test client");

        let keys = rekey_test_key_material();
        let initial = Arc::new(
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 0)
                .expect("initial data channel"),
        );
        let rekeyed = Arc::new(
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 1)
                .expect("rekeyed data channel"),
        );
        client.install_data_channel(Arc::clone(&initial));
        client.install_data_channel(Arc::clone(&rekeyed));

        let bad = [packet::opcode_key_id(packet::P_DATA_V2, 1)];
        assert!(client.decrypt_data_packet(&bad).is_err(), "malformed new-key packet unexpectedly decrypted");
        assert!(!rekeyed.peer_active(), "failed decryption latched peer evidence");

        let ctx = CancellationToken::new();
        client.write_data_packet(&ctx, &[0x45, 0, 0, 20], false).await.expect("write data packet");
        let pkt = server_io.read_packet(&CancelContext::background()).await.expect("data packet");
        let (_, key_id) = parse_opcode_key_id(pkt[0]);
        assert_eq!(key_id, 0, "outbound key ID after failed decrypt want 0");
    }

    #[tokio::test]
    async fn test_outbound_promotes_after_auth_deferred_expire() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { username: "u".to_owned(), password: "p".to_owned(), ..Default::default() }),
            control_io_packet_adapter(client_io),
        )
        .expect("test client");

        let keys = rekey_test_key_material();
        let initial = Arc::new(
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 0)
                .expect("initial data channel"),
        );
        let rekeyed = Arc::new(
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 1)
                .expect("rekeyed data channel"),
        );
        client.install_data_channel(Arc::clone(&initial));
        client.install_data_channel(Arc::clone(&rekeyed));

        let ctx = CancellationToken::new();
        let read_ctx = CancelContext::background();
        client.write_data_packet(&ctx, &[0x45, 0, 0, 20], false).await.expect("write data packet");
        let pkt = server_io.read_packet(&read_ctx).await.expect("data packet");
        let (_, key_id) = parse_opcode_key_id(pkt[0]);
        assert_eq!(key_id, 0, "outbound before window want 0");

        client.data.write().outbound_start =
            Some(tokio::time::Instant::now() - AUTH_DEFERRED_EXPIRE - Duration::from_secs(1));

        client.write_data_packet(&ctx, &[0x45, 0, 0, 20], false).await.expect("write data packet");
        let pkt = server_io.read_packet(&read_ctx).await.expect("data packet");
        let (_, key_id) = parse_opcode_key_id(pkt[0]);
        assert_eq!(key_id, 1, "outbound after window want 1");
    }

    #[tokio::test]
    async fn test_auth_pending_timeout_does_not_extend_outbound_selection() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { username: "u".to_owned(), password: "p".to_owned(), ..Default::default() }),
            control_io_packet_adapter(client_io),
        )
        .expect("test client");

        let keys = rekey_test_key_material();
        let initial = Arc::new(
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 0)
                .expect("initial data channel"),
        );
        let rekeyed = Arc::new(
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 1)
                .expect("rekeyed data channel"),
        );
        client.install_data_channel(Arc::clone(&initial));
        client.control.adopt_key_id(1);
        let mut reply = PushReply { auth_pending_timeout: Duration::from_secs(300), ..Default::default() };
        client.apply_auth_pending_timeout(&mut reply);
        client.install_data_channel(Arc::clone(&rekeyed));

        let deferred = {
            let mut state = client.data.write();
            state.outbound_start = Some(tokio::time::Instant::now() - AUTH_DEFERRED_EXPIRE - Duration::from_secs(1));
            state.deferred_until
        };
        let deferred = deferred.expect("AUTH_PENDING deadline retained");
        assert!(
            deferred.saturating_duration_since(tokio::time::Instant::now()) >= Duration::from_secs(290),
            "epoch install discarded AUTH_PENDING deadline"
        );

        let ctx = CancellationToken::new();
        client.write_data_packet(&ctx, &[0x45, 0, 0, 20], false).await.expect("write data packet");
        let pkt = server_io.read_packet(&CancelContext::background()).await.expect("data packet");
        let (_, key_id) = parse_opcode_key_id(pkt[0]);
        assert_eq!(key_id, 1, "AUTH_PENDING extended outbound selection");
    }

    #[tokio::test]
    async fn test_retiring_window_anchored_at_accepted_soft_reset() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { transition_window: 10 * murmur_common::time::SECOND, ..Default::default() }),
            control_io_packet_adapter(client_io),
        )
        .expect("test client");
        let initial = Arc::new(data::data_channel_with_key_id(0));
        let rekeyed = Arc::new(data::data_channel_with_key_id(1));
        client.install_data_channel(Arc::clone(&initial));

        let accepted_at = tokio::time::Instant::now() - TOKEN_PUSH_READ_TIMEOUT;
        let reset = ControlPacket { received_at: Some(accepted_at), ..Default::default() };
        let anchored = client.retiring_window_deadline(Some(&reset));
        assert_eq!(anchored, accepted_at + client.transition_window(), "stashed reset shifted transition deadline");

        client.run_ctx.cancel(None);
        assert!(
            client.renegotiate(None, Some(anchored)).await.is_err(),
            "renegotiate unexpectedly succeeded with a canceled run context"
        );

        client.install_data_channel(Arc::clone(&rekeyed));
        let state = client.data.read();
        assert_eq!(state.retiring_expiry, Some(anchored), "transition window shifted after accepted reset");
        assert_eq!(state.pending_retiring_expiry, None, "installed transition deadline remained pending");
    }

    #[tokio::test]
    async fn test_explicit_zero_transition_window() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { transition_window_set: true, ..Default::default() }),
            control_io_packet_adapter(client_io),
        )
        .expect("test client");
        assert_eq!(client.transition_window(), Duration::ZERO, "explicit zero transition window became non-zero");

        let (default_io, _default_server_io) = new_memory_packet_pair();
        let default_client = new_test_client(&Arc::new(ClientConfig::default()), control_io_packet_adapter(default_io))
            .expect("default test client");
        assert_eq!(default_client.transition_window(), TRANSITION_WINDOW, "omitted transition window");
    }

    #[tokio::test]
    async fn test_retiring_expiry_forces_outbound_promotion() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { transition_window: 10 * murmur_common::time::SECOND, ..Default::default() }),
            control_io_packet_adapter(client_io),
        )
        .expect("test client");
        let initial = Arc::new(
            DataChannel::new(
                &rekey_test_key_material_filled(0x11),
                config::CIPHER_AES_128_GCM,
                config::AUTH_SHA256,
                7,
                0,
            )
            .expect("initial data channel"),
        );
        let rekeyed = Arc::new(
            DataChannel::new(
                &rekey_test_key_material_filled(0x22),
                config::CIPHER_AES_128_GCM,
                config::AUTH_SHA256,
                7,
                1,
            )
            .expect("rekeyed data channel"),
        );
        client.install_data_channel(Arc::clone(&initial));
        client.install_data_channel(Arc::clone(&rekeyed));
        {
            let mut state = client.data.write();
            state.retiring_expiry = Some(tokio::time::Instant::now() - Duration::from_millis(1));
            state.outbound_start = Some(tokio::time::Instant::now());
        }

        let ctx = CancellationToken::new();
        client.write_data_packet(&ctx, &[0x45, 0, 0, 20], false).await.expect("write data packet");
        let pkt = server_io.read_packet(&CancelContext::background()).await.expect("data packet");
        let (_, key_id) = parse_opcode_key_id(pkt[0]);
        assert_eq!(key_id, 1, "expired retiring key remained outbound");
    }

    #[tokio::test]
    async fn test_standalone_auth_pending_keeps_token_probe_short() {
        let conn = ChunkConn {
            data: vec![
                b"AUTH_PENDING,timeout 60\x00".to_vec(),
                Vec::new(),
                b"PUSH_REPLY,auth-token SESS_ID_late\x00".to_vec(),
            ],
            errs: vec![None, Some(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")), None],
            ..Default::default()
        };
        let (reply, rest) =
            read_token_push_reply(&conn, &[], &[]).await.expect("standalone AUTH_PENDING transport read");
        assert_eq!(*conn.idx.lock(), 2, "standalone AUTH_PENDING waited for optional final push");
        let reply = reply.expect("standalone AUTH_PENDING metadata lost");
        assert_eq!(reply.auth_pending_timeout, Duration::from_secs(60), "standalone AUTH_PENDING metadata lost");
        assert!(!reply.has_push_reply, "standalone AUTH_PENDING metadata lost");
        assert!(rest.is_empty(), "unexpected rest: {rest:?}");
        let deadlines = conn.operation_deadlines.lock();
        assert!(!deadlines.is_empty(), "AUTH_PENDING transport deadline not propagated");
        let first = deadlines[0].expect("recorded transport deadline");
        assert!(
            first.saturating_duration_since(tokio::time::Instant::now()) >= Duration::from_secs(50),
            "AUTH_PENDING transport deadline not propagated"
        );
    }

    #[tokio::test]
    async fn test_read_token_push_reply_promotes_dynamic_wait() {
        let conn = ChunkConn {
            data: vec![
                b"PUSH_REPLY,route 10.1.0.0 255.255.0.0,push-continuation 2\x00".to_vec(),
                Vec::new(),
                b"PUSH_REPLY,route 10.2.0.0 255.255.0.0\x00".to_vec(),
            ],
            errs: vec![None, Some(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")), None],
            ..Default::default()
        };
        let (reply, _rest) = read_token_push_reply(&conn, &[], &[]).await.expect("continuation transport read");
        assert_eq!(*conn.idx.lock(), 3, "reader returned before final continuation");
        let reply = reply.expect("continuation state lost");
        assert_eq!(reply.routes.len(), 2, "continuation state lost");
        assert_eq!(reply.routes[0].to_string(), "10.1.0.0/16");
        assert_eq!(reply.routes[1].to_string(), "10.2.0.0/16");
    }

    #[tokio::test]
    async fn test_read_token_push_reply_extends_reliable_ack_deadline() {
        let (client_control, server_control) = new_test_channels();
        client_control.set_remote_session_id(server_control.local_session_id());
        server_control.set_remote_session_id(client_control.local_session_id());
        let conn = ControlConn::new(Arc::clone(&client_control));
        conn.unsafe_feed(b"AUTH_PENDING,timeout 1\x00");
        conn.set_deadline(Some(tokio::time::Instant::now() - Duration::from_secs(1))).expect("set stale deadline");
        server_control
            .send(
                &CancelContext::background(),
                packet::P_CONTROL_V1,
                b"PUSH_REPLY,auth-token SESS_ID_after_deadline\x00",
            )
            .await
            .expect("send push reply");

        let reader = ControlConnPushReader(conn);
        let (reply, rest) = read_token_push_reply(&reader, &[], &[])
            .await
            .expect("extended read could not deliver final reliable packet");
        let reply = reply.expect("final PUSH_REPLY not delivered");
        assert_eq!(reply.auth_token_pass, "SESS_ID_after_deadline", "final PUSH_REPLY not delivered");
        assert!(rest.is_empty(), "unexpected rest: {rest:?}");
    }

    #[tokio::test]
    async fn test_auth_pending_deadline_anchored_at_tls_establishment() {
        let (pending, _rest, ok) = take_push_reply(b"AUTH_PENDING,timeout 1\x00");
        assert!(!ok, "AUTH_PENDING intermediate state malformed");
        let mut pending = pending.expect("AUTH_PENDING intermediate state malformed");
        assert_eq!(pending.auth_pending_until, None, "AUTH_PENDING intermediate state malformed");

        let established_at = tokio::time::Instant::now() - Duration::from_millis(150);
        anchor_auth_pending_deadline(&mut pending, Some(established_at));
        let want_deadline = established_at + Duration::from_secs(1);
        assert_eq!(pending.auth_pending_until, Some(want_deadline), "AUTH_PENDING deadline");

        let final_reply =
            parse_push_reply_inner("PUSH_REPLY,auth-token SESS_ID_anchored").expect("parse final push reply");
        let mut merged = merge_push_reply(Some(pending), Some(final_reply)).expect("merged push reply");
        assert_eq!(merged.auth_pending_until, Some(want_deadline), "AUTH_PENDING deadline moved during final merge");

        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(&Arc::new(ClientConfig::default()), control_io_packet_adapter(client_io))
            .expect("test client");
        client.state.lock().control_established_at = Some(established_at);
        client.apply_auth_pending_timeout(&mut merged);
        let staged = client.data.read().pending_deferred_until;
        assert_eq!(staged, Some(want_deadline), "AUTH_PENDING timeout restarted after final PUSH_REPLY");
    }

    #[tokio::test]
    async fn test_auth_pending_update_can_shorten_deadline() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(&Arc::new(ClientConfig::default()), control_io_packet_adapter(client_io))
            .expect("test client");

        let mut long = parse_auth_pending_timeout("AUTH_PENDING,timeout 60").expect("long timeout");
        let mut short = parse_auth_pending_timeout("AUTH_PENDING,timeout 1").expect("short timeout");
        client.apply_auth_pending_timeout(&mut long);
        client.apply_auth_pending_timeout(&mut short);
        let shortest = short.auth_pending_until.expect("short AUTH_PENDING deadline");
        {
            let state = client.control.state().lock();
            assert_eq!(
                state.read_deadline,
                Some(shortest),
                "later AUTH_PENDING did not replace transport read deadline"
            );
            assert_eq!(
                state.write_deadline,
                Some(shortest),
                "later AUTH_PENDING did not replace transport write deadline"
            );
        }
        assert_eq!(
            client.data.read().pending_deferred_until,
            Some(shortest),
            "later AUTH_PENDING did not shorten staged deadline"
        );
        assert_eq!(client.auth_pending_deadline(), Some(shortest), "effective AUTH_PENDING deadline");

        let initial = Arc::new(
            DataChannel::new(
                &rekey_test_key_material_filled(0x11),
                config::CIPHER_AES_128_GCM,
                config::AUTH_SHA256,
                7,
                0,
            )
            .expect("initial data channel"),
        );
        let active = Arc::new(
            DataChannel::new(
                &rekey_test_key_material_filled(0x22),
                config::CIPHER_AES_128_GCM,
                config::AUTH_SHA256,
                7,
                1,
            )
            .expect("active data channel"),
        );
        client.install_data_channel(Arc::clone(&initial));
        client.control.adopt_key_id(1);
        client.apply_auth_pending_timeout(&mut long);
        let mut shorter = PushReply {
            auth_pending_timeout: Duration::from_secs(1),
            auth_pending_until: Some(tokio::time::Instant::now() - Duration::from_millis(1)),
            ..Default::default()
        };
        client.apply_auth_pending_timeout(&mut shorter);
        client.install_data_channel(Arc::clone(&active));

        let (active_deferred, active_outbound) = {
            let state = client.data.read();
            (state.deferred_until, state.outbound_key.clone())
        };
        assert!(
            active_deferred.expect("active deferred deadline") < tokio::time::Instant::now(),
            "shorter AUTH_PENDING deadline not transferred to active epoch"
        );
        assert!(
            active_outbound.is_some_and(|outbound| Arc::ptr_eq(&outbound, &initial)),
            "AUTH_PENDING metadata changed independent outbound selection"
        );

        let conn = ChunkConn {
            data: vec![
                b"AUTH_PENDING,timeout 60\x00".to_vec(),
                b"AUTH_PENDING,timeout 1\x00".to_vec(),
                b"PUSH_REPLY,auth-token SESS_ID_short\x00".to_vec(),
            ],
            ..Default::default()
        };
        read_token_push_reply(&conn, &[], &[]).await.expect("short AUTH_PENDING transport read");
        let deadlines = conn.operation_deadlines.lock().clone();
        assert!(deadlines.len() >= 2, "AUTH_PENDING updates not propagated");
        let first = deadlines[0].expect("first transport deadline");
        let second = deadlines[1].expect("second transport deadline");
        assert!(second < first, "reader ignored shorter AUTH_PENDING: first={first:?} second={second:?}");
    }

    #[tokio::test]
    async fn test_consume_parked_rekey_push_feeds_control_conn_in_order() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(&Arc::new(ClientConfig::default()), control_io_packet_adapter(client_io))
            .expect("test client");
        client.control.state().lock().parked_tls = vec![b"first".to_vec(), b"second".to_vec()];
        client.consume_parked_rekey_push().await.expect("consume parked rekey push");
        let got = client.control_conn.read_buf();
        assert_eq!(got, b"firstsecond".to_vec(), "parked TLS bytes");
        assert_eq!(client.control.state().lock().parked_tls.len(), 0, "parked TLS payloads not drained");
    }

    #[tokio::test]
    async fn test_consume_parked_rekey_push_clears_deadline() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(&Arc::new(ClientConfig::default()), control_io_packet_adapter(client_io))
            .expect("test client");
        client.state.lock().push = Some(PushReply { peer_id: 7, ..Default::default() });
        client.state.lock().leftover_tls =
            b"AUTH_PENDING,timeout 1\x00PUSH_REPLY,auth-token SESS_ID_parked\x00".to_vec();

        client.consume_parked_rekey_push().await.expect("consume parked rekey push");
        {
            let state = client.control.state().lock();
            assert_eq!(state.read_deadline, None, "successful parked push consume leaked read deadline");
            assert_eq!(state.write_deadline, None, "successful parked push consume leaked write deadline");
        }
        assert_eq!(client.state.lock().auth_pass, "SESS_ID_parked", "parked auth token was not consumed");
    }

    #[tokio::test]
    async fn test_consume_rekey_push_rejects_continuation_discovered_by_reader() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(&Arc::new(ClientConfig::default()), control_io_packet_adapter(client_io))
            .expect("test client");
        client.state.lock().push =
            Some(PushReply { peer_id: 7, auth_token_pass: "SESS_ID_old".to_owned(), ..Default::default() });
        let conn = Arc::new(ChunkConn::default());
        let reader = ContinuationDiscoveredReader { expected: Arc::clone(&conn) };

        let err = client
            .consume_rekey_push_from(Some(&*conn), &reader)
            .await
            .expect_err("reader-discovered continuation returned success");
        assert!(
            err.to_string().contains("continued push reply incomplete"),
            "reader-discovered continuation returned success: {err}"
        );
        {
            let state = client.state.lock();
            assert!(state.push_continuation_pending, "reader-discovered continuation state was not persisted");
            let pending = state.push_pending.as_ref().expect("reader-discovered partial push was not retained");
            assert_eq!(pending.push_continuation, 2, "reader-discovered partial push was not retained");
            assert_eq!(pending.routes.len(), 1, "reader-discovered partial push was not retained");
        }
        {
            let state = client.state.lock();
            let push = state.push.as_ref().expect("cached push");
            assert_eq!(push.auth_token_pass, "SESS_ID_old", "partial continuation was committed to active push");
            assert!(push.routes.is_empty(), "partial continuation was committed to active push");
        }
    }

    #[tokio::test]
    async fn test_consume_rekey_push_allows_auth_pending_without_final_push() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(&Arc::new(ClientConfig::default()), control_io_packet_adapter(client_io))
            .expect("test client");
        let initial = Arc::new(
            DataChannel::new(
                &rekey_test_key_material_filled(0x11),
                config::CIPHER_AES_128_GCM,
                config::AUTH_SHA256,
                7,
                0,
            )
            .expect("initial data channel"),
        );
        let rekeyed = Arc::new(
            DataChannel::new(
                &rekey_test_key_material_filled(0x22),
                config::CIPHER_AES_128_GCM,
                config::AUTH_SHA256,
                7,
                1,
            )
            .expect("rekeyed data channel"),
        );
        client.install_data_channel(Arc::clone(&initial));
        client.control.adopt_key_id(1);
        let established_at = tokio::time::Instant::now() - Duration::from_millis(150);
        client.state.lock().push = Some(PushReply {
            peer_id: 7,
            cipher: config::CIPHER_AES_128_GCM.to_owned(),
            auth_token_pass: String::new(),
            routes: vec!["10.8.0.0/24".parse().expect("test prefix")],
            ..Default::default()
        });
        client.state.lock().control_established_at = Some(established_at);

        let conn = Arc::new(ChunkConn::default());
        let pending = parse_auth_pending_timeout("AUTH_PENDING,timeout 1").expect("auth pending");
        let want_deadline = established_at + pending.auth_pending_timeout;
        let reader = AuthPendingReader { expected: Arc::clone(&conn), pending };

        client
            .consume_rekey_push_from(Some(&*conn), &reader)
            .await
            .expect("standalone AUTH_PENDING required a final PUSH_REPLY");

        {
            let state = client.state.lock();
            let push = state.push.as_ref().expect("cached push");
            assert_eq!(push.peer_id, 7, "cached push changed without a final PUSH_REPLY");
            assert_eq!(push.cipher, config::CIPHER_AES_128_GCM, "cached push changed without a final PUSH_REPLY");
            assert_eq!(push.routes.len(), 1, "cached push changed without a final PUSH_REPLY");
            assert_eq!(push.routes[0].to_string(), "10.8.0.0/24");
            assert!(
                state.push_pending.is_none() && !state.push_continuation_pending,
                "standalone AUTH_PENDING left incomplete push state"
            );
        }
        let pending_until = {
            let key_id = client.control.key_id();
            let state = client.data.read();
            assert!(state.pending_deferred_set, "AUTH_PENDING epoch deadline not retained");
            assert_eq!(state.pending_deferred_key_id, key_id, "AUTH_PENDING epoch deadline not retained");
            assert_eq!(
                state.pending_deferred_until,
                Some(want_deadline),
                "AUTH_PENDING epoch deadline not anchored at TLS establishment"
            );
            state.pending_deferred_until.expect("AUTH_PENDING epoch deadline not retained")
        };

        client.install_data_channel(Arc::clone(&rekeyed));
        {
            let state = client.data.read();
            assert!(
                state.data.as_ref().is_some_and(|data| Arc::ptr_eq(data, &rekeyed)),
                "valid deferred epoch was not installable"
            );
            assert!(
                state.outbound_key.as_ref().is_some_and(|outbound| Arc::ptr_eq(outbound, &initial)),
                "valid deferred epoch was not installable"
            );
            assert_eq!(
                state.deferred_until,
                Some(pending_until),
                "staged deferred deadline not transferred to installed epoch"
            );
        }
    }

    #[tokio::test]
    async fn test_standalone_auth_pending_does_not_complete_push() {
        let (bare_reply, _rest, bare_ok) = take_push_reply(b"AUTH_PENDING\x00");
        assert!(!bare_ok, "bare AUTH_PENDING alone completed PUSH parsing");
        assert_eq!(
            bare_reply.expect("bare AUTH_PENDING did not receive default timeout").auth_pending_timeout,
            AUTH_DEFERRED_EXPIRE,
            "bare AUTH_PENDING did not receive default timeout"
        );

        let (reply, rest, ok) = take_push_reply(b"AUTH_PENDING,timeout 300\x00");
        assert!(!ok, "AUTH_PENDING alone completed PUSH parsing");
        assert!(rest.is_empty(), "unexpected rest: {rest:?}");
        assert_eq!(
            reply.expect("AUTH_PENDING timeout not parsed").auth_pending_timeout,
            Duration::from_secs(300),
            "AUTH_PENDING timeout not parsed"
        );

        let (reply, _rest, ok) =
            take_push_reply(b"AUTH_PENDING,timeout 300\x00PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\x00");
        assert!(ok, "final PUSH_REPLY did not complete parsing");
        assert_eq!(
            reply.expect("merged push reply").auth_pending_timeout,
            Duration::from_secs(300),
            "AUTH_PENDING timeout lost during merge"
        );
    }

    #[tokio::test]
    async fn test_push_continuation_wire_order_and_cross_call() {
        let full = b"PUSH_REPLY,route 10.1.0.0 255.255.0.0,dhcp-option DNS 1.1.1.1,data-ciphers AES-256-GCM,push-continuation 2\x00PUSH_REPLY,route 10.2.0.0 255.255.0.0,dhcp-option DNS 8.8.8.8,data-ciphers AES-128-GCM\x00";
        let (reply, _rest, ok) = take_push_reply(full);
        assert!(ok, "coalesced continuation did not complete");
        let reply = reply.expect("coalesced continuation reply");
        let routes: Vec<String> = reply.routes.iter().map(ToString::to_string).collect();
        assert_eq!(routes, vec!["10.1.0.0/16", "10.2.0.0/16"], "route wire order changed");
        let dns: Vec<String> = reply.dns.iter().map(ToString::to_string).collect();
        assert_eq!(dns, vec!["1.1.1.1", "8.8.8.8"], "DNS wire order changed");
        assert_eq!(reply.data_ciphers, vec!["AES-256-GCM", "AES-128-GCM"], "cipher wire order changed");

        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { username: "u".to_owned(), password: "p".to_owned(), ..Default::default() }),
            control_io_packet_adapter(client_io),
        )
        .expect("test client");
        client.state.lock().push = Some(PushReply { peer_id: 7, ..Default::default() });
        client.state.lock().leftover_tls = b"PUSH_REPLY,route 10.1.0.0 255.255.0.0,push-continuation 2\x00".to_vec();
        client.consume_rekey_push().await.expect("consume intermediate push");
        {
            let state = client.state.lock();
            let pending = state.push_pending.as_ref().expect("intermediate continuation not retained");
            assert_eq!(pending.routes.len(), 1, "intermediate continuation not retained");
        }

        client.state.lock().leftover_tls = b"PUSH_REPLY,route 10.2.0.0 255.255.0.0\x00".to_vec();
        client.consume_rekey_push().await.expect("consume final push");
        {
            let state = client.state.lock();
            let push = state.push.as_ref().expect("cached push");
            let routes: Vec<String> = push.routes.iter().map(ToString::to_string).collect();
            assert_eq!(routes, vec!["10.1.0.0/16", "10.2.0.0/16"], "intermediate continuation discarded across calls");
        }
    }

    #[tokio::test]
    async fn test_take_push_reply_continuation() {
        let intermediate = b"PUSH_REPLY,route 10.2.0.0 255.255.0.0,push-continuation 2\x00";
        let (reply, _rest, ok) = take_push_reply(intermediate);
        assert!(!ok, "intermediate push-continuation segment treated as complete");
        assert_eq!(
            reply.expect("intermediate segment routes not parsed").routes.len(),
            1,
            "intermediate segment routes not parsed"
        );

        let full = b"PUSH_REPLY,route 10.2.0.0 255.255.0.0,push-continuation 2\x00PUSH_REPLY,dhcp-option DNS 8.8.8.8,ifconfig 10.8.0.2 255.255.255.0,route 10.3.0.0 255.255.0.0\x00";
        let (reply, _rest, ok) = take_push_reply(full);
        assert!(ok, "final push-continuation segment not complete");
        let reply = reply.expect("final continuation reply");
        assert_eq!(reply.routes.len(), 2, "continuation routes lost");
        assert_eq!(reply.dns.len(), 1, "continuation dns lost");
        assert_eq!(reply.dns[0].to_string(), "8.8.8.8");
        assert_eq!(reply.prefixes.len(), 1, "continuation ifconfig lost");
    }

    #[tokio::test]
    async fn test_outbound_key_stays_lame_duck_until_peer_evidence() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { username: "u".to_owned(), password: "p".to_owned(), ..Default::default() }),
            control_io_packet_adapter(client_io),
        )
        .expect("test client");

        let keys = rekey_test_key_material();
        let initial = Arc::new(
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 0)
                .expect("initial data channel"),
        );
        let rekeyed = Arc::new(
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 1)
                .expect("rekeyed data channel"),
        );
        client.install_data_channel(Arc::clone(&initial));

        let ctx = CancellationToken::new();
        let read_ctx = CancelContext::background();
        client.write_data_packet(&ctx, &[0x45, 0, 0, 20], false).await.expect("write first data packet");
        server_io.read_packet(&read_ctx).await.expect("first data packet");
        client.install_data_channel(Arc::clone(&rekeyed));

        client.write_data_packet(&ctx, &[0x45, 0, 0, 20], false).await.expect("write rekeyed data packet");
        let pkt = server_io.read_packet(&read_ctx).await.expect("rekeyed data packet");
        let (_, key_id) = parse_opcode_key_id(pkt[0]);
        assert_eq!(key_id, 0, "outbound key ID after rekey want 0 (lame duck)");

        let peer_pkt = rekeyed.encrypt(&[0x45, 0, 0, 20]).expect("encrypt peer packet");
        client.decrypt_data_packet(&peer_pkt).expect("decrypt new-key packet");

        client.write_data_packet(&ctx, &[0x45, 0, 0, 20], false).await.expect("write promoted data packet");
        let pkt = server_io.read_packet(&read_ctx).await.expect("promoted data packet");
        let (_, key_id) = parse_opcode_key_id(pkt[0]);
        assert_eq!(key_id, 1, "outbound key ID after evidence want 1");
    }

    #[tokio::test]
    async fn test_merge_push_reply_continuation() {
        let seg1 = PushReply {
            dns: vec!["8.8.8.8".parse().expect("test address")],
            peer_id: 7,
            cipher: "AES-128-GCM".to_owned(),
            ..Default::default()
        };
        let seg2 = PushReply {
            peer_id: data::PEER_ID_UNSET,
            prefixes: vec!["10.8.0.2/24".parse().expect("test prefix")],
            routes: vec!["0.0.0.0/1".parse().expect("test prefix")],
            redirect: true,
            ..Default::default()
        };
        let merged = merge_push_reply(Some(seg1.clone()), Some(seg2)).expect("merged push reply");
        assert_eq!(merged.dns.len(), 1, "DNS not inherited");
        assert_eq!(merged.dns[0], seg1.dns[0], "DNS not inherited");
        assert_eq!(merged.peer_id, 7, "PeerID not inherited");
        assert_eq!(merged.cipher, "AES-128-GCM", "Cipher not inherited");
        assert_eq!(merged.prefixes.len(), 1, "seg2 fields missing");
        assert_eq!(merged.routes.len(), 1, "seg2 fields missing");
        assert!(merged.redirect, "Redirect not inherited");
    }

    #[tokio::test]
    async fn test_rekey_data_header_uses_active_key_id() {
        let keys = keymethod::KeyMaterial {
            send_cipher_key: vec![0x11; 16],
            send_hmac_key: vec![0x22; 64],
            recv_cipher_key: vec![0x33; 16],
            recv_hmac_key: vec![0x44; 64],
        };
        let initial = DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 0)
            .expect("initial data channel");
        let rekeyed = DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 1)
            .expect("rekeyed data channel");

        let first = initial.encrypt(&[0x45, 0, 0, 20]).expect("encrypt initial packet");
        let (_, key_id) = parse_opcode_key_id(first[0]);
        assert_eq!(key_id, 0, "initial data packet key ID");

        let second = rekeyed.encrypt(&[0x45, 0, 0, 20]).expect("encrypt rekeyed packet");
        let (_, key_id) = parse_opcode_key_id(second[0]);
        assert_eq!(key_id, 1, "rekeyed data packet key ID");
    }

    #[tokio::test]
    async fn test_record_complete_rejects_fragmented_km2() {
        let mut packet: Vec<u8> = Vec::new();
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.push(keymethod::KEY_METHOD_2);
        packet.extend_from_slice(&[1u8; 32]);
        packet.extend_from_slice(&[2u8; 32]);
        marshal_open_vpn_string(&mut packet, "server-options");
        marshal_open_vpn_string(&mut packet, "user");

        let (complete, _) = record_complete(&packet);
        assert!(!complete, "fragmented record reported complete");

        marshal_open_vpn_string(&mut packet, "pass");
        marshal_open_vpn_string(&mut packet, "IV_VER=server\n");
        let (complete, _) = record_complete(&packet);
        assert!(complete, "complete record not reported complete");

        let (complete, _) = record_complete(&packet[..packet.len() - 1]);
        assert!(!complete, "truncated record reported complete");
    }

    #[tokio::test]
    async fn test_parse_shortened_km2_only_when_tls_control_follows() {
        let mut packet: Vec<u8> = Vec::new();
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.push(keymethod::KEY_METHOD_2);
        packet.extend_from_slice(&[1u8; 32]);
        packet.extend_from_slice(&[2u8; 32]);
        marshal_open_vpn_string(&mut packet, "server-options");
        packet.extend_from_slice(b"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\x00");

        assert!(
            parse_server_key_method2_record_consumed(&packet).is_ok(),
            "shortened record with PUSH_REPLY should parse"
        );

        let mut frag: Vec<u8> = Vec::new();
        frag.extend_from_slice(&0u32.to_be_bytes());
        frag.push(keymethod::KEY_METHOD_2);
        frag.extend_from_slice(&[1u8; 32]);
        frag.extend_from_slice(&[2u8; 32]);
        marshal_open_vpn_string(&mut frag, "server-options");
        marshal_open_vpn_string(&mut frag, "username");
        frag.truncate(frag.len() - 1);
        assert!(parse_server_key_method2_record_consumed(&frag).is_err(), "truncated trailing field should not parse");

        let mut full = packet.clone();
        marshal_open_vpn_string(&mut full, "user");
        marshal_open_vpn_string(&mut full, "pass");
        marshal_open_vpn_string(&mut full, "IV_VER=server\n");
        assert!(parse_server_key_method2_record_consumed(&full).is_ok(), "standard full record should parse");
    }

    #[tokio::test]
    async fn test_take_push_reply_requires_terminator() {
        let frag = b"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0";
        let (_reply, _rest, ok) = take_push_reply(frag);
        assert!(!ok, "unterminated PUSH_REPLY was accepted");

        let mut full = frag.to_vec();
        full.extend_from_slice(b",route-gateway 10.8.0.1\x00");
        let (reply, rest, ok) = take_push_reply(&full);
        assert!(ok, "terminated PUSH_REPLY was not accepted");
        assert_eq!(reply.expect("terminated push reply").prefixes.len(), 1, "prefixes not parsed");
        assert!(rest.is_empty(), "unexpected leftover: {rest:?}");
    }

    #[tokio::test]
    async fn test_parse_push_reply_auth_token() {
        let reply = push::parse_push_reply(
            "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,auth-token SESS_ID_tok,auth-token-user dGVzdA==",
        )
        .expect("parse push reply");
        let (user, pass) = reply.auth_token().expect("unexpected auth-token");
        assert_eq!(pass, "SESS_ID_tok", "unexpected auth-token pass");
        assert_eq!(user, "test", "unexpected auth-token user");

        let reply = push::parse_push_reply(
            "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,auth-token SESS_ID_tok,auth-token-user dGVzdA",
        )
        .expect("parse push reply");
        let (user, pass) = reply.auth_token().expect("unexpected auth-token");
        assert_eq!(pass, "SESS_ID_tok", "unexpected unpadded auth-token pass");
        assert_eq!(user, "test", "unexpected unpadded auth-token user");
    }

    #[tokio::test]
    async fn test_stashed_soft_reset_is_not_swallowed_by_control_read() {
        let (client, server) = new_test_channels();
        client.set_remote_session_id(server.local_session_id());
        server.set_remote_session_id(client.local_session_id());

        let ctx = CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_secs(2));

        client.adopt_key_id(1);
        server.adopt_key_id(2);
        server.send(&ctx, packet::P_CONTROL_SOFT_RESET_V1, &[]).await.expect("send soft reset");

        let read_ctx =
            CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_millis(80));
        let read = client.read(&read_ctx).await;
        assert!(read.is_err(), "Read delivered key={:?}, want timeout", read.ok().map(|pkt| pkt.key_id));

        let got = client.wait_for_soft_reset(&ctx).await.expect("wait for soft reset");
        assert_eq!(got.opcode, packet::P_CONTROL_SOFT_RESET_V1, "stashed packet opcode");
        assert_eq!(got.key_id, 2, "stashed packet key");
    }

    // ---- rekey tests (b) ----
    fn rekey_b_unix(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(secs, 0).expect("valid test timestamp")
    }

    fn rekey_b_data_channel(key_id: u8) -> Arc<DataChannel> {
        let keys = keymethod::KeyMaterial {
            send_cipher_key: vec![0x11; 16],
            send_hmac_key: vec![0x22; keymethod::MAX_HMAC_KEY_LENGTH],
            recv_cipher_key: vec![0x11; 16],
            recv_hmac_key: vec![0x22; keymethod::MAX_HMAC_KEY_LENGTH],
        };
        Arc::new(
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, key_id).expect("data channel"),
        )
    }

    #[tokio::test]
    async fn test_read_all_keeps_pending_soft_reset() {
        let (client, server) = new_test_channels();
        client.set_remote_session_id(server.local_session_id());
        server.set_remote_session_id(client.local_session_id());

        let ctx = CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_secs(2));

        client.adopt_key_id(1);
        server.adopt_key_id(2);
        server.send(&ctx, packet::P_CONTROL_SOFT_RESET_V1, &[]).await.expect("server soft reset");

        let read_ctx =
            CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_millis(80));
        let _ = client.read(&read_ctx).await;
        assert!(client.state().lock().pending_soft_reset.is_some(), "soft reset was not stashed in pendingSoftReset");

        let _ = client.read_all();
        assert!(client.state().lock().pending_soft_reset.is_some(), "ReadAll consumed the pending soft reset");

        let got = client.wait_for_soft_reset(&ctx).await.expect("soft reset lost");
        assert!(
            got.opcode == packet::P_CONTROL_SOFT_RESET_V1 && got.key_id == 2,
            "soft reset lost: got {} key={}",
            got.opcode,
            got.key_id
        );
    }

    #[tokio::test]
    async fn test_rekey_retransmits_lost_client_hello() {
        let (client_io, server_io) = new_memory_packet_pair();
        let server_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), false).expect("tls-crypt"));
        let server_id = packet::SessionID(*b"server01");

        let client = new_test_client(
            &Arc::new(ClientConfig {
                proto: PROTO_UDP.to_owned(),
                tls_crypt_key: test_static_key(),
                ..Default::default()
            }),
            control_io_packet_adapter(Arc::<MemoryPacketIO>::clone(&client_io)),
        )
        .expect("test client");
        client.control.set_remote_session_id(server_id);

        let server =
            ControlChannel::new(Arc::<MemoryPacketIO>::clone(&server_io), Some(Arc::clone(&server_crypt)), server_id);
        server.set_remote_session_id(client.control.local_session_id());
        client.control.set_clock(Arc::new(|| rekey_b_unix(1714567890)));
        server.set_clock(Arc::new(|| rekey_b_unix(1714567891)));

        let ctx = CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_secs(3));

        server.adopt_key_id(1);
        server.send(&ctx, packet::P_CONTROL_SOFT_RESET_V1, &[]).await.expect("server soft reset");
        let soft = client.control.wait_for_soft_reset(&ctx).await.expect("soft reset");

        client.control.adopt_key_id(1);
        client.control.mark_received(soft.message_id);
        client.control.queue_ack(soft.message_id);
        client.control.send_soft_reset(&ctx).await.expect("client soft reset");
        let mut stop = client.retransmit_control(&ctx, None);
        client.control.send(&ctx, packet::P_CONTROL_V1, b"client-hello").await.expect("client hello");

        let mut first_hello = u32::MAX;
        let mut got_retransmit = false;
        for _ in 0..5 {
            if got_retransmit {
                break;
            }
            let raw = server_io.read_packet(&ctx).await.expect("read packet");
            let (pkt, _, _) =
                packet::decode_control_packet(Some(server_crypt.as_ref()), &raw).expect("decode control packet");
            if pkt.opcode != packet::P_CONTROL_V1 || pkt.payload.as_slice() != b"client-hello" {
                continue;
            }
            if first_hello == u32::MAX {
                first_hello = pkt.message_id;
                continue;
            }
            if pkt.message_id == first_hello {
                got_retransmit = true;
            }
        }
        stop.stop();
        assert!(got_retransmit, "client-hello was never retransmitted after loss");
    }

    #[tokio::test]
    async fn test_initial_handshake_retransmits_lost_client_hello() {
        ensure_test_crypto_provider();
        let (client_io, server_io) = new_memory_packet_pair();
        let (_, ca_pem) = test_server_tls_acceptor();
        let client = new_test_client(
            &Arc::new(ClientConfig {
                proto: PROTO_UDP.to_owned(),
                ca: ca_pem,
                cipher: config::CIPHER_AES_128_GCM.to_owned(),
                auth: config::AUTH_SHA256.to_owned(),
                username: "user".to_owned(),
                password: "pass".to_owned(),
                remote_host: "server".to_owned(),
                remote_port: 1194,
                ..Default::default()
            }),
            control_io_packet_adapter(client_io),
        )
        .expect("test client");

        let ctx = CancelContext::background().with_deadline(Instant::now() + Duration::from_secs(4));
        let token = ctx.token().clone();
        let mut handshake_task = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.handshake(&token).await }
        });

        let reset_raw = server_io.read_packet(&ctx).await.expect("read client reset");
        let (reset, _, _) = packet::decode_control_packet(None, &reset_raw).expect("decode client reset");
        let server =
            ControlChannel::new(Arc::<MemoryPacketIO>::clone(&server_io), None, packet::SessionID(*b"server01"));
        server.set_remote_session_id(reset.local_session);
        server.mark_received(reset.message_id);
        server.queue_ack(reset.message_id);
        server.send(&ctx, packet::P_CONTROL_HARD_RESET_SERVER_V2, &[]).await.expect("send server reset");

        let mut first_hello: Option<Arc<ControlPacket>> = None;
        let mut got_retransmit = false;
        for _ in 0..5 {
            if got_retransmit {
                break;
            }
            let raw = server_io.read_packet(&ctx).await.expect("read packet");
            let Ok((pkt, _, _)) = packet::decode_control_packet(None, &raw) else {
                continue;
            };
            if pkt.opcode != packet::P_CONTROL_V1 {
                continue;
            }
            match &first_hello {
                None => first_hello = Some(Arc::new(pkt)),
                Some(first) if first.message_id == pkt.message_id => {
                    assert_eq!(pkt.payload, first.payload, "retransmitted ClientHello payload changed");
                    got_retransmit = true;
                }
                Some(_) => {}
            }
        }
        assert!(got_retransmit, "client-hello was never retransmitted after loss");

        ctx.cancel(None);
        let result = tokio::time::timeout(Duration::from_secs(2), &mut handshake_task)
            .await
            .expect("guard timeout waiting for handshake to end")
            .expect("handshake task joined");
        assert!(result.is_err(), "incomplete test handshake unexpectedly succeeded");
    }

    #[tokio::test]
    async fn test_real_tls_rekey_survives_extended_auth_pending() {
        ensure_test_crypto_provider();
        for use_tls_auth in [false, true] {
            let (client_io, server_io) = new_memory_packet_pair();
            let (acceptor, ca_pem) = test_server_tls_acceptor();
            let server_km2 = marshal_test_server_key_method();

            let mut client_cfg = ClientConfig {
                proto: PROTO_UDP.to_owned(),
                cipher: config::CIPHER_AES_128_GCM.to_owned(),
                auth: config::AUTH_SHA256.to_owned(),
                ca: ca_pem,
                username: "test".to_owned(),
                transition_window: murmur_common::time::MINUTE,
                transition_window_set: true,
                ..Default::default()
            };
            let mut server_crypt: Option<Arc<dyn ControlCryptor>> = None;
            if use_tls_auth {
                let static_key = vec![0x42u8; 256];
                client_cfg.tls_auth_key = static_key.clone();
                client_cfg.key_direction = "1".to_owned();
                server_crypt =
                    Some(Arc::new(tlsauth::new_tls_auth(&static_key, "0", &client_cfg.auth).expect("tls-auth")));
            }

            let client =
                new_test_client(&Arc::new(client_cfg), control_io_packet_adapter(client_io)).expect("test client");
            client.set_rekey_handshake_timeout_for_test(Duration::from_millis(250));

            let keys = keymethod::KeyMaterial {
                send_cipher_key: vec![0x11; 16],
                send_hmac_key: vec![0x22; keymethod::MAX_HMAC_KEY_LENGTH],
                recv_cipher_key: vec![0x33; 16],
                recv_hmac_key: vec![0x44; keymethod::MAX_HMAC_KEY_LENGTH],
            };
            let old_data = DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 0, 0)
                .expect("initial data channel");
            client.install_data_channel(Arc::new(old_data));
            client.state.lock().push = Some(PushReply {
                prefixes: vec!["10.8.0.2/24".parse().expect("test prefix")],
                peer_id: 0,
                cipher: config::CIPHER_AES_128_GCM.to_owned(),
                has_push_reply: true,
                ..Default::default()
            });
            client.state.lock().negotiated_cipher = config::CIPHER_AES_128_GCM.to_owned();
            client.state.lock().control_established_at = Some(Instant::now() - Duration::from_secs(3600));

            let server_id = packet::SessionID(*b"server01");
            client.control.set_remote_session_id(server_id);
            let server = Arc::new(ControlChannel::new(
                Arc::<MemoryPacketIO>::clone(&server_io),
                server_crypt.clone(),
                server_id,
            ));
            server.set_remote_session_id(client.control.local_session_id());

            server.adopt_key_id(1);
            let ctx = CancelContext::background().with_deadline(Instant::now() + Duration::from_secs(10));
            server.send(&ctx, packet::P_CONTROL_SOFT_RESET_V1, &[]).await.expect("server soft reset");
            let reset = client.control.wait_for_soft_reset(&ctx).await.expect("client soft reset wait");
            let retiring_expiry = client.retiring_window_deadline(Some(reset.as_ref()));
            client.stage_retiring_window(Some(retiring_expiry));

            let (client_km2_tx, client_km2_rx) = oneshot::channel::<Instant>();
            let (release_tx, release_rx) = oneshot::channel::<()>();

            let mut server_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn({
                let server = Arc::clone(&server);
                let server_crypt = server_crypt.clone();
                let ctx = ctx.clone();
                async move {
                    let raw_reset =
                        server_io.read_packet(&ctx).await.map_err(|err| anyhow!("read client soft reset: {err}"))?;
                    let (client_reset, _, _) = packet::decode_control_packet(server_crypt.as_deref(), &raw_reset)
                        .map_err(|err| anyhow!("decode client soft reset: {err}"))?;
                    if client_reset.opcode != packet::P_CONTROL_SOFT_RESET_V1
                        || client_reset.key_id != 1
                        || client_reset.message_id != 0
                    {
                        return Err(anyhow!(
                            "unexpected client reset: opcode={} key={} message={}",
                            client_reset.opcode,
                            client_reset.key_id,
                            client_reset.message_id
                        ));
                    }
                    {
                        let mut st = server.state().lock();
                        for ack_id in &client_reset.ack_ids {
                            st.pending.remove(ack_id);
                        }
                        st.recv_message = 1;
                        control::append_ack(&mut st.ack_pending, client_reset.message_id);
                    }

                    let server_conn = ControlConn::new(Arc::clone(&server));
                    let server_tls =
                        acceptor.accept(server_conn).await.map_err(|err| anyhow!("server TLS handshake: {err}"))?;
                    let push_conn = ServerTlsPushConn(tokio::sync::Mutex::new(server_tls));
                    read_test_client_key_method(&push_conn).await.map_err(|err| anyhow!("read client KM2: {err}"))?;
                    let _ = client_km2_tx.send(Instant::now());
                    tokio::select! {
                        result = release_rx => { result.map_err(|_| anyhow!("release channel closed"))?; }
                        () = ctx.done() => return Err(ctx.err().unwrap_or_else(|| anyhow!("context done"))),
                    }
                    {
                        let mut server_tls = push_conn.0.lock().await;
                        server_tls.write_all(&server_km2).await.map_err(|err| anyhow!("write server KM2: {err}"))?;
                        server_tls
                            .write_all(b"AUTH_PENDING,timeout 2\x00PUSH_REPLY,push-continuation 2\x00")
                            .await
                            .map_err(|err| anyhow!("write deferred push: {err}"))?;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    {
                        let mut server_tls = push_conn.0.lock().await;
                        server_tls
                            .write_all(b"PUSH_REPLY,auth-token SESS_ID_rotated,push-continuation 1\x00")
                            .await
                            .map_err(|err| anyhow!("write final push: {err}"))?;
                    }
                    Ok(())
                }
            });

            let started = Instant::now();
            let mut rekey_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn({
                let client = Arc::clone(&client);
                let reset_owned = (*reset).clone();
                async move { client.renegotiate(Some(&reset_owned), Some(retiring_expiry)).await }
            });

            let client_km2_read_at = tokio::select! {
                result = client_km2_rx => result.expect("client KM2 read signal channel closed"),
                result = &mut rekey_task => {
                    let result = result.expect("rekey task joined");
                    panic!("client rekey ended before sending KM2: {result:?}");
                }
                result = &mut server_task => {
                    let result = result.expect("server task joined");
                    panic!("server ended before reading client KM2: {result:?}");
                }
                () = ctx.done() => panic!("{}", ctx.err().map(|err| err.to_string()).unwrap_or_default()),
            };

            assert!(
                client.state.lock().control_established_at.is_none(),
                "AUTH_PENDING anchor captured before server KM2: {:?}",
                client.state.lock().control_established_at
            );

            let server_km2_released_at = Instant::now();
            let _ = release_tx.send(());

            let rekey_result = tokio::select! {
                result = &mut rekey_task => result.expect("rekey task joined"),
                () = ctx.done() => panic!("{}", ctx.err().map(|err| err.to_string()).unwrap_or_default()),
            };
            if let Err(err) = rekey_result {
                if server_task.is_finished() {
                    let server_result = (&mut server_task).await.expect("server task joined");
                    panic!("client rekey: {err}; server: {server_result:?}");
                }
                panic!("client rekey: {err}");
            }

            assert!(
                started.elapsed() >= client.rekey_timeout(),
                "rekey completed before deferred auth delay: {:?}",
                started.elapsed()
            );

            let server_result = tokio::time::timeout(Duration::from_secs(5), server_task)
                .await
                .expect("guard timeout waiting for server task")
                .expect("server task joined");
            assert!(server_result.is_ok(), "server error: {:?}", server_result.err());

            let established_at = client.state.lock().control_established_at.expect("control established at set");
            assert!(
                established_at >= server_km2_released_at && established_at >= client_km2_read_at,
                "AUTH_PENDING anchor {established_at:?} predates KM2 activation (read {client_km2_read_at:?}, released {server_km2_released_at:?})"
            );

            let (active_key_id, deferred_until) = {
                let state = client.data.read();
                (state.data.as_ref().expect("data channel installed").key_id, state.deferred_until)
            };
            assert_eq!(active_key_id, 1, "active data key ID = {active_key_id}, want 1");
            let want_deferred = established_at + Duration::from_secs(2);
            assert_eq!(
                deferred_until,
                Some(want_deferred),
                "AUTH_PENDING deadline = {deferred_until:?}, want KM2 anchor deadline {want_deferred:?}"
            );

            let auth_pass = client.state.lock().auth_pass.clone();
            assert_eq!(auth_pass, "SESS_ID_rotated", "rotated auth token = {auth_pass:?}");
        }
    }

    #[tokio::test]
    async fn test_rekey_retransmit_keeps_reset_ack() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), true).expect("tls-crypt"));
        let server_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), false).expect("tls-crypt"));
        let client_id = packet::SessionID(*b"client01");
        let server_id = packet::SessionID(*b"server01");

        let client =
            ControlChannel::new(Arc::<MemoryPacketIO>::clone(&client_io), Some(Arc::clone(&client_crypt)), client_id);
        client.set_remote_session_id(server_id);
        let server =
            ControlChannel::new(Arc::<MemoryPacketIO>::clone(&server_io), Some(Arc::clone(&server_crypt)), server_id);
        server.set_remote_session_id(client_id);
        client.set_clock(Arc::new(|| rekey_b_unix(1714567890)));
        server.set_clock(Arc::new(|| rekey_b_unix(1714567891)));

        let ctx = CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_secs(2));

        server.adopt_key_id(1);
        server.send(&ctx, packet::P_CONTROL_SOFT_RESET_V1, &[]).await.expect("server soft reset");
        let soft = client.wait_for_soft_reset(&ctx).await.expect("soft reset");
        client.adopt_key_id(1);
        client.mark_received(soft.message_id);
        client.queue_ack(soft.message_id);
        client.send_soft_reset(&ctx).await.expect("client soft reset");

        let raw = server_io.read_packet(&ctx).await.expect("read packet");
        let (first, _, _) =
            packet::decode_control_packet(Some(server_crypt.as_ref()), &raw).expect("decode control packet");
        assert_eq!(first.opcode, packet::P_CONTROL_SOFT_RESET_V1, "first packet opcode = {}", first.opcode);
        assert!(first.ack_ids.contains(&0), "first client soft reset missing reset ACK: {:?}", first.ack_ids);

        client.retransmit_pending(&ctx).await.expect("retransmit pending");

        let raw = server_io.read_packet(&ctx).await.expect("read packet");
        let (re, _, _) =
            packet::decode_control_packet(Some(server_crypt.as_ref()), &raw).expect("decode control packet");
        assert_eq!(re.opcode, packet::P_CONTROL_SOFT_RESET_V1, "retransmitted opcode = {}", re.opcode);
        assert!(re.ack_ids.contains(&0), "retransmitted soft reset lost the reset ACK: {:?}", re.ack_ids);
    }

    #[tokio::test]
    async fn test_stale_soft_reset_not_parked() {
        let (client, server) = new_test_channels();
        client.set_remote_session_id(server.local_session_id());
        server.set_remote_session_id(client.local_session_id());

        let ctx = CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_secs(2));

        client.adopt_key_id(2);
        server.adopt_key_id(1);
        server.send(&ctx, packet::P_CONTROL_SOFT_RESET_V1, &[]).await.expect("server soft reset");

        let read_ctx =
            CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_millis(80));
        if let Ok(pkt) = client.read(&read_ctx).await {
            panic!("Read delivered {} key={}, want stale reset dropped", pkt.opcode, pkt.key_id);
        }
        let parked = client.state().lock().pending_soft_reset.clone();
        if let Some(parked) = parked {
            panic!("stale soft reset was parked: key={}", parked.key_id);
        }

        server.adopt_key_id(3);
        server.send(&ctx, packet::P_CONTROL_SOFT_RESET_V1, &[]).await.expect("server soft reset");
        let got = client.wait_for_soft_reset(&ctx).await.expect("soft reset");
        assert_eq!(got.key_id, 3, "watcher accepted stale epoch, got key={} want 3", got.key_id);
    }

    #[tokio::test]
    async fn test_merge_push_reply_preserves_continuation_across_auth_pending() {
        let continued = PushReply { has_push_reply: true, push_continuation: 2, ..Default::default() };
        let pending =
            PushReply { has_auth_pending: true, auth_pending_timeout: Duration::from_secs(1), ..Default::default() };
        let merged = merge_push_reply(Some(continued), Some(pending)).expect("merged reply");
        assert!(
            merged.push_continuation == 2 && merged.has_push_reply,
            "AUTH_PENDING lost continuation state: {merged:?}"
        );
        let final_reply =
            merge_push_reply(Some(merged), Some(PushReply { has_push_reply: true, ..Default::default() }))
                .expect("final reply");
        assert_eq!(
            final_reply.push_continuation, 0,
            "final PUSH_REPLY retained continuation {}",
            final_reply.push_continuation
        );
    }

    #[tokio::test]
    async fn test_read_server_key_method_rejects_invalid_prefix_immediately() {
        let mut packet = vec![0u8; 4 + 1 + keymethod::KEY_SOURCE_RANDOM_SIZE * 2];
        packet[3] = 1;
        packet[4] = keymethod::KEY_METHOD_2;
        let conn = ChunkConn { data: vec![packet], ..Default::default() };
        let client = new_bare_control_client();
        let ctx = CancelContext::background();
        let err = client
            .read_server_key_method_from(&ctx, Some(&conn))
            .await
            .expect_err("invalid key method 2 prefix was accepted");
        assert!(err.to_string().contains("invalid key method 2 prefix"), "invalid prefix returned {err}");
        assert_eq!(*conn.idx.lock(), 1, "invalid prefix triggered reads, want 1");
    }

    #[tokio::test]
    async fn test_read_push_reply_canceled_before_read() {
        let ctx = CancelContext::background();
        ctx.cancel(None);
        let conn = ChunkConn { data: vec![b"must not read".to_vec()], ..Default::default() };
        let client = new_bare_control_client();
        let err = client.read_push_reply_from(&ctx, Some(&conn)).await.expect_err("canceled push read was accepted");
        assert!(err.to_string().contains("context canceled"), "canceled push read returned {err}");
        assert_eq!(*conn.idx.lock(), 0, "canceled push reader consumed chunks, want 0");
    }

    #[tokio::test]
    async fn test_outbound_promotion_window_anchored_at_soft_reset() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig {
                transition_window: murmur_common::time::MINUTE,
                transition_window_set: true,
                ..Default::default()
            }),
            control_io_packet_adapter(Arc::<MemoryPacketIO>::clone(&client_io)),
        )
        .expect("test client");

        client.install_data_channel(rekey_b_data_channel(0));
        let accepted_at = tokio::time::Instant::now() - Duration::from_secs(30);
        client.stage_retiring_window(Some(accepted_at + Duration::from_secs(60)));
        client.install_data_channel(rekey_b_data_channel(1));

        let outbound_start = client.data.read().outbound_start.expect("outbound promotion start is unset");
        assert!(
            outbound_start >= accepted_at && outbound_start.duration_since(accepted_at) <= Duration::from_millis(1),
            "outbound promotion start = {outbound_start:?}, want {accepted_at:?}"
        );
    }

    #[tokio::test]
    async fn test_parse_push_rejects_malformed_credential_and_continuation() {
        for message in [
            "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,auth-token SESS_ID_ok,auth-token-user !!!",
            "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,push-continuation nope",
            "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,push-continuation 3",
        ] {
            assert!(push::parse_push_reply(message).is_err(), "malformed pushed field accepted: {message:?}");
        }
    }

    #[tokio::test]
    async fn test_retransmit_control_reports_physical_error_racing_stop() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let packet_io = Arc::new(BlockingPermanentPacketIo {
            entered: Some(Arc::clone(&entered)),
            release: Some(Arc::clone(&release)),
            write_err: Mutex::new(Some(anyhow!("permanent write at stop"))),
            ..Default::default()
        });
        let client =
            new_test_client(&Arc::new(ClientConfig::default()), Arc::<BlockingPermanentPacketIo>::clone(&packet_io))
                .expect("test client");
        client
            .control
            .send(&CancelContext::background(), packet::P_CONTROL_V1, b"pending")
            .await
            .expect("queue pending control");

        let ctx = CancelContext::from_token(CancellationToken::new());
        let mut stop = client.retransmit_control(&ctx, Some(ctx.clone()));
        let entered_wait = tokio::time::timeout(2 * CONTROL_RETRANSMIT_DELAY, entered.notified()).await;
        assert!(entered_wait.is_ok(), "retransmission did not enter blocked write");

        stop.stop();
        release.notify_one();

        let failed = tokio::time::timeout(Duration::from_secs(1), ctx.done()).await;
        assert!(failed.is_ok(), "physical error racing stop did not fail the parent operation");
        let cause = ctx.cause().expect("operation failure cause is unset");
        assert!(
            cause.to_string().contains("permanent write at stop"),
            "physical error racing stop produced cause {cause}"
        );

        let terminated = tokio::time::timeout(Duration::from_secs(1), client.mux.wait_done()).await;
        assert!(terminated.is_ok(), "permanent physical write did not terminate transport");
        let err = client.mux.terminal_error();
        assert!(err.to_string().contains("permanent write at stop"), "physical transport error was lost: {err}");
    }

    #[tokio::test]
    async fn test_retransmit_control_suppresses_dropped_packet_racing_stop() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let packet_io = Arc::new(BlockingPermanentPacketIo {
            entered: Some(Arc::clone(&entered)),
            release: Some(Arc::clone(&release)),
            write_err: Mutex::new(Some(anyhow::Error::new(packetio::PacketDroppedError {
                cause: anyhow!("dropped retransmit"),
            }))),
            ..Default::default()
        });
        let client =
            new_test_client(&Arc::new(ClientConfig::default()), Arc::<BlockingPermanentPacketIo>::clone(&packet_io))
                .expect("test client");
        client
            .control
            .send(&CancelContext::background(), packet::P_CONTROL_V1, b"pending")
            .await
            .expect("queue pending control");

        let ctx = CancelContext::from_token(CancellationToken::new());
        let mut stop = client.retransmit_control(&ctx, Some(ctx.clone()));
        let entered_wait = tokio::time::timeout(2 * CONTROL_RETRANSMIT_DELAY, entered.notified()).await;
        assert!(entered_wait.is_ok(), "retransmission did not enter blocked write");

        stop.stop();
        release.notify_one();
        let _ = tokio::time::timeout(Duration::from_millis(200), ctx.done()).await;
        if let Some(cause) = ctx.cause() {
            panic!("dropped stop-boundary packet became operation failure: {cause}");
        }
    }

    #[tokio::test]
    async fn test_dropped_initial_reliable_write_remains_queued() {
        let packet_io = Arc::new(RetransmitTestPacketIo {
            first: Mutex::new(Some(anyhow::Error::new(packetio::PacketDroppedError {
                cause: anyhow!("dropped initial packet"),
            }))),
            ..Default::default()
        });
        let client = new_test_client(
            &Arc::new(ClientConfig { proto: PROTO_UDP.to_owned(), ..Default::default() }),
            Arc::<RetransmitTestPacketIo>::clone(&packet_io),
        )
        .expect("test client");

        let ctx = CancelContext::background();
        client.control.send_reset(&ctx).await.expect("dropped initial send failed");
        assert_eq!(
            client.control.pending_messages(),
            1,
            "dropped initial send pending = {}, want 1",
            client.control.pending_messages()
        );
        client.control.retransmit_pending(&ctx).await.expect("retransmit pending");
        let writes = *packet_io.writes.lock();
        assert_eq!(writes, 2, "physical writes = {writes}, want initial plus retransmit");
    }

    #[tokio::test]
    async fn test_retransmit_control_retries_dropped_packet() {
        let retried = Arc::new(tokio::sync::Notify::new());
        let packet_io = Arc::new(RetransmitTestPacketIo {
            second: Mutex::new(Some(anyhow::Error::new(packetio::PacketDroppedError {
                cause: anyhow!("dropped retransmit"),
            }))),
            retried: Some(Arc::clone(&retried)),
            ..Default::default()
        });
        let client =
            new_test_client(&Arc::new(ClientConfig::default()), Arc::<RetransmitTestPacketIo>::clone(&packet_io))
                .expect("test client");
        client
            .control
            .send(&CancelContext::background(), packet::P_CONTROL_V1, b"pending")
            .await
            .expect("queue pending control");

        let ctx = CancelContext::from_token(CancellationToken::new());
        let mut stop = client.retransmit_control(&ctx, Some(ctx.clone()));
        let retried_wait = tokio::time::timeout(3 * CONTROL_RETRANSMIT_DELAY, retried.notified()).await;
        assert!(retried_wait.is_ok(), "dropped retransmission stopped retry loop");
        if let Some(cause) = ctx.cause() {
            panic!("dropped retransmission canceled operation: {cause}");
        }
        stop.stop();
    }

    #[tokio::test]
    async fn test_retransmit_control_propagates_permanent_error() {
        let packet_io = Arc::new(RetransmitTestPacketIo {
            second: Mutex::new(Some(anyhow!("permanent control write"))),
            ..Default::default()
        });
        let client =
            new_test_client(&Arc::new(ClientConfig::default()), Arc::<RetransmitTestPacketIo>::clone(&packet_io))
                .expect("test client");
        client
            .control
            .send(&CancelContext::background(), packet::P_CONTROL_V1, b"pending")
            .await
            .expect("queue pending control");

        let ctx = CancelContext::from_token(CancellationToken::new());
        let mut stop = client.retransmit_control(&ctx, Some(ctx.clone()));
        let propagated = tokio::time::timeout(2 * CONTROL_RETRANSMIT_DELAY, ctx.done()).await;
        assert!(propagated.is_ok(), "permanent retransmission error was not propagated");
        let cause = ctx.cause().expect("retransmission cause is unset");
        assert!(cause.to_string().contains("permanent control write"), "unexpected retransmission cause: {cause}");
        stop.stop();
    }

    #[tokio::test]
    async fn test_consume_rekey_push_auth_failed() {
        let client = new_bare_control_client();
        {
            let mut state = client.state.lock();
            state.push =
                Some(PushReply { peer_id: 5, auth_token_pass: "SESS_ID_old".to_owned(), ..Default::default() });
            state.leftover_tls = b"AUTH_FAILED,SESSION: auth-token expired\x00".to_vec();
        }

        let err = client.consume_rekey_push().await.expect_err("consumeRekeyPush returned nil on AUTH_FAILED");
        assert!(error_is::<ErrAuthFailed>(&err), "expected errAuthFailed, got {err}");
        assert!(err.to_string().contains("openvpn authentication failed"), "expected errAuthFailed, got {err}");
    }

    #[tokio::test]
    async fn test_read_token_push_reply_uses_extended_continuation_deadline() {
        let limit = tokio::time::Instant::now() + Duration::from_secs(3600);
        let conn = ChunkConn {
            data: vec![
                b"PUSH_REPLY,push-continuation 2\x00".to_vec(),
                b"PUSH_REPLY,auth-token SESS_ID_final,push-continuation 1\x00".to_vec(),
            ],
            ..Default::default()
        };
        let (reply, rest) =
            read_token_push_reply(&conn, &[], &[None, None, Some(limit)]).await.expect("continued token push reply");
        assert!(rest.is_empty() && reply.is_some(), "continued reply = {reply:?} rest={rest:?}");
        let reply = reply.expect("continued reply");
        assert_eq!(reply.push_continuation, 1, "continued reply = {reply:?} rest={rest:?}");
        let write_deadline = *conn.last_write_deadline.lock();
        let operations = conn.operation_deadlines.lock().clone();
        assert_eq!(
            write_deadline,
            Some(limit),
            "continuation deadline = write {write_deadline:?} operations {operations:?}, want {limit:?}"
        );
        assert_eq!(
            operations.first().copied().flatten(),
            Some(limit),
            "continuation operations = {operations:?}, want {limit:?}"
        );
        let read_deadline = *conn.last_deadline.lock();
        assert!(read_deadline.is_none(), "temporary read deadline was not cleared: {read_deadline:?}");
    }

    #[tokio::test]
    async fn test_take_push_reply_auth_pending_before_push() {
        let stream: &[u8] = b"AUTH_PENDING,timeout 60\x00\
INFO_PRE,Auth-Message:OTAwODcxMjU5MTQ1MDExNjA3MjM=\x00\
PUSH_REPLY,auth-token SESS_ID_fresh\x00";
        let (reply, rest, ok) = take_push_reply(stream);
        assert!(ok, "token PUSH_REPLY not found after AUTH_PENDING/INFO_PRE");
        let reply = reply.expect("token not parsed");
        assert_eq!(reply.auth_token_pass.as_str(), "SESS_ID_fresh");
        assert!(rest.is_empty(), "unexpected leftover: {rest:?}");
    }

    #[tokio::test]
    async fn test_read_token_push_reply_deferred_auth() {
        let conn = ChunkConn {
            data: vec![b"AUTH_PENDING,timeout 60\x00PUSH_REPLY,auth-token SESS_ID_deferred\x00".to_vec()],
            ..Default::default()
        };
        let (reply, _) = read_token_push_reply(&conn, &[], &[]).await.expect("deferred token push reply");
        let reply = reply.expect("deferred-auth token not parsed");
        assert_eq!(reply.auth_token_pass.as_str(), "SESS_ID_deferred");
    }

    #[tokio::test]
    async fn test_read_token_push_reply_split_across_reads() {
        let conn = ChunkConn {
            data: vec![b"PUSH_REPLY,auth-token ".to_vec(), b"SESS_ID_split\x00".to_vec()],
            ..Default::default()
        };
        let (reply, rest) = read_token_push_reply(&conn, &[], &[]).await.expect("split token push reply");
        let reply = reply.expect("split token not parsed");
        assert_eq!(reply.auth_token_pass.as_str(), "SESS_ID_split");
        assert!(rest.is_empty(), "unexpected leftover: {rest:?}");
    }

    #[tokio::test]
    async fn test_read_token_push_reply_partial_preserved() {
        let conn = ChunkConn { data: vec![b"PUSH_REPLY,auth-token ".to_vec()], ..Default::default() };
        let (reply, rest) = read_token_push_reply(&conn, &[], &[]).await.expect("partial token push reply");
        assert!(reply.is_none(), "unexpected reply for partial data: {reply:?}");
        assert_eq!(rest.as_slice(), b"PUSH_REPLY,auth-token ");
    }

    #[tokio::test]
    async fn test_read_token_push_reply_auth_failed_with_eof() {
        let conn = ChunkConn {
            data: vec![b"AUTH_FAILED,SESSION: auth-token expired\x00".to_vec()],
            errs: vec![Some(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))],
            ..Default::default()
        };
        let err = read_token_push_reply(&conn, &[], &[])
            .await
            .expect_err("readTokenPushReply lost AUTH_FAILED returned with io.EOF");
        assert!(error_is::<ErrAuthFailed>(&err), "expected errAuthFailed, got {err}");
        assert!(err.to_string().contains("openvpn authentication failed"), "expected errAuthFailed, got {err}");
    }

    #[tokio::test]
    async fn test_read_token_push_reply_eof_propagated() {
        let conn = ChunkConn {
            data: vec![b"PUSH_REPLY,auth-token SESS".to_vec()],
            errs: vec![Some(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"))],
            ..Default::default()
        };
        let err = read_token_push_reply(&conn, &[], &[]).await.expect_err("EOF was suppressed");
        assert!(!error_is::<ErrAuthFailed>(&err), "unexpected errAuthFailed: {err}");
        assert!(!err.to_string().contains("openvpn authentication failed"), "unexpected errAuthFailed: {err}");
    }

    #[tokio::test]
    async fn test_read_token_push_reply_complete_reply_with_eof() {
        let conn = ChunkConn {
            data: vec![b"PUSH_REPLY,auth-token SESS_ID_new\x00".to_vec()],
            errs: vec![Some(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))],
            ..Default::default()
        };
        let (reply, _) =
            read_token_push_reply(&conn, &[], &[]).await.expect("complete reply with EOF should be accepted");
        let reply = reply.expect("unexpected reply");
        assert_eq!(reply.auth_token_pass.as_str(), "SESS_ID_new");
    }

    #[tokio::test]
    async fn test_read_server_key_method_complete_with_eof() {
        let mut record = Vec::new();
        record.extend_from_slice(&0u32.to_be_bytes());
        record.push(keymethod::KEY_METHOD_2);
        record.extend(std::iter::repeat_n(1u8, keymethod::KEY_SOURCE_RANDOM_SIZE));
        record.extend(std::iter::repeat_n(2u8, keymethod::KEY_SOURCE_RANDOM_SIZE));
        keymethod::append_openvpn_string(&mut record, "server-options");
        keymethod::append_openvpn_string(&mut record, "");
        keymethod::append_openvpn_string(&mut record, "");
        keymethod::append_openvpn_string(&mut record, "IV_VER=server\n");

        let conn = ChunkConn {
            data: vec![record],
            errs: vec![Some(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))],
            ..Default::default()
        };
        let client = new_bare_control_client();
        let ctx = CancelContext::background();
        let parsed = client
            .read_server_key_method_from(&ctx, Some(&conn))
            .await
            .expect("complete KM2 with EOF should be accepted");
        assert!(
            parsed.options == "server-options" && parsed.peer_info == "IV_VER=server\n",
            "unexpected KM2: {parsed:?}"
        );
    }

    #[tokio::test]
    async fn test_read_push_reply_eof_boundaries() {
        let client = new_bare_control_client();
        let ctx = CancelContext::background();

        let complete = ChunkConn {
            data: vec![b"PUSH_REPLY,peer-id 7\x00".to_vec()],
            errs: vec![Some(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))],
            ..Default::default()
        };
        let reply = client
            .read_push_reply_from(&ctx, Some(&complete))
            .await
            .expect("complete PUSH_REPLY with EOF should be accepted");
        assert_eq!(reply.peer_id, 7, "peer id = {}, want 7", reply.peer_id);

        client.state.lock().leftover_tls = Vec::new();
        let incomplete = ChunkConn {
            data: vec![b"PUSH_REPLY,peer-id 7".to_vec()],
            errs: vec![Some(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"))],
            ..Default::default()
        };
        assert!(
            client.read_push_reply_from(&ctx, Some(&incomplete)).await.is_err(),
            "unterminated PUSH_REPLY was accepted at EOF"
        );
    }

    #[tokio::test]
    async fn test_control_message_error_does_not_leak_auth_token() {
        let buf = b"PUSH_REPLY,auth-token SECRET_TOKEN\x00AUTH_FAILED,SESSION: expired\x00";
        let err = control_message_error(buf).expect_err("expected AUTH_FAILED");
        assert!(error_is::<ErrAuthFailed>(&err), "expected AUTH_FAILED, got {err}");
        assert!(err.to_string().contains("openvpn authentication failed"), "expected AUTH_FAILED, got {err}");
        assert!(!err.to_string().contains("SECRET_TOKEN"), "authentication token leaked in error: {err}");
        assert!(err.to_string().contains("AUTH_FAILED,SESSION: expired"), "wrong failure message selected: {err}");
    }

    #[tokio::test]
    async fn test_terminal_control_messages_stop_token_read() {
        for directive in ["RESTART,reconnect", "HALT,disabled", "EXIT"] {
            let conn = ChunkConn::default();
            let buf = format!("{directive}\x00PUSH_REPLY,auth-token SECRET\x00");
            let err =
                read_token_push_reply(&conn, buf.as_bytes(), &[]).await.expect_err("terminal directive was ignored");
            assert!(error_is::<ErrControlTerminated>(&err), "terminal directive {directive:?} was ignored: {err}");
            assert!(
                err.to_string().contains("openvpn server terminated the control session"),
                "terminal directive {directive:?} was ignored: {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_merge_push_reply_preserves_split_auth_token_user() {
        let first = PushReply {
            peer_id: data::PEER_ID_UNSET,
            auth_token_user: "token-user".to_owned(),
            push_continuation: 2,
            has_push_reply: true,
            ..Default::default()
        };
        let final_reply = PushReply {
            peer_id: data::PEER_ID_UNSET,
            auth_token_pass: "SESS_ID_new".to_owned(),
            push_continuation: 1,
            has_push_reply: true,
            ..Default::default()
        };
        let merged = merge_push_reply(Some(first), Some(final_reply)).expect("merged reply");
        assert!(
            merged.auth_token_user == "token-user" && merged.auth_token_pass == "SESS_ID_new",
            "split auth token pair lost: {merged:?}"
        );
    }

    #[tokio::test]
    async fn test_auth_pending_timeout_zero_and_cap() {
        let mut zero = parse_auth_pending_timeout("AUTH_PENDING,timeout 0").expect("auth pending parse");
        assert!(zero.has_auth_pending && zero.auth_pending_timeout.is_zero(), "explicit zero timeout lost: {zero:?}");
        let established_at = tokio::time::Instant::now() - Duration::from_secs(1);
        anchor_auth_pending_deadline(&mut zero, Some(established_at));
        assert_eq!(
            zero.auth_pending_until,
            Some(established_at),
            "zero timeout deadline = {:?}, want {established_at:?}",
            zero.auth_pending_until
        );

        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig::default()),
            control_io_packet_adapter(Arc::<MemoryPacketIO>::clone(&client_io)),
        )
        .expect("test client");
        client.state.lock().control_established_at = Some(established_at);
        client.apply_auth_pending_timeout(&mut zero);

        let (staged_set, staged_until) = {
            let state = client.data.read();
            (state.pending_deferred_set, state.pending_deferred_until)
        };
        assert!(
        staged_set && staged_until == Some(established_at),
        "zero timeout was not applied to pending epoch: set={staged_set} until={staged_until:?} want={established_at:?}"
    );

        for input in ["AUTH_PENDING,timeout 7200", "AUTH_PENDING,timeout 9223372036854775807"] {
            let capped = parse_auth_pending_timeout(input).expect("auth pending parse");
            assert_eq!(
                capped.auth_pending_timeout, AUTH_PENDING_MAX_TIMEOUT,
                "timeout {input:?} was not capped: got={:?} want={AUTH_PENDING_MAX_TIMEOUT:?}",
                capped.auth_pending_timeout
            );
        }
    }

    #[tokio::test]
    async fn test_tls_control_buffer_limit() {
        let conn = ChunkConn::default();
        let oversized = vec![0u8; MAX_TLS_CONTROL_BUFFER + 1];
        assert!(
            read_token_push_reply(&conn, &oversized, &[]).await.is_err(),
            "oversized TLS control buffer was accepted"
        );
    }

    #[tokio::test]
    async fn test_expired_pending_retiring_window_pauses_until_install() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { username: "u".to_owned(), password: "p".to_owned(), ..Default::default() }),
            control_io_packet_adapter(Arc::<MemoryPacketIO>::clone(&client_io)),
        )
        .expect("test client");

        client.install_data_channel(rekey_b_data_channel(0));
        client.stage_retiring_window(Some(tokio::time::Instant::now() - Duration::from_secs(1)));

        let write_client = Arc::clone(&client);
        let write_ctx = CancellationToken::new();
        let task_ctx = write_ctx.clone();
        let mut write_handle =
            tokio::spawn(async move { write_client.write_data_packet(&task_ctx, &[0x45, 0, 0, 20], false).await });
        let paused = tokio::time::timeout(Duration::from_millis(20), &mut write_handle).await;
        assert!(paused.is_err(), "expired old-key write did not pause");

        let peer = rekey_b_data_channel(0);
        let packet = peer.encrypt(&[0x45, 0, 0, 20]).expect("encrypt");
        assert!(
            client.decrypt_data_packet(&packet).is_err(),
            "old inbound epoch accepted after pending retiring deadline"
        );

        client.install_data_channel(rekey_b_data_channel(1));
        let resumed = tokio::time::timeout(Duration::from_secs(1), &mut write_handle).await;
        resumed
            .expect("new epoch install did not wake paused write")
            .expect("write task panicked")
            .expect("paused write failed");

        let emitted = server_io.read_packet(&CancelContext::background()).await.expect("read packet");
        let (_, key_id) = parse_opcode_key_id(emitted[0]);
        assert_eq!(key_id, 1, "resumed write used key id {key_id}, want 1");
    }

    // Two tasks block a worker each synchronously (the writer on key1's lock, the stager on
    // client.data); a third worker is required to drive this test at all.
    #[expect(
        clippy::await_holding_lock,
        reason = "holding `held` across the awaits deliberately blocks the writer inside its epoch-selection critical section"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_retiring_expiry_staged_between_selection_and_encryption() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { username: "u".to_owned(), password: "p".to_owned(), ..Default::default() }),
            control_io_packet_adapter(Arc::<MemoryPacketIO>::clone(&client_io)),
        )
        .expect("test client");

        let key0 = rekey_b_data_channel(0);
        let key1 = rekey_b_data_channel(1);
        client.install_data_channel(Arc::clone(&key0));
        client.install_data_channel(Arc::clone(&key1));

        let held = key1.lock_state();

        let write_client = Arc::clone(&client);
        let write_ctx = CancellationToken::new();
        let task_ctx = write_ctx.clone();
        let mut write_handle =
            tokio::spawn(async move { write_client.write_data_packet(&task_ctx, &[0x45, 0, 0, 20], false).await });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while client.data.try_write().is_some() {
            assert!(tokio::time::Instant::now() <= deadline, "writer did not enter epoch selection");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        let stage_client = Arc::clone(&client);
        let mut stage_handle = tokio::spawn(async move {
            stage_client.stage_retiring_window(Some(tokio::time::Instant::now() - Duration::from_secs(1)));
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while client.data.try_read().is_some() {
            assert!(tokio::time::Instant::now() <= deadline, "retiring deadline writer did not queue");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        drop(held);
        let staged = tokio::time::timeout(Duration::from_secs(1), &mut stage_handle).await;
        staged.expect("retiring deadline was not staged").expect("stage task panicked");

        let escaped = tokio::time::timeout(Duration::from_millis(20), &mut write_handle).await;
        assert!(escaped.is_err(), "write escaped newly staged expired deadline");

        client.install_data_channel(rekey_b_data_channel(2));
        let resumed = tokio::time::timeout(Duration::from_secs(1), &mut write_handle).await;
        resumed.expect("writer did not resume on new epoch").expect("write task panicked").expect("write failed");

        let emitted = server_io.read_packet(&CancelContext::background()).await.expect("read packet");
        let (_, key_id) = parse_opcode_key_id(emitted[0]);
        assert_eq!(key_id, 2, "raced write used key id {key_id}, want 2");
    }

    // Two tasks block a worker each synchronously (the writer on key1's lock, the expiry
    // setter on client.data); a third worker is required to drive this test at all.
    #[expect(
        clippy::await_holding_lock,
        reason = "holding `held` across the awaits deliberately blocks the writer inside its epoch-selection critical section"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_retiring_expiry_changes_between_selection_and_encryption() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { username: "u".to_owned(), password: "p".to_owned(), ..Default::default() }),
            control_io_packet_adapter(Arc::<MemoryPacketIO>::clone(&client_io)),
        )
        .expect("test client");

        let key0 = rekey_b_data_channel(0);
        let key1 = rekey_b_data_channel(1);
        client.install_data_channel(Arc::clone(&key0));
        client.install_data_channel(Arc::clone(&key1));

        let held = key1.lock_state();

        let write_client = Arc::clone(&client);
        let write_ctx = CancellationToken::new();
        let task_ctx = write_ctx.clone();
        let mut write_handle =
            tokio::spawn(async move { write_client.write_data_packet(&task_ctx, &[0x45, 0, 0, 20], false).await });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while client.data.try_write().is_some() {
            assert!(tokio::time::Instant::now() <= deadline, "writer did not enter epoch selection");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        let expiry_client = Arc::clone(&client);
        let mut expiry_handle = tokio::spawn(async move {
            let mut state = expiry_client.data.write();
            state.retiring_expiry = Some(tokio::time::Instant::now() - Duration::from_secs(1));
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while client.data.try_read().is_some() {
            assert!(tokio::time::Instant::now() <= deadline, "retiring expiry writer did not queue");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        drop(held);
        let updated = tokio::time::timeout(Duration::from_secs(1), &mut expiry_handle).await;
        updated.expect("retiring expiry was not updated").expect("expiry task panicked");

        let finished = tokio::time::timeout(Duration::from_secs(1), &mut write_handle).await;
        finished.expect("writer did not finish after promotion").expect("write task panicked").expect("write failed");

        let packet = server_io.read_packet(&CancelContext::background()).await.expect("read packet");
        let (_, key_id) = parse_opcode_key_id(packet[0]);
        assert_eq!(key_id, 1, "raced retiring expiry write used key id {key_id}, want 1");
    }

    #[tokio::test]
    async fn test_watch_control_surfaces_parked_auth_failed() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig { username: "u".to_owned(), password: "p".to_owned(), ..Default::default() }),
            control_io_packet_adapter(Arc::<MemoryPacketIO>::clone(&client_io)),
        )
        .expect("test client");

        let server_id = packet::SessionID(*b"server01");
        client.control.set_remote_session_id(server_id);
        client.control.adopt_key_id(1);
        {
            let mut state = client.state.lock();
            state.push =
                Some(PushReply { peer_id: 1, auth_token_pass: "SESS_ID_old".to_owned(), ..Default::default() });
            state.leftover_tls = b"AUTH_FAILED,SESSION: auth-token expired\x00".to_vec();
        }
        client.control.state().lock().recv_pending.insert(
            0,
            Arc::new(ControlPacket {
                opcode: packet::P_CONTROL_V1,
                key_id: 1,
                message_id: 0,
                local_session: server_id,
                payload: b"deferred auth status".to_vec(),
                ..Default::default()
            }),
        );

        let watcher_client = Arc::clone(&client);
        let mut watcher = tokio::spawn(async move { watcher_client.watch_control().await });
        let exited = tokio::time::timeout(Duration::from_secs(2), &mut watcher).await;
        assert!(exited.is_ok(), "watchControl did not exit after parked AUTH_FAILED");
        let rekey_err = client.last_rekey_error().expect("watchControl swallowed parked AUTH_FAILED");
        assert!(rekey_err.to_string().contains("auth"), "unexpected rekey error: {rekey_err}");
    }

    #[tokio::test]
    async fn test_watch_control_close_does_not_record_rekey_failure() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(
            &Arc::new(ClientConfig::default()),
            control_io_packet_adapter(Arc::<MemoryPacketIO>::clone(&client_io)),
        )
        .expect("test client");

        let watcher_client = Arc::clone(&client);
        let mut watcher = tokio::spawn(async move { watcher_client.watch_control().await });
        client.close().await.expect("close client");
        let exited = tokio::time::timeout(Duration::from_secs(1), &mut watcher).await;
        assert!(exited.is_ok(), "watchControl did not stop on Close");
        if let Some(err) = client.last_rekey_error() {
            panic!("normal Close recorded a rekey failure: {err}");
        }
    }

    #[tokio::test]
    async fn test_retransmit_pending_empty_does_not_consume_acks() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client =
            ControlChannel::new(Arc::<MemoryPacketIO>::clone(&client_io), None, packet::SessionID(*b"client01"));
        client.set_remote_session_id(packet::SessionID(*b"server01"));
        client.set_clock(Arc::new(|| rekey_b_unix(1714567890)));

        let ctx = CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_secs(1));

        client.queue_ack(42);
        client.retransmit_pending(&ctx).await.expect("retransmit pending");
        let pending = client.state().lock().ack_pending.clone();
        assert!(pending.len() == 1 && pending[0] == 42, "ackPending after empty retransmit = {pending:?}, want [42]");
    }

    #[tokio::test]
    async fn test_decrypt_rejects_unknown_key_id() {
        let client = new_bare_control_client();
        let packet = [packet::opcode_key_id(packet::P_DATA_V2, 0)];
        assert!(client.decrypt_data_packet(&packet).is_err(), "unknown key id was accepted");
    }

    #[tokio::test]
    async fn test_decrypt_rejects_expired_retiring_key() {
        let current = Arc::new(data::data_channel_with_key_id(2));
        let retiring = Arc::new(data::data_channel_with_key_id(1));
        let client = new_bare_control_client();
        {
            let mut state = client.data.write();
            state.data = Some(Arc::clone(&current));
            state.retiring = Some(Arc::clone(&retiring));
            state.retiring_expiry = Some(tokio::time::Instant::now() - Duration::from_secs(1));
            state.data_by_key = HashMap::from([(1u8, Arc::clone(&retiring)), (2u8, Arc::clone(&current))]);
        }

        let packet = [packet::opcode_key_id(packet::P_DATA_V2, 1)];
        assert!(client.decrypt_data_packet(&packet).is_err(), "expired retiring key was accepted");
    }

    #[tokio::test]
    async fn test_decrypt_accepts_retiring_key_before_expiry() {
        let current = Arc::new(data::data_channel_with_key_id(2));
        let retiring = Arc::new(data::data_channel_with_key_id(1));
        let client = new_bare_control_client();
        {
            let mut state = client.data.write();
            state.data = Some(Arc::clone(&current));
            state.retiring = Some(Arc::clone(&retiring));
            state.retiring_expiry = Some(tokio::time::Instant::now() + Duration::from_secs(3600));
            state.data_by_key = HashMap::from([(1u8, Arc::clone(&retiring)), (2u8, Arc::clone(&current))]);
        }

        let packet = [packet::opcode_key_id(packet::P_DATA_V2, 1)];
        if let Err(err) = client.decrypt_data_packet(&packet) {
            let message = err.to_string();
            assert_ne!(
                message, "openvpn data packet with unknown key id",
                "retiring key rejected before expiry: {err}"
            );
            assert_ne!(
                message, "openvpn data packet from expired retiring epoch",
                "retiring key rejected as expired before expiry: {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_mru_carries_ack_on_subsequent_sends() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), true).expect("tls-crypt"));
        let server_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), false).expect("tls-crypt"));
        let client_id = packet::SessionID(*b"client01");
        let server_id = packet::SessionID(*b"server01");

        let client =
            ControlChannel::new(Arc::<MemoryPacketIO>::clone(&client_io), Some(Arc::clone(&client_crypt)), client_id);
        client.set_remote_session_id(server_id);
        let server =
            ControlChannel::new(Arc::<MemoryPacketIO>::clone(&server_io), Some(Arc::clone(&server_crypt)), server_id);
        server.set_remote_session_id(client_id);
        client.set_clock(Arc::new(|| rekey_b_unix(1714567890)));
        server.set_clock(Arc::new(|| rekey_b_unix(1714567891)));

        let ctx = CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_secs(2));

        server.adopt_key_id(1);
        server.send(&ctx, packet::P_CONTROL_SOFT_RESET_V1, &[]).await.expect("server soft reset");
        let soft = client.wait_for_soft_reset(&ctx).await.expect("soft reset");
        client.adopt_key_id(1);
        client.mark_received(soft.message_id);
        client.queue_ack(soft.message_id);

        client.send_soft_reset(&ctx).await.expect("client soft reset");
        let raw = server_io.read_packet(&ctx).await.expect("read packet");
        let (first, _, _) =
            packet::decode_control_packet(Some(server_crypt.as_ref()), &raw).expect("decode control packet");
        assert!(
            first.ack_ids.contains(&soft.message_id),
            "first packet missing ACK {}: {:?}",
            soft.message_id,
            first.ack_ids
        );

        client.send(&ctx, packet::P_CONTROL_V1, b"second").await.expect("second control packet");
        let raw = server_io.read_packet(&ctx).await.expect("read packet");
        let (second, _, _) =
            packet::decode_control_packet(Some(server_crypt.as_ref()), &raw).expect("decode control packet");
        assert!(
            second.ack_ids.contains(&soft.message_id),
            "second packet lost ACK {} (MRU): {:?}",
            soft.message_id,
            second.ack_ids
        );
    }

    #[tokio::test]
    async fn test_mru_move_to_front_matches_reference() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let client =
            ControlChannel::new(Arc::<MemoryPacketIO>::clone(&client_io), None, packet::SessionID(*b"client01"));
        client.state().lock().lru_acks = vec![1, 2, 3, 4, 5, 6, 7, 8];
        client.state().lock().ack_pending = vec![8, 9];

        let got = client.take_acks_locked(control::RELIABLE_ACK_SIZE);
        let want = [8u32, 9, 1, 2, 3, 4, 5, 6];
        assert_eq!(got.len(), want.len(), "len={} want {}: {got:?}", got.len(), want.len());
        assert_eq!(got.as_slice(), want.as_slice(), "got {got:?} want {want:?}");

        let mru = client.state().lock().lru_acks.clone();
        assert_eq!(mru.len(), want.len(), "mru len={} want {}: {mru:?}", mru.len(), want.len());
        assert_eq!(mru.as_slice(), want.as_slice(), "mru got {mru:?} want {want:?}");
    }

    #[tokio::test]
    async fn test_ack_cap_retains_unsent_pending() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client =
            ControlChannel::new(Arc::<MemoryPacketIO>::clone(&client_io), None, packet::SessionID(*b"client01"));
        client.set_remote_session_id(packet::SessionID(*b"server01"));
        client.set_clock(Arc::new(|| rekey_b_unix(1714567890)));

        let ctx = CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_secs(2));

        for i in 1..=5 {
            client.queue_ack(i);
        }
        client.send_ack(&ctx).await.expect("send ack");

        let raw = server_io.read_packet(&ctx).await.expect("read packet");
        let (first, _, _) = packet::decode_control_packet(None, &raw).expect("decode control packet");
        let want_first = [1u32, 2, 3, 4];
        assert_eq!(
            first.ack_ids.as_slice(),
            want_first.as_slice(),
            "first packet acks = {:?}, want {want_first:?}",
            first.ack_ids
        );
        let pending = client.state().lock().ack_pending.clone();
        assert!(pending.len() == 1 && pending[0] == 5, "ackPending after first send = {pending:?}, want [5]");

        client.send_ack(&ctx).await.expect("send ack");
        let raw = server_io.read_packet(&ctx).await.expect("read packet");
        let (second, _, _) = packet::decode_control_packet(None, &raw).expect("decode control packet");
        assert!(second.ack_ids.contains(&5), "second packet missing retained ACK 5: {:?}", second.ack_ids);
    }

    #[tokio::test]
    async fn test_ack_serialization_caps() {
        let cases: [(&str, bool, u8, usize, usize); 6] = [
            ("reliable-control-with-tls", true, 0, 0, 4),
            ("reliable-control-plain", false, 0, 0, 4),
            ("dedicated-ack-with-tls", true, 1, 0, 5),
            ("dedicated-ack-plain", false, 1, 0, 4),
            ("retransmit-with-tls", true, 2, 2, 4),
            ("retransmit-plain", false, 2, 2, 4),
        ];

        for (name, with_tls, path, reads, want_max) in cases {
            let (client_io, server_io) = new_memory_packet_pair();
            let client_id = packet::SessionID(*b"client01");
            let server_id = packet::SessionID(*b"server01");

            let crypt: Option<Arc<dyn ControlCryptor>> = if with_tls {
                Some(Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), true).expect("tls-crypt")))
            } else {
                None
            };
            let peer_crypt: Option<Arc<dyn ControlCryptor>> = if with_tls {
                Some(Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), false).expect("tls-crypt")))
            } else {
                None
            };

            let client = ControlChannel::new(Arc::<MemoryPacketIO>::clone(&client_io), crypt, client_id);
            client.set_remote_session_id(server_id);
            client.set_clock(Arc::new(|| rekey_b_unix(1714567890)));

            let ctx = CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_secs(2));

            match path {
                0 => {
                    for i in 1..=5 {
                        client.queue_ack(i);
                    }
                    client.send(&ctx, packet::P_CONTROL_V1, b"data").await.expect("reliable control send");
                }
                1 => {
                    for i in 0..5 {
                        client.queue_ack(i);
                    }
                    client.send_ack(&ctx).await.expect("dedicated ack send");
                }
                _ => {
                    client.send(&ctx, packet::P_CONTROL_V1, b"data").await.expect("reliable control send");
                    for i in 0..5 {
                        client.queue_ack(i);
                    }
                    client.retransmit_pending(&ctx).await.expect("retransmit pending");
                }
            }

            let reads = if reads == 0 { 1 } else { reads };
            let mut pkt = None;
            for _ in 0..reads {
                let raw = server_io.read_packet(&ctx).await.expect("read packet");
                let decoded = packet::decode_control_packet(peer_crypt.as_deref(), &raw)
                    .unwrap_or_else(|err| panic!("decode: {err}"));
                pkt = Some(decoded.0);
            }
            let pkt = pkt.expect("decoded packet");
            assert!(
                pkt.ack_ids.len() <= want_max,
                "serialized {} acks, want <= {want_max}: {:?} ({name})",
                pkt.ack_ids.len(),
                pkt.ack_ids
            );
            assert!(!pkt.ack_ids.is_empty(), "expected at least one ack ({name})");
        }
    }

    #[tokio::test]
    async fn test_read_token_push_reply_clears_deadline_on_success() {
        let conn = ChunkConn { data: vec![b"PUSH_REPLY,auth-token SESS_ID_new\x00".to_vec()], ..Default::default() };
        let (reply, _) = read_token_push_reply(&conn, &[], &[]).await.expect("token push reply");
        assert!(reply.is_some(), "expected a reply");
        let read_deadline = *conn.last_deadline.lock();
        assert!(read_deadline.is_none(), "read deadline not cleared on success: {read_deadline:?}");
    }

    #[tokio::test]
    async fn test_read_token_push_reply_clears_deadline_on_error() {
        let conn = ChunkConn::default();
        let (reply, _) = read_token_push_reply(&conn, &[], &[]).await.expect("empty token push reply");
        assert!(reply.is_none(), "unexpected reply: {reply:?}");
        let read_deadline = *conn.last_deadline.lock();
        assert!(read_deadline.is_none(), "read deadline not cleared on no-data path: {read_deadline:?}");
    }

    #[tokio::test]
    async fn test_read_all_emits_parked_before_contiguous() {
        let (client, _server) = new_test_channels();
        client.state().lock().recv_message = 2;
        client.state().lock().recv_pending.insert(
            2,
            Arc::new(ControlPacket {
                opcode: packet::P_CONTROL_V1,
                message_id: 2,
                payload: b"later".to_vec(),
                ..Default::default()
            }),
        );
        client.state().lock().parked_tls = vec![b"earlier".to_vec()];

        let out = client.read_all();
        assert_eq!(out.len(), 2, "len = {}, want 2", out.len());
        assert_eq!(
            out[0].payload.as_slice(),
            b"earlier",
            "order wrong: {:?} then {:?}",
            out[0].payload,
            out[1].payload
        );
        assert_eq!(out[1].payload.as_slice(), b"later", "order wrong: {:?} then {:?}", out[0].payload, out[1].payload);
    }

    #[tokio::test]
    async fn test_wait_for_soft_reset_rejects_invalid_parked_reset() {
        let (client, server) = new_test_channels();
        client.set_remote_session_id(server.local_session_id());
        server.set_remote_session_id(client.local_session_id());
        client.adopt_key_id(1);
        client.state().lock().pending_soft_reset = Some(Arc::new(ControlPacket {
            opcode: packet::P_CONTROL_SOFT_RESET_V1,
            key_id: 2,
            message_id: 5,
            local_session: server.local_session_id(),
            ..Default::default()
        }));

        let ctx = CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_millis(150));
        assert!(client.wait_for_soft_reset(&ctx).await.is_err(), "invalid parked reset was accepted");
    }

    #[tokio::test]
    async fn test_mark_received_unblocks_next_epoch_control() {
        let (client, server) = new_test_channels();
        client.set_remote_session_id(server.local_session_id());
        server.set_remote_session_id(client.local_session_id());

        let ctx = CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_secs(2));

        server.adopt_key_id(1);
        server.send(&ctx, packet::P_CONTROL_SOFT_RESET_V1, &[]).await.expect("server soft reset");
        let reset = client.wait_for_soft_reset(&ctx).await.expect("soft reset");
        assert!(
            reset.key_id == 1 && reset.message_id == 0,
            "soft reset = key {} msg {}",
            reset.key_id,
            reset.message_id
        );

        client.adopt_key_id(1);
        client.mark_received(reset.message_id);
        client.queue_ack(reset.message_id);
        client.send_soft_reset(&ctx).await.expect("client soft reset");

        server.send(&ctx, packet::P_CONTROL_V1, b"server-hello").await.expect("server hello");
        let got = client.read(&ctx).await.expect("client did not receive post-rekey control");
        assert!(
            got.message_id == 1 && got.payload.as_slice() == b"server-hello",
            "unexpected packet: id={} payload={:?}",
            got.message_id,
            got.payload
        );
    }

    #[tokio::test]
    async fn test_capture_auth_token_used_on_next_key_method() {
        let client = new_bare_control_client();
        {
            let mut state = client.state.lock();
            state.auth_user = "orig".to_owned();
            state.auth_pass = "origpass".to_owned();
        }
        let push = PushReply {
            auth_token_user: "test".to_owned(),
            auth_token_pass: "SESS_ID_next".to_owned(),
            ..Default::default()
        };
        client.capture_auth_token(&push);

        let (auth_user, auth_pass) = {
            let state = client.state.lock();
            (state.auth_user.clone(), state.auth_pass.clone())
        };
        assert!(
            auth_user == "test" && auth_pass == "SESS_ID_next",
            "auth credentials not refreshed: {auth_user:?}/{auth_pass:?}"
        );
    }

    #[tokio::test]
    async fn test_rekey_consumes_token_push_reply_and_keeps_peer_id() {
        let client = new_bare_control_client();
        {
            let mut state = client.state.lock();
            state.push = Some(PushReply { peer_id: 42, ..Default::default() });
            state.leftover_tls = b"PUSH_REPLY,auth-token SESS_ID_new,auth-token-user dGVzdA==\x00".to_vec();
        }

        client.consume_rekey_push().await.expect("consume rekey push");

        let (peer_id, auth_token_pass) = {
            let state = client.state.lock();
            let push = state.push.as_ref().expect("cached push");
            (push.peer_id, push.auth_token_pass.clone())
        };
        assert_eq!(peer_id, 42, "peer-id not inherited across rekey: {peer_id}");
        assert_eq!(auth_token_pass, "SESS_ID_new", "auth-token not renewed");

        let (auth_user, auth_pass) = {
            let state = client.state.lock();
            (state.auth_user.clone(), state.auth_pass.clone())
        };
        assert!(
            auth_user == "test" && auth_pass == "SESS_ID_new",
            "auth credentials not applied: {auth_user:?}/{auth_pass:?}"
        );
    }

    #[tokio::test]
    async fn test_wait_for_soft_reset_parks_late_control_payload() {
        let (client, server) = new_test_channels();
        client.set_remote_session_id(server.local_session_id());
        server.set_remote_session_id(client.local_session_id());

        let ctx = CancelContext::background().with_deadline(tokio::time::Instant::now() + Duration::from_secs(2));

        client.adopt_key_id(1);
        server.adopt_key_id(1);

        let task_ctx = ctx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = server.send(&task_ctx, packet::P_CONTROL_V1, b"PUSH_REPLY,auth-token SESS_ID_parked\x00").await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            server.adopt_key_id(2);
            let _ = server.send(&task_ctx, packet::P_CONTROL_SOFT_RESET_V1, &[]).await;
        });

        let err = client.wait_for_soft_reset(&ctx).await.expect_err("expected errParkedTLS");
        assert!(err.downcast_ref::<control::ErrParkedTLS>().is_some(), "expected errParkedTLS, got {err}");

        let queued = client.read_all();
        assert!(
            queued.len() == 1 && queued[0].payload.as_slice() == b"PUSH_REPLY,auth-token SESS_ID_parked\x00",
            "parked payload lost: {queued:?}"
        );

        let got = client.wait_for_soft_reset(&ctx).await.expect("soft reset");
        assert!(
            got.opcode == packet::P_CONTROL_SOFT_RESET_V1 && got.key_id == 2,
            "got {} key={}",
            got.opcode,
            got.key_id
        );
    }

    #[tokio::test]
    async fn test_consume_rekey_push_reads_parked_token_via_leftover() {
        let client = new_bare_control_client();
        {
            let mut state = client.state.lock();
            state.push =
                Some(PushReply { peer_id: 9, auth_token_pass: "SESS_ID_old".to_owned(), ..Default::default() });
            state.leftover_tls = b"PUSH_REPLY,auth-token SESS_ID_parked,auth-token-user dGVzdA==\x00".to_vec();
        }

        client.consume_rekey_push().await.expect("consume rekey push");

        let (auth_pass, peer_id) = {
            let state = client.state.lock();
            (state.auth_pass.clone(), state.push.as_ref().map(|push| push.peer_id))
        };
        assert_eq!(auth_pass, "SESS_ID_parked", "parked token not applied");
        assert_eq!(peer_id, Some(9), "peer-id lost");
    }

    #[tokio::test]
    async fn test_looks_like_following_tls_control_not_on_whole_km2_buffer() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.push(keymethod::KEY_METHOD_2);
        packet.extend(std::iter::repeat_n(1u8, keymethod::KEY_SOURCE_RANDOM_SIZE));
        packet.extend(std::iter::repeat_n(2u8, keymethod::KEY_SOURCE_RANDOM_SIZE));
        keymethod::append_openvpn_string(&mut packet, "server-options");
        packet.extend_from_slice(b"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\x00");

        assert!(
            !keymethod::looks_like_following_tls_control(&packet),
            "looksLikeFollowingTLSControl must not match a KM2-prefixed buffer"
        );

        let mut offset = 5 + keymethod::KEY_SOURCE_RANDOM_SIZE * 2;
        offset += 2 + usize::from(u16::from_be_bytes([packet[offset], packet[offset + 1]]));
        assert!(
            keymethod::looks_like_following_tls_control(&packet[offset..]),
            "tail after options should look like TLS control"
        );
        assert!(
            parse_server_key_method2_record_consumed(&packet).is_ok(),
            "shortened record should parse via tail check"
        );
    }

    #[tokio::test]
    async fn test_rekey_keeps_peer_id_without_token_push() {
        let client = new_bare_control_client();
        client.state.lock().push = Some(PushReply { peer_id: 7, ..Default::default() });

        client.consume_rekey_push().await.expect("consume rekey push");

        let peer_id = client.state.lock().push.as_ref().map(|push| push.peer_id);
        assert_eq!(peer_id, Some(7), "peer-id not inherited across rekey without token: {peer_id:?}");
    }

    // ---- control-channel tests ----
    fn control_test_closed_error() -> anyhow::Error {
        anyhow::Error::new(control::closed_error())
    }

    fn control_test_ctx_error(ctx: &CancelContext) -> anyhow::Error {
        ctx.err().unwrap_or_else(|| anyhow::Error::new(ContextError::DeadlineExceeded))
    }

    fn control_test_is_timeout_error(err: &anyhow::Error) -> bool {
        err.chain().any(|cause| {
            cause
                .downcast_ref::<io::Error>()
                .is_some_and(|err| matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock))
        })
    }

    fn control_test_ctx(timeout: Duration) -> CancelContext {
        CancelContext::background().with_deadline(tokio::time::Instant::now() + timeout)
    }

    fn control_test_datetime(seconds: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(seconds, 0).expect("valid test timestamp")
    }

    fn control_test_now_unix_nanos() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after the unix epoch")
            .as_nanos() as i64
    }

    pub(crate) struct MemoryPacketIO {
        incoming: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
        outgoing: mpsc::Sender<Vec<u8>>,
        closed: CancellationToken,
    }

    impl MemoryPacketIO {
        pub(crate) fn from_channels(incoming: mpsc::Receiver<Vec<u8>>, outgoing: mpsc::Sender<Vec<u8>>) -> Self {
            Self { incoming: tokio::sync::Mutex::new(incoming), outgoing, closed: CancellationToken::new() }
        }

        pub(crate) async fn read_packet(&self, ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
            let mut incoming = self.incoming.lock().await;
            tokio::select! {
                () = ctx.done() => Err(control_test_ctx_error(ctx)),
                () = self.closed.cancelled() => Err(control_test_closed_error()),
                packet = incoming.recv() => packet.ok_or_else(control_test_closed_error),
            }
        }

        pub(crate) async fn write_packet(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
            tokio::select! {
                () = ctx.done() => Err(control_test_ctx_error(ctx)),
                () = self.closed.cancelled() => Err(control_test_closed_error()),
                sent = self.outgoing.send(packet.to_vec()) => sent.map_err(|_| control_test_closed_error()),
            }
        }

        pub(crate) fn try_read_packet(&self) -> Option<Vec<u8>> {
            let mut incoming = self.incoming.try_lock().ok()?;
            incoming.try_recv().ok()
        }

        pub(crate) async fn close(&self) -> anyhow::Result<()> {
            self.closed.cancel();
            Ok(())
        }

        pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("local"))
        }

        pub(crate) fn remote_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("remote"))
        }
    }

    #[async_trait::async_trait]
    impl control::ControlIO for MemoryPacketIO {
        async fn read_packet(&self, ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
            MemoryPacketIO::read_packet(self, ctx).await
        }

        async fn write_packet(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
            MemoryPacketIO::write_packet(self, ctx, packet).await
        }

        async fn write_packet_allow_active_stop(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
            MemoryPacketIO::write_packet(self, ctx, packet).await
        }

        async fn close(&self) -> anyhow::Result<()> {
            MemoryPacketIO::close(self).await
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            MemoryPacketIO::local_addr(self)
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            MemoryPacketIO::remote_addr(self)
        }
    }

    pub(crate) fn new_memory_packet_pair() -> (Arc<MemoryPacketIO>, Arc<MemoryPacketIO>) {
        let (a_to_b_tx, a_to_b_rx) = mpsc::channel(16);
        let (b_to_a_tx, b_to_a_rx) = mpsc::channel(16);
        let a = Arc::new(MemoryPacketIO::from_channels(b_to_a_rx, a_to_b_tx));
        let b = Arc::new(MemoryPacketIO::from_channels(a_to_b_rx, b_to_a_tx));
        (a, b)
    }

    pub(crate) struct ControlIOPacketAdapter {
        io: Arc<dyn control::ControlIO>,
        ctx: CancelContext,
    }

    impl ControlIOPacketAdapter {
        pub(crate) fn new(io: Arc<dyn control::ControlIO>) -> Self {
            Self { io, ctx: CancelContext::background() }
        }

        pub(crate) async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>) {
            match control::ControlIO::read_packet(&*self.io, &self.ctx).await {
                Ok(packet) => (Some(packet), None),
                Err(err) => (None, Some(err)),
            }
        }

        pub(crate) async fn write_packet(&self, packet: &[u8]) -> anyhow::Result<()> {
            control::ControlIO::write_packet(&*self.io, &CancelContext::background(), packet).await
        }

        pub(crate) async fn close(&self) -> anyhow::Result<()> {
            self.ctx.cancel(None);
            control::ControlIO::close(&*self.io).await
        }

        pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
            control::ControlIO::local_addr(&*self.io)
        }

        pub(crate) fn remote_addr(&self) -> Option<SocketAddr> {
            control::ControlIO::remote_addr(&*self.io)
        }
    }

    #[async_trait::async_trait]
    impl PacketIO for ControlIOPacketAdapter {
        async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>) {
            ControlIOPacketAdapter::read_packet(self).await
        }

        async fn write_packet(&self, packet: &[u8]) -> anyhow::Result<()> {
            ControlIOPacketAdapter::write_packet(self, packet).await
        }

        async fn close(&self) -> anyhow::Result<()> {
            ControlIOPacketAdapter::close(self).await
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            ControlIOPacketAdapter::local_addr(self)
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            ControlIOPacketAdapter::remote_addr(self)
        }
    }

    pub(crate) fn control_io_packet_adapter(io: Arc<dyn control::ControlIO>) -> Arc<dyn PacketIO> {
        Arc::new(ControlIOPacketAdapter::new(io))
    }

    pub(crate) struct InitialPacketRecordingIO {
        inner: Arc<dyn control::ControlIO>,
        pub(crate) marked: CancellationToken,
    }

    impl InitialPacketRecordingIO {
        pub(crate) fn new(inner: Arc<dyn control::ControlIO>) -> Self {
            Self { inner, marked: CancellationToken::new() }
        }

        pub(crate) fn mark_initial_packet_received(&self) {
            self.marked.cancel();
        }
    }

    #[async_trait::async_trait]
    impl control::ControlIO for InitialPacketRecordingIO {
        async fn read_packet(&self, ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
            control::ControlIO::read_packet(&*self.inner, ctx).await
        }

        async fn write_packet(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
            control::ControlIO::write_packet(&*self.inner, ctx, packet).await
        }

        async fn write_packet_allow_active_stop(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
            control::ControlIO::write_packet_allow_active_stop(&*self.inner, ctx, packet).await
        }

        async fn close(&self) -> anyhow::Result<()> {
            control::ControlIO::close(&*self.inner).await
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            control::ControlIO::local_addr(&*self.inner)
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            control::ControlIO::remote_addr(&*self.inner)
        }

        fn mark_initial_packet_received(&self) {
            InitialPacketRecordingIO::mark_initial_packet_received(self);
        }
    }

    pub(crate) fn dummy_addr(name: &str) -> SocketAddr {
        let port = if name == "remote" { 2 } else { 1 };
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    pub(crate) fn new_test_client(
        config: &Arc<ClientConfig>,
        packet_io: Arc<dyn PacketIO>,
    ) -> anyhow::Result<Arc<Client>> {
        Client::new(Arc::clone(config), packet_io)
    }

    fn start_test_ack_flusher(channel: &Arc<ControlChannel>) {
        let channel = Arc::clone(channel);
        tokio::spawn(async move {
            let ctx = CancelContext::background();
            loop {
                channel.wait_ack_wake().await;
                while channel.pending_acks() > 0 {
                    if channel.send_ack(&ctx).await.is_err() {
                        return;
                    }
                }
            }
        });
    }

    pub(crate) fn new_test_channels_with_io(
    ) -> (Arc<ControlChannel>, Arc<ControlChannel>, Arc<MemoryPacketIO>, Arc<MemoryPacketIO>) {
        let (client_io, server_io) = new_memory_packet_pair();
        let client_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), true).expect("client tls crypt"));
        let server_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), false).expect("server tls crypt"));

        let client = Arc::new(ControlChannel::new(
            Arc::<MemoryPacketIO>::clone(&client_io),
            Some(client_crypt),
            packet::SessionID(*b"client01"),
        ));
        let server = Arc::new(ControlChannel::new(
            Arc::<MemoryPacketIO>::clone(&server_io),
            Some(server_crypt),
            packet::SessionID(*b"server01"),
        ));
        client.set_remote_session_id(packet::SessionID(*b"server01"));
        server.set_remote_session_id(packet::SessionID(*b"client01"));
        client.set_clock(Arc::new(|| control_test_datetime(1_714_567_890)));
        server.set_clock(Arc::new(|| control_test_datetime(1_714_567_891)));
        start_test_ack_flusher(&client);
        start_test_ack_flusher(&server);
        (client, server, client_io, server_io)
    }

    pub(crate) fn new_test_channels() -> (Arc<ControlChannel>, Arc<ControlChannel>) {
        let (client, server, _client_io, _server_io) = new_test_channels_with_io();
        (client, server)
    }

    pub(crate) struct RecordingPacketIO {
        writes: std::sync::atomic::AtomicUsize,
    }

    impl RecordingPacketIO {
        pub(crate) fn new() -> Self {
            Self { writes: std::sync::atomic::AtomicUsize::new(0) }
        }

        pub(crate) fn writes(&self) -> usize {
            self.writes.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl control::ControlIO for RecordingPacketIO {
        async fn read_packet(&self, ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
            ctx.done().await;
            Err(control_test_ctx_error(ctx))
        }

        async fn write_packet(&self, _ctx: &CancelContext, _packet: &[u8]) -> anyhow::Result<()> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn write_packet_allow_active_stop(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
            RecordingPacketIO::write_packet(self, ctx, packet).await
        }

        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("local"))
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("remote"))
        }
    }

    pub(crate) struct DeadlineRacePacketIO {
        packet: Vec<u8>,
        pub(crate) started: CancellationToken,
        pub(crate) release: CancellationToken,
    }

    impl DeadlineRacePacketIO {
        pub(crate) fn new(packet: Vec<u8>) -> Self {
            Self { packet, started: CancellationToken::new(), release: CancellationToken::new() }
        }
    }

    #[async_trait::async_trait]
    impl control::ControlIO for DeadlineRacePacketIO {
        async fn read_packet(&self, _ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
            self.started.cancel();
            self.release.cancelled().await;
            Ok(self.packet.clone())
        }

        async fn write_packet(&self, _ctx: &CancelContext, _packet: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }

        async fn write_packet_allow_active_stop(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
            DeadlineRacePacketIO::write_packet(self, ctx, packet).await
        }

        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("local"))
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("remote"))
        }
    }

    pub(crate) struct BlockingWritePacketIO {
        pub(crate) entered: CancellationToken,
    }

    impl BlockingWritePacketIO {
        pub(crate) fn new() -> Self {
            Self { entered: CancellationToken::new() }
        }
    }

    #[async_trait::async_trait]
    impl control::ControlIO for BlockingWritePacketIO {
        async fn read_packet(&self, ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
            ctx.done().await;
            Err(control_test_ctx_error(ctx))
        }

        async fn write_packet(&self, ctx: &CancelContext, _packet: &[u8]) -> anyhow::Result<()> {
            self.entered.cancel();
            ctx.done().await;
            Err(control_test_ctx_error(ctx))
        }

        async fn write_packet_allow_active_stop(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
            BlockingWritePacketIO::write_packet(self, ctx, packet).await
        }

        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("local"))
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("remote"))
        }
    }

    pub(crate) struct HeldCanceledWritePacketIO {
        pub(crate) entered: CancellationToken,
        pub(crate) canceled: CancellationToken,
        pub(crate) release: CancellationToken,
    }

    impl HeldCanceledWritePacketIO {
        pub(crate) fn new() -> Self {
            Self {
                entered: CancellationToken::new(),
                canceled: CancellationToken::new(),
                release: CancellationToken::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl control::ControlIO for HeldCanceledWritePacketIO {
        async fn read_packet(&self, ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
            ctx.done().await;
            Err(control_test_ctx_error(ctx))
        }

        async fn write_packet(&self, ctx: &CancelContext, _packet: &[u8]) -> anyhow::Result<()> {
            self.entered.cancel();
            ctx.done().await;
            self.canceled.cancel();
            self.release.cancelled().await;
            Err(control_test_ctx_error(ctx))
        }

        async fn write_packet_allow_active_stop(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
            HeldCanceledWritePacketIO::write_packet(self, ctx, packet).await
        }

        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("local"))
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("remote"))
        }
    }

    pub(crate) struct AckCloseRacePacketIO {
        pub(crate) entered: CancellationToken,
        pub(crate) release: CancellationToken,
        writes: Mutex<usize>,
    }

    impl AckCloseRacePacketIO {
        pub(crate) fn new() -> Self {
            Self { entered: CancellationToken::new(), release: CancellationToken::new(), writes: Mutex::new(0) }
        }

        pub(crate) fn writes(&self) -> usize {
            *self.writes.lock()
        }
    }

    #[async_trait::async_trait]
    impl control::ControlIO for AckCloseRacePacketIO {
        async fn read_packet(&self, ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
            ctx.done().await;
            Err(control_test_ctx_error(ctx))
        }

        async fn write_packet(&self, _ctx: &CancelContext, _packet: &[u8]) -> anyhow::Result<()> {
            let count = {
                let mut writes = self.writes.lock();
                *writes += 1;
                *writes
            };
            if count == 1 {
                self.entered.cancel();
                self.release.cancelled().await;
            }
            Ok(())
        }

        async fn write_packet_allow_active_stop(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
            AckCloseRacePacketIO::write_packet(self, ctx, packet).await
        }

        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("local"))
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("remote"))
        }
    }

    /// Stands in for a physical socket that blocks in a read or write until the transport closes it:
    /// `packetio::PacketIO` carries no context, so only `close` can interrupt it.
    pub(crate) struct BlockedPhysicalPacketIO {
        pub(crate) read_entered: CancellationToken,
        pub(crate) write_entered: CancellationToken,
        released: CancellationToken,
    }

    impl BlockedPhysicalPacketIO {
        pub(crate) fn new() -> Self {
            Self {
                read_entered: CancellationToken::new(),
                write_entered: CancellationToken::new(),
                released: CancellationToken::new(),
            }
        }

        pub(crate) fn release(&self) {
            self.released.cancel();
        }
    }

    #[async_trait::async_trait]
    impl PacketIO for BlockedPhysicalPacketIO {
        async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>) {
            self.read_entered.cancel();
            self.released.cancelled().await;
            (None, Some(control_test_closed_error()))
        }

        async fn write_packet(&self, _packet: &[u8]) -> anyhow::Result<()> {
            self.write_entered.cancel();
            self.released.cancelled().await;
            Err(control_test_closed_error())
        }

        async fn close(&self) -> anyhow::Result<()> {
            self.released.cancel();
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("local"))
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("remote"))
        }
    }

    /// In-memory replacement for an in-process pipe, which the crate has no implementor for.
    #[derive(Debug)]
    pub(crate) struct ControlTestPipe(tokio::io::DuplexStream);

    impl ControlTestPipe {
        pub(crate) fn pair(buffer: usize) -> (ControlTestPipe, ControlTestPipe) {
            let (a, b) = tokio::io::duplex(buffer);
            (ControlTestPipe(a), ControlTestPipe(b))
        }
    }

    impl AsyncRead for ControlTestPipe {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
        }
    }

    impl AsyncWrite for ControlTestPipe {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
        }
    }

    impl Stream for ControlTestPipe {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(dummy_addr("local"))
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(dummy_addr("remote"))
        }
    }

    fn control_test_envelope(inner: &ControlPacket, crypt: Option<&dyn ControlCryptor>) -> Vec<u8> {
        inner.encode(crypt, 0, 0).expect("encode control packet")
    }

    async fn control_test_send_buffered_duplicate(
        client: &Arc<ControlChannel>,
        server_io: &Arc<MemoryPacketIO>,
        crypt: &dyn ControlCryptor,
        inner: &ControlPacket,
        outer_pid: u32,
    ) -> ControlPacket {
        let raw = inner.encode(Some(crypt), outer_pid, 1_714_567_891).expect("encode buffered duplicate");
        server_io.write_packet(&CancelContext::background(), &raw).await.expect("write buffered duplicate");
        let ctx = control_test_ctx(Duration::from_millis(100));
        let _ = client.read(&ctx).await;
        let ack_raw = server_io.try_read_packet().expect("buffered in-window duplicate was not re-ACKed");
        let (ack, _, _) = packet::decode_control_packet(Some(crypt), &ack_raw).expect("decode ack");
        ack
    }

    #[tokio::test]
    async fn test_recv_pending_bounded() {
        const BASE: u32 = 100;
        for i in 1..control::RELIABLE_CAPACITY as u32 {
            assert!(control::recv_window_ok(BASE, BASE + i, (i - 1) as usize), "in-window id {} refused", BASE + i);
        }
        assert!(
            !control::recv_window_ok(BASE, BASE + 1, control::RELIABLE_CAPACITY),
            "buffered==capacity should refuse"
        );
        assert!(
            !control::recv_window_ok(BASE, BASE + control::RELIABLE_CAPACITY as u32, 0),
            "id at window edge accepted"
        );
        assert!(
            !control::recv_window_ok(BASE, BASE + control::RELIABLE_CAPACITY as u32 + 1, 0),
            "id past window accepted"
        );
        assert!(!control::recv_window_ok(BASE, BASE - 1, 0), "id below recvMessage accepted");
    }

    #[tokio::test]
    async fn test_reliable_message_window_wraparound() {
        let base = u32::MAX - 1;
        assert!(control::recv_window_ok(base, 0, 0), "wrapped message id inside receive window was rejected");
        assert!(
            !control::recv_window_ok(base, control::RELIABLE_CAPACITY as u32 - 2, 0),
            "wrapped message id at receive window edge was accepted"
        );
        assert!(!control::reliable_message_before(0, base), "wrapped next message classified as replay");
        assert!(control::reliable_message_before(base - 1, base), "previous message not classified as replay");

        let (io, _peer) = new_memory_packet_pair();
        let channel = ControlChannel::new(io, None, packet::SessionID(*b"client01"));
        channel.state.lock().recv_message = base;
        channel.mark_received(u32::MAX);
        assert_eq!(channel.state.lock().recv_message, 0, "MarkReceived did not wrap the receive sequence");
    }

    #[tokio::test]
    async fn test_buffered_duplicate_re_acked() {
        let (client, server, _client_io, server_io) = new_test_channels_with_io();
        client.set_remote_session_id(server.local_session_id());
        server.set_remote_session_id(client.local_session_id());
        let server_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), false).expect("server tls crypt"));

        let inner = ControlPacket {
            opcode: packet::P_CONTROL_V1,
            key_id: 0,
            local_session: server.local_session_id(),
            message_id: 1,
            payload: b"buffer me".to_vec(),
            ..Default::default()
        };

        let first = control_test_send_buffered_duplicate(&client, &server_io, &*server_crypt, &inner, 1).await;
        assert_eq!(first.ack_ids.first(), Some(&1), "first ACK missing message 1: {:?}", first.ack_ids);
        assert_eq!(client.state.lock().recv_pending.len(), 1, "message 1 not buffered");

        let second = control_test_send_buffered_duplicate(&client, &server_io, &*server_crypt, &inner, 2).await;
        assert_eq!(second.ack_ids.first(), Some(&1), "duplicate ACK missing message 1: {:?}", second.ack_ids);
        assert_eq!(client.state.lock().recv_pending.len(), 1, "duplicate was re-inserted");
    }

    #[tokio::test]
    async fn test_out_of_window_packet_not_acked() {
        let (client, server, _client_io, server_io) = new_test_channels_with_io();
        client.set_remote_session_id(server.local_session_id());
        server.set_remote_session_id(client.local_session_id());
        let server_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), false).expect("server tls crypt"));

        client.state.lock().recv_message = 0;
        let pkt = ControlPacket {
            opcode: packet::P_CONTROL_V1,
            key_id: 0,
            local_session: server.local_session_id(),
            message_id: 12,
            payload: b"hello".to_vec(),
            ..Default::default()
        };
        let raw = pkt.encode(Some(&*server_crypt), 1, 1_714_567_890).expect("encode out-of-window packet");
        server_io.write_packet(&CancelContext::background(), &raw).await.expect("write out-of-window packet");

        let ctx = control_test_ctx(Duration::from_millis(100));
        let err = client.read(&ctx).await.expect_err("rejected window packet was delivered");
        assert!(
            is_context_deadline_exceeded(&err) || control_test_is_timeout_error(&err),
            "expected a timeout after the rejected window packet, got {err}"
        );
        assert_eq!(client.state.lock().ack_pending.len(), 0, "out-of-window message was ACKed");
        assert!(server_io.try_read_packet().is_none(), "unexpected outbound packet after the rejected window");
    }

    #[tokio::test]
    async fn test_check_replay_anti_replay() {
        let (io, _peer) = new_memory_packet_pair();
        let channel = ControlChannel::new(io, None, packet::SessionID(*b"client01"));

        channel.check_replay_locked(1, 1000).expect("first packet rejected");
        for id in [2u32, 3, 5] {
            channel.check_replay_locked(id, 1000).expect("advancing id rejected");
        }
        channel.check_replay_locked(4, 1000).expect("out-of-order id 4 rejected");
        assert!(channel.check_replay_locked(4, 1000).is_err(), "replayed id 4 accepted");
        assert!(channel.check_replay_locked(1, 1000).is_err(), "stale id 1 accepted");
        assert!(channel.check_replay_locked(10, 999).is_err(), "timestamp backtrack accepted");
        channel.check_replay_locked(1, 1001).expect("new second id 1 rejected");
        assert!(channel.check_replay_locked(1, 1001).is_err(), "replay after reset accepted");

        channel.begin_epoch_locked(1);
        assert!(
            channel.check_replay_locked(1, 1001).is_err(),
            "key epoch reset accepted an already-seen wrapper packet id"
        );
    }

    #[tokio::test]
    async fn test_control_channel_reset_and_ack() {
        let (client, server) = new_test_channels();
        server.set_remote_session_id(client.local_session_id());

        client.send_reset(&CancelContext::background()).await.expect("send reset");
        let packet = server.read(&CancelContext::background()).await.expect("read reset");
        assert_eq!(packet.opcode, packet::P_CONTROL_HARD_RESET_CLIENT_V2);
        assert_eq!(packet.message_id, 0);
        assert_eq!(client.state.lock().send_packet_id, 1, "unexpected first tls-crypt packet id");
        assert_eq!(server.remote_session_id(), client.local_session_id());

        server.send_ack(&CancelContext::background()).await.expect("send ack");
        let ctx = control_test_ctx(Duration::from_secs(1));
        let err = client.read(&ctx).await.expect_err("expected a deadline after consuming the pure ack");
        assert!(is_context_deadline_exceeded(&err), "expected deadline after consuming pure ack, got {err}");
        assert_eq!(client.pending_messages(), 0, "expected the client reset to be acked");
    }

    #[tokio::test]
    async fn test_control_conn_carries_tls_bytes() {
        let (client, server) = new_test_channels();
        client.set_remote_session_id(server.local_session_id());
        server.set_remote_session_id(client.local_session_id());

        let client_conn = ControlConn::new(Arc::clone(&client));
        let server_conn = ControlConn::new(Arc::clone(&server));

        let writer = {
            let conn = client_conn.clone();
            tokio::spawn(async move {
                let payload = b"client tls record".to_vec();
                conn.write(&payload).await
            })
        };

        let mut buf = vec![0u8; 64];
        let n = server_conn.read(&mut buf).await.expect("server read");
        assert_eq!(&buf[..n], b"client tls record", "unexpected payload");
        writer.await.expect("join").expect("client write");

        let ctx = control_test_ctx(Duration::from_secs(1));
        let err = client.read(&ctx).await.expect_err("expected a deadline after consuming the pure ack");
        assert!(is_context_deadline_exceeded(&err), "expected deadline after consuming pure ack, got {err}");
        assert_eq!(client.pending_messages(), 0, "expected the client message to be acked");
    }

    #[tokio::test]
    async fn test_control_channel_reorders_reliable_messages() {
        let (packets_tx, packets_rx) = mpsc::channel(4);
        let (acks_tx, _acks_rx) = mpsc::channel(4);
        let io = Arc::new(MemoryPacketIO::from_channels(packets_rx, acks_tx));
        let server = ControlChannel::new(io, None, packet::SessionID(*b"server01"));
        server.set_remote_session_id(packet::SessionID(*b"client01"));

        let second = control_test_envelope(
            &ControlPacket {
                opcode: packet::P_CONTROL_V1,
                local_session: packet::SessionID(*b"client01"),
                message_id: 1,
                payload: b"second".to_vec(),
                ..Default::default()
            },
            None,
        );
        let first = control_test_envelope(
            &ControlPacket {
                opcode: packet::P_CONTROL_V1,
                local_session: packet::SessionID(*b"client01"),
                message_id: 0,
                payload: b"first".to_vec(),
                ..Default::default()
            },
            None,
        );

        packets_tx.send(second).await.expect("queue second");
        packets_tx.send(first).await.expect("queue first");

        let ctx = control_test_ctx(Duration::from_secs(1));
        let packet = server.read(&ctx).await.expect("read first");
        assert_eq!(packet.message_id, 0);
        assert_eq!(packet.payload, b"first");
        let packet = server.read(&ctx).await.expect("read second");
        assert_eq!(packet.message_id, 1);
        assert_eq!(packet.payload, b"second");
    }

    #[tokio::test]
    async fn test_client_wait_server_reset_retransmits_udp() {
        let (client_io, server_io) = new_memory_packet_pair();
        let config = ClientConfig { proto: PROTO_UDP.to_owned(), ..Default::default() };
        let client =
            new_test_client(&Arc::new(config), control_io_packet_adapter(Arc::<MemoryPacketIO>::clone(&client_io)))
                .expect("new test client");

        let server_control =
            ControlChannel::new(Arc::<MemoryPacketIO>::clone(&server_io), None, packet::SessionID(*b"server01"));
        server_control.set_remote_session_id(client.control.local_session_id());

        let ctx = control_test_ctx(Duration::from_secs(5));
        client.control.send_reset(&ctx).await.expect("send reset");

        let mut waiter = tokio::spawn({
            let client = Arc::clone(&client);
            let ctx = ctx.clone();
            async move { client.wait_server_reset(&ctx).await }
        });

        let first = server_io.read_packet(&ctx).await.expect("read first reset");
        let (pkt, _, _) = packet::decode_control_packet(None, &first).expect("decode first reset");
        assert_eq!(pkt.opcode, packet::P_CONTROL_HARD_RESET_CLIENT_V2, "unexpected first reset opcode");

        let second = server_io.read_packet(&ctx).await.expect("read retransmitted reset");
        let (pkt, _, _) = packet::decode_control_packet(None, &second).expect("decode retransmitted reset");
        assert_eq!(pkt.opcode, packet::P_CONTROL_HARD_RESET_CLIENT_V2, "unexpected retransmitted reset");
        assert_eq!(pkt.message_id, 0);

        server_control.queue_ack(0);
        server_control.send_ack(&ctx).await.expect("server send ack");
        server_control.send(&ctx, packet::P_CONTROL_HARD_RESET_SERVER_V2, &[]).await.expect("server send reset");

        tokio::select! {
            result = &mut waiter => result.expect("join").expect("wait server reset"),
            () = tokio::time::sleep(Duration::from_secs(5)) => panic!("wait server reset did not finish"),
        }
        assert_eq!(client.control.pending_messages(), 0, "expected the client reset to be acked");
    }

    #[tokio::test]
    async fn test_client_control_watcher_ignores_invalid_packets() {
        let server_id = packet::SessionID(*b"server01");
        let other_id = packet::SessionID(*b"server02");

        let encode = |key_id: u8, local: packet::SessionID| {
            control_test_envelope(
                &ControlPacket {
                    opcode: packet::P_CONTROL_SOFT_RESET_V1,
                    key_id,
                    local_session: local,
                    message_id: 0,
                    ..Default::default()
                },
                None,
            )
        };

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("malformed", vec![packet::opcode_key_id(packet::P_CONTROL_SOFT_RESET_V1, 1)]),
            ("initial key id", encode(0, server_id)),
            ("wrong session", encode(1, other_id)),
        ];

        for (name, raw) in cases {
            let (client_io, server_io) = new_memory_packet_pair();
            let client = new_test_client(&Arc::new(ClientConfig::default()), control_io_packet_adapter(client_io))
                .expect("new test client");
            client.control.set_remote_session_id(server_id);
            let watcher = tokio::spawn({
                let client = Arc::clone(&client);
                async move { client.watch_control().await }
            });

            let ctx = control_test_ctx(Duration::from_millis(50));
            server_io.write_packet(&ctx, &raw).await.expect("write invalid packet");

            assert!(
                !control_test_mux_failed_within(&client, Duration::from_millis(50)).await,
                "invalid packet closed client: {name}"
            );
            assert_eq!(
                client.control.state.lock().recv_message,
                0,
                "invalid packet moved the receive sequence: {name}"
            );
            assert_eq!(client.control.state.lock().ack_pending.len(), 0, "invalid packet queued an ACK: {name}");

            client.close().await.expect("close client");
            watcher.abort();
        }
    }

    #[tokio::test]
    async fn test_control_read_drops_malformed_packet() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = ControlChannel::new(client_io, None, packet::SessionID(*b"client01"));
        client.set_remote_session_id(packet::SessionID(*b"server01"));

        let ctx = control_test_ctx(Duration::from_secs(1));
        server_io
            .write_packet(&ctx, &[packet::opcode_key_id(packet::P_CONTROL_V1, 0)])
            .await
            .expect("write malformed datagram");
        let valid = control_test_envelope(
            &ControlPacket {
                opcode: packet::P_CONTROL_V1,
                local_session: packet::SessionID(*b"server01"),
                message_id: 0,
                payload: b"valid".to_vec(),
                ..Default::default()
            },
            None,
        );
        server_io.write_packet(&ctx, &valid).await.expect("write valid datagram");

        let packet = client.read(&ctx).await.expect("read valid packet");
        assert_eq!(packet.payload, b"valid", "unexpected payload after the malformed datagram");
    }

    #[tokio::test]
    async fn test_control_conn_write_fragments_tls_ciphertext() {
        let (client_io, server_io) = new_memory_packet_pair();
        let channel = ControlChannel::new(client_io, None, packet::SessionID(*b"client01"));
        let conn = ControlConn::new(Arc::new(channel));
        let payload = vec![0x5a_u8; 2 * control::MAX_TLS_CONTROL_PAYLOAD + 17];

        let n = conn.write(&payload).await.expect("write payload");
        assert_eq!(n, payload.len(), "Write returned the wrong length");

        let mut got = Vec::new();
        for _ in 0..3 {
            let raw = server_io.read_packet(&CancelContext::background()).await.expect("read control datagram");
            assert!(raw.len() <= 1250, "control datagram length = {}", raw.len());
            let (packet, _, _) = packet::decode_control_packet(None, &raw).expect("decode datagram");
            assert_eq!(packet.opcode, packet::P_CONTROL_V1);
            got.extend_from_slice(&packet.payload);
        }
        assert_eq!(got, payload, "reassembled payload length mismatch");
    }

    #[tokio::test]
    async fn test_expired_control_write_deadline_skips_packet_io() {
        let packet_io = Arc::new(RecordingPacketIO::new());
        let channel =
            ControlChannel::new(Arc::<RecordingPacketIO>::clone(&packet_io), None, packet::SessionID(*b"client01"));
        channel.queue_ack(1);
        channel
            .set_write_deadline(Some(tokio::time::Instant::now() - Duration::from_secs(1)))
            .expect("set expired write deadline");

        let err =
            channel.send_ack(&CancelContext::background()).await.expect_err("expired deadline must fail the ACK send");
        assert!(is_context_deadline_exceeded(&err), "expired deadline returned {err}");
        assert_eq!(packet_io.writes(), 0, "expired deadline reached the PacketIO");
    }

    #[tokio::test]
    async fn test_control_send_gate_observes_context() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let channel = ControlChannel::new(client_io, None, packet::SessionID(*b"client01"));
        channel.queue_ack(1);
        let _gate = Arc::clone(&channel.send_gate).try_acquire_owned().expect("send gate available");

        let ctx = control_test_ctx(Duration::from_millis(20));
        let err = channel.send_ack(&ctx).await.expect_err("queued control send must time out");
        assert!(is_context_deadline_exceeded(&err), "queued control send returned {err}");
    }

    #[tokio::test]
    async fn test_control_conn_close_cancels_queued_payload_write() {
        let (client_io, server_io) = new_memory_packet_pair();
        let channel = Arc::new(ControlChannel::new(client_io, None, packet::SessionID(*b"client01")));
        let conn = ControlConn::new(Arc::clone(&channel));
        let gate = Arc::clone(&channel.send_gate).try_acquire_owned().expect("send gate available");

        let writer = {
            let conn = conn.clone();
            tokio::spawn(async move {
                let payload = b"queued payload".to_vec();
                conn.write(&payload).await
            })
        };

        let deadline = Instant::now() + Duration::from_secs(1);
        while channel.pending_messages() == 0 {
            assert!(Instant::now() < deadline, "payload was not queued");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        conn.close().expect("close control conn");
        drop(gate);
        let err = writer.await.expect("join").expect_err("queued payload write must fail");
        let err = anyhow::Error::new(err);
        assert!(is_err_net_closed(&err), "queued payload write returned {err}");

        let ctx = control_test_ctx(Duration::from_millis(30));
        assert!(server_io.read_packet(&ctx).await.is_err(), "payload was emitted after Close");
    }

    async fn control_test_mux_failed_within(client: &Arc<Client>, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if client.mux.current_error().is_some() {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test]
    async fn test_soft_reset_received_at_stamped_on_acceptance() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = ControlChannel::new(client_io, None, packet::SessionID(*b"client01"));
        client.set_remote_session_id(packet::SessionID(*b"server01"));
        let reset = control_test_envelope(
            &ControlPacket {
                opcode: packet::P_CONTROL_SOFT_RESET_V1,
                key_id: 1,
                local_session: packet::SessionID(*b"server01"),
                message_id: 0,
                ..Default::default()
            },
            None,
        );

        let before = tokio::time::Instant::now();
        let ctx = control_test_ctx(Duration::from_secs(1));
        server_io.write_packet(&ctx, &reset).await.expect("write soft reset");
        let packet = client.wait_for_soft_reset(&ctx).await.expect("wait for soft reset");
        let after = tokio::time::Instant::now();
        let received_at = packet.received_at.expect("soft reset was not stamped");
        assert!(
            received_at >= before && received_at <= after,
            "soft reset received_at = {received_at:?}, want within [{before:?}, {after:?}]"
        );
    }

    #[tokio::test]
    async fn test_protected_soft_reset_replay_rejected_after_key_reuse() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), true).expect("client tls crypt"));
        let server_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), false).expect("server tls crypt"));
        let client = ControlChannel::new(client_io, Some(client_crypt), packet::SessionID(*b"client01"));
        client.set_remote_session_id(packet::SessionID(*b"server01"));
        {
            let mut state = client.state.lock();
            state.key_id = 7;
            state.rec_replay = control::ReplayState {
                seen: true,
                time: 2000,
                high_id: 100,
                slots: [0; control::CONTROL_REPLAY_WINDOW],
            };
            state.rec_replay.slots[0] = control_test_now_unix_nanos();
        }

        let stale = ControlPacket {
            opcode: packet::P_CONTROL_SOFT_RESET_V1,
            key_id: 1,
            local_session: packet::SessionID(*b"server01"),
            message_id: 0,
            ..Default::default()
        }
        .encode(Some(&*server_crypt), 5, 1000)
        .expect("encode stale soft reset");

        let ctx = control_test_ctx(Duration::from_millis(50));
        server_io.write_packet(&ctx, &stale).await.expect("write stale soft reset");
        let err = client.wait_for_soft_reset(&ctx).await.expect_err("stale wrapped soft reset was accepted");
        assert!(is_context_deadline_exceeded(&err), "stale soft reset returned {err}");
    }

    #[tokio::test]
    async fn test_protected_control_timestamp_stable_across_packets() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), true).expect("client tls crypt"));
        let server_crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), false).expect("server tls crypt"));
        let channel = ControlChannel::new(client_io, Some(client_crypt), packet::SessionID(*b"client01"));

        channel.set_clock(Arc::new(|| control_test_datetime(1000)));
        channel.send(&CancelContext::background(), packet::P_CONTROL_V1, b"one").await.expect("send one");
        channel.set_clock(Arc::new(|| control_test_datetime(2000)));
        channel.send(&CancelContext::background(), packet::P_CONTROL_V1, b"two").await.expect("send two");

        let mut times = [0u32; 2];
        for time in times.iter_mut() {
            let raw = server_io.read_packet(&CancelContext::background()).await.expect("read protected packet");
            let (_, _, unix_time) =
                packet::decode_control_packet(Some(&*server_crypt), &raw).expect("decode protected packet");
            *time = unix_time;
        }
        assert_eq!(times, [1000, 1000], "protected packet timestamps must stay stable for the session");
    }

    #[tokio::test]
    async fn test_control_replay_rejects_zero_and_expired_gap() {
        let (io, _peer) = new_memory_packet_pair();
        let channel = ControlChannel::new(io, None, packet::SessionID(*b"client01"));

        let now_seconds = Arc::new(AtomicI64::new(100));
        channel.set_replay_clock(Arc::new({
            let now_seconds = Arc::clone(&now_seconds);
            move || control_test_datetime(now_seconds.load(Ordering::SeqCst))
        }));

        assert!(channel.check_replay_locked(0, 50).is_err(), "packet id zero accepted");
        channel.check_replay_locked(1, 50).expect("id 1 rejected");
        channel.check_replay_locked(3, 50).expect("id 3 rejected");

        now_seconds.store(100 + control::CONTROL_REPLAY_TIME_BACKTRACK.as_secs() as i64 + 1, Ordering::SeqCst);
        assert!(channel.check_replay_locked(2, 50).is_err(), "aged replay-window gap accepted");
    }

    #[tokio::test]
    async fn test_unset_remote_session_ignores_non_reset_packet() {
        let (client_io, server_io) = new_memory_packet_pair();
        let recording_io = Arc::new(InitialPacketRecordingIO::new(client_io));
        let channel = ControlChannel::new(
            Arc::<InitialPacketRecordingIO>::clone(&recording_io),
            None,
            packet::SessionID(*b"client01"),
        );

        let bogus = control_test_envelope(
            &ControlPacket {
                opcode: packet::P_ACK_V1,
                local_session: packet::SessionID(*b"attacker"),
                ..Default::default()
            },
            None,
        );
        let reset = control_test_envelope(
            &ControlPacket {
                opcode: packet::P_CONTROL_HARD_RESET_SERVER_V2,
                local_session: packet::SessionID(*b"server01"),
                message_id: 0,
                ..Default::default()
            },
            None,
        );

        let ctx = CancelContext::background();
        server_io.write_packet(&ctx, &bogus).await.expect("write non-reset packet");
        server_io.write_packet(&ctx, &reset).await.expect("write hard reset");

        let packet = channel.read(&ctx).await.expect("read hard reset");
        assert_eq!(packet.opcode, packet::P_CONTROL_HARD_RESET_SERVER_V2);
        assert_eq!(channel.remote_session_id(), packet::SessionID(*b"server01"));
        assert!(
            recording_io.marked.is_cancelled(),
            "accepted initial hard reset did not mark the transport established"
        );
    }

    #[tokio::test]
    async fn test_tcp_packet_io_waits_for_complete_frame() {
        for body_partial in [false, true] {
            let name = if body_partial { "body" } else { "prefix" };
            let (client_net, mut server_net) = ControlTestPipe::pair(64 * 1024);
            let packet_io = packetio::new_tcp_packet_io(Box::new(client_net));
            let payload = b"hello".to_vec();
            let (first, rest) = if body_partial {
                (vec![0u8, payload.len() as u8, payload[0], payload[1]], payload[2..].to_vec())
            } else {
                (vec![0u8], [vec![payload.len() as u8], payload.clone()].concat())
            };

            let mut read_task = tokio::spawn(async move { PacketIO::read_packet(&*packet_io).await });
            AsyncWriteExt::write_all(&mut server_net, &first).await.expect("write partial frame");

            tokio::select! {
                result = &mut read_task => panic!("partial frame returned for {name}: {result:?}"),
                () = tokio::time::sleep(Duration::from_millis(20)) => {}
            }

            AsyncWriteExt::write_all(&mut server_net, &rest).await.expect("write remaining frame");
            let (packet, err) = tokio::time::timeout(Duration::from_secs(1), &mut read_task)
                .await
                .expect("complete frame was not returned")
                .expect("join");
            if let Some(err) = err {
                panic!("read failed for {name}: {err}");
            }
            assert_eq!(packet.expect("packet"), payload, "completed frame mismatch");
        }
    }

    #[tokio::test]
    async fn test_packet_mux_write_gate_observes_context() {
        let physical = Arc::new(BlockedPhysicalPacketIO::new());
        let physical_io: Arc<dyn PacketIO> = Arc::<BlockedPhysicalPacketIO>::clone(&physical);
        let mux = Arc::new(PacketMux::new(physical_io));

        let first = tokio::spawn({
            let mux = Arc::clone(&mux);
            async move { mux.write_data_packet(&CancelContext::background(), b"blocked").await }
        });
        physical.write_entered.cancelled().await;

        let ctx = control_test_ctx(Duration::from_millis(20));
        let err = mux.write_data_packet(&ctx, b"queued").await.expect_err("queued write must time out");
        assert!(is_context_deadline_exceeded(&err), "queued write returned {err}");

        physical.release();
        let err = first.await.expect("join").expect_err("blocked write unexpectedly succeeded");
        assert!(
            is_context_deadline_exceeded(&err) || is_err_net_closed(&err) || control_test_is_timeout_error(&err),
            "blocked write returned {err}"
        );
        mux.close().expect("close mux");
    }

    #[tokio::test]
    async fn test_control_rejects_ack_for_different_session() {
        let (client_io, server_io) = new_memory_packet_pair();
        let client = ControlChannel::new(client_io, None, packet::SessionID(*b"client01"));
        client.set_remote_session_id(packet::SessionID(*b"server01"));

        let ctx = control_test_ctx(Duration::from_millis(50));
        client.send(&ctx, packet::P_CONTROL_V1, b"pending").await.expect("send pending message");
        server_io.read_packet(&ctx).await.expect("drain outbound packet");

        let ack = control_test_envelope(
            &ControlPacket {
                opcode: packet::P_ACK_V1,
                local_session: packet::SessionID(*b"server01"),
                ack_ids: vec![0],
                ack_remote_session: packet::SessionID(*b"other001"),
                ..Default::default()
            },
            None,
        );
        server_io.write_packet(&ctx, &ack).await.expect("write wrong-session ACK");

        let err = client.read(&ctx).await.expect_err("wrong-session ACK was accepted");
        assert!(is_context_deadline_exceeded(&err), "wrong-session ACK returned {err}");
        assert_eq!(client.pending_messages(), 1, "wrong-session ACK cleared the pending reliable message");
    }

    #[tokio::test]
    async fn test_read_deadline_race_does_not_drop_packet() {
        let raw = control_test_envelope(
            &ControlPacket {
                opcode: packet::P_CONTROL_V1,
                local_session: packet::SessionID(*b"server01"),
                message_id: 0,
                payload: b"kept".to_vec(),
                ..Default::default()
            },
            None,
        );
        let packet_io = Arc::new(DeadlineRacePacketIO::new(raw));
        let channel = Arc::new(ControlChannel::new(
            Arc::<DeadlineRacePacketIO>::clone(&packet_io),
            None,
            packet::SessionID(*b"client01"),
        ));
        channel.set_remote_session_id(packet::SessionID(*b"server01"));

        let reader = tokio::spawn({
            let channel = Arc::clone(&channel);
            async move { channel.read(&CancelContext::background()).await }
        });
        packet_io.started.cancelled().await;
        channel.set_read_deadline(None).expect("clear read deadline");
        packet_io.release.cancel();

        let packet = tokio::time::timeout(Duration::from_secs(1), reader)
            .await
            .expect("packet was dropped when the deadline changed")
            .expect("join")
            .expect("read packet");
        assert_eq!(packet.payload, b"kept", "deadline race returned the wrong payload");
    }

    #[tokio::test]
    async fn test_control_conn_write_deadline_interrupts_blocked_write() {
        let packet_io = Arc::new(BlockingWritePacketIO::new());
        let channel = Arc::new(ControlChannel::new(
            Arc::<BlockingWritePacketIO>::clone(&packet_io),
            None,
            packet::SessionID(*b"client01"),
        ));
        let conn = ControlConn::new(Arc::clone(&channel));

        let writer = {
            let conn = conn.clone();
            tokio::spawn(async move {
                let payload = b"TLS record".to_vec();
                conn.write(&payload).await
            })
        };
        packet_io.entered.cancelled().await;
        conn.set_write_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(20)))
            .expect("set write deadline");

        let err = tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .expect("SetWriteDeadline did not interrupt the blocked write")
            .expect("join")
            .expect_err("blocked write must fail");
        let err = anyhow::Error::new(err);
        assert!(is_context_deadline_exceeded(&err), "blocked write returned {err}");
    }

    #[tokio::test]
    async fn test_control_conn_close_interrupts_blocked_write() {
        let packet_io = Arc::new(BlockingWritePacketIO::new());
        let channel = Arc::new(ControlChannel::new(
            Arc::<BlockingWritePacketIO>::clone(&packet_io),
            None,
            packet::SessionID(*b"client01"),
        ));
        let conn = ControlConn::new(Arc::clone(&channel));

        let writer = {
            let conn = conn.clone();
            tokio::spawn(async move {
                let payload = b"TLS record".to_vec();
                conn.write(&payload).await
            })
        };
        packet_io.entered.cancelled().await;
        conn.close().expect("close control conn");

        let err = tokio::time::timeout(Duration::from_secs(1), writer)
            .await
            .expect("Close did not interrupt the blocked write")
            .expect("join")
            .expect_err("blocked write must fail");
        let err = anyhow::Error::new(err);
        assert!(is_err_net_closed(&err), "blocked write returned {err}");
    }

    #[tokio::test]
    async fn test_tcp_control_conn_deadline_interrupts_socket_read() {
        let physical = Arc::new(BlockedPhysicalPacketIO::new());
        let physical_io: Arc<dyn PacketIO> = Arc::<BlockedPhysicalPacketIO>::clone(&physical);
        let mux = Arc::new(PacketMux::new(physical_io));
        tokio::spawn({
            let mux = Arc::clone(&mux);
            async move { mux.run().await }
        });
        let mux_io: Arc<dyn control::ControlIO> = Arc::<PacketMux>::clone(&mux);
        let conn = ControlConn::new(Arc::new(ControlChannel::new(mux_io, None, packet::SessionID(*b"client01"))));

        let reader = {
            let conn = conn.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1];
                conn.read(&mut buf).await
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        conn.set_read_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(20)))
            .expect("set read deadline");

        let err = tokio::time::timeout(Duration::from_secs(1), reader)
            .await
            .expect("the blocked read ignored the updated deadline")
            .expect("join")
            .expect_err("blocked read must fail");
        let err = anyhow::Error::new(err);
        assert!(
            is_context_deadline_exceeded(&err) || control_test_is_timeout_error(&err),
            "blocked TCP read returned {err}"
        );
        mux.close().expect("close mux");
    }

    #[tokio::test]
    async fn test_protected_control_packet_id_exhaustion() {
        let (client_io, server_io) = new_memory_packet_pair();
        let crypt: Arc<dyn ControlCryptor> =
            Arc::new(tlscrypt::new_tls_crypt(&test_static_key(), true).expect("tls crypt"));
        let channel = ControlChannel::new(client_io, Some(crypt), packet::SessionID(*b"client01"));
        channel.state.lock().send_packet_id = u32::MAX;

        let ctx = control_test_ctx(Duration::from_millis(30));
        channel
            .send(&ctx, packet::P_CONTROL_V1, b"must not send")
            .await
            .expect_err("protected control packet ID rollover succeeded");
        let err =
            server_io.read_packet(&ctx).await.expect_err("a packet was emitted after control packet ID exhaustion");
        assert!(is_context_deadline_exceeded(&err), "expected deadline, got {err}");
    }

    #[tokio::test]
    async fn test_control_write_deadline_extension_ignores_old_timer() {
        let packet_io = Arc::new(BlockingWritePacketIO::new());
        let channel = Arc::new(ControlChannel::new(
            Arc::<BlockingWritePacketIO>::clone(&packet_io),
            None,
            packet::SessionID(*b"client01"),
        ));
        let conn = ControlConn::new(Arc::clone(&channel));

        let mut writer = {
            let conn = conn.clone();
            tokio::spawn(async move {
                let payload = b"blocked".to_vec();
                conn.write(&payload).await
            })
        };
        packet_io.entered.cancelled().await;
        conn.set_write_deadline(Some(tokio::time::Instant::now() + Duration::from_secs(3600)))
            .expect("set write deadline");

        let (old_write_generation, old_deadline_generation, old_cancel) = {
            let state = channel.state.lock();
            (
                state.write_generation,
                state.write_deadline_generation,
                state.write_cancel.clone().expect("in-flight write cancel"),
            )
        };

        conn.set_write_deadline(Some(tokio::time::Instant::now() + Duration::from_secs(7200)))
            .expect("extend write deadline");
        channel.cancel_write_generation(old_write_generation, old_deadline_generation, &old_cancel);
        tokio::select! {
            result = &mut writer => panic!("superseded deadline canceled the write: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(30)) => {}
        }

        conn.close().expect("close control conn");
        let err = writer.await.expect("join").expect_err("blocked write must fail");
        let err = anyhow::Error::new(err);
        assert!(is_err_net_closed(&err), "cleanup close returned {err}");
    }

    #[tokio::test]
    async fn test_control_write_keeps_cancellation_cause_after_deadline_change() {
        let packet_io = Arc::new(HeldCanceledWritePacketIO::new());
        let channel = Arc::new(ControlChannel::new(
            Arc::<HeldCanceledWritePacketIO>::clone(&packet_io),
            None,
            packet::SessionID(*b"client01"),
        ));

        let writer = {
            let channel = Arc::clone(&channel);
            tokio::spawn(
                async move { channel.send(&CancelContext::background(), packet::P_CONTROL_V1, b"blocked").await },
            )
        };
        packet_io.entered.cancelled().await;
        let cancel = channel.state.lock().write_cancel.clone().expect("in-flight write cancel");
        cancel.cancel(Some(Cause::DeadlineExceeded));
        packet_io.canceled.cancelled().await;

        channel
            .set_write_deadline(Some(tokio::time::Instant::now() + Duration::from_secs(3600)))
            .expect("extend write deadline");
        packet_io.release.cancel();

        let err = writer.await.expect("join").expect_err("blocked write must fail");
        assert!(
            is_context_deadline_exceeded(&err),
            "write lost its cancellation cause after the deadline change: {err}"
        );
    }

    #[tokio::test]
    async fn test_tcp_control_conn_interrupts_socket_write() {
        for close_conn in [false, true] {
            let name = if close_conn { "close" } else { "deadline" };
            let physical = Arc::new(BlockedPhysicalPacketIO::new());
            let physical_io: Arc<dyn PacketIO> = Arc::<BlockedPhysicalPacketIO>::clone(&physical);
            let mux = Arc::new(PacketMux::new(physical_io));
            tokio::spawn({
                let mux = Arc::clone(&mux);
                async move { mux.run().await }
            });
            let mux_io: Arc<dyn control::ControlIO> = Arc::<PacketMux>::clone(&mux);
            let conn = ControlConn::new(Arc::new(ControlChannel::new(mux_io, None, packet::SessionID(*b"client01"))));

            let writer = {
                let conn = conn.clone();
                tokio::spawn(async move {
                    let payload = b"blocked socket write".to_vec();
                    conn.write(&payload).await
                })
            };
            physical.write_entered.cancelled().await;
            if close_conn {
                conn.close().expect("close control conn");
            } else {
                conn.set_write_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(20)))
                    .expect("set write deadline");
            }

            let err = tokio::time::timeout(Duration::from_secs(1), writer)
                .await
                .expect("the socket write was not interrupted")
                .expect("join")
                .expect_err("blocked socket write must fail");
            let err = anyhow::Error::new(err);
            if close_conn {
                assert!(is_err_net_closed(&err), "{name}: closed socket write returned {err}");
            } else {
                assert!(
                    is_context_deadline_exceeded(&err) || control_test_is_timeout_error(&err),
                    "{name}: timed-out socket write returned {err}"
                );
            }
            mux.close().expect("close mux");
        }
    }

    #[tokio::test]
    async fn test_control_conn_close_after_ack_prevents_payload_write() {
        let packet_io = Arc::new(AckCloseRacePacketIO::new());
        let channel = Arc::new(ControlChannel::new(
            Arc::<AckCloseRacePacketIO>::clone(&packet_io),
            None,
            packet::SessionID(*b"client01"),
        ));
        channel.set_remote_session_id(packet::SessionID(*b"server01"));
        channel.queue_ack(7);
        let conn = ControlConn::new(Arc::clone(&channel));

        let writer = {
            let conn = conn.clone();
            tokio::spawn(async move {
                let payload = b"must not send after close".to_vec();
                conn.write(&payload).await
            })
        };
        packet_io.entered.cancelled().await;
        conn.close().expect("close control conn");
        packet_io.release.cancel();

        let err = writer.await.expect("join").expect_err("write after close must fail");
        let err = anyhow::Error::new(err);
        assert!(is_err_net_closed(&err), "write after close returned {err}");
        assert_eq!(packet_io.writes(), 1, "the TLS payload was written after Close");
    }

    #[tokio::test]
    async fn test_control_conn_deadline_interrupts_blocked_read() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let conn = ControlConn::new(Arc::new(ControlChannel::new(client_io, None, packet::SessionID(*b"client01"))));

        let reader = {
            let conn = conn.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1];
                conn.read(&mut buf).await
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        conn.set_read_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(20)))
            .expect("set read deadline");

        let err = tokio::time::timeout(Duration::from_secs(1), reader)
            .await
            .expect("SetReadDeadline did not interrupt the blocked read")
            .expect("join")
            .expect_err("blocked read must fail");
        let err = anyhow::Error::new(err);
        assert!(is_context_deadline_exceeded(&err), "blocked read returned {err}");
    }

    #[tokio::test]
    async fn test_control_conn_close_interrupts_blocked_read() {
        let (client_io, _server_io) = new_memory_packet_pair();
        let conn = ControlConn::new(Arc::new(ControlChannel::new(client_io, None, packet::SessionID(*b"client01"))));

        let reader = {
            let conn = conn.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1];
                conn.read(&mut buf).await
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        conn.close().expect("close control conn");

        let err = tokio::time::timeout(Duration::from_secs(1), reader)
            .await
            .expect("Close did not interrupt the blocked read")
            .expect("join")
            .expect_err("blocked read must fail");
        let err = anyhow::Error::new(err);
        assert!(is_err_net_closed(&err), "blocked read returned {err}");
    }

    #[tokio::test]
    async fn test_control_conn_close_reset_does_not_leave_read_deadline() {
        let (client_io, server_io) = new_memory_packet_pair();
        let channel = ControlChannel::new(client_io, None, packet::SessionID(*b"client01"));
        channel.set_remote_session_id(packet::SessionID(*b"server01"));
        let conn = ControlConn::new(Arc::new(channel));
        conn.close().expect("close control conn");
        conn.reset();

        let mut reader = {
            let conn = conn.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 32];
                match conn.read(&mut buf).await {
                    Ok(n) => Ok(String::from_utf8_lossy(&buf[..n]).into_owned()),
                    Err(err) => Err(err),
                }
            })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut reader).await.is_err(),
            "read after Reset returned before a packet arrived"
        );

        let raw = control_test_envelope(
            &ControlPacket {
                opcode: packet::P_CONTROL_V1,
                local_session: packet::SessionID(*b"server01"),
                message_id: 0,
                payload: b"after reset".to_vec(),
                ..Default::default()
            },
            None,
        );
        server_io.write_packet(&CancelContext::background(), &raw).await.expect("write packet after reset");

        let result = tokio::time::timeout(Duration::from_secs(1), &mut reader)
            .await
            .expect("read after Reset did not receive the packet")
            .expect("join");
        match result {
            Ok(payload) => assert_eq!(payload, "after reset", "read after Reset returned the wrong payload"),
            Err(err) => panic!("read after Reset failed: {err}"),
        }
    }

    #[tokio::test]
    async fn test_tcp_packet_io_framing() {
        let (client_net, server_net) = ControlTestPipe::pair(64 * 1024);
        let client_io = packetio::new_tcp_packet_io(Box::new(client_net));
        let server_io = packetio::new_tcp_packet_io(Box::new(server_net));
        let payload = vec![1u8, 2, 3, 4];

        let writer = tokio::spawn({
            let payload = payload.clone();
            async move { PacketIO::write_packet(&*client_io, &payload).await }
        });

        let (got, err) = PacketIO::read_packet(&*server_io).await;
        if let Some(err) = err {
            panic!("read failed: {err}");
        }
        assert_eq!(got.expect("packet"), payload, "unexpected payload");
        writer.await.expect("join").expect("client write");
    }

    // ---- data-channel tests ----
    #[tokio::test]
    async fn test_data_channel_aesgcm_v2_round_trip() {
        let client_keys = keymethod::KeyMaterial {
            send_cipher_key: vec![0x11; 16],
            send_hmac_key: vec![0x22; keymethod::MAX_HMAC_KEY_LENGTH],
            recv_cipher_key: vec![0x33; 16],
            recv_hmac_key: vec![0x44; keymethod::MAX_HMAC_KEY_LENGTH],
        };
        let server_keys = keymethod::KeyMaterial {
            send_cipher_key: client_keys.recv_cipher_key.clone(),
            send_hmac_key: client_keys.recv_hmac_key.clone(),
            recv_cipher_key: client_keys.send_cipher_key.clone(),
            recv_hmac_key: client_keys.send_hmac_key.clone(),
        };
        let client = DataChannel::new(&client_keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 0)
            .expect("create client data channel");
        let server = DataChannel::new(&server_keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 0)
            .expect("create server data channel");

        let ip_packet = vec![0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1];
        let mut encrypted = client.encrypt(&ip_packet).expect("encrypt packet");
        let (opcode, _) = parse_opcode_key_id(encrypted[0]);
        assert_eq!(opcode, packet::P_DATA_V2, "unexpected data opcode: {opcode}");
        let packet_id = u32::from_be_bytes([encrypted[4], encrypted[5], encrypted[6], encrypted[7]]);
        assert_eq!(packet_id, 1, "unexpected first data packet id: {packet_id}");

        let plain = server.decrypt(&encrypted).expect("decrypt packet");
        assert_eq!(plain, ip_packet, "unexpected decrypted packet: {plain:x?}");

        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xff;
        assert!(server.decrypt(&encrypted).is_err(), "expected authentication failure");

        encrypted = client.encrypt(&ip_packet).expect("encrypt packet");
        encrypted[7] ^= 0xff;
        assert!(server.decrypt(&encrypted).is_err(), "expected authentication failure after packet id tamper");
    }

    #[tokio::test]
    async fn test_data_channel_accepts_out_of_order_packets_within_replay_window() {
        let client_keys = keymethod::KeyMaterial {
            send_cipher_key: vec![0x11; 16],
            send_hmac_key: vec![0x22; keymethod::MAX_HMAC_KEY_LENGTH],
            recv_cipher_key: vec![0x33; 16],
            recv_hmac_key: vec![0x44; keymethod::MAX_HMAC_KEY_LENGTH],
        };
        let server_keys = keymethod::KeyMaterial {
            send_cipher_key: client_keys.recv_cipher_key.clone(),
            send_hmac_key: client_keys.recv_hmac_key.clone(),
            recv_cipher_key: client_keys.send_cipher_key.clone(),
            recv_hmac_key: client_keys.send_hmac_key.clone(),
        };
        let client = DataChannel::new(&client_keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 0)
            .expect("create client data channel");
        let server = DataChannel::new(&server_keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 7, 0)
            .expect("create server data channel");

        let packets: Vec<Vec<u8>> = vec![
            vec![0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1],
            vec![0x45, 0, 0, 20, 1, 2, 3, 5, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1],
            vec![0x45, 0, 0, 20, 1, 2, 3, 6, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1],
        ];
        let mut encrypted: Vec<Vec<u8>> = Vec::with_capacity(packets.len());
        for packet in &packets {
            encrypted.push(client.encrypt(packet).expect("encrypt packet"));
        }

        for index in [0usize, 2, 1] {
            let plain = server.decrypt(&encrypted[index]).unwrap_or_else(|err| {
                panic!("decrypt packet {}: {err}", index + 1);
            });
            assert_eq!(plain, packets[index], "unexpected packet {} plaintext: {:x?}", index + 1, plain);
        }
        assert!(server.decrypt(&encrypted[1]).is_err(), "expected duplicate packet to be rejected");
    }

    #[tokio::test]
    async fn test_parse_push_reply() {
        let reply = push::parse_push_reply(
        "PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 8.8.8.8,ifconfig 10.8.0.2 255.255.255.0,peer-id 3,block-ipv6\0",
    )
    .expect("parse push reply");
        let prefix_count = reply.prefixes.len();
        assert_eq!(prefix_count, 1, "unexpected prefixes: {:?}", reply.prefixes);
        assert_eq!(reply.prefixes[0].to_string(), "10.8.0.2/24", "unexpected prefixes: {:?}", reply.prefixes);
        assert!(reply.peer_id == 3 && reply.redirect && reply.block_ipv6, "unexpected push flags: {reply:?}");
        let dns_count = reply.dns.len();
        assert_eq!(dns_count, 1, "unexpected DNS: {:?}", reply.dns);
        assert_eq!(reply.dns[0].to_string(), "8.8.8.8", "unexpected DNS: {:?}", reply.dns);
    }

    #[tokio::test]
    async fn test_parse_push_reply_point_to_point_ifconfig() {
        let reply = push::parse_push_reply(
        "PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.211.254.254,ifconfig 10.211.1.37 10.211.254.254,peer-id 16777215\0",
    )
    .expect("parse push reply");
        let prefix_count = reply.prefixes.len();
        assert_eq!(prefix_count, 1, "unexpected prefixes: {:?}", reply.prefixes);
        assert_eq!(reply.prefixes[0].to_string(), "10.211.1.37/32", "unexpected prefixes: {:?}", reply.prefixes);
        let dns_count = reply.dns.len();
        assert_eq!(dns_count, 1, "unexpected DNS: {:?}", reply.dns);
        assert_eq!(reply.dns[0].to_string(), "10.211.254.254", "unexpected DNS: {:?}", reply.dns);
    }

    #[tokio::test]
    async fn test_data_channel_chacha20_poly1305_v2_round_trip() {
        let client_keys = keymethod::KeyMaterial {
            send_cipher_key: vec![0x11; 32],
            send_hmac_key: vec![0x22; keymethod::MAX_HMAC_KEY_LENGTH],
            recv_cipher_key: vec![0x33; 32],
            recv_hmac_key: vec![0x44; keymethod::MAX_HMAC_KEY_LENGTH],
        };
        let server_keys = keymethod::KeyMaterial {
            send_cipher_key: client_keys.recv_cipher_key.clone(),
            send_hmac_key: client_keys.recv_hmac_key.clone(),
            recv_cipher_key: client_keys.send_cipher_key.clone(),
            recv_hmac_key: client_keys.send_hmac_key.clone(),
        };
        let client = DataChannel::new(&client_keys, config::CIPHER_CHACHA20_POLY1305, config::AUTH_SHA256, 7, 0)
            .expect("create client data channel");
        let server = DataChannel::new(&server_keys, config::CIPHER_CHACHA20_POLY1305, config::AUTH_SHA256, 7, 0)
            .expect("create server data channel");

        let ip_packet = vec![0x45, 0, 0, 20, 1, 2, 3, 4, 64, 17, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1];
        let mut encrypted = client.encrypt(&ip_packet).expect("encrypt packet");
        let plain = server.decrypt(&encrypted).expect("decrypt packet");
        assert_eq!(plain, ip_packet, "unexpected decrypted packet: {plain:x?}");

        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xff;
        assert!(server.decrypt(&encrypted).is_err(), "expected authentication failure");
    }

    #[tokio::test]
    async fn test_data_channel_aescbc_sha1_v2_round_trip() {
        let client_keys = keymethod::KeyMaterial {
            send_cipher_key: vec![0x11; 16],
            send_hmac_key: vec![0x22; keymethod::MAX_HMAC_KEY_LENGTH],
            recv_cipher_key: vec![0x33; 16],
            recv_hmac_key: vec![0x44; keymethod::MAX_HMAC_KEY_LENGTH],
        };
        let server_keys = keymethod::KeyMaterial {
            send_cipher_key: client_keys.recv_cipher_key.clone(),
            send_hmac_key: client_keys.recv_hmac_key.clone(),
            recv_cipher_key: client_keys.send_cipher_key.clone(),
            recv_hmac_key: client_keys.send_hmac_key.clone(),
        };
        let client = DataChannel::new(&client_keys, config::CIPHER_AES_128_CBC, config::AUTH_SHA1, 7, 0)
            .expect("create client data channel");
        let server = DataChannel::new(&server_keys, config::CIPHER_AES_128_CBC, config::AUTH_SHA1, 7, 0)
            .expect("create server data channel");

        let ip_packet = vec![0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1];
        let mut encrypted = client.encrypt(&ip_packet).expect("encrypt packet");
        let (opcode, _) = parse_opcode_key_id(encrypted[0]);
        assert_eq!(opcode, packet::P_DATA_V2, "unexpected data opcode: {opcode}");

        let header_size = 4usize;
        let sha1_size = 20usize;
        let aes_block_size = 16usize;
        let cbc_iv_size = data::DATA_CHANNEL_CBC_IV_SIZE;
        let encrypted_len = encrypted.len();
        assert!(
            encrypted_len >= header_size + sha1_size + cbc_iv_size + aes_block_size,
            "encrypted CBC packet too short: {encrypted_len}"
        );
        assert_eq!(
            (encrypted_len - (header_size + sha1_size + cbc_iv_size)) % aes_block_size,
            0,
            "encrypted CBC payload is not block aligned"
        );

        let plain = server.decrypt(&encrypted).expect("decrypt packet");
        assert_eq!(plain, ip_packet, "unexpected decrypted packet: {plain:x?}");

        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xff;
        assert!(server.decrypt(&encrypted).is_err(), "expected HMAC authentication failure");

        encrypted = client.encrypt(&ip_packet).expect("encrypt packet");
        encrypted[header_size + sha1_size] ^= 0xff;
        assert!(server.decrypt(&encrypted).is_err(), "expected HMAC authentication failure after IV tamper");
    }

    #[tokio::test]
    async fn test_data_channel_stops_at_packet_id_rekey_threshold() {
        for cipher in [config::CIPHER_AES_128_GCM, config::CIPHER_AES_128_CBC, config::CIPHER_CHACHA20_POLY1305] {
            let keys = keymethod::KeyMaterial {
                send_cipher_key: vec![0x11; 32],
                send_hmac_key: vec![0x22; keymethod::MAX_HMAC_KEY_LENGTH],
                recv_cipher_key: vec![0x33; 32],
                recv_hmac_key: vec![0x44; keymethod::MAX_HMAC_KEY_LENGTH],
            };
            let channel = DataChannel::new(&keys, cipher, config::AUTH_SHA256, 7, 0)
                .unwrap_or_else(|err| panic!("{cipher}: create data channel: {err}"));
            channel.set_send_packet_id(data::DATA_PACKET_ID_REKEY_THRESHOLD - 1);
            channel.encrypt(&[0x45, 0, 0, 20]).unwrap_or_else(|err| {
                panic!("{cipher}: final packet before rekey threshold: {err}");
            });
            let err = match channel.encrypt(&[0x45, 0, 0, 20]) {
                Ok(_) => panic!("{cipher}: packet at rekey threshold returned no error"),
                Err(err) => err,
            };
            assert!(
                err.chain().any(|cause| cause.is::<data::ErrDataPacketIDExhausted>()),
                "packet at rekey threshold returned {err}"
            );
            assert_eq!(
                channel.send_packet_id(),
                data::DATA_PACKET_ID_REKEY_THRESHOLD,
                "packet ID advanced after threshold: got {:#x}",
                channel.send_packet_id()
            );
        }
    }

    #[tokio::test]
    async fn test_negotiate_cipher_no_push_uses_configured() {
        let cfg = ClientConfig { cipher: config::CIPHER_AES_128_GCM.to_owned(), ..Default::default() };
        let got = cfg.negotiate_cipher(&[], "").expect("negotiate cipher");
        assert_eq!(got, config::CIPHER_AES_128_GCM, "expected {}, got {}", config::CIPHER_AES_128_GCM, got);
    }

    #[tokio::test]
    async fn test_negotiate_cipher_intersection() {
        let cfg = ClientConfig {
            cipher: config::CIPHER_AES_128_GCM.to_owned(),
            data_ciphers: vec![config::CIPHER_AES_256_GCM.to_owned(), config::CIPHER_AES_128_GCM.to_owned()],
            ..Default::default()
        };
        let got = cfg
            .negotiate_cipher(&[config::CIPHER_AES_128_GCM.to_owned(), config::CIPHER_AES_256_GCM.to_owned()], "")
            .expect("negotiate cipher");
        assert_eq!(
            got,
            config::CIPHER_AES_128_GCM,
            "expected {} (first server cipher in client list), got {}",
            config::CIPHER_AES_128_GCM,
            got
        );
    }

    #[tokio::test]
    async fn test_negotiate_cipher_no_intersection_uses_fallback() {
        let cfg = ClientConfig {
            cipher: config::CIPHER_AES_128_GCM.to_owned(),
            data_ciphers: vec![config::CIPHER_AES_256_GCM.to_owned()],
            fallback_cipher: config::CIPHER_AES_128_CBC.to_owned(),
            ..Default::default()
        };
        let got = cfg.negotiate_cipher(&[config::CIPHER_CHACHA20_POLY1305.to_owned()], "").expect("negotiate cipher");
        assert_eq!(got, config::CIPHER_AES_128_CBC, "expected fallback {}, got {}", config::CIPHER_AES_128_CBC, got);
    }

    #[tokio::test]
    async fn test_negotiate_cipher_no_intersection_no_fallback_error() {
        let cfg = ClientConfig {
            cipher: config::CIPHER_AES_128_GCM.to_owned(),
            data_ciphers: vec![config::CIPHER_AES_256_GCM.to_owned()],
            ..Default::default()
        };
        assert!(
            cfg.negotiate_cipher(&[config::CIPHER_CHACHA20_POLY1305.to_owned()], "").is_err(),
            "expected error when no common cipher and no fallback"
        );
    }

    #[tokio::test]
    async fn test_negotiate_cipher_legacy_single_cipher_push() {
        let cfg = ClientConfig { cipher: config::CIPHER_AES_128_GCM.to_owned(), ..Default::default() };
        let got = cfg.negotiate_cipher(&[], config::CIPHER_AES_128_GCM).expect("negotiate cipher");
        assert_eq!(got, config::CIPHER_AES_128_GCM, "expected {}, got {}", config::CIPHER_AES_128_GCM, got);
    }

    #[tokio::test]
    async fn test_negotiate_cipher_server_pushes_different_cipher_accepted() {
        let cfg = ClientConfig { cipher: config::CIPHER_AES_128_GCM.to_owned(), ..Default::default() };
        let got = cfg.negotiate_cipher(&[], config::CIPHER_AES_256_GCM).expect("negotiate cipher");
        assert_eq!(
            got,
            config::CIPHER_AES_256_GCM,
            "expected server-pushed {}, got {}",
            config::CIPHER_AES_256_GCM,
            got
        );
    }

    #[tokio::test]
    async fn test_parse_push_reply_data_ciphers() {
        let msg = "PUSH_REPLY,data-ciphers AES-256-GCM:AES-128-GCM,ifconfig 10.8.0.2 255.255.255.0";
        let reply = push::parse_push_reply(msg).expect("parse push reply");
        let count = reply.data_ciphers.len();
        assert_eq!(count, 2, "expected 2 data ciphers, got {count}");
        assert_eq!(
            reply.data_ciphers[0], "AES-256-GCM",
            "expected first cipher AES-256-GCM, got {}",
            reply.data_ciphers[0]
        );
        assert_eq!(
            reply.data_ciphers[1], "AES-128-GCM",
            "expected second cipher AES-128-GCM, got {}",
            reply.data_ciphers[1]
        );
    }

    #[tokio::test]
    async fn test_parse_push_reply_legacy_cipher() {
        let msg = "PUSH_REPLY,cipher AES-256-GCM,ifconfig 10.8.0.2 255.255.255.0";
        let reply = push::parse_push_reply(msg).expect("parse push reply");
        assert_eq!(reply.cipher, "AES-256-GCM", "expected cipher AES-256-GCM, got {}", reply.cipher);
    }

    #[tokio::test]
    async fn test_parse_push_reply_ncp_ciphers() {
        let msg = "PUSH_REPLY,ncp-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305,ifconfig 10.8.0.2 255.255.255.0";
        let reply = push::parse_push_reply(msg).expect("parse push reply");
        let count = reply.data_ciphers.len();
        assert_eq!(count, 3, "expected 3 data ciphers, got {count}");
        assert_eq!(
            reply.data_ciphers[2], "CHACHA20-POLY1305",
            "expected third cipher CHACHA20-POLY1305, got {}",
            reply.data_ciphers[2]
        );
    }

    #[tokio::test]
    async fn test_install_script_peer_info_with_data_ciphers() {
        let info = install_script_peer_info(
            config::CIPHER_AES_128_GCM,
            &[
                config::CIPHER_AES_256_GCM.to_owned(),
                config::CIPHER_AES_128_GCM.to_owned(),
                config::CIPHER_CHACHA20_POLY1305.to_owned(),
            ],
            "",
            &HashMap::new(),
        );
        let want = "IV_VER=murmur-openvpn\nIV_PROTO=22\nIV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n";
        assert_eq!(info, want, "unexpected peer-info:\n got {info:?}\nwant {want:?}");
    }

    // ---- packet I/O tests ----

    type ErrorFactory = Box<dyn Fn() -> anyhow::Error + Send + Sync>;

    fn background_context() -> CancelContext {
        CancelContext::background()
    }

    fn deadline_context(timeout: Duration) -> CancelContext {
        CancelContext::background().with_deadline(tokio::time::Instant::now() + timeout)
    }

    fn canceled_context() -> CancelContext {
        let ctx = CancelContext::background();
        ctx.cancel(None);
        ctx
    }

    async fn wait_context_done(ctx: &CancelContext) {
        ctx.done().await;
    }

    fn error_has_message(err: &anyhow::Error, message: &str) -> bool {
        err.chain().any(|cause| cause.to_string() == message)
    }

    fn io_error_kind(err: &anyhow::Error) -> Option<io::ErrorKind> {
        err.chain().find_map(|cause| cause.downcast_ref::<io::Error>().map(io::Error::kind))
    }

    fn is_eof_error(err: &anyhow::Error) -> bool {
        let eof = io::Error::from(io::ErrorKind::UnexpectedEof).to_string();
        err.chain().any(|cause| match cause.downcast_ref::<io::Error>() {
            Some(err) => err.kind() == io::ErrorKind::UnexpectedEof,
            None => cause.to_string() == eof,
        })
    }

    fn is_context_canceled(err: &anyhow::Error) -> bool {
        err.chain().any(|cause| {
            matches!(cause.downcast_ref::<ContextError>(), Some(ContextError::Canceled))
                || cause.to_string() == "context canceled"
        })
    }

    fn enetunreach_error() -> anyhow::Error {
        io::Error::from_raw_os_error(libc::ENETUNREACH).into()
    }

    fn is_enetunreach_error(err: &anyhow::Error) -> bool {
        let message = io::Error::from_raw_os_error(libc::ENETUNREACH).to_string();
        err.chain().any(|cause| match cause.downcast_ref::<io::Error>() {
            Some(err) => err.raw_os_error() == Some(libc::ENETUNREACH),
            None => cause.to_string() == message,
        })
    }

    fn new_packet_dropped_error(cause: &str) -> anyhow::Error {
        anyhow::Error::new(packetio::PacketDroppedError { cause: anyhow::anyhow!("{cause}") })
    }

    async fn wait_mux_closed(mux: &PacketMux, message: &str) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while !mux.is_closed() {
            assert!(Instant::now() < deadline, "{message}");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// The physical layer has no deadline methods at all now (`Stream` carries none): the
    /// invariant this used to enforce with a panicking `set_deadline` override is enforced by the
    /// compiler instead, since `PhysicalConn` cannot call a method `Stream` does not declare.
    struct DeadlinePanicConn {
        inner: Box<dyn Stream>,
    }

    impl AsyncRead for DeadlinePanicConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut *self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DeadlinePanicConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut *self.get_mut().inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl Stream for DeadlinePanicConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.inner.peer_addr()
        }
    }

    #[tokio::test]
    async fn test_physical_packet_io_does_not_call_deadline_methods_tcp_logical_read_deadline() {
        let (client_net, _server_net) = ControlTestPipe::pair(4096);
        let io: Arc<dyn PacketIO> =
            Arc::from(packetio::new_tcp_packet_io(Box::new(DeadlinePanicConn { inner: Box::new(client_net) })));
        let mux = PacketMux::new(io);
        tokio::spawn({
            let mux = mux.clone();
            async move { mux.run().await }
        });

        let mut client_id = packet::SessionID::default();
        client_id.0.copy_from_slice(b"client01");
        let conn = ControlConn::new(Arc::new(ControlChannel::new(Arc::new(mux.clone()), None, client_id)));
        conn.set_read_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(20)))
            .expect("set read deadline");
        let mut buf = [0u8; 1];
        let err: anyhow::Error = conn.read(&mut buf).await.expect_err("logical read with expired deadline").into();
        assert!(is_context_deadline_exceeded(&err), "logical deadline returned {err}");
        assert!(!mux.is_closed(), "logical read deadline closed physical transport: {}", mux.terminal_error());
        mux.close().expect("close mux");
    }

    #[tokio::test]
    async fn test_physical_packet_io_does_not_call_deadline_methods_tcp_write() {
        let (client_net, mut server_net) = ControlTestPipe::pair(4096);
        let packet_io = packetio::new_tcp_packet_io(Box::new(DeadlinePanicConn { inner: Box::new(client_net) }));
        let payload = b"framed";
        let read_done = tokio::spawn(async move {
            let mut frame = vec![0u8; payload.len() + 2];
            AsyncReadExt::read_exact(&mut server_net, &mut frame).await?;
            assert_eq!(&frame[2..], &payload[..], "unexpected TCP frame payload");
            Ok::<(), anyhow::Error>(())
        });
        packet_io.write_packet(payload).await.expect("write packet");
        read_done.await.expect("join frame reader").expect("read frame");
    }

    #[tokio::test]
    async fn test_physical_packet_io_does_not_call_deadline_methods_udp_write() {
        let (client_net, mut server_net) = ControlTestPipe::pair(4096);
        let packet_io = packetio::new_datagram_packet_io(Box::new(DeadlinePanicConn { inner: Box::new(client_net) }));
        let payload = b"datagram";
        let read_done = tokio::spawn(async move {
            let mut buf = vec![0u8; payload.len()];
            AsyncReadExt::read_exact(&mut server_net, &mut buf).await?;
            assert_eq!(buf.as_slice(), &payload[..], "unexpected UDP payload");
            Ok::<(), anyhow::Error>(())
        });
        packet_io.write_packet(payload).await.expect("write packet");
        read_done.await.expect("join datagram reader").expect("read datagram");
    }

    struct WriteResultConn {
        n: usize,
        err: Option<io::Error>,
    }

    impl AsyncRead for WriteResultConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(err_net_closed()))
        }
    }

    impl AsyncWrite for WriteResultConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            match this.err.take() {
                Some(err) => Poll::Ready(Err(err)),
                None => Poll::Ready(Ok(this.n)),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for WriteResultConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(dummy_addr("local"))
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(dummy_addr("remote"))
        }
    }

    struct ReadResultConn {
        packet: Vec<u8>,
        err: Option<io::Error>,
        delivered: bool,
    }

    impl AsyncRead for ReadResultConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if !this.delivered {
                this.delivered = true;
                let n = buf.remaining().min(this.packet.len());
                buf.put_slice(&this.packet[..n]);
                return Poll::Ready(Ok(()));
            }
            match this.err.take() {
                Some(err) => Poll::Ready(Err(err)),
                None => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for ReadResultConn {
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

    impl Stream for ReadResultConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(dummy_addr("local"))
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(dummy_addr("remote"))
        }
    }

    struct SyscallWriteResultConn {
        inner: WriteResultConn,
    }

    impl AsyncRead for SyscallWriteResultConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for SyscallWriteResultConn {
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

    impl Stream for SyscallWriteResultConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.inner.peer_addr()
        }
    }

    fn datagram_packet_io(conn: Box<dyn Stream>, recoverable_udp: bool) -> Box<dyn PacketIO> {
        if recoverable_udp {
            packetio::new_datagram_packet_io_recoverable(conn)
        } else {
            packetio::new_datagram_packet_io(conn)
        }
    }

    struct DatagramWriteCase {
        name: &'static str,
        conn: Box<dyn Stream>,
        recoverable_udp: bool,
        want_kind: Option<io::ErrorKind>,
        want_message: Option<&'static str>,
        want_dropped: bool,
    }

    #[tokio::test]
    async fn test_datagram_packet_io_write_classification() {
        let packet = b"packet";
        let drop_cause = "single datagram rejected";
        // the "partial datagram" and "complete write" rows need a `Write` returning `n > 0` together
        // with an error in one call, which `AsyncWrite` cannot express.
        let cases = [
            DatagramWriteCase {
                name: "syscall UDP zero-byte nonterminal error is one packet loss",
                conn: Box::new(SyscallWriteResultConn {
                    inner: WriteResultConn { n: 0, err: Some(io::Error::other(drop_cause)) },
                }),
                recoverable_udp: true,
                want_kind: None,
                want_message: Some(drop_cause),
                want_dropped: true,
            },
            DatagramWriteCase {
                name: "non-syscall transport error is fatal",
                conn: Box::new(WriteResultConn { n: 0, err: Some(io::Error::other(drop_cause)) }),
                recoverable_udp: false,
                want_kind: None,
                want_message: Some(drop_cause),
                want_dropped: false,
            },
            DatagramWriteCase {
                name: "timeout is fatal",
                conn: Box::new(SyscallWriteResultConn {
                    inner: WriteResultConn { n: 0, err: Some(io::Error::from(io::ErrorKind::TimedOut)) },
                }),
                recoverable_udp: true,
                want_kind: Some(io::ErrorKind::TimedOut),
                want_message: None,
                want_dropped: false,
            },
            DatagramWriteCase {
                name: "closed is fatal",
                conn: Box::new(SyscallWriteResultConn { inner: WriteResultConn { n: 0, err: Some(err_net_closed()) } }),
                recoverable_udp: true,
                want_kind: Some(io::ErrorKind::NotConnected),
                want_message: None,
                want_dropped: false,
            },
        ];

        for case in cases {
            let err =
                datagram_packet_io(case.conn, case.recoverable_udp).write_packet(packet).await.expect_err(case.name);
            if let Some(kind) = case.want_kind {
                assert_eq!(io_error_kind(&err), Some(kind), "{}: WritePacket error = {err}, want {kind:?}", case.name);
            }
            if let Some(message) = case.want_message {
                assert!(error_has_message(&err, message), "{}: WritePacket error = {err}, want {message}", case.name);
            }
            assert_eq!(is_packet_dropped(&err), case.want_dropped, "{}: packet-dropped classification", case.name);
        }
    }

    #[tokio::test]
    async fn test_packet_mux_delivers_datagram_returned_with_read_error() {
        let packet = vec![packet::opcode_key_id(packet::P_DATA_V2, 0), 1, 2, 3];
        let io: Arc<dyn PacketIO> = Arc::from(packetio::new_datagram_packet_io(Box::new(ReadResultConn {
            packet: packet.clone(),
            err: Some(io::Error::from(io::ErrorKind::UnexpectedEof)),
            delivered: false,
        })));
        let mux = PacketMux::new(io);
        tokio::spawn({
            let mux = mux.clone();
            async move { mux.run().await }
        });

        wait_mux_closed(&mux, "physical reader did not report EOF").await;

        let ctx = background_context();
        let got = mux.read_data_packet(&ctx).await.expect("packet returned with EOF");
        assert_eq!(got, packet, "packet returned with EOF = {got:02x?}, want {packet:02x?}");
        let err = mux.read_data_packet(&ctx).await.expect_err("terminal read error");
        assert!(is_eof_error(&err), "terminal read error = {err}, want eof");
    }

    struct PhysicalWriteCall {
        packet: Vec<u8>,
        result: oneshot::Sender<Option<anyhow::Error>>,
    }

    struct ControlledPacketIO {
        writes: mpsc::Sender<PhysicalWriteCall>,
        closed: CancellationToken,
    }

    fn new_controlled_packet_io() -> (Arc<ControlledPacketIO>, mpsc::Receiver<PhysicalWriteCall>) {
        let (writes, writes_rx) = mpsc::channel(16);
        (Arc::new(ControlledPacketIO { writes, closed: CancellationToken::new() }), writes_rx)
    }

    #[async_trait::async_trait]
    impl PacketIO for ControlledPacketIO {
        async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>) {
            self.closed.cancelled().await;
            (None, Some(err_net_closed().into()))
        }

        async fn write_packet(&self, packet: &[u8]) -> anyhow::Result<()> {
            let (result, result_rx) = oneshot::channel();
            let call = PhysicalWriteCall { packet: packet.to_vec(), result };
            tokio::select! {
                sent = self.writes.send(call) => {
                    if sent.is_err() {
                        return Err(err_net_closed().into());
                    }
                }
                () = self.closed.cancelled() => return Err(err_net_closed().into()),
            }
            tokio::select! {
                result = result_rx => match result {
                    Ok(Some(err)) => Err(err),
                    Ok(None) => Ok(()),
                    Err(_) => Err(err_net_closed().into()),
                },
                () = self.closed.cancelled() => Err(err_net_closed().into()),
            }
        }

        async fn close(&self) -> anyhow::Result<()> {
            self.closed.cancel();
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("local"))
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("remote"))
        }
    }

    async fn wait_write_gate_queues(mux: &PacketMux, control: usize, data: usize) {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let (got_control, got_data) = mux.gate_queue_lengths();
            if got_control == control && got_data == data {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "write queues = control {got_control} data {got_data}, want control {control} data {data}"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test]
    async fn test_packet_mux_active_data_cancellation_keeps_transport() {
        let (packet_io, mut writes) = new_controlled_packet_io();
        let mux = PacketMux::new(packet_io);
        let ctx = deadline_context(Duration::from_millis(20));
        let write = tokio::spawn({
            let mux = mux.clone();
            let ctx = ctx.clone();
            async move { mux.write_data_packet(&ctx, b"data").await }
        });
        let call = writes.recv().await.expect("physical data write");
        wait_context_done(&ctx).await;
        assert!(!write.is_finished(), "active data write returned before physical completion");
        assert!(!mux.is_closed(), "data cancellation closed transport: {}", mux.terminal_error());
        call.result.send(None).expect("complete physical write");
        write.await.expect("join data write").expect("data write");
        mux.close().expect("close mux");
    }

    #[tokio::test]
    async fn test_packet_mux_cancellation_before_physical_commit_keeps_transport() {
        let packet_io = Arc::new(StaticErrorPacketIO { err: None, closed: CancellationToken::new() });
        let mux = PacketMux::new(packet_io);
        let ctx = canceled_context();
        let err = mux.write_packet(&ctx, b"control").await.expect_err("pre-physical cancellation");
        assert!(is_context_canceled(&err), "pre-physical cancellation returned {err}");
        assert!(!mux.is_closed(), "pre-physical cancellation closed transport: {}", mux.terminal_error());
        mux.close().expect("close mux");
    }

    #[tokio::test]
    async fn test_packet_mux_active_control_cancellation_closes_transport() {
        let (packet_io, mut writes) = new_controlled_packet_io();
        let mux = PacketMux::new(packet_io);
        let ctx = deadline_context(Duration::from_millis(20));
        let write = tokio::spawn({
            let mux = mux.clone();
            let ctx = ctx.clone();
            async move { mux.write_packet(&ctx, b"control").await }
        });
        let _call = writes.recv().await.expect("physical control write");
        wait_mux_closed(&mux, "active control timeout did not close transport").await;
        assert!(is_context_deadline_exceeded(&mux.terminal_error()), "terminal error = {}", mux.terminal_error());
        let err = tokio::time::timeout(Duration::from_secs(1), write)
            .await
            .expect("physical control write was not interrupted by Close")
            .expect("join control write")
            .expect_err("active control write");
        assert!(is_context_deadline_exceeded(&err), "active control write returned {err}");
    }

    #[tokio::test]
    async fn test_reliable_retransmit_deadline_aborts_active_physical_write() {
        let (packet_io, mut writes) = new_controlled_packet_io();
        let mux = PacketMux::new(packet_io);
        let mut client_id = packet::SessionID::default();
        client_id.0.copy_from_slice(b"client01");
        let channel = Arc::new(ControlChannel::new(Arc::new(mux.clone()), None, client_id));

        let ctx = background_context();
        let initial = tokio::spawn({
            let channel = Arc::clone(&channel);
            let ctx = ctx.clone();
            async move { channel.send(&ctx, packet::P_CONTROL_V1, b"pending").await.map(|_| ()) }
        });
        let call = writes.recv().await.expect("initial physical write");
        call.result.send(None).expect("complete initial write");
        initial.await.expect("join initial send").expect("initial send");

        let retransmit = tokio::spawn({
            let channel = Arc::clone(&channel);
            let ctx = ctx.clone();
            async move { channel.retransmit_pending(&ctx).await }
        });
        let _call = writes.recv().await.expect("retransmit physical write");
        channel
            .set_write_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(20)))
            .expect("set write deadline");
        wait_mux_closed(&mux, "logical write deadline did not terminate active retransmit").await;
        assert!(is_context_deadline_exceeded(&mux.terminal_error()), "terminal error = {}", mux.terminal_error());
        let err = tokio::time::timeout(Duration::from_secs(1), retransmit)
            .await
            .expect("active retransmit was not interrupted")
            .expect("join retransmit")
            .expect_err("active retransmit");
        assert!(is_context_deadline_exceeded(&err), "active retransmit returned {err}");
    }

    #[tokio::test]
    async fn test_packet_mux_queued_cancellation_keeps_transport() {
        let (packet_io, mut writes) = new_controlled_packet_io();
        let mux = PacketMux::new(packet_io);
        let ctx = background_context();
        let first = tokio::spawn({
            let mux = mux.clone();
            let ctx = ctx.clone();
            async move { mux.write_data_packet(&ctx, b"active").await }
        });
        let call = writes.recv().await.expect("active physical write");

        let queued_ctx = deadline_context(Duration::from_millis(20));
        let err = mux.write_packet(&queued_ctx, b"queued").await.expect_err("queued control write");
        assert!(is_context_deadline_exceeded(&err), "queued control write returned {err}");
        let (control_queue, _data_queue) = mux.gate_queue_lengths();
        assert_eq!(control_queue, 0, "canceled write gate retained control queue: {control_queue}");
        assert!(!mux.is_closed(), "queued cancellation closed transport: {}", mux.terminal_error());
        call.result.send(None).expect("complete active write");
        first.await.expect("join first write").expect("active data write");
        assert!(
            matches!(writes.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "canceled queued packet reached physical writer"
        );
        mux.close().expect("close mux");
    }

    #[tokio::test]
    async fn test_packet_mux_prioritizes_queued_control() {
        let (packet_io, mut writes) = new_controlled_packet_io();
        let mux = PacketMux::new(packet_io);
        let (results, mut result_rx) = mpsc::channel(3);
        let ctx = background_context();

        tokio::spawn({
            let mux = mux.clone();
            let ctx = ctx.clone();
            let results = results.clone();
            async move {
                let _ = results.send(mux.write_data_packet(&ctx, b"data-1").await).await;
            }
        });
        let first = writes.recv().await.expect("first physical write");
        tokio::spawn({
            let mux = mux.clone();
            let ctx = ctx.clone();
            let results = results.clone();
            async move {
                let _ = results.send(mux.write_data_packet(&ctx, b"data-2").await).await;
            }
        });
        tokio::spawn({
            let mux = mux.clone();
            let ctx = ctx.clone();
            let results = results.clone();
            async move {
                let _ = results.send(mux.write_packet(&ctx, b"control").await).await;
            }
        });
        wait_write_gate_queues(&mux, 1, 1).await;

        first.result.send(None).expect("complete first write");
        let second = writes.recv().await.expect("second physical write");
        assert_eq!(second.packet, b"control".to_vec(), "second physical write = {:?}, want control", second.packet);
        second.result.send(None).expect("complete control write");
        let third = writes.recv().await.expect("third physical write");
        assert_eq!(third.packet, b"data-2".to_vec(), "third physical write = {:?}, want data-2", third.packet);
        third.result.send(None).expect("complete third write");
        for _ in 0..3 {
            result_rx.recv().await.expect("write result").expect("write");
        }

        let (control_queue, data_queue) = mux.gate_queue_lengths();
        assert_eq!(
            (control_queue, data_queue),
            (0, 0),
            "drained write gate retained waiter queues: control={control_queue} data={data_queue}"
        );
        mux.close().expect("close mux");
    }

    #[tokio::test]
    async fn test_packet_mux_preserves_first_physical_error_for_queued_writers() {
        let (packet_io, mut writes) = new_controlled_packet_io();
        let mux = PacketMux::new(packet_io);
        let ctx = background_context();
        let fatal_message = "physical write failed";

        let first = tokio::spawn({
            let mux = mux.clone();
            let ctx = ctx.clone();
            async move { mux.write_data_packet(&ctx, b"first").await }
        });
        let call = writes.recv().await.expect("first physical write");
        let second = tokio::spawn({
            let mux = mux.clone();
            let ctx = ctx.clone();
            async move { mux.write_data_packet(&ctx, b"second").await }
        });
        wait_write_gate_queues(&mux, 0, 1).await;

        call.result.send(Some(anyhow::anyhow!("{fatal_message}"))).expect("fail physical write");
        let err = first.await.expect("join first write").expect_err("first write");
        assert!(error_has_message(&err, fatal_message), "first write error = {err}");
        let err = second.await.expect("join second write").expect_err("queued write");
        assert!(error_has_message(&err, fatal_message), "queued write error = {err}");
        assert!(error_has_message(&mux.terminal_error(), fatal_message), "terminal error = {}", mux.terminal_error());
    }

    struct QueuedReadPacketIO {
        packets: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
        closed: CancellationToken,
    }

    struct FiniteReadPacketIO {
        packets: Mutex<Vec<Vec<u8>>>,
        err: Option<ErrorFactory>,
    }

    #[async_trait::async_trait]
    impl PacketIO for FiniteReadPacketIO {
        async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>) {
            let mut packets = self.packets.lock();
            if packets.is_empty() {
                return (None, self.err.as_ref().map(|err| err()));
            }
            (Some(packets.remove(0)), None)
        }

        async fn write_packet(&self, _packet: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }

        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("local"))
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("remote"))
        }
    }

    #[tokio::test]
    async fn test_packet_mux_drains_complete_packets_before_physical_read_error() {
        let control_packet = vec![packet::opcode_key_id(packet::P_ACK_V1, 0)];
        let data_packet = vec![packet::opcode_key_id(packet::P_DATA_V2, 0), 1, 2, 3];
        let packet_io = Arc::new(FiniteReadPacketIO {
            packets: Mutex::new(vec![control_packet.clone(), data_packet.clone()]),
            err: Some(Box::new(|| io::Error::from(io::ErrorKind::UnexpectedEof).into())),
        });
        let mux = PacketMux::new(packet_io);
        tokio::spawn({
            let mux = mux.clone();
            async move { mux.run().await }
        });

        wait_mux_closed(&mux, "physical reader did not report EOF").await;

        let ctx = background_context();
        let got_control = mux.read_packet(&ctx).await.expect("queued control packet");
        assert_eq!(
            got_control, control_packet,
            "queued control packet = {got_control:02x?}, want {control_packet:02x?}"
        );
        let got_data = mux.read_data_packet(&ctx).await.expect("queued data packet");
        assert_eq!(got_data, data_packet, "queued data packet = {got_data:02x?}, want {data_packet:02x?}");
        let err = mux.read_packet(&ctx).await.expect_err("control terminal error");
        assert!(is_eof_error(&err), "control terminal error = {err}, want eof");
        let err = mux.read_data_packet(&ctx).await.expect_err("data terminal error");
        assert!(is_eof_error(&err), "data terminal error = {err}, want eof");
    }

    #[tokio::test]
    async fn test_packet_mux_explicit_close_does_not_drain_queued_packets() {
        let packet_io = Arc::new(FiniteReadPacketIO { packets: Mutex::new(Vec::new()), err: None });
        let mux = PacketMux::new(packet_io);
        mux.push_control_packet(vec![packet::opcode_key_id(packet::P_ACK_V1, 0)]).await.expect("push control packet");
        mux.close().expect("close mux");
        let err = mux.read_packet(&background_context()).await.expect_err("read after close");
        assert!(
            is_err_net_closed(&err) || error_has_message(&err, "use of closed network connection"),
            "read after close = {err}, want net.ErrClosed"
        );
    }

    #[async_trait::async_trait]
    impl PacketIO for QueuedReadPacketIO {
        async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>) {
            let mut packets = self.packets.lock().await;
            tokio::select! {
                packet = packets.recv() => match packet {
                    Some(packet) => (Some(packet), None),
                    None => (None, Some(err_net_closed().into())),
                },
                () = self.closed.cancelled() => (None, Some(err_net_closed().into())),
            }
        }

        async fn write_packet(&self, _packet: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }

        async fn close(&self) -> anyhow::Result<()> {
            self.closed.cancel();
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("local"))
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("remote"))
        }
    }

    #[tokio::test]
    async fn test_packet_mux_receive_queue_applies_backpressure_without_dropping() {
        let (packets, packets_rx) = mpsc::channel(300);
        for i in 0..257u32 {
            packets
                .send(vec![packet::opcode_key_id(packet::P_DATA_V2, 0), (i >> 8) as u8, i as u8])
                .await
                .expect("queue data packet");
        }
        packets.send(vec![packet::opcode_key_id(packet::P_ACK_V1, 0)]).await.expect("queue control packet");
        let _packets = packets;

        let packet_io = Arc::new(QueuedReadPacketIO {
            packets: tokio::sync::Mutex::new(packets_rx),
            closed: CancellationToken::new(),
        });
        let mux = PacketMux::new(packet_io);
        tokio::spawn({
            let mux = mux.clone();
            async move { mux.run().await }
        });

        let deadline = Instant::now() + Duration::from_secs(1);
        while mux.data_queue_len() != mux.data_queue_capacity() {
            assert!(
                Instant::now() < deadline,
                "data queue length = {}, want {}",
                mux.data_queue_len(),
                mux.data_queue_capacity()
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        let ctx = deadline_context(Duration::from_secs(1));
        let first = mux.read_data_packet(&ctx).await.expect("read first data packet");
        assert_eq!(u16::from_be_bytes([first[1], first[2]]), 0, "first data sequence = {:02x?}", &first[1..]);
        mux.read_packet(&ctx).await.expect("control packet did not progress after backpressure released");
        for want in 1..257u16 {
            let packet = mux.read_data_packet(&ctx).await.unwrap_or_else(|err| panic!("read data {want}: {err}"));
            assert_eq!(u16::from_be_bytes([packet[1], packet[2]]), want, "data sequence = {want}");
        }
        mux.close().expect("close mux");
    }

    struct StaticErrorPacketIO {
        err: Option<ErrorFactory>,
        closed: CancellationToken,
    }

    #[async_trait::async_trait]
    impl PacketIO for StaticErrorPacketIO {
        async fn read_packet(&self) -> (Option<Vec<u8>>, Option<anyhow::Error>) {
            self.closed.cancelled().await;
            (None, Some(err_net_closed().into()))
        }

        async fn write_packet(&self, _packet: &[u8]) -> anyhow::Result<()> {
            match &self.err {
                Some(err) => Err(err()),
                None => Ok(()),
            }
        }

        async fn close(&self) -> anyhow::Result<()> {
            self.closed.cancel();
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("local"))
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            Some(dummy_addr("remote"))
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("classified initial network unreachable")]
    struct ClassifiedInitialUnreachableError {
        source: packetio::PacketDroppedError,
    }

    #[tokio::test]
    async fn test_packet_mux_treats_recoverable_udp_write_as_packet_loss() {
        let packet_io = Arc::new(StaticErrorPacketIO {
            err: Some(Box::new(|| new_packet_dropped_error("datagram rejected"))),
            closed: CancellationToken::new(),
        });
        let mux = PacketMux::new(packet_io);
        let ctx = background_context();
        let err = mux.write_data_packet(&ctx, b"data").await.expect_err("recoverable data-packet loss");
        assert!(is_packet_dropped(&err), "recoverable data-packet loss = {err}, want packet-dropped classification");
        let err = mux.write_packet(&ctx, b"control").await.expect_err("recoverable control-packet loss");
        assert!(is_packet_dropped(&err), "recoverable control-packet loss = {err}, want packet-dropped classification");
        assert!(!mux.is_closed(), "recoverable UDP packet loss closed transport: {}", mux.terminal_error());
        mux.close().expect("close mux");
    }

    #[tokio::test]
    async fn test_packet_mux_initial_network_unreachable_terminates_transport() {
        let packet_io = Arc::new(StaticErrorPacketIO {
            err: Some(Box::new(|| anyhow::Error::new(packetio::PacketDroppedError { cause: enetunreach_error() }))),
            closed: CancellationToken::new(),
        });
        let mux = PacketMux::new(packet_io);
        let err = mux
            .write_packet(&background_context(), b"initial control")
            .await
            .expect_err("initial network-unreachable write");
        assert!(is_enetunreach_error(&err), "initial network-unreachable write returned {err}");
        assert!(!is_packet_dropped(&err), "terminal initial error retained packet-dropped classification: {err}");
        assert!(mux.is_closed(), "initial network-unreachable write kept transport alive");
        assert!(is_enetunreach_error(&mux.terminal_error()), "terminal error = {}", mux.terminal_error());
    }

    #[tokio::test]
    async fn test_control_initial_network_unreachable_fails_send_reset() {
        let packet_io = Arc::new(StaticErrorPacketIO {
            err: Some(Box::new(|| {
                anyhow::Error::new(ClassifiedInitialUnreachableError {
                    source: packetio::PacketDroppedError { cause: enetunreach_error() },
                })
            })),
            closed: CancellationToken::new(),
        });
        let mux = PacketMux::new(packet_io);
        let channel = Arc::new(ControlChannel::new(Arc::new(mux.clone()), None, packet::SessionID::default()));
        let err = channel.send_reset(&background_context()).await.expect_err("send reset");
        assert!(is_enetunreach_error(&err), "SendReset error = {err}, want terminal network-unreachable");
        assert!(!is_packet_dropped(&err), "SendReset error retained packet-dropped classification: {err}");
        assert!(
            is_enetunreach_error(&mux.terminal_error()),
            "terminal error = {}, want network-unreachable",
            mux.terminal_error()
        );
    }

    #[tokio::test]
    async fn test_packet_mux_established_network_unreachable_is_packet_loss() {
        let packet_io = Arc::new(StaticErrorPacketIO {
            err: Some(Box::new(|| anyhow::Error::new(packetio::PacketDroppedError { cause: enetunreach_error() }))),
            closed: CancellationToken::new(),
        });
        let mux = PacketMux::new(packet_io);
        mux.mark_initial_packet_received();
        let err = mux
            .write_packet(&background_context(), b"established control")
            .await
            .expect_err("established network-unreachable write");
        assert!(is_packet_dropped(&err), "established network-unreachable write returned {err}");
        assert!(!mux.is_closed(), "established network-unreachable write closed transport: {}", mux.terminal_error());
        mux.close().expect("close mux");
    }

    #[tokio::test]
    async fn test_control_channel_treats_recoverable_udp_write_as_packet_loss() {
        let packet_io = Arc::new(StaticErrorPacketIO {
            err: Some(Box::new(|| new_packet_dropped_error("datagram rejected"))),
            closed: CancellationToken::new(),
        });
        let mux = PacketMux::new(packet_io);
        let channel = Arc::new(ControlChannel::new(Arc::new(mux.clone()), None, packet::SessionID::default()));
        channel
            .send(&background_context(), packet::P_CONTROL_V1, b"reliable")
            .await
            .expect("recoverable control-packet loss escaped reliable layer");
        assert_eq!(channel.pending_messages(), 1, "pending reliable messages = {}, want 1", channel.pending_messages());
        assert!(!mux.is_closed(), "recoverable control-packet loss closed transport: {}", mux.terminal_error());
        mux.close().expect("close mux");
    }

    #[tokio::test]
    async fn test_dropped_data_packet_does_not_mark_send_activity() {
        let packet_io = Arc::new(StaticErrorPacketIO {
            err: Some(Box::new(|| new_packet_dropped_error("datagram rejected"))),
            closed: CancellationToken::new(),
        });
        let client = new_test_client(&Arc::new(ClientConfig::default()), packet_io).expect("create client");
        let keys = keymethod::KeyMaterial {
            send_cipher_key: vec![0x11; 16],
            send_hmac_key: vec![0x22; 64],
            recv_cipher_key: vec![0x33; 16],
            recv_hmac_key: vec![0x44; 64],
        };
        let data_channel = Arc::new(
            DataChannel::new(&keys, config::CIPHER_AES_128_GCM, config::AUTH_SHA256, 0, 0)
                .expect("create data channel"),
        );
        client.install_data_channel(data_channel);
        client.last_send_nano.store(1, Ordering::SeqCst);
        client.write_ip_packet(&CancellationToken::new(), &[0x45, 0, 0, 20]).await.expect("write ip packet");
        assert_eq!(client.last_send_nano.load(Ordering::SeqCst), 1, "dropped data packet updated send status");
        client.close().await.expect("close client");
    }

    // ---- misc tests (a) ----

    pub(crate) const TEST_CERT: &str = r"-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUQbG/Z7JQGg+Jb42bBYK6q8I4g5swCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHbWlob21vMB4XDTI2MDUwMTAwMDAwMFoXDTM2MDQyOTAwMDAw
MFowEjEQMA4GA1UEAwwHbWlob21vMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
hT8O8v9COiL0e7Gmab6r8jYxgB5xIvEtL10eF6QpJm+5ROK8f8yO8JHj2L2F6i1v
g7CNgMCoX9YnZ9wqOqNTMFEwHQYDVR0OBBYEFDuK1nBI7w+Kz8o9hD7UzpJkq1N2
MB8GA1UdIwQYMBaAFDuK1nBI7w+Kz8o9hD7UzpJkq1N2MA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwIDSAAwRQIhAJ4mquCRw+W1M7RCNzUVpV9qPzR9qYpK4SAi
6pEh8FeaAiBKv+YbWBjjiWk0Yxch3v7y8W7S7e3pVtHh8x9n9+6w1Q==
-----END CERTIFICATE-----";

    pub(crate) const TEST_KEY: &str = r"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIG1paG9tb19vcGVudnBuX3Rlc3Rfa2V5XzEyMzQ1Njc4oAoGCCqGSM49
AwEHoUQDQgAEhT8O8v9COiL0e7Gmab6r8jYxgB5xIvEtL10eF6QpJm+5ROK8f8yO
8JHj2L2F6i1vg7CNgMCoX9YnZ9wqOg==
-----END EC PRIVATE KEY-----";

    pub(crate) fn test_tls_crypt_block() -> String {
        format!("-----BEGIN OpenVPN Static key V1-----\n{}\n-----END OpenVPN Static key V1-----", "00".repeat(256))
    }

    pub(crate) fn yaml_style_config() -> ClientConfig {
        ClientConfig {
            remote_host: "vpn.example.com".to_owned(),
            remote_port: 1194,
            proto: "udp".to_owned(),
            dev: "tun".to_owned(),
            cipher: "AES-128-GCM".to_owned(),
            auth: "SHA256".to_owned(),
            ca: TEST_CERT.as_bytes().to_vec(),
            cert: TEST_CERT.as_bytes().to_vec(),
            key: TEST_KEY.as_bytes().to_vec(),
            tls_crypt: test_tls_crypt_block().into_bytes(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_client_config_yaml_style_install_script_subset() {
        let mut cfg = yaml_style_config();
        cfg.prepare().expect("prepare");
        assert_eq!(cfg.remote_address(), "vpn.example.com:1194", "unexpected remote address: {}", cfg.remote_address());
        assert_eq!(cfg.proto, PROTO_UDP, "unexpected proto: {}", cfg.proto);
        assert!(
            cfg.cipher == config::CIPHER_AES_128_GCM && cfg.auth == config::AUTH_SHA256,
            "unexpected crypto: {}/{}",
            cfg.cipher,
            cfg.auth
        );
        assert_eq!(cfg.tls_crypt_key.len(), 256, "unexpected tls-crypt key length: {}", cfg.tls_crypt_key.len());
    }

    #[tokio::test]
    async fn test_client_config_defaults() {
        let mut cfg = yaml_style_config();
        cfg.proto = String::new();
        cfg.dev = String::new();
        cfg.cipher = String::new();
        cfg.auth = String::new();

        cfg.prepare().expect("prepare");
        assert!(
            cfg.proto == PROTO_UDP
                && cfg.dev == "tun"
                && cfg.cipher == config::CIPHER_AES_128_GCM
                && cfg.auth == config::AUTH_SHA256,
            "unexpected defaults: proto={} dev={} cipher={} auth={}",
            cfg.proto,
            cfg.dev,
            cfg.cipher,
            cfg.auth
        );
    }

    #[tokio::test]
    async fn test_client_config_rejects_unsupported_proto() {
        let mut cfg = yaml_style_config();
        cfg.proto = "tcp-server".to_owned();
        let err = cfg.prepare().expect_err("expected unsupported proto error");
        assert!(err.to_string().contains("unsupported openvpn proto"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn test_client_config_rejects_negative_transition_window() {
        let mut cfg = yaml_style_config();
        cfg.transition_window = -murmur_common::time::SECOND;
        let err = cfg.prepare().expect_err("negative transition window accepted");
        assert!(err.to_string().contains("transition window"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn test_client_config_allows_missing_tls_crypt() {
        let mut cfg = yaml_style_config();
        cfg.tls_crypt = Vec::new();
        cfg.prepare().expect("prepare");
        assert!(cfg.tls_crypt_key.is_empty(), "unexpected tls-crypt key length: {}", cfg.tls_crypt_key.len());
    }

    #[tokio::test]
    async fn test_client_config_auth_user_pass_aes256() {
        let mut cfg = ClientConfig {
            remote_host: "vpn.example.com".to_owned(),
            remote_port: 31194,
            proto: "udp".to_owned(),
            dev: "tun".to_owned(),
            cipher: "AES-256-GCM".to_owned(),
            auth: "SHA256".to_owned(),
            ca: TEST_CERT.as_bytes().to_vec(),
            username: "user".to_owned(),
            password: "secret".to_owned(),
            tls_crypt: test_tls_crypt_block().into_bytes(),
            ..Default::default()
        };
        cfg.prepare().expect("prepare");
        assert_eq!(cfg.cipher, config::CIPHER_AES_256_GCM, "unexpected cipher: {}", cfg.cipher);
        assert_eq!(
            cfg.data_cipher_key_length(),
            32,
            "unexpected data key length helper: {}",
            cfg.data_cipher_key_length()
        );
    }

    #[tokio::test]
    async fn test_client_config_aes_cbc_sha1() {
        let mut cfg = ClientConfig {
            remote_host: "vpn.example.com".to_owned(),
            remote_port: 1194,
            proto: "udp".to_owned(),
            dev: "tun".to_owned(),
            cipher: "AES-CBC".to_owned(),
            auth: "sha-1".to_owned(),
            ca: TEST_CERT.as_bytes().to_vec(),
            username: "user".to_owned(),
            password: "secret".to_owned(),
            tls_crypt: test_tls_crypt_block().into_bytes(),
            ..Default::default()
        };
        cfg.prepare().expect("prepare");
        assert!(
            cfg.cipher == config::CIPHER_AES_128_CBC && cfg.auth == config::AUTH_SHA1,
            "unexpected crypto: {}/{}",
            cfg.cipher,
            cfg.auth
        );
        assert_eq!(
            cfg.data_cipher_key_length(),
            16,
            "unexpected data key length helper: {}",
            cfg.data_cipher_key_length()
        );
    }

    #[tokio::test]
    async fn test_client_config_requires_auth() {
        let mut cfg = yaml_style_config();
        cfg.cert = Vec::new();
        cfg.key = Vec::new();
        cfg.username = String::new();
        let err = cfg.prepare().expect_err("expected missing auth error");
        assert!(err.to_string().contains("cert+key or username"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn test_client_config_auth_user_pass_chacha20_poly1305() {
        let mut cfg = ClientConfig {
            remote_host: "vpn.example.com".to_owned(),
            remote_port: 31194,
            proto: "udp".to_owned(),
            dev: "tun".to_owned(),
            cipher: "chacha20-poly1305".to_owned(),
            auth: "SHA256".to_owned(),
            ca: TEST_CERT.as_bytes().to_vec(),
            username: "user".to_owned(),
            password: "secret".to_owned(),
            tls_crypt: test_tls_crypt_block().into_bytes(),
            ..Default::default()
        };
        cfg.prepare().expect("prepare");
        assert_eq!(cfg.cipher, config::CIPHER_CHACHA20_POLY1305, "unexpected cipher: {}", cfg.cipher);
        assert_eq!(
            cfg.data_cipher_key_length(),
            32,
            "unexpected data key length helper: {}",
            cfg.data_cipher_key_length()
        );
    }

    #[tokio::test]
    async fn test_client_config_tls_auth() {
        let mut cfg = ClientConfig {
            remote_host: "vpn.example.com".to_owned(),
            remote_port: 1194,
            proto: "udp".to_owned(),
            dev: "tun".to_owned(),
            cipher: "AES-128-GCM".to_owned(),
            auth: "SHA256".to_owned(),
            ca: TEST_CERT.as_bytes().to_vec(),
            username: "user".to_owned(),
            password: "secret".to_owned(),
            tls_auth: test_tls_crypt_block().into_bytes(),
            key_direction: "1".to_owned(),
            ..Default::default()
        };
        cfg.prepare().expect("prepare");
        assert_eq!(cfg.tls_auth_key.len(), 256, "unexpected tls-auth key length: {}", cfg.tls_auth_key.len());
    }

    #[tokio::test]
    async fn test_client_config_rejects_tls_auth_tls_crypt_together() {
        let mut cfg = ClientConfig {
            remote_host: "vpn.example.com".to_owned(),
            remote_port: 1194,
            proto: "udp".to_owned(),
            dev: "tun".to_owned(),
            cipher: "AES-128-GCM".to_owned(),
            auth: "SHA256".to_owned(),
            ca: TEST_CERT.as_bytes().to_vec(),
            username: "user".to_owned(),
            password: "secret".to_owned(),
            tls_auth: test_tls_crypt_block().into_bytes(),
            tls_crypt: test_tls_crypt_block().into_bytes(),
            key_direction: "1".to_owned(),
            ..Default::default()
        };
        let err = cfg.prepare().expect_err("expected mutual exclusion error");
        assert!(err.to_string().contains("mutually exclusive"), "unexpected error: {err}");
    }

    // ---- misc tests (b) ----
    fn test_static_key() -> Vec<u8> {
        let mut key = Vec::with_capacity(256);
        for i in 0..=255u8 {
            key.push(i);
        }
        key
    }

    fn hmac_tag<D>(key: &[u8], parts: &[&[u8]]) -> Vec<u8>
    where
        D: digest::block_api::EagerHash,
    {
        let mut mac = <hmac::Hmac<D> as hmac::KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
        for part in parts {
            <hmac::Hmac<D> as hmac::Mac>::update(&mut mac, part);
        }
        <hmac::Hmac<D> as hmac::Mac>::finalize(mac).into_bytes().to_vec()
    }

    #[tokio::test]
    async fn test_tls_auth_client_server_round_trip() -> anyhow::Result<()> {
        let client = tlsauth::new_tls_auth(&test_static_key(), "1", config::AUTH_SHA1)?;
        let server = tlsauth::new_tls_auth(&test_static_key(), "0", config::AUTH_SHA1)?;

        let header = vec![0x38, 1, 2, 3, 4, 5, 6, 7, 8];
        let plaintext = b"client hello over openvpn control channel".to_vec();
        let packet = client.wrap(&header, 7, 1_714_567_890, &plaintext)?;
        let want = tlscrypt::TLS_CRYPT_HEADER_SIZE + client.tag_size() + tlsauth::TLS_AUTH_PID_SIZE + plaintext.len();
        let got = packet.len();
        assert_eq!(got, want, "unexpected tls-auth packet length: got {got}, want {want}");

        let (got_header, packet_id, unix_time, got_plaintext) = server.unwrap(&packet)?;
        assert_eq!(got_header, header, "unexpected header: {}", hex::encode(&got_header));
        assert!(packet_id == 7 && unix_time == 1_714_567_890, "unexpected packet id/time: {packet_id}/{unix_time}");
        assert_eq!(got_plaintext, plaintext, "unexpected plaintext: {:?}", String::from_utf8_lossy(&got_plaintext));
        Ok(())
    }

    #[tokio::test]
    async fn test_tls_auth_rejects_tampered_packet() -> anyhow::Result<()> {
        let client = tlsauth::new_tls_auth(&test_static_key(), "1", config::AUTH_SHA1)?;
        let server = tlsauth::new_tls_auth(&test_static_key(), "0", config::AUTH_SHA1)?;

        let mut packet = client.wrap(&[0x38, 1, 2, 3, 4, 5, 6, 7, 8], 7, 1_714_567_890, b"hello")?;
        let last = packet.len() - 1;
        packet[last] ^= 0xff;

        assert!(server.unwrap(&packet).is_err(), "expected authentication failure");
        Ok(())
    }

    struct DigestCase {
        auth: &'static str,
        tag_size: usize,
        hmac: fn(&[u8], &[&[u8]]) -> Vec<u8>,
    }

    #[tokio::test]
    async fn test_tls_auth_digest_follows_auth() -> anyhow::Result<()> {
        let digests = [
            DigestCase {
                auth: config::AUTH_MD5,
                tag_size: <md5::Md5 as digest::Digest>::output_size(),
                hmac: hmac_tag::<md5::Md5>,
            },
            DigestCase {
                auth: config::AUTH_SHA1,
                tag_size: <sha1::Sha1 as digest::Digest>::output_size(),
                hmac: hmac_tag::<sha1::Sha1>,
            },
            DigestCase {
                auth: config::AUTH_SHA256,
                tag_size: <sha2::Sha256 as digest::Digest>::output_size(),
                hmac: hmac_tag::<sha2::Sha256>,
            },
            DigestCase {
                auth: config::AUTH_SHA384,
                tag_size: <sha2::Sha384 as digest::Digest>::output_size(),
                hmac: hmac_tag::<sha2::Sha384>,
            },
            DigestCase {
                auth: config::AUTH_SHA512,
                tag_size: <sha2::Sha512 as digest::Digest>::output_size(),
                hmac: hmac_tag::<sha2::Sha512>,
            },
        ];
        let static_key = test_static_key();
        let header = vec![0x38, 1, 2, 3, 4, 5, 6, 7, 8];
        let plaintext = b"client hello over openvpn control channel".to_vec();
        for case in digests {
            let client = tlsauth::new_tls_auth(&static_key, "1", case.auth)?;
            let server = tlsauth::new_tls_auth(&static_key, "0", case.auth)?;
            let size = case.tag_size;
            let got_size = client.tag_size();
            assert_eq!(got_size, size, "tag size {got_size}, want digest size {size}");

            let packet = client.wrap(&header, 7, 1_714_567_890, &plaintext)?;
            let want = tlscrypt::TLS_CRYPT_HEADER_SIZE + size + tlsauth::TLS_AUTH_PID_SIZE + plaintext.len();
            let got = packet.len();
            assert_eq!(got, want, "packet length {got}, want {want}");

            // The tag covers packet id|time, header and payload, keyed by the second slot's HMAC half.
            let key_offset = tlscrypt::KEY_SLOT_SIZE + tlsauth::TLS_AUTH_HMAC_KEY_OFFSET;
            let hmac_key = &static_key[key_offset..key_offset + size];
            let pid_start = tlscrypt::TLS_CRYPT_HEADER_SIZE + size;
            let pid_end = pid_start + tlsauth::TLS_AUTH_PID_SIZE;
            let expected =
                (case.hmac)(hmac_key, &[&packet[pid_start..pid_end], header.as_slice(), plaintext.as_slice()]);
            let tag = &packet[tlscrypt::TLS_CRYPT_HEADER_SIZE..tlscrypt::TLS_CRYPT_HEADER_SIZE + size];
            assert_eq!(
                tag,
                expected.as_slice(),
                "tag is not HMAC-{} over packet id, header and payload with the slot's HMAC key",
                case.auth
            );

            let (_got_header, _packet_id, _unix_time, got) = server.unwrap(&packet)?;
            assert_eq!(got, plaintext, "server unwrap: plaintext={:?}", String::from_utf8_lossy(&got));
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_tls_auth_digest_mismatch_is_rejected() -> anyhow::Result<()> {
        let client = tlsauth::new_tls_auth(&test_static_key(), "1", config::AUTH_SHA256)?;
        let server = tlsauth::new_tls_auth(&test_static_key(), "0", config::AUTH_SHA1)?;
        let packet = client.wrap(&[0x38, 1, 2, 3, 4, 5, 6, 7, 8], 7, 1_714_567_890, b"hello")?;
        assert!(server.unwrap(&packet).is_err(), "a SHA256 tag must not verify under a SHA1 peer");
        Ok(())
    }

    #[tokio::test]
    async fn test_tls_auth_default_and_unsupported_digest() -> anyhow::Result<()> {
        let client = tlsauth::new_tls_auth(&test_static_key(), "1", "")?;
        let want = <sha2::Sha256 as digest::Digest>::output_size();
        let got = client.tag_size();
        assert_eq!(got, want, "default tag size {got}, want {want}");
        assert!(
            tlsauth::new_tls_auth(&test_static_key(), "1", "SHA224").is_err(),
            "unsupported digest must be refused at construction"
        );
        Ok(())
    }

    fn test_tls_crypt_v2_client_pem() -> Vec<u8> {
        let mut key = Vec::with_capacity(256);
        for i in 0..=255u8 {
            key.push(i);
        }
        key.extend_from_slice(b"wrapped-client-key-fixture");

        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key.as_slice());
        let mut pem = String::from("-----BEGIN OpenVPN tls-crypt-v2 client key-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }
        pem.push_str("-----END OpenVPN tls-crypt-v2 client key-----\n");
        pem.into_bytes()
    }

    #[tokio::test]
    async fn test_client_with_tls_crypt_v2() -> anyhow::Result<()> {
        let mut client_config = ClientConfig {
            remote_host: "1.2.3.4".to_owned(),
            remote_port: 1194,
            ca: TEST_CERT.as_bytes().to_vec(),
            cipher: config::CIPHER_AES_128_GCM.to_owned(),
            auth: config::AUTH_SHA256.to_owned(),
            username: "user".to_owned(),
            password: "pass".to_owned(),
            tls_crypt_v2: test_tls_crypt_v2_client_pem(),
            ..Default::default()
        };
        client_config.prepare()?;
        let key_len = client_config.tls_crypt_v2_key.len();
        assert!(key_len == 256 && !client_config.tls_crypt_v2_wrapped_key.is_empty(), "v2 material not prepared");

        let (client_io, _server_io) = new_memory_packet_pair();
        let client = new_test_client(&Arc::new(client_config), control_io_packet_adapter(client_io))?;
        let is_v2 = client.control.crypt().is_some_and(|crypt| crypt.wrapped_client_key().is_some());
        assert!(is_v2, "wrong cryptor");
        let _ = client.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn test_tls_crypt_v2_mutually_exclusive_with_tls_crypt() -> anyhow::Result<()> {
        let mut client_config = ClientConfig {
            remote_host: "1.2.3.4".to_owned(),
            remote_port: 1194,
            ca: TEST_CERT.as_bytes().to_vec(),
            cipher: config::CIPHER_AES_128_GCM.to_owned(),
            auth: config::AUTH_SHA256.to_owned(),
            username: "user".to_owned(),
            tls_crypt: test_tls_crypt_block().into_bytes(),
            tls_crypt_v2: test_tls_crypt_v2_client_pem(),
            ..Default::default()
        };
        assert!(client_config.prepare().is_err(), "expected mutual exclusion error");
        Ok(())
    }

    struct RacedCloseControlIO;

    #[async_trait::async_trait]
    impl control::ControlIO for RacedCloseControlIO {
        async fn read_packet(&self, _ctx: &CancelContext) -> anyhow::Result<Vec<u8>> {
            Err(anyhow::Error::new(control::ErrClosed))
        }

        async fn write_packet(&self, _ctx: &CancelContext, _packet: &[u8]) -> anyhow::Result<()> {
            Err(anyhow::Error::new(control::ErrClosed))
        }

        async fn write_packet_allow_active_stop(&self, ctx: &CancelContext, packet: &[u8]) -> anyhow::Result<()> {
            RacedCloseControlIO::write_packet(self, ctx, packet).await
        }

        async fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            None
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    #[tokio::test]
    async fn test_control_conn_read_reports_err_net_closed_without_explicit_close() {
        let channel = Arc::new(ControlChannel::new(Arc::new(RacedCloseControlIO), None, packet::SessionID::default()));
        let conn = ControlConn::new(channel);
        let mut buf = [0u8; 16];
        let io_err = conn.read(&mut buf).await.expect_err("underlying ErrClosed must surface as an io error");
        let err: anyhow::Error = io_err.into();
        assert!(is_err_net_closed(&err), "ErrClosed boxed through ControlConn::read was not recognized: {err}");
    }
}

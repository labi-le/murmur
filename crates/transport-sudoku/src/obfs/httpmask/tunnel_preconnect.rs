use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::Stream;
use murmur_component::dialer::options::NetDialer;
use murmur_component_tls::utls::{client as tls_client, Config as TlsConfig, VERSION_TLS12};

pub(crate) const PRECONNECTED_CONN_TTL: Duration = Duration::from_secs(4);
pub(crate) const MAX_PRECONNECTED_CONNS: usize = 64;
pub(crate) const TUNNEL_TLS_HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);

/// A timeout-scoped child over a `tokio_util::sync::CancellationToken`: the returned child
/// token is cancelled when `parent` is cancelled or `timeout` elapses, whichever is first.
pub(crate) fn with_timeout(parent: &CancellationToken, timeout: Duration) -> CancellationToken {
    let child = parent.child_token();
    let sleeper = child.clone();
    tokio::spawn(async move {
        // cancel-safe: the spawned timer only ever cancels its own child token.
        tokio::select! {
            () = tokio::time::sleep(timeout) => sleeper.cancel(),
            () = sleeper.cancelled() => {}
        }
    });
    child
}

type DialFuture = Pin<Box<dyn Future<Output = anyhow::Result<Box<dyn Stream>>> + Send>>;

struct PreparedConn {
    conn: Box<dyn Stream>,
    expires_at: Instant,
    release: Option<OwnedSemaphorePermit>,
}

/// The preconnect limiter, using a counting [`Semaphore`] in place of the buffered-channel
/// semaphore; the observable behaviour (bounded concurrent preconnects, non-blocking `acquire`)
/// is identical.
struct PreconnectLimiter {
    semaphore: Arc<Semaphore>,
}

/// Whether a preconnect dial may proceed, and which permit it holds.
enum PreconnectSlot {
    /// A permit was reserved; it is released when the value is dropped.
    Reserved(OwnedSemaphorePermit),
    /// No limiter is configured, so the dial proceeds unpaced.
    Unlimited,
    /// The limiter rejected the dial.
    AtCapacity,
}

impl PreconnectLimiter {
    fn new(limit: usize) -> Option<Self> {
        if limit == 0 {
            return None;
        }
        Some(Self { semaphore: Arc::new(Semaphore::new(limit)) })
    }

    fn acquire(this: Option<&Arc<Self>>) -> PreconnectSlot {
        let Some(limiter) = this else {
            return PreconnectSlot::Unlimited;
        };
        match Arc::clone(&limiter.semaphore).try_acquire_owned() {
            Ok(permit) => PreconnectSlot::Reserved(permit),
            Err(_) => PreconnectSlot::AtCapacity,
        }
    }
}

static GLOBAL_PRECONNECT_LIMITER: std::sync::LazyLock<Option<Arc<PreconnectLimiter>>> =
    std::sync::LazyLock::new(|| PreconnectLimiter::new(MAX_PRECONNECTED_CONNS).map(Arc::new));

fn global_preconnect_limiter() -> Option<&'static Arc<PreconnectLimiter>> {
    GLOBAL_PRECONNECT_LIMITER.as_ref()
}

struct PreparedConnPoolState {
    ready: Vec<PreparedConn>,
    pending: i32,
    closed: bool,
}

struct PreparedConnPool {
    state: Mutex<PreparedConnPoolState>,
    changed: Mutex<Arc<tokio::sync::Notify>>,
    limiter: Option<Arc<PreconnectLimiter>>,
}

impl PreparedConnPool {
    fn new(limiter: Option<Arc<PreconnectLimiter>>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(PreparedConnPoolState { ready: Vec::new(), pending: 0, closed: false }),
            changed: Mutex::new(Arc::new(tokio::sync::Notify::new())),
            limiter,
        })
    }

    fn notify_locked(&self) {
        let mut changed = self.changed.lock();
        changed.notify_waiters();
        *changed = Arc::new(tokio::sync::Notify::new());
    }

    fn fill(
        self: &Arc<Self>,
        ctx: &CancellationToken,
        count: i32,
        dial: &Arc<dyn Fn(CancellationToken) -> DialFuture + Send + Sync>,
        done: Option<Box<dyn FnOnce() + Send>>,
    ) {
        if count <= 0 {
            if let Some(done) = done {
                done();
            }
            return;
        }

        let count = {
            let mut state = self.state.lock();
            if state.closed {
                drop(state);
                if let Some(done) = done {
                    done();
                }
                return;
            }
            let remaining = count - (i32::try_from(state.ready.len()).unwrap_or(i32::MAX) + state.pending);
            if remaining <= 0 {
                drop(state);
                if let Some(done) = done {
                    done();
                }
                return;
            }
            state.pending += remaining;
            drop(state);
            self.notify_locked();
            remaining
        };

        let mut handles = Vec::with_capacity(usize::try_from(count).unwrap_or_default());
        for _ in 0..count {
            let pool = Arc::clone(self);
            let ctx = ctx.clone();
            let dial = Arc::clone(dial);
            handles.push(tokio::spawn(async move {
                let release = match PreconnectLimiter::acquire(pool.limiter.as_ref()) {
                    PreconnectSlot::Reserved(permit) => Some(permit),
                    PreconnectSlot::Unlimited => None,
                    PreconnectSlot::AtCapacity => {
                        let mut state = pool.state.lock();
                        state.pending -= 1;
                        drop(state);
                        pool.notify_locked();
                        return;
                    }
                };
                let conn = dial(ctx).await;

                let mut state = pool.state.lock();
                state.pending -= 1;
                if state.closed {
                    pool.notify_locked();
                    drop(state);
                    drop(release);
                    if let Ok(conn) = conn {
                        let _ = murmur_common_net::io::close_stream(&*conn);
                    }
                    return;
                }
                if let Ok(conn) = conn {
                    let expires_at = Instant::now() + PRECONNECTED_CONN_TTL;
                    state.ready.push(PreparedConn { conn, expires_at, release });
                    pool.notify_locked();
                    drop(state);
                    let pool = Arc::clone(&pool);
                    tokio::spawn(async move { pool.expire(expires_at).await });
                } else {
                    pool.notify_locked();
                    drop(state);
                    drop(release);
                }
            }));
        }

        if let Some(done) = done {
            tokio::spawn(async move {
                for handle in handles {
                    let _ = handle.await;
                }
                done();
            });
        }
    }

    // cancel-safe: the entry is removed under the lock before the wait, and a dropped wait only
    // stops waiting.
    async fn take(&self, ctx: &CancellationToken) -> anyhow::Result<Option<Box<dyn Stream>>> {
        loop {
            let (found, wait_notify) = {
                let mut state = self.state.lock();
                if !state.ready.is_empty() {
                    let item = state.ready.remove(0);
                    self.notify_locked();
                    (Some(item), None)
                } else if state.pending == 0 || state.closed {
                    (None, None)
                } else {
                    (None, Some(Arc::clone(&self.changed.lock())))
                }
            };

            if let Some(item) = found {
                if Instant::now() >= item.expires_at {
                    drop(item.release);
                    drop(item.conn);
                    continue;
                }
                return Ok(Some(item.conn));
            }

            let Some(notify) = wait_notify else {
                return Ok(None);
            };
            tokio::select! {
                () = notify.notified() => {}
                () = ctx.cancelled() => return Err(anyhow::anyhow!("context canceled")),
            }
        }
    }

    async fn expire(self: Arc<Self>, expires_at: Instant) {
        tokio::time::sleep_until(expires_at.max(Instant::now())).await;

        let removed = {
            let mut state = self.state.lock();
            let pos = state.ready.iter().position(|item| item.expires_at == expires_at);
            let removed = pos.map(|pos| state.ready.remove(pos));
            if removed.is_some() {
                self.notify_locked();
            }
            removed
        };
        if let Some(item) = removed {
            drop(item.release);
        }
    }

    fn close(&self) {
        let mut state = self.state.lock();
        if state.closed {
            return;
        }
        state.closed = true;
        let ready = std::mem::take(&mut state.ready);
        self.notify_locked();
        drop(state);
        drop(ready);
    }

    fn clear_idle(&self) {
        let mut state = self.state.lock();
        let ready = std::mem::take(&mut state.ready);
        self.notify_locked();
        drop(state);
        drop(ready);
    }
}

// cancel-safe: a cancelled dial drops the connection the inner dial had just opened.
async fn dial_fresh_impl(
    dial: &Arc<dyn NetDialer>,
    url_host: &str,
    dial_addr: &str,
    ctx: &CancellationToken,
    network: &str,
    addr: &str,
) -> anyhow::Result<Box<dyn Stream>> {
    let addr = if addr == url_host { dial_addr } else { addr };
    dial.dial_context(ctx, network, addr).await
}

// cancel-safe: as `dial_fresh_impl`; a cancelled handshake drops the TLS conn with it.
async fn dial_tls_fresh_impl(
    dial: &Arc<dyn NetDialer>,
    url_host: &str,
    dial_addr: &str,
    server_name: &str,
    tls_config: Option<&Arc<TlsConfig>>,
    ctx: &CancellationToken,
    network: &str,
    addr: &str,
) -> anyhow::Result<Box<dyn Stream>> {
    let dial_ctx = with_timeout(ctx, TUNNEL_TLS_HANDSHAKE_LIMIT);

    let TlsConfig {
        rand,
        time,
        certificates,
        get_certificate,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        next_protos,
        server_name: default_server_name,
        client_auth,
        client_cas,
        insecure_skip_verify,
        cipher_suites,
        session_tickets_disabled,
        max_version,
        curve_preferences,
        renegotiation,
        key_log_writer,
        encrypted_client_hello_config_list,
        encrypted_client_hello_rejection_verify,
        encrypted_client_hello_keys,
        get_encrypted_client_hello_keys,
        session_id_generator,
        ..
    } = TlsConfig::default();
    let mut config = match tls_config {
        Some(config) => TlsConfig::clone(config),
        None => TlsConfig {
            rand,
            time,
            certificates,
            get_certificate,
            get_client_certificate,
            verify_peer_certificate,
            verify_connection,
            root_cas,
            next_protos,
            server_name: default_server_name,
            client_auth,
            client_cas,
            insecure_skip_verify,
            cipher_suites,
            session_tickets_disabled,
            min_version: VERSION_TLS12,
            max_version,
            curve_preferences,
            renegotiation,
            key_log_writer,
            encrypted_client_hello_config_list,
            encrypted_client_hello_rejection_verify,
            encrypted_client_hello_keys,
            get_encrypted_client_hello_keys,
            session_id_generator,
        },
    };
    if addr == url_host {
        config.server_name = server_name.to_owned();
    }

    let raw_conn = dial_fresh_impl(dial, url_host, dial_addr, &dial_ctx, network, addr).await?;
    let tls_conn = tls_client(raw_conn, Arc::new(config));
    tls_conn.handshake_context(&dial_ctx).await?;
    Ok(Box::new(tls_conn))
}

pub(crate) struct PreconnectDialer {
    url_host: String,
    dial_addr: String,
    server_name: String,
    tls_config: Option<Arc<TlsConfig>>,
    dial: Arc<dyn NetDialer>,
    pool: Arc<PreparedConnPool>,
}

pub(crate) fn new_preconnect_dialer(
    url_host: String,
    dial_addr: String,
    server_name: String,
    tls_config: Option<Arc<TlsConfig>>,
    dial: Arc<dyn NetDialer>,
) -> PreconnectDialer {
    PreconnectDialer {
        url_host,
        dial_addr,
        server_name,
        tls_config,
        dial,
        pool: PreparedConnPool::new(global_preconnect_limiter().cloned()),
    }
}

impl PreconnectDialer {
    ///
    /// Deviation: the dial context is built from an empty parent context with only an absolute
    /// deadline ("Auto cancels its stream probe after a successful dial. Preserve only the
    /// absolute deadline while the initial pull and push connections finish"), deliberately
    /// detached from the caller's `ctx` so that cancelling `ctx` after a successful dial does not
    /// empty the preconnect pool. `CancellationToken` has no deadline to read off `ctx` the way a
    /// plain context does, so this crate uses a brand-new, `ctx`-independent token bounded only
    /// by the TTL timer, dropping just the "or ctx's own earlier deadline" refinement.
    pub(crate) fn preconnect(
        &self,
        _ctx: &CancellationToken,
        tls_enabled: bool,
        count: i32,
    ) -> Box<dyn FnOnce() + Send> {
        let dial_ctx = CancellationToken::new();
        let timer_token = dial_ctx.clone();
        tokio::spawn(async move {
            // cancel-safe: aborting this spawned timer only stops the TTL wait; the pool it fills
            // is reached through the same `Arc` the dialer holds.
            tokio::select! {
                () = tokio::time::sleep(PRECONNECTED_CONN_TTL) => timer_token.cancel(),
                () = timer_token.cancelled() => {}
            }
        });

        let dial = Arc::clone(&self.dial);
        let url_host = self.url_host.clone();
        let dial_addr = self.dial_addr.clone();
        let server_name = self.server_name.clone();
        let tls_config = self.tls_config.clone();
        let dial_closure: Arc<dyn Fn(CancellationToken) -> DialFuture + Send + Sync> =
            Arc::new(move |ctx: CancellationToken| {
                let dial = Arc::clone(&dial);
                let url_host = url_host.clone();
                let dial_addr = dial_addr.clone();
                let server_name = server_name.clone();
                let tls_config = tls_config.clone();
                Box::pin(async move {
                    if tls_enabled {
                        dial_tls_fresh_impl(
                            &dial,
                            &url_host,
                            &dial_addr,
                            &server_name,
                            tls_config.as_ref(),
                            &ctx,
                            "tcp",
                            &url_host,
                        )
                        .await
                    } else {
                        dial_fresh_impl(&dial, &url_host, &dial_addr, &ctx, "tcp", &url_host).await
                    }
                })
            });

        let cancel_token = dial_ctx.clone();
        self.pool.fill(
            &dial_ctx,
            count,
            &dial_closure,
            Some(Box::new({
                let cancel_token = cancel_token.clone();
                move || cancel_token.cancel()
            })),
        );

        Box::new(move || cancel_token.cancel())
    }

    pub(crate) async fn dial_context(
        &self,
        ctx: &CancellationToken,
        network: &str,
        addr: &str,
    ) -> anyhow::Result<Box<dyn Stream>> {
        if addr == self.url_host {
            if let Some(conn) = self.pool.take(ctx).await? {
                return Ok(conn);
            }
        }
        self.dial_fresh(ctx, network, addr).await
    }

    pub(crate) async fn dial_tls_context(
        &self,
        ctx: &CancellationToken,
        network: &str,
        addr: &str,
    ) -> anyhow::Result<Box<dyn Stream>> {
        if addr == self.url_host {
            if let Some(conn) = self.pool.take(ctx).await? {
                return Ok(conn);
            }
        }
        self.dial_tls_fresh(ctx, network, addr).await
    }

    async fn dial_fresh(&self, ctx: &CancellationToken, network: &str, addr: &str) -> anyhow::Result<Box<dyn Stream>> {
        dial_fresh_impl(&self.dial, &self.url_host, &self.dial_addr, ctx, network, addr).await
    }

    async fn dial_tls_fresh(
        &self,
        ctx: &CancellationToken,
        network: &str,
        addr: &str,
    ) -> anyhow::Result<Box<dyn Stream>> {
        dial_tls_fresh_impl(
            &self.dial,
            &self.url_host,
            &self.dial_addr,
            &self.server_name,
            self.tls_config.as_ref(),
            ctx,
            network,
            addr,
        )
        .await
    }

    pub(crate) fn close(&self) {
        self.pool.close();
    }

    pub(crate) fn clear_idle(&self) {
        self.pool.clear_idle();
    }
}

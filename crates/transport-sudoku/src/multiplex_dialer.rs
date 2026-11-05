use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::future::BoxFuture;
use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::multiplex_file::{start_multiplex_client, MultiplexClient};
use murmur_common::contextutils::after_func;
use murmur_common_net::io::Stream;

pub type MultiplexBaseDialer =
    Arc<dyn Fn(CancellationToken) -> BoxFuture<'static, Result<Box<dyn Stream>>> + Send + Sync>;

struct State {
    creating: bool,
    create_done: Option<Arc<Notify>>,
    create_stop: Option<CancellationToken>,
    client: Option<Arc<MultiplexClient>>,
    maintain_stop: Option<CancellationToken>,
    closed: bool,
}

/// `MultiplexDialer`: starts maintaining a warmed Sudoku mux session after the first
/// successful `Dial` and recreates it after transport failures.
/// Concurrent callers share the same creation attempt.
pub struct MultiplexDialer {
    dial_base: MultiplexBaseDialer,
    state: Mutex<State>,
    maintain_done: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for MultiplexDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexDialer")
            .field("closed", &self.state.try_lock().map(|state| state.closed))
            .finish_non_exhaustive()
    }
}

impl MultiplexDialer {
    pub fn new(dial_base: MultiplexBaseDialer) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            dial_base,
            state: Mutex::new(State {
                creating: false,
                create_done: None,
                create_stop: None,
                client: None,
                maintain_stop: None,
                closed: false,
            }),
            maintain_done: tokio::sync::Mutex::new(None),
        }))
    }

    pub async fn dial(self: &Arc<Self>, ctx: &CancellationToken, target_address: &str) -> Result<Box<dyn Stream>> {
        let mut last_err: Option<anyhow::Error> = None;
        for _ in 0..2 {
            let client = self.get_or_create_client(ctx).await?;
            match client.dial(ctx, target_address).await {
                Ok(stream) => {
                    self.start_maintaining();
                    return Ok(stream);
                }
                Err(err) => {
                    if !client.is_closed() {
                        return Err(err);
                    }
                    last_err = Some(err);
                    self.discard_client(&client);
                }
            }
        }
        Err(anyhow!("multiplex open stream failed: {}", last_err.map(|err| err.to_string()).unwrap_or_default()))
    }

    /// Keeps a ready mux session available until `ctx` is
    /// canceled.
    // cancel-safe: a drop stops the keep-alive loop; the session it was watching is closed by the
    // dialer's own `close`, and no state is left half-updated.
    pub(crate) async fn maintain(self: &Arc<Self>, ctx: &CancellationToken) {
        const MIN_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);
        const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);
        let mut backoff = MIN_BACKOFF;
        loop {
            let client = match self.get_or_create_client(ctx).await {
                Ok(client) => client,
                Err(err) => {
                    if ctx.is_cancelled() || is_err_closed(&err) || !wait_multiplex_retry(ctx, backoff).await {
                        return;
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
            };

            backoff = MIN_BACKOFF;
            let done = client.done();
            tokio::select! {
                () = ctx.cancelled() => return,
                () = done.cancelled() => {}
            }
            self.discard_client(&client);
            if ctx.is_cancelled() || !wait_multiplex_retry(ctx, backoff).await {
                return;
            }
        }
    }

    pub async fn close(self: &Arc<Self>) -> Result<()> {
        let (stop, client, stop_maintaining) = {
            let mut state = self.state.lock();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            let stop = state.create_stop.take();
            let client = state.client.take();
            let stop_maintaining = state.maintain_stop.take();
            drop(state);
            (stop, client, stop_maintaining)
        };

        if let Some(stop_maintaining) = stop_maintaining {
            stop_maintaining.cancel();
        }
        if let Some(stop) = stop {
            stop.cancel();
        }
        if let Some(client) = &client {
            client.close();
        }
        let handle = self.maintain_done.lock().await.take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        Ok(())
    }

    fn start_maintaining(self: &Arc<Self>) {
        let Ok(mut maintain_guard) = self.maintain_done.try_lock() else {
            return;
        };
        let mut state = self.state.lock();
        if state.closed || maintain_guard.is_some() {
            return;
        }
        let ctx = CancellationToken::new();
        state.maintain_stop = Some(ctx.clone());
        drop(state);

        let this = Arc::clone(self);
        *maintain_guard = Some(tokio::spawn(async move {
            this.maintain(&ctx).await;
        }));
    }

    // NOT cancel-safe: the `creating` flag is set before the client is built, so a drop between the
    // two leaves the flag set and every later caller waiting for a notification that never comes.
    async fn get_or_create_client(self: &Arc<Self>, ctx: &CancellationToken) -> Result<Arc<MultiplexClient>> {
        loop {
            let notify = {
                let mut state = self.state.lock();
                if state.closed {
                    return Err(anyhow!("use of closed network connection"));
                }
                if let Some(client) = &state.client {
                    if !client.is_closed() {
                        return Ok(Arc::clone(client));
                    }
                }
                if state.creating {
                    state.create_done.clone()
                } else {
                    state.creating = true;
                    let notify = Arc::new(Notify::new());
                    state.create_done = Some(notify);
                    None
                }
            };

            if let Some(notify) = notify {
                tokio::select! {
                    () = notify.notified() => continue,
                    () = ctx.cancelled() => return Err(anyhow!("context canceled")),
                }
            }
            break;
        }

        let create_ctx = ctx.child_token();
        {
            let mut state = self.state.lock();
            if state.closed {
                Self::finish_create_locked(&mut state);
                drop(state);
                create_ctx.cancel();
                return Err(anyhow!("use of closed network connection"));
            }
            state.create_stop = Some(create_ctx.clone());
        }

        let result = self.create_client(&create_ctx).await;
        create_ctx.cancel();

        let mut state = self.state.lock();
        state.create_stop = None;

        match &result {
            Ok(client) if !state.closed => {
                state.client = Some(Arc::clone(client));
            }
            Ok(client) => {
                let client = Arc::clone(client);
                drop(state);
                client.close();
                state = self.state.lock();
            }
            Err(_) => {}
        }
        Self::finish_create_locked(&mut state);
        let closed_after = state.closed;
        drop(state);

        if closed_after {
            return Err(anyhow!("use of closed network connection"));
        }
        result
    }

    async fn create_client(self: &Arc<Self>, ctx: &CancellationToken) -> Result<Arc<MultiplexClient>> {
        let base_conn = (self.dial_base)(ctx.clone()).await?;
        let shared =
            murmur_common::shared_conn::SharedConn::new(murmur_common_net::io::CancellableStream::new(base_conn));

        let shared_for_stop = shared.clone();
        let stop = after_func(ctx, move || {
            let _ = shared_for_stop.close();
        });

        let client =
            match start_multiplex_client(ctx, Box::new(murmur_common_net::io::OldConnAsStream(shared.clone()))).await {
                Ok(client) => client,
                Err(err) => {
                    stop();
                    let _ = shared.close();
                    return Err(err);
                }
            };
        if !stop() {
            client.close();
            if ctx.is_cancelled() {
                return Err(anyhow!("context canceled"));
            }
            return Err(anyhow!("use of closed network connection"));
        }
        Ok(Arc::new(client))
    }

    fn finish_create_locked(state: &mut State) {
        state.creating = false;
        if let Some(notify) = state.create_done.take() {
            notify.notify_waiters();
        }
    }

    fn discard_client(&self, client: &Arc<MultiplexClient>) {
        let mut state = self.state.lock();
        if let Some(current) = &state.client {
            if Arc::ptr_eq(current, client) {
                state.client = None;
            }
        }
    }
}

// cancel-safe: it only waits out the backoff and reports whether the context is still live.
async fn wait_multiplex_retry(ctx: &CancellationToken, delay: std::time::Duration) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => true,
        () = ctx.cancelled() => false,
    }
}

/// Matches a closed-network-connection error: this crate has no typed closed-conn sentinel, so the
/// dialer's own closed-network-connection message (the only source of that error here) is
/// matched by text instead.
fn is_err_closed(err: &anyhow::Error) -> bool {
    err.to_string() == "use of closed network connection"
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
    use tokio::sync::mpsc;

    use super::*;
    use crate::kip::{read_kip_message, KIP_TYPE_START_MUX};
    use crate::multiplex::session::Session;

    /// In-memory pipe stand-in: a bidirectional in-memory conn.
    struct PipeConn(DuplexStream);

    impl AsyncRead for PipeConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PipeConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl Stream for PipeConn {
        fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
        }

        fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    async fn start_test_multiplex_peer(mut conn: Box<dyn Stream>) -> Arc<Session> {
        let msg = read_kip_message(&mut conn).await.expect("read mux start");
        assert!(
            msg.typ == KIP_TYPE_START_MUX && msg.payload.is_empty(),
            "unexpected mux start: type={} payload={}",
            msg.typ,
            msg.payload.len()
        );
        Session::server(conn)
    }

    #[tokio::test]
    async fn multiplex_dialer_maintain_reconnects_closed_session() {
        let calls = Arc::new(AtomicI32::new(0));
        let (peers_tx, mut peers_rx) = mpsc::channel::<Box<dyn Stream>>(2);

        let calls_dial = Arc::clone(&calls);
        let dial_base: MultiplexBaseDialer = Arc::new(move |_ctx: CancellationToken| {
            calls_dial.fetch_add(1, Ordering::SeqCst);
            let peers_tx = peers_tx.clone();
            Box::pin(async move {
                let (client_conn, server_conn) = tokio::io::duplex(64 * 1024);
                let server_conn: Box<dyn Stream> = Box::new(PipeConn(server_conn));
                let _ = peers_tx.send(server_conn).await;
                let client_conn: Box<dyn Stream> = Box::new(PipeConn(client_conn));
                Ok(client_conn)
            })
        });
        let dialer = MultiplexDialer::new(dial_base).expect("new dialer");

        let ctx = CancellationToken::new();
        let dialer_maintain = Arc::clone(&dialer);
        let ctx_maintain = ctx.clone();
        let done = tokio::spawn(async move {
            dialer_maintain.maintain(&ctx_maintain).await;
        });

        let first_peer = peers_rx.recv().await.expect("first peer");
        let first_server = start_test_multiplex_peer(first_peer).await;
        first_server.close();

        let peer = match tokio::time::timeout(Duration::from_secs(2), peers_rx.recv()).await {
            Ok(Some(peer)) => peer,
            _ => panic!("maintainer did not reconnect; base dial count={}", calls.load(Ordering::SeqCst)),
        };
        let server = start_test_multiplex_peer(peer).await;

        ctx.cancel();
        let _ = dialer.close().await;
        done.await.expect("maintainer task");
        server.close();
    }

    #[tokio::test]
    async fn multiplex_dialer_close_cancels_creation() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (canceled_tx, canceled_rx) = tokio::sync::oneshot::channel::<()>();
        let started_tx = Arc::new(Mutex::new(Some(started_tx)));
        let canceled_tx = Arc::new(Mutex::new(Some(canceled_tx)));

        let dial_base: MultiplexBaseDialer = Arc::new(move |ctx: CancellationToken| {
            let started_tx = Arc::clone(&started_tx);
            let canceled_tx = Arc::clone(&canceled_tx);
            Box::pin(async move {
                if let Some(tx) = started_tx.lock().take() {
                    let _ = tx.send(());
                }
                ctx.cancelled().await;
                if let Some(tx) = canceled_tx.lock().take() {
                    let _ = tx.send(());
                }
                Err(anyhow!("context canceled"))
            })
        });
        let dialer = MultiplexDialer::new(dial_base).expect("new dialer");

        let dialer_maintain = Arc::clone(&dialer);
        let done = tokio::spawn(async move {
            dialer_maintain.maintain(&CancellationToken::new()).await;
        });

        started_rx.await.expect("started");
        dialer.close().await.expect("close");

        tokio::time::timeout(Duration::from_secs(1), canceled_rx)
            .await
            .expect("base dial was not canceled")
            .expect("canceled signal");
        tokio::time::timeout(Duration::from_secs(1), done)
            .await
            .expect("maintainer did not stop")
            .expect("maintainer task");
    }
}

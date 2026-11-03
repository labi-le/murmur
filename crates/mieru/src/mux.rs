//! Simplified for a single server address: idle-underlay cleanup on a timer instead of the
//! traffic-volume-based scheduler.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;

use crate::io::{ClientDialer, PacketIo, ServerEndpoint};
use crate::session::{Session, Transport};
use crate::trafficpattern::Config;
use crate::underlay::{PacketUnderlay, Result, ServerUsers, StreamUnderlay, UnderlayError};

const UNDERLAY_CLEAN_INTERVAL: Duration = Duration::from_secs(5);
/// `KeyRefreshInterval / 2`: how long a client-side UDP underlay's cipher stays valid before a
/// long-lived client must redial rather than reuse it.
const PACKET_UNDERLAY_KEY_LIFETIME: Duration = Duration::from_secs(60);

enum UnderlayHandle {
    Stream(StreamUnderlay),
    Packet(PacketUnderlay),
}

impl UnderlayHandle {
    async fn dial_session(&self, id: u32) -> Arc<Session> {
        match self {
            Self::Stream(u) => u.dial_session(id).await,
            Self::Packet(u) => u.dial_session(id).await,
        }
    }

    async fn session_count(&self) -> usize {
        match self {
            Self::Stream(u) => u.session_count().await,
            Self::Packet(u) => u.session_count().await,
        }
    }
}

struct TrackedUnderlay {
    handle: UnderlayHandle,
    created_at: Instant,
}

/// Client-side `Mux`: dials one port of the configured range (chosen uniformly at random),
/// reusing an existing underlay with probability `multiplex_factor /
/// (live_underlay_count*multiplex_factor + 1)`.
///
/// `credential` is the hashed secret the mux takes, not the
/// configured password: [`crate::cipher::hash_password`] is what the server's credential builder
/// mirrors, so handing the mux a raw password can never authenticate.
pub struct ClientMux {
    host: String,
    ports: Vec<u16>,
    credential: Vec<u8>,
    username: String,
    transport: Transport,
    multiplex_factor: u32,
    dialer: Arc<dyn ClientDialer>,
    /// The `traffic-pattern` every underlay this mux dials is built with; `None` is mieru's
    /// unpadded, unshaped default.
    traffic_pattern: Option<Config>,
    underlays: AsyncMutex<Vec<Arc<TrackedUnderlay>>>,
    closed: AtomicBool,
}

impl std::fmt::Debug for ClientMux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientMux")
            .field("host", &self.host)
            .field("ports", &self.ports)
            .field("username", &self.username)
            .field("transport", &self.transport)
            .field("multiplex_factor", &self.multiplex_factor)
            .finish_non_exhaustive()
    }
}

impl ClientMux {
    pub fn new(
        host: String,
        ports: Vec<u16>,
        credential: Vec<u8>,
        username: String,
        transport: Transport,
        multiplex_factor: u32,
        dialer: Arc<dyn ClientDialer>,
        traffic_pattern: Option<Config>,
    ) -> Arc<Self> {
        let mux = Arc::new(Self {
            host,
            ports,
            credential,
            username,
            transport,
            multiplex_factor,
            dialer,
            traffic_pattern,
            underlays: AsyncMutex::new(Vec::new()),
            closed: AtomicBool::new(false),
        });
        spawn_client_cleanup(Arc::clone(&mux));
        mux
    }

    pub async fn dial(&self, ctx: &CancellationToken) -> Result<Arc<Session>> {
        let reused = self.maybe_pick_existing_underlay().await;
        let underlay = match reused {
            Some(u) => u,
            None => self.dial_fresh_underlay(ctx).await?,
        };
        let id = Session::random_id();
        Ok(underlay.handle.dial_session(id).await)
    }

    async fn maybe_pick_existing_underlay(&self) -> Option<Arc<TrackedUnderlay>> {
        if self.multiplex_factor == 0 {
            return None;
        }
        let live: Vec<Arc<TrackedUnderlay>> = self
            .underlays
            .lock()
            .await
            .iter()
            .filter(|u| self.transport == Transport::Stream || u.created_at.elapsed() < PACKET_UNDERLAY_KEY_LIFETIME)
            .cloned()
            .collect();
        if live.is_empty() {
            return None;
        }
        // `n` is drawn from `[0, len*factor+1)` and `active[n/factor]` reused when `n` lands
        // below the reuse bound, so every live underlay carries the same weight. Drawing per
        // candidate instead would skew the earliest underlay and never reuse once a later one won.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "every live underlay owns an open socket, so the count stays far below u32::MAX"
        )]
        let reuse_bound = live.len() as u32 * self.multiplex_factor;
        let n = rand::rng().random_range(0..=reuse_bound);
        if n >= reuse_bound {
            return None;
        }
        live.get((n / self.multiplex_factor) as usize).map(Arc::clone)
    }

    async fn dial_fresh_underlay(&self, ctx: &CancellationToken) -> Result<Arc<TrackedUnderlay>> {
        let port = *self.ports.get(rand::rng().random_range(0..self.ports.len())).ok_or_else(|| {
            UnderlayError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, "no ports configured"))
        })?;
        let handle = match self.transport {
            Transport::Stream => UnderlayHandle::Stream(
                StreamUnderlay::connect(
                    self.dialer.as_ref(),
                    ctx,
                    &self.host,
                    port,
                    &self.credential,
                    &self.username,
                    self.traffic_pattern.clone(),
                )
                .await?,
            ),
            Transport::Packet => UnderlayHandle::Packet(
                PacketUnderlay::connect(
                    self.dialer.as_ref(),
                    ctx,
                    &self.host,
                    port,
                    &self.credential,
                    &self.username,
                    self.traffic_pattern.clone(),
                )
                .await?,
            ),
        };
        let tracked = Arc::new(TrackedUnderlay { handle, created_at: Instant::now() });
        self.underlays.lock().await.push(Arc::clone(&tracked));
        Ok(tracked)
    }

    pub async fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let mut underlays = self.underlays.lock().await;
        for underlay in underlays.drain(..) {
            match &underlay.handle {
                UnderlayHandle::Stream(u) => u.close().await,
                UnderlayHandle::Packet(u) => u.close().await,
            }
        }
    }
}

fn spawn_client_cleanup(mux: Arc<ClientMux>) {
    tokio::spawn(async move {
        // the first tick must land one interval out; `tokio::time::interval` fires at once.
        let mut interval =
            tokio::time::interval_at(tokio::time::Instant::now() + UNDERLAY_CLEAN_INTERVAL, UNDERLAY_CLEAN_INTERVAL);
        loop {
            interval.tick().await;
            if mux.closed.load(Ordering::Acquire) {
                return;
            }
            let mut underlays = mux.underlays.lock().await;
            let mut keep = Vec::with_capacity(underlays.len());
            for underlay in underlays.drain(..) {
                if underlay.handle.session_count().await == 0 {
                    match &underlay.handle {
                        UnderlayHandle::Stream(u) => u.close().await,
                        UnderlayHandle::Packet(u) => u.close().await,
                    }
                } else {
                    keep.push(underlay);
                }
            }
            *underlays = keep;
        }
    });
}

/// Server-side `Mux`: one listener (stream) or socket (packet) per bound endpoint, all feeding a
/// single "new session ready" channel.
pub struct ServerMux {
    accept_rx: AsyncMutex<mpsc::Receiver<Arc<Session>>>,
    bound_addrs: Vec<std::net::SocketAddr>,
    acceptors: Vec<Arc<dyn crate::io::Acceptor>>,
    closed: Arc<AtomicBool>,
}

impl std::fmt::Debug for ServerMux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerMux").field("bound_addrs", &self.bound_addrs).finish_non_exhaustive()
    }
}

const SERVER_ACCEPT_CAPACITY: usize = 256;

impl ServerMux {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the exported constructor takes the traffic pattern by value; it is cloned per listener"
    )]
    pub fn new(
        users: &HashMap<String, String>,
        endpoints: Vec<ServerEndpoint>,
        user_hint_is_mandatory: bool,
        traffic_pattern: Option<Config>,
    ) -> Result<Self> {
        if endpoints.is_empty() {
            return Err(UnderlayError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no bind endpoints configured",
            )));
        }
        let (accept_tx, accept_rx) = mpsc::channel(SERVER_ACCEPT_CAPACITY);
        let closed = Arc::new(AtomicBool::new(false));
        let server_users = ServerUsers::new(users, user_hint_is_mandatory);
        let mut acceptors = Vec::new();
        let mut bound_addrs = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            match endpoint {
                ServerEndpoint::Stream(acceptor) => {
                    if let Ok(addr) = acceptor.addr() {
                        bound_addrs.push(addr);
                    }
                    spawn_stream_listener(
                        Arc::clone(&acceptor),
                        server_users.clone(),
                        accept_tx.clone(),
                        Arc::clone(&closed),
                        traffic_pattern.clone(),
                    );
                    acceptors.push(acceptor);
                }
                ServerEndpoint::Packet(socket) => {
                    if let Ok(addr) = socket.local_addr() {
                        bound_addrs.push(addr);
                    }
                    spawn_packet_listener(
                        socket,
                        server_users.clone(),
                        accept_tx.clone(),
                        Arc::clone(&closed),
                        traffic_pattern.clone(),
                    );
                }
            }
        }
        Ok(Self { accept_rx: AsyncMutex::new(accept_rx), bound_addrs, acceptors, closed })
    }

    // cancel-safe: receives from a channel, so a dropped call leaves the queued item for the next one.
    pub async fn accept(&self) -> Option<Arc<Session>> {
        self.accept_rx.lock().await.recv().await
    }

    /// The actual bound addresses, useful when a configured port was `0`.
    pub fn bound_addrs(&self) -> &[std::net::SocketAddr] {
        &self.bound_addrs
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        for acceptor in &self.acceptors {
            let _ = acceptor.close();
        }
    }
}

fn spawn_stream_listener(
    acceptor: Arc<dyn crate::io::Acceptor>,
    users: ServerUsers,
    accept_tx: mpsc::Sender<Arc<Session>>,
    closed: Arc<AtomicBool>,
    traffic_pattern: Option<Config>,
) {
    tokio::spawn(async move {
        loop {
            if closed.load(Ordering::Acquire) {
                return;
            }
            let Ok(accepted) = acceptor.accept().await else { return };
            let Ok(underlay) = StreamUnderlay::from_accepted(accepted, users.clone(), traffic_pattern.clone()) else {
                continue;
            };
            let accept_tx = accept_tx.clone();
            tokio::spawn(async move {
                let underlay = Arc::new(underlay);
                while let Some(session) = underlay.accept_session().await {
                    if accept_tx.send(session).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
}

fn spawn_packet_listener(
    socket: Arc<dyn PacketIo>,
    users: ServerUsers,
    accept_tx: mpsc::Sender<Arc<Session>>,
    closed: Arc<AtomicBool>,
    traffic_pattern: Option<Config>,
) {
    let underlay = Arc::new(PacketUnderlay::bound(socket, users, traffic_pattern));
    tokio::spawn(async move {
        while let Some(session) = underlay.accept_session().await {
            if closed.load(Ordering::Acquire) {
                return;
            }
            if accept_tx.send(session).await.is_err() {
                return;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::io::{boxed_stream, DialedStream, SystemDialer};

    fn mux_with(underlays: Vec<Arc<TrackedUnderlay>>) -> Arc<ClientMux> {
        Arc::new(ClientMux {
            host: "127.0.0.1".to_owned(),
            ports: vec![1],
            credential: vec![0u8; 32],
            username: "user".to_owned(),
            transport: Transport::Stream,
            multiplex_factor: 1,
            dialer: Arc::new(SystemDialer),
            traffic_pattern: None,
            underlays: AsyncMutex::new(underlays),
            closed: AtomicBool::new(false),
        })
    }

    /// An underlay whose session has not registered yet, i.e. what `dial_fresh_underlay` publishes
    /// before `dial_session` runs: a cleaner pass in that window closes a live connection.
    fn fresh_underlay() -> (Arc<TrackedUnderlay>, tokio::io::DuplexStream) {
        let (dialed, peer) = tokio::io::duplex(1024);
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("address");
        let underlay = StreamUnderlay::from_dialed(
            DialedStream { stream: boxed_stream(dialed), local_addr: Ok(addr), peer_addr: Ok(addr) },
            true,
            None,
            None,
            None,
        )
        .expect("build the underlay");
        (Arc::new(TrackedUnderlay { handle: UnderlayHandle::Stream(underlay), created_at: Instant::now() }), peer)
    }

    /// the first tick must land a full interval out. `tokio::time::interval` fires
    /// immediately instead, which ran a cleanup pass over an underlay that had just been dialed
    /// and had no session yet, closing it out from under the dial.
    #[tokio::test(start_paused = true)]
    async fn the_client_cleaner_waits_a_full_interval_before_its_first_pass() {
        let (underlay, _peer) = fresh_underlay();
        let mux = mux_with(vec![underlay]);
        assert_eq!(mux.underlays.lock().await.len(), 1);

        spawn_client_cleanup(Arc::clone(&mux));
        tokio::task::yield_now().await;
        assert_eq!(
            mux.underlays.lock().await.len(),
            1,
            "the cleaner closed a fresh underlay before the interval elapsed"
        );

        tokio::time::advance(UNDERLAY_CLEAN_INTERVAL).await;
        tokio::task::yield_now().await;
        assert_eq!(mux.underlays.lock().await.len(), 0, "the cleaner must still drop an underlay with no sessions");
    }
}

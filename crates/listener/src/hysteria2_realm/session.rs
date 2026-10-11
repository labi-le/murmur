use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::RngCore;
use regex::Regex;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub const SESSION_TTL: Duration = Duration::from_secs(60);
pub const REAPER_INTERVAL: Duration = Duration::from_secs(1);
pub const DEFAULT_REALM_NAME_PATTERN: &str = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$";
pub const EVENTS_BUFFER_SIZE: usize = 16;
pub const MAX_PENDING_ATTEMPTS: usize = EVENTS_BUFFER_SIZE;

#[derive(Debug)]
pub struct SessionEvent {
    pub kind: String,
    pub data: Value,
}

#[derive(Debug)]
pub struct PunchResponsePayload {
    pub addresses: Vec<String>,
}

#[derive(Debug)]
struct SessionInner {
    addresses: Vec<String>,
    expires: Instant,
    pending: HashMap<String, oneshot::Sender<PunchResponsePayload>>,
}

#[derive(Debug)]
pub struct Session {
    pub id: String,
    pub realm_id: String,
    pub client_ip: String,
    inner: Mutex<SessionInner>,
    /// One buffered event channel per session, drained by the SSE handler.
    pub events_rx: tokio::sync::Mutex<mpsc::Receiver<SessionEvent>>,
    events_tx: mpsc::Sender<SessionEvent>,
    /// The session's done signal, cancelled on removal.
    pub done: CancellationToken,
    closed: AtomicBool,
}

impl Session {
    pub fn addresses(&self) -> Vec<String> {
        self.inner.lock().addresses.clone()
    }

    pub fn set_addresses(&self, addresses: Vec<String>) {
        self.inner.lock().addresses = addresses;
    }

    pub fn expires(&self) -> Instant {
        self.inner.lock().expires
    }

    pub fn touch(&self, ttl: Duration) {
        self.inner.lock().expires = Instant::now() + ttl;
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn mark_closed(&self) -> bool {
        !self.closed.swap(true, Ordering::SeqCst)
    }
}

#[derive(Debug, Default)]
pub struct ServerConfig {
    pub realm_token: String,
    pub max_realms: i32,
    pub max_realms_per_ip: i32,
    pub proxy_header: String,
    pub realm_id_pattern: Option<Regex>,
    /// The connect-response timeout, held per server so it cannot leak between listeners. `None`
    /// uses the default of 10s.
    pub connect_response_timeout: Option<Duration>,
}

#[derive(Debug)]
struct ServerState {
    /// realmID -> session
    realms: HashMap<String, Arc<Session>>,
    /// sessionID -> session
    sessions: HashMap<String, Arc<Session>>,
    /// clientIP -> realm count
    ip_counts: HashMap<String, i32>,
}

#[derive(Debug)]
pub struct Server {
    mu: Mutex<ServerState>,
    pub(crate) realm_token: String,
    pub(crate) max_realms: i32,
    pub(crate) max_realms_per_ip: i32,
    pub(crate) proxy_header: String,
    pub(crate) realm_id_pattern: Regex,
    pub(crate) connect_response_timeout: Duration,
}

#[expect(clippy::expect_used, reason = "DEFAULT_REALM_NAME_PATTERN is a compile-time-valid regex literal")]
#[must_use]
pub fn new_server(cfg: ServerConfig) -> Server {
    let realm_id_pattern = cfg
        .realm_id_pattern
        .unwrap_or_else(|| Regex::new(DEFAULT_REALM_NAME_PATTERN).expect("static realm name pattern"));
    Server {
        mu: Mutex::new(ServerState { realms: HashMap::new(), sessions: HashMap::new(), ip_counts: HashMap::new() }),
        realm_token: cfg.realm_token,
        max_realms: cfg.max_realms,
        max_realms_per_ip: cfg.max_realms_per_ip,
        proxy_header: cfg.proxy_header,
        realm_id_pattern,
        connect_response_timeout: cfg.connect_response_timeout.unwrap_or(CONNECT_RESPONSE_TIMEOUT),
    }
}

pub const CONNECT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

#[must_use]
pub fn rand_token() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// `register`, under the lock it takes there: creates the session when the realm and both
/// limits allow it, and returns the rejection the caller must answer with otherwise.
#[derive(Debug)]
pub enum RegisterOutcome {
    Registered(Arc<Session>),
    Taken,
    RealmLimit,
    IpLimit,
}

impl Server {
    pub fn get_session_by_token(&self, token: &str) -> Option<Arc<Session>> {
        let state = self.mu.lock();
        let sess = Arc::clone(state.sessions.get(token)?);
        drop(state);
        if sess.is_closed() || Instant::now() > sess.expires() {
            return None;
        }
        Some(sess)
    }

    /// `connect`'s direct `s.realms[id]` lookup, which never consults the session token.
    pub fn realm_session(&self, id: &str) -> Option<Arc<Session>> {
        let state = self.mu.lock();
        let sess = Arc::clone(state.realms.get(id)?);
        drop(state);
        if sess.is_closed() || Instant::now() > sess.expires() {
            return None;
        }
        Some(sess)
    }

    /// `register`'s locked section.
    pub fn register(&self, id: &str, addresses: Vec<String>, client_ip: String) -> RegisterOutcome {
        let mut state = self.mu.lock();
        if state.realms.contains_key(id) {
            return RegisterOutcome::Taken;
        }
        if self.max_realms > 0 && state.realms.len() >= usize::try_from(self.max_realms).unwrap_or(usize::MAX) {
            return RegisterOutcome::RealmLimit;
        }
        let ip_count = state.ip_counts.get(&client_ip).copied().unwrap_or(0);
        if self.max_realms_per_ip > 0 && ip_count >= self.max_realms_per_ip {
            return RegisterOutcome::IpLimit;
        }
        let (events_tx, events_rx) = mpsc::channel(EVENTS_BUFFER_SIZE);
        let sess = Arc::new(Session {
            id: rand_token(),
            realm_id: id.to_owned(),
            client_ip: client_ip.clone(),
            inner: Mutex::new(SessionInner {
                addresses,
                expires: Instant::now() + SESSION_TTL,
                pending: HashMap::new(),
            }),
            events_rx: tokio::sync::Mutex::new(events_rx),
            events_tx,
            done: CancellationToken::new(),
            closed: AtomicBool::new(false),
        });
        state.realms.insert(id.to_owned(), Arc::clone(&sess));
        state.sessions.insert(sess.id.clone(), Arc::clone(&sess));
        *state.ip_counts.entry(client_ip).or_insert(0) += 1;
        drop(state);
        RegisterOutcome::Registered(sess)
    }

    pub fn remove_session(&self, sess: &Arc<Session>) {
        let mut state = self.mu.lock();
        Self::remove_session_locked(&mut state, sess);
    }

    fn remove_session_locked(state: &mut ServerState, sess: &Arc<Session>) {
        if !sess.mark_closed() {
            return;
        }
        sess.done.cancel();
        if state.realms.get(&sess.realm_id).is_some_and(|s| Arc::ptr_eq(s, sess)) {
            state.realms.remove(&sess.realm_id);
        }
        if state.sessions.contains_key(&sess.id) {
            let count = state.ip_counts.get_mut(&sess.client_ip);
            if let Some(count) = count {
                *count -= 1;
                if *count <= 0 {
                    state.ip_counts.remove(&sess.client_ip);
                }
            }
        }
        state.sessions.remove(&sess.id);
        sess.inner.lock().pending.clear();
    }

    pub fn remove_expired_session(&self, sess: &Arc<Session>, now: Instant) -> bool {
        let mut state = self.mu.lock();
        if sess.is_closed() || !now.gt(&sess.expires()) {
            return false;
        }
        Self::remove_session_locked(&mut state, sess);
        true
    }

    pub fn register_pending(
        &self,
        sess: &Arc<Session>,
        nonce: &str,
    ) -> Option<oneshot::Receiver<PunchResponsePayload>> {
        let mut inner = sess.inner.lock();
        if sess.is_closed() || inner.pending.len() >= MAX_PENDING_ATTEMPTS {
            return None;
        }
        if inner.pending.contains_key(nonce) {
            return None;
        }
        let (tx, rx) = oneshot::channel();
        inner.pending.insert(nonce.to_owned(), tx);
        drop(inner);
        Some(rx)
    }

    pub fn deliver_pending(&self, sess: &Arc<Session>, nonce: &str, payload: PunchResponsePayload) -> bool {
        let mut inner = sess.inner.lock();
        if sess.is_closed() {
            return false;
        }
        let Some(tx) = inner.pending.remove(nonce) else {
            return false;
        };
        drop(inner);
        let _ = tx.send(payload);
        true
    }

    pub fn cancel_pending(&self, sess: &Arc<Session>, nonce: &str) {
        sess.inner.lock().pending.remove(nonce);
    }

    pub fn send_event(&self, sess: &Arc<Session>, ev: SessionEvent) -> bool {
        if sess.is_closed() {
            return false;
        }
        sess.events_tx.try_send(ev).is_ok()
    }

    // cancel-safe: the loop only drops sessions that already expired, and no arm awaits inside its body.
    pub async fn reaper(self: Arc<Self>, ctx: CancellationToken) {
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + REAPER_INTERVAL, REAPER_INTERVAL);
        loop {
            tokio::select! {
                () = ctx.cancelled() => return,
                _ = ticker.tick() => {
                    let now = Instant::now();
                    let expired: Vec<Arc<Session>> = {
                        let state = self.mu.lock();
                        state.sessions.values().filter(|s| now > s.expires()).cloned().collect()
                    };
                    for sess in expired {
                        if self.remove_expired_session(&sess, now) {
                            murmur_log::debugln!("[RealmServer] session expired realm={} session={}", sess.realm_id, sess.id);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> Arc<Server> {
        Arc::new(new_server(ServerConfig {
            realm_token: "tok".into(),
            max_realms: 2,
            max_realms_per_ip: 1,
            ..Default::default()
        }))
    }

    fn register(server: &Server, id: &str, ip: &str) -> Arc<Session> {
        match server.register(id, vec!["192.0.2.1:4242".into()], ip.to_owned()) {
            RegisterOutcome::Registered(sess) => sess,
            RegisterOutcome::Taken | RegisterOutcome::RealmLimit | RegisterOutcome::IpLimit => {
                panic!("expected registration to succeed")
            }
        }
    }

    #[test]
    fn rand_token_is_32_hex_characters() {
        let token = rand_token();
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(rand_token(), token);
    }

    #[test]
    fn register_enforces_realm_and_per_ip_limits_and_release() {
        let server = server();
        let first = register(&server, "realm-a", "203.0.113.1");

        assert!(matches!(
            server.register("realm-a", vec!["192.0.2.1:1".into()], "203.0.113.2".into()),
            RegisterOutcome::Taken
        ));
        assert!(matches!(
            server.register("realm-b", vec!["192.0.2.1:1".into()], "203.0.113.1".into()),
            RegisterOutcome::IpLimit
        ));
        let second = register(&server, "realm-b", "203.0.113.2");
        assert!(matches!(
            server.register("realm-c", vec!["192.0.2.1:1".into()], "203.0.113.3".into()),
            RegisterOutcome::RealmLimit
        ));

        assert!(server.get_session_by_token(&first.id).is_some());
        server.remove_session(&first);
        assert!(server.get_session_by_token(&first.id).is_none());
        assert!(!server.deliver_pending(&first, "00", PunchResponsePayload { addresses: vec![] }));
        assert!(!server.send_event(&first, SessionEvent { kind: "x".into(), data: Value::Null }));
        let replacement = register(&server, "realm-a", "203.0.113.1");
        assert_ne!(replacement.id, second.id);
        assert!(server.get_session_by_token(&second.id).is_some());
    }

    #[test]
    fn session_expiry_is_reported_and_reaped_once() {
        let server = server();
        let sess = register(&server, "realm-a", "203.0.113.1");
        let future = Instant::now() + SESSION_TTL + Duration::from_secs(1);
        assert!(!server.remove_expired_session(&sess, Instant::now()));
        assert!(server.remove_expired_session(&sess, future));
        assert!(!server.remove_expired_session(&sess, future));
        assert!(server.get_session_by_token(&sess.id).is_none());
    }

    #[test]
    fn pending_attempts_are_capped_and_delivered_once() {
        let server = server();
        let sess = register(&server, "realm-a", "203.0.113.1");
        for i in 0..MAX_PENDING_ATTEMPTS {
            assert!(server.register_pending(&sess, &format!("{i:032x}")).is_some());
        }
        assert!(server.register_pending(&sess, &"f".repeat(32)).is_none());
        assert!(server.register_pending(&sess, &"0".repeat(32)).is_none(), "duplicate nonce is dropped");

        let nonce = "0".repeat(32);
        assert!(server.deliver_pending(
            &sess,
            &nonce,
            PunchResponsePayload { addresses: vec!["203.0.113.9:1".into()] }
        ));
        assert!(!server.deliver_pending(&sess, &nonce, PunchResponsePayload { addresses: vec![] }));
        server.cancel_pending(&sess, &nonce);
    }

    #[test]
    fn pending_receiver_observes_cancellation_and_session_removal() {
        let server = server();
        let sess = register(&server, "realm-a", "203.0.113.1");

        let cancelled = server.register_pending(&sess, &"1".repeat(32)).expect("pending attempt");
        server.cancel_pending(&sess, &"1".repeat(32));
        assert!(cancelled.blocking_recv().is_err());

        let removed = server.register_pending(&sess, &"2".repeat(32)).expect("pending attempt");
        server.remove_session(&sess);
        assert!(removed.blocking_recv().is_err());
    }

    #[test]
    fn pending_payload_reaches_the_waiter() {
        let server = server();
        let sess = register(&server, "realm-a", "203.0.113.1");
        let nonce = "a".repeat(32);
        let rx = server.register_pending(&sess, &nonce).expect("pending attempt");
        assert!(server.deliver_pending(
            &sess,
            &nonce,
            PunchResponsePayload { addresses: vec!["203.0.113.9:1".into()] }
        ));
        assert_eq!(rx.blocking_recv().expect("payload").addresses, vec!["203.0.113.9:1".to_owned()]);
    }

    #[test]
    fn events_buffer_overflows_only_past_capacity() {
        let server = server();
        let sess = register(&server, "realm-a", "203.0.113.1");
        for i in 0..EVENTS_BUFFER_SIZE {
            assert!(server.send_event(&sess, SessionEvent { kind: "punch".into(), data: Value::from(i as u64) }));
        }
        assert!(!server.send_event(&sess, SessionEvent { kind: "punch".into(), data: Value::Null }));
    }

    #[test]
    fn heartbeat_refreshes_expiry_and_addresses() {
        let server = server();
        let sess = register(&server, "realm-a", "203.0.113.1");
        let before = sess.expires();
        sess.touch(SESSION_TTL);
        sess.set_addresses(vec!["203.0.113.9:1".into()]);
        assert!(sess.expires() > before);
        assert_eq!(sess.addresses(), vec!["203.0.113.9:1".to_owned()]);
    }

    #[tokio::test]
    async fn reaper_removes_expired_sessions() {
        let server = server();
        let sess = register(&server, "realm-a", "203.0.113.1");
        sess.touch(Duration::ZERO);
        let ctx = CancellationToken::new();
        let handle = tokio::spawn(Arc::clone(&server).reaper(ctx.clone()));
        let deadline = tokio::time::Instant::now() + REAPER_INTERVAL * 5;
        while server.get_session_by_token(&sess.id).is_some() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        ctx.cancel();
        handle.await.expect("reaper task");
        assert!(server.get_session_by_token(&sess.id).is_none());
    }
}

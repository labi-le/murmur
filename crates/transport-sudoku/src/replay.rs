use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::{DateTime, TimeDelta, Utc};
use dashmap::DashMap;
use parking_lot::Mutex;

use super::kip::KIP_HELLO_NONCE_SIZE;

pub(crate) static HANDSHAKE_REPLAY_TTL: LazyLock<TimeDelta> = LazyLock::new(|| TimeDelta::seconds(60));

struct NonceSetInner {
    m: HashMap<[u8; KIP_HELLO_NONCE_SIZE], DateTime<Utc>>,
    last_prune: DateTime<Utc>,
}

pub(crate) struct NonceSet {
    inner: Mutex<NonceSetInner>,
    max_entries: usize,
}

impl NonceSet {
    pub(crate) fn new(max_entries: usize) -> Self {
        let max_entries = if max_entries == 0 { 4096 } else { max_entries };
        Self {
            inner: Mutex::new(NonceSetInner { m: HashMap::new(), last_prune: DateTime::<Utc>::UNIX_EPOCH }),
            max_entries,
        }
    }

    pub(crate) fn allow(&self, nonce: [u8; KIP_HELLO_NONCE_SIZE], now: DateTime<Utc>, ttl: TimeDelta) -> bool {
        let mut inner = self.inner.lock();
        let ttl = if ttl <= TimeDelta::zero() { TimeDelta::seconds(60) } else { ttl };

        if now - inner.last_prune > ttl / 2 || inner.m.len() > self.max_entries {
            inner.m.retain(|_, exp| now < *exp);
            inner.last_prune = now;
            while inner.m.len() > self.max_entries {
                if let Some(key) = inner.m.keys().next().copied() {
                    inner.m.remove(&key);
                } else {
                    break;
                }
            }
        }

        if let Some(exp) = inner.m.get(&nonce) {
            if now < *exp {
                return false;
            }
        }
        inner.m.insert(nonce, now + ttl);
        true
    }
}

pub(crate) struct HandshakeReplayProtector {
    users: DashMap<String, NonceSet>,
}

impl HandshakeReplayProtector {
    pub(crate) fn new() -> Self {
        Self { users: DashMap::new() }
    }

    pub(crate) fn allow(&self, user_hash: &str, nonce: [u8; KIP_HELLO_NONCE_SIZE], now: DateTime<Utc>) -> bool {
        let user_hash = if user_hash.is_empty() { "_" } else { user_hash };
        let set = self.users.entry(user_hash.to_owned()).or_insert_with(|| NonceSet::new(4096));
        set.allow(nonce, now, *HANDSHAKE_REPLAY_TTL)
    }
}

pub(crate) static GLOBAL_HANDSHAKE_REPLAY: LazyLock<HandshakeReplayProtector> =
    LazyLock::new(HandshakeReplayProtector::new);

pub(crate) type ReplayAllowFunc =
    std::sync::Arc<dyn Fn(&str, [u8; KIP_HELLO_NONCE_SIZE], DateTime<Utc>) -> bool + Send + Sync>;

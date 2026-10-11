use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::{DateTime, TimeDelta, Utc};
use dashmap::DashMap;
use parking_lot::Mutex;

use super::handshake_kip::KIP_HANDSHAKE_SKEW;
use super::kip::KIP_HELLO_NONCE_SIZE;

/// How long a client nonce stays remembered. The timestamp check accepts a hello up to
/// `KIP_HANDSHAKE_SKEW` either side of the server clock, so the memory has to outlast twice that
/// window (plus a margin) or a hello it still accepts finds its nonce forgotten.
pub(crate) static HANDSHAKE_REPLAY_TTL: LazyLock<TimeDelta> =
    LazyLock::new(|| TimeDelta::seconds(2 * KIP_HANDSHAKE_SKEW.num_seconds() + 30));

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
            inner.m.retain(|_, exp| now <= *exp);
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
            if now <= *exp {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_replay_memory_outlives_the_timestamp_window() {
        let window = 2 * KIP_HANDSHAKE_SKEW.num_seconds();
        assert!(
            HANDSHAKE_REPLAY_TTL.num_seconds() > window,
            "replay memory of {} s must outlast the {window}-second timestamp window",
            HANDSHAKE_REPLAY_TTL.num_seconds()
        );
    }

    #[test]
    fn nonce_set_rejects_a_replay_at_the_ttl_boundary() {
        let set = NonceSet::new(4096);
        let ttl = TimeDelta::seconds(60);
        let t0 = DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_000);
        let nonce = [7u8; KIP_HELLO_NONCE_SIZE];

        assert!(set.allow(nonce, t0, ttl), "first use must be allowed");
        assert!(!set.allow(nonce, t0, ttl), "an immediate replay must be rejected");
        assert!(!set.allow(nonce, t0 + ttl, ttl), "a replay at the TTL boundary must still be rejected");
        assert!(set.allow(nonce, t0 + ttl + TimeDelta::seconds(1), ttl), "a use past the TTL must be allowed");
    }

    #[test]
    fn pruning_at_the_ttl_boundary_keeps_the_nonce_remembered() {
        let set = NonceSet::new(4096);
        let ttl = TimeDelta::seconds(60);
        let t0 = DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(1_000);
        let nonce = [9u8; KIP_HELLO_NONCE_SIZE];
        let other = [10u8; KIP_HELLO_NONCE_SIZE];

        assert!(set.allow(nonce, t0, ttl), "first use must be allowed");
        // Pushes the prune past its interval with the boundary entry still in the map.
        assert!(set.allow(other, t0 + ttl, ttl), "unrelated nonce must be allowed");
        assert!(!set.allow(nonce, t0 + ttl, ttl), "a pruned entry at its expiry instant must still be rejected");
    }
}

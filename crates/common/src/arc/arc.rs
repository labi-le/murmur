use std::collections::HashMap;
use std::hash::Hash;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;

use super::entry::{Entry, EntryLists, ListId};

/// Part of the Functional Options Pattern.
pub type Option<K, V> = Box<dyn FnOnce(&mut ARC<K, V>)>;

#[must_use]
pub fn with_size<K, V>(max_size: i32) -> Option<K, V> {
    Box::new(move |a: &mut ARC<K, V>| {
        a.inner.get_mut().c = max_size;
    })
}

/// Holds the fields protected by `ARC`'s single lock.
#[derive(Debug)]
struct Inner<K, V> {
    p: i32,
    c: i32,
    lists: EntryLists<K, V>,
    len: i32,
    cache: HashMap<K, usize>,
}

#[derive(Debug)]
pub struct ARC<K, V> {
    inner: Mutex<Inner<K, V>>,
}

impl<K: Eq + Hash + Clone, V: Default> ARC<K, V> {
    /// Returns a new Adaptive Replacement Cache (ARC).
    #[must_use]
    pub fn new(options: Vec<Option<K, V>>) -> Self {
        let mut arc = Self {
            inner: Mutex::new(Inner { p: 0, c: 0, lists: EntryLists::default(), len: 0, cache: HashMap::new() }),
        };
        arc.clear();

        for option in options {
            option(&mut arc);
        }
        arc
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock();

        inner.p = 0;
        inner.lists = EntryLists::default();
        inner.len = 0;
        inner.cache = HashMap::new();
    }

    /// Inserts a new key-value pair into the cache.
    /// This optimizes future access to this entry (side effect).
    pub fn set(&self, key: K, value: V) {
        let mut inner = self.inner.lock();

        inner.set(key, value);
    }

    /// Stores any representation of a response for a given key and given expires.
    /// The expires time will round to second.
    pub fn set_with_expire(&self, key: K, value: V, expires: DateTime<Utc>) {
        let mut inner = self.inner.lock();

        inner.set_with_expire(key, value, expires);
    }

    /// Retrieves a previously via Set inserted entry.
    /// This optimizes future access to this entry (side effect).
    pub fn get(&self, key: &K) -> (V, bool)
    where
        V: Clone,
    {
        let mut inner = self.inner.lock();

        match inner.get(key) {
            Some(index) => (inner.lists.get(index).value.clone(), true),
            None => (V::default(), false),
        }
    }

    /// Returns any representation of a cached response, a `DateTime` giving the expected expires,
    /// and a bool set to true if the key was found.
    /// This method will NOT update the expires.
    pub fn get_with_expire(&self, key: &K) -> (V, core::option::Option<DateTime<Utc>>, bool)
    where
        V: Clone,
    {
        let mut inner = self.inner.lock();

        let Some(index) = inner.get(key) else {
            return (V::default(), None, false);
        };

        let entry = inner.lists.get(index);
        let expires = DateTime::from_timestamp(entry.expires, 0).unwrap_or(DateTime::<Utc>::MIN_UTC);
        let value = entry.value.clone();
        drop(inner);
        (value, Some(expires), true)
    }

    /// Determines the number of currently cached entries.
    /// This method is side-effect free in the sense that it does not attempt to optimize random
    /// cache access.
    pub fn len(&self) -> i32 {
        let inner = self.inner.lock();

        inner.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<K: Eq + Hash + Clone, V: Default> Inner<K, V> {
    fn set(&mut self, key: K, value: V) {
        self.set_with_expire(key, value, DateTime::UNIX_EPOCH);
    }

    fn set_with_expire(&mut self, key: K, value: V, expires: DateTime<Utc>) {
        let found = self.cache.get(&key).copied();
        if let Some(index) = found {
            if self.lists.get(index).ghost {
                self.len += 1;
            }

            let entry = self.lists.get_mut(index);
            entry.value = value;
            entry.ghost = false;
            entry.expires = expires.timestamp();
            self.req(index);
            return;
        }

        self.len += 1;
        let entry = Entry::new(key.clone(), value, false, expires.timestamp());
        let index = self.lists.alloc(entry);
        self.req(index);
        self.cache.insert(key, index);
    }

    fn get(&mut self, key: &K) -> core::option::Option<usize> {
        let index = *self.cache.get(key)?;
        self.req(index);
        if self.lists.get(index).ghost {
            None
        } else {
            Some(index)
        }
    }

    fn req(&mut self, index: usize) {
        let ll = self.lists.get(index).ll;
        if ll == Some(ListId::T1) || ll == Some(ListId::T2) {
            // Case I
            self.lists.set_mru(index, ListId::T2);
        } else if ll == Some(ListId::B1) {
            // Case II
            // Cache miss in t1 and t2

            // Adaptation
            let d = if self.lists.list_len(ListId::B1) >= self.lists.list_len(ListId::B2) {
                1
            } else {
                self.lists.list_len(ListId::B2) / self.lists.list_len(ListId::B1)
            };
            self.p = (self.p + d).min(self.c);

            self.replace(index);
            self.lists.set_mru(index, ListId::T2);
        } else if ll == Some(ListId::B2) {
            // Case III
            // Cache miss in t1 and t2

            // Adaptation
            let d = if self.lists.list_len(ListId::B2) >= self.lists.list_len(ListId::B1) {
                1
            } else {
                self.lists.list_len(ListId::B1) / self.lists.list_len(ListId::B2)
            };
            self.p = (self.p - d).max(0);

            self.replace(index);
            self.lists.set_mru(index, ListId::T2);
        } else if ll.is_none() && self.lists.list_len(ListId::T1) + self.lists.list_len(ListId::B1) == self.c {
            // Case IV A
            if self.lists.list_len(ListId::T1) < self.c {
                self.del_lru(ListId::B1);
                self.replace(index);
            } else {
                self.del_lru(ListId::T1);
            }
            self.lists.set_mru(index, ListId::T1);
        } else if ll.is_none() && self.lists.list_len(ListId::T1) + self.lists.list_len(ListId::B1) < self.c {
            // Case IV B
            if self.lists.list_len(ListId::T1)
                + self.lists.list_len(ListId::T2)
                + self.lists.list_len(ListId::B1)
                + self.lists.list_len(ListId::B2)
                >= self.c
            {
                if self.lists.list_len(ListId::T1)
                    + self.lists.list_len(ListId::T2)
                    + self.lists.list_len(ListId::B1)
                    + self.lists.list_len(ListId::B2)
                    == 2 * self.c
                {
                    self.del_lru(ListId::B2);
                }
                self.replace(index);
            }
            self.lists.set_mru(index, ListId::T1);
        } else if ll.is_none() {
            // Case IV, not A nor B
            self.lists.set_mru(index, ListId::T1);
        }
    }

    #[expect(clippy::expect_used, reason = "every caller evicts only from a list it has just measured as non-empty")]
    fn del_lru(&mut self, list: ListId) {
        let index = self.lists.pop_back(list).expect("the evicted list is non-empty");
        let lru = self.lists.take(index);
        if !lru.ghost {
            self.len -= 1;
        }
        self.cache.remove(&lru.key);
    }

    #[expect(
        clippy::expect_used,
        reason = "the T1 arm is length-guarded; |T1| + |T2| <= c with the guards in `req` holds T2"
    )]
    fn replace(&mut self, index: usize) {
        let ll = self.lists.get(index).ll;
        if self.lists.list_len(ListId::T1) > 0
            && (self.lists.list_len(ListId::T1) > self.p
                || (ll == Some(ListId::B2) && self.lists.list_len(ListId::T1) == self.p))
        {
            let lru = self.lists.list_back(ListId::T1).expect("t1 is non-empty");
            self.ghost(lru, ListId::B1);
        } else {
            let lru = self.lists.list_back(ListId::T2).expect("t2 is non-empty");
            self.ghost(lru, ListId::B2);
        }
    }

    /// Displaces `index` into the ghost list `id`. `T2` can hold a ghost, which a `get` promoted
    /// out of `B1`/`B2`, and such an entry is already uncounted, so only a live one decrements.
    fn ghost(&mut self, index: usize, id: ListId) {
        let entry = self.lists.get_mut(index);
        entry.value = V::default();
        if !entry.ghost {
            entry.ghost = true;
            self.len -= 1;
        }
        self.lists.set_mru(index, id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insertion() {
        let cache = ARC::<String, String>::new(vec![with_size(3)]);
        assert_eq!(cache.len(), 0);

        const K1: &str = "Hello";
        const K2: &str = "Hallo";
        const K3: &str = "Ciao";
        const K4: &str = "Salut";

        const V1: &str = "World";
        const V2: &str = "Worlds";
        const V3: &str = "Welt";

        // Insert the first value
        cache.set(K1.to_owned(), V1.to_owned());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&K1.to_owned()), (V1.to_owned(), true));

        // Replace existing value for a given key
        cache.set(K1.to_owned(), V2.to_owned());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&K1.to_owned()), (V2.to_owned(), true));

        // Add a second different key
        cache.set(K2.to_owned(), V3.to_owned());
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&K1.to_owned()), (V2.to_owned(), true));
        assert_eq!(cache.get(&K2.to_owned()), (V3.to_owned(), true));

        // Fill cache
        cache.set(K3.to_owned(), V1.to_owned());
        assert_eq!(cache.len(), 3);

        // Exceed size, this should not exceed size:
        cache.set(K4.to_owned(), V1.to_owned());
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_eviction() {
        let size: i32 = 3;
        let cache = ARC::<String, String>::new(vec![with_size(size)]);
        assert_eq!(cache.len(), 0);

        let tests = [("k1", "v1"), ("k2", "v2"), ("k3", "v3"), ("k4", "v4")];
        for (i, (k, v)) in tests[..size as usize].iter().enumerate() {
            cache.set(k.to_string(), v.to_string());
            assert_eq!(cache.len(), i as i32 + 1);
        }

        // Exceed size and check we don't outgrow it:
        cache.set(tests[size as usize].0.to_owned(), tests[size as usize].1.to_owned());
        assert_eq!(cache.len(), size);

        // Check that LRU got evicted:
        assert_eq!(cache.get(&tests[0].0.to_owned()), (String::new(), false));

        for (k, v) in &tests[1..] {
            assert_eq!(cache.get(&k.to_string()), (v.to_string(), true));
        }
    }

    #[test]
    fn len_does_not_drift_negative_after_a_ghost_hit() {
        let cache = ARC::<i32, i32>::new(vec![with_size(1)]);
        cache.set(0, 0);
        cache.get(&0); // promote 0 into T2
        cache.set(1, 1); // 0 becomes a ghost in B2, 1 is live in T1
        assert_eq!(cache.len(), 1);
        cache.get(&0); // B2 -> T2, still a ghost; 1 becomes a ghost in B1
        assert_eq!(cache.len(), 0);
        cache.get(&1); // B1 -> T2; the replace ghosts the already-ghost 0
        assert_eq!(cache.len(), 0, "no live entry remains");
        assert!(cache.is_empty());
    }

    #[test]
    fn len_does_not_uncount_the_ghost_a_ghost_list_eviction_drops() {
        let cache = ARC::<i32, i32>::new(vec![with_size(1)]);
        cache.set(0, 0);
        cache.set(0, 0);
        cache.set(3, 3);
        cache.get(&0); // 0 is a ghost in B2; 3 is displaced out of T1 into B1
        cache.set(2, 2); // case IV A deletes the ghost 3 out of B1, then replaces

        assert_eq!(cache.len(), 1, "key 2 is the one live entry");
        assert_eq!(cache.get(&2), (2, true));
        assert!(!cache.is_empty());
    }

    #[test]
    fn len_stays_within_the_live_range_across_random_get_set_sequences() {
        use rand::{Rng, SeedableRng};

        const CAPACITY: i32 = 4;

        for seed in 0..64_u64 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let cache = ARC::<i32, i32>::new(vec![with_size(CAPACITY)]);

            for step in 0..500 {
                let key = rng.random_range(0..8);
                if rng.random_bool(0.5) {
                    cache.set(key, key);
                } else {
                    cache.get(&key);
                }

                let len = cache.len();
                assert!((0..=CAPACITY).contains(&len), "seed {seed} step {step}: len()={len} leaves 0..={CAPACITY}");
                assert_eq!(cache.is_empty(), len == 0, "seed {seed} step {step}: is_empty disagrees with len");
            }
        }
    }
}

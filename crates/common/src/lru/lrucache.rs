use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::hash::Hash;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;

/// A functional option applied to a cache under construction. Renamed
/// so it does not shadow Rust's `Option` in this module.
pub type LruOption<K, V> = Box<dyn FnOnce(&mut LruCache<K, V>)>;

/// Called with the key and value of an evicted entry.
pub type EvictCallback<K, V> = Box<dyn Fn(K, V) + Send + Sync>;

/// Sets the evict callback.
#[must_use]
pub fn with_evict<K: 'static, V: 'static>(cb: EvictCallback<K, V>) -> LruOption<K, V> {
    Box::new(move |l| l.on_evict = Some(cb))
}

/// Updates expires when Get element.
#[must_use]
pub fn with_update_age_on_get<K, V>() -> LruOption<K, V> {
    Box::new(|l| l.update_age_on_get = true)
}

/// Defines element max age (second).
#[must_use]
pub fn with_age<K, V>(max_age: i64) -> LruOption<K, V> {
    Box::new(move |l| l.max_age = max_age)
}

/// Defines max length of `LruCache`.
#[must_use]
pub fn with_size<K, V>(max_size: usize) -> LruOption<K, V> {
    Box::new(move |l| l.max_size = max_size)
}

/// Decides whether Stale return is enabled. If this feature is enabled, element will not get
/// Evicted on age.
#[must_use]
pub fn with_stale<K, V>(stale: bool) -> LruOption<K, V> {
    Box::new(move |l| l.stale_return = stale)
}

/// A thread-safe, in-memory lru-cache that evicts the least recently used entries from memory
/// when (if set) the entries are older than maxAge (in seconds). Use the `new` constructor to
/// create one.
pub struct LruCache<K, V> {
    max_age: i64,
    max_size: usize,
    update_age_on_get: bool,
    stale_return: bool,
    on_evict: Option<EvictCallback<K, V>>,
    mu: Mutex<Cache<K, V>>,
}

/// The `cache` map and `lru` list, guarded by the cache's `mu`; element handles are slots of
/// the arena-backed list since Rust has no list-element pointer to keep in the map.
#[derive(Debug)]
pub(crate) struct Cache<K, V> {
    cache: HashMap<K, usize>,
    lru: List<K, V>,
}

/// One entry. `key` is read-only once built, so only `value` and `expires` need
/// interior mutability: `clone_to` shares entries between two caches, each holding its own mutex.
#[derive(Debug)]
pub(crate) struct Entry<K, V> {
    key: K,
    value: Mutex<V>,
    expires: AtomicI64,
}

impl<K, V> Entry<K, V> {
    const fn new(key: K, value: V, expires: i64) -> Self {
        Self { key, value: Mutex::new(value), expires: AtomicI64::new(expires) }
    }

    fn expires(&self) -> i64 {
        self.expires.load(Ordering::SeqCst)
    }

    fn set_expires(&self, expires: i64) {
        self.expires.store(expires, Ordering::SeqCst);
    }

    fn read_value(&self) -> V
    where
        V: Clone,
    {
        self.value.lock().clone()
    }

    fn set_value(&self, value: V) {
        *self.value.lock() = value;
    }
}

/// A generic doubly linked list whose element handle is a slot index rather than a pointer.
#[derive(Debug)]
pub(crate) struct List<K, V> {
    nodes: Vec<Option<Node<K, V>>>,
    free: Vec<usize>,
    front: Option<usize>,
    back: Option<usize>,
    len: usize,
}

#[derive(Debug)]
struct Node<K, V> {
    entry: Arc<Entry<K, V>>,
    prev: Option<usize>,
    next: Option<usize>,
}

impl<K, V> List<K, V> {
    const fn new() -> Self {
        Self { nodes: Vec::new(), free: Vec::new(), front: None, back: None, len: 0 }
    }

    const fn len(&self) -> usize {
        self.len
    }

    const fn front(&self) -> Option<usize> {
        self.front
    }

    fn next(&self, index: usize) -> Option<usize> {
        self.node(index).next
    }

    fn entry(&self, index: usize) -> &Arc<Entry<K, V>> {
        &self.node(index).entry
    }

    fn push_back(&mut self, entry: Arc<Entry<K, V>>) -> usize {
        let index = self.alloc(Node { entry, prev: None, next: None });
        self.link_back(index);
        index
    }

    fn move_to_back(&mut self, index: usize) {
        self.unlink(index);
        self.link_back(index);
    }

    #[expect(clippy::expect_used, reason = "a removed list handle refers to a live node until it is unlinked")]
    fn remove(&mut self, index: usize) -> Arc<Entry<K, V>> {
        self.unlink(index);
        let node = self.nodes.get_mut(index).and_then(Option::take).expect("removed lru handle refers to a live node");
        self.free.push(index);
        node.entry
    }

    #[expect(
        clippy::expect_used,
        reason = "a list handle is only ever handed out by `alloc`, which leaves a live node at it"
    )]
    fn node(&self, index: usize) -> &Node<K, V> {
        self.nodes.get(index).and_then(Option::as_ref).expect("lru list handle refers to a live node")
    }

    #[expect(
        clippy::expect_used,
        reason = "a list handle is only ever handed out by `alloc`, which leaves a live node at it"
    )]
    fn node_mut(&mut self, index: usize) -> &mut Node<K, V> {
        self.nodes.get_mut(index).and_then(Option::as_mut).expect("lru list handle refers to a live node")
    }

    fn alloc(&mut self, node: Node<K, V>) -> usize {
        if let Some(index) = self.free.pop() {
            if let Some(slot) = self.nodes.get_mut(index) {
                *slot = Some(node);
            }
            index
        } else {
            self.nodes.push(Some(node));
            self.nodes.len() - 1
        }
    }

    fn link_back(&mut self, index: usize) {
        let back = self.back;
        {
            let node = self.node_mut(index);
            node.prev = back;
            node.next = None;
        }
        match back {
            Some(back) => self.node_mut(back).next = Some(index),
            None => self.front = Some(index),
        }
        self.back = Some(index);
        self.len += 1;
    }

    fn unlink(&mut self, index: usize) {
        let (prev, next) = {
            let node = self.node(index);
            (node.prev, node.next)
        };
        match prev {
            Some(prev) => self.node_mut(prev).next = next,
            None => self.front = next,
        }
        match next {
            Some(next) => self.node_mut(next).prev = prev,
            None => self.back = prev,
        }
        let node = self.node_mut(index);
        node.prev = None;
        node.next = None;
        self.len -= 1;
    }
}

impl<K, V> Debug for LruCache<K, V>
where
    K: Debug,
    V: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let state = self.mu.lock();
        f.debug_struct("LruCache")
            .field("max_age", &self.max_age)
            .field("max_size", &self.max_size)
            .field("cache", &state.cache)
            .field("lru", &state.lru)
            .field("update_age_on_get", &self.update_age_on_get)
            .field("stale_return", &self.stale_return)
            .field("on_evict", &self.on_evict.is_some())
            .finish()
    }
}

/// creates an `LruCache`.
#[must_use]
pub fn new<K: Eq + Hash + Clone, V: Clone>(options: Vec<LruOption<K, V>>) -> LruCache<K, V> {
    let mut lc = LruCache {
        max_age: 0,
        max_size: 0,
        update_age_on_get: false,
        stale_return: false,
        on_evict: None,
        mu: Mutex::new(Cache { cache: HashMap::new(), lru: List::new() }),
    };
    lc.clear();

    for option in options {
        option(&mut lc);
    }

    lc
}

impl<K: Eq + Hash + Clone, V: Clone> LruCache<K, V> {
    pub fn clear(&self) {
        let mut state = self.mu.lock();

        state.lru = List::new();
        state.cache = HashMap::new();
    }

    /// Returns any representation of a cached response and a bool set to true if the key was
    /// found.
    pub fn get<Q>(&self, key: &Q) -> (V, bool)
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        V: Default,
    {
        let mut state = self.mu.lock();

        match self.get_locked(&mut state, key) {
            None => (V::default(), false),
            Some(index) => (state.lru.entry(index).read_value(), true),
        }
    }

    /// Applies [`Self::get`]'s expiry and recency effects without reading the stored value.
    pub fn touch<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let mut state = self.mu.lock();

        self.get_locked(&mut state, key).is_some()
    }

    pub fn get_or_store(&self, key: K, constructor: impl FnOnce() -> V) -> (V, bool) {
        let mut state = self.mu.lock();

        match self.get_locked(&mut state, &key) {
            None => {
                let value = constructor();
                self.set_locked(&mut state, key, value.clone());
                (value, false)
            }
            Some(index) => (state.lru.entry(index).read_value(), true),
        }
    }

    /// Returns any representation of a cached response, the expected expires, and a bool set to
    /// true if the key was found. An entry past `max_age` is absent (`None`, `false`) and is
    /// removed, unless `with_stale(true)` is set; its expiry is extended when
    /// `with_update_age_on_get` is set.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the API takes the key by value; `&K` would change the public signature"
    )]
    pub fn get_with_expire(&self, key: K) -> (V, Option<DateTime<Utc>>, bool)
    where
        V: Default,
    {
        let mut state = self.mu.lock();

        match self.get_locked(&mut state, &key) {
            None => (V::default(), None, false),
            Some(index) => {
                let entry = Arc::clone(state.lru.entry(index));
                drop(state);
                (entry.read_value(), Some(unix_time(entry.expires())), true)
            }
        }
    }

    /// Returns if key exist in cache but not put item to the head of linked list.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the API takes the key by value; `&K` would change the public signature"
    )]
    pub fn exist(&self, key: K) -> bool {
        let state = self.mu.lock();

        state.cache.contains_key(&key)
    }

    /// Stores any representation of a response for a given key.
    pub fn set(&self, key: K, value: V) {
        let mut state = self.mu.lock();

        self.set_locked(&mut state, key, value);
    }

    pub(crate) fn set_locked(&self, state: &mut Cache<K, V>, key: K, value: V) {
        let expires = if self.max_age > 0 { now_unix() + self.max_age } else { 0 };
        self.set_with_expire_locked(state, key, value, expires);
    }

    /// Stores any representation of a response for a given key and given expires. The expires
    /// time will round to second.
    pub fn set_with_expire(&self, key: K, value: V, expires: DateTime<Utc>) {
        let mut state = self.mu.lock();

        self.set_with_expire_locked(&mut state, key, value, expires.timestamp());
    }

    #[expect(clippy::expect_used, reason = "the list overflowed max_size, so it is non-empty")]
    pub(crate) fn set_with_expire_locked(&self, state: &mut Cache<K, V>, key: K, value: V, expires: i64) {
        if let Some(index) = state.cache.get(&key).copied() {
            state.lru.move_to_back(index);
            let entry = state.lru.entry(index);
            entry.set_value(value);
            entry.set_expires(expires);
        } else {
            let entry = Arc::new(Entry::new(key.clone(), value, expires));
            let index = state.lru.push_back(entry);
            state.cache.insert(key, index);

            if self.max_size > 0 && state.lru.len() > self.max_size {
                let oldest = state.lru.front().expect("the list is non-empty");
                self.delete_element(state, oldest);
            }
        }

        self.maybe_delete_oldest(state);
    }

    /// Clones and overwrites elements to another `LruCache`.
    pub fn clone_to(&self, n: &Self) {
        let state = self.mu.lock();
        let mut target = n.mu.lock();

        target.lru = List::new();
        target.cache = HashMap::new();

        let mut cursor = state.lru.front();
        while let Some(index) = cursor {
            let entry = state.lru.entry(index);
            let pushed = target.lru.push_back(Arc::clone(entry));
            target.cache.insert(entry.key.clone(), pushed);
            cursor = state.lru.next(index);
        }
        drop(state);
        drop(target);
    }

    pub(crate) fn get_locked<Q>(&self, state: &mut Cache<K, V>, key: &Q) -> Option<usize>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let index = state.cache.get(key).copied()?;

        if !self.stale_return && self.max_age > 0 && state.lru.entry(index).expires() <= now_unix() {
            self.delete_element(state, index);
            self.maybe_delete_oldest(state);

            return None;
        }

        state.lru.move_to_back(index);
        if self.max_age > 0 && self.update_age_on_get {
            state.lru.entry(index).set_expires(now_unix() + self.max_age);
        }
        Some(index)
    }

    /// Removes the value associated with a key.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the API takes the key by value; `&K` would change the public signature"
    )]
    pub fn delete(&self, key: K) {
        let mut state = self.mu.lock();

        self.delete_locked(&mut state, &key);
    }

    pub(crate) fn delete_locked(&self, state: &mut Cache<K, V>, key: &K) {
        if let Some(index) = state.cache.get(key).copied() {
            self.delete_element(state, index);
        }
    }

    pub(crate) fn maybe_delete_oldest(&self, state: &mut Cache<K, V>) {
        if !self.stale_return && self.max_age > 0 {
            let now = now_unix();
            while let Some(index) = state.lru.front() {
                if state.lru.entry(index).expires() > now {
                    break;
                }
                self.delete_element(state, index);
            }
        }
    }

    pub(crate) fn delete_element(&self, state: &mut Cache<K, V>, index: usize) {
        let entry = state.lru.remove(index);
        state.cache.remove(&entry.key);
        if let Some(on_evict) = &self.on_evict {
            on_evict(entry.key.clone(), entry.read_value());
        }
    }

    /// Either sets the computed new value for the key or deletes the value for the key. When the
    /// delete result of the valueFn function is set to true, the value will be deleted, if it
    /// exists. When delete is set to false, the value is updated to the newValue. The ok result
    /// indicates whether value was computed and stored, thus, is present in the map. The actual
    /// result contains the new value in cases where the value was computed and stored.
    pub fn compute(&self, key: K, value_fn: impl FnOnce(V, bool) -> (V, bool)) -> (V, bool)
    where
        V: Default,
    {
        let mut state = self.mu.lock();

        let (actual, ok) = match self.get_locked(&mut state, &key) {
            Some(index) => (state.lru.entry(index).read_value(), true),
            None => (V::default(), false),
        };
        let (new_value, delete) = value_fn(actual, ok);
        let result = if delete {
            if ok {
                self.delete_locked(&mut state, &key);
            }
            (V::default(), false)
        } else {
            self.set_locked(&mut state, key, new_value.clone());
            (new_value, true)
        };
        drop(state);
        result
    }
}

fn now_unix() -> i64 {
    Utc::now().timestamp()
}

/// A second count outside chrono's range collapses to the zero time.
fn unix_time(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).unwrap_or(DateTime::<Utc>::MIN_UTC)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicI32;

    use super::*;

    const ENTRIES: [(&str, &str); 5] = [("1", "one"), ("2", "two"), ("3", "three"), ("4", "four"), ("5", "five")];

    fn back_entry<K, V>(c: &LruCache<K, V>) -> Arc<Entry<K, V>> {
        let state = c.mu.lock();
        let index = state.lru.back.expect("the test cache holds an element");
        Arc::clone(state.lru.entry(index))
    }

    fn cached_entry<K: Eq + Hash, V>(c: &LruCache<K, V>, key: &K) -> Arc<Entry<K, V>> {
        let state = c.mu.lock();
        let index = state.cache.get(key).copied().expect("the test key is cached");
        Arc::clone(state.lru.entry(index))
    }

    fn lru_len<K, V>(c: &LruCache<K, V>) -> usize {
        c.mu.lock().lru.len()
    }

    #[test]
    fn test_lru_cache() {
        let c = new::<String, String>(Vec::new());

        for (key, value) in ENTRIES {
            c.set(key.to_owned(), value.to_owned());
        }

        c.delete("missing".to_owned());
        let (_, ok) = c.get("missing");
        assert!(!ok);

        for (key, value) in ENTRIES {
            let (got, ok) = c.get(key);
            assert!(ok);
            assert_eq!(got, value);
        }

        for (key, _) in ENTRIES {
            c.delete(key.to_owned());

            let (_, ok) = c.get(key);
            assert!(!ok);
        }
    }

    #[test]
    fn test_lru_max_age() {
        let c = new::<String, String>(vec![with_age(86400)]);

        let now = now_unix();
        let expected = now + 86400;

        // Add one expired entry
        c.set("foo".to_owned(), "bar".to_owned());
        back_entry(&c).set_expires(now);

        // Reset
        c.set("foo".to_owned(), "bar".to_owned());
        let e = back_entry(&c);
        assert!(e.expires() >= now);
        e.set_expires(now);

        // Set a few and verify expiration times
        for (key, value) in ENTRIES {
            c.set(key.to_owned(), value.to_owned());
            let e = back_entry(&c);
            assert!(e.expires() >= expected && e.expires() <= expected + 10);
        }

        // Make sure we can get them all
        for (key, _) in ENTRIES {
            let (_, ok) = c.get(key);
            assert!(ok);
        }

        // Expire all entries
        for (key, _) in ENTRIES {
            cached_entry(&c, &key.to_owned()).set_expires(now);
        }

        // Get one expired entry, which should clear all expired entries
        let (_, ok) = c.get("3");
        assert!(!ok);
        assert_eq!(lru_len(&c), 0);
    }

    #[test]
    fn test_lr_update_on_get() {
        let c = new::<String, String>(vec![with_age(86400), with_update_age_on_get()]);

        let now = now_unix();
        let expires = now + 86400 / 2;

        // Add one expired entry
        c.set("foo".to_owned(), "bar".to_owned());
        back_entry(&c).set_expires(expires);

        let (_, ok) = c.get("foo");
        assert!(ok);
        assert!(back_entry(&c).expires() > expires);
    }

    #[test]
    fn test_max_size() {
        let c = new::<String, String>(vec![with_size(2)]);
        // Add one expired entry
        c.set("foo".to_owned(), "bar".to_owned());
        let (_, ok) = c.get("foo");
        assert!(ok);

        c.set("bar".to_owned(), "foo".to_owned());
        c.set("baz".to_owned(), "foo".to_owned());

        let (_, ok) = c.get("foo");
        assert!(!ok);
    }

    #[test]
    fn test_get_borrowed_key() {
        let c = new::<String, String>(vec![with_size(2)]);
        c.set("a".to_owned(), "1".to_owned());
        c.set("b".to_owned(), "2".to_owned());

        let (value, ok) = c.get("a");
        assert!(ok);
        assert_eq!(value, "1");

        c.set("c".to_owned(), "3".to_owned());
        assert!(!c.get("b").1);
        assert!(c.get("a").1);
        assert!(!c.get("missing").1);
    }

    #[test]
    fn test_get_borrowed_expiry() {
        let c = new::<String, String>(vec![with_age(86400)]);
        c.set("foo".to_owned(), "bar".to_owned());
        cached_entry(&c, &"foo".to_owned()).set_expires(now_unix());

        assert!(!c.get("foo").1);
        assert_eq!(lru_len(&c), 0);
    }

    #[test]
    fn test_touch() {
        let c = new::<String, i32>(vec![with_size(2)]);
        c.set("a".to_owned(), 1);
        c.set("b".to_owned(), 2);

        assert!(c.touch("a"));
        assert!(!c.touch("missing"));

        c.set("c".to_owned(), 3);
        assert!(!c.get("b").1);
        assert!(c.get("a").1);
    }

    #[test]
    fn test_touch_expired() {
        let c = new::<String, i32>(vec![with_age(86400)]);
        c.set("a".to_owned(), 1);
        cached_entry(&c, &"a".to_owned()).set_expires(now_unix());

        assert!(!c.touch("a"));
        assert_eq!(lru_len(&c), 0);
    }

    #[test]
    fn test_exist() {
        let c = new::<i32, i32>(vec![with_size(1)]);
        c.set(1, 2);
        assert!(c.exist(1));
        c.set(2, 3);
        assert!(!c.exist(1));
    }

    #[test]
    fn test_evict() {
        let temp = Arc::new(AtomicI32::new(0));
        let evict_temp = Arc::clone(&temp);
        let evict = move |key: i32, value: i32| {
            evict_temp.store(key + value, Ordering::SeqCst);
        };

        let c = new::<i32, i32>(vec![with_evict(Box::new(evict)), with_size(1)]);
        c.set(1, 2);
        c.set(2, 3);

        assert_eq!(temp.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_set_with_expire() {
        let c = new::<i32, Option<Arc<()>>>(vec![with_age(1)]);
        let now = now_unix();

        let ten_sec_before = unix_time(now - 10);
        c.set_with_expire(1, Some(Arc::new(())), ten_sec_before);

        let (res, expires, exist) = c.get_with_expire(1);

        assert!(res.is_none());
        assert_eq!(None, expires);
        assert!(!exist);
    }

    #[test]
    fn get_with_expire_checks_and_extends_the_expiry_it_reports() {
        let c = new::<String, String>(vec![with_age(86400), with_update_age_on_get()]);

        c.set("foo".to_owned(), "bar".to_owned());
        let stale = now_unix() + 1;
        cached_entry(&c, &"foo".to_owned()).set_expires(stale);

        let (value, expires, ok) = c.get_with_expire("foo".to_owned());
        assert!(ok);
        assert_eq!(value, "bar");
        assert!(expires.expect("a live entry reports its expiry").timestamp() > stale);

        cached_entry(&c, &"foo".to_owned()).set_expires(now_unix() - 1);
        let (value, expires, ok) = c.get_with_expire("foo".to_owned());
        assert!(!ok);
        assert_eq!(value, "");
        assert_eq!(expires, None);
        assert_eq!(lru_len(&c), 0);
    }

    #[test]
    fn test_stale() {
        let c = new::<i32, i32>(vec![with_age(1), with_stale(true)]);
        let now = now_unix();

        let ten_sec_before = unix_time(now - 10);
        c.set_with_expire(1, 2, ten_sec_before);

        let (res, expires, exist) = c.get_with_expire(1);
        assert_eq!(2, res);
        assert_eq!(Some(ten_sec_before), expires);
        assert!(exist);
    }

    #[test]
    fn cloned_entries_keep_shared_updates_and_survive_source_eviction() {
        let source = new::<String, i32>(vec![with_size(1)]);
        let target = new::<String, i32>(vec![with_size(1)]);
        source.set("shared".to_owned(), 1);
        source.clone_to(&target);

        source.set("shared".to_owned(), 2);
        assert_eq!(target.get("shared"), (2, true));

        source.set("replacement".to_owned(), 3);
        assert_eq!(source.get("shared"), (0, false));
        assert_eq!(source.get("replacement"), (3, true));
        assert_eq!(target.get("shared"), (2, true));
    }

    #[test]
    fn test_clone_to() {
        let o = new::<String, i32>(vec![with_size(10)]);
        o.set("1".to_owned(), 1);
        o.set("2".to_owned(), 2);

        let n = new::<String, i32>(vec![with_size(2)]);
        n.set("3".to_owned(), 3);
        n.set("4".to_owned(), 4);

        o.clone_to(&n);

        assert!(!n.exist("3".to_owned()));
        assert!(n.exist("1".to_owned()));

        n.set("5".to_owned(), 5);
        assert!(!n.exist("1".to_owned()));
    }
}

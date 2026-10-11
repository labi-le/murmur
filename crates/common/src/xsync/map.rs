//!
//! A concurrent map, licensed under Apache v2.
//!
//! Notable properties:
//! 1. a compute-or-store api.
//! 2. a zero Map is usable as-is.
//! 3. no extra member variables are kept to optimize integer keys.
//!
//! The CLHT layout is kept — cache-line buckets with up to five entries each, chained overflow
//! buckets, SWAR metadata, per-chain locking, striped size counters and the cooperative
//! grow/shrink/clear resize. Raw bucket and entry pointers are never loaded or stored atomically
//! here; `ArcSwapOption` table publication and `Arc` entries stand in their place, and a root
//! bucket is guarded together with its chained buckets by one `parking_lot::Mutex`, so the
//! readers take the chain lock rather than staying lock-free.

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Once};

use arc_swap::ArcSwapOption;
use parking_lot::{Condvar, Mutex};

use rand::random;

// number of Map entries per bucket; 5 entries lead to size of 64B
// (one cache line) on 64-bit machines
const ENTRIES_PER_MAP_BUCKET: usize = 5;
// threshold fraction of table occupation to start a table shrinking
// when deleting the last entry in a bucket chain
const MAP_SHRINK_FRACTION: usize = 128;
// map load factor to trigger a table resize during insertion;
// a map holds up to mapLoadFactor*entriesPerMapBucket*mapTableLen
// key-value pairs (this is a soft limit)
const MAP_LOAD_FACTOR: f64 = 0.75;
// minimal table size, i.e. number of buckets; thus, minimal map
// capacity can be calculated as entriesPerMapBucket*defaultMinMapTableLen
const DEFAULT_MIN_MAP_TABLE_LEN: usize = 32;
// minimum counter stripes to use
const MIN_MAP_COUNTER_LEN: usize = 8;
// maximum counter stripes to use; stands for around 4KB of memory
const MAX_MAP_COUNTER_LEN: usize = 32;
const META_MASK: u64 = 0xffffffffff;
const OCCUPIED_META: u64 = 0x8080808080808080;
const OCCUPIED_META_MASKED: u64 = OCCUPIED_META & META_MASK;
// minimal number of buckets to transfer when participating in cooperative
// resize; should be at least defaultMinMapTableLen
const MIN_RESIZE_TRANSFER_STRIDE: usize = 64;
// upper limit for max number of additional tasks that participate
// in cooperative resize; must be changed simultaneously with resizeCtl
// and the related code
const MAX_RESIZE_HELPERS_LIMIT: u64 = (1 << 5) - 1;

// max number of additional tasks that participate in cooperative resize;
// "resize owner" task isn't counted
pub(crate) static MAX_RESIZE_HELPERS: LazyLock<i32> = LazyLock::new(|| {
    let limit = i32::try_from(MAX_RESIZE_HELPERS_LIMIT).unwrap_or(i32::MAX);
    let helpers = parallelism().cast_signed().saturating_sub(1);
    helpers.clamp(1, limit)
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MapResizeHint {
    Grow,
    Shrink,
    Clear,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComputeOp {
    // CancelOp signals to Compute to not do anything as a result
    // of executing the lambda. If the entry was not present in
    // the map, nothing happens, and if it was present, the
    // returned value is ignored.
    CancelOp,
    // UpdateOp signals to Compute to update the entry to the
    // value returned by the lambda, creating it if necessary.
    UpdateOp,
    // DeleteOp signals to Compute to always delete the entry
    // from the map.
    DeleteOp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LoadOp {
    None,
    OrCompute,
    AndDelete,
}

/// the `entry`: an immutable map entry, shared by the old and the new table while resizing.
#[derive(Debug)]
struct Entry<K, V> {
    key: K,
    value: V,
}

impl<K, V> Entry<K, V> {
    const fn new(key: K, value: V) -> Self {
        Self { key, value }
    }
}

/// the `bucket`: one cache-line sized map bucket holding up to
/// [`ENTRIES_PER_MAP_BUCKET`] entries, with `meta` marking the occupied slots.
#[derive(Debug)]
struct Bucket<K, V> {
    meta: u64,
    entries: [Option<Arc<Entry<K, V>>>; ENTRIES_PER_MAP_BUCKET],
}

impl<K, V> Bucket<K, V> {
    fn new() -> Self {
        Self { meta: 0, entries: std::array::from_fn(|_| None) }
    }

    /// A bucket whose slot 0 holds `entry`, marked occupied by `h2`.
    fn with_first(h2: u8, entry: Arc<Entry<K, V>>) -> Self {
        let mut entries: [Option<Arc<Entry<K, V>>>; ENTRIES_PER_MAP_BUCKET] = std::array::from_fn(|_| None);
        if let Some(slot) = entries.first_mut() {
            *slot = Some(entry);
        }
        Self { meta: set_byte(0, h2, 0), entries }
    }
}

/// the `bucket` plus its `next` chain, under the root bucket's lock.
#[derive(Debug)]
struct BucketChain<K, V> {
    chain: Mutex<Vec<Bucket<K, V>>>,
}

impl<K, V> BucketChain<K, V> {
    fn new() -> Self {
        Self { chain: Mutex::new(vec![Bucket::new()]) }
    }
}

/// The striped counter, padded to a cache line to prevent false sharing.
#[derive(Debug)]
struct CounterStripe {
    c: AtomicI64,
    _pad: [u8; CACHE_LINE_SIZE - 8],
}

impl CounterStripe {
    const fn new() -> Self {
        Self { c: AtomicI64::new(0), _pad: [0; CACHE_LINE_SIZE - 8] }
    }
}

#[derive(Debug)]
pub(crate) struct MapTable<K, V> {
    buckets: Vec<BucketChain<K, V>>,
    // striped counter for number of table entries;
    // used to determine if a table shrinking is needed
    // occupies min(buckets_memory/1024, 64KB) of memory
    size: Vec<CounterStripe>,
    seed: u64,
}

impl<K, V> MapTable<K, V> {
    /// The bucket `h1` names. The table length is a power of two, so masking the hash
    /// always lands on an existing bucket.
    fn bucket_index(&self, h1: u64) -> usize {
        usize::try_from(h1 & (self.buckets.len() - 1) as u64).unwrap_or_default()
    }

    fn add_size(&self, bucket_idx: usize, delta: i32) {
        let cidx = bucket_idx & (self.size.len() - 1);
        if let Some(stripe) = self.size.get(cidx) {
            stripe.c.fetch_add(i64::from(delta), Ordering::SeqCst);
        }
    }

    fn sum_size(&self) -> i64 {
        let mut sum = 0i64;
        for stripe in &self.size {
            sum += stripe.c.load(Ordering::SeqCst);
        }
        sum
    }
}

/// A random per-table seed.
fn make_seed() -> u64 {
    random()
}

fn new_map_table<K, V>(min_table_len: usize, seed: u64) -> Arc<MapTable<K, V>> {
    let buckets = (0..min_table_len).map(|_| BucketChain::new()).collect();
    let counter_len = (min_table_len >> 10).clamp(MIN_MAP_COUNTER_LEN, MAX_MAP_COUNTER_LEN);
    let counter = (0..counter_len).map(|_| CounterStripe::new()).collect();
    Arc::new(MapTable { buckets, size: counter, seed })
}

/// What a [`Map::do_compute`] callback asks the map to do.
///
/// The callback returns a value together with the operation to apply, and hands back the zero
/// `V` on cancel or delete, where the value is dropped; there is no zero value to hand back, so
/// those two operations carry none.
#[derive(Debug)]
pub(crate) enum ComputeOutcome<V> {
    Update(V),
    Cancel,
    Delete,
}

/// The read-only load lookups a write path runs first.
enum LoadLookup<V> {
    /// The key was found, with its value.
    Found(V),
    /// The key is absent, and the caller is `LoadOp::AndDelete`.
    Missing,
    /// The write path has to decide the operation.
    Proceed,
}

/// What a write path's bucket scan decided.
enum Scan<K, V> {
    /// The operation finished in place; this is the value `do_compute` returns.
    Updated(V),
    /// The present entry was deleted; `true` when its bucket is now empty.
    Deleted(V, bool),
    /// Nothing matched: the caller inserts, using the reported free slot and the key back.
    Absent(K, Option<usize>, usize),
}

/// Map is like a hash map but is safe for concurrent use by multiple tasks without additional
/// locking or coordination.
///
/// The interface carries a number of valuable extensions, such as compute-or-store and a size
/// query.
///
/// A Map must not be copied after first use.
///
/// Map uses a modified version of the Cache-Line Hash Table (CLHT) data structure.
///
/// CLHT organizes the hash table in cache-line-sized buckets, so that on all modern CPUs update
/// operations complete with at most one cache-line transfer. Read operations involve no write to
/// memory, and no mutexes or any other sort of locks.
///
/// Map also borrows ideas from Java's j.u.c.ConcurrentHashMap
/// (immutable K/V pair structs instead of atomic snapshots)
/// and C++'s `absl::flat_hash_map` (meta memory and SWAR-based
/// lookups).
#[derive(Debug)]
pub struct Map<K, V> {
    init_once: Once,
    total_growths: AtomicI64,
    total_shrinks: AtomicI64,
    table: ArcSwapOption<MapTable<K, V>>,
    // table being transferred to
    next_table: ArcSwapOption<MapTable<K, V>>,
    // resize control state: combines resize sequence number (upper 59 bits) and
    // the current number of resize helpers (lower 5 bits);
    // odd values of resize sequence mean in-progress resize
    resize_ctl: AtomicU64,
    // only used along with resize_cond
    resize_mu: Mutex<()>,
    // used to wake up resize waiters (concurrent writes)
    resize_cond: Condvar,
    // transfer progress index for resize
    resize_idx: AtomicI64,
    min_table_len: AtomicUsize,
    grow_only: AtomicBool,
}

impl<K, V> Default for Map<K, V> {
    fn default() -> Self {
        Self {
            init_once: Once::new(),
            total_growths: AtomicI64::new(0),
            total_shrinks: AtomicI64::new(0),
            table: ArcSwapOption::const_empty(),
            next_table: ArcSwapOption::const_empty(),
            resize_ctl: AtomicU64::new(0),
            resize_mu: Mutex::new(()),
            resize_cond: Condvar::new(),
            resize_idx: AtomicI64::new(0),
            min_table_len: AtomicUsize::new(0),
            grow_only: AtomicBool::new(false),
        }
    }
}

/// `MapConfig` defines configurable Map options.
#[derive(Clone, Copy, Debug, Default)]
pub struct MapConfig {
    size_hint: i32,
    grow_only: bool,
}

/// A functional option applied to a map under construction.
pub type MapOption<'a> = &'a dyn Fn(&mut MapConfig);

/// Configures a new Map instance with capacity enough to hold the requested number of entries.
///
/// The capacity is treated as the minimal capacity meaning that the underlying hash table will
/// never shrink to a smaller capacity. A zero or negative hint is ignored.
pub fn with_presize(size_hint: i32) -> impl Fn(&mut MapConfig) {
    move |c| {
        c.size_hint = size_hint;
    }
}

/// Configures a new Map instance to be grow-only.
///
/// This means that the underlying hash table grows in capacity when
/// new keys are added, but does not shrink when keys are deleted.
/// The only exception to this rule is the Clear method which
/// shrinks the hash table back to the initial capacity.
pub fn with_grow_only() -> impl Fn(&mut MapConfig) {
    |c| {
        c.grow_only = true;
    }
}

impl<K, V> Map<K, V> {
    /// Creates a new Map instance configured with the given options.
    pub fn new(options: &[MapOption<'_>]) -> Self {
        let mut c = MapConfig::default();
        for o in options {
            o(&mut c);
        }

        let m = Self::default();
        let entries_per_bucket = f64::from(u32::try_from(ENTRIES_PER_MAP_BUCKET).unwrap_or(u32::MAX));
        let min_size = i32::try_from(DEFAULT_MIN_MAP_TABLE_LEN * ENTRIES_PER_MAP_BUCKET).unwrap_or(i32::MAX);
        if c.size_hint > min_size {
            let hint = f64::from(c.size_hint) / entries_per_bucket / MAP_LOAD_FACTOR;
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "the quotient of a positive size hint stays positive and far below 2^53"
            )]
            let table_len = next_pow_of_2(hint as u64);
            m.min_table_len.store(usize::try_from(table_len).unwrap_or(usize::MAX), Ordering::SeqCst);
        }
        m.grow_only.store(c.grow_only, Ordering::SeqCst);
        m
    }

    fn init(&self) {
        if self.min_table_len.load(Ordering::SeqCst) == 0 {
            self.min_table_len.store(DEFAULT_MIN_MAP_TABLE_LEN, Ordering::SeqCst);
        }
        let table = new_map_table(self.min_table_len.load(Ordering::SeqCst), make_seed());
        self.min_table_len.store(table.buckets.len(), Ordering::SeqCst);
        self.table.store(Some(table));
    }

    #[expect(clippy::expect_used, reason = "`init` publishes the table before any other method runs")]
    fn table_load(&self) -> Arc<MapTable<K, V>> {
        self.table.load_full().expect("the table is published by init")
    }

    fn newer_table_exists(&self, table: &Arc<MapTable<K, V>>) -> bool {
        !Arc::ptr_eq(table, &self.table_load())
    }
}

impl<K: MapKey, V> Map<K, V> {
    /// Store sets the value for a key.
    pub fn store(&self, key: K, value: V) {
        self.init_once.call_once(|| self.init());
        // Store is a popular operation, hence instead of using do_compute,
        // it uses a simplified and slightly faster version of it.
        'store_attempt: loop {
            let mut emptyb: Option<usize> = None;
            let mut emptyidx = 0;
            let table = self.table_load();
            let table_len = table.buckets.len();
            let hash = key.hash_with_seed(table.seed);
            let bucket_hash = h1(hash);
            let tag = h2(hash);
            let tag_word = broadcast(tag);
            let bidx = table.bucket_index(bucket_hash);
            let Some(rootb) = table.buckets.get(bidx) else {
                continue 'store_attempt;
            };

            let mut chain = rootb.chain.lock();
            // The following two checks must go in reverse to what's
            // in the resize method.
            let seq = resize_seq(self.resize_ctl.load(Ordering::SeqCst));
            if seq & 1 == 1 {
                // Resize is in progress. Help with the transfer, then go for another attempt.
                drop(chain);
                self.help_resize(seq);
                continue 'store_attempt;
            }
            if self.newer_table_exists(&table) {
                // Someone resized the table. Retry.
                drop(chain);
                continue 'store_attempt;
            }
            for (bi, bucket) in chain.iter_mut().enumerate() {
                let metaw = bucket.meta;
                let mut markedw = mark_zero_bytes(metaw ^ tag_word) & META_MASK;
                while markedw != 0 {
                    let idx = first_marked_byte_index(markedw);
                    markedw &= markedw - 1;
                    let Some(slot) = bucket.entries.get_mut(idx) else {
                        continue;
                    };
                    if slot.as_ref().is_some_and(|e| e.key == key) {
                        // In-place update.
                        *slot = Some(Arc::new(Entry::new(key, value)));
                        return;
                    }
                }
                if emptyb.is_none() {
                    // Search for empty entries (up to 5 per bucket).
                    let empty_slots = !metaw & OCCUPIED_META_MASKED;
                    if empty_slots != 0 {
                        emptyb = Some(bi);
                        emptyidx = first_marked_byte_index(empty_slots);
                    }
                }
            }
            if let Some(eb) = emptyb {
                // Insertion into an existing bucket.
                // First we update meta, then the entry.
                if let Some(bucket) = chain.get_mut(eb) {
                    bucket.meta = set_byte(bucket.meta, tag, emptyidx);
                    if let Some(slot) = bucket.entries.get_mut(emptyidx) {
                        *slot = Some(Arc::new(Entry::new(key, value)));
                    }
                }
                table.add_size(bidx, 1);
                return;
            }
            let grow_limit = grow_threshold(table_len);
            if table.sum_size() > grow_limit {
                // Need to grow the table. Then go for another attempt.
                drop(chain);
                self.resize(&table, MapResizeHint::Grow);
                continue 'store_attempt;
            }
            // Insertion into a new bucket: create and append a bucket.
            chain.push(Bucket::with_first(tag, Arc::new(Entry::new(key, value))));
            drop(chain);
            table.add_size(bidx, 1);
            return;
        }
    }

    /// Delete deletes the value for a key.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the API takes the key by value; `&K` would change the public signature"
    )]
    pub fn delete(&self, key: K)
    where
        V: Clone,
    {
        let _ = self.load_and_delete(&key);
    }

    pub(crate) fn do_compute<F>(
        &self,
        key: K,
        mut value_fn: F,
        load_op: LoadOp,
        compute_only: bool,
    ) -> (Option<V>, bool)
    where
        F: FnMut(Option<V>, bool) -> ComputeOutcome<V>,
        V: Clone,
    {
        self.init_once.call_once(|| self.init());
        // `scan` takes the key by value and hands it back, and every retry path
        // has to re-enter the loop with a live key; a rebound local keeps that
        // explicit instead of shadowing the parameter inside the loop body.
        let mut key = key;
        'compute_attempt: loop {
            let mut emptyb: Option<usize> = None;
            let mut emptyidx = 0;
            let table = self.table_load();
            let table_len = table.buckets.len();
            let hash = key.hash_with_seed(table.seed);
            let bucket_hash = h1(hash);
            let tag = h2(hash);
            let tag_word = broadcast(tag);
            let bidx = table.bucket_index(bucket_hash);
            let Some(rootb) = table.buckets.get(bidx) else {
                continue 'compute_attempt;
            };

            if load_op != LoadOp::None {
                match Self::lookup(rootb, &key, tag_word, load_op) {
                    LoadLookup::Found(value) => return (Some(value), true),
                    LoadLookup::Missing => return (None, false),
                    LoadLookup::Proceed => {}
                }
            }

            let mut chain = rootb.chain.lock();
            // The following two checks must go in reverse to what's
            // in the resize method.
            let seq = resize_seq(self.resize_ctl.load(Ordering::SeqCst));
            if seq & 1 == 1 {
                // Resize is in progress. Help with the transfer, then go for another attempt.
                drop(chain);
                self.help_resize(seq);
                continue 'compute_attempt;
            }
            if self.newer_table_exists(&table) {
                // Someone resized the table. Retry.
                drop(chain);
                continue 'compute_attempt;
            }
            let (scanned_key, emptyb, emptyidx) = match Self::scan(
                chain.as_mut_slice(),
                key,
                tag_word,
                &mut value_fn,
                compute_only,
                &mut emptyb,
                &mut emptyidx,
            ) {
                Scan::Updated(value) => return (Some(value), true),
                Scan::Deleted(oldv, emptied) => {
                    drop(chain);
                    table.add_size(bidx, -1);
                    // Might need to shrink the table if we left bucket empty.
                    if emptied {
                        self.resize(&table, MapResizeHint::Shrink);
                    }
                    return (Some(oldv), !compute_only);
                }
                Scan::Absent(key, emptyb, emptyidx) => (key, emptyb, emptyidx),
            };
            key = scanned_key;
            if emptyb.is_none() {
                // Need to grow the table. Then go for another attempt.
                let grow_limit = grow_threshold(table_len);
                if table.sum_size() > grow_limit {
                    drop(chain);
                    self.resize(&table, MapResizeHint::Grow);
                    continue 'compute_attempt;
                }
            }
            let slot = emptyb.map(|bi| (bi, emptyidx));
            let Some(new_value) = Self::insert(&mut chain, key, tag, slot, &mut value_fn) else {
                drop(chain);
                return (None, false);
            };
            drop(chain);
            table.add_size(bidx, 1);
            return (Some(new_value), compute_only);
        }
    }

    /// The read-only lookup the load operations run before the write path.
    fn lookup(rootb: &BucketChain<K, V>, key: &K, tag_word: u64, load_op: LoadOp) -> LoadLookup<V>
    where
        V: Clone,
    {
        let chain = rootb.chain.lock();
        for b in chain.iter() {
            let metaw = b.meta;
            let mut markedw = mark_zero_bytes(metaw ^ tag_word) & META_MASK;
            while markedw != 0 {
                let idx = first_marked_byte_index(markedw);
                markedw &= markedw - 1;
                let Some(e) = b.entries.get(idx).and_then(Option::as_ref) else {
                    continue;
                };
                if e.key == *key {
                    if load_op == LoadOp::OrCompute {
                        return LoadLookup::Found(e.value.clone());
                    }
                    return LoadLookup::Proceed;
                }
            }
        }
        drop(chain);
        if load_op == LoadOp::AndDelete {
            LoadLookup::Missing
        } else {
            LoadLookup::Proceed
        }
    }

    /// Scans a chain for `key`, applying an in-place update or delete. An in-place delete is
    /// handed back rather than applied, because the chain lock has to be released before the
    /// size counter moves.
    fn scan<F>(
        chain: &mut [Bucket<K, V>],
        key: K,
        tag_word: u64,
        value_fn: &mut F,
        compute_only: bool,
        emptyb: &mut Option<usize>,
        emptyidx: &mut usize,
    ) -> Scan<K, V>
    where
        F: FnMut(Option<V>, bool) -> ComputeOutcome<V>,
        V: Clone,
    {
        for (bi, bucket) in chain.iter_mut().enumerate() {
            let metaw = bucket.meta;
            let mut markedw = mark_zero_bytes(metaw ^ tag_word) & META_MASK;
            while markedw != 0 {
                let idx = first_marked_byte_index(markedw);
                markedw &= markedw - 1;
                let Some(slot) = bucket.entries.get_mut(idx) else {
                    continue;
                };
                // We get a copy of the value on each call, thus the live
                // value pointers are unique. Otherwise atomic snapshot won't be
                // correct in case of multiple Store calls using the same value.
                let Some(oldv) = slot.as_ref().filter(|e| e.key == key).map(|e| e.value.clone()) else {
                    continue;
                };
                return match value_fn(Some(oldv.clone()), true) {
                    ComputeOutcome::Delete => {
                        // Deletion.
                        // First we update the hash, then the entry.
                        let newmetaw = set_byte(metaw, 0, idx);
                        bucket.meta = newmetaw;
                        *slot = None;
                        Scan::Deleted(oldv, newmetaw == 0)
                    }
                    ComputeOutcome::Update(newv) => {
                        // In-place update.
                        *slot = Some(Arc::new(Entry::new(key, newv.clone())));
                        if compute_only {
                            // Compute expects the new value to be returned.
                            Scan::Updated(newv)
                        } else {
                            // The caller expects the old value back.
                            Scan::Updated(oldv)
                        }
                    }
                    ComputeOutcome::Cancel => Scan::Updated(oldv),
                };
            }
            if emptyb.is_none() {
                // Search for empty entries (up to 5 per bucket).
                let empty_slots = !metaw & OCCUPIED_META_MASKED;
                if empty_slots != 0 {
                    *emptyb = Some(bi);
                    *emptyidx = first_marked_byte_index(empty_slots);
                }
            }
        }
        Scan::Absent(key, *emptyb, *emptyidx)
    }

    /// Applies the insertion half of a write: the entry goes into an existing free slot, or
    /// into a newly appended bucket when the chain has none. `None` reports that the callback
    /// cancelled the insertion.
    fn insert<F>(
        chain: &mut Vec<Bucket<K, V>>,
        key: K,
        tag: u8,
        slot: Option<(usize, usize)>,
        value_fn: &mut F,
    ) -> Option<V>
    where
        F: FnMut(Option<V>, bool) -> ComputeOutcome<V>,
        V: Clone,
    {
        let ComputeOutcome::Update(new_value) = value_fn(None, false) else {
            return None;
        };
        match slot {
            // First we update meta, then the entry.
            Some((bi, idx)) => {
                if let Some(bucket) = chain.get_mut(bi) {
                    bucket.meta = set_byte(bucket.meta, tag, idx);
                    if let Some(entry) = bucket.entries.get_mut(idx) {
                        *entry = Some(Arc::new(Entry::new(key, new_value.clone())));
                    }
                }
            }
            // Insertion into a new bucket: create and append a bucket.
            None => chain.push(Bucket::with_first(tag, Arc::new(Entry::new(key, new_value.clone())))),
        }
        Some(new_value)
    }

    /// Range calls f sequentially for each key and value present in the
    /// map. If f returns false, range stops the iteration.
    ///
    /// Range does not necessarily correspond to any consistent snapshot
    /// of the Map's contents: no key will be visited more than once, but
    /// if the value for any key is stored or deleted concurrently, Range
    /// may reflect any mapping for that key from any point during the
    /// Range call.
    ///
    /// It is safe to modify the map while iterating it, including entry
    /// creation, modification and deletion. However, the concurrent
    /// modification rule apply, i.e. the changes may be not reflected
    /// in the subsequently iterated entries.
    pub fn range(&self, mut f: impl FnMut(&K, &V) -> bool) {
        self.init_once.call_once(|| self.init());
        // Pre-allocate array big enough to fit entries for most hash tables.
        let mut bentries: Vec<Arc<Entry<K, V>>> = Vec::with_capacity(16 * ENTRIES_PER_MAP_BUCKET);
        let table = self.table_load();
        for rootb in &table.buckets {
            // Prevent concurrent modifications and copy all entries into
            // the intermediate slice.
            {
                let chain = rootb.chain.lock();
                for b in chain.iter() {
                    for e in b.entries.iter().flatten() {
                        bentries.push(Arc::clone(e));
                    }
                }
            }
            // Call the function for all copied entries.
            for e in &bentries {
                if !f(&e.key, &e.value) {
                    return;
                }
            }
            bentries.clear();
        }
    }

    /// Like `Range`, but taking the callback `Range` takes rather than returning an iterator,
    /// which Rust has no counterpart for.
    ///
    /// For a faster, lock-free alternative with relaxed consistency
    /// guarantees, see [`Map::all_relaxed`].
    pub fn all(&self, f: impl FnMut(&K, &V) -> bool) {
        self.range(f);
    }

    /// Calls f sequentially over each key and value present
    /// in the map. If f returns false, range stops the iteration.
    ///
    /// The iteration does not necessarily correspond to any consistent
    /// snapshot of the Map's contents: if the value for any key is stored
    /// or deleted concurrently, it may reflect any mapping of
    /// that key from any point during the call. Unlike the strict variant,
    /// the same key may be visited more than once if it is concurrently
    /// deleted and re-inserted during the iteration.
    ///
    /// It is safe to modify the map while iterating it, including entry
    /// creation, modification and deletion. However, the concurrent
    /// modification rule apply, i.e. the changes may be not reflected
    /// in the subsequently iterated entries.
    ///
    /// The entries are copied out from under the chain lock, so that `f` may modify the map; that
    /// allocates where a lock-free read of each entry would not.
    pub fn range_relaxed(&self, mut f: impl FnMut(&K, &V) -> bool) {
        self.init_once.call_once(|| self.init());
        let table = self.table_load();
        let mut bentries: Vec<Arc<Entry<K, V>>> = Vec::new();
        for rootb in &table.buckets {
            bentries.clear();
            {
                let chain = rootb.chain.lock();
                for b in chain.iter() {
                    let mut markedw = b.meta & OCCUPIED_META;
                    while markedw != 0 {
                        let idx = first_marked_byte_index(markedw);
                        markedw &= markedw - 1;
                        if let Some(e) = b.entries.get(idx).and_then(Option::as_ref) {
                            bentries.push(Arc::clone(e));
                        }
                    }
                }
            }
            for e in &bentries {
                if !f(&e.key, &e.value) {
                    return;
                }
            }
        }
    }

    /// Like the relaxed variant, but taking a callback rather than an iterator.
    ///
    /// For stronger consistency guarantees where each key is visited at
    /// most once, see [`Map::all`].
    pub fn all_relaxed(&self, f: impl FnMut(&K, &V) -> bool) {
        self.range_relaxed(f);
    }

    /// Deletes all entries whose callback returns a true delete flag. A
    /// true stop flag stops the iteration immediately. The number of
    /// deleted entries is returned.
    ///
    /// This does not necessarily correspond to any consistent snapshot of
    /// the Map's contents: when a value is stored or deleted concurrently
    /// (including by a concurrent `delete_matching` call), the result may
    /// reflect any mapping of that key from any point during the call. In
    /// particular, a resize during the call (say, from concurrent
    /// modifications) restarts the iteration internally with the new table,
    /// which may result in the callback seeing the same key more than once.
    ///
    /// The call locks a hash table bucket as the callback runs over every
    /// entry in the bucket and the deletions are performed, so modifications
    /// on other entries in the bucket stay blocked until the callback
    /// returns. Consider this when the callback includes long-running
    /// operations.
    pub fn delete_matching(&self, mut f: impl FnMut(&K, &V) -> (bool, bool)) -> i32 {
        self.init_once.call_once(|| self.init());
        let mut total_deleted = 0i32;
        let mut any_bucket_emptied = false;
        'delete_loop_attempt: loop {
            let table = self.table_load();
            for bidx in 0..table.buckets.len() {
                let Some(rootb) = table.buckets.get(bidx) else {
                    continue;
                };
                let mut chain = rootb.chain.lock();
                // The following two checks must go in reverse to what's
                // in the resize method.
                let seq = resize_seq(self.resize_ctl.load(Ordering::SeqCst));
                if seq & 1 == 1 {
                    // Resize is in progress. Help with the transfer, then go for another attempt.
                    drop(chain);
                    self.help_resize(seq);
                    continue 'delete_loop_attempt;
                }
                if self.newer_table_exists(&table) {
                    // Someone resized the table. Retry.
                    drop(chain);
                    continue 'delete_loop_attempt;
                }

                let mut bucket_deleted = 0i32;
                let mut stop = false;
                for bucket in chain.iter_mut() {
                    for (i, slot) in bucket.entries.iter_mut().enumerate() {
                        let Some(e) = slot.as_ref() else {
                            continue;
                        };
                        let (del, stop_hit) = f(&e.key, &e.value);
                        if del {
                            // Deletion.
                            // First we update the meta, then the entry.
                            let newmetaw = set_byte(bucket.meta, 0, i);
                            bucket.meta = newmetaw;
                            *slot = None;
                            bucket_deleted += 1;
                            if newmetaw == 0 {
                                any_bucket_emptied = true;
                            }
                        }
                        if stop_hit {
                            stop = true;
                            break;
                        }
                    }
                    if stop {
                        break;
                    }
                }
                drop(chain);
                if stop {
                    total_deleted += bucket_deleted;
                    if bucket_deleted > 0 {
                        table.add_size(bidx, -bucket_deleted);
                    }
                    if any_bucket_emptied {
                        self.resize(&table, MapResizeHint::Shrink);
                    }
                    return total_deleted;
                }
                if bucket_deleted > 0 {
                    total_deleted += bucket_deleted;
                    table.add_size(bidx, -bucket_deleted);
                }
            }
            if any_bucket_emptied {
                self.resize(&table, MapResizeHint::Shrink);
            }
            return total_deleted;
        }
    }

    /// Clear deletes all keys and values currently stored in the map.
    pub fn clear(&self) {
        self.init_once.call_once(|| self.init());
        let table = self.table_load();
        self.resize(&table, MapResizeHint::Clear);
    }

    /// Size returns current size of the map.
    pub fn size(&self) -> i32 {
        self.init_once.call_once(|| self.init());
        i32::try_from(self.table_load().sum_size()).unwrap_or(i32::MAX)
    }

    /// Stats returns statistics for the Map. Just like other map
    /// methods, this one is thread-safe. Yet it's an O(N) operation,
    /// so it should be used only for diagnostics or debugging purposes.
    pub fn stats(&self) -> MapStats {
        self.init_once.call_once(|| self.init());
        let mut stats = MapStats {
            root_buckets: 0,
            total_buckets: 0,
            empty_buckets: 0,
            capacity: 0,
            size: 0,
            counter: 0,
            counter_len: 0,
            min_entries: i32::MAX,
            max_entries: 0,
            total_growths: self.total_growths.load(Ordering::SeqCst),
            total_shrinks: self.total_shrinks.load(Ordering::SeqCst),
        };
        let table = self.table_load();
        stats.root_buckets = i32::try_from(table.buckets.len()).unwrap_or(i32::MAX);
        stats.counter = i32::try_from(table.sum_size()).unwrap_or(i32::MAX);
        stats.counter_len = i32::try_from(table.size.len()).unwrap_or(i32::MAX);
        let per_bucket = i32::try_from(ENTRIES_PER_MAP_BUCKET).unwrap_or(i32::MAX);
        for rootb in &table.buckets {
            let mut nentries = 0i32;
            let chain = rootb.chain.lock();
            for b in chain.iter() {
                let mut nentries_local = 0i32;
                stats.capacity += per_bucket;
                for slot in &b.entries {
                    if slot.is_some() {
                        stats.size += 1;
                        nentries_local += 1;
                    }
                }
                nentries += nentries_local;
                if nentries_local == 0 {
                    stats.empty_buckets += 1;
                }
            }
            let chained = i32::try_from(chain.len()).unwrap_or(i32::MAX);
            drop(chain);
            stats.total_buckets += chained;
            if nentries < stats.min_entries {
                stats.min_entries = nentries;
            }
            if nentries > stats.max_entries {
                stats.max_entries = nentries;
            }
        }
        stats
    }

    fn wait_for_resize(&self) {
        let mut guard = self.resize_mu.lock();
        while resize_seq(self.resize_ctl.load(Ordering::SeqCst)) & 1 == 1 {
            self.resize_cond.wait(&mut guard);
        }
    }

    fn resize(&self, known_table: &Arc<MapTable<K, V>>, hint: MapResizeHint) {
        let known_table_len = known_table.buckets.len();
        // Fast path for shrink attempts.
        if hint == MapResizeHint::Shrink
            && (self.grow_only.load(Ordering::SeqCst)
                || self.min_table_len.load(Ordering::SeqCst) == known_table_len
                || known_table.sum_size() > shrink_threshold(known_table_len))
        {
            return;
        }
        // Slow path.
        let seq = resize_seq(self.resize_ctl.load(Ordering::SeqCst));
        if seq & 1 == 1
            || self
                .resize_ctl
                .compare_exchange(resize_ctl(seq, 0), resize_ctl(seq + 1, 0), Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            self.help_resize(seq);
            return;
        }
        let table = self.table_load();
        let table_len = table.buckets.len();
        let new_table = match hint {
            MapResizeHint::Grow => {
                // Grow the table with factor of 2.
                // We must keep the same table seed here to keep the same hash codes
                // allowing us to avoid locking destination buckets when resizing.
                self.total_growths.fetch_add(1, Ordering::SeqCst);
                new_map_table(table_len << 1, table.seed)
            }
            MapResizeHint::Shrink => {
                let limit = shrink_threshold(table_len);
                if table_len > self.min_table_len.load(Ordering::SeqCst) && table.sum_size() <= limit {
                    // Shrink the table with factor of 2.
                    // Analogous to growth, we must preserve the seed to ensure stable
                    // hash mapping, enabling lock-free writes to destination buckets.
                    self.total_shrinks.fetch_add(1, Ordering::SeqCst);
                    new_map_table(table_len >> 1, table.seed)
                } else {
                    // No need to shrink. Wake up all waiters and give up.
                    let _guard = self.resize_mu.lock();
                    self.resize_ctl.store(resize_ctl(seq + 2, 0), Ordering::SeqCst);
                    self.resize_cond.notify_all();
                    return;
                }
            }
            MapResizeHint::Clear => new_map_table(self.min_table_len.load(Ordering::SeqCst), make_seed()),
        };

        // Copy the data only if we're not clearing the map.
        if hint != MapResizeHint::Clear {
            // Set up cooperative transfer state.
            // Next table must be published as the last step.
            self.resize_idx.store(0, Ordering::SeqCst);
            self.next_table.store(Some(Arc::clone(&new_table)));
            // Copy the buckets.
            self.transfer(&table, &new_table);
        }

        // We're about to publish the new table, but before that
        // we must wait for all helpers to finish.
        while resize_helpers(self.resize_ctl.load(Ordering::SeqCst)) != 0 {
            std::thread::yield_now();
        }
        self.table.store(Some(Arc::clone(&new_table)));
        self.next_table.store(None);
        let ctl = resize_ctl(seq + 1, 0);
        let new_ctl = resize_ctl(seq + 2, 0);
        // Increment the sequence number and wake up all waiters.
        let _guard = self.resize_mu.lock();
        // There may be slowpoke helpers who have just incremented
        // the helper counter. This CAS loop makes sure to wait
        // for them to back off.
        while self.resize_ctl.compare_exchange(ctl, new_ctl, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            std::thread::yield_now();
        }
        self.resize_cond.notify_all();
    }

    fn help_resize(&self, seq: u64) {
        loop {
            let table = self.table_load();
            let next_table = self.next_table.load_full();
            if resize_seq(self.resize_ctl.load(Ordering::SeqCst)) == seq {
                let Some(next_table) = next_table else {
                    // Carry on until the next table is set by the main
                    // resize task or until the resize finishes.
                    std::thread::yield_now();
                    continue;
                };
                if Arc::ptr_eq(&next_table, &table) {
                    std::thread::yield_now();
                    continue;
                }
                // The resize is still in-progress, so let's try registering
                // as a helper.
                loop {
                    let ctl = self.resize_ctl.load(Ordering::SeqCst);
                    let max_helpers = u64::try_from(*MAX_RESIZE_HELPERS).unwrap_or(1);
                    if resize_seq(ctl) != seq || resize_helpers(ctl) >= max_helpers {
                        // The resize has ended or there are too many helpers.
                        break;
                    }
                    if self.resize_ctl.compare_exchange(ctl, ctl + 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                        // Yay, we're a resize helper!
                        self.transfer(&table, &next_table);
                        // Don't forget to unregister as a helper.
                        self.resize_ctl.fetch_sub(1, Ordering::SeqCst);
                        break;
                    }
                }
                self.wait_for_resize();
            }
            break;
        }
    }

    fn transfer(&self, table: &Arc<MapTable<K, V>>, new_table: &Arc<MapTable<K, V>>) {
        let table_len = table.buckets.len();
        let new_table_len = new_table.buckets.len();
        // Determines the concurrent task range for destination buckets.
        // We iterate based on these properties to avoid locking destination
        // buckets:
        // - Grow (Pow2):   baseLen == tableLen
        //   Entries from source bucket i move to dest buckets i and i+baseLen
        // - Shrink (Pow2): baseLen == newTableLen
        //   Entries from source buckets i and i+baseLen move to dest bucket i
        // By iterating 0..baseLen and processing all possible source buckets
        // (srcIdx += baseLen) in the inner loop, a single task exclusively
        // owns the write operations for its assigned destination buckets.
        let mut base_len = table_len;
        if base_len > new_table_len {
            base_len = new_table_len;
        }
        let mut stride = (table_len >> 3) / usize::try_from(*MAX_RESIZE_HELPERS).unwrap_or(1);
        if stride < MIN_RESIZE_TRANSFER_STRIDE {
            stride = MIN_RESIZE_TRANSFER_STRIDE;
        }
        let stride = i64::try_from(stride).unwrap_or(i64::MAX);
        let base_len_i64 = i64::try_from(base_len).unwrap_or(i64::MAX);
        loop {
            // Claim work by incrementing resizeIdx.
            let next_idx = self.resize_idx.fetch_add(stride, Ordering::SeqCst) + stride;
            let mut start = next_idx - stride;
            if start < 0 {
                start = 0;
            }
            if start >= base_len_i64 {
                break;
            }
            let end = next_idx.min(base_len_i64);
            let start = usize::try_from(start).unwrap_or_default();
            let end = usize::try_from(end).unwrap_or_default();
            // Transfer buckets in this range.
            let mut total = 0i32;
            for i in start..end {
                // Visit all source buckets that map to this destination bucket.
                // When growing, runs once. When shrinking, runs twice.
                let mut src_idx = i;
                while src_idx < table_len {
                    if let Some(src) = table.buckets.get(src_idx) {
                        total += transfer_bucket_unsafe(src, new_table);
                    }
                    src_idx += base_len;
                }
            }
            // The exact counter stripe doesn't matter here, so pick up the one
            // that corresponds to the start value to avoid contention.
            new_table.add_size(start, total);
        }
    }
}

impl<K: MapKey, V: Clone> Map<K, V> {
    /// Load returns the value stored in the map for a key, or zero value
    /// of type V if no value is present.
    /// The ok result indicates whether value was found in the map.
    pub fn load(&self, key: &K) -> Option<V> {
        self.init_once.call_once(|| self.init());
        let table = self.table_load();
        let hash = key.hash_with_seed(table.seed);
        let bucket_hash = h1(hash);
        let tag_word = broadcast(h2(hash));
        let bidx = table.bucket_index(bucket_hash);
        let rootb = table.buckets.get(bidx)?;
        let chain = rootb.chain.lock();

        for b in chain.iter() {
            let metaw = b.meta;
            let mut markedw = mark_zero_bytes(metaw ^ tag_word) & META_MASK;
            while markedw != 0 {
                let idx = first_marked_byte_index(markedw);
                markedw &= markedw - 1;
                if let Some(e) = b.entries.get(idx).and_then(Option::as_ref) {
                    if e.key == *key {
                        return Some(e.value.clone());
                    }
                }
            }
        }
        drop(chain);
        None
    }

    /// Yields the existing value when the key is present.
    /// Otherwise, it stores and returns the given value.
    /// The loaded result is true if the value was loaded, false if stored.
    #[expect(clippy::expect_used, reason = "`do_compute` consults the callback once, so the value is still there")]
    pub fn load_or_store(&self, key: K, value: V) -> (V, bool) {
        let mut value = Some(value);
        let (actual, loaded) = self.do_compute(
            key,
            |_old_value, loaded| {
                if loaded {
                    return ComputeOutcome::Cancel;
                }
                ComputeOutcome::Update(value.take().expect("the value is stored once"))
            },
            LoadOp::OrCompute,
            false,
        );
        (actual.expect("load_or_store always yields the stored value"), loaded)
    }

    /// Yields the existing value when the key is present,
    /// while setting the new value for the key.
    /// It stores the new value and returns the existing one, if present.
    /// The loaded result is true if the existing value was loaded,
    /// false otherwise.
    #[expect(clippy::expect_used, reason = "`do_compute` consults the callback once, so the value is still there")]
    pub fn load_and_store(&self, key: K, value: V) -> (Option<V>, bool) {
        let mut value = Some(value);
        self.do_compute(
            key,
            |_old_value, _loaded| ComputeOutcome::Update(value.take().expect("the value is stored once")),
            LoadOp::None,
            false,
        )
    }

    /// Returns the existing value of the key when present. Otherwise it
    /// tries to compute the value with the provided callback and, when
    /// successful, stores and returns the computed value. The loaded flag
    /// reports whether the value was loaded rather than computed. A true
    /// cancel flag from the callback cancels the computation and returns
    /// the zero value of `V`.
    ///
    /// The call locks a hash table bucket as the compute callback runs,
    /// so modifications on other entries in the bucket stay blocked until
    /// the callback returns. Consider this when the callback includes
    /// long-running operations.
    pub fn load_or_compute(&self, key: K, mut value_fn: impl FnMut() -> (V, bool)) -> (Option<V>, bool) {
        self.do_compute(
            key,
            |_old_value, loaded| {
                if loaded {
                    return ComputeOutcome::Cancel;
                }
                let (new_value, cancel) = value_fn();
                if !cancel {
                    return ComputeOutcome::Update(new_value);
                }
                ComputeOutcome::Cancel
            },
            LoadOp::OrCompute,
            false,
        )
    }

    /// Sets the computed value of a key, deletes the key, or leaves it
    /// alone, based on the returned [`ComputeOp`]. An update op stores the
    /// new value; a delete op removes the entry from the map altogether; a
    /// cancel op leaves the entry as-is. In other words, a cancel op does
    /// not create an absent key and does not touch a present one. The ok
    /// result indicates whether the entry is present in the map after the
    /// operation.
    ///
    /// The call locks a hash table bucket as the compute callback runs,
    /// so modifications on other entries in the bucket stay blocked until
    /// the callback returns. Consider this when the callback includes
    /// long-running operations.
    pub fn compute(&self, key: K, mut value_fn: impl FnMut(Option<V>, bool) -> (V, ComputeOp)) -> (Option<V>, bool) {
        self.do_compute(
            key,
            |old_value, loaded| match value_fn(old_value, loaded) {
                (new_value, ComputeOp::UpdateOp) => ComputeOutcome::Update(new_value),
                (_, ComputeOp::DeleteOp) => ComputeOutcome::Delete,
                (_, ComputeOp::CancelOp) => ComputeOutcome::Cancel,
            },
            LoadOp::None,
            true,
        )
    }

    /// Deletes the value of a key, returning the previous value when there
    /// is one. The loaded flag reports whether the key was present.
    pub fn load_and_delete(&self, key: &K) -> (Option<V>, bool) {
        self.do_compute(key.clone(), |_value, _loaded| ComputeOutcome::Delete, LoadOp::AndDelete, false)
    }
}

/// Returns a native map with a copy of the Map's contents.
///
/// The copied Map should not be modified during this call. When the copied Map is
/// modified, the copying behavior is the same as in the `range` method.
#[must_use]
pub fn to_plain_map<K: MapKey + Hash, V: Clone>(m: Option<&Map<K, V>>) -> HashMap<K, V> {
    let mut pm = HashMap::new();
    if let Some(m) = m {
        m.range(|key, value| {
            pm.insert(key.clone(), value.clone());
            true
        });
    }
    pm
}

// It is safe to use plain stores here because the destination bucket must be
// either locked or exclusively written to by the helper during resize.
fn append_to_bucket<K, V>(h2: u8, e: Arc<Entry<K, V>>, b: &BucketChain<K, V>) {
    let mut chain = b.chain.lock();
    for bucket in chain.iter_mut() {
        for (i, slot) in bucket.entries.iter_mut().enumerate() {
            if slot.is_none() {
                bucket.meta = set_byte(bucket.meta, h2, i);
                *slot = Some(Arc::clone(&e));
                return;
            }
        }
    }
    chain.push(Bucket::with_first(h2, e));
}

// Doesn't acquire dest bucket lock.
fn transfer_bucket_unsafe<K: MapKey, V>(b: &BucketChain<K, V>, dest_table: &MapTable<K, V>) -> i32 {
    let mut copied = 0i32;
    let chain = b.chain.lock();
    for bucket in chain.iter() {
        for e in bucket.entries.iter().flatten() {
            let hash = e.key.hash_with_seed(dest_table.seed);
            let bidx = dest_table.bucket_index(h1(hash));
            if let Some(dest) = dest_table.buckets.get(bidx) {
                append_to_bucket(h2(hash), Arc::clone(e), dest);
            }
            copied += 1;
        }
    }
    drop(chain);
    copied
}

const fn h1(h: u64) -> u64 {
    h >> 7
}

#[allow(clippy::cast_possible_truncation, reason = "the mask above bounds the byte to seven bits")]
const fn h2(h: u64) -> u8 {
    0x80 | (h & 0x7f) as u8
}

/// The entry count at which the table is grown: the soft limit the load factor defines.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "the threshold of any allocatable table is exact in the float product and fits an `i64`"
)]
fn grow_threshold(table_len: usize) -> i64 {
    (table_len as f64 * ENTRIES_PER_MAP_BUCKET as f64 * MAP_LOAD_FACTOR) as i64
}

/// The entry count below which a shrink is attempted, measured over the table's buckets.
fn shrink_threshold(table_len: usize) -> i64 {
    i64::try_from((table_len * ENTRIES_PER_MAP_BUCKET) / MAP_SHRINK_FRACTION).unwrap_or(i64::MAX)
}

const fn resize_seq(ctl: u64) -> u64 {
    ctl >> 5
}

const fn resize_helpers(ctl: u64) -> u64 {
    ctl & MAX_RESIZE_HELPERS_LIMIT
}

const fn resize_ctl(seq: u64, helpers: u64) -> u64 {
    (seq << 5) | (helpers & MAX_RESIZE_HELPERS_LIMIT)
}

// cacheLineSize is used in paddings to prevent false sharing;
// 64B are used instead of 128B as a compromise between
// memory footprint and performance; 128B usage may give ~30%
// improvement on NUMA machines.
const CACHE_LINE_SIZE: usize = 64;

/// Computes the next highest power of 2 of 64-bit v.
fn next_pow_of_2(v: u64) -> u64 {
    if v <= 1 {
        return 1;
    }
    // A shift of 64 or more yields zero, which `checked_shl` keeps.
    1u64.checked_shl(u64::BITS - (v - 1).leading_zeros()).unwrap_or(0)
}

fn parallelism() -> u32 {
    u32::try_from(std::thread::available_parallelism().map_or(1, std::num::NonZero::get)).unwrap_or(u32::MAX)
}

fn broadcast(b: u8) -> u64 {
    0x101010101010101 * u64::from(b)
}

const fn first_marked_byte_index(w: u64) -> usize {
    // `usize::from(u32)` does not exist, and `try_from` is not const here; the
    // value is at most 8, so the cast is exact on every supported target.
    (w.trailing_zeros() >> 3) as usize
}

// SWAR byte search: may produce false positives, e.g. for 0x0100,
// so make sure to double-check bytes found by this function.
const fn mark_zero_bytes(w: u64) -> u64 {
    (w.wrapping_sub(0x0101010101010101)) & (!w) & 0x8080808080808080
}

// Sets byte of the input word at the specified index to the given value.
fn set_byte(w: u64, b: u8, idx: usize) -> u64 {
    let shift = idx << 3;
    (w & !(0xffu64 << shift)) | (u64::from(b) << shift)
}

/// hashUint64 computes a hash for integer keys using two rounds of
/// multiply-xorshift mixing (wyhash-style).
#[must_use]
pub fn hash_uint64(seed: u64, v: u64) -> u64 {
    let m = u128::from(v ^ seed) * 0x2d358dccaa6c78a5u128;
    let (hi, lo) =
        (u64::try_from(m >> 64).unwrap_or_default(), u64::try_from(m & u128::from(u64::MAX)).unwrap_or_default());
    let m2 = u128::from(hi ^ lo) * 0x8bb84b93962eacc9u128;
    let (hi2, lo2) =
        (u64::try_from(m2 >> 64).unwrap_or_default(), u64::try_from(m2 & u128::from(u64::MAX)).unwrap_or_default());
    hi2 ^ lo2
}

/// The key surface of the Map. Integer-key detection and hashing are
/// folded in here: integer keys hash through [`hash_uint64`], every other key through
/// [`std::hash::Hash`].
pub trait MapKey: Eq + Clone + Hash {
    const IS_INT_KEY: bool = false;

    fn to_uint64(&self) -> u64 {
        0
    }

    fn hash_with_seed(&self, seed: u64) -> u64 {
        if Self::IS_INT_KEY {
            hash_uint64(seed, self.to_uint64())
        } else {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            seed.hash(&mut hasher);
            self.hash(&mut hasher);
            hasher.finish()
        }
    }
}

/// the `toUint64[K]`: the key reinterpreted as a `uint64` by its width.
trait ToUint64 {
    fn to_uint64(&self) -> u64;
}

macro_rules! to_uint64_by_width {
    ($($t:ty => $w:ty),+ $(,)?) => {
        $(
            impl ToUint64 for $t {
                #[allow(
                    trivial_numeric_casts,
                    clippy::cast_possible_wrap,
                    clippy::cast_sign_loss,
                    clippy::cast_lossless,
                    reason = "the key is reinterpreted at its own width, as the trait documents"
                )]
                fn to_uint64(&self) -> u64 {
                    (*self as $w) as u64
                }
            }
        )+
    };
}

to_uint64_by_width!(
    i8 => u8,
    i16 => u16,
    i32 => u32,
    i64 => u64,
    isize => u64,
    u8 => u8,
    u16 => u16,
    u32 => u32,
    u64 => u64,
    usize => u64,
);

macro_rules! int_map_key {
    ($($t:ty),+ $(,)?) => {
        $(
            impl MapKey for $t {
                const IS_INT_KEY: bool = true;

                fn to_uint64(&self) -> u64 {
                    ToUint64::to_uint64(self)
                }
            }
        )+
    };
}

int_map_key!(i8, i16, i32, i64, isize, u8, u16, u32, u64, usize);

/// Implements [`MapKey`] for a type that already implements [`std::hash::Hash`], the
/// non-integer key arm of the `detectIntKey[K]()`.
#[macro_export]
macro_rules! impl_map_key_comparable {
    ($($t:ty),+ $(,)?) => {
        $(
            impl $crate::xsync::map::MapKey for $t {}
        )+
    };
}

impl_map_key_comparable!(bool, String, &'static str, std::net::SocketAddr);

/// `MapStats` is Map statistics.
///
/// Warning: map statistics are intented to be used for diagnostic
/// purposes, not for production code. This means that breaking changes
/// may be introduced into this struct even between minor releases.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MapStats {
    /// `RootBuckets` is the number of root buckets in the hash table.
    /// Each bucket holds a few entries.
    pub root_buckets: i32,
    /// `TotalBuckets` is the total number of buckets in the hash table,
    /// including root and their chained buckets. Each bucket holds
    /// a few entries.
    pub total_buckets: i32,
    /// `EmptyBuckets` is the number of buckets that hold no entries.
    pub empty_buckets: i32,
    /// Capacity is the Map capacity, i.e. the total number of
    /// entries that all buckets can physically hold. This number
    /// does not consider the load factor.
    pub capacity: i32,
    /// Size is the exact number of entries stored in the map.
    pub size: i32,
    /// Counter is the number of entries stored in the map according
    /// to the internal atomic counter. In case of concurrent map
    /// modifications this number may be different from Size.
    pub counter: i32,
    /// `CounterLen` is the number of internal atomic counter stripes.
    /// This number may grow with the map capacity to improve
    /// multithreaded scalability.
    pub counter_len: i32,
    /// `MinEntries` is the minimum number of entries per a chain of
    /// buckets, i.e. a root bucket and its chained buckets.
    pub min_entries: i32,
    /// `MaxEntries` is the maximum number of entries per a chain of
    /// buckets, i.e. a root bucket and its chained buckets.
    pub max_entries: i32,
    /// `TotalGrowths` is the number of times the hash table grew.
    pub total_growths: i64,
    /// `TotalShrinks` is the number of times the hash table shrinked.
    pub total_shrinks: i64,
}

impl fmt::Display for MapStats {
    /// the `ToString`: the string representation of map stats.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MapStats{\n")?;
        writeln!(f, "RootBuckets:  {}", self.root_buckets)?;
        writeln!(f, "TotalBuckets: {}", self.total_buckets)?;
        writeln!(f, "EmptyBuckets: {}", self.empty_buckets)?;
        writeln!(f, "Capacity:     {}", self.capacity)?;
        writeln!(f, "Size:         {}", self.size)?;
        writeln!(f, "Counter:      {}", self.counter)?;
        writeln!(f, "CounterLen:   {}", self.counter_len)?;
        writeln!(f, "MinEntries:   {}", self.min_entries)?;
        writeln!(f, "MaxEntries:   {}", self.max_entries)?;
        writeln!(f, "TotalGrowths: {}", self.total_growths)?;
        writeln!(f, "TotalShrinks: {}", self.total_shrinks)?;
        f.write_str("}\n")
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::sync::atomic::AtomicI64;
    use std::thread;
    use std::time::Duration;

    use rand::Rng;

    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct Point {
        x: i32,
        y: i32,
    }

    crate::impl_map_key_comparable!(Point);

    fn join_all(handles: Vec<thread::JoinHandle<()>>) {
        for handle in handles {
            handle.join().expect("worker thread panicked");
        }
    }

    fn size_based_on_typed_range(m: &Map<String, i32>) -> i32 {
        let mut size = 0;
        m.range(|_key, _value| {
            size += 1;
            true
        });
        size
    }

    fn assert_map_capacity<K: MapKey, V>(m: &Map<K, V>, expected_cap: i32) {
        let stats = m.stats();
        assert_eq!(stats.capacity, expected_cap, "capacity was different");
    }

    fn test_map_store_keys<K: MapKey + fmt::Debug>(num_entries: i32, to_key: impl Fn(i32) -> K) {
        let m = Map::<K, K>::new(&[]);
        for i in 0..num_entries {
            m.store(to_key(i), to_key(i));
        }
        for i in 0..num_entries {
            let v = m.load(&to_key(i));
            assert_eq!(v, Some(to_key(i)), "value not found for {i}");
        }
    }

    fn test_map_store_then_delete_keys<K: MapKey + fmt::Debug>(num_entries: i32, to_key: impl Fn(i32) -> K) {
        let m = Map::<K, K>::new(&[]);
        for i in 0..num_entries {
            m.store(to_key(i), to_key(i));
        }
        for i in 0..num_entries {
            m.delete(to_key(i));
            assert!(m.load(&to_key(i)).is_none(), "value was not expected for {i}");
        }
    }

    fn test_map_store_then_load_and_delete_keys<K: MapKey + fmt::Debug>(num_entries: i32, to_key: impl Fn(i32) -> K) {
        let m = Map::<K, K>::new(&[]);
        for i in 0..num_entries {
            m.store(to_key(i), to_key(i));
        }
        for i in 0..num_entries {
            let (_, loaded) = m.load_and_delete(&to_key(i));
            assert!(loaded, "value was not found for {i}");
            assert!(m.load(&to_key(i)).is_none(), "value was not expected for {i}");
        }
    }

    #[test]
    fn test_map_missing_entry() {
        let m = Map::<String, String>::new(&[]);
        let v = m.load(&"foo".to_owned());
        assert!(v.is_none(), "value was not expected: {v:?}");
        let (deleted, loaded) = m.load_and_delete(&"foo".to_owned());
        assert!(!loaded, "value was not expected {deleted:?}");
        let (actual, loaded) = m.load_or_store("foo".to_owned(), "bar".to_owned());
        assert!(!loaded, "value was not expected {actual}");
    }

    #[test]
    fn test_map_empty_string_key() {
        let m = Map::<String, String>::new(&[]);
        m.store(String::new(), "foobar".to_owned());
        let v = m.load(&String::new());
        assert!(v.is_some(), "value was expected");
        assert_eq!(v, Some("foobar".to_owned()));
    }

    // TestMapHashUint64_NoDifferentialBias verifies that hashUint64 does
    // not exhibit seed-independent differential bias for XOR deltas.
    #[test]
    fn test_map_hash_uint64_no_differential_bias() {
        const N_BUCKETS: u64 = 256;
        const MASK: u64 = N_BUCKETS - 1;
        const N_TRIALS: u64 = 100_000;
        const THRESHOLD: f64 = 3.0;
        let expected = N_TRIALS as f64 / N_BUCKETS as f64;

        // Deltas from the issue report.
        let issue_deltas: [u64; 4] = [0x0000015000000000, 0x0000004F00000000, 0x000000A300000000, 0x00000D0000000000];
        // Structured deltas across various shift amounts.
        let mut shifted_deltas = Vec::new();
        for shift in [0u32, 8, 16, 24, 32, 40, 48] {
            for k in 1u64..=64 {
                shifted_deltas.push(k << shift);
            }
        }
        // Single-bit and two-bit (Hamming distance 1-2) deltas.
        let mut hamming_deltas = Vec::new();
        for b in 0..64 {
            hamming_deltas.push(1u64 << b);
        }
        for b1 in (0..64).step_by(4) {
            for b2 in ((b1 + 1)..64).step_by(4) {
                hamming_deltas.push((1u64 << b1) | (1u64 << b2));
            }
        }

        let mut all_deltas = Vec::new();
        all_deltas.extend_from_slice(&issue_deltas);
        all_deltas.extend_from_slice(&shifted_deltas);
        all_deltas.extend_from_slice(&hamming_deltas);

        for s in [0u64, 42, 0xDEADBEEF] {
            let seed = s;
            for delta in &all_deltas {
                if *delta == 0 {
                    continue;
                }
                let mut collisions = 0u64;
                for i in 0..N_TRIALS {
                    let v = i.wrapping_mul(0x9E3779B97F4A7C15); // spread values
                    let h1 = hash_uint64(seed, v);
                    let h2 = hash_uint64(seed, v ^ delta);
                    if (h1 & MASK) == (h2 & MASK) {
                        collisions += 1;
                    }
                }
                let ratio = collisions as f64 / expected;
                assert!(
                    ratio <= THRESHOLD,
                    "seed={s:#x} delta={delta:#x}: got {ratio:.2}x expected collision rate \
                     (threshold={THRESHOLD:.1}x)"
                );
            }
        }
    }

    #[test]
    fn test_map_store_nil_value() {
        let m = Map::<String, Option<Arc<()>>>::new(&[]);
        m.store("foo".to_owned(), None);
        let v = m.load(&"foo".to_owned());
        assert!(v.is_some(), "nil value was expected");
        assert!(v.expect("value was expected").is_none(), "value was not nil");
    }

    #[test]
    fn test_map_load_or_store_nil_value() {
        let m = Map::<String, Option<Arc<()>>>::new(&[]);
        m.load_or_store("foo".to_owned(), None);
        let (v, loaded) = m.load_or_store("foo".to_owned(), None);
        assert!(loaded, "nil value was expected");
        assert!(v.is_none(), "value was not nil");
    }

    #[test]
    fn test_map_load_or_store_non_nil_value() {
        #[derive(Debug)]
        struct Foo;

        let m = Map::<String, Option<Arc<Foo>>>::new(&[]);
        let newv = Arc::new(Foo);
        let (v, loaded) = m.load_or_store("foo".to_owned(), Some(Arc::clone(&newv)));
        assert!(!loaded, "no value was expected");
        assert!(Arc::ptr_eq(&v.expect("value was expected"), &newv), "value does not match");

        let newv2 = Arc::new(Foo);
        let (v, loaded) = m.load_or_store("foo".to_owned(), Some(Arc::clone(&newv2)));
        assert!(loaded, "value was expected");
        assert!(Arc::ptr_eq(&v.expect("value was expected"), &newv), "value does not match");
    }

    #[test]
    fn test_map_load_and_store_nil_value() {
        let m = Map::<String, Option<Arc<()>>>::new(&[]);
        m.load_and_store("foo".to_owned(), None);
        let (v, loaded) = m.load_and_store("foo".to_owned(), None);
        assert!(loaded, "nil value was expected");
        assert_eq!(v, Some(None), "value was not nil");

        let v = m.load(&"foo".to_owned());
        assert!(v.is_some(), "nil value was expected");
        assert!(v.expect("value was expected").is_none(), "value was not nil");
    }

    #[test]
    fn test_map_load_and_store_non_nil_value() {
        let m = Map::<String, i32>::new(&[]);
        let v1 = 1;
        let (v, loaded) = m.load_and_store("foo".to_owned(), v1);
        assert!(!loaded, "no value was expected");
        assert_eq!(v, Some(v1), "value does not match");

        let v2 = 2;
        let (v, loaded) = m.load_and_store("foo".to_owned(), v2);
        assert!(loaded, "value was expected");
        assert_eq!(v, Some(v1), "value does not match");

        let v = m.load(&"foo".to_owned());
        assert!(v.is_some(), "value was expected");
        assert_eq!(v, Some(v2), "value does not match");
    }

    #[test]
    fn test_map_all() {
        let m = Map::<String, i32>::new(&[]);
        m.all(|_key, _value| panic!("got an iteration on empty map"));

        for i in 0..1000 {
            m.store(i.to_string(), i);
        }

        let mut iters = 0;
        let mut met = HashMap::new();
        m.all(|key, value| {
            assert_eq!(*key, value.to_string(), "got unexpected key/value for iteration {iters}");
            *met.entry(key.clone()).or_insert(0) += 1;
            iters += 1;
            true
        });

        assert_eq!(iters, 1000, "got unexpected number of iterations");
        for i in 0..1000 {
            assert_eq!(met.get(&i.to_string()), Some(&1), "all did not iterate correctly over {i}");
        }
    }

    #[test]
    fn test_map_all_break() {
        let m = Map::<String, i32>::new(&[]);
        for i in 0..100 {
            m.store(i.to_string(), i);
        }

        let mut iters = 0;
        m.all(|_key, _value| {
            iters += 1;
            iters != 50
        });

        assert_eq!(iters, 50, "got unexpected number of iterations");
    }

    #[test]
    fn test_map_all_nested_delete() {
        const NUM_ENTRIES: i32 = 256;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }

        m.all(|key, _value| {
            m.delete(key.clone());
            true
        });

        for i in 0..NUM_ENTRIES {
            assert!(m.load(&i.to_string()).is_none(), "value found for {i}");
        }
    }

    #[test]
    fn test_map_range() {
        const NUM_ENTRIES: i32 = 1000;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        let mut iters = 0;
        let mut met = HashMap::new();
        m.range(|key, value| {
            assert_eq!(*key, value.to_string(), "got unexpected key/value for iteration {iters}");
            *met.entry(key.clone()).or_insert(0) += 1;
            iters += 1;
            true
        });
        assert_eq!(iters, NUM_ENTRIES, "got unexpected number of iterations");
        for i in 0..NUM_ENTRIES {
            assert_eq!(met.get(&i.to_string()), Some(&1), "range did not iterate correctly over {i}");
        }
    }

    #[test]
    fn test_map_range_false_returned() {
        let m = Map::<String, i32>::new(&[]);
        for i in 0..100 {
            m.store(i.to_string(), i);
        }
        let mut iters = 0;
        m.range(|key, value| {
            assert_eq!(*key, value.to_string(), "got unexpected key/value for iteration {iters}");
            iters += 1;
            iters != 13
        });
        assert_eq!(iters, 13, "got unexpected number of iterations");
    }

    #[test]
    fn test_map_range_nested_delete() {
        const NUM_ENTRIES: i32 = 256;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        let mut iters = 0;
        m.range(|key, value| {
            assert_eq!(*key, value.to_string(), "got unexpected key/value for iteration {iters}");
            m.delete(key.clone());
            iters += 1;
            true
        });
        for i in 0..NUM_ENTRIES {
            assert!(m.load(&i.to_string()).is_none(), "value found for {i}");
        }
    }

    #[test]
    fn test_map_range_relaxed() {
        const NUM_ENTRIES: i32 = 1000;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        let mut iters = 0;
        let mut met = HashMap::new();
        m.range_relaxed(|key, value| {
            assert_eq!(*key, value.to_string(), "got unexpected key/value for iteration {iters}");
            *met.entry(key.clone()).or_insert(0) += 1;
            iters += 1;
            true
        });
        assert_eq!(iters, NUM_ENTRIES, "got unexpected number of iterations");
        for i in 0..NUM_ENTRIES {
            assert_eq!(met.get(&i.to_string()), Some(&1), "range did not iterate correctly over {i}");
        }
    }

    #[test]
    fn test_map_range_relaxed_false_returned() {
        let m = Map::<String, i32>::new(&[]);
        for i in 0..100 {
            m.store(i.to_string(), i);
        }
        let mut iters = 0;
        m.range_relaxed(|key, value| {
            assert_eq!(*key, value.to_string(), "got unexpected key/value for iteration {iters}");
            iters += 1;
            iters != 13
        });
        assert_eq!(iters, 13, "got unexpected number of iterations");
    }

    #[test]
    fn test_map_range_relaxed_nested_delete() {
        const NUM_ENTRIES: i32 = 256;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        m.range_relaxed(|key, value| {
            assert_eq!(*key, value.to_string(), "got unexpected key/value");
            m.delete(key.clone());
            true
        });
        for i in 0..NUM_ENTRIES {
            assert!(m.load(&i.to_string()).is_none(), "value found for {i}");
        }
    }

    #[test]
    fn test_map_all_relaxed() {
        const NUM_ENTRIES: i32 = 1000;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        let mut iters = 0;
        let mut met = HashMap::new();
        m.all_relaxed(|key, value| {
            assert_eq!(*key, value.to_string(), "got unexpected key/value for iteration {iters}");
            *met.entry(key.clone()).or_insert(0) += 1;
            iters += 1;
            true
        });
        assert_eq!(iters, NUM_ENTRIES, "got unexpected number of iterations");
        for i in 0..NUM_ENTRIES {
            assert_eq!(met.get(&i.to_string()), Some(&1), "all did not iterate correctly over {i}");
        }
    }

    #[test]
    fn test_map_delete_matching() {
        const NUM_ENTRIES: i32 = 1000;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        // Delete even values.
        let deleted = m.delete_matching(|_key, value| (*value % 2 == 0, false));
        assert_eq!(deleted, NUM_ENTRIES / 2, "unexpected number of deleted entries");
        assert_eq!(m.size(), NUM_ENTRIES / 2, "unexpected size");
        // Verify only odd values remain.
        for i in 0..NUM_ENTRIES {
            let ok = m.load(&i.to_string()).is_some();
            if i % 2 == 0 {
                assert!(!ok, "even value {i} should have been deleted");
            } else {
                assert!(ok, "odd value {i} should not have been deleted");
            }
        }
    }

    #[test]
    fn test_map_delete_matching_cancel() {
        const NUM_ENTRIES: i32 = 100;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        // Delete entries and cancel after 10 deletions.
        let mut call_count = 0;
        let deleted = m.delete_matching(|_key, _value| {
            call_count += 1;
            if call_count == 10 {
                return (true, true); // delete this one and cancel
            }
            (true, false)
        });
        assert_eq!(deleted, 10, "unexpected number of deleted entries");
        assert_eq!(call_count, 10, "expected f to be called 10 times");
        assert_eq!(m.size(), NUM_ENTRIES - 10, "unexpected size");
    }

    #[test]
    fn test_map_delete_matching_empty_map() {
        let m = Map::<String, i32>::new(&[]);
        let mut call_count = 0;
        let deleted = m.delete_matching(|_key, _value| {
            call_count += 1;
            (false, false)
        });
        assert_eq!(deleted, 0, "expected 0 deleted on empty map");
        assert_eq!(call_count, 0, "expected f to be called 0 times");
    }

    #[test]
    fn test_map_delete_matching_no_deletions() {
        const NUM_ENTRIES: i32 = 100;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        let mut call_count = 0;
        let deleted = m.delete_matching(|_key, _value| {
            call_count += 1;
            (false, false) // never delete
        });
        assert_eq!(deleted, 0, "expected 0 deleted");
        assert_eq!(call_count, NUM_ENTRIES, "unexpected number of calls");
        assert_eq!(m.size(), NUM_ENTRIES, "unexpected size");
    }

    #[test]
    fn test_map_delete_matching_all_deleted() {
        const NUM_ENTRIES: i32 = 256;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        let deleted = m.delete_matching(|_key, _value| (true, false));
        assert_eq!(deleted, NUM_ENTRIES, "unexpected number of deleted entries");
        assert_eq!(m.size(), 0, "expected size 0");
    }

    #[test]
    fn test_map_load_or_store() {
        const NUM_ENTRIES: i32 = 1000;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        for i in 0..NUM_ENTRIES {
            let (_, loaded) = m.load_or_store(i.to_string(), i);
            assert!(loaded, "value not found for {i}");
        }
    }

    #[test]
    fn test_map_load_or_compute() {
        const NUM_ENTRIES: i32 = 1000;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            let (v, loaded) = m.load_or_compute(i.to_string(), || (i, true));
            assert!(!loaded, "value not computed for {i}");
            assert_eq!(v, None, "values do not match for {i}");
        }
        assert_eq!(m.size(), 0, "zero map size expected");
        for i in 0..NUM_ENTRIES {
            let (v, loaded) = m.load_or_compute(i.to_string(), || (i, false));
            assert!(!loaded, "value not computed for {i}");
            assert_eq!(v, Some(i), "values do not match for {i}");
        }
        for i in 0..NUM_ENTRIES {
            let (v, loaded) = m.load_or_compute(i.to_string(), || panic!("value func invoked"));
            assert!(loaded, "value not loaded for {i}");
            assert_eq!(v, Some(i), "values do not match for {i}");
        }
    }

    #[test]
    fn test_map_load_or_compute_function_called_once() {
        let m = Map::<i32, i32>::new(&[]);
        let mut i = 0i32;
        while i < 100 {
            let key = i;
            m.load_or_compute(key, || {
                let new_value = i;
                i += 1;
                (new_value, false)
            });
        }
        m.range(|k, v| {
            assert_eq!(k, v, "key is not equal to value");
            true
        });
    }

    #[test]
    fn test_map_load_or_compute_existing_key() {
        let m = Map::<String, i32>::new(&[]);
        m.store("key".to_owned(), 42);
        let (v, loaded) = m.load_or_compute("key".to_owned(), || panic!("value func invoked"));
        assert!(loaded, "expected loaded to be true");
        assert_eq!(v, Some(42), "unexpected value");
    }

    #[test]
    fn test_map_of_compute() {
        let m = Map::<String, i32>::new(&[]);
        // Store a new value.
        let (v, ok) = m.compute("foobar".to_owned(), |old_value, loaded| {
            assert_eq!(old_value, None, "oldValue should be None when computing a new value");
            assert!(!loaded, "loaded should be false when computing a new value");
            (42, ComputeOp::UpdateOp)
        });
        assert_eq!(v, Some(42), "v should be 42 when computing a new value");
        assert!(ok, "ok should be true when computing a new value");
        // Update an existing value.
        let (v, ok) = m.compute("foobar".to_owned(), |old_value, loaded| {
            assert_eq!(old_value, Some(42), "oldValue should be 42 when updating the value");
            assert!(loaded, "loaded should be true when updating the value");
            (old_value.expect("old value") + 42, ComputeOp::UpdateOp)
        });
        assert_eq!(v, Some(84), "v should be 84 when updating the value");
        assert!(ok, "ok should be true when updating the value");
        // Check that NoOp doesn't update the value
        let (v, ok) = m.compute("foobar".to_owned(), |_old_value, _loaded| (0, ComputeOp::CancelOp));
        assert_eq!(v, Some(84), "v should be 84 after using NoOp");
        assert!(ok, "ok should be true when updating the value");
        // Delete an existing value.
        let (v, ok) = m.compute("foobar".to_owned(), |old_value, loaded| {
            assert_eq!(old_value, Some(84), "oldValue should be 84 when deleting the value");
            assert!(loaded, "loaded should be true when deleting the value");
            (0, ComputeOp::DeleteOp)
        });
        assert_eq!(v, Some(84), "v should be 84 when deleting the value");
        assert!(!ok, "ok should be false when deleting the value");
        // Try to delete a non-existing value. Notice different key.
        let (v, ok) = m.compute("barbaz".to_owned(), |old_value, loaded| {
            assert_eq!(old_value, None, "oldValue should be None for a non-existing value");
            assert!(!loaded, "loaded should be false for a non-existing value");
            // We're returning a non-zero value, but the map should ignore it.
            (42, ComputeOp::DeleteOp)
        });
        assert_eq!(v, None, "v should be None when trying to delete a non-existing value");
        assert!(!ok, "ok should be false when trying to delete a non-existing value");
        // Try NoOp on a non-existing value
        let (v, ok) = m.compute("barbaz".to_owned(), |old_value, loaded| {
            assert_eq!(old_value, None, "oldValue should be None for a non-existing value");
            assert!(!loaded, "loaded should be false for a non-existing value");
            // We're returning a non-zero value, but the map should ignore it.
            (42, ComputeOp::CancelOp)
        });
        assert_eq!(v, None, "v should be None when trying to delete a non-existing value");
        assert!(!ok, "ok should be false when trying to delete a non-existing value");
    }

    #[test]
    fn test_map_compute_cancel_op_on_overflow_bucket() {
        // This test covers the CancelOp path when inserting into a new overflow bucket.
        // We need to fill buckets completely so that a new key requires creating
        // an overflow bucket, then return CancelOp to abort the insertion.
        const NUM_ATTEMPTS: i32 = 1000;
        const SENTINEL: i32 = 999;

        for attempt in 0..NUM_ATTEMPTS {
            let m = Map::<i32, i32>::new(&[]);
            // Fill the map to create conditions where some bucket chains are full.
            // Insert entries - some will hash to the same bucket creating overflow.
            let num_entries = 100 + (attempt % 100); // Vary the fill level
            for i in 0..num_entries {
                m.store(i, i);
            }

            // Try Compute with CancelOp for new keys.
            let base_key = 10000 + attempt * 1000;
            for i in 0..50 {
                let key = base_key + i;
                let (v, ok) = m.compute(key, |_old_value, loaded| {
                    assert!(!loaded, "key should not exist");
                    (SENTINEL, ComputeOp::CancelOp)
                });
                assert!(!ok, "ok should be false when CancelOp is returned for new key");
                // Both code paths should return zero value for CancelOp
                assert_eq!(v, None, "expected zero value for CancelOp");
                // Verify the key was not inserted
                assert!(m.load(&key).is_none(), "key {key} should not exist after CancelOp");
            }
        }
    }

    #[test]
    fn test_map_store_typed_keys() {
        const N: i32 = 128;
        test_map_store_keys(N, |i| i as i64);
        test_map_store_keys(N, |i| i as u64);
        test_map_store_keys(N, |i| i as i8);
        test_map_store_keys(N, |i| i as u8);
        test_map_store_keys(N, |i| i as i16);
        test_map_store_keys(N, |i| i as u16);
        test_map_store_keys(N, |i| i);
        test_map_store_keys(N, |i| i as u32);
        test_map_store_keys(N, |i| i as usize);

        const NUM_ENTRIES: i32 = 1000;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        for i in 0..NUM_ENTRIES {
            assert_eq!(m.load(&i.to_string()), Some(i), "value not found for {i}");
        }

        let m = Map::<Point, String>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(Point { x: i, y: 42 }, i.to_string());
        }
        for i in 0..NUM_ENTRIES {
            assert_eq!(m.load(&Point { x: i, y: 42 }), Some(i.to_string()), "value not found for {i}");
        }
    }

    #[test]
    fn test_map_store_then_delete_typed_keys() {
        const N: i32 = 1000;
        const N_BYTE: i32 = 200;
        test_map_store_then_delete_keys(N, |i| i as i64);
        test_map_store_then_delete_keys(N, |i| i as u64);
        test_map_store_then_delete_keys(N_BYTE, |i| i as i8);
        test_map_store_then_delete_keys(N_BYTE, |i| i as u8);
        test_map_store_then_delete_keys(N, |i| i as i16);
        test_map_store_then_delete_keys(N, |i| i as u16);
        test_map_store_then_delete_keys(N, |i| i);
        test_map_store_then_delete_keys(N, |i| i as u32);
        test_map_store_then_delete_keys(N, |i| i as usize);

        let m = Map::<String, i32>::new(&[]);
        for i in 0..N {
            m.store(i.to_string(), i);
        }
        for i in 0..N {
            m.delete(i.to_string());
            assert!(m.load(&i.to_string()).is_none(), "value was not expected for {i}");
        }

        let m = Map::<Point, String>::new(&[]);
        for i in 0..N {
            m.store(Point { x: i, y: 42 }, i.to_string());
        }
        for i in 0..N {
            m.delete(Point { x: i, y: 42 });
            assert!(m.load(&Point { x: i, y: 42 }).is_none(), "value was not expected for {i}");
        }
    }

    #[test]
    fn test_map_store_then_load_and_delete_typed_keys() {
        const N: i32 = 1000;
        const N_BYTE: i32 = 200;
        test_map_store_then_load_and_delete_keys(N, |i| i as i64);
        test_map_store_then_load_and_delete_keys(N, |i| i as u64);
        test_map_store_then_load_and_delete_keys(N_BYTE, |i| i as i8);
        test_map_store_then_load_and_delete_keys(N_BYTE, |i| i as u8);
        test_map_store_then_load_and_delete_keys(N, |i| i as i16);
        test_map_store_then_load_and_delete_keys(N, |i| i as u16);
        test_map_store_then_load_and_delete_keys(N, |i| i);
        test_map_store_then_load_and_delete_keys(N, |i| i as u32);
        test_map_store_then_load_and_delete_keys(N, |i| i as usize);

        let m = Map::<String, i32>::new(&[]);
        for i in 0..N {
            m.store(i.to_string(), i);
        }
        for i in 0..N {
            let (v, loaded) = m.load_and_delete(&i.to_string());
            assert!(loaded && v == Some(i), "value was not found or different for {i}");
            assert!(m.load(&i.to_string()).is_none(), "value was not expected for {i}");
        }

        let m = Map::<Point, i32>::new(&[]);
        for i in 0..N {
            m.store(Point { x: 42, y: i }, i);
        }
        for i in 0..N {
            let (_, loaded) = m.load_and_delete(&Point { x: 42, y: i });
            assert!(loaded, "value was not found for {i}");
            assert!(m.load(&Point { x: 42, y: i }).is_none(), "value was not expected for {i}");
        }
    }

    #[test]
    fn test_map_size() {
        const NUM_ENTRIES: i32 = 1000;
        let m = Map::<String, i32>::new(&[]);
        assert_eq!(m.size(), 0, "zero size expected");
        let mut expected_size = 0;
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
            expected_size += 1;
            let size = m.size();
            assert_eq!(size, expected_size, "unexpected size");
            let rsize = size_based_on_typed_range(&m);
            assert_eq!(size, rsize, "size does not match number of entries in Range");
        }
        for i in 0..NUM_ENTRIES {
            m.delete(i.to_string());
            expected_size -= 1;
            let size = m.size();
            assert_eq!(size, expected_size, "unexpected size");
            let rsize = size_based_on_typed_range(&m);
            assert_eq!(size, rsize, "size does not match number of entries in Range");
        }
    }

    #[test]
    fn test_map_clear() {
        const NUM_ENTRIES: i32 = 1000;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        assert_eq!(m.size(), NUM_ENTRIES, "unexpected size");
        m.clear();
        assert_eq!(m.size(), 0, "zero size was expected");
        assert_eq!(size_based_on_typed_range(&m), 0, "zero number of entries in Range expected");
    }

    #[test]
    fn test_new_map_with_presize() {
        const DEFAULT_MIN_MAP_TABLE_CAP: i32 = (DEFAULT_MIN_MAP_TABLE_LEN * ENTRIES_PER_MAP_BUCKET) as i32;
        assert_map_capacity(&Map::<String, String>::new(&[]), DEFAULT_MIN_MAP_TABLE_CAP);
        assert_map_capacity(&Map::<String, String>::new(&[&with_presize(0)]), DEFAULT_MIN_MAP_TABLE_CAP);
        assert_map_capacity(&Map::<String, String>::new(&[&with_presize(-100)]), DEFAULT_MIN_MAP_TABLE_CAP);
        assert_map_capacity(&Map::<String, String>::new(&[&with_presize(500)]), 1280);
        assert_map_capacity(&Map::<i32, i32>::new(&[&with_presize(1_000_000)]), 2621440);
        assert_map_capacity(&Map::<Point, Point>::new(&[&with_presize(100)]), 160);
    }

    #[test]
    fn test_new_map_with_presize_does_not_shrink_below_min_table_len() {
        const MIN_TABLE_LEN: i32 = 1024;
        const NUM_ENTRIES: i32 = (MIN_TABLE_LEN as f64 * ENTRIES_PER_MAP_BUCKET as f64 * MAP_LOAD_FACTOR) as i32;
        let m = Map::<i32, i32>::new(&[&with_presize(NUM_ENTRIES)]);
        for i in 0..2 * NUM_ENTRIES {
            m.store(i, i);
        }

        let stats = m.stats();
        assert!(stats.root_buckets > MIN_TABLE_LEN, "table did not grow");

        for i in 0..2 * NUM_ENTRIES {
            m.delete(i);
        }

        let stats = m.stats();
        assert_eq!(stats.root_buckets, MIN_TABLE_LEN, "table length was different from the minimum");
    }

    #[test]
    fn test_new_map_grow_only_only_shrinks_on_clear() {
        const MIN_TABLE_LEN: i32 = 128;
        const NUM_ENTRIES: i32 = MIN_TABLE_LEN * ENTRIES_PER_MAP_BUCKET as i32;
        let m = Map::<i32, i32>::new(&[&with_presize(NUM_ENTRIES), &with_grow_only()]);

        let stats = m.stats();
        let initial_table_len = stats.root_buckets;

        for i in 0..2 * NUM_ENTRIES {
            m.store(i, i);
        }
        let stats = m.stats();
        let max_table_len = stats.root_buckets;
        assert!(max_table_len > MIN_TABLE_LEN, "table did not grow");

        for i in 0..NUM_ENTRIES {
            m.delete(i);
        }
        let stats = m.stats();
        assert_eq!(stats.root_buckets, max_table_len, "table length was different");

        m.clear();
        let stats = m.stats();
        assert_eq!(stats.root_buckets, initial_table_len, "table length was different");
    }

    #[test]
    fn test_map_resize() {
        let m = Map::<String, i32>::new(&[]);
        const NUM_ENTRIES: i32 = 100_000;

        for i in 0..NUM_ENTRIES {
            m.store(i.to_string(), i);
        }
        let stats = m.stats();
        assert_eq!(stats.size, NUM_ENTRIES, "size was too small");
        let mut expected_capacity =
            (MAP_LOAD_FACTOR + 1.0).round_ties_even() as i32 * stats.root_buckets * ENTRIES_PER_MAP_BUCKET as i32;
        assert!(stats.capacity <= expected_capacity, "capacity was too large");
        assert!(stats.root_buckets > DEFAULT_MIN_MAP_TABLE_LEN as i32, "table was too small");
        assert_ne!(stats.total_growths, 0, "non-zero total growths expected");
        assert_eq!(stats.total_shrinks, 0, "zero total shrinks expected");

        for i in 0..NUM_ENTRIES {
            m.delete(i.to_string());
        }
        let stats = m.stats();
        assert_eq!(stats.size, 0, "zero size was expected");
        expected_capacity = stats.root_buckets * ENTRIES_PER_MAP_BUCKET as i32;
        assert_eq!(stats.capacity, expected_capacity, "capacity was too large");
        assert_eq!(stats.root_buckets, DEFAULT_MIN_MAP_TABLE_LEN as i32, "table was too large");
        assert_ne!(stats.total_shrinks, 0, "non-zero total shrinks expected");
    }

    #[test]
    fn test_map_resize_counter_len_limit() {
        const NUM_ENTRIES: i32 = 1_000_000;
        let m = Map::<String, String>::new(&[]);

        for i in 0..NUM_ENTRIES {
            m.store(format!("foo{i}"), format!("bar{i}"));
        }
        let stats = m.stats();
        assert_eq!(stats.size, NUM_ENTRIES, "size was too small");
        assert_eq!(stats.counter_len, MAX_MAP_COUNTER_LEN as i32, "number of counter stripes was wrong");
    }

    #[test]
    fn test_map_stats() {
        let m = Map::<i32, i32>::new(&[]);

        let stats = m.stats();
        assert_eq!(stats.root_buckets, DEFAULT_MIN_MAP_TABLE_LEN as i32);
        assert_eq!(stats.total_buckets, stats.root_buckets);
        assert_eq!(stats.empty_buckets, stats.root_buckets);
        assert_eq!(stats.capacity, (ENTRIES_PER_MAP_BUCKET * DEFAULT_MIN_MAP_TABLE_LEN) as i32);
        assert_eq!(stats.size, 0);
        assert_eq!(stats.counter, 0);
        assert_eq!(stats.counter_len, 8);

        for i in 0..200 {
            m.store(i, i);
        }

        let stats = m.stats();
        assert_eq!(stats.root_buckets, 2 * DEFAULT_MIN_MAP_TABLE_LEN as i32);
        assert!(stats.total_buckets >= stats.root_buckets);
        assert!(stats.empty_buckets < stats.root_buckets);
        assert!(stats.capacity >= (2 * ENTRIES_PER_MAP_BUCKET * DEFAULT_MIN_MAP_TABLE_LEN) as i32);
        assert_eq!(stats.size, 200);
        assert_eq!(stats.counter, 200);
        assert_eq!(stats.counter_len, 8);
    }

    #[test]
    fn test_to_plain_map_nil_pointer() {
        let pm = to_plain_map::<i32, i32>(None);
        assert!(pm.is_empty(), "got unexpected size of nil map copy");
    }

    #[test]
    fn test_to_plain_map() {
        const NUM_ENTRIES: i32 = 1000;
        let m = Map::<i32, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            m.store(i, i);
        }
        let pm = to_plain_map(Some(&m));
        assert_eq!(pm.len() as i32, NUM_ENTRIES, "got unexpected size of map copy");
        for i in 0..NUM_ENTRIES {
            assert_eq!(pm.get(&i), Some(&i), "unexpected value for key {i}");
        }
    }

    #[test]
    fn test_map_store_then_parallel_delete_does_not_shrink_below_min_table_len() {
        const NUM_ENTRIES: i32 = 1000;
        let m = Arc::new(Map::<i32, i32>::new(&[]));
        for i in 0..NUM_ENTRIES {
            m.store(i, i);
        }

        // Wait for the tasks to finish.
        let handles = vec![
            {
                let m = Arc::clone(&m);
                thread::spawn(move || {
                    for i in 0..NUM_ENTRIES {
                        m.delete(i);
                    }
                })
            },
            {
                let m = Arc::clone(&m);
                thread::spawn(move || {
                    for i in 0..NUM_ENTRIES {
                        m.delete(i);
                    }
                })
            },
        ];
        join_all(handles);

        let stats = m.stats();
        assert_eq!(stats.root_buckets, DEFAULT_MIN_MAP_TABLE_LEN as i32, "table length was different from the minimum");
    }

    fn test_parallel_resize(num_tasks: usize) {
        let m = Arc::new(Map::<i32, i32>::new(&[]));

        // Fill the map to trigger resizing
        const INITIAL_ENTRIES: i32 = 10_000;
        const NEW_ENTRIES: i32 = 5000;
        for i in 0..INITIAL_ENTRIES {
            m.store(i, i * 2);
        }

        // Launch tasks that will encounter resize operations
        let mut handles = Vec::new();
        for task_id in 0..num_tasks as i32 {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                // Perform many operations to trigger resize and helping
                for i in 0..NEW_ENTRIES {
                    let key = task_id * NEW_ENTRIES + i + INITIAL_ENTRIES;
                    m.store(key, key * 2);

                    // Verify the value
                    assert_eq!(m.load(&key), Some(key * 2), "Failed to load key {key}");
                }
            }));
        }
        join_all(handles);

        // Verify all entries are present
        let final_size = m.size();
        let expected_size = INITIAL_ENTRIES + num_tasks as i32 * NEW_ENTRIES;
        assert_eq!(final_size, expected_size, "unexpected size");

        let stats = m.stats();
        assert_ne!(stats.total_growths, 0, "expected at least one table growth");
    }

    #[test]
    fn test_map_parallel_resize() {
        test_parallel_resize(1);
        test_parallel_resize(parallelism() as usize);
        test_parallel_resize(100);
    }

    fn test_parallel_resize_with_same_keys(num_tasks: usize) {
        let m = Arc::new(Map::<i32, i32>::new(&[]));

        // Fill the map to trigger resizing
        const ENTRIES: i32 = 1000;
        for i in 0..ENTRIES {
            m.store(2 * i, 2 * i);
        }

        // Launch tasks that will encounter resize operations
        let mut handles = Vec::new();
        for _ in 0..num_tasks {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for i in 0..10 * ENTRIES {
                    m.store(i, i);
                }
            }));
        }
        join_all(handles);

        // Verify all entries are present
        assert_eq!(m.size(), 10 * ENTRIES, "unexpected size");
        let stats = m.stats();
        assert_ne!(stats.total_growths, 0, "expected at least one table growth");
    }

    #[test]
    fn test_map_parallel_resize_intersecting_keys() {
        test_parallel_resize_with_same_keys(1);
        test_parallel_resize_with_same_keys(parallelism() as usize);
        test_parallel_resize_with_same_keys(100);
    }

    fn test_parallel_shrinking(num_tasks: usize) {
        let m = Arc::new(Map::<i32, i32>::new(&[]));

        // Fill the map to trigger resizing
        const ENTRIES: i32 = 100_000;
        for i in 0..ENTRIES {
            m.store(i, i);
        }

        // Launch tasks that will encounter resize operations
        let mut handles = Vec::new();
        for _ in 0..num_tasks {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for i in 0..ENTRIES {
                    m.delete(i);
                }
            }));
        }
        join_all(handles);

        // Verify all entries are deleted
        assert_eq!(m.size(), 0, "unexpected size");
        let stats = m.stats();
        assert_ne!(stats.total_shrinks, 0, "expected at least one table shrinking");
    }

    #[test]
    fn test_map_parallel_shrinking() {
        test_parallel_shrinking(1);
        test_parallel_shrinking(parallelism() as usize);
    }

    fn parallel_seq_map_grower(m: Arc<Map<i32, i32>>, num_entries: i32, positive: bool) {
        for i in 0..num_entries {
            if positive {
                m.store(i, i);
            } else {
                m.store(-i, -i);
            }
        }
    }

    #[test]
    fn test_map_parallel_growth_grow_only() {
        const NUM_ENTRIES: i32 = 100_000;
        let m = Arc::new(Map::<i32, i32>::new(&[]));
        let handles = vec![
            {
                let m = Arc::clone(&m);
                thread::spawn(move || parallel_seq_map_grower(m, NUM_ENTRIES, true))
            },
            {
                let m = Arc::clone(&m);
                thread::spawn(move || parallel_seq_map_grower(m, NUM_ENTRIES, false))
            },
        ];
        join_all(handles);
        // Verify map contents.
        for i in -NUM_ENTRIES + 1..NUM_ENTRIES {
            assert_eq!(m.load(&i), Some(i), "value not found for {i}");
        }
        assert_eq!(m.size(), 2 * NUM_ENTRIES - 1, "unexpected size");
    }

    fn parallel_rand_map_resizer(m: Arc<Map<String, i32>>, num_iters: i32, num_entries: i32) {
        let mut rng = rand::rng();
        for _ in 0..num_iters {
            let coin = rng.random_range(0..2);
            for j in 0..num_entries {
                if coin == 1 {
                    m.store(j.to_string(), j);
                } else {
                    m.delete(j.to_string());
                }
            }
        }
    }

    #[test]
    fn test_map_parallel_growth() {
        const NUM_ITERS: i32 = 1_000;
        const NUM_ENTRIES: i32 = (2 * ENTRIES_PER_MAP_BUCKET * DEFAULT_MIN_MAP_TABLE_LEN) as i32;
        let m = Arc::new(Map::<String, i32>::new(&[]));
        let handles = vec![
            {
                let m = Arc::clone(&m);
                thread::spawn(move || parallel_rand_map_resizer(m, NUM_ITERS, NUM_ENTRIES))
            },
            {
                let m = Arc::clone(&m);
                thread::spawn(move || parallel_rand_map_resizer(m, NUM_ITERS, NUM_ENTRIES))
            },
        ];
        join_all(handles);
        // Verify map contents.
        for i in 0..NUM_ENTRIES {
            let Some(v) = m.load(&i.to_string()) else {
                // The entry may be deleted and that's ok.
                continue;
            };
            assert_eq!(v, i, "values do not match for {i}");
        }
        let s = m.size();
        assert!(s <= NUM_ENTRIES, "unexpected size: {s}");
        let rs = size_based_on_typed_range(&m);
        assert_eq!(s, rs, "size does not match number of entries in Range");
    }

    fn parallel_rand_map_clearer(m: Arc<Map<String, i32>>, num_iters: i32, num_entries: i32) {
        let mut rng = rand::rng();
        for _ in 0..num_iters {
            let coin = rng.random_range(0..2);
            for j in 0..num_entries {
                if coin == 1 {
                    m.store(j.to_string(), j);
                } else {
                    m.clear();
                }
            }
        }
    }

    #[test]
    fn test_map_parallel_clear() {
        const NUM_ITERS: i32 = 100;
        const NUM_ENTRIES: i32 = 1_000;
        let m = Arc::new(Map::<String, i32>::new(&[]));
        let handles = vec![
            {
                let m = Arc::clone(&m);
                thread::spawn(move || parallel_rand_map_clearer(m, NUM_ITERS, NUM_ENTRIES))
            },
            {
                let m = Arc::clone(&m);
                thread::spawn(move || parallel_rand_map_clearer(m, NUM_ITERS, NUM_ENTRIES))
            },
        ];
        join_all(handles);
        // Verify map size.
        let s = m.size();
        assert!(s <= NUM_ENTRIES, "unexpected size: {s}");
        let rs = size_based_on_typed_range(&m);
        assert_eq!(s, rs, "size does not match number of entries in Range");
    }

    fn parallel_seq_map_storer(m: Arc<Map<String, i32>>, store_each: i32, num_iters: i32, num_entries: i32) {
        for _ in 0..num_iters {
            for j in 0..num_entries {
                if store_each == 0 || j % store_each == 0 {
                    m.store(j.to_string(), j);
                    // Due to atomic snapshots we must see a "<j>"/j pair.
                    assert_eq!(m.load(&j.to_string()), Some(j), "value was not expected for {j}");
                }
            }
        }
    }

    #[test]
    fn test_map_parallel_stores() {
        const NUM_STORERS: i32 = 4;
        const NUM_ITERS: i32 = 10_000;
        const NUM_ENTRIES: i32 = 100;
        let m = Arc::new(Map::<String, i32>::new(&[]));
        let mut handles = Vec::new();
        for i in 0..NUM_STORERS {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || parallel_seq_map_storer(m, i, NUM_ITERS, NUM_ENTRIES)));
        }
        join_all(handles);
        // Verify map contents.
        for i in 0..NUM_ENTRIES {
            assert_eq!(m.load(&i.to_string()), Some(i), "value not found for {i}");
        }
    }

    fn parallel_rand_map_storer(m: Arc<Map<String, i32>>, num_iters: i32, num_entries: i32) {
        let mut rng = rand::rng();
        for _ in 0..num_iters {
            let j = rng.random_range(0..num_entries);
            let (v, loaded) = m.load_or_store(j.to_string(), j);
            if loaded {
                assert_eq!(v, j, "value was not expected for {j}");
            }
        }
    }

    fn parallel_rand_map_deleter(m: Arc<Map<String, i32>>, num_iters: i32, num_entries: i32) {
        let mut rng = rand::rng();
        for _ in 0..num_iters {
            let j = rng.random_range(0..num_entries);
            let (v, loaded) = m.load_and_delete(&j.to_string());
            if loaded {
                assert_eq!(v, Some(j), "value was not expected for {j}");
            }
        }
    }

    fn parallel_map_loader(m: Arc<Map<String, i32>>, num_iters: i32, num_entries: i32) {
        for _ in 0..num_iters {
            for j in 0..num_entries {
                // Due to atomic snapshots we must either see no entry, or a "<j>"/j pair.
                if let Some(v) = m.load(&j.to_string()) {
                    assert_eq!(v, j, "value was not expected for {j}");
                }
            }
        }
    }

    #[test]
    fn test_map_atomic_snapshot() {
        const NUM_ITERS: i32 = 100_000;
        const NUM_ENTRIES: i32 = 100;
        let m = Arc::new(Map::<String, i32>::new(&[]));
        // Update or delete random entry in parallel with loads.
        let handles = vec![
            {
                let m = Arc::clone(&m);
                thread::spawn(move || parallel_rand_map_storer(m, NUM_ITERS, NUM_ENTRIES))
            },
            {
                let m = Arc::clone(&m);
                thread::spawn(move || parallel_rand_map_deleter(m, NUM_ITERS, NUM_ENTRIES))
            },
            {
                let m = Arc::clone(&m);
                thread::spawn(move || parallel_map_loader(m, NUM_ITERS, NUM_ENTRIES))
            },
        ];
        join_all(handles);
    }

    #[test]
    fn test_map_parallel_stores_and_deletes() {
        const NUM_WORKERS: usize = 2;
        const NUM_ITERS: i32 = 100_000;
        const NUM_ENTRIES: i32 = 1000;
        let m = Arc::new(Map::<String, i32>::new(&[]));
        // Update random entry in parallel with deletes.
        let mut handles = Vec::new();
        for _ in 0..NUM_WORKERS {
            let storer = {
                let m = Arc::clone(&m);
                thread::spawn(move || parallel_rand_map_storer(m, NUM_ITERS, NUM_ENTRIES))
            };
            let deleter = {
                let m = Arc::clone(&m);
                thread::spawn(move || parallel_rand_map_deleter(m, NUM_ITERS, NUM_ENTRIES))
            };
            handles.push(storer);
            handles.push(deleter);
        }
        join_all(handles);
    }

    fn parallel_map_computer(m: Arc<Map<u64, u64>>, num_iters: i32, num_entries: u64) {
        for _ in 0..num_iters {
            for j in 0..num_entries {
                m.compute(j, |old_value, _loaded| (old_value.map_or(1, |v| v + 1), ComputeOp::UpdateOp));
            }
        }
    }

    #[test]
    fn test_map_parallel_computes() {
        const NUM_WORKERS: i32 = 4; // Also stands for numEntries.
        const NUM_ITERS: i32 = 10_000;
        let m = Arc::new(Map::<u64, u64>::new(&[]));
        let mut handles = Vec::new();
        for _ in 0..NUM_WORKERS {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || parallel_map_computer(m, NUM_ITERS, NUM_WORKERS as u64)));
        }
        join_all(handles);
        // Verify map contents.
        for i in 0..NUM_WORKERS as u64 {
            let v = m.load(&i);
            assert_eq!(v, Some((NUM_WORKERS * NUM_ITERS) as u64), "value not found for {i}");
        }
    }

    fn parallel_range_map_storer(m: Arc<Map<i32, i32>>, num_entries: i32, stop_flag: Arc<AtomicI64>) {
        loop {
            for i in 0..num_entries {
                m.store(i, i);
            }
            if stop_flag.load(Ordering::SeqCst) != 0 {
                break;
            }
        }
    }

    fn parallel_range_map_deleter(m: Arc<Map<i32, i32>>, num_entries: i32, stop_flag: Arc<AtomicI64>) {
        loop {
            for i in 0..num_entries {
                m.delete(i);
            }
            if stop_flag.load(Ordering::SeqCst) != 0 {
                break;
            }
        }
    }

    #[test]
    fn test_map_parallel_range() {
        const NUM_ENTRIES: i32 = 10_000;
        let m = Arc::new(Map::<i32, i32>::new(&[&with_presize(NUM_ENTRIES)]));
        for i in 0..NUM_ENTRIES {
            m.store(i, i);
        }
        // Start tasks that would be storing and deleting items in parallel.
        let stop_flag = Arc::new(AtomicI64::new(0));
        let handles = vec![
            {
                let m = Arc::clone(&m);
                let stop_flag = Arc::clone(&stop_flag);
                thread::spawn(move || parallel_range_map_storer(m, NUM_ENTRIES, stop_flag))
            },
            {
                let m = Arc::clone(&m);
                let stop_flag = Arc::clone(&stop_flag);
                thread::spawn(move || parallel_range_map_deleter(m, NUM_ENTRIES, stop_flag))
            },
        ];
        // Iterate the map and verify that no duplicate keys were met.
        let mut met = HashMap::new();
        m.range(|key, value| {
            assert_eq!(key, value, "got unexpected value for key {key}");
            *met.entry(*key).or_insert(0) += 1;
            true
        });
        assert!(!met.is_empty(), "no entries were met when iterating");
        for (k, c) in met {
            assert_eq!(c, 1, "met key {k} multiple times");
        }
        // Make sure that both tasks finish.
        stop_flag.store(1, Ordering::SeqCst);
        join_all(handles);
    }

    fn parallel_map_shrinker(
        m: Arc<Map<u64, Option<Arc<Point>>>>,
        num_iters: i32,
        num_entries: u64,
        stop_flag: Arc<AtomicI64>,
    ) {
        for _ in 0..num_iters {
            for j in 0..num_entries {
                let (p, loaded) = m.load_or_store(j, Some(Arc::new(Point { x: j as i32, y: j as i32 })));
                assert!(!loaded, "value was present for {j}: {p:?}");
            }
            for j in 0..num_entries {
                m.delete(j);
            }
        }
        stop_flag.store(1, Ordering::SeqCst);
    }

    fn parallel_map_updater(m: Arc<Map<u64, Option<Arc<Point>>>>, idx: u64, stop_flag: Arc<AtomicI64>) {
        while stop_flag.load(Ordering::SeqCst) != 1 {
            let sleep_us = random::<u64>() % 10;
            let (p, loaded) = m.load_or_store(idx, Some(Arc::new(Point { x: idx as i32, y: idx as i32 })));
            assert!(!loaded, "value was present for {idx}: {p:?}");
            thread::sleep(Duration::from_micros(sleep_us));
            assert!(m.load(&idx).is_some(), "value was not found for {idx}");
            m.delete(idx);
        }
    }

    #[test]
    fn test_map_does_not_lose_entries_on_resize() {
        const NUM_ITERS: i32 = 10_000;
        const NUM_ENTRIES: u64 = 128;
        let m = Arc::new(Map::<u64, Option<Arc<Point>>>::new(&[]));
        let stop_flag = Arc::new(AtomicI64::new(0));
        let handles = vec![
            {
                let m = Arc::clone(&m);
                let stop_flag = Arc::clone(&stop_flag);
                thread::spawn(move || parallel_map_shrinker(m, NUM_ITERS, NUM_ENTRIES, stop_flag))
            },
            {
                let m = Arc::clone(&m);
                let stop_flag = Arc::clone(&stop_flag);
                thread::spawn(move || parallel_map_updater(m, NUM_ENTRIES, stop_flag))
            },
        ];
        join_all(handles);
        // Verify map contents.
        assert_eq!(m.size(), 0, "map is not empty");
    }

    fn test_parallel_range_relaxed(num_tasks: usize) {
        const NUM_ENTRIES: i32 = 10_000;
        const NUM_ITERATIONS: i32 = 50;

        let m = Arc::new(Map::<i32, i32>::new(&[]));
        for i in 0..NUM_ENTRIES {
            m.store(i, i);
        }

        let total_iterations = Arc::new(AtomicI64::new(0));
        let mut handles = Vec::new();

        // Launch tasks that iterate using the relaxed variant.
        for _ in 0..num_tasks / 2 {
            let m = Arc::clone(&m);
            let total_iterations = Arc::clone(&total_iterations);
            handles.push(thread::spawn(move || {
                for _ in 0..NUM_ITERATIONS {
                    m.range_relaxed(|key, value| {
                        assert_eq!(key, value, "key {key} != value {value}");
                        total_iterations.fetch_add(1, Ordering::SeqCst);
                        true
                    });
                }
            }));
        }

        // Launch tasks that modify the map.
        for _ in 0..num_tasks / 2 {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for _ in 0..NUM_ITERATIONS {
                    for i in 0..NUM_ENTRIES {
                        m.store(i, i);
                        if i % 10 == 0 {
                            m.delete(i);
                            m.store(i, i);
                        }
                    }
                }
            }));
        }

        join_all(handles);

        assert_ne!(total_iterations.load(Ordering::SeqCst), 0, "expected some iterations");
    }

    #[test]
    fn test_map_parallel_range_relaxed() {
        test_parallel_range_relaxed(2);
        test_parallel_range_relaxed(parallelism() as usize);
    }

    fn test_parallel_delete_matching(num_tasks: usize) {
        const NUM_ENTRIES: i32 = 10_000;
        const NUM_ITERATIONS: i32 = 50;

        let m = Arc::new(Map::<i32, i32>::new(&[]));
        for i in 0..NUM_ENTRIES {
            m.store(i, i);
        }

        let total_deleted = Arc::new(AtomicI64::new(0));
        let mut handles = Vec::new();

        // Launch tasks that delete even numbers.
        for _ in 0..num_tasks / 2 {
            let m = Arc::clone(&m);
            let total_deleted = Arc::clone(&total_deleted);
            handles.push(thread::spawn(move || {
                for _ in 0..NUM_ITERATIONS {
                    let deleted = m.delete_matching(|key, _value| (key % 2 == 0, false));
                    total_deleted.fetch_add(i64::from(deleted), Ordering::SeqCst);
                }
            }));
        }

        // Launch tasks that re-add entries.
        for _ in 0..num_tasks / 2 {
            let m = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for _ in 0..NUM_ITERATIONS {
                    for i in 0..NUM_ENTRIES {
                        m.store(i, i);
                    }
                }
            }));
        }

        join_all(handles);

        // Verify map is in consistent state.
        let size = m.size();
        let mut range_count = 0;
        m.range(|key, value| {
            assert_eq!(key, value, "key {key} != value {value}");
            range_count += 1;
            true
        });
        assert_eq!(size, range_count, "size != range count");
        assert_ne!(total_deleted.load(Ordering::SeqCst), 0, "expected some deletions");
    }

    #[test]
    fn test_map_parallel_delete_matching() {
        test_parallel_delete_matching(2);
        test_parallel_delete_matching(parallelism() as usize);
    }

    #[test]
    fn test_map_delete_matching_concurrent_resize() {
        // This test attempts to cover the resize paths in DeleteMatching:
        // 1. Resize in progress during DeleteMatching iteration
        // 2. Table changed (resize completed) during DeleteMatching iteration
        //
        // 100 iterations keeps the suite fast.
        const NUM_ITERATIONS: i32 = 100;
        const NUM_ENTRIES: i32 = 100;

        for _ in 0..NUM_ITERATIONS {
            // Start with minimal size to maximize resize frequency
            let m = Arc::new(Map::<i32, i32>::new(&[]));
            // Pre-fill just enough to have entries
            for i in 0..NUM_ENTRIES {
                m.store(i, i);
            }

            let mut handles = Vec::new();

            // Tasks that trigger resize by adding many new entries
            for _ in 0..8 {
                let m = Arc::clone(&m);
                handles.push(thread::spawn(move || {
                    for i in NUM_ENTRIES..NUM_ENTRIES * 10 {
                        m.store(i, i);
                    }
                }));
            }

            // Tasks that call DeleteMatching repeatedly during resize
            for _ in 0..8 {
                let m = Arc::clone(&m);
                handles.push(thread::spawn(move || {
                    for _ in 0..10 {
                        m.delete_matching(|key, _value| (key % 5 == 0, false));
                    }
                }));
            }

            join_all(handles);

            // Verify map consistency
            let size = m.size();
            let mut range_count = 0;
            m.range(|_key, _value| {
                range_count += 1;
                true
            });
            assert_eq!(size, range_count, "size != range count");
        }
    }

    #[test]
    fn test_map_load_or_compute_concurrent_existing_key() {
        // This test attempts to cover the race condition where:
        // 1. LoadOrCompute's fast path doesn't find the key
        // 2. Another task inserts the key
        // 3. LoadOrCompute acquires the lock and finds the key
        const NUM_ITERS: i32 = 1000;
        for _ in 0..NUM_ITERS {
            let m = Arc::new(Map::<i32, i32>::new(&[]));
            let handles = vec![
                {
                    let m = Arc::clone(&m);
                    thread::spawn(move || m.store(1, 42))
                },
                {
                    let m = Arc::clone(&m);
                    thread::spawn(move || {
                        m.load_or_compute(1, || (100, false));
                    })
                },
            ];
            join_all(handles);
            let v = m.load(&1);
            let v = v.expect("key should exist");
            assert!(v == 42 || v == 100, "unexpected value: {v}");
        }
    }
}

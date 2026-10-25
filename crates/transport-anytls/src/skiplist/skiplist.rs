//! A skip list implementation built around an arena of nodes and an explicit level index, with
//! these optimizations:
//!
//!  - adaptive level
//!  - a shorter search over the previous nodes when the key already exists.
//!  - fewer memory allocations
//!  - a richer API.
//!
//! etc.

use std::collections::HashMap;
use std::fmt;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::contianer::{Container, Map};
use super::skiplist_newnode::new_skip_list_node;
use super::types::CompareFn;

pub(crate) const SKIP_LIST_MAX_LEVEL: usize = 40;

/// A probabilistic alternative to a balanced tree: the same expected asymptotic time bounds, but
/// simpler, faster and smaller.
///
/// See <https://en.wikipedia.org/wiki/Skip_list> for more details.
///
/// Nodes live in an arena owned by the list and are linked by arena index rather than raw pointer;
/// `head_next` holds the head's level array (standing in for an inline head node), and a freed
/// slot is handed out by the next insertion.
pub struct SkipList<K: 'static, V: 'static> {
    level: usize,
    len: usize,
    head_next: Vec<Option<usize>>,
    prevs_cache: Vec<Option<usize>>,
    nodes: Vec<Option<SkipListNode<K, V>>>,
    free_nodes: Vec<usize>,
    rander: StdRng,
    impl_: Box<dyn SkipListImpl<K, V>>,
}

/// Creates a new `SkipList` keyed by ordered values.
#[must_use]
pub fn new_skip_list<K: PartialOrd + 'static, V: 'static>() -> SkipList<K, V> {
    SkipList::with_impl(Box::new(SkipListOrdered))
}

/// Creates a new `SkipList` populated from a map.
#[expect(
    clippy::implicit_hasher,
    reason = "the signature is public and every caller passes the default `HashMap`; generalizing the hasher would widen it for no caller"
)]
#[must_use]
pub fn new_skip_list_from_map<K: PartialOrd + Clone + 'static, V: Clone + 'static>(
    m: &HashMap<K, V>,
) -> SkipList<K, V> {
    let mut sl = new_skip_list::<K, V>();
    for (k, v) in m {
        sl.insert(k.clone(), v.clone());
    }
    sl
}

/// Creates a new `SkipList` using the supplied `CompareFn`.
pub fn new_skip_list_func<K: 'static, V: 'static>(key_cmp: CompareFn<K>) -> SkipList<K, V> {
    SkipList::with_impl(Box::new(SkipListFunc { key_cmp }))
}

impl<K: 'static, V: 'static> SkipList<K, V> {
    /// Whether the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The number of elements in the list.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Removes every element from the list.
    pub fn clear(&mut self) {
        for next in &mut self.head_next {
            *next = None;
        }
        // The arena owns the nodes, so clearing it frees the unlinked ones.
        self.nodes.clear();
        self.free_nodes.clear();
        self.level = 1;
        self.len = 0;
    }

    /// Returns an iterator over the list.
    #[must_use]
    pub fn iterate(&self) -> SkipListIterator<'_, K, V> {
        SkipListIterator { sl: self, node: self.head_next.first().copied().flatten(), end: None }
    }

    /// Inserts a key-value pair into the list.
    /// When the key is already present its value is replaced.
    pub fn insert(&mut self, key: K, value: V) {
        let mut prevs = std::mem::take(&mut self.prevs_cache);
        let Some(prevs_tail) = prevs.get_mut(..self.level) else {
            self.prevs_cache = prevs;
            return;
        };
        let node = self.impl_.find_insert_point(self, &key, prevs_tail);

        if let Some(id) = node {
            // Already exist, update the value
            self.node_mut(id).value = value;
            self.prevs_cache = prevs;
            return;
        }

        let level = self.random_level();
        let id = self.alloc_node(level, key, value);

        let min_level = self.level.min(level);
        for (i, prev) in prevs.iter().take(min_level).enumerate() {
            let next = self.next_at(*prev, i);
            self.set_next(Some(id), i, next);
            self.set_next(*prev, i, Some(id));
        }

        if level > self.level {
            for next in self.head_next.iter_mut().take(level).skip(self.level) {
                *next = Some(id);
            }
            self.level = level;
        }

        self.len += 1;
        self.prevs_cache = prevs;
    }

    /// Returns the value associated with `key`, or `None` when the key is absent from the
    /// list.
    pub fn find(&self, key: &K) -> Option<&V> {
        let node = self.impl_.find_node(self, key)?;
        Some(&self.node(node).value)
    }

    /// Whether the list contains `key`.
    pub fn has(&self, key: &K) -> bool {
        self.impl_.find_node(self, key).is_some()
    }

    /// Returns an iterator to the first element that is not less than `value`
    /// (that is, greater than or equal to), or the end iterator when no such element
    /// exists.
    pub fn lower_bound(&self, key: &K) -> SkipListIterator<'_, K, V> {
        SkipListIterator { sl: self, node: self.impl_.lower_bound(self, key), end: None }
    }

    /// Returns an iterator to the first element strictly greater than `value`, or the end
    /// iterator when no such element exists.
    pub fn upper_bound(&self, key: &K) -> SkipListIterator<'_, K, V> {
        SkipListIterator { sl: self, node: self.impl_.upper_bound(self, key), end: None }
    }

    /// Returns an iterator over `[first, last)`, where `last` is excluded.
    ///
    /// The range ends at the first key strictly greater than `last`, so an element equal to `last`
    /// is still yielded.
    pub fn find_range(&self, first: &K, last: &K) -> SkipListIterator<'_, K, V> {
        SkipListIterator {
            sl: self,
            node: self.impl_.lower_bound(self, first),
            end: self.impl_.upper_bound(self, last),
        }
    }

    /// Removes the key-value pair associated with `key`, reporting whether the key was present.
    pub fn remove(&mut self, key: &K) -> bool {
        let mut prevs = std::mem::take(&mut self.prevs_cache);
        let Some(prevs_tail) = prevs.get_mut(..self.level) else {
            self.prevs_cache = prevs;
            return false;
        };
        let node = self.impl_.find_remove_point(self, key, prevs_tail);
        let Some(id) = node else {
            self.prevs_cache = prevs;
            return false;
        };

        let next = std::mem::take(&mut self.node_mut(id).next);
        for (i, v) in next.iter().enumerate() {
            if let Some(&prev) = prevs.get(i) {
                self.set_next(prev, i, *v);
            }
        }
        self.free_node(id);

        while self.level > 1 && self.head_next.get(self.level - 1).copied().flatten().is_none() {
            self.level -= 1;
        }
        self.len -= 1;
        self.prevs_cache = prevs;
        true
    }

    /// Calls `op` on every key-value pair in the list.
    pub fn for_each(&self, mut op: impl FnMut(&K, &V)) {
        let mut e = self.head_next.first().copied().flatten();
        while let Some(id) = e {
            let node = self.node(id);
            e = node.next.first().copied().flatten();
            op(&node.key, &node.value);
        }
    }

    /// Calls `op` on every entry, allowing the value to be mutated.
    pub fn for_each_mutable(&mut self, mut op: impl FnMut(&K, &mut V)) {
        let mut e = self.head_next.first().copied().flatten();
        while let Some(id) = e {
            let node = self.node_mut(id);
            e = node.next.first().copied().flatten();
            op(&node.key, &mut node.value);
        }
    }

    /// Calls `op` on every entry, stopping early when `op` returns false.
    pub fn for_each_if(&self, mut op: impl FnMut(&K, &V) -> bool) {
        let mut e = self.head_next.first().copied().flatten();
        while let Some(id) = e {
            let node = self.node(id);
            e = node.next.first().copied().flatten();
            if !op(&node.key, &node.value) {
                return;
            }
        }
    }

    /// Calls `op` on every entry with a mutable value, stopping early when `op` returns false.
    pub fn for_each_mutable_if(&mut self, mut op: impl FnMut(&K, &mut V) -> bool) {
        let mut e = self.head_next.first().copied().flatten();
        while let Some(id) = e {
            let node = self.node_mut(id);
            e = node.next.first().copied().flatten();
            if !op(&node.key, &mut node.value) {
                return;
            }
        }
    }
}

impl<K: 'static, V: 'static> Container for SkipList<K, V> {
    fn is_empty(&self) -> bool {
        Self::is_empty(self)
    }

    fn len(&self) -> usize {
        Self::len(self)
    }

    fn clear(&mut self) {
        Self::clear(self);
    }
}

impl<K: 'static, V: 'static> Map<K, V> for SkipList<K, V> {
    fn has(&self, key: &K) -> bool {
        Self::has(self, key)
    }

    fn find(&self, key: &K) -> Option<&V> {
        Self::find(self, key)
    }

    fn insert(&mut self, key: K, value: V) {
        Self::insert(self, key, value);
    }

    fn remove(&mut self, key: &K) -> bool {
        Self::remove(self, key)
    }

    fn for_each(&self, op: &mut dyn FnMut(&K, &V)) {
        Self::for_each(self, op);
    }

    fn for_each_if(&self, op: &mut dyn FnMut(&K, &V) -> bool) {
        Self::for_each_if(self, op);
    }

    fn for_each_mutable(&mut self, op: &mut dyn FnMut(&K, &mut V)) {
        Self::for_each_mutable(self, op);
    }

    fn for_each_mutable_if(&mut self, op: &mut dyn FnMut(&K, &mut V) -> bool) {
        Self::for_each_mutable_if(self, op);
    }
}

impl<K: fmt::Debug + 'static, V: fmt::Debug + 'static> fmt::Debug for SkipList<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SkipList").field("level", &self.level).field("len", &self.len).finish_non_exhaustive()
    }
}

/// `SkipList` implementation.
impl<K: 'static, V: 'static> SkipList<K, V> {
    fn with_impl(impl_: Box<dyn SkipListImpl<K, V>>) -> Self {
        // Constructing the struct seeds the rng and leaves the caches empty.
        let mut sl = Self {
            level: 0,
            len: 0,
            head_next: Vec::new(),
            prevs_cache: Vec::new(),
            nodes: Vec::new(),
            free_nodes: Vec::new(),
            rander: StdRng::seed_from_u64(0),
            impl_,
        };
        sl.init();
        sl
    }

    fn init(&mut self) {
        self.level = 1;
        // #nosec G404 -- This is not a security condition
        self.rander = StdRng::seed_from_u64(unix_seconds());
        self.prevs_cache = vec![None; SKIP_LIST_MAX_LEVEL];
        self.head_next = vec![None; SKIP_LIST_MAX_LEVEL];
    }

    fn random_level(&mut self) -> usize {
        let total = (1u64 << SKIP_LIST_MAX_LEVEL) - 1; // 2^n-1
        let k = self.rander.random::<u64>() % total;
        let mut level = SKIP_LIST_MAX_LEVEL - (64 - k.leading_zeros() as usize) + 1;
        // Since levels are randomly generated, most should be less than log2(s.len).
        // Then make a limit according to sl.len to avoid unexpectedly large value.
        while level > 3 && (1usize << (level - 3)) > self.len {
            level -= 1;
        }

        level
    }

    fn next_at(&self, node: Option<usize>, level: usize) -> Option<usize> {
        node.map_or_else(
            || self.head_next.get(level).copied().flatten(),
            |id| self.node(id).next.get(level).copied().flatten(),
        )
    }

    fn set_next(&mut self, node: Option<usize>, level: usize, value: Option<usize>) {
        let slot = match node {
            Some(id) => self.node_mut(id).next.get_mut(level),
            None => self.head_next.get_mut(level),
        };
        if let Some(slot) = slot {
            *slot = value;
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "the accessor's signature is infallible, and every `id` comes from `alloc_node`, which hands out slots the arena holds"
    )]
    fn node(&self, id: usize) -> &SkipListNode<K, V> {
        self.nodes.get(id).and_then(Option::as_ref).expect("skip list slot holds a live node")
    }

    #[expect(
        clippy::expect_used,
        reason = "the accessor's signature is infallible, and every `id` comes from `alloc_node`, which hands out slots the arena holds"
    )]
    fn node_mut(&mut self, id: usize) -> &mut SkipListNode<K, V> {
        self.nodes.get_mut(id).and_then(Option::as_mut).expect("skip list slot holds a live node")
    }

    fn alloc_node(&mut self, level: usize, key: K, value: V) -> usize {
        let node = new_skip_list_node(level, key, value);
        let Some(id) = self.free_nodes.pop() else {
            self.nodes.push(Some(node));
            return self.nodes.len() - 1;
        };
        let Some(slot) = self.nodes.get_mut(id) else {
            self.nodes.push(Some(node));
            return self.nodes.len() - 1;
        };
        *slot = Some(node);
        id
    }

    fn free_node(&mut self, id: usize) {
        let Some(slot) = self.nodes.get_mut(id) else {
            return;
        };
        *slot = None;
        self.free_nodes.push(id);
    }
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A node of a [`SkipList`]; `next[level]` is the arena slot of the node that follows at that level,
/// or `None` at the end of the level.
pub(crate) struct SkipListNode<K, V> {
    pub(crate) key: K,
    pub(crate) value: V,
    pub(crate) next: Vec<Option<usize>>,
}

/// An iterator over a [`SkipList`]; `end` is the node that terminates the range.
#[derive(Debug)]
pub struct SkipListIterator<'a, K: 'static, V: 'static> {
    sl: &'a SkipList<K, V>,
    node: Option<usize>,
    end: Option<usize>,
}

impl<K: 'static, V: 'static> SkipListIterator<'_, K, V> {
    /// Whether the iterator points to the end of the range.
    #[must_use]
    pub fn is_not_end(&self) -> bool {
        self.node != self.end
    }

    /// Advances to the next element.
    pub fn move_to_next(&mut self) {
        #[expect(
            clippy::expect_used,
            reason = "the iterator contract is `is_not_end` before `move_to_next`, and the signature has no failure channel"
        )]
        let id = self.node.expect("move_to_next called at the end of the iteration");
        self.node = self.sl.node(id).next.first().copied().flatten();
    }
}

impl<K: Clone + 'static, V: 'static> SkipListIterator<'_, K, V> {
    /// The key of the element.
    #[must_use]
    pub fn key(&self) -> K {
        #[expect(
            clippy::expect_used,
            reason = "the iterator contract is `is_not_end` before `key`, and the signature has no failure channel"
        )]
        let id = self.node.expect("key called at the end of the iteration");
        self.sl.node(id).key.clone()
    }
}

impl<K: 'static, V: Clone + 'static> SkipListIterator<'_, K, V> {
    /// The value of the current element.
    #[must_use]
    pub fn value(&self) -> V {
        #[expect(
            clippy::expect_used,
            reason = "the iterator contract is `is_not_end` before `value`, and the signature has no failure channel"
        )]
        let id = self.node.expect("value called at the end of the iteration");
        self.sl.node(id).value.clone()
    }
}

impl<K: 'static, V: Clone + 'static> super::contianer::Iterator<V> for SkipListIterator<'_, K, V> {
    fn is_not_end(&self) -> bool {
        SkipListIterator::is_not_end(self)
    }

    fn move_to_next(&mut self) {
        SkipListIterator::move_to_next(self);
    }

    fn value(&self) -> V {
        SkipListIterator::value(self)
    }
}

impl<K: Clone + 'static, V: Clone + 'static> super::contianer::MapIterator<K, V> for SkipListIterator<'_, K, V> {
    fn key(&self) -> K {
        SkipListIterator::key(self)
    }
}

/// The key-comparison strategy behind a `SkipList`: one implementation covers `Ordered` keys
/// and another covers an arbitrary `CompareFn`.
///
/// A `CompareFn` can compare ordered keys too, but a dedicated implementation is much faster.
/// The list itself is not a trait, which keeps the type-independent methods shared.
/// Because these methods are called directly rather than through a trait object, they are also
/// much faster.
///
/// The implementations embed `SkipList`; a Rust value cannot own the list it is embedded in, so
/// every method takes the list it works on as an argument.
trait SkipListImpl<K: 'static, V: 'static>: Send + Sync {
    fn find_node(&self, sl: &SkipList<K, V>, key: &K) -> Option<usize>;
    fn lower_bound(&self, sl: &SkipList<K, V>, key: &K) -> Option<usize>;
    fn upper_bound(&self, sl: &SkipList<K, V>, key: &K) -> Option<usize>;
    fn find_insert_point(&self, sl: &SkipList<K, V>, key: &K, prevs: &mut [Option<usize>]) -> Option<usize>;
    fn find_remove_point(&self, sl: &SkipList<K, V>, key: &K, prevs: &mut [Option<usize>]) -> Option<usize>;
}

/// `SkipListOrdered`, the implementation used with ordered keys.
struct SkipListOrdered;

impl<K: PartialOrd + 'static, V: 'static> SkipListImpl<K, V> for SkipListOrdered {
    fn find_node(&self, sl: &SkipList<K, V>, key: &K) -> Option<usize> {
        Self::do_find_node(sl, key, true)
    }

    fn lower_bound(&self, sl: &SkipList<K, V>, key: &K) -> Option<usize> {
        Self::do_find_node(sl, key, false)
    }

    fn upper_bound(&self, sl: &SkipList<K, V>, key: &K) -> Option<usize> {
        let node = self.lower_bound(sl, key);
        if let Some(id) = node {
            if sl.node(id).key == *key {
                return sl.next_at(node, 0);
            }
        }
        node
    }

    /// Returns the existing node when the key is present, or fills `prevs` with the preceding
    /// nodes and returns `None` when the key is absent.
    fn find_insert_point(&self, sl: &SkipList<K, V>, key: &K, prevs: &mut [Option<usize>]) -> Option<usize> {
        let mut prev = None;
        for i in (0..sl.level).rev() {
            let mut next = sl.next_at(prev, i);
            while let Some(id) = next {
                let next_key = &sl.node(id).key;
                if next_key == key {
                    // The key is already present, so `prevs` is unused and the search stops.
                    return Some(id);
                }
                if next_key > key {
                    // All other node in this level must be greater than the key,
                    // search the next level.
                    break;
                }
                prev = next;
                next = sl.next_at(prev, i);
            }
            if let Some(slot) = prevs.get_mut(i) {
                *slot = prev;
            }
        }
        None
    }

    /// Finds the node matching the key together with its predecessors.
    fn find_remove_point(&self, sl: &SkipList<K, V>, key: &K, prevs: &mut [Option<usize>]) -> Option<usize> {
        Self::find_prev_nodes(sl, key, prevs);
        sl.next_at(prevs.first().copied().flatten(), 0).filter(|id| sl.node(*id).key == *key)
    }
}

/// `SkipListOrdered` implementation.
impl SkipListOrdered {
    fn do_find_node<K: PartialOrd + 'static, V: 'static>(sl: &SkipList<K, V>, key: &K, eq: bool) -> Option<usize> {
        // This does the work of both the node lookup and the lower bound, selected by `eq`.
        // Threading the control value through is ugly, but faster than testing the node again
        // in the caller.
        let mut prev = None;
        for i in (0..sl.level).rev() {
            let mut cur = sl.next_at(prev, i);
            while let Some(id) = cur {
                let cur_key = &sl.node(id).key;
                if cur_key == key {
                    return Some(id);
                }
                if cur_key > key {
                    // All other node in this level must be greater than the key,
                    // search the next level.
                    break;
                }
                prev = cur;
                cur = sl.next_at(prev, i);
            }
        }
        if eq {
            return None;
        }
        sl.next_at(prev, 0)
    }

    fn find_prev_nodes<K: PartialOrd + 'static, V: 'static>(sl: &SkipList<K, V>, key: &K, prevs: &mut [Option<usize>]) {
        let mut prev = None;
        for i in (0..sl.level).rev() {
            let mut next = sl.next_at(prev, i);
            while let Some(id) = next {
                if sl.node(id).key >= *key {
                    break;
                }
                prev = next;
                next = sl.next_at(prev, i);
            }
            if let Some(slot) = prevs.get_mut(i) {
                *slot = prev;
            }
        }
    }
}

/// `SkipListFunc`, the implementation that compares keys with a `CompareFn`.
struct SkipListFunc<K: 'static> {
    key_cmp: CompareFn<K>,
}

impl<K: 'static, V: 'static> SkipListImpl<K, V> for SkipListFunc<K> {
    fn find_node(&self, sl: &SkipList<K, V>, key: &K) -> Option<usize> {
        self.lower_bound(sl, key).filter(|id| (self.key_cmp)(&sl.node(*id).key, key) == 0)
    }

    fn lower_bound(&self, sl: &SkipList<K, V>, key: &K) -> Option<usize> {
        let mut prev = None;
        for i in (0..sl.level).rev() {
            let mut cur = sl.next_at(prev, i);
            while let Some(id) = cur {
                let cmp_ret = (self.key_cmp)(&sl.node(id).key, key);
                if cmp_ret == 0 {
                    return Some(id);
                }
                if cmp_ret > 0 {
                    break;
                }
                prev = cur;
                cur = sl.next_at(prev, i);
            }
        }
        sl.next_at(prev, 0)
    }

    fn upper_bound(&self, sl: &SkipList<K, V>, key: &K) -> Option<usize> {
        let node = self.lower_bound(sl, key);
        if let Some(id) = node {
            if (self.key_cmp)(&sl.node(id).key, key) == 0 {
                return sl.next_at(node, 0);
            }
        }
        node
    }

    /// Returns the existing node when the key is present, or fills `prevs` with the preceding
    /// nodes and returns `None` when the key is absent.
    fn find_insert_point(&self, sl: &SkipList<K, V>, key: &K, prevs: &mut [Option<usize>]) -> Option<usize> {
        let mut prev = None;
        for i in (0..sl.level).rev() {
            let mut cur = sl.next_at(prev, i);
            while let Some(id) = cur {
                let r = (self.key_cmp)(&sl.node(id).key, key);
                if r == 0 {
                    // The key is already present, so `prevs` is unused and the search stops.
                    return Some(id);
                }
                if r > 0 {
                    // All other node in this level must be greater than the key,
                    // search the next level.
                    break;
                }
                prev = cur;
                cur = sl.next_at(prev, i);
            }
            if let Some(slot) = prevs.get_mut(i) {
                *slot = prev;
            }
        }
        None
    }

    /// Finds the node matching the key together with its predecessors.
    fn find_remove_point(&self, sl: &SkipList<K, V>, key: &K, prevs: &mut [Option<usize>]) -> Option<usize> {
        self.find_prev_nodes(sl, key, prevs);
        sl.next_at(prevs.first().copied().flatten(), 0).filter(|id| (self.key_cmp)(&sl.node(*id).key, key) == 0)
    }
}

/// `SkipListFunc` implementation.
impl<K: 'static> SkipListFunc<K> {
    fn find_prev_nodes<V: 'static>(&self, sl: &SkipList<K, V>, key: &K, prevs: &mut [Option<usize>]) {
        let mut prev = None;
        for i in (0..sl.level).rev() {
            let mut next = sl.next_at(prev, i);
            while let Some(id) = next {
                if (self.key_cmp)(&sl.node(id).key, key) >= 0 {
                    break;
                }
                prev = next;
                next = sl.next_at(prev, i);
            }
            if let Some(slot) = prevs.get_mut(i) {
                *slot = prev;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;

    fn lcg(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *seed >> 33
    }

    fn entries(sl: &SkipList<u64, u64>) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut it = sl.iterate();
        while it.is_not_end() {
            out.push((it.key(), it.value()));
            it.move_to_next();
        }
        out
    }

    #[test]
    fn insert_find_remove_and_iteration_match_a_btreemap() {
        let mut sl = new_skip_list::<u64, u64>();
        let mut bt = BTreeMap::new();
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..20_000 {
            let key = lcg(&mut seed) % 500;
            let value = lcg(&mut seed);
            match lcg(&mut seed) % 4 {
                0 => {
                    sl.insert(key, value);
                    bt.insert(key, value);
                }
                1 => assert_eq!(sl.remove(&key), bt.remove(&key).is_some()),
                _ => {
                    assert_eq!(sl.find(&key), bt.get(&key));
                    assert_eq!(sl.has(&key), bt.contains_key(&key));
                }
            }
            assert_eq!(sl.len(), bt.len());
        }

        let expected: Vec<(u64, u64)> = bt.iter().map(|(k, v)| (*k, *v)).collect();
        assert_eq!(entries(&sl), expected);

        // The range ends at the first key strictly greater than `last`, so `last` is included.
        let range: Vec<(u64, u64)> = {
            let mut out = Vec::new();
            let mut it = sl.find_range(&100, &200);
            while it.is_not_end() {
                out.push((it.key(), it.value()));
                it.move_to_next();
            }
            out
        };
        assert_eq!(range, expected.iter().filter(|(k, _)| (100..=200).contains(k)).copied().collect::<Vec<_>>());

        let mut bumped = Vec::new();
        sl.for_each_mutable(|k, v| {
            *v = v.wrapping_add(1);
            bumped.push(*k);
        });
        assert_eq!(bumped, expected.iter().map(|(k, _)| *k).collect::<Vec<_>>());

        for (key, _) in &expected {
            assert!(sl.remove(key));
        }
        assert!(sl.is_empty());
        assert!(!sl.iterate().is_not_end());
    }

    #[test]
    fn a_custom_comparator_orders_the_list() {
        let descending = Arc::new(|a: &u64, b: &u64| match a.cmp(b) {
            std::cmp::Ordering::Less => 1,
            std::cmp::Ordering::Greater => -1,
            std::cmp::Ordering::Equal => 0,
        });
        let mut sl = new_skip_list_func::<u64, u64>(descending);
        for key in 0..64u64 {
            sl.insert(key, key);
        }
        let keys: Vec<u64> = entries(&sl).into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, (0..64u64).rev().collect::<Vec<_>>());
        assert!(sl.has(&7));
        assert!(sl.remove(&7));
        assert!(!sl.has(&7));
    }
}

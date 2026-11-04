//! Node construction for the skip list; the level is clamped to the list's level range.

use super::skiplist::{SkipListNode, SKIP_LIST_MAX_LEVEL};

/// Creates a node holding the given key and value, with a `next` slot at every level up to the
/// node's own level.
///
/// The level is clamped to `1..=SKIP_LIST_MAX_LEVEL`, so `next` is never empty and never longer
/// than the list's own level array.
pub(crate) fn new_skip_list_node<K, V>(level: usize, key: K, value: V) -> SkipListNode<K, V> {
    SkipListNode { key, value, next: vec![None; level.clamp(1, SKIP_LIST_MAX_LEVEL)] }
}

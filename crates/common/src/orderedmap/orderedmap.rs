use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;

/// One entry of an [`OrderedMap`].
///
/// Callers get a cursor that borrows the map and addresses the entry by node index, rather than
/// a pointer to the map's list element walked with `next`/`prev`.
#[derive(Debug)]
pub struct Pair<'a, K, V> {
    map: &'a OrderedMap<K, V>,
    index: usize,
}

impl<'a, K, V> Pair<'a, K, V> {
    /// The key this pair was inserted with.
    #[must_use]
    pub fn key(&self) -> &'a K {
        &self.map.node(self.index).key
    }

    /// The value currently associated with the key.
    #[must_use]
    pub fn value(&self) -> &'a V {
        &self.map.node(self.index).value
    }

    /// The pair inserted after this one, or `None` at the newest end.
    #[must_use]
    pub fn next(&self) -> Option<Self> {
        let map = self.map;
        map.node(self.index).next.map(|index| Pair { map, index })
    }

    /// The pair inserted before this one, or `None` at the oldest end.
    #[must_use]
    pub fn prev(&self) -> Option<Self> {
        let map = self.map;
        map.node(self.index).prev.map(|index| Pair { map, index })
    }
}

/// One element of the insertion-order list. `prev`/`next` index into [`OrderedMap::nodes`] rather
/// than holding `*list.Element` pointers; dropped slots are recycled through `free`.
#[derive(Debug, Clone)]
struct Node<K, V> {
    key: K,
    value: V,
    prev: Option<usize>,
    next: Option<usize>,
}

/// a map that also keeps track of the order keys were inserted in.
#[derive(Debug, Clone)]
pub struct OrderedMap<K, V> {
    pairs: HashMap<K, usize>,
    nodes: Vec<Option<Node<K, V>>>,
    free: Vec<usize>,
    head: Option<usize>,
    tail: Option<usize>,
}
#[derive(Debug)]
pub struct InitConfig<K, V> {
    capacity: usize,
    initial_data: Vec<(K, V)>,
}

/// a callback that adjusts [`InitConfig`] before the map is built.
pub type InitOption<K, V> = Box<dyn FnOnce(&mut InitConfig<K, V>)>;

/// Gives a capacity hint on the map under construction.
#[must_use]
pub fn with_capacity<K, V>(capacity: usize) -> InitOption<K, V> {
    Box::new(move |config| config.capacity = capacity)
}

/// passes initial data for the map.
#[must_use]
pub fn with_initial_data<K: 'static, V: 'static>(initial_data: Vec<(K, V)>) -> InitOption<K, V> {
    Box::new(move |config| {
        if config.capacity < initial_data.len() {
            config.capacity = initial_data.len();
        }
        config.initial_data = initial_data;
    })
}

impl<K, V> Default for OrderedMap<K, V> {
    fn default() -> Self {
        Self { pairs: HashMap::new(), nodes: Vec::new(), free: Vec::new(), head: None, tail: None }
    }
}

impl<K, V> OrderedMap<K, V> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// the pair at the oldest end of the map.
    #[must_use]
    pub fn oldest(&self) -> Option<Pair<'_, K, V>> {
        self.head.map(|index| Pair { map: self, index })
    }

    /// the pair at the newest end of the map.
    #[must_use]
    pub fn newest(&self) -> Option<Pair<'_, K, V>> {
        self.tail.map(|index| Pair { map: self, index })
    }

    #[expect(
        clippy::expect_used,
        reason = "a node index is only ever handed out by `alloc_node`, which leaves a live node at it"
    )]
    fn node(&self, index: usize) -> &Node<K, V> {
        self.nodes.get(index).and_then(Option::as_ref).expect("orderedmap: node slot is empty")
    }

    #[expect(
        clippy::expect_used,
        reason = "a node index is only ever handed out by `alloc_node`, which leaves a live node at it"
    )]
    fn node_mut(&mut self, index: usize) -> &mut Node<K, V> {
        self.nodes.get_mut(index).and_then(Option::as_mut).expect("orderedmap: node slot is empty")
    }
}

impl<K: Eq + Hash + Clone, V> OrderedMap<K, V> {
    #[must_use]
    pub fn new_with_capacity(capacity: usize) -> Self {
        let mut ordered_map = Self::default();
        ordered_map.initialize(capacity);
        ordered_map
    }

    #[must_use]
    pub fn new_with_options(options: Vec<InitOption<K, V>>) -> Self {
        let mut config = InitConfig { capacity: 0, initial_data: Vec::new() };
        for option in options {
            option(&mut config);
        }

        let mut ordered_map = Self::default();
        ordered_map.initialize(config.capacity);
        ordered_map.add_pairs(config.initial_data);

        ordered_map
    }

    fn initialize(&mut self, capacity: usize) {
        self.pairs = HashMap::with_capacity(capacity);
        self.nodes = Vec::new();
        self.free = Vec::new();
        self.head = None;
        self.tail = None;
    }

    fn alloc_node(&mut self, key: K, value: V) -> usize {
        let node = Node { key, value, prev: None, next: None };
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

    fn unlink(&mut self, index: usize) {
        let (prev, next) = {
            let node = self.node(index);
            (node.prev, node.next)
        };
        match prev {
            Some(prev) => self.node_mut(prev).next = next,
            None => self.head = next,
        }
        match next {
            Some(next) => self.node_mut(next).prev = prev,
            None => self.tail = prev,
        }
    }

    /// Links the unlinked node `index` directly after `mark`; `None` links it at the oldest end.
    fn link_after(&mut self, index: usize, mark: Option<usize>) {
        let next = match mark {
            Some(mark) => self.node(mark).next,
            None => self.head,
        };
        match mark {
            Some(mark) => self.node_mut(mark).next = Some(index),
            None => self.head = Some(index),
        }
        match next {
            Some(next) => self.node_mut(next).prev = Some(index),
            None => self.tail = Some(index),
        }

        let node = self.node_mut(index);
        node.prev = mark;
        node.next = next;
    }

    /// Moving to the back, front, after or before no-ops when the element is already
    /// in place, so the index helpers repeat that guard.
    fn move_to_back_index(&mut self, index: usize) {
        let tail = self.tail;
        if tail == Some(index) {
            return;
        }
        self.unlink(index);
        self.link_after(index, tail);
    }

    fn move_to_front_index(&mut self, index: usize) {
        if self.head == Some(index) {
            return;
        }
        self.unlink(index);
        self.link_after(index, None);
    }

    fn move_after_index(&mut self, index: usize, mark: usize) {
        if index == mark {
            return;
        }
        self.unlink(index);
        self.link_after(index, Some(mark));
    }

    fn move_before_index(&mut self, index: usize, mark: usize) {
        if index == mark {
            return;
        }

        // `mark.prev` is evaluated before the element leaves the list, and moving the element no-ops when
        // the element is already there.
        let prev = self.node(mark).prev;
        if prev == Some(index) {
            return;
        }

        self.unlink(index);
        self.link_after(index, prev);
    }

    /// the value stored under `key`.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.pairs.get(key).map(|&index| &self.node(index).value)
    }

    /// An alias of `get`.
    pub fn load(&self, key: &K) -> Option<&V> {
        self.get(key)
    }

    /// the value stored under `key`, or the zero value.
    pub fn value(&self, key: &K) -> Option<&V> {
        self.get(key)
    }

    /// the pair stored under `key`, from which the map can be walked
    /// forward or backward.
    pub fn get_pair(&self, key: &K) -> Option<Pair<'_, K, V>> {
        self.pairs.get(key).map(|&index| Pair { map: self, index })
    }

    /// returns the value the key held before the call, and whether the
    /// key was present.
    pub fn set(&mut self, key: K, value: V) -> (Option<V>, bool) {
        if let Some(&index) = self.pairs.get(&key) {
            let old_value = std::mem::replace(&mut self.node_mut(index).value, value);
            return (Some(old_value), true);
        }

        let index = self.alloc_node(key.clone(), value);
        let tail = self.tail;
        self.link_after(index, tail);
        self.pairs.insert(key, index);

        (None, false)
    }

    /// `Set` on each pair sequentially.
    pub fn add_pairs(&mut self, pairs: impl IntoIterator<Item = (K, V)>) {
        for (key, value) in pairs {
            self.set(key, value);
        }
    }

    /// An alias of `set`.
    pub fn store(&mut self, key: K, value: V) -> (Option<V>, bool) {
        self.set(key, value)
    }

    /// returns the value the key held before the call, and whether the
    /// key was present.
    #[expect(
        clippy::expect_used,
        reason = "a node index is only ever handed out by `alloc_node`, which leaves a live node at it"
    )]
    pub fn delete(&mut self, key: &K) -> (Option<V>, bool) {
        let Some(&index) = self.pairs.get(key) else {
            return (None, false);
        };
        self.pairs.remove(key);
        self.unlink(index);
        let node = self.nodes.get_mut(index).and_then(Option::take).expect("orderedmap: node slot is empty");
        self.free.push(index);

        (Some(node.value), true)
    }
}

impl<K, V> OrderedMap<K, V>
where
    K: Eq + Hash + Clone + fmt::Display + fmt::Debug + Send + Sync + 'static,
{
    /// moves `key` right after `mark_key`.
    pub fn move_after(&mut self, key: &K, mark_key: &K) -> anyhow::Result<()> {
        let (index, mark) = self.get_two_indices(key, mark_key)?;
        self.move_after_index(index, mark);
        Ok(())
    }

    /// moves `key` right before `mark_key`.
    pub fn move_before(&mut self, key: &K, mark_key: &K) -> anyhow::Result<()> {
        let (index, mark) = self.get_two_indices(key, mark_key)?;
        self.move_before_index(index, mark);
        Ok(())
    }

    /// The slot indices of `key` and `mark_key`, reported as missing in that order.
    fn get_two_indices(&self, key: &K, mark_key: &K) -> anyhow::Result<(usize, usize)> {
        Ok((self.get_index(key)?, self.get_index(mark_key)?))
    }

    fn get_index(&self, key: &K) -> anyhow::Result<usize> {
        match self.pairs.get(key) {
            Some(&index) => Ok(index),
            None => Err(KeyNotFoundError { missing_key: key.clone() }.into()),
        }
    }

    /// Moves `key` to the newest end of the map. The pair is moved directly rather than composing
    /// `get_and_move_to_back` and dropping its value, so it needs no
    /// `V: Clone`.
    pub fn move_to_back(&mut self, key: &K) -> anyhow::Result<()> {
        let index = self.get_index(key)?;
        self.move_to_back_index(index);

        Ok(())
    }

    /// moves `key` to the oldest end of the map.
    pub fn move_to_front(&mut self, key: &K) -> anyhow::Result<()> {
        let index = self.get_index(key)?;
        self.move_to_front_index(index);

        Ok(())
    }
}

impl<K, V: Clone> OrderedMap<K, V>
where
    K: Eq + Hash + Clone + fmt::Display + fmt::Debug + Send + Sync + 'static,
{
    /// Gets a value and moves its key to the back.
    pub fn get_and_move_to_back(&mut self, key: &K) -> anyhow::Result<V> {
        let Some(&index) = self.pairs.get(key) else {
            return Err(KeyNotFoundError { missing_key: key.clone() }.into());
        };
        let value = self.node(index).value.clone();
        self.move_to_back_index(index);

        Ok(value)
    }

    /// Gets a value and moves its key to the front.
    pub fn get_and_move_to_front(&mut self, key: &K) -> anyhow::Result<V> {
        let Some(&index) = self.pairs.get(key) else {
            return Err(KeyNotFoundError { missing_key: key.clone() }.into());
        };
        let value = self.node(index).value.clone();
        self.move_to_front_index(index);

        Ok(value)
    }
}

/// Returned when a lookup is made with a key that is not present in the map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyNotFoundError<K> {
    pub missing_key: K,
}

impl<K: fmt::Display> fmt::Display for KeyNotFoundError<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "missing key: {}", self.missing_key)
    }
}

impl<K: fmt::Display + fmt::Debug> std::error::Error for KeyNotFoundError<K> {}

#[cfg(test)]
pub(crate) mod tests {
    use std::fmt::Debug;

    use serde_json::json;

    use super::*;

    #[test]
    fn test_basic_features() {
        let n = 100;
        let mut om = OrderedMap::<i32, i32>::new();

        fill_and_check_growth(&mut om, n);
        check_values_after_fill(&om, n);
        check_pairs_after_fill(&om, n);
        check_iteration_order_after_fill(&om, n);
        overwrite_even_keys(&mut om, n);
        delete_odd_keys(&mut om, n);
        check_values_and_iteration_order_after_churn(&om, n);
    }

    fn fill_and_check_growth(om: &mut OrderedMap<i32, i32>, n: i32) {
        for i in 0..n {
            assert_len_equal(om, i as usize);
            let (old_value, present) = om.set(i, 2 * i);
            assert_len_equal(om, i as usize + 1);

            assert_eq!(None, old_value);
            assert!(!present);
        }
    }

    fn check_values_after_fill(om: &OrderedMap<i32, i32>, n: i32) {
        for i in 0..n {
            let value = om.get(&i);

            assert_eq!(Some(&(2 * i)), value);
            assert_eq!(value, om.value(&i));
            assert!(value.is_some());
        }
    }

    fn check_pairs_after_fill(om: &OrderedMap<i32, i32>, n: i32) {
        for i in 0..n {
            let pair = om.get_pair(&i);

            assert!(pair.is_some());
            assert_eq!(Some(2 * i), pair.map(|pair| *pair.value()));
        }
    }

    fn check_iteration_order_after_fill(om: &OrderedMap<i32, i32>, n: i32) {
        let mut i = 0;
        let mut pair = om.oldest();
        while let Some(current) = pair {
            assert_eq!(i, *current.key());
            assert_eq!(2 * i, *current.value());
            i += 1;
            pair = current.next();
        }
        let mut i = n - 1;
        let mut pair = om.newest();
        while let Some(current) = pair {
            assert_eq!(i, *current.key());
            assert_eq!(2 * i, *current.value());
            i -= 1;
            pair = current.prev();
        }

        let mut i = 42;
        let mut pair = om.get_pair(&i);
        while let Some(current) = pair {
            assert_eq!(i, *current.key());
            assert_eq!(2 * i, *current.value());
            i += 1;
            pair = current.next();
        }
    }

    fn overwrite_even_keys(om: &mut OrderedMap<i32, i32>, n: i32) {
        for j in 0..n / 2 {
            let i = 2 * j;
            let (old_value, present) = om.set(i, 4 * i);

            assert_eq!(Some(2 * i), old_value);
            assert!(present);
        }
    }

    fn delete_odd_keys(om: &mut OrderedMap<i32, i32>, n: i32) {
        for j in 0..n / 2 {
            let i = 2 * j + 1;
            assert_len_equal(om, (n - j) as usize);
            let (value, present) = om.delete(&i);
            assert_len_equal(om, (n - j - 1) as usize);

            assert_eq!(Some(2 * i), value);
            assert!(present);

            let (value, present) = om.delete(&i);
            assert_len_equal(om, (n - j - 1) as usize);
            assert_eq!(None, value);
            assert!(!present);
        }
    }

    fn check_values_and_iteration_order_after_churn(om: &OrderedMap<i32, i32>, n: i32) {
        for j in 0..n / 2 {
            let i = 2 * j;
            let value = om.get(&i);
            assert_eq!(Some(&(4 * i)), value);
            assert_eq!(value, om.value(&i));
            assert!(value.is_some());

            let i = 2 * j + 1;
            let value = om.get(&i);
            assert_eq!(None, value);
            assert_eq!(value, om.value(&i));
            assert!(value.is_none());
        }

        let mut i = 0;
        let mut pair = om.oldest();
        while let Some(current) = pair {
            assert_eq!(i, *current.key());
            assert_eq!(4 * i, *current.value());
            i += 2;
            pair = current.next();
        }
        let mut i = 2 * ((n - 1) / 2);
        let mut pair = om.newest();
        while let Some(current) = pair {
            assert_eq!(i, *current.key());
            assert_eq!(4 * i, *current.value());
            i -= 2;
            pair = current.prev();
        }
    }

    #[test]
    fn test_updating_doesnt_change_pairs_order() {
        let mut om = OrderedMap::<String, serde_json::Value>::new();
        om.set("foo".to_owned(), json!("bar"));
        om.set("wk".to_owned(), json!(28));
        om.set("po".to_owned(), json!(100));
        om.set("bar".to_owned(), json!("baz"));

        let (old_value, present) = om.set("po".to_owned(), json!(102));
        assert_eq!(Some(json!(100)), old_value);
        assert!(present);

        assert_ordered_pairs_equal(
            &om,
            &key_strings(["foo", "wk", "po", "bar"]),
            &[json!("bar"), json!(28), json!(102), json!("baz")],
        );
    }

    #[test]
    fn test_deleting_and_reinserting_changes_pairs_order() {
        let mut om = OrderedMap::<String, serde_json::Value>::new();
        om.set("foo".to_owned(), json!("bar"));
        om.set("wk".to_owned(), json!(28));
        om.set("po".to_owned(), json!(100));
        om.set("bar".to_owned(), json!("baz"));

        let (old_value, present) = om.delete(&"po".to_owned());
        assert_eq!(Some(json!(100)), old_value);
        assert!(present);

        let (old_value, present) = om.set("po".to_owned(), json!(100));
        assert_eq!(None, old_value);
        assert!(!present);

        assert_ordered_pairs_equal(
            &om,
            &key_strings(["foo", "wk", "bar", "po"]),
            &[json!("bar"), json!(28), json!("baz"), json!(100)],
        );
    }

    #[test]
    fn test_empty_map_operations() {
        let mut om = OrderedMap::<String, serde_json::Value>::new();

        let old_value = om.get(&"foo".to_owned());
        assert_eq!(None, old_value);
        assert_eq!(None, om.value(&"foo".to_owned()));
        assert!(old_value.is_none());

        let (old_value, present) = om.delete(&"bar".to_owned());
        assert_eq!(None, old_value);
        assert!(!present);

        assert_len_equal(&om, 0);

        assert!(om.oldest().is_none());
        assert!(om.newest().is_none());
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DummyTestStruct {
        value: String,
    }

    #[test]
    fn test_pack_unpack_structs() {
        let mut om = OrderedMap::<String, DummyTestStruct>::new();
        om.set("foo".to_owned(), DummyTestStruct { value: "foo!".to_owned() });
        om.set("bar".to_owned(), DummyTestStruct { value: "bar!".to_owned() });

        let value = om.get(&"foo".to_owned());
        assert!(value.is_some());
        assert_eq!(value, om.value(&"foo".to_owned()));
        if let Some(value) = value {
            assert_eq!("foo!", value.value);
        }

        let (value, present) = om.set("bar".to_owned(), DummyTestStruct { value: "baz!".to_owned() });
        assert!(present);
        if let Some(value) = value {
            assert_eq!("bar!", value.value);
        }

        let value = om.get(&"bar".to_owned());
        assert_eq!(value, om.value(&"bar".to_owned()));
        assert!(value.is_some());
        if let Some(value) = value {
            assert_eq!("baz!", value.value);
        }
    }

    #[test]
    fn test_shuffle() {
        let ran_len = 100;

        for n in [0, 10, 20, 100, 1000, 10000] {
            let mut om = OrderedMap::<String, String>::new();

            let mut keys = Vec::with_capacity(n);
            let mut values = Vec::with_capacity(n);

            for i in 0..n {
                // the number prefix ensures there are no duplicates
                keys.push(format!("{i}_{}", random_hex_string(ran_len)));
                values.push(random_hex_string(ran_len));

                let (value, present) = om.set(keys[i].clone(), values[i].clone());
                assert_eq!(None, value);
                assert!(!present);
            }

            assert_ordered_pairs_equal(&om, &keys, &values);
        }
    }

    #[test]
    fn test_move() {
        let mut om = OrderedMap::<i32, serde_json::Value>::new();
        om.set(1, json!("bar"));
        om.set(2, json!(28));
        om.set(3, json!(100));
        om.set(4, json!("baz"));
        om.set(5, json!("28"));
        om.set(6, json!("100"));
        om.set(7, json!("baz"));
        om.set(8, json!("baz"));

        om.move_after(&2, &3).unwrap();
        assert_ordered_pairs_equal(
            &om,
            &[1, 3, 2, 4, 5, 6, 7, 8],
            &[json!("bar"), json!(100), json!(28), json!("baz"), json!("28"), json!("100"), json!("baz"), json!("baz")],
        );

        om.move_before(&6, &4).unwrap();
        assert_ordered_pairs_equal(
            &om,
            &[1, 3, 2, 6, 4, 5, 7, 8],
            &[json!("bar"), json!(100), json!(28), json!("100"), json!("baz"), json!("28"), json!("baz"), json!("baz")],
        );

        om.move_to_back(&3).unwrap();
        assert_ordered_pairs_equal(
            &om,
            &[1, 2, 6, 4, 5, 7, 8, 3],
            &[json!("bar"), json!(28), json!("100"), json!("baz"), json!("28"), json!("baz"), json!("baz"), json!(100)],
        );

        om.move_to_front(&5).unwrap();
        assert_ordered_pairs_equal(
            &om,
            &[5, 1, 2, 6, 4, 7, 8, 3],
            &[json!("28"), json!("bar"), json!(28), json!("100"), json!("baz"), json!("baz"), json!("baz"), json!(100)],
        );

        let err = om.move_to_front(&100).unwrap_err();
        assert_eq!(Some(&KeyNotFoundError { missing_key: 100 }), err.downcast_ref::<KeyNotFoundError<i32>>());
    }

    #[test]
    fn test_get_and_move() {
        let mut om = OrderedMap::<i32, serde_json::Value>::new();
        om.set(1, json!("bar"));
        om.set(2, json!(28));
        om.set(3, json!(100));
        om.set(4, json!("baz"));
        om.set(5, json!("28"));
        om.set(6, json!("100"));
        om.set(7, json!("baz"));
        om.set(8, json!("baz"));

        let value = om.get_and_move_to_back(&3).unwrap();
        assert_eq!(json!(100), value);
        assert_ordered_pairs_equal(
            &om,
            &[1, 2, 4, 5, 6, 7, 8, 3],
            &[json!("bar"), json!(28), json!("baz"), json!("28"), json!("100"), json!("baz"), json!("baz"), json!(100)],
        );

        let value = om.get_and_move_to_front(&5).unwrap();
        assert_eq!(json!("28"), value);
        assert_ordered_pairs_equal(
            &om,
            &[5, 1, 2, 4, 6, 7, 8, 3],
            &[json!("28"), json!("bar"), json!(28), json!("baz"), json!("100"), json!("baz"), json!("baz"), json!(100)],
        );

        let err = om.get_and_move_to_back(&100).unwrap_err();
        assert_eq!(Some(&KeyNotFoundError { missing_key: 100 }), err.downcast_ref::<KeyNotFoundError<i32>>());
    }

    #[test]
    fn test_move_before_across_a_gap() {
        let mut om = OrderedMap::<i32, i32>::new();
        om.set(1, 1);
        om.set(2, 2);
        om.set(3, 3);

        om.move_before(&1, &3).unwrap();

        assert_ordered_pairs_equal(&om, &[2, 1, 3], &[2, 1, 3]);
    }

    #[test]
    fn test_add_pairs() {
        let mut om = OrderedMap::<i32, serde_json::Value>::new();

        om.add_pairs([(28, json!("foo")), (12, json!("bar")), (28, json!("baz"))]);

        assert_ordered_pairs_equal(&om, &[28, 12], &[json!("baz"), json!("bar")]);
    }

    #[test]
    fn test_new_with_capacity() {
        let zero = OrderedMap::<i32, String>::new_with_capacity(0);
        assert_eq!(0, zero.len());

        let mut om = OrderedMap::<i32, String>::new_with_capacity(1);
        om.set(1337, "quarante-deux".to_owned());
        assert_eq!(1, om.len());
    }

    #[test]
    fn test_new_with_options() {
        let om = OrderedMap::<String, serde_json::Value>::new_with_options(vec![with_capacity(98)]);
        assert_eq!(0, om.len());

        let om = OrderedMap::<String, i32>::new_with_options(vec![with_initial_data(vec![
            ("a".to_owned(), 1),
            ("b".to_owned(), 2),
            ("c".to_owned(), 3),
        ])]);

        assert_ordered_pairs_equal(&om, &key_strings(["a", "b", "c"]), &[1, 2, 3]);
    }

    #[test]
    fn test_nil_map() {
        // A null map has no distinct in-memory form here: it is an absent map.
        let om = None::<OrderedMap<i32, serde_json::Value>>;

        assert_eq!(0, om.as_ref().map_or(0, OrderedMap::len));

        assert!(om.as_ref().and_then(OrderedMap::oldest).is_none());
        assert!(om.as_ref().and_then(OrderedMap::newest).is_none());
    }

    pub(crate) fn key_strings<const N: usize>(keys: [&str; N]) -> Vec<String> {
        keys.iter().map(|key| (*key).to_owned()).collect()
    }

    pub(crate) fn assert_len_equal<K, V>(om: &OrderedMap<K, V>, expected_len: usize) {
        assert_eq!(expected_len, om.len());

        // also check the list length, for good measure
        let mut list_len = 0;
        let mut pair = om.oldest();
        while let Some(current) = pair {
            list_len += 1;
            pair = current.next();
        }
        assert_eq!(expected_len, list_len);
    }

    pub(crate) fn assert_ordered_pairs_equal<K, V>(om: &OrderedMap<K, V>, expected_keys: &[K], expected_values: &[V])
    where
        K: PartialEq + Debug,
        V: PartialEq + Debug,
    {
        assert_ordered_pairs_equal_from_newest(om, expected_keys, expected_values);
        assert_ordered_pairs_equal_from_oldest(om, expected_keys, expected_values);
    }

    fn assert_ordered_pairs_equal_from_newest<K, V>(om: &OrderedMap<K, V>, expected_keys: &[K], expected_values: &[V])
    where
        K: PartialEq + Debug,
        V: PartialEq + Debug,
    {
        assert_eq!(expected_keys.len(), expected_values.len());
        assert_eq!(expected_keys.len(), om.len());

        let mut i = om.len();
        let mut pair = om.newest();
        while let Some(current) = pair {
            i -= 1;
            assert_eq!(expected_keys[i], *current.key(), "from newest index={i} on key");
            assert_eq!(expected_values[i], *current.value(), "from newest index={i} on value");
            pair = current.prev();
        }
    }

    fn assert_ordered_pairs_equal_from_oldest<K, V>(om: &OrderedMap<K, V>, expected_keys: &[K], expected_values: &[V])
    where
        K: PartialEq + Debug,
        V: PartialEq + Debug,
    {
        assert_eq!(expected_keys.len(), expected_values.len());
        assert_eq!(expected_keys.len(), om.len());

        let mut i = 0;
        let mut pair = om.oldest();
        while let Some(current) = pair {
            assert_eq!(expected_keys[i], *current.key(), "from oldest index={i} on key");
            assert_eq!(expected_values[i], *current.value(), "from oldest index={i} on value");
            i += 1;
            pair = current.next();
        }
    }

    pub(crate) fn random_hex_string(length: usize) -> String {
        use rand::Rng;

        let bytes = length / 2;
        let mut rand_bytes = vec![0u8; bytes];
        rand::rng().fill(&mut rand_bytes[..]);

        hex::encode(rand_bytes)
    }
}

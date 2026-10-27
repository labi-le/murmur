/// A holder object that stores a collection of other objects.
pub trait Container {
    /// Whether the container has no elements.
    fn is_empty(&self) -> bool;
    /// The number of elements in the container.
    fn len(&self) -> usize;
    /// Erases all elements from the container, so it becomes empty.
    fn clear(&mut self);
}

/// An associative container of key-value pairs with unique keys.
///
/// element access hands out a borrow into the container and iteration passes references; nothing
/// is copied.
pub trait Map<K, V>: Container {
    /// Checks whether the container contains element with specific key.
    fn has(&self, key: &K) -> bool;
    /// Finds element with specific key.
    fn find(&self, key: &K) -> Option<&V>;
    /// Inserts a key-value pair in to the container or replace existing value.
    fn insert(&mut self, key: K, value: V);
    /// Remove element with specific key.
    fn remove(&mut self, key: &K) -> bool;
    /// Iterate the container.
    fn for_each(&self, op: &mut dyn FnMut(&K, &V));
    /// Iterate the container, stops when the callback returns false.
    fn for_each_if(&self, op: &mut dyn FnMut(&K, &V) -> bool);
    /// Iterate the container, allowing values to be mutated.
    fn for_each_mutable(&mut self, op: &mut dyn FnMut(&K, &mut V));
    /// Iterate the container with mutable values, stopping when the callback returns false.
    fn for_each_mutable_if(&mut self, op: &mut dyn FnMut(&K, &mut V) -> bool);
}

/// A container that stores unique elements.
pub trait Set<K>: Container {
    /// Checks whether the container contains element with specific key.
    fn has(&self, key: &K) -> bool;
    /// Inserts a key into the set, replacing an existing equal key.
    fn insert(&mut self, key: K);
    /// Inserts multiple keys, replacing any existing equal keys.
    fn insert_n(&mut self, keys: Vec<K>);
    /// Remove element with specific key.
    fn remove(&mut self, key: &K) -> bool;
    /// Remove multiple elements with specific keys.
    fn remove_n(&mut self, keys: Vec<K>);
    /// Iterate the container.
    fn for_each(&self, op: &mut dyn FnMut(&K));
    /// Iterate the container, stops when the callback returns false.
    fn for_each_if(&self, op: &mut dyn FnMut(&K) -> bool);
}

/// The iterator over a container.
pub trait Iterator<T> {
    /// Whether the iterator points to the end of the range.
    fn is_not_end(&self) -> bool;
    /// Advances to the next element.
    fn move_to_next(&mut self);
    /// The value of the current element.
    fn value(&self) -> T;
}

/// The iterator over a map.
pub trait MapIterator<K, V>: Iterator<V> {
    /// The key of the element.
    fn key(&self) -> K;
}

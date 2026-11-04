//!
//! The hand-rolled circular buffer is replaced here with `std::collections::VecDeque`.
//!
//! `VecDeque` implements the same amortized-O(1) push/pop-at-both-ends behavior. Capacity and
//! growth/shrink timing are not part of any caller's observable contract (nothing outside this
//! module reads `cap()`), so std's own growth policy is used instead of reproducing the
//! power-of-two doubling and quarter-full shrink.

use std::collections::VecDeque;

/// Double-ended queue backed by [`VecDeque`].
#[derive(Debug, Clone)]
pub struct Deque<T> {
    buf: VecDeque<T>,
}

impl<T> Default for Deque<T> {
    fn default() -> Self {
        Self { buf: VecDeque::new() }
    }
}

impl<T> Deque<T> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current capacity.
    #[must_use]
    pub fn cap(&self) -> usize {
        self.buf.capacity()
    }

    /// Number of elements currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Needed alongside `len()` for `clippy::len_without_is_empty`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Appends to the back.
    pub fn push_back(&mut self, elem: T) {
        self.buf.push_back(elem);
    }

    /// Prepends to the front.
    pub fn push_front(&mut self, elem: T) {
        self.buf.push_front(elem);
    }

    /// Removes and returns the front element, panicking when the queue is empty.
    #[expect(clippy::expect_used, reason = "the assert above fixes the empty-queue panic contract")]
    pub fn pop_front(&mut self) -> T {
        assert!(!self.buf.is_empty(), "deque: PopFront() called on empty queue");
        self.buf.pop_front().expect("checked non-empty above")
    }

    /// Removes from the front, handing each item to `yield_fn` until it returns `false`.
    pub fn iter_pop_front(&mut self, mut yield_fn: impl FnMut(T) -> bool) {
        while let Some(v) = self.buf.pop_front() {
            if !yield_fn(v) {
                break;
            }
        }
    }

    /// Removes and returns the back element, panicking when the queue is empty.
    #[expect(clippy::expect_used, reason = "the assert above fixes the empty-queue panic contract")]
    pub fn pop_back(&mut self) -> T {
        assert!(!self.buf.is_empty(), "deque: PopBack() called on empty queue");
        self.buf.pop_back().expect("checked non-empty above")
    }

    /// Removes from the back, handing each item to `yield_fn` until it returns `false`.
    pub fn iter_pop_back(&mut self, mut yield_fn: impl FnMut(T) -> bool) {
        while let Some(v) = self.buf.pop_back() {
            if !yield_fn(v) {
                break;
            }
        }
    }

    /// Front element, the one `pop_front` would return; panics when the queue is empty.
    #[must_use]
    #[expect(clippy::expect_used, reason = "the assert above fixes the empty-queue panic contract")]
    pub fn front(&self) -> &T {
        assert!(!self.buf.is_empty(), "deque: Front() called when empty");
        self.buf.front().expect("checked non-empty above")
    }

    /// Back element, the one `pop_back` would return; panics when the queue is empty.
    #[must_use]
    #[expect(clippy::expect_used, reason = "the assert above fixes the empty-queue panic contract")]
    pub fn back(&self) -> &T {
        assert!(!self.buf.is_empty(), "deque: Back() called when empty");
        self.buf.back().expect("checked non-empty above")
    }

    /// Element at index `i` counted from the front, without removing it; panics out of range.
    #[must_use]
    #[expect(clippy::expect_used, reason = "`check_range` has already panicked unless `i` is in bounds")]
    pub fn at(&self, i: usize) -> &T {
        self.check_range(i);
        self.buf.get(i).expect("checked range above")
    }

    /// Overwrites the element at index `i` counted from the front; panics out of range.
    pub fn set(&mut self, i: usize, item: T) {
        self.check_range(i);
        if let Some(slot) = self.buf.get_mut(i) {
            *slot = item;
        }
    }

    /// Hands every item from front to back to `yield_fn` until it returns `false`.
    #[expect(
        clippy::iter_not_returning_iterator,
        reason = "the API hands each item to a callback instead of returning an iterator"
    )]
    pub fn iter(&self, mut yield_fn: impl FnMut(&T) -> bool) {
        for v in &self.buf {
            if !yield_fn(v) {
                return;
            }
        }
    }

    /// Hands every item from back to front to `yield_fn` until it returns `false`.
    pub fn r_iter(&self, mut yield_fn: impl FnMut(&T) -> bool) {
        for v in self.buf.iter().rev() {
            if !yield_fn(v) {
                return;
            }
        }
    }

    /// Removes all elements, retaining the capacity.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Guarantees room for `n` more items; panics on a negative count.
    pub fn grow(&mut self, n: isize) {
        assert!(n >= 0, "deque.Grow: negative count");
        self.buf.reserve(n.unsigned_abs());
    }

    /// Copies the contents of `src` into this deque, returning how many elements were copied.
    pub fn copy(&mut self, src: &Self) -> usize
    where
        T: Clone,
    {
        self.buf.clear();
        self.buf.extend(src.buf.iter().cloned());
        self.buf.len()
    }

    /// Appends every element to `out` in front-to-back order.
    #[must_use]
    pub fn append_to_slice(&self, mut out: Vec<T>) -> Vec<T>
    where
        T: Clone,
    {
        out.extend(self.buf.iter().cloned());
        out
    }

    /// Replaces the contents with the elements of `in_`; an empty `in_` clears the deque.
    pub fn copy_in_slice(&mut self, in_: &[T])
    where
        T: Clone,
    {
        self.buf.clear();
        self.buf.extend(in_.iter().cloned());
    }

    /// Copies up to `out.len()` elements into `out`, returning how many were copied.
    pub fn copy_out_slice(&self, out: &mut [T]) -> usize
    where
        T: Clone,
    {
        let n = out.len().min(self.buf.len());
        for (slot, item) in out.iter_mut().zip(self.buf.iter()).take(n) {
            *slot = item.clone();
        }
        n
    }

    /// Rotates `n` steps front-to-back; a negative `n` rotates back-to-front.
    pub fn rotate(&mut self, n: isize) {
        if self.buf.len() <= 1 {
            return;
        }
        let len = self.len_isize();
        let n = n % len;
        if n == 0 {
            return;
        }
        if n > 0 {
            self.buf.rotate_left(n.unsigned_abs());
        } else {
            self.buf.rotate_right(n.unsigned_abs());
        }
    }

    /// Index of the first item satisfying `f`, searching from the front; `None` is the `-1`.
    pub fn index(&self, f: impl Fn(&T) -> bool) -> Option<usize> {
        self.buf.iter().position(f)
    }

    /// Same as `index`, searching from the back; the index is still counted from the front.
    pub fn r_index(&self, f: impl Fn(&T) -> bool) -> Option<usize> {
        self.buf.iter().rposition(f)
    }

    /// Inserts `item` before index `at`; out of range indexes push onto the nearer end.
    pub fn insert(&mut self, at: isize, item: T) {
        let at = at.clamp(0, self.len_isize()).unsigned_abs();
        self.buf.insert(at, item);
    }

    /// Removes and returns the element at index `at`, panicking out of range.
    #[expect(clippy::expect_used, reason = "`check_range` has already panicked unless `at` is in bounds")]
    pub fn remove(&mut self, at: usize) -> T {
        self.check_range(at);
        self.buf.remove(at).expect("checked range above")
    }

    /// Sets a base capacity that resizes never go below, reserved up front.
    pub fn set_base_cap(&mut self, base_cap: usize) {
        self.buf.reserve(base_cap.saturating_sub(self.buf.len()));
    }

    /// Exchanges the values at `idx_a` and `idx_b`, panicking when either is out of range.
    pub fn swap(&mut self, idx_a: usize, idx_b: usize) {
        self.check_range(idx_a);
        self.check_range(idx_b);
        self.buf.swap(idx_a, idx_b);
    }

    fn check_range(&self, i: usize) {
        assert!(i < self.buf.len(), "deque: index out of range {} with length {}", i, self.buf.len());
    }

    #[expect(clippy::expect_used, reason = "a `VecDeque` length never exceeds `isize::MAX`")]
    fn len_isize(&self) -> isize {
        isize::try_from(self.buf.len()).expect("deque: length fits in isize")
    }
}

#[cfg(test)]
mod tests {
    use super::Deque;

    #[test]
    fn push_pop_order() {
        let mut d = Deque::new();
        d.push_back(1);
        d.push_back(2);
        d.push_front(0);
        assert_eq!(d.len(), 3);
        assert_eq!(*d.front(), 0);
        assert_eq!(*d.back(), 2);
        assert_eq!(d.pop_front(), 0);
        assert_eq!(d.pop_back(), 2);
        assert_eq!(d.pop_front(), 1);
        assert!(d.is_empty());
    }

    #[test]
    fn iter_and_r_iter_order() {
        let mut d = Deque::new();
        for i in 0..5 {
            d.push_back(i);
        }
        let mut forward = Vec::new();
        d.iter(|v| {
            forward.push(*v);
            true
        });
        assert_eq!(forward, vec![0, 1, 2, 3, 4]);

        let mut backward = Vec::new();
        d.r_iter(|v| {
            backward.push(*v);
            true
        });
        assert_eq!(backward, vec![4, 3, 2, 1, 0]);

        let mut stopped = Vec::new();
        d.iter(|v| {
            stopped.push(*v);
            *v < 2
        });
        assert_eq!(stopped, vec![0, 1, 2]);
    }

    #[test]
    fn index_and_r_index() {
        let mut d = Deque::new();
        for i in [10, 20, 30, 20] {
            d.push_back(i);
        }
        assert_eq!(d.index(|v| *v == 20), Some(1));
        assert_eq!(d.r_index(|v| *v == 20), Some(3));
        assert_eq!(d.index(|v| *v == 999), None);
    }

    #[test]
    fn insert_front_half_and_back_half() {
        let mut d = Deque::new();
        for i in 0..6 {
            d.push_back(i);
        }
        d.insert(0, 100);
        assert_eq!(d.append_to_slice(Vec::new()), vec![100, 0, 1, 2, 3, 4, 5]);

        let mut d = Deque::new();
        for i in 0..6 {
            d.push_back(i);
        }
        d.insert(6, 200);
        assert_eq!(d.append_to_slice(Vec::new()), vec![0, 1, 2, 3, 4, 5, 200]);

        let mut d = Deque::new();
        for i in 0..6 {
            d.push_back(i);
        }
        d.insert(1, 300);
        assert_eq!(d.append_to_slice(Vec::new()), vec![0, 300, 1, 2, 3, 4, 5]);

        let mut d = Deque::new();
        for i in 0..6 {
            d.push_back(i);
        }
        d.insert(4, 400);
        assert_eq!(d.append_to_slice(Vec::new()), vec![0, 1, 2, 3, 400, 4, 5]);
    }

    #[test]
    fn remove_front_half_and_back_half() {
        let mut d = Deque::new();
        for i in 0..6 {
            d.push_back(i);
        }
        assert_eq!(d.remove(1), 1);
        assert_eq!(d.append_to_slice(Vec::new()), vec![0, 2, 3, 4, 5]);

        let mut d = Deque::new();
        for i in 0..6 {
            d.push_back(i);
        }
        assert_eq!(d.remove(4), 4);
        assert_eq!(d.append_to_slice(Vec::new()), vec![0, 1, 2, 3, 5]);
    }

    #[test]
    fn rotate_forward_and_backward() {
        let mut d = Deque::new();
        for i in 0..5 {
            d.push_back(i);
        }
        d.rotate(2);
        assert_eq!(d.append_to_slice(Vec::new()), vec![2, 3, 4, 0, 1]);

        let mut d = Deque::new();
        for i in 0..5 {
            d.push_back(i);
        }
        d.rotate(-2);
        assert_eq!(d.append_to_slice(Vec::new()), vec![3, 4, 0, 1, 2]);
    }

    #[test]
    fn clear_then_reuse() {
        let mut d = Deque::new();
        for i in 0..10 {
            d.push_back(i);
        }
        d.clear();
        assert!(d.is_empty());
        d.push_back(42);
        assert_eq!(*d.front(), 42);
    }

    #[test]
    fn copy_between_deques() {
        let mut src = Deque::new();
        for i in 0..4 {
            src.push_back(i);
        }
        let mut dst = Deque::new();
        dst.push_back(999);
        let n = dst.copy(&src);
        assert_eq!(n, 4);
        assert_eq!(dst.append_to_slice(Vec::new()), vec![0, 1, 2, 3]);
    }

    #[test]
    fn copy_in_and_out_slice() {
        let mut d = Deque::new();
        d.copy_in_slice(&[1, 2, 3, 4]);
        assert_eq!(d.len(), 4);

        let mut out = vec![0; 2];
        let n = d.copy_out_slice(&mut out);
        assert_eq!(n, 2);
        assert_eq!(out, vec![1, 2]);

        d.copy_in_slice(&[]);
        assert!(d.is_empty());
    }

    #[test]
    fn iter_pop_front_and_back_with_stop() {
        let mut d = Deque::new();
        for i in 0..5 {
            d.push_back(i);
        }
        let mut popped = Vec::new();
        d.iter_pop_front(|v| {
            popped.push(v);
            v < 2
        });
        assert_eq!(popped, vec![0, 1, 2]);
        assert_eq!(d.len(), 2);

        let mut d = Deque::new();
        for i in 0..5 {
            d.push_back(i);
        }
        let mut popped = Vec::new();
        d.iter_pop_back(|v| {
            popped.push(v);
            v > 2
        });
        assert_eq!(popped, vec![4, 3, 2]);
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn grow_reserves_capacity_without_changing_contents() {
        let mut d = Deque::new();
        d.push_back(1);
        d.grow(50);
        assert_eq!(d.append_to_slice(Vec::new()), vec![1]);
        assert!(d.cap() >= 51);
    }

    #[test]
    #[should_panic(expected = "deque: index out of range")]
    fn at_out_of_range_panics() {
        let d: Deque<i32> = Deque::new();
        // The panic is the assertion; the returned value is irrelevant here.
        let _ = d.at(0);
    }

    #[test]
    #[should_panic(expected = "deque: PopFront() called on empty queue")]
    fn pop_front_empty_panics() {
        let mut d: Deque<i32> = Deque::new();
        d.pop_front();
    }
}

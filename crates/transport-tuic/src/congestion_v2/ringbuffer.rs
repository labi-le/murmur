/// A `RingBuffer` is a ring buffer.
/// It acts as a heap that doesn't cause any allocations.
#[derive(Debug)]
pub struct RingBuffer<T> {
    ring: Vec<T>,
    head_pos: usize,
    tail_pos: usize,
    full: bool,
}

impl<T> Default for RingBuffer<T> {
    fn default() -> Self {
        Self { ring: Vec::new(), head_pos: 0, tail_pos: 0, full: false }
    }
}

impl<T: Clone + Default> RingBuffer<T> {
    /// Init preallocs a buffer with a certain size.
    pub fn init(&mut self, size: usize) {
        self.ring = vec![T::default(); size];
    }

    /// Len returns the number of elements in the ring buffer.
    ///
    /// the buffer exposes no `is_empty` counterpart under that name.
    #[allow(
        clippy::len_without_is_empty,
        reason = "the ring buffer's `len` counts live elements and exposes no `is_empty` counterpart"
    )]
    #[must_use]
    pub const fn len(&self) -> usize {
        if self.full {
            return self.ring.len();
        }
        if self.tail_pos >= self.head_pos {
            return self.tail_pos - self.head_pos;
        }
        self.tail_pos - self.head_pos + self.ring.len()
    }

    /// Empty says if the ring buffer is empty.
    #[must_use]
    pub const fn empty(&self) -> bool {
        !self.full && self.head_pos == self.tail_pos
    }

    /// Adds a new element.
    /// If the ring buffer is full, its capacity is increased first.
    #[expect(clippy::indexing_slicing, reason = "grow() leaves a non-empty ring and tail_pos is always a valid index")]
    pub fn push_back(&mut self, t: T) {
        if self.full || self.ring.is_empty() {
            self.grow();
        }
        self.ring[self.tail_pos] = t;
        self.tail_pos += 1;
        if self.tail_pos == self.ring.len() {
            self.tail_pos = 0;
        }
        if self.tail_pos == self.head_pos {
            self.full = true;
        }
    }

    /// `PopFront` returns the next element.
    /// It must not be called when the buffer is empty, that means that
    /// callers might need to check if there are elements in the buffer first.
    #[expect(clippy::indexing_slicing, reason = "the assert rejects an empty ring, so head_pos is a valid index")]
    pub fn pop_front(&mut self) -> T {
        assert!(!self.empty(), "ringbuffer: pop from an empty queue");
        self.full = false;
        let t = self.ring[self.head_pos].clone();
        self.ring[self.head_pos] = T::default();
        self.head_pos += 1;
        if self.head_pos == self.ring.len() {
            self.head_pos = 0;
        }
        t
    }

    /// Offset returns the offset element.
    /// It must not be called when the buffer is empty, that means that
    /// callers might need to check if there are elements in the buffer first
    /// and check if the index larger than buffer length.
    #[must_use]
    #[expect(
        clippy::indexing_slicing,
        reason = "the assert bounds index below len(), so the wrap-around offset is valid"
    )]
    pub fn offset(&self, index: usize) -> &T {
        assert!(!(self.empty() || index >= self.len()), "ringbuffer: offset from invalid index");
        let offset = (self.head_pos + index) % self.ring.len();
        &self.ring[offset]
    }

    /// Front returns the front element.
    /// It must not be called when the buffer is empty, that means that
    /// callers might need to check if there are elements in the buffer first.
    #[must_use]
    #[expect(clippy::indexing_slicing, reason = "the assert rejects an empty ring, so head_pos is a valid index")]
    pub fn front(&self) -> &T {
        assert!(!self.empty(), "ringbuffer: front from an empty queue");
        &self.ring[self.head_pos]
    }

    /// Back returns the back element.
    /// It must not be called when the buffer is empty, that means that
    /// callers might need to check if there are elements in the buffer first.
    #[must_use]
    pub fn back(&self) -> &T {
        assert!(!self.empty(), "ringbuffer: back from an empty queue");
        self.offset(self.len() - 1)
    }

    /// Grow the maximum size of the queue.
    /// This method assume the queue is full.
    fn grow(&mut self) {
        let old_ring = std::mem::take(&mut self.ring);
        let new_size = if old_ring.len() * 2 == 0 { 1 } else { old_ring.len() * 2 };
        let mut ring = vec![T::default(); new_size];
        let head_len = old_ring.len() - self.head_pos;
        let (old_low, old_high) = old_ring.split_at(self.head_pos);
        let (ring_low, ring_high) = ring.split_at_mut(head_len);
        ring_low.clone_from_slice(old_high);
        let (ring_mid, _) = ring_high.split_at_mut(self.head_pos);
        ring_mid.clone_from_slice(old_low);
        self.ring = ring;
        self.head_pos = 0;
        self.tail_pos = old_ring.len();
        self.full = false;
    }

    /// Clear removes all elements.
    pub fn clear(&mut self) {
        self.ring.fill(T::default());
        self.head_pos = 0;
        self.tail_pos = 0;
        self.full = false;
    }
}

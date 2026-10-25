/// The entry stores its list identity rather than comparing against a list pointer's head/tail fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ListId {
    T1,
    B1,
    T2,
    B2,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct List {
    head: Option<usize>,
    tail: Option<usize>,
    pub(crate) len: i32,
}

#[derive(Debug)]
pub(crate) struct Entry<K, V> {
    pub(crate) key: K,
    pub(crate) value: V,
    pub(crate) ll: Option<ListId>,
    prev: Option<usize>,
    next: Option<usize>,
    pub(crate) ghost: bool,
    pub(crate) expires: i64,
}

impl<K, V> Entry<K, V> {
    pub(crate) const fn new(key: K, value: V, ghost: bool, expires: i64) -> Self {
        Self { key, value, ll: None, prev: None, next: None, ghost, expires }
    }
}

/// Arena-backed intrusive list set: entries are slot indices and `el` is implied by the slot's
/// position.
#[derive(Debug)]
pub(crate) struct EntryLists<K, V> {
    entries: Vec<Option<Entry<K, V>>>,
    free: Vec<usize>,
    lists: [List; 4],
}

impl<K, V> Default for EntryLists<K, V> {
    fn default() -> Self {
        Self { entries: Vec::new(), free: Vec::new(), lists: [List::default(); 4] }
    }
}

impl<K, V> EntryLists<K, V> {
    /// The list `id` names, reached by variant so the array needs no runtime index.
    fn list(&self, id: ListId) -> &List {
        match id {
            ListId::T1 => &self.lists[0],
            ListId::B1 => &self.lists[1],
            ListId::T2 => &self.lists[2],
            ListId::B2 => &self.lists[3],
        }
    }

    fn list_mut(&mut self, id: ListId) -> &mut List {
        match id {
            ListId::T1 => &mut self.lists[0],
            ListId::B1 => &mut self.lists[1],
            ListId::T2 => &mut self.lists[2],
            ListId::B2 => &mut self.lists[3],
        }
    }

    pub(crate) fn alloc(&mut self, entry: Entry<K, V>) -> usize {
        if let Some(index) = self.free.pop() {
            if let Some(slot) = self.entries.get_mut(index) {
                *slot = Some(entry);
            }
            index
        } else {
            self.entries.push(Some(entry));
            self.entries.len() - 1
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "a slot index is only ever handed out by `alloc`, which leaves a live entry at it"
    )]
    pub(crate) fn take(&mut self, index: usize) -> Entry<K, V> {
        let entry = self.entries.get_mut(index).and_then(Option::take).expect("entry index refers to a live entry");
        self.free.push(index);
        entry
    }

    #[expect(
        clippy::expect_used,
        reason = "a slot index is only ever handed out by `alloc`, which leaves a live entry at it"
    )]
    pub(crate) fn get(&self, index: usize) -> &Entry<K, V> {
        self.entries.get(index).and_then(Option::as_ref).expect("entry index refers to a live entry")
    }

    #[expect(
        clippy::expect_used,
        reason = "a slot index is only ever handed out by `alloc`, which leaves a live entry at it"
    )]
    pub(crate) fn get_mut(&mut self, index: usize) -> &mut Entry<K, V> {
        self.entries.get_mut(index).and_then(Option::as_mut).expect("entry index refers to a live entry")
    }

    pub(crate) fn list_len(&self, id: ListId) -> i32 {
        self.list(id).len
    }

    pub(crate) fn list_back(&self, id: ListId) -> Option<usize> {
        self.list(id).tail
    }

    pub(crate) fn pop_back(&mut self, id: ListId) -> Option<usize> {
        let index = self.list(id).tail?;
        self.unlink(index, id);
        Some(index)
    }

    pub(crate) fn detach(&mut self, index: usize) {
        if let Some(id) = self.get(index).ll {
            self.unlink(index, id);
        }
    }

    pub(crate) fn set_mru(&mut self, index: usize, id: ListId) {
        self.detach(index);
        self.push_front(index, id);
    }

    fn push_front(&mut self, index: usize, id: ListId) {
        let old_head = self.list(id).head;
        let entry = self.get_mut(index);
        entry.prev = None;
        entry.next = old_head;
        match old_head {
            Some(head) => self.get_mut(head).prev = Some(index),
            None => self.list_mut(id).tail = Some(index),
        }
        let list = self.list_mut(id);
        list.head = Some(index);
        list.len += 1;
        self.get_mut(index).ll = Some(id);
    }

    fn unlink(&mut self, index: usize, id: ListId) {
        let (prev, next) = {
            let entry = self.get(index);
            (entry.prev, entry.next)
        };
        match prev {
            Some(prev) => self.get_mut(prev).next = next,
            None => self.list_mut(id).head = next,
        }
        match next {
            Some(next) => self.get_mut(next).prev = prev,
            None => self.list_mut(id).tail = prev,
        }
        let entry = self.get_mut(index);
        entry.prev = None;
        entry.next = None;
        self.list_mut(id).len -= 1;
    }
}

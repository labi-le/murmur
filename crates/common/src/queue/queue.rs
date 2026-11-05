use std::collections::VecDeque;

use parking_lot::RwLock;

/// a simple concurrent safe queue.
#[derive(Debug)]
pub struct Queue<T> {
    items: RwLock<VecDeque<T>>,
}

impl<T> Queue<T> {
    /// adds the items to the queue.
    pub fn put(&self, items: impl IntoIterator<Item = T>) {
        let mut items = items.into_iter();
        let Some(first) = items.next() else {
            return;
        };

        let mut guard = self.items.write();
        guard.push_back(first);
        guard.extend(items);
    }

    /// the head of the items.
    pub fn pop(&self) -> Option<T> {
        self.items.write().pop_front()
    }

    /// the number of items in this queue.
    pub fn len(&self) -> i64 {
        i64::try_from(self.items.read().len()).unwrap_or(i64::MAX)
    }

    pub fn is_empty(&self) -> bool {
        self.items.read().is_empty()
    }
}

impl<T: Clone> Queue<T> {
    /// the last item.
    pub fn last(&self) -> Option<T> {
        self.items.read().back().cloned()
    }

    /// a copy of the queue, oldest item first.
    pub fn copy(&self) -> Vec<T> {
        self.items.read().iter().cloned().collect()
    }
}

/// a constructor for a new concurrent safe queue.
#[must_use]
pub fn new<T>(hint: i64) -> Queue<T> {
    Queue { items: RwLock::new(VecDeque::with_capacity(usize::try_from(hint).unwrap_or_default())) }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use parking_lot::Mutex;
    use tokio::task::JoinSet;

    use super::*;

    #[test]
    fn test_queue_put() {
        let q = new::<i32>(10);

        q.put([1]);
        assert_eq!(1, q.len(), "Queue length should be 1 after putting one item");

        q.put([2, 3, 4]);
        assert_eq!(4, q.len(), "Queue length should be 4 after putting three more items");

        q.put([]);
        assert_eq!(4, q.len(), "Queue length should remain unchanged when putting zero items");
    }

    #[test]
    fn test_queue_pop() {
        let q = new::<i32>(10);
        q.put([1, 2, 3]);

        let item = q.pop();
        assert_eq!(Some(1), item, "First item popped should be 1");
        assert_eq!(2, q.len(), "Queue length should be 2 after popping one item");

        let item = q.pop();
        assert_eq!(Some(2), item, "Second item popped should be 2");
        assert_eq!(1, q.len(), "Queue length should be 1 after popping two items");

        let item = q.pop();
        assert_eq!(Some(3), item, "Third item popped should be 3");
        assert_eq!(0, q.len(), "Queue length should be 0 after popping all items");
    }

    #[test]
    fn test_queue_pop_empty() {
        let q = new::<i32>(0);

        let item = q.pop();
        assert_eq!(None, item, "Popping from an empty queue should return the zero value");
        assert_eq!(0, q.len(), "Queue length should remain 0 after popping from an empty queue");
    }

    #[test]
    fn test_queue_last() {
        let q = new::<i32>(10);
        q.put([1, 2, 3]);

        let item = q.last();
        assert_eq!(Some(3), item, "Last item should be 3");
        assert_eq!(3, q.len(), "Queue length should remain unchanged after calling Last");

        let empty_q = new::<i32>(0);
        let empty_item = empty_q.last();
        assert_eq!(None, empty_item, "Last on an empty queue should return the zero value");
    }

    #[test]
    fn test_queue_copy() {
        let q = new::<i32>(10);
        q.put([1, 2, 3]);

        let copied = q.copy();
        assert_eq!(3, copied.len(), "Copy should have the same number of items as the original queue");
        assert_eq!(1, copied[0], "First item in copy should be 1");
        assert_eq!(2, copied[1], "Second item in copy should be 2");
        assert_eq!(3, copied[2], "Third item in copy should be 3");

        let mut copied = copied;
        copied[0] = 99;
        assert_eq!(Some(1), q.pop(), "Original queue should not be affected by modifying the copy");
    }

    #[test]
    fn test_queue_len() {
        let q = new::<i32>(10);
        assert_eq!(0, q.len(), "New queue should have length 0");

        q.put([1, 2]);
        assert_eq!(2, q.len(), "Queue length should be 2 after putting two items");

        q.pop();
        assert_eq!(1, q.len(), "Queue length should be 1 after popping one item");
    }

    #[test]
    fn test_queue_new() {
        let q1 = new::<i32>(0);
        assert_eq!(0, q1.len(), "New queue should have length 0");

        let q2 = new::<i32>(10);
        assert_eq!(0, q2.len(), "New queue should have length 0");

        let q3 = new::<String>(5);
        assert_eq!(0, q3.len(), "New queue should have length 0");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_queue_concurrency() {
        let q = Arc::new(new::<i32>(100));

        let task_count = 10;
        let operations = 100;

        let mut tasks = JoinSet::new();

        for id in 0..task_count {
            let q = Arc::clone(&q);
            tasks.spawn(async move {
                for j in 0..operations {
                    q.put([id * operations + j]);
                    tokio::time::sleep(Duration::from_micros(1)).await;
                }
            });
        }

        let consumed = Arc::new(Mutex::new(Vec::new()));
        for _ in 0..task_count {
            let q = Arc::clone(&q);
            let consumed = Arc::clone(&consumed);
            tasks.spawn(async move {
                for _ in 0..operations {
                    if let Some(item) = q.pop() {
                        consumed.lock().push(item);
                    }
                    tokio::time::sleep(Duration::from_micros(1)).await;
                }
            });
        }

        while tasks.join_next().await.is_some() {}
        let consumed_count = consumed.lock().len() as i64;

        let total_items = task_count * operations;
        let remaining = q.len();
        assert_eq!(
            total_items as i64,
            consumed_count + remaining,
            "Total items should equal consumed items plus remaining items"
        );
    }

    #[test]
    fn test_queue_with_different_types() {
        let q_string = new::<String>(5);
        q_string.put(["hello".to_owned(), "world".to_owned()]);
        assert_eq!(2, q_string.len(), "Queue length should be 2");
        assert_eq!(Some("hello".to_owned()), q_string.pop(), "First item should be 'hello'");
        assert_eq!(Some("world".to_owned()), q_string.pop(), "Second item should be 'world'");

        struct Person {
            name: String,
            age: i32,
        }

        let q_struct = new::<Person>(5);
        q_struct.put([Person { name: "Alice".to_owned(), age: 30 }, Person { name: "Bob".to_owned(), age: 25 }]);
        assert_eq!(2, q_struct.len(), "Queue length should be 2");

        let first_person = q_struct.pop();
        assert_eq!(Some(30), first_person.as_ref().map(|person| person.age));
        assert_eq!(
            Some("Alice".to_owned()),
            first_person.map(|person| person.name),
            "First person's name should be 'Alice'"
        );
        let second_person = q_struct.pop();
        assert_eq!(
            Some("Bob".to_owned()),
            second_person.map(|person| person.name),
            "Second person's name should be 'Bob'"
        );
    }
}

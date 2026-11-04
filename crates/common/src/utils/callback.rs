use std::fmt;
use std::sync::{Arc, Once};

use parking_lot::RwLock;

type Entry<T> = Arc<dyn Fn(T) + Send + Sync>;

/// A value that can be closed.
pub trait Closer: Send + Sync {
    fn close(&self) -> anyhow::Result<()>;
}

impl<T> fmt::Debug for Callback<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Callback")
    }
}

pub struct Callback<T> {
    list: Arc<RwLock<Vec<Entry<T>>>>,
}

impl<T> Default for Callback<T> {
    fn default() -> Self {
        new_callback()
    }
}

#[must_use]
pub fn new_callback<T>() -> Callback<T> {
    Callback { list: Arc::new(RwLock::new(Vec::new())) }
}

impl<T: Clone + Send + 'static> Callback<T> {
    pub fn register(&self, item: impl Fn(T) + Send + Sync + 'static) -> CallbackCloser<T> {
        let element: Entry<T> = Arc::new(item);
        self.list.write().push(Arc::clone(&element));
        CallbackCloser { element, list: Arc::clone(&self.list), once: Once::new() }
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "each subscriber gets its own copy of the item, so the caller gives the original up"
    )]
    pub fn emit(&self, item: T) {
        let list = self.list.read();
        for element in list.iter() {
            let element = Arc::clone(element);
            let item = item.clone();
            tokio::spawn(async move { element(item) });
        }
    }
}

pub struct CallbackCloser<T> {
    element: Entry<T>,
    list: Arc<RwLock<Vec<Entry<T>>>>,
    once: Once,
}

impl<T> fmt::Debug for CallbackCloser<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallbackCloser")
    }
}

impl<T> Closer for CallbackCloser<T> {
    fn close(&self) -> anyhow::Result<()> {
        self.once.call_once(|| {
            self.list.write().retain(|element| !Arc::ptr_eq(element, &self.element));
        });
        Ok(())
    }
}

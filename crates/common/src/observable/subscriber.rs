use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::Once;

use parking_lot::Mutex;
use tokio::sync::mpsc;

/// The receiving end of a subscriber's channel.
///
/// the channel value is a copyable handle, which the `Arc` mirrors; the observable keys
/// its subscribers by this handle's identity.
pub struct Subscription<T> {
    buffer: Arc<tokio::sync::Mutex<mpsc::Receiver<T>>>,
}

impl<T> Subscription<T> {
    pub(crate) fn new(buffer: mpsc::Receiver<T>) -> Self {
        Self { buffer: Arc::new(tokio::sync::Mutex::new(buffer)) }
    }

    /// Receives the next item, or `None` once the subscriber has been closed and its
    /// buffered items are drained.
    pub async fn recv(&self) -> Option<T> {
        // cancel-safe: the channel receive and the tokio mutex both leave the receiver untouched
        // when the future is dropped.
        self.buffer.lock().await.recv().await
    }
}

impl<T> Clone for Subscription<T> {
    fn clone(&self) -> Self {
        Self { buffer: Arc::clone(&self.buffer) }
    }
}

impl<T> PartialEq for Subscription<T> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.buffer, &other.buffer)
    }
}

impl<T> Eq for Subscription<T> {}

impl<T> Hash for Subscription<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize(Arc::as_ptr(&self.buffer) as usize);
    }
}

impl<T> fmt::Debug for Subscription<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Subscription")
    }
}

#[derive(Debug)]
pub struct Subscriber<T> {
    buffer: Mutex<Option<mpsc::Sender<T>>>,
    out: Subscription<T>,
    once: Once,
}

impl<T> Subscriber<T> {
    /// Sends one item, blocking until the subscriber's buffered channel has room.
    ///
    /// A send blocks indefinitely when the channel has no receiver left; sending stops
    /// instead, `send` reporting the dropped receiver.
    pub async fn emit(&self, item: T) {
        // cancel-safe: the sender is cloned under a guard that is released before the await, and a
        // dropped `mpsc::Sender::send` sends nothing.
        let sender = self.buffer.lock().as_ref().cloned();
        if let Some(sender) = sender {
            let _ = sender.send(item).await;
        }
    }

    pub const fn out(&self) -> &Subscription<T> {
        &self.out
    }

    pub fn close(&self) {
        self.once.call_once(|| {
            // Closing the channel is done by dropping the sending half, which leaves the buffered items
            // receivable and then ends the stream.
            self.buffer.lock().take();
        });
    }
}

pub(crate) fn new_subscriber<T>() -> Arc<Subscriber<T>> {
    let (buffer, out) = mpsc::channel(200);
    Arc::new(Subscriber { buffer: Mutex::new(Some(buffer)), out: Subscription::new(out), once: Once::new() })
}

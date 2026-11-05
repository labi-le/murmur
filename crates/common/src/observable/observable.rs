use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use super::iterable::Iterable;
use super::subscriber::{new_subscriber, Subscriber, Subscription};

///
/// One mutex guards `listener`, `done` and the close signal; the listener map carries that
/// mutex here, and `done` is a plain flag, since the map lock is still held around every read
/// and write of it.
#[derive(Debug)]
pub struct Observable<T> {
    iterable: Mutex<mpsc::Receiver<T>>,
    listener: Mutex<HashMap<Subscription<T>, Arc<Subscriber<T>>>>,
    done: AtomicBool,
    stop_ch: CancellationToken,
}

impl<T> Observable<T> {
    // cancel-safe: the listener lock is the only await, and nothing is mutated before it is held.
    pub(crate) async fn close(&self) {
        let listener = self.listener.lock().await;

        self.done.store(true, Ordering::SeqCst);
        for sub in listener.values() {
            sub.close();
        }
        drop(listener);
        self.stop_ch.cancel();
    }

    // cancel-safe: the listener lock is the only await, and the insert runs once it is held.
    pub async fn subscribe(&self) -> anyhow::Result<Subscription<T>> {
        let mut listener = self.listener.lock().await;
        if self.done.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("observable is closed"));
        }
        let subscriber = new_subscriber::<T>();
        listener.insert(subscriber.out().clone(), Arc::clone(&subscriber));
        drop(listener);
        Ok(subscriber.out().clone())
    }

    // cancel-safe: the listener lock is the only await, and the removal runs once it is held.
    pub async fn unsubscribe(&self, sub: Subscription<T>) {
        let mut listener = self.listener.lock().await;
        let Some(subscriber) = listener.remove(&sub) else {
            return;
        };
        drop(listener);
        subscriber.close();
    }
}

impl<T: Clone + Send + 'static> Observable<T> {
    // NOT cancel-safe: an item already taken from the channel is lost for the subscribers the
    // running loop has not reached yet.
    async fn process(self: Arc<Self>) {
        let mut iterable = self.iterable.lock().await;
        while let Some(item) = iterable.recv().await {
            let listener = self.listener.lock().await;
            for sub in listener.values() {
                // the channel send copies the item for each subscriber.
                sub.emit(item.clone()).await;
            }
        }
        drop(iterable);
        self.close().await;
    }
}

#[must_use]
pub fn new_observable<T: Clone + Send + 'static>(iter: Iterable<T>) -> Arc<Observable<T>> {
    let observable = Arc::new(Observable {
        iterable: Mutex::new(iter),
        listener: Mutex::new(HashMap::new()),
        done: AtomicBool::new(false),
        stop_ch: CancellationToken::new(),
    });
    tokio::spawn({
        let observable = Arc::clone(&observable);
        async move { observable.process().await }
    });
    observable
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicI32;
    use std::time::Duration;

    use super::*;

    fn iterator<T: Send + 'static>(item: Vec<T>) -> Iterable<T> {
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            for elm in item {
                if tx.send(elm).await.is_err() {
                    break;
                }
            }
        });
        rx
    }

    #[tokio::test]
    async fn test_observable() {
        let iter = iterator(vec![1, 2, 3, 4, 5]);
        let src = new_observable(iter);
        let data = src.subscribe().await.expect("subscribe");
        let mut count = 0;
        while data.recv().await.is_some() {
            count += 1;
        }
        assert_eq!(5, count);
    }

    #[tokio::test]
    async fn test_observable_multi_subscribe() {
        let iter = iterator(vec![1, 2, 3, 4, 5]);
        let src = new_observable(iter);
        let ch1 = src.subscribe().await.expect("subscribe");
        let ch2 = src.subscribe().await.expect("subscribe");
        let count = Arc::new(AtomicI32::new(0));

        let first = Arc::clone(&count);
        let h1 = tokio::spawn(async move {
            while ch1.recv().await.is_some() {
                first.fetch_add(1, Ordering::SeqCst);
            }
        });
        let second = Arc::clone(&count);
        let h2 = tokio::spawn(async move {
            while ch2.recv().await.is_some() {
                second.fetch_add(1, Ordering::SeqCst);
            }
        });
        h1.await.expect("join");
        h2.await.expect("join");
        assert_eq!(10, count.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_observable_unsubscribe() {
        let iter = iterator(vec![1, 2, 3, 4, 5]);
        let src = new_observable(iter);
        let data = src.subscribe().await.expect("subscribe");
        src.unsubscribe(data.clone()).await;
        assert!(data.recv().await.is_none());
    }

    #[tokio::test]
    async fn test_observable_subscribe_closed_source() {
        let iter = iterator(vec![1]);
        let src = new_observable(iter);
        let data = src.subscribe().await.expect("subscribe");
        assert!(data.recv().await.is_some());
        tokio::time::timeout(Duration::from_secs(1), src.stop_ch.cancelled()).await.expect("timeout not stop");
    }

    #[tokio::test]
    async fn test_observable_unsubscribe_with_not_exist_subscription() {
        let (_tx, rx) = mpsc::channel::<i32>(1);
        let sub = Subscription::new(rx);
        let iter = iterator(vec![1]);
        let src = new_observable(iter);
        src.unsubscribe(sub).await;
    }

    #[tokio::test]
    async fn test_observable_subscribe_task_leak() {
        let iter = iterator(vec![1, 2, 3, 4, 5]);
        let src = new_observable(iter);
        let max = 100;

        let mut list = Vec::new();
        for _ in 0..max {
            list.push(src.subscribe().await.expect("subscribe"));
        }

        let mut readers = Vec::new();
        for sub in &list {
            let sub = sub.clone();
            readers.push(tokio::spawn(async move { while sub.recv().await.is_some() {} }));
        }
        for reader in readers {
            reader.await.expect("join");
        }

        for sub in &list {
            assert!(sub.recv().await.is_none());
        }

        assert!(list[0].recv().await.is_none());
    }
}

use std::future::Future;

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub type Factory<T> = Box<dyn Fn(CancellationToken) -> BoxFuture<'static, anyhow::Result<T>> + Send + Sync>;

/// The option closure type, renamed from `Option` to avoid shadowing `std::option::Option`.
pub type PoolOption<T> = Box<dyn FnOnce(&mut PoolInner<T>)>;

pub(crate) struct Entry<T> {
    elm: T,
    time: DateTime<Utc>,
}

pub(crate) struct Chan<T> {
    capacity: usize,
    tx: mpsc::Sender<T>,
    rx: Mutex<mpsc::Receiver<T>>,
}

impl<T> Chan<T> {
    fn new(capacity: usize) -> Self {
        // a zero capacity is the unbuffered channel, only sending to a waiting receiver.
        let (tx, rx) = mpsc::channel(capacity.max(1));
        Self { capacity, tx, rx: Mutex::new(rx) }
    }

    fn try_send(&self, value: T) -> Result<(), T> {
        if self.capacity == 0 {
            return Err(value);
        }
        self.tx.try_send(value).map_err(mpsc::error::TrySendError::into_inner)
    }

    fn try_recv(&self) -> Result<T, mpsc::error::TryRecvError> {
        self.rx.lock().try_recv()
    }
}

/// The private inner pool; public because the `PoolOption` alias names it.
pub struct PoolInner<T> {
    ch: Chan<Entry<T>>,
    factory: Factory<T>,
    evict: Option<Box<dyn Fn(T) + Send + Sync>>,
    max_age: Option<i64>,
}

impl<T> std::fmt::Debug for PoolInner<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolInner").finish_non_exhaustive()
    }
}

impl<T> PoolInner<T> {
    // NOT cancel-safe: a pool miss ends in the fallback factory, whose already-started connection a dropped call abandons.
    pub async fn get_context(&self, ctx: CancellationToken) -> anyhow::Result<T> {
        let now = Utc::now();
        loop {
            match self.ch.try_recv() {
                Ok(item) => {
                    if let Some(max_age) = self.max_age {
                        if (now - item.time).num_milliseconds() > max_age {
                            if let Some(evict) = &self.evict {
                                evict(item.elm);
                            }
                            continue;
                        }
                    }

                    return Ok(item.elm);
                }
                Err(_) => return (self.factory)(ctx).await,
            }
        }
    }

    // NOT cancel-safe: on a pool miss the fallback factory has already started opening a connection, which a dropped call abandons instead of returning to the pool.
    pub async fn get(&self) -> anyhow::Result<T> {
        self.get_context(CancellationToken::new()).await
    }

    pub fn put(&self, item: T) {
        let e = Entry { elm: item, time: Utc::now() };

        match self.ch.try_send(e) {
            Ok(()) => {}
            Err(e) => {
                // pool is full
                if let Some(evict) = &self.evict {
                    evict(e.elm);
                }
            }
        }
    }
}

/// Pool is for GC, see New for detail
pub struct Pool<T> {
    pub(crate) pool: PoolInner<T>,
}

impl<T> std::fmt::Debug for Pool<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool").finish_non_exhaustive()
    }
}

impl<T> Pool<T> {
    // NOT cancel-safe: pure delegation to PoolInner::get_context, whose pool miss abandons the connection the factory has started opening.
    pub async fn get_context(&self, ctx: CancellationToken) -> anyhow::Result<T> {
        self.pool.get_context(ctx).await
    }

    // NOT cancel-safe: pure delegation to PoolInner::get, whose pool miss abandons the connection the factory has started opening.
    pub async fn get(&self) -> anyhow::Result<T> {
        self.pool.get().await
    }

    pub fn put(&self, item: T) {
        self.pool.put(item);
    }
}

pub(crate) fn recycle<T>(p: &Pool<T>) {
    while let Ok(item) = p.pool.ch.try_recv() {
        if let Some(evict) = &p.pool.evict {
            evict(item.elm);
        }
    }
}

impl<T> Drop for Pool<T> {
    fn drop(&mut self) {
        recycle(self);
    }
}

/// Sets the evict callback.
pub fn with_evict<T>(cb: impl Fn(T) + Send + Sync + 'static) -> PoolOption<T> {
    Box::new(move |p: &mut PoolInner<T>| {
        p.evict = Some(Box::new(cb));
    })
}

/// The element max age in milliseconds; zero means no max age.
#[must_use]
pub fn with_age<T>(max_age: i64) -> PoolOption<T> {
    Box::new(move |p: &mut PoolInner<T>| {
        p.max_age = (max_age != 0).then_some(max_age);
    })
}

/// Defines the max size of the pool.
#[must_use]
pub fn with_size<T>(max_size: usize) -> PoolOption<T> {
    Box::new(move |p: &mut PoolInner<T>| {
        p.ch = Chan::new(max_size);
    })
}

pub fn new<T, F, Fut>(factory: F, options: Vec<PoolOption<T>>) -> Pool<T>
where
    F: Fn(CancellationToken) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<T>> + Send + 'static,
{
    let mut p = PoolInner::<T> {
        ch: Chan::new(10),
        factory: Box::new(move |ctx: CancellationToken| -> BoxFuture<'static, anyhow::Result<T>> {
            Box::pin(factory(ctx))
        }),
        evict: None,
        max_age: None,
    };

    for option in options {
        option(&mut p);
    }

    Pool { pool: p }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lg() -> impl Fn(CancellationToken) -> BoxFuture<'static, anyhow::Result<i32>> {
        let initial = std::sync::Arc::new(Mutex::new(-1));
        move |_ctx| {
            let initial = std::sync::Arc::clone(&initial);
            Box::pin(async move {
                *initial.lock() += 1;
                Ok(*initial.lock())
            })
        }
    }

    #[tokio::test]
    async fn test_pool_basic() {
        let g = lg();
        let pool = new::<i32, _, _>(g, Vec::new());

        let elm = pool.get().await.unwrap();
        assert_eq!(0, elm);
        pool.put(elm);
        let elm = pool.get().await.unwrap();
        assert_eq!(0, elm);
        let elm = pool.get().await.unwrap();
        assert_eq!(1, elm);
    }

    #[tokio::test]
    async fn test_pool_max_size() {
        let g = lg();
        let size = 5usize;
        let pool = new::<i32, _, _>(g, vec![with_size(size)]);

        let mut items = Vec::new();

        for _ in 0..size {
            items.push(pool.get().await.unwrap());
        }

        let extra = pool.get().await.unwrap();
        assert_eq!(size as i32, extra);

        for item in &items {
            pool.put(*item);
        }

        pool.put(extra);

        for item in &items {
            let elm = pool.get().await.unwrap();
            assert_eq!(*item, elm);
        }
    }

    #[tokio::test]
    async fn test_pool_max_age() {
        let g = lg();
        let pool = new::<i32, _, _>(g, vec![with_age(20)]);

        let elm = pool.get().await.unwrap();
        pool.put(elm);

        let elm = pool.get().await.unwrap();
        assert_eq!(0, elm);
        pool.put(elm);

        tokio::time::sleep(std::time::Duration::from_millis(22)).await;
        let elm = pool.get().await.unwrap();
        assert_eq!(1, elm);
    }
}

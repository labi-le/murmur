pub mod lrucache;

pub use lrucache::{
    new, with_age, with_evict, with_size, with_stale, with_update_age_on_get, EvictCallback, LruCache, LruOption,
};

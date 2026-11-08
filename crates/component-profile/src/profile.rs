use murmur_common::atomic::type_::{new_bool, Bool};

/// `StoreSelected` is a global switch for storing selected proxy to cache.
pub static STORE_SELECTED: Bool = new_bool(true);

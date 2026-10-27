use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering};

use portable_atomic::{AtomicI64, AtomicU64};
use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

/// Expands the wrappers that differ only in payload type, so every one of them keeps the same
/// load/store/swap/compare-and-swap surface every wrapper shares.
macro_rules! atomic_wrapper {
    ($name:ident, $value:ty, $atomic:ty, $new:ident) => {
        #[derive(Debug)]
        pub struct $name {
            inner: $atomic,
        }

        impl Default for $name {
            fn default() -> Self {
                Self { inner: <$atomic>::new(<$value>::default()) }
            }
        }

        /// So that a module-level initializer can stay a `static`.
        pub const fn $new(val: $value) -> $name {
            $name { inner: <$atomic>::new(val) }
        }

        impl $name {
            pub fn load(&self) -> $value {
                self.inner.load(Ordering::SeqCst)
            }

            pub fn store(&self, val: $value) {
                self.inner.store(val, Ordering::SeqCst);
            }

            pub fn swap(&self, new: $value) -> $value {
                self.inner.swap(new, Ordering::SeqCst)
            }

            pub fn compare_and_swap(&self, old: $value, new: $value) -> bool {
                self.inner.compare_exchange(old, new, Ordering::SeqCst, Ordering::SeqCst).is_ok()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.load())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.load().serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                // A `null` payload leaves the zero value in place.
                let v = Option::<$value>::deserialize(deserializer)?.unwrap_or_default();
                let i = $name::default();
                i.store(v);
                Ok(i)
            }
        }
    };
}

atomic_wrapper!(Bool, bool, AtomicBool, new_bool);

/// The integer wrappers wrap the integer atomics, so they carry `add` as well.
macro_rules! atomic_int_wrapper {
    ($name:ident, $value:ty, $atomic:ty, $new:ident) => {
        atomic_wrapper!($name, $value, $atomic, $new);

        impl $name {
            pub fn add(&self, delta: $value) -> $value {
                self.inner.fetch_add(delta, Ordering::SeqCst).wrapping_add(delta)
            }
        }
    };
}

atomic_int_wrapper!(Int32, i32, AtomicI32, new_int32);
atomic_int_wrapper!(Int64, i64, AtomicI64, new_int64);
atomic_int_wrapper!(Uint32, u32, AtomicU32, new_uint32);
atomic_int_wrapper!(Uint64, u64, AtomicU64, new_uint64);
atomic_int_wrapper!(Uintptr, usize, AtomicUsize, new_uintptr);

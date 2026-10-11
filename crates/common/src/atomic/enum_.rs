use std::fmt;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicI32, Ordering};

use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

/// Stands in for the `T ~int32`: the payload type must convert to and from a plain `i32`.
pub trait Int32EnumValue: Copy {
    fn from_i32(v: i32) -> Self;
    fn into_i32(self) -> i32;
}

impl<T: Copy + From<i32> + Into<i32>> Int32EnumValue for T {
    fn from_i32(v: i32) -> Self {
        Self::from(v)
    }

    fn into_i32(self) -> i32 {
        self.into()
    }
}

#[derive(Debug)]
pub struct Int32Enum<T> {
    value: AtomicI32,
    _marker: PhantomData<fn() -> T>,
}

impl<T: Int32EnumValue> Default for Int32Enum<T> {
    fn default() -> Self {
        Self { value: AtomicI32::new(0), _marker: PhantomData }
    }
}

pub fn new_int32_enum<T: Int32EnumValue>(v: T) -> Int32Enum<T> {
    let a = Int32Enum::default();
    a.store(v);
    a
}

impl<T: Int32EnumValue> Int32Enum<T> {
    pub fn store(&self, v: T) {
        self.value.store(v.into_i32(), Ordering::SeqCst);
    }

    pub fn load(&self) -> T {
        T::from_i32(self.value.load(Ordering::SeqCst))
    }

    pub fn swap(&self, new: T) -> T {
        T::from_i32(self.value.swap(new.into_i32(), Ordering::SeqCst))
    }

    pub fn compare_and_swap(&self, old: T, new: T) -> bool {
        self.value.compare_exchange(old.into_i32(), new.into_i32(), Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }
}

impl<T: Int32EnumValue + fmt::Display> fmt::Display for Int32Enum<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.load())
    }
}

impl<T: Int32EnumValue + Serialize> Serialize for Int32Enum<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.load().serialize(serializer)
    }
}

impl<'de, T: Int32EnumValue + Deserialize<'de>> Deserialize<'de> for Int32Enum<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // A `null` payload leaves the zero value in place.
        let v = Option::<T>::deserialize(deserializer)?.unwrap_or_else(|| T::from_i32(0));
        let i = Self::default();
        i.store(v);
        Ok(i)
    }
}

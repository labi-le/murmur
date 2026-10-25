use std::sync::Arc;

use arc_swap::ArcSwapOption;
use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct TypedValue<T> {
    value: ArcSwapOption<T>,
}

impl<T> Default for TypedValue<T> {
    fn default() -> Self {
        Self { value: ArcSwapOption::const_empty() }
    }
}

impl<T> TypedValue<T> {
    /// `const` so that a never-stored value can live in a `static`.
    #[must_use]
    pub const fn new() -> Self {
        Self { value: ArcSwapOption::const_empty() }
    }

    /// The zero value is returned when nothing was stored.
    ///
    /// The zero value here is `T::default()`. For a payload whose source zero value is not Rust's
    /// `Default` — `DateTime<Utc>` defaults to the Unix epoch where the zero time is 0001-01-01 —
    /// read `load_ok`'s flag instead of trusting the value.
    pub fn load(&self) -> T
    where
        T: Clone + Default,
    {
        self.load_ok().0
    }

    pub fn load_ok(&self) -> (T, bool)
    where
        T: Clone + Default,
    {
        let value = self.value.load_full();
        match value {
            Some(value) => ((*value).clone(), true),
            None => (T::default(), false),
        }
    }

    pub fn store(&self, value: T) {
        self.value.store(Some(Arc::new(value)));
    }

    pub fn swap(&self, new: T) -> T
    where
        T: Clone + Default,
    {
        let old = self.value.swap(Some(Arc::new(new)));
        match old {
            Some(old) => (*old).clone(),
            None => T::default(),
        }
    }

    /// The compare-and-swap: `eq` decides how the stored value compares with `old`.
    ///
    /// The two are compared by value for scalars and by identity for pointers, channels and funcs.
    /// `compare_and_swap` supplies value equality; payloads holding pointers
    /// need `option_arc_ptr_eq` or an equivalent identity comparison.
    pub fn compare_and_swap_by<F>(&self, old: &T, new: &T, eq: F) -> bool
    where
        T: Clone + Default,
        F: Fn(&T, &T) -> bool,
    {
        loop {
            let current = self.value.load_full();
            let current_value = match &current {
                Some(value) => (**value).clone(),
                None => T::default(),
            };
            if !eq(&current_value, old) {
                return false;
            }
            let previous = self.value.compare_and_swap(&current, Some(Arc::new(new.clone())));
            match (&*previous, &current) {
                (None, None) => return true,
                (Some(previous), Some(current)) if Arc::ptr_eq(previous, current) => return true,
                _ => {}
            }
        }
    }

    /// The stored value is compared with `old` before the pointer swap, and the swap is retried
    /// while another thread keeps changing the pointer.
    pub fn compare_and_swap(&self, old: &T, new: &T) -> bool
    where
        T: Clone + Default + PartialEq,
    {
        self.compare_and_swap_by(old, new, |a, b| a == b)
    }
}

/// Interface equality on a payload holding a pointer: identity, or both null.
#[must_use]
pub fn option_arc_ptr_eq<T: ?Sized>(a: &Option<Arc<T>>, b: &Option<Arc<T>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    }
}

pub fn new_typed_value<T>(t: T) -> TypedValue<T> {
    let v = TypedValue::default();
    v.store(t);
    v
}

impl<T> Serialize for TypedValue<T>
where
    T: Serialize + Clone + Default,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.load().serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for TypedValue<T>
where
    T: Deserialize<'de> + Default,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // A `null` payload leaves the zero value in place.
        let v = Option::<T>::deserialize(deserializer)?.unwrap_or_default();
        let t = Self::default();
        t.store(v);
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// Stands in for the channels and readers compared by identity.
    #[derive(Debug, PartialEq, Eq)]
    struct Handle(u32);

    #[test]
    fn test_typed_value() {
        scalar_store_and_load_roundtrips();
        arc_str_store_and_load_roundtrips();
        pointer_identity_swaps_roundtrip();
        value_equality_is_not_pointer_identity();
    }

    fn scalar_store_and_load_roundtrips() {
        let v = TypedValue::<i32>::default();
        let (got, got_ok) = v.load_ok();
        assert_eq!((got, got_ok), (0, false));

        v.store(1);
        let (got, got_ok) = v.load_ok();
        assert_eq!((got, got_ok), (1, true));
    }

    fn arc_str_store_and_load_roundtrips() {
        let v = TypedValue::<Option<Arc<str>>>::default();
        let (got, got_ok) = v.load_ok();
        assert_eq!(got, None);
        assert!(!got_ok);

        v.store(Some(Arc::from("EOF")));
        let (got, got_ok) = v.load_ok();
        assert_eq!(got, Some(Arc::from("EOF")));
        assert!(got_ok);

        v.store(Some(Arc::from("path error")));
        let (got, got_ok) = v.load_ok();
        assert_eq!(got, Some(Arc::from("path error")));
        assert!(got_ok);

        v.store(None);
        let (got, got_ok) = v.load_ok();
        assert_eq!(got, None);
        assert!(got_ok);
    }

    fn pointer_identity_swaps_roundtrip() {
        let e1: Option<Arc<str>> = Some(Arc::from("EOF"));
        let e2: Option<Arc<str>> = Some(Arc::from("first path error"));
        let e3: Option<Arc<str>> = Some(Arc::from("second path error"));
        assert_pointer_identity_swap(e1, e2, e3);

        let h1 = Some(Arc::new(Handle(1)));
        let h2 = Some(Arc::new(Handle(2)));
        let h3 = Some(Arc::new(Handle(3)));
        assert_pointer_identity_swap(h1, h2, h3);

        let v1: Option<Arc<Vec<u8>>> = Some(Arc::new(vec![1]));
        let v2: Option<Arc<Vec<u8>>> = Some(Arc::new(vec![2]));
        let v3: Option<Arc<Vec<u8>>> = Some(Arc::new(vec![3]));
        assert_pointer_identity_swap(v1, v2, v3);
    }

    fn assert_pointer_identity_swap<T>(c1: Option<Arc<T>>, c2: Option<Arc<T>>, c3: Option<Arc<T>>)
    where
        T: std::fmt::Debug + PartialEq + ?Sized,
    {
        let v = TypedValue::<Option<Arc<T>>>::default();

        assert!(!v.compare_and_swap_by(&c1, &c2, option_arc_ptr_eq));
        assert_eq!(v.load(), None);
        assert!(v.compare_and_swap_by(&None, &c1, option_arc_ptr_eq));
        assert_eq!(v.load(), c1);
        assert!(!v.compare_and_swap_by(&c2, &c3, option_arc_ptr_eq));
        assert_eq!(v.load(), c1);
        assert!(v.compare_and_swap_by(&c1, &c2, option_arc_ptr_eq));
        assert_eq!(v.load(), c2);
        assert!(!v.compare_and_swap_by(&c3, &c2, option_arc_ptr_eq));
        assert_eq!(v.load(), c2);
        assert!(!v.compare_and_swap_by(&None, &c3, option_arc_ptr_eq));
        assert_eq!(v.load(), c2);
    }

    fn value_equality_is_not_pointer_identity() {
        // The stored pointer is compared, so an equal-content copy is a different value; the
        // value-based `compare_and_swap` cannot tell them apart, which is what this pins.
        let stored: Option<Arc<str>> = Some(Arc::from("path error"));
        let same_content: Option<Arc<str>> = Some(Arc::from("path error"));
        let v = TypedValue::<Option<Arc<str>>>::default();
        v.store(stored);

        assert!(!v.compare_and_swap_by(&same_content, &None, option_arc_ptr_eq));
        assert!(v.compare_and_swap(&same_content, &None));
        assert_eq!(v.load(), None);
    }
}

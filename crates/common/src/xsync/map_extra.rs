use super::map::{ComputeOutcome, LoadOp, Map, MapKey};

impl<K: MapKey, V: Clone> Map<K, V> {
    /// Returns the existing value of the key when present. Otherwise it
    /// tries to compute the value with the provided callback and, when
    /// successful, stores and returns the computed value. The loaded flag
    /// reports whether the value was loaded rather than computed.
    ///
    /// The call locks a hash table bucket as the compute callback runs,
    /// so modifications on other entries in the bucket stay blocked until
    /// the callback returns. Consider this when the callback includes
    /// long-running operations.
    ///
    /// This is the compute-or-store api under a new name. A cancel
    /// compute operation is deliberately unsupported: it would only add
    /// complexity to existing code.
    #[expect(
        clippy::expect_used,
        reason = "the `OrCompute` path returns a stored value on every branch: `scan` hands back the value of a present key, and a `Cancel` outcome is only reached once a value is already stored"
    )]
    pub fn load_or_store_fn(&self, key: K, mut value_fn: impl FnMut() -> V) -> (V, bool) {
        let (actual, loaded) = self.do_compute(
            key,
            |_old_value, loaded| {
                if loaded {
                    return ComputeOutcome::Cancel;
                }
                ComputeOutcome::Update(value_fn())
            },
            LoadOp::OrCompute,
            false,
        );
        (actual.expect("load_or_store_fn always yields the stored value"), loaded)
    }
}

#[cfg(test)]
mod tests {
    use crate::xsync::map::Map;

    #[test]
    fn test_map_of_load_or_store_fn() {
        const NUM_ENTRIES: i32 = 1000;
        let m = Map::<String, i32>::new(&[]);
        for i in 0..NUM_ENTRIES {
            let (v, loaded) = m.load_or_store_fn(i.to_string(), || i);
            assert!(!loaded, "value not computed for {i}");
            assert_eq!(v, i, "values do not match for {i}");
        }
        for i in 0..NUM_ENTRIES {
            let (v, loaded) = m.load_or_store_fn(i.to_string(), || i);
            assert!(loaded, "value not loaded for {i}");
            assert_eq!(v, i, "values do not match for {i}");
        }
    }

    #[test]
    fn test_map_of_load_or_store_fn_function_called_once() {
        let m = Map::<i32, i32>::new(&[]);
        let mut i = 0i32;
        while i < 100 {
            let next = i;
            m.load_or_store_fn(next, || {
                let v = i;
                i += 1;
                v
            });
        }
        m.range(|k, v| {
            assert_eq!(*k, *v, "key is not equal to value");
            true
        });
    }
}

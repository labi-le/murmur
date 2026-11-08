/// Returns the default when `v` is the zero value of `T`, else `v`.
pub fn empty_or<T: PartialEq + Default>(v: T, def: T) -> T {
    if v == T::default() {
        def
    } else {
        v
    }
}

//! Constraint marker traits `Signed`, `Unsigned`, `Integer`, `Float`, `Ordered` and `Numeric` cover
//! the primitive types they permit; every type in each set is listed explicitly.

use std::sync::Arc;

/// Signed is a constraint that permits any signed integer type.
pub trait Signed: Integer {}

impl Signed for i8 {}
impl Signed for i16 {}
impl Signed for i32 {}
impl Signed for i64 {}
impl Signed for isize {}

/// Unsigned is a constraint that permits any unsigned integer type.
pub trait Unsigned: Integer {}

impl Unsigned for u8 {}
impl Unsigned for u16 {}
impl Unsigned for u32 {}
impl Unsigned for u64 {}
impl Unsigned for usize {}

/// Integer is a constraint that permits any integer type.
pub trait Integer: Copy + PartialOrd {}

impl Integer for i8 {}
impl Integer for i16 {}
impl Integer for i32 {}
impl Integer for i64 {}
impl Integer for isize {}
impl Integer for u8 {}
impl Integer for u16 {}
impl Integer for u32 {}
impl Integer for u64 {}
impl Integer for usize {}

/// Float is a constraint that permits any floating-point type.
pub trait Float: Copy + PartialOrd {}

impl Float for f32 {}
impl Float for f64 {}

/// Ordered is a constraint that permits any ordered type: any type that supports the operators
/// `< <= >= >`.
pub trait Ordered: PartialOrd {}

impl Ordered for i8 {}
impl Ordered for i16 {}
impl Ordered for i32 {}
impl Ordered for i64 {}
impl Ordered for isize {}
impl Ordered for u8 {}
impl Ordered for u16 {}
impl Ordered for u32 {}
impl Ordered for u64 {}
impl Ordered for usize {}
impl Ordered for f32 {}
impl Ordered for f64 {}
impl Ordered for String {}
impl Ordered for str {}

/// Numeric is a constraint that permits any numeric type.
pub trait Numeric: Copy + PartialOrd {}

impl Numeric for i8 {}
impl Numeric for i16 {}
impl Numeric for i32 {}
impl Numeric for i64 {}
impl Numeric for isize {}
impl Numeric for u8 {}
impl Numeric for u16 {}
impl Numeric for u32 {}
impl Numeric for u64 {}
impl Numeric for usize {}
impl Numeric for f32 {}
impl Numeric for f64 {}

/// `LessFn` is a function that returns whether 'a' is less than 'b'.
pub type LessFn<T> = Arc<dyn Fn(T, T) -> bool + Send + Sync>;

/// `CompareFn` is a 3 way compare function that
/// returns 1  if a >  b,
/// returns 0  if a == b,
/// returns -1 if a < b.
pub type CompareFn<T> = Arc<dyn Fn(&T, &T) -> i32 + Send + Sync>;

/// `HashFn` is a function that returns the hash of 't'.
pub type HashFn<T> = Arc<dyn Fn(T) -> u64 + Send + Sync>;

/// Equals wraps the '==' operator for comparable types.
pub fn equals<T: PartialEq>(a: &T, b: &T) -> bool {
    a == b
}

/// Less wraps the '<' operator for ordered types.
pub fn less<T: PartialOrd>(a: &T, b: &T) -> bool {
    a < b
}

/// Provides the default `CompareFn` used with ordered types.
pub fn ordered_compare<T: PartialOrd>(a: &T, b: &T) -> i32 {
    if a < b {
        return -1;
    }
    if a > b {
        return 1;
    }
    0
}

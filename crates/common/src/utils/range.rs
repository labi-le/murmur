use std::fmt;

use anyhow::anyhow;

pub trait Ordered: PartialOrd + Copy {}

// Blanket by design: `Ordered` is a marker alias for `PartialOrd + Copy`.
impl<T: PartialOrd + Copy> Ordered for T {}

pub trait Integer: Ordered + Ord {
    fn zero() -> Self;
    #[must_use]
    fn wrapping_inc(self) -> Self;
}

pub trait Unsigned: Integer {
    /// The conversion truncates to the target width.
    fn from_u64(val: u64) -> Self;
}

pub trait Signed: Integer {
    /// The conversion truncates to the target width.
    fn from_i64(val: i64) -> Self;
}

macro_rules! impl_integer {
    ($($t:ty),*) => {
        $(
            impl Integer for $t {
                fn zero() -> Self {
                    0
                }

                fn wrapping_inc(self) -> Self {
                    self.wrapping_add(1)
                }
            }
        )*
    };
}

impl_integer!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

macro_rules! impl_unsigned {
    ($($t:ty),*) => {
        $(
            impl Unsigned for $t {
                #[allow(
                    trivial_numeric_casts,
                    clippy::cast_possible_truncation,
                    reason = "the conversion truncates to the target width, as the trait documents"
                )]
                fn from_u64(val: u64) -> Self {
                    val as $t
                }
            }
        )*
    };
}

impl_unsigned!(u8, u16, u32, u64, usize);

macro_rules! impl_signed {
    ($($t:ty),*) => {
        $(
            impl Signed for $t {
                #[allow(
                    trivial_numeric_casts,
                    clippy::cast_possible_truncation,
                    reason = "the conversion truncates to the target width, as the trait documents"
                )]
                fn from_i64(val: i64) -> Self {
                    val as $t
                }
            }
        )*
    };
}

impl_signed!(i8, i16, i32, i64, isize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range<T> {
    pub(crate) start: T,
    pub(crate) end: T,
}

pub fn new_range<T: Ordered>(start: T, end: T) -> Range<T> {
    if start > end {
        return Range { start: end, end: start };
    }

    Range { start, end }
}

impl<T: Ordered> Range<T> {
    pub fn contains(&self, t: T) -> bool {
        t >= self.start && t <= self.end
    }

    pub fn left_contains(&self, t: T) -> bool {
        t >= self.start && t < self.end
    }

    pub fn right_contains(&self, t: T) -> bool {
        t > self.start && t <= self.end
    }

    pub const fn start(&self) -> T {
        self.start
    }

    pub const fn end(&self) -> T {
        self.end
    }
}

impl<T: Ordered + fmt::Display> Range<T> {
    pub fn string(&self) -> String {
        self.to_string()
    }
}

impl<T: Ordered + fmt::Display> fmt::Display for Range<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            return write!(f, "{}", self.start);
        }
        write!(f, "{}-{}", self.start, self.end)
    }
}

pub fn new_unsigned_range<T: Unsigned>(expected: &str) -> anyhow::Result<Range<T>> {
    new_int_range(expected, parse_unsigned::<T>)
}

pub fn new_signed_range<T: Signed>(expected: &str) -> anyhow::Result<Range<T>> {
    new_int_range(expected, parse_signed::<T>)
}

pub(crate) fn new_int_range<T: Integer>(s: &str, parse_fn: fn(&str) -> anyhow::Result<T>) -> anyhow::Result<Range<T>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(new_range(T::zero(), T::zero()));
    }
    let mut parts = s.split('-');
    let Some(first) = parts.next() else {
        return Err(anyhow!("invalid range: {s}"));
    };
    let Ok(start) = parse_fn(trim_range_chars(first)) else {
        return Err(anyhow!("invalid range: {s}"));
    };
    match (parts.next(), parts.next()) {
        (None, _) => Ok(new_range(start, start)),
        (Some(second), None) => {
            let Ok(end) = parse_fn(trim_range_chars(second)) else {
                return Err(anyhow!("invalid range: {s}"));
            };
            Ok(new_range(start, end))
        }
        (Some(_), Some(_)) => Err(anyhow!("invalid range: {s}")),
    }
}

fn trim_range_chars(s: &str) -> &str {
    s.trim_matches(|c| c == '[' || c == ' ' || c == ']')
}

pub(crate) fn parse_unsigned<T: Unsigned>(s: &str) -> anyhow::Result<T> {
    match s.parse::<u64>() {
        Ok(val) => Ok(T::from_u64(val)),
        Err(err) => Err(err.into()),
    }
}

pub(crate) fn parse_signed<T: Signed>(s: &str) -> anyhow::Result<T> {
    match s.parse::<i64>() {
        Ok(val) => Ok(T::from_i64(val)),
        Err(err) => Err(err.into()),
    }
}

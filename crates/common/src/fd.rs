//! The process's descriptor budget: `RLIMIT_NOFILE` and the number of open descriptors.
//!
//! A proxy runs out of descriptors by keeping a socket's owner alive, not by forgetting to close a
//! handle. The failure mode is therefore a silent one until the limit is reached, and then every
//! dial and every accept fails with `EMFILE`. The limit and the count live together here so the
//! binary can raise the soft limit once at startup and warn while there is still room to act.

use std::io;

/// Descriptors currently open, the soft limit and the hard limit.
///
/// Every field is optional: a target may expose the count without the limits, or neither, and a
/// missing value must not read as zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdStatus {
    /// Descriptors open at the moment of the read.
    pub open: Option<usize>,
    /// Soft `RLIMIT_NOFILE`.
    pub soft: Option<u64>,
    /// Hard `RLIMIT_NOFILE`.
    pub hard: Option<u64>,
}

impl FdStatus {
    /// Reads the limits and the current count.
    #[must_use]
    pub fn read() -> Self {
        let limits = nofile_limit();
        Self { open: open_descriptor_count(), soft: limits.map(|(soft, _)| soft), hard: limits.map(|(_, hard)| hard) }
    }

    /// Whether the count has reached three quarters of the soft limit.
    ///
    /// The threshold leaves room for the descriptors one dial or one accept needs, so the warning
    /// arrives while the process still serves traffic rather than at the first `EMFILE`.
    #[must_use]
    pub fn near_limit(&self) -> bool {
        let (Some(open), Some(soft)) = (self.open, self.soft) else { return false };
        let open = u64::try_from(open).unwrap_or(u64::MAX);
        soft > 0 && open.saturating_mul(4) >= soft.saturating_mul(3)
    }
}

/// The soft and hard `RLIMIT_NOFILE` values, in that order.
///
/// An unlimited limit is reported as `u64::MAX`, which is what `RLIM_INFINITY` is on every platform
/// this tree builds for.
#[cfg(unix)]
#[must_use]
pub fn nofile_limit() -> Option<(u64, u64)> {
    let limits = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    let soft = limits.current.unwrap_or(u64::MAX);
    let hard = limits.maximum.unwrap_or(u64::MAX);
    Some((soft, hard))
}

/// Targets without POSIX resource limits report none instead of guessing.
#[cfg(not(unix))]
#[must_use]
pub fn nofile_limit() -> Option<(u64, u64)> {
    None
}

/// Raises the soft limit to the hard limit and returns the effective pair.
///
/// Only the soft half is raised: the hard limit is privileged, so the operating system's ceiling on
/// this process is unchanged and a caller cannot grant itself more than it was given.
#[cfg(unix)]
pub fn raise_nofile_limit() -> io::Result<(u64, u64)> {
    let (soft, hard) = nofile_limit().unwrap_or((0, 0));
    if soft >= hard {
        return Ok((soft, hard));
    }
    let raised = rustix::process::Rlimit { current: Some(hard), maximum: Some(hard) };
    rustix::process::setrlimit(rustix::process::Resource::Nofile, raised).map_err(io::Error::from)?;
    nofile_limit().ok_or_else(|| io::Error::other("descriptor limits were readable before the raise and not after"))
}

/// Targets without POSIX resource limits cannot raise anything.
#[cfg(not(unix))]
pub fn raise_nofile_limit() -> io::Result<(u64, u64)> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "descriptor limits are not exposed on this target"))
}

/// The number of descriptors this process has open, or `None` where the OS does not expose it.
///
/// The count includes the directory handle the listing itself holds, so a single reading is off by
/// one; callers compare it against a limit rather than treating it as exact.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[must_use]
pub fn open_descriptor_count() -> Option<usize> {
    let entries = std::fs::read_dir("/proc/self/fd").ok()?;
    Some(entries.flatten().count())
}

/// Darwin exposes the count through `libproc`, which this target does not link; report nothing
/// rather than a number that cannot be trusted.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[must_use]
pub fn open_descriptor_count() -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_limit_is_false_when_the_limit_or_the_count_is_unknown() {
        assert!(!FdStatus { open: None, soft: Some(1024), hard: Some(1024) }.near_limit());
        assert!(!FdStatus { open: Some(700), soft: None, hard: None }.near_limit());
    }

    #[test]
    fn near_limit_triggers_at_three_quarters_and_spares_a_zero_limit() {
        assert!(!FdStatus { open: Some(767), soft: Some(1024), hard: Some(1024) }.near_limit());
        assert!(FdStatus { open: Some(768), soft: Some(1024), hard: Some(1024) }.near_limit());
        assert!(!FdStatus { open: Some(1), soft: Some(0), hard: Some(0) }.near_limit());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_descriptor_count_sees_the_descriptors_the_test_holds_open() {
        let before = open_descriptor_count().expect("linux reports /proc/self/fd");
        let held: Vec<std::fs::File> = (0..16).filter_map(|_| std::fs::File::open("/dev/null").ok()).collect();
        let during = open_descriptor_count().expect("linux reports /proc/self/fd");
        assert_eq!(held.len(), 16);
        assert!(during >= before + held.len(), "count {during} did not grow by {} over {before}", held.len());
    }

    #[cfg(unix)]
    #[test]
    fn a_raised_limit_never_exceeds_the_hard_one() {
        let (soft, hard) = raise_nofile_limit().expect("raising the soft limit to the hard one is allowed");
        assert!(soft <= hard, "soft {soft} ended above hard {hard}");
        assert!(soft > 0);
    }
}

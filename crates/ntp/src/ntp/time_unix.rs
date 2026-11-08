//! System wall-clock adjustment on Linux and macOS.

use chrono::{DateTime, Utc};

/// The C `timeval` this target's C library expects.
///
/// `musl` 1.2 widened `time_t` and `suseconds_t` to 64 bits on every architecture, so its
/// `timeval` is two 64-bit fields. The `libc` crate still models the pre-1.2 `c_long` aliases on
/// musl and marks them deprecated (0.2.80, libc#1848): naming `libc::timeval` there warns, and on
/// a 32-bit target it describes the 8-byte legacy layout rather than the one the library uses.
#[cfg(target_env = "musl")]
#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

#[cfg(not(target_env = "musl"))]
use libc::timeval as Timeval;

#[cfg(all(target_env = "musl", target_pointer_width = "32"))]
#[allow(unsafe_code)]
unsafe extern "C" {
    /// `musl`'s 64-bit-time entry point. `include/sys/time.h` sends new C builds here with
    /// `__REDIR(settimeofday, __settimeofday_time64)`; the plain `settimeofday` symbol on a
    /// 32-bit target is the pre-1.2 compatibility wrapper, which reads a 32-bit `timeval` and
    /// would truncate the clock to that range.
    fn __settimeofday_time64(tv: *const Timeval, tz: *const core::ffi::c_void) -> core::ffi::c_int;
}

/// Set the system wall clock to `now_time`.
#[allow(unsafe_code)]
#[allow(trivial_numeric_casts)]
pub(crate) fn set_system_time(now_time: DateTime<Utc>) -> std::io::Result<()> {
    let nsec = now_time.timestamp_nanos_opt().unwrap_or(0);
    let secs = nsec / 1_000_000_000;
    let usecs = (nsec % 1_000_000_000) / 1_000;
    let tv = Timeval { tv_sec: secs as _, tv_usec: usecs as _ };
    // SAFETY: `tv` is a valid, fully-initialized `timeval` on the stack; the callee only reads
    // through the pointer for the duration of the call, and a null `timezone` pointer is the
    // documented way to leave the kernel's timezone untouched.
    #[cfg(all(target_env = "musl", target_pointer_width = "32"))]
    let rc = unsafe { __settimeofday_time64(&raw const tv, std::ptr::null()) };
    #[cfg(not(all(target_env = "musl", target_pointer_width = "32")))]
    let rc = unsafe { libc::settimeofday((&raw const tv).cast(), std::ptr::null()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

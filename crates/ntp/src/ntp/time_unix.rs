//! System wall-clock adjustment on Linux and macOS.

use chrono::{DateTime, Utc};

/// Set the system wall clock to `now_time`.
#[allow(unsafe_code)]
#[allow(trivial_numeric_casts)]
pub(crate) fn set_system_time(now_time: DateTime<Utc>) -> std::io::Result<()> {
    let nsec = now_time.timestamp_nanos_opt().unwrap_or(0);
    let tv = libc::timeval {
        tv_sec: (nsec / 1_000_000_000) as libc::time_t,
        tv_usec: ((nsec % 1_000_000_000) / 1_000) as libc::suseconds_t,
    };
    // SAFETY: `tv` is a valid, fully-initialized `timeval` on the stack; `settimeofday` only
    // reads through the pointer for the duration of the call, and a null `timezone` pointer is
    // the documented way to leave the kernel's timezone untouched.
    let rc = unsafe { libc::settimeofday(&raw const tv, std::ptr::null()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

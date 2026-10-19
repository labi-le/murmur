#![cfg(all(target_os = "linux", not(target_arch = "x86")))]

use std::io;

pub(crate) const GETSOCKOPT: i64 = libc::SYS_getsockopt;

/// `socketcall`, calling the raw `SYS_getsockopt` syscall directly.
#[expect(unsafe_code, reason = "the raw SYS_getsockopt syscall")]
pub(crate) fn socketcall(
    call: i64,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> io::Result<()> {
    // Safety: `call` is `SYS_getsockopt` and `a0..a5` are the `getsockopt(2)` arguments in the
    // exact order the kernel's C ABI expects them.
    let rc = unsafe { libc::syscall(call, a0, a1, a2, a3, a4, a5) };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

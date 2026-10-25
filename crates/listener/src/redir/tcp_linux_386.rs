use std::io;

/// `GETSOCKOPT`: the `SYS_socketcall` subcommand number for `getsockopt` on linux/386.
pub(crate) const GETSOCKOPT: i64 = 15;

/// `socketcall`, isolating the `SYS_socketcall`-multiplexed raw syscall linux/386 needs.
#[expect(unsafe_code, reason = "SYS_socketcall and its six-word argument array")]
pub(crate) fn socketcall(
    call: i64,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> io::Result<()> {
    let args: [usize; 6] = [a0, a1, a2, a3, a4, a5];
    // Safety: `SYS_socketcall`'s second argument is a pointer to the real syscall's own six-word
    // argument array; `args` outlives the syscall and is laid out exactly as the kernel expects.
    let rc = unsafe { libc::syscall(libc::SYS_socketcall, call as libc::c_long, args.as_ptr()) };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

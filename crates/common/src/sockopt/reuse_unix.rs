use std::os::fd::AsFd;

use socket2::SockRef;

/// `socket2`'s `all`-feature `SO_REUSEPORT` support excludes Cygwin, illumos and Solaris; this
/// crate does not build for them, so a target that somehow does fails to compile rather than
/// silently skip the option.
#[cfg(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin"))]
pub(crate) fn reuse_control<S: AsFd>(_socket: &S) -> anyhow::Result<()> {
    compile_error!("reuse_unix::reuse_control: socket2's `all` feature has no SO_REUSEPORT support on this target; add an explicit SO_REUSEPORT call before building for it");
}

/// Attempts both options unconditionally and reports the first error.
#[cfg(not(any(target_os = "solaris", target_os = "illumos", target_os = "cygwin")))]
pub(crate) fn reuse_control<S: AsFd>(socket: &S) -> anyhow::Result<()> {
    let sock_ref = SockRef::from(socket);
    let e1 = sock_ref.set_reuse_address(true);
    let e2 = sock_ref.set_reuse_port(true);
    e1.and(e2)?;
    Ok(())
}

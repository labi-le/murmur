#[allow(
    unsafe_code,
    reason = "`BorrowedFd::borrow_raw` is the only constructor for a borrowed descriptor, so the caller's liveness guarantee cannot be expressed in the type system"
)]
pub(crate) fn mark_control(fd: usize, mark: i32) -> anyhow::Result<()> {
    // SAFETY: `fd` is a live socket held by the caller, and it outlives this synchronous call.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd as std::os::fd::RawFd) };
    socket2::SockRef::from(&borrowed).set_mark(mark.cast_unsigned())?;
    Ok(())
}

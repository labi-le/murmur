#[expect(
    clippy::unnecessary_wraps,
    reason = "a stub for targets without SO_MARK still has to match the mark_control contract its callers are written against"
)]
pub(crate) fn mark_control(_fd: usize, _mark: i32) -> anyhow::Result<()> {
    Ok(())
}

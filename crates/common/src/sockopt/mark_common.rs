#[cfg(target_os = "linux")]
use super::mark_linux::mark_control;
#[cfg(not(target_os = "linux"))]
use super::mark_other::mark_control;

/// With no raw-connection callback to own the descriptor, it is taken directly here, so the
/// control error source disappears.
pub fn raw_conn_mark(fd: usize, mark: i32) -> anyhow::Result<()> {
    mark_control(fd, mark)
}

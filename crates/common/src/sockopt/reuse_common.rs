use murmur_std_compat::net::PacketConn;

#[cfg(not(any(unix, windows)))]
use super::reuse_other::reuse_control;
#[cfg(unix)]
use super::reuse_unix::reuse_control;
#[cfg(windows)]
use super::reuse_windows::reuse_control;

/// The hook's own error is not split from the socket-reuse control's; a borrowed socket has no
/// such split, so this now forwards directly.
///
/// It stays its own function as the module's public entry point over the per-platform `reuse_*`
/// modules `component/dialer` doesn't select between itself.
#[cfg(unix)]
pub fn raw_conn_reuseaddr<S: std::os::fd::AsFd>(socket: &S) -> anyhow::Result<()> {
    reuse_control(socket)
}

#[cfg(windows)]
pub fn raw_conn_reuseaddr<S: std::os::windows::io::AsSocket>(socket: &S) -> anyhow::Result<()> {
    reuse_control(socket)
}

#[cfg(not(any(unix, windows)))]
pub fn raw_conn_reuseaddr<S>(socket: &S) -> anyhow::Result<()> {
    reuse_control(socket)
}

/// The `PacketConn::as_socket` capability is the nearest equivalent of a socket assertion.
///
/// It reaches through any wrapper that delegates it rather than only the bare concrete socket,
/// falling through quietly on every `PacketConn` that does not expose a raw fd or handle.
pub fn udp_reuseaddr(c: &dyn PacketConn) -> anyhow::Result<()> {
    match c.as_socket() {
        Some(socket) => raw_conn_reuseaddr(&*socket),
        None => Ok(()),
    }
}

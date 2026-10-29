use std::sync::Arc;

use murmur_common::sockopt;

use super::control::{add_control_to_listen_config, StdListenConfig};

pub(crate) fn addr_reuse_to_listen_config(lc: &mut StdListenConfig) {
    add_control_to_listen_config(
        lc,
        Arc::new(|_ctx, _network, _address, fd| Box::pin(async move { reuseaddr_from_raw(fd) })),
    );
}

/// `ControlFn` (shared across every `component/dialer` hook, not owned by `common/sockopt`;
/// report: `SHARED CHANGE NEEDED` if it should carry a borrowed handle instead) still crosses
/// this boundary as a raw descriptor; reconstruct a non-owning borrow from it for the one call.
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "`BorrowedFd::borrow_raw` rebuilds a non-owning descriptor from the raw fd the dialer hook hands over"
)]
fn reuseaddr_from_raw(fd: usize) -> anyhow::Result<()> {
    // SAFETY: `fd` names the socket still owned by the live `Socket` in
    // `control.rs::listen`/`listen_packet`, which outlives this synchronous call.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd as std::os::fd::RawFd) };
    sockopt::reuse_common::raw_conn_reuseaddr(&borrowed)
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "`BorrowedSocket::borrow_raw` rebuilds a non-owning handle from the raw socket the dialer hook hands over"
)]
fn reuseaddr_from_raw(fd: usize) -> anyhow::Result<()> {
    // SAFETY: `fd` names the socket still owned by the live `Socket` in
    // `control.rs::listen`/`listen_packet`, which outlives this synchronous call.
    let borrowed = unsafe { std::os::windows::io::BorrowedSocket::borrow_raw(fd as std::os::windows::io::RawSocket) };
    sockopt::reuse_common::raw_conn_reuseaddr(&borrowed)
}

#[cfg(not(any(unix, windows)))]
fn reuseaddr_from_raw(_fd: usize) -> anyhow::Result<()> {
    Ok(())
}

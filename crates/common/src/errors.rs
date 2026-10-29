//! Shared error-identity helpers: the standard library has no single home, so call sites across
//! the crate use this module instead of duplicating the helper per subtree.

use anyhow::Error;

/// Reports whether `err` or anything in its chain is a `T`.
#[must_use]
pub fn error_is<T: std::error::Error + 'static>(err: &Error) -> bool {
    err.chain().any(|cause| cause.downcast_ref::<T>().is_some())
}

/// Returned once a closed OS file descriptor is read or written again.
///
/// `adapter/outbound/util.rs::IpStack::read`/`write` must return this (wrapped or bare) once the
/// underlying tun/gVisor device is closed, mirroring the wireguard backend
/// there; the `mips` stack (`adapter-outbound/src/util.rs`, over
/// `murmur-component-wireguard`) is the backend that does, and
/// `adapter::outbound::openvpn::is_os_closed`'s `error_is::<ErrOsClosed>` check matches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("file already closed")]
pub struct ErrOsClosed;

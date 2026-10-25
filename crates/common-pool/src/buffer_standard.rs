//! Standard-memory buffer sizes, used unless the `with_low_memory` feature is on.

/// `RelayBufferSize`, used for tcp: the standard copy buffer size is 32 KiB.
#[cfg(not(feature = "with_low_memory"))]
pub const RELAY_BUFFER_SIZE: usize = 32 * 1024;

/// UDP reads must fit a complete datagram rather than silently truncate at the MTU.
#[cfg(not(feature = "with_low_memory"))]
pub const UDP_BUFFER_SIZE: usize = 64 * 1024;

//! Standard-memory buffer sizes, used unless the `with_low_memory` feature is on.

/// `RelayBufferSize`, used for tcp: the standard copy buffer size is 32 KiB.
#[cfg(not(feature = "with_low_memory"))]
pub const RELAY_BUFFER_SIZE: usize = 32 * 1024;

/// `UDPBufferSize`, used for udp: most datagrams are smaller than the MTU, and the TUN MTU is
/// 9000, so a 16 KiB buffer is enough.
#[cfg(not(feature = "with_low_memory"))]
pub const UDP_BUFFER_SIZE: usize = 16 * 1024;

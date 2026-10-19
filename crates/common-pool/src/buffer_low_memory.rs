//! Low-memory buffer sizes, selected by the `with_low_memory` feature.

/// `RelayBufferSize`, used for tcp, at the low-memory size of 16 KiB.
#[cfg(feature = "with_low_memory")]
pub const RELAY_BUFFER_SIZE: usize = 16 * 1024;

/// `UDPBufferSize`, used for udp, at the low-memory size of 8 KiB.
#[cfg(feature = "with_low_memory")]
pub const UDP_BUFFER_SIZE: usize = 8 * 1024;

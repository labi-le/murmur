pub mod obfs;
#[cfg(all(target_os = "linux", not(feature = "no_fake_tcp")))]
pub mod tcp_linux;
#[cfg(any(not(target_os = "linux"), feature = "no_fake_tcp"))]
pub mod tcp_stub;

#[cfg(all(target_os = "linux", not(feature = "no_fake_tcp")))]
pub use tcp_linux::{dial, listen, TCPConn};
#[cfg(any(not(target_os = "linux"), feature = "no_fake_tcp"))]
pub use tcp_stub::{dial, listen, TCPConn};

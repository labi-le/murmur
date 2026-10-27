//! The WireGuard device and the userspace IP stack it carries.
//!
//! `adapter::outbound::wireguard` drives it: it dials the UDP transport through murmur's
//! own dialer (so `interface`, `routing-mark` and `dialer-proxy` keep working), and gets
//! TCP/UDP sockets inside the tunnel back out of [`stack::Stack`].
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::pedantic,
        clippy::nursery
    )
)]

pub mod bind;
pub mod cookie;
pub mod crypto;
pub mod device;
pub mod handshake;
pub mod keys;
pub mod replay;
pub mod stack;

pub use bind::{Bind, ConnectedBind, DatagramBind, ReservedBind};
pub use cookie::{CookieChecker, CookieGenerator, MessageCookieReply};
pub use device::{Device, DeviceConfig, PeerConfig, Tun};
pub use keys::{PresharedKey, PublicKey, StaticKey};
pub use stack::{Events, PacketDevice, PacketHandle, Stack, StackConfig, TcpConn, UdpConn, DEFAULT_MTU};

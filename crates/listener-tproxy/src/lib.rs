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

pub mod packet;
#[cfg(target_os = "linux")]
pub mod setsockopt_linux;
#[cfg(not(target_os = "linux"))]
pub mod setsockopt_other;
pub mod tproxy;
pub mod tproxy_iptables;
pub mod udp;
#[cfg(target_os = "linux")]
pub mod udp_linux;
#[cfg(not(target_os = "linux"))]
pub mod udp_other;

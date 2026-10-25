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

pub mod client;
pub mod dhcp;
pub mod dialer;
pub mod doh;
pub mod doq;
pub mod dot;
pub mod easytier;
pub mod edns0_subnet;
pub mod enhancer;
pub mod middleware;
#[cfg(target_os = "android")]
pub mod patch_android;
pub mod policy;
pub mod rcode;
pub mod resolver;
pub mod server;
pub mod service;
pub mod system;
pub mod system_common;
pub mod system_posix;
#[cfg(target_os = "windows")]
pub mod system_windows;
pub mod tailscale;
pub mod util;

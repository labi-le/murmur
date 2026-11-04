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

pub mod find_process_mode;
pub mod process;
#[cfg(target_os = "macos")]
pub mod process_darwin;
#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
pub mod process_freebsd_amd64;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod process_linux;
#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    all(target_os = "freebsd", target_arch = "x86_64")
)))]
pub mod process_other;
#[cfg(target_os = "windows")]
pub mod process_windows;

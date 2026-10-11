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

pub mod memory;
#[cfg(target_os = "macos")]
pub mod memory_darwin;
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "windows"
)))]
pub mod memory_falllback;
#[cfg(target_os = "freebsd")]
pub mod memory_freebsd;
#[cfg(all(target_os = "freebsd", target_arch = "x86"))]
pub mod memory_freebsd_386;
#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
pub mod memory_freebsd_amd64;
#[cfg(all(target_os = "freebsd", target_arch = "arm"))]
pub mod memory_freebsd_arm;
#[cfg(all(target_os = "freebsd", target_arch = "aarch64"))]
pub mod memory_freebsd_arm64;
#[cfg(target_os = "linux")]
pub mod memory_linux;
#[cfg(target_os = "openbsd")]
pub mod memory_openbsd;
#[cfg(all(target_os = "openbsd", target_arch = "x86"))]
pub mod memory_openbsd_386;
#[cfg(all(target_os = "openbsd", target_arch = "x86_64"))]
pub mod memory_openbsd_amd64;
#[cfg(all(target_os = "openbsd", target_arch = "arm"))]
pub mod memory_openbsd_arm;
#[cfg(all(target_os = "openbsd", target_arch = "aarch64"))]
pub mod memory_openbsd_arm64;
#[cfg(all(target_os = "openbsd", target_arch = "riscv64"))]
pub mod memory_openbsd_riscv64;
#[cfg(target_os = "windows")]
pub mod memory_windows;

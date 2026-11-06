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

pub mod build_flags;
pub mod cmfa;
pub mod cmfa_stub;
pub mod low_memory;
pub mod low_memory_stub;
pub mod no_easytier;
pub mod no_easytier_stub;
pub mod no_fake_tcp;
pub mod no_fake_tcp_stub;
pub mod no_tailscale;
pub mod no_tailscale_stub;
pub mod no_zerotier;
pub mod no_zerotier_stub;
pub mod tags;
pub mod version;
#[cfg(target_os = "windows")]
pub mod version_windows;
pub mod with_gvisor;
pub mod with_gvisor_stub;

#[cfg(feature = "cmfa")]
pub use cmfa::CMFA;
#[cfg(not(feature = "cmfa"))]
pub use cmfa_stub::CMFA;

#[cfg(feature = "with_low_memory")]
pub use low_memory::WITH_LOW_MEMORY;
#[cfg(not(feature = "with_low_memory"))]
pub use low_memory_stub::WITH_LOW_MEMORY;

#[cfg(feature = "no_easytier")]
pub use no_easytier::NO_EASY_TIER;
#[cfg(not(feature = "no_easytier"))]
pub use no_easytier_stub::NO_EASY_TIER;

#[cfg(feature = "no_fake_tcp")]
pub use no_fake_tcp::NO_FAKE_TCP;
#[cfg(not(feature = "no_fake_tcp"))]
pub use no_fake_tcp_stub::NO_FAKE_TCP;

#[cfg(feature = "no_tailscale")]
pub use no_tailscale::NO_TAILSCALE;
#[cfg(not(feature = "no_tailscale"))]
pub use no_tailscale_stub::NO_TAILSCALE;

#[cfg(feature = "no_zerotier")]
pub use no_zerotier::NO_ZERO_TIER;
#[cfg(not(feature = "no_zerotier"))]
pub use no_zerotier_stub::NO_ZERO_TIER;

#[cfg(feature = "with_gvisor")]
pub use with_gvisor::WITH_GVISOR;
#[cfg(not(feature = "with_gvisor"))]
pub use with_gvisor_stub::WITH_GVISOR;

pub use build_flags::{AMD64_LEVEL, ARM_VERSION, MIPS_FLOAT};
pub use tags::tags;
pub use version::{WINDOWS_BUILD_NUMBER, WINDOWS_MAJOR_VERSION, WINDOWS_MINOR_VERSION};

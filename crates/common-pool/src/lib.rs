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

pub mod alloc;
pub mod buffer;
pub mod buffer_low_memory;
pub mod buffer_standard;
#[allow(clippy::module_inception)]
pub mod pool;
pub mod sing;

pub use alloc::{DefaultAllocator, DEFAULT_ALLOCATOR};
pub use buffer::{get_buffer, put_buffer};
#[cfg(feature = "with_low_memory")]
pub use buffer_low_memory::{RELAY_BUFFER_SIZE, UDP_BUFFER_SIZE};
#[cfg(not(feature = "with_low_memory"))]
pub use buffer_standard::{RELAY_BUFFER_SIZE, UDP_BUFFER_SIZE};
pub use pool::{get, put};

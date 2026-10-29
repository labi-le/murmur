//! Module aggregator: a namespace only, with no items of its own.
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
        clippy::nursery,
        reason = "test scaffolding is not product code, and a failing test should abort"
    )
)]

pub mod arc;
pub mod atomic;
pub mod batch;
pub mod cmd;
pub mod contextutils;
pub mod deque;
pub mod errors;
pub mod lru;
pub mod murmur3;
pub mod net;
pub mod net_addr;
pub mod observable;
pub mod once;
pub mod orderedmap;
pub mod picker;
pub mod queue;
pub mod shared_conn;
pub mod singledo;
pub mod singleflight;
pub mod sockopt;
pub mod structure;
pub mod time;
pub mod time_rfc3339;
pub mod utils;
pub mod xsync;
pub mod yaml;

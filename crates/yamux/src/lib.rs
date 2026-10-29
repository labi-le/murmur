//! A multiplexed stream protocol: a `Session` runs two tokio tasks, one per half of the
//! connection (`tokio::io::split`), plus an optional keepalive task, coordinating through
//! `tokio::sync::{mpsc, oneshot, Notify, Semaphore}` and a `parking_lot`-guarded stream
//! registry.
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

mod config;
mod error;
mod frame;
mod session;
mod stream;

pub use config::{default_config, verify_config, Config};
pub use session::{client, server, Session};
pub use stream::Stream;

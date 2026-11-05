//!
//! The module is nested at `listener::inner` (matching the directory layout) rather than as a
//! Rust sibling of `listener`, so `component/http` — which needs
//! [`tcp::get_tunnel`]/[`tcp::handle_tcp`] — does not depend on all of `listener`, and the
//! protocol listener modules can import it without a cycle.
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

pub mod tcp;
pub mod udp;

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

pub mod executor;
pub mod route;

pub mod hub;

/// Serialises the tests that assert on a tunnel-state transaction: the process globals behind
/// `murmur_tunnel::tunnel::mode` and `murmur_listener`'s stored confs are written both by a
/// `/configs` PATCH and by every config parse (through the general-update hook), so overlapping
/// transactions clobber each other's assertions.
#[cfg(test)]
pub(crate) mod test_support {
    use tokio::sync::Mutex;

    pub(crate) static TUNNEL_STATE_LOCK: Mutex<()> = Mutex::const_new(());
}

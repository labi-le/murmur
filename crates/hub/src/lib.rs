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
pub mod watch;

/// Serialises the tests that call `parse_with_bytes` directly: the general-update hook such a parse
/// fires writes the process-global tunnel mode and `murmur_listener`'s stored confs for the
/// duration of the parse and rolls them back afterwards, so two overlapping parses clobber each
/// other's assertions.
///
/// The production entry points (`hub::parse`, `PUT` and `PATCH /configs`) do not use this lock:
/// they take `hub::lock_config_operation`, which is also what a test that asserts on one of those
/// transactions holds. `CONFIG_OPERATION` is always taken first, so the two are never acquired in
/// the opposite order.
#[cfg(test)]
pub(crate) mod test_support {
    use tokio::sync::Mutex;

    pub(crate) static TUNNEL_STATE_LOCK: Mutex<()> = Mutex::const_new(());
}

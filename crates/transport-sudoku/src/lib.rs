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

pub mod crypto;
pub mod multiplex;
pub mod obfs;

pub mod address;
pub mod config;
pub mod early_handshake;
pub mod handshake;
pub mod handshake_kip;
pub mod httpmask_tunnel;
pub mod init;
pub mod kip;
pub mod multiplex_dialer;
pub mod multiplex_file;
pub mod replay;
pub mod session_keys;
pub mod table_probe;
pub mod tables;
pub mod uot;
pub mod write_chunks;

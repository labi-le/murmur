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

pub mod anytls;
pub mod auth;
pub mod hysteria2;
pub mod hysteria2_realm;
pub mod jls;
pub mod kcptun;
pub mod mekya;
pub mod mkcp;
pub mod reality;
pub mod restls;
pub mod shadowquic;
pub mod shadowsocks;
pub mod shadowtls;
pub mod snell;
pub mod sudoku;
pub mod trojan;
pub mod trusttunnel;
pub mod tuic;
pub mod tun;
pub mod tunnel;
pub mod vless;
pub mod vmess;

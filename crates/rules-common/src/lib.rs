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

pub mod base;
pub mod domain;
pub mod domain_keyword;
pub mod domain_regex;
pub mod domain_suffix;
pub mod domain_wildcard;
pub mod dscp;
pub mod final_;
pub mod geoip;
pub mod geosite;
pub mod in_name;
pub mod in_type;
pub mod in_user;
pub mod ipasn;
pub mod ipcidr;
pub mod ipsuffix;
pub mod network_type;
pub mod port;
pub mod process;
pub mod rematch_name;
pub mod uid;

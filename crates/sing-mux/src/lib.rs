//! The generic multiplexing transport option shared by murmur's outbound `smux` option and the
//! generic sing listener's `MuxService`: smux/yamux/h2mux framing, padding, TCP Brutal.
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

pub mod brutal;
pub mod client;
pub mod client_conn;
pub mod error;
pub mod h2mux;
mod padding;
pub mod protocol;
mod protocol_conn;
pub mod server;
pub mod server_conn;
pub mod session;
mod smux;
mod yamux_session;

pub use client::{new_client, BrutalOptions, Client, Dialer, Options};
pub use padding::new_padding_conn;
pub use protocol_conn::new_protocol_conn;
pub use server::{new_service, Metadata, Service, ServiceHandler, ServiceOptions};
pub use session::{MuxConn, MuxStream, Session};

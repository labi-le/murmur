//! KCP, the reliable ARQ transport over UDP: the sync ARQ core ([`core::Kcp`]), cipher suite
//! ([`crypt`]), Reed-Solomon FEC framing ([`fec`]), bandwidth autotuning ([`autotune`]) and the
//! generic (non-Linux-batching) session layer ([`session`]): [`UdpSession`], [`Listener`],
//! [`new_conn4`], [`serve_conn`].
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

pub mod autotune;
pub mod core;
pub mod crypt;
pub mod fec;
pub mod session;

pub use crypt::{
    AeadCrypt, AesCfbCrypt, AesGcmCrypt, Block8, BlockCrypt, BlockCrypt8, NoneCrypt, Salsa20Crypt, SimpleXorCrypt, Tea,
    Xtea,
};
pub use session::{new_conn4, serve_conn, Listener, UdpSession};

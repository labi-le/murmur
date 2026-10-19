//! The Hysteria2 protocol: the transport over which a client and a server multiplex TCP
//! streams and UDP sessions on one authenticated QUIC connection.
//!
//! Layering, bottom up:
//!
//! * [`protocol`] -- the wire format: QUIC-varint framed TCP requests/responses, the UDP message
//!   header, and the `Hysteria-Auth`/`Hysteria-UDP`/`Hysteria-CC-RX` authentication headers.
//! * [`obfs`] -- the `salamander` and `gecko` packet-conn obfuscators.
//! * [`packet`] -- the QUIC-datagram UDP relay, including fragmentation and reassembly.
//! * [`quic`] -- the QUIC session: a `quinn` endpoint over the (possibly obfuscated) packet conn.
//! * [`client`] -- the `Client`: the HTTP/3 authentication exchange, the TCP proxy streams and
//!   the UDP sessions, all multiplexed over one connection.
//! * [`dispatch`] -- the stream dispatcher, splitting `0x401` streams
//!   off an `h3` connection and handing them to the server session.
//! * [`service`] -- the `Service` and server session: endpoint construction, the server side of the
//!   authentication exchange, and the per-connection stream and datagram dispatch.
//!
//! Deliberately absent: `realm`, which is mutually exclusive with port hopping and is a separate
//! STUN/UDP-hole-punch control protocol rather than part of the QUIC transport.
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

pub mod client;
pub mod dispatch;
pub mod obfs;
pub mod packet;
pub mod protocol;
pub mod quic;
pub mod service;

pub use client::{Client, ClientOptions};
pub use obfs::Obfs;
pub use service::{MasqueradeHandler, NotFoundMasquerade, ServerHandler, Service, ServiceOptions};

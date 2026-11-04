//! The realm is a rendezvous service: peers talk directly once introduced.
//!
//! It hands a client the addresses a registered hysteria server reports after a UDP hole-punch.
//! This crate serves it over HTTP routes with an SSE event stream; it matches paths and methods
//! directly (see `api`'s module doc) and streams events through a channel-backed body.

pub mod api;
pub mod server;
pub mod session;
pub mod validate;

#[expect(
    clippy::needless_pass_by_value,
    reason = "callers build the message with `format!`, keeping this a crate-internal signature"
)]
pub(crate) fn debugf(message: String) {
    murmur_log::debugln!("[RealmServer] {message}");
}

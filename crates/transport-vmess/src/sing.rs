//! The VMess client and server halves: KDF, protocol framing, chunked AEAD bodies, the
//! VMess AEAD chunk stream and packet-address handling.
//!
//! VLESS is out of scope (a separate protocol implemented elsewhere in this crate). VMess's own
//! mux multiplexing (`COMMAND_MUX`) is also not implemented — distinct from the
//! generic `murmur_sing_mux` crate this crate uses elsewhere — so `Service::accept`'s
//! `COMMAND_MUX` case and `listener::sing_vmess::server::VmessService::new_connection`
//! fail closed rather than dispatching to it; see `client::tests`/`service::tests` for the AEAD-2
//! surface this crate does implement.
//!
//! **Scope cut:** `security = "aes-128-cfb"` — the legacy CFB body framing with its stream
//! checksums — is not implemented. The `alter_id > 0` client dialect is: `client::WriteState::write_handshake`
//! and `client::ReadState::read_response` send the legacy HMAC-MD5/CFB request header and read the
//! legacy CFB response header, while the body keeps the configured AEAD framing. On the server side
//! `service::Service::accept` never rejects on `alter_id`: an AEAD-2 handshake matches any user
//! regardless of that user's `alter_id` — only the separate legacy alter-id map path (not
//! implemented) cares about it.
//!
//! [`shake128`] wraps the `sha3` crate's SHAKE128 XOF for VMess AEAD-2's chunk-length masking and
//! optional padding, byte-for-byte identical to the SHAKE128 output the known-answer vectors
//! encode (see `kat_tests`).

mod addr;
mod chunk;
pub mod client;
mod conn_driver;
pub mod packetaddr;
pub mod service;
mod shake128;
pub mod xudp;

#[cfg(test)]
mod kat_tests;

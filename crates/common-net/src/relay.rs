//!
//! This file holds only the commented-out first `Relay` implementation, which wrapped the peers in
//! `ReadOnlyReader`/`WriteOnlyWriter` to dodge the bulk-read path a TCP conn would expose.
//!
//! The live `Relay` is [`super::sing::relay`]; this module has nothing to port.

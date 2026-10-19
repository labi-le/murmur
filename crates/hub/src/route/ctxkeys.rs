//! Keys for request-scoped values exchanged between API handlers.
//!
//! This router dispatches on pre-parsed path segments (see `server.rs`'s module doc) and passes
//! resolved values as plain function parameters instead of a request-scoped context map, so these
//! keys are not read back anywhere in this crate; they remain part of the public surface for any
//! external caller that expects them.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContextKey(pub &'static str);

impl fmt::Display for ContextKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "murmur context key {}", self.0)
    }
}

pub const CTX_KEY_PROXY_NAME: ContextKey = ContextKey("proxy name");
pub const CTX_KEY_PROVIDER_NAME: ContextKey = ContextKey("provider name");
pub const CTX_KEY_PROXY: ContextKey = ContextKey("proxy");
pub const CTX_KEY_PROVIDER: ContextKey = ContextKey("provider");

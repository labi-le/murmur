//! [`SingContext`] carries the cancellation token plus the two typed values
//! this file attaches (`Additions`, `InAddr`) and the auth user this file only reads.
//!
//! It stands in place of a general-purpose context object. No caller populates the auth
//! user yet (the `anytls/sing_shadowsocks/sing_vless/trusttunnel` listeners this feeds are still
//! unimplemented), so [`get_additions`] always finds `None` there for now.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::addition::{with_in_user, Addition};
use murmur_sing::auth::{self, UserContext};
use murmur_std_compat::net::Addr;

/// The context type for this package, narrowed to what it attaches to the connection.
#[derive(Clone, Default)]
pub struct SingContext {
    pub cancellation: CancellationToken,
    additions: Option<Vec<Addition>>,
    in_addr: Option<Arc<dyn Addr>>,
    user: Option<String>,
}

impl core::fmt::Debug for SingContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `additions` holds erased closures without a `Debug` bound.
        let Self { cancellation, additions, in_addr, user } = self;
        f.debug_struct("SingContext")
            .field("cancellation", cancellation)
            .field("additions", &additions.as_ref().map(Vec::len))
            .field("in_addr", in_addr)
            .field("user", user)
            .finish_non_exhaustive()
    }
}

impl UserContext<String> for SingContext {
    fn with_user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }

    fn user_ref(&self) -> Option<&String> {
        self.user.as_ref()
    }
}

#[must_use]
pub fn with_additions(ctx: &SingContext, additions: Vec<Addition>) -> SingContext {
    let mut ctx = ctx.clone();
    ctx.additions = Some(additions);
    ctx
}

#[must_use]
pub fn additions_from_context(ctx: &SingContext) -> Vec<Addition> {
    get_additions(ctx)
}

pub(crate) fn get_additions(ctx: &SingContext) -> Vec<Addition> {
    let mut additions = ctx.additions.clone().unwrap_or_default();
    if let Some(user) = auth::user_from_context(ctx) {
        additions.push(with_in_user(&user));
    }
    additions
}

pub fn with_in_addr(ctx: &SingContext, in_addr: Arc<dyn Addr>) -> SingContext {
    let mut ctx = ctx.clone();
    ctx.in_addr = Some(in_addr);
    ctx
}

pub(crate) fn get_in_addr(ctx: &SingContext) -> Option<Arc<dyn Addr>> {
    ctx.in_addr.clone()
}

/// Backs the `with_user` helper: applied directly, since [`SingContext`] carries typed state
/// instead of a string-keyed value chain.
#[must_use]
pub fn with_user(ctx: &SingContext, user: String) -> SingContext {
    auth::context_with_user(ctx.clone(), user)
}

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use super::sing::SingDialer;
use murmur_component::slowdown::slowdown::{do_, SlowDown};
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Conn as NetConn, PacketConn as NetPacketConn};

pub struct SlowDownSingDialer {
    pub sing_dialer: Arc<dyn SingDialer>,
    pub slowdown: Arc<SlowDown>,
}

/// Omits the sing dialer, whose trait object is not `Debug`.
impl std::fmt::Debug for SlowDownSingDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlowDownSingDialer").field("slowdown", &self.slowdown).finish_non_exhaustive()
    }
}

#[async_trait]
impl SingDialer for SlowDownSingDialer {
    // cancel-safe: the backoff counters are updated only after the inner call returns, and a
    // cancelled dial drops the connection the inner dial had just opened.
    async fn dial_context(
        &self,
        ctx: &CancellationToken,
        network: &str,
        destination: Socksaddr,
    ) -> Result<Box<dyn NetConn>> {
        do_(&self.slowdown, ctx, || self.sing_dialer.dial_context(ctx, network, destination)).await
    }

    // cancel-safe: the backoff counters are updated only after the inner call returns, and a
    // cancelled listen drops the packet conn the inner listen had just bound.
    async fn listen_packet(&self, ctx: &CancellationToken, destination: Socksaddr) -> Result<Box<dyn NetPacketConn>> {
        do_(&self.slowdown, ctx, || self.sing_dialer.listen_packet(ctx, destination)).await
    }
}

pub fn new_slow_down_sing_dialer(d: Arc<dyn SingDialer>, sd: Arc<SlowDown>) -> SlowDownSingDialer {
    SlowDownSingDialer { sing_dialer: d, slowdown: sd }
}

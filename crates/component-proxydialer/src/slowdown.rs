use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{Datagram, Stream};
use murmur_component::slowdown::slowdown::{do_, SlowDown};
use murmur_constant::adapters::Dialer;

pub struct SlowDownDialer {
    pub dialer: Arc<dyn Dialer>,
    pub slowdown: Arc<SlowDown>,
}

/// Omits the dialer, whose trait object is not `Debug`.
impl std::fmt::Debug for SlowDownDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlowDownDialer").field("slowdown", &self.slowdown).finish_non_exhaustive()
    }
}

#[async_trait]
impl Dialer for SlowDownDialer {
    // cancel-safe: the backoff counters are updated only after the inner call returns, and a
    // cancelled dial drops the connection the inner dial had just opened.
    async fn dial_context(&self, ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn Stream>> {
        do_(&self.slowdown, ctx, || self.dialer.dial_context(ctx, network, address)).await
    }

    // cancel-safe: the backoff counters are updated only after the inner call returns, and a
    // cancelled listen drops the packet conn the inner listen had just bound.
    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
        r_addr_port: Option<SocketAddr>,
    ) -> Result<Box<dyn Datagram>> {
        do_(&self.slowdown, ctx, || self.dialer.listen_packet(ctx, network, address, r_addr_port)).await
    }
}

pub fn new_slow_down_dialer(d: Arc<dyn Dialer>, sd: Arc<SlowDown>) -> SlowDownDialer {
    SlowDownDialer { dialer: d, slowdown: sd }
}

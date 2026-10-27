use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_component_proxydialer::sing::SingDialer;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_inner::tcp::handle_tcp;
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Conn as NetConn, PacketConn as NetPacketConn};
use std::sync::Arc;

pub struct Dialer {
    t: Arc<dyn Tunnel>,
    proxy: String,
}

impl core::fmt::Debug for Dialer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The tunnel is an erased trait object without a `Debug` bound.
        let Self { proxy, .. } = self;
        f.debug_struct("Dialer").field("proxy", proxy).finish_non_exhaustive()
    }
}

#[async_trait]
impl SingDialer for Dialer {
    async fn dial_context(
        &self,
        _ctx: &CancellationToken,
        network: &str,
        destination: Socksaddr,
    ) -> Result<Box<dyn NetConn>> {
        if network != "tcp" && network != "tcp4" && network != "tcp6" {
            return Err(anyhow!("unsupported network {network}"));
        }
        handle_tcp(Some(Arc::clone(&self.t)), &destination.string(), &self.proxy).await
    }

    async fn listen_packet(&self, _ctx: &CancellationToken, _destination: Socksaddr) -> Result<Box<dyn NetPacketConn>> {
        Err(anyhow!("unsupported ListenPacket"))
    }
}

pub fn new_dialer(t: Arc<dyn Tunnel>, proxy: String) -> Dialer {
    Dialer { t, proxy }
}

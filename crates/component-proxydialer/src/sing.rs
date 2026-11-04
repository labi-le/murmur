use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_constant::adapters::Dialer as ConstantDialer;
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Conn as NetConn, PacketConn as NetPacketConn};

/// `SingDialer`, kept as the spelling its callers use.
pub use murmur_sing::network::Dialer as SingDialer;

struct SingDialerImpl {
    c_dialer: Arc<dyn ConstantDialer>,
}

#[async_trait]
impl SingDialer for SingDialerImpl {
    async fn dial_context(
        &self,
        ctx: &CancellationToken,
        network: &str,
        destination: Socksaddr,
    ) -> Result<Box<dyn NetConn>> {
        Ok(Box::new(murmur_common_net::io::StreamAsOldConn::new(
            self.c_dialer.dial_context(ctx, network, &destination.string()).await?,
        )))
    }

    async fn listen_packet(&self, ctx: &CancellationToken, destination: Socksaddr) -> Result<Box<dyn NetPacketConn>> {
        Ok(Box::new(murmur_common_net::io::DatagramAsOldPacketConn(
            self.c_dialer.listen_packet(ctx, "udp", "", destination.addr_port()).await?,
        )))
    }
}

pub fn new_sing_dialer(c_dialer: Arc<dyn ConstantDialer>) -> Arc<dyn SingDialer> {
    Arc::new(SingDialerImpl { c_dialer })
}

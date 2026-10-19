use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use super::adapters::{NatTable, Proxy, UDPPacket};
use super::metadata::Metadata;

#[async_trait]
pub trait Tunnel: Send + Sync {
    /// The call awaits because it may block; the metadata moves to the connection context.
    async fn handle_tcp_conn(&self, conn: Box<dyn murmur_common_net::io::Stream>, metadata: Metadata);

    /// Only queues the packet and never blocks.
    fn handle_udp_packet(&self, packet: Arc<dyn UDPPacket>, metadata: Metadata);

    fn nat_table(&self) -> Arc<dyn NatTable>;

    /// A structural capability check: the method succeeds for any tunnel that happens to have a
    /// `proxies` method, not just one concrete type. `None` here is that check failing.
    fn proxies(&self) -> Option<HashMap<String, Arc<dyn Proxy>>> {
        None
    }
}

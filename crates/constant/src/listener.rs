use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_std_compat::net::Addr;

use super::tunnel::Tunnel;

pub trait Listener: Send + Sync {
    fn raw_address(&self) -> String;
    fn address(&self) -> String;
    fn close(&self) -> Result<()>;
}

pub trait MultiAddrListener: Send + Sync {
    fn close(&self) -> Result<()>;
    fn config(&self) -> String;
    fn addr_list(&self) -> Vec<Box<dyn Addr>>;
}

#[async_trait]
pub trait InboundListener: Send + Sync {
    fn name(&self) -> String;
    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()>;
    fn close(&self) -> Result<()>;
    fn address(&self) -> String;
    fn raw_address(&self) -> String;
    fn config(&self) -> Arc<dyn InboundConfig>;
}

pub trait InboundConfig: Send + Sync {
    fn name(&self) -> String;
    fn equal(&self, config: &dyn InboundConfig) -> bool;
    /// The option's `mapstructure`/`json`-tagged fields serialised to JSON.
    fn option_to_string(&self) -> String;
}

#[async_trait]
pub trait InboundListenConfig: Send + Sync {
    async fn listen(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> Result<Box<dyn murmur_common_net::io::Acceptor>>;

    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> Result<Box<dyn murmur_common_net::io::Datagram>>;
}

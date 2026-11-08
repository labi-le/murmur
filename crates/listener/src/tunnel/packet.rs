use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use murmur_common_net::io::Datagram;
use murmur_common_pool as pool;
use murmur_constant::adapters::{UDPPacket, WriteBack};

pub struct Packet {
    pc: Arc<dyn Datagram>,
    r_addr: std::net::SocketAddr,
    payload: Vec<u8>,
}

impl core::fmt::Debug for Packet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Packet").field("r_addr", &self.r_addr).finish_non_exhaustive()
    }
}

impl Packet {
    pub fn new(pc: Arc<dyn Datagram>, r_addr: std::net::SocketAddr, payload: Vec<u8>) -> Self {
        Self { pc, r_addr, payload }
    }
}

impl Drop for Packet {
    /// The payload is a pooled block; `Drop` is what puts it back, so the packet owns it for
    /// exactly as long as the last `Arc` clone exists.
    fn drop(&mut self) {
        let _ = pool::put(std::mem::take(&mut self.payload));
    }
}

impl UDPPacket for Packet {
    fn data(&self) -> &[u8] {
        &self.payload
    }

    fn local_addr(&self) -> std::net::SocketAddr {
        self.r_addr
    }

    fn in_addr(&self) -> Option<std::net::SocketAddr> {
        Some(self.pc.local_addr().ok().unwrap_or(self.r_addr))
    }
}

#[async_trait]
impl WriteBack for Packet {
    /// Writes with source `(ip, port) = addr`.
    async fn write_back(&self, b: &[u8], _addr: Option<std::net::SocketAddr>) -> Result<usize> {
        Ok(self.pc.send_to(b, self.r_addr).await?)
    }
}

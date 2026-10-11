//! DEVIATION: `Drop` cannot null the backing storage through the trait's `&self` receiver.
//!
//! Clearing the payload inside `UDPPacket::drop_` is impossible through the trait's `&self`
//! receiver, so the payload's readable length is tracked in a separate atomic counter that `Drop`
//! zeroes instead, mirroring `listener::inner::udp::InnerUdpPacket`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;

use murmur_constant::adapters::{UDPPacket, WriteBack};
use murmur_std_compat::net::PacketConn;
use murmur_transport::socks5::socks5;

pub(crate) struct Packet {
    pc: Arc<dyn PacketConn>,
    r_addr: std::net::SocketAddr,
    payload: Vec<u8>,
    len: AtomicUsize,
    put: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Packet {
    pub(crate) fn new(
        pc: Arc<dyn PacketConn>,
        r_addr: std::net::SocketAddr,
        payload: Vec<u8>,
        put: Option<Box<dyn FnOnce() + Send>>,
    ) -> Self {
        let len = AtomicUsize::new(payload.len());
        Self { pc, r_addr, payload, len, put: Mutex::new(put) }
    }
}

#[async_trait]
impl WriteBack for Packet {
    /// write a UDP packet with source `(ip, port)` = `addr`.
    async fn write_back(&self, b: &[u8], addr: Option<std::net::SocketAddr>) -> Result<usize> {
        let addr = addr.ok_or_else(|| anyhow!("address is invalid"))?;
        let addr = murmur_common_net::io::udp_addr_from_socket_addr(addr);
        let socks_addr = socks5::parse_addr_to_socks_addr(&addr).ok_or_else(|| anyhow!("address is invalid"))?;
        let packet = socks5::encode_udp_packet(&socks_addr, b)?;
        let r_addr = murmur_common_net::io::udp_addr_from_socket_addr(self.r_addr);
        Ok(self.pc.write_to(&packet, &r_addr).await?)
    }
}

impl UDPPacket for Packet {
    fn data(&self) -> &[u8] {
        let len = self.len.load(Ordering::Acquire).min(self.payload.len());
        self.payload.get(..len).unwrap_or_default()
    }

    fn drop_(&self) {
        let put = self.put.lock().take();
        if let Some(put) = put {
            put();
        }
        self.len.store(0, Ordering::Release);
    }

    /// returns the source IP/Port of the UDP packet.
    fn local_addr(&self) -> std::net::SocketAddr {
        self.r_addr
    }

    fn in_addr(&self) -> Option<std::net::SocketAddr> {
        Some(
            self.pc
                .local_addr()
                .ok()
                .and_then(|a| murmur_common_net::io::old_addr_to_socket_addr(a.as_ref()).ok())
                .unwrap_or(self.r_addr),
        )
    }
}

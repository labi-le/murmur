use std::cell::UnsafeCell;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use murmur_common_net::io::Datagram;
use murmur_common_pool as pool;
use murmur_constant::adapters::{UDPPacket, WriteBack};

pub struct Packet {
    pc: Arc<dyn Datagram>,
    r_addr: std::net::SocketAddr,
    payload: UnsafeCell<Vec<u8>>,
}

impl core::fmt::Debug for Packet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Packet").field("r_addr", &self.r_addr).finish_non_exhaustive()
    }
}

// SAFETY: `Sync` is required only so `Arc<dyn UDPPacket>` (the trait's `Send + Sync` bound) can
// move across tokio worker threads; a `Packet` is produced once per received datagram and travels
// through a single processing pipeline (`data()`, an optional `write_back()`, then `drop_()`)
// before being discarded, with no other clone of the `Arc` outstanding — the same
// non-concurrent-access contract the unsynchronized byte-slice field relies on. A caller that
// clones this `Arc` and calls `data()`/`drop_()` from two tasks concurrently would race through
// `payload.get()` with no synchronization — `UnsafeCell` provides none.
#[expect(unsafe_code, reason = "the Sync contract documented above the type")]
unsafe impl Sync for Packet {}

impl Packet {
    pub fn new(pc: Arc<dyn Datagram>, r_addr: std::net::SocketAddr, payload: Vec<u8>) -> Self {
        Self { pc, r_addr, payload: UnsafeCell::new(payload) }
    }

    #[expect(unsafe_code, reason = "reads the payload under that Sync contract")]
    fn payload_slice(&self) -> &[u8] {
        // SAFETY: see the `Sync` impl above.
        unsafe { &*self.payload.get() }
    }

    #[expect(unsafe_code, reason = "moves the payload out under that Sync contract")]
    fn take_payload(&self) -> Vec<u8> {
        // SAFETY: see the `Sync` impl above.
        unsafe { std::mem::take(&mut *self.payload.get()) }
    }
}

impl UDPPacket for Packet {
    fn data(&self) -> &[u8] {
        self.payload_slice()
    }

    fn drop_(&self) {
        let buf = self.take_payload();
        let _ = pool::put(buf);
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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;

use murmur_common_net::io::Datagram;
use murmur_common_pool as pool;
use murmur_constant::adapters::{UDPPacket, WriteBack};

pub(crate) struct Packet {
    pc: Arc<dyn Datagram>,
    r_addr: std::net::SocketAddr,
    /// A fresh per-connection key so multiple smux substreams sharing one physical TCP conn's
    /// `remote_addr` still land in distinct NAT entries.
    nat_key: String,
    payload: Vec<u8>,
    len: AtomicUsize,
    put: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// `payload` is the transferred pooled block itself, so `put` is `None` and this struct owes
    /// the block back to the pool at drop time.
    pooled: bool,
}

impl Packet {
    pub(crate) fn new(
        pc: Arc<dyn Datagram>,
        r_addr: std::net::SocketAddr,
        nat_key: String,
        payload: Vec<u8>,
        put: Option<Box<dyn FnOnce() + Send>>,
    ) -> Self {
        let len = AtomicUsize::new(payload.len());
        let pooled = put.is_none();
        Self { pc, r_addr, nat_key, payload, len, put: Mutex::new(put), pooled }
    }
}

impl Drop for Packet {
    fn drop(&mut self) {
        if self.pooled {
            // No callback owns the transferred block; `drop_` cannot move it out of `&self`, so
            // the owner returns it here, exactly once.
            let payload = std::mem::take(&mut self.payload);
            let _ = pool::put(payload);
        }
    }
}

#[async_trait]
impl WriteBack for Packet {
    /// write a UDP packet with source `(ip, port)` = `addr`.
    async fn write_back(&self, b: &[u8], addr: Option<std::net::SocketAddr>) -> Result<usize> {
        let sock_addr = addr.ok_or_else(|| anyhow!("address is invalid"))?;
        Ok(self.pc.send_to(b, sock_addr).await?)
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

    /// returns the source IP/Port of the UDP packet.
    fn in_addr(&self) -> Option<std::net::SocketAddr> {
        Some(self.pc.local_addr().unwrap_or(self.r_addr))
    }

    /// The remote address string, see the `nat_key` field doc.
    fn nat_key(&self) -> String {
        self.nat_key.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::SocketAddr;

    use async_trait::async_trait;

    use super::*;

    struct NullDatagram;

    #[async_trait]
    impl Datagram for NullDatagram {
        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::other("unused"))
        }

        async fn send_to(&self, _buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(0)
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Err(io::Error::other("unused"))
        }
    }

    /// Two smux substreams sharing one physical TCP conn's `remote_addr` (`Listener::
    /// handle_conn_inner` generates a fresh `nat_key` per call) must not collapse onto the
    /// same NAT entry.
    #[test]
    fn nat_key_differs_across_substreams_sharing_the_same_remote_addr() {
        let r_addr: SocketAddr = "198.51.100.9:4433".parse().unwrap();
        let pc: Arc<dyn Datagram> = Arc::new(NullDatagram);

        let one = Packet::new(Arc::<dyn Datagram>::clone(&pc), r_addr, "substream-one".to_owned(), Vec::new(), None);
        let two = Packet::new(pc, r_addr, "substream-two".to_owned(), Vec::new(), None);

        assert_eq!(one.local_addr(), two.local_addr());
        assert_ne!(one.nat_key(), two.nat_key());
    }

    #[test]
    fn a_transfer_read_packet_returns_its_pooled_block_on_drop() {
        let mut block = pool::get(8192);
        block.truncate(6);
        let ptr = block.as_ptr();
        let r_addr: SocketAddr = "198.51.100.9:4433".parse().unwrap();
        let pc: Arc<dyn Datagram> = Arc::new(NullDatagram);

        let packet = Arc::new(Packet::new(pc, r_addr, "transfer".to_owned(), block, None));
        drop(packet);

        let recycled = pool::get(8192);
        assert_eq!(recycled.capacity(), 8192, "the dropped packet must return a poolable block");
        assert_eq!(recycled.as_ptr(), ptr, "the block must be the one the packet owned");
    }

    #[test]
    fn a_callback_packet_still_releases_through_its_callback() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let put: Box<dyn FnOnce() + Send> = Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let r_addr: SocketAddr = "198.51.100.9:4433".parse().unwrap();
        let pc: Arc<dyn Datagram> = Arc::new(NullDatagram);

        let packet = Packet::new(pc, r_addr, "callback".to_owned(), vec![1, 2, 3], Some(put));
        packet.drop_();
        drop(packet);

        assert_eq!(calls.load(Ordering::SeqCst), 1, "the callback must run exactly once");
    }
}

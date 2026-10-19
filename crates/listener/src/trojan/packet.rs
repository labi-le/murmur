use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;

use murmur_common_net::io::Datagram;
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
        Self { pc, r_addr, nat_key, payload, len, put: Mutex::new(put) }
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
}

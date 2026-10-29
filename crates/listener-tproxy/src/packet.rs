use std::cell::UnsafeCell;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::net::UdpSocket;

use murmur_adapter_inbound::addition::Addition;
use murmur_common_net::io::Datagram;
use murmur_common_pool as pool;
use murmur_constant::adapters::{UDPPacket, WriteBack};
use murmur_constant::tunnel::Tunnel;

#[cfg(target_os = "linux")]
use super::udp_linux::dial_udp;
#[cfg(not(target_os = "linux"))]
use super::udp_other::dial_udp;

pub struct Packet {
    pc: Arc<dyn Datagram>,
    l_addr: SocketAddr,
    buf: UnsafeCell<Vec<u8>>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet").field("l_addr", &self.l_addr).finish_non_exhaustive()
    }
}

// SAFETY: `Sync` is required only so `Arc<dyn UDPPacket>` (the trait's own `Send + Sync` bound,
// `constant::adapters::UDPPacket`) can move across the tokio worker threads that carry it from
// the receiving task to the single `process_udp` worker that owns it; it is never used to permit
// real concurrent access. Exactly one `Arc` is created per received datagram
// (`handle_packet_conn`) and handed to `tunnel::handle_udp_packet`, which queues it on one mpsc
// channel to one consumer; `data()`, an optional `write_back()`, then `drop_()` run there in
// sequence with no other clone of the `Arc` outstanding. A future caller that clones this `Arc`
// and calls `data()`/`drop_()` from two tasks concurrently would race through `buf.get()` with no
// synchronization — `UnsafeCell` provides none.
#[expect(unsafe_code, reason = "the Sync contract documented above the type")]
unsafe impl Sync for Packet {}

impl Packet {
    pub fn new(
        pc: Arc<dyn Datagram>,
        l_addr: SocketAddr,
        buf: Vec<u8>,
        tunnel: Arc<dyn Tunnel>,
        additions: Vec<Addition>,
    ) -> Self {
        Self { pc, l_addr, buf: UnsafeCell::new(buf), tunnel, additions }
    }

    #[expect(unsafe_code, reason = "reads the buffer under that Sync contract")]
    fn buf_slice(&self) -> &[u8] {
        // SAFETY: see the `Sync` impl above.
        unsafe { &*self.buf.get() }
    }

    #[expect(unsafe_code, reason = "moves the buffer out under that Sync contract")]
    fn take_buf(&self) -> Vec<u8> {
        // SAFETY: see the `Sync` impl above.
        unsafe { std::mem::take(&mut *self.buf.get()) }
    }
}

impl UDPPacket for Packet {
    fn data(&self) -> &[u8] {
        self.buf_slice()
    }

    fn drop_(&self) {
        let buf = self.take_buf();
        let _ = pool::put(buf);
    }

    /// The source IP/port of the UDP packet.
    fn local_addr(&self) -> SocketAddr {
        self.l_addr
    }

    fn in_addr(&self) -> Option<SocketAddr> {
        Some(self.pc.local_addr().ok().unwrap_or(self.l_addr))
    }
}

#[async_trait]
impl WriteBack for Packet {
    /// Opens a new socket bound to `addr` to write the UDP packet back.
    async fn write_back(&self, b: &[u8], addr: Option<SocketAddr>) -> Result<usize> {
        let r_addr = addr.ok_or_else(|| anyhow!("tproxy: WriteBack requires an address"))?;
        let tc =
            create_or_get_local_conn(r_addr, self.l_addr, Arc::clone(&self.tunnel), self.additions.clone()).await?;
        Ok(tc.send(b).await?)
    }
}

/// Creates or reuses a local connection that listens at `rAddr` and writes to `lAddr`. Here
/// `rAddr` is the ip/port the client wants to access, and `lAddr` is the ip/port the client
/// opened.
async fn create_or_get_local_conn(
    r_addr: SocketAddr,
    l_addr: SocketAddr,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<UdpSocket>> {
    let remote = r_addr.to_string();
    let local = l_addr.to_string();
    let nat_table = tunnel.nat_table();

    if let Some(local_conn) = nat_table.get_for_local_conn(&local, &remote) {
        return Ok(local_conn);
    }

    let (notify, loaded) = nat_table.get_or_create_lock_for_local_conn(&local, &remote);
    if loaded {
        notify.notified().await;
        return nat_table
            .get_for_local_conn(&local, &remote)
            .ok_or_else(|| anyhow!("localConn is nil, nat entry not exist"));
    }

    let result = listen_local_conn(r_addr, l_addr, Arc::clone(&tunnel), additions).await;
    nat_table.delete_lock_for_local_conn(&local, &remote);
    notify.notify_waiters();

    match result {
        Ok(conn) => {
            nat_table.add_for_local_conn(&local, &remote, Arc::clone(&conn));
            Ok(conn)
        }
        Err(err) => {
            murmur_log::errorln!(
                "listenLocalConn failed with error: {}, packet loss (rAddr[{}]={} lAddr[{}]={})",
                err,
                "netip.AddrPort",
                remote,
                "netip.AddrPort",
                local
            );
            Err(err)
        }
    }
}

/// Listens at `rAddr` and sends what it receives back to the
/// program itself, then sends it to the real remote.
async fn listen_local_conn(
    r_addr: SocketAddr,
    l_addr: SocketAddr,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<UdpSocket>> {
    let lc = Arc::new(dial_udp("udp", r_addr, l_addr).await?);

    {
        let lc = Arc::clone(&lc);
        tokio::spawn(async move {
            murmur_log::debugln!("TProxy listenLocalConn rAddr={} lAddr={}", r_addr, l_addr);
            loop {
                let mut buf = pool::get(pool::UDP_BUFFER_SIZE);
                let mut br = 0usize;
                match lc.recv(&mut buf).await {
                    Ok(n) => br = n,
                    Err(err) => {
                        if is_closed(&err) {
                            murmur_log::debugln!("TProxy local conn listener exit.. rAddr={} lAddr={}", r_addr, l_addr);
                            let _ = pool::put(buf);
                            return;
                        }
                    }
                }
                buf.truncate(br);
                // Since following local packets pass through this socket which listens at
                // rAddr, the current listener is chosen as the packet's packet conn.
                let pc = Arc::clone(&lc);
                handle_packet_conn(pc, Arc::clone(&tunnel), buf, l_addr, r_addr, additions.clone());
            }
        });
    }

    Ok(lc)
}

fn is_closed(err: &std::io::Error) -> bool {
    matches!(err.kind(), std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::NotConnected)
}

/// The packet-conn handler.
#[expect(
    clippy::needless_pass_by_value,
    reason = "signature pinned for the listener seam: the callers hand over owned clones and the Arc argument must stay by value for their unsizing coercion"
)]
pub(super) fn handle_packet_conn(
    pc: Arc<dyn Datagram>,
    tunnel: Arc<dyn Tunnel>,
    buf: Vec<u8>,
    l_addr: SocketAddr,
    r_addr: SocketAddr,
    additions: Vec<Addition>,
) {
    let target = murmur_transport::socks5::socks5::addr_from_std_addr_port(r_addr);
    let pkt = Arc::new(Packet::new(pc, l_addr, buf, Arc::clone(&tunnel), additions.clone()));
    let packet_conn = Arc::clone(&pkt);
    let (packet, metadata) = murmur_adapter_inbound::packet::new_packet(
        &target,
        packet_conn,
        murmur_constant::metadata::Type::TPROXY,
        &additions,
    );
    drop(pkt);
    tunnel.handle_udp_packet(packet, metadata);
}

#[cfg(test)]
mod in_addr_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    use murmur_constant::adapters::NatTable;
    use murmur_constant::metadata::Metadata;

    use super::*;

    struct StubDatagram {
        local: SocketAddr,
    }

    #[async_trait]
    impl Datagram for StubDatagram {
        async fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            unimplemented!("not exercised by this test")
        }

        async fn send_to(&self, _buf: &[u8], _addr: SocketAddr) -> std::io::Result<usize> {
            unimplemented!("not exercised by this test")
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local)
        }
    }

    struct CapturingTunnel {
        captured: Mutex<Option<Metadata>>,
    }

    #[async_trait]
    impl Tunnel for CapturingTunnel {
        async fn handle_tcp_conn(&self, _conn: Box<dyn murmur_common_net::io::Stream>, _metadata: Metadata) {
            unimplemented!("not exercised by this test")
        }

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, metadata: Metadata) {
            *self.captured.lock().unwrap() = Some(metadata);
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            unimplemented!("not exercised by this test")
        }
    }

    #[tokio::test]
    async fn handle_packet_conn_fills_in_ip_and_in_port_from_the_local_addr() {
        let l_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 4321);
        let listener_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 8080);
        let r_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 443);
        let pc: Arc<dyn Datagram> = Arc::new(StubDatagram { local: listener_addr });
        let tunnel = Arc::new(CapturingTunnel { captured: Mutex::new(None) });

        let handle = Arc::clone(&tunnel);
        handle_packet_conn(pc, handle, b"hello".to_vec(), l_addr, r_addr, Vec::new());

        let metadata = tunnel.captured.lock().unwrap().take().expect("metadata captured");
        assert_eq!(metadata.in_ip, Some(listener_addr.ip()));
        assert_eq!(metadata.in_port, listener_addr.port());
    }
}

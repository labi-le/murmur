//! The TCP half of the TUN listener: the userspace network stack.
//!
//! TCP is terminated inside the stack and each flow is called back into the listener handler, which
//! this crate drives over the same smoltcp stack a WireGuard tunnel uses. UDP datagrams and ICMP
//! echo stay on the direct path in [`super`]: an echo is answered with a synthesised reply rather
//! than forwarded, and the UDP handler receives whole datagrams either way.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use ipnet::IpNet;

use murmur_adapter_inbound::addition::Addition;
use murmur_adapter_inbound::socket::new_socket;
use murmur_common_net::io::Stream;
use murmur_component_wireguard::{PacketHandle, Stack, StackConfig, TcpConn};
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_transport::socks5::socks5;

use super::device::MAX_PACKET_SIZE;
use super::packet::DeviceWriter;

/// The stack plus its TCP forwarder.
pub struct TcpForwarder {
    stack: Arc<Stack>,
    packets: Arc<PacketHandle>,
}

impl core::fmt::Debug for TcpForwarder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpForwarder").finish_non_exhaustive()
    }
}

impl TcpForwarder {
    /// `local_addresses` are the TUN's own addresses and `mtu` its effective one.
    pub fn new(local_addresses: Vec<IpNet>, mtu: u16) -> Result<Arc<Self>> {
        let (stack, packets) = Stack::with_packet_handle_promiscuous(StackConfig { local_addresses, mtu })?;
        Ok(Arc::new(Self { stack, packets: Arc::new(packets) }))
    }

    /// One TCP packet into the stack. A SYN needs its port armed first: smoltcp answers a
    /// connection only from a socket listening on that port, and resets anything else.
    pub async fn forward(&self, raw: &[u8], syn: bool, dst_port: u16) -> Result<()> {
        if syn {
            self.stack.arm_tcp_port(dst_port).await?;
        }
        self.packets.write(raw).map_err(|err| anyhow!("write to the tun tcp stack: {err}"))
    }

    /// The stack's write loop: everything the stack transmits goes back out the device.
    pub fn spawn_writer(self: &Arc<Self>, writer: Arc<dyn DeviceWriter>) {
        let packets = Arc::clone(&self.packets);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            loop {
                let Ok(read) = packets.read_async(&mut buf).await else { return };
                let Some(packet) = buf.get(..read) else { return };
                if writer.write_packet(packet).await.is_err() {
                    return;
                }
            }
        });
    }

    /// `Forward`: each connection the stack establishes reaches the tunnel on its own task.
    pub fn spawn_acceptor(self: &Arc<Self>, tunnel: Arc<dyn Tunnel>, additions: Arc<Vec<Addition>>) {
        let stack = Arc::clone(&self.stack);
        tokio::spawn(async move {
            loop {
                let Ok(conn) = stack.accept_tcp().await else { return };
                let tunnel = Arc::clone(&tunnel);
                let additions = Arc::clone(&additions);
                tokio::spawn(async move { handle_connection(conn, tunnel, additions).await });
            }
        });
    }

    /// Ends the stack's driver task, which releases a writer waiting on a packet.
    pub fn close(&self) {
        self.stack.close();
    }
}

/// The destination the client dialled is the
/// connection's local address and the client is its peer, which the forwarder passes through as the
/// metadata destination and source.
#[expect(
    clippy::rc_buffer,
    reason = "the accept loop shares this list as an `Arc<Vec<Addition>>`; reslicing here would copy it per connection"
)]
async fn handle_connection(conn: TcpConn, tunnel: Arc<dyn Tunnel>, additions: Arc<Vec<Addition>>) {
    let Ok(destination) = conn.local_addr() else { return };
    let target = socks5::addr_from_std_addr_port(destination);
    let (conn, metadata) = new_socket(&target, Box::new(conn), Type::TUN, &additions);
    tunnel.handle_tcp_conn(conn, metadata).await;
}

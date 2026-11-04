use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::addition::{with_special_proxy, Addition};
use murmur_adapter_inbound::packet::new_packet;
use murmur_common_net::io::Datagram;
use murmur_common_pool as pool;
use murmur_constant::listener::{InboundListenConfig, Listener as ConstListener};
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_transport::socks5::socks5;

use super::packet::Packet;

pub struct PacketConn {
    conn: Arc<dyn Datagram>,
    addr: String,
    target: socks5::Addr,
    closed: AtomicBool,
}

impl core::fmt::Debug for PacketConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketConn")
            .field("addr", &self.addr)
            .field("target", &self.target)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl ConstListener for PacketConn {
    fn raw_address(&self) -> String {
        self.addr.clone()
    }

    fn address(&self) -> String {
        self.conn.local_addr().map(|addr| addr.to_string()).unwrap_or_default()
    }

    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(self.conn.close()?)
    }
}

impl PacketConn {
    fn handle_udp(
        self: &Arc<Self>,
        buf: Vec<u8>,
        addr: std::net::SocketAddr,
        tunnel: &Arc<dyn Tunnel>,
        additions: &[Addition],
    ) {
        let c_packet = Arc::new(Packet::new(Arc::clone(&self.conn), addr, buf));
        let c_packet_clone = Arc::clone(&c_packet);
        let (packet, metadata) = new_packet(&self.target, c_packet_clone, Type::TUNNEL, additions);
        drop(c_packet);
        tunnel.handle_udp_packet(packet, metadata);
    }
}

pub async fn new_udp(
    addr: &str,
    target: &str,
    proxy: &str,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<PacketConn>> {
    let l: Arc<dyn Datagram> = Arc::from(lc.listen_packet(&CancellationToken::new(), "udp", addr).await?);

    let target_addr = socks5::parse_addr(target).ok_or_else(|| anyhow!("invalid target address {target}"))?;

    let sl = Arc::new(PacketConn {
        conn: Arc::clone(&l),
        addr: addr.to_owned(),
        target: target_addr,
        closed: AtomicBool::new(false),
    });

    let mut additions = additions;
    if !proxy.is_empty() {
        additions.insert(0, with_special_proxy(proxy));
    }

    {
        let sl = Arc::clone(&sl);
        tokio::spawn(async move {
            loop {
                let mut buf = pool::get(pool::UDP_BUFFER_SIZE);
                let Ok((n, remote_addr)) = l.recv_from(&mut buf).await else {
                    let _ = pool::put(buf);
                    if sl.closed.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                };
                buf.truncate(n);
                let tunnel = Arc::clone(&tunnel);
                let additions = additions.clone();
                sl.handle_udp(buf, remote_addr, &tunnel, &additions);
            }
        });
    }

    Ok(sl)
}

#[cfg(test)]
mod in_addr_tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Mutex;
    use std::time::Duration;

    use async_trait::async_trait;
    use murmur_adapter_inbound::listen::default_listen_config;
    use murmur_constant::adapters::{NatTable, UDPPacket};
    use murmur_constant::metadata::Metadata;
    use tokio::net::UdpSocket;
    use tokio::sync::Notify;

    use super::*;

    struct CapturingTunnel {
        captured: Mutex<Option<Metadata>>,
        notify: Notify,
    }

    #[async_trait]
    impl Tunnel for CapturingTunnel {
        async fn handle_tcp_conn(&self, _conn: Box<dyn murmur_common_net::io::Stream>, _metadata: Metadata) {
            unimplemented!("not exercised by this test")
        }

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, metadata: Metadata) {
            *self.captured.lock().unwrap() = Some(metadata);
            self.notify.notify_one();
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            unimplemented!("not exercised by this test")
        }
    }

    #[tokio::test]
    async fn new_udp_fills_in_ip_and_in_port_from_the_listener_address() {
        let tunnel = Arc::new(CapturingTunnel { captured: Mutex::new(None), notify: Notify::new() });
        let listener_tunnel = Arc::clone(&tunnel);
        let listener = new_udp("127.0.0.1:0", "1.2.3.4:80", "", default_listen_config(), listener_tunnel, Vec::new())
            .await
            .expect("new_udp binds");
        let listener_addr: SocketAddr = listener.address().parse().expect("listener has a local address");

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client binds");
        client.send_to(b"hello", listener_addr).await.expect("client sends");

        tokio::time::timeout(Duration::from_secs(5), tunnel.notify.notified())
            .await
            .expect("tunnel receives the packet");

        let metadata = tunnel.captured.lock().unwrap().take().expect("metadata captured");
        assert_eq!(metadata.in_ip, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(metadata.in_port, listener_addr.port());

        listener.close().expect("listener closes");
    }
}

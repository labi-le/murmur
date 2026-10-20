use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::addition::Addition;
use murmur_adapter_inbound::packet::new_packet;
use murmur_common::sockopt::reuse_common::udp_reuseaddr;
use murmur_common_net::packet::packet::EnhancePacketConn;
use murmur_common_net::packet_file::new_enhance_packet_conn;
use murmur_common_pool as pool;
use murmur_constant::listener::InboundListenConfig;
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_log::warnln;
use murmur_std_compat::net::{Addr, PacketConn as NetPacketConn};
use murmur_transport::socks5::socks5;
use murmur_transport_shadowsocks::core::cipher::Cipher;

use super::utils::Packet;

pub(crate) struct UdpListener {
    packet_conn: Arc<dyn NetPacketConn>,
    closed: AtomicBool,
}

impl UdpListener {
    pub(crate) fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(self.packet_conn.close()?)
    }

    pub(crate) fn local_addr(&self) -> std::io::Result<Box<dyn Addr>> {
        self.packet_conn.local_addr()
    }
}

/// A datagram socket bound and wrapped, with its read loop not yet running: the caller binds
/// every address of the listener before it starts serving any of them.
pub(crate) struct BoundUdp {
    listener: Arc<UdpListener>,
    conn: Arc<dyn EnhancePacketConn>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
}

impl BoundUdp {
    #[must_use]
    pub(crate) fn listener(&self) -> Arc<UdpListener> {
        Arc::clone(&self.listener)
    }

    pub(crate) fn serve(self) {
        let Self { listener, conn, tunnel, additions } = self;
        tokio::spawn(async move {
            loop {
                let (data, put, remote_addr, result) = conn.wait_read_from().await;
                if result.is_err() {
                    if let Some(put) = put {
                        put();
                    } else {
                        let _ = pool::put(data);
                    }
                    if listener.closed.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                }
                let Some(remote_addr) = remote_addr else {
                    if let Some(put) = put {
                        put();
                    } else {
                        let _ = pool::put(data);
                    }
                    continue;
                };
                let Ok(remote_addr) = murmur_common_net::io::old_addr_to_socket_addr(remote_addr.as_ref()) else {
                    if let Some(put) = put {
                        put();
                    } else {
                        let _ = pool::put(data);
                    }
                    continue;
                };
                let pooled = put.is_none();
                handle_socks_udp(Arc::clone(&conn).into_packet_conn(), &tunnel, &data, put, remote_addr, &additions);
                // `handle_socks_udp` copies the payload out; a transferred block is free again.
                if pooled {
                    let _ = pool::put(data);
                }
            }
        });
    }
}

pub(crate) async fn bind_udp(
    addr: &str,
    lc: &Arc<dyn InboundListenConfig>,
    pick_cipher: &dyn Cipher,
    tunnel: &Arc<dyn Tunnel>,
    additions: &[Addition],
) -> Result<BoundUdp> {
    let l: Box<dyn murmur_std_compat::net::PacketConn> = Box::new(murmur_common_net::io::DatagramAsOldPacketConn(
        lc.listen_packet(&CancellationToken::new(), "udp", addr).await?,
    ));

    if let Err(err) = udp_reuseaddr(l.as_ref()) {
        warnln!("Failed to Reuse UDP Address: {err}");
    }

    let l: Arc<dyn NetPacketConn> = Arc::from(l);
    let listener = Arc::new(UdpListener { packet_conn: Arc::clone(&l), closed: AtomicBool::new(false) });

    let conn = pick_cipher.packet_conn(new_enhance_packet_conn(l))?;

    Ok(BoundUdp { listener, conn, tunnel: Arc::clone(tunnel), additions: additions.to_vec() })
}

fn handle_socks_udp(
    pc: Arc<dyn NetPacketConn>,
    tunnel: &Arc<dyn Tunnel>,
    buf: &[u8],
    put: Option<Box<dyn FnOnce() + Send>>,
    addr: std::net::SocketAddr,
    additions: &[Addition],
) {
    let Some(tgt_addr) = socks5::split_addr(buf) else {
        if let Some(put) = put {
            put();
        }
        return;
    };
    let payload = buf.get(tgt_addr.len()..).unwrap_or_default().to_vec();

    let packet = Arc::new(Packet::new(pc, addr, payload, put));
    let (packet, metadata) = new_packet(&tgt_addr, packet, Type::SHADOWSOCKS, additions);
    tunnel.handle_udp_packet(packet, metadata);
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::addition::{with_in_name, with_special_rules, Addition};
use murmur_adapter_inbound::listen::default_listen_config;
use murmur_adapter_inbound::packet::new_packet;
use murmur_common::sockopt::reuse_common::udp_reuseaddr;
use murmur_common_net::packet_file::{new_enhance_packet_conn, EnhancePacketConn};
use murmur_constant::listener::{InboundListenConfig, Listener as ConstListener};
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_log::warnln;
use murmur_std_compat::net::PacketConn as NetPacketConn;
use murmur_transport::socks5::socks5;

use super::tcp::default_config;
use super::utils::Packet;

pub struct UdpListener {
    packet_conn: Arc<dyn NetPacketConn>,
    addr: String,
    closed: AtomicBool,
}

impl core::fmt::Debug for UdpListener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdpListener").field("addr", &self.addr).field("closed", &self.closed).finish_non_exhaustive()
    }
}

impl ConstListener for UdpListener {
    fn raw_address(&self) -> String {
        self.addr.clone()
    }

    fn address(&self) -> String {
        self.packet_conn.local_addr().map(|addr| addr.string()).unwrap_or_default()
    }

    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(self.packet_conn.close()?)
    }
}

pub async fn new_udp(addr: &str, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) -> Result<Arc<UdpListener>> {
    new_udp_with_config(default_config(addr), default_listen_config(), tunnel, additions).await
}

pub async fn new_udp_with_config(
    config: murmur_listener_config::auth::AuthServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<UdpListener>> {
    let bound = bind_udp_with_config(config, lc, tunnel, additions).await?;
    let listener = bound.listener();
    bound.serve();
    Ok(listener)
}

/// A bound-but-not-yet-serving SOCKS UDP listener; the caller binds every address before any of them serves.
pub(crate) struct BoundUdpListener {
    listener: Arc<UdpListener>,
    conn: Arc<dyn EnhancePacketConn>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
}

impl BoundUdpListener {
    pub(crate) fn listener(&self) -> Arc<UdpListener> {
        Arc::clone(&self.listener)
    }

    pub(crate) fn serve(self) {
        let Self { listener: sl_task, conn: ep, tunnel, additions } = self;
        let l = Arc::clone(&sl_task.packet_conn);
        tokio::spawn(async move {
            loop {
                let (data, put, remote_addr, result) = ep.wait_read_from().await;
                if result.is_err() {
                    if let Some(put) = put {
                        put();
                    }
                    if sl_task.closed.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                }
                let Some(remote_addr) = remote_addr else {
                    if let Some(put) = put {
                        put();
                    }
                    continue;
                };
                let Ok(remote_addr) = murmur_common_net::io::old_addr_to_socket_addr(remote_addr.as_ref()) else {
                    if let Some(put) = put {
                        put();
                    }
                    continue;
                };
                handle_socks_udp(Arc::clone(&l), &tunnel, &data, put, remote_addr, &additions);
            }
        });
    }
}

pub(crate) async fn bind_udp_with_config(
    config: murmur_listener_config::auth::AuthServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<BoundUdpListener> {
    let additions =
        if additions.is_empty() { vec![with_in_name("DEFAULT-SOCKS"), with_special_rules("")] } else { additions };

    // S11: remove with murmur-std-compat: `common::sockopt::udp_reuseaddr` and common-net's
    // `new_enhance_packet_conn` (packet/packet.rs) still require the old PacketConn trait.
    let l: Box<dyn murmur_std_compat::net::PacketConn> = Box::new(murmur_common_net::io::DatagramAsOldPacketConn(
        lc.listen_packet(&CancellationToken::new(), "udp", &config.listen).await?,
    ));

    if let Err(err) = udp_reuseaddr(l.as_ref()) {
        warnln!("Failed to Reuse UDP Address: {err}");
    }

    let l: Arc<dyn NetPacketConn> = Arc::from(l);

    let listener = Arc::new(UdpListener {
        packet_conn: Arc::clone(&l),
        addr: config.listen.clone(),
        closed: AtomicBool::new(false),
    });

    let conn = new_enhance_packet_conn(Arc::clone(&l));

    Ok(BoundUdpListener { listener, conn, tunnel, additions })
}

fn handle_socks_udp(
    pc: Arc<dyn NetPacketConn>,
    tunnel: &Arc<dyn Tunnel>,
    buf: &[u8],
    put: Option<Box<dyn FnOnce() + Send>>,
    addr: std::net::SocketAddr,
    additions: &[Addition],
) {
    let Ok((target, payload)) = socks5::decode_udp_packet(buf) else {
        if let Some(put) = put {
            put();
        }
        return;
    };
    let payload = payload.to_vec();
    let packet = Arc::new(Packet::new(pc, addr, payload, put));
    let (packet, metadata) = new_packet(&target, packet, Type::SOCKS5, additions);
    tunnel.handle_udp_packet(packet, metadata);
}

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;

use murmur_adapter_inbound::addition::{with_dscp, with_in_name, with_special_rules, Addition};
use murmur_constant::listener::Listener as ConstListener;
use murmur_constant::tunnel::Tunnel;

use super::packet::handle_packet_conn;

#[cfg(target_os = "linux")]
use super::setsockopt_linux::setsockopt;
#[cfg(not(target_os = "linux"))]
use super::setsockopt_other::setsockopt;

#[cfg(target_os = "linux")]
use super::udp_linux::{get_dscp, get_orig_dst, recv_msg_udp};
#[cfg(not(target_os = "linux"))]
use super::udp_other::{get_dscp, get_orig_dst, recv_msg_udp};

#[derive(Debug)]
pub struct UdpListener {
    packet_conn: Arc<UdpSocket>,
    addr: String,
    closed: AtomicBool,
}

impl ConstListener for UdpListener {
    fn raw_address(&self) -> String {
        self.addr.clone()
    }

    fn address(&self) -> String {
        self.packet_conn.local_addr().map(|addr| addr.to_string()).unwrap_or_default()
    }

    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

pub async fn new_udp(addr: &str, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) -> Result<Arc<UdpListener>> {
    let mut additions = additions;
    if additions.is_empty() {
        additions = vec![with_in_name("DEFAULT-TPROXY"), with_special_rules("")];
    }

    let l = Arc::new(UdpSocket::bind(addr).await?);

    let rl =
        Arc::new(UdpListener { packet_conn: Arc::clone(&l), addr: addr.to_owned(), closed: AtomicBool::new(false) });

    #[cfg(target_os = "linux")]
    setsockopt(&l, addr)?;
    #[cfg(not(target_os = "linux"))]
    setsockopt(addr)?;

    {
        let rl = Arc::clone(&rl);
        tokio::spawn(async move {
            let mut oob = [0u8; 1024];
            loop {
                let mut buf = murmur_common_pool::get(murmur_common_pool::UDP_BUFFER_SIZE);
                let Ok((n, oobn, mut l_addr)) = recv_msg_udp(&l, &mut buf, &mut oob).await else {
                    let _ = murmur_common_pool::put(buf);
                    if rl.closed.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                };

                let oob_data = oob.get(..oobn).unwrap_or_default();
                let Ok(r_addr) = get_orig_dst(oob_data) else {
                    let _ = murmur_common_pool::put(buf);
                    continue;
                };

                let dscp = get_dscp(oob_data).unwrap_or(0);
                let mut additions = additions.clone();
                additions.push(with_dscp(dscp));

                if r_addr.is_ipv4() {
                    // try to unmap a 4-in-6 address
                    if let std::net::IpAddr::V6(v6) = l_addr.ip() {
                        if let Some(v4) = v6.to_ipv4_mapped() {
                            l_addr = SocketAddr::new(std::net::IpAddr::V4(v4), l_addr.port());
                        }
                    }
                }

                buf.truncate(n);
                let pc = Arc::clone(&l);
                handle_packet_conn(pc, Arc::clone(&tunnel), buf, l_addr, r_addr, additions);
            }
        });
    }

    Ok(rl)
}

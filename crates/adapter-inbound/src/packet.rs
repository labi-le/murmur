use std::sync::Arc;

use murmur_common_net::io::udp_addr_from_socket_addr;
use murmur_constant::adapters::UDPPacket;
use murmur_constant::metadata::{Metadata, NetWork, Type};
use murmur_std_compat::net::Addr;
use murmur_transport::socks5::socks5;

use super::addition::{apply_additions, with_in_addr, with_src_addr, Addition};
use super::util::parse_socks_addr;

fn arc_addr(addr: impl Addr + 'static) -> Arc<dyn Addr> {
    Arc::new(addr)
}

pub fn new_packet(
    target: &socks5::Addr,
    packet: Arc<dyn UDPPacket>,
    source: Type,
    additions: &[Addition],
) -> (Arc<dyn UDPPacket>, Metadata) {
    let mut metadata = parse_socks_addr(target);
    metadata.network = NetWork::UDP;
    metadata.type_ = source;
    let local_addr = packet.local_addr();
    metadata.raw_src_addr = Some(arc_addr(udp_addr_from_socket_addr(local_addr)));
    metadata.raw_dst_addr = metadata.udp_addr().map(arc_addr);
    apply_additions(&mut metadata, &[with_src_addr(Some(Box::new(udp_addr_from_socket_addr(local_addr))))]);
    if let Some(in_addr) = packet.in_addr() {
        apply_additions(&mut metadata, &[with_in_addr(Some(Box::new(udp_addr_from_socket_addr(in_addr))))]);
    }
    apply_additions(&mut metadata, additions);

    (packet, metadata)
}

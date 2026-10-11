use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio_util::sync::CancellationToken;

use crate::dialer::dialer::listen_packet;
use crate::dialer::options::{with_addr_reuse, with_fallback_bind, with_interface};
use murmur_common_net::io::Datagram;

pub async fn listen_dhcp_client(ctx: &CancellationToken, iface_name: &str) -> anyhow::Result<Box<dyn Datagram>> {
    let listen_addr =
        if cfg!(any(target_os = "linux", target_os = "android")) { "255.255.255.255:68" } else { "0.0.0.0:68" };

    let mut options = vec![with_interface(iface_name), with_addr_reuse(true)];

    // fallback bind on windows, because syscall bind can not receive broadcast
    if cfg!(target_os = "windows") {
        options.push(with_fallback_bind(true));
    }

    listen_packet(ctx, "udp4", listen_addr, Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 67)), options).await
}

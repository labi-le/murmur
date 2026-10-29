use std::net::{IpAddr, SocketAddr};

use super::bind::{fallback_bind_iface_to_dialer, fallback_bind_iface_to_listen_config, fallback_parse_network};
use super::control::{StdDialer, StdListenConfig};

pub(crate) async fn bind_iface_to_dialer(
    iface_name: &str,
    dialer: &mut StdDialer,
    network: &str,
    destination: Option<IpAddr>,
) -> anyhow::Result<()> {
    fallback_bind_iface_to_dialer(iface_name, dialer, network, destination).await
}

pub(crate) async fn bind_iface_to_listen_config(
    iface_name: &str,
    lc: &mut StdListenConfig,
    network: &str,
    address: &str,
    r_addr_port: Option<SocketAddr>,
) -> anyhow::Result<String> {
    fallback_bind_iface_to_listen_config(iface_name, lc, network, address, r_addr_port).await
}

pub fn parse_network(network: &str, addr: Option<IpAddr>) -> String {
    fallback_parse_network(network, addr)
}

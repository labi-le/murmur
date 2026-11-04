use anyhow::{anyhow, Result};
use tokio::net::UdpSocket;

pub fn get_orig_dst(_oob: &[u8]) -> Result<std::net::SocketAddr> {
    Err(anyhow!("UDP redir not supported on current platform"))
}

pub fn get_dscp(_oob: &[u8]) -> Result<u8> {
    Err(anyhow!("UDP redir not supported on current platform"))
}

pub async fn dial_udp(
    _network: &str,
    _l_addr: std::net::SocketAddr,
    _r_addr: std::net::SocketAddr,
) -> Result<UdpSocket> {
    Err(anyhow!("UDP redir not supported on current platform"))
}

/// Package-local seam mirroring `udp_linux::recv_msg_udp`; reading a datagram's ancillary data
/// has no portable equivalent here.
pub async fn recv_msg_udp(
    _socket: &UdpSocket,
    _buf: &mut [u8],
    _oob: &mut [u8],
) -> std::io::Result<(usize, usize, std::net::SocketAddr)> {
    Err(std::io::Error::other("UDP redir not supported on current platform"))
}

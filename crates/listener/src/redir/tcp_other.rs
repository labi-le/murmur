#![cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]

use anyhow::{anyhow, Result};
use tokio::net::TcpStream;

use murmur_transport::socks5::socks5;

pub(crate) fn parser_packet(_conn: &TcpStream) -> Result<socks5::Addr> {
    Err(anyhow!("system not support yet"))
}

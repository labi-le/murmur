use std::io;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::time::Instant;

use murmur_std_compat::net::{Addr, PacketConn};

/// Wraps the packet conn handle the platform provides.
pub struct TCPConn {
    pub udp_conn: Arc<dyn PacketConn>,
}

impl std::fmt::Debug for TCPConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The packet conn handle is a dyn trait object, so the connection is reported without it.
        f.debug_struct("TCPConn").finish_non_exhaustive()
    }
}

pub async fn dial(_network: &str, _address: &str) -> Result<TCPConn> {
    Err(anyhow!("faketcp is not supported on this platform"))
}

pub async fn listen(_network: &str, _address: &str) -> Result<TCPConn> {
    Err(anyhow!("faketcp is not supported on this platform"))
}

impl TCPConn {
    pub fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        if let Some(socket) = self.udp_conn.as_socket() {
            return socket.set_recv_buffer_size(bytes);
        }
        Ok(())
    }

    pub fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        if let Some(socket) = self.udp_conn.as_socket() {
            return socket.set_send_buffer_size(bytes);
        }
        Ok(())
    }

    #[cfg(unix)]
    pub fn syscall_conn(&self) -> Result<usize> {
        use std::os::fd::AsRawFd;

        if let Some(socket) = self.udp_conn.as_socket() {
            Ok(usize::try_from(socket.as_raw_fd()).map_err(|_| anyhow!("not supported"))?)
        } else {
            Err(anyhow!("not supported"))
        }
    }

    #[cfg(not(unix))]
    pub fn syscall_conn(&self) -> Result<usize> {
        Err(anyhow!("not supported"))
    }
}

#[async_trait]
impl PacketConn for TCPConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.udp_conn.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.udp_conn.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.udp_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.udp_conn.close()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.udp_conn.as_socket()
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.udp_conn.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.udp_conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.udp_conn.set_write_deadline(deadline)
    }
}

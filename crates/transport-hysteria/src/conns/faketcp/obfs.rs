use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::obfs::obfs::Obfuscator;
use murmur_std_compat::net::{Addr, PacketConn};

use super::TCPConn;

pub const UDP_BUFFER_SIZE: usize = 65535;

/// A scratch buffer per direction, kept inside the mutex that protects it.
pub struct ObfsFakeTCPConn {
    orig: TCPConn,
    obfs: Arc<dyn Obfuscator>,
    read_buf: Mutex<Vec<u8>>,
    write_buf: Mutex<Vec<u8>>,
}

impl std::fmt::Debug for ObfsFakeTCPConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The wrapped `TCPConn` is a raw socket wrapper that is not `Debug` on every platform
        // (`faketcp`'s stub variant), so the struct is reported without its fields.
        f.debug_struct("ObfsFakeTCPConn").finish_non_exhaustive()
    }
}

impl ObfsFakeTCPConn {
    pub fn new(orig: TCPConn, obfs: Arc<dyn Obfuscator>) -> Self {
        Self {
            orig,
            obfs,
            read_buf: Mutex::new(vec![0u8; UDP_BUFFER_SIZE]),
            write_buf: Mutex::new(vec![0u8; UDP_BUFFER_SIZE]),
        }
    }

    pub fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        self.orig.set_read_buffer(bytes)
    }

    pub fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        self.orig.set_write_buffer(bytes)
    }

    pub fn syscall_conn(&self) -> anyhow::Result<usize> {
        self.orig.syscall_conn()
    }
}

#[async_trait]
impl PacketConn for ObfsFakeTCPConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        loop {
            let mut read_buf = self.read_buf.lock().await;
            let (n, addr) = self.orig.read_from(read_buf.as_mut_slice()).await?;
            if n == 0 {
                drop(read_buf);
                return Ok((0, addr));
            }
            let Some(packet) = read_buf.get(..n) else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet larger than the buffer"));
            };
            let new_n = self.obfs.deobfuscate(packet, p);
            drop(read_buf);
            if new_n > 0 {
                return Ok((new_n, addr));
            }
        }
    }

    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let mut write_buf = self.write_buf.lock().await;
        let bn = self.obfs.obfuscate(p, write_buf.as_mut_slice());
        let Some(packet) = write_buf.get(..bn) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "obfuscated packet exceeds the buffer"));
        };
        let result = self.orig.write_to(packet, addr).await;
        drop(write_buf);
        result?;
        Ok(p.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.orig.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.orig.close()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.orig.as_socket()
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.orig.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.orig.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.orig.set_write_deadline(deadline)
    }
}

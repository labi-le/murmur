use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use crate::obfs::obfs::Obfuscator;
use murmur_std_compat::net::{Addr, PacketConn};

pub(crate) const UDP_BUFFER_SIZE: usize = 65535;

pub struct ObfsUDPConn {
    orig: Box<dyn PacketConn>,
    obfs: Arc<dyn Obfuscator>,
    read_buf: tokio::sync::Mutex<Vec<u8>>,
    write_buf: tokio::sync::Mutex<Vec<u8>>,
}

impl std::fmt::Debug for ObfsUDPConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfsUDPConn").finish_non_exhaustive()
    }
}

impl ObfsUDPConn {
    pub fn new(orig: Box<dyn PacketConn>, obfs: Arc<dyn Obfuscator>) -> Self {
        Self {
            orig,
            obfs,
            read_buf: tokio::sync::Mutex::new(vec![0; UDP_BUFFER_SIZE]),
            write_buf: tokio::sync::Mutex::new(vec![0; UDP_BUFFER_SIZE]),
        }
    }
}

#[async_trait]
impl PacketConn for ObfsUDPConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        loop {
            let mut read_buf = self.read_buf.lock().await;
            let (n, addr) = self.orig.read_from(read_buf.as_mut_slice()).await?;
            if n == 0 {
                return Ok((0, addr));
            }
            let Some(packet) = read_buf.get(..n) else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet larger than the buffer"));
            };
            let new_n = self.obfs.deobfuscate(packet, buf);
            drop(read_buf);
            if new_n > 0 {
                return Ok((new_n, addr));
            }
        }
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let mut write_buf = self.write_buf.lock().await;
        let bn = self.obfs.obfuscate(buf, write_buf.as_mut_slice());
        let Some(packet) = write_buf.get(..bn) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "obfuscated packet exceeds the buffer"));
        };
        let result = self.orig.write_to(packet, addr).await;
        drop(write_buf);
        result?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.orig.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.orig.close()
    }
}

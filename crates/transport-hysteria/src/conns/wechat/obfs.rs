use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use crate::obfs::obfs::Obfuscator;
use murmur_std_compat::net::{Addr, PacketConn};

pub(crate) const UDP_BUFFER_SIZE: usize = 65535;

pub struct ObfsWeChatUDPConn {
    orig: Box<dyn PacketConn>,
    obfs: Arc<dyn Obfuscator>,
    read_buf: tokio::sync::Mutex<Vec<u8>>,
    write_buf: tokio::sync::Mutex<Vec<u8>>,
    sn: parking_lot::Mutex<u32>,
}

/// The byte count of the header the obfuscated payload sits behind.
const HEADER_LEN: usize = 13;

impl std::fmt::Debug for ObfsWeChatUDPConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfsWeChatUDPConn").finish_non_exhaustive()
    }
}

impl ObfsWeChatUDPConn {
    pub fn new(orig: Box<dyn PacketConn>, obfs: Arc<dyn Obfuscator>) -> Self {
        murmur_log::infoln!("new wechat");
        Self {
            orig,
            obfs,
            read_buf: tokio::sync::Mutex::new(vec![0; UDP_BUFFER_SIZE]),
            write_buf: tokio::sync::Mutex::new(vec![0; UDP_BUFFER_SIZE]),
            sn: parking_lot::Mutex::new(rand::random::<u32>() & 0xFFFF),
        }
    }
}

#[async_trait]
impl PacketConn for ObfsWeChatUDPConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        loop {
            let mut read_buf = self.read_buf.lock().await;
            let (n, addr) = self.orig.read_from(read_buf.as_mut_slice()).await?;
            if n <= HEADER_LEN {
                drop(read_buf);
                return Ok((0, addr));
            }
            let Some(payload) = read_buf.get(HEADER_LEN..n) else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet larger than the buffer"));
            };
            let new_n = self.obfs.deobfuscate(payload, buf);
            drop(read_buf);
            if new_n > 0 {
                return Ok((new_n, addr));
            }
        }
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let mut write_buf = self.write_buf.lock().await;
        let sn = {
            let mut sn = self.sn.lock();
            let value = *sn;
            *sn += 1;
            value
        };
        let mut head = [0xa1, 0x08, 0, 0, 0, 0, 0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30];
        let Some(sn_field) = head.get_mut(2..6) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "header is 13 bytes"));
        };
        sn_field.copy_from_slice(&sn.to_be_bytes());
        let Some(payload) = write_buf.get_mut(HEADER_LEN..) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "write buffer is too small"));
        };
        let bn = self.obfs.obfuscate(buf, payload);
        let Some(prefix) = write_buf.get_mut(..HEADER_LEN) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "write buffer is too small"));
        };
        prefix.copy_from_slice(&head);
        let Some(packet) = write_buf.get(..HEADER_LEN + bn) else {
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

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.orig.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.orig.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.orig.set_write_deadline(deadline)
    }
}

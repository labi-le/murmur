use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use murmur_common_net::{EnhancePacketConn, WaitReadFrom};
use murmur_common_pool as pool;
use murmur_std_compat::net::{Addr, PacketConn as NetPacketConn};

use super::protocol::Protocol;

/// The protocol wrapper around an `EnhancePacketConn`.
///
/// The `Protocol` value is shared between the packet conn and every call that reads it; the codec
/// half takes `&mut self`, so the value sits behind a lock that is never held across an await.
pub struct PacketConn {
    enhance_packet_conn: Arc<dyn EnhancePacketConn>,
    protocol: Mutex<Box<dyn Protocol>>,
}

impl core::fmt::Debug for PacketConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketConn").finish_non_exhaustive()
    }
}

impl PacketConn {
    pub fn new(enhance_packet_conn: Arc<dyn EnhancePacketConn>, protocol: Box<dyn Protocol>) -> Self {
        Self { enhance_packet_conn, protocol: Mutex::new(protocol) }
    }
}

#[async_trait]
impl NetPacketConn for PacketConn {
    async fn read_from(&self, b: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let (n, addr) = self.enhance_packet_conn.read_from(b).await?;
        let decoded = {
            let (received, _) = b.split_at(n);
            self.protocol.lock().decode_packet(received).map_err(io::Error::other)?
        };
        let (payload, _) = b.split_at_mut(decoded.len());
        payload.copy_from_slice(&decoded);
        Ok((decoded.len(), addr))
    }

    async fn write_to(&self, b: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let mut buf = pool::get_buffer();
        let encoded = self.protocol.lock().encode_packet(&mut buf, b);
        let result = match encoded {
            Ok(()) => self.enhance_packet_conn.write_to(&buf, addr).await,
            Err(err) => Err(io::Error::other(err)),
        };
        pool::put_buffer(buf);
        match result {
            Ok(_) => Ok(b.len()),
            Err(err) => Err(err),
        }
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.enhance_packet_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.enhance_packet_conn.close()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.enhance_packet_conn.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.enhance_packet_conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.enhance_packet_conn.set_write_deadline(deadline)
    }
}

#[async_trait]
impl WaitReadFrom for PacketConn {
    // NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let (data, put, addr, result) = self.enhance_packet_conn.wait_read_from().await;
        if result.is_err() {
            if put.is_some() {
                return (data, put, addr, result);
            }
            let _ = pool::put(data);
            return (Vec::new(), None, addr, result);
        }
        let decoded = {
            let mut protocol = self.protocol.lock();
            protocol.decode_packet(&data)
        };
        match decoded {
            Ok(decoded) => {
                // `decode_packet` returns a fresh Vec; the transferred block can go back now.
                if put.is_none() {
                    let _ = pool::put(data);
                }
                (decoded, put, addr, result)
            }
            Err(err) => {
                if let Some(put) = put {
                    put();
                } else {
                    let _ = pool::put(data);
                }
                (Vec::new(), None, addr, Err(io::Error::other(err)))
            }
        }
    }
}

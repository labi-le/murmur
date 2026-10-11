use std::any::Any;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use murmur_std_compat::net::{Addr, PacketConn};

use super::packet::{
    new_enhance_packet_conn, EnhancePacketConn, ReaderWithUpstream, WaitReadFrom, WithUpstream, WriterWithUpstream,
};

pub(crate) struct ThreadSafePacketConn {
    enhance_packet_conn: Arc<dyn EnhancePacketConn>,
    // Serializes the blocking write across the await.
    pub(crate) access: Mutex<()>,
}

impl ThreadSafePacketConn {
    pub(crate) fn new(enhance_packet_conn: Arc<dyn EnhancePacketConn>) -> Self {
        Self { enhance_packet_conn, access: Mutex::new(()) }
    }
}

#[async_trait]
impl PacketConn for ThreadSafePacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.enhance_packet_conn.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let _access = self.access.lock().await;
        self.enhance_packet_conn.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.enhance_packet_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.enhance_packet_conn.close()
    }
}

#[async_trait]
impl WaitReadFrom for ThreadSafePacketConn {
    // cancel-safe: forwards to the wrapped conn's `wait_read_from` and owns no state of its own, so dropping this future is exactly dropping the inner call.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        self.enhance_packet_conn.wait_read_from().await
    }
}

impl WithUpstream for ThreadSafePacketConn {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(self.enhance_packet_conn.as_ref())
    }
}

impl ReaderWithUpstream for ThreadSafePacketConn {
    fn reader_replaceable(&self) -> bool {
        true
    }
}

impl WriterWithUpstream for ThreadSafePacketConn {
    fn writer_replaceable(&self) -> bool {
        true
    }
}

/// The plain branch; the sing branch cannot be tested on an erased
/// `Arc<dyn PacketConn>` and lives in `thread_sing::new_thread_safe_sing_packet_conn`.
pub fn new_thread_safe_packet_conn(pc: Arc<dyn PacketConn>) -> Arc<dyn EnhancePacketConn> {
    Arc::new(ThreadSafePacketConn::new(new_enhance_packet_conn(pc)))
}

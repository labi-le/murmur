use std::any::Any;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use murmur_std_compat::net::{Addr, PacketConn};

use super::packet::{
    new_enhance_packet_conn, EnhancePacketConn, ReaderWithUpstream, WaitReadFrom, WithUpstream, WriterWithUpstream,
};

pub(crate) struct RefPacketConn {
    pc: Arc<dyn EnhancePacketConn>,
    #[allow(
        dead_code,
        reason = "keeps the source handle alive for RefPacketConn's lifetime; Rust ownership does the runtime.KeepAlive(c.ref) job"
    )]
    ref_: Arc<dyn Any + Send + Sync>,
}

impl RefPacketConn {
    pub(crate) fn new(pc: Arc<dyn EnhancePacketConn>, ref_: Arc<dyn Any + Send + Sync>) -> Self {
        Self { pc, ref_ }
    }
}

#[async_trait]
impl WaitReadFrom for RefPacketConn {
    // cancel-safe: forwards to the wrapped conn's `wait_read_from` and owns no state of its own, so dropping this future is exactly dropping the inner call.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        self.pc.wait_read_from().await
    }
}

#[async_trait]
impl PacketConn for RefPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.pc.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.pc.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.pc.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.pc.close()
    }
}

impl WithUpstream for RefPacketConn {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(self.pc.as_ref())
    }
}

impl ReaderWithUpstream for RefPacketConn {
    fn reader_replaceable(&self) -> bool {
        true
    }
}

impl WriterWithUpstream for RefPacketConn {
    fn writer_replaceable(&self) -> bool {
        true
    }
}

/// The plain branch; the sing branch cannot be tested on an erased
/// `Arc<dyn PacketConn>` and lives in `ref_sing::new_ref_sing_packet_conn`.
pub fn new_ref_packet_conn(pc: Arc<dyn PacketConn>, ref_: Arc<dyn Any + Send + Sync>) -> Arc<dyn EnhancePacketConn> {
    Arc::new(RefPacketConn::new(new_enhance_packet_conn(pc), ref_))
}

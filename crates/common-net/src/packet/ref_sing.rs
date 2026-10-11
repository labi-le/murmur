use std::any::Any;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use murmur_compat::sing_buf::Buffer;
use murmur_sing::metadata::Socksaddr;
use murmur_sing::network::{
    NetPacketReader, NetPacketWriter, PacketConn as SingPacketConnBase, PacketReader, PacketWriter,
};
use murmur_std_compat::net::{Addr, PacketConn};

use super::packet::{EnhancePacketConn, ReaderWithUpstream, WaitReadFrom, WithUpstream, WriterWithUpstream};
use super::packet_sing::{new_enhance_sing_packet_conn, SingPacketConn};
use super::ref_::RefPacketConn;

pub(crate) struct RefSingPacketConn {
    ref_packet_conn: Arc<RefPacketConn>,
    sing_packet_conn: Arc<dyn SingPacketConn>,
}

#[async_trait]
impl PacketReader for RefSingPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        self.sing_packet_conn.read_packet(buffer).await
    }
}

#[async_trait]
impl PacketWriter for RefSingPacketConn {
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        self.sing_packet_conn.write_packet(buffer, destination).await
    }
}

#[async_trait]
impl SingPacketConnBase for RefSingPacketConn {
    async fn close(&self) -> io::Result<()> {
        PacketConn::close(&*self.ref_packet_conn)
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        PacketConn::local_addr(&*self.ref_packet_conn)
    }

    // The `PacketConn` contract has no deadline setters, so the ref wrapper cannot carry the
    // promotion of them and they reach the inner conn directly.
    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        SingPacketConnBase::set_read_deadline(&*self.sing_packet_conn, deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        SingPacketConnBase::set_write_deadline(&*self.sing_packet_conn, deadline)
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        SingPacketConnBase::set_deadline(&*self.sing_packet_conn, deadline)
    }
}

#[async_trait]
impl NetPacketReader for RefSingPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        PacketConn::read_from(&*self.ref_packet_conn, p).await
    }
}

#[async_trait]
impl NetPacketWriter for RefSingPacketConn {
    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        PacketConn::write_to(&*self.ref_packet_conn, p, addr).await
    }
}

#[async_trait]
impl WaitReadFrom for RefSingPacketConn {
    // cancel-safe: forwards to the wrapped conn's `wait_read_from` and owns no state of its own, so dropping this future is exactly dropping the inner call.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        self.ref_packet_conn.wait_read_from().await
    }
}

#[async_trait]
impl PacketConn for RefSingPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.ref_packet_conn.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.ref_packet_conn.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.ref_packet_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.ref_packet_conn.close()
    }
}

impl WithUpstream for RefSingPacketConn {
    fn upstream(&self) -> Option<&dyn Any> {
        self.ref_packet_conn.upstream()
    }
}

impl ReaderWithUpstream for RefSingPacketConn {
    fn reader_replaceable(&self) -> bool {
        self.ref_packet_conn.reader_replaceable()
    }
}

impl WriterWithUpstream for RefSingPacketConn {
    fn writer_replaceable(&self) -> bool {
        self.ref_packet_conn.writer_replaceable()
    }
}

/// The sing branch of the ref packet-conn constructor.
pub fn new_ref_sing_packet_conn(
    pc: Arc<dyn SingPacketConn>,
    ref_: Arc<dyn Any + Send + Sync>,
) -> Arc<dyn EnhancePacketConn> {
    let ref_packet_conn = Arc::new(RefPacketConn::new(new_enhance_sing_packet_conn(Arc::clone(&pc)), ref_));
    Arc::new(RefSingPacketConn { ref_packet_conn, sing_packet_conn: pc })
}

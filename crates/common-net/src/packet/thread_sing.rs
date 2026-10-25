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
use super::thread::ThreadSafePacketConn;

pub(crate) struct ThreadSafeSingPacketConn {
    thread_safe_packet_conn: Arc<ThreadSafePacketConn>,
    sing_packet_conn: Arc<dyn SingPacketConn>,
}

#[async_trait]
impl PacketWriter for ThreadSafeSingPacketConn {
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        let _access = self.thread_safe_packet_conn.access.lock().await;
        self.sing_packet_conn.write_packet(buffer, destination).await
    }
}

#[async_trait]
impl PacketReader for ThreadSafeSingPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        self.sing_packet_conn.read_packet(buffer).await
    }
}

#[async_trait]
impl SingPacketConnBase for ThreadSafeSingPacketConn {
    async fn close(&self) -> io::Result<()> {
        PacketConn::close(&*self.thread_safe_packet_conn)
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        PacketConn::local_addr(&*self.thread_safe_packet_conn)
    }

    // The `PacketConn` contract has no deadline setters, so the thread-safe wrapper cannot carry
    // the promotion of them and they reach the inner conn directly.
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
impl NetPacketReader for ThreadSafeSingPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        PacketConn::read_from(&*self.thread_safe_packet_conn, p).await
    }
}

#[async_trait]
impl NetPacketWriter for ThreadSafeSingPacketConn {
    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        PacketConn::write_to(&*self.thread_safe_packet_conn, p, addr).await
    }
}

#[async_trait]
impl WaitReadFrom for ThreadSafeSingPacketConn {
    // NOT cancel-safe: reaches `ThreadSafePacketConn`'s `dyn EnhancePacketConn`, which can be the framing-consuming `EnhancePacketConnImpl`; a dropped call loses that packet.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        self.thread_safe_packet_conn.wait_read_from().await
    }
}

#[async_trait]
impl PacketConn for ThreadSafeSingPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.thread_safe_packet_conn.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.thread_safe_packet_conn.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.thread_safe_packet_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.thread_safe_packet_conn.close()
    }
}

impl WithUpstream for ThreadSafeSingPacketConn {
    fn upstream(&self) -> Option<&dyn Any> {
        self.thread_safe_packet_conn.upstream()
    }
}

impl ReaderWithUpstream for ThreadSafeSingPacketConn {
    fn reader_replaceable(&self) -> bool {
        self.thread_safe_packet_conn.reader_replaceable()
    }
}

impl WriterWithUpstream for ThreadSafeSingPacketConn {
    fn writer_replaceable(&self) -> bool {
        self.thread_safe_packet_conn.writer_replaceable()
    }
}

/// The sing branch of the thread-safe packet-conn constructor.
pub fn new_thread_safe_sing_packet_conn(pc: Arc<dyn SingPacketConn>) -> Arc<dyn EnhancePacketConn> {
    let thread_safe_packet_conn = Arc::new(ThreadSafePacketConn::new(new_enhance_sing_packet_conn(Arc::clone(&pc))));
    Arc::new(ThreadSafeSingPacketConn { thread_safe_packet_conn, sing_packet_conn: pc })
}

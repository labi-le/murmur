use std::any::Any;
use std::fmt;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::time::Instant;

use crate::packet::packet::{
    EnhancePacketConn as EnhancePacketConnTrait, ReaderWithUpstream, WaitReadFrom, WithUpstream, WriterWithUpstream,
};
use crate::packet::packet_sing::{
    EnhanceSingPacketConn as EnhanceSingPacketConnTrait, SingPacketConn as SingPacketConnTrait,
};
use murmur_compat::sing_buf::{new_packet, Buffer};
use murmur_sing::metadata::Socksaddr;
use murmur_sing::network::{
    NetPacketReader, NetPacketWriter, PacketConn as SingPacketConnBase, PacketReadWaiter, PacketReader, PacketWriter,
    ReadWaitOptions, ReadWaitable,
};
use murmur_std_compat::net::{Addr, PacketConn};

use super::packet::NetPacketConn;
use super::packet_enhance::EnhancePacketConn;

/// The sing packet-conn union, wrapping a `NetPacketConn` and a `SingPacketConnTrait`.
pub struct SingPacketConn {
    pub(crate) net_packet_conn: Arc<NetPacketConn>,
    pub(crate) sing_packet_conn: Arc<dyn SingPacketConnTrait>,
}

impl fmt::Debug for SingPacketConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingPacketConn").finish_non_exhaustive()
    }
}

pub fn new_sing_packet_conn(pc: Arc<dyn SingPacketConnTrait>) -> Arc<dyn SingPacketConnTrait> {
    let sing_conn: Arc<dyn SingPacketConnTrait> = Arc::clone(&pc);
    let packet_conn: Arc<dyn PacketConn> = sing_conn;
    let net_packet_conn = Arc::new(NetPacketConn::new(packet_conn));
    Arc::new(SingPacketConn { net_packet_conn, sing_packet_conn: pc })
}

/// The enhanced sing packet-conn union, wrapping an `EnhancePacketConn` and a `SingPacketConnTrait`.
pub struct EnhanceSingPacketConn {
    pub(crate) enhance_packet_conn: EnhancePacketConn,
    pub(crate) sing_packet_conn: Arc<dyn SingPacketConnTrait>,
}

impl fmt::Debug for EnhanceSingPacketConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnhanceSingPacketConn").finish_non_exhaustive()
    }
}

pub fn new_enhance_sing_packet_conn(pc: Arc<dyn EnhanceSingPacketConnTrait>) -> Arc<dyn EnhanceSingPacketConnTrait> {
    let sing_conn: Arc<dyn EnhanceSingPacketConnTrait> = Arc::clone(&pc);
    let packet_conn: Arc<dyn PacketConn> = sing_conn;
    let net_packet_conn = Arc::new(NetPacketConn::new(packet_conn));
    let enhance_conn: Arc<dyn EnhanceSingPacketConnTrait> = Arc::clone(&pc);
    let enhance_packet_conn_trait: Arc<dyn EnhancePacketConnTrait> = enhance_conn;
    let sing_packet_conn: Arc<dyn SingPacketConnTrait> = pc;
    let enhance_packet_conn = EnhancePacketConn::new(Arc::clone(&net_packet_conn), enhance_packet_conn_trait);
    Arc::new(EnhanceSingPacketConn { enhance_packet_conn, sing_packet_conn })
}

#[async_trait]
impl PacketConn for SingPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.net_packet_conn.read_from(p).await
    }

    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.net_packet_conn.write_to(p, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.net_packet_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.net_packet_conn.close()
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.net_packet_conn.set_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.net_packet_conn.set_write_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.net_packet_conn.set_read_deadline(deadline)
    }
}

#[async_trait]
impl SingPacketConnBase for SingPacketConn {
    async fn close(&self) -> io::Result<()> {
        self.net_packet_conn.close()
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.net_packet_conn.local_addr()
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.net_packet_conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.net_packet_conn.set_write_deadline(deadline)
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.net_packet_conn.set_deadline(deadline)
    }
}

#[async_trait]
impl NetPacketReader for SingPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.net_packet_conn.read_from(p).await
    }
}

#[async_trait]
impl NetPacketWriter for SingPacketConn {
    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.net_packet_conn.write_to(p, addr).await
    }
}

#[async_trait]
impl PacketReader for SingPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        self.net_packet_conn.with_read_deadline(self.sing_packet_conn.read_packet(buffer)).await
    }
}

#[async_trait]
impl PacketWriter for SingPacketConn {
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        self.sing_packet_conn.write_packet(buffer, destination).await
    }
}

impl WithUpstream for SingPacketConn {
    fn upstream(&self) -> Option<&dyn Any> {
        self.net_packet_conn.upstream()
    }
}

impl ReaderWithUpstream for SingPacketConn {
    fn reader_replaceable(&self) -> bool {
        self.net_packet_conn.reader_replaceable()
    }
}

impl WriterWithUpstream for SingPacketConn {
    fn writer_replaceable(&self) -> bool {
        self.net_packet_conn.writer_replaceable()
    }
}

#[async_trait]
impl PacketConn for EnhanceSingPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.enhance_packet_conn.read_from(p).await
    }

    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.enhance_packet_conn.write_to(p, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.enhance_packet_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.enhance_packet_conn.close()
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.enhance_packet_conn.set_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.enhance_packet_conn.set_write_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.enhance_packet_conn.set_read_deadline(deadline)
    }
}

#[async_trait]
impl WaitReadFrom for EnhanceSingPacketConn {
    // NOT cancel-safe: forwards to the wrapped `EnhancePacketConn`, whose read latches `in_read` and races the deadline token in a `select!`, so a dropped call abandons the caller's read.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        self.enhance_packet_conn.wait_read_from().await
    }
}

#[async_trait]
impl SingPacketConnBase for EnhanceSingPacketConn {
    async fn close(&self) -> io::Result<()> {
        self.enhance_packet_conn.close()
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.enhance_packet_conn.local_addr()
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.enhance_packet_conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.enhance_packet_conn.set_write_deadline(deadline)
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.enhance_packet_conn.set_deadline(deadline)
    }
}

#[async_trait]
impl NetPacketReader for EnhanceSingPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.enhance_packet_conn.read_from(p).await
    }
}

#[async_trait]
impl NetPacketWriter for EnhanceSingPacketConn {
    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.enhance_packet_conn.write_to(p, addr).await
    }
}

#[async_trait]
impl PacketReader for EnhanceSingPacketConn {
    /// Reads a packet through the embedded enhance layer.
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        self.enhance_packet_conn.net_packet_conn.with_read_deadline(self.sing_packet_conn.read_packet(buffer)).await
    }
}

#[async_trait]
impl PacketWriter for EnhanceSingPacketConn {
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        self.sing_packet_conn.write_packet(buffer, destination).await
    }
}

impl WithUpstream for EnhanceSingPacketConn {
    fn upstream(&self) -> Option<&dyn Any> {
        self.enhance_packet_conn.upstream()
    }
}

impl ReaderWithUpstream for EnhanceSingPacketConn {
    fn reader_replaceable(&self) -> bool {
        self.enhance_packet_conn.reader_replaceable()
    }
}

impl WriterWithUpstream for EnhanceSingPacketConn {
    fn writer_replaceable(&self) -> bool {
        self.enhance_packet_conn.writer_replaceable()
    }
}

/// Wraps a sing packet read waiter.
///
/// The `SingPacketConn` blanket impl already owns the read-waiter factory, so this wrapper cannot
/// be installed and the direct read path is used.
pub struct SingPacketReadWaiter {
    net_packet_conn: Arc<NetPacketConn>,
    packet_read_waiter: Box<dyn PacketReadWaiter + Send + Sync>,
}

impl fmt::Debug for SingPacketReadWaiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingPacketReadWaiter").finish_non_exhaustive()
    }
}

impl ReadWaitable for SingPacketReadWaiter {
    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        self.packet_read_waiter.initialize_read_waiter(options)
    }
}

#[async_trait]
impl PacketReadWaiter for SingPacketReadWaiter {
    async fn wait_read_packet(&self) -> io::Result<(Buffer, Socksaddr)> {
        self.net_packet_conn.with_read_deadline(self.packet_read_waiter.wait_read_packet()).await
    }
}

impl WithUpstream for SingPacketReadWaiter {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(&self.packet_read_waiter)
    }
}

/// A copy waiter that reads a packet into a fresh buffer.
pub struct CopyPacketReadWaiter {
    reader: Arc<dyn SingPacketConnTrait>,
}

impl fmt::Debug for CopyPacketReadWaiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CopyPacketReadWaiter").finish_non_exhaustive()
    }
}

impl ReadWaitable for CopyPacketReadWaiter {
    fn initialize_read_waiter(&self, _options: ReadWaitOptions) -> bool {
        true
    }
}

#[async_trait]
impl PacketReadWaiter for CopyPacketReadWaiter {
    async fn wait_read_packet(&self) -> io::Result<(Buffer, Socksaddr)> {
        let mut buffer = new_packet();
        let destination = self.reader.read_packet(&mut buffer).await?;
        Ok((buffer, destination))
    }
}

/// Builds a read waiter, unreachable through the blanket impl.
pub fn create_read_waiter(
    net_packet_conn: Arc<NetPacketConn>,
    sing_packet_conn: Arc<dyn SingPacketConnTrait>,
) -> Box<dyn PacketReadWaiter + Send + Sync> {
    Box::new(SingPacketReadWaiter {
        net_packet_conn,
        packet_read_waiter: Box::new(CopyPacketReadWaiter { reader: sing_packet_conn }),
    })
}

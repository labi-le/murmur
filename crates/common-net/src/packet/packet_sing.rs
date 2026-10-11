use std::any::Any;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;

use murmur_compat::sing_buf::{new_size, Buffer, UDP_BUFFER_SIZE};
use murmur_sing::metadata::Socksaddr;
use murmur_sing::network::{
    NetPacketReader, NetPacketWriter, PacketConn as SingPacketConnBase, PacketReadWaiter, PacketReader, PacketWriter,
    ReadWaitOptions,
};
use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};

use super::packet::{EnhancePacketConn, ReaderWithUpstream, WaitReadFrom, WithUpstream, WriterWithUpstream};

/// The packet-conn union: every capability a packet conn needs, gathered into one trait.
///
/// The union is split over `murmur_std_compat::net::PacketConn`
/// (`read_packet`/`write_packet`/`close`/deadlines), `NetPacketReader` (`read_from`) and
/// `NetPacketWriter` (`write_to`). Because those traits name `read_from`/`write_to`/`close`/
/// `local_addr` on the same value, calls through a `dyn SingPacketConn` need the trait named, as
/// `NetPacketReader::read_from` does.
pub trait SingPacketConn: SingPacketConnBase + NetPacketReader + NetPacketWriter + PacketConn + Send + Sync {
    /// The read-waiter factory the buffered reader requests.
    ///
    /// A `WaitReadFrom` wrapper cannot run a type assertion on an erased conn, so the conn reports
    /// its waiter here instead. `None` is the "no waiter" case, which reads the packet straight
    /// into a buffer.
    fn create_read_waiter(&self) -> Option<Box<dyn PacketReadWaiter + Send + Sync>> {
        None
    }
}

// Compatibility bridge: every concrete sing packet conn already implements all three halves.
impl<T: SingPacketConnBase + NetPacketReader + NetPacketWriter + PacketConn> SingPacketConn for T {}
pub trait EnhanceSingPacketConn: SingPacketConn + EnhancePacketConn + Send + Sync {}

// Compatibility bridge: the trait is the intersection of two traits it adds nothing to.
impl<T: SingPacketConn + EnhancePacketConn> EnhanceSingPacketConn for T {}

/// Renders a `Socksaddr` as the sockaddr view the mirror does not carry.
///
/// The mirror's `IpAddr` has no zone, so the copied zone is always empty, and its `Option`
/// substitutes the unspecified address when the IP is null.
#[must_use]
pub fn udp_addr(dest: &Socksaddr) -> UdpAddr {
    UdpAddr::new(dest.addr.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), dest.port)
}

fn new_packet_buffer(options: &ReadWaitOptions) -> Buffer {
    new_buffer(options, UDP_BUFFER_SIZE, true)
}

fn new_buffer(options: &ReadWaitOptions, default_buffer_size: i32, reserve: bool) -> Buffer {
    let buffer_size = if options.mtu > 0 {
        // An MTU whose headroomed size does not fit the allocator's `i32` length keeps the default
        // packet buffer instead of wrapping to an arbitrary one.
        i32::try_from(options.mtu + options.front_headroom + options.rear_headroom).unwrap_or(default_buffer_size)
    } else {
        default_buffer_size
    };
    let mut buffer = new_size(buffer_size);
    if options.front_headroom > 0 {
        buffer.resize(options.front_headroom, 0);
    }
    if options.rear_headroom > 0 && reserve {
        buffer.reserve(options.rear_headroom);
    }
    buffer
}

fn post_return(options: &ReadWaitOptions, buffer: &mut Buffer) {
    if options.rear_headroom > 0 {
        buffer.over_cap(options.rear_headroom);
    }
}

pub(crate) struct EnhanceSingPacketConnImpl {
    sing_packet_conn: Arc<dyn SingPacketConn>,
    packet_read_waiter: Option<Box<dyn PacketReadWaiter + Send + Sync>>,
}

impl EnhanceSingPacketConnImpl {
    pub(crate) fn new(sing_packet_conn: Arc<dyn SingPacketConn>) -> Self {
        let packet_read_waiter = sing_packet_conn.create_read_waiter();
        Self { sing_packet_conn, packet_read_waiter }
    }
}

#[async_trait]
impl WaitReadFrom for EnhanceSingPacketConnImpl {
    // NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let read_wait_options = ReadWaitOptions::default();
        let mut buffer: Option<Buffer> = None;
        let mut destination = Socksaddr::default();
        let mut err: Option<io::Error> = None;
        if let Some(packet_read_waiter) = &self.packet_read_waiter {
            packet_read_waiter.initialize_read_waiter(read_wait_options);
            match packet_read_waiter.wait_read_packet().await {
                Ok((read_buffer, read_destination)) => {
                    buffer = Some(read_buffer);
                    destination = read_destination;
                }
                Err(read_err) => err = Some(read_err),
            }
        } else {
            let mut read_buffer = new_packet_buffer(&read_wait_options);
            let read_packet = self.sing_packet_conn.read_packet(&mut read_buffer).await;
            post_return(&read_wait_options, &mut read_buffer);
            buffer = Some(read_buffer);
            match read_packet {
                Ok(read_destination) => destination = read_destination,
                Err(read_err) => err = Some(read_err),
            }
        }
        let addr: Box<dyn Addr> =
            if destination.is_fqdn() { Box::new(destination) } else { Box::new(udp_addr(&destination)) };
        if let Some(err) = err {
            if let Some(mut buffer) = buffer {
                buffer.release();
            }
            return (Vec::new(), None, Some(addr), Err(err));
        }
        let Some(mut buffer) = buffer else {
            return (Vec::new(), None, Some(addr), Ok(()));
        };
        if buffer.is_empty() {
            buffer.release();
            return (Vec::new(), None, Some(addr), Ok(()));
        }
        let data = buffer.bytes().to_vec();
        let put: Box<dyn FnOnce() + Send> = Box::new(move || buffer.release());
        (data, Some(put), Some(addr), Ok(()))
    }
}

#[async_trait]
impl PacketConn for EnhanceSingPacketConnImpl {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        NetPacketReader::read_from(&*self.sing_packet_conn, buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        NetPacketWriter::write_to(&*self.sing_packet_conn, buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        PacketConn::local_addr(&*self.sing_packet_conn)
    }

    fn close(&self) -> io::Result<()> {
        PacketConn::close(&*self.sing_packet_conn)
    }
}

#[async_trait]
impl PacketReader for EnhanceSingPacketConnImpl {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        self.sing_packet_conn.read_packet(buffer).await
    }
}

#[async_trait]
impl PacketWriter for EnhanceSingPacketConnImpl {
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        self.sing_packet_conn.write_packet(buffer, destination).await
    }
}

#[async_trait]
impl SingPacketConnBase for EnhanceSingPacketConnImpl {
    async fn close(&self) -> io::Result<()> {
        SingPacketConnBase::close(&*self.sing_packet_conn).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        SingPacketConnBase::local_addr(&*self.sing_packet_conn)
    }

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
impl NetPacketReader for EnhanceSingPacketConnImpl {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        NetPacketReader::read_from(&*self.sing_packet_conn, p).await
    }
}

#[async_trait]
impl NetPacketWriter for EnhanceSingPacketConnImpl {
    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        NetPacketWriter::write_to(&*self.sing_packet_conn, p, addr).await
    }
}

impl WithUpstream for EnhanceSingPacketConnImpl {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(self.sing_packet_conn.as_ref())
    }
}

impl ReaderWithUpstream for EnhanceSingPacketConnImpl {
    fn reader_replaceable(&self) -> bool {
        true
    }
}

impl WriterWithUpstream for EnhanceSingPacketConnImpl {
    fn writer_replaceable(&self) -> bool {
        true
    }
}
pub(crate) fn new_enhance_sing_packet_conn(conn: Arc<dyn SingPacketConn>) -> Arc<dyn EnhancePacketConn> {
    Arc::new(EnhanceSingPacketConnImpl::new(conn))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An MTU whose headroomed size exceeds the allocator's `i32` length must keep the default
    /// packet buffer rather than reserve, and touch, an `i32::MAX`-sized (2 GiB) block.
    #[test]
    fn an_oversized_mtu_falls_back_to_the_default_packet_buffer() {
        let options = ReadWaitOptions { front_headroom: 0, rear_headroom: 0, mtu: usize::MAX };
        let buffer = new_packet_buffer(&options);
        assert_eq!(UDP_BUFFER_SIZE as usize, buffer.raw_cap());
    }
}

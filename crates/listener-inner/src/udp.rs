//! Inner-tunnel UDP: the `PacketConn`/`UDPPacket` pair that carries datagrams into the tunnel.
//!
//! DEVIATION: `data(&self) -> &[u8]` (both `constant::adapters::UDPPacket` and this file's own
//! `Drop`) cannot null out its backing storage through a shared reference, so a payload's byte
//! length is tracked in a separate atomic counter that
//! `Drop` zeroes instead; the original allocation is returned to the pool once by `InnerUdpPacket`'s
//! `std::ops::Drop` impl, which runs when the packet itself is deallocated.
//! DEVIATION: a short-buffer error cannot be returned alongside the partial byte
//! count and source address, so a short destination buffer
//! returns that error alone (the bytes are still copied into the caller's buffer beforehand).
//! DEVIATION: `Close`'s pool drain uses a non-blocking `try_lock` on the receiver instead of
//! the lock-free channel drain, so a concurrent in-flight read may cause the drain to be
//! skipped for that call.

use portable_atomic::AtomicU64;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{mpsc, Mutex as TokioMutex};

use murmur_adapter_inbound as inbound;
use murmur_common_net::deadline::conn::err_deadline_exceeded;
use murmur_common_net::deadline::pipe::{make_pipe_deadline, CloseSignal, PipeDeadline};
use murmur_common_pool as pool;
use murmur_constant::adapters::{UDPPacket, WriteBack};
use murmur_constant::dns::DNSMode;
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_constant::version::PROJECT_NAME;
use murmur_std_compat::net::{deadline_time, Addr, PacketConn};
use murmur_transport::socks5::socks5;

const INNER_UDP_QUEUE_SIZE: usize = 128;

static INNER_UDP_CONN_ID: AtomicU64 = AtomicU64::new(0);

fn err_closed() -> io::Error {
    io::Error::other("use of closed network connection")
}

fn err_short_buffer() -> io::Error {
    io::Error::other("short buffer")
}

#[derive(Debug, Clone)]
struct InnerUdpAddr {
    network: String,
    address: String,
}

impl Addr for InnerUdpAddr {
    fn network(&self) -> &str {
        &self.network
    }

    fn string(&self) -> String {
        self.address.clone()
    }
}

struct InnerUdpDatagram {
    data: Vec<u8>,
    addr: Box<dyn Addr>,
}

struct Inner {
    tunnel: Arc<dyn Tunnel>,
    proxy: String,
    /// The synthetic inner-UDP address; encodes `id` into a
    /// loopback `SocketAddr` so `UDPPacket::local_addr` stays a concrete socket address (this
    /// trait's return type cannot be a non-address string).
    /// Only used where an address genuinely needs to behave like a socket address (the
    /// read-loop's default write-back destination, `PacketConn::local_addr`); the NAT-table key
    /// and the packet's metadata source use `nat_key`/id below instead, matching the real
    /// behaviour of a string-form address whose value never
    /// parses back into a socket address.
    local_addr: std::net::SocketAddr,
    id: u64,
    read_tx: mpsc::Sender<InnerUdpDatagram>,
    read_rx: TokioMutex<mpsc::Receiver<InnerUdpDatagram>>,
    done: Arc<CloseSignal>,
    close_once: std::sync::Once,
    closed: Mutex<bool>,
    read_deadline: PipeDeadline,
    write_deadline: PipeDeadline,
}

impl Inner {
    fn write_back(&self, data: &[u8], addr: Option<std::net::SocketAddr>) -> Result<usize> {
        let mut payload = pool::get(data.len());
        payload.copy_from_slice(data);

        let closed = *self.closed.lock();
        if closed {
            let _ = pool::put(payload);
            return Err(err_closed().into());
        }

        let addr: Box<dyn Addr> =
            Box::new(murmur_common_net::io::udp_addr_from_socket_addr(addr.unwrap_or(self.local_addr)));
        let datagram = InnerUdpDatagram { data: payload, addr };
        if let Err(err) = self.read_tx.try_send(datagram) {
            let _ = pool::put(err.into_inner().data);
        }
        Ok(data.len())
    }
}

pub struct InnerUdpPacketConn(Arc<Inner>);

impl core::fmt::Debug for InnerUdpPacketConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InnerUdpPacketConn").field("id", &self.0.id).finish_non_exhaustive()
    }
}

pub fn handle_udp(
    tunnel: Option<Arc<dyn Tunnel>>,
    network: &str,
    address: &str,
    proxy: &str,
) -> Result<(Box<dyn PacketConn>, Box<dyn Addr>)> {
    let Some(tunnel) = tunnel else {
        return Err(anyhow!("tunnel uninitialized"));
    };
    match network {
        "udp" | "udp4" | "udp6" => {}
        _ => return Err(anyhow!("unsupported network {network}")),
    }
    if socks5::parse_addr(address).is_none() {
        return Err(anyhow!("invalid target address {address}"));
    }

    let id = INNER_UDP_CONN_ID.fetch_add(1, Ordering::SeqCst) + 1;
    let port = u16::try_from(id % 65535 + 1).map_err(|_| anyhow!("invalid inner udp conn id {id}"))?;
    let (read_tx, read_rx) = mpsc::channel(INNER_UDP_QUEUE_SIZE);
    let inner = Arc::new(Inner {
        tunnel,
        proxy: proxy.to_owned(),
        local_addr: std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port),
        id,
        read_tx,
        read_rx: TokioMutex::new(read_rx),
        done: Arc::new(CloseSignal::new()),
        close_once: std::sync::Once::new(),
        closed: Mutex::new(false),
        read_deadline: make_pipe_deadline(),
        write_deadline: make_pipe_deadline(),
    });

    Ok((
        Box::new(InnerUdpPacketConn(inner)),
        Box::new(InnerUdpAddr { network: network.to_owned(), address: address.to_owned() }),
    ))
}

#[async_trait]
impl PacketConn for InnerUdpPacketConn {
    // cancel-safe: the only awaits are the receiver lock and a cancel-safe `mpsc::Receiver::recv`;
    // once the receive returns, the copy and the pool return run to completion.
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut rx = self.0.read_rx.lock().await;
        let read_deadline = self.0.read_deadline.wait();
        let result = tokio::select! {
            () = self.0.done.wait() => Err(err_closed()),
            () = read_deadline.wait() => Err(err_deadline_exceeded()),
            datagram = rx.recv() => {
                match datagram {
                    Some(datagram) => {
                        let total = datagram.data.len();
                        let n = total.min(buf.len());
                        let (dst, _) = buf.split_at_mut(n);
                        let (src, _) = datagram.data.split_at(n);
                        dst.copy_from_slice(src);
                        let addr = datagram.addr;
                        let _ = pool::put(datagram.data);
                        if n < total {
                            Err(err_short_buffer())
                        } else {
                            Ok((n, addr))
                        }
                    }
                    None => Err(err_closed()),
                }
            }
        };
        drop(rx);
        result
    }

    // cancel-safe: no await points; the send path completes on the first poll.
    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        if self.0.done.is_closed() {
            return Err(err_closed());
        }
        if self.0.write_deadline.wait().is_closed() {
            return Err(err_deadline_exceeded());
        }

        let Some(target) = socks5::parse_addr(&addr.string()) else {
            return Err(io::Error::other(format!("invalid target address {}", addr.string())));
        };
        let mut data = pool::get(buf.len());
        data.copy_from_slice(buf);
        let inner = Arc::clone(&self.0);
        let packet_len = data.len();
        let udp_packet = Arc::new(InnerUdpPacket { conn: inner, data, len: AtomicUsize::new(packet_len) });
        let (packet, mut metadata) = inbound::packet::new_packet(&target, udp_packet, Type::INNER, &[]);
        // Packet construction also sets the source address from the packet's `local_addr()`, but
        // the synthetic inner-UDP address never parses as a socket address, so that step leaves
        // the source IP/port untouched. This crate's `local_addr()` must return a concrete
        // `SocketAddr` (see the `Inner::local_addr` doc), so `with_src_addr` always "succeeds"
        // here; undo it instead of
        // reporting a fabricated loopback source to SRC-IP/SRC-PORT rules and sniffers.
        metadata.src_ip = None;
        metadata.src_port = 0;
        metadata.dns_mode = DNSMode::DNS_NORMAL;
        PROJECT_NAME.clone_into(&mut metadata.process);
        metadata.special_proxy.clone_from(&self.0.proxy);
        self.0.tunnel.handle_udp_packet(packet, metadata);
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(murmur_common_net::io::udp_addr_from_socket_addr(self.0.local_addr)))
    }

    fn close(&self) -> io::Result<()> {
        self.0.close_once.call_once(|| {
            let mut closed = self.0.closed.lock();
            *closed = true;
            drop(closed);
            self.0.done.close();
            if let Ok(mut rx) = self.0.read_rx.try_lock() {
                while let Ok(datagram) = rx.try_recv() {
                    let _ = pool::put(datagram.data);
                }
            }
        });
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let t = deadline_time(deadline);
        self.0.read_deadline.set(t);
        self.0.write_deadline.set(t);
        Ok(())
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.read_deadline.set(deadline_time(deadline));
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.write_deadline.set(deadline_time(deadline));
        Ok(())
    }
}

pub struct InnerUdpPacket {
    conn: Arc<Inner>,
    data: Vec<u8>,
    len: AtomicUsize,
}

/// The payload is left out: the bytes are arbitrary user data, not debug material.
impl core::fmt::Debug for InnerUdpPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InnerUdpPacket")
            .field("conn_id", &self.conn.id)
            .field("len", &self.len.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Drop for InnerUdpPacket {
    fn drop(&mut self) {
        let _ = pool::put(std::mem::take(&mut self.data));
    }
}

#[async_trait]
impl WriteBack for InnerUdpPacket {
    // cancel-safe: no await points; the write-back completes on the first poll.
    async fn write_back(&self, b: &[u8], addr: Option<std::net::SocketAddr>) -> Result<usize> {
        self.conn.write_back(b, addr)
    }
}

impl UDPPacket for InnerUdpPacket {
    fn data(&self) -> &[u8] {
        let visible = self.len.load(Ordering::Acquire).min(self.data.len());
        let (visible_data, _) = self.data.split_at(visible);
        visible_data
    }

    fn drop_(&self) {
        self.len.store(0, Ordering::Release);
    }

    fn local_addr(&self) -> std::net::SocketAddr {
        self.conn.local_addr
    }

    fn in_addr(&self) -> Option<std::net::SocketAddr> {
        Some(self.conn.local_addr)
    }

    fn nat_key(&self) -> String {
        format!("inner-udp-{}", self.conn.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use murmur_constant::adapters::NatTable;
    use murmur_constant::metadata::Metadata;

    struct NoopTunnel;

    #[async_trait]
    impl Tunnel for NoopTunnel {
        async fn handle_tcp_conn(&self, _conn: Box<dyn murmur_common_net::io::Stream>, _metadata: Metadata) {
            unimplemented!("not exercised by this test")
        }

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {
            unimplemented!("not exercised by this test")
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            unimplemented!("not exercised by this test")
        }
    }

    fn test_packet_with_id(payload: &[u8], id: u64) -> InnerUdpPacket {
        let (read_tx, read_rx) = mpsc::channel(INNER_UDP_QUEUE_SIZE);
        let conn = Arc::new(Inner {
            tunnel: Arc::new(NoopTunnel),
            proxy: String::new(),
            local_addr: std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1),
            id,
            read_tx,
            read_rx: TokioMutex::new(read_rx),
            done: Arc::new(CloseSignal::new()),
            close_once: std::sync::Once::new(),
            closed: Mutex::new(false),
            read_deadline: make_pipe_deadline(),
            write_deadline: make_pipe_deadline(),
        });
        let mut data = pool::get(payload.len());
        data.copy_from_slice(payload);
        InnerUdpPacket { conn, len: AtomicUsize::new(data.len()), data }
    }

    fn test_packet(payload: &[u8]) -> InnerUdpPacket {
        test_packet_with_id(payload, 1)
    }

    #[test]
    fn drop_zeroes_len_without_touching_the_backing_allocation() {
        let payload = vec![0xABu8; 200];
        let packet = test_packet(&payload);

        assert_eq!(packet.data(), payload.as_slice());
        UDPPacket::drop_(&packet);
        assert!(packet.data().is_empty(), "drop_ must zero the visible length, matching the `p.data = nil`");
        assert_eq!(packet.data.len(), payload.len(), "drop_ must not clone or otherwise touch the backing Vec");
    }

    #[test]
    fn real_drop_recycles_the_backing_allocation_exactly_once() {
        // Regression test for the no-op `self.data.clone()` that used to run inside `drop_`: a
        // payload length that is not itself a power of two (200 here, unlike its pool block's
        // 256-byte capacity) made the old code clone a short Vec, so `pool::put` rejected the
        // clone on the allocator's exact-capacity check and the real block was only ever freed,
        // never reused.
        //
        // Reuse is observed through the free list rather than a sentinel byte: `put` wipes the
        // whole block before it is parked, so no caller-visible byte can survive to prove the
        // block came back.
        let payload = vec![0xCDu8; 200];
        let packet = test_packet(&payload);
        assert_eq!(256, packet.data.capacity(), "pool::get(200) rounds up to a 256-byte block");
        assert_eq!(0, pool::DEFAULT_ALLOCATOR.free_len(256), "the class starts empty");

        UDPPacket::drop_(&packet);
        drop(packet);

        assert_eq!(1, pool::DEFAULT_ALLOCATOR.free_len(256), "drop_ must return the real block to the pool");

        let recycled = pool::get(200);
        assert_eq!(256, recycled.capacity(), "the pooled block is handed back out again");
        assert_eq!(0, pool::DEFAULT_ALLOCATOR.free_len(256));
    }

    /// Regression: `INNER_UDP_CONN_ID` wraps mod 65535 into `local_addr`'s port, so two inner
    /// UDP conns (or one inner conn and a real client) can share the exact same fabricated
    /// `127.0.0.1:N` — that used to be the NAT-table key too, merging their sessions. `nat_key`
    /// must stay unique per conn `id` even when `local_addr` collides.
    #[test]
    fn nat_key_stays_unique_even_when_local_addr_collides() {
        let one = test_packet_with_id(b"one", 65536);
        let two = test_packet_with_id(b"two", 131_071);
        assert_eq!(
            one.local_addr(),
            two.local_addr(),
            "test setup: ids 65536 and 131071 must collide on the same fabricated loopback port \
             (both are 65535*n + 1), reproducing the real bug"
        );
        assert_ne!(
            one.nat_key(),
            two.nat_key(),
            "two inner UDP conns sharing a fabricated local_addr must not share a NAT key"
        );
        assert_eq!(one.nat_key(), "inner-udp-65536");
        assert_eq!(two.nat_key(), "inner-udp-131071");
    }
}

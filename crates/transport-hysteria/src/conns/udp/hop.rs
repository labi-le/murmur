use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::obfs::obfs::Obfuscator;
use crate::utils::misc::{split_host_port, PacketDialer};
use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};

use super::obfs::{ObfsUDPConn, UDP_BUFFER_SIZE};

const PACKET_QUEUE_SIZE: usize = 1024;

/// A pool may drop its entries at any collection, so the count kept is capped.
const MAX_POOLED_BUFFERS: usize = 64;

fn err_net_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection")
}

fn random_index(len: usize) -> usize {
    rand::rng().random_range(0..len)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct UdpHopAddr(String);

impl Addr for UdpHopAddr {
    fn network(&self) -> &'static str {
        "udp-hop"
    }

    fn string(&self) -> String {
        self.0.clone()
    }
}

struct UdpPacket {
    buf: Vec<u8>,
    n: usize,
}

/// A pool of receive buffers.
struct BufPool {
    buffers: Mutex<Vec<Vec<u8>>>,
}

impl BufPool {
    const fn new() -> Self {
        Self { buffers: Mutex::new(Vec::new()) }
    }

    fn get(&self) -> Vec<u8> {
        self.buffers.lock().pop().unwrap_or_else(|| vec![0; UDP_BUFFER_SIZE])
    }

    fn put(&self, buf: Vec<u8>) {
        let mut buffers = self.buffers.lock();
        if buffers.len() < MAX_POOLED_BUFFERS {
            buffers.push(buf);
        }
    }
}

/// State guarded by the hop conn's lock.
struct HopState {
    prev_conn: Option<Arc<dyn PacketConn>>,
    current_conn: Arc<dyn PacketConn>,
    addr_index: usize,
    read_buffer_size: usize,
    write_buffer_size: usize,
    closed: bool,
    server_addrs: Vec<Arc<UdpAddr>>,
}

/// A hop conn shared with its two tasks through the `Arc`.
struct HopConn {
    server_addr: UdpHopAddr,
    hop_interval: Duration,
    obfs: Option<Arc<dyn Obfuscator>>,
    state: RwLock<HopState>,
    recv_queue: mpsc::Sender<UdpPacket>,
    recv_queue_rx: tokio::sync::Mutex<mpsc::Receiver<UdpPacket>>,
    close_chan: CancellationToken,
    buf_pool: BufPool,
}

impl std::fmt::Debug for HopConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopConn")
            .field("server_addr", &self.server_addr)
            .field("hop_interval", &self.hop_interval)
            .field("obfs", &self.obfs.is_some())
            .finish_non_exhaustive()
    }
}

impl HopConn {
    // cancel-safe: the queue lock is released before the packet is copied out, and a cancelled wait leaves
    // the queued packet for the next call.
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut queue = self.recv_queue_rx.lock().await;
        let packet = tokio::select! {
            packet = queue.recv() => packet,
            () = self.close_chan.cancelled() => None,
        };
        drop(queue);
        let Some(packet) = packet else {
            return Err(err_net_closed());
        };
        let n = std::cmp::min(buf.len(), packet.n);
        let (Some(dst), Some(src)) = (buf.get_mut(..n), packet.buf.get(..n)) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet larger than the buffer"));
        };
        dst.copy_from_slice(src);
        self.buf_pool.put(packet.buf);
        Ok((n, Box::new(self.server_addr.clone())))
    }

    async fn write_to(&self, buf: &[u8], _addr: &dyn Addr) -> io::Result<usize> {
        let (current_conn, server_addr) = {
            let state = self.state.read();
            if state.closed {
                return Err(err_net_closed());
            }
            let server_addr = state.server_addrs.get(state.addr_index).ok_or_else(err_net_closed)?;
            (Arc::clone(&state.current_conn), Arc::clone(server_addr))
        };
        current_conn.write_to(buf, &*server_addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.state.read().current_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        let mut state = self.state.write();
        if state.closed {
            return Ok(());
        }
        if let Some(prev_conn) = state.prev_conn.as_ref() {
            let _ = prev_conn.close();
        }
        let err = state.current_conn.close();
        self.close_chan.cancel();
        state.closed = true;
        state.server_addrs = Vec::new();
        err
    }

    fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        let mut state = self.state.write();
        state.read_buffer_size = bytes;
        if let Some(prev_conn) = state.prev_conn.as_ref() {
            let _ = try_set_packet_conn_read_buffer(&**prev_conn, bytes);
        }
        try_set_packet_conn_read_buffer(&*state.current_conn, bytes)
    }

    fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        let mut state = self.state.write();
        state.write_buffer_size = bytes;
        if let Some(prev_conn) = state.prev_conn.as_ref() {
            let _ = try_set_packet_conn_write_buffer(&**prev_conn, bytes);
        }
        try_set_packet_conn_write_buffer(&*state.current_conn, bytes)
    }

    async fn recv_routine(self: Arc<Self>, conn: Arc<dyn PacketConn>) {
        loop {
            let mut buf = self.buf_pool.get();
            let Ok((n, _addr)) = conn.read_from(&mut buf).await else {
                return;
            };
            if let Err(err) = self.recv_queue.try_send(UdpPacket { buf, n }) {
                // The queue is full, so the packet is dropped.
                self.buf_pool.put(err.into_inner().buf);
            }
        }
    }

    // cancel-safe: an interrupted iteration only skips the hop it was about to send, and the ticker re-arms
    // for the next one.
    async fn hop_routine(self: Arc<Self>, dialer: Arc<dyn PacketDialer>, r_addr: Box<dyn Addr>) {
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + self.hop_interval, self.hop_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = self.close_chan.cancelled() => return,
                _ = ticker.tick() => {}
            }
            Arc::clone(&self).hop(Arc::clone(&dialer), &*r_addr).await;
        }
    }

    async fn hop(self: Arc<Self>, dialer: Arc<dyn PacketDialer>, r_addr: &dyn Addr) {
        let closed = self.state.read().closed;
        if closed {
            return;
        }
        // Skip this hop if failed to listen.
        let Ok(new_conn) = dialer.listen_packet(r_addr).await else {
            return;
        };

        let mut state = self.state.write();
        if state.closed {
            drop(state);
            let _ = new_conn.close();
            return;
        }
        // Keep receiving from the previous connection: packets still in flight were sent
        // before the server learned about the new port.
        if let Some(prev_conn) = state.prev_conn.take() {
            let _ = prev_conn.close();
        }
        let prev_conn = Arc::clone(&state.current_conn);
        state.prev_conn = Some(prev_conn);
        let current_conn: Arc<dyn PacketConn> = match &self.obfs {
            Some(obfs) => Arc::new(ObfsUDPConn::new(new_conn, Arc::clone(obfs))),
            None => Arc::from(new_conn),
        };
        state.current_conn = Arc::clone(&current_conn);
        if state.read_buffer_size > 0 {
            let _ = try_set_packet_conn_read_buffer(&*current_conn, state.read_buffer_size);
        }
        if state.write_buffer_size > 0 {
            let _ = try_set_packet_conn_write_buffer(&*current_conn, state.write_buffer_size);
        }
        state.addr_index = random_index(state.server_addrs.len());
        drop(state);

        tokio::spawn(Arc::clone(&self).recv_routine(current_conn));
    }

    /// Answers the syscall-conn assertion with the socket descriptor.
    #[cfg(unix)]
    fn syscall_conn(&self) -> anyhow::Result<usize> {
        use std::os::fd::AsRawFd;

        let pid = {
            let state = self.state.read();
            state.current_conn.as_socket().map(|socket| usize::try_from(socket.as_raw_fd()).unwrap_or_default())
        };
        pid.ok_or_else(|| anyhow!("not supported"))
    }

    /// Answers the syscall-conn assertion with the socket descriptor.
    #[cfg(not(unix))]
    #[expect(
        clippy::unused_self,
        reason = "kept a method so callers spell one name on every platform, mirroring the TCP stub"
    )]
    fn syscall_conn(&self) -> anyhow::Result<usize> {
        Err(anyhow!("not supported"))
    }
}

#[derive(Debug)]
pub struct ObfsUDPHopClientPacketConn {
    conn: Arc<HopConn>,
}

#[async_trait]
impl PacketConn for ObfsUDPHopClientPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.conn.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.conn.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.conn.close()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }
}

impl ObfsUDPHopClientPacketConn {
    pub fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        self.conn.set_read_buffer(bytes)
    }

    pub fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        self.conn.set_write_buffer(bytes)
    }

    /// The hop conn does not support a read deadline, so this is a no-op.
    pub const fn set_read_deadline(&self, _t: Option<DateTime<Utc>>) -> io::Result<()> {
        Ok(())
    }

    /// The hop conn does not support a write deadline, so this is a no-op.
    pub const fn set_write_deadline(&self, _t: Option<DateTime<Utc>>) -> io::Result<()> {
        Ok(())
    }

    pub fn set_deadline(&self, t: Option<DateTime<Utc>>) -> io::Result<()> {
        self.set_read_deadline(t)?;
        self.set_write_deadline(t)
    }
}

#[derive(Debug)]
pub struct ObfsUDPHopClientPacketConnWithSyscall {
    conn: ObfsUDPHopClientPacketConn,
}

#[async_trait]
impl PacketConn for ObfsUDPHopClientPacketConnWithSyscall {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.conn.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.conn.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.conn.close()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }
}

impl ObfsUDPHopClientPacketConnWithSyscall {
    pub fn syscall_conn(&self) -> anyhow::Result<usize> {
        self.conn.conn.syscall_conn()
    }
}

pub async fn new_obfs_udp_hop_client_packet_conn(
    server: &str,
    server_ports: &str,
    hop_interval: Duration,
    obfs: Option<Arc<dyn Obfuscator>>,
    dialer: Arc<dyn PacketDialer>,
) -> anyhow::Result<Box<dyn PacketConn>> {
    let ports = parse_ports(server_ports)?;
    // Resolve the server IP address, then attach the ports to UDP addresses.
    let r_addr = dialer.remote_addr(server).await?;
    let (ip, _) = split_host_port(&r_addr.string())?;
    let ip: Option<IpAddr> = ip.parse().ok();
    let server_addrs: Vec<Arc<UdpAddr>> = ports
        .iter()
        .map(|port| Arc::new(UdpAddr::new(ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), *port)))
        .collect();

    let cur_conn = dialer.listen_packet(&*r_addr).await?;
    let current_conn: Arc<dyn PacketConn> = match &obfs {
        Some(obfs) => Arc::new(ObfsUDPConn::new(cur_conn, Arc::clone(obfs))),
        None => Arc::from(cur_conn),
    };

    let (recv_queue, recv_queue_rx) = mpsc::channel(PACKET_QUEUE_SIZE);
    let conn = Arc::new(HopConn {
        server_addr: UdpHopAddr(server.to_owned()),
        hop_interval,
        obfs,
        state: RwLock::new(HopState {
            prev_conn: None,
            current_conn: Arc::clone(&current_conn),
            addr_index: random_index(server_addrs.len()),
            read_buffer_size: 0,
            write_buffer_size: 0,
            closed: false,
            server_addrs,
        }),
        recv_queue,
        recv_queue_rx: tokio::sync::Mutex::new(recv_queue_rx),
        close_chan: CancellationToken::new(),
        buf_pool: BufPool::new(),
    });

    tokio::spawn(Arc::clone(&conn).recv_routine(Arc::clone(&current_conn)));
    tokio::spawn(Arc::clone(&conn).hop_routine(dialer, r_addr));

    if supports_syscall_conn(&*current_conn) {
        return Ok(Box::new(ObfsUDPHopClientPacketConnWithSyscall { conn: ObfsUDPHopClientPacketConn { conn } }));
    }
    Ok(Box::new(ObfsUDPHopClientPacketConn { conn }))
}

/// the `conn.currentConn.(syscall.Conn)` assertion.
fn supports_syscall_conn(conn: &dyn PacketConn) -> bool {
    conn.as_socket().is_some()
}

fn try_set_packet_conn_read_buffer(pc: &dyn PacketConn, bytes: usize) -> io::Result<()> {
    if let Some(socket) = pc.as_socket() {
        return socket.set_recv_buffer_size(bytes);
    }
    Ok(())
}

fn try_set_packet_conn_write_buffer(pc: &dyn PacketConn, bytes: usize) -> io::Result<()> {
    if let Some(socket) = pc.as_socket() {
        return socket.set_send_buffer_size(bytes);
    }
    Ok(())
}

pub(crate) fn parse_ports(server_ports: &str) -> anyhow::Result<Vec<u16>> {
    let mut ports = Vec::new();
    for port_str in server_ports.split(',') {
        let Some((start, end)) = port_str.split_once('-') else {
            let port = parse_port(port_str).ok_or_else(|| anyhow!("invalid port"))?;
            ports.push(port);
            continue;
        };
        if end.contains('-') {
            return Err(anyhow!("invalid port range"));
        }
        let start = parse_port(start).ok_or_else(|| anyhow!("invalid port range"))?;
        let end = parse_port(end).ok_or_else(|| anyhow!("invalid port range"))?;
        let (start, end) = if start > end { (end, start) } else { (start, end) };
        for port in start..=end {
            ports.push(port);
        }
    }
    if ports.is_empty() {
        return Err(anyhow!("invalid port"));
    }
    Ok(ports)
}

fn parse_port(port: &str) -> Option<u16> {
    if port.is_empty() || port.starts_with('+') || port.starts_with('-') {
        return None;
    }
    port.parse::<u16>().ok()
}

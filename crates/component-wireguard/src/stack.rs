//! The userspace IP stack: local addresses, the default route installed for each family it has a
//! local address in, and TCP/UDP sockets over whatever packet device the caller supplies.
//!
//! There is no passive TCP listener: the stack interface declares `listen_tcp` but no caller
//! invokes it — only `dial_tcp`, `dial_udp` and `listen_udp` have callers — so a passive TCP endpoint
//! would be unreachable from this crate as well.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, LazyLock, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use anyhow::{anyhow, Result};
use ipnet::IpNet;
use murmur_log::errorln;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_util::sync::CancellationToken;

use crate::device::Tun;

/// Default socket buffer: enough segments to keep a bulk transfer busy, small enough not
/// to pin megabytes per connection.
const TCP_SOCKET_BUFFER: usize = 32 * 1024;
/// Datagrams buffered per UDP socket in each direction.
pub const UDP_SOCKET_PACKETS: usize = 32;
/// The stack refuses an MTU below this when IPv6 output is in use.
const IPV6_MINIMUM_MTU: u16 = 1280;
/// The lowest MTU the stack accepts at all.
const MINIMUM_MTU: u16 = 68;
pub const DEFAULT_MTU: u16 = 1500;
/// The ephemeral range the stack hands out when a socket asks for no port.
const EPHEMERAL_START: u16 = 49_152;
/// How many ports that range holds.
const EPHEMERAL_PORTS: u16 = 16_384;

/// How a packet device tells the stack that it queued a packet.
///
/// A notification that arrives while the driver polls is not lost, so a device may notify
/// before or after the packet becomes readable.
#[derive(Clone, Default)]
pub struct Events(Arc<Notify>);

impl core::fmt::Debug for Events {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Events").finish_non_exhaustive()
    }
}

impl Events {
    /// Queue a driver wakeup.
    pub fn notify(&self) {
        self.0.notify_one();
    }

    fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.0.notified()
    }
}

/// The subset of stack configuration this crate exposes.
#[derive(Clone, Debug)]
pub struct StackConfig {
    pub local_addresses: Vec<IpNet>,
    pub mtu: u16,
}

enum Action {
    Write(Vec<u8>),
    SendTo(Vec<u8>, IpEndpoint),
    Close,
}

enum Event {
    Data(Vec<u8>),
    Datagram(Vec<u8>, IpEndpoint),
    Closed,
}

enum Command {
    TcpConnect { local: IpListenEndpoint, remote: IpEndpoint, reply: oneshot::Sender<Result<(TcpConn, SocketAddr)>> },
    UdpBind { local: IpListenEndpoint, peer: Option<IpEndpoint>, reply: oneshot::Sender<Result<(UdpConn, SocketAddr)>> },
    TcpListen { port: u16, reply: oneshot::Sender<Result<()>> },
}

/// The forwarder's in-flight cap, standing here for the ports armed before their connections
/// arrive: `smoltcp` answers a SYN only from a socket listening on its port.
const MAX_ARMED_TCP_PORTS: usize = 1024;

/// `smoltcp` measures time from a fixed origin, so the whole stack shares one wall-clock
/// starting point instead of taking a fresh `Instant` per call.
static ORIGIN: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);

fn now_millis() -> u64 {
    u64::try_from(ORIGIN.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn now() -> SmolInstant {
    SmolInstant::from_millis(now_millis().cast_signed())
}

fn deadline_to_sleep(deadline: SmolInstant) -> tokio::time::Instant {
    let remaining = deadline.total_millis().cast_unsigned().saturating_sub(now_millis());
    tokio::time::Instant::now() + Duration::from_millis(remaining).max(Duration::from_millis(1))
}

/// The packet device backed by a WireGuard [`Tun`].
pub struct ChannelPhy {
    tun: Tun,
    mtu: usize,
    receive_buffer: Vec<u8>,
}

impl core::fmt::Debug for ChannelPhy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChannelPhy").field("mtu", &self.mtu).finish_non_exhaustive()
    }
}

impl ChannelPhy {
    /// A packet device over the device's channel pair.
    #[must_use]
    pub fn new(tun: Tun, mtu: usize) -> Self {
        Self { tun, mtu, receive_buffer: vec![0u8; mtu] }
    }
}

pub struct RxToken<'a>(&'a [u8]);

impl core::fmt::Debug for RxToken<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RxToken").field("len", &self.0.len()).finish_non_exhaustive()
    }
}

impl phy::RxToken for RxToken<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0)
    }
}

pub struct TxToken<'a> {
    tun: &'a Tun,
}

impl core::fmt::Debug for TxToken<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxToken").finish_non_exhaustive()
    }
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.tun.write(buffer);
        result
    }
}

impl phy::Device for ChannelPhy {
    type RxToken<'a> = RxToken<'a>;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(RxToken<'_>, TxToken<'_>)> {
        let packet = self.tun.try_receive()?;
        let len = packet.len().min(self.receive_buffer.len());
        for (slot, byte) in self.receive_buffer.iter_mut().zip(&packet) {
            *slot = *byte;
        }
        Some((RxToken(self.receive_buffer.get(..len)?), TxToken { tun: &self.tun }))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<TxToken<'_>> {
        Some(TxToken { tun: &self.tun })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

/// What a [`PacketDevice`] queues in each direction, and how many events a socket's reader may
/// fall behind before the driver stops draining that socket.
pub const PACKET_QUEUE_SIZE: usize = 256;

/// The packet device behind [`Stack::with_packet_handle`]: a stack whose packets the caller
/// moves itself — both the socket surface and the packet device an OpenVPN or MASQUE outbound reads
/// and writes.
pub struct PacketDevice {
    /// Packets the caller queued for the stack's receive path.
    inbound: Receiver<Vec<u8>>,
    /// Packets the stack transmitted, for the caller to drain.
    outbound: SyncSender<Vec<u8>>,
    /// Wakes a caller waiting in [`PacketHandle::read_async`]; separate from the driver's own
    /// notification so waking one never consumes the other's.
    read_ready: Events,
    mtu: usize,
    scratch: Vec<u8>,
}

impl core::fmt::Debug for PacketDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketDevice").field("mtu", &self.mtu).finish_non_exhaustive()
    }
}

/// The caller's end of a [`PacketDevice`], the packet-device surface.
pub struct PacketHandle {
    /// [`PacketDevice::outbound`]'s other end; behind a lock so `read` can take `&self`.
    outbound: Mutex<Receiver<Vec<u8>>>,
    inbound: Mutex<SyncSender<Vec<u8>>>,
    events: Events,
    read_ready: Events,
}

impl core::fmt::Debug for PacketHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketHandle").finish_non_exhaustive()
    }
}

pub struct PacketTxToken<'a> {
    outbound: &'a SyncSender<Vec<u8>>,
    read_ready: &'a Events,
}

impl core::fmt::Debug for PacketTxToken<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketTxToken").finish_non_exhaustive()
    }
}

impl phy::TxToken for PacketTxToken<'_> {
    /// A full queue drops the packet, as [`crate::device::Tun::write`] does: the stack's
    /// caller is a packet loop that must not block on it.
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        match self.outbound.try_send(buffer) {
            Ok(()) => self.read_ready.notify(),
            Err(TrySendError::Full(_)) => errorln!("[Stack] dropped a transmitted packet: the caller's queue is full"),
            Err(TrySendError::Disconnected(_)) => {}
        }
        result
    }
}

impl phy::Device for PacketDevice {
    type RxToken<'a> = RxToken<'a>;
    type TxToken<'a> = PacketTxToken<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(RxToken<'_>, PacketTxToken<'_>)> {
        let packet = self.inbound.try_recv().ok()?;
        let len = packet.len().min(self.scratch.len());
        for (slot, byte) in self.scratch.iter_mut().zip(&packet) {
            *slot = *byte;
        }
        Some((
            RxToken(self.scratch.get(..len)?),
            PacketTxToken { outbound: &self.outbound, read_ready: &self.read_ready },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<PacketTxToken<'_>> {
        Some(PacketTxToken { outbound: &self.outbound, read_ready: &self.read_ready })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

impl PacketHandle {
    /// Block until the stack transmits a packet, or the stack closes.
    pub fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let packet = {
            let receiver = self.outbound.lock().map_err(|_| closed_socket())?;
            receiver.recv()
        };
        let packet = packet.map_err(|_| closed_socket())?;
        Ok(Self::copy(buffer, &packet))
    }

    /// The non-blocking half of [`Self::read`], for draining a batch.
    pub fn try_read(&self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        let receiver = self.outbound.lock().map_err(|_| closed_socket())?;
        match receiver.try_recv() {
            Ok(packet) => Ok(Some(Self::copy(buffer, &packet))),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(closed_socket()),
        }
    }

    /// [`Self::read`] for a caller on a task rather than a packet thread: waits for the stack to
    /// transmit a packet instead of parking the thread it runs on.
    pub async fn read_async(&self, buffer: &mut [u8]) -> io::Result<usize> {
        // cancel-safe: a dropped wait leaves the queued packet in the channel, and the readiness
        // notification is re-armed on every pass.
        loop {
            let notified = self.read_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(size) = self.try_read(buffer)? {
                return Ok(size);
            }
            notified.await;
        }
    }

    fn copy(buffer: &mut [u8], packet: &[u8]) -> usize {
        let len = packet.len().min(buffer.len());
        for (slot, byte) in buffer.iter_mut().zip(packet) {
            *slot = *byte;
        }
        len
    }

    /// Hand a packet to the stack's receive path. A full queue drops
    /// it, as the equivalent [`crate::device::Tun::write`] does.
    pub fn write(&self, packet: &[u8]) -> io::Result<()> {
        let sender = self.inbound.lock().map_err(|_| closed_socket())?;
        match sender.try_send(packet.to_vec()) {
            Ok(()) => {
                self.events.notify();
                Ok(())
            }
            Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Disconnected(_)) => Err(closed_socket()),
        }
    }
}

/// The running stack. Sockets are created and driven on its own task, so a `smoltcp`
/// `Interface` never moves between threads.
pub struct Stack {
    commands: mpsc::UnboundedSender<Command>,
    closed: CancellationToken,
    is_up: AtomicBool,
    mtu: usize,
    local_addresses: Vec<IpNet>,
    /// The connections of every port [`Self::arm_tcp_port`] answered, in arrival order.
    accepts: tokio::sync::Mutex<mpsc::UnboundedReceiver<TcpConn>>,
}

impl core::fmt::Debug for Stack {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stack")
            .field("mtu", &self.mtu)
            .field("local_addresses", &self.local_addresses)
            .finish_non_exhaustive()
    }
}

impl Stack {
    /// Build the stack over the device's tun.
    pub fn new(config: StackConfig, tun: Tun) -> Result<Arc<Self>> {
        let mtu = validate_mtu(config.mtu, &config.local_addresses)?;
        let events = tun.events();
        let phy = ChannelPhy::new(tun, usize::from(mtu));
        Self::spawn(config, phy, mtu, events, false)
    }

    /// The same stack over a caller-supplied `smoltcp` device, which the tests use to run a
    /// loopback instead of a WireGuard tunnel. The device must notify `events` whenever it
    /// queues a packet, as the device's own event stream does.
    pub fn with_device<D: phy::Device + Send + 'static>(
        config: StackConfig,
        device: D,
        events: Events,
    ) -> Result<Arc<Self>> {
        let mtu = validate_mtu(config.mtu, &config.local_addresses)?;
        Self::spawn(config, device, mtu, events, false)
    }

    /// A stack whose packets the caller carries through the returned
    /// [`PacketHandle`], for a transport that is not WireGuard.
    pub fn with_packet_handle(config: StackConfig) -> Result<(Arc<Self>, PacketHandle)> {
        Self::with_packet_handle_shape(config, false)
    }

    /// Promiscuous mode: the stack admits every unicast destination the device hands it, not only
    /// its own addresses.
    pub fn with_packet_handle_promiscuous(config: StackConfig) -> Result<(Arc<Self>, PacketHandle)> {
        Self::with_packet_handle_shape(config, true)
    }

    fn with_packet_handle_shape(config: StackConfig, promiscuous: bool) -> Result<(Arc<Self>, PacketHandle)> {
        let mtu = validate_mtu(config.mtu, &config.local_addresses)?;
        let (inbound_tx, inbound_rx) = std::sync::mpsc::sync_channel(PACKET_QUEUE_SIZE);
        let (outbound_tx, outbound_rx) = std::sync::mpsc::sync_channel(PACKET_QUEUE_SIZE);
        let events = Events::default();
        let read_ready = Events::default();
        let device = PacketDevice {
            inbound: inbound_rx,
            outbound: outbound_tx,
            read_ready: read_ready.clone(),
            mtu: usize::from(mtu),
            scratch: vec![0u8; usize::from(mtu)],
        };
        let handle = PacketHandle {
            outbound: Mutex::new(outbound_rx),
            inbound: Mutex::new(inbound_tx),
            events: events.clone(),
            read_ready,
        };
        let stack = Self::spawn(config, device, mtu, events, promiscuous)?;
        Ok((stack, handle))
    }

    fn spawn<D: phy::Device + Send + 'static>(
        config: StackConfig,
        device: D,
        mtu: u16,
        events: Events,
        promiscuous: bool,
    ) -> Result<Arc<Self>> {
        if config.local_addresses.is_empty() {
            return Err(anyhow!("at least one local address is required"));
        }
        let mut device = device;
        let mut iface_config = IfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface = Interface::new(iface_config, &mut device, now());
        let cidrs: Vec<IpCidr> = config.local_addresses.iter().map(to_smoltcp_cidr).collect();
        iface.update_ip_addrs(|addresses| {
            for cidr in &cidrs {
                let _ = addresses.push(*cidr);
            }
        });
        // A default route is added per family the stack has a local address in; the tunnel
        // itself picks the peer from the peer's allowed IPs, as a kernel wg interface does.
        // Under AnyIP the next hop has to be an address of our own, which is how `smoltcp`
        // admits a packet addressed elsewhere.
        if has_family(&config.local_addresses, IpAddr::V4(Ipv4Addr::UNSPECIFIED)) {
            let gateway = first_v4(&config.local_addresses).filter(|_| promiscuous).unwrap_or(Ipv4Addr::UNSPECIFIED);
            iface.routes_mut().add_default_ipv4_route(gateway).map_err(|_| anyhow!("route table is full"))?;
        }
        if has_family(&config.local_addresses, IpAddr::V6(Ipv6Addr::UNSPECIFIED)) {
            let gateway = first_v6(&config.local_addresses).filter(|_| promiscuous).unwrap_or(Ipv6Addr::UNSPECIFIED);
            iface.routes_mut().add_default_ipv6_route(gateway).map_err(|_| anyhow!("route table is full"))?;
        }
        if promiscuous {
            iface.set_any_ip(true);
        }

        let (commands, command_rx) = mpsc::unbounded_channel();
        let (accepts, accept_rx) = mpsc::unbounded_channel();
        let closed = CancellationToken::new();
        tokio::spawn(
            Driver {
                iface,
                device,
                sockets: SocketSet::new(vec![]),
                entries: HashMap::new(),
                armed: Vec::new(),
                accepts,
                next_id: 1,
                mtu: usize::from(mtu),
                commands: command_rx,
                closed: closed.clone(),
                events,
            }
            .run(),
        );
        Ok(Arc::new(Self {
            commands,
            closed,
            is_up: AtomicBool::new(true),
            mtu: usize::from(mtu),
            local_addresses: config.local_addresses,
            accepts: tokio::sync::Mutex::new(accept_rx),
        }))
    }

    pub async fn dial_tcp(&self, local: Option<SocketAddr>, destination: SocketAddr) -> Result<TcpConn> {
        // cancel-safe: a dropped call drops the connection the driver hands back, and `TcpConn`
        // closes its socket on drop.
        let local = self.local_address(local, destination.ip())?;
        let (reply, answered) = oneshot::channel();
        self.commands
            .send(Command::TcpConnect {
                local: IpListenEndpoint { addr: Some(to_smoltcp_address(local.ip())), port: local.port() },
                remote: to_smoltcp_endpoint(destination),
                reply,
            })
            .map_err(|_| anyhow!("wireguard stack is closed"))?;
        match answered.await {
            Ok(Ok((conn, _))) => Ok(conn),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(anyhow!("wireguard stack closed before the connection was established")),
        }
    }

    pub async fn dial_udp(&self, local: Option<SocketAddr>, destination: SocketAddr) -> Result<UdpConn> {
        // cancel-safe: a dropped call drops the socket the driver binds, and a socket whose action
        // channel closed is removed by the driver.
        let local = self.local_address(local, destination.ip())?;
        let (reply, answered) = oneshot::channel();
        self.commands
            .send(Command::UdpBind {
                local: IpListenEndpoint { addr: Some(to_smoltcp_address(local.ip())), port: local.port() },
                peer: Some(to_smoltcp_endpoint(destination)),
                reply,
            })
            .map_err(|_| anyhow!("wireguard stack is closed"))?;
        match answered.await {
            Ok(Ok((conn, _))) => Ok(conn),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(anyhow!("wireguard stack closed before the socket was bound")),
        }
    }

    /// Binds a UDP socket. A zero address — the wildcard this crate passes — serves both
    /// families; an explicit address and port are bound as asked.
    pub async fn listen_udp(&self, local: Option<SocketAddr>) -> Result<UdpConn> {
        // cancel-safe: a dropped call drops the socket the driver binds, and a socket whose action
        // channel closed is removed by the driver.
        let local = self.listen_endpoint(local)?;
        let (reply, answered) = oneshot::channel();
        self.commands
            .send(Command::UdpBind { local, peer: None, reply })
            .map_err(|_| anyhow!("wireguard stack is closed"))?;
        match answered.await {
            Ok(Ok((conn, _))) => Ok(conn),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(anyhow!("wireguard stack closed before the socket was bound")),
        }
    }

    /// Reduced to what a forwarder needs: arm `port` so the
    /// stack answers its SYNs, with the connection arriving on [`Self::accept_tcp`]. Arming is
    /// idempotent and lives only until that SYN arrives, so a caller arms before it feeds one.
    pub async fn arm_tcp_port(&self, port: u16) -> Result<()> {
        // cancel-safe: arming is idempotent, so a dropped answer leaves the port armed.
        let (reply, answered) = oneshot::channel();
        self.commands.send(Command::TcpListen { port, reply }).map_err(|_| anyhow!("wireguard stack is closed"))?;
        match answered.await {
            Ok(result) => result,
            Err(_) => Err(anyhow!("wireguard stack closed before the port was armed")),
        }
    }

    /// The next connection the TCP forwarder established, handed to the handler that asked
    /// for it.
    pub async fn accept_tcp(&self) -> Result<TcpConn> {
        // cancel-safe: a connection that arrives while the wait is in flight stays queued.
        let mut accepts = self.accepts.lock().await;
        accepts.recv().await.ok_or_else(|| anyhow!("wireguard stack is closed"))
    }

    /// The listen-address admission checks: `None` and an
    /// unspecified address both mean the wildcard, multicast and zoned requests are refused,
    /// and any other address has to be one the stack holds.
    fn listen_endpoint(&self, requested: Option<SocketAddr>) -> Result<IpListenEndpoint> {
        let Some(requested) = requested else {
            return Ok(IpListenEndpoint::default());
        };
        if requested.ip().is_multicast() {
            return Err(anyhow!("wireguard stack: invalid UDP listen address"));
        }
        if let SocketAddr::V6(address) = requested {
            if address.scope_id() != 0 {
                return Err(anyhow!("wireguard stack: invalid UDP listen address"));
            }
        }
        let address = canonical(requested.ip());
        if address.is_unspecified() {
            return Ok(IpListenEndpoint { addr: None, port: requested.port() });
        }
        if !self.is_local(address) {
            return Err(anyhow!("cannot assign requested address"));
        }
        Ok(IpListenEndpoint { addr: Some(to_smoltcp_address(address)), port: requested.port() })
    }

    fn is_local(&self, address: IpAddr) -> bool {
        self.local_addresses.iter().map(IpNet::addr).any(|local| canonical(local) == address)
    }

    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn close(&self) {
        self.is_up.store(false, Ordering::Relaxed);
        self.closed.cancel();
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        !self.is_up.load(Ordering::Relaxed) || self.closed.is_cancelled()
    }

    /// RFC 6724-lite source selection: the caller's address when it gave one, otherwise the
    /// first local address of the destination's family; route admission requires one to exist.
    fn local_address(&self, requested: Option<SocketAddr>, destination: IpAddr) -> Result<SocketAddr> {
        if let Some(requested) = requested {
            if !requested.ip().is_unspecified() {
                return Ok(requested);
            }
            let port = requested.port();
            let address = self.pick_source(destination)?;
            return Ok(SocketAddr::new(address, port));
        }
        let address = self.pick_source(destination)?;
        Ok(SocketAddr::new(address, 0))
    }

    fn pick_source(&self, destination: IpAddr) -> Result<IpAddr> {
        self.local_addresses
            .iter()
            .map(IpNet::addr)
            .find(|address| address.is_ipv4() == destination.is_ipv4() && !address.is_unspecified())
            .ok_or_else(|| anyhow!("no local address of the destination's family ({destination})"))
    }
}

/// The two ways a socket learns that the driver changed its state: a `Waker` slot for
/// `poll_*`, and a `Notify` for the async datagram path.
#[derive(Default)]
struct Signal {
    waker: Mutex<Option<Waker>>,
    notify: Notify,
}

impl Signal {
    fn register(&self, waker: &Waker) {
        if let Ok(mut slot) = self.waker.lock() {
            *slot = Some(waker.clone());
        }
    }

    fn wake(&self) {
        if let Some(waker) = self.waker.lock().ok().and_then(|mut slot| slot.take()) {
            waker.wake();
        }
        self.notify.notify_waiters();
    }
}

/// A `dial_tcp` call still waiting for its handshake to finish.
struct Connect {
    reply: oneshot::Sender<Result<(TcpConn, SocketAddr)>>,
    /// Held only so the socket's action channel stays open until the handshake resolves.
    conn: TcpConn,
}

struct Entry {
    handle: SocketHandle,
    is_tcp: bool,
    events: mpsc::Sender<Event>,
    signal: Arc<Signal>,
    actions: mpsc::UnboundedReceiver<Action>,
    /// Outbound bytes `smoltcp` has not accepted yet; its own send buffer supplies the
    /// backpressure, so this only holds what one `poll_write` handed over.
    outbox: VecDeque<u8>,
    datagrams: VecDeque<(Vec<u8>, IpEndpoint)>,
    queued: Arc<std::sync::atomic::AtomicU64>,
    local: Arc<Mutex<SocketAddr>>,
    closing: bool,
    /// An event the reader had no room for; it goes out as soon as the reader makes room.
    pending: Option<Event>,
    connect: Option<Connect>,
    established: bool,
}

impl Entry {
    /// A close must not be lost behind a full queue: the reader's next read makes room and wakes
    /// the driver, which delivers it then.
    fn queue_closed(&mut self) {
        self.pending = Some(Event::Closed);
    }

    /// Hand the queued event to the reader's queue, unless it is the close and the socket still
    /// holds bytes the driver has not taken out of it. The drain stops at a full queue and leaves
    /// those bytes behind, and the reader can free a queue slot between that drain and this call,
    /// so handing the close over first would put EOF ahead of the stream and truncate it.
    fn deliver_pending(&mut self, socket_drained: bool) {
        let Some(event) = self.pending.take() else {
            return;
        };
        if !socket_drained && matches!(event, Event::Closed) {
            self.pending = Some(event);
            return;
        }
        match self.events.try_send(event) {
            Ok(()) => self.signal.wake(),
            Err(mpsc::error::TrySendError::Full(event)) => self.pending = Some(event),
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

struct Driver<D: phy::Device> {
    iface: Interface,
    device: D,
    sockets: SocketSet<'static>,
    entries: HashMap<u64, Entry>,
    /// The listening sockets [`Command::TcpListen`] installed, with the port each answers.
    armed: Vec<(SocketHandle, u16)>,
    accepts: mpsc::UnboundedSender<TcpConn>,
    next_id: u64,
    mtu: usize,
    commands: mpsc::UnboundedReceiver<Command>,
    closed: CancellationToken,
    events: Events,
}

impl<D: phy::Device> Driver<D> {
    async fn run(mut self) {
        loop {
            self.drain_commands();
            self.drain_outbox();
            let timestamp = now();
            self.iface.poll(timestamp, &mut self.device, &mut self.sockets);
            self.accept_ready();
            self.drain_events();
            self.resolve_connects();
            self.drop_finished();

            let deadline = self.iface.poll_at(timestamp, &self.sockets);
            let timer = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(deadline_to_sleep(at)).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                biased;
                () = self.closed.cancelled() => break,
                command = self.commands.recv() => match command {
                    Some(command) => self.apply(command),
                    None => break,
                },
                () = self.events.notified() => {}
                () = timer => {}
            }
        }
    }

    fn drain_commands(&mut self) {
        while let Ok(command) = self.commands.try_recv() {
            self.apply(command);
        }
    }
    fn apply(&mut self, command: Command) {
        match command {
            Command::TcpConnect { local, remote, reply } => self.open_tcp(local, remote, reply),
            Command::UdpBind { local, peer, reply } => self.open_udp(local, peer, reply),
            Command::TcpListen { port, reply } => self.open_tcp_listen(port, reply),
        }
    }

    /// The TCP forwarder: one listening socket per port whose SYN it must answer, which `smoltcp`
    /// resolves by port rather than per packet.
    fn open_tcp_listen(&mut self, port: u16, reply: oneshot::Sender<Result<()>>) {
        if self.armed.iter().any(|(_, armed)| *armed == port) {
            let _ = reply.send(Ok(()));
            return;
        }
        if self.armed.len() >= MAX_ARMED_TCP_PORTS {
            let _ = reply.send(Err(anyhow!("the TCP forwarder is answering {MAX_ARMED_TCP_PORTS} ports already")));
            return;
        }
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUFFER]),
        );
        let handle = self.sockets.add(socket);
        let listening = IpListenEndpoint { addr: None, port };
        match self.sockets.get_mut::<tcp::Socket>(handle).listen(listening) {
            Ok(()) => {
                self.armed.push((handle, port));
                let _ = reply.send(Ok(()));
            }
            Err(err) => {
                self.sockets.remove(handle);
                let _ = reply.send(Err(anyhow!("{err}")));
            }
        }
    }

    /// A listening socket a SYN arrived at becomes the
    /// connection the forwarder's handler receives, and its connection is the socket's own from
    /// here on.
    fn accept_ready(&mut self) {
        let mut answered = Vec::new();
        {
            let Self { sockets, armed, .. } = &mut *self;
            armed.retain(|(handle, _)| {
                if sockets.get::<tcp::Socket>(*handle).state() == tcp::State::Listen {
                    return true;
                }
                answered.push(*handle);
                false
            });
        }
        for handle in answered {
            let socket: &tcp::Socket = self.sockets.get(handle);
            let state = socket.state();
            let endpoints = socket.local_endpoint().zip(socket.remote_endpoint());
            let Some((local, remote)) = endpoints.filter(|_| state != tcp::State::Closed) else {
                self.sockets.remove(handle);
                continue;
            };
            let Some(conn) = self.register_tcp(handle, local, remote, None, true) else { continue };
            // A closed acceptor drops the connection, whose entry then closes the socket.
            let _ = self.accepts.send(conn);
        }
    }

    fn open_tcp(
        &mut self,
        local: IpListenEndpoint,
        remote: IpEndpoint,
        reply: oneshot::Sender<Result<(TcpConn, SocketAddr)>>,
    ) {
        let port = match local.port {
            0 => match self.allocate_local_port() {
                Ok(port) => port,
                Err(err) => {
                    let _ = reply.send(Err(err));
                    return;
                }
            },
            port => port,
        };
        let local = IpListenEndpoint { addr: local.addr, port };
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUFFER]),
            tcp::SocketBuffer::new(vec![0u8; TCP_SOCKET_BUFFER]),
        );
        let handle = self.sockets.add(socket);
        {
            let Self { iface, sockets, .. } = &mut *self;
            let context = iface.context();
            let tcp: &mut tcp::Socket = sockets.get_mut(handle);
            if let Err(err) = tcp.connect(context, remote, local) {
                sockets.remove(handle);
                let _ = reply.send(Err(anyhow!("{err}")));
                return;
            }
        }
        let local = IpEndpoint::new(local.addr.unwrap_or(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED)), local.port);
        self.register_tcp(handle, local, remote, Some(reply), false);
    }

    /// The socket surfaces a TCP flow gets once it exists: a [`TcpConn`] plus the entry that
    /// drives it. A dial returns `None`, because its connection stays inside [`Connect`] until
    /// the handshake resolves; an accepted socket returns the connection for its acceptor.
    fn register_tcp(
        &mut self,
        handle: SocketHandle,
        local: IpEndpoint,
        remote: IpEndpoint,
        dialing: Option<oneshot::Sender<Result<(TcpConn, SocketAddr)>>>,
        established: bool,
    ) -> Option<TcpConn> {
        let id = self.take_id();
        let (action_tx, actions) = mpsc::unbounded_channel();
        let (events, event_rx) = mpsc::channel(PACKET_QUEUE_SIZE);
        let signal = Arc::new(Signal::default());
        let queued = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let local = Arc::new(Mutex::new(from_smoltcp_endpoint(local)));
        let conn = TcpConn::new(
            action_tx,
            event_rx,
            Arc::clone(&signal),
            self.events.clone(),
            Arc::clone(&queued),
            Arc::clone(&local),
            remote,
        );
        let (connect, accepted) = match dialing {
            Some(reply) => (Some(Connect { reply, conn }), None),
            None => (None, Some(conn)),
        };
        self.entries.insert(
            id,
            Entry {
                handle,
                is_tcp: true,
                events,
                signal,
                actions,
                outbox: VecDeque::new(),
                datagrams: VecDeque::new(),
                queued,
                local,
                closing: false,
                pending: None,
                connect,
                established,
            },
        );
        accepted
    }

    fn open_udp(
        &mut self,
        local: IpListenEndpoint,
        peer: Option<IpEndpoint>,
        reply: oneshot::Sender<Result<(UdpConn, SocketAddr)>>,
    ) {
        let socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_SOCKET_PACKETS], vec![0; self.mtu]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_SOCKET_PACKETS], vec![0; self.mtu]),
        );
        let handle = self.sockets.add(socket);
        let bound = {
            let udp: &mut udp::Socket = self.sockets.get_mut(handle);
            match bind(udp, local) {
                Ok(bound) => bound,
                Err(err) => {
                    self.sockets.remove(handle);
                    let _ = reply.send(Err(err));
                    return;
                }
            }
        };
        let id = self.take_id();
        let (action_tx, actions) = mpsc::unbounded_channel();
        let (events, event_rx) = mpsc::channel(PACKET_QUEUE_SIZE);
        let signal = Arc::new(Signal::default());
        let queued = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let local_addr = from_smoltcp_endpoint(IpEndpoint::new(
            bound.addr.unwrap_or(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED)),
            bound.port,
        ));
        let conn = UdpConn::new(
            action_tx,
            event_rx,
            Arc::clone(&signal),
            self.events.clone(),
            Arc::clone(&queued),
            local_addr,
            peer,
        );
        let _ = reply.send(Ok((conn, local_addr)));
        self.entries.insert(
            id,
            Entry {
                handle,
                is_tcp: false,
                events,
                signal,
                actions,
                outbox: VecDeque::new(),
                datagrams: VecDeque::new(),
                queued,
                local: Arc::new(Mutex::new(local_addr)),
                closing: false,
                pending: None,
                connect: None,
                established: true,
            },
        );
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// A local port for a socket that asked for
    /// none, kept clear of the ones this driver already handed out.
    fn allocate_local_port(&self) -> Result<u16> {
        for _ in 0..16 {
            let port = EPHEMERAL_START + (rand::random::<u16>() % EPHEMERAL_PORTS);
            if !self.port_in_use(port) {
                return Ok(port);
            }
        }
        Err(anyhow!("address already in use"))
    }

    fn port_in_use(&self, port: u16) -> bool {
        self.entries.values().any(|entry| entry.local.lock().map_or(true, |local| local.port() == port))
    }

    /// the per-socket read side: hand whatever `smoltcp` buffered to the socket's task, and stop
    /// at a full queue so the window the stack advertises reflects what the reader has not taken.
    fn drain_events(&mut self) {
        let mtu = self.mtu;
        let Self { sockets, entries, .. } = &mut *self;
        for entry in entries.values_mut() {
            loop {
                // Stop before taking anything out of the socket: the `try_send` below would drop
                // whatever it could not queue, and for TCP that event is the bytes themselves, so
                // a chunk smoltcp had handed over would vanish from the stream. A full queue is
                // the backpressure; the reader notifies the driver once it makes room.
                if entry.events.capacity() == 0 {
                    break;
                }
                if entry.is_tcp {
                    let tcp: &mut tcp::Socket = sockets.get_mut(entry.handle);
                    if !tcp.may_recv() {
                        break;
                    }
                    let mut chunk = vec![0u8; TCP_SOCKET_BUFFER];
                    let Ok(size) = tcp.recv_slice(&mut chunk) else {
                        break;
                    };
                    if size == 0 {
                        break;
                    }
                    chunk.truncate(size);
                    if entry.events.try_send(Event::Data(chunk)).is_err() {
                        break;
                    }
                    entry.signal.wake();
                } else {
                    let udp: &mut udp::Socket = sockets.get_mut(entry.handle);
                    if !udp.can_recv() {
                        break;
                    }
                    let mut chunk = vec![0u8; mtu];
                    match udp.recv_slice(&mut chunk) {
                        Ok((size, meta)) => {
                            chunk.truncate(size);
                            if entry.events.try_send(Event::Datagram(chunk, meta.endpoint)).is_err() {
                                break;
                            }
                            entry.signal.wake();
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        // After the data, so a reader that sees the close has already been handed everything the
        // socket held.
        for entry in entries.values_mut() {
            let socket_drained = !entry.is_tcp || sockets.get::<tcp::Socket>(entry.handle).recv_queue() == 0;
            entry.deliver_pending(socket_drained);
        }
    }

    fn drain_outbox(&mut self) {
        let Self { sockets, entries, .. } = &mut *self;
        for entry in entries.values_mut() {
            while let Ok(action) = entry.actions.try_recv() {
                match action {
                    Action::Write(data) => entry.outbox.extend(data),
                    Action::SendTo(data, destination) => entry.datagrams.push_back((data, destination)),
                    Action::Close => {
                        entry.outbox.clear();
                        entry.datagrams.clear();
                        entry.closing = true;
                    }
                }
            }
            if entry.is_tcp {
                let tcp: &mut tcp::Socket = sockets.get_mut(entry.handle);
                while !entry.outbox.is_empty() {
                    if !tcp.may_send() {
                        break;
                    }
                    let chunk: Vec<u8> = entry.outbox.iter().take(TCP_SOCKET_BUFFER).copied().collect();
                    // `send_slice` enqueues only what the transmit buffer has room for, so drop
                    // only what it took and leave the rest for the next pass: the peer's
                    // window has to be the backpressure, not a silent truncation.
                    let Ok(accepted) = tcp.send_slice(&chunk) else {
                        break;
                    };
                    if accepted == 0 {
                        break;
                    }
                    entry.outbox.drain(..accepted);
                }
                if entry.closing {
                    tcp.close();
                }
            } else {
                let udp: &mut udp::Socket = sockets.get_mut(entry.handle);
                while let Some((data, destination)) = entry.datagrams.pop_front() {
                    if udp.send_slice(&data, destination).is_err() {
                        entry.datagrams.push_front((data, destination));
                        break;
                    }
                }
            }
            if entry.outbox.is_empty() && entry.datagrams.is_empty() {
                entry.queued.store(0, Ordering::Relaxed);
                entry.signal.wake();
            }
        }
    }

    /// `dial_tcp` answers only once the handshake finished; a close before that means
    /// the peer refused or the path broke.
    fn resolve_connects(&mut self) {
        let Self { sockets, entries, .. } = &mut *self;
        let mut failed = Vec::new();
        for (id, entry) in entries.iter_mut() {
            if entry.connect.is_none() {
                if entry.is_tcp && entry.established {
                    let tcp: &mut tcp::Socket = sockets.get_mut(entry.handle);
                    let closed = matches!(tcp.state(), tcp::State::CloseWait | tcp::State::Closed);
                    if closed {
                        entry.established = false;
                        entry.queue_closed();
                        // The bytes this close follows may still sit in the socket: the drain above
                        // stops at a full queue, and the reader can free a slot at any moment, so
                        // the close is handed over only once the socket has given them all up.
                        entry.deliver_pending(tcp.recv_queue() == 0);
                    }
                }
                continue;
            }
            let tcp: &mut tcp::Socket = sockets.get_mut(entry.handle);
            match tcp.state() {
                tcp::State::Established => {
                    let Some(connect) = entry.connect.take() else {
                        continue;
                    };
                    entry.established = true;
                    if let Some(local) = tcp.local_endpoint().map(from_smoltcp_endpoint) {
                        if let Ok(mut slot) = entry.local.lock() {
                            *slot = local;
                        }
                    }
                    if let Ok(local) = entry.local.lock() {
                        let _ = connect.reply.send(Ok((connect.conn, *local)));
                    }
                }
                tcp::State::Closed | tcp::State::FinWait1 | tcp::State::CloseWait | tcp::State::TimeWait => {
                    failed.push(*id);
                }
                tcp::State::Listen
                | tcp::State::SynSent
                | tcp::State::SynReceived
                | tcp::State::FinWait2
                | tcp::State::Closing
                | tcp::State::LastAck => {}
            }
        }
        for id in failed {
            if let Some(entry) = entries.remove(&id) {
                sockets.remove(entry.handle);
                if let Some(connect) = entry.connect {
                    let _ = connect.reply.send(Err(anyhow!("connect: connection refused")));
                }
            }
        }
    }

    /// A socket the caller has dropped loses its action channel, which is how its entry
    /// learns to close the `smoltcp` socket.
    fn drop_finished(&mut self) {
        let Self { sockets, entries, .. } = &mut *self;
        entries.retain(|_, entry| {
            let keep = !entry.actions.is_closed() || !entry.outbox.is_empty() || !entry.datagrams.is_empty();
            if keep {
                return true;
            }
            sockets.remove(entry.handle);
            false
        });
    }
}

/// A TCP connection inside the tunnel, expressed as the
/// `AsyncRead`/`AsyncWrite` pair the rest of this crate speaks.
pub struct TcpConn {
    actions: mpsc::UnboundedSender<Action>,
    events: mpsc::Receiver<Event>,
    signal: Arc<Signal>,
    wake: Events,
    queued: Arc<std::sync::atomic::AtomicU64>,
    incoming: VecDeque<u8>,
    local: Arc<Mutex<SocketAddr>>,
    peer: IpEndpoint,
    read_closed: bool,
    write_closed: bool,
}

impl core::fmt::Debug for TcpConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpConn").field("local", &self.local).field("peer", &self.peer).finish_non_exhaustive()
    }
}

impl TcpConn {
    fn new(
        actions: mpsc::UnboundedSender<Action>,
        events: mpsc::Receiver<Event>,
        signal: Arc<Signal>,
        wake: Events,
        queued: Arc<std::sync::atomic::AtomicU64>,
        local: Arc<Mutex<SocketAddr>>,
        peer: IpEndpoint,
    ) -> Self {
        Self {
            actions,
            events,
            signal,
            wake,
            queued,
            incoming: VecDeque::new(),
            local,
            peer,
            read_closed: false,
            write_closed: false,
        }
    }

    #[must_use]
    pub fn remote_endpoint(&self) -> SocketAddr {
        from_smoltcp_endpoint(self.peer)
    }

    fn closed_error() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "use of closed network connection")
    }

    fn fill(&mut self) -> bool {
        while self.incoming.is_empty() {
            match self.events.try_recv() {
                Ok(Event::Data(data)) => self.incoming.extend(data),
                Ok(Event::Datagram(_, _)) => {}
                Err(mpsc::error::TryRecvError::Empty) => return false,
                Ok(Event::Closed) | Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.read_closed = true;
                    return false;
                }
            }
        }
        true
    }
}

impl tokio::io::AsyncRead for TcpConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.fill() {
            this.signal.register(cx.waker());
            if this.fill() {
                return Pin::new(&mut *this).poll_read(cx, buf);
            }
            return if this.read_closed && this.incoming.is_empty() { Poll::Ready(Ok(())) } else { Poll::Pending };
        }
        let take = buf.remaining().min(this.incoming.len());
        let chunk: Vec<u8> = this.incoming.drain(..take).collect();
        buf.put_slice(&chunk);
        // The driver stops draining a full queue, so a read is what lets it drain again.
        this.wake.notify();
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for TcpConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(Self::closed_error()));
        }
        if this.queued.load(Ordering::Relaxed) > 0 {
            this.signal.register(cx.waker());
            if this.queued.load(Ordering::Relaxed) > 0 {
                return Poll::Pending;
            }
        }
        this.queued.fetch_add(1, Ordering::Relaxed);
        if this.actions.send(Action::Write(data.to_vec())).is_ok() {
            this.wake.notify();
            Poll::Ready(Ok(data.len()))
        } else {
            this.queued.store(0, Ordering::Relaxed);
            Poll::Ready(Err(Self::closed_error()))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write_closed = true;
        let _ = this.actions.send(Action::Close);
        this.wake.notify();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpConn {
    fn drop(&mut self) {
        let _ = self.actions.send(Action::Close);
        self.wake.notify();
    }
}

impl murmur_common::net::Stream for TcpConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local.lock().map(|slot| *slot).map_err(|_| closed_socket())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.remote_endpoint())
    }
}

/// A UDP socket inside the tunnel, which serves both
/// `dial_udp` and `listen_udp`.
pub struct UdpConn {
    actions: mpsc::UnboundedSender<Action>,
    events: Mutex<mpsc::Receiver<Event>>,
    signal: Arc<Signal>,
    wake: Events,
    queued: Arc<std::sync::atomic::AtomicU64>,
    local: SocketAddr,
    peer: Option<IpEndpoint>,
}

impl core::fmt::Debug for UdpConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdpConn").field("local", &self.local).field("peer", &self.peer).finish_non_exhaustive()
    }
}

impl UdpConn {
    fn new(
        actions: mpsc::UnboundedSender<Action>,
        events: mpsc::Receiver<Event>,
        signal: Arc<Signal>,
        wake: Events,
        queued: Arc<std::sync::atomic::AtomicU64>,
        local: SocketAddr,
        peer: Option<IpEndpoint>,
    ) -> Self {
        Self { actions, events: Mutex::new(events), signal, wake, queued, local, peer }
    }

    #[must_use]
    pub fn local_endpoint(&self) -> SocketAddr {
        self.local
    }

    /// The receive lock is taken and released inside this synchronous helper, never across
    /// an `.await`; the notify-then-recheck loop below is what makes the wait race-free.
    fn take_event(&self) -> Result<Option<Event>, ()> {
        let mut events = self.events.lock().map_err(|_| ())?;
        match events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(()),
        }
    }
}

#[async_trait::async_trait]
impl murmur_common::net::Datagram for UdpConn {
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // cancel-safe: nothing leaves the event queue until a datagram is copied out and returned.
        loop {
            let notified = self.signal.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.take_event() {
                Ok(Some(Event::Datagram(data, source))) => {
                    let length = data.len().min(buffer.len());
                    for (slot, byte) in buffer.iter_mut().zip(&data) {
                        *slot = *byte;
                    }
                    // A taken datagram makes room, so the driver may drain again.
                    self.wake.notify();
                    return Ok((length, from_smoltcp_endpoint(source)));
                }
                Ok(Some(Event::Data(_))) => continue,
                Ok(Some(Event::Closed)) | Err(()) => return Err(closed_socket()),
                Ok(None) => {}
            }
            notified.await;
        }
    }

    async fn send_to(&self, buffer: &[u8], addr: SocketAddr) -> io::Result<usize> {
        // cancel-safe: the only wait is taken after the queue is found busy, so a dropped call
        // leaves the queue counter untouched.
        // A connected socket sends to its peer whatever destination the caller names, as
        // a write to a connected socket does.
        let endpoint = match self.peer {
            Some(peer) => peer,
            None => to_smoltcp_endpoint(addr),
        };
        loop {
            let notified = self.signal.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.queued.load(Ordering::Relaxed) == 0 {
                self.queued.fetch_add(1, Ordering::Relaxed);
                if self.actions.send(Action::SendTo(buffer.to_vec(), endpoint)).is_ok() {
                    self.wake.notify();
                    return Ok(buffer.len());
                }
                self.queued.store(0, Ordering::Relaxed);
                return Err(closed_socket());
            }
            notified.await;
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn close(&self) -> io::Result<()> {
        self.queued.store(0, Ordering::Relaxed);
        self.actions.send(Action::Close).map_err(|_| closed_socket())?;
        self.wake.notify();
        Ok(())
    }
}

fn closed_socket() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "use of closed network connection")
}

/// MTU admission: the default when unset, a floor for any MTU, and the
/// IPv6 minimum whenever the stack holds an IPv6 address.
pub fn validate_mtu(mtu: u16, local_addresses: &[IpNet]) -> Result<u16> {
    let mtu = if mtu == 0 { DEFAULT_MTU } else { mtu };
    if mtu < MINIMUM_MTU {
        return Err(anyhow!("wireguard stack: MTU must be between {MINIMUM_MTU} and 65535"));
    }
    if has_family(local_addresses, IpAddr::V6(Ipv6Addr::UNSPECIFIED)) && mtu < IPV6_MINIMUM_MTU {
        return Err(anyhow!("wireguard stack: IPv6 requires an MTU of at least {IPV6_MINIMUM_MTU}"));
    }
    Ok(mtu)
}

fn has_family(local_addresses: &[IpNet], probe: IpAddr) -> bool {
    local_addresses
        .iter()
        .map(IpNet::addr)
        .any(|address| address.is_ipv4() == probe.is_ipv4() && !address.is_unspecified())
}

fn first_v4(local_addresses: &[IpNet]) -> Option<Ipv4Addr> {
    local_addresses.iter().find_map(|prefix| match prefix.addr() {
        IpAddr::V4(address) if !address.is_unspecified() => Some(address),
        IpAddr::V4(_) | IpAddr::V6(_) => None,
    })
}

fn first_v6(local_addresses: &[IpNet]) -> Option<Ipv6Addr> {
    local_addresses.iter().find_map(|prefix| match prefix.addr() {
        IpAddr::V6(address) if !address.is_unspecified() => Some(address),
        IpAddr::V4(_) | IpAddr::V6(_) => None,
    })
}

/// An IPv4-mapped IPv6 address becomes its IPv4 form.
fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address.to_ipv4_mapped().map_or(IpAddr::V6(address), IpAddr::V4),
        IpAddr::V4(address) => IpAddr::V4(address),
    }
}

/// `ipnet` reports an IPv4-mapped IPv6 prefix with 96 extra bits, which `smoltcp` wants as a plain
/// IPv4 prefix length.
fn to_smoltcp_cidr(prefix: &IpNet) -> IpCidr {
    match to_smoltcp_address(prefix.addr()) {
        IpAddress::Ipv4(address) => {
            let bits = prefix.prefix_len().saturating_sub(96);
            IpCidr::Ipv4(smoltcp::wire::Ipv4Cidr::new(address, bits))
        }
        IpAddress::Ipv6(address) => IpCidr::Ipv6(smoltcp::wire::Ipv6Cidr::new(address, prefix.prefix_len())),
    }
}

fn to_smoltcp_address(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, d] = address.octets();
            IpAddress::Ipv4(Ipv4Address::new(a, b, c, d))
        }
        IpAddr::V6(address) => {
            let octets = address.octets();
            IpAddress::Ipv6(Ipv6Address::new(
                u16::from_be_bytes([octets[0], octets[1]]),
                u16::from_be_bytes([octets[2], octets[3]]),
                u16::from_be_bytes([octets[4], octets[5]]),
                u16::from_be_bytes([octets[6], octets[7]]),
                u16::from_be_bytes([octets[8], octets[9]]),
                u16::from_be_bytes([octets[10], octets[11]]),
                u16::from_be_bytes([octets[12], octets[13]]),
                u16::from_be_bytes([octets[14], octets[15]]),
            ))
        }
    }
}

fn to_smoltcp_endpoint(address: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(to_smoltcp_address(address.ip()), address.port())
}

fn from_smoltcp_address(address: IpAddress) -> IpAddr {
    match address {
        IpAddress::Ipv4(address) => IpAddr::V4(address),
        IpAddress::Ipv6(address) => IpAddr::V6(address),
    }
}

fn from_smoltcp_endpoint(endpoint: IpEndpoint) -> SocketAddr {
    SocketAddr::new(from_smoltcp_address(endpoint.addr), endpoint.port)
}

/// `smoltcp` treats port 0 as "not open", so a wildcard bind needs a real port; the
/// ephemeral range is what the kernel would have handed out anyway.
fn bind(socket: &mut udp::Socket, requested: IpListenEndpoint) -> Result<IpListenEndpoint> {
    if requested.port != 0 {
        return socket.bind(requested).map_err(|err| anyhow!("{err}")).map(|()| requested);
    }
    let mut last = None;
    for _ in 0..16 {
        let port = EPHEMERAL_START + (rand::random::<u16>() % EPHEMERAL_PORTS);
        let endpoint = IpListenEndpoint { addr: requested.addr, port };
        match socket.bind(endpoint) {
            Ok(()) => return Ok(endpoint),
            Err(err) => last = Some(err),
        }
    }
    Err(anyhow!("{last:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How many bytes the socket still holds once the driver has run out of queue.
    const LEFTOVER: usize = 8;

    /// The socket bytes the driver copies out of `smoltcp` are the ones at risk: a socket whose
    /// receive buffer is filled before it is handed to the driver reports them through
    /// `recv_queue` without any packet ever crossing a wire.
    fn socket_holding(bytes: usize) -> tcp::Socket<'static> {
        let mut rx = tcp::SocketBuffer::new(vec![0u8; 64]);
        assert_eq!(rx.enqueue_slice(&vec![7u8; bytes]), bytes, "the socket starts holding {bytes} bytes");
        tcp::Socket::new(rx, tcp::SocketBuffer::new(vec![0u8; 64]))
    }

    fn entry(handle: SocketHandle, events: mpsc::Sender<Event>) -> Entry {
        let (action_tx, actions) = mpsc::unbounded_channel();
        let _ = action_tx;
        Entry {
            handle,
            is_tcp: true,
            events,
            signal: Arc::new(Signal::default()),
            actions,
            outbox: VecDeque::new(),
            datagrams: VecDeque::new(),
            queued: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            local: Arc::new(Mutex::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))),
            closing: false,
            pending: None,
            connect: None,
            established: true,
        }
    }

    /// A driver over the two structures `drain_events` and `resolve_connects` read, the socket set
    /// and the entries. The interface is never polled, so an idle loopback device is enough.
    fn driver(handle: SocketHandle, sockets: SocketSet<'static>, events: mpsc::Sender<Event>) -> Driver<phy::Loopback> {
        let mut device = phy::Loopback::new(Medium::Ip);
        let iface = Interface::new(IfaceConfig::new(HardwareAddress::Ip), &mut device, now());
        let (_commands, commands) = mpsc::unbounded_channel();
        let (accepts, _accepted) = mpsc::unbounded_channel();
        let mut entries = HashMap::new();
        entries.insert(1_u64, entry(handle, events));
        Driver {
            iface,
            device,
            sockets,
            entries,
            armed: Vec::new(),
            accepts,
            next_id: 2,
            mtu: usize::from(DEFAULT_MTU),
            commands,
            closed: CancellationToken::new(),
            events: Events::default(),
        }
    }

    /// `drain_events` stops before taking anything out of a socket whose queue is full, leaving
    /// the socket's bytes where `smoltcp` holds them; the close that follows has to wait for them
    /// even when the reader frees a queue slot in between. This replays that interleaving with the
    /// test standing in for the concurrent reader: without the gate, the close takes the freed
    /// slot and the bytes that follow it are behind EOF, which `read_to_end` reports as a
    /// truncated stream.
    #[test]
    fn a_close_waits_for_the_bytes_a_full_queue_left_in_the_socket() {
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(socket_holding(LEFTOVER));

        // A queue the reader has not caught up with: one slot, taken.
        let (events, mut queue) = mpsc::channel(1);
        events.try_send(Event::Data(vec![0])).expect("an empty queue takes one event");
        assert_eq!(events.capacity(), 0, "the queue starts full");

        let mut driver = driver(handle, sockets, events);

        // The drain stops at the full queue, leaving the socket's bytes where they are.
        driver.drain_events();
        // The reader frees a slot between that drain and the close the driver is about to queue.
        assert!(matches!(queue.try_recv(), Ok(Event::Data(_))));
        driver.resolve_connects();

        // The close must not have overtaken the bytes still in the socket.
        assert!(
            matches!(queue.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "the close was queued before the bytes the socket still held"
        );

        // Once the socket has surrendered its bytes the close follows them.
        driver.drain_events();
        assert!(
            matches!(queue.try_recv(), Ok(Event::Data(data)) if data.len() == LEFTOVER),
            "the socket's bytes must be queued before the close"
        );
        driver.drain_events();
        assert!(matches!(queue.try_recv(), Ok(Event::Closed)), "the close must follow the bytes the socket held");
    }
}

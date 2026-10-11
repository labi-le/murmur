use anyhow::anyhow;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{close_stream, Stream};
use murmur_component::resolver::ip4p::lookup_ip4p;
use murmur_component::resolver::resolver::{
    resolve_ip_prefer6_with_resolver, resolve_ip_with_resolver as resolve_ip_with_resolver_default,
    resolve_ipv4_with_resolver, resolve_ipv6_with_resolver, ResolverRef,
};
use murmur_constant::dns::DNSPrefer;
use murmur_constant::metadata::{AddrType, Metadata};
use murmur_std_compat::net::UdpAddr;
use murmur_transport::socks5::socks5::{ATYP_DOMAIN_NAME, ATYP_IPV4, ATYP_IPV6};

pub(crate) fn serializes_socks_addr(metadata: &Metadata) -> Vec<u8> {
    let addr_type = metadata.addr_type();
    let port = metadata.dst_port;
    let port_bytes = [(port >> 8) as u8, (port & 0xff) as u8];

    let mut buf = Vec::new();
    match addr_type {
        AddrType::ATYP_DOMAIN_NAME => {
            let host = metadata.host.as_bytes();
            buf.push(ATYP_DOMAIN_NAME);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the SOCKS5 domain length prefix is one byte wide by definition"
            )]
            buf.push(host.len() as u8);
            buf.extend_from_slice(host);
            buf.extend_from_slice(&port_bytes);
        }
        AddrType::ATYP_IPV4 => {
            buf.push(ATYP_IPV4);
            if let Some(std::net::IpAddr::V4(v4)) = metadata.dst_ip {
                buf.extend_from_slice(&v4.octets());
            }
            buf.extend_from_slice(&port_bytes);
        }
        AddrType::ATYP_IPV6 => {
            buf.push(ATYP_IPV6);
            if let Some(std::net::IpAddr::V6(v6)) = metadata.dst_ip {
                buf.extend_from_slice(&v6.octets());
            }
            buf.extend_from_slice(&port_bytes);
        }
        _ => {}
    }
    buf
}

pub(crate) async fn resolve_ip_with_resolver(
    ctx: &CancellationToken,
    host: &str,
    prefer: DNSPrefer,
    r: Option<&ResolverRef>,
) -> anyhow::Result<std::net::IpAddr> {
    match prefer {
        DNSPrefer::IPV4_ONLY => resolve_ipv4_with_resolver(ctx, host, r).await,
        DNSPrefer::IPV6_ONLY => resolve_ipv6_with_resolver(ctx, host, r).await,
        DNSPrefer::IPV6_PREFER => resolve_ip_prefer6_with_resolver(ctx, host, r).await,
        _ => resolve_ip_with_resolver_default(ctx, host, r).await,
    }
}

pub(crate) async fn resolve_udp_addr(
    ctx: &CancellationToken,
    _network: &str,
    address: &str,
    prefer: DNSPrefer,
) -> anyhow::Result<UdpAddr> {
    let (host, port, has_port) = murmur_common_net::split_host_port(address)?;
    if !has_port {
        return Err(anyhow!("address {address}: missing port in address"));
    }

    let ip = resolve_ip_with_resolver(
        ctx,
        &host,
        prefer,
        murmur_component::resolver::resolver::proxy_server_host_resolver().as_deref(),
    )
    .await?;

    let (ip, port) = lookup_ip4p(ip, &port);

    let uint16_port: u16 = port.parse().map_err(|_| anyhow!("invalid port {port}"))?;

    Ok(UdpAddr::new(ip, uint16_port))
}

pub(crate) fn safe_conn_close(c: Option<&dyn Stream>, err: bool) {
    if err {
        if let Some(conn) = c {
            let _ = close_stream(conn);
        }
    }
}

/// Shared IP-stack plumbing, also driven by the masque and openvpn adapters. Relocated here
/// (rather than kept in the now-deleted `wireguard.rs`) since Rust module boundaries require the
/// consumers to import it from somewhere that still exists.
pub(crate) mod ip_stack {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;

    use anyhow::{anyhow, Result};
    use async_trait::async_trait;
    use ipnet::IpNet;
    use serde::{Deserialize, Serialize};
    use tokio_util::sync::CancellationToken;

    use murmur_common::errors::ErrOsClosed;
    use murmur_common_net::io::{DatagramAsOldPacketConn, StreamAsOldConn};
    use murmur_common_net::new_bind_packet_conn;
    use murmur_component::dialer::options::NetDialer;
    use murmur_component_wireguard::stack::{PacketHandle, Stack, StackConfig};
    use murmur_constant_features::WITH_GVISOR;
    use murmur_std_compat::net::{Conn as NetConn, PacketConn as NetPacketConn};

    const IP_STACK_AUTO: &str = "auto";
    const IP_STACK_GVISOR: &str = "gvisor";
    const IP_STACK_MIPS: &str = "mips";

    /// `IPStackOption`. `pub` (not `pub(crate)`): embedded by `pub struct`s in sibling
    /// `adapter::outbound` units.
    #[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
    pub struct IpStackOption {
        #[serde(rename = "mode", default)]
        pub mode: String,
        #[serde(rename = "congestion-controller", default)]
        pub congestion_controller: String,
    }

    impl IpStackOption {
        pub fn normalize(&mut self) {
            self.mode = self.mode.to_lowercase();
            if self.mode.is_empty() {
                IP_STACK_AUTO.clone_into(&mut self.mode);
            }
            self.congestion_controller = self.congestion_controller.to_lowercase();
        }

        pub fn validate(&self) -> Result<()> {
            match self.mode.as_str() {
                IP_STACK_AUTO | IP_STACK_MIPS => {}
                IP_STACK_GVISOR => {
                    if !WITH_GVISOR {
                        return Err(anyhow!("gVisor IP stack requires the with_gvisor build tag"));
                    }
                }
                other => return Err(anyhow!("invalid IP stack mode {other:?}; expected auto, gvisor, or mips")),
            }
            match self.congestion_controller.as_str() {
                "" | "cubic" | "reno" | "bbr" | "bbr3" => Ok(()),
                other => {
                    Err(anyhow!("invalid IP stack congestion controller {other:?}; expected cubic, reno, bbr, or bbr3"))
                }
            }
        }
    }

    /// Murmur's IP stack packet-and-socket surface. The trait also declares a few raw-IP and
    /// passive-TCP methods; no murmur code path calls them and the smoltcp stack cannot serve
    /// them, so they are not implemented.
    #[async_trait]
    pub(crate) trait IpStack: Send + Sync {
        async fn start(&self) -> Result<()>;
        async fn dial_tcp(
            &self,
            ctx: &CancellationToken,
            network: &str,
            source: SocketAddr,
            destination: SocketAddr,
        ) -> Result<Box<dyn NetConn>>;
        async fn dial_udp(
            &self,
            ctx: &CancellationToken,
            network: &str,
            source: SocketAddr,
            destination: SocketAddr,
        ) -> Result<Box<dyn NetConn>>;
        async fn listen_udp(
            &self,
            ctx: &CancellationToken,
            network: &str,
            local: SocketAddr,
        ) -> Result<Box<dyn NetPacketConn>>;
        /// The packets the stack transmitted, in batches of up to
        /// [`Self::batch_size`]. Blocks until the first one is available.
        fn read(&self, buffers: &mut [Vec<u8>], sizes: &mut [usize], offset: usize) -> Result<usize>;
        /// The packets received on the tunnel, into the stack.
        fn write(&self, buffers: &[Vec<u8>], offset: usize) -> Result<usize>;
        /// No Rust outbound reads the stack's MTU or name yet.
        #[allow(dead_code, reason = "no Rust outbound reads the stack's MTU or name yet")]
        fn mtu(&self) -> Result<u32>;
        #[allow(dead_code, reason = "no Rust outbound reads the stack's MTU or name yet")]
        fn name(&self) -> Result<String>;
        fn batch_size(&self) -> usize;
        fn close(&self) -> Result<()>;
    }

    /// The cap on packets one [`IpStack::read`] returns.
    const DEVICE_BATCH_SIZE: usize = 64;
    /// The `mips` mode: `murmur-component-wireguard`'s smoltcp stack, whose packets the
    /// outbound carries through the [`PacketHandle`].
    struct ComponentIpStack {
        stack: Arc<Stack>,
        packets: PacketHandle,
    }

    /// Builds the IP stack. Only the `mips` engine is implemented: `gvisor` needs the
    /// sing-wireguard stack device, which is unavailable, so it fails closed instead of running the
    /// smoltcp stack under its name.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "`new_ip_stack` is the entry point whose by-value option is the fixed call contract for the masque, openvpn and zerotier adapters"
    )]
    pub(crate) fn new_ip_stack(
        option: IpStackOption,
        local_addresses: Vec<IpNet>,
        mtu: u32,
    ) -> Result<Arc<dyn IpStack>> {
        // `auto` is the "default engine"; a gVisor device would need the sing-wireguard stack,
        // so the engine it can default to is the smoltcp one.
        let mode = if option.mode == IP_STACK_AUTO { IP_STACK_MIPS } else { option.mode.as_str() };
        match mode {
            IP_STACK_GVISOR => {
                Err(anyhow!("gVisor IP stack device is not implemented (NEEDED CRATE: sing-wireguard stack device)"))
            }
            IP_STACK_MIPS => {
                let mtu =
                    u16::try_from(mtu).map_err(|_| anyhow!("wireguard stack: MTU must be between 68 and 65535"))?;
                // The congestion controller is validated by `IpStackOption::validate` but has no
                // seam in the smoltcp stack, so the stack's own default runs instead.
                let (stack, packets) = Stack::with_packet_handle(StackConfig { local_addresses, mtu })
                    .map_err(|err| anyhow!("create IP stack: {err}"))?;
                Ok(Arc::new(ComponentIpStack { stack, packets }))
            }
            _ => Err(anyhow!("invalid IP stack mode")),
        }
    }

    #[async_trait]
    impl IpStack for ComponentIpStack {
        async fn start(&self) -> Result<()> {
            // The driver task is spawned by `Stack::with_packet_handle`; there is nothing to
            // start later, and the consumers still call this and check the error.
            Ok(())
        }

        async fn dial_tcp(
            &self,
            _ctx: &CancellationToken,
            network: &str,
            source: SocketAddr,
            destination: SocketAddr,
        ) -> Result<Box<dyn NetConn>> {
            check_network(network, "tcp", Some(destination.ip()))?;
            let conn = self.stack.dial_tcp(source_option(source), destination).await?;
            Ok(Box::new(StreamAsOldConn::new(conn)))
        }

        async fn dial_udp(
            &self,
            _ctx: &CancellationToken,
            network: &str,
            source: SocketAddr,
            destination: SocketAddr,
        ) -> Result<Box<dyn NetConn>> {
            check_network(network, "udp", Some(destination.ip()))?;
            let conn = self.stack.dial_udp(source_option(source), destination).await?;
            // The stack's UDP dial answers a connected socket; a datagram socket fixed to one peer
            // is what this adapter has for that shape.
            let packets: Arc<dyn NetPacketConn> = Arc::new(DatagramAsOldPacketConn(conn));
            Ok(Box::new(StreamAsOldConn::new(new_bind_packet_conn(packets, destination))))
        }

        async fn listen_udp(
            &self,
            _ctx: &CancellationToken,
            network: &str,
            local: SocketAddr,
        ) -> Result<Box<dyn NetPacketConn>> {
            check_network(network, "udp", Some(local.ip()))?;
            let conn = self.stack.listen_udp(source_option(local)).await?;
            Ok(Box::new(DatagramAsOldPacketConn(conn)))
        }

        fn read(&self, buffers: &mut [Vec<u8>], sizes: &mut [usize], offset: usize) -> Result<usize> {
            let limit = buffers.len().min(sizes.len()).min(self.batch_size());
            let mut count = 0;
            for (index, (buffer, size_slot)) in buffers.iter_mut().zip(sizes.iter_mut()).take(limit).enumerate() {
                let length = buffer.len();
                let packet = buffer
                    .get_mut(offset..)
                    .ok_or_else(|| anyhow!("read offset {offset} is past the {length} byte buffer {index}"))?;
                let size = if index == 0 {
                    wait_for_packet(|| self.packets.read(packet)).map_err(|_| closed_device())?
                } else {
                    // Only the first packet waits: a batch is whatever is already queued.
                    match self.packets.try_read(packet).map_err(|_| closed_device())? {
                        Some(size) => size,
                        None => break,
                    }
                };
                *size_slot = size;
                count = index + 1;
            }
            Ok(count)
        }

        fn write(&self, buffers: &[Vec<u8>], offset: usize) -> Result<usize> {
            let limit = buffers.len().min(self.batch_size());
            let mut count = 0;
            for (index, buffer) in buffers.iter().take(limit).enumerate() {
                let packet = buffer
                    .get(offset..)
                    .ok_or_else(|| anyhow!("write offset {offset} is past the {} byte buffer {index}", buffer.len()))?;
                self.packets.write(packet).map_err(|_| closed_device())?;
                count += 1;
            }
            Ok(count)
        }

        fn mtu(&self) -> Result<u32> {
            let mtu = self.stack.mtu();
            u32::try_from(mtu).map_err(|_| anyhow!("stack MTU {mtu} does not fit in 32 bits"))
        }

        fn name(&self) -> Result<String> {
            Ok("murmur IP stack".to_owned())
        }

        fn batch_size(&self) -> usize {
            DEVICE_BATCH_SIZE
        }

        fn close(&self) -> Result<()> {
            self.stack.close();
            Ok(())
        }
    }

    /// The closed-device error the contract [`IpStack::read`]/[`IpStack::write`] owes;
    /// `openvpn::is_os_closed` matches on it to drop the teardown log line.
    fn closed_device() -> anyhow::Error {
        anyhow::Error::new(ErrOsClosed)
    }

    /// Waits inside `IpStack::read`, whose packet loops call it from a spawned task. On a
    /// multi-threaded runtime the worker goes back to the scheduler and only the task is parked;
    /// anywhere else the thread simply blocks.
    fn wait_for_packet<T>(wait: impl FnOnce() -> T) -> T {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(wait)
            }
            _ => wait(),
        }
    }

    /// the `net` network names carry an optional family suffix (`tcp4`, `udp6`); the address is
    /// already resolved, so the suffix only has to agree with it. An unspecified address is the
    /// family-agnostic wildcard the IP stack contract promises.
    fn check_network(network: &str, protocol: &str, address: Option<IpAddr>) -> Result<()> {
        let family = match network.strip_prefix(protocol) {
            Some("") => return Ok(()),
            Some("4") => 4,
            Some("6") => 6,
            _ => return Err(anyhow!("invalid network {network:?}")),
        };
        match address {
            Some(address) if !address.is_unspecified() && (family == 4) != address.is_ipv4() => {
                return Err(anyhow!("invalid network {network:?} for address {address}"));
            }
            _ => {}
        }
        Ok(())
    }

    /// A zero source address means "let the stack pick".
    fn source_option(source: SocketAddr) -> Option<SocketAddr> {
        if source.ip().is_unspecified() {
            None
        } else {
            Some(source)
        }
    }

    pub(crate) struct IpStackNetDialer {
        pub(crate) stack: Arc<dyn IpStack>,
    }

    #[async_trait]
    impl NetDialer for IpStackNetDialer {
        async fn dial_context(
            &self,
            ctx: &CancellationToken,
            network: &str,
            address: &str,
        ) -> Result<Box<dyn murmur_common_net::io::Stream>> {
            let dst: SocketAddr = address.parse().map_err(|e| anyhow!("invalid address {address:?}: {e}"))?;
            let conn = if network.starts_with("tcp") {
                self.stack
                    .dial_tcp(ctx, network, SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0), dst)
                    .await
            } else if network.starts_with("udp") {
                self.stack
                    .dial_udp(ctx, network, SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0), dst)
                    .await
            } else {
                Err(anyhow!("invalid network {network:?}"))
            }?;
            Ok(Box::new(murmur_common_net::io::OldConnAsStream(conn)))
        }
    }
}

#[cfg(test)]
mod ip_stack_tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::{Arc, LazyLock, Mutex};
    use std::time::Duration;

    use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
    use smoltcp::phy::{self, DeviceCapabilities, Medium};
    use smoltcp::socket::{tcp, udp};
    use smoltcp::time::Instant as SmolInstant;
    use smoltcp::wire::{HardwareAddress, IpCidr, IpListenEndpoint, Ipv4Address, Ipv4Cidr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    use murmur_common::errors::{error_is, ErrOsClosed};

    use super::ip_stack::*;

    const CLIENT_PREFIX: &str = "10.0.0.2/32";
    const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const MTU: u32 = 1408;
    const ECHO_PORT: u16 = 8080;
    const PAYLOAD: &[u8] = b"ip-stack-util-e2e";
    const TIMEOUT: Duration = Duration::from_secs(20);

    fn unspecified() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }

    fn destination() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(SERVER_IP), ECHO_PORT)
    }

    /// The option each consumer normalizes before calling `new_ip_stack`.
    fn auto_option() -> IpStackOption {
        let mut option = IpStackOption::default();
        option.normalize();
        option.validate().expect("the default IP stack option is valid");
        option
    }

    fn new_client_stack() -> Arc<dyn IpStack> {
        new_ip_stack(auto_option(), vec![CLIENT_PREFIX.parse().expect("client prefix")], MTU)
            .expect("the mips stack must build")
    }

    static ORIGIN: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);

    fn now() -> SmolInstant {
        SmolInstant::from_millis(ORIGIN.elapsed().as_millis() as i64)
    }

    /// One direction of the wire between the stack and the peer host.
    #[derive(Default)]
    struct Wire(Mutex<VecDeque<Vec<u8>>>);

    impl Wire {
        fn push(&self, packet: Vec<u8>) {
            if let Ok(mut queue) = self.0.lock() {
                queue.push_back(packet);
            }
        }

        fn pop(&self) -> Option<Vec<u8>> {
            self.0.lock().ok()?.pop_front()
        }
    }

    struct HostRx<'a>(&'a [u8]);

    impl phy::RxToken for HostRx<'_> {
        fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
            f(self.0)
        }
    }

    struct HostTx(Arc<Wire>);

    impl phy::TxToken for HostTx {
        fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
            let mut buffer = vec![0u8; len];
            let result = f(&mut buffer);
            self.0.push(buffer);
            result
        }
    }

    struct HostDevice {
        inbound: Arc<Wire>,
        outbound: Arc<Wire>,
        mtu: usize,
        scratch: Vec<u8>,
    }

    impl phy::Device for HostDevice {
        type RxToken<'a> = HostRx<'a>;
        type TxToken<'a> = HostTx;

        fn receive(&mut self, _timestamp: SmolInstant) -> Option<(HostRx<'_>, HostTx)> {
            let packet = self.inbound.pop()?;
            let len = packet.len().min(self.scratch.len());
            self.scratch[..len].copy_from_slice(&packet[..len]);
            Some((HostRx(&self.scratch[..len]), HostTx(Arc::clone(&self.outbound))))
        }

        fn transmit(&mut self, _timestamp: SmolInstant) -> Option<HostTx> {
            Some(HostTx(Arc::clone(&self.outbound)))
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut capabilities = DeviceCapabilities::default();
            capabilities.medium = Medium::Ip;
            capabilities.max_transmission_unit = self.mtu;
            capabilities
        }
    }

    /// The peer inside the tunnel: a smoltcp host that echoes on `ECHO_PORT` over TCP and UDP,
    /// as the wireguard adapter's end-to-end test does.
    fn spawn_echo_host() -> (Arc<Wire>, Arc<Wire>, tokio::task::JoinHandle<()>) {
        let inbound = Arc::new(Wire::default());
        let outbound = Arc::new(Wire::default());
        let mtu = usize::try_from(MTU).expect("MTU fits usize");
        let mut device =
            HostDevice { inbound: Arc::clone(&inbound), outbound: Arc::clone(&outbound), mtu, scratch: vec![0u8; mtu] };
        let task = tokio::spawn(async move {
            let mut iface = Interface::new(IfaceConfig::new(HardwareAddress::Ip), &mut device, now());
            iface.update_ip_addrs(|addresses| {
                let octets = SERVER_IP.octets();
                let _ = addresses.push(IpCidr::Ipv4(Ipv4Cidr::new(
                    Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]),
                    32,
                )));
            });
            iface.routes_mut().add_default_ipv4_route(Ipv4Address::UNSPECIFIED).expect("default route");
            let mut sockets = SocketSet::new(vec![]);
            let tcp_handle = sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
                tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
            ));
            let udp_handle = sockets.add(udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 64 * 1024]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 64 * 1024]),
            ));
            loop {
                {
                    let socket: &mut tcp::Socket = sockets.get_mut(tcp_handle);
                    if !socket.is_open() {
                        let _ = socket.listen(IpListenEndpoint { addr: None, port: ECHO_PORT });
                    }
                }
                {
                    let socket: &mut udp::Socket = sockets.get_mut(udp_handle);
                    if !socket.is_open() {
                        let _ = socket.bind(IpListenEndpoint { addr: None, port: ECHO_PORT });
                    }
                }
                iface.poll(now(), &mut device, &mut sockets);
                let socket: &mut tcp::Socket = sockets.get_mut(tcp_handle);
                while socket.can_recv() {
                    let mut buffer = [0u8; 4096];
                    match socket.recv_slice(&mut buffer) {
                        Ok(size) if size != 0 => {
                            if socket.send_slice(&buffer[..size]).is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                let socket: &mut udp::Socket = sockets.get_mut(udp_handle);
                while socket.can_recv() {
                    let mut buffer = [0u8; 4096];
                    match socket.recv_slice(&mut buffer) {
                        Ok((size, meta)) if size != 0 => {
                            if socket.send_slice(&buffer[..size], meta.endpoint).is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        (inbound, outbound, task)
    }

    /// What the stack transmitted, into the peer host's queue. The blocking read is the surface
    /// the OpenVPN and MASQUE packet loops use.
    async fn relay_stack_to_host(stack: Arc<dyn IpStack>, inbound: Arc<Wire>) -> anyhow::Result<()> {
        let mut buffers = vec![vec![0u8; 65_535]];
        let mut sizes = vec![0usize];
        loop {
            let count = stack.read(&mut buffers, &mut sizes, 0)?;
            for index in 0..count {
                inbound.push(buffers[index][..sizes[index]].to_vec());
            }
        }
    }

    /// What the peer host transmitted, back into the stack.
    fn spawn_host_to_stack(stack: Arc<dyn IpStack>, outbound: Arc<Wire>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                while let Some(packet) = outbound.pop() {
                    if stack.write(&[packet], 0).is_err() {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn new_ip_stack_dials_tcp_through_the_packet_surface() {
        let stack = new_client_stack();
        let (inbound, outbound, host) = spawn_echo_host();
        let relay = tokio::spawn(relay_stack_to_host(Arc::clone(&stack), inbound));
        let writer = spawn_host_to_stack(Arc::clone(&stack), outbound);

        let mut conn = tokio::time::timeout(
            TIMEOUT,
            stack.dial_tcp(&CancellationToken::new(), "tcp", unspecified(), destination()),
        )
        .await
        .expect("the dial must not hang")
        .expect("the stack must dial the peer host");

        conn.write_all(PAYLOAD).await.expect("write payload");
        let mut received = vec![0u8; PAYLOAD.len()];
        tokio::time::timeout(TIMEOUT, conn.read_exact(&mut received))
            .await
            .expect("the echo must arrive")
            .expect("read the echo");
        assert_eq!(received, PAYLOAD);

        assert_eq!(stack.mtu().expect("mtu"), MTU);
        assert_eq!(stack.name().expect("name"), "murmur IP stack");
        assert_eq!(stack.batch_size(), 64);

        stack.close().expect("close");
        let error = relay.await.expect("relay task").expect_err("a closed stack must fail its reads");
        assert!(error_is::<ErrOsClosed>(&error), "closed stack must report a closed-device error, got {error}");
        writer.abort();
        host.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn new_ip_stack_dials_udp_through_the_packet_surface() {
        let stack = new_client_stack();
        let (inbound, outbound, host) = spawn_echo_host();
        let relay = tokio::spawn(relay_stack_to_host(Arc::clone(&stack), inbound));
        let writer = spawn_host_to_stack(Arc::clone(&stack), outbound);

        let mut conn = tokio::time::timeout(
            TIMEOUT,
            stack.dial_udp(&CancellationToken::new(), "udp", unspecified(), destination()),
        )
        .await
        .expect("the dial must not hang")
        .expect("the stack must dial the peer host");

        conn.write_all(PAYLOAD).await.expect("write payload");
        let mut received = vec![0u8; PAYLOAD.len()];
        tokio::time::timeout(TIMEOUT, conn.read_exact(&mut received))
            .await
            .expect("the echo must arrive")
            .expect("read the echo");
        assert_eq!(received, PAYLOAD);

        stack.close().expect("close");
        let error = relay.await.expect("relay task").expect_err("a closed stack must fail its reads");
        assert!(error_is::<ErrOsClosed>(&error), "closed stack must report a closed-device error, got {error}");
        writer.abort();
        host.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn new_ip_stack_listen_udp_serves_the_generic_wildcard() {
        let stack = new_client_stack();
        let conn =
            stack.listen_udp(&CancellationToken::new(), "udp", unspecified()).await.expect("the wildcard must bind");
        let local = conn.local_addr().expect("local address");
        let local = local.addr_port().expect("a bound address port");
        assert_ne!(local.port, 0, "a bound wildcard must have a real port");
        stack.close().expect("close");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn new_ip_stack_fails_closed_for_the_backends_that_are_not_implemented() {
        let prefixes = vec![CLIENT_PREFIX.parse().expect("client prefix")];

        let error =
            new_ip_stack(IpStackOption { mode: "gvisor".to_owned(), ..Default::default() }, prefixes.clone(), MTU)
                .err()
                .expect("the gVisor stack device is not implemented");
        assert!(error.to_string().contains("NEEDED CRATE: sing-wireguard stack device"), "{error}");

        let error = new_ip_stack(
            IpStackOption { mode: "MIPS".to_owned(), congestion_controller: "reno".to_owned() },
            prefixes.clone(),
            MTU,
        )
        .err()
        .expect("an unnormalized mode is not accepted either");
        assert!(error.to_string().contains("invalid IP stack mode"), "{error}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn new_ip_stack_validates_the_mtu() {
        let prefixes = vec![CLIENT_PREFIX.parse().expect("client prefix")];

        let error = new_ip_stack(auto_option(), prefixes.clone(), 1).err().expect("MTU 1 is below the floor");
        assert!(error.to_string().contains("wireguard stack: MTU must be between 68 and 65535"), "{error}");

        let error = new_ip_stack(auto_option(), prefixes.clone(), 70_000).err().expect("MTU 70000 is above the cap");
        assert!(error.to_string().contains("wireguard stack: MTU must be between 68 and 65535"), "{error}");

        let ipv6 = vec!["fd00::2/128".parse().expect("ipv6 prefix")];
        let error = new_ip_stack(auto_option(), ipv6, 1_000).err().expect("IPv6 needs at least 1280");
        assert!(error.to_string().contains("IPv6 requires an MTU of at least 1280"), "{error}");

        // Zero means the stack's 1500, and the address family the suffixes no longer need.
        let stack = new_ip_stack(auto_option(), prefixes, 0).expect("MTU 0 defaults");
        assert_eq!(stack.mtu().expect("mtu"), 1_500);
    }

    /// The two outbounds that build a stack: MASQUE defaults to a 1280 MTU, OpenVPN to 1500, and
    /// both hand `new_ip_stack` the prefixes the server pushed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn new_ip_stack_serves_the_consumers_prefix_and_mtu_shapes() {
        for (prefix, mtu) in [("10.8.0.2/24", 1_500_u32), ("10.0.0.2/32", 1_280), ("fd00::2/128", 1_280)] {
            let stack = new_ip_stack(auto_option(), vec![prefix.parse().expect("prefix")], mtu)
                .unwrap_or_else(|err| panic!("{prefix} at MTU {mtu} must build: {err}"));
            assert_eq!(stack.mtu().expect("mtu"), mtu);
            stack.close().expect("close");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn new_ip_stack_rejects_a_network_the_stack_cannot_serve() {
        let stack = new_client_stack();
        let ctx = CancellationToken::new();

        let error = stack
            .dial_tcp(&ctx, "tcp6", unspecified(), destination())
            .await
            .err()
            .expect("tcp6 cannot dial an IPv4 destination");
        assert!(error.to_string().contains("invalid network \"tcp6\""), "{error}");

        let error = stack
            .dial_udp(&ctx, "icmp", unspecified(), destination())
            .await
            .err()
            .expect("icmp is not a dialable network");
        assert!(error.to_string().contains("invalid network \"icmp\""), "{error}");

        let error = new_ip_stack(auto_option(), vec![CLIENT_PREFIX.parse().expect("prefix")], MTU)
            .expect("stack")
            .dial_tcp(&ctx, "tcp", unspecified(), SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80))
            .await
            .err()
            .expect("the stack holds no IPv6 address");
        assert!(error.to_string().contains("no local address"), "{error}");
        stack.close().expect("close");
    }
}

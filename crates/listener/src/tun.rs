//! A whole userspace network stack: the device is created here, TCP, UDP and ICMP are terminated
//! on top of it, and the stack calls back into the listener handler for each flow.
//!
//! The device and the handler wiring live here: TCP terminates in `murmur-component-wireguard`'s
//! smoltcp stack, driven from the device's own packets by [`tcp`], and UDP datagrams are forwarded
//! directly. An ICMP echo is answered with a synthesised reply whenever `disable-icmp-forwarding`
//! is set.

use portable_atomic::AtomicU64;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use ipnet::IpNet;

use murmur_adapter_inbound::addition::{with_in_name, with_special_rules, Addition};
use murmur_adapter_inbound::packet::new_packet;
use murmur_constant::listener::Listener as ConstListener;
use murmur_constant::metadata::Type;
use murmur_constant::tun::{TunStack, INTERFACE_NAME};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::tun::Tun as TunConfig;
use murmur_log::{errorln, infoln, warnln};

mod default_routes;
pub mod device;
pub mod fragment;
#[cfg(target_os = "linux")]
pub mod netlink_linux;
pub mod packet;
pub mod tcp;

use device::{Cleanup, Device, PacketDevice, TunAddresses, MAX_PACKET_SIZE};
use packet::DeviceWriter as _;

/// A rejected packet is reported a few times and then only counted, so a sender repeating a shape
/// this listener will not carry cannot turn it into a log flood.
const MAX_REPORTED_REJECTS: u64 = 8;

pub struct Listener {
    addr: String,
    /// The address the TUN itself answers on, which is what a packet's `in_addr` reports.
    local: Option<IpAddr>,
    device: Mutex<Option<Arc<dyn PacketDevice>>>,
    cleanup: Mutex<Cleanup>,
    tcp: Arc<tcp::TcpForwarder>,
    mtu: u16,
    closed: AtomicBool,
    ctx: CancellationToken,
    rejected: AtomicU64,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Listener")
            .field("addr", &self.addr)
            .field("local", &self.local)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("rejected", &self.rejected.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Everything the config asks for that this crate cannot do is refused by name first, before a
/// device exists, so a rejected config leaves the host's routing table exactly as it was.
#[expect(
    clippy::unused_async,
    reason = "the listeners are constructed and awaited uniformly from `apply_config`; the device open is synchronous"
)]
pub async fn new(config: TunConfig, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) -> Result<Arc<Listener>> {
    reject_unsupported(&config)?;

    let additions =
        if additions.is_empty() { vec![with_in_name("DEFAULT-TUN"), with_special_rules("")] } else { additions };
    let mut config = config;
    config.enable = true;
    let requested =
        if config.device.is_empty() { calculate_interface_name(INTERFACE_NAME) } else { config.device.clone() };

    let addresses = tun_addresses(&config)?;
    if config.auto_route {
        let when =
            if config.auto_route_delay == 0 { "now".to_owned() } else { format!("in {}s", config.auto_route_delay) };
        infoln!(
            "tun auto-route installs metric-less default routes via {requested} {when}, which outrank a metric-bearing \
             uplink default; current default: {}",
            default_routes::describe()
        );
    }
    // An adopted device belongs to whoever created it: this process configured nothing on it and
    // installs no routes there, exactly as before.
    let owned = config.file_descriptor == 0;
    let (device, mut cleanup) = Device::open(&requested, config.file_descriptor, &addresses)?;
    if owned && config.auto_route_delay == 0 {
        if let Some((_, err)) = device.install_routes(&addresses.routes, &mut cleanup).into_iter().next() {
            let _ = cleanup.revert();
            return Err(err);
        }
    }
    let addr = format!(
        "{}({},{}), mtu: {}, auto route: {}, auto redir: {}, ip stack: {}",
        if config.file_descriptor == 0 {
            device.name().to_owned()
        } else {
            format!("{}(fd={})", device.name(), config.file_descriptor)
        },
        format_prefixes(&config.inet4_address),
        format_prefixes(&config.inet6_address),
        config.tun_mtu(),
        config.auto_route,
        config.auto_redirect,
        config.stack,
    );
    let packet_device: Arc<dyn PacketDevice> = Arc::<Device>::clone(&device);
    let listener = serve(&config, addr, packet_device, cleanup, tunnel, additions)?;
    if owned && config.auto_route_delay != 0 && !addresses.routes.is_empty() {
        spawn_delayed_routes(Arc::clone(&listener), device, addresses.routes, config.auto_route_delay);
    }
    Ok(listener)
}

/// Waits out the configured delay, then installs the routes unless the listener was closed first.
/// Returns whether the installation ran.
// cancel-safe: dropping the future abandons the sleep and the closure, and no route has been
// installed at that point; the delayed task is only cancelled by the listener's own close.
async fn install_after_delay(delay: u32, ctx: &CancellationToken, install: impl FnOnce()) -> bool {
    tokio::select! {
        () = ctx.cancelled() => false,
        () = tokio::time::sleep(Duration::from_secs(u64::from(delay))) => {
            install();
            true
        }
    }
}

fn spawn_delayed_routes(listener: Arc<Listener>, device: Arc<Device>, routes: Vec<IpNet>, delay: u32) {
    tokio::spawn(async move {
        install_after_delay(delay, &listener.ctx, || listener.install_delayed_routes(&device, &routes)).await;
    });
}

/// The listener from the point the device exists, so a caller that already owns a packet pipe —
/// the tests, which cannot open `/dev/net/tun` — drives the same stack, reader and writer.
fn serve(
    config: &TunConfig,
    addr: String,
    device: Arc<dyn PacketDevice>,
    cleanup: Cleanup,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<Listener>> {
    let local = config.inet4_address.first().map(IpNet::addr).or_else(|| config.inet6_address.first().map(IpNet::addr));
    let mtu =
        u16::try_from(config.tun_mtu()).map_err(|_| anyhow!("tun mtu {} does not fit in 16 bits", config.tun_mtu()))?;
    let local_addresses = {
        let mut addresses = config.inet4_address.clone();
        addresses.extend(config.inet6_address.iter().copied());
        addresses
    };
    let forwarder = tcp::TcpForwarder::new(local_addresses, mtu)?;

    let listener = Arc::new(Listener {
        addr,
        local,
        device: Mutex::new(Some(device)),
        cleanup: Mutex::new(cleanup),
        tcp: forwarder,
        mtu,
        closed: AtomicBool::new(false),
        ctx: CancellationToken::new(),
        rejected: AtomicU64::new(0),
    });

    {
        let writer = Arc::new(DeviceWriter(Arc::clone(&listener)));
        let writer_clone = Arc::clone(&writer);
        let packet_writer: Arc<dyn packet::DeviceWriter> = writer_clone;
        let tcp = Arc::clone(&listener.tcp);
        tcp.spawn_writer(packet_writer);
        tcp.spawn_acceptor(Arc::clone(&tunnel), Arc::new(additions.clone()));
        let reader = Arc::clone(&listener);
        tokio::spawn(async move { read_loop(reader, writer, tunnel, additions).await });
    }

    Ok(listener)
}

/// The TUN options, reduced to what a device acts on. The default routes are the family
/// `0.0.0.0/0` and `::/0` installed on Linux; the sub-range split it uses instead is a
/// Darwin-only choice, and one family is installed only where the TUN has an address in it.
fn tun_addresses(config: &TunConfig) -> Result<TunAddresses> {
    let mut addresses = config.inet4_address.clone();
    addresses.extend(config.inet6_address.iter().copied());

    let mut routes = Vec::new();
    if config.auto_route {
        if !config.inet4_address.is_empty() {
            routes.push(IpNet::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)?);
        }
        if !config.inet6_address.is_empty() {
            routes.push(IpNet::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)?);
        }
        routes.extend(config.inet4_route_address());
        routes.extend(config.inet6_route_address());
    }

    // A route named twice (a default also present in `route-address`, say) is installed once:
    // the second add would fail as already present and look like a partial installation.
    let mut unique = Vec::with_capacity(routes.len());
    for route in routes {
        if !unique.contains(&route) {
            unique.push(route);
        }
    }

    Ok(TunAddresses { mtu: config.tun_mtu(), addresses, routes: unique })
}

/// The options whose behaviour lives in a layer this crate does not have. A config naming one is
/// refused rather than started with the option quietly dropped, which would leave the host
/// routing traffic somewhere the config never asked for.
fn reject_unsupported(config: &TunConfig) -> Result<()> {
    let mut refused = Vec::new();
    reject_stack(config, &mut refused);
    reject_scalars(config, &mut refused);
    reject_flags(config, &mut refused);
    reject_unsupported_lists(config, &mut refused);
    finish_refusal(&refused)
}

fn reject_stack(config: &TunConfig, refused: &mut Vec<String>) {
    match config.stack {
        TunStack::Gvisor | TunStack::Mips => {}
        TunStack::System => refused.push(
            "tun stack `System` is not supported: the system stack hands every flow to the host's own networking stack, \
             and this build carries the packets itself (see README)"
                .to_owned(),
        ),
        TunStack::Mixed => refused.push(
            "tun stack `Mixed` is not supported: the mixed stack is the system stack with the gVisor TCP endpoint over \
             it, and this build has no system stack to mix (see README)"
                .to_owned(),
        ),
    }
}

fn reject_scalars(config: &TunConfig, refused: &mut Vec<String>) {
    if !config.disable_icmp_forwarding {
        refused.push(
            "tun requires `disable-icmp-forwarding: true`: routing an ICMP echo out to its destination needs a raw \
             ICMP socket this build does not open, and without the option pings would be forwarded"
                .to_owned(),
        );
    }
    if config.udp_timeout != 0 {
        refused.push(
            "tun `udp-timeout` is not supported: a datagram's lifetime is the tunnel's UDP NAT entry, not a stack session"
                .to_owned(),
        );
    }
    if config.icmp_timeout != 0 {
        refused.push(
            "tun `icmp-timeout` is not supported: an echo reply is written in the same tick the request is read"
                .to_owned(),
        );
    }
    if config.iproute2_table_index != 0 || config.iproute2_rule_index != 0 {
        refused.push(
            "tun `iproute2-table-index`/`iproute2-rule-index` are not supported: this build installs routes in the main table"
                .to_owned(),
        );
    }
    if !matches!(config.processors_per_channel, 0 | 1) {
        refused.push(format!(
            "tun `processors-per-channel` is not supported at {}: parallel per-channel workers would need a device reader \
             this build does not have, and its single reader and writer per device are one processor per channel (see README)",
            config.processors_per_channel
        ));
    }
}

fn reject_flags(config: &TunConfig, refused: &mut Vec<String>) {
    reject_flag(
        refused,
        "auto-redirect",
        config.auto_redirect,
        "it installs nftables rules and an eBPF cgroup redirect",
    );
    reject_flag(
        refused,
        "auto-detect-interface",
        config.auto_detect_interface,
        "it needs a netlink network monitor this build does not run",
    );
    reject_flag(
        refused,
        "gso",
        config.gso,
        "generic segmentation offload needs the virtio-net header and a stack that reassembles it",
    );
    reject_flag(
        refused,
        "gso-max-size",
        config.gso_max_size != 0,
        "it sizes the batched writes `gso` would enable, and this build writes one packet per call",
    );
    reject_flag(
        refused,
        "recvmsgx",
        config.recvmsgx,
        "it selects the batched recvmsg read path, and this build reads one packet per call",
    );
    reject_flag(
        refused,
        "sendmsgx",
        config.sendmsgx,
        "it selects the batched sendmsg write path, and this build writes one packet per call",
    );
    reject_flag(
        refused,
        "strict-route",
        config.strict_route,
        "it adds unreachable rules for the address families the TUN has no address in",
    );
    reject_flag(
        refused,
        "endpoint-independent-nat",
        config.endpoint_independent_nat,
        "the TUN has no NAT table of its own; the tunnel's UDP NAT table is always endpoint-dependent",
    );
}

/// The options rejected for the shape of the list they carry rather than for a flag, split so each
/// family of checks stays readable next to the reason this crate cannot honour it.
fn reject_unsupported_lists(config: &TunConfig, refused: &mut Vec<String>) {
    reject_route_lists(config, refused);
    reject_flow_filters(config, refused);
    reject_process_filters(config, refused);
    reject_redirect_marks(config, refused);
}

fn reject_route_lists(config: &TunConfig, refused: &mut Vec<String>) {
    reject_non_empty(
        refused,
        "dns-hijack",
        config.dns_hijack.as_deref().unwrap_or(&[]),
        "intercepting a port-53 flow means relaying it through the resolver and blacklisting the TUN's resolver address, and this \
         port's TUN handler wires neither half",
    );
    reject_non_empty(
        refused,
        "route-address-set",
        &config.route_address_set,
        "it resolves a rule provider into an nftables set",
    );
    reject_non_empty(
        refused,
        "route-exclude-address-set",
        &config.route_exclude_address_set,
        "it resolves a rule provider into an nftables set",
    );
    reject_non_empty(
        refused,
        "route-exclude-address",
        &config.route_exclude_address,
        "exclusion needs the private routing table and `ip rule` entries auto-route installs",
    );
    reject_non_empty(
        refused,
        "inet4-route-exclude-address",
        &config.inet4_route_exclude_address,
        "as `route-exclude-address`",
    );
    reject_non_empty(
        refused,
        "inet6-route-exclude-address",
        &config.inet6_route_exclude_address,
        "as `route-exclude-address`",
    );
}

fn reject_flow_filters(config: &TunConfig, refused: &mut Vec<String>) {
    for (name, len) in
        [("include-interface", config.include_interface.len()), ("exclude-interface", config.exclude_interface.len())]
    {
        if len > 0 {
            refused
                .push(format!("tun `{name}` is not supported: it matches the socket behind a flow by netlink lookup"));
        }
    }
    for (name, len) in [
        ("include-uid", config.include_uid.len()),
        ("exclude-uid", config.exclude_uid.len()),
        ("include-uid-range", config.include_uid_range.len()),
        ("exclude-uid-range", config.exclude_uid_range.len()),
    ] {
        if len > 0 {
            refused
                .push(format!("tun `{name}` is not supported: it matches the socket behind a flow by netlink lookup"));
        }
    }
    for (name, len) in [
        ("exclude-src-port", config.exclude_src_port.len()),
        ("exclude-dst-port", config.exclude_dst_port.len()),
        ("exclude-src-port-range", config.exclude_src_port_range.len()),
        ("exclude-dst-port-range", config.exclude_dst_port_range.len()),
    ] {
        if len > 0 {
            refused.push(format!(
                "tun `{name}` is not supported: it is an `ip rule` port match, which needs the routing policy this build does not install"
            ));
        }
    }
}

fn reject_process_filters(config: &TunConfig, refused: &mut Vec<String>) {
    for (name, len) in [
        ("include-android-user", config.include_android_user.len()),
        ("include-package", config.include_package.len()),
        ("exclude-package", config.exclude_package.len()),
    ] {
        if len > 0 {
            refused.push(format!("tun `{name}` is not supported: it is an Android VPN rule"));
        }
    }
    for (name, len) in [
        ("include-mac-address", config.include_mac_address.len()),
        ("exclude-mac-address", config.exclude_mac_address.len()),
    ] {
        if len > 0 {
            refused.push(format!(
                "tun `{name}` is not supported: a TUN device is layer 3 and carries no hardware address"
            ));
        }
    }
    if !config.loopback_address.is_empty() {
        refused.push(
            "tun `loopback-address` is not supported: it asks the system stack to add loopback addresses the TUN does not own"
                .to_owned(),
        );
    }
}

fn reject_redirect_marks(config: &TunConfig, refused: &mut Vec<String>) {
    if config.auto_redirect_input_mark != 0 || config.auto_redirect_output_mark != 0 {
        refused.push(
            "tun `auto-redirect-input-mark`/`auto-redirect-output-mark` belong to auto-redirect, which is not supported"
                .to_owned(),
        );
    }
    if config.auto_redirect_iproute2_fallback_rule_index != 0 {
        refused.push(
            "tun `auto-redirect-iproute2-fallback-rule-index` belongs to auto-redirect, which is not supported"
                .to_owned(),
        );
    }
}

fn finish_refusal(refused: &[String]) -> Result<()> {
    if refused.is_empty() {
        return Ok(());
    }
    let mut message = String::from("tun configuration names options this build cannot honour:");
    for reason in refused {
        message.push_str("\n  - ");
        message.push_str(reason);
    }
    bail!(message)
}

fn reject_flag(refused: &mut Vec<String>, name: &str, value: bool, why: &str) {
    if value {
        refused.push(format!("tun `{name}` is not supported: {why} (see README)"));
    }
}

fn reject_non_empty<T>(refused: &mut Vec<String>, name: &str, value: &[T], why: &str) {
    if !value.is_empty() {
        refused.push(format!("tun `{name}` is not supported: {why} (see README)"));
    }
}

/// Derives the interface name from the configured prefix.
///
/// The caller only ever reaches this with a non-empty prefix, in which case the name is used
/// exactly as written; the indexed form is what a config naming the bare platform prefix would
/// get.
#[must_use]
pub fn calculate_interface_name(name: &str) -> String {
    if cfg!(target_os = "macos") {
        return "utun".to_owned();
    }
    if !name.is_empty() {
        return name.to_owned();
    }
    let prefix = "tun";
    let mut taken: Vec<u16> = Vec::new();
    for interface in std::fs::read_dir("/sys/class/net").into_iter().flatten().flatten() {
        let Some(interface) = interface.file_name().into_string().ok() else { continue };
        if let Some(suffix) = interface.strip_prefix(prefix).and_then(|s| s.parse::<u16>().ok()) {
            taken.push(suffix);
        }
    }
    format!("{prefix}{}", next_free_index(&taken))
}

/// the index loop: the first gap in the sorted, de-duplicated set of suffixes already in use.
fn next_free_index(taken: &[u16]) -> u16 {
    let mut sorted = taken.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut index: u16 = 0;
    for used in sorted {
        if used == index {
            index += 1;
        } else {
            break;
        }
    }
    index
}

fn format_prefixes(prefixes: &[IpNet]) -> String {
    let list: Vec<String> = prefixes.iter().map(ToString::to_string).collect();
    format!("[{}]", list.join(" "))
}

/// Gives the packet writer the device without the reader task holding a `parking_lot` guard across
/// an await, which would not be `Send`.
struct DeviceWriter(Arc<Listener>);

#[async_trait::async_trait]
impl packet::DeviceWriter for DeviceWriter {
    /// NOT cancel-safe: the `AsyncFd` readiness future is dropped mid-poll. A TUN write is a
    /// single whole-packet syscall, so a drop either has not issued it or has already completed
    /// it — there is no half-written packet left on the device.
    async fn write_packet(&self, packet: &[u8]) -> std::io::Result<()> {
        let device = self.0.device.lock().clone();
        match device {
            Some(device) => device.write(packet).await,
            None => Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
        }
    }
}

async fn read_loop(
    listener: Arc<Listener>,
    writer: Arc<DeviceWriter>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) {
    let Some(device) = listener.device.lock().clone() else { return };
    let Some(local) = listener.local else { return };
    let mut buf = vec![0u8; MAX_PACKET_SIZE];
    let mut fragments = fragment::FragmentCache::new();
    loop {
        if listener.ctx.is_cancelled() {
            return;
        }
        let read = match device.read(&mut buf).await {
            Ok(read) => read,
            Err(err) if is_closed(&err) => return,
            Err(_) => {
                if listener.ctx.is_cancelled() {
                    return;
                }
                continue;
            }
        };
        if read == 0 {
            return;
        }
        let Some(raw) = buf.get(..read) else { return };
        let outcome = fragments.feed(raw, std::time::Instant::now());
        let whole: &[u8] = match &outcome {
            fragment::FragmentOutcome::NotFragmented => raw,
            fragment::FragmentOutcome::Complete(packet) => packet,
            fragment::FragmentOutcome::Pending => continue,
            fragment::FragmentOutcome::Dropped(reason) => {
                let seen = listener.rejected.fetch_add(1, Ordering::Relaxed) + 1;
                if seen <= MAX_REPORTED_REJECTS {
                    warnln!("[TUN] dropping fragment: {reason}");
                }
                continue;
            }
        };
        if let Err(err) = dispatch(whole, local, &writer, &tunnel, &additions, &listener.tcp, listener.mtu).await {
            let seen = listener.rejected.fetch_add(1, Ordering::Relaxed) + 1;
            if seen <= MAX_REPORTED_REJECTS {
                warnln!("[TUN] dropping packet: {err}");
            }
        }
    }
}

fn is_closed(err: &std::io::Error) -> bool {
    matches!(err.kind(), std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::NotConnected)
}

async fn dispatch(
    raw: &[u8],
    local: IpAddr,
    writer: &Arc<DeviceWriter>,
    tunnel: &Arc<dyn Tunnel>,
    additions: &[Addition],
    forwarder: &tcp::TcpForwarder,
    mtu: u16,
) -> Result<()> {
    let parsed = packet::parse(raw)?;
    match parsed.transport {
        packet::Transport::Udp(udp) => {
            let flow =
                packet::Flow { src: parsed.src, dst: parsed.dst, src_port: udp.src_port, dst_port: udp.dst_port };
            let target = murmur_transport::socks5::socks5::addr_from_std_addr_port(std::net::SocketAddr::new(
                flow.dst,
                flow.dst_port,
            ));
            let packet_writer = Arc::clone(writer);
            let packet = Arc::new(packet::TunPacket::new(packet_writer, flow, udp.payload.to_vec(), local, mtu));
            let (packet, metadata) = new_packet(&target, packet, Type::TUN, additions);
            tunnel.handle_udp_packet(packet, metadata);
            Ok(())
        }
        packet::Transport::Icmp { .. } | packet::Transport::IcmpV6 { .. } => {
            match packet::icmp_echo_reply(raw, &parsed) {
                Some(reply) => {
                    writer.write_packet(&reply).await?;
                    Ok(())
                }
                None => Err(anyhow!("icmp message other than an echo request")),
            }
        }
        packet::Transport::Tcp(segment) => {
            forwarder.forward(raw, parsed.transport.carries_syn(), segment.dst_port).await
        }
        // A protocol with no handler of its own gets the answer a host gives a closed port,
        // rather than a packet that looks carried and goes nowhere.
        packet::Transport::Other { .. } => match packet::icmp_unreachable(raw, &parsed) {
            Some(reply) => {
                writer.write_packet(&reply).await?;
                Ok(())
            }
            None => Err(anyhow!("could not build the ICMP error for this packet")),
        },
    }
}

impl Listener {
    /// How many packets have been dropped for a shape this listener will not carry, for a caller that
    /// needs to know a flow was refused rather than carried.
    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    /// Installs the routes the auto-route delay postponed. The cleanup lock is held while they are
    /// added, so a concurrent `close` either reverts them or finds none: the check of `closed` and
    /// the cancellation token happens under the same lock `close` takes before reverting.
    fn install_delayed_routes(&self, device: &Device, routes: &[IpNet]) {
        let mut cleanup = self.cleanup.lock();
        if self.closed.load(Ordering::SeqCst) || self.ctx.is_cancelled() {
            return;
        }
        let failures = device.install_routes(routes, &mut cleanup);
        if failures.is_empty() {
            infoln!("tun auto-route delay elapsed: installed {} route(s) via {}", routes.len(), device.name());
            return;
        }
        // All-or-nothing: the config asked for the set, and a half-applied set would route one
        // destination into the TUN while the next still leaves directly. The immediately due path
        // refuses the listener outright; at runtime the coherent fallback is no auto routes at all.
        let failed: Vec<IpNet> = failures.iter().map(|(dst, _)| *dst).collect();
        let mut kept = 0usize;
        for dst in routes.iter().filter(|dst| !failed.contains(dst)) {
            match device.remove_route(dst) {
                Ok(()) => cleanup.forget_route(device.index(), dst),
                Err(err) => {
                    kept += 1;
                    errorln!("[TUN] could not remove partially installed route {dst}: {err:#}");
                }
            }
        }
        for (dst, err) in &failures {
            errorln!("[TUN] route {dst} was not installed: {err:#}");
        }
        errorln!(
            "[TUN] auto-route installation failed: {} route(s) not installed, {} partial route(s) removed, {} left",
            failures.len(),
            routes.len() - failures.len() - kept,
            kept
        );
    }
}

impl ConstListener for Listener {
    fn raw_address(&self) -> String {
        self.addr.clone()
    }

    fn address(&self) -> String {
        self.addr.clone()
    }

    /// stops the reader and removes the addresses and routes this device
    /// installed, so a restart does not inherit a route pointing at a device that is gone.
    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        self.ctx.cancel();
        self.tcp.close();
        self.device.lock().take();
        let errs = self.cleanup.lock().revert();
        if errs.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(errs.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")))
        }
    }
}

/// Reports where a TUN listener listens, at the one moment a user is reading it.
pub fn log_startup(addr: &str) {
    infoln!("Tun proxy listening at: {addr}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first gap in the sorted set of numeric suffixes already present is picked, so a host
    /// with `tun0` and `tun2` gets `tun1` rather than `tun3`.
    #[test]
    fn next_free_index_takes_the_first_gap() {
        assert_eq!(next_free_index(&[]), 0);
        assert_eq!(next_free_index(&[0]), 1);
        assert_eq!(next_free_index(&[0, 1]), 2);
        assert_eq!(next_free_index(&[0, 2]), 1);
        assert_eq!(next_free_index(&[1, 2]), 0);
        assert_eq!(next_free_index(&[0, 0, 1, 1, 2]), 3);
    }

    /// The caller always asks for `Meta`, and a non-empty name is returned unchanged rather than
    /// with an index appended.
    #[test]
    fn calculate_interface_name_keeps_a_named_prefix_verbatim() {
        assert_eq!(calculate_interface_name(INTERFACE_NAME), "Meta");
    }

    /// A delay is a real wait: nothing is installed early, the routes are installed once, and a
    /// listener closed during the wait installs nothing.
    #[tokio::test(start_paused = true)]
    async fn delayed_routes_wait_for_the_delay_and_are_skipped_when_closed() {
        let ctx = CancellationToken::new();
        let runs = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&runs);
        let pending = tokio::spawn(async move {
            install_after_delay(3, &ctx, move || {
                counted.fetch_add(1, Ordering::SeqCst);
            })
            .await
        });
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 0, "nothing is installed before the delay");
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(pending.await.unwrap(), "the installation ran");
        assert_eq!(runs.load(Ordering::SeqCst), 1, "the routes are installed once");

        let ctx = CancellationToken::new();
        let cancel = ctx.clone();
        let runs = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&runs);
        let pending = tokio::spawn(async move {
            install_after_delay(30, &ctx, move || {
                counted.fetch_add(1, Ordering::SeqCst);
            })
            .await
        });
        cancel.cancel();
        assert!(!pending.await.unwrap(), "a closed listener installs nothing");
        assert_eq!(runs.load(Ordering::SeqCst), 0);
    }

    /// A config that names an option this crate cannot honour must be refused rather than started
    /// with the option dropped, and the message has to name the option.
    #[test]
    fn unsupported_options_are_refused_by_name() {
        let base = TunConfig {
            disable_icmp_forwarding: true,
            inet4_address: vec!["198.18.0.1/30".parse().unwrap()],
            ..Default::default()
        };
        assert!(reject_unsupported(&base).is_ok());

        for (name, patch) in [
            ("auto-redirect", TunConfig { auto_redirect: true, ..base.clone() }),
            ("gso", TunConfig { gso: true, ..base.clone() }),
            ("strict-route", TunConfig { strict_route: true, ..base.clone() }),
            ("auto-detect-interface", TunConfig { auto_detect_interface: true, ..base.clone() }),
            ("endpoint-independent-nat", TunConfig { endpoint_independent_nat: true, ..base.clone() }),
            ("dns-hijack", TunConfig { dns_hijack: Some(vec!["any:53".into()]), ..base.clone() }),
            ("exclude-uid", TunConfig { exclude_uid: vec![1000], ..base.clone() }),
            ("exclude-dst-port", TunConfig { exclude_dst_port: vec![53], ..base.clone() }),
            ("include-package", TunConfig { include_package: vec!["com.example".into()], ..base.clone() }),
            (
                "include-mac-address",
                TunConfig { include_mac_address: vec!["00:11:22:33:44:55".into()], ..base.clone() },
            ),
            ("loopback-address", TunConfig { loopback_address: vec!["127.0.0.1".parse().unwrap()], ..base.clone() }),
            (
                "route-exclude-address",
                TunConfig { route_exclude_address: vec!["10.0.0.0/8".parse().unwrap()], ..base.clone() },
            ),
            ("route-address-set", TunConfig { route_address_set: vec!["rejects".into()], ..base.clone() }),
            ("iproute2-rule-index", TunConfig { iproute2_rule_index: 9000, ..base.clone() }),
            ("udp-timeout", TunConfig { udp_timeout: 60, ..base.clone() }),
            ("icmp-timeout", TunConfig { icmp_timeout: 30, ..base.clone() }),
            ("recvmsgx", TunConfig { recvmsgx: true, ..base.clone() }),
            ("sendmsgx", TunConfig { sendmsgx: true, ..base.clone() }),
            ("gso-max-size", TunConfig { gso_max_size: 65536, ..base.clone() }),
            ("processors-per-channel", TunConfig { processors_per_channel: 2, ..base.clone() }),
        ] {
            let err = reject_unsupported(&patch).expect_err("option must be refused").to_string();
            assert!(err.contains(name), "the refusal must name `{name}`, got: {err}");
        }
    }

    /// One config can trip several checks, and the startup error must name all of them: a
    /// default `tun:` section used to require one restart per rejected default.
    #[test]
    fn one_refusal_lists_every_offending_option() {
        let config = TunConfig {
            auto_detect_interface: true,
            recvmsgx: true,
            dns_hijack: Some(vec!["0.0.0.0:53".into()]),
            ..Default::default()
        };
        let err = reject_unsupported(&config).expect_err("the default tun section must be refused").to_string();
        for name in ["disable-icmp-forwarding", "auto-detect-interface", "recvmsgx", "dns-hijack"] {
            assert!(err.contains(name), "one refusal must name `{name}`, got: {err}");
        }
    }

    /// The unset value of each of those four options asks for exactly what this build does, so
    /// refusing it would turn every config that leaves it alone into a startup failure.
    #[test]
    fn tun_options_that_match_what_the_port_does_are_accepted() {
        let base = TunConfig {
            disable_icmp_forwarding: true,
            inet4_address: vec!["198.18.0.1/30".parse().unwrap()],
            ..Default::default()
        };
        assert!(reject_unsupported(&base).is_ok(), "unset: single reads and writes, no gso size");

        let one_processor = TunConfig { processors_per_channel: 1, ..base };
        assert!(reject_unsupported(&one_processor).is_ok(), "one processor per channel is what the port runs");
    }

    /// The userspace stack is what `gvisor` and `mips` both name here; `system` and `mixed` need
    /// the host's own stack underneath, and the message says which one was asked for.
    #[test]
    fn only_the_userspace_stacks_are_accepted() {
        for stack in [TunStack::Gvisor, TunStack::Mips] {
            let config = TunConfig { stack, disable_icmp_forwarding: true, ..Default::default() };
            assert!(reject_unsupported(&config).is_ok(), "{stack} is a userspace stack");
        }
        for stack in [TunStack::System, TunStack::Mixed] {
            let config = TunConfig { stack, disable_icmp_forwarding: true, ..Default::default() };
            let err = reject_unsupported(&config).expect_err("stack must be refused").to_string();
            assert!(err.contains(&stack.to_string()), "the refusal must name `{stack}`, got: {err}");
        }
    }

    /// ICMP forwarding is what makes a ping go out to its destination, which needs a raw socket
    /// this crate does not open; without the option a config would silently lose pings instead.
    #[test]
    fn icmp_forwarding_is_refused_rather_than_silently_lost() {
        let err = reject_unsupported(&TunConfig::default()).expect_err("must be refused").to_string();
        assert!(err.contains("disable-icmp-forwarding"), "the refusal must name the option, got: {err}");
    }

    /// `auto-route` installs one default route per address family the TUN has an address in, plus
    /// whatever `route-address` named — the shape the auto-route ranges take on
    /// Linux, where the sub-range split is a Darwin-only choice.
    #[test]
    fn auto_route_installs_one_default_route_per_configured_family() {
        let ipv4_only = tun_addresses(&TunConfig {
            auto_route: true,
            disable_icmp_forwarding: true,
            inet4_address: vec!["198.18.0.1/30".parse().unwrap()],
            ..Default::default()
        })
        .expect("addresses");
        assert_eq!(ipv4_only.routes, vec!["0.0.0.0/0".parse::<IpNet>().unwrap()]);

        let both = tun_addresses(&TunConfig {
            auto_route: true,
            disable_icmp_forwarding: true,
            inet4_address: vec!["198.18.0.1/30".parse().unwrap()],
            inet6_address: vec!["fd00::1/126".parse().unwrap()],
            route_address: vec!["10.0.0.0/8".parse().unwrap()],
            ..Default::default()
        })
        .expect("addresses");
        assert_eq!(
            both.routes,
            vec![
                "0.0.0.0/0".parse::<IpNet>().unwrap(),
                "::/0".parse::<IpNet>().unwrap(),
                "10.0.0.0/8".parse::<IpNet>().unwrap(),
            ]
        );
    }

    /// Without `auto-route` nothing is installed and the host's routing is left to the user, and a
    /// `route-address` naming a destination does not by itself change the routing table.
    #[test]
    fn no_auto_route_installs_no_routes() {
        let addresses = tun_addresses(&TunConfig {
            disable_icmp_forwarding: true,
            inet4_address: vec!["198.18.0.1/30".parse().unwrap()],
            route_address: vec!["10.0.0.0/8".parse().unwrap()],
            ..Default::default()
        })
        .expect("addresses");
        assert!(addresses.routes.is_empty());
        assert_eq!(addresses.addresses, vec!["198.18.0.1/30".parse::<IpNet>().unwrap()]);
    }

    /// The device needs the MTU it will actually run at, not the config's zero, which is
    /// substituted before the options reach the device.
    #[test]
    fn the_device_gets_the_effective_mtu() {
        let address = vec!["198.18.0.1/30".parse::<IpNet>().unwrap()];
        assert_eq!(
            tun_addresses(&TunConfig { inet4_address: address.clone(), ..Default::default() }).expect("addresses").mtu,
            9000
        );
        assert_eq!(
            tun_addresses(&TunConfig { mtu: 1500, inet4_address: address, ..Default::default() })
                .expect("addresses")
                .mtu,
            1500
        );
    }

    mod e2e {
        use std::sync::Arc;
        use std::time::Duration;

        use murmur_common_net::io::Stream;
        use murmur_component_nat::Table;
        use murmur_component_wireguard::{PacketHandle, Stack, StackConfig};
        use murmur_constant::adapters::{NatTable, UDPPacket};
        use murmur_constant::metadata::{Metadata, NetWork};
        use murmur_constant::tunnel::Tunnel;
        use parking_lot::Mutex;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::sync::{mpsc, Mutex as AsyncMutex};

        use super::*;

        const TIMEOUT: Duration = Duration::from_secs(30);
        const CLIENT_ADDRESS: &str = "198.18.0.2/32";
        const TUN_ADDRESS: &str = "198.18.0.1/30";
        const MTU: u32 = 1500;
        const DESTINATION: &str = "203.0.113.7";
        const TCP_PORT: u16 = 443;
        const UDP_PORT: u16 = 53;
        const PAYLOAD: &[u8] = b"tun-e2e";

        /// The host behind the TUN: a second stack whose transmissions are what the device reads,
        /// so the listener is driven by a real handshake rather than a hand-built packet.
        struct HookedDevice {
            inbound: AsyncMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
            client: Arc<PacketHandle>,
            written: Arc<Mutex<Vec<Vec<u8>>>>,
        }

        #[async_trait::async_trait]
        impl PacketDevice for HookedDevice {
            async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
                let mut inbound = self.inbound.lock().await;
                let packet = inbound.recv().await.ok_or_else(closed)?;
                let len = packet.len().min(buf.len());
                buf[..len].copy_from_slice(&packet[..len]);
                Ok(len)
            }

            async fn write(&self, packet: &[u8]) -> std::io::Result<()> {
                self.written.lock().push(packet.to_vec());
                self.client.write(packet)
            }
        }

        fn closed() -> std::io::Error {
            std::io::Error::from(std::io::ErrorKind::NotConnected)
        }

        /// the handler half of the stack, without a proxy behind it: TCP is echoed and its
        /// metadata recorded, a UDP datagram is answered on its own write-back path.
        struct EchoTunnel {
            tcp: mpsc::UnboundedSender<Metadata>,
            udp: mpsc::UnboundedSender<Metadata>,
        }

        #[async_trait::async_trait]
        impl Tunnel for EchoTunnel {
            async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, metadata: Metadata) {
                let _ = self.tcp.send(metadata);
                let mut buf = [0u8; 4096];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if conn.write_all(&buf[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }

            fn handle_udp_packet(&self, packet: Arc<dyn UDPPacket>, metadata: Metadata) {
                let _ = self.udp.send(metadata);
                let source = packet.local_addr();
                tokio::spawn(async move {
                    let _ = packet.write_back(packet.data(), Some(source)).await;
                });
            }

            fn nat_table(&self) -> Arc<dyn NatTable> {
                Arc::new(Table::default())
            }
        }

        struct Harness {
            listener: Arc<Listener>,
            client: Arc<Stack>,
            written: Arc<Mutex<Vec<Vec<u8>>>>,
            tcp_metadata: mpsc::UnboundedReceiver<Metadata>,
            udp_metadata: mpsc::UnboundedReceiver<Metadata>,
            inject: mpsc::UnboundedSender<Vec<u8>>,
        }

        /// A listener over a device the test drives, with the client stack's packets as its wire.
        fn harness() -> Harness {
            let config = TunConfig {
                stack: TunStack::Gvisor,
                disable_icmp_forwarding: true,
                inet4_address: vec![TUN_ADDRESS.parse().expect("tun prefix")],
                mtu: MTU,
                ..Default::default()
            };
            let (client, client_packets) = Stack::with_packet_handle(StackConfig {
                local_addresses: vec![CLIENT_ADDRESS.parse().expect("client prefix")],
                mtu: u16::try_from(MTU).expect("MTU fits"),
            })
            .expect("client stack must build");
            let client_packets = Arc::new(client_packets);
            let (inject, inbound) = mpsc::unbounded_channel();
            let written = Arc::new(Mutex::new(Vec::new()));
            let device = Arc::new(HookedDevice {
                inbound: AsyncMutex::new(inbound),
                client: Arc::clone(&client_packets),
                written: Arc::clone(&written),
            });

            let pump = Arc::clone(&client_packets);
            let to_device = inject.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_PACKET_SIZE];
                loop {
                    let Ok(read) = pump.read_async(&mut buf).await else { return };
                    if to_device.send(buf[..read].to_vec()).is_err() {
                        return;
                    }
                }
            });

            let (tcp, tcp_metadata) = mpsc::unbounded_channel();
            let (udp, udp_metadata) = mpsc::unbounded_channel();
            let tunnel: Arc<dyn Tunnel> = Arc::new(EchoTunnel { tcp, udp });
            let listener = serve(
                &config,
                "Meta(198.18.0.1/30,[]), mtu: 1500, auto route: false, auto redir: false, ip stack: gVisor".to_owned(),
                device,
                Cleanup::default(),
                tunnel,
                Vec::new(),
            )
            .expect("listener must build over the fake device");

            Harness { listener, client, written, tcp_metadata, udp_metadata, inject }
        }

        fn destination(port: u16) -> std::net::SocketAddr {
            format!("{DESTINATION}:{port}").parse().expect("destination")
        }

        /// The TCP forward path end to end: the client's SYN reaches the stack the
        /// listener drives, and the connection it establishes reaches the tunnel.
        #[tokio::test(flavor = "multi_thread")]
        async fn tcp_reaches_the_tunnel_through_the_tun_stack() {
            let mut harness = harness();
            let mut conn = tokio::time::timeout(TIMEOUT, harness.client.dial_tcp(None, destination(TCP_PORT)))
                .await
                .expect("the handshake must not hang")
                .expect("the listener's stack must accept the connection");

            let metadata = tokio::time::timeout(TIMEOUT, harness.tcp_metadata.recv())
                .await
                .expect("the tunnel must be handed the connection")
                .expect("tunnel channel");
            assert_eq!(metadata.dst_ip, Some(DESTINATION.parse::<IpAddr>().expect("destination ip")));
            assert_eq!(metadata.dst_port, TCP_PORT);
            assert_eq!(metadata.src_ip, Some("198.18.0.2".parse::<IpAddr>().expect("client ip")));
            assert_eq!(metadata.src_port, conn.local_addr().expect("client port").port());
            assert_eq!(metadata.network, NetWork::TCP);
            assert_eq!(metadata.type_, Type::TUN);

            conn.write_all(PAYLOAD).await.expect("write the payload");
            let mut echoed = vec![0u8; PAYLOAD.len()];
            tokio::time::timeout(TIMEOUT, conn.read_exact(&mut echoed))
                .await
                .expect("the echo must arrive")
                .expect("read the echo");
            assert_eq!(echoed, PAYLOAD);
            harness.listener.close().expect("close the listener");
        }

        /// the UDP handler path: the datagram reaches the tunnel's `write_back`, and the reply
        /// the listener rebuilds arrives at the client.
        #[tokio::test(flavor = "multi_thread")]
        async fn udp_datagrams_round_trip_through_the_tunnel() {
            let mut harness = harness();
            let conn = tokio::time::timeout(TIMEOUT, harness.client.dial_udp(None, destination(UDP_PORT)))
                .await
                .expect("the bind must not hang")
                .expect("the client stack must bind a datagram socket");

            murmur_common::net::Datagram::send_to(&conn, PAYLOAD, destination(UDP_PORT))
                .await
                .expect("send the datagram");

            let metadata = tokio::time::timeout(TIMEOUT, harness.udp_metadata.recv())
                .await
                .expect("the tunnel must be handed the datagram")
                .expect("tunnel channel");
            assert_eq!(metadata.dst_ip, Some(DESTINATION.parse::<IpAddr>().expect("destination ip")));
            assert_eq!(metadata.dst_port, UDP_PORT);
            assert_eq!(metadata.network, NetWork::UDP);
            assert_eq!(metadata.type_, Type::TUN);

            let mut buf = vec![0u8; 64];
            let (read, from) = tokio::time::timeout(TIMEOUT, murmur_common::net::Datagram::recv_from(&conn, &mut buf))
                .await
                .expect("the reply must arrive")
                .expect("read the reply");
            assert_eq!(&buf[..read], PAYLOAD);
            assert_eq!(from, destination(UDP_PORT));
            harness.listener.close().expect("close the listener");
        }

        /// An echo aimed at the TUN is answered with a synthesised reply rather than forwarded,
        /// which is what `disable-icmp-forwarding` asks for.
        #[tokio::test(flavor = "multi_thread")]
        async fn icmp_echo_is_answered_without_reaching_the_tunnel() {
            let harness = harness();
            let request = echo_request(
                "198.18.0.2".parse::<IpAddr>().expect("client ip"),
                DESTINATION.parse::<IpAddr>().expect("destination ip"),
            );
            harness.inject.send(request.clone()).expect("inject the echo request");

            let reply = tokio::time::timeout(TIMEOUT, async {
                loop {
                    let found = {
                        let written = harness.written.lock();
                        written
                            .iter()
                            .find(|packet| {
                                matches!(packet::parse(packet), Ok(parsed) if matches!(
                                    parsed.transport,
                                    packet::Transport::Icmp { icmp_type: 0, .. }
                                ))
                            })
                            .cloned()
                    };
                    if let Some(echo) = found {
                        return echo;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the echo reply must be written back");

            let parsed = packet::parse(&reply).expect("the reply parses");
            assert_eq!(parsed.src, DESTINATION.parse::<IpAddr>().expect("destination ip"));
            assert_eq!(parsed.dst, "198.18.0.2".parse::<IpAddr>().expect("client ip"));
            let packet::Transport::Icmp { message, .. } = parsed.transport else { panic!("icmp") };
            assert_eq!(&message[8..], &request[28..]);
            assert_eq!(packet::checksum(&[&reply[20..]]), 0, "the reply's checksum must be valid");
            harness.listener.close().expect("close the listener");
        }

        /// An IPv4 ICMP echo request, checksummed: the test's own packets come from the
        /// same client range the client stack uses.
        fn echo_request(src: IpAddr, dst: IpAddr) -> Vec<u8> {
            let (IpAddr::V4(src), IpAddr::V4(dst)) = (src, dst) else { panic!("ipv4") };
            let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
            icmp.extend_from_slice(PAYLOAD);
            let checksum = packet::checksum(&[&icmp]);
            icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
            let mut header = vec![0u8; 20];
            header[0] = 0x45;
            header[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
            header[8] = 64;
            header[9] = 1;
            header[12..16].copy_from_slice(&src.octets());
            header[16..20].copy_from_slice(&dst.octets());
            let header_checksum = packet::checksum(&[&header]);
            header[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            header.extend_from_slice(&icmp);
            header
        }
    }
}

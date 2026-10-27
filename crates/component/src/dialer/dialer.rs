use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::{interval_at, Instant};
use tokio_util::sync::CancellationToken;

use crate::keepalive::tcp_keepalive::set_net_dialer as set_keepalive_net_dialer;
use crate::mptcp::set_net_dialer as set_mptcp_net_dialer;
use crate::resolver::ip4p::lookup_ip4p;
use crate::resolver::resolver::{
    lookup_ip_with_resolver, lookup_ipv4_with_resolver, lookup_ipv6_with_resolver, proxy_server_host_resolver,
    sortation_addr, ResolverRef,
};
use murmur_common::atomic::type_::{new_bool, Bool};
use murmur_common_net::io::{Acceptor, Datagram, Stream};

use super::bind::{
    fallback_bind_iface_to_dialer, fallback_bind_iface_to_listen_config, is4in6, join_host_port, unmap_addr,
};
use super::control::{BasicControlFn, StdDialer, StdListenConfig};
use super::error::{ERROR_INVALIDED_NETWORK_STACK, ERROR_NO_IP_ADDRESS};
use super::options::{
    apply_options, with_option, IpVersion, Options, DEFAULT_INTERFACE, DEFAULT_INTERFACE_FINDER, DEFAULT_ROUTING_MARK,
};
use super::reuse::addr_reuse_to_listen_config;
use super::socket_hook::{default_socket_hook, socket_hook_to_listen_config, socket_hook_to_to_dialer};
use super::tfo::{dial_tfo, DISABLE_TFO};

#[cfg(target_os = "macos")]
use super::bind_darwin::{bind_iface_to_dialer, bind_iface_to_listen_config, parse_network};
#[cfg(target_os = "linux")]
use super::bind_linux::{bind_iface_to_dialer, bind_iface_to_listen_config, parse_network};
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use super::bind_others::{bind_iface_to_dialer, bind_iface_to_listen_config, parse_network};
#[cfg(target_os = "windows")]
use super::bind_windows::{bind_iface_to_dialer, bind_iface_to_listen_config, parse_network};

#[cfg(target_os = "linux")]
use super::mark_linux::{bind_mark_to_dialer, bind_mark_to_listen_config};
#[cfg(not(target_os = "linux"))]
use super::mark_nonlinux::{bind_mark_to_dialer, bind_mark_to_listen_config};

pub const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_UDP_TIMEOUT: Duration = DEFAULT_TCP_TIMEOUT;

const DUAL_STACK_FALLBACK_TIMEOUT: Duration = Duration::from_millis(300);

static TCP_CONCURRENT: Bool = new_bool(false);

pub fn set_tcp_concurrent(concurrent: bool) {
    TCP_CONCURRENT.store(concurrent);
}

pub fn get_tcp_concurrent() -> bool {
    TCP_CONCURRENT.load()
}

pub async fn dial_context(
    ctx: &CancellationToken,
    network: &str,
    address: &str,
    options: Vec<super::options::Option>,
) -> anyhow::Result<Box<dyn Stream>> {
    let opt = apply_options(&options);

    let mut network = network.to_owned();
    if opt.network != IpVersion::Any {
        if network.contains("tcp") {
            "tcp".clone_into(&mut network);
        } else {
            "udp".clone_into(&mut network);
        }

        network = format!("{network}{}", opt.network.suffix());
    }

    let (ips, port) = parse_addr(ctx, &network, address, opt.resolver.as_deref()).await?;

    let tcp_concurrent = get_tcp_concurrent();

    match network.as_str() {
        "tcp4" | "tcp6" | "udp4" | "udp6" => {
            if tcp_concurrent {
                parallel_dial_context(ctx, &network, &ips, &port, &opt).await
            } else {
                serial_dial_context(ctx, &network, ips, &port, &opt).await
            }
        }
        "tcp" | "udp" => {
            if tcp_concurrent {
                if opt.prefer == IpVersion::Any {
                    return parallel_dial_context(ctx, &network, &ips, &port, &opt).await;
                }
                dual_stack_dial_context(ctx, DialKind::Parallel, &network, &ips, &port, &opt).await
            } else {
                dual_stack_dial_context(ctx, DialKind::Serial, &network, &ips, &port, &opt).await
            }
        }
        _ => Err(ERROR_INVALIDED_NETWORK_STACK.into()),
    }
}

pub async fn listen_packet(
    ctx: &CancellationToken,
    network: &str,
    address: &str,
    r_addr_port: Option<SocketAddr>,
    options: Vec<super::options::Option>,
) -> anyhow::Result<Box<dyn Datagram>> {
    let opt = apply_options(&options);

    let (lc, address) = listen_config(network, address, r_addr_port, &opt).await?;
    lc.listen_packet(ctx, network, &address).await
}

/// Shares `listen_packet`'s socket policy.
pub async fn listen(
    ctx: &CancellationToken,
    network: &str,
    address: &str,
    options: Vec<super::options::Option>,
) -> anyhow::Result<Box<dyn Acceptor>> {
    let (lc, address) = listen_config(network, address, None, &apply_options(&options)).await?;
    lc.listen(ctx, network, &address).await
}

async fn listen_config(
    network: &str,
    address: &str,
    r_addr_port: Option<SocketAddr>,
    opt: &Options,
) -> anyhow::Result<(StdListenConfig, String)> {
    let mut lc = StdListenConfig::default();
    let mut opt = opt.clone();
    let mut address = address.to_owned();

    if opt.addr_reuse {
        addr_reuse_to_listen_config(&mut lc);
    }
    if default_socket_hook().is_some() {
        // ignore interfaceName, routingMark when DefaultSocketHook not null (in CMFA)
        socket_hook_to_listen_config(&mut lc);
    } else {
        if opt.interface_name.is_empty() {
            opt.interface_name = DEFAULT_INTERFACE.load();
        }
        if opt.interface_name.is_empty() {
            if let Some(finder) = DEFAULT_INTERFACE_FINDER.load() {
                opt.interface_name =
                    finder.find_interface_name(unmap_addr(r_addr_port.map(|addr_port| addr_port.ip())));
            }
        }
        if unmap_addr(r_addr_port.map(|addr_port| addr_port.ip())).is_some_and(|ip| ip.is_loopback())
            || listen_address_is_loopback(&address)
        {
            // avoid "The requested address is not valid in its context."
            opt.interface_name = String::new();
        }
        if !opt.interface_name.is_empty() {
            address = if opt.fallback_bind {
                fallback_bind_iface_to_listen_config(&opt.interface_name, &mut lc, network, &address, r_addr_port)
                    .await?
            } else {
                bind_iface_to_listen_config(&opt.interface_name, &mut lc, network, &address, r_addr_port).await?
            };
        }
        if opt.routing_mark == 0 {
            opt.routing_mark = DEFAULT_ROUTING_MARK.load();
        }
        if opt.routing_mark != 0 {
            bind_mark_to_listen_config(opt.routing_mark, &mut lc, network, &address);
        }
    }

    Ok((lc, address))
}

/// The ip + port form; `dial_context` takes an address string.
async fn dial_context_ip(
    ctx: &CancellationToken,
    network: &str,
    destination: IpAddr,
    port: &str,
    opt: &Options,
) -> anyhow::Result<Box<dyn Stream>> {
    let mut opt = opt.clone();
    let (destination, port) = lookup_ip4p(destination, port);
    let address = join_host_port(&destination.to_string(), &port);

    let net_dialer = opt.net_dialer.clone();
    let mut std_dialer = match net_dialer {
        None => StdDialer::default(),
        Some(net_dialer) => match net_dialer.as_std_dialer() {
            Some(std_dialer) => std_dialer,
            None => return net_dialer.dial_context(ctx, network, &address).await,
        },
    };

    set_keepalive_net_dialer(&mut std_dialer);
    set_mptcp_net_dialer(&mut std_dialer, opt.mp_tcp);

    if default_socket_hook().is_some() {
        // ignore interfaceName, routingMark and tfo when DefaultSocketHook not null (in CMFA)
        socket_hook_to_to_dialer(&mut std_dialer);
    } else {
        if opt.interface_name.is_empty() {
            opt.interface_name = DEFAULT_INTERFACE.load();
        }
        if opt.interface_name.is_empty() {
            if let Some(finder) = DEFAULT_INTERFACE_FINDER.load() {
                opt.interface_name = finder.find_interface_name(Some(destination));
            }
        }
        if !opt.interface_name.is_empty() {
            if opt.fallback_bind {
                fallback_bind_iface_to_dialer(&opt.interface_name, &mut std_dialer, network, Some(destination)).await?;
            } else {
                bind_iface_to_dialer(&opt.interface_name, &mut std_dialer, network, Some(destination)).await?;
            }
        }
        if opt.routing_mark == 0 {
            opt.routing_mark = DEFAULT_ROUTING_MARK.load();
        }
        if opt.routing_mark != 0 {
            bind_mark_to_dialer(opt.routing_mark, &mut std_dialer, network, Some(destination));
        }
        if opt.tfo && !DISABLE_TFO.load() {
            return Ok(dial_tfo(&std_dialer, network, &address));
        }
    }

    std_dialer.dial_context(ctx, network, &address).await
}

/// the `ICMPControl`; the token it runs under is freshly created.
#[must_use]
pub fn icmp_control(destination: Option<IpAddr>) -> BasicControlFn {
    Arc::new(move |network, address, fd| {
        Box::pin(async move {
            if default_socket_hook().is_some() {
                return match default_socket_hook() {
                    Some(hook) => hook(network, address, fd).await,
                    None => Ok(()),
                };
            }

            let mut dialer = StdDialer::default();
            let mut interface_name = DEFAULT_INTERFACE.load();
            if interface_name.is_empty() {
                if let Some(finder) = DEFAULT_INTERFACE_FINDER.load() {
                    interface_name = finder.find_interface_name(destination);
                }
            }
            if !interface_name.is_empty() {
                bind_iface_to_dialer(&interface_name, &mut dialer, &network, destination).await?;
            }
            let routing_mark = DEFAULT_ROUTING_MARK.load();
            if routing_mark != 0 {
                bind_mark_to_dialer(routing_mark, &mut dialer, &network, destination);
            }
            if let Some(control) = dialer.control_context.take() {
                return control(&CancellationToken::new(), network, address, fd).await;
            }
            Ok(())
        })
    })
}

/// `dual_stack_dial_context` receives either racer.
#[derive(Clone, Copy)]
enum DialKind {
    Parallel,
    Serial,
}

async fn dial_with_kind(
    kind: DialKind,
    ctx: &CancellationToken,
    network: &str,
    ips: Vec<IpAddr>,
    port: &str,
    opt: &Options,
) -> anyhow::Result<Box<dyn Stream>> {
    match kind {
        DialKind::Parallel => parallel_dial_context(ctx, network, &ips, port, opt).await,
        DialKind::Serial => serial_dial_context(ctx, network, ips, port, opt).await,
    }
}

// cancel-safe: a dropped call drops the watch sender, and each racer then drops the connection it
// produced instead of handing it over.
async fn dual_stack_dial_context(
    ctx: &CancellationToken,
    dial_kind: DialKind,
    network: &str,
    ips: &[IpAddr],
    port: &str,
    opt: &Options,
) -> anyhow::Result<Box<dyn Stream>> {
    let (ipv4s, ipv6s) = sortation_addr(ips);
    if ipv4s.is_empty() && ipv6s.is_empty() {
        return Err(ERROR_NO_IP_ADDRESS.into());
    }
    if ipv4s.is_empty() && !ipv6s.is_empty() {
        return dial_with_kind(dial_kind, ctx, network, ipv6s, port, opt).await;
    }
    if !ipv4s.is_empty() && ipv6s.is_empty() {
        return dial_with_kind(dial_kind, ctx, network, ipv4s, port, opt).await;
    }

    let prefer_ip_version = opt.prefer;
    let mut fallback_ticker = interval_at(Instant::now() + DUAL_STACK_FALLBACK_TIMEOUT, DUAL_STACK_FALLBACK_TIMEOUT);

    let (tx, mut rx) = mpsc::channel::<DialResult>(2);
    // held until this function returns; dropping it closes the returned channel.
    let (_returned_tx, returned_rx) = watch::channel(false);

    let mut racers = Vec::new();
    if !ipv4s.is_empty() {
        racers.push((ipv4s, prefer_ip_version != IpVersion::V6));
    }
    if !ipv6s.is_empty() {
        racers.push((ipv6s, prefer_ip_version != IpVersion::V4));
    }

    for (ips, is_primary) in racers {
        let tx = tx.clone();
        let mut returned_rx = returned_rx.clone();
        let ctx = ctx.clone();
        let network = network.to_owned();
        let port = port.to_owned();
        let opt = opt.clone();
        tokio::spawn(async move {
            let result = dual_racer(dial_kind, ctx, network, ips, port, opt, is_primary).await;
            // The implicit cleanup: hand the result over, or drop it — which closes the conn — when the
            // caller has already returned.
            tokio::select! {
                biased;
                _ = returned_rx.changed() => {}
                _ = tx.send(result) => {}
            }
        });
    }
    drop(tx);

    let mut fallback: Option<DialResult> = None;
    let mut errs = Vec::new();

    loop {
        tokio::select! {
            _ = fallback_ticker.tick() => {
                if let Some(conn) = fallback.as_mut().and_then(DialResult::take_conn) {
                    return Ok(conn);
                }
            }
            res = rx.recv() => {
                let Some(res) = res else { break };
                if res.error.is_none() {
                    if res.is_primary {
                        if let Some(conn) = fallback.as_mut().and_then(DialResult::take_conn) {
                            // close fallback connection in a new task to avoid blocking
                            tokio::spawn(async move {
                                let _ = conn.shutdown_read();
                                let _ = conn.shutdown_write();
                            });
                        }
                        return match res.conn {
                            Some(conn) => Ok(conn),
                            None => Err(ERROR_NO_IP_ADDRESS.into()),
                        };
                    }
                    fallback = Some(res);
                } else if let Some(err) = res.error {
                    let err = anyhow::anyhow!("connect failed: {err}");
                    if res.is_primary {
                        errs.insert(0, err);
                    } else {
                        errs.push(err);
                    }
                }
            }
        }
    }

    if let Some(conn) = fallback.as_mut().and_then(DialResult::take_conn) {
        return Ok(conn);
    }
    Err(super::control::join_errors(errs))
}

async fn dual_racer(
    dial_kind: DialKind,
    ctx: CancellationToken,
    network: String,
    ips: Vec<IpAddr>,
    port: String,
    opt: Options,
    is_primary: bool,
) -> DialResult {
    let mut result = DialResult { conn: None, error: None, is_primary };
    match dial_with_kind(dial_kind, &ctx, &network, ips, &port, &opt).await {
        Ok(conn) => result.conn = Some(conn),
        Err(err) => result.error = Some(err),
    }
    result
}

// cancel-safe: a dropped call drops the watch sender, and each racer then drops the connection it
// produced instead of handing it over.
async fn parallel_dial_context(
    ctx: &CancellationToken,
    network: &str,
    ips: &[IpAddr],
    port: &str,
    opt: &Options,
) -> anyhow::Result<Box<dyn Stream>> {
    match ips {
        [] => return Err(ERROR_NO_IP_ADDRESS.into()),
        [ip] => return dial_context_ip(ctx, network, *ip, port, opt).await,
        _ => {}
    }

    let (tx, mut rx) = mpsc::channel::<DialResult>(ips.len());
    // held until this function returns; dropping it closes the returned channel.
    let (_returned_tx, returned_rx) = watch::channel(false);

    for ip in ips.iter().copied() {
        let tx = tx.clone();
        let mut returned_rx = returned_rx.clone();
        let ctx = ctx.clone();
        let network = network.to_owned();
        let port = port.to_owned();
        let opt = opt.clone();
        tokio::spawn(async move {
            let mut result = DialResult { conn: None, error: None, is_primary: true };
            match dial_context_ip(&ctx, &network, ip, &port, &opt).await {
                Ok(conn) => result.conn = Some(conn),
                Err(err) => result.error = Some(err),
            }
            tokio::select! {
                biased;
                _ = returned_rx.changed() => {}
                _ = tx.send(result) => {}
            }
        });
    }
    drop(tx);

    let mut errs = Vec::new();
    for _ in 0..ips.len() {
        let Some(res) = rx.recv().await else { break };
        if res.error.is_none() {
            if let Some(conn) = res.conn {
                return Ok(conn);
            }
            continue;
        }
        if let Some(err) = res.error {
            errs.push(err);
        }
    }

    if !errs.is_empty() {
        return Err(super::control::join_errors(errs));
    }
    Err(deadline_exceeded_error())
}

async fn serial_dial_context(
    ctx: &CancellationToken,
    network: &str,
    ips: Vec<IpAddr>,
    port: &str,
    opt: &Options,
) -> anyhow::Result<Box<dyn Stream>> {
    if ips.is_empty() {
        return Err(ERROR_NO_IP_ADDRESS.into());
    }

    let mut errs = Vec::new();
    for ip in ips {
        match dial_context_ip(ctx, network, ip, port, opt).await {
            Ok(conn) => return Ok(conn),
            Err(err) => errs.push(err),
        }
    }
    Err(super::control::join_errors(errs))
}

/// `Conn` and the error become optional fields.
struct DialResult {
    conn: Option<Box<dyn Stream>>,
    error: Option<anyhow::Error>,
    is_primary: bool,
}

impl DialResult {
    /// Takes the conn when there is no error and a conn is present.
    fn take_conn(&mut self) -> Option<Box<dyn Stream>> {
        if self.error.is_none() {
            self.conn.take()
        } else {
            None
        }
    }
}

fn deadline_exceeded_error() -> anyhow::Error {
    anyhow::Error::new(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout"))
}

async fn parse_addr(
    ctx: &CancellationToken,
    network: &str,
    address: &str,
    prefer_resolver: Option<&ResolverRef>,
) -> anyhow::Result<(Vec<IpAddr>, String)> {
    let (host, port) = murmur_common::net_addr::split_host_port(address)?;

    let owned_resolver = if prefer_resolver.is_none() { proxy_server_host_resolver() } else { None };
    let prefer_resolver = match prefer_resolver {
        Some(resolver) => Some(resolver),
        None => owned_resolver.as_deref(),
    };

    let ips = match network {
        "tcp4" | "udp4" => lookup_ipv4_with_resolver(ctx, &host, prefer_resolver).await,
        "tcp6" | "udp6" => lookup_ipv6_with_resolver(ctx, &host, prefer_resolver).await,
        _ => lookup_ip_with_resolver(ctx, &host, prefer_resolver).await,
    }
    .map_err(|err| anyhow::anyhow!("dns resolve failed: {err}"))?;

    let ips = ips.into_iter().map(|ip| if is4in6(ip) { unmap_addr(Some(ip)).unwrap_or(ip) } else { ip }).collect();

    Ok((ips, port))
}

fn listen_address_is_loopback(address: &str) -> bool {
    let host = match murmur_common::net_addr::split_host_port(address) {
        Ok((host, _)) => host,
        Err(_) => address.to_owned(),
    };
    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };
    unmap_addr(Some(ip)).is_some_and(|ip| ip.is_loopback())
}

#[derive(Debug)]
pub struct Dialer {
    pub opt: Options,
}

impl Dialer {
    pub async fn dial_context(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> anyhow::Result<Box<dyn Stream>> {
        dial_context(ctx, network, address, vec![with_option(self.opt.clone())]).await
    }

    pub async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
        r_addr_port: Option<SocketAddr>,
    ) -> anyhow::Result<Box<dyn Datagram>> {
        listen_packet(
            ctx,
            &parse_network(network, r_addr_port.map(|addr_port| addr_port.ip())),
            address,
            r_addr_port,
            vec![with_option(self.opt.clone())],
        )
        .await
    }
}

#[must_use]
#[expect(
    clippy::needless_pass_by_value,
    reason = "public entry point: every workspace caller builds and hands over an owned option list, so the signature is load-bearing"
)]
pub fn new_dialer(options: Vec<super::options::Option>) -> Dialer {
    Dialer { opt: apply_options(&options) }
}

#[cfg(test)]
mod loopback_tests {
    use super::listen_address_is_loopback;

    #[test]
    fn bare_ipv6_loopback_is_detected() {
        assert!(listen_address_is_loopback("::1"));
        assert!(listen_address_is_loopback("[::1]:80"));
        assert!(!listen_address_is_loopback("fe80::1"));
        assert!(!listen_address_is_loopback("192.0.2.1:80"));
    }
}

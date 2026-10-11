//! All functions in this file should only be used in the dns module.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio_util::sync::CancellationToken;

use crate::statistic::manager::DEFAULT_MANAGER;
use crate::statistic::tracker::{TcpTracker, UdpTracker};
use murmur_component::dialer::{dialer, options::with_interface};
use murmur_component::resolver::resolver::{resolve_ip_with_resolver, SharedResolver};
use murmur_constant::adapters::ProxyAdapter;
use murmur_constant::dns::DNSMode;
use murmur_constant::metadata::{Metadata, NetWork, Type};
use murmur_constant::rule::Rule;
use murmur_std_compat::net::PacketConn;

use super::tunnel::{log_metadata, log_metadata_err, proxies, resolve_metadata};

pub const DNS_RESPECT_RULES: &str = "RULES";

pub struct DNSDialer {
    r: Option<SharedResolver>,
    proxy_adapter: Option<Arc<dyn ProxyAdapter>>,
    proxy_name: String,
}

impl core::fmt::Debug for DNSDialer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DNSDialer")
            .field("proxy_name", &self.proxy_name)
            .field("has_resolver", &self.r.is_some())
            .field("has_proxy_adapter", &self.proxy_adapter.is_some())
            .finish_non_exhaustive()
    }
}

/// The metadata a dns-dialed connection starts from: inner network, everything else default.
fn inner_metadata(network: NetWork) -> Metadata {
    Metadata {
        network,
        type_: Type::INNER,
        src_ip: None,
        dst_ip: None,
        src_geo_ip: None,
        dst_geo_ip: None,
        src_ipasn: String::new(),
        dst_ipasn: String::new(),
        src_port: 0,
        dst_port: 0,
        in_ip: None,
        in_port: 0,
        in_name: String::new(),
        in_user: String::new(),
        rematch_name: String::new(),
        host: String::new(),
        dns_mode: DNSMode::DNS_NORMAL,
        uid: 0,
        process: String::new(),
        process_path: String::new(),
        special_proxy: String::new(),
        special_rules: String::new(),
        remote_dst: String::new(),
        dscp: 0,
        raw_src_addr: None,
        raw_dst_addr: None,
        sniff_host: String::new(),
    }
}

impl DNSDialer {
    #[must_use]
    pub fn new(r: Option<SharedResolver>, proxy_adapter: Option<Arc<dyn ProxyAdapter>>, proxy_name: String) -> Self {
        Self { r, proxy_adapter, proxy_name }
    }

    // cancel-safe: a cancelled dial drops the connection it had just opened.
    pub async fn dial_context(
        &self,
        ctx: &CancellationToken,
        network: &str,
        addr: &str,
    ) -> Result<Box<dyn murmur_std_compat::net::Conn>> {
        let r = self.r.clone();
        let proxy_name = self.proxy_name.clone();
        let mut proxy_adapter = self.proxy_adapter.clone();
        let mut opts = Vec::new();
        let mut rule: Option<Arc<dyn Rule>> = None;

        let mut metadata = inner_metadata(NetWork::TCP);
        metadata.set_remote_address(addr)?;

        if !network.contains("tcp") {
            metadata.network = NetWork::UDP;
            if !metadata.resolved() {
                let dst_ip = resolve_ip_with_resolver(ctx, &metadata.host, r.as_deref()).await?;
                metadata.dst_ip = Some(dst_ip);
            }
        }

        if proxy_adapter.is_none() && !proxy_name.is_empty() {
            if proxy_name == DNS_RESPECT_RULES {
                if !metadata.resolved() {
                    let dst_ip = resolve_ip_with_resolver(ctx, &metadata.host, r.as_deref()).await?;
                    metadata.dst_ip = Some(dst_ip);
                }
                let (resolved_proxy, resolved_rule) = resolve_metadata(&mut metadata).await?;
                proxy_adapter = resolved_proxy.map(|proxy| -> Arc<dyn ProxyAdapter> { proxy });
                rule = resolved_rule;
            } else if let Some(proxy) = proxies().get(&proxy_name) {
                // Bind the concrete source first: `Arc::clone` would otherwise be
                // checked against the (upcast) target type and reject the coercion.
                let proxy_arc = Arc::clone(proxy);
                let adapter: Arc<dyn ProxyAdapter> = proxy_arc;
                proxy_adapter = Some(adapter);
                metadata.special_proxy = proxy_name.clone();
            } else {
                opts.push(with_interface(&proxy_name));
            }
        }

        if metadata.network == NetWork::TCP {
            let Some(proxy_adapter) = proxy_adapter else {
                opts.push(murmur_component::dialer::options::with_resolver(r));
                return Ok(Box::new(murmur_common_net::io::StreamAsOldConn::new(
                    dialer::dial_context(ctx, network, addr, opts).await?,
                )));
            };

            if proxy_adapter.is_l3_protocol(&metadata) {
                if !metadata.resolved() {
                    let dst_ip = resolve_ip_with_resolver(ctx, &metadata.host, r.as_deref()).await?;
                    metadata.dst_ip = Some(dst_ip);
                }
                metadata.host = String::new();
            }

            let conn = match proxy_adapter.dial_context(ctx, &mut metadata).await {
                Ok(conn) => conn,
                Err(err) => {
                    log_metadata_err(&metadata, rule.as_deref(), proxy_adapter.as_ref(), &err);
                    return Err(err);
                }
            };
            log_metadata(&metadata, rule.as_deref(), conn.as_ref());

            let conn = TcpTracker::new(conn, &DEFAULT_MANAGER, &mut metadata, rule, 0, 0, false);

            Ok(Box::new(murmur_common_net::io::StreamAsOldConn::new(conn)))
        } else {
            let Some(proxy_adapter) = proxy_adapter else {
                return Ok(Box::new(murmur_common_net::io::StreamAsOldConn::new(
                    dialer::dial_context(ctx, network, &addr_port_string(&metadata), opts).await?,
                )));
            };

            if !proxy_adapter.support_udp() {
                return Err(anyhow!("proxy adapter [{}] UDP is not supported", proxy_adapter.name()));
            }

            let packet_conn = match proxy_adapter.listen_packet_context(ctx, &mut metadata).await {
                Ok(packet_conn) => packet_conn,
                Err(err) => {
                    log_metadata_err(&metadata, rule.as_deref(), proxy_adapter.as_ref(), &err);
                    return Err(err);
                }
            };
            log_metadata(&metadata, rule.as_deref(), packet_conn.as_ref());

            let packet_conn = UdpTracker::new(packet_conn, &DEFAULT_MANAGER, &mut metadata, rule, 0, 0, false);

            let Some(udp_addr) = metadata.udp_addr() else {
                return Err(anyhow!("udp metadata has no resolved address"));
            };
            let r_addr = murmur_common_net::io::socket_addr_from_udp_addr(&udp_addr);
            let bound = murmur_common_net::new_bind_packet_conn(packet_conn, r_addr);
            Ok(Box::new(murmur_common_net::io::StreamAsOldConn::new(bound)))
        }
    }

    // cancel-safe: a cancelled call drops the packet conn it had just bound.
    pub async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        addr: &str,
    ) -> Result<Box<dyn PacketConn>> {
        let r = self.r.clone();
        let mut proxy_adapter = self.proxy_adapter.clone();
        let proxy_name = self.proxy_name.clone();
        let mut opts = Vec::new();

        let mut metadata = inner_metadata(NetWork::UDP);
        metadata.set_remote_address(addr)?;
        if !metadata.resolved() {
            let dst_ip = resolve_ip_with_resolver(ctx, &metadata.host, r.as_deref()).await?;
            metadata.dst_ip = Some(dst_ip);
        }

        let mut rule: Option<Arc<dyn Rule>> = None;
        if proxy_adapter.is_none() {
            if proxy_name == DNS_RESPECT_RULES {
                let (resolved_proxy, resolved_rule) = resolve_metadata(&mut metadata).await?;
                proxy_adapter = resolved_proxy.map(|proxy| -> Arc<dyn ProxyAdapter> { proxy });
                rule = resolved_rule;
            } else if let Some(proxy) = proxies().get(&proxy_name) {
                // Bind the concrete source first: `Arc::clone` would otherwise be
                // checked against the (upcast) target type and reject the coercion.
                let proxy_arc = Arc::clone(proxy);
                let adapter: Arc<dyn ProxyAdapter> = proxy_arc;
                proxy_adapter = Some(adapter);
                metadata.special_proxy = proxy_name.clone();
            } else {
                opts.push(with_interface(&proxy_name));
            }
        }

        let Some(proxy_adapter) = proxy_adapter else {
            return Ok(Box::new(murmur_common_net::io::DatagramAsOldPacketConn(
                dialer::new_dialer(opts).listen_packet(ctx, network, "", metadata.addr_port()).await?,
            )));
        };

        if !proxy_adapter.support_udp() {
            return Err(anyhow!("proxy adapter [{}] UDP is not supported", proxy_adapter.name()));
        }

        let packet_conn = match proxy_adapter.listen_packet_context(ctx, &mut metadata).await {
            Ok(packet_conn) => packet_conn,
            Err(err) => {
                log_metadata_err(&metadata, rule.as_deref(), proxy_adapter.as_ref(), &err);
                return Err(err);
            }
        };
        log_metadata(&metadata, rule.as_deref(), packet_conn.as_ref());

        let packet_conn = UdpTracker::new(packet_conn, &DEFAULT_MANAGER, &mut metadata, rule, 0, 0, false);

        Ok(Box::new(ArcPacketConn(packet_conn)))
    }
}

/// The metadata's addr port rendered as a string, or `invalid AddrPort` when unresolved.
fn addr_port_string(metadata: &Metadata) -> String {
    match metadata.addr_port() {
        Some(addr_port) => addr_port.to_string(),
        None => "invalid AddrPort".to_owned(),
    }
}

/// Bridges a shared `Arc<dyn PacketConn>` into `Box<dyn PacketConn>`, so `listen_packet`'s
/// exclusive-ownership return type can carry the shared udp tracker.
struct ArcPacketConn(Arc<dyn PacketConn>);

#[async_trait::async_trait]
impl PacketConn for ArcPacketConn {
    // cancel-safe: it only forwards to the shared packet conn it wraps.
    async fn read_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, Box<dyn murmur_std_compat::net::Addr>)> {
        self.0.read_from(buf).await
    }

    // cancel-safe: it only forwards to the shared packet conn it wraps.
    async fn write_to(&self, buf: &[u8], addr: &dyn murmur_std_compat::net::Addr) -> std::io::Result<usize> {
        self.0.write_to(buf, addr).await
    }

    fn local_addr(&self) -> std::io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        self.0.local_addr()
    }

    fn close(&self) -> std::io::Result<()> {
        self.0.close()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> std::io::Result<()> {
        self.0.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> std::io::Result<()> {
        self.0.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> std::io::Result<()> {
        self.0.set_write_deadline(deadline)
    }
}

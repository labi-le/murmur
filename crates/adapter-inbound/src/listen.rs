use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_common::atomic::type_::{new_bool, Bool};
use murmur_common::sockopt::mark_common::raw_conn_mark;
use murmur_component::dialer::bind::join_host_port;
use murmur_component::dialer::control::{add_control_to_listen_config, StdListenConfig};
use murmur_component::keepalive::tcp_keepalive::set_net_listen_config as set_keepalive_listen_config;
use murmur_component::mptcp::set_net_listen_config as set_mptcp_listen_config;
use murmur_component::resolver::host::parse_addr;
use murmur_std_compat::net::{Listener, PacketConn};

static GLOBAL_TFO: Bool = new_bool(false);
static GLOBAL_MPTCP: Bool = new_bool(false);

pub fn set_tfo(open: bool) {
    GLOBAL_TFO.store(open);
}

pub fn tfo() -> bool {
    GLOBAL_TFO.load()
}

pub fn set_mptcp(open: bool) {
    GLOBAL_MPTCP.store(open);
}

pub fn mptcp() -> bool {
    GLOBAL_MPTCP.load()
}

#[derive(Clone, Debug, Default)]
pub struct ListenConfig {
    route_mark: i32,
}

#[must_use]
pub fn new_listen_config() -> ListenConfig {
    ListenConfig::default()
}

/// Satisfies the `InboundListenConfig` trait object every listener parameter expects, by handing
/// back the standard config's acceptor/datagram directly (no bridge round trip).
#[async_trait]
impl murmur_constant::listener::InboundListenConfig for ListenConfig {
    async fn listen(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> Result<Box<dyn murmur_common_net::io::Acceptor>> {
        let address = pre_resolve(network, address)?;
        Ok(self.new_listen_config().listen(ctx, network, &address).await?)
    }

    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> Result<Box<dyn murmur_common_net::io::Datagram>> {
        let address = pre_resolve(network, address)?;
        Ok(self.new_listen_config().listen_packet(ctx, network, &address).await?)
    }
}

/// The default listen config, boxed as the `InboundListenConfig` trait object callers expect.
#[must_use]
pub fn default_listen_config() -> Arc<dyn murmur_constant::listener::InboundListenConfig> {
    Arc::new(new_listen_config())
}

impl ListenConfig {
    pub const fn set_route_mark(&mut self, mark: i32) {
        self.route_mark = mark;
    }

    fn new_listen_config(&self) -> StdListenConfig {
        let mut lc = StdListenConfig { disable_tfo: !tfo(), ..StdListenConfig::default() };
        set_keepalive_listen_config(&mut lc);
        set_mptcp_listen_config(&mut lc, mptcp());
        let route_mark = self.route_mark;
        add_control_to_listen_config(
            &mut lc,
            Arc::new(move |_ctx, _network, _address, fd| {
                let route_mark = route_mark;
                Box::pin(async move {
                    if route_mark != 0 {
                        raw_conn_mark(fd, route_mark)?;
                    }
                    Ok(())
                })
            }),
        );
        lc
    }

    pub async fn listen(&self, ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn Listener>> {
        let address = pre_resolve(network, address)?;
        Ok(Box::new(murmur_common_net::io::AcceptorAsOldListener(
            self.new_listen_config().listen(ctx, network, &address).await?,
        )))
    }

    pub async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> Result<Box<dyn PacketConn>> {
        let address = pre_resolve(network, address)?;
        Ok(Box::new(murmur_common_net::io::DatagramAsOldPacketConn(
            self.new_listen_config().listen_packet(ctx, network, &address).await?,
        )))
    }
}

/// Filters a domain out of the address instead of resolving it, to avoid a resolver call.
pub(crate) fn pre_resolve(network: &str, address: &str) -> Result<String> {
    match network {
        "tcp" | "tcp4" | "tcp6" | "udp" | "udp4" | "udp6" | "ip" | "ip4" | "ip6" => {
            if let Ok((host, port)) = murmur_common::net_addr::split_host_port(address) {
                match host.as_str() {
                    "localhost" => {
                        let host = match network {
                            "tcp6" | "udp6" | "ip6" => "::1",
                            _ => "127.0.0.1",
                        };
                        return Ok(join_host_port(host, &port));
                    }
                    "" => {}
                    _ => {
                        if parse_addr(&host).is_err() {
                            return Err(anyhow!("invalid network address: {address}"));
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(address.to_owned())
}

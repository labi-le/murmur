use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::auth::{get_auth_store, AuthUsers};
use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::mixed::mixed as mixed_server;
use crate::socks::udp as socks_udp;
use murmur_constant::listener::{InboundConfig, InboundListener, Listener as ConstListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::auth::AuthServer;
use murmur_listener_config::reality::RealityConfig;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct MixedOption {
    pub base: BaseOption,
    pub users: AuthUsers,
    pub udp: bool,
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
    pub reality_config: Option<RealityConfig>,
}

impl InboundConfig for MixedOption {
    fn name(&self) -> String {
        self.base.name()
    }

    fn equal(&self, config: &dyn InboundConfig) -> bool {
        config_equal(self, config)
    }

    fn option_to_string(&self) -> String {
        option_to_string(self)
    }
}

pub struct Mixed {
    base: Base,
    config: Arc<MixedOption>,
    l: Mutex<Vec<Arc<mixed_server::Listener>>>,
    l_udp: Mutex<Vec<Arc<socks_udp::UdpListener>>>,
    udp: bool,
}

impl core::fmt::Debug for Mixed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mixed").field("base", &self.base).field("config", &self.config).finish_non_exhaustive()
    }
}

impl Mixed {
    pub fn new(options: Arc<MixedOption>) -> Result<Self> {
        let udp = options.udp;
        let base = Base::new(Arc::new(options.base.clone()))?;
        Ok(Self { base, config: options, l: Mutex::new(Vec::new()), l_udp: Mutex::new(Vec::new()), udp })
    }
}

#[async_trait]
impl InboundListener for Mixed {
    fn name(&self) -> String {
        self.base.config().name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let lc = self.base.listen_config();
        let mut listeners = Vec::new();
        let mut udp_listeners = Vec::new();
        for addr in self.base.raw_address().split(',') {
            let config = AuthServer {
                enable: true,
                listen: addr.to_owned(),
                auth_store: get_auth_store(&self.config.users),
                certificate: self.config.certificate.clone(),
                private_key: self.config.private_key.clone(),
                client_auth_type: self.config.client_auth_type.clone(),
                client_auth_cert: self.config.client_auth_cert.clone(),
                ech_key: self.config.ech_key.clone(),
                reality_config: self.config.reality_config.clone(),
            };
            let l = mixed_server::new_with_config(
                config.clone(),
                Arc::clone(&lc),
                Arc::clone(&tunnel),
                self.base.additions(),
            )
            .await?;
            listeners.push(l);
            if self.udp {
                let l_udp =
                    socks_udp::new_udp_with_config(config, Arc::clone(&lc), Arc::clone(&tunnel), self.base.additions())
                        .await?;
                udp_listeners.push(l_udp);
            }
        }
        *self.l.lock() = listeners;
        *self.l_udp.lock() = udp_listeners;
        infoln!("Mixed(http+socks)[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        let mut errs = Vec::new();
        for l in self.l.lock().iter() {
            if let Err(err) = l.close() {
                errs.push(format!("close tcp listener {} err: {err}", l.address()));
            }
        }
        for l in self.l_udp.lock().iter() {
            if let Err(err) = l.close() {
                errs.push(format!("close udp listener {} err: {err}", l.address()));
            }
        }
        if !errs.is_empty() {
            return Err(anyhow::anyhow!(errs.join("\n")));
        }
        Ok(())
    }

    fn address(&self) -> String {
        self.l.lock().iter().map(|l| l.address()).collect::<Vec<_>>().join(",")
    }

    fn raw_address(&self) -> String {
        self.base.raw_address()
    }

    fn config(&self) -> Arc<dyn InboundConfig> {
        upcast_config(Arc::clone(&self.config))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use murmur_adapter_outbound::socks5::{Socks5, Socks5Option};
    use murmur_constant::adapters::ProxyAdapter;
    use murmur_testsupport::HttpTestTunnel;

    /// A SOCKS5 CONNECT through the [`Mixed`] inbound (which serves both SOCKS5 and HTTP on the
    /// same port) to the shared mock HTTP/HTTPS origin, driven by the crate's own SOCKS5 outbound
    /// adapter. This is new coverage.
    ///
    /// `set_allowed_ips` mirrors the `lan-allowed-ips` default a real config application installs
    /// (`0.0.0.0/0`, `::/0`); a bare unit test never runs that path, and without it the global
    /// LAN allowlist stays empty, so the accept loop's allowlist gate rejects every connection.
    #[tokio::test]
    async fn test_inbound_mixed_socks_connect_round_trip() {
        murmur_adapter_inbound::ipfilter::set_allowed_ips(Some(vec![
            "0.0.0.0/0".parse().expect("valid ipnet literal"),
            "::/0".parse().expect("valid ipnet literal"),
        ]));

        let inbound_options = MixedOption {
            base: BaseOption {
                name_str: "mixed_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let inbound = Mixed::new(Arc::new(inbound_options)).expect("mixed inbound construction");

        let tunnel = HttpTestTunnel::new();
        let listener_tunnel = Arc::clone(&tunnel);
        inbound.listen(listener_tunnel).await.expect("mixed inbound listen");

        let addr_port: std::net::SocketAddr = inbound.address().parse().expect("bound address");

        let api_tunnel = Arc::clone(&tunnel);
        let outbound_options = Socks5Option {
            name: "mixed_socks5_outbound".to_owned(),
            server: addr_port.ip().to_string(),
            port: addr_port.port(),
            basic_option: murmur_adapter_outbound::base::BasicOption {
                dialer_for_api: Some(tunnel.new_dialer()),
                tunnel_for_api: Some(api_tunnel),
                ..Default::default()
            },
            ..Default::default()
        };
        let out = Socks5::new(outbound_options).expect("socks5 outbound construction");

        tunnel.do_test(out.as_ref()).await;

        let _ = out.close();
        inbound.close().expect("mixed inbound close");
        tunnel.close();
    }
}

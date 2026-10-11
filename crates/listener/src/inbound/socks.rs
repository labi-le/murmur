use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::auth::{get_auth_store, AuthUsers};
use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::socks::tcp as socks_tcp;
use crate::socks::udp as socks_udp;
use murmur_constant::listener::{InboundConfig, InboundListener, Listener as ConstListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::auth::AuthServer;
use murmur_listener_config::reality::RealityConfig;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SocksOption {
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

impl InboundConfig for SocksOption {
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

pub struct Socks {
    base: Base,
    config: Arc<SocksOption>,
    udp: bool,
    stl: Mutex<Vec<Arc<socks_tcp::Listener>>>,
    sul: Mutex<Vec<Arc<socks_udp::UdpListener>>>,
}

impl core::fmt::Debug for Socks {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Socks").field("base", &self.base).field("config", &self.config).finish_non_exhaustive()
    }
}

impl Socks {
    pub fn new(options: Arc<SocksOption>) -> Result<Self> {
        let udp = options.udp;
        let base = Base::new(Arc::new(options.base.clone()))?;
        Ok(Self { base, config: options, udp, stl: Mutex::new(Vec::new()), sul: Mutex::new(Vec::new()) })
    }
}

#[async_trait]
impl InboundListener for Socks {
    fn name(&self) -> String {
        self.base.config().name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let lc = self.base.listen_config();
        let mut stl = Vec::new();
        let mut sul = Vec::new();
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
            let l =
                socks_tcp::new_with_config(config.clone(), Arc::clone(&lc), Arc::clone(&tunnel), self.base.additions())
                    .await?;
            stl.push(l);
            if self.udp {
                let l_udp =
                    socks_udp::new_udp_with_config(config, Arc::clone(&lc), Arc::clone(&tunnel), self.base.additions())
                        .await?;
                sul.push(l_udp);
            }
        }
        *self.stl.lock() = stl;
        *self.sul.lock() = sul;
        infoln!("SOCKS[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        let mut errs = Vec::new();
        for l in self.stl.lock().iter() {
            if let Err(err) = l.close() {
                errs.push(format!("close tcp listener {} err: {err}", l.address()));
            }
        }
        for l in self.sul.lock().iter() {
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
        self.stl.lock().iter().map(|l| l.address()).collect::<Vec<_>>().join(",")
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
    use crate::inbound::mixed::MixedOption;
    use murmur_adapter_outbound::socks5::{Socks5, Socks5Option};
    use murmur_constant::adapters::ProxyAdapter;
    use murmur_testsupport::HttpTestTunnel;

    #[test]
    fn equal_treats_socks_and_mixed_with_equal_fields_as_equal() {
        let socks = SocksOption {
            base: BaseOption { name_str: "in-1".into(), ..Default::default() },
            udp: true,
            ..Default::default()
        };
        let mixed = MixedOption {
            base: BaseOption { name_str: "in-1".into(), ..Default::default() },
            udp: true,
            ..Default::default()
        };
        assert!(InboundConfig::equal(&socks, &mixed));
    }

    /// A SOCKS5 CONNECT through the [`Socks`] inbound to the shared mock HTTP/HTTPS origin,
    /// driven by the crate's own SOCKS5 outbound adapter. This is new coverage.
    ///
    /// `set_allowed_ips` mirrors the `lan-allowed-ips` default a real config application installs
    /// (`0.0.0.0/0`, `::/0`); a bare unit test never runs that path, and without it the global
    /// LAN allowlist stays empty, so `handle_socks`'s allowlist gate rejects every connection.
    #[tokio::test]
    async fn test_inbound_socks_connect_round_trip() {
        murmur_adapter_inbound::ipfilter::set_allowed_ips(Some(vec![
            "0.0.0.0/0".parse().expect("valid ipnet literal"),
            "::/0".parse().expect("valid ipnet literal"),
        ]));

        let inbound_options = SocksOption {
            base: BaseOption {
                name_str: "socks_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let inbound = Socks::new(Arc::new(inbound_options)).expect("socks inbound construction");

        let tunnel = HttpTestTunnel::new();
        let listener_tunnel = Arc::clone(&tunnel);
        inbound.listen(listener_tunnel).await.expect("socks inbound listen");

        let addr_port: std::net::SocketAddr = inbound.address().parse().expect("bound address");

        let api_tunnel = Arc::clone(&tunnel);
        let outbound_options = Socks5Option {
            name: "socks_outbound".to_owned(),
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
        inbound.close().expect("socks inbound close");
        tunnel.close();
    }
}

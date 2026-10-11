use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::inbound::jls::JLSConfig;
use crate::inbound::restls::ResTLS;
use crate::inbound::shadowtls::ShadowTLS;
use crate::snell::server as snell_server;
use murmur_constant::listener::{InboundConfig, InboundListener, MultiAddrListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::snell as lc_snell;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SnellOption {
    pub base: BaseOption,
    pub psk: String,
    pub version: i32,
    pub udp: bool,
    pub obfs_opts: SnellObfsOption,
    pub shadow_tls: ShadowTLS,
    pub res_tls: ResTLS,
    pub jls_config: JLSConfig,
}

impl InboundConfig for SnellOption {
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

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SnellObfsOption {
    pub mode: String,
    pub host: String,
}

pub struct Snell {
    base: Base,
    config: Arc<SnellOption>,
    l: Mutex<Option<Arc<snell_server::Listener>>>,
    server: lc_snell::SnellServer,
}

impl core::fmt::Debug for Snell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Snell").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Snell {
    pub fn new(options: Arc<SnellOption>) -> Result<Self> {
        let mut owned = Arc::unwrap_or_clone(options);
        let base = Base::new(Arc::new(owned.base.clone()))?;
        if owned.version == 0 {
            owned.version = 4;
        }
        if !(1..=5).contains(&owned.version) {
            return Err(anyhow!("snell inbound version {} is not supported", owned.version));
        }

        let snell = lc_snell::SnellServer {
            listen: base.raw_address(),
            psk: owned.psk.clone(),
            version: owned.version,
            udp: owned.udp,
            obfs_mode: owned.obfs_opts.mode.clone(),
            obfs_host: owned.obfs_opts.host.clone(),
            shadow_tls: owned.shadow_tls.build(),
            res_tls: owned.res_tls.build(),
            jls_config: owned.jls_config.build(),
        };

        Ok(Self { base, config: Arc::new(owned), l: Mutex::new(None), server: snell })
    }
}

#[async_trait]
impl InboundListener for Snell {
    fn name(&self) -> String {
        self.base.name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let l =
            snell_server::new(self.server.clone(), self.base.listen_config(), tunnel, self.base.additions()).await?;
        *self.l.lock() = Some(l);
        infoln!("Snell[{}] inbound listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        self.l.lock().as_ref().map_or(Ok(()), |l| l.close())
    }

    fn address(&self) -> String {
        self.l
            .lock()
            .as_ref()
            .map(|l| l.addr_list().iter().map(|addr| addr.string()).collect::<Vec<_>>().join(","))
            .unwrap_or_default()
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

    use std::sync::{Arc, LazyLock};

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use rand::RngCore;

    use super::*;
    use crate::inbound::shadowtls::ShadowTLSHandshakeOptions;
    use murmur_adapter_outbound::snell::{Snell as OutSnell, SnellOption as OutSnellOption};
    use murmur_constant::adapters::ProxyAdapter;
    use murmur_testsupport::{tls_fingerprint, HttpTestTunnel, REALITY_DEST, USER_UUID};
    use murmur_transport_shadowtls::client::MODE as SHADOW_TLS_MODE;

    static PASSWORD16: LazyLock<String> = LazyLock::new(|| {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        STANDARD.encode(bytes)
    });

    fn yaml_str(s: &str) -> serde_yaml::Value {
        serde_yaml::Value::from(s)
    }
    fn yaml_i64(n: i64) -> serde_yaml::Value {
        serde_yaml::Value::from(n)
    }
    fn yaml_str_list(items: &[&str]) -> serde_yaml::Value {
        serde_yaml::Value::Sequence(items.iter().map(|s| serde_yaml::Value::from(*s)).collect())
    }
    fn yaml_map(entries: &[(&str, serde_yaml::Value)]) -> serde_yaml::Mapping {
        entries.iter().map(|(k, v)| (serde_yaml::Value::from(*k), v.clone())).collect()
    }

    async fn test_inbound_snell(inbound_options: SnellOption, mut outbound_options: OutSnellOption) {
        let inbound_options = SnellOption {
            base: BaseOption {
                name_str: "snell_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            psk: USER_UUID.clone(),
            ..inbound_options
        };
        let inbound = Snell::new(Arc::new(inbound_options)).expect("snell inbound construction");

        let tunnel = HttpTestTunnel::new();
        let listener_tunnel = Arc::clone(&tunnel);
        inbound.listen(listener_tunnel).await.expect("snell inbound listen");

        let addr_port: std::net::SocketAddr = inbound.address().parse().expect("bound address");

        outbound_options.name = "snell_outbound".to_owned();
        outbound_options.server = addr_port.ip().to_string();
        outbound_options.port = addr_port.port();
        outbound_options.psk = USER_UUID.clone();
        outbound_options.basic_option.dialer_for_api = Some(tunnel.new_dialer());
        let api_tunnel = Arc::clone(&tunnel);
        outbound_options.basic_option.tunnel_for_api = Some(api_tunnel);

        let out = OutSnell::new(outbound_options).expect("snell outbound construction");

        tunnel.do_test(out.as_ref()).await;

        let _ = out.close();
        inbound.close().expect("snell inbound close");
        tunnel.close();
    }

    async fn test_inbound_snell_utls(inbound_options: SnellOption, outbound_options: OutSnellOption) {
        test_inbound_snell(inbound_options.clone(), outbound_options.clone()).await;

        let mut uconn_outbound = outbound_options;
        uconn_outbound.client_fingerprint = "chrome".to_owned();
        test_inbound_snell(inbound_options, uconn_outbound).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_snell_versions() {
        for version in 1..=5 {
            let inbound_options = SnellOption { version, ..Default::default() };
            let outbound_options = OutSnellOption { version, ..Default::default() };
            test_inbound_snell(inbound_options, outbound_options).await;
        }
    }

    /// Confirmed root cause (see `test_support::TLS_CONFIG`): the shadow-tls v2 camouflage TLS
    /// handshake's disguise destination (this harness's own mock server) is a rustls-backed TLS
    /// 1.3 peer that, once no client certificate is requested, queues its `NewSessionTicket`
    /// only after processing the client's own `Finished` (rustls's `ExpectFinished::handle`,
    /// the only call site of `emit_ticket`; confirmed by instrumenting the byte stream — the
    /// ticket's 179-byte ciphertext payload was exactly what the client's post-switch
    /// `ShadowConn::poll_read` mis-consumed as the first tunnel frame). A typical TLS server
    /// folds the ticket into its own first flight, flushed together with `Finished`, so a client's
    /// handshake read usually receives the ticket together with `Finished`, but only as a
    /// best-effort side effect of reading whatever is already on the wire, not a guarantee. A
    /// ticket split into a later TCP read meets the same unfiltered read path as any other
    /// destination. Real destinations commonly send the ticket late rather than folded into the
    /// first flight: OpenSSL sends it after the client's `Finished` (openssl/openssl#7948), and
    /// BoringSSL sends it early only when 0-RTT was accepted, otherwise also after `Finished`.
    /// The client-side read path (`ShadowConn::poll_read`) has no defense of its own against a
    /// stray trailing record from a late-ticket disguise destination; this is a shared
    /// protocol-design gap, not an implementation bug.
    /// The fix makes this harness's mock server behave like a ticket-free (or early-ticket)
    /// disguise destination by disabling its session tickets outright, matching the ticket-free
    /// flight the shadow-tls v2 client/server switch protocol actually requires.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_snell_shadow_tls_v2() {
        let inbound_options = SnellOption {
            shadow_tls: ShadowTLS {
                enable: true,
                version: 2,
                password: PASSWORD16.clone(),
                handshake: ShadowTLSHandshakeOptions { dest: format!("{REALITY_DEST}:443"), ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        let outbound_options = OutSnellOption {
            version: 5,
            obfs_opts: yaml_map(&[
                ("mode", yaml_str(SHADOW_TLS_MODE)),
                ("host", yaml_str(REALITY_DEST)),
                ("password", yaml_str(&PASSWORD16)),
                ("fingerprint", yaml_str(tls_fingerprint())),
                ("version", yaml_i64(2)),
                ("alpn", yaml_str_list(&["http/1.1"])),
            ]),
            ..Default::default()
        };
        test_inbound_snell_utls(inbound_options, outbound_options).await;
    }
}

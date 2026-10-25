use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::inbound::mux::MuxOption;
use crate::shadowquic::server as shadowquic_server;
use murmur_constant::listener::{InboundConfig, InboundListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::shadowquic as lc_shadowquic;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ShadowQuicOption {
    pub base: BaseOption,
    pub users: Vec<ShadowQuicUser>,
    pub jls_upstream: ShadowQuicJLSUpstream,
    pub alpn: Vec<String>,
    pub quic_versions: Vec<String>,
    pub zero_rtt: bool,
    pub congestion_controller: String,
    pub up: String,
    pub down: String,
    pub ignore_client_bandwidth: bool,
    pub max_idle_time: i32,
    pub max_datagram_frame_size: i32,
    pub receive_window_conn: i32,
    pub receive_window: i32,
    pub disable_mtu_discovery: bool,
    pub cwnd: i32,
    pub bbr_profile: String,
    pub mux_option: MuxOption,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ShadowQuicUser {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ShadowQuicJLSUpstream {
    pub addr: String,
    pub sni: String,
    pub proxy: String,
    pub rate_limit: u64,
}

impl ShadowQuicUser {
    #[must_use]
    pub fn build(&self) -> lc_shadowquic::ShadowQuicUser {
        lc_shadowquic::ShadowQuicUser { username: self.username.clone(), password: self.password.clone() }
    }
}

impl ShadowQuicJLSUpstream {
    #[must_use]
    pub fn build(&self) -> lc_shadowquic::ShadowQuicJLSUpstream {
        lc_shadowquic::ShadowQuicJLSUpstream {
            addr: self.addr.clone(),
            sni: self.sni.clone(),
            proxy: self.proxy.clone(),
            rate_limit: self.rate_limit,
        }
    }
}

impl InboundConfig for ShadowQuicOption {
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

pub struct ShadowQuic {
    base: Base,
    config: Arc<ShadowQuicOption>,
    l: Mutex<Option<shadowquic_server::Listener>>,
    ss: lc_shadowquic::ShadowQuicServer,
}

impl core::fmt::Debug for ShadowQuic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShadowQuic").field("base", &self.base).field("config", &self.config).finish_non_exhaustive()
    }
}

impl ShadowQuic {
    pub fn new(options: Arc<ShadowQuicOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        let ss = lc_shadowquic::ShadowQuicServer {
            enable: true,
            listen: base.raw_address(),
            users: options.users.iter().map(ShadowQuicUser::build).collect(),
            jls_upstream: options.jls_upstream.build(),
            alpn: options.alpn.clone(),
            quic_versions: options.quic_versions.clone(),
            zero_rtt: options.zero_rtt,
            congestion_controller: options.congestion_controller.clone(),
            up: options.up.clone(),
            down: options.down.clone(),
            ignore_client_bandwidth: options.ignore_client_bandwidth,
            max_idle_time: options.max_idle_time,
            max_datagram_frame_size: options.max_datagram_frame_size,
            receive_window_conn: options.receive_window_conn,
            receive_window: options.receive_window,
            disable_mtu_discovery: options.disable_mtu_discovery,
            cwnd: options.cwnd,
            bbr_profile: options.bbr_profile.clone(),
            mux_option: options.mux_option.build(),
        };
        Ok(Self { base, config: options, l: Mutex::new(None), ss })
    }
}

#[async_trait]
impl InboundListener for ShadowQuic {
    fn name(&self) -> String {
        self.base.name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let l =
            shadowquic_server::new(self.ss.clone(), self.base.listen_config(), tunnel, self.base.additions()).await?;
        *self.l.lock() = Some(l);
        infoln!("ShadowQuic[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        match self.l.lock().as_ref() {
            Some(l) => l.close(),
            None => Ok(()),
        }
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
    //!
    //! The test dials the inbound with the real outbound ShadowQuic adapter while the inbound
    //! holds an `HttpTestTunnel`, and runs that round trip for both QUIC versions, so the
    //! listener, the JLS handshake, the CONNECT framing and the tunnel handler are all on the
    //! path. `InboundTestTunnel` adds the UDP-packet-handler assertion to `HttpTestTunnel`: the
    //! listener authenticates the client from its own `users`, so a connection that reaches
    //! the JLS backend through the tunnel means the handshake was not the listener's own.
    //!
    //! `test_inbound_shadow_quic_v1`/`_v2` prove one HTTP round trip survives each QUIC version and
    //! never reaches the JLS backend, so the v2 case pins the outbound's version selection.

    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::*;
    use murmur_adapter_outbound::shadowquic::{ShadowQuic as OutShadowQuic, ShadowQuicOption as OutShadowQuicOption};
    use murmur_common_net::io::Stream;
    use murmur_constant::adapters::{NatTable, ProxyAdapter as CProxyAdapter, UDPPacket};
    use murmur_constant::metadata::Metadata;
    use murmur_testsupport::HttpTestTunnel;

    const USERNAME: &str = "shadowquic-user";
    const PASSWORD: &str = "shadowquic-password";
    const JLS_UPSTREAM: &str = "127.0.0.1:1";

    /// `HttpTestTunnel` plus the JLS-backend guard.
    struct InboundTestTunnel {
        http: Arc<HttpTestTunnel>,
        upstream_hit: AtomicBool,
    }

    impl InboundTestTunnel {
        fn new() -> Arc<Self> {
            Arc::new(Self { http: HttpTestTunnel::new(), upstream_hit: AtomicBool::new(false) })
        }
    }

    #[async_trait]
    impl Tunnel for InboundTestTunnel {
        async fn handle_tcp_conn(&self, conn: Box<dyn Stream>, metadata: Metadata) {
            self.http.handle_tcp_conn(conn, metadata).await;
        }

        fn handle_udp_packet(&self, packet: Arc<dyn UDPPacket>, metadata: Metadata) {
            if metadata.remote_address() == JLS_UPSTREAM {
                self.upstream_hit.store(true, Ordering::SeqCst);
            }
            self.http.handle_udp_packet(packet, metadata);
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            self.http.nat_table()
        }
    }

    async fn test_inbound_shadow_quic(version: &str) {
        let inbound_options = ShadowQuicOption {
            base: BaseOption {
                name_str: "shadowquic_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            alpn: vec!["h3".to_owned()],
            quic_versions: vec![version.to_owned()],
            zero_rtt: true,
            max_idle_time: 30000,
            max_datagram_frame_size: 1400,
            users: vec![ShadowQuicUser { username: USERNAME.to_owned(), password: PASSWORD.to_owned() }],
            jls_upstream: ShadowQuicJLSUpstream { addr: JLS_UPSTREAM.to_owned(), ..Default::default() },
            ..Default::default()
        };
        let inbound = ShadowQuic::new(Arc::new(inbound_options)).expect("shadowquic inbound construction");

        let tunnel = InboundTestTunnel::new();
        let listener_tunnel = Arc::clone(&tunnel);
        inbound.listen(listener_tunnel).await.expect("shadowquic inbound listen");

        let addr_port: SocketAddr = inbound.address().parse().expect("bound address");

        let api_tunnel = Arc::clone(&tunnel);
        let outbound_options = OutShadowQuicOption {
            name: "shadowquic_outbound".to_owned(),
            server: addr_port.ip().to_string(),
            port: i32::from(addr_port.port()),
            alpn: Some(vec!["h3".to_owned()]),
            quic_versions: vec![version.to_owned()],
            zero_rtt: true,
            max_datagram_frame_size: 1400,
            username: USERNAME.to_owned(),
            password: PASSWORD.to_owned(),
            basic_option: murmur_adapter_outbound::base::BasicOption {
                dialer_for_api: Some(tunnel.http.new_dialer()),
                tunnel_for_api: Some(api_tunnel),
                ..Default::default()
            },
            ..Default::default()
        };
        let out = OutShadowQuic::new(outbound_options).expect("shadowquic outbound construction");

        tunnel.http.do_test(out.as_ref()).await;
        assert!(
            !tunnel.upstream_hit.load(Ordering::SeqCst),
            "an authenticated connection must not reach the JLS upstream {JLS_UPSTREAM} through the tunnel"
        );

        let _ = out.close();
        inbound.close().expect("shadowquic inbound close");
        tunnel.http.close();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_shadow_quic_v1() {
        test_inbound_shadow_quic("v1").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_shadow_quic_v2() {
        test_inbound_shadow_quic("v2").await;
    }
}

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::inbound::jls::JLSConfig;
use crate::inbound::mux::MuxOption;
use crate::inbound::restls::ResTLS;
use crate::inbound::shadowtls::ShadowTLS;
use crate::trojan::server as trojan_server;
use murmur_constant::listener::{InboundConfig, InboundListener, MultiAddrListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::reality::RealityConfig;
use murmur_listener_config::trojan as lc_trojan;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TrojanOption {
    pub base: BaseOption,
    pub users: Vec<TrojanUser>,
    pub ws_path: String,
    pub grpc_service_name: String,
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
    pub allow_insecure: bool,
    pub shadow_tls: ShadowTLS,
    pub res_tls: ResTLS,
    pub jls_config: JLSConfig,
    pub reality_config: Option<RealityConfig>,
    pub mux_option: MuxOption,
    pub ss_option: TrojanSSOption,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TrojanUser {
    pub username: String,
    pub password: String,
}

/// `TrojanSSOption`.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TrojanSSOption {
    pub enabled: bool,
    pub method: String,
    pub password: String,
}

impl InboundConfig for TrojanOption {
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

pub struct Trojan {
    base: Base,
    config: Arc<TrojanOption>,
    l: Mutex<Option<Arc<dyn MultiAddrListener>>>,
    vs: lc_trojan::TrojanServer,
}

impl core::fmt::Debug for Trojan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Trojan").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Trojan {
    pub fn new(options: Arc<TrojanOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        let users: Vec<lc_trojan::TrojanUser> = options
            .users
            .iter()
            .map(|v| lc_trojan::TrojanUser { username: v.username.clone(), password: v.password.clone() })
            .collect();
        let vs = lc_trojan::TrojanServer {
            enable: true,
            listen: base.raw_address(),
            users,
            ws_path: options.ws_path.clone(),
            grpc_service_name: options.grpc_service_name.clone(),
            certificate: options.certificate.clone(),
            private_key: options.private_key.clone(),
            client_auth_type: options.client_auth_type.clone(),
            client_auth_cert: options.client_auth_cert.clone(),
            ech_key: options.ech_key.clone(),
            allow_insecure: options.allow_insecure,
            shadow_tls: options.shadow_tls.build(),
            res_tls: options.res_tls.build(),
            jls_config: options.jls_config.build(),
            reality_config: options.reality_config.clone(),
            mux_option: options.mux_option.build(),
            trojan_ss_option: lc_trojan::TrojanSSOption {
                enabled: options.ss_option.enabled,
                method: options.ss_option.method.clone(),
                password: options.ss_option.password.clone(),
            },
        };
        Ok(Self { base, config: options, l: Mutex::new(None), vs })
    }
}

#[async_trait]
impl InboundListener for Trojan {
    fn name(&self) -> String {
        self.config.name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let listener: Arc<dyn MultiAddrListener> =
            trojan_server::new(self.vs.clone(), self.base.listen_config(), tunnel, self.base.additions()).await?;
        *self.l.lock() = Some(listener);
        infoln!("Trojan[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        self.l.lock().as_ref().map_or(Ok(()), |l| l.close())
    }

    fn address(&self) -> String {
        let addr_list: Vec<String> =
            self.l.lock().as_ref().map(|l| l.addr_list().iter().map(|a| a.string()).collect()).unwrap_or_default();
        addr_list.join(",")
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

    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use murmur_adapter_outbound::ech::ECHOptions;
    use murmur_adapter_outbound::trojan::{Trojan as OutTrojan, TrojanOption as OutTrojanOption, TrojanSsOption};
    use murmur_adapter_outbound::vmess::{GrpcOptions as OutboundGrpcOptions, WsOptions};
    use murmur_component_nat::table::Table;
    use murmur_constant::adapters::{NatTable, PacketConn as CPacketConn, ProxyAdapter, UDPPacket};
    use murmur_constant::metadata::{Metadata, NetWork};
    use murmur_std_compat::net::UdpAddr;
    use murmur_testsupport::{
        ech_config_base64, ech_key_pem, tls_auth_certificate, tls_auth_private_key, tls_certificate, tls_fingerprint,
        tls_private_key, HttpTestTunnel, USER_UUID,
    };
    use tokio::net::UdpSocket;
    use tokio_util::sync::CancellationToken;

    async fn test_inbound_trojan(inbound_options: TrojanOption, mut outbound_options: OutTrojanOption) {
        let inbound_options = TrojanOption {
            base: BaseOption {
                name_str: "trojan_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            users: vec![TrojanUser { username: "test".to_owned(), password: USER_UUID.clone() }],
            ..inbound_options
        };
        let inbound = Trojan::new(Arc::new(inbound_options)).expect("trojan inbound construction");

        let tunnel = HttpTestTunnel::new();
        let listener_tunnel = Arc::clone(&tunnel);
        inbound.listen(listener_tunnel).await.expect("trojan inbound listen");

        let addr_port: SocketAddr = inbound.address().parse().expect("bound address");

        outbound_options.name = "trojan_outbound".to_owned();
        outbound_options.server = addr_port.ip().to_string();
        outbound_options.port = addr_port.port() as i32;
        outbound_options.password = USER_UUID.clone();
        outbound_options.basic_option.dialer_for_api = Some(tunnel.new_dialer());
        let api_tunnel = Arc::clone(&tunnel);
        outbound_options.basic_option.tunnel_for_api = Some(api_tunnel);

        let out = OutTrojan::new(outbound_options).expect("trojan outbound construction");

        tunnel.do_test(out.as_ref()).await;

        let _ = out.close();
        inbound.close().expect("trojan inbound close");
        tunnel.close();
    }

    async fn test_inbound_trojan_tls(inbound_options: TrojanOption, outbound_options: OutTrojanOption) {
        test_inbound_trojan(inbound_options.clone(), outbound_options.clone()).await;

        let mut ech_inbound = inbound_options.clone();
        ech_inbound.ech_key = ech_key_pem().to_owned();
        let mut ech_outbound = outbound_options.clone();
        ech_outbound.ech_opts =
            ECHOptions { enable: true, config: ech_config_base64().to_owned(), ..Default::default() };
        test_inbound_trojan(ech_inbound, ech_outbound).await;

        let mut mtls_inbound = inbound_options.clone();
        mtls_inbound.client_auth_cert = tls_auth_certificate().to_owned();
        let mut mtls_outbound = outbound_options.clone();
        mtls_outbound.certificate = tls_auth_certificate().to_owned();
        mtls_outbound.private_key = tls_auth_private_key().to_owned();
        test_inbound_trojan(mtls_inbound, mtls_outbound).await;

        let mut mtls_ech_inbound = inbound_options;
        mtls_ech_inbound.client_auth_cert = tls_auth_certificate().to_owned();
        mtls_ech_inbound.ech_key = ech_key_pem().to_owned();
        let mut mtls_ech_outbound = outbound_options;
        mtls_ech_outbound.certificate = tls_auth_certificate().to_owned();
        mtls_ech_outbound.private_key = tls_auth_private_key().to_owned();
        mtls_ech_outbound.ech_opts =
            ECHOptions { enable: true, config: ech_config_base64().to_owned(), ..Default::default() };
        test_inbound_trojan(mtls_ech_inbound, mtls_ech_outbound).await;
    }

    #[tokio::test]
    async fn test_inbound_trojan_tls_basic() {
        let inbound_options = TrojanOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ..Default::default()
        };
        let outbound_options = OutTrojanOption { fingerprint: tls_fingerprint().to_owned(), ..Default::default() };
        test_inbound_trojan_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_trojan_wss1() {
        let inbound_options = TrojanOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ws_path: "/ws".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutTrojanOption {
            fingerprint: tls_fingerprint().to_owned(),
            network: "ws".to_owned(),
            ws_opts: WsOptions { path: "/ws".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_trojan_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_trojan_wss2() {
        let inbound_options = TrojanOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ws_path: "/ws".to_owned(),
            grpc_service_name: "GunService".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutTrojanOption {
            fingerprint: tls_fingerprint().to_owned(),
            network: "ws".to_owned(),
            ws_opts: WsOptions { path: "/ws".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_trojan_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_trojan_grpc1() {
        let inbound_options = TrojanOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            grpc_service_name: "GunService".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutTrojanOption {
            fingerprint: tls_fingerprint().to_owned(),
            network: "grpc".to_owned(),
            grpc_opts: OutboundGrpcOptions { grpc_service_name: "GunService".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_trojan_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_trojan_grpc2() {
        let inbound_options = TrojanOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ws_path: "/ws".to_owned(),
            grpc_service_name: "GunService".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutTrojanOption {
            fingerprint: tls_fingerprint().to_owned(),
            network: "grpc".to_owned(),
            grpc_opts: OutboundGrpcOptions { grpc_service_name: "GunService".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_trojan_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_trojan_tls_trojan_ss() {
        let inbound_options = TrojanOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ss_option: TrojanSSOption { enabled: true, method: String::new(), password: "password".to_owned() },
            ..Default::default()
        };
        let outbound_options = OutTrojanOption {
            fingerprint: tls_fingerprint().to_owned(),
            ss_opts: TrojanSsOption { enabled: true, method: String::new(), password: "password".to_owned() },
            ..Default::default()
        };
        test_inbound_trojan_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_trojan_wss_trojan_ss() {
        let inbound_options = TrojanOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ss_option: TrojanSSOption { enabled: true, method: String::new(), password: "password".to_owned() },
            ws_path: "/ws".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutTrojanOption {
            fingerprint: tls_fingerprint().to_owned(),
            ss_opts: TrojanSsOption { enabled: true, method: String::new(), password: "password".to_owned() },
            network: "ws".to_owned(),
            ws_opts: WsOptions { path: "/ws".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_trojan_tls(inbound_options, outbound_options).await;
    }

    struct UdpEchoTunnel;

    #[async_trait]
    impl Tunnel for UdpEchoTunnel {
        async fn handle_tcp_conn(&self, _conn: Box<dyn murmur_common_net::io::Stream>, _metadata: Metadata) {
            unreachable!("UDP regression must not dispatch TCP");
        }

        fn handle_udp_packet(&self, packet: Arc<dyn UDPPacket>, metadata: Metadata) {
            tokio::spawn(async move {
                let target = metadata.raw_dst_addr.expect("Trojan UDP destination");
                let target =
                    murmur_common_net::io::old_addr_to_socket_addr(target.as_ref()).expect("socket destination");
                let socket = UdpSocket::bind("127.0.0.1:0").await.expect("UDP forward socket");
                socket.send_to(packet.data(), target).await.expect("forward UDP payload");
                let mut buf = [0u8; 128];
                let (n, source) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
                    .await
                    .expect("UDP echo timed out")
                    .expect("UDP echo read");
                packet.write_back(&buf[..n], Some(source)).await.expect("return UDP echo");
            });
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    #[tokio::test]
    async fn test_inbound_trojan_udp_echo() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.expect("UDP echo socket");
        let echo_addr = echo.local_addr().expect("UDP echo address");
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            let (n, source) = tokio::time::timeout(Duration::from_secs(5), echo.recv_from(&mut buf))
                .await
                .expect("UDP echo request timed out")
                .expect("UDP echo request");
            echo.send_to(&buf[..n], source).await.expect("UDP echo reply");
        });

        let inbound_options = TrojanOption {
            base: BaseOption {
                name_str: "trojan_inbound_udp".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            users: vec![TrojanUser { username: "test".to_owned(), password: USER_UUID.clone() }],
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ..Default::default()
        };
        let inbound = Trojan::new(Arc::new(inbound_options)).expect("trojan inbound construction");
        inbound.listen(Arc::new(UdpEchoTunnel)).await.expect("trojan inbound listen");
        let inbound_addr: SocketAddr = inbound.address().parse().expect("bound address");
        let out = OutTrojan::new(OutTrojanOption {
            name: "trojan_outbound_udp".to_owned(),
            server: inbound_addr.ip().to_string(),
            port: i32::from(inbound_addr.port()),
            password: USER_UUID.clone(),
            fingerprint: tls_fingerprint().to_owned(),
            udp: true,
            ..Default::default()
        })
        .expect("trojan outbound construction");

        let ctx = CancellationToken::new();
        let mut metadata = Metadata {
            network: NetWork::UDP,
            dst_ip: Some(echo_addr.ip()),
            dst_port: echo_addr.port(),
            ..Default::default()
        };
        let pc: Arc<dyn CPacketConn> =
            out.listen_packet_context(&ctx, &mut metadata).await.expect("trojan UDP listen_packet");
        let destination = UdpAddr::new(echo_addr.ip(), echo_addr.port());
        let payload = b"trojan UDP echo through inbound";
        pc.write_to(payload, &destination).await.expect("trojan UDP write");
        let mut reply = [0u8; 8192];
        let (n, source) = tokio::time::timeout(Duration::from_secs(5), pc.read_from(&mut reply))
            .await
            .expect("trojan UDP reply timed out")
            .expect("trojan UDP read");
        assert_eq!(&reply[..n], payload);
        assert_eq!(murmur_common_net::io::old_addr_to_socket_addr(source.as_ref()).expect("UDP source"), echo_addr);
        tokio::time::timeout(Duration::from_secs(5), echo_task)
            .await
            .expect("UDP echo task timed out")
            .expect("UDP echo task");

        pc.close().expect("trojan UDP packet close");
        out.close().expect("trojan outbound close");
        inbound.close().expect("trojan inbound close");
    }
}

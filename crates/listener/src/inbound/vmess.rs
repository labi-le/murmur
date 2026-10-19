use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::inbound::jls::JLSConfig;
use crate::inbound::mekya::MekyaConfig;
use crate::inbound::mkcp::MKCPConfig;
use crate::inbound::mux::MuxOption;
use crate::inbound::restls::ResTLS;
use crate::inbound::shadowtls::ShadowTLS;
use crate::inbound::tlsmirror::TLSMirrorConfig;
use crate::sing_vmess::server as sing_vmess;
use murmur_constant::listener::{InboundConfig, InboundListener, MultiAddrListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::reality::RealityConfig;
use murmur_listener_config::vmess::{VmessServer, VmessUser as LcVmessUser};
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct VmessOption {
    pub base: BaseOption,
    pub users: Vec<VmessUser>,
    pub ws_path: String,
    pub grpc_service_name: String,
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
    pub shadow_tls: ShadowTLS,
    pub res_tls: ResTLS,
    pub jls_config: JLSConfig,
    pub reality_config: Option<RealityConfig>,
    pub tls_mirror_config: TLSMirrorConfig,
    pub mekya_config: MekyaConfig,
    pub mkcp_config: MKCPConfig,
    pub mux_option: MuxOption,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct VmessUser {
    pub username: String,
    pub uuid: String,
    pub alter_id: i32,
}

impl InboundConfig for VmessOption {
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

pub struct Vmess {
    base: Base,
    config: Arc<VmessOption>,
    l: Mutex<Option<Arc<sing_vmess::Listener>>>,
    vs: VmessServer,
}

impl core::fmt::Debug for Vmess {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vmess").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Vmess {
    pub fn new(options: Arc<VmessOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        let users = options
            .users
            .iter()
            .map(|v| LcVmessUser { username: v.username.clone(), uuid: v.uuid.clone(), alter_id: v.alter_id })
            .collect();
        let vs = VmessServer {
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
            shadow_tls: options.shadow_tls.build(),
            res_tls: options.res_tls.build(),
            jls_config: options.jls_config.build(),
            reality_config: options.reality_config.clone(),
            tls_mirror_config: options.tls_mirror_config.build(),
            mekya_config: options.mekya_config.build(),
            mkcp_config: options.mkcp_config.build(),
            mux_option: options.mux_option.build(),
        };
        Ok(Self { base, config: options, l: Mutex::new(None), vs })
    }
}

#[async_trait]
impl InboundListener for Vmess {
    fn name(&self) -> String {
        self.base.name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let additions = self.base.additions();
        let listener = sing_vmess::new(self.vs.clone(), self.base.listen_config(), tunnel, additions).await?;
        *self.l.lock() = Some(listener);
        infoln!("Vmess[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        self.l.lock().as_ref().map_or(Ok(()), |l| l.close())
    }

    fn address(&self) -> String {
        self.l
            .lock()
            .as_ref()
            .map(|l| l.addr_list().iter().map(|a| a.string()).collect::<Vec<_>>().join(","))
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

    use std::net::SocketAddr;
    use std::sync::Arc;

    use super::*;
    use murmur_adapter_outbound::ech::ECHOptions;

    use crate::inbound::shadowtls::ShadowTLSHandshakeOptions;
    use crate::inbound::tlsmirror::{TLSMirrorTimeSpec, TLSMirrorTransportLayerPadding};
    use murmur_adapter_outbound::shadowtls::ShadowTLSOptions;
    use murmur_adapter_outbound::tlsmirror::{
        TLSMirrorConnectionEnrolment as OutTLSMirrorConnectionEnrolment, TLSMirrorOptions,
        TLSMirrorTimeSpec as OutTLSMirrorTimeSpec, TLSMirrorTrafficGenerator, TLSMirrorTrafficStep,
        TLSMirrorTrafficTransferCandidate, TLSMirrorTransportLayerPadding as OutTLSMirrorTransportLayerPadding,
    };
    use murmur_adapter_outbound::vmess::{
        GrpcOptions as OutGrpcOptions, MekyaOptions, MkcpOptions, Vmess as OutVmess, VmessOption as OutVmessOption,
        WsOptions,
    };
    use murmur_constant::adapters::ProxyAdapter as CProxyAdapter;
    use murmur_testsupport::{
        ech_config_base64, ech_key_pem, tls_auth_certificate, tls_auth_private_key, tls_certificate, tls_fingerprint,
        tls_private_key, HttpTestTunnel, HTTP_PATH, REALITY_DEST, REALITY_REAL_DIAL, USER_UUID,
    };
    use murmur_transport_tlsmirror::config::RECOMMENDED_EXPLICIT_NONCE_CIPHER_SUITES;

    async fn test_inbound_vmess(inbound_options: VmessOption, mut outbound_options: OutVmessOption) {
        let inbound_options = VmessOption {
            base: BaseOption {
                name_str: "vmess_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            users: vec![VmessUser { username: "test".to_owned(), uuid: USER_UUID.clone(), alter_id: 0 }],
            ..inbound_options
        };
        let inbound = Vmess::new(Arc::new(inbound_options)).expect("vmess inbound construction");

        let tunnel = HttpTestTunnel::new();
        let listener_tunnel = Arc::clone(&tunnel);
        inbound.listen(listener_tunnel).await.expect("vmess inbound listen");

        let addr_port: SocketAddr = inbound.address().parse().expect("bound address");

        outbound_options.name = "vmess_outbound".to_owned();
        outbound_options.server = addr_port.ip().to_string();
        outbound_options.port = addr_port.port();
        outbound_options.uuid = USER_UUID.clone();
        outbound_options.alter_id = 0;
        outbound_options.cipher = "auto".to_owned();
        outbound_options.basic.dialer_for_api = Some(tunnel.new_dialer());
        let api_tunnel = Arc::clone(&tunnel);
        outbound_options.basic.tunnel_for_api = Some(api_tunnel);

        let out = OutVmess::new(outbound_options).expect("vmess outbound construction");

        tunnel.do_test(out.as_ref()).await;

        let _ = out.close();
        inbound.close().expect("vmess inbound close");
        tunnel.close();
    }

    async fn test_inbound_vmess_tls(inbound_options: VmessOption, outbound_options: OutVmessOption) {
        test_inbound_vmess(inbound_options.clone(), outbound_options.clone()).await;

        let mut ech_inbound = inbound_options.clone();
        ech_inbound.ech_key = ech_key_pem().to_owned();
        let mut ech_outbound = outbound_options.clone();
        ech_outbound.ech_opts =
            ECHOptions { enable: true, config: ech_config_base64().to_owned(), ..Default::default() };
        test_inbound_vmess(ech_inbound, ech_outbound).await;

        let mut mtls_inbound = inbound_options.clone();
        mtls_inbound.client_auth_cert = tls_auth_certificate().to_owned();
        let mut mtls_outbound = outbound_options.clone();
        mtls_outbound.certificate = tls_auth_certificate().to_owned();
        mtls_outbound.private_key = tls_auth_private_key().to_owned();
        test_inbound_vmess(mtls_inbound, mtls_outbound).await;

        let mut mtls_ech_inbound = inbound_options;
        mtls_ech_inbound.client_auth_cert = tls_auth_certificate().to_owned();
        mtls_ech_inbound.ech_key = ech_key_pem().to_owned();
        let mut mtls_ech_outbound = outbound_options;
        mtls_ech_outbound.certificate = tls_auth_certificate().to_owned();
        mtls_ech_outbound.private_key = tls_auth_private_key().to_owned();
        mtls_ech_outbound.ech_opts =
            ECHOptions { enable: true, config: ech_config_base64().to_owned(), ..Default::default() };
        test_inbound_vmess(mtls_ech_inbound, mtls_ech_outbound).await;
    }

    async fn run_vmess_tls_mirror_matrix(inbound_options: VmessOption, outbound_options: OutVmessOption) {
        test_inbound_vmess(inbound_options.clone(), outbound_options.clone()).await;
        let mut utls_outbound = outbound_options;
        utls_outbound.client_fingerprint = "chrome".to_owned();
        test_inbound_vmess(inbound_options, utls_outbound).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_basic() {
        test_inbound_vmess(VmessOption::default(), OutVmessOption::default()).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_tls_basic() {
        let inbound_options = VmessOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ..Default::default()
        };
        let outbound_options =
            OutVmessOption { tls: true, fingerprint: tls_fingerprint().to_owned(), ..Default::default() };
        test_inbound_vmess_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_ws() {
        let inbound_options = VmessOption { ws_path: "/ws".to_owned(), ..Default::default() };
        let outbound_options = OutVmessOption {
            network: "ws".to_owned(),
            ws_opts: WsOptions { path: "/ws".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_vmess(inbound_options, outbound_options).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_vmess_mkcp() {
        let inbound_options =
            VmessOption { mkcp_config: MKCPConfig { enable: true, ..Default::default() }, ..Default::default() };
        let outbound_options = OutVmessOption { network: "mkcp".to_owned(), ..Default::default() };
        test_inbound_vmess(inbound_options, outbound_options).await;

        for (seed, header) in [("murmur-mkcp-test", ""), ("", "srtp"), ("murmur-mkcp-test", "srtp")] {
            let inbound_options = VmessOption {
                mkcp_config: MKCPConfig {
                    enable: true,
                    seed: seed.to_owned(),
                    header: header.to_owned(),
                    ..Default::default()
                },
                ..Default::default()
            };
            let outbound_options = OutVmessOption {
                network: "mkcp".to_owned(),
                mkcp_opts: MkcpOptions { seed: seed.to_owned(), header: header.to_owned(), ..Default::default() },
                ..Default::default()
            };
            test_inbound_vmess(inbound_options, outbound_options).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_vmess_mekya() {
        let inbound_options = VmessOption {
            mekya_config: MekyaConfig {
                enable: true,
                max_write_size: 1 << 20,
                max_write_duration_ms: 100,
                max_simultaneous_write_connection: 16,
                packet_writing_buffer: 1024,
                kcp: MKCPConfig { tti: 15, ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        let outbound_options = OutVmessOption {
            network: "mekya".to_owned(),
            mekya_opts: MekyaOptions {
                max_write_delay: 20,
                max_request_size: 96000,
                polling_interval_initial: 20,
                h2_pool_size: 8,
                kcp: MkcpOptions { tti: 15, ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        test_inbound_vmess(inbound_options, outbound_options).await;
    }

    fn tls_mirror_outbound_fingerprint(mut out: OutVmessOption) -> OutVmessOption {
        if !REALITY_REAL_DIAL {
            out.fingerprint = tls_fingerprint().to_owned();
        }
        out
    }

    #[tokio::test]
    async fn test_inbound_vmess_tls_mirror() {
        let primary_key = murmur_transport_tlsmirror::config::generate_primary_key();
        let inbound_options = VmessOption {
            tls_mirror_config: TLSMirrorConfig {
                primary_key: primary_key.clone(),
                dest: format!("{REALITY_DEST}:443"),
                ..Default::default()
            },
            ..Default::default()
        };
        let outbound_options = tls_mirror_outbound_fingerprint(OutVmessOption {
            server_name: REALITY_DEST.to_owned(),
            tls: true,
            tls_mirror_opts: TLSMirrorOptions { primary_key: primary_key.clone(), ..Default::default() },
            ..Default::default()
        });
        run_vmess_tls_mirror_matrix(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_tls_mirror_ws() {
        let primary_key = murmur_transport_tlsmirror::config::generate_primary_key();
        let inbound_options = VmessOption {
            ws_path: "/ws".to_owned(),
            tls_mirror_config: TLSMirrorConfig {
                primary_key: primary_key.clone(),
                dest: format!("{REALITY_DEST}:443"),
                ..Default::default()
            },
            ..Default::default()
        };
        let outbound_options = tls_mirror_outbound_fingerprint(OutVmessOption {
            network: "ws".to_owned(),
            server_name: REALITY_DEST.to_owned(),
            tls: true,
            ws_opts: WsOptions { path: "/ws".to_owned(), ..Default::default() },
            tls_mirror_opts: TLSMirrorOptions { primary_key: primary_key.clone(), ..Default::default() },
            ..Default::default()
        });
        run_vmess_tls_mirror_matrix(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_tls_mirror_grpc() {
        let primary_key = murmur_transport_tlsmirror::config::generate_primary_key();
        let inbound_options = VmessOption {
            grpc_service_name: "GunService".to_owned(),
            tls_mirror_config: TLSMirrorConfig {
                primary_key: primary_key.clone(),
                dest: format!("{REALITY_DEST}:443"),
                ..Default::default()
            },
            ..Default::default()
        };
        let outbound_options = tls_mirror_outbound_fingerprint(OutVmessOption {
            network: "grpc".to_owned(),
            server_name: REALITY_DEST.to_owned(),
            tls: true,
            grpc_opts: OutGrpcOptions { grpc_service_name: "GunService".to_owned(), ..Default::default() },
            tls_mirror_opts: TLSMirrorOptions { primary_key: primary_key.clone(), ..Default::default() },
            ..Default::default()
        });
        run_vmess_tls_mirror_matrix(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_tls_mirror_advanced_options() {
        let primary_key = murmur_transport_tlsmirror::config::generate_primary_key();
        let cipher_suites: Vec<u16> = RECOMMENDED_EXPLICIT_NONCE_CIPHER_SUITES.to_vec();
        let inbound_options = VmessOption {
            tls_mirror_config: TLSMirrorConfig {
                primary_key: primary_key.clone(),
                dest: format!("{REALITY_DEST}:443"),
                explicit_nonce_cipher_suites: cipher_suites.clone(),
                defer_instance_derived_write_time: TLSMirrorTimeSpec {
                    base_nanoseconds: 1_000_000,
                    ..Default::default()
                },
                transport_layer_padding: TLSMirrorTransportLayerPadding { enabled: true },
                sequence_watermarking_enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let outbound_options = tls_mirror_outbound_fingerprint(OutVmessOption {
            server_name: REALITY_DEST.to_owned(),
            tls: true,
            tls_mirror_opts: TLSMirrorOptions {
                primary_key: primary_key.clone(),
                explicit_nonce_cipher_suites: cipher_suites,
                defer_instance_derived_write_time: OutTLSMirrorTimeSpec {
                    base_nanoseconds: 1_000_000,
                    ..Default::default()
                },
                transport_layer_padding: OutTLSMirrorTransportLayerPadding { enabled: true },
                sequence_watermarking_enabled: true,
                ..Default::default()
            },
            ..Default::default()
        });
        run_vmess_tls_mirror_matrix(inbound_options, outbound_options).await;
    }

    /// Was `#[ignore]`d for a stack overflow reported as a state-machine sizing defect; the
    /// actual cause was unbounded recursion: `verify_connection_enrollment`'s control-connection
    /// dial re-entered the same outbound's `make_tls_mirror_dialer`, which re-triggered
    /// `verify_connection_enrollment` because the bypass/loopback-protection flags set on the
    /// control dial's `DialCtx` were lost crossing the generic, `CancellationToken`-only proxy
    /// dial chain back into `stream_tls_conn`. Fixed by propagating that state through the
    /// re-entrant call via `enrollment::AMBIENT_DIAL_CTX`.
    #[tokio::test]
    async fn test_inbound_vmess_tls_mirror_connection_enrolment() {
        let primary_key = murmur_transport_tlsmirror::config::generate_primary_key();
        let inbound_options = VmessOption {
            tls_mirror_config: TLSMirrorConfig {
                primary_key: primary_key.clone(),
                dest: format!("{REALITY_DEST}:443"),
                connection_enrolment: Some(crate::inbound::tlsmirror::TLSMirrorConnectionEnrolment {
                    primary_ingress_outbound: "tlsmirror-enrollment".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let outbound_options = tls_mirror_outbound_fingerprint(OutVmessOption {
            server_name: REALITY_DEST.to_owned(),
            tls: true,
            tls_mirror_opts: TLSMirrorOptions {
                primary_key: primary_key.clone(),
                connection_enrolment: Some(OutTLSMirrorConnectionEnrolment {
                    primary_ingress_outbound: "tlsmirror-enrollment".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        });
        run_vmess_tls_mirror_matrix(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_tls_mirror_embedded_traffic_generator() {
        let primary_key = murmur_transport_tlsmirror::config::generate_primary_key();
        let inbound_options = VmessOption {
            tls_mirror_config: TLSMirrorConfig {
                primary_key: primary_key.clone(),
                dest: format!("{REALITY_DEST}:443"),
                ..Default::default()
            },
            ..Default::default()
        };
        let outbound_options = tls_mirror_outbound_fingerprint(OutVmessOption {
            server_name: REALITY_DEST.to_owned(),
            tls: true,
            tls_mirror_opts: TLSMirrorOptions {
                primary_key: primary_key.clone(),
                embedded_traffic_generator: TLSMirrorTrafficGenerator {
                    steps: vec![TLSMirrorTrafficStep {
                        host: REALITY_DEST.to_owned(),
                        path: format!("{HTTP_PATH}?size=1"),
                        method: "GET".to_owned(),
                        connection_ready: true,
                        connection_recall_exit: true,
                        wait_time: OutTLSMirrorTimeSpec { base_nanoseconds: 1_000_000, ..Default::default() },
                        next_step: vec![TLSMirrorTrafficTransferCandidate { weight: 1, goto_location: 0 }],
                        ..Default::default()
                    }],
                },
                ..Default::default()
            },
            ..Default::default()
        });
        run_vmess_tls_mirror_matrix(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_ws_upgrade1() {
        let inbound_options = VmessOption { ws_path: "/ws".to_owned(), ..Default::default() };
        let outbound_options = OutVmessOption {
            network: "ws".to_owned(),
            ws_opts: WsOptions { path: "/ws".to_owned(), v2ray_http_upgrade: true, ..Default::default() },
            ..Default::default()
        };
        test_inbound_vmess(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_ws_upgrade2() {
        let inbound_options = VmessOption { ws_path: "/ws".to_owned(), ..Default::default() };
        let outbound_options = OutVmessOption {
            network: "ws".to_owned(),
            ws_opts: WsOptions {
                path: "/ws".to_owned(),
                v2ray_http_upgrade: true,
                v2ray_http_upgrade_fast_open: true,
                ..Default::default()
            },
            ..Default::default()
        };
        test_inbound_vmess(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_wss1() {
        let inbound_options = VmessOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ws_path: "/ws".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutVmessOption {
            tls: true,
            fingerprint: tls_fingerprint().to_owned(),
            network: "ws".to_owned(),
            ws_opts: WsOptions { path: "/ws".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_vmess_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_wss2() {
        let inbound_options = VmessOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ws_path: "/ws".to_owned(),
            grpc_service_name: "GunService".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutVmessOption {
            tls: true,
            fingerprint: tls_fingerprint().to_owned(),
            network: "ws".to_owned(),
            ws_opts: WsOptions { path: "/ws".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_vmess_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_grpc1() {
        let inbound_options = VmessOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            grpc_service_name: "GunService".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutVmessOption {
            tls: true,
            fingerprint: tls_fingerprint().to_owned(),
            network: "grpc".to_owned(),
            grpc_opts: OutGrpcOptions { grpc_service_name: "GunService".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_vmess_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vmess_grpc2() {
        let inbound_options = VmessOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ws_path: "/ws".to_owned(),
            grpc_service_name: "GunService".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutVmessOption {
            tls: true,
            fingerprint: tls_fingerprint().to_owned(),
            network: "grpc".to_owned(),
            grpc_opts: OutGrpcOptions { grpc_service_name: "GunService".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_vmess_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_vmess_shadow_tls_v2() {
        let password = "vmess-shadow-tls-v2";
        let inbound_options = VmessOption {
            shadow_tls: ShadowTLS {
                enable: true,
                version: 2,
                password: password.to_owned(),
                handshake: ShadowTLSHandshakeOptions { dest: format!("{REALITY_DEST}:443"), ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        let outbound_options = OutVmessOption {
            tls: true,
            server_name: REALITY_DEST.to_owned(),
            fingerprint: tls_fingerprint().to_owned(),
            shadow_tls_opts: ShadowTLSOptions { password: password.to_owned(), version: 2 },
            ..Default::default()
        };
        tokio::time::timeout(std::time::Duration::from_secs(60), test_inbound_vmess(inbound_options, outbound_options))
            .await
            .expect("ShadowTLS VMess round trip timed out");
    }
}

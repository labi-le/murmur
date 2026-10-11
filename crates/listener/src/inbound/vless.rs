use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::inbound::jls::JLSConfig;
use crate::inbound::mux::MuxOption;
use crate::inbound::restls::ResTLS;
use crate::inbound::shadowtls::ShadowTLS;
use crate::sing_vless::server as sing_vless;
use murmur_constant::listener::{InboundConfig, InboundListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::reality::RealityConfig;
use murmur_listener_config::vless::{VlessServer, VlessUser as LcVlessUser, XHTTPConfig as LcXHTTPConfig};
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct VlessOption {
    pub base: BaseOption,
    pub users: Vec<VlessUser>,
    pub decryption: String,
    pub ws_path: String,
    pub xhttp_config: XHTTPConfig,
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
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct VlessUser {
    pub username: String,
    pub uuid: String,
    pub flow: String,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct XHTTPConfig {
    pub path: String,
    pub host: String,
    pub mode: String,
    pub x_padding_bytes: String,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_placement: String,
    pub x_padding_method: String,
    pub uplink_http_method: String,
    pub session_placement: String,
    pub session_key: String,
    pub seq_placement: String,
    pub seq_key: String,
    pub uplink_data_placement: String,
    pub uplink_data_key: String,
    pub uplink_chunk_size: String,
    pub no_sse_header: bool,
    pub sc_stream_up_server_secs: String,
    pub sc_max_buffered_posts: String,
    pub sc_max_each_post_bytes: String,
}

impl XHTTPConfig {
    #[must_use]
    pub fn build(&self) -> LcXHTTPConfig {
        LcXHTTPConfig {
            path: self.path.clone(),
            host: self.host.clone(),
            mode: self.mode.clone(),
            no_sse_header: self.no_sse_header,
            x_padding_bytes: self.x_padding_bytes.clone(),
            x_padding_obfs_mode: self.x_padding_obfs_mode,
            x_padding_key: self.x_padding_key.clone(),
            x_padding_header: self.x_padding_header.clone(),
            x_padding_placement: self.x_padding_placement.clone(),
            x_padding_method: self.x_padding_method.clone(),
            uplink_http_method: self.uplink_http_method.clone(),
            session_placement: self.session_placement.clone(),
            session_key: self.session_key.clone(),
            seq_placement: self.seq_placement.clone(),
            seq_key: self.seq_key.clone(),
            uplink_data_placement: self.uplink_data_placement.clone(),
            uplink_data_key: self.uplink_data_key.clone(),
            uplink_chunk_size: self.uplink_chunk_size.clone(),
            sc_stream_up_server_secs: self.sc_stream_up_server_secs.clone(),
            sc_max_buffered_posts: self.sc_max_buffered_posts.clone(),
            sc_max_each_post_bytes: self.sc_max_each_post_bytes.clone(),
        }
    }
}

impl InboundConfig for VlessOption {
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

pub struct Vless {
    base: Base,
    config: Arc<VlessOption>,
    l: Mutex<Option<sing_vless::Listener>>,
    vs: VlessServer,
}

impl core::fmt::Debug for Vless {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vless").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Vless {
    pub fn new(options: Arc<VlessOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        let users = options
            .users
            .iter()
            .map(|v| LcVlessUser { username: v.username.clone(), uuid: v.uuid.clone(), flow: v.flow.clone() })
            .collect();
        let vs = VlessServer {
            enable: true,
            listen: base.raw_address(),
            users,
            decryption: options.decryption.clone(),
            ws_path: options.ws_path.clone(),
            xhttp_config: options.xhttp_config.build(),
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
        };
        Ok(Self { base, config: options, l: Mutex::new(None), vs })
    }
}

#[async_trait]
impl InboundListener for Vless {
    fn name(&self) -> String {
        self.base.name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let additions = self.base.additions();
        let listener = sing_vless::new(self.vs.clone(), self.base.listen_config(), tunnel, &additions).await?;
        *self.l.lock() = Some(listener);
        infoln!("Vless[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        self.l.lock().as_ref().map_or(Ok(()), sing_vless::Listener::close)
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
    use murmur_adapter_outbound::vless::{
        Vless as OutVless, VlessOption as OutVlessOption, XHTTPDownloadSettings, XHTTPOptions as OutXHTTPOptions,
        XHTTPReuseSettings,
    };
    use murmur_adapter_outbound::vmess::{GrpcOptions as OutboundGrpcOptions, WsOptions};
    use murmur_constant::adapters::ProxyAdapter;
    use murmur_testsupport::{
        ech_config_base64, ech_key_pem, tls_auth_certificate, tls_auth_private_key, tls_certificate, tls_fingerprint,
        tls_private_key, HttpTestTunnel, USER_UUID,
    };
    use murmur_transport_vless::encryption::key::{gen_mlkem768, gen_x25519};

    async fn test_inbound_vless(inbound_options: VlessOption, mut outbound_options: OutVlessOption) {
        let inbound_options = VlessOption {
            base: BaseOption {
                name_str: "vless_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            users: vec![VlessUser {
                username: "test".to_owned(),
                uuid: USER_UUID.clone(),
                flow: "xtls-rprx-vision".to_owned(),
            }],
            ..inbound_options
        };
        let inbound = Vless::new(Arc::new(inbound_options)).expect("vless inbound construction");

        let tunnel = HttpTestTunnel::new();
        let listener_tunnel = Arc::clone(&tunnel);
        inbound.listen(listener_tunnel).await.expect("vless inbound listen");

        let addr_port: SocketAddr = inbound.address().parse().expect("bound address");

        outbound_options.name = "vless_outbound".to_owned();
        outbound_options.server = addr_port.ip().to_string();
        outbound_options.port = addr_port.port();
        outbound_options.uuid = USER_UUID.clone();
        outbound_options.basic_option.dialer_for_api = Some(tunnel.new_dialer());
        let api_tunnel = Arc::clone(&tunnel);
        outbound_options.basic_option.tunnel_for_api = Some(api_tunnel);

        let out = OutVless::new(outbound_options).expect("vless outbound construction");

        tunnel.do_test(out.as_ref()).await;

        let _ = out.close();
        inbound.close().expect("vless inbound close");
        tunnel.close();
    }

    /// The `xtls-rprx-vision` sub-cases are unsupported: `listener::sing_vless::service::new_connection`
    /// hardcodes `vision_conn::TlsConnCheck::Unsupported` on the server side (see that module's
    /// doc comment, the erased conn exposes no downcast at that boundary), so any
    /// inbound Vision flow fails closed regardless of the underlying transport being real TLS.
    async fn test_inbound_vless_tls(inbound_options: VlessOption, outbound_options: OutVlessOption) {
        eprintln!("xhttp tls case: plain");
        test_inbound_vless(inbound_options.clone(), outbound_options.clone()).await;

        eprintln!("xhttp tls case: ech");
        let mut ech_inbound = inbound_options.clone();
        ech_inbound.ech_key = ech_key_pem().to_owned();
        let mut ech_outbound = outbound_options.clone();
        ech_outbound.ech_opts =
            ECHOptions { enable: true, config: ech_config_base64().to_owned(), ..Default::default() };
        test_inbound_vless(ech_inbound, ech_outbound).await;

        eprintln!("xhttp tls case: mtls");
        let mut mtls_inbound = inbound_options.clone();
        mtls_inbound.client_auth_cert = tls_auth_certificate().to_owned();
        let mut mtls_outbound = outbound_options.clone();
        mtls_outbound.certificate = tls_auth_certificate().to_owned();
        mtls_outbound.private_key = tls_auth_private_key().to_owned();
        test_inbound_vless(mtls_inbound, mtls_outbound).await;

        eprintln!("xhttp tls case: mtls-ech");
        let mut mtls_ech_inbound = inbound_options;
        mtls_ech_inbound.client_auth_cert = tls_auth_certificate().to_owned();
        mtls_ech_inbound.ech_key = ech_key_pem().to_owned();
        let mut mtls_ech_outbound = outbound_options;
        mtls_ech_outbound.certificate = tls_auth_certificate().to_owned();
        mtls_ech_outbound.private_key = tls_auth_private_key().to_owned();
        mtls_ech_outbound.ech_opts =
            ECHOptions { enable: true, config: ech_config_base64().to_owned(), ..Default::default() };
        test_inbound_vless(mtls_ech_inbound, mtls_ech_outbound).await;
    }

    fn with_xhttp_reuse(mut out: OutVlessOption) -> OutVlessOption {
        let reuse = XHTTPReuseSettings {
            max_connections: "0".to_owned(),
            max_concurrency: "16-32".to_owned(),
            c_max_reuse_times: "0".to_owned(),
            h_max_request_times: "600-900".to_owned(),
            h_max_reusable_secs: "1800-3000".to_owned(),
            ..Default::default()
        };
        out.xhttp_opts.reuse_settings = Some(reuse.clone());
        if let Some(download_settings) = out.xhttp_opts.download_settings.as_mut() {
            download_settings.reuse_settings = Some(reuse);
        }
        out
    }

    async fn test_inbound_vless_xhttp_tls_case(get_config: impl Fn() -> (VlessOption, OutVlessOption), mode: &str) {
        let (inbound_options, outbound_options) = get_config();
        test_inbound_vless_tls(inbound_options, outbound_options).await;

        let (inbound_options, outbound_options) = get_config();
        test_inbound_vless_tls(inbound_options, with_xhttp_reuse(outbound_options)).await;

        // `OutVless::new` rejects `stream-one` with `download-settings`, so the split group cannot
        // be built through this adapter at all. What that mode does with a separate download
        // transport is covered one
        // layer down, in `transport_xhttp::client::download_split_tests`.
        if mode == "stream-one" {
            return;
        }

        let (inbound_options, mut outbound_options) = get_config();
        outbound_options.xhttp_opts.download_settings = Some(Box::new(XHTTPDownloadSettings::default()));
        test_inbound_vless_tls(inbound_options, outbound_options).await;

        let (inbound_options, mut outbound_options) = get_config();
        outbound_options.xhttp_opts.download_settings = Some(Box::new(XHTTPDownloadSettings::default()));
        test_inbound_vless_tls(inbound_options, with_xhttp_reuse(outbound_options)).await;
    }

    #[tokio::test]
    async fn test_inbound_vless_tls_basic() {
        let inbound_options = VlessOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ..Default::default()
        };
        let outbound_options =
            OutVlessOption { tls: true, fingerprint: tls_fingerprint().to_owned(), ..Default::default() };
        test_inbound_vless_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vless_wss1() {
        let inbound_options = VlessOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ws_path: "/ws".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutVlessOption {
            tls: true,
            fingerprint: tls_fingerprint().to_owned(),
            network: "ws".to_owned(),
            ws_opts: WsOptions { path: "/ws".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_vless_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vless_wss2() {
        let inbound_options = VlessOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ws_path: "/ws".to_owned(),
            grpc_service_name: "GunService".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutVlessOption {
            tls: true,
            fingerprint: tls_fingerprint().to_owned(),
            network: "ws".to_owned(),
            ws_opts: WsOptions { path: "/ws".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_vless_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vless_grpc1() {
        let inbound_options = VlessOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            grpc_service_name: "GunService".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutVlessOption {
            tls: true,
            fingerprint: tls_fingerprint().to_owned(),
            network: "grpc".to_owned(),
            grpc_opts: OutboundGrpcOptions { grpc_service_name: "GunService".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_vless_tls(inbound_options, outbound_options).await;
    }

    #[tokio::test]
    async fn test_inbound_vless_grpc2() {
        let inbound_options = VlessOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ws_path: "/ws".to_owned(),
            grpc_service_name: "GunService".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutVlessOption {
            tls: true,
            fingerprint: tls_fingerprint().to_owned(),
            network: "grpc".to_owned(),
            grpc_opts: OutboundGrpcOptions { grpc_service_name: "GunService".to_owned(), ..Default::default() },
            ..Default::default()
        };
        test_inbound_vless_tls(inbound_options, outbound_options).await;
    }

    /// An ML-KEM-768 NFS key is paired with an X25519 NFS key
    /// inside one `mlkem768x25519plus` decryption/encryption string
    /// (`"mlkem768x25519plus." + mode + ".600s." + padding + privateKeyBase64 + "." + seedBase64`),
    /// unlike `test_inbound_vless_xhttp_encryption`'s pure-X25519 NFS key: an NFS key is treated
    /// as ML-KEM-768 whenever it decodes to more than 32 bytes (a seed exceeds 32 bytes), so this
    /// is the only test exercising
    /// `transport::vless::encryption::client::encapsulate`/`server::decapsulate`'s ML-KEM-768 branch
    /// rather than its bare-X25519 one. The `xtls-rprx-vision` sub-cases are unsupported, for the same
    /// reason given on `test_inbound_vless_tls`.
    macro_rules! vless_encryption_test {
        ($fn_name:ident, $mode:literal, $padding:literal) => {
            #[tokio::test]
            async fn $fn_name() {
                let (seed_base64, client_base64, _) = gen_mlkem768("").expect("gen_mlkem768");
                let (private_key_base64, password_base64, _) = gen_x25519("").expect("gen_x25519");
                let mode = $mode;
                let padding = $padding;
                let inbound_base = VlessOption {
                    decryption: format!("mlkem768x25519plus.{mode}.600s.{padding}{private_key_base64}.{seed_base64}"),
                    ..Default::default()
                };
                let outbound_base = OutVlessOption {
                    encryption: format!("mlkem768x25519plus.{mode}.0rtt.{padding}{password_base64}.{client_base64}"),
                    ..Default::default()
                };

                test_inbound_vless(inbound_base.clone(), outbound_base.clone()).await;

                let mut ws_inbound = inbound_base.clone();
                ws_inbound.ws_path = "/ws".to_owned();
                let mut ws_outbound = outbound_base.clone();
                ws_outbound.network = "ws".to_owned();
                ws_outbound.ws_opts = WsOptions { path: "/ws".to_owned(), ..Default::default() };
                test_inbound_vless(ws_inbound, ws_outbound).await;

                let mut grpc_inbound = inbound_base.clone();
                grpc_inbound.grpc_service_name = "GunService".to_owned();
                let mut grpc_outbound = outbound_base.clone();
                grpc_outbound.network = "grpc".to_owned();
                grpc_outbound.grpc_opts =
                    OutboundGrpcOptions { grpc_service_name: "GunService".to_owned(), ..Default::default() };
                test_inbound_vless(grpc_inbound, grpc_outbound).await;
            }
        };
    }

    // Split from a single 3-mode x 4-padding x {raw,ws,grpc} loop (36 serial round trips, ~46s)
    // into one test per (mode, padding) pair so nextest/cargo-test run them concurrently.
    vless_encryption_test!(test_inbound_vless_encryption_native_padding0, "native", "");
    vless_encryption_test!(test_inbound_vless_encryption_native_padding1, "native", "100-111-1111.75-0-111.50-0-3333.");
    vless_encryption_test!(test_inbound_vless_encryption_native_padding2, "native", "100-100-1000.");
    vless_encryption_test!(
        test_inbound_vless_encryption_native_padding3,
        "native",
        "100-1234-7890.33-0-1111.66-0-6666.55-111-777."
    );
    vless_encryption_test!(test_inbound_vless_encryption_xorpub_padding0, "xorpub", "");
    vless_encryption_test!(test_inbound_vless_encryption_xorpub_padding1, "xorpub", "100-111-1111.75-0-111.50-0-3333.");
    vless_encryption_test!(test_inbound_vless_encryption_xorpub_padding2, "xorpub", "100-100-1000.");
    vless_encryption_test!(
        test_inbound_vless_encryption_xorpub_padding3,
        "xorpub",
        "100-1234-7890.33-0-1111.66-0-6666.55-111-777."
    );
    vless_encryption_test!(test_inbound_vless_encryption_random_padding0, "random", "");
    vless_encryption_test!(test_inbound_vless_encryption_random_padding1, "random", "100-111-1111.75-0-111.50-0-3333.");
    vless_encryption_test!(test_inbound_vless_encryption_random_padding2, "random", "100-100-1000.");
    vless_encryption_test!(
        test_inbound_vless_encryption_random_padding3,
        "random",
        "100-1234-7890.33-0-1111.66-0-6666.55-111-777."
    );

    macro_rules! vless_xhttp_test {
        ($fn_name:ident, $mode:literal) => {
            #[tokio::test]
            async fn $fn_name() {
                let mode = $mode;
                let get_config = || {
                    let inbound_options = VlessOption {
                        certificate: tls_certificate().to_owned(),
                        private_key: tls_private_key().to_owned(),
                        xhttp_config: XHTTPConfig {
                            path: "/vless-xhttp".to_owned(),
                            host: "example.com".to_owned(),
                            mode: mode.to_owned(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    let outbound_options = OutVlessOption {
                        tls: true,
                        fingerprint: tls_fingerprint().to_owned(),
                        server_name: "example.org".to_owned(),
                        client_fingerprint: "chrome".to_owned(),
                        network: "xhttp".to_owned(),
                        xhttp_opts: OutXHTTPOptions {
                            path: "/vless-xhttp".to_owned(),
                            host: "example.com".to_owned(),
                            mode: mode.to_owned(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    (inbound_options, outbound_options)
                };
                test_inbound_vless_xhttp_tls_case(get_config, mode).await;
            }
        };
    }

    // Split from a single 4-mode serial loop (~25s) into one test per mode.
    vless_xhttp_test!(test_inbound_vless_xhttp_auto, "auto");
    vless_xhttp_test!(test_inbound_vless_xhttp_stream_one, "stream-one");
    vless_xhttp_test!(test_inbound_vless_xhttp_stream_up, "stream-up");
    vless_xhttp_test!(test_inbound_vless_xhttp_packet_up, "packet-up");

    /// The xhttp mode `"stream-one"` uses a single bidirectional connection, so combining
    /// it with `download-settings` is rejected at construction rather than silently ignored.
    #[test]
    fn test_outbound_vless_xhttp_stream_one_rejects_download_settings() {
        let outbound_options = OutVlessOption {
            server: "127.0.0.1".to_owned(),
            port: 1,
            uuid: USER_UUID.clone(),
            tls: true,
            fingerprint: tls_fingerprint().to_owned(),
            network: "xhttp".to_owned(),
            xhttp_opts: OutXHTTPOptions {
                path: "/vless-xhttp".to_owned(),
                host: "example.com".to_owned(),
                mode: "stream-one".to_owned(),
                download_settings: Some(Box::new(XHTTPDownloadSettings::default())),
                ..Default::default()
            },
            ..Default::default()
        };

        let err = match OutVless::new(outbound_options) {
            Ok(_) => panic!("expected xhttp stream-one + download-settings to be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.to_string(), r#"xhttp mode "stream-one" cannot be used with download-settings"#);
    }

    macro_rules! vless_xhttp_h1_test {
        ($fn_name:ident, $mode:literal) => {
            #[tokio::test]
            async fn $fn_name() {
                let mode = $mode;
                let get_config = || {
                    let inbound_options = VlessOption {
                        certificate: tls_certificate().to_owned(),
                        private_key: tls_private_key().to_owned(),
                        xhttp_config: XHTTPConfig {
                            path: "/vless-xhttp".to_owned(),
                            host: "example.com".to_owned(),
                            mode: mode.to_owned(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    let outbound_options = OutVlessOption {
                        tls: true,
                        fingerprint: tls_fingerprint().to_owned(),
                        network: "xhttp".to_owned(),
                        alpn: vec!["http/1.1".to_owned()],
                        xhttp_opts: OutXHTTPOptions {
                            path: "/vless-xhttp".to_owned(),
                            host: "example.com".to_owned(),
                            mode: mode.to_owned(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    (inbound_options, outbound_options)
                };
                test_inbound_vless_xhttp_tls_case(get_config, mode).await;
            }
        };
    }

    // Split from a single 4-mode serial loop (~19s) into one test per mode.
    vless_xhttp_h1_test!(test_inbound_vless_xhttp_h1_auto, "auto");
    vless_xhttp_h1_test!(test_inbound_vless_xhttp_h1_stream_one, "stream-one");
    vless_xhttp_h1_test!(test_inbound_vless_xhttp_h1_stream_up, "stream-up");
    vless_xhttp_h1_test!(test_inbound_vless_xhttp_h1_packet_up, "packet-up");

    async fn test_inbound_vless_xhttp_encryption_case(
        get_config: impl Fn() -> (VlessOption, OutVlessOption),
        mode: &str,
    ) {
        let (inbound_options, outbound_options) = get_config();
        test_inbound_vless(inbound_options, outbound_options).await;

        let (inbound_options, outbound_options) = get_config();
        test_inbound_vless(inbound_options, with_xhttp_reuse(outbound_options)).await;

        // Same reason as `test_inbound_vless_xhttp_tls_case`: the adapter refuses the
        // combination, and the transport-level split is covered in
        // `transport_xhttp::client::download_split_tests`.
        if mode == "stream-one" {
            return;
        }

        let (inbound_options, mut outbound_options) = get_config();
        outbound_options.xhttp_opts.download_settings = Some(Box::new(XHTTPDownloadSettings::default()));
        test_inbound_vless(inbound_options, outbound_options).await;

        let (inbound_options, mut outbound_options) = get_config();
        outbound_options.xhttp_opts.download_settings = Some(Box::new(XHTTPDownloadSettings::default()));
        test_inbound_vless(inbound_options, with_xhttp_reuse(outbound_options)).await;
    }

    /// An X25519-derived long-term ("NFS") key is paired
    /// with the `mlkem768x25519plus` scheme; the handshake (at
    /// `transport::vless::encryption::server`) shows the NFS key itself can be pure X25519 when it is
    /// exactly 32 bytes, but the per-session forward-secrecy ("PFS") exchange that scheme performs
    /// afterward is unconditionally ML-KEM-768 + X25519 hybrid (no branch on the NFS key's type).
    /// `transport::vless::encryption::key::mlkem` now implements that
    /// surface over the `ml-kem` crate. `test_inbound_vless_encryption` (the ML-KEM-768 +
    /// X25519 hybrid NFS case) covers the ML-KEM-768 NFS-key branch; the PFS exchange this
    /// test already exercises is identical regardless of NFS key type.
    macro_rules! vless_xhttp_encryption_test {
        ($fn_name:ident, $mode:literal) => {
            #[tokio::test]
            async fn $fn_name() {
                let (private_key_base64, password_base64, _) = gen_x25519("").expect("gen_x25519");
                let mode = $mode;
                let get_config = || {
                    let inbound_options = VlessOption {
                        decryption: format!("mlkem768x25519plus.native.600s.{private_key_base64}"),
                        xhttp_config: XHTTPConfig {
                            path: "/vless-xhttp".to_owned(),
                            host: "example.com".to_owned(),
                            mode: mode.to_owned(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    let outbound_options = OutVlessOption {
                        encryption: format!("mlkem768x25519plus.native.0rtt.{password_base64}"),
                        network: "xhttp".to_owned(),
                        xhttp_opts: OutXHTTPOptions {
                            path: "/vless-xhttp".to_owned(),
                            host: "example.com".to_owned(),
                            mode: mode.to_owned(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    (inbound_options, outbound_options)
                };
                test_inbound_vless_xhttp_encryption_case(get_config, mode).await;
            }
        };
    }

    // Split from a single 4-mode serial loop (~17s) into one test per mode.
    vless_xhttp_encryption_test!(test_inbound_vless_xhttp_encryption_auto, "auto");
    vless_xhttp_encryption_test!(test_inbound_vless_xhttp_encryption_stream_one, "stream-one");
    vless_xhttp_encryption_test!(test_inbound_vless_xhttp_encryption_stream_up, "stream-up");
    vless_xhttp_encryption_test!(test_inbound_vless_xhttp_encryption_packet_up, "packet-up");

    /// The HTTP/1.1 xhttp encryption case. See `test_inbound_vless_xhttp_encryption` for
    /// the `mlkem768x25519plus` PFS exchange this test also relies on; this variant additionally
    /// forces HTTP/1.1 via `alpn`.
    macro_rules! vless_xhttp_h1_encryption_test {
        ($fn_name:ident, $mode:literal) => {
            #[tokio::test]
            async fn $fn_name() {
                let (private_key_base64, password_base64, _) = gen_x25519("").expect("gen_x25519");
                let mode = $mode;
                let get_config = || {
                    let inbound_options = VlessOption {
                        decryption: format!("mlkem768x25519plus.native.600s.{private_key_base64}"),
                        xhttp_config: XHTTPConfig {
                            path: "/vless-xhttp".to_owned(),
                            host: "example.com".to_owned(),
                            mode: mode.to_owned(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    let outbound_options = OutVlessOption {
                        encryption: format!("mlkem768x25519plus.native.0rtt.{password_base64}"),
                        network: "xhttp".to_owned(),
                        alpn: vec!["http/1.1".to_owned()],
                        xhttp_opts: OutXHTTPOptions {
                            path: "/vless-xhttp".to_owned(),
                            host: "example.com".to_owned(),
                            mode: mode.to_owned(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    (inbound_options, outbound_options)
                };
                test_inbound_vless_xhttp_encryption_case(get_config, mode).await;
            }
        };
    }

    // Split from a single 4-mode serial loop (~17s) into one test per mode.
    vless_xhttp_h1_encryption_test!(test_inbound_vless_xhttp_h1_encryption_auto, "auto");
    vless_xhttp_h1_encryption_test!(test_inbound_vless_xhttp_h1_encryption_stream_one, "stream-one");
    vless_xhttp_h1_encryption_test!(test_inbound_vless_xhttp_h1_encryption_stream_up, "stream-up");
    vless_xhttp_h1_encryption_test!(test_inbound_vless_xhttp_h1_encryption_packet_up, "packet-up");
}

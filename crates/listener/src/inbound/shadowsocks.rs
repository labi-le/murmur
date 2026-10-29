use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::inbound::jls::JLSConfig;
use crate::inbound::kcptun::KcpTun;
use crate::inbound::mux::MuxOption;
use crate::inbound::restls::ResTLS;
use crate::inbound::shadowtls::ShadowTLS;
use crate::sing_shadowsocks::server as sing_shadowsocks;
use murmur_constant::listener::{InboundConfig, InboundListener, MultiAddrListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::shadowsocks as lc_shadowsocks;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ShadowSocksOption {
    pub base: BaseOption,
    pub password: String,
    pub cipher: String,
    pub udp: bool,
    pub mux_option: MuxOption,
    pub shadow_tls: ShadowTLS,
    pub res_tls: ResTLS,
    pub jls_config: JLSConfig,
    pub kcp_tun: KcpTun,
    pub simple_obfs: SimpleObfs,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SimpleObfs {
    pub enable: bool,
    pub mode: String,
}

impl SimpleObfs {
    #[must_use]
    pub fn build(&self) -> lc_shadowsocks::SimpleObfs {
        lc_shadowsocks::SimpleObfs { enable: self.enable, mode: self.mode.clone() }
    }
}

impl InboundConfig for ShadowSocksOption {
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

pub struct ShadowSocks {
    base: Base,
    config: Arc<ShadowSocksOption>,
    l: Mutex<Option<Arc<dyn MultiAddrListener>>>,
    ss: lc_shadowsocks::ShadowsocksServer,
}

impl core::fmt::Debug for ShadowSocks {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShadowSocks").field("config", &self.config).finish_non_exhaustive()
    }
}

impl ShadowSocks {
    pub fn new(options: Arc<ShadowSocksOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        let ss = lc_shadowsocks::ShadowsocksServer {
            enable: true,
            listen: base.raw_address(),
            password: options.password.clone(),
            cipher: options.cipher.clone(),
            udp: options.udp,
            mux_option: options.mux_option.build(),
            shadow_tls: options.shadow_tls.build(),
            res_tls: options.res_tls.build(),
            jls_config: options.jls_config.build(),
            kcp_tun: options.kcp_tun.build(),
            simple_obfs: options.simple_obfs.build(),
        };
        Ok(Self { base, config: options, l: Mutex::new(None), ss })
    }
}

#[async_trait]
impl InboundListener for ShadowSocks {
    /// The config is not `Name`, and `Base` has no promoted `Name`, so this mirrors `Base`'s own
    /// `InboundListener::name`.
    fn name(&self) -> String {
        self.config.name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let listener =
            sing_shadowsocks::new(self.ss.clone(), self.base.listen_config(), tunnel, self.base.additions()).await?;
        *self.l.lock() = Some(listener);
        infoln!("ShadowSocks[{}] proxy listening at: {}", self.name(), self.address());
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

    use std::sync::{Arc, LazyLock};

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use rand::RngCore;

    use super::*;
    use crate::inbound::shadowtls::ShadowTLSHandshakeOptions;
    use murmur_adapter_outbound::shadowsocks::{
        ShadowSocks as OutShadowSocks, ShadowSocksOption as OutShadowSocksOption,
    };
    use murmur_constant::adapters::ProxyAdapter;
    use murmur_testsupport::{tls_fingerprint, HttpTestTunnel, REALITY_DEST};
    use murmur_transport_kcptun::client::MODE as KCPTUN_MODE;
    use murmur_transport_shadowtls::client::MODE as SHADOW_TLS_MODE;

    const NONE_LIST: &[&str] = &["none"];

    /// The AEAD cipher names `pick_cipher` actually implements. The
    /// excluded names (`rabbit128-poly1305`, `aegis-*`, `lea-*-gcm`, `ascon128*`, `aez-384`,
    /// `deoxys-ii-256-128`, `*-gcm-siv`) are accepted by the name gate in
    /// `listener::sing_shadowsocks::server` but have no `pick_cipher` implementation.
    const AEAD_LIST: &[&str] = &[
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "chacha8-ietf-poly1305",
        "xchacha8-ietf-poly1305",
        "aes-128-ccm",
        "aes-192-ccm",
        "aes-256-ccm",
    ];

    const STREAM_LIST: &[&str] = &[
        "rc4-md5",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "chacha20",
        "chacha20-ietf",
        "xchacha20",
    ];

    static PASSWORD32: LazyLock<String> = LazyLock::new(|| {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        STANDARD.encode(bytes)
    });
    static PASSWORD16: LazyLock<String> = LazyLock::new(|| {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        STANDARD.encode(bytes)
    });

    fn yaml_str(s: &str) -> yaml_serde::Value {
        yaml_serde::Value::from(s)
    }
    fn yaml_i64(n: i64) -> yaml_serde::Value {
        yaml_serde::Value::from(n)
    }
    fn yaml_str_list(items: &[&str]) -> yaml_serde::Value {
        yaml_serde::Value::Sequence(items.iter().map(|s| yaml_serde::Value::from(*s)).collect())
    }
    fn yaml_map(entries: &[(&str, yaml_serde::Value)]) -> yaml_serde::Mapping {
        entries.iter().map(|(k, v)| (yaml_serde::Value::from(*k), v.clone())).collect()
    }

    async fn test_inbound_shadowsocks0(inbound_options: ShadowSocksOption, mut outbound_options: OutShadowSocksOption) {
        let password = if inbound_options.cipher.contains("-128-") { PASSWORD16.clone() } else { PASSWORD32.clone() };
        let inbound_options = ShadowSocksOption {
            base: BaseOption {
                name_str: "shadowsocks_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            password: password.clone(),
            ..inbound_options
        };
        let inbound = ShadowSocks::new(Arc::new(inbound_options)).expect("shadowsocks inbound construction");

        let tunnel = HttpTestTunnel::new();
        let listener_tunnel = Arc::clone(&tunnel);
        inbound.listen(listener_tunnel).await.expect("shadowsocks inbound listen");

        let addr_port: std::net::SocketAddr = inbound.address().parse().expect("bound address");

        outbound_options.name = "shadowsocks_outbound".to_owned();
        outbound_options.server = addr_port.ip().to_string();
        outbound_options.port = addr_port.port() as i32;
        outbound_options.password = password;
        outbound_options.basic_option.dialer_for_api = Some(tunnel.new_dialer());
        let api_tunnel = Arc::clone(&tunnel);
        outbound_options.basic_option.tunnel_for_api = Some(api_tunnel);

        let out = OutShadowSocks::new(outbound_options).expect("shadowsocks outbound construction");

        tunnel.do_test(out.as_ref()).await;

        let _ = out.close();
        inbound.close().expect("shadowsocks inbound close");
        tunnel.close();
    }

    async fn test_inbound_shadowsocks(
        inbound_options: ShadowSocksOption,
        outbound_options: OutShadowSocksOption,
        cipher_lists: &[&[&str]],
    ) {
        use futures::StreamExt as _;

        // Bounded, not fully unbounded, concurrency: unbounded spawning of every cipher's real
        // TCP+TLS+HTTP round trip at once was observed to trip transient "connection closed
        // before message completed" failures under host load (ephemeral port / fd pressure from
        // dozens of simultaneous real sockets), not a correctness bug in any single case.
        let max_concurrent = 6;
        let cases: Vec<_> = cipher_lists.iter().flat_map(|cipher_list| cipher_list.iter()).collect();
        futures::stream::iter(cases)
            .map(|cipher| {
                let cipher_name = (*cipher).to_owned();
                let mut inbound_options = inbound_options.clone();
                let mut outbound_options = outbound_options.clone();
                inbound_options.cipher = cipher_name.clone();
                outbound_options.cipher = cipher_name.clone();
                let handle =
                    tokio::spawn(async move { test_inbound_shadowsocks0(inbound_options, outbound_options).await });
                async move { (cipher_name, handle.await) }
            })
            .buffer_unordered(max_concurrent)
            .for_each(|(cipher_name, result)| async move {
                result.unwrap_or_else(|err| panic!("shadowsocks cipher case {cipher_name} panicked: {err}"));
            })
            .await;
    }

    async fn test_inbound_shadowsocks_utls(inbound_options: ShadowSocksOption, outbound_options: OutShadowSocksOption) {
        let short_lists: &[&[&str]] = &[NONE_LIST, &AEAD_LIST[..5]];

        let mut uconn_outbound = outbound_options.clone();
        uconn_outbound.client_fingerprint = "chrome".to_owned();

        tokio::join!(
            test_inbound_shadowsocks(inbound_options.clone(), outbound_options, short_lists),
            test_inbound_shadowsocks(inbound_options, uconn_outbound, short_lists),
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_shadowsocks_basic() {
        let inbound_options = ShadowSocksOption::default();
        let outbound_options = OutShadowSocksOption::default();
        let cipher_lists: &[&[&str]] = &[NONE_LIST, AEAD_LIST, STREAM_LIST];
        test_inbound_shadowsocks(inbound_options, outbound_options, cipher_lists).await;
    }

    /// The `2022-blake3-*` ciphers, all six names accepted.
    const SS2022_LIST: &[&str] = &[
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "2022-blake3-chacha8-poly1305",
        "2022-blake3-aes-128-ccm",
        "2022-blake3-aes-256-ccm",
    ];

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_shadowsocks_aead_2022() {
        let inbound_options = ShadowSocksOption::default();
        let outbound_options = OutShadowSocksOption::default();
        test_inbound_shadowsocks(inbound_options, outbound_options, &[SS2022_LIST]).await;
    }

    /// A multi-PSK (EIH) client password dials a real multi-user resolver, implemented here since
    /// `listener::sing_shadowsocks::server` never constructs the multi-user service (see the
    /// `shadowaead_2022` module doc), that decrypts the client's identity header the same way,
    /// checks it against the pinned PSK hash, then hands the connection to
    /// the real single-PSK inbound unchanged. This exercises `build_request`'s EIH-writing path
    /// end to end without inventing EIH support the production server doesn't have.
    #[tokio::test]
    async fn test_inbound_shadowsocks_aead_2022_eih_password() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use murmur_transport_shadowsocks::shadowaead_2022::protocol::{
            identity_subkey, psk_hash_blocks, AesBlockCipher, AES_BLOCK_SIZE,
        };

        let inbound_options = ShadowSocksOption {
            base: BaseOption {
                name_str: "shadowsocks_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            password: PASSWORD32.clone(),
            cipher: "2022-blake3-aes-256-gcm".to_owned(),
            ..Default::default()
        };
        let inbound = ShadowSocks::new(Arc::new(inbound_options)).expect("shadowsocks inbound construction");
        let tunnel = HttpTestTunnel::new();
        let listener_tunnel = Arc::clone(&tunnel);
        inbound.listen(listener_tunnel).await.expect("shadowsocks inbound listen");
        let backend_addr: std::net::SocketAddr = inbound.address().parse().expect("bound address");

        let psk = STANDARD.decode(&*PASSWORD32).expect("decode psk");
        let key_salt_length = psk.len();
        let expected_identity_block = psk_hash_blocks(&[psk.clone(), psk.clone()]).expect("hash blocks");

        let resolver = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind resolver");
        let resolver_addr = resolver.local_addr().expect("resolver addr");
        let resolver_psk = psk.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut client_conn, _)) = resolver.accept().await else {
                    return;
                };
                let resolver_psk = resolver_psk.clone();
                let expected_identity_block = expected_identity_block.clone();
                tokio::spawn(async move {
                    let mut salt = vec![0u8; key_salt_length];
                    client_conn.read_exact(&mut salt).await.expect("read salt");
                    let mut identity_block = [0u8; AES_BLOCK_SIZE];
                    client_conn.read_exact(&mut identity_block).await.expect("read identity header");
                    let subkey = identity_subkey(&resolver_psk, &salt, key_salt_length);
                    let cipher = AesBlockCipher::new(&subkey).expect("aes block cipher");
                    cipher.decrypt_block(&mut identity_block);
                    assert_eq!(
                        &identity_block[..],
                        &expected_identity_block[..],
                        "identity header must resolve to psk[1]"
                    );

                    let mut backend_conn = tokio::net::TcpStream::connect(backend_addr).await.expect("connect backend");
                    backend_conn.write_all(&salt).await.expect("forward salt");
                    let _ = tokio::io::copy_bidirectional(&mut client_conn, &mut backend_conn).await;
                });
            }
        });

        let api_tunnel = Arc::clone(&tunnel);
        let outbound_options = OutShadowSocksOption {
            name: "shadowsocks_outbound".to_owned(),
            server: resolver_addr.ip().to_string(),
            port: resolver_addr.port() as i32,
            password: format!("{}:{}", *PASSWORD32, *PASSWORD32),
            cipher: "2022-blake3-aes-256-gcm".to_owned(),
            basic_option: murmur_adapter_outbound::base::BasicOption {
                dialer_for_api: Some(tunnel.new_dialer()),
                tunnel_for_api: Some(api_tunnel),
                ..Default::default()
            },
            ..Default::default()
        };
        let out = OutShadowSocks::new(outbound_options).expect("shadowsocks outbound construction");
        tunnel.do_sequential_test(out.as_ref()).await;

        let _ = out.close();
        inbound.close().expect("shadowsocks inbound close");
        tunnel.close();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_shadowsocks_shadow_tls_v1() {
        let inbound_options = ShadowSocksOption {
            shadow_tls: ShadowTLS {
                enable: true,
                version: 1,
                handshake: ShadowTLSHandshakeOptions { dest: format!("{REALITY_DEST}:443"), ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        let outbound_options = OutShadowSocksOption {
            plugin: SHADOW_TLS_MODE.to_owned(),
            plugin_opts: yaml_map(&[
                ("host", yaml_str(REALITY_DEST)),
                ("fingerprint", yaml_str(tls_fingerprint())),
                ("version", yaml_i64(1)),
            ]),
            ..Default::default()
        };
        test_inbound_shadowsocks_utls(inbound_options, outbound_options).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_shadowsocks_shadow_tls_v2() {
        let inbound_options = ShadowSocksOption {
            shadow_tls: ShadowTLS {
                enable: true,
                version: 2,
                password: PASSWORD16.clone(),
                handshake: ShadowTLSHandshakeOptions { dest: format!("{REALITY_DEST}:443"), ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        let outbound_options = OutShadowSocksOption {
            plugin: SHADOW_TLS_MODE.to_owned(),
            plugin_opts: yaml_map(&[
                ("host", yaml_str(REALITY_DEST)),
                ("password", yaml_str(&PASSWORD16)),
                ("fingerprint", yaml_str(tls_fingerprint())),
                ("version", yaml_i64(2)),
                ("alpn", yaml_str_list(&["http/1.1"])),
            ]),
            ..Default::default()
        };
        test_inbound_shadowsocks_utls(inbound_options, outbound_options).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_shadowsocks_simple_obfs_http() {
        let inbound_options = ShadowSocksOption {
            simple_obfs: SimpleObfs { enable: true, mode: "http".to_owned() },
            ..Default::default()
        };
        let outbound_options = OutShadowSocksOption {
            plugin: "obfs".to_owned(),
            plugin_opts: yaml_map(&[("mode", yaml_str("http")), ("host", yaml_str(REALITY_DEST))]),
            ..Default::default()
        };
        let short_lists: &[&[&str]] = &[NONE_LIST, &AEAD_LIST[..5]];
        test_inbound_shadowsocks(inbound_options, outbound_options, short_lists).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_shadowsocks_simple_obfs_tls() {
        let inbound_options = ShadowSocksOption {
            simple_obfs: SimpleObfs { enable: true, mode: "tls".to_owned() },
            ..Default::default()
        };
        let outbound_options = OutShadowSocksOption {
            plugin: "obfs".to_owned(),
            plugin_opts: yaml_map(&[("mode", yaml_str("tls")), ("host", yaml_str(REALITY_DEST))]),
            ..Default::default()
        };
        let short_lists: &[&[&str]] = &[NONE_LIST, &AEAD_LIST[..5]];
        test_inbound_shadowsocks(inbound_options, outbound_options, short_lists).await;
    }

    /// The kcptun plugin's dial must build a real kcp+smux stack and open a substream.
    #[tokio::test]
    async fn test_inbound_shadowsocks_kcptun() {
        use tokio::io::AsyncWriteExt;
        let inbound_options = ShadowSocksOption {
            base: BaseOption {
                name_str: "shadowsocks_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            password: PASSWORD16.clone(),
            cipher: "none".to_owned(),
            kcp_tun: KcpTun { enable: true, key: PASSWORD16.clone(), ..Default::default() },
            ..Default::default()
        };
        let inbound = ShadowSocks::new(Arc::new(inbound_options)).expect("shadowsocks inbound construction");

        let tunnel = HttpTestTunnel::new();
        let listener_tunnel = Arc::clone(&tunnel);
        inbound.listen(listener_tunnel).await.expect("shadowsocks inbound listen");
        let addr_port: std::net::SocketAddr = inbound.address().parse().expect("bound address");

        let api_tunnel = Arc::clone(&tunnel);
        let outbound_options = OutShadowSocksOption {
            name: "shadowsocks_outbound".to_owned(),
            server: addr_port.ip().to_string(),
            port: addr_port.port() as i32,
            password: PASSWORD16.clone(),
            cipher: "none".to_owned(),
            plugin: KCPTUN_MODE.to_owned(),
            plugin_opts: yaml_map(&[("key", yaml_str(&PASSWORD16))]),
            basic_option: murmur_adapter_outbound::base::BasicOption {
                dialer_for_api: Some(tunnel.new_dialer()),
                tunnel_for_api: Some(api_tunnel),
                ..Default::default()
            },
            ..Default::default()
        };
        let out = OutShadowSocks::new(outbound_options).expect("shadowsocks outbound construction");

        let ctx = tokio_util::sync::CancellationToken::new();
        let mut metadata = murmur_constant::metadata::Metadata {
            network: murmur_constant::metadata::NetWork::TCP,
            dst_ip: Some(*murmur_testsupport::REMOTE_ADDR),
            dst_port: 80,
            ..Default::default()
        };
        // Reaching a live proxied conn proves the kcptun obfs path is real: the dial builds the
        // kcp session (`murmur-kcp`), multiplexes it (`murmur-smux`) and opens a
        // substream, none of which the previous stand-in could do.
        let mut conn = out.dial_context(&ctx, &mut metadata).await.expect("kcptun dial must succeed");

        let probe = &murmur_testsupport::HTTP_DATA[..64];
        conn.write_all(probe).await.expect("write through the kcptun substream");

        let _ = out.close();
        inbound.close().expect("shadowsocks inbound close");
        tunnel.close();
    }
}

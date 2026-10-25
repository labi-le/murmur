use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common::structure::structure::{new_decoder, Option as StructureOption};
use murmur_component::dialer::bind::join_host_port;
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport_jls::client as jls;
use murmur_transport_shadowtls::{self as shadowtls, client::ShadowTLSOption as TransportShadowTLSOption};
use murmur_transport_simple_obfs::{http::new_http_obfs, tls::new_tls_obfs};
use murmur_transport_snell::pool::{new_pool, Pool};
use murmur_transport_snell::snell::{self as snellt, Snell as SnellStream};

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter as BaseProxyAdapter};
use super::shadowsocks::{JlsOption, RestlsOption, ShadowTLSOption as ShadowTlsOpt, SimpleObfsOption};
use super::util::safe_conn_close;

pub struct Snell {
    base: Base,
    option: SnellOption,
    psk: Vec<u8>,
    pool: std::sync::OnceLock<Arc<Pool>>,
    obfs_option: SimpleObfsOption,
    shadow_tls_option: Option<TransportShadowTLSOption>,
    restls_config: Option<Arc<murmur_restls::Config>>,
    jls_option: Option<jls::ClientConfig>,
    version: i32,
    reuse: bool,
    self_weak: Weak<Self>,
}

impl core::fmt::Debug for Snell {
    /// Redacts `psk` so accidental `{:?}` logging cannot leak it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Snell")
            .field("name", &self.base.name)
            .field("addr", &self.base.addr)
            .field("psk", &"<redacted>")
            .field("version", &self.version)
            .field("reuse", &self.reuse)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct SnellOption {
    pub basic_option: BasicOption,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub psk: String,
    pub udp: bool,
    pub version: i32,
    pub reuse: bool,
    pub obfs_opts: yaml_serde::Mapping,
    pub client_fingerprint: String,
}

impl core::fmt::Debug for SnellOption {
    /// Redacts `psk` so accidental `{:?}` logging cannot leak it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SnellOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("psk", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// The obfs-plugin settings decoded from `SnellOption::obfs_opts`; only the backend named by the
/// mode is populated.
struct ObfsSetup {
    obfs_option: SimpleObfsOption,
    shadow_tls_option: Option<TransportShadowTLSOption>,
    restls_config: Option<Arc<murmur_restls::Config>>,
    jls_option: Option<jls::ClientConfig>,
}

fn decode_obfs(option: &SnellOption, addr: &str) -> Result<ObfsSetup> {
    let decoder =
        new_decoder(StructureOption { tag_name: "obfs".to_owned(), weakly_typed_input: true, key_replacer: None });
    let obfs_option: SimpleObfsOption =
        decoder.decode(&option.obfs_opts).map_err(|err| anyhow!("snell {addr} initialize obfs error: {err}"))?;

    let mut shadow_tls_option: Option<TransportShadowTLSOption> = None;
    let mut restls_config: Option<Arc<murmur_restls::Config>> = None;
    let mut jls_option: Option<jls::ClientConfig> = None;

    match obfs_option.mode.as_str() {
        "tls" | "http" | "" => {}
        mode if mode == shadowtls::client::MODE => {
            let opt: ShadowTlsOpt = decoder
                .decode(&option.obfs_opts)
                .map_err(|err| anyhow!("snell {addr} initialize shadow-tls-plugin error: {err}"))?;
            let alpn = opt.alpn.unwrap_or_else(|| shadowtls::client::DEFAULT_ALPN.clone());
            shadow_tls_option = Some(TransportShadowTLSOption {
                password: opt.password,
                host: opt.host,
                fingerprint: opt.fingerprint,
                certificate: opt.certificate,
                private_key: opt.private_key,
                client_fingerprint: option.client_fingerprint.clone(),
                skip_cert_verify: opt.skip_cert_verify,
                name_cert_verify: opt.name_cert_verify,
                version: opt.version,
                alpn,
            });
        }
        "restls" => {
            let opt: RestlsOption = decoder
                .decode(&option.obfs_opts)
                .map_err(|err| anyhow!("snell {addr} initialize restls-plugin error: {err}"))?;
            let version_hint = if opt.force_tls12 { "tls12" } else { opt.version_hint.as_str() };
            let mut config =
                murmur_restls::new_restls_config(&opt.host, &opt.password, version_hint, &opt.restls_script)
                    .map_err(|err| anyhow!("snell {addr} initialize restls-plugin error: {err}"))?;
            config.insecure_skip_verify = opt.skip_cert_verify;
            if !opt.fingerprint.is_empty() {
                murmur_restls::config::set_fingerprint(&mut config, &opt.fingerprint, &opt.name_cert_verify)
                    .map_err(|err| anyhow!("snell {addr} initialize restls-plugin error: {err}"))?;
            } else if !opt.name_cert_verify.is_empty() {
                murmur_restls::config::set_name_cert_verify(&mut config, &opt.name_cert_verify);
            }
            restls_config = Some(Arc::new(config));
        }
        mode if mode == jls::MODE => {
            let opt: JlsOption = decoder
                .decode(&option.obfs_opts)
                .map_err(|err| anyhow!("snell {addr} initialize jls-plugin error: {err}"))?;
            jls_option = Some(
                jls::new_client_config(&opt.host, &opt.username, &opt.password, opt.alpn)
                    .map_err(|err| anyhow!("snell {addr} initialize jls-plugin error: {err}"))?,
            );
        }
        _ => return Err(anyhow!("snell {addr} obfs mode error: {}", obfs_option.mode)),
    }

    Ok(ObfsSetup { obfs_option, shadow_tls_option, restls_config, jls_option })
}

/// Resolves the version defaults and reports whether the result keeps a connection pool.
fn normalize_version(option: &mut SnellOption) -> Result<bool> {
    if option.version == 0 {
        option.version = snellt::DEFAULT_SNELL_VERSION;
    }
    if option.version == snellt::VERSION5 {
        option.version = snellt::VERSION4;
    }
    let reuse = option.version == snellt::VERSION2 || (option.version == snellt::VERSION4 && option.reuse);
    match option.version {
        snellt::VERSION1 | snellt::VERSION2 => {
            if option.udp {
                return Err(anyhow!("snell version {} not support UDP", option.version));
            }
        }
        snellt::VERSION3 | snellt::VERSION4 => {}
        _ => return Err(anyhow!("snell version error: {}", option.version)),
    }
    Ok(reuse)
}

impl Snell {
    pub fn new(mut option: SnellOption) -> Result<Arc<Self>> {
        let addr = join_host_port(&option.server, option.port);
        let psk = option.psk.as_bytes().to_vec();

        let obfs = decode_obfs(&option, &addr)?;

        let reuse = normalize_version(&mut option)?;

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr: addr.clone(),
            type_: AdapterType::SNELL,
            provider_name: option.basic_option.provider_name.clone(),
            udp: option.udp,
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
            xudp: false,
        });
        let dial_options = base.dial_options();
        let dialer = option.basic_option.new_dialer(dial_options);
        base.dialer = Some(Arc::clone(&dialer));
        let version = option.version;

        let s = Arc::new_cyclic(|weak| Self {
            base,
            option,
            psk,
            pool: std::sync::OnceLock::new(),
            obfs_option: obfs.obfs_option,
            shadow_tls_option: obfs.shadow_tls_option,
            restls_config: obfs.restls_config,
            jls_option: obfs.jls_option,
            version,
            reuse,
            self_weak: Weak::clone(weak),
        });

        if reuse {
            let self_weak = Weak::clone(&s.self_weak);
            let dialer_for_pool = dialer;
            let addr_for_pool = addr;
            let pool = new_pool(move |ctx| {
                let self_weak = Weak::clone(&self_weak);
                let dialer = Arc::clone(&dialer_for_pool);
                let addr = addr_for_pool.clone();
                async move {
                    let this = self_weak.upgrade().ok_or_else(|| anyhow!("Snell adapter dropped"))?;
                    let c = dialer.dial_context(&ctx, "tcp", &addr).await?;
                    // S11: remove with std-compat (murmur_transport_snell::snell::stream_conn requires the old Conn)
                    let c: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(c));
                    this.stream_conn_context(&ctx, c).await
                }
            });
            let _ = s.pool.set(pool);
        }

        Ok(s)
    }
    async fn stream_conn_context(&self, ctx: &CancellationToken, c: Box<dyn NetConn>) -> Result<SnellStream> {
        // NOT cancel-safe: the restls handshake consumes the connection, so a drop loses it.
        let mut c = c;
        match self.obfs_option.mode.as_str() {
            "tls" => c = new_tls_obfs(c, self.obfs_option.host.clone()),
            "http" => {
                let (_, port, _) = murmur_common_net::split_host_port(&self.base.addr()).unwrap_or_default();
                c = new_http_obfs(c, self.obfs_option.host.clone(), port);
            }
            mode if mode == shadowtls::client::MODE => {
                c = Box::new(murmur_common_net::io::StreamAsOldConn::new(
                    shadowtls::client::new_shadow_tls(
                        ctx,
                        Box::new(murmur_common_net::io::OldConnAsStream(c)),
                        self.shadow_tls_option.as_ref(),
                    )
                    .await?,
                ));
            }
            "restls" => {
                let config = self.restls_config.as_ref().ok_or_else(|| anyhow!("restls_config set for restls mode"))?;
                c = tokio::select! {
                    biased;
                    () = ctx.cancelled() => return Err(anyhow!("{} (restls) connect error: context canceled", self.base.addr())),
                    result = murmur_restls::new_restls(c, config) => {
                        result.map_err(|err| anyhow!("{} (restls) connect error: {err}", self.base.addr()))?
                    }
                };
            }
            mode if mode == jls::MODE => {
                c = jls::new_client(ctx, c, self.jls_option.as_ref().ok_or_else(|| anyhow!("jls: nil client option"))?)
                    .await?;
            }
            _ => {}
        }
        Ok(snellt::stream_conn(c, &self.psk, self.version))
    }

    /// The runtime type check in the header writer: only a raw (non-pooled) connection exposes the
    /// reply reader, so a pooled reuse connection silently skips it, matching the failed type
    /// assertion.
    async fn write_header_context<C>(&self, c: &mut C, metadata: &Metadata) -> Result<()>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + MaybeSnellReply,
    {
        if metadata.network == NetWork::UDP {
            snellt::write_udp_header(c, self.version).await?;
            if self.version >= snellt::VERSION4 {
                if let Some(sc) = c.as_snell_stream_mut() {
                    sc.read_reply().await?;
                }
            }
            return Ok(());
        }
        snellt::write_header_with_reuse(c, &metadata.string(), u32::from(metadata.dst_port), self.version, self.reuse)
            .await
    }
}

/// The runtime type check on the connection in the header writer: the connection keeps its runtime
/// type info through every obfs wrapper — shadow-tls, whose TLS setup is the deepest stack,
/// included. This adapter keeps the same guarantee by carrying the concrete [`SnellStream`] out of
/// `stream_conn_context` rather than erasing it.
trait MaybeSnellReply {
    fn as_snell_stream_mut(&mut self) -> Option<&mut SnellStream>;
}

impl MaybeSnellReply for SnellStream {
    fn as_snell_stream_mut(&mut self) -> Option<&mut SnellStream> {
        Some(self)
    }
}

impl MaybeSnellReply for murmur_transport_snell::pool::PoolConn {
    fn as_snell_stream_mut(&mut self) -> Option<&mut SnellStream> {
        None
    }
}

#[async_trait]
impl CProxyAdapter for Snell {
    fn name(&self) -> String {
        self.base.name()
    }

    fn type_(&self) -> AdapterType {
        self.base.type_()
    }

    fn addr(&self) -> String {
        self.base.addr()
    }

    fn support_udp(&self) -> bool {
        self.base.support_udp()
    }

    fn proxy_info(&self) -> ProxyInfo {
        let mut info = self.base.proxy_info();
        info.dialer_proxy.clone_from(&self.option.basic_option.dialer_proxy);
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        if self.reuse {
            let pool = self.pool.get().ok_or_else(|| anyhow!("Snell.pool must be set when reuse is enabled"))?;
            let mut c = pool.get().await?;
            if let Err(err) = self.write_header_context(&mut c, metadata).await {
                let _ = c.close_async().await;
                return Err(err);
            }
            c.mark_reusable();
            // S11: remove with std-compat (transport_snell::pool::PoolConn is old-Conn-based)
            return Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(c)), self));
        }

        let dialer = self.base.dialer.as_ref();
        let dialer = dialer.ok_or_else(|| anyhow!("Snell.base.dialer must be set before DialContext"))?;
        let addr = self.base.addr();
        let raw = dialer.dial_context(ctx, "tcp", &addr).await.map_err(|err| anyhow!("{addr} connect error: {err}"))?;
        // S11: remove with std-compat (murmur_common::shared_conn::SharedConn is old-Conn-based)
        let raw: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(raw));

        let shared = SharedConn::from_boxed(raw);
        let result: Result<SnellStream> = async {
            let mut c = self.stream_conn_context(ctx, Box::new(shared.clone())).await?;
            self.write_header_context(&mut c, metadata).await?;
            Ok(c)
        }
        .await;
        safe_conn_close(Some(&shared), result.is_err());
        let c = result?;
        // S11: remove with std-compat (murmur_transport_snell::snell::Snell is old-Conn-based)
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(c)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        BaseProxyAdapter::resolve_udp(self, ctx, metadata).await?;
        let dialer = self.base.dialer.as_ref();
        let dialer = dialer.ok_or_else(|| anyhow!("Snell.base.dialer must be set before ListenPacketContext"))?;
        let addr = self.base.addr();
        let raw = dialer.dial_context(ctx, "tcp", &addr).await?;
        // S11: remove with std-compat (murmur_common::shared_conn::SharedConn is old-Conn-based)
        let raw: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(raw));

        let shared = SharedConn::from_boxed(raw);
        let result: Result<SnellStream> = async {
            let mut c = self.stream_conn_context(ctx, Box::new(shared.clone())).await?;
            self.write_header_context(&mut c, metadata).await?;
            Ok(c)
        }
        .await;
        safe_conn_close(Some(&shared), result.is_err());
        let c = result?;

        let this = self.self_weak.upgrade().ok_or_else(|| anyhow!("Snell adapter dropped"))?;
        let pc = snellt::packet_conn(snellt::PacketConnConn::Snell(c));
        // S11: remove with std-compat (transport_snell::snell::packet_conn returns the old PacketConn)
        let pc: Arc<dyn murmur_common_net::io::Datagram> = Arc::new(murmur_common_net::io::OldPacketConnAsDatagram(pc));
        Ok(new_packet_conn(pc, this))
    }

    fn support_uot(&self) -> bool {
        true
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.base.is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.base.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        self.base.close()
    }
}

#[async_trait]
impl BaseProxyAdapter for Snell {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}

#[cfg(test)]
mod restls_cancellation_tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn stalled_restls_handshake_obeys_cancellation() {
        let adapter = Snell::new(SnellOption {
            server: "localhost".into(),
            port: 443,
            version: snellt::VERSION3,
            obfs_opts: yaml_serde::from_str("mode: restls\nhost: localhost\npassword: secret\nversion-hint: tls13")
                .unwrap(),
            ..Default::default()
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let ctx = CancellationToken::new();
        let cancel = ctx.clone();
        let server_task = async move {
            let mut first_byte = [0];
            server.read_exact(&mut first_byte).await.unwrap();
            cancel.cancel();
            let mut rest = [0; 4096];
            loop {
                if server.read(&mut rest).await.unwrap() == 0 {
                    break 0;
                }
            }
        };
        let (result, remaining) = timeout(Duration::from_secs(2), async {
            tokio::join!(adapter.stream_conn_context(&ctx, Box::new(client)), server_task)
        })
        .await
        .expect("cancelled Restls handshake stalled");
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("cancelled handshake succeeded"),
        };
        assert!(err.to_string().contains("cancel"), "{err}");
        assert_eq!(remaining, 0);
    }
}

use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{
    close_stream, CancellableStream, Datagram, DatagramAsOldPacketConn, OldConnAsStream, Stream,
};
use murmur_common_net::{
    new_thread_safe_packet_conn, old_enhance_packet_conn_as_enhance_datagram, setup_context_for_conn,
};
use murmur_component::dialer::bind::join_host_port;
use murmur_component::dialer::options::NetDialerFunc;
use murmur_constant::adapters::{
    Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::PacketConn as NetPacketConn;
use murmur_transport_sudoku::address::encode_address;
use murmur_transport_sudoku::config::{
    default_config, deref_bool, normalize_table_type, resolve_padding, ProtocolConfig,
};
use murmur_transport_sudoku::handshake::client_handshake;
use murmur_transport_sudoku::httpmask_tunnel::{dial_http_mask_tunnel, TunnelDialer};
use murmur_transport_sudoku::init::client_aead_seed;
use murmur_transport_sudoku::kip::{write_kip_message, KIP_TYPE_OPEN_TCP, KIP_TYPE_START_UOT};
use murmur_transport_sudoku::multiplex_dialer::{MultiplexBaseDialer, MultiplexDialer};
use murmur_transport_sudoku::obfs::httpmask::tunnel_api::{
    new_tunnel_client, TunnelClient, TunnelClientOptions, TunnelDialOptions,
};
use murmur_transport_sudoku::tables::new_client_tables_with_custom_patterns;
use murmur_transport_sudoku::uot::UoTPacketConn;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};

pub struct Sudoku {
    base: Base,
    option: SudokuOption,
    base_conf: ProtocolConfig,

    mux_dialer: Option<Arc<MultiplexDialer>>,

    http_mask: tokio::sync::Mutex<HttpMaskState>,

    self_weak: Weak<Self>,
}

impl core::fmt::Debug for Sudoku {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sudoku")
            .field("name", &self.base.name())
            .field("addr", &self.base.addr())
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct HttpMaskState {
    client: Option<Arc<TunnelClient>>,
    key: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SudokuOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "server")]
    pub server: String,
    #[serde(rename = "port")]
    pub port: i32,
    #[serde(rename = "key")]
    pub key: String,
    #[serde(rename = "aead-method", default)]
    pub aead_method: String,
    #[serde(rename = "padding-min", default)]
    pub padding_min: Option<i32>,
    #[serde(rename = "padding-max", default)]
    pub padding_max: Option<i32>,
    #[serde(rename = "table-type", default)]
    pub table_type: String,
    #[serde(rename = "enable-pure-downlink", default)]
    pub enable_pure_downlink: Option<bool>,
    #[serde(rename = "http-mask", default)]
    pub http_mask: Option<bool>,
    #[serde(rename = "http-mask-mode", default)]
    pub http_mask_mode: String,
    #[serde(rename = "http-mask-tls", default)]
    pub http_mask_tls: bool,
    #[serde(rename = "http-mask-host", default)]
    pub http_mask_host: String,
    #[serde(rename = "path-root", default)]
    pub path_root: String,
    #[serde(rename = "multiplex", default)]
    pub multiplex: String,
    #[serde(rename = "http-mask-multiplex", default)]
    pub http_mask_multiplex: String,
    #[serde(rename = "httpmask", default)]
    pub http_mask_options: Option<SudokuHttpMaskOptions>,
    #[serde(rename = "custom-table", default)]
    pub custom_table: String,
    #[serde(rename = "custom-tables", default)]
    pub custom_tables: Vec<String>,
}

impl core::fmt::Debug for SudokuOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SudokuOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("key", &"<redacted>")
            .field("table_type", &self.table_type)
            .field("custom_table", &self.custom_table)
            .field("custom_tables", &self.custom_tables)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SudokuHttpMaskOptions {
    #[serde(rename = "disable", default)]
    pub disable: bool,
    #[serde(rename = "mode", default)]
    pub mode: String,
    #[serde(rename = "tls", default)]
    pub tls: bool,
    #[serde(rename = "host", default)]
    pub host: String,
    #[serde(rename = "path-root", default)]
    pub path_root: String,
    #[serde(rename = "multiplex", default)]
    pub multiplex: String,
}

fn http_tunnel_mode_enabled(mode: &str) -> bool {
    matches!(mode.trim().to_lowercase().as_str(), "stream" | "poll" | "auto" | "ws")
}

struct HttpMaskSettings {
    disable_http_mask: bool,
    http_mask_mode: String,
    http_mask_tls: bool,
    http_mask_host: String,
    path_root: String,
    multiplex: String,
}

impl HttpMaskSettings {
    fn resolve(option: &SudokuOption, default_conf: &ProtocolConfig) -> Self {
        let mut settings = Self {
            disable_http_mask: option.http_mask.map_or(default_conf.disable_http_mask, |http_mask| !http_mask),
            http_mask_mode: default_conf.http_mask_mode.clone(),
            http_mask_tls: option.http_mask_tls,
            http_mask_host: option.http_mask_host.clone(),
            path_root: option.path_root.trim().to_owned(),
            multiplex: default_conf.multiplex.clone(),
        };
        if !option.http_mask_mode.is_empty() {
            option.http_mask_mode.clone_into(&mut settings.http_mask_mode);
        }
        if !option.multiplex.trim().is_empty() {
            option.multiplex.trim().clone_into(&mut settings.multiplex);
        }
        if !option.http_mask_multiplex.trim().is_empty() {
            option.http_mask_multiplex.trim().clone_into(&mut settings.multiplex);
        }
        let Some(hm) = &option.http_mask_options else {
            return settings;
        };
        settings.disable_http_mask = hm.disable;
        if !hm.mode.is_empty() {
            hm.mode.clone_into(&mut settings.http_mask_mode);
        }
        settings.http_mask_tls = hm.tls;
        hm.host.clone_into(&mut settings.http_mask_host);
        if !hm.path_root.trim().is_empty() {
            hm.path_root.trim().clone_into(&mut settings.path_root);
        }
        if !hm.multiplex.trim().is_empty() {
            hm.multiplex.trim().clone_into(&mut settings.multiplex);
        }
        settings
    }
}

impl Sudoku {
    pub fn new(option: SudokuOption) -> Result<Arc<Self>> {
        if option.server.is_empty() {
            return Err(anyhow!("server is required"));
        }
        if option.port <= 0 || option.port > 65535 {
            return Err(anyhow!("invalid port: {}", option.port));
        }
        if option.key.is_empty() {
            return Err(anyhow!("key is required"));
        }

        let default_conf = default_config();
        let table_type = normalize_table_type(&option.table_type)?;
        let (padding_min, padding_max) =
            resolve_padding(option.padding_min, option.padding_max, default_conf.padding_min, default_conf.padding_max);
        let enable_pure_downlink = deref_bool(option.enable_pure_downlink, default_conf.enable_pure_downlink);

        let mask_settings = HttpMaskSettings::resolve(&option, &default_conf);
        let port = u16::try_from(option.port).map_err(|_| anyhow!("invalid port: {}", option.port))?;

        let mut base_conf = ProtocolConfig {
            server_address: join_host_port(&option.server, port),
            key: option.key.clone(),
            aead_method: default_conf.aead_method.clone(),
            padding_min,
            padding_max,
            enable_pure_downlink,
            handshake_timeout_seconds: default_conf.handshake_timeout_seconds,
            disable_http_mask: mask_settings.disable_http_mask,
            http_mask_mode: mask_settings.http_mask_mode,
            http_mask_tls_enabled: mask_settings.http_mask_tls,
            http_mask_host: mask_settings.http_mask_host,
            http_mask_path_root: mask_settings.path_root,
            multiplex: mask_settings.multiplex,
            table: None,
            tables: Vec::new(),
            target_address: String::new(),
            http_mask_multiplex: String::new(),
        };

        let mut tables = new_client_tables_with_custom_patterns(
            &client_aead_seed(&option.key),
            &table_type,
            &option.custom_table,
            &option.custom_tables,
        )
        .map_err(|e| anyhow!("build table(s) failed: {e}"))?;
        if tables.len() == 1 {
            base_conf.table = tables.pop();
        } else {
            base_conf.tables = tables;
        }
        if !option.aead_method.is_empty() {
            option.aead_method.clone_into(&mut base_conf.aead_method);
        }
        base_conf.validate()?;

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr: base_conf.server_address.clone(),
            type_: murmur_constant::adapters::AdapterType::SUDOKU,
            provider_name: option.basic_option.provider_name.clone(),
            udp: true,
            xudp: false,
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
        });
        base.dialer = Some(option.basic_option.new_dialer(base.dial_options()));

        let session_mux_enabled = base_conf.session_mux_enabled();

        let this = Arc::new_cyclic(|self_weak| Self {
            base,
            base_conf: base_conf.clone(),
            mux_dialer: None,
            http_mask: tokio::sync::Mutex::new(HttpMaskState::default()),
            self_weak: Weak::clone(self_weak),
            option,
        });

        if session_mux_enabled {
            let sudoku_for_dial: Weak<Self> = Arc::downgrade(&this);
            let dial_base: MultiplexBaseDialer = Arc::new(move |ctx| {
                let sudoku = sudoku_for_dial.upgrade();
                Box::pin(async move {
                    let sudoku = sudoku.ok_or_else(|| anyhow!("Sudoku dropped while dialing multiplex base"))?;
                    let cfg = sudoku.base_conf.clone();
                    sudoku.dial_and_handshake(&ctx, &cfg).await
                })
            });
            let mux_dialer = MultiplexDialer::new(dial_base)?;
            // `this` is the sole strong owner right after `Arc::new_cyclic`; `Arc::get_mut` is safe
            // here because no other strong reference has been handed out yet.
            let mut this = this;
            match Arc::get_mut(&mut this) {
                Some(sudoku) => sudoku.mux_dialer = Some(mux_dialer),
                None => return Err(anyhow!("internal error: Sudoku Arc had more than one owner during construction")),
            }
            return Ok(this);
        }

        Ok(this)
    }

    fn build_config(&self, metadata: &Metadata) -> Result<ProtocolConfig> {
        if metadata.dst_port == 0 || !metadata.valid() {
            return Err(anyhow!("invalid metadata for sudoku outbound"));
        }

        let mut cfg = self.base_conf.clone();
        cfg.target_address = metadata.remote_address();

        cfg.validate_client()?;
        Ok(cfg)
    }

    async fn dial_multiplex(&self, ctx: &CancellationToken, target_address: &str) -> Result<Box<dyn Stream>> {
        let Some(mux_dialer) = &self.mux_dialer else {
            return Err(anyhow!("multiplex dialer is unavailable"));
        };
        mux_dialer.dial(ctx, target_address).await
    }

    async fn reset_http_mask_client(&self) {
        let client = {
            let mut state = self.http_mask.lock().await;
            let client = state.client.take();
            state.key.clear();
            client
        };
        if let Some(client) = client {
            client.close_idle_connections().await;
        }
    }

    async fn get_or_create_http_mask_client(&self, cfg: &ProtocolConfig) -> Result<Arc<TunnelClient>> {
        let key = format!("{}|{}|{}", cfg.server_address, cfg.http_mask_tls_enabled, cfg.http_mask_host.trim());

        {
            let state = self.http_mask.lock().await;
            if let Some(client) = &state.client {
                if state.key == key {
                    return Ok(Arc::clone(client));
                }
            }
        }

        let client = Arc::new(
            new_tunnel_client(
                &cfg.server_address,
                TunnelClientOptions {
                    tls_enabled: cfg.http_mask_tls_enabled,
                    host_override: cfg.http_mask_host.clone(),
                    dial_context: Some(Arc::new(NetDialerFunc::new(self.dialer_dial_fn_stream()))),
                    max_idle_conns: 32,
                },
            )
            .await?,
        );

        let mut state = self.http_mask.lock().await;
        if let Some(existing) = &state.client {
            if state.key == key {
                let existing = Arc::clone(existing);
                drop(state);
                client.close_idle_connections().await;
                return Ok(existing);
            }
        }
        let old = state.client.take();
        state.client = Some(Arc::clone(&client));
        state.key = key;
        drop(state);
        if let Some(old) = old {
            old.close_idle_connections().await;
        }
        Ok(client)
    }

    /// Adapts `Base.dialer`'s `Arc<dyn CDialer>` to the closure vocabulary
    /// `component::dialer::options::NetDialerFunc` expects.
    fn dialer_dial_fn_stream(
        &self,
    ) -> impl Fn(CancellationToken, String, String) -> futures::future::BoxFuture<'static, Result<Box<dyn Stream>>>
           + Send
           + Sync
           + 'static {
        let dialer = self.base.dialer.clone();
        move |ctx, network, addr| {
            let dialer = dialer.as_ref().map(Arc::clone);
            Box::pin(async move {
                let dialer = dialer.ok_or_else(|| anyhow!("dialer is not initialized"))?;
                dialer.dial_context(&ctx, &network, &addr).await
            })
        }
    }

    async fn dial_and_handshake(&self, ctx: &CancellationToken, cfg: &ProtocolConfig) -> Result<Box<dyn Stream>> {
        let mut handshake_cfg = cfg.clone();
        if !handshake_cfg.disable_http_mask && http_tunnel_mode_enabled(&handshake_cfg.http_mask_mode) {
            handshake_cfg.disable_http_mask = true;
        }

        let upgrade_cfg = handshake_cfg.clone();
        let upgrade: murmur_transport_sudoku::obfs::httpmask::early_handshake::WrapConnFn = Arc::new(move |raw| {
            let cfg = upgrade_cfg.clone();
            Box::pin(async move { client_handshake(raw, &cfg).await })
        });

        let mut c: Option<Box<dyn Stream>> = None;
        let mut handshake_done = false;

        if !cfg.disable_http_mask && http_tunnel_mode_enabled(&cfg.http_mask_mode) {
            let mux_mode = cfg.multiplex_mode();
            if mux_mode == "auto" && cfg.http_mask_mode.trim().to_lowercase() != "ws" {
                if let Ok(client) = self.get_or_create_http_mask_client(cfg).await {
                    match client
                        .dial_tunnel(
                            ctx,
                            TunnelDialOptions {
                                mode: cfg.http_mask_mode.clone(),
                                tls_enabled: cfg.http_mask_tls_enabled,
                                host_override: cfg.http_mask_host.clone(),
                                path_root: cfg.http_mask_path_root.clone(),
                                auth_key: client_aead_seed(&cfg.key),
                                early_handshake: None,
                                upgrade: Some(Arc::clone(&upgrade)),
                                dial_context: Some(Arc::new(NetDialerFunc::new(self.dialer_dial_fn_stream()))),
                            },
                        )
                        .await
                    {
                        Ok(conn) => c = Some(conn),
                        Err(_) => self.reset_http_mask_client().await,
                    }
                }
            }
            if c.is_none() {
                let dial: TunnelDialer = Arc::new(self.dialer_dial_fn_stream());
                c = Some(
                    dial_http_mask_tunnel(ctx, &cfg.server_address, cfg, Some(dial), Some(Arc::clone(&upgrade)))
                        .await?,
                );
            }
            if c.is_some() {
                handshake_done = true;
            }
        }

        let c: Box<dyn Stream> = match c {
            Some(c) => c,
            None => self
                .base
                .dialer
                .as_ref()
                .ok_or_else(|| anyhow!("dialer is not initialized"))?
                .dial_context(ctx, "tcp", &self.base.addr)
                .await
                .map_err(|e| anyhow!("{}: connect error: {e}", self.base.addr))?,
        };

        let shared = SharedConn::new(CancellableStream::new(c));
        let mut done = setup_context_for_conn(ctx, shared.clone());

        let result: Result<Box<dyn Stream>> = async {
            if handshake_done {
                let conn: Box<dyn Stream> = Box::new(OldConnAsStream(shared.clone()));
                Ok(conn)
            } else {
                client_handshake(Box::new(OldConnAsStream(shared.clone())), &handshake_cfg).await
            }
        }
        .await;

        let mut err = result.as_ref().err().map(|e| anyhow!("{e}"));
        done.call(&mut err).await;
        match err {
            Some(err) => Err(err),
            None => result,
        }
    }
}

#[async_trait]
impl CProxyAdapter for Sudoku {
    fn name(&self) -> String {
        self.base.name()
    }

    fn type_(&self) -> murmur_constant::adapters::AdapterType {
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
        self.option.basic_option.dialer_proxy.clone_into(&mut info.dialer_proxy);
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let cfg = self.build_config(metadata)?;

        if cfg.session_mux_enabled() {
            let stream = self.dial_multiplex(ctx, &cfg.target_address).await?;
            return Ok(new_conn(stream, self));
        }

        let c = self.dial_and_handshake(ctx, &cfg).await?;

        let addr_buf = encode_address(&cfg.target_address).map_err(|e| anyhow!("encode target address failed: {e}"))?;

        let mut c = c;
        write_kip_message(&mut c, KIP_TYPE_OPEN_TCP, &addr_buf)
            .await
            .map_err(|e| anyhow!("send target address failed: {e}"))?;

        Ok(new_conn(c, self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.resolve_udp(ctx, metadata).await?;

        let cfg = self.build_config(metadata)?;

        let mut c = self.dial_and_handshake(ctx, &cfg).await?;

        if let Err(e) = write_kip_message(&mut c, KIP_TYPE_START_UOT, &[]).await {
            let _ = close_stream(&*c);
            return Err(anyhow!("start uot failed: {e}"));
        }

        // S11: remove with std-compat (murmur_common_net::new_thread_safe_packet_conn still requires the old PacketConn)
        let uot: Arc<dyn NetPacketConn> = Arc::new(DatagramAsOldPacketConn(UoTPacketConn::new(c)));
        let enhanced = new_thread_safe_packet_conn(uot);
        // S11: remove with std-compat (bridges common-net's own old EnhancePacketConn back to Datagram for new_packet_conn)
        let enhanced: Arc<dyn Datagram> = old_enhance_packet_conn_as_enhance_datagram(enhanced);
        let self_arc =
            self.self_weak.upgrade().ok_or_else(|| anyhow!("Sudoku dropped while listen_packet_context is running"))?;
        Ok(new_packet_conn(enhanced, self_arc))
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
        if let Some(mux_dialer) = self.mux_dialer.clone() {
            tokio::task::block_in_place(|| {
                let _ = tokio::runtime::Handle::current().block_on(mux_dialer.close());
            });
        }
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.reset_http_mask_client());
        });
        self.base.close()
    }
}

#[async_trait]
impl ProxyAdapter for Sudoku {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}

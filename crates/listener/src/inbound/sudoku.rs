use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::inbound::mux::MuxOption;
use crate::sudoku::server as sudoku_server;
use murmur_component::dialer::control::join_errors;
use murmur_constant::listener::{InboundConfig, InboundListener, Listener as ConstListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::sudoku as lc_sudoku;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SudokuOption {
    pub base: BaseOption,
    pub key: String,
    pub aead_method: String,
    pub padding_min: Option<i32>,
    pub padding_max: Option<i32>,
    pub table_type: String,
    pub handshake_timeout_second: Option<i32>,
    pub enable_pure_downlink: Option<bool>,
    pub custom_table: String,
    pub custom_tables: Vec<String>,
    pub disable_http_mask: bool,
    pub http_mask_mode: String,
    pub path_root: String,
    pub fallback: String,
    pub http_mask_options: Option<SudokuHTTPMaskOptions>,

    /// A private extension (not part of the standard Sudoku protocol).
    pub mux_option: MuxOption,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SudokuHTTPMaskOptions {
    pub disable: bool,
    pub mode: String,
    pub path_root: String,
}

impl InboundConfig for SudokuOption {
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

pub struct Sudoku {
    base: Base,
    config: Arc<SudokuOption>,
    listeners: Mutex<Vec<Arc<sudoku_server::Listener>>>,
    server_conf: lc_sudoku::SudokuServer,
}

impl core::fmt::Debug for Sudoku {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sudoku")
            .field("base", &self.base)
            .field("config", &self.config)
            .field("server_conf", &self.server_conf)
            .finish_non_exhaustive()
    }
}

impl Sudoku {
    pub fn new(options: Arc<SudokuOption>) -> Result<Self> {
        if options.key.is_empty() {
            return Err(anyhow!("sudoku inbound requires key"));
        }
        let base = Base::new(Arc::new(options.base.clone()))?;

        let mut server_conf = {
            let lc_sudoku::SudokuServer { mux_option, .. } = lc_sudoku::SudokuServer::default();
            lc_sudoku::SudokuServer {
                enable: true,
                listen: base.raw_address(),
                key: options.key.clone(),
                aead_method: options.aead_method.clone(),
                padding_min: options.padding_min,
                padding_max: options.padding_max,
                table_type: options.table_type.clone(),
                handshake_timeout_second: options.handshake_timeout_second,
                enable_pure_downlink: options.enable_pure_downlink,
                custom_table: options.custom_table.clone(),
                custom_tables: options.custom_tables.clone(),
                disable_http_mask: options.disable_http_mask,
                http_mask_mode: options.http_mask_mode.clone(),
                path_root: options.path_root.trim().to_owned(),
                fallback: options.fallback.trim().to_owned(),
                mux_option,
            }
        };
        if let Some(hm) = &options.http_mask_options {
            server_conf.disable_http_mask = hm.disable;
            if !hm.mode.is_empty() {
                server_conf.http_mask_mode.clone_from(&hm.mode);
            }
            let pr = hm.path_root.trim();
            if !pr.is_empty() {
                pr.clone_into(&mut server_conf.path_root);
            }
        }
        server_conf.mux_option = options.mux_option.build();

        Ok(Self { base, config: options, listeners: Mutex::new(Vec::new()), server_conf })
    }
}

#[async_trait]
impl InboundListener for Sudoku {
    fn name(&self) -> String {
        self.base.name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        if self.server_conf.key.is_empty() {
            return Err(anyhow!("sudoku inbound requires key"));
        }

        let mut errs = Vec::new();
        let lc = self.base.listen_config();
        for addr in self.base.raw_address().split(',') {
            let mut conf = self.server_conf.clone();
            conf.listen = addr.to_owned();

            match sudoku_server::new(conf, Arc::clone(&lc), Arc::clone(&tunnel), self.base.additions()).await {
                Ok(l) => self.listeners.lock().push(l),
                Err(err) => errs.push(err),
            }
        }
        if !errs.is_empty() {
            return Err(join_errors(errs));
        }

        infoln!("Sudoku[{}] inbound listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        let mut errs = Vec::new();
        for l in self.listeners.lock().iter() {
            if let Err(err) = l.close() {
                errs.push(err);
            }
        }
        if !errs.is_empty() {
            return Err(join_errors(errs));
        }
        Ok(())
    }

    fn address(&self) -> String {
        self.listeners.lock().iter().map(|l| l.address()).collect::<Vec<_>>().join(",")
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
    use std::sync::LazyLock;

    use super::*;
    use murmur_adapter_outbound::sudoku::{Sudoku as OutSudoku, SudokuOption as OutSudokuOption};
    use murmur_constant::adapters::ProxyAdapter;
    use murmur_testsupport::HttpTestTunnel;
    use murmur_transport_sudoku::init::gen_key_pair;

    static SUDOKU_KEY_PAIR: LazyLock<(String, String)> = LazyLock::new(|| gen_key_pair().expect("sudoku key pair"));

    fn sudoku_private_key() -> &'static str {
        &SUDOKU_KEY_PAIR.0
    }
    fn sudoku_public_key() -> &'static str {
        &SUDOKU_KEY_PAIR.1
    }

    async fn test_inbound_sudoku(inbound_options: SudokuOption, mut outbound_options: OutSudokuOption) {
        let inbound_options = SudokuOption {
            base: BaseOption {
                name_str: "sudoku_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            ..inbound_options
        };
        let inbound = Sudoku::new(Arc::new(inbound_options)).expect("sudoku inbound construction");

        let tunnel = HttpTestTunnel::new();
        let listen_tunnel = Arc::clone(&tunnel);
        inbound.listen(listen_tunnel).await.expect("sudoku inbound listen");

        let addr_port: SocketAddr = inbound.address().parse().expect("bound address");

        outbound_options.name = "sudoku_outbound".to_owned();
        outbound_options.server = addr_port.ip().to_string();
        outbound_options.port = addr_port.port() as i32;
        outbound_options.basic_option.dialer_for_api = Some(tunnel.new_dialer());
        let tunnel_for_api = Arc::clone(&tunnel);
        outbound_options.basic_option.tunnel_for_api = Some(tunnel_for_api);

        let out = OutSudoku::new(outbound_options).expect("sudoku outbound construction");

        tunnel.do_test(out.as_ref()).await;

        let _ = out.close();
        inbound.close().expect("sudoku inbound close");
        tunnel.close();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_sudoku_basic() {
        let key = "test_key".to_owned();
        let inbound_options = SudokuOption { key: key.clone(), ..Default::default() };
        let outbound_options = OutSudokuOption { key: key.clone(), ..Default::default() };
        test_inbound_sudoku(inbound_options, outbound_options).await;

        let inbound_options = SudokuOption { key: sudoku_public_key().to_owned(), ..Default::default() };
        let outbound_options = OutSudokuOption { key: sudoku_private_key().to_owned(), ..Default::default() };
        test_inbound_sudoku(inbound_options, outbound_options).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_sudoku_entropy() {
        let key = "test_key_entropy".to_owned();
        let inbound_options =
            SudokuOption { key: key.clone(), table_type: "prefer_entropy".to_owned(), ..Default::default() };
        let outbound_options =
            OutSudokuOption { key: key.clone(), table_type: "prefer_entropy".to_owned(), ..Default::default() };
        test_inbound_sudoku(inbound_options, outbound_options).await;

        let inbound_options = SudokuOption {
            key: sudoku_public_key().to_owned(),
            table_type: "prefer_entropy".to_owned(),
            ..Default::default()
        };
        let outbound_options = OutSudokuOption {
            key: sudoku_private_key().to_owned(),
            table_type: "prefer_entropy".to_owned(),
            ..Default::default()
        };
        test_inbound_sudoku(inbound_options, outbound_options).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_sudoku_padding() {
        let key = "test_key_padding".to_owned();
        let inbound_options =
            SudokuOption { key: key.clone(), padding_min: Some(10), padding_max: Some(100), ..Default::default() };
        let outbound_options =
            OutSudokuOption { key: key.clone(), padding_min: Some(10), padding_max: Some(100), ..Default::default() };
        test_inbound_sudoku(inbound_options, outbound_options).await;

        let inbound_options = SudokuOption {
            key: sudoku_public_key().to_owned(),
            padding_min: Some(10),
            padding_max: Some(100),
            ..Default::default()
        };
        let outbound_options = OutSudokuOption {
            key: sudoku_private_key().to_owned(),
            padding_min: Some(10),
            padding_max: Some(100),
            ..Default::default()
        };
        test_inbound_sudoku(inbound_options, outbound_options).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_sudoku_packed_downlink() {
        let key = "test_key_packed".to_owned();
        let inbound_options =
            SudokuOption { key: key.clone(), enable_pure_downlink: Some(false), ..Default::default() };
        let outbound_options =
            OutSudokuOption { key: key.clone(), enable_pure_downlink: Some(false), ..Default::default() };
        test_inbound_sudoku(inbound_options, outbound_options).await;

        let inbound_options = SudokuOption {
            key: sudoku_public_key().to_owned(),
            enable_pure_downlink: Some(false),
            ..Default::default()
        };
        let outbound_options = OutSudokuOption {
            key: sudoku_private_key().to_owned(),
            enable_pure_downlink: Some(false),
            ..Default::default()
        };
        test_inbound_sudoku(inbound_options, outbound_options).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_sudoku_custom_table() {
        let key = "test_key_custom".to_owned();
        let custom = "xpxvvpvv".to_owned();
        let inbound_options = SudokuOption {
            key: key.clone(),
            table_type: "prefer_entropy".to_owned(),
            custom_table: custom.clone(),
            ..Default::default()
        };
        let outbound_options = OutSudokuOption {
            key: key.clone(),
            table_type: "prefer_entropy".to_owned(),
            custom_table: custom.clone(),
            ..Default::default()
        };
        test_inbound_sudoku(inbound_options, outbound_options).await;

        let inbound_options = SudokuOption {
            key: sudoku_public_key().to_owned(),
            table_type: "prefer_entropy".to_owned(),
            custom_table: custom.clone(),
            ..Default::default()
        };
        let outbound_options = OutSudokuOption {
            key: sudoku_private_key().to_owned(),
            table_type: "prefer_entropy".to_owned(),
            custom_table: custom.clone(),
            ..Default::default()
        };
        test_inbound_sudoku(inbound_options, outbound_options).await;
    }

    async fn test_inbound_sudoku_http_mask_mode(mode: &str) {
        let key = "test_key_http_mask_mode".to_owned();
        let inbound_options = SudokuOption { key: key.clone(), http_mask_mode: mode.to_owned(), ..Default::default() };
        let outbound_options = OutSudokuOption {
            key: key.clone(),
            http_mask: Some(true),
            http_mask_mode: mode.to_owned(),
            ..Default::default()
        };
        test_inbound_sudoku(inbound_options, outbound_options).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_sudoku_http_mask_mode_stream() {
        test_inbound_sudoku_http_mask_mode("stream").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_sudoku_http_mask_mode_poll() {
        test_inbound_sudoku_http_mask_mode("poll").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_sudoku_http_mask_mode_auto() {
        test_inbound_sudoku_http_mask_mode("auto").await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_sudoku_http_mask_mode_ws() {
        test_inbound_sudoku_http_mask_mode("ws").await;
    }
}

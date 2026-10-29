use std::sync::Arc;

use futures::future::BoxFuture;
use tokio_util::sync::CancellationToken;

use murmur_component_tls::utls::{Config as TlsConfig, VERSION_TLS13};

pub type GetEncryptedClientHelloConfigListFn =
    Arc<dyn Fn(CancellationToken, String) -> BoxFuture<'static, anyhow::Result<Vec<u8>>> + Send + Sync>;

pub struct Config {
    pub get_encrypted_client_hello_config_list: GetEncryptedClientHelloConfigListFn,
}

impl core::fmt::Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config").finish_non_exhaustive()
    }
}

impl Config {
    /// Resolves the ECH config list and raises the min/max TLS version to 1.3 when below it.
    // cancel-safe: nothing is written to `tls_config` until the resolver future resolves.
    pub async fn client_handle(&self, ctx: CancellationToken, tls_config: &mut TlsConfig) -> anyhow::Result<()> {
        let ech_config_list = (self.get_encrypted_client_hello_config_list)(ctx, tls_config.server_name.clone())
            .await
            .map_err(|err| anyhow::anyhow!("resolve ECH config error: {err}"))?;

        tls_config.encrypted_client_hello_config_list = ech_config_list;
        if tls_config.min_version != 0 && tls_config.min_version < VERSION_TLS13 {
            tls_config.min_version = VERSION_TLS13;
        }
        if tls_config.max_version != 0 && tls_config.max_version < VERSION_TLS13 {
            tls_config.max_version = VERSION_TLS13;
        }
        Ok(())
    }

    /// Resolves the ECH config list and raises the minimum TLS version to 1.3 when below it.
    // cancel-safe: nothing is written to `tls_config` until the resolver future resolves.
    pub async fn client_handle_utls(&self, ctx: CancellationToken, tls_config: &mut TlsConfig) -> anyhow::Result<()> {
        let ech_config_list = (self.get_encrypted_client_hello_config_list)(ctx, tls_config.server_name.clone())
            .await
            .map_err(|err| anyhow::anyhow!("resolve ECH config error: {err}"))?;

        tls_config.encrypted_client_hello_config_list = ech_config_list;
        if tls_config.min_version != 0 && tls_config.min_version < VERSION_TLS13 {
            tls_config.min_version = VERSION_TLS13;
        }
        if tls_config.max_version != 0 && tls_config.max_version < VERSION_TLS13 {
            tls_config.max_version = VERSION_TLS13;
        }
        Ok(())
    }
}

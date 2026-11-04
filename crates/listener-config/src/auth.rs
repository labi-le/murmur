use std::sync::Arc;

use murmur_component::auth::auth::AuthStore;

use crate::reality::RealityConfig;

/// `AuthServer` for http/socks/mixed server.
#[derive(Clone)]
pub struct AuthServer {
    pub enable: bool,
    pub listen: String,
    pub auth_store: Arc<dyn AuthStore>,
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
    pub reality_config: Option<RealityConfig>,
}

impl std::fmt::Debug for AuthServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `auth_store` has no `Debug` bound; the key material is left out on purpose.
        f.debug_struct("AuthServer")
            .field("enable", &self.enable)
            .field("listen", &self.listen)
            .field("client_auth_type", &self.client_auth_type)
            .field("reality_config", &self.reality_config)
            .finish_non_exhaustive()
    }
}

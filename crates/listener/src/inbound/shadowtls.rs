use std::collections::BTreeMap;

use murmur_listener_config::shadowtls as lc_shadowtls;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ShadowTLS {
    pub enable: bool,
    pub version: i32,
    pub password: String,
    pub handshake: ShadowTLSHandshakeOptions,
    pub handshake_for_server_name: BTreeMap<String, ShadowTLSHandshakeOptions>,
    pub users: Vec<ShadowTLSUser>,
    pub strict_mode: bool,
    pub wildcard_sni: String,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ShadowTLSUser {
    pub name: String,
    pub password: String,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ShadowTLSHandshakeOptions {
    pub dest: String,
    pub proxy: String,
}

impl ShadowTLS {
    pub fn build(&self) -> lc_shadowtls::ShadowTLS {
        let handshake_for_server_name =
            self.handshake_for_server_name.iter().map(|(k, v)| (k.clone(), v.build())).collect();
        lc_shadowtls::ShadowTLS {
            enable: self.enable,
            version: self.version,
            password: self.password.clone(),
            handshake: self.handshake.build(),
            handshake_for_server_name,
            users: self.users.iter().map(ShadowTLSUser::build).collect(),
            strict_mode: self.strict_mode,
            wildcard_sni: self.wildcard_sni.clone(),
        }
    }
}

impl ShadowTLSUser {
    #[must_use]
    pub fn build(&self) -> lc_shadowtls::ShadowTLSUser {
        lc_shadowtls::ShadowTLSUser { name: self.name.clone(), password: self.password.clone() }
    }
}

impl ShadowTLSHandshakeOptions {
    #[must_use]
    pub fn build(&self) -> lc_shadowtls::ShadowTLSHandshakeOptions {
        lc_shadowtls::ShadowTLSHandshakeOptions { dest: self.dest.clone(), proxy: self.proxy.clone() }
    }
}

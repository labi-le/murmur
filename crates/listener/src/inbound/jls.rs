use murmur_listener_config::jls as lc_jls;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct JLSConfig {
    pub enable: bool,
    pub users: Vec<JLSUser>,
    pub sni: String,
    pub dest: String,
    pub alpn: Option<Vec<String>>,
    pub proxy: String,
    pub rate_limit: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct JLSUser {
    pub username: String,
    pub password: String,
}

impl JLSConfig {
    pub fn build(&self) -> lc_jls::JLSConfig {
        lc_jls::JLSConfig {
            enable: self.enable,
            users: self.users.iter().map(JLSUser::build).collect(),
            sni: self.sni.clone(),
            dest: self.dest.clone(),
            alpn: self.alpn.clone(),
            proxy: self.proxy.clone(),
            rate_limit: self.rate_limit,
        }
    }
}

impl JLSUser {
    #[must_use]
    pub fn build(&self) -> lc_jls::JLSUser {
        lc_jls::JLSUser { username: self.username.clone(), password: self.password.clone() }
    }
}

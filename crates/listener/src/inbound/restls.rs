use murmur_listener_config::restls as lc_restls;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ResTLS {
    pub enable: bool,
    pub dest: String,
    pub password: String,
    pub restls_script: String,
    pub min_record_len: i32,
    pub rate_limit: u64,
    pub proxy: String,
}

impl ResTLS {
    #[must_use]
    pub fn build(&self) -> lc_restls::ResTLS {
        lc_restls::ResTLS {
            enable: self.enable,
            dest: self.dest.clone(),
            password: self.password.clone(),
            restls_script: self.restls_script.clone(),
            min_record_len: self.min_record_len,
            rate_limit: self.rate_limit,
            proxy: self.proxy.clone(),
        }
    }
}

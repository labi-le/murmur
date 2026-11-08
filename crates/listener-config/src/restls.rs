use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResTLS {
    #[serde(rename = "Enable")]
    pub enable: bool,
    #[serde(rename = "Dest")]
    pub dest: String,
    #[serde(rename = "Password")]
    pub password: String,
    #[serde(rename = "RestlsScript")]
    pub restls_script: String,
    #[serde(rename = "MinRecordLen")]
    pub min_record_len: i32,
    #[serde(rename = "RateLimit")]
    pub rate_limit: u64,
    #[serde(rename = "Proxy")]
    pub proxy: String,
}

impl std::fmt::Display for ResTLS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Ok(()),
        }
    }
}

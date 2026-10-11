use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct JLSConfig {
    #[serde(rename = "Enable")]
    pub enable: bool,
    #[serde(rename = "Users")]
    pub users: Vec<JLSUser>,
    #[serde(rename = "SNI")]
    pub sni: String,
    #[serde(rename = "Dest")]
    pub dest: String,
    /// The nullable ALPN list: the default ALPN is substituted only when the field is absent,
    /// so an explicitly empty `ALPN: []` must survive as `Some(vec![])` and leave the
    /// server offering no ALPN.
    #[serde(rename = "ALPN", default)]
    pub alpn: Option<Vec<String>>,
    #[serde(rename = "Proxy")]
    pub proxy: String,
    #[serde(rename = "RateLimit")]
    pub rate_limit: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct JLSUser {
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "Password")]
    pub password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ALPN field is a nullable list that is only replaced with the default when it is
    /// absent, so the parsed form has to keep "absent" and "empty" apart.
    #[test]
    fn alpn_separates_absent_from_explicitly_empty() {
        let parse = |alpn_field: &str| -> JLSConfig {
            let doc = format!(
                r#"{{"Enable":true,"Users":[{{"Username":"u","Password":"p"}}],"SNI":"example.com","Dest":"127.0.0.1:8443",{alpn_field}"Proxy":"proxy","RateLimit":0}}"#
            );
            serde_json::from_str(&doc).unwrap()
        };
        assert_eq!(parse("").alpn, None);
        assert_eq!(parse(r#""ALPN":[],"#).alpn, Some(vec![]));
        assert_eq!(parse(r#""ALPN":["h2","http/1.1"],"#).alpn, Some(vec!["h2".to_owned(), "http/1.1".to_owned()]));
    }
}

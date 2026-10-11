use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize};

use murmur_transport_jls as transport_jls;

#[derive(Clone, Debug, Default, Serialize)]
pub struct JlsOptions {
    #[serde(rename = "username")]
    pub username: String,
    #[serde(rename = "password")]
    pub password: String,
}

/// Both fields are required, so a block that is present but leaves one out fails the config, while
/// an explicit `null` leaves the field at its zero value.
#[derive(Deserialize)]
struct JlsOptionsRepr {
    #[serde(deserialize_with = "super::base::null_as_default::deserialize")]
    username: String,
    #[serde(deserialize_with = "super::base::null_as_default::deserialize")]
    password: String,
}

impl<'de> Deserialize<'de> for JlsOptions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let Some(repr) = Option::<JlsOptionsRepr>::deserialize(deserializer)? else {
            return Ok(Self::default());
        };
        Ok(Self { username: repr.username, password: repr.password })
    }
}

impl JlsOptions {
    /// Two empty credentials mean "no JLS", not an error; one empty credential is a parse error.
    pub fn parse(&self) -> Result<Option<transport_jls::Config>> {
        if self.username.is_empty() && self.password.is_empty() {
            return Ok(None);
        }
        Ok(Some(transport_jls::new_config(&self.username, &self.password)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct Holder {
        #[serde(rename = "jls-opts", default)]
        jls_opts: JlsOptions,
    }

    fn parse(yaml: &str) -> Result<Holder, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    #[test]
    fn an_absent_or_null_block_leaves_the_mode_off() {
        for yaml in ["{}\n", "jls-opts: null\n"] {
            let holder = parse(yaml).unwrap_or_else(|err| panic!("{yaml:?} must decode: {err}"));
            assert!(holder.jls_opts.parse().unwrap().is_none(), "{yaml:?}");
        }
    }

    /// the config decoder reports an incompletely filled block as
    /// `'jls-opts' has unset fields: <sorted fields>`; serde names the first missing field and
    /// appends a location, since a `Deserialize` impl never sees the key the block came from.
    #[test]
    fn a_block_that_cannot_be_filled_completely_fails_the_config() {
        for (yaml, field) in [
            ("jls-opts: {}\n", "username"),
            ("jls-opts:\n  username: user\n", "password"),
            ("jls-opts:\n  password: pass\n", "username"),
        ] {
            let err = parse(yaml).unwrap_err().to_string();
            assert!(err.contains(&format!("missing field `{field}`")), "{yaml:?}: {err}");
        }
    }

    #[test]
    fn a_key_the_option_struct_does_not_declare_is_ignored() {
        let holder = parse("jls-opts:\n  user: u\n  username: user\n  password: pass\n").expect("decodes");
        assert_eq!(holder.jls_opts.parse().unwrap().unwrap().user.username, "user");
    }

    #[test]
    fn empty_credentials_keep_the_mode_off() {
        for yaml in
            ["jls-opts:\n  username: \"\"\n  password: \"\"\n", "jls-opts:\n  username: null\n  password: null\n"]
        {
            let holder = parse(yaml).unwrap_or_else(|err| panic!("{yaml:?} must decode: {err}"));
            assert!(holder.jls_opts.parse().unwrap().is_none(), "{yaml:?}");
        }
    }

    #[test]
    fn parse_returns_the_credentials_jls_authenticates_with() {
        let holder = parse("jls-opts:\n  username: user\n  password: pass\n").expect("decodes");
        let config = holder.jls_opts.parse().expect("parses").expect("selects JLS");
        assert_eq!(config.user.username, "user");
        assert_eq!(config.user.password, "pass");
    }

    #[test]
    fn a_single_empty_credential_is_rejected() {
        let username_only = JlsOptions { username: "user".to_owned(), password: String::new() };
        assert_eq!(username_only.parse().unwrap_err().to_string(), "jls: password is required");
        let password_only = JlsOptions { username: String::new(), password: "pass".to_owned() };
        assert_eq!(password_only.parse().unwrap_err().to_string(), "jls: username is required");
    }

    #[test]
    fn the_client_config_keeps_nil_versus_empty_alpn() {
        let config = JlsOptions { username: "user".to_owned(), password: "pass".to_owned() }.parse().unwrap().unwrap();
        assert!(config.client_config("example.com", None).alpn.is_none());
        assert_eq!(config.client_config("example.com", Some(Vec::new())).alpn, Some(Vec::new()));
        assert_eq!(config.client_config("example.com", Some(vec!["h2".to_owned()])).alpn, Some(vec!["h2".to_owned()]));
    }
}

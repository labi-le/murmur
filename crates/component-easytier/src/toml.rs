use std::collections::HashMap;
use std::fmt::Write as _;

use anyhow::{anyhow, Result};
use url::Url;

use murmur_common::utils::path_unescape::path_unescape;

const DEFAULT_LISTENER: &str = "tcp://0.0.0.0:11010";

struct RequiredFlag {
    key: &'static str,
    value: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub network_name: String,
    pub network_secret: String,
    pub hostname: String,
    pub ipv4: String,
    pub dhcp: bool,
    pub peers: Vec<String>,
    pub listeners: Vec<String>,
    pub no_listener: Option<bool>,
    pub mapped_listeners: Vec<String>,
    pub exit_nodes: Vec<String>,
    pub proxy_networks: Vec<String>,
    pub instance_name: String,
    pub accept_dns: Option<bool>,
    pub enable_exit_node: Option<bool>,
    pub enable_encryption: Option<bool>,
    pub encryption_algorithm: String,
    pub private_mode: Option<bool>,
    pub latency_first: Option<bool>,
    pub disable_p2p: Option<bool>,
    pub enable_kcp_proxy: Option<bool>,
    pub disable_kcp_input: Option<bool>,
    pub enable_quic_proxy: Option<bool>,
    pub disable_quic_input: Option<bool>,
    pub mtu: i32,
    pub tld_dns_zone: String,
    pub secure_mode: Option<bool>,
    pub local_private_key: String,
    pub local_public_key: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Peer {
    pub uri: String,
    pub peer_public_key: String,
}

impl Config {
    pub(crate) fn listeners(&self) -> Vec<String> {
        if self.no_listener == Some(true) {
            return Vec::new();
        }
        if !self.listeners.is_empty() {
            return self.listeners.clone();
        }
        if self.no_listener == Some(false) {
            return vec![DEFAULT_LISTENER.to_owned()];
        }
        Vec::new()
    }

    pub fn validate_structured(&self) -> Result<()> {
        if self.network_name.trim().is_empty() {
            return Err(anyhow!("easytier: network-name is required"));
        }
        if self.no_listener == Some(true) && !self.listeners.is_empty() {
            return Err(anyhow!("easytier: no-listener cannot be combined with listeners"));
        }
        if self.peers.is_empty() && self.listeners().is_empty() {
            return Err(anyhow!(
                "easytier: peers is required when listeners are empty; implicit public.easytier.top is disabled"
            ));
        }
        self.parsed_peers()?;
        if !self.local_public_key.is_empty() && self.local_private_key.is_empty() {
            return Err(anyhow!("easytier: local-public-key requires local-private-key"));
        }
        if self.secure_mode == Some(false) && self.has_secure_mode_material() {
            return Err(anyhow!("easytier: local keys and peer-public-key require secure-mode"));
        }
        Ok(())
    }

    pub(crate) fn parsed_peers(&self) -> Result<Vec<Peer>> {
        let mut out = Vec::with_capacity(self.peers.len());
        for (i, raw) in self.peers.iter().enumerate() {
            let peer = parse_peer_uri(raw).map_err(|err| anyhow!("easytier: peers[{i}]: {err}"))?;
            out.push(peer);
        }
        Ok(out)
    }

    fn has_secure_mode_material(&self) -> bool {
        if !self.local_private_key.is_empty() || !self.local_public_key.is_empty() {
            return true;
        }
        let Ok(peers) = self.parsed_peers() else { return false };
        for peer in peers {
            if !peer.peer_public_key.is_empty() {
                return true;
            }
        }
        false
    }

    fn secure_mode_enabled(&self) -> bool {
        match self.secure_mode {
            Some(secure_mode) => secure_mode,
            None => self.has_secure_mode_material(),
        }
    }

    pub fn render_toml(&self) -> Result<String> {
        self.validate_structured()?;
        let mut encoded = String::new();
        if !self.instance_name.is_empty() {
            write_toml_string_field(&mut encoded, "instance_name", &self.instance_name);
        }
        if !self.hostname.is_empty() {
            write_toml_string_field(&mut encoded, "hostname", &self.hostname);
        }
        if !self.ipv4.trim().is_empty() {
            write_toml_string_field(&mut encoded, "ipv4", &self.ipv4);
        }
        if self.dhcp || self.ipv4.trim().is_empty() {
            write_toml_bool_field(&mut encoded, "dhcp", true);
        }
        write_toml_string_array_field(&mut encoded, "listeners", &self.listeners());
        if !self.mapped_listeners.is_empty() {
            write_toml_string_array_field(&mut encoded, "mapped_listeners", &self.mapped_listeners);
        }
        if !self.exit_nodes.is_empty() {
            write_toml_string_array_field(&mut encoded, "exit_nodes", &self.exit_nodes);
        }
        encoded.push('\n');
        encoded.push_str("[network_identity]\n");
        write_toml_string_field(&mut encoded, "network_name", &self.network_name);
        write_toml_string_field(&mut encoded, "network_secret", &self.network_secret);

        let peers = self.parsed_peers()?;

        if self.secure_mode_enabled() {
            encoded.push_str("\n[secure_mode]\n");
            write_toml_bool_field(&mut encoded, "enabled", true);
            if !self.local_private_key.is_empty() {
                write_toml_string_field(&mut encoded, "local_private_key", &self.local_private_key);
            }
            if !self.local_public_key.is_empty() {
                write_toml_string_field(&mut encoded, "local_public_key", &self.local_public_key);
            }
        }

        for peer in &peers {
            encoded.push_str("\n[[peer]]\n");
            write_toml_string_field(&mut encoded, "uri", &peer.uri);
            if !peer.peer_public_key.is_empty() {
                write_toml_string_field(&mut encoded, "peer_public_key", &peer.peer_public_key);
            }
        }
        for network in &self.proxy_networks {
            encoded.push_str("\n[[proxy_network]]\n");
            write_toml_string_field(&mut encoded, "cidr", network);
        }

        encoded.push_str("\n[flags]\n");
        write_toml_bool_field(&mut encoded, "no_tun", true);
        write_toml_bool_field(&mut encoded, "bind_device", false);
        write_optional_bool_field(&mut encoded, "accept_dns", self.accept_dns);
        write_optional_bool_field(&mut encoded, "enable_exit_node", self.enable_exit_node);
        write_optional_bool_field(&mut encoded, "enable_encryption", self.enable_encryption);
        if !self.encryption_algorithm.is_empty() {
            write_toml_string_field(&mut encoded, "encryption_algorithm", &self.encryption_algorithm);
        }
        write_optional_bool_field(&mut encoded, "private_mode", self.private_mode);
        write_optional_bool_field(&mut encoded, "latency_first", self.latency_first);
        write_optional_bool_field(&mut encoded, "disable_p2p", self.disable_p2p);
        write_optional_bool_field(&mut encoded, "enable_kcp_proxy", self.enable_kcp_proxy);
        write_optional_bool_field(&mut encoded, "disable_kcp_input", self.disable_kcp_input);
        write_optional_bool_field(&mut encoded, "enable_quic_proxy", self.enable_quic_proxy);
        write_optional_bool_field(&mut encoded, "disable_quic_input", self.disable_quic_input);
        if self.mtu > 0 {
            let _ = writeln!(encoded, "mtu = {}", self.mtu);
        }
        if !self.tld_dns_zone.is_empty() {
            write_toml_string_field(&mut encoded, "tld_dns_zone", &self.tld_dns_zone);
        }
        Ok(encoded)
    }
}

pub(crate) fn parse_peer_uri(raw: &str) -> Result<Peer> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("uri is required"));
    }
    let mut url = Url::parse(raw).map_err(|err| anyhow!("invalid uri: {err}"))?;
    if url.query().unwrap_or_default().is_empty() {
        return Ok(Peer { uri: raw.to_owned(), peer_public_key: String::new() });
    }
    let mut kept: Vec<String> = Vec::new();
    let mut key = String::new();
    let mut stripped = false;
    for pair in url.query().unwrap_or_default().split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = match pair.split_once('=') {
            Some((name, value)) => (name, value),
            None => (pair, ""),
        };
        let decoded_name = path_unescape(name).map_err(|err| anyhow!("invalid uri query: {err}"))?;
        match decoded_name.as_str() {
            "peer-public-key" | "peer_public_key" => {
                key = path_unescape(value).map_err(|err| anyhow!("invalid peer-public-key: {err}"))?;
                stripped = true;
            }
            _ => kept.push(pair.to_owned()),
        }
    }
    if !stripped {
        return Ok(Peer { uri: raw.to_owned(), peer_public_key: String::new() });
    }
    if kept.is_empty() {
        url.set_query(None);
    } else {
        url.set_query(Some(&kept.join("&")));
    }
    Ok(Peer { uri: url.to_string(), peer_public_key: key })
}

const fn required_flags() -> [RequiredFlag; 2] {
    [RequiredFlag { key: "no_tun", value: "true" }, RequiredFlag { key: "bind_device", value: "false" }]
}

#[must_use]
pub fn apply_required_flags(config_toml: &str) -> String {
    let flags = required_flags();
    let required: HashMap<&str, &str> = flags.iter().map(|flag| (flag.key, flag.value)).collect();
    let mut out: Vec<String> = Vec::new();
    let mut section = String::new();
    let mut seen: HashMap<String, bool> = HashMap::new();
    let mut wrote_flags = false;
    for line in config_toml.split('\n') {
        let trimmed = line.trim();
        if is_toml_section(trimmed) {
            flush_flags(&flags, &section, &mut out, &mut seen, &mut wrote_flags);
            section = section_name(trimmed);
            out.push(line.to_owned());
            continue;
        }
        if section == "flags" {
            let key = flag_key(trimmed);
            if let Some(value) = required.get(key.as_str()) {
                out.push(format!("{key} = {value}"));
                seen.insert(key, true);
                continue;
            }
        }
        out.push(line.to_owned());
    }
    flush_flags(&flags, &section, &mut out, &mut seen, &mut wrote_flags);
    if !wrote_flags {
        if let Some(last) = out.last() {
            if !last.trim().is_empty() {
                out.push(String::new());
            }
        }
        out.push("[flags]".to_owned());
        for flag in &flags {
            out.push(format!("{} = {}", flag.key, flag.value));
        }
    }
    format!("{}\n", out.join("\n").trim())
}

fn flush_flags(
    flags: &[RequiredFlag],
    section: &str,
    out: &mut Vec<String>,
    seen: &mut HashMap<String, bool>,
    wrote_flags: &mut bool,
) {
    if section != "flags" {
        return;
    }
    for flag in flags {
        if !seen.contains_key(flag.key) {
            out.push(format!("{} = {}", flag.key, flag.value));
        }
    }
    *wrote_flags = true;
    seen.clear();
}

fn is_toml_section(trimmed: &str) -> bool {
    let Some(rest) = trimmed.strip_prefix('[') else { return false };
    let Some((_, rest)) = rest.split_once(']') else { return false };
    let rest = rest.trim();
    rest.is_empty() || rest.starts_with('#')
}

fn section_name(trimmed: &str) -> String {
    let Some((name, _)) = trimmed.split_once(']') else { return String::new() };
    let name = name.trim();
    let name = name.strip_prefix("[[").unwrap_or(name);
    let name = name.strip_prefix('[').unwrap_or(name);
    let name = name.strip_suffix("]]").unwrap_or(name);
    let name = name.strip_suffix(']').unwrap_or(name);
    name.trim_matches(|c| c == '"' || c == '\'').to_owned()
}

fn flag_key(trimmed: &str) -> String {
    match trimmed.split_once('=') {
        Some((name, _)) => name.trim().trim_matches(|c| c == '"' || c == '\'').to_owned(),
        None => String::new(),
    }
}

fn write_optional_bool_field(encoded: &mut String, name: &str, value: Option<bool>) {
    if let Some(value) = value {
        write_toml_bool_field(encoded, name, value);
    }
}

fn write_toml_string_field(encoded: &mut String, name: &str, value: &str) {
    let _ = writeln!(encoded, "{name} = {}", quote_toml_string(value));
}

fn write_toml_bool_field(encoded: &mut String, name: &str, value: bool) {
    let _ = writeln!(encoded, "{name} = {value}");
}

fn write_toml_string_array_field(encoded: &mut String, name: &str, values: &[String]) {
    let _ = write!(encoded, "{name} = [");
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            encoded.push_str(", ");
        }
        encoded.push_str(&quote_toml_string(value));
    }
    encoded.push_str("]\n");
}

/// JSON-style string quoting, whose HTML escaping the TOML output keeps.
fn quote_toml_string(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for c in value.chars() {
        match c {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            '<' => encoded.push_str("\\u003c"),
            '>' => encoded.push_str("\\u003e"),
            '&' => encoded.push_str("\\u0026"),
            '\u{2028}' => encoded.push_str("\\u2028"),
            '\u{2029}' => encoded.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                let _ = write!(encoded, "\\u{:04x}", c as u32);
            }
            c => encoded.push(c),
        }
    }
    encoded.push('"');
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bool_ptr(value: bool) -> Option<bool> {
        Some(value)
    }

    #[test]
    fn render_toml_default_no_listener_requires_peers() {
        let config = Config { network_name: "example".to_owned(), ..Config::default() };
        assert!(config.render_toml().is_err());
    }

    #[test]
    fn render_toml_no_listener_false_default_listener() {
        let config = Config { network_name: "example".to_owned(), no_listener: bool_ptr(false), ..Config::default() };
        let toml = config.render_toml().expect("render");
        assert!(toml.contains(r#"listeners = ["tcp://0.0.0.0:11010"]"#), "{toml}");
        assert!(toml.contains("no_tun = true"), "{toml}");
        assert!(toml.contains("bind_device = false"), "{toml}");
    }

    #[test]
    fn render_toml_explicit_empty_listeners_with_peers() {
        let config = Config {
            network_name: "example".to_owned(),
            network_secret: "secret".to_owned(),
            peers: vec!["tcp://192.0.2.10:11010".to_owned()],
            hostname: "node-a".to_owned(),
            ipv4: "10.144.0.1/24".to_owned(),
            ..Config::default()
        };
        let toml = config.render_toml().expect("render");
        assert!(toml.contains("listeners = []"), "{toml}");
        assert!(toml.contains("[[peer]]"), "{toml}");
        assert!(toml.contains(r#"uri = "tcp://192.0.2.10:11010""#), "{toml}");
    }

    #[test]
    fn apply_required_flags_injects_no_tun() {
        let got = apply_required_flags("[network_identity]\nnetwork_name = \"n\"\n");
        assert!(got.contains("[flags]"), "{got}");
        assert!(got.contains("no_tun = true"), "{got}");
        assert!(got.contains("bind_device = false"), "{got}");
    }

    #[test]
    fn apply_required_flags_replaces_no_tun() {
        let got = apply_required_flags("[flags]\nno_tun = false\nmtu = 1200\n");
        assert!(got.contains("no_tun = true"), "{got}");
        assert!(got.contains("bind_device = false"), "{got}");
        assert!(got.contains("mtu = 1200"), "{got}");
    }

    #[test]
    fn no_listener_conflict() {
        let config = Config {
            network_name: "example".to_owned(),
            no_listener: bool_ptr(true),
            listeners: vec!["tcp://0.0.0.0:11010".to_owned()],
            ..Config::default()
        };
        assert!(config.validate_structured().is_err());
    }

    #[test]
    fn render_toml_manual_ipv4_without_prefix() {
        let config = Config {
            network_name: "example".to_owned(),
            network_secret: "example".to_owned(),
            ipv4: "10.144.0.10".to_owned(),
            peers: vec!["tcp://192.0.2.10:11010".to_owned()],
            ..Config::default()
        };
        let toml = config.render_toml().expect("render");
        assert!(toml.contains(r#"ipv4 = "10.144.0.10""#), "{toml}");
        assert!(toml.contains(r#"uri = "tcp://192.0.2.10:11010""#), "{toml}");
    }

    #[test]
    fn render_toml_multiple_peers() {
        let config = Config {
            network_name: "example".to_owned(),
            network_secret: "secret".to_owned(),
            peers: vec!["tcp://192.0.2.10:11010".to_owned(), "udp://192.0.2.11:11010".to_owned()],
            ..Config::default()
        };
        let toml = config.render_toml().expect("render");
        assert_eq!(2, toml.matches("[[peer]]").count(), "{toml}");
        assert!(toml.contains(r#"uri = "tcp://192.0.2.10:11010""#), "{toml}");
        assert!(toml.contains(r#"uri = "udp://192.0.2.11:11010""#), "{toml}");
    }

    #[test]
    fn apply_required_flags_section_comment() {
        let got = apply_required_flags("[flags] # tun flags\nno_tun = false\nmtu = 1200\n");
        assert_eq!(1, got.matches("[flags]").count(), "{got}");
        assert!(got.contains("no_tun = true"), "{got}");
        assert!(got.contains("mtu = 1200"), "{got}");
    }

    #[test]
    fn apply_required_flags_quoted_key() {
        let got = apply_required_flags("[flags]\n\"no_tun\" = false\n");
        assert_eq!(1, got.matches("no_tun").count(), "{got}");
        assert!(got.contains("no_tun = true"), "{got}");
    }

    #[test]
    fn render_toml_defaults_dhcp_when_ipv4_omitted() {
        let config = Config {
            network_name: "example".to_owned(),
            network_secret: "secret".to_owned(),
            peers: vec!["tcp://192.0.2.10:11010".to_owned()],
            ..Config::default()
        };
        let toml = config.render_toml().expect("render");
        assert!(toml.contains("dhcp = true"), "{toml}");
        assert!(!toml.contains("ipv4"), "{toml}");
    }

    #[test]
    fn render_toml_static_ipv4_omits_dhcp() {
        let config = Config {
            network_name: "example".to_owned(),
            network_secret: "secret".to_owned(),
            ipv4: "10.144.0.10".to_owned(),
            peers: vec!["tcp://192.0.2.10:11010".to_owned()],
            ..Config::default()
        };
        let toml = config.render_toml().expect("render");
        assert!(!toml.contains("dhcp = true"), "{toml}");
    }

    #[test]
    fn render_toml_writes_tld_dns_zone() {
        let config = Config {
            network_name: "example".to_owned(),
            network_secret: "secret".to_owned(),
            peers: vec!["tcp://192.0.2.10:11010".to_owned()],
            tld_dns_zone: "overlay.example.".to_owned(),
            ..Config::default()
        };
        let toml = config.render_toml().expect("render");
        assert!(toml.contains(r#"tld_dns_zone = "overlay.example.""#), "{toml}");
    }

    #[test]
    fn render_toml_secure_mode() {
        let config = Config {
            network_name: "example".to_owned(),
            network_secret: "secret".to_owned(),
            peers: vec!["tcp://192.0.2.10:11010".to_owned()],
            secure_mode: bool_ptr(true),
            local_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            local_public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_owned(),
            ..Config::default()
        };
        let toml = config.render_toml().expect("render");
        assert!(toml.contains("[secure_mode]"), "{toml}");
        assert!(toml.contains("enabled = true"), "{toml}");
        assert!(toml.contains(r#"local_private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=""#), "{toml}");
        assert!(toml.contains(r#"local_public_key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=""#), "{toml}");
    }

    #[test]
    fn render_toml_peer_public_key_enables_secure_mode() {
        let config = Config {
            network_name: "example".to_owned(),
            network_secret: "secret".to_owned(),
            peers: vec![
                "tcp://relay.example.com:11010?peer-public-key=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".to_owned()
            ],
            ..Config::default()
        };
        let toml = config.render_toml().expect("render");
        assert!(toml.contains("[secure_mode]"), "{toml}");
        assert!(toml.contains("enabled = true"), "{toml}");
        assert!(toml.contains(r#"uri = "tcp://relay.example.com:11010""#), "{toml}");
        assert!(!toml.contains("peer-public-key="), "{toml}");
        assert!(toml.contains(r#"peer_public_key = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=""#), "{toml}");
    }

    #[test]
    fn render_toml_secure_mode_false_rejects_pinned_peer() {
        let config = Config {
            network_name: "example".to_owned(),
            network_secret: "secret".to_owned(),
            secure_mode: bool_ptr(false),
            peers: vec![
                "tcp://relay.example.com:11010?peer-public-key=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".to_owned()
            ],
            ..Config::default()
        };
        assert!(config.validate_structured().is_err());
    }

    #[test]
    fn render_toml_local_public_key_requires_private_key() {
        let config = Config {
            network_name: "example".to_owned(),
            network_secret: "secret".to_owned(),
            peers: vec!["tcp://192.0.2.10:11010".to_owned()],
            local_public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_owned(),
            ..Config::default()
        };
        assert!(config.validate_structured().is_err());
    }

    #[test]
    fn render_toml_empty_peer_uri() {
        let config = Config {
            network_name: "example".to_owned(),
            network_secret: "secret".to_owned(),
            peers: vec![String::new()],
            ..Config::default()
        };
        assert!(config.validate_structured().is_err());
    }

    #[test]
    fn parse_peer_uri_query() {
        let peer =
            parse_peer_uri(" tcp://relay.example.com:11010?foo=1&peer-public-key=CC%2BCC/CC=&bar=2 ").expect("peer");
        assert_eq!("tcp://relay.example.com:11010?foo=1&bar=2", peer.uri);
        assert_eq!("CC+CC/CC=", peer.peer_public_key);

        let peer = parse_peer_uri(
            "tcp://relay.example.com:11010?peer_public_key=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
        )
        .expect("peer");
        assert_eq!("tcp://relay.example.com:11010", peer.uri);
        assert!(!peer.peer_public_key.is_empty());

        let peer = parse_peer_uri("tcp://192.0.2.10:11010?foo=1").expect("peer");
        assert_eq!("tcp://192.0.2.10:11010?foo=1", peer.uri);
        assert!(peer.peer_public_key.is_empty());
    }
}

//! Pure host-side data modeling: builds and validates an [`InstanceConfig`].
//!
//! The document is rendered to the TOML the embedded core's `easytier_core.wasm` guest expects on
//! Core initialization. No wasm/ABI interaction lives here.

use std::collections::HashSet;
use std::fmt;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ipnet::Ipv4Net;
use rand::Rng;
use x25519_dalek::{PublicKey, StaticSecret};

/// The P2P advertisement flags.
///
/// `disable` normally suppresses P2P, but a peer advertising `need` may still request it. `need`
/// advertises that this instance requires P2P and may override a peer's `disable` setting. `lazy`
/// defers background P2P until traffic needs it, except for peers advertising `need`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct P2PPolicy {
    pub disable: bool,
    pub need: bool,
    pub lazy: bool,
}

///
/// Selects the hole-punching methods available to an instance. `symmetric_udp` requires `udp`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HolePunchingPolicy {
    pub tcp: bool,
    pub udp: bool,
    pub symmetric_udp: bool,
}

/// The protocol a forwarded port carries: TCP or UDP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PortForwardProtocol {
    Tcp,
    Udp,
}

impl fmt::Display for PortForwardProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

/// Uses [`SocketAddr`] for the bound address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortForwardConfig {
    pub protocol: PortForwardProtocol,
    pub bind: SocketAddr,
    pub destination: SocketAddr,
}

/// The validated instance configuration. Its only constructor is [`InstanceConfigBuilder::build`].
pub struct InstanceConfig {
    document: InstanceConfigDocument,
}

impl fmt::Debug for InstanceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceConfig{<redacted>}")
    }
}

pub struct InstanceConfigBuilder {
    document: InstanceConfigDocument,
    network_secret_set: bool,
}

impl fmt::Debug for InstanceConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceConfigBuilder{<redacted>}")
    }
}

struct InstanceConfigDocument {
    network_name: String,
    network_secret: String,
    hostname: Option<String>,
    ipv4: Option<Ipv4Net>,
    peers: Vec<String>,
    listeners: Vec<String>,
    port_forwards: Vec<PortForwardConfig>,
    stun_servers: Option<Vec<String>>,
    stun_servers_v6: Option<Vec<String>>,
    p2p: Option<P2PPolicy>,
    hole_punching: Option<HolePunchingPolicy>,
    encryption: Option<bool>,
    secure_mode: SecureMode,
    secure_private_key: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecureMode {
    Disabled,
    Automatic,
    Manual,
}

/// The invalid-instance-config errors, split into one variant per validation rule.
///
/// Rules the type system already makes unreachable (UTF-8 validity of the
/// input text, `PortForwardProtocol` values outside `Tcp`/`Udp`, `Ipv4Net` prefixes
/// outside 0-32) have no corresponding variant.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid EasyTier instance config network.name: must not be empty")]
    NetworkNameEmpty,
    #[error("invalid EasyTier instance config network.secret: must be explicitly set")]
    NetworkSecretNotSet,
    #[error("invalid EasyTier instance config hostname: must not be empty")]
    HostnameEmpty,
    #[error("invalid EasyTier instance config hostname: must not exceed 32 characters")]
    HostnameTooLong,
    #[error("invalid EasyTier instance config hostname: must not contain control characters")]
    HostnameControlCharacter,
    #[error("invalid EasyTier instance config ipv4: must include a network prefix shorter than /32")]
    Ipv4PrefixTooNarrow,
    #[error("invalid EasyTier instance config {field}[{index}]: {reason}")]
    InvalidEndpoint { field: &'static str, index: usize, reason: &'static str },
    #[error("invalid EasyTier instance config {field}[{index}]: duplicates another endpoint")]
    DuplicateEndpoint { field: &'static str, index: usize },
    #[error("invalid EasyTier instance config port_forwards[{index}].bind: must be a valid IPv4 socket address")]
    PortForwardInvalidBind { index: usize },
    #[error(
        "invalid EasyTier instance config port_forwards[{index}].destination: must be a valid IPv4 socket address"
    )]
    PortForwardInvalidDestination { index: usize },
    #[error("invalid EasyTier instance config port_forwards[{index}].destination: port must not be zero")]
    PortForwardZeroDestinationPort { index: usize },
    #[error("invalid EasyTier instance config port_forwards[{index}]: duplicates another port forward")]
    DuplicatePortForward { index: usize },
    #[error("invalid EasyTier instance config {field}[{index}]: {reason}")]
    InvalidStunServer { field: &'static str, index: usize, reason: &'static str },
    #[error("invalid EasyTier instance config {field}[{index}]: duplicates another STUN server")]
    DuplicateStunServer { field: &'static str, index: usize },
    #[error("invalid EasyTier instance config hole_punching.symmetric_udp: requires UDP hole punching")]
    SymmetricUdpRequiresUdp,
    #[error("invalid EasyTier instance config secure_mode: requires a non-empty network secret")]
    SecureModeRequiresNetworkSecret,
    #[error("invalid EasyTier instance config secure_mode.private_key: must contain exactly 32 bytes")]
    SecurePrivateKeyWrongLength,
}

impl InstanceConfigBuilder {
    pub fn new(network_name: impl Into<String>) -> Self {
        Self {
            document: InstanceConfigDocument {
                network_name: network_name.into(),
                network_secret: String::new(),
                hostname: None,
                ipv4: None,
                peers: Vec::new(),
                listeners: Vec::new(),
                port_forwards: Vec::new(),
                stun_servers: None,
                stun_servers_v6: None,
                p2p: None,
                hole_punching: None,
                encryption: None,
                secure_mode: SecureMode::Disabled,
                secure_private_key: Vec::new(),
            },
            network_secret_set: false,
        }
    }

    /// Sets the network secret. An empty secret is valid unless secure mode
    /// is enabled.
    #[must_use]
    pub fn network_secret(mut self, secret: impl Into<String>) -> Self {
        self.document.network_secret = secret.into();
        self.network_secret_set = true;
        self
    }

    #[must_use]
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.document.hostname = Some(hostname.into());
        self
    }

    #[must_use]
    pub fn ipv4(mut self, prefix: Ipv4Net) -> Self {
        self.document.ipv4 = Some(prefix);
        self
    }

    #[must_use]
    pub fn add_peers<I, S>(mut self, uris: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.document.peers.extend(uris.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn add_listeners<I, S>(mut self, uris: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.document.listeners.extend(uris.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn add_port_forwards<I>(mut self, forwards: I) -> Self
    where
        I: IntoIterator<Item = PortForwardConfig>,
    {
        self.document.port_forwards.extend(forwards);
        self
    }

    /// Sets the STUN server list. Calling with an empty iterator explicitly
    /// disables the list; never calling this method uses the embedded core's defaults.
    #[must_use]
    pub fn stun_servers<I, S>(mut self, servers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.document.stun_servers = Some(servers.into_iter().map(Into::into).collect());
        self
    }

    /// Sets the IPv6 STUN server list. Calling with an empty iterator explicitly
    /// disables the list; never calling this method uses the embedded core's defaults.
    #[must_use]
    pub fn stun_servers_v6<I, S>(mut self, servers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.document.stun_servers_v6 = Some(servers.into_iter().map(Into::into).collect());
        self
    }

    #[must_use]
    pub fn p2p(mut self, policy: P2PPolicy) -> Self {
        self.document.p2p = Some(policy);
        self
    }

    #[must_use]
    pub fn hole_punching(mut self, policy: HolePunchingPolicy) -> Self {
        self.document.hole_punching = Some(policy);
        self
    }

    #[must_use]
    pub fn encryption(mut self, enabled: bool) -> Self {
        self.document.encryption = Some(enabled);
        self
    }

    /// enables secure mode with an automatically
    /// generated X25519 key.
    #[must_use]
    pub fn secure_mode(mut self) -> Self {
        self.document.secure_mode = SecureMode::Automatic;
        self.document.secure_private_key.clear();
        self
    }

    /// enables secure mode with a
    /// caller-provided raw X25519 private key. The key is copied immediately; its length is
    /// validated by [`Self::build`].
    #[must_use]
    pub fn secure_mode_with_private_key(mut self, private_key: &[u8]) -> Self {
        self.document.secure_mode = SecureMode::Manual;
        self.document.secure_private_key = private_key.to_vec();
        self
    }

    /// Consumes the builder, so there is no aliasing risk between the built [`InstanceConfig`]
    /// and the original document and no defensive clone is needed.
    pub fn build(mut self) -> Result<InstanceConfig, ConfigError> {
        if self.document.network_name.is_empty() {
            return Err(ConfigError::NetworkNameEmpty);
        }
        if !self.network_secret_set {
            return Err(ConfigError::NetworkSecretNotSet);
        }

        validate_hostname(self.document.hostname.as_deref())?;
        validate_ipv4(self.document.ipv4)?;
        normalize_endpoints(&mut self.document.peers, false, "peers")?;
        normalize_endpoints(&mut self.document.listeners, true, "listeners")?;
        validate_port_forwards(&self.document.port_forwards)?;
        if let Some(servers) = &self.document.stun_servers {
            validate_stun_servers(servers, false, "stun_servers")?;
        }
        if let Some(servers) = &self.document.stun_servers_v6 {
            validate_stun_servers(servers, true, "stun_servers_v6")?;
        }
        if let Some(policy) = &self.document.hole_punching {
            if policy.symmetric_udp && !policy.udp {
                return Err(ConfigError::SymmetricUdpRequiresUdp);
            }
        }
        if self.document.secure_mode != SecureMode::Disabled {
            if self.document.network_secret.is_empty() {
                return Err(ConfigError::SecureModeRequiresNetworkSecret);
            }
            self.document.secure_private_key = self.secure_mode_private_key()?;
        }

        Ok(InstanceConfig { document: self.document })
    }

    fn secure_mode_private_key(&mut self) -> Result<Vec<u8>, ConfigError> {
        match self.document.secure_mode {
            SecureMode::Automatic => {
                if self.document.secure_private_key.is_empty() {
                    let mut bytes = [0u8; 32];
                    rand::rng().fill(&mut bytes);
                    self.document.secure_private_key = bytes.to_vec();
                }
            }
            SecureMode::Manual => {
                if self.document.secure_private_key.len() != 32 {
                    return Err(ConfigError::SecurePrivateKeyWrongLength);
                }
            }
            SecureMode::Disabled => {}
        }
        Ok(self.document.secure_private_key.clone())
    }
}

fn validate_hostname(hostname: Option<&str>) -> Result<(), ConfigError> {
    let Some(hostname) = hostname else { return Ok(()) };
    if hostname.is_empty() {
        return Err(ConfigError::HostnameEmpty);
    }
    if hostname.chars().count() > 32 {
        return Err(ConfigError::HostnameTooLong);
    }
    if hostname.chars().any(char::is_control) {
        return Err(ConfigError::HostnameControlCharacter);
    }
    Ok(())
}

/// `Ipv4Net`'s constructors already reject invalid addresses and out-of-range prefix lengths, so
/// only the narrower `/32` rule remains to check.
fn validate_ipv4(prefix: Option<Ipv4Net>) -> Result<(), ConfigError> {
    let Some(prefix) = prefix else { return Ok(()) };
    if prefix.prefix_len() == 32 {
        return Err(ConfigError::Ipv4PrefixTooNarrow);
    }
    Ok(())
}

/// `PortForwardConfig::protocol` is a two-variant enum, so the "protocol must be TCP or UDP"
/// check is unreachable in Rust and has no corresponding branch here.
fn validate_port_forwards(forwards: &[PortForwardConfig]) -> Result<(), ConfigError> {
    let mut seen = HashSet::with_capacity(forwards.len());
    for (index, forward) in forwards.iter().enumerate() {
        if !forward.bind.is_ipv4() {
            return Err(ConfigError::PortForwardInvalidBind { index });
        }
        if !forward.destination.is_ipv4() {
            return Err(ConfigError::PortForwardInvalidDestination { index });
        }
        if forward.destination.port() == 0 {
            return Err(ConfigError::PortForwardZeroDestinationPort { index });
        }
        if !seen.insert(*forward) {
            return Err(ConfigError::DuplicatePortForward { index });
        }
    }
    Ok(())
}

fn normalize_endpoints(values: &mut [String], listener: bool, field: &'static str) -> Result<(), ConfigError> {
    let mut seen = HashSet::with_capacity(values.len());
    for (index, value) in values.iter_mut().enumerate() {
        let normalized = normalize_endpoint(value, listener).map_err(|reason| ConfigError::InvalidEndpoint {
            field,
            index,
            reason,
        })?;
        if !seen.insert(normalized.clone()) {
            return Err(ConfigError::DuplicateEndpoint { field, index });
        }
        *value = normalized;
    }
    Ok(())
}

/// Normalizes an endpoint. Accepts the grammar (`tcp://` or `udp://` authority form, no
/// userinfo/path/query/fragment) directly rather than through `url::Url`, whose WHATWG host
/// normalization (notably domain lowercasing) is not RFC 3986-conformant.
fn normalize_endpoint(value: &str, listener: bool) -> Result<String, &'static str> {
    if value.is_empty() || value.trim() != value {
        return Err("must be a non-empty URI without surrounding whitespace");
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return Err("must be an absolute TCP or UDP URI");
    };
    if scheme.is_empty() {
        return Err("must be an absolute TCP or UDP URI");
    }
    let scheme_lower = scheme.to_ascii_lowercase();
    if scheme_lower != "tcp" && scheme_lower != "udp" {
        return Err("must use the TCP or UDP scheme");
    }

    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..authority_end).ok_or("must not contain credentials, a path, query, or fragment")?;
    if authority_end != rest.len() {
        return Err("must not contain credentials, a path, query, or fragment");
    }
    if authority.contains('@') {
        return Err("must not contain credentials, a path, query, or fragment");
    }
    if authority.is_empty() {
        return Err("must be an absolute TCP or UDP URI");
    }

    let (host, port) = split_host_port(authority).map_err(|()| "must include a host")?;
    if host.is_empty() {
        return Err("must include a host");
    }
    if let Some(port) = port {
        validate_port_digits(port, listener)?;
    }
    if listener && host.parse::<IpAddr>().is_err() {
        return Err("listener host must be an IP address");
    }

    Ok(format!("{scheme_lower}://{authority}"))
}

fn validate_port_digits(port: &str, listener: bool) -> Result<(), &'static str> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("has an invalid port");
    }
    let value: u32 = port.parse().map_err(|_| "has an invalid port")?;
    if value > 65535 || (!listener && value == 0) {
        return Err("has an invalid port");
    }
    Ok(())
}

/// Splits a URI authority (`host`, `host:port`, `[v6]`, or `[v6]:port`) into host and optional
/// port. The port half of the pair is `Some("")` for a bare trailing colon (an invalid port,
/// matching the trailing-colon check).
fn split_host_port(authority: &str) -> Result<(&str, Option<&str>), ()> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']').ok_or(())?;
        let host = rest.get(..close).ok_or(())?;
        let after = rest.get(close + 1..).ok_or(())?;
        if after.is_empty() {
            return Ok((host, None));
        }
        let port = after.strip_prefix(':').ok_or(())?;
        return Ok((host, Some(port)));
    }
    match authority.rfind(':') {
        Some(index) => Ok((authority.get(..index).ok_or(())?, Some(authority.get(index + 1..).ok_or(())?))),
        None => Ok((authority, None)),
    }
}

fn validate_stun_servers(values: &[String], ipv6: bool, field: &'static str) -> Result<(), ConfigError> {
    let mut seen = HashSet::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        validate_stun_server(value, ipv6).map_err(|reason| ConfigError::InvalidStunServer { field, index, reason })?;
        if !seen.insert(value.as_str()) {
            return Err(ConfigError::DuplicateStunServer { field, index });
        }
    }
    Ok(())
}

fn validate_stun_server(value: &str, ipv6: bool) -> Result<(), &'static str> {
    if value.is_empty() || value.trim() != value {
        return Err("must be non-empty without surrounding whitespace");
    }
    if let Some(domain) = value.strip_prefix("txt:") {
        if !valid_stun_hostname(domain) {
            return Err("has an invalid TXT lookup name");
        }
        return Ok(());
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        return validate_stun_address_family(address, ipv6);
    }
    if let Ok(address) = value.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err("port must not be zero");
        }
        return validate_stun_address_family(address.ip(), ipv6);
    }
    if value.contains('@') {
        return Err("must be a host, IP address, socket address, or txt: name");
    }

    let (host, port) =
        split_host_port(value).map_err(|()| "must be a host, IP address, socket address, or txt: name")?;
    if !valid_stun_hostname(host) {
        return Err("has an invalid host");
    }
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("has an invalid port");
        }
        let port_value: u32 = port.parse().map_err(|_| "has an invalid port")?;
        if port_value == 0 || port_value > 65535 {
            return Err("has an invalid port");
        }
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return validate_stun_address_family(address, ipv6);
    }
    Ok(())
}

fn valid_stun_hostname(value: &str) -> bool {
    if value.is_empty() || value.contains([' ', '\t', '\r', '\n', '/', '?', '#', '@', '[', ']', ':']) {
        return false;
    }
    !value.chars().any(char::is_control)
}

fn validate_stun_address_family(address: IpAddr, ipv6: bool) -> Result<(), &'static str> {
    match (address, ipv6) {
        (IpAddr::V6(v6), true) if v6.to_ipv4_mapped().is_none() => Ok(()),
        (_, true) => Err("literal address must be IPv6"),
        (IpAddr::V4(_), false) => Ok(()),
        (_, false) => Err("literal address must be IPv4"),
    }
}

pub fn render_toml(config: &InstanceConfig) -> Result<String, ConfigError> {
    let document = &config.document;
    let mut encoded = String::new();

    if let Some(hostname) = &document.hostname {
        write_toml_string_field(&mut encoded, "hostname", hostname);
    }
    if let Some(ipv4) = &document.ipv4 {
        write_toml_string_field(&mut encoded, "ipv4", &ipv4.to_string());
    }
    if !document.listeners.is_empty() {
        write_toml_string_array_field(&mut encoded, "listeners", &document.listeners);
    }
    if let Some(servers) = &document.stun_servers {
        write_toml_string_array_field(&mut encoded, "stun_servers", servers);
    }
    if let Some(servers) = &document.stun_servers_v6 {
        write_toml_string_array_field(&mut encoded, "stun_servers_v6", servers);
    }
    if !encoded.is_empty() {
        encoded.push('\n');
    }

    encoded.push_str("[network_identity]\n");
    write_toml_string_field(&mut encoded, "network_name", &document.network_name);
    write_toml_string_field(&mut encoded, "network_secret", &document.network_secret);

    for peer in &document.peers {
        encoded.push_str("\n[[peer]]\n");
        write_toml_string_field(&mut encoded, "uri", peer);
    }

    for forward in &document.port_forwards {
        encoded.push_str("\n[[port_forward]]\n");
        write_toml_string_field(&mut encoded, "bind_addr", &forward.bind.to_string());
        write_toml_string_field(&mut encoded, "dst_addr", &forward.destination.to_string());
        write_toml_string_field(&mut encoded, "proto", &forward.protocol.to_string());
    }

    if document.encryption.is_some() || document.p2p.is_some() || document.hole_punching.is_some() {
        encoded.push_str("\n[flags]\n");
        if let Some(encryption) = document.encryption {
            write_toml_bool_field(&mut encoded, "enable_encryption", encryption);
        }
        if let Some(policy) = &document.p2p {
            write_toml_bool_field(&mut encoded, "disable_p2p", policy.disable);
            write_toml_bool_field(&mut encoded, "need_p2p", policy.need);
            write_toml_bool_field(&mut encoded, "lazy_p2p", policy.lazy);
        }
        if let Some(policy) = &document.hole_punching {
            write_toml_bool_field(&mut encoded, "disable_tcp_hole_punching", !policy.tcp);
            write_toml_bool_field(&mut encoded, "disable_udp_hole_punching", !policy.udp);
            write_toml_bool_field(&mut encoded, "disable_sym_hole_punching", !policy.symmetric_udp);
        }
    }

    if document.secure_mode != SecureMode::Disabled {
        let key_bytes: [u8; 32] =
            document.secure_private_key.as_slice().try_into().map_err(|_| ConfigError::SecurePrivateKeyWrongLength)?;
        let public_key = PublicKey::from(&StaticSecret::from(key_bytes));
        encoded.push_str("\n[secure_mode]\n");
        write_toml_bool_field(&mut encoded, "enabled", true);
        write_toml_string_field(&mut encoded, "local_private_key", &STANDARD.encode(&document.secure_private_key));
        write_toml_string_field(&mut encoded, "local_public_key", &STANDARD.encode(public_key.to_bytes()));
    }

    Ok(encoded)
}

fn write_toml_string_field(encoded: &mut String, name: &str, value: &str) {
    encoded.push_str(name);
    encoded.push_str(" = ");
    encoded.push_str(&quote_toml_string(value));
    encoded.push('\n');
}

fn write_toml_bool_field(encoded: &mut String, name: &str, value: bool) {
    encoded.push_str(name);
    encoded.push_str(" = ");
    encoded.push_str(if value { "true" } else { "false" });
    encoded.push('\n');
}

fn write_toml_string_array_field(encoded: &mut String, name: &str, values: &[String]) {
    encoded.push_str(name);
    encoded.push_str(" = [");
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            encoded.push_str(", ");
        }
        encoded.push_str(&quote_toml_string(value));
    }
    encoded.push_str("]\n");
}

/// JSON-quotes `value` with default HTML-safe escaping of `<`, `>`, `&`, U+2028 and U+2029.
/// `serde_json` does not replicate that escaping, so this is hand-rolled to keep [`render_toml`]
/// byte-identical.
fn quote_toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            control if (control as u32) < 0x20 || control as u32 == 0x7f => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn minimal_config_renders_expected_toml() {
        let config = InstanceConfigBuilder::new("net1").network_secret("secret1").build().expect("build");

        let rendered = render_toml(&config).expect("render");

        assert_eq!(rendered, "[network_identity]\nnetwork_name = \"net1\"\nnetwork_secret = \"secret1\"\n");
    }

    #[test]
    fn full_config_renders_expected_toml() {
        let config = InstanceConfigBuilder::new("net1")
            .network_secret("secret1")
            .hostname("host-a")
            .ipv4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 5), 24).expect("prefix"))
            .add_listeners(["tcp://0.0.0.0:11010"])
            .stun_servers::<[&str; 0], &str>([])
            .add_peers(["tcp://1.2.3.4:11010"])
            .add_port_forwards([PortForwardConfig {
                protocol: PortForwardProtocol::Tcp,
                bind: "127.0.0.1:8080".parse().expect("bind"),
                destination: "10.0.0.2:9090".parse().expect("destination"),
            }])
            .p2p(P2PPolicy { disable: false, need: true, lazy: false })
            .hole_punching(HolePunchingPolicy { tcp: true, udp: true, symmetric_udp: false })
            .encryption(true)
            .build()
            .expect("build");

        let rendered = render_toml(&config).expect("render");

        assert_eq!(
            rendered,
            concat!(
                "hostname = \"host-a\"\n",
                "ipv4 = \"10.0.0.5/24\"\n",
                "listeners = [\"tcp://0.0.0.0:11010\"]\n",
                "stun_servers = []\n",
                "\n",
                "[network_identity]\n",
                "network_name = \"net1\"\n",
                "network_secret = \"secret1\"\n",
                "\n",
                "[[peer]]\n",
                "uri = \"tcp://1.2.3.4:11010\"\n",
                "\n",
                "[[port_forward]]\n",
                "bind_addr = \"127.0.0.1:8080\"\n",
                "dst_addr = \"10.0.0.2:9090\"\n",
                "proto = \"tcp\"\n",
                "\n",
                "[flags]\n",
                "enable_encryption = true\n",
                "disable_p2p = false\n",
                "need_p2p = true\n",
                "lazy_p2p = false\n",
                "disable_tcp_hole_punching = false\n",
                "disable_udp_hole_punching = false\n",
                "disable_sym_hole_punching = true\n",
            )
        );
    }

    #[test]
    fn secure_mode_renders_expected_toml() {
        let raw_private_key = [0x11u8; 32];
        let expected_public_key = x25519_dalek::x25519(raw_private_key, x25519_dalek::X25519_BASEPOINT_BYTES);

        let config = InstanceConfigBuilder::new("net1")
            .network_secret("secret1")
            .secure_mode_with_private_key(&raw_private_key)
            .build()
            .expect("build");

        let rendered = render_toml(&config).expect("render");

        let expected = format!(
            concat!(
                "[network_identity]\n",
                "network_name = \"net1\"\n",
                "network_secret = \"secret1\"\n",
                "\n",
                "[secure_mode]\n",
                "enabled = true\n",
                "local_private_key = \"{}\"\n",
                "local_public_key = \"{}\"\n",
            ),
            STANDARD.encode(raw_private_key),
            STANDARD.encode(expected_public_key),
        );
        assert_eq!(rendered, expected);
    }

    #[test]
    fn network_name_must_be_set() {
        let err = InstanceConfigBuilder::new("").network_secret("s").build().unwrap_err();
        assert!(matches!(err, ConfigError::NetworkNameEmpty));
    }

    #[test]
    fn network_secret_must_be_explicitly_set() {
        let err = InstanceConfigBuilder::new("net1").build().unwrap_err();
        assert!(matches!(err, ConfigError::NetworkSecretNotSet));
    }

    #[test]
    fn secure_mode_requires_nonempty_secret() {
        let err = InstanceConfigBuilder::new("net1").network_secret("").secure_mode().build().unwrap_err();
        assert!(matches!(err, ConfigError::SecureModeRequiresNetworkSecret));
    }

    #[test]
    fn secure_mode_with_private_key_rejects_wrong_length() {
        let err = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .secure_mode_with_private_key(&[0u8; 16])
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::SecurePrivateKeyWrongLength));
    }

    #[test]
    fn ipv4_prefix_must_be_narrower_than_32() {
        let err = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .ipv4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 32).expect("prefix"))
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::Ipv4PrefixTooNarrow));
    }

    #[test]
    fn hostname_rejects_control_characters() {
        let err = InstanceConfigBuilder::new("net1").network_secret("s").hostname("a\u{7}b").build().unwrap_err();
        assert!(matches!(err, ConfigError::HostnameControlCharacter));
    }

    #[test]
    fn peer_endpoint_rejects_non_tcp_udp_scheme() {
        let err = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .add_peers(["http://1.2.3.4:80"])
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEndpoint { field: "peers", index: 0, .. }));
    }

    #[test]
    fn peer_endpoint_allows_hostname() {
        let config = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .add_peers(["tcp://relay.example.com:11010"])
            .build()
            .expect("build");
        let rendered = render_toml(&config).expect("render");
        assert!(rendered.contains("uri = \"tcp://relay.example.com:11010\"\n"));
    }

    #[test]
    fn listener_endpoint_rejects_hostname() {
        let err = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .add_listeners(["tcp://relay.example.com:11010"])
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEndpoint { field: "listeners", index: 0, .. }));
    }

    #[test]
    fn duplicate_peer_endpoints_are_rejected() {
        let err = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .add_peers(["tcp://1.2.3.4:11010", "tcp://1.2.3.4:11010"])
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateEndpoint { field: "peers", index: 1 }));
    }

    #[test]
    fn duplicate_port_forwards_are_rejected() {
        let forward = PortForwardConfig {
            protocol: PortForwardProtocol::Tcp,
            bind: "127.0.0.1:8080".parse().expect("bind"),
            destination: "10.0.0.2:9090".parse().expect("destination"),
        };
        let err = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .add_port_forwards([forward, forward])
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::DuplicatePortForward { index: 1 }));
    }

    #[test]
    fn port_forward_rejects_ipv6() {
        let err = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .add_port_forwards([PortForwardConfig {
                protocol: PortForwardProtocol::Tcp,
                bind: "[::1]:8080".parse().expect("bind"),
                destination: "10.0.0.2:9090".parse().expect("destination"),
            }])
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::PortForwardInvalidBind { index: 0 }));
    }

    #[test]
    fn port_forward_rejects_zero_destination_port() {
        let err = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .add_port_forwards([PortForwardConfig {
                protocol: PortForwardProtocol::Udp,
                bind: "127.0.0.1:8080".parse().expect("bind"),
                destination: "10.0.0.2:0".parse().expect("destination"),
            }])
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::PortForwardZeroDestinationPort { index: 0 }));
    }

    #[test]
    fn hole_punching_symmetric_udp_requires_udp() {
        let err = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .hole_punching(HolePunchingPolicy { tcp: true, udp: false, symmetric_udp: true })
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::SymmetricUdpRequiresUdp));
    }

    #[test]
    fn stun_server_accepts_bare_ipv4() {
        let config = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .stun_servers(["203.0.113.1"])
            .build()
            .expect("build");
        assert!(render_toml(&config).expect("render").contains("stun_servers = [\"203.0.113.1\"]\n"));
    }

    #[test]
    fn stun_server_rejects_ipv4_in_v6_list() {
        let err = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .stun_servers_v6(["203.0.113.1"])
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidStunServer { field: "stun_servers_v6", index: 0, .. }));
    }

    #[test]
    fn stun_server_accepts_txt_lookup() {
        let config = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .stun_servers(["txt:stun.example.com"])
            .build()
            .expect("build");
        assert!(render_toml(&config).expect("render").contains("stun_servers = [\"txt:stun.example.com\"]\n"));
    }

    #[test]
    fn stun_server_rejects_zero_port() {
        let err = InstanceConfigBuilder::new("net1")
            .network_secret("s")
            .stun_servers(["stun.example.com:0"])
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidStunServer { field: "stun_servers", index: 0, .. }));
    }

    #[test]
    fn quote_toml_string_uses_html_safe_json_escaping() {
        assert_eq!(quote_toml_string("plain"), "\"plain\"");
        assert_eq!(quote_toml_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quote_toml_string("<b>&</b>"), "\"\\u003cb\\u003e\\u0026\\u003c/b\\u003e\"");
        assert_eq!(quote_toml_string("\x07\x7f"), "\"\\u0007\\u007f\"");
    }

    #[test]
    fn debug_impls_redact() {
        let config = InstanceConfigBuilder::new("net1").network_secret("top-secret").build().expect("build");
        assert_eq!(format!("{config:?}"), "InstanceConfig{<redacted>}");

        let builder = InstanceConfigBuilder::new("net1").network_secret("top-secret");
        assert_eq!(format!("{builder:?}"), "InstanceConfigBuilder{<redacted>}");
    }
}

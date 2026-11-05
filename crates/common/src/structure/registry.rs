use super::structure::RequiredFieldsTable;

#[cfg(test)]
const STRUCTURE_TESTS: RequiredFieldsTable =
    &[("RequiredDemo", &["certificate"]), ("RequiredDemoFlatten", &["certificate"])];

/// `listener/parse.rs`'s DTOs, each decoded independently of the `BaseOptionDto` that carries
/// its listener's `name`/`listen`/`port`/etc. (see that file's module doc), so each entry lists
/// only its own struct's directly-declared `inbound:"..."` tags.
const LISTENER_PARSE: RequiredFieldsTable = &[
    ("BaseOptionDto", &["name"]),
    ("AuthUserDto", &["username", "password"]),
    ("RealityConfigDto", &["dest", "private-key", "short-id", "server-names"]),
    ("ShadowTLSDto", &["enable"]),
    ("ShadowTLSHandshakeOptionsDto", &["dest"]),
    ("ResTLSDto", &["enable", "dest", "password"]),
    ("JLSUserDto", &["username", "password"]),
    ("JLSConfigDto", &["enable", "users", "dest"]),
    ("KcpTunDto", &["enable"]),
    ("VmessUserDto", &["uuid"]),
    ("VlessUserDto", &["uuid"]),
    ("TrojanUserDto", &["password"]),
    ("ShadowQuicUserDto", &["username", "password"]),
    ("ShadowQuicJLSUpstreamDto", &["addr"]),
    ("TunnelOptionDto", &["network", "target"]),
    ("ShadowSocksOptionDto", &["password", "cipher"]),
    ("SnellOptionDto", &["psk"]),
    ("VmessOptionDto", &["users"]),
    ("VlessOptionDto", &["users"]),
    ("TrojanOptionDto", &["users"]),
    ("Hysteria2OptionDto", &["certificate", "private-key"]),
    ("Hysteria2RealmServerOptionDto", &["token"]),
    ("TuicOptionDto", &["certificate", "private-key"]),
    ("ShadowQuicOptionDto", &["jls-upstream"]),
    ("MieruOptionDto", &["transport", "users"]),
    ("SudokuOptionDto", &["key"]),
    ("TrustTunnelOptionDto", &["certificate", "private-key"]),
];

const ADAPTER_PARSER: RequiredFieldsTable = &[
    ("ShadowSocksRDto", &["name", "server", "port", "password", "cipher", "obfs", "protocol"]),
    ("Socks5Dto", &["name", "server", "port"]),
    ("HttpDto", &["name", "server", "port"]),
    ("DnsDto", &["name"]),
    ("RejectDto", &["name"]),
    ("SshDto", &["name", "server", "port", "username"]),
    ("SnellDto", &["name", "server", "port", "psk"]),
    ("MieruDto", &["name", "server", "transport", "username", "password"]),
];

const OUTBOUNDGROUP_PARSER: RequiredFieldsTable = &[("GroupCommonOption", &["name", "type"])];

const PROVIDER_PARSER: RequiredFieldsTable = &[("ProxyProviderSchema", &["type"]), ("HealthCheckSchema", &["enable"])];

const RULES_PROVIDER_PARSE: RequiredFieldsTable = &[("RuleProviderSchema", &["type", "behavior"])];

/// Outbound `proxy:"..."`-tagged option structs decoded via `adapter::parser::parse_proxy`'s
/// `flattened!` macro. Each of these flattens `BasicOption` (zero required fields, confirmed
/// against the outbound base option struct) and, for `WireGuardOption`, the anonymously embedded
/// `WireGuardPeerOption` (also zero required fields), so only each struct's own directly-declared
/// tags are listed here.
const ADAPTER_OUTBOUND: RequiredFieldsTable = &[
    ("ShadowSocksOption", &["name", "server", "port", "password", "cipher"]),
    ("VmessOption", &["name", "server", "port", "uuid", "alterId", "cipher"]),
    ("VlessOption", &["name", "server", "port", "uuid"]),
    ("TrojanOption", &["name", "server", "port", "password"]),
    ("HysteriaOption", &["name", "server", "up", "down"]),
    ("Hysteria2Option", &["name", "server"]),
    ("WireGuardOption", &["name", "private-key"]),
    ("TuicOption", &["name", "server", "port"]),
    ("ShadowQuicOption", &["name", "server", "port"]),
    ("GostRelayOption", &["name", "server", "port"]),
    ("DirectOption", &["name"]),
    ("RematchOption", &["name"]),
    ("AnyTLSOption", &["name", "server", "port", "password"]),
    ("SudokuOption", &["name", "server", "port", "key"]),
    ("MasqueOption", &["name", "server", "port", "private-key", "public-key"]),
    ("TrustTunnelOption", &["name", "server", "port"]),
    ("OpenVPNOption", &["name", "server", "port", "ca"]),
    ("TailscaleOption", &["name"]),
    ("ZeroTierOption", &["name", "network"]),
    ("EasyTierOption", &["name"]),
];

/// Nested structs reached from the `ADAPTER_OUTBOUND` options above: shadowsocks `plugin-opts`
/// variants (each decoded top-level in its own right by `ShadowSocks::new`, tag name `obfs`), and
/// a `ZeroTier` orbit entry. The TLS-wrapper blocks are absent for two different reasons:
/// `reality-opts`/`jls-opts` are option structs that enforce the rules in their own
/// decoding (`RealityOpts` requires `public-key`, `JlsOptions::parse` rejects a half-filled block),
/// while `restls-opts` still decodes into `base::UnsupportedTlsOption` and is rejected by name.
const ADAPTER_OUTBOUND_NESTED: RequiredFieldsTable = &[
    ("V2rayObfsOption", &["mode"]),
    ("GostObfsOption", &["mode"]),
    ("ShadowTLSOption", &["host"]),
    ("ZeroTierOrbitOption", &["world", "seed"]),
];

#[cfg(test)]
pub(crate) const ALL: &[RequiredFieldsTable] = &[
    STRUCTURE_TESTS,
    LISTENER_PARSE,
    ADAPTER_PARSER,
    OUTBOUNDGROUP_PARSER,
    PROVIDER_PARSER,
    RULES_PROVIDER_PARSE,
    ADAPTER_OUTBOUND,
    ADAPTER_OUTBOUND_NESTED,
];

#[cfg(not(test))]
pub(crate) const ALL: &[RequiredFieldsTable] = &[
    LISTENER_PARSE,
    ADAPTER_PARSER,
    OUTBOUNDGROUP_PARSER,
    PROVIDER_PARSER,
    RULES_PROVIDER_PARSE,
    ADAPTER_OUTBOUND,
    ADAPTER_OUTBOUND_NESTED,
];

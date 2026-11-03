//! The `adapter/outbound` option structs that lack `Serialize`/`Deserialize` cannot be decoded
//! directly by the YAML decoder.
//!
//! For those (`Socks5Option`, `HttpOption`, `DnsOption`, `RejectOption`, `SshOption`,
//! `ShadowSocksROption`, `SnellOption`) this file decodes into a local DTO carrying the same
//! `proxy:"..."` wire names and copies the result into the outbound option struct field by field.

use std::fmt;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde::Deserialize;
use yaml_serde::{Mapping, Value};

use murmur_adapter_outbound::base::{self, BasicOption, ProxyAdapter as OutboundProxyAdapter};
use murmur_common::structure::structure::{
    drop_null_fields, new_decoder, Decoder, Option as StructureOption, DEFAULT_KEY_REPLACER,
};
use murmur_constant::adapters::{Dialer as CDialer, Proxy as CProxy};

use super::adapter::Proxy;
use murmur_adapter_outbound as outbound;

/// Decodes into `$ty` and copies the API-only [`BasicOption`] fields (`dialer_for_api`,
/// `tunnel_for_api`, `provider_name`) into its `$field` before invoking `$ctor`.
macro_rules! flattened {
    ($mapping:expr, $decoder:expr, $basic_option:expr, $ty:path, $field:ident, $ctor:path) => {{
        let mut opt: $ty = $decoder.decode($mapping)?;
        opt.$field.dialer_for_api.clone_from(&$basic_option.dialer_for_api);
        opt.$field.tunnel_for_api.clone_from(&$basic_option.tunnel_for_api);
        opt.$field.provider_name.clone_from(&$basic_option.provider_name);
        $ctor(opt)
    }};
}

/// Overlays the API-only `BasicOption` fields (`dialer_for_api`, `tunnel_for_api`,
/// `provider_name`) from `api` onto a `BasicOption` decoded from a DTO's flattened fields.
fn merge_api_only(mut basic: BasicOption, api: &BasicOption) -> BasicOption {
    basic.dialer_for_api.clone_from(&api.dialer_for_api);
    basic.tunnel_for_api.clone_from(&api.tunnel_for_api);
    basic.provider_name.clone_from(&api.provider_name);
    basic
}

#[expect(
    clippy::too_many_lines,
    reason = "one flat protocol dispatch table, one arm per `proxy:` type; the length is the protocol list, not logic"
)]
pub fn parse_proxy(mapping: &Mapping, options: &[ProxyOption]) -> Result<Arc<dyn CProxy>> {
    // Every outbound option struct embeds `BasicOption`, so the decoder reaches
    // `deserialize_map` rather than `deserialize_struct` and needs null fields gone first.
    let stripped = mapping.iter().any(|(_, value)| value.is_null()).then(|| drop_null_fields(mapping));
    let mapping = stripped.as_ref().unwrap_or(mapping);

    let decoder = new_decoder(StructureOption {
        tag_name: "proxy".to_owned(),
        weakly_typed_input: true,
        key_replacer: Some(DEFAULT_KEY_REPLACER.clone()),
    });

    let proxy_type = mapping.get("type").and_then(Value::as_str).ok_or_else(|| anyhow!("missing type"))?;

    let opt = apply_proxy_options(options);
    let basic_option = BasicOption {
        dialer_for_api: opt.dialer_for_api.clone(),
        tunnel_for_api: opt.tunnel_for_api.clone(),
        provider_name: opt.provider_name.clone(),
        ..Default::default()
    };

    let proxy: Arc<dyn OutboundProxyAdapter> = match proxy_type {
        #[cfg(not(feature = "extra-protocols"))]
        "ss" | "ssr" | "socks5" | "http" | "snell" | "mieru" | "hysteria" | "hysteria2" | "tuic" | "shadowquic"
        | "gost-relay" | "wireguard" | "ssh" | "anytls" | "sudoku" | "masque" | "trusttunnel" | "openvpn" => {
            return Err(anyhow!("outbound protocol {proxy_type} requires feature extra-protocols"));
        }
        #[cfg(feature = "extra-protocols")]
        "ss" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::shadowsocks::ShadowSocksOption,
            basic_option,
            outbound::shadowsocks::ShadowSocks::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "ssr" => {
            let dto: ShadowSocksRDto = decoder.decode(mapping)?;
            let ssr_option = outbound::shadowsocksr::ShadowSocksROption {
                basic_option: merge_api_only(dto.basic, &basic_option),
                name: dto.name,
                server: dto.server,
                port: dto.port,
                password: dto.password,
                cipher: dto.cipher,
                obfs: dto.obfs,
                obfs_param: dto.obfs_param,
                protocol: dto.protocol,
                protocol_param: dto.protocol_param,
                udp: dto.udp,
            };
            outbound::shadowsocksr::ShadowSocksR::new(ssr_option)?
        }
        #[cfg(feature = "extra-protocols")]
        "socks5" => {
            let dto: Socks5Dto = decoder.decode(mapping)?;
            let socks5_option = outbound::socks5::Socks5Option {
                basic_option: merge_api_only(dto.basic, &basic_option),
                name: dto.name,
                server: dto.server,
                port: dto.port,
                user_name: dto.user_name,
                password: dto.password,
                tls: dto.tls,
                udp: dto.udp,
                skip_cert_verify: dto.skip_cert_verify,
                name_cert_verify: dto.name_cert_verify,
                fingerprint: dto.fingerprint,
                certificate: dto.certificate,
                private_key: dto.private_key,
            };
            outbound::socks5::Socks5::new(socks5_option)?
        }
        #[cfg(feature = "extra-protocols")]
        "http" => {
            let dto: HttpDto = decoder.decode(mapping)?;
            let http_option = outbound::http::HttpOption {
                basic_option: merge_api_only(dto.basic, &basic_option),
                name: dto.name,
                server: dto.server,
                port: dto.port,
                user_name: dto.user_name,
                password: dto.password,
                tls: dto.tls,
                sni: dto.sni,
                skip_cert_verify: dto.skip_cert_verify,
                name_cert_verify: dto.name_cert_verify,
                fingerprint: dto.fingerprint,
                certificate: dto.certificate,
                private_key: dto.private_key,
                headers: dto.headers,
            };
            Arc::new(outbound::http::Http::new(http_option)?)
        }
        "vmess" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::vmess::VmessOption,
            basic,
            outbound::vmess::Vmess::new
        )?,
        "vless" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::vless::VlessOption,
            basic_option,
            outbound::vless::Vless::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "snell" => {
            let dto: SnellDto = decoder.decode(mapping)?;
            let snell_option = outbound::snell::SnellOption {
                basic_option: merge_api_only(dto.basic, &basic_option),
                name: dto.name,
                server: dto.server,
                port: dto.port,
                psk: dto.psk,
                udp: dto.udp,
                version: dto.version,
                reuse: dto.reuse,
                obfs_opts: dto.obfs_opts,
                client_fingerprint: dto.client_fingerprint,
            };
            outbound::snell::Snell::new(snell_option)?
        }
        #[cfg(feature = "extra-protocols")]
        "mieru" => {
            let dto: MieruDto = decoder.decode(mapping)?;
            let mieru_option = outbound::mieru::MieruOption {
                basic_option: merge_api_only(dto.basic, &basic_option),
                name: dto.name,
                server: dto.server,
                port: dto.port,
                port_range: dto.port_range,
                transport: dto.transport,
                udp: dto.udp,
                user_name: dto.user_name,
                password: dto.password,
                multiplexing: dto.multiplexing,
                handshake_mode: dto.handshake_mode,
                traffic_pattern: dto.traffic_pattern,
            };
            outbound::mieru::Mieru::new(mieru_option)?
        }
        "trojan" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::trojan::TrojanOption,
            basic_option,
            outbound::trojan::Trojan::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "hysteria" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::hysteria::HysteriaOption,
            basic_option,
            outbound::hysteria::Hysteria::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "hysteria2" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::hysteria2::Hysteria2Option,
            basic_option,
            outbound::hysteria2::Hysteria2::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "tuic" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::tuic::TuicOption,
            basic_option,
            outbound::tuic::Tuic::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "shadowquic" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::shadowquic::ShadowQuicOption,
            basic_option,
            outbound::shadowquic::ShadowQuic::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "gost-relay" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::gost_relay::GostRelayOption,
            basic_option,
            outbound::gost_relay::GostRelay::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "wireguard" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::wireguard::WireGuardOption,
            basic_option,
            outbound::wireguard::WireGuard::new
        )?,
        "direct" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::direct::DirectOption,
            basic_option,
            outbound::direct::Direct::new
        ),
        "dns" => {
            let dto: DnsDto = decoder.decode(mapping)?;
            let dns_option =
                outbound::dns::DnsOption { basic_option: merge_api_only(dto.basic, &basic_option), name: dto.name };
            outbound::dns::Dns::new(dns_option)
        }
        "reject" => {
            let dto: RejectDto = decoder.decode(mapping)?;
            let reject_option = outbound::reject::RejectOption {
                basic_option: merge_api_only(dto.basic, &basic_option),
                name: dto.name,
            };
            outbound::reject::Reject::new(reject_option)
        }
        "rematch" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::rematch::RematchOption,
            basic_option,
            outbound::rematch::Rematch::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "ssh" => {
            let dto: SshDto = decoder.decode(mapping)?;
            let ssh_option = outbound::ssh::SshOption {
                basic_option: merge_api_only(dto.basic, &basic_option),
                name: dto.name,
                server: dto.server,
                port: dto.port,
                user_name: dto.user_name,
                password: dto.password,
                private_key: dto.private_key,
                private_key_passphrase: dto.private_key_passphrase,
                host_key: dto.host_key,
                host_key_algorithms: dto.host_key_algorithms,
            };
            outbound::ssh::Ssh::new(ssh_option)?
        }
        #[cfg(feature = "extra-protocols")]
        "anytls" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::anytls::AnyTLSOption,
            basic_option,
            outbound::anytls::AnyTLS::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "sudoku" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::sudoku::SudokuOption,
            basic_option,
            outbound::sudoku::Sudoku::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "masque" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::masque::MasqueOption,
            basic,
            outbound::masque::Masque::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "trusttunnel" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::trusttunnel::TrustTunnelOption,
            basic_option,
            outbound::trusttunnel::TrustTunnel::new
        )?,
        #[cfg(feature = "extra-protocols")]
        "openvpn" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::openvpn::OpenVPNOption,
            basic_option,
            outbound::openvpn::OpenVPN::new
        )?,
        "tailscale" => build_tailscale(&decoder, mapping, &basic_option)?,
        "easytier" => build_easytier(&decoder, mapping, &basic_option)?,
        #[cfg(all(feature = "zerotier", not(feature = "no_zerotier")))]
        "zerotier" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::zerotier::ZeroTierOption,
            basic_option,
            outbound::zerotier::ZeroTier::new
        )?,
        #[cfg(not(all(feature = "zerotier", not(feature = "no_zerotier"))))]
        "zerotier" => {
            return Err(anyhow!("zerotier support is disabled: requires feature \"zerotier\" without \"no_zerotier\""))
        }
        other => return Err(anyhow!("unsupport proxy type: {other}")),
    };

    let mut proxy = proxy;
    if let Some(mux_mapping) = mapping.get("smux").and_then(Value::as_mapping) {
        let mux_option: outbound::singmux::SingMuxOption = decoder.decode(mux_mapping)?;
        if mux_option.enabled {
            proxy = outbound::singmux::new_sing_mux(mux_option, proxy)?;
        }
    }

    let proxy = base::new_auto_close_proxy_adapter(proxy);
    Ok(Proxy::new(proxy))
}

#[cfg(all(feature = "tailscale", feature = "with_gvisor", not(feature = "no_tailscale")))]
fn build_tailscale(
    decoder: &Decoder,
    mapping: &Mapping,
    basic_option: &BasicOption,
) -> Result<Arc<dyn OutboundProxyAdapter>> {
    Ok(flattened!(
        mapping,
        decoder,
        basic_option,
        outbound::tailscale::TailscaleOption,
        basic_option,
        outbound::tailscale::Tailscale::new
    )?)
}

#[cfg(not(all(feature = "tailscale", feature = "with_gvisor", not(feature = "no_tailscale"))))]
fn build_tailscale(
    _decoder: &Decoder,
    _mapping: &Mapping,
    _basic_option: &BasicOption,
) -> Result<Arc<dyn OutboundProxyAdapter>> {
    Err(anyhow!(
        "tailscale support is disabled: requires features \"tailscale\" and \"with_gvisor\" without \"no_tailscale\""
    ))
}

#[cfg(all(feature = "easytier", not(feature = "no_easytier")))]
fn build_easytier(
    decoder: &Decoder,
    mapping: &Mapping,
    basic_option: &BasicOption,
) -> Result<Arc<dyn OutboundProxyAdapter>> {
    let mut opt: outbound::easytier::EasyTierOption = decoder.decode(mapping)?;
    opt.basic.dialer_for_api.clone_from(&basic_option.dialer_for_api);
    opt.basic.tunnel_for_api.clone_from(&basic_option.tunnel_for_api);
    opt.basic.provider_name.clone_from(&basic_option.provider_name);
    Ok(outbound::easytier::EasyTier::new(opt)?)
}

#[cfg(not(all(feature = "easytier", not(feature = "no_easytier"))))]
fn build_easytier(
    _decoder: &Decoder,
    _mapping: &Mapping,
    _basic_option: &BasicOption,
) -> Result<Arc<dyn OutboundProxyAdapter>> {
    Err(anyhow!("easytier support is disabled: requires feature \"easytier\" without \"no_easytier\""))
}

#[cfg(feature = "extra-protocols")]
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct ShadowSocksRDto {
    #[serde(flatten)]
    basic: BasicOption,
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "server")]
    server: String,
    #[serde(rename = "port")]
    port: u16,
    #[serde(rename = "password")]
    password: String,
    #[serde(rename = "cipher")]
    cipher: String,
    #[serde(rename = "obfs")]
    obfs: String,
    #[serde(rename = "obfs-param", default)]
    obfs_param: String,
    #[serde(rename = "protocol")]
    protocol: String,
    #[serde(rename = "protocol-param", default)]
    protocol_param: String,
    #[serde(rename = "udp", default)]
    udp: bool,
}

#[cfg(feature = "extra-protocols")]
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct Socks5Dto {
    #[serde(flatten)]
    basic: BasicOption,
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "server")]
    server: String,
    #[serde(rename = "port")]
    port: u16,
    #[serde(rename = "username", default)]
    user_name: String,
    #[serde(rename = "password", default)]
    password: String,
    #[serde(rename = "tls", default)]
    tls: bool,
    #[serde(rename = "udp", default)]
    udp: bool,
    #[serde(rename = "skip-cert-verify", default)]
    skip_cert_verify: bool,
    #[serde(rename = "name-cert-verify", default)]
    name_cert_verify: String,
    #[serde(rename = "fingerprint", default)]
    fingerprint: String,
    #[serde(rename = "certificate", default)]
    certificate: String,
    #[serde(rename = "private-key", default)]
    private_key: String,
}

#[cfg(feature = "extra-protocols")]
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct HttpDto {
    #[serde(flatten)]
    basic: BasicOption,
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "server")]
    server: String,
    #[serde(rename = "port")]
    port: u16,
    #[serde(rename = "username", default)]
    user_name: String,
    #[serde(rename = "password", default)]
    password: String,
    #[serde(rename = "tls", default)]
    tls: bool,
    #[serde(rename = "sni", default)]
    sni: String,
    #[serde(rename = "skip-cert-verify", default)]
    skip_cert_verify: bool,
    #[serde(rename = "name-cert-verify", default)]
    name_cert_verify: String,
    #[serde(rename = "fingerprint", default)]
    fingerprint: String,
    #[serde(rename = "certificate", default)]
    certificate: String,
    #[serde(rename = "private-key", default)]
    private_key: String,
    #[serde(rename = "headers", default)]
    headers: std::collections::HashMap<String, String>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct DnsDto {
    #[serde(flatten)]
    basic: BasicOption,
    #[serde(rename = "name")]
    name: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct RejectDto {
    #[serde(flatten)]
    basic: BasicOption,
    #[serde(rename = "name")]
    name: String,
}

#[cfg(feature = "extra-protocols")]
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct SshDto {
    #[serde(flatten)]
    basic: BasicOption,
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "server")]
    server: String,
    #[serde(rename = "port")]
    port: u16,
    #[serde(rename = "username")]
    user_name: String,
    #[serde(rename = "password", default)]
    password: String,
    #[serde(rename = "private-key", default)]
    private_key: String,
    #[serde(rename = "private-key-passphrase", default)]
    private_key_passphrase: String,
    #[serde(rename = "host-key", default)]
    host_key: Vec<String>,
    #[serde(rename = "host-key-algorithms", default)]
    host_key_algorithms: Vec<String>,
}

#[cfg(feature = "extra-protocols")]
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct SnellDto {
    #[serde(flatten)]
    basic: BasicOption,
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "server")]
    server: String,
    #[serde(rename = "port")]
    port: u16,
    #[serde(rename = "psk")]
    psk: String,
    #[serde(rename = "udp", default)]
    udp: bool,
    #[serde(rename = "version", default)]
    version: i32,
    #[serde(rename = "reuse", default)]
    reuse: bool,
    #[serde(rename = "obfs-opts", default)]
    obfs_opts: Mapping,
    #[serde(rename = "client-fingerprint", default)]
    client_fingerprint: String,
}

#[cfg(feature = "extra-protocols")]
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct MieruDto {
    #[serde(flatten)]
    basic: BasicOption,
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "server")]
    server: String,
    #[serde(rename = "port", default)]
    port: u16,
    #[serde(rename = "port-range", default)]
    port_range: String,
    #[serde(rename = "transport")]
    transport: String,
    #[serde(rename = "udp", default)]
    udp: bool,
    #[serde(rename = "username")]
    user_name: String,
    #[serde(rename = "password")]
    password: String,
    #[serde(rename = "multiplexing", default)]
    multiplexing: String,
    #[serde(rename = "handshake-mode", default)]
    handshake_mode: String,
    #[serde(rename = "traffic-pattern", default)]
    traffic_pattern: String,
}

/// The per-proxy option struct. It is `ProxyOpt` rather than `ProxyOption` because the exported
/// `ProxyOption` function type below would otherwise collide.
#[derive(Clone, Default)]
pub struct ProxyOpt {
    dialer_for_api: Option<Arc<dyn CDialer>>,
    tunnel_for_api: Option<Arc<dyn murmur_constant::tunnel::Tunnel>>,
    provider_name: String,
}

impl fmt::Debug for ProxyOpt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyOpt").field("provider_name", &self.provider_name).finish_non_exhaustive()
    }
}

fn apply_proxy_options(options: &[ProxyOption]) -> ProxyOpt {
    let mut opt = ProxyOpt::default();
    for o in options {
        o(&mut opt);
    }
    opt
}

pub(crate) type ProxyOption = Arc<dyn Fn(&mut ProxyOpt) + Send + Sync>;

#[allow(dead_code, reason = "no caller anywhere")]
pub(crate) fn with_dialer_for_api(dialer: Arc<dyn CDialer>) -> ProxyOption {
    Arc::new(move |opt: &mut ProxyOpt| opt.dialer_for_api = Some(Arc::clone(&dialer)))
}

pub fn with_tunnel_for_api(tunnel: Arc<dyn murmur_constant::tunnel::Tunnel>) -> ProxyOption {
    Arc::new(move |opt: &mut ProxyOpt| opt.tunnel_for_api = Some(Arc::clone(&tunnel)))
}

#[must_use]
pub fn with_provider_name(name: String) -> ProxyOption {
    Arc::new(move |opt: &mut ProxyOpt| opt.provider_name.clone_from(&name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "extra-protocols"))]
    #[test]
    fn removed_outbounds_fail_before_decoding_protocol_options() {
        for protocol in [
            "ss",
            "ssr",
            "socks5",
            "http",
            "snell",
            "mieru",
            "hysteria",
            "hysteria2",
            "tuic",
            "shadowquic",
            "gost-relay",
            "wireguard",
            "ssh",
            "anytls",
            "sudoku",
            "masque",
            "trusttunnel",
            "openvpn",
        ] {
            let mapping = yaml_serde::from_str::<Mapping>(&format!("name: removed\ntype: {protocol}\n")).unwrap();
            let error = parse_proxy(&mapping, &[]).err().expect("removed protocol must fail");
            let message = error.to_string();
            assert!(message.contains(protocol), "{message}");
            assert!(message.contains("extra-protocols"), "{message}");
        }
    }

    #[tokio::test]
    async fn retained_outbounds_parse_with_or_without_extra_protocols() {
        for protocol in ["vless", "vmess", "trojan"] {
            let mapping = yaml_serde::from_str::<Mapping>(&format!(
                "name: retained\ntype: {protocol}\nserver: 192.0.2.1\nport: 443\nuuid: 11111111-1111-1111-1111-111111111111\npassword: example\ncipher: auto\nalterId: 0\n"
            )).unwrap();
            let proxy = parse_proxy(&mapping, &[]).expect("retained outbound parses");
            assert_eq!(proxy.name(), "retained");
        }
    }

    #[test]
    fn unavailable_overlay_engines_reject_configuration() {
        let engines = [
            ("easytier", cfg!(all(feature = "easytier", not(feature = "no_easytier")))),
            ("tailscale", cfg!(all(feature = "tailscale", feature = "with_gvisor", not(feature = "no_tailscale")))),
            ("zerotier", cfg!(all(feature = "zerotier", not(feature = "no_zerotier")))),
        ];
        for (engine, enabled) in engines {
            if enabled {
                continue;
            }
            let mapping = yaml_serde::from_str::<Mapping>(&format!("name: overlay\ntype: {engine}\n")).unwrap();
            let error = parse_proxy(&mapping, &[]).err().expect("disabled engines must reject configuration");
            let message = error.to_string();
            assert!(message.contains(engine), "the rejection must identify the engine: {message}");
            assert!(message.contains("disabled"), "the rejection must explain build availability: {message}");
        }
    }

    #[test]
    fn direct_configuration_remains_available_without_overlay_engines() {
        let mapping = yaml_serde::from_str::<Mapping>("name: local\ntype: direct\n").unwrap();
        let proxy = parse_proxy(&mapping, &[]).expect("direct routing does not require an overlay engine");
        assert_eq!(proxy.name(), "local");
    }
}

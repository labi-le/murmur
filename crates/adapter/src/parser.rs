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
use serde_yaml::{Mapping, Value};

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
        "ss" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::shadowsocks::ShadowSocksOption,
            basic_option,
            outbound::shadowsocks::ShadowSocks::new
        )?,
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
        "hysteria" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::hysteria::HysteriaOption,
            basic_option,
            outbound::hysteria::Hysteria::new
        )?,
        "hysteria2" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::hysteria2::Hysteria2Option,
            basic_option,
            outbound::hysteria2::Hysteria2::new
        )?,
        "tuic" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::tuic::TuicOption,
            basic_option,
            outbound::tuic::Tuic::new
        )?,
        "shadowquic" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::shadowquic::ShadowQuicOption,
            basic_option,
            outbound::shadowquic::ShadowQuic::new
        )?,
        "gost-relay" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::gost_relay::GostRelayOption,
            basic_option,
            outbound::gost_relay::GostRelay::new
        )?,
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
        "anytls" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::anytls::AnyTLSOption,
            basic_option,
            outbound::anytls::AnyTLS::new
        )?,
        "sudoku" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::sudoku::SudokuOption,
            basic_option,
            outbound::sudoku::Sudoku::new
        )?,
        "masque" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::masque::MasqueOption,
            basic,
            outbound::masque::Masque::new
        )?,
        "trusttunnel" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::trusttunnel::TrustTunnelOption,
            basic_option,
            outbound::trusttunnel::TrustTunnel::new
        )?,
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
        "zerotier" => flattened!(
            mapping,
            decoder,
            basic_option,
            outbound::zerotier::ZeroTierOption,
            basic_option,
            outbound::zerotier::ZeroTier::new
        )?,
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

#[cfg(all(feature = "with_gvisor", not(feature = "no_tailscale")))]
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

#[cfg(not(all(feature = "with_gvisor", not(feature = "no_tailscale"))))]
fn build_tailscale(
    decoder: &Decoder,
    mapping: &Mapping,
    basic_option: &BasicOption,
) -> Result<Arc<dyn OutboundProxyAdapter>> {
    let mut opt: outbound::tailscale_stub::TailscaleOption = decoder.decode(mapping)?;
    opt.basic_option.dialer_for_api.clone_from(&basic_option.dialer_for_api);
    opt.basic_option.tunnel_for_api.clone_from(&basic_option.tunnel_for_api);
    opt.basic_option.provider_name.clone_from(&basic_option.provider_name);
    outbound::tailscale_stub::Tailscale::new(opt)?;
    Err(anyhow!("the \"tailscale_stub\" constructor always returns an error"))
}

#[cfg(not(feature = "no_easytier"))]
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

#[cfg(feature = "no_easytier")]
fn build_easytier(
    decoder: &Decoder,
    mapping: &Mapping,
    basic_option: &BasicOption,
) -> Result<Arc<dyn OutboundProxyAdapter>> {
    let mut opt: outbound::easytier_stub::EasyTierOption = decoder.decode(mapping)?;
    opt.basic_option.dialer_for_api.clone_from(&basic_option.dialer_for_api);
    opt.basic_option.tunnel_for_api.clone_from(&basic_option.tunnel_for_api);
    opt.basic_option.provider_name.clone_from(&basic_option.provider_name);
    outbound::easytier_stub::EasyTier::new(opt)?;
    Err(anyhow!("the \"easytier_stub\" constructor always returns an error"))
}

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

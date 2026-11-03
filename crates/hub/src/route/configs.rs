//! The `/configs` mount: read and update the running configuration.
//!
//! The config types carry plain `json` field names, so the API serializes them directly.
//! [`GeneralForApi`] is a local API-shape mirror built from the real config value, the same
//! `ForApi` pattern `adapter/provider/provider.rs`'s `ProviderForApi` uses (a wire shape distinct
//! from the internal representation).

use std::path::Path as StdPath;
use std::sync::Arc;

use hyper::{Method, Response, StatusCode};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
#[cfg(feature = "extra-protocols")]
use std::collections::BTreeMap;

use crate::executor::executor::{apply_config, get_general, parse_with_bytes, parse_with_path};
use murmur_adapter_inbound::auth::set_skip_auth_prefixes;
use murmur_adapter_inbound::ipfilter::{set_allowed_ips, set_dis_allowed_ips};
use murmur_component::dialer::dialer::set_tcp_concurrent;
use murmur_component::dialer::options::DEFAULT_INTERFACE;
use murmur_component::resolver::resolver::set_disable_ipv6;
use murmur_component_process::find_process_mode::FindProcessMode;
use murmur_component_updater::update_geo::update_geo_databases_guarded;
use murmur_config::config::{Config, GeoXUrl};
use murmur_constant::path::PATH;
use murmur_constant::tunnel::Tunnel as ConstantTunnel;
use murmur_listener::listener::{
    get_ports, get_tun_conf, re_create_http, re_create_mixed, re_create_redir, re_create_socks, re_create_tproxy,
    re_create_tun, re_create_vmess, set_allow_lan, set_bind_address,
};
#[cfg(feature = "extra-protocols")]
use murmur_listener::listener::{last_tuic_conf, re_create_shadow_socks, re_create_tuic};
#[cfg(feature = "extra-protocols")]
use murmur_listener_config::tuic::TuicServer;
use murmur_log::LogLevel;
use murmur_log::{errorln, set_level};
use murmur_tunnel::mode::TunnelMode;
use murmur_tunnel::tunnel::set_sniffing;
use murmur_tunnel::tunnel::TUNNEL;

use super::common::{json_response, no_content, status_only, Req, RespBody};
use super::errors::{err_bad_request, HttpError};
use super::server::embed_mode;
use super::server::query_param;

fn tunnel_arc() -> Arc<dyn ConstantTunnel> {
    Arc::new(TUNNEL)
}

pub(crate) async fn route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    match segs {
        [] => match *req.method() {
            Method::GET => Some(get_configs().await),
            // The body is decoded before the process-wide lock is taken: decoding awaits the
            // client, and a slow or stalled body must not hold up a watched reload, a SIGHUP or
            // another update. The parse and the mutation that follow are what the lock covers.
            Method::PUT if !embed_mode() => {
                let force = force_requested(req.uri().query().unwrap_or(""));
                let Ok(request) =
                    super::common::decode_json_body::<Option<UpdateConfigsRequest>, _>(req.into_body()).await
                else {
                    return Some(json_response(StatusCode::BAD_REQUEST, &err_bad_request()));
                };
                let _operation = crate::hub::lock_config_operation().await;
                Some(update_configs(force, request.unwrap_or_default()).await)
            }
            Method::PATCH if !embed_mode() => {
                let Ok(general) = super::common::decode_json_body::<ConfigSchema, _>(req.into_body()).await else {
                    return Some(json_response(StatusCode::BAD_REQUEST, &err_bad_request()));
                };
                let _operation = crate::hub::lock_config_operation().await;
                Some(patch_configs(general).await)
            }
            _ => Some(status_only(StatusCode::METHOD_NOT_ALLOWED)),
        },
        ["geo"] if !embed_mode() => {
            if req.method() != Method::POST {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            Some(update_geo_databases().await)
        }
        _ => None,
    }
}

/// Renders prefixes as CIDR text; `ipnet::IpNet` carries no `serde` support at the pinned feature
/// set, matching `config/config.rs`'s and `listener/config/tun.rs`'s local "with"-module
/// re-implementations.
fn ip_net_vec_to_strings(prefixes: &[IpNet]) -> Vec<String> {
    prefixes.iter().map(ToString::to_string).collect()
}

/// Null-vs-empty slice distinction: an absent slice marshals to JSON `null`; the equivalent fields
/// never carry that distinction, so an empty `Vec` is the only signal "absent" ever produces
/// (see `hub/executor/executor.rs`'s `get_general`).
fn empty_to_none(values: Vec<String>) -> Option<Vec<String>> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

/// A zero/empty value, matching the intent of an omitted field: a zero-valued field is
/// skipped, while a present-but-empty slice still serializes as `[]` — see `RawTun`'s fields,
/// none of which are pointers.
fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

/// The `tun:` section rendered through its `json` field names, built from the actual parsed
/// `tun:` section (`murmur_listener_config::tun::Tun`) via [`tun_for_api`].
#[derive(Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "every field is one key of the `tun:` JSON section, so the flags cannot be grouped into a state enum"
)]
struct TunForApi {
    enable: bool,
    device: String,
    stack: String,
    #[serde(rename = "dns-hijack")]
    dns_hijack: Option<Vec<String>>,
    #[serde(rename = "auto-route")]
    auto_route: bool,
    #[serde(rename = "auto-route-delay", skip_serializing_if = "is_default")]
    auto_route_delay: u32,
    #[serde(rename = "auto-detect-interface")]
    auto_detect_interface: bool,
    #[serde(rename = "mtu", skip_serializing_if = "is_default")]
    mtu: u32,
    #[serde(rename = "gso", skip_serializing_if = "is_default")]
    gso: bool,
    #[serde(rename = "gso-max-size", skip_serializing_if = "is_default")]
    gso_max_size: u32,
    #[serde(rename = "inet4-address", skip_serializing_if = "is_default")]
    inet4_address: Vec<String>,
    #[serde(rename = "inet6-address", skip_serializing_if = "is_default")]
    inet6_address: Vec<String>,
    #[serde(rename = "iproute2-table-index", skip_serializing_if = "is_default")]
    iproute2_table_index: i64,
    #[serde(rename = "iproute2-rule-index", skip_serializing_if = "is_default")]
    iproute2_rule_index: i64,
    #[serde(rename = "auto-redirect", skip_serializing_if = "is_default")]
    auto_redirect: bool,
    #[serde(rename = "auto-redirect-input-mark", skip_serializing_if = "is_default")]
    auto_redirect_input_mark: u32,
    #[serde(rename = "auto-redirect-output-mark", skip_serializing_if = "is_default")]
    auto_redirect_output_mark: u32,
    #[serde(rename = "auto-redirect-iproute2-fallback-rule-index", skip_serializing_if = "is_default")]
    auto_redirect_iproute2_fallback_rule_index: i64,
    #[serde(rename = "loopback-address", skip_serializing_if = "is_default")]
    loopback_address: Vec<String>,
    #[serde(rename = "strict-route", skip_serializing_if = "is_default")]
    strict_route: bool,
    #[serde(rename = "route-address", skip_serializing_if = "is_default")]
    route_address: Vec<String>,
    #[serde(rename = "route-address-set", skip_serializing_if = "is_default")]
    route_address_set: Vec<String>,
    #[serde(rename = "route-exclude-address", skip_serializing_if = "is_default")]
    route_exclude_address: Vec<String>,
    #[serde(rename = "route-exclude-address-set", skip_serializing_if = "is_default")]
    route_exclude_address_set: Vec<String>,
    #[serde(rename = "include-interface", skip_serializing_if = "is_default")]
    include_interface: Vec<String>,
    #[serde(rename = "exclude-interface", skip_serializing_if = "is_default")]
    exclude_interface: Vec<String>,
    #[serde(rename = "include-uid", skip_serializing_if = "is_default")]
    include_uid: Vec<u32>,
    #[serde(rename = "include-uid-range", skip_serializing_if = "is_default")]
    include_uid_range: Vec<String>,
    #[serde(rename = "exclude-uid", skip_serializing_if = "is_default")]
    exclude_uid: Vec<u32>,
    #[serde(rename = "exclude-uid-range", skip_serializing_if = "is_default")]
    exclude_uid_range: Vec<String>,
    #[serde(rename = "exclude-src-port", skip_serializing_if = "is_default")]
    exclude_src_port: Vec<u16>,
    #[serde(rename = "exclude-src-port-range", skip_serializing_if = "is_default")]
    exclude_src_port_range: Vec<String>,
    #[serde(rename = "exclude-dst-port", skip_serializing_if = "is_default")]
    exclude_dst_port: Vec<u16>,
    #[serde(rename = "exclude-dst-port-range", skip_serializing_if = "is_default")]
    exclude_dst_port_range: Vec<String>,
    #[serde(rename = "include-android-user", skip_serializing_if = "is_default")]
    include_android_user: Vec<i64>,
    #[serde(rename = "include-package", skip_serializing_if = "is_default")]
    include_package: Vec<String>,
    #[serde(rename = "exclude-package", skip_serializing_if = "is_default")]
    exclude_package: Vec<String>,
    #[serde(rename = "include-mac-address", skip_serializing_if = "is_default")]
    include_mac_address: Vec<String>,
    #[serde(rename = "exclude-mac-address", skip_serializing_if = "is_default")]
    exclude_mac_address: Vec<String>,
    #[serde(rename = "endpoint-independent-nat", skip_serializing_if = "is_default")]
    endpoint_independent_nat: bool,
    #[serde(rename = "udp-timeout", skip_serializing_if = "is_default")]
    udp_timeout: i64,
    #[serde(rename = "icmp-timeout", skip_serializing_if = "is_default")]
    icmp_timeout: i64,
    #[serde(rename = "disable-icmp-forwarding", skip_serializing_if = "is_default")]
    disable_icmp_forwarding: bool,
    #[serde(rename = "file-descriptor")]
    file_descriptor: i32,
    #[serde(rename = "inet4-route-address", skip_serializing_if = "is_default")]
    inet4_route_address: Vec<String>,
    #[serde(rename = "inet6-route-address", skip_serializing_if = "is_default")]
    inet6_route_address: Vec<String>,
    #[serde(rename = "inet4-route-exclude-address", skip_serializing_if = "is_default")]
    inet4_route_exclude_address: Vec<String>,
    #[serde(rename = "inet6-route-exclude-address", skip_serializing_if = "is_default")]
    inet6_route_exclude_address: Vec<String>,
    #[serde(rename = "recvmsgx", skip_serializing_if = "is_default")]
    recvmsgx: bool,
    #[serde(rename = "sendmsgx", skip_serializing_if = "is_default")]
    sendmsgx: bool,
    #[serde(rename = "processors-per-channel", skip_serializing_if = "is_default")]
    processors_per_channel: i32,
}

/// The `tun:` section rendered field for field, built by the config parser's `parse_tun`.
fn tun_for_api(tun: &murmur_listener_config::tun::Tun) -> TunForApi {
    TunForApi {
        enable: tun.enable,
        device: tun.device.clone(),
        stack: tun.stack.to_string(),
        dns_hijack: tun.dns_hijack.clone(),
        auto_route: tun.auto_route,
        auto_route_delay: tun.auto_route_delay,
        auto_detect_interface: tun.auto_detect_interface,
        mtu: tun.mtu,
        gso: tun.gso,
        gso_max_size: tun.gso_max_size,
        inet4_address: ip_net_vec_to_strings(&tun.inet4_address),
        inet6_address: ip_net_vec_to_strings(&tun.inet6_address),
        iproute2_table_index: tun.iproute2_table_index,
        iproute2_rule_index: tun.iproute2_rule_index,
        auto_redirect: tun.auto_redirect,
        auto_redirect_input_mark: tun.auto_redirect_input_mark,
        auto_redirect_output_mark: tun.auto_redirect_output_mark,
        auto_redirect_iproute2_fallback_rule_index: tun.auto_redirect_iproute2_fallback_rule_index,
        loopback_address: tun.loopback_address.iter().map(ToString::to_string).collect(),
        strict_route: tun.strict_route,
        route_address: ip_net_vec_to_strings(&tun.route_address),
        route_address_set: tun.route_address_set.clone(),
        route_exclude_address: ip_net_vec_to_strings(&tun.route_exclude_address),
        route_exclude_address_set: tun.route_exclude_address_set.clone(),
        include_interface: tun.include_interface.clone(),
        exclude_interface: tun.exclude_interface.clone(),
        include_uid: tun.include_uid.clone(),
        include_uid_range: tun.include_uid_range.clone(),
        exclude_uid: tun.exclude_uid.clone(),
        exclude_uid_range: tun.exclude_uid_range.clone(),
        exclude_src_port: tun.exclude_src_port.clone(),
        exclude_src_port_range: tun.exclude_src_port_range.clone(),
        exclude_dst_port: tun.exclude_dst_port.clone(),
        exclude_dst_port_range: tun.exclude_dst_port_range.clone(),
        include_android_user: tun.include_android_user.clone(),
        include_package: tun.include_package.clone(),
        exclude_package: tun.exclude_package.clone(),
        include_mac_address: tun.include_mac_address.clone(),
        exclude_mac_address: tun.exclude_mac_address.clone(),
        endpoint_independent_nat: tun.endpoint_independent_nat,
        udp_timeout: tun.udp_timeout,
        icmp_timeout: tun.icmp_timeout,
        disable_icmp_forwarding: tun.disable_icmp_forwarding,
        file_descriptor: tun.file_descriptor,
        inet4_route_address: ip_net_vec_to_strings(&tun.inet4_route_address),
        inet6_route_address: ip_net_vec_to_strings(&tun.inet6_route_address),
        inet4_route_exclude_address: ip_net_vec_to_strings(&tun.inet4_route_exclude_address),
        inet6_route_exclude_address: ip_net_vec_to_strings(&tun.inet6_route_exclude_address),
        recvmsgx: tun.recvmsgx,
        sendmsgx: tun.sendmsgx,
        processors_per_channel: tun.processors_per_channel,
    }
}

/// `General` rendered through the `Inbound`+`General` `json` tags.
#[derive(Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "every field is one key of the `general:`/`inbound:` JSON sections, so the flags cannot be grouped into a state enum"
)]
struct GeneralForApi {
    port: i32,
    #[serde(rename = "socks-port")]
    socks_port: i32,
    #[serde(rename = "redir-port")]
    redir_port: i32,
    #[serde(rename = "tproxy-port")]
    tproxy_port: i32,
    #[serde(rename = "mixed-port")]
    mixed_port: i32,
    tun: TunForApi,
    #[cfg(feature = "extra-protocols")]
    #[serde(rename = "tuic-server")]
    tuic_server: TuicServer,
    #[cfg(feature = "extra-protocols")]
    #[serde(rename = "ss-config")]
    ss_config: String,
    #[serde(rename = "vmess-config")]
    vmess_config: String,
    /// `null` is written when no authenticator is configured; an empty JSON array is an
    /// observable divergence.
    authentication: Option<Vec<String>>,
    #[serde(rename = "skip-auth-prefixes")]
    skip_auth_prefixes: Option<Vec<String>>,
    #[serde(rename = "lan-allowed-ips")]
    lan_allowed_ips: Option<Vec<String>>,
    #[serde(rename = "lan-disallowed-ips")]
    lan_dis_allowed_ips: Option<Vec<String>>,
    #[serde(rename = "allow-lan")]
    allow_lan: bool,
    #[serde(rename = "bind-address")]
    bind_address: String,
    #[serde(rename = "inbound-tfo")]
    inbound_tfo: bool,
    #[serde(rename = "inbound-mptcp")]
    inbound_mptcp: bool,
    mode: TunnelMode,
    #[serde(rename = "unified-delay")]
    unified_delay: bool,
    #[serde(rename = "log-level")]
    log_level: LogLevel,
    ipv6: bool,
    #[serde(rename = "interface-name")]
    interface_name: String,
    #[serde(rename = "routing-mark")]
    routing_mark: i32,
    #[serde(rename = "geox-url")]
    geox_url: GeoXUrl,
    #[serde(rename = "geo-auto-update")]
    geo_auto_update: bool,
    #[serde(rename = "geo-update-interval")]
    geo_update_interval: i32,
    #[serde(rename = "geodata-mode")]
    geodata_mode: bool,
    #[serde(rename = "geodata-loader")]
    geodata_loader: String,
    #[serde(rename = "geosite-matcher")]
    geosite_matcher: String,
    #[serde(rename = "tcp-concurrent")]
    tcp_concurrent: bool,
    #[serde(rename = "find-process-mode")]
    find_process_mode: FindProcessMode,
    sniffing: bool,
    #[serde(rename = "global-ua")]
    global_ua: String,
    #[serde(rename = "etag-support")]
    etag_support: bool,
    #[serde(rename = "keep-alive-idle")]
    keep_alive_idle: i32,
    #[serde(rename = "keep-alive-interval")]
    keep_alive_interval: i32,
    #[serde(rename = "disable-keep-alive")]
    disable_keep_alive: bool,
}

fn general_to_api(general: murmur_config::config::General) -> GeneralForApi {
    let murmur_config::config::General {
        inbound,
        mode,
        unified_delay,
        log_level,
        ipv6,
        interface,
        routing_mark,
        geo_x_url,
        geo_auto_update,
        geo_update_interval,
        geodata_mode,
        geodata_loader,
        geosite_matcher,
        tcp_concurrent,
        find_process_mode,
        sniffing,
        global_ua,
        etag_support,
        keep_alive_idle,
        keep_alive_interval,
        disable_keep_alive,
    } = general;

    GeneralForApi {
        port: inbound.port,
        socks_port: inbound.socks_port,
        redir_port: inbound.redir_port,
        tproxy_port: inbound.tproxy_port,
        mixed_port: inbound.mixed_port,
        tun: tun_for_api(&inbound.tun),
        #[cfg(feature = "extra-protocols")]
        tuic_server: inbound.tuic_server,
        #[cfg(feature = "extra-protocols")]
        ss_config: inbound.shadow_socks_config,
        vmess_config: inbound.vmess_config,
        authentication: empty_to_none(inbound.authentication),
        skip_auth_prefixes: inbound.skip_auth_prefixes.map(|prefixes| ip_net_vec_to_strings(&prefixes)),
        lan_allowed_ips: inbound.lan_allowed_ips.map(|prefixes| ip_net_vec_to_strings(&prefixes)),
        lan_dis_allowed_ips: inbound.lan_dis_allowed_ips.map(|prefixes| ip_net_vec_to_strings(&prefixes)),
        allow_lan: inbound.allow_lan,
        bind_address: inbound.bind_address,
        inbound_tfo: inbound.inbound_tfo,
        inbound_mptcp: inbound.inbound_mptcp,
        mode,
        unified_delay,
        log_level,
        ipv6,
        interface_name: interface,
        routing_mark,
        geox_url: geo_x_url,
        geo_auto_update,
        geo_update_interval,
        geodata_mode,
        geodata_loader,
        geosite_matcher,
        tcp_concurrent,
        find_process_mode,
        sniffing,
        global_ua,
        etag_support,
        keep_alive_idle,
        keep_alive_interval,
        disable_keep_alive,
    }
}

/// Text-form `Deserialize` for an optional `Vec<IpNet>` field; see the module doc comment for why
/// `IpNet` has no direct `serde` support.
mod opt_ip_net_vec {
    use ipnet::IpNet;
    use serde::{Deserialize, Deserializer};

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<IpNet>>, D::Error> {
        let opt: Option<Vec<String>> = Option::deserialize(deserializer)?;
        opt.map(|values| values.iter().map(|v| v.parse().map_err(serde::de::Error::custom)).collect()).transpose()
    }
}

/// Text-form `Deserialize` for an optional `Vec<IpAddr>` field.
mod opt_ip_addr_vec {
    use std::net::IpAddr;

    use serde::{Deserialize, Deserializer};

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<IpAddr>>, D::Error> {
        let opt: Option<Vec<String>> = Option::deserialize(deserializer)?;
        opt.map(|values| values.iter().map(|v| v.parse::<IpAddr>().map_err(serde::de::Error::custom)).collect())
            .transpose()
    }
}

/// Every named field parses and merges into the stored `tun:` conf via [`merge_tun_schema`], and
/// the result is handed to `murmur_listener::listener::re_create_tun`.
#[derive(Deserialize, Default)]
struct TunSchema {
    #[serde(default)]
    enable: bool,
    device: Option<String>,
    stack: Option<murmur_constant::tun::TunStack>,
    #[serde(rename = "dns-hijack")]
    dns_hijack: Option<Vec<String>>,
    #[serde(rename = "auto-route")]
    auto_route: Option<bool>,
    #[serde(rename = "auto-route-delay")]
    auto_route_delay: Option<u32>,
    #[serde(rename = "auto-detect-interface")]
    auto_detect_interface: Option<bool>,
    mtu: Option<u32>,
    gso: Option<bool>,
    #[serde(rename = "gso-max-size")]
    gso_max_size: Option<u32>,
    #[serde(rename = "inet6-address", default, deserialize_with = "opt_ip_net_vec::deserialize")]
    inet6_address: Option<Vec<IpNet>>,
    #[serde(rename = "iproute2-table-index")]
    iproute2_table_index: Option<i64>,
    #[serde(rename = "iproute2-rule-index")]
    iproute2_rule_index: Option<i64>,
    #[serde(rename = "auto-redirect")]
    auto_redirect: Option<bool>,
    #[serde(rename = "auto-redirect-input-mark")]
    auto_redirect_input_mark: Option<u32>,
    #[serde(rename = "auto-redirect-output-mark")]
    auto_redirect_output_mark: Option<u32>,
    #[serde(rename = "auto-redirect-iproute2-fallback-rule-index")]
    auto_redirect_iproute2_fallback_rule_index: Option<i64>,
    #[serde(rename = "loopback-address", default, deserialize_with = "opt_ip_addr_vec::deserialize")]
    loopback_address: Option<Vec<std::net::IpAddr>>,
    #[serde(rename = "strict-route")]
    strict_route: Option<bool>,
    #[serde(rename = "route-address", default, deserialize_with = "opt_ip_net_vec::deserialize")]
    route_address: Option<Vec<IpNet>>,
    #[serde(rename = "route-address-set")]
    route_address_set: Option<Vec<String>>,
    #[serde(rename = "route-exclude-address", default, deserialize_with = "opt_ip_net_vec::deserialize")]
    route_exclude_address: Option<Vec<IpNet>>,
    #[serde(rename = "route-exclude-address-set")]
    route_exclude_address_set: Option<Vec<String>>,
    #[serde(rename = "include-interface")]
    include_interface: Option<Vec<String>>,
    #[serde(rename = "exclude-interface")]
    exclude_interface: Option<Vec<String>>,
    #[serde(rename = "include-uid")]
    include_uid: Option<Vec<u32>>,
    #[serde(rename = "include-uid-range")]
    include_uid_range: Option<Vec<String>>,
    #[serde(rename = "exclude-uid")]
    exclude_uid: Option<Vec<u32>>,
    #[serde(rename = "exclude-uid-range")]
    exclude_uid_range: Option<Vec<String>>,
    #[serde(rename = "include-android-user")]
    include_android_user: Option<Vec<i64>>,
    #[serde(rename = "include-package")]
    include_package: Option<Vec<String>>,
    #[serde(rename = "exclude-package")]
    exclude_package: Option<Vec<String>>,
    #[serde(rename = "include-mac-address")]
    include_mac_address: Option<Vec<String>>,
    #[serde(rename = "exclude-mac-address")]
    exclude_mac_address: Option<Vec<String>>,
    #[serde(rename = "endpoint-independent-nat")]
    endpoint_independent_nat: Option<bool>,
    #[serde(rename = "udp-timeout")]
    udp_timeout: Option<i64>,
    #[serde(rename = "icmp-timeout")]
    icmp_timeout: Option<i64>,
    #[serde(rename = "file-descriptor")]
    file_descriptor: Option<i32>,
    #[serde(rename = "inet4-route-address", default, deserialize_with = "opt_ip_net_vec::deserialize")]
    inet4_route_address: Option<Vec<IpNet>>,
    #[serde(rename = "inet6-route-address", default, deserialize_with = "opt_ip_net_vec::deserialize")]
    inet6_route_address: Option<Vec<IpNet>>,
    #[serde(rename = "inet4-route-exclude-address", default, deserialize_with = "opt_ip_net_vec::deserialize")]
    inet4_route_exclude_address: Option<Vec<IpNet>>,
    #[serde(rename = "inet6-route-exclude-address", default, deserialize_with = "opt_ip_net_vec::deserialize")]
    inet6_route_exclude_address: Option<Vec<IpNet>>,
    recvmsgx: Option<bool>,
    sendmsgx: Option<bool>,
    #[serde(rename = "processors-per-channel")]
    processors_per_channel: Option<i32>,
}

/// `def` (the currently stored `tun:` conf) is overridden field by field wherever the PATCH body
/// named that field. `enable`/`inet4-address` are the two exceptions: `enable` is unconditional (a
/// PATCH omitting it means "disable"), and `inet4-address` is never patchable (computed only at
/// parse time from `dns.fake-ip-range`).
fn merge_tun_schema(def: &murmur_listener_config::tun::Tun, patch: TunSchema) -> murmur_listener_config::tun::Tun {
    let mut merged = def.clone();
    merged.enable = patch.enable;
    overwrite_if_present(&mut merged.device, patch.device);
    overwrite_if_present(&mut merged.stack, patch.stack);
    if let Some(v) = patch.dns_hijack {
        merged.dns_hijack = Some(v);
    }
    overwrite_if_present(&mut merged.auto_route, patch.auto_route);
    overwrite_if_present(&mut merged.auto_route_delay, patch.auto_route_delay);
    overwrite_if_present(&mut merged.auto_detect_interface, patch.auto_detect_interface);
    overwrite_if_present(&mut merged.mtu, patch.mtu);
    overwrite_if_present(&mut merged.gso, patch.gso);
    overwrite_if_present(&mut merged.gso_max_size, patch.gso_max_size);
    overwrite_if_present(&mut merged.inet6_address, patch.inet6_address);
    overwrite_if_present(&mut merged.iproute2_table_index, patch.iproute2_table_index);
    overwrite_if_present(&mut merged.iproute2_rule_index, patch.iproute2_rule_index);
    overwrite_if_present(&mut merged.auto_redirect, patch.auto_redirect);
    overwrite_if_present(&mut merged.auto_redirect_input_mark, patch.auto_redirect_input_mark);
    overwrite_if_present(&mut merged.auto_redirect_output_mark, patch.auto_redirect_output_mark);
    overwrite_if_present(
        &mut merged.auto_redirect_iproute2_fallback_rule_index,
        patch.auto_redirect_iproute2_fallback_rule_index,
    );
    overwrite_if_present(&mut merged.loopback_address, patch.loopback_address);
    overwrite_if_present(&mut merged.strict_route, patch.strict_route);
    overwrite_if_present(&mut merged.route_address, patch.route_address);
    overwrite_if_present(&mut merged.route_address_set, patch.route_address_set);
    overwrite_if_present(&mut merged.route_exclude_address, patch.route_exclude_address);
    overwrite_if_present(&mut merged.route_exclude_address_set, patch.route_exclude_address_set);
    overwrite_if_present(&mut merged.include_interface, patch.include_interface);
    overwrite_if_present(&mut merged.exclude_interface, patch.exclude_interface);
    overwrite_if_present(&mut merged.include_uid, patch.include_uid);
    overwrite_if_present(&mut merged.include_uid_range, patch.include_uid_range);
    overwrite_if_present(&mut merged.exclude_uid, patch.exclude_uid);
    overwrite_if_present(&mut merged.exclude_uid_range, patch.exclude_uid_range);
    overwrite_if_present(&mut merged.include_android_user, patch.include_android_user);
    overwrite_if_present(&mut merged.include_package, patch.include_package);
    overwrite_if_present(&mut merged.exclude_package, patch.exclude_package);
    overwrite_if_present(&mut merged.include_mac_address, patch.include_mac_address);
    overwrite_if_present(&mut merged.exclude_mac_address, patch.exclude_mac_address);
    overwrite_if_present(&mut merged.endpoint_independent_nat, patch.endpoint_independent_nat);
    overwrite_if_present(&mut merged.udp_timeout, patch.udp_timeout);
    overwrite_if_present(&mut merged.icmp_timeout, patch.icmp_timeout);
    overwrite_if_present(&mut merged.file_descriptor, patch.file_descriptor);
    overwrite_if_present(&mut merged.inet4_route_address, patch.inet4_route_address);
    overwrite_if_present(&mut merged.inet6_route_address, patch.inet6_route_address);
    overwrite_if_present(&mut merged.inet4_route_exclude_address, patch.inet4_route_exclude_address);
    overwrite_if_present(&mut merged.inet6_route_exclude_address, patch.inet6_route_exclude_address);
    overwrite_if_present(&mut merged.recvmsgx, patch.recvmsgx);
    overwrite_if_present(&mut merged.sendmsgx, patch.sendmsgx);
    overwrite_if_present(&mut merged.processors_per_channel, patch.processors_per_channel);
    merged
}

/// The single-field merge rule: a `Some` patch value replaces the stored one, a `None` keeps it.
fn overwrite_if_present<T>(slot: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *slot = value;
    }
}

#[derive(Deserialize, Default)]
struct TuicServerSchema {
    #[serde(default)]
    enable: bool,
    #[cfg(feature = "extra-protocols")]
    listen: Option<String>,
    #[cfg(feature = "extra-protocols")]
    token: Option<Vec<String>>,
    #[cfg(feature = "extra-protocols")]
    users: Option<BTreeMap<String, String>>,
    #[cfg(feature = "extra-protocols")]
    certificate: Option<String>,
    #[cfg(feature = "extra-protocols")]
    #[serde(rename = "private-key")]
    private_key: Option<String>,
    #[cfg(feature = "extra-protocols")]
    #[serde(rename = "congestion-controller")]
    congestion_controller: Option<String>,
    #[cfg(feature = "extra-protocols")]
    #[serde(rename = "max-idle-time")]
    max_idle_time: Option<i32>,
    #[cfg(feature = "extra-protocols")]
    #[serde(rename = "authentication-timeout")]
    authentication_timeout: Option<i32>,
    #[cfg(feature = "extra-protocols")]
    alpn: Option<Vec<String>>,
    #[cfg(feature = "extra-protocols")]
    #[serde(rename = "max-udp-relay-packet-size")]
    max_udp_relay_packet_size: Option<i32>,
    #[cfg(feature = "extra-protocols")]
    cwnd: Option<i32>,
    #[cfg(feature = "extra-protocols")]
    #[serde(rename = "bbr-profile")]
    bbr_profile: Option<String>,
}

#[derive(Deserialize, Default)]
struct ConfigSchema {
    port: Option<i32>,
    #[serde(rename = "socks-port")]
    socks_port: Option<i32>,
    #[serde(rename = "redir-port")]
    redir_port: Option<i32>,
    #[serde(rename = "tproxy-port")]
    tproxy_port: Option<i32>,
    #[serde(rename = "mixed-port")]
    mixed_port: Option<i32>,
    tun: Option<TunSchema>,
    #[serde(rename = "tuic-server")]
    tuic_server: Option<TuicServerSchema>,
    #[serde(rename = "ss-config")]
    shadow_socks_config: Option<String>,
    #[serde(rename = "vmess-config")]
    vmess_config: Option<String>,
    #[serde(rename = "tcptun-config")]
    #[allow(
        dead_code,
        reason = "accepted PATCH /configs JSON field mirroring the tcp tun config; the handler never applies it either, so this is schema-only on both sides"
    )]
    tcptun_config: Option<String>,
    #[serde(rename = "udptun-config")]
    #[allow(
        dead_code,
        reason = "accepted PATCH /configs JSON field mirroring the udp tun config; the handler never applies it either, so this is schema-only on both sides"
    )]
    udptun_config: Option<String>,
    #[serde(rename = "allow-lan")]
    allow_lan: Option<bool>,
    #[serde(rename = "skip-auth-prefixes", default, deserialize_with = "opt_ip_net_vec::deserialize")]
    skip_auth_prefixes: Option<Vec<IpNet>>,
    #[serde(rename = "lan-allowed-ips", default, deserialize_with = "opt_ip_net_vec::deserialize")]
    lan_allowed_ips: Option<Vec<IpNet>>,
    #[serde(rename = "lan-disallowed-ips", default, deserialize_with = "opt_ip_net_vec::deserialize")]
    lan_dis_allowed_ips: Option<Vec<IpNet>>,
    #[serde(rename = "bind-address")]
    bind_address: Option<String>,
    mode: Option<TunnelMode>,
    #[serde(rename = "log-level")]
    log_level: Option<LogLevel>,
    ipv6: Option<bool>,
    sniffing: Option<bool>,
    #[serde(rename = "tcp-concurrent")]
    tcp_concurrent: Option<bool>,
    #[serde(rename = "find-process-mode")]
    find_process_mode: Option<FindProcessMode>,
    #[serde(rename = "interface-name")]
    interface_name: Option<String>,
}

async fn get_configs() -> Response<RespBody> {
    let general = get_general().await;
    json_response(StatusCode::OK, &general_to_api(general))
}

#[cfg(feature = "extra-protocols")]
fn pointer_or_default_tuic_server(p: Option<TuicServerSchema>, mut def: TuicServer) -> TuicServer {
    if let Some(p) = p {
        def.enable = p.enable;
        if let Some(v) = p.listen {
            def.listen = v;
        }
        if let Some(v) = p.token {
            def.token = v;
        }
        if let Some(v) = p.users {
            def.users = v;
        }
        if let Some(v) = p.certificate {
            def.certificate = v;
        }
        if let Some(v) = p.private_key {
            def.private_key = v;
        }
        if let Some(v) = p.congestion_controller {
            def.congestion_controller = v;
        }
        if let Some(v) = p.max_idle_time {
            def.max_idle_time = v;
        }
        if let Some(v) = p.authentication_timeout {
            def.authentication_timeout = v;
        }
        if let Some(v) = p.alpn {
            def.alpn = v;
        }
        if let Some(v) = p.max_udp_relay_packet_size {
            def.max_udp_relay_packet_size = v;
        }
        if let Some(v) = p.cwnd {
            def.cwnd = v;
        }
        if let Some(v) = p.bbr_profile {
            def.bbr_profile = v;
        }
    }
    def
}

///
/// The `tuic-server` merge base is the last stored tuic conf (see [`last_tuic_conf`]), not the
/// freshly read one: the latter reports a zero conf whenever no tuic listener is running,
/// which would drop the fields an earlier PATCH or config load had stored.
///
/// A top-level `null` body is not a valid `ConfigSchema`, so it answers 400 `Body invalid`. An
/// implementation that dereferences the absent result instead would abort the connection with a
/// panic, a failure mode hyper cannot reproduce here.
async fn patch_configs(mut general: ConfigSchema) -> Response<RespBody> {
    #[cfg(not(feature = "extra-protocols"))]
    {
        let unsupported = if general.shadow_socks_config.as_ref().is_some_and(|value| !value.is_empty()) {
            Some("ss-config requires feature extra-protocols")
        } else if general.tuic_server.as_ref().is_some_and(|value| value.enable) {
            Some("tuic-server requires feature extra-protocols")
        } else {
            None
        };
        if let Some(message) = unsupported {
            return json_response(StatusCode::BAD_REQUEST, &HttpError::new(message));
        }
    }
    apply_general_schema(&mut general);

    let ports = get_ports().await;

    let tunnel = tunnel_arc();
    let mut failures = Vec::new();
    for result in [
        re_create_http(general.port.unwrap_or(ports.port), Arc::clone(&tunnel)).await,
        re_create_socks(general.socks_port.unwrap_or(ports.socks_port), Arc::clone(&tunnel)).await,
        re_create_redir(general.redir_port.unwrap_or(ports.redir_port), Arc::clone(&tunnel)).await,
        re_create_tproxy(general.tproxy_port.unwrap_or(ports.tproxy_port), Arc::clone(&tunnel)).await,
        re_create_mixed(general.mixed_port.unwrap_or(ports.mixed_port), Arc::clone(&tunnel)).await,
        #[cfg(feature = "extra-protocols")]
        re_create_shadow_socks(&general.shadow_socks_config.unwrap_or(ports.shadow_socks_config), Arc::clone(&tunnel))
            .await,
        re_create_vmess(&general.vmess_config.unwrap_or(ports.vmess_config), Arc::clone(&tunnel)).await,
        #[cfg(feature = "extra-protocols")]
        re_create_tuic(pointer_or_default_tuic_server(general.tuic_server, last_tuic_conf().await), tunnel).await,
    ] {
        if let Err(err) = result {
            failures.push(err);
        }
    }
    if let Some(tun_patch) = general.tun {
        re_create_tun(merge_tun_schema(&get_tun_conf(), tun_patch), tunnel_arc()).await;
    }
    if !failures.is_empty() {
        // Each listener logged its own bind error; this line says the request left the running
        // configuration incomplete rather than conforming to it.
        let joined = failures.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ");
        errorln!("PATCH /configs left the running configuration incomplete: {joined}");
    }

    if let Some(mode) = general.mode {
        murmur_tunnel::tunnel::set_mode(mode);
    }
    if let Some(mode) = general.find_process_mode {
        murmur_tunnel::tunnel::set_find_process_mode(mode);
    }
    if let Some(level) = general.log_level {
        set_level(level);
    }
    if let Some(ipv6) = general.ipv6 {
        set_disable_ipv6(!ipv6);
    }

    no_content()
}

/// The inbound and general knobs a PATCH sets before the listeners are recreated; each `None` keeps
/// the stored value.
fn apply_general_schema(general: &mut ConfigSchema) {
    if let Some(allow_lan) = general.allow_lan.take() {
        set_allow_lan(allow_lan);
    }
    if let Some(prefixes) = general.skip_auth_prefixes.take() {
        set_skip_auth_prefixes(Some(prefixes));
    }
    if let Some(ips) = general.lan_allowed_ips.take() {
        set_allowed_ips(Some(ips));
    }
    if let Some(ips) = general.lan_dis_allowed_ips.take() {
        set_dis_allowed_ips(Some(ips));
    }
    if let Some(addr) = general.bind_address.take() {
        set_bind_address(&addr);
    }
    if let Some(sniffing) = general.sniffing.take() {
        set_sniffing(sniffing);
    }
    if let Some(concurrent) = general.tcp_concurrent.take() {
        set_tcp_concurrent(concurrent);
    }
    if let Some(name) = general.interface_name.take() {
        DEFAULT_INTERFACE.store(name);
    }
}

/// The `PUT /configs` body: an optional `path` or inline `payload`, both empty meaning "reread the
/// configured file".
#[derive(Deserialize, Default)]
struct UpdateConfigsRequest {
    #[serde(default)]
    path: String,
    #[serde(default)]
    payload: String,
}

async fn update_configs(force: bool, mut request: UpdateConfigsRequest) -> Response<RespBody> {
    let cfg: Config = if request.payload.is_empty() {
        if request.path.is_empty() {
            request.path = PATH.config();
        } else {
            if !StdPath::new(&request.path).is_absolute() {
                return json_response(StatusCode::BAD_REQUEST, &HttpError::new("path is not a absolute path"));
            }
            if !PATH.is_safe_path(&request.path) {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &HttpError::new(PATH.err_not_safe_path(&request.path).to_string()),
                );
            }
        }

        match parse_with_path(&request.path).await {
            Ok(cfg) => cfg,
            Err(err) => return json_response(StatusCode::BAD_REQUEST, &HttpError::new(err.to_string())),
        }
    } else {
        match parse_with_bytes(request.payload.as_bytes()).await {
            Ok(cfg) => cfg,
            Err(err) => return json_response(StatusCode::BAD_REQUEST, &HttpError::new(err.to_string())),
        }
    };

    if let Err(err) = apply_config(cfg, force).await {
        // The request still carries the configuration it was given; this says the running state
        // does not match it yet, which a 204 alone would hide.
        errorln!("PUT /configs left the running configuration incomplete: {err}");
    }
    no_content()
}

/// The `force` parameter is decoded like every other query parameter, and an
/// escaped value therefore has to decode before the comparison. The `apply_config` this feeds is
/// what no in-process test can run.
fn force_requested(query: &str) -> bool {
    query_param(query, "force").as_deref() == Some("true")
}

/// Shared with `upgrade.rs`'s `/upgrade/geo`.
pub(crate) async fn update_geo_databases() -> Response<RespBody> {
    if let Err(err) = update_geo_databases_guarded().await {
        errorln!("[GEO] update GEO databases failed: {}", err);
        return json_response(StatusCode::INTERNAL_SERVER_ERROR, &HttpError::new(err.to_string()));
    }
    no_content()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "extra-protocols"))]
    #[tokio::test]
    async fn patch_rejects_removed_listeners_before_mutating_general_state() {
        let _tunnel_state = TUNNEL_STATE_LOCK.lock().await;
        let original = murmur_tunnel::tunnel::mode();
        for body in [
            br#"{"mode":"direct","ss-config":"ss://example"}"#.as_slice(),
            br#"{"mode":"direct","tuic-server":{"enable":true}}"#.as_slice(),
        ] {
            let (status, body) = patch_configs_over_http(body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(String::from_utf8_lossy(&body).contains("extra-protocols"));
            assert_eq!(murmur_tunnel::tunnel::mode(), original);
        }
    }

    #[cfg(not(feature = "extra-protocols"))]
    #[tokio::test]
    async fn put_rejects_removed_configuration_without_replacing_active_state() {
        crate::test_support::with_tunnel_state_lock(async {
            let original = murmur_tunnel::tunnel::proxies();
            let original_mode = murmur_tunnel::tunnel::mode();
            for payload in [
                "mode: direct\nproxies:\n  - {name: removed, type: ss}\n",
                "mode: direct\nlisteners:\n  - {name: removed, type: tuic, port: 1080}\n",
                "mode: direct\nss-config: ss://example\n",
                "mode: direct\ntuic-server:\n  enable: true\n",
            ] {
                let response =
                    update_configs(true, UpdateConfigsRequest { payload: payload.to_owned(), ..Default::default() })
                        .await;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert_eq!(murmur_tunnel::tunnel::mode(), original_mode);
                let current = murmur_tunnel::tunnel::proxies();
                assert_eq!(current.len(), original.len());
                for (name, proxy) in &original {
                    assert!(Arc::ptr_eq(current.get(name).expect("active proxy remains"), proxy));
                }
            }
        })
        .await;
    }
    use crate::test_support::TUNNEL_STATE_LOCK;
    use murmur_component_process::find_process_mode::FindProcessMode;
    use murmur_config::config::{General, Inbound};
    #[cfg(feature = "extra-protocols")]
    use murmur_listener::listener::get_tuic_conf;
    use murmur_listener::listener::set_tun_conf;
    #[cfg(feature = "extra-protocols")]
    use murmur_listener_config::tuic::TuicServer;
    use murmur_listener_config::tun::Tun;
    use murmur_log::LogLevel;

    fn default_tun_for_test() -> Tun {
        Tun {
            dns_hijack: Some(vec!["0.0.0.0:53".to_owned()]),
            auto_route: true,
            auto_detect_interface: true,
            recvmsgx: true,
            processors_per_channel: 1,
            inet4_address: vec!["198.18.0.1/30".parse().expect("valid literal")],
            ..Default::default()
        }
    }

    fn full_general() -> General {
        general_with_auth_fields(None, None)
    }

    /// Like `full_general`, but with `skip-auth-prefixes`/`lan-disallowed-ips` set explicitly
    /// (null-vs-empty-slice distinction: `None` is absent, `Some(vec![])` is `[]`).
    fn general_with_auth_fields(
        skip_auth_prefixes: Option<Vec<IpNet>>,
        lan_dis_allowed_ips: Option<Vec<IpNet>>,
    ) -> General {
        General {
            inbound: Inbound {
                port: 7890,
                socks_port: 7891,
                redir_port: 0,
                tproxy_port: 0,
                mixed_port: 0,
                #[cfg(feature = "extra-protocols")]
                tuic_server: TuicServer::default(),
                tun: default_tun_for_test(),
                #[cfg(feature = "extra-protocols")]
                shadow_socks_config: String::new(),
                vmess_config: String::new(),
                authentication: Vec::new(),
                skip_auth_prefixes,
                lan_allowed_ips: Some(Vec::new()),
                lan_dis_allowed_ips,
                allow_lan: false,
                bind_address: "*".to_owned(),
                inbound_tfo: false,
                inbound_mptcp: false,
            },
            mode: TunnelMode::RULE,
            unified_delay: false,
            log_level: LogLevel::INFO,
            ipv6: false,
            interface: String::new(),
            routing_mark: 0,
            geo_x_url: GeoXUrl::default(),
            geo_auto_update: false,
            geo_update_interval: 24,
            geodata_mode: false,
            geodata_loader: String::new(),
            geosite_matcher: String::new(),
            tcp_concurrent: false,
            find_process_mode: FindProcessMode::FIND_PROCESS_STRICT,
            sniffing: false,
            global_ua: String::new(),
            etag_support: false,
            keep_alive_idle: 15,
            keep_alive_interval: 15,
            disable_keep_alive: false,
        }
    }

    /// The `json` field names of the general/inbound config, including `tun`: a `/configs`
    /// response always has a `"tun"` key, produced here by `tun_for_api`.
    const EXPECTED_KEYS: &[&str] = &[
        "port",
        "socks-port",
        "redir-port",
        "tproxy-port",
        "mixed-port",
        "tun",
        #[cfg(feature = "extra-protocols")]
        "tuic-server",
        #[cfg(feature = "extra-protocols")]
        "ss-config",
        "vmess-config",
        "authentication",
        "skip-auth-prefixes",
        "lan-allowed-ips",
        "lan-disallowed-ips",
        "allow-lan",
        "bind-address",
        "inbound-tfo",
        "inbound-mptcp",
        "mode",
        "unified-delay",
        "log-level",
        "ipv6",
        "interface-name",
        "routing-mark",
        "geox-url",
        "geo-auto-update",
        "geo-update-interval",
        "geodata-mode",
        "geodata-loader",
        "geosite-matcher",
        "tcp-concurrent",
        "find-process-mode",
        "sniffing",
        "global-ua",
        "etag-support",
        "keep-alive-idle",
        "keep-alive-interval",
        "disable-keep-alive",
    ];

    #[test]
    fn general_for_api_key_set_is_the_json_field_names() {
        let json = serde_json::to_value(general_to_api(full_general())).expect("GeneralForApi serializes");
        let object = json.as_object().expect("GeneralForApi serializes to a JSON object");

        let mut actual: Vec<&str> = object.keys().map(String::as_str).collect();
        actual.sort_unstable();
        let mut expected: Vec<&str> = EXPECTED_KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(actual, expected);
    }

    #[test]
    fn general_for_api_value_types_are_stable() {
        let json = serde_json::to_value(general_to_api(full_general())).expect("GeneralForApi serializes");
        assert!(json["port"].is_number());
        assert!(json["allow-lan"].is_boolean());
        #[cfg(feature = "extra-protocols")]
        assert!(json["tuic-server"].is_object());
        #[cfg(not(feature = "extra-protocols"))]
        assert!(json.get("tuic-server").is_none());
        assert!(json["geox-url"].is_object());
        assert!(json["mode"].is_string());
        assert!(json["log-level"].is_string());
        assert!(json["find-process-mode"].is_string());
    }

    /// A default config with no configured authenticator, `skip-auth-prefixes` or
    /// `lan-disallowed-ips`: all three serialize as `null`, not `[]`, because no authenticator is
    /// configured and the two inbound lists are absent.
    #[test]
    fn general_for_api_absent_auth_fields_serialize_as_null() {
        let json = serde_json::to_value(general_to_api(full_general())).expect("GeneralForApi serializes");
        assert!(json["authentication"].is_null(), "{:?}", json["authentication"]);
        assert!(json["skip-auth-prefixes"].is_null(), "{:?}", json["skip-auth-prefixes"]);
        assert!(json["lan-disallowed-ips"].is_null(), "{:?}", json["lan-disallowed-ips"]);
        assert!(json["lan-allowed-ips"].is_array());
    }

    /// null-vs-empty-slice distinction the other way: `skip-auth-prefixes: []` and
    /// `lan-disallowed-ips: []` in YAML decode to present empty slices (the YAML library gives a
    /// concrete empty list, not an absent one), and the inbound setters store that as-is, so
    /// `/configs` renders `[]`, not `null`.
    #[test]
    fn general_for_api_explicit_empty_auth_fields_serialize_as_empty_arrays() {
        let general = general_with_auth_fields(Some(Vec::new()), Some(Vec::new()));
        let json = serde_json::to_value(general_to_api(general)).expect("GeneralForApi serializes");
        assert_eq!(json["skip-auth-prefixes"], serde_json::json!([]));
        assert_eq!(json["lan-disallowed-ips"], serde_json::json!([]));
    }

    /// PATCH's `TunSchema` decodes named sub-fields directly, matching the schema's pointer
    /// fields.
    #[test]
    fn tun_schema_decodes_named_sub_fields() {
        let schema: TunSchema =
            serde_json::from_str(r#"{"enable":false,"stack":"system","device":"utun9","mtu":9000}"#)
                .expect("TunSchema decodes");
        assert!(!schema.enable);
        assert_eq!(schema.stack, Some(murmur_constant::tun::TunStack::System));
        assert_eq!(schema.device, Some("utun9".to_owned()));
        assert_eq!(schema.mtu, Some(9000));
    }

    /// A PATCH naming only `device` leaves every other field at its current stored value.
    #[test]
    fn merge_tun_schema_overrides_only_named_fields() {
        let current = default_tun_for_test();
        let schema: TunSchema =
            serde_json::from_str(r#"{"enable":false,"device":"utun9"}"#).expect("TunSchema decodes");
        let merged = merge_tun_schema(&current, schema);
        assert_eq!(merged.device, "utun9");
        assert_eq!(merged.dns_hijack, current.dns_hijack);
        assert_eq!(merged.auto_route, current.auto_route);
    }

    /// A `"tun"` key is always emitted; a default config with no `tun:` section renders
    /// `enable: false` plus the default `tun:` values.
    #[test]
    fn general_for_api_renders_a_tun_object_for_a_default_config() {
        let json = serde_json::to_value(general_to_api(full_general())).expect("GeneralForApi serializes");
        let tun = &json["tun"];
        assert_eq!(tun["enable"], false);
        assert_eq!(tun["device"], "");
        assert_eq!(tun["stack"], "gVisor");
        assert_eq!(tun["dns-hijack"], serde_json::json!(["0.0.0.0:53"]));
        assert_eq!(tun["auto-route"], true);
        assert_eq!(tun["auto-detect-interface"], true);
        assert!(tun["inet4-address"].is_array());
        assert_eq!(tun["file-descriptor"], 0);
        assert_eq!(tun["recvmsgx"], true);
        assert_eq!(tun["processors-per-channel"], 1);
    }

    /// PATCH's `TunSchema` has no exclude-src-port or exclude-src-port-range field and no
    /// exclude-dst-port or exclude-dst-port-range field and no disable-icmp-forwarding field, so a
    /// PATCH naming those keys is silently ignored (serde tolerates unknown fields by default) and
    /// never reaches the merge; the file-descriptor key is present and does apply. `TunSchema`
    /// mirrors that exact field set, with no unknown-field rejection, rather than the full `RawTun`.
    #[test]
    fn tun_schema_ignores_fields_it_lacks_but_applies_file_descriptor() {
        let current = default_tun_for_test();
        let schema: TunSchema = serde_json::from_str(
            r#"{"file-descriptor":7,"disable-icmp-forwarding":true,"exclude-src-port":[22],
                "exclude-src-port-range":["1:2"],"exclude-dst-port":[80],"exclude-dst-port-range":["3:4"]}"#,
        )
        .expect("TunSchema decodes, silently dropping the unrecognized keys");
        let merged = merge_tun_schema(&current, schema);
        assert_eq!(merged.file_descriptor, 7);
        assert_eq!(merged.disable_icmp_forwarding, current.disable_icmp_forwarding);
        assert_eq!(merged.exclude_src_port, current.exclude_src_port);
        assert_eq!(merged.exclude_src_port_range, current.exclude_src_port_range);
        assert_eq!(merged.exclude_dst_port, current.exclude_dst_port);
        assert_eq!(merged.exclude_dst_port_range, current.exclude_dst_port_range);
    }

    /// A valid IPv6 `loopback-address` PATCH is accepted and rendered.
    #[test]
    fn patch_configs_accepts_and_renders_an_ipv6_loopback_address() {
        let current = default_tun_for_test();
        let schema: TunSchema =
            serde_json::from_str(r#"{"loopback-address":["fe80::1"]}"#).expect("TunSchema decodes an IPv6 address");
        let mut merged = merge_tun_schema(&current, schema);
        merged.sort();
        let rendered: Vec<String> = merged.loopback_address.iter().map(ToString::to_string).collect();
        assert_eq!(rendered, ["fe80::1"]);
    }

    /// An unparseable `loopback-address` PATCH is rejected.
    #[test]
    fn patch_configs_rejects_an_unparseable_loopback_address() {
        let err = serde_json::from_str::<TunSchema>(r#"{"loopback-address":["bogus"]}"#).err().unwrap();
        assert!(err.to_string().contains("invalid IP address syntax"));
    }

    /// A mixed-prefix-length `route-address` PATCH is sorted into prefix order after the merge.
    #[test]
    fn patch_configs_sorts_route_address_after_merge() {
        let current = default_tun_for_test();
        let schema: TunSchema =
            serde_json::from_str(r#"{"route-address":["10.0.0.0/8","1.0.0.0/16","fd00::/8","::/0"]}"#)
                .expect("TunSchema decodes route-address");
        let mut merged = merge_tun_schema(&current, schema);
        merged.sort();
        let rendered: Vec<String> = merged.route_address.iter().map(ToString::to_string).collect();
        assert_eq!(rendered, ["10.0.0.0/8", "1.0.0.0/16", "::/0", "fd00::/8"]);
    }

    /// The `force` query value is read from the URL, so an escaped value must decode before the
    /// `"true"` comparison.
    #[test]
    fn update_configs_decodes_an_escaped_force_query_value() {
        assert!(force_requested("force=%74rue"), "`%74rue` decodes to `true`");
        assert!(force_requested("force=true"));
        assert!(!force_requested("force=%66alse"), "`%66alse` decodes to `false`");
        assert!(!force_requested("force=1"));
        assert!(!force_requested("other=true"));
        assert!(!force_requested(""));
    }

    /// Puts `MODE` and `LAST_TUN_CONF` back on drop, so a panicking assertion cannot leak them
    /// into whichever test runs next.
    struct TunnelStateGuard {
        mode: TunnelMode,
        tun: Tun,
    }

    impl TunnelStateGuard {
        fn save() -> Self {
            Self { mode: murmur_tunnel::tunnel::mode(), tun: get_tun_conf() }
        }
    }

    impl Drop for TunnelStateGuard {
        fn drop(&mut self) {
            murmur_tunnel::tunnel::set_mode(self.mode);
            set_tun_conf(self.tun.clone());
        }
    }

    /// Drives `patch_configs` over a real HTTP/1.1 connection (not a hand-built `Req`, which
    /// `hyper::body::Incoming` cannot be) so the request body goes through hyper's own framing
    /// exactly like the live server.
    async fn patch_configs_over_http(body: &[u8]) -> (StatusCode, Vec<u8>) {
        use std::convert::Infallible;

        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener has a local address");
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept loopback connection");
            let svc = service_fn(|req: Req| async move {
                // The route decodes before taking the config lock; mirror that order here.
                let general = crate::route::common::decode_json_body::<ConfigSchema, _>(req.into_body())
                    .await
                    .expect("the test body is valid JSON");
                Ok::<_, Infallible>(patch_configs(general).await)
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(conn), svc).await;
        });

        let mut stream = TcpStream::connect(addr).await.expect("connect to loopback listener");
        let request = format!(
            "PATCH /configs/ HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.expect("write request head");
        stream.write_all(body).await.expect("write request body");

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");

        let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("response has a header/body split");
        let head = std::str::from_utf8(&raw[..head_end]).expect("response head is ascii");
        let status_str = head.split_whitespace().nth(1).expect("status line has a code");
        let status = StatusCode::from_bytes(status_str.as_bytes()).expect("valid status code");
        (status, raw[head_end + 4..].to_vec())
    }

    /// An enabled `tun:` PATCH is answered 204 and handed to `re_create_tun` with the named fields
    /// merged onto the stored conf. `stack: system` is one the device refuses by name, so `enable`
    /// comes back cleared - the same non-fatal degradation the listener performs, and the proof
    /// that the conf reached the listener
    /// factory rather than the PATCH being dropped.
    #[tokio::test(flavor = "multi_thread")]
    async fn patch_configs_hands_enabled_tun_to_re_create_tun() {
        let _tunnel_state = TUNNEL_STATE_LOCK.lock().await;
        let _restore = TunnelStateGuard::save();
        let (status, body) =
            patch_configs_over_http(br#"{"tun":{"enable":true,"stack":"system","device":"utun9","mtu":9000}}"#).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "body: {}", String::from_utf8_lossy(&body));

        let stored = get_tun_conf();
        assert!(!stored.enable, "a refused device must leave enable cleared, as the ReCreateTun does");
        assert_eq!(stored.device, "utun9");
        assert_eq!(stored.stack, murmur_constant::tun::TunStack::System);
        assert_eq!(stored.mtu, 9000);
    }

    /// A PATCH that only disables the section stores that, and never reaches the device: the
    /// listener is closed and the call returns, since the tun is disabled.
    #[tokio::test(flavor = "multi_thread")]
    async fn patch_configs_stores_disabled_tun_without_touching_the_device() {
        let _tunnel_state = TUNNEL_STATE_LOCK.lock().await;
        let _restore = TunnelStateGuard::save();
        let (status, body) = patch_configs_over_http(br#"{"tun":{"enable":false,"device":"utun10"}}"#).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "body: {}", String::from_utf8_lossy(&body));

        let stored = get_tun_conf();
        assert!(!stored.enable);
        assert_eq!(stored.device, "utun10");
    }

    #[cfg(feature = "extra-protocols")]
    /// The merge base is the conf the last tuic-listener recreation stored, which survives a
    /// listener that is not running. Merging onto the freshly read conf instead would drop
    /// `listen` and `certificate` here, and a `tuic-server` object that omits `enable` has to
    /// decode as `false` (the bare `enable` bool), not fail the whole body.
    #[tokio::test(flavor = "multi_thread")]
    async fn patch_configs_merges_tuic_server_onto_last_stored_conf() {
        let _tunnel_state = TUNNEL_STATE_LOCK.lock().await;
        let _restore = TunnelStateGuard::save();
        // The listener may or may not bind in the test process; what the test reads back is the
        // conf this call stores, which is stored either way.
        let _ = re_create_tuic(
            TuicServer { listen: ":10443".to_owned(), certificate: "example.crt".to_owned(), ..TuicServer::default() },
            tunnel_arc(),
        )
        .await;

        assert_eq!(get_tuic_conf().await.listen, "", "no listener is running, so GetTuicConf is the zero conf");

        let (status, body) = patch_configs_over_http(br#"{"tuic-server":{"max-idle-time":90000}}"#).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "body: {}", String::from_utf8_lossy(&body));

        let stored = last_tuic_conf().await;
        assert_eq!(stored.listen, ":10443");
        assert_eq!(stored.certificate, "example.crt");
        assert_eq!(stored.max_idle_time, 90000);
        assert!(!stored.enable);
    }

    /// The representative PATCH row, at the handler: a mode change, a `tun` patch and an unknown
    /// top-level key in one body. The unknown key is dropped, the mode is applied, the named
    /// `tun` fields are merged onto the stored conf, and the response is 204 with no body.
    #[tokio::test(flavor = "multi_thread")]
    async fn patch_configs_applies_mode_and_tun_and_ignores_an_unknown_key() {
        let _tunnel_state = TUNNEL_STATE_LOCK.lock().await;
        let _restore = TunnelStateGuard::save();
        let (status, body) = patch_configs_over_http(
            br#"{"mode":"direct","tun":{"enable":false,"device":"metatun","mtu":1400},"not-a-field":123}"#,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "body: {}", String::from_utf8_lossy(&body));
        assert!(body.is_empty(), "the render.NoContent writes no body: {:?}", String::from_utf8_lossy(&body));

        assert_eq!(murmur_tunnel::tunnel::mode(), TunnelMode::DIRECT);
        let stored = get_tun_conf();
        assert!(!stored.enable);
        assert_eq!(stored.device, "metatun");
        assert_eq!(stored.mtu, 1400);
    }

    /// A stalled request body must not hold the process-wide configuration lock: the route decodes
    /// before taking it, so a client that stops mid-body cannot block watched reloads or SIGHUPs.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_request_body_does_not_hold_the_config_lock() {
        use std::convert::Infallible;

        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use tokio::io::AsyncWriteExt as _;
        use tokio::net::{TcpListener, TcpStream};

        // Serialise with the reload tests, which hold the same lock through `hub::parse`.
        let _listeners = crate::route::server::CONTROLLER_LISTENERS.lock().await;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener has a local address");
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.expect("accept loopback connection");
            let svc = service_fn(|req: Req| async move {
                Ok::<_, Infallible>(route(req, &[]).await.unwrap_or_else(|| status_only(StatusCode::NOT_FOUND)))
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(conn), svc).await;
        });

        let mut stream = TcpStream::connect(addr).await.expect("connect to loopback listener");
        // A complete head and a body that declares more than it sends: the handler waits in the
        // decoder, which runs before the lock is taken.
        stream
            .write_all(
                b"PATCH /configs HTTP/1.1\r\nHost: test\r\nContent-Length: 64\r\nConnection: close\r\n\r\n{\"tun\":",
            )
            .await
            .expect("write the partial request");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(500), crate::hub::lock_config_operation())
                .await
                .is_ok(),
            "a stalled request body must not hold the config lock"
        );
    }
}

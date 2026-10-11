//! DEVIATION: none of the `listener::inbound` option structs derive `serde::Deserialize`.
//!
//! They only derive `Serialize`, for `option_to_string`/`Equal`. Following the precedent already set by
//! `adapter/parser.rs` for the analogous gap in `adapter/outbound`, every branch below decodes into
//! a local DTO (`#[serde(rename = "...")]` mirroring the `inbound:"..."` tag exactly, container
//! `#[serde(default)]` mirroring mapstructure's "absent key keeps the zero value" behaviour) and
//! copies the result field by field into the real option struct before calling its `New`.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;
use serde_yaml::{Mapping, Value};

use crate::inbound::anytls::{AnyTLS, AnyTLSOption};
use crate::inbound::auth::AuthUser;
use crate::inbound::base::BaseOption;
use crate::inbound::http::{HTTPOption, HTTP};
use crate::inbound::hysteria2::{Hysteria2, Hysteria2Option, Hysteria2RealmOption};
use crate::inbound::hysteria2_realm::{Hysteria2RealmServer, Hysteria2RealmServerOption};
use crate::inbound::jls::{JLSConfig, JLSUser};
use crate::inbound::kcptun::KcpTun;
use crate::inbound::mekya::MekyaConfig;
use crate::inbound::mieru::{Mieru, MieruOption};
use crate::inbound::mixed::{Mixed, MixedOption};
use crate::inbound::mkcp::MKCPConfig;
use crate::inbound::mux::{BrutalOptions, MuxOption};
use crate::inbound::redir::{Redir, RedirOption};
use crate::inbound::restls::ResTLS;
use crate::inbound::shadowquic::{ShadowQuic, ShadowQuicJLSUpstream, ShadowQuicOption, ShadowQuicUser};
use crate::inbound::shadowsocks::{ShadowSocks, ShadowSocksOption, SimpleObfs};
use crate::inbound::shadowtls::{ShadowTLS, ShadowTLSHandshakeOptions, ShadowTLSUser};
use crate::inbound::snell::{Snell, SnellObfsOption, SnellOption};
use crate::inbound::socks::{Socks, SocksOption};
use crate::inbound::sudoku::{Sudoku, SudokuHTTPMaskOptions, SudokuOption};
use crate::inbound::tlsmirror::{
    TLSMirrorConfig, TLSMirrorConnectionEnrolment, TLSMirrorTimeSpec, TLSMirrorTransportLayerPadding,
};
use crate::inbound::tproxy::{TProxy, TProxyOption};
use crate::inbound::trojan::{Trojan, TrojanOption, TrojanSSOption, TrojanUser};
use crate::inbound::trusttunnel::{TrustTunnel, TrustTunnelOption};
use crate::inbound::tuic::{Tuic, TuicOption};
use crate::inbound::tun::{Tun, TunOption};
use crate::inbound::tunnel::{Tunnel as TunnelInbound, TunnelOption};
use crate::inbound::vless::{Vless, VlessOption, VlessUser, XHTTPConfig};
use crate::inbound::vmess::{Vmess, VmessOption, VmessUser};
use murmur_common::structure::structure::{new_decoder, Decoder, Option as StructureOption, DEFAULT_KEY_REPLACER};
use murmur_constant::listener::InboundListener;
use murmur_listener_config::reality::{RealityConfig, RealityLimitFallback};

const fn default_true() -> bool {
    true
}

fn default_h3_alpn() -> Vec<String> {
    vec!["h3".to_owned()]
}

fn default_bbr() -> String {
    "bbr".to_owned()
}

const fn default_tuic_max_idle_time() -> i32 {
    15000
}

const fn default_tuic_authentication_timeout() -> i32 {
    1000
}

const fn default_tuic_max_udp_relay_packet_size() -> i32 {
    1500
}

const fn default_shadowquic_max_idle_time() -> i32 {
    30000
}

const fn default_shadowquic_max_datagram_frame_size() -> i32 {
    1400
}

/// The default maximum realm count.
const fn default_realm_max_realms() -> i32 {
    crate::hysteria2_realm::server::DEFAULT_MAX_REALMS
}

/// The default maximum realms per client IP.
const fn default_realm_max_realms_per_ip() -> i32 {
    crate::hysteria2_realm::server::DEFAULT_MAX_REALMS_PER_IP
}

/// The default realm-name pattern.
fn default_realm_name_pattern() -> String {
    crate::hysteria2_realm::session::DEFAULT_REALM_NAME_PATTERN.to_owned()
}

/// The default realm ALPN.
fn default_realm_alpn() -> Vec<String> {
    crate::hysteria2_realm::server::default_alpn()
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
struct BaseOptionDto {
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "listen")]
    listen: String,
    #[serde(rename = "port")]
    port: String,
    #[serde(rename = "rule")]
    rule: String,
    #[serde(rename = "proxy")]
    proxy: String,
    #[serde(rename = "routing-mark")]
    routing_mark: i32,
}

fn build_base(dto: BaseOptionDto) -> BaseOption {
    BaseOption {
        name_str: dto.name,
        listen: dto.listen,
        port: dto.port,
        special_rules: dto.rule,
        special_proxy: dto.proxy,
        routing_mark: dto.routing_mark,
        listen_config_for_api: None,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AuthUserDto {
    #[serde(rename = "username")]
    username: String,
    #[serde(rename = "password")]
    password: String,
}

fn build_auth_user_list(users: Vec<AuthUserDto>) -> Vec<AuthUser> {
    users.into_iter().map(|u| AuthUser { username: u.username, password: u.password }).collect()
}

/// `RealityConfig` merged with `Config`: this DTO decodes straight to the fully-parsed shape (`private-key` base64, `short-id`
/// hex) since there is no tunnel-dependent step left to defer to listen-time (see
/// `murmur_listener_config::reality::RealityConfig`'s module doc).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RealityConfigDto {
    #[serde(rename = "dest")]
    dest: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "short-id")]
    short_id: Vec<String>,
    #[serde(rename = "server-names")]
    server_names: Vec<String>,
    #[serde(rename = "max-time-difference")]
    max_time_difference: i32,
    #[serde(rename = "proxy")]
    proxy: String,
    #[serde(rename = "limit-fallback-upload")]
    limit_fallback_upload: RealityLimitFallbackDto,
    #[serde(rename = "limit-fallback-download")]
    limit_fallback_download: RealityLimitFallbackDto,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RealityLimitFallbackDto {
    #[serde(rename = "after-bytes")]
    after_bytes: u64,
    #[serde(rename = "bytes-per-sec")]
    bytes_per_sec: u64,
    #[serde(rename = "burst-bytes-per-sec")]
    burst_bytes_per_sec: u64,
}

fn build_reality_limit_fallback(dto: &RealityLimitFallbackDto) -> RealityLimitFallback {
    RealityLimitFallback {
        after_bytes: dto.after_bytes,
        bytes_per_sec: dto.bytes_per_sec,
        burst_bytes_per_sec: dto.burst_bytes_per_sec,
    }
}

/// The decode/validation half of the REALITY config build (everything
/// but the tunnel-dependent dial context, built instead by each listener's own
/// server-construction code at listen-time). `Ok(None)` is returned when the private key is empty.
fn build_reality_config(dto: &RealityConfigDto) -> Result<Option<RealityConfig>> {
    if dto.private_key.is_empty() {
        return Ok(None);
    }
    let decoded = URL_SAFE_NO_PAD.decode(&dto.private_key).map_err(|err| anyhow!("decode private key: {err}"))?;
    let private_key: [u8; 32] = decoded.try_into().map_err(|_| anyhow!("invalid private key"))?;

    let mut short_ids = HashSet::with_capacity(dto.short_id.len());
    for (i, short_id_string) in dto.short_id.iter().enumerate() {
        if short_id_string.len() > murmur_reality::MAX_SHORT_ID_LEN * 2 {
            return Err(anyhow!("invalid short_id[{i}]: {short_id_string}"));
        }
        let decoded_short_id =
            hex::decode(short_id_string).map_err(|err| anyhow!("decode short_id[{i}] '{short_id_string}': {err}"))?;
        if decoded_short_id.len() > murmur_reality::MAX_SHORT_ID_LEN {
            return Err(anyhow!("invalid short_id[{i}]: {short_id_string}"));
        }
        let mut short_id = [0u8; murmur_reality::MAX_SHORT_ID_LEN];
        let Some(prefix) = short_id.get_mut(..decoded_short_id.len()) else {
            return Err(anyhow!("invalid short_id[{i}]: {short_id_string}"));
        };
        prefix.copy_from_slice(&decoded_short_id);
        short_ids.insert(short_id);
    }

    Ok(Some(RealityConfig {
        dest: dto.dest.clone(),
        private_key,
        server_names: dto.server_names.iter().cloned().collect(),
        short_ids,
        max_time_diff: (dto.max_time_difference != 0)
            .then(|| Duration::from_micros(u64::try_from(dto.max_time_difference).unwrap_or_default())),
        proxy: dto.proxy.clone(),
        limit_fallback_upload: build_reality_limit_fallback(&dto.limit_fallback_upload),
        limit_fallback_download: build_reality_limit_fallback(&dto.limit_fallback_download),
    }))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BrutalOptionsDto {
    #[serde(rename = "enabled")]
    enabled: bool,
    #[serde(rename = "up")]
    up: String,
    #[serde(rename = "down")]
    down: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct MuxOptionDto {
    #[serde(rename = "padding")]
    padding: bool,
    #[serde(rename = "brutal")]
    brutal: BrutalOptionsDto,
}

fn build_mux_option(dto: MuxOptionDto) -> MuxOption {
    MuxOption {
        padding: dto.padding,
        brutal: BrutalOptions { enabled: dto.brutal.enabled, up: dto.brutal.up, down: dto.brutal.down },
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ShadowTLSHandshakeOptionsDto {
    #[serde(rename = "dest")]
    dest: String,
    #[serde(rename = "proxy")]
    proxy: String,
}

fn build_shadow_tls_handshake(dto: ShadowTLSHandshakeOptionsDto) -> ShadowTLSHandshakeOptions {
    ShadowTLSHandshakeOptions { dest: dto.dest, proxy: dto.proxy }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ShadowTLSDto {
    #[serde(rename = "enable")]
    enable: bool,
    #[serde(rename = "version")]
    version: i32,
    #[serde(rename = "password")]
    password: String,
    #[serde(rename = "handshake")]
    handshake: ShadowTLSHandshakeOptionsDto,
    #[serde(rename = "handshake-for-server-name")]
    handshake_for_server_name: BTreeMap<String, ShadowTLSHandshakeOptionsDto>,
    #[serde(rename = "users")]
    users: Vec<ShadowTLSUserDto>,
    #[serde(rename = "strict-mode")]
    strict_mode: bool,
    #[serde(rename = "wildcard-sni")]
    wildcard_sni: String,
}

fn build_shadow_tls(dto: ShadowTLSDto) -> ShadowTLS {
    ShadowTLS {
        enable: dto.enable,
        version: dto.version,
        password: dto.password,
        handshake: build_shadow_tls_handshake(dto.handshake),
        handshake_for_server_name: dto
            .handshake_for_server_name
            .into_iter()
            .map(|(k, v)| (k, build_shadow_tls_handshake(v)))
            .collect(),
        users: dto.users.into_iter().map(build_shadow_tls_user).collect(),
        strict_mode: dto.strict_mode,
        wildcard_sni: dto.wildcard_sni,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ShadowTLSUserDto {
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "password")]
    password: String,
}

fn build_shadow_tls_user(dto: ShadowTLSUserDto) -> ShadowTLSUser {
    ShadowTLSUser { name: dto.name, password: dto.password }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ResTLSDto {
    #[serde(rename = "enable")]
    enable: bool,
    #[serde(rename = "dest")]
    dest: String,
    #[serde(rename = "password")]
    password: String,
    #[serde(rename = "restls-script")]
    restls_script: String,
    #[serde(rename = "min-record-len")]
    min_record_len: i32,
    #[serde(rename = "rate-limit")]
    rate_limit: u64,
    #[serde(rename = "proxy")]
    proxy: String,
}

fn build_res_tls(dto: ResTLSDto) -> ResTLS {
    ResTLS {
        enable: dto.enable,
        dest: dto.dest,
        password: dto.password,
        restls_script: dto.restls_script,
        min_record_len: dto.min_record_len,
        rate_limit: dto.rate_limit,
        proxy: dto.proxy,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct JLSUserDto {
    #[serde(rename = "username")]
    username: String,
    #[serde(rename = "password")]
    password: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct JLSConfigDto {
    #[serde(rename = "enable")]
    enable: bool,
    #[serde(rename = "users")]
    users: Vec<JLSUserDto>,
    #[serde(rename = "sni")]
    sni: String,
    #[serde(rename = "dest")]
    dest: String,
    #[serde(rename = "alpn")]
    alpn: Option<Vec<String>>,
    #[serde(rename = "proxy")]
    proxy: String,
    #[serde(rename = "rate-limit")]
    rate_limit: u64,
}

fn build_jls_config(dto: JLSConfigDto) -> JLSConfig {
    JLSConfig {
        enable: dto.enable,
        users: dto.users.into_iter().map(|u| JLSUser { username: u.username, password: u.password }).collect(),
        sni: dto.sni,
        dest: dto.dest,
        alpn: dto.alpn,
        proxy: dto.proxy,
        rate_limit: dto.rate_limit,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct KcpTunDto {
    #[serde(rename = "enable")]
    enable: bool,
    #[serde(rename = "key")]
    key: String,
    #[serde(rename = "crypt")]
    crypt: String,
    #[serde(rename = "mode")]
    mode: String,
    #[serde(rename = "conn")]
    conn: i32,
    #[serde(rename = "autoexpire")]
    auto_expire: i32,
    #[serde(rename = "scavengettl")]
    scavenge_ttl: i32,
    #[serde(rename = "mtu")]
    mtu: i32,
    #[serde(rename = "ratelimit")]
    rate_limit: i32,
    #[serde(rename = "sndwnd")]
    snd_wnd: i32,
    #[serde(rename = "rcvwnd")]
    rcv_wnd: i32,
    #[serde(rename = "datashard")]
    data_shard: i32,
    #[serde(rename = "parityshard")]
    parity_shard: i32,
    #[serde(rename = "dscp")]
    dscp: i32,
    #[serde(rename = "nocomp")]
    no_comp: bool,
    #[serde(rename = "acknodelay")]
    ack_nodelay: bool,
    #[serde(rename = "nodelay")]
    no_delay: i32,
    #[serde(rename = "interval")]
    interval: i32,
    #[serde(rename = "resend")]
    resend: i32,
    #[serde(rename = "nc")]
    no_congestion: i32,
    #[serde(rename = "sockbuf")]
    sock_buf: i32,
    #[serde(rename = "smuxver")]
    smux_ver: i32,
    #[serde(rename = "smuxbuf")]
    smux_buf: i32,
    #[serde(rename = "framesize")]
    frame_size: i32,
    #[serde(rename = "streambuf")]
    stream_buf: i32,
    #[serde(rename = "keepalive")]
    keep_alive: i32,
}

fn build_kcp_tun(dto: KcpTunDto) -> KcpTun {
    KcpTun {
        enable: dto.enable,
        key: dto.key,
        crypt: dto.crypt,
        mode: dto.mode,
        conn: dto.conn,
        auto_expire: dto.auto_expire,
        scavenge_ttl: dto.scavenge_ttl,
        mtu: dto.mtu,
        rate_limit: dto.rate_limit,
        snd_wnd: dto.snd_wnd,
        rcv_wnd: dto.rcv_wnd,
        data_shard: dto.data_shard,
        parity_shard: dto.parity_shard,
        dscp: dto.dscp,
        no_comp: dto.no_comp,
        ack_nodelay: dto.ack_nodelay,
        no_delay: dto.no_delay,
        interval: dto.interval,
        resend: dto.resend,
        no_congestion: dto.no_congestion,
        sock_buf: dto.sock_buf,
        smux_ver: dto.smux_ver,
        smux_buf: dto.smux_buf,
        frame_size: dto.frame_size,
        stream_buf: dto.stream_buf,
        keep_alive: dto.keep_alive,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct MKCPConfigDto {
    #[serde(rename = "enable")]
    enable: bool,
    #[serde(rename = "mtu")]
    mtu: u32,
    #[serde(rename = "tti")]
    tti: u32,
    #[serde(rename = "uplink-capacity")]
    uplink_capacity: u32,
    #[serde(rename = "downlink-capacity")]
    downlink_capacity: u32,
    #[serde(rename = "congestion")]
    congestion: bool,
    #[serde(rename = "write-buffer")]
    write_buffer: u32,
    #[serde(rename = "read-buffer")]
    read_buffer: u32,
    #[serde(rename = "seed")]
    seed: String,
    #[serde(rename = "header")]
    header: String,
}

fn build_mkcp_config(dto: MKCPConfigDto) -> MKCPConfig {
    MKCPConfig {
        enable: dto.enable,
        mtu: dto.mtu,
        tti: dto.tti,
        uplink_capacity: dto.uplink_capacity,
        downlink_capacity: dto.downlink_capacity,
        congestion: dto.congestion,
        write_buffer: dto.write_buffer,
        read_buffer: dto.read_buffer,
        seed: dto.seed,
        header: dto.header,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct MekyaConfigDto {
    #[serde(rename = "enable")]
    enable: bool,
    #[serde(rename = "url")]
    url: String,
    #[serde(rename = "h2-pool-size")]
    h2_pool_size: i32,
    #[serde(rename = "max-write-delay")]
    max_write_delay: i32,
    #[serde(rename = "max-request-size")]
    max_request_size: i32,
    #[serde(rename = "polling-interval-initial")]
    polling_interval_initial: i32,
    #[serde(rename = "max-write-size")]
    max_write_size: i32,
    #[serde(rename = "max-write-duration-ms")]
    max_write_duration_ms: i32,
    #[serde(rename = "max-simultaneous-write-connection")]
    max_simultaneous_write_connection: i32,
    #[serde(rename = "packet-writing-buffer")]
    packet_writing_buffer: i32,
    #[serde(rename = "kcp")]
    kcp: MKCPConfigDto,
}

fn build_mekya_config(dto: MekyaConfigDto) -> MekyaConfig {
    MekyaConfig {
        enable: dto.enable,
        url: dto.url,
        h2_pool_size: dto.h2_pool_size,
        max_write_delay: dto.max_write_delay,
        max_request_size: dto.max_request_size,
        polling_interval_initial: dto.polling_interval_initial,
        max_write_size: dto.max_write_size,
        max_write_duration_ms: dto.max_write_duration_ms,
        max_simultaneous_write_connection: dto.max_simultaneous_write_connection,
        packet_writing_buffer: dto.packet_writing_buffer,
        kcp: build_mkcp_config(dto.kcp),
    }
}

/// `SimpleObfs`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SimpleObfsDto {
    #[serde(rename = "enable")]
    enable: bool,
    #[serde(rename = "mode")]
    mode: String,
}

fn build_simple_obfs(dto: SimpleObfsDto) -> SimpleObfs {
    SimpleObfs { enable: dto.enable, mode: dto.mode }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TLSMirrorConnectionEnrolmentDto {
    #[serde(rename = "primary-ingress-outbound")]
    primary_ingress_outbound: String,
    #[serde(rename = "primary-egress-outbound")]
    primary_egress_outbound: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TLSMirrorTimeSpecDto {
    #[serde(rename = "base-nanoseconds")]
    base_nanoseconds: u64,
    #[serde(rename = "uniform-random-multiplier-nanoseconds")]
    uniform_random_multiplier_nanoseconds: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TLSMirrorTransportLayerPaddingDto {
    #[serde(rename = "enabled")]
    enabled: bool,
}

/// `TLSMirrorConfig`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TLSMirrorConfigDto {
    #[serde(rename = "primary-key")]
    primary_key: String,
    #[serde(rename = "dest")]
    dest: String,
    #[serde(rename = "proxy")]
    proxy: String,
    #[serde(rename = "explicit-nonce-ciphersuites")]
    explicit_nonce_cipher_suites: Vec<u16>,
    #[serde(rename = "defer-instance-derived-write-time")]
    defer_instance_derived_write_time: TLSMirrorTimeSpecDto,
    #[serde(rename = "transport-layer-padding")]
    transport_layer_padding: TLSMirrorTransportLayerPaddingDto,
    #[serde(rename = "connection-enrolment")]
    connection_enrolment: Option<TLSMirrorConnectionEnrolmentDto>,
    #[serde(rename = "sequence-watermarking-enabled")]
    sequence_watermarking_enabled: bool,
}

fn build_tls_mirror_config(dto: TLSMirrorConfigDto) -> TLSMirrorConfig {
    TLSMirrorConfig {
        primary_key: dto.primary_key,
        dest: dto.dest,
        proxy: dto.proxy,
        explicit_nonce_cipher_suites: dto.explicit_nonce_cipher_suites,
        defer_instance_derived_write_time: TLSMirrorTimeSpec {
            base_nanoseconds: dto.defer_instance_derived_write_time.base_nanoseconds,
            uniform_random_multiplier_nanoseconds: dto
                .defer_instance_derived_write_time
                .uniform_random_multiplier_nanoseconds,
        },
        transport_layer_padding: TLSMirrorTransportLayerPadding { enabled: dto.transport_layer_padding.enabled },
        connection_enrolment: dto.connection_enrolment.map(|e| TLSMirrorConnectionEnrolment {
            primary_ingress_outbound: e.primary_ingress_outbound,
            primary_egress_outbound: e.primary_egress_outbound,
        }),
        sequence_watermarking_enabled: dto.sequence_watermarking_enabled,
    }
}

/// `SnellObfsOption`. The option object is untagged, so a decoder configured with a tag name falls
/// back to matching the lower-cased field name; the DTO uses the field's own lower-cased name
/// instead of an `inbound:"..."` tag.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SnellObfsOptionDto {
    #[serde(rename = "mode")]
    mode: String,
    #[serde(rename = "host")]
    host: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct VmessUserDto {
    #[serde(rename = "username")]
    username: String,
    #[serde(rename = "uuid")]
    uuid: String,
    #[serde(rename = "alterId")]
    alter_id: i32,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct VlessUserDto {
    #[serde(rename = "username")]
    username: String,
    #[serde(rename = "uuid")]
    uuid: String,
    #[serde(rename = "flow")]
    flow: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct XHTTPConfigDto {
    #[serde(rename = "path")]
    path: String,
    #[serde(rename = "host")]
    host: String,
    #[serde(rename = "mode")]
    mode: String,
    #[serde(rename = "x-padding-bytes")]
    x_padding_bytes: String,
    #[serde(rename = "x-padding-obfs-mode")]
    x_padding_obfs_mode: bool,
    #[serde(rename = "x-padding-key")]
    x_padding_key: String,
    #[serde(rename = "x-padding-header")]
    x_padding_header: String,
    #[serde(rename = "x-padding-placement")]
    x_padding_placement: String,
    #[serde(rename = "x-padding-method")]
    x_padding_method: String,
    #[serde(rename = "uplink-http-method")]
    uplink_http_method: String,
    #[serde(rename = "session-placement")]
    session_placement: String,
    #[serde(rename = "session-key")]
    session_key: String,
    #[serde(rename = "seq-placement")]
    seq_placement: String,
    #[serde(rename = "seq-key")]
    seq_key: String,
    #[serde(rename = "uplink-data-placement")]
    uplink_data_placement: String,
    #[serde(rename = "uplink-data-key")]
    uplink_data_key: String,
    #[serde(rename = "uplink-chunk-size")]
    uplink_chunk_size: String,
    #[serde(rename = "no-sse-header")]
    no_sse_header: bool,
    #[serde(rename = "sc-stream-up-server-secs")]
    sc_stream_up_server_secs: String,
    #[serde(rename = "sc-max-buffered-posts")]
    sc_max_buffered_posts: String,
    #[serde(rename = "sc-max-each-post-bytes")]
    sc_max_each_post_bytes: String,
}

fn build_xhttp_config(dto: XHTTPConfigDto) -> XHTTPConfig {
    XHTTPConfig {
        path: dto.path,
        host: dto.host,
        mode: dto.mode,
        x_padding_bytes: dto.x_padding_bytes,
        x_padding_obfs_mode: dto.x_padding_obfs_mode,
        x_padding_key: dto.x_padding_key,
        x_padding_header: dto.x_padding_header,
        x_padding_placement: dto.x_padding_placement,
        x_padding_method: dto.x_padding_method,
        uplink_http_method: dto.uplink_http_method,
        session_placement: dto.session_placement,
        session_key: dto.session_key,
        seq_placement: dto.seq_placement,
        seq_key: dto.seq_key,
        uplink_data_placement: dto.uplink_data_placement,
        uplink_data_key: dto.uplink_data_key,
        uplink_chunk_size: dto.uplink_chunk_size,
        no_sse_header: dto.no_sse_header,
        sc_stream_up_server_secs: dto.sc_stream_up_server_secs,
        sc_max_buffered_posts: dto.sc_max_buffered_posts,
        sc_max_each_post_bytes: dto.sc_max_each_post_bytes,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TrojanUserDto {
    #[serde(rename = "username")]
    username: String,
    #[serde(rename = "password")]
    password: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TrojanSSOptionDto {
    #[serde(rename = "enabled")]
    enabled: bool,
    #[serde(rename = "method")]
    method: String,
    #[serde(rename = "password")]
    password: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ShadowQuicUserDto {
    #[serde(rename = "username")]
    username: String,
    #[serde(rename = "password")]
    password: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ShadowQuicJLSUpstreamDto {
    #[serde(rename = "addr")]
    addr: String,
    #[serde(rename = "sni")]
    sni: String,
    #[serde(rename = "proxy")]
    proxy: String,
    #[serde(rename = "rate-limit")]
    rate_limit: u64,
}

fn build_shadow_quic_jls_upstream(dto: ShadowQuicJLSUpstreamDto) -> ShadowQuicJLSUpstream {
    ShadowQuicJLSUpstream { addr: dto.addr, sni: dto.sni, proxy: dto.proxy, rate_limit: dto.rate_limit }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SudokuHTTPMaskOptionsDto {
    #[serde(rename = "disable")]
    disable: bool,
    #[serde(rename = "mode")]
    mode: String,
    #[serde(rename = "path-root")]
    path_root: String,
}

fn build_sudoku_http_mask_options(dto: SudokuHTTPMaskOptionsDto) -> SudokuHTTPMaskOptions {
    SudokuHTTPMaskOptions { disable: dto.disable, mode: dto.mode, path_root: dto.path_root }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SocksOptionDto {
    #[serde(rename = "users")]
    users: Option<Vec<AuthUserDto>>,
    #[serde(rename = "udp", default = "default_true")]
    udp: bool,
    #[serde(rename = "certificate")]
    certificate: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "client-auth-type")]
    client_auth_type: String,
    #[serde(rename = "client-auth-cert")]
    client_auth_cert: String,
    #[serde(rename = "ech-key")]
    ech_key: String,
    #[serde(rename = "reality-config")]
    reality_config: RealityConfigDto,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HTTPOptionDto {
    #[serde(rename = "users")]
    users: Option<Vec<AuthUserDto>>,
    #[serde(rename = "certificate")]
    certificate: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "client-auth-type")]
    client_auth_type: String,
    #[serde(rename = "client-auth-cert")]
    client_auth_cert: String,
    #[serde(rename = "ech-key")]
    ech_key: String,
    #[serde(rename = "reality-config")]
    reality_config: RealityConfigDto,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TProxyOptionDto {
    #[serde(rename = "udp", default = "default_true")]
    udp: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct MixedOptionDto {
    #[serde(rename = "users")]
    users: Option<Vec<AuthUserDto>>,
    #[serde(rename = "udp", default = "default_true")]
    udp: bool,
    #[serde(rename = "certificate")]
    certificate: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "client-auth-type")]
    client_auth_type: String,
    #[serde(rename = "client-auth-cert")]
    client_auth_cert: String,
    #[serde(rename = "ech-key")]
    ech_key: String,
    #[serde(rename = "reality-config")]
    reality_config: RealityConfigDto,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TunnelOptionDto {
    #[serde(rename = "network")]
    network: Vec<String>,
    #[serde(rename = "target")]
    target: String,
}

/// A prefix or an address decodes from its text form, so every list of them below parses from
/// strings.
fn ip_net_vec<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<ipnet::IpNet>, D::Error> {
    use serde::de::Error as _;
    Vec::<String>::deserialize(deserializer)?.iter().map(|s| s.parse().map_err(D::Error::custom)).collect()
}

fn ip_addr_vec<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<std::net::IpAddr>, D::Error> {
    use serde::de::Error as _;
    Vec::<String>::deserialize(deserializer)?.iter().map(|s| s.parse().map_err(D::Error::custom)).collect()
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
#[expect(clippy::struct_excessive_bools, reason = "the fields mirror the `tun:` option keys one-to-one")]
struct TunOptionDto {
    #[serde(rename = "device")]
    device: String,
    #[serde(rename = "stack")]
    stack: murmur_constant::tun::TunStack,
    #[serde(rename = "dns-hijack")]
    dns_hijack: Option<Vec<String>>,
    #[serde(rename = "auto-route")]
    auto_route: bool,
    #[serde(rename = "auto-detect-interface")]
    auto_detect_interface: bool,
    #[serde(rename = "mtu")]
    mtu: u32,
    #[serde(rename = "gso")]
    gso: bool,
    #[serde(rename = "gso-max-size")]
    gso_max_size: u32,
    #[serde(rename = "inet4-address", deserialize_with = "ip_net_vec")]
    inet4_address: Vec<ipnet::IpNet>,
    #[serde(rename = "inet6-address", deserialize_with = "ip_net_vec")]
    inet6_address: Vec<ipnet::IpNet>,
    #[serde(rename = "iproute2-table-index")]
    iproute2_table_index: i64,
    #[serde(rename = "iproute2-rule-index")]
    iproute2_rule_index: i64,
    #[serde(rename = "auto-redirect")]
    auto_redirect: bool,
    #[serde(rename = "auto-redirect-input-mark")]
    auto_redirect_input_mark: u32,
    #[serde(rename = "auto-redirect-output-mark")]
    auto_redirect_output_mark: u32,
    #[serde(rename = "auto-redirect-iproute2-fallback-rule-index")]
    auto_redirect_iproute2_fallback_rule_index: i64,
    #[serde(rename = "loopback-address", deserialize_with = "ip_addr_vec")]
    loopback_address: Vec<std::net::IpAddr>,
    #[serde(rename = "strict-route")]
    strict_route: bool,
    #[serde(rename = "route-address", deserialize_with = "ip_net_vec")]
    route_address: Vec<ipnet::IpNet>,
    #[serde(rename = "route-address-set")]
    route_address_set: Vec<String>,
    #[serde(rename = "route-exclude-address", deserialize_with = "ip_net_vec")]
    route_exclude_address: Vec<ipnet::IpNet>,
    #[serde(rename = "route-exclude-address-set")]
    route_exclude_address_set: Vec<String>,
    #[serde(rename = "include-interface")]
    include_interface: Vec<String>,
    #[serde(rename = "exclude-interface")]
    exclude_interface: Vec<String>,
    #[serde(rename = "include-uid")]
    include_uid: Vec<u32>,
    #[serde(rename = "include-uid-range")]
    include_uid_range: Vec<String>,
    #[serde(rename = "exclude-uid")]
    exclude_uid: Vec<u32>,
    #[serde(rename = "exclude-uid-range")]
    exclude_uid_range: Vec<String>,
    #[serde(rename = "exclude-src-port")]
    exclude_src_port: Vec<u16>,
    #[serde(rename = "exclude-src-port-range")]
    exclude_src_port_range: Vec<String>,
    #[serde(rename = "exclude-dst-port")]
    exclude_dst_port: Vec<u16>,
    #[serde(rename = "exclude-dst-port-range")]
    exclude_dst_port_range: Vec<String>,
    #[serde(rename = "include-android-user")]
    include_android_user: Vec<i64>,
    #[serde(rename = "include-package")]
    include_package: Vec<String>,
    #[serde(rename = "exclude-package")]
    exclude_package: Vec<String>,
    #[serde(rename = "include-mac-address")]
    include_mac_address: Vec<String>,
    #[serde(rename = "exclude-mac-address")]
    exclude_mac_address: Vec<String>,
    #[serde(rename = "endpoint-independent-nat")]
    endpoint_independent_nat: bool,
    #[serde(rename = "udp-timeout")]
    udp_timeout: i64,
    #[serde(rename = "icmp-timeout")]
    icmp_timeout: i64,
    #[serde(rename = "disable-icmp-forwarding")]
    disable_icmp_forwarding: bool,
    #[serde(rename = "file-descriptor")]
    file_descriptor: i32,
    #[serde(rename = "inet4-route-address", deserialize_with = "ip_net_vec")]
    inet4_route_address: Vec<ipnet::IpNet>,
    #[serde(rename = "inet6-route-address", deserialize_with = "ip_net_vec")]
    inet6_route_address: Vec<ipnet::IpNet>,
    #[serde(rename = "inet4-route-exclude-address", deserialize_with = "ip_net_vec")]
    inet4_route_exclude_address: Vec<ipnet::IpNet>,
    #[serde(rename = "inet6-route-exclude-address", deserialize_with = "ip_net_vec")]
    inet6_route_exclude_address: Vec<ipnet::IpNet>,
    #[serde(rename = "recvmsgx")]
    recvmsgx: bool,
    #[serde(rename = "sendmsgx")]
    sendmsgx: bool,
    #[serde(rename = "processors-per-channel")]
    processors_per_channel: i32,
}

fn build_tun_option(dto: TunOptionDto, base: BaseOption) -> TunOption {
    TunOption {
        base,
        device: dto.device,
        stack: dto.stack,
        dns_hijack: dto.dns_hijack,
        auto_route: dto.auto_route,
        auto_detect_interface: dto.auto_detect_interface,
        mtu: dto.mtu,
        gso: dto.gso,
        gso_max_size: dto.gso_max_size,
        inet4_address: dto.inet4_address,
        inet6_address: dto.inet6_address,
        iproute2_table_index: dto.iproute2_table_index,
        iproute2_rule_index: dto.iproute2_rule_index,
        auto_redirect: dto.auto_redirect,
        auto_redirect_input_mark: dto.auto_redirect_input_mark,
        auto_redirect_output_mark: dto.auto_redirect_output_mark,
        auto_redirect_iproute2_fallback_rule_index: dto.auto_redirect_iproute2_fallback_rule_index,
        loopback_address: dto.loopback_address,
        strict_route: dto.strict_route,
        route_address: dto.route_address,
        route_address_set: dto.route_address_set,
        route_exclude_address: dto.route_exclude_address,
        route_exclude_address_set: dto.route_exclude_address_set,
        include_interface: dto.include_interface,
        exclude_interface: dto.exclude_interface,
        include_uid: dto.include_uid,
        include_uid_range: dto.include_uid_range,
        exclude_uid: dto.exclude_uid,
        exclude_uid_range: dto.exclude_uid_range,
        exclude_src_port: dto.exclude_src_port,
        exclude_src_port_range: dto.exclude_src_port_range,
        exclude_dst_port: dto.exclude_dst_port,
        exclude_dst_port_range: dto.exclude_dst_port_range,
        include_android_user: dto.include_android_user,
        include_package: dto.include_package,
        exclude_package: dto.exclude_package,
        include_mac_address: dto.include_mac_address,
        exclude_mac_address: dto.exclude_mac_address,
        endpoint_independent_nat: dto.endpoint_independent_nat,
        udp_timeout: dto.udp_timeout,
        icmp_timeout: dto.icmp_timeout,
        disable_icmp_forwarding: dto.disable_icmp_forwarding,
        file_descriptor: dto.file_descriptor,
        inet4_route_address: dto.inet4_route_address,
        inet6_route_address: dto.inet6_route_address,
        inet4_route_exclude_address: dto.inet4_route_exclude_address,
        inet6_route_exclude_address: dto.inet6_route_exclude_address,
        recvmsgx: dto.recvmsgx,
        sendmsgx: dto.sendmsgx,
        processors_per_channel: dto.processors_per_channel,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ShadowSocksOptionDto {
    #[serde(rename = "password")]
    password: String,
    #[serde(rename = "cipher")]
    cipher: String,
    #[serde(rename = "udp", default = "default_true")]
    udp: bool,
    #[serde(rename = "mux-option")]
    mux_option: MuxOptionDto,
    #[serde(rename = "shadow-tls")]
    shadow_tls: ShadowTLSDto,
    #[serde(rename = "res-tls")]
    res_tls: ResTLSDto,
    #[serde(rename = "jls-config")]
    jls_config: JLSConfigDto,
    #[serde(rename = "kcp-tun")]
    kcp_tun: KcpTunDto,
    #[serde(rename = "simple-obfs")]
    simple_obfs: SimpleObfsDto,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SnellOptionDto {
    #[serde(rename = "psk")]
    psk: String,
    #[serde(rename = "version")]
    version: i32,
    #[serde(rename = "udp", default = "default_true")]
    udp: bool,
    #[serde(rename = "obfs-opts")]
    obfs_opts: SnellObfsOptionDto,
    #[serde(rename = "shadow-tls")]
    shadow_tls: ShadowTLSDto,
    #[serde(rename = "res-tls")]
    res_tls: ResTLSDto,
    #[serde(rename = "jls-config")]
    jls_config: JLSConfigDto,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct VmessOptionDto {
    #[serde(rename = "users")]
    users: Vec<VmessUserDto>,
    #[serde(rename = "ws-path")]
    ws_path: String,
    #[serde(rename = "grpc-service-name")]
    grpc_service_name: String,
    #[serde(rename = "certificate")]
    certificate: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "client-auth-type")]
    client_auth_type: String,
    #[serde(rename = "client-auth-cert")]
    client_auth_cert: String,
    #[serde(rename = "ech-key")]
    ech_key: String,
    #[serde(rename = "shadow-tls")]
    shadow_tls: ShadowTLSDto,
    #[serde(rename = "res-tls")]
    res_tls: ResTLSDto,
    #[serde(rename = "jls-config")]
    jls_config: JLSConfigDto,
    #[serde(rename = "reality-config")]
    reality_config: RealityConfigDto,
    #[serde(rename = "tlsmirror-config")]
    tls_mirror_config: TLSMirrorConfigDto,
    #[serde(rename = "mekya-config")]
    mekya_config: MekyaConfigDto,
    #[serde(rename = "mkcp-config")]
    mkcp_config: MKCPConfigDto,
    #[serde(rename = "mux-option")]
    mux_option: MuxOptionDto,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct VlessOptionDto {
    #[serde(rename = "users")]
    users: Vec<VlessUserDto>,
    #[serde(rename = "decryption")]
    decryption: String,
    #[serde(rename = "ws-path")]
    ws_path: String,
    #[serde(rename = "xhttp-config")]
    xhttp_config: XHTTPConfigDto,
    #[serde(rename = "grpc-service-name")]
    grpc_service_name: String,
    #[serde(rename = "certificate")]
    certificate: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "client-auth-type")]
    client_auth_type: String,
    #[serde(rename = "client-auth-cert")]
    client_auth_cert: String,
    #[serde(rename = "ech-key")]
    ech_key: String,
    #[serde(rename = "allow-insecure")]
    allow_insecure: bool,
    #[serde(rename = "shadow-tls")]
    shadow_tls: ShadowTLSDto,
    #[serde(rename = "res-tls")]
    res_tls: ResTLSDto,
    #[serde(rename = "jls-config")]
    jls_config: JLSConfigDto,
    #[serde(rename = "reality-config")]
    reality_config: RealityConfigDto,
    #[serde(rename = "mux-option")]
    mux_option: MuxOptionDto,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TrojanOptionDto {
    #[serde(rename = "users")]
    users: Vec<TrojanUserDto>,
    #[serde(rename = "ws-path")]
    ws_path: String,
    #[serde(rename = "grpc-service-name")]
    grpc_service_name: String,
    #[serde(rename = "certificate")]
    certificate: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "client-auth-type")]
    client_auth_type: String,
    #[serde(rename = "client-auth-cert")]
    client_auth_cert: String,
    #[serde(rename = "ech-key")]
    ech_key: String,
    #[serde(rename = "allow-insecure")]
    allow_insecure: bool,
    #[serde(rename = "shadow-tls")]
    shadow_tls: ShadowTLSDto,
    #[serde(rename = "res-tls")]
    res_tls: ResTLSDto,
    #[serde(rename = "jls-config")]
    jls_config: JLSConfigDto,
    #[serde(rename = "reality-config")]
    reality_config: RealityConfigDto,
    #[serde(rename = "mux-option")]
    mux_option: MuxOptionDto,
    #[serde(rename = "ss-option")]
    ss_option: TrojanSSOptionDto,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TuicOptionDto {
    #[serde(rename = "token")]
    token: Vec<String>,
    #[serde(rename = "users")]
    users: BTreeMap<String, String>,
    #[serde(rename = "certificate")]
    certificate: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "client-auth-type")]
    client_auth_type: String,
    #[serde(rename = "client-auth-cert")]
    client_auth_cert: String,
    #[serde(rename = "ech-key")]
    ech_key: String,
    #[serde(rename = "congestion-controller", default = "default_bbr")]
    congestion_controller: String,
    #[serde(rename = "max-idle-time", default = "default_tuic_max_idle_time")]
    max_idle_time: i32,
    #[serde(rename = "authentication-timeout", default = "default_tuic_authentication_timeout")]
    authentication_timeout: i32,
    #[serde(rename = "alpn", default = "default_h3_alpn")]
    alpn: Vec<String>,
    #[serde(rename = "max-udp-relay-packet-size", default = "default_tuic_max_udp_relay_packet_size")]
    max_udp_relay_packet_size: i32,
    #[serde(rename = "cwnd")]
    cwnd: i32,
    #[serde(rename = "bbr-profile")]
    bbr_profile: String,
    #[serde(rename = "mux-option")]
    mux_option: MuxOptionDto,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ShadowQuicOptionDto {
    #[serde(rename = "users")]
    users: Vec<ShadowQuicUserDto>,
    #[serde(rename = "jls-upstream")]
    jls_upstream: ShadowQuicJLSUpstreamDto,
    #[serde(rename = "alpn", default = "default_h3_alpn")]
    alpn: Vec<String>,
    #[serde(rename = "quic-versions")]
    quic_versions: Vec<String>,
    #[serde(rename = "zero-rtt", default = "default_true")]
    zero_rtt: bool,
    #[serde(rename = "congestion-controller", default = "default_bbr")]
    congestion_controller: String,
    #[serde(rename = "up")]
    up: String,
    #[serde(rename = "down")]
    down: String,
    #[serde(rename = "ignore-client-bandwidth")]
    ignore_client_bandwidth: bool,
    #[serde(rename = "max-idle-time", default = "default_shadowquic_max_idle_time")]
    max_idle_time: i32,
    #[serde(rename = "max-datagram-frame-size", default = "default_shadowquic_max_datagram_frame_size")]
    max_datagram_frame_size: i32,
    #[serde(rename = "recv-window-conn")]
    receive_window_conn: i32,
    #[serde(rename = "recv-window")]
    receive_window: i32,
    #[serde(rename = "disable-mtu-discovery")]
    disable_mtu_discovery: bool,
    #[serde(rename = "cwnd")]
    cwnd: i32,
    #[serde(rename = "bbr-profile")]
    bbr_profile: String,
    #[serde(rename = "mux-option")]
    mux_option: MuxOptionDto,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct MieruOptionDto {
    #[serde(rename = "transport")]
    transport: String,
    #[serde(rename = "users", default)]
    users: BTreeMap<String, String>,
    #[serde(rename = "traffic-pattern", default)]
    traffic_pattern: String,
    #[serde(rename = "user-hint-is-mandatory", default)]
    user_hint_is_mandatory: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AnyTLSOptionDto {
    #[serde(rename = "users")]
    users: BTreeMap<String, String>,
    #[serde(rename = "certificate")]
    certificate: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "client-auth-type")]
    client_auth_type: String,
    #[serde(rename = "client-auth-cert")]
    client_auth_cert: String,
    #[serde(rename = "ech-key")]
    ech_key: String,
    #[serde(rename = "shadow-tls")]
    shadow_tls: ShadowTLSDto,
    #[serde(rename = "res-tls")]
    res_tls: ResTLSDto,
    #[serde(rename = "jls-config")]
    jls_config: JLSConfigDto,
    #[serde(rename = "allow-insecure")]
    allow_insecure: bool,
    #[serde(rename = "padding-scheme")]
    padding_scheme: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SudokuOptionDto {
    #[serde(rename = "key")]
    key: String,
    #[serde(rename = "aead-method")]
    aead_method: String,
    #[serde(rename = "padding-min")]
    padding_min: Option<i32>,
    #[serde(rename = "padding-max")]
    padding_max: Option<i32>,
    #[serde(rename = "table-type")]
    table_type: String,
    #[serde(rename = "handshake-timeout")]
    handshake_timeout_second: Option<i32>,
    #[serde(rename = "enable-pure-downlink")]
    enable_pure_downlink: Option<bool>,
    #[serde(rename = "custom-table")]
    custom_table: String,
    #[serde(rename = "custom-tables")]
    custom_tables: Vec<String>,
    #[serde(rename = "disable-http-mask")]
    disable_http_mask: bool,
    #[serde(rename = "http-mask-mode")]
    http_mask_mode: String,
    #[serde(rename = "path-root")]
    path_root: String,
    #[serde(rename = "fallback")]
    fallback: String,
    #[serde(rename = "httpmask")]
    http_mask_options: Option<SudokuHTTPMaskOptionsDto>,
    #[serde(rename = "mux-option")]
    mux_option: MuxOptionDto,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TrustTunnelOptionDto {
    #[serde(rename = "users")]
    users: Option<Vec<AuthUserDto>>,
    #[serde(rename = "certificate")]
    certificate: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "client-auth-type")]
    client_auth_type: String,
    #[serde(rename = "client-auth-cert")]
    client_auth_cert: String,
    #[serde(rename = "ech-key")]
    ech_key: String,
    #[serde(rename = "network")]
    network: Vec<String>,
    #[serde(rename = "congestion-controller")]
    congestion_controller: String,
    #[serde(rename = "cwnd")]
    cwnd: i32,
    #[serde(rename = "bbr-profile")]
    bbr_profile: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Hysteria2RealmServerOptionDto {
    #[serde(rename = "token")]
    token: String,
    #[serde(rename = "max-realms", default = "default_realm_max_realms")]
    max_realms: i32,
    #[serde(rename = "max-realms-per-ip", default = "default_realm_max_realms_per_ip")]
    max_realms_per_ip: i32,
    #[serde(rename = "trusted-proxy-header")]
    trusted_proxy_header: String,
    #[serde(rename = "realm-name-pattern", default = "default_realm_name_pattern")]
    realm_name_pattern: String,
    #[serde(rename = "certificate")]
    certificate: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "client-auth-type")]
    client_auth_type: String,
    #[serde(rename = "client-auth-cert")]
    client_auth_cert: String,
    #[serde(rename = "ech-key")]
    ech_key: String,
    #[serde(rename = "alpn", default = "default_realm_alpn")]
    alpn: Vec<String>,
}

/// `Hysteria2RealmOption`, the `realm-opts` block of `Hysteria2Option`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Hysteria2RealmOptionDto {
    #[serde(rename = "enable")]
    enable: bool,
    #[serde(rename = "server-url")]
    server_url: String,
    #[serde(rename = "token")]
    token: String,
    #[serde(rename = "realm-id")]
    realm_id: String,
    #[serde(rename = "stun-servers")]
    stun_servers: Vec<String>,
    #[serde(rename = "sni")]
    sni: String,
    #[serde(rename = "skip-cert-verify")]
    skip_cert_verify: bool,
    #[serde(rename = "name-cert-verify")]
    name_cert_verify: String,
    #[serde(rename = "fingerprint")]
    fingerprint: String,
    #[serde(rename = "certificate")]
    certificate: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "alpn")]
    alpn: Vec<String>,
    #[serde(rename = "proxy")]
    proxy: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Hysteria2OptionDto {
    #[serde(rename = "users")]
    users: BTreeMap<String, String>,
    #[serde(rename = "obfs")]
    obfs: String,
    #[serde(rename = "obfs-password")]
    obfs_password: String,
    #[serde(rename = "obfs-min-packet-size")]
    obfs_min_packet_size: i32,
    #[serde(rename = "obfs-max-packet-size")]
    obfs_max_packet_size: i32,
    #[serde(rename = "certificate")]
    certificate: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "client-auth-type")]
    client_auth_type: String,
    #[serde(rename = "client-auth-cert")]
    client_auth_cert: String,
    #[serde(rename = "ech-key")]
    ech_key: String,
    #[serde(rename = "max-idle-time")]
    max_idle_time: i32,
    #[serde(rename = "alpn")]
    alpn: Vec<String>,
    #[serde(rename = "up")]
    up: String,
    #[serde(rename = "down")]
    down: String,
    #[serde(rename = "ignore-client-bandwidth")]
    ignore_client_bandwidth: bool,
    #[serde(rename = "masquerade")]
    masquerade: String,
    #[serde(rename = "cwnd")]
    cwnd: i32,
    #[serde(rename = "bbr-profile")]
    bbr_profile: String,
    #[serde(rename = "udp-mtu")]
    udp_mtu: i32,
    #[serde(rename = "mux-option")]
    mux_option: MuxOptionDto,
    #[serde(rename = "realm-opts")]
    realm_opts: Hysteria2RealmOptionDto,
    #[serde(rename = "initial-stream-receive-window")]
    initial_stream_receive_window: u64,
    #[serde(rename = "max-stream-receive-window")]
    max_stream_receive_window: u64,
    #[serde(rename = "initial-connection-receive-window")]
    initial_connection_receive_window: u64,
    #[serde(rename = "max-connection-receive-window")]
    max_connection_receive_window: u64,
}

pub fn parse_listener(mapping: &Mapping) -> Result<Arc<dyn InboundListener>> {
    let decoder = new_decoder(StructureOption {
        tag_name: "inbound".to_owned(),
        weakly_typed_input: true,
        key_replacer: Some(DEFAULT_KEY_REPLACER.clone()),
    });

    let proxy_type = mapping.get("type").and_then(Value::as_str).ok_or_else(|| anyhow!("missing type"))?;
    let base: BaseOptionDto = decoder.decode(mapping)?;

    match proxy_type {
        "socks" | "http" | "tproxy" | "redir" | "mixed" | "tunnel" | "tun" => {
            parse_basic_listener(proxy_type, mapping, &decoder, base)
        }
        "shadowsocks" | "snell" | "vmess" => parse_stream_listener(proxy_type, mapping, &decoder, base),
        "vless" | "trojan" => parse_tls_listener(proxy_type, mapping, &decoder, base),
        "hysteria2" => parse_hysteria2_listener(proxy_type, mapping, &decoder, base),
        "hysteria2-realm" | "tuic" | "shadowquic" => parse_quic_listener(proxy_type, mapping, &decoder, base),
        "anytls" | "mieru" | "sudoku" | "trusttunnel" => parse_misc_listener(proxy_type, mapping, &decoder, base),
        other => Err(anyhow!("unsupport proxy type: {other}")),
    }
}

fn parse_basic_listener(
    proxy_type: &str,
    mapping: &Mapping,
    decoder: &Decoder,
    base: BaseOptionDto,
) -> Result<Arc<dyn InboundListener>> {
    let listener: Arc<dyn InboundListener> = match proxy_type {
        "socks" => {
            let dto: SocksOptionDto = decoder.decode(mapping)?;
            let reality_config = build_reality_config(&dto.reality_config)?;
            let option = SocksOption {
                base: build_base(base),
                users: dto.users.map(build_auth_user_list),
                udp: dto.udp,
                certificate: dto.certificate,
                private_key: dto.private_key,
                client_auth_type: dto.client_auth_type,
                client_auth_cert: dto.client_auth_cert,
                ech_key: dto.ech_key,
                reality_config,
            };
            Arc::new(Socks::new(Arc::new(option))?)
        }
        "http" => {
            let dto: HTTPOptionDto = decoder.decode(mapping)?;
            let reality_config = build_reality_config(&dto.reality_config)?;
            let option = HTTPOption {
                base: build_base(base),
                users: dto.users.map(build_auth_user_list),
                certificate: dto.certificate,
                private_key: dto.private_key,
                client_auth_type: dto.client_auth_type,
                client_auth_cert: dto.client_auth_cert,
                ech_key: dto.ech_key,
                reality_config,
            };
            Arc::new(HTTP::new(Arc::new(option))?)
        }
        "tproxy" => {
            let dto: TProxyOptionDto = decoder.decode(mapping)?;
            let option = TProxyOption { base: build_base(base), udp: dto.udp };
            Arc::new(TProxy::new(Arc::new(option))?)
        }
        "redir" => {
            let option = RedirOption { base: build_base(base) };
            Arc::new(Redir::new(Arc::new(option))?)
        }
        "mixed" => {
            let dto: MixedOptionDto = decoder.decode(mapping)?;
            let reality_config = build_reality_config(&dto.reality_config)?;
            let option = MixedOption {
                base: build_base(base),
                users: dto.users.map(build_auth_user_list),
                udp: dto.udp,
                certificate: dto.certificate,
                private_key: dto.private_key,
                client_auth_type: dto.client_auth_type,
                client_auth_cert: dto.client_auth_cert,
                ech_key: dto.ech_key,
                reality_config,
            };
            Arc::new(Mixed::new(Arc::new(option))?)
        }
        "tunnel" => {
            let dto: TunnelOptionDto = decoder.decode(mapping)?;
            let option = TunnelOption { base: build_base(base), network: dto.network, target: dto.target };
            Arc::new(TunnelInbound::new(Arc::new(option))?)
        }
        "tun" => {
            let dto: TunOptionDto = decoder.decode(mapping)?;
            let option = build_tun_option(dto, build_base(base));
            Arc::new(Tun::new(Arc::new(option))?)
        }
        other => return Err(anyhow!("unsupport proxy type: {other}")),
    };

    Ok(listener)
}

fn parse_stream_listener(
    proxy_type: &str,
    mapping: &Mapping,
    decoder: &Decoder,
    base: BaseOptionDto,
) -> Result<Arc<dyn InboundListener>> {
    let listener: Arc<dyn InboundListener> = match proxy_type {
        "shadowsocks" => {
            let dto: ShadowSocksOptionDto = decoder.decode(mapping)?;
            let option = ShadowSocksOption {
                base: build_base(base),
                password: dto.password,
                cipher: dto.cipher,
                udp: dto.udp,
                mux_option: build_mux_option(dto.mux_option),
                shadow_tls: build_shadow_tls(dto.shadow_tls),
                res_tls: build_res_tls(dto.res_tls),
                jls_config: build_jls_config(dto.jls_config),
                kcp_tun: build_kcp_tun(dto.kcp_tun),
                simple_obfs: build_simple_obfs(dto.simple_obfs),
            };
            Arc::new(ShadowSocks::new(Arc::new(option))?)
        }
        "snell" => {
            let dto: SnellOptionDto = decoder.decode(mapping)?;
            let option = SnellOption {
                base: build_base(base),
                psk: dto.psk,
                version: dto.version,
                udp: dto.udp,
                obfs_opts: SnellObfsOption { mode: dto.obfs_opts.mode, host: dto.obfs_opts.host },
                shadow_tls: build_shadow_tls(dto.shadow_tls),
                res_tls: build_res_tls(dto.res_tls),
                jls_config: build_jls_config(dto.jls_config),
            };
            Arc::new(Snell::new(Arc::new(option))?)
        }
        "vmess" => {
            let dto: VmessOptionDto = decoder.decode(mapping)?;
            let reality_config = build_reality_config(&dto.reality_config)?;
            let option = VmessOption {
                base: build_base(base),
                users: dto
                    .users
                    .into_iter()
                    .map(|u| VmessUser { username: u.username, uuid: u.uuid, alter_id: u.alter_id })
                    .collect(),
                ws_path: dto.ws_path,
                grpc_service_name: dto.grpc_service_name,
                certificate: dto.certificate,
                private_key: dto.private_key,
                client_auth_type: dto.client_auth_type,
                client_auth_cert: dto.client_auth_cert,
                ech_key: dto.ech_key,
                shadow_tls: build_shadow_tls(dto.shadow_tls),
                res_tls: build_res_tls(dto.res_tls),
                jls_config: build_jls_config(dto.jls_config),
                reality_config,
                tls_mirror_config: build_tls_mirror_config(dto.tls_mirror_config),
                mekya_config: build_mekya_config(dto.mekya_config),
                mkcp_config: build_mkcp_config(dto.mkcp_config),
                mux_option: build_mux_option(dto.mux_option),
            };
            Arc::new(Vmess::new(Arc::new(option))?)
        }
        other => return Err(anyhow!("unsupport proxy type: {other}")),
    };

    Ok(listener)
}

fn parse_tls_listener(
    proxy_type: &str,
    mapping: &Mapping,
    decoder: &Decoder,
    base: BaseOptionDto,
) -> Result<Arc<dyn InboundListener>> {
    let listener: Arc<dyn InboundListener> = match proxy_type {
        "vless" => {
            let dto: VlessOptionDto = decoder.decode(mapping)?;
            let reality_config = build_reality_config(&dto.reality_config)?;
            let option = VlessOption {
                base: build_base(base),
                users: dto
                    .users
                    .into_iter()
                    .map(|u| VlessUser { username: u.username, uuid: u.uuid, flow: u.flow })
                    .collect(),
                decryption: dto.decryption,
                ws_path: dto.ws_path,
                xhttp_config: build_xhttp_config(dto.xhttp_config),
                grpc_service_name: dto.grpc_service_name,
                certificate: dto.certificate,
                private_key: dto.private_key,
                client_auth_type: dto.client_auth_type,
                client_auth_cert: dto.client_auth_cert,
                ech_key: dto.ech_key,
                allow_insecure: dto.allow_insecure,
                shadow_tls: build_shadow_tls(dto.shadow_tls),
                res_tls: build_res_tls(dto.res_tls),
                jls_config: build_jls_config(dto.jls_config),
                reality_config,
                mux_option: build_mux_option(dto.mux_option),
            };
            Arc::new(Vless::new(Arc::new(option))?)
        }
        "trojan" => {
            let dto: TrojanOptionDto = decoder.decode(mapping)?;
            let reality_config = build_reality_config(&dto.reality_config)?;
            let option = TrojanOption {
                base: build_base(base),
                users: dto
                    .users
                    .into_iter()
                    .map(|u| TrojanUser { username: u.username, password: u.password })
                    .collect(),
                ws_path: dto.ws_path,
                grpc_service_name: dto.grpc_service_name,
                certificate: dto.certificate,
                private_key: dto.private_key,
                client_auth_type: dto.client_auth_type,
                client_auth_cert: dto.client_auth_cert,
                ech_key: dto.ech_key,
                allow_insecure: dto.allow_insecure,
                shadow_tls: build_shadow_tls(dto.shadow_tls),
                res_tls: build_res_tls(dto.res_tls),
                jls_config: build_jls_config(dto.jls_config),
                reality_config,
                mux_option: build_mux_option(dto.mux_option),
                ss_option: TrojanSSOption {
                    enabled: dto.ss_option.enabled,
                    method: dto.ss_option.method,
                    password: dto.ss_option.password,
                },
            };
            Arc::new(Trojan::new(Arc::new(option))?)
        }
        other => return Err(anyhow!("unsupport proxy type: {other}")),
    };

    Ok(listener)
}

fn parse_hysteria2_listener(
    proxy_type: &str,
    mapping: &Mapping,
    decoder: &Decoder,
    base: BaseOptionDto,
) -> Result<Arc<dyn InboundListener>> {
    let listener: Arc<dyn InboundListener> = match proxy_type {
        "hysteria2" => {
            let dto: Hysteria2OptionDto = decoder.decode(mapping)?;
            let option = Hysteria2Option {
                base: build_base(base),
                users: dto.users,
                obfs: dto.obfs,
                obfs_password: dto.obfs_password,
                obfs_min_packet_size: dto.obfs_min_packet_size,
                obfs_max_packet_size: dto.obfs_max_packet_size,
                certificate: dto.certificate,
                private_key: dto.private_key,
                client_auth_type: dto.client_auth_type,
                client_auth_cert: dto.client_auth_cert,
                ech_key: dto.ech_key,
                max_idle_time: dto.max_idle_time,
                alpn: dto.alpn,
                up: dto.up,
                down: dto.down,
                ignore_client_bandwidth: dto.ignore_client_bandwidth,
                masquerade: dto.masquerade,
                cwnd: dto.cwnd,
                bbr_profile: dto.bbr_profile,
                udp_mtu: dto.udp_mtu,
                mux_option: build_mux_option(dto.mux_option),
                realm_opts: Hysteria2RealmOption {
                    enable: dto.realm_opts.enable,
                    server_url: dto.realm_opts.server_url,
                    token: dto.realm_opts.token,
                    realm_id: dto.realm_opts.realm_id,
                    stun_servers: dto.realm_opts.stun_servers,
                    sni: dto.realm_opts.sni,
                    skip_cert_verify: dto.realm_opts.skip_cert_verify,
                    name_cert_verify: dto.realm_opts.name_cert_verify,
                    fingerprint: dto.realm_opts.fingerprint,
                    certificate: dto.realm_opts.certificate,
                    private_key: dto.realm_opts.private_key,
                    alpn: dto.realm_opts.alpn,
                    proxy: dto.realm_opts.proxy,
                },
                initial_stream_receive_window: dto.initial_stream_receive_window,
                max_stream_receive_window: dto.max_stream_receive_window,
                initial_connection_receive_window: dto.initial_connection_receive_window,
                max_connection_receive_window: dto.max_connection_receive_window,
            };
            Arc::new(Hysteria2::new(Arc::new(option))?)
        }
        other => return Err(anyhow!("unsupport proxy type: {other}")),
    };

    Ok(listener)
}

fn parse_quic_listener(
    proxy_type: &str,
    mapping: &Mapping,
    decoder: &Decoder,
    base: BaseOptionDto,
) -> Result<Arc<dyn InboundListener>> {
    let listener: Arc<dyn InboundListener> = match proxy_type {
        "hysteria2-realm" => {
            let dto: Hysteria2RealmServerOptionDto = decoder.decode(mapping)?;
            let option = Hysteria2RealmServerOption {
                base: build_base(base),
                token: dto.token,
                max_realms: dto.max_realms,
                max_realms_per_ip: dto.max_realms_per_ip,
                trusted_proxy_header: dto.trusted_proxy_header,
                realm_name_pattern: dto.realm_name_pattern,
                certificate: dto.certificate,
                private_key: dto.private_key,
                client_auth_type: dto.client_auth_type,
                client_auth_cert: dto.client_auth_cert,
                ech_key: dto.ech_key,
                alpn: dto.alpn,
            };
            Arc::new(Hysteria2RealmServer::new(Arc::new(option))?)
        }
        "tuic" => {
            let dto: TuicOptionDto = decoder.decode(mapping)?;
            let option = TuicOption {
                base: build_base(base),
                token: dto.token,
                users: dto.users,
                certificate: dto.certificate,
                private_key: dto.private_key,
                client_auth_type: dto.client_auth_type,
                client_auth_cert: dto.client_auth_cert,
                ech_key: dto.ech_key,
                congestion_controller: dto.congestion_controller,
                max_idle_time: dto.max_idle_time,
                authentication_timeout: dto.authentication_timeout,
                alpn: dto.alpn,
                max_udp_relay_packet_size: dto.max_udp_relay_packet_size,
                cwnd: dto.cwnd,
                bbr_profile: dto.bbr_profile,
                mux_option: build_mux_option(dto.mux_option),
            };
            Arc::new(Tuic::new(Arc::new(option))?)
        }
        "shadowquic" => {
            let dto: ShadowQuicOptionDto = decoder.decode(mapping)?;
            let option = ShadowQuicOption {
                base: build_base(base),
                users: dto
                    .users
                    .into_iter()
                    .map(|u| ShadowQuicUser { username: u.username, password: u.password })
                    .collect(),
                jls_upstream: build_shadow_quic_jls_upstream(dto.jls_upstream),
                alpn: dto.alpn,
                quic_versions: dto.quic_versions,
                zero_rtt: dto.zero_rtt,
                congestion_controller: dto.congestion_controller,
                up: dto.up,
                down: dto.down,
                ignore_client_bandwidth: dto.ignore_client_bandwidth,
                max_idle_time: dto.max_idle_time,
                max_datagram_frame_size: dto.max_datagram_frame_size,
                receive_window_conn: dto.receive_window_conn,
                receive_window: dto.receive_window,
                disable_mtu_discovery: dto.disable_mtu_discovery,
                cwnd: dto.cwnd,
                bbr_profile: dto.bbr_profile,
                mux_option: build_mux_option(dto.mux_option),
            };
            Arc::new(ShadowQuic::new(Arc::new(option))?)
        }
        other => return Err(anyhow!("unsupport proxy type: {other}")),
    };

    Ok(listener)
}

fn parse_misc_listener(
    proxy_type: &str,
    mapping: &Mapping,
    decoder: &Decoder,
    base: BaseOptionDto,
) -> Result<Arc<dyn InboundListener>> {
    let listener: Arc<dyn InboundListener> = match proxy_type {
        "anytls" => {
            let dto: AnyTLSOptionDto = decoder.decode(mapping)?;
            let option = AnyTLSOption {
                base: build_base(base),
                users: dto.users,
                certificate: dto.certificate,
                private_key: dto.private_key,
                client_auth_type: dto.client_auth_type,
                client_auth_cert: dto.client_auth_cert,
                ech_key: dto.ech_key,
                shadow_tls: build_shadow_tls(dto.shadow_tls),
                res_tls: build_res_tls(dto.res_tls),
                jls_config: build_jls_config(dto.jls_config),
                allow_insecure: dto.allow_insecure,
                padding_scheme: dto.padding_scheme,
            };
            Arc::new(AnyTLS::new(Arc::new(option))?)
        }
        "mieru" => {
            let dto: MieruOptionDto = decoder.decode(mapping)?;
            let option = MieruOption {
                base: build_base(base),
                transport: dto.transport,
                users: dto.users.into_iter().collect(),
                traffic_pattern: dto.traffic_pattern,
                user_hint_is_mandatory: dto.user_hint_is_mandatory,
            };
            Arc::new(Mieru::new(Arc::new(option))?)
        }
        "sudoku" => {
            let dto: SudokuOptionDto = decoder.decode(mapping)?;
            let option = SudokuOption {
                base: build_base(base),
                key: dto.key,
                aead_method: dto.aead_method,
                padding_min: dto.padding_min,
                padding_max: dto.padding_max,
                table_type: dto.table_type,
                handshake_timeout_second: dto.handshake_timeout_second,
                enable_pure_downlink: dto.enable_pure_downlink,
                custom_table: dto.custom_table,
                custom_tables: dto.custom_tables,
                disable_http_mask: dto.disable_http_mask,
                http_mask_mode: dto.http_mask_mode,
                path_root: dto.path_root,
                fallback: dto.fallback,
                http_mask_options: dto.http_mask_options.map(build_sudoku_http_mask_options),
                mux_option: build_mux_option(dto.mux_option),
            };
            Arc::new(Sudoku::new(Arc::new(option))?)
        }
        "trusttunnel" => {
            let dto: TrustTunnelOptionDto = decoder.decode(mapping)?;
            let option = TrustTunnelOption {
                base: build_base(base),
                users: dto.users.map(build_auth_user_list),
                certificate: dto.certificate,
                private_key: dto.private_key,
                client_auth_type: dto.client_auth_type,
                client_auth_cert: dto.client_auth_cert,
                ech_key: dto.ech_key,
                network: dto.network,
                congestion_controller: dto.congestion_controller,
                cwnd: dto.cwnd,
                bbr_profile: dto.bbr_profile,
            };
            Arc::new(TrustTunnel::new(Arc::new(option))?)
        }
        other => return Err(anyhow!("unsupport proxy type: {other}")),
    };

    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hysteria2_realm::server::{DEFAULT_MAX_REALMS, DEFAULT_MAX_REALMS_PER_IP};

    #[test]
    fn parse_listener_accepts_integer_port() {
        let yaml = "name: socks5-in-1\ntype: socks\nport: 10808\n";
        let mapping: Mapping = serde_yaml::from_str(yaml).expect("parse yaml");
        parse_listener(&mapping).expect("integer port should coerce like the WeaklyTypedInput");
    }

    #[test]
    fn parse_listener_applies_hysteria2_realm_defaults() {
        let yaml = "name: realm-in\ntype: hysteria2-realm\ntoken: secret\nport: 8443\n";
        let mapping: Mapping = serde_yaml::from_str(yaml).expect("parse yaml");
        let listener = parse_listener(&mapping).expect("hysteria2-realm listener parses");
        let option: serde_json::Value =
            serde_json::from_str(&listener.config().option_to_string()).expect("option json");
        assert_eq!(option["token"], "secret");
        assert_eq!(option["max_realms"], DEFAULT_MAX_REALMS);
        assert_eq!(option["max_realms_per_ip"], DEFAULT_MAX_REALMS_PER_IP);
        assert_eq!(option["realm_name_pattern"], crate::hysteria2_realm::session::DEFAULT_REALM_NAME_PATTERN);
        assert_eq!(option["alpn"], serde_json::json!(["h2", "http/1.1"]));
    }

    #[test]
    fn parse_listener_requires_a_hysteria2_realm_token() {
        let yaml = "name: realm-in\ntype: hysteria2-realm\nport: 8443\n";
        let mapping: Mapping = serde_yaml::from_str(yaml).expect("parse yaml");
        let Err(err) = parse_listener(&mapping) else {
            panic!("a hysteria2-realm listener without a token must be rejected");
        };
        assert!(err.to_string().contains("has unset fields: token"), "{err}");
    }
}

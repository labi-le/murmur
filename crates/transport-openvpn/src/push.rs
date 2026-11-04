//! The `PUSH_REPLY` message: the options a server pushes to a client, and their parser.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use anyhow::anyhow;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use ipnet::IpNet;
use tokio::time::Instant;

use super::data::PEER_ID_UNSET;

pub const PUSH_REQUEST: &str = "PUSH_REQUEST";

/// The standard base64 alphabet is non-strict: unlike base64 0.22's `STANDARD`, it
/// tolerates non-zero unused bits in the final quantum.
const AUTH_BASE64_STANDARD: GeneralPurpose =
    GeneralPurpose::new(&base64::alphabet::STANDARD, GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true));

/// The non-strict form of the unpadded standard alphabet, which requires no padding and
/// rejects it.
const AUTH_BASE64_RAW_STANDARD: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent OpenVPN push flag or reply-state marker, not a state machine"
)]
#[derive(Clone, Debug, Default)]
pub struct PushReply {
    pub raw: String,
    pub prefixes: Vec<IpNet>,
    pub routes: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub peer_id: u32,
    pub redirect: bool,
    pub block_ipv6: bool,

    /// The list of data channel ciphers pushed by the server via the
    /// "data-ciphers" option (`OpenVPN` 2.5+).
    pub data_ciphers: Vec<String>,

    /// The single cipher pushed by the server via the "cipher" option (legacy
    /// or fallback).
    pub cipher: String,

    /// The most recently pushed auth-token / auth-token-user pair. Empty when
    /// the server does not rotate credentials.
    pub auth_token_user: String,
    pub auth_token_pass: String,

    /// Mirrors `OpenVPN`'s "push-continuation N": 2 marks an intermediate
    /// multi-segment `PUSH_REPLY`, 1 marks the final segment, 0 means a single
    /// segment.
    pub push_continuation: i32,
    /// Distinguishes a parsed `PUSH_REPLY` from standalone control metadata such
    /// as `AUTH_PENDING` carried in the same accumulator.
    pub has_push_reply: bool,

    /// The deferred-auth window advertised by `AUTH_PENDING,timeout` N. Zero when
    /// no `AUTH_PENDING` was seen.
    pub auth_pending_timeout: Duration,
    /// Anchors that window to the TLS key establishment time, preventing delayed
    /// messages or later final `PUSH_REPLY` segments from restarting it.
    pub(crate) auth_pending_until: Option<Instant>,
    /// Distinguishes an explicit timeout of zero from no `AUTH_PENDING` message.
    pub(crate) has_auth_pending: bool,
}

/// Reply skeleton for the parsers and the rekey path. The literal below names every field so one
/// added to [`PushReply`] cannot silently take its default value there.
pub(crate) fn new_push_reply(raw: String, peer_id: u32, has_push_reply: bool) -> PushReply {
    let PushReply {
        prefixes,
        routes,
        dns,
        redirect,
        block_ipv6,
        data_ciphers,
        cipher,
        auth_token_user,
        auth_token_pass,
        push_continuation,
        auth_pending_timeout,
        auth_pending_until,
        has_auth_pending,
        ..
    } = PushReply::default();
    PushReply {
        raw,
        prefixes,
        routes,
        dns,
        peer_id,
        redirect,
        block_ipv6,
        data_ciphers,
        cipher,
        auth_token_user,
        auth_token_pass,
        push_continuation,
        has_push_reply,
        auth_pending_timeout,
        auth_pending_until,
        has_auth_pending,
    }
}

pub fn parse_push_reply(message: &str) -> anyhow::Result<PushReply> {
    let reply = parse_push_reply_inner(message)?;
    if reply.prefixes.is_empty() {
        return Err(anyhow!("openvpn push reply missing ifconfig address"));
    }
    Ok(reply)
}

pub(crate) fn parse_push_reply_inner(message: &str) -> anyhow::Result<PushReply> {
    let message = message.trim_end_matches('\0');
    if !message.starts_with("PUSH_REPLY") {
        return Err(anyhow!("unexpected openvpn push message {message:?}"));
    }
    let mut reply = new_push_reply(message.to_owned(), PEER_ID_UNSET, true);
    for option in split_push_options(message) {
        let fields: Vec<&str> = option.split_whitespace().collect();
        let Some((command, args)) = fields.split_first() else {
            continue;
        };
        match *command {
            "ifconfig" => {
                if let [address, mask, ..] = args {
                    reply.prefixes.push(parse_ipv4_ifconfig(address, mask)?);
                }
            }
            "ifconfig-ipv6" => {
                if let [address, ..] = args {
                    let prefix = address
                        .parse::<IpNet>()
                        .map_err(|err| anyhow!("parse pushed ipv6 address {address:?}: {err}"))?;
                    reply.prefixes.push(prefix);
                }
            }
            "route" => {
                if let [network, mask, ..] = args {
                    if let Ok(prefix) = parse_ipv4_route(network, mask) {
                        reply.routes.push(prefix);
                    }
                }
            }
            "route-ipv6" => {
                if let [network, ..] = args {
                    if let Ok(prefix) = network.parse::<IpNet>() {
                        reply.routes.push(prefix);
                    }
                }
            }
            "dhcp-option" => {
                if let [kind, address, ..] = args {
                    if *kind == "DNS" {
                        if let Ok(addr) = address.parse::<IpAddr>() {
                            reply.dns.push(addr);
                        }
                    }
                }
            }
            "peer-id" => {
                if let [raw_id, ..] = args {
                    let id = parse_uint24(raw_id).map_err(|err| anyhow!("parse pushed peer-id {raw_id:?}: {err}"))?;
                    reply.peer_id = id;
                }
            }
            "redirect-gateway" => {
                reply.redirect = true;
            }
            "block-ipv6" => {
                reply.block_ipv6 = true;
            }
            "data-ciphers" | "ncp-ciphers" => {
                if let [ciphers, ..] = args {
                    for c in ciphers.split(':') {
                        let c = c.trim();
                        if !c.is_empty() {
                            reply.data_ciphers.push(c.to_owned());
                        }
                    }
                }
            }
            "cipher" => {
                if let [cipher, ..] = args {
                    cipher.trim().clone_into(&mut reply.cipher);
                }
            }
            "auth-token" => {
                if let [token, ..] = args {
                    token.trim().clone_into(&mut reply.auth_token_pass);
                }
            }
            "auth-token-user" => {
                if let [token, ..] = args {
                    let user = decode_auth_token_user(token).map_err(|err| anyhow!("decode auth-token-user: {err}"))?;
                    reply.auth_token_user = user;
                }
            }
            "push-continuation" => {
                let [value] = args else {
                    return Err(anyhow!("invalid push-continuation"));
                };
                let n = value.parse::<i32>().ok().filter(|n| (0..=2).contains(n));
                let Some(n) = n else {
                    return Err(anyhow!("invalid push-continuation {value:?}"));
                };
                reply.push_continuation = n;
            }
            _ => {}
        }
    }
    Ok(reply)
}

impl PushReply {
    #[must_use]
    pub fn auth_token(&self) -> Option<(String, String)> {
        if self.auth_token_pass.is_empty() {
            return None;
        }
        Some((self.auth_token_user.clone(), self.auth_token_pass.clone()))
    }
}

pub(crate) fn decode_auth_token_user(raw: &str) -> anyhow::Result<String> {
    let raw = raw.trim();
    decode_base64_auth(raw)
}

pub(crate) fn decode_base64_auth(raw: &str) -> anyhow::Result<String> {
    let data = match AUTH_BASE64_STANDARD.decode(raw) {
        Ok(data) => data,
        Err(_) => AUTH_BASE64_RAW_STANDARD.decode(raw)?,
    };
    Ok(String::from_utf8_lossy(&data).into_owned())
}

pub(crate) fn split_push_options(message: &str) -> Vec<String> {
    let message = message.trim_end_matches('\0');
    let mut parts: Vec<&str> = message.split(',').collect();
    if parts.first() == Some(&"PUSH_REPLY") {
        parts.remove(0);
    }
    let mut out = Vec::new();
    for part in parts {
        let part = part.trim();
        if !part.is_empty() {
            out.push(part.to_owned());
        }
    }
    out
}

pub(crate) fn parse_ipv4_ifconfig(address: &str, mask_or_peer: &str) -> anyhow::Result<IpNet> {
    let addr = address.parse::<IpAddr>().map_err(|err| anyhow!("parse pushed ipv4 address {address:?}: {err}"))?;
    let mask_addr =
        mask_or_peer.parse::<IpAddr>().map_err(|err| anyhow!("parse pushed ipv4 mask {mask_or_peer:?}: {err}"))?;
    let (IpAddr::V4(addr), IpAddr::V4(mask_addr)) = (addr, mask_addr) else {
        return Err(anyhow!("openvpn ifconfig requires ipv4 address and mask"));
    };

    if let Some(ones) = ipv4_mask_size(mask_addr) {
        return Ok(IpNet::new_assert(IpAddr::V4(addr), ones));
    }

    // Some servers, including SoftEther/VPNGate in net30/p2p mode, push
    // "ifconfig <local> <remote>" rather than "ifconfig <local> <netmask>".
    // Use a host prefix for that local tunnel address.
    Ok(IpNet::new_assert(IpAddr::V4(addr), 32))
}

pub(crate) fn parse_ipv4_route(network: &str, mask: &str) -> anyhow::Result<IpNet> {
    let addr = network.parse::<IpAddr>().map_err(|err| anyhow!("parse route network {network:?}: {err}"))?;
    let mask_addr = mask.parse::<IpAddr>().map_err(|err| anyhow!("parse route mask {mask:?}: {err}"))?;
    let (IpAddr::V4(addr), IpAddr::V4(mask_addr)) = (addr, mask_addr) else {
        return Err(anyhow!("openvpn route requires ipv4 address and mask"));
    };
    let Some(ones) = ipv4_mask_size(mask_addr) else {
        return Err(anyhow!("invalid route mask {mask:?}"));
    };
    Ok(IpNet::new_assert(IpAddr::V4(addr), ones))
}

pub(crate) fn parse_uint24(raw: &str) -> anyhow::Result<u32> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(anyhow!("invalid integer syntax: {raw:?}"));
    }
    match raw.parse::<u32>() {
        Ok(id) if id <= 0x00ff_ffff => Ok(id),
        _ => Err(anyhow!("integer out of range: {raw:?}")),
    }
}

pub(crate) fn ipv4_mask_size(mask: Ipv4Addr) -> Option<u8> {
    let mask_bytes = mask.octets();
    let mut ones: u8 = 0;
    let mut seen_zero = false;
    for b in mask_bytes {
        for i in (0..8u32).rev() {
            if b & (1u8 << i) == 0 {
                seen_zero = true;
                continue;
            }
            if seen_zero {
                return None;
            }
            ones += 1;
        }
    }
    Some(ones)
}

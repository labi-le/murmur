use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::obfs::sudoku::ascii_mode::normalize_ascii_mode;
use crate::obfs::sudoku::table::Table;

/// Defines the configuration for the Sudoku protocol stack.
/// It is intentionally kept close to the Sudoku wire format to ensure compatibility.
#[derive(Debug, Clone, Default)]
pub struct ProtocolConfig {
    /// Client-only: "host:port".
    pub server_address: String,

    /// Pre-shared key (or ED25519 key material) used to derive crypto and tables.
    pub key: String,

    /// "aes-128-gcm", "chacha20-poly1305", or "none".
    pub aead_method: String,

    /// The single obfuscation table to use when table rotation is disabled.
    pub table: Option<Arc<Table>>,

    /// An optional candidate set for table rotation.
    /// If provided (non-empty), the client will pick one table per connection and the server will
    /// probe the handshake to detect which one was used, keeping the handshake format unchanged.
    /// When `tables` is set, `table` may be `None`.
    pub tables: Vec<Arc<Table>>,

    /// Padding insertion ratio (0-100). Must satisfy `padding_max >= padding_min`.
    pub padding_min: i32,
    pub padding_max: i32,

    /// Enables the pure Sudoku downlink mode.
    /// When false, the connection uses the bandwidth-optimized packed downlink.
    pub enable_pure_downlink: bool,

    /// Client-only: final target "host:port".
    pub target_address: String,

    /// Server-side handshake timeout (seconds).
    pub handshake_timeout_seconds: i32,

    /// Disables all HTTP camouflage layers.
    pub disable_http_mask: bool,

    /// Controls how the HTTP layer behaves:
    ///   - "legacy": write a fake HTTP/1.1 header then switch to raw stream (default, not CDN-compatible)
    ///   - "stream": real HTTP tunnel (split-stream), CDN-compatible
    ///   - "poll": plain HTTP tunnel (authorize/push/pull), strong restricted-network pass-through
    ///   - "auto": try stream then fall back to poll
    ///   - "ws": WebSocket tunnel (GET upgrade), CDN-friendly
    pub http_mask_mode: String,

    /// Enables HTTPS for HTTP tunnel modes (client-side).
    /// If false, the tunnel uses HTTP (no port-based inference).
    pub http_mask_tls_enabled: bool,

    /// Optionally overrides the HTTP Host header / SNI host for HTTP tunnel modes (client-side).
    pub http_mask_host: String,

    /// Optionally prefixes all HTTP mask paths with a first-level segment.
    /// Example: "aabbcc" => "/aabbcc/session", "/aabbcc/api/v1/upload", ...
    pub http_mask_path_root: String,

    /// Controls transport reuse and Sudoku session mux:
    ///   - "off": disable session mux and `HTTPMask` transport reuse
    ///   - "auto": enable `HTTPMask` transport reuse only
    ///   - "on": enable session mux over raw TCP or `HTTPMask`
    pub multiplex: String,

    /// The legacy location for `multiplex`.
    /// When both fields are set, this legacy field wins for compatibility.
    pub http_mask_multiplex: String,
}

impl ProtocolConfig {
    pub fn validate(&self) -> Result<()> {
        if self.table.is_none() && self.tables.is_empty() {
            return Err(anyhow!("table cannot be nil (or provide tables)"));
        }

        match self.aead_method.as_str() {
            "aes-128-gcm" | "chacha20-poly1305" | "none" => {}
            other => {
                return Err(anyhow!(
                    "invalid aead-method: {other}, must be one of: aes-128-gcm, chacha20-poly1305, none"
                ))
            }
        }

        if !(0..=100).contains(&self.padding_min) {
            return Err(anyhow!("padding-min must be between 0 and 100, got {}", self.padding_min));
        }
        if !(0..=100).contains(&self.padding_max) {
            return Err(anyhow!("padding-max must be between 0 and 100, got {}", self.padding_max));
        }
        if self.padding_max < self.padding_min {
            return Err(anyhow!("padding-max ({}) must be >= padding-min ({})", self.padding_max, self.padding_min));
        }

        if self.handshake_timeout_seconds < 0 {
            return Err(anyhow!("handshake-timeout must be >= 0, got {}", self.handshake_timeout_seconds));
        }

        match self.http_mask_mode.trim().to_lowercase().as_str() {
            "" | "legacy" | "stream" | "poll" | "auto" | "ws" => {}
            other => {
                return Err(anyhow!("invalid http-mask-mode: {other}, must be one of: legacy, stream, poll, auto, ws"))
            }
        }

        let v = self.http_mask_path_root.trim();
        if !v.is_empty() {
            let v = v.trim_matches('/');
            if v.is_empty() || v.contains('/') {
                return Err(anyhow!("invalid http-mask-path-root: must be a single path segment"));
            }
            for ch in v.chars() {
                match ch {
                    'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => {}
                    other => return Err(anyhow!("invalid http-mask-path-root: contains invalid character {other:?}")),
                }
            }
        }

        normalize_multiplex_mode(&self.multiplex).map_err(|err| anyhow!("invalid multiplex: {err}"))?;
        normalize_multiplex_mode(&self.http_mask_multiplex)
            .map_err(|err| anyhow!("invalid http-mask-multiplex: {err}"))?;

        Ok(())
    }

    pub fn validate_client(&self) -> Result<()> {
        self.validate()?;
        if self.server_address.is_empty() {
            return Err(anyhow!("server address cannot be empty"));
        }
        if self.target_address.is_empty() {
            return Err(anyhow!("target address cannot be empty"));
        }
        Ok(())
    }

    #[must_use]
    pub fn multiplex_mode(&self) -> String {
        for mode in [&self.http_mask_multiplex, &self.multiplex] {
            if mode.trim().is_empty() {
                continue;
            }
            return normalize_multiplex_mode(mode).unwrap_or_else(|_| "off".to_owned());
        }
        "off".to_owned()
    }

    #[must_use]
    pub fn session_mux_enabled(&self) -> bool {
        self.multiplex_mode() == "on"
    }

    pub(crate) fn table_candidates(&self) -> Vec<Arc<Table>> {
        if !self.tables.is_empty() {
            return self.tables.clone();
        }
        if let Some(table) = &self.table {
            return vec![Arc::clone(table)];
        }
        Vec::new()
    }
}

#[must_use]
pub fn default_config() -> ProtocolConfig {
    let ProtocolConfig {
        server_address,
        key,
        table,
        tables,
        target_address,
        disable_http_mask,
        http_mask_tls_enabled,
        http_mask_host,
        http_mask_path_root,
        http_mask_multiplex,
        ..
    } = ProtocolConfig::default();
    ProtocolConfig {
        server_address,
        key,
        aead_method: "chacha20-poly1305".to_owned(),
        table,
        tables,
        padding_min: 10,
        padding_max: 30,
        enable_pure_downlink: true,
        target_address,
        handshake_timeout_seconds: 5,
        disable_http_mask,
        http_mask_mode: "legacy".to_owned(),
        http_mask_tls_enabled,
        http_mask_host,
        http_mask_path_root,
        multiplex: "off".to_owned(),
        http_mask_multiplex,
    }
}

pub(crate) fn normalize_multiplex_mode(mode: &str) -> Result<String> {
    match mode.trim().to_lowercase().as_str() {
        "" | "off" => Ok("off".to_owned()),
        "auto" => Ok("auto".to_owned()),
        "on" => Ok("on".to_owned()),
        _ => Err(anyhow!("{mode:?}, must be one of: off, auto, on")),
    }
}

#[must_use]
pub fn deref_int(v: Option<i32>, def: i32) -> i32 {
    v.unwrap_or(def)
}

#[must_use]
pub fn deref_bool(v: Option<bool>, def: bool) -> bool {
    v.unwrap_or(def)
}

/// `ResolvePadding`: applies defaults and keeps min/max consistent when only one side is
/// provided.
#[must_use]
pub fn resolve_padding(min: Option<i32>, max: Option<i32>, def_min: i32, def_max: i32) -> (i32, i32) {
    let mut padding_min = deref_int(min, def_min);
    let mut padding_max = deref_int(max, def_max);
    let (min_given, max_given) = (min.is_some(), max.is_some());
    if padding_max < padding_min {
        if max_given && !min_given {
            padding_min = padding_max;
        } else if min_given && !max_given {
            padding_max = padding_min;
        }
    }
    (padding_min, padding_max)
}

pub fn normalize_table_type(table_type: &str) -> Result<String> {
    normalize_ascii_mode(table_type).map_err(|_| {
        anyhow!("table-type must be prefer_ascii, prefer_entropy, up_ascii_down_entropy, or up_entropy_down_ascii")
    })
}

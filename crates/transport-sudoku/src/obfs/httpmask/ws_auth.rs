use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::tunnel_api::TunnelMode;

pub(crate) const TUNNEL_AUTH_HEADER_PREFIX: &str = "Bearer ";
pub(crate) const TUNNEL_AUTH_QUERY_KEY: &str = "auth";

/// `TunnelAuth` is intentionally used only by the WebSocket transport. The stream and poll
/// transports already have a cryptographic Sudoku handshake; duplicating it at the HTTP layer
/// adds latency and another compatibility surface without improving tunnel security.
pub(crate) struct TunnelAuth {
    key: [u8; 32],
    skew: Duration,
}

impl TunnelAuth {
    pub(crate) fn new(key: &str, skew: Duration) -> Option<Self> {
        let key = key.trim();
        if key.is_empty() {
            return None;
        }
        let skew = if skew.is_zero() { Duration::from_secs(60) } else { skew };

        let mut hasher = Sha256::new();
        hasher.update(b"sudoku-httpmask-auth-v1:");
        hasher.update(key.as_bytes());
        let sum: [u8; 32] = hasher.finalize().into();

        Some(Self { key: sum, skew })
    }

    pub(crate) fn token(
        &self,
        mode: TunnelMode,
        method: &str,
        path: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> String {
        let ts = now.timestamp();
        let sig = self.sign(mode, method, path, ts);

        let mut buf = [0u8; 8 + 16];
        buf[..8].copy_from_slice(&ts.to_be_bytes());
        buf[8..].copy_from_slice(&sig);
        URL_SAFE_NO_PAD.encode(buf)
    }

    pub(crate) fn verify_value(
        &self,
        val: &str,
        mode: TunnelMode,
        method: &str,
        path: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let mut val = val.trim();
        if val.is_empty() {
            return false;
        }

        if val.len() > TUNNEL_AUTH_HEADER_PREFIX.len() {
            if let Some(prefix) = val.get(..TUNNEL_AUTH_HEADER_PREFIX.len()) {
                if prefix.eq_ignore_ascii_case(TUNNEL_AUTH_HEADER_PREFIX) {
                    val = val.get(TUNNEL_AUTH_HEADER_PREFIX.len()..).unwrap_or_default().trim();
                }
            }
        }
        if val.is_empty() {
            return false;
        }

        let Ok(raw) = URL_SAFE_NO_PAD.decode(val) else {
            return false;
        };
        if raw.len() != 8 + 16 {
            return false;
        }

        let (Some(ts_bytes), Some(sig)) = (raw.get(..8), raw.get(8..)) else {
            return false;
        };
        let Ok(ts_bytes) = <[u8; 8]>::try_from(ts_bytes) else {
            return false;
        };
        let ts = i64::from_be_bytes(ts_bytes);
        let now_ts = now.timestamp();
        let delta = now_ts.abs_diff(ts);
        if delta > self.skew.as_secs() {
            return false;
        }

        let want = self.sign(mode, method, path, ts);
        sig.ct_eq(&want).into()
    }

    fn sign(&self, mode: TunnelMode, method: &str, path: &str, ts: i64) -> [u8; 16] {
        let method = method.trim().to_uppercase();
        let method = if method.is_empty() { "GET".to_owned() } else { method };
        let path = path.trim();

        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.key) else {
            return [0u8; 16];
        };
        mac.update(mode.as_str().as_bytes());
        mac.update(&[0]);
        mac.update(method.as_bytes());
        mac.update(&[0]);
        mac.update(path.as_bytes());
        mac.update(&[0]);
        mac.update(&ts.to_be_bytes());

        let full: [u8; 32] = mac.finalize().into_bytes().into();
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }
}

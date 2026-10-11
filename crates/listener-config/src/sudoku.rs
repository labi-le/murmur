use serde::{Deserialize, Serialize};

use murmur_listener_sing::sing::MuxOption;

/// `SudokuServer` describes a Sudoku inbound server configuration.
/// It is internal to the listener layer and mainly used for logging and wiring.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SudokuServer {
    #[serde(rename = "enable")]
    pub enable: bool,
    #[serde(rename = "listen")]
    pub listen: String,
    #[serde(rename = "key")]
    pub key: String,
    #[serde(rename = "aead-method", default, skip_serializing_if = "String::is_empty")]
    pub aead_method: String,
    #[serde(rename = "padding-min", default, skip_serializing_if = "Option::is_none")]
    pub padding_min: Option<i32>,
    #[serde(rename = "padding-max", default, skip_serializing_if = "Option::is_none")]
    pub padding_max: Option<i32>,
    #[serde(rename = "table-type", default, skip_serializing_if = "String::is_empty")]
    pub table_type: String,
    #[serde(rename = "handshake-timeout", default, skip_serializing_if = "Option::is_none")]
    pub handshake_timeout_second: Option<i32>,
    #[serde(rename = "enable-pure-downlink", default, skip_serializing_if = "Option::is_none")]
    pub enable_pure_downlink: Option<bool>,
    #[serde(rename = "custom-table", default, skip_serializing_if = "String::is_empty")]
    pub custom_table: String,
    #[serde(rename = "custom-tables", default, skip_serializing_if = "Vec::is_empty")]
    pub custom_tables: Vec<String>,
    #[serde(rename = "disable-http-mask", default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_http_mask: bool,
    #[serde(rename = "http-mask-mode", default, skip_serializing_if = "String::is_empty")]
    pub http_mask_mode: String,
    #[serde(rename = "path-root", default, skip_serializing_if = "String::is_empty")]
    pub path_root: String,
    #[serde(rename = "fallback", default, skip_serializing_if = "String::is_empty")]
    pub fallback: String,

    /// A private extension (not part of the standard Sudoku protocol).
    #[serde(rename = "mux-option", default)]
    pub mux_option: MuxOption,
}

impl std::fmt::Display for SudokuServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(_) => Ok(()),
        }
    }
}

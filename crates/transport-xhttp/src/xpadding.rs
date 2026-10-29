use rand::Rng;

use super::config::{
    Config, Cookie, Request, PLACEMENT_COOKIE, PLACEMENT_HEADER, PLACEMENT_QUERY, PLACEMENT_QUERY_IN_HEADER,
};

/// `PaddingMethod`. Kept as a string newtype (not a closed enum) because unlisted values fall
/// through to a `default:` case in every `switch` over it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PaddingMethod(pub String);

pub const PADDING_METHOD_REPEAT_X: &str = "repeat-x";
pub const PADDING_METHOD_TOKENISH: &str = "tokenish";

const CHARSET_BASE62: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Huffman encoding gives ~20% size reduction for base62 sequences.
const AVG_HUFFMAN_BYTES_PER_CHAR_BASE62: f64 = 0.8;

const VALIDATION_TOLERANCE: i64 = 2;

#[derive(Clone, Debug, Default)]
pub struct XPaddingPlacement {
    pub placement: String,
    pub key: String,
    pub header: String,
    pub raw_url: String,
}

#[derive(Clone, Debug, Default)]
pub struct XPaddingConfig {
    pub length: i64,
    pub placement: XPaddingPlacement,
    pub method: PaddingMethod,
}

/// RFC 7541 Appendix B canonical Huffman code lengths per byte value (shared by HPACK and QPACK).
const HUFFMAN_CODE_LEN: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12,
    10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6,
    5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22,
    22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20,
    22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28,
    27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28,
    27, 27, 27, 27, 27, 26,
];

/// The number of bytes required to encode `s` in the RFC 7541 static Huffman code, rounded up to
/// a byte boundary.
fn huffman_encode_length(s: &str) -> u64 {
    let bits: u64 =
        s.bytes().map(|b| u64::from(HUFFMAN_CODE_LEN.get(usize::from(b)).copied().unwrap_or_default())).sum();
    bits.div_ceil(8)
}

fn rand_string_from_charset(n: i64, charset: &str) -> Option<String> {
    if n <= 0 || charset.is_empty() {
        return None;
    }

    let charset_bytes = charset.as_bytes();
    let m = charset_bytes.len();
    let limit = u8::try_from(256usize - (256usize % m)).unwrap_or_default();

    let n = usize::try_from(n).ok()?;
    let mut result = vec![0u8; n];
    let mut i = 0usize;
    let mut buf = [0u8; 256];
    while i < n {
        rand::rng().fill(&mut buf);
        for &rb in &buf {
            if rb >= limit {
                continue;
            }
            let Some(slot) = result.get_mut(i) else {
                break;
            };
            *slot = charset_bytes.get(usize::from(rb) % m).copied().unwrap_or_default();
            i += 1;
            if i == n {
                break;
            }
        }
    }

    Some(String::from_utf8(result).unwrap_or_default())
}

#[must_use]
pub fn generate_tokenish_padding_base62(target_huffman_bytes: i64) -> String {
    const MAX_ITER: i32 = 150;

    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        reason = "the byte target is far inside f64's exact integer range, so the ceiling is exact"
    )]
    let mut n = (target_huffman_bytes as f64 / AVG_HUFFMAN_BYTES_PER_CHAR_BASE62).ceil() as i64;
    if n < 1 {
        n = 1;
    }

    let Some(mut rand_base62_str) = rand_string_from_charset(n, CHARSET_BASE62) else {
        return String::new();
    };

    let mut adjust_char = b'X';

    for _ in 0..MAX_ITER {
        let current_length = huffman_encode_length(&rand_base62_str).cast_signed();
        let diff = current_length - target_huffman_bytes;

        if diff.abs() <= VALIDATION_TOLERANCE {
            return rand_base62_str;
        }

        if diff < 0 {
            rand_base62_str.push(adjust_char as char);
            adjust_char = if adjust_char == b'X' { b'Z' } else { b'X' };
        } else {
            if rand_base62_str.len() <= 1 {
                return rand_base62_str;
            }
            rand_base62_str.pop();
        }
    }

    rand_base62_str
}

#[must_use]
pub fn generate_padding(method: &PaddingMethod, length: i64) -> String {
    if length <= 0 {
        return String::new();
    }
    let Ok(len) = usize::try_from(length) else {
        return String::new();
    };

    match method.0.as_str() {
        PADDING_METHOD_TOKENISH => {
            let padding_value = generate_tokenish_padding_base62(length);
            if padding_value.is_empty() {
                "X".repeat(len)
            } else {
                padding_value
            }
        }
        _ => "X".repeat(len),
    }
}

pub fn apply_padding_to_cookie(req: Option<&mut Request>, name: &str, value: &str) {
    if name.is_empty() || value.is_empty() {
        return;
    }
    let Some(req) = req else {
        return;
    };
    req.add_cookie(&Cookie { name: name.to_owned(), value: value.to_owned() });
}

pub fn apply_padding_to_response_cookie(response_header: &mut http::HeaderMap, name: &str, value: &str) {
    if name.is_empty() || value.is_empty() {
        return;
    }
    super::config::set_response_cookie(response_header, name, value, "/");
}

pub fn apply_padding_to_query(u: Option<&mut url::Url>, key: &str, value: &str) {
    if key.is_empty() || value.is_empty() {
        return;
    }
    let Some(u) = u else {
        return;
    };
    u.query_pairs_mut().append_pair(key, value);
}

impl Config {
    pub fn normalized_x_padding_bytes(&self) -> anyhow::Result<super::config::Range> {
        super::config::parse_range(&self.x_padding_bytes, "100-1000")
            .map_err(|e| anyhow::anyhow!("invalid x-padding-bytes: {e}"))
    }

    pub fn apply_x_padding_to_header(&self, h: &mut http::HeaderMap, config: &XPaddingConfig) {
        let padding_value = generate_padding(&config.method, config.length);

        match config.placement.placement.as_str() {
            PLACEMENT_HEADER => {
                if let (Ok(name), Ok(value)) = (
                    http::HeaderName::from_bytes(config.placement.header.as_bytes()),
                    http::HeaderValue::from_str(&padding_value),
                ) {
                    h.insert(name, value);
                }
            }
            PLACEMENT_QUERY_IN_HEADER => {
                let Ok(mut u) = url::Url::parse(&config.placement.raw_url) else {
                    return;
                };
                u.set_query(Some(&format!("{}={}", config.placement.key, padding_value)));
                if let (Ok(name), Ok(value)) = (
                    http::HeaderName::from_bytes(config.placement.header.as_bytes()),
                    http::HeaderValue::from_str(u.as_str()),
                ) {
                    h.insert(name, value);
                }
            }
            _ => {}
        }
    }

    pub fn apply_x_padding_to_request(&self, req: &mut Request, config: &XPaddingConfig) {
        let placement = config.placement.placement.as_str();

        if placement == PLACEMENT_HEADER || placement == PLACEMENT_QUERY_IN_HEADER {
            self.apply_x_padding_to_header(&mut req.header, config);
            return;
        }

        let padding_value = generate_padding(&config.method, config.length);

        match placement {
            PLACEMENT_COOKIE => apply_padding_to_cookie(Some(req), &config.placement.key, &padding_value),
            PLACEMENT_QUERY => {
                let mut url = req.url.clone();
                apply_padding_to_query(Some(&mut url), &config.placement.key, &padding_value);
                req.url = url;
            }
            _ => {}
        }
    }

    pub fn apply_x_padding_to_response(&self, response_header: &mut http::HeaderMap, config: &XPaddingConfig) {
        let placement = config.placement.placement.as_str();

        if placement == PLACEMENT_HEADER || placement == PLACEMENT_QUERY_IN_HEADER {
            self.apply_x_padding_to_header(response_header, config);
            return;
        }

        let padding_value = generate_padding(&config.method, config.length);

        if placement == PLACEMENT_COOKIE {
            apply_padding_to_response_cookie(response_header, &config.placement.key, &padding_value);
        }
    }

    pub fn extract_x_padding_from_request(&self, req: &Request, obfs_mode: bool) -> (String, String) {
        if !obfs_mode {
            let referrer = req.header.get(http::header::REFERER).and_then(|v| v.to_str().ok()).unwrap_or("");

            if referrer.is_empty() {
                let padding_value = req
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "x_padding")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
                return (padding_value, format!("{PLACEMENT_QUERY}, key=x_padding"));
            }
            if let Ok(referrer_url) = url::Url::parse(referrer) {
                let padding_value = referrer_url
                    .query_pairs()
                    .find(|(k, _)| k == "x_padding")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
                let padding_placement = format!("{PLACEMENT_QUERY_IN_HEADER}=Referer, key=x_padding");
                return (padding_value, padding_placement);
            }
        }

        let key = &self.x_padding_key;
        let header = &self.x_padding_header;

        if let Some(cookie) = req.cookie(key) {
            if !cookie.value.is_empty() {
                let padding_value = cookie.value;
                let padding_placement = format!("{PLACEMENT_COOKIE}, key={key}");
                return (padding_value, padding_placement);
            }
        }

        let header_value = req.header.get(header.as_str()).and_then(|v| v.to_str().ok()).unwrap_or("");

        if !header_value.is_empty() {
            if self.x_padding_placement == PLACEMENT_HEADER {
                let padding_placement = format!("{PLACEMENT_HEADER}={header}");
                return (header_value.to_owned(), padding_placement);
            }

            if let Ok(parsed_url) = url::Url::parse(header_value) {
                let padding_placement = format!("{PLACEMENT_QUERY_IN_HEADER}={header}, key={key}");
                let value = parsed_url
                    .query_pairs()
                    .find(|(k, _)| k == key.as_str())
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
                return (value, padding_placement);
            }
        }

        let query_value =
            req.url.query_pairs().find(|(k, _)| k == key.as_str()).map(|(_, v)| v.into_owned()).unwrap_or_default();

        if !query_value.is_empty() {
            let padding_placement = format!("{PLACEMENT_QUERY}, key={key}");
            return (query_value, padding_placement);
        }

        (String::new(), String::new())
    }

    #[must_use]
    pub fn is_padding_valid(&self, padding_value: &str, mut from: i64, mut to: i64, method: &PaddingMethod) -> bool {
        if padding_value.is_empty() {
            return false;
        }
        if to <= 0 {
            if let Ok(r) = self.normalized_x_padding_bytes() {
                from = r.min;
                to = r.max;
            }
        }

        if method.0.as_str() == PADDING_METHOD_TOKENISH {
            let n = huffman_encode_length(padding_value).cast_signed();
            let f = (from - VALIDATION_TOLERANCE).max(0);
            let t = to + VALIDATION_TOLERANCE;
            n >= f && n <= t
        } else {
            let n = i64::try_from(padding_value.len()).unwrap_or(i64::MAX);
            n >= from && n <= to
        }
    }
}

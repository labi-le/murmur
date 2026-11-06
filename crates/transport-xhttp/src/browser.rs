use chrono::{TimeZone, Utc};
use rand::Rng;

#[expect(
    clippy::cast_possible_truncation,
    reason = "the draw is scaled to at most 165, so the floored value fits an i64 exactly"
)]
fn floor_draw(power: i32, scale: f64) -> i64 {
    (rand::rng().random::<f64>().powi(power) * scale).floor() as i64
}

/// The Chrome version generator suffers from deviation of a normal
/// distribution.
#[must_use]
pub fn chrome_version() -> i64 {
    let start_version: i64 = 144;
    let time_start = Utc.with_ymd_and_hms(2026, 1, 13, 0, 0, 0).unwrap().timestamp() / 86400;
    let time_current = Utc::now().timestamp() / 86400;
    let time_diff = (time_current - time_start - 35) - floor_draw(2, 105.0);
    start_version + (time_diff / 35)
}

const SAFARI_MINOR_MAP: [i64; 25] = [0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6];

/// The following version generators use deterministic generators, but with the
/// distribution scaled by a curve.
#[must_use]
pub fn curl_version() -> String {
    let time_current = Utc::now().timestamp() / 86400;
    let time_start = Utc.with_ymd_and_hms(2023, 3, 20, 0, 0, 0).unwrap().timestamp() / 86400;
    let time_diff = (time_current - time_start - 60) - floor_draw(2, 165.0);
    let minor_value = time_diff / 57;
    format!("8.{minor_value}.0")
}

#[must_use]
pub fn firefox_version() -> i64 {
    let time_current = Utc::now().timestamp() / 86400;
    let time_start = Utc.with_ymd_and_hms(2024, 7, 29, 0, 0, 0).unwrap().timestamp() / 86400;
    let time_diff = time_current - time_start - 25 - floor_draw(2, 50.0);
    (time_diff / 30) + 128
}

#[must_use]
pub fn safari_version() -> String {
    let anchored_time = Utc::now();
    let mut release_year = chrono::Datelike::year(&anchored_time);
    let delayed_days = floor_draw(3, 75.0);
    let mut split_point =
        Utc.with_ymd_and_hms(release_year, 9, 23, 0, 0, 0).unwrap() + chrono::Duration::days(delayed_days);

    if anchored_time < split_point {
        release_year -= 1;
        split_point =
            Utc.with_ymd_and_hms(release_year, 9, 23, 0, 0, 0).unwrap() + chrono::Duration::days(delayed_days);
    }

    let minor_index = (anchored_time.timestamp() - split_point.timestamp()) / 1_296_000;
    let minor_version =
        usize::try_from(minor_index).ok().and_then(|i| SAFARI_MINOR_MAP.get(i)).copied().unwrap_or_default();
    format!("{}.{minor_version}", release_year - 1999)
}

/// The full Chromium brand GREASE implementation.
const CLIENT_HINT_GREASE_NA: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
const CLIENT_HINT_VERSION_NA: [&str; 3] = ["8", "99", "24"];
const CLIENT_HINT_SHUFFLE3: [[usize; 3]; 6] = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
const CLIENT_HINT_SHUFFLE4: [[usize; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

fn get_greased_ch_invalid_brand(seed: i64) -> String {
    let seed = usize::try_from(seed.max(0)).unwrap_or_default();
    let na = CLIENT_HINT_GREASE_NA.get(seed % CLIENT_HINT_GREASE_NA.len()).copied().unwrap_or_default();
    let na_next = CLIENT_HINT_GREASE_NA.get((seed + 1) % CLIENT_HINT_GREASE_NA.len()).copied().unwrap_or_default();
    let version = CLIENT_HINT_VERSION_NA.get(seed % CLIENT_HINT_VERSION_NA.len()).copied().unwrap_or_default();
    format!("\"Not{na}A{na_next}Brand\";v=\"{version}\"")
}

fn get_greased_ch_order(brand_length: usize, seed: i64) -> Vec<usize> {
    let seed = usize::try_from(seed.max(0)).unwrap_or_default();
    match brand_length {
        1 => vec![0],
        2 => vec![seed % brand_length, (seed + 1) % brand_length],
        3 => CLIENT_HINT_SHUFFLE3.get(seed % CLIENT_HINT_SHUFFLE3.len()).copied().unwrap_or_default().to_vec(),
        _ => CLIENT_HINT_SHUFFLE4.get(seed % CLIENT_HINT_SHUFFLE4.len()).copied().unwrap_or_default().to_vec(),
    }
}

fn get_ungreased_ch_ua(major_version: i64, fork_name: &str) -> Vec<String> {
    let mut base_ch_ua = Vec::with_capacity(4);
    base_ch_ua.push(get_greased_ch_invalid_brand(major_version));
    base_ch_ua.push(format!("\"Chromium\";v=\"{major_version}\""));
    match fork_name {
        "chrome" => base_ch_ua.push(format!("\"Google Chrome\";v=\"{major_version}\"")),
        "edge" => base_ch_ua.push(format!("\"Microsoft Edge\";v=\"{major_version}\"")),
        _ => {}
    }
    base_ch_ua
}

fn get_greased_ch_ua(major_version: i64, fork_name: &str) -> String {
    let ungreased_ch = get_ungreased_ch_ua(major_version, fork_name);
    let shuffle_map = get_greased_ch_order(ungreased_ch.len(), major_version);
    let mut shuffled_ch = vec![String::new(); ungreased_ch.len()];
    // `shuffle_map` is a permutation of `0..len`, so every entry lands in a slot.
    for (entry, slot) in ungreased_ch.into_iter().zip(shuffle_map) {
        if let Some(dst) = shuffled_ch.get_mut(slot) {
            *dst = entry;
        }
    }
    shuffled_ch.join(", ")
}

/// The code below provides a coherent default browser user agent string based on a CPU-seeded
/// PRNG.
///
/// `std::sync::LazyLock` stands in for the package-level `var` initializers, which run once at
/// program start.
pub static CURL_UA: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| format!("curl/{}", curl_version()));
pub static ANCHORED_FIREFOX_VERSION: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| firefox_version().to_string());
pub static FIREFOX_UA: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{0}.0) Gecko/20100101 Firefox/{0}.0",
        *ANCHORED_FIREFOX_VERSION
    )
});
pub static SAFARI_UA: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{} Safari/605.1.15", safari_version())
});

/// Chromium browsers.
pub static ANCHORED_CHROME_VERSION: std::sync::LazyLock<i64> = std::sync::LazyLock::new(chrome_version);
pub static CHROME_UA: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.0.0.0 Safari/537.36", *ANCHORED_CHROME_VERSION)
});
pub static CHROME_UACH: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| get_greased_ch_ua(*ANCHORED_CHROME_VERSION, "chrome"));
pub static MSEDGE_UA: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| format!("{}Edg/{}.0.0.0", *CHROME_UA, *ANCHORED_CHROME_VERSION));
pub static MSEDGE_UACH: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| get_greased_ch_ua(*ANCHORED_CHROME_VERSION, "edge"));

fn apply_masqueraded_headers(header: &mut http::HeaderMap, browser: &str, variant: &str) {
    fn set(header: &mut http::HeaderMap, name: &'static str, value: &str) {
        if let Ok(v) = http::HeaderValue::from_str(value) {
            header.insert(name, v);
        }
    }
    fn has(header: &http::HeaderMap, name: &str) -> bool {
        header.get(name).and_then(|v| v.to_str().ok()).is_some_and(|v| !v.is_empty())
    }

    match browser {
        "chrome" => {
            set(header, "sec-ch-ua", &CHROME_UACH);
            set(header, "sec-ch-ua-mobile", "?0");
            set(header, "sec-ch-ua-platform", "\"Windows\"");
            set(header, "dnt", "1");
            set(header, "user-agent", &CHROME_UA);
            set(header, "accept-language", "en-US,en;q=0.9");
        }
        "edge" => {
            set(header, "sec-ch-ua", &MSEDGE_UACH);
            set(header, "sec-ch-ua-mobile", "?0");
            set(header, "sec-ch-ua-platform", "\"Windows\"");
            set(header, "dnt", "1");
            set(header, "user-agent", &MSEDGE_UA);
            set(header, "accept-language", "en-US,en;q=0.9");
        }
        "firefox" => {
            set(header, "user-agent", &FIREFOX_UA);
            set(header, "dnt", "1");
            set(header, "accept-language", "en-US,en;q=0.5");
        }
        "safari" => {
            set(header, "user-agent", &SAFARI_UA);
            set(header, "accept-language", "en-US,en;q=0.9");
        }
        "curl" => {
            set(header, "user-agent", &CURL_UA);
            return;
        }
        _ => {}
    }

    match variant {
        "nav" => {
            if !has(header, "cache-control") && matches!(browser, "chrome" | "edge") {
                set(header, "cache-control", "max-age=0");
            }
            set(header, "upgrade-insecure-requests", "1");
            if !has(header, "accept") {
                match browser {
                    "chrome" | "edge" => set(
                        header,
                        "accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    ),
                    "firefox" | "safari" => set(header, "accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                    _ => {}
                }
            }
            set(header, "sec-fetch-site", "none");
            set(header, "sec-fetch-mode", "navigate");
            if browser != "safari" {
                set(header, "sec-fetch-user", "?1");
            }
            set(header, "sec-fetch-dest", "document");
            set(header, "priority", "u=0, i");
        }
        "ws" => {
            set(header, "sec-fetch-mode", "websocket");
            if browser == "safari" {
                set(header, "sec-fetch-dest", "websocket");
            } else {
                set(header, "sec-fetch-dest", "empty");
            }
            set(header, "sec-fetch-site", "same-origin");
            if !has(header, "cache-control") {
                set(header, "cache-control", "no-cache");
            }
            if !has(header, "pragma") {
                set(header, "pragma", "no-cache");
            }
            if !has(header, "accept") {
                set(header, "accept", "*/*");
            }
        }
        "fetch" => {
            set(header, "sec-fetch-mode", "cors");
            set(header, "sec-fetch-dest", "empty");
            set(header, "sec-fetch-site", "same-origin");
            if !has(header, "priority") {
                match browser {
                    "chrome" | "edge" => set(header, "priority", "u=1, i"),
                    "firefox" => set(header, "priority", "u=4"),
                    "safari" => set(header, "priority", "u=3, i"),
                    _ => {}
                }
            }
            if !has(header, "cache-control") {
                set(header, "cache-control", "no-cache");
            }
            if !has(header, "pragma") {
                set(header, "pragma", "no-cache");
            }
            if !has(header, "accept") {
                set(header, "accept", "*/*");
            }
        }
        _ => {}
    }
}

/// The global user-agent special-value handler for transports.
pub fn try_default_headers_with(header: &mut http::HeaderMap, variant: &str) {
    let user_agent = header.get(http::header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("");
    if user_agent.is_empty() {
        apply_masqueraded_headers(header, "chrome", variant);
    } else {
        match user_agent {
            "chrome" => apply_masqueraded_headers(header, "chrome", variant),
            "firefox" => apply_masqueraded_headers(header, "firefox", variant),
            "safari" => apply_masqueraded_headers(header, "safari", variant),
            "edge" => apply_masqueraded_headers(header, "edge", variant),
            "curl" => apply_masqueraded_headers(header, "curl", variant),
            _ => {}
        }
    }
}

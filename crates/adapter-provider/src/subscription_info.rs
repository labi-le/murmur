use murmur_log::warnln;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SubscriptionInfo {
    #[serde(rename = "Upload")]
    pub upload: i64,
    #[serde(rename = "Download")]
    pub download: i64,
    #[serde(rename = "Total")]
    pub total: i64,
    #[serde(rename = "Expire")]
    pub expire: i64,
}

impl SubscriptionInfo {
    #[must_use]
    pub fn new(userinfo: &str) -> Self {
        let userinfo = userinfo.to_lowercase().replace(' ', "");
        let mut si = Self::default();

        for field in userinfo.split(';') {
            let Some((name, value)) = field.split_once('=') else {
                continue;
            };

            let int_value = match parse_value(value) {
                Ok(int_value) => int_value,
                Err(err) => {
                    warnln!("[Provider] get subscription-userinfo: {err}");
                    continue;
                }
            };
            match name {
                "upload" => si.upload = int_value,
                "download" => si.download = int_value,
                "total" => si.total = int_value,
                "expire" => si.expire = int_value,
                _ => {}
            }
        }
        si
    }
}

fn parse_value(value: &str) -> anyhow::Result<i64> {
    if let Ok(int_value) = value.parse::<i64>() {
        return Ok(int_value);
    }

    if let Ok(float_value) = value.parse::<f64>() {
        #[expect(clippy::cast_possible_truncation, reason = "subscription-userinfo counters are integral byte counts")]
        let counter = float_value as i64;
        return Ok(counter);
    }

    Err(anyhow::anyhow!("failed to parse value '{value}'"))
}

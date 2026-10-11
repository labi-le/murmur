use anyhow::{anyhow, Result};

pub(crate) const ASCII_MODE_TOKEN_ASCII: &str = "ascii";
pub(crate) const ASCII_MODE_TOKEN_ENTROPY: &str = "entropy";

/// Preferred wire layout for each traffic direction: uplink is client->server,
/// downlink is server->client.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ASCIIMode {
    pub uplink: String,
    pub downlink: String,
}

/// Accepts legacy symmetric values ("ascii"/"entropy"/"prefer_*") and
/// directional values like "`up_ascii_down_entropy`".
pub fn parse_ascii_mode(mode: &str) -> Result<ASCIIMode> {
    let raw = mode.trim().to_lowercase();
    match raw.as_str() {
        "" | "entropy" | "prefer_entropy" => {
            return Ok(ASCIIMode {
                uplink: ASCII_MODE_TOKEN_ENTROPY.to_owned(),
                downlink: ASCII_MODE_TOKEN_ENTROPY.to_owned(),
            });
        }
        "ascii" | "prefer_ascii" => {
            return Ok(ASCIIMode {
                uplink: ASCII_MODE_TOKEN_ASCII.to_owned(),
                downlink: ASCII_MODE_TOKEN_ASCII.to_owned(),
            });
        }
        _ => {}
    }

    let Some(rest) = raw.strip_prefix("up_") else {
        return Err(anyhow!("invalid ascii mode: {mode}"));
    };
    let Some((up_token, down_token)) = rest.split_once("_down_") else {
        return Err(anyhow!("invalid ascii mode: {mode}"));
    };

    let Some(up) = normalize_ascii_mode_token(up_token) else {
        return Err(anyhow!("invalid ascii mode: {mode}"));
    };
    let Some(down) = normalize_ascii_mode_token(down_token) else {
        return Err(anyhow!("invalid ascii mode: {mode}"));
    };
    Ok(ASCIIMode { uplink: up.to_owned(), downlink: down.to_owned() })
}

/// Canonical config string for a supported mode.
pub fn normalize_ascii_mode(mode: &str) -> Result<String> {
    let parsed = parse_ascii_mode(mode)?;
    Ok(parsed.canonical())
}

impl ASCIIMode {
    #[must_use]
    pub fn canonical(&self) -> String {
        if self.uplink == ASCII_MODE_TOKEN_ASCII && self.downlink == ASCII_MODE_TOKEN_ASCII {
            return "prefer_ascii".to_owned();
        }
        if self.uplink == ASCII_MODE_TOKEN_ENTROPY && self.downlink == ASCII_MODE_TOKEN_ENTROPY {
            return "prefer_entropy".to_owned();
        }
        format!("up_{}_down_{}", self.uplink, self.downlink)
    }

    pub(crate) fn uplink_preference(&self) -> String {
        single_direction_preference(&self.uplink)
    }

    pub(crate) fn downlink_preference(&self) -> String {
        single_direction_preference(&self.downlink)
    }
}

fn normalize_ascii_mode_token(token: &str) -> Option<&'static str> {
    match token.trim().to_lowercase().as_str() {
        "ascii" | "prefer_ascii" => Some(ASCII_MODE_TOKEN_ASCII),
        "entropy" | "prefer_entropy" | "" => Some(ASCII_MODE_TOKEN_ENTROPY),
        _ => None,
    }
}

fn single_direction_preference(token: &str) -> String {
    if token == ASCII_MODE_TOKEN_ASCII {
        "prefer_ascii".to_owned()
    } else {
        "prefer_entropy".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::super::table::new_table_with_custom;
    use super::normalize_ascii_mode;
    use std::sync::Arc;

    #[test]
    fn test_normalize_ascii_mode() {
        let tests = [
            ("", "prefer_entropy"),
            ("entropy", "prefer_entropy"),
            ("prefer_ascii", "prefer_ascii"),
            ("up_ascii_down_entropy", "up_ascii_down_entropy"),
            ("up_entropy_down_ascii", "up_entropy_down_ascii"),
            ("up_prefer_ascii_down_prefer_entropy", "up_ascii_down_entropy"),
        ];

        for (input, want) in tests {
            let got =
                normalize_ascii_mode(input).unwrap_or_else(|err| panic!("normalize_ascii_mode({input:?}): {err}"));
            assert_eq!(got, want, "normalize_ascii_mode({input:?})");
        }

        assert!(normalize_ascii_mode("up_ascii_down_binary").is_err());
    }

    #[test]
    fn test_new_table_with_custom_directional_opposite() {
        let table = new_table_with_custom("seed", "up_ascii_down_entropy", "xpxvvpvv")
            .unwrap_or_else(|err| panic!("new_table_with_custom: {err}"));
        assert!(table.is_ascii, "uplink table should be ascii");
        let opposite = table.opposite_direction();
        assert!(!Arc::ptr_eq(&table, &opposite), "expected distinct opposite table");
        assert!(!opposite.is_ascii, "downlink table should be entropy/custom");

        let symmetric = new_table_with_custom("seed", "prefer_ascii", "xpxvvpvv")
            .unwrap_or_else(|err| panic!("new_table_with_custom symmetric: {err}"));
        assert!(Arc::ptr_eq(&symmetric, &symmetric.opposite_direction()), "symmetric table should point to itself");
    }
}

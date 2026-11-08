use murmur_quic::{Version, VERSION1, VERSION2};

#[must_use]
pub fn default_quic_versions() -> Vec<Version> {
    vec![VERSION1]
}

pub fn parse_quic_versions(values: &[String]) -> anyhow::Result<Vec<Version>> {
    let mut versions = Vec::with_capacity(values.len());
    for value in values {
        let version = parse_quic_version(value)?;
        if !contains_quic_version(&versions, version) {
            versions.push(version);
        }
    }
    Ok(versions)
}

pub fn parse_quic_version(value: &str) -> anyhow::Result<Version> {
    let normalized = value.trim().to_lowercase().replace('_', "-");
    match normalized.as_str() {
        "v1" | "1" | "rfc9000" | "rfc-9000" => Ok(VERSION1),
        "v2" | "2" | "rfc9369" | "rfc-9369" => Ok(VERSION2),
        _ => Err(anyhow::anyhow!("unsupported QUIC version {value:?} (supported: v1, v2)")),
    }
}

fn contains_quic_version(versions: &[Version], version: Version) -> bool {
    versions.contains(&version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_quic_versions() {
        let versions = parse_quic_versions(&[
            "v1".to_owned(),
            "v2".to_owned(),
            "rfc9000".to_owned(),
            "rfc-9369".to_owned(),
            "v1".to_owned(),
        ])
        .unwrap();

        assert_eq!(versions, vec![VERSION1, VERSION2]);
    }

    #[test]
    fn test_parse_quic_versions_rejects_unsupported_versions() {
        for version in ["draft-29", "0xabcd0000", "v3"] {
            assert!(parse_quic_versions(&[version.to_owned()]).is_err(), "ParseQUICVersions({version:?}) succeeded");
        }
    }
}

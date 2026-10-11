use std::net::IpAddr;
use std::sync::Arc;

use maxminddb::Reader;
use serde::de::DeserializeOwned;
use serde::Deserialize;

use murmur_log::warnln;

use super::mmdb::DatabaseType;

#[derive(Clone, Debug, Default, Deserialize)]
struct Geoip2Country {
    #[serde(rename = "country", default)]
    country: Country,
}

/// The nested country record.
#[derive(Clone, Debug, Default, Deserialize)]
struct Country {
    #[serde(rename = "iso_code", default)]
    iso_code: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct GeoLite2 {
    #[serde(rename = "autonomous_system_number", default)]
    pub autonomous_system_number: u32,
    #[serde(rename = "autonomous_system_organization", default)]
    pub autonomous_system_organization: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct IpInfo {
    #[serde(rename = "asn", default)]
    pub asn: String,
    #[serde(rename = "name", default)]
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct IpReader {
    pub reader: Arc<Reader<Vec<u8>>>,
    pub(crate) database_type: DatabaseType,
}

impl IpReader {
    pub(crate) const fn new(reader: Arc<Reader<Vec<u8>>>) -> Self {
        Self { reader, database_type: DatabaseType::Maxmind }
    }

    #[must_use]
    pub fn lookup_code(&self, ip_address: &IpAddr) -> Vec<String> {
        match self.database_type {
            DatabaseType::Maxmind => {
                let country: Geoip2Country = lookup_or_default(&self.reader, ip_address);
                if country.country.iso_code.is_empty() {
                    return Vec::new();
                }
                vec![country.country.iso_code.to_lowercase()]
            }

            DatabaseType::Sing => {
                let code: String = lookup_or_default(&self.reader, ip_address);
                if code.is_empty() {
                    return Vec::new();
                }
                vec![code]
            }

            DatabaseType::MetaV0 => {
                let record: serde_json::Value = lookup_or_default(&self.reader, ip_address);
                match record {
                    serde_json::Value::String(record) => vec![record],
                    serde_json::Value::Array(record) => {
                        let mut result = Vec::with_capacity(record.len());
                        for item in record {
                            #[expect(
                                clippy::expect_used,
                                reason = "a Meta-geoip0 record holds strings, so a non-string item means the database itself is malformed"
                            )]
                            result.push(item.as_str().expect("a Meta-geoip0 record item is a string").to_owned());
                        }
                        result
                    }
                    serde_json::Value::Null
                    | serde_json::Value::Bool(_)
                    | serde_json::Value::Number(_)
                    | serde_json::Value::Object(_) => Vec::new(),
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct AsnReader {
    pub reader: Arc<Reader<Vec<u8>>>,
}

impl AsnReader {
    pub(crate) const fn new(reader: Arc<Reader<Vec<u8>>>) -> Self {
        Self { reader }
    }

    #[must_use]
    pub fn lookup_asn(&self, ip: &IpAddr) -> (String, String) {
        match self.reader.metadata().database_type.as_str() {
            "GeoLite2-ASN" | "DBIP-ASN-Lite (compat=GeoLite2-ASN)" => {
                let result: GeoLite2 = lookup_or_default(&self.reader, ip);
                (result.autonomous_system_number.to_string(), result.autonomous_system_organization)
            }
            "ipinfo generic_asn_free.mmdb" => {
                let result: IpInfo = lookup_or_default(&self.reader, ip);
                (result.asn.get(2..).unwrap_or_default().to_owned(), result.name)
            }
            database_type => {
                warnln!("Unsupported ASN type: {}", database_type);
                (String::new(), String::new())
            }
        }
    }
}

/// A failed or missing lookup leaves the result at its zero value.
fn lookup_or_default<T: DeserializeOwned + Default>(reader: &Reader<Vec<u8>>, ip: &IpAddr) -> T {
    // The lookup normalizes a 4-in-6 address before walking the tree.
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(*ip, IpAddr::V4),
        IpAddr::V4(_) => *ip,
    };
    let Ok(result) = reader.lookup(ip) else {
        return T::default();
    };
    match result.decode::<T>() {
        Ok(Some(value)) => value,
        Ok(None) | Err(_) => T::default(),
    }
}

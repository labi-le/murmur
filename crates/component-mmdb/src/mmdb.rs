use std::sync::{Arc, LazyLock};

use maxminddb::Reader;
use parking_lot::RwLock;

use murmur_common::once::once_native::{reset, Once};
use murmur_constant::path::PATH;
use murmur_log::{fatalln, infoln};

use super::reader::{AsnReader, IpReader};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseType {
    Maxmind,
    Sing,
    MetaV0,
}

static IP_READER: LazyLock<RwLock<Option<IpReader>>> = LazyLock::new(|| RwLock::new(None));
static ASN_READER: LazyLock<RwLock<Option<AsnReader>>> = LazyLock::new(|| RwLock::new(None));
static IP_ONCE: Once = Once::new();
static ASN_ONCE: Once = Once::new();

pub fn load_from_bytes(buffer: Vec<u8>) {
    IP_ONCE.call_once(|| match Reader::from_source(buffer) {
        Ok(mmdb) => {
            let mut ip_reader = IpReader::new(Arc::new(mmdb));
            ip_reader.database_type = database_type_of(&ip_reader);
            *IP_READER.write() = Some(ip_reader);
        }
        Err(err) => fatalln!("Can't load mmdb: {}", err),
    });
}

#[must_use]
pub fn verify(path: &str) -> bool {
    match Reader::open_readfile(path) {
        Ok(_instance) => true,
        Err(_) => false,
    }
}

#[expect(
    clippy::expect_used,
    reason = "the load runs under `IP_ONCE` and fatals on failure, so the reader is always installed by the time this reads it"
)]
pub fn ip_instance() -> IpReader {
    IP_ONCE.call_once(|| {
        let mmdb_path = PATH.mmdb();
        infoln!("Load MMDB file: {}", mmdb_path);
        match Reader::open_readfile(&mmdb_path) {
            Ok(mmdb) => {
                let mut ip_reader = IpReader::new(Arc::new(mmdb));
                ip_reader.database_type = database_type_of(&ip_reader);
                *IP_READER.write() = Some(ip_reader);
            }
            Err(err) => fatalln!("Can't load MMDB: {}", err),
        }
    });

    IP_READER.read().clone().expect("IPInstance always loads a reader")
}

#[expect(
    clippy::expect_used,
    reason = "the load runs under `ASN_ONCE` and fatals on failure, so the reader is always installed by the time this reads it"
)]
pub fn asn_instance() -> AsnReader {
    ASN_ONCE.call_once(|| {
        let asn_path = PATH.asn();
        infoln!("Load ASN file: {}", asn_path);
        match Reader::open_readfile(&asn_path) {
            Ok(asn) => {
                *ASN_READER.write() = Some(AsnReader::new(Arc::new(asn)));
            }
            Err(err) => fatalln!("Can't load ASN: {}", err),
        }
    });

    ASN_READER.read().clone().expect("ASNInstance always loads a reader")
}

pub fn reload_ip() {
    reset(&IP_ONCE);
}

pub fn reload_asn() {
    reset(&ASN_ONCE);
}

fn database_type_of(reader: &IpReader) -> DatabaseType {
    match reader.reader.metadata().database_type.as_str() {
        "sing-geoip" => DatabaseType::Sing,
        "Meta-geoip0" => DatabaseType::MetaV0,
        _ => DatabaseType::Maxmind,
    }
}

//! The `salamander` and `gecko` packet-conn obfuscators, selected by the `obfs` configuration
//! field.

pub mod gecko;
pub mod salamander;

use std::io;
use std::sync::Arc;

use murmur_std_compat::net::PacketConn;

pub use gecko::{GeckoPacketConn, MAX_ON_WIRE_SIZE};
pub use salamander::SalamanderPacketConn;

/// The obfuscation a client and a server agree on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Obfs {
    Salamander(Arc<[u8]>),
    Gecko { password: Arc<[u8]>, min_packet_size: usize, max_packet_size: usize },
}

impl Obfs {
    /// Validates the obfs kind and password; the `missing obfs password` and
    /// `unknown obfs type` errors are the config surface's own.
    pub fn new(kind: &str, password: &str, min_packet_size: usize, max_packet_size: usize) -> Result<Self, String> {
        if password.is_empty() {
            return Err("missing obfs password".to_owned());
        }
        let password: Arc<[u8]> = Arc::from(password.as_bytes());
        match kind {
            salamander::OBFUS_TYPE_SALAMANDER => Ok(Self::Salamander(password)),
            gecko::OBFUS_TYPE_GECKO => {
                let (min_packet_size, max_packet_size) =
                    GeckoPacketConn::resolve_packet_sizes(min_packet_size, max_packet_size).map_err(str::to_owned)?;
                Ok(Self::Gecko { password, min_packet_size, max_packet_size })
            }
            other => Err(format!("unknown obfs type: {other}")),
        }
    }

    /// Wraps the packet conn with the selected obfuscator, on both the client's dialer side and the
    /// server's listener side.
    pub fn wrap(&self, conn: Arc<dyn PacketConn>) -> Arc<dyn PacketConn> {
        match self {
            Self::Salamander(password) => Arc::new(SalamanderPacketConn::new(conn, Arc::clone(password))),
            Self::Gecko { password, min_packet_size, max_packet_size } => {
                Arc::new(GeckoPacketConn::new(conn, Arc::clone(password), *min_packet_size, *max_packet_size))
            }
        }
    }
}

/// The gecko packet-size resolution, for a config whose obfs is gecko.
///
/// The resolution is otherwise only reachable through [`GeckoPacketConn`], but the outbound
/// option struct stores the raw configured values, so this is the same validation the client
/// performs.
pub fn validate_gecko_packet_sizes(min_packet_size: usize, max_packet_size: usize) -> io::Result<()> {
    GeckoPacketConn::resolve_packet_sizes(min_packet_size, max_packet_size)
        .map(|_| ())
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_is_required_for_every_kind() {
        assert_eq!(Obfs::new("salamander", "", 0, 0).unwrap_err(), "missing obfs password");
        assert_eq!(Obfs::new("gecko", "", 0, 0).unwrap_err(), "missing obfs password");
    }

    #[test]
    fn an_unknown_kind_is_rejected_by_name() {
        assert_eq!(Obfs::new("nonesuch", "pw", 0, 0).unwrap_err(), "unknown obfs type: nonesuch");
    }

    #[test]
    fn gecko_defaults_its_packet_size_range() {
        let obfs = Obfs::new("gecko", "pw", 0, 0).unwrap();
        assert_eq!(obfs, Obfs::Gecko { password: Arc::from(&b"pw"[..]), min_packet_size: 512, max_packet_size: 1200 });
    }

    #[test]
    fn gecko_rejects_an_impossible_packet_size_range() {
        assert!(Obfs::new("gecko", "pw", 1400, 600).is_err());
        assert!(Obfs::new("gecko", "pw", 512, MAX_ON_WIRE_SIZE + 1).is_err());
    }

    #[test]
    fn salamander_keeps_the_password_bytes() {
        assert_eq!(Obfs::new("salamander", "pw", 0, 0).unwrap(), Obfs::Salamander(Arc::from(&b"pw"[..])));
    }

    #[test]
    fn validate_gecko_packet_sizes_reports_an_invalid_range() {
        assert!(validate_gecko_packet_sizes(0, 0).is_ok());
        assert!(validate_gecko_packet_sizes(1400, 600).is_err());
    }
}

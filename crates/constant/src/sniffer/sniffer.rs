use std::fmt;
use std::sync::Arc;

use crate::adapters::PacketSender;
use crate::metadata::{Metadata, NetWork};

/// the `Sniffer` interface.
///
/// The `MultiPacketSniffer` type assertion is a capability query the dispatcher makes to decide
/// whether it can hand a UDP flow to a sniffer that wraps the packet sender itself, rather than
/// sniffing one packet at a time; [`Sniffer::as_multi_packet`] answers it directly instead of
/// downcasting.
pub trait Sniffer: Send + Sync {
    fn support_network(&self) -> NetWork;
    /// `SniffData` must not change input bytes
    fn sniff_data(&self, bytes: &[u8]) -> anyhow::Result<String>;
    fn protocol(&self) -> String;
    fn support_port(&self, port: u16) -> bool;

    /// `Some` for a sniffer that implements [`MultiPacketSniffer`].
    fn as_multi_packet(&self) -> Option<&dyn MultiPacketSniffer> {
        None
    }
}

pub type ReplaceDomain = Arc<dyn Fn(&mut Metadata, &str) + Send + Sync>;

/// the `MultiPacketSniffer` interface, narrowed to the sniffers the dispatcher asserts it on.
pub trait MultiPacketSniffer: Sniffer {
    fn wrapper_sender(
        &self,
        packet_sender: Arc<dyn PacketSender>,
        replace_domain: ReplaceDomain,
    ) -> Arc<dyn PacketSender>;
}

/// The type, keeping the `i32` representation so unknown values still render.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Type(pub i32);

impl Type {
    pub const TLS: Self = Self(0);
    pub const HTTP: Self = Self(1);
    pub const QUIC: Self = Self(2);

    #[must_use]
    pub fn string(&self) -> String {
        let name = match *self {
            Self::TLS => "TLS",
            Self::HTTP => "HTTP",
            Self::QUIC => "QUIC",
            _ => "Unknown",
        };
        name.to_owned()
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

pub static LIST: [Type; 3] = [Type::TLS, Type::HTTP, Type::QUIC];

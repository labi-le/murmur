use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use murmur_common::utils::ranges::IntRanges;
use murmur_common_net::io::{Datagram, Stream};
use murmur_common_net::EnhancePacketConn;
use murmur_component::dialer::dialer::{
    DEFAULT_TCP_TIMEOUT as DIALER_DEFAULT_TCP_TIMEOUT, DEFAULT_UDP_TIMEOUT as DIALER_DEFAULT_UDP_TIMEOUT,
};

use super::metadata::Metadata;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdapterType(pub i32);

impl AdapterType {
    pub const DIRECT: Self = Self(0);
    pub const REJECT: Self = Self(1);
    pub const REJECT_DROP: Self = Self(2);
    pub const COMPATIBLE: Self = Self(3);
    pub const PASS: Self = Self(4);
    pub const PASS_RULE: Self = Self(5);
    pub const REMATCH: Self = Self(6);
    pub const DNS: Self = Self(7);
    pub const RELAY: Self = Self(8);
    pub const SELECTOR: Self = Self(9);
    pub const FALLBACK: Self = Self(10);
    pub const URL_TEST: Self = Self(11);
    pub const LOAD_BALANCE: Self = Self(12);
    pub const SHADOWSOCKS: Self = Self(13);
    pub const SHADOWSOCKS_R: Self = Self(14);
    pub const SNELL: Self = Self(15);
    pub const SOCKS5: Self = Self(16);
    pub const HTTP: Self = Self(17);
    pub const VMESS: Self = Self(18);
    pub const VLESS: Self = Self(19);
    pub const TROJAN: Self = Self(20);
    pub const HYSTERIA: Self = Self(21);
    pub const HYSTERIA2: Self = Self(22);
    pub const WIRE_GUARD: Self = Self(23);
    pub const TUIC: Self = Self(24);
    pub const SSH: Self = Self(25);
    pub const MIERU: Self = Self(26);
    pub const ANY_TLS: Self = Self(27);
    pub const SUDOKU: Self = Self(28);
    pub const MASQUE: Self = Self(29);
    pub const TRUST_TUNNEL: Self = Self(30);
    pub const SHADOW_QUIC: Self = Self(31);
    pub const OPEN_VPN: Self = Self(32);
    pub const TAILSCALE: Self = Self(33);
    pub const ZERO_TIER: Self = Self(34);
    pub const EASY_TIER: Self = Self(35);
    pub const GOST_RELAY: Self = Self(36);

    #[must_use]
    pub fn string(&self) -> String {
        match *self {
            Self::DIRECT => "Direct",
            Self::REJECT => "Reject",
            Self::REJECT_DROP => "RejectDrop",
            Self::COMPATIBLE => "Compatible",
            Self::PASS => "Pass",
            Self::PASS_RULE => "PassRule",
            Self::REMATCH => "Rematch",
            Self::DNS => "Dns",
            Self::SHADOWSOCKS => "Shadowsocks",
            Self::SHADOWSOCKS_R => "ShadowsocksR",
            Self::SNELL => "Snell",
            Self::SOCKS5 => "Socks5",
            Self::HTTP => "Http",
            Self::VMESS => "Vmess",
            Self::VLESS => "Vless",
            Self::TROJAN => "Trojan",
            Self::HYSTERIA => "Hysteria",
            Self::HYSTERIA2 => "Hysteria2",
            Self::WIRE_GUARD => "WireGuard",
            Self::TUIC => "Tuic",
            Self::SSH => "Ssh",
            Self::MIERU => "Mieru",
            Self::ANY_TLS => "AnyTLS",
            Self::SUDOKU => "Sudoku",
            Self::MASQUE => "Masque",
            Self::TRUST_TUNNEL => "TrustTunnel",
            Self::SHADOW_QUIC => "ShadowQuic",
            Self::OPEN_VPN => "OpenVPN",
            Self::TAILSCALE => "Tailscale",
            Self::ZERO_TIER => "ZeroTier",
            Self::EASY_TIER => "EasyTier",
            Self::GOST_RELAY => "GostRelay",
            Self::RELAY => "Relay",
            Self::SELECTOR => "Selector",
            Self::FALLBACK => "Fallback",
            Self::URL_TEST => "URLTest",
            Self::LOAD_BALANCE => "LoadBalance",
            _ => "Unknown",
        }
        .to_owned()
    }
}

impl fmt::Display for AdapterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

pub const DEFAULT_TCP_TIMEOUT: Duration = DIALER_DEFAULT_TCP_TIMEOUT;

pub const DEFAULT_UDP_TIMEOUT: Duration = DIALER_DEFAULT_UDP_TIMEOUT;

pub const DEFAULT_DROP_TIME: Duration = DEFAULT_TCP_TIMEOUT.saturating_mul(12);

pub const DEFAULT_TLS_TIMEOUT: Duration = DEFAULT_TCP_TIMEOUT;

pub const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("no support")]
pub struct ErrNotSupport;

#[must_use]
pub fn err_not_support() -> Error {
    ErrNotSupport.into()
}

pub trait Connection: Send + Sync {
    fn chains(&self) -> Chain;

    fn provider_chains(&self) -> Chain;

    fn append_to_chains(&self, adapter: Arc<dyn ProxyAdapter>);

    fn remote_destination(&self) -> String;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Chain(pub Vec<String>);

impl Chain {
    #[must_use]
    pub fn string(&self) -> String {
        match self.0.as_slice() {
            [] => String::new(),
            [only] => only.clone(),
            [first, .., last] => format!("{last}[{first}]"),
        }
    }

    #[must_use]
    pub fn last(&self) -> String {
        match self.0.as_slice() {
            [] => String::new(),
            [first, ..] => first.clone(),
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

pub trait Conn: murmur_common_net::io::ExtendedStream + Connection {}

impl<T: murmur_common_net::io::ExtendedStream + Connection> Conn for T {}

/// Bridges an old `ExtendedConn` implementor (an outbound adapter's own wrapper conn,
/// pre-migration) into the new [`Conn`]: `common::net::io::OldConnAsStream` already forwards
/// `Stream`/`ExtendedStream`, this fills in the app-level `Connection` half by forwarding to the
/// wrapped value.
impl<T: Connection> Connection for murmur_common_net::io::OldConnAsStream<T> {
    fn chains(&self) -> Chain {
        self.0.chains()
    }

    fn provider_chains(&self) -> Chain {
        self.0.provider_chains()
    }

    fn append_to_chains(&self, adapter: Arc<dyn ProxyAdapter>) {
        self.0.append_to_chains(adapter);
    }

    fn remote_destination(&self) -> String {
        self.0.remote_destination()
    }
}

#[async_trait]
pub trait PacketConn: EnhancePacketConn + Connection {
    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()>;
}

/// `Dialer`. An `AddrPort` has no crate mirror, so an invalid one is `None`.
#[async_trait]
pub trait Dialer: Send + Sync {
    async fn dial_context(&self, ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn Stream>>;

    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
        r_addr_port: Option<SocketAddr>,
    ) -> Result<Box<dyn Datagram>>;
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "the four flags are independent wire capabilities, not one state encoded as bools"
)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProxyInfo {
    #[serde(rename = "XUDP")]
    pub xudp: bool,
    #[serde(rename = "TFO")]
    pub tfo: bool,
    #[serde(rename = "MPTCP")]
    pub mptcp: bool,
    #[serde(rename = "SMUX")]
    pub smux: bool,
    #[serde(rename = "Interface")]
    pub interface: String,
    #[serde(rename = "RoutingMark")]
    pub routing_mark: i32,
    #[serde(rename = "ProviderName")]
    pub provider_name: String,
    #[serde(rename = "DialerProxy")]
    pub dialer_proxy: String,
}

/// Bound on `ProxyAdapter` itself, not on a broader always-satisfied bound like `Any`.
///
/// Nothing forwards `ProxyAdapter` through `Box`/`Arc`, so a boxed/`Arc`'d adapter never satisfies
/// this blanket merely by wrapping something that already does, and `as_any` on one always
/// dispatches through to the real adapter's own vtable instead of answering for the wrapper.
pub trait AsAny: Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T: ProxyAdapter + 'static> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
pub trait ProxyAdapter: AsAny + Send + Sync {
    fn name(&self) -> String;

    /// The `type_` method; `type` is a Rust keyword.
    fn type_(&self) -> AdapterType;

    fn addr(&self) -> String;

    fn support_udp(&self) -> bool;

    fn proxy_info(&self) -> ProxyInfo;

    fn marshal_json(&self) -> Result<Vec<u8>>;

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn Conn>>;

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn PacketConn>>;

    fn support_uot(&self) -> bool;

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool;

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>>;

    fn close(&self) -> Result<()>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelayHistory {
    #[serde(with = "murmur_common::time_rfc3339")]
    pub time: DateTime<Utc>,
    pub delay: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyState {
    pub alive: bool,
    pub history: Vec<DelayHistory>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DelayHistoryStoreType(pub i32);

#[async_trait]
pub trait Proxy: ProxyAdapter {
    fn adapter(&self) -> Arc<dyn ProxyAdapter>;

    fn alive_for_test_url(&self, url: &str) -> bool;

    fn delay_history(&self) -> Vec<DelayHistory>;

    fn extra_delay_histories(&self) -> HashMap<String, ProxyState>;

    fn last_delay_for_test_url(&self, url: &str) -> u16;

    async fn url_test(&self, ctx: &CancellationToken, url: &str, expected_status: IntRanges<u16>) -> Result<u16>;
}

pub trait UDPPacket: WriteBack + Send + Sync {
    fn data(&self) -> &[u8];

    /// the `Drop`; the trailing underscore keeps it clear of `std::ops::Drop`.
    fn drop_(&self);

    fn local_addr(&self) -> SocketAddr;

    /// A second interface that an erased `Arc<dyn UDPPacket>` can no longer be asked about, so the
    /// capability rides on the trait; `None` is the packets without it.
    fn in_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// The UDP NAT table is keyed on this string, and several protocols hand back a per-session
    /// key there specifically so two sessions
    /// sharing one peer socket (tuic associations, sing/h2/grpc/xhttp multiplexed UDP, trojan and
    /// sudoku over one TCP/mux conn) still land in distinct NAT entries. `local_addr()` above
    /// stays the real socket address (used for metadata src/dst); this is the string half, kept
    /// separate so retyping `local_addr` to a plain
    /// `SocketAddr` (rather than `Box<dyn Addr>`) never has to fabricate an address to keep a
    /// per-session key. Defaults to `local_addr().to_string()` for every implementor whose local
    /// address is already unique per session.
    fn nat_key(&self) -> String {
        self.local_addr().to_string()
    }
}

pub trait PacketAdapter: UDPPacket + Send + Sync {
    fn metadata(&self) -> &Metadata;

    fn key(&self) -> String;
}

pub struct PacketAdapterImpl {
    pub packet: Arc<dyn UDPPacket>,
    pub(crate) metadata: Metadata,
    pub(crate) key: String,
}

impl fmt::Debug for PacketAdapterImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketAdapterImpl")
            .field("metadata", &self.metadata)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

pub fn new_packet_adapter(packet: Arc<dyn UDPPacket>, metadata: Metadata) -> PacketAdapterImpl {
    PacketAdapterImpl { key: packet.nat_key(), packet, metadata }
}

impl PacketAdapterImpl {
    /// Mutation handle for the metadata held alongside the packet.
    pub const fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }

    /// The NAT key as a borrowed string.
    ///
    /// [`PacketAdapter::key`] clones it; the established-entry fast path uses this form so a
    /// per-datagram lookup on an existing key allocates no key buffer.
    #[must_use]
    pub fn key_ref(&self) -> &str {
        &self.key
    }
}

#[async_trait]
impl WriteBack for PacketAdapterImpl {
    // cancel-safe: the body only forwards to the wrapped packet, so a drop at the await adds no
    // partial state beyond what that call leaves behind.
    async fn write_back(&self, b: &[u8], addr: Option<SocketAddr>) -> Result<usize> {
        self.packet.write_back(b, addr).await
    }
}

impl UDPPacket for PacketAdapterImpl {
    fn data(&self) -> &[u8] {
        self.packet.data()
    }

    fn drop_(&self) {
        self.packet.drop_();
    }

    fn local_addr(&self) -> SocketAddr {
        self.packet.local_addr()
    }

    fn in_addr(&self) -> Option<SocketAddr> {
        self.packet.in_addr()
    }

    fn nat_key(&self) -> String {
        self.packet.nat_key()
    }
}

impl PacketAdapter for PacketAdapterImpl {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn key(&self) -> String {
        self.key.clone()
    }
}

#[async_trait]
pub trait WriteBack: Send + Sync {
    async fn write_back(&self, b: &[u8], addr: Option<SocketAddr>) -> Result<usize>;
}

pub trait WriteBackProxy: WriteBack {
    fn update_write_back(&self, wb: Arc<dyn WriteBack>);
}

#[async_trait]
pub trait PacketSender: Send + Sync {
    async fn send(&self, packet: Arc<dyn PacketAdapter>);

    async fn process(&self, conn: Arc<dyn PacketConn>, proxy: Arc<dyn WriteBackProxy>);

    fn close(&self);

    async fn do_sniff(&self, metadata: &mut Metadata) -> Result<()>;

    fn add_mapping(&self, origin_metadata: &Metadata, metadata: &Metadata);

    fn restore_read_from(&self, addr: IpAddr) -> IpAddr;
}

/// `NatTable`. Local conns are `tokio::net::UdpSocket`s, and the condition variable is a
/// `tokio::sync::Notify` (waiter: `notified()`, waker: `notify_waiters()`).
pub trait NatTable: Send + Sync {
    /// Returns the sender stored for `key`, or `None` when this lookup did not observe an entry.
    ///
    /// This borrows `key` and never constructs an entry, so it is the established-flow fast path.
    /// Neither answer is a reservation. A `None` can be stale because a concurrent `get_or_create`
    /// can store the key right after the lookup, and a `Some` sender can be removed and closed right
    /// after it is returned. Callers must fall back to `get_or_create` on `None`; the sender a `Some`
    /// returns has the same lifetime guarantee as the sender `get_or_create` returns.
    fn get(&self, key: &str) -> Option<Arc<dyn PacketSender>>;

    fn get_or_create(
        &self,
        key: &str,
        maker: Box<dyn FnOnce() -> Arc<dyn PacketSender> + Send>,
    ) -> (Arc<dyn PacketSender>, bool);

    fn delete(&self, key: &str);

    fn get_for_local_conn(&self, l_addr: &str, r_addr: &str) -> Option<Arc<UdpSocket>>;

    fn add_for_local_conn(&self, l_addr: &str, r_addr: &str, conn: Arc<UdpSocket>) -> bool;

    fn range_for_local_conn(&self, l_addr: &str, f: &mut dyn FnMut(&str, &Arc<UdpSocket>) -> bool);

    fn get_or_create_lock_for_local_conn(&self, l_addr: &str, key: &str) -> (Arc<Notify>, bool);

    fn delete_for_local_conn(&self, l_addr: &str, key: &str);

    fn delete_lock_for_local_conn(&self, l_addr: &str, key: &str);
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use murmur_common::errors::error_is;

    use super::{err_not_support, ErrNotSupport, PacketAdapter};

    #[test]
    fn err_not_support_survives_context_wrapping() {
        let err = err_not_support().context("dial context");
        assert_eq!(err.to_string(), "dial context");
        assert!(
            error_is::<ErrNotSupport>(&err),
            "error_is::<ErrNotSupport> must still find the sentinel once anyhow adds context, \
             unlike a text comparison against the outer message"
        );
    }

    struct MarkerAdapter;

    #[async_trait]
    impl super::ProxyAdapter for MarkerAdapter {
        fn name(&self) -> String {
            "marker".to_owned()
        }

        fn type_(&self) -> super::AdapterType {
            super::AdapterType::DIRECT
        }

        fn addr(&self) -> String {
            String::new()
        }

        fn support_udp(&self) -> bool {
            false
        }

        fn proxy_info(&self) -> super::ProxyInfo {
            super::ProxyInfo::default()
        }

        fn marshal_json(&self) -> anyhow::Result<Vec<u8>> {
            Ok(Vec::new())
        }

        async fn dial_context(
            &self,
            _ctx: &tokio_util::sync::CancellationToken,
            _metadata: &mut crate::metadata::Metadata,
        ) -> anyhow::Result<Box<dyn super::Conn>> {
            Err(anyhow::anyhow!("marker adapter cannot dial"))
        }

        async fn listen_packet_context(
            &self,
            _ctx: &tokio_util::sync::CancellationToken,
            _metadata: &mut crate::metadata::Metadata,
        ) -> anyhow::Result<std::sync::Arc<dyn super::PacketConn>> {
            Err(anyhow::anyhow!("marker adapter cannot listen"))
        }

        fn support_uot(&self) -> bool {
            false
        }

        fn is_l3_protocol(&self, _metadata: &crate::metadata::Metadata) -> bool {
            false
        }

        fn unwrap(
            &self,
            _metadata: &crate::metadata::Metadata,
            _touch: bool,
        ) -> Option<std::sync::Arc<dyn super::Proxy>> {
            None
        }

        fn close(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn as_any_reaches_the_boxed_adapter_not_the_box() {
        let boxed: Box<dyn super::ProxyAdapter> = Box::new(MarkerAdapter);
        assert!(
            boxed.as_any().downcast_ref::<MarkerAdapter>().is_some(),
            "expected the boxed MarkerAdapter, got the box"
        );
    }

    /// Two UDP sessions can share one peer socket (tuic associations, sing/h2/grpc/xhttp
    /// multiplexed UDP, trojan/sudoku over one mux conn): the NAT table tells them apart by a
    /// per-session key whose string differs even though the underlying address is the one shared
    /// peer socket. `nat_key()` is that seam; if
    /// `new_packet_adapter` fell back to `local_addr().to_string()` (as it did before this fix),
    /// two packets sharing one peer socket would collapse onto the same NAT entry.
    struct MarkerPacket {
        addr: std::net::SocketAddr,
        key: &'static str,
    }

    #[async_trait]
    impl super::WriteBack for MarkerPacket {
        async fn write_back(&self, _b: &[u8], _addr: Option<std::net::SocketAddr>) -> anyhow::Result<usize> {
            unreachable!("not exercised by this test")
        }
    }

    impl super::UDPPacket for MarkerPacket {
        fn data(&self) -> &[u8] {
            &[]
        }

        fn drop_(&self) {}

        fn local_addr(&self) -> std::net::SocketAddr {
            self.addr
        }

        fn nat_key(&self) -> String {
            self.key.to_owned()
        }
    }

    #[test]
    fn new_packet_adapter_keys_on_nat_key_not_local_addr() {
        let peer: std::net::SocketAddr = "198.51.100.7:9".parse().unwrap();
        let one = super::new_packet_adapter(
            std::sync::Arc::new(MarkerPacket { addr: peer, key: "session-one" }),
            crate::metadata::Metadata::default(),
        );
        let two = super::new_packet_adapter(
            std::sync::Arc::new(MarkerPacket { addr: peer, key: "session-two" }),
            crate::metadata::Metadata::default(),
        );
        assert_ne!(one.key(), two.key(), "two sessions behind one peer socket must not collapse onto the same NAT key");
        assert_eq!(one.key(), "session-one");
        assert_eq!(two.key(), "session-two");
        assert_eq!(one.key_ref(), "session-one", "the borrowed key disagrees with the owned one");
        assert_eq!(one.key_ref(), one.key(), "the established fast path would look up another key");
    }

    #[test]
    fn nat_key_defaults_to_local_addr_when_not_overridden() {
        let addr: std::net::SocketAddr = "203.0.113.5:443".parse().unwrap();
        let packet = MarkerPacket { addr, key: "unused" };
        struct DefaultKeyPacket(std::net::SocketAddr);
        #[async_trait]
        impl super::WriteBack for DefaultKeyPacket {
            async fn write_back(&self, _b: &[u8], _addr: Option<std::net::SocketAddr>) -> anyhow::Result<usize> {
                unreachable!("not exercised by this test")
            }
        }
        impl super::UDPPacket for DefaultKeyPacket {
            fn data(&self) -> &[u8] {
                &[]
            }
            fn drop_(&self) {}
            fn local_addr(&self) -> std::net::SocketAddr {
                self.0
            }
        }
        let _ = &packet;
        let adapter = super::new_packet_adapter(
            std::sync::Arc::new(DefaultKeyPacket(addr)),
            crate::metadata::Metadata::default(),
        );
        assert_eq!(adapter.key(), addr.to_string());
    }
}

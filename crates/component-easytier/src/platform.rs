//! The capability vocabulary `EasyTier` hands back is mirrored in [`platform`].

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{close_stream, udp_addr_from_socket_addr, DatagramAsOldPacketConn, StreamAsOldConn};
use murmur_component::dialer::dialer;
use murmur_component::dialer::options::{with_addr_reuse, with_option, Options};
use murmur_component::resolver::host::{parse_addr, unmap_addr};
use murmur_component::resolver::resolver::{
    lookup_ip_with_resolver, lookup_ipv4_with_resolver, lookup_ipv6_with_resolver, proxy_server_host_resolver,
    system_resolver,
};
use murmur_constant::adapters::Dialer as ConstantDialer;
use murmur_std_compat::net::{Addr, Conn, Listener, PacketConn, TcpAddr, UdpAddr};

pub use platform::{
    DNSQuery, EnvironmentSnapshot, IPVersion, Services, Srv, TCPBindOptions, TCPConnectOptions, TCPConnectPurpose,
    TCPListenOptions, TCPListenPurpose, UDPBindOptions,
};

/// The capability vocabulary `EasyTier` calls back into; this crate supplies its murmur halves as
/// [`SocketFactory`], [`DNSResolver`] and [`ConnectorEnvironment`].
pub mod platform {
    use std::net::IpAddr;
    use std::sync::Arc;

    use anyhow::Result;
    use async_trait::async_trait;
    use tokio_util::sync::CancellationToken;

    use murmur_std_compat::net::{Addr, Conn, Listener, PacketConn, TcpAddr, UdpAddr};

    #[derive(Clone, Debug, Default)]
    pub struct DNSQuery {
        pub host: String,
        pub ip_version: u8,
        pub socket_mark: Option<u32>,
        pub net_ns: Option<String>,
    }

    #[async_trait]
    pub trait DNSResolver: Send + Sync {
        async fn lookup_ip(&self, ctx: &CancellationToken, query: DNSQuery) -> Result<Vec<IpAddr>>;

        async fn lookup_txt(&self, ctx: &CancellationToken, query: DNSQuery) -> Result<String>;

        async fn lookup_srv(&self, ctx: &CancellationToken, query: DNSQuery) -> Result<Vec<Srv>>;
    }

    #[async_trait]
    pub trait ConnectorEnvironment: Send + Sync {
        async fn local_addr_for_remote(
            &self,
            ctx: &CancellationToken,
            remote: Option<&UdpAddr>,
            socket_context: SocketContext,
        ) -> Result<Box<dyn Addr>>;
    }

    #[derive(Clone, Debug, Default)]
    pub struct EnvironmentSnapshot {
        pub public_ipv4: Option<IpAddr>,
        pub interface_ipv4s: Vec<IpAddr>,
        pub public_ipv6: Option<IpAddr>,
        pub interface_ipv6s: Vec<IpAddr>,
        pub mapped_listeners: Vec<String>,
        pub local_ips: Vec<IpAddr>,
        pub protected_tcp_ports: Vec<u16>,
        pub preferred_ipv6_sources: Vec<PreferredIPv6Source>,
    }

    #[derive(Clone, Debug, Default)]
    pub struct PreferredIPv6Source {
        pub ip: Option<IpAddr>,
        pub if_index: u32,
    }

    #[derive(Clone)]
    pub struct Services {
        pub sockets: Arc<dyn SocketFactory>,
        pub dns: Arc<dyn DNSResolver>,
        pub environment: Arc<dyn ConnectorEnvironment>,
        pub snapshot: EnvironmentSnapshot,
    }

    impl std::fmt::Debug for Services {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Services").field("snapshot", &self.snapshot).finish_non_exhaustive()
        }
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct TCPConnectPurpose(pub u8);

    impl TCPConnectPurpose {
        pub const TCP_CONNECT_DIRECT: Self = Self(0);
        pub const TCP_CONNECT_FAKE: Self = Self(1);
        pub const TCP_CONNECT_HOLE_PUNCH: Self = Self(2);
        pub const TCP_CONNECT_MANUAL: Self = Self(3);
        pub const TCP_CONNECT_PROXY_NAT: Self = Self(4);
        pub const TCP_CONNECT_STUN_PROBE: Self = Self(5);
        pub const TCP_CONNECT_SOCKS5: Self = Self(6);
        pub const TCP_CONNECT_PORT_FORWARD: Self = Self(7);
        pub const TCP_CONNECT_DATA_PLANE: Self = Self(8);
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct UDPBindPurpose(pub u8);

    impl UDPBindPurpose {
        pub const UDP_BIND_HOLE_PUNCH_CONTROL: Self = Self(0);
        pub const UDP_BIND_HOLE_PUNCH_CANDIDATE: Self = Self(1);
        pub const UDP_BIND_DIRECT: Self = Self(2);
        pub const UDP_BIND_PORT_BOUND_LISTENER: Self = Self(3);
        pub const UDP_BIND_PROXY_NAT: Self = Self(4);
        pub const UDP_BIND_STUN_PROBE: Self = Self(5);
        pub const UDP_BIND_SOCKS5: Self = Self(6);
        pub const UDP_BIND_PORT_FORWARD: Self = Self(7);
        pub const UDP_BIND_PORT_LEASE: Self = Self(8);
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct TCPListenPurpose(pub u8);

    impl TCPListenPurpose {
        pub const TCP_LISTEN_DIRECT: Self = Self(0);
        pub const TCP_LISTEN_HOLE_PUNCH: Self = Self(1);
        pub const TCP_LISTEN_MANUAL: Self = Self(2);
        pub const TCP_LISTEN_PROXY_NAT: Self = Self(3);
        pub const TCP_LISTEN_SOCKS5: Self = Self(4);
        pub const TCP_LISTEN_PORT_FORWARD: Self = Self(5);
        pub const TCP_LISTEN_PORT_LEASE: Self = Self(6);
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct IPVersion(pub u8);

    impl IPVersion {
        pub const IP_VERSION_V4: Self = Self(0);
        pub const IP_VERSION_V6: Self = Self(1);
        pub const IP_VERSION_BOTH: Self = Self(2);
    }

    #[derive(Clone, Debug, Default)]
    pub struct SocketContext {
        pub ip_version: IPVersion,
        pub socket_mark: Option<u32>,
        pub net_ns: Option<String>,
    }

    #[derive(Clone, Debug, Default)]
    pub struct TCPBindOptions {
        pub context: SocketContext,
        pub local_addr: Option<TcpAddr>,
        pub bind_device: Option<String>,
        pub reuse_addr: Option<bool>,
        pub reuse_port: bool,
        pub only_v6: bool,
    }

    #[derive(Clone, Debug, Default)]
    pub struct TCPConnectOptions {
        pub remote_addr: Option<TcpAddr>,
        pub bind: TCPBindOptions,
        pub purpose: TCPConnectPurpose,
    }

    #[derive(Clone, Debug, Default)]
    pub struct UDPBindOptions {
        pub context: SocketContext,
        pub local_addr: Option<UdpAddr>,
        pub bind_device: Option<String>,
        pub reuse_addr: bool,
        pub reuse_port: bool,
        pub only_v6: bool,
        pub purpose: UDPBindPurpose,
    }

    #[derive(Clone, Debug, Default)]
    pub struct TCPListenOptions {
        pub bind: TCPBindOptions,
        pub purpose: TCPListenPurpose,
    }

    #[async_trait]
    pub trait SocketFactory: Send + Sync {
        async fn connect_tcp(&self, ctx: &CancellationToken, options: TCPConnectOptions) -> Result<Box<dyn Conn>>;

        async fn bind_udp(&self, ctx: &CancellationToken, options: UDPBindOptions) -> Result<Box<dyn PacketConn>>;

        async fn listen_tcp(&self, ctx: &CancellationToken, options: TCPListenOptions) -> Result<Box<dyn Listener>>;
    }

    /// The SRV record the `EasyTier` callback hands back.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Srv {
        pub target: String,
        pub port: u16,
        pub priority: u16,
        pub weight: u16,
    }
}

pub fn services(d: Arc<dyn ConstantDialer>) -> Services {
    services_with(SocketFactory::new(Arc::clone(&d)), d)
}

/// Builds [`Services`] with a direct dialer: whether the dialer is the concrete type is decided
/// by the caller, since an erased `constant::adapters::Dialer` carries no
/// `as_any` to test.
pub fn services_with_direct_dialer(d: Arc<dyn ConstantDialer>, direct_opt: Options) -> Services {
    services_with(SocketFactory::new_direct(Arc::clone(&d), Some(direct_opt)), d)
}

fn services_with(sockets: SocketFactory, d: Arc<dyn ConstantDialer>) -> Services {
    Services {
        sockets: Arc::new(sockets),
        dns: Arc::new(DNSResolver {}),
        environment: Arc::new(ConnectorEnvironment { dialer: d }),
        snapshot: EnvironmentSnapshot::default(),
    }
}

pub struct SocketFactory {
    pub dialer: Arc<dyn ConstantDialer>,
    /// The concrete-dialer assertion: Rust cannot test an erased value against a concrete
    /// type, and `constant::adapters::Dialer` exposes no `as_any`, so the caller supplies the
    /// concrete dialer's options through [`SocketFactory::new_direct`].
    pub direct_opt: Option<Options>,
}

impl std::fmt::Debug for SocketFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketFactory").field("direct_opt", &self.direct_opt).finish_non_exhaustive()
    }
}

impl SocketFactory {
    /// Builds a [`SocketFactory`] for a dialer that is not the concrete dialer type.
    pub fn new(dialer: Arc<dyn ConstantDialer>) -> Self {
        Self { dialer, direct_opt: None }
    }

    /// Builds a [`SocketFactory`] when `d` is the concrete dialer type.
    pub fn new_direct(dialer: Arc<dyn ConstantDialer>, direct_opt: Option<Options>) -> Self {
        Self { dialer, direct_opt }
    }
}

#[async_trait]
impl platform::SocketFactory for SocketFactory {
    /// `EasyTier`'s `BindDevice`, `SocketMark` and reuse options are ignored so hole punching can bind
    /// local UDP ports; the interface, routing mark and dialer proxy stay on the murmur dialer.
    /// `FakeTCP` is not supported.
    // cancel-safe: a dropped future abandons the dial; nothing shared is written before it returns.
    async fn connect_tcp(&self, ctx: &CancellationToken, options: TCPConnectOptions) -> Result<Box<dyn Conn>> {
        if options.purpose == TCPConnectPurpose::TCP_CONNECT_FAKE {
            return Err(anyhow!("easytier: FakeTCP is not supported"));
        }
        let Some(remote_addr) = options.remote_addr else {
            return Err(anyhow!("easytier: TCP connect is missing a remote address"));
        };
        let network = tcp_network(&options.bind);
        let remote_addr = tcp_address(&remote_addr);
        Ok(Box::new(StreamAsOldConn::new(self.dialer.dial_context(ctx, network, &remote_addr).await?)))
    }

    // cancel-safe: a dropped future abandons the bind and closes the socket it opened.
    async fn bind_udp(&self, ctx: &CancellationToken, options: UDPBindOptions) -> Result<Box<dyn PacketConn>> {
        let (network, address) = udp_bind(&options);
        Ok(Box::new(DatagramAsOldPacketConn(self.dialer.listen_packet(ctx, &network, &address, None).await?)))
    }

    // cancel-safe: a dropped future abandons the listener; nothing shared is written.
    async fn listen_tcp(&self, ctx: &CancellationToken, options: TCPListenOptions) -> Result<Box<dyn Listener>> {
        if options.bind.context.net_ns.is_some() {
            return Err(anyhow!("easytier: network namespaces are not supported"));
        }
        let address = options.bind.local_addr.as_ref().map_or_else(|| ":0".to_owned(), tcp_address);
        let network = tcp_network(&options.bind);
        let reuse = options.bind.reuse_port || options.bind.reuse_addr == Some(true);
        let mut listen_opts = vec![with_addr_reuse(reuse)];
        if let Some(direct_opt) = &self.direct_opt {
            listen_opts.push(with_option(direct_opt.clone()));
            return Ok(Box::new(murmur_common_net::io::AcceptorAsOldListener(
                dialer::listen(ctx, network, &address, listen_opts).await?,
            )));
        }
        if external_tcp_listen(options.purpose) {
            return Err(anyhow!("easytier: TCP listeners are unavailable through a proxy or custom dialer"));
        }
        // ProxyNAT, port leases and hole-punch reservations bind on the host even when peer traffic
        // uses the dialer proxy.
        Ok(Box::new(murmur_common_net::io::AcceptorAsOldListener(
            dialer::listen(ctx, network, &address, listen_opts).await?,
        )))
    }
}

const fn external_tcp_listen(purpose: TCPListenPurpose) -> bool {
    matches!(purpose, TCPListenPurpose::TCP_LISTEN_DIRECT | TCPListenPurpose::TCP_LISTEN_MANUAL)
}

/// A 4-in-6 address collapses to a dotted quad, so the family
/// [`tcp_network`] picks and the address handed to the dialer have to collapse together.
fn tcp_address(addr: &TcpAddr) -> String {
    TcpAddr { ip: unmap_addr(addr.ip), ..*addr }.string()
}

fn tcp_network(options: &TCPBindOptions) -> &'static str {
    if options.local_addr.as_ref().is_some_and(|local_addr| unmap_addr(local_addr.ip).is_ipv4()) {
        return "tcp4";
    }
    if options.only_v6 || options.context.ip_version == IPVersion::IP_VERSION_V6 {
        return "tcp6";
    }
    if options.context.ip_version == IPVersion::IP_VERSION_V4 {
        return "tcp4";
    }
    "tcp"
}

fn udp_bind(options: &UDPBindOptions) -> (String, String) {
    if let Some(local_addr) = &options.local_addr {
        // Collapsed like [`tcp_address`], so the family and the rendered address agree.
        let local_addr = UdpAddr { ip: unmap_addr(local_addr.ip), ..local_addr.clone() };
        let address = local_addr.string();
        if local_addr.ip.is_ipv4() {
            return ("udp4".to_owned(), address);
        }
        if options.only_v6 || local_addr.ip.is_ipv6() {
            return ("udp6".to_owned(), address);
        }
        return ("udp".to_owned(), address);
    }
    if options.only_v6 || options.context.ip_version == IPVersion::IP_VERSION_V6 {
        return ("udp6".to_owned(), "[::]:0".to_owned());
    }
    if options.context.ip_version == IPVersion::IP_VERSION_V4 {
        return ("udp4".to_owned(), "0.0.0.0:0".to_owned());
    }
    ("udp".to_owned(), ":0".to_owned())
}

/// `DNSResolver`, resolving `EasyTier` control-plane names through the proxy-server resolver.
#[derive(Debug)]
pub struct DNSResolver {}

#[async_trait]
impl platform::DNSResolver for DNSResolver {
    // cancel-safe: a dropped lookup only abandons the outstanding query; the resolver owns its connection.
    async fn lookup_ip(&self, ctx: &CancellationToken, query: DNSQuery) -> Result<Vec<IpAddr>> {
        if let Ok(address) = parse_addr(&query.host) {
            return Ok(vec![unmap_addr(address)]);
        }
        let resolver = proxy_server_host_resolver();
        match query.ip_version {
            4 => lookup_ipv4_with_resolver(ctx, &query.host, resolver.as_deref()).await,
            6 => lookup_ipv6_with_resolver(ctx, &query.host, resolver.as_deref()).await,
            _ => lookup_ip_with_resolver(ctx, &query.host, resolver.as_deref()).await,
        }
    }

    // cancel-safe: a dropped lookup only abandons the outstanding query; the resolver owns its connection.
    async fn lookup_txt(&self, ctx: &CancellationToken, query: DNSQuery) -> Result<String> {
        let reply = exchange_dns(ctx, &query.host, RecordType::TXT).await?;
        for answer in &reply.answers {
            if let RData::TXT(txt) = &answer.data {
                let joined: Vec<u8> = txt.txt_data.iter().flat_map(|chunk| chunk.iter().copied()).collect();
                return Ok(String::from_utf8_lossy(&joined).into_owned());
            }
        }
        Err(anyhow!("easytier: DNS TXT query for {:?} returned no records", query.host))
    }

    // cancel-safe: a dropped lookup only abandons the outstanding query; the resolver owns its connection.
    async fn lookup_srv(&self, ctx: &CancellationToken, query: DNSQuery) -> Result<Vec<Srv>> {
        let reply = exchange_dns(ctx, &query.host, RecordType::SRV).await?;
        let mut records = Vec::new();
        for answer in &reply.answers {
            if let RData::SRV(srv) = &answer.data {
                records.push(Srv {
                    target: srv.target.to_utf8(),
                    port: srv.port,
                    priority: srv.priority,
                    weight: srv.weight,
                });
            }
        }
        if records.is_empty() {
            return Err(anyhow!("easytier: DNS SRV query for {:?} returned no records", query.host));
        }
        Ok(records)
    }
}

// cancel-safe: a dropped future abandons the outstanding query; the resolver owns its connection.
async fn exchange_dns(ctx: &CancellationToken, host: &str, qtype: RecordType) -> Result<Message> {
    let r = match proxy_server_host_resolver() {
        Some(r) if r.invalid() => r,
        _ => system_resolver(),
    };
    let mut request = Message::new(0, MessageType::Query, OpCode::Query);
    set_question(&mut request, host, qtype)?;
    let reply = r.exchange_context(ctx, &request).await?;
    if reply.metadata.response_code != ResponseCode::NoError {
        return Err(anyhow!(
            "easytier: DNS query for {:?} returned {}",
            host,
            rcode_string(reply.metadata.response_code)
        ));
    }
    Ok(reply)
}

fn set_question(request: &mut Message, host: &str, qtype: RecordType) -> Result<()> {
    request.metadata.id = rand::random::<u16>();
    request.metadata.recursion_desired = true;
    let fqdn = if host.ends_with('.') { host.to_owned() } else { format!("{host}.") };
    let name = Name::from_utf8(fqdn).map_err(|err| anyhow!("easytier: invalid DNS name {host:?}: {err}"))?;
    request.queries = vec![Query::query(name, qtype)];
    Ok(())
}

/// The response-code name, whose absent entries are the empty string.
const fn rcode_string(rcode: ResponseCode) -> &'static str {
    match rcode {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::Refused => "REFUSED",
        ResponseCode::YXDomain => "YXDOMAIN",
        ResponseCode::YXRRSet => "YXRRSET",
        ResponseCode::NXRRSet => "NXRRSET",
        ResponseCode::NotAuth => "NOTAUTH",
        ResponseCode::NotZone => "NOTZONE",
        ResponseCode::BADVERS | ResponseCode::BADSIG => "BADSIG",
        ResponseCode::BADKEY => "BADKEY",
        ResponseCode::BADTIME => "BADTIME",
        ResponseCode::BADMODE => "BADMODE",
        ResponseCode::BADNAME => "BADNAME",
        ResponseCode::BADALG => "BADALG",
        ResponseCode::BADTRUNC => "BADTRUNC",
        ResponseCode::BADCOOKIE => "BADCOOKIE",
        ResponseCode::Unknown(_) => "",
    }
}

/// `ConnectorEnvironment`, reporting the local address used toward a remote UDP peer.
pub struct ConnectorEnvironment {
    pub dialer: Arc<dyn ConstantDialer>,
}

impl std::fmt::Debug for ConnectorEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectorEnvironment").finish_non_exhaustive()
    }
}

#[async_trait]
impl platform::ConnectorEnvironment for ConnectorEnvironment {
    // cancel-safe: the probe connection is dropped with the future; nothing shared is written.
    async fn local_addr_for_remote(
        &self,
        ctx: &CancellationToken,
        remote: Option<&UdpAddr>,
        _socket_context: platform::SocketContext,
    ) -> Result<Box<dyn Addr>> {
        let Some(remote) = remote else {
            return Err(anyhow!("easytier: missing remote address"));
        };
        let remote = UdpAddr { ip: unmap_addr(remote.ip), ..remote.clone() };
        let network = if remote.ip.is_ipv4() { "udp4" } else { "udp6" };
        let conn = self.dialer.dial_context(ctx, network, &remote.string()).await?;
        let local_addr = conn.local_addr();
        let _ = close_stream(conn.as_ref());
        Ok(Box::new(udp_addr_from_socket_addr(local_addr?)))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use anyhow::Result;
    use async_trait::async_trait;
    use hickory_proto::rr::rdata::{SRV, TXT};
    use hickory_proto::rr::Record;

    use super::platform::{DNSResolver as _, SocketFactory as _};
    use super::*;
    use murmur_common_net::split_host_port;
    use murmur_component::resolver::relay::set_rcode;
    use murmur_component::resolver::resolver::{set_proxy_server_host_resolver, Resolver, ResolverRef, SharedResolver};
    use murmur_std_compat::net::TcpAddr;

    struct TestDNSResolver {
        exchange: Box<dyn Fn(&Message) -> Result<Message> + Send + Sync>,
    }

    impl TestDNSResolver {
        fn new_resolver(exchange: impl Fn(&Message) -> Result<Message> + Send + Sync + 'static) -> Arc<ResolverRef> {
            Arc::new(Self { exchange: Box::new(exchange) })
        }
    }

    #[async_trait]
    impl Resolver for TestDNSResolver {
        async fn lookup_ip(&self, _ctx: &CancellationToken, _host: &str) -> Result<Vec<IpAddr>> {
            panic!("the test resolver embeds no resolver")
        }

        async fn lookup_ipv4(&self, _ctx: &CancellationToken, _host: &str) -> Result<Vec<IpAddr>> {
            panic!("the test resolver embeds no resolver")
        }

        async fn lookup_ipv6(&self, _ctx: &CancellationToken, _host: &str) -> Result<Vec<IpAddr>> {
            panic!("the test resolver embeds no resolver")
        }

        async fn resolve_ech(&self, _ctx: &CancellationToken, _host: &str) -> Result<Vec<u8>> {
            panic!("the test resolver embeds no resolver")
        }

        async fn exchange_context(&self, _ctx: &CancellationToken, m: &Message) -> Result<Message> {
            (self.exchange)(m)
        }

        fn invalid(&self) -> bool {
            true
        }

        fn clear_cache(&self) {}

        fn reset_connection(&self) {}
    }

    /// The proxy resolver is the only one installed, so any lookup that reached the system resolver
    /// would panic on its unset value.
    #[tokio::test]
    async fn dns_records_use_murmur_resolver() {
        let previous: Option<SharedResolver> = proxy_server_host_resolver();
        let resolver = TestDNSResolver::new_resolver(|m| {
            let mut reply = Message::new(0, MessageType::Query, OpCode::Query);
            set_rcode(&mut reply, m, ResponseCode::NoError);
            let query_type = m.queries[0].query_type();
            if query_type == RecordType::TXT {
                reply.answers = vec![Record::from_rdata(Name::root(), 0, RData::TXT(TXT::new(vec!["ok".to_owned()])))];
            } else if query_type == RecordType::SRV {
                reply.answers = vec![Record::from_rdata(
                    Name::root(),
                    0,
                    RData::SRV(SRV::new(0, 0, 11010, Name::from_utf8("peer.example.").expect("name"))),
                )];
            }
            Ok(reply)
        });
        set_proxy_server_host_resolver(Some(resolver));

        let ctx = CancellationToken::new();
        let txt = DNSResolver {}.lookup_txt(&ctx, DNSQuery { host: "example".to_owned(), ..DNSQuery::default() }).await;
        assert_eq!(Ok("ok".to_owned()), txt.map_err(|err| err.to_string()));

        let srv = DNSResolver {}.lookup_srv(&ctx, DNSQuery { host: "example".to_owned(), ..DNSQuery::default() }).await;
        let srv = srv.expect("SRV records");
        assert_eq!(1, srv.len());
        assert_eq!("peer.example.", srv[0].target);
        assert_eq!(11010, srv[0].port);

        set_proxy_server_host_resolver(previous);
    }

    #[test]
    fn udp_bind_preserves_wildcard_port() {
        let (_, address) = udp_bind(&UDPBindOptions {
            local_addr: Some(UdpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 45678)),
            ..UDPBindOptions::default()
        });
        let (_, port, _) = split_host_port(&address).expect("host:port");
        assert_eq!("45678", port);
    }

    struct ForbiddenDialer;

    #[async_trait]
    impl ConstantDialer for ForbiddenDialer {
        async fn dial_context(
            &self,
            _ctx: &CancellationToken,
            _network: &str,
            _address: &str,
        ) -> Result<Box<dyn murmur_common_net::io::Stream>> {
            panic!("unexpected proxy session");
        }

        async fn listen_packet(
            &self,
            _ctx: &CancellationToken,
            _network: &str,
            _address: &str,
            _r_addr_port: Option<SocketAddr>,
        ) -> Result<Box<dyn murmur_common_net::io::Datagram>> {
            panic!("unexpected proxy socket");
        }
    }

    #[tokio::test]
    async fn listen_tcp_internal_allowed_through_proxy_dialer() {
        let factory = SocketFactory::new(Arc::new(ForbiddenDialer));
        let ctx = CancellationToken::new();
        let bind = TCPBindOptions {
            local_addr: Some(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            ..TCPBindOptions::default()
        };

        let listener = factory
            .listen_tcp(&ctx, TCPListenOptions { bind: bind.clone(), purpose: TCPListenPurpose::TCP_LISTEN_PROXY_NAT })
            .await
            .expect("internal listener");
        listener.close().expect("close listener");

        let external =
            factory.listen_tcp(&ctx, TCPListenOptions { bind, purpose: TCPListenPurpose::TCP_LISTEN_DIRECT }).await;
        assert!(external.is_err());
    }

    /// A v4-mapped IPv6 literal is read as IPv4, so the guest's mapped address must bind as
    /// `tcp4`/`udp4` instead of the v6 family.
    #[test]
    fn mapped_ipv6_addresses_bind_in_the_ipv4_family() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201));
        let bind = TCPBindOptions { local_addr: Some(TcpAddr::new(mapped, 8443)), ..TCPBindOptions::default() };
        assert_eq!(tcp_network(&bind), "tcp4");
        assert_eq!(tcp_address(bind.local_addr.as_ref().expect("local addr")), "192.0.2.1:8443");
        let bind = UDPBindOptions { local_addr: Some(UdpAddr::new(mapped, 0)), ..UDPBindOptions::default() };
        assert_eq!(udp_bind(&bind), ("udp4".to_owned(), "192.0.2.1:0".to_owned()));
    }

    /// Only the 4-in-6 form collapses; a real v6 literal keeps its brackets.
    #[test]
    fn tcp_address_leaves_native_v6_alone() {
        assert_eq!(tcp_address(&TcpAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 11010)), "[::1]:11010");
        assert_eq!(tcp_address(&TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 11010)), "127.0.0.1:11010");
    }
}

//! Wire-vocabulary this crate shares with `sing`-protocol-based transports (vmess, shadowsocks,
//! tuic's `uot`): the `Socksaddr` address encoding, the `Dialer` contract, packet-conn/read-wait
//! abstractions, and UDP-over-TCP framing — the `metadata`, `network`, `bufio` and `uot` modules.
//!
//! Only the vocabulary murmur actually uses is mirrored here; a caller that needs more reports
//! `NEEDED SHIM ITEM: <signature>` instead of editing this file.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::pedantic,
        clippy::nursery
    )
)]

pub mod metadata {
    use std::fmt;
    use std::io;
    use std::net::{IpAddr, SocketAddr};

    use murmur_std_compat::net::{Addr, TcpAddr, UdpAddr};

    #[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
    pub struct Socksaddr {
        pub fqdn: String,
        pub addr: Option<IpAddr>,
        pub port: u16,
    }

    impl Socksaddr {
        pub fn fqdn(fqdn: impl Into<String>, port: u16) -> Self {
            Self { fqdn: fqdn.into(), addr: None, port }
        }

        #[must_use]
        pub const fn from_ip(addr: IpAddr, port: u16) -> Self {
            Self { fqdn: String::new(), addr: Some(addr), port }
        }

        #[must_use]
        pub const fn is_fqdn(&self) -> bool {
            !self.fqdn.is_empty()
        }

        #[must_use]
        pub fn is_ip(&self) -> bool {
            !self.is_fqdn()
        }

        #[must_use]
        pub fn is_ipv4(&self) -> bool {
            !self.is_fqdn() && matches!(self.addr, Some(IpAddr::V4(_)))
        }

        #[must_use]
        pub fn is_ipv6(&self) -> bool {
            !self.is_fqdn() && matches!(self.addr, Some(IpAddr::V6(_)))
        }

        #[must_use]
        pub fn is_valid(&self) -> bool {
            self.is_fqdn() || self.addr.is_some()
        }

        #[must_use]
        pub fn unwrap(&self) -> Self {
            match self.addr {
                Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
                    Some(v4) => Self::from_ip(IpAddr::V4(v4), self.port),
                    None => self.clone(),
                },
                _ => self.clone(),
            }
        }

        #[must_use]
        pub fn addr_port(&self) -> Option<SocketAddr> {
            self.addr.map(|addr| SocketAddr::new(addr, self.port))
        }

        #[must_use]
        pub fn tcp_addr(&self) -> Option<TcpAddr> {
            self.addr.map(|addr| TcpAddr::new(addr, self.port))
        }

        #[must_use]
        pub fn udp_addr(&self) -> Option<UdpAddr> {
            self.addr.map(|addr| UdpAddr::new(addr, self.port))
        }

        #[must_use]
        pub fn string(&self) -> String {
            if self.is_fqdn() {
                if self.fqdn.contains(':') {
                    format!("[{}]:{}", self.fqdn, self.port)
                } else {
                    format!("{}:{}", self.fqdn, self.port)
                }
            } else if let Some(addr) = self.addr {
                SocketAddr::new(addr, self.port).to_string()
            } else {
                String::new()
            }
        }

        #[must_use]
        pub fn from_socket_addr(addr: SocketAddr) -> Self {
            Self::from_ip(addr.ip(), addr.port())
        }
    }

    impl fmt::Display for Socksaddr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.string())
        }
    }

    impl From<SocketAddr> for Socksaddr {
        fn from(addr: SocketAddr) -> Self {
            Self::from_socket_addr(addr)
        }
    }

    impl Addr for Socksaddr {
        fn network(&self) -> &'static str {
            "socks"
        }

        fn string(&self) -> String {
            Self::string(self)
        }

        fn addr_port(&self) -> Option<murmur_std_compat::net::AddrPort> {
            Some(murmur_std_compat::net::AddrPort { port: self.port, ip: self.addr, fqdn: Some(self.fqdn.clone()) })
        }
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
    pub struct Metadata {
        pub protocol: String,
        pub source: Socksaddr,
        pub destination: Socksaddr,
    }

    fn unwrap_ipv6_address(address: &str) -> &str {
        address.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(address)
    }

    #[must_use]
    pub fn parse_socksaddr_host_port(host: &str, port: u16) -> Socksaddr {
        match unwrap_ipv6_address(host).parse::<IpAddr>() {
            Ok(addr) => Socksaddr::from_ip(addr, port),
            Err(_) => Socksaddr::fqdn(host, port),
        }
    }

    /// Parses a decimal integer, keeping the value it returns on error too: the caller uses the
    /// value unconditionally. Private copy: this file is the only caller that needs it after the
    /// crate split.
    fn parse_int(s: &str) -> i64 {
        const CUTOFF: u64 = 1u64 << 63;
        let (neg, digits) = match s.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, s.strip_prefix('+').unwrap_or(s)),
        };
        if digits.is_empty() {
            return 0;
        }
        let mut n: u64 = 0;
        for b in digits.bytes() {
            if !b.is_ascii_digit() {
                return 0;
            }
            n = match n.checked_mul(10).and_then(|v| v.checked_add(u64::from(b - b'0'))) {
                Some(v) => v,
                None => return if neg { i64::MIN } else { i64::MAX },
            };
        }
        if neg {
            if n > CUTOFF {
                i64::MIN
            } else {
                n.cast_signed().wrapping_neg()
            }
        } else if n >= CUTOFF {
            i64::MAX
        } else {
            n.cast_signed()
        }
    }

    #[must_use]
    pub fn parse_socksaddr(address: &str) -> Socksaddr {
        // A local host-and-port split: the has-port-default handling, without depending on
        // `common::net` (crate split: that crate already depends on this one normally, for its
        // wire-vocabulary types).
        let (temp, has_port) = if address.contains(':') || address.contains("]:") {
            (address.to_owned(), true)
        } else {
            (format!("{address}:0"), false)
        };
        match murmur_common::net_addr::split_host_port(&temp) {
            Ok((host, port)) if has_port => {
                // The port is a 16-bit wire field, so the value keeps its low two bytes.
                let port = u16::try_from(parse_int(&port) & 0xffff).unwrap_or_default();
                parse_socksaddr_host_port(&host, port)
            }
            _ => parse_socksaddr_host_port(address, 0),
        }
    }

    /// Builds a [`Socksaddr`] from an IP address and port.
    #[must_use]
    pub const fn socksaddr_from(addr: Option<IpAddr>, port: u16) -> Socksaddr {
        Socksaddr { fqdn: String::new(), addr, port }
    }

    #[must_use]
    pub fn socksaddr_from_net(addr: Option<&dyn Addr>) -> Socksaddr {
        let Some(addr) = addr else {
            return Socksaddr::default();
        };
        if let Some(addr_port) = addr.addr_port() {
            return Socksaddr { fqdn: addr_port.fqdn.unwrap_or_default(), addr: addr_port.ip, port: addr_port.port };
        }
        parse_socksaddr(&addr.string())
    }

    pub type Family = u8;
    pub const ADDRESS_FAMILY_IPV4: Family = 0x01;
    pub const ADDRESS_FAMILY_IPV6: Family = 0x04;
    pub const ADDRESS_FAMILY_FQDN: Family = 0x03;
    pub const ADDRESS_FAMILY_EMPTY: Family = 0xff;

    /// Address serialization.
    ///
    /// No caller needs port-first framing, and every reader in this tree parses its own family
    /// byte inline against an async conn instead of a blocking reader.
    #[derive(Debug)]
    pub struct Serializer {
        family_byte_map: Vec<(Family, u8)>,
    }

    impl Serializer {
        #[must_use]
        pub fn new(byte_options: &[(u8, Family)]) -> Self {
            Self { family_byte_map: byte_options.iter().map(|&(byte, family)| (family, byte)).collect() }
        }

        fn family_byte(&self, family: Family) -> Option<u8> {
            self.family_byte_map.iter().find(|&&(f, _)| f == family).map(|&(_, byte)| byte)
        }

        pub fn write_address(&self, buffer: &mut Vec<u8>, addr: &Socksaddr) -> io::Result<()> {
            let family = if !addr.is_valid() {
                ADDRESS_FAMILY_EMPTY
            } else if addr.is_ipv4() {
                ADDRESS_FAMILY_IPV4
            } else if addr.is_ipv6() {
                ADDRESS_FAMILY_IPV6
            } else {
                ADDRESS_FAMILY_FQDN
            };
            let byte = self
                .family_byte(family)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unsupported address"))?;
            buffer.push(byte);
            match (family, addr.addr) {
                (ADDRESS_FAMILY_IPV4, Some(IpAddr::V4(v4))) => buffer.extend_from_slice(&v4.octets()),
                (ADDRESS_FAMILY_IPV6, Some(IpAddr::V6(v6))) => buffer.extend_from_slice(&v6.octets()),
                (ADDRESS_FAMILY_FQDN, _) => write_socks_string(buffer, &addr.fqdn)?,
                _ => {}
            }
            Ok(())
        }

        #[must_use]
        pub fn address_len(&self, addr: &Socksaddr) -> usize {
            if !addr.is_valid() {
                1
            } else if addr.is_ipv4() {
                5
            } else if addr.is_ipv6() {
                17
            } else {
                2 + addr.fqdn.len()
            }
        }

        pub fn write_port(&self, buffer: &mut Vec<u8>, port: u16) {
            buffer.extend_from_slice(&port.to_be_bytes());
        }

        pub fn write_addr_port(&self, buffer: &mut Vec<u8>, destination: &Socksaddr) -> io::Result<()> {
            self.write_address(buffer, destination)?;
            if destination.is_valid() {
                self.write_port(buffer, destination.port);
            }
            Ok(())
        }

        #[must_use]
        pub fn addr_port_len(&self, destination: &Socksaddr) -> usize {
            if destination.is_valid() {
                self.address_len(destination) + 2
            } else {
                self.address_len(destination)
            }
        }
    }

    pub fn write_socks_string(buffer: &mut Vec<u8>, s: &str) -> io::Result<()> {
        let len = u8::try_from(s.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "fqdn too long"))?;
        buffer.push(len);
        buffer.extend_from_slice(s.as_bytes());
        Ok(())
    }

    pub static SOCKSADDR_SERIALIZER: std::sync::LazyLock<Serializer> = std::sync::LazyLock::new(|| {
        Serializer::new(&[(0x01, ADDRESS_FAMILY_IPV4), (0x04, ADDRESS_FAMILY_IPV6), (0x03, ADDRESS_FAMILY_FQDN)])
    });
}

pub mod network {
    use std::io;
    use std::sync::Arc;

    use anyhow::Result;
    use async_trait::async_trait;
    use tokio_util::sync::CancellationToken;

    use crate::metadata::Socksaddr;
    use murmur_compat::sing_buf::UDP_BUFFER_SIZE;
    use murmur_compat::sing_buf::{new_size, Buffer, BUFFER_SIZE};
    use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn as NetPacketConn};

    /// The dialer contract: its returns are the connection/packet-conn traits aliased in from
    /// `murmur_std_compat::net`.
    #[async_trait]
    pub trait Dialer: Send + Sync {
        async fn dial_context(
            &self,
            ctx: &CancellationToken,
            network: &str,
            destination: Socksaddr,
        ) -> Result<Box<dyn NetConn>>;

        async fn listen_packet(
            &self,
            ctx: &CancellationToken,
            destination: Socksaddr,
        ) -> Result<Box<dyn NetPacketConn>>;
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ReadWaitOptions {
        pub front_headroom: usize,
        pub rear_headroom: usize,
        pub mtu: usize,
    }

    impl ReadWaitOptions {
        #[must_use]
        pub const fn need_headroom(&self) -> bool {
            self.front_headroom > 0 || self.rear_headroom > 0
        }

        #[must_use]
        pub fn new_buffer(&self) -> Buffer {
            self.make_buffer(BUFFER_SIZE, true)
        }

        #[must_use]
        pub fn new_packet_buffer(&self) -> Buffer {
            self.make_buffer(UDP_BUFFER_SIZE, true)
        }

        fn make_buffer(&self, default_buffer_size: i32, reserve: bool) -> Buffer {
            let buffer_size = if self.mtu > 0 {
                // An MTU whose headroomed size does not fit the allocator's i32 length keeps
                // the default packet buffer instead of wrapping to an arbitrary one.
                i32::try_from(self.mtu + self.front_headroom + self.rear_headroom).unwrap_or(default_buffer_size)
            } else {
                default_buffer_size
            };
            let mut buffer = new_size(buffer_size);
            if self.front_headroom > 0 {
                buffer.resize(self.front_headroom, 0);
            }
            if self.rear_headroom > 0 && reserve {
                buffer.reserve(self.rear_headroom);
            }
            buffer
        }

        pub fn copy(&self, mut buffer: Buffer) -> Buffer {
            if self.front_headroom > buffer.start() || self.rear_headroom > buffer.free_len() {
                let mut new_buffer = self.make_buffer(UDP_BUFFER_SIZE, false);
                let _ = new_buffer.write_bytes(buffer.bytes());
                buffer.release();
                new_buffer
            } else {
                buffer
            }
        }

        pub fn post_return(&self, buffer: &mut Buffer) {
            if self.rear_headroom > 0 {
                buffer.over_cap(self.rear_headroom);
            }
        }
    }

    #[derive(Debug)]
    pub struct PacketBuffer {
        pub buffer: Buffer,
        pub destination: Socksaddr,
    }

    #[async_trait]
    pub trait PacketReader: Send + Sync {
        async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr>;
    }

    #[async_trait]
    pub trait PacketWriter: Send + Sync {
        async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()>;
    }

    #[async_trait]
    pub trait NetPacketReader: PacketReader {
        async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)>;
    }

    #[async_trait]
    pub trait NetPacketWriter: PacketWriter {
        async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize>;
    }

    #[async_trait]
    pub trait PacketConn: PacketReader + PacketWriter {
        async fn close(&self) -> io::Result<()>;
        fn local_addr(&self) -> io::Result<Box<dyn Addr>>;
        fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            Ok(())
        }
        fn set_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    pub trait NetworkPacketConn: NetPacketReader + NetPacketWriter {
        async fn close(&self) -> io::Result<()>;
        fn local_addr(&self) -> io::Result<Box<dyn Addr>>;
    }

    pub trait ReadWaitable: Send + Sync {
        fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool;
    }

    #[async_trait]
    pub trait ReadWaiter: ReadWaitable {
        async fn wait_read_buffer(&self) -> io::Result<Buffer>;
    }

    pub trait ReadWaitCreator {
        fn create_read_waiter(&self) -> Option<Box<dyn ReadWaiter>>;
    }

    #[async_trait]
    pub trait PacketReadWaiter: ReadWaitable {
        async fn wait_read_packet(&self) -> io::Result<(Buffer, Socksaddr)>;
    }

    pub trait PacketReadWaitCreator {
        fn create_read_waiter(&self) -> Option<Box<dyn PacketReadWaiter>>;
    }

    pub fn create_packet_read_waiter(reader: Arc<dyn PacketReader>) -> Box<dyn PacketReadWaiter> {
        Box::new(CopyPacketReadWaiter { reader })
    }

    struct CopyPacketReadWaiter {
        reader: Arc<dyn PacketReader>,
    }

    impl ReadWaitable for CopyPacketReadWaiter {
        fn initialize_read_waiter(&self, _options: ReadWaitOptions) -> bool {
            true
        }
    }

    #[async_trait]
    impl PacketReadWaiter for CopyPacketReadWaiter {
        async fn wait_read_packet(&self) -> io::Result<(Buffer, Socksaddr)> {
            let mut buffer = murmur_compat::sing_buf::new_packet();
            let destination = self.reader.read_packet(&mut buffer).await?;
            Ok((buffer, destination))
        }
    }
}

pub mod bufio {
    use std::io;
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use crate::metadata::{socksaddr_from_net, Socksaddr};
    use crate::network::{NetPacketWriter, PacketReadWaiter, PacketReader, PacketWriter};
    use murmur_compat::sing_buf::{as_ as buffer_as, Buffer};
    use murmur_std_compat::net::Addr;

    pub fn create_packet_read_waiter(reader: Arc<dyn PacketReader>) -> Box<dyn PacketReadWaiter> {
        crate::network::create_packet_read_waiter(reader)
    }

    struct PacketWriterAdapter(Arc<dyn PacketWriter>);

    #[async_trait]
    impl PacketWriter for PacketWriterAdapter {
        async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
            self.0.write_packet(buffer, destination).await
        }
    }

    #[async_trait]
    impl NetPacketWriter for PacketWriterAdapter {
        async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
            let destination = socksaddr_from_net(Some(addr));
            let buffer = buffer_as(p.to_vec());
            self.write_packet(&buffer, &destination).await?;
            Ok(p.len())
        }
    }

    pub fn new_net_packet_writer(conn: Arc<dyn PacketWriter>) -> Arc<dyn NetPacketWriter> {
        Arc::new(PacketWriterAdapter(conn))
    }

    /// Writes every buffer in order as one call.
    ///
    /// The raw-fd `writev` fast path is unavailable because this crate denies `unsafe`
    /// crate-wide, so this always takes the safe concatenate-then-write path used for
    /// non-syscall writers.
    pub async fn create_vectorised_writer<W>(writer: &mut W, buffers: &[&[u8]]) -> io::Result<()>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        match buffers {
            [] => writer.write_all(&[]).await,
            [only] => writer.write_all(only).await,
            _ => {
                let mut concatenated = Vec::with_capacity(buffers.iter().map(|b| b.len()).sum());
                for b in buffers {
                    concatenated.extend_from_slice(b);
                }
                writer.write_all(&concatenated).await
            }
        }
    }
}

pub mod auth {
    /// Backs `context_with_user`/`user_from_context`: a trait any typed context struct in this
    /// tree can implement for its own user type.
    pub trait UserContext<T> {
        #[must_use]
        fn with_user(self, user: T) -> Self;
        fn user_ref(&self) -> Option<&T>;
    }

    pub fn context_with_user<T, C: UserContext<T>>(ctx: C, user: T) -> C {
        ctx.with_user(user)
    }

    pub fn user_from_context<T: Clone, C: UserContext<T>>(ctx: &C) -> Option<T> {
        ctx.user_ref().cloned()
    }
}

pub mod uot {
    use std::io;

    use async_trait::async_trait;
    use parking_lot::Mutex;
    use tokio::io::{AsyncRead, AsyncReadExt};

    use crate::bufio::create_vectorised_writer;
    use crate::metadata::{Serializer, Socksaddr, ADDRESS_FAMILY_FQDN, ADDRESS_FAMILY_IPV4, ADDRESS_FAMILY_IPV6};
    use crate::network::{PacketReader, PacketWriter};
    use murmur_common::shared_conn::SharedConn;
    use murmur_compat::sing_buf::Buffer;
    use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn, UdpAddr};

    pub const VERSION: u8 = 2;
    pub const LEGACY_VERSION: u8 = 1;
    pub const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
    pub const LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

    static ADDR_PARSER: std::sync::LazyLock<Serializer> = std::sync::LazyLock::new(|| {
        Serializer::new(&[(0x00, ADDRESS_FAMILY_IPV4), (0x01, ADDRESS_FAMILY_IPV6), (0x02, ADDRESS_FAMILY_FQDN)])
    });

    #[must_use]
    pub fn request_destination(version: u8) -> Socksaddr {
        match version {
            0 | VERSION => Socksaddr::fqdn(MAGIC_ADDRESS, 0),
            _ => Socksaddr::fqdn(LEGACY_MAGIC_ADDRESS, 0),
        }
    }

    #[derive(Clone, Debug)]
    pub struct Request {
        pub is_connect: bool,
        pub destination: Socksaddr,
    }

    fn encode_request(request: &Request) -> io::Result<Vec<u8>> {
        let mut buf = vec![u8::from(request.is_connect)];
        crate::metadata::SOCKSADDR_SERIALIZER.write_addr_port(&mut buf, &request.destination)?;
        Ok(buf)
    }

    async fn read_addr_port<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<Socksaddr> {
        read_addr_port_with_families(reader, [0x00, 0x01, 0x02]).await
    }

    async fn read_addr_port_with_families<R: AsyncRead + Unpin + ?Sized>(
        reader: &mut R,
        [ipv4, ipv6, fqdn]: [u8; 3],
    ) -> io::Result<Socksaddr> {
        let mut family = [0u8; 1];
        reader.read_exact(&mut family).await?;
        let mut addr = match family[0] {
            family if family == ipv4 => {
                let mut b = [0u8; 4];
                reader.read_exact(&mut b).await?;
                Socksaddr::from_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(b)), 0)
            }
            family if family == ipv6 => {
                let mut b = [0u8; 16];
                reader.read_exact(&mut b).await?;
                Socksaddr::from_ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(b)), 0)
            }
            family if family == fqdn => {
                let mut len = [0u8; 1];
                reader.read_exact(&mut len).await?;
                let mut fqdn = vec![0u8; len[0] as usize];
                reader.read_exact(&mut fqdn).await?;
                Socksaddr::fqdn(String::from_utf8_lossy(&fqdn).into_owned(), 0)
            }
            other => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("uot: unknown address family {other}")))
            }
        };
        let mut port = [0u8; 2];
        reader.read_exact(&mut port).await?;
        addr.port = u16::from_be_bytes(port);
        Ok(addr)
    }

    pub async fn read_request<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<Request> {
        let mut is_connect = [0u8; 1];
        reader.read_exact(&mut is_connect).await?;
        let destination = read_addr_port_with_families(reader, [0x01, 0x04, 0x03]).await?;
        Ok(Request { is_connect: is_connect[0] != 0, destination })
    }

    fn socksaddr_to_addr(destination: &Socksaddr) -> Box<dyn Addr> {
        match destination.addr {
            Some(ip) => Box::new(UdpAddr::new(ip, destination.port)),
            None => Box::new(UdpAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), destination.port)),
        }
    }

    /// Builds a [`Socksaddr`] from a resolved address, for the two address kinds this crate's packet-conn
    /// callers hand back.
    fn socksaddr_from_addr(addr: &dyn Addr) -> Socksaddr {
        match murmur_std_compat::net::sock_addr_of(addr) {
            Some(murmur_std_compat::net::SockAddr::Tcp(tcp)) => Socksaddr::from_ip(tcp.ip, tcp.port),
            Some(murmur_std_compat::net::SockAddr::Udp(udp)) => Socksaddr::from_ip(udp.ip, udp.port),
            None => addr.string().parse::<std::net::SocketAddr>().map(Socksaddr::from_socket_addr).unwrap_or_default(),
        }
    }

    /// A UDP-over-TCP connection, covering both the packet-conn surface (`read_from`/`write_to`) and the
    /// packet-reader/writer surface (`read_packet`/`write_packet`).
    ///
    /// One type therefore serves both the listener side
    /// (`network::PacketReader`/`PacketWriter`) and the outbound side
    /// (`murmur_std_compat::net::PacketConn`). `pending_request` holds the encoded
    /// [`Request`] for the lazy-conn variant until the first write.
    /// The plain conn variant never populates it, so no header is ever sent.
    pub struct Conn {
        shared: SharedConn,
        is_connect: bool,
        destination: Socksaddr,
        pending_request: Mutex<Option<Request>>,
    }

    impl core::fmt::Debug for Conn {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Conn")
                .field("is_connect", &self.is_connect)
                .field("destination", &self.destination)
                .field("pending_request", &self.pending_request)
                .finish_non_exhaustive()
        }
    }

    impl Conn {
        fn build(conn: Box<dyn NetConn>, request: Request, lazy: bool) -> Self {
            Self {
                shared: SharedConn::from_boxed(conn),
                is_connect: request.is_connect,
                destination: request.destination.clone(),
                pending_request: Mutex::new(if lazy { Some(request) } else { None }),
            }
        }

        async fn write_frame(&self, header_tail: &[u8], payload: &[u8]) -> io::Result<()> {
            let pending = self.pending_request.lock().take();
            let prefix = match &pending {
                Some(request) => Some(encode_request(request)?),
                None => None,
            };
            let mut conn = self.shared.clone();
            let buffers: Vec<&[u8]> = match &prefix {
                Some(prefix) => vec![prefix.as_slice(), header_tail, payload],
                None => vec![header_tail, payload],
            };
            create_vectorised_writer(&mut conn, &buffers).await
        }
    }

    #[must_use]
    pub fn new_conn(conn: Box<dyn NetConn>, request: Request) -> Conn {
        Conn::build(conn, request, false)
    }

    #[must_use]
    pub fn new_lazy_conn(conn: Box<dyn NetConn>, request: Request) -> Conn {
        Conn::build(conn, request, true)
    }

    #[async_trait]
    impl PacketReader for Conn {
        async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
            let mut conn = self.shared.clone();
            let destination =
                if self.is_connect { self.destination.clone() } else { read_addr_port(&mut conn).await? };
            let mut length = [0u8; 2];
            conn.read_exact(&mut length).await?;
            let length = u16::from_be_bytes(length) as usize;
            buffer.read_full_from(&mut conn, length).await?;
            Ok(destination)
        }
    }

    #[async_trait]
    impl PacketWriter for Conn {
        async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
            let mut addr_header = Vec::new();
            if !self.is_connect {
                ADDR_PARSER.write_addr_port(&mut addr_header, destination)?;
            }
            // The frame length prefix is a 16-bit wire field: a longer payload keeps its low
            // two bytes, which always fit.
            let length = u16::try_from(buffer.len() & 0xffff).unwrap_or_default();
            addr_header.extend_from_slice(&length.to_be_bytes());
            self.write_frame(&addr_header, buffer.bytes()).await
        }
    }

    #[async_trait]
    impl PacketConn for Conn {
        async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
            let mut conn = self.shared.clone();
            let destination =
                if self.is_connect { self.destination.clone() } else { read_addr_port(&mut conn).await? };
            let mut length_buf = [0u8; 2];
            conn.read_exact(&mut length_buf).await?;
            let length = u16::from_be_bytes(length_buf) as usize;
            let Some(payload) = buf.get_mut(..length) else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "UoT read: short buffer"));
            };
            conn.read_exact(payload).await?;
            Ok((length, socksaddr_to_addr(&destination)))
        }

        async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
            let mut addr_header = Vec::new();
            if !self.is_connect {
                ADDR_PARSER.write_addr_port(&mut addr_header, &socksaddr_from_addr(addr))?;
            }
            let length = u16::try_from(buf.len() & 0xffff).unwrap_or_default();
            addr_header.extend_from_slice(&length.to_be_bytes());
            self.write_frame(&addr_header, buf).await?;
            Ok(buf.len())
        }

        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            self.shared.local_addr()
        }

        fn close(&self) -> io::Result<()> {
            self.shared.close()
        }
    }

    #[async_trait]
    impl crate::network::PacketConn for Conn {
        async fn close(&self) -> io::Result<()> {
            self.shared.close()
        }

        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            self.shared.local_addr()
        }
    }

    #[cfg(test)]
    mod wire_tests {
        use super::*;

        // sing v0.5.7 common/uot/protocol.go uses metadata/socksaddr.go for requests,
        // not the separate datagram address family mapping.
        fn reference_addresses() -> [(Socksaddr, &'static [u8], &'static [u8]); 3] {
            [
                (
                    Socksaddr::from_ip("192.0.2.1".parse().expect("test IPv4"), 53),
                    &[0x01, 192, 0, 2, 1, 0x00, 0x35],
                    &[0x00, 192, 0, 2, 1, 0x00, 0x35],
                ),
                (
                    Socksaddr::from_ip("2001:db8::1".parse().expect("test IPv6"), 443),
                    &[0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb],
                    &[0x01, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb],
                ),
                (Socksaddr::fqdn("example.com", 8080), b"\x03\x0bexample.com\x1f\x90", b"\x02\x0bexample.com\x1f\x90"),
            ]
        }

        #[test]
        fn request_encoding_matches_reference_socks_address_bytes() {
            for (destination, address, _) in reference_addresses() {
                for is_connect in [false, true] {
                    let request = Request { is_connect, destination: destination.clone() };
                    let expected = [&[u8::from(is_connect)][..], address].concat();
                    assert_eq!(encode_request(&request).expect("encode request"), expected, "{request:?}");
                }
            }
        }

        #[tokio::test]
        async fn request_decoding_matches_reference_socks_address_bytes() {
            for (destination, address, _) in reference_addresses() {
                for is_connect in [false, true] {
                    let wire = [&[u8::from(is_connect)][..], address, b"next frame"].concat();
                    let mut reader = wire.as_slice();
                    let request = read_request(&mut reader).await.expect("decode reference request");
                    assert_eq!(request.is_connect, is_connect);
                    assert_eq!(request.destination, destination);
                    assert_eq!(reader, b"next frame");
                }
            }
        }

        #[test]
        fn datagram_encoding_keeps_reference_uot_address_bytes() {
            for (destination, _, address) in reference_addresses() {
                let mut wire = Vec::new();
                ADDR_PARSER.write_addr_port(&mut wire, &destination).expect("encode datagram address");
                assert_eq!(wire, address, "{destination:?}");
            }
        }

        #[tokio::test]
        async fn datagram_decoding_keeps_reference_uot_address_bytes() {
            for (destination, _, address) in reference_addresses() {
                let wire = [address, b"next frame"].concat();
                let mut reader = wire.as_slice();
                assert_eq!(read_addr_port(&mut reader).await.expect("decode datagram address"), destination);
                assert_eq!(reader, b"next frame");
            }
        }
    }
}

#[cfg(test)]
mod uot_tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use murmur_compat::sing_buf::{new_packet, new_size, Buffer};
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    use crate::metadata::Socksaddr;
    use crate::network::{PacketReader, PacketWriter};
    use crate::uot::{self, Request};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind uot listener");
        let addr = listener.local_addr().expect("uot listener addr");
        let client = TcpStream::connect(addr).await.expect("connect uot client");
        let (server, _) = listener.accept().await.expect("accept uot client");
        (client, server)
    }

    fn payload(bytes: &[u8]) -> Buffer {
        let mut buffer = new_size(i32::try_from(bytes.len()).expect("payload fits a packet"));
        buffer.write_bytes(bytes).expect("payload fits a packet");
        buffer
    }

    async fn read_packet(server: &uot::Conn) -> (Socksaddr, Vec<u8>) {
        let mut buffer = new_packet();
        let from = tokio::time::timeout(Duration::from_secs(5), server.read_packet(&mut buffer))
            .await
            .expect("uot packet within timeout")
            .expect("read uot packet");
        (from, buffer.bytes()[..buffer.len()].to_vec())
    }

    /// Addressed mode writes the destination ahead of every packet, so a read must return the
    /// per-packet address rather than whatever address the conn was configured with.
    #[tokio::test]
    async fn addressed_mode_round_trips_each_destination() {
        let (client_tcp, server_tcp) = tcp_pair().await;
        let client =
            uot::new_conn(Box::new(client_tcp), Request { is_connect: false, destination: Socksaddr::default() });
        let server = uot::new_conn(
            Box::new(server_tcp),
            Request { is_connect: false, destination: Socksaddr::fqdn("stale.example", 1) },
        );

        let first = Socksaddr::from_ip("192.0.2.1".parse().expect("test ip"), 53);
        let second = Socksaddr::fqdn("example.com", 443);
        client.write_packet(&payload(b"one"), &first).await.expect("write first packet");
        client.write_packet(&payload(b"two"), &second).await.expect("write second packet");

        let (from, body) = read_packet(&server).await;
        assert_eq!(from, first);
        assert_eq!(body, b"one");

        let (from, body) = read_packet(&server).await;
        assert_eq!(from, second);
        assert_eq!(body, b"two");
    }

    /// Connect mode omits the per-packet address, so a frame on the wire is exactly the
    /// two-byte length followed by the payload. An addressed frame for `192.0.2.1:53` would
    /// instead start `00 c0 00 02 01 00 35 00`, so the first two bytes alone tell the modes
    /// apart and prove nothing was prepended.
    #[tokio::test]
    async fn connect_mode_emits_a_bare_length_prefix() {
        let (client_tcp, mut server_tcp) = tcp_pair().await;
        let destination = Socksaddr::fqdn("example.com", 443);
        let client = uot::new_conn(Box::new(client_tcp), Request { is_connect: true, destination });

        client.write_packet(&payload(b"ping"), &Socksaddr::default()).await.expect("write uot packet");

        let mut frame = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(5), server_tcp.read_exact(&mut frame))
            .await
            .expect("uot frame within timeout")
            .expect("read uot frame");
        assert_eq!(frame, [0x00, 0x04, b'p', b'i', b'n', b'g']);
    }

    /// Only the lazy variant emits a request, and only ahead of the first frame.
    #[tokio::test]
    async fn lazy_conn_sends_its_request_header_exactly_once() {
        let (client_tcp, mut server_tcp) = tcp_pair().await;
        let destination = Socksaddr::from_ip("198.51.100.7".parse().expect("test ip"), 8080);
        let client =
            uot::new_lazy_conn(Box::new(client_tcp), Request { is_connect: false, destination: destination.clone() });

        let target = Socksaddr::fqdn("example.com", 443);
        client.write_packet(&payload(b"first"), &target).await.expect("write first packet");

        let request = tokio::time::timeout(Duration::from_secs(5), uot::read_request(&mut server_tcp))
            .await
            .expect("uot request within timeout")
            .expect("read uot request");
        assert!(!request.is_connect);
        assert_eq!(request.destination, destination);

        let server =
            uot::new_conn(Box::new(server_tcp), Request { is_connect: false, destination: Socksaddr::default() });
        let (from, body) = read_packet(&server).await;
        assert_eq!(from, target);
        assert_eq!(body, b"first");

        client.write_packet(&payload(b"second"), &target).await.expect("write second packet");
        let (from, body) = read_packet(&server).await;
        assert_eq!(from, target);
        assert_eq!(body, b"second");
    }
}

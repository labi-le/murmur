use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::time::Instant;

use murmur_common::lru::{self, LruCache};
use murmur_common_net::{BufferedConn, BufioError};
use murmur_constant::adapters::{PacketAdapter, PacketSender};
use murmur_constant::dns::DNSMode;
use murmur_constant::matcher::{DomainMatcher, IpMatcher};
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_constant::sniffer::sniffer::{ReplaceDomain, Sniffer, Type, LIST};
use murmur_log::{debugln, errorln};
use murmur_std_compat::net::Conn as NetConn;

use super::base_sniffer::SnifferConfig;
use super::http_sniffer::HTTPSniffer;
use super::quic_sniffer::QUICSniffer;
use super::tls_sniffer::{ErrNeedAtLeastData, TLSSniffer};

#[derive(Debug, Error)]
#[error("unsupported sniffer")]
pub struct ErrorUnsupportedSniffer;

#[derive(Debug, Error)]
#[error("all sniffer failed")]
pub struct ErrorSniffFailed;

#[derive(Debug, Error)]
#[error("not enough information for making a decision")]
pub struct ErrNoClue;

const MAX_SNIFF_BUFFER_SIZE: usize = 64 * 1024;

pub(crate) struct ConfiguredSniffer {
    sniffer: Box<dyn Sniffer>,
    config: SnifferConfig,
}

impl ConfiguredSniffer {
    fn supports_network(&self, network: NetWork) -> bool {
        let supported = self.sniffer.support_network();
        supported == network || supported == NetWork::ALL_NET
    }
}

pub struct Dispatcher {
    pub(crate) enable: bool,
    pub(crate) sniffers: Vec<ConfiguredSniffer>,
    pub(crate) force_domain: Vec<Arc<dyn DomainMatcher>>,
    pub(crate) skip_src_address: Vec<Arc<dyn IpMatcher>>,
    pub(crate) skip_dst_address: Vec<Arc<dyn IpMatcher>>,
    pub(crate) skip_domain: Vec<Arc<dyn DomainMatcher>>,
    pub(crate) skip_list: LruCache<(Option<IpAddr>, u16), u8>,
    pub(crate) force_dns_mapping: bool,
    pub(crate) parse_pure_ip: bool,
}

/// The matcher vectors hold trait objects that are not `Debug`, so this reports their sizes only.
impl core::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dispatcher")
            .field("enable", &self.enable)
            .field("sniffers", &self.sniffers.len())
            .field("force_domain", &self.force_domain.len())
            .field("skip_src_address", &self.skip_src_address.len())
            .field("skip_dst_address", &self.skip_dst_address.len())
            .field("skip_domain", &self.skip_domain.len())
            .field("force_dns_mapping", &self.force_dns_mapping)
            .field("parse_pure_ip", &self.parse_pure_ip)
            .finish_non_exhaustive()
    }
}

fn addr_to_string(ip: Option<IpAddr>) -> String {
    match ip {
        Some(ip) => ip.to_string(),
        None => "invalid IP".to_owned(),
    }
}

fn addr_port_to_string(ip: Option<IpAddr>, port: u16) -> String {
    match ip {
        Some(ip) => std::net::SocketAddr::new(ip, port).to_string(),
        None => "invalid AddrPort".to_owned(),
    }
}

/// `Sniffer::sniff_data` returns `anyhow::Result<String>` (the trait lives outside this module,
/// in `constant::sniffer::sniffer`), so this is the one place left that inspects the concrete
/// type of a sniff failure instead of matching a vocabulary. Centralizes that downcast: `Some`
/// means "call again once this many bytes are buffered", `None` means "not this protocol".
fn need_more_data(err: &anyhow::Error) -> Option<usize> {
    err.downcast_ref::<ErrNeedAtLeastData>().map(|need| need.length)
}

impl Dispatcher {
    fn should_override(&self, metadata: &Metadata) -> bool {
        for matcher in &self.skip_dst_address {
            if let Some(ip) = metadata.dst_ip {
                if matcher.match_ip(ip) {
                    return false;
                }
            }
        }
        for matcher in &self.skip_src_address {
            if let Some(ip) = metadata.src_ip {
                if matcher.match_ip(ip) {
                    return false;
                }
            }
        }
        if metadata.host.is_empty() && self.parse_pure_ip {
            return true;
        }
        if metadata.dns_mode == DNSMode::DNS_MAPPING && self.force_dns_mapping {
            return true;
        }
        self.force_sniff(metadata)
    }

    fn force_sniff(&self, metadata: &Metadata) -> bool {
        self.force_domain.iter().any(|matcher| matcher.match_domain(&metadata.host))
    }

    /// The UDP sniff entry point. `packet` only exposes a read-only `Metadata()`, so the caller
    /// passes the mutable `Metadata` it shares with `packet` separately, the same convention
    /// `QuicPacketSender::do_sniff` already uses.
    pub fn udp_sniff(
        &self,
        packet: &Arc<dyn PacketAdapter>,
        metadata: &mut Metadata,
        packet_sender: Arc<dyn PacketSender>,
    ) -> Arc<dyn PacketSender> {
        if self.should_override(metadata) {
            for current in &self.sniffers {
                if current.supports_network(NetWork::UDP) {
                    let in_whitelist = current.sniffer.support_port(metadata.dst_port);
                    let override_dest = current.config.override_dest;

                    if in_whitelist {
                        let replace_domain_fn = make_domain_replacer(self.skip_domain.clone(), override_dest);

                        if let Some(wrapable) = current.sniffer.as_multi_packet() {
                            return wrapable.wrapper_sender(packet_sender, replace_domain_fn);
                        }

                        let Ok(host) = current.sniffer.sniff_data(packet.data()) else {
                            continue;
                        };

                        replace_domain_fn(metadata, &host);
                        return packet_sender;
                    }
                }
            }
        }

        packet_sender
    }

    pub async fn tcp_sniff(&self, conn: &mut BufferedConn, metadata: &mut Metadata) -> bool {
        if !self.should_override(metadata) {
            return false;
        }

        let mut in_whitelist = false;
        for current in &self.sniffers {
            if current.supports_network(NetWork::TCP) {
                in_whitelist = current.sniffer.support_port(metadata.dst_port);
                if in_whitelist {
                    break;
                }
            }
        }

        if !in_whitelist {
            return false;
        }
        let force_sniffer = self.force_sniff(metadata);

        let dst = (metadata.dst_ip, metadata.dst_port);
        if !force_sniffer {
            let (count, ok) = self.skip_list.get(&dst);
            if ok && count > 5 {
                debugln!("[Sniffer] Skip sniffing[{}] due to multiple failures", addr_port_to_string(dst.0, dst.1));
                return false;
            }
        }

        let (host, config) = match self.sniff_domain(conn, metadata).await {
            Ok(result) => result,
            Err(_err) => {
                if !force_sniffer {
                    self.cache_sniff_failed(metadata);
                }
                debugln!(
                    "[Sniffer] All sniffing sniff failed with from [{}:{}] to [{}:{}]",
                    addr_to_string(metadata.src_ip),
                    metadata.src_port,
                    metadata.string(),
                    metadata.dst_port
                );
                return false;
            }
        };

        if !self.domain_can_replace(&host) {
            debugln!("[Sniffer] Skip sni[{}]", host);
            return false;
        }

        self.skip_list.delete(dst);

        replace_domain(metadata, &host, config.override_dest);
        true
    }

    fn domain_can_replace(&self, host: &str) -> bool {
        domain_can_replace_with(&self.skip_domain, host)
    }

    /// Whether the dispatcher is enabled; callers hold an `Option<Dispatcher>` and check it there.
    pub const fn enable(&self) -> bool {
        self.enable
    }

    async fn sniff_domain(
        &self,
        conn: &mut BufferedConn,
        metadata: &Metadata,
    ) -> anyhow::Result<(String, SnifferConfig)> {
        struct Candidate<'a> {
            configured: &'a ConfiguredSniffer,
            want: usize,
        }

        let mut candidates: Vec<Candidate> = self
            .sniffers
            .iter()
            .filter(|current| current.supports_network(NetWork::TCP) && current.sniffer.support_port(metadata.dst_port))
            .map(|current| Candidate { configured: current, want: 1 })
            .collect();

        if candidates.is_empty() {
            return Err(ErrorSniffFailed.into());
        }

        let _ = conn.set_read_deadline(Some(Instant::now() + Duration::from_secs(1)));
        let (_, err) = conn.peek(1).await;
        let _ = conn.set_read_deadline(None);
        if let Err(err) = err {
            debugln!("[Sniffer] [{}] the data length not enough, error: {}", addr_to_string(metadata.dst_ip), err);
            return Err(err.into());
        }

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut want = conn.buffered();
        while !candidates.is_empty() {
            if want > MAX_SNIFF_BUFFER_SIZE && want > conn.buffered() {
                return Err(BufioError::BufferFull.into());
            }
            conn.grow(want);

            let _ = conn.set_read_deadline(Some(deadline));
            let (_, err) = conn.peek(want).await;
            let _ = conn.set_read_deadline(None);
            if let Err(err) = err {
                debugln!("[Sniffer] [{}] the data length not enough, error: {}", addr_to_string(metadata.dst_ip), err);
                return Err(err.into());
            }

            let buffered = conn.buffered();
            let (remaining, next_want) = {
                // The candidate loop borrows the connection's buffer for the round: copying it
                // first would memcpy the whole prefix once per delivered byte.
                let (data, _) = conn.peek(buffered).await;

                let mut remaining = Vec::with_capacity(candidates.len());
                let mut next_want = 0usize;
                for mut current in candidates {
                    if current.want <= data.len() {
                        match current.configured.sniffer.sniff_data(data) {
                            Ok(host) => {
                                if is_valid_sniff_host(&host) {
                                    return Ok((host, current.configured.config.clone()));
                                }
                                continue;
                            }
                            Err(err) => match need_more_data(&err) {
                                Some(length) if length > data.len() => current.want = length,
                                _ => continue,
                            },
                        }
                    }

                    let want = current.want;
                    remaining.push(current);
                    if next_want == 0 || want < next_want {
                        next_want = want;
                    }
                }

                (remaining, next_want)
            };

            candidates = remaining;
            want = next_want;
        }

        Err(ErrorSniffFailed.into())
    }

    fn cache_sniff_failed(&self, metadata: &Metadata) {
        let dst = (metadata.dst_ip, metadata.dst_port);
        self.skip_list.compute(dst, |mut old_value, _loaded| {
            if old_value <= 5 {
                old_value += 1;
            }
            (old_value, false)
        });
    }
}

fn domain_can_replace_with(skip_domain: &[Arc<dyn DomainMatcher>], host: &str) -> bool {
    if !is_valid_sniff_host(host) {
        return false;
    }
    for matcher in skip_domain {
        if matcher.match_domain(host) {
            return false;
        }
    }
    true
}

fn replace_domain(metadata: &mut Metadata, host: &str, override_dest: bool) {
    host.clone_into(&mut metadata.sniff_host);
    if override_dest {
        debugln!(
            "[Sniffer] Sniff {} [{}]-->[{}] success, replace domain [{}]-->[{}]",
            metadata.network,
            metadata.source_detail(),
            metadata.remote_address(),
            metadata.host,
            host
        );
        host.clone_into(&mut metadata.host);
        metadata.dst_ip = None;
    }
    metadata.dns_mode = DNSMode::DNS_NORMAL;
}

/// The local domain-replacement closure, wired to [`ReplaceDomain`].
fn make_domain_replacer(skip_domain: Vec<Arc<dyn DomainMatcher>>, override_dest: bool) -> ReplaceDomain {
    Arc::new(move |metadata: &mut Metadata, host: &str| {
        if domain_can_replace_with(&skip_domain, host) {
            replace_domain(metadata, host, override_dest);
        } else {
            debugln!("[Sniffer] Skip sni[{}]", host);
        }
    })
}

/// Local domain-name validation; this crate has no equivalent
/// module.
fn is_valid_sniff_host(host: &str) -> bool {
    host != "." && is_domain_name(host)
}

fn is_domain_name(s: &str) -> bool {
    if s == "." {
        return true;
    }

    let bytes = s.as_bytes();
    let l = bytes.len();
    if l == 0 || l > 254 || (l == 254 && bytes.get(l - 1) != Some(&b'.')) {
        return false;
    }

    let mut last = b'.';
    let mut non_numeric = false;
    let mut part_len = 0usize;
    for &c in bytes {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                part_len += 1;
            }
            b'0'..=b'9' => {
                part_len += 1;
            }
            b'-' => {
                if last == b'.' {
                    return false;
                }
                part_len += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' {
                    return false;
                }
                if part_len > 63 || part_len == 0 {
                    return false;
                }
                part_len = 0;
            }
            _ => return false,
        }
        last = c;
    }
    if last == b'-' || part_len > 63 {
        return false;
    }

    non_numeric
}

pub struct Config {
    pub enable: bool,
    pub sniffers: HashMap<Type, SnifferConfig>,
    pub force_domain: Vec<Arc<dyn DomainMatcher>>,
    pub skip_src_address: Vec<Arc<dyn IpMatcher>>,
    pub skip_dst_address: Vec<Arc<dyn IpMatcher>>,
    pub skip_domain: Vec<Arc<dyn DomainMatcher>>,
    pub force_dns_mapping: bool,
    pub parse_pure_ip: bool,
}

/// The matcher vectors hold trait objects that are not `Debug`, so this reports their sizes only.
impl core::fmt::Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("enable", &self.enable)
            .field("sniffers", &self.sniffers)
            .field("force_domain", &self.force_domain.len())
            .field("skip_src_address", &self.skip_src_address.len())
            .field("skip_dst_address", &self.skip_dst_address.len())
            .field("skip_domain", &self.skip_domain.len())
            .field("force_dns_mapping", &self.force_dns_mapping)
            .field("parse_pure_ip", &self.parse_pure_ip)
            .finish_non_exhaustive()
    }
}

/// Deviation: the documented constructor returns a disabled `Dispatcher` alongside the failure on
/// every error path; every caller only inspects the error, so this returns the error alone.
pub fn new_dispatcher(sniffer_config: &Config) -> anyhow::Result<Dispatcher> {
    let mut dispatcher = Dispatcher {
        enable: sniffer_config.enable,
        sniffers: Vec::with_capacity(sniffer_config.sniffers.len()),
        force_domain: sniffer_config.force_domain.clone(),
        skip_src_address: sniffer_config.skip_src_address.clone(),
        skip_dst_address: sniffer_config.skip_dst_address.clone(),
        skip_domain: sniffer_config.skip_domain.clone(),
        skip_list: lru::new(vec![lru::with_size(128), lru::with_age(600)]),
        force_dns_mapping: sniffer_config.force_dns_mapping,
        parse_pure_ip: sniffer_config.parse_pure_ip,
    };

    for &sniffer_name in &LIST {
        let Some(config) = sniffer_config.sniffers.get(&sniffer_name) else {
            continue;
        };
        let s = match new_sniffer(sniffer_name, config.clone()) {
            Ok(s) => s,
            Err(err) => {
                errorln!("Sniffer name[{}] is error", sniffer_name);
                return Err(err);
            }
        };
        dispatcher.sniffers.push(ConfiguredSniffer { sniffer: s, config: config.clone() });
    }

    if dispatcher.sniffers.len() != sniffer_config.sniffers.len() {
        for sniffer_name in sniffer_config.sniffers.keys() {
            let found = LIST.iter().any(|supported| supported == sniffer_name);
            if !found {
                errorln!("Sniffer name[{}] is error", sniffer_name);
                return Err(ErrorUnsupportedSniffer.into());
            }
        }
    }

    Ok(dispatcher)
}

pub fn new_sniffer(name: Type, sniffer_config: SnifferConfig) -> anyhow::Result<Box<dyn Sniffer>> {
    match name {
        Type::TLS => Ok(Box::new(TLSSniffer::new(sniffer_config)?)),
        Type::HTTP => Ok(Box::new(HTTPSniffer::new(sniffer_config)?)),
        Type::QUIC => Ok(Box::new(QUICSniffer::new(sniffer_config)?)),
        _ => Err(ErrorUnsupportedSniffer.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc as StdArc;
    use std::task::{Context, Poll};

    use parking_lot::Mutex as SyncMutex;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use murmur_common_net::{new_buffered_conn, new_extended_conn};
    use murmur_constant::sniffer::sniffer::Type as SnifferType;
    use murmur_std_compat::net::{Addr, Conn as NetConn, TcpAddr};

    use super::*;

    struct ChunkedConnState {
        chunks: VecDeque<Vec<u8>>,
        read_err: bool,
        closed: bool,
        deadline: Option<Instant>,
        deadlines: Vec<Instant>,
        would_block: bool,
    }

    /// The chunked conn hands out one chunk per read; this harness drops the real watchdog timer
    /// that fails the test whenever a read deadline literally elapses (this conn's reads never block,
    /// so the timer would never fire) and keeps only the deadline bookkeeping the assertions use.
    #[derive(Clone)]
    struct ChunkedConn {
        state: StdArc<SyncMutex<ChunkedConnState>>,
    }

    impl ChunkedConn {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                state: StdArc::new(SyncMutex::new(ChunkedConnState {
                    chunks: chunks.into(),
                    read_err: false,
                    closed: false,
                    deadline: None,
                    deadlines: Vec::new(),
                    would_block: false,
                })),
            }
        }

        fn with_read_err(chunks: Vec<Vec<u8>>) -> Self {
            let conn = Self::new(chunks);
            conn.state.lock().read_err = true;
            conn
        }

        fn deadline(&self) -> Option<Instant> {
            self.state.lock().deadline
        }

        fn deadlines(&self) -> Vec<Instant> {
            self.state.lock().deadlines.clone()
        }

        fn closed(&self) -> bool {
            self.state.lock().closed
        }

        fn chunks_left(&self) -> usize {
            self.state.lock().chunks.len()
        }

        fn would_block(&self) -> bool {
            self.state.lock().would_block
        }
    }

    impl AsyncRead for ChunkedConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let mut state = self.state.lock();
            if let Some(chunk) = state.chunks.pop_front() {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                return Poll::Ready(Ok(()));
            }
            if state.read_err {
                return Poll::Ready(Err(io::Error::other("read tcp: i/o operation failed")));
            }
            if state.deadline.is_none() {
                state.would_block = true;
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ChunkedConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl NetConn for ChunkedConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }

        fn close(&self) -> io::Result<()> {
            self.state.lock().closed = true;
            Ok(())
        }

        fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
            let mut state = self.state.lock();
            state.deadline = deadline;
            if let Some(d) = deadline {
                state.deadlines.push(d);
            }
            Ok(())
        }
    }

    impl murmur_common_net::io::Stream for ChunkedConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        fn old_conn(&self) -> Option<&dyn NetConn> {
            Some(self)
        }
    }

    fn buffered_conn(raw: ChunkedConn) -> (ChunkedConn, BufferedConn) {
        let handle = raw.clone();
        let extended = new_extended_conn(raw);
        (handle, new_buffered_conn(extended))
    }

    /// the `stubSniffer`: records the size of every buffer it is handed and replies with a
    /// scripted answer.
    struct StubSniffer {
        network: NetWork,
        seen: SeenHandle,
        reply: Box<dyn Fn(&[u8]) -> anyhow::Result<String> + Send + Sync>,
    }

    /// Shared handle a test keeps after handing a [`StubSniffer`] to a [`ConfiguredSniffer`], so
    /// it can still inspect what the sniffer saw without downcasting the boxed trait object.
    type SeenHandle = StdArc<SyncMutex<Vec<usize>>>;

    impl StubSniffer {
        fn new(reply: impl Fn(&[u8]) -> anyhow::Result<String> + Send + Sync + 'static) -> Self {
            Self { network: NetWork::TCP, seen: SeenHandle::default(), reply: Box::new(reply) }
        }

        fn with_network(
            network: NetWork,
            reply: impl Fn(&[u8]) -> anyhow::Result<String> + Send + Sync + 'static,
        ) -> Self {
            Self { network, seen: SeenHandle::default(), reply: Box::new(reply) }
        }

        fn seen_handle(&self) -> SeenHandle {
            Arc::clone(&self.seen)
        }
    }

    impl Sniffer for StubSniffer {
        fn support_network(&self) -> NetWork {
            self.network
        }

        fn sniff_data(&self, bytes: &[u8]) -> anyhow::Result<String> {
            self.seen.lock().push(bytes.len());
            (self.reply)(bytes)
        }

        fn protocol(&self) -> String {
            "stub".to_owned()
        }

        fn support_port(&self, _port: u16) -> bool {
            true
        }
    }

    struct DomainMatcherFn<F>(F);

    impl<F: Fn(&str) -> bool + Send + Sync> DomainMatcher for DomainMatcherFn<F> {
        fn match_domain(&self, domain: &str) -> bool {
            (self.0)(domain)
        }
    }

    fn need_at_least(n: usize) -> anyhow::Error {
        ErrNeedAtLeastData::no_clue(n)
    }

    fn new_test_dispatcher(sniffers: Vec<ConfiguredSniffer>) -> Dispatcher {
        Dispatcher {
            enable: true,
            sniffers,
            force_domain: Vec::new(),
            skip_src_address: Vec::new(),
            skip_dst_address: Vec::new(),
            skip_domain: Vec::new(),
            skip_list: lru::new(vec![]),
            force_dns_mapping: false,
            parse_pure_ip: false,
        }
    }

    fn configured(sniffer: StubSniffer) -> (ConfiguredSniffer, SeenHandle) {
        let seen = sniffer.seen_handle();
        (ConfiguredSniffer { sniffer: Box::new(sniffer), config: SnifferConfig::default() }, seen)
    }

    fn configured_with(sniffer: StubSniffer, config: SnifferConfig) -> (ConfiguredSniffer, SeenHandle) {
        let seen = sniffer.seen_handle();
        (ConfiguredSniffer { sniffer: Box::new(sniffer), config }, seen)
    }

    struct FeedLoopCase {
        name: &'static str,
        chunks: Vec<Vec<u8>>,
        reply: Box<dyn Fn(&[u8]) -> anyhow::Result<String> + Send + Sync>,
        host: &'static str,
        want_err: bool,
        error_is_buffer_full: bool,
        seen: Vec<usize>,
        buffer_size: usize,
        buffered: usize,
        chunks_left: usize,
    }

    #[tokio::test]
    async fn dispatcher_feed_loop() {
        let segment = || b"0123456789".to_vec();
        let three_segments = || vec![segment(), segment(), segment()];
        let large_size = 5000usize;

        let cases: Vec<FeedLoopCase> = vec![
            FeedLoopCase {
                name: "retries until the sniffer reaches a verdict",
                chunks: three_segments(),
                reply: Box::new(|data: &[u8]| {
                    for want in [20usize, 30] {
                        if data.len() < want {
                            return Err(need_at_least(want));
                        }
                    }
                    Ok("example.com".to_owned())
                }),
                host: "example.com",
                want_err: false,
                error_is_buffer_full: false,
                seen: vec![10, 20, 30],
                buffer_size: 0,
                buffered: 0,
                chunks_left: 0,
            },
            FeedLoopCase {
                name: "grows the peek buffer on demand",
                chunks: vec![segment(), vec![b'x'; large_size - segment().len()]],
                reply: Box::new(move |data: &[u8]| {
                    if data.len() < large_size {
                        return Err(need_at_least(large_size));
                    }
                    Ok("example.com".to_owned())
                }),
                host: "example.com",
                want_err: false,
                error_is_buffer_full: false,
                seen: vec![10, large_size],
                buffer_size: 8192,
                buffered: 0,
                chunks_left: 0,
            },
            FeedLoopCase {
                name: "hands over all buffered data, not just the extra byte",
                chunks: three_segments(),
                reply: Box::new(|data: &[u8]| {
                    if data.len() < 30 {
                        return Err(need_at_least(data.len() + 1));
                    }
                    Ok("example.com".to_owned())
                }),
                host: "example.com",
                want_err: false,
                error_is_buffer_full: false,
                seen: vec![10, 20, 30],
                buffer_size: 0,
                buffered: 0,
                chunks_left: 0,
            },
            FeedLoopCase {
                name: "stops when the request cannot grow",
                chunks: three_segments(),
                reply: Box::new(|data: &[u8]| Err(need_at_least(data.len()))),
                host: "",
                want_err: true,
                error_is_buffer_full: false,
                seen: vec![10],
                buffer_size: 0,
                buffered: 0,
                chunks_left: 0,
            },
            FeedLoopCase {
                name: "stops when the request exceeds the peek limit",
                chunks: three_segments(),
                reply: Box::new(|_data: &[u8]| Err(need_at_least(1 << 20))),
                host: "",
                want_err: true,
                error_is_buffer_full: true,
                seen: vec![10],
                buffer_size: 4096,
                buffered: 10,
                chunks_left: 2,
            },
            FeedLoopCase {
                name: "gives up when the data never completes",
                chunks: vec![segment()],
                reply: Box::new(|data: &[u8]| Err(need_at_least(data.len() + 1))),
                host: "",
                want_err: true,
                error_is_buffer_full: false,
                seen: vec![10],
                buffer_size: 0,
                buffered: 0,
                chunks_left: 0,
            },
        ];

        for case in cases {
            let (configured_sniffer, seen) = configured(StubSniffer::new(case.reply));
            let dispatcher = new_test_dispatcher(vec![configured_sniffer]);
            let (raw, mut conn) = buffered_conn(ChunkedConn::new(case.chunks));
            let metadata = Metadata { network: NetWork::TCP, dst_port: 80, ..Default::default() };

            let result = dispatcher.sniff_domain(&mut conn, &metadata).await;

            if case.want_err {
                let err = result.expect_err(case.name);
                if case.error_is_buffer_full {
                    assert!(matches!(err.downcast_ref::<BufioError>(), Some(BufioError::BufferFull)), "{}", case.name);
                }
            } else {
                let (host, _) = result.unwrap_or_else(|err| panic!("{}: {err}", case.name));
                assert_eq!(host, case.host, "{}", case.name);
            }
            assert_eq!(seen.lock().clone(), case.seen, "{}", case.name);
            if case.buffer_size != 0 {
                assert_eq!(conn.reader().expect("reader present").size(), case.buffer_size, "{}", case.name);
            }
            if case.buffered != 0 {
                assert_eq!(conn.buffered(), case.buffered, "{}", case.name);
            }
            if case.chunks_left != 0 {
                assert_eq!(raw.chunks_left(), case.chunks_left, "{}", case.name);
            }
            assert!(raw.deadline().is_none(), "{}: read deadline was not cleared", case.name);
            let deadlines = raw.deadlines();
            assert!(deadlines.len() >= 2, "{}: initial and shared deadlines must both be set", case.name);
            for deadline in &deadlines[2..] {
                assert_eq!(*deadline, deadlines[1], "{}: all retries must reuse the shared deadline", case.name);
            }
            assert!(!raw.would_block(), "{}: read would block with no read deadline set", case.name);
        }
    }

    /// Each retry round must hand the sniffer a borrow of the connection's buffer: copying the
    /// whole prefix once per delivered byte is quadratic in the sniff buffer size (#38).
    #[tokio::test]
    async fn sniff_retry_rounds_borrow_the_connection_buffer() {
        let pointers = StdArc::new(SyncMutex::new(Vec::new()));
        let recorder = StdArc::clone(&pointers);
        let sniffer = StubSniffer::new(move |data: &[u8]| {
            recorder.lock().push(data.as_ptr() as usize);
            Err(need_at_least(data.len() + 1))
        });
        let (configured_sniffer, _seen) = configured(sniffer);
        let dispatcher = new_test_dispatcher(vec![configured_sniffer]);
        let (_raw, mut conn) = buffered_conn(ChunkedConn::new(vec![vec![b'a']; 4]));
        let metadata = Metadata { network: NetWork::TCP, dst_port: 80, ..Default::default() };

        assert!(dispatcher.sniff_domain(&mut conn, &metadata).await.is_err());

        let seen = pointers.lock().clone();
        assert_eq!(seen.len(), 4, "one retry round per delivered byte");
        let reader = conn.reader().expect("reader present");
        let start = reader.buf.as_ptr() as usize;
        let end = start + reader.buf.len();
        for pointer in seen {
            assert!((start..end).contains(&pointer), "a retry round copied the connection buffer");
        }
    }

    #[tokio::test]
    async fn uses_successful_sniffer_config_before_reading_more() {
        let segment = b"0123456789".to_vec();
        let waiting = StubSniffer::new(|data: &[u8]| Err(need_at_least(data.len() + 1)));
        let successful = StubSniffer::new(|_data: &[u8]| Ok("example.com".to_owned()));

        let dispatcher = new_dispatcher(&Config {
            enable: true,
            sniffers: HashMap::new(),
            force_domain: Vec::new(),
            skip_src_address: Vec::new(),
            skip_dst_address: Vec::new(),
            skip_domain: Vec::new(),
            force_dns_mapping: false,
            parse_pure_ip: true,
        })
        .expect("dispatcher constructs");
        let mut dispatcher = dispatcher;
        let (waiting_configured, waiting_seen) =
            configured_with(waiting, SnifferConfig { override_dest: false, ..Default::default() });
        let (successful_configured, successful_seen) =
            configured_with(successful, SnifferConfig { override_dest: true, ..Default::default() });
        dispatcher.sniffers = vec![waiting_configured, successful_configured];

        let (raw, mut conn) = buffered_conn(ChunkedConn::new(vec![segment.clone(), segment.clone()]));
        let mut metadata = Metadata {
            network: NetWork::TCP,
            dst_ip: Some("192.0.2.1".parse().unwrap()),
            dst_port: 80,
            ..Default::default()
        };

        let sniffed = dispatcher.tcp_sniff(&mut conn, &mut metadata).await;

        assert!(sniffed);
        assert_eq!(metadata.sniff_host, "example.com");
        assert_eq!(metadata.host, "example.com");
        assert!(metadata.dst_ip.is_none());
        assert_eq!(waiting_seen.lock().clone(), vec![segment.len()]);
        assert_eq!(successful_seen.lock().clone(), vec![segment.len()]);
        assert_eq!(raw.chunks_left(), 1);
        assert!(raw.deadline().is_none(), "read deadline was not cleared");
        assert_eq!(raw.deadlines().len(), 2, "one initial and one shared deadline should be sufficient");
    }

    #[tokio::test]
    async fn reads_the_smallest_candidate_request_next() {
        let segment = b"0123456789".to_vec();
        let slow = StubSniffer::new(|data: &[u8]| {
            if data.len() < 30 {
                return Err(need_at_least(30));
            }
            Ok("slow.example.com".to_owned())
        });
        let fast = StubSniffer::new(|data: &[u8]| {
            if data.len() < 20 {
                return Err(need_at_least(20));
            }
            Ok("fast.example.com".to_owned())
        });
        let (slow_configured, slow_seen) = configured(slow);
        let (fast_configured, fast_seen) = configured(fast);
        let dispatcher = new_test_dispatcher(vec![slow_configured, fast_configured]);
        let (raw, mut conn) = buffered_conn(ChunkedConn::new(vec![segment.clone(), segment.clone(), segment.clone()]));
        let metadata = Metadata { network: NetWork::TCP, dst_port: 80, ..Default::default() };

        let (host, _) = dispatcher.sniff_domain(&mut conn, &metadata).await.expect("sniffs");

        assert_eq!(host, "fast.example.com");
        assert_eq!(slow_seen.lock().clone(), vec![10]);
        assert_eq!(fast_seen.lock().clone(), vec![10, 20]);
        assert_eq!(raw.chunks_left(), 1);
    }

    #[tokio::test]
    async fn continues_after_an_invalid_host() {
        let segment = b"0123456789".to_vec();
        let invalid = StubSniffer::new(|_data: &[u8]| Ok("not a domain".to_owned()));
        let valid = StubSniffer::new(|_data: &[u8]| Ok("example.com".to_owned()));
        let (invalid_configured, invalid_seen) = configured(invalid);
        let (valid_configured, valid_seen) = configured(valid);
        let dispatcher = new_test_dispatcher(vec![invalid_configured, valid_configured]);
        let (_raw, mut conn) = buffered_conn(ChunkedConn::new(vec![segment.clone()]));
        let metadata = Metadata { network: NetWork::TCP, dst_port: 80, ..Default::default() };

        let (host, _) = dispatcher.sniff_domain(&mut conn, &metadata).await.expect("sniffs");

        assert_eq!(host, "example.com");
        assert_eq!(invalid_seen.lock().clone(), vec![segment.len()]);
        assert_eq!(valid_seen.lock().clone(), vec![segment.len()]);
    }

    #[tokio::test]
    async fn keeps_the_connection_open_after_a_follow_up_read_failure() {
        let segment = b"0123456789".to_vec();
        let waiting = StubSniffer::new(|data: &[u8]| Err(need_at_least(data.len() + 1)));
        let dispatcher = new_dispatcher(&Config {
            enable: false,
            sniffers: HashMap::new(),
            force_domain: Vec::new(),
            skip_src_address: Vec::new(),
            skip_dst_address: Vec::new(),
            skip_domain: Vec::new(),
            force_dns_mapping: false,
            parse_pure_ip: false,
        })
        .expect("dispatcher constructs");
        let mut dispatcher = dispatcher;
        let (waiting_configured, _waiting_seen) = configured(waiting);
        dispatcher.sniffers = vec![waiting_configured];
        let (raw, mut conn) = buffered_conn(ChunkedConn::with_read_err(vec![segment]));
        let metadata = Metadata {
            network: NetWork::TCP,
            dst_ip: Some("192.0.2.1".parse().unwrap()),
            dst_port: 80,
            ..Default::default()
        };

        let result = dispatcher.sniff_domain(&mut conn, &metadata).await;

        assert!(result.is_err());
        assert!(!raw.closed());
        let (_, cached) = dispatcher.skip_list.get(&(metadata.dst_ip, metadata.dst_port));
        assert!(!cached);
    }

    #[tokio::test]
    async fn keeps_the_connection_open_and_caches_an_initial_read_failure_once() {
        let waiting = StubSniffer::new(|data: &[u8]| Err(need_at_least(data.len() + 1)));
        let dispatcher = new_dispatcher(&Config {
            enable: true,
            sniffers: HashMap::new(),
            force_domain: Vec::new(),
            skip_src_address: Vec::new(),
            skip_dst_address: Vec::new(),
            skip_domain: Vec::new(),
            force_dns_mapping: false,
            parse_pure_ip: true,
        })
        .expect("dispatcher constructs");
        let mut dispatcher = dispatcher;
        let (waiting_configured, waiting_seen) = configured(waiting);
        dispatcher.sniffers = vec![waiting_configured];
        let (raw, mut conn) = buffered_conn(ChunkedConn::with_read_err(Vec::new()));
        let mut metadata = Metadata {
            network: NetWork::TCP,
            dst_ip: Some("192.0.2.1".parse().unwrap()),
            dst_port: 80,
            ..Default::default()
        };

        let sniffed = dispatcher.tcp_sniff(&mut conn, &mut metadata).await;

        assert!(!sniffed);
        assert!(!raw.closed());
        assert!(waiting_seen.lock().is_empty());
        let (failures, cached) = dispatcher.skip_list.get(&(metadata.dst_ip, metadata.dst_port));
        assert!(cached);
        assert_eq!(failures, 1);
        assert!(raw.deadline().is_none(), "read deadline was not cleared");
    }

    #[tokio::test]
    async fn does_not_cache_a_forced_initial_read_failure() {
        let waiting = StubSniffer::new(|data: &[u8]| Err(need_at_least(data.len() + 1)));
        let dispatcher = new_dispatcher(&Config {
            enable: true,
            sniffers: HashMap::new(),
            force_domain: vec![StdArc::new(DomainMatcherFn(|_: &str| true))],
            skip_src_address: Vec::new(),
            skip_dst_address: Vec::new(),
            skip_domain: Vec::new(),
            force_dns_mapping: false,
            parse_pure_ip: false,
        })
        .expect("dispatcher constructs");
        let mut dispatcher = dispatcher;
        let (waiting_configured, _waiting_seen) = configured(waiting);
        dispatcher.sniffers = vec![waiting_configured];
        let (raw, mut conn) = buffered_conn(ChunkedConn::with_read_err(Vec::new()));
        let mut metadata = Metadata {
            network: NetWork::TCP,
            host: "forced.example".to_owned(),
            dst_ip: Some("192.0.2.1".parse().unwrap()),
            dst_port: 80,
            ..Default::default()
        };

        let sniffed = dispatcher.tcp_sniff(&mut conn, &mut metadata).await;

        assert!(!sniffed);
        assert!(!raw.closed());
        let (_, cached) = dispatcher.skip_list.get(&(metadata.dst_ip, metadata.dst_port));
        assert!(!cached);
    }

    #[tokio::test]
    async fn accepts_all_network_sniffer() {
        let segment = b"0123456789".to_vec();
        let all_network = StubSniffer::with_network(NetWork::ALL_NET, |_data: &[u8]| Ok("example.com".to_owned()));
        let (all_network_configured, all_network_seen) = configured(all_network);
        let dispatcher = new_test_dispatcher(vec![all_network_configured]);
        let (_raw, mut conn) = buffered_conn(ChunkedConn::new(vec![segment.clone()]));
        let metadata = Metadata { network: NetWork::TCP, dst_port: 80, ..Default::default() };

        let (host, _) = dispatcher.sniff_domain(&mut conn, &metadata).await.expect("sniffs");

        assert_eq!(host, "example.com");
        assert_eq!(all_network_seen.lock().clone(), vec![segment.len()]);
    }

    #[test]
    fn constructs_sniffers_in_protocol_order() {
        let dispatcher = new_dispatcher(&Config {
            enable: false,
            sniffers: HashMap::from([
                (SnifferType::QUIC, SnifferConfig::default()),
                (SnifferType::HTTP, SnifferConfig::default()),
                (SnifferType::TLS, SnifferConfig::default()),
            ]),
            force_domain: Vec::new(),
            skip_src_address: Vec::new(),
            skip_dst_address: Vec::new(),
            skip_domain: Vec::new(),
            force_dns_mapping: false,
            parse_pure_ip: false,
        })
        .expect("dispatcher constructs");

        let protocols: Vec<String> = dispatcher.sniffers.iter().map(|current| current.sniffer.protocol()).collect();
        assert_eq!(protocols, vec!["tls", "http", "quic"]);
    }
}

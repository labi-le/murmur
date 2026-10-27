//! The realm client runs: listen a UDP socket per address family, STUN-discover its mapped
//! addresses, ask the control plane for the registered peer's, punch, then run the QUIC session
//! over the punched socket. This module ends at that socket and the peer address; `hysteria2.rs`
//! hands both to `transport_hysteria2::ClientOptions`, which is why the transport needed no realm
//! API of its own.
//!
//! The punch packet conn, the register/heartbeat/events calls and the connect response belong to
//! the registered peer (the hysteria2 server) and have no client counterpart, so they are absent
//! here.
//!
//! Where this diverges, and why:
//!
//! * The punched socket and the peer address are produced once per adapter client build rather than
//!   per QUIC connection attempt: `ClientOptions` takes a bound packet conn and a fixed server
//!   address, while the packet-listener/QUIC-dialer callbacks are what let a new offer re-punch,
//!   so a session that reconnects keeps the path its first punch found.
//! * The control plane goes through `component_http`'s one-shot HTTP/1.1 client, with that crate's
//!   recorded "no keep-alive, no HTTP/2" deviation.
//! * `handshake-timeout` bounds this offer and then the QUIC handshake separately, rather than one
//!   deadline covering both.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Write as _;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use futures::future::join_all;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{old_addr_to_socket_addr, DatagramAsOldPacketConn};
use murmur_component::resolver::resolver::{
    lookup_ip_with_resolver, lookup_ipv4_with_resolver, lookup_ipv6_with_resolver, proxy_server_host_resolver,
    ResolverRef,
};
use murmur_component_ca as ca;
use murmur_component_http::http as murmur_http;
use murmur_component_tls::utls as tls_c;
use murmur_constant::adapters::Dialer as CDialer;
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{PacketConn as NetPacketConn, UdpAddr};

use super::hysteria2::Hysteria2RealmOption;

const STUN_HEADER_SIZE: usize = 20;
const STUN_TRANSACTION_ID_SIZE: usize = 12;
const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_FAMILY_IPV4: u8 = 0x01;
const STUN_FAMILY_IPV6: u8 = 0x02;
const STUN_DEFAULT_PORT: &str = "3478";
/// The attempt timeouts of the discovery loop.
const STUN_ATTEMPT_TIMEOUTS: [Duration; 3] =
    [Duration::from_millis(500), Duration::from_secs(2), Duration::from_secs(4)];

const PUNCH_SALT_LENGTH: usize = 8;
const PUNCH_MAGIC_LENGTH: usize = 8;
const PUNCH_NONCE_LENGTH: usize = 16;
const PUNCH_KEY_LENGTH: usize = 32;
const PUNCH_MIN_BODY_SIZE: usize = PUNCH_MAGIC_LENGTH + 1 + PUNCH_NONCE_LENGTH;
const PUNCH_MAX_PADDING: usize = 1024;
const PUNCH_MAGIC: [u8; PUNCH_MAGIC_LENGTH] = *b"HYRLMv1\0";
const PUNCH_HELLO: u8 = 0x01;
const PUNCH_ACK: u8 = 0x02;

const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
const SYMMETRIC_NAT_PORT_GAP: u16 = 4;
const SYMMETRIC_NAT_EXTRA_PORTS: u16 = 4;
const SYMMETRIC_NAT_MAX_PORTS_PER_HOST: usize = 32;

const MAX_ERROR_BODY_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PunchMetadata {
    nonce: [u8; PUNCH_NONCE_LENGTH],
    obfuscation_key: [u8; PUNCH_KEY_LENGTH],
}

impl PunchMetadata {
    fn generate() -> Self {
        let mut metadata = Self { nonce: [0; PUNCH_NONCE_LENGTH], obfuscation_key: [0; PUNCH_KEY_LENGTH] };
        let mut rng = rand::rng();
        rng.fill_bytes(&mut metadata.nonce);
        rng.fill_bytes(&mut metadata.obfuscation_key);
        metadata
    }

    fn decode_wire(nonce_hex: &str, obfs_hex: &str) -> Result<Self> {
        let nonce = hex::decode(nonce_hex).map_err(|err| anyhow!("decode nonce: {err}"))?;
        if nonce.len() != PUNCH_NONCE_LENGTH {
            bail!("invalid nonce length: {}", nonce.len());
        }
        let obfuscation_key = hex::decode(obfs_hex).map_err(|err| anyhow!("decode obfs: {err}"))?;
        if obfuscation_key.len() != PUNCH_KEY_LENGTH {
            bail!("invalid obfs length: {}", obfuscation_key.len());
        }
        let mut metadata = Self { nonce: [0; PUNCH_NONCE_LENGTH], obfuscation_key: [0; PUNCH_KEY_LENGTH] };
        metadata.nonce.copy_from_slice(&nonce);
        metadata.obfuscation_key.copy_from_slice(&obfuscation_key);
        Ok(metadata)
    }
}

/// The packet body XORed with `SHA-256(key || salt)`.
fn xor_obfuscate(obfuscation_key: &[u8; PUNCH_KEY_LENGTH], salt: &[u8], body: &mut [u8]) {
    let mut material = [0u8; PUNCH_KEY_LENGTH + PUNCH_SALT_LENGTH];
    material[..PUNCH_KEY_LENGTH].copy_from_slice(obfuscation_key);
    material[PUNCH_KEY_LENGTH..].copy_from_slice(salt);
    let key = Sha256::digest(material);
    for (byte, key_byte) in body.iter_mut().zip(key.iter().cycle()) {
        *byte ^= *key_byte;
    }
}

fn encode_punch_packet(packet_type: u8, metadata: &PunchMetadata) -> Vec<u8> {
    let mut random = [0u8; PUNCH_SALT_LENGTH + 2 + PUNCH_MAX_PADDING];
    rand::rng().fill_bytes(&mut random);
    let padding_length = (usize::from(random[PUNCH_SALT_LENGTH]) << 8 | usize::from(random[PUNCH_SALT_LENGTH + 1]))
        % (PUNCH_MAX_PADDING + 1);
    let (salt, random_rest) = random.split_at(PUNCH_SALT_LENGTH);
    let (_, padding_pool) = random_rest.split_at(2);
    let (padding, _) = padding_pool.split_at(padding_length);
    let body = {
        let mut body = [0u8; PUNCH_MIN_BODY_SIZE];
        let (magic, rest) = body.split_at_mut(PUNCH_MAGIC_LENGTH);
        magic.copy_from_slice(&PUNCH_MAGIC);
        let (type_slot, nonce_slot) = rest.split_at_mut(1);
        type_slot.copy_from_slice(&[packet_type]);
        nonce_slot.copy_from_slice(&metadata.nonce);
        body
    };
    let mut packet = Vec::with_capacity(PUNCH_SALT_LENGTH + PUNCH_MIN_BODY_SIZE + padding_length);
    packet.extend_from_slice(salt);
    packet.extend_from_slice(&body);
    packet.extend_from_slice(padding);
    let (salt_slice, body_slice) = packet.split_at_mut(PUNCH_SALT_LENGTH);
    xor_obfuscate(&metadata.obfuscation_key, salt_slice, body_slice);
    packet
}

fn decode_punch_packet(data: &[u8], metadata: &PunchMetadata) -> Result<u8> {
    if data.len() < PUNCH_SALT_LENGTH + PUNCH_MIN_BODY_SIZE {
        bail!("packet too short");
    }
    if data.len() > PUNCH_SALT_LENGTH + PUNCH_MIN_BODY_SIZE + PUNCH_MAX_PADDING {
        bail!("packet too long");
    }
    let (salt, obfuscated) = data.split_at(PUNCH_SALT_LENGTH);
    let mut body = obfuscated.to_vec();
    xor_obfuscate(&metadata.obfuscation_key, salt, &mut body);
    let rest = body.strip_prefix(PUNCH_MAGIC.as_slice()).ok_or_else(|| anyhow!("magic mismatch"))?;
    let Some((&packet_type, rest)) = rest.split_first() else {
        bail!("packet too short");
    };
    if packet_type != PUNCH_HELLO && packet_type != PUNCH_ACK {
        bail!("unknown punch type: {packet_type}");
    }
    let (nonce, _) = rest.split_at(PUNCH_NONCE_LENGTH);
    if nonce != metadata.nonce.as_slice() {
        bail!("nonce mismatch");
    }
    Ok(packet_type)
}

#[derive(Debug)]
struct StunMessage {
    raw: Vec<u8>,
    transaction_id: [u8; STUN_TRANSACTION_ID_SIZE],
}

impl StunMessage {
    fn new_binding_request() -> (Vec<u8>, [u8; STUN_TRANSACTION_ID_SIZE]) {
        let mut transaction_id = [0u8; STUN_TRANSACTION_ID_SIZE];
        rand::rng().fill_bytes(&mut transaction_id);
        let mut raw = vec![0u8; STUN_HEADER_SIZE];
        let (message_type, rest) = raw.split_at_mut(2);
        message_type.copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        let (_, rest) = rest.split_at_mut(2);
        let (cookie, transaction_slot) = rest.split_at_mut(4);
        cookie.copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        transaction_slot.copy_from_slice(&transaction_id);
        (raw, transaction_id)
    }

    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < STUN_HEADER_SIZE {
            bail!("STUN message too short: {}", data.len());
        }
        let (header, _) = data.split_at(STUN_HEADER_SIZE);
        let Ok(header) = <[u8; STUN_HEADER_SIZE]>::try_from(header) else {
            bail!("STUN message too short: {}", data.len());
        };
        if u32::from_be_bytes([header[4], header[5], header[6], header[7]]) != STUN_MAGIC_COOKIE {
            bail!("invalid STUN magic cookie");
        }
        let attr_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if data.len() < STUN_HEADER_SIZE + attr_len {
            bail!("truncated STUN message");
        }
        let (message, _) = data.split_at(STUN_HEADER_SIZE + attr_len);
        let raw = message.to_vec();
        let mut transaction_id = [0u8; STUN_TRANSACTION_ID_SIZE];
        transaction_id.copy_from_slice(&header[8..STUN_HEADER_SIZE]);
        Ok(Self { raw, transaction_id })
    }

    fn xor_mapped_address(&self) -> Result<SocketAddr> {
        // `decode` stores the header plus exactly the declared attribute bytes.
        let Some(mut body) = self.raw.get(STUN_HEADER_SIZE..) else {
            bail!("truncated STUN message");
        };
        while body.len() >= 4 {
            let (attribute, after_attribute) = body.split_at(4);
            let Ok(attribute) = <[u8; 4]>::try_from(attribute) else {
                bail!("truncated STUN attribute");
            };
            let attr_type = u16::from_be_bytes([attribute[0], attribute[1]]);
            let value_len = usize::from(u16::from_be_bytes([attribute[2], attribute[3]]));
            let padded_len = (value_len + 3) & !3;
            if 4 + padded_len > body.len() {
                bail!("truncated STUN attribute");
            }
            let (value, tail) = after_attribute.split_at(value_len);
            let (_, next_attribute) = tail.split_at(padded_len - value_len);
            body = next_attribute;
            if attr_type != STUN_ATTR_XOR_MAPPED_ADDRESS {
                continue;
            }
            if value.len() < 4 {
                bail!("XOR-MAPPED-ADDRESS too short: {}", value.len());
            }
            let (value_head, address_bytes) = value.split_at(4);
            let Ok(value_head) = <[u8; 4]>::try_from(value_head) else {
                bail!("XOR-MAPPED-ADDRESS too short: {}", value.len());
            };
            let ip_len = match value_head[1] {
                STUN_FAMILY_IPV4 => 4,
                STUN_FAMILY_IPV6 => 16,
                family => bail!("unknown XOR-MAPPED-ADDRESS family: {family}"),
            };
            if value.len() != 4 + ip_len {
                bail!("XOR-MAPPED-ADDRESS length mismatch: {}", value.len());
            }
            let port = u16::from_be_bytes([value_head[2], value_head[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;
            let mut key = [0u8; 4 + STUN_TRANSACTION_ID_SIZE];
            key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(&self.transaction_id);
            let mut ip = [0u8; 16];
            for ((byte, key_byte), value_byte) in ip.iter_mut().zip(key.iter()).zip(address_bytes.iter()) {
                *byte = value_byte ^ key_byte;
            }
            let addr = if ip_len == 4 {
                IpAddr::V4(Ipv4Addr::from([ip[0], ip[1], ip[2], ip[3]]))
            } else {
                IpAddr::V6(Ipv6Addr::from(ip))
            };
            return Ok(SocketAddr::new(addr, port));
        }
        bail!("XOR-MAPPED-ADDRESS not found")
    }
}

struct StunRequest {
    server: SocketAddr,
    raw: Vec<u8>,
    transaction_id: [u8; STUN_TRANSACTION_ID_SIZE],
}

async fn resolve_stun_servers(
    ctx: &CancellationToken,
    servers: &[String],
    ipv4: bool,
    ipv6: bool,
) -> Result<Vec<SocketAddr>> {
    // cancel-safe: plain lookups, and every partial result is collected locally.
    let results = join_all(servers.iter().map(|server| resolve_stun_server(ctx, server, ipv4, ipv6))).await;
    let mut resolved = Vec::new();
    for result in results {
        resolved.extend(result?);
    }
    if resolved.is_empty() {
        bail!("no STUN servers resolved");
    }
    Ok(resolved)
}

async fn resolve_stun_server(ctx: &CancellationToken, server: &str, ipv4: bool, ipv6: bool) -> Result<Vec<SocketAddr>> {
    // cancel-safe: one lookup, no state outlives the call.
    let (host, port) = match murmur_common_net::split_host_port(server) {
        Ok((host, port, true)) => (host, port),
        _ => (server.to_owned(), STUN_DEFAULT_PORT.to_owned()),
    };
    let port: u16 = port.parse().map_err(|_| anyhow!("resolve STUN port: {port}"))?;
    if let Ok(address) = host.parse::<IpAddr>() {
        let address = unmap(address);
        if (address.is_ipv4() && !ipv4) || (address.is_ipv6() && !ipv6) {
            return Ok(Vec::new());
        }
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    let resolver = proxy_server_host_resolver();
    let resolver: Option<&ResolverRef> = resolver.as_deref();
    let addresses = if ipv4 && !ipv6 {
        lookup_ipv4_with_resolver(ctx, &host, resolver).await
    } else if ipv6 && !ipv4 {
        lookup_ipv6_with_resolver(ctx, &host, resolver).await
    } else {
        lookup_ip_with_resolver(ctx, &host, resolver).await
    }
    .map_err(|err| anyhow!("resolve STUN server: {server}: {err}"))?;
    Ok(addresses.into_iter().map(|address| SocketAddr::new(unmap(address), port)).collect())
}

async fn discover(
    ctx: &CancellationToken,
    conn: &Arc<dyn NetPacketConn>,
    servers: &[SocketAddr],
) -> Result<Vec<SocketAddr>> {
    if servers.is_empty() {
        bail!("no STUN servers");
    }
    // cancel-safe: it reads from the caller's socket and keeps its pending set local.
    let requests = servers
        .iter()
        .map(|server| {
            let (raw, transaction_id) = StunMessage::new_binding_request();
            StunRequest { server: *server, raw, transaction_id }
        })
        .collect::<Vec<_>>();
    let mut pending = requests.iter().map(|request| request.transaction_id).collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    let mut last_err: Option<anyhow::Error> = None;
    let mut buffer = vec![0u8; 1500];
    for attempt_timeout in STUN_ATTEMPT_TIMEOUTS {
        if ctx.is_cancelled() {
            last_err = Some(anyhow!("context canceled"));
            break;
        }
        if pending.is_empty() {
            break;
        }
        if let Err(err) = transmit_stun_requests(conn, &requests, &pending).await {
            last_err = Some(err);
        }
        let deadline = Instant::now() + attempt_timeout;
        while !pending.is_empty() {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else { break };
            match tokio::time::timeout(remaining, conn.read_from(&mut buffer)).await {
                Err(_) => break,
                Ok(Err(err)) => return Err(anyhow!("read STUN response: {err}")),
                Ok(Ok((n, _))) => {
                    let Some(data) = buffer.get(..n) else { continue };
                    let Ok(message) = StunMessage::decode(data) else { continue };
                    if !pending.remove(&message.transaction_id) {
                        continue;
                    }
                    if let Ok(address) = message.xor_mapped_address() {
                        if seen.insert(address) {
                            result.push(address);
                        }
                    }
                }
            }
        }
    }
    if !result.is_empty() {
        return Ok(result);
    }
    match last_err {
        Some(err) => Err(err),
        None => bail!("no STUN responses received"),
    }
}

async fn transmit_stun_requests(
    conn: &Arc<dyn NetPacketConn>,
    requests: &[StunRequest],
    pending: &HashSet<[u8; STUN_TRANSACTION_ID_SIZE]>,
) -> Result<()> {
    // cancel-safe: a dropped round has simply asked fewer servers, which the next attempt covers.
    let mut send_errs = Vec::new();
    let mut sent = 0;
    for request in requests {
        if !pending.contains(&request.transaction_id) {
            continue;
        }
        match conn.write_to(&request.raw, &UdpAddr::from(request.server)).await {
            Ok(_) => sent += 1,
            Err(err) => send_errs.push(format!("send STUN request to {}: {err}", request.server)),
        }
    }
    if sent == 0 && send_errs.is_empty() {
        bail!("no STUN requests sent");
    }
    if send_errs.is_empty() {
        return Ok(());
    }
    Err(anyhow!(send_errs.join("; ")))
}

/// Sends a hello every `PUNCH_INTERVAL` until a packet decodes under `metadata`.
async fn punch(
    ctx: &CancellationToken,
    conn: &Arc<dyn NetPacketConn>,
    peer_addresses: &[SocketAddr],
    metadata: PunchMetadata,
) -> Result<SocketAddr> {
    // cancel-safe: the candidates and the metadata are all the state it owns.
    let candidates = candidate_punch_addrs(peer_addresses);
    if candidates.is_empty() {
        bail!("no compatible peer addresses");
    }
    let deadline = Instant::now() + PUNCH_TIMEOUT;
    let mut next_send = Instant::now();
    let mut buffer = vec![0u8; PUNCH_SALT_LENGTH + PUNCH_MIN_BODY_SIZE + PUNCH_MAX_PADDING];
    loop {
        if ctx.is_cancelled() {
            bail!("punch timeout: context canceled");
        }
        let now = Instant::now();
        if now >= deadline {
            bail!("punch timeout");
        }
        if now >= next_send {
            for candidate in &candidates {
                send_punch_packet(conn, *candidate, PUNCH_HELLO, &metadata).await;
            }
            next_send = now + PUNCH_INTERVAL;
        }
        let read_deadline = std::cmp::min(next_send, deadline);
        let remaining = read_deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, conn.read_from(&mut buffer)).await {
            Err(_) => {}
            Ok(Err(err)) => return Err(anyhow!("punch read: {err}")),
            Ok(Ok((n, addr))) => {
                let Ok(peer) = old_addr_to_socket_addr(addr.as_ref()) else { continue };
                let Some(data) = buffer.get(..n) else { continue };
                let Ok(packet_type) = decode_punch_packet(data, &metadata) else { continue };
                if packet_type == PUNCH_HELLO {
                    send_punch_packet(conn, peer, PUNCH_ACK, &metadata).await;
                }
                return Ok(peer);
            }
        }
    }
}

async fn send_punch_packet(
    conn: &Arc<dyn NetPacketConn>,
    address: SocketAddr,
    packet_type: u8,
    metadata: &PunchMetadata,
) {
    // cancel-safe: one datagram, nothing to leave half written.
    let packet = encode_punch_packet(packet_type, metadata);
    let _ = conn.write_to(&packet, &UdpAddr::from(address)).await;
}

fn candidate_punch_addrs(peer_addresses: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for address in peer_addresses {
        if address.port() == 0 || !seen.insert(*address) {
            continue;
        }
        candidates.push(*address);
    }
    expand_symmetric_nat_candidates(&mut candidates, &mut seen);
    candidates
}

fn expand_symmetric_nat_candidates(candidates: &mut Vec<SocketAddr>, seen: &mut HashSet<SocketAddr>) {
    let mut ports_by_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    for address in candidates.iter() {
        if address.is_ipv4() {
            ports_by_ip.entry(address.ip()).or_default().push(address.port());
        }
    }
    for (ip, mut ports) in ports_by_ip {
        ports.sort_unstable();
        ports.dedup();
        let (Some(first), Some(last)) = (ports.first(), ports.last()) else { continue };
        let predictable = ports.len() >= 2
            && ports.iter().zip(ports.iter().skip(1)).all(|(low, high)| high - low <= SYMMETRIC_NAT_PORT_GAP);
        if !predictable {
            continue;
        }
        let end = last.saturating_add(SYMMETRIC_NAT_EXTRA_PORTS);
        let mut added = 0;
        for port in *first..=end {
            if added >= SYMMETRIC_NAT_MAX_PORTS_PER_HOST {
                break;
            }
            let address = SocketAddr::new(ip, port);
            if seen.insert(address) {
                candidates.push(address);
                added += 1;
            }
        }
    }
}

fn unmap(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 @ IpAddr::V4(_) => v4,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn unspecified(self) -> SocketAddr {
        match self {
            Self::V4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            Self::V6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        }
    }

    fn matches(self, address: IpAddr) -> bool {
        address.is_ipv4() == (self == Self::V4)
    }
}

impl fmt::Display for IpFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
        })
    }
}

/// A per-family packet conn, minus its write-only local addresses.
struct FamilyConn {
    family: IpFamily,
    conn: Arc<dyn NetPacketConn>,
}

struct ConnectResponse {
    addresses: Vec<SocketAddr>,
    metadata: PunchMetadata,
}

/// The realm options, plus the HTTP client built from the realm TLS options.
pub(crate) struct RealmClient {
    server_url: String,
    token: String,
    realm_id: String,
    stun_servers: Vec<String>,
    dialer: Arc<dyn CDialer>,
    ca_option: ca::config::Option,
}

impl RealmClient {
    /// The realm block plus the control client.
    pub(crate) fn new(realm: &Hysteria2RealmOption, dialer: Arc<dyn CDialer>) -> Result<Self> {
        let ca_option = realm_ca_option(realm);
        // This config is built at construction, so bad certificate material fails at load.
        ca::config::get_tls_config(ca_option.clone())?;
        if realm.server_url.is_empty() {
            bail!("create control client: control server URL is required");
        }
        Ok(Self {
            server_url: realm.server_url.trim_end_matches('/').to_owned(),
            token: realm.token.clone(),
            realm_id: realm.realm_id.clone(),
            stun_servers: realm.stun_servers.clone(),
            dialer,
            ca_option,
        })
    }

    /// a punched socket and the peer address to run QUIC against.
    pub(crate) async fn offer_new(&self, ctx: &CancellationToken) -> Result<(Arc<dyn NetPacketConn>, Socksaddr)> {
        // cancel-safe: the family sockets and the in-flight control request are owned here, so a
        // drop closes them; nothing outside this future is mutated.
        let families = self.open_families(ctx).await?;
        let (surviving, local_addresses) = self.discover_families(ctx, families).await?;
        let local_metadata = PunchMetadata::generate();
        let response = match self.control_connect(ctx, &local_addresses, &local_metadata).await {
            Ok(response) => response,
            Err(err) => {
                for family in &surviving {
                    let _ = family.conn.close();
                }
                return Err(anyhow!("realm connect: {err}"));
            }
        };
        let (winner, peer) = self.race_punch(ctx, surviving, &response).await?;
        Ok((winner.conn, Socksaddr::from_socket_addr(peer)))
    }

    async fn open_families(&self, ctx: &CancellationToken) -> Result<Vec<FamilyConn>> {
        // cancel-safe: sockets bound so far are dropped, and closed, with the future.
        let mut families = Vec::new();
        let mut errs = Vec::new();
        for family in [IpFamily::V4, IpFamily::V6] {
            match self.dialer.listen_packet(ctx, "udp", "", Some(family.unspecified())).await {
                Ok(datagram) => {
                    let conn: Arc<dyn NetPacketConn> = Arc::new(DatagramAsOldPacketConn(datagram));
                    families.push(FamilyConn { family, conn });
                }
                Err(err) => errs.push(format!("{family}: {err}")),
            }
        }
        if families.is_empty() {
            bail!("listen UDP for realm: {}", errs.join("; "));
        }
        Ok(families)
    }

    async fn discover_families(
        &self,
        ctx: &CancellationToken,
        families: Vec<FamilyConn>,
    ) -> Result<(Vec<FamilyConn>, Vec<SocketAddr>)> {
        // cancel-safe: the union is local, and the families' sockets close with the future.
        let need_ipv4 = families.iter().any(|family| family.family == IpFamily::V4);
        let need_ipv6 = families.iter().any(|family| family.family == IpFamily::V6);
        let stun_servers = resolve_stun_servers(ctx, &self.stun_servers, need_ipv4, need_ipv6)
            .await
            .map_err(|err| anyhow!("resolve STUN servers: {err}"))?;
        let results = join_all(families.into_iter().map(|family| {
            let servers =
                stun_servers.iter().copied().filter(|server| family.family.matches(server.ip())).collect::<Vec<_>>();
            async move {
                let addresses = discover(ctx, &family.conn, &servers).await;
                (family, addresses)
            }
        }))
        .await;
        let mut surviving = Vec::new();
        let mut local_addresses = Vec::new();
        let mut errs = Vec::new();
        for (family, result) in results {
            match result {
                Ok(addresses) => {
                    local_addresses.extend(addresses);
                    surviving.push(family);
                }
                Err(err) => {
                    let _ = family.conn.close();
                    errs.push(format!("{}: {err}", family.family));
                }
            }
        }
        if surviving.is_empty() {
            bail!("realm STUN discovery: {}", errs.join("; "));
        }
        Ok((surviving, local_addresses))
    }

    /// The first family to complete a punch wins, the others are closed.
    async fn race_punch(
        &self,
        ctx: &CancellationToken,
        families: Vec<FamilyConn>,
        response: &ConnectResponse,
    ) -> Result<(FamilyConn, SocketAddr)> {
        // NOT cancel-safe: the per-family punches are spawned, so dropping this future leaves them
        // running until their sockets close.
        let race = ctx.child_token();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let conns = families.iter().map(|family| (family.family, Arc::clone(&family.conn))).collect::<Vec<_>>();
        let mut pending = families.len();
        for family in families {
            let peers =
                response.addresses.iter().copied().filter(|peer| family.family.matches(peer.ip())).collect::<Vec<_>>();
            let conn = Arc::clone(&family.conn);
            let race = race.clone();
            let metadata = response.metadata;
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = punch(&race, &conn, &peers, metadata).await;
                let _ = tx.send((family, result));
            });
        }
        drop(tx);
        let mut errs = Vec::new();
        while pending > 0 {
            pending -= 1;
            let Some((family, result)) = rx.recv().await else { break };
            match result {
                Ok(peer) => {
                    race.cancel();
                    for (other, conn) in &conns {
                        if *other != family.family {
                            let _ = conn.close();
                        }
                    }
                    return Ok((family, peer));
                }
                Err(err) => errs.push(format!("{}: {err}", family.family)),
            }
        }
        bail!("realm punch: {}", errs.join("; "))
    }

    async fn control_connect(
        &self,
        ctx: &CancellationToken,
        addresses: &[SocketAddr],
        metadata: &PunchMetadata,
    ) -> Result<ConnectResponse> {
        // cancel-safe: `http_request` dials a fresh connection, and the response is read into a
        // local buffer only after the request resolves.
        let url = format!("{}/v1/{}/connect", self.server_url, path_escape(&self.realm_id));
        let body = serde_json::json!({
            "addresses": addresses.iter().map(SocketAddr::to_string).collect::<Vec<_>>(),
            "nonce": hex::encode(metadata.nonce),
            "obfs": hex::encode(metadata.obfuscation_key),
        })
        .to_string();
        let headers = HashMap::from([
            ("Content-Type".to_owned(), vec!["application/json".to_owned()]),
            ("Authorization".to_owned(), vec![format!("Bearer {}", self.token)]),
        ]);
        let options =
            [murmur_http::with_dialer(Arc::clone(&self.dialer)), murmur_http::with_ca_option(self.ca_option.clone())];
        let mut body = Cursor::new(body.into_bytes());
        let response = murmur_http::http_request(ctx, &url, "POST", &headers, Some(&mut body), &options)
            .await
            .map_err(|err| anyhow!("connect: {url}: {err}"))?;
        let status = response.status().as_u16();
        let raw = http_body_util::BodyExt::collect(response.into_body())
            .await
            .map_err(|err| anyhow!("connect: {url}: {err}"))?
            .to_bytes();
        if !(200..300).contains(&status) {
            let error =
                serde_json::from_slice::<ErrorWire>(raw.get(..MAX_ERROR_BODY_SIZE).unwrap_or(&raw)).unwrap_or_default();
            let detail = if error.message.is_empty() { String::new() } else { format!(": {}", error.message) };
            bail!("connect: control {status}/{}{detail}", error.error);
        }
        let wire: ConnectWire =
            serde_json::from_slice(&raw).map_err(|err| anyhow!("connect: decode response: {err}"))?;
        let metadata = PunchMetadata::decode_wire(&wire.nonce, &wire.obfs)
            .map_err(|err| anyhow!("connect: decode connect response metadata: {err}"))?;
        let mut addresses = Vec::with_capacity(wire.addresses.len());
        for address in &wire.addresses {
            addresses.push(address.parse::<SocketAddr>().map_err(|err| anyhow!("connect: decode response: {err}"))?);
        }
        Ok(ConnectResponse { addresses, metadata })
    }
}

#[derive(serde::Deserialize)]
struct ConnectWire {
    addresses: Vec<String>,
    nonce: String,
    obfs: String,
}

#[derive(Default, serde::Deserialize)]
struct ErrorWire {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

/// The http TLS config for `server-url`, built from the realm options rather than the hysteria2
/// server's.
fn realm_ca_option(realm: &Hysteria2RealmOption) -> ca::config::Option {
    ca::config::Option {
        tls_config: Some(tls_c::Config {
            server_name: realm.sni.clone(),
            insecure_skip_verify: realm.skip_cert_verify,
            next_protos: realm.alpn.clone().unwrap_or_default(),
            rand: None,
            time: None,
            certificates: Vec::new(),
            get_certificate: None,
            get_client_certificate: None,
            verify_peer_certificate: None,
            verify_connection: None,
            root_cas: None,
            client_auth: tls_c::ClientAuthType::default(),
            client_cas: None,
            cipher_suites: None,
            session_tickets_disabled: false,
            min_version: 0,
            max_version: 0,
            curve_preferences: None,
            renegotiation: tls_c::RenegotiationSupport::default(),
            key_log_writer: None,
            encrypted_client_hello_config_list: Vec::new(),
            encrypted_client_hello_rejection_verify: None,
            encrypted_client_hello_keys: Vec::new(),
            get_encrypted_client_hello_keys: None,
            session_id_generator: None,
        }),
        fingerprint: realm.fingerprint.clone(),
        name_cert_verify: realm.name_cert_verify.clone(),
        certificate: realm.certificate.clone(),
        private_key: realm.private_key.clone(),
        zero_trust: false,
    }
}

/// Escapes the one path segment the realm URL builds.
fn path_escape(segment: &str) -> String {
    let mut escaped = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => escaped.push(char::from(byte)),
            _ => {
                let _ = write!(escaped, "%{byte:02X}");
            }
        }
    }
    escaped
}

/// The registered peer's half of the punch protocol, so the adapter's round-trip test can answer a
/// client without the hysteria2 server's own realm support.
#[cfg(test)]
pub(crate) mod test_support {
    use anyhow::Result;

    pub(crate) use super::PunchMetadata;

    pub(crate) const HELLO: u8 = super::PUNCH_HELLO;
    pub(crate) const ACK: u8 = super::PUNCH_ACK;

    /// Decodes the wire metadata as the peer reads it off a `punch` event.
    pub(crate) fn decode_metadata(nonce_hex: &str, obfs_hex: &str) -> Result<PunchMetadata> {
        PunchMetadata::decode_wire(nonce_hex, obfs_hex)
    }

    pub(crate) fn encode_packet(packet_type: u8, metadata: &PunchMetadata) -> Vec<u8> {
        super::encode_punch_packet(packet_type, metadata)
    }

    pub(crate) fn decode_packet(data: &[u8], metadata: &PunchMetadata) -> Result<u8> {
        super::decode_punch_packet(data, metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn punch_metadata(nonce: u8, key: u8) -> PunchMetadata {
        PunchMetadata { nonce: [nonce; PUNCH_NONCE_LENGTH], obfuscation_key: [key; PUNCH_KEY_LENGTH] }
    }

    #[test]
    fn punch_packets_carry_the_type_and_nonce_under_the_key() {
        let metadata = punch_metadata(7, 3);
        let hello = encode_punch_packet(PUNCH_HELLO, &metadata);
        assert!(hello.len() >= PUNCH_SALT_LENGTH + PUNCH_MIN_BODY_SIZE);
        assert!(hello.len() <= PUNCH_SALT_LENGTH + PUNCH_MIN_BODY_SIZE + PUNCH_MAX_PADDING);
        assert_eq!(decode_punch_packet(&hello, &metadata).expect("our own hello decodes"), PUNCH_HELLO);
        let ack = encode_punch_packet(PUNCH_ACK, &metadata);
        assert_eq!(decode_punch_packet(&ack, &metadata).expect("our own ack decodes"), PUNCH_ACK);

        assert_eq!(
            decode_punch_packet(&hello, &punch_metadata(7, 4)).expect_err("a foreign key").to_string(),
            "magic mismatch"
        );
        assert_eq!(
            decode_punch_packet(&hello, &punch_metadata(8, 3)).expect_err("a foreign nonce").to_string(),
            "nonce mismatch"
        );
    }

    #[test]
    fn punch_packets_reject_lengths_outside_the_encoding() {
        let metadata = punch_metadata(1, 2);
        let short = vec![0u8; PUNCH_SALT_LENGTH + PUNCH_MIN_BODY_SIZE - 1];
        assert_eq!(decode_punch_packet(&short, &metadata).expect_err("too short").to_string(), "packet too short");
        let long = vec![0u8; PUNCH_SALT_LENGTH + PUNCH_MIN_BODY_SIZE + PUNCH_MAX_PADDING + 1];
        assert_eq!(decode_punch_packet(&long, &metadata).expect_err("too long").to_string(), "packet too long");
    }

    /// The request is 20 bytes with the RFC 5389 header, and the response's XOR-MAPPED-ADDRESS is
    /// returned with the port and address un-XORed.
    #[test]
    fn stun_binding_requests_and_xor_mapped_addresses_round_trip() {
        let (raw, transaction_id) = StunMessage::new_binding_request();
        assert_eq!(raw.len(), STUN_HEADER_SIZE);
        assert_eq!(u16::from_be_bytes([raw[0], raw[1]]), STUN_BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([raw[2], raw[3]]), 0);
        assert_eq!(u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]), STUN_MAGIC_COOKIE);
        assert_eq!(raw[8..], transaction_id);

        let mapped: SocketAddr = "192.0.2.7:41234".parse().expect("a mapped address");
        let message = StunMessage::decode(&stun_response(&transaction_id, mapped)).expect("decode the response");
        assert_eq!(message.transaction_id, transaction_id);
        assert_eq!(message.xor_mapped_address().expect("the mapped address"), mapped);

        let mapped_v6: SocketAddr = "[2001:db8::1]:9".parse().expect("a mapped v6 address");
        let message = StunMessage::decode(&stun_response(&transaction_id, mapped_v6)).expect("decode the v6 response");
        assert_eq!(message.xor_mapped_address().expect("the mapped v6 address"), mapped_v6);
    }

    #[test]
    fn stun_messages_reject_foreign_and_truncated_wire_data() {
        let (_, transaction_id) = StunMessage::new_binding_request();
        assert!(StunMessage::decode(&[0u8; STUN_HEADER_SIZE - 1]).is_err());
        let mut bad_cookie = stun_response(&transaction_id, "192.0.2.7:1".parse().expect("address"));
        bad_cookie[6] ^= 0xff;
        assert_eq!(
            StunMessage::decode(&bad_cookie).expect_err("a broken cookie").to_string(),
            "invalid STUN magic cookie"
        );
        let truncated = &stun_response(&transaction_id, "192.0.2.7:1".parse().expect("address"))[..STUN_HEADER_SIZE];
        assert_eq!(
            StunMessage::decode(truncated).expect_err("a truncated message").to_string(),
            "truncated STUN message"
        );

        let mut no_attribute = vec![0u8; STUN_HEADER_SIZE];
        no_attribute[..2].copy_from_slice(&0x0101u16.to_be_bytes());
        no_attribute[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        no_attribute[8..].copy_from_slice(&transaction_id);
        let message = StunMessage::decode(&no_attribute).expect("an attribute-less response decodes");
        assert_eq!(
            message.xor_mapped_address().expect_err("nothing to map").to_string(),
            "XOR-MAPPED-ADDRESS not found"
        );
    }

    #[test]
    fn symmetric_nat_expansion_adds_the_predictable_port_window() {
        let peer: SocketAddr = "192.0.2.7:1000".parse().expect("address");
        let second: SocketAddr = "192.0.2.7:1002".parse().expect("address");
        let port = |port: u16| SocketAddr::new(peer.ip(), port);
        let candidates = candidate_punch_addrs(&[peer, second]);
        assert_eq!(
            candidates,
            vec![peer, second, port(1001), port(1003), port(1004), port(1005), port(1006)],
            "the window reaches SYMMETRIC_NAT_EXTRA_PORTS past the range end and is appended in port order"
        );

        let sparse: SocketAddr = "192.0.2.7:1200".parse().expect("address");
        assert_eq!(
            candidate_punch_addrs(&[peer, sparse]),
            vec![peer, sparse],
            "a gap wider than the window is not a predictable group"
        );

        assert_eq!(candidate_punch_addrs(&[peer]), vec![peer], "one port is not enough to predict the next");
        assert!(candidate_punch_addrs(&[]).is_empty());
        assert_eq!(candidate_punch_addrs(&[peer, peer, port(0)]), vec![peer], "duplicates and a zero port drop out");

        let v6: SocketAddr = "[2001:db8::1]:1000".parse().expect("address");
        assert_eq!(candidate_punch_addrs(&[v6, v6]), vec![v6], "v6 candidates are not port-expanded");
    }

    #[test]
    fn the_predictable_port_window_is_capped() {
        let ip: IpAddr = "192.0.2.7".parse().expect("address");
        let peers = (0..11).map(|step| SocketAddr::new(ip, 1000 + step * 4)).collect::<Vec<_>>();
        let candidates = candidate_punch_addrs(&peers);
        assert_eq!(
            candidates.len(),
            peers.len() + SYMMETRIC_NAT_MAX_PORTS_PER_HOST,
            "the window stops at SYMMETRIC_NAT_MAX_PORTS_PER_HOST added ports"
        );
        assert_eq!(candidates[..peers.len()], peers[..]);
        let expanded = &candidates[peers.len()..];
        assert_eq!(expanded.len(), SYMMETRIC_NAT_MAX_PORTS_PER_HOST);
        assert!(expanded.iter().all(|address| !peers.contains(address) && address.port() <= 1044));
    }

    #[tokio::test]
    async fn stun_servers_default_the_port_and_skip_the_other_family() {
        let ctx = CancellationToken::new();
        let resolved = resolve_stun_servers(&ctx, &["192.0.2.9".to_owned(), "192.0.2.9:9999".to_owned()], true, false)
            .await
            .expect("literals resolve without a resolver");
        assert_eq!(
            resolved,
            vec!["192.0.2.9:3478".parse().expect("address"), "192.0.2.9:9999".parse().expect("address")]
        );

        let resolved = resolve_stun_servers(&ctx, &["192.0.2.9".to_owned(), "2001:db8::1".to_owned()], false, true)
            .await
            .expect("a v4 literal is skipped for a v6-only family, not fatal");
        assert_eq!(resolved, vec!["[2001:db8::1]:3478".parse().expect("address")]);
        let err = resolve_stun_servers(&ctx, &["192.0.2.9".to_owned()], false, true)
            .await
            .expect_err("a v4-only list resolves to nothing for a v6-only family");
        assert_eq!(err.to_string(), "no STUN servers resolved");

        let err = resolve_stun_servers(&ctx, &[], true, true).await.expect_err("no servers at all");
        assert_eq!(err.to_string(), "no STUN servers resolved");
        let err =
            resolve_stun_servers(&ctx, &["192.0.2.9:not-a-port".to_owned()], true, true).await.expect_err("a bad port");
        assert_eq!(err.to_string(), "resolve STUN port: not-a-port");
    }

    #[tokio::test]
    async fn discovery_needs_a_server_and_ignores_undecodable_datagrams() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let conn: Arc<dyn NetPacketConn> = Arc::new(socket);
        let ctx = CancellationToken::new();
        assert_eq!(discover(&ctx, &conn, &[]).await.expect_err("no servers").to_string(), "no STUN servers");

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind the STUN peer");
        let server_addr = server.local_addr().expect("peer address");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            let (n, from) = server.recv_from(&mut buf).await.expect("receive the request");
            let request = StunMessage::decode(&buf[..n]).expect("decode the request");
            server.send_to(&[0xff; 64], from).await.expect("send noise first");
            server.send_to(&stun_response(&request.transaction_id, from), from).await.expect("answer the request");
            let _ = tx.send(());
        });
        let discovered = discover(&ctx, &conn, &[server_addr]).await.expect("the fake peer answers");
        assert_eq!(discovered.len(), 1, "the noise is ignored");
        assert!(rx.recv().await.is_some());
    }

    fn stun_response(transaction_id: &[u8; STUN_TRANSACTION_ID_SIZE], mapped: SocketAddr) -> Vec<u8> {
        let (family, ip) = match mapped.ip() {
            IpAddr::V4(v4) => (STUN_FAMILY_IPV4, v4.octets().to_vec()),
            IpAddr::V6(v6) => (STUN_FAMILY_IPV6, v6.octets().to_vec()),
        };
        let mut value = vec![0u8, family];
        value.extend_from_slice(&(mapped.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        let mut key = [0u8; 4 + STUN_TRANSACTION_ID_SIZE];
        key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        key[4..].copy_from_slice(transaction_id);
        value.extend(ip.iter().enumerate().map(|(i, byte)| byte ^ key[i]));

        let mut response = vec![0u8; STUN_HEADER_SIZE];
        response[..2].copy_from_slice(&0x0101u16.to_be_bytes());
        response[2..4].copy_from_slice(&u16::try_from(value.len() + 4).expect("attribute length").to_be_bytes());
        response[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response[8..].copy_from_slice(transaction_id);
        response.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&u16::try_from(value.len()).expect("value length").to_be_bytes());
        response.extend_from_slice(&value);
        response
    }

    #[test]
    fn the_realm_id_is_path_escaped() {
        assert_eq!(path_escape("realm-1_test"), "realm-1_test");
        assert_eq!(path_escape("a/b c"), "a%2Fb%20c");
    }

    #[test]
    fn realm_options_map_onto_the_http_tls_config() {
        let realm = Hysteria2RealmOption {
            enable: true,
            server_url: "https://realm.example.com".to_owned(),
            sni: "realm.example.com".to_owned(),
            skip_cert_verify: true,
            name_cert_verify: "verify.example.com".to_owned(),
            fingerprint: "chrome".to_owned(),
            certificate: String::new(),
            private_key: String::new(),
            alpn: Some(vec!["h3".to_owned()]),
            ..Default::default()
        };
        let option = realm_ca_option(&realm);
        let tls = option.tls_config.expect("the realm TLS config");
        assert_eq!(tls.server_name, "realm.example.com");
        assert!(tls.insecure_skip_verify);
        assert_eq!(tls.next_protos, vec!["h3".to_owned()]);
        assert_eq!(option.name_cert_verify, "verify.example.com");
        assert_eq!(option.fingerprint, "chrome");

        let unset = realm_ca_option(&Hysteria2RealmOption::default());
        let tls = unset.tls_config.expect("the realm TLS config");
        assert!(tls.server_name.is_empty(), "an unset realm SNI leaves the URL host as the name");
        assert!(tls.next_protos.is_empty());
        assert!(!tls.insecure_skip_verify);
    }
}

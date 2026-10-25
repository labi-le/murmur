#![cfg(feature = "extra-protocols")]
//! End-to-end realm tests: a realm-aware hysteria2 client asks the listener's own realm control
//! plane for a punch, punches a peer, and carries a TCP payload to a real
//! `murmur_transport_hysteria2::service::Service` over the punched socket.
//!
//! The server half has no Rust implementation yet, so the
//! test plays it: it registers the peer with the realm, answers the `punch` event on
//! `connects/{nonce}`, and answers the client's punch hello from the server's own socket. What is
//! exercised for real is everything else: the realm server's register/events/connect/connects
//! routes, the client's STUN discovery and hole punch, and the QUIC session on the punched socket.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![allow(
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
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::listen::default_listen_config;
use murmur_adapter_outbound::hysteria2::{Hysteria2, Hysteria2Option, Hysteria2RealmOption};
use murmur_common_net::io::old_addr_to_socket_addr;
use murmur_component_ca::keypair::new_tls_key_pair_loader;
use murmur_component_tls::utls as tls_c;
use murmur_constant::adapters::ProxyAdapter;
use murmur_constant::listener::MultiAddrListener;
use murmur_constant::metadata::Metadata;
use murmur_listener::hysteria2_realm::server::{
    default_alpn, Listener as RealmListener, DEFAULT_MAX_REALMS, DEFAULT_MAX_REALMS_PER_IP,
};
use murmur_listener::hysteria2_realm::session::DEFAULT_REALM_NAME_PATTERN;
use murmur_listener_config::hysteria2_realm::Hysteria2RealmServer;
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Addr as NetAddr, Conn as NetConn, PacketConn as NetPacketConn, UdpAddr};
use murmur_testsupport::{tls_certificate, tls_private_key, HttpTestTunnel};
use murmur_testsupport_probe::ensure_test_crypto_provider;
use murmur_transport_hysteria2::quic::{CongestionOption, QuicConfig};
use murmur_transport_hysteria2::service::{ServerHandler, Service, ServiceOptions};

const REALM_TOKEN: &str = "realm-token";
const REALM_ID: &str = "realm-e2e";
const SESSION_PASSWORD: &str = "test-password";
const PAYLOAD: &[u8] = b"hysteria2-realm-e2e-payload";
const TIMEOUT: Duration = Duration::from_secs(20);

/// The punch-metadata wire lengths.
const PUNCH_SALT_LENGTH: usize = 8;
const PUNCH_MAGIC_LENGTH: usize = 8;
const PUNCH_NONCE_LENGTH: usize = 16;
const PUNCH_KEY_LENGTH: usize = 32;
const PUNCH_MIN_BODY_SIZE: usize = PUNCH_MAGIC_LENGTH + 1 + PUNCH_NONCE_LENGTH;
const PUNCH_MAX_PADDING: usize = 1024;
const PUNCH_MAGIC: [u8; PUNCH_MAGIC_LENGTH] = *b"HYRLMv1\0";
const PUNCH_HELLO: u8 = 0x01;
const PUNCH_ACK: u8 = 0x02;

#[derive(Clone, Copy)]
struct PunchMetadata {
    nonce: [u8; PUNCH_NONCE_LENGTH],
    obfuscation_key: [u8; PUNCH_KEY_LENGTH],
}

impl PunchMetadata {
    fn decode_wire(nonce_hex: &str, obfs_hex: &str) -> Self {
        let mut metadata = Self { nonce: [0; PUNCH_NONCE_LENGTH], obfuscation_key: [0; PUNCH_KEY_LENGTH] };
        let nonce = hex::decode(nonce_hex).expect("the punch event's nonce is hex");
        let key = hex::decode(obfs_hex).expect("the punch event's obfs key is hex");
        metadata.nonce.copy_from_slice(&nonce);
        metadata.obfuscation_key.copy_from_slice(&key);
        metadata
    }
}

fn xor_obfuscate(key: &[u8; PUNCH_KEY_LENGTH], salt: &[u8], body: &mut [u8]) {
    let mut material = [0u8; PUNCH_KEY_LENGTH + PUNCH_SALT_LENGTH];
    material[..PUNCH_KEY_LENGTH].copy_from_slice(key);
    material[PUNCH_KEY_LENGTH..].copy_from_slice(salt);
    let digest = Sha256::digest(material);
    for (i, byte) in body.iter_mut().enumerate() {
        *byte ^= digest[i % PUNCH_KEY_LENGTH];
    }
}

fn encode_punch_packet(packet_type: u8, metadata: &PunchMetadata) -> Vec<u8> {
    let mut salt = [0u8; PUNCH_SALT_LENGTH];
    rand::rng().fill_bytes(&mut salt);
    let mut padding_byte = [0u8; 1];
    rand::rng().fill_bytes(&mut padding_byte);
    let padding = usize::from(padding_byte[0]);
    let mut packet = vec![0u8; PUNCH_SALT_LENGTH + PUNCH_MIN_BODY_SIZE + padding];
    packet[..PUNCH_SALT_LENGTH].copy_from_slice(&salt);
    let body = &mut packet[PUNCH_SALT_LENGTH..];
    body[..PUNCH_MAGIC_LENGTH].copy_from_slice(&PUNCH_MAGIC);
    body[PUNCH_MAGIC_LENGTH] = packet_type;
    body[PUNCH_MAGIC_LENGTH + 1..PUNCH_MAGIC_LENGTH + 1 + PUNCH_NONCE_LENGTH].copy_from_slice(&metadata.nonce);
    xor_obfuscate(&metadata.obfuscation_key, &salt, body);
    packet
}

fn decode_punch_packet(data: &[u8], metadata: &PunchMetadata) -> Option<u8> {
    if data.len() < PUNCH_SALT_LENGTH + PUNCH_MIN_BODY_SIZE
        || data.len() > PUNCH_SALT_LENGTH + PUNCH_MIN_BODY_SIZE + PUNCH_MAX_PADDING
    {
        return None;
    }
    let mut salt = [0u8; PUNCH_SALT_LENGTH];
    salt.copy_from_slice(&data[..PUNCH_SALT_LENGTH]);
    let mut body = data[PUNCH_SALT_LENGTH..].to_vec();
    xor_obfuscate(&metadata.obfuscation_key, &salt, &mut body);
    if body[..PUNCH_MAGIC_LENGTH] != PUNCH_MAGIC {
        return None;
    }
    let packet_type = body[PUNCH_MAGIC_LENGTH];
    if packet_type != PUNCH_HELLO && packet_type != PUNCH_ACK {
        return None;
    }
    if body[PUNCH_MAGIC_LENGTH + 1..PUNCH_MAGIC_LENGTH + 1 + PUNCH_NONCE_LENGTH] != metadata.nonce {
        return None;
    }
    Some(packet_type)
}

/// As the punch packet conn: punch datagrams leave the server's socket for the test, everything
/// else reaches the hysteria2 service.
struct PunchDemux {
    inner: Arc<UdpSocket>,
    metadata: Mutex<Option<PunchMetadata>>,
    punches: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
}

#[async_trait]
impl NetPacketConn for PunchDemux {
    async fn read_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, Box<dyn NetAddr>)> {
        loop {
            let (n, addr) = self.inner.read_from(buf).await?;
            let metadata = *self.metadata.lock().expect("punch metadata lock");
            if let Some(metadata) = metadata {
                if decode_punch_packet(&buf[..n], &metadata).is_some() {
                    if let Ok(from) = old_addr_to_socket_addr(addr.as_ref()) {
                        let _ = self.punches.send((buf[..n].to_vec(), from));
                    }
                    continue;
                }
            }
            return Ok((n, addr));
        }
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn NetAddr) -> std::io::Result<usize> {
        self.inner.write_to(buf, addr).await
    }

    fn local_addr(&self) -> std::io::Result<Box<dyn NetAddr>> {
        NetPacketConn::local_addr(&*self.inner)
    }

    fn close(&self) -> std::io::Result<()> {
        self.inner.close()
    }
}

#[derive(Default)]
struct EchoHandler {
    echoed: Mutex<Vec<u8>>,
    requested: Mutex<Option<String>>,
}

#[async_trait]
impl ServerHandler for EchoHandler {
    async fn new_connection(
        &self,
        _source: Socksaddr,
        destination: Socksaddr,
        mut conn: Box<dyn NetConn>,
    ) -> Result<()> {
        *self.requested.lock().expect("requested lock") = Some(destination.string());
        let mut buf = vec![0u8; PAYLOAD.len()];
        conn.read_exact(&mut buf).await?;
        self.echoed.lock().expect("echoed lock").extend_from_slice(&buf);
        conn.write_all(&buf).await?;
        Ok(())
    }

    async fn new_packet_connection(
        &self,
        _source: Socksaddr,
        _destination: Socksaddr,
        _conn: Box<dyn NetPacketConn>,
    ) -> Result<()> {
        Ok(())
    }
}

struct Peer {
    demux: Arc<PunchDemux>,
    address: SocketAddr,
    punches: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    _service: Arc<Service>,
}

impl Peer {
    fn addresses(&self) -> Vec<String> {
        vec![self.address.to_string()]
    }
}

async fn start_peer(handler: Arc<EchoHandler>) -> Peer {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind the peer socket"));
    let address = socket.local_addr().expect("the peer's address");
    let (punches_tx, punches) = mpsc::unbounded_channel();
    let demux = Arc::new(PunchDemux { inner: Arc::clone(&socket), metadata: Mutex::new(None), punches: punches_tx });
    let service = Service::new(ServiceOptions {
        send_bps: 0,
        receive_bps: 0,
        ignore_client_bandwidth: false,
        obfs: None,
        tls: Arc::new(tls_c::server_rustls_config(&server_tls_config()).expect("build the server rustls config")),
        quic: QuicConfig { enable_datagrams: true, ..QuicConfig::default() },
        udp_disabled: false,
        congestion: CongestionOption::default(),
        udp_mtu: 0,
        handler,
        masquerade: None,
    });
    service.update_users(vec!["test-user".to_owned()], vec![SESSION_PASSWORD.to_owned()]);
    let packet_conn = Arc::clone(&demux);
    let packet_conn: Arc<dyn NetPacketConn> = packet_conn;
    service.start(packet_conn).expect("start the hysteria2 server");
    Peer { demux, address, punches, _service: service }
}

/// The listener crate does not depend on `rustls`, so the server config is built through
/// `murmur_component_tls` and its concrete type stays inferred at the `ServiceOptions` field.
fn server_tls_config() -> tls_c::Config {
    let cert_loader = new_tls_key_pair_loader(tls_certificate(), tls_private_key()).expect("load the test key pair");
    tls_c::Config {
        min_version: tls_c::VERSION_TLS13,
        next_protos: vec!["h3".to_owned()],
        get_certificate: Some(Arc::new(move |_info: &tls_c::ClientHelloInfo| cert_loader().map(Some))),
        ..Default::default()
    }
}

async fn start_realm(token: &str) -> (RealmListener, SocketAddr) {
    let config = Hysteria2RealmServer {
        enable: true,
        listen: "127.0.0.1:0".to_owned(),
        token: token.to_owned(),
        max_realms: DEFAULT_MAX_REALMS,
        max_realms_per_ip: DEFAULT_MAX_REALMS_PER_IP,
        realm_name_pattern: DEFAULT_REALM_NAME_PATTERN.to_owned(),
        alpn: default_alpn(),
        ..Default::default()
    };
    let listener = RealmListener::new(config, default_listen_config(), HttpTestTunnel::new(), &[])
        .await
        .expect("start the realm listener");
    let address = listener.addr_list()[0].string().parse().expect("the realm listener's address");
    (listener, address)
}

/// `internal/stun`'s XOR-MAPPED-ADDRESS response, encoded from the requester's own address.
async fn start_stun_server() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind the STUN server");
    let port = socket.local_addr().expect("the STUN server's address").port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((read, from)) = socket.recv_from(&mut buf).await else { return };
            if let Some(response) = binding_response(&buf[..read], from) {
                let _ = socket.send_to(&response, from).await;
            }
        }
    });
    port
}

fn binding_response(request: &[u8], mapped: SocketAddr) -> Option<Vec<u8>> {
    if request.len() < 20 || request[..2] != [0x00, 0x01] || request[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return None;
    }
    let transaction_id = &request[8..20];
    let (family, ip) = match mapped.ip() {
        std::net::IpAddr::V4(v4) => (0x01u8, v4.octets().to_vec()),
        std::net::IpAddr::V6(v6) => (0x02u8, v6.octets().to_vec()),
    };
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    key[4..].copy_from_slice(transaction_id);
    let mut value = vec![0u8, family];
    value.extend_from_slice(&(mapped.port() ^ 0x2112).to_be_bytes());
    value.extend(ip.iter().enumerate().map(|(i, byte)| byte ^ key[i]));

    let mut response = vec![0u8; 20];
    response[..2].copy_from_slice(&[0x01, 0x01]);
    response[2..4].copy_from_slice(&u16::try_from(value.len() + 4).expect("attribute length").to_be_bytes());
    response[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    response[8..].copy_from_slice(transaction_id);
    response.extend_from_slice(&0x0020u16.to_be_bytes());
    response.extend_from_slice(&u16::try_from(value.len()).expect("value length").to_be_bytes());
    response.extend_from_slice(&value);
    Some(response)
}

async fn realm_call(
    address: SocketAddr,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    body: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(address).await.expect("connect the realm");
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    if let Some(token) = authorization {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("Content-Type: application/json\r\n");
    request.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream.write_all(request.as_bytes()).await.expect("write the realm request");
    stream.flush().await.expect("flush the realm request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read the realm response");
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n").expect("an http head");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status code");
    (status, String::from_utf8_lossy(&raw[split + 4..]).to_string())
}

/// The register call plus the `events` stream punches are read from.
async fn register_peer(realm: SocketAddr, addresses: &[String]) -> (String, mpsc::UnboundedReceiver<(String, String)>) {
    let body = serde_json::json!({ "addresses": addresses }).to_string();
    let (status, raw) = realm_call(realm, "POST", &format!("/v1/{REALM_ID}"), Some(REALM_TOKEN), &body).await;
    assert_eq!(status, 200, "register: {raw}");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("the register response is json");
    let session = value["session_id"].as_str().expect("a session id").to_owned();
    let events = open_events(realm, &session).await;
    (session, events)
}

async fn open_events(realm: SocketAddr, session: &str) -> mpsc::UnboundedReceiver<(String, String)> {
    let mut stream = TcpStream::connect(realm).await.expect("connect the realm events stream");
    let request = format!(
        "GET /v1/{REALM_ID}/events HTTP/1.1\r\nHost: {realm}\r\nAuthorization: Bearer {session}\r\n\
         Accept: text/event-stream\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.expect("write the events request");
    stream.flush().await.expect("flush the events request");
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut framed = String::new();
        let mut head_done = false;
        loop {
            let read = match stream.read(&mut chunk).await {
                Ok(read) => read,
                Err(_) => return,
            };
            if read == 0 {
                return;
            }
            raw.extend_from_slice(&chunk[..read]);
            if !head_done {
                let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") else { continue };
                raw.drain(..position + 4);
                head_done = true;
            }
            framed.push_str(&String::from_utf8_lossy(&raw));
            raw.clear();
            while let Some(position) = framed.find("\n\n") {
                let frame: String = framed.drain(..position + 2).collect();
                let mut kind = String::new();
                let mut data = String::new();
                for line in frame.lines() {
                    if let Some(value) = line.strip_prefix("event: ") {
                        kind = value.trim().to_owned();
                    } else if let Some(value) = line.strip_prefix("data: ") {
                        data = value.trim().to_owned();
                    }
                }
                if tx.send((kind, data)).is_err() {
                    return;
                }
            }
        }
    });
    rx
}

/// The punch response: the punch event carries the client's addresses, and the
/// server answers with its own on `connects/{nonce}` before the client's hello arrives.
async fn answer_punch(
    peer: &mut Peer,
    realm: SocketAddr,
    session: String,
    mut events: mpsc::UnboundedReceiver<(String, String)>,
) {
    let Some((kind, data)) = events.recv().await else { return };
    assert_eq!(kind, "punch", "the first realm event is the punch");
    let value: serde_json::Value = serde_json::from_str(&data).expect("the punch payload is json");
    let nonce = value["nonce"].as_str().expect("a nonce").to_owned();
    let obfs = value["obfs"].as_str().expect("an obfs key").to_owned();
    let client_addresses: Vec<SocketAddr> = value["addresses"]
        .as_array()
        .expect("client addresses")
        .iter()
        .map(|address| address.as_str().expect("an address string").parse().expect("an addrport"))
        .collect();
    let metadata = PunchMetadata::decode_wire(&nonce, &obfs);
    *peer.demux.metadata.lock().expect("punch metadata lock") = Some(metadata);

    let body = serde_json::json!({ "addresses": peer.addresses() }).to_string();
    let path = format!("/v1/{REALM_ID}/connects/{nonce}");
    let (status, raw) = realm_call(realm, "POST", &path, Some(&session), &body).await;
    assert_eq!(status, 204, "connect-response: {raw}");

    let mut ticker = tokio::time::interval(Duration::from_millis(50));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let hello = encode_punch_packet(PUNCH_HELLO, &metadata);
                for address in &client_addresses {
                    let _ = peer.demux.write_to(&hello, &UdpAddr::from(*address)).await;
                }
            }
            Some((data, from)) = peer.punches.recv() => {
                if decode_punch_packet(&data, &metadata) == Some(PUNCH_HELLO) {
                    let ack = encode_punch_packet(PUNCH_ACK, &metadata);
                    let _ = peer.demux.write_to(&ack, &UdpAddr::from(from)).await;
                    return;
                }
            }
        }
    }
}

fn realm_option(control: SocketAddr, stun_port: u16, port: u16, token: &str) -> Hysteria2Option {
    Hysteria2Option {
        name: "hysteria2-realm-e2e".to_owned(),
        server: "127.0.0.1".to_owned(),
        port: i32::from(port),
        password: SESSION_PASSWORD.to_owned(),
        skip_cert_verify: true,
        realm_opts: Hysteria2RealmOption {
            enable: true,
            server_url: format!("http://{control}"),
            token: token.to_owned(),
            realm_id: REALM_ID.to_owned(),
            stun_servers: vec![format!("127.0.0.1:{stun_port}")],
            ..Default::default()
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn a_realm_aware_client_reaches_a_hysteria2_server_through_the_punch() {
    ensure_test_crypto_provider();
    let (_realm, control) = start_realm(REALM_TOKEN).await;
    let stun_port = start_stun_server().await;
    let handler = Arc::new(EchoHandler::default());
    let mut peer = start_peer(Arc::clone(&handler)).await;
    let (session, events) = register_peer(control, &peer.addresses()).await;
    let punch = tokio::spawn(async move { answer_punch(&mut peer, control, session, events).await });

    // Nothing listens on the configured address: only the punched socket can reach the peer.
    let option = realm_option(control, stun_port, 9, REALM_TOKEN);
    let adapter = Hysteria2::new(option).expect("build the realm outbound");
    let ctx = CancellationToken::new();
    let mut metadata = Metadata { host: "example.com".to_owned(), dst_port: 80, ..Default::default() };
    let mut conn = tokio::time::timeout(TIMEOUT, adapter.dial_context(&ctx, &mut metadata))
        .await
        .expect("the realm dial completes in time")
        .expect("the punched socket reaches the hysteria2 server");

    conn.write_all(PAYLOAD).await.expect("write the payload");
    conn.flush().await.expect("flush the payload");
    let mut buf = vec![0u8; PAYLOAD.len()];
    tokio::time::timeout(TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("the echo arrives in time")
        .expect("read the echo");
    assert_eq!(buf, PAYLOAD, "the tunnel carries the payload back");
    assert_eq!(&*handler.echoed.lock().expect("echoed lock"), PAYLOAD, "the server received the payload");
    assert_eq!(
        handler.requested.lock().expect("requested lock").as_deref(),
        Some("example.com:80"),
        "the server saw the destination the client asked for"
    );
    punch.await.expect("the punch task finishes");
}

#[tokio::test]
async fn a_realm_token_the_service_refuses_fails_the_dial() {
    ensure_test_crypto_provider();
    let (_realm, control) = start_realm(REALM_TOKEN).await;
    let stun_port = start_stun_server().await;
    let adapter = Hysteria2::new(realm_option(control, stun_port, 9, "wrong-token")).expect("build the outbound");

    let ctx = CancellationToken::new();
    let mut metadata = Metadata { host: "example.com".to_owned(), dst_port: 80, ..Default::default() };
    let err = tokio::time::timeout(TIMEOUT, adapter.dial_context(&ctx, &mut metadata))
        .await
        .expect("the dial finishes in time")
        .err()
        .expect("the realm refuses the token");
    let message = err.to_string();
    assert!(message.contains("401/invalid_token"), "{message}");
}

#[tokio::test]
async fn a_realm_id_the_service_never_registered_fails_the_dial() {
    ensure_test_crypto_provider();
    let (_realm, control) = start_realm(REALM_TOKEN).await;
    let stun_port = start_stun_server().await;
    let mut option = realm_option(control, stun_port, 9, REALM_TOKEN);
    option.realm_opts.realm_id = "nobody".to_owned();
    let adapter = Hysteria2::new(option).expect("build the outbound");

    let ctx = CancellationToken::new();
    let mut metadata = Metadata { host: "example.com".to_owned(), dst_port: 80, ..Default::default() };
    let err = tokio::time::timeout(TIMEOUT, adapter.dial_context(&ctx, &mut metadata))
        .await
        .expect("the dial finishes in time")
        .err()
        .expect("an unregistered realm has nobody to connect");
    let message = err.to_string();
    assert!(message.contains("404/realm_not_found"), "{message}");
}

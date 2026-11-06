//! End-to-end behaviour of mieru's `traffic-pattern` on this crate: the nonce prefix the pattern
//! asks for actually appears on the wire, the padding lengths it caps actually bound what is
//! written, TCP fragmentation still delivers a segment intact, and a session with no pattern
//! behaves exactly as before.
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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use murmur_mieru::cipher::BlockCipher;
use murmur_mieru::client::{Client, ClientConfig, HandshakeMode, MultiplexLevel};
use murmur_mieru::io::ServerEndpoint;
use murmur_mieru::model::{AddrSpec, Request, Response, CMD_CONNECT};
use murmur_mieru::padding::{PRINTABLE_CHAR_SUB, PRINTABLE_CHAR_SUP};
use murmur_mieru::server::Server;
use murmur_mieru::session::Transport;
use murmur_mieru::trafficpattern::{self, Config, NoncePatternProto, TrafficPattern};

const TIMEOUT: Duration = Duration::from_secs(10);
const USER: &str = "alice";
const PASSWORD: &str = "s3cret-password";
/// Application bytes the client appends to its handshake, so a write is what puts a first
/// segment on the wire: `HandshakeMode::NoWait` defers the request header to the first write.
const PROBE: &[u8] = b"probe";

fn destination() -> AddrSpec {
    AddrSpec::Ip("192.0.2.1".parse().expect("ip"), 8080)
}

fn config(encoded: &str) -> Config {
    Client::parse_traffic_pattern(encoded).expect("parse").expect("a configured pattern is never None")
}

fn client_config(bound: SocketAddr, traffic_pattern: Option<Config>) -> ClientConfig {
    client_config_with(bound, traffic_pattern, HandshakeMode::NoWait)
}

fn client_config_with(
    bound: SocketAddr,
    traffic_pattern: Option<Config>,
    handshake_mode: HandshakeMode,
) -> ClientConfig {
    ClientConfig {
        server: bound.ip().to_string(),
        port_start: bound.port(),
        port_end: bound.port(),
        username: USER.to_owned(),
        password: PASSWORD.to_owned(),
        transport: Transport::Stream,
        multiplex: MultiplexLevel::Off,
        handshake_mode,
        traffic_pattern,
    }
}

/// A peer that reports the first segment it reads and then says nothing, so the framing the
/// client produced is observable without a working session in the way.
async fn start_raw_server() -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let bound = listener.local_addr().expect("bound addr");
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _peer) = listener.accept().await.expect("accept");
        let mut observed = vec![0u8; 8192];
        let n = socket.read(&mut observed).await.expect("read the first segment");
        observed.truncate(n);
        let _ = tx.send(observed);
        let mut rest = Vec::new();
        let _ = socket.read_to_end(&mut rest).await;
    });
    (bound, rx)
}

/// Dials and writes [`PROBE`], so the client's first segment is on the wire by the time the
/// returned future resolves.
async fn write_first_segment(client: &Client) -> murmur_mieru::client::Stream {
    let mut stream = client.dial_connect(&CancellationToken::new(), destination()).await.expect("dial_connect").stream;
    stream.write_all(PROBE).await.expect("client write");
    stream.flush().await.expect("flush");
    stream
}

/// The size one open-session request carrying [`PROBE`] occupies with no padding at all: the
/// transmitted nonce, the 32-byte metadata with its tag, and the sealed payload with its own.
fn unpadded_segment_len() -> usize {
    let request = Request { command: CMD_CONNECT, dst_addr: destination() };
    let payload_len = request.encode().len() + PROBE.len();
    24 + (32 + 16) + (payload_len + 16)
}

fn padding_config(max_end_padding_len: Option<i32>) -> Config {
    let pattern = TrafficPattern {
        padding: Some(trafficpattern::PaddingPattern { max_middle_padding_len: Some(0), max_end_padding_len }),
        ..Default::default()
    };
    Config::new(Some(pattern)).expect("config")
}

/// The first nonce a pattern shapes is transmitted in the clear at the head of the first segment,
/// so a `PRINTABLE` pattern over the longest rewrite window mieru allows must make that many
/// leading bytes printable ASCII. Nothing after them promises anything: the user hint mieru
/// stamps over the last four is binary by construction.
#[tokio::test]
async fn a_printable_nonce_pattern_makes_the_first_nonce_printable() {
    let (bound, observed) = start_raw_server().await;
    let pattern = TrafficPattern {
        nonce: Some(NoncePatternProto {
            nonce_type: Some(trafficpattern::NonceType::Printable as i32),
            apply_to_all_udp_packet: Some(true),
            min_len: Some(12),
            max_len: Some(12),
            ..Default::default()
        }),
        ..Default::default()
    };
    let client = Client::new(client_config(bound, Some(Config::new(Some(pattern)).expect("config"))));
    let stream = write_first_segment(&client).await;

    let first = observed.await.expect("the server observed the first segment");
    assert!(first.len() >= unpadded_segment_len(), "the first segment is too short to carry a nonce: {first:02x?}");
    let nonce = &first[..24];
    assert!(
        nonce[..12].iter().all(|b| (PRINTABLE_CHAR_SUB..=PRINTABLE_CHAR_SUP).contains(b)),
        "the pattern must shape the nonce prefix to printable ASCII, got {nonce:02x?}"
    );
    assert!(
        BlockCipher::check_user_from_hint(USER, nonce),
        "the last four nonce bytes carry mieru's user hint, not pattern output"
    );
    drop(stream);
    client.close().await;
}

/// A pattern's padding caps have to bound what actually reaches the socket. `maxEndPaddingLen: 0`
/// is the sharpest form, and an open cap the other: the segment must be exactly the unpadded size
/// under the first and strictly longer under the second, so neither direction passes vacuously.
#[tokio::test]
async fn a_padding_cap_bounds_the_bytes_that_reach_the_socket() {
    let unpadded = unpadded_segment_len();

    let (bound, observed) = start_raw_server().await;
    let client = Client::new(client_config(bound, Some(padding_config(Some(0)))));
    let stream = write_first_segment(&client).await;
    let capped = observed.await.expect("the server observed the first segment");
    assert_eq!(
        capped.len(),
        unpadded,
        "a zero padding cap must leave the segment exactly unpadded, got {} bytes",
        capped.len()
    );
    drop(stream);
    client.close().await;

    let (bound, observed) = start_raw_server().await;
    let client = Client::new(client_config(bound, Some(padding_config(Some(255)))));
    let stream = write_first_segment(&client).await;
    let open = observed.await.expect("the server observed the first segment");
    assert!(open.len() > unpadded, "an open padding cap must actually pad the segment, got {} bytes", open.len());
    drop(stream);
    client.close().await;
}

/// Fragmentation splits a large segment across several writes. A single-read probe
/// cannot see that, so the assertion is that a fragmenting pattern still delivers the segment
/// intact: fragmentation may not corrupt, reorder or truncate what it splits.
#[tokio::test]
async fn fragmentation_splits_writes_without_corrupting_the_segment() {
    let mut users = HashMap::new();
    users.insert(USER.to_owned(), PASSWORD.to_owned());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let bound = listener.local_addr().expect("bound addr");
    let pattern = TrafficPattern {
        tcp_fragment: Some(trafficpattern::TcpFragment { enable: Some(true), max_sleep_ms: Some(5) }),
        ..Default::default()
    };
    let traffic_pattern = Config::new(Some(pattern)).expect("config");
    assert_eq!(traffic_pattern.tcp_fragment(), Some((true, 5)), "the pattern must enable fragmentation");

    let server =
        Server::new(&users, vec![ServerEndpoint::Stream(Arc::new(listener))], false, Some(traffic_pattern.clone()))
            .expect("build server");
    let server_task = tokio::spawn(async move {
        let (mut stream, _request) = server.accept().await.expect("accept");
        Response::success().write_to(&mut stream).await.expect("write response");
        let mut buf = vec![0u8; 8192];
        stream.read_exact(&mut buf).await.expect("read the fragmented segment");
        let _ = stream.write_all(&buf).await;
        server
    });

    let client = Client::new(client_config_with(bound, Some(traffic_pattern), HandshakeMode::Standard));
    let mut stream = client.dial_connect(&CancellationToken::new(), destination()).await.expect("dial_connect").stream;
    let payload: Vec<u8> = (0..8192u32).map(|i| (i % 256) as u8).collect();
    stream.write_all(&payload).await.expect("client write");
    stream.flush().await.expect("flush");

    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut echoed)).await.expect("timeout").expect("read_exact");
    assert_eq!(echoed, payload, "fragmentation must not reorder or corrupt the segment");

    let server = server_task.await.expect("server task panicked");
    client.close().await;
    server.close();
}

/// A pattern must not change the protocol: a padded, nonce-shaped client still completes the
/// CONNECT handshake against a server that has no pattern configured, because padding lengths
/// travel in the metadata and the nonce carries its own shape.
#[tokio::test]
async fn a_padded_client_completes_the_handshake_against_an_unpatterned_server() {
    let mut users = HashMap::new();
    users.insert(USER.to_owned(), PASSWORD.to_owned());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let bound = listener.local_addr().expect("bound addr");
    let server =
        Server::new(&users, vec![ServerEndpoint::Stream(Arc::new(listener))], false, None).expect("build server");

    let server_task = tokio::spawn(async move {
        let (mut stream, request) = server.accept().await.expect("accept");
        assert_eq!(request.command, CMD_CONNECT);
        Response::success().write_to(&mut stream).await.expect("write response");
        let mut buf = [0u8; 5];
        tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf)).await.expect("timeout").expect("read_exact");
        assert_eq!(&buf, b"early", "the padded stream must deliver application bytes intact");
        server
    });

    let client = Client::new(client_config_with(bound, Some(config("GgQIARAK")), HandshakeMode::Standard));
    let mut stream = client.dial_connect(&CancellationToken::new(), destination()).await.expect("dial_connect").stream;
    stream.write_all(b"early").await.expect("client write");
    stream.flush().await.expect("flush");

    let server = server_task.await.expect("server task panicked");
    client.close().await;
    server.close();
}

/// A session with no pattern is the pre-existing path: same handshake, same bytes, no padding.
#[tokio::test]
async fn a_session_without_a_pattern_behaves_as_before() {
    let mut users = HashMap::new();
    users.insert(USER.to_owned(), PASSWORD.to_owned());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let bound = listener.local_addr().expect("bound addr");
    let server =
        Server::new(&users, vec![ServerEndpoint::Stream(Arc::new(listener))], false, None).expect("build server");

    let server_task = tokio::spawn(async move {
        let (mut stream, _request) = server.accept().await.expect("accept");
        Response::success().write_to(&mut stream).await.expect("write response");
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
        let mut buf = vec![0u8; payload.len()];
        tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf)).await.expect("timeout").expect("read_exact");
        assert_eq!(buf, payload);
        let _ = stream.write_all(&buf).await;
        server
    });

    let client = Client::new(client_config_with(bound, None, HandshakeMode::Standard));
    let mut stream = client.dial_connect(&CancellationToken::new(), destination()).await.expect("dial_connect").stream;
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
    stream.write_all(&payload).await.expect("client write");
    stream.flush().await.expect("flush");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut echoed)).await.expect("timeout").expect("read_exact");
    assert_eq!(echoed, payload);

    let server = server_task.await.expect("server task panicked");
    client.close().await;
    server.close();
}

/// A pattern asking for low-entropy payload coding cannot be honoured here, so it is refused at
/// parse time instead of being accepted and then quietly not applied.
#[test]
fn a_low_entropy_pattern_is_refused_rather_than_ignored() {
    let pattern = TrafficPattern {
        low_entropy: Some(trafficpattern::LowEntropyPattern { mode: Some(3), mask_rotation: Some(0) }),
        ..Default::default()
    };
    let encoded = trafficpattern::encode(&pattern);
    let err = Client::parse_traffic_pattern(&encoded).expect_err("low entropy must be refused");
    assert!(err.to_string().contains("lowEntropy"), "unexpected error: {err}");

    let server_err = Server::parse_traffic_pattern(&encoded).expect_err("low entropy must be refused");
    assert!(server_err.to_string().contains("lowEntropy"), "unexpected error: {server_err}");
}

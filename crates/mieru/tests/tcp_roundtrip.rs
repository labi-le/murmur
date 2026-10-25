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

use murmur_mieru::client::{Client, ClientConfig, HandshakeMode, MultiplexLevel};
use murmur_mieru::io::ServerEndpoint;
use murmur_mieru::model::{AddrSpec, Response, CMD_CONNECT};
use murmur_mieru::server::Server;
use murmur_mieru::session::Transport;

const TIMEOUT: Duration = Duration::from_secs(10);

async fn read_exact_timeout<R: AsyncReadExt + Unpin>(r: &mut R, buf: &mut [u8]) {
    tokio::time::timeout(TIMEOUT, r.read_exact(buf)).await.expect("timed out reading").expect("read_exact failed");
}

#[tokio::test]
async fn tcp_client_server_connect_round_trip() {
    let mut users = HashMap::new();
    users.insert("alice".to_owned(), "s3cret-password".to_owned());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let bound = listener.local_addr().expect("bound addr");
    let server =
        Server::new(&users, vec![ServerEndpoint::Stream(Arc::new(listener))], false, None).expect("build server");

    let server_task = tokio::spawn(async move {
        let (mut stream, request) = server.accept().await.expect("accept");
        assert_eq!(request.command, CMD_CONNECT);
        assert_eq!(request.dst_addr.to_string(), "192.0.2.1:8080");

        Response::success().write_to(&mut stream).await.expect("write response");

        let mut buf = vec![0u8; 4096];
        read_exact_timeout(&mut stream, &mut buf).await;
        stream.write_all(&buf).await.expect("echo write");
        stream.flush().await.expect("flush");
        server
    });

    let client = Client::new(ClientConfig {
        server: bound.ip().to_string(),
        port_start: bound.port(),
        port_end: bound.port(),
        username: "alice".to_owned(),
        password: "s3cret-password".to_owned(),
        transport: Transport::Stream,
        multiplex: MultiplexLevel::Off,
        handshake_mode: HandshakeMode::Standard,
        traffic_pattern: None,
    });

    let ctx = CancellationToken::new();
    let dest = AddrSpec::Ip("192.0.2.1".parse().expect("ip"), 8080);
    let mut stream = client.dial_connect(&ctx, dest).await.expect("dial_connect").stream;

    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
    stream.write_all(&payload).await.expect("client write");
    stream.flush().await.expect("flush");

    let mut echoed = vec![0u8; payload.len()];
    read_exact_timeout(&mut stream, &mut echoed).await;
    assert_eq!(echoed, payload, "echoed bytes diverge from what was sent");

    let server = server_task.await.expect("server task panicked");
    client.close().await;
    server.close();
}

/// A rejected request must surface as a `Response` the client turns into an error, not as a
/// silently dead stream.
#[tokio::test]
async fn tcp_client_sees_nonzero_reply_code() {
    let mut users = HashMap::new();
    users.insert("alice".to_owned(), "s3cret-password".to_owned());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let bound = listener.local_addr().expect("bound addr");
    let server =
        Server::new(&users, vec![ServerEndpoint::Stream(Arc::new(listener))], false, None).expect("build server");

    let server_task = tokio::spawn(async move {
        let (mut stream, _request) = server.accept().await.expect("accept");
        Response { reply_code: 0x01, bind_addr: AddrSpec::Ip("0.0.0.0".parse().expect("ip"), 0) }
            .write_to(&mut stream)
            .await
            .expect("write response");
        server
    });

    let client = Client::new(ClientConfig {
        server: bound.ip().to_string(),
        port_start: bound.port(),
        port_end: bound.port(),
        username: "alice".to_owned(),
        password: "s3cret-password".to_owned(),
        transport: Transport::Stream,
        multiplex: MultiplexLevel::Off,
        handshake_mode: HandshakeMode::Standard,
        traffic_pattern: None,
    });

    let ctx = CancellationToken::new();
    let dest = AddrSpec::Ip("192.0.2.1".parse().expect("ip"), 8080);
    let Err(err) = client.dial_connect(&ctx, dest).await else { panic!("a nonzero reply code must fail the dial") };
    assert!(matches!(err, murmur_mieru::client::ClientError::Rejected(1)), "unexpected error: {err}");

    let server = server_task.await.expect("server task panicked");
    client.close().await;
    server.close();
}

/// the `HANDSHAKE_NO_WAIT`: the first write carries the request header and the caller's bytes in
/// one segment, so a server that answers only after reading application data still sees both.
#[tokio::test]
async fn tcp_no_wait_handshake_sends_request_with_first_write() {
    let mut users = HashMap::new();
    users.insert("alice".to_owned(), "s3cret-password".to_owned());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let bound = listener.local_addr().expect("bound addr");
    let server =
        Server::new(&users, vec![ServerEndpoint::Stream(Arc::new(listener))], false, None).expect("build server");

    let server_task = tokio::spawn(async move {
        let (mut stream, request) = server.accept().await.expect("accept");
        assert_eq!(request.command, CMD_CONNECT);
        Response::success().write_to(&mut stream).await.expect("write response");
        let mut buf = vec![0u8; 5];
        read_exact_timeout(&mut stream, &mut buf).await;
        assert_eq!(&buf, b"early", "the first application write must reach the server intact");
        server
    });

    let client = Client::new(ClientConfig {
        server: bound.ip().to_string(),
        port_start: bound.port(),
        port_end: bound.port(),
        username: "alice".to_owned(),
        password: "s3cret-password".to_owned(),
        transport: Transport::Stream,
        multiplex: MultiplexLevel::Off,
        handshake_mode: HandshakeMode::NoWait,
        traffic_pattern: None,
    });

    let ctx = CancellationToken::new();
    let dest = AddrSpec::Ip("192.0.2.1".parse().expect("ip"), 8080);
    let mut stream = client.dial_connect(&ctx, dest).await.expect("dial_connect").stream;
    stream.write_all(b"early").await.expect("client write");
    stream.flush().await.expect("flush");

    let server = server_task.await.expect("server task panicked");
    client.close().await;
    server.close();
}

/// The accepted session must report the peer facts an inbound builds its metadata from.
#[tokio::test]
async fn accepted_session_reports_authenticated_user_and_addresses() {
    let mut users = HashMap::new();
    users.insert("alice".to_owned(), "s3cret-password".to_owned());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let bound: SocketAddr = listener.local_addr().expect("bound addr");
    let server =
        Server::new(&users, vec![ServerEndpoint::Stream(Arc::new(listener))], false, None).expect("build server");

    let server_task = tokio::spawn(async move {
        let (mut stream, _request) = server.accept().await.expect("accept");
        Response::success().write_to(&mut stream).await.expect("write response");
        let session = stream.session();
        assert_eq!(session.user_name(), Some("alice"), "the session must report the user it authenticated as");
        assert_eq!(session.local_addr(), Some(bound), "the session must report the listener's address");
        assert!(
            session.peer_addr().is_some_and(|addr| addr.ip().is_loopback()),
            "the session must report the client's address"
        );
        server
    });

    let client = Client::new(ClientConfig {
        server: bound.ip().to_string(),
        port_start: bound.port(),
        port_end: bound.port(),
        username: "alice".to_owned(),
        password: "s3cret-password".to_owned(),
        transport: Transport::Stream,
        multiplex: MultiplexLevel::Off,
        handshake_mode: HandshakeMode::Standard,
        traffic_pattern: None,
    });

    let ctx = CancellationToken::new();
    let dest = AddrSpec::Ip("192.0.2.1".parse().expect("ip"), 8080);
    let _stream = client.dial_connect(&ctx, dest).await.expect("dial_connect");

    let server = server_task.await.expect("server task panicked");
    client.close().await;
    server.close();
}

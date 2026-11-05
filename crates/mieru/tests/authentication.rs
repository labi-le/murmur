//! The credential a client hands its mux must be the hashed one: the password is hashed before
//! it reaches the mux, and the server derives every key from that same hash.
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
use murmur_mieru::io::{ServerEndpoint, SystemDialer};
use murmur_mieru::model::{AddrSpec, Request, Response, CMD_CONNECT};
use murmur_mieru::mux::ClientMux;
use murmur_mieru::server::Server;
use murmur_mieru::session::{SessionStream, Transport};

const TIMEOUT: Duration = Duration::from_secs(10);
const USER: &str = "alice";
const PASSWORD: &str = "s3cret-password";

fn destination() -> AddrSpec {
    AddrSpec::Ip("192.0.2.1".parse().expect("ip"), 8080)
}

async fn start_server() -> (Server, SocketAddr) {
    let mut users = HashMap::new();
    users.insert(USER.to_owned(), PASSWORD.to_owned());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let bound = listener.local_addr().expect("bound addr");
    let server =
        Server::new(&users, vec![ServerEndpoint::Stream(Arc::new(listener))], false, None).expect("build server");
    (server, bound)
}

/// The configured password is hashed with the user name before it reaches the mux, so the client
/// the proxy builds authenticates, the server accepts the session as that user, and the bytes
/// both sides write travel in order.
#[tokio::test]
async fn a_configured_password_authenticates_the_client() {
    for handshake_mode in [HandshakeMode::Standard, HandshakeMode::NoWait] {
        let (server, bound) = start_server().await;
        let server_task = tokio::spawn(async move {
            let (mut stream, request) = server.accept().await.expect("accept");
            assert_eq!(request.dst_addr, destination());
            Response::success().write_to(&mut stream).await.expect("write the response");
            let mut seen = [0u8; 4];
            stream.read_exact(&mut seen).await.expect("read the client's bytes");
            (server, stream.session().user_name().map(str::to_owned), seen)
        });

        let client = Client::new(ClientConfig {
            server: bound.ip().to_string(),
            port_start: bound.port(),
            port_end: bound.port(),
            username: USER.to_owned(),
            password: PASSWORD.to_owned(),
            transport: Transport::Stream,
            multiplex: MultiplexLevel::Off,
            handshake_mode,
            traffic_pattern: None,
        });
        let mut stream = tokio::time::timeout(TIMEOUT, client.dial_connect(&CancellationToken::new(), destination()))
            .await
            .unwrap_or_else(|_| panic!("the {handshake_mode:?} handshake must not hang"))
            .expect("dial_connect")
            .stream;

        stream.write_all(b"ping").await.expect("client write");
        stream.flush().await.expect("client flush");
        let (server, user_name, seen) = tokio::time::timeout(TIMEOUT, server_task)
            .await
            .unwrap_or_else(|_| panic!("the server must accept the {handshake_mode:?} session"))
            .expect("server task panicked");
        assert_eq!(user_name.as_deref(), Some(USER), "the session must report the user the client authenticated as");
        assert_eq!(seen, *b"ping", "the application bytes must arrive intact and in order");

        client.close().await;
        server.close();
    }
}

/// The mux is the seam the `SetClientUserNamePassword` sits on, and it only accepts the hashed
/// secret. A raw password there cannot be authenticated, and the client has to learn that within
/// a bound rather than wait for a response nobody will send.
#[tokio::test]
async fn a_raw_password_cannot_authenticate() {
    let (server, bound) = start_server().await;
    let mux = ClientMux::new(
        bound.ip().to_string(),
        vec![bound.port()],
        PASSWORD.as_bytes().to_vec(),
        USER.to_owned(),
        Transport::Stream,
        0,
        Arc::new(SystemDialer),
        None,
    );

    let session = tokio::time::timeout(TIMEOUT, mux.dial(&CancellationToken::new()))
        .await
        .expect("the dial must not hang")
        .expect("dial");
    let request = Request { command: CMD_CONNECT, dst_addr: destination() };
    session.write(&request.encode()).await.expect("the request must reach the underlay");
    let mut stream = SessionStream::new(session);

    let response = tokio::time::timeout(TIMEOUT, Response::read_from(&mut stream)).await;
    assert!(
        matches!(response, Ok(Err(_))),
        "an unauthenticated client must be answered with an error, got {response:?}"
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(500), server.accept()).await.is_err(),
        "the server must not create a session for a raw password"
    );
    server.close();
}

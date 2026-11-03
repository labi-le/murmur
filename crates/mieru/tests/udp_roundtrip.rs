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

use tokio_util::sync::CancellationToken;

use murmur_mieru::client::{Client, ClientConfig, HandshakeMode, MultiplexLevel};
use murmur_mieru::io::ServerEndpoint;
use murmur_mieru::model::{AddrSpec, Response, UdpAssociateWrapper, CMD_UDP_ASSOCIATE};
use murmur_mieru::server::Server;
use murmur_mieru::session::Transport;

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn udp_client_server_associate_round_trip_with_fragmentation() {
    let mut users = HashMap::new();
    users.insert("bob".to_owned(), "another-secret".to_owned());

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
    let bound = socket.local_addr().expect("bound addr");
    let server =
        Server::new(&users, vec![ServerEndpoint::Packet(Arc::new(socket))], false, None).expect("build server");

    let server_task = tokio::spawn(async move {
        let (mut stream, request) = server.accept().await.expect("accept");
        assert_eq!(request.command, CMD_UDP_ASSOCIATE);

        Response::success().write_to(&mut stream).await.expect("write response");
        let mut relay = UdpAssociateWrapper::new(stream);

        for _ in 0..3 {
            let (payload, from) =
                tokio::time::timeout(TIMEOUT, relay.recv_from()).await.expect("timeout").expect("recv_from");
            tokio::time::timeout(TIMEOUT, relay.send_to(&payload, &from)).await.expect("timeout").expect("send_to");
        }
        server
    });

    let client = Client::new(ClientConfig {
        server: bound.ip().to_string(),
        port_start: bound.port(),
        port_end: bound.port(),
        username: "bob".to_owned(),
        password: "another-secret".to_owned(),
        transport: Transport::Packet,
        multiplex: MultiplexLevel::Off,
        handshake_mode: HandshakeMode::Standard,
        traffic_pattern: None,
    });

    let ctx = CancellationToken::new();
    let dest = AddrSpec::Ip("198.51.100.9".parse().expect("ip"), 53);
    let stream = client.dial_udp_associate(&ctx, dest.clone()).await.expect("dial_udp_associate").stream;
    let mut relay = UdpAssociateWrapper::new(stream);

    let small = b"dns-query".to_vec();
    let medium = vec![0xABu8; 900];
    let large = (0..3000u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>();

    for packet in [&small, &medium, &large] {
        tokio::time::timeout(TIMEOUT, relay.send_to(packet, &dest)).await.expect("timeout").expect("send_to");
        let (got, from) = tokio::time::timeout(TIMEOUT, relay.recv_from()).await.expect("timeout").expect("recv_from");
        assert_eq!(&got, packet, "echoed UDP packet diverges from what was sent");
        assert_eq!(from, dest, "echoed packet's source address diverges");
    }

    let server = server_task.await.expect("server task panicked");
    client.close().await;
    server.close();
}

/// A packet underlay reuses one socket for many sessions, so a second session must reach the
/// server and get its own session id rather than being mistaken for the first one's traffic.
#[tokio::test]
async fn udp_two_sessions_share_one_underlay() {
    let mut users = HashMap::new();
    users.insert("bob".to_owned(), "another-secret".to_owned());

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
    let bound = socket.local_addr().expect("bound addr");
    let server =
        Server::new(&users, vec![ServerEndpoint::Packet(Arc::new(socket))], false, None).expect("build server");

    let server_task = tokio::spawn(async move {
        for expected in 0..2u16 {
            let (mut stream, request) = server.accept().await.expect("accept");
            assert_eq!(request.command, CMD_UDP_ASSOCIATE);
            assert_eq!(request.dst_addr.port(), 1000 + expected, "each session must carry its own destination");
            let dest = request.dst_addr.clone();
            Response::success().write_to(&mut stream).await.expect("write response");
            let mut relay = UdpAssociateWrapper::new(stream);
            let (payload, _from) =
                tokio::time::timeout(TIMEOUT, relay.recv_from()).await.expect("timeout").expect("recv_from");
            assert_eq!(payload, vec![expected as u8; 4], "a session must not receive another session's payload");
            relay.send_to(&payload, &dest).await.expect("send_to");
        }
        server
    });

    let client = Client::new(ClientConfig {
        server: bound.ip().to_string(),
        port_start: bound.port(),
        port_end: bound.port(),
        username: "bob".to_owned(),
        password: "another-secret".to_owned(),
        transport: Transport::Packet,
        multiplex: MultiplexLevel::High,
        handshake_mode: HandshakeMode::Standard,
        traffic_pattern: None,
    });

    for expected in 0..2u16 {
        let ctx = CancellationToken::new();
        let dest = AddrSpec::Ip("198.51.100.9".parse().expect("ip"), 1000 + expected);
        let stream = client.dial_udp_associate(&ctx, dest.clone()).await.expect("dial_udp_associate").stream;
        let mut relay = UdpAssociateWrapper::new(stream);
        relay.send_to(&[expected as u8; 4], &dest).await.expect("send_to");
        let (got, _) = tokio::time::timeout(TIMEOUT, relay.recv_from()).await.expect("timeout").expect("recv_from");
        assert_eq!(got, vec![expected as u8; 4]);
    }

    let server = server_task.await.expect("server task panicked");
    client.close().await;
    server.close();
}

/// The accepted packet session reports the datagram's source address as its peer, which is how a
/// UDP-associate inbound addresses replies.
#[tokio::test]
async fn udp_accepted_session_reports_user_and_datagram_source() {
    let mut users = HashMap::new();
    users.insert("bob".to_owned(), "another-secret".to_owned());

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
    let bound: SocketAddr = socket.local_addr().expect("bound addr");
    let server =
        Server::new(&users, vec![ServerEndpoint::Packet(Arc::new(socket))], false, None).expect("build server");

    let server_task = tokio::spawn(async move {
        let (mut stream, _request) = server.accept().await.expect("accept");
        Response::success().write_to(&mut stream).await.expect("write response");
        let session = stream.session();
        assert_eq!(session.user_name(), Some("bob"), "the session must report the user it authenticated as");
        assert_eq!(session.local_addr(), Some(bound), "the session must report the socket's address");
        assert!(
            session.peer_addr().is_some_and(|addr| addr.ip().is_loopback()),
            "the session must report the client's datagram source"
        );
        server
    });

    let client = Client::new(ClientConfig {
        server: bound.ip().to_string(),
        port_start: bound.port(),
        port_end: bound.port(),
        username: "bob".to_owned(),
        password: "another-secret".to_owned(),
        transport: Transport::Packet,
        multiplex: MultiplexLevel::Off,
        handshake_mode: HandshakeMode::Standard,
        traffic_pattern: None,
    });

    let ctx = CancellationToken::new();
    let dest = AddrSpec::Ip("198.51.100.9".parse().expect("ip"), 53);
    let _stream = client.dial_udp_associate(&ctx, dest).await.expect("dial_udp_associate").stream;

    let server = server_task.await.expect("server task panicked");
    client.close().await;
    server.close();
}

//! End-to-end tests for the JLS client/server port.
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

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::StreamAsOldConn;
use murmur_jls_tls::JlsUser;
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport_jls::client::{new_client, new_client_config};
use murmur_transport_jls::server::{
    new_server_config, server, user_from_conn, DialContextFn, FallbackCompleted, ServerConfig,
};

const USERNAME: &str = "alice";
const PASSWORD: &str = "s3cret";
const SNI: &str = "example.com";
const PAYLOAD: &[u8] = b"jls round trip payload";

fn users() -> Vec<JlsUser> {
    vec![JlsUser { username: USERNAME.to_owned(), password: PASSWORD.to_owned() }]
}

fn unused_dial() -> DialContextFn {
    Arc::new(|_ctx, _network, _address| Box::pin(async { Err(anyhow!("unused dial")) }))
}

fn server_config(dest: &str) -> Arc<ServerConfig> {
    Arc::new(new_server_config(SNI, dest, &users(), None, 0, unused_dial()).expect("build a jls server config"))
}

/// A camouflage relay has to dial `dest` for real, which `server_config` never does.
fn camouflage_server_config(dest: &str) -> Arc<ServerConfig> {
    let dial: DialContextFn = Arc::new(|_ctx, _network, address| {
        Box::pin(async move {
            let stream = TcpStream::connect(address).await?;
            let conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(stream));
            Ok(conn)
        })
    });
    Arc::new(new_server_config(SNI, dest, &users(), None, 0, dial).expect("build a jls camouflage server config"))
}

/// Accepts one connection, completes the JLS handshake, and echoes one payload
/// back when `echo` is set. Returns the username the handshake authenticated,
/// or `None` when the handshake did not complete.
async fn serve_one(listener: TcpListener, config: Arc<ServerConfig>, echo: bool) -> std::io::Result<Option<String>> {
    let (stream, _) = listener.accept().await?;
    let inbound: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(stream));
    let Ok(mut conn) = server(&CancellationToken::new(), inbound, &config).await else {
        return Ok(None);
    };
    let user = user_from_conn(&*conn);
    if echo {
        let mut received = vec![0u8; PAYLOAD.len()];
        conn.read_exact(&mut received).await?;
        conn.write_all(&received).await?;
    }
    Ok(user)
}

#[tokio::test]
async fn jls_client_and_server_exchange_data_and_report_the_user() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let server_task = tokio::spawn(serve_one(listener, server_config(&addr.to_string()), true));

    let raw = TcpStream::connect(addr).await.expect("connect");
    let client_config = new_client_config(SNI, USERNAME, PASSWORD, None).expect("client config");
    let mut conn = new_client(&CancellationToken::new(), Box::new(StreamAsOldConn::new(raw)), &client_config)
        .await
        .expect("jls client handshake");

    conn.write_all(PAYLOAD).await.expect("client write");
    let mut echoed = vec![0u8; PAYLOAD.len()];
    conn.read_exact(&mut echoed).await.expect("client read echo");
    assert_eq!(&echoed, PAYLOAD);

    let user = server_task.await.expect("server task").expect("server accept");
    assert_eq!(user.as_deref(), Some(USERNAME));
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let server_task = tokio::spawn(serve_one(listener, server_config(&addr.to_string()), false));

    let raw = TcpStream::connect(addr).await.expect("connect");
    let client_config = new_client_config(SNI, USERNAME, "wrong-password", None).expect("client config");
    let result = new_client(&CancellationToken::new(), Box::new(StreamAsOldConn::new(raw)), &client_config).await;
    assert!(result.is_err(), "a wrong password must not authenticate");

    let user = server_task.await.expect("server task").expect("server accept");
    assert!(user.is_none(), "the server must not report a user for a rejected client");
}

/// A probe that is not a JLS `ClientHello` (an ordinary HTTP request) must be
/// replayed verbatim to the camouflage destination, and the connection reported
/// as relayed to the fallback.
#[tokio::test]
async fn a_non_jls_probe_is_relayed_to_the_camouflage_destination() {
    const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: example.com\r\n";

    tokio::time::timeout(Duration::from_secs(30), async {
        let upstream = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream addr").to_string();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("upstream accept");
            let mut buf = vec![0u8; REQUEST.len()];
            stream.read_exact(&mut buf).await.expect("upstream read");
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.expect("upstream write");
            buf
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let config = camouflage_server_config(&upstream_addr);

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let inbound: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(stream));
            server(&CancellationToken::new(), inbound, &config).await
        });

        let mut probe = TcpStream::connect(addr).await.expect("connect");
        probe.write_all(REQUEST).await.expect("write probe");
        let mut response = [0u8; 19];
        probe.read_exact(&mut response).await.expect("read response");
        assert_eq!(&response, b"HTTP/1.1 200 OK\r\n\r\n");

        // As in the `Relay`, the fallback call returns only once both directions
        // have closed, so the finished probe has to let go of its half first.
        drop(probe);

        let relayed = upstream_task.await.expect("upstream task");
        assert_eq!(&relayed, REQUEST, "the camouflage relay must replay the probe verbatim");

        let err = server_task.await.expect("server task").err().expect("server must report an error");
        assert!(err.downcast_ref::<FallbackCompleted>().is_some(), "server error = {err}, want FallbackCompleted");
    })
    .await
    .expect("the camouflage relay must complete");
}

/// A probe whose record header declares a body longer than the probe itself must
/// fail the handshake rather than wait for it, or the fallback is never reached.
#[tokio::test]
async fn a_non_tls_probe_does_not_wait_for_its_declared_record_body() {
    const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: example.com\r\n";

    tokio::time::timeout(Duration::from_secs(30), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let config = server_config(&addr.to_string());

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let inbound: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(stream));
            server(&CancellationToken::new(), inbound, &config).await
        });

        let mut probe = TcpStream::connect(addr).await.expect("connect");
        probe.write_all(REQUEST).await.expect("write probe");

        let result = server_task.await.expect("server task");
        assert!(result.is_err(), "a non-TLS probe must not be served as a JLS connection");
    })
    .await
    .expect("the handshake must not block on the probe's declared record length");
}

/// the first-record guard rejects a header that cannot open a handshake whatever
/// its type, so a probe that opens with `ChangeCipherSpec` and a body it never
/// sends must fail the handshake rather than wait for it.
#[tokio::test]
async fn a_leading_change_cipher_spec_probe_does_not_wait_for_its_declared_record_body() {
    const PROBE: &[u8] = &[0x14, 0x03, 0x03, 0xff, 0xff];

    tokio::time::timeout(Duration::from_secs(30), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let config = server_config(&addr.to_string());

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let inbound: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(stream));
            server(&CancellationToken::new(), inbound, &config).await
        });

        let mut probe = TcpStream::connect(addr).await.expect("connect");
        probe.write_all(PROBE).await.expect("write probe");

        let result = server_task.await.expect("server task");
        assert!(result.is_err(), "a ChangeCipherSpec probe must not be served as a JLS connection");
    })
    .await
    .expect("the handshake must not block on the probe's declared record length");
}

/// A record whose declared body exceeds its ciphertext caps is refused before it is read,
/// so a probe that declares one and never sends it must be refused rather than wait.
#[tokio::test]
async fn an_oversized_declared_record_body_does_not_wait_to_be_read() {
    const PROBE: &[u8] = &[0x16, 0x03, 0x01, 0xff, 0xff];

    tokio::time::timeout(Duration::from_secs(30), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let config = server_config(&addr.to_string());

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let inbound: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(stream));
            server(&CancellationToken::new(), inbound, &config).await
        });

        let mut probe = TcpStream::connect(addr).await.expect("connect");
        probe.write_all(PROBE).await.expect("write probe");

        let result = server_task.await.expect("server task");
        assert!(result.is_err(), "an oversized record body must not be served as a JLS connection");
    })
    .await
    .expect("the handshake must not block on the probe's declared record length");
}

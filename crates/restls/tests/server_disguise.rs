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

use murmur_restls::{restls_server, ServerConfig};
use murmur_std_compat::net::Conn as NetConn;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(15);
const PASSWORD: &str = "restls-disguise-password";

/// A probe that is not a Restls client is relayed byte for byte to the disguise target, prefix
/// included, and the server reports an error once the client goes away.
#[tokio::test]
async fn non_tls_probe_reaches_disguise_target_without_losing_prefix() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound_addr = listener.local_addr().unwrap();
    let config = ServerConfig {
        server_hostname: target_addr.to_string(),
        password: PASSWORD.to_owned(),
        restls_script: String::new(),
        min_record_len: 0,
        rate_limit: 0,
        dial: Arc::new(|address| {
            Box::pin(async move {
                let stream = TcpStream::connect(address).await?;
                let conn: Box<dyn NetConn> = Box::new(stream);
                Ok(conn)
            })
        }),
    };
    let server = tokio::spawn(async move {
        let (inbound, _) = listener.accept().await?;
        restls_server(Box::new(inbound), &config).await.map(|_| ())
    });
    let target_task = tokio::spawn(async move {
        let (mut conn, _) = target.accept().await?;
        let request = b"GET / HTTP/1.1\r\nHost: disguise\r\n\r\n";
        let mut received = vec![0; request.len()];
        conn.read_exact(&mut received).await?;
        assert_eq!(received, request);
        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong").await?;
        Ok::<_, anyhow::Error>(())
    });
    let mut client = TcpStream::connect(inbound_addr).await.unwrap();
    timeout(DEADLINE, async {
        client.write_all(b"GET / HTTP/1.1\r\nHost: disguise\r\n\r\n").await?;
        let mut response = vec![0; b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong".len()];
        client.read_exact(&mut response).await?;
        assert_eq!(response, b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong");
        Ok::<_, std::io::Error>(())
    })
    .await
    .expect("non-TLS probe stalled")
    .expect("non-TLS probe failed");
    drop(client);
    timeout(DEADLINE, target_task).await.unwrap().unwrap().unwrap();
    assert!(timeout(DEADLINE, server).await.unwrap().unwrap().is_err());
}

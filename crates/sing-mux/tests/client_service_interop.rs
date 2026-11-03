//! Proves the outbound `smux` option path (`client::Client`) and the listener `MuxService` path
//! (`server::Service`) interoperate over one carrier, for every protocol the option accepts and
//! with padding on and off, since padding moves the protocol header inside the padded frames.
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

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use murmur_sing::metadata::Socksaddr;
use murmur_sing::network::PacketConn;
use murmur_sing_mux::client::{new_client, BrutalOptions, Dialed, Dialer, Options};
use murmur_sing_mux::protocol::{PROTOCOL_H2MUX, PROTOCOL_SMUX, PROTOCOL_YAMUX};
use murmur_sing_mux::server::{new_service, Metadata, Service, ServiceHandler, ServiceOptions};
use murmur_sing_mux::session::MuxConn;

/// Hands out the one carrier it was built with and then refuses, so a test that asks for a second
/// carrier fails loudly instead of silently opening one.
struct OneShotDialer(Mutex<Option<Box<dyn MuxConn>>>);

#[async_trait]
impl Dialer for OneShotDialer {
    async fn dial_context(&self, _ctx: &CancellationToken, _destination: &Socksaddr) -> std::io::Result<Dialed> {
        let conn = self.0.lock().take().ok_or_else(|| std::io::Error::other("mux client dialled a second carrier"))?;
        Ok(Dialed { conn, socket: 0 })
    }
}

struct EchoHandler;

#[async_trait]
impl ServiceHandler for EchoHandler {
    async fn new_connection(&self, mut conn: Box<dyn MuxConn>, _metadata: Metadata) -> anyhow::Result<()> {
        let mut buf = vec![0u8; 4096];
        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            conn.write_all(&buf[..n]).await?;
        }
    }

    async fn new_packet_connection(&self, _conn: Box<dyn PacketConn>, _metadata: Metadata) -> anyhow::Result<()> {
        anyhow::bail!("packet streams are not exercised here")
    }
}

async fn round_trip_once(client: &murmur_sing_mux::client::Client, payload: &[u8]) {
    let mut conn = client
        .dial_context(&CancellationToken::new(), "tcp", Socksaddr::fqdn("example.com", 443))
        .await
        .expect("open a mux stream");
    conn.write_all(payload).await.expect("write request");
    let mut reply = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut reply))
        .await
        .expect("echo within 5s")
        .expect("read echo");
    assert_eq!(reply, payload);
}

async fn interop(protocol: u8, padding: bool) {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let dialer = Arc::new(OneShotDialer(Mutex::new(Some(Box::new(client_io)))));

    let client = new_client(Options {
        dialer,
        protocol,
        max_connections: 0,
        min_streams: 0,
        max_streams: 8,
        padding,
        tcp_timeout: Duration::from_secs(5),
        brutal: BrutalOptions::default(),
    })
    .expect("client options");

    let service: Service =
        new_service(ServiceOptions { padding, brutal: BrutalOptions::default() }).expect("service options");
    let server_task = tokio::spawn(async move {
        let _ = service
            .new_connection(
                &EchoHandler,
                Box::new(server_io),
                0,
                Metadata {
                    protocol: "test".to_owned(),
                    source: Socksaddr::default(),
                    destination: Socksaddr::default(),
                },
            )
            .await;
    });

    round_trip_once(&client, b"ping").await;
    // The one-shot dialer rejects a redial, so reaching the same service again proves the second
    // stream was multiplexed onto the pooled session.
    round_trip_once(&client, b"a longer payload spanning several mux frames").await;

    client.close().await.expect("client close");
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("service unwinds within 5s")
        .expect("service task");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smux_round_trips_unpadded() {
    interop(PROTOCOL_SMUX, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smux_round_trips_padded() {
    interop(PROTOCOL_SMUX, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yamux_round_trips_unpadded() {
    interop(PROTOCOL_YAMUX, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yamux_round_trips_padded() {
    interop(PROTOCOL_YAMUX, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2mux_round_trips_unpadded() {
    interop(PROTOCOL_H2MUX, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2mux_round_trips_padded() {
    interop(PROTOCOL_H2MUX, true).await;
}

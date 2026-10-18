//! Drives `dial_context` for an encryption-only XTLS Vision outbound against this workspace's own
//! VLESS encryption server, so the dial path is exercised end to end rather than only asserted at
//! construction: the encryption handshake runs, Vision pads the first frame, and the VLESS request
//! and payload follow inside it.
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

use std::time::Duration;

use murmur_adapter_outbound::vless::{Vless, VlessOption};
use murmur_constant::adapters::ProxyAdapter;
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_transport_vless::encryption::factory::new_server;
use murmur_transport_vless::encryption::key::{gen_mlkem768, gen_x25519};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const UUID: [u8; 16] = [0x11; 16];
const PAYLOAD: &[u8] = b"encryption-only-vision";
const DEST_HOST: &str = "example.com";
const DEST_PORT: u16 = 443;
const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn an_encryption_only_vision_dial_reaches_padding_only_vision() {
    let (seed, client, _) = gen_mlkem768("").expect("gen_mlkem768");
    let (private_key, password, _) = gen_x25519("").expect("gen_x25519");
    let decryption = format!("mlkem768x25519plus.native.600s.{private_key}.{seed}");
    let encryption = format!("mlkem768x25519plus.native.0rtt.{password}.{client}");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let server = new_server(&decryption).expect("server config").expect("server instance");
        let mut conn = server.handshake(Box::new(stream), None).await.expect("encryption handshake");

        // The VLESS request is written before the Vision stream pads the payload, matching the
        // reference's request-then-Vision order.
        let mut request = [0u8; 17];
        conn.read_exact(&mut request).await.expect("vless request prefix");
        assert_eq!(request[0], 0, "VLESS version");
        assert_eq!(&request[1..17], UUID, "VLESS request UUID");

        let mut addon_len = [0u8; 1];
        conn.read_exact(&mut addon_len).await.expect("addon length");
        let mut addons = vec![0u8; usize::from(addon_len[0])];
        conn.read_exact(&mut addons).await.expect("addons");
        assert!(addons.ends_with(b"xtls-rprx-vision"), "flow is sent in the addons");

        let mut command = [0u8; 3];
        conn.read_exact(&mut command).await.expect("command and port");
        assert_eq!(command[0], 1, "VLESS COMMAND_TCP");
        assert_eq!(u16::from_be_bytes([command[1], command[2]]), DEST_PORT);

        let mut address = [0u8; 2];
        conn.read_exact(&mut address).await.expect("address head");
        assert_eq!(address[0], 2, "ATYP_DOMAIN_NAME");
        let mut host = vec![0u8; usize::from(address[1])];
        conn.read_exact(&mut host).await.expect("address");
        assert_eq!(host, DEST_HOST.as_bytes());

        // The first payload write is a Vision frame: a UUID header, then the payload.
        let mut head = [0u8; 21];
        conn.read_exact(&mut head).await.expect("vision header");
        assert_eq!(&head[..16], UUID, "the first frame carries the user UUID");
        assert_eq!(head[16], 0, "padding continues while the stream is filtered");
        let content_len = usize::from(u16::from_be_bytes([head[17], head[18]]));
        let padding_len = usize::from(u16::from_be_bytes([head[19], head[20]]));
        let mut body = vec![0u8; content_len + padding_len];
        conn.read_exact(&mut body).await.expect("vision body");
        assert_eq!(&body[..content_len], PAYLOAD, "payload rides inside the padded frame");
    });

    let vless = Vless::new(VlessOption {
        name: "vision-encrypted".to_owned(),
        server: "127.0.0.1".to_owned(),
        port: addr.port(),
        uuid: "11111111-1111-1111-1111-111111111111".to_owned(),
        flow: "xtls-rprx-vision".to_owned(),
        encryption,
        ..Default::default()
    })
    .expect("encryption-only vision config");

    let mut metadata =
        Metadata { network: NetWork::TCP, host: DEST_HOST.to_owned(), dst_port: DEST_PORT, ..Default::default() };
    let mut conn = tokio::time::timeout(TIMEOUT, vless.dial_context(&CancellationToken::new(), &mut metadata))
        .await
        .expect("the encryption-only Vision dial must not hang")
        .expect("encryption-only Vision dial");
    conn.write_all(PAYLOAD).await.expect("payload write");
    conn.flush().await.expect("payload flush");

    server.await.expect("server task");
}

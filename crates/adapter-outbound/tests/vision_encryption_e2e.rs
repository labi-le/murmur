//! Drives `dial_context` for encryption-only and TLS-plus-encryption XTLS Vision outbounds
//! against this workspace's own VLESS encryption server, so the dial path is exercised end to end
//! rather than only asserted at construction: the handshake runs, Vision pads the payload, and the
//! VLESS request precedes it.
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

use murmur_adapter_outbound::vless::{Vless, VlessOption};
use murmur_component_tls::utls;
use murmur_constant::adapters::{Conn as CConn, ProxyAdapter};
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_testsupport::TLS_CONFIG;
use murmur_transport_vless::encryption::common::CommonConn;
use murmur_transport_vless::encryption::factory::new_server;
use murmur_transport_vless::encryption::key::{gen_mlkem768, gen_x25519};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const UUID: [u8; 16] = [0x11; 16];
const PAYLOAD: &[u8] = b"encryption-only-vision";
const RAW_DOWNLINK: &[u8] = b"downlink-raw";
const DEST_HOST: &str = "example.com";
const DEST_PORT: u16 = 443;
const TIMEOUT: Duration = Duration::from_secs(10);

fn key_material() -> (String, String) {
    let (seed, client, _) = gen_mlkem768("").expect("gen_mlkem768");
    let (private_key, password, _) = gen_x25519("").expect("gen_x25519");
    (
        format!("mlkem768x25519plus.native.600s.{private_key}.{seed}"),
        format!("mlkem768x25519plus.native.0rtt.{password}.{client}"),
    )
}

fn adapter(port: u16, encryption: String, tls: bool) -> Arc<Vless> {
    Vless::new(VlessOption {
        name: "vision-encrypted".to_owned(),
        server: "127.0.0.1".to_owned(),
        port,
        uuid: "11111111-1111-1111-1111-111111111111".to_owned(),
        flow: "xtls-rprx-vision".to_owned(),
        tls,
        skip_cert_verify: true,
        encryption,
        ..Default::default()
    })
    .expect("encryption Vision config")
}

async fn dial(vless: &Arc<Vless>) -> Box<dyn CConn> {
    let mut metadata =
        Metadata { network: NetWork::TCP, host: DEST_HOST.to_owned(), dst_port: DEST_PORT, ..Default::default() };
    tokio::time::timeout(TIMEOUT, vless.dial_context(&CancellationToken::new(), &mut metadata))
        .await
        .expect("the Vision dial must not hang")
        .expect("Vision dial")
}

/// The VLESS request is written before the Vision stream pads the payload, matching the
/// reference's request-then-Vision order. The reply then sends the VLESS response header, a
/// Vision DIRECT command, and raw bytes from beneath the encryption layer.
async fn assert_request_then_padded_payload(conn: &mut CommonConn) {
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

    let mut head = [0u8; 21];
    conn.read_exact(&mut head).await.expect("vision header");
    assert_eq!(&head[..16], UUID, "the first frame carries the user UUID");
    assert_eq!(head[16], 0, "padding continues while the stream is filtered");
    let content_len = usize::from(u16::from_be_bytes([head[17], head[18]]));
    let padding_len = usize::from(u16::from_be_bytes([head[19], head[20]]));
    let mut body = vec![0u8; content_len + padding_len];
    conn.read_exact(&mut body).await.expect("vision body");
    assert_eq!(&body[..content_len], PAYLOAD, "payload rides inside the padded frame");

    conn.write_all(&[0u8, 0u8]).await.expect("vless response header");
    let mut direct = Vec::with_capacity(21);
    direct.extend_from_slice(&UUID);
    direct.push(2); // COMMAND_PADDING_DIRECT
    direct.extend_from_slice(&0u16.to_be_bytes());
    direct.extend_from_slice(&0u16.to_be_bytes());
    conn.write_all(&direct).await.expect("vision direct frame");
    conn.flush().await.expect("vision direct flush");
    conn.conn.write_all(RAW_DOWNLINK).await.expect("raw downlink write");
    conn.conn.flush().await.expect("raw downlink flush");
}

async fn assert_direct_downlink(conn: &mut (impl AsyncRead + Unpin)) {
    let mut downlink = [0u8; RAW_DOWNLINK.len()];
    tokio::time::timeout(TIMEOUT, conn.read_exact(&mut downlink))
        .await
        .expect("downlink read timed out")
        .expect("downlink read");
    assert_eq!(&downlink, RAW_DOWNLINK, "DIRECT bytes come from beneath the encryption layer");
}

/// A server config capped at TLS 1.2, so the client's Vision check would see a non-1.3 session.
fn tls12_server_config() -> Arc<utls::Config> {
    Arc::new(utls::Config {
        time: TLS_CONFIG.time.clone(),
        certificates: TLS_CONFIG.certificates.clone(),
        next_protos: TLS_CONFIG.next_protos.clone(),
        session_tickets_disabled: TLS_CONFIG.session_tickets_disabled,
        max_version: utls::VERSION_TLS12,
        ..Default::default()
    })
}

#[tokio::test]
async fn an_encryption_only_vision_dial_reaches_padding_only_vision() {
    let (decryption, encryption) = key_material();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let server = new_server(&decryption).expect("server config").expect("server instance");
        let mut conn = server.handshake(Box::new(stream), None).await.expect("encryption handshake");
        assert_request_then_padded_payload(&mut conn).await;
    });

    let vless = adapter(addr.port(), encryption, false);
    let mut conn = dial(&vless).await;
    conn.write_all(PAYLOAD).await.expect("payload write");
    conn.flush().await.expect("payload flush");
    assert_direct_downlink(&mut conn).await;

    server.await.expect("server task");
}

/// Encryption wraps the TLS session, so Vision must pad the encryption conn instead of rejecting
/// a TLS 1.2 session as non-TLS-1.3 or keeping the TLS raw-transport handoff.
#[tokio::test]
async fn a_tls12_encryption_dial_reaches_padding_only_vision() {
    let (decryption, encryption) = key_material();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("listener address");

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let tls_conn = utls::server(Box::new(stream), tls12_server_config());
        tls_conn.handshake().await.expect("TLS 1.2 handshake");
        let server = new_server(&decryption).expect("server config").expect("server instance");
        let mut conn = server.handshake(Box::new(tls_conn), None).await.expect("encryption handshake");
        assert_request_then_padded_payload(&mut conn).await;
    });

    let vless = adapter(addr.port(), encryption, true);
    let mut conn = dial(&vless).await;
    conn.write_all(PAYLOAD).await.expect("payload write");
    conn.flush().await.expect("payload flush");
    assert_direct_downlink(&mut conn).await;

    server.await.expect("server task");
}

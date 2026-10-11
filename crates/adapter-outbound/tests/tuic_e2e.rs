//! Adapter-level round trips for `Tuic` against a real loopback `murmur_transport_tuic` server:
//! the native datagram path, the QUIC (uni-stream) datagram path, UDP-over-stream v1/v2 and the
//! TUIC v4 token handshake.
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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use murmur_adapter_outbound::tuic::{Tuic, TuicOption};
use murmur_component_ca as ca;
use murmur_component_ca::keypair::{new_random_tls_key_pair, KeyPairType};
use murmur_component_tls::utls as tls_c;
use murmur_constant::adapters::{PacketConn as CPacketConn, ProxyAdapter as CProxyAdapter};
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_sing::uot;
use murmur_std_compat::net::{PacketConn as NetPacketConn, UdpAddr};
use murmur_transport_tuic::quic::{self as tuic_quic, Config as QuicConfig};
use murmur_transport_tuic::server::{new_server, HandleTcpFn, HandleUdpFn, Server, ServerOption};
use murmur_transport_tuic::tuic::gen_tkn;
use rustls::pki_types::PrivateKeyDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const UUID: &str = "ae5f84f6-2f16-4b1f-9f4f-2a2b4c6d8e0f";
const PASSWORD: &str = "test-password";
const TOKEN: &str = "test-token";
const PAYLOAD: &[u8] = b"tuic-udp-payload";
const REPLY: &[u8] = b"tuic-udp-reply";
const TCP_PAYLOAD: &[u8] = b"tuic-tcp-payload";
const DESTINATION: &str = "192.0.2.1:53";
const TIMEOUT: Duration = Duration::from_secs(20);

fn destination() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53)
}

fn udp_metadata() -> Metadata {
    Metadata {
        network: NetWork::UDP,
        host: "192.0.2.1".to_owned(),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        dst_port: 53,
        ..Default::default()
    }
}

fn pem_section(pem: &str, label: &str) -> Vec<u8> {
    ca::config::pem_sections(pem.as_bytes())
        .into_iter()
        .find(|(section, _, _)| section == label)
        .map(|(_, der, _)| der)
        .unwrap_or_else(|| panic!("no {label} section in the generated PEM"))
}

fn server_tls() -> Arc<tuic_quic::ServerTls> {
    let (cert_pem, key_pem, _) = new_random_tls_key_pair(KeyPairType::P256).expect("generate a test key pair");
    let certificate = tls_c::Certificate {
        certificate: vec![pem_section(&cert_pem, "CERTIFICATE")],
        private_key: Some(PrivateKeyDer::Pkcs8(pem_section(&key_pem, "PRIVATE KEY").into())),
        ..Default::default()
    };
    let config = tls_c::Config {
        min_version: tls_c::VERSION_TLS13,
        next_protos: vec!["h3".to_owned()],
        get_certificate: Some(Arc::new(move |_info: &tls_c::ClientHelloInfo| Ok(Some(certificate.clone())))),
        ..Default::default()
    };
    Arc::new(tuic_quic::ServerTls {
        config: Arc::new(tls_c::server_rustls_config(&config).expect("build the server rustls config")),
    })
}

fn server_quic_config() -> Arc<QuicConfig> {
    Arc::new(tuic_quic::effective_config(QuicConfig {
        enable_datagrams: true,
        max_datagram_frame_size: 1400,
        ..QuicConfig::default()
    }))
}

fn v5_option(handle_tcp_fn: HandleTcpFn, handle_udp_fn: HandleUdpFn) -> Arc<ServerOption> {
    Arc::new(ServerOption {
        handle_tcp_fn,
        handle_udp_fn,
        tls_config: server_tls(),
        quic_config: server_quic_config(),
        tokens: Vec::new(),
        users: HashMap::from([(
            uuid::Uuid::parse_str(UUID).expect("the test UUID parses").into_bytes(),
            PASSWORD.to_owned(),
        )]),
        congestion_controller: "bbr".to_owned(),
        authentication_timeout: Duration::from_secs(5),
        max_udp_relay_packet_size: 1400,
        cwnd: 32,
        bbr_profile: String::new(),
    })
}

fn v4_option(handle_tcp_fn: HandleTcpFn, handle_udp_fn: HandleUdpFn) -> Arc<ServerOption> {
    Arc::new(ServerOption {
        handle_tcp_fn,
        handle_udp_fn,
        tls_config: server_tls(),
        quic_config: server_quic_config(),
        tokens: vec![gen_tkn(TOKEN)],
        users: HashMap::new(),
        congestion_controller: "bbr".to_owned(),
        authentication_timeout: Duration::from_secs(5),
        max_udp_relay_packet_size: 1400,
        cwnd: 32,
        bbr_profile: String::new(),
    })
}

async fn start_server(option: Arc<ServerOption>) -> (u16, Arc<Server>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind the server socket");
    let port = socket.local_addr().expect("the server socket's address").port();
    let packet_conn: Arc<dyn NetPacketConn> = Arc::new(socket);
    let server = Arc::new(new_server(option, packet_conn).expect("start the TUIC server"));
    let serving = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = serving.serve().await;
    });
    (port, server)
}

async fn v5_client(port: u16, option: impl FnOnce(&mut TuicOption)) -> Arc<Tuic> {
    let mut tuic_option = TuicOption {
        name: "tuic-e2e".to_owned(),
        server: "127.0.0.1".to_owned(),
        port: i32::from(port),
        uuid: UUID.to_owned(),
        password: PASSWORD.to_owned(),
        skip_cert_verify: true,
        ..Default::default()
    };
    option(&mut tuic_option);
    Tuic::new(tuic_option).expect("build the outbound")
}

async fn v4_client(port: u16) -> Arc<Tuic> {
    Tuic::new(TuicOption {
        name: "tuic-e2e-v4".to_owned(),
        server: "127.0.0.1".to_owned(),
        port: i32::from(port),
        token: TOKEN.to_owned(),
        skip_cert_verify: true,
        ..Default::default()
    })
    .expect("build the v4 outbound")
}

/// The server half of a datagram round trip: it records the destination it was handed and writes
/// `REPLY` back along the association the packet arrived on.
fn echo_udp_fn(seen: Arc<parking_lot::Mutex<Vec<(String, Vec<u8>)>>>) -> HandleUdpFn {
    Arc::new(move |addr, packet, _additions| {
        let data = packet.data().to_vec();
        seen.lock().push((addr.string(), data));
        let reply_addr = addr.udp_addr().and_then(|udp| SocketAddr::try_from(&udp).ok());
        tokio::spawn(async move {
            if let Some(reply_addr) = reply_addr {
                let _ = packet.write_back(REPLY, Some(reply_addr)).await;
            }
        });
        Ok(())
    })
}

/// The server half of UDP-over-stream: `request_header` is true for uot v2, where the client sends
/// its `Request` before the first frame, and false for the legacy version, which carries only the
/// per-datagram address header.
fn uot_echo_tcp_fn(seen: Arc<parking_lot::Mutex<Vec<(String, Vec<u8>)>>>, request_header: bool) -> HandleTcpFn {
    Arc::new(move |conn, addr, _additions| {
        let connect_addr = addr.string();
        let seen = Arc::clone(&seen);
        let mut conn = conn;
        tokio::spawn(async move {
            let request = if request_header {
                match uot::read_request(&mut conn).await {
                    Ok(request) => request,
                    Err(_) => return,
                }
            } else {
                uot::Request { is_connect: false, destination: Default::default() }
            };
            let conn = uot::new_conn(conn, request);
            let mut buf = vec![0u8; 2048];
            if let Ok((n, from)) = NetPacketConn::read_from(&conn, &mut buf).await {
                seen.lock().push((connect_addr, buf[..n].to_vec()));
                let _ = NetPacketConn::write_to(&conn, REPLY, &*from).await;
            }
        });
        Ok(())
    })
}

fn silent_tcp_fn() -> HandleTcpFn {
    Arc::new(|_conn, _addr, _additions| Ok(()))
}

async fn datagram_round_trip(client: &Tuic) -> (Vec<u8>, SocketAddr) {
    let ctx = CancellationToken::new();
    let mut metadata = udp_metadata();
    let pc: Arc<dyn CPacketConn> = tokio::time::timeout(TIMEOUT, client.listen_packet_context(&ctx, &mut metadata))
        .await
        .expect("the packet dial completes in time")
        .expect("the packet dial reaches the server");

    let target = UdpAddr::from(destination());
    tokio::time::timeout(TIMEOUT, pc.write_to(PAYLOAD, &target))
        .await
        .expect("the datagram is written in time")
        .expect("the datagram is written");

    let mut buf = vec![0u8; 2048];
    let (n, from) = tokio::time::timeout(TIMEOUT, pc.read_from(&mut buf))
        .await
        .expect("the reply arrives in time")
        .expect("the reply is read");
    let from =
        murmur_common_net::io::old_addr_to_socket_addr(from.as_ref()).expect("the reply address is a socket address");
    (buf[..n].to_vec(), from)
}

#[tokio::test]
async fn tuic_native_datagram_round_trip_over_v5() {
    let seen: Arc<parking_lot::Mutex<Vec<(String, Vec<u8>)>>> = Default::default();
    let (port, server) = start_server(v5_option(silent_tcp_fn(), echo_udp_fn(Arc::clone(&seen)))).await;

    let client = v5_client(port, |_| {}).await;
    let (reply, from) = datagram_round_trip(&client).await;

    assert_eq!(reply, REPLY, "the tunnel carries the reply back");
    assert_eq!(from, destination(), "the reply reports the destination the datagram was sent to");
    assert_eq!(&*seen.lock(), &[(DESTINATION.to_owned(), PAYLOAD.to_vec())], "the server saw the datagram");
    let _ = server.close();
}

#[tokio::test]
async fn tuic_quic_datagram_round_trip_over_v5() {
    let seen: Arc<parking_lot::Mutex<Vec<(String, Vec<u8>)>>> = Default::default();
    let (port, server) = start_server(v5_option(silent_tcp_fn(), echo_udp_fn(Arc::clone(&seen)))).await;

    let client = v5_client(port, |option| option.udp_relay_mode = "quic".to_owned()).await;
    let (reply, from) = datagram_round_trip(&client).await;

    assert_eq!(reply, REPLY, "the QUIC relay mode carries the reply back");
    assert_eq!(from, destination());
    assert_eq!(&*seen.lock(), &[(DESTINATION.to_owned(), PAYLOAD.to_vec())]);
    let _ = server.close();
}

#[tokio::test]
async fn tuic_udp_over_stream_v2_round_trip_over_v5() {
    let seen: Arc<parking_lot::Mutex<Vec<(String, Vec<u8>)>>> = Default::default();
    let (port, server) =
        start_server(v5_option(uot_echo_tcp_fn(Arc::clone(&seen), true), Arc::new(|_, _, _| Ok(())))).await;

    let client = v5_client(port, |option| {
        option.udp_over_stream = true;
        option.udp_over_stream_version = i32::from(uot::VERSION);
    })
    .await;
    let (reply, from) = datagram_round_trip(&client).await;

    assert_eq!(reply, REPLY, "the UDP-over-stream tunnel carries the reply back");
    assert_eq!(from, destination(), "the reply reports the destination the client sent to");
    assert_eq!(
        &*seen.lock(),
        &[(format!("{}:0", uot::MAGIC_ADDRESS), PAYLOAD.to_vec())],
        "the server saw the uot destination"
    );
    let _ = server.close();
}

#[tokio::test]
async fn tuic_udp_over_stream_legacy_round_trip_over_v5() {
    let seen: Arc<parking_lot::Mutex<Vec<(String, Vec<u8>)>>> = Default::default();
    let (port, server) =
        start_server(v5_option(uot_echo_tcp_fn(Arc::clone(&seen), false), Arc::new(|_, _, _| Ok(())))).await;

    let client = v5_client(port, |option| option.udp_over_stream = true).await;
    let (reply, from) = datagram_round_trip(&client).await;

    assert_eq!(reply, REPLY, "the legacy UDP-over-stream tunnel carries the reply back");
    assert_eq!(from, destination(), "the reply reports the destination the client sent to");
    assert_eq!(
        &*seen.lock(),
        &[(format!("{}:0", uot::LEGACY_MAGIC_ADDRESS), PAYLOAD.to_vec())],
        "the server saw the legacy uot destination"
    );
    let _ = server.close();
}

#[tokio::test]
async fn tuic_v4_token_stream_round_trip() {
    let requested: Arc<parking_lot::Mutex<Option<String>>> = Default::default();
    let echoed: Arc<parking_lot::Mutex<Vec<u8>>> = Default::default();
    let handle_tcp_fn: HandleTcpFn = {
        let requested = Arc::clone(&requested);
        let echoed = Arc::clone(&echoed);
        Arc::new(move |mut conn, addr, _additions| {
            *requested.lock() = Some(addr.string());
            let echoed = Arc::clone(&echoed);
            tokio::spawn(async move {
                let mut buf = vec![0u8; TCP_PAYLOAD.len()];
                if conn.read_exact(&mut buf).await.is_ok() {
                    echoed.lock().extend_from_slice(&buf);
                    let _ = conn.write_all(&buf).await;
                }
            });
            Ok(())
        })
    };
    let (port, server) = start_server(v4_option(handle_tcp_fn, Arc::new(|_, _, _| Ok(())))).await;
    let client = v4_client(port).await;

    let ctx = CancellationToken::new();
    let mut metadata = Metadata { host: "example.com".to_owned(), dst_port: 80, ..Default::default() };
    let mut conn = tokio::time::timeout(TIMEOUT, client.dial_context(&ctx, &mut metadata))
        .await
        .expect("the v4 dial completes in time")
        .expect("the v4 token handshake succeeds");

    conn.write_all(TCP_PAYLOAD).await.expect("write the payload");
    conn.flush().await.expect("flush the payload");
    let mut buf = vec![0u8; TCP_PAYLOAD.len()];
    tokio::time::timeout(TIMEOUT, conn.read_exact(&mut buf)).await.expect("the echo arrives in time").expect("read");
    assert_eq!(&buf[..], TCP_PAYLOAD, "the v4 tunnel carries the payload back");
    assert_eq!(&*echoed.lock(), TCP_PAYLOAD, "the server received the payload");
    assert_eq!(requested.lock().as_deref(), Some("example.com:80"), "the server saw the requested address");
    let _ = server.close();
}

#[tokio::test]
async fn tuic_v4_token_datagram_round_trip() {
    let seen: Arc<parking_lot::Mutex<Vec<(String, Vec<u8>)>>> = Default::default();
    let (port, server) = start_server(v4_option(silent_tcp_fn(), echo_udp_fn(Arc::clone(&seen)))).await;
    let client = v4_client(port).await;

    let (reply, from) = datagram_round_trip(&client).await;

    assert_eq!(reply, REPLY, "the v4 tunnel carries the reply back");
    assert_eq!(from, destination(), "the reply reports the destination the datagram was sent to");
    assert_eq!(&*seen.lock(), &[(DESTINATION.to_owned(), PAYLOAD.to_vec())], "the server saw the datagram");
    let _ = server.close();
}

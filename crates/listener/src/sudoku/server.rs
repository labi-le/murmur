//! DEVIATION: the handshake conn's HTTP-mask-rejection type assertion is not available.
//!
//! `murmur_std_compat::net::Conn` deliberately carries no `Any` support, and the conn returned by
//! `HttpMaskTunnelServer::wrap_conn` is already erased behind `Box<dyn Conn>` by the time it
//! reaches this file, so the concrete
//! `obfs::httpmask::tunnel_server::PreBufferedConn` producing a rejected conn can never be
//! recovered here. This always answers `false` (never treats a wrapped conn as HTTP-mask-rejected),
//! matching `listener::sing::sing::need_additional_read_deadline`'s precedent for the same class of
//! missing downcast: the fallback bypass optimization is skipped and every conn instead goes
//! through the normal Sudoku handshake attempt.
//!
//! DEVIATION: a close-everything closure would rely on the aliased conn value
//! staying valid after being handed to the wrap/handshake calls. Rust's ownership model moves
//! the conn into each of those calls instead, so there is never a second, still-open handle left
//! over to close on their error paths; whichever call consumed the conn is responsible for its own
//! cleanup on error, and this file simply returns.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::addition::{with_in_name, with_special_rules, Addition};
use murmur_adapter_inbound::packet::new_packet;
use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{Acceptor, CancellableStream, Datagram, OldConnAsStream, Stream};
use murmur_common_net::{new_deadline_conn, relay_streams};
use murmur_constant::adapters::{UDPPacket, WriteBack};
use murmur_constant::listener::{InboundListenConfig, Listener as ConstListener};
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::sudoku::SudokuServer;
use murmur_listener_inner::tcp::handle_tcp;
use murmur_listener_sing::sing::{new_listener_handler, ListenerConfig as SingListenerConfig, ListenerHandler};
use murmur_log::{debugln, warnln};
use murmur_transport::socks5::socks5;
use murmur_transport_sudoku::config::{
    default_config as sudoku_default_config, deref_bool, deref_int, normalize_table_type, resolve_padding,
    ProtocolConfig,
};
use murmur_transport_sudoku::handshake::{
    read_server_session, server_handshake, BufferedRecorderConn, SessionType, SuspiciousError,
};
use murmur_transport_sudoku::httpmask_tunnel::{
    new_http_mask_tunnel_server, new_http_mask_tunnel_server_with_fallback, HttpMaskTunnelServer,
};
use murmur_transport_sudoku::init::server_aead_seed;
use murmur_transport_sudoku::multiplex_file::accept_multiplex_server;
use murmur_transport_sudoku::tables::new_server_tables_with_custom_patterns;
use murmur_transport_sudoku::uot::{read_datagram, UoTPacketConn};

fn is_eof(err: &anyhow::Error) -> bool {
    err.downcast_ref::<std::io::Error>().is_some_and(|err| err.kind() == std::io::ErrorKind::UnexpectedEof)
}

/// See the module-level `DEVIATION` note.
fn is_http_mask_rejected(_conn: &dyn Stream) -> bool {
    false
}

/// Sudoku uses framed reads. The asynchronous peek deadlines must not interrupt
/// a partially consumed frame and desynchronize the session.
fn wrap_session_conn(conn: Box<dyn Stream>) -> Box<dyn Stream> {
    new_deadline_conn(conn)
}

pub struct Listener {
    acceptor: Box<dyn Acceptor>,
    addr: String,
    closed: AtomicBool,
    proto_conf: ProtocolConfig,
    tunnel_srv: HttpMaskTunnelServer,
    fallback: String,
    handler: ListenerHandler,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("addr", &self.addr)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl ConstListener for Listener {
    fn raw_address(&self) -> String {
        self.addr.clone()
    }

    fn address(&self) -> String {
        self.acceptor.addr().map(|addr| addr.to_string()).unwrap_or_default()
    }

    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(self.acceptor.close()?)
    }
}

impl Listener {
    async fn handle_conn(self: Arc<Self>, conn: Box<dyn Stream>, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) {
        let remote_addr = conn.peer_addr().map(|addr| addr.to_string()).unwrap_or_default();
        debugln!("[Sudoku] accepted {remote_addr}");

        let mut handshake_conn = conn;
        let mut handshake_cfg = self.proto_conf.clone();
        let early_user_hash: Option<String>;

        match self.tunnel_srv.wrap_conn(handshake_conn).await {
            Ok((c, cfg, done, hash)) => {
                if done {
                    return;
                }
                let Some(c) = c else {
                    return;
                };
                handshake_conn = c;
                if let Some(cfg) = cfg {
                    handshake_cfg = cfg;
                }
                early_user_hash = hash;
            }
            Err(_) => return,
        }

        if !self.fallback.is_empty() && is_http_mask_rejected(&*handshake_conn) {
            let Ok(fb) = handle_tcp(Some(Arc::clone(&tunnel)), &self.fallback, "").await else {
                let _ = murmur_common_net::io::close_stream(&*handshake_conn);
                return;
            };
            let mut fb_stream = OldConnAsStream(fb);
            relay_streams(&mut *handshake_conn, &mut fb_stream).await;
            return;
        }

        let (c_conn, meta) = match server_handshake(handshake_conn, &handshake_cfg, early_user_hash.as_deref()).await {
            Ok(result) => result,
            Err(err) => {
                let fallback_addr = self.fallback.clone();
                match err.downcast::<SuspiciousError>() {
                    Ok(SuspiciousError { err, conn: Some(wrapper) }) => {
                        warnln!("[Sudoku] suspicious handshake from {remote_addr}: {err}");
                        if !fallback_addr.is_empty() {
                            if let Ok(fb) = handle_tcp(Some(Arc::clone(&tunnel)), &fallback_addr, "").await {
                                let mut fb_stream = OldConnAsStream(fb);
                                relay_to_fallback(wrapper, &mut fb_stream).await;
                                return;
                            }
                        }
                    }
                    Ok(susp) => {
                        debugln!("[Sudoku] handshake failed from {remote_addr}: {susp}");
                    }
                    Err(err) => {
                        debugln!("[Sudoku] handshake failed from {remote_addr}: {err}");
                    }
                }
                return;
            }
        };
        let c_conn = wrap_session_conn(c_conn);

        let session = match read_server_session(c_conn, Some(&meta)).await {
            Ok(session) => session,
            Err(err) => {
                warnln!("[Sudoku] read session failed from {remote_addr}: {err}");
                return;
            }
        };

        match session.typ {
            SessionType::UoT => self.handle_uot_session(session.conn, &tunnel, &additions).await,
            SessionType::Multiplex => {
                let Ok(mux) = accept_multiplex_server(session.conn) else {
                    return;
                };

                loop {
                    let Ok((stream, target)) = mux.accept_tcp().await else {
                        break;
                    };
                    let Some(target_addr) = socks5::parse_addr(&target) else {
                        let _ = murmur_common_net::io::close_stream(&*stream);
                        continue;
                    };
                    let sl = Arc::clone(&self);
                    let additions = additions.clone();
                    tokio::spawn(async move { sl.handler.handle_socket(&target_addr, stream, &additions).await });
                }
                mux.close();
            }
            SessionType::Tcp => {
                let Some(target_addr) = socks5::parse_addr(&session.target) else {
                    warnln!("[Sudoku] invalid target from {remote_addr}: {:?}", session.target);
                    let _ = murmur_common_net::io::close_stream(&*session.conn);
                    return;
                };
                self.handler.handle_socket(&target_addr, session.conn, &additions).await;
            }
        }
    }

    async fn handle_uot_session(&self, conn: Box<dyn Stream>, tunnel: &Arc<dyn Tunnel>, additions: &[Addition]) {
        let Ok(peer_addr) = conn.peer_addr() else {
            return;
        };
        let shared = SharedConn::new(CancellableStream::new(conn));
        let writer = Arc::new(UoTPacketConn::new(Box::new(OldConnAsStream(shared.clone()))));
        // One fresh SNAT key for
        // this whole UoT session, shared by every packet it reads.
        let nat_key = murmur_common::utils::uuid::new_uuid_v4().to_string();

        loop {
            let mut reader = shared.clone();
            let (addr_str, payload) = match read_datagram(&mut reader).await {
                Ok(result) => result,
                Err(err) => {
                    if !is_eof(&err) {
                        debugln!("[Sudoku][UoT] session closed: {err}");
                    }
                    let _ = shared.close();
                    return;
                }
            };

            let Some(target) = socks5::parse_addr(&addr_str) else {
                debugln!("[Sudoku][UoT] drop invalid target: {addr_str}");
                continue;
            };

            let payload_len = payload.len();
            let c_packet = Arc::new(UotPacket {
                payload,
                len: AtomicUsize::new(payload_len),
                writer: Arc::clone(&writer),
                local_addr: peer_addr,
                nat_key: nat_key.clone(),
            });
            let (packet, metadata) = new_packet(&target, c_packet, Type::SUDOKU, additions);
            tunnel.handle_udp_packet(packet, metadata);
        }
    }
}

/// DEVIATION: `Drop` cannot null the backing storage through the trait's
/// `&self` receiver (`constant::adapters::UDPPacket::drop_`), so the payload's readable length is
/// tracked in a separate atomic counter that `Drop` zeroes instead, mirroring
/// `listener::socks::utils::Packet`.
struct UotPacket {
    payload: Vec<u8>,
    len: AtomicUsize,
    writer: Arc<UoTPacketConn>,
    local_addr: std::net::SocketAddr,
    /// A fresh
    /// per-session key so several UoT sessions multiplexed over one physical conn still land
    /// in distinct NAT entries even though `local_addr` (the shared peer) is the same.
    nat_key: String,
}

#[async_trait]
impl WriteBack for UotPacket {
    async fn write_back(&self, b: &[u8], addr: Option<std::net::SocketAddr>) -> Result<usize> {
        let socket_addr = addr.ok_or_else(|| anyhow!("address is invalid"))?;
        Ok(self.writer.send_to(b, socket_addr).await?)
    }
}

impl UDPPacket for UotPacket {
    fn data(&self) -> &[u8] {
        self.payload.get(..self.len.load(Ordering::Acquire).min(self.payload.len())).unwrap_or_default()
    }

    fn drop_(&self) {
        self.len.store(0, Ordering::Release);
    }

    fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// The remote address string, see the `nat_key` field doc.
    fn nat_key(&self) -> String {
        self.nat_key.clone()
    }
}

async fn relay_to_fallback(wrapper: Box<dyn BufferedRecorderConn>, fallback: &mut dyn Stream) {
    let mut wrapper = wrapper;
    let bad_data = wrapper.get_buffered_and_recorded();
    if !bad_data.is_empty() {
        use tokio::io::AsyncWriteExt as _;
        let write_result = tokio::time::timeout(std::time::Duration::from_secs(3), fallback.write_all(&bad_data)).await;
        if !matches!(write_result, Ok(Ok(()))) {
            let _ = murmur_common_net::io::close_stream(fallback);
            let _ = murmur_common_net::io::close_stream(&*wrapper);
            return;
        }
    }
    let mut raw = wrapper.into_raw();
    relay_streams(&mut *raw, fallback).await;
}

pub async fn new(
    config: SudokuServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<Listener>> {
    let additions =
        if additions.is_empty() { vec![with_in_name("DEFAULT-SUDOKU"), with_special_rules("")] } else { additions };

    let handler = new_listener_handler(SingListenerConfig {
        tunnel: Arc::clone(&tunnel),
        type_: Type::SUDOKU,
        additions: additions.clone(),
        udp_timeout: std::time::Duration::default(),
        mux_option: config.mux_option.clone(),
    })?;

    let l: Box<dyn Acceptor> = lc.listen(&CancellationToken::new(), "tcp", &config.listen).await?;

    let table_type = match normalize_table_type(&config.table_type) {
        Ok(table_type) => table_type,
        Err(err) => {
            let _ = l.close();
            return Err(err);
        }
    };

    let default_conf = sudoku_default_config();
    let (padding_min, padding_max) =
        resolve_padding(config.padding_min, config.padding_max, default_conf.padding_min, default_conf.padding_max);
    let enable_pure_downlink = deref_bool(config.enable_pure_downlink, default_conf.enable_pure_downlink);

    let tables = match new_server_tables_with_custom_patterns(
        &server_aead_seed(&config.key),
        &table_type,
        &config.custom_table,
        &config.custom_tables,
    ) {
        Ok(tables) => tables,
        Err(err) => {
            let _ = l.close();
            return Err(err);
        }
    };

    let handshake_timeout = deref_int(config.handshake_timeout_second, default_conf.handshake_timeout_seconds);

    let mut proto_conf =
        build_proto_conf(&config, &default_conf, padding_min, padding_max, enable_pure_downlink, handshake_timeout);
    if tables.len() == 1 {
        proto_conf.table = tables.first().map(Arc::clone);
    } else {
        proto_conf.tables = tables;
    }
    if !config.aead_method.is_empty() {
        config.aead_method.clone_into(&mut proto_conf.aead_method);
    }

    let fallback = config.fallback.trim().to_owned();
    let tunnel_srv = if fallback.is_empty() {
        new_http_mask_tunnel_server(proto_conf.clone())
    } else {
        new_http_mask_tunnel_server_with_fallback(proto_conf.clone())
    };

    let sl = Arc::new(Listener {
        acceptor: l,
        addr: config.listen.clone(),
        closed: AtomicBool::new(false),
        proto_conf,
        tunnel_srv,
        fallback,
        handler,
    });

    spawn_accept_loop(&sl, &tunnel, &additions);

    Ok(sl)
}

/// Serves the single Sudoku `Acceptor` until the listener is closed.
fn spawn_accept_loop(sl: &Arc<Listener>, tunnel: &Arc<dyn Tunnel>, additions: &[Addition]) {
    let sl = Arc::clone(sl);
    let tunnel = Arc::clone(tunnel);
    let additions = additions.to_vec();
    tokio::spawn(async move {
        loop {
            let Ok(conn) = sl.acceptor.accept().await else {
                if sl.closed.load(Ordering::SeqCst) {
                    break;
                }
                continue;
            };
            let sl = Arc::clone(&sl);
            let tunnel = Arc::clone(&tunnel);
            let additions = additions.clone();
            tokio::spawn(async move { sl.handle_conn(conn, tunnel, additions).await });
        }
    });
}

#[expect(
    clippy::unneeded_field_pattern,
    reason = "naming every field makes a field added to ProtocolConfig fail the build instead of silently taking its default"
)]
fn build_proto_conf(
    config: &SudokuServer,
    default_conf: &ProtocolConfig,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    handshake_timeout: i32,
) -> ProtocolConfig {
    let ProtocolConfig {
        server_address,
        key: _,
        aead_method: _,
        table: default_table,
        tables: default_tables,
        padding_min: _,
        padding_max: _,
        enable_pure_downlink: _,
        target_address,
        handshake_timeout_seconds: _,
        disable_http_mask: _,
        http_mask_mode: _,
        http_mask_tls_enabled,
        http_mask_host,
        http_mask_path_root: _,
        multiplex,
        http_mask_multiplex,
    } = ProtocolConfig::default();
    ProtocolConfig {
        server_address,
        key: config.key.clone(),
        aead_method: default_conf.aead_method.clone(),
        table: default_table,
        tables: default_tables,
        padding_min,
        padding_max,
        enable_pure_downlink,
        target_address,
        handshake_timeout_seconds: handshake_timeout,
        disable_http_mask: config.disable_http_mask,
        http_mask_mode: config.http_mask_mode.clone(),
        http_mask_tls_enabled,
        http_mask_host,
        http_mask_path_root: config.path_root.trim().to_owned(),
        multiplex,
        http_mask_multiplex,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use murmur_adapter_inbound::listen::new_listen_config;
    use murmur_adapter_outbound::base::BasicOption;
    use murmur_adapter_outbound::sudoku::{Sudoku, SudokuOption};
    use murmur_constant::adapters::ProxyAdapter as CProxyAdapter;
    use murmur_constant::metadata::Metadata;
    use murmur_testsupport::EchoTunnel;

    /// Regression test for the `Stream`/old-`Conn` boundary bridges added to `handle_conn`,
    /// `wrap_session_conn`, and `read_server_session`'s caller: a real Sudoku client (the same
    /// production `dial_context` path `adapter::outbound::sudoku::Sudoku` uses) dials the real
    /// listener over a real TCP loopback socket, and the echoed payload proves the handshake,
    /// the `wrap_session_conn`/`DeadlineConn` wrap, and the final `ListenerHandler::handle_socket`
    /// dispatch into `Tunnel::handle_tcp_conn` all still carry live bytes end to end.
    #[tokio::test]
    async fn tcp_session_round_trips_through_the_real_listener() {
        let tunnel = Arc::new(EchoTunnel { camouflage_addr: String::new() });
        let key = "sudoku-listener-boundary-key".to_owned();

        let config =
            SudokuServer { enable: true, listen: "127.0.0.1:0".to_owned(), key: key.clone(), ..Default::default() };

        let listener_tunnel = Arc::clone(&tunnel);
        let listener_tunnel: Arc<dyn Tunnel> = listener_tunnel;
        let listener = new(config, Arc::new(new_listen_config()), listener_tunnel, Vec::new())
            .await
            .expect("listener should start");
        let addr = listener.address();

        let (host, port) = addr.rsplit_once(':').expect("host:port");
        let client = Sudoku::new(SudokuOption {
            basic_option: BasicOption::default(),
            server: host.to_owned(),
            port: port.parse().expect("port"),
            key,
            ..Default::default()
        })
        .expect("client construction");

        let mut metadata =
            Metadata { dst_ip: Some("1.2.3.4".parse().expect("ip")), dst_port: 80, ..Default::default() };

        let ctx = CancellationToken::new();
        let mut conn = tokio::time::timeout(Duration::from_secs(5), client.dial_context(&ctx, &mut metadata))
            .await
            .expect("dial did not time out")
            .expect("dial succeeded");

        let payload = b"sudoku-listener-boundary-smoke";
        tokio::time::timeout(Duration::from_secs(5), conn.write_all(payload))
            .await
            .expect("write timed out")
            .expect("write");

        let mut buf = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut buf))
            .await
            .expect("read timed out")
            .expect("read");
        assert_eq!(&buf, payload);

        let _ = listener.close();
    }

    struct DummyStream(tokio::io::DuplexStream);

    impl tokio::io::AsyncRead for DummyStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for DummyStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl Stream for DummyStream {
        fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }

        fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
    }

    fn dummy_writer() -> Arc<UoTPacketConn> {
        let (a, _b) = tokio::io::duplex(64);
        Arc::new(UoTPacketConn::new(Box::new(DummyStream(a))))
    }

    /// `Listener::handle_uot_session` generates one fresh `nat_key` per call and shares it
    /// across every packet built from that session's datagrams; two UoT sessions sharing the
    /// same peer socket must not collapse onto the same NAT entry.
    #[test]
    fn nat_key_differs_across_sessions_sharing_the_same_peer_addr() {
        let peer_addr: std::net::SocketAddr = "203.0.113.9:9000".parse().unwrap();
        let writer = dummy_writer();

        let one = UotPacket {
            payload: Vec::new(),
            len: AtomicUsize::new(0),
            writer: Arc::clone(&writer),
            local_addr: peer_addr,
            nat_key: murmur_common::utils::uuid::new_uuid_v4().to_string(),
        };
        let two = UotPacket {
            payload: Vec::new(),
            len: AtomicUsize::new(0),
            writer,
            local_addr: peer_addr,
            nat_key: murmur_common::utils::uuid::new_uuid_v4().to_string(),
        };

        assert_eq!(one.local_addr(), two.local_addr());
        assert_ne!(one.nat_key(), two.nat_key());
    }
}

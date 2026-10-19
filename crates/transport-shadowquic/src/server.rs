use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::congestion::{set_brutal_congestion_controller, set_congestion_controller};
use crate::extension::{
    read_extension_opcode, read_extension_subcommand, shadow_quic_conn_stats, write_extension_conn_stats_result,
    write_extension_error_result, EXTENSION_CONN_GET_STATS, EXTENSION_ERR_NOT_AVAILABLE, EXTENSION_OPCODE_CONN,
    EXTENSION_OPCODE_USER,
};
use crate::extension_brutal::{
    read_brutal_negotiation_request, write_brutal_negotiation_response, EXTENSION_OPCODE_BRUTAL,
};
use crate::packet::{new_association, write_back, Association};
use crate::protocol::{
    read_command, read_request_addr, COMMAND_ASSOCIATE_DATAGRAM, COMMAND_ASSOCIATE_STREAM, COMMAND_CONNECT,
    COMMAND_EXTENSION,
};
use crate::state::{new_conn_state, ConnState, UdpMode};
use crate::stream_conn::new_quic_stream_conn;
use murmur_adapter_inbound::addition::{with_in_user, Addition};
use murmur_common_net::io::{close_stream, Stream as NetStream, StreamAsOldConn};
use murmur_constant::adapters::{UDPPacket, WriteBack};
use murmur_quic::jls::{Conn as JlsConn, EarlyListener, ListenEarlyFn};
use murmur_quic::{Config, JlsStatus, Stream, TlsConfig};
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn};
use murmur_transport::socks5::socks5;

/// The TCP handler's ownership contract: a failing call hands the connection back.
///
/// The caller closes `conn` when the call returns an error, and since the callback takes
/// ownership of `conn`, the `Err` arm carries it back so that close can still happen.
pub type HandleTcpFn = Arc<
    dyn Fn(Box<dyn NetConn>, socks5::Addr, &[Addition]) -> Result<(), (Box<dyn NetConn>, anyhow::Error)> + Send + Sync,
>;
pub type HandleUdpFn = Arc<dyn Fn(socks5::Addr, Box<dyn UDPPacket>, &[Addition]) -> anyhow::Result<()> + Send + Sync>;

pub struct ServerOption {
    pub handle_tcp_fn: Option<HandleTcpFn>,
    pub handle_udp_fn: Option<HandleUdpFn>,

    pub tls_config: Arc<dyn TlsConfig>,
    pub quic_config: Arc<Config>,

    pub congestion_controller: String,
    pub send_bps: u64,
    pub receive_bps: u64,
    pub ignore_client_bandwidth: bool,
    pub cwnd: i32,
    pub bbr_profile: String,
}

impl std::fmt::Debug for ServerOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerOption")
            .field("handle_tcp_fn", &self.handle_tcp_fn.is_some())
            .field("handle_udp_fn", &self.handle_udp_fn.is_some())
            .field("congestion_controller", &self.congestion_controller)
            .field("send_bps", &self.send_bps)
            .field("receive_bps", &self.receive_bps)
            .field("ignore_client_bandwidth", &self.ignore_client_bandwidth)
            .field("cwnd", &self.cwnd)
            .field("bbr_profile", &self.bbr_profile)
            .finish_non_exhaustive()
    }
}

pub struct Server {
    option: Arc<ServerOption>,
    listener: Arc<dyn EarlyListener>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").field("option", &self.option).finish_non_exhaustive()
    }
}

impl Server {
    /// Builds a server. The listener factory is an explicit parameter so the caller
    /// chooses which QUIC implementation backs the server, the same way
    /// `dial.rs`'s `dial_quic` takes a `TransportFactory`.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the public constructor takes the listener factory by value; its signature is the interface listener crates build against"
    )]
    pub fn new(
        option: Arc<ServerOption>,
        pc: Box<dyn PacketConn>,
        listen_early: ListenEarlyFn,
    ) -> anyhow::Result<Self> {
        let listener = listen_early(pc, Arc::clone(&option.tls_config), Arc::clone(&option.quic_config))?;
        Ok(Self { option, listener })
    }

    pub async fn serve(&self) -> anyhow::Result<()> {
        loop {
            let conn = self.listener.accept(&CancellationToken::new()).await?;
            // Application streams may arrive before Brutal negotiation completes.
            set_congestion_controller(
                &*conn,
                &self.option.congestion_controller,
                self.option.cwnd,
                &self.option.bbr_profile,
            );
            let state = new_conn_state(conn);
            tokio::spawn(Self::handle_connection(Arc::clone(&self.option), state));
        }
    }

    pub fn close(&self) -> std::io::Result<()> {
        self.listener.close()
    }

    async fn handle_connection(option: Arc<ServerOption>, state: Arc<ConnState>) {
        loop {
            let Ok(stream) = state.quic_conn.accept_stream(&state.ctx).await else {
                state.ctx.cancel();
                return;
            };
            tokio::spawn(Self::handle_stream(Arc::clone(&option), Arc::clone(&state), stream));
        }
    }

    async fn handle_stream(option: Arc<ServerOption>, state: Arc<ConnState>, mut stream: Box<dyn Stream>) {
        let Ok(command) = read_command(&mut stream).await else {
            let _ = stream.close();
            return;
        };
        match command {
            COMMAND_CONNECT => {
                let Ok(target) = read_request_addr(&mut stream).await else {
                    let _ = stream.close();
                    return;
                };
                let Some(handle_tcp_fn) = &option.handle_tcp_fn else {
                    let _ = stream.close();
                    return;
                };
                let (l_addr, r_addr) = (
                    Arc::<dyn Addr>::from(state.quic_conn.local_addr()),
                    Arc::<dyn Addr>::from(state.quic_conn.remote_addr()),
                );
                let stream_conn = new_quic_stream_conn(stream, l_addr, r_addr, None);
                let conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(stream_conn));
                if let Err((conn, _err)) = handle_tcp_fn(conn, target, &Self::jls_additions(&state)) {
                    let _ = conn.close();
                }
            }
            COMMAND_ASSOCIATE_DATAGRAM | COMMAND_ASSOCIATE_STREAM => {
                if read_request_addr(&mut stream).await.is_err() {
                    let _ = stream.close();
                    return;
                }
                if option.handle_udp_fn.is_none() {
                    let _ = stream.close();
                    return;
                }
                let mode = if command == COMMAND_ASSOCIATE_STREAM { UdpMode::Stream } else { UdpMode::Datagram };
                let assoc = new_association(Arc::clone(&state), stream, mode);
                tokio::spawn(Self::handle_association(Arc::clone(&option), Arc::clone(&state), assoc));
            }
            COMMAND_EXTENSION => {
                let (l_addr, r_addr) = (
                    Arc::<dyn Addr>::from(state.quic_conn.local_addr()),
                    Arc::<dyn Addr>::from(state.quic_conn.remote_addr()),
                );
                let mut conn = new_quic_stream_conn(stream, l_addr, r_addr, None);
                Self::handle_extension(Some(option.as_ref()), Some(state.as_ref()), &mut *conn).await;
            }
            _ => {
                let _ = stream.close();
            }
        }
    }

    async fn handle_brutal_negotiation(option: &ServerOption, state: &ConnState, conn: &mut dyn NetStream) {
        let Ok(rx) = read_brutal_negotiation_request(conn).await else {
            return;
        };
        let Ok(rx_auto) = Self::configure_brutal_congestion(option, &*state.quic_conn, rx) else {
            return;
        };
        let _ = write_brutal_negotiation_response(conn, option.receive_bps, rx_auto).await;
    }

    fn configure_brutal_congestion(
        option: &ServerOption,
        quic_conn: &dyn JlsConn,
        client_rx: u64,
    ) -> anyhow::Result<bool> {
        if option.receive_bps > 0 && option.ignore_client_bandwidth && client_rx == 0 {
            return Err(anyhow::anyhow!("shadowquic: brutal negotiation failed"));
        }
        if !(option.receive_bps == 0 && option.ignore_client_bandwidth) && client_rx > 0 {
            let mut rx = client_rx;
            if option.send_bps > 0 && rx > option.send_bps {
                rx = option.send_bps;
            }
            set_brutal_congestion_controller(quic_conn, rx);
            return Ok(false);
        }
        set_congestion_controller(quic_conn, "bbr", option.cwnd, &option.bbr_profile);
        Ok(true)
    }

    pub(crate) async fn handle_extension(
        option: Option<&ServerOption>,
        state: Option<&ConnState>,
        conn: &mut dyn NetStream,
    ) {
        let Ok(opcode) = read_extension_opcode(conn).await else {
            let _ = close_stream(conn);
            return;
        };
        match opcode {
            EXTENSION_OPCODE_BRUTAL => match (state, option) {
                (Some(state), Some(option)) => Self::handle_brutal_negotiation(option, state, conn).await,
                _ => {
                    let _ = write_extension_error_result(conn, EXTENSION_ERR_NOT_AVAILABLE, "").await;
                }
            },
            EXTENSION_OPCODE_CONN => {
                let Ok(subcommand) = read_extension_subcommand(conn).await else {
                    let _ = close_stream(conn);
                    return;
                };
                if subcommand != EXTENSION_CONN_GET_STATS {
                    let _ = write_extension_error_result(conn, EXTENSION_ERR_NOT_AVAILABLE, "").await;
                } else if let Some(state) = state {
                    let _ = write_extension_conn_stats_result(conn, shadow_quic_conn_stats(&*state.quic_conn)).await;
                }
            }
            EXTENSION_OPCODE_USER => {
                // Intentionally unsupported: remote management would be granted to every username
                // prefixed with "admin". Without an explicit opt-in and
                // persistence model, that would be a surprising control plane. Keep returning
                // NotAvailable unless such a model is deliberately added.
                if read_extension_subcommand(conn).await.is_err() {
                    let _ = close_stream(conn);
                    return;
                }
                let _ = write_extension_error_result(conn, EXTENSION_ERR_NOT_AVAILABLE, "").await;
            }
            _ => {
                let _ = write_extension_error_result(conn, EXTENSION_ERR_NOT_AVAILABLE, "").await;
            }
        }
        let _ = close_stream(conn);
    }

    /// Test-only mirror of `handle_extension` over a plain `AsyncRead + AsyncWrite` pipe (the
    /// test drives an in-memory pipe directly; `handle_extension` needs the full
    /// `common_net::io::Stream`, which a bare `tokio::io::DuplexStream` does not implement).
    #[cfg(test)]
    pub(crate) async fn handle_extension_for_test<C>(state: Option<&ConnState>, conn: &mut C)
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        let opcode = match read_extension_opcode(conn).await {
            Ok(opcode) => opcode,
            Err(_) => {
                let _ = conn.shutdown().await;
                return;
            }
        };
        match opcode {
            EXTENSION_OPCODE_CONN => {
                let Ok(subcommand) = read_extension_subcommand(conn).await else {
                    let _ = conn.shutdown().await;
                    return;
                };
                if subcommand != EXTENSION_CONN_GET_STATS {
                    let _ = write_extension_error_result(conn, EXTENSION_ERR_NOT_AVAILABLE, "").await;
                } else if let Some(state) = state {
                    let _ = write_extension_conn_stats_result(conn, shadow_quic_conn_stats(&*state.quic_conn)).await;
                }
            }
            EXTENSION_OPCODE_USER => {
                if read_extension_subcommand(conn).await.is_err() {
                    let _ = conn.shutdown().await;
                    return;
                }
                let _ = write_extension_error_result(conn, EXTENSION_ERR_NOT_AVAILABLE, "").await;
            }
            _ => {
                let _ = write_extension_error_result(conn, EXTENSION_ERR_NOT_AVAILABLE, "").await;
            }
        }
        let _ = conn.shutdown().await;
    }

    async fn handle_association(
        option: Arc<ServerOption>,
        state: Arc<ConnState>,
        assoc: Arc<Association>,
    ) -> anyhow::Result<()> {
        let r_addr = murmur_common_net::io::old_addr_to_socket_addr(state.quic_conn.remote_addr().as_ref())?;
        let l_addr = murmur_common_net::io::old_addr_to_socket_addr(assoc.local_addr().as_ref())?;
        let additions = Self::jls_additions(&state);
        let Some(handle_udp_fn) = &option.handle_udp_fn else {
            return Ok(());
        };

        loop {
            let Some(packet) = assoc.recv_for_server().await else {
                return Ok(());
            };
            let udp_packet: Box<dyn UDPPacket> =
                Box::new(ServerUdpPacket::new(Arc::clone(&assoc), packet.data, r_addr, l_addr));
            let _ = handle_udp_fn(packet.socks_addr, udp_packet, &additions);
        }
    }

    fn jls_additions(state: &ConnState) -> Vec<Addition> {
        let user = Self::jls_user(state);
        if user.is_empty() {
            Vec::new()
        } else {
            vec![with_in_user(&user)]
        }
    }

    fn jls_user(state: &ConnState) -> String {
        let tls_state = state.quic_conn.connection_state().tls;
        if tls_state.jls.status == JlsStatus::Authenticated {
            return tls_state.jls.user;
        }
        String::new()
    }
}

struct ServerUdpPacket {
    assoc: Arc<Association>,
    data: Vec<u8>,
    len: AtomicUsize,
    r_addr: std::net::SocketAddr,
    l_addr: std::net::SocketAddr,
}

impl ServerUdpPacket {
    fn new(assoc: Arc<Association>, data: Vec<u8>, r_addr: std::net::SocketAddr, l_addr: std::net::SocketAddr) -> Self {
        let len = AtomicUsize::new(data.len());
        Self { assoc, data, len, r_addr, l_addr }
    }
}

#[async_trait]
impl WriteBack for ServerUdpPacket {
    async fn write_back(&self, b: &[u8], addr: Option<std::net::SocketAddr>) -> anyhow::Result<usize> {
        write_back(&self.assoc, b, addr).await
    }
}

impl UDPPacket for ServerUdpPacket {
    fn data(&self) -> &[u8] {
        let len = self.len.load(Ordering::Acquire).min(self.data.len());
        self.data.get(..len).unwrap_or_default()
    }

    fn drop_(&self) {
        self.len.store(0, Ordering::Release);
    }

    fn local_addr(&self) -> std::net::SocketAddr {
        self.r_addr
    }

    fn in_addr(&self) -> Option<std::net::SocketAddr> {
        Some(self.l_addr)
    }

    /// Keys the NAT table per-association (`assoc`'s pointer identity), not per
    /// shared peer socket.
    fn nat_key(&self) -> String {
        format!("shadowquic-{:p}", Arc::as_ptr(&self.assoc))
    }
}

#[cfg(test)]
mod nat_key_tests {
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use async_trait::async_trait;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::packet::new_association;
    use crate::state::{new_conn_state, UdpMode};
    use murmur_quic::jls::congestion::CongestionControlEx;
    use murmur_quic::{
        ApplicationErrorCode, ConnectionState, ConnectionStats, ReceiveStream, SendStream, StreamErrorCode, StreamId,
        StreamReadHalf, StreamWriteHalf,
    };

    /// A control stream that never yields data or errors; `read_control`'s spawned task parks on
    /// it instead of returning, which is fine since the test drops the whole runtime on exit.
    struct FakeControlHalf;

    impl AsyncRead for FakeControlHalf {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for FakeControlHalf {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl StreamReadHalf for FakeControlHalf {
        fn cancel_read(&self, _error_code: StreamErrorCode) {}
    }

    impl StreamWriteHalf for FakeControlHalf {
        fn close(&self) -> io::Result<()> {
            Ok(())
        }

        fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            Ok(())
        }
    }

    struct FakeControlStream;

    impl AsyncRead for FakeControlStream {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for FakeControlStream {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for FakeControlStream {
        fn stream_id(&self) -> StreamId {
            0
        }

        fn cancel_read(&self, _error_code: StreamErrorCode) {}

        fn cancel_write(&self, _error_code: StreamErrorCode) {}

        fn close(&self) -> io::Result<()> {
            Ok(())
        }

        fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            Ok(())
        }

        fn set_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
            Ok(())
        }

        fn split(self: Box<Self>) -> (Box<dyn StreamReadHalf>, Box<dyn StreamWriteHalf>) {
            (Box::new(FakeControlHalf), Box::new(FakeControlHalf))
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct FakeJlsConn {
        closed: CancellationToken,
    }

    #[async_trait]
    impl JlsConn for FakeJlsConn {
        fn closed(&self) -> CancellationToken {
            self.closed.clone()
        }

        async fn open_stream_sync(&self, _ctx: &CancellationToken) -> anyhow::Result<Box<dyn Stream>> {
            unimplemented!("not exercised by the nat_key test path")
        }

        async fn open_uni_stream_sync(&self, _ctx: &CancellationToken) -> anyhow::Result<Box<dyn SendStream>> {
            unimplemented!("not exercised by the nat_key test path")
        }

        async fn accept_stream(&self, _ctx: &CancellationToken) -> anyhow::Result<Box<dyn Stream>> {
            unimplemented!("not exercised by the nat_key test path")
        }

        async fn accept_uni_stream(&self, _ctx: &CancellationToken) -> anyhow::Result<Box<dyn ReceiveStream>> {
            std::future::pending().await
        }

        fn local_addr(&self) -> Box<dyn Addr> {
            unimplemented!("not exercised by the nat_key test path")
        }

        fn remote_addr(&self) -> Box<dyn Addr> {
            unimplemented!("not exercised by the nat_key test path")
        }

        fn close_with_error(&self, _code: ApplicationErrorCode, _message: &str) -> io::Result<()> {
            Ok(())
        }

        fn config(&self) -> Config {
            Config::default()
        }

        fn set_congestion_control(&self, _cc: Box<dyn CongestionControlEx>) {}

        fn connection_stats(&self) -> ConnectionStats {
            ConnectionStats::default()
        }

        fn connection_state(&self) -> ConnectionState {
            ConnectionState::default()
        }

        async fn receive_datagram(&self, _ctx: &CancellationToken) -> anyhow::Result<Vec<u8>> {
            std::future::pending().await
        }

        fn send_datagram(&self, _data: Vec<u8>) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Two `Association`s spawned over one shared simulated QUIC connection (one `ConnState`, one
    /// `r_addr`) must still key their `ServerUdpPacket`s distinctly, keyed on the association
    /// pointer.
    #[tokio::test]
    async fn nat_key_differs_for_two_associations_sharing_one_conn() {
        let quic_conn: Arc<dyn JlsConn> = Arc::new(FakeJlsConn { closed: CancellationToken::new() });
        let state = new_conn_state(quic_conn);

        let assoc_one = new_association(Arc::clone(&state), Box::new(FakeControlStream), UdpMode::Datagram);
        let assoc_two = new_association(Arc::clone(&state), Box::new(FakeControlStream), UdpMode::Datagram);

        let peer: std::net::SocketAddr = "198.51.100.7:9".parse().unwrap();
        let local: std::net::SocketAddr = "127.0.0.1:1080".parse().unwrap();

        let packet_one = ServerUdpPacket::new(assoc_one, b"one".to_vec(), peer, local);
        let packet_two = ServerUdpPacket::new(assoc_two, b"two".to_vec(), peer, local);

        assert_eq!(packet_one.local_addr(), peer);
        assert_eq!(packet_two.local_addr(), peer);
        assert_ne!(
            packet_one.nat_key(),
            packet_two.nat_key(),
            "two associations sharing one QUIC connection/peer must not share a NAT key"
        );
    }
}

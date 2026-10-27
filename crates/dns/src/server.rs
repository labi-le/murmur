//! Length-framed TCP and datagram UDP need per-request handling that hickory-proto does not provide.
//!
//! The accept/read loops below implement that framing directly over the platform listener and
//! packet sockets.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use murmur_common::sockopt::reuse_common::raw_conn_reuseaddr;
use murmur_common_net::io::{close_stream, Acceptor, Datagram, Stream};
use murmur_common_net::split_host_port;
use murmur_common_pool as pool;
use murmur_component::resolver::relay::{request_udp_size, set_rcode, truncate};
use murmur_component::resolver::service::SharedService;
use murmur_constant::listener::InboundListenConfig;
use murmur_log::{errorln, infoln, warnln};

pub(crate) const DNS_DEFAULT_TTL: u32 = 600;

const MAX_UDP_MESSAGE_SIZE: usize = 65535;

/// The deadline for a TCP connection's first query.
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(2);
/// The deadline for each query after the first on a TCP connection.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(8);
/// The default cap on queries served per TCP connection.
const MAX_TCP_QUERIES: usize = 128;

pub struct Server {
    service: RwLock<Option<SharedService>>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").field("has_service", &self.service.read().is_some()).finish_non_exhaustive()
    }
}

impl Server {
    fn new(service: Option<SharedService>) -> Arc<Self> {
        Arc::new(Self { service: RwLock::new(service) })
    }

    pub fn set_service(&self, service: Option<SharedService>) {
        *self.service.write() = service;
    }

    fn service(&self) -> Option<SharedService> {
        self.service.read().clone()
    }
}

struct GlobalState {
    address: String,
    server: Arc<Server>,
    udp_conn: Option<Arc<dyn Datagram>>,
    tcp_listener: Option<Arc<dyn Acceptor>>,
}

static STATE: LazyLock<Mutex<GlobalState>> = LazyLock::new(|| {
    Mutex::new(GlobalState { address: String::new(), server: Server::new(None), udp_conn: None, tcp_listener: None })
});

async fn serve(server: &Server, is_udp: bool, r: &Message) -> Message {
    let service = server.service();
    let Some(service) = service else {
        let mut m = Message::new(0, MessageType::Response, OpCode::Query);
        set_rcode(&mut m, r, ResponseCode::ServFail);
        return m;
    };

    let ctx = CancellationToken::new();
    let Ok(mut msg) = service.serve_msg(&ctx, r).await else {
        let mut m = Message::new(0, MessageType::Response, OpCode::Query);
        set_rcode(&mut m, r, ResponseCode::ServFail);
        return m;
    };

    if is_udp {
        truncate(&mut msg, request_udp_size(r));
    }
    msg
}

async fn run_udp(server: Arc<Server>, conn: Arc<dyn Datagram>) {
    // `recv_from` fills only the front of the buffer, and each datagram is copied out below, so one
    // buffer serves the whole connection: the per-packet 64 KiB allocate-and-zero of the moved-in
    // buffer is gone, and the block returns to the pool when the loop ends.
    let mut scratch = pool::get(MAX_UDP_MESSAGE_SIZE);
    while let Ok((n, addr)) = conn.recv_from(&mut scratch).await {
        let Some(payload) = scratch.get(..n) else {
            errorln!("DNS server(UDP) received {n} bytes into a {MAX_UDP_MESSAGE_SIZE}-byte buffer");
            break;
        };
        let request = payload.to_vec();
        let server = Arc::clone(&server);
        let conn = Arc::clone(&conn);
        tokio::spawn(async move {
            let Ok(request) = Message::from_vec(&request) else {
                return;
            };
            let response = serve(&server, true, &request).await;
            if let Ok(bytes) = response.to_vec() {
                let _ = conn.send_to(&bytes, addr).await;
            }
        });
    }
    let _ = pool::put(scratch);
}

// cancel-safe: the connection is owned by the caller's task, and the read timeout only ends this loop.
async fn handle_tcp_conn(server: Arc<Server>, mut conn: Box<dyn Stream>) {
    let mut timeout = TCP_READ_TIMEOUT;
    for _ in 0..MAX_TCP_QUERIES {
        let read = tokio::time::timeout(timeout, read_length_prefixed(conn.as_mut())).await;
        let Ok(Ok(buf)) = read else {
            break;
        };
        let Ok(request) = Message::from_vec(&buf) else {
            break;
        };
        let response = serve(&server, false, &request).await;
        let Ok(bytes) = response.to_vec() else {
            break;
        };
        let Ok(out_len) = u16::try_from(bytes.len()) else {
            break;
        };
        if conn.write_all(&out_len.to_be_bytes()).await.is_err() {
            break;
        }
        if conn.write_all(&bytes).await.is_err() {
            break;
        }

        timeout = TCP_IDLE_TIMEOUT;
    }
    let _ = close_stream(conn.as_ref());
}

async fn read_length_prefixed(conn: &mut dyn Stream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    conn.read_exact(&mut len_buf).await?;
    let len = usize::from(u16::from_be_bytes(len_buf));
    let mut buf = vec![0u8; len];
    conn.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn run_tcp(server: Arc<Server>, listener: Arc<dyn Acceptor>) {
    while let Ok(conn) = listener.accept().await {
        let server = Arc::clone(&server);
        tokio::spawn(handle_tcp_conn(server, conn));
    }
}

/// The UDP and TCP handlers are folded into [`serve`]; there is no separate handler value to
/// expose.
pub fn re_create_server(addr: &str, lc: Option<Arc<dyn InboundListenConfig>>, service: Option<SharedService>) {
    let mut state = STATE.lock();

    if addr == state.address && service.is_some() {
        state.server.set_service(service);
        return;
    }

    if let Some(listener) = state.tcp_listener.take() {
        let _ = listener.close();
    }
    if let Some(conn) = state.udp_conn.take() {
        let _ = conn.close();
    }

    state.server.set_service(None);
    state.address.clear();

    let (Some(lc), Some(service)) = (lc, service) else {
        return;
    };
    if addr.is_empty() {
        return;
    }

    let port = match split_host_port(addr) {
        Ok((_, port, _)) => port,
        Err(err) => {
            errorln!("Start DNS server error: {err}");
            return;
        }
    };
    if port == "0" || port.is_empty() {
        return;
    }

    addr.clone_into(&mut state.address);
    let server = Server::new(Some(service));
    state.server = Arc::clone(&server);
    drop(state);

    let addr_owned = addr.to_owned();
    let udp_lc = Arc::clone(&lc);
    let udp_server = Arc::clone(&server);
    tokio::spawn(async move {
        match udp_lc.listen_packet(&CancellationToken::new(), "udp", &addr_owned).await {
            Ok(conn) => {
                if let Some(socket) = conn.as_socket() {
                    if let Err(err) = raw_conn_reuseaddr(&*socket) {
                        warnln!("Failed to Reuse UDP Address: {err}");
                    }
                }
                let local = conn.local_addr().map(|addr| addr.to_string()).unwrap_or_default();
                infoln!("DNS server(UDP) listening at: {local}");
                let conn: Arc<dyn Datagram> = Arc::from(conn);
                STATE.lock().udp_conn = Some(Arc::clone(&conn));
                run_udp(udp_server, conn).await;
            }
            Err(err) => errorln!("Start DNS server(UDP) error: {err}"),
        }
    });

    let addr_owned = addr.to_owned();
    let tcp_lc = lc;
    let tcp_server = server;
    tokio::spawn(async move {
        match tcp_lc.listen(&CancellationToken::new(), "tcp", &addr_owned).await {
            Ok(listener) => {
                let local = listener.addr().map(|addr| addr.to_string()).unwrap_or_default();
                infoln!("DNS server(TCP) listening at: {local}");
                let listener: Arc<dyn Acceptor> = Arc::from(listener);
                STATE.lock().tcp_listener = Some(Arc::clone(&listener));
                run_tcp(tcp_server, listener).await;
            }
            Err(err) => errorln!("Start DNS server(TCP) error: {err}"),
        }
    });
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;

    /// `--test-threads` against `available_parallelism`, not the code under test.
    const HANG_DEADLINE: Duration = Duration::from_secs(60);

    /// A TCP peer that never sends a byte and never closes: an unauthenticated client that opens
    /// a connection and goes silent. The pre-fix `handle_tcp_conn` had no read deadline and
    /// blocked on it forever; the read is bounded by `TCP_READ_TIMEOUT`.
    struct SilentConn {
        closed: StdArc<AtomicBool>,
    }

    impl AsyncRead for SilentConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for SilentConn {
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

    impl Stream for SilentConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        fn shutdown_read(&self) -> io::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn shutdown_write(&self) -> io::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn handle_tcp_conn_closes_idle_silent_connection() {
        let closed = StdArc::new(AtomicBool::new(false));
        let conn: Box<dyn Stream> = Box::new(SilentConn { closed: Arc::clone(&closed) });
        let server = Server::new(None);

        let result = tokio::time::timeout(HANG_DEADLINE, handle_tcp_conn(server, conn)).await;

        assert!(result.is_ok(), "handle_tcp_conn did not return for a silent connection within the hang deadline");
        assert!(closed.load(Ordering::SeqCst), "connection was not closed after the read timeout elapsed");
    }

    /// A TCP peer that pipelines more queries than the `MAX_TCP_QUERIES` default of 128 allows.
    /// The pre-fix `handle_tcp_conn` had no per-connection cap and would have served all of them.
    struct QueueConn {
        data: io::Cursor<Vec<u8>>,
        query_writes: StdArc<AtomicUsize>,
    }

    impl AsyncRead for QueueConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let pos = this.data.position() as usize;
            let remaining = &this.data.get_ref()[pos..];
            if !remaining.is_empty() {
                let n = std::cmp::min(buf.remaining(), remaining.len());
                buf.put_slice(&remaining[..n]);
                this.data.set_position((pos + n) as u64);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for QueueConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            if buf.len() == 2 {
                self.query_writes.fetch_add(1, Ordering::SeqCst);
            }
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for QueueConn {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    fn build_length_prefixed_queries(n: usize) -> Vec<u8> {
        use std::str::FromStr;

        use hickory_proto::rr::{Name, RecordType};

        let mut buf = Vec::new();
        for i in 0..n {
            let mut msg = Message::new(i as u16, MessageType::Query, OpCode::Query);
            msg.queries.push(hickory_proto::op::Query::query(Name::from_str("example.com.").unwrap(), RecordType::A));
            let bytes = msg.to_vec().expect("query encodes");
            buf.extend_from_slice(&(u16::try_from(bytes.len()).unwrap()).to_be_bytes());
            buf.extend_from_slice(&bytes);
        }
        buf
    }

    #[tokio::test]
    async fn handle_tcp_conn_caps_queries_per_connection() {
        let query_writes = StdArc::new(AtomicUsize::new(0));
        let data = build_length_prefixed_queries(MAX_TCP_QUERIES + 50);
        let conn: Box<dyn Stream> =
            Box::new(QueueConn { data: io::Cursor::new(data), query_writes: StdArc::clone(&query_writes) });
        let server = Server::new(None);

        tokio::time::timeout(HANG_DEADLINE, handle_tcp_conn(server, conn))
            .await
            .expect("handle_tcp_conn did not return within the hang deadline");

        assert_eq!(
            query_writes.load(Ordering::SeqCst),
            MAX_TCP_QUERIES,
            "connection served a different number of queries than the maxTCPQueries default"
        );
    }

    struct LoopbackListenConfig {
        tcp: Mutex<Option<tokio::net::TcpListener>>,
        udp: Mutex<Option<tokio::net::UdpSocket>>,
    }

    #[async_trait::async_trait]
    impl InboundListenConfig for LoopbackListenConfig {
        async fn listen(
            &self,
            _ctx: &CancellationToken,
            _network: &str,
            _address: &str,
        ) -> anyhow::Result<Box<dyn Acceptor>> {
            Ok(Box::new(self.tcp.lock().take().expect("tcp listener already taken")))
        }

        async fn listen_packet(
            &self,
            _ctx: &CancellationToken,
            _network: &str,
            _address: &str,
        ) -> anyhow::Result<Box<dyn Datagram>> {
            Ok(Box::new(self.udp.lock().take().expect("udp socket already taken")))
        }
    }

    struct EchoService;

    #[async_trait::async_trait]
    impl murmur_component::resolver::service::Service for EchoService {
        async fn serve_msg(&self, _ctx: &CancellationToken, msg: &Message) -> anyhow::Result<Message> {
            let mut reply = Message::new(msg.metadata.id, MessageType::Response, OpCode::Query);
            set_rcode(&mut reply, msg, ResponseCode::NoError);
            Ok(reply)
        }
    }

    /// Proves the query still reaches a real TCP socket and comes back through it, now that the
    /// removed socket bridges between `InboundListenConfig`'s `Datagram`/`Acceptor` and
    /// `run_udp`/`run_tcp`/`handle_tcp_conn` are gone.
    #[tokio::test]
    async fn re_create_server_answers_a_tcp_query_over_a_real_socket() {
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
        let addr = tcp_listener.local_addr().expect("local addr");
        let udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let lc: Arc<dyn InboundListenConfig> =
            Arc::new(LoopbackListenConfig { tcp: Mutex::new(Some(tcp_listener)), udp: Mutex::new(Some(udp_socket)) });

        re_create_server(&addr.to_string(), Some(lc), Some(Arc::new(EchoService)));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut query = Message::new(42, MessageType::Query, OpCode::Query);
        query.queries.push(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_utf8("example.com.").expect("name"),
            hickory_proto::rr::RecordType::A,
        ));
        let bytes = query.to_vec().expect("encode query");
        let len = u16::try_from(bytes.len()).expect("length fits u16");
        client.write_all(&len.to_be_bytes()).await.expect("write length");
        client.write_all(&bytes).await.expect("write query");

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut len_buf))
            .await
            .expect("response did not arrive over the real socket")
            .expect("read response length");
        let response_len = usize::from(u16::from_be_bytes(len_buf));
        let mut response_buf = vec![0u8; response_len];
        client.read_exact(&mut response_buf).await.expect("read response body");
        let response = Message::from_vec(&response_buf).expect("decode response");
        assert_eq!(response.metadata.id, 42, "response did not answer the query that was sent");
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);

        re_create_server("", None, None);
    }

    /// A datagram socket that serves a fixed list of payloads and then fails, counting the receive
    /// buffers that arrive freshly zeroed.
    struct ReuseProbeDatagram {
        pending: Mutex<std::collections::VecDeque<Vec<u8>>>,
        fresh_buffers: Arc<AtomicUsize>,
    }

    const RECEIVE_MARKER: u8 = 0xa5;

    #[async_trait::async_trait]
    impl Datagram for ReuseProbeDatagram {
        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let Some(datagram) = self.pending.lock().pop_front() else {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "no datagrams left"));
            };
            let Some(tail) = buf.last_mut() else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty receive buffer"));
            };
            if *tail != RECEIVE_MARKER {
                self.fresh_buffers.fetch_add(1, Ordering::SeqCst);
            }
            *tail = RECEIVE_MARKER;
            let Some(target) = buf.get_mut(..datagram.len()) else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "datagram larger than the receive buffer"));
            };
            target.copy_from_slice(&datagram);

            Ok((datagram.len(), SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)))
        }

        async fn send_to(&self, buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53))
        }
    }

    /// The pre-fix loop built its receive buffer inside the loop and moved it into the per-packet
    /// task, so every datagram paid a 64 KiB allocate-and-zero for a response under 100 bytes.
    #[tokio::test]
    async fn run_udp_reuses_one_receive_buffer_instead_of_allocating_per_datagram() {
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.queries.push(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_utf8("example.com.").expect("name"),
            hickory_proto::rr::RecordType::A,
        ));
        let datagram = query.to_vec().expect("encode query");
        let fresh_buffers = Arc::new(AtomicUsize::new(0));
        let conn: Arc<dyn Datagram> = Arc::new(ReuseProbeDatagram {
            pending: Mutex::new(std::collections::VecDeque::from([datagram.clone(), datagram.clone(), datagram])),
            fresh_buffers: Arc::clone(&fresh_buffers),
        });

        run_udp(Server::new(None), conn).await;

        assert_eq!(
            fresh_buffers.load(Ordering::SeqCst),
            1,
            "the receive loop allocated and zeroed a fresh buffer per datagram instead of reusing one"
        );
    }
}
